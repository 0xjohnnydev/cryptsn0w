// Narrowed service implementation derived from the supplied SBInject jitterd.
#import <Foundation/Foundation.h>

#include "sbinject_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <os/log.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <unistd.h>

#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
#define CODEX_PROC_PIDPATH_MAX 4096
#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_KILLED 0x01000000U
#define CODEX_CS_DEBUGGED 0x10000000U

extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int csops(pid_t pid, unsigned int operation, void *user_address,
                 size_t user_size);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern kern_return_t bootstrap_check_in(mach_port_t bootstrap_port,
                                        const char *service,
                                        mach_port_t *server_port);

static os_log_t service_log(void) {
    static os_log_t log;
    if (log == NULL) {
        log = os_log_create("com.openai.codex.sbinject", "jitterd");
    }
    return log;
}

static bool exact_root_process(pid_t pid, const char *expected_path) {
    if (pid <= 1 || expected_path == NULL) return false;
    char path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    char expected[CODEX_PROC_PIDPATH_MAX] = {0};
    struct stat status = {0};
    return proc_pidpath(pid, path, sizeof(path)) > 0 &&
           realpath(path, observed) != NULL &&
           realpath(expected_path, expected) != NULL &&
           strcmp(observed, expected) == 0 &&
           lstat(expected, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool exact_root_launchd_process(pid_t pid) {
    if (pid != 1) return false;
    char path[CODEX_PROC_PIDPATH_MAX] = {0};
    struct stat status = {0};
    if (proc_pidpath(pid, path, sizeof(path)) <= 0) return false;
    const char *leaf = strrchr(path, '/');
    leaf = leaf != NULL ? leaf + 1 : path;
    return strcmp(leaf, "launchd") == 0 &&
           lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool secure_regular_file(const char *path, off_t maximum_size,
                                struct stat *status_out) {
    struct stat status = {0};
    if (path == NULL || lstat(path, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 || status.st_uid != 0 || status.st_gid != 0 ||
        status.st_size <= 0 || status.st_size > maximum_size ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }
    if (status_out != NULL) *status_out = status;
    return true;
}

static bool regular_files_equal(const char *left, const char *right) {
    struct stat left_status = {0};
    struct stat right_status = {0};
    if (!secure_regular_file(left, 16 * 1024 * 1024, &left_status) ||
        !secure_regular_file(right, 16 * 1024 * 1024, &right_status) ||
        left_status.st_size != right_status.st_size) {
        return false;
    }
    int left_fd = open(left, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int right_fd = open(right, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    bool equal = left_fd >= 0 && right_fd >= 0;
    uint8_t left_bytes[64 * 1024];
    uint8_t right_bytes[sizeof(left_bytes)];
    while (equal) {
        ssize_t left_amount = read(left_fd, left_bytes, sizeof(left_bytes));
        ssize_t right_amount = read(right_fd, right_bytes,
                                    sizeof(right_bytes));
        if (left_amount < 0 && errno == EINTR) continue;
        if (right_amount < 0 && errno == EINTR) continue;
        if (left_amount < 0 || right_amount < 0 ||
            left_amount != right_amount) {
            equal = false;
            break;
        }
        if (left_amount == 0) break;
        if (memcmp(left_bytes, right_bytes, (size_t)left_amount) != 0) {
            equal = false;
            break;
        }
    }
    if (left_fd >= 0) close(left_fd);
    if (right_fd >= 0) close(right_fd);
    return equal;
}

static bool managed_app_launcher_process(pid_t pid) {
    char raw_path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(pid, raw_path, sizeof(raw_path)) <= 0 ||
        realpath(raw_path, observed) == NULL) {
        return false;
    }
    static const char *const launchers[] = {
        CODEX_SBINJECT_APP_LAUNCHER,
        CODEX_SBINJECT_APP_LAUNCHER_NO_KEYCHAIN,
        CODEX_SBINJECT_APP_LAUNCHER_NATIVE_SDK,
        CODEX_SBINJECT_APP_LAUNCHER_NATIVE_SDK_NO_KEYCHAIN,
    };
    bool launcher = false;
    for (size_t index = 0;
         index < sizeof(launchers) / sizeof(launchers[0]); ++index) {
        if (regular_files_equal(observed, launchers[index])) {
            launcher = true;
            break;
        }
    }
    if (!launcher) return false;
    char bundle[CODEX_PROC_PIDPATH_MAX] = {0};
    if (strlcpy(bundle, observed, sizeof(bundle)) >= sizeof(bundle)) {
        return false;
    }
    char *separator = strrchr(bundle, '/');
    if (separator == NULL || separator == bundle) return false;
    *separator = '\0';
    size_t bundle_length = strlen(bundle);
    if (bundle_length < 4U ||
        strcmp(bundle + bundle_length - 4U, ".app") != 0) {
        return false;
    }
    char container[CODEX_PROC_PIDPATH_MAX] = {0};
    if (strlcpy(container, bundle, sizeof(container)) >= sizeof(container)) {
        return false;
    }
    separator = strrchr(container, '/');
    if (separator == NULL || separator == container) return false;
    *separator = '\0';
    char parent[CODEX_PROC_PIDPATH_MAX] = {0};
    if (strlcpy(parent, container, sizeof(parent)) >= sizeof(parent)) {
        return false;
    }
    separator = strrchr(parent, '/');
    if (separator == NULL || separator == parent) return false;
    *separator = '\0';
    if (strcmp(parent, "/private/var/containers/Bundle/Application") != 0 &&
        strcmp(parent, "/var/containers/Bundle/Application") != 0) {
        return false;
    }
    char marker[CODEX_PROC_PIDPATH_MAX] = {0};
    int length = snprintf(marker, sizeof(marker), "%s/%s", container,
                          CODEX_SBINJECT_MANAGED_APP_MARKER);
    return length > 0 && (size_t)length < sizeof(marker) &&
           secure_regular_file(marker, 64 * 1024, NULL);
}

static bool shadow_policy_enabled(NSString *identifier) {
    if (identifier.length == 0) return false;
    NSDictionary *preferences =
        [NSDictionary dictionaryWithContentsOfFile:
            @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
    if (![preferences isKindOfClass:[NSDictionary class]]) return false;
    NSDictionary *app = preferences[identifier];
    if (![app isKindOfClass:[NSDictionary class]]) app = nil;
    if ([app[@"App_Disabled"] boolValue]) return false;
    if ([preferences[@"Global_Enabled"] boolValue] &&
        ![preferences[@"SingleToggleMigrated"] boolValue]) {
        return true;
    }
    return [app[@"App_Enabled"] boolValue];
}

static bool shadow_enabled_app_process(pid_t pid) {
    char raw_path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(pid, raw_path, sizeof(raw_path)) <= 0 ||
        realpath(raw_path, observed) == NULL) {
        return false;
    }
    static const char *const prefixes[] = {
        "/private/var/containers/Bundle/Application/",
        "/var/containers/Bundle/Application/",
    };
    bool app_store_path = false;
    for (size_t index = 0;
         index < sizeof(prefixes) / sizeof(prefixes[0]); ++index) {
        size_t length = strlen(prefixes[index]);
        if (strncmp(observed, prefixes[index], length) == 0) {
            app_store_path = true;
            break;
        }
    }
    if (!app_store_path) return false;

    char bundle_path[CODEX_PROC_PIDPATH_MAX] = {0};
    if (strlcpy(bundle_path, observed, sizeof(bundle_path)) >=
        sizeof(bundle_path)) {
        return false;
    }
    char *app_suffix = strstr(bundle_path, ".app/");
    if (app_suffix == NULL) return false;
    app_suffix[4] = '\0';

    NSString *bundlePath = [NSString stringWithUTF8String:bundle_path];
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
    NSString *identifier = bundle.bundleIdentifier;
    NSString *executablePath = bundle.executablePath;
    if (identifier.length == 0 || executablePath.length == 0) return false;
    char resolved_executable[CODEX_PROC_PIDPATH_MAX] = {0};
    if (realpath(executablePath.fileSystemRepresentation,
                 resolved_executable) == NULL ||
        strcmp(resolved_executable, observed) != 0) {
        return false;
    }

    return shadow_policy_enabled(identifier);
}

static bool target_compatibility_app_process(pid_t pid) {
    char raw_path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(pid, raw_path, sizeof(raw_path)) <= 0 ||
        realpath(raw_path, observed) == NULL) {
        return false;
    }
    static const char *const prefixes[] = {
        "/private/var/containers/Bundle/Application/",
        "/var/containers/Bundle/Application/",
    };
    bool app_store_path = false;
    for (size_t index = 0;
         index < sizeof(prefixes) / sizeof(prefixes[0]); ++index) {
        size_t length = strlen(prefixes[index]);
        if (strncmp(observed, prefixes[index], length) == 0) {
            app_store_path = true;
            break;
        }
    }
    if (!app_store_path) return false;

    char bundle_path[CODEX_PROC_PIDPATH_MAX] = {0};
    if (strlcpy(bundle_path, observed, sizeof(bundle_path)) >=
        sizeof(bundle_path)) {
        return false;
    }
    char *app_suffix = strstr(bundle_path, ".app/");
    if (app_suffix == NULL) return false;
    app_suffix[4] = '\0';

    NSString *bundlePath = [NSString stringWithUTF8String:bundle_path];
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
    NSString *identifier = bundle.bundleIdentifier;
    NSString *executablePath = bundle.executablePath;
    bool fixedCompatibilityTarget =
        [identifier isEqualToString:@"uk.co.bbc.news"] ||
        [identifier isEqualToString:@"org.navyfederal.nfcuforiphone"];
    if (identifier.length == 0 || executablePath.length == 0 ||
        (!fixedCompatibilityTarget &&
         !shadow_policy_enabled(identifier))) {
        return false;
    }
    char resolved_executable[CODEX_PROC_PIDPATH_MAX] = {0};
    if (realpath(executablePath.fileSystemRepresentation,
                 resolved_executable) == NULL ||
        strcmp(resolved_executable, observed) != 0) {
        return false;
    }

    NSString *containerPath = bundlePath.stringByDeletingLastPathComponent;
    NSString *markerPath = [containerPath stringByAppendingPathComponent:
        [NSString stringWithUTF8String:CODEX_SBINJECT_MANAGED_APP_MARKER]];
    if (!secure_regular_file(markerPath.fileSystemRepresentation,
                             64 * 1024, NULL)) {
        return false;
    }
    NSDictionary *marker =
        [NSDictionary dictionaryWithContentsOfFile:markerPath];
    if (![marker isKindOfClass:NSDictionary.class] ||
        [marker[@"Version"] integerValue] != 5 ||
        ![marker[@"Mode"] isEqualToString:@"TargetCompatibility"] ||
        ![marker[@"BundleIdentifier"] isEqualToString:identifier]) {
        return false;
    }

    NSString *bootstrapPath = [bundlePath stringByAppendingPathComponent:
        [NSString stringWithUTF8String:
            CODEX_SBINJECT_COMPATIBILITY_APP_BOOTSTRAP_NAME]];
    return regular_files_equal(bootstrapPath.fileSystemRepresentation,
                               CODEX_SBINJECT_SHADOW_BOOTSTRAP);
}

static bool navy_runtime_policy_app_process(pid_t pid) {
    char raw_path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(pid, raw_path, sizeof(raw_path)) <= 0 ||
        realpath(raw_path, observed) == NULL) {
        return false;
    }
    static const char *const prefixes[] = {
        "/private/var/containers/Bundle/Application/",
        "/var/containers/Bundle/Application/",
    };
    bool app_store_path = false;
    for (size_t index = 0;
         index < sizeof(prefixes) / sizeof(prefixes[0]); ++index) {
        size_t length = strlen(prefixes[index]);
        if (strncmp(observed, prefixes[index], length) == 0) {
            app_store_path = true;
            break;
        }
    }
    if (!app_store_path) return false;

    char bundle_path[CODEX_PROC_PIDPATH_MAX] = {0};
    if (strlcpy(bundle_path, observed, sizeof(bundle_path)) >=
        sizeof(bundle_path)) {
        return false;
    }
    char *app_suffix = strstr(bundle_path, ".app/");
    if (app_suffix == NULL) return false;
    app_suffix[4] = '\0';
    NSBundle *bundle = [NSBundle bundleWithPath:
        [NSString stringWithUTF8String:bundle_path]];
    NSString *identifier = bundle.bundleIdentifier;
    NSString *executablePath = bundle.executablePath;
    if (![identifier isEqualToString:@"org.navyfederal.nfcuforiphone"] ||
        executablePath.length == 0) {
        return false;
    }
    char resolved_executable[CODEX_PROC_PIDPATH_MAX] = {0};
    if (realpath(executablePath.fileSystemRepresentation,
                 resolved_executable) == NULL ||
        strcmp(resolved_executable, observed) != 0) {
        return false;
    }
    struct stat status = {0};
    return lstat(observed, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 33 && status.st_gid == 33 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool exact_process_path(pid_t pid, const char *expected_path) {
    char raw_path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    char expected[CODEX_PROC_PIDPATH_MAX] = {0};
    return pid > 1 && expected_path != NULL &&
           proc_pidpath(pid, raw_path, sizeof(raw_path)) > 0 &&
           realpath(raw_path, observed) != NULL &&
           realpath(expected_path, expected) != NULL &&
           strcmp(observed, expected) == 0;
}

static bool safe_candidate(pid_t requested, audit_token_t token) {
    pid_t caller = (pid_t)token.val[5];
    uid_t effective_user = (uid_t)token.val[1];
    bool self_request = requested == caller &&
                        (effective_user == 0 || effective_user == 501);
    bool broker_amfid_request = effective_user == 0 &&
        exact_root_process(caller, CODEX_SBINJECT_ROOT_BROKER);
    bool broker_shadow_request = effective_user == 0 &&
        exact_root_process(caller, CODEX_SBINJECT_ELLEKIT_LOADER);
    if (requested <= 1 ||
        (!self_request && !broker_amfid_request && !broker_shadow_request)) {
        return false;
    }
    char path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(requested, path, sizeof(path)) <= 0 ||
        realpath(path, observed) == NULL) {
        return false;
    }
    if (broker_shadow_request) {
        return shadow_enabled_app_process(requested);
    }
    const char *const candidates[] = {
        CODEX_SBINJECT_SPRINGBOARD,
        CODEX_SBINJECT_PREFERENCES,
        CODEX_SBINJECT_AMFID,
    };
    char configured[CODEX_PROC_PIDPATH_MAX] = {0};
    bool exact = false;
    size_t matched_index = SIZE_MAX;
    for (size_t index = 0;
         index < sizeof(candidates) / sizeof(candidates[0]); ++index) {
        if (realpath(candidates[index], configured) != NULL &&
            strcmp(configured, observed) == 0) {
            exact = true;
            matched_index = index;
            break;
        }
    }
    bool managed_app = self_request && managed_app_launcher_process(requested);
    if ((!exact && !managed_app) ||
        (broker_amfid_request &&
         matched_index != (sizeof(candidates) / sizeof(candidates[0]) - 1U))) {
        return false;
    }
    if (managed_app) return true;
    struct stat status;
    return lstat(configured, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool publish_amfid_jit_ready(pid_t pid) {
    char contents[32] = {0};
    int length = snprintf(contents, sizeof(contents), "%d\n", pid);
    if (length <= 0 || (size_t)length >= sizeof(contents)) return false;
    int marker = open(CODEX_SBINJECT_AMFID_JIT_READY_MARKER,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (marker < 0) return false;
    bool ready = write(marker, contents, (size_t)length) == (ssize_t)length &&
                 fchown(marker, 0, 0) == 0 && fchmod(marker, 0644) == 0 &&
                 fsync(marker) == 0;
    close(marker);
    if (!ready) (void)unlink(CODEX_SBINJECT_AMFID_JIT_READY_MARKER);
    return ready;
}

static void reap_exited_children(void) {
    for (;;) {
        int status = 0;
        errno = 0;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            os_log_with_type(service_log(), OS_LOG_TYPE_DEFAULT,
                             "reaped attached target pid=%d status=0x%x",
                             pid, status);
            continue;
        }
        if (pid < 0 && errno == EINTR) continue;
        return;
    }
}

static int mark_debugged(pid_t pid, bool publish_amfid_marker,
                         bool resume_target) {
    if (publish_amfid_marker) {
        (void)unlink(CODEX_SBINJECT_AMFID_JIT_READY_MARKER);
    }
    // POSIX_SPAWN_START_SUSPENDED and SIGSTOP are both signal stops, and
    // PT_ATTACHEXC can release them. A Mach task suspend count is independent
    // of ptrace. Hold app targets with that count until detach has queued a
    // fresh SIGSTOP for the loader handoff.
    task_t held_task = MACH_PORT_NULL;
    kern_return_t task_result = KERN_SUCCESS;
    kern_return_t suspend_result = KERN_SUCCESS;
    bool mach_held = false;
    bool task_was_held = false;
    kern_return_t task_resume_result = KERN_SUCCESS;
    int hold_result = 0;
    int hold_error = 0;
    if (!resume_target) {
        task_result = task_for_pid(mach_task_self(), pid, &held_task);
        if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(held_task)) {
            return EPERM;
        }
        suspend_result = task_suspend(held_task);
        if (suspend_result != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), held_task);
            return EPERM;
        }
        mach_held = true;
        task_was_held = true;
        errno = 0;
        hold_result = kill(pid, SIGSTOP);
        hold_error = hold_result == 0 ? 0 : errno;
        if (hold_result != 0) {
            (void)task_resume(held_task);
            mach_port_deallocate(mach_task_self(), held_task);
            return hold_error != 0 ? hold_error : ESRCH;
        }
    }
    errno = 0;
    if (ptrace(CODEX_PT_ATTACHEXC, pid, NULL, 0) != 0) {
        int attach_error = errno != 0 ? errno : EPERM;
        if (mach_held) {
            (void)task_resume(held_task);
            mach_port_deallocate(mach_task_self(), held_task);
        }
        return attach_error;
    }
    if (!resume_target) {
        (void)kill(pid, SIGSTOP);
    }
    // App targets arrive with POSIX_SPAWN_START_SUSPENDED. PT_ATTACHEXC marks
    // that existing task debugged, but it does not create a second waitpid
    // stop event. Poll the code-signing state directly, then detach. The
    // SIGCHLD source below still reaps a target if the attach changes its
    // eventual parent relationship.
    int stop_status = 0;
    uint32_t flags = 0;
    bool debugged = false;
    if (!mach_held) {
        for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
            if (csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
                (flags & CODEX_CS_DEBUGGED) != 0) {
                debugged = true;
                break;
            }
            usleep(10U * 1000U);
        }
    }
    int detach_result = -1;
    int detach_error = 0;
    int detach_signal = resume_target ? 0 : SIGSTOP;
    for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
        errno = 0;
        detach_result = ptrace(CODEX_PT_DETACH, pid, NULL, detach_signal);
        detach_error = detach_result == 0 ? 0 : errno;
        if (detach_result == 0 ||
            (detach_error != EBUSY && detach_error != EINTR)) {
            break;
        }
        usleep(10U * 1000U);
    }
    if (!debugged && detach_result == 0) {
        flags = 0;
        debugged = csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
                   (flags & CODEX_CS_DEBUGGED) != 0;
    }
    if (mach_held) {
        task_resume_result = task_resume(held_task);
        mach_held = false;
        mach_port_deallocate(mach_task_self(), held_task);
        held_task = MACH_PORT_NULL;
    }
    if (!debugged && detach_result == 0 &&
        task_resume_result == KERN_SUCCESS) {
        flags = 0;
        for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
            if (csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
                (flags & CODEX_CS_DEBUGGED) != 0) {
                debugged = true;
                break;
            }
            usleep(10U * 1000U);
        }
    }
    bool marker_ready = !publish_amfid_marker ||
                        (debugged && detach_result == 0 &&
                         publish_amfid_jit_ready(pid));
    int resume_result = 0;
    int resume_error = 0;
    if (resume_target) {
        errno = 0;
        resume_result = kill(pid, SIGCONT);
        resume_error = resume_result == 0 ? 0 : errno;
    }
    os_log_with_type(service_log(),
                     debugged && detach_result == 0 && resume_result == 0
                         ? OS_LOG_TYPE_DEFAULT
                         : OS_LOG_TYPE_ERROR,
                     "JIT state pid=%d stopStatus=0x%x flags=0x%08x "
                     "task=%d suspend=%d held=%{public}s hold=%d "
                     "holdError=%d taskResume=%d "
                     "debugged=%{public}s "
                     "detach=%d detachError=%d detachSignal=%d "
                     "marker=%{public}s "
                     "resume=%{public}s resumeResult=%d resumeError=%d",
                     pid, stop_status, flags, task_result, suspend_result,
                     task_was_held ? "true" : "false", hold_result,
                     hold_error,
                     task_resume_result,
                     debugged ? "true" : "false",
                     detach_result, detach_error, detach_signal,
                     marker_ready ? "true" : "false",
                     resume_target ? "true" : "false", resume_result,
                     resume_error);
    if (detach_result != 0) {
        return detach_error != 0 ? detach_error : EPERM;
    }
    if (task_resume_result != KERN_SUCCESS) return EIO;
    if (!marker_ready) return EIO;
    if (resume_result != 0) {
        return resume_error != 0 ? resume_error : EIO;
    }
    return debugged ? 0 : ETIMEDOUT;
}

static int admit_trusted_shadow_task(pid_t pid) {
    task_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(mach_task_self(), pid, &task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
        return EPERM;
    }

    task_basic_info_data_t information = {0};
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kern_return_t info_result = task_info(
        task, TASK_BASIC_INFO, (task_info_t)&information, &count);
    mach_port_deallocate(mach_task_self(), task);

    uint32_t flags = 0;
    int status_result = csops(pid, CODEX_CS_OPS_STATUS, &flags,
                              sizeof(flags));
    bool admitted = info_result == KERN_SUCCESS && status_result == 0 &&
                    (flags & CODEX_CS_VALID) != 0 &&
                    (flags & CODEX_CS_KILLED) == 0;
    os_log_with_type(service_log(),
                     admitted ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_ERROR,
                     "Shadow task admission pid=%d task=%d info=%d "
                     "flags=0x%08x admitted=%{public}s",
                     pid, task_result, info_result, flags,
                     admitted ? "true" : "false");
    return admitted ? 0 : EACCES;
}

static int socket_read_exact(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = buffer;
    size_t total = 0;
    while (total < size) {
        ssize_t amount = recv(descriptor, cursor + total, size - total, 0);
        if (amount > 0) {
            total += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) continue;
        return amount == 0 ? EPIPE : (errno != 0 ? errno : EIO);
    }
    return 0;
}

static int socket_write_exact(int descriptor, const void *buffer,
                              size_t size) {
    const uint8_t *cursor = buffer;
    size_t total = 0;
    while (total < size) {
        ssize_t amount = send(descriptor, cursor + total, size - total, 0);
        if (amount > 0) {
            total += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) continue;
        return amount == 0 ? EPIPE : (errno != 0 ? errno : EIO);
    }
    return 0;
}

static void receive_shadow_socket_request(int descriptor) {
    struct timeval timeout = {.tv_sec = 6, .tv_usec = 0};
    int no_sigpipe = 1;
    (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                     sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                     sizeof(no_sigpipe));

    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    pid_t peer_pid = -1;
    socklen_t peer_pid_size = sizeof(peer_pid);
    int result = getpeereid(descriptor, &peer_uid, &peer_gid) == 0 &&
                         getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID,
                                    &peer_pid, &peer_pid_size) == 0 &&
                         peer_pid_size == sizeof(peer_pid)
                     ? 0
                     : (errno != 0 ? errno : EPERM);

    struct codex_sbinject_shadow_request request = {0};
    if (result == 0) {
        result = socket_read_exact(descriptor, &request, sizeof(request));
    }
    pid_t requested = request.pid;
    bool admitted = result == 0 &&
                    request.magic == CODEX_SBINJECT_SHADOW_SOCKET_MAGIC &&
                    request.version == CODEX_SBINJECT_SHADOW_SOCKET_VERSION &&
                    request.reserved == 0 && requested > 1 &&
                    peer_uid == 0 &&
                    (exact_root_process(peer_pid,
                                        CODEX_SBINJECT_ELLEKIT_LOADER) ||
                     exact_root_launchd_process(peer_pid)) &&
                    (shadow_enabled_app_process(requested) ||
                     target_compatibility_app_process(requested) ||
                     navy_runtime_policy_app_process(requested));
    if (result == 0) {
        result = admitted ? admit_trusted_shadow_task(requested) : EPERM;
    }

    uint32_t flags = 0;
    if (requested > 1) {
        (void)csops(requested, CODEX_CS_OPS_STATUS, &flags, sizeof(flags));
    }
    struct codex_sbinject_shadow_response response = {
        .magic = CODEX_SBINJECT_SHADOW_SOCKET_MAGIC,
        .version = CODEX_SBINJECT_SHADOW_SOCKET_VERSION,
        .result = result,
        .flags = flags,
    };
    int write_result = socket_write_exact(descriptor, &response,
                                          sizeof(response));
    fprintf(stderr,
            "shadow socket peer=%d uid=%u gid=%u target=%d admitted=%s "
            "result=%d flags=0x%08x write=%d\n",
            peer_pid, peer_uid, peer_gid, requested,
            admitted ? "true" : "false", result, flags, write_result);
    fflush(stderr);
}

static int create_shadow_socket(void) {
    struct stat existing = {0};
    if (lstat(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET, &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid != 0 ||
            existing.st_gid != 0 ||
            (existing.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            return -1;
        }
        int probe = socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe < 0) return -1;
        struct sockaddr_un address = {0};
        address.sun_len = sizeof(address);
        address.sun_family = AF_UNIX;
        (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                       CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
        int connected = connect(probe, (struct sockaddr *)&address,
                                sizeof(address));
        int connect_error = connected == 0 ? 0 : errno;
        close(probe);
        if (connected == 0) {
            errno = EADDRINUSE;
            return -1;
        }
        if (connect_error != ECONNREFUSED && connect_error != ENOENT) {
            errno = connect_error;
            return -1;
        }
        if (unlink(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET) != 0) return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return -1;
    struct sockaddr_un address = {0};
    address.sun_len = sizeof(address);
    address.sun_family = AF_UNIX;
    int length = snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                          CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
    bool valid_path = length > 0 && (size_t)length < sizeof(address.sun_path);
    bool ready = valid_path &&
                 bind(descriptor, (struct sockaddr *)&address,
                      sizeof(address)) == 0 &&
                 chown(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET, 0, 0) == 0 &&
                 chmod(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET, 0600) == 0 &&
                 listen(descriptor, 16) == 0;
    if (!ready) {
        int saved_error = errno != 0 ? errno : EIO;
        close(descriptor);
        (void)unlink(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
        errno = saved_error;
        return -1;
    }
    int flags = fcntl(descriptor, F_GETFL, 0);
    int descriptor_flags = fcntl(descriptor, F_GETFD, 0);
    if (flags < 0 || descriptor_flags < 0 ||
        fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        int saved_error = errno != 0 ? errno : EIO;
        close(descriptor);
        (void)unlink(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
        errno = saved_error;
        return -1;
    }
    return descriptor;
}

static void accept_shadow_socket_requests(int listener) {
    for (;;) {
        int descriptor = accept(listener, NULL, NULL);
        if (descriptor >= 0) {
            receive_shadow_socket_request(descriptor);
            close(descriptor);
            continue;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        os_log_with_type(service_log(), OS_LOG_TYPE_ERROR,
                         "shadow socket accept failed: %d", errno);
        return;
    }
}

static void receive_message(mach_port_t port) {
    @autoreleasepool {
        xpc_object_t message = NULL;
        if (xpc_pipe_receive(port, &message) != 0 || message == NULL) {
            return;
        }
        xpc_object_t reply = xpc_dictionary_create_reply(message);
        int64_t result = EINVAL;
        pid_t requested = -1;
        if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
            audit_token_t token = {0};
            xpc_dictionary_get_audit_token(message, &token);
            int64_t identifier = xpc_dictionary_get_int64(message, "id");
            int64_t raw_pid = xpc_dictionary_get_int64(message, "pid");
            bool standard_request =
                identifier == CODEX_SBINJECT_JIT_MESSAGE_ID;
            bool deferred_shadow_request =
                identifier == CODEX_SBINJECT_JIT_DEFER_RESUME_MESSAGE_ID;
            if ((standard_request || deferred_shadow_request) &&
                raw_pid > 1 && raw_pid <= INT_MAX) {
                requested = (pid_t)raw_pid;
                bool publish_amfid_marker =
                    requested != (pid_t)token.val[5] &&
                    exact_process_path(requested, CODEX_SBINJECT_AMFID);
                bool deferred_admitted = deferred_shadow_request &&
                    (uid_t)token.val[1] == 0 &&
                    exact_root_process((pid_t)token.val[5],
                                       CODEX_SBINJECT_ELLEKIT_LOADER) &&
                    shadow_enabled_app_process(requested);
                bool admitted = deferred_shadow_request
                                    ? deferred_admitted
                                    : safe_candidate(requested, token);
                result = admitted
                             ? mark_debugged(requested,
                                            publish_amfid_marker,
                                            !deferred_shadow_request)
                             : EPERM;
            }
        }
        if (reply != NULL) {
            xpc_dictionary_set_int64(reply, "result", result);
            (void)xpc_pipe_routine_reply(reply);
            xpc_release(reply);
        }
        xpc_release(message);
        os_log_with_type(service_log(),
                         result == 0 ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_ERROR,
                         "JIT request pid=%d result=%lld", requested, result);
    }
}

int main(void) {
    @autoreleasepool {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t result = bootstrap_check_in(
            bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE, &port);
        if (result != KERN_SUCCESS || !MACH_PORT_VALID(port)) {
            os_log_with_type(service_log(), OS_LOG_TYPE_FAULT,
                             "bootstrap_check_in failed: %d", result);
            return 1;
        }
        int shadow_socket = create_shadow_socket();
        if (shadow_socket < 0) {
            os_log_with_type(service_log(), OS_LOG_TYPE_FAULT,
                             "shadow socket setup failed: %d", errno);
            return 1;
        }
        dispatch_source_t source = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)port, 0,
            dispatch_get_main_queue());
        if (source == NULL) {
            close(shadow_socket);
            (void)unlink(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
            return 1;
        }
        dispatch_queue_t shadow_queue = dispatch_queue_create(
            "com.openai.codex.sbinject.jitterd.shadow", DISPATCH_QUEUE_SERIAL);
        if (shadow_queue == NULL) {
            close(shadow_socket);
            (void)unlink(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
            return 1;
        }
        dispatch_source_t shadow_source = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_READ, (uintptr_t)shadow_socket, 0,
            shadow_queue);
        if (shadow_source == NULL) {
            close(shadow_socket);
            (void)unlink(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
            return 1;
        }
        dispatch_source_t child_source = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_SIGNAL, SIGCHLD, 0,
            dispatch_get_main_queue());
        if (child_source == NULL) {
            close(shadow_socket);
            (void)unlink(CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
            return 1;
        }
        dispatch_source_set_event_handler(source, ^{
            receive_message((mach_port_t)dispatch_source_get_handle(source));
        });
        dispatch_source_set_event_handler(shadow_source, ^{
            accept_shadow_socket_requests((int)dispatch_source_get_handle(
                shadow_source));
        });
        dispatch_source_set_event_handler(child_source, ^{
            reap_exited_children();
        });
        dispatch_resume(source);
        dispatch_resume(shadow_source);
        dispatch_resume(child_source);
        reap_exited_children();
        os_log_with_type(service_log(), OS_LOG_TYPE_DEFAULT,
                         "jitterd ready service=%{public}s socket=%{public}s",
                         CODEX_SBINJECT_JITTERD_SERVICE,
                         CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
        dispatch_main();
    }
}
