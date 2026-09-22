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
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
#define CODEX_PROC_PIDPATH_MAX 4096
#define CODEX_CS_OPS_STATUS 0U
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

static bool safe_candidate(pid_t requested, audit_token_t token) {
    pid_t caller = (pid_t)token.val[5];
    uid_t effective_user = (uid_t)token.val[1];
    bool self_request = requested == caller &&
                        (effective_user == 0 || effective_user == 501);
    bool broker_amfid_request = effective_user == 0 &&
        exact_root_process(caller, CODEX_SBINJECT_ROOT_BROKER);
    if (requested <= 1 || (!self_request && !broker_amfid_request)) {
        return false;
    }
    char path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(requested, path, sizeof(path)) <= 0 ||
        realpath(path, observed) == NULL) {
        return false;
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

static int mark_debugged(pid_t pid, bool publish_amfid_marker) {
    if (publish_amfid_marker) {
        (void)unlink(CODEX_SBINJECT_AMFID_JIT_READY_MARKER);
    }
    errno = 0;
    if (ptrace(CODEX_PT_ATTACHEXC, pid, NULL, 0) != 0) {
        return errno != 0 ? errno : EPERM;
    }
    uint32_t flags = 0;
    bool debugged = false;
    for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
        if (csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
            (flags & CODEX_CS_DEBUGGED) != 0) {
            debugged = true;
            break;
        }
        usleep(10U * 1000U);
    }
    int detach_result = -1;
    int detach_error = 0;
    for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
        errno = 0;
        detach_result = ptrace(CODEX_PT_DETACH, pid, NULL, 0);
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
    bool marker_ready = !publish_amfid_marker ||
                        (debugged && detach_result == 0 &&
                         publish_amfid_jit_ready(pid));
    (void)kill(pid, SIGCONT);
    os_log_with_type(service_log(),
                     debugged && detach_result == 0
                         ? OS_LOG_TYPE_DEFAULT
                         : OS_LOG_TYPE_ERROR,
                     "JIT state pid=%d flags=0x%08x debugged=%{public}s "
                     "detach=%d detachError=%d marker=%{public}s",
                     pid, flags, debugged ? "true" : "false",
                     detach_result, detach_error,
                     marker_ready ? "true" : "false");
    if (detach_result != 0) {
        return detach_error != 0 ? detach_error : EPERM;
    }
    if (!marker_ready) return EIO;
    return debugged ? 0 : ETIMEDOUT;
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
            if (identifier == CODEX_SBINJECT_JIT_MESSAGE_ID && raw_pid > 1 &&
                raw_pid <= INT_MAX) {
                requested = (pid_t)raw_pid;
                bool broker_request = requested != (pid_t)token.val[5];
                result = safe_candidate(requested, token)
                             ? mark_debugged(requested, broker_request)
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
        dispatch_source_t source = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)port, 0,
            dispatch_get_main_queue());
        if (source == NULL) {
            return 1;
        }
        dispatch_source_set_event_handler(source, ^{
            receive_message((mach_port_t)dispatch_source_get_handle(source));
        });
        dispatch_resume(source);
        os_log_with_type(service_log(), OS_LOG_TYPE_DEFAULT,
                         "jitterd ready service=%{public}s",
                         CODEX_SBINJECT_JITTERD_SERVICE);
        dispatch_main();
    }
}
