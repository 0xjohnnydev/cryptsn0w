// Safety-scoped port of the supplied SBInject launchdhook.
#include "litehook_rebind.h"
#include "sbinject_protocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attributes,
                                               uint8_t launch_type);
extern char *sandbox_extension_issue_file(const char *extension_class,
                                          const char *path, uint32_t flags);
extern const char *APP_SANDBOX_READ;
static int (*original_posix_spawn)(pid_t *, const char *,
                                   const posix_spawn_file_actions_t *,
                                   const posix_spawnattr_t *, char *const[],
                                   char *const[]);
static int (*original_posix_spawnp)(pid_t *, const char *,
                                    const posix_spawn_file_actions_t *,
                                    const posix_spawnattr_t *, char *const[],
                                    char *const[]);

static pthread_mutex_t g_redirect_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_window_started;
static unsigned int g_window_launches;
static uint64_t g_preferences_window_started;
static unsigned int g_preferences_window_launches;

static void hook_log(const char *format, ...) {
    int descriptor = open(CODEX_SBINJECT_LOG,
                          O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return;
    }
    char line[1024];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length > 0) {
        size_t amount = (size_t)length < sizeof(line) - 1U
                            ? (size_t)length
                            : sizeof(line) - 1U;
        line[amount++] = '\n';
        (void)write(descriptor, line, amount);
    }
    close(descriptor);
}

static bool safe_root_file(const char *path, bool executable) {
    struct stat status;
    return lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
           (!executable || (status.st_mode & S_IXUSR) != 0);
}

static bool marker_is_enabled(const char *path) {
    struct stat status;
    return lstat(path, &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 && status.st_uid == 0 && status.st_gid == 0 &&
           status.st_size == 0 && (status.st_mode & 07777) == 0644;
}

static bool tweak_safe_mode_active(void) {
    struct stat status;
    return lstat(CODEX_SBINJECT_SAFE_MODE_MARKER, &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 &&
           (status.st_uid == 0 || status.st_uid == 501) &&
           status.st_size > 0 && status.st_size <= 4096 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static void reset_springboard_redirect_window(uint64_t seconds) {
    pthread_mutex_lock(&g_redirect_lock);
    g_window_started = seconds;
    g_window_launches = 0;
    pthread_mutex_unlock(&g_redirect_lock);
}

static bool enter_tweak_safe_mode(const char *reason) {
    int marker = open(CODEX_SBINJECT_SAFE_MODE_MARKER,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0600);
    if (marker < 0) {
        return false;
    }
    const char *prefix = "tweak=Unknown tweak\nreason=";
    bool wrote = write(marker, prefix, strlen(prefix)) == (ssize_t)strlen(prefix) &&
                 write(marker, reason, strlen(reason)) == (ssize_t)strlen(reason) &&
                 write(marker, "\n", 1) == 1 && fchown(marker, 501, 501) == 0 &&
                 fchmod(marker, 0600) == 0 && fsync(marker) == 0;
    close(marker);
    if (!wrote) {
        (void)unlink(CODEX_SBINJECT_SAFE_MODE_MARKER);
        return false;
    }
    hook_log("tweak safe mode armed culprit=Unknown tweak reason=%s", reason);
    return true;
}

static void disable_redirect(bool preferences, const char *reason) {
    const char *enable_marker = preferences
                                    ? CODEX_SBINJECT_PREFERENCES_ENABLE_MARKER
                                    : CODEX_SBINJECT_ENABLE_MARKER;
    const char *crash_marker = preferences
                                   ? CODEX_SBINJECT_PREFERENCES_CRASH_MARKER
                                   : CODEX_SBINJECT_CRASH_MARKER;
    (void)unlink(enable_marker);
    int marker = open(crash_marker,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0600);
    if (marker >= 0) {
        (void)write(marker, reason, strlen(reason));
        (void)write(marker, "\n", 1);
        close(marker);
    }
    hook_log("launchd redirect disabled target=%s reason=%s",
             preferences ? "Preferences" : "SpringBoard", reason);
}

static bool publish_ready_marker(void) {
    int marker = open(CODEX_SBINJECT_LAUNCHD_READY_MARKER,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (marker < 0) {
        return false;
    }
    bool ready = fchown(marker, 0, 0) == 0 && fchmod(marker, 0644) == 0 &&
                 fsync(marker) == 0;
    close(marker);
    if (!ready) {
        (void)unlink(CODEX_SBINJECT_LAUNCHD_READY_MARKER);
    }
    return ready;
}

static bool reserve_redirect_attempt(bool preferences) {
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return false;
    }
    pthread_mutex_lock(&g_redirect_lock);
    uint64_t seconds = (uint64_t)now.tv_sec;
    uint64_t *window_started = preferences ? &g_preferences_window_started
                                           : &g_window_started;
    unsigned int *window_launches =
        preferences ? &g_preferences_window_launches : &g_window_launches;
    if (*window_started == 0 || seconds < *window_started ||
        seconds - *window_started > 60U) {
        *window_started = seconds;
        *window_launches = 0;
    }
    bool allowed = *window_launches < 3U;
    if (allowed) {
        ++*window_launches;
    }
    pthread_mutex_unlock(&g_redirect_lock);
    if (!allowed) {
        const char *reason = preferences
            ? "three Preferences launches in sixty seconds"
            : "three SpringBoard launches in sixty seconds";
        if (preferences) {
            disable_redirect(true, reason);
        } else if (enter_tweak_safe_mode(reason)) {
            reset_springboard_redirect_window(seconds);
            allowed = true;
        } else {
            disable_redirect(false, reason);
        }
    }
    return allowed;
}

static const char *redirect_candidate(const char *path,
                                      bool *preferences_out) {
    if (preferences_out != NULL) {
        *preferences_out = false;
    }
    if (path == NULL) {
        return NULL;
    }
    bool safe_mode = tweak_safe_mode_active();
    if (!safe_mode &&
        access(CODEX_SBINJECT_ELLEKIT_SAFE_MODE_MARKER, F_OK) == 0) {
        (void)enter_tweak_safe_mode("ElleKit reported a SpringBoard crash");
        safe_mode = true;
    }
    if (safe_mode) {
        struct timespec now = {0};
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            reset_springboard_redirect_window((uint64_t)now.tv_sec);
        }
    }
    if (strcmp(path, CODEX_SBINJECT_STOCK_SPRINGBOARD) == 0 &&
        marker_is_enabled(CODEX_SBINJECT_ENABLE_MARKER) &&
        safe_root_file(CODEX_SBINJECT_SPRINGBOARD, true) &&
        safe_root_file(CODEX_SBINJECT_BUNDLE_HOOK, true) &&
        (safe_mode || reserve_redirect_attempt(false))) {
        return CODEX_SBINJECT_SPRINGBOARD;
    }
    if (strcmp(path, CODEX_SBINJECT_STOCK_PREFERENCES) == 0 &&
        marker_is_enabled(CODEX_SBINJECT_PREFERENCES_ENABLE_MARKER) &&
        safe_root_file(CODEX_SBINJECT_PREFERENCES, true) &&
        safe_root_file(CODEX_SBINJECT_PREFERENCES_HOOK, true) &&
        reserve_redirect_attempt(true)) {
        if (preferences_out != NULL) {
            *preferences_out = true;
        }
        return CODEX_SBINJECT_PREFERENCES;
    }
    return NULL;
}

static bool colon_list_contains(const char *list, const char *value) {
    if (list == NULL || value == NULL || value[0] == '\0') {
        return false;
    }
    size_t value_length = strlen(value);
    const char *cursor = list;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ':');
        size_t length = end != NULL ? (size_t)(end - cursor) : strlen(cursor);
        if (length == value_length && memcmp(cursor, value, length) == 0) {
            return true;
        }
        if (end == NULL) {
            break;
        }
        cursor = end + 1;
    }
    return false;
}

static bool app_store_executable(const char *path) {
    static const char *const prefixes[] = {
        "/private/var/containers/Bundle/Application/",
        "/var/containers/Bundle/Application/",
    };
    if (path == NULL) {
        return false;
    }
    const char *relative = NULL;
    for (size_t index = 0;
         index < sizeof(prefixes) / sizeof(prefixes[0]); ++index) {
        size_t length = strlen(prefixes[index]);
        if (strncmp(path, prefixes[index], length) == 0) {
            relative = path + length;
            break;
        }
    }
    if (relative == NULL || relative[0] == '\0') {
        return false;
    }
    const char *bundle = strstr(relative, ".app/");
    return bundle != NULL && bundle[5] != '\0' &&
           strchr(bundle + 5, '/') == NULL;
}

static int wait_for_shadow_preparer(pid_t child) {
    int status = 0;
    for (unsigned int attempt = 0; attempt < 3000U; ++attempt) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
        }
        if (result < 0 && errno != EINTR) return 126;
        usleep(10 * 1000);
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return 124;
}

static int prepare_shadow_target(const char *path) {
    if (!safe_root_file(CODEX_SBINJECT_ELLEKIT_LOADER, true) || path == NULL) {
        return 126;
    }
    char *arguments[] = {
        (char *)CODEX_SBINJECT_ELLEKIT_LOADER,
        "--prepare-enabled-shadow-path",
        (char *)path,
        NULL,
    };
    char *environment[] = {
        "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/var/root",
        NULL,
    };
    pid_t helper = 0;
    int result = original_posix_spawn(
        &helper, CODEX_SBINJECT_ELLEKIT_LOADER, NULL, NULL, arguments,
        environment);
    if (result != 0 || helper <= 1) return result != 0 ? result : 126;
    return wait_for_shadow_preparer(helper);
}

static int shadow_socket_write_exact(int descriptor, const void *buffer,
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

static int shadow_socket_read_exact(int descriptor, void *buffer,
                                    size_t size) {
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

static int request_shadow_debug_state(pid_t target, uint32_t *flags_out) {
    if (flags_out != NULL) *flags_out = 0;
    if (target <= 1) return EINVAL;

    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return errno != 0 ? errno : EIO;
    struct timeval timeout = {.tv_sec = 6, .tv_usec = 0};
    int no_sigpipe = 1;
    (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                     sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                     sizeof(no_sigpipe));

    struct sockaddr_un address = {0};
    address.sun_len = sizeof(address);
    address.sun_family = AF_UNIX;
    int length = snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                          CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
    int result = 0;
    if (length <= 0 || (size_t)length >= sizeof(address.sun_path)) {
        result = ENAMETOOLONG;
    } else if (connect(descriptor, (struct sockaddr *)&address,
                       sizeof(address)) != 0) {
        result = errno != 0 ? errno : EIO;
    }

    struct codex_sbinject_shadow_request request = {
        .magic = CODEX_SBINJECT_SHADOW_SOCKET_MAGIC,
        .version = CODEX_SBINJECT_SHADOW_SOCKET_VERSION,
        .pid = target,
        .reserved = 0,
    };
    if (result == 0) {
        result = shadow_socket_write_exact(descriptor, &request,
                                           sizeof(request));
    }
    struct codex_sbinject_shadow_response response = {0};
    if (result == 0) {
        result = shadow_socket_read_exact(descriptor, &response,
                                          sizeof(response));
    }
    close(descriptor);
    if (result == 0 &&
        (response.magic != CODEX_SBINJECT_SHADOW_SOCKET_MAGIC ||
         response.version != CODEX_SBINJECT_SHADOW_SOCKET_VERSION)) {
        result = EPROTO;
    }
    if (result == 0) result = response.result;
    if (flags_out != NULL) *flags_out = response.flags;
    return result;
}

static bool start_shadow_broker(pid_t target, pid_t *helper_out) {
    if (target <= 1 ||
        !safe_root_file(CODEX_SBINJECT_ELLEKIT_LOADER, true) ||
        !safe_root_file(CODEX_SBINJECT_SHADOW_CORE, false)) {
        return false;
    }
    char target_text[32] = {0};
    int length = snprintf(target_text, sizeof(target_text), "%d", target);
    if (length <= 0 || (size_t)length >= sizeof(target_text)) return false;
    char *arguments[] = {
        (char *)CODEX_SBINJECT_ELLEKIT_LOADER,
        "--inject-enabled-shadow-and-resume-pid",
        target_text,
        NULL,
    };
    char *environment[] = {
        "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/var/root",
        NULL,
    };
    pid_t helper = 0;
    int result = original_posix_spawn(
        &helper, CODEX_SBINJECT_ELLEKIT_LOADER, NULL, NULL, arguments,
        environment);
    if (helper_out != NULL) *helper_out = result == 0 ? helper : -1;
    hook_log("app Shadow broker target=%d result=%d helper=%d", target,
             result, result == 0 ? helper : -1);
    return result == 0 && helper > 1;
}

static bool start_compatibility_broker(pid_t target, const char *dylib,
                                       pid_t *helper_out) {
    if (target <= 1 || dylib == NULL ||
        !safe_root_file(CODEX_SBINJECT_ELLEKIT_LOADER, true) ||
        !safe_root_file(dylib, false)) {
        return false;
    }
    char target_text[32] = {0};
    int length = snprintf(target_text, sizeof(target_text), "%d", target);
    if (length <= 0 || (size_t)length >= sizeof(target_text)) return false;
    char *arguments[] = {
        (char *)CODEX_SBINJECT_ELLEKIT_LOADER,
        "--inject-and-resume-pid",
        target_text,
        (char *)dylib,
        NULL,
    };
    char *environment[] = {
        "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/var/root",
        NULL,
    };
    pid_t helper = 0;
    int result = original_posix_spawn(
        &helper, CODEX_SBINJECT_ELLEKIT_LOADER, NULL, NULL, arguments,
        environment);
    if (helper_out != NULL) *helper_out = result == 0 ? helper : -1;
    hook_log("app compatibility broker target=%d result=%d helper=%d",
             target, result, result == 0 ? helper : -1);
    return result == 0 && helper > 1;
}

static bool start_navy_patch_broker(pid_t target, pid_t *helper_out) {
    if (target <= 1 ||
        !safe_root_file(CODEX_SBINJECT_ELLEKIT_LOADER, true)) {
        return false;
    }
    char target_text[32] = {0};
    int length = snprintf(target_text, sizeof(target_text), "%d", target);
    if (length <= 0 || (size_t)length >= sizeof(target_text)) return false;
    char *arguments[] = {
        (char *)CODEX_SBINJECT_ELLEKIT_LOADER,
        "--patch-navy-and-resume-pid",
        target_text,
        NULL,
    };
    char *environment[] = {
        "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/var/root",
        NULL,
    };
    pid_t helper = 0;
    int result = original_posix_spawn(
        &helper, CODEX_SBINJECT_ELLEKIT_LOADER, NULL, NULL, arguments,
        environment);
    if (helper_out != NULL) *helper_out = result == 0 ? helper : -1;
    hook_log("app Navy runtime policy broker target=%d result=%d helper=%d",
             target, result, result == 0 ? helper : -1);
    return result == 0 && helper > 1;
}

static bool start_ring_policy_broker(pid_t target, pid_t *helper_out) {
    if (target <= 1 ||
        !safe_root_file(CODEX_SBINJECT_ELLEKIT_LOADER, true)) {
        return false;
    }
    char target_text[32] = {0};
    int length = snprintf(target_text, sizeof(target_text), "%d", target);
    if (length <= 0 || (size_t)length >= sizeof(target_text)) return false;
    char *arguments[] = {
        (char *)CODEX_SBINJECT_ELLEKIT_LOADER,
        "--protect-ring-and-resume-pid",
        target_text,
        NULL,
    };
    char *environment[] = {
        "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/var/root",
        NULL,
    };
    pid_t helper = 0;
    int result = original_posix_spawn(
        &helper, CODEX_SBINJECT_ELLEKIT_LOADER, NULL, NULL, arguments,
        environment);
    if (helper_out != NULL) *helper_out = result == 0 ? helper : -1;
    hook_log("app Ring runtime policy broker target=%d result=%d helper=%d",
             target, result, result == 0 ? helper : -1);
    return result == 0 && helper > 1;
}

static int spawn_with_runtime_policy(
    int (*implementation)(pid_t *, const char *,
                          const posix_spawn_file_actions_t *,
                          const posix_spawnattr_t *, char *const[],
                          char *const[]),
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[], const char *label, bool ring_policy) {
    const char *policy = ring_policy ? "Ring" : "Navy";
    if (tweak_safe_mode_active() ||
        access(CODEX_SBINJECT_ELLEKIT_SAFE_MODE_MARKER, F_OK) == 0 ||
        !safe_root_file(CODEX_SBINJECT_ELLEKIT_LOADER, true)) {
        hook_log("app %s runtime policy refused label=%s", policy, label);
        return EACCES;
    }

    short original_flags = 0;
    bool changed_flags = false;
    posix_spawnattr_t local_attributes = NULL;
    const posix_spawnattr_t *effective_attributes = attributes;
    int status = 0;
    if (attributes != NULL) {
        status = posix_spawnattr_getflags(attributes, &original_flags);
        if (status == 0 &&
            (original_flags & POSIX_SPAWN_START_SUSPENDED) == 0) {
            status = posix_spawnattr_setflags(
                (posix_spawnattr_t *)attributes,
                (short)(original_flags | POSIX_SPAWN_START_SUSPENDED));
            changed_flags = status == 0;
        }
    } else {
        status = posix_spawnattr_init(&local_attributes);
        if (status == 0) {
            status = posix_spawnattr_setflags(
                &local_attributes, POSIX_SPAWN_START_SUSPENDED);
        }
        if (status == 0) effective_attributes = &local_attributes;
    }
    if (status == 0) {
        status = posix_spawnattr_set_launch_type_np(
            (posix_spawnattr_t *)effective_attributes, 0);
    }
    if (status != 0) {
        if (changed_flags) {
            (void)posix_spawnattr_setflags((posix_spawnattr_t *)attributes,
                                           original_flags);
        }
        if (local_attributes != NULL) {
            posix_spawnattr_destroy(&local_attributes);
        }
        hook_log("app %s runtime policy cannot suspend label=%s error=%d",
                 policy, label, status);
        return status;
    }

    int result = implementation(pid, path, file_actions, effective_attributes,
                                arguments, environment);
    if (changed_flags) {
        (void)posix_spawnattr_setflags((posix_spawnattr_t *)attributes,
                                       original_flags);
    }
    if (local_attributes != NULL) {
        posix_spawnattr_destroy(&local_attributes);
    }

    int debug_result = 0;
    uint32_t debug_flags = 0;
    pid_t helper = -1;
    bool admitted = false;
    if (result == 0 && pid != NULL && *pid > 1) {
        debug_result = request_shadow_debug_state(*pid, &debug_flags);
        admitted = debug_result == 0 &&
            (ring_policy ? start_ring_policy_broker(*pid, &helper)
                         : start_navy_patch_broker(*pid, &helper));
        if (!admitted) {
            (void)kill(*pid, SIGKILL);
            result = debug_result != 0 ? debug_result : EIO;
        }
    }
    hook_log("app %s runtime policy handoff label=%s result=%d pid=%d "
             "debug=%d flags=0x%08x broker=%s helper=%d",
             policy, label, result, result == 0 && pid != NULL ? *pid : -1,
             debug_result, debug_flags, admitted ? "true" : "false",
             helper);
    return result;
}

static int spawn_with_ellekit(
    int (*implementation)(pid_t *, const char *,
                          const posix_spawn_file_actions_t *,
                          const posix_spawnattr_t *, char *const[],
                          char *const[]),
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[], const char *dylib, const char *kind,
    const char *label, bool debug_admission, bool compatibility_broker,
    bool required);

static int spawn_with_shadow_broker(
    int (*implementation)(pid_t *, const char *,
                          const posix_spawn_file_actions_t *,
                          const posix_spawnattr_t *, char *const[],
                          char *const[]),
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[], const char *label) {
    const char *leaf = path != NULL ? strrchr(path, '/') : NULL;
    char bootstrap[PATH_MAX] = {0};
    int length = leaf != NULL
        ? snprintf(bootstrap, sizeof(bootstrap), "%.*s/%s",
                   (int)(leaf - path), path,
                   CODEX_SBINJECT_SHADOW_APP_BOOTSTRAP_NAME)
        : -1;
    if (length <= 0 || (size_t)length >= sizeof(bootstrap) ||
        !safe_root_file(bootstrap, false)) {
        hook_log("app Shadow bootstrap unavailable label=%s", label);
        return EACCES;
    }
    return spawn_with_ellekit(
        implementation, pid, path, file_actions, attributes, arguments,
        environment, bootstrap, "app Shadow", label, true, false,
        true);
}

static int spawn_with_target_compatibility(
    int (*implementation)(pid_t *, const char *,
                          const posix_spawn_file_actions_t *,
                          const posix_spawnattr_t *, char *const[],
                          char *const[]),
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[], const char *label) {
    const char *leaf = path != NULL ? strrchr(path, '/') : NULL;
    char bootstrap[PATH_MAX] = {0};
    int length = leaf != NULL
        ? snprintf(bootstrap, sizeof(bootstrap), "%.*s/%s",
                   (int)(leaf - path), path,
                   CODEX_SBINJECT_COMPATIBILITY_APP_BOOTSTRAP_NAME)
        : -1;
    if (length <= 0 || (size_t)length >= sizeof(bootstrap) ||
        !safe_root_file(bootstrap, false)) {
        hook_log("app compatibility bootstrap unavailable label=%s", label);
        return EACCES;
    }
    return spawn_with_ellekit(
        implementation, pid, path, file_actions, attributes, arguments,
        environment, bootstrap, "app compatibility", label, true, true,
        true);
}

static int spawn_with_ellekit(
    int (*implementation)(pid_t *, const char *,
                          const posix_spawn_file_actions_t *,
                          const posix_spawnattr_t *, char *const[],
                          char *const[]),
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[], const char *dylib, const char *kind,
    const char *label, bool debug_admission, bool compatibility_broker,
    bool required) {
    static const char dyld_prefix[] = "DYLD_INSERT_LIBRARIES=";
    static const char sandbox_prefix[] = "SANDBOX_EXTENSION=";
    if (tweak_safe_mode_active() ||
        access(CODEX_SBINJECT_ELLEKIT_SAFE_MODE_MARKER, F_OK) == 0 ||
        !safe_root_file(dylib, false)) {
        if (required) {
            hook_log("%s broker refused: payload unavailable label=%s", kind,
                     label);
            return EACCES;
        }
        return implementation(pid, path, file_actions, attributes, arguments,
                              environment);
    }

    size_t count = 0;
    size_t dyld_index = SIZE_MAX;
    size_t sandbox_index = SIZE_MAX;
    const char *existing_dyld = NULL;
    if (environment != NULL) {
        while (environment[count] != NULL && count < 4096U) {
            if (strncmp(environment[count], dyld_prefix,
                        sizeof(dyld_prefix) - 1U) == 0 &&
                dyld_index == SIZE_MAX) {
                dyld_index = count;
                existing_dyld =
                    environment[count] + sizeof(dyld_prefix) - 1U;
            }
            if (strncmp(environment[count], sandbox_prefix,
                        sizeof(sandbox_prefix) - 1U) == 0 &&
                sandbox_index == SIZE_MAX) {
                sandbox_index = count;
            }
            ++count;
        }
        if (count == 4096U) {
            hook_log("%s injection skipped: environment is too large", kind);
            if (required) return E2BIG;
            return implementation(pid, path, file_actions, attributes,
                                  arguments, environment);
        }
    }

    char resolved_root[PATH_MAX] = {0};
    char *extensions[3] = {NULL, NULL, NULL};
    size_t extension_count = debug_admission ? 3U : 1U;
    if (realpath("/var/jb", resolved_root) != NULL &&
        APP_SANDBOX_READ != NULL) {
        extensions[0] = sandbox_extension_issue_file(
            APP_SANDBOX_READ, resolved_root, 0);
        if (debug_admission) {
            extensions[1] = sandbox_extension_issue_file(
                "com.apple.sandbox.executable", resolved_root, 0);
            extensions[2] = sandbox_extension_issue_file(
                APP_SANDBOX_READ,
                "/var/mobile/Library/Preferences/me.jjolano.shadow.plist",
                0);
        }
    }
    bool extensions_ready = true;
    for (size_t index = 0; index < extension_count; ++index) {
        extensions_ready = extensions_ready && extensions[index] != NULL;
    }
    if (!extensions_ready) {
        for (size_t index = 0; index < 3; ++index) free(extensions[index]);
        hook_log("%s injection skipped: sandbox extension failed label=%s",
                 kind, label);
        if (required) return EACCES;
        return implementation(pid, path, file_actions, attributes, arguments,
                              environment);
    }

    bool add_dylib = !colon_list_contains(existing_dyld, dylib);
    size_t dyld_length = 0;
    char *dyld_value = NULL;
    if (add_dylib) {
        dyld_length = sizeof(dyld_prefix) - 1U + strlen(dylib) + 1U;
        if (existing_dyld != NULL && existing_dyld[0] != '\0') {
            dyld_length += 1U + strlen(existing_dyld);
        }
        dyld_value = malloc(dyld_length);
    }
    size_t extension_length = 1U;
    for (size_t index = 0; index < extension_count; ++index) {
        extension_length += strlen(extensions[index]);
        if (index + 1U < extension_count) ++extension_length;
    }
    char *extension_value = malloc(extension_length);
    if (extension_value != NULL) {
        size_t used = 0;
        extension_value[0] = '\0';
        for (size_t index = 0; index < extension_count; ++index) {
            int written = snprintf(extension_value + used,
                                   extension_length - used, "%s%s",
                                   index == 0 ? "" : "|",
                                   extensions[index]);
            if (written < 0 || (size_t)written >= extension_length - used) {
                free(extension_value);
                extension_value = NULL;
                break;
            }
            used += (size_t)written;
        }
    }
    size_t sandbox_length = sizeof(sandbox_prefix) - 1U +
                            (extension_value != NULL
                                 ? strlen(extension_value) : 0U) + 1U;
    char *sandbox_value = malloc(sandbox_length);
    size_t extra = (add_dylib && dyld_index == SIZE_MAX ? 1U : 0U) +
                   (sandbox_index == SIZE_MAX ? 1U : 0U);
    char **updated = calloc(count + extra + 1U, sizeof(*updated));
    if ((add_dylib && dyld_value == NULL) || extension_value == NULL ||
        sandbox_value == NULL || updated == NULL) {
        for (size_t index = 0; index < 3; ++index) free(extensions[index]);
        free(extension_value);
        free(dyld_value);
        free(sandbox_value);
        free(updated);
        hook_log("%s injection skipped: allocation failed", kind);
        if (required) return ENOMEM;
        return implementation(pid, path, file_actions, attributes, arguments,
                              environment);
    }

    if (add_dylib) {
        if (existing_dyld != NULL && existing_dyld[0] != '\0') {
            (void)snprintf(dyld_value, dyld_length, "%s%s:%s", dyld_prefix,
                           dylib, existing_dyld);
        } else {
            (void)snprintf(dyld_value, dyld_length, "%s%s", dyld_prefix,
                           dylib);
        }
    }
    (void)snprintf(sandbox_value, sandbox_length, "%s%s", sandbox_prefix,
                   extension_value);
    for (size_t index = 0; index < count; ++index) {
        updated[index] = environment[index];
    }
    size_t next = count;
    if (add_dylib) {
        if (dyld_index == SIZE_MAX) {
            dyld_index = next++;
        }
        updated[dyld_index] = dyld_value;
    }
    if (sandbox_index == SIZE_MAX) {
        sandbox_index = next++;
    }
    updated[sandbox_index] = sandbox_value;

    short original_flags = 0;
    bool changed_flags = false;
    posix_spawnattr_t local_attributes = NULL;
    const posix_spawnattr_t *effective_attributes = attributes;
    if (debug_admission) {
        int status = 0;
        if (attributes != NULL) {
            status = posix_spawnattr_getflags(attributes, &original_flags);
            if (status == 0 &&
                (original_flags & POSIX_SPAWN_START_SUSPENDED) == 0) {
                status = posix_spawnattr_setflags(
                    (posix_spawnattr_t *)attributes,
                    (short)(original_flags | POSIX_SPAWN_START_SUSPENDED));
                changed_flags = status == 0;
            } else if (status == 0) {
                status = EBUSY;
            }
        } else {
            status = posix_spawnattr_init(&local_attributes);
            if (status == 0) {
                status = posix_spawnattr_setflags(
                    &local_attributes, POSIX_SPAWN_START_SUSPENDED);
            }
            if (status == 0) {
                effective_attributes = &local_attributes;
            }
        }
        if (status != 0) {
            if (local_attributes != NULL) {
                posix_spawnattr_destroy(&local_attributes);
            }
            free(updated);
            free(sandbox_value);
            free(dyld_value);
            free(extension_value);
            for (size_t index = 0; index < 3; ++index) {
                free(extensions[index]);
            }
            hook_log("%s injection skipped: cannot suspend label=%s error=%d",
                     kind, label, status);
            if (required) return status;
            return implementation(pid, path, file_actions, attributes,
                                  arguments, environment);
        }
    }

    if (required) {
        int status = posix_spawnattr_set_launch_type_np(
            (posix_spawnattr_t *)effective_attributes, 0);
        if (status != 0) {
            if (changed_flags) {
                (void)posix_spawnattr_setflags(
                    (posix_spawnattr_t *)attributes, original_flags);
            }
            if (local_attributes != NULL) {
                posix_spawnattr_destroy(&local_attributes);
            }
            free(updated);
            free(sandbox_value);
            free(dyld_value);
            free(extension_value);
            for (size_t index = 0; index < 3; ++index) {
                free(extensions[index]);
            }
            hook_log("%s broker cannot set launch type label=%s error=%d",
                     kind, label, status);
            return status;
        }
    }

    int result = implementation(pid, path, file_actions, effective_attributes,
                                arguments, updated);
    if (changed_flags) {
        (void)posix_spawnattr_setflags((posix_spawnattr_t *)attributes,
                                       original_flags);
    }
    if (local_attributes != NULL) {
        posix_spawnattr_destroy(&local_attributes);
    }

    bool admitted = !debug_admission;
    int debug_result = 0;
    uint32_t debug_flags = 0;
    pid_t helper = -1;
    if (result == 0 && debug_admission && pid != NULL && *pid > 1) {
        debug_result = request_shadow_debug_state(*pid, &debug_flags);
        admitted = debug_result == 0 &&
            (compatibility_broker
                 ? start_compatibility_broker(*pid, dylib, &helper)
                 : start_shadow_broker(*pid, &helper));
        if (!admitted) {
            if (required) {
                (void)kill(*pid, SIGKILL);
                result = debug_result != 0 ? debug_result : EIO;
            } else {
                (void)kill(*pid, SIGCONT);
            }
        }
    }
    hook_log("%s ElleKit handoff label=%s result=%d pid=%d debug=%d "
             "flags=0x%08x broker=%s helper=%d",
             kind, label, result, result == 0 && pid != NULL ? *pid : -1,
             debug_result, debug_flags, admitted ? "true" : "false",
             helper);
    free(updated);
    free(sandbox_value);
    free(dyld_value);
    free(extension_value);
    for (size_t index = 0; index < 3; ++index) free(extensions[index]);
    return result;
}

static int spawn_redirected(
    bool search_path, pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[]) {
    int (*implementation)(pid_t *, const char *,
                          const posix_spawn_file_actions_t *,
                          const posix_spawnattr_t *, char *const[],
                          char *const[]) =
        search_path ? original_posix_spawnp : original_posix_spawn;
    if (path != NULL && strcmp(path, CODEX_SBINJECT_XPCPROXY) == 0) {
        const char *service = arguments != NULL && arguments[1] != NULL
                                  ? arguments[1]
                                  : "unknown";
        return spawn_with_ellekit(
            implementation, pid, path, file_actions, attributes, arguments,
            environment, CODEX_SBINJECT_ELLEKIT_PSPAWN, "xpcproxy", service,
            false, false, false);
    }
    if (app_store_executable(path)) {
        const char *leaf = strrchr(path, '/');
        int preparation = prepare_shadow_target(path);
        int first_preparation = preparation;
        if (preparation >= 79 && preparation <= 81) {
            usleep(100U * 1000U);
            preparation = prepare_shadow_target(path);
        }
        if (first_preparation != preparation) {
            hook_log("app Shadow prepare retry label=%s first=%d second=%d",
                     leaf != NULL ? leaf + 1 : path, first_preparation,
                     preparation);
        }
        hook_log("app Shadow prepare label=%s result=%d",
                 leaf != NULL ? leaf + 1 : path, preparation);
        if (preparation == 72 || preparation == 73) {
            return spawn_with_runtime_policy(
                implementation, pid, path, file_actions, attributes,
                arguments, environment, leaf != NULL ? leaf + 1 : path,
                preparation == 72);
        }
        if (preparation == 74) {
            return spawn_with_target_compatibility(
                implementation, pid, path, file_actions, attributes,
                arguments, environment, leaf != NULL ? leaf + 1 : path);
        }
        if (preparation != 0) {
            if (preparation != 75) {
                hook_log("app Shadow broker refused label=%s prepare=%d",
                         leaf != NULL ? leaf + 1 : path, preparation);
                return EACCES;
            }
            return implementation(pid, path, file_actions, attributes,
                                  arguments, environment);
        }
        return spawn_with_shadow_broker(
            implementation, pid, path, file_actions, attributes, arguments,
            environment, leaf != NULL ? leaf + 1 : path);
    }
    bool preferences = false;
    const char *redirected_path = redirect_candidate(path, &preferences);
    if (redirected_path == NULL) {
        return implementation(pid, path, file_actions, attributes, arguments,
                              environment);
    }

    char **mutable_arguments = (char **)arguments;
    char *saved_argument_zero =
        mutable_arguments != NULL ? mutable_arguments[0] : NULL;
    if (arguments != NULL) {
        mutable_arguments[0] = (char *)redirected_path;
    }
    if (attributes != NULL) {
        (void)posix_spawnattr_set_launch_type_np(
            (posix_spawnattr_t *)attributes, 0);
    }
    const char *target = preferences ? "Preferences" : "SpringBoard";
    hook_log("redirecting %s to %s", target, redirected_path);
    int result = implementation(pid, redirected_path, file_actions, attributes,
                                arguments, environment);
    if (arguments != NULL) {
        mutable_arguments[0] = saved_argument_zero;
    }
    if (result == 0) {
        return 0;
    }

    hook_log("redirected %s spawn failed error=%d; using stock", target,
             result);
    disable_redirect(preferences, "redirected posix_spawn failed");
    return implementation(pid, path, file_actions, attributes, arguments,
                          environment);
}

static int hooked_posix_spawn(
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[]) {
    return spawn_redirected(false, pid, path, file_actions, attributes,
                            arguments, environment);
}

static int hooked_posix_spawnp(
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[]) {
    return spawn_redirected(true, pid, path, file_actions, attributes,
                            arguments, environment);
}

static int hooked_chained_spawn(
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const arguments[],
    char *const environment[]) {
    bool search_path = path != NULL && strchr(path, '/') == NULL;
    return spawn_redirected(search_path, pid, path, file_actions, attributes,
                            arguments, environment);
}

static bool find_live_previous_launchd_hook(char path[PATH_MAX]) {
    if (path == NULL) return false;
    path[0] = '\0';
    for (unsigned int generation =
             CODEX_SBINJECT_LAUNCHDHOOK_GENERATION - 1U;
         generation > 0; --generation) {
        int length = snprintf(path, PATH_MAX, "%s%u.dylib",
                              CODEX_SBINJECT_LAUNCHDHOOK_PREFIX, generation);
        if (length <= 0 || length >= PATH_MAX) {
            path[0] = '\0';
            return false;
        }
        void *previous = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
        if (previous == NULL) continue;
        dlclose(previous);
        return true;
    }
    path[0] = '\0';
    return false;
}

__attribute__((constructor)) static void initialize_launchd_hook(void) {
    char previous_path[PATH_MAX] = {0};
    bool chaining = find_live_previous_launchd_hook(previous_path);
    if (chaining) {
        hook_log("launchd hook chaining over live previous image=%s",
                 previous_path);
    }
    original_posix_spawn = dlsym(RTLD_DEFAULT, "posix_spawn");
    original_posix_spawnp = dlsym(RTLD_DEFAULT, "posix_spawnp");
    if (original_posix_spawn == NULL || original_posix_spawnp == NULL) {
        hook_log("launchd hook initialization failed: spawn symbols missing");
        return;
    }
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    litehook_rebind_result_t spawn = {0};
    litehook_rebind_result_t spawnp = {0};
    bool rebound = false;
    if (chaining) {
        // The previous generation owns both launchd import slots. Take them
        // over in one pass; matching "any pointer in the previous image" in
        // two passes would consume both during the first pass and make the
        // second pass report a false failure.
        spawn = litehook_rebind_symbol_with_previous_image(
            header, original_posix_spawn, hooked_chained_spawn,
            previous_path);
        rebound = spawn.matches > 0 && spawn.writes == spawn.matches;
    } else {
        spawn = litehook_rebind_symbol(
            header, original_posix_spawn, hooked_posix_spawn);
        spawnp = litehook_rebind_symbol(
            header, original_posix_spawnp, hooked_posix_spawnp);
        rebound = spawn.matches > 0 && spawn.writes == spawn.matches &&
                  spawnp.matches > 0 && spawnp.writes == spawnp.matches;
    }
    bool ready = rebound && publish_ready_marker();
    hook_log("launchd hook ready posix_spawn matches=%zu writes=%zu kr=%d "
             "posix_spawnp matches=%zu writes=%zu kr=%d chaining=%s "
             "previous=%s published=%s",
             spawn.matches, spawn.writes, spawn.first_error, spawnp.matches,
             spawnp.writes, spawnp.first_error,
             chaining ? "true" : "false",
             chaining ? previous_path : "none",
             ready ? "true" : "false");
}
