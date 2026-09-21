// Safety-scoped port of the supplied SBInject launchdhook.
#include "litehook_rebind.h"
#include "sbinject_protocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attributes,
                                               uint8_t launch_type);

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

__attribute__((constructor)) static void initialize_launchd_hook(void) {
    void *previous = dlopen(CODEX_SBINJECT_PREVIOUS_LAUNCHDHOOK,
                            RTLD_LAZY | RTLD_NOLOAD);
    bool chaining = previous != NULL;
    if (previous != NULL) {
        hook_log("launchd hook chaining over live previous image=%s",
                 CODEX_SBINJECT_PREVIOUS_LAUNCHDHOOK);
        dlclose(previous);
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
            CODEX_SBINJECT_PREVIOUS_LAUNCHDHOOK);
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
             "published=%s",
             spawn.matches, spawn.writes, spawn.first_error, spawnp.matches,
             spawnp.writes, spawnp.first_error,
             chaining ? "true" : "false", ready ? "true" : "false");
}
