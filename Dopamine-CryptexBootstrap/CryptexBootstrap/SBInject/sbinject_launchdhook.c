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

static bool marker_is_enabled(void) {
    struct stat status;
    return lstat(CODEX_SBINJECT_ENABLE_MARKER, &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 && status.st_uid == 0 && status.st_gid == 0 &&
           status.st_size == 0 && (status.st_mode & 07777) == 0644;
}

static void disable_redirect(const char *reason) {
    (void)unlink(CODEX_SBINJECT_ENABLE_MARKER);
    int marker = open(CODEX_SBINJECT_CRASH_MARKER,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0600);
    if (marker >= 0) {
        (void)write(marker, reason, strlen(reason));
        (void)write(marker, "\n", 1);
        close(marker);
    }
    hook_log("launchd redirect disabled reason=%s", reason);
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

static bool reserve_redirect_attempt(void) {
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return false;
    }
    pthread_mutex_lock(&g_redirect_lock);
    uint64_t seconds = (uint64_t)now.tv_sec;
    if (g_window_started == 0 || seconds < g_window_started ||
        seconds - g_window_started > 60U) {
        g_window_started = seconds;
        g_window_launches = 0;
    }
    bool allowed = g_window_launches < 3U;
    if (allowed) {
        ++g_window_launches;
    }
    pthread_mutex_unlock(&g_redirect_lock);
    if (!allowed) {
        disable_redirect("three SpringBoard launches in sixty seconds");
    }
    return allowed;
}

static bool should_redirect(const char *path) {
    return path != NULL &&
           strcmp(path, CODEX_SBINJECT_STOCK_SPRINGBOARD) == 0 &&
           access("/var/mobile/.eksafemode", F_OK) != 0 &&
           marker_is_enabled() &&
           safe_root_file(CODEX_SBINJECT_SPRINGBOARD, true) &&
           safe_root_file(CODEX_SBINJECT_BUNDLE_HOOK, true) &&
           reserve_redirect_attempt();
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
    if (!should_redirect(path)) {
        return implementation(pid, path, file_actions, attributes, arguments,
                              environment);
    }

    char **mutable_arguments = (char **)arguments;
    char *saved_argument_zero =
        mutable_arguments != NULL ? mutable_arguments[0] : NULL;
    if (arguments != NULL) {
        mutable_arguments[0] = (char *)CODEX_SBINJECT_SPRINGBOARD;
    }
    if (attributes != NULL) {
        (void)posix_spawnattr_set_launch_type_np(
            (posix_spawnattr_t *)attributes, 0);
    }
    hook_log("redirecting SpringBoard to %s", CODEX_SBINJECT_SPRINGBOARD);
    int result = implementation(pid, CODEX_SBINJECT_SPRINGBOARD, file_actions,
                                attributes, arguments, environment);
    if (arguments != NULL) {
        mutable_arguments[0] = saved_argument_zero;
    }
    if (result == 0) {
        return 0;
    }

    hook_log("redirected SpringBoard spawn failed error=%d; using stock",
             result);
    disable_redirect("redirected posix_spawn failed");
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

__attribute__((constructor)) static void initialize_launchd_hook(void) {
    original_posix_spawn = dlsym(RTLD_DEFAULT, "posix_spawn");
    original_posix_spawnp = dlsym(RTLD_DEFAULT, "posix_spawnp");
    if (original_posix_spawn == NULL || original_posix_spawnp == NULL) {
        hook_log("launchd hook initialization failed: spawn symbols missing");
        return;
    }
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    litehook_rebind_result_t spawn = litehook_rebind_symbol(
        header, original_posix_spawn, hooked_posix_spawn);
    litehook_rebind_result_t spawnp = litehook_rebind_symbol(
        header, original_posix_spawnp, hooked_posix_spawnp);
    bool ready = spawn.matches > 0 && spawn.writes == spawn.matches &&
                 spawnp.matches > 0 && spawnp.writes == spawnp.matches &&
                 publish_ready_marker();
    hook_log("launchd hook ready posix_spawn matches=%zu writes=%zu kr=%d "
             "posix_spawnp matches=%zu writes=%zu kr=%d published=%s",
             spawn.matches, spawn.writes, spawn.first_error, spawnp.matches,
             spawnp.writes, spawnp.first_error, ready ? "true" : "false");
}
