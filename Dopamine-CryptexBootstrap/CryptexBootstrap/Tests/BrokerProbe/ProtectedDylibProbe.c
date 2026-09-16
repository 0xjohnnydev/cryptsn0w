#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern int proc_listallpids(void *buffer, int buffer_size);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kLoaderPath =
    "/var/jb/usr/libexec/codex-ellekit-loader";
static const char *const kDylibPath =
    "/var/jb/Library/MobileSubstrate/DynamicLibraries/BrokerProbe.dylib";
static const char *const kSafeModePath = "/var/mobile/.eksafemode";
static const char *const kLoadedMarkerPath =
    "/var/mobile/Library/Caches/codex-broker-probe-loaded.txt";
static const char *const kResultPath =
    "/var/jb/var/lib/codex-broker-probe/protected-injection.txt";

static bool exact_springboard(pid_t pid) {
    char path[PATH_MAX] = {0};
    return pid > 1 && proc_pidpath(pid, path, sizeof(path)) > 0 &&
           strcmp(path, kSpringBoardPath) == 0;
}

static pid_t find_springboard(void) {
    int capacity = proc_listallpids(NULL, 0);
    if (capacity <= 0 || capacity > 1024 * 1024) {
        return -1;
    }
    capacity += 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return -1;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    if (count > capacity) {
        count = capacity;
    }
    pid_t result = -1;
    for (int index = 0; index < count; ++index) {
        if (exact_springboard(pids[index])) {
            result = pids[index];
            break;
        }
    }
    free(pids);
    return result;
}

static pid_t wait_for_stable_springboard(void) {
    pid_t candidate = -1;
    unsigned int consecutive = 0;
    for (unsigned int attempt = 0; attempt < 120; ++attempt) {
        pid_t current = find_springboard();
        if (current > 1 && current == candidate && exact_springboard(current)) {
            ++consecutive;
        } else {
            candidate = current;
            consecutive = current > 1 ? 1 : 0;
        }
        if (consecutive >= 20) {
            return candidate;
        }
        usleep(250 * 1000);
    }
    return -1;
}

static int wait_for_child(pid_t child) {
    int status = 0;
    for (unsigned int attempt = 0; attempt < 240; ++attempt) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
        }
        if (result < 0 && errno != EINTR) {
            return 125;
        }
        usleep(250 * 1000);
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    return 124;
}

static bool marker_confirms_pid(pid_t pid) {
    int descriptor = open(kLoadedMarkerPath, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return false;
    }
    char contents[1024] = {0};
    ssize_t amount = read(descriptor, contents, sizeof(contents) - 1);
    close(descriptor);
    if (amount <= 0) {
        return false;
    }
    contents[amount] = '\0';
    char expected[96];
    snprintf(expected, sizeof(expected),
             "BROKER_PROBE_LOADED version=1.0.18 pid=%d", pid);
    return strstr(contents, expected) != NULL;
}

static void write_result(pid_t pid, int loader_status, bool marker_confirmed,
                         bool safe_mode_cleared) {
    int descriptor = open(kResultPath,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (descriptor < 0) {
        return;
    }
    dprintf(descriptor,
            "PROTECTED_DYLIB_PROBE version=1.0.18 pid=%d target=%s "
            "loader-status=%d marker=%s safe-mode-cleared=%s pid1-guard=true\n",
            pid, kSpringBoardPath, loader_status,
            marker_confirmed ? "confirmed" : "missing",
            safe_mode_cleared ? "true" : "false");
    (void)fsync(descriptor);
    close(descriptor);
}

int main(void) {
    if (getuid() != 0) {
        dprintf(STDERR_FILENO, "ProtectedDylibProbe requires root\n");
        return 67;
    }

    pid_t target = wait_for_stable_springboard();
    if (target <= 1 || !exact_springboard(target)) {
        dprintf(STDERR_FILENO,
                "ProtectedDylibProbe found no stable admitted SpringBoard\n");
        write_result(target, 78, false, false);
        return 78;
    }

    bool safe_mode_cleared = unlink(kSafeModePath) == 0 || errno == ENOENT;
    if (!safe_mode_cleared) {
        dprintf(STDERR_FILENO,
                "ProtectedDylibProbe could not clear exact safe-mode marker: %s\n",
                strerror(errno));
        write_result(target, 73, false, false);
        return 73;
    }
    if (unlink(kLoadedMarkerPath) != 0 && errno != ENOENT) {
        dprintf(STDERR_FILENO,
                "ProtectedDylibProbe could not clear old result marker: %s\n",
                strerror(errno));
        write_result(target, 73, false, true);
        return 73;
    }

    char pid_text[32];
    snprintf(pid_text, sizeof(pid_text), "%d", target);
    char *arguments[] = {(char *)kLoaderPath, "--inject-pid", pid_text,
                         (char *)kDylibPath, NULL};
    pid_t child = -1;
    int spawn_status =
        posix_spawn(&child, kLoaderPath, NULL, NULL, arguments, environ);
    if (spawn_status != 0) {
        dprintf(STDERR_FILENO,
                "ProtectedDylibProbe loader spawn failed: %s\n",
                strerror(spawn_status));
        write_result(target, spawn_status, false, true);
        return 74;
    }

    int loader_status = wait_for_child(child);
    bool marker_confirmed = loader_status == 0 && exact_springboard(target);
    for (unsigned int attempt = 0;
         marker_confirmed && attempt < 30 && !marker_confirms_pid(target);
         ++attempt) {
        usleep(100 * 1000);
    }
    marker_confirmed = marker_confirmed && marker_confirms_pid(target);
    write_result(target, loader_status, marker_confirmed, true);
    dprintf(STDOUT_FILENO,
            "PROTECTED_DYLIB_PROBE version=1.0.18 pid=%d loader-status=%d "
            "marker=%s pid1-guard=true\n",
            target, loader_status,
            marker_confirmed ? "confirmed" : "missing");
    return loader_status == 0 && marker_confirmed ? 0 : 75;
}
