#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif

extern char **environ;
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t task_port);

static const char *const kCryptexdPath = "/usr/libexec/cryptexd";
static const char *const kLoaderPath =
    "/var/jb/usr/libexec/codex-ellekit-loader";

static pid_t find_unique_cryptexd(void) {
    int reported = proc_listallpids(NULL, 0);
    if (reported <= 0 || reported > 256 * 1024) {
        return -1;
    }
    /* proc_listallpids(NULL, 0) reports a PID count, while the second call's
       size argument is bytes.  Leave growth room for concurrent launches. */
    int capacity = reported + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return -1;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    pid_t found = -1;
    for (int index = 0; index < count && index < capacity; ++index) {
        if (pids[index] <= 1) {
            continue;
        }
        char path[PATH_MAX] = {0};
        if (proc_pidpath(pids[index], path, sizeof(path)) > 0 &&
            strcmp(path, kCryptexdPath) == 0) {
            if (found > 1) {
                found = -1;
                break;
            }
            found = pids[index];
        }
    }
    free(pids);
    return found;
}

int main(void) {
    if (geteuid() != 0 || getpid() <= 1) {
        return 64;
    }
    pid_t target = find_unique_cryptexd();
    if (target <= 1) {
        fprintf(stderr, "customd-ptrauth-spawn: cryptexd not unique\n");
        return 65;
    }
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t task_result =
        task_for_pid(mach_task_self(), target, &task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
        fprintf(stderr,
                "customd-ptrauth-spawn: task_for_pid(%d) failed=%d\n",
                target, task_result);
        return 66;
    }

    posix_spawnattr_t attributes;
    int result = posix_spawnattr_init(&attributes);
    if (result == 0) {
        result = posix_spawnattr_setflags(
            &attributes,
            (short)(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP));
    }
    if (result == 0) {
        result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    if (result == 0) {
        result = posix_spawnattr_set_ptrauth_task_port_np(&attributes, task);
    }
    char pid_text[24] = {0};
    int length = snprintf(pid_text, sizeof(pid_text), "%d", target);
    char *arguments[] = {
        (char *)kLoaderPath,
        (char *)"--inspect-pid",
        pid_text,
        (char *)"--ptrauth-child",
        NULL,
    };
    pid_t child = -1;
    if (result == 0 && length > 0 && (size_t)length < sizeof(pid_text)) {
        result = posix_spawn(&child, kLoaderPath, NULL, &attributes,
                             arguments, environ);
    } else if (result == 0) {
        result = EINVAL;
    }
    (void)posix_spawnattr_destroy(&attributes);
    (void)mach_port_deallocate(mach_task_self(), task);
    if (result != 0 || child <= 1) {
        fprintf(stderr,
                "customd-ptrauth-spawn: loader spawn failed=%d child=%d\n",
                result, child);
        return 67;
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, WUNTRACED);
    } while (waited < 0 && errno == EINTR);
    char path[PATH_MAX] = {0};
    char fixed_path[PATH_MAX] = {0};
    bool exact = waited == child && WIFSTOPPED(status) &&
                 realpath(kLoaderPath, fixed_path) != NULL &&
                 proc_pidpath(child, path, sizeof(path)) > 0 &&
                 strcmp(path, fixed_path) == 0;
    if (!exact) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        fprintf(stderr,
                "customd-ptrauth-spawn: child validation failed pid=%d "
                "status=0x%x path=%s\n",
                child, status, path);
        return 68;
    }
    printf("customd-ptrauth-loader-spawn=success child-pid=%d "
           "target-pid=%d owner-pid=%d stop-signal=%d\n",
           child, target, getpid(), WSTOPSIG(status));
    fflush(stdout);
    /* Stay alive as the exact owner while a bounded local controller uses the
       suspended child.  Parent exit tears down this ptrauth-context child on
       current iOS, so returning immediately would invalidate the handoff. */
    for (unsigned int attempt = 0; attempt < 2400U; ++attempt) {
        pid_t reaped = waitpid(child, &status, WNOHANG);
        if (reaped == child) {
            return WIFEXITED(status) ? WEXITSTATUS(status)
                                     : (WIFSIGNALED(status)
                                            ? 128 + WTERMSIG(status)
                                            : 70);
        }
        if (reaped < 0 && errno != EINTR) {
            return 70;
        }
        usleep(50U * 1000U);
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    return 69;
}
