#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif
#define PT_CONTINUE 7
#define PT_KILL 8

#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_OBSERVER_MAX_SAMPLES 3000000U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U

#define CODEX_RESULT_PATH                                                    \
    "/private/var/mobile/Media/codex-exec-cs-persistence-probe.txt"
#define CODEX_OBSERVER_RESULT_PATH                                           \
    "/private/var/mobile/Media/codex-exec-cs-observer.txt"

extern int csops(pid_t pid, unsigned int ops, void *useraddr,
                 size_t usersize);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);

static bool wait_for_child(pid_t child, int *status) {
    for (unsigned int attempt = 0; attempt < 500; ++attempt) {
        pid_t result = waitpid(child, status, WUNTRACED | WNOHANG);
        if (result == child) {
            return true;
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(10 * 1000);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool write_all(int descriptor, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t written = write(descriptor, cursor, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        cursor += written;
        length -= (size_t)written;
    }
    return true;
}

static bool write_result(const char *result) {
    int descriptor =
        open(CODEX_RESULT_PATH,
             O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return false;
    }

    struct stat attributes;
    bool regular = fstat(descriptor, &attributes) == 0 &&
                   S_ISREG(attributes.st_mode);
    bool written = regular && fchmod(descriptor, 0600) == 0 &&
                   write_all(descriptor, result, strlen(result)) &&
                   write_all(descriptor, "\n", 1);
    if (written) {
        written = fsync(descriptor) == 0;
    }
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return written;
}

static bool write_result_at_path(const char *path, const char *result) {
    int descriptor =
        open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
             0600);
    if (descriptor < 0) {
        return false;
    }

    struct stat attributes;
    bool regular = fstat(descriptor, &attributes) == 0 &&
                   S_ISREG(attributes.st_mode);
    bool written = regular && fchmod(descriptor, 0600) == 0 &&
                   write_all(descriptor, result, strlen(result)) &&
                   write_all(descriptor, "\n", 1);
    if (written) {
        written = fsync(descriptor) == 0;
    }
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return written;
}

static void run_probe(char *result, size_t result_size) {
    result[0] = '\0';

    sigset_t blocked_signals;
    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, SIGPIPE);
    int mask_result =
        pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
    if (mask_result != 0) {
        snprintf(result, result_size, "phase=sigmask error=%d", mask_result);
        return;
    }

    int gate[2] = {-1, -1};
    if (pipe(gate) != 0) {
        snprintf(result, result_size, "phase=pipe errno=%d", errno);
        return;
    }

    pid_t child = fork();
    if (child < 0) {
        int saved_errno = errno;
        close(gate[0]);
        close(gate[1]);
        snprintf(result, result_size, "phase=fork errno=%d", saved_errno);
        return;
    }

    if (child == 0) {
        close(gate[1]);
        uint8_t command = 0;
        ssize_t amount;
        do {
            amount = read(gate[0], &command, sizeof(command));
        } while (amount < 0 && errno == EINTR);
        close(gate[0]);
        if (amount != (ssize_t)sizeof(command) || command != 0x43) {
            _exit(70);
        }

        const char *path =
            "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
        char *const argv[] = {(char *)path, NULL};
        char *const envp[] = {(char *)"CODEX_EXEC_CS_PROBE=1", NULL};
        execve(path, argv, envp);
        _exit(71);
    }

    close(gate[0]);
    errno = 0;
    int attach_result = ptrace(PT_ATTACHEXC, child, NULL, 0);
    int attach_errno = errno;
    int attach_status = 0;
    bool attach_waited =
        attach_result == 0 && wait_for_child(child, &attach_status);

    uint32_t before_flags = 0;
    errno = 0;
    int before_result =
        attach_waited
            ? csops(child, CODEX_CS_OPS_STATUS, &before_flags,
                    sizeof(before_flags))
            : -1;
    int before_errno = errno;

    uint8_t command = 0x43;
    bool released = attach_waited &&
                    write(gate[1], &command, sizeof(command)) ==
                        (ssize_t)sizeof(command);
    close(gate[1]);

    errno = 0;
    int continue_result =
        released ? ptrace(PT_CONTINUE, child, (caddr_t)1, 0) : -1;
    int continue_errno = errno;
    int exec_status = 0;
    bool exec_waited =
        continue_result == 0 && wait_for_child(child, &exec_status);

    uint32_t after_flags = 0;
    errno = 0;
    int after_result =
        exec_waited && WIFSTOPPED(exec_status)
            ? csops(child, CODEX_CS_OPS_STATUS, &after_flags,
                    sizeof(after_flags))
            : -1;
    int after_errno = errno;

    errno = 0;
    int kill_result =
        exec_waited && WIFSTOPPED(exec_status)
            ? ptrace(PT_KILL, child, NULL, 0)
            : kill(child, SIGKILL);
    int kill_errno = errno;
    int final_status = 0;
    (void)wait_for_child(child, &final_status);

    snprintf(
        result, result_size,
        "child=%d attach=%d attachErrno=%d attachWaited=%d "
        "attachStatus=0x%x beforeCsops=%d beforeErrno=%d "
        "beforeFlags=0x%08x beforeDebugged=%d released=%d continue=%d "
        "continueErrno=%d execWaited=%d execStatus=0x%x afterCsops=%d "
        "afterErrno=%d afterFlags=0x%08x afterDebugged=%d afterHardKill=%d "
        "kill=%d killErrno=%d finalStatus=0x%x",
        child, attach_result, attach_errno, attach_waited, attach_status,
        before_result, before_errno, before_flags,
        (before_flags & CODEX_CS_DEBUGGED) != 0, released, continue_result,
        continue_errno, exec_waited, exec_status, after_result, after_errno,
        after_flags, (after_flags & CODEX_CS_DEBUGGED) != 0,
        (after_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0, kill_result,
        kill_errno, final_status);
}

__attribute__((visibility("default")))
const char *codex_exec_cs_persistence_probe(void) {
    static char result[1024];
    run_probe(result, sizeof(result));
    return result;
}

static _Atomic bool async_probe_running = false;

static void *async_probe_main(void *context) {
    (void)context;
    usleep(250 * 1000);

    char result[1024];
    run_probe(result, sizeof(result));
    (void)write_result(result);
    atomic_store_explicit(&async_probe_running, false, memory_order_release);
    return NULL;
}

__attribute__((visibility("default")))
int codex_exec_cs_persistence_probe_start_async(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &async_probe_running, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) {
        return EBUSY;
    }

    pthread_t thread;
    int create_result = pthread_create(&thread, NULL, async_probe_main, NULL);
    if (create_result != 0) {
        atomic_store_explicit(&async_probe_running, false,
                              memory_order_release);
        return create_result;
    }
    int detach_result = pthread_detach(thread);
    if (detach_result != 0) {
        return detach_result;
    }
    return 0;
}

__attribute__((visibility("default")))
const char *codex_exec_cs_persistence_probe_result_path(void) {
    return CODEX_RESULT_PATH;
}

struct observer_context {
    pid_t pid;
};

static _Atomic bool observer_running = false;

static void *observer_main(void *opaque_context) {
    struct observer_context context = *(struct observer_context *)opaque_context;
    free(opaque_context);

    bool armed = false;
    uint32_t baseline_flags = 0;
    uint32_t transition_flags = 0;
    uint32_t stopped_flags = 0;
    int transition_csops = -1;
    int transition_errno = 0;
    int stop_result = -1;
    int stop_errno = 0;
    int stopped_csops = -1;
    int stopped_errno = 0;
    unsigned int samples = 0;
    const char *phase = "timeout";

    for (samples = 0; samples < CODEX_OBSERVER_MAX_SAMPLES; ++samples) {
        uint32_t flags = 0;
        errno = 0;
        int result = csops(context.pid, CODEX_CS_OPS_STATUS, &flags,
                           sizeof(flags));
        int result_errno = errno;

        if (result != 0) {
            if (armed && result_errno == ESRCH) {
                phase = "exited";
                transition_csops = result;
                transition_errno = result_errno;
                break;
            }
            usleep(100);
            continue;
        }

        if (!armed) {
            if ((flags & CODEX_CS_DEBUGGED) != 0 &&
                (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0) {
                baseline_flags = flags;
                armed = true;
            }
            usleep(100);
            continue;
        }

        if (flags == baseline_flags) {
            usleep(100);
            continue;
        }

        phase = "transition";
        transition_flags = flags;
        transition_csops = result;
        transition_errno = result_errno;

        errno = 0;
        stop_result = kill(context.pid, SIGSTOP);
        stop_errno = errno;
        usleep(2 * 1000);

        errno = 0;
        stopped_csops = csops(context.pid, CODEX_CS_OPS_STATUS,
                              &stopped_flags, sizeof(stopped_flags));
        stopped_errno = errno;
        break;
    }

    char result[1024];
    snprintf(result, sizeof(result),
             "phase=%s pid=%d armed=%d samples=%u baseline=0x%08x "
             "transitionCsops=%d transitionErrno=%d transition=0x%08x "
             "transitionDebugged=%d transitionHardKill=%d stop=%d "
             "stopErrno=%d stoppedCsops=%d stoppedErrno=%d "
             "stopped=0x%08x stoppedDebugged=%d stoppedHardKill=%d",
             phase, context.pid, armed, samples, baseline_flags,
             transition_csops, transition_errno, transition_flags,
             (transition_flags & CODEX_CS_DEBUGGED) != 0,
             (transition_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0,
             stop_result, stop_errno, stopped_csops, stopped_errno,
             stopped_flags, (stopped_flags & CODEX_CS_DEBUGGED) != 0,
             (stopped_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0);
    (void)write_result_at_path(CODEX_OBSERVER_RESULT_PATH, result);
    atomic_store_explicit(&observer_running, false, memory_order_release);
    return NULL;
}

__attribute__((visibility("default")))
int codex_exec_cs_observer_start_async(pid_t pid) {
    if (pid <= 1 || pid == getpid()) {
        return EINVAL;
    }

    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &observer_running, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) {
        return EBUSY;
    }

    struct observer_context *context = malloc(sizeof(*context));
    if (context == NULL) {
        atomic_store_explicit(&observer_running, false, memory_order_release);
        return ENOMEM;
    }
    context->pid = pid;

    pthread_t thread;
    int create_result = pthread_create(&thread, NULL, observer_main, context);
    if (create_result != 0) {
        free(context);
        atomic_store_explicit(&observer_running, false, memory_order_release);
        return create_result;
    }
    int detach_result = pthread_detach(thread);
    if (detach_result != 0) {
        return detach_result;
    }
    return 0;
}

__attribute__((visibility("default")))
const char *codex_exec_cs_observer_result_path(void) {
    return CODEX_OBSERVER_RESULT_PATH;
}
