#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CODEX_PT_TRACE_ME 0
#define CODEX_PT_KILL 8
#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14

#ifndef POSIX_SPAWN_SETEXEC
#define POSIX_SPAWN_SETEXEC 0x0040
#endif
#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_OPS_CDHASH 5U
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_GET_TASK_ALLOW 0x00000004U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U

#define CODEX_CANDIDATE_PATH                                                \
    "/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard.app/"     \
    "SpringBoard"
#define CODEX_RESULT_PATH                                                   \
    "/var/mobile/Media/customd-trace-me-reexec-probe.log"

static const uint8_t kExpectedCandidateCdhash[20] = {
    0x9b, 0x29, 0x8e, 0x84, 0x6a, 0xb9, 0x1a, 0xaa, 0x1f, 0xba,
    0x30, 0x3f, 0x2c, 0x89, 0x2d, 0x82, 0x8e, 0x9e, 0x92, 0x1c,
};

extern int csops(pid_t pid, unsigned int operation, void *buffer,
                 size_t size);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);

struct trace_me_result {
    int result;
    int error;
};

static bool write_all(int descriptor, const void *bytes, size_t size) {
    const uint8_t *cursor = bytes;
    while (size != 0U) {
        ssize_t amount = write(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return true;
}

static bool read_all(int descriptor, void *bytes, size_t size) {
    uint8_t *cursor = bytes;
    while (size != 0U) {
        ssize_t amount = read(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return true;
}

static bool write_result(const char *text) {
    int descriptor = open(CODEX_RESULT_PATH,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0644);
    if (descriptor < 0) {
        return false;
    }
    struct stat attributes = {0};
    bool valid = fstat(descriptor, &attributes) == 0 &&
        S_ISREG(attributes.st_mode) && fchmod(descriptor, 0644) == 0;
    bool written = valid && write_all(descriptor, text, strlen(text)) &&
        write_all(descriptor, "\n", 1U) && fsync(descriptor) == 0;
    int saved_errno = errno;
    (void)close(descriptor);
    errno = saved_errno;
    return written;
}

static bool wait_for_event(pid_t child, int *status, unsigned int attempts) {
    for (unsigned int attempt = 0; attempt < attempts; ++attempt) {
        errno = 0;
        pid_t waited = waitpid(child, status, WUNTRACED | WNOHANG);
        if (waited == child) {
            return true;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool wait_for_terminal(pid_t child, int *status) {
    for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
        errno = 0;
        pid_t waited = waitpid(child, status, WUNTRACED | WNOHANG);
        if (waited == child) {
            if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
                return true;
            }
        } else if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool candidate_file_is_safe(void) {
    struct stat attributes = {0};
    return lstat(CODEX_CANDIDATE_PATH, &attributes) == 0 &&
        S_ISREG(attributes.st_mode) && !S_ISLNK(attributes.st_mode) &&
        attributes.st_uid == 0 &&
        (attributes.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        (attributes.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

static bool candidate_path_matches(pid_t child, char *observed,
                                   size_t observed_size) {
    char fixed[PATH_MAX] = {0};
    char canonical_observed[PATH_MAX] = {0};
    int path_length = proc_pidpath(child, observed, (uint32_t)observed_size);
    return path_length > 0 && realpath(CODEX_CANDIDATE_PATH, fixed) != NULL &&
        realpath(observed, canonical_observed) != NULL &&
        strcmp(fixed, canonical_observed) == 0;
}

static void force_cleanup(pid_t child, bool traced) {
    if (child <= 1) {
        return;
    }
    if (traced) {
        (void)ptrace(CODEX_PT_KILL, child, NULL, 0);
    } else {
        (void)kill(child, SIGKILL);
    }
    int ignored = 0;
    (void)wait_for_terminal(child, &ignored);
}

static int run_in_place_exec_child(void) {
    errno = 0;
    int trace_result = ptrace(CODEX_PT_TRACE_ME, 0, NULL, 0);
    int trace_errno = errno;
    dprintf(trace_result == 0 ? STDOUT_FILENO : STDERR_FILENO,
            "customd-trace-me-reexec-agent pid=%d trace=%d errno=%d\n",
            getpid(), trace_result, trace_errno);
    if (trace_result != 0) {
        return 75;
    }
    char *const arguments[] = {(char *)CODEX_CANDIDATE_PATH, NULL};
    char *const environment[] = {
        (char *)"CODEX_CUSTOMD_TRACE_ME_REEXEC_PROBE=1",
        (char *)"PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin",
        NULL,
    };
    execve(CODEX_CANDIDATE_PATH, arguments, environment);
    return 76;
}

static int run_in_place_setexec_child(void) {
    posix_spawnattr_t attributes;
    int result = posix_spawnattr_init(&attributes);
    bool initialized = result == 0;
    if (result == 0) {
        result = posix_spawnattr_setflags(
            &attributes,
            (short)(POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED));
    }
    char *const arguments[] = {(char *)CODEX_CANDIDATE_PATH, NULL};
    char *const environment[] = {
        (char *)"CODEX_CUSTOMD_SETEXEC_REEXEC_PROBE=1",
        (char *)"PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin",
        NULL,
    };
    pid_t ignored_pid = 0;
    dprintf(STDOUT_FILENO,
            "customd-setexec-reexec-agent pid=%d setup=%d\n",
            getpid(), result);
    if (result == 0) {
        result = posix_spawn(&ignored_pid, CODEX_CANDIDATE_PATH, NULL,
                             &attributes, arguments, environment);
    }
    if (initialized) {
        (void)posix_spawnattr_destroy(&attributes);
    }
    dprintf(STDERR_FILENO,
            "customd-setexec-reexec-agent pid=%d returned=%d\n",
            getpid(), result);
    return result == 0 ? 0 : 79;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--exec-child") == 0) {
        return run_in_place_exec_child();
    }
    if (argc == 2 && strcmp(argv[1], "--setexec-child") == 0) {
        return run_in_place_setexec_child();
    }
    if (argc != 1) {
        return 64;
    }
    char report[4096] = {0};
    if (!candidate_file_is_safe()) {
        int saved_errno = errno;
        (void)snprintf(report, sizeof(report),
                       "verdict=preflight-failed errno=%d candidate=%s",
                       saved_errno, CODEX_CANDIDATE_PATH);
        (void)write_result(report);
        return 72;
    }

    int trace_pipe[2] = {-1, -1};
    if (pipe(trace_pipe) != 0) {
        int saved_errno = errno;
        (void)snprintf(report, sizeof(report),
                       "verdict=pipe-failed errno=%d", saved_errno);
        (void)write_result(report);
        return 73;
    }
    (void)fcntl(trace_pipe[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(trace_pipe[1], F_SETFD, FD_CLOEXEC);

    pid_t child = fork();
    if (child < 0) {
        int saved_errno = errno;
        (void)close(trace_pipe[0]);
        (void)close(trace_pipe[1]);
        (void)snprintf(report, sizeof(report),
                       "verdict=fork-failed errno=%d", saved_errno);
        (void)write_result(report);
        return 74;
    }
    if (child == 0) {
        (void)close(trace_pipe[0]);
        errno = 0;
        struct trace_me_result trace = {
            .result = ptrace(CODEX_PT_TRACE_ME, 0, NULL, 0),
            .error = errno,
        };
        (void)write_all(trace_pipe[1], &trace, sizeof(trace));
        (void)close(trace_pipe[1]);
        if (trace.result != 0) {
            _exit(75);
        }
        char *const arguments[] = {(char *)CODEX_CANDIDATE_PATH, NULL};
        char *const environment[] = {
            (char *)"CODEX_CUSTOMD_TRACE_ME_REEXEC_PROBE=1",
            (char *)"PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin",
            NULL,
        };
        execve(CODEX_CANDIDATE_PATH, arguments, environment);
        _exit(76);
    }

    (void)close(trace_pipe[1]);
    int exec_status = 0;
    bool exec_waited = wait_for_event(child, &exec_status, 500U);
    struct trace_me_result trace = {.result = -1, .error = 0};
    bool trace_read = read_all(trace_pipe[0], &trace, sizeof(trace));
    (void)close(trace_pipe[0]);
    bool exec_stopped = exec_waited && WIFSTOPPED(exec_status);
    int exec_signal = exec_stopped ? WSTOPSIG(exec_status) : -1;

    char observed_path[PATH_MAX] = {0};
    bool path_exact = exec_stopped &&
        candidate_path_matches(child, observed_path, sizeof(observed_path));
    uint32_t exec_flags = 0;
    errno = 0;
    int exec_csops = exec_stopped
        ? csops(child, CODEX_CS_OPS_STATUS, &exec_flags,
                sizeof(exec_flags))
        : -1;
    int exec_csops_errno = errno;
    uint8_t exec_cdhash[20] = {0};
    errno = 0;
    int cdhash_result = exec_stopped
        ? csops(child, CODEX_CS_OPS_CDHASH, exec_cdhash,
                sizeof(exec_cdhash))
        : -1;
    int cdhash_errno = errno;
    bool cdhash_exact = cdhash_result == 0 &&
        memcmp(exec_cdhash, kExpectedCandidateCdhash,
               sizeof(exec_cdhash)) == 0;

    bool trace_me_stop = trace_read && trace.result == 0 && exec_stopped &&
        exec_signal == SIGTRAP && path_exact && exec_csops == 0 &&
        (exec_flags & (CODEX_CS_VALID | CODEX_CS_GET_TASK_ALLOW)) ==
            (CODEX_CS_VALID | CODEX_CS_GET_TASK_ALLOW) &&
        cdhash_exact;
    if (!trace_me_stop) {
        force_cleanup(child, exec_stopped && trace.result == 0);
        (void)snprintf(
            report, sizeof(report),
            "verdict=trace-me-stop-failed child=%d traceRead=%d trace=%d "
            "traceErrno=%d waited=%d status=0x%x stopped=%d signal=%d "
            "pathExact=%d path=%s csops=%d csopsErrno=%d flags=0x%08x "
            "cdhash=%d cdhashErrno=%d cdhashExact=%d",
            child, trace_read, trace.result, trace.error, exec_waited,
            exec_status, exec_stopped, exec_signal, path_exact,
            observed_path[0] != '\0' ? observed_path : "<none>",
            exec_csops, exec_csops_errno, exec_flags, cdhash_result,
            cdhash_errno, cdhash_exact);
        (void)write_result(report);
        return 77;
    }

    errno = 0;
    int detach_result =
        ptrace(CODEX_PT_DETACH, child, (caddr_t)1, SIGSTOP);
    int detach_errno = errno;
    int handoff_status = 0;
    bool handoff_waited = detach_result == 0 &&
        wait_for_event(child, &handoff_status, 500U);
    bool handoff_stopped = handoff_waited && WIFSTOPPED(handoff_status);
    int handoff_signal = handoff_stopped ? WSTOPSIG(handoff_status) : -1;

    errno = 0;
    int attach_result = handoff_stopped
        ? ptrace(CODEX_PT_ATTACHEXC, child, NULL, 0)
        : -1;
    int attach_errno = errno;
    int attach_status = 0;
    bool attach_waited = attach_result == 0 &&
        wait_for_event(child, &attach_status, 500U);
    bool attach_stopped = attach_waited && WIFSTOPPED(attach_status);

    uint32_t attached_flags = 0;
    errno = 0;
    int attached_csops = attach_stopped
        ? csops(child, CODEX_CS_OPS_STATUS, &attached_flags,
                sizeof(attached_flags))
        : -1;
    int attached_csops_errno = errno;
    char attached_path[PATH_MAX] = {0};
    bool attached_path_exact = attach_stopped && candidate_path_matches(
        child, attached_path, sizeof(attached_path));
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t task_result = attach_stopped
        ? task_for_pid(mach_task_self(), child, &task)
        : KERN_FAILURE;
    bool task_valid = task_result == KERN_SUCCESS && MACH_PORT_VALID(task);
    if (task_valid) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }

    bool debug_ready = attach_stopped && attached_csops == 0 &&
        attached_path_exact &&
        (attached_flags & (CODEX_CS_VALID | CODEX_CS_GET_TASK_ALLOW |
                           CODEX_CS_DEBUGGED)) ==
            (CODEX_CS_VALID | CODEX_CS_GET_TASK_ALLOW |
             CODEX_CS_DEBUGGED) &&
        (attached_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0 &&
        task_valid;

    errno = 0;
    int kill_result = attach_stopped
        ? ptrace(CODEX_PT_KILL, child, NULL, 0)
        : -1;
    int kill_errno = errno;
    if (kill_result != 0) {
        (void)kill(child, SIGKILL);
    }
    int final_status = 0;
    bool final_waited = wait_for_terminal(child, &final_status);
    bool final_killed = final_waited && WIFSIGNALED(final_status) &&
        WTERMSIG(final_status) == SIGKILL;

    bool success = detach_result == 0 && handoff_stopped &&
        handoff_signal == SIGSTOP && attach_result == 0 && debug_ready &&
        kill_result == 0 && final_killed;
    (void)snprintf(
        report, sizeof(report),
        "verdict=%s child=%d trace=%d traceErrno=%d execStatus=0x%x "
        "execSignal=%d pathExact=%d execFlags=0x%08x cdhashExact=%d "
        "detach=%d detachErrno=%d handoffStatus=0x%x "
        "handoffStopped=%d handoffSignal=%d attach=%d attachErrno=%d "
        "attachStatus=0x%x attachStopped=%d attachedPathExact=%d "
        "attachedCsops=%d attachedCsopsErrno=%d attachedFlags=0x%08x "
        "taskKr=%d taskValid=%d debugReady=%d kill=%d killErrno=%d "
        "finalWaited=%d finalStatus=0x%x finalKilled=%d "
        "candidateUserInstructions=0",
        success ? "success" : "handoff-failed", child, trace.result,
        trace.error, exec_status, exec_signal, path_exact, exec_flags,
        cdhash_exact, detach_result, detach_errno, handoff_status,
        handoff_stopped, handoff_signal, attach_result, attach_errno,
        attach_status, attach_stopped, attached_path_exact, attached_csops,
        attached_csops_errno, attached_flags, task_result, task_valid,
        debug_ready, kill_result, kill_errno, final_waited, final_status,
        final_killed);
    bool result_written = write_result(report);
    dprintf(success && result_written ? STDOUT_FILENO : STDERR_FILENO,
            "%s\n", report);
    return success && result_written ? 0 : 78;
}
