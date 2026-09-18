#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_WAIT_ATTEMPTS 200U
#define CODEX_WAIT_DELAY_USEC 5000U

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int csops(pid_t pid, unsigned int operations, void *userAddress,
                 size_t userSize);

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";

static bool springboard_path_matches(pid_t pid) {
    char path[4096] = {0};
    return pid > 1 && proc_pidpath(pid, path, sizeof(path)) > 0 &&
           strcmp(path, kSpringBoardPath) == 0;
}

static pid_t find_springboard(void) {
    int requested = proc_listallpids(NULL, 0);
    if (requested <= 0 || requested > INT32_MAX - 128) {
        return -1;
    }
    int capacity = requested + 128;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return -1;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    if (count > capacity) {
        count = capacity;
    }
    pid_t found = -1;
    for (int index = 0; index < count; ++index) {
        if (springboard_path_matches(pids[index])) {
            found = pids[index];
            break;
        }
    }
    free(pids);
    return found;
}

static int read_csflags(pid_t pid, uint32_t *flags) {
    *flags = 0;
    errno = 0;
    return csops(pid, CODEX_CS_OPS_STATUS, flags, sizeof(*flags));
}

static bool wait_for_trace_stop(pid_t pid, int *status, int *waitError) {
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        pid_t result = waitpid(pid, status, WUNTRACED | WNOHANG);
        if (result == pid) {
            *waitError = 0;
            return WIFSTOPPED(*status);
        }
        if (result < 0 && errno != EINTR) {
            *waitError = errno;
            return false;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
    *waitError = ETIMEDOUT;
    return false;
}

int main(int argc, char **argv) {
    bool threadCreateRequested =
        argc == 2 && strcmp(argv[1], "--thread-create") == 0;
    if (argc != 1 && !threadCreateRequested) {
        dprintf(STDERR_FILENO,
                "usage: %s [--thread-create]\n", argv[0]);
        return 64;
    }
    pid_t targetPid = find_springboard();
    bool initialPathValid = springboard_path_matches(targetPid);
    uint32_t beforeFlags = 0;
    uint32_t attachedFlags = 0;
    uint32_t afterFlags = 0;
    int beforeCsops = -1;
    int beforeCsopsError = 0;
    int attachedCsops = -1;
    int attachedCsopsError = 0;
    int afterCsops = -1;
    int afterCsopsError = 0;
    int attachResult = -1;
    int attachError = 0;
    int stopStatus = 0;
    int waitError = 0;
    bool stopped = false;
    int detachResult = -1;
    int detachError = 0;
    int continueResult = -1;
    int continueError = 0;
    mach_port_t targetTask = MACH_PORT_NULL;
    kern_return_t taskResult = KERN_INVALID_ARGUMENT;
    thread_act_t createdThread = MACH_PORT_NULL;
    kern_return_t threadCreateResult = KERN_INVALID_ARGUMENT;
    kern_return_t threadTerminateResult = KERN_INVALID_ARGUMENT;
    kern_return_t threadPortDeallocateResult = KERN_INVALID_ARGUMENT;
    kern_return_t taskPortDeallocateResult = KERN_INVALID_ARGUMENT;

    if (initialPathValid) {
        beforeCsops = read_csflags(targetPid, &beforeFlags);
        beforeCsopsError = beforeCsops == 0 ? 0 : errno;
        dprintf(STDOUT_FILENO,
                "springboardPtraceProbe phase=attach begin targetPid=%d "
                "beforeCsflags=0x%08x\n",
                targetPid, beforeFlags);
        errno = 0;
        attachResult = ptrace(CODEX_PT_ATTACHEXC, targetPid, NULL, 0);
        attachError = attachResult == 0 ? 0 : errno;
        dprintf(STDOUT_FILENO,
                "springboardPtraceProbe phase=attach end result=%d errno=%d\n",
                attachResult, attachError);
    }
    if (attachResult == 0) {
        stopped = wait_for_trace_stop(targetPid, &stopStatus, &waitError);
        dprintf(STDOUT_FILENO,
                "springboardPtraceProbe phase=wait stopped=%d status=0x%x "
                "errno=%d\n",
                stopped, stopStatus, waitError);
        attachedCsops = read_csflags(targetPid, &attachedFlags);
        attachedCsopsError = attachedCsops == 0 ? 0 : errno;

        if (threadCreateRequested && stopped &&
            springboard_path_matches(targetPid)) {
            taskResult =
                task_for_pid(mach_task_self(), targetPid, &targetTask);
            dprintf(STDOUT_FILENO,
                    "springboardPtraceProbe phase=thread-create begin "
                    "taskKr=%d task=0x%x\n",
                    taskResult, targetTask);
            if (taskResult == KERN_SUCCESS && MACH_PORT_VALID(targetTask)) {
                threadCreateResult =
                    thread_create(targetTask, &createdThread);
            }
            dprintf(STDOUT_FILENO,
                    "springboardPtraceProbe phase=thread-create end kr=%d "
                    "thread=0x%x\n",
                    threadCreateResult, createdThread);
            if (threadCreateResult == KERN_SUCCESS &&
                MACH_PORT_VALID(createdThread)) {
                threadTerminateResult = thread_terminate(createdThread);
                threadPortDeallocateResult =
                    mach_port_deallocate(mach_task_self(), createdThread);
            }
            if (MACH_PORT_VALID(targetTask)) {
                taskPortDeallocateResult =
                    mach_port_deallocate(mach_task_self(), targetTask);
            }
        }

        errno = 0;
        detachResult = ptrace(CODEX_PT_DETACH, targetPid, NULL, 0);
        detachError = detachResult == 0 ? 0 : errno;
        if (springboard_path_matches(targetPid)) {
            errno = 0;
            continueResult = kill(targetPid, SIGCONT);
            continueError = continueResult == 0 ? 0 : errno;
        }
    }

    usleep(20U * 1000U);
    bool finalPathValid = springboard_path_matches(targetPid);
    if (finalPathValid) {
        afterCsops = read_csflags(targetPid, &afterFlags);
        afterCsopsError = afterCsops == 0 ? 0 : errno;
    }

    const char *outcome = "unknown";
    int exitCode = 29;
    if (!initialPathValid) {
        outcome = "target-not-found";
        exitCode = 20;
    } else if (attachResult != 0) {
        outcome = "attach-denied";
        exitCode = 21;
    } else if (!stopped) {
        outcome = "trace-stop-failed";
        exitCode = 22;
    } else if (threadCreateRequested &&
               threadCreateResult != KERN_SUCCESS) {
        outcome = "traced-thread-create-denied";
        exitCode = 24;
    } else if (threadCreateRequested &&
               (threadTerminateResult != KERN_SUCCESS ||
                threadPortDeallocateResult != KERN_SUCCESS ||
                taskPortDeallocateResult != KERN_SUCCESS)) {
        outcome = "thread-cleanup-failed";
        exitCode = 25;
    } else if (detachResult != 0 || continueResult != 0 || !finalPathValid) {
        outcome = "detach-failed";
        exitCode = 23;
    } else {
        outcome = threadCreateRequested ? "traced-thread-create-roundtrip"
                                        : "attach-detach-roundtrip";
        exitCode = 0;
    }

    dprintf(
        STDOUT_FILENO,
        "springboardPtraceProbe summary version=2 mode=%s selfPid=%d "
        "targetPid=%d "
        "initialPathValid=%d finalPathValid=%d beforeCsops=%d "
        "beforeCsopsErrno=%d beforeCsflags=0x%08x beforeDebugged=%d "
        "attachResult=%d attachErrno=%d stopped=%d stopStatus=0x%x "
        "waitErrno=%d attachedCsops=%d attachedCsopsErrno=%d "
        "attachedCsflags=0x%08x attachedDebugged=%d detachResult=%d "
        "detachErrno=%d continueResult=%d continueErrno=%d afterCsops=%d "
        "afterCsopsErrno=%d afterCsflags=0x%08x afterDebugged=%d taskKr=%d "
        "threadCreateKr=%d createdThread=0x%x threadTerminateKr=%d "
        "threadPortDeallocateKr=%d taskPortDeallocateKr=%d outcome=%s "
        "exitCode=%d\n",
        threadCreateRequested ? "thread-create" : "attach-only", getpid(),
        targetPid, initialPathValid, finalPathValid, beforeCsops,
        beforeCsopsError, beforeFlags,
        (beforeFlags & CODEX_CS_DEBUGGED) != 0, attachResult, attachError,
        stopped, stopStatus, waitError, attachedCsops, attachedCsopsError,
        attachedFlags, (attachedFlags & CODEX_CS_DEBUGGED) != 0,
        detachResult, detachError, continueResult, continueError, afterCsops,
        afterCsopsError, afterFlags, (afterFlags & CODEX_CS_DEBUGGED) != 0,
        taskResult, threadCreateResult, createdThread, threadTerminateResult,
        threadPortDeallocateResult, taskPortDeallocateResult, outcome,
        exitCode);
    return exitCode;
}
