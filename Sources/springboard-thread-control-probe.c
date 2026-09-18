#include <errno.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);

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

static pid_t start_resume_watchdog(thread_act_t thread, int *signalFd) {
    int descriptors[2] = {-1, -1};
    *signalFd = -1;
    if (pipe(descriptors) != 0) {
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        return -1;
    }
    if (child == 0) {
        close(descriptors[1]);
        struct pollfd descriptor = {
            .fd = descriptors[0],
            .events = POLLIN,
        };
        int pollResult;
        do {
            pollResult = poll(&descriptor, 1, 250);
        } while (pollResult < 0 && errno == EINTR);
        uint8_t token = 0;
        bool cancelled = pollResult > 0 &&
                         (descriptor.revents & POLLIN) != 0 &&
                         read(descriptors[0], &token, sizeof(token)) ==
                             (ssize_t)sizeof(token) &&
                         token == 1;
        close(descriptors[0]);
        if (!cancelled) {
            (void)thread_resume(thread);
        }
        _exit(0);
    }
    close(descriptors[0]);
    *signalFd = descriptors[1];
    return child;
}

static void finish_resume_watchdog(pid_t watchdogPid, int signalFd,
                                   int *watchdogStatus) {
    if (signalFd >= 0) {
        uint8_t token = 1;
        (void)write(signalFd, &token, sizeof(token));
        close(signalFd);
    }
    if (watchdogPid <= 0) {
        return;
    }
    while (waitpid(watchdogPid, watchdogStatus, 0) < 0) {
        if (errno != EINTR) {
            *watchdogStatus = -1;
            break;
        }
    }
}

int main(int argc, char **argv) {
    bool enumerateOnly =
        argc == 2 && strcmp(argv[1], "--enumerate-only") == 0;
    bool readStateOnly =
        argc == 2 && strcmp(argv[1], "--read-state") == 0;
    bool suspendResumeOnly =
        argc == 2 && strcmp(argv[1], "--suspend-resume") == 0;
    if (argc != 1 && !enumerateOnly && !readStateOnly &&
        !suspendResumeOnly) {
        dprintf(STDERR_FILENO,
                "usage: %s [--enumerate-only|--read-state|--suspend-resume]\n",
                argv[0]);
        return 64;
    }
    const char *mode = enumerateOnly ? "enumerate-only"
                       : readStateOnly ? "read-state"
                       : suspendResumeOnly ? "suspend-resume"
                                       : "same-state";
    pid_t targetPid = find_springboard();
    bool initialPathValid = springboard_path_matches(targetPid);
    dprintf(STDOUT_FILENO,
            "springboardThreadControlProbe phase=start mode=%s selfPid=%d "
            "targetPid=%d pathValid=%d\n",
            mode, getpid(), targetPid, initialPathValid);
    mach_port_t targetTask = MACH_PORT_NULL;
    kern_return_t taskResult = KERN_INVALID_ARGUMENT;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t threadCount = 0;
    kern_return_t threadsResult = KERN_INVALID_ARGUMENT;
    int chosenIndex = -1;
    thread_basic_info_data_t chosenInfo = {0};
    kern_return_t chosenInfoResult = KERN_INVALID_ARGUMENT;
    kern_return_t suspendResult = KERN_INVALID_ARGUMENT;
    kern_return_t getStateResult = KERN_INVALID_ARGUMENT;
    kern_return_t setSameStateResult = KERN_INVALID_ARGUMENT;
    kern_return_t resumeResult = KERN_INVALID_ARGUMENT;
    pid_t watchdogPid = -1;
    int watchdogSignalFd = -1;
    int watchdogStatus = 0;
    arm_thread_state64_t state = {0};
    mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;

    if (initialPathValid) {
        dprintf(STDOUT_FILENO,
                "springboardThreadControlProbe phase=task-for-pid begin\n");
        taskResult = task_for_pid(mach_task_self(), targetPid, &targetTask);
        dprintf(STDOUT_FILENO,
                "springboardThreadControlProbe phase=task-for-pid end kr=%d "
                "task=0x%x\n",
                taskResult, targetTask);
    }
    if (taskResult == KERN_SUCCESS && MACH_PORT_VALID(targetTask)) {
        dprintf(STDOUT_FILENO,
                "springboardThreadControlProbe phase=task-threads begin\n");
        threadsResult = task_threads(targetTask, &threads, &threadCount);
        dprintf(STDOUT_FILENO,
                "springboardThreadControlProbe phase=task-threads end kr=%d "
                "count=%u\n",
                threadsResult, threadCount);
    }

    if (threadsResult == KERN_SUCCESS && threadCount > 0 &&
        threadCount <= 1024) {
        int lowestCpuUsage = INT32_MAX;
        for (mach_msg_type_number_t index = 0; index < threadCount; ++index) {
            thread_basic_info_data_t info = {0};
            mach_msg_type_number_t infoCount = THREAD_BASIC_INFO_COUNT;
            kern_return_t infoResult = thread_info(
                threads[index], THREAD_BASIC_INFO,
                (thread_info_t)&info, &infoCount);
            if (index > 0 && infoResult == KERN_SUCCESS &&
                info.suspend_count == 0 &&
                info.run_state == TH_STATE_WAITING &&
                info.cpu_usage < lowestCpuUsage) {
                chosenIndex = (int)index;
                chosenInfo = info;
                chosenInfoResult = infoResult;
                lowestCpuUsage = info.cpu_usage;
            }
        }
        dprintf(STDOUT_FILENO,
                "springboardThreadControlProbe phase=thread-selection "
                "chosen=%d infoKr=%d runState=%d suspendCount=%d\n",
                chosenIndex, chosenInfoResult, chosenInfo.run_state,
                chosenInfo.suspend_count);
    }

    if (readStateOnly && chosenIndex >= 0 &&
        springboard_path_matches(targetPid)) {
        dprintf(STDOUT_FILENO,
                "springboardThreadControlProbe phase=thread-get-state-readonly "
                "begin index=%d\n",
                chosenIndex);
        getStateResult = thread_get_state(
            threads[chosenIndex], ARM_THREAD_STATE64,
            (thread_state_t)&state, &stateCount);
        dprintf(STDOUT_FILENO,
                "springboardThreadControlProbe phase=thread-get-state-readonly "
                "end kr=%d count=%u\n",
                getStateResult, stateCount);
    } else if (suspendResumeOnly && chosenIndex >= 0 &&
               springboard_path_matches(targetPid)) {
        thread_act_t chosen = threads[chosenIndex];
        watchdogPid =
            start_resume_watchdog(chosen, &watchdogSignalFd);
        if (watchdogPid > 0) {
            dprintf(STDOUT_FILENO,
                    "springboardThreadControlProbe phase=thread-suspend begin "
                    "index=%d watchdogPid=%d\n",
                    chosenIndex, watchdogPid);
            suspendResult = thread_suspend(chosen);
            dprintf(STDOUT_FILENO,
                    "springboardThreadControlProbe phase=thread-suspend end "
                    "kr=%d\n",
                    suspendResult);
            if (suspendResult == KERN_SUCCESS) {
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe phase=thread-resume "
                        "begin\n");
                resumeResult = thread_resume(chosen);
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe phase=thread-resume end "
                        "kr=%d\n",
                        resumeResult);
            }
            finish_resume_watchdog(watchdogPid, watchdogSignalFd,
                                   &watchdogStatus);
        }
    } else if (!enumerateOnly && chosenIndex >= 0 &&
        springboard_path_matches(targetPid)) {
        thread_act_t chosen = threads[chosenIndex];
        watchdogPid =
            start_resume_watchdog(chosen, &watchdogSignalFd);
        if (watchdogPid > 0) {
            dprintf(STDOUT_FILENO,
                    "springboardThreadControlProbe phase=thread-suspend begin "
                    "index=%d watchdogPid=%d\n",
                    chosenIndex, watchdogPid);
            suspendResult = thread_suspend(chosen);
            dprintf(STDOUT_FILENO,
                    "springboardThreadControlProbe phase=thread-suspend end "
                    "kr=%d\n",
                    suspendResult);
            if (suspendResult == KERN_SUCCESS) {
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe phase=thread-get-state "
                        "begin\n");
                getStateResult = thread_get_state(
                    chosen, ARM_THREAD_STATE64, (thread_state_t)&state,
                    &stateCount);
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe phase=thread-get-state "
                        "end kr=%d count=%u\n",
                        getStateResult, stateCount);
            }
            if (getStateResult == KERN_SUCCESS) {
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe "
                        "phase=thread-set-same-state begin\n");
                setSameStateResult = thread_set_state(
                    chosen, ARM_THREAD_STATE64, (thread_state_t)&state,
                    stateCount);
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe "
                        "phase=thread-set-same-state end kr=%d\n",
                        setSameStateResult);
            }
            if (suspendResult == KERN_SUCCESS) {
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe phase=thread-resume "
                        "begin\n");
                resumeResult = thread_resume(chosen);
                dprintf(STDOUT_FILENO,
                        "springboardThreadControlProbe phase=thread-resume end "
                        "kr=%d\n",
                        resumeResult);
            }
            finish_resume_watchdog(watchdogPid, watchdogSignalFd,
                                   &watchdogStatus);
        } else {
            dprintf(STDOUT_FILENO,
                    "springboardThreadControlProbe phase=watchdog-fork "
                    "failed\n");
        }
    }

    kern_return_t rightsDeallocateResult = KERN_SUCCESS;
    if (threads != NULL) {
        for (mach_msg_type_number_t index = 0; index < threadCount; ++index) {
            kern_return_t result =
                mach_port_deallocate(mach_task_self(), threads[index]);
            if (result != KERN_SUCCESS && rightsDeallocateResult == KERN_SUCCESS) {
                rightsDeallocateResult = result;
            }
        }
    }
    kern_return_t arrayDeallocateResult = KERN_INVALID_ARGUMENT;
    if (threads != NULL) {
        arrayDeallocateResult = mach_vm_deallocate(
            mach_task_self(), (mach_vm_address_t)(uintptr_t)threads,
            (mach_vm_size_t)threadCount * sizeof(*threads));
    }
    kern_return_t taskPortDeallocateResult = KERN_INVALID_ARGUMENT;
    if (MACH_PORT_VALID(targetTask)) {
        taskPortDeallocateResult =
            mach_port_deallocate(mach_task_self(), targetTask);
    }
    bool finalPathValid = springboard_path_matches(targetPid);

    const char *outcome = "unknown";
    int exitCode = 29;
    if (!initialPathValid) {
        outcome = "target-not-found";
        exitCode = 20;
    } else if (taskResult != KERN_SUCCESS || !MACH_PORT_VALID(targetTask)) {
        outcome = "task-port-denied";
        exitCode = 21;
    } else if (threadsResult != KERN_SUCCESS || chosenIndex < 0) {
        outcome = "thread-selection-failed";
        exitCode = 22;
    } else if ((enumerateOnly || readStateOnly || suspendResumeOnly) &&
               (rightsDeallocateResult != KERN_SUCCESS ||
                arrayDeallocateResult != KERN_SUCCESS ||
                taskPortDeallocateResult != KERN_SUCCESS)) {
        outcome = "cleanup-failed";
        exitCode = 27;
    } else if (enumerateOnly) {
        outcome = "thread-enumeration-available";
        exitCode = 0;
    } else if (readStateOnly && getStateResult != KERN_SUCCESS) {
        outcome = "thread-read-denied";
        exitCode = 24;
    } else if (readStateOnly) {
        outcome = "thread-read-available";
        exitCode = 0;
    } else if (suspendResumeOnly && watchdogPid <= 0) {
        outcome = "watchdog-fork-failed";
        exitCode = 28;
    } else if (suspendResumeOnly && suspendResult != KERN_SUCCESS) {
        outcome = "thread-suspend-denied";
        exitCode = 23;
    } else if (suspendResumeOnly &&
               (resumeResult != KERN_SUCCESS || !finalPathValid)) {
        outcome = "thread-resume-failed";
        exitCode = 26;
    } else if (suspendResumeOnly) {
        outcome = "suspend-resume-roundtrip";
        exitCode = 0;
    } else if (watchdogPid <= 0) {
        outcome = "watchdog-fork-failed";
        exitCode = 28;
    } else if (suspendResult != KERN_SUCCESS) {
        outcome = "thread-suspend-denied";
        exitCode = 23;
    } else if (getStateResult != KERN_SUCCESS) {
        outcome = "thread-read-denied";
        exitCode = 24;
    } else if (setSameStateResult != KERN_SUCCESS) {
        outcome = "thread-write-denied";
        exitCode = 25;
    } else if (resumeResult != KERN_SUCCESS || !finalPathValid) {
        outcome = "thread-resume-failed";
        exitCode = 26;
    } else if (rightsDeallocateResult != KERN_SUCCESS ||
               arrayDeallocateResult != KERN_SUCCESS ||
               taskPortDeallocateResult != KERN_SUCCESS) {
        outcome = "cleanup-failed";
        exitCode = 27;
    } else {
        outcome = "same-state-roundtrip";
        exitCode = 0;
    }

    dprintf(
        STDOUT_FILENO,
        "springboardThreadControlProbe summary version=2 mode=%s selfPid=%d "
        "targetPid=%d initialPathValid=%d finalPathValid=%d taskKr=%d "
        "threadsKr=%d threadCount=%u chosenIndex=%d chosenInfoKr=%d "
        "chosenRunState=%d chosenSuspendCount=%d chosenCpuUsage=%d "
        "suspendKr=%d getStateKr=%d stateCount=%u pc=0x%llx sp=0x%llx "
        "stateFlags=0x%x setSameStateKr=%d resumeKr=%d "
        "watchdogPid=%d watchdogStatus=0x%x "
        "rightsDeallocateKr=%d arrayDeallocateKr=%d "
        "taskPortDeallocateKr=%d outcome=%s exitCode=%d\n",
        mode, getpid(), targetPid, initialPathValid, finalPathValid, taskResult,
        threadsResult, threadCount, chosenIndex, chosenInfoResult,
        chosenInfo.run_state, chosenInfo.suspend_count, chosenInfo.cpu_usage,
        suspendResult, getStateResult, stateCount,
        (unsigned long long)__darwin_arm_thread_state64_get_pc(state),
        (unsigned long long)__darwin_arm_thread_state64_get_sp(state),
        state.__pad, setSameStateResult, resumeResult, watchdogPid,
        watchdogStatus,
        rightsDeallocateResult, arrayDeallocateResult,
        taskPortDeallocateResult, outcome, exitCode);
    return exitCode;
}
