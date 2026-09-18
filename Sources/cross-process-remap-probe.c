#include <errno.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t destination,
                                            mach_vm_size_t *copied);
extern kern_return_t mach_vm_region_recurse(
    vm_map_read_t target, mach_vm_address_t *address,
    mach_vm_size_t *size, natural_t *nestingDepth,
    vm_region_recurse_info_t info, mach_msg_type_number_t *infoCount);
extern kern_return_t mach_vm_remap(
    vm_map_t target, mach_vm_address_t *targetAddress,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
    vm_map_t source, mach_vm_address_t sourceAddress, boolean_t copy,
    vm_prot_t *currentProtection, vm_prot_t *maximumProtection,
    vm_inherit_t inheritance);
extern kern_return_t mach_vm_write(vm_map_t target,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);

#define CODEX_SAMPLE_SIZE 64U
#define CODEX_REGION_MAX_DEPTH 32U
#define CODEX_MARKER_ATTEMPTS 500U
#define CODEX_MARKER_DELAY_USEC 2000U
#define CODEX_REMOTE_MARKER UINT64_C(0x4352584d41524b31)

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";

typedef struct RegionSnapshot {
    kern_return_t result;
    mach_vm_address_t address;
    mach_vm_size_t size;
    vm_prot_t currentProtection;
    vm_prot_t maximumProtection;
    unsigned char shareMode;
    unsigned int userTag;
    unsigned short flags;
    unsigned char externalPager;
    natural_t depth;
} RegionSnapshot;

typedef struct ExecutionResult {
    mach_vm_address_t scratchAddress;
    mach_vm_address_t stackAddress;
    kern_return_t scratchAllocateResult;
    kern_return_t scratchWriteResult;
    kern_return_t stackAllocateResult;
    kern_return_t threadCreateResult;
    kern_return_t markerReadResult;
    mach_vm_size_t markerBytesRead;
    uint64_t markerValue;
    unsigned int markerAttempts;
    bool markerObserved;
    kern_return_t threadSuspendResult;
    kern_return_t threadTerminateResult;
    kern_return_t threadPortDeallocateResult;
    kern_return_t scratchDeallocateResult;
    kern_return_t stackDeallocateResult;
} ExecutionResult;

__attribute__((noinline, used))
static uint64_t remap_sentinel(uint64_t value) {
    return (value ^ UINT64_C(0x43524f535352584d)) + UINT64_C(0x102030405060708);
}

__attribute__((naked, used, aligned(16384)))
static void remote_marker_stub(void) {
    __asm__ volatile(
        ".inst 0xd503245f\n"
        "movz x1, #0x4b31\n"
        "movk x1, #0x4152, lsl #16\n"
        "movk x1, #0x584d, lsl #32\n"
        "movk x1, #0x4352, lsl #48\n"
        "str x1, [x0]\n"
        "dmb ish\n"
        "mov x9, #0x42\n"
        "1:\n"
        "wfe\n"
        "b 1b\n");
}

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

static RegionSnapshot query_region(vm_map_read_t task,
                                   mach_vm_address_t requestedAddress) {
    RegionSnapshot snapshot = {
        .result = KERN_FAILURE,
        .address = requestedAddress,
    };
    natural_t depth = 0;

    for (unsigned int attempt = 0; attempt < CODEX_REGION_MAX_DEPTH;
         ++attempt) {
        mach_vm_address_t address = requestedAddress;
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            task, &address, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        snapshot.result = result;
        snapshot.address = address;
        snapshot.size = size;
        snapshot.depth = depth;
        if (result != KERN_SUCCESS) {
            return snapshot;
        }
        if (info.is_submap) {
            ++depth;
            continue;
        }

        snapshot.currentProtection = info.protection;
        snapshot.maximumProtection = info.max_protection;
        snapshot.shareMode = info.share_mode;
        snapshot.userTag = info.user_tag;
        snapshot.flags = info.flags;
        snapshot.externalPager = info.external_pager;
        return snapshot;
    }

    snapshot.result = KERN_RESOURCE_SHORTAGE;
    return snapshot;
}

static bool has_read_execute(vm_prot_t protection) {
    const vm_prot_t required = VM_PROT_READ | VM_PROT_EXECUTE;
    return (protection & required) == required;
}

static ExecutionResult execute_remote_marker(mach_port_t task,
                                             mach_vm_address_t entry,
                                             mach_vm_size_t pageSize) {
    ExecutionResult result = {
        .scratchAllocateResult = KERN_INVALID_ARGUMENT,
        .scratchWriteResult = KERN_INVALID_ARGUMENT,
        .stackAllocateResult = KERN_INVALID_ARGUMENT,
        .threadCreateResult = KERN_INVALID_ARGUMENT,
        .markerReadResult = KERN_INVALID_ARGUMENT,
        .threadSuspendResult = KERN_INVALID_ARGUMENT,
        .threadTerminateResult = KERN_INVALID_ARGUMENT,
        .threadPortDeallocateResult = KERN_INVALID_ARGUMENT,
        .scratchDeallocateResult = KERN_INVALID_ARGUMENT,
        .stackDeallocateResult = KERN_INVALID_ARGUMENT,
    };
    uint64_t initialMarker = 0;
    thread_act_t remoteThread = MACH_PORT_NULL;

    result.scratchAllocateResult = mach_vm_allocate(
        task, &result.scratchAddress, pageSize, VM_FLAGS_ANYWHERE);
    if (result.scratchAllocateResult == KERN_SUCCESS) {
        result.scratchWriteResult = mach_vm_write(
            task, result.scratchAddress,
            (vm_offset_t)(uintptr_t)&initialMarker,
            (mach_msg_type_number_t)sizeof(initialMarker));
    }
    if (result.scratchWriteResult == KERN_SUCCESS) {
        result.stackAllocateResult = mach_vm_allocate(
            task, &result.stackAddress, pageSize, VM_FLAGS_ANYWHERE);
    }
    if (result.stackAllocateResult == KERN_SUCCESS) {
        arm_thread_state64_t state = {0};
        state.__x[0] = result.scratchAddress;
        __darwin_arm_thread_state64_set_sp(
            state, result.stackAddress + pageSize - 16U);
        __darwin_arm_thread_state64_set_pc_fptr(
            state, (void *)(uintptr_t)entry);
        result.threadCreateResult = thread_create_running(
            task, ARM_THREAD_STATE64, (thread_state_t)&state,
            ARM_THREAD_STATE64_COUNT, &remoteThread);
    }

    if (result.threadCreateResult == KERN_SUCCESS &&
        MACH_PORT_VALID(remoteThread)) {
        for (unsigned int attempt = 1; attempt <= CODEX_MARKER_ATTEMPTS;
             ++attempt) {
            result.markerValue = 0;
            result.markerBytesRead = 0;
            result.markerReadResult = mach_vm_read_overwrite(
                task, result.scratchAddress, sizeof(result.markerValue),
                (mach_vm_address_t)(uintptr_t)&result.markerValue,
                &result.markerBytesRead);
            result.markerAttempts = attempt;
            if (result.markerReadResult == KERN_SUCCESS &&
                result.markerBytesRead == sizeof(result.markerValue) &&
                result.markerValue == CODEX_REMOTE_MARKER) {
                result.markerObserved = true;
                break;
            }
            usleep(CODEX_MARKER_DELAY_USEC);
        }

        result.threadSuspendResult = thread_suspend(remoteThread);
        result.threadTerminateResult = thread_terminate(remoteThread);
        if (result.threadTerminateResult == KERN_SUCCESS) {
            usleep(10U * 1000U);
        }
        result.threadPortDeallocateResult =
            mach_port_deallocate(mach_task_self(), remoteThread);
        remoteThread = MACH_PORT_NULL;
    }

    bool threadStopped = result.threadCreateResult != KERN_SUCCESS ||
                         result.threadTerminateResult == KERN_SUCCESS ||
                         result.threadTerminateResult == KERN_TERMINATED;
    if (threadStopped && result.stackAddress != 0) {
        result.stackDeallocateResult =
            mach_vm_deallocate(task, result.stackAddress, pageSize);
    }
    if (threadStopped && result.scratchAddress != 0) {
        result.scratchDeallocateResult =
            mach_vm_deallocate(task, result.scratchAddress, pageSize);
    }
    return result;
}

int main(int argc, char **argv) {
    bool executionRequested =
        argc == 2 && strcmp(argv[1], "--execute-marker") == 0;
    if (argc != 1 && !executionRequested) {
        dprintf(STDERR_FILENO,
                "usage: %s [--execute-marker]\n", argv[0]);
        return 64;
    }
    const mach_vm_size_t pageSize = (mach_vm_size_t)getpagesize();
    const mach_vm_address_t functionAddress =
        executionRequested
            ? (mach_vm_address_t)(uintptr_t)&remote_marker_stub
            : (mach_vm_address_t)(uintptr_t)&remap_sentinel;
    const mach_vm_address_t sourcePage =
        functionAddress & ~(pageSize - UINT64_C(1));
    const mach_vm_size_t functionOffset = functionAddress - sourcePage;
    uint8_t sourceBytes[CODEX_SAMPLE_SIZE] = {0};
    uint8_t remoteBytes[CODEX_SAMPLE_SIZE] = {0};
    memcpy(sourceBytes, (const void *)(uintptr_t)functionAddress,
           sizeof(sourceBytes));

    RegionSnapshot sourceRegion =
        query_region(mach_task_self(), sourcePage);
    pid_t targetPid = find_springboard();
    bool initialPathValid = springboard_path_matches(targetPid);
    mach_port_t targetTask = MACH_PORT_NULL;
    kern_return_t taskResult = KERN_INVALID_ARGUMENT;
    mach_vm_address_t remotePage = 0;
    vm_prot_t returnedCurrent = VM_PROT_NONE;
    vm_prot_t returnedMaximum = VM_PROT_NONE;
    kern_return_t remapResult = KERN_INVALID_ARGUMENT;
    RegionSnapshot remoteRegion = {.result = KERN_INVALID_ARGUMENT};
    kern_return_t readResult = KERN_INVALID_ARGUMENT;
    mach_vm_size_t bytesRead = 0;

    if (initialPathValid) {
        taskResult = task_for_pid(mach_task_self(), targetPid, &targetTask);
    }
    bool taskPortAcquired =
        taskResult == KERN_SUCCESS && MACH_PORT_VALID(targetTask);
    if (taskPortAcquired) {
        remapResult = mach_vm_remap(
            targetTask, &remotePage, pageSize, 0, VM_FLAGS_ANYWHERE,
            mach_task_self(), sourcePage, FALSE, &returnedCurrent,
            &returnedMaximum, VM_INHERIT_NONE);
    }
    if (remapResult == KERN_SUCCESS && remotePage != 0) {
        remoteRegion = query_region(targetTask, remotePage);
        readResult = mach_vm_read_overwrite(
            targetTask, remotePage + functionOffset, sizeof(remoteBytes),
            (mach_vm_address_t)(uintptr_t)remoteBytes, &bytesRead);
    }

    bool bytesEqual = readResult == KERN_SUCCESS &&
                      bytesRead == sizeof(remoteBytes) &&
                      memcmp(sourceBytes, remoteBytes, sizeof(sourceBytes)) == 0;
    bool returnedExecutable = remapResult == KERN_SUCCESS &&
                              has_read_execute(returnedCurrent);
    bool regionExecutable = remoteRegion.result == KERN_SUCCESS &&
                            has_read_execute(remoteRegion.currentProtection);

    ExecutionResult execution = {
        .scratchAllocateResult = KERN_INVALID_ARGUMENT,
        .scratchWriteResult = KERN_INVALID_ARGUMENT,
        .stackAllocateResult = KERN_INVALID_ARGUMENT,
        .threadCreateResult = KERN_INVALID_ARGUMENT,
        .markerReadResult = KERN_INVALID_ARGUMENT,
        .threadSuspendResult = KERN_INVALID_ARGUMENT,
        .threadTerminateResult = KERN_INVALID_ARGUMENT,
        .threadPortDeallocateResult = KERN_INVALID_ARGUMENT,
        .scratchDeallocateResult = KERN_INVALID_ARGUMENT,
        .stackDeallocateResult = KERN_INVALID_ARGUMENT,
    };
    if (executionRequested && bytesEqual && returnedExecutable &&
        regionExecutable) {
        execution = execute_remote_marker(
            targetTask, remotePage + functionOffset, pageSize);
    }

    kern_return_t deallocateResult = KERN_INVALID_ARGUMENT;
    bool executionThreadStopped =
        !executionRequested || execution.threadCreateResult != KERN_SUCCESS ||
        execution.threadTerminateResult == KERN_SUCCESS ||
        execution.threadTerminateResult == KERN_TERMINATED;
    if (executionThreadStopped && remotePage != 0 &&
        MACH_PORT_VALID(targetTask)) {
        deallocateResult =
            mach_vm_deallocate(targetTask, remotePage, pageSize);
    }
    kern_return_t portDeallocateResult = KERN_INVALID_ARGUMENT;
    if (MACH_PORT_VALID(targetTask)) {
        portDeallocateResult =
            mach_port_deallocate(mach_task_self(), targetTask);
        targetTask = MACH_PORT_NULL;
    }
    bool finalPathValid = springboard_path_matches(targetPid);

    const char *outcome = "unknown";
    int exitCode = 29;
    if (!initialPathValid) {
        outcome = "target-not-found";
        exitCode = 20;
    } else if (!taskPortAcquired) {
        outcome = "task-port-denied";
        exitCode = 21;
    } else if (remapResult != KERN_SUCCESS || remotePage == 0) {
        outcome = "remap-denied";
        exitCode = 22;
    } else if (!bytesEqual) {
        outcome = "readback-mismatch";
        exitCode = 23;
    } else if (!returnedExecutable || !regionExecutable) {
        outcome = "execute-stripped";
        exitCode = 24;
    } else if (executionRequested &&
               (execution.scratchAllocateResult != KERN_SUCCESS ||
                execution.scratchWriteResult != KERN_SUCCESS ||
                execution.stackAllocateResult != KERN_SUCCESS)) {
        outcome = "execution-setup-failed";
        exitCode = 30;
    } else if (executionRequested &&
               execution.threadCreateResult != KERN_SUCCESS) {
        outcome = "thread-create-denied";
        exitCode = 31;
    } else if (executionRequested && !execution.markerObserved) {
        outcome = "marker-not-observed";
        exitCode = 32;
    } else if (executionRequested && !finalPathValid) {
        outcome = "target-lost";
        exitCode = 34;
    } else if (deallocateResult != KERN_SUCCESS ||
               portDeallocateResult != KERN_SUCCESS ||
               (executionRequested &&
                (execution.threadTerminateResult != KERN_SUCCESS ||
                 execution.threadPortDeallocateResult != KERN_SUCCESS ||
                 execution.scratchDeallocateResult != KERN_SUCCESS ||
                 execution.stackDeallocateResult != KERN_SUCCESS))) {
        outcome = "cleanup-failed";
        exitCode = executionRequested ? 33 : 25;
    } else if (executionRequested) {
        outcome = "marker-executed";
        exitCode = 0;
    } else {
        outcome = "rx-survived";
        exitCode = 0;
    }

    dprintf(
        STDOUT_FILENO,
        "crossProcessRemapProbe summary version=2 mode=%s selfPid=%d "
        "targetPid=%d "
        "initialPathValid=%d finalPathValid=%d pageSize=0x%llx "
        "sourcePage=0x%llx functionOffset=0x%llx sourceRegionKr=%d "
        "sourceCurrent=0x%x sourceMaximum=0x%x sourceShareMode=%u "
        "sourceUserTag=%u sourceFlags=0x%x sourceExternalPager=%u "
        "taskKr=%d remapKr=%d remotePage=0x%llx returnedCurrent=0x%x "
        "returnedMaximum=0x%x returnedExecutable=%d regionKr=%d "
        "regionAddress=0x%llx regionSize=0x%llx regionCurrent=0x%x "
        "regionMaximum=0x%x regionShareMode=%u regionUserTag=%u "
        "regionFlags=0x%x regionExternalPager=%u regionExecutable=%d "
        "readKr=%d bytesRead=0x%llx bytesEqual=%d scratchAddress=0x%llx "
        "scratchAllocateKr=%d scratchWriteKr=%d stackAddress=0x%llx "
        "stackAllocateKr=%d threadCreateKr=%d markerReadKr=%d "
        "markerBytesRead=0x%llx markerValue=0x%llx markerAttempts=%u "
        "markerObserved=%d threadSuspendKr=%d threadTerminateKr=%d "
        "threadPortDeallocateKr=%d scratchDeallocateKr=%d "
        "stackDeallocateKr=%d deallocateKr=%d portDeallocateKr=%d "
        "outcome=%s exitCode=%d\n",
        executionRequested ? "execute-marker" : "remap-only", getpid(),
        targetPid, initialPathValid, finalPathValid,
        (unsigned long long)pageSize, (unsigned long long)sourcePage,
        (unsigned long long)functionOffset, sourceRegion.result,
        sourceRegion.currentProtection, sourceRegion.maximumProtection,
        sourceRegion.shareMode, sourceRegion.userTag, sourceRegion.flags,
        sourceRegion.externalPager, taskResult, remapResult,
        (unsigned long long)remotePage, returnedCurrent, returnedMaximum,
        returnedExecutable, remoteRegion.result,
        (unsigned long long)remoteRegion.address,
        (unsigned long long)remoteRegion.size, remoteRegion.currentProtection,
        remoteRegion.maximumProtection, remoteRegion.shareMode,
        remoteRegion.userTag, remoteRegion.flags, remoteRegion.externalPager,
        regionExecutable, readResult, (unsigned long long)bytesRead,
        bytesEqual, (unsigned long long)execution.scratchAddress,
        execution.scratchAllocateResult, execution.scratchWriteResult,
        (unsigned long long)execution.stackAddress,
        execution.stackAllocateResult, execution.threadCreateResult,
        execution.markerReadResult,
        (unsigned long long)execution.markerBytesRead,
        (unsigned long long)execution.markerValue, execution.markerAttempts,
        execution.markerObserved, execution.threadSuspendResult,
        execution.threadTerminateResult,
        execution.threadPortDeallocateResult,
        execution.scratchDeallocateResult, execution.stackDeallocateResult,
        deallocateResult, portDeallocateResult, outcome, exitCode);
    return exitCode;
}
