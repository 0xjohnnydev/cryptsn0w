#include <errno.h>
#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CS_OPS_STATUS 0
#define CS_GET_TASK_ALLOW 0x00000004u
#define CS_HARD 0x00000100u
#define CS_KILL 0x00000200u
#define CS_DEBUGGED 0x10000000u

/* sys/ptrace.h is not part of the iPhoneOS SDK. */
#define PT_TRACE_ME 0
#define PT_DETACH 11

#define UNTITLED_PAGE_MAGIC 0x55444350u
#define UNTITLED_WAIT_ATTEMPTS 100
#define UNTITLED_WAIT_DELAY_USEC (50 * 1000)

extern int csops(pid_t pid, unsigned int ops, void *useraddr,
                 size_t usersize);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);

/* These MIG routines are present on iOS, but mach/mach_vm.h is SDK-internal. */
extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_protect(vm_map_t target_task,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     boolean_t set_maximum,
                                     vm_prot_t new_protection);
extern kern_return_t mach_vm_write(vm_map_t target_task,
                                   mach_vm_address_t address, vm_offset_t data,
                                   mach_msg_type_number_t data_count);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *out_size);
extern kern_return_t mach_vm_remap(
    vm_map_t target_task, mach_vm_address_t *target_address,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
    vm_map_t source_task, mach_vm_address_t source_address, boolean_t copy,
    vm_prot_t *current_protection, vm_prot_t *maximum_protection,
    vm_inherit_t inheritance);

typedef struct UntitledPreparedPage {
    uint32_t magic;
    mach_vm_address_t address;
    mach_vm_size_t size;
    kern_return_t allocateResult;
    kern_return_t prepareReadWriteResult;
    kern_return_t initialWriteResult;
    kern_return_t initialCacheFlushResult;
    kern_return_t prepareReadExecuteResult;
} UntitledPreparedPage;

typedef struct UntitledRemapResult {
    kern_return_t result;
    mach_vm_address_t address;
    vm_prot_t currentProtection;
    vm_prot_t maximumProtection;
} UntitledRemapResult;

typedef struct UntitledDebuggerResult {
    kern_return_t taskForPidResult;
    UntitledRemapResult before;
    kern_return_t readResult;
    mach_vm_size_t bytesRead;
    kern_return_t protectReadWriteResult;
    bool protectCopyAttempted;
    kern_return_t protectCopyResult;
    kern_return_t sameByteWriteResult;
    kern_return_t cacheFlushResult;
    kern_return_t restoreReadExecuteResult;
    UntitledRemapResult after;
    const char *outcome;
    int exitCode;
} UntitledDebuggerResult;

static bool HasReadExecute(vm_prot_t protection) {
    const vm_prot_t required = VM_PROT_READ | VM_PROT_EXECUTE;
    return (protection & required) == required;
}

static void LogNumericSysctl(const char *phase, const char *name) {
    uint64_t value = 0;
    size_t size = sizeof(value);
    errno = 0;
    int result = sysctlbyname(name, &value, &size, NULL, 0);
    int savedError = result == 0 ? 0 : errno;
    bool numeric = result == 0 && size > 0 && size <= sizeof(value);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=%s operation=sysctlbyname name=%s "
            "result=%d errno=%d size=%zu numeric=%d value=%llu "
            "valueHex=0x%llx\n",
            phase, name, result, savedError, size, numeric,
            (unsigned long long)value, (unsigned long long)value);
}

static void LogCodeSigningState(const char *phase) {
    uint32_t flags = 0;
    errno = 0;
    int result = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    int savedError = result == 0 ? 0 : errno;
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=%s pid=%d operation=csops-status "
            "result=%d errno=%d csflags=0x%08x getTaskAllow=%d "
            "debugged=%d hard=%d kill=%d\n",
            phase, getpid(), result, savedError, flags,
            (flags & CS_GET_TASK_ALLOW) != 0, (flags & CS_DEBUGGED) != 0,
            (flags & CS_HARD) != 0, (flags & CS_KILL) != 0);
    LogNumericSysctl(phase, "security.codesigning.monitor");
    LogNumericSysctl(phase, "security.codesigning.config");
}

static kern_return_t FlushRemoteCaches(mach_port_t task,
                                       mach_vm_address_t address,
                                       mach_vm_size_t size,
                                       const char *phase) {
    vm_machine_attribute_val_t value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t result = vm_machine_attribute(
        task, (vm_address_t)address, (vm_size_t)size, MATTR_CACHE, &value);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=%s operation=vm_machine_attribute "
            "attribute=%u requestedValue=%d returnedValue=%d kr=%d "
            "address=0x%llx size=0x%llx\n",
            phase, MATTR_CACHE, MATTR_VAL_CACHE_FLUSH, value, result,
            (unsigned long long)address, (unsigned long long)size);
    return result;
}

static UntitledRemapResult RemapExecutableView(mach_port_t task,
                                               mach_vm_address_t source,
                                               mach_vm_size_t size,
                                               const char *phase) {
    UntitledRemapResult remap = {
        .result = KERN_FAILURE,
        .address = 0,
        .currentProtection = VM_PROT_NONE,
        .maximumProtection = VM_PROT_NONE,
    };

    remap.result = mach_vm_remap(
        task, &remap.address, size, 0, VM_FLAGS_ANYWHERE, task, source, FALSE,
        &remap.currentProtection, &remap.maximumProtection, VM_INHERIT_NONE);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=%s operation=mach_vm_remap kr=%d "
            "source=0x%llx address=0x%llx size=0x%llx current=0x%x "
            "maximum=0x%x readExecute=%d\n",
            phase, remap.result, (unsigned long long)source,
            (unsigned long long)remap.address, (unsigned long long)size,
            remap.currentProtection, remap.maximumProtection,
            remap.result == KERN_SUCCESS &&
                HasReadExecute(remap.currentProtection));
    return remap;
}

static void DeallocateIfNeeded(mach_port_t task, mach_vm_address_t *address,
                               mach_vm_size_t size, const char *phase) {
    if (*address == 0) {
        return;
    }
    kern_return_t result = mach_vm_deallocate(task, *address, size);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=%s operation=mach_vm_deallocate kr=%d "
            "address=0x%llx size=0x%llx\n",
            phase, result, (unsigned long long)*address,
            (unsigned long long)size);
    if (result == KERN_SUCCESS) {
        *address = 0;
    }
}

static bool WriteAll(int descriptor, const void *buffer, size_t size) {
    const uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t written = write(descriptor, cursor, size);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        cursor += (size_t)written;
        size -= (size_t)written;
    }
    return true;
}

static bool ReadAll(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = buffer;
    while (size != 0) {
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

static UntitledPreparedPage PrepareAnonymousPage(void) {
    UntitledPreparedPage prepared = {
        .magic = UNTITLED_PAGE_MAGIC,
        .address = 0,
        .size = (mach_vm_size_t)getpagesize(),
        .allocateResult = KERN_FAILURE,
        .prepareReadWriteResult = KERN_FAILURE,
        .initialWriteResult = KERN_FAILURE,
        .initialCacheFlushResult = KERN_FAILURE,
        .prepareReadExecuteResult = KERN_FAILURE,
    };
    mach_port_t task = mach_task_self();
    uint8_t sentinel = 0xa5;

    prepared.allocateResult = mach_vm_allocate(
        task, &prepared.address, prepared.size, VM_FLAGS_ANYWHERE);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=prepare-allocate "
            "operation=mach_vm_allocate kr=%d address=0x%llx size=0x%llx\n",
            prepared.allocateResult, (unsigned long long)prepared.address,
            (unsigned long long)prepared.size);
    if (prepared.allocateResult != KERN_SUCCESS) {
        return prepared;
    }

    prepared.prepareReadWriteResult = mach_vm_protect(
        task, prepared.address, prepared.size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=prepare-rw operation=mach_vm_protect "
            "kr=%d protection=0x%x\n",
            prepared.prepareReadWriteResult,
            VM_PROT_READ | VM_PROT_WRITE);
    if (prepared.prepareReadWriteResult != KERN_SUCCESS) {
        return prepared;
    }

    mach_vm_address_t boundary = prepared.address + prepared.size - 1;
    prepared.initialWriteResult = mach_vm_write(
        task, boundary, (vm_offset_t)(uintptr_t)&sentinel,
        (mach_msg_type_number_t)sizeof(sentinel));
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=prepare-byte operation=mach_vm_write "
            "kr=%d address=0x%llx size=%zu value=0x%02x\n",
            prepared.initialWriteResult, (unsigned long long)boundary,
            sizeof(sentinel), sentinel);
    if (prepared.initialWriteResult != KERN_SUCCESS) {
        return prepared;
    }

    prepared.initialCacheFlushResult = FlushRemoteCaches(
        task, prepared.address, prepared.size, "prepare-cache-flush");
    prepared.prepareReadExecuteResult = mach_vm_protect(
        task, prepared.address, prepared.size, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=prepare-rx operation=mach_vm_protect "
            "kr=%d protection=0x%x\n",
            prepared.prepareReadExecuteResult,
            VM_PROT_READ | VM_PROT_EXECUTE);
    return prepared;
}

static bool PagePreparationSucceeded(const UntitledPreparedPage *prepared) {
    return prepared->allocateResult == KERN_SUCCESS &&
           prepared->prepareReadWriteResult == KERN_SUCCESS &&
           prepared->initialWriteResult == KERN_SUCCESS &&
           prepared->prepareReadExecuteResult == KERN_SUCCESS;
}

static UntitledDebuggerResult RunDebuggerOperations(
    pid_t child, const UntitledPreparedPage *prepared) {
    UntitledDebuggerResult result = {
        .taskForPidResult = KERN_FAILURE,
        .before = {.result = KERN_FAILURE},
        .readResult = KERN_FAILURE,
        .bytesRead = 0,
        .protectReadWriteResult = KERN_FAILURE,
        .protectCopyAttempted = false,
        .protectCopyResult = KERN_FAILURE,
        .sameByteWriteResult = KERN_FAILURE,
        .cacheFlushResult = KERN_FAILURE,
        .restoreReadExecuteResult = KERN_FAILURE,
        .after = {.result = KERN_FAILURE},
        .outcome = "indeterminate",
        .exitCode = 2,
    };
    mach_port_t childTask = MACH_PORT_NULL;
    uint8_t sentinel = 0;
    bool writable = false;

    if (!PagePreparationSucceeded(prepared)) {
        result.outcome = "anonymous-rx-rejected";
        result.exitCode = 1;
        return result;
    }

    result.taskForPidResult =
        task_for_pid(mach_task_self(), child, &childTask);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=task-port operation=task_for_pid "
            "child=%d kr=%d task=0x%x\n",
            child, result.taskForPidResult, childTask);
    if (result.taskForPidResult != KERN_SUCCESS ||
        childTask == MACH_PORT_NULL) {
        result.outcome = "task-port-rejected";
        result.exitCode = 1;
        return result;
    }

    result.before = RemapExecutableView(
        childTask, prepared->address, prepared->size, "remap-before");
    DeallocateIfNeeded(childTask, &result.before.address, prepared->size,
                       "remap-before-cleanup");

    mach_vm_address_t boundary = prepared->address + prepared->size - 1;
    result.readResult = mach_vm_read_overwrite(
        childTask, boundary, sizeof(sentinel),
        (mach_vm_address_t)(uintptr_t)&sentinel, &result.bytesRead);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=debug-read "
            "operation=mach_vm_read_overwrite kr=%d address=0x%llx "
            "requested=%zu read=0x%llx value=0x%02x\n",
            result.readResult, (unsigned long long)boundary,
            sizeof(sentinel), (unsigned long long)result.bytesRead, sentinel);

    result.protectReadWriteResult = mach_vm_protect(
        childTask, prepared->address, prepared->size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=debug-write "
            "operation=mach_vm_protect-rw kr=%d protection=0x%x\n",
            result.protectReadWriteResult,
            VM_PROT_READ | VM_PROT_WRITE);
    if (result.protectReadWriteResult == KERN_SUCCESS) {
        writable = true;
    } else {
        result.protectCopyAttempted = true;
        result.protectCopyResult = mach_vm_protect(
            childTask, prepared->address, prepared->size, FALSE,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        dprintf(STDOUT_FILENO,
                "debuggerCowProbe phase=debug-write "
                "operation=mach_vm_protect-rw-copy kr=%d protection=0x%x\n",
                result.protectCopyResult,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        writable = result.protectCopyResult == KERN_SUCCESS;
    }

    if (writable && result.readResult == KERN_SUCCESS &&
        result.bytesRead == sizeof(sentinel)) {
        result.sameByteWriteResult = mach_vm_write(
            childTask, boundary, (vm_offset_t)(uintptr_t)&sentinel,
            (mach_msg_type_number_t)sizeof(sentinel));
        dprintf(STDOUT_FILENO,
                "debuggerCowProbe phase=debug-write "
                "operation=mach_vm_write-same-byte kr=%d address=0x%llx "
                "size=%zu value=0x%02x\n",
                result.sameByteWriteResult, (unsigned long long)boundary,
                sizeof(sentinel), sentinel);
        if (result.sameByteWriteResult == KERN_SUCCESS) {
            result.cacheFlushResult = FlushRemoteCaches(
                childTask, prepared->address, prepared->size,
                "debug-cache-flush");
        }
    } else {
        dprintf(STDOUT_FILENO,
                "debuggerCowProbe phase=debug-write "
                "operation=mach_vm_write-same-byte skipped=1 "
                "writable=%d readKr=%d bytesRead=0x%llx\n",
                writable, result.readResult,
                (unsigned long long)result.bytesRead);
    }

    result.restoreReadExecuteResult = mach_vm_protect(
        childTask, prepared->address, prepared->size, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=restore-rx operation=mach_vm_protect "
            "kr=%d protection=0x%x\n",
            result.restoreReadExecuteResult,
            VM_PROT_READ | VM_PROT_EXECUTE);
    if (result.restoreReadExecuteResult == KERN_SUCCESS) {
        result.after = RemapExecutableView(
            childTask, prepared->address, prepared->size, "remap-after");
        DeallocateIfNeeded(childTask, &result.after.address, prepared->size,
                           "remap-after-cleanup");
    }

    bool beforeExecutable = result.before.result == KERN_SUCCESS &&
                            HasReadExecute(result.before.currentProtection);
    bool afterExecutable = result.after.result == KERN_SUCCESS &&
                           HasReadExecute(result.after.currentProtection);
    bool debugWriteSucceeded = writable &&
                               result.readResult == KERN_SUCCESS &&
                               result.bytesRead == sizeof(sentinel) &&
                               result.sameByteWriteResult == KERN_SUCCESS &&
                               result.restoreReadExecuteResult == KERN_SUCCESS;
    if (result.before.result != KERN_SUCCESS) {
        result.outcome = "remap-oracle-unavailable";
        result.exitCode = 2;
    } else if (beforeExecutable) {
        result.outcome = "mapping-not-enforced";
        result.exitCode = 0;
    } else if (debugWriteSucceeded && afterExecutable) {
        result.outcome = "debugger-cow-supported";
        result.exitCode = 0;
    } else {
        result.outcome = "debugger-cow-rejected";
        result.exitCode = 1;
    }

    kern_return_t releaseResult =
        mach_port_deallocate(mach_task_self(), childTask);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=task-port "
            "operation=mach_port_deallocate kr=%d task=0x%x\n",
            releaseResult, childTask);
    return result;
}

static int RunChild(int resultDescriptor) {
    LogCodeSigningState("child-before-trace-me");
    errno = 0;
    int traceResult = ptrace(PT_TRACE_ME, 0, NULL, 0);
    int traceError = traceResult == 0 ? 0 : errno;
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=trace-me pid=%d ppid=%d ptrace=%d "
            "errno=%d\n",
            getpid(), getppid(), traceResult, traceError);
    if (traceResult != 0) {
        return 1;
    }

    LogCodeSigningState("child-after-trace-me");
    UntitledPreparedPage prepared = PrepareAnonymousPage();
    errno = 0;
    bool sent = WriteAll(resultDescriptor, &prepared, sizeof(prepared));
    int sendError = sent ? 0 : errno;
    close(resultDescriptor);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=prepare-report operation=write "
            "result=%d errno=%d size=%zu\n",
            sent, sendError, sizeof(prepared));
    if (!sent) {
        DeallocateIfNeeded(mach_task_self(), &prepared.address, prepared.size,
                           "child-send-failed-cleanup");
        return 2;
    }

    if (raise(SIGSTOP) != 0) {
        int stopError = errno;
        dprintf(STDOUT_FILENO,
                "debuggerCowProbe phase=trace-stop pid=%d raise=-1 "
                "errno=%d\n",
                getpid(), stopError);
        DeallocateIfNeeded(mach_task_self(), &prepared.address, prepared.size,
                           "child-stop-failed-cleanup");
        return 3;
    }

    LogCodeSigningState("child-after-detach");
    DeallocateIfNeeded(mach_task_self(), &prepared.address, prepared.size,
                       "child-source-cleanup");
    return 0;
}

static int WaitForChildExit(pid_t child) {
    int status = 0;
    for (int attempt = 0; attempt < UNTITLED_WAIT_ATTEMPTS; attempt++) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                dprintf(STDOUT_FILENO,
                        "debuggerCowProbe phase=child-exit child=%d "
                        "exited=%d\n",
                        child, code);
                return code;
            }
            if (WIFSIGNALED(status)) {
                dprintf(STDOUT_FILENO,
                        "debuggerCowProbe phase=child-exit child=%d "
                        "signal=%d\n",
                        child, WTERMSIG(status));
                return 128 + WTERMSIG(status);
            }
            return 4;
        }
        if (waited < 0 && errno != EINTR) {
            dprintf(STDOUT_FILENO,
                    "debuggerCowProbe phase=child-exit child=%d "
                    "waitpid=-1 errno=%d\n",
                    child, errno);
            return 5;
        }
        usleep(UNTITLED_WAIT_DELAY_USEC);
    }

    errno = 0;
    int killResult = kill(child, SIGKILL);
    int killError = killResult == 0 ? 0 : errno;
    do {
        errno = 0;
    } while (waitpid(child, &status, 0) < 0 && errno == EINTR);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=child-timeout child=%d kill=%d errno=%d\n",
            child, killResult, killError);
    return 6;
}

static void KillAndReapOwnChild(pid_t child, const char *phase) {
    int status = 0;
    errno = 0;
    int killResult = kill(child, SIGKILL);
    int killError = killResult == 0 ? 0 : errno;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=%s child=%d operation=kill-own-child "
            "kill=%d errno=%d waitpid=%d status=0x%x\n",
            phase, child, killResult, killError, waited, status);
}

int main(int argc, char **argv) {
    if (argc != 1) {
        dprintf(STDERR_FILENO, "usage: %s\n", argv[0]);
        return 64;
    }

    int resultPipe[2];
    if (pipe(resultPipe) != 0) {
        dprintf(STDERR_FILENO,
                "debuggerCowProbe phase=pipe result=-1 errno=%d\n", errno);
        return 71;
    }

    pid_t child = fork();
    if (child < 0) {
        int forkError = errno;
        close(resultPipe[0]);
        close(resultPipe[1]);
        dprintf(STDERR_FILENO,
                "debuggerCowProbe phase=fork fork=-1 errno=%d\n",
                forkError);
        return 72;
    }
    if (child == 0) {
        close(resultPipe[0]);
        _exit(RunChild(resultPipe[1]));
    }
    close(resultPipe[1]);
    if (child <= 1) {
        close(resultPipe[0]);
        dprintf(STDERR_FILENO,
                "debuggerCowProbe phase=fork unsafeChild=%d\n", child);
        return 73;
    }

    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=fork parent=%d child=%d "
            "projectOwned=1 externalTarget=0 executesPage=0\n",
            getpid(), child);

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, WUNTRACED);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) {
        int waitError = errno;
        close(resultPipe[0]);
        KillAndReapOwnChild(child, "trace-wait-failed");
        dprintf(STDERR_FILENO,
                "debuggerCowProbe phase=trace-wait child=%d waitpid=%d "
                "errno=%d\n",
                child, waited, waitError);
        return 74;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        close(resultPipe[0]);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            dprintf(STDOUT_FILENO,
                    "debuggerCowProbe phase=trace-wait child=%d exited=%d "
                    "stopped=0\n",
                    child, code);
            return code;
        }
        if (WIFSIGNALED(status)) {
            dprintf(STDOUT_FILENO,
                    "debuggerCowProbe phase=trace-wait child=%d signal=%d "
                    "stopped=0\n",
                    child, WTERMSIG(status));
            return 128 + WTERMSIG(status);
        }
        KillAndReapOwnChild(child, "unexpected-trace-stop");
        return 75;
    }

    UntitledPreparedPage prepared;
    memset(&prepared, 0, sizeof(prepared));
    errno = 0;
    bool received = ReadAll(resultPipe[0], &prepared, sizeof(prepared));
    int receiveError = received ? 0 : errno;
    close(resultPipe[0]);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=prepare-report operation=read "
            "result=%d errno=%d size=%zu magic=0x%08x\n",
            received, receiveError, sizeof(prepared), prepared.magic);
    if (!received || prepared.magic != UNTITLED_PAGE_MAGIC) {
        KillAndReapOwnChild(child, "invalid-prepare-report");
        return 76;
    }

    LogCodeSigningState("parent-after-child-stop");
    UntitledDebuggerResult result =
        RunDebuggerOperations(child, &prepared);

    errno = 0;
    int detachResult = ptrace(PT_DETACH, child, NULL, 0);
    int detachError = detachResult == 0 ? 0 : errno;
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe phase=detach child=%d ptrace=%d errno=%d\n",
            child, detachResult, detachError);
    if (detachResult != 0) {
        KillAndReapOwnChild(child, "detach-failed");
        return 77;
    }

    int childExit = WaitForChildExit(child);
    dprintf(STDOUT_FILENO,
            "debuggerCowProbe summary parent=%d child=%d outcome=%s "
            "childExit=%d pageSize=0x%llx allocateKr=%d prepareRwKr=%d "
            "initialWriteKr=%d initialCacheFlushKr=%d prepareRxKr=%d "
            "taskForPidKr=%d beforeRemapKr=%d beforeCurrent=0x%x "
            "beforeMaximum=0x%x readKr=%d bytesRead=0x%llx protectRwKr=%d "
            "protectCopyAttempted=%d protectCopyKr=%d sameByteWriteKr=%d "
            "cacheFlushKr=%d restoreRxKr=%d afterRemapKr=%d "
            "afterCurrent=0x%x afterMaximum=0x%x projectOwned=1 "
            "externalTarget=0 executesPage=0 usesMapJit=0\n",
            getpid(), child, result.outcome, childExit,
            (unsigned long long)prepared.size, prepared.allocateResult,
            prepared.prepareReadWriteResult, prepared.initialWriteResult,
            prepared.initialCacheFlushResult,
            prepared.prepareReadExecuteResult, result.taskForPidResult,
            result.before.result, result.before.currentProtection,
            result.before.maximumProtection, result.readResult,
            (unsigned long long)result.bytesRead,
            result.protectReadWriteResult, result.protectCopyAttempted,
            result.protectCopyResult, result.sameByteWriteResult,
            result.cacheFlushResult, result.restoreReadExecuteResult,
            result.after.result, result.after.currentProtection,
            result.after.maximumProtection);
    if (childExit != 0) {
        return childExit;
    }
    return result.exitCode;
}
