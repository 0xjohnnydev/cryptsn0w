#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <os/log.h>
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
#define CODEX_WAIT_ATTEMPTS 500
#define CODEX_WAIT_DELAY_USEC (10 * 1000)

extern int proc_pidpath(int pid, void *buffer, uint32_t bufferSize);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_protect(vm_map_t target,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     boolean_t setMaximum,
                                     vm_prot_t protection);
extern kern_return_t mach_vm_write(vm_map_t target,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t destination,
                                            mach_vm_size_t *copied);
extern kern_return_t mach_vm_remap(
    vm_map_t target, mach_vm_address_t *targetAddress,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
    vm_map_t source, mach_vm_address_t sourceAddress, boolean_t copy,
    vm_prot_t *currentProtection, vm_prot_t *maximumProtection,
    vm_inherit_t inheritance);

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";

static void page_probe_log(const char *message) {
    os_log_t log = os_log_create("com.openai.codex.broker-probe",
                                 "springboard-page-probe");
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT, "%{public}s", message);
}

static bool valid_springboard(pid_t pid) {
    char path[4096] = {0};
    return pid > 1 && proc_pidpath(pid, path, sizeof(path)) > 0 &&
           strcmp(path, kSpringBoardPath) == 0;
}

static bool wait_for_trace_stop(pid_t pid, int *status) {
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        pid_t result = waitpid(pid, status, WUNTRACED | WNOHANG);
        if (result == pid) {
            return WIFSTOPPED(*status);
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
    errno = ETIMEDOUT;
    return false;
}

static kern_return_t flush_remote(mach_port_t task,
                                  mach_vm_address_t address,
                                  mach_vm_size_t size) {
    vm_machine_attribute_val_t value = MATTR_VAL_CACHE_FLUSH;
    return vm_machine_attribute(task, (vm_address_t)address,
                                (vm_size_t)size, MATTR_CACHE, &value);
}

static kern_return_t remap_oracle(mach_port_t task,
                                  mach_vm_address_t source,
                                  mach_vm_size_t size,
                                  vm_prot_t *current,
                                  vm_prot_t *maximum) {
    mach_vm_address_t alias = 0;
    *current = VM_PROT_NONE;
    *maximum = VM_PROT_NONE;
    kern_return_t result = mach_vm_remap(
        task, &alias, size, 0, VM_FLAGS_ANYWHERE, task, source, false,
        current, maximum, VM_INHERIT_NONE);
    if (result == KERN_SUCCESS && alias != 0) {
        (void)mach_vm_deallocate(task, alias, size);
    }
    return result;
}

__attribute__((constructor)) static void codex_springboard_page_probe(void) {
    const char *pidText = getenv("CODEX_PAGE_PROBE_PID");
    char *end = NULL;
    errno = 0;
    long parsed = pidText != NULL ? strtol(pidText, &end, 10) : 0;
    if (errno != 0 || end == pidText || end == NULL || *end != '\0' ||
        parsed <= 1 || parsed > INT32_MAX ||
        !valid_springboard((pid_t)parsed)) {
        char failure[192];
        snprintf(failure, sizeof(failure),
                 "springboardPageProbe phase=validate pid=%ld valid=false "
                 "errno=%d",
                 parsed, errno);
        dprintf(STDERR_FILENO,
                "%s\n", failure);
        page_probe_log(failure);
        return;
    }

    pid_t target = (pid_t)parsed;
    int attachResult = -1;
    int attachError = 0;
    int stopStatus = 0;
    bool stopped = false;
    kern_return_t taskResult = KERN_FAILURE;
    mach_port_t task = MACH_PORT_NULL;
    mach_vm_address_t page = 0;
    mach_vm_size_t pageSize = (mach_vm_size_t)getpagesize();
    kern_return_t allocateResult = KERN_FAILURE;
    kern_return_t initialWriteResult = KERN_FAILURE;
    kern_return_t initialFlushResult = KERN_FAILURE;
    kern_return_t initialRxResult = KERN_FAILURE;
    kern_return_t beforeOracleResult = KERN_FAILURE;
    vm_prot_t beforeCurrent = VM_PROT_NONE;
    vm_prot_t beforeMaximum = VM_PROT_NONE;
    kern_return_t readResult = KERN_FAILURE;
    mach_vm_size_t bytesRead = 0;
    kern_return_t rwResult = KERN_FAILURE;
    kern_return_t rwCopyResult = KERN_FAILURE;
    kern_return_t sameByteWriteResult = KERN_FAILURE;
    kern_return_t debugFlushResult = KERN_FAILURE;
    kern_return_t restoreRxResult = KERN_FAILURE;
    kern_return_t afterOracleResult = KERN_FAILURE;
    vm_prot_t afterCurrent = VM_PROT_NONE;
    vm_prot_t afterMaximum = VM_PROT_NONE;
    int detachResult = -1;
    int detachError = 0;

    errno = 0;
    attachResult = ptrace(CODEX_PT_ATTACHEXC, target, NULL, 0);
    attachError = attachResult == 0 ? 0 : errno;
    if (attachResult == 0) {
        stopped = wait_for_trace_stop(target, &stopStatus);
    }
    if (attachResult == 0 && stopped && valid_springboard(target)) {
        taskResult = task_for_pid(mach_task_self(), target, &task);
    }

    uint8_t sentinel = 0xa5;
    if (taskResult == KERN_SUCCESS && MACH_PORT_VALID(task)) {
        allocateResult = mach_vm_allocate(task, &page, pageSize,
                                          VM_FLAGS_ANYWHERE);
    }
    if (allocateResult == KERN_SUCCESS) {
        initialWriteResult = mach_vm_write(
            task, page + pageSize - 1,
            (vm_offset_t)(uintptr_t)&sentinel,
            (mach_msg_type_number_t)sizeof(sentinel));
    }
    if (initialWriteResult == KERN_SUCCESS) {
        initialFlushResult = flush_remote(task, page, pageSize);
        initialRxResult = mach_vm_protect(
            task, page, pageSize, false,
            VM_PROT_READ | VM_PROT_EXECUTE);
    }
    if (initialRxResult == KERN_SUCCESS) {
        beforeOracleResult = remap_oracle(
            task, page, pageSize, &beforeCurrent, &beforeMaximum);
        readResult = mach_vm_read_overwrite(
            task, page + pageSize - 1, sizeof(sentinel),
            (mach_vm_address_t)(uintptr_t)&sentinel, &bytesRead);
        rwResult = mach_vm_protect(
            task, page, pageSize, false, VM_PROT_READ | VM_PROT_WRITE);
        if (rwResult != KERN_SUCCESS) {
            rwCopyResult = mach_vm_protect(
                task, page, pageSize, false,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        }
        if ((rwResult == KERN_SUCCESS || rwCopyResult == KERN_SUCCESS) &&
            readResult == KERN_SUCCESS && bytesRead == sizeof(sentinel)) {
            sameByteWriteResult = mach_vm_write(
                task, page + pageSize - 1,
                (vm_offset_t)(uintptr_t)&sentinel,
                (mach_msg_type_number_t)sizeof(sentinel));
            if (sameByteWriteResult == KERN_SUCCESS) {
                debugFlushResult = flush_remote(task, page, pageSize);
            }
        }
        if (sameByteWriteResult == KERN_SUCCESS) {
            restoreRxResult = mach_vm_protect(
                task, page, pageSize, false,
                VM_PROT_READ | VM_PROT_EXECUTE);
        }
        if (restoreRxResult == KERN_SUCCESS) {
            afterOracleResult = remap_oracle(
                task, page, pageSize, &afterCurrent, &afterMaximum);
        }
    }

    if (page != 0 && MACH_PORT_VALID(task)) {
        (void)mach_vm_deallocate(task, page, pageSize);
    }
    if (MACH_PORT_VALID(task)) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }
    if (attachResult == 0 && valid_springboard(target)) {
        errno = 0;
        detachResult = ptrace(CODEX_PT_DETACH, target, NULL, 0);
        detachError = detachResult == 0 ? 0 : errno;
        if (detachResult == 0 && valid_springboard(target)) {
            (void)kill(target, SIGCONT);
        }
    }

    bool beforeExecutable = beforeOracleResult == KERN_SUCCESS &&
        (beforeCurrent & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
            (VM_PROT_READ | VM_PROT_EXECUTE);
    bool afterExecutable = afterOracleResult == KERN_SUCCESS &&
        (afterCurrent & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
            (VM_PROT_READ | VM_PROT_EXECUTE);
    char summary[1536];
    snprintf(summary, sizeof(summary),
             "springboardPageProbe summary pid=%d attach=%d attachErrno=%d "
             "stopped=%d stopStatus=0x%x taskKr=%d allocateKr=%d "
             "initialWriteKr=%d initialFlushKr=%d initialRxKr=%d "
             "beforeOracleKr=%d beforeCurrent=0x%x beforeMaximum=0x%x "
             "beforeExecutable=%d readKr=%d bytesRead=0x%llx rwKr=%d "
             "rwCopyKr=%d sameByteWriteKr=%d debugFlushKr=%d "
             "restoreRxKr=%d afterOracleKr=%d afterCurrent=0x%x "
             "afterMaximum=0x%x afterExecutable=%d detach=%d "
             "detachErrno=%d targetStillValid=%d",
             target, attachResult, attachError, stopped, stopStatus,
             taskResult, allocateResult, initialWriteResult,
             initialFlushResult, initialRxResult, beforeOracleResult,
             beforeCurrent, beforeMaximum, beforeExecutable, readResult,
             (unsigned long long)bytesRead, rwResult, rwCopyResult,
             sameByteWriteResult, debugFlushResult, restoreRxResult,
             afterOracleResult, afterCurrent, afterMaximum, afterExecutable,
             detachResult, detachError, valid_springboard(target));
    dprintf(STDOUT_FILENO, "%s\n", summary);
    page_probe_log(summary);
}
