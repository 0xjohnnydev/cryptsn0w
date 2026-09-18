#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_REPORT_MAGIC "codex-donor-remap-v1"

static const char *const kReportPath =
    "/var/mobile/Media/codex-donor-remap-report.txt";

static const uint8_t kDonorPagePrefix[] = {
    /* Entry zero: BTI; low-power loop, keeping this owned process alive. */
    0x5f, 0x24, 0x03, 0xd5, 0x5f, 0x20, 0x03, 0xd5,
    0xff, 0xff, 0xff, 0x17, 0x1f, 0x20, 0x03, 0xd5,
    /* Entry 0x10: BTI; mov w0, #42; ret. */
    0x5f, 0x24, 0x03, 0xd5, 0x40, 0x05, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20, 0x03, 0xd5,
};

extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
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
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outSize);
extern kern_return_t mach_vm_write(vm_map_t target,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);

static int write_report(pid_t pid, mach_vm_address_t address,
                        mach_vm_size_t size, uint32_t csflags) {
    int descriptor = open(kReportPath,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          0644);
    if (descriptor < 0) {
        return 80;
    }
    int length = dprintf(
        descriptor,
        "magic=%s\npid=%d\naddress=0x%llx\nsize=0x%llx\n"
        "entryOffset=0x10\ncsflags=0x%08x\ndebugged=%d\nhard=%d\nkill=%d\n",
        CODEX_REPORT_MAGIC, pid, (unsigned long long)address,
        (unsigned long long)size, csflags,
        (csflags & CODEX_CS_DEBUGGED) != 0,
        (csflags & CODEX_CS_HARD) != 0,
        (csflags & CODEX_CS_KILL) != 0);
    bool ok = length > 0 && fsync(descriptor) == 0;
    int savedError = errno;
    close(descriptor);
    errno = savedError;
    return ok ? 0 : 81;
}

int main(void) {
    const mach_vm_size_t pageSize = (mach_vm_size_t)getpagesize();
    if (getpid() <= 1 || pageSize != 0x4000 ||
        sizeof(kDonorPagePrefix) != 0x20) {
        return 70;
    }

    uint32_t csflags = 0;
    if (csops(getpid(), CODEX_CS_OPS_STATUS, &csflags, sizeof(csflags)) != 0 ||
        (csflags & CODEX_CS_DEBUGGED) == 0 ||
        (csflags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0) {
        return 71;
    }

    mach_port_t task = mach_task_self();
    mach_vm_address_t page = 0;
    kern_return_t result = mach_vm_allocate(
        task, &page, pageSize, VM_FLAGS_ANYWHERE);
    if (result != KERN_SUCCESS || page == 0 ||
        (page & (pageSize - 1U)) != 0) {
        return 72;
    }

    result = mach_vm_write(
        task, page, (vm_offset_t)(uintptr_t)kDonorPagePrefix,
        (mach_msg_type_number_t)sizeof(kDonorPagePrefix));
    if (result != KERN_SUCCESS) {
        (void)mach_vm_deallocate(task, page, pageSize);
        return 73;
    }

    vm_machine_attribute_val_t cacheValue = MATTR_VAL_CACHE_FLUSH;
    result = vm_machine_attribute(
        task, (vm_address_t)page, (vm_size_t)pageSize, MATTR_CACHE,
        &cacheValue);
    if (result != KERN_SUCCESS) {
        (void)mach_vm_deallocate(task, page, pageSize);
        return 74;
    }

    result = mach_vm_protect(
        task, page, pageSize, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if (result != KERN_SUCCESS) {
        (void)mach_vm_deallocate(task, page, pageSize);
        return 75;
    }

    uint8_t readback[sizeof(kDonorPagePrefix)] = {0};
    mach_vm_size_t copied = 0;
    result = mach_vm_read_overwrite(
        task, page, sizeof(readback),
        (mach_vm_address_t)(uintptr_t)readback, &copied);
    if (result != KERN_SUCCESS || copied != sizeof(readback) ||
        memcmp(readback, kDonorPagePrefix, sizeof(readback)) != 0) {
        (void)mach_vm_deallocate(task, page, pageSize);
        return 76;
    }

    int reportResult = write_report(getpid(), page, pageSize, csflags);
    if (reportResult != 0) {
        (void)mach_vm_deallocate(task, page, pageSize);
        return reportResult;
    }

    /* The validated host harness terminates exactly this owned process after
     * deallocating the SpringBoard view. */
    for (;;) {
        pause();
    }
}
