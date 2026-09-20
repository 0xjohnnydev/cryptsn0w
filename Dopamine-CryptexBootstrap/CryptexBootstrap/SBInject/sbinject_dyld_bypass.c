// Hardened, target-pinned port of the supplied SBInject dyld bypass.
#include "sbinject_dyld_bypass.h"

#include <errno.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <ptrauth.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef F_ADDFILESIGS_RETURN
#define F_ADDFILESIGS_RETURN 97
#endif
#ifndef F_CHECK_LV
#define F_CHECK_LV 98
#endif

static const uint8_t k_mmap_signature[] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
static const uint8_t k_fcntl_signature[] = {
    0x90, 0x0b, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
static const size_t k_mmap_offset = 0x147d4U;
static const size_t k_fcntl_offset = 0x0b6ccU;
static const size_t k_dyld_scan_size = 0x80000U;

extern void *__mmap(void *address, size_t length, int protection, int flags,
                    int descriptor, off_t offset);
extern int __fcntl(int descriptor, int command, void *argument);

static int (*original_fcntl)(int, int, void *);

__attribute__((naked)) static kern_return_t raw_vm_protect(
    mach_port_name_t task, mach_vm_address_t address, mach_vm_size_t size,
    boolean_t maximum, vm_prot_t protection) {
    __asm("mov x16, #-14");
    __asm("svc 0x80");
    __asm("ret");
}

static void copy_bytes(uint8_t *destination, const uint8_t *source,
                       size_t amount) {
    for (size_t index = 0; index < amount; ++index) {
        destination[index] = source[index];
    }
}

static bool write_absolute_jump(void *location, void *replacement) {
    static const uint8_t jump_template[24] = {
        0x88, 0x00, 0x00, 0x58, 0x00, 0x01, 0x1f, 0xd6,
        0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    kern_return_t result = raw_vm_protect(
        mach_task_self(), (mach_vm_address_t)location, sizeof(jump_template),
        false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (result != KERN_SUCCESS) {
        return false;
    }
    copy_bytes(location, jump_template, sizeof(jump_template));
    uintptr_t target = (uintptr_t)ptrauth_strip(
        replacement, ptrauth_key_function_pointer);
    copy_bytes((uint8_t *)location + 16U, (const uint8_t *)&target,
               sizeof(target));
    sys_icache_invalidate(location, sizeof(jump_template));
    return raw_vm_protect(mach_task_self(), (mach_vm_address_t)location,
                          sizeof(jump_template), false,
                          VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS;
}

static void *dyld_base(void) {
    task_dyld_info_data_t information = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO,
                  (task_info_t)&information, &count) != KERN_SUCCESS ||
        information.all_image_info_addr == 0) {
        return NULL;
    }
    const struct dyld_all_image_infos *images =
        (const struct dyld_all_image_infos *)information.all_image_info_addr;
    return (void *)images->dyldImageLoadAddress;
}

static bool signature_is_unique(const uint8_t *base, const uint8_t *signature,
                                size_t signature_size, size_t expected_offset) {
    size_t matches = 0;
    size_t observed = 0;
    for (size_t offset = 0;
         offset + signature_size <= k_dyld_scan_size; offset += 4U) {
        if (base[offset] == signature[0] &&
            memcmp(base + offset, signature, signature_size) == 0) {
            ++matches;
            observed = offset;
        }
    }
    return matches == 1U && observed == expected_offset;
}

static void *bypass_mmap(void *address, size_t length, int protection,
                         int flags, int descriptor, off_t offset) {
    if ((flags & MAP_JIT) != 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    void *mapping = __mmap(address, length, protection, flags, descriptor,
                           offset);
    if (descriptor == -1 || (protection & PROT_EXEC) == 0) {
        return mapping;
    }
    if (mapping != MAP_FAILED && mprotect(mapping, length, protection) == 0) {
        return mapping;
    }
    if (mapping != MAP_FAILED) {
        (void)munmap(mapping, length);
    }

    void *source = __mmap(NULL, length, PROT_READ, MAP_PRIVATE, descriptor,
                          offset);
    if (source == MAP_FAILED) {
        return MAP_FAILED;
    }
    int anonymous_flags = (flags & ~MAP_SHARED) | MAP_PRIVATE | MAP_ANON;
    mapping = __mmap(address, length, PROT_READ | PROT_WRITE,
                     anonymous_flags, -1, 0);
    if (mapping == MAP_FAILED) {
        (void)munmap(source, length);
        return MAP_FAILED;
    }
    memcpy(mapping, source, length);
    (void)munmap(source, length);
    if (mprotect(mapping, length, protection) != 0) {
        int saved_error = errno;
        (void)munmap(mapping, length);
        errno = saved_error;
        return MAP_FAILED;
    }
    return mapping;
}

static int bypass_fcntl(int descriptor, int command, void *argument) {
    if (command == F_ADDFILESIGS_RETURN) {
        (void)original_fcntl(descriptor, command, argument);
        if (argument != NULL) {
            fsignatures_t *signatures = argument;
            signatures->fs_file_start = 0xffffffffU;
        }
        return 0;
    }
    if (command == F_CHECK_LV) {
        return 0;
    }
    return original_fcntl(descriptor, command, argument);
}

bool sbinject_install_dyld_validation_bypass(void) {
    static bool attempted;
    static bool installed;
    if (attempted) {
        return installed;
    }
    attempted = true;
    uint8_t *base = dyld_base();
    if (base == NULL ||
        !signature_is_unique(base, k_mmap_signature,
                             sizeof(k_mmap_signature), k_mmap_offset) ||
        !signature_is_unique(base, k_fcntl_signature,
                             sizeof(k_fcntl_signature), k_fcntl_offset)) {
        return false;
    }
    original_fcntl = __fcntl;
    struct sigaction ignored = {0};
    struct sigaction prior = {0};
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    (void)sigaction(SIGBUS, &ignored, &prior);
    bool mmap_ready = write_absolute_jump(base + k_mmap_offset, bypass_mmap);
    bool fcntl_ready =
        mmap_ready &&
        write_absolute_jump(base + k_fcntl_offset, bypass_fcntl);
    (void)sigaction(SIGBUS, &prior, NULL);
    installed = mmap_ready && fcntl_ready;
    return installed;
}

