// Runtime-discovered port of the supplied SBInject dyld bypass.
#include "sbinject_dyld_bypass.h"

#include <errno.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <os/log.h>
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
static const uintptr_t k_user_pointer_mask = 0x0000FFFFFFFFFFFFULL;

extern void *__mmap(void *address, size_t length, int protection, int flags,
                    int descriptor, off_t offset);
extern int __fcntl(int descriptor, int command, void *argument);

static os_log_t bypass_log(void) {
    static os_log_t log;
    if (log == NULL) {
        log = os_log_create("com.openai.codex.sbinject", "dyld-bypass");
    }
    return log;
}

__attribute__((naked)) static kern_return_t raw_vm_protect(
    mach_port_name_t task, mach_vm_address_t address, mach_vm_size_t size,
    boolean_t maximum, vm_prot_t protection) {
    __asm("mov x16, #-14");
    __asm("svc 0x80");
    __asm("ret");
}

// Direct Unix syscall wrappers avoid recursing through the libsystem entry
// points when those entry points themselves are the fallback patch targets.
// XNU reports Unix errors in x0 with carry set; mirror libsystem's errno/-1
// contract so the surrounding mmap/fcntl logic remains conventional C.
__attribute__((naked)) static void *raw_mmap(
    void *address, size_t length, int protection, int flags, int descriptor,
    off_t offset) {
    __asm("mov x16, #197");
    __asm("svc 0x80");
    __asm("b.cc 1f");
    __asm("stp x29, x30, [sp, #-32]!");
    __asm("mov x29, sp");
    __asm("str x0, [sp, #16]");
    __asm("bl ___error");
    __asm("ldr w9, [sp, #16]");
    __asm("str w9, [x0]");
    __asm("mov x0, #-1");
    __asm("ldp x29, x30, [sp], #32");
    __asm("1: ret");
}

__attribute__((naked)) static int raw_fcntl(int descriptor, int command,
                                            void *argument) {
    __asm("mov x16, #92");
    __asm("svc 0x80");
    __asm("b.cc 1f");
    __asm("stp x29, x30, [sp, #-32]!");
    __asm("mov x29, sp");
    __asm("str x0, [sp, #16]");
    __asm("bl ___error");
    __asm("ldr w9, [sp, #16]");
    __asm("str w9, [x0]");
    __asm("mov x0, #-1");
    __asm("ldp x29, x30, [sp], #32");
    __asm("1: ret");
}

static void copy_bytes(uint8_t *destination, const uint8_t *source,
                       size_t amount) {
    for (size_t index = 0; index < amount; ++index) {
        destination[index] = source[index];
    }
}

static bool write_absolute_jump(void *location, void *replacement,
                                const char *name) {
    static const uint8_t jump_template[24] = {
        0x88, 0x00, 0x00, 0x58, 0x00, 0x01, 0x1f, 0xd6,
        0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    kern_return_t result = raw_vm_protect(
        mach_task_self(), (mach_vm_address_t)location, sizeof(jump_template),
        false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (result != KERN_SUCCESS) {
        os_log_error(bypass_log(),
                     "%{public}s writable transition failed kr=%{public}d",
                     name, result);
        return false;
    }
    copy_bytes(location, jump_template, sizeof(jump_template));
    uintptr_t target = (uintptr_t)ptrauth_strip(
        replacement, ptrauth_key_function_pointer);
    target &= k_user_pointer_mask;
    copy_bytes((uint8_t *)location + 16U, (const uint8_t *)&target,
               sizeof(target));
    sys_icache_invalidate(location, sizeof(jump_template));
    result = raw_vm_protect(mach_task_self(), (mach_vm_address_t)location,
                            sizeof(jump_template), false,
                            VM_PROT_READ | VM_PROT_EXECUTE);
    if (result != KERN_SUCCESS) {
        os_log_error(bypass_log(),
                     "%{public}s executable transition failed kr=%{public}d",
                     name, result);
        return false;
    }
    return true;
}

static const struct mach_header_64 *dyld_header(void) {
    task_dyld_info_data_t information = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO,
                  (task_info_t)&information, &count) != KERN_SUCCESS ||
        information.all_image_info_addr == 0) {
        return NULL;
    }
    const struct dyld_all_image_infos *images =
        (const struct dyld_all_image_infos *)information.all_image_info_addr;
    return (const struct mach_header_64 *)(
        (uintptr_t)images->dyldImageLoadAddress & k_user_pointer_mask);
}

static bool find_unique_signature(const struct mach_header_64 *header,
                                  const uint8_t *signature,
                                  size_t signature_size,
                                  uint8_t **match_out,
                                  size_t *match_count_out) {
    if (header == NULL || header->magic != MH_MAGIC_64 ||
        header->ncmds == 0 || header->ncmds > 1024U ||
        header->sizeofcmds > 16U * 1024U * 1024U || match_out == NULL ||
        match_count_out == NULL) {
        return false;
    }
    const uint8_t *commands = (const uint8_t *)(header + 1);
    const uint8_t *commands_end = commands + header->sizeofcmds;
    const uint8_t *cursor = commands;
    uint64_t text_vmaddr = 0;
    bool found_text = false;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(commands_end - cursor) < sizeof(struct load_command)) {
            return false;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(commands_end - cursor)) {
            return false;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)cursor;
            if (segment->fileoff == 0 &&
                strncmp(segment->segname, SEG_TEXT, sizeof(segment->segname)) ==
                    0) {
                text_vmaddr = segment->vmaddr;
                found_text = true;
                break;
            }
        }
        cursor += command->cmdsize;
    }
    if (!found_text || (uintptr_t)header < text_vmaddr) return false;
    uintptr_t slide = (uintptr_t)header - (uintptr_t)text_vmaddr;

    size_t matches = 0;
    uint8_t *observed = NULL;
    cursor = commands;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)cursor;
            if ((segment->initprot & VM_PROT_EXECUTE) != 0 &&
                segment->filesize <= 64U * 1024U * 1024U) {
                uint8_t *start = (uint8_t *)(slide + segment->vmaddr);
                size_t size = (size_t)segment->filesize;
                for (size_t offset = 0;
                     offset + signature_size <= size; offset += 4U) {
                    if (start[offset] == signature[0] &&
                        memcmp(start + offset, signature, signature_size) == 0) {
                        ++matches;
                        observed = start + offset;
                    }
                }
            }
        }
        cursor += command->cmdsize;
    }
    *match_out = observed;
    *match_count_out = matches;
    return matches == 1U;
}

static void *bypass_mmap(void *address, size_t length, int protection,
                         int flags, int descriptor, off_t offset) {
    if ((flags & MAP_JIT) != 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    void *mapping = raw_mmap(address, length, protection, flags, descriptor,
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

    void *source = raw_mmap(NULL, length, PROT_READ, MAP_PRIVATE, descriptor,
                            offset);
    if (source == MAP_FAILED) {
        return MAP_FAILED;
    }
    int anonymous_flags = (flags & ~MAP_SHARED) | MAP_PRIVATE | MAP_ANON;
    mapping = raw_mmap(address, length, PROT_READ | PROT_WRITE,
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
        (void)raw_fcntl(descriptor, command, argument);
        if (argument != NULL) {
            fsignatures_t *signatures = argument;
            signatures->fs_file_start = 0xffffffffU;
        }
        return 0;
    }
    if (command == F_CHECK_LV) {
        return 0;
    }
    return raw_fcntl(descriptor, command, argument);
}

bool sbinject_install_dyld_validation_bypass(void) {
    static bool attempted;
    static bool installed;
    if (attempted) {
        return installed;
    }
    attempted = true;
    const struct mach_header_64 *header = dyld_header();
    uint8_t *mmap_site = NULL;
    uint8_t *fcntl_site = NULL;
    size_t mmap_matches = 0;
    size_t fcntl_matches = 0;
    bool dyld_mmap = find_unique_signature(
        header, k_mmap_signature, sizeof(k_mmap_signature), &mmap_site,
        &mmap_matches);
    bool dyld_fcntl = find_unique_signature(
        header, k_fcntl_signature, sizeof(k_fcntl_signature), &fcntl_site,
        &fcntl_matches);
    // Some iOS 27 process configurations route dyld's late validation calls
    // through the exported libsystem stubs and therefore contain no private
    // syscall sequence in dyld itself. Patch those exact stubs as the runtime
    // fallback; the replacements use syscall(2), so they never recurse into
    // the overwritten entry points.
    if (!dyld_mmap) {
        mmap_site = (uint8_t *)ptrauth_strip(
            (void *)(uintptr_t)&__mmap, ptrauth_key_function_pointer);
    }
    if (!dyld_fcntl) {
        fcntl_site = (uint8_t *)ptrauth_strip(
            (void *)(uintptr_t)&__fcntl, ptrauth_key_function_pointer);
    }
    if (mmap_site == NULL || fcntl_site == NULL) {
        os_log_error(bypass_log(),
                     "target discovery failed header=%{public}s "
                     "mmapMatches=%{public}lu fcntlMatches=%{public}lu",
                     header != NULL ? "valid" : "missing",
                     (unsigned long)mmap_matches,
                     (unsigned long)fcntl_matches);
        return false;
    }
    struct sigaction ignored = {0};
    struct sigaction prior = {0};
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    (void)sigaction(SIGBUS, &ignored, &prior);
    bool mmap_ready = write_absolute_jump(mmap_site, bypass_mmap, "mmap");
    bool fcntl_ready =
        mmap_ready &&
        write_absolute_jump(fcntl_site, bypass_fcntl, "fcntl");
    (void)sigaction(SIGBUS, &prior, NULL);
    installed = mmap_ready && fcntl_ready;
    os_log_with_type(bypass_log(),
                     installed ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_ERROR,
                     "installation %{public}s mmapMatches=%{public}lu "
                     "fcntlMatches=%{public}lu mmapTarget=%{public}s "
                     "fcntlTarget=%{public}s",
                     installed ? "succeeded" : "failed",
                     (unsigned long)mmap_matches,
                     (unsigned long)fcntl_matches,
                     dyld_mmap ? "dyld" : "libsystem",
                     dyld_fcntl ? "dyld" : "libsystem");
    return installed;
}
