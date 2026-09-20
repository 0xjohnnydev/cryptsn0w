// Derived from the supplied SBInject launchdhook and opa334/litehook.
#include "litehook_rebind.h"

#include <dlfcn.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/vm_prot.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define COMM_PAGE_START_ADDRESS (0x0000000FFFFFC000ULL)
#define COMM_PAGE_TPRO_WRITE_ENABLE (COMM_PAGE_START_ADDRESS + 0x0D0)
#define COMM_PAGE_TPRO_WRITE_DISABLE (COMM_PAGE_START_ADDRESS + 0x0D8)

__attribute__((noinline, naked))
static kern_return_t litehook_vm_protect(mach_port_name_t target,
                                         mach_vm_address_t address,
                                         mach_vm_size_t size,
                                         boolean_t set_maximum,
                                         vm_prot_t new_protection) {
    __asm("mov x16, #-14");
    __asm("svc 0x80");
    __asm("ret");
}

static bool tpro_is_supported(void) {
    return *(volatile uint64_t *)COMM_PAGE_TPRO_WRITE_ENABLE != 0;
}

__attribute__((naked)) static bool tpro_is_writable(void) {
    __asm__ __volatile__(
        "mrs x0, s3_6_c15_c1_5\n"
        "ubfx x0, x0, #0x24, #1\n"
        "ret\n");
}

static void tpro_set_writable(void) {
    __asm__ __volatile__(
        "mov x0, %0\n"
        "ldr x0, [x0]\n"
        "msr s3_6_c15_c1_5, x0\n"
        "isb sy\n"
        :: "r"(COMM_PAGE_TPRO_WRITE_ENABLE)
        : "memory", "x0");
}

static void tpro_set_readonly(void) {
    __asm__ __volatile__(
        "mov x0, %0\n"
        "ldr x0, [x0]\n"
        "msr s3_6_c15_c1_5, x0\n"
        "isb sy\n"
        :: "r"(COMM_PAGE_TPRO_WRITE_DISABLE)
        : "memory", "x0");
}

static kern_return_t protect_slot(void *slot, vm_prot_t protection) {
    mach_vm_size_t page_size = vm_page_size;
    mach_vm_address_t address = (mach_vm_address_t)slot;
    mach_vm_address_t page = address & ~(page_size - 1U);
    return litehook_vm_protect(mach_task_self(), page, page_size, false,
                               protection);
}

static void remember_error(litehook_rebind_result_t *result,
                           kern_return_t error) {
    if (error != KERN_SUCCESS && result->first_error == KERN_SUCCESS) {
        result->first_error = error;
    }
}

static bool pointer_belongs_to_image(void *pointer,
                                     const char *expected_image) {
    if (pointer == NULL || expected_image == NULL) {
        return false;
    }
    Dl_info information = {0};
    if (dladdr(pointer, &information) == 0 || information.dli_fname == NULL) {
        return false;
    }
    if (strcmp(information.dli_fname, expected_image) == 0) {
        return true;
    }
    char observed[PATH_MAX] = {0};
    char expected[PATH_MAX] = {0};
    return realpath(information.dli_fname, observed) != NULL &&
           realpath(expected_image, expected) != NULL &&
           strcmp(observed, expected) == 0;
}

static void rebind_section(const struct mach_header_64 *target_header,
                           const struct section_64 *section, void *replacee,
                           void *replacement, const char *previous_image,
                           litehook_rebind_result_t *result) {
    char segment_name[sizeof(section->segname) + 1] = {0};
    char section_name[sizeof(section->sectname) + 1] = {0};
    memcpy(segment_name, section->segname, sizeof(section->segname));
    memcpy(section_name, section->sectname, sizeof(section->sectname));

    unsigned long section_size = 0;
    uint8_t *section_start = getsectiondata(target_header, segment_name,
                                            section_name, &section_size);
    if (section_start == NULL || section_size < sizeof(void *)) {
        return;
    }

    bool authenticated = strcmp(section_name, "__auth_got") == 0;
    bool tpro_section = strcmp(segment_name, "__AUTH_CONST") == 0 ||
                        strcmp(segment_name, "__DATA_CONST") == 0;
    void **slots = (void **)section_start;
    void *unsigned_replacee = ptrauth_strip(
        ptrauth_auth_function(replacee, ptrauth_key_function_pointer, 0),
        ptrauth_key_function_pointer);

    for (size_t index = 0; index < section_size / sizeof(void *); ++index) {
        void *current = slots[index];
        if (current == NULL) {
            continue;
        }
        if (authenticated) {
            current = ptrauth_strip(
                ptrauth_auth_function(current,
                                      ptrauth_key_process_independent_code,
                                      &slots[index]),
                ptrauth_key_function_pointer);
        } else {
            current = ptrauth_strip(current, ptrauth_key_function_pointer);
        }
        if (current != unsigned_replacee &&
            !pointer_belongs_to_image(current, previous_image)) {
            continue;
        }

        ++result->matches;
        bool tpro_available = tpro_section && tpro_is_supported();
        bool restore_tpro = false;
        if (tpro_available && !tpro_is_writable()) {
            tpro_set_writable();
            restore_tpro = true;
        }

        kern_return_t error = protect_slot(
            &slots[index], VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (error != KERN_SUCCESS) {
            ++result->protect_failures;
        }
        if (error == KERN_SUCCESS || tpro_available) {
            if (authenticated) {
                slots[index] = ptrauth_auth_and_resign(
                    replacement, ptrauth_key_function_pointer, 0,
                    ptrauth_key_process_independent_code, &slots[index]);
            } else {
                slots[index] =
                    ptrauth_strip(replacement, ptrauth_key_function_pointer);
            }
            ++result->writes;
            if (error == KERN_SUCCESS) {
                remember_error(result,
                               protect_slot(&slots[index], VM_PROT_READ));
            } else {
                ++result->tpro_writes;
            }
        } else {
            remember_error(result, error);
        }
        if (restore_tpro) {
            tpro_set_readonly();
        }
    }
}

litehook_rebind_result_t litehook_rebind_symbol_with_previous_image(
    const struct mach_header_64 *target_header, void *replacee,
    void *replacement, const char *previous_image) {
    litehook_rebind_result_t result = {0, 0, 0, 0, KERN_SUCCESS};
    if (target_header == NULL || replacee == NULL || replacement == NULL ||
        target_header->magic != MH_MAGIC_64) {
        result.first_error = KERN_INVALID_ARGUMENT;
        return result;
    }

    const struct load_command *command =
        (const struct load_command *)((const uint8_t *)target_header +
                                      sizeof(*target_header));
    for (uint32_t index = 0; index < target_header->ncmds; ++index) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__AUTH_CONST",
                        sizeof(segment->segname)) == 0 ||
                strncmp(segment->segname, "__DATA_CONST",
                        sizeof(segment->segname)) == 0 ||
                strncmp(segment->segname, "__DATA",
                        sizeof(segment->segname)) == 0) {
                const struct section_64 *section =
                    (const struct section_64 *)(segment + 1);
                for (uint32_t section_index = 0;
                     section_index < segment->nsects; ++section_index) {
                    uint32_t type =
                        section[section_index].flags & SECTION_TYPE;
                    if (type == S_LAZY_SYMBOL_POINTERS ||
                        type == S_NON_LAZY_SYMBOL_POINTERS) {
                        rebind_section(target_header, &section[section_index],
                                       replacee, replacement, previous_image,
                                       &result);
                    }
                }
            }
        }
        command = (const struct load_command *)((const uint8_t *)command +
                                                 command->cmdsize);
    }
    return result;
}

litehook_rebind_result_t litehook_rebind_symbol(
    const struct mach_header_64 *target_header, void *replacee,
    void *replacement) {
    return litehook_rebind_symbol_with_previous_image(
        target_header, replacee, replacement, NULL);
}
