#ifndef CODEX_SBINJECT_LITEHOOK_REBIND_H
#define CODEX_SBINJECT_LITEHOOK_REBIND_H

#include <mach/kern_return.h>
#include <mach-o/loader.h>
#include <stddef.h>

typedef struct {
    size_t matches;
    size_t writes;
    size_t tpro_writes;
    size_t protect_failures;
    kern_return_t first_error;
} litehook_rebind_result_t;

litehook_rebind_result_t litehook_rebind_symbol(
    const struct mach_header_64 *target_header, void *replacee,
    void *replacement);

#endif

