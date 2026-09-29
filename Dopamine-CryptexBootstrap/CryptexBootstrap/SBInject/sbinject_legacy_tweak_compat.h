#ifndef CODEX_SBINJECT_LEGACY_TWEAK_COMPAT_H
#define CODEX_SBINJECT_LEGACY_TWEAK_COMPAT_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool codex_legacy_tweak_compat_register_class_alias(
    const char *legacy_name, const char *current_name);
bool codex_legacy_tweak_compat_register_selector_alias(
    const char *class_name, const char *legacy_selector,
    const char *current_selector, bool class_method);
bool codex_legacy_tweak_compat_apply(void);

#ifdef __cplusplus
}
#endif

#endif
