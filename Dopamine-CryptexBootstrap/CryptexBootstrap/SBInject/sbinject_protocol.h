#ifndef CODEX_SBINJECT_PROTOCOL_H
#define CODEX_SBINJECT_PROTOCOL_H

#include <mach/mach.h>
#include <sys/types.h>
#include <xpc/xpc.h>

#define CODEX_SBINJECT_JITTERD_LABEL \
    "com.openai.codex.sbinject.jitterd"
#define CODEX_SBINJECT_JITTERD_SERVICE \
    "com.openai.codex.sbinject.jitterd.systemwide"
#define CODEX_SBINJECT_JIT_MESSAGE_ID 67

#define CODEX_SBINJECT_STOCK_SPRINGBOARD \
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
#define CODEX_SBINJECT_SPRINGBOARD \
    "/var/jb/System/Library/CoreServices/SpringBoard.app/notSpringBoard"
#define CODEX_SBINJECT_STOCK_PREFERENCES \
    "/Applications/Preferences.app/Preferences"
#define CODEX_SBINJECT_PREFERENCES \
    "/var/jb/Applications/Preferences.app/notPreferences"
#define CODEX_SBINJECT_GENERALHOOK \
    "/var/jb/usr/lib/sbinject/generalhook.dylib"
#define CODEX_SBINJECT_BUNDLE_HOOK \
    "/var/jb/System/Library/CoreServices/SpringBoard.app/g"
#define CODEX_SBINJECT_PREFERENCES_HOOK \
    "/var/jb/Applications/Preferences.app/g"
#define CODEX_SBINJECT_LAUNCHDHOOK \
    "/var/jb/usr/lib/sbinject/launchdhook-v3.dylib"
#define CODEX_SBINJECT_PREVIOUS_LAUNCHDHOOK \
    "/var/jb/usr/lib/sbinject/launchdhook-v2.dylib"
#define CODEX_SBINJECT_ELLEKIT \
    "/var/jb/usr/lib/ellekit/libinjector.dylib"
#define CODEX_SBINJECT_PREFERENCELOADER \
    "/var/jb/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib"
#define CODEX_SBINJECT_PREFERENCELOADER_LEGACY \
    "/var/jb/usr/lib/TweakInject/PreferenceLoader.dylib"
#define CODEX_SBINJECT_PREFERENCES_BRIDGE \
    "/var/jb/usr/lib/sbinject/preferences-bridge.dylib"
#define CODEX_SBINJECT_ENABLE_MARKER \
    "/var/jb/var/lib/sbinject/enabled"
#define CODEX_SBINJECT_CRASH_MARKER \
    "/var/jb/var/lib/sbinject/disabled-crash-loop"
#define CODEX_SBINJECT_SAFE_MODE_MARKER "/var/mobile/.sbinject-safe-mode"
#define CODEX_SBINJECT_ELLEKIT_SAFE_MODE_MARKER "/var/mobile/.eksafemode"
#define CODEX_SBINJECT_PREFERENCES_ENABLE_MARKER \
    "/var/jb/var/lib/sbinject/preferences-enabled"
#define CODEX_SBINJECT_PREFERENCES_CRASH_MARKER \
    "/var/jb/var/lib/sbinject/preferences-disabled-crash-loop"
#define CODEX_SBINJECT_LAUNCHD_READY_MARKER \
    "/var/jb/var/lib/sbinject/launchd-hook-ready"
#define CODEX_SBINJECT_LOG "/var/jb/var/log/sbinject.log"

extern xpc_object_t xpc_pipe_create_from_port(mach_port_t port,
                                               uint32_t flags);
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message,
                            xpc_object_t *reply);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, xpc_object_t *message);
extern void xpc_dictionary_get_audit_token(xpc_object_t dictionary,
                                            audit_token_t *token);

#endif
