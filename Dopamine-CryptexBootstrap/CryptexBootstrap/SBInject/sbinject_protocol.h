#ifndef CODEX_SBINJECT_PROTOCOL_H
#define CODEX_SBINJECT_PROTOCOL_H

#include <mach/mach.h>
#include <sys/types.h>
#include <xpc/xpc.h>

#define CODEX_SBINJECT_JITTERD_LABEL \
    "com.openai.codex.sbinject.jitterd"
#define CODEX_SBINJECT_JITTERD_SERVICE \
    "com.openai.codex.sbinject.jitterd.systemwide"
#define CODEX_SBINJECT_JITTERD_SHADOW_SOCKET \
    "/var/jb/var/run/sbinject-jitterd-shadow.sock"
#define CODEX_SBINJECT_JIT_MESSAGE_ID 67
#define CODEX_SBINJECT_JIT_DEFER_RESUME_MESSAGE_ID 68
#define CODEX_SBINJECT_SHADOW_SOCKET_MAGIC 0x53424a54U
#define CODEX_SBINJECT_SHADOW_SOCKET_VERSION 1U

struct codex_sbinject_shadow_request {
    uint32_t magic;
    uint32_t version;
    int32_t pid;
    uint32_t reserved;
};

struct codex_sbinject_shadow_response {
    uint32_t magic;
    uint32_t version;
    int32_t result;
    uint32_t flags;
};

#define CODEX_SBINJECT_STOCK_SPRINGBOARD \
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
#define CODEX_SBINJECT_SPRINGBOARD \
    "/var/jb/System/Library/CoreServices/SpringBoard.app/notSpringBoard"
#define CODEX_SBINJECT_STOCK_PREFERENCES \
    "/Applications/Preferences.app/Preferences"
#define CODEX_SBINJECT_PREFERENCES \
    "/var/jb/Applications/Preferences.app/notPreferences"
#define CODEX_SBINJECT_STOCK_AMFID "/usr/libexec/amfid"
#define CODEX_SBINJECT_XPCPROXY "/usr/libexec/xpcproxy"
#define CODEX_SBINJECT_AMFID "/var/jb/usr/libexec/sbinject/notamfid"
#define CODEX_SBINJECT_ROOT_BROKER \
    "/var/jb/usr/libexec/codex-sileo-root-broker"
#define CODEX_SBINJECT_ELLEKIT_LOADER \
    "/var/jb/usr/libexec/codex-ellekit-loader"
#define CODEX_SBINJECT_SHADOW_SIGNER \
    "/var/jb/usr/libexec/codex-ldid-ce"
#define CODEX_SBINJECT_SHADOW_ORIGINAL_ROOT \
    "/var/jb/var/lib/sbinject/shadow-originals"
#define CODEX_SBINJECT_APP_LAUNCHER \
    "/var/jb/usr/libexec/codex-exec-worker"
#define CODEX_SBINJECT_APP_LAUNCHER_NO_KEYCHAIN \
    "/var/jb/usr/libexec/codex-exec-worker-no-keychain"
#define CODEX_SBINJECT_APP_LAUNCHER_NATIVE_SDK \
    "/var/jb/usr/libexec/codex-exec-worker-native-sdk"
#define CODEX_SBINJECT_APP_LAUNCHER_NATIVE_SDK_NO_KEYCHAIN \
    "/var/jb/usr/libexec/codex-exec-worker-native-sdk-no-keychain"
#define CODEX_SBINJECT_MANAGED_APP_SETTINGS \
    "/var/jb/var/lib/sbinject/managed-app-settings.plist"
#define CODEX_SBINJECT_TROLLSTORE_SETTINGS_HOOK \
    "/var/jb/usr/lib/sbinject/trollstore-settings-hook.dylib"
#define CODEX_SBINJECT_TROLLSTORE_BROKER_CLIENT \
    "/var/jb/usr/libexec/codex-trollstore-broker-client"
#define CODEX_SBINJECT_TROLLSTORE_REGISTRATION_HOOK \
    "/var/jb/usr/lib/sbinject/trollstore-registration-hook.dylib"
#define CODEX_SBINJECT_APP_LAUNCHER_IDENTIFIER \
    "com.openai.codex.sbinject.app-launcher"
#define CODEX_SBINJECT_APP_PAYLOAD_NAME ".sbinject-payload"
#define CODEX_SBINJECT_TROLLSTORE_HELPER_PAYLOAD_NAME \
    ".sbinject-root-helper"
#define CODEX_SBINJECT_MANAGED_APP_MARKER \
    "_SBInjectManagedApp.plist"
#define CODEX_SBINJECT_AMFID_HOOK \
    "/var/jb/usr/libexec/sbinject/a"
#define CODEX_SBINJECT_GENERALHOOK \
    "/var/jb/usr/lib/sbinject/generalhook.dylib"
#define CODEX_SBINJECT_BUNDLE_HOOK \
    "/var/jb/System/Library/CoreServices/SpringBoard.app/g"
#define CODEX_SBINJECT_PREFERENCES_HOOK \
    "/var/jb/Applications/Preferences.app/g"
#define CODEX_SBINJECT_LAUNCHDHOOK \
    "/var/jb/usr/lib/sbinject/launchdhook-v42.dylib"
#define CODEX_SBINJECT_LAUNCHDHOOK_PREFIX \
    "/var/jb/usr/lib/sbinject/launchdhook-v"
#define CODEX_SBINJECT_LAUNCHDHOOK_GENERATION 42U
#define CODEX_SBINJECT_ELLEKIT \
    "/var/jb/usr/lib/ellekit/libinjector.dylib"
#define CODEX_SBINJECT_ELLEKIT_PSPAWN \
    "/var/jb/usr/lib/ellekit/pspawn.dylib"
#define CODEX_SBINJECT_SHADOW \
    "/var/jb/usr/lib/TweakInject/Shadow.dylib"
#define CODEX_SBINJECT_SHADOW_CORE "/var/jb/usr/lib/ShadowCore.dylib"
#define CODEX_SBINJECT_SHADOW_BOOTSTRAP \
    "/var/jb/usr/lib/sbinject/shadow-bootstrap.dylib"
#define CODEX_SBINJECT_SHADOW_APP_BOOTSTRAP_NAME \
    "_SBInjectShadowBootstrap.dylib"
#define CODEX_SBINJECT_COMPATIBILITY_APP_BOOTSTRAP_NAME \
    "_AppCompatibility.dylib"
#define CODEX_SBINJECT_PREFERENCELOADER \
    "/var/jb/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib"
#define CODEX_SBINJECT_PREFERENCELOADER_LEGACY \
    "/var/jb/usr/lib/TweakInject/PreferenceLoader.dylib"
#define CODEX_SBINJECT_PREFERENCES_BRIDGE \
    "/var/jb/usr/lib/sbinject/preferences-bridge.dylib"
#define CODEX_SBINJECT_LEGACY_TWEAK_COMPAT \
    "/var/jb/usr/lib/sbinject/legacy-tweak-compat.dylib"
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
#define CODEX_SBINJECT_AMFID_ENABLE_MARKER \
    "/var/jb/var/lib/sbinject/amfid-injection-enabled"
#define CODEX_SBINJECT_AMFID_CRASH_MARKER \
    "/var/jb/var/lib/sbinject/amfid-injection-disabled-crash-loop"
#define CODEX_SBINJECT_AMFID_READY_MARKER \
    "/var/jb/var/lib/sbinject/amfid-hook-ready"
#define CODEX_SBINJECT_AMFID_FAILURE_MARKER \
    "/var/jb/var/lib/sbinject/amfid-hook-failure"
#define CODEX_SBINJECT_AMFID_JIT_READY_MARKER \
    "/var/jb/var/lib/sbinject/amfid-jit-ready"
#define CODEX_SBINJECT_LAUNCHD_READY_MARKER \
    "/var/jb/var/lib/sbinject/launchd-hook-ready"
#define CODEX_SBINJECT_LOG "/var/jb/var/log/sbinject.log"
#define CODEX_SBINJECT_AMFID_LOG \
    "/var/jb/var/lib/sbinject/amfid-hook.log"
#define CODEX_SBINJECT_AMFID_PROFILE \
    "/var/jb/var/lib/sbinject/amfid-profile.der"

extern xpc_object_t xpc_pipe_create_from_port(mach_port_t port,
                                               uint32_t flags);
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message,
                            xpc_object_t *reply);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, xpc_object_t *message);
extern void xpc_dictionary_get_audit_token(xpc_object_t dictionary,
                                            audit_token_t *token);

#endif
