#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <os/log.h>

#include "sbinject_legacy_tweak_compat.h"
#include "litehook_rebind.h"
#include "../sileo_root_broker_protocol.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdint.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xpc/xpc.h>

#define CODEX_LEGACY_COMPAT_CONFIG \
    "/var/jb/etc/sbinject/legacy-tweak-compat.plist"
#define CODEX_LEGACY_COMPAT_DISABLE_MARKER \
    "/var/mobile/.sbinject-legacy-compat-disabled"

@interface NSObject (SBInjectLegacyPreferences)
- (id)specifier;
- (id)specifierAtIndexPath:(id)indexPath;
- (id)propertyForKey:(id)key;
@end

typedef void (*WindowHiddenImplementation)(UIWindow *, SEL, BOOL);
typedef void (*WindowVisibleImplementation)(UIWindow *, SEL);
typedef void (*WindowOwnerFrameImplementation)(id, SEL);
typedef void (*MonitorUpdateImplementation)(id, SEL);
typedef id (*BatteryDictionaryImplementation)(id, SEL);
typedef CGFloat (*RowHeightImplementation)(id, SEL, UITableView *, NSIndexPath *);
typedef void (*CellLayoutImplementation)(UITableViewCell *, SEL);
typedef id (*ObjectGetterImplementation)(id, SEL);
typedef void (*ApplicationShortcutActivationImplementation)(
    id, SEL, id, id, id);
typedef char ***(*ArgumentsStorageImplementation)(void);
typedef void (*SetProgramNameImplementation)(const char *);
typedef BOOL (*ResolveInstanceMethodImplementation)(id, SEL, SEL);

static WindowHiddenImplementation OriginalWindowSetHidden;
static WindowVisibleImplementation OriginalWindowMakeKeyAndVisible;
static NSMutableDictionary<NSString *, NSValue *> *HeightImplementations;
static NSMutableDictionary<NSString *, NSValue *> *LayoutImplementations;
static NSHashTable<UIWindow *> *OrphanWindows;
static NSMutableArray<Class> *LegacyWindowOwnerClasses;
static NSMutableSet<NSString *> *LegacyWindowOwnerNames;
static NSMutableSet<NSString *> *NoninteractiveWindowOwnerNames;
static NSMutableDictionary<NSString *, NSValue *> *WindowOwnerFrameImplementations;
static MonitorUpdateImplementation OriginalBatteryMonitorUpdate;
static MonitorUpdateImplementation OriginalCPUMonitorUpdate;
static MonitorUpdateImplementation OriginalRAMMonitorUpdate;
static MonitorUpdateImplementation OriginalNetworkMonitorUpdate;
static BatteryDictionaryImplementation OriginalBatteryDictionary;
static io_service_t BatteryPackService;
static BOOL KeepEyeDisplayCompatibilityInstalled;
static char SubtitleLabelKey;
static ObjectGetterImplementation OriginalApplicationShortcutItems;
static ApplicationShortcutActivationImplementation
    OriginalApplicationShortcutActivation;
static ResolveInstanceMethodImplementation OriginalResolveInstanceMethod;
static char *ManagedArgumentZero;

static id CompatFlashlightButton(id view, SEL selector);
static id CompatCameraButton(id view, SEL selector);
static float CompatCurrentVolume(id viewController, SEL selector);
static void InstallSpringBoardQuickActionsHooks(void);
static void LayoutLegacyStatusOverlayWindows(UIWindowScene *scene);
static void ScheduleLegacyStatusOverlayLayout(void);
static void ScheduleLegacyPreferenceRefresh(void);

static _Atomic bool QuickActionsInstallScheduled;
static _Atomic bool LegacyWindowRegistrationScheduled;
static _Atomic bool LegacyWindowRepairScheduled;
static _Atomic bool LegacyStatusLayoutScheduled;
static _Atomic bool LegacyPreferenceRefreshScheduled;

#define CODEX_MAX_PATH_MAPPINGS 32U

struct CodexPathMapping {
    char legacy[PATH_MAX];
    char current[PATH_MAX];
};

static struct CodexPathMapping ConfiguredPathMappings[
    CODEX_MAX_PATH_MAPPINGS];
static size_t ConfiguredPathMappingCount;
static pthread_mutex_t PathMappingLock = PTHREAD_MUTEX_INITIALIZER;

#define CODEX_FAKE_RESPRING_PID_FIRST ((pid_t)0x3e000000)
#define CODEX_COMPLETED_RESPRING_COUNT 32U

static pthread_mutex_t RespringJobLock = PTHREAD_MUTEX_INITIALIZER;
static pid_t CompletedRespringJobs[CODEX_COMPLETED_RESPRING_COUNT];
static size_t NextCompletedRespringJob;
static uint32_t NextRespringJobIdentifier;
typedef int (*SystemImplementation)(const char *command);
static SystemImplementation OriginalSystem;

static bool RetryPathFailure(int error);

static os_log_t CompatLog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.openai.codex.sbinject", "legacy-compat");
    });
    return log;
}

static BOOL RunningOnIOS27(void) {
    return NSProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27;
}

static BOOL ValidRuntimeName(const char *name) {
    if (name == NULL) return NO;
    size_t length = strnlen(name, 128);
    if (length == 0 || length >= 128) return NO;
    for (size_t index = 0; index < length; ++index) {
        unsigned char character = (unsigned char)name[index];
        if (!isalnum(character) && character != '_' && character != '$' &&
            character != '.') {
            return NO;
        }
    }
    return YES;
}

static bool PathHasPrefix(const char *path, const char *prefix) {
    if (path == NULL || prefix == NULL) return false;
    size_t length = strlen(prefix);
    return strncmp(path, prefix, length) == 0;
}

static bool PathHasUnsafeComponent(const char *path) {
    if (path == NULL) return true;
    return strstr(path, "/../") != NULL || strstr(path, "/./") != NULL ||
           strcmp(path, "/..") == 0 || strcmp(path, "/.") == 0 ||
           (strlen(path) >= 3U &&
            strcmp(path + strlen(path) - 3U, "/..") == 0) ||
           (strlen(path) >= 2U &&
            strcmp(path + strlen(path) - 2U, "/.") == 0);
}

static bool IsSystemPreferencePath(const char *path) {
    static const char preferenceRoot[] =
        "/var/mobile/Library/Preferences/";
    if (!PathHasPrefix(path, preferenceRoot)) return false;
    const char *name = strrchr(path, '/');
    name = name != NULL ? name + 1 : path;
    static const char *const prefixes[] = {
        "com.apple.", "group.com.apple.", "systemgroup.com.apple.",
    };
    for (size_t index = 0;
         index < sizeof(prefixes) / sizeof(prefixes[0]); ++index) {
        if (PathHasPrefix(name, prefixes[index])) return true;
    }
    static const char *const exactNames[] = {
        ".GlobalPreferences.plist", ".GlobalPreferences_m.plist",
        "NetworkInterfaces.plist", "preferences.plist",
        "mobile_storage_proxy.plist", "splashboardd.plist",
    };
    for (size_t index = 0;
         index < sizeof(exactNames) / sizeof(exactNames[0]); ++index) {
        if (strcmp(name, exactNames[index]) == 0) return true;
    }
    return false;
}

static bool BuiltInLegacyPath(const char *path) {
    static const char *const roots[] = {
        "/Library/", "/usr/local/", "/usr/lib/", "/usr/libexec/",
        "/usr/bin/", "/usr/sbin/", "/usr/share/", "/bin/", "/sbin/",
        "/etc/", "/opt/", "/Applications/", "/var/lib/", "/var/log/",
        "/var/cache/", "/var/mobile/Library/Preferences/",
        "/var/mobile/Library/Application Support/",
        "/var/mobile/Library/Logs/",
    };
    if (path == NULL || path[0] != '/' ||
        PathHasPrefix(path, "/var/jb/") || PathHasUnsafeComponent(path) ||
        IsSystemPreferencePath(path)) {
        return false;
    }
    for (size_t index = 0; index < sizeof(roots) / sizeof(roots[0]); ++index) {
        if (PathHasPrefix(path, roots[index])) return true;
    }
    return false;
}

static bool CopyJoinedPath(const char *prefix, const char *suffix,
                           char *output, size_t outputSize) {
    if (prefix == NULL || suffix == NULL || output == NULL ||
        outputSize == 0) {
        return false;
    }
    int length = snprintf(output, outputSize, "%s%s", prefix, suffix);
    return length > 0 && (size_t)length < outputSize;
}

static bool ConfiguredPathTranslation(const char *path, char *output,
                                      size_t outputSize, bool *preferred) {
    bool translated = false;
    size_t bestLength = 0;
    pthread_mutex_lock(&PathMappingLock);
    for (size_t index = 0; index < ConfiguredPathMappingCount; ++index) {
        const struct CodexPathMapping *mapping =
            &ConfiguredPathMappings[index];
        size_t length = strlen(mapping->legacy);
        if (length <= bestLength || strncmp(path, mapping->legacy, length) != 0) {
            continue;
        }
        char boundary = path[length];
        if (boundary != '\0' && boundary != '/' &&
            mapping->legacy[length - 1U] != '/') {
            continue;
        }
        if (CopyJoinedPath(mapping->current, path + length, output,
                           outputSize)) {
            translated = true;
            bestLength = length;
        }
    }
    pthread_mutex_unlock(&PathMappingLock);
    if (translated && preferred != NULL) *preferred = true;
    return translated;
}

static bool TranslateLegacyPath(const char *path, char *output,
                                size_t outputSize, bool *preferred) {
    if (preferred != NULL) *preferred = false;
    if (path == NULL || output == NULL || outputSize == 0 ||
        strnlen(path, PATH_MAX) >= PATH_MAX || PathHasUnsafeComponent(path)) {
        return false;
    }
    if (ConfiguredPathTranslation(path, output, outputSize, preferred)) {
        return true;
    }
    if (!BuiltInLegacyPath(path)) return false;
    if (preferred != NULL &&
        PathHasPrefix(path, "/var/mobile/Library/Preferences/")) {
        *preferred = true;
    }
    return CopyJoinedPath("/var/jb", path, output, outputSize);
}

bool codex_legacy_tweak_compat_translate_path(
    const char *legacyPath, char *translatedPath,
    size_t translatedPathSize) {
    return TranslateLegacyPath(legacyPath, translatedPath,
                               translatedPathSize, NULL);
}

static BOOL IsPreferencesProcess(void) {
    return [NSBundle.mainBundle.bundleIdentifier
        isEqualToString:@"com.apple.Preferences"];
}

static BOOL IsSpringBoardProcess(void) {
    return [NSBundle.mainBundle.bundleIdentifier
        isEqualToString:@"com.apple.springboard"];
}

static const char *CommandLeaf(const char *path) {
    if (path == NULL || path[0] == '\0') return NULL;
    const char *separator = strrchr(path, '/');
    return separator != NULL ? separator + 1 : path;
}

static void RepairManagedProcessIdentity(void) {
    ArgumentsStorageImplementation argumentsStorage =
        (ArgumentsStorageImplementation)dlsym(RTLD_DEFAULT, "_NSGetArgv");
    char ***storage = argumentsStorage != NULL ? argumentsStorage() : NULL;
    if (storage == NULL || *storage == NULL || (*storage)[0] == NULL) return;

    NSString *identifier = NSBundle.mainBundle.bundleIdentifier;
    const char *currentLeaf = CommandLeaf((*storage)[0]);
    const char *canonicalPath = NULL;
    if ([identifier isEqualToString:@"com.apple.springboard"] &&
        currentLeaf != NULL && strcmp(currentLeaf, "notSpringBoard") == 0) {
        canonicalPath =
            "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
    } else if ([identifier isEqualToString:@"com.apple.Preferences"] &&
               currentLeaf != NULL &&
               strcmp(currentLeaf, "notPreferences") == 0) {
        canonicalPath = "/Applications/Preferences.app/Preferences";
    }
    if (canonicalPath == NULL) return;

    ManagedArgumentZero = strdup(canonicalPath);
    if (ManagedArgumentZero == NULL) return;
    (*storage)[0] = ManagedArgumentZero;

    SetProgramNameImplementation setProgramName =
        (SetProgramNameImplementation)dlsym(RTLD_DEFAULT, "setprogname");
    if (setProgramName != NULL) {
        setProgramName(CommandLeaf(canonicalPath));
    }
    os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                     "restored managed process identity name=%{public}s",
                     CommandLeaf(canonicalPath));
}

static BOOL ArgumentsRequestRespring(const char *path,
                                     char *const arguments[]) {
    const char *leaf = CommandLeaf(path);
    if (leaf == NULL && arguments != NULL) {
        leaf = CommandLeaf(arguments[0]);
    }
    if (leaf == NULL) return NO;
    if (strcmp(leaf, "sbreload") == 0) return YES;
    if (strcmp(leaf, "killall") != 0 || arguments == NULL) return NO;

    BOOL sawSpringBoard = NO;
    size_t index = 1;
    for (; index < 16U && arguments[index] != NULL; ++index) {
        const char *argument = arguments[index];
        if (argument[0] == '-' && argument[1] != '\0') continue;
        const char *target = CommandLeaf(argument);
        BOOL springBoard = target != NULL &&
            (strcmp(target, "SpringBoard") == 0 ||
             strcmp(target, "notSpringBoard") == 0);
        if (!springBoard || sawSpringBoard) return NO;
        sawSpringBoard = YES;
    }
    return index < 16U && sawSpringBoard;
}

static BOOL RequestPreferencesRespring(void) {
    typedef xpc_connection_t (*CreateMachServiceImplementation)(
        const char *, dispatch_queue_t, uint64_t);
    CreateMachServiceImplementation createMachService =
        (CreateMachServiceImplementation)dlsym(
            RTLD_DEFAULT, "xpc_connection_create_mach_service");
    xpc_connection_t connection = createMachService != NULL
        ? createMachService(CODEX_ROOT_BROKER_MACH_SERVICE, NULL, 0) : NULL;
    if (connection == NULL) {
        errno = ECONNREFUSED;
        return NO;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_resume(connection);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(
        message, CODEX_ROOT_BROKER_OPERATION_KEY,
        CODEX_ROOT_BROKER_PREFERENCES_RESPRING_OPERATION);
    xpc_object_t reply =
        xpc_connection_send_message_with_reply_sync(connection, message);
    BOOL accepted = reply != NULL &&
        xpc_get_type(reply) == XPC_TYPE_DICTIONARY &&
        xpc_dictionary_get_bool(reply, "accepted") &&
        xpc_dictionary_get_bool(reply, "valid") &&
        xpc_dictionary_get_bool(reply, "allowed") &&
        xpc_dictionary_get_int64(reply, "status") == 0;
    if (reply != NULL && xpc_get_type(reply) == XPC_TYPE_ERROR) {
        const char *description =
            xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION);
        os_log_with_type(CompatLog(), OS_LOG_TYPE_ERROR,
                         "respring broker transport error: %{public}s",
                         description != NULL ? description : "unknown");
    } else if (!accepted) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_ERROR,
                         "respring broker rejected Settings request");
    }
#if !OS_OBJECT_USE_OBJC
    if (reply != NULL) xpc_release(reply);
    xpc_release(message);
    xpc_connection_cancel(connection);
    xpc_release(connection);
#else
    xpc_connection_cancel(connection);
#endif
    if (!accepted) errno = EPERM;
    return accepted;
}

static pid_t RememberCompletedRespring(void) {
    pthread_mutex_lock(&RespringJobLock);
    pid_t result = CODEX_FAKE_RESPRING_PID_FIRST +
        (pid_t)(NextRespringJobIdentifier++ & 0x00ffffffU);
    CompletedRespringJobs[NextCompletedRespringJob] = result;
    NextCompletedRespringJob =
        (NextCompletedRespringJob + 1U) % CODEX_COMPLETED_RESPRING_COUNT;
    pthread_mutex_unlock(&RespringJobLock);
    return result;
}

static bool ExistingTranslatedExecutable(const char *path, char *translated,
                                         size_t translatedSize) {
    return TranslateLegacyPath(path, translated, translatedSize, NULL) &&
           access(translated, X_OK) == 0;
}

static bool RootlessExecutableForLeaf(const char *path, char *translated,
                                      size_t translatedSize) {
    if (path == NULL || path[0] == '\0' || strchr(path, '/') != NULL ||
        strnlen(path, NAME_MAX) >= NAME_MAX) {
        return false;
    }
    static const char *const roots[] = {
        "/var/jb/usr/bin/", "/var/jb/bin/",
        "/var/jb/usr/sbin/", "/var/jb/sbin/",
        "/var/jb/usr/local/bin/", "/var/jb/usr/local/sbin/",
    };
    for (size_t index = 0; index < sizeof(roots) / sizeof(roots[0]); ++index) {
        if (CopyJoinedPath(roots[index], path, translated, translatedSize) &&
            access(translated, X_OK) == 0) {
            return true;
        }
    }
    return false;
}

static int CompatPosixSpawn(pid_t *restrict pid, const char *restrict path,
                            const posix_spawn_file_actions_t *actions,
                            const posix_spawnattr_t *restrict attributes,
                            char *const arguments[restrict],
                            char *const environment[restrict]) {
    if (IsPreferencesProcess() &&
        ArgumentsRequestRespring(path, arguments)) {
        if (pid == NULL) return EINVAL;
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "routing preference respring command=%{public}s",
                         path != NULL ? path : "none");
        if (!RequestPreferencesRespring()) {
            return errno != 0 ? errno : EPERM;
        }
        *pid = RememberCompletedRespring();
        return 0;
    }

    int result = posix_spawn(pid, path, actions, attributes, arguments,
                             environment);
    if (result == 0 || !RetryPathFailure(result)) return result;
    char translated[PATH_MAX];
    if (!ExistingTranslatedExecutable(path, translated, sizeof(translated))) {
        return result;
    }
    return posix_spawn(pid, translated, actions, attributes, arguments,
                       environment);
}

static int CompatPosixSpawnp(pid_t *restrict pid, const char *restrict path,
                             const posix_spawn_file_actions_t *actions,
                             const posix_spawnattr_t *restrict attributes,
                             char *const arguments[restrict],
                             char *const environment[restrict]) {
    if (IsPreferencesProcess() &&
        ArgumentsRequestRespring(path, arguments)) {
        return CompatPosixSpawn(pid, path, actions, attributes, arguments,
                                environment);
    }

    int result = posix_spawnp(pid, path, actions, attributes, arguments,
                              environment);
    if (result == 0 || !RetryPathFailure(result)) return result;
    char translated[PATH_MAX];
    bool available = ExistingTranslatedExecutable(
        path, translated, sizeof(translated));
    if (!available) {
        available = RootlessExecutableForLeaf(path, translated,
                                              sizeof(translated));
    }
    if (!available) return result;
    return posix_spawn(pid, translated, actions, attributes, arguments,
                       environment);
}

static pid_t CompatWaitpid(pid_t pid, int *status, int options) {
    if ((options & ~WNOHANG) != 0) return waitpid(pid, status, options);
    pthread_mutex_lock(&RespringJobLock);
    size_t match = CODEX_COMPLETED_RESPRING_COUNT;
    for (size_t index = 0; index < CODEX_COMPLETED_RESPRING_COUNT; ++index) {
        if (CompletedRespringJobs[index] != 0 &&
            (pid == -1 || CompletedRespringJobs[index] == pid)) {
            match = index;
            break;
        }
    }
    if (match == CODEX_COMPLETED_RESPRING_COUNT) {
        pthread_mutex_unlock(&RespringJobLock);
        return waitpid(pid, status, options);
    }
    pid_t completed = CompletedRespringJobs[match];
    CompletedRespringJobs[match] = 0;
    pthread_mutex_unlock(&RespringJobLock);
    if (status != NULL) *status = 0;
    return completed;
}

static BOOL ShellCommandRequestsRespring(const char *command) {
    if (command == NULL) return NO;
    size_t length = strnlen(command, 512U);
    if (length == 0 || length == 512U) return NO;
    char copy[512];
    memcpy(copy, command, length + 1U);
    char *arguments[16] = {0};
    size_t count = 0;
    char *cursor = copy;
    while (*cursor != '\0' && count + 1U < 16U) {
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor == '\0') break;
        arguments[count++] = cursor;
        while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
            if (strchr(";&|<>`$\\\"'", *cursor) != NULL) return NO;
            ++cursor;
        }
        if (*cursor != '\0') *cursor++ = '\0';
    }
    return count != 0 && ArgumentsRequestRespring(arguments[0], arguments);
}

static int CompatSystem(const char *command) {
    if (!IsPreferencesProcess() ||
        !ShellCommandRequestsRespring(command)) {
        if (OriginalSystem == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return OriginalSystem(command);
    }
    os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                     "routing preference shell respring");
    if (!RequestPreferencesRespring()) return -1;
    return 0;
}

static bool RetryPathFailure(int error) {
    return error == ENOENT || error == ENOTDIR || error == EACCES ||
           error == EPERM || error == EROFS;
}

static NSUInteger SelectorArgumentCount(const char *name) {
    NSUInteger count = 0;
    if (name == NULL) return count;
    for (const char *cursor = name; *cursor != '\0'; ++cursor) {
        if (*cursor == ':') ++count;
    }
    return count;
}

bool codex_legacy_tweak_compat_register_class_alias(const char *legacyName,
                                                     const char *currentName) {
    if (!ValidRuntimeName(legacyName) || !ValidRuntimeName(currentName)) {
        return false;
    }
    if (objc_getClass(legacyName) != Nil) return true;
    Class currentClass = objc_getClass(currentName);
    if (currentClass == Nil) return false;
    Class alias = objc_allocateClassPair(currentClass, legacyName, 0);
    if (alias == Nil) return objc_getClass(legacyName) != Nil;
    objc_registerClassPair(alias);
    os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                     "class alias %{public}s -> %{public}s", legacyName,
                     currentName);
    return true;
}

bool codex_legacy_tweak_compat_register_selector_alias(
    const char *className, const char *legacySelector,
    const char *currentSelector, bool classMethod) {
    if (!ValidRuntimeName(className) || legacySelector == NULL ||
        currentSelector == NULL || strlen(legacySelector) >= 192 ||
        strlen(currentSelector) >= 192 ||
        SelectorArgumentCount(legacySelector) !=
            SelectorArgumentCount(currentSelector)) {
        return false;
    }
    Class cls = objc_getClass(className);
    if (cls == Nil) return false;
    Class target = classMethod ? object_getClass(cls) : cls;
    SEL oldSelector = sel_registerName(legacySelector);
    SEL newSelector = sel_registerName(currentSelector);
    if (class_getInstanceMethod(target, oldSelector) != NULL) return true;
    Method current = class_getInstanceMethod(target, newSelector);
    if (current == NULL) return false;
    BOOL added = class_addMethod(target, oldSelector,
                                 method_getImplementation(current),
                                 method_getTypeEncoding(current));
    if (added) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "selector alias %{public}s[%{public}s %{public}s] "
                         "-> %{public}s",
                         classMethod ? "+" : "-", className, legacySelector,
                         currentSelector);
    }
    return added || class_getInstanceMethod(target, oldSelector) != NULL;
}

static NSDictionary *TrustedAliasConfiguration(void) {
    struct stat status = {0};
    if (lstat(CODEX_LEGACY_COMPAT_CONFIG, &status) != 0) return nil;
    if (!S_ISREG(status.st_mode) || status.st_uid != 0 ||
        status.st_size <= 0 || status.st_size > 64 * 1024 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_ERROR,
                         "ignored unsafe alias configuration");
        return nil;
    }
    return [NSDictionary dictionaryWithContentsOfFile:
        @CODEX_LEGACY_COMPAT_CONFIG];
}

static void UpdateConfiguredPathMappings(NSDictionary *configuration) {
    struct CodexPathMapping mappings[CODEX_MAX_PATH_MAPPINGS] = {0};
    size_t count = 0;
    NSDictionary *pathPrefixes = configuration[@"PathPrefixes"];
    if ([pathPrefixes isKindOfClass:NSDictionary.class]) {
        for (id legacyValue in pathPrefixes) {
            id currentValue = pathPrefixes[legacyValue];
            if (![legacyValue isKindOfClass:NSString.class] ||
                ![currentValue isKindOfClass:NSString.class] ||
                count >= CODEX_MAX_PATH_MAPPINGS) {
                continue;
            }
            const char *legacy = [legacyValue fileSystemRepresentation];
            const char *current = [currentValue fileSystemRepresentation];
            if (!BuiltInLegacyPath(legacy) || current == NULL ||
                !PathHasPrefix(current, "/var/jb/") ||
                PathHasUnsafeComponent(current) ||
                strnlen(legacy, PATH_MAX) >= PATH_MAX ||
                strnlen(current, PATH_MAX) >= PATH_MAX) {
                continue;
            }
            strlcpy(mappings[count].legacy, legacy,
                    sizeof(mappings[count].legacy));
            strlcpy(mappings[count].current, current,
                    sizeof(mappings[count].current));
            ++count;
        }
    }
    pthread_mutex_lock(&PathMappingLock);
    memset(ConfiguredPathMappings, 0, sizeof(ConfiguredPathMappings));
    memcpy(ConfiguredPathMappings, mappings,
           count * sizeof(struct CodexPathMapping));
    ConfiguredPathMappingCount = count;
    pthread_mutex_unlock(&PathMappingLock);
}

static void ApplyConfiguredAliases(void) {
    NSDictionary *configuration = TrustedAliasConfiguration();
    UpdateConfiguredPathMappings(configuration);
    NSDictionary *classAliases = configuration[@"ClassAliases"];
    if ([classAliases isKindOfClass:NSDictionary.class]) {
        [classAliases enumerateKeysAndObjectsUsingBlock:
            ^(id legacyName, id currentName, __unused BOOL *stop) {
            if ([legacyName isKindOfClass:NSString.class] &&
                [currentName isKindOfClass:NSString.class]) {
                codex_legacy_tweak_compat_register_class_alias(
                    [legacyName UTF8String], [currentName UTF8String]);
            }
        }];
    }
    NSArray *selectorAliases = configuration[@"SelectorAliases"];
    if (![selectorAliases isKindOfClass:NSArray.class]) return;
    for (id value in selectorAliases) {
        if (![value isKindOfClass:NSDictionary.class]) continue;
        NSString *className = value[@"Class"];
        NSString *legacy = value[@"Legacy"];
        NSString *current = value[@"Current"];
        if (![className isKindOfClass:NSString.class] ||
            ![legacy isKindOfClass:NSString.class] ||
            ![current isKindOfClass:NSString.class]) {
            continue;
        }
        codex_legacy_tweak_compat_register_selector_alias(
            className.UTF8String, legacy.UTF8String, current.UTF8String,
            [value[@"ClassMethod"] boolValue]);
    }
}

static int CompatAccess(const char *path, int mode) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = access(translated, mode);
        if (result == 0) return result;
    }
    int result = access(path, mode);
    if (result == 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return access(translated, mode);
}

static int CompatFAccessAt(int descriptor, const char *path, int mode,
                           int flags) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = faccessat(descriptor, translated, mode, flags);
        if (result == 0) return result;
    }
    int result = faccessat(descriptor, path, mode, flags);
    if (result == 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return faccessat(descriptor, translated, mode, flags);
}

typedef int (*StatPathImplementation)(const char *, struct stat *);

static int CompatStatPath(StatPathImplementation implementation,
                          const char *path, struct stat *status) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = implementation(translated, status);
        if (result == 0) return result;
    }
    int result = implementation(path, status);
    if (result == 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return implementation(translated, status);
}

static int CompatStat(const char *path, struct stat *status) {
    return CompatStatPath(stat, path, status);
}

static int CompatLstat(const char *path, struct stat *status) {
    return CompatStatPath(lstat, path, status);
}

static int CompatOpen(const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = open(translated, flags, mode);
        if (result >= 0) return result;
    }
    int result = open(path, flags, mode);
    if (result >= 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return open(translated, flags, mode);
}

static int CompatOpenAt(int descriptor, const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = openat(descriptor, translated, flags, mode);
        if (result >= 0) return result;
    }
    int result = openat(descriptor, path, flags, mode);
    if (result >= 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return openat(descriptor, translated, flags, mode);
}

static FILE *CompatFopen(const char *path, const char *mode) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        FILE *result = fopen(translated, mode);
        if (result != NULL) return result;
    }
    FILE *result = fopen(path, mode);
    if (result != NULL || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return fopen(translated, mode);
}

static DIR *CompatOpendir(const char *path) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        DIR *result = opendir(translated);
        if (result != NULL) return result;
    }
    DIR *result = opendir(path);
    if (result != NULL || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return opendir(translated);
}

static ssize_t CompatReadlink(const char *path, char *buffer, size_t size) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        ssize_t result = readlink(translated, buffer, size);
        if (result >= 0) return result;
    }
    ssize_t result = readlink(path, buffer, size);
    if (result >= 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return readlink(translated, buffer, size);
}

static char *CompatRealpath(const char *path, char *resolved) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        char *result = realpath(translated, resolved);
        if (result != NULL) return result;
    }
    char *result = realpath(path, resolved);
    if (result != NULL || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return realpath(translated, resolved);
}

typedef int (*SinglePathOperation)(const char *);

static int CompatSinglePathOperation(SinglePathOperation operation,
                                     const char *path) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = operation(translated);
        if (result == 0) return result;
    }
    int result = operation(path);
    if (result == 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return operation(translated);
}

static int CompatUnlink(const char *path) {
    return CompatSinglePathOperation(unlink, path);
}

static int CompatRemove(const char *path) {
    return CompatSinglePathOperation(remove, path);
}

static int CompatMkdir(const char *path, mode_t mode) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = mkdir(translated, mode);
        if (result == 0) return result;
    }
    int result = mkdir(path, mode);
    if (result == 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return mkdir(translated, mode);
}

static int CompatChmod(const char *path, mode_t mode) {
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        int result = chmod(translated, mode);
        if (result == 0) return result;
    }
    int result = chmod(path, mode);
    if (result == 0 || !available || preferred ||
        !RetryPathFailure(errno)) {
        return result;
    }
    return chmod(translated, mode);
}

typedef int (*TwoPathOperation)(const char *, const char *);

static int CompatTwoPathOperation(TwoPathOperation operation,
                                  const char *source,
                                  const char *destination) {
    char translatedSource[PATH_MAX];
    char translatedDestination[PATH_MAX];
    bool sourcePreferred = false;
    bool destinationPreferred = false;
    bool sourceAvailable = TranslateLegacyPath(
        source, translatedSource, sizeof(translatedSource), &sourcePreferred);
    bool destinationAvailable = TranslateLegacyPath(
        destination, translatedDestination, sizeof(translatedDestination),
        &destinationPreferred);
    bool preferred = sourcePreferred || destinationPreferred;
    const char *mappedSource = sourceAvailable ? translatedSource : source;
    const char *mappedDestination = destinationAvailable
        ? translatedDestination : destination;
    if ((sourceAvailable || destinationAvailable) && preferred) {
        int result = operation(mappedSource, mappedDestination);
        if (result == 0) return result;
    }
    int result = operation(source, destination);
    if (result == 0 || (!sourceAvailable && !destinationAvailable) ||
        preferred || !RetryPathFailure(errno)) {
        return result;
    }
    return operation(mappedSource, mappedDestination);
}

static int CompatRename(const char *source, const char *destination) {
    return CompatTwoPathOperation(rename, source, destination);
}

static int CompatLink(const char *source, const char *destination) {
    return CompatTwoPathOperation(link, source, destination);
}

static int CompatSymlink(const char *source, const char *destination) {
    return CompatTwoPathOperation(symlink, source, destination);
}

static void *CompatDlopen(const char *path, int mode) {
    if (path == NULL) return dlopen(path, mode);
    char translated[PATH_MAX];
    bool preferred = false;
    bool available = TranslateLegacyPath(path, translated,
                                         sizeof(translated), &preferred);
    if (available && preferred) {
        void *result = dlopen(translated, mode);
        if (result != NULL) return result;
    }
    void *result = dlopen(path, mode);
    if (result != NULL || !available || preferred) return result;
    return dlopen(translated, mode);
}

static BOOL CompatibilityConsumerImage(const char *path) {
    if (path == NULL) return NO;
    if (strstr(path, "/Foundation.framework/Foundation") != NULL ||
        strstr(path, "/CoreFoundation.framework/CoreFoundation") != NULL) {
        return YES;
    }
    BOOL rootless = PathHasPrefix(path, "/var/jb/") ||
                    strstr(path, "/procursus/") != NULL;
    if (!rootless || strstr(path, "/usr/lib/sbinject/") != NULL) return NO;
    return strstr(path, "/Library/MobileSubstrate/DynamicLibraries/") != NULL ||
           strstr(path, "/Library/TweakInject/") != NULL ||
           strstr(path, "/usr/lib/TweakInject/") != NULL ||
           strstr(path, "/Library/PreferenceBundles/") != NULL ||
           strstr(path, "/Library/Frameworks/") != NULL ||
           strstr(path, "/usr/lib/") != NULL;
}

static void RebindCompatibilityImage(const struct mach_header *header,
                                     __unused intptr_t slide) {
    Dl_info information = {0};
    if (header == NULL || dladdr(header, &information) == 0 ||
        !CompatibilityConsumerImage(information.dli_fname)) {
        return;
    }
    const struct mach_header_64 *header64 =
        (const struct mach_header_64 *)header;
    size_t writes = 0;
#define CODEX_REBIND(symbol, replacement) do { \
    litehook_rebind_result_t result = litehook_rebind_symbol( \
        header64, (void *)(uintptr_t)(symbol), \
        (void *)(uintptr_t)(replacement)); \
    writes += result.writes; \
} while (0)
    CODEX_REBIND(access, CompatAccess);
    CODEX_REBIND(faccessat, CompatFAccessAt);
    CODEX_REBIND(stat, CompatStat);
    CODEX_REBIND(lstat, CompatLstat);
    CODEX_REBIND(open, CompatOpen);
    CODEX_REBIND(openat, CompatOpenAt);
    CODEX_REBIND(fopen, CompatFopen);
    CODEX_REBIND(opendir, CompatOpendir);
    CODEX_REBIND(readlink, CompatReadlink);
    CODEX_REBIND(realpath, CompatRealpath);
    CODEX_REBIND(unlink, CompatUnlink);
    CODEX_REBIND(remove, CompatRemove);
    CODEX_REBIND(mkdir, CompatMkdir);
    CODEX_REBIND(chmod, CompatChmod);
    CODEX_REBIND(rename, CompatRename);
    CODEX_REBIND(link, CompatLink);
    CODEX_REBIND(symlink, CompatSymlink);
    CODEX_REBIND(dlopen, CompatDlopen);
    CODEX_REBIND(posix_spawn, CompatPosixSpawn);
    CODEX_REBIND(posix_spawnp, CompatPosixSpawnp);
    CODEX_REBIND(waitpid, CompatWaitpid);
    if (OriginalSystem != NULL) {
        CODEX_REBIND(OriginalSystem, CompatSystem);
    }
#undef CODEX_REBIND
    if (writes > 0) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_INFO,
                         "installed %lu path repairs image=%{public}s",
                         (unsigned long)writes, information.dli_fname);
    }
}

static void InstallPathHooks(void) {
    _dyld_register_func_for_add_image(RebindCompatibilityImage);
}

static UIWindowScene *ActiveWindowScene(void) {
    UIApplication *application = UIApplication.sharedApplication;
    UIWindowScene *fallback = nil;
    for (UIScene *scene in application.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        if (windowScene.activationState ==
            UISceneActivationStateForegroundActive) {
            return windowScene;
        }
        if (fallback == nil && windowScene.activationState !=
                                   UISceneActivationStateUnattached) {
            fallback = windowScene;
        }
    }
    return fallback;
}

static BOOL AdoptWindowScene(UIWindow *window) {
    if (window == nil || window.windowScene != nil) return YES;
    UIWindowScene *scene = ActiveWindowScene();
    if (scene == nil) {
        @synchronized (OrphanWindows) {
            [OrphanWindows addObject:window];
        }
        return NO;
    }
    window.windowScene = scene;
    @synchronized (OrphanWindows) {
        [OrphanWindows removeObject:window];
    }
    os_log_with_type(CompatLog(), OS_LOG_TYPE_INFO,
                     "attached legacy window class=%{public}s",
                     class_getName(window.class));
    return YES;
}

static void CompatWindowSetHidden(UIWindow *window, SEL selector, BOOL hidden) {
    if (!hidden) (void)AdoptWindowScene(window);
    OriginalWindowSetHidden(window, selector, hidden);
    if (!hidden) ScheduleLegacyStatusOverlayLayout();
}

static void CompatWindowMakeKeyAndVisible(UIWindow *window, SEL selector) {
    (void)AdoptWindowScene(window);
    OriginalWindowMakeKeyAndVisible(window, selector);
    ScheduleLegacyStatusOverlayLayout();
}

static void RepairOrphanWindows(void) {
    NSArray<UIWindow *> *windows = nil;
    @synchronized (OrphanWindows) {
        windows = OrphanWindows.allObjects;
    }
    for (UIWindow *window in windows) {
        (void)AdoptWindowScene(window);
    }
}

static BOOL TweakInjectionImage(NSString *path) {
    if (path.length == 0 || [path containsString:@"/usr/lib/sbinject/"]) {
        return NO;
    }
    return [path containsString:@"/Library/MobileSubstrate/DynamicLibraries/"] ||
           [path containsString:@"/Library/TweakInject/"] ||
           [path containsString:@"/usr/lib/TweakInject/"];
}

static BOOL ObjectReturningNoArgumentMethod(Method method) {
    if (method == NULL || method_getNumberOfArguments(method) != 2) return NO;
    char returnType[8] = {0};
    method_getReturnType(method, returnType, sizeof(returnType));
    return returnType[0] == '@';
}

static WindowOwnerFrameImplementation WindowOwnerFrameImplementationForClass(
    Class cls) {
    @synchronized (WindowOwnerFrameImplementations) {
        for (Class cursor = cls; cursor != Nil;
             cursor = class_getSuperclass(cursor)) {
            NSValue *value = WindowOwnerFrameImplementations[
                NSStringFromClass(cursor)];
            if (value != nil) return value.pointerValue;
        }
    }
    return NULL;
}

static void DisableLegacyWindowOwnerInteraction(id owner) {
    if (![NoninteractiveWindowOwnerNames containsObject:
            NSStringFromClass([owner class])]) {
        return;
    }
    SEL selector = sel_registerName("springboardWindow");
    if (![owner respondsToSelector:selector]) return;
    id window = ((id (*)(id, SEL))objc_msgSend)(owner, selector);
    if ([window isKindOfClass:UIWindow.class]) {
        ((UIWindow *)window).userInteractionEnabled = NO;
    }
}

static void CompatWindowOwnerUpdateFrame(id owner, SEL selector) {
    WindowOwnerFrameImplementation original =
        WindowOwnerFrameImplementationForClass((Class)[owner class]);
    if (original != NULL) original(owner, selector);
    DisableLegacyWindowOwnerInteraction(owner);
    if (NSThread.isMainThread) {
        UIWindowScene *scene = ActiveWindowScene();
        if (scene != nil) LayoutLegacyStatusOverlayWindows(scene);
    } else {
        ScheduleLegacyStatusOverlayLayout();
    }
}

static void InstallLegacyWindowOwnerFrameHook(Class cls) {
    SEL selector = sel_registerName("updateFrame");
    Method method = class_getInstanceMethod(cls, selector);
    if (method == NULL || method_getNumberOfArguments(method) != 2) return;
    NSString *name = NSStringFromClass(cls);
    @synchronized (WindowOwnerFrameImplementations) {
        if (WindowOwnerFrameImplementations[name] != nil) return;
        IMP original = method_getImplementation(method);
        if (original == (IMP)CompatWindowOwnerUpdateFrame) return;
        IMP replaced = class_replaceMethod(
            cls, selector, (IMP)CompatWindowOwnerUpdateFrame,
            method_getTypeEncoding(method));
        if (replaced != NULL) original = replaced;
        WindowOwnerFrameImplementations[name] =
            [NSValue valueWithPointer:original];
    }
}

static id KeepEyeLabel(id monitor) {
    SEL selector = sel_registerName("label");
    if (![monitor respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(monitor, selector);
}

static void SetKeepEyeLabelText(id monitor, NSString *text) {
    id label = KeepEyeLabel(monitor);
    if (label == nil || text == nil ||
        ![label respondsToSelector:@selector(setText:)]) {
        return;
    }
    ((void (*)(id, SEL, id))objc_msgSend)(label, @selector(setText:), text);
}

static NSString *KeepEyeLabelText(id monitor) {
    id label = KeepEyeLabel(monitor);
    if (label == nil || ![label respondsToSelector:@selector(text)]) {
        return nil;
    }
    id text = ((id (*)(id, SEL))objc_msgSend)(label, @selector(text));
    return [text isKindOfClass:NSString.class] ? text : nil;
}

static void FitKeepEyeMonitorToText(id monitor) {
    id label = KeepEyeLabel(monitor);
    SEL windowSelector = sel_registerName("springboardWindow");
    if (label == nil || ![label respondsToSelector:@selector(sizeThatFits:)] ||
        ![monitor respondsToSelector:windowSelector]) {
        return;
    }
    UIWindow *window = ((id (*)(id, SEL))objc_msgSend)(monitor,
                                                       windowSelector);
    if (![window isKindOfClass:UIWindow.class]) return;
    window.userInteractionEnabled = NO;

    CGRect frame = window.frame;
    CGSize textSize = ((CGSize (*)(id, SEL, CGSize))objc_msgSend)(
        label, @selector(sizeThatFits:),
        CGSizeMake(CGFLOAT_MAX, MAX(1.0, CGRectGetHeight(frame))));
    CGFloat width = MAX(CGRectGetWidth(frame), ceil(textSize.width) + 10.0);
    frame.size.width = MIN(width, 180.0);
    window.frame = frame;

    CGFloat height = CGRectGetHeight(frame);
    CGFloat innerWidth = MAX(0.0, CGRectGetWidth(frame) - 8.0);
    for (NSString *selectorName in @[@"backView", @"content"]) {
        SEL selector = NSSelectorFromString(selectorName);
        if (![monitor respondsToSelector:selector]) continue;
        id view = ((id (*)(id, SEL))objc_msgSend)(monitor, selector);
        if (![view isKindOfClass:UIView.class]) continue;
        CGRect bounds = [selectorName isEqualToString:@"backView"]
            ? CGRectMake(0.0, 0.0, CGRectGetWidth(frame), height)
            : CGRectMake(4.0, 0.0, innerWidth, height);
        ((void (*)(id, SEL, CGRect))objc_msgSend)(view,
                                                  @selector(setFrame:), bounds);
    }
    if ([label isKindOfClass:UIView.class]) {
        ((UIView *)label).frame = CGRectMake(0.0, 0.0, innerWidth, height);
    }
    if ([label respondsToSelector:@selector(setAdjustsFontSizeToFitWidth:)]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(
            label, @selector(setAdjustsFontSizeToFitWidth:), YES);
    }
    if ([label respondsToSelector:@selector(setMinimumScaleFactor:)]) {
        ((void (*)(id, SEL, CGFloat))objc_msgSend)(
            label, @selector(setMinimumScaleFactor:), 0.6);
    }
    if (NSThread.isMainThread) {
        UIWindowScene *scene = ActiveWindowScene();
        if (scene != nil) LayoutLegacyStatusOverlayWindows(scene);
    } else {
        ScheduleLegacyStatusOverlayLayout();
    }
}

static id KeepEyeBatteryDictionary(id monitor, SEL selector) {
    id dictionary = OriginalBatteryDictionary == NULL
        ? nil
        : OriginalBatteryDictionary(monitor, selector);
    if (![dictionary isKindOfClass:NSDictionary.class] ||
        dictionary[@"Temperature"] != nil) {
        return dictionary;
    }

    if (BatteryPackService == IO_OBJECT_NULL) {
        BatteryPackService = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("AppleSmartBatteryPack"));
    }
    if (BatteryPackService == IO_OBJECT_NULL) return dictionary;

    CFMutableDictionaryRef properties = NULL;
    kern_return_t result = IORegistryEntryCreateCFProperties(
        BatteryPackService, &properties, kCFAllocatorDefault, 0);
    if (result != KERN_SUCCESS || properties == NULL) return dictionary;

    NSDictionary *propertyDictionary = CFBridgingRelease(properties);
    id batteryData = propertyDictionary[@"BatteryData"];
    id temperature = [batteryData isKindOfClass:NSDictionary.class]
        ? batteryData[@"Temperature"]
        : nil;
    if (temperature == nil) return dictionary;

    NSMutableDictionary *updated = [dictionary mutableCopy];
    updated[@"Temperature"] = temperature;
    return updated;
}

static void KeepEyeBatteryUpdate(id monitor, SEL selector) {
    if (OriginalBatteryMonitorUpdate != NULL) {
        OriginalBatteryMonitorUpdate(monitor, selector);
    }
    NSString *text = KeepEyeLabelText(monitor);
    NSRange degree = [text rangeOfString:@"°"];
    if (degree.location == NSNotFound) {
        ScheduleLegacyStatusOverlayLayout();
        return;
    }

    NSString *number = [text substringToIndex:degree.location];
    NSScanner *scanner = [NSScanner scannerWithString:number];
    double celsius = 0.0;
    if (![scanner scanDouble:&celsius] || !scanner.isAtEnd) {
        ScheduleLegacyStatusOverlayLayout();
        return;
    }
    NSString *suffix = [text substringFromIndex:NSMaxRange(degree)];
    SetKeepEyeLabelText(
        monitor,
        [NSString stringWithFormat:@"%.1f°%@", celsius * 9.0 / 5.0 + 32.0,
                                   suffix]);
    FitKeepEyeMonitorToText(monitor);
    ScheduleLegacyStatusOverlayLayout();
}

static void KeepEyeCPUUpdate(id monitor, SEL selector) {
    if (OriginalCPUMonitorUpdate != NULL) {
        OriginalCPUMonitorUpdate(monitor, selector);
    }
    FitKeepEyeMonitorToText(monitor);
    ScheduleLegacyStatusOverlayLayout();
}

static void KeepEyeRAMUpdate(id monitor, SEL selector) {
    if (OriginalRAMMonitorUpdate != NULL) {
        OriginalRAMMonitorUpdate(monitor, selector);
    }
    NSString *text = KeepEyeLabelText(monitor);
    NSScanner *scanner = [NSScanner scannerWithString:text ?: @""];
    double megabytes = 0.0;
    if ([scanner scanDouble:&megabytes]) {
        NSString *unit = [[text substringFromIndex:scanner.scanLocation]
            stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceCharacterSet];
        if ([unit isEqualToString:@"MB"] && megabytes >= 1024.0) {
            SetKeepEyeLabelText(
                monitor,
                [NSString stringWithFormat:@"%.1f GB", megabytes / 1024.0]);
        }
    }
    FitKeepEyeMonitorToText(monitor);
    ScheduleLegacyStatusOverlayLayout();
}

static void KeepEyeNetworkUpdate(id monitor, SEL selector) {
    if (OriginalNetworkMonitorUpdate != NULL) {
        OriginalNetworkMonitorUpdate(monitor, selector);
    }
    NSString *text = KeepEyeLabelText(monitor);
    NSDictionary<NSString *, NSString *> *units = @{
        @"K/s" : @"kb/s",
        @"M/s" : @"mb/s",
        @"G/s" : @"gb/s",
        @"B/s" : @"b/s",
    };
    for (NSString *unit in units) {
        text = [text stringByReplacingOccurrencesOfString:unit
                                               withString:units[unit]];
    }
    SetKeepEyeLabelText(monitor, text);
    FitKeepEyeMonitorToText(monitor);
    ScheduleLegacyStatusOverlayLayout();
}

static BOOL InstallKeepEyeUpdateHook(Class cls, IMP replacement,
                                     MonitorUpdateImplementation *original) {
    Method method = class_getInstanceMethod(cls, sel_registerName("update"));
    if (method == NULL || method_getNumberOfArguments(method) != 2) return NO;
    IMP current = method_getImplementation(method);
    if (current == replacement) return *original != NULL;
    *original = (MonitorUpdateImplementation)
        method_setImplementation(method, replacement);
    return *original != NULL;
}

static void InstallKeepEyeDisplayCompatibility(void) {
    if (KeepEyeDisplayCompatibilityInstalled || !IsSpringBoardProcess()) {
        return;
    }
    Class batteryClass = objc_getClass("BattMonitor");
    Class ramClass = objc_getClass("RAMMonitor");
    Class networkClass = objc_getClass("NetMonitor");
    Class cpuClass = objc_getClass("CPUMonitor");
    if (batteryClass == Nil || ramClass == Nil || networkClass == Nil ||
        cpuClass == Nil) {
        return;
    }

    const char *image = class_getImageName(batteryClass);
    const char *ramImage = class_getImageName(ramClass);
    const char *networkImage = class_getImageName(networkClass);
    const char *cpuImage = class_getImageName(cpuClass);
    if (image == NULL || ramImage == NULL || networkImage == NULL ||
        cpuImage == NULL || strcmp(image, ramImage) != 0 ||
        strcmp(image, networkImage) != 0 || strcmp(image, cpuImage) != 0 ||
        !TweakInjectionImage([NSString stringWithUTF8String:image])) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_ERROR,
                         "KeepEye display compatibility image check failed");
        return;
    }

    Method dictionaryMethod = class_getInstanceMethod(
        batteryClass, sel_registerName("dicPrivateBatt"));
    if (dictionaryMethod == NULL ||
        !ObjectReturningNoArgumentMethod(dictionaryMethod)) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_ERROR,
                         "KeepEye battery dictionary method is unavailable");
        return;
    }
    IMP currentDictionary = method_getImplementation(dictionaryMethod);
    if (currentDictionary != (IMP)KeepEyeBatteryDictionary) {
        OriginalBatteryDictionary = (BatteryDictionaryImplementation)
            method_setImplementation(dictionaryMethod,
                                     (IMP)KeepEyeBatteryDictionary);
    }
    if (OriginalBatteryDictionary == NULL ||
        !InstallKeepEyeUpdateHook(batteryClass,
                                  (IMP)KeepEyeBatteryUpdate,
                                  &OriginalBatteryMonitorUpdate) ||
        !InstallKeepEyeUpdateHook(cpuClass, (IMP)KeepEyeCPUUpdate,
                                  &OriginalCPUMonitorUpdate) ||
        !InstallKeepEyeUpdateHook(ramClass, (IMP)KeepEyeRAMUpdate,
                                  &OriginalRAMMonitorUpdate) ||
        !InstallKeepEyeUpdateHook(networkClass,
                                  (IMP)KeepEyeNetworkUpdate,
                                  &OriginalNetworkMonitorUpdate)) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_ERROR,
                         "KeepEye display compatibility hook failed");
        return;
    }

    KeepEyeDisplayCompatibilityInstalled = YES;
    [NoninteractiveWindowOwnerNames addObjectsFromArray:@[
        NSStringFromClass(batteryClass), NSStringFromClass(cpuClass),
        NSStringFromClass(ramClass), NSStringFromClass(networkClass)
    ]];
    os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                     "installed KeepEye display compatibility");
}

static void RegisterLegacyWindowOwnersInImage(NSString *path) {
    if (!IsSpringBoardProcess() || !TweakInjectionImage(path)) return;
    unsigned int count = 0;
    const char **names = objc_copyClassNamesForImage(
        path.fileSystemRepresentation, &count);
    SEL sharedSelector = sel_registerName("sharedInstance");
    SEL windowSelector = sel_registerName("springboardWindow");
    for (unsigned int index = 0; index < count; ++index) {
        Class cls = objc_getClass(names[index]);
        if (cls == Nil ||
            !ObjectReturningNoArgumentMethod(
                class_getClassMethod(cls, sharedSelector)) ||
            !ObjectReturningNoArgumentMethod(
                class_getInstanceMethod(cls, windowSelector))) {
            continue;
        }
        NSString *name = NSStringFromClass(cls);
        if ([LegacyWindowOwnerNames containsObject:name]) continue;
        [LegacyWindowOwnerNames addObject:name];
        [LegacyWindowOwnerClasses addObject:cls];
        InstallLegacyWindowOwnerFrameHook(cls);
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "registered legacy window owner class=%{public}s",
                         class_getName(cls));
    }
    free(names);
}

static BOOL RepairLegacyWindowOwners(void) {
    if (!IsSpringBoardProcess() || LegacyWindowOwnerClasses.count == 0) {
        return YES;
    }
    UIWindowScene *scene = ActiveWindowScene();
    if (scene == nil) return NO;

    BOOL ready = YES;
    SEL sharedSelector = sel_registerName("sharedInstance");
    SEL windowSelector = sel_registerName("springboardWindow");
    SEL updateFrameSelector = sel_registerName("updateFrame");
    for (Class cls in [LegacyWindowOwnerClasses copy]) {
        @try {
            id owner = ((id (*)(id, SEL))objc_msgSend)(cls, sharedSelector);
            if (owner == nil) {
                ready = NO;
                continue;
            }
            UIWindow *window = ((id (*)(id, SEL))objc_msgSend)(
                owner, windowSelector);
            if (![window isKindOfClass:UIWindow.class]) {
                ready = NO;
                continue;
            }
            DisableLegacyWindowOwnerInteraction(owner);
            if (window.windowScene != scene) window.windowScene = scene;
            if ([owner respondsToSelector:updateFrameSelector]) {
                ((void (*)(id, SEL))objc_msgSend)(owner,
                                                  updateFrameSelector);
            }
            if (!window.hidden) window.hidden = NO;
        } @catch (NSException *exception) {
            ready = NO;
            os_log_with_type(
                CompatLog(), OS_LOG_TYPE_ERROR,
                "legacy window owner failed class=%{public}s reason=%{public}s",
                class_getName(cls), exception.reason.UTF8String);
        }
    }
    return ready;
}

static BOOL IsLegacyStatusOverlayWindow(UIWindow *window,
                                        CGRect statusBarFrame) {
    const char *image = class_getImageName(window.class);
    if (image == NULL ||
        !TweakInjectionImage([NSString stringWithUTF8String:image]) ||
        window.hidden || window.alpha <= 0.0 ||
        window.rootViewController != nil) {
        return NO;
    }
    CGRect frame = window.frame;
    return frame.size.width >= 16.0 && frame.size.width <= 180.0 &&
           frame.size.height >= 8.0 && frame.size.height <= 44.0 &&
           CGRectGetMinY(frame) >= 0.0 &&
           CGRectGetMinY(frame) <= CGRectGetMaxY(statusBarFrame) + 20.0;
}

static void LayoutLegacyStatusOverlayWindows(UIWindowScene *scene) {
    CGRect screenBounds = scene.screen.bounds;
    CGRect statusBarFrame = scene.statusBarManager.statusBarFrame;
    if (screenBounds.size.width <= 0.0 ||
        CGRectGetMaxY(statusBarFrame) < 50.0) {
        return;
    }

    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    for (UIWindow *window in scene.windows) {
        if (IsLegacyStatusOverlayWindow(window, statusBarFrame)) {
            [windows addObject:window];
        }
    }
    if (windows.count < 2U || windows.count > 12U) return;
    [windows sortUsingComparator:^NSComparisonResult(UIWindow *left,
                                                       UIWindow *right) {
        CGFloat difference = CGRectGetMinX(left.frame) -
                             CGRectGetMinX(right.frame);
        return difference < 0.0 ? NSOrderedAscending :
               difference > 0.0 ? NSOrderedDescending : NSOrderedSame;
    }];

    CGFloat spacing = 8.0;
    CGFloat contentWidth = 0.0;
    CGFloat rowHeight = 0.0;
    for (UIWindow *window in windows) {
        contentWidth += CGRectGetWidth(window.frame);
        rowHeight = MAX(rowHeight, CGRectGetHeight(window.frame));
    }
    CGFloat availableWidth = CGRectGetWidth(screenBounds) - 16.0;
    CGFloat rowWidth = contentWidth + spacing * (windows.count - 1U);
    if (rowWidth > availableWidth) {
        spacing = 4.0;
        rowWidth = contentWidth + spacing * (windows.count - 1U);
    }
    CGFloat widthScale = rowWidth > availableWidth && contentWidth > 0.0
        ? (availableWidth - spacing * (windows.count - 1U)) / contentWidth
        : 1.0;
    rowWidth = contentWidth * widthScale + spacing * (windows.count - 1U);

    CGFloat screenScale = MAX(1.0, scene.screen.scale);
    CGFloat x = CGRectGetMinX(screenBounds) +
                (CGRectGetWidth(screenBounds) - rowWidth) / 2.0;
    CGFloat y = CGRectGetMaxY(statusBarFrame) + 2.0;
    BOOL changed = NO;
    for (UIWindow *window in windows) {
        CGFloat width = CGRectGetWidth(window.frame) * widthScale;
        CGRect frame = CGRectMake(round(x * screenScale) / screenScale,
                                  round(y * screenScale) / screenScale,
                                  round(width * screenScale) / screenScale,
                                  rowHeight);
        if (!CGRectEqualToRect(window.frame, frame)) {
            window.frame = frame;
            changed = YES;
        }
        x += width + spacing;
    }
    if (changed) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "aligned %lu legacy status overlays below cutout",
                         (unsigned long)windows.count);
    }
}

static void ScheduleLegacyStatusOverlayLayout(void) {
    if (!IsSpringBoardProcess() ||
        atomic_exchange(&LegacyStatusLayoutScheduled, true)) {
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        UIWindowScene *scene = ActiveWindowScene();
        if (scene != nil) LayoutLegacyStatusOverlayWindows(scene);
        atomic_store(&LegacyStatusLayoutScheduled, false);
    });
}

static void RefreshLegacyPreferenceObservers(void) {
    if (LegacyWindowOwnerClasses.count == 0) return;
    NSString *directory = @"/var/jb/Library/PreferenceLoader/Preferences";
    NSArray<NSString *> *files =
        [NSFileManager.defaultManager contentsOfDirectoryAtPath:directory
                                                          error:nil];
    NSMutableSet<NSString *> *domains = [NSMutableSet set];
    for (NSString *file in files) {
        if (![file.pathExtension.lowercaseString isEqualToString:@"plist"]) {
            continue;
        }
        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:
            [directory stringByAppendingPathComponent:file]];
        NSString *bundleName = plist[@"entry"][@"bundle"];
        if (![bundleName isKindOfClass:NSString.class] ||
            bundleName.length == 0) {
            continue;
        }
        NSString *infoPath = [NSString stringWithFormat:
            @"/var/jb/Library/PreferenceBundles/%@.bundle/Info.plist",
            bundleName];
        NSString *identifier =
            [NSDictionary dictionaryWithContentsOfFile:infoPath]
                [@"CFBundleIdentifier"];
        if (![identifier isKindOfClass:NSString.class]) continue;
        NSString *lowercase = identifier.lowercaseString;
        for (NSString *suffix in @[@".settings", @".preferences", @".prefs"]) {
            if (![lowercase hasSuffix:suffix] ||
                identifier.length <= suffix.length) {
                continue;
            }
            [domains addObject:[identifier substringToIndex:
                identifier.length - suffix.length]];
            break;
        }
    }
    for (NSString *domain in domains) {
        NSString *notification = [domain stringByAppendingString:@"/Settings"];
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge CFStringRef)notification, NULL, NULL, true);
    }
    if (domains.count > 0) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "refreshed %lu legacy preference observer(s)",
                         (unsigned long)domains.count);
    }
}

static void ScheduleLegacyPreferenceRefresh(void) {
    if (!IsSpringBoardProcess() ||
        atomic_exchange(&LegacyPreferenceRefreshScheduled, true)) {
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        if (LegacyWindowOwnerClasses.count == 0) {
            atomic_store(&LegacyPreferenceRefreshScheduled, false);
            return;
        }
        RefreshLegacyPreferenceObservers();
    });
}

static void RepairLegacyWindowOwnersWithRetry(NSUInteger attempt) {
    RepairOrphanWindows();
    BOOL ready = RepairLegacyWindowOwners();
    ScheduleLegacyStatusOverlayLayout();
    if (ready || attempt >= 40U) {
        atomic_store(&LegacyWindowRepairScheduled, false);
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC / 2),
                   dispatch_get_main_queue(), ^{
        RepairLegacyWindowOwnersWithRetry(attempt + 1U);
    });
}

static void ScheduleLegacyWindowOwnerRepair(void) {
    if (atomic_exchange(&LegacyWindowRepairScheduled, true)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        RepairLegacyWindowOwnersWithRetry(0);
    });
}

static void RegisterLoadedLegacyWindowOwners(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; ++index) {
        const char *path = _dyld_get_image_name(index);
        if (path != NULL) {
            RegisterLegacyWindowOwnersInImage(
                [NSString stringWithUTF8String:path]);
        }
    }
    InstallKeepEyeDisplayCompatibility();
    ScheduleLegacyWindowOwnerRepair();
    ScheduleLegacyPreferenceRefresh();
}

static void ScheduleLoadedLegacyWindowOwners(void) {
    if (atomic_exchange(&LegacyWindowRegistrationScheduled, true)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        RegisterLoadedLegacyWindowOwners();
        atomic_store(&LegacyWindowRegistrationScheduled, false);
    });
}

static void InstallWindowHooks(void) {
    Method hidden = class_getInstanceMethod(UIWindow.class,
                                            @selector(setHidden:));
    Method visible = class_getInstanceMethod(UIWindow.class,
                                             @selector(makeKeyAndVisible));
    if (hidden == NULL || visible == NULL) return;
    OriginalWindowSetHidden = (WindowHiddenImplementation)
        method_setImplementation(hidden, (IMP)CompatWindowSetHidden);
    OriginalWindowMakeKeyAndVisible = (WindowVisibleImplementation)
        method_setImplementation(visible, (IMP)CompatWindowMakeKeyAndVisible);
}

static id CompatRootFolderController(id iconController,
                                     __unused SEL selector) {
    SEL managerSelector = sel_registerName("iconManager");
    SEL rootSelector = sel_registerName("rootFolderController");
    if ([iconController respondsToSelector:managerSelector]) {
        id manager = ((id (*)(id, SEL))objc_msgSend)(iconController,
                                                     managerSelector);
        if ([manager respondsToSelector:rootSelector]) {
            return ((id (*)(id, SEL))objc_msgSend)(manager, rootSelector);
        }
    }
    SEL currentSelector = sel_registerName("_currentFolderController");
    if ([iconController respondsToSelector:currentSelector]) {
        return ((id (*)(id, SEL))objc_msgSend)(iconController,
                                               currentSelector);
    }
    return nil;
}

static id CompatVirtualIconApplication(__unused id icon,
                                       __unused SEL selector) {
    return nil;
}

static void InstallSpringBoardFolderHooks(void) {
    if (!IsSpringBoardProcess()) return;
    Class iconControllerClass = objc_getClass("SBIconController");
    SEL legacySelector = sel_registerName("_rootFolderController");
    if (iconControllerClass != Nil &&
        class_getInstanceMethod(iconControllerClass, legacySelector) == NULL &&
        class_addMethod(iconControllerClass, legacySelector,
                        (IMP)CompatRootFolderController, "@16@0:8")) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "installed root folder controller bridge");
    }

    Class iconClass = objc_getClass("SBIcon");
    SEL applicationSelector = sel_registerName("application");
    if (iconClass != Nil &&
        class_getInstanceMethod(iconClass, applicationSelector) == NULL &&
        class_addMethod(iconClass, applicationSelector,
                        (IMP)CompatVirtualIconApplication, "@16@0:8")) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "installed base icon application bridge");
    }
}

static id CompatDatabaseInitializer(id database, __unused SEL selector,
                                    id storeDescription,
                                    __unused BOOL runMigrations,
                                    __unused BOOL useLockFile,
                                    NSError **error) {
    SEL urlSelector = sel_registerName("URL");
    SEL currentSelector = sel_registerName(
        "initWithPersistenceMode:fileURL:error:");
    if (storeDescription == nil) return nil;
    id fileURL = ((id (*)(id, SEL))objc_msgSend)(storeDescription,
                                                 urlSelector);
    if (fileURL == nil) return nil;
    return ((id (*)(id, SEL, NSUInteger, id, NSError **))objc_msgSend)(
        database, currentSelector, 0, fileURL, error);
}

static id CompatDatabaseInitializerWithoutLock(
    id database, SEL selector, id storeDescription, BOOL runMigrations,
    NSError **error) {
    return CompatDatabaseInitializer(database, selector, storeDescription,
                                     runMigrations, YES, error);
}

static float CompatCurrentVolume(id viewController,
                                __unused SEL selector) {
    SEL currentValueSelector = sel_registerName("currentValue");
    if (![viewController respondsToSelector:currentValueSelector]) return 0.0f;
    return ((float (*)(id, SEL))objc_msgSend)(viewController,
                                            currentValueSelector);
}

static BOOL CompatResolveInstanceMethod(id cls, SEL selector,
                                        SEL missingSelector) {
    static const char initializerWithLock[] =
        "initWithStoreDescription:runMigrationsIfNecessary:"
        "useLockFile:error:";
    static const char initializerWithoutLock[] =
        "initWithStoreDescription:runMigrationsIfNecessary:error:";
    const char *className = class_getName(cls);
    const char *methodName = sel_getName(missingSelector);
    IMP implementation = NULL;
    const char *types = NULL;
    if (className != NULL && methodName != NULL &&
        strcmp(className, "WFDatabase") == 0) {
        if (strcmp(methodName, initializerWithLock) == 0) {
            implementation = (IMP)CompatDatabaseInitializer;
            types = "@40@0:8@16B24B28^@32";
        } else if (strcmp(methodName, initializerWithoutLock) == 0) {
            implementation = (IMP)CompatDatabaseInitializerWithoutLock;
            types = "@40@0:8@16B24^@32";
        }
    } else if (className != NULL && methodName != NULL &&
        strcmp(className, "SBElasticVolumeViewController") == 0 &&
        strcmp(methodName, "currentVolume") == 0) {
        implementation = (IMP)CompatCurrentVolume;
        types = "f16@0:8";
    } else if (className != NULL && methodName != NULL &&
        strcmp(className, "CSQuickActionsView") == 0) {
        if (strcmp(methodName, "flashlightButton") == 0) {
            implementation = (IMP)CompatFlashlightButton;
        } else if (strcmp(methodName, "cameraButton") == 0) {
            implementation = (IMP)CompatCameraButton;
        }
        types = "@16@0:8";
    }
    if (implementation != NULL &&
        class_addMethod(cls, missingSelector, implementation, types)) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "resolved legacy method -[%{public}s %{public}s]",
                         className, methodName);
        return YES;
    }
    return OriginalResolveInstanceMethod != NULL
        ? OriginalResolveInstanceMethod(cls, selector, missingSelector) : NO;
}

static void InstallLegacyMethodResolver(void) {
    if (OriginalResolveInstanceMethod != NULL) return;
    Method resolver = class_getClassMethod(
        NSObject.class, @selector(resolveInstanceMethod:));
    if (resolver == NULL ||
        method_getImplementation(resolver) ==
            (IMP)CompatResolveInstanceMethod) {
        return;
    }
    OriginalResolveInstanceMethod = (ResolveInstanceMethodImplementation)
        method_setImplementation(resolver,
                                 (IMP)CompatResolveInstanceMethod);
}

static BOOL IsSubclassOfClass(Class candidate, Class parent) {
    for (Class cursor = candidate; cursor != Nil;
         cursor = class_getSuperclass(cursor)) {
        if (cursor == parent) return YES;
    }
    return NO;
}

static BOOL IsThirdPartyPreferenceClass(Class cls) {
    const char *image = cls == Nil ? NULL : class_getImageName(cls);
    return image != NULL && strstr(image, "/PreferenceBundles/") != NULL;
}

static Method DirectInstanceMethod(Class cls, SEL selector) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method result = NULL;
    for (unsigned int index = 0; index < count; ++index) {
        if (method_getName(methods[index]) == selector) {
            result = methods[index];
            break;
        }
    }
    free(methods);
    return result;
}

static id CompatApplicationShortcutItems(id iconView, SEL selector) {
    id items = OriginalApplicationShortcutItems != NULL
        ? OriginalApplicationShortcutItems(iconView, selector) : nil;
    if (items != nil) return items;
    SEL fetchedSelector = sel_registerName("fetchedApplicationShortcutItems");
    if ([iconView respondsToSelector:fetchedSelector]) {
        items = ((id (*)(id, SEL))objc_msgSend)(iconView, fetchedSelector);
    }
    return items != nil ? items : @[];
}

static void CompatActivateApplicationShortcut(id providerClass, SEL selector,
                                               id shortcut,
                                               id bundleIdentifier,
                                               id iconView) {
    Class legacyClass = objc_getClass("SBIconView");
    if (legacyClass != Nil && [legacyClass respondsToSelector:selector]) {
        ((ApplicationShortcutActivationImplementation)objc_msgSend)(
            legacyClass, selector, shortcut, bundleIdentifier, iconView);
        return;
    }
    if (OriginalApplicationShortcutActivation != NULL) {
        OriginalApplicationShortcutActivation(
            providerClass, selector, shortcut, bundleIdentifier, iconView);
    }
}

static void InstallSpringBoardShortcutHooks(void) {
    if (!IsSpringBoardProcess()) return;

    Class iconViewClass = objc_getClass("SBIconView");
    if (iconViewClass == Nil) return;
    SEL itemsSelector = sel_registerName("applicationShortcutItems");
    if (OriginalApplicationShortcutItems == NULL) {
        Method itemsMethod = DirectInstanceMethod(iconViewClass,
                                                  itemsSelector);
        if (itemsMethod != NULL) {
            OriginalApplicationShortcutItems = (ObjectGetterImplementation)
                method_setImplementation(
                    itemsMethod, (IMP)CompatApplicationShortcutItems);
            os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                             "installed application shortcut item bridge");
        }
    }

    if (OriginalApplicationShortcutActivation != NULL) return;
    Class providerClass = objc_getClass(
        "SBHIconViewApplicationShortcutsContextMenuProvider");
    if (providerClass == Nil) return;
    SEL activationSelector = sel_registerName(
        "activateShortcut:withBundleIdentifier:forIconView:");
    Class providerMetaClass = object_getClass(providerClass);
    Method providerMethod = DirectInstanceMethod(providerMetaClass,
                                                 activationSelector);
    if (providerMethod == NULL) return;

    Class iconViewMetaClass = object_getClass(iconViewClass);
    Method legacyMethod = class_getInstanceMethod(iconViewMetaClass,
                                                  activationSelector);
    if (legacyMethod == NULL &&
        !class_addMethod(iconViewMetaClass, activationSelector,
                         method_getImplementation(providerMethod),
                         method_getTypeEncoding(providerMethod))) {
        return;
    }
    OriginalApplicationShortcutActivation =
        (ApplicationShortcutActivationImplementation)method_setImplementation(
            providerMethod, (IMP)CompatActivateApplicationShortcut);
    os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                     "installed application shortcut action bridge");
}

static id CompatQuickActionsButton(id view, BOOL trailing) {
    SEL buttonsSelector = sel_registerName("buttons");
    if (![view respondsToSelector:buttonsSelector]) return nil;
    id buttons = ((id (*)(id, SEL))objc_msgSend)(view, buttonsSelector);
    SEL buttonSelector = trailing ? @selector(lastObject) :
                                    @selector(firstObject);
    if (![buttons respondsToSelector:buttonSelector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(buttons, buttonSelector);
}

static id CompatFlashlightButton(id view, __unused SEL selector) {
    return CompatQuickActionsButton(view, NO);
}

static id CompatCameraButton(id view, __unused SEL selector) {
    return CompatQuickActionsButton(view, YES);
}

static void InstallSpringBoardQuickActionsHooks(void) {
    if (!IsSpringBoardProcess()) return;
    Class viewClass = objc_getClass("CSQuickActionsView");
    if (viewClass == Nil) return;

    SEL flashlightSelector = sel_registerName("flashlightButton");
    SEL cameraSelector = sel_registerName("cameraButton");
    BOOL installed = NO;
    if (class_getInstanceMethod(viewClass, flashlightSelector) == NULL) {
        installed |= class_addMethod(viewClass, flashlightSelector,
                                     (IMP)CompatFlashlightButton,
                                     "@16@0:8");
    }
    if (class_getInstanceMethod(viewClass, cameraSelector) == NULL) {
        installed |= class_addMethod(viewClass, cameraSelector,
                                     (IMP)CompatCameraButton,
                                     "@16@0:8");
    }
    if (installed) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "installed lock screen quick action bridge");
    }
}

static void ScheduleSpringBoardQuickActionsHooks(void) {
    if (atomic_exchange(&QuickActionsInstallScheduled, true)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        atomic_store(&QuickActionsInstallScheduled, false);
        InstallSpringBoardQuickActionsHooks();
    });
}

static void CompatObjectiveCImageDidLoad(
    __unused const struct mach_header *header) {
    ScheduleSpringBoardQuickActionsHooks();
    ScheduleLoadedLegacyWindowOwners();
}

static IMP OriginalImplementation(NSDictionary<NSString *, NSValue *> *table,
                                  Class cls) {
    @synchronized (table) {
        for (Class cursor = cls; cursor != Nil;
             cursor = class_getSuperclass(cursor)) {
            NSValue *value = table[NSStringFromClass(cursor)];
            if (value != nil) return (IMP)value.pointerValue;
        }
    }
    return NULL;
}

static id SpecifierProperty(id owner, NSString *key) {
    if (owner == nil || ![owner respondsToSelector:@selector(propertyForKey:)]) {
        return nil;
    }
    @try {
        return [owner propertyForKey:key];
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static id SpecifierAtIndexPath(id controller, NSIndexPath *indexPath) {
    if (![controller respondsToSelector:@selector(specifierAtIndexPath:)]) {
        return nil;
    }
    @try {
        return [controller specifierAtIndexPath:indexPath];
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static CGFloat CompatRowHeight(id controller, SEL selector,
                               UITableView *tableView,
                               NSIndexPath *indexPath) {
    RowHeightImplementation original = (RowHeightImplementation)
        OriginalImplementation(HeightImplementations,
                               (Class)[controller class]);
    CGFloat result = original != NULL
        ? original(controller, selector, tableView, indexPath)
        : UITableViewAutomaticDimension;
    id specifier = SpecifierAtIndexPath(controller, indexPath);
    id explicitHeight = SpecifierProperty(specifier, @"height");
    if ([explicitHeight respondsToSelector:@selector(doubleValue)]) {
        CGFloat value = [explicitHeight doubleValue];
        if (value >= 20.0 && value <= 512.0) return value;
    }
    id subtitle = SpecifierProperty(specifier, @"cellSubtitleText");
    if ([subtitle isKindOfClass:NSString.class] && [subtitle length] > 0) {
        return result > 0.0 ? MAX(result, 68.0) : 68.0;
    }
    return result;
}

static void ApplyLegacySubtitle(UITableViewCell *cell) {
    id specifier = [cell respondsToSelector:@selector(specifier)]
        ? [cell specifier] : nil;
    NSString *text = SpecifierProperty(specifier, @"cellSubtitleText");
    UILabel *subtitle = objc_getAssociatedObject(cell, &SubtitleLabelKey);
    if (![text isKindOfClass:NSString.class] || text.length == 0 ||
        [SpecifierProperty(specifier, @"SBInjectDisableLegacySubtitle")
            boolValue]) {
        subtitle.hidden = YES;
        return;
    }
    UILabel *title = cell.textLabel;
    if (title == nil) return;
    cell.detailTextLabel.hidden = YES;
    if (subtitle == nil) {
        subtitle = [[UILabel alloc] initWithFrame:CGRectZero];
        subtitle.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
        subtitle.textColor = UIColor.secondaryLabelColor;
        subtitle.numberOfLines = 2;
        subtitle.adjustsFontForContentSizeCategory = YES;
        [cell.contentView addSubview:subtitle];
        objc_setAssociatedObject(cell, &SubtitleLabelKey, subtitle,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    subtitle.hidden = NO;
    subtitle.text = text;
    subtitle.lineBreakMode = NSLineBreakByTruncatingTail;
    CGRect content = cell.contentView.bounds;
    CGRect titleFrame = title.frame;
    titleFrame.origin.y = 7.0;
    titleFrame.size.height = MIN(24.0, MAX(18.0, CGRectGetHeight(content) - 30.0));
    title.frame = titleFrame;
    CGFloat rightInset = cell.accessoryView == nil
        ? 16.0 : CGRectGetWidth(cell.accessoryView.bounds) + 24.0;
    CGFloat subtitleY = CGRectGetMaxY(titleFrame);
    subtitle.frame = CGRectMake(
        titleFrame.origin.x, subtitleY,
        MAX(0.0, CGRectGetWidth(content) - titleFrame.origin.x - rightInset),
        MAX(18.0, CGRectGetHeight(content) - subtitleY - 5.0));
}

static void CompatCellLayout(UITableViewCell *cell, SEL selector) {
    CellLayoutImplementation original = (CellLayoutImplementation)
        OriginalImplementation(LayoutImplementations, cell.class);
    if (original != NULL) original(cell, selector);
    ApplyLegacySubtitle(cell);
}

static BOOL InstallMethodHook(Class cls, SEL selector, IMP replacement,
                              NSMutableDictionary<NSString *, NSValue *> *table) {
    NSString *key = NSStringFromClass(cls);
    @synchronized (table) {
        if (table[key] != nil) return NO;
        Method inherited = class_getInstanceMethod(cls, selector);
        if (inherited == NULL) return NO;
        IMP original = method_getImplementation(inherited);
        if (original == replacement) return NO;
        IMP replaced = class_replaceMethod(cls, selector, replacement,
                                            method_getTypeEncoding(inherited));
        if (replaced != NULL) original = replaced;
        table[key] = [NSValue valueWithPointer:original];
        return YES;
    }
}

static void InstallPreferenceHooks(void) {
    if (!IsPreferencesProcess()) return;
    Class listController = objc_getClass("PSListController");
    Class tableCell = objc_getClass("PSTableCell");
    if (listController == Nil || tableCell == Nil) return;
    int count = objc_getClassList(NULL, 0);
    if (count <= 0 || count > 100000) return;
    int capacity = count;
    Class __unsafe_unretained *classes =
        (Class __unsafe_unretained *)calloc((size_t)capacity, sizeof(Class));
    if (classes == NULL) return;
    count = objc_getClassList(classes, capacity);
    if (count > capacity) count = capacity;
    NSUInteger installed = 0;
    for (int index = 0; index < count; ++index) {
        Class cls = classes[index];
        if (!IsThirdPartyPreferenceClass(cls)) continue;
        if (IsSubclassOfClass(cls, listController)) {
            installed += InstallMethodHook(
                cls, @selector(tableView:heightForRowAtIndexPath:),
                (IMP)CompatRowHeight, HeightImplementations);
        }
        if (IsSubclassOfClass(cls, tableCell)) {
            installed += InstallMethodHook(cls, @selector(layoutSubviews),
                                           (IMP)CompatCellLayout,
                                           LayoutImplementations);
        }
    }
    free(classes);
    if (installed > 0) {
        os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                         "installed %lu preference compatibility hooks",
                         (unsigned long)installed);
    }
}

bool codex_legacy_tweak_compat_apply(void) {
    if (!RunningOnIOS27() ||
        access(CODEX_LEGACY_COMPAT_DISABLE_MARKER, F_OK) == 0) {
        return false;
    }
    ApplyConfiguredAliases();
    InstallLegacyMethodResolver();
    InstallSpringBoardFolderHooks();
    InstallSpringBoardShortcutHooks();
    InstallSpringBoardQuickActionsHooks();
    ScheduleLegacyWindowOwnerRepair();
    if (NSThread.isMainThread) {
        InstallPreferenceHooks();
        RepairOrphanWindows();
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            InstallPreferenceHooks();
            RepairOrphanWindows();
        });
    }
    return true;
}

__attribute__((constructor))
static void InitializeLegacyTweakCompatibility(void) {
    if (!RunningOnIOS27() ||
        access(CODEX_LEGACY_COMPAT_DISABLE_MARKER, F_OK) == 0) {
        return;
    }
    RepairManagedProcessIdentity();
    HeightImplementations = [NSMutableDictionary dictionary];
    LayoutImplementations = [NSMutableDictionary dictionary];
    OrphanWindows = [NSHashTable weakObjectsHashTable];
    LegacyWindowOwnerClasses = [NSMutableArray array];
    LegacyWindowOwnerNames = [NSMutableSet set];
    NoninteractiveWindowOwnerNames = [NSMutableSet set];
    WindowOwnerFrameImplementations = [NSMutableDictionary dictionary];
    OriginalSystem = (SystemImplementation)dlsym(RTLD_DEFAULT, "system");
    InstallWindowHooks();
    ApplyConfiguredAliases();
    InstallLegacyMethodResolver();
    InstallSpringBoardFolderHooks();
    InstallSpringBoardShortcutHooks();
    InstallSpringBoardQuickActionsHooks();
    if (IsSpringBoardProcess()) {
        objc_addLoadImageFunc(CompatObjectiveCImageDidLoad);
    }
    InstallPathHooks();
    [NSNotificationCenter.defaultCenter
        addObserverForName:NSBundleDidLoadNotification
                    object:nil
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(__unused NSNotification *notification) {
        ApplyConfiguredAliases();
        InstallSpringBoardFolderHooks();
        InstallSpringBoardShortcutHooks();
        InstallSpringBoardQuickActionsHooks();
        InstallPreferenceHooks();
        ScheduleLoadedLegacyWindowOwners();
    }];
    [NSNotificationCenter.defaultCenter
        addObserverForName:UISceneDidActivateNotification
                    object:nil
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(__unused NSNotification *notification) {
        ScheduleLegacyWindowOwnerRepair();
    }];
    dispatch_async(dispatch_get_main_queue(), ^{
        InstallSpringBoardFolderHooks();
        InstallSpringBoardQuickActionsHooks();
        InstallPreferenceHooks();
        ScheduleLoadedLegacyWindowOwners();
    });
    os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                     "iOS 27 legacy tweak compatibility ready");
}
