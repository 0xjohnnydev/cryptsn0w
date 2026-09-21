#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach-o/dyld.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <os/log.h>

#include "sileo_root_broker_protocol.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <notify.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xpc/xpc.h>

extern char **environ;
extern char *sandbox_extension_issue_file(const char *extension_class,
                                          const char *path, uint32_t flags);
extern char *sandbox_extension_issue_file_to_process_by_pid(
    const char *extension_class, const char *path, uint32_t flags, pid_t pid);
extern char *sandbox_extension_issue_mach(const char *extension_class,
                                          const char *name, uint32_t flags);
extern const uint32_t SANDBOX_EXTENSION_CANONICAL;
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern int proc_listallpids(void *buffer, int buffer_size);
extern kern_return_t bootstrap_look_up(mach_port_t bootstrap_port,
                                       const char *service_name,
                                       mach_port_t *service_port);
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags,
                                void *buffer, size_t buffersize);

#define CODEX_PROC_PIDPATH_MAX 4096
#define CODEX_MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK 5
#define CODEX_MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES 7
#define CODEX_MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES 8
#define CODEX_BOOTSTRAP_MEMORY_LIMIT_MB 64

typedef struct codex_memorystatus_memlimit_properties {
    int32_t memlimit_active;
    uint32_t memlimit_active_attr;
    int32_t memlimit_inactive;
    uint32_t memlimit_inactive_attr;
} codex_memorystatus_memlimit_properties_t;

typedef struct codex_jetsam_adjustment {
    int initial_status;
    int initial_errno;
    codex_memorystatus_memlimit_properties_t initial;
    int set_status;
    int set_errno;
    int fallback_status;
    int fallback_errno;
    int effective_status;
    int effective_errno;
    codex_memorystatus_memlimit_properties_t effective;
} codex_jetsam_adjustment_t;

static codex_jetsam_adjustment_t adjust_self_jetsam_limit(void) {
    codex_jetsam_adjustment_t result = {0};
    pid_t self = getpid();

    errno = 0;
    result.initial_status = memorystatus_control(
        CODEX_MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, self, 0,
        &result.initial, sizeof(result.initial));
    result.initial_errno = errno;

    codex_memorystatus_memlimit_properties_t requested = {
        .memlimit_active = CODEX_BOOTSTRAP_MEMORY_LIMIT_MB,
        .memlimit_active_attr = 0,
        .memlimit_inactive = CODEX_BOOTSTRAP_MEMORY_LIMIT_MB,
        .memlimit_inactive_attr = 0,
    };
    errno = 0;
    result.set_status = memorystatus_control(
        CODEX_MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, self, 0, &requested,
        sizeof(requested));
    result.set_errno = errno;

    result.fallback_status = 0;
    result.fallback_errno = 0;
    if (result.set_status != 0) {
        errno = 0;
        result.fallback_status = memorystatus_control(
            CODEX_MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, self,
            CODEX_BOOTSTRAP_MEMORY_LIMIT_MB, NULL, 0);
        result.fallback_errno = errno;
    }

    errno = 0;
    result.effective_status = memorystatus_control(
        CODEX_MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, self, 0,
        &result.effective, sizeof(result.effective));
    result.effective_errno = errno;
    return result;
}

static const char *const kLogPath =
    "/var/tmp/codex-dopamine-cryptex-bootstrap.log";
static const char *const kDonePath =
    "/var/tmp/codex-dopamine-cryptex-bootstrap.done";
static const char *const kFailurePath =
    "/var/tmp/codex-dopamine-cryptex-bootstrap.failed";
static const char *const kVarJb = "/var/jb";
static NSString *const kInstallerIdentifier =
    @"com.openai.codex.dopamine.bootstrap";
#ifndef CODEX_SILEO_BUNDLE_IDENTIFIER
#define CODEX_SILEO_BUNDLE_IDENTIFIER @"org.coolstar.SileoStore"
#endif
static NSString *const kSileoIdentifier = CODEX_SILEO_BUNDLE_IDENTIFIER;
static NSString *const kSileoPackageVersion = @"2.5.1+codex1";
static NSString *const kSystemSileoDataRoot = @"/var/mobile";
static NSString *const kBundleContainerRoot =
    @"/var/containers/Bundle/Application";
static NSString *const kSystemSileoBundlePath =
    @"/var/containers/Bundle/Application/"
     "D7A9C65A-1FD8-4D9C-AC8D-4E8E5143A191/Sileo.app";
static NSString *const kTrollStoreLiteIdentifier =
    @"com.opa334.TrollStoreLite";
static NSString *const kManagedApplicationMarker =
    @"_SBInjectManagedApp.plist";
static NSString *const kTrollStoreLiteMarker = @"_TrollStoreLite";
static NSString *const kRootBrokerLabel =
    @"com.openai.codex.dopamine.sileo-root-broker";
static NSString *const kRootBrokerExecutable =
    @"/var/jb/usr/libexec/codex-sileo-root-broker";
static NSString *const kRootBrokerPlist =
    @"/var/jb/Library/LaunchDaemons/com.openai.codex.dopamine."
     "sileo-root-broker.plist";
static NSString *const kRootlessUicache = @"/var/jb/usr/bin/uicache";
static NSString *const kExecWorkerExecutable =
    @"/var/jb/usr/libexec/codex-exec-worker";
static NSString *const kOpenSSHLabel = @"com.openssh.sshd";
static NSString *const kOpenSSHExecutable = @"/var/jb/usr/sbin/sshd";
static NSString *const kOpenSSHKeygen = @"/var/jb/usr/bin/ssh-keygen";
static NSString *const kOpenSSHKeygenWrapper =
    @"/var/jb/usr/libexec/sshd-keygen-wrapper";
static NSString *const kOpenSSHConfig = @"/var/jb/etc/ssh/sshd_config";
static NSString *const kOpenSSHPlist =
    @"/var/jb/Library/LaunchDaemons/com.openssh.sshd.plist";
static NSString *const kSBInjectPackageValidatorExecutable =
    @"/var/jb/usr/libexec/sbinject-package-validator";
static NSString *const kSBInjectJitterdLabel =
    @"com.openai.codex.sbinject.jitterd";
static NSString *const kSBInjectJitterdExecutable =
    @"/var/jb/usr/libexec/sbinject-jitterd";
static NSString *const kSBInjectJitterdPlist =
    @"/var/jb/Library/LaunchDaemons/"
     "com.openai.codex.sbinject.jitterd.plist";
static NSString *const kSBInjectGeneralHook =
    @"/var/jb/usr/lib/sbinject/generalhook.dylib";
static NSString *const kSBInjectAmfidHook =
    @"/var/jb/usr/libexec/sbinject/a";
static NSString *const kSBInjectPreferencesBridge =
    @"/var/jb/usr/lib/sbinject/preferences-bridge.dylib";
static NSString *const kSBInjectLaunchdHook =
    @"/var/jb/usr/lib/sbinject/launchdhook-v12.dylib";
static NSString *const kSBInjectLsdRegistrationHook =
    @"/var/jb/usr/lib/sbinject/lsd-registration-hook.dylib";
static NSString *const kSBInjectLsdRegistrationMarker =
    @"/var/mobile/.sbinject-lsd-registration-ready";
static NSString *const kSBInjectBundle =
    @"/var/jb/System/Library/CoreServices/SpringBoard.app";
static NSString *const kSBInjectBundleHook =
    @"/var/jb/System/Library/CoreServices/SpringBoard.app/g";
static NSString *const kSBInjectPreferencesBundle =
    @"/var/jb/Applications/Preferences.app";
static NSString *const kSBInjectPreferencesBundleHook =
    @"/var/jb/Applications/Preferences.app/g";
static NSString *const kSBInjectEnableMarker =
    @"/var/jb/var/lib/sbinject/enabled";
static NSString *const kSBInjectCrashMarker =
    @"/var/jb/var/lib/sbinject/disabled-crash-loop";
static NSString *const kSBInjectSafeModeMarker =
    @"/var/mobile/.sbinject-safe-mode";
static NSString *const kElleKitSafeModeMarker = @"/var/mobile/.eksafemode";
static NSString *const kSBInjectPreferencesEnableMarker =
    @"/var/jb/var/lib/sbinject/preferences-enabled";
static NSString *const kSBInjectPreferencesCrashMarker =
    @"/var/jb/var/lib/sbinject/preferences-disabled-crash-loop";
static NSString *const kSBInjectPreferencesRestartMarker =
    @"/var/jb/var/lib/sbinject/preferences-restart-required";
static NSString *const kSBInjectAmfidEnableMarker =
    @"/var/jb/var/lib/sbinject/amfid-injection-enabled";
static NSString *const kSBInjectAmfidCrashMarker =
    @"/var/jb/var/lib/sbinject/amfid-injection-disabled-crash-loop";
static NSString *const kSBInjectAmfidReadyMarker =
    @"/var/jb/var/lib/sbinject/amfid-hook-ready";
static NSString *const kSBInjectAmfidFailureMarker =
    @"/var/jb/var/lib/sbinject/amfid-hook-failure";
static NSString *const kSBInjectLaunchdReadyMarker =
    @"/var/jb/var/lib/sbinject/launchd-hook-ready";
static NSString *const kSBInjectLaunchdUpgradeMarker =
    @"/var/jb/var/lib/sbinject/launchd-hook-upgrade-required";
static NSString *const kSBInjectRespringMarker =
    @"/var/jb/var/lib/sbinject/respring-required";
static NSString *const kSpringBoardCandidateExecutable =
    @"/var/jb/System/Library/CoreServices/"
     "SpringBoard.app/notSpringBoard";
static NSString *const kPreferencesCandidateExecutable =
    @"/var/jb/Applications/Preferences.app/notPreferences";
static NSString *const kAmfidCandidateExecutable =
    @"/var/jb/usr/libexec/sbinject/notamfid";
static NSString *const kStockAmfidExecutable = @"/usr/libexec/amfid";
static NSString *const kHeadlessSileoExecutable =
    @"/var/jb/Applications/Sileo.app/Sileo";
static NSString *const kElleKitInjectorExecutable =
    @"/var/jb/usr/libexec/codex-ellekit-loader";
static NSString *const kElleKitInjectorDylib =
    @"/var/jb/usr/lib/ellekit/libinjector.dylib";

#define CODEX_SBINJECT_JITTERD_SERVICE \
    "com.openai.codex.sbinject.jitterd.systemwide"
@interface NSObject (CodexLaunchServices)
+ (id)applicationProxyForIdentifier:(NSString *)identifier;
+ (id)defaultWorkspace;
+ (id)containerWithIdentifier:(NSString *)identifier
             createIfNecessary:(BOOL)create
                       existed:(BOOL *)existed
                         error:(NSError **)error;
- (BOOL)registerApplicationDictionary:(NSDictionary *)dictionary;
- (BOOL)unregisterApplication:(NSURL *)url;
- (id)registerContainerizedApplicationWithInfoDictionaries:(NSArray *)infos
                                              operationUUID:(NSUUID *)uuid
                                             requestContext:(id)context
                                               saveObserver:(id)observer
                                          registrationError:(NSError **)error;
- (NSURL *)bundleURL;
- (NSURL *)url;
- (NSString *)applicationType;
@end

static int gLog = STDERR_FILENO;
static os_log_t gUnifiedLog;

static void log_message(const char *format, ...);
static int run_and_wait(const char *executable, char *const arguments[]);
static int run_and_wait_bounded_to_fd(const char *executable,
                                      char *const arguments[],
                                      unsigned int timeoutMilliseconds,
                                      int outputDescriptor);
static int run_and_wait_bounded(const char *executable,
                                char *const arguments[],
                                unsigned int timeoutMilliseconds);
static bool is_exact_springboard_candidate_process(pid_t pid,
                                                    const char *path);
static bool is_exact_preferences_candidate_process(pid_t pid,
                                                    const char *path);
static bool is_exact_amfid_candidate_process(pid_t pid, const char *path);
static bool sbinject_managed_file(NSString *path, mode_t mode);
static bool exact_empty_root_marker(NSString *path);
static bool prepare_sbinject_redirect(const char *reason);
static bool activate_sbinject_springboard(void);
static bool activate_sbinject_preferences(void);
static bool activate_sbinject_amfid(void);
static bool respring_sbinject_springboard(const char *reason);
static bool prepare_lsd_registration_hook(const char *reason);
static bool executable_paths_match(NSString *expected, NSString *actual);
static NSString *registered_application_path(NSString *identifier);
static NSArray<NSString *> *validated_bundle_entries(NSString *root,
                                                      bool requireManaged);
static bool normalize_bundle_tree(NSString *source, NSString *destination);
static bool bundle_trees_are_equal(NSString *source, NSString *destination);
static bool register_managed_rootless_application(NSString *source,
                                                   NSString **targetPath,
                                                   NSString **errorText);
static bool cleanup_stale_managed_applications(NSSet<NSString *> *active,
                                                NSString **errorText);

static bool refresh_rootless_application_registrations(const char *reason) {
    if (!prepare_lsd_registration_hook(reason)) {
        log_message("sbinjectApplicationRegistration=false reason=%s "
                    "phase=lsd-hook",
                    reason);
        return false;
    }
    NSString *applications = @"/var/jb/Applications";
    NSArray<NSString *> *entries = [[[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:applications error:nil]
        sortedArrayUsingSelector:@selector(compare:)];
    bool registered = true;
    NSUInteger submitted = 0;
    NSMutableArray<NSDictionary *> *bundles = [NSMutableArray array];
    NSMutableSet<NSString *> *activeIdentifiers = [NSMutableSet set];
    for (NSString *entry in entries) {
        if ([[entry pathExtension] caseInsensitiveCompare:@"app"] !=
            NSOrderedSame) {
            continue;
        }
        NSString *path = [applications stringByAppendingPathComponent:entry];
        struct stat status = {0};
        if (lstat([path fileSystemRepresentation], &status) != 0 ||
            !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode) ||
            status.st_uid != 0 || (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            registered = false;
            log_message("sbinjectApplicationRegistration=false reason=%s "
                        "phase=bundle-validation path=%s",
                        reason, [path UTF8String]);
            continue;
        }
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
            [path stringByAppendingPathComponent:@"Info.plist"]];
        NSString *identifier = info[@"CFBundleIdentifier"];
        if (![identifier isKindOfClass:NSString.class] ||
            identifier.length == 0) {
            registered = false;
            log_message("sbinjectApplicationRegistration=false reason=%s "
                        "phase=bundle-identifier path=%s",
                        reason, [path UTF8String]);
            continue;
        }
        if (++submitted > 128U) {
            registered = false;
            break;
        }
        if ([identifier isEqualToString:@"com.apple.Preferences"]) {
            log_message("sbinjectApplicationRegistration=skipped reason=%s "
                        "scope=redirect-managed identifier=%s path=%s",
                        reason, [identifier UTF8String], [path UTF8String]);
            continue;
        }
        [activeIdentifiers addObject:identifier];
        NSString *verificationPath = nil;
        NSString *directError = nil;
        bool directReady = register_managed_rootless_application(
            path, &verificationPath, &directError);
        log_message("sbinjectEmbeddedApplicationRegistration=%s "
                    "reason=%s identifier=%s source=%s target=%s error=%s",
                    directReady ? "true" : "false", reason,
                    [identifier UTF8String], [path UTF8String],
                    verificationPath != nil
                        ? [verificationPath UTF8String] : "none",
                    directError != nil
                        ? [[directError description] UTF8String] : "none");
        [bundles addObject:@{
            @"path" : verificationPath ?: path,
            @"identifier" : identifier,
            @"directReady" : @(directReady),
        }];
    }
    NSString *cleanupError = nil;
    bool cleanupReady = cleanup_stale_managed_applications(
        activeIdentifiers, &cleanupError);
    registered &= cleanupReady;
    if (!cleanupReady) {
        log_message("sbinjectApplicationCleanup=false reason=%s error=%s",
                    reason,
                    cleanupError != nil
                        ? [[cleanupError description] UTF8String] : "unknown");
    }
    for (NSDictionary *bundle in bundles) {
        NSString *path = bundle[@"path"];
        NSString *identifier = bundle[@"identifier"];
        bool directReady = [bundle[@"directReady"] boolValue];
        NSString *observedPath = nil;
        bool verified = false;
        for (NSUInteger attempt = 0; attempt < 200; ++attempt) {
            observedPath = registered_application_path(identifier);
            if (executable_paths_match(path, observedPath)) {
                verified = true;
                break;
            }
            usleep(10 * 1000);
        }
        bool pathReady = directReady && verified;
        registered &= pathReady;
        log_message("sbinjectApplicationPathRegistration=%s reason=%s "
                    "identifier=%s path=%s observed=%s",
                    pathReady ? "true" : "false", reason,
                    [identifier UTF8String], [path UTF8String],
                    observedPath != nil ? [observedPath UTF8String] : "none");
    }
    bool ready = registered;
    log_message("sbinjectApplicationRegistration=%s reason=%s bundles=%lu "
                "cleanup=%s",
                ready ? "true" : "false", reason,
                (unsigned long)submitted, cleanupReady ? "true" : "false");
    return ready;
}

static void log_message(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    char *message = NULL;
    int length = vasprintf(&message, format, arguments);
    va_end(arguments);
    if (length < 0 || message == NULL) {
        return;
    }
    dprintf(gLog, "%s\n", message);
    fsync(gLog);
    if (gUnifiedLog != NULL) {
        os_log_with_type(gUnifiedLog, OS_LOG_TYPE_DEFAULT, "%{public}s",
                         message);
    }
    free(message);
}

static bool write_marker(const char *path, NSString *value) {
    NSError *error = nil;
    BOOL wrote = [value writeToFile:[NSString stringWithUTF8String:path]
                         atomically:YES
                           encoding:NSUTF8StringEncoding
                              error:&error];
    if (!wrote) {
        log_message("marker write failed path=%s error=%s", path,
                    [[error description] UTF8String]);
    }
    return wrote;
}

static bool ensure_root_owned_empty_file(const char *path, mode_t mode,
                                         NSString **errorText) {
    struct stat before;
    int statusResult = lstat(path, &before);
    if (statusResult == 0) {
        if (S_ISREG(before.st_mode)) {
            // Continue below to normalize the existing marker in place.
        } else {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"managed marker is not a regular file: %s", path];
            }
            return false;
        }
    } else if (errno != ENOENT) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed marker status failed: %s",
                                 strerror(errno)];
        }
        return false;
    }

    int file = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, mode);
    if (file < 0) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed marker open failed: %s",
                                 strerror(errno)];
        }
        return false;
    }
    struct stat opened;
    bool ready = fstat(file, &opened) == 0 && S_ISREG(opened.st_mode) &&
                 ftruncate(file, 0) == 0 && fchown(file, 0, 0) == 0 &&
                 fchmod(file, mode) == 0 && fsync(file) == 0;
    int savedError = ready ? 0 : errno;
    if (close(file) != 0 && ready) {
        ready = false;
        savedError = errno;
    }
    struct stat after;
    if (!ready || lstat(path, &after) != 0 || !S_ISREG(after.st_mode) ||
        after.st_size != 0 || after.st_uid != 0 || after.st_gid != 0 ||
        (after.st_mode & 07777) != mode) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed marker preparation failed: %s",
                                 strerror(savedError != 0 ? savedError
                                                          : errno)];
        }
        return false;
    }
    return true;
}

static NSString *boot_manifest_hash(void) {
    io_registry_entry_t chosen =
        IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
    if (chosen == IO_OBJECT_NULL) {
        return nil;
    }
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    IOObjectRelease(chosen);
    if (property == NULL || CFGetTypeID(property) != CFDataGetTypeID()) {
        if (property != NULL) {
            CFRelease(property);
        }
        return nil;
    }

    NSData *data = CFBridgingRelease(property);
    const unsigned char *bytes = data.bytes;
    NSMutableString *hex =
        [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger index = 0; index < data.length; ++index) {
        [hex appendFormat:@"%02x", bytes[index]];
    }
    return hex;
}

static NSString *executable_path(void) {
    uint32_t size = 0;
    (void)_NSGetExecutablePath(NULL, &size);
    char *buffer = calloc(size + 1, 1);
    if (buffer == NULL || _NSGetExecutablePath(buffer, &size) != 0) {
        free(buffer);
        return nil;
    }
    char resolved[PATH_MAX] = {0};
    NSString *result = nil;
    if (realpath(buffer, resolved) != NULL) {
        result = [NSString stringWithUTF8String:resolved];
    } else {
        result = [NSString stringWithUTF8String:buffer];
    }
    free(buffer);
    return result;
}

static bool executable_paths_match(NSString *expected, NSString *actual) {
    if (expected == nil || actual == nil) {
        return false;
    }
    if ([expected isEqual:actual]) {
        return true;
    }
    char expectedPath[PATH_MAX] = {0};
    char actualPath[PATH_MAX] = {0};
    return realpath([expected fileSystemRepresentation], expectedPath) != NULL &&
           realpath([actual fileSystemRepresentation], actualPath) != NULL &&
           strcmp(expectedPath, actualPath) == 0;
}

static bool configure_managed_environment(NSString *jailbreakRoot) {
    if (jailbreakRoot == nil) {
        return false;
    }
    const char *root = [jailbreakRoot fileSystemRepresentation];
    char path[8192];
    char shell[4096];
    char libraryPath[4096];
    int lengths[] = {
        snprintf(path, sizeof(path),
                 "%s/usr/bin:%s/bin:%s/usr/sbin:%s/sbin:"
                 "/usr/bin:/bin:/usr/sbin:/sbin",
                 root, root, root, root),
        snprintf(shell, sizeof(shell), "%s/bin/sh", root),
        snprintf(libraryPath, sizeof(libraryPath), "%s/usr/lib", root),
    };
    size_t capacities[] = {sizeof(path), sizeof(shell), sizeof(libraryPath)};
    for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]);
         ++index) {
        if (lengths[index] < 0 ||
            (size_t)lengths[index] >= capacities[index]) {
            return false;
        }
    }
    return setenv("PATH", path, 1) == 0 &&
           setenv("SHELL", shell, 1) == 0 &&
           setenv("DYLD_LIBRARY_PATH", libraryPath, 1) == 0 &&
           setenv("HOME", "/var/root", 1) == 0 &&
           setenv("TMPDIR", "/var/tmp", 1) == 0;
}

static bool path_is_absent(const char *path) {
    struct stat status;
    if (lstat(path, &status) == 0) {
        return false;
    }
    return errno == ENOENT;
}

static bool apt_package_lists_are_populated(void) {
    NSError *error = nil;
    NSArray<NSString *> *entries = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:@"/var/jb/var/lib/apt/lists"
                             error:&error];
    if (entries == nil) {
        log_message("aptListsRead=false error=%s",
                    error != nil ? [[error description] UTF8String]
                                 : "unknown");
        return false;
    }
    for (NSString *entry in entries) {
        if ([entry hasSuffix:@"_Packages"] ||
            [entry hasSuffix:@"_Packages.lz4"] ||
            [entry hasSuffix:@"_Packages.xz"] ||
            [entry hasSuffix:@"_Packages.gz"]) {
            log_message("aptPackagesIndex=%s", [entry UTF8String]);
            return true;
        }
    }
    log_message("aptPackagesIndex=none entryCount=%lu",
                (unsigned long)entries.count);
    return false;
}

static NSString *managed_jailbreak_root(void) {
    struct stat status;
    if (lstat(kVarJb, &status) != 0 || !S_ISLNK(status.st_mode)) {
        return nil;
    }
    NSString *resolved = [@"/var/jb" stringByResolvingSymlinksInPath];
    NSString *marker = [resolved
        stringByAppendingPathComponent:@".codex-cryptex-bootstrap.plist"];
    NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:marker];
    if (![manifest[@"Installer"] isEqual:kInstallerIdentifier] ||
        ![manifest[@"JailbreakRoot"] isEqual:resolved]) {
        return nil;
    }
    return resolved;
}

static bool uninstall_managed_jailbreak_root(NSString *activePreboot,
                                              NSString **errorText) {
    NSString *resolved = managed_jailbreak_root();
    if (resolved == nil) {
        if (errorText != NULL) {
            *errorText = @"clean install refused an unmanaged /var/jb";
        }
        return false;
    }
    NSString *marker = [resolved
        stringByAppendingPathComponent:@".codex-cryptex-bootstrap.plist"];
    NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:marker];
    NSString *randomizedRoot = manifest[@"RandomizedRoot"];
    struct stat linkStatus;
    struct stat randomizedStatus;
    struct stat procursusStatus;
    struct stat markerStatus;
    bool manifestShape =
        [randomizedRoot isKindOfClass:[NSString class]] &&
        [manifest[@"VarJbCreated"] isEqual:@YES] &&
        [manifest[@"Installer"] isEqual:kInstallerIdentifier] &&
        [manifest[@"JailbreakRoot"] isEqual:resolved] &&
        [[resolved lastPathComponent] isEqual:@"procursus"] &&
        [[resolved stringByDeletingLastPathComponent]
            isEqual:randomizedRoot];
    bool pathShape = manifestShape &&
        [[resolved stringByStandardizingPath] isEqual:resolved] &&
        [[randomizedRoot stringByStandardizingPath] isEqual:randomizedRoot] &&
        [[[randomizedRoot stringByDeletingLastPathComponent]
            stringByStandardizingPath]
            isEqual:[activePreboot stringByStandardizingPath]] &&
        [[randomizedRoot lastPathComponent] hasPrefix:@"dopamine-"];
    bool linkShape = lstat(kVarJb, &linkStatus) == 0 &&
                     S_ISLNK(linkStatus.st_mode);
    bool randomizedShape =
        [randomizedRoot isKindOfClass:[NSString class]] &&
        lstat([randomizedRoot fileSystemRepresentation], &randomizedStatus) ==
            0 &&
        S_ISDIR(randomizedStatus.st_mode) &&
        !S_ISLNK(randomizedStatus.st_mode);
    bool procursusShape =
        lstat([resolved fileSystemRepresentation], &procursusStatus) == 0 &&
        S_ISDIR(procursusStatus.st_mode) && !S_ISLNK(procursusStatus.st_mode);
    bool markerShape =
        lstat([marker fileSystemRepresentation], &markerStatus) == 0 &&
        S_ISREG(markerStatus.st_mode) && !S_ISLNK(markerStatus.st_mode) &&
        markerStatus.st_size > 0 && markerStatus.st_size <= 64 * 1024;

    // Procursus' copied root can legitimately preserve a non-wheel group from
    // the fixed Cryptex payload.  Ownership and write bits are useful audit
    // signals, but rejecting on them deadlocks the explicit one-time cleanup:
    // the daemon can neither remove the old managed root nor install the new
    // SBInject-only root.  The legacy installer also created its manifest with
    // the copied Procursus ownership.  Deletion remains constrained by a
    // regular, bounded manifest with the exact installer/root values and the
    // exact active-preboot/dopamine-*/procursus structure above.
    bool ownershipAdvisory =
        linkShape && randomizedShape && procursusShape &&
        linkStatus.st_uid == 0 && linkStatus.st_gid == 0 &&
        randomizedStatus.st_uid == 0 && randomizedStatus.st_gid == 0 &&
        (randomizedStatus.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        procursusStatus.st_uid == 0 && procursusStatus.st_gid == 0 &&
        (procursusStatus.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        markerShape && markerStatus.st_uid == 0 && markerStatus.st_gid == 0 &&
        (markerStatus.st_mode & (S_IWGRP | S_IWOTH)) == 0;
    log_message(
        "cleanInstallValidation manifestShape=%s pathShape=%s "
        "linkShape=%s randomizedShape=%s procursusShape=%s "
        "markerShape=%s ownershipAdvisory=%s "
        "linkUid=%u linkGid=%u randomizedUid=%u randomizedGid=%u "
        "procursusUid=%u procursusGid=%u markerUid=%u markerGid=%u "
        "markerMode=%o",
        manifestShape ? "true" : "false", pathShape ? "true" : "false",
        linkShape ? "true" : "false",
        randomizedShape ? "true" : "false",
        procursusShape ? "true" : "false",
        markerShape ? "true" : "false",
        ownershipAdvisory ? "true" : "false",
        linkShape ? linkStatus.st_uid : UINT_MAX,
        linkShape ? linkStatus.st_gid : UINT_MAX,
        randomizedShape ? randomizedStatus.st_uid : UINT_MAX,
        randomizedShape ? randomizedStatus.st_gid : UINT_MAX,
        procursusShape ? procursusStatus.st_uid : UINT_MAX,
        procursusShape ? procursusStatus.st_gid : UINT_MAX,
        markerShape ? markerStatus.st_uid : UINT_MAX,
        markerShape ? markerStatus.st_gid : UINT_MAX,
        markerShape ? markerStatus.st_mode & 07777 : 0);
    bool safe = manifestShape && pathShape && linkShape && randomizedShape &&
                procursusShape && markerShape;
    if (!safe) {
        if (errorText != NULL) {
            *errorText = @"clean install safety validation rejected the old "
                         "managed bootstrap";
        }
        return false;
    }

    NSString *staged = [activePreboot
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".codex-uninstall-%@",
                                       [[NSUUID UUID] UUIDString]]];
    if (rename([randomizedRoot fileSystemRepresentation],
               [staged fileSystemRepresentation]) != 0) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"clean install could not stage the old "
                                 "bootstrap: %s",
                                 strerror(errno)];
        }
        return false;
    }
    if (unlink(kVarJb) != 0) {
        int unlinkError = errno;
        bool restored = rename([staged fileSystemRepresentation],
                               [randomizedRoot fileSystemRepresentation]) == 0;
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"clean install could not unlink /var/jb: "
                                 "%s (rollback=%@)",
                                 strerror(unlinkError),
                                 restored ? @"complete" : @"failed"];
        }
        return false;
    }

    NSError *removeError = nil;
    if (![[NSFileManager defaultManager] removeItemAtPath:staged
                                                    error:&removeError]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"clean install could not remove the old "
                                 "bootstrap: %@",
                                 removeError];
        }
        return false;
    }
    log_message("cleanInstallOldBootstrapRemoved=true root=%s",
                [randomizedRoot UTF8String]);
    return true;
}

static id registered_application_proxy(NSString *identifier) {
    static void *launchServices = NULL;
    static bool attemptedLoad = false;
    if (!attemptedLoad) {
        attemptedLoad = true;
        launchServices = dlopen(
            "/System/Library/Frameworks/MobileCoreServices.framework/"
            "MobileCoreServices",
            RTLD_NOW | RTLD_LOCAL);
    }
    if (launchServices == NULL) {
        log_message("LaunchServices dlopen failed error=%s", dlerror());
        return nil;
    }
    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if (proxyClass == Nil ||
        ![proxyClass respondsToSelector:
                        @selector(applicationProxyForIdentifier:)]) {
        log_message("LSApplicationProxy unavailable");
        return nil;
    }
    return [proxyClass applicationProxyForIdentifier:identifier];
}

static NSString *registered_application_path(NSString *identifier) {
    id proxy = registered_application_proxy(identifier);
    if (proxy == nil || ![proxy respondsToSelector:@selector(bundleURL)]) {
        return nil;
    }
    return [[proxy bundleURL] path];
}

static bool is_sileo_bundle_container_path(NSString *path) {
    if (path.length == 0 ||
        ![[path lastPathComponent] isEqual:@"Sileo.app"]) {
        return false;
    }
    NSString *container = [path stringByDeletingLastPathComponent];
    NSString *base = [container stringByDeletingLastPathComponent];
    if (![base isEqual:@"/var/containers/Bundle/Application"] &&
        ![base isEqual:@"/private/var/containers/Bundle/Application"]) {
        return false;
    }
    if ([[NSUUID alloc] initWithUUIDString:[container lastPathComponent]] ==
        nil) {
        return false;
    }
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [path stringByAppendingPathComponent:@"Info.plist"]];
    return [info[@"CFBundleIdentifier"] isEqual:kSileoIdentifier];
}

static bool is_sileo_system_bundle_path(NSString *path) {
    if (path.length == 0 ||
        ![[path lastPathComponent] isEqual:@"Sileo.app"]) return false;
    NSString *standardized = [path stringByStandardizingPath];
    bool stableSystemPath = [standardized isEqual:@"/Applications/Sileo.app"];
    static NSString *const privateCryptexPrefix =
        @"/private/var/run/com.apple.security.cryptexd/mnt/"
         "com.openai.codex.dopamine.bootstrap.";
    static NSString *const cryptexPrefix =
        @"/var/run/com.apple.security.cryptexd/mnt/"
         "com.openai.codex.dopamine.bootstrap.";
    bool cryptexPath =
        ([standardized hasPrefix:privateCryptexPrefix] ||
         [standardized hasPrefix:cryptexPrefix]) &&
        [standardized hasSuffix:@"/Applications/Sileo.app"];
    bool managedContainerPath =
        [standardized isEqual:[kSystemSileoBundlePath stringByStandardizingPath]];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [standardized stringByAppendingPathComponent:@"Info.plist"]];
    bool identifier =
        [info[@"CFBundleIdentifier"] isEqual:@"org.coolstar.SileoStore"];
    bool executable = [info[@"CFBundleExecutable"] isEqual:@"Sileo"];
    bool profile = [[NSFileManager defaultManager] fileExistsAtPath:
        [standardized stringByAppendingPathComponent:
            @"embedded.mobileprovision"]];
    bool valid = (stableSystemPath || cryptexPath || managedContainerPath) && identifier &&
                 executable && !profile;
    log_message("sileoSystemPathValidation valid=%s path=%s stable=%s "
                "cryptex=%s managedContainer=%s identifier=%s executable=%s "
                "profile=%s",
                valid ? "true" : "false", [standardized UTF8String],
                stableSystemPath ? "true" : "false",
                cryptexPath ? "true" : "false",
                managedContainerPath ? "true" : "false",
                identifier ? "true" : "false",
                executable ? "true" : "false",
                profile ? "true" : "false");
    return valid;
}

static bool is_sileo_client_bundle_path(NSString *path) {
    return is_sileo_system_bundle_path(path) ||
           is_sileo_bundle_container_path(path);
}

static bool is_sileo_data_container_path(NSString *path) {
    if (path.length == 0) {
        return false;
    }
    NSString *standardized = [path stringByStandardizingPath];
    if ([standardized isEqual:kSystemSileoDataRoot]) return true;
    NSString *base = [standardized stringByDeletingLastPathComponent];
    if (![base isEqual:@"/var/mobile/Containers/Data/Application"] &&
        ![base isEqual:@"/private/var/mobile/Containers/Data/Application"]) {
        return false;
    }
    if ([[NSUUID alloc]
            initWithUUIDString:[standardized lastPathComponent]] == nil) {
        return false;
    }
    BOOL isDirectory = NO;
    return [[NSFileManager defaultManager] fileExistsAtPath:standardized
                                               isDirectory:&isDirectory] &&
           isDirectory;
}

static bool register_sileo_system_application(NSString *bundlePath,
                                              NSString **errorText) {
    if (!is_sileo_system_bundle_path(bundlePath)) {
        if (errorText != NULL) {
            *errorText = @"Cryptex Sileo system bundle is invalid";
        }
        return false;
    }
    if (!prepare_lsd_registration_hook("system-sileo-registration")) {
        if (errorText != NULL) {
            *errorText = @"iOS 27 lsd registration hook is unavailable";
        }
        return false;
    }
    // registered_application_proxy() performs the one-time MobileCoreServices
    // load that publishes LSApplicationWorkspace into this process.
    (void)registered_application_proxy(kSileoIdentifier);
    id workspace = [NSClassFromString(@"LSApplicationWorkspace")
        defaultWorkspace];
    SEL registrationSelector = @selector(
        registerContainerizedApplicationWithInfoDictionaries:operationUUID:
        requestContext:saveObserver:registrationError:);
    if (workspace == nil ||
        ![workspace respondsToSelector:registrationSelector]) {
        if (errorText != NULL) {
            *errorText = @"iOS 27 containerized registration API is unavailable";
        }
        return false;
    }
    NSDictionary *bundleInfo = [NSDictionary dictionaryWithContentsOfFile:
        [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
    NSDictionary *registrationEntitlements =
        [NSDictionary dictionaryWithContentsOfFile:
            [bundlePath stringByAppendingPathComponent:
                            @"CodexSystemEntitlements.plist"]];
    if (bundleInfo == nil || bundleInfo[@"CFBundleIcons"] == nil ||
        bundleInfo[@"CFBundleDisplayName"] == nil ||
        ![registrationEntitlements[
            @"com.apple.private.security.no-container"] boolValue] ||
        ![registrationEntitlements[
            @"com.apple.private.security.no-sandbox"] boolValue]) {
        if (errorText != NULL) {
            *errorText = @"Cryptex Sileo icon metadata is unavailable";
        }
        return false;
    }
    NSMutableDictionary *registration = [bundleInfo mutableCopy];
    [registration addEntriesFromDictionary:@{
        @"Path" : [bundlePath stringByStandardizingPath],
        @"CFBundleIdentifier" : @"org.coolstar.SileoStore",
        @"CodeInfoIdentifier" : @"org.coolstar.SileoStore",
        @"ApplicationType" : @"System",
        @"BundleNameIsLocalized" : @YES,
        @"CompatibilityState" : @0,
        @"Entitlements" : registrationEntitlements,
        @"IsContainerized" : @NO,
        @"SignerIdentity" : @"Apple iPhone OS Application Signing",
        @"SignerOrganization" : @"Apple Inc.",
        @"IsAdHocSigned" : @YES,
        @"SignatureVersion" : @132352,
        @"IsDeletable" : @NO,
        @"LSInstallType" : @1,
        @"HasMIDBasedSINF" : @NO,
        @"MissingSINF" : @NO,
        @"FamilyID" : @0,
        @"IsOnDemandInstallCapable" : @NO,
    }];
    Class requestContextClass = NSClassFromString(@"LSOperationRequestContext");
    id requestContext = requestContextClass != Nil
        ? [[requestContextClass alloc] init] : nil;
    if (requestContext == nil) {
        if (errorText != NULL) {
            *errorText = @"iOS 27 LaunchServices request context is unavailable";
        }
        return false;
    }
    [requestContext setValue:@501 forKey:@"targetUserID"];
    NSError *registrationError = nil;
    id registrationResult = [workspace
        registerContainerizedApplicationWithInfoDictionaries:@[registration]
        operationUUID:[NSUUID UUID]
        requestContext:requestContext
        saveObserver:nil
        registrationError:&registrationError];
    (void)notify_post("com.apple.mobile.application_installed");
    (void)notify_post("com.apple.itunesstored.application_installed");
    bool registered = false;
    NSString *observedPath = nil;
    NSString *applicationType = nil;
    for (NSUInteger attempt = 0; attempt < 200; ++attempt) {
        id proxy = registered_application_proxy(kSileoIdentifier);
        observedPath = [proxy respondsToSelector:@selector(bundleURL)]
            ? [[proxy bundleURL] path] : nil;
        applicationType =
            [proxy respondsToSelector:@selector(applicationType)]
                ? [proxy applicationType] : nil;
        if (executable_paths_match(bundlePath, observedPath) &&
            [applicationType isEqualToString:@"System"]) {
            registered = true;
            break;
        }
        usleep(25 * 1000);
    }
    log_message("sileoSystemRegistration transport=%s error=%s registered=%s "
                "path=%s observed=%s type=%s profile=false bundleId=%s",
                registrationResult != nil ? "true" : "false",
                registrationError != nil
                    ? [[registrationError description] UTF8String] : "none",
                registered ? "true" : "false",
                [bundlePath UTF8String],
                observedPath != nil ? [observedPath UTF8String] : "none",
                applicationType != nil ? [applicationType UTF8String] : "none",
                [kSileoIdentifier UTF8String]);
    if (!registered && errorText != NULL) {
        *errorText = [NSString stringWithFormat:
            @"Cryptex Sileo system registration failed (error=%@ path=%@ "
             "type=%@)", registrationError ?: @"none",
            observedPath ?: @"none", applicationType ?: @"none"];
    }
    return registered;
}

static bool managed_app_container_path_is_valid(NSString *path) {
    if (path.length == 0) return false;
    NSString *standardized = [path stringByStandardizingPath];
    NSString *parent = [standardized stringByDeletingLastPathComponent];
    if (![parent isEqual:@"/var/containers/Bundle/Application"] &&
        ![parent isEqual:@"/private/var/containers/Bundle/Application"]) {
        return false;
    }
    return [[NSUUID alloc]
        initWithUUIDString:[standardized lastPathComponent]] != nil;
}

static bool write_managed_application_marker(NSString *containerPath,
                                             NSString *identifier,
                                             NSString *sourcePath,
                                             NSString *bundlePath,
                                             NSString **errorText) {
    NSDictionary *marker = @{
        @"Version" : @1,
        @"BundleIdentifier" : identifier,
        @"SourcePath" : [sourcePath stringByStandardizingPath],
        @"BundlePath" : [bundlePath stringByStandardizingPath],
    };
    NSString *path = [containerPath
        stringByAppendingPathComponent:kManagedApplicationMarker];
    NSString *temporary = [containerPath stringByAppendingPathComponent:
        [NSString stringWithFormat:@".%@-%@", kManagedApplicationMarker,
                                   [NSUUID UUID].UUIDString]];
    NSError *error = nil;
    if (![marker writeToFile:temporary atomically:NO] ||
        ![[NSFileManager defaultManager]
            setAttributes:@{
                NSFilePosixPermissions : @0644,
                NSFileOwnerAccountID : @0,
                NSFileGroupOwnerAccountID : @0,
            }
             ofItemAtPath:temporary error:&error] ||
        rename([temporary fileSystemRepresentation],
               [path fileSystemRepresentation]) != 0) {
        int savedError = errno;
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"managed application marker failed: %@ (%s)",
                error ?: @"none", strerror(savedError)];
        }
        return false;
    }
    if ([identifier isEqual:kTrollStoreLiteIdentifier]) {
        NSString *trollStoreMarker = [containerPath
            stringByAppendingPathComponent:kTrollStoreLiteMarker];
        NSString *markerError = nil;
        if (!ensure_root_owned_empty_file(
                [trollStoreMarker fileSystemRepresentation], 0644,
                &markerError)) {
            if (errorText != NULL) *errorText = markerError;
            return false;
        }
    }
    return true;
}

static bool replace_managed_application_bundle(NSString *source,
                                               NSString *containerPath,
                                               NSString *destination,
                                               NSString **errorText) {
    if (validated_bundle_entries(source, false) == nil) {
        if (errorText != NULL) {
            *errorText = @"rootless application bundle is invalid";
        }
        return false;
    }
    if (bundle_trees_are_equal(source, destination)) return true;

    NSFileManager *manager = [NSFileManager defaultManager];
    NSString *temporary = [containerPath stringByAppendingPathComponent:
        [NSString stringWithFormat:@".%@.new-%@",
            [destination lastPathComponent], [NSUUID UUID].UUIDString]];
    NSError *error = nil;
    if (![manager copyItemAtPath:source toPath:temporary error:&error] ||
        !normalize_bundle_tree(source, temporary) ||
        !bundle_trees_are_equal(source, temporary)) {
        [manager removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"managed application copy failed: %@", error ?: @"none"];
        }
        return false;
    }

    NSString *backup = nil;
    struct stat existing = {0};
    if (lstat([destination fileSystemRepresentation], &existing) == 0) {
        NSString *markerPath = [containerPath
            stringByAppendingPathComponent:kManagedApplicationMarker];
        struct stat marker = {0};
        bool managed = S_ISDIR(existing.st_mode) &&
            !S_ISLNK(existing.st_mode) &&
            lstat([markerPath fileSystemRepresentation], &marker) == 0 &&
            S_ISREG(marker.st_mode) && !S_ISLNK(marker.st_mode) &&
            marker.st_uid == 0 && marker.st_gid == 0;
        if (!managed) {
            [manager removeItemAtPath:temporary error:nil];
            if (errorText != NULL) {
                *errorText = @"refusing to replace an unmanaged app container";
            }
            return false;
        }
        backup = [containerPath stringByAppendingPathComponent:
            [NSString stringWithFormat:@".%@.old-%@",
                [destination lastPathComponent], [NSUUID UUID].UUIDString]];
        if (rename([destination fileSystemRepresentation],
                   [backup fileSystemRepresentation]) != 0) {
            [manager removeItemAtPath:temporary error:nil];
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"managed application backup failed: %s", strerror(errno)];
            }
            return false;
        }
    } else if (errno != ENOENT) {
        [manager removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"managed application status failed: %s", strerror(errno)];
        }
        return false;
    }

    if (rename([temporary fileSystemRepresentation],
               [destination fileSystemRepresentation]) != 0) {
        int savedError = errno;
        if (backup != nil) {
            (void)rename([backup fileSystemRepresentation],
                         [destination fileSystemRepresentation]);
        }
        [manager removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"managed application activation failed: %s",
                strerror(savedError)];
        }
        return false;
    }
    if (backup != nil) [manager removeItemAtPath:backup error:nil];
    if (!bundle_trees_are_equal(source, destination)) {
        if (errorText != NULL) {
            *errorText = @"managed application verification failed";
        }
        return false;
    }
    return true;
}

static bool load_mobile_container_manager(void) {
    static dispatch_once_t once;
    static bool loaded = false;
    dispatch_once(&once, ^{
        loaded = dlopen(
            "/System/Library/PrivateFrameworks/"
            "MobileContainerManager.framework/MobileContainerManager",
            RTLD_NOW | RTLD_LOCAL) != NULL;
    });
    return loaded;
}

static bool register_managed_rootless_application(NSString *source,
                                                   NSString **targetPath,
                                                   NSString **errorText) {
    if (targetPath != NULL) *targetPath = nil;
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [source stringByAppendingPathComponent:@"Info.plist"]];
    NSString *identifier = info[@"CFBundleIdentifier"];
    NSString *executable = info[@"CFBundleExecutable"];
    if (![identifier isKindOfClass:NSString.class] || identifier.length == 0 ||
        ![executable isKindOfClass:NSString.class] || executable.length == 0 ||
        validated_bundle_entries(source, false) == nil ||
        !load_mobile_container_manager()) {
        if (errorText != NULL) {
            *errorText = @"managed application metadata is unavailable";
        }
        return false;
    }
    Class appContainerClass = NSClassFromString(@"MCMAppContainer");
    Class dataContainerClass = NSClassFromString(@"MCMAppDataContainer");
    BOOL existed = NO;
    NSError *containerError = nil;
    id appContainer = [appContainerClass
        containerWithIdentifier:identifier
              createIfNecessary:YES
                        existed:&existed
                          error:&containerError];
    NSURL *containerURL = [appContainer respondsToSelector:@selector(url)]
        ? [appContainer url] : nil;
    NSString *containerPath = [containerURL path];
    if (containerPath == nil ||
        !managed_app_container_path_is_valid(containerPath)) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"could not create application container: %@",
                containerError ?: @"unknown"];
        }
        return false;
    }
    NSString *destination = [containerPath
        stringByAppendingPathComponent:[source lastPathComponent]];
    if (!replace_managed_application_bundle(
            source, containerPath, destination, errorText) ||
        !write_managed_application_marker(
            containerPath, identifier, source, destination, errorText)) {
        return false;
    }
    if (targetPath != NULL) *targetPath = destination;

    NSError *dataError = nil;
    id dataContainer = [dataContainerClass
        containerWithIdentifier:identifier
              createIfNecessary:YES
                        existed:NULL
                          error:&dataError];
    NSURL *dataURL = [dataContainer respondsToSelector:@selector(url)]
        ? [dataContainer url] : nil;
    NSString *dataPath = [dataURL path];
    if (dataPath.length == 0) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"could not create application data container: %@",
                dataError ?: @"unknown"];
        }
        return false;
    }

    (void)registered_application_proxy(identifier);
    id workspace = [NSClassFromString(@"LSApplicationWorkspace")
        defaultWorkspace];
    SEL registrationSelector = @selector(
        registerContainerizedApplicationWithInfoDictionaries:operationUUID:
        requestContext:saveObserver:registrationError:);
    if (workspace == nil ||
        ![workspace respondsToSelector:registrationSelector]) {
        if (errorText != NULL) {
            *errorText = @"LaunchServices embedded registration is unavailable";
        }
        return false;
    }
    NSMutableDictionary *registration = [info mutableCopy];
    [registration addEntriesFromDictionary:@{
        @"ApplicationType" : @"User",
        @"CFBundleIdentifier" : identifier,
        @"CodeInfoIdentifier" : identifier,
        @"CompatibilityState" : @0,
        @"IsContainerized" : @YES,
        @"Container" : dataPath,
        @"EnvironmentVariables" : @{
            @"CFFIXED_USER_HOME" : dataPath,
            @"HOME" : dataPath,
            @"TMPDIR" : [dataPath stringByAppendingPathComponent:@"tmp"],
        },
        @"IsDeletable" : @YES,
        @"Path" : [destination stringByStandardizingPath],
        @"SignerOrganization" : @"Apple Inc.",
        @"SignatureVersion" : @132352,
        @"SignerIdentity" : @"Apple iPhone OS Application Signing",
        @"IsAdHocSigned" : @YES,
        @"LSInstallType" : @1,
        @"HasMIDBasedSINF" : @NO,
        @"MissingSINF" : @NO,
        @"FamilyID" : @0,
        @"IsOnDemandInstallCapable" : @NO,
        @"_LSBundlePlugins" : @{},
    }];
    Class requestContextClass = NSClassFromString(@"LSOperationRequestContext");
    id requestContext = requestContextClass != Nil
        ? [[requestContextClass alloc] init] : nil;
    if (requestContext == nil) {
        if (errorText != NULL) {
            *errorText = @"LaunchServices request context is unavailable";
        }
        return false;
    }
    [requestContext setValue:@501 forKey:@"targetUserID"];
    NSError *registrationError = nil;
    id registrationResult = nil;
    @try {
        registrationResult = [workspace
            registerContainerizedApplicationWithInfoDictionaries:
                @[registration]
            operationUUID:[NSUUID UUID]
            requestContext:requestContext
            saveObserver:nil
            registrationError:&registrationError];
    } @catch (NSException *exception) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"LaunchServices registration raised %@", exception];
        }
        return false;
    }
    (void)notify_post("com.apple.mobile.application_installed");
    (void)notify_post("com.apple.itunesstored.application_installed");
    NSString *observed = nil;
    for (NSUInteger attempt = 0; attempt < 200; ++attempt) {
        observed = registered_application_path(identifier);
        if (executable_paths_match(destination, observed)) return true;
        usleep(25 * 1000);
    }
    if (errorText != NULL) {
        *errorText = [NSString stringWithFormat:
            @"LaunchServices registration failed (transport=%@ error=%@ "
             "observed=%@)",
            registrationResult != nil ? @"true" : @"false",
            registrationError ?: @"none", observed ?: @"none"];
    }
    return false;
}

static NSDictionary *managed_application_marker(NSString *containerPath) {
    NSString *path = [containerPath
        stringByAppendingPathComponent:kManagedApplicationMarker];
    struct stat status = {0};
    if (lstat([path fileSystemRepresentation], &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 || status.st_uid != 0 || status.st_gid != 0 ||
        status.st_size <= 0 || status.st_size > 64 * 1024 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return nil;
    }
    NSDictionary *marker = [NSDictionary dictionaryWithContentsOfFile:path];
    return [marker[@"Version"] integerValue] == 1 ? marker : nil;
}

static bool cleanup_stale_managed_applications(NSSet<NSString *> *active,
                                                NSString **errorText) {
    NSString *root = @"/var/containers/Bundle/Application";
    NSArray<NSString *> *entries = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:root error:nil];
    id workspace = [NSClassFromString(@"LSApplicationWorkspace")
        defaultWorkspace];
    NSUInteger inspected = 0;
    for (NSString *entry in entries) {
        if (++inspected > 4096U) break;
        if ([[NSUUID alloc] initWithUUIDString:entry] == nil) continue;
        NSString *containerPath = [root stringByAppendingPathComponent:entry];
        NSDictionary *marker = managed_application_marker(containerPath);
        if (marker == nil) continue;
        NSString *identifier = marker[@"BundleIdentifier"];
        NSString *sourcePath = marker[@"SourcePath"];
        NSString *bundlePath = marker[@"BundlePath"];
        bool retained = [identifier isKindOfClass:NSString.class] &&
            [sourcePath isKindOfClass:NSString.class] &&
            [bundlePath isKindOfClass:NSString.class] &&
            [active containsObject:identifier] &&
            [[NSFileManager defaultManager] fileExistsAtPath:sourcePath];
        if (retained) continue;
        if ([bundlePath isKindOfClass:NSString.class] &&
            [workspace respondsToSelector:@selector(unregisterApplication:)]) {
            (void)[workspace unregisterApplication:
                [NSURL fileURLWithPath:bundlePath]];
        }
        NSError *removeError = nil;
        if (![[NSFileManager defaultManager]
                removeItemAtPath:containerPath error:&removeError]) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"managed application cleanup failed: %@", removeError];
            }
            return false;
        }
        (void)notify_post("com.apple.mobile.application_uninstalled");
    }
    return true;
}

static bool write_sileo_sandbox_extensions(NSString *dataContainer,
                                           NSString *jailbreakRoot,
                                           NSString **tokenPathOut,
                                           NSString **errorText) {
    static const char *const classes[] = {
        "com.apple.app-sandbox.read",
        "com.apple.sandbox.executable",
        "com.apple.app-sandbox.read-write",
    };
    NSString *paths[] = {
        jailbreakRoot,
        jailbreakRoot,
        @"/var/mobile",
    };
    char *tokens[3] = {NULL, NULL, NULL};
    NSMutableString *serialized = [NSMutableString string];
    for (NSUInteger index = 0; index < 3; ++index) {
        const char *path = [paths[index] fileSystemRepresentation];
        tokens[index] = sandbox_extension_issue_file(classes[index], path, 0);
        if (tokens[index] == NULL) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"sandbox extension issue failed for %s at %s",
                        classes[index], path];
            }
            for (NSUInteger cleanup = 0; cleanup < 3; ++cleanup) {
                free(tokens[cleanup]);
            }
            return false;
        }
        NSString *token = [NSString stringWithUTF8String:tokens[index]];
        if (token.length == 0 || [token containsString:@"\n"] ||
            [token containsString:@"\r"]) {
            if (errorText != NULL) {
                *errorText = @"sandbox extension returned invalid text";
            }
            for (NSUInteger cleanup = 0; cleanup < 3; ++cleanup) {
                free(tokens[cleanup]);
            }
            return false;
        }
        [serialized appendFormat:@"%@\n", token];
    }

    NSString *directory = [dataContainer
        stringByAppendingPathComponent:@"Library/CodexBootstrap"];
    NSError *error = nil;
    if (![[NSFileManager defaultManager]
            createDirectoryAtPath:directory
      withIntermediateDirectories:YES
                       attributes:@{
                           NSFilePosixPermissions : @0700,
                           NSFileOwnerAccountID : @501,
                           NSFileGroupOwnerAccountID : @501,
                       }
                            error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"sandbox extension directory failed: %@",
                                 error];
        }
        for (NSUInteger cleanup = 0; cleanup < 3; ++cleanup) {
            free(tokens[cleanup]);
        }
        return false;
    }
    (void)[[NSFileManager defaultManager]
        setAttributes:@{
            NSFilePosixPermissions : @0700,
            NSFileOwnerAccountID : @501,
            NSFileGroupOwnerAccountID : @501,
        }
         ofItemAtPath:directory
                error:nil];

    NSString *rootPath =
        [directory stringByAppendingPathComponent:@"jailbreak-root"];
    NSString *serializedRoot = [jailbreakRoot stringByAppendingString:@"\n"];
    if (![serializedRoot writeToFile:rootPath
                          atomically:YES
                            encoding:NSUTF8StringEncoding
                               error:&error] ||
        ![[NSFileManager defaultManager]
            setAttributes:@{
                NSFilePosixPermissions : @0600,
                NSFileOwnerAccountID : @501,
                NSFileGroupOwnerAccountID : @501,
            }
             ofItemAtPath:rootPath
                    error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"jailbreak-root file failed: %@", error];
        }
        for (NSUInteger cleanup = 0; cleanup < 3; ++cleanup) {
            free(tokens[cleanup]);
        }
        return false;
    }

    NSString *tokenPath =
        [directory stringByAppendingPathComponent:@"sandbox-extensions"];
    BOOL wrote = [serialized writeToFile:tokenPath
                              atomically:YES
                                encoding:NSUTF8StringEncoding
                                   error:&error];
    for (NSUInteger cleanup = 0; cleanup < 3; ++cleanup) {
        free(tokens[cleanup]);
    }
    if (!wrote || ![[NSFileManager defaultManager]
                      setAttributes:@{
                          NSFilePosixPermissions : @0600,
                          NSFileOwnerAccountID : @501,
                          NSFileGroupOwnerAccountID : @501,
                      }
                       ofItemAtPath:tokenPath
                              error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"sandbox extension file failed: %@", error];
        }
        return false;
    }
    if (tokenPathOut != NULL) {
        *tokenPathOut = tokenPath;
    }
    return true;
}

static int create_sileo_broker_socket(NSString *dataContainer,
                                      NSString **socketPathOut,
                                      NSString **errorText) {
    NSString *socketPath =
        [dataContainer stringByAppendingPathComponent:@".codex-broker"];
    const char *path = [socketPath fileSystemRepresentation];
    struct sockaddr_un address = {0};
    if (strlen(path) >= sizeof(address.sun_path)) {
        if (errorText != NULL) {
            *errorText = @"Sileo broker socket path is too long";
        }
        return -1;
    }
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"Sileo broker socket failed: %s",
                                 strerror(errno)];
        }
        return -1;
    }
    (void)unlink(path);
    address.sun_family = AF_UNIX;
    address.sun_len = sizeof(address);
    strlcpy(address.sun_path, path, sizeof(address.sun_path));
    if (bind(server, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        chown(path, 501, 501) != 0 || chmod(path, 0600) != 0 ||
        listen(server, 4) != 0) {
        int savedError = errno;
        close(server);
        (void)unlink(path);
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"Sileo broker setup failed: %s",
                                 strerror(savedError)];
        }
        return -1;
    }
    if (socketPathOut != NULL) {
        *socketPathOut = socketPath;
    }
    return server;
}

static bool write_all(int descriptor, const void *bytes, size_t length) {
    const unsigned char *cursor = bytes;
    while (length > 0) {
        ssize_t written = write(descriptor, cursor, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        cursor += written;
        length -= (size_t)written;
    }
    return true;
}

static bool read_all(int descriptor, void *bytes, size_t length) {
    unsigned char *cursor = bytes;
    while (length > 0) {
        ssize_t received = read(descriptor, cursor, length);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return false;
        }
        cursor += received;
        length -= (size_t)received;
    }
    return true;
}

struct codex_root_broker_request {
    struct codex_root_broker_header header;
    unsigned char *payload;
    char *arguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 1U];
    int descriptors[CODEX_ROOT_BROKER_MAX_FDS];
};

static void close_root_broker_request(
    struct codex_root_broker_request *request) {
    for (uint32_t index = 0; index < request->header.descriptor_count &&
                             index < CODEX_ROOT_BROKER_MAX_FDS;
         ++index) {
        if (request->descriptors[index] >= 0) {
            close(request->descriptors[index]);
            request->descriptors[index] = -1;
        }
    }
    free(request->payload);
    request->payload = NULL;
}

static bool is_allowed_descriptor_number(int number) {
    static const int allowed[] = {0, 1, 2, 3, 5, 6};
    for (size_t index = 0; index < sizeof(allowed) / sizeof(allowed[0]);
         ++index) {
        if (allowed[index] == number) {
            return true;
        }
    }
    return false;
}

static bool descriptor_numbers_contain(const int numbers[], uint32_t count,
                                       int number) {
    for (uint32_t index = 0; index < count; ++index) {
        if (numbers[index] == number) {
            return true;
        }
    }
    return false;
}

static bool valid_control_environment(const char *entry,
                                      const int descriptorNumbers[],
                                      uint32_t descriptorCount) {
    if (entry == NULL) {
        return false;
    }
    const char *value = NULL;
    if (strncmp(entry, "SILEO=", strlen("SILEO=")) == 0) {
        value = entry + strlen("SILEO=");
    } else if (strncmp(entry, "CYDIA=", strlen("CYDIA=")) == 0) {
        value = entry + strlen("CYDIA=");
    } else {
        return false;
    }
    errno = 0;
    char *separator = NULL;
    long descriptor = strtol(value, &separator, 10);
    if (errno != 0 || separator == value || separator == NULL ||
        *separator != ' ' || descriptor < 0 || descriptor > INT_MAX ||
        !descriptor_numbers_contain(descriptorNumbers, descriptorCount,
                                    (int)descriptor)) {
        return false;
    }
    const char *versionText = separator + 1;
    errno = 0;
    char *end = NULL;
    long version = strtol(versionText, &end, 10);
    return errno == 0 && end != versionText && end != NULL && *end == '\0' &&
           version >= 1 && version <= INT_MAX;
}

static void close_ancillary_rights(struct msghdr *message) {
    for (struct cmsghdr *entry = CMSG_FIRSTHDR(message); entry != NULL;
         entry = CMSG_NXTHDR(message, entry)) {
        if (entry->cmsg_level != SOL_SOCKET || entry->cmsg_type != SCM_RIGHTS ||
            entry->cmsg_len < CMSG_LEN(0)) {
            continue;
        }
        size_t byteCount = entry->cmsg_len - CMSG_LEN(0);
        size_t descriptorCount = byteCount / sizeof(int);
        int *descriptors = (int *)CMSG_DATA(entry);
        for (size_t index = 0; index < descriptorCount; ++index) {
            close(descriptors[index]);
        }
    }
}

static bool receive_root_broker_request(
    int client, struct codex_root_broker_request *request) {
    memset(request, 0, sizeof(*request));
    for (uint32_t index = 0; index < CODEX_ROOT_BROKER_MAX_FDS; ++index) {
        request->descriptors[index] = -1;
    }
    unsigned char control[CMSG_SPACE(CODEX_ROOT_BROKER_MAX_FDS *
                                     sizeof(int))] = {0};
    struct iovec vector = {
        .iov_base = &request->header,
        .iov_len = sizeof(request->header),
    };
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    ssize_t received;
    do {
        received = recvmsg(client, &message, 0);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
        return false;
    }
    if ((size_t)received > sizeof(request->header) ||
        (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 ||
        !read_all(client, (unsigned char *)&request->header + received,
                  sizeof(request->header) - (size_t)received)) {
        close_ancillary_rights(&message);
        return false;
    }

    struct cmsghdr *rights = NULL;
    for (struct cmsghdr *entry = CMSG_FIRSTHDR(&message); entry != NULL;
         entry = CMSG_NXTHDR(&message, entry)) {
        if (entry->cmsg_level == SOL_SOCKET && entry->cmsg_type == SCM_RIGHTS) {
            if (rights != NULL) {
                close_ancillary_rights(&message);
                return false;
            }
            rights = entry;
        }
    }
    if (request->header.magic != CODEX_ROOT_BROKER_MAGIC ||
        request->header.version != CODEX_ROOT_BROKER_VERSION ||
        request->header.argument_count == 0 ||
        request->header.argument_count > CODEX_ROOT_BROKER_MAX_ARGUMENTS ||
        request->header.payload_length == 0 ||
        request->header.payload_length > CODEX_ROOT_BROKER_MAX_PAYLOAD ||
        request->header.descriptor_count == 0 ||
        request->header.descriptor_count > CODEX_ROOT_BROKER_MAX_FDS ||
        rights == NULL || rights->cmsg_len < CMSG_LEN(0) ||
        rights->cmsg_len - CMSG_LEN(0) !=
            request->header.descriptor_count * sizeof(int)) {
        close_ancillary_rights(&message);
        return false;
    }
    memcpy(request->descriptors, CMSG_DATA(rights),
           request->header.descriptor_count * sizeof(int));
    for (uint32_t index = 0; index < request->header.descriptor_count;
         ++index) {
        int number = request->header.descriptor_numbers[index];
        if (!is_allowed_descriptor_number(number)) {
            close_root_broker_request(request);
            return false;
        }
        for (uint32_t previous = 0; previous < index; ++previous) {
            if (request->header.descriptor_numbers[previous] == number) {
                close_root_broker_request(request);
                return false;
            }
        }
    }

    request->payload = malloc(request->header.payload_length);
    if (request->payload == NULL ||
        !read_all(client, request->payload, request->header.payload_length)) {
        close_root_broker_request(request);
        return false;
    }
    unsigned char *cursor = request->payload;
    size_t remaining = request->header.payload_length;
    for (uint32_t index = 0; index < request->header.argument_count; ++index) {
        uint32_t length = 0;
        if (remaining < sizeof(length)) {
            close_root_broker_request(request);
            return false;
        }
        memcpy(&length, cursor, sizeof(length));
        cursor += sizeof(length);
        remaining -= sizeof(length);
        if (length == 0 || length > remaining || cursor[length - 1] != '\0' ||
            memchr(cursor, '\0', length - 1) != NULL) {
            close_root_broker_request(request);
            return false;
        }
        request->arguments[index] = (char *)cursor;
        cursor += length;
        remaining -= length;
    }
    if (remaining != 0) {
        close_root_broker_request(request);
        return false;
    }
    request->arguments[request->header.argument_count] = NULL;
    return true;
}

static bool resolve_broker_command(const char *requested,
                                   NSString *jailbreakRoot, char *resolved,
                                   size_t resolvedSize) {
    if (requested == NULL || requested[0] != '/' ||
        strstr(requested, "/../") != NULL || strstr(requested, "/./") != NULL ||
        realpath(requested, resolved) == NULL || strlen(resolved) >= resolvedSize) {
        return false;
    }
    const char *root = [jailbreakRoot fileSystemRepresentation];
    size_t rootLength = strlen(root);
    struct stat status;
    return strncmp(resolved, root, rootLength) == 0 &&
           resolved[rootLength] == '/' && stat(resolved, &status) == 0 &&
           S_ISREG(status.st_mode) && access(resolved, X_OK) == 0;
}

static bool broker_command_is_macho(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    uint32_t magic = 0;
    ssize_t amount = descriptor >= 0 ? read(descriptor, &magic, sizeof(magic))
                                     : -1;
    if (descriptor >= 0) {
        close(descriptor);
    }
    return amount == sizeof(magic) &&
           (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
            magic == FAT_MAGIC || magic == FAT_CIGAM);
}

typedef struct codex_payload_classification {
    bool contains_macho;
    bool contains_springboard_tweak;
    bool contains_ellekit_injector;
} codex_payload_classification_t;

static NSString *normalized_sbinject_payload_path(NSString *relativePath) {
    while ([relativePath hasPrefix:@"./"] || [relativePath hasPrefix:@"/"]) {
        relativePath = [relativePath substringFromIndex:1];
    }
    for (NSString *root in @[@"private/var/jb/", @"var/jb/"]) {
        if ([relativePath hasPrefix:root]) {
            relativePath = [relativePath substringFromIndex:root.length];
            break;
        }
    }
    return relativePath;
}

static bool relative_path_is_springboard_tweak(NSString *relativePath) {
    relativePath = normalized_sbinject_payload_path(relativePath);
    NSArray<NSString *> *roots = @[
        @"Library/MobileSubstrate/DynamicLibraries/",
        @"Library/TweakInject/",
        @"usr/lib/TweakInject/",
    ];
    bool admittedRoot = false;
    for (NSString *root in roots) {
        if ([relativePath hasPrefix:root]) {
            admittedRoot = true;
            break;
        }
    }
    return admittedRoot &&
           [[relativePath pathExtension]
               caseInsensitiveCompare:@"dylib"] == NSOrderedSame;
}

static bool relative_path_is_ellekit_injector(NSString *relativePath) {
    relativePath = normalized_sbinject_payload_path(relativePath);
    return [relativePath
        isEqualToString:@"usr/lib/ellekit/libinjector.dylib"];
}

static codex_payload_classification_t classify_payload(NSString *path) {
    codex_payload_classification_t classification = {0};
    struct stat status;
    const char *fileSystemPath = [path fileSystemRepresentation];
    if (stat(fileSystemPath, &status) != 0) {
        return classification;
    }
    if (S_ISREG(status.st_mode)) {
        classification.contains_macho = broker_command_is_macho(fileSystemPath);
        classification.contains_springboard_tweak =
            classification.contains_macho &&
            relative_path_is_springboard_tweak([path lastPathComponent]);
        classification.contains_ellekit_injector =
            classification.contains_macho &&
            relative_path_is_ellekit_injector([path lastPathComponent]);
        return classification;
    }
    if (!S_ISDIR(status.st_mode)) {
        return classification;
    }
    NSDirectoryEnumerator<NSString *> *enumerator =
        [[NSFileManager defaultManager] enumeratorAtPath:path];
    for (NSString *relativePath in enumerator) {
        NSString *candidate = [path stringByAppendingPathComponent:relativePath];
        if (lstat([candidate fileSystemRepresentation], &status) == 0 &&
            S_ISREG(status.st_mode) &&
            broker_command_is_macho([candidate fileSystemRepresentation])) {
            bool springBoardTweak =
                relative_path_is_springboard_tweak(relativePath);
            bool elleKitInjector =
                relative_path_is_ellekit_injector(relativePath);
            classification.contains_macho = true;
            classification.contains_springboard_tweak |= springBoardTweak;
            classification.contains_ellekit_injector |= elleKitInjector;
        }
    }
    return classification;
}

static bool sbinject_infrastructure_ready(const char *reason) {
    bool validator = access(
        [kSBInjectPackageValidatorExecutable fileSystemRepresentation], X_OK) ==
        0;
    bool loader =
        access([kElleKitInjectorExecutable fileSystemRepresentation], X_OK) == 0;
    bool jitterd =
        access([kSBInjectJitterdExecutable fileSystemRepresentation], X_OK) == 0;
    bool launchdHook =
        access([kSBInjectLaunchdHook fileSystemRepresentation], R_OK) == 0;
    bool generalHook =
        access([kSBInjectGeneralHook fileSystemRepresentation], R_OK) == 0;
    bool candidate = access(
        [kSpringBoardCandidateExecutable fileSystemRepresentation], X_OK) == 0;
    bool bundleHook =
        access([kSBInjectBundleHook fileSystemRepresentation], R_OK) == 0;
    bool elleKit =
        access([kElleKitInjectorDylib fileSystemRepresentation], R_OK) == 0;
    bool amfidHook =
        access([kSBInjectAmfidHook fileSystemRepresentation], R_OK) == 0;
    bool amfidCandidate =
        access([kAmfidCandidateExecutable fileSystemRepresentation], X_OK) ==
        0;
    log_message("sbinjectInfrastructure reason=%s validator=%s loader=%s "
                "jitterd=%s launchdHook=%s generalHook=%s candidate=%s "
                "bundleHook=%s elleKit=%s amfidHook=%s amfidCandidate=%s "
                "dynamicTrustCache=disabled",
                reason, validator ? "ready" : "missing",
                loader ? "ready" : "missing",
                jitterd ? "ready" : "missing",
                launchdHook ? "ready" : "missing",
                generalHook ? "ready" : "missing",
                candidate ? "ready" : "missing",
                bundleHook ? "ready" : "missing",
                elleKit ? "ready" : "missing",
                amfidHook ? "ready" : "missing",
                amfidCandidate ? "ready" : "missing");
    return validator && loader && jitterd && launchdHook && generalHook &&
           candidate && bundleHook && amfidHook && amfidCandidate;
}

static bool broker_command_is_named(const char *resolvedCommand,
                                    const char *name) {
    if (resolvedCommand == NULL || name == NULL) {
        return false;
    }
    const char *lastSlash = strrchr(resolvedCommand, '/');
    const char *baseName = lastSlash != NULL ? lastSlash + 1 : resolvedCommand;
    return strcmp(baseName, name) == 0;
}

static bool is_hex_character(char character) {
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f') ||
           (character >= 'A' && character <= 'F');
}

static bool is_managed_documents_deb_path(const char *path) {
    static const char prefix[] =
        "/private/var/mobile/Containers/Data/Application/";
    static const char documents[] = "/Documents/";
    if (path == NULL || strncmp(path, prefix, sizeof(prefix) - 1U) != 0 ||
        strstr(path, "/../") != NULL || strstr(path, "/./") != NULL) {
        return false;
    }
    const char *identifier = path + sizeof(prefix) - 1U;
    for (size_t index = 0; index < 36U; ++index) {
        bool separator = index == 8U || index == 13U || index == 18U ||
                         index == 23U;
        if ((separator && identifier[index] != '-') ||
            (!separator && !is_hex_character(identifier[index]))) {
            return false;
        }
    }
    const char *leaf = identifier + 36U;
    if (strncmp(leaf, documents, sizeof(documents) - 1U) != 0) {
        return false;
    }
    leaf += sizeof(documents) - 1U;
    size_t leafLength = strnlen(leaf, NAME_MAX + 1U);
    if (leafLength <= strlen(".deb") || leafLength > NAME_MAX ||
        strchr(leaf, '/') != NULL ||
        strcmp(leaf + leafLength - strlen(".deb"), ".deb") != 0) {
        return false;
    }
    struct stat status;
    return lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
           status.st_uid == 501 && status.st_nlink == 1 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool headless_sileo_request_allowed(
    char *const arguments[], uint32_t argumentCount,
    char *const controlEnvironment[], uint32_t controlEnvironmentCount,
    const int descriptorNumbers[], uint32_t descriptorCount,
    const char *resolvedCommand) {
    (void)controlEnvironment;
    if (controlEnvironmentCount != 0 || descriptorCount == 0) {
        return false;
    }
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        if (descriptorNumbers[index] != STDOUT_FILENO &&
            descriptorNumbers[index] != STDERR_FILENO) {
            return false;
        }
    }
    if (broker_command_is_named(resolvedCommand, "whoami")) {
        return argumentCount == 1 && descriptorCount == 1 &&
               descriptorNumbers[0] == STDOUT_FILENO;
    }
    return broker_command_is_named(resolvedCommand, "dpkg") &&
           argumentCount == 3 && strcmp(arguments[1], "-i") == 0 &&
           is_managed_documents_deb_path(arguments[2]);
}

static bool sbinject_validate_deb_paths(NSArray<NSString *> *paths,
                                        const char *reason) {
    if (paths.count == 0) {
        return true;
    }
    char stagingTemplate[] = "/var/tmp/sbinject-package.XXXXXX";
    char *stagingPath = mkdtemp(stagingTemplate);
    if (stagingPath == NULL) {
        log_message("sbinjectPackageStageFailed reason=%s error=%s", reason,
                    strerror(errno));
        return false;
    }
    NSString *staging = [NSString stringWithUTF8String:stagingPath];
    bool success = true;
    NSUInteger extracted = 0;
    for (NSString *path in paths) {
        struct stat status;
        if (![path hasPrefix:@"/"] || ![path hasSuffix:@".deb"] ||
            lstat([path fileSystemRepresentation], &status) != 0 ||
            !S_ISREG(status.st_mode)) {
            log_message("sbinjectPackageRejected reason=%s path=%s",
                        reason, [path UTF8String]);
            success = false;
            break;
        }
        char *arguments[] = {
            "/var/jb/usr/bin/dpkg-deb", "-x",
            (char *)[path fileSystemRepresentation], stagingPath, NULL};
        char captureTemplate[] = "/var/tmp/sbinject-package-extract.XXXXXX";
        int capture = mkstemp(captureTemplate);
        if (capture >= 0) {
            (void)unlink(captureTemplate);
        }
        int extractStatus = capture >= 0
            ? run_and_wait_bounded_to_fd(arguments[0], arguments, 30000,
                                         capture)
            : run_and_wait_bounded(arguments[0], arguments, 30000);
        if (capture >= 0) {
            char output[4096] = {0};
            if (lseek(capture, 0, SEEK_SET) >= 0) {
                ssize_t outputLength;
                do {
                    outputLength = read(capture, output, sizeof(output) - 1U);
                } while (outputLength < 0 && errno == EINTR);
                if (outputLength > 0) {
                    for (ssize_t index = 0; index < outputLength; ++index) {
                        unsigned char character = (unsigned char)output[index];
                        if (character == '\n' || character == '\r' ||
                            character == '\t' || character < 0x20U) {
                            output[index] = ' ';
                        }
                    }
                    log_message("sbinjectPackageExtractOutput path=%s "
                                "output=%s",
                                [path UTF8String], output);
                }
            }
            close(capture);
        }
        log_message("sbinjectPackageExtract path=%s status=%d",
                    [path UTF8String], extractStatus);
        if (extractStatus != 0) {
            success = false;
            break;
        }
        ++extracted;
    }
    codex_payload_classification_t classification =
        success && extracted != 0
            ? classify_payload(staging)
            : (codex_payload_classification_t){0};
    bool containsMachO = classification.contains_macho;
    bool requiresSBInject = classification.contains_springboard_tweak ||
                            classification.contains_ellekit_injector;
    bool elleKitAvailable =
        classification.contains_ellekit_injector ||
        access([kElleKitInjectorDylib fileSystemRepresentation], R_OK) == 0;
    bool sbinjectReady =
        success && requiresSBInject && elleKitAvailable &&
        access([kSBInjectCrashMarker fileSystemRepresentation], F_OK) != 0 &&
        sbinject_infrastructure_ready("package-pre-install") &&
        access([kSpringBoardCandidateExecutable fileSystemRepresentation],
               X_OK) == 0 &&
        access([kSBInjectBundleHook fileSystemRepresentation], R_OK) == 0;
    if (success && requiresSBInject && !sbinjectReady) {
        log_message("sbinjectPackageAdmission=false reason=%s "
                    "cause=sbinject-unavailable elleKitAvailable=%s "
                    "dynamicTrustCache=disabled",
                    reason, elleKitAvailable ? "true" : "false");
        success = false;
    }
    bool respringMarked = false;
    if (success && sbinjectReady) {
        NSString *markerError = nil;
        respringMarked = ensure_root_owned_empty_file(
            [kSBInjectRespringMarker fileSystemRepresentation], 0644,
            &markerError);
        log_message("sbinjectPackageRespringMarker ready=%s error=%s",
                    respringMarked ? "true" : "false",
                    markerError != nil
                        ? [[markerError description] UTF8String]
                        : "none");
        if (!respringMarked) {
            success = false;
        }
    }
    int admissionStatus = success && extracted != 0 ? 0 : 1;
    if (extracted != 0) {
        NSString *recordDirectory = @"/var/jb/var/lib/sbinject";
        NSError *recordError = nil;
        BOOL directoryReady = [[NSFileManager defaultManager]
            createDirectoryAtPath:recordDirectory
      withIntermediateDirectories:YES
                       attributes:@{
                           NSFilePosixPermissions : @0755,
                           NSFileOwnerAccountID : @0,
                           NSFileGroupOwnerAccountID : @0,
                       }
                            error:&recordError];
        NSDictionary *record = @{
            @"Backend" : @"sbinject-jit-v1",
            @"AdmissionMode" : sbinjectReady
                ? @"springboard-pre-main-jit-dyld-bypass"
                : (containsMachO ? @"installed-without-execution-admission"
                                 : @"data-or-script-payload"),
            @"Reason" : [NSString stringWithUTF8String:reason],
            @"Archives" : paths,
            @"ArchiveCount" : @(extracted),
            @"ContainsMachO" : @(containsMachO),
            @"ContainsSpringBoardTweak" :
                @(classification.contains_springboard_tweak),
            @"ContainsElleKitInjector" :
                @(classification.contains_ellekit_injector),
            @"SBInjectPayloadAdmission" : @(sbinjectReady),
            @"RespringMarked" : @(respringMarked),
            @"DynamicTrustCacheUsed" : @NO,
            @"AdmissionStatus" : @(admissionStatus),
            @"RecordedAt" : [NSDate date],
        };
        NSString *recordPath = [recordDirectory
            stringByAppendingPathComponent:@"last-package-transaction.plist"];
        BOOL recorded = directoryReady &&
                        [record writeToFile:recordPath atomically:YES];
        log_message("sbinjectPackageRecord path=%s recorded=%s error=%s",
                    [recordPath UTF8String], recorded ? "true" : "false",
                    recordError != nil
                        ? [[recordError description] UTF8String]
                        : "none");
    }
    NSError *cleanupError = nil;
    if (![[NSFileManager defaultManager] removeItemAtPath:staging
                                                    error:&cleanupError]) {
        log_message("sbinjectPackageCleanup path=%s error=%s",
                    [staging UTF8String],
                    [[cleanupError description] UTF8String]);
    }
    log_message("sbinjectPackageResult reason=%s archives=%lu macho=%s "
                "springBoardTweak=%s sbinjectAdmission=%s "
                "admissionStatus=%d backend=sbinject-jit-v1 "
                "dynamicTrustCache=false respringMarked=%s status=%s",
                reason, (unsigned long)extracted,
                containsMachO ? "true" : "false",
                classification.contains_springboard_tweak ? "true" : "false",
                sbinjectReady ? "true" : "false", admissionStatus,
                respringMarked ? "true" : "false",
                success ? "success" : "failed");
    return success;
}

static bool sbinject_validate_debs_from_standard_input(void) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length = 0;
    while ((length = getline(&line, &capacity, stdin)) >= 0) {
        while (length > 0 &&
               (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            line[--length] = '\0';
        }
        if (length > 0 && line[0] == '/') {
            [paths addObject:[NSString stringWithUTF8String:line]];
        }
    }
    free(line);
    return sbinject_validate_deb_paths(paths, "apt-pre-install");
}

static bool rewrite_rootless_maintainer_shebang(NSString *path,
                                                bool *changed,
                                                NSString **errorText) {
    if (changed != NULL) {
        *changed = false;
    }
    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfFile:path
                                          options:0
                                            error:&readError];
    if (data == nil || data.length == 0 || data.length > 16U * 1024U * 1024U) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"maintainer script read failed: %@", readError];
        }
        return false;
    }
    const uint8_t *bytes = data.bytes;
    NSUInteger newline = 0;
    while (newline < data.length && bytes[newline] != '\n') {
        ++newline;
    }
    if (newline == data.length || newline > 256U) {
        return true;
    }
    NSString *firstLine = [[NSString alloc]
        initWithBytes:bytes
               length:newline
             encoding:NSUTF8StringEncoding];
    NSDictionary<NSString *, NSString *> *replacements = @{
        @"#!/bin/sh" : @"#!/var/jb/bin/sh",
        @"#!/bin/bash" : @"#!/var/jb/bin/bash",
        @"#!/usr/bin/env sh" : @"#!/var/jb/bin/sh",
        @"#!/usr/bin/env bash" : @"#!/var/jb/bin/bash",
    };
    NSString *replacement = replacements[firstLine];
    if (replacement == nil) {
        return true;
    }
    NSMutableData *rewritten = [NSMutableData data];
    NSData *prefix = [[replacement stringByAppendingString:@"\n"]
        dataUsingEncoding:NSUTF8StringEncoding];
    [rewritten appendData:prefix];
    if (newline + 1U < data.length) {
        [rewritten appendBytes:bytes + newline + 1U
                        length:data.length - newline - 1U];
    }
    NSError *writeError = nil;
    if (![rewritten writeToFile:path options:NSDataWritingAtomic
                          error:&writeError] ||
        ![[NSFileManager defaultManager]
            setAttributes:@{
                NSFilePosixPermissions : @0755,
                NSFileOwnerAccountID : @0,
                NSFileGroupOwnerAccountID : @0,
            }
             ofItemAtPath:path
                    error:&writeError]) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"maintainer shebang rewrite failed: %@", writeError];
        }
        return false;
    }
    if (changed != NULL) {
        *changed = true;
    }
    log_message("sbinjectMaintainerShebang path=%s from=%s to=%s",
                [path UTF8String], [firstLine UTF8String],
                [replacement UTF8String]);
    return true;
}

static bool sbinject_valid_package_name(NSString *name) {
    const char *text = [name UTF8String];
    if (text == NULL) {
        return false;
    }
    size_t length = strlen(text);
    if (length < 2U || length > 200U ||
        !((text[0] >= 'a' && text[0] <= 'z') ||
          (text[0] >= '0' && text[0] <= '9'))) {
        return false;
    }
    for (size_t index = 1; index < length; ++index) {
        char character = text[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '+' ||
              character == '-' || character == '.')) {
            return false;
        }
    }
    return true;
}

static NSString *sbinject_package_name_from_spec(const char *argument,
                                                 bool *removalOut) {
    if (removalOut != NULL) {
        *removalOut = false;
    }
    if (argument == NULL || argument[0] == '\0' || argument[0] == '-') {
        return nil;
    }
    NSString *spec = [NSString stringWithUTF8String:argument];
    if (spec == nil || [spec containsString:@"/"]) {
        return nil;
    }
    bool removal = [spec hasSuffix:@"-"] && spec.length > 1U;
    if (removal) {
        spec = [spec substringToIndex:spec.length - 1U];
    }
    NSRange version = [spec rangeOfString:@"="];
    if (version.location != NSNotFound) {
        spec = [spec substringToIndex:version.location];
    }
    NSRange architecture = [spec rangeOfString:@":"];
    if (architecture.location != NSNotFound) {
        spec = [spec substringToIndex:architecture.location];
    }
    if (!sbinject_valid_package_name(spec)) {
        return nil;
    }
    if (removalOut != NULL) {
        *removalOut = removal;
    }
    return spec;
}

static NSString *sbinject_package_name_from_control(NSString *controlPath,
                                                    NSString **errorText) {
    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfFile:controlPath
                                          options:0
                                            error:&readError];
    if (data == nil || data.length == 0 || data.length > 1024U * 1024U) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"maintainer control read failed: %@", readError];
        }
        return nil;
    }
    NSString *control = [[NSString alloc] initWithData:data
                                               encoding:NSUTF8StringEncoding];
    for (NSString *line in
         [control componentsSeparatedByCharactersInSet:
                      [NSCharacterSet newlineCharacterSet]]) {
        if (![line hasPrefix:@"Package:"]) {
            continue;
        }
        NSString *name = [[line substringFromIndex:strlen("Package:")]
            stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (sbinject_valid_package_name(name)) {
            return name;
        }
        break;
    }
    if (errorText != NULL) {
        *errorText = [NSString stringWithFormat:
            @"invalid or missing Package field in %@", controlPath];
    }
    return nil;
}

static bool sbinject_write_installed_macho_wrapper(NSString *script,
                                                   NSString *phase,
                                                   NSString **errorText) {
    NSString *guest = [script stringByAppendingString:@".sbinject-macho"];
    struct stat guestStatus;
    if (lstat([guest fileSystemRepresentation], &guestStatus) == 0) {
        if (!S_ISREG(guestStatus.st_mode) || S_ISLNK(guestStatus.st_mode) ||
            guestStatus.st_size <= 0 ||
            guestStatus.st_size > 16 * 1024 * 1024) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"unsafe existing maintainer guest: %@", guest];
            }
            return false;
        }
        if (unlink([guest fileSystemRepresentation]) != 0) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"maintainer guest replacement failed: %s",
                    strerror(errno)];
            }
            return false;
        }
    } else if (errno != ENOENT) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"maintainer guest status failed: %s", strerror(errno)];
        }
        return false;
    }
    if (rename([script fileSystemRepresentation],
               [guest fileSystemRepresentation]) != 0) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"maintainer binary staging failed: %s", strerror(errno)];
        }
        return false;
    }
    NSString *wrapper = [NSString stringWithFormat:
        @"#!/var/jb/bin/sh\n"
         "exec /var/jb/usr/libexec/codex-exec-worker --macho \"%@\" \"$@\"\n",
        guest];
    NSError *wrapperError = nil;
    BOOL wrote = [wrapper writeToFile:script
                           atomically:YES
                             encoding:NSUTF8StringEncoding
                                error:&wrapperError] &&
        [[NSFileManager defaultManager]
            setAttributes:@{
                NSFilePosixPermissions : @0755,
                NSFileOwnerAccountID : @0,
                NSFileGroupOwnerAccountID : @0,
            }
             ofItemAtPath:script
                    error:&wrapperError] &&
        [[NSFileManager defaultManager]
            setAttributes:@{
                NSFilePosixPermissions : @0755,
                NSFileOwnerAccountID : @0,
                NSFileGroupOwnerAccountID : @0,
            }
             ofItemAtPath:guest
                    error:&wrapperError];
    if (!wrote) {
        (void)unlink([script fileSystemRepresentation]);
        (void)rename([guest fileSystemRepresentation],
                     [script fileSystemRepresentation]);
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"maintainer wrapper write failed: %@", wrapperError];
        }
        return false;
    }
    log_message("sbinjectInstalledMaintainerMachO path=%s phase=%s "
                "backend=jit-rw-to-rx",
                [script UTF8String], [phase UTF8String]);
    return true;
}

static bool sbinject_package_owns_springboard_tweak(NSString *packageName) {
    NSString *list = [NSString stringWithFormat:
        @"/var/jb/Library/dpkg/info/%@.list", packageName];
    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfFile:list
                                          options:NSDataReadingMappedIfSafe
                                            error:&readError];
    if (data == nil || data.length == 0 || data.length > 32U * 1024U * 1024U) {
        return false;
    }
    NSString *contents = [[NSString alloc] initWithData:data
                                                encoding:NSUTF8StringEncoding];
    for (NSString *path in
         [contents componentsSeparatedByCharactersInSet:
                       [NSCharacterSet newlineCharacterSet]]) {
        if (relative_path_is_springboard_tweak(path)) {
            return true;
        }
    }
    return false;
}

static NSArray<NSString *> *sbinject_all_maintainer_packages(
    NSString **errorText) {
    NSString *directory = @"/var/jb/Library/dpkg/info";
    NSError *directoryError = nil;
    NSArray<NSString *> *entries = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:directory
                           error:&directoryError];
    if (entries == nil) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"installed maintainer directory read failed: %@",
                directoryError];
        }
        return nil;
    }
    NSArray<NSString *> *suffixes =
        @[@".preinst", @".postinst", @".prerm", @".postrm", @".config"];
    NSMutableOrderedSet<NSString *> *packages =
        [NSMutableOrderedSet orderedSet];
    for (NSString *entry in entries) {
        for (NSString *suffix in suffixes) {
            if (![entry hasSuffix:suffix] || entry.length <= suffix.length) {
                continue;
            }
            NSString *name =
                [entry substringToIndex:entry.length - suffix.length];
            if (sbinject_valid_package_name(name)) {
                [packages addObject:name];
            }
            break;
        }
    }
    return packages.array;
}

static bool sbinject_prepare_installed_maintainers(
    NSArray<NSString *> *packageNames, bool markTweakRemoval,
    NSString **errorText) {
    NSMutableOrderedSet<NSString *> *packages =
        [NSMutableOrderedSet orderedSet];
    for (NSString *packageName in packageNames) {
        if (sbinject_valid_package_name(packageName)) {
            [packages addObject:packageName];
        }
    }
    NSArray<NSString *> *phases =
        @[@"preinst", @"postinst", @"prerm", @"postrm", @"config"];
    NSUInteger rewritten = 0;
    bool ownsTweak = false;
    for (NSString *packageName in packages) {
        ownsTweak |= markTweakRemoval &&
                     sbinject_package_owns_springboard_tweak(packageName);
        for (NSString *phase in phases) {
            NSString *script = [NSString stringWithFormat:
                @"/var/jb/Library/dpkg/info/%@.%@", packageName, phase];
            struct stat status;
            if (lstat([script fileSystemRepresentation], &status) != 0) {
                if (errno == ENOENT) {
                    continue;
                }
                if (errorText != NULL) {
                    *errorText = [NSString stringWithFormat:
                        @"installed maintainer status failed: %@", script];
                }
                return false;
            }
            if (!S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
                status.st_size <= 0 || status.st_size > 16 * 1024 * 1024) {
                if (errorText != NULL) {
                    *errorText = [NSString stringWithFormat:
                        @"unsafe installed maintainer script: %@", script];
                }
                return false;
            }
            if (broker_command_is_macho([script fileSystemRepresentation])) {
                if (!sbinject_write_installed_macho_wrapper(
                        script, phase, errorText)) {
                    return false;
                }
                ++rewritten;
                continue;
            }
            bool shebangChanged = false;
            if (!rewrite_rootless_maintainer_shebang(
                    script, &shebangChanged, errorText)) {
                return false;
            }
            rewritten += shebangChanged ? 1U : 0U;
        }
    }
    if (ownsTweak) {
        NSString *markerError = nil;
        if (!ensure_root_owned_empty_file(
                [kSBInjectRespringMarker fileSystemRepresentation], 0644,
                &markerError)) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"removal respring marker failed: %@", markerError];
            }
            return false;
        }
    }
    log_message("sbinjectInstalledMaintainers packages=%lu rewritten=%lu "
                "removal=%s springBoardTweak=%s backend=jit-rw-to-rx",
                (unsigned long)packages.count, (unsigned long)rewritten,
                markTweakRemoval ? "true" : "false",
                ownsTweak ? "true" : "false");
    return true;
}

static NSArray<NSString *> *sbinject_prepare_maintainer_archives(
    NSArray<NSString *> *archives, NSString **stagingOut,
    NSArray<NSString *> **packageNamesOut, bool *managedOut,
    NSString **errorText) {
    if (stagingOut != NULL) {
        *stagingOut = nil;
    }
    if (packageNamesOut != NULL) {
        *packageNamesOut = nil;
    }
    if (managedOut != NULL) {
        *managedOut = false;
    }
    if (archives.count == 0 || archives.count > 128U) {
        if (errorText != NULL) {
            *errorText = @"invalid maintainer archive count";
        }
        return nil;
    }
    char stagingTemplate[] =
        "/var/jb/var/cache/sbinject-maintainers.XXXXXX";
    char *stagingBytes = mkdtemp(stagingTemplate);
    if (stagingBytes == NULL) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"maintainer staging failed: %s", strerror(errno)];
        }
        return nil;
    }
    NSString *staging = [NSString stringWithUTF8String:stagingBytes];
    NSMutableArray<NSString *> *prepared = [NSMutableArray array];
    NSMutableOrderedSet<NSString *> *packageNames =
        [NSMutableOrderedSet orderedSet];
    bool anyRewritten = false;
    bool managedLifecycle = false;
    NSString *failure = nil;
    NSArray<NSString *> *scriptNames =
        @[@"preinst", @"postinst", @"prerm", @"postrm", @"config"];
    for (NSUInteger index = 0; index < archives.count; ++index) {
        NSString *archive = archives[index];
        NSString *root = [staging stringByAppendingPathComponent:
            [NSString stringWithFormat:@"package-%03lu",
                                       (unsigned long)index]];
        char *extractArguments[] = {
            "/var/jb/usr/bin/dpkg-deb", "-R",
            (char *)[archive fileSystemRepresentation],
            (char *)[root fileSystemRepresentation], NULL};
        int extractStatus = run_and_wait_bounded(
            extractArguments[0], extractArguments, 30000);
        if (extractStatus != 0) {
            failure = [NSString stringWithFormat:
                @"maintainer archive extraction exited %d", extractStatus];
            break;
        }
        bool archiveRewritten = false;
        NSString *control = [root stringByAppendingPathComponent:@"DEBIAN"];
        NSString *packageName = sbinject_package_name_from_control(
            [control stringByAppendingPathComponent:@"control"], &failure);
        if (packageName == nil) {
            break;
        }
        [packageNames addObject:packageName];
        for (NSString *scriptName in scriptNames) {
            NSString *script =
                [control stringByAppendingPathComponent:scriptName];
            struct stat scriptStatus;
            if (lstat([script fileSystemRepresentation], &scriptStatus) != 0) {
                if (errno == ENOENT) {
                    continue;
                }
                failure = [NSString stringWithFormat:
                    @"maintainer script status failed: %@", script];
                break;
            }
            if (!S_ISREG(scriptStatus.st_mode) ||
                scriptStatus.st_size <= 0 ||
                scriptStatus.st_size > 16 * 1024 * 1024) {
                failure = [NSString stringWithFormat:
                    @"invalid maintainer script: %@", script];
                break;
            }
            if (broker_command_is_macho(
                    [script fileSystemRepresentation])) {
                managedLifecycle = true;
                if (![scriptName isEqualToString:@"preinst"]) {
                    log_message("sbinjectMaintainerMachO archive=%s "
                                "package=%s phase=%s action=defer-to-info "
                                "backend=jit-rw-to-rx",
                                [archive UTF8String],
                                [packageName UTF8String],
                                [scriptName UTF8String]);
                    continue;
                }
                NSString *guest =
                    [script stringByAppendingString:@".sbinject-macho"];
                if (rename([script fileSystemRepresentation],
                           [guest fileSystemRepresentation]) != 0) {
                    failure = [NSString stringWithFormat:
                        @"maintainer binary staging failed: %s",
                        strerror(errno)];
                    break;
                }
                NSString *wrapper = [NSString stringWithFormat:
                    @"#!/var/jb/bin/sh\n"
                     "script_dir=${0%%/*}\n"
                     "exec /var/jb/usr/libexec/codex-exec-worker --macho "
                     "\"$script_dir/%@.sbinject-macho\" \"$@\"\n",
                    scriptName];
                NSError *wrapperError = nil;
                if (![wrapper writeToFile:script
                                atomically:YES
                                  encoding:NSUTF8StringEncoding
                                     error:&wrapperError] ||
                    ![[NSFileManager defaultManager]
                        setAttributes:@{
                            NSFilePosixPermissions : @0755,
                            NSFileOwnerAccountID : @0,
                            NSFileGroupOwnerAccountID : @0,
                        }
                         ofItemAtPath:script
                                error:&wrapperError]) {
                    failure = [NSString stringWithFormat:
                        @"maintainer wrapper write failed: %@", wrapperError];
                    break;
                }
                archiveRewritten = true;
                log_message("sbinjectMaintainerMachO archive=%s phase=%s "
                            "backend=jit-rw-to-rx",
                            [archive UTF8String], [scriptName UTF8String]);
            } else {
                bool shebangChanged = false;
                if (!rewrite_rootless_maintainer_shebang(
                        script, &shebangChanged, &failure)) {
                    break;
                }
                archiveRewritten |= shebangChanged;
                managedLifecycle |= shebangChanged;
            }
        }
        if (failure != nil) {
            break;
        }
        if (!archiveRewritten) {
            [prepared addObject:archive];
            continue;
        }
        NSString *output = [staging
            stringByAppendingPathComponent:[archive lastPathComponent]];
        char *buildArguments[] = {
            "/var/jb/usr/bin/dpkg-deb", "--root-owner-group", "-b",
            (char *)[root fileSystemRepresentation],
            (char *)[output fileSystemRepresentation], NULL};
        int buildStatus = run_and_wait_bounded(
            buildArguments[0], buildArguments, 30000);
        if (buildStatus != 0) {
            failure = [NSString stringWithFormat:
                @"maintainer archive rebuild exited %d", buildStatus];
            break;
        }
        [prepared addObject:output];
        anyRewritten = true;
    }
    if (failure == nil && anyRewritten &&
        !sbinject_validate_deb_paths(prepared,
                                    "sileo-maintainer-repack")) {
        failure = @"rewritten maintainer archive validation failed";
    }
    if (failure != nil) {
        [[NSFileManager defaultManager] removeItemAtPath:staging error:nil];
        if (errorText != NULL) {
            *errorText = failure;
        }
        return nil;
    }
    if (packageNamesOut != NULL) {
        *packageNamesOut = packageNames.array;
    }
    if (managedOut != NULL) {
        *managedOut = managedLifecycle;
    }
    if (!anyRewritten) {
        [[NSFileManager defaultManager] removeItemAtPath:staging error:nil];
        return archives;
    }
    if (stagingOut != NULL) {
        *stagingOut = staging;
    }
    log_message("sbinjectMaintainerResult archives=%lu rewritten=true "
                "managed=%s packages=%lu backend=jit-rw-to-rx "
                "dynamicTrustCache=false",
                (unsigned long)archives.count,
                managedLifecycle ? "true" : "false",
                (unsigned long)packageNames.count);
    return prepared;
}

static NSArray<NSString *> *sbinject_deb_paths_from_arguments(
    char *const arguments[]) {
    NSMutableOrderedSet<NSString *> *paths =
        [NSMutableOrderedSet orderedSet];
    for (NSUInteger index = 1;
         index <= CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
         arguments[index] != NULL;
         ++index) {
        NSString *path = [NSString stringWithUTF8String:arguments[index]];
        if ([path hasPrefix:@"/"] &&
            [[path pathExtension] caseInsensitiveCompare:@"deb"] ==
                NSOrderedSame) {
            [paths addObject:path];
        }
    }
    return paths.array;
}

static NSArray<NSString *> *sbinject_apt_removal_packages(
    char *const arguments[], bool *scanAllOut) {
    if (scanAllOut != NULL) {
        *scanAllOut = false;
    }
    enum {
        kAptActionNone,
        kAptActionInstall,
        kAptActionRemove,
        kAptActionPurge,
        kAptActionAutoremove,
    } action = kAptActionNone;
    NSMutableOrderedSet<NSString *> *packages =
        [NSMutableOrderedSet orderedSet];
    for (NSUInteger index = 1;
         index <= CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
         arguments[index] != NULL;
         ++index) {
        const char *argument = arguments[index];
        if (strcmp(argument, "install") == 0) {
            action = kAptActionInstall;
            continue;
        }
        if (strcmp(argument, "remove") == 0) {
            action = kAptActionRemove;
            continue;
        }
        if (strcmp(argument, "purge") == 0) {
            action = kAptActionPurge;
            continue;
        }
        if (strcmp(argument, "autoremove") == 0) {
            action = kAptActionAutoremove;
            if (scanAllOut != NULL) {
                *scanAllOut = true;
            }
            continue;
        }
        bool removal = false;
        NSString *packageName =
            sbinject_package_name_from_spec(argument, &removal);
        if (packageName != nil &&
            ((action == kAptActionInstall && removal) ||
             action == kAptActionRemove || action == kAptActionPurge ||
             action == kAptActionAutoremove)) {
            [packages addObject:packageName];
        }
    }
    return packages.array;
}

static NSArray<NSString *> *sbinject_dpkg_removal_packages(
    char *const arguments[], bool *configureAllOut) {
    if (configureAllOut != NULL) {
        *configureAllOut = false;
    }
    bool removalAction = false;
    NSMutableOrderedSet<NSString *> *packages =
        [NSMutableOrderedSet orderedSet];
    for (NSUInteger index = 1;
         index <= CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
         arguments[index] != NULL;
         ++index) {
        const char *argument = arguments[index];
        if (strcmp(argument, "--remove") == 0 ||
            strcmp(argument, "--purge") == 0 ||
            strcmp(argument, "-r") == 0 || strcmp(argument, "-P") == 0) {
            removalAction = true;
            continue;
        }
        if (strcmp(argument, "--configure") == 0 ||
            strcmp(argument, "--pending") == 0 ||
            strcmp(argument, "-a") == 0) {
            if (configureAllOut != NULL) {
                *configureAllOut = true;
            }
        }
        if (!removalAction) {
            continue;
        }
        NSString *packageName =
            sbinject_package_name_from_spec(argument, NULL);
        if (packageName != nil) {
            [packages addObject:packageName];
        }
    }
    return packages.array;
}

static bool sbinject_build_apt_reconcile_arguments(
    char *const arguments[], char *output[], size_t outputCapacity) {
    size_t outputIndex = 0;
    bool noDownload = false;
    for (size_t input = 0;
         input < CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
         arguments[input] != NULL;
         ++input) {
        const char *argument = arguments[input];
        if (strcmp(argument, "--reinstall") == 0 ||
            strncmp(argument, "-oAPT::Status-Fd=", 17U) == 0 ||
            strncmp(argument, "-oAPT::Keep-Fds::=", 18U) == 0) {
            continue;
        }
        if (strcmp(argument, "reinstall") == 0) {
            argument = "install";
        }
        noDownload |= strcmp(argument, "--no-download") == 0;
        if (outputIndex + 2U >= outputCapacity) {
            return false;
        }
        output[outputIndex++] = (char *)argument;
    }
    if (!noDownload) {
        if (outputIndex + 2U >= outputCapacity) {
            return false;
        }
        output[outputIndex++] = "--no-download";
    }
    output[outputIndex] = NULL;
    return outputIndex > 1U;
}

static bool broker_spawn_error_is_admission_failure(int error) {
    if (error == EACCES || error == EPERM || error == ENOEXEC) {
        return true;
    }
#ifdef EBADEXEC
    if (error == EBADEXEC) {
        return true;
    }
#endif
#ifdef EBADARCH
    if (error == EBADARCH) {
        return true;
    }
#endif
    return false;
}

static bool exact_empty_root_marker(NSString *path) {
    struct stat status;
    return lstat([path fileSystemRepresentation], &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 && status.st_uid == 0 && status.st_gid == 0 &&
           status.st_size == 0 && (status.st_mode & 07777) == 0644;
}

static bool sbinject_boot_fresh_marker(NSString *path) {
    struct timeval bootTime = {0};
    size_t bootTimeSize = sizeof(bootTime);
    struct stat status;
    return sysctlbyname("kern.boottime", &bootTime, &bootTimeSize, NULL, 0) ==
               0 &&
           bootTimeSize == sizeof(bootTime) &&
           lstat([path fileSystemRepresentation], &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 && status.st_uid == 0 && status.st_gid == 0 &&
           status.st_size == 0 && (status.st_mode & 07777) == 0644 &&
           status.st_mtimespec.tv_sec >= bootTime.tv_sec;
}

static pid_t current_springboard_process(bool *candidateOut) {
    if (candidateOut != NULL) {
        *candidateOut = false;
    }
    int capacity = proc_listallpids(NULL, 0);
    if (capacity <= 0 || capacity > 1024 * 1024) {
        return -1;
    }
    capacity += 32;
    pid_t *processes = calloc((size_t)capacity, sizeof(*processes));
    if (processes == NULL) {
        return -1;
    }
    int count = proc_listallpids(processes, capacity * (int)sizeof(*processes));
    if (count > capacity) {
        count = capacity;
    }
    pid_t result = -1;
    for (int index = 0; index < count; ++index) {
        pid_t pid = processes[index];
        if (pid <= 1) {
            continue;
        }
        char path[CODEX_PROC_PIDPATH_MAX] = {0};
        if (proc_pidpath(pid, path, sizeof(path)) <= 0) {
            continue;
        }
        bool candidate = is_exact_springboard_candidate_process(pid, path);
        bool stock = strcmp(path,
                            "/System/Library/CoreServices/"
                            "SpringBoard.app/SpringBoard") == 0;
        if (candidate || stock) {
            result = pid;
            if (candidateOut != NULL) {
                *candidateOut = candidate;
            }
            break;
        }
    }
    free(processes);
    return result;
}

static pid_t current_preferences_process(bool *candidateOut) {
    if (candidateOut != NULL) {
        *candidateOut = false;
    }
    int capacity = proc_listallpids(NULL, 0);
    if (capacity <= 0 || capacity > 1024 * 1024) {
        return -1;
    }
    capacity += 32;
    pid_t *processes = calloc((size_t)capacity, sizeof(*processes));
    if (processes == NULL) {
        return -1;
    }
    int count = proc_listallpids(processes, capacity * (int)sizeof(*processes));
    if (count <= 0) {
        free(processes);
        return -1;
    }
    if (count > capacity) {
        count = capacity;
    }
    // Distinguish a successful scan with no Preferences process from a proc
    // enumeration failure. Callers may safely consume a pending restart only
    // after the former.
    pid_t result = 0;
    for (int index = 0; index < count; ++index) {
        pid_t pid = processes[index];
        if (pid <= 1) {
            continue;
        }
        char path[CODEX_PROC_PIDPATH_MAX] = {0};
        if (proc_pidpath(pid, path, sizeof(path)) <= 0) {
            continue;
        }
        bool candidate = is_exact_preferences_candidate_process(pid, path);
        bool stock = strcmp(path,
                            "/Applications/Preferences.app/Preferences") == 0;
        if (candidate || stock) {
            result = pid;
            if (candidateOut != NULL) {
                *candidateOut = candidate;
            }
            break;
        }
    }
    free(processes);
    return result;
}

static pid_t current_amfid_process(bool *candidateOut) {
    if (candidateOut != NULL) *candidateOut = false;
    int capacity = proc_listallpids(NULL, 0);
    if (capacity <= 0 || capacity > 1024 * 1024) return -1;
    capacity += 32;
    pid_t *processes = calloc((size_t)capacity, sizeof(*processes));
    if (processes == NULL) return -1;
    int count = proc_listallpids(processes,
                                 capacity * (int)sizeof(*processes));
    if (count > capacity) count = capacity;
    pid_t result = 0;
    for (int index = 0; index < count; ++index) {
        pid_t pid = processes[index];
        if (pid <= 1) continue;
        char path[CODEX_PROC_PIDPATH_MAX] = {0};
        if (proc_pidpath(pid, path, sizeof(path)) <= 0) continue;
        bool candidate = is_exact_amfid_candidate_process(pid, path);
        bool stock = strcmp(path, "/usr/libexec/amfid") == 0;
        if (candidate || stock) {
            result = pid;
            if (candidateOut != NULL) *candidateOut = candidate;
            break;
        }
    }
    free(processes);
    return result;
}

static pid_t current_lsd_process(void) {
    int capacity = proc_listallpids(NULL, 0);
    if (capacity <= 0 || capacity > 1024 * 1024) return -1;
    capacity += 32;
    pid_t *processes = calloc((size_t)capacity, sizeof(*processes));
    if (processes == NULL) return -1;
    int count = proc_listallpids(processes,
                                 capacity * (int)sizeof(*processes));
    if (count > capacity) count = capacity;
    pid_t result = -1;
    for (int index = 0; index < count; ++index) {
        pid_t pid = processes[index];
        if (pid <= 1) continue;
        char path[CODEX_PROC_PIDPATH_MAX] = {0};
        if (proc_pidpath(pid, path, sizeof(path)) > 0 &&
            strcmp(path, "/usr/libexec/lsd") == 0) {
            result = pid;
            break;
        }
    }
    free(processes);
    return result;
}

static bool lsd_registration_marker_matches_process(pid_t expectedPid) {
    struct timeval bootTime = {0};
    size_t bootTimeSize = sizeof(bootTime);
    if (expectedPid <= 1 ||
        sysctlbyname("kern.boottime", &bootTime, &bootTimeSize, NULL, 0) != 0 ||
        bootTimeSize != sizeof(bootTime)) {
        return false;
    }
    int descriptor = open(
        [kSBInjectLsdRegistrationMarker fileSystemRepresentation],
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status = {0};
    char contents[32] = {0};
    ssize_t amount = descriptor >= 0
        ? read(descriptor, contents, sizeof(contents) - 1U) : -1;
    bool shape = descriptor >= 0 && fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_nlink == 1 &&
                 status.st_uid == 501 && status.st_gid == 501 &&
                 status.st_size > 1 &&
                 status.st_size < (off_t)sizeof(contents) &&
                 (status.st_mode & 07777) == 0600 &&
                 status.st_mtimespec.tv_sec >= bootTime.tv_sec &&
                 amount == status.st_size;
    if (descriptor >= 0) close(descriptor);
    if (!shape) return false;
    contents[amount] = '\0';
    errno = 0;
    char *end = NULL;
    long markerPid = strtol(contents, &end, 10);
    return errno == 0 && end != contents && end[0] == '\n' && end[1] == '\0' &&
           markerPid == expectedPid;
}

static bool finish_sbinject_package_transaction(pid_t springBoardBefore,
                                                int commandStatus,
                                                const char *command) {
    if (!WIFEXITED(commandStatus) || WEXITSTATUS(commandStatus) != 0 ||
        !exact_empty_root_marker(kSBInjectRespringMarker)) {
        return true;
    }
    bool preferencesCandidate = false;
    pid_t preferences = current_preferences_process(&preferencesCandidate);
    if (preferencesCandidate && preferences > 1 &&
        exact_empty_root_marker(kSBInjectPreferencesEnableMarker)) {
        int preferencesSignal = kill(preferences, SIGTERM);
        log_message("sbinjectPackagePreferencesRestart command=%s pid=%d "
                    "status=%d error=%d",
                    command, preferences, preferencesSignal,
                    preferencesSignal == 0 ? 0 : errno);
    } else if (preferences > 1 && !preferencesCandidate) {
        bool preferencesActivated = activate_sbinject_preferences();
        log_message("sbinjectPackagePreferencesRestart command=%s "
                    "action=activate status=%s",
                    command,
                    preferencesActivated ? "success" : "failed");
    }
    // Package finalization must not make the user's Now/Later decision for
    // them. Prove that the next SpringBoard launch will take the resigned
    // SBInject route, then leave the respring marker and Sileo UI intact. The
    // bottom-sheet "Respring Now" action enters --sbinject-respring and does
    // the actual signal only after repeating this verification.
    bool prepared =
        prepare_sbinject_redirect("package-transaction-posthook");
    log_message("sbinjectPackagePostHook command=%s before=%d "
                "redirectPrepared=%s respring=deferred-to-sileo",
                command, springBoardBefore, prepared ? "true" : "false");
    return prepared;
}

static int32_t run_root_broker_command(
    int server, int client, char *const arguments[], int descriptors[],
    const int descriptorNumbers[], uint32_t descriptorCount,
    char *const controlEnvironment[], uint32_t controlEnvironmentCount,
    NSString *jailbreakRoot, const char *resolvedCommand) {
    bool dpkgCommand = broker_command_is_named(resolvedCommand, "dpkg");
    bool aptCommand = broker_command_is_named(resolvedCommand, "apt") ||
                      broker_command_is_named(resolvedCommand, "apt-get");
    bool packageTransaction = dpkgCommand || aptCommand;
    bool aptMutation = false;
    bool aptInstall = false;
    bool aptUpgrade = false;
    bool aptSimulation = false;
    if (aptCommand) {
        for (uint32_t index = 1;
             index < CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
             arguments[index] != NULL;
             ++index) {
            const char *argument = arguments[index];
            bool install = strcmp(argument, "install") == 0 ||
                           strcmp(argument, "reinstall") == 0;
            bool upgrade = strcmp(argument, "upgrade") == 0 ||
                           strcmp(argument, "dist-upgrade") == 0 ||
                           strcmp(argument, "full-upgrade") == 0 ||
                           strcmp(argument, "dselect-upgrade") == 0;
            aptInstall |= install;
            aptUpgrade |= upgrade;
            aptMutation |= install ||
                           strcmp(argument, "remove") == 0 ||
                           strcmp(argument, "purge") == 0 ||
                           upgrade ||
                           strcmp(argument, "autoremove") == 0;
            aptSimulation |= strcmp(argument, "-s") == 0 ||
                             strcmp(argument, "-sqf") == 0 ||
                             strcmp(argument, "--simulate") == 0 ||
                             strcmp(argument, "--just-print") == 0 ||
                             strcmp(argument, "--dry-run") == 0 ||
                             strcmp(argument, "--download-only") == 0;
        }
    }
    bool packageMutation =
        dpkgCommand || (aptCommand && aptMutation && !aptSimulation);
    bool aptDownloadMutation = aptInstall || aptUpgrade;
    const char *spawnCommand = resolvedCommand;
    char *const *spawnArguments = arguments;
    char *preparedDpkgArguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 4U] = {0};
    NSArray<NSString *> *preparedArchives = nil;
    NSArray<NSString *> *managedPackageNames = @[];
    NSString *maintainerStaging = nil;
    bool managedDpkgTransaction = false;
    bool aptReconcile = false;

    bool aptScanAllRemovals = false;
    NSArray<NSString *> *aptRemovalPackages = aptCommand && !aptSimulation
        ? sbinject_apt_removal_packages(arguments, &aptScanAllRemovals)
        : @[];
    bool dpkgConfigureAll = false;
    NSArray<NSString *> *dpkgRemovalPackages = dpkgCommand
        ? sbinject_dpkg_removal_packages(arguments, &dpkgConfigureAll)
        : @[];

    if (aptCommand && aptDownloadMutation && !aptSimulation) {
        char *cleanArguments[] = {(char *)resolvedCommand, "clean", NULL};
        int cleanStatus = run_and_wait_bounded(
            resolvedCommand, cleanArguments, 30000);
        log_message("sileoRootBrokerAptCacheClean command=%s status=%d "
                    "transactionScoped=true",
                    resolvedCommand, cleanStatus);
        if (cleanStatus != 0) {
            return (int32_t)(cleanStatus << 8);
        }

        char *prefetchArguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 3U] = {0};
        uint32_t output = 0;
        for (uint32_t input = 0;
             input < CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
             arguments[input] != NULL;
             ++input) {
            const char *argument = arguments[input];
            if (strcmp(argument, "--no-download") == 0 ||
                strncmp(argument, "-oAPT::Status-Fd=", 17U) == 0 ||
                strncmp(argument, "-oAPT::Keep-Fds::=", 18U) == 0) {
                continue;
            }
            if (output + 2U >=
                CODEX_ROOT_BROKER_MAX_ARGUMENTS + 3U) {
                return 73 << 8;
            }
            prefetchArguments[output++] = arguments[input];
        }
        prefetchArguments[output++] = "--download-only";
        prefetchArguments[output] = NULL;
        int prefetchStatus = run_and_wait_bounded(
            resolvedCommand, prefetchArguments, 120000);
        log_message("sileoRootBrokerAptPrefetch command=%s status=%d "
                    "sileoLists=true dynamicTrustCache=false",
                    resolvedCommand, prefetchStatus);
        if (prefetchStatus != 0) {
            return (int32_t)(prefetchStatus << 8);
        }
        NSString *archiveDirectory = @"/var/jb/var/cache/apt/archives";
        NSError *archiveError = nil;
        NSArray<NSString *> *archiveEntries =
            [[[NSFileManager defaultManager]
                contentsOfDirectoryAtPath:archiveDirectory
                                     error:&archiveError]
                sortedArrayUsingSelector:@selector(compare:)];
        NSMutableArray<NSString *> *archives = [NSMutableArray array];
        for (NSString *entry in archiveEntries) {
            if ([[entry pathExtension]
                    caseInsensitiveCompare:@"deb"] == NSOrderedSame) {
                [archives addObject:
                    [archiveDirectory stringByAppendingPathComponent:entry]];
            }
        }
        if (archiveError != nil ||
            (archives.count != 0 &&
             !sbinject_validate_deb_paths(
                 archives, "sileo-broker-pre-install"))) {
            log_message("sileoRootBrokerPreflight=false command=%s "
                        "backend=sbinject-jit-v1 archives=%lu error=%s "
                        "dynamicTrustCache=false",
                        resolvedCommand, (unsigned long)archives.count,
                        archiveError != nil
                            ? [[archiveError description] UTF8String]
                            : "none");
            return 72 << 8;
        }
        log_message("sileoRootBrokerPreflight=true command=%s "
                    "backend=sbinject-jit-v1 archives=%lu "
                    "transactionScoped=true "
                    "dynamicTrustCache=false",
                    resolvedCommand, (unsigned long)archives.count);
        if (archives.count != 0) {
            bool managedLifecycle = false;
            NSString *maintainerError = nil;
            preparedArchives = sbinject_prepare_maintainer_archives(
                archives, &maintainerStaging, &managedPackageNames,
                &managedLifecycle, &maintainerError);
            if (preparedArchives == nil) {
                log_message("sileoRootBrokerMaintainers=false command=%s "
                            "error=%s dynamicTrustCache=false",
                            resolvedCommand,
                            maintainerError != nil
                                ? [[maintainerError description] UTF8String]
                                : "unknown");
                return 73 << 8;
            }
            if (managedLifecycle) {
                uint32_t dpkgIndex = 0;
                preparedDpkgArguments[dpkgIndex++] =
                    "/var/jb/usr/bin/dpkg";
                preparedDpkgArguments[dpkgIndex++] = "--unpack";
                preparedDpkgArguments[dpkgIndex++] = "--force-confdef";
                preparedDpkgArguments[dpkgIndex++] = "--force-confnew";
                for (NSString *archive in preparedArchives) {
                    if (dpkgIndex >= CODEX_ROOT_BROKER_MAX_ARGUMENTS + 3U) {
                        if (maintainerStaging != nil) {
                            [[NSFileManager defaultManager]
                                removeItemAtPath:maintainerStaging error:nil];
                        }
                        return 73 << 8;
                    }
                    preparedDpkgArguments[dpkgIndex++] =
                        (char *)[archive fileSystemRepresentation];
                }
                preparedDpkgArguments[dpkgIndex] = NULL;
                spawnCommand = preparedDpkgArguments[0];
                spawnArguments = preparedDpkgArguments;
                managedDpkgTransaction = true;
                aptReconcile = true;
                log_message("sileoRootBrokerMaintainers=true command=%s "
                            "selected=dpkg-jit-unpack archives=%lu "
                            "transactionScoped=true dynamicTrustCache=false",
                            resolvedCommand,
                            (unsigned long)preparedArchives.count);
            }
        }
    }

    if (dpkgCommand) {
        NSArray<NSString *> *dpkgArchives =
            sbinject_deb_paths_from_arguments(arguments);
        if (dpkgArchives.count != 0) {
            if (!sbinject_validate_deb_paths(
                    dpkgArchives, "dpkg-pre-install")) {
                log_message("sileoRootBrokerPreflight=false command=%s "
                            "backend=sbinject-jit-v1 "
                            "dynamicTrustCache=false",
                            resolvedCommand);
                return 72 << 8;
            }
            bool managedLifecycle = false;
            NSString *maintainerError = nil;
            preparedArchives = sbinject_prepare_maintainer_archives(
                dpkgArchives, &maintainerStaging, &managedPackageNames,
                &managedLifecycle, &maintainerError);
            if (preparedArchives == nil) {
                log_message("sileoRootBrokerMaintainers=false command=%s "
                            "error=%s dynamicTrustCache=false",
                            resolvedCommand,
                            maintainerError != nil
                                ? [[maintainerError description] UTF8String]
                                : "unknown");
                return 73 << 8;
            }
            if (managedLifecycle) {
                uint32_t dpkgIndex = 0;
                preparedDpkgArguments[dpkgIndex++] =
                    "/var/jb/usr/bin/dpkg";
                preparedDpkgArguments[dpkgIndex++] = "--unpack";
                preparedDpkgArguments[dpkgIndex++] = "--force-confdef";
                preparedDpkgArguments[dpkgIndex++] = "--force-confnew";
                for (NSString *archive in preparedArchives) {
                    if (dpkgIndex >= CODEX_ROOT_BROKER_MAX_ARGUMENTS + 3U) {
                        if (maintainerStaging != nil) {
                            [[NSFileManager defaultManager]
                                removeItemAtPath:maintainerStaging error:nil];
                        }
                        return 73 << 8;
                    }
                    preparedDpkgArguments[dpkgIndex++] =
                        (char *)[archive fileSystemRepresentation];
                }
                preparedDpkgArguments[dpkgIndex] = NULL;
                spawnCommand = preparedDpkgArguments[0];
                spawnArguments = preparedDpkgArguments;
                managedDpkgTransaction = true;
                log_message("sileoRootBrokerMaintainers=true command=%s "
                            "selected=dpkg-jit-unpack archives=%lu "
                            "transactionScoped=true dynamicTrustCache=false",
                            resolvedCommand,
                            (unsigned long)preparedArchives.count);
            }
        }
    }

    NSString *installedMaintainerError = nil;
    if (managedPackageNames.count != 0 &&
        !sbinject_prepare_installed_maintainers(
            managedPackageNames, false, &installedMaintainerError)) {
        log_message("sileoRootBrokerInstalledMaintainers=false command=%s "
                    "phase=pre-unpack error=%s",
                    resolvedCommand,
                    installedMaintainerError != nil
                        ? [[installedMaintainerError description] UTF8String]
                        : "unknown");
        if (maintainerStaging != nil) {
            [[NSFileManager defaultManager]
                removeItemAtPath:maintainerStaging error:nil];
        }
        return 74 << 8;
    }

    NSArray<NSString *> *removalPackages = aptCommand
        ? aptRemovalPackages
        : dpkgRemovalPackages;
    bool scanAllMaintainers = aptScanAllRemovals || dpkgConfigureAll;
    if (scanAllMaintainers) {
        removalPackages =
            sbinject_all_maintainer_packages(&installedMaintainerError);
        if (removalPackages == nil) {
            log_message("sileoRootBrokerInstalledMaintainers=false command=%s "
                        "phase=enumerate error=%s",
                        resolvedCommand,
                        installedMaintainerError != nil
                            ? [[installedMaintainerError description] UTF8String]
                            : "unknown");
            if (maintainerStaging != nil) {
                [[NSFileManager defaultManager]
                    removeItemAtPath:maintainerStaging error:nil];
            }
            return 74 << 8;
        }
    }
    if (removalPackages.count != 0 &&
        !sbinject_prepare_installed_maintainers(
            removalPackages, aptScanAllRemovals ||
                                 aptRemovalPackages.count != 0 ||
                                 dpkgRemovalPackages.count != 0,
            &installedMaintainerError)) {
        log_message("sileoRootBrokerInstalledMaintainers=false command=%s "
                    "phase=pre-remove error=%s",
                    resolvedCommand,
                    installedMaintainerError != nil
                        ? [[installedMaintainerError description] UTF8String]
                        : "unknown");
        if (maintainerStaging != nil) {
            [[NSFileManager defaultManager]
                removeItemAtPath:maintainerStaging error:nil];
        }
        return 74 << 8;
    }

    pid_t springBoardBefore =
        packageMutation ? current_springboard_process(NULL) : -1;
    int temporary[CODEX_ROOT_BROKER_MAX_FDS];
    for (uint32_t index = 0; index < CODEX_ROOT_BROKER_MAX_FDS; ++index) {
        temporary[index] = -1;
    }
    bool duplicated = true;
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        temporary[index] =
            fcntl(descriptors[index], F_DUPFD_CLOEXEC, 64);
        if (temporary[index] < 0) {
            duplicated = false;
            break;
        }
    }
    if (!duplicated) {
        for (uint32_t index = 0; index < CODEX_ROOT_BROKER_MAX_FDS; ++index) {
            if (temporary[index] >= 0) {
                close(temporary[index]);
            }
        }
        return 127 << 8;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        posix_spawn_file_actions_adddup2(&actions, temporary[index],
                                         descriptorNumbers[index]);
    }
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        posix_spawn_file_actions_addclose(&actions, temporary[index]);
    }
    if (server >= 0 &&
        !descriptor_numbers_contain(descriptorNumbers, descriptorCount,
                                    server)) {
        posix_spawn_file_actions_addclose(&actions, server);
    }
    if (client >= 0 &&
        !descriptor_numbers_contain(descriptorNumbers, descriptorCount,
                                    client)) {
        posix_spawn_file_actions_addclose(&actions, client);
    }

    const char *root = [jailbreakRoot fileSystemRepresentation];
    char pathEnvironment[8192];
    char shellEnvironment[4096];
    char libraryEnvironment[4096];
    int environmentLengths[] = {
        snprintf(pathEnvironment, sizeof(pathEnvironment),
                 "PATH=%s/usr/bin:%s/bin:%s/usr/sbin:%s/sbin:"
                 "/usr/bin:/bin:/usr/sbin:/sbin",
                 root, root, root, root),
        snprintf(shellEnvironment, sizeof(shellEnvironment), "SHELL=%s/bin/sh",
                 root),
        snprintf(libraryEnvironment, sizeof(libraryEnvironment),
                 "DYLD_LIBRARY_PATH=%s/usr/lib", root),
    };
    size_t environmentCapacities[] = {
        sizeof(pathEnvironment), sizeof(shellEnvironment),
        sizeof(libraryEnvironment),
    };
    for (size_t index = 0;
         index < sizeof(environmentLengths) / sizeof(environmentLengths[0]);
         ++index) {
        if (environmentLengths[index] < 0 ||
            (size_t)environmentLengths[index] >= environmentCapacities[index]) {
            posix_spawn_file_actions_destroy(&actions);
            for (uint32_t descriptor = 0; descriptor < descriptorCount;
                 ++descriptor) {
                close(temporary[descriptor]);
            }
            return 127 << 8;
        }
    }
    char *environment[CODEX_ROOT_BROKER_MAX_ENVIRONMENT + 8U] = {0};
    uint32_t environmentCount = 0;
    for (uint32_t index = 0; index < controlEnvironmentCount; ++index) {
        environment[environmentCount++] = controlEnvironment[index];
    }
    environment[environmentCount++] = pathEnvironment;
    environment[environmentCount++] = shellEnvironment;
    environment[environmentCount++] = libraryEnvironment;
    environment[environmentCount++] = "HOME=/var/root";
    environment[environmentCount++] = "TMPDIR=/var/tmp";
    environment[environmentCount] = NULL;

    if (packageTransaction) {
        for (uint32_t index = 0;
             index < CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
             spawnArguments[index] != NULL;
             ++index) {
            log_message("sileoRootBrokerArgument command=%s index=%u "
                        "value=%s",
                        spawnCommand, index, spawnArguments[index]);
        }
    }

    pid_t child = 0;
    bool runtimeFallback = false;
    int spawnResult = posix_spawn(&child, spawnCommand, &actions, NULL,
                                  spawnArguments, environment);
    if (spawnResult != 0 &&
        broker_spawn_error_is_admission_failure(spawnResult) &&
        strcmp(spawnCommand,
               [kExecWorkerExecutable fileSystemRepresentation]) != 0 &&
        broker_command_is_macho(spawnCommand)) {
        char *runtimeArguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 3U] = {0};
        runtimeArguments[0] =
            (char *)[kExecWorkerExecutable fileSystemRepresentation];
        runtimeArguments[1] = "--macho";
        uint32_t index = 0;
        while (index < CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
               spawnArguments[index] != NULL) {
            runtimeArguments[index + 2U] = spawnArguments[index];
            ++index;
        }
        runtimeArguments[index + 2U] = NULL;
        int directError = spawnResult;
        spawnResult = posix_spawn(
            &child, [kExecWorkerExecutable fileSystemRepresentation],
            &actions, NULL, runtimeArguments, environment);
        runtimeFallback = spawnResult == 0;
        log_message("sileoRootBrokerJITFallback command=%s "
                    "directError=%s workerError=%s selected=%s",
                    spawnCommand, strerror(directError),
                    spawnResult == 0 ? "none" : strerror(spawnResult),
                    runtimeFallback ? "true" : "false");
    }
    posix_spawn_file_actions_destroy(&actions);
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        close(temporary[index]);
    }
    if (spawnResult != 0) {
        log_message("sileoRootBrokerSpawnError command=%s error=%s",
                    spawnCommand, strerror(spawnResult));
        if (maintainerStaging != nil) {
            [[NSFileManager defaultManager]
                removeItemAtPath:maintainerStaging error:nil];
        }
        return 127 << 8;
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
                if (maintainerStaging != nil) {
                    [[NSFileManager defaultManager]
                        removeItemAtPath:maintainerStaging error:nil];
                }
                return 125 << 8;
        }
    }
    if (managedDpkgTransaction && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0) {
        NSString *installedError = nil;
        NSArray<NSString *> *allMaintainerPackages =
            sbinject_all_maintainer_packages(&installedError);
        if (allMaintainerPackages == nil ||
            !sbinject_prepare_installed_maintainers(
                allMaintainerPackages, false, &installedError)) {
            log_message("sileoRootBrokerInstalledMaintainers=false command=%s "
                        "phase=post-unpack error=%s",
                        resolvedCommand,
                        installedError != nil
                            ? [[installedError description] UTF8String]
                            : "unknown");
            status = 74 << 8;
        } else {
            char *configureArguments[] = {
                "/var/jb/usr/bin/dpkg", "--configure", "-a", NULL};
            int configureStatus = run_and_wait_bounded(
                configureArguments[0], configureArguments, 90000);
            log_message("sileoRootBrokerDpkgConfigure status=%d "
                        "maintainerRewrite=true backend=jit-rw-to-rx",
                        configureStatus);
            if (configureStatus != 0) {
                status = configureStatus << 8;
            }
        }
    }
    if (aptReconcile && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        char *reconcileArguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 4U] = {0};
        if (!sbinject_build_apt_reconcile_arguments(
                arguments, reconcileArguments,
                CODEX_ROOT_BROKER_MAX_ARGUMENTS + 4U)) {
            log_message("sileoRootBrokerAptReconcile status=invalid-arguments "
                        "command=%s",
                        resolvedCommand);
            status = 73 << 8;
        } else {
            int reconcileStatus = run_and_wait_bounded(
                resolvedCommand, reconcileArguments, 120000);
            log_message("sileoRootBrokerAptReconcile command=%s status=%d "
                        "reinstallSuppressed=true removalPreserved=true "
                        "transactionScoped=true",
                        resolvedCommand, reconcileStatus);
            if (reconcileStatus != 0) {
                status = reconcileStatus << 8;
            }
        }
    }
    if (runtimeFallback) {
        log_message("sileoRootBrokerJITResult command=%s status=%d",
                    resolvedCommand, status);
    }
    if (packageMutation && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        !refresh_rootless_application_registrations(
            "sileo-package-transaction")) {
        status = 75 << 8;
    }
    if (packageMutation) {
        bool finalized = finish_sbinject_package_transaction(
            springBoardBefore, status, resolvedCommand);
        bool respringRequired =
            finalized && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
            exact_empty_root_marker(kSBInjectRespringMarker);
        bool sileoFinishChannelExpected = false;
        for (uint32_t index = 0; index < controlEnvironmentCount; ++index) {
            if (strncmp(controlEnvironment[index], "SILEO=", 6U) == 0) {
                sileoFinishChannelExpected = true;
                break;
            }
        }
        if (respringRequired && sileoFinishChannelExpected) {
            static const char finishSignal[] = "finish:restart\n";
            bool signaled = false;
            // Pinned Sileo reserves descriptor 6 for its native finish-action
            // channel.  The virtualized spawn keeps that pipe open through
            // this post-hook, so upgrade the otherwise-successful result from
            // Done to Sileo's standard Respring Now / Respring Later sheet.
            for (uint32_t index = 0; index < descriptorCount; ++index) {
                if (descriptorNumbers[index] == 6) {
                    signaled = write_all(descriptors[index], finishSignal,
                                         sizeof(finishSignal) - 1U);
                    break;
                }
            }
            log_message("sileoRootBrokerFinishSignal command=%s "
                        "action=restart descriptor=6 status=%s",
                        resolvedCommand, signaled ? "success" : "failed");
            if (!signaled) {
                static const char finishError[] =
                    "Error: SBInject prepared the SpringBoard redirect but "
                    "could not notify Sileo that a respring is required.\n";
                for (uint32_t index = 0; index < descriptorCount; ++index) {
                    if (descriptorNumbers[index] == STDERR_FILENO) {
                        (void)write_all(descriptors[index], finishError,
                                        sizeof(finishError) - 1U);
                        break;
                    }
                }
                status = 76 << 8;
            }
        } else if (respringRequired) {
            log_message("sileoRootBrokerFinishSignal command=%s "
                        "action=restart status=not-requested-headless",
                        resolvedCommand);
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && !finalized) {
            static const char packageError[] =
                "Error: SBInject could not prepare and verify the resigned "
                "SpringBoard redirect; Sileo's respring action was not "
                "armed.\n";
            for (uint32_t index = 0; index < descriptorCount; ++index) {
                if (descriptorNumbers[index] == STDERR_FILENO) {
                    (void)write_all(descriptors[index], packageError,
                                    sizeof(packageError) - 1U);
                    break;
                }
            }
            log_message("sileoRootBrokerPackageError command=%s code=75 "
                        "reason=sbinject-redirect-not-ready",
                        resolvedCommand);
            status = 75 << 8;
        }
    }
    if (maintainerStaging != nil) {
        NSError *cleanupError = nil;
        BOOL cleaned = [[NSFileManager defaultManager]
            removeItemAtPath:maintainerStaging error:&cleanupError];
        log_message("sbinjectMaintainerCleanup path=%s status=%s error=%s",
                    [maintainerStaging UTF8String],
                    cleaned ? "success" : "failed",
                    cleanupError != nil
                        ? [[cleanupError description] UTF8String]
                        : "none");
    }
    return status;
}

static void serve_sileo_broker(int server, NSString *registeredPath,
                               NSString *jailbreakRoot) {
    NSString *expectedHelper =
        [registeredPath stringByAppendingPathComponent:@"giveMeRoot"];
    NSString *expectedMain =
        [registeredPath stringByAppendingPathComponent:@"Sileo"];
    log_message("sileoRootBrokerServing=true socketFd=%d", server);
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno != EINTR) {
                log_message("sileoBrokerAcceptError=%s", strerror(errno));
            }
            continue;
        }
        int noSigpipe = 1;
        (void)setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe,
                         sizeof(noSigpipe));
        uid_t peerUser = (uid_t)-1;
        gid_t peerGroup = (gid_t)-1;
        pid_t peerPid = -1;
        socklen_t peerPidLength = sizeof(peerPid);
        char peerPath[CODEX_PROC_PIDPATH_MAX] = {0};
        bool accepted = getpeereid(client, &peerUser, &peerGroup) == 0 &&
            peerUser == 501 &&
            getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peerPid,
                       &peerPidLength) == 0 &&
            peerPidLength == sizeof(peerPid) && peerPid > 1 &&
            proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0 &&
            ([expectedHelper isEqual:[NSString stringWithUTF8String:peerPath]] ||
             [expectedMain isEqual:[NSString stringWithUTF8String:peerPath]]);
        if (!accepted) {
            log_message("sileoRootBrokerRejected pid=%d uid=%u path=%s",
                        peerPid, peerUser,
                        peerPath[0] != '\0' ? peerPath : "none");
            close(client);
            continue;
        }
        struct codex_root_broker_request request;
        bool received = receive_root_broker_request(client, &request);
        char resolved[PATH_MAX] = {0};
        bool allowed = received &&
            resolve_broker_command(request.arguments[0], jailbreakRoot,
                                   resolved, sizeof(resolved));
        int32_t status = 126 << 8;
        if (allowed) {
            status = run_root_broker_command(
                server, client, request.arguments, request.descriptors,
                request.header.descriptor_numbers,
                request.header.descriptor_count, NULL, 0, jailbreakRoot,
                resolved);
        }
        bool replied = write_all(client, &status, sizeof(status));
        if (received) {
            close_root_broker_request(&request);
        }
        close(client);
        log_message("sileoRootBrokerRequest pid=%d received=%s allowed=%s "
                    "command=%s status=%d replied=%s",
                    peerPid, received ? "true" : "false",
                    allowed ? "true" : "false",
                    resolved[0] != '\0' ? resolved : "none", status,
                    replied ? "true" : "false");
    }
}

static bool is_exact_managed_candidate_process(
    pid_t pid, const char *path, NSString *configuredPath) {
    (void)pid;
    const char *configured = [configuredPath fileSystemRepresentation];
    const char *leaf = strrchr(path, '/');
    const char *expectedLeaf = strrchr(configured, '/');
    leaf = leaf != NULL ? leaf + 1 : path;
    expectedLeaf = expectedLeaf != NULL ? expectedLeaf + 1 : configured;
    return strcmp(leaf, expectedLeaf) == 0;
}

static bool is_exact_springboard_candidate_process(pid_t pid,
                                                    const char *path) {
    return is_exact_managed_candidate_process(
        pid, path, kSpringBoardCandidateExecutable);
}

static bool is_exact_preferences_candidate_process(pid_t pid,
                                                    const char *path) {
    return is_exact_managed_candidate_process(
        pid, path, kPreferencesCandidateExecutable);
}

static bool is_exact_amfid_candidate_process(pid_t pid, const char *path) {
    return is_exact_managed_candidate_process(
        pid, path, kAmfidCandidateExecutable);
}

static bool sbinject_managed_file(NSString *path, mode_t mode) {
    struct stat status;
    return lstat([path fileSystemRepresentation], &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 && status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & 07777) == mode;
}

static bool immutable_payload_file(NSString *path, mode_t mode) {
    struct stat status;
    return lstat([path fileSystemRepresentation], &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 && (status.st_mode & 07777) == mode;
}

static bool prepare_lsd_registration_hook(const char *reason) {
    pid_t existingLsd = current_lsd_process();
    if (lsd_registration_marker_matches_process(existingLsd)) {
        log_message("sileoLsdRegistrationHook=true reason=%s reused=true",
                    reason);
        return true;
    }
    if (!sbinject_managed_file(kElleKitInjectorExecutable, 0755) ||
        !sbinject_managed_file(kSBInjectLsdRegistrationHook, 0755)) {
        log_message("sileoLsdRegistrationHook=false reason=%s "
                    "phase=artifacts",
                    reason);
        return false;
    }
    (void)unlink(
        [kSBInjectLsdRegistrationMarker fileSystemRepresentation]);
    for (NSUInteger attempt = 0; attempt < 3; ++attempt) {
        pid_t lsd = current_lsd_process();
        if (lsd <= 1) {
            usleep(100 * 1000);
            continue;
        }
        char pidText[32];
        int pidLength = snprintf(pidText, sizeof(pidText), "%d", lsd);
        if (pidLength <= 0 || (size_t)pidLength >= sizeof(pidText)) return false;
        char *arguments[] = {
            (char *)[kElleKitInjectorExecutable fileSystemRepresentation],
            "--inject-pid", pidText,
            (char *)[kSBInjectLsdRegistrationHook fileSystemRepresentation],
            NULL,
        };
        int status = run_and_wait_bounded(arguments[0], arguments, 30000);
        bool ready = false;
        for (NSUInteger markerAttempt = 0; markerAttempt < 200;
             ++markerAttempt) {
            if (lsd_registration_marker_matches_process(lsd) &&
                current_lsd_process() == lsd) {
                ready = true;
                break;
            }
            usleep(10 * 1000);
        }
        log_message("sileoLsdRegistrationHook=%s reason=%s pid=%d "
                    "attempt=%lu status=%d reused=false",
                    ready ? "true" : "false", reason, lsd,
                    (unsigned long)(attempt + 1U), status);
        if (ready) return true;
    }
    return false;
}

static bool prepare_sbinject_redirect(const char *reason) {
    NSArray<NSDictionary *> *artifacts = @[
        @{@"path" : kElleKitInjectorExecutable, @"mode" : @0755},
        @{@"path" : kElleKitInjectorDylib, @"mode" : @0644},
        @{@"path" : kSBInjectJitterdExecutable, @"mode" : @0755},
        @{@"path" : kSBInjectGeneralHook, @"mode" : @0755},
        @{@"path" : kSBInjectLaunchdHook, @"mode" : @0755},
        @{@"path" : kSpringBoardCandidateExecutable, @"mode" : @0755},
        @{@"path" : kSBInjectBundleHook, @"mode" : @0755},
        @{@"path" : kSBInjectJitterdPlist, @"mode" : @0644},
    ];
    for (NSDictionary *artifact in artifacts) {
        NSString *path = artifact[@"path"];
        mode_t mode = (mode_t)[artifact[@"mode"] unsignedShortValue];
        if (!sbinject_managed_file(path, mode)) {
            log_message("sbinjectActivation=false reason=artifact path=%s",
                        [path UTF8String]);
            (void)unlink([kSBInjectEnableMarker fileSystemRepresentation]);
            return false;
        }
    }
    if (access([kSBInjectCrashMarker fileSystemRepresentation], F_OK) == 0) {
        log_message("sbinjectActivation=false reason=crash-loop-marker");
        (void)unlink([kSBInjectEnableMarker fileSystemRepresentation]);
        return false;
    }

    mach_port_t jitterdPort = MACH_PORT_NULL;
    kern_return_t lookup = bootstrap_look_up(
        bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE, &jitterdPort);
    if (lookup != KERN_SUCCESS || !MACH_PORT_VALID(jitterdPort)) {
        log_message("sbinjectActivation=false reason=jitterd-service kr=%d",
                    lookup);
        (void)unlink([kSBInjectEnableMarker fileSystemRepresentation]);
        return false;
    }
    mach_port_deallocate(mach_task_self(), jitterdPort);

    bool launchdHookUpgrade =
        exact_empty_root_marker(kSBInjectLaunchdUpgradeMarker);
    if (launchdHookUpgrade) {
        (void)unlink(
            [kSBInjectLaunchdReadyMarker fileSystemRepresentation]);
    }
    bool launchdHookReady =
        sbinject_boot_fresh_marker(kSBInjectLaunchdReadyMarker);
    int injectionStatus = 0;
    if (!launchdHookReady && !launchdHookUpgrade) {
        // A launchd-injected dylib cannot unload before the next boot. If an
        // exact managed notSpringBoard from this boot is alive, the redirect
        // hook is necessarily already resident in PID 1. Recover a readiness
        // marker that an in-place Cryptex refresh removed instead of coupling
        // redirect health to any process-specific module inventory.
        bool liveCandidate = false;
        pid_t livePid = current_springboard_process(&liveCandidate);
        bool liveRedirectProof = liveCandidate && livePid > 1;
        if (liveRedirectProof) {
            NSString *recoveryError = nil;
            bool markerRecovered = ensure_root_owned_empty_file(
                [kSBInjectLaunchdReadyMarker fileSystemRepresentation], 0644,
                &recoveryError);
            launchdHookReady =
                markerRecovered &&
                sbinject_boot_fresh_marker(kSBInjectLaunchdReadyMarker);
            log_message("sbinjectLaunchdReadyRecovered=%s reason=%s pid=%d "
                        "proof=exact-managed-candidate modules=diagnostic-only "
                        "error=%s",
                        launchdHookReady ? "true" : "false", reason, livePid,
                        recoveryError != nil
                            ? [[recoveryError description] UTF8String]
                            : "none");
        }
    }
    if (!launchdHookReady) {
        (void)unlink([kSBInjectLaunchdReadyMarker fileSystemRepresentation]);
        char *injectArguments[] = {
            (char *)[kElleKitInjectorExecutable fileSystemRepresentation],
            "--inject-launchd-hook", NULL,
        };
        injectionStatus = run_and_wait_bounded(
            injectArguments[0], injectArguments, 30000);
        for (NSUInteger attempt = 0;
             injectionStatus == 0 && attempt < 200; ++attempt) {
            if (sbinject_boot_fresh_marker(kSBInjectLaunchdReadyMarker)) {
                launchdHookReady = true;
                break;
            }
            usleep(10 * 1000);
        }
    }
    if (injectionStatus != 0 || !launchdHookReady) {
        log_message("sbinjectActivation=false reason=launchd-injection "
                    "status=%d hookReady=%s",
                    injectionStatus,
                    launchdHookReady ? "true" : "false");
        (void)unlink([kSBInjectEnableMarker fileSystemRepresentation]);
        return false;
    }
    if (launchdHookUpgrade) {
        (void)unlink(
            [kSBInjectLaunchdUpgradeMarker fileSystemRepresentation]);
        log_message("sbinjectLaunchdHotChain=true reason=%s", reason);
    }
    NSString *markerError = nil;
    if (!ensure_root_owned_empty_file(
            [kSBInjectEnableMarker fileSystemRepresentation], 0644,
            &markerError)) {
        log_message("sbinjectActivation=false reason=enable-marker error=%s",
                    markerError != nil
                        ? [[markerError description] UTF8String]
                        : "unknown");
        return false;
    }

    log_message("sbinjectRedirectPrepared=true reason=%s hookReady=true "
                "candidateReady=true jitterdReady=true",
                reason);
    return true;
}

static bool activate_sbinject_springboard(void) {
    if (!prepare_sbinject_redirect("activation")) {
        return false;
    }

    bool candidate = false;
    pid_t springBoard = current_springboard_process(&candidate);
    if (springBoard > 1 && !candidate) {
        int signalStatus = kill(springBoard, SIGTERM);
        log_message("sbinjectStockRespring pid=%d status=%d error=%d",
                    springBoard, signalStatus,
                    signalStatus == 0 ? 0 : errno);
    }

    bool redirected = false;
    pid_t candidatePid = -1;
    for (NSUInteger attempt = 0; attempt < 200; ++attempt) {
        bool observedCandidate = false;
        pid_t observed = current_springboard_process(&observedCandidate);
        if (observed > 1 && observedCandidate) {
            candidatePid = observed;
            redirected = true;
            break;
        }
        usleep(100 * 1000);
    }
    if (redirected) {
        log_message("sbinjectActivation=true pid=%d "
                    "redirectVerified=exact-managed-candidate "
                    "modules=diagnostic-only",
                    candidatePid);
        return true;
    }

    (void)unlink([kSBInjectEnableMarker fileSystemRepresentation]);
    bool finalCandidate = false;
    pid_t finalSpringBoard = current_springboard_process(&finalCandidate);
    if (finalCandidate && finalSpringBoard > 1) {
        (void)kill(finalSpringBoard, SIGTERM);
    }
    log_message("sbinjectActivation=false reason=candidate-not-observed pid=%d "
                "fallback=stock",
                finalSpringBoard);
    return false;
}

static bool activate_sbinject_preferences(void) {
    NSArray<NSDictionary *> *artifacts = @[
        @{@"path" : kElleKitInjectorDylib, @"mode" : @0644},
        @{@"path" : kSBInjectJitterdExecutable, @"mode" : @0755},
        @{@"path" : kSBInjectGeneralHook, @"mode" : @0755},
        @{@"path" : kSBInjectPreferencesBridge, @"mode" : @0755},
        @{@"path" : kSBInjectLaunchdHook, @"mode" : @0755},
        @{@"path" : kPreferencesCandidateExecutable, @"mode" : @0755},
        @{@"path" : kSBInjectPreferencesBundleHook, @"mode" : @0755},
    ];
    for (NSDictionary *artifact in artifacts) {
        NSString *path = artifact[@"path"];
        mode_t mode = (mode_t)[artifact[@"mode"] unsignedShortValue];
        if (!sbinject_managed_file(path, mode)) {
            log_message("sbinjectPreferencesActivation=false "
                        "reason=artifact path=%s",
                        [path UTF8String]);
            (void)unlink(
                [kSBInjectPreferencesEnableMarker fileSystemRepresentation]);
            return false;
        }
    }
    if (access([kSBInjectPreferencesCrashMarker fileSystemRepresentation],
               F_OK) == 0) {
        log_message("sbinjectPreferencesActivation=false "
                    "reason=crash-loop-marker");
        (void)unlink(
            [kSBInjectPreferencesEnableMarker fileSystemRepresentation]);
        return false;
    }
    if (!sbinject_boot_fresh_marker(kSBInjectLaunchdReadyMarker)) {
        log_message("sbinjectPreferencesActivation=false "
                    "reason=launchd-hook-not-ready");
        return false;
    }

    mach_port_t jitterdPort = MACH_PORT_NULL;
    kern_return_t lookup = bootstrap_look_up(
        bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE, &jitterdPort);
    if (lookup != KERN_SUCCESS || !MACH_PORT_VALID(jitterdPort)) {
        log_message("sbinjectPreferencesActivation=false "
                    "reason=jitterd-service kr=%d",
                    lookup);
        return false;
    }
    mach_port_deallocate(mach_task_self(), jitterdPort);

    NSString *markerError = nil;
    if (!ensure_root_owned_empty_file(
            [kSBInjectPreferencesEnableMarker fileSystemRepresentation], 0644,
            &markerError)) {
        log_message("sbinjectPreferencesActivation=false "
                    "reason=enable-marker error=%s",
                    markerError != nil
                        ? [[markerError description] UTF8String]
                        : "unknown");
        return false;
    }

    bool restartRequired =
        exact_empty_root_marker(kSBInjectPreferencesRestartMarker);
    bool candidate = false;
    pid_t preferences = current_preferences_process(&candidate);
    if (preferences < 0) {
        log_message("sbinjectPreferencesActivation=false "
                    "reason=process-enumeration");
        return false;
    }
    if (preferences == 0) {
        if (restartRequired) {
            (void)unlink(
                [kSBInjectPreferencesRestartMarker fileSystemRepresentation]);
        }
        log_message("sbinjectPreferencesActivation=true pid=none "
                    "state=armed-deferred restartRequired=%s",
                    restartRequired ? "true" : "false");
        return true;
    }
    if (!restartRequired && candidate && preferences > 1) {
        log_message("sbinjectPreferencesActivation=true pid=%d "
                    "redirectVerified=exact-managed-candidate reused=true "
                    "modules=diagnostic-only",
                    preferences);
        return true;
    }
    pid_t rejectedPid = restartRequired ? preferences : -1;
    if (preferences > 1 && (!candidate || restartRequired)) {
        int signalStatus = kill(preferences, SIGTERM);
        log_message("sbinjectPreferencesRestart pid=%d candidate=%s "
                    "required=%s status=%d error=%d",
                    preferences, candidate ? "true" : "false",
                    restartRequired ? "true" : "false", signalStatus,
                    signalStatus == 0 ? 0 : errno);
        if (signalStatus != 0) {
            return false;
        }
    }

    for (NSUInteger attempt = 0; attempt < 200; ++attempt) {
        bool observedCandidate = false;
        pid_t observed = current_preferences_process(&observedCandidate);
        if (observed > 1 && observed != rejectedPid && observedCandidate) {
            if (restartRequired) {
                (void)unlink(
                    [kSBInjectPreferencesRestartMarker
                        fileSystemRepresentation]);
            }
            log_message("sbinjectPreferencesActivation=true pid=%d "
                        "redirectVerified=exact-managed-candidate "
                        "reused=false restartRequired=%s "
                        "modules=diagnostic-only",
                        observed,
                        restartRequired ? "true" : "false");
            return true;
        }
        usleep(100 * 1000);
    }

    bool finalCandidate = false;
    pid_t finalPreferences = current_preferences_process(&finalCandidate);
    if (finalPreferences == 0) {
        if (restartRequired) {
            (void)unlink(
                [kSBInjectPreferencesRestartMarker fileSystemRepresentation]);
        }
        log_message("sbinjectPreferencesActivation=true pid=none "
                    "state=armed-deferred restartRequired=%s",
                    restartRequired ? "true" : "false");
        return true;
    }
    (void)unlink(
        [kSBInjectPreferencesEnableMarker fileSystemRepresentation]);
    if (finalCandidate) {
        (void)kill(finalPreferences, SIGTERM);
    }
    log_message("sbinjectPreferencesActivation=false "
                "reason=candidate-not-observed pid=%d fallback=stock",
                finalPreferences);
    return false;
}

static int trigger_amfid_service(void) {
    char *arguments[] = {
        "/var/jb/usr/bin/launchctl", "kickstart", "-k",
        "user/501/com.apple.MobileFileIntegrity", NULL};
    return run_and_wait_bounded(arguments[0], arguments, 10000);
}

static void trigger_amfid_service_async(void) {
    dispatch_async(
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            int result = trigger_amfid_service();
            log_message("sbinjectAmfidRespawnTrigger=%d", result);
        });
}

static dispatch_source_t gAmfidJitMonitor;

static bool inject_sbinject_amfid_hook(pid_t pid) {
    char observedPath[CODEX_PROC_PIDPATH_MAX] = {0};
    if (pid <= 1 ||
        proc_pidpath(pid, observedPath, sizeof(observedPath)) <= 0 ||
        strcmp(observedPath,
               [kStockAmfidExecutable fileSystemRepresentation]) != 0) {
        return false;
    }

    (void)unlink([kSBInjectAmfidReadyMarker fileSystemRepresentation]);
    (void)unlink([kSBInjectAmfidFailureMarker fileSystemRepresentation]);

    char pidText[32] = {0};
    if (snprintf(pidText, sizeof(pidText), "%d", pid) <= 0) return false;
    char *arguments[] = {
        (char *)[kElleKitInjectorExecutable fileSystemRepresentation],
        "--inject-pid", pidText,
        (char *)[kSBInjectAmfidHook fileSystemRepresentation], NULL,
    };
    int injectionStatus = run_and_wait_bounded(
        arguments[0], arguments, 30000);
    bool candidate = false;
    pid_t current = current_amfid_process(&candidate);
    bool ready = injectionStatus == 0 && current == pid && !candidate &&
                 sbinject_boot_fresh_marker(kSBInjectAmfidReadyMarker) &&
                 access([kSBInjectAmfidFailureMarker fileSystemRepresentation],
                        F_OK) != 0;
    log_message("sbinjectAmfidInjection pid=%d fixedTrust=true injection=%d "
                "current=%d stock=%s ready=%s",
                pid, injectionStatus, current,
                current == pid && !candidate ? "true" : "false",
                ready ? "true" : "false");
    return ready;
}

static void start_amfid_jit_monitor(void) {
    if (gAmfidJitMonitor != NULL) return;
    dispatch_queue_t queue = dispatch_queue_create(
        "com.openai.codex.dopamine.amfid-jit-monitor",
        DISPATCH_QUEUE_SERIAL);
    dispatch_source_t timer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    if (timer == NULL) return;
    bool initialCandidate = false;
    pid_t initialPid = current_amfid_process(&initialCandidate);
    __block pid_t attachedPid =
        initialPid > 1 && !initialCandidate &&
                sbinject_boot_fresh_marker(kSBInjectAmfidReadyMarker)
            ? initialPid
            : 0;
    dispatch_source_set_timer(
        timer, dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC),
        50 * NSEC_PER_MSEC, 10 * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{
        if (!exact_empty_root_marker(kSBInjectAmfidEnableMarker)) {
            attachedPid = 0;
            return;
        }
        bool candidate = false;
        pid_t observed = current_amfid_process(&candidate);
        if (observed <= 1 || candidate) {
            if (observed != attachedPid) attachedPid = 0;
            return;
        }
        if (observed == attachedPid) return;
        bool injected = inject_sbinject_amfid_hook(observed);
        log_message("sbinjectAmfidJITMonitor pid=%d injected=%s",
                    observed, injected ? "true" : "false");
        attachedPid = injected ? observed : 0;
    });
    gAmfidJitMonitor = timer;
    dispatch_resume(timer);
    log_message("sbinjectAmfidJITMonitor=ready initialPid=%d",
                attachedPid);
}

static bool activate_sbinject_amfid(void) {
    NSArray<NSDictionary *> *artifacts = @[
        @{@"path" : kSBInjectAmfidHook, @"mode" : @0755},
        @{@"path" : kElleKitInjectorExecutable, @"mode" : @0755},
    ];
    for (NSDictionary *artifact in artifacts) {
        NSString *path = artifact[@"path"];
        mode_t mode = (mode_t)[artifact[@"mode"] unsignedShortValue];
        if (!sbinject_managed_file(path, mode)) {
            log_message("sbinjectAmfidActivation=false reason=artifact path=%s",
                        [path UTF8String]);
            (void)unlink(
                [kSBInjectAmfidEnableMarker fileSystemRepresentation]);
            return false;
        }
    }
    (void)unlink([kSBInjectAmfidCrashMarker fileSystemRepresentation]);

    NSString *markerError = nil;
    if (!ensure_root_owned_empty_file(
            [kSBInjectAmfidEnableMarker fileSystemRepresentation], 0644,
            &markerError)) {
        log_message("sbinjectAmfidActivation=false "
                    "reason=enable-marker error=%s",
                    markerError != nil
                        ? [[markerError description] UTF8String]
                        : "unknown");
        return false;
    }

    // A previous experimental build used this marker to redirect launchd to
    // a resigned amfid copy.  Keep it absent: the kernel authenticates AMFI
    // replies against the genuine daemon's CDHash, so only live injection
    // into /usr/libexec/amfid is valid.
    (void)unlink("/var/jb/var/lib/sbinject/amfid-enabled");
    (void)unlink([kSBInjectAmfidFailureMarker fileSystemRepresentation]);
    (void)unlink([kSBInjectAmfidReadyMarker fileSystemRepresentation]);

    bool candidate = false;
    pid_t amfid = current_amfid_process(&candidate);
    if (amfid < 0) {
        log_message("sbinjectAmfidActivation=false "
                    "reason=process-enumeration");
        (void)unlink([kSBInjectAmfidEnableMarker fileSystemRepresentation]);
        return false;
    }
    if (candidate && amfid > 1) {
        int signalStatus = kill(amfid, SIGKILL);
        log_message("sbinjectAmfidLegacyCandidateStop pid=%d status=%d "
                    "error=%d",
                    amfid, signalStatus,
                    signalStatus == 0 ? 0 : errno);
        if (signalStatus != 0) {
            (void)unlink(
                [kSBInjectAmfidEnableMarker fileSystemRepresentation]);
            return false;
        }
        amfid = 0;
    } else if (amfid > 1 && inject_sbinject_amfid_hook(amfid)) {
        log_message("sbinjectAmfidActivation=true pid=%d reused=true "
                    "mode=stock-live-injection",
                    amfid);
        return true;
    }

    trigger_amfid_service_async();

    pid_t injectedPid = 0;
    for (NSUInteger attempt = 0; attempt < 300; ++attempt) {
        bool observedCandidate = false;
        pid_t observed = current_amfid_process(&observedCandidate);
        if (observed > 1 && !observedCandidate) {
            if (observed != injectedPid &&
                inject_sbinject_amfid_hook(observed)) {
                injectedPid = observed;
                log_message("sbinjectAmfidActivation=true pid=%d "
                            "reused=false mode=stock-live-injection",
                            observed);
                return true;
            }
        } else if (observed > 1 && observedCandidate) {
            (void)kill(observed, SIGKILL);
        }
        usleep(100 * 1000);
    }

    bool finalCandidate = false;
    pid_t finalAmfid = current_amfid_process(&finalCandidate);
    bool initializedThenIdle = injectedPid > 1 && finalAmfid == 0 &&
        sbinject_boot_fresh_marker(kSBInjectAmfidReadyMarker) &&
        access([kSBInjectAmfidFailureMarker fileSystemRepresentation], F_OK) !=
            0;
    if (initializedThenIdle) {
        log_message("sbinjectAmfidActivation=true pid=none "
                    "state=initialized-idle mode=stock-live-injection");
        return true;
    }
    (void)unlink([kSBInjectAmfidEnableMarker fileSystemRepresentation]);
    (void)unlink([kSBInjectAmfidReadyMarker fileSystemRepresentation]);
    log_message("sbinjectAmfidActivation=false "
                "reason=stock-injection-not-ready pid=%d "
                "fallback=stock",
                finalAmfid);
    return false;
}

static bool respring_sbinject_springboard(const char *reason) {
    if (!prepare_sbinject_redirect(reason)) {
        log_message("sbinjectRespring=false reason=%s phase=prepare", reason);
        return false;
    }

    // A user-requested respring means the named tweak has been disabled in
    // Sileo and normal injection should be tried again.
    (void)unlink([kSBInjectSafeModeMarker fileSystemRepresentation]);
    (void)unlink([kElleKitSafeModeMarker fileSystemRepresentation]);
    bool candidateBefore = false;
    pid_t before = current_springboard_process(&candidateBefore);
    if (before > 1) {
        int signalStatus = kill(before, SIGTERM);
        log_message("sbinjectRespringSignal reason=%s pid=%d candidate=%s "
                    "status=%d error=%d",
                    reason, before, candidateBefore ? "true" : "false",
                    signalStatus, signalStatus == 0 ? 0 : errno);
        if (signalStatus != 0) {
            return false;
        }
        for (NSUInteger attempt = 0; attempt < 250; ++attempt) {
            pid_t observed = current_springboard_process(NULL);
            if (observed != before) {
                break;
            }
            usleep(20 * 1000);
        }
    }
    bool active = activate_sbinject_springboard();
    if (active) {
        (void)unlink([kSBInjectRespringMarker fileSystemRepresentation]);
    }
    bool finalCandidate = false;
    pid_t finalPid = current_springboard_process(&finalCandidate);
    log_message("sbinjectRespring=%s reason=%s before=%d final=%d "
                "candidate=%s",
                active ? "true" : "false", reason, before, finalPid,
                finalCandidate ? "true" : "false");
    return active && finalCandidate && finalPid > 1;
}

static xpc_connection_t gSileoXpcListener;
static pthread_mutex_t gPreferencesRespringLock = PTHREAD_MUTEX_INITIALIZER;
static bool gPreferencesRespringPending;

static void schedule_preferences_respring(void) {
    pthread_mutex_lock(&gPreferencesRespringLock);
    bool alreadyPending = gPreferencesRespringPending;
    gPreferencesRespringPending = true;
    pthread_mutex_unlock(&gPreferencesRespringLock);
    if (alreadyPending) {
        log_message("preferencesRespringRequest coalesced=true");
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        bool resprung = respring_sbinject_springboard("preferences-button");
        log_message("preferencesRespringRequest result=%s",
                    resprung ? "success" : "failed");
        pthread_mutex_lock(&gPreferencesRespringLock);
        gPreferencesRespringPending = false;
        pthread_mutex_unlock(&gPreferencesRespringLock);
    });
}

static void handle_preferences_xpc_request(xpc_connection_t peer,
                                           xpc_object_t message,
                                           pid_t peerPid) {
    xpc_object_t reply = xpc_dictionary_create_reply(message);
    if (reply == NULL) {
        return;
    }
    char peerPath[CODEX_PROC_PIDPATH_MAX] = {0};
    bool accepted = peerPid > 1 &&
        proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0 &&
        executable_paths_match(
            kPreferencesCandidateExecutable,
            [NSString stringWithUTF8String:peerPath]);
    const char *operation = accepted &&
                                    xpc_get_type(message) == XPC_TYPE_DICTIONARY
                                ? xpc_dictionary_get_string(
                                      message,
                                      CODEX_ROOT_BROKER_OPERATION_KEY)
                                : NULL;
    bool valid = operation != NULL &&
        strcmp(operation,
               CODEX_ROOT_BROKER_PREFERENCES_RESPRING_OPERATION) == 0;
    bool allowed = accepted && valid;
    xpc_dictionary_set_int64(reply, "status", allowed ? 0 : EPERM);
    xpc_dictionary_set_bool(reply, "accepted", accepted);
    xpc_dictionary_set_bool(reply, "valid", valid);
    xpc_dictionary_set_bool(reply, "allowed", allowed);
    xpc_connection_send_message(peer, reply);
    log_message("preferencesXpcBrokerRequest pid=%d accepted=%s valid=%s "
                "allowed=%s operation=%s",
                peerPid, accepted ? "true" : "false",
                valid ? "true" : "false", allowed ? "true" : "false",
                operation != NULL ? operation : "none");
    if (allowed) {
        // Reply before replacing SpringBoard so callers using waitpid/NSTask do
        // not remain blocked while FrontBoard tears down the current scene.
        schedule_preferences_respring();
    }
}

static void handle_sileo_xpc_request(xpc_connection_t peer,
                                     xpc_object_t message, pid_t peerPid,
                                     NSString *expectedMain,
                                     NSString *expectedHelper,
                                     NSString *jailbreakRoot,
                                     bool headlessSileoClient) {
    xpc_object_t reply = xpc_dictionary_create_reply(message);
    if (reply == NULL) {
        return;
    }
    int32_t status = 126 << 8;
    bool accepted = false;
    char peerPath[CODEX_PROC_PIDPATH_MAX] = {0};
    if (peerPid > 1 && proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0) {
        NSString *path = [NSString stringWithUTF8String:peerPath];
        bool sileoClient = executable_paths_match(expectedMain, path) ||
                           executable_paths_match(expectedHelper, path) ||
                           (headlessSileoClient &&
                            executable_paths_match(kHeadlessSileoExecutable,
                                                   path));
        accepted = sileoClient;
    }

    char *arguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 1U] = {0};
    char *controlEnvironment[CODEX_ROOT_BROKER_MAX_ENVIRONMENT + 1U] = {0};
    int descriptors[CODEX_ROOT_BROKER_MAX_FDS];
    int descriptorNumbers[CODEX_ROOT_BROKER_MAX_FDS];
    uint32_t argumentCount = 0;
    uint32_t controlEnvironmentCount = 0;
    uint32_t descriptorCount = 0;
    for (uint32_t index = 0; index < CODEX_ROOT_BROKER_MAX_FDS; ++index) {
        descriptors[index] = -1;
    }
    bool valid = accepted && xpc_get_type(message) == XPC_TYPE_DICTIONARY;
    xpc_object_t argumentArray =
        valid ? xpc_dictionary_get_value(message, "arguments") : NULL;
    xpc_object_t environmentArray =
        valid ? xpc_dictionary_get_value(message, "control-environment")
              : NULL;
    xpc_object_t descriptorArray =
        valid ? xpc_dictionary_get_value(message, "descriptor-numbers")
              : NULL;
    if (argumentArray == NULL || xpc_get_type(argumentArray) != XPC_TYPE_ARRAY ||
        environmentArray == NULL ||
        xpc_get_type(environmentArray) != XPC_TYPE_ARRAY ||
        descriptorArray == NULL ||
        xpc_get_type(descriptorArray) != XPC_TYPE_ARRAY) {
        valid = false;
    }
    if (valid) {
        size_t count = xpc_array_get_count(argumentArray);
        size_t environmentCount = xpc_array_get_count(environmentArray);
        size_t fdCount = xpc_array_get_count(descriptorArray);
        valid = count > 0 && count <= CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
                environmentCount <= CODEX_ROOT_BROKER_MAX_ENVIRONMENT &&
                fdCount > 0 && fdCount <= CODEX_ROOT_BROKER_MAX_FDS;
        argumentCount = valid ? (uint32_t)count : 0;
        controlEnvironmentCount =
            valid ? (uint32_t)environmentCount : 0;
        descriptorCount = valid ? (uint32_t)fdCount : 0;
    }
    for (uint32_t index = 0; valid && index < argumentCount; ++index) {
        const char *value = xpc_array_get_string(argumentArray, index);
        if (value == NULL || strnlen(value, PATH_MAX * 4U) == PATH_MAX * 4U) {
            valid = false;
            break;
        }
        arguments[index] = (char *)value;
    }
    for (uint32_t index = 0; valid && index < controlEnvironmentCount;
         ++index) {
        const char *value = xpc_array_get_string(environmentArray, index);
        if (value == NULL || strnlen(value, 64U) == 64U) {
            valid = false;
            break;
        }
        controlEnvironment[index] = (char *)value;
    }
    for (uint32_t index = 0; valid && index < descriptorCount; ++index) {
        int64_t value = xpc_array_get_int64(descriptorArray, index);
        if (value < INT_MIN || value > INT_MAX ||
            !is_allowed_descriptor_number((int)value) ||
            descriptor_numbers_contain(descriptorNumbers, index, (int)value)) {
            valid = false;
            break;
        }
        descriptorNumbers[index] = (int)value;
        char key[32];
        int keyLength = snprintf(key, sizeof(key), "descriptor-%u", index);
        descriptors[index] = keyLength > 0 && (size_t)keyLength < sizeof(key)
                                 ? xpc_dictionary_dup_fd(message, key)
                                 : -1;
        if (descriptors[index] < 0) {
            valid = false;
            break;
        }
    }
    for (uint32_t index = 0; valid && index < controlEnvironmentCount;
         ++index) {
        if (!valid_control_environment(controlEnvironment[index],
                                       descriptorNumbers, descriptorCount)) {
            valid = false;
            break;
        }
        for (uint32_t previous = 0; previous < index; ++previous) {
            bool duplicateSileo =
                strncmp(controlEnvironment[index], "SILEO=", 6) == 0 &&
                strncmp(controlEnvironment[previous], "SILEO=", 6) == 0;
            bool duplicateCydia =
                strncmp(controlEnvironment[index], "CYDIA=", 6) == 0 &&
                strncmp(controlEnvironment[previous], "CYDIA=", 6) == 0;
            if (duplicateSileo || duplicateCydia) {
                valid = false;
                break;
            }
        }
    }
    char resolved[PATH_MAX] = {0};
    bool resolvedBrokerCommand = valid &&
        resolve_broker_command(arguments[0], jailbreakRoot, resolved,
                               sizeof(resolved));
    bool allowed = valid &&
        resolvedBrokerCommand &&
        (!headlessSileoClient ||
         headless_sileo_request_allowed(
             arguments, argumentCount, controlEnvironment,
             controlEnvironmentCount, descriptorNumbers, descriptorCount,
             resolved));
    log_message("sileoXpcBrokerRequestStart pid=%d accepted=%s valid=%s "
                "allowed=%s command=%s",
                peerPid, accepted ? "true" : "false",
                valid ? "true" : "false", allowed ? "true" : "false",
                resolved[0] != '\0' ? resolved : "none");
    if (allowed) {
        status = run_root_broker_command(
            -1, -1, arguments, descriptors, descriptorNumbers,
            descriptorCount, controlEnvironment,
            controlEnvironmentCount, jailbreakRoot, resolved);
    }
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        if (descriptors[index] >= 0) {
            close(descriptors[index]);
        }
    }
    xpc_dictionary_set_int64(reply, "status", status);
    xpc_dictionary_set_bool(reply, "accepted", accepted);
    xpc_dictionary_set_bool(reply, "valid", valid);
    xpc_dictionary_set_bool(reply, "allowed", allowed);
    xpc_connection_send_message(peer, reply);
    log_message("sileoXpcBrokerRequest pid=%d accepted=%s valid=%s allowed=%s "
                "command=%s status=%d controlEnvironment=%u",
                peerPid, accepted ? "true" : "false",
                valid ? "true" : "false", allowed ? "true" : "false",
                resolved[0] != '\0' ? resolved : "none",
                status,
                controlEnvironmentCount);
}

static bool start_sileo_xpc_broker(NSString *registeredPath,
                                   NSString *jailbreakRoot) {
    NSString *expectedMain =
        [registeredPath stringByAppendingPathComponent:@"Sileo"];
    NSString *expectedHelper =
        [registeredPath stringByAppendingPathComponent:@"giveMeRoot"];
    dispatch_queue_t queue = dispatch_queue_create(
        "com.openai.codex.dopamine.sileo-xpc-root-broker",
        DISPATCH_QUEUE_CONCURRENT);
    typedef xpc_connection_t (*xpc_create_mach_service_function)(
        const char *, dispatch_queue_t, uint64_t);
    xpc_create_mach_service_function createMachService =
        (xpc_create_mach_service_function)dlsym(
            RTLD_DEFAULT, "xpc_connection_create_mach_service");
    gSileoXpcListener =
        createMachService != NULL
            ? createMachService(CODEX_ROOT_BROKER_MACH_SERVICE, queue,
                                XPC_CONNECTION_MACH_SERVICE_LISTENER)
            : NULL;
    if (gSileoXpcListener == NULL) {
        return false;
    }
    xpc_connection_set_event_handler(gSileoXpcListener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) {
            return;
        }
        xpc_connection_t peer = (xpc_connection_t)event;
        typedef pid_t (*xpc_pid_function)(xpc_connection_t);
        xpc_pid_function getPid =
            (xpc_pid_function)dlsym(RTLD_DEFAULT, "xpc_connection_get_pid");
        pid_t peerPid = getPid != NULL ? getPid(peer) : -1;
        uid_t peerUser = xpc_connection_get_euid(peer);
        char peerPath[CODEX_PROC_PIDPATH_MAX] = {0};
        // The original Sileo binary asks for its first root job while UIKit is
        // still decoding the main storyboard.  On iOS 27 the XPC connection
        // can arrive a few milliseconds before proc_pidpath publishes the app
        // executable.  A one-shot lookup therefore rejects a legitimate peer
        // and, worse, leaves Sileo's synchronous request waiting on a canceled
        // connection until FrontBoard's scene-create watchdog fires.
        bool pathAvailable = false;
        if (peerPid > 1) {
            for (unsigned int attempt = 0; attempt < 50; ++attempt) {
                if (proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0) {
                    pathAvailable = true;
                    break;
                }
                if (attempt + 1U < 50U) {
                    usleep(10 * 1000);
                }
            }
        }
        NSString *path = pathAvailable
            ? [NSString stringWithUTF8String:peerPath]
            : nil;
        bool sileoClient = peerUser == 501 &&
            (executable_paths_match(expectedMain, path) ||
             executable_paths_match(expectedHelper, path));
        bool headlessSileoClient = peerUser == 501 &&
            executable_paths_match(kHeadlessSileoExecutable, path);
        bool preferencesClient = peerUser == 501 &&
            executable_paths_match(kPreferencesCandidateExecutable, path);
        bool accepted = sileoClient || headlessSileoClient || preferencesClient;
        if (!accepted) {
            log_message("sileoXpcBrokerRejected pid=%d uid=%u path=%s",
                        peerPid, peerUser,
                        peerPath[0] != '\0' ? peerPath : "none");
            // Never strand a synchronous virtual job.  Send a structured
            // denial for the first dictionary and then close the connection;
            // the constructor can surface EPERM and release its waiter.
            xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
                if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
                    xpc_object_t reply = xpc_dictionary_create_reply(message);
                    if (reply != NULL) {
                        xpc_dictionary_set_bool(reply, "accepted", false);
                        xpc_dictionary_set_bool(reply, "valid", false);
                        xpc_dictionary_set_bool(reply, "allowed", false);
                        xpc_dictionary_set_int64(reply, "status", EPERM);
                        xpc_connection_send_message(peer, reply);
                    }
                    xpc_connection_cancel(peer);
                } else if (xpc_get_type(message) == XPC_TYPE_ERROR) {
                    xpc_connection_cancel(peer);
                }
            });
            xpc_connection_resume(peer);
            return;
        }
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
                if (preferencesClient) {
                    handle_preferences_xpc_request(peer, message, peerPid);
                } else {
                    handle_sileo_xpc_request(
                        peer, message, peerPid, expectedMain, expectedHelper,
                        jailbreakRoot, headlessSileoClient);
                }
            }
        });
        xpc_connection_resume(peer);
    });
    xpc_connection_resume(gSileoXpcListener);
    mach_port_t servicePort = MACH_PORT_NULL;
    kern_return_t lookupResult = bootstrap_look_up(
        bootstrap_port, CODEX_ROOT_BROKER_MACH_SERVICE, &servicePort);
    log_message("sileoXpcBootstrapLookup result=%d portValid=%s",
                lookupResult,
                MACH_PORT_VALID(servicePort) ? "true" : "false");
    if (MACH_PORT_VALID(servicePort)) {
        mach_port_deallocate(mach_task_self(), servicePort);
    }
    log_message("sileoXpcRootBrokerServing=true service=%s",
                CODEX_ROOT_BROKER_MACH_SERVICE);
    return true;
}

static void serve_sileo_file_broker(NSString *registeredPath,
                                    NSString *jailbreakRoot,
                                    NSString *dataContainer) {
    NSString *expectedExecutable =
        [registeredPath stringByAppendingPathComponent:@"Sileo"];
    NSString *directory = [dataContainer
        stringByAppendingPathComponent:@"Library/CodexBootstrap"];
    NSString *extensionPaths[] = {
        jailbreakRoot,
        @"/var/jb",
        jailbreakRoot,
        [registeredPath stringByAppendingPathComponent:@"giveMeRoot"],
        @"/var/mobile",
    };
    const char *const classes[] = {
        "com.apple.app-sandbox.read-write",
        "com.apple.app-sandbox.read-write",
        "com.apple.sandbox.executable",
        "com.apple.sandbox.executable",
        "com.apple.app-sandbox.read-write",
    };
    log_message("sileoFileBrokerServing=true directory=%s",
                [directory UTF8String]);
    for (;;) {
        @autoreleasepool {
            NSArray<NSString *> *entries = [[NSFileManager defaultManager]
                contentsOfDirectoryAtPath:directory
                                     error:nil];
            for (NSString *entry in entries) {
                static NSString *const prefix = @"broker-request-";
                if (![entry hasPrefix:prefix]) {
                    continue;
                }
                NSString *pidText = [entry substringFromIndex:prefix.length];
                const char *pidBytes = [pidText UTF8String];
                char *pidEnd = NULL;
                long parsedPid = strtol(pidBytes, &pidEnd, 10);
                if (pidBytes[0] == '\0' || pidEnd == NULL || *pidEnd != '\0' ||
                    parsedPid <= 1 || parsedPid > INT_MAX) {
                    continue;
                }
                pid_t peerPid = (pid_t)parsedPid;
                NSString *request = [directory
                    stringByAppendingPathComponent:entry];
                NSString *requestBody = [NSString
                    stringWithContentsOfFile:request
                                    encoding:NSUTF8StringEncoding
                                       error:nil];
                if (![[requestBody
                        stringByTrimmingCharactersInSet:
                            [NSCharacterSet whitespaceAndNewlineCharacterSet]]
                        isEqual:pidText]) {
                    continue;
                }
                (void)unlink([request fileSystemRepresentation]);

                char peerPath[CODEX_PROC_PIDPATH_MAX] = {0};
                NSString *peerExecutable = nil;
                for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
                    if (proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0) {
                        break;
                    }
                    if (attempt + 1U < 100U) {
                        usleep(10U * 1000U);
                    }
                }
                if (peerPath[0] != '\0') {
                    peerExecutable =
                        [NSString stringWithUTF8String:peerPath];
                }
                bool accepted =
                    executable_paths_match(expectedExecutable,
                                           peerExecutable);
                if (!accepted) {
                    log_message("sileoFileBrokerRejected pid=%d path=%s",
                                peerPid,
                                peerPath[0] != '\0' ? peerPath : "none");
                    continue;
                }

                char *tokens[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
                NSUInteger tokenCount = 0;
                NSMutableString *responseBody = [NSMutableString string];
                bool issued = true;
                for (NSUInteger index = 0; index < 5; ++index) {
                    tokens[tokenCount] =
                        sandbox_extension_issue_file_to_process_by_pid(
                            classes[index],
                            [extensionPaths[index] fileSystemRepresentation],
                            0, peerPid);
                    if (tokens[tokenCount] == NULL) {
                        issued = false;
                        break;
                    }
                    [responseBody appendFormat:@"%s\n",
                                               tokens[tokenCount]];
                    ++tokenCount;
                }
                if (issued) {
                    char *token = sandbox_extension_issue_mach(
                        "com.apple.security.exception.mach-lookup.global-name",
                        CODEX_ROOT_BROKER_MACH_SERVICE,
                        SANDBOX_EXTENSION_CANONICAL);
                    log_message(
                        "sileoMachExtensionIssue pid=%d "
                        "class=com.apple.security.exception.mach-lookup."
                        "global-name bound=false "
                        "flags=%u issued=%s",
                        peerPid, SANDBOX_EXTENSION_CANONICAL,
                        token != NULL ? "true" : "false");
                    if (token != NULL) {
                        tokens[tokenCount++] = token;
                        [responseBody appendFormat:@"%s\n", token];
                    }
                    issued = tokenCount == 6;
                }
                for (NSUInteger index = 0; index < tokenCount; ++index) {
                    free(tokens[index]);
                }
                bool wrote = false;
                if (issued) {
                    NSString *response = [directory
                        stringByAppendingPathComponent:
                            [NSString stringWithFormat:@"broker-response-%d",
                                                       peerPid]];
                    NSError *responseError = nil;
                    wrote = [responseBody
                                writeToFile:response
                                  atomically:YES
                                    encoding:NSUTF8StringEncoding
                                       error:&responseError] &&
                            [[NSFileManager defaultManager]
                                setAttributes:@{
                                    NSFilePosixPermissions : @0600,
                                    NSFileOwnerAccountID : @501,
                                    NSFileGroupOwnerAccountID : @501,
                                }
                                 ofItemAtPath:response
                                        error:&responseError];
                }
                log_message("sileoFileBrokerRequest pid=%d tokens=%lu "
                            "issued=%s wrote=%s",
                            peerPid, (unsigned long)tokenCount,
                            issued ? "true" : "false",
                            wrote ? "true" : "false");
            }
        }
        usleep(10 * 1000);
    }
}

static bool files_are_equal(NSString *left, NSString *right) {
    struct stat leftStatus;
    struct stat rightStatus;
    if (lstat([left fileSystemRepresentation], &leftStatus) != 0 ||
        lstat([right fileSystemRepresentation], &rightStatus) != 0 ||
        !S_ISREG(leftStatus.st_mode) || !S_ISREG(rightStatus.st_mode) ||
        leftStatus.st_size != rightStatus.st_size) {
        return false;
    }
    int leftFile = open([left fileSystemRepresentation], O_RDONLY | O_CLOEXEC |
                                                         O_NOFOLLOW);
    int rightFile = open([right fileSystemRepresentation],
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (leftFile < 0 || rightFile < 0) {
        if (leftFile >= 0) {
            close(leftFile);
        }
        if (rightFile >= 0) {
            close(rightFile);
        }
        return false;
    }
    unsigned char leftBytes[64 * 1024];
    unsigned char rightBytes[64 * 1024];
    bool equal = true;
    for (;;) {
        ssize_t leftLength;
        do {
            leftLength = read(leftFile, leftBytes, sizeof(leftBytes));
        } while (leftLength < 0 && errno == EINTR);
        ssize_t rightLength;
        do {
            rightLength = read(rightFile, rightBytes, sizeof(rightBytes));
        } while (rightLength < 0 && errno == EINTR);
        if (leftLength < 0 || rightLength < 0 || leftLength != rightLength) {
            equal = false;
            break;
        }
        if (leftLength == 0) {
            break;
        }
        if (memcmp(leftBytes, rightBytes, (size_t)leftLength) != 0) {
            equal = false;
            break;
        }
    }
    close(leftFile);
    close(rightFile);
    return equal;
}

static bool install_dopamine_default_sources(NSString *source,
                                             bool *didUpdate,
                                             NSString **errorText) {
    if (didUpdate != NULL) {
        *didUpdate = false;
    }
    NSError *readError = nil;
    NSData *expected = [NSData dataWithContentsOfFile:source
                                              options:NSDataReadingMappedIfSafe
                                                error:&readError];
    if (expected == nil || expected.length == 0 || expected.length > 64 * 1024) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"default APT source payload is invalid: %@",
                                 readError];
        }
        return false;
    }

    NSString *directory = @"/var/jb/etc/apt/sources.list.d";
    NSError *directoryError = nil;
    NSDictionary *directoryAttributes = @{
        NSFilePosixPermissions : @0755,
        NSFileOwnerAccountID : @0,
        NSFileGroupOwnerAccountID : @0,
    };
    if (![[NSFileManager defaultManager]
            createDirectoryAtPath:directory
      withIntermediateDirectories:YES
                       attributes:directoryAttributes
                            error:&directoryError] ||
        ![[NSFileManager defaultManager] setAttributes:directoryAttributes
                                         ofItemAtPath:directory
                                                error:&directoryError]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"default APT source directory failed: %@",
                                 directoryError];
        }
        return false;
    }

    NSString *destination =
        [directory stringByAppendingPathComponent:@"dopamine-default.sources"];
    struct stat destinationStatus;
    if (lstat([destination fileSystemRepresentation], &destinationStatus) ==
        0) {
        if (!S_ISREG(destinationStatus.st_mode)) {
            if (errorText != NULL) {
                *errorText = @"managed default APT source is not a regular file";
            }
            return false;
        }
        NSError *currentError = nil;
        NSData *current = [NSData dataWithContentsOfFile:destination
                                                 options:0
                                                   error:&currentError];
        if (current == nil) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"default APT source read failed: %@",
                                     currentError];
            }
            return false;
        }
        if ([current isEqualToData:expected]) {
            log_message("dopamineDefaultSources=current path=%s",
                        [destination UTF8String]);
            return true;
        }
    } else if (errno != ENOENT) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"default APT source status failed: %s",
                                 strerror(errno)];
        }
        return false;
    }

    NSString *temporary = [directory
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".dopamine-default-%@",
                                       [[NSUUID UUID] UUIDString]]];
    NSError *writeError = nil;
    if (![expected writeToFile:temporary
                       options:NSDataWritingWithoutOverwriting
                         error:&writeError] ||
        ![[NSFileManager defaultManager]
            setAttributes:@{
                NSFilePosixPermissions : @0644,
                NSFileOwnerAccountID : @0,
                NSFileGroupOwnerAccountID : @0,
            }
             ofItemAtPath:temporary
                    error:&writeError]) {
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"default APT source staging failed: %@",
                                 writeError];
        }
        return false;
    }
    if (rename([temporary fileSystemRepresentation],
               [destination fileSystemRepresentation]) != 0) {
        int savedError = errno;
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"default APT source activation failed: %s",
                                 strerror(savedError)];
        }
        return false;
    }
    if (!files_are_equal(source, destination)) {
        if (errorText != NULL) {
            *errorText = @"default APT source verification failed";
        }
        return false;
    }
    if (didUpdate != NULL) {
        *didUpdate = true;
    }
    log_message("dopamineDefaultSources=updated path=%s bytes=%lu",
                [destination UTF8String], (unsigned long)expected.length);
    return true;
}

static bool install_managed_apt_file(NSString *source, NSString *directory,
                                     NSString *filename, off_t maximumSize,
                                     mode_t mode, const char *logName,
                                     bool *didUpdate, NSString **errorText) {
    if (didUpdate != NULL) {
        *didUpdate = false;
    }
    if (![filename isEqualToString:[filename lastPathComponent]]) {
        if (errorText != NULL) {
            *errorText = @"managed APT filename is invalid";
        }
        return false;
    }
    struct stat sourceStatus;
    if (lstat([source fileSystemRepresentation], &sourceStatus) != 0 ||
        !S_ISREG(sourceStatus.st_mode) || sourceStatus.st_size <= 0 ||
        sourceStatus.st_size > maximumSize) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed APT payload is invalid: %@",
                                 source];
        }
        return false;
    }
    NSError *readError = nil;
    NSData *expected = [NSData dataWithContentsOfFile:source
                                              options:NSDataReadingMappedIfSafe
                                                error:&readError];
    if (expected == nil) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed APT payload read failed: %@",
                                 readError];
        }
        return false;
    }

    NSError *fileError = nil;
    NSDictionary *directoryAttributes = @{
        NSFilePosixPermissions : @0755,
        NSFileOwnerAccountID : @0,
        NSFileGroupOwnerAccountID : @0,
    };
    if (![[NSFileManager defaultManager]
            createDirectoryAtPath:directory
      withIntermediateDirectories:YES
                       attributes:directoryAttributes
                            error:&fileError] ||
        ![[NSFileManager defaultManager] setAttributes:directoryAttributes
                                         ofItemAtPath:directory
                                                error:&fileError]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed APT directory failed: %@",
                                 fileError];
        }
        return false;
    }

    NSString *destination = [directory stringByAppendingPathComponent:filename];
    struct stat destinationStatus;
    if (lstat([destination fileSystemRepresentation], &destinationStatus) ==
        0) {
        if (!S_ISREG(destinationStatus.st_mode)) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"managed APT path is not a "
                                      "regular file: %@",
                                     destination];
            }
            return false;
        }
        if (files_are_equal(source, destination)) {
            if (![[NSFileManager defaultManager]
                    setAttributes:@{
                        NSFilePosixPermissions : @(mode),
                        NSFileOwnerAccountID : @0,
                        NSFileGroupOwnerAccountID : @0,
                    }
                     ofItemAtPath:destination
                            error:&fileError]) {
                if (errorText != NULL) {
                    *errorText = [NSString
                        stringWithFormat:@"managed APT metadata failed: "
                                          "%@",
                                         fileError];
                }
                return false;
            }
            log_message("%s=current path=%s", logName,
                        [destination UTF8String]);
            return true;
        }
    } else if (errno != ENOENT) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed APT status failed: %s",
                                 strerror(errno)];
        }
        return false;
    }

    NSString *temporary = [directory
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".%@-%@", filename,
                                       [[NSUUID UUID] UUIDString]]];
    if (![expected writeToFile:temporary
                       options:NSDataWritingWithoutOverwriting
                         error:&fileError] ||
        ![[NSFileManager defaultManager]
            setAttributes:@{
                NSFilePosixPermissions : @(mode),
                NSFileOwnerAccountID : @0,
                NSFileGroupOwnerAccountID : @0,
            }
             ofItemAtPath:temporary
                    error:&fileError]) {
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed APT staging failed: %@",
                                 fileError];
        }
        return false;
    }
    if (rename([temporary fileSystemRepresentation],
               [destination fileSystemRepresentation]) != 0) {
        int savedError = errno;
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"managed APT activation failed: %s",
                                 strerror(savedError)];
        }
        return false;
    }
    if (!files_are_equal(source, destination) ||
        lstat([destination fileSystemRepresentation], &destinationStatus) !=
            0 ||
        destinationStatus.st_uid != 0 || destinationStatus.st_gid != 0 ||
        (destinationStatus.st_mode & 07777) != mode) {
        if (errorText != NULL) {
            *errorText = @"managed APT payload verification failed";
        }
        return false;
    }
    if (didUpdate != NULL) {
        *didUpdate = true;
    }
    log_message("%s=updated path=%s bytes=%lu", logName,
                [destination UTF8String], (unsigned long)expected.length);
    return true;
}


static bool secure_openssh_root_directories(NSString **errorText) {
    NSFileManager *manager = [NSFileManager defaultManager];
    NSDictionary *attributes = @{
        NSFilePosixPermissions : @0700,
        NSFileOwnerAccountID : @0,
        NSFileGroupOwnerAccountID : @0,
    };
    NSArray<NSString *> *directories = @[
        @"/var/jb/var/root",
        @"/var/jb/var/root/.ssh",
    ];
    NSError *error = nil;
    for (NSString *directory in directories) {
        if (![manager createDirectoryAtPath:directory
                 withIntermediateDirectories:YES
                                  attributes:attributes
                                       error:&error] ||
            ![manager setAttributes:attributes
                       ofItemAtPath:directory
                              error:&error]) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"OpenSSH root directory preparation failed: %@",
                    error];
            }
            return false;
        }
        struct stat status = {0};
        if (lstat([directory fileSystemRepresentation], &status) != 0 ||
            !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode) ||
            status.st_uid != 0 || status.st_gid != 0 ||
            (status.st_mode & 07777) != 0700) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"OpenSSH root directory verification failed: %@",
                    directory];
            }
            return false;
        }
    }
    return true;
}

static bool install_openssh_job(NSString **errorText) {
    if (!secure_openssh_root_directories(errorText)) return false;
    NSDictionary<NSString *, NSNumber *> *files = @{
        kOpenSSHExecutable : @0755,
        kOpenSSHKeygen : @0755,
        kOpenSSHKeygenWrapper : @0755,
        kOpenSSHConfig : @0644,
        kOpenSSHPlist : @0644,
    };
    for (NSString *path in files) {
        mode_t mode = (mode_t)[files[path] unsignedShortValue];
        if (!sbinject_managed_file(path, mode)) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"OpenSSH payload verification failed: %@", path];
            }
            return false;
        }
    }

    NSString *target = [@"system/" stringByAppendingString:kOpenSSHLabel];
    char *printArguments[] = {
        "/var/jb/usr/bin/launchctl", "print",
        (char *)[target fileSystemRepresentation], NULL};
    int printStatus = run_and_wait_bounded(printArguments[0], printArguments,
                                           10000);
    if (printStatus != 0) {
        char *bootstrapArguments[] = {
            "/var/jb/usr/bin/launchctl", "bootstrap", "system",
            (char *)[kOpenSSHPlist fileSystemRepresentation], NULL};
        int bootstrapStatus = run_and_wait_bounded(
            bootstrapArguments[0], bootstrapArguments, 10000);
        log_message("openSSHBootstrapExit=%d", bootstrapStatus);
        if (bootstrapStatus != 0) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"OpenSSH bootstrap exited %d", bootstrapStatus];
            }
            return false;
        }
        printStatus = run_and_wait_bounded(printArguments[0], printArguments,
                                           10000);
    }
    log_message("openSSHReady=%s label=%s",
                printStatus == 0 ? "true" : "false",
                [kOpenSSHLabel UTF8String]);
    if (printStatus != 0 && errorText != NULL) {
        *errorText = @"OpenSSH launch daemon did not become ready";
    }
    return printStatus == 0;
}

static NSArray<NSString *> *validated_bundle_entries(NSString *root,
                                                      bool requireManaged) {
    struct stat rootStatus;
    if (lstat([root fileSystemRepresentation], &rootStatus) != 0 ||
        !S_ISDIR(rootStatus.st_mode) || S_ISLNK(rootStatus.st_mode) ||
        (requireManaged &&
         (rootStatus.st_uid != 0 || rootStatus.st_gid != 0 ||
          (rootStatus.st_mode & 07777) != 0755))) {
        return nil;
    }
    NSMutableArray<NSString *> *entries = [NSMutableArray array];
    NSDirectoryEnumerator<NSString *> *enumerator =
        [[NSFileManager defaultManager] enumeratorAtPath:root];
    unsigned long long totalBytes = 0;
    for (NSString *relative in enumerator) {
        if (entries.count >= 8192U || [relative hasPrefix:@"/"] ||
            [relative containsString:@"../"] ||
            [relative containsString:@"/./"]) {
            return nil;
        }
        NSString *path = [root stringByAppendingPathComponent:relative];
        struct stat status;
        if (lstat([path fileSystemRepresentation], &status) != 0 ||
            (!S_ISDIR(status.st_mode) && !S_ISREG(status.st_mode)) ||
            S_ISLNK(status.st_mode)) {
            return nil;
        }
        mode_t expectedMode = S_ISDIR(status.st_mode)
                                  ? 0755
                                  : ((status.st_mode & 0111) != 0 ? 0755
                                                                  : 0644);
        if (requireManaged &&
            (status.st_uid != 0 || status.st_gid != 0 ||
             (status.st_mode & 07777) != expectedMode)) {
            return nil;
        }
        if (S_ISREG(status.st_mode)) {
            if (status.st_size < 0 ||
                totalBytes > 128ULL * 1024ULL * 1024ULL -
                                 (unsigned long long)status.st_size) {
                return nil;
            }
            totalBytes += (unsigned long long)status.st_size;
        }
        [entries addObject:relative];
    }
    return entries.count != 0 ? entries : nil;
}

static bool normalize_bundle_tree(NSString *source, NSString *destination) {
    NSArray<NSString *> *entries = validated_bundle_entries(source, false);
    if (entries == nil) {
        return false;
    }
    NSFileManager *manager = [NSFileManager defaultManager];
    NSError *error = nil;
    NSDictionary *directoryAttributes = @{
        NSFilePosixPermissions : @0755,
        NSFileOwnerAccountID : @0,
        NSFileGroupOwnerAccountID : @0,
    };
    if (![manager setAttributes:directoryAttributes
                   ofItemAtPath:destination
                          error:&error]) {
        return false;
    }
    for (NSString *relative in entries) {
        NSString *sourcePath = [source stringByAppendingPathComponent:relative];
        NSString *destinationPath =
            [destination stringByAppendingPathComponent:relative];
        struct stat status;
        if (lstat([sourcePath fileSystemRepresentation], &status) != 0) {
            return false;
        }
        mode_t mode = S_ISDIR(status.st_mode)
                          ? 0755
                          : ((status.st_mode & 0111) != 0 ? 0755 : 0644);
        if (![manager setAttributes:@{
                NSFilePosixPermissions : @(mode),
                NSFileOwnerAccountID : @0,
                NSFileGroupOwnerAccountID : @0,
            }
                         ofItemAtPath:destinationPath
                                error:&error]) {
            return false;
        }
    }
    return true;
}

static bool bundle_trees_are_equal(NSString *source, NSString *destination) {
    NSArray<NSString *> *sourceEntries =
        validated_bundle_entries(source, false);
    NSArray<NSString *> *destinationEntries =
        validated_bundle_entries(destination, true);
    if (sourceEntries == nil || destinationEntries == nil ||
        ![[NSSet setWithArray:sourceEntries]
            isEqualToSet:[NSSet setWithArray:destinationEntries]]) {
        return false;
    }
    for (NSString *relative in sourceEntries) {
        NSString *sourcePath = [source stringByAppendingPathComponent:relative];
        NSString *destinationPath =
            [destination stringByAppendingPathComponent:relative];
        struct stat sourceStatus;
        struct stat destinationStatus;
        if (lstat([sourcePath fileSystemRepresentation], &sourceStatus) != 0 ||
            lstat([destinationPath fileSystemRepresentation],
                  &destinationStatus) != 0 ||
            (sourceStatus.st_mode & S_IFMT) !=
                (destinationStatus.st_mode & S_IFMT) ||
            (S_ISREG(sourceStatus.st_mode) &&
             !files_are_equal(sourcePath, destinationPath))) {
            return false;
        }
    }
    return true;
}

static bool install_sileo_system_bundle_copy(NSString *source,
                                             bool *didUpdate,
                                             NSString **errorText) {
    if (didUpdate != NULL) *didUpdate = false;
    if (!is_sileo_system_bundle_path(source) ||
        validated_bundle_entries(source, false) == nil) {
        if (errorText != NULL) {
            *errorText = @"Cryptex Sileo source bundle is invalid";
        }
        return false;
    }
    NSString *destination = kSystemSileoBundlePath;
    NSString *parent = [destination stringByDeletingLastPathComponent];
    NSFileManager *manager = [NSFileManager defaultManager];
    NSDictionary *directoryAttributes = @{
        NSFilePosixPermissions : @0755,
        NSFileOwnerAccountID : @0,
        NSFileGroupOwnerAccountID : @0,
    };
    NSError *error = nil;
    if (![manager createDirectoryAtPath:parent
             withIntermediateDirectories:YES
                              attributes:directoryAttributes
                                   error:&error] ||
        ![manager setAttributes:directoryAttributes
                   ofItemAtPath:parent
                          error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"system Sileo container preparation failed: %@", error];
        }
        return false;
    }
    if (bundle_trees_are_equal(source, destination)) {
        log_message("sileoSystemBundleCopy=current path=%s",
                    [destination UTF8String]);
        return true;
    }

    NSString *temporary = [parent stringByAppendingPathComponent:
        [NSString stringWithFormat:@".Sileo.app.new-%@",
                                   [[NSUUID UUID] UUIDString]]];
    if (![manager copyItemAtPath:source toPath:temporary error:&error] ||
        !normalize_bundle_tree(source, temporary) ||
        !bundle_trees_are_equal(source, temporary)) {
        [manager removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"system Sileo bundle staging failed: %@", error];
        }
        return false;
    }

    NSString *backup = nil;
    struct stat existing = {0};
    if (lstat([destination fileSystemRepresentation], &existing) == 0) {
        bool safeExisting = S_ISDIR(existing.st_mode) &&
                            !S_ISLNK(existing.st_mode) &&
                            existing.st_uid == 0 && existing.st_gid == 0 &&
                            (existing.st_mode & (S_IWGRP | S_IWOTH)) == 0;
        if (!safeExisting) {
            [manager removeItemAtPath:temporary error:nil];
            if (errorText != NULL) {
                *errorText = @"refusing unsafe existing system Sileo bundle";
            }
            return false;
        }
        backup = [parent stringByAppendingPathComponent:
            [NSString stringWithFormat:@".Sileo.app.previous-%@",
                                       [[NSUUID UUID] UUIDString]]];
        if (![manager moveItemAtPath:destination toPath:backup error:&error]) {
            [manager removeItemAtPath:temporary error:nil];
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"system Sileo old bundle staging failed: %@", error];
            }
            return false;
        }
    } else if (errno != ENOENT) {
        [manager removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = @"system Sileo destination status failed";
        }
        return false;
    }

    bool activated = rename([temporary fileSystemRepresentation],
                            [destination fileSystemRepresentation]) == 0 &&
                     bundle_trees_are_equal(source, destination);
    if (!activated) {
        int savedError = errno;
        [manager removeItemAtPath:temporary error:nil];
        [manager removeItemAtPath:destination error:nil];
        if (backup != nil) {
            [manager moveItemAtPath:backup toPath:destination error:nil];
        }
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"system Sileo bundle activation failed: %s",
                strerror(savedError)];
        }
        return false;
    }
    if (backup != nil && ![manager removeItemAtPath:backup error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"system Sileo old bundle cleanup failed: %@", error];
        }
        return false;
    }
    if (didUpdate != NULL) *didUpdate = true;
    log_message("sileoSystemBundleCopy=updated path=%s",
                [destination UTF8String]);
    return true;
}

static bool install_sbinject_bundle(NSString *source, NSString *destination,
                                    NSString *enableMarker,
                                    NSString *bundleStem, bool *didUpdate,
                                    NSString **backupOut,
                                    NSString **errorText) {
    if (didUpdate != NULL) {
        *didUpdate = false;
    }
    if (backupOut != NULL) {
        *backupOut = nil;
    }
    if (validated_bundle_entries(source, false) == nil) {
        if (errorText != NULL) {
            *errorText = @"SBInject SpringBoard source bundle is invalid";
        }
        return false;
    }
    NSString *parent = [destination stringByDeletingLastPathComponent];
    NSFileManager *manager = [NSFileManager defaultManager];
    NSError *error = nil;
    NSDictionary *directoryAttributes = @{
        NSFilePosixPermissions : @0755,
        NSFileOwnerAccountID : @0,
        NSFileGroupOwnerAccountID : @0,
    };
    if (![manager createDirectoryAtPath:parent
             withIntermediateDirectories:YES
                              attributes:directoryAttributes
                                   error:&error] ||
        ![manager setAttributes:directoryAttributes
                   ofItemAtPath:parent
                          error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                                       @"SBInject bundle parent failed: %@",
                                       error];
        }
        return false;
    }
    if (bundle_trees_are_equal(source, destination)) {
        log_message("sbinjectBundle=current target=%s path=%s",
                    [bundleStem UTF8String], [destination UTF8String]);
        return true;
    }

    // Stop launchd from selecting this bundle while it is being replaced.
    (void)unlink([enableMarker fileSystemRepresentation]);

    NSString *temporary = [parent
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".%@.sbinject-%@", bundleStem,
                                       [[NSUUID UUID] UUIDString]]];
    if (![manager copyItemAtPath:source toPath:temporary error:&error] ||
        !normalize_bundle_tree(source, temporary) ||
        !bundle_trees_are_equal(source, temporary)) {
        [manager removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                                       @"SBInject bundle staging failed: %@",
                                       error];
        }
        return false;
    }

    NSString *backup = nil;
    struct stat existing;
    if (lstat([destination fileSystemRepresentation], &existing) == 0) {
        NSString *backupDirectory = @"/var/jb/.codex-cache";
        if (![manager createDirectoryAtPath:backupDirectory
                 withIntermediateDirectories:YES
                                  attributes:directoryAttributes
                                       error:&error]) {
            [manager removeItemAtPath:temporary error:nil];
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"SBInject backup directory failed: %@", error];
            }
            return false;
        }
        backup = [backupDirectory
            stringByAppendingPathComponent:
                [NSString stringWithFormat:@"%@.before-sbinject-%@",
                                           bundleStem,
                                           [[NSUUID UUID] UUIDString]]];
        if (![manager moveItemAtPath:destination
                              toPath:backup
                               error:&error]) {
            [manager removeItemAtPath:temporary error:nil];
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"SBInject existing bundle backup failed: %@", error];
            }
            return false;
        }
    } else if (errno != ENOENT) {
        [manager removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = @"SBInject destination bundle status failed";
        }
        return false;
    }

    if (rename([temporary fileSystemRepresentation],
               [destination fileSystemRepresentation]) != 0 ||
        !bundle_trees_are_equal(source, destination)) {
        int savedError = errno;
        [manager removeItemAtPath:temporary error:nil];
        [manager removeItemAtPath:destination error:nil];
        if (backup != nil) {
            [manager moveItemAtPath:backup toPath:destination error:nil];
        }
        if (errorText != NULL) {
            *errorText = [NSString stringWithFormat:
                @"SBInject bundle activation failed: %s",
                strerror(savedError)];
        }
        return false;
    }
    if (didUpdate != NULL) {
        *didUpdate = true;
    }
    if (backupOut != NULL) {
        *backupOut = backup;
    }
    log_message("sbinjectBundle=updated target=%s path=%s backup=%s",
                [bundleStem UTF8String], [destination UTF8String],
                backup != nil ? [backup UTF8String] : "none");
    return true;
}

static bool install_sbinject_springboard_bundle(NSString *source,
                                                 bool *didUpdate,
                                                 NSString **backupOut,
                                                 NSString **errorText) {
    return install_sbinject_bundle(
        source, kSBInjectBundle, kSBInjectEnableMarker, @"SpringBoard.app",
        didUpdate, backupOut, errorText);
}

static bool install_sbinject_preferences_bundle(NSString *source,
                                                 bool *didUpdate,
                                                 NSString **backupOut,
                                                 NSString **errorText) {
    return install_sbinject_bundle(
        source, kSBInjectPreferencesBundle,
        kSBInjectPreferencesEnableMarker, @"Preferences.app", didUpdate,
        backupOut, errorText);
}

static bool replace_file_with_backup(NSString *source, NSString *destination,
                                     NSString *backup, NSString **errorText) {
    struct stat sourceStatus;
    struct stat destinationStatus;
    if (lstat([source fileSystemRepresentation], &sourceStatus) != 0 ||
        !S_ISREG(sourceStatus.st_mode) ||
        lstat([destination fileSystemRepresentation], &destinationStatus) !=
            0 ||
        !S_ISREG(destinationStatus.st_mode)) {
        if (errorText != NULL) {
            *errorText = @"source or destination is not a regular file";
        }
        return false;
    }
    NSString *temporary = [[destination stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".codex-new-%@",
                                       [[NSUUID UUID] UUIDString]]];
    int sourceFile = open([source fileSystemRepresentation],
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int temporaryFile = open([temporary fileSystemRepresentation],
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                                 O_NOFOLLOW,
                             0600);
    bool copied = sourceFile >= 0 && temporaryFile >= 0;
    unsigned char buffer[64 * 1024];
    while (copied) {
        ssize_t readLength;
        do {
            readLength = read(sourceFile, buffer, sizeof(buffer));
        } while (readLength < 0 && errno == EINTR);
        if (readLength < 0) {
            copied = false;
            break;
        }
        if (readLength == 0) {
            break;
        }
        const unsigned char *cursor = buffer;
        size_t remaining = (size_t)readLength;
        while (remaining > 0) {
            ssize_t writeLength = write(temporaryFile, cursor, remaining);
            if (writeLength < 0 && errno == EINTR) {
                continue;
            }
            if (writeLength <= 0) {
                copied = false;
                break;
            }
            cursor += writeLength;
            remaining -= (size_t)writeLength;
        }
    }
    if (copied &&
        (fchown(temporaryFile, destinationStatus.st_uid,
                destinationStatus.st_gid) != 0 ||
         fchmod(temporaryFile, destinationStatus.st_mode & 07777) != 0 ||
         fsync(temporaryFile) != 0)) {
        copied = false;
    }
    int savedCopyError = errno;
    if (sourceFile >= 0) {
        close(sourceFile);
    }
    if (temporaryFile >= 0) {
        close(temporaryFile);
    }
    if (!copied) {
        (void)unlink([temporary fileSystemRepresentation]);
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"trusted executable staging failed: %s",
                                 strerror(savedCopyError)];
        }
        return false;
    }
    log_message("trustedExecutableStaged source=%s temporary=%s",
                [source UTF8String], [temporary UTF8String]);
    if (rename([destination fileSystemRepresentation],
               [backup fileSystemRepresentation]) != 0) {
        int savedError = errno;
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"developer executable backup failed: %s",
                                 strerror(savedError)];
        }
        return false;
    }
    if (rename([temporary fileSystemRepresentation],
               [destination fileSystemRepresentation]) != 0) {
        int savedError = errno;
        (void)rename([backup fileSystemRepresentation],
                     [destination fileSystemRepresentation]);
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"trusted executable activation failed: %s",
                                 strerror(savedError)];
        }
        return false;
    }
    return true;
}

static int run_and_wait(const char *executable, char *const arguments[]) {
    pid_t child = 0;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, gLog, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, gLog, STDERR_FILENO);
    int spawn_result =
        posix_spawn(&child, executable, &actions, NULL, arguments, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (spawn_result != 0) {
        log_message("spawn failed executable=%s error=%s", executable,
                    strerror(spawn_result));
        return 255;
    }

    int status = 0;
    while (waitpid(child, &status, 0) == -1) {
        if (errno != EINTR) {
            log_message("waitpid failed pid=%d error=%s", child,
                        strerror(errno));
            return 255;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        log_message("child signaled executable=%s signal=%d", executable,
                    WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    return 255;
}

static int run_and_wait_bounded_to_fd(const char *executable,
                                      char *const arguments[],
                                      unsigned int timeoutMilliseconds,
                                      int outputDescriptor) {
    pid_t child = 0;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes = NULL;
    int result = posix_spawn_file_actions_init(&actions);
    if (result != 0) {
        return 255;
    }
    posix_spawn_file_actions_adddup2(&actions, outputDescriptor,
                                     STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, outputDescriptor,
                                     STDERR_FILENO);
    result = posix_spawnattr_init(&attributes);
    if (result == 0) {
        result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    if (result == 0) {
        result = posix_spawnattr_setflags(&attributes,
                                          POSIX_SPAWN_SETPGROUP);
    }
    if (result == 0) {
        result = posix_spawn(&child, executable, &actions, &attributes,
                             arguments, environ);
    }
    posix_spawn_file_actions_destroy(&actions);
    if (result == 0) {
        posix_spawnattr_destroy(&attributes);
    } else {
        if (attributes != NULL) {
            posix_spawnattr_destroy(&attributes);
        }
        log_message("bounded spawn failed executable=%s error=%s",
                    executable, strerror(result));
        return 255;
    }

    const useconds_t pollInterval = 10 * 1000;
    unsigned int elapsed = 0;
    int status = 0;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                log_message("bounded child signaled executable=%s signal=%d",
                            executable, WTERMSIG(status));
                return 128 + WTERMSIG(status);
            }
            return 255;
        }
        if (waited < 0 && errno != EINTR) {
            log_message("bounded waitpid failed pid=%d error=%s", child,
                        strerror(errno));
            return 255;
        }
        if (elapsed >= timeoutMilliseconds) {
            // The child is a dedicated process-group leader. Terminate only
            // that loader group; the target process is never a member.
            log_message("bounded child timeout executable=%s pid=%d "
                        "timeoutMs=%u pid1Guard=true",
                        executable, child, timeoutMilliseconds);
            if (child > 1) {
                (void)kill(-child, SIGTERM);
                for (unsigned int grace = 0; grace < 25; ++grace) {
                    waited = waitpid(child, &status, WNOHANG);
                    if (waited == child) {
                        return 124;
                    }
                    usleep(pollInterval);
                }
                (void)kill(-child, SIGKILL);
            }
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
            return 124;
        }
        usleep(pollInterval);
        elapsed += 10;
    }
}

static int run_and_wait_bounded(const char *executable,
                                char *const arguments[],
                                unsigned int timeoutMilliseconds) {
    return run_and_wait_bounded_to_fd(executable, arguments,
                                      timeoutMilliseconds, gLog);
}

static NSString *dpkg_control_field(NSString *paragraph, NSString *field) {
    NSString *prefix = [field stringByAppendingString:@":"];
    NSMutableString *value = nil;
    BOOL collecting = NO;
    for (NSString *line in
         [paragraph componentsSeparatedByCharactersInSet:
                        [NSCharacterSet newlineCharacterSet]]) {
        if ([line hasPrefix:prefix]) {
            NSString *firstLine = [[line substringFromIndex:prefix.length]
                stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceCharacterSet]];
            value = [firstLine mutableCopy];
            collecting = YES;
            continue;
        }
        if (collecting &&
            ([line hasPrefix:@" "] || [line hasPrefix:@"\t"])) {
            NSString *continuation =
                [line stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
            if (continuation.length != 0) {
                [value appendFormat:@" %@", continuation];
            }
            continue;
        }
        if (collecting) {
            break;
        }
    }
    return value;
}

static NSArray<NSString *> *dpkg_installed_paragraphs(NSString *status) {
    NSString *normalized =
        [status stringByReplacingOccurrencesOfString:@"\r\n"
                                          withString:@"\n"];
    NSMutableArray<NSString *> *installed = [NSMutableArray array];
    for (NSString *paragraph in
         [normalized componentsSeparatedByString:@"\n\n"]) {
        if ([[dpkg_control_field(paragraph, @"Status") lowercaseString]
                isEqualToString:@"install ok installed"] &&
            dpkg_control_field(paragraph, @"Package").length != 0) {
            [installed addObject:paragraph];
        }
    }
    return installed;
}

static bool dpkg_package_version_is_installed(NSString *packageName,
                                               NSString *version) {
    NSError *error = nil;
    NSString *status = [NSString
        stringWithContentsOfFile:@"/var/jb/Library/dpkg/status"
                        encoding:NSUTF8StringEncoding
                           error:&error];
    if (status == nil || error != nil) return false;
    for (NSString *paragraph in dpkg_installed_paragraphs(status)) {
        if ([dpkg_control_field(paragraph, @"Package")
                isEqualToString:packageName] &&
            [dpkg_control_field(paragraph, @"Version")
                isEqualToString:version]) return true;
    }
    return false;
}

static NSString *dpkg_relation_name(NSString *relation) {
    NSString *name =
        [relation stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceCharacterSet]];
    NSRange delimiter = [name
        rangeOfCharacterFromSet:
            [NSCharacterSet characterSetWithCharactersInString:@" \t([<"]];
    if (delimiter.location != NSNotFound) {
        name = [name substringToIndex:delimiter.location];
    }
    NSRange architecture = [name rangeOfString:@":"];
    if (architecture.location != NSNotFound) {
        name = [name substringToIndex:architecture.location];
    }
    return name;
}

static bool dpkg_relation_field_contains(NSString *value,
                                         NSString *packageName) {
    for (NSString *group in [value componentsSeparatedByString:@","]) {
        for (NSString *alternative in
             [group componentsSeparatedByString:@"|"]) {
            if ([dpkg_relation_name(alternative)
                    isEqualToString:packageName]) {
                return true;
            }
        }
    }
    return false;
}

static bool dpkg_has_installed_capability(
    NSArray<NSString *> *installedParagraphs, NSString *capability) {
    for (NSString *paragraph in installedParagraphs) {
        if ([dpkg_control_field(paragraph, @"Package")
                isEqualToString:capability] ||
            dpkg_relation_field_contains(
                dpkg_control_field(paragraph, @"Provides"), capability)) {
            return true;
        }
    }
    return false;
}

static bool repair_unsupported_kernel_packages(bool *didRemove,
                                                NSString **errorText) {
    if (didRemove != NULL) {
        *didRemove = false;
    }
    NSError *statusError = nil;
    NSString *status = [NSString
        stringWithContentsOfFile:@"/var/jb/Library/dpkg/status"
                        encoding:NSUTF8StringEncoding
                           error:&statusError];
    if (status == nil) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"could not read dpkg status: %@",
                                 statusError];
        }
        return false;
    }

    NSArray<NSString *> *installedParagraphs =
        dpkg_installed_paragraphs(status);
    if (!dpkg_has_installed_capability(installedParagraphs, @"libkrw0")) {
        log_message("kernelPackageCompatibility=not-needed");
        return true;
    }
    if (dpkg_has_installed_capability(installedParagraphs,
                                      @"libkrw0-plugin")) {
        log_message("kernelPackageCompatibility=provider-present");
        return true;
    }

    NSArray<NSString *> *removalOrder =
        @[@"shshd", @"libdimentio0", @"libkrw0"];
    NSSet<NSString *> *removalSet = [NSSet setWithArray:removalOrder];
    NSMutableArray<NSString *> *installedTargets = [NSMutableArray array];
    for (NSString *paragraph in installedParagraphs) {
        NSString *packageName = dpkg_control_field(paragraph, @"Package");
        if (![removalSet containsObject:packageName]) {
            continue;
        }
        NSString *essential =
            [dpkg_control_field(paragraph, @"Essential") lowercaseString];
        NSString *protectedValue =
            [dpkg_control_field(paragraph, @"Protected") lowercaseString];
        if ([essential isEqualToString:@"yes"] ||
            [protectedValue isEqualToString:@"yes"]) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"refusing to remove protected package %@",
                        packageName];
            }
            return false;
        }
        [installedTargets addObject:packageName];
    }

    for (NSString *paragraph in installedParagraphs) {
        NSString *packageName = dpkg_control_field(paragraph, @"Package");
        if ([removalSet containsObject:packageName]) {
            continue;
        }
        for (NSString *field in @[@"Pre-Depends", @"Depends"]) {
            NSString *relations = dpkg_control_field(paragraph, field);
            for (NSString *target in removalSet) {
                if (dpkg_relation_field_contains(relations, target)) {
                    if (errorText != NULL) {
                        *errorText = [NSString
                            stringWithFormat:
                                @"refusing kernel-package repair because %@ "
                                 "depends on %@",
                                packageName, target];
                    }
                    return false;
                }
            }
        }
    }

    if (installedTargets.count == 0) {
        if (errorText != NULL) {
            *errorText = @"libkrw0 capability has no removable package";
        }
        return false;
    }

    NSString *savedPrerm = nil;
    NSString *shshdPrerm = @"/var/jb/Library/dpkg/info/shshd.prerm";
    if ([installedTargets containsObject:@"shshd"] &&
        [[NSFileManager defaultManager] fileExistsAtPath:shshdPrerm]) {
        char *bootoutArguments[] = {
            "/var/jb/usr/bin/launchctl", "bootout", "system/us.diatr.shshd",
            NULL};
        int bootoutStatus =
            run_and_wait(bootoutArguments[0], bootoutArguments);
        log_message("shshdBootoutExit=%d", bootoutStatus);

        NSString *cacheDirectory = @"/var/jb/.codex-cache";
        NSError *cacheError = nil;
        if (![[NSFileManager defaultManager]
                createDirectoryAtPath:cacheDirectory
          withIntermediateDirectories:YES
                           attributes:@{
                               NSFilePosixPermissions : @0700,
                               NSFileOwnerAccountID : @0,
                               NSFileGroupOwnerAccountID : @0,
                           }
                                error:&cacheError]) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"could not stage shshd removal: %@",
                                     cacheError];
            }
            return false;
        }
        savedPrerm = [cacheDirectory
            stringByAppendingPathComponent:
                [NSString stringWithFormat:@"shshd.prerm-%@",
                                           [[NSUUID UUID] UUIDString]]];
        if (rename([shshdPrerm fileSystemRepresentation],
                   [savedPrerm fileSystemRepresentation]) != 0) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"could not isolate shshd prerm: %s",
                                     strerror(errno)];
            }
            return false;
        }
        log_message("shshdPrermIsolated=true backup=%s",
                    [savedPrerm UTF8String]);
    }

    char *dpkgArguments[6] = {
        "/var/jb/usr/bin/dpkg", "--remove", NULL, NULL, NULL, NULL};
    NSUInteger argumentIndex = 2;
    for (NSString *packageName in removalOrder) {
        if ([installedTargets containsObject:packageName]) {
            dpkgArguments[argumentIndex++] =
                (char *)[packageName UTF8String];
        }
    }
    int dpkgStatus = run_and_wait(dpkgArguments[0], dpkgArguments);
    log_message("kernelPackageRemoveExit=%d packages=%s", dpkgStatus,
                [[installedTargets componentsJoinedByString:@","] UTF8String]);
    if (dpkgStatus != 0) {
        bool restored = savedPrerm == nil;
        if (savedPrerm != nil &&
            ![[NSFileManager defaultManager] fileExistsAtPath:shshdPrerm]) {
            restored = rename([savedPrerm fileSystemRepresentation],
                              [shshdPrerm fileSystemRepresentation]) == 0;
        }
        log_message("shshdPrermRollback=%s",
                    restored ? "complete" : "failed");
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:
                    @"unsupported kernel package removal exited %d",
                    dpkgStatus];
        }
        return false;
    }
    if (savedPrerm != nil &&
        unlink([savedPrerm fileSystemRepresentation]) != 0 &&
        errno != ENOENT) {
        log_message("shshdPrermBackupCleanup=false error=%s",
                    strerror(errno));
    }
    if (didRemove != NULL) {
        *didRemove = true;
    }
    log_message("kernelPackageCompatibility=repaired");
    return true;
}

static bool install_sbinject_jitterd_job(NSString *sourceExecutable,
                                         NSString *sourcePlist,
                                         bool restartRequired,
                                         NSString **errorText) {
    if (!files_are_equal(sourceExecutable, kSBInjectJitterdExecutable) ||
        !files_are_equal(sourcePlist, kSBInjectJitterdPlist) ||
        !sbinject_managed_file(kSBInjectJitterdExecutable, 0755) ||
        !sbinject_managed_file(kSBInjectJitterdPlist, 0644)) {
        if (errorText != NULL) {
            *errorText = @"SBInject jitterd payload verification failed";
        }
        return false;
    }

    NSError *directoryError = nil;
    NSDictionary *attributes = @{
        NSFilePosixPermissions : @0755,
        NSFileOwnerAccountID : @0,
        NSFileGroupOwnerAccountID : @0,
    };
    for (NSString *directory in @[@"/var/jb/var/log",
                                   @"/var/jb/var/lib/sbinject"]) {
        if (![[NSFileManager defaultManager]
                createDirectoryAtPath:directory
          withIntermediateDirectories:YES
                           attributes:attributes
                                error:&directoryError] ||
            ![[NSFileManager defaultManager] setAttributes:attributes
                                              ofItemAtPath:directory
                                                     error:&directoryError]) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"SBInject state directory failed: %@", directoryError];
            }
            return false;
        }
    }

    NSString *target =
        [@"system/" stringByAppendingString:kSBInjectJitterdLabel];
    if (restartRequired) {
        char *bootoutArguments[] = {
            "/var/jb/usr/bin/launchctl", "bootout",
            (char *)[target fileSystemRepresentation], NULL};
        int bootoutStatus = run_and_wait_bounded(
            bootoutArguments[0], bootoutArguments, 10000);
        log_message("sbinjectJitterdBootout status=%d target=%s",
                    bootoutStatus, [target UTF8String]);
    }

    mach_port_t existingPort = MACH_PORT_NULL;
    kern_return_t existing = bootstrap_look_up(
        bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE, &existingPort);
    bool alreadyReady = existing == KERN_SUCCESS &&
                        MACH_PORT_VALID(existingPort) && !restartRequired;
    if (MACH_PORT_VALID(existingPort)) {
        mach_port_deallocate(mach_task_self(), existingPort);
    }
    if (!alreadyReady) {
        char *bootstrapArguments[] = {
            "/var/jb/usr/bin/launchctl", "bootstrap", "system",
            (char *)[kSBInjectJitterdPlist fileSystemRepresentation], NULL};
        int bootstrapStatus = run_and_wait_bounded(
            bootstrapArguments[0], bootstrapArguments, 10000);
        log_message("sbinjectJitterdBootstrap status=%d plist=%s",
                    bootstrapStatus, [kSBInjectJitterdPlist UTF8String]);
        if (bootstrapStatus != 0) {
            if (errorText != NULL) {
                *errorText = [NSString stringWithFormat:
                    @"SBInject jitterd bootstrap exited %d", bootstrapStatus];
            }
            return false;
        }
    }

    bool serviceReady = false;
    for (NSUInteger attempt = 0; attempt < 500; ++attempt) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t lookup = bootstrap_look_up(
            bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE, &port);
        if (lookup == KERN_SUCCESS && MACH_PORT_VALID(port)) {
            mach_port_deallocate(mach_task_self(), port);
            serviceReady = true;
            break;
        }
        usleep(10 * 1000);
    }
    log_message("sbinjectJitterdReady=%s restartRequired=%s",
                serviceReady ? "true" : "false",
                restartRequired ? "true" : "false");
    if (!serviceReady && errorText != NULL) {
        *errorText = @"SBInject jitterd Mach service did not become ready";
    }
    return serviceReady;
}

static bool install_sileo_root_broker_job(NSString *sourceExecutable,
                                          NSString *registeredPath,
                                          NSString *jailbreakRoot,
                                          NSString **errorText) {
    NSFileManager *manager = [NSFileManager defaultManager];
    NSArray<NSString *> *directories = @[
        [kRootBrokerExecutable stringByDeletingLastPathComponent],
        [kRootBrokerPlist stringByDeletingLastPathComponent],
    ];
    NSError *error = nil;
    for (NSString *directory in directories) {
        if (![manager createDirectoryAtPath:directory
                 withIntermediateDirectories:YES
                                  attributes:@{
                                      NSFilePosixPermissions : @0755,
                                      NSFileOwnerAccountID : @0,
                                      NSFileGroupOwnerAccountID : @0,
                                  }
                                       error:&error]) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"root broker directory failed: %@",
                                     error];
            }
            return false;
        }
    }

    NSString *serviceTarget =
        [@"system/" stringByAppendingString:kRootBrokerLabel];
    char *bootoutArguments[] = {
        "/var/jb/usr/bin/launchctl", "bootout", "system/"
        "com.openai.codex.dopamine.sileo-root-broker", NULL};
    int bootoutStatus = run_and_wait(bootoutArguments[0], bootoutArguments);
    log_message("sileoRootBrokerBootoutExit=%d target=%s", bootoutStatus,
                [serviceTarget UTF8String]);

    NSString *temporaryExecutable = [[kRootBrokerExecutable
        stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".codex-sileo-root-broker-%@",
                                       [[NSUUID UUID] UUIDString]]];
    if (![manager copyItemAtPath:sourceExecutable
                          toPath:temporaryExecutable
                           error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"root broker executable copy failed: %@",
                                 error];
        }
        return false;
    }
    int executableFile = open([temporaryExecutable fileSystemRepresentation],
                              O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (executableFile < 0 || fchown(executableFile, 0, 0) != 0 ||
        fchmod(executableFile, 0755) != 0 ||
        rename([temporaryExecutable fileSystemRepresentation],
               [kRootBrokerExecutable fileSystemRepresentation]) != 0) {
        int savedError = errno;
        if (executableFile >= 0) {
            close(executableFile);
        }
        [manager removeItemAtPath:temporaryExecutable error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"root broker executable activation failed: %s",
                                 strerror(savedError)];
        }
        return false;
    }
    close(executableFile);
    if (!files_are_equal(sourceExecutable, kRootBrokerExecutable)) {
        if (errorText != NULL) {
            *errorText = @"root broker executable does not exactly match its "
                         "trust-cache input";
        }
        return false;
    }

    NSDictionary *job = @{
        @"Label" : kRootBrokerLabel,
        @"ProgramArguments" : @[
            kRootBrokerExecutable,
            @"--sileo-root-broker",
            registeredPath,
            jailbreakRoot,
        ],
        @"RunAtLoad" : @YES,
        @"KeepAlive" : @YES,
        @"ProcessType" : @"Background",
        @"ThrottleInterval" : @10,
        @"MachServices" : @{
            @CODEX_ROOT_BROKER_MACH_SERVICE : @YES,
        },
    };
    NSData *jobData = [NSPropertyListSerialization
        dataWithPropertyList:job
                      format:NSPropertyListXMLFormat_v1_0
                     options:0
                       error:&error];
    NSString *temporaryPlist = [[kRootBrokerPlist
        stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".codex-sileo-root-broker-%@.plist",
                                       [[NSUUID UUID] UUIDString]]];
    if (jobData == nil || ![jobData writeToFile:temporaryPlist
                                      options:NSDataWritingAtomic
                                        error:&error]) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"root broker plist write failed: %@", error];
        }
        return false;
    }
    int plistFile = open([temporaryPlist fileSystemRepresentation],
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (plistFile < 0 || fchown(plistFile, 0, 0) != 0 ||
        fchmod(plistFile, 0644) != 0 ||
        rename([temporaryPlist fileSystemRepresentation],
               [kRootBrokerPlist fileSystemRepresentation]) != 0) {
        int savedError = errno;
        if (plistFile >= 0) {
            close(plistFile);
        }
        [manager removeItemAtPath:temporaryPlist error:nil];
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"root broker plist activation failed: %s",
                                 strerror(savedError)];
        }
        return false;
    }
    close(plistFile);

    char *bootstrapArguments[] = {
        "/var/jb/usr/bin/launchctl", "bootstrap", "system",
        (char *)[kRootBrokerPlist fileSystemRepresentation], NULL};
    int bootstrapStatus =
        run_and_wait(bootstrapArguments[0], bootstrapArguments);
    log_message("sileoRootBrokerBootstrapExit=%d plist=%s", bootstrapStatus,
                [kRootBrokerPlist UTF8String]);
    if (bootstrapStatus != 0) {
        if (errorText != NULL) {
            *errorText = [NSString
                stringWithFormat:@"launchctl bootstrap exited %d",
                                 bootstrapStatus];
        }
        return false;
    }

    bool serviceReady = false;
    for (NSUInteger attempt = 0; attempt < 200; ++attempt) {
        mach_port_t servicePort = MACH_PORT_NULL;
        kern_return_t lookupResult = bootstrap_look_up(
            bootstrap_port, CODEX_ROOT_BROKER_MACH_SERVICE, &servicePort);
        if (lookupResult == KERN_SUCCESS && MACH_PORT_VALID(servicePort)) {
            mach_port_deallocate(mach_task_self(), servicePort);
            serviceReady = true;
            break;
        }
        usleep(10 * 1000);
    }
    log_message("sileoSystemRootBrokerReady=%s",
                serviceReady ? "true" : "false");
    if (!serviceReady && errorText != NULL) {
        *errorText = @"system root broker Mach service did not become ready";
    }
    return serviceReady;
}

static int fail(NSString *reason, NSString *partialRoot) {
    log_message("result=failed reason=%s", [reason UTF8String]);
    if (partialRoot != nil && path_is_absent(kVarJb)) {
        NSError *cleanup_error = nil;
        if ([[NSFileManager defaultManager] removeItemAtPath:partialRoot
                                                       error:&cleanup_error]) {
            log_message("partialCleanup=complete path=%s",
                        [partialRoot UTF8String]);
        } else {
            log_message("partialCleanup=failed path=%s error=%s",
                        [partialRoot UTF8String],
                        [[cleanup_error description] UTF8String]);
        }
    }
    write_marker(kFailurePath,
                 [reason stringByAppendingString:@"\n"]);
    close(gLog);
    return 1;
}

int main(int argc, char *argv[]) {
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_LIBRARY_PATH");
    codex_jetsam_adjustment_t jetsam = adjust_self_jetsam_limit();
    @autoreleasepool {
        gUnifiedLog = os_log_create("com.openai.codex.dopamine.bootstrap",
                                    "installer");
        gLog = open(kLogPath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (gLog < 0) {
            gLog = STDERR_FILENO;
        }
        log_message(
            "selfJetsam initialStatus=%d initialErrno=%d initialActiveMB=%d "
            "initialInactiveMB=%d setStatus=%d setErrno=%d "
            "fallbackStatus=%d fallbackErrno=%d effectiveStatus=%d "
            "effectiveErrno=%d effectiveActiveMB=%d effectiveInactiveMB=%d",
            jetsam.initial_status, jetsam.initial_errno,
            jetsam.initial.memlimit_active, jetsam.initial.memlimit_inactive,
            jetsam.set_status, jetsam.set_errno, jetsam.fallback_status,
            jetsam.fallback_errno, jetsam.effective_status,
            jetsam.effective_errno, jetsam.effective.memlimit_active,
            jetsam.effective.memlimit_inactive);
        if (argc == 2 &&
            strcmp(argv[1], "--sbinject-respring") == 0) {
            NSString *managedRoot = managed_jailbreak_root();
            if (geteuid() != 0 || managedRoot == nil ||
                !configure_managed_environment(managedRoot)) {
                log_message("sbinjectRespringModeValidation=false");
                return 1;
            }
            bool resprung =
                respring_sbinject_springboard("sileo-button");
            log_message("sbinjectRespringMode=%s",
                        resprung ? "success" : "failed");
            return resprung ? 0 : 1;
        }
        if (argc == 4 &&
            strcmp(argv[1], "--sileo-root-broker") == 0) {
            log_message("event=sileo-root-broker-start uid=%u euid=%u pid=%d",
                        getuid(), geteuid(), getpid());
            NSString *registeredPath =
                [NSString stringWithUTF8String:argv[2]];
            NSString *jailbreakRoot =
                [NSString stringWithUTF8String:argv[3]];
            NSString *managedRoot = managed_jailbreak_root();
            if (geteuid() != 0 ||
                !is_sileo_client_bundle_path(registeredPath) ||
                managedRoot == nil ||
                ![managedRoot isEqual:jailbreakRoot]) {
                log_message("sileoRootBrokerModeValidation=false");
                return 1;
            }
            if (!configure_managed_environment(jailbreakRoot)) {
                log_message("sileoRootBrokerEnvironment=false");
                return 1;
            }
            log_message("sileoRootBrokerEnvironment=true root=%s",
                        [jailbreakRoot UTF8String]);
            log_message("deviceAutonomyVersion=3 "
                        "aptPreInstallClassification=true "
                        "sbinjectJITPackages=true preMainElleKit=true "
                        "dynamicTrustCache=false");
            bool sbinjectReady =
                sbinject_infrastructure_ready("broker-start");
            if (!sbinjectReady) {
                log_message("sbinjectStartup=false reason=infrastructure "
                            "dynamicTrustCache=false");
                return 1;
            }
            if (!start_sileo_xpc_broker(registeredPath, jailbreakRoot)) {
                log_message("sileoRootBrokerModeListener=false");
                return 1;
            }
            log_message("sileoRootBrokerModeReady=true path=%s root=%s",
                        [registeredPath UTF8String],
                        [jailbreakRoot UTF8String]);
            dispatch_queue_t activationQueue = dispatch_queue_create(
                "com.openai.codex.dopamine.sbinject-boot-activation",
                DISPATCH_QUEUE_SERIAL);
            dispatch_async(activationQueue, ^{
                bool sbinjectActive = activate_sbinject_springboard();
                bool sbinjectPreferencesActive =
                    sbinjectActive && activate_sbinject_preferences();
                bool sbinjectAmfidActive =
                    sbinjectActive && activate_sbinject_amfid();
                if (sbinjectAmfidActive) {
                    start_amfid_jit_monitor();
                }
                bool applicationRegistrationsReady =
                    sbinjectAmfidActive &&
                    refresh_rootless_application_registrations(
                        "broker-start");
                log_message("sbinjectStartup=%s fallback=%s",
                            sbinjectActive ? "active" : "inactive",
                            sbinjectActive ? "none" : "stock-springboard");
                log_message("sbinjectPreferencesStartup=%s fallback=%s",
                            sbinjectPreferencesActive ? "active" : "inactive",
                            sbinjectPreferencesActive ? "none"
                                                       : "stock-preferences");
                log_message("sbinjectAmfidStartup=%s fallback=%s",
                            sbinjectAmfidActive ? "active" : "inactive",
                            sbinjectAmfidActive ? "none" : "stock-amfid");
                log_message("sbinjectApplicationStartup=%s",
                            applicationRegistrationsReady ? "ready"
                                                          : "inactive");
            });
            dispatch_main();
            __builtin_unreachable();
        }
        if (argc == 2 &&
            strcmp(argv[1], "--sbinject-debs-stdin") == 0) {
            NSString *managedRoot = managed_jailbreak_root();
            if (geteuid() != 0 || managedRoot == nil) {
                log_message("sbinjectAptHookValidation=false");
                return 1;
            }
            if (!configure_managed_environment(managedRoot)) {
                log_message("sbinjectAptHookEnvironment=false");
                return 1;
            }
            bool validated = sbinject_validate_debs_from_standard_input();
            log_message("sbinjectAptHook=%s dynamicTrustCache=false",
                        validated ? "success" : "failed");
            return validated ? 0 : 1;
        }
        if (argc != 1) {
            log_message("result=failed reason=invalid invocation");
            return 1;
        }
        unlink(kDonePath);
        unlink(kFailurePath);
        log_message("event=start uid=%u euid=%u gid=%u egid=%u pid=%d",
                    getuid(), geteuid(), getgid(), getegid(), getpid());
        if (geteuid() != 0) {
            return fail(@"installer did not run as root", nil);
        }
        NSString *destinationProcursus = managed_jailbreak_root();
        BOOL repairMode = destinationProcursus != nil;
        if (!path_is_absent(kVarJb) && !repairMode) {
            return fail(@"refusing unmanaged pre-existing /var/jb", nil);
        }
        log_message("mode=%s", repairMode ? "registration-repair"
                                           : "fresh-bootstrap");

        NSString *executable = executable_path();
        if (executable == nil) {
            return fail(@"could not resolve installer path", nil);
        }
        NSString *mountRoot = executable;
        for (NSUInteger index = 0; index < 4; ++index) {
            mountRoot = [mountRoot stringByDeletingLastPathComponent];
        }
        NSString *payloadRoot =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/share/codex-bootstrap"];
        NSString *sourceProcursus =
            [payloadRoot stringByAppendingPathComponent:@"procursus"];
        NSString *sourceSileo =
            [payloadRoot stringByAppendingPathComponent:@"sileo.deb"];
        NSString *sourceElleKit =
            [payloadRoot stringByAppendingPathComponent:@"ellekit.deb"];
        NSString *sourcePreferenceLoader =
            [payloadRoot stringByAppendingPathComponent:
                             @"preferenceloader.deb"];
        NSString *sourceOpenSSHClient =
            [payloadRoot stringByAppendingPathComponent:@"openssh-client.deb"];
        NSString *sourceOpenSSHServer =
            [payloadRoot stringByAppendingPathComponent:@"openssh-server.deb"];
        NSString *sourceOpenSSHSFTPServer =
            [payloadRoot stringByAppendingPathComponent:
                             @"openssh-sftp-server.deb"];
        NSString *sourceOpenSSHConfig =
            [sourceProcursus stringByAppendingPathComponent:
                                  @"etc/ssh/sshd_config"];
        NSString *sourceHostSSHAuthorizedKeys =
            [payloadRoot stringByAppendingPathComponent:
                             @"host-ssh-authorized-keys"];
        NSString *sourceTrustedSileo =
            [mountRoot stringByAppendingPathComponent:@"Applications/Sileo.app"];
        NSString *sourceTrustedElleKitRoot =
            [payloadRoot stringByAppendingPathComponent:
                             @"trusted/ellekit-root/var/jb"];
        NSString *sourceTrustedLaunchctl =
            [sourceProcursus stringByAppendingPathComponent:@"usr/bin/launchctl"];
        NSString *sourceTrustedUiopen =
            [sourceProcursus stringByAppendingPathComponent:@"usr/bin/uiopen"];
        NSString *sourceTrustedUicache =
            [sourceProcursus stringByAppendingPathComponent:@"usr/bin/uicache"];
        NSString *sourceDefaultSources =
            [payloadRoot stringByAppendingPathComponent:
                             @"dopamine-default.sources"];
        NSString *sourceRepositoryCompatibility =
            [payloadRoot stringByAppendingPathComponent:
                             @"apt/99dopamine-repository-compat"];
        NSString *sourceSBInjectAptConfig =
            [payloadRoot stringByAppendingPathComponent:
                             @"apt/98sbinject-packages"];
        NSString *sourcePreferenceLoaderPin =
            [payloadRoot stringByAppendingPathComponent:
                             @"apt/99preferenceloader"];
        NSString *sourceSileoPin =
            [payloadRoot stringByAppendingPathComponent:
                             @"apt/99codex-system-sileo"];
        NSString *sourceAptListNormalizer =
            [payloadRoot stringByAppendingPathComponent:
                             @"normalize-apt-lists.sh"];
        NSString *sourceCleanInstallToken =
            [payloadRoot stringByAppendingPathComponent:
                             @"clean-install-token.txt"];
        NSString *sourceElleKitCompatLoader =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/codex-ellekit-loader"];
        NSString *sourceExecWorker =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/codex-exec-worker"];
        NSString *sourceSBInjectGeneralHook =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/lib/sbinject/generalhook.dylib"];
        NSString *sourceSBInjectAmfidHook =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/lib/sbinject/amfihook.dylib"];
        NSString *sourceSBInjectPreferencesBridge =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/lib/sbinject/preferences-bridge.dylib"];
        NSString *sourceSBInjectLaunchdHook =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/lib/sbinject/launchdhook-v12.dylib"];
        NSString *sourceSBInjectLsdRegistrationHook =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/lib/sbinject/lsd-registration-hook.dylib"];
        NSString *sourceSBInjectJitterd =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/sbinject-jitterd"];
        NSString *sourceSBInjectPackageValidator =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/sbinject-package-validator"];
        NSString *sourceSBInjectRoot =
            [payloadRoot stringByAppendingPathComponent:@"sbinject"];
        NSString *sourceSBInjectBundle =
            [sourceSBInjectRoot stringByAppendingPathComponent:
                                    @"SpringBoard.app"];
        NSString *sourceSBInjectPreferencesBundle =
            [sourceSBInjectRoot stringByAppendingPathComponent:
                                    @"Preferences.app"];
        NSString *sourceSBInjectAmfidRoot =
            [sourceSBInjectRoot stringByAppendingPathComponent:@"amfid"];
        NSString *sourceSBInjectAmfidCandidate =
            [sourceSBInjectAmfidRoot stringByAppendingPathComponent:
                                        @"notamfid"];
        NSString *sourceSBInjectAmfidCandidateHook =
            [sourceSBInjectAmfidRoot stringByAppendingPathComponent:@"a"];
        NSString *sourceSBInjectJitterdPlist =
            [sourceSBInjectRoot stringByAppendingPathComponent:
                                    @"com.openai.codex.sbinject.jitterd.plist"];
        NSString *sourceKeyringDirectory =
            [payloadRoot stringByAppendingPathComponent:@"keyrings"];
        NSString *sourceElleKitKey =
            [sourceKeyringDirectory stringByAppendingPathComponent:
                                        @"ellekit.gpg"];
        NSString *sourceBigBossKey =
            [sourceKeyringDirectory stringByAppendingPathComponent:
                                        @"bigboss.gpg"];
        BOOL isDirectory = NO;
        if (![[NSFileManager defaultManager] fileExistsAtPath:sourceProcursus
                                                 isDirectory:&isDirectory] ||
            !isDirectory ||
            ![[NSFileManager defaultManager] fileExistsAtPath:sourceSileo] ||
            ![[NSFileManager defaultManager] fileExistsAtPath:sourceElleKit] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourcePreferenceLoader] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceOpenSSHClient] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceOpenSSHServer] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceOpenSSHSFTPServer] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedSileo
                     isDirectory:&isDirectory] ||
            !isDirectory ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedElleKitRoot
                     isDirectory:&isDirectory] ||
            !isDirectory ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedLaunchctl] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedUiopen] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedUicache] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceSBInjectAmfidHook] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceSBInjectAmfidCandidate] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceSBInjectAmfidCandidateHook] ||
            !is_sileo_system_bundle_path(sourceTrustedSileo)) {
            return fail(@"cryptex payload is incomplete", nil);
        }
        if (!files_are_equal(sourceSBInjectAmfidHook,
                             sourceSBInjectAmfidCandidateHook)) {
            return fail(@"amfid fixed hook copies do not match", nil);
        }
        struct stat defaultSourcesStatus;
        if (lstat([sourceDefaultSources fileSystemRepresentation],
                  &defaultSourcesStatus) != 0 ||
            !S_ISREG(defaultSourcesStatus.st_mode)) {
            return fail(@"default APT source payload is missing", nil);
        }
        struct stat repositoryCompatibilityStatus;
        if (lstat([sourceRepositoryCompatibility fileSystemRepresentation],
                  &repositoryCompatibilityStatus) != 0 ||
            !S_ISREG(repositoryCompatibilityStatus.st_mode)) {
            return fail(@"repository compatibility payload is missing", nil);
        }
        if (lstat([sourceSBInjectAptConfig fileSystemRepresentation],
                  &repositoryCompatibilityStatus) != 0 ||
            !S_ISREG(repositoryCompatibilityStatus.st_mode)) {
            return fail(@"SBInject APT package policy is missing", nil);
        }
        if (lstat([sourcePreferenceLoaderPin fileSystemRepresentation],
                  &repositoryCompatibilityStatus) != 0 ||
            !S_ISREG(repositoryCompatibilityStatus.st_mode)) {
            return fail(@"PreferenceLoader APT pin is missing", nil);
        }
        if (lstat([sourceSileoPin fileSystemRepresentation],
                  &repositoryCompatibilityStatus) != 0 ||
            !S_ISREG(repositoryCompatibilityStatus.st_mode)) {
            return fail(@"system Sileo APT pin is missing", nil);
        }
        struct stat aptListNormalizerStatus;
        if (lstat([sourceAptListNormalizer fileSystemRepresentation],
                  &aptListNormalizerStatus) != 0 ||
            !S_ISREG(aptListNormalizerStatus.st_mode)) {
            return fail(@"APT package-list normalizer is missing", nil);
        }
        NSString *cleanInstallToken = nil;
        struct stat cleanInstallTokenStatus;
        if (lstat([sourceCleanInstallToken fileSystemRepresentation],
                  &cleanInstallTokenStatus) == 0) {
            NSError *tokenError = nil;
            NSString *rawToken = [NSString
                stringWithContentsOfFile:sourceCleanInstallToken
                                encoding:NSUTF8StringEncoding
                                   error:&tokenError];
            cleanInstallToken = [rawToken
                stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            NSCharacterSet *invalidTokenCharacters = [[NSCharacterSet
                characterSetWithCharactersInString:@"0123456789."]
                invertedSet];
            if (!S_ISREG(cleanInstallTokenStatus.st_mode) ||
                cleanInstallTokenStatus.st_size <= 0 ||
                cleanInstallTokenStatus.st_size > 128 || tokenError != nil ||
                cleanInstallToken.length == 0 ||
                cleanInstallToken.length > 127 ||
                [cleanInstallToken
                    rangeOfCharacterFromSet:invalidTokenCharacters].location !=
                    NSNotFound) {
                return fail(@"clean-install token is invalid", nil);
            }
        } else if (errno != ENOENT) {
            return fail(@"clean-install token status failed", nil);
        }
        struct stat injectionHelperStatus;
        if (lstat([sourceElleKitCompatLoader fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceExecWorker fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceSBInjectGeneralHook fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceSBInjectLaunchdHook fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceSBInjectLsdRegistrationHook fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceSBInjectJitterd fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceSBInjectPackageValidator fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceSBInjectJitterdPlist fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            validated_bundle_entries(sourceSBInjectBundle, false) == nil ||
            validated_bundle_entries(sourceSBInjectPreferencesBundle,
                                     false) == nil) {
            return fail(@"SBInject execution payload is incomplete", nil);
        }
        struct stat repositoryKeyStatus;
        if (lstat([sourceElleKitKey fileSystemRepresentation],
                  &repositoryKeyStatus) != 0 ||
            !S_ISREG(repositoryKeyStatus.st_mode) ||
            lstat([sourceBigBossKey fileSystemRepresentation],
                  &repositoryKeyStatus) != 0 ||
            !S_ISREG(repositoryKeyStatus.st_mode)) {
            return fail(@"repository keyring payload is missing", nil);
        }

        NSString *manifestHash = boot_manifest_hash();
        if (manifestHash.length == 0) {
            return fail(@"boot-manifest-hash unavailable", nil);
        }
        log_message("bootManifestHash=%s", [manifestHash UTF8String]);
        NSString *activePreboot =
            [@"/private/preboot" stringByAppendingPathComponent:manifestHash];
        if (![[NSFileManager defaultManager] fileExistsAtPath:activePreboot
                                                 isDirectory:&isDirectory] ||
            !isDirectory) {
            NSError *listing_error = nil;
            NSArray<NSString *> *entries = [[NSFileManager defaultManager]
                contentsOfDirectoryAtPath:@"/private/preboot"
                                     error:&listing_error];
            log_message("prebootListingCount=%lu error=%s",
                        (unsigned long)entries.count,
                        listing_error != nil
                            ? [[listing_error description] UTF8String]
                            : "none");
            for (NSString *entry in entries) {
                log_message("prebootEntry=%s", [entry UTF8String]);
                if ([entry caseInsensitiveCompare:manifestHash] ==
                    NSOrderedSame) {
                    activePreboot = [@"/private/preboot"
                        stringByAppendingPathComponent:entry];
                    isDirectory = NO;
                    if ([[NSFileManager defaultManager]
                            fileExistsAtPath:activePreboot
                                 isDirectory:&isDirectory] &&
                        isDirectory) {
                        log_message("activePrebootCaseFoldMatch=%s",
                                    [activePreboot UTF8String]);
                        break;
                    }
                }
            }
        }
        if (![[NSFileManager defaultManager] fileExistsAtPath:activePreboot
                                                 isDirectory:&isDirectory] ||
            !isDirectory) {
            return fail(@"active preboot directory unavailable", nil);
        }

        if (cleanInstallToken != nil && repairMode) {
            NSString *installedManifestPath = [destinationProcursus
                stringByAppendingPathComponent:
                    @".codex-cryptex-bootstrap.plist"];
            NSDictionary *installedManifest = [NSDictionary
                dictionaryWithContentsOfFile:installedManifestPath];
            if ([installedManifest[@"CleanInstallToken"]
                    isEqual:cleanInstallToken]) {
                log_message("cleanInstallAlreadyApplied=true token=%s",
                            [cleanInstallToken UTF8String]);
            } else {
                NSString *uninstallError = nil;
                if (!uninstall_managed_jailbreak_root(activePreboot,
                                                       &uninstallError)) {
                    return fail(uninstallError, nil);
                }
                destinationProcursus = nil;
                repairMode = NO;
                log_message("cleanInstallReset=true token=%s",
                            [cleanInstallToken UTF8String]);
            }
        }

        NSString *randomizedRoot =
            repairMode ? [destinationProcursus stringByDeletingLastPathComponent]
                       : nil;
        NSError *copy_error = nil;
        if (!repairMode) {
            for (NSUInteger attempt = 0; attempt < 128; ++attempt) {
                NSString *name = [NSString
                    stringWithFormat:@"dopamine-%06x",
                                     arc4random_uniform(0x1000000)];
                NSString *candidate =
                    [activePreboot stringByAppendingPathComponent:name];
                if ([[NSFileManager defaultManager]
                        createDirectoryAtPath:candidate
                  withIntermediateDirectories:NO
                                   attributes:@{
                                       NSFilePosixPermissions : @0755,
                                       NSFileOwnerAccountID : @0,
                                       NSFileGroupOwnerAccountID : @0,
                                   }
                                        error:nil]) {
                    randomizedRoot = candidate;
                    break;
                }
            }
            if (randomizedRoot == nil) {
                return fail(@"could not allocate a fresh preboot root", nil);
            }

            destinationProcursus =
                [randomizedRoot stringByAppendingPathComponent:@"procursus"];
            if (![[NSFileManager defaultManager]
                    copyItemAtPath:sourceProcursus
                           toPath:destinationProcursus
                            error:&copy_error]) {
                return fail(
                    [NSString stringWithFormat:@"bootstrap copy failed: %@",
                                               copy_error],
                    randomizedRoot);
            }
            NSString *cachedSileo =
                [destinationProcursus stringByAppendingPathComponent:
                                          @".codex-cache/sileo.deb"];
            if (![[NSFileManager defaultManager]
                    createDirectoryAtPath:
                        [cachedSileo stringByDeletingLastPathComponent]
              withIntermediateDirectories:YES
                               attributes:@{
                                   NSFilePosixPermissions : @0700,
                                   NSFileOwnerAccountID : @0,
                                   NSFileGroupOwnerAccountID : @0,
                               }
                                    error:&copy_error] ||
                ![[NSFileManager defaultManager] copyItemAtPath:sourceSileo
                                                         toPath:cachedSileo
                                                          error:&copy_error]) {
                return fail(
                    [NSString stringWithFormat:@"Sileo staging failed: %@",
                                               copy_error],
                    randomizedRoot);
            }

            NSString *rollbackManifest = [destinationProcursus
                stringByAppendingPathComponent:
                    @".codex-cryptex-bootstrap.plist"];
            NSMutableDictionary *manifest = [@{
                @"Installer" : kInstallerIdentifier,
                @"JailbreakRoot" : destinationProcursus,
                @"RandomizedRoot" : randomizedRoot,
                @"VarJbCreated" : @YES,
                @"CryptexMountRoot" : mountRoot,
                @"Source" : @"opa334/Dopamine 3.x",
            } mutableCopy];
            if (cleanInstallToken != nil) {
                manifest[@"CleanInstallToken"] = cleanInstallToken;
            }
            if (![manifest writeToFile:rollbackManifest atomically:YES]) {
                return fail(@"could not write rollback manifest",
                            randomizedRoot);
            }

            if (symlink([destinationProcursus fileSystemRepresentation],
                        kVarJb) != 0) {
                return fail(
                    [NSString stringWithFormat:@"/var/jb symlink failed: %s",
                                               strerror(errno)],
                    randomizedRoot);
            }
            log_message("varJbCreated=true target=%s",
                        [destinationProcursus UTF8String]);
        } else {
            log_message("managedVarJbReused=true target=%s",
                        [destinationProcursus UTF8String]);
        }

        NSString *rootlessLaunchctl = @"/var/jb/usr/bin/launchctl";
        NSString *rootlessLaunchctlBackup = nil;
        BOOL launchctlMatches =
            files_are_equal(sourceTrustedLaunchctl, rootlessLaunchctl);
        log_message("rootlessLaunchctlMatches=%s",
                    launchctlMatches ? "true" : "false");
        if (!launchctlMatches) {
            NSString *cacheDirectory = [destinationProcursus
                stringByAppendingPathComponent:@".codex-cache"];
            NSError *cacheError = nil;
            if (![[NSFileManager defaultManager]
                    createDirectoryAtPath:cacheDirectory
              withIntermediateDirectories:YES
                               attributes:@{
                                   NSFilePosixPermissions : @0700,
                                   NSFileOwnerAccountID : @0,
                                   NSFileGroupOwnerAccountID : @0,
                               }
                                    error:&cacheError]) {
                return fail(
                    [NSString stringWithFormat:
                                  @"launchctl backup directory failed: %@",
                                  cacheError],
                    nil);
            }
            rootlessLaunchctlBackup = [cacheDirectory
                stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"launchctl-backup-%@",
                                               [[NSUUID UUID] UUIDString]]];
            NSString *replacementError = nil;
            if (!replace_file_with_backup(sourceTrustedLaunchctl,
                                          rootlessLaunchctl,
                                          rootlessLaunchctlBackup,
                                          &replacementError)) {
                return fail(replacementError, nil);
            }
        }
        if (!files_are_equal(sourceTrustedLaunchctl, rootlessLaunchctl)) {
            return fail(@"rootless launchctl refresh did not match the "
                         "Cryptex trust-cache input",
                        nil);
        }
        log_message("rootlessLaunchctlTrusted=true backup=%s",
                    rootlessLaunchctlBackup != nil
                        ? [rootlessLaunchctlBackup UTF8String]
                        : "not-needed");

        [[NSFileManager defaultManager]
            removeItemAtPath:@"/private/var/tmp/codex-stage-ssh" error:nil];

        NSString *rootlessUiopen = @"/var/jb/usr/bin/uiopen";
        NSString *rootlessUiopenBackup = nil;
        BOOL uiopenMatches = files_are_equal(sourceTrustedUiopen, rootlessUiopen);
        log_message("rootlessUiopenMatches=%s",
                    uiopenMatches ? "true" : "false");
        if (!uiopenMatches) {
            NSString *cacheDirectory = [destinationProcursus
                stringByAppendingPathComponent:@".codex-cache"];
            NSError *cacheError = nil;
            if (![[NSFileManager defaultManager]
                    createDirectoryAtPath:cacheDirectory
              withIntermediateDirectories:YES
                               attributes:@{
                                   NSFilePosixPermissions : @0700,
                                   NSFileOwnerAccountID : @0,
                                   NSFileGroupOwnerAccountID : @0,
                               }
                                    error:&cacheError]) {
                return fail(
                    [NSString stringWithFormat:
                                  @"uiopen backup directory failed: %@",
                                  cacheError],
                    nil);
            }
            rootlessUiopenBackup = [cacheDirectory
                stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"uiopen-backup-%@",
                                               [[NSUUID UUID] UUIDString]]];
            NSString *replacementError = nil;
            if (!replace_file_with_backup(sourceTrustedUiopen, rootlessUiopen,
                                          rootlessUiopenBackup,
                                          &replacementError)) {
                return fail(replacementError, nil);
            }
        }
        if (!files_are_equal(sourceTrustedUiopen, rootlessUiopen)) {
            return fail(@"rootless uiopen refresh did not match the Cryptex "
                         "trust-cache input",
                        nil);
        }
        log_message("rootlessUiopenTrusted=true backup=%s",
                    rootlessUiopenBackup != nil
                        ? [rootlessUiopenBackup UTF8String]
                        : "not-needed");

        NSString *rootlessUicacheBackup = nil;
        BOOL uicacheMatches =
            files_are_equal(sourceTrustedUicache, kRootlessUicache);
        log_message("rootlessUicacheMatches=%s",
                    uicacheMatches ? "true" : "false");
        if (!uicacheMatches) {
            NSString *cacheDirectory = [destinationProcursus
                stringByAppendingPathComponent:@".codex-cache"];
            NSError *cacheError = nil;
            if (![[NSFileManager defaultManager]
                    createDirectoryAtPath:cacheDirectory
              withIntermediateDirectories:YES
                               attributes:@{
                                   NSFilePosixPermissions : @0700,
                                   NSFileOwnerAccountID : @0,
                                   NSFileGroupOwnerAccountID : @0,
                               }
                                    error:&cacheError]) {
                return fail(
                    [NSString stringWithFormat:
                                  @"uicache backup directory failed: %@",
                                  cacheError], nil);
            }
            rootlessUicacheBackup = [cacheDirectory
                stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"uicache-backup-%@",
                                               [[NSUUID UUID] UUIDString]]];
            NSString *replacementError = nil;
            if (!replace_file_with_backup(sourceTrustedUicache,
                                          kRootlessUicache,
                                          rootlessUicacheBackup,
                                          &replacementError)) {
                return fail(replacementError, nil);
            }
        }
        if (!files_are_equal(sourceTrustedUicache, kRootlessUicache)) {
            return fail(@"rootless uicache refresh did not match the Cryptex "
                         "trust-cache input", nil);
        }
        log_message("rootlessUicacheTrusted=true backup=%s",
                    rootlessUicacheBackup != nil
                        ? [rootlessUicacheBackup UTF8String]
                        : "not-needed");

        setenv("PATH",
               "/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:"
               "/usr/bin:/bin:/usr/sbin:/sbin",
               1);
        setenv("HOME", "/var/root", 1);
        setenv("SHELL", "/var/jb/bin/sh", 1);
        setenv("NO_PASSWORD_PROMPT", "1", 1);

        NSString *dopamineMarkerError = nil;
        if (!ensure_root_owned_empty_file("/var/jb/.installed_dopamine", 0644,
                                          &dopamineMarkerError)) {
            return fail(dopamineMarkerError, nil);
        }
        log_message("dopamineMarkerReady=true path=/var/jb/.installed_dopamine");

        bool systemSileoBundleUpdated = false;
        NSString *systemSileoBundleError = nil;
        if (!install_sileo_system_bundle_copy(
                sourceTrustedSileo, &systemSileoBundleUpdated,
                &systemSileoBundleError)) {
            return fail(systemSileoBundleError, nil);
        }
        if (repairMode &&
            access([kSBInjectAmfidCrashMarker fileSystemRepresentation],
                   F_OK) == 0) {
            int resetStatus = unlink(
                [kSBInjectAmfidCrashMarker fileSystemRepresentation]);
            log_message("sbinjectAmfidRepairReset=%s error=%d",
                        resetStatus == 0 ? "success" : "failed",
                        resetStatus == 0 ? 0 : errno);
        }

        // The Cryptex launch daemon runs again after every reboot.  When its
        // immutable payload is already installed byte-for-byte, bring up the
        // local control plane immediately instead of reinstalling packages or
        // waiting on repository networking.  The root broker then re-injects
        // launchd and replaces the already-started stock SpringBoard; Settings
        // is armed before its first user launch.
        if (repairMode) {
            NSString *installedManifestPath = [destinationProcursus
                stringByAppendingPathComponent:
                    @".codex-cryptex-bootstrap.plist"];
            NSDictionary *installedManifest = [NSDictionary
                dictionaryWithContentsOfFile:installedManifestPath];
            NSString *fastRegisteredPath = kSystemSileoBundlePath;
            NSString *fastDataContainer = kSystemSileoDataRoot;
            NSString *fastRegistrationError = nil;
            bool fastSystemMode =
                [installedManifest[@"SileoInstallMode"]
                    isEqual:@"cryptex-system-app"];
            bool fastRegistrationArtifactsExact =
                files_are_equal(sourceElleKitCompatLoader,
                                kElleKitInjectorExecutable) &&
                files_are_equal(sourceSBInjectLsdRegistrationHook,
                                kSBInjectLsdRegistrationHook);
            bool fastSystemRegistered = false;
            if (fastSystemMode && fastRegistrationArtifactsExact) {
                fastSystemRegistered = register_sileo_system_application(
                    fastRegisteredPath, &fastRegistrationError);
            } else {
                fastRegistrationError = fastSystemMode
                    ? @"installed lsd registration artifacts are stale"
                    : @"migration from provisioned Sileo requires full repair";
            }
            NSArray<NSDictionary *> *fastPairs = @[
                @{@"source" : executable,
                  @"installed" : kRootBrokerExecutable},
                @{@"source" : sourceElleKitCompatLoader,
                  @"installed" : kElleKitInjectorExecutable},
                @{@"source" : sourceExecWorker,
                  @"installed" : kExecWorkerExecutable},
                @{@"source" : [sourceProcursus
                                     stringByAppendingPathComponent:
                                         @"usr/bin/ssh"],
                  @"installed" : @"/var/jb/usr/bin/ssh"},
                @{@"source" : [sourceProcursus
                                     stringByAppendingPathComponent:
                                         @"usr/bin/ssh-keygen"],
                  @"installed" : kOpenSSHKeygen},
                @{@"source" : [sourceProcursus
                                     stringByAppendingPathComponent:
                                         @"usr/libexec/sftp-server"],
                  @"installed" : @"/var/jb/usr/libexec/sftp-server"},
                @{@"source" : [sourceProcursus
                                     stringByAppendingPathComponent:
                                         @"usr/libexec/sshd-keygen-wrapper"],
                  @"installed" : kOpenSSHKeygenWrapper},
                @{@"source" : [sourceProcursus
                                     stringByAppendingPathComponent:
                                         @"usr/sbin/sshd"],
                  @"installed" : kOpenSSHExecutable},
                @{@"source" : sourceOpenSSHConfig,
                  @"installed" : kOpenSSHConfig},
                @{@"source" : [sourceProcursus
                                     stringByAppendingPathComponent:
                                         @"Library/LaunchDaemons/"
                                          "com.openssh.sshd.plist"],
                  @"installed" : kOpenSSHPlist},
                @{@"source" : sourceSBInjectGeneralHook,
                  @"installed" : kSBInjectGeneralHook},
                @{@"source" : sourceSBInjectAmfidHook,
                  @"installed" : kSBInjectAmfidHook},
                @{@"source" : sourceSBInjectAmfidCandidate,
                  @"installed" : kAmfidCandidateExecutable},
                @{@"source" : sourceSBInjectPreferencesBridge,
                  @"installed" : kSBInjectPreferencesBridge},
                @{@"source" : sourceSBInjectLaunchdHook,
                  @"installed" : kSBInjectLaunchdHook},
                @{@"source" : sourceSBInjectLsdRegistrationHook,
                  @"installed" : kSBInjectLsdRegistrationHook},
                @{@"source" : sourceSBInjectJitterd,
                  @"installed" : kSBInjectJitterdExecutable},
                @{@"source" : sourceSBInjectJitterdPlist,
                  @"installed" : kSBInjectJitterdPlist},
                @{@"source" : sourceSBInjectPackageValidator,
                  @"installed" : kSBInjectPackageValidatorExecutable},
                @{@"source" : [sourceSBInjectBundle
                                     stringByAppendingPathComponent:
                                         @"notSpringBoard"],
                  @"installed" : kSpringBoardCandidateExecutable},
                @{@"source" : [sourceSBInjectBundle
                                     stringByAppendingPathComponent:@"g"],
                  @"installed" : kSBInjectBundleHook},
                @{@"source" : [sourceSBInjectPreferencesBundle
                                     stringByAppendingPathComponent:
                                         @"notPreferences"],
                  @"installed" : kPreferencesCandidateExecutable},
                @{@"source" : [sourceSBInjectPreferencesBundle
                                     stringByAppendingPathComponent:@"g"],
                  @"installed" : kSBInjectPreferencesBundleHook},
            ];
            bool fastPayloadExact =
                [installedManifest[@"Installer"] isEqual:kInstallerIdentifier] &&
                [installedManifest[@"JailbreakRoot"]
                    isEqual:destinationProcursus] &&
                fastSystemMode &&
                fastSystemRegistered &&
                is_sileo_system_bundle_path(fastRegisteredPath) &&
                dpkg_package_version_is_installed(@"ellekit", @"1.2") &&
                dpkg_package_version_is_installed(@"preferenceloader",
                                                  @"2.3.3") &&
                dpkg_package_version_is_installed(@"org.coolstar.sileo",
                                                  kSileoPackageVersion) &&
                dpkg_package_version_is_installed(@"openssh-client",
                                                  @"9.7p1-1") &&
                dpkg_package_version_is_installed(@"openssh-server",
                                                  @"9.7p1-1") &&
                dpkg_package_version_is_installed(@"openssh-sftp-server",
                                                  @"9.7p1-1");
            for (NSDictionary *pair in fastPairs) {
                fastPayloadExact &= files_are_equal(pair[@"source"],
                                                     pair[@"installed"]);
            }
            if ([[NSFileManager defaultManager]
                    fileExistsAtPath:sourceHostSSHAuthorizedKeys]) {
                fastPayloadExact &= files_are_equal(
                    sourceHostSSHAuthorizedKeys,
                    @"/var/jb/var/root/.ssh/authorized_keys");
            }
            NSArray<NSString *> *fastSileoExecutables = @[
                @"Sileo", @"giveMeRoot", @"F/libiosexec.1.dylib",
                @"F/liblzma.5.dylib", @"F/libcodex-sileo-broker.dylib",
                @"F/libzstd.1.dylib",
                @"F/libzstd.real.dylib",
            ];
            for (NSString *relativePath in fastSileoExecutables) {
                NSString *sourcePath = [sourceTrustedSileo
                    stringByAppendingPathComponent:relativePath];
                fastPayloadExact &= files_are_equal(
                    sourcePath, [fastRegisteredPath
                                    stringByAppendingPathComponent:relativePath]);
            }
            NSArray<NSString *> *fastElleKitExecutables = @[
                @"usr/lib/ellekit/MobileSafety.dylib",
                @"usr/lib/ellekit/libinjector.dylib",
                @"usr/lib/ellekit/pspawn.dylib",
                @"usr/lib/libellekit.dylib",
                @"usr/libexec/ellekit/loader",
            ];
            for (NSString *relativePath in fastElleKitExecutables) {
                fastPayloadExact &= files_are_equal(
                    [sourceTrustedElleKitRoot
                        stringByAppendingPathComponent:relativePath],
                    [@"/var/jb" stringByAppendingPathComponent:relativePath]);
            }
            log_message("fastBootPayloadExact=%s registeredPath=%s "
                        "dataContainer=%s systemSileoUpdated=%s "
                        "networkRequired=false",
                        fastPayloadExact ? "true" : "false",
                        fastRegisteredPath != nil
                            ? [fastRegisteredPath UTF8String] : "none",
                        fastDataContainer != nil
                            ? [fastDataContainer UTF8String] : "none",
                        systemSileoBundleUpdated ? "true" : "false");
            if (!fastSystemRegistered) {
                log_message("fastBootSystemSileoRegistration=false error=%s",
                            fastRegistrationError != nil
                                ? [[fastRegistrationError description] UTF8String]
                                : "unknown");
            }
            if (fastPayloadExact) {
                NSString *fastError = nil;
                NSString *fastTokenPath = nil;
                NSString *fastBrokerPath = nil;
                int fastBroker = -1;
                bool fastJitterd = install_sbinject_jitterd_job(
                    sourceSBInjectJitterd, sourceSBInjectJitterdPlist,
                    false, &fastError);
                bool fastRootBroker = fastJitterd &&
                    install_sileo_root_broker_job(
                        executable, fastRegisteredPath,
                        destinationProcursus, &fastError);
                bool fastOpenSSH = fastRootBroker &&
                    install_openssh_job(&fastError);
                log_message("fastBootControlPlane jitterd=%s rootBroker=%s "
                            "openSSH=%s error=%s",
                            fastJitterd ? "true" : "false",
                            fastRootBroker ? "true" : "false",
                            fastOpenSSH ? "true" : "false",
                            fastError != nil
                                ? [[fastError description] UTF8String] : "none");
                if (fastOpenSSH) {
                    fastError = nil;
                    bool fastExtensions =
                        write_sileo_sandbox_extensions(
                            fastDataContainer, destinationProcursus,
                            &fastTokenPath, &fastError);
                    if (fastExtensions) {
                        fastBroker = create_sileo_broker_socket(
                            fastDataContainer, &fastBrokerPath, &fastError);
                    }
                    if (fastBroker < 0) {
                        log_message("fastBootSileoData=false error=%s",
                                    fastError != nil
                                        ? [[fastError description] UTF8String]
                                        : "unknown");
                        return fail(@"system Sileo file broker failed",
                                    nil);
                    }
                    log_message("fastBootSileoDataReady token=%s socket=%s",
                                fastTokenPath != nil
                                    ? [fastTokenPath UTF8String] : "none",
                                fastBrokerPath != nil
                                    ? [fastBrokerPath UTF8String] : "none");
                    dispatch_queue_t fastRootBrokerQueue =
                        dispatch_queue_create(
                            "com.openai.codex.dopamine.fast-root-broker",
                            DISPATCH_QUEUE_SERIAL);
                    dispatch_async(fastRootBrokerQueue, ^{
                        @autoreleasepool {
                            serve_sileo_broker(fastBroker, fastRegisteredPath,
                                               destinationProcursus);
                        }
                    });
                    NSString *done = [NSString stringWithFormat:
                        @"result=success\nmode=fast-boot\nuid=%u\n"
                         "jailbreakRoot=%@\nsileo=%@\nlaunchServicesPath=%@\n",
                        geteuid(), destinationProcursus,
                        [fastRegisteredPath
                            stringByAppendingPathComponent:@"Sileo"],
                        fastRegisteredPath];
                    (void)write_marker(kDonePath, done);
                    log_message("result=success mode=fast-boot "
                                "networkRequired=false sileo=%s",
                                [fastRegisteredPath UTF8String]);
                    serve_sileo_file_broker(
                        fastRegisteredPath, destinationProcursus,
                        fastDataContainer);
                    __builtin_unreachable();
                }
                log_message("fastBootFallback=registration-repair error=%s",
                            fastError != nil
                                ? [[fastError description] UTF8String]
                                : "unknown");
            }
        }

        if (!repairMode) {
            char *prep_arguments[] = {
                "/var/jb/bin/sh", "/var/jb/prep_bootstrap.sh", NULL};
            int prep_status = run_and_wait(prep_arguments[0], prep_arguments);
            log_message("prepBootstrapExit=%d", prep_status);
            if (prep_status != 0) {
                return fail([NSString stringWithFormat:
                                          @"prep_bootstrap.sh exited %d",
                                          prep_status],
                            nil);
            }

            char *dpkg_arguments[] = {"/var/jb/usr/bin/dpkg", "-i",
                                      "/var/jb/.codex-cache/sileo.deb", NULL};
            int dpkg_status = run_and_wait(dpkg_arguments[0], dpkg_arguments);
            log_message("sileoDpkgExit=%d", dpkg_status);
            if (dpkg_status != 0) {
                return fail(
                    [NSString stringWithFormat:@"Sileo dpkg exited %d",
                                               dpkg_status],
                    nil);
            }
        }

        // ElleKit is the sole package payload admitted by the fixed Cryptex
        // trust cache.  Installing this repacked, pinned copy before the
        // broker starts removes the first-tweak chicken-and-egg problem:
        // SpringBoard can enter through SBInject with ElleKit already present,
        // while every third-party tweak dylib remains on the JIT/dyld lane.
        char *elleKitDpkgArguments[] = {
            "/var/jb/usr/bin/dpkg", "-i",
            (char *)[sourceElleKit fileSystemRepresentation], NULL};
        int elleKitDpkgStatus = run_and_wait_bounded(
            elleKitDpkgArguments[0], elleKitDpkgArguments, 90000);
        log_message("elleKitFixedDpkgExit=%d package=ellekit version=1.2",
                    elleKitDpkgStatus);
        if (elleKitDpkgStatus != 0) {
            return fail(
                [NSString stringWithFormat:
                              @"fixed ElleKit install exited %d",
                              elleKitDpkgStatus],
                nil);
        }
        NSArray<NSDictionary *> *trustedElleKitFiles = @[
            @{@"path" : @"usr/lib/ellekit/MobileSafety.dylib",
              @"mode" : @0644},
            @{@"path" : @"usr/lib/ellekit/libinjector.dylib",
              @"mode" : @0644},
            @{@"path" : @"usr/lib/ellekit/pspawn.dylib",
              @"mode" : @0644},
            @{@"path" : @"usr/lib/libellekit.dylib", @"mode" : @0644},
            @{@"path" : @"usr/libexec/ellekit/loader", @"mode" : @0755},
        ];
        for (NSDictionary *entry in trustedElleKitFiles) {
            NSString *relativePath = entry[@"path"];
            NSString *sourcePath =
                [sourceTrustedElleKitRoot
                    stringByAppendingPathComponent:relativePath];
            NSString *installedPath =
                [@"/var/jb" stringByAppendingPathComponent:relativePath];
            mode_t expectedMode =
                (mode_t)[entry[@"mode"] unsignedShortValue];
            if (!files_are_equal(sourcePath, installedPath) ||
                !sbinject_managed_file(installedPath, expectedMode)) {
                return fail(
                    [NSString stringWithFormat:
                                  @"fixed ElleKit payload mismatch: %@",
                                  relativePath],
                    nil);
            }
        }
        log_message("elleKitFixedTrustReady=true package=ellekit "
                    "version=1.2 files=%lu dynamicTrustCache=false",
                    (unsigned long)trustedElleKitFiles.count);

        // Install pinned rootless PreferenceLoader/libprefs before launching
        // the resigned Preferences candidate. The fixed Cryptex bridge adapts
        // these registrations to iOS 27's SettingsSidebarListState model.
        char *preferenceLoaderDpkgArguments[] = {
            "/var/jb/usr/bin/dpkg", "--force-downgrade", "-i",
            (char *)[sourcePreferenceLoader fileSystemRepresentation], NULL};
        int preferenceLoaderDpkgStatus = run_and_wait_bounded(
            preferenceLoaderDpkgArguments[0], preferenceLoaderDpkgArguments,
            90000);
        log_message("preferenceLoaderFixedDpkgExit=%d "
                    "package=preferenceloader version=2.3.3",
                    preferenceLoaderDpkgStatus);
        if (preferenceLoaderDpkgStatus != 0) {
            return fail(
                [NSString stringWithFormat:
                              @"fixed PreferenceLoader install exited %d",
                              preferenceLoaderDpkgStatus],
                nil);
        }
        // Re-running the explicit Cryptex repair is the recovery boundary for
        // Settings. The launchd hook may have disabled only the Preferences
        // redirect after a prior rapid-launch window; once the pinned
        // PreferenceLoader package has verified again, discard that stale
        // marker and let this run re-arm the resigned candidate. A genuine
        // crash loop can still recreate the marker during the current boot.
        bool preferencesCrashMarkerPresent =
            access([kSBInjectPreferencesCrashMarker fileSystemRepresentation],
                   F_OK) == 0;
        if (preferencesCrashMarkerPresent &&
            unlink([kSBInjectPreferencesCrashMarker
                       fileSystemRepresentation]) != 0) {
            return fail(@"could not reset the Settings crash-loop marker",
                        nil);
        }
        log_message("sbinjectPreferencesRepairReset=%s",
                    preferencesCrashMarkerPresent ? "true" : "not-needed");

        char *openSSHDpkgArguments[] = {
            "/var/jb/usr/bin/dpkg", "-i",
            (char *)[sourceOpenSSHClient fileSystemRepresentation],
            (char *)[sourceOpenSSHSFTPServer fileSystemRepresentation],
            (char *)[sourceOpenSSHServer fileSystemRepresentation], NULL};
        int openSSHDpkgStatus = run_and_wait_bounded(
            openSSHDpkgArguments[0], openSSHDpkgArguments, 120000);
        log_message("openSSHFixedDpkgExit=%d version=9.7p1-1",
                    openSSHDpkgStatus);
        if (openSSHDpkgStatus != 0 ||
            !dpkg_package_version_is_installed(@"openssh-client",
                                               @"9.7p1-1") ||
            !dpkg_package_version_is_installed(@"openssh-server",
                                               @"9.7p1-1") ||
            !dpkg_package_version_is_installed(@"openssh-sftp-server",
                                               @"9.7p1-1")) {
            return fail(
                [NSString stringWithFormat:@"fixed OpenSSH install exited %d",
                                           openSSHDpkgStatus],
                nil);
        }
        bool openSSHConfigUpdated = false;
        NSString *openSSHConfigError = nil;
        if (!install_managed_apt_file(
                sourceOpenSSHConfig, @"/var/jb/etc/ssh", @"sshd_config",
                256 * 1024, 0644, "openSSHConfig", &openSSHConfigUpdated,
                &openSSHConfigError)) {
            return fail(openSSHConfigError, nil);
        }
        NSDictionary<NSString *, NSString *> *trustedOpenSSHFiles = @{
            @"usr/bin/ssh" : @"/var/jb/usr/bin/ssh",
            @"usr/bin/ssh-keygen" : kOpenSSHKeygen,
            @"usr/libexec/sftp-server" : @"/var/jb/usr/libexec/sftp-server",
            @"usr/libexec/sshd-keygen-wrapper" : kOpenSSHKeygenWrapper,
            @"usr/sbin/sshd" : kOpenSSHExecutable,
            @"etc/ssh/sshd_config" : kOpenSSHConfig,
            @"Library/LaunchDaemons/com.openssh.sshd.plist" : kOpenSSHPlist,
        };
        for (NSString *relativePath in trustedOpenSSHFiles) {
            NSString *sourcePath =
                [sourceProcursus stringByAppendingPathComponent:relativePath];
            if (!files_are_equal(sourcePath,
                                 trustedOpenSSHFiles[relativePath])) {
                return fail(
                    [NSString stringWithFormat:
                                  @"fixed OpenSSH payload mismatch: %@",
                                  relativePath],
                    nil);
            }
        }
        log_message("openSSHFixedTrustReady=true version=9.7p1-1 files=%lu",
                    (unsigned long)trustedOpenSSHFiles.count);

        bool hostSSHAuthorizedKeysUpdated = false;
        NSString *hostSSHAuthorizedKeysError = nil;
        bool hostSSHAuthorizedKeyAvailable =
            [[NSFileManager defaultManager]
                fileExistsAtPath:sourceHostSSHAuthorizedKeys];
        if (hostSSHAuthorizedKeyAvailable &&
            !install_managed_apt_file(
                sourceHostSSHAuthorizedKeys, @"/var/jb/var/root/.ssh",
                @"authorized_keys", 64 * 1024, 0600,
                "openSSHHostAuthorizedKeys", &hostSSHAuthorizedKeysUpdated,
                &hostSSHAuthorizedKeysError)) {
            return fail(hostSSHAuthorizedKeysError, nil);
        }
        log_message("openSSHHostAccess=%s updated=%s path=%s",
                    hostSSHAuthorizedKeyAvailable ? "enabled" : "disabled",
                    hostSSHAuthorizedKeysUpdated ? "true" : "false",
                    hostSSHAuthorizedKeyAvailable
                        ? "/var/jb/var/root/.ssh/authorized_keys"
                        : "none");

        bool elleKitKeyUpdated = false;
        bool bigBossKeyUpdated = false;
        bool aptListNormalizerUpdated = false;
        bool repositoryCompatibilityUpdated = false;
        bool sbinjectAptConfigUpdated = false;
        bool preferenceLoaderPinUpdated = false;
        bool sileoPinUpdated = false;
        NSString *repositoryMetadataError = nil;
        if (!install_managed_apt_file(
                sourceElleKitKey, @"/var/jb/etc/apt/trusted.gpg.d",
                @"dopamine-ellekit.gpg", 64 * 1024, 0644,
                "repositoryKeyring",
                &elleKitKeyUpdated, &repositoryMetadataError) ||
            !install_managed_apt_file(
                sourceBigBossKey, @"/var/jb/etc/apt/trusted.gpg.d",
                @"dopamine-bigboss.gpg", 64 * 1024, 0644,
                "repositoryKeyring",
                &bigBossKeyUpdated, &repositoryMetadataError) ||
            !install_managed_apt_file(
                sourceAptListNormalizer, @"/var/jb/usr/libexec",
                @"codex-normalize-apt-lists", 64 * 1024, 0644,
                "aptListNormalizer", &aptListNormalizerUpdated,
                &repositoryMetadataError) ||
            !install_managed_apt_file(
                sourceRepositoryCompatibility,
                @"/var/jb/etc/apt/apt.conf.d",
                @"99dopamine-repository-compat", 64 * 1024, 0644,
                "repositoryCompatibility", &repositoryCompatibilityUpdated,
                &repositoryMetadataError) ||
            !install_managed_apt_file(
                sourceSBInjectAptConfig,
                @"/var/jb/etc/apt/apt.conf.d",
                @"98sbinject-packages", 64 * 1024, 0644,
                "sbinjectAptHook", &sbinjectAptConfigUpdated,
                &repositoryMetadataError) ||
            !install_managed_apt_file(
                sourcePreferenceLoaderPin,
                @"/var/jb/etc/apt/preferences.d",
                @"99codex-preferenceloader", 64 * 1024, 0644,
                "preferenceLoaderPin", &preferenceLoaderPinUpdated,
                &repositoryMetadataError) ||
            !install_managed_apt_file(
                sourceSileoPin, @"/var/jb/etc/apt/preferences.d",
                @"99codex-system-sileo", 64 * 1024, 0644,
                "sileoPin", &sileoPinUpdated,
                &repositoryMetadataError)) {
            return fail(repositoryMetadataError, nil);
        }

        bool defaultSourcesUpdated = false;
        NSString *defaultSourcesError = nil;
        if (!install_dopamine_default_sources(sourceDefaultSources,
                                              &defaultSourcesUpdated,
                                              &defaultSourcesError)) {
            return fail(defaultSourcesError, nil);
        }

        bool sbinjectGeneralHookUpdated = false;
        bool sbinjectAmfidHookUpdated = false;
        bool sbinjectAmfidCandidateUpdated = false;
        bool sbinjectPreferencesBridgeUpdated = false;
        bool sbinjectLaunchdHookUpdated = false;
        bool sbinjectLsdRegistrationHookUpdated = false;
        bool sbinjectJitterdUpdated = false;
        bool sbinjectJitterdPlistUpdated = false;
        bool sbinjectPackageValidatorUpdated = false;
        NSString *sbinjectPayloadError = nil;
        if (!install_managed_apt_file(
                sourceElleKitCompatLoader, @"/var/jb/usr/libexec",
                @"codex-ellekit-loader", 16 * 1024 * 1024, 0755,
                "elleKitInjector", NULL,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceExecWorker, @"/var/jb/usr/libexec",
                @"codex-exec-worker", 16 * 1024 * 1024, 0755,
                "runtimeExecWorker", NULL,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectGeneralHook, @"/var/jb/usr/lib/sbinject",
                @"generalhook.dylib", 16 * 1024 * 1024, 0755,
                "sbinjectGeneralHook", &sbinjectGeneralHookUpdated,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectAmfidHook, @"/var/jb/usr/libexec/sbinject",
                @"a", 4 * 1024 * 1024, 0755,
                "sbinjectAmfidHook", &sbinjectAmfidHookUpdated,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectAmfidCandidate,
                @"/var/jb/usr/libexec/sbinject", @"notamfid",
                32 * 1024 * 1024, 0755, "sbinjectAmfidCandidate",
                &sbinjectAmfidCandidateUpdated, &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectPreferencesBridge,
                @"/var/jb/usr/lib/sbinject",
                @"preferences-bridge.dylib", 4 * 1024 * 1024, 0755,
                "sbinjectPreferencesBridge",
                &sbinjectPreferencesBridgeUpdated,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectLaunchdHook, @"/var/jb/usr/lib/sbinject",
                @"launchdhook-v12.dylib", 16 * 1024 * 1024, 0755,
                "sbinjectLaunchdHook", &sbinjectLaunchdHookUpdated,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectLsdRegistrationHook,
                @"/var/jb/usr/lib/sbinject",
                @"lsd-registration-hook.dylib", 4 * 1024 * 1024, 0755,
                "sbinjectLsdRegistrationHook",
                &sbinjectLsdRegistrationHookUpdated,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectJitterd, @"/var/jb/usr/libexec",
                @"sbinject-jitterd", 16 * 1024 * 1024, 0755,
                "sbinjectJitterd", &sbinjectJitterdUpdated,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectJitterdPlist,
                @"/var/jb/Library/LaunchDaemons",
                @"com.openai.codex.sbinject.jitterd.plist", 64 * 1024,
                0644, "sbinjectJitterdPlist",
                &sbinjectJitterdPlistUpdated,
                &sbinjectPayloadError) ||
            !install_managed_apt_file(
                sourceSBInjectPackageValidator, @"/var/jb/usr/libexec",
                @"sbinject-package-validator", 1024 * 1024, 0755,
                "sbinjectPackageValidator",
                &sbinjectPackageValidatorUpdated,
                &sbinjectPayloadError)) {
            return fail(sbinjectPayloadError, nil);
        }
        bool sbinjectBundleUpdated = false;
        NSString *sbinjectBundleBackup = nil;
        NSString *sbinjectBundleError = nil;
        if (!install_sbinject_springboard_bundle(
                sourceSBInjectBundle, &sbinjectBundleUpdated,
                &sbinjectBundleBackup, &sbinjectBundleError)) {
            return fail(sbinjectBundleError, nil);
        }
        bool sbinjectPreferencesBundleUpdated = false;
        NSString *sbinjectPreferencesBundleBackup = nil;
        NSString *sbinjectPreferencesBundleError = nil;
        if (!install_sbinject_preferences_bundle(
                sourceSBInjectPreferencesBundle,
                &sbinjectPreferencesBundleUpdated,
                &sbinjectPreferencesBundleBackup,
                &sbinjectPreferencesBundleError)) {
            return fail(sbinjectPreferencesBundleError, nil);
        }
        bool sbinjectPayloadUpdated =
            sbinjectGeneralHookUpdated ||
            sbinjectAmfidHookUpdated || sbinjectAmfidCandidateUpdated ||
            sbinjectPreferencesBridgeUpdated ||
            sbinjectLaunchdHookUpdated ||
            sbinjectLsdRegistrationHookUpdated ||
            sbinjectJitterdUpdated || sbinjectJitterdPlistUpdated ||
            sbinjectPackageValidatorUpdated || sbinjectBundleUpdated ||
            sbinjectPreferencesBundleUpdated;
        bool sbinjectPreferencesRestartRequired =
            preferenceLoaderDpkgStatus == 0 || sbinjectGeneralHookUpdated ||
            sbinjectPreferencesBridgeUpdated ||
            sbinjectPreferencesBundleUpdated;
        if (sbinjectPayloadUpdated) {
            (void)unlink([kSBInjectEnableMarker fileSystemRepresentation]);
            (void)unlink(
                [kSBInjectPreferencesEnableMarker fileSystemRepresentation]);
            (void)unlink([kSBInjectRespringMarker fileSystemRepresentation]);
            (void)unlink([kSBInjectCrashMarker fileSystemRepresentation]);
            (void)unlink(
                [kSBInjectPreferencesCrashMarker fileSystemRepresentation]);
            (void)unlink(
                [kSBInjectAmfidEnableMarker fileSystemRepresentation]);
            (void)unlink(
                [kSBInjectAmfidCrashMarker fileSystemRepresentation]);
            (void)unlink(
                [kSBInjectAmfidReadyMarker fileSystemRepresentation]);
            if (sbinjectLaunchdHookUpdated) {
                NSString *upgradeMarkerError = nil;
                if (!ensure_root_owned_empty_file(
                        [kSBInjectLaunchdUpgradeMarker
                            fileSystemRepresentation],
                        0644, &upgradeMarkerError)) {
                    return fail(upgradeMarkerError, nil);
                }
                (void)unlink(
                    [kSBInjectLaunchdReadyMarker fileSystemRepresentation]);
            }
        }
        // Each hook generation has a unique image path and can rebind launchd
        // slots owned by the preceding generation. Clear readiness only when
        // the generation changed so prepare_sbinject_redirect hot-chains the
        // new image without requiring a reboot.
        log_message("sbinjectPayload updated=%s bundleUpdated=%s "
                    "preferencesBundleUpdated=%s amfidHookUpdated=%s "
                    "amfidCandidateUpdated=%s launchdHookUpdated=%s "
                    "launchdReadyCurrent=%s candidate=%s "
                    "preferencesCandidate=%s dynamicTrustCache=false",
                    sbinjectPayloadUpdated ? "true" : "false",
                    sbinjectBundleUpdated ? "true" : "false",
                    sbinjectPreferencesBundleUpdated ? "true" : "false",
                    sbinjectAmfidHookUpdated ? "true" : "false",
                    sbinjectAmfidCandidateUpdated ? "true" : "false",
                    sbinjectLaunchdHookUpdated ? "true" : "false",
                    sbinject_boot_fresh_marker(kSBInjectLaunchdReadyMarker)
                        ? "true"
                        : "false",
                    [kSpringBoardCandidateExecutable UTF8String],
                    [kPreferencesCandidateExecutable UTF8String]);
        unsetenv("DYLD_INSERT_LIBRARIES");
        log_message("sbinjectExecutionEnvironment=ready mode=jit-rw-to-rx "
                    "interposer=false dynamicTrustCache=false");

        NSString *kernelPackageError = nil;
        if (!repair_unsupported_kernel_packages(NULL, &kernelPackageError)) {
            return fail(kernelPackageError, nil);
        }

        // Repair runs must refresh dpkg's metadata-only maintainer-script copy
        // after the SBInject package policy and broker are refreshed. The
        // immutable application itself remains in the Cryptex.
        if (repairMode) {
            char *sileoRepairArguments[] = {
                "/var/jb/usr/bin/dpkg", "-i",
                (char *)[sourceSileo fileSystemRepresentation], NULL};
            int sileoRepairStatus = run_and_wait_bounded(
                sileoRepairArguments[0], sileoRepairArguments, 90000);
            log_message("sileoRepairDpkgExit=%d", sileoRepairStatus);
            if (sileoRepairStatus != 0) {
                NSString *repairTrustedMain =
                    [sourceTrustedSileo
                        stringByAppendingPathComponent:@"Sileo"];
                NSString *repairTrustedHelper =
                    [sourceTrustedSileo
                        stringByAppendingPathComponent:@"giveMeRoot"];
                BOOL repairPayloadInstalled =
                    is_sileo_system_bundle_path(sourceTrustedSileo) &&
                    immutable_payload_file(repairTrustedMain, 0755) &&
                    immutable_payload_file(repairTrustedHelper, 0755) &&
                    dpkg_package_version_is_installed(@"org.coolstar.sileo",
                                                      kSileoPackageVersion);
                if (!repairPayloadInstalled) {
                    return fail(
                        [NSString stringWithFormat:
                                      @"Sileo repair install exited %d",
                                      sileoRepairStatus],
                        nil);
                }
                log_message(
                    "sileoRepairDpkgAdvisory=true status=%d "
                    "payloadInstalled=true cause=unrelated-trigger",
                    sileoRepairStatus);
            }
        }

        // Finish pending shell maintainer scripts after the SBInject APT hook
        // is installed. Package Mach-Os stay outside the fixed Cryptex set;
        // SpringBoard dylibs execute only in the jitterd-enabled replacement.
        char *dpkgConfigureArguments[] = {
            "/var/jb/usr/bin/dpkg", "--configure", "-a", NULL};
        int dpkgConfigureStatus =
            repairMode
                ? run_and_wait_bounded(dpkgConfigureArguments[0],
                                       dpkgConfigureArguments, 90000)
                : run_and_wait(dpkgConfigureArguments[0],
                               dpkgConfigureArguments);
        log_message("dpkgConfigurePendingExit=%d", dpkgConfigureStatus);
        if (dpkgConfigureStatus != 0 && !repairMode) {
            return fail(
                [NSString stringWithFormat:
                              @"pending package configuration exited %d",
                              dpkgConfigureStatus],
                nil);
        }
        if (dpkgConfigureStatus != 0) {
            log_message("dpkgConfigurePendingAdvisory=true "
                        "mode=registration-repair status=%d",
                        dpkgConfigureStatus);
        }

        bool repositoryMetadataChanged =
            elleKitKeyUpdated || bigBossKeyUpdated ||
            aptListNormalizerUpdated || repositoryCompatibilityUpdated ||
            sbinjectAptConfigUpdated || preferenceLoaderPinUpdated ||
            sileoPinUpdated || defaultSourcesUpdated;
        // A populated Packages file does not prove that APT retained the
        // authenticated Release/InRelease state.  Sileo otherwise reports an
        // opaque exit 100 before the SBInject validator can run.  Refresh the
        // complete signed source set on every bootstrap/repair; an offline
        // repair may retain an already populated cache, but a fresh bootstrap
        // may not proceed with an unauthenticated or empty index.
        char *apt_update_arguments[] = {
            "/var/jb/usr/bin/apt-get", "update", "-o",
            "Dpkg::Use-Pty=0", NULL};
        log_message("aptUpdateScope=all reason=%s",
                    repositoryMetadataChanged
                        ? "repository-metadata-changed"
                        : "sileo-authentication-preflight");
        int apt_update_status =
            repairMode
                ? run_and_wait_bounded(apt_update_arguments[0],
                                       apt_update_arguments, 60000)
                : run_and_wait(apt_update_arguments[0],
                               apt_update_arguments);
        log_message("aptUpdateExit=%d", apt_update_status);
        bool packageListsPopulated = apt_package_lists_are_populated();
        if (!packageListsPopulated ||
            (!repairMode && apt_update_status != 0)) {
            return fail(
                [NSString stringWithFormat:@"APT index refresh exited %d",
                                           apt_update_status],
                nil);
        }
        if (apt_update_status != 0) {
            log_message("aptUpdateAdvisory=true mode=registration-repair "
                        "lists=populated status=%d",
                        apt_update_status);
        }

        char *apt_check_arguments[] = {
            "/var/jb/usr/bin/apt-get", "check", "-o", "Dpkg::Use-Pty=0",
            NULL};
        int apt_check_status =
            repairMode
                ? run_and_wait_bounded(apt_check_arguments[0],
                                       apt_check_arguments, 60000)
                : run_and_wait(apt_check_arguments[0], apt_check_arguments);
        log_message("aptDependencyCheckExit=%d", apt_check_status);
        if (apt_check_status != 0 && !repairMode) {
            return fail(
                [NSString stringWithFormat:
                              @"APT dependency check exited %d",
                              apt_check_status],
                nil);
        }
        if (apt_check_status != 0) {
            log_message("aptDependencyCheckAdvisory=true "
                        "mode=registration-repair status=%d",
                        apt_check_status);
        }

        NSString *trustedMain =
            [sourceTrustedSileo stringByAppendingPathComponent:@"Sileo"];
        NSString *trustedHelper =
            [sourceTrustedSileo stringByAppendingPathComponent:@"giveMeRoot"];
        if (access([trustedMain fileSystemRepresentation], X_OK) != 0 ||
            access([trustedHelper fileSystemRepresentation], X_OK) != 0) {
            return fail(@"Cryptex Sileo executables are unavailable", nil);
        }
        NSString *systemRegistrationError = nil;
        if (!register_sileo_system_application(
                kSystemSileoBundlePath, &systemRegistrationError)) {
            return fail(systemRegistrationError, nil);
        }
        NSString *registeredPath = registered_application_path(
            @"org.coolstar.SileoStore");
        log_message("launchServicesPath=%s",
                    registeredPath != nil ? [registeredPath UTF8String]
                                          : "none");
        if (!is_sileo_system_bundle_path(registeredPath) ||
            !executable_paths_match(kSystemSileoBundlePath, registeredPath) ||
            !bundle_trees_are_equal(sourceTrustedSileo, registeredPath)) {
            return fail(@"LaunchServices did not retain the managed fixed-trust "
                         "Sileo system path", nil);
        }

        NSArray<NSString *> *trustedSileoExecutables = @[
            @"Sileo",
            @"giveMeRoot",
            @"F/libiosexec.1.dylib",
            @"F/liblzma.5.dylib",
            @"F/libcodex-sileo-broker.dylib",
            @"F/libzstd.1.dylib",
            @"F/libzstd.real.dylib",
        ];
        for (NSString *relativePath in trustedSileoExecutables) {
            NSString *trustedPath =
                [sourceTrustedSileo stringByAppendingPathComponent:relativePath];
            NSString *registeredExecutable =
                [registeredPath stringByAppendingPathComponent:relativePath];
            if (!files_are_equal(trustedPath, registeredExecutable)) {
                return fail(
                    [NSString stringWithFormat:
                                  @"registered Sileo fixed-trust mismatch: %@",
                                  relativePath],
                    nil);
            }
        }
        log_message("sileoFixedTrustExecutableSetReady=true files=%lu",
                    (unsigned long)trustedSileoExecutables.count);

        NSString *registeredHelper =
            [registeredPath stringByAppendingPathComponent:@"giveMeRoot"];
        if (!files_are_equal(trustedHelper, registeredHelper)) {
            return fail(@"registered giveMeRoot does not exactly match the "
                         "Cryptex trust-cache input",
                        nil);
        }
        int registeredHelperFile =
            open([registeredHelper fileSystemRepresentation],
                 O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat registeredHelperBefore;
        if (registeredHelperFile < 0 ||
            fstat(registeredHelperFile, &registeredHelperBefore) != 0 ||
            !S_ISREG(registeredHelperBefore.st_mode)) {
            int savedError = errno;
            if (registeredHelperFile >= 0) {
                close(registeredHelperFile);
            }
            return fail(
                [NSString stringWithFormat:
                              @"registered giveMeRoot is unavailable: %s",
                              strerror(savedError)],
                nil);
        }
        struct stat registeredHelperAfter;
        bool registeredHelperReady =
            fstat(registeredHelperFile, &registeredHelperAfter) == 0 &&
            S_ISREG(registeredHelperAfter.st_mode) &&
            registeredHelperAfter.st_nlink == 1 &&
            registeredHelperBefore.st_dev == registeredHelperAfter.st_dev &&
            registeredHelperBefore.st_ino == registeredHelperAfter.st_ino &&
            registeredHelperBefore.st_size == registeredHelperAfter.st_size;
        close(registeredHelperFile);
        if (!registeredHelperReady ||
            (registeredHelperAfter.st_mode & 07777) != 0755) {
            return fail(@"registered giveMeRoot identity or mode did not verify",
                        nil);
        }
        log_message("registeredGiveMeRootReady=true path=%s "
                    "beforeUid=%u beforeGid=%u beforeMode=%04o "
                    "afterUid=%u afterGid=%u afterMode=%04o",
                    [registeredHelper UTF8String], registeredHelperBefore.st_uid,
                    registeredHelperBefore.st_gid,
                    registeredHelperBefore.st_mode & 07777,
                    registeredHelperAfter.st_uid, registeredHelperAfter.st_gid,
                    registeredHelperAfter.st_mode & 07777);

        NSString *dataContainer = kSystemSileoDataRoot;
        log_message("launchServicesDataContainer=%s",
                    dataContainer != nil ? [dataContainer UTF8String]
                                         : "none");
        if (!is_sileo_data_container_path(dataContainer)) {
            return fail(@"Sileo data container is unavailable or invalid",
                        nil);
        }
        NSString *tokenPath = nil;
        NSString *tokenError = nil;
        if (!write_sileo_sandbox_extensions(dataContainer,
                                            destinationProcursus,
                                            &tokenPath, &tokenError)) {
            return fail(tokenError, nil);
        }
        log_message("sileoSandboxExtensionsReady=true path=%s",
                    [tokenPath UTF8String]);
        NSString *brokerPath = nil;
        NSString *brokerError = nil;
        int broker = create_sileo_broker_socket(dataContainer, &brokerPath,
                                                &brokerError);
        if (broker < 0) {
            return fail(brokerError, nil);
        }
        log_message("sileoSandboxBrokerReady=true path=%s",
                    [brokerPath UTF8String]);

        NSString *rollbackManifest = [destinationProcursus
            stringByAppendingPathComponent:@".codex-cryptex-bootstrap.plist"];
        NSMutableDictionary *manifest = [NSMutableDictionary
            dictionaryWithContentsOfFile:rollbackManifest];
        if (manifest == nil) {
            manifest = [NSMutableDictionary dictionary];
        }
        manifest[@"Installer"] = kInstallerIdentifier;
        manifest[@"JailbreakRoot"] = destinationProcursus;
        manifest[@"RandomizedRoot"] = randomizedRoot;
        manifest[@"VarJbCreated"] = @YES;
        manifest[@"CryptexMountRoot"] = mountRoot;
        manifest[@"SileoBundlePath"] = registeredPath;
        manifest[@"SileoBundleIdentifier"] = @"org.coolstar.SileoStore";
        manifest[@"SileoInstallMode"] = @"cryptex-system-app";
        manifest[@"SileoProvisioningProfile"] = @NO;
        manifest[@"SileoDataContainer"] = dataContainer;
        manifest[@"SileoSandboxExtensions"] = tokenPath;
        manifest[@"SileoSandboxBroker"] = brokerPath;
        manifest[@"SileoRootBroker"] = @CODEX_ROOT_BROKER_MACH_SERVICE;
        manifest[@"SileoRootBrokerExecutable"] = kRootBrokerExecutable;
        manifest[@"SBInjectPackageValidatorExecutable"] =
            kSBInjectPackageValidatorExecutable;
        manifest[@"SBInjectJitterdExecutable"] = kSBInjectJitterdExecutable;
        manifest[@"SBInjectJitterdLaunchDaemon"] = kSBInjectJitterdPlist;
        manifest[@"SBInjectSpringBoardBundle"] = kSBInjectBundle;
        manifest[@"SBInjectSpringBoardExecutable"] =
            kSpringBoardCandidateExecutable;
        manifest[@"SBInjectPreferencesBundle"] = kSBInjectPreferencesBundle;
        manifest[@"SBInjectPreferencesExecutable"] =
            kPreferencesCandidateExecutable;
        manifest[@"SBInjectGeneralHook"] = kSBInjectGeneralHook;
        manifest[@"SBInjectAmfidHook"] = kSBInjectAmfidHook;
        manifest[@"SBInjectAmfidExecutable"] = kAmfidCandidateExecutable;
        manifest[@"SBInjectPreferencesBridge"] = kSBInjectPreferencesBridge;
        manifest[@"SBInjectLaunchdHook"] = kSBInjectLaunchdHook;
        manifest[@"SpringBoardTweakAdmission"] =
            @"sbinject-jit-pre-main-no-dynamic-trust-cache";
        manifest[@"RuntimeExecWorkerExecutable"] = kExecWorkerExecutable;
        manifest[@"OpenSSHVersion"] = @"9.7p1-1";
        manifest[@"OpenSSHExecutable"] = kOpenSSHExecutable;
        manifest[@"OpenSSHLaunchDaemon"] = kOpenSSHPlist;
        manifest[@"OpenSSHHostKeyAccess"] =
            @(hostSSHAuthorizedKeyAvailable);
        manifest[@"SileoRootBrokerPlist"] = kRootBrokerPlist;
        manifest[@"SileoExecutableMode"] =
            @"fixed-trust-adhoc-system-app-with-constructor-broker";
        if (rootlessLaunchctlBackup != nil) {
            manifest[@"RootlessLaunchctlBackup"] = rootlessLaunchctlBackup;
        }
        if (rootlessUiopenBackup != nil) {
            manifest[@"RootlessUiopenBackup"] = rootlessUiopenBackup;
        }
        if (rootlessUicacheBackup != nil) {
            manifest[@"RootlessUicacheBackup"] = rootlessUicacheBackup;
        }
        if (sbinjectBundleBackup != nil) {
            manifest[@"SBInjectSpringBoardBundleBackup"] =
                sbinjectBundleBackup;
        }
        if (sbinjectPreferencesBundleBackup != nil) {
            manifest[@"SBInjectPreferencesBundleBackup"] =
                sbinjectPreferencesBundleBackup;
        }
        manifest[@"Source"] = @"opa334/Dopamine 3.x";
        if (![manifest writeToFile:rollbackManifest atomically:YES]) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(@"could not update rollback manifest", nil);
        }

        NSString *sbinjectJitterdError = nil;
        bool sbinjectJitterdRestartRequired =
            sbinjectJitterdUpdated || sbinjectJitterdPlistUpdated;
        if (!install_sbinject_jitterd_job(
                sourceSBInjectJitterd, sourceSBInjectJitterdPlist,
                sbinjectJitterdRestartRequired, &sbinjectJitterdError)) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(sbinjectJitterdError, nil);
        }

        if (sbinjectPreferencesRestartRequired) {
            NSString *restartMarkerError = nil;
            if (!ensure_root_owned_empty_file(
                    [kSBInjectPreferencesRestartMarker
                        fileSystemRepresentation],
                    0644, &restartMarkerError)) {
                close(broker);
                (void)unlink([brokerPath fileSystemRepresentation]);
                return fail(
                    [NSString stringWithFormat:
                                  @"Preferences restart handoff failed: %@",
                                  restartMarkerError],
                    nil);
            }
            log_message("sbinjectPreferencesRestartRequired=true "
                        "preferenceLoaderInstalled=true generalHookUpdated=%s "
                        "bridgeUpdated=%s bundleUpdated=%s",
                        sbinjectGeneralHookUpdated ? "true" : "false",
                        sbinjectPreferencesBridgeUpdated ? "true" : "false",
                        sbinjectPreferencesBundleUpdated ? "true" : "false");
        }

        NSString *rootBrokerJobError = nil;
        if (!install_sileo_root_broker_job(executable, registeredPath,
                                           destinationProcursus,
                                           &rootBrokerJobError)) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(rootBrokerJobError, nil);
        }

        NSString *openSSHJobError = nil;
        if (!install_openssh_job(&openSSHJobError)) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(openSSHJobError, nil);
        }

        dispatch_queue_t rootBrokerQueue = dispatch_queue_create(
            "com.openai.codex.dopamine.sileo-root-broker",
            DISPATCH_QUEUE_SERIAL);
        dispatch_async(rootBrokerQueue, ^{
            @autoreleasepool {
                serve_sileo_broker(broker, registeredPath,
                                   destinationProcursus);
            }
        });
        log_message("sileoRootBrokerReady=true path=%s",
                    [brokerPath UTF8String]);

        char *uiopen_arguments[] = {
            "/var/jb/usr/bin/uiopen", "--bundleid",
            (char *)[kSileoIdentifier UTF8String], NULL};
        int uiopen_status =
            run_and_wait(uiopen_arguments[0], uiopen_arguments);
        log_message("uiopenExit=%d", uiopen_status);

        NSString *done = [NSString
            stringWithFormat:
                @"result=success\nuid=%u\njailbreakRoot=%@\n"
                 "sileo=%@\nlaunchServicesPath=%@\nuiopenExit=%d\n",
                geteuid(), destinationProcursus, trustedMain,
                registeredPath, uiopen_status];
        if (!write_marker(kDonePath, done)) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(@"could not write completion marker", nil);
        }
        log_message("result=success jailbreakRoot=%s sileo=%s uiopenExit=%d",
                    [destinationProcursus UTF8String],
                    [trustedMain UTF8String], uiopen_status);
        serve_sileo_file_broker(registeredPath, destinationProcursus,
                                dataContainer);
        __builtin_unreachable();
    }
}
