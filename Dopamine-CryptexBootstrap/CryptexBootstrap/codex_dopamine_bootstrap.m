#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
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
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
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
extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
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
#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_PLATFORM_BINARY 0x04000000U

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
static NSString *const kBundleContainerRoot =
    @"/var/containers/Bundle/Application";
static NSString *const kRootBrokerLabel =
    @"com.openai.codex.dopamine.sileo-root-broker";
static NSString *const kRootBrokerExecutable =
    @"/var/jb/usr/libexec/codex-sileo-root-broker";
static NSString *const kRootBrokerPlist =
    @"/var/jb/Library/LaunchDaemons/com.openai.codex.dopamine."
     "sileo-root-broker.plist";
static NSString *const kExecWorkerExecutable =
    @"/var/jb/usr/libexec/codex-exec-worker";
static NSString *const kExecInterposerLibrary =
    @"/var/jb/usr/lib/codex-exec-interposer.dylib";
static NSString *const kRuntimeTrustClientExecutable =
    @"/var/jb/usr/libexec/codex-runtime-trust-client";
static NSString *const kElleKitInjectorExecutable =
    @"/var/jb/usr/libexec/codex-ellekit-loader";
static NSString *const kElleKitInjectorDylib =
    @"/var/jb/usr/lib/ellekit/libinjector.dylib";

@interface NSObject (CodexLaunchServices)
+ (id)applicationProxyForIdentifier:(NSString *)identifier;
- (NSURL *)bundleURL;
- (NSURL *)dataContainerURL;
@end

static int gLog = STDERR_FILENO;
static os_log_t gUnifiedLog;

static int run_and_wait(const char *executable, char *const arguments[]);
static int run_and_wait_bounded(const char *executable,
                                char *const arguments[],
                                unsigned int timeoutMilliseconds);

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

static NSString *registered_application_data_path(NSString *identifier) {
    id proxy = registered_application_proxy(identifier);
    if (proxy == nil ||
        ![proxy respondsToSelector:@selector(dataContainerURL)]) {
        return nil;
    }
    return [[proxy dataContainerURL] path];
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

static bool is_sileo_data_container_path(NSString *path) {
    if (path.length == 0) {
        return false;
    }
    NSString *standardized = [path stringByStandardizingPath];
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

static bool path_contains_macho(NSString *path) {
    struct stat status;
    const char *fileSystemPath = [path fileSystemRepresentation];
    if (stat(fileSystemPath, &status) != 0) {
        return false;
    }
    if (S_ISREG(status.st_mode)) {
        return broker_command_is_macho(fileSystemPath);
    }
    if (!S_ISDIR(status.st_mode)) {
        return false;
    }
    NSDirectoryEnumerator<NSString *> *enumerator =
        [[NSFileManager defaultManager] enumeratorAtPath:path];
    for (NSString *relativePath in enumerator) {
        NSString *candidate = [path stringByAppendingPathComponent:relativePath];
        if (lstat([candidate fileSystemRepresentation], &status) == 0 &&
            S_ISREG(status.st_mode) &&
            broker_command_is_macho([candidate fileSystemRepresentation])) {
            return true;
        }
    }
    return false;
}

static bool runtime_admission_infrastructure_ready(const char *reason) {
    bool worker =
        access([kExecWorkerExecutable fileSystemRepresentation], X_OK) == 0;
    bool interposer =
        access([kExecInterposerLibrary fileSystemRepresentation], R_OK) == 0;
    bool injector =
        access([kElleKitInjectorExecutable fileSystemRepresentation], X_OK) == 0;
    log_message("runtimeAdmissionInfrastructure reason=%s worker=%s "
                "interposer=%s injector=%s backend=debugged-worker",
                reason, worker ? "ready" : "missing",
                interposer ? "ready" : "missing",
                injector ? "ready" : "missing");
    return worker && interposer && injector;
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

static bool runtime_trust_deb_paths(NSArray<NSString *> *paths,
                                    const char *reason) {
    if (paths.count == 0) {
        return true;
    }
    char stagingTemplate[] = "/var/tmp/codex-runtime-trust.XXXXXX";
    char *stagingPath = mkdtemp(stagingTemplate);
    if (stagingPath == NULL) {
        log_message("runtimeTrustDebStageFailed reason=%s error=%s", reason,
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
            log_message("runtimeAdmissionDebRejected reason=%s path=%s",
                        reason, [path UTF8String]);
            success = false;
            break;
        }
        char *arguments[] = {
            "/var/jb/usr/bin/dpkg-deb", "-x",
            (char *)[path fileSystemRepresentation], stagingPath, NULL};
        int extractStatus =
            run_and_wait_bounded(arguments[0], arguments, 30000);
        log_message("runtimeTrustDebExtract path=%s status=%d",
                    [path UTF8String], extractStatus);
        if (extractStatus != 0) {
            success = false;
            break;
        }
        ++extracted;
    }
    bool containsMachO = success && extracted != 0 &&
                         path_contains_macho(staging);
    /*
     * iOS 27 can reject post-boot trust-cache loads after successful Generic
     * Cryptex personalization.  Package payloads therefore stay out of the
     * immutable trust cache: fixed Procursus parents carry the interposer and
     * route non-baseline executables into the fixed debugger-softened worker.
     * Keep extracting here so malformed archives are rejected before dpkg,
     * but do not make package installation depend on a per-payload cdhash.
     */
    int admissionStatus = success && extracted != 0 ? 0 : 1;
    if (success && extracted != 0) {
        NSString *recordDirectory =
            @"/var/jb/var/lib/codex-runtime-admission";
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
            @"Backend" : @"debugged-worker-v1",
            @"AdmissionMode" : @"fixed-loader-no-payload-trust-cache",
            @"Reason" : [NSString stringWithUTF8String:reason],
            @"Archives" : paths,
            @"ArchiveCount" : @(extracted),
            @"ContainsMachO" : @(containsMachO),
            @"AdmissionStatus" : @(admissionStatus),
            @"RecordedAt" : [NSDate date],
        };
        NSString *recordPath = [recordDirectory
            stringByAppendingPathComponent:@"last-transaction.plist"];
        BOOL recorded = directoryReady &&
                        [record writeToFile:recordPath atomically:YES];
        log_message("runtimeAdmissionDebRecord path=%s recorded=%s error=%s",
                    [recordPath UTF8String], recorded ? "true" : "false",
                    recordError != nil
                        ? [[recordError description] UTF8String]
                        : "none");
    }
    NSError *cleanupError = nil;
    if (![[NSFileManager defaultManager] removeItemAtPath:staging
                                                    error:&cleanupError]) {
        log_message("runtimeTrustDebCleanup path=%s error=%s",
                    [staging UTF8String],
                    [[cleanupError description] UTF8String]);
    }
    log_message("runtimeAdmissionDebResult reason=%s archives=%lu macho=%s "
                "admissionStatus=%d backend=debugged-worker-v1 "
                "payloadTrustCache=false status=%s",
                reason, (unsigned long)extracted,
                containsMachO ? "true" : "false", admissionStatus,
                success ? "success" : "failed");
    return success;
}

static bool runtime_trust_deb_arguments(char *const arguments[],
                                        const char *reason) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for (NSUInteger index = 1;
         index <= CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
         arguments[index] != NULL;
         ++index) {
        NSString *path = [NSString stringWithUTF8String:arguments[index]];
        if ([path hasSuffix:@".deb"]) {
            [paths addObject:path];
        }
    }
    return runtime_trust_deb_paths(paths, reason);
}

static bool runtime_trust_debs_from_standard_input(void) {
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
    return runtime_trust_deb_paths(paths, "apt-pre-install");
}

static bool broker_spawn_error_is_admission_failure(int error) {
    if (error == EACCES || error == EPERM || error == ENOEXEC) {
        return true;
    }
#ifdef EBADARCH
    if (error == EBADARCH) {
        return true;
    }
#endif
    return false;
}

static int32_t run_root_broker_command(
    int server, int client, char *const arguments[], int descriptors[],
    const int descriptorNumbers[], uint32_t descriptorCount,
    char *const controlEnvironment[], uint32_t controlEnvironmentCount,
    NSString *jailbreakRoot, const char *resolvedCommand) {
    if (broker_command_is_named(resolvedCommand, "dpkg") &&
        !runtime_trust_deb_arguments(arguments, "dpkg-pre-install")) {
        log_message("sileoRootBrokerPreAdmission=false command=%s "
                    "backend=debugged-worker-v1",
                    resolvedCommand);
        return 72 << 8;
    }
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
    environment[environmentCount++] =
        "CODEX_RUNTIME_ADMISSION=debugged-worker-v1";
    environment[environmentCount++] = "HOME=/var/root";
    environment[environmentCount++] = "TMPDIR=/var/tmp";
    environment[environmentCount] = NULL;

    pid_t child = 0;
    bool runtimeFallback = false;
    int spawnResult = posix_spawn(&child, resolvedCommand, &actions, NULL,
                                  arguments, environment);
    if (spawnResult != 0 &&
        broker_spawn_error_is_admission_failure(spawnResult) &&
        strcmp(resolvedCommand,
               [kExecWorkerExecutable fileSystemRepresentation]) != 0 &&
        broker_command_is_macho(resolvedCommand)) {
        char *runtimeArguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 3U] = {0};
        runtimeArguments[0] =
            (char *)[kExecWorkerExecutable fileSystemRepresentation];
        runtimeArguments[1] = "--macho";
        uint32_t index = 0;
        while (index < CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
               arguments[index] != NULL) {
            runtimeArguments[index + 2U] = arguments[index];
            ++index;
        }
        runtimeArguments[index + 2U] = NULL;
        int directError = spawnResult;
        spawnResult = posix_spawn(
            &child, [kExecWorkerExecutable fileSystemRepresentation],
            &actions, NULL, runtimeArguments, environment);
        runtimeFallback = spawnResult == 0;
        log_message("sileoRootBrokerRuntimeFallback command=%s "
                    "directError=%s workerError=%s selected=%s",
                    resolvedCommand, strerror(directError),
                    spawnResult == 0 ? "none" : strerror(spawnResult),
                    runtimeFallback ? "true" : "false");
    }
    posix_spawn_file_actions_destroy(&actions);
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        close(temporary[index]);
    }
    if (spawnResult != 0) {
        log_message("sileoRootBrokerSpawnError command=%s error=%s",
                    resolvedCommand, strerror(spawnResult));
        return 127 << 8;
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return 125 << 8;
        }
    }
    if (runtimeFallback) {
        log_message("sileoRootBrokerRuntimeResult command=%s status=%d",
                    resolvedCommand, status);
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

static bool is_ellekit_target_process(pid_t pid, const char *path) {
    static const char *const jailbreakApplications =
        "/var/jb/Applications/";
    static const char *const privateApplicationContainers =
        "/private/var/containers/Bundle/Application/";
    static const char *const applicationContainers =
        "/var/containers/Bundle/Application/";
    static const char *const sileoExecutableSuffix = "/Sileo.app/Sileo";
    static const char *const uiTestRunnerPathComponent = "-Runner.app/";
    size_t pathLength = strlen(path);
    size_t sileoSuffixLength = strlen(sileoExecutableSuffix);
    bool sileoProcess =
        pathLength >= sileoSuffixLength &&
        strcmp(path + pathLength - sileoSuffixLength,
               sileoExecutableSuffix) == 0;
    if (sileoProcess || strstr(path, uiTestRunnerPathComponent) != NULL) {
        // Sileo has its own launch-time constructor and broker bridge. Loading
        // ElleKit's generic injector afterward is redundant and destabilizes
        // the app once its package-manager worker threads are running. XCTest
        // runner hosts likewise manage their own injected test bundle and can
        // crash if a second late loader mutates the process.
        return false;
    }
    if (strcmp(path,
               "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ==
        0) {
        return true;
    }
    if (strncmp(path, jailbreakApplications,
                strlen(jailbreakApplications)) == 0) {
        return true;
    }
    bool applicationContainer =
        strncmp(path, privateApplicationContainers,
                strlen(privateApplicationContainers)) == 0 ||
        strncmp(path, applicationContainers,
                strlen(applicationContainers)) == 0;
    uint32_t flags = 0;
    return applicationContainer &&
           csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
           (flags & CODEX_CS_PLATFORM_BINARY) == 0;
}

static void serve_ellekit_per_process_injector(bool springBoardOnly) {
    NSMutableDictionary<NSNumber *, NSDictionary *> *states =
        [NSMutableDictionary dictionary];
    const char *lane = springBoardOnly ? "springboard" : "applications";
    unsigned long long scan = 0;
    log_message("elleKitPerProcessInjectorServing=true lane=%s "
                "pid1Guard=true", lane);
    for (;;) {
        @autoreleasepool {
            if (access([kElleKitInjectorExecutable fileSystemRepresentation],
                       X_OK) != 0 ||
                access([kElleKitInjectorDylib fileSystemRepresentation],
                       R_OK) != 0 ||
                access([kExecInterposerLibrary fileSystemRepresentation],
                       R_OK) != 0) {
                usleep(1000 * 1000);
                continue;
            }
            int capacity = proc_listallpids(NULL, 0);
            if (capacity <= 0 || capacity > 1024 * 1024) {
                usleep(500 * 1000);
                continue;
            }
            capacity += 32;
            pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
            if (pids == NULL) {
                usleep(500 * 1000);
                continue;
            }
            int count = proc_listallpids(pids,
                                         capacity * (int)sizeof(*pids));
            if (count < 0) {
                free(pids);
                usleep(500 * 1000);
                continue;
            }
            if (count > capacity) {
                count = capacity;
            }
            NSMutableSet<NSNumber *> *live = [NSMutableSet set];
            NSUInteger targetCount = 0;
            NSUInteger pendingCount = 0;
            for (int index = 0; index < count; ++index) {
                pid_t pid = pids[index];
                if (pid <= 1 || pid == getpid()) {
                    continue;
                }
                char path[CODEX_PROC_PIDPATH_MAX] = {0};
                if (proc_pidpath(pid, path, sizeof(path)) <= 0 ||
                    strcmp(path, "/sbin/launchd") == 0 ||
                    !is_ellekit_target_process(pid, path)) {
                    continue;
                }
                bool springBoardProcess =
                    strcmp(path,
                           "/System/Library/CoreServices/"
                           "SpringBoard.app/SpringBoard") == 0;
                if (springBoardProcess != springBoardOnly) {
                    continue;
                }
                ++targetCount;
                NSNumber *key = @(pid);
                [live addObject:key];
                NSDictionary *state = states[key];
                NSString *pathValue = [NSString stringWithUTF8String:path];
                NSUInteger attempts =
                    [state[@"path"] isEqual:pathValue]
                        ? [state[@"attempts"] unsignedIntegerValue]
                        : 0;
                bool complete = [state[@"complete"] boolValue];
                if (complete || attempts >= 3) {
                    continue;
                }
                ++pendingCount;
                char pidText[32];
                snprintf(pidText, sizeof(pidText), "%d", pid);
                char *elleKitArguments[] = {
                    (char *)[kElleKitInjectorExecutable
                        fileSystemRepresentation],
                    "--inject-pid", pidText,
                    (char *)[kElleKitInjectorDylib fileSystemRepresentation],
                    NULL};
                int elleKitStatus = run_and_wait_bounded(
                    elleKitArguments[0], elleKitArguments, 30000);
                int status = elleKitStatus == 0 ? 0 : 1;
                ++attempts;
                states[key] = @{
                    @"path" : pathValue,
                    @"attempts" : @(attempts),
                    @"complete" : @(status == 0),
                };
                log_message("elleKitPerProcessInjection lane=%s pid=%d "
                            "path=%s attempt=%lu elleKitStatus=%d status=%d",
                            lane, pid, path, (unsigned long)attempts,
                            elleKitStatus, status);
            }
            free(pids);
            for (NSNumber *key in [states.allKeys copy]) {
                if (![live containsObject:key]) {
                    [states removeObjectForKey:key];
                }
            }
            ++scan;
            if (scan == 1 || scan % 80 == 0) {
                log_message("elleKitPerProcessInjectorHeartbeat lane=%s "
                            "scan=%llu targets=%lu pending=%lu states=%lu "
                            "safeMode=%s",
                            lane, scan, (unsigned long)targetCount,
                            (unsigned long)pendingCount,
                            (unsigned long)states.count,
                            access("/var/mobile/.eksafemode", F_OK) == 0
                                ? "true"
                                : "false");
            }
        }
        usleep(250 * 1000);
    }
}

static xpc_connection_t gSileoXpcListener;

static void handle_sileo_xpc_request(xpc_connection_t peer,
                                     xpc_object_t message, pid_t peerPid,
                                     NSString *expectedMain,
                                     NSString *expectedHelper,
                                     NSString *jailbreakRoot,
                                     bool runtimeTrustClient) {
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
                           executable_paths_match(expectedHelper, path);
        accepted = sileoClient ||
            (runtimeTrustClient &&
             executable_paths_match(kRuntimeTrustClientExecutable, path));
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
    NSMutableArray<NSString *> *trustPaths = [NSMutableArray array];
    bool runtimeTrustRequest =
        valid && runtimeTrustClient && controlEnvironmentCount == 0 &&
        strcmp(arguments[0], CODEX_RUNTIME_TRUST_BROKER_VERB) == 0;
    for (uint32_t index = 1; runtimeTrustRequest && index < argumentCount;
         ++index) {
        NSString *path = [NSString stringWithUTF8String:arguments[index]];
        if (![path hasPrefix:@"/"] || ![path hasSuffix:@".deb"]) {
            runtimeTrustRequest = false;
            break;
        }
        [trustPaths addObject:path];
    }
    char resolved[PATH_MAX] = {0};
    bool allowed = valid &&
        (runtimeTrustRequest ||
         (!runtimeTrustClient &&
          resolve_broker_command(arguments[0], jailbreakRoot, resolved,
                                 sizeof(resolved))));
    log_message("sileoXpcBrokerRequestStart pid=%d accepted=%s valid=%s "
                "allowed=%s command=%s",
                peerPid, accepted ? "true" : "false",
                valid ? "true" : "false", allowed ? "true" : "false",
                runtimeTrustRequest
                    ? CODEX_RUNTIME_TRUST_BROKER_VERB
                    : (resolved[0] != '\0' ? resolved : "none"));
    if (allowed) {
        if (runtimeTrustRequest) {
            bool registered = runtime_trust_deb_paths(
                trustPaths, "apt-pre-install-client");
            status = registered ? 0 : (1 << 8);
        } else {
            status = run_root_broker_command(
                -1, -1, arguments, descriptors, descriptorNumbers,
                descriptorCount, controlEnvironment,
                controlEnvironmentCount, jailbreakRoot, resolved);
        }
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
                runtimeTrustRequest
                    ? CODEX_RUNTIME_TRUST_BROKER_VERB
                    : (resolved[0] != '\0' ? resolved : "none"),
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
        bool pathAvailable = peerPid > 1 &&
            proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0;
        NSString *path = pathAvailable
            ? [NSString stringWithUTF8String:peerPath]
            : nil;
        bool sileoClient = peerUser == 501 &&
            (executable_paths_match(expectedMain, path) ||
             executable_paths_match(expectedHelper, path));
        bool runtimeTrustClient = peerUser == 0 &&
            executable_paths_match(kRuntimeTrustClientExecutable, path);
        bool accepted = sileoClient || runtimeTrustClient;
        if (!accepted) {
            log_message("sileoXpcBrokerRejected pid=%d uid=%u path=%s",
                        peerPid, peerUser,
                        peerPath[0] != '\0' ? peerPath : "none");
            xpc_connection_cancel(peer);
            return;
        }
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
                handle_sileo_xpc_request(
                    peer, message, peerPid, expectedMain, expectedHelper,
                    jailbreakRoot, runtimeTrustClient);
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
                bool accepted =
                    proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0 &&
                    [expectedExecutable
                        isEqual:[NSString stringWithUTF8String:peerPath]];
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

static NSString *sha256_for_regular_file(NSString *path) {
    int file = open([path fileSystemRepresentation],
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    if (file < 0 || fstat(file, &status) != 0 ||
        !S_ISREG(status.st_mode)) {
        if (file >= 0) {
            close(file);
        }
        return nil;
    }

    CC_SHA256_CTX context;
    bool hashed = CC_SHA256_Init(&context) == 1;
    unsigned char buffer[64 * 1024];
    while (hashed) {
        ssize_t length;
        do {
            length = read(file, buffer, sizeof(buffer));
        } while (length < 0 && errno == EINTR);
        if (length < 0) {
            hashed = false;
            break;
        }
        if (length == 0) {
            break;
        }
        hashed = CC_SHA256_Update(&context, buffer, (CC_LONG)length) == 1;
    }
    close(file);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    if (!hashed || CC_SHA256_Final(digest, &context) != 1) {
        return nil;
    }
    NSMutableString *hex =
        [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2U];
    for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
        [hex appendFormat:@"%02x", digest[index]];
    }
    return hex;
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

static bool restore_replaced_file(NSString *destination, NSString *backup) {
    NSString *failed = [[destination stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@".codex-failed-%@",
                                       [[NSUUID UUID] UUIDString]]];
    if (rename([destination fileSystemRepresentation],
               [failed fileSystemRepresentation]) != 0) {
        return false;
    }
    if (rename([backup fileSystemRepresentation],
               [destination fileSystemRepresentation]) != 0) {
        (void)rename([failed fileSystemRepresentation],
                     [destination fileSystemRepresentation]);
        return false;
    }
    [[NSFileManager defaultManager] removeItemAtPath:failed error:nil];
    return true;
}

static bool refresh_procursus_runtime_executables(
    NSString *normalizedRoot, NSString *baselineManifest,
    NSUInteger *didUpdate, NSUInteger *alreadyCurrent,
    NSUInteger *diverged, NSString **errorText) {
    if (didUpdate != NULL) {
        *didUpdate = 0;
    }
    if (alreadyCurrent != NULL) {
        *alreadyCurrent = 0;
    }
    if (diverged != NULL) {
        *diverged = 0;
    }

    NSDictionary *manifest =
        [NSDictionary dictionaryWithContentsOfFile:baselineManifest];
    NSDictionary *executables = manifest[@"Executables"];
    bool manifestVersionOne = [manifest[@"Version"] isEqual:@1];
    bool manifestVersionTwo = [manifest[@"Version"] isEqual:@2];
    if ((!manifestVersionOne && !manifestVersionTwo) ||
        ![executables isKindOfClass:[NSDictionary class]] ||
        executables.count == 0) {
        if (errorText != NULL) {
            *errorText = @"Procursus runtime baseline manifest is invalid";
        }
        return false;
    }

    NSFileManager *manager = [NSFileManager defaultManager];
    NSCharacterSet *nonHex = [[NSCharacterSet
        characterSetWithCharactersInString:@"0123456789abcdef"]
        invertedSet];
    NSArray<NSString *> *paths =
        [[executables allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (id candidatePath in paths) {
        if (![candidatePath isKindOfClass:[NSString class]]) {
            if (errorText != NULL) {
                *errorText = @"Procursus runtime baseline path is not text";
            }
            return false;
        }
        NSString *relativePath = (NSString *)candidatePath;
        id candidateDigests = executables[relativePath];
        NSArray *acceptedDigests = nil;
        if (manifestVersionOne &&
            [candidateDigests isKindOfClass:[NSString class]]) {
            acceptedDigests = @[ candidateDigests ];
        } else if (manifestVersionTwo &&
                   [candidateDigests isKindOfClass:[NSArray class]]) {
            acceptedDigests = (NSArray *)candidateDigests;
        }
        if (acceptedDigests.count == 0 || acceptedDigests.count > 64) {
            if (errorText != NULL) {
                *errorText =
                    @"Procursus runtime baseline digest history is invalid";
            }
            return false;
        }
        NSArray<NSString *> *components = [relativePath pathComponents];
        bool safePath = relativePath.length > 0 &&
            ![relativePath hasPrefix:@"/"] &&
            [[relativePath stringByStandardizingPath] isEqual:relativePath] &&
            components.count > 0;
        for (NSString *component in components) {
            if ([component isEqualToString:@"."] ||
                [component isEqualToString:@".."] ||
                [component containsString:@"/"]) {
                safePath = false;
                break;
            }
        }
        bool safeDigests = true;
        for (id candidateDigest in acceptedDigests) {
            if (![candidateDigest isKindOfClass:[NSString class]] ||
                [(NSString *)candidateDigest length] != 64 ||
                [(NSString *)candidateDigest
                    rangeOfCharacterFromSet:nonHex].location != NSNotFound) {
                safeDigests = false;
                break;
            }
        }
        if (!safePath || !safeDigests) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"invalid Procursus runtime baseline "
                                     @"entry: %@",
                                     relativePath];
            }
            return false;
        }

        NSString *normalized =
            [normalizedRoot stringByAppendingPathComponent:relativePath];
        NSString *destination =
            [@"/var/jb" stringByAppendingPathComponent:relativePath];
        struct stat normalizedStatus;
        struct stat destinationStatus;
        if (lstat([normalized fileSystemRepresentation], &normalizedStatus) !=
                0 ||
            !S_ISREG(normalizedStatus.st_mode) ||
            (normalizedStatus.st_mode & 0111) == 0) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"normalized Procursus runtime "
                                     @"executable is unavailable: %@",
                                     relativePath];
            }
            return false;
        }
        if (lstat([destination fileSystemRepresentation],
                  &destinationStatus) != 0) {
            if (errno != ENOENT) {
                if (errorText != NULL) {
                    *errorText = [NSString
                        stringWithFormat:@"installed Procursus runtime "
                                         @"status failed for %@: %s",
                                         destination, strerror(errno)];
                }
                return false;
            }
            log_message("procursusRuntimeExecutable=absent path=%s",
                        [destination UTF8String]);
            if (diverged != NULL) {
                ++*diverged;
            }
            continue;
        }
        if (!S_ISREG(destinationStatus.st_mode)) {
            log_message("procursusRuntimeExecutable=nonregular path=%s",
                        [destination UTF8String]);
            if (diverged != NULL) {
                ++*diverged;
            }
            continue;
        }
        if (files_are_equal(normalized, destination)) {
            if (alreadyCurrent != NULL) {
                ++*alreadyCurrent;
            }
            continue;
        }

        NSString *installedDigest = sha256_for_regular_file(destination);
        if (installedDigest == nil) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"could not hash installed Procursus "
                                     @"runtime executable: %@",
                                     destination];
            }
            return false;
        }
        if (![acceptedDigests containsObject:installedDigest]) {
            log_message("procursusRuntimeExecutable=diverged path=%s",
                        [destination UTF8String]);
            if (diverged != NULL) {
                ++*diverged;
            }
            continue;
        }

        NSString *backup =
            [[destination stringByDeletingLastPathComponent]
                stringByAppendingPathComponent:
                    [NSString stringWithFormat:@".codex-runtime-backup-%@",
                                               [[NSUUID UUID] UUIDString]]];
        NSString *replacementError = nil;
        if (!replace_file_with_backup(normalized, destination, backup,
                                      &replacementError)) {
            if (errorText != NULL) {
                *errorText = replacementError;
            }
            return false;
        }
        if (!files_are_equal(normalized, destination)) {
            bool restored = restore_replaced_file(destination, backup);
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"Procursus runtime executable refresh "
                                     @"failed for %@ (rollback=%@)",
                                     destination,
                                     restored ? @"complete" : @"failed"];
            }
            return false;
        }
        NSError *removeError = nil;
        if (![manager removeItemAtPath:backup error:&removeError]) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"Procursus runtime backup cleanup "
                                     @"failed: %@",
                                     removeError];
            }
            return false;
        }
        log_message("procursusRuntimeExecutable=updated path=%s",
                    [destination UTF8String]);
        if (didUpdate != NULL) {
            ++*didUpdate;
        }
    }
    return true;
}

static bool refresh_trusted_package_executables(
    NSString *originalRoot, NSString *normalizedRoot, NSUInteger *didUpdate,
    NSUInteger *alreadyCurrent, NSUInteger *notApplicable,
    NSString **errorText) {
    if (didUpdate != NULL) {
        *didUpdate = 0;
    }
    if (alreadyCurrent != NULL) {
        *alreadyCurrent = 0;
    }
    if (notApplicable != NULL) {
        *notApplicable = 0;
    }

    NSFileManager *manager = [NSFileManager defaultManager];
    BOOL originalIsDirectory = NO;
    BOOL normalizedIsDirectory = NO;
    if (![manager fileExistsAtPath:originalRoot
                       isDirectory:&originalIsDirectory] ||
        !originalIsDirectory ||
        ![manager fileExistsAtPath:normalizedRoot
                       isDirectory:&normalizedIsDirectory] ||
        !normalizedIsDirectory) {
        if (errorText != NULL) {
            *errorText = @"trusted package payload roots are unavailable";
        }
        return false;
    }

    NSDirectoryEnumerator<NSString *> *enumerator =
        [manager enumeratorAtPath:normalizedRoot];
    for (NSString *relativePath in enumerator) {
        NSString *normalized =
            [normalizedRoot stringByAppendingPathComponent:relativePath];
        struct stat normalizedStatus;
        if (lstat([normalized fileSystemRepresentation], &normalizedStatus) !=
                0 ||
            !S_ISREG(normalizedStatus.st_mode)) {
            continue;
        }

        NSString *original =
            [originalRoot stringByAppendingPathComponent:relativePath];
        struct stat originalStatus;
        if (lstat([original fileSystemRepresentation], &originalStatus) != 0) {
            if (errno == ENOENT) {
                // codesign may add bundle-local CodeResources metadata. It is
                // not an executable from the Debian payload and has no
                // installed destination to refresh.
                if (notApplicable != NULL) {
                    ++*notApplicable;
                }
                continue;
            }
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"trusted package original status failed for %@: %s",
                        relativePath, strerror(errno)];
            }
            return false;
        }
        if (!S_ISREG(originalStatus.st_mode)) {
            if (notApplicable != NULL) {
                ++*notApplicable;
            }
            continue;
        }

        // Non-executable package data is byte-identical in both trees. Only
        // files whose CodeDirectories were normalized need activation.
        if (files_are_equal(original, normalized)) {
            continue;
        }

        NSArray<NSString *> *components = [relativePath pathComponents];
        if (components.count < 4 ||
            ![components[1] isEqualToString:@"var"] ||
            ![components[2] isEqualToString:@"jb"]) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"trusted package path is outside var/jb: %@",
                        relativePath];
            }
            return false;
        }
        for (NSString *component in components) {
            if ([component isEqualToString:@"."] ||
                [component isEqualToString:@".."] ||
                [component containsString:@"/"]) {
                if (errorText != NULL) {
                    *errorText = [NSString
                        stringWithFormat:@"unsafe trusted package path: %@",
                                         relativePath];
                }
                return false;
            }
        }

        NSString *destination = @"/var/jb";
        for (NSUInteger index = 3; index < components.count; ++index) {
            destination =
                [destination stringByAppendingPathComponent:components[index]];
        }

        struct stat destinationStatus;
        if (lstat([destination fileSystemRepresentation],
                  &destinationStatus) != 0) {
            if (errno == ENOENT) {
                if (notApplicable != NULL) {
                    ++*notApplicable;
                }
                continue;
            }
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:@"installed package status failed for "
                                      @"%@: %s",
                                     destination, strerror(errno)];
            }
            return false;
        }
        if (!S_ISREG(destinationStatus.st_mode)) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"installed package executable is not regular: %@",
                        destination];
            }
            return false;
        }
        if (files_are_equal(normalized, destination)) {
            if (alreadyCurrent != NULL) {
                ++*alreadyCurrent;
            }
            continue;
        }
        if (!files_are_equal(original, destination)) {
            // An independently updated package owns this path. Never replace
            // bytes that do not match the exact pinned archive input.
            log_message("trustedPackageExecutable=diverged path=%s",
                        [destination UTF8String]);
            if (notApplicable != NULL) {
                ++*notApplicable;
            }
            continue;
        }

        NSString *backup =
            [[destination stringByDeletingLastPathComponent]
                stringByAppendingPathComponent:
                    [NSString stringWithFormat:@".codex-signature-backup-%@",
                                               [[NSUUID UUID] UUIDString]]];
        NSString *replacementError = nil;
        if (!replace_file_with_backup(normalized, destination, backup,
                                      &replacementError)) {
            if (errorText != NULL) {
                *errorText = replacementError;
            }
            return false;
        }
        if (!files_are_equal(normalized, destination)) {
            bool restored = restore_replaced_file(destination, backup);
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"trusted package executable verification failed for "
                         "%@ (rollback=%@)",
                        destination, restored ? @"complete" : @"failed"];
            }
            return false;
        }
        NSError *removeError = nil;
        if (![manager removeItemAtPath:backup error:&removeError]) {
            if (errorText != NULL) {
                *errorText = [NSString
                    stringWithFormat:
                        @"trusted package backup cleanup failed: %@",
                        removeError];
            }
            return false;
        }
        log_message("trustedPackageExecutable=updated path=%s",
                    [destination UTF8String]);
        if (didUpdate != NULL) {
            ++*didUpdate;
        }
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

static int run_and_wait_bounded(const char *executable,
                                char *const arguments[],
                                unsigned int timeoutMilliseconds) {
    pid_t child = 0;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes = NULL;
    int result = posix_spawn_file_actions_init(&actions);
    if (result != 0) {
        return 255;
    }
    posix_spawn_file_actions_adddup2(&actions, gLog, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, gLog, STDERR_FILENO);
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
                !is_sileo_bundle_container_path(registeredPath) ||
                managedRoot == nil ||
                ![managedRoot isEqual:jailbreakRoot]) {
                log_message("sileoRootBrokerModeValidation=false");
                return 1;
            }
            if (!start_sileo_xpc_broker(registeredPath, jailbreakRoot)) {
                log_message("sileoRootBrokerModeListener=false");
                return 1;
            }
            log_message("sileoRootBrokerModeReady=true path=%s root=%s",
                        [registeredPath UTF8String],
                        [jailbreakRoot UTF8String]);
            bool startupAdmission =
                runtime_admission_infrastructure_ready("broker-start");
            log_message("runtimeAdmissionStartup=%s backend=debugged-worker",
                        startupAdmission ? "success" : "failed");
            log_message("runtimePayloadAdmissionStartup=%s "
                        "backend=debugged-worker-v1 "
                        "payloadTrustCache=false",
                        startupAdmission ? "success" : "failed");
            dispatch_queue_t springBoardInjectionQueue =
                dispatch_queue_create(
                "com.openai.codex.dopamine.ellekit-springboard",
                DISPATCH_QUEUE_SERIAL);
            dispatch_async(springBoardInjectionQueue, ^{
                serve_ellekit_per_process_injector(true);
            });
            dispatch_queue_t applicationInjectionQueue =
                dispatch_queue_create(
                "com.openai.codex.dopamine.ellekit-applications",
                DISPATCH_QUEUE_SERIAL);
            dispatch_async(applicationInjectionQueue, ^{
                serve_ellekit_per_process_injector(false);
            });
            dispatch_main();
            __builtin_unreachable();
        }
        if (argc == 2 &&
            strcmp(argv[1], "--trust-debs-stdin") == 0) {
            NSString *managedRoot = managed_jailbreak_root();
            if (geteuid() != 0 || managedRoot == nil) {
                log_message("runtimeTrustAptHookValidation=false");
                return 1;
            }
            bool trusted = runtime_trust_debs_from_standard_input();
            log_message("runtimeTrustAptHook=%s",
                        trusted ? "success" : "failed");
            return trusted ? 0 : 1;
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
        NSString *sourceTrustedSileo =
            [payloadRoot stringByAppendingPathComponent:@"trusted/Sileo.app"];
        NSString *sourceTrustedLaunchctl =
            [sourceProcursus stringByAppendingPathComponent:@"usr/bin/launchctl"];
        NSString *sourceTrustedUiopen =
            [sourceProcursus stringByAppendingPathComponent:@"usr/bin/uiopen"];
        NSString *sourceDefaultSources =
            [payloadRoot stringByAppendingPathComponent:
                             @"dopamine-default.sources"];
        NSString *sourceRepositoryCompatibility =
            [payloadRoot stringByAppendingPathComponent:
                             @"apt/99dopamine-repository-compat"];
        NSString *sourceRuntimeTrustAptConfig =
            [payloadRoot stringByAppendingPathComponent:
                             @"apt/98codex-runtime-trust"];
        NSString *sourceAptListNormalizer =
            [payloadRoot stringByAppendingPathComponent:
                             @"normalize-apt-lists.sh"];
        NSString *sourceBaseCdhashes =
            [payloadRoot stringByAppendingPathComponent:
                             @"base-cdhashes.txt"];
        NSString *sourceProcursusRuntimeBaseline =
            [payloadRoot stringByAppendingPathComponent:
                             @"procursus-runtime-baseline.plist"];
        NSString *sourceElleKitCompatLoader =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/codex-ellekit-loader"];
        NSString *sourceExecWorker =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/codex-exec-worker"];
        NSString *sourceExecInterposer =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/lib/codex-exec-interposer.dylib"];
        NSString *sourceRuntimeTrust =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/codex-runtime-trust"];
        NSString *sourceRuntimeTrustClient =
            [mountRoot stringByAppendingPathComponent:
                           @"usr/local/bin/codex-runtime-trust-client"];
        NSString *sourceKeyringDirectory =
            [payloadRoot stringByAppendingPathComponent:@"keyrings"];
        NSString *sourceElleKitKey =
            [sourceKeyringDirectory stringByAppendingPathComponent:
                                        @"ellekit.gpg"];
        NSString *sourceBigBossKey =
            [sourceKeyringDirectory stringByAppendingPathComponent:
                                        @"bigboss.gpg"];
        NSString *sourceOriginalTrustedPackages =
            [payloadRoot stringByAppendingPathComponent:
                             @"trusted-packages-original"];
        NSString *sourceTrustedPackages =
            [payloadRoot stringByAppendingPathComponent:@"trusted-packages"];
        BOOL isDirectory = NO;
        if (![[NSFileManager defaultManager] fileExistsAtPath:sourceProcursus
                                                 isDirectory:&isDirectory] ||
            !isDirectory ||
            ![[NSFileManager defaultManager] fileExistsAtPath:sourceSileo] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedSileo
                     isDirectory:&isDirectory] ||
            !isDirectory ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedLaunchctl] ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedUiopen]) {
            return fail(@"cryptex payload is incomplete", nil);
        }
        if (![[NSFileManager defaultManager]
                fileExistsAtPath:sourceOriginalTrustedPackages
                     isDirectory:&isDirectory] ||
            !isDirectory ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:sourceTrustedPackages
                     isDirectory:&isDirectory] ||
            !isDirectory) {
            return fail(@"trusted package payload is incomplete", nil);
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
        if (lstat([sourceRuntimeTrustAptConfig fileSystemRepresentation],
                  &repositoryCompatibilityStatus) != 0 ||
            !S_ISREG(repositoryCompatibilityStatus.st_mode)) {
            return fail(@"runtime admission APT policy is missing", nil);
        }
        struct stat aptListNormalizerStatus;
        if (lstat([sourceAptListNormalizer fileSystemRepresentation],
                  &aptListNormalizerStatus) != 0 ||
            !S_ISREG(aptListNormalizerStatus.st_mode)) {
            return fail(@"APT package-list normalizer is missing", nil);
        }
        struct stat baseCdhashesStatus;
        if (lstat([sourceBaseCdhashes fileSystemRepresentation],
                  &baseCdhashesStatus) != 0 ||
            !S_ISREG(baseCdhashesStatus.st_mode) ||
            baseCdhashesStatus.st_size <= 0 ||
            baseCdhashesStatus.st_size > 1024 * 1024) {
            return fail(@"runtime admission baseline is missing", nil);
        }
        struct stat procursusRuntimeBaselineStatus;
        if (lstat([sourceProcursusRuntimeBaseline fileSystemRepresentation],
                  &procursusRuntimeBaselineStatus) != 0 ||
            !S_ISREG(procursusRuntimeBaselineStatus.st_mode) ||
            procursusRuntimeBaselineStatus.st_size <= 0 ||
            procursusRuntimeBaselineStatus.st_size > 1024 * 1024) {
            return fail(@"Procursus runtime baseline manifest is missing", nil);
        }
        struct stat injectionHelperStatus;
        if (lstat([sourceElleKitCompatLoader fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceExecWorker fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceExecInterposer fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceRuntimeTrust fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode) ||
            lstat([sourceRuntimeTrustClient fileSystemRepresentation],
                  &injectionHelperStatus) != 0 ||
            !S_ISREG(injectionHelperStatus.st_mode)) {
            return fail(@"runtime admission helpers are missing", nil);
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
            NSDictionary *manifest = @{
                @"Installer" : kInstallerIdentifier,
                @"JailbreakRoot" : destinationProcursus,
                @"RandomizedRoot" : randomizedRoot,
                @"VarJbCreated" : @YES,
                @"CryptexMountRoot" : mountRoot,
                @"Source" : @"opa334/Dopamine 3.x",
            };
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

        NSUInteger procursusRuntimeUpdated = 0;
        NSUInteger procursusRuntimeCurrent = 0;
        NSUInteger procursusRuntimeDiverged = 0;
        NSString *procursusRuntimeError = nil;
        if (!refresh_procursus_runtime_executables(
                sourceProcursus, sourceProcursusRuntimeBaseline,
                &procursusRuntimeUpdated, &procursusRuntimeCurrent,
                &procursusRuntimeDiverged, &procursusRuntimeError)) {
            return fail(procursusRuntimeError, nil);
        }
        log_message("procursusRuntimeExecutables updated=%lu current=%lu "
                    "diverged=%lu",
                    (unsigned long)procursusRuntimeUpdated,
                    (unsigned long)procursusRuntimeCurrent,
                    (unsigned long)procursusRuntimeDiverged);

        bool earlyExecWorkerUpdated = false;
        bool earlyExecInterposerUpdated = false;
        bool earlyRuntimeBaselineUpdated = false;
        NSString *earlyRuntimeAdmissionError = nil;
        if (!install_managed_apt_file(
                sourceExecWorker, @"/var/jb/usr/libexec",
                @"codex-exec-worker", 16 * 1024 * 1024, 0755,
                "runtimeExecWorkerEarly", &earlyExecWorkerUpdated,
                &earlyRuntimeAdmissionError) ||
            !install_managed_apt_file(
                sourceExecInterposer, @"/var/jb/usr/lib",
                @"codex-exec-interposer.dylib", 16 * 1024 * 1024, 0755,
                "runtimeExecInterposerEarly", &earlyExecInterposerUpdated,
                &earlyRuntimeAdmissionError) ||
            !install_managed_apt_file(
                sourceBaseCdhashes,
                @"/var/jb/usr/share/codex-runtime-admission",
                @"base-cdhashes.txt", 1024 * 1024, 0644,
                "runtimeAdmissionBaselineEarly", &earlyRuntimeBaselineUpdated,
                &earlyRuntimeAdmissionError)) {
            return fail(earlyRuntimeAdmissionError, nil);
        }
        setenv("CODEX_RUNTIME_ADMISSION", "debugged-worker-v1", 1);
        unsetenv("DYLD_INSERT_LIBRARIES");
        log_message("runtimeAdmissionTransport=pinned-load workerUpdated=%s "
                    "interposerUpdated=%s baselineUpdated=%s",
                    earlyExecWorkerUpdated ? "true" : "false",
                    earlyExecInterposerUpdated ? "true" : "false",
                    earlyRuntimeBaselineUpdated ? "true" : "false");

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

        bool elleKitKeyUpdated = false;
        bool bigBossKeyUpdated = false;
        bool aptListNormalizerUpdated = false;
        bool repositoryCompatibilityUpdated = false;
        bool runtimeTrustAptConfigUpdated = false;
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
                sourceRuntimeTrustAptConfig,
                @"/var/jb/etc/apt/apt.conf.d",
                @"98codex-runtime-trust", 64 * 1024, 0644,
                "runtimeTrustAptHook", &runtimeTrustAptConfigUpdated,
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

        bool elleKitInjectorUpdated = false;
        bool execWorkerUpdated = false;
        bool execInterposerUpdated = false;
        bool runtimeTrustUpdated = false;
        bool runtimeTrustClientUpdated = false;
        bool runtimeBaselineUpdated = false;
        NSString *runtimeAdmissionError = nil;
        if (!install_managed_apt_file(
                sourceElleKitCompatLoader, @"/var/jb/usr/libexec",
                @"codex-ellekit-loader", 16 * 1024 * 1024, 0755,
                "elleKitPerProcessInjector", &elleKitInjectorUpdated,
                &runtimeAdmissionError) ||
            !install_managed_apt_file(
                sourceExecWorker, @"/var/jb/usr/libexec",
                @"codex-exec-worker", 16 * 1024 * 1024, 0755,
                "runtimeExecWorker", &execWorkerUpdated,
                &runtimeAdmissionError) ||
            !install_managed_apt_file(
                sourceExecInterposer, @"/var/jb/usr/lib",
                @"codex-exec-interposer.dylib", 16 * 1024 * 1024, 0755,
                "runtimeExecInterposer", &execInterposerUpdated,
                &runtimeAdmissionError) ||
            !install_managed_apt_file(
                sourceRuntimeTrust, @"/var/jb/usr/libexec",
                @"codex-runtime-trust", 16 * 1024 * 1024, 0755,
                "runtimeTrustHelper", &runtimeTrustUpdated,
                &runtimeAdmissionError) ||
            !install_managed_apt_file(
                sourceRuntimeTrustClient, @"/var/jb/usr/libexec",
                @"codex-runtime-trust-client", 1024 * 1024, 0755,
                "runtimeTrustClient", &runtimeTrustClientUpdated,
                &runtimeAdmissionError) ||
            !install_managed_apt_file(
                sourceBaseCdhashes,
                @"/var/jb/usr/share/codex-runtime-admission",
                @"base-cdhashes.txt", 1024 * 1024, 0644,
                "runtimeAdmissionBaseline", &runtimeBaselineUpdated,
                &runtimeAdmissionError)) {
            return fail(runtimeAdmissionError, nil);
        }
        log_message("runtimeAdmissionBaseline updated=%s path=%s",
                    runtimeBaselineUpdated ? "true" : "false",
                    "/var/jb/usr/share/codex-runtime-admission/"
                    "base-cdhashes.txt");
        setenv("CODEX_RUNTIME_ADMISSION", "debugged-worker-v1", 1);
        unsetenv("DYLD_INSERT_LIBRARIES");
        log_message("runtimeAdmissionEnvironment=ready transport=pinned-load "
                    "interposer=%s",
                    [kExecInterposerLibrary fileSystemRepresentation]);

        bool unsupportedKernelPackagesRemoved = false;
        NSString *kernelPackageError = nil;
        if (!repair_unsupported_kernel_packages(
                &unsupportedKernelPackagesRemoved, &kernelPackageError)) {
            return fail(kernelPackageError, nil);
        }

        NSUInteger trustedPackageUpdated = 0;
        NSUInteger trustedPackageCurrent = 0;
        NSUInteger trustedPackageNotApplicable = 0;
        NSString *trustedPackageError = nil;
        if (!refresh_trusted_package_executables(
                sourceOriginalTrustedPackages, sourceTrustedPackages,
                &trustedPackageUpdated, &trustedPackageCurrent,
                &trustedPackageNotApplicable, &trustedPackageError)) {
            return fail(trustedPackageError, nil);
        }
        log_message("trustedPackageExecutables updated=%lu current=%lu "
                    "notApplicable=%lu",
                    (unsigned long)trustedPackageUpdated,
                    (unsigned long)trustedPackageCurrent,
                    (unsigned long)trustedPackageNotApplicable);

        char *runtimeSelfTestArguments[] = {
            (char *)[kExecWorkerExecutable fileSystemRepresentation],
            "--self-test", NULL};
        int runtimeSelfTestStatus = run_and_wait(
            runtimeSelfTestArguments[0], runtimeSelfTestArguments);
        log_message("runtimeAdmissionSelfTestExit=%d", runtimeSelfTestStatus);
        if (runtimeSelfTestStatus != 0) {
            return fail(@"on-device runtime admission self-test failed", nil);
        }
        log_message("elleKitInjectionMode=per-process "
                    "launchdInjection=false pid1Guard=true");

        // Repair runs must refresh dpkg's installed maintainer-script copy as
        // well as the provisioned application. Reinstall the matched package
        // after trusted package executables are ready so its UIKit trigger can
        // execute under the static Cryptex trust cache.
        if (repairMode) {
            char *sileoRepairArguments[] = {
                "/var/jb/usr/bin/dpkg", "-i",
                (char *)[sourceSileo fileSystemRepresentation], NULL};
            int sileoRepairStatus = run_and_wait_bounded(
                sileoRepairArguments[0], sileoRepairArguments, 90000);
            log_message("sileoRepairDpkgExit=%d", sileoRepairStatus);
            if (sileoRepairStatus != 0) {
                return fail(
                    [NSString stringWithFormat:
                                  @"Sileo repair install exited %d",
                                  sileoRepairStatus],
                    nil);
            }
        }

        // Finish pending maintainer scripts after the fixed worker/interposer
        // is installed. Newly unpacked executables remain outside the static
        // trust cache and are routed through that runtime backend.
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
            runtimeTrustAptConfigUpdated || defaultSourcesUpdated;
        if (repositoryMetadataChanged) {
            char *apt_update_arguments[] = {
                "/var/jb/usr/bin/apt-get", "update", "-o",
                "Dpkg::Use-Pty=0", NULL};
            log_message("aptUpdateScope=all reason=repository-metadata-changed");
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
                    [NSString stringWithFormat:
                                  @"APT index refresh exited %d",
                                  apt_update_status],
                    nil);
            }
            if (apt_update_status != 0) {
                log_message("aptUpdateAdvisory=true mode=registration-repair "
                            "lists=populated status=%d",
                            apt_update_status);
            }
        } else if (!apt_package_lists_are_populated()) {
            NSString *procursusSources =
                @"/var/jb/etc/apt/sources.list.d/procursus.sources";
            if (access([procursusSources fileSystemRepresentation], R_OK) !=
                0) {
                return fail(@"Procursus APT source is unavailable", nil);
            }
            char *apt_update_arguments[] = {
                "/var/jb/usr/bin/apt-get", "update", "-o",
                "Dpkg::Use-Pty=0", "-o",
                "Dir::Etc::sourcelist=/var/jb/etc/apt/sources.list.d/"
                "procursus.sources",
                "-o", "Dir::Etc::sourceparts=-", NULL};
            log_message("aptUpdateScope=procursus");
            int apt_update_status =
                repairMode
                    ? run_and_wait_bounded(apt_update_arguments[0],
                                           apt_update_arguments, 60000)
                    : run_and_wait(apt_update_arguments[0],
                                   apt_update_arguments);
            log_message("aptUpdateExit=%d", apt_update_status);
            if (apt_update_status != 0 ||
                !apt_package_lists_are_populated()) {
                return fail(
                    [NSString stringWithFormat:
                                  @"initial apt index refresh exited %d",
                                  apt_update_status],
                    nil);
            }
        } else {
            log_message("aptUpdateSkipped=repository-metadata-current");
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

        const char *sileoBinary =
            "/var/jb/Applications/Sileo.app/Sileo";
        if (access(sileoBinary, X_OK) != 0) {
            return fail(@"Sileo executable missing after dpkg", nil);
        }

        NSString *registeredPath =
            registered_application_path(kSileoIdentifier);
        log_message("launchServicesPath=%s",
                    registeredPath != nil ? [registeredPath UTF8String]
                                          : "none");
        if (!is_sileo_bundle_container_path(registeredPath) ||
            ![[NSFileManager defaultManager]
                fileExistsAtPath:[registeredPath
                                     stringByAppendingPathComponent:
                                         @"embedded.mobileprovision"]]) {
            return fail(
                @"a provisioned Sileo placeholder is not registered in a "
                 "standard bundle container",
                nil);
        }
        NSString *trustedMain =
            [sourceTrustedSileo stringByAppendingPathComponent:@"Sileo"];
        NSString *trustedHelper =
            [sourceTrustedSileo stringByAppendingPathComponent:@"giveMeRoot"];
        NSString *rootlessMain =
            @"/var/jb/Applications/Sileo.app/Sileo";
        NSString *rootlessHelper =
            @"/var/jb/Applications/Sileo.app/giveMeRoot";
        NSString *rootlessBackupRoot = nil;
        NSString *rootlessMainBackup = nil;
        NSString *rootlessHelperBackup = nil;
        log_message("rootlessSileoVerification=start");
        BOOL mainMatches = files_are_equal(trustedMain, rootlessMain);
        log_message("rootlessSileoMainMatches=%s",
                    mainMatches ? "true" : "false");
        BOOL helperMatches = files_are_equal(trustedHelper, rootlessHelper);
        log_message("rootlessSileoHelperMatches=%s",
                    helperMatches ? "true" : "false");
        if (!mainMatches || !helperMatches) {
            rootlessBackupRoot = [destinationProcursus
                stringByAppendingPathComponent:
                    [NSString stringWithFormat:
                                  @".codex-cache/executable-backup-%@",
                                  [[NSUUID UUID] UUIDString]]];
            NSError *backupError = nil;
            if (![[NSFileManager defaultManager]
                    createDirectoryAtPath:rootlessBackupRoot
              withIntermediateDirectories:NO
                               attributes:@{
                                   NSFilePosixPermissions : @0700,
                                   NSFileOwnerAccountID : @0,
                                   NSFileGroupOwnerAccountID : @0,
                               }
                                    error:&backupError]) {
                return fail(
                    [NSString
                        stringWithFormat:
                            @"could not create rootless executable backup: %@",
                            backupError],
                    nil);
            }
            NSString *replacementError = nil;
            if (!mainMatches) {
                rootlessMainBackup = [rootlessBackupRoot
                    stringByAppendingPathComponent:@"Sileo"];
                if (!replace_file_with_backup(trustedMain, rootlessMain,
                                              rootlessMainBackup,
                                              &replacementError)) {
                    [[NSFileManager defaultManager]
                        removeItemAtPath:rootlessBackupRoot
                                  error:nil];
                    return fail(replacementError, nil);
                }
            }
            if (!helperMatches) {
                rootlessHelperBackup = [rootlessBackupRoot
                    stringByAppendingPathComponent:@"giveMeRoot"];
                if (!replace_file_with_backup(trustedHelper, rootlessHelper,
                                              rootlessHelperBackup,
                                              &replacementError)) {
                    BOOL restored = rootlessMainBackup == nil ||
                                    restore_replaced_file(
                                        rootlessMain, rootlessMainBackup);
                    log_message("rootlessMainRollback=%s",
                                restored ? "complete" : "failed");
                    if (restored) {
                        [[NSFileManager defaultManager]
                            removeItemAtPath:rootlessBackupRoot
                                      error:nil];
                    }
                    return fail(replacementError, nil);
                }
            }
        }
        if (!files_are_equal(trustedMain, rootlessMain) ||
            !files_are_equal(trustedHelper, rootlessHelper)) {
            return fail(@"rootless Sileo executable refresh did not match "
                         "the Cryptex trust-cache inputs",
                        nil);
        }
        log_message("rootlessSileoTrusted=true backup=%s",
                    rootlessBackupRoot != nil
                        ? [rootlessBackupRoot UTF8String]
                        : "not-needed");

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
        if (fchown(registeredHelperFile, 0, 0) != 0 ||
            fchmod(registeredHelperFile, 0755) != 0) {
            int savedError = errno;
            close(registeredHelperFile);
            return fail(
                [NSString stringWithFormat:
                              @"could not prepare registered giveMeRoot: %s",
                              strerror(savedError)],
                nil);
        }
        struct stat registeredHelperAfter;
        bool registeredHelperReady =
            fstat(registeredHelperFile, &registeredHelperAfter) == 0;
        close(registeredHelperFile);
        if (!registeredHelperReady || registeredHelperAfter.st_uid != 0 ||
            registeredHelperAfter.st_gid != 0 ||
            (registeredHelperAfter.st_mode & 07777) != 0755) {
            return fail(@"registered giveMeRoot ownership or mode did not "
                         "verify",
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

        NSString *dataContainer =
            registered_application_data_path(kSileoIdentifier);
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
        manifest[@"SileoDataContainer"] = dataContainer;
        manifest[@"SileoSandboxExtensions"] = tokenPath;
        manifest[@"SileoSandboxBroker"] = brokerPath;
        manifest[@"SileoRootBroker"] = @CODEX_ROOT_BROKER_MACH_SERVICE;
        manifest[@"SileoRootBrokerExecutable"] = kRootBrokerExecutable;
        manifest[@"RuntimeTrustClientExecutable"] =
            kRuntimeTrustClientExecutable;
        manifest[@"RuntimeExecWorkerExecutable"] = kExecWorkerExecutable;
        manifest[@"RuntimeExecInterposerLibrary"] = kExecInterposerLibrary;
        manifest[@"SileoRootBrokerPlist"] = kRootBrokerPlist;
        manifest[@"SileoExecutableMode"] =
            @"developer-signed-main-with-constructor-broker";
        if (rootlessBackupRoot != nil) {
            manifest[@"RootlessExecutableBackup"] = rootlessBackupRoot;
        }
        if (rootlessMainBackup != nil) {
            manifest[@"RootlessSileoBackup"] = rootlessMainBackup;
        }
        if (rootlessHelperBackup != nil) {
            manifest[@"RootlessGiveMeRootBackup"] = rootlessHelperBackup;
        }
        if (rootlessLaunchctlBackup != nil) {
            manifest[@"RootlessLaunchctlBackup"] = rootlessLaunchctlBackup;
        }
        if (rootlessUiopenBackup != nil) {
            manifest[@"RootlessUiopenBackup"] = rootlessUiopenBackup;
        }
        manifest[@"Source"] = @"opa334/Dopamine 3.x";
        if (![manifest writeToFile:rollbackManifest atomically:YES]) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(@"could not update rollback manifest", nil);
        }

        NSString *rootBrokerJobError = nil;
        if (!install_sileo_root_broker_job(executable, registeredPath,
                                           destinationProcursus,
                                           &rootBrokerJobError)) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(rootBrokerJobError, nil);
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
                geteuid(), destinationProcursus, rootlessMain,
                registeredPath, uiopen_status];
        if (!write_marker(kDonePath, done)) {
            close(broker);
            (void)unlink([brokerPath fileSystemRepresentation]);
            return fail(@"could not write completion marker", nil);
        }
        log_message(
            "result=success jailbreakRoot=%s sileo=%s uiopenExit=%d",
            [destinationProcursus UTF8String], [rootlessMain UTF8String],
            uiopen_status);
        serve_sileo_file_broker(registeredPath, destinationProcursus,
                                dataContainer);
        __builtin_unreachable();
    }
}
