#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach-o/dyld.h>
#import <os/log.h>

#include "sileo_root_broker_protocol.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
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
extern kern_return_t bootstrap_look_up(mach_port_t bootstrap_port,
                                       const char *service_name,
                                       mach_port_t *service_port);

#define CODEX_PROC_PIDPATH_MAX 4096

static const char *const kLogPath =
    "/var/tmp/codex-dopamine-cryptex-bootstrap.log";
static const char *const kDonePath =
    "/var/tmp/codex-dopamine-cryptex-bootstrap.done";
static const char *const kFailurePath =
    "/var/tmp/codex-dopamine-cryptex-bootstrap.failed";
static const char *const kVarJb = "/var/jb";
static NSString *const kInstallerIdentifier =
    @"com.openai.codex.dopamine.bootstrap";
static NSString *const kSileoIdentifier = @"org.coolstar.SileoStore";
static NSString *const kBundleContainerRoot =
    @"/var/containers/Bundle/Application";
static NSString *const kRootBrokerLabel =
    @"com.openai.codex.dopamine.sileo-root-broker";
static NSString *const kRootBrokerExecutable =
    @"/var/jb/usr/libexec/codex-sileo-root-broker";
static NSString *const kRootBrokerPlist =
    @"/var/jb/Library/LaunchDaemons/com.openai.codex.dopamine."
     "sileo-root-broker.plist";

@interface NSObject (CodexLaunchServices)
+ (id)applicationProxyForIdentifier:(NSString *)identifier;
- (NSURL *)bundleURL;
- (NSURL *)dataContainerURL;
@end

static int gLog = STDERR_FILENO;
static os_log_t gUnifiedLog;

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

static int32_t run_root_broker_command(
    int server, int client, char *const arguments[], int descriptors[],
    const int descriptorNumbers[], uint32_t descriptorCount,
    NSString *jailbreakRoot, const char *resolvedCommand) {
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
    char *environment[] = {
        "SILEO=1",
        "CYDIA=1",
        pathEnvironment,
        shellEnvironment,
        libraryEnvironment,
        "HOME=/var/root",
        "TMPDIR=/var/tmp",
        NULL,
    };

    pid_t child = 0;
    int spawnResult = posix_spawn(&child, resolvedCommand, &actions, NULL,
                                  arguments, environment);
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
                request.header.descriptor_count, jailbreakRoot, resolved);
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

static xpc_connection_t gSileoXpcListener;

static void handle_sileo_xpc_request(xpc_connection_t peer,
                                     xpc_object_t message, pid_t peerPid,
                                     NSString *expectedMain,
                                     NSString *expectedHelper,
                                     NSString *jailbreakRoot) {
    xpc_object_t reply = xpc_dictionary_create_reply(message);
    if (reply == NULL) {
        return;
    }
    int32_t status = 126 << 8;
    bool accepted = false;
    char peerPath[CODEX_PROC_PIDPATH_MAX] = {0};
    if (peerPid > 1 && proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0) {
        NSString *path = [NSString stringWithUTF8String:peerPath];
        accepted = [expectedMain isEqual:path] || [expectedHelper isEqual:path];
    }

    char *arguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 1U] = {0};
    int descriptors[CODEX_ROOT_BROKER_MAX_FDS];
    int descriptorNumbers[CODEX_ROOT_BROKER_MAX_FDS];
    uint32_t argumentCount = 0;
    uint32_t descriptorCount = 0;
    for (uint32_t index = 0; index < CODEX_ROOT_BROKER_MAX_FDS; ++index) {
        descriptors[index] = -1;
    }
    bool valid = accepted && xpc_get_type(message) == XPC_TYPE_DICTIONARY;
    xpc_object_t argumentArray =
        valid ? xpc_dictionary_get_value(message, "arguments") : NULL;
    xpc_object_t descriptorArray =
        valid ? xpc_dictionary_get_value(message, "descriptor-numbers")
              : NULL;
    if (argumentArray == NULL || xpc_get_type(argumentArray) != XPC_TYPE_ARRAY ||
        descriptorArray == NULL ||
        xpc_get_type(descriptorArray) != XPC_TYPE_ARRAY) {
        valid = false;
    }
    if (valid) {
        size_t count = xpc_array_get_count(argumentArray);
        size_t fdCount = xpc_array_get_count(descriptorArray);
        valid = count > 0 && count <= CODEX_ROOT_BROKER_MAX_ARGUMENTS &&
                fdCount > 0 && fdCount <= CODEX_ROOT_BROKER_MAX_FDS;
        argumentCount = valid ? (uint32_t)count : 0;
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
    char resolved[PATH_MAX] = {0};
    bool allowed =
        valid && resolve_broker_command(arguments[0], jailbreakRoot, resolved,
                                        sizeof(resolved));
    log_message("sileoXpcBrokerRequestStart pid=%d accepted=%s valid=%s "
                "allowed=%s command=%s",
                peerPid, accepted ? "true" : "false",
                valid ? "true" : "false", allowed ? "true" : "false",
                resolved[0] != '\0' ? resolved : "none");
    if (allowed) {
        status = run_root_broker_command(-1, -1, arguments, descriptors,
                                         descriptorNumbers, descriptorCount,
                                         jailbreakRoot, resolved);
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
                "command=%s status=%d",
                peerPid, accepted ? "true" : "false",
                valid ? "true" : "false", allowed ? "true" : "false",
                resolved[0] != '\0' ? resolved : "none", status);
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
        bool accepted = peerUser == 501 && peerPid > 1 &&
            proc_pidpath(peerPid, peerPath, sizeof(peerPath)) > 0 &&
            ([expectedMain
                 isEqual:[NSString stringWithUTF8String:peerPath]] ||
             [expectedHelper
                 isEqual:[NSString stringWithUTF8String:peerPath]]);
        if (!accepted) {
            log_message("sileoXpcBrokerRejected pid=%d uid=%u path=%s",
                        peerPid, peerUser,
                        peerPath[0] != '\0' ? peerPath : "none");
            xpc_connection_cancel(peer);
            return;
        }
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
                handle_sileo_xpc_request(peer, message, peerPid, expectedMain,
                                         expectedHelper, jailbreakRoot);
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
    @autoreleasepool {
        gUnifiedLog = os_log_create("com.openai.codex.dopamine.bootstrap",
                                    "installer");
        gLog = open(kLogPath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (gLog < 0) {
            gLog = STDERR_FILENO;
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
            dispatch_main();
            __builtin_unreachable();
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
                fileExistsAtPath:sourceTrustedLaunchctl]) {
            return fail(@"cryptex payload is incomplete", nil);
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

        setenv("PATH",
               "/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:"
               "/usr/bin:/bin:/usr/sbin:/sbin",
               1);
        setenv("HOME", "/var/root", 1);
        setenv("SHELL", "/var/jb/bin/sh", 1);
        setenv("NO_PASSWORD_PROMPT", "1", 1);

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

        bool unsupportedKernelPackagesRemoved = false;
        NSString *kernelPackageError = nil;
        if (!repair_unsupported_kernel_packages(
                &unsupportedKernelPackagesRemoved, &kernelPackageError)) {
            return fail(kernelPackageError, nil);
        }

        if (!apt_package_lists_are_populated()) {
            char *apt_update_arguments[] = {
                "/var/jb/usr/bin/apt-get", "update", "-o",
                "Dpkg::Use-Pty=0", NULL};
            int apt_update_status =
                run_and_wait(apt_update_arguments[0], apt_update_arguments);
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
            log_message("aptUpdateSkipped=package-lists-present");
        }

        char *apt_check_arguments[] = {
            "/var/jb/usr/bin/apt-get", "check", "-o", "Dpkg::Use-Pty=0",
            NULL};
        int apt_check_status =
            run_and_wait(apt_check_arguments[0], apt_check_arguments);
        log_message("aptDependencyCheckExit=%d", apt_check_status);
        if (apt_check_status != 0) {
            return fail(
                [NSString stringWithFormat:
                              @"APT dependency check exited %d",
                              apt_check_status],
                nil);
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
            "org.coolstar.SileoStore", NULL};
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
