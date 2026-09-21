// TrollStore Lite constructs a legacy registration dictionary for the
// ad-hoc payload immediately after copying it into its MCM bundle container.
// On iOS 27 LaunchServices rejects that dictionary before the root broker's
// normal post-hook can replace the executable with the fixed SBInject app
// launcher.  Suppress only that exact, marker-owned intermediate
// registration.  The broker then prepares and registers the final launcher
// synchronously before returning success to TrollStore.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <os/log.h>

#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef BOOL (*register_application_dictionary_function)(id, SEL,
                                                          NSDictionary *);

static register_application_dictionary_function gOriginalRegistration;

static void hook_log(const char *format, ...) {
    int descriptor = open(
        "/var/mobile/.sbinject-trollstore-registration.log",
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vdprintf(descriptor, format, arguments);
    va_end(arguments);
    (void)dprintf(descriptor, "\n");
    close(descriptor);
}

static bool admitted_trollstore_registration(NSDictionary *dictionary) {
    NSString *path = dictionary[@"Path"];
    NSString *identifier = dictionary[@"CFBundleIdentifier"];
    if (![path isKindOfClass:NSString.class] ||
        ![identifier isKindOfClass:NSString.class] ||
        path.length == 0 || identifier.length == 0 ||
        [identifier isEqualToString:@"com.opa334.TrollStoreLite"] ||
        ![dictionary[@"ApplicationType"] isEqual:@"System"] ||
        ![dictionary[@"IsAdHocSigned"] boolValue]) {
        return false;
    }

    NSString *bundle = [[path stringByResolvingSymlinksInPath]
        stringByStandardizingPath];
    NSString *container = bundle.stringByDeletingLastPathComponent;
    NSString *root = container.stringByDeletingLastPathComponent;
    bool admittedRoot = [root isEqualToString:
            @"/private/var/containers/Bundle/Application"] ||
        [root isEqualToString:@"/var/containers/Bundle/Application"];
    if (!admittedRoot ||
        ![bundle.pathExtension.lowercaseString isEqualToString:@"app"] ||
        [[NSUUID alloc] initWithUUIDString:container.lastPathComponent] == nil) {
        hook_log("registration rejected phase=path path=%s root=%s",
                 path.UTF8String, root.UTF8String);
        return false;
    }

    struct stat bundleStatus = {0};
    if (lstat(bundle.fileSystemRepresentation, &bundleStatus) != 0 ||
        !S_ISDIR(bundleStatus.st_mode) || S_ISLNK(bundleStatus.st_mode) ||
        (bundleStatus.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        hook_log("registration rejected phase=ownership path=%s uid=%u gid=%u "
                 "mode=%o",
                 bundle.UTF8String, bundleStatus.st_uid,
                 bundleStatus.st_gid, bundleStatus.st_mode & 07777);
        return false;
    }

    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [bundle stringByAppendingPathComponent:@"Info.plist"]];
    bool matches = [info[@"CFBundleIdentifier"] isEqual:identifier];
    if (!matches) {
        hook_log("registration rejected phase=identifier path=%s id=%s",
                 bundle.UTF8String, identifier.UTF8String);
    }
    return matches;
}

static BOOL register_application_dictionary(id object, SEL selector,
                                            NSDictionary *dictionary) {
    if (admitted_trollstore_registration(dictionary)) {
        hook_log("registration deferred path=%s id=%s",
                 [dictionary[@"Path"] UTF8String],
                 [dictionary[@"CFBundleIdentifier"] UTF8String]);
        os_log(OS_LOG_DEFAULT,
               "SBInject deferred TrollStore registration for %{public}@",
               dictionary[@"CFBundleIdentifier"]);
        return YES;
    }
    return gOriginalRegistration != NULL
        ? gOriginalRegistration(object, selector, dictionary) : NO;
}

__attribute__((constructor)) static void initialize_registration_hook(void) {
    Class workspace = NSClassFromString(@"LSApplicationWorkspace");
    SEL selector = @selector(registerApplicationDictionary:);
    Method method = workspace != Nil
        ? class_getInstanceMethod(workspace, selector) : NULL;
    if (method == NULL) {
        os_log_error(OS_LOG_DEFAULT,
                     "SBInject TrollStore registration method unavailable");
        return;
    }
    gOriginalRegistration =
        (register_application_dictionary_function)method_getImplementation(
            method);
    method_setImplementation(method, (IMP)register_application_dictionary);
    hook_log("registration hook ready class=%s",
             class_getName(workspace));
    os_log(OS_LOG_DEFAULT,
           "SBInject armed TrollStore deferred registration");
}
