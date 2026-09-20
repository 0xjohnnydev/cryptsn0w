#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <os/log.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xpc/xpc.h>

#import "PLHeap.h"
#import "PLSwiftMeta.h"
#include "litehook_rebind.h"
#include "../sileo_root_broker_protocol.h"

extern int32_t PL27DiscoverMetadata(const void *object,
                                    const void **output,
                                    NSInteger capacity);
extern bool PL27UpdateLookups(const void *object, void *snapshot,
                              int32_t sectionLookupOffset,
                              int32_t itemLookupOffset);

enum {
    PL27SnapshotMeta = 0,
    PL27SectionMeta = 1,
    PL27ItemMeta = 2,
    PL27SectionIdentifierMeta = 3,
    PL27ItemIdentifierMeta = 4,
    PL27ViewTypeMeta = 5,
    PL27LabelModelMeta = 6,
    PL27MetadataCount = 7,
};

typedef void *(*PL27SwiftAllocObjectFn)(const void *metadata, size_t size,
                                        size_t alignmentMask);
typedef void *(*PL27SwiftRetainFn)(void *object);
typedef void (*PL27SwiftReleaseFn)(void *object);

static void bridge_log(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static const void *gInjectedSections;
static NSInteger gInjectedSectionCount = -1;
static __unsafe_unretained id gStateInstance;
static const void *gItemIdentifierMetadata;
static uint32_t gItemIdentityCarrierTag = UINT32_MAX;
static NSString *gLastSelection;
static BOOL gPanePushScheduled;
static NSString *gHandledIdentity;
static CFTimeInterval gPaneShownAt;
static BOOL gUserAskedToPop;
static NSString *const kPL27IdentityPrefix = @"PLTweak:";
static NSString *const kPL27PreferencesDirectory =
    @"/var/jb/Library/PreferenceLoader/Preferences";
static const void *kPL27PaneHostKey = &kPL27PaneHostKey;
static const void *kPL27PaneSpecifiersKey = &kPL27PaneSpecifiersKey;
static const void *kPL27PaneMarkerKey = &kPL27PaneMarkerKey;
static PL27SwiftRetainFn gSwiftRetain;
static PL27SwiftReleaseFn gSwiftRelease;

#define PL27_FAKE_RESPRING_PID_FIRST ((pid_t)0x3e000000)
#define PL27_COMPLETED_RESPRING_COUNT 32U

static pthread_mutex_t gRespringJobLock = PTHREAD_MUTEX_INITIALIZER;
static pid_t gCompletedRespringJobs[PL27_COMPLETED_RESPRING_COUNT];
static size_t gNextCompletedRespringJob;
static uint32_t gNextRespringJobIdentifier;
typedef int (*PL27SystemFn)(const char *command);
static PL27SystemFn gOriginalSystem;

static const char *respring_command_leaf(const char *path) {
    if (path == NULL || path[0] == '\0') return NULL;
    const char *separator = strrchr(path, '/');
    return separator != NULL ? separator + 1 : path;
}

static BOOL arguments_request_respring(const char *path,
                                       char *const arguments[]) {
    const char *leaf = respring_command_leaf(path);
    if (leaf == NULL && arguments != NULL) {
        leaf = respring_command_leaf(arguments[0]);
    }
    if (leaf == NULL) return NO;
    if (strcmp(leaf, "sbreload") == 0) return YES;
    if (strcmp(leaf, "killall") != 0 || arguments == NULL) return NO;

    BOOL sawSpringBoard = NO;
    size_t index = 1;
    for (; index < 16U && arguments[index] != NULL; ++index) {
        const char *argument = arguments[index];
        if (argument[0] == '-' && argument[1] != '\0') continue;
        const char *target = respring_command_leaf(argument);
        BOOL springBoard = target != NULL &&
            (strcmp(target, "SpringBoard") == 0 ||
             strcmp(target, "notSpringBoard") == 0);
        if (!springBoard || sawSpringBoard) return NO;
        sawSpringBoard = YES;
    }
    return index < 16U && sawSpringBoard;
}

static BOOL request_preferences_respring(void) {
    typedef xpc_connection_t (*PL27CreateMachServiceFn)(
        const char *, dispatch_queue_t, uint64_t);
    PL27CreateMachServiceFn createMachService =
        (PL27CreateMachServiceFn)dlsym(
            RTLD_DEFAULT, "xpc_connection_create_mach_service");
    xpc_connection_t connection = createMachService != NULL
        ? createMachService(CODEX_ROOT_BROKER_MACH_SERVICE, NULL, 0) : NULL;
    if (connection == NULL) {
        bridge_log(@"respring broker connection unavailable");
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
        bridge_log(@"respring broker transport error: %s",
                   description != NULL ? description : "unknown");
    } else if (!accepted) {
        bridge_log(@"respring broker rejected Settings request");
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

static pid_t remember_completed_respring(void) {
    pthread_mutex_lock(&gRespringJobLock);
    pid_t result = PL27_FAKE_RESPRING_PID_FIRST +
        (pid_t)(gNextRespringJobIdentifier++ & 0x00ffffffU);
    gCompletedRespringJobs[gNextCompletedRespringJob] = result;
    gNextCompletedRespringJob =
        (gNextCompletedRespringJob + 1U) % PL27_COMPLETED_RESPRING_COUNT;
    pthread_mutex_unlock(&gRespringJobLock);
    return result;
}

static int bridge_posix_spawn(pid_t *restrict pid,
                              const char *restrict path,
                              const posix_spawn_file_actions_t *actions,
                              const posix_spawnattr_t *restrict attributes,
                              char *const arguments[restrict],
                              char *const environment[restrict]) {
    (void)actions;
    (void)attributes;
    (void)environment;
    if (!arguments_request_respring(path, arguments)) {
        return posix_spawn(pid, path, actions, attributes, arguments,
                           environment);
    }
    if (pid == NULL) return EINVAL;
    bridge_log(@"routing preference-pane respring command=%s",
               path != NULL ? path : "none");
    if (!request_preferences_respring()) return errno != 0 ? errno : EPERM;
    *pid = remember_completed_respring();
    return 0;
}

static int bridge_posix_spawnp(pid_t *restrict pid,
                               const char *restrict path,
                               const posix_spawn_file_actions_t *actions,
                               const posix_spawnattr_t *restrict attributes,
                               char *const arguments[restrict],
                               char *const environment[restrict]) {
    if (!arguments_request_respring(path, arguments)) {
        return posix_spawnp(pid, path, actions, attributes, arguments,
                            environment);
    }
    return bridge_posix_spawn(pid, path, actions, attributes, arguments,
                              environment);
}

static pid_t bridge_waitpid(pid_t pid, int *status, int options) {
    if ((options & ~WNOHANG) != 0) return waitpid(pid, status, options);
    pthread_mutex_lock(&gRespringJobLock);
    size_t match = PL27_COMPLETED_RESPRING_COUNT;
    for (size_t index = 0; index < PL27_COMPLETED_RESPRING_COUNT; ++index) {
        if (gCompletedRespringJobs[index] != 0 &&
            (pid == -1 || gCompletedRespringJobs[index] == pid)) {
            match = index;
            break;
        }
    }
    if (match == PL27_COMPLETED_RESPRING_COUNT) {
        pthread_mutex_unlock(&gRespringJobLock);
        return waitpid(pid, status, options);
    }
    pid_t completed = gCompletedRespringJobs[match];
    gCompletedRespringJobs[match] = 0;
    pthread_mutex_unlock(&gRespringJobLock);
    if (status != NULL) *status = 0;
    return completed;
}

static BOOL shell_command_requests_respring(const char *command) {
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
    return count != 0 && arguments_request_respring(arguments[0], arguments);
}

static int bridge_system(const char *command) {
    if (!shell_command_requests_respring(command)) {
        if (gOriginalSystem == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return gOriginalSystem(command);
    }
    bridge_log(@"routing preference-pane shell respring");
    if (!request_preferences_respring()) return -1;
    return 0;
}

static BOOL preference_code_image(const char *path) {
    BOOL rootless = path != NULL &&
        (strncmp(path, "/var/jb/", strlen("/var/jb/")) == 0 ||
         strstr(path, "/procursus/") != NULL);
    return rootless &&
        (strstr(path, "/Library/PreferenceBundles/") != NULL ||
         strstr(path, "/Library/Frameworks/") != NULL);
}

static void rebind_preference_process_functions(
    const struct mach_header *header, intptr_t slide) {
    (void)slide;
    Dl_info image = {0};
    if (header == NULL || dladdr(header, &image) == 0 ||
        !preference_code_image(image.dli_fname)) return;
    const struct mach_header_64 *header64 =
        (const struct mach_header_64 *)header;
    (void)litehook_rebind_symbol(header64, (void *)(uintptr_t)posix_spawn,
                                 (void *)(uintptr_t)bridge_posix_spawn);
    (void)litehook_rebind_symbol(header64, (void *)(uintptr_t)posix_spawnp,
                                 (void *)(uintptr_t)bridge_posix_spawnp);
    (void)litehook_rebind_symbol(header64, (void *)(uintptr_t)waitpid,
                                 (void *)(uintptr_t)bridge_waitpid);
    if (gOriginalSystem != NULL) {
        (void)litehook_rebind_symbol(
            header64, (void *)(uintptr_t)gOriginalSystem,
            (void *)(uintptr_t)bridge_system);
    }
}

static BOOL swift_memory_functions_ready(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gSwiftRetain = (PL27SwiftRetainFn)dlsym(RTLD_DEFAULT,
                                                "swift_retain");
        gSwiftRelease = (PL27SwiftReleaseFn)dlsym(RTLD_DEFAULT,
                                                  "swift_release");
    });
    return gSwiftRetain != NULL && gSwiftRelease != NULL;
}

bool PL27ReplaceDictionaryStorages(void *firstField,
                                   uintptr_t firstStorageWord,
                                   void *secondField,
                                   uintptr_t secondStorageWord) {
    if (firstField == NULL || secondField == NULL ||
        firstStorageWord == 0 || secondStorageWord == 0) return false;
    if (!swift_memory_functions_ready()) return false;
    uintptr_t firstOldWord = *(uintptr_t *)firstField;
    uintptr_t secondOldWord = *(uintptr_t *)secondField;
    (void)gSwiftRetain((void *)firstStorageWord);
    (void)gSwiftRetain((void *)secondStorageWord);
    *(uintptr_t *)firstField = firstStorageWord;
    *(uintptr_t *)secondField = secondStorageWord;
    if (firstOldWord != 0) gSwiftRelease((void *)firstOldWord);
    if (secondOldWord != 0) gSwiftRelease((void *)secondOldWord);
    return true;
}

static NSString *current_selection_identity(void) {
    if (gStateInstance == nil || gItemIdentifierMetadata == NULL ||
        gItemIdentityCarrierTag == UINT32_MAX) {
        return nil;
    }
    Ivar selectionIvar = class_getInstanceVariable(
        object_getClass(gStateInstance), "_selectionState");
    if (selectionIvar == NULL) return nil;
    id selectionState = object_getIvar(gStateInstance, selectionIvar);
    if (selectionState == nil) return nil;
    Ivar currentIvar = class_getInstanceVariable(
        object_getClass(selectionState), "currentSelectionStorage");
    if (currentIvar == NULL) return nil;
    const uint8_t *current =
        (const uint8_t *)(__bridge const void *)selectionState +
        ivar_getOffset(currentIvar);
    size_t size = PLSwiftTypeSize(gItemIdentifierMetadata);
    if (size == 0 || size > 256U) return nil;
    uint8_t copy[256] = {0};
    memcpy(copy, current, size);
    uint32_t tag = PLSwiftEnumTag(copy, gItemIdentifierMetadata);
    if (tag != gItemIdentityCarrierTag) return nil;
    PLSwiftEnumProject(copy, gItemIdentifierMetadata);
    char *bytes = PLSwiftStringCopyUTF8(copy);
    if (bytes == NULL) return nil;
    NSString *identity = [NSString stringWithUTF8String:bytes];
    free(bytes);
    return identity;
}

static BOOL preference_filter_passes(id filter) {
    if (filter == nil) return YES;
    Class specifier = NSClassFromString(@"PSSpecifier");
    SEL selector = NSSelectorFromString(
        @"environmentPassesPreferenceLoaderFilter:");
    return specifier == Nil || ![specifier respondsToSelector:selector] ||
        ((BOOL (*)(id, SEL, id))objc_msgSend)(specifier, selector, filter);
}

static NSDictionary<NSString *, NSDictionary *> *entries_by_title(void) {
    static NSDictionary<NSString *, NSDictionary *> *entries;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableDictionary<NSString *, NSDictionary *> *found =
            [NSMutableDictionary dictionary];
        NSDirectoryEnumerator<NSString *> *enumerator =
            [NSFileManager.defaultManager
                enumeratorAtPath:kPL27PreferencesDirectory];
        for (NSString *relative in enumerator) {
            if (![relative.pathExtension.lowercaseString
                    isEqualToString:@"plist"]) continue;
            NSString *path = [kPL27PreferencesDirectory
                stringByAppendingPathComponent:relative];
            NSDictionary *plist =
                [NSDictionary dictionaryWithContentsOfFile:path];
            if (![plist isKindOfClass:NSDictionary.class] ||
                !preference_filter_passes(plist[@"filter"] ?: plist[@"Filter"])) {
                continue;
            }
            NSDictionary *entry = plist[@"entry"];
            if (![entry isKindOfClass:NSDictionary.class] ||
                !preference_filter_passes(entry[@"filter"] ?: entry[@"Filter"])) {
                continue;
            }
            NSString *title = entry[@"label"];
            if (![title isKindOfClass:NSString.class] || title.length == 0) {
                title = relative.lastPathComponent.stringByDeletingPathExtension;
            }
            if (title.length == 0 || title.length > 200U) continue;
            found[title] = @{
                @"entry" : entry,
                @"name" : relative.lastPathComponent.stringByDeletingPathExtension,
                @"source" : path.stringByDeletingLastPathComponent,
            };
        }
        entries = [found copy];
    });
    return entries;
}

static NSArray<NSString *> *preference_titles(void) {
    return [entries_by_title().allKeys
        sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
}

static NSString *identity_for_title(NSString *title) {
    return [kPL27IdentityPrefix stringByAppendingString:title];
}

static NSString *title_for_identity(NSString *identity) {
    if (![identity hasPrefix:kPL27IdentityPrefix]) return nil;
    NSString *title = [identity substringFromIndex:kPL27IdentityPrefix.length];
    return entries_by_title()[title] != nil ? title : nil;
}

static Class entry_controller_class(void) {
    static Class result;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class parent = NSClassFromString(@"PSListController");
        if (parent == Nil) return;
        result = objc_getClass("SBInjectPreferenceEntryController");
        if (result != Nil) return;
        result = objc_allocateClassPair(parent,
                                        "SBInjectPreferenceEntryController", 0);
        if (result == Nil) return;
        IMP implementation = imp_implementationWithBlock(^id(id object) {
            return objc_getAssociatedObject(object,
                                            kPL27PaneSpecifiersKey);
        });
        class_addMethod(result, NSSelectorFromString(@"specifiers"),
                        implementation, "@@:");
        objc_registerClassPair(result);
    });
    return result;
}

static NSMutableDictionary<NSString *, UIViewController *> *pane_cache(void) {
    static NSMutableDictionary<NSString *, UIViewController *> *panes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        panes = [NSMutableDictionary dictionary];
    });
    return panes;
}

static UIViewController *pane_for_identity(
    NSString *identity, UINavigationController *navigation) {
    NSString *title = title_for_identity(identity);
    if (title == nil) return nil;
    UIViewController *cached = pane_cache()[title];
    if (cached != nil) {
        if ([cached respondsToSelector:NSSelectorFromString(
                @"setRootController:")]) {
            ((void (*)(id, SEL, id))objc_msgSend)(
                cached, NSSelectorFromString(@"setRootController:"),
                navigation);
        }
        return cached;
    }
    NSDictionary *record = entries_by_title()[title];
    NSDictionary *entry = record[@"entry"];
    Class listController = NSClassFromString(@"PSListController");
    Class hostClass = entry_controller_class();
    if (listController == Nil || hostClass == Nil) {
        bridge_log(@"PSListController is unavailable");
        return nil;
    }
    id host = [[hostClass alloc] init];
    SEL specifierSelector = NSSelectorFromString(
        @"specifiersFromEntry:sourcePreferenceLoaderBundlePath:title:");
    if (![host respondsToSelector:specifierSelector]) {
        bridge_log(@"libprefs specifier entry point is unavailable");
        return nil;
    }
    NSArray *specifiers = ((id (*)(id, SEL, id, id, id))objc_msgSend)(
        host, specifierSelector, entry, record[@"source"], record[@"name"]);
    id specifier = specifiers.firstObject;
    if (specifier == nil) {
        bridge_log(@"specifier could not be built for %@", title);
        return nil;
    }
    id pane = nil;
    if (entry[@"bundle"] == nil) {
        Class specifierClass = NSClassFromString(@"PSSpecifier");
        SEL groupSelector = NSSelectorFromString(@"emptyGroupSpecifier");
        id group = [specifierClass respondsToSelector:groupSelector]
            ? ((id (*)(id, SEL))objc_msgSend)(specifierClass, groupSelector)
            : nil;
        NSMutableArray *paneSpecifiers = [NSMutableArray array];
        if (group != nil) [paneSpecifiers addObject:group];
        [paneSpecifiers addObjectsFromArray:specifiers];
        objc_setAssociatedObject(host, kPL27PaneSpecifiersKey,
                                 paneSpecifiers,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        pane = host;
    } else {
        SEL controllerSelector = NSSelectorFromString(@"controllerForSpecifier:");
        if (![host respondsToSelector:controllerSelector]) {
            bridge_log(@"controller resolver is unavailable for %@", title);
            return nil;
        }
        pane = ((id (*)(id, SEL, id))objc_msgSend)(
            host, controllerSelector, specifier);
    }
    if (![pane isKindOfClass:UIViewController.class]) {
        bridge_log(@"controller resolution for %@ returned %@", title, pane);
        return nil;
    }
    if ([pane respondsToSelector:NSSelectorFromString(@"setRootController:")]) {
        ((void (*)(id, SEL, id))objc_msgSend)(
            pane, NSSelectorFromString(@"setRootController:"), navigation);
    }
    if ([pane respondsToSelector:NSSelectorFromString(@"setParentController:")]) {
        ((void (*)(id, SEL, id))objc_msgSend)(
            pane, NSSelectorFromString(@"setParentController:"), nil);
    }
    objc_setAssociatedObject(pane, kPL27PaneHostKey, host,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(pane, kPL27PaneSpecifiersKey, specifiers,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(pane, kPL27PaneMarkerKey, identity,
                             OBJC_ASSOCIATION_COPY_NONATOMIC);
    ((UIViewController *)pane).title = title;
    ((UIViewController *)pane).navigationItem.title = title;
    pane_cache()[title] = pane;
    bridge_log(@"built pane title=%@ class=%@", title,
               NSStringFromClass([pane class]));
    return pane;
}

static UINavigationController *find_navigation_controller(
    UIViewController *controller) {
    if (controller == nil) return nil;
    if ([controller isKindOfClass:UINavigationController.class]) {
        UINavigationController *navigation =
            (UINavigationController *)controller;
        if (navigation.view.window != nil) return navigation;
    }
    if (controller.presentedViewController != nil) {
        UINavigationController *found = find_navigation_controller(
            controller.presentedViewController);
        if (found != nil) return found;
    }
    for (UIViewController *child in controller.childViewControllers.reverseObjectEnumerator) {
        UINavigationController *found = find_navigation_controller(child);
        if (found != nil) return found;
    }
    return nil;
}

static UINavigationController *active_navigation_controller(void) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            (scene.activationState != UISceneActivationStateForegroundActive &&
             scene.activationState != UISceneActivationStateForegroundInactive)) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.hidden) continue;
            UINavigationController *navigation =
                find_navigation_controller(window.rootViewController);
            if (navigation != nil) return navigation;
        }
    }
    return nil;
}

static void schedule_pane_for_identity(NSString *identity) {
    if (title_for_identity(identity) == nil || gPanePushScheduled ||
        [identity isEqualToString:gHandledIdentity]) return;
    gPanePushScheduled = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        gPanePushScheduled = NO;
        UINavigationController *navigation = active_navigation_controller();
        UIViewController *pane = navigation != nil
            ? pane_for_identity(identity, navigation) : nil;
        if (navigation == nil || pane == nil) {
            bridge_log(@"could not resolve navigation or pane for %@", identity);
            return;
        }
        if ([navigation.viewControllers containsObject:pane]) return;
        gHandledIdentity = [identity copy];
        gPaneShownAt = CACurrentMediaTime();
        bridge_log(@"directly pushing pane identity=%@ stack=%lu nav=%@",
                   identity,
                   (unsigned long)navigation.viewControllers.count,
                   NSStringFromClass(navigation.class));
        [navigation pushViewController:pane animated:YES];
    });
}

typedef void (*PL27PushIMP)(UINavigationController *, SEL,
                            UIViewController *, BOOL);
typedef UIViewController *(*PL27PopIMP)(UINavigationController *, SEL, BOOL);
typedef BOOL (*PL27ShouldPopIMP)(UINavigationController *, SEL,
                                UINavigationBar *, UINavigationItem *);
static PL27PushIMP gOriginalPush;
static PL27PopIMP gOriginalPop;
static PL27ShouldPopIMP gOriginalShouldPop;

static void bridge_push(UINavigationController *navigation, SEL selector,
                        UIViewController *controller, BOOL animated) {
    NSString *identity = current_selection_identity();
    NSString *title = title_for_identity(identity);
    UIViewController *existingPane = title != nil ? pane_cache()[title] : nil;
    NSString *controllerBundle =
        [NSBundle bundleForClass:controller.class].bundleIdentifier;
    if (existingPane != nil &&
        [navigation.viewControllers containsObject:existingPane] &&
        [controllerBundle hasPrefix:@"com.apple.SwiftUI"] &&
        CACurrentMediaTime() - gPaneShownAt <= 2.0) {
        bridge_log(@"refused immediate duplicate push for %@", title);
        return;
    }
    UIViewController *pane = nil;
    if (navigation.viewControllers.count == 1 &&
        title != nil) {
        pane = pane_for_identity(identity, navigation);
        if ([navigation.viewControllers containsObject:pane]) pane = nil;
    }
    if (pane != nil) {
        gHandledIdentity = [identity copy];
        gPaneShownAt = CACurrentMediaTime();
        bridge_log(@"substituting pane identity=%@ for controller=%@",
                   identity, NSStringFromClass(controller.class));
    }
    gOriginalPush(navigation, selector, pane ?: controller, animated);
}

static UIViewController *bridge_pop(UINavigationController *navigation,
                                    SEL selector, BOOL animated) {
    UIViewController *top = navigation.topViewController;
    BOOL ours = objc_getAssociatedObject(top, kPL27PaneMarkerKey) != nil;
    BOOL interactive =
        navigation.interactivePopGestureRecognizer.state ==
            UIGestureRecognizerStateBegan ||
        navigation.interactivePopGestureRecognizer.state ==
            UIGestureRecognizerStateChanged;
    BOOL expired = CACurrentMediaTime() - gPaneShownAt > 2.0;
    if (ours && !gUserAskedToPop && !interactive && !expired) {
        bridge_log(@"refused immediate housekeeping pop for %@", top.title);
        return nil;
    }
    gUserAskedToPop = NO;
    return gOriginalPop(navigation, selector, animated);
}

static BOOL bridge_should_pop(UINavigationController *navigation,
                              SEL selector, UINavigationBar *bar,
                              UINavigationItem *item) {
    gUserAskedToPop = YES;
    return gOriginalShouldPop != NULL
        ? gOriginalShouldPop(navigation, selector, bar, item) : YES;
}

static void install_navigation_hooks(void) {
    Method push = class_getInstanceMethod(UINavigationController.class,
                                          @selector(pushViewController:animated:));
    if (push != NULL) {
        gOriginalPush = (PL27PushIMP)method_getImplementation(push);
        method_setImplementation(push, (IMP)bridge_push);
    }
    Method pop = class_getInstanceMethod(
        UINavigationController.class,
        @selector(popViewControllerAnimated:));
    if (pop != NULL) {
        gOriginalPop = (PL27PopIMP)method_getImplementation(pop);
        method_setImplementation(pop, (IMP)bridge_pop);
    }
    SEL shouldPopSelector =
        @selector(navigationBar:shouldPopItem:);
    Method shouldPop = class_getInstanceMethod(
        UINavigationController.class, shouldPopSelector);
    if (shouldPop != NULL) {
        gOriginalShouldPop =
            (PL27ShouldPopIMP)method_getImplementation(shouldPop);
        method_setImplementation(shouldPop, (IMP)bridge_should_pop);
    }
}

static void *allocate_array_like(const void *arrayField, NSInteger count,
                                 size_t stride) {
    if (arrayField == NULL || count <= 0 || stride == 0) return NULL;
    uintptr_t storage = *(const uintptr_t *)arrayField;
    if (storage == 0) return NULL;
    Class runtimeClass = object_getClass((__bridge id)(void *)storage);
    static PL27SwiftAllocObjectFn allocate;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        allocate = (PL27SwiftAllocObjectFn)dlsym(RTLD_DEFAULT,
                                                 "swift_allocObject");
    });
    if (allocate == NULL || runtimeClass == Nil) return NULL;
    size_t bytes = 32U + (size_t)count * stride;
    uintptr_t buffer = (uintptr_t)allocate(
        (__bridge const void *)runtimeClass, bytes, 7);
    if (buffer == 0) return NULL;
    *(NSInteger *)(buffer + 16U) = count;
    uintptr_t templateFlags = *(const uintptr_t *)(storage + 24U) & 1U;
    *(uintptr_t *)(buffer + 24U) = ((uintptr_t)count << 1U) | templateFlags;
    return (void *)buffer;
}

static BOOL section_tag_is_used(const void *sectionsField,
                                NSInteger sectionCount,
                                size_t sectionStride, int32_t sectionID,
                                const void *sectionIdentifierMeta,
                                uint32_t candidate) {
    for (NSInteger index = 0; index < sectionCount; ++index) {
        const void *section = PLSwiftArrayElement(
            sectionsField, index, sectionStride);
        if (section != NULL && PLSwiftEnumTag(
                (const uint8_t *)section + sectionID,
                sectionIdentifierMeta) == candidate) {
            return YES;
        }
    }
    return NO;
}

static uint32_t unused_section_tag(const void *sectionsField,
                                   NSInteger sectionCount,
                                   size_t sectionStride, int32_t sectionID,
                                   const void *sectionIdentifierMeta) {
    uint32_t preferred = PLSwiftEnumTagNamed(
        sectionIdentifierMeta, "connectedHeadphones");
    if (preferred != UINT32_MAX &&
        !PLSwiftEnumCaseHasPayload(sectionIdentifierMeta, preferred) &&
        !section_tag_is_used(sectionsField, sectionCount, sectionStride,
                             sectionID, sectionIdentifierMeta, preferred)) {
        return preferred;
    }
    for (uint32_t candidate = PLSwiftEnumCaseCount(sectionIdentifierMeta);
         candidate-- > 0;) {
        if (!PLSwiftEnumCaseHasPayload(sectionIdentifierMeta, candidate) &&
            !section_tag_is_used(sectionsField, sectionCount, sectionStride,
                                 sectionID, sectionIdentifierMeta,
                                 candidate)) {
            return candidate;
        }
    }
    return UINT32_MAX;
}

static void bridge_log(NSString *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    NSString *body = [[NSString alloc] initWithFormat:format
                                             arguments:arguments];
    va_end(arguments);
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.openai.codex.sbinject",
                            "preferences-bridge");
    });
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT, "%{public}s",
                     body.UTF8String);
    int descriptor = open("/var/mobile/.sbinject-preferences-bridge.log",
                          O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) return;
    struct stat status = {0};
    if (fstat(descriptor, &status) == 0 && status.st_size > 64 * 1024) {
        (void)ftruncate(descriptor, 0);
    }
    NSData *data = [[body stringByAppendingString:@"\n"]
        dataUsingEncoding:NSUTF8StringEncoding];
    (void)write(descriptor, data.bytes, data.length);
    close(descriptor);
}

static BOOL inject_one_row(id state) {
    Ivar cachedSnapshot = class_getInstanceVariable(
        object_getClass(state), "_cachedSnapshot");
    if (cachedSnapshot == NULL) {
        bridge_log(@"_cachedSnapshot ivar missing");
        return NO;
    }
    uint8_t *snapshot = (__bridge void *)state +
        ivar_getOffset(cachedSnapshot);
    uintptr_t currentSections = *(const uintptr_t *)snapshot;
    if ((const void *)currentSections == gInjectedSections &&
        currentSections != 0 &&
        *(const NSInteger *)(currentSections + 16U) ==
            gInjectedSectionCount) {
        return YES;
    }

    const void *metadata[PL27MetadataCount] = {0};
    if (PL27DiscoverMetadata((__bridge const void *)state, metadata,
                             PL27MetadataCount) != PL27MetadataCount) {
        bridge_log(@"metadata discovery failed");
        return NO;
    }

    const void *snapshotMeta = metadata[PL27SnapshotMeta];
    const void *sectionMeta = metadata[PL27SectionMeta];
    const void *itemMeta = metadata[PL27ItemMeta];
    const void *sectionIdentifierMeta =
        metadata[PL27SectionIdentifierMeta];
    const void *itemIdentifierMeta = metadata[PL27ItemIdentifierMeta];
    const void *viewTypeMeta = metadata[PL27ViewTypeMeta];
    const void *labelModelMeta = metadata[PL27LabelModelMeta];

    int32_t snapshotSections =
        PLSwiftStructOffsetOfField(snapshotMeta, "sections");
    int32_t snapshotSectionLookup = PLSwiftStructOffsetOfField(
        snapshotMeta, "sectionIdentifierLookup");
    int32_t snapshotItemLookup = PLSwiftStructOffsetOfField(
        snapshotMeta, "itemIdentifierLookup");
    int32_t sectionID = PLSwiftStructOffsetOfField(sectionMeta, "id");
    int32_t sectionItems =
        PLSwiftStructOffsetOfField(sectionMeta, "items");
    int32_t itemID = PLSwiftStructOffsetOfField(itemMeta, "id");
    int32_t itemType = PLSwiftStructOffsetOfField(itemMeta, "type");
    int32_t labelText =
        PLSwiftStructOffsetOfField(labelModelMeta, "text");
    size_t sectionStride = PLSwiftTypeStride(sectionMeta);
    size_t itemStride = PLSwiftTypeStride(itemMeta);
    if (snapshotSections < 0 || snapshotSectionLookup < 0 ||
        snapshotItemLookup < 0 || sectionID < 0 || sectionItems < 0 ||
        itemID < 0 || itemType < 0 || labelText < 0 ||
        sectionStride == 0 || itemStride == 0) {
        return NO;
    }

    void *sectionsField = snapshot + snapshotSections;
    NSInteger sectionCount = PLSwiftArrayCount(sectionsField);
    if (sectionCount <= 0) {
        bridge_log(@"invalid section count %td", sectionCount);
        return NO;
    }
    if (*(const void *const *)sectionsField == gInjectedSections &&
        sectionCount == gInjectedSectionCount) {
        return YES;
    }

    NSArray<NSString *> *titles = preference_titles();
    if (titles.count == 0 || titles.count > 256U) return YES;

    const void *templateSection = NULL;
    const void *templateItems = NULL;
    const void *templateItem = NULL;
    for (NSInteger index = sectionCount; index-- > 0;) {
        const void *candidateSection = PLSwiftArrayElement(
            sectionsField, index, sectionStride);
        if (candidateSection == NULL) continue;
        const void *candidateSectionID =
            (const uint8_t *)candidateSection + sectionID;
        uint32_t candidateSectionTag = PLSwiftEnumTag(
            candidateSectionID, sectionIdentifierMeta);
        if (PLSwiftEnumCaseHasPayload(sectionIdentifierMeta,
                                      candidateSectionTag)) continue;
        const void *candidateItems =
            (const uint8_t *)candidateSection + sectionItems;
        const void *candidateItem =
            PLSwiftArrayElement(candidateItems, 0, itemStride);
        if (candidateItem == NULL) continue;
        const void *candidateItemID =
            (const uint8_t *)candidateItem + itemID;
        uint32_t candidateItemTag = PLSwiftEnumTag(
            candidateItemID, itemIdentifierMeta);
        if (PLSwiftEnumCaseHasPayload(itemIdentifierMeta,
                                      candidateItemTag)) continue;
        const void *candidateView =
            (const uint8_t *)candidateItem + itemType;
        const char *candidateCase = PLSwiftEnumCaseName(
            viewTypeMeta, PLSwiftEnumTag(candidateView, viewTypeMeta));
        if (candidateCase == NULL || strcmp(candidateCase, "label") != 0) {
            continue;
        }
        templateSection = candidateSection;
        templateItems = candidateItems;
        templateItem = candidateItem;
        break;
    }
    if (templateSection == NULL || templateItems == NULL ||
        templateItem == NULL) {
        bridge_log(@"no payload-free label template is available");
        return NO;
    }

    void *newItems = allocate_array_like(
        templateItems, (NSInteger)titles.count, itemStride);
    if (newItems == NULL) {
        bridge_log(@"item allocation failed");
        return NO;
    }
    uint32_t itemTag =
        PLSwiftEnumTagNamed(itemIdentifierMeta, "connectedHeadphone");
    size_t itemIDSize = PLSwiftTypeSize(itemIdentifierMeta);
    if (itemTag == UINT32_MAX || itemIDSize == 0) {
        bridge_log(@"item identity carrier unavailable");
        return NO;
    }
    gItemIdentifierMetadata = itemIdentifierMeta;
    gItemIdentityCarrierTag = itemTag;
    uint8_t *itemBase =
        (uint8_t *)newItems + PLSwiftArrayElementOffset();
    for (NSUInteger index = 0; index < titles.count; ++index) {
        NSString *title = titles[index];
        void *newItem = itemBase + index * itemStride;
        PLSwiftValueInitializeWithCopy(newItem, templateItem, itemMeta);

        void *newItemID = (uint8_t *)newItem + itemID;
        memset(newItemID, 0, itemIDSize);
        PLSwiftStringInitialize(identity_for_title(title).UTF8String,
                                newItemID);
        PLSwiftEnumInject(newItemID, itemTag, itemIdentifierMeta);

        void *newViewType = (uint8_t *)newItem + itemType;
        uint32_t viewTag = PLSwiftEnumTag(newViewType, viewTypeMeta);
        const char *viewCase = PLSwiftEnumCaseName(viewTypeMeta, viewTag);
        if (viewCase == NULL || strcmp(viewCase, "label") != 0) {
            bridge_log(@"template changed from a label row");
            return NO;
        }
        PLSwiftEnumProject(newViewType, viewTypeMeta);
        PLSwiftStringAssign((uint8_t *)newViewType + labelText,
                            title.UTF8String);
        PLSwiftEnumInject(newViewType, viewTag, viewTypeMeta);
    }

    void *newSections = allocate_array_like(
        sectionsField, sectionCount + 1, sectionStride);
    if (newSections == NULL) {
        bridge_log(@"section allocation failed");
        return NO;
    }
    uint8_t *sectionBase =
        (uint8_t *)newSections + PLSwiftArrayElementOffset();
    for (NSInteger index = 0; index < sectionCount; ++index) {
        PLSwiftValueInitializeWithCopy(
            sectionBase + index * sectionStride,
            PLSwiftArrayElement(sectionsField, index, sectionStride),
            sectionMeta);
    }
    void *newSection = sectionBase + sectionCount * sectionStride;
    PLSwiftValueInitializeWithCopy(newSection, templateSection, sectionMeta);

    uint32_t sectionTag = unused_section_tag(
        sectionsField, sectionCount, sectionStride, sectionID,
        sectionIdentifierMeta);
    size_t sectionIDSize = PLSwiftTypeSize(sectionIdentifierMeta);
    if (sectionTag == UINT32_MAX || sectionIDSize == 0) {
        bridge_log(@"section identity unavailable");
        return NO;
    }
    void *newSectionID = (uint8_t *)newSection + sectionID;
    memset(newSectionID, 0, sectionIDSize);
    PLSwiftEnumInject(newSectionID, sectionTag, sectionIdentifierMeta);
    *(void **)((uint8_t *)newSection + sectionItems) = newItems;

    *(void **)sectionsField = newSections;
    bool lookupsUpdated = PL27UpdateLookups(
        (__bridge const void *)state, snapshot, snapshotSectionLookup,
        snapshotItemLookup);
    if (!lookupsUpdated) {
        *(uintptr_t *)sectionsField = currentSections;
        if (swift_memory_functions_ready()) {
            gSwiftRelease(newSections);
        }
        bridge_log(@"lookup dictionary update failed");
        return NO;
    }
    if (currentSections != 0 && swift_memory_functions_ready()) {
        gSwiftRelease((void *)currentSections);
    }
    gInjectedSections = newSections;
    gInjectedSectionCount = sectionCount + 1;
    bridge_log(@"injected %lu preference row(s) as section %td",
               (unsigned long)titles.count, sectionCount);
    return YES;
}

static void run_bridge(void) {
    if (gStateInstance != nil) {
        (void)inject_one_row(gStateInstance);
        NSString *selection = current_selection_identity();
        if ((selection != nil || gLastSelection != nil) &&
            ![selection isEqualToString:gLastSelection]) {
            bridge_log(@"selection changed %@ -> %@", gLastSelection ?: @"none",
                       selection ?: @"none");
            if (![selection isEqualToString:gHandledIdentity]) {
                gHandledIdentity = nil;
            }
            gLastSelection = [selection copy];
        }
        schedule_pane_for_identity(selection);
        return;
    }
    Class stateClass = objc_getClass(
        "_TtC11SettingsApp24SettingsSidebarListState");
    __unsafe_unretained id instances[8] = {nil};
    NSUInteger count = PLHeapFindInstances(stateClass, instances, 8);
    if (count > 0) {
        gStateInstance = instances[0];
        bridge_log(@"SettingsSidebarListState discovered");
        (void)inject_one_row(gStateInstance);
    }
}

static void bridge_runloop(CFRunLoopObserverRef observer,
                           CFRunLoopActivity activity, void *information) {
    (void)observer;
    (void)activity;
    (void)information;
    run_bridge();
}

__attribute__((constructor)) static void initialize_bridge(void) {
    if (objc_getClass("_TtC11SettingsApp24SettingsSidebarListState") == Nil) {
        return;
    }
    gOriginalSystem = (PL27SystemFn)dlsym(RTLD_DEFAULT, "system");
    _dyld_register_func_for_add_image(rebind_preference_process_functions);
    install_navigation_hooks();
    CFRunLoopObserverRef observer = CFRunLoopObserverCreate(
        kCFAllocatorDefault,
        kCFRunLoopBeforeTimers | kCFRunLoopBeforeWaiting,
        true, -2000000, bridge_runloop, NULL);
    if (observer != NULL) {
        CFRunLoopAddObserver(CFRunLoopGetMain(), observer,
                             kCFRunLoopCommonModes);
        bridge_log(@"iOS 27 Settings bridge armed");
    }
}
