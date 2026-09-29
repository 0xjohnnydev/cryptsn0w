#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <os/log.h>

#include "sbinject_legacy_tweak_compat.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
typedef CGFloat (*RowHeightImplementation)(id, SEL, UITableView *, NSIndexPath *);
typedef void (*CellLayoutImplementation)(UITableViewCell *, SEL);

static WindowHiddenImplementation OriginalWindowSetHidden;
static WindowVisibleImplementation OriginalWindowMakeKeyAndVisible;
static NSMutableDictionary<NSString *, NSValue *> *HeightImplementations;
static NSMutableDictionary<NSString *, NSValue *> *LayoutImplementations;
static NSHashTable<UIWindow *> *OrphanWindows;
static char SubtitleLabelKey;

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

static void ApplyConfiguredAliases(void) {
    NSDictionary *configuration = TrustedAliasConfiguration();
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
}

static void CompatWindowMakeKeyAndVisible(UIWindow *window, SEL selector) {
    (void)AdoptWindowScene(window);
    OriginalWindowMakeKeyAndVisible(window, selector);
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
        const char *types = method_getTypeEncoding(inherited);
        Method direct = DirectInstanceMethod(cls, selector);
        if (direct != NULL) {
            original = method_setImplementation(direct, replacement);
        } else if (!class_addMethod(cls, selector, replacement, types)) {
            return NO;
        }
        table[key] = [NSValue valueWithPointer:original];
        return YES;
    }
}

static void InstallPreferenceHooks(void) {
    if (![NSBundle.mainBundle.bundleIdentifier
            isEqualToString:@"com.apple.Preferences"]) {
        return;
    }
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
    HeightImplementations = [NSMutableDictionary dictionary];
    LayoutImplementations = [NSMutableDictionary dictionary];
    OrphanWindows = [NSHashTable weakObjectsHashTable];
    InstallWindowHooks();
    ApplyConfiguredAliases();
    [NSNotificationCenter.defaultCenter
        addObserverForName:NSBundleDidLoadNotification
                    object:nil
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(__unused NSNotification *notification) {
        ApplyConfiguredAliases();
        InstallPreferenceHooks();
    }];
    [NSNotificationCenter.defaultCenter
        addObserverForName:UISceneDidActivateNotification
                    object:nil
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(__unused NSNotification *notification) {
        RepairOrphanWindows();
    }];
    dispatch_async(dispatch_get_main_queue(), ^{
        InstallPreferenceHooks();
        RepairOrphanWindows();
    });
    os_log_with_type(CompatLog(), OS_LOG_TYPE_DEFAULT,
                     "iOS 27 legacy tweak compatibility ready");
}
