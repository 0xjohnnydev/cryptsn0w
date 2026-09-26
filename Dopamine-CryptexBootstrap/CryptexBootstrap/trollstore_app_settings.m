#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#include "SBInject/sbinject_protocol.h"

#include <errno.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

static NSString *const kOptionKeys[] = {
    @"BlockExceptionPorts",
    @"KeychainIdentity",
    @"LegacySDK",
    @"TweakInjection",
};

static NSString *const kOptionNames[] = {
    @"Crashlytics workaround",
    @"Keychain compatibility",
    @"iOS 18.5 compatibility",
    @"Tweak injection",
};

static NSString *const kOptionDetails[] = {
    @"Stops Crashlytics from taking control of the app exception ports.",
    @"Gives the shared launcher a default keychain identity.",
    @"Uses pre-iOS-26 Foundation behavior for older apps.",
    @"Loads enabled jailbreak tweaks before this app starts.",
};

static const NSInteger kOptionCount =
    sizeof(kOptionKeys) / sizeof(kOptionKeys[0]);

static NSDictionary *managed_settings(void) {
    NSDictionary *settings = [NSDictionary dictionaryWithContentsOfFile:
        @CODEX_SBINJECT_MANAGED_APP_SETTINGS];
    return [settings isKindOfClass:NSDictionary.class] ? settings : @{};
}

static BOOL option_enabled(NSString *bundleIdentifier, NSString *key) {
    NSDictionary *entry = managed_settings()[bundleIdentifier];
    NSNumber *value = [entry isKindOfClass:NSDictionary.class]
        ? entry[key] : nil;
    BOOL defaultValue = ![key isEqualToString:@"TweakInjection"];
    return [value isKindOfClass:NSNumber.class]
        ? value.boolValue : defaultValue;
}

@interface CodexManagedAppSettingsController : UITableViewController
@property(nonatomic, copy) NSString *bundleIdentifier;
@property(nonatomic, copy) NSString *displayName;
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier
                              displayName:(NSString *)displayName;
@end

@implementation CodexManagedAppSettingsController

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier
                              displayName:(NSString *)displayName {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self != nil) {
        _bundleIdentifier = [bundleIdentifier copy];
        _displayName = [displayName copy];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = self.displayName.length != 0
        ? self.displayName : @"App Compatibility";
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    (void)tableView;
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView
 numberOfRowsInSection:(NSInteger)section {
    (void)tableView;
    (void)section;
    return kOptionCount;
}

- (NSString *)tableView:(UITableView *)tableView
 titleForHeaderInSection:(NSInteger)section {
    (void)tableView;
    (void)section;
    return @"Compatibility";
}

- (NSString *)tableView:(UITableView *)tableView
 titleForFooterInSection:(NSInteger)section {
    (void)tableView;
    (void)section;
    return @"Changes apply the next time you open this app.";
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *const reuse = @"CodexManagedAppOption";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if (cell == nil) {
        cell = [[UITableViewCell alloc]
            initWithStyle:UITableViewCellStyleSubtitle
            reuseIdentifier:reuse];
    }
    NSInteger row = indexPath.row;
    cell.textLabel.text = kOptionNames[row];
    cell.detailTextLabel.text = kOptionDetails[row];
    cell.detailTextLabel.numberOfLines = 0;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    UISwitch *toggle = [[UISwitch alloc] initWithFrame:CGRectZero];
    toggle.tag = row;
    toggle.on = option_enabled(self.bundleIdentifier, kOptionKeys[row]);
    [toggle addTarget:self action:@selector(optionChanged:)
      forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
    return cell;
}

- (void)optionChanged:(UISwitch *)toggle {
    NSInteger row = toggle.tag;
    if (row < 0 || row >= kOptionCount) return;
    BOOL requested = toggle.on;
    toggle.enabled = NO;
    NSString *bundleIdentifier = self.bundleIdentifier;
    NSString *key = kOptionKeys[row];
    NSString *helper = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"trollstorehelper"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        const char *arguments[] = {
            helper.fileSystemRepresentation,
            "sbinject-settings",
            bundleIdentifier.UTF8String,
            key.UTF8String,
            requested ? "1" : "0",
            NULL,
        };
        pid_t child = -1;
        int spawnStatus = posix_spawn(
            &child, arguments[0], NULL, NULL, (char *const *)arguments,
            environ);
        int waitStatus = 0;
        if (spawnStatus == 0) {
            while (waitpid(child, &waitStatus, 0) < 0 && errno == EINTR) {}
        }
        BOOL success = spawnStatus == 0 && WIFEXITED(waitStatus) &&
            WEXITSTATUS(waitStatus) == 0;
        dispatch_async(dispatch_get_main_queue(), ^{
            toggle.enabled = YES;
            if (!success) {
                toggle.on = !requested;
                UIAlertController *alert = [UIAlertController
                    alertControllerWithTitle:@"Could Not Save Setting"
                    message:@"TrollStore Lite could not update this app."
                    preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction
                    actionWithTitle:@"OK" style:UIAlertActionStyleDefault
                    handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
            }
        });
    });
}

@end

typedef void (*did_select_function)(id, SEL, UITableView *, NSIndexPath *);
typedef void (*present_function)(id, SEL, UIViewController *, BOOL,
                                 void (^)(void));

static did_select_function gOriginalDidSelect;
static present_function gOriginalPresent;
static NSString *gSelectedBundleIdentifier;
static NSString *gSelectedDisplayName;
static __weak UIViewController *gSelectedController;

static NSString *string_property(id object, const char *selectorName) {
    SEL selector = sel_registerName(selectorName);
    if (object == nil || ![object respondsToSelector:selector]) return nil;
    NSString *(*implementation)(id, SEL) =
        (NSString *(*)(id, SEL))[object methodForSelector:selector];
    id value = implementation(object, selector);
    return [value isKindOfClass:NSString.class] ? value : nil;
}

static void hooked_did_select(id object, SEL selector, UITableView *tableView,
                              NSIndexPath *indexPath) {
    Ivar appsIvar = class_getInstanceVariable([object class],
                                              "_cachedAppInfos");
    NSArray *apps = appsIvar != NULL ? object_getIvar(object, appsIvar) : nil;
    id appInfo = indexPath.row >= 0 && indexPath.row < (NSInteger)apps.count
        ? apps[(NSUInteger)indexPath.row] : nil;
    gSelectedBundleIdentifier = [string_property(
        appInfo, "bundleIdentifier") copy];
    gSelectedDisplayName = [string_property(appInfo, "displayName") copy];
    gSelectedController = object;
    gOriginalDidSelect(object, selector, tableView, indexPath);
    gSelectedBundleIdentifier = nil;
    gSelectedDisplayName = nil;
    gSelectedController = nil;
}

static void hooked_present(id object, SEL selector,
                           UIViewController *viewController, BOOL animated,
                           void (^completion)(void)) {
    UIAlertController *alert =
        [viewController isKindOfClass:UIAlertController.class]
            ? (UIAlertController *)viewController : nil;
    NSString *bundleIdentifier = gSelectedBundleIdentifier;
    NSString *displayName = gSelectedDisplayName;
    UIViewController *source = gSelectedController;
    if (alert.preferredStyle == UIAlertControllerStyleActionSheet &&
        bundleIdentifier.length != 0 &&
        [alert.message isEqualToString:bundleIdentifier]) {
        [alert addAction:[UIAlertAction
            actionWithTitle:@"Compatibility Settings"
            style:UIAlertActionStyleDefault
            handler:^(__unused UIAlertAction *action) {
                CodexManagedAppSettingsController *settings =
                    [[CodexManagedAppSettingsController alloc]
                        initWithBundleIdentifier:bundleIdentifier
                        displayName:displayName];
                if (source.navigationController != nil) {
                    [source.navigationController pushViewController:settings
                                                            animated:YES];
                } else {
                    UINavigationController *navigation =
                        [[UINavigationController alloc]
                            initWithRootViewController:settings];
                    [source presentViewController:navigation animated:YES
                                       completion:nil];
                }
            }]];
    }
    gOriginalPresent(object, selector, viewController, animated, completion);
}

bool codex_install_trollstore_settings_hook(void) {
    static dispatch_once_t once;
    static bool ready;
    dispatch_once(&once, ^{
        Class tableClass = objc_getClass("TSAppTableViewController");
        Class presentationClass = objc_getClass("TSPresentationDelegate");
        SEL didSelect = @selector(tableView:didSelectRowAtIndexPath:);
        SEL present = @selector(presentViewController:animated:completion:);
        Method didSelectMethod = class_getInstanceMethod(tableClass, didSelect);
        Method presentMethod = class_getClassMethod(presentationClass, present);
        if (didSelectMethod == NULL || presentMethod == NULL) return;
        gOriginalDidSelect = (did_select_function)(void *)
            method_setImplementation(didSelectMethod,
                                     (IMP)(void *)&hooked_did_select);
        gOriginalPresent = (present_function)(void *)
            method_setImplementation(presentMethod,
                                     (IMP)(void *)&hooked_present);
        ready = gOriginalDidSelect != NULL && gOriginalPresent != NULL;
    });
    return ready;
}
