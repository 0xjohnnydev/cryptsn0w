#import <UIKit/UIKit.h>

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

extern int csops(pid_t pid, unsigned int operation, void *userAddress,
                 size_t userSize);

@interface AppRegistrarProbeDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation AppRegistrarProbeDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    (void)application;
    (void)launchOptions;

    uint32_t codeSigningFlags = 0;
    int status = csops(getpid(), 0, &codeSigningFlags,
                       sizeof(codeSigningFlags));

    UIViewController *controller = [UIViewController new];
    controller.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *label = [UILabel new];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.font = [UIFont monospacedSystemFontOfSize:16.0
                                            weight:UIFontWeightRegular];
    label.text = [NSString
        stringWithFormat:@"appregistrard probe running\n"
                          "pid=%d csops=%d flags=0x%08x",
                         getpid(), status, codeSigningFlags];
    [controller.view addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.centerXAnchor constraintEqualToAnchor:controller.view.centerXAnchor],
        [label.centerYAnchor constraintEqualToAnchor:controller.view.centerYAnchor],
        [label.leadingAnchor constraintGreaterThanOrEqualToAnchor:controller.view.leadingAnchor
                                                            constant:24.0],
        [label.trailingAnchor constraintLessThanOrEqualToAnchor:controller.view.trailingAnchor
                                                           constant:-24.0],
    ]];

    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)application.connectedScenes.anyObject];
    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];

    fprintf(stderr,
            "appregistrarProbe phase=running pid=%d csops=%d flags=0x%08x\n",
            getpid(), status, codeSigningFlags);
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass(AppRegistrarProbeDelegate.class));
    }
}
