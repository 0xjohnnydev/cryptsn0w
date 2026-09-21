#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>

#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static NSString *const kBootProgressPath =
    @"/var/mobile/.sbinject-boot-progress.plist";
static const char *const kStockSpringBoard =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";

static UIWindow *gProgressWindow;
static UILabel *gStageLabel;
static UILabel *gPercentLabel;
static UIProgressView *gProgressView;

static bool is_stock_springboard(void) {
    uint32_t size = 0;
    (void)_NSGetExecutablePath(NULL, &size);
    char *path = calloc((size_t)size + 1U, 1U);
    if (path == NULL || _NSGetExecutablePath(path, &size) != 0) {
        free(path);
        return false;
    }
    char resolved[PATH_MAX] = {0};
    bool exact = realpath(path, resolved) != NULL &&
        strcmp(resolved, kStockSpringBoard) == 0;
    free(path);
    return exact;
}

static UIWindowScene *active_window_scene(void) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class] &&
            scene.activationState == UISceneActivationStateForegroundActive) {
            return (UIWindowScene *)scene;
        }
    }
    return nil;
}

static void create_progress_window(void) {
    if (gProgressWindow != nil) return;
    UIWindowScene *scene = active_window_scene();
    if (scene == nil) return;

    UIViewController *controller = [UIViewController new];
    controller.view.backgroundColor = UIColor.clearColor;

    UIBlurEffect *effect =
        [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemChromeMaterialDark];
    UIVisualEffectView *card =
        [[UIVisualEffectView alloc] initWithEffect:effect];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.layer.cornerRadius = 22.0;
    card.clipsToBounds = YES;
    [controller.view addSubview:card];

    UILabel *title = [UILabel new];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"Finishing startup";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont systemFontOfSize:20.0 weight:UIFontWeightSemibold];
    title.textAlignment = NSTextAlignmentCenter;

    gStageLabel = [UILabel new];
    gStageLabel.translatesAutoresizingMaskIntoConstraints = NO;
    gStageLabel.textColor = [UIColor colorWithWhite:1.0 alpha:0.78];
    gStageLabel.font = [UIFont systemFontOfSize:14.0 weight:UIFontWeightRegular];
    gStageLabel.textAlignment = NSTextAlignmentCenter;
    gStageLabel.numberOfLines = 2;

    gProgressView = [[UIProgressView alloc]
        initWithProgressViewStyle:UIProgressViewStyleDefault];
    gProgressView.translatesAutoresizingMaskIntoConstraints = NO;
    gProgressView.progressTintColor = UIColor.systemBlueColor;
    gProgressView.trackTintColor =
        [UIColor colorWithWhite:1.0 alpha:0.18];

    gPercentLabel = [UILabel new];
    gPercentLabel.translatesAutoresizingMaskIntoConstraints = NO;
    gPercentLabel.textColor = [UIColor colorWithWhite:1.0 alpha:0.62];
    gPercentLabel.font = [UIFont monospacedDigitSystemFontOfSize:12.0
                                                         weight:UIFontWeightMedium];
    gPercentLabel.textAlignment = NSTextAlignmentCenter;

    UIStackView *stack = [[UIStackView alloc]
        initWithArrangedSubviews:@[title, gStageLabel, gProgressView,
                                    gPercentLabel]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentFill;
    stack.spacing = 12.0;
    [card.contentView addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:controller.view.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:controller.view.centerYAnchor],
        [card.widthAnchor constraintEqualToConstant:310.0],
        [stack.leadingAnchor constraintEqualToAnchor:card.contentView.leadingAnchor
                                            constant:24.0],
        [stack.trailingAnchor constraintEqualToAnchor:card.contentView.trailingAnchor
                                             constant:-24.0],
        [stack.topAnchor constraintEqualToAnchor:card.contentView.topAnchor
                                         constant:24.0],
        [stack.bottomAnchor constraintEqualToAnchor:card.contentView.bottomAnchor
                                            constant:-22.0],
        [gProgressView.heightAnchor constraintEqualToConstant:4.0],
    ]];

    gProgressWindow = [[UIWindow alloc] initWithWindowScene:scene];
    gProgressWindow.frame = scene.coordinateSpace.bounds;
    gProgressWindow.windowLevel = UIWindowLevelAlert + 20.0;
    gProgressWindow.backgroundColor = UIColor.clearColor;
    gProgressWindow.userInteractionEnabled = NO;
    gProgressWindow.rootViewController = controller;
    gProgressWindow.hidden = NO;
}

static bool update_progress(void) {
    NSDictionary *state =
        [NSDictionary dictionaryWithContentsOfFile:kBootProgressPath];
    if (![state[@"Version"] isEqual:@1] ||
        [state[@"SpringBoardPID"] intValue] != getpid()) {
        return false;
    }
    create_progress_window();
    if (gProgressWindow == nil) return true;

    NSString *stage = state[@"Stage"];
    if (![stage isKindOfClass:NSString.class] || stage.length == 0 ||
        stage.length > 120U) {
        stage = @"Preparing services";
    }
    double value = [state[@"Progress"] doubleValue];
    value = fmax(0.0, fmin(1.0, value));
    gStageLabel.text = stage;
    gPercentLabel.text = [NSString stringWithFormat:@"%ld%%",
                                                    lround(value * 100.0)];
    [gProgressView setProgress:(float)value animated:YES];
    return true;
}

static void poll_progress(void) {
    if (!update_progress()) {
        if (gProgressWindow != nil) gProgressWindow.hidden = YES;
        gProgressWindow = nil;
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{
              poll_progress();
            });
        return;
    }
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
          poll_progress();
        });
}

__attribute__((constructor)) static void initialize_boot_progress(void) {
    if (!is_stock_springboard()) return;
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
          poll_progress();
        });
}
