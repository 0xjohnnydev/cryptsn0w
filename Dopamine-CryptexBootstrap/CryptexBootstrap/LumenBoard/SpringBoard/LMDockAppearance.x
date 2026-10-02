#import "../Shared/LMShared.h"
#import "../Shared/LMHomeScreenOptions.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

@interface SBDockView : UIView
- (void)setBackgroundAlpha:(CGFloat)alpha;
@end

@interface SBFloatingDockPlatterView : UIView
@end

static BOOL LMHideDockBackground;
static BOOL LMNormalDockInstalled, LMNormalDockAlphaInstalled, LMFloatingDockInstalled;
static _Thread_local BOOL LMUpdatingDockAlpha;
static NSHashTable *LMDockViews;
static char LMDockOriginalHiddenKey, LMDockRequestedAlphaKey;

BOOL LMDockBackgroundRenderingIsReady(void) { return LMNormalDockInstalled || LMFloatingDockInstalled; }

// Read only the named background child; never change the dock container.
static UIView *LMBackgroundOfDock(UIView *dock) {
  UIView *background = nil;
  SEL getter = NSSelectorFromString(@"backgroundView");
  Method method = class_getInstanceMethod(object_getClass(dock), getter);
  char type[16] = {0};
  if (method && method_getNumberOfArguments(method) == 2) {
    method_getReturnType(method, type, sizeof(type));
    if (type[0] == '@') {
      id candidate = ((id (*)(id, SEL))objc_msgSend)(dock, getter);
      if ([candidate isKindOfClass:[UIView class]]) background = candidate;
    }
  }
  if (!background) {
    Ivar ivar = class_getInstanceVariable(object_getClass(dock), "_backgroundView");
    const char *encoding = ivar ? ivar_getTypeEncoding(ivar) : NULL;
    if (encoding && encoding[0] == '@') {
      id candidate = object_getIvar(dock, ivar);
      if ([candidate isKindOfClass:[UIView class]]) background = candidate;
    }
  }
  return background != dock && [background isDescendantOfView:dock] ? background : nil;
}

static void LMUpdateDockBackground(UIView *dock) {
  [LMDockViews addObject:dock];
  UIView *background = LMBackgroundOfDock(dock);
  NSNumber *previous = objc_getAssociatedObject(background, &LMDockOriginalHiddenKey);
  if (LMHideDockBackground && background) {
    if (!previous) objc_setAssociatedObject(background, &LMDockOriginalHiddenKey, @(background.hidden), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    background.hidden = YES;
  } else if (previous) {
    background.hidden = previous.boolValue;
    objc_setAssociatedObject(background, &LMDockOriginalHiddenKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  }
  Class normalDock = objc_getClass("SBDockView");
  if (LMNormalDockAlphaInstalled && [dock isKindOfClass:normalDock]) {
    NSNumber *requested = objc_getAssociatedObject(dock, &LMDockRequestedAlphaKey);
    if (LMHideDockBackground || requested) {
      LMUpdatingDockAlpha = YES;
      @try {
        ((void (*)(id, SEL, CGFloat))objc_msgSend)(dock, @selector(setBackgroundAlpha:), requested ? requested.doubleValue : 1.0);
      } @finally { LMUpdatingDockAlpha = NO; }
    }
  }
}

static void LMReloadDockOptions(void) {
  NSDictionary *map = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
  NSDictionary *config = [map[LMMapAppliedConfig] isKindOfClass:[NSDictionary class]] ? map[LMMapAppliedConfig] : @{};
  LMHideDockBackground = [map[@"Version"] integerValue] == LMMapVersion && [config[LMConfigHideDockBackground] boolValue];
  NSNumber *override = [LMHomeScreenOptions appliedDockBackground];
  if (override) LMHideDockBackground = override.boolValue;
  for (UIView *dock in LMDockViews.allObjects) {
    LMUpdateDockBackground(dock);
    [dock setNeedsLayout];
  }
}

static void LMDockMapChanged(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
  dispatch_async(dispatch_get_main_queue(), ^{ LMReloadDockOptions(); });
}

%group DockAlpha
%hook SBDockView
- (void)setBackgroundAlpha:(CGFloat)alpha {
  if (!LMUpdatingDockAlpha) objc_setAssociatedObject(self, &LMDockRequestedAlphaKey, @(alpha), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  %orig(LMHideDockBackground ? 0 : alpha);
}
%end
%end

%group NormalDockBackground
%hook SBDockView
- (void)layoutSubviews { %orig; LMUpdateDockBackground(self); }
- (void)didMoveToWindow { %orig; LMUpdateDockBackground(self); }
%end
%end

%group FloatingDockBackground
%hook SBFloatingDockPlatterView
- (void)layoutSubviews { %orig; LMUpdateDockBackground(self); }
- (void)didMoveToWindow { %orig; LMUpdateDockBackground(self); }
%end
%end

static BOOL LMHasDockBackground(Class cls) {
  Ivar ivar = class_getInstanceVariable(cls, "_backgroundView");
  const char *type = ivar ? ivar_getTypeEncoding(ivar) : NULL;
  Method getter = class_getInstanceMethod(cls, NSSelectorFromString(@"backgroundView"));
  char result[16] = {0};
  if (getter && method_getNumberOfArguments(getter) == 2) method_getReturnType(getter, result, sizeof(result));
  return (type && type[0] == '@') || result[0] == '@';
}

static void LMInstallDockHooks(void) {
  Class normal = objc_getClass("SBDockView");
  Method setter = class_getInstanceMethod(normal, @selector(setBackgroundAlpha:));
  char argument[16] = {0}, result[16] = {0};
  if (setter && method_getNumberOfArguments(setter) == 3) {
    method_getArgumentType(setter, 2, argument, sizeof(argument));
    method_getReturnType(setter, result, sizeof(result));
  }
  if (!LMNormalDockAlphaInstalled && [normal isSubclassOfClass:[UIView class]] && argument[0] == 'd' && result[0] == 'v') {
    %init(DockAlpha);
    LMNormalDockAlphaInstalled = YES;
  }
  if (!LMNormalDockInstalled && [normal isSubclassOfClass:[UIView class]] && (LMNormalDockAlphaInstalled || LMHasDockBackground(normal))) {
    %init(NormalDockBackground);
    LMNormalDockInstalled = YES;
  }
  Class floating = objc_getClass("SBFloatingDockPlatterView");
  if (!LMFloatingDockInstalled && [floating isSubclassOfClass:[UIView class]] && LMHasDockBackground(floating)) {
    %init(FloatingDockBackground);
    LMFloatingDockInstalled = YES;
  }
}

static void LMDockDidLoadImage(const struct mach_header *header, intptr_t slide) {
  Dl_info info = {0};
  if (!dladdr(header, &info) || !info.dli_fname) return;
  NSString *name = [NSString stringWithUTF8String:info.dli_fname];
  if ([name containsString:@"SpringBoard"]) dispatch_async(dispatch_get_main_queue(), ^{ LMInstallDockHooks(); });
}

%ctor {
  @autoreleasepool {
    if (![[NSBundle mainBundle].bundleIdentifier isEqual:@"com.apple.springboard"]) return;
    LMDockViews = [NSHashTable weakObjectsHashTable];
    LMReloadDockOptions();
    LMInstallDockHooks();
    _dyld_register_func_for_add_image(LMDockDidLoadImage);
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, LMDockMapChanged, CFSTR(LMNotifyMapChanged), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, LMDockMapChanged, CFSTR(LMNotifyDockChanged), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
  }
}
