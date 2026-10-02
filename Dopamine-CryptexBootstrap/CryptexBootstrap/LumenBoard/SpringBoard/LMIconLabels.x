#import "../Shared/LMShared.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

@interface SBIconView : UIView
- (NSString *)location;
- (UIView *)labelView;
- (BOOL)isLabelHidden;
- (void)setLabelHidden:(BOOL)hidden;
- (void)_updateLabel;
@end

static BOOL LMHideIconLabels, LMIconLabelsInstalled, LMLabelUpdateInstalled, LMLabelSetterInstalled;
static NSHashTable *LMIconLabelViews;
static char LMOriginalLabelHiddenKey;

BOOL LMIconLabelRenderingIsReady(void) { return LMIconLabelsInstalled; }

static BOOL LMObjectGetter(Class cls, SEL selector) {
  Method method = class_getInstanceMethod(cls, selector);
  char result[16] = {0};
  if (method && method_getNumberOfArguments(method) == 2) method_getReturnType(method, result, sizeof(result));
  return result[0] == '@';
}

static BOOL LMObjectIvar(Class cls, const char *name) {
  Ivar ivar = class_getInstanceVariable(cls, name);
  const char *type = ivar ? ivar_getTypeEncoding(ivar) : NULL;
  return type && type[0] == '@';
}

static id LMIconLabelObject(UIView *icon, NSString *getterName, const char *ivarName) {
  Class cls = object_getClass(icon);
  SEL getter = NSSelectorFromString(getterName);
  if (LMObjectGetter(cls, getter)) {
    id value = ((id (*)(id, SEL))objc_msgSend)(icon, getter);
    if (value) return value;
  }
  return LMObjectIvar(cls, ivarName) ? object_getIvar(icon, class_getInstanceVariable(cls, ivarName)) : nil;
}

static BOOL LMHomeScreenIcon(UIView *icon) {
  id location = LMIconLabelObject(icon, @"location", "_iconLocation");
  if (![location isKindOfClass:[NSString class]]) return NO;
  return [location isEqual:@"SBIconLocationRoot"] || [location isEqual:@"SBIconLocationFolder"] || [location isEqual:@"SBIconLocationDock"] || [location isEqual:@"SBIconLocationFloatingDock"];
}

// Change only the visible label child. Keep the icon layout, native labelHidden
// state, icon artwork, and accessibility name intact, including in Small mode.
static void LMUpdateIconLabels(UIView *icon) {
  [LMIconLabelViews addObject:icon];
  id child = LMIconLabelObject(icon, @"labelView", "_labelView");
  if (![child isKindOfClass:[UIView class]] || child == icon || ![child isDescendantOfView:icon]) return;
  UIView *label = child;
  NSNumber *previous = objc_getAssociatedObject(label, &LMOriginalLabelHiddenKey);
  if (LMHideIconLabels && LMHomeScreenIcon(icon)) {
    if (!previous) objc_setAssociatedObject(label, &LMOriginalLabelHiddenKey, @(label.hidden), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    label.hidden = YES;
  } else if (previous) {
    // Respect the latest native visibility, such as Large icons or a drag,
    // rather than exposing a label that iOS deliberately keeps hidden.
    BOOL hidden = previous.boolValue;
    Method method = class_getInstanceMethod(object_getClass(icon), @selector(isLabelHidden));
    char result[16] = {0};
    if (method && method_getNumberOfArguments(method) == 2) method_getReturnType(method, result, sizeof(result));
    if (result[0] == 'B' || result[0] == 'c') hidden = ((BOOL (*)(id, SEL))objc_msgSend)(icon, @selector(isLabelHidden));
    label.hidden = hidden;
    objc_setAssociatedObject(label, &LMOriginalLabelHiddenKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  }
}

static void LMReloadIconLabelOptions(void) {
  NSDictionary *map = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
  NSDictionary *config = [map[LMMapAppliedConfig] isKindOfClass:[NSDictionary class]] ? map[LMMapAppliedConfig] : @{};
  LMHideIconLabels = [map[@"Version"] integerValue] == LMMapVersion && [config[LMConfigHideIconLabels] boolValue];
  for (UIView *icon in LMIconLabelViews.allObjects) {
    LMUpdateIconLabels(icon);
    [icon setNeedsLayout];
  }
}

static void LMIconLabelMapChanged(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
  dispatch_async(dispatch_get_main_queue(), ^{ LMReloadIconLabelOptions(); });
}

%group IconLabels
%hook SBIconView
- (void)layoutSubviews { %orig; LMUpdateIconLabels(self); }
- (void)didMoveToWindow { %orig; LMUpdateIconLabels(self); }
%end
%end

%group IconLabelUpdates
%hook SBIconView
- (void)_updateLabel { %orig; LMUpdateIconLabels(self); }
%end
%end

%group IconLabelVisibility
%hook SBIconView
- (void)setLabelHidden:(BOOL)hidden { %orig(hidden); LMUpdateIconLabels(self); }
%end
%end

static void LMInstallIconLabelHooks(void) {
  Class cls = objc_getClass("SBIconView");
  if (![cls isSubclassOfClass:[UIView class]]) return;
  BOOL hasLabel = LMObjectGetter(cls, @selector(labelView)) || LMObjectIvar(cls, "_labelView");
  BOOL hasLocation = LMObjectGetter(cls, @selector(location)) || LMObjectIvar(cls, "_iconLocation");
  if (!hasLabel || !hasLocation) return;
  if (!LMIconLabelsInstalled) { %init(IconLabels); LMIconLabelsInstalled = YES; }
  Method update = class_getInstanceMethod(cls, @selector(_updateLabel));
  char result[16] = {0};
  if (update && method_getNumberOfArguments(update) == 2) method_getReturnType(update, result, sizeof(result));
  if (!LMLabelUpdateInstalled && result[0] == 'v') { %init(IconLabelUpdates); LMLabelUpdateInstalled = YES; }
  Method setter = class_getInstanceMethod(cls, @selector(setLabelHidden:));
  char argument[16] = {0};
  result[0] = 0;
  if (setter && method_getNumberOfArguments(setter) == 3) {
    method_getArgumentType(setter, 2, argument, sizeof(argument));
    method_getReturnType(setter, result, sizeof(result));
  }
  if (!LMLabelSetterInstalled && (argument[0] == 'B' || argument[0] == 'c') && result[0] == 'v') { %init(IconLabelVisibility); LMLabelSetterInstalled = YES; }
}

static void LMIconLabelDidLoadImage(const struct mach_header *header, intptr_t slide) {
  Dl_info info = {0};
  if (!dladdr(header, &info) || !info.dli_fname) return;
  if ([[NSString stringWithUTF8String:info.dli_fname] containsString:@"SpringBoard"]) dispatch_async(dispatch_get_main_queue(), ^{ LMInstallIconLabelHooks(); });
}

%ctor {
  @autoreleasepool {
    if (![[NSBundle mainBundle].bundleIdentifier isEqual:@"com.apple.springboard"]) return;
    LMIconLabelViews = [NSHashTable weakObjectsHashTable];
    LMReloadIconLabelOptions();
    LMInstallIconLabelHooks();
    _dyld_register_func_for_add_image(LMIconLabelDidLoadImage);
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, LMIconLabelMapChanged, CFSTR(LMNotifyMapChanged), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
  }
}
