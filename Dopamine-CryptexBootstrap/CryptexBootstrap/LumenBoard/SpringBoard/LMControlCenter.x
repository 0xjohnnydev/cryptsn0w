#import "../Shared/LMCCResources.h"
#import <UIKit/UIKit.h>
#import <ImageIO/ImageIO.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

static NSCache *LMCCImages;
static BOOL LMCCReady;
static _Thread_local BOOL LMCCLoadingImage;
BOOL LMControlCenterRenderingIsReady(void) { return LMCCReady; }

static id LMCCStore(void) {
  Class cls = objc_getClass("LMIconStore");
  return [cls respondsToSelector:@selector(sharedStore)] ? ((id (*)(Class, SEL))objc_msgSend)(cls, @selector(sharedStore)) : nil;
}

static UIImage *LMCCImage(NSArray<NSString *> *keys, UITraitCollection *traits) {
  if (LMCCLoadingImage) return nil;
  id store = LMCCStore();
  if (![store respondsToSelector:@selector(resourceForKey:)]) return nil;
  NSDictionary *entry = nil;
  for (NSString *key in keys) {
    entry = ((id (*)(id, SEL, id))objc_msgSend)(store, @selector(resourceForKey:), key);
    if (entry) break;
  }
  NSString *path = traits.userInterfaceStyle == UIUserInterfaceStyleDark ? entry[LMIconDark] : nil;
  path = path ?: entry[LMIconLight];
  NSString *token = entry[LMIconToken];
  if (!path.length || !token.length) return nil;
  NSArray *key = @[path, token];
  UIImage *cached = [LMCCImages objectForKey:key];
  if (cached) return cached;
  LMCCLoadingImage = YES;
  CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:path], NULL);
  CGImageRef pixels = source && CGImageSourceGetCount(source) ? CGImageSourceCreateImageAtIndex(source, 0, NULL) : NULL;
  if (source) CFRelease(source);
  UIImage *image = nil;
  if (pixels) {
    CGFloat scale = [path.lowercaseString containsString:@"@3x"] ? 3 : ([path.lowercaseString containsString:@"@2x"] ? 2 : 1);
    image = [UIImage imageWithCGImage:pixels scale:scale orientation:UIImageOrientationUp];
    if (image) [LMCCImages setObject:image forKey:key cost:CGImageGetWidth(pixels) * CGImageGetHeight(pixels) * 4];
    CGImageRelease(pixels);
  }
  LMCCLoadingImage = NO;
  return image;
}

// Shared UIImages and SF Symbol aliases are limited to CC/media callers.
// A bundle's explicitly named resource uses its own bundle identifier.
static NSBundle *LMCCCallerBundle(void *address, BOOL *controlCenter) {
  Dl_info info = {0};
  NSString *path = dladdr(address, &info) && info.dli_fname ? [NSString stringWithUTF8String:info.dli_fname] : @"";
  NSString *lower = path.lowercaseString;
  *controlCenter = [lower containsString:@"/controlcenter"] || [lower containsString:@"/mediacontrols"] || [lower containsString:@"/bigsurcenter"] || [lower containsString:@"/prysm"];
  NSString *directory = path.stringByDeletingLastPathComponent;
  while (directory.length > 1) {
    if ([@[@"bundle", @"framework"] containsObject:directory.pathExtension.lowercaseString]) return [NSBundle bundleWithPath:directory];
    directory = directory.stringByDeletingLastPathComponent;
  }
  return nil;
}

static UIImage *LMCCNamedImage(NSString *name, NSBundle *bundle, UITraitCollection *traits, UIImage *original, void *caller) {
  BOOL cc = NO;
  NSBundle *callerBundle = LMCCCallerBundle(caller, &cc);
  NSBundle *resourceBundle = bundle ?: callerBundle;
  NSString *identifier = resourceBundle.bundleIdentifier;
  cc |= [LMCCResources isControlCenterBundle:identifier];
  NSString *folder = resourceBundle.bundleURL.lastPathComponent.stringByDeletingPathExtension;
  UIImage *image = LMCCImage([LMCCResources keysForName:name bundle:identifier folder:folder shared:cc], traits);
  return image ? [image imageWithRenderingMode:original ? original.renderingMode : UIImageRenderingModeAlwaysTemplate] : nil;
}

static UIImage *LMCCSymbolImage(NSString *name, UITraitCollection *traits, UIImage *original, void *caller) {
  BOOL cc = NO;
  LMCCCallerBundle(caller, &cc);
  if (!cc) return nil;
  UIImage *image = LMCCImage([LMCCResources keysForSymbol:name], traits);
  if (!image) return nil;
  if (original.size.width > 0 && original.size.height > 0) {
    CGSize size = original.size;
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:size];
    image = [renderer imageWithActions:^(UIGraphicsImageRendererContext *context) {
      CGFloat ratio = MIN(size.width / image.size.width, size.height / image.size.height);
      CGSize fitted = CGSizeMake(image.size.width * ratio, image.size.height * ratio);
      [image drawInRect:CGRectMake((size.width - fitted.width) / 2, (size.height - fitted.height) / 2, fitted.width, fitted.height)];
    }];
  }
  return [image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}

%group CCArtwork
%hook UIImage
+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
  UIImage *original = %orig;
  BOOL cc = NO;
  NSBundle *bundle = LMCCCallerBundle(__builtin_return_address(0), &cc);
  if (!cc) return original;
  NSMutableArray *keys = [[LMCCResources keysForName:path.lastPathComponent bundle:bundle.bundleIdentifier folder:nil shared:YES] mutableCopy];
  NSArray *components = path.pathComponents;
  // Folder themes can mirror nested resources, e.g. Prysm/blackIcons/wifi.png.
  for (NSUInteger index = components.count > 6 ? components.count - 6 : 0; index + 1 < components.count; index++) {
    NSString *name = [[components subarrayWithRange:NSMakeRange(index + 1, components.count - index - 1)] componentsJoinedByString:@"/"];
    [keys addObjectsFromArray:[LMCCResources keysForName:name bundle:nil folder:components[index] shared:YES]];
  }
  UIImage *image = LMCCImage(keys, [UITraitCollection currentTraitCollection]);
  return image ? [image imageWithRenderingMode:original ? original.renderingMode : UIImageRenderingModeAlwaysTemplate] : original;
}
+ (UIImage *)imageNamed:(NSString *)name {
  UIImage *original = %orig;
  return LMCCNamedImage(name, nil, [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traits {
  UIImage *original = %orig;
  return LMCCNamedImage(name, bundle, traits ?: [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle withConfiguration:(UIImageConfiguration *)configuration {
  UIImage *original = %orig;
  return LMCCNamedImage(name, bundle, configuration.traitCollection ?: [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle variableValue:(double)value withConfiguration:(UIImageConfiguration *)configuration {
  UIImage *original = %orig;
  return LMCCNamedImage(name, bundle, configuration.traitCollection ?: [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
+ (UIImage *)systemImageNamed:(NSString *)name {
  UIImage *original = %orig;
  return LMCCSymbolImage(name, [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
+ (UIImage *)systemImageNamed:(NSString *)name withConfiguration:(UIImageConfiguration *)configuration {
  UIImage *original = %orig;
  return LMCCSymbolImage(name, configuration.traitCollection ?: [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
+ (UIImage *)systemImageNamed:(NSString *)name compatibleWithTraitCollection:(UITraitCollection *)traits {
  UIImage *original = %orig;
  return LMCCSymbolImage(name, traits ?: [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
+ (UIImage *)systemImageNamed:(NSString *)name variableValue:(double)value withConfiguration:(UIImageConfiguration *)configuration {
  UIImage *original = %orig;
  return LMCCSymbolImage(name, configuration.traitCollection ?: [UITraitCollection currentTraitCollection], original, __builtin_return_address(0)) ?: original;
}
%end
%end

// Modules that expose CCUIToggleModule's image/package API can use a PNG in
// place of a vector glyph. Do not suppress a package without valid artwork.
static NSLock *LMModuleLock;
static NSMutableDictionary *LMModuleBindings;
static NSDictionary *LMModuleBinding(id module, SEL selector) {
  [LMModuleLock lock];
  NSDictionary *binding = nil;
  for (Class cls = object_getClass(module); cls && !binding; cls = class_getSuperclass(cls))
    binding = LMModuleBindings[[NSString stringWithFormat:@"%@/%@", NSStringFromClass(cls), NSStringFromSelector(selector)]];
  [LMModuleLock unlock];
  return binding;
}

static UIImage *LMModuleImage(NSString *identifier, BOOL selected) {
  for (NSString *name in [LMCCResources glyphNamesForBundle:identifier selected:selected]) {
    UIImage *image = LMCCImage([LMCCResources keysForName:name bundle:identifier folder:nil shared:NO], [UITraitCollection currentTraitCollection]);
    if (image) return [image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
  }
  return nil;
}

static id LMModuleGlyph(id self, SEL selector) {
  NSDictionary *binding = LMModuleBinding(self, selector);
  UIImage *image = LMModuleImage(binding[@"Bundle"], selector == @selector(selectedIconGlyph));
  if (image) return image;
  IMP original = [binding[@"Original"] pointerValue];
  return original ? ((id (*)(id, SEL))original)(self, selector) : nil;
}

static id LMModulePackage(id self, SEL selector) {
  NSDictionary *binding = LMModuleBinding(self, selector);
  if (LMModuleImage(binding[@"Bundle"], NO) && LMModuleImage(binding[@"Bundle"], YES)) return nil;
  IMP original = [binding[@"Original"] pointerValue];
  return original ? ((id (*)(id, SEL))original)(self, selector) : nil;
}

static void LMInstallModuleGlyphHooks(void) {
  Class base = objc_getClass("CCUIToggleModule");
  if (!base) return;
  for (NSBundle *bundle in [NSBundle allBundles]) {
    if (![LMCCResources isControlCenterBundle:bundle.bundleIdentifier]) continue;
    Class cls = bundle.principalClass;
    if (!cls || ![cls isSubclassOfClass:base]) continue;
    // Shared launcher classes belong to the framework, not one module bundle.
    if (![[NSBundle bundleForClass:cls].bundleIdentifier isEqual:bundle.bundleIdentifier]) continue;
    for (NSString *name in @[@"iconGlyph", @"selectedIconGlyph", @"glyphPackageDescription", @"glyphPackage"]) {
      SEL selector = NSSelectorFromString(name);
      Method method = class_getInstanceMethod(cls, selector);
      char type[16] = {0};
      if (!method || method_getNumberOfArguments(method) != 2) continue;
      method_getReturnType(method, type, sizeof(type));
      if (type[0] != '@') continue;
      NSString *key = [NSString stringWithFormat:@"%@/%@", NSStringFromClass(cls), name];
      [LMModuleLock lock];
      if (!LMModuleBindings[key]) {
        IMP original = method_getImplementation(method);
        LMModuleBindings[key] = @{@"Bundle": bundle.bundleIdentifier, @"Original": [NSValue valueWithPointer:original]};
        IMP replacement = [name containsString:@"Package"] ? (IMP)LMModulePackage : (IMP)LMModuleGlyph;
        if (!class_addMethod(cls, selector, replacement, method_getTypeEncoding(method))) class_replaceMethod(cls, selector, replacement, method_getTypeEncoding(method));
      }
      [LMModuleLock unlock];
    }
  }
}

static void LMCCDidLoadImage(const struct mach_header *header, intptr_t slide) {
  Dl_info info = {0};
  if (!dladdr(header, &info) || !info.dli_fname) return;
  NSString *name = [[NSString stringWithUTF8String:info.dli_fname] lowercaseString];
  if (![name containsString:@"controlcenter"]) return;
  dispatch_async(dispatch_get_main_queue(), ^{ LMInstallModuleGlyphHooks(); });
}

%ctor {
  @autoreleasepool {
    if (![[NSBundle mainBundle].bundleIdentifier isEqual:@"com.apple.springboard"]) return;
    LMCCImages = [NSCache new];
    LMCCImages.countLimit = 200;
    LMCCImages.totalCostLimit = 16 * 1024 * 1024;
    LMModuleLock = [NSLock new];
    LMModuleBindings = [NSMutableDictionary new];
    %init(CCArtwork);
    LMCCReady = YES;
    _dyld_register_func_for_add_image(LMCCDidLoadImage);
    LMInstallModuleGlyphHooks();
  }
}
