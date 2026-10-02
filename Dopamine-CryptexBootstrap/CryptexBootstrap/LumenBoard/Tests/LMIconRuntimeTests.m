#import "../Core/LMIconStore.h"
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <ImageIO/ImageIO.h>
#import <objc/runtime.h>

@interface NSObject (LMIconTestAPI)
- (instancetype)initWithBundleIdentifier:(NSString *)identifier;
- (instancetype)initWithSize:(CGSize)size scale:(double)scale;
- (id)imageForDescriptor:(id)descriptor;
- (void)getImageForImageDescriptor:(id)descriptor completion:(void (^)(id image))completion;
- (void)prepareImagesForImageDescriptors:(NSArray *)descriptors;
- (instancetype)initWithCGImage:(CGImageRef)image scale:(double)scale;
@end

#define CHECK(condition, message) do { if (!(condition)) { fprintf(stderr, "FAIL: %s\n", message); exit(1); } } while (0)

static id LMFixtureImage;
static id LMFixtureCachedImage(id self, SEL selector, id descriptor) { return LMFixtureImage; }

int main(void) {
  @autoreleasepool {
    CHECK(dlopen("/System/Library/PrivateFrameworks/IconServices.framework/IconServices", RTLD_NOW), "load native IconServices");
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:3];
    while (![LMIconStore sharedStore].canRenderIconsLocally && deadline.timeIntervalSinceNow > 0)
      [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    CHECK([LMIconStore sharedStore].canRenderIconsLocally, "install local image methods on native classes");
    id icon = [[NSClassFromString(@"ISIcon") alloc] initWithBundleIdentifier:@"com.apple.finder"];
    id descriptor = [[NSClassFromString(@"ISImageDescriptor") alloc] initWithSize:CGSizeMake(60, 60) scale:2];
    id image = [icon imageForDescriptor:descriptor];
    CHECK([[LMIconStore sharedStore] isLocallyRenderedImage:image], "native icon request returns locally rendered IFImage");
    CGImageRef cgImage = ((CGImageRef (*)(id, SEL, id))objc_msgSend)(icon, @selector(CGImageForDescriptor:), descriptor);
    CHECK(cgImage && CGImageGetWidth(cgImage) == 120 && CGImageGetHeight(cgImage) == 120, "native CGImage accessor consumes themed IFImage");
    __block BOOL answered = NO, themed = NO;
    [icon getImageForImageDescriptor:descriptor completion:^(id result) {
      themed = [[LMIconStore sharedStore] isLocallyRenderedImage:result];
      answered = YES;
    }];
    deadline = [NSDate dateWithTimeIntervalSinceNow:3];
    while (!answered && deadline.timeIntervalSinceNow > 0)
      [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    CHECK(answered && themed, "native asynchronous request uses locally rendered artwork");
    NSMutableDictionary *map = [[NSDictionary dictionaryWithContentsOfFile:LMIconMapPath] mutableCopy];
    map[LMMapIcons] = @{};
    map[LMMapIconEffects] = @{LMEffectOverlay: @{LMIconLight: [LMDataDirectory stringByAppendingPathComponent:@"overlay.png"], LMIconToken: @"native-overlay"}};
    CHECK([map writeToFile:LMIconMapPath atomically:YES], "prepare effects-only map");
    [[LMIconStore sharedStore] reload];
    icon = [[NSClassFromString(@"ISIcon") alloc] initWithBundleIdentifier:@"com.apple.finder"];
    [icon prepareImagesForImageDescriptors:@[descriptor]];
    image = [icon imageForDescriptor:descriptor];
    BOOL placeholder = [image respondsToSelector:@selector(placeholder)] && ((BOOL (*)(id, SEL))objc_msgSend)(image, @selector(placeholder));
    CHECK(!placeholder || ![[LMIconStore sharedStore] isLocallyRenderedImage:image], "stock placeholders are never acknowledged as decorated artwork");

    // The host service can return only placeholders in this command-line app.
    // Supply a known native IFImage through a test-only subclass's cache getter
    // to exercise the real client methods without relying on that service.
    CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:[LMDataDirectory stringByAppendingPathComponent:@"icon.png"]], NULL);
    CHECK(source, "load stock fixture source");
    CGImageRef pixels = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    CFRelease(source);
    CHECK(pixels, "decode stock fixture source");
    LMFixtureImage = [[NSClassFromString(@"IFImage") alloc] initWithCGImage:pixels scale:1];
    CGImageRelease(pixels);
    CHECK(LMFixtureImage, "create native stock fixture image");
    Class fixtureClass = objc_allocateClassPair(object_getClass(icon), "LMStockFixtureIcon", 0);
    CHECK(fixtureClass, "create test-only native icon subclass");
    CHECK(class_addMethod(fixtureClass, @selector(_cachedImageForDescriptor:), (IMP)LMFixtureCachedImage, "@@:@"), "supply native fixture cache");
    objc_registerClassPair(fixtureClass);
    icon = [[fixtureClass alloc] initWithBundleIdentifier:@"com.example.stock-fixture"];
    image = [icon imageForDescriptor:descriptor];
    CHECK([[LMIconStore sharedStore] isLocallyRenderedImage:image], "effect layers decorate stock fixture through native client methods");
    map[LMMapSkipped] = @{LMMapIcons: @[@"com.example.stock-fixture"]};
    CHECK([map writeToFile:LMIconMapPath atomically:YES], "prepare skipped app");
    [[LMIconStore sharedStore] reload];
    image = [icon imageForDescriptor:descriptor];
    CHECK(![[LMIconStore sharedStore] isLocallyRenderedImage:image], "accepted skipped apps keep stock artwork even with global effects");
    puts("PASS: native sync/async icon requests, fixture stock effects, and skipped app fallback");
  }
  return 0;
}
