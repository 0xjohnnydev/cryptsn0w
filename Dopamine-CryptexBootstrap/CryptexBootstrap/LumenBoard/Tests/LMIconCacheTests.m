#import "../Core/LMIconArtwork.h"
#import "../Shared/LMIconMapWriter.h"
#import <ImageIO/ImageIO.h>

#define CHECK(condition, message) do { if (!(condition)) { fprintf(stderr, "FAIL: %s (line %d)\n", message, __LINE__); exit(1); } } while (0)

static void WritePNG(NSString *path, CGFloat red, CGFloat green, CGFloat blue) {
  CGColorSpaceRef colors = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
  CGContextRef context = CGBitmapContextCreate(NULL, 8, 8, 8, 0, colors, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
  CGColorSpaceRelease(colors);
  CHECK(context, "create fixture bitmap");
  CGContextSetRGBFillColor(context, red, green, blue, 1);
  CGContextFillRect(context, CGRectMake(0, 0, 8, 8));
  CGImageRef image = CGBitmapContextCreateImage(context);
  CGContextRelease(context);
  CGImageDestinationRef destination = CGImageDestinationCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:path], CFSTR("public.png"), 1, NULL);
  CHECK(destination, "create fixture PNG");
  CGImageDestinationAddImage(destination, image, NULL);
  CHECK(CGImageDestinationFinalize(destination), "write fixture PNG");
  CFRelease(destination);
  CGImageRelease(image);
}

static void Pixel(CGImageRef image, size_t x, size_t y, unsigned char rgba[4]) {
  CGColorSpaceRef colors = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
  CGContextRef context = CGBitmapContextCreate(rgba, 1, 1, 8, 4, colors, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
  CGColorSpaceRelease(colors);
  CGContextSetBlendMode(context, kCGBlendModeCopy);
  CGContextDrawImage(context, CGRectMake(-(CGFloat)x, -(CGFloat)y, CGImageGetWidth(image), CGImageGetHeight(image)), image);
  CGContextRelease(context);
}

static void WriteLayerPNG(NSString *path, BOOL ellipse, CGFloat red, CGFloat green, CGFloat blue, CGRect rect) {
  CGColorSpaceRef colors = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
  CGContextRef context = CGBitmapContextCreate(NULL, 8, 8, 8, 0, colors, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
  CGColorSpaceRelease(colors);
  CHECK(context, "create layer bitmap");
  CGContextSetRGBFillColor(context, red, green, blue, 1);
  if (ellipse) CGContextFillEllipseInRect(context, rect);
  else CGContextFillRect(context, rect);
  CGImageRef image = CGBitmapContextCreateImage(context);
  CGContextRelease(context);
  CGImageDestinationRef destination = CGImageDestinationCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:path], CFSTR("public.png"), 1, NULL);
  CHECK(destination, "create layer PNG");
  CGImageDestinationAddImage(destination, image, NULL);
  CHECK(CGImageDestinationFinalize(destination), "write layer PNG");
  CFRelease(destination);
  CGImageRelease(image);
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    CHECK(argc == 2, "supply scratch directory");
    NSString *root = [NSString stringWithUTF8String:argv[1]];
    NSString *png = [root stringByAppendingPathComponent:@"icon.png"];
    NSString *dark = [root stringByAppendingPathComponent:@"dark.png"];
    NSString *mapPath = [root stringByAppendingPathComponent:@"IconMap.plist"];
    WritePNG(png, 1, 0, 0);
    WritePNG(dark, 0, 1, 0);
    NSDictionary *config = @{LMConfigEnabledThemes: @[@"Test.theme"], LMConfigUseSystemIconShape: @NO, LMConfigKeepIconsInDarkAndTinted: @NO};
    NSDictionary *icons = @{@"com.apple.finder": @{LMIconLight: png, LMIconDark: dark}};
    NSError *error = nil;
    CHECK([LMIconMapWriter writeConfig:config icons:icons toPath:mapPath forceGeneration:NO error:&error] == LMIconMapWritten, "prepare map");
    NSDictionary *first = [NSDictionary dictionaryWithContentsOfFile:mapPath];
    CHECK(![first[LMMapApplied] boolValue], "preparing is not applying");
    CHECK([LMIconMapWriter writeConfig:config icons:icons toPath:mapPath forceGeneration:NO error:&error] == LMIconMapUnchanged, "boot preserves an unchanged generation");
    CHECK([LMIconMapWriter markGenerationApplied:first[@"Generation"] atPath:mapPath error:&error], "commit a rendered map");
    CHECK([[NSDictionary dictionaryWithContentsOfFile:mapPath][LMMapApplied] boolValue], "completion persists");

    LMIconArtwork *cache = [LMIconArtwork new];
    NSDictionary *entry = first[LMMapIcons][@"com.apple.finder"];
    CGImageRef red = [cache copyImageForEntry:entry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO];
    CHECK(red && CGImageGetWidth(red) == 120 && CGImageGetHeight(red) == 120, "render at descriptor pixel size");
    unsigned char pixel[4] = {0};
    Pixel(red, 60, 60, pixel);
    CHECK(pixel[0] > 240 && pixel[2] < 10, "render fixture artwork");
    CGImageRelease(red);

    CHECK([LMIconMapWriter writeConfig:config icons:icons toPath:mapPath forceGeneration:YES error:&error] == LMIconMapWritten, "unchanged Apply still writes a new generation");
    NSDictionary *retry = [NSDictionary dictionaryWithContentsOfFile:mapPath];
    CHECK(![first[@"Generation"] isEqual:retry[@"Generation"]], "retry rotates generation");
    CHECK(![entry[LMIconToken] isEqual:retry[LMMapIcons][@"com.apple.finder"][LMIconToken]], "retry rotates icon cache key");
    CHECK(![retry[LMMapApplied] boolValue], "retry stays pending until rendering");
    CHECK(![LMIconMapWriter markGenerationApplied:first[@"Generation"] atPath:mapPath error:&error], "stale render cannot acknowledge a newer map");

    // Replace the pixels without changing the path while the first image is cached.
    WritePNG(png, 0, 0, 1);
    NSDictionary *retryEntry = retry[LMMapIcons][@"com.apple.finder"];
    CGImageRef blue = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO];
    CHECK(blue, "decode a replacement PNG at the same path");
    Pixel(blue, 60, 60, pixel);
    CHECK(pixel[2] > 240 && pixel[0] < 10, "new token never returns old decoded pixels");
    CGImageRelease(blue);

    CGImageRef green = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:1 applyMask:NO];
    Pixel(green, 60, 60, pixel);
    CHECK(pixel[1] > 240 && pixel[2] < 10, "dark variant has a separate cache entry");
    CGImageRelease(green);
    CGImageRef lightAgain = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO];
    Pixel(lightAgain, 60, 60, pixel);
    CHECK(pixel[2] > 240 && pixel[1] < 10, "returning to light doesn't reuse dark artwork");
    CGImageRelease(lightAgain);

    CGImageRef masked = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:YES];
    Pixel(masked, 0, 0, pixel);
    CHECK(pixel[3] == 0, "mask isn't shared with unmasked cache entry");
    CGImageRelease(masked);
    CHECK(![cache copyImageForEntry:retryEntry size:CGSizeZero scale:2 appearance:0 applyMask:NO], "reject invalid descriptor size");
    NSDictionary *missingEntry = @{LMIconLight: [root stringByAppendingPathComponent:@"missing.png"], LMIconToken: @"missing"};
    CHECK(![cache copyImageForEntry:missingEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO], "missing artwork cannot report a themed render");

    NSString *obstruction = [root stringByAppendingPathComponent:@"not-a-directory"];
    CHECK([@"fixture" writeToFile:obstruction atomically:YES encoding:NSUTF8StringEncoding error:&error], "prepare write failure");
    error = nil;
    CHECK([LMIconMapWriter writeConfig:config icons:icons toPath:[obstruction stringByAppendingPathComponent:@"Map.plist"] forceGeneration:YES error:&error] == LMIconMapWriteFailed && error, "write failures are distinct from unchanged maps");
    CHECK(![[NSDictionary dictionaryWithContentsOfFile:mapPath][LMMapApplied] boolValue], "failed work never marks pending map applied");
    CHECK([LMIconMapWriter markGenerationApplied:retry[@"Generation"] atPath:mapPath error:&error], "commit current successful render");

    NSString *maskPath = [root stringByAppendingPathComponent:@"mask.png"];
    NSString *overlayPath = [root stringByAppendingPathComponent:@"overlay.png"];
    WriteLayerPNG(maskPath, YES, 0, 0, 0, CGRectMake(1, 1, 6, 6));
    WriteLayerPNG(overlayPath, NO, 1, 1, 0, CGRectMake(3, 3, 2, 2));
    NSDictionary *maskEffects = @{LMEffectMask: @{LMIconLight: maskPath, LMIconToken: @"mask-v1"}};
    CGImageRef circle = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO effects:maskEffects];
    CHECK(circle, "render custom alpha mask");
    Pixel(circle, 0, 60, pixel);
    CHECK(pixel[3] == 0, "custom mask removes artwork outside the shape");
    Pixel(circle, 60, 60, pixel);
    CHECK(pixel[2] > 240 && pixel[3] > 240, "black RGB with opaque alpha keeps artwork inside the mask");
    CGImageRelease(circle);
    CGImageRef system = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:YES effects:maskEffects];
    Pixel(system, 0, 60, pixel);
    CHECK(pixel[2] > 240 && pixel[3] > 240, "system-shape option overrides a custom mask");
    CGImageRelease(system);

    NSMutableDictionary *effects = [maskEffects mutableCopy];
    effects[LMEffectUnderlay] = @{LMIconLight: dark, LMIconToken: @"underlay-v1"};
    effects[LMEffectOverlay] = @{LMIconLight: overlayPath, LMIconToken: @"overlay-v1"};
    CGImageRef layered = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO effects:effects];
    CHECK(layered, "compose mask, background, and overlay");
    Pixel(layered, 0, 0, pixel);
    CHECK(pixel[1] > 240 && pixel[3] > 240, "underlay is behind the shaped app artwork");
    Pixel(layered, 60, 60, pixel);
    CHECK(pixel[0] > 240 && pixel[1] > 240 && pixel[2] < 10, "overlay is above the app artwork");
    CGImageRelease(layered);
    WriteLayerPNG(overlayPath, NO, 1, 0, 0, CGRectMake(3, 3, 2, 2));
    effects[LMEffectOverlay] = @{LMIconLight: overlayPath, LMIconToken: @"overlay-v2"};
    CGImageRef changedOverlay = [cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO effects:effects];
    Pixel(changedOverlay, 60, 60, pixel);
    CHECK(pixel[0] > 240 && pixel[1] < 10, "changed layer token invalidates cached composites");
    CGImageRelease(changedOverlay);
    effects[LMEffectOverlay] = missingEntry;
    CHECK(![cache copyImageForEntry:retryEntry size:CGSizeMake(60, 60) scale:2 appearance:0 applyMask:NO effects:effects], "a failed effect is not acknowledged as applied");
    puts("PASS: generations, artwork caches, appearances, custom masks, effect composition, and failed writes");
  }
  return 0;
}
