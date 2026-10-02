#import "LMIconArtwork.h"
#import <ImageIO/ImageIO.h>
#include <math.h>

@interface LMArtworkImage : NSObject
@property (nonatomic, readonly) CGImageRef image;
- (instancetype)initWithImage:(CGImageRef)image;
@end

@implementation LMArtworkImage
- (instancetype)initWithImage:(CGImageRef)image {
  if ((self = [super init])) _image = CGImageRetain(image);
  return self;
}
- (void)dealloc { CGImageRelease(_image); }
@end

static NSString *LMArtworkPath(NSDictionary *entry, NSInteger appearance) {
  NSString *variant = appearance == 1 ? entry[LMIconDark] : (appearance == 2 ? entry[LMIconTinted] : nil);
  return [variant isKindOfClass:[NSString class]] && variant.length ? variant : entry[LMIconLight];
}

static CGImageRef LMLoadArtwork(NSString *path) {
  if (![path isKindOfClass:[NSString class]] || !path.length) return NULL;
  CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:path], NULL);
  CGImageRef image = source && CGImageSourceGetCount(source) ? CGImageSourceCreateImageAtIndex(source, 0, NULL) : NULL;
  if (source) CFRelease(source);
  return image;
}

static NSArray *LMArtworkCacheKey(NSArray *baseKey, CGSize size, CGFloat scale, NSInteger appearance, BOOL mask, NSDictionary *effects) {
  if (!isfinite(size.width) || !isfinite(size.height) || !isfinite(scale) || size.width <= 0 || size.height <= 0 || scale <= 0) return nil;
  double width = ceil(size.width * scale), height = ceil(size.height * scale);
  if (!isfinite(width) || !isfinite(height) || width > 4096 || height > 4096) return nil;
  NSMutableArray *key = [baseKey mutableCopy];
  [key addObjectsFromArray:@[@(width), @(height), @(mask), @(appearance)]];
  for (NSString *slot in @[LMEffectMask, LMEffectUnderlay, LMEffectShadow, LMEffectOverlay]) [key addObject:effects[slot][LMIconToken] ?: @""];
  return key;
}

@implementation LMIconArtwork {
  NSCache *_images;
}

+ (instancetype)sharedCache {
  static LMIconArtwork *cache;
  static dispatch_once_t once;
  dispatch_once(&once, ^{ cache = [self new]; });
  return cache;
}

- (instancetype)init {
  if ((self = [super init])) {
    _images = [NSCache new];
    _images.countLimit = 200;
    _images.totalCostLimit = 32 * 1024 * 1024;
  }
  return self;
}

- (CGImageRef)copyImageForEntry:(NSDictionary *)entry size:(CGSize)size scale:(CGFloat)scale appearance:(NSInteger)appearance applyMask:(BOOL)applyMask {
  return [self copyImageForEntry:entry size:size scale:scale appearance:appearance applyMask:applyMask effects:@{}];
}

- (CGImageRef)copyImageForEntry:(NSDictionary *)entry size:(CGSize)size scale:(CGFloat)scale appearance:(NSInteger)appearance applyMask:(BOOL)applyMask effects:(NSDictionary *)effects {
  NSString *token = entry[LMIconToken];
  NSString *path = LMArtworkPath(entry, appearance);
  if (![token isKindOfClass:[NSString class]] || !token.length || ![path isKindOfClass:[NSString class]] || !path.length) return NULL;
  NSArray *key = LMArtworkCacheKey(@[token, path], size, scale, appearance, applyMask, effects);
  if (!key) return NULL;
  LMArtworkImage *cached = [_images objectForKey:key];
  if (cached) return CGImageRetain(cached.image);
  CGImageRef artwork = LMLoadArtwork(path);
  if (!artwork) return NULL;
  CGImageRef rendered = [self copyImageFromImage:artwork cacheKey:@[token, path] size:size scale:scale appearance:appearance applyMask:applyMask effects:effects];
  CGImageRelease(artwork);
  return rendered;
}

- (CGImageRef)copyImageFromImage:(CGImageRef)artwork cacheKey:(NSArray *)baseKey size:(CGSize)size scale:(CGFloat)scale appearance:(NSInteger)appearance applyMask:(BOOL)applyMask effects:(NSDictionary *)effects {
  if (!artwork) return NULL;
  NSArray *key = LMArtworkCacheKey(baseKey, size, scale, appearance, applyMask, effects);
  if (!key) return NULL;
  size_t width = (size_t)ceil(size.width * scale), height = (size_t)ceil(size.height * scale);
  LMArtworkImage *cached = [_images objectForKey:key];
  if (cached) return CGImageRetain(cached.image);

  CGColorSpaceRef colors = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
  CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, 0, colors, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
  CGColorSpaceRelease(colors);
  if (!context) return NULL;
  CGRect rect = CGRectMake(0, 0, width, height);
  for (NSString *slot in @[LMEffectUnderlay, LMEffectShadow]) {
    if (!effects[slot]) continue;
    CGImageRef layer = LMLoadArtwork(LMArtworkPath(effects[slot], appearance));
    if (!layer) { CGContextRelease(context); return NULL; }
    CGContextDrawImage(context, rect, layer);
    CGImageRelease(layer);
  }
  CGContextSaveGState(context);
  if (applyMask) {
    CGPathRef mask = CGPathCreateWithRoundedRect(rect, width * 0.225, height * 0.225, NULL);
    CGContextAddPath(context, mask);
    CGContextClip(context);
    CGPathRelease(mask);
  } else if (effects[LMEffectMask]) {
    CGImageRef mask = LMLoadArtwork(LMArtworkPath(effects[LMEffectMask], appearance));
    if (!mask) { CGContextRelease(context); return NULL; }
    CGContextClipToMask(context, rect, mask);
    CGImageRelease(mask);
  }
  CGContextSetInterpolationQuality(context, kCGInterpolationHigh);
  CGContextDrawImage(context, rect, artwork);
  CGContextRestoreGState(context);
  if (effects[LMEffectOverlay]) {
    CGImageRef layer = LMLoadArtwork(LMArtworkPath(effects[LMEffectOverlay], appearance));
    if (!layer) { CGContextRelease(context); return NULL; }
    CGContextDrawImage(context, rect, layer);
    CGImageRelease(layer);
  }
  CGImageRef rendered = CGBitmapContextCreateImage(context);
  CGContextRelease(context);
  if (rendered) [_images setObject:[[LMArtworkImage alloc] initWithImage:rendered] forKey:key cost:width * height * 4];
  return rendered;
}

- (void)invalidate { [_images removeAllObjects]; }

@end
