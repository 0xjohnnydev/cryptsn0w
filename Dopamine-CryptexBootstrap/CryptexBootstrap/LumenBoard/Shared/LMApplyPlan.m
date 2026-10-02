#import "LMApplyPlan.h"
#import <ImageIO/ImageIO.h>

static BOOL LMReadableArtwork(NSString *path) {
  if (![path isKindOfClass:[NSString class]] || !path.length) return NO;
  CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:LMRootPath(path)], NULL);
  CGImageRef image = source && CGImageSourceGetCount(source) ? CGImageSourceCreateImageAtIndex(source, 0, NULL) : NULL;
  if (source) CFRelease(source);
  BOOL valid = image && CGImageGetWidth(image) > 0 && CGImageGetHeight(image) > 0 && CGImageGetWidth(image) <= 4096 && CGImageGetHeight(image) <= 4096;
  if (image) CGImageRelease(image);
  return valid;
}

@implementation LMApplyPlan
+ (NSDictionary<NSString *, NSArray *> *)invalidEntriesInMap:(NSDictionary *)map {
  NSMutableDictionary *skipped = [NSMutableDictionary new];
  for (NSString *group in @[LMMapIcons, LMMapResources, LMMapIconEffects]) {
    NSMutableArray *invalid = [NSMutableArray new];
    NSDictionary *entries = [map[group] isKindOfClass:[NSDictionary class]] ? map[group] : @{};
    for (NSString *key in [entries.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
      @autoreleasepool {
        NSDictionary *entry = entries[key];
        if (![entry isKindOfClass:[NSDictionary class]]) { [invalid addObject:key]; continue; }
        BOOL valid = LMReadableArtwork(entry[LMIconLight]);
        for (NSString *slot in @[LMIconDark, LMIconTinted]) if (entry[slot] && !LMReadableArtwork(entry[slot])) valid = NO;
        if (!valid) [invalid addObject:key];
      }
    }
    if (invalid.count) skipped[group] = invalid;
  }
  return skipped;
}

+ (NSUInteger)skippedCount:(NSDictionary *)skipped {
  NSUInteger count = 0;
  if (![skipped isKindOfClass:[NSDictionary class]]) return 0;
  for (id entries in skipped.allValues) if ([entries isKindOfClass:[NSArray class]]) count += [entries count];
  return count;
}

+ (BOOL)canContinueResult:(NSDictionary *)result map:(NSDictionary *)map config:(NSDictionary *)config {
  if ([map[@"Version"] integerValue] != LMMapVersion) return NO;
  NSString *generation = result[@"Generation"];
  if (![generation isKindOfClass:[NSString class]] || !generation.length || ![generation isEqual:map[@"Generation"]]) return NO;
  if (![result[@"State"] isEqual:@"Partial"] || ![result[@"SuccessCount"] unsignedIntegerValue] || ![self skippedCount:result[LMMapSkipped]] || [map[LMMapApplied] boolValue]) return NO;
  return [LMNormalizedConfig(config) isEqual:LMNormalizedConfig(map[LMMapAppliedConfig])];
}
@end
