#import "LMHomeScreenOptions.h"
#include <sys/stat.h>

@implementation LMHomeScreenOptions
+ (NSNumber *)appliedDockBackground {
  NSDictionary *options = [NSDictionary dictionaryWithContentsOfFile:LMDockOptionsPath];
  id value = options[LMConfigHideDockBackground];
  return [options[LMMapApplied] boolValue] && [value isKindOfClass:[NSNumber class]] ? value : nil;
}

+ (BOOL)applyDockBackground:(BOOL)hidden error:(NSError **)error {
  // A separate acknowledgement keeps dock-only changes out of the artwork map
  // and leaves pending themes and icon-label changes pending.
  if (![[NSFileManager defaultManager] createDirectoryAtPath:LMDataDirectory withIntermediateDirectories:YES attributes:nil error:error]) return NO;
  NSDictionary *options = @{LMConfigHideDockBackground: @(hidden), LMMapApplied: @YES};
  NSData *data = [NSPropertyListSerialization dataWithPropertyList:options format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
  if (!data || ![data writeToFile:LMDockOptionsPath options:NSDataWritingAtomic error:error]) return NO;
  if (chmod(LMDockOptionsPath.fileSystemRepresentation, 0644) == 0) return YES;
  if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
  return NO;
}

+ (NSDictionary *)configWithAppliedDockBackground:(NSDictionary *)config {
  NSMutableDictionary *applied = [LMNormalizedConfig(config) mutableCopy];
  NSNumber *dock = [self appliedDockBackground];
  if (dock) applied[LMConfigHideDockBackground] = dock;
  return applied;
}

+ (NSDictionary *)startupConfig:(NSDictionary *)saved map:(NSDictionary *)map {
  // Refresh installed artwork for the current map without activating changes
  // merely saved in Settings, including after a dock-only update.
  NSDictionary *current = map[LMMapAppliedConfig];
  if ([map[@"Version"] integerValue] == LMMapVersion && [current isKindOfClass:[NSDictionary class]]) return LMNormalizedConfig(current);
  if ([self appliedDockBackground]) return LMNormalizedConfig(@{});
  return LMNormalizedConfig(saved);
}
@end
