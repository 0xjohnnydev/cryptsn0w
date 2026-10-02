#import "LMConfigStore.h"
#import "../Shared/LMHomeScreenOptions.h"
#include <sys/stat.h>

NSNotificationName const LMConfigAppliedDidChangeNotification = @"LMConfigAppliedDidChangeNotification";

@implementation LMConfigStore {
  NSDictionary *_appliedConfig;
  NSUInteger _appliedSkippedCount;
}

+ (instancetype)sharedStore {
  static LMConfigStore *store;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    store = [self new];
  });
  return store;
}

- (instancetype)init {
  if ((self = [super init])) {
    NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:LMConfigPath] ? : @{};
    NSArray *themes = config[LMConfigEnabledThemes];
    _enabledThemes = [themes isKindOfClass:[NSArray class]] ? [themes copy] : @[];
    _useSystemIconShape = [config[LMConfigUseSystemIconShape] boolValue];
    _keepIconsInDarkAndTinted = [config[LMConfigKeepIconsInDarkAndTinted] boolValue];
    _hideDockBackground = [config[LMConfigHideDockBackground] boolValue];
    _hideIconLabels = [config[LMConfigHideIconLabels] boolValue];
    // A map may have been prepared before rendering failed. Only a completed
    // render counts as applied, including when Settings is opened again.
    NSDictionary *map = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
    NSDictionary *applied = map[LMMapAppliedConfig];
    _appliedConfig = [map[LMMapApplied] boolValue] && [applied isKindOfClass:[NSDictionary class]] ? [LMHomeScreenOptions configWithAppliedDockBackground:applied] : nil;
    if (!map && [LMHomeScreenOptions appliedDockBackground]) _appliedConfig = [LMHomeScreenOptions configWithAppliedDockBackground:@{}];
    if ([map[LMMapApplied] boolValue]) [self readSkippedCountFromMap:map];
  }
  return self;
}

- (NSDictionary *)dictionaryRepresentation {
  return @{
    LMConfigEnabledThemes : _enabledThemes ? : @[],
    LMConfigUseSystemIconShape : @(_useSystemIconShape),
    LMConfigKeepIconsInDarkAndTinted : @(_keepIconsInDarkAndTinted),
    LMConfigHideDockBackground : @(_hideDockBackground),
    LMConfigHideIconLabels : @(_hideIconLabels),
  };
}

- (BOOL)hasUnappliedChanges {
  return ![[self dictionaryRepresentation] isEqual:_appliedConfig];
}

- (NSUInteger)appliedSkippedCount { return _appliedSkippedCount; }

- (void)readSkippedCountFromMap:(NSDictionary *)map {
  _appliedSkippedCount = 0;
  NSDictionary *skipped = map[LMMapSkipped];
  if ([skipped isKindOfClass:[NSDictionary class]])
    for (id entries in skipped.allValues) if ([entries isKindOfClass:[NSArray class]]) _appliedSkippedCount += [entries count];
}

- (BOOL)save:(NSError **)error {
  if (![[NSFileManager defaultManager] createDirectoryAtPath:LMDataDirectory withIntermediateDirectories:YES attributes:nil error:error]) return NO;
  NSData *data = [NSPropertyListSerialization dataWithPropertyList:[self dictionaryRepresentation] format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
  if (!data || ![data writeToFile:LMConfigPath options:NSDataWritingAtomic error:error]) return NO;
  chmod(LMConfigPath.fileSystemRepresentation, 0644);
  return YES;
}

- (void)markApplied {
  NSDictionary *map = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
  NSDictionary *applied = map[LMMapAppliedConfig];
  if ([map[LMMapApplied] boolValue] && [applied isKindOfClass:[NSDictionary class]]) {
    _appliedConfig = [LMHomeScreenOptions configWithAppliedDockBackground:applied];
    [self readSkippedCountFromMap:map];
    [[NSNotificationCenter defaultCenter] postNotificationName:LMConfigAppliedDidChangeNotification object:self];
  }
}

- (void)markDockApplied {
  if (_appliedConfig) _appliedConfig = [LMHomeScreenOptions configWithAppliedDockBackground:_appliedConfig];
  else if (![[NSFileManager defaultManager] fileExistsAtPath:LMIconMapPath] && [LMHomeScreenOptions appliedDockBackground]) _appliedConfig = [LMHomeScreenOptions configWithAppliedDockBackground:@{}];
  [[NSNotificationCenter defaultCenter] postNotificationName:LMConfigAppliedDidChangeNotification object:self];
}

@end
