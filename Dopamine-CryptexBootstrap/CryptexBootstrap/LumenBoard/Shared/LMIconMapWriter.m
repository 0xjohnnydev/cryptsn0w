#import "LMIconMapWriter.h"
#import <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>

static NSString *LMHash(NSString *string) {
  NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
  unsigned char hash[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
  NSMutableString *hex = [NSMutableString stringWithCapacity:20];
  for (int i = 0; i < 10; i++) [hex appendFormat:@"%02x", hash[i]];
  return hex;
}

static NSString *LMFileStamp(NSString *path) {
  struct stat info;
  if (!path || stat(path.fileSystemRepresentation, &info) != 0) return @"-";
  return [NSString stringWithFormat:@"%lld.%ld/%lld", (long long)info.st_mtimespec.tv_sec, info.st_mtimespec.tv_nsec, (long long)info.st_size];
}

static BOOL LMStoreMap(NSDictionary *map, NSString *path, NSError **error) {
  if (![[NSFileManager defaultManager] createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:error]) return NO;
  NSData *data = [NSPropertyListSerialization dataWithPropertyList:map format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
  if (!data || ![data writeToFile:path options:NSDataWritingAtomic error:error]) return NO;
  if (chmod(path.fileSystemRepresentation, 0644) != 0) {
    if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
    return NO;
  }
  return YES;
}

@implementation LMIconMapWriter

+ (LMIconMapWriteResult)writeConfig:(NSDictionary *)config icons:(NSDictionary<NSString *, NSDictionary *> *)icons toPath:(NSString *)path forceGeneration:(BOOL)forceGeneration error:(NSError **)error {
  return [self writeConfig:config icons:icons resources:@{} effects:@{} toPath:path forceGeneration:forceGeneration error:error];
}

+ (LMIconMapWriteResult)writeConfig:(NSDictionary *)config icons:(NSDictionary *)icons resources:(NSDictionary *)resources effects:(NSDictionary *)effects toPath:(NSString *)path forceGeneration:(BOOL)forceGeneration error:(NSError **)error {
  config = LMNormalizedConfig(config);
  BOOL systemShape = [config[LMConfigUseSystemIconShape] boolValue];
  BOOL keepAppearance = [config[LMConfigKeepIconsInDarkAndTinted] boolValue];
  NSArray *themes = config[LMConfigEnabledThemes] ?: @[];
  NSString *style = [NSString stringWithFormat:@"v%d shape=%d keep=%d dock=%d labels=%d", LMMapVersion, systemShape, keepAppearance, [config[LMConfigHideDockBackground] boolValue], [config[LMConfigHideIconLabels] boolValue]];
  NSMutableDictionary *groups = [NSMutableDictionary new], *materials = [NSMutableDictionary new];
  NSMutableString *content = [NSMutableString stringWithFormat:@"resources-v1\n%@\n%@\n", style, [themes componentsJoinedByString:@"/"]];
  NSDictionary *inputs = @{LMMapIcons: icons, LMMapResources: resources, LMMapIconEffects: effects};
  for (NSString *group in @[LMMapIcons, LMMapResources, LMMapIconEffects]) {
    NSMutableDictionary *entries = [NSMutableDictionary new];
    groups[group] = entries;
    NSDictionary *input = inputs[group];
    for (NSString *bundleID in [input.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
      NSDictionary *icon = input[bundleID];
      NSMutableDictionary *entry = [NSMutableDictionary new];
      NSMutableString *material = [[NSString stringWithFormat:@"%@/%@", group, bundleID] mutableCopy];
      for (NSString *slot in @[LMIconLight, LMIconDark, LMIconTinted]) {
        if (icon[slot]) entry[slot] = LMJailbreakPath(icon[slot]);
        [material appendFormat:@"|%@@%@", entry[slot] ?: @"", LMFileStamp(icon[slot])];
      }
      [material appendFormat:@"|%@", style];
      entries[bundleID] = entry;
      materials[[NSString stringWithFormat:@"%@/%@", group, bundleID]] = material;
      [content appendFormat:@"%@\n", material];
    }
  }
  NSString *contentHash = LMHash(content);
  NSDictionary *previous = [NSDictionary dictionaryWithContentsOfFile:path];
  if (!forceGeneration && [previous[@"Version"] integerValue] == LMMapVersion && [previous[@"ContentHash"] isEqual:contentHash]) return LMIconMapUnchanged;

  // Apply and Clear Cache always produce new tokens, including an unchanged
  // theme being retried after a failed render or a PNG replaced in place.
  NSString *generation = [NSUUID UUID].UUIDString;
  for (NSString *group in groups) [groups[group] enumerateKeysAndObjectsUsingBlock:^(NSString *bundleID, NSMutableDictionary *entry, BOOL *stop) {
    entry[LMIconToken] = LMHash([materials[[NSString stringWithFormat:@"%@/%@", group, bundleID]] stringByAppendingFormat:@"|%@", generation]);
  }];
  NSDictionary *map = @{
    @"Version": @(LMMapVersion), @"ContentHash": contentHash, @"Generation": generation,
    LMConfigUseSystemIconShape: @(systemShape), LMConfigKeepIconsInDarkAndTinted: @(keepAppearance),
    LMMapAppliedConfig: config, LMMapApplied: @NO, LMMapIcons: groups[LMMapIcons],
    LMMapResources: groups[LMMapResources], LMMapIconEffects: groups[LMMapIconEffects],
  };
  return LMStoreMap(map, path, error) ? LMIconMapWritten : LMIconMapWriteFailed;
}

+ (BOOL)markGenerationApplied:(NSString *)generation atPath:(NSString *)path error:(NSError **)error {
  return [self markGenerationApplied:generation skipping:@{} atPath:path error:error];
}

+ (BOOL)markGenerationApplied:(NSString *)generation skipping:(NSDictionary<NSString *, NSArray *> *)skipped atPath:(NSString *)path error:(NSError **)error {
  return [self updateGeneration:generation excluding:skipped applied:YES atPath:path error:error];
}

+ (BOOL)updateGeneration:(NSString *)generation excluding:(NSDictionary<NSString *, NSArray *> *)skipped applied:(BOOL)applied atPath:(NSString *)path error:(NSError **)error {
  NSMutableDictionary *map = [[NSDictionary dictionaryWithContentsOfFile:path] mutableCopy];
  if (!map || ![map[@"Generation"] isEqual:generation]) {
    if (error) *error = [NSError errorWithDomain:@"LumenBoard" code:LMApplyErrorWriteMap userInfo:@{NSLocalizedDescriptionKey: @"The icon map changed while rendering."}];
    return NO;
  }
  for (NSString *group in @[LMMapIcons, LMMapResources, LMMapIconEffects]) {
    NSMutableDictionary *entries = [map[group] mutableCopy];
    [entries removeObjectsForKeys:skipped[group] ?: @[]];
    if (entries) map[group] = entries;
  }
  map[LMMapSkipped] = skipped;
  map[LMMapApplied] = @(applied);
  return LMStoreMap(map, path, error);
}

@end
