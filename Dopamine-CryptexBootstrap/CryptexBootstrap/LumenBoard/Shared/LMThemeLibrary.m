#import "LMThemeLibrary.h"
#include <os/lock.h>
#include <sys/utsname.h>

// What a file name tells about an icon, e.g. "com.apple.MobileSMS-large@3x~iphone.png".
typedef struct {
  NSInteger appearance; // 0 light, 1 dark, 2 tinted
  NSInteger rank;       // higher wins: matching device, then "-large", then scale
} LMIconFileTraits;

static BOOL LMDeviceIsPad(void) {
  static BOOL pad;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    struct utsname name;
    uname(&name);
    pad = strncmp(name.machine, "iPad", 4) == 0;
  });
  return pad;
}

static NSRegularExpression *LMTrailingSuffix(void) {
  static NSRegularExpression *expression;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    expression = [NSRegularExpression regularExpressionWithPattern:@"(?:-large|-dark|-tinted|@[123]x|~iphone|~ipad)$" options:NSRegularExpressionCaseInsensitive error:nil];
  });
  return expression;
}

// Returns the lowercased icon name (bundle identifier or app name), or nil if the file isn't an icon.
static NSString *LMIconNameForFile(NSString *file, LMIconFileTraits *traits) {
  if ([file.pathExtension caseInsensitiveCompare:@"png"] != NSOrderedSame) return nil;
  NSString *name = file.stringByDeletingPathExtension;
  NSInteger scale = 1, device = 1, large = 0, appearance = 0;
  BOOL pad = LMDeviceIsPad();
  for (;;) {
    NSTextCheckingResult *match = [LMTrailingSuffix() firstMatchInString:name options:0 range:NSMakeRange(0, name.length)];
    if (!match || match.range.location == 0) break;
    NSString *suffix = [name substringWithRange:match.range].lowercaseString;
    if ([suffix isEqualToString:@"-large"]) large = 1;
    else if ([suffix isEqualToString:@"-dark"]) appearance = 1;
    else if ([suffix isEqualToString:@"-tinted"]) appearance = 2;
    else if ([suffix isEqualToString:@"~iphone"]) device = pad ? 0 : 2;
    else if ([suffix isEqualToString:@"~ipad"]) device = pad ? 2 : 0;
    else scale = [suffix characterAtIndex:1] - '0';
    name = [name substringToIndex:match.range.location];
  }
  if (!name.length) return nil;
  traits->appearance = appearance;
  traits->rank = device * 1000 + large * 100 + scale;
  return name.lowercaseString;
}

static os_unfair_lock LMLibraryLock = OS_UNFAIR_LOCK_INIT;
static NSMutableDictionary *LMFolderCache; // "<theme>/<folder>" -> parsed icons
static NSUInteger LMLibraryGeneration;

@implementation LMThemeLibrary

+ (NSArray<NSString *> *)installedThemes {
  NSMutableArray *themes = [NSMutableArray new];
  for (NSString *folder in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:LMThemesDirectory error:nil]) {
    if ([folder hasPrefix:@"."]) continue;
    BOOL isDirectory = NO;
    NSString *path = [LMThemesDirectory stringByAppendingPathComponent:folder];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDirectory] && isDirectory) [themes addObject:folder];
  }
  [themes sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
    return [[self displayNameForTheme:a] localizedCaseInsensitiveCompare:[self displayNameForTheme:b]];
  }];
  return themes;
}

+ (NSString *)displayNameForTheme:(NSString *)theme {
  return [theme.pathExtension caseInsensitiveCompare:@"theme"] == NSOrderedSame ? theme.stringByDeletingPathExtension : theme;
}

+ (NSDictionary<NSString *, NSDictionary *> *)iconsInFolder:(NSString *)folder ofTheme:(NSString *)theme {
  if (!theme.length) return @{};
  NSString *cacheKey = [theme stringByAppendingPathComponent:folder];
  os_unfair_lock_lock(&LMLibraryLock);
  NSDictionary *cached = LMFolderCache[cacheKey];
  NSUInteger generation = LMLibraryGeneration;
  os_unfair_lock_unlock(&LMLibraryLock);
  if (cached) return cached;

  NSString *directory = [[LMThemesDirectory stringByAppendingPathComponent:theme] stringByAppendingPathComponent:folder];
  NSMutableDictionary *icons = [NSMutableDictionary new];
  NSMutableDictionary *ranks = [NSMutableDictionary new];
  for (NSString *file in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:nil]) {
    LMIconFileTraits traits;
    NSString *name = LMIconNameForFile(file, &traits);
    if (!name) continue;
    NSString *slot = @[LMIconLight, LMIconDark, LMIconTinted][traits.appearance];
    NSString *rankKey = [NSString stringWithFormat:@"%@\n%@", name, slot];
    NSNumber *best = ranks[rankKey];
    if (best && best.integerValue >= traits.rank) continue;
    ranks[rankKey] = @(traits.rank);
    NSMutableDictionary *icon = icons[name] ? : (icons[name] = [NSMutableDictionary new]);
    icon[slot] = [directory stringByAppendingPathComponent:file];
  }
  // dark/tinted artwork without a normal icon isn't usable on its own
  for (NSString *name in icons.allKeys) if (!icons[name][LMIconLight]) [icons removeObjectForKey:name];

  NSDictionary *result = [icons copy];
  os_unfair_lock_lock(&LMLibraryLock);
  if (!LMFolderCache) LMFolderCache = [NSMutableDictionary new];
  if (generation == LMLibraryGeneration) LMFolderCache[cacheKey] = result;
  os_unfair_lock_unlock(&LMLibraryLock);
  return result;
}

+ (NSDictionary<NSString *, NSDictionary *> *)iconsInTheme:(NSString *)theme {
  NSMutableDictionary *icons = [[self iconsInFolder:@"IconBundles" ofTheme:theme] mutableCopy];
  // Add-on packages often put their catalogue preview here. It is not an app.
  [icons removeObjectsForKeys:@[@"icon", @"preview", @"thumbnail"]];
  return icons;
}

+ (NSDictionary<NSString *, NSDictionary *> *)iconsByAppNameInTheme:(NSString *)theme {
  return [self iconsInFolder:@"Icons" ofTheme:theme];
}

+ (NSString *)resourceKeyForBundle:(NSString *)bundle name:(NSString *)name {
  LMIconFileTraits traits;
  NSString *filename = [name.pathExtension caseInsensitiveCompare:@"png"] == NSOrderedSame ? name : [name stringByAppendingPathExtension:@"png"];
  NSString *base = LMIconNameForFile(filename, &traits) ?: name.lowercaseString;
  return [NSString stringWithFormat:@"bundles/%@/%@", bundle.lowercaseString, base];
}

+ (NSDictionary<NSString *, NSDictionary *> *)controlCenterAssetsInTheme:(NSString *)theme {
  NSString *root = [LMThemesDirectory stringByAppendingPathComponent:theme];
  NSString *bundleRoot = [root stringByAppendingPathComponent:@"Bundles"];
  NSArray *bundles = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundleRoot error:nil] ?: @[];
  BOOL cc = NO;
  for (NSString *bundle in bundles) {
    NSString *lower = bundle.lowercaseString;
    cc |= [lower containsString:@"control-center"] || [lower containsString:@"controlcenter"] || [lower isEqual:@"com.apple.mediacontrols"];
  }
  NSDictionary *shared = [self iconsInFolder:@"UIImages" ofTheme:theme];
  for (NSString *name in @[@"play.fill", @"pause.fill", @"forward.fill", @"backward.fill", @"volume.1.fill", @"volume.3.fill"]) cc |= shared[name] != nil;
  if (!cc) return @{};
  NSMutableDictionary *resources = [NSMutableDictionary new];
  for (NSString *bundle in bundles) {
    NSString *lower = bundle.lowercaseString;
    if ([lower isEqual:@"com.apple.mobileicons.framework"] || [lower isEqual:@"com.apple.springboard"] || [lower isEqual:@"com.apple.backboardservices"]) continue;
    NSDictionary *icons = [self iconsInFolder:[@"Bundles" stringByAppendingPathComponent:bundle] ofTheme:theme];
    [icons enumerateKeysAndObjectsUsingBlock:^(NSString *name, NSDictionary *icon, BOOL *stop) {
      resources[[self resourceKeyForBundle:bundle name:name]] = icon;
    }];
  }
  [shared enumerateKeysAndObjectsUsingBlock:^(NSString *name, NSDictionary *icon, BOOL *stop) {
    if (![name isEqual:@"appiconmask"]) resources[[@"uiimages/" stringByAppendingString:name]] = icon;
  }];
  NSString *foldersRoot = [root stringByAppendingPathComponent:@"Folders"];
  for (NSString *folder in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:foldersRoot error:nil]) {
    NSString *directory = [foldersRoot stringByAppendingPathComponent:folder];
    NSMutableSet *parents = [NSMutableSet setWithObject:@""];
    for (NSString *relative in [[NSFileManager defaultManager] enumeratorAtPath:directory])
      if ([relative.pathExtension caseInsensitiveCompare:@"png"] == NSOrderedSame) [parents addObject:relative.stringByDeletingLastPathComponent];
    for (NSString *parent in parents) {
      NSString *themeFolder = [[@"Folders" stringByAppendingPathComponent:folder] stringByAppendingPathComponent:parent];
      [[self iconsInFolder:themeFolder ofTheme:theme] enumerateKeysAndObjectsUsingBlock:^(NSString *name, NSDictionary *icon, BOOL *stop) {
        NSString *relative = parent.length ? [parent.lowercaseString stringByAppendingPathComponent:name] : name;
        resources[[NSString stringWithFormat:@"folders/%@/%@", folder.lowercaseString, relative]] = icon;
      }];
    }
  }
  return resources;
}

+ (NSDictionary<NSString *, NSDictionary *> *)iconEffectsInTheme:(NSString *)theme {
  NSMutableDictionary *effects = [NSMutableDictionary new];
  NSDictionary *mask = [self iconsInFolder:@"Bundles/com.apple.mobileicons.framework" ofTheme:theme][@"appiconmask"];
  if (!mask) mask = [self iconsInFolder:@"UIImages" ofTheme:theme][@"appiconmask"];
  if (mask) effects[LMEffectMask] = mask;
  NSDictionary *art = [self iconsInFolder:@"AnemoneEffects" ofTheme:theme];
  NSString *device = LMDeviceIsPad() ? @"ipad" : @"iphone";
  for (NSString *slot in @[LMEffectUnderlay, LMEffectShadow, LMEffectOverlay]) {
    NSDictionary *entry = art[[device stringByAppendingString:slot.lowercaseString]];
    if (entry) effects[slot] = entry;
  }
  return effects;
}

+ (NSDictionary *)detailsForTheme:(NSString *)theme {
  NSDictionary *icons = [self iconsInTheme:theme];
  NSUInteger iconCount = icons.count + [self iconsByAppNameInTheme:theme].count;
  NSDictionary *cc = [self controlCenterAssetsInTheme:theme];
  NSDictionary *effects = [self iconEffectsInTheme:theme];
  LMThemeCategories categories = (iconCount ? LMThemeCategoryAppIcons : 0) | (cc.count ? LMThemeCategoryControlCenter : 0) | (effects.count ? LMThemeCategoryIconEffects : 0);
  NSMutableArray *previews = [NSMutableArray new];
  for (NSDictionary *group in @[icons, [self iconsByAppNameInTheme:theme], cc, effects]) {
    for (NSString *key in [group.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
      NSString *path = group[key][LMIconLight];
      if (path && previews.count < 4) [previews addObject:path];
    }
  }
  return @{@"Categories": @(categories ?: LMThemeCategoryOther), @"AppIconCount": @(iconCount), @"CCAssetCount": @(cc.count), @"EffectCount": @(effects.count), @"PreviewPaths": previews};
}

+ (NSDictionary *)resolvedResourcesForThemes:(NSArray<NSString *> *)themes {
  NSMutableDictionary *resources = [NSMutableDictionary new], *effects = [NSMutableDictionary new];
  NSMutableArray *unsupported = [NSMutableArray new];
  for (NSString *theme in themes) {
    if (![theme isKindOfClass:[NSString class]]) continue;
    NSDictionary *cc = [self controlCenterAssetsInTheme:theme];
    NSDictionary *art = [self iconEffectsInTheme:theme];
    for (NSString *key in cc) if (!resources[key]) resources[key] = cc[key];
    for (NSString *key in art) if (!effects[key]) effects[key] = art[key];
    if ([[self detailsForTheme:theme][@"Categories"] unsignedIntegerValue] == LMThemeCategoryOther) [unsupported addObject:theme];
  }
  return @{LMMapResources: resources, LMMapIconEffects: effects, @"UnsupportedThemes": unsupported};
}

+ (NSDictionary<NSString *, NSDictionary *> *)resolvedIconsForThemes:(NSArray<NSString *> *)themes appNames:(NSDictionary<NSString *, NSArray<NSString *> *> *)appNames {
  NSMutableDictionary *resolved = [NSMutableDictionary new];
  for (NSString *theme in themes) {
    if (![theme isKindOfClass:[NSString class]]) continue;
    [[self iconsInTheme:theme] enumerateKeysAndObjectsUsingBlock:^(NSString *bundleID, NSDictionary *icon, BOOL *stop) {
      if (!resolved[bundleID]) resolved[bundleID] = icon;
    }];
    if (!appNames.count) continue;
    [[self iconsByAppNameInTheme:theme] enumerateKeysAndObjectsUsingBlock:^(NSString *appName, NSDictionary *icon, BOOL *stop) {
      for (NSString *bundleID in appNames[appName]) if (!resolved[bundleID]) resolved[bundleID] = icon;
    }];
  }
  return resolved;
}

+ (void)invalidate {
  os_unfair_lock_lock(&LMLibraryLock);
  [LMFolderCache removeAllObjects];
  LMLibraryGeneration++;
  os_unfair_lock_unlock(&LMLibraryLock);
}

@end
