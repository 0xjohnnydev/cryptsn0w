#import "LMShared.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_OPTIONS(NSUInteger, LMThemeCategories) {
  LMThemeCategoryAppIcons = 1,
  LMThemeCategoryControlCenter = 2,
  LMThemeCategoryIconEffects = 4,
  LMThemeCategoryOther = 8,
};

// Reads theme folders in the formats SnowBoard, Anemone and WinterBoard use:
//   Theme.theme/IconBundles/<bundle id>[-large][-dark|-tinted][@2x|@3x][~iphone|~ipad].png
//   Theme.theme/Icons/<App Name>.png
@interface LMThemeLibrary : NSObject

// folder names in /Library/Themes, sorted by display name
+ (NSArray<NSString *> *)installedThemes;
// "Viola.theme" -> "Viola"
+ (NSString *)displayNameForTheme:(NSString *)theme;
// lowercased bundle identifier -> @{ LMIconLight: path, LMIconDark: path, LMIconTinted: path }
+ (NSDictionary<NSString *, NSDictionary *> *)iconsInTheme:(NSString *)theme;
// same, keyed by lowercased app name ("Icons" folder)
+ (NSDictionary<NSString *, NSDictionary *> *)iconsByAppNameInTheme:(NSString *)theme;
+ (NSDictionary *)detailsForTheme:(NSString *)theme;
+ (NSDictionary<NSString *, NSDictionary *> *)controlCenterAssetsInTheme:(NSString *)theme;
+ (NSDictionary<NSString *, NSDictionary *> *)iconEffectsInTheme:(NSString *)theme;
+ (NSDictionary *)resolvedResourcesForThemes:(NSArray<NSString *> *)themes;
+ (NSString *)resourceKeyForBundle:(NSString *)bundle name:(NSString *)name;
// first theme wins, IconBundles before Icons. appNames: app name -> bundle ids
+ (NSDictionary<NSString *, NSDictionary *> *)resolvedIconsForThemes:(NSArray<NSString *> *)themes appNames:(nullable NSDictionary<NSString *, NSArray<NSString *> *> *)appNames;
// forget cached folder listings (after themes were installed or removed)
+ (void)invalidate;

@end

NS_ASSUME_NONNULL_END
