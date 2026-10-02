#import "../Shared/LMThemeLibrary.h"
#import "../Shared/LMCCResources.h"
#import "../Shared/LMApplyPlan.h"
#import "../Shared/LMIconMapWriter.h"
#import "../Preferences/LMConfigStore.h"
#import "../Shared/LMHomeScreenOptions.h"

#define CHECK(condition, message) do { if (!(condition)) { fprintf(stderr, "FAIL: %s (line %d)\n", message, __LINE__); exit(1); } } while (0)

static NSString *Fixture(NSString *theme, NSString *relative, NSString *png) {
  NSString *path = [[LMThemesDirectory stringByAppendingPathComponent:theme] stringByAppendingPathComponent:relative];
  CHECK([[NSFileManager defaultManager] createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil], "create theme fixture folder");
  CHECK([[NSFileManager defaultManager] copyItemAtPath:png toPath:path error:nil], "copy fixture PNG");
  return path;
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    CHECK(argc == 2, "supply scratch folder");
    NSString *root = [NSString stringWithUTF8String:argv[1]];
    NSString *png = [root stringByAppendingPathComponent:@"icon.png"];
    Fixture(@"Apps.theme", @"IconBundles/com.apple.MobileSafari@3x.png", png);
    Fixture(@"Apps.theme", @"IconBundles/Icon.png", png);
    Fixture(@"Apps.theme", @"Icons/Calculator.png", png);
    Fixture(@"CC Icons (Glif)", @"IconBundles/Icon.png", png);
    Fixture(@"CC Icons (Glif)", @"Bundles/com.apple.control-center.ConnectivityModule/WiFiGlyph@2x.png", png);
    NSString *wifi = Fixture(@"CC Icons (Glif)", @"Bundles/com.apple.control-center.ConnectivityModule/WiFiGlyph@3x.png", png);
    Fixture(@"CC Icons (Glif)", @"UIImages/play.fill@3x.png", png);
    Fixture(@"CC Icons (Glif)", @"Folders/Prysm/blackIcons/wifi@3x.png", png);
    NSString *override = Fixture(@"CC override", @"Bundles/com.apple.control-center.ConnectivityModule/WiFiGlyph@3x.png", png);
    NSString *mask = Fixture(@"Shape.standalone", @"Bundles/com.apple.mobileicons.framework/AppIconMask@3x~iphone.png", png);
    Fixture(@"Shape.standalone", @"IconBundles/Icon.png", png);
    Fixture(@"Shape.standalone", @"AnemoneEffects/iPhoneOverlay@3x.png", png);
    Fixture(@"Shape.standalone", @"AnemoneEffects/iPhoneUnderlay@3x.png", png);
    Fixture(@"Respring RGB16 (Glif)", @"IconBundles/Icon.png", png);
    Fixture(@"Respring RGB16 (Glif)", @"Bundles/com.apple.BackBoardServices/lightspinny.0@3x.png", png);
    Fixture(@"CC shared", @"UIImages/pause.fill@3x.png", png);
    [LMThemeLibrary invalidate];

    NSDictionary *appInfo = [LMThemeLibrary detailsForTheme:@"Apps.theme"];
    CHECK([appInfo[@"AppIconCount"] unsignedIntegerValue] == 2, "app bundle IDs and app-name icons are recognized");
    CHECK([appInfo[@"Categories"] unsignedIntegerValue] == LMThemeCategoryAppIcons, "app category");
    NSDictionary *ccInfo = [LMThemeLibrary detailsForTheme:@"CC Icons (Glif)"];
    CHECK([ccInfo[@"AppIconCount"] unsignedIntegerValue] == 0, "catalogue Icon.png is never an app icon");
    CHECK([ccInfo[@"CCAssetCount"] unsignedIntegerValue] == 3, "bundle, shared, and nested folder glyphs are counted once per scale");
    CHECK([ccInfo[@"Categories"] unsignedIntegerValue] == LMThemeCategoryControlCenter, "CC category");
    CHECK([[LMThemeLibrary detailsForTheme:@"CC shared"][@"Categories"] unsignedIntegerValue] == LMThemeCategoryControlCenter, "shared-only media glyphs are recognized");
    NSDictionary *shapeInfo = [LMThemeLibrary detailsForTheme:@"Shape.standalone"];
    CHECK([shapeInfo[@"Categories"] unsignedIntegerValue] == LMThemeCategoryIconEffects && [shapeInfo[@"EffectCount"] unsignedIntegerValue] == 3, "standalone mask and effect layers need no Info.plist");
    CHECK([[LMThemeLibrary iconEffectsInTheme:@"Shape.standalone"][LMEffectMask][LMIconLight] isEqual:mask], "iPhone mask variants are normalized");
    CHECK([[LMThemeLibrary detailsForTheme:@"Respring RGB16 (Glif)"][@"Categories"] unsignedIntegerValue] == LMThemeCategoryOther, "unsupported animations are not app packs");

    NSString *wifiKey = @"bundles/com.apple.control-center.connectivitymodule/wifiglyph";
    CHECK([[LMThemeLibrary controlCenterAssetsInTheme:@"CC Icons (Glif)"][wifiKey][LMIconLight] isEqual:wifi], "highest scale wins without duplicating a resource");
    CHECK([[LMThemeLibrary resourceKeyForBundle:@"COM.Apple.Control-Center.ConnectivityModule" name:@"WiFiGlyph@3x~iphone.png"] isEqual:wifiKey], "request suffixes and bundle case match theme names");
    CHECK([[LMCCResources keysForSymbol:@"wifi"] containsObject:wifiKey], "SF connectivity symbols find legacy PNG names");
    CHECK([[LMCCResources keysForSymbol:@"play.fill"] containsObject:@"uiimages/play.fill"], "media SF glyphs retain their dotted name");
    CHECK([[LMCCResources keysForName:@"blackIcons/wifi@3x.png" bundle:nil folder:@"Prysm" shared:YES] containsObject:@"folders/prysm/blackicons/wifi"], "nested folder names are preserved");
    CHECK(![[LMCCResources keysForName:@"play.fill" bundle:@"com.apple.unrelated" folder:nil shared:NO] containsObject:@"uiimages/play.fill"], "shared resources are not routed into unrelated callers");
    CHECK([[[LMCCResources glyphNamesForBundle:@"com.apple.control-center.FlashlightModule" selected:YES] firstObject] isEqual:@"FlashlightOn"], "selected modules use their selected artwork");

    NSArray *themes = @[@"Apps.theme", @"CC override", @"CC Icons (Glif)", @"Shape.standalone", @"Respring RGB16 (Glif)"];
    NSDictionary *resolved = [LMThemeLibrary resolvedResourcesForThemes:themes];
    CHECK([resolved[LMMapResources][wifiKey][LMIconLight] isEqual:override], "CC theme priority is independent of the app pack");
    CHECK([resolved[LMMapIconEffects] count] == 3 && [resolved[@"UnsupportedThemes"] count] == 1, "effects resolve alongside CC, unsupported packs remain explicit");
    NSDictionary *icons = [LMThemeLibrary resolvedIconsForThemes:themes appNames:@{@"calculator": @[@"com.apple.calculator"]}];
    CHECK(icons.count == 2 && icons[@"com.apple.calculator"], "categories can be enabled together");

    NSString *bad = [root stringByAppendingPathComponent:@"broken.png"];
    CHECK([@"not a PNG" writeToFile:bad atomically:YES encoding:NSUTF8StringEncoding error:nil], "prepare corrupt PNG");
    NSMutableDictionary *wantedIcons = [icons mutableCopy];
    wantedIcons[@"com.example.broken"] = @{LMIconLight: bad};
    NSMutableDictionary *wantedResources = [resolved[LMMapResources] mutableCopy];
    wantedResources[@"uiimages/broken"] = @{LMIconLight: bad};
    NSMutableDictionary *wantedEffects = [resolved[LMMapIconEffects] mutableCopy];
    wantedEffects[LMEffectMask] = @{LMIconLight: bad};
    NSDictionary *config = @{LMConfigEnabledThemes: themes, LMConfigUseSystemIconShape: @NO, LMConfigKeepIconsInDarkAndTinted: @NO};
    NSString *path = [root stringByAppendingPathComponent:@"ResourceMap.plist"];
    NSError *error = nil;
    CHECK([LMIconMapWriter writeConfig:config icons:wantedIcons resources:wantedResources effects:wantedEffects toPath:path forceGeneration:YES error:&error] == LMIconMapWritten, "prepare resource map");
    NSDictionary *map = [NSDictionary dictionaryWithContentsOfFile:path];
    NSMutableDictionary *skipped = [[LMApplyPlan invalidEntriesInMap:map] mutableCopy];
    CHECK([LMApplyPlan skippedCount:skipped] == 3, "corrupt app, CC, and mask entries are identified independently");
    skipped[@"Themes"] = resolved[@"UnsupportedThemes"];
    CHECK([LMIconMapWriter updateGeneration:map[@"Generation"] excluding:skipped applied:NO atPath:path error:&error], "filter broken layers before rendering");
    NSDictionary *filtered = [NSDictionary dictionaryWithContentsOfFile:path];
    CHECK(![filtered[LMMapApplied] boolValue] && !filtered[LMMapIconEffects][LMEffectMask] && filtered[LMMapIconEffects][LMEffectOverlay], "filtering preserves good layers and stays pending");
    NSDictionary *partial = @{@"State": @"Partial", @"Generation": map[@"Generation"], @"SuccessCount": @5, LMMapSkipped: skipped};
    CHECK([LMApplyPlan canContinueResult:partial map:filtered config:config], "valid partial attempt is continuable");
    NSMutableDictionary *oldMap = [filtered mutableCopy];
    oldMap[@"Version"] = @(LMMapVersion - 1);
    CHECK(![LMApplyPlan canContinueResult:partial map:oldMap config:config], "old map formats cannot accept continuation");
    NSMutableDictionary *changedConfig = [config mutableCopy];
    changedConfig[LMConfigEnabledThemes] = @[@"Apps.theme"];
    CHECK(![LMApplyPlan canContinueResult:partial map:filtered config:changedConfig], "changed selection cannot acknowledge an old attempt");
    changedConfig = [config mutableCopy];
    changedConfig[LMConfigHideDockBackground] = @YES;
    CHECK(![LMApplyPlan canContinueResult:partial map:filtered config:changedConfig], "changing dock visibility invalidates an earlier partial attempt");
    changedConfig = [config mutableCopy];
    changedConfig[LMConfigHideIconLabels] = @YES;
    CHECK(![LMApplyPlan canContinueResult:partial map:filtered config:changedConfig], "changing label visibility invalidates an earlier partial attempt");
    NSMutableDictionary *emptyResult = [partial mutableCopy];
    emptyResult[@"SuccessCount"] = @0;
    CHECK(![LMApplyPlan canContinueResult:emptyResult map:filtered config:config], "all-failed attempts never offer continuation");
    CHECK([LMIconMapWriter markGenerationApplied:map[@"Generation"] skipping:skipped atPath:path error:&error], "continue commits only the good entries");
    NSDictionary *complete = [NSDictionary dictionaryWithContentsOfFile:path];
    CHECK([complete[LMMapApplied] boolValue] && [complete[LMMapIcons] count] == 2 && [complete[LMMapResources] count] == 3, "continue retains good app and CC entries");
    CHECK([LMApplyPlan skippedCount:complete[LMMapSkipped]] == 4, "completed partial map records every skipped item");
    CHECK(![LMApplyPlan canContinueResult:partial map:complete config:config], "a completed attempt cannot be continued twice");
    CHECK([LMIconMapWriter writeConfig:config icons:wantedIcons resources:wantedResources effects:wantedEffects toPath:path forceGeneration:NO error:&error] == LMIconMapUnchanged, "respring preserves an accepted partial map");
    CHECK([LMIconMapWriter writeConfig:config icons:wantedIcons resources:wantedResources effects:wantedEffects toPath:path forceGeneration:YES error:&error] == LMIconMapWritten, "Apply retries skipped artwork");
    NSDictionary *retry = [NSDictionary dictionaryWithContentsOfFile:path];
    CHECK(retry[LMMapIcons][@"com.example.broken"] && ![retry[LMMapApplied] boolValue], "retry restores wanted entries without claiming success");
    CHECK(![LMApplyPlan canContinueResult:partial map:retry config:config], "stale continuation cannot apply a newer map");
    CHECK(![LMIconMapWriter markGenerationApplied:map[@"Generation"] skipping:skipped atPath:path error:&error], "stale commit cannot remove new artwork");
    NSData *previousMap = [NSData dataWithContentsOfFile:LMIconMapPath];
    CHECK(previousMap, "preserve native integration map");
    NSDictionary *emptyConfig = @{LMConfigEnabledThemes: @[], LMConfigUseSystemIconShape: @NO, LMConfigKeepIconsInDarkAndTinted: @NO};
    NSMutableDictionary *statusMap = [@{@"Version": @(LMMapVersion), LMMapApplied: @NO, LMMapAppliedConfig: emptyConfig, LMMapSkipped: skipped} mutableCopy];
    CHECK([statusMap writeToFile:LMIconMapPath atomically:YES], "prepare pending pane status");
    LMConfigStore *settings = [LMConfigStore new];
    CHECK(settings.hasUnappliedChanges && settings.appliedSkippedCount == 0, "pending empty selection is not reported as applied");
    [settings markApplied];
    CHECK(settings.hasUnappliedChanges, "pane cannot acknowledge a pending map");
    statusMap[LMMapApplied] = @YES;
    CHECK([statusMap writeToFile:LMIconMapPath atomically:YES], "prepare completed partial pane status");
    [settings markApplied];
    CHECK(!settings.hasUnappliedChanges && settings.appliedSkippedCount == 4, "pane records completed partial status and skipped count");
    settings = [LMConfigStore new];
    CHECK(!settings.hasUnappliedChanges && settings.appliedSkippedCount == 4, "reopening Settings preserves completed partial status");
    CHECK(!settings.hideDockBackground, "older configurations keep the dock background visible");
    CHECK(!settings.hideIconLabels, "older configurations preserve native icon label visibility");
    settings.hideDockBackground = YES;
    settings.hideIconLabels = YES;
    CHECK(settings.hasUnappliedChanges, "dock visibility participates in Apply status");
    CHECK([settings save:&error], "save dock visibility without a theme selection");
    settings = [LMConfigStore new];
    CHECK(settings.hideDockBackground && settings.hideIconLabels && settings.hasUnappliedChanges, "dock and label visibility survive reopening Settings before Apply");
    NSString *dockMapPath = [root stringByAppendingPathComponent:@"DockMap.plist"];
    NSMutableDictionary *dockConfig = [emptyConfig mutableCopy];
    dockConfig[LMConfigHideDockBackground] = @YES;
    CHECK([LMIconMapWriter writeConfig:dockConfig icons:@{} toPath:dockMapPath forceGeneration:NO error:&error] == LMIconMapWritten, "prepare dock-only configuration");
    NSDictionary *dockMap = [NSDictionary dictionaryWithContentsOfFile:dockMapPath];
    CHECK([dockMap[LMMapAppliedConfig][LMConfigHideDockBackground] boolValue] && ![dockMap[LMMapIcons] count], "applied configuration carries dock visibility without app artwork");
    CHECK([LMIconMapWriter writeConfig:dockConfig icons:@{} toPath:dockMapPath forceGeneration:NO error:&error] == LMIconMapUnchanged, "startup retains unchanged dock visibility");
    CHECK([LMIconMapWriter writeConfig:emptyConfig icons:@{} toPath:dockMapPath forceGeneration:NO error:&error] == LMIconMapWritten, "restoring the dock background creates a new generation");
    dockMap = [NSDictionary dictionaryWithContentsOfFile:dockMapPath];
    CHECK(![dockMap[LMMapAppliedConfig][LMConfigHideDockBackground] boolValue], "missing dock option restores the default");
    NSMutableDictionary *appearanceConfig = [emptyConfig mutableCopy];
    appearanceConfig[LMConfigHideDockBackground] = @YES;
    appearanceConfig[LMConfigHideIconLabels] = @YES;
    CHECK([LMIconMapWriter writeConfig:appearanceConfig icons:@{} toPath:LMIconMapPath forceGeneration:NO error:&error] == LMIconMapWritten, "prepare label visibility with no icon pack");
    NSDictionary *labelMap = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
    CHECK([labelMap[LMMapAppliedConfig][LMConfigHideIconLabels] boolValue] && ![labelMap[LMMapIcons] count], "saved map carries label visibility independently of app artwork");
    CHECK([LMIconMapWriter markGenerationApplied:labelMap[@"Generation"] atPath:LMIconMapPath error:&error], "complete visibility-only Apply");
    [settings markApplied];
    CHECK(!settings.hasUnappliedChanges, "completed label change clears pending Settings status");
    settings.hideIconLabels = NO;
    CHECK(settings.hasUnappliedChanges && settings.hideDockBackground, "restoring labels leaves the dock preference unchanged");
    appearanceConfig[LMConfigHideIconLabels] = @NO;
    CHECK([LMIconMapWriter writeConfig:appearanceConfig icons:@{} toPath:LMIconMapPath forceGeneration:NO error:&error] == LMIconMapWritten, "restoring labels creates a new generation");
    labelMap = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
    CHECK(![labelMap[LMMapAppliedConfig][LMConfigHideIconLabels] boolValue] && [labelMap[LMMapAppliedConfig][LMConfigHideDockBackground] boolValue], "restored label configuration preserves dock visibility");
    CHECK([LMIconMapWriter markGenerationApplied:labelMap[@"Generation"] atPath:LMIconMapPath error:&error], "prepare applied artwork before a dock-only update");
    CHECK([LMHomeScreenOptions applyDockBackground:YES error:&error], "acknowledge the dock setting from a full Apply");
    settings = [LMConfigStore new];
    settings.enabledThemes = @[@"Apps.theme"];
    settings.hideIconLabels = YES;
    settings.hideDockBackground = NO;
    CHECK([settings save:&error], "save pending themes and labels with a dock change");
    NSData *artworkBeforeDock = [NSData dataWithContentsOfFile:LMIconMapPath];
    NSData *configBeforeDock = [NSData dataWithContentsOfFile:LMConfigPath];
    CHECK([LMHomeScreenOptions applyDockBackground:NO error:&error], "apply only the dock background");
    CHECK([[NSData dataWithContentsOfFile:LMIconMapPath] isEqual:artworkBeforeDock], "dock-only update leaves artwork, labels, tokens, and map acknowledgement byte-identical");
    CHECK([[NSData dataWithContentsOfFile:LMConfigPath] isEqual:configBeforeDock], "dock-only update leaves saved pending selections intact");
    [settings markDockApplied];
    CHECK(settings.hasUnappliedChanges, "dock-only acknowledgement never acknowledges pending themes or labels");
    NSDictionary *saved = [NSDictionary dictionaryWithContentsOfFile:LMConfigPath];
    NSDictionary *startup = [LMHomeScreenOptions startupConfig:saved map:labelMap];
    CHECK(![startup[LMConfigEnabledThemes] count] && ![startup[LMConfigHideIconLabels] boolValue], "restart refreshes current artwork without applying queued selections");
    CHECK(![[LMHomeScreenOptions configWithAppliedDockBackground:startup][LMConfigHideDockBackground] boolValue], "dock-only state survives restart independently of the icon map");
    NSDictionary *firstStartup = [LMHomeScreenOptions startupConfig:saved map:nil];
    CHECK(![firstStartup[LMConfigEnabledThemes] count] && ![firstStartup[LMConfigHideIconLabels] boolValue], "dock-only state also keeps queued themes pending before the first icon map exists");
    CHECK([[NSFileManager defaultManager] removeItemAtPath:LMConfigPath error:&error], "remove isolated settings fixture");
    CHECK([previousMap writeToFile:LMIconMapPath atomically:YES], "restore native integration map");
    CHECK([[NSFileManager defaultManager] removeItemAtPath:LMDockOptionsPath error:&error], "remove isolated dock acknowledgement");
    puts("PASS: theme categories, CC routing, partial continuation, retries, dock/label configuration, and independent dock-only updates");
  }
  return 0;
}
