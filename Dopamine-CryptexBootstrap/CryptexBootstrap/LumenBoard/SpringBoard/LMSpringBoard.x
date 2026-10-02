// SpringBoard: builds IconMap.plist from Config.plist and handles Apply (pre-render icons, respring)

#import "../Shared/LMThemeLibrary.h"
#import "../Shared/LMIconMapWriter.h"
#import "../Shared/LMApplyPlan.h"
#import "../Shared/LMHomeScreenOptions.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <notify.h>
#import <spawn.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <objc/message.h>
#import <objc/runtime.h>

extern BOOL LMControlCenterRenderingIsReady(void);
extern BOOL LMDockBackgroundRenderingIsReady(void);
extern BOOL LMIconLabelRenderingIsReady(void);
static BOOL LMApplying;

@interface LSApplicationProxy : NSObject
- (NSString *)applicationIdentifier;
- (NSString *)localizedName;
@end

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (NSArray<LSApplicationProxy *> *)allInstalledApplications;
@end

@interface SBSRelaunchAction : NSObject
+ (instancetype)actionWithReason:(NSString *)reason options:(NSUInteger)options targetURL:(NSURL *)url;
@end

@interface FBSSystemService : NSObject
+ (instancetype)sharedService;
- (void)sendActions:(NSSet *)actions withResult:(id)result;
@end

@interface ISIcon : NSObject
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
- (void)prepareImagesForImageDescriptors:(NSArray *)descriptors;
- (id)imageForDescriptor:(id)descriptor;
@end

@interface ISImageDescriptor : NSObject
- (instancetype)initWithSize:(CGSize)size scale:(double)scale;
- (void)setShouldApplyMask:(BOOL)shouldApplyMask;
@end

#pragma mark - Helpers

static void LMRun(NSString *tool, NSArray<NSString *> *arguments) {
  NSString *path = LMRootPath(tool);
  if (access(path.fileSystemRepresentation, X_OK) != 0) path = tool;
  const char *argv[arguments.count + 2];
  argv[0] = path.lastPathComponent.fileSystemRepresentation;
  for (NSUInteger i = 0; i < arguments.count; i++) argv[i + 1] = arguments[i].UTF8String;
  argv[arguments.count + 1] = NULL;
  pid_t pid;
  if (posix_spawn(&pid, path.fileSystemRepresentation, NULL, NULL, (char * const *)argv, NULL) == 0) {
    int status;
    waitpid(pid, &status, 0);
  }
}

// a fresh agent has the new map and no old artwork in memory
static void LMRestartIconAgent(void) {
  LMRun(@"/usr/bin/killall", @[@"-9", @"iconservicesagent"]);
}

static id LMStoreInThisProcess(void) {
  Class store = objc_getClass("LMIconStore");
  if (![store respondsToSelector:@selector(sharedStore)]) return nil;
  return ((id (*)(Class, SEL))objc_msgSend)(store, @selector(sharedStore));
}

static void LMReloadStoreInThisProcess(void) {
  id store = LMStoreInThisProcess();
  if ([store respondsToSelector:@selector(reload)]) ((void (*)(id, SEL))objc_msgSend)(store, @selector(reload));
}

#pragma mark - Icon map

// app name -> bundle ids, for Icons/<App Name>.png
static NSDictionary *LMInstalledAppNames(void) {
  NSMutableDictionary *names = [NSMutableDictionary new];
  for (LSApplicationProxy *app in [[objc_getClass("LSApplicationWorkspace") defaultWorkspace] allInstalledApplications]) {
    NSString *name = app.localizedName.lowercaseString, *bundleID = app.applicationIdentifier.lowercaseString;
    if (!name.length || !bundleID.length) continue;
    NSMutableArray *bundleIDs = names[name] ? : (names[name] = [NSMutableArray new]);
    [bundleIDs addObject:bundleID];
  }
  return names;
}

static LMIconMapWriteResult LMWriteIconMap(BOOL forceGeneration, NSError **error) {
  NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:LMConfigPath];
  if (!config && [[NSFileManager defaultManager] fileExistsAtPath:LMConfigPath]) {
    if (error) *error = [NSError errorWithDomain:@"LumenBoard" code:LMApplyErrorReadConfig userInfo:nil];
    return LMIconMapWriteFailed;
  }
  NSDictionary *previousMap = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
  config = forceGeneration ? LMNormalizedConfig(config) : [LMHomeScreenOptions startupConfig:config map:previousMap];
  NSArray *themes = [config[LMConfigEnabledThemes] isKindOfClass:[NSArray class]] ? config[LMConfigEnabledThemes] : @[];
  NSDictionary *previousConfig = previousMap[LMMapAppliedConfig];
  BOOL appearanceRequested = LMAppearanceOptionRequested(previousConfig, config, LMConfigHideDockBackground) || LMAppearanceOptionRequested(previousConfig, config, LMConfigHideIconLabels);

  [LMThemeLibrary invalidate];
  BOOL usesAppNames = NO;
  for (NSString *theme in themes) usesAppNames = usesAppNames || ([theme isKindOfClass:[NSString class]] && [LMThemeLibrary iconsByAppNameInTheme:theme].count);
  NSDictionary *icons = [LMThemeLibrary resolvedIconsForThemes:themes appNames:(usesAppNames ? LMInstalledAppNames() : nil)];
  NSDictionary *resources = [LMThemeLibrary resolvedResourcesForThemes:themes];
  if (themes.count && !icons.count && ![resources[LMMapResources] count] && ![resources[LMMapIconEffects] count] && !appearanceRequested) {
    if (error) *error = [NSError errorWithDomain:@"LumenBoard" code:LMApplyErrorNoIcons userInfo:nil];
    return LMIconMapWriteFailed;
  }

  NSDictionary *appliedConfig = LMNormalizedConfig(config);

  return [LMIconMapWriter writeConfig:appliedConfig icons:icons resources:resources[LMMapResources] effects:resources[LMMapIconEffects] toPath:LMIconMapPath forceGeneration:forceGeneration error:error];
}

#pragma mark - Apply

// progress for the app: notify state = (done << 32) | total
static void LMReportProgress(uint32_t done, uint32_t total) {
  static int token;
  static BOOL registered;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    registered = notify_register_check(LMNotifyProgress, &token) == NOTIFY_STATUS_OK;
  });
  if (!registered) return;
  notify_set_state(token, ((uint64_t)done << 32) | total);
  notify_post(LMNotifyProgress);
}

static void LMClearSystemIconCache(void) {
  for (NSString *path in @[
    @"/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache",
    @"/var/mobile/Library/Caches/com.apple.IconsCache",
    @"/var/mobile/Library/Caches/MappedImageCache/Persistent"
  ]) [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
}

// the descriptors SpringBoard uses for home screen icons, main thread only
static NSArray *LMHomeScreenDescriptors(void) {
  BOOL pad = [UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad;
  CGFloat longestSide = MAX([UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height);
  CGSize size = pad ? ((longestSide >= 1366) ? CGSizeMake(83.5, 83.5) : CGSizeMake(76, 76)) : CGSizeMake(60, 60);
  CGFloat scale = [UIScreen mainScreen].scale;
  UITraitCollection *traits = [UIScreen mainScreen].traitCollection;

  typedef id (*DescriptorFunction)(UITraitCollection *traitCollection, BOOL unmasked, double width, double height, double scale);
  DescriptorFunction springBoardDescriptor = (DescriptorFunction)dlsym(RTLD_DEFAULT, "SBHImageDescriptorWithTraitCollection");
  Class descriptorClass = objc_getClass("ISImageDescriptor");
  NSMutableArray *descriptors = [NSMutableArray new];
  for (NSNumber *unmasked in @[@YES, @NO]) {
    id descriptor = springBoardDescriptor ? springBoardDescriptor(traits, unmasked.boolValue, size.width, size.height, scale) : nil;
    if (!descriptor && [descriptorClass instancesRespondToSelector:@selector(initWithSize:scale:)]) {
      descriptor = [[descriptorClass alloc] initWithSize:size scale:scale];
      if ([descriptor respondsToSelector:@selector(setShouldApplyMask:)]) [descriptor setShouldApplyMask:!unmasked.boolValue];
    }
    if (descriptor) [descriptors addObject:descriptor];
  }
  return descriptors;
}

// apps whose icon changed, nil maps = all apps
static NSArray<NSString *> *LMAppsToRender(NSDictionary *before, NSDictionary *after) {
  NSMutableArray *bundleIDs = [NSMutableArray new];
  for (LSApplicationProxy *app in [[objc_getClass("LSApplicationWorkspace") defaultWorkspace] allInstalledApplications]) {
    NSString *bundleID = app.applicationIdentifier;
    NSString *key = bundleID.lowercaseString;
    if (!key.length) continue;
    NSDictionary *previous = before[key], *current = after[key];
    BOOL everyApp = !before && !after;
    if (everyApp || ((previous || current) && ![previous isEqual:current])) [bundleIDs addObject:bundleID];
  }
  return bundleIDs;
}

static BOOL LMIconIsCached(ISIcon *icon, NSArray *descriptors, BOOL themed) {
  id store = LMStoreInThisProcess();
  for (id descriptor in descriptors) {
    id image = [icon imageForDescriptor:descriptor];
    // IFImage -placeholder: still rendering, or the cached image is outdated
    if (!image || ([image respondsToSelector:@selector(placeholder)] && ((BOOL (*)(id, SEL))objc_msgSend)(image, @selector(placeholder)))) return NO;
    // A stock image returned after a PNG failed to decode isn't a themed render.
    if (themed && (![store respondsToSelector:@selector(isLocallyRenderedImage:)] || !((BOOL (*)(id, SEL, id))objc_msgSend)(store, @selector(isLocallyRenderedImage:), image))) return NO;
  }
  return YES;
}

// render the icons now so they don't pop in one by one after the respring
static NSDictionary *LMPrerenderIcons(NSArray<NSString *> *bundleIDs, NSArray *descriptors, NSDictionary *themedIcons, BOOL effects) {
  if (!bundleIDs.count) return @{@"Failed": @[], @"Rendered": @[]};
  Class iconClass = objc_getClass("ISIcon");
  if (!descriptors.count || ![iconClass instancesRespondToSelector:@selector(prepareImagesForImageDescriptors:)] || ![iconClass instancesRespondToSelector:@selector(imageForDescriptor:)]) return @{@"Failed": bundleIDs, @"Rendered": @[]};
  NSMutableArray *pending = [NSMutableArray new];
  NSMutableArray *failed = [NSMutableArray new], *rendered = [NSMutableArray new];
  for (NSString *bundleID in bundleIDs) {
    @autoreleasepool {
      ISIcon *icon = [[iconClass alloc] initWithBundleIdentifier:bundleID];
      if (!icon) { [failed addObject:bundleID]; continue; }
      [icon prepareImagesForImageDescriptors:descriptors];
      [pending addObject:@{@"Icon": icon, @"Bundle": bundleID, @"Themed": @(effects || themedIcons[bundleID.lowercaseString] != nil)}];
    }
  }
  uint32_t total = (uint32_t)bundleIDs.count, done = 0;
  LMReportProgress(0, total);
  CFAbsoluteTime start = CFAbsoluteTimeGetCurrent(), lastProgress = start;
  // max 60s, or 10s without progress
  while (pending.count && CFAbsoluteTimeGetCurrent() - start < 60 && CFAbsoluteTimeGetCurrent() - lastProgress < 10) {
    usleep(150 * 1000);
    NSIndexSet *cached = [pending indexesOfObjectsPassingTest:^BOOL(NSDictionary *item, NSUInteger index, BOOL *stop) {
      return LMIconIsCached(item[@"Icon"], descriptors, [item[@"Themed"] boolValue]);
    }];
    if (!cached.count) continue;
    for (NSDictionary *item in [pending objectsAtIndexes:cached]) [rendered addObject:item[@"Bundle"]];
    [pending removeObjectsAtIndexes:cached];
    done += (uint32_t)cached.count;
    lastProgress = CFAbsoluteTimeGetCurrent();
    LMReportProgress(done, total);
  }
  for (NSDictionary *item in pending) [failed addObject:item[@"Bundle"]];
  return @{@"Failed": failed, @"Rendered": rendered};
}

static void LMRespring(void) {
  Class relaunchAction = objc_getClass("SBSRelaunchAction");
  Class systemService = objc_getClass("FBSSystemService");
  if (relaunchAction && systemService) {
    id action = [relaunchAction actionWithReason:@"LumenBoardApply" options:4 targetURL:nil]; // 4: restart render server
    [[systemService sharedService] sendActions:[NSSet setWithObject:action] withResult:nil];
    return;
  }
  LMRun(@"/usr/bin/killall", @[@"-9", @"SpringBoard"]);
}

static BOOL LMWriteApplyResult(NSDictionary *result, NSError **error) {
  NSData *data = [NSPropertyListSerialization dataWithPropertyList:result format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
  if (!data || ![data writeToFile:LMApplyResultPath options:NSDataWritingAtomic error:error]) return NO;
  return chmod(LMApplyResultPath.fileSystemRepresentation, 0644) == 0;
}

static void LMEndApply(uint32_t failure, BOOL respring) {
  dispatch_async(dispatch_get_main_queue(), ^{
    LMApplying = NO;
    LMReportProgress(failure ? LMProgressFailed : LMProgressComplete, failure);
    if (respring && !failure) LMRespring();
  });
}

static void LMApply(BOOL clearCache) {
  if (LMApplying) return;
  LMApplying = YES;
  NSDictionary *beforeMap = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath] ?: @{};
  [[NSFileManager defaultManager] removeItemAtPath:LMApplyResultPath error:nil];
  [[NSFileManager defaultManager] removeItemAtPath:LMContinueRequestPath error:nil];
  LMReportProgress(0, 0);
  NSError *error = nil;
  if (![LMHomeScreenOptions appliedDockBackground]) {
    BOOL oldDock = [beforeMap[LMMapAppliedConfig][LMConfigHideDockBackground] boolValue];
    if (![LMHomeScreenOptions applyDockBackground:oldDock error:&error]) { LMEndApply(LMApplyErrorWriteMap, NO); return; }
  }
  if (LMWriteIconMap(YES, &error) == LMIconMapWriteFailed) {
    NSLog(@"[LumenBoard] icon map failed: %@", error);
    uint32_t code = [error.domain isEqual:@"LumenBoard"] ? (uint32_t)error.code : LMApplyErrorWriteMap;
    LMReportProgress(LMProgressFailed, code);
    LMApplying = NO;
    return;
  }
  NSDictionary *map = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
  id store = LMStoreInThisProcess();
  BOOL localReady = [store respondsToSelector:@selector(canRenderIconsLocally)] && ((BOOL (*)(id, SEL))objc_msgSend)(store, @selector(canRenderIconsLocally));
  BOOL ccReady = LMControlCenterRenderingIsReady() && [store respondsToSelector:@selector(resourceForKey:)];
  BOOL dockRequested = LMAppearanceOptionRequested([LMHomeScreenOptions configWithAppliedDockBackground:beforeMap[LMMapAppliedConfig]], map[LMMapAppliedConfig], LMConfigHideDockBackground);
  BOOL dockReady = LMDockBackgroundRenderingIsReady();
  BOOL labelsRequested = LMAppearanceOptionRequested(beforeMap[LMMapAppliedConfig], map[LMMapAppliedConfig], LMConfigHideIconLabels);
  BOOL labelsReady = LMIconLabelRenderingIsReady();
  NSArray *descriptors = LMHomeScreenDescriptors();
  NSArray *unsupported = [LMThemeLibrary resolvedResourcesForThemes:map[LMMapAppliedConfig][LMConfigEnabledThemes]][@"UnsupportedThemes"];
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    NSMutableDictionary *skipped = [[LMApplyPlan invalidEntriesInMap:map] mutableCopy];
    if (unsupported.count) skipped[@"Themes"] = unsupported;
    if (!localReady) {
      if ([map[LMMapIcons] count]) skipped[LMMapIcons] = [map[LMMapIcons] allKeys];
      if ([map[LMMapIconEffects] count]) skipped[LMMapIconEffects] = [map[LMMapIconEffects] allKeys];
    }
    if (!ccReady && [map[LMMapResources] count]) skipped[LMMapResources] = [map[LMMapResources] allKeys];
    NSMutableArray *badAppearance = [NSMutableArray new];
    if (dockRequested && !dockReady) [badAppearance addObject:@"Dock background"];
    if (labelsRequested && !labelsReady) [badAppearance addObject:@"Icon labels"];
    if (badAppearance.count) skipped[@"Appearance"] = badAppearance;
    NSError *commitError = nil;
    // Remove bad layers before rendering; one broken mask must not break every app.
    if ([LMApplyPlan skippedCount:skipped] && ![LMIconMapWriter updateGeneration:map[@"Generation"] excluding:skipped applied:NO atPath:LMIconMapPath error:&commitError]) {
      LMEndApply(LMApplyErrorWriteMap, NO);
      return;
    }
    NSDictionary *filtered = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
    NSDictionary *after = filtered[LMMapIcons] ?: @{};
    BOOL effects = [filtered[LMMapIconEffects] count] > 0;
    LMReloadStoreInThisProcess();
    notify_post(LMNotifyMapChanged);
    if (clearCache) LMClearSystemIconCache();
    if (clearCache) { LMRestartIconAgent(); usleep(300 * 1000); }
    NSArray *apps = clearCache || effects || [beforeMap[LMMapIconEffects] count] ? LMAppsToRender(nil, nil) : LMAppsToRender(beforeMap[LMMapIcons] ?: @{}, after);
    NSDictionary *render = LMPrerenderIcons(apps, descriptors, after, effects);
    NSMutableArray *badIcons = [skipped[LMMapIcons] mutableCopy] ?: [NSMutableArray new];
    NSMutableArray *otherApps = [NSMutableArray new];
    for (NSString *bundleID in render[@"Failed"]) {
      NSString *key = bundleID.lowercaseString;
      if (effects || after[key]) { if (![badIcons containsObject:key]) [badIcons addObject:key]; }
      else [otherApps addObject:bundleID];
    }
    if (badIcons.count) skipped[LMMapIcons] = badIcons;
    if (otherApps.count) skipped[@"OtherApps"] = otherApps;
    NSUInteger renderedThemes = 0;
    for (NSString *bundleID in render[@"Rendered"]) if (effects || after[bundleID.lowercaseString]) renderedThemes++;
    NSUInteger good = [filtered[LMMapResources] count] + renderedThemes;
    if (dockRequested && dockReady) good++;
    if (labelsRequested && labelsReady) good++;
    if (effects && renderedThemes) good += [filtered[LMMapIconEffects] count];
    if (![map[LMMapAppliedConfig][LMConfigEnabledThemes] count]) good += [render[@"Rendered"] count];
    NSUInteger failed = [LMApplyPlan skippedCount:skipped];
    if (!good && ([map[LMMapIcons] count] || [map[LMMapResources] count] || [map[LMMapIconEffects] count] || failed)) {
      uint32_t failure = !localReady || !ccReady || badAppearance.count ? LMApplyErrorRendererUnavailable : (failed ? LMApplyErrorRendering : LMApplyErrorNoMatchingApps);
      LMEndApply(failure, NO);
      return;
    }
    NSDictionary *result = @{@"Generation": map[@"Generation"], @"State": failed ? @"Partial" : @"Complete", @"SuccessCount": @(good), @"FailedCount": @(failed), LMMapSkipped: skipped};
    if (failed) {
      if (!LMWriteApplyResult(result, &commitError)) { LMEndApply(LMApplyErrorWriteMap, NO); return; }
      dispatch_async(dispatch_get_main_queue(), ^{ LMApplying = NO; LMReportProgress(LMProgressPartial, (uint32_t)failed); });
      return;
    }
    if (![LMIconMapWriter markGenerationApplied:map[@"Generation"] atPath:LMIconMapPath error:&commitError]) { LMEndApply(LMApplyErrorWriteMap, NO); return; }
    if (dockReady && ![LMHomeScreenOptions applyDockBackground:[map[LMMapAppliedConfig][LMConfigHideDockBackground] boolValue] error:&commitError]) { LMEndApply(LMApplyErrorWriteMap, NO); return; }
    if (dockReady) notify_post(LMNotifyDockChanged);
    LMWriteApplyResult(result, nil);
    LMEndApply(0, YES);
  });
}

static void LMContinueApply(void) {
  if (LMApplying) return;
  LMApplying = YES;
  LMReportProgress(0, 0);
  NSDictionary *request = [NSDictionary dictionaryWithContentsOfFile:LMContinueRequestPath];
  NSDictionary *result = [NSDictionary dictionaryWithContentsOfFile:LMApplyResultPath];
  NSDictionary *map = [NSDictionary dictionaryWithContentsOfFile:LMIconMapPath];
  NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:LMConfigPath];
  [[NSFileManager defaultManager] removeItemAtPath:LMContinueRequestPath error:nil];
  if (![request[@"Generation"] isEqual:result[@"Generation"]] || ![LMApplyPlan canContinueResult:result map:map config:config]) {
    LMApplying = NO;
    LMReportProgress(LMProgressFailed, LMApplyErrorStaleAttempt);
    return;
  }
  NSError *error = nil;
  if (![LMIconMapWriter markGenerationApplied:result[@"Generation"] skipping:result[LMMapSkipped] atPath:LMIconMapPath error:&error]) {
    LMApplying = NO;
    LMReportProgress(LMProgressFailed, LMApplyErrorWriteMap);
    return;
  }
  if (LMDockBackgroundRenderingIsReady() && ![result[LMMapSkipped][@"Appearance"] containsObject:@"Dock background"]) {
    if (![LMHomeScreenOptions applyDockBackground:[map[LMMapAppliedConfig][LMConfigHideDockBackground] boolValue] error:&error]) { LMEndApply(LMApplyErrorWriteMap, NO); return; }
    notify_post(LMNotifyDockChanged);
  }
  NSMutableDictionary *complete = [result mutableCopy];
  complete[@"State"] = @"Complete";
  LMWriteApplyResult(complete, nil);
  LMReloadStoreInThisProcess();
  notify_post(LMNotifyMapChanged);
  LMApplying = NO;
  LMReportProgress(LMProgressComplete, (uint32_t)[LMApplyPlan skippedCount:result[LMMapSkipped]]);
  LMRespring();
}

static void LMApplyDockOnly(void) {
  if (LMApplying) return;
  LMApplying = YES;
  LMReportProgress(0, 0);
  if (!LMDockBackgroundRenderingIsReady()) { LMEndApply(LMApplyErrorRendererUnavailable, NO); return; }
  NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:LMConfigPath];
  if (!config && [[NSFileManager defaultManager] fileExistsAtPath:LMConfigPath]) { LMEndApply(LMApplyErrorReadConfig, NO); return; }
  NSError *error = nil;
  if (![LMHomeScreenOptions applyDockBackground:[config[LMConfigHideDockBackground] boolValue] error:&error]) { LMEndApply(LMApplyErrorWriteMap, NO); return; }
  notify_post(LMNotifyDockChanged);
  LMEndApply(0, NO);
}

static void LMApplyNotification(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
  BOOL clearCache = CFEqual(name, CFSTR(LMNotifyClearCache));
  BOOL continuation = CFEqual(name, CFSTR(LMNotifyContinue));
  BOOL dockOnly = CFEqual(name, CFSTR(LMNotifyApplyDock));
  dispatch_async(dispatch_get_main_queue(), ^{ if (dockOnly) LMApplyDockOnly(); else if (continuation) LMContinueApply(); else LMApply(clearCache); });
}

%ctor {
  @autoreleasepool {
    if (![[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){17, 0, 0}]) return;
    // themes might have been updated by the package manager
    NSError *error = nil;
    LMIconMapWriteResult result = LMWriteIconMap(NO, &error);
    if (result == LMIconMapWritten) {
      LMReloadStoreInThisProcess();
      notify_post(LMNotifyMapChanged);
    }
    if (result == LMIconMapWriteFailed) NSLog(@"[LumenBoard] startup map failed: %@", error);
    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationCenterAddObserver(center, NULL, LMApplyNotification, CFSTR(LMNotifyApply), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(center, NULL, LMApplyNotification, CFSTR(LMNotifyClearCache), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(center, NULL, LMApplyNotification, CFSTR(LMNotifyContinue), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(center, NULL, LMApplyNotification, CFSTR(LMNotifyApplyDock), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
  }
}
