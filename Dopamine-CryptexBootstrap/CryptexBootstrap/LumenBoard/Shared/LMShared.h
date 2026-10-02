#pragma once

#import <Foundation/Foundation.h>
#include <unistd.h>

#ifdef THEOS_PACKAGE_SCHEME_ROOTHIDE
#include <roothide.h>
#endif

// jailbreak path -> real path (/var/jb/... on rootless, inside the random jbroot folder on roothide)
static inline NSString *LMRootPath(NSString *path) {
#ifdef THEOS_PACKAGE_SCHEME_ROOTHIDE
  return jbroot(path);
#else
  static NSString *root;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    root = (access("/var/jb", F_OK) == 0) ? @"/var/jb" : @"";
  });
  return [root stringByAppendingString:path];
#endif
}

// real path -> jailbreak path. Used for paths we save, roothide renames the jbroot folder on every jailbreak.
static inline NSString *LMJailbreakPath(NSString *path) {
#ifdef THEOS_PACKAGE_SCHEME_ROOTHIDE
  return rootfs(path);
#else
  NSString *root = LMRootPath(@"");
  return (root.length && [path hasPrefix:[root stringByAppendingString:@"/"]]) ? [path substringFromIndex:root.length] : path;
#endif
}

#define LMThemesDirectory LMRootPath(@"/Library/Themes")
#ifdef THEOS_PACKAGE_SCHEME_ROOTHIDE
#define LMThemesDirectoryDisplayName @"/Library/Themes"
#else
#define LMThemesDirectoryDisplayName LMThemesDirectory
#endif

// Config.plist (app) and IconMap.plist (SpringBoard). Not in /var/mobile/Library/Preferences because
// iconservicesagent is sandboxed and can only read from the jailbreak folder.
#define LMDataDirectory LMRootPath(@"/var/mobile/Library/LumenBoard")
#define LMConfigPath [LMDataDirectory stringByAppendingPathComponent:@"Config.plist"]
#define LMIconMapPath [LMDataDirectory stringByAppendingPathComponent:@"IconMap.plist"]
#define LMApplyResultPath [LMDataDirectory stringByAppendingPathComponent:@"ApplyResult.plist"]
#define LMContinueRequestPath [LMDataDirectory stringByAppendingPathComponent:@"ContinueRequest.plist"]
#define LMDockOptionsPath [LMDataDirectory stringByAppendingPathComponent:@"DockOptions.plist"]

#define LMNotifyApply "com.xsxs18.lumenboard/apply"
#define LMNotifyClearCache "com.xsxs18.lumenboard/clear-cache"
#define LMNotifyMapChanged "com.xsxs18.lumenboard/map-changed"
#define LMNotifyContinue "com.xsxs18.lumenboard/continue"
#define LMNotifyApplyDock "com.xsxs18.lumenboard/apply-dock"
#define LMNotifyDockChanged "com.xsxs18.lumenboard/dock-changed"
// state = (done << 32) | total; terminal states use total as an error code.
#define LMNotifyProgress "com.xsxs18.lumenboard/progress"
#define LMProgressComplete UINT32_MAX
#define LMProgressFailed (UINT32_MAX - 1)
#define LMProgressPartial (UINT32_MAX - 2)
typedef NS_ENUM(uint32_t, LMApplyError) {
  LMApplyErrorWriteMap = 1,
  LMApplyErrorNoIcons,
  LMApplyErrorRendererUnavailable,
  LMApplyErrorRendering,
  LMApplyErrorReadConfig,
  LMApplyErrorNoMatchingApps,
  LMApplyErrorStaleAttempt,
};

// Config.plist
#define LMConfigEnabledThemes @"EnabledThemes" // theme folder names, first one wins
#define LMConfigUseSystemIconShape @"UseSystemIconShape"
#define LMConfigKeepIconsInDarkAndTinted @"KeepIconsInDarkAndTinted"
#define LMConfigHideDockBackground @"HideDockBackground"
#define LMConfigHideIconLabels @"HideIconLabels"

// Missing options in an older configuration retain their default values.
static inline NSDictionary *LMNormalizedConfig(NSDictionary *config) {
  NSArray *themes = [config[LMConfigEnabledThemes] isKindOfClass:[NSArray class]] ? config[LMConfigEnabledThemes] : @[];
  return @{
    LMConfigEnabledThemes: themes,
    LMConfigUseSystemIconShape: @([config[LMConfigUseSystemIconShape] boolValue]),
    LMConfigKeepIconsInDarkAndTinted: @([config[LMConfigKeepIconsInDarkAndTinted] boolValue]),
    LMConfigHideDockBackground: @([config[LMConfigHideDockBackground] boolValue]),
    LMConfigHideIconLabels: @([config[LMConfigHideIconLabels] boolValue]),
  };
}

static inline BOOL LMAppearanceOptionRequested(NSDictionary *before, NSDictionary *after, NSString *option) {
  BOOL hidden = [after[option] boolValue];
  return hidden || hidden != [before[option] boolValue];
}

// IconMap.plist
#define LMMapVersion 3 // jailbreak paths, CC resources, and icon effect layers
#define LMMapIcons @"Icons" // lowercased bundle id -> icon
#define LMIconLight @"Light"
#define LMIconDark @"Dark"
#define LMIconTinted @"Tinted"
#define LMIconToken @"Token" // changes whenever the icon or the settings change
#define LMMapAppliedConfig @"AppliedConfig"
#define LMMapApplied @"Applied" // set only after the requested icons rendered
#define LMMapResources @"Resources" // normalized bundle/asset -> artwork
#define LMMapIconEffects @"IconEffects"
#define LMMapSkipped @"Skipped"
#define LMEffectMask @"Mask"
#define LMEffectUnderlay @"Underlay"
#define LMEffectShadow @"Shadow"
#define LMEffectOverlay @"Overlay"
