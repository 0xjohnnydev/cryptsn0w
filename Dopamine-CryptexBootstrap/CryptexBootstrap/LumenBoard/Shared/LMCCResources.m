#import "LMCCResources.h"
#import "LMThemeLibrary.h"

@implementation LMCCResources
+ (BOOL)isControlCenterBundle:(NSString *)identifier {
  NSString *name = identifier.lowercaseString;
  return [name containsString:@"control-center"] || [name containsString:@"controlcenter"] || [name isEqual:@"com.apple.mediacontrols"];
}

+ (NSString *)normalizedName:(NSString *)name {
  if (![name isKindOfClass:[NSString class]] || !name.length) return @"";
  NSString *stem = [LMThemeLibrary resourceKeyForBundle:@"" name:name.lastPathComponent].lastPathComponent;
  NSString *parent = name.stringByDeletingLastPathComponent.lowercaseString;
  return parent.length ? [parent stringByAppendingPathComponent:stem] : stem;
}

+ (NSArray<NSString *> *)keysForName:(NSString *)name bundle:(NSString *)identifier folder:(NSString *)folder shared:(BOOL)shared {
  NSString *stem = [self normalizedName:name];
  if (!stem.length) return @[];
  NSMutableArray *keys = [NSMutableArray new];
  if (identifier.length) [keys addObject:[NSString stringWithFormat:@"bundles/%@/%@", identifier.lowercaseString, stem]];
  if (shared && folder.length) [keys addObject:[NSString stringWithFormat:@"folders/%@/%@", folder.lowercaseString, stem]];
  if (shared) [keys addObject:[@"uiimages/" stringByAppendingString:stem]];
  return keys;
}

+ (NSArray<NSString *> *)keysForSymbol:(NSString *)symbol {
  NSMutableArray *keys = [[self keysForName:symbol bundle:nil folder:nil shared:YES] mutableCopy];
  NSDictionary *media = @{@"speaker.wave.1.fill": @"volume.1.fill", @"speaker.wave.2.fill": @"volume.3.fill", @"speaker.wave.3.fill": @"volume.3.fill"};
  if (media[symbol]) [keys addObject:[@"uiimages/" stringByAppendingString:media[symbol]]];
  static NSDictionary *aliases;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    aliases = @{
      @"airplane": @[@"ConnectivityModule", @"AirplaneGlyph"],
      @"wifi": @[@"ConnectivityModule", @"WiFiGlyph"],
      @"wifi.slash": @[@"ConnectivityModule", @"WiFiGlyph"],
      @"antenna.radiowaves.left.and.right": @[@"ConnectivityModule", @"CellularDataGlyph"],
      @"airdrop": @[@"ConnectivityModule", @"AirDropGlyph"],
      @"personalhotspot": @[@"ConnectivityModule", @"HotspotGlyph"],
      @"flashlight.off.fill": @[@"FlashlightModule", @"FlashlightOff"],
      @"flashlight.on.fill": @[@"FlashlightModule", @"FlashlightOn"],
      @"calculator": @[@"CalculatorModule", @"AppIcon"],
      @"camera.fill": @[@"CameraModule", @"AppIcon"],
      @"alarm.fill": @[@"AlarmModule", @"AppIcon"],
      @"sun.max.fill": @[@"DisplayModule", @"BrightnessGlyph"],
      @"mic.fill": @[@"VoiceMemosModule", @"AppIcon"],
    };
  });
  NSArray *alias = aliases[symbol.lowercaseString];
  if (alias) [keys addObject:[LMThemeLibrary resourceKeyForBundle:[@"com.apple.control-center." stringByAppendingString:alias[0]] name:alias[1]]];
  return keys;
}

+ (NSArray<NSString *> *)glyphNamesForBundle:(NSString *)identifier selected:(BOOL)selected {
  NSString *module = identifier.lowercaseString;
  if ([module hasSuffix:@".flashlightmodule"]) return @[selected ? @"FlashlightOn" : @"FlashlightOff", @"ModuleIcon"];
  if ([module hasSuffix:@".displaymodule"]) return @[@"BrightnessGlyph", @"ModuleIcon"];
  if ([module hasSuffix:@".mutemodule"]) return @[selected ? @"Mute" : @"Ring", @"ModuleIcon"];
  return @[@"ModuleIcon", @"AppIcon"];
}
@end
