#import "LMShared.h"

// Resource names used by Control Center themes. This resolver only chooses
// keys; the SpringBoard client decides whether a request belongs to CC.
@interface LMCCResources : NSObject
+ (BOOL)isControlCenterBundle:(NSString *)identifier;
+ (NSString *)normalizedName:(NSString *)name;
+ (NSArray<NSString *> *)keysForName:(NSString *)name bundle:(NSString *)identifier folder:(NSString *)folder shared:(BOOL)shared;
+ (NSArray<NSString *> *)keysForSymbol:(NSString *)symbol;
+ (NSArray<NSString *> *)glyphNamesForBundle:(NSString *)identifier selected:(BOOL)selected;
@end
