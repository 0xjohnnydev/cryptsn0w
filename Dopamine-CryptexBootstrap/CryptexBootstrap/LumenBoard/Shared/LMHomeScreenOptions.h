#import "LMShared.h"

@interface LMHomeScreenOptions : NSObject
+ (NSNumber *)appliedDockBackground;
+ (BOOL)applyDockBackground:(BOOL)hidden error:(NSError **)error;
+ (NSDictionary *)configWithAppliedDockBackground:(NSDictionary *)config;
+ (NSDictionary *)startupConfig:(NSDictionary *)saved map:(NSDictionary *)map;
@end
