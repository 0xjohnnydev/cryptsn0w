#import "LMShared.h"

@interface LMApplyPlan : NSObject
+ (NSDictionary<NSString *, NSArray *> *)invalidEntriesInMap:(NSDictionary *)map;
+ (NSUInteger)skippedCount:(NSDictionary *)skipped;
+ (BOOL)canContinueResult:(NSDictionary *)result map:(NSDictionary *)map config:(NSDictionary *)config;
@end
