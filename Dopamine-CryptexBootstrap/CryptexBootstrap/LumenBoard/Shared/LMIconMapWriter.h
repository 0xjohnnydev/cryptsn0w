#import "LMShared.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, LMIconMapWriteResult) {
  LMIconMapWriteFailed = -1,
  LMIconMapUnchanged = 0,
  LMIconMapWritten = 1,
};

@interface LMIconMapWriter : NSObject
+ (LMIconMapWriteResult)writeConfig:(NSDictionary *)config
                             icons:(NSDictionary<NSString *, NSDictionary *> *)icons
                            toPath:(NSString *)path
                   forceGeneration:(BOOL)forceGeneration
                             error:(NSError **)error;
+ (LMIconMapWriteResult)writeConfig:(NSDictionary *)config icons:(NSDictionary *)icons resources:(NSDictionary *)resources effects:(NSDictionary *)effects toPath:(NSString *)path forceGeneration:(BOOL)forceGeneration error:(NSError **)error;
+ (BOOL)markGenerationApplied:(NSString *)generation atPath:(NSString *)path error:(NSError **)error;
+ (BOOL)markGenerationApplied:(NSString *)generation skipping:(NSDictionary<NSString *, NSArray *> *)skipped atPath:(NSString *)path error:(NSError **)error;
+ (BOOL)updateGeneration:(NSString *)generation excluding:(NSDictionary<NSString *, NSArray *> *)skipped applied:(BOOL)applied atPath:(NSString *)path error:(NSError **)error;
@end

NS_ASSUME_NONNULL_END
