#import "../Shared/LMShared.h"
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

// Decoded artwork belongs to a map token, not just to a filename. Theme packages
// can replace a PNG in place while a client still has the old pixels cached.
@interface LMIconArtwork : NSObject
+ (instancetype)sharedCache;
- (nullable CGImageRef)copyImageForEntry:(NSDictionary *)entry
                                  size:(CGSize)size
                                 scale:(CGFloat)scale
                            appearance:(NSInteger)appearance
                             applyMask:(BOOL)applyMask CF_RETURNS_RETAINED;
- (nullable CGImageRef)copyImageForEntry:(NSDictionary *)entry size:(CGSize)size scale:(CGFloat)scale appearance:(NSInteger)appearance applyMask:(BOOL)applyMask effects:(NSDictionary *)effects CF_RETURNS_RETAINED;
- (nullable CGImageRef)copyImageFromImage:(CGImageRef)image cacheKey:(NSArray *)key size:(CGSize)size scale:(CGFloat)scale appearance:(NSInteger)appearance applyMask:(BOOL)applyMask effects:(NSDictionary *)effects CF_RETURNS_RETAINED;
- (void)invalidate;
@end

NS_ASSUME_NONNULL_END
