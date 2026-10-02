#import "../Shared/LMShared.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSNotificationName const LMConfigAppliedDidChangeNotification;

// Config.plist is shared with SpringBoard, which builds the icon map on Apply.
@interface LMConfigStore : NSObject

+ (instancetype)sharedStore;
// theme folder names, highest priority first
@property (nonatomic, copy) NSArray<NSString *> *enabledThemes;
@property (nonatomic) BOOL useSystemIconShape;
@property (nonatomic) BOOL keepIconsInDarkAndTinted;
@property (nonatomic) BOOL hideDockBackground;
@property (nonatomic) BOOL hideIconLabels;
// changed since the last apply
@property (nonatomic, readonly) BOOL hasUnappliedChanges;
@property (nonatomic, readonly) NSUInteger appliedSkippedCount;

- (BOOL)save:(NSError **)error;
- (void)markApplied;
- (void)markDockApplied;

@end

NS_ASSUME_NONNULL_END
