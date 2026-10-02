// Keep the upstream providers, and render locally in SpringBoard/Settings.
// This bootstrap runs the stock icon service, which cannot render our providers.

#import "LMIconStore.h"
#import "LMIconArtwork.h"
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <ImageIO/ImageIO.h>
#import <CommonCrypto/CommonDigest.h>

@interface ISConcreteIcon : NSObject
- (NSUUID *)digest;
@end

@interface ISBundleIdentifierIcon : ISConcreteIcon
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
- (NSString *)bundleIdentifier;
@end

@interface ISBundleIcon : ISConcreteIcon
- (instancetype)initWithBundleURL:(NSURL *)url type:(NSString *)type tag:(NSString *)tag tagClass:(NSString *)tagClass;
- (NSURL *)url;
@end

@interface ISApplicationIdentityIcon : ISConcreteIcon
- (instancetype)initWithApplicationIdentity:(id)identity;
- (NSString *)identityString;
@end

@interface ISResourceProvider : NSObject
- (instancetype)initWithResource:(id)resource templateResource:(id)templateResource;
- (void)setResourceType:(unsigned long long)resourceType;
- (void)setAllowNonDefaultAppearances:(BOOL)allow;
- (void)setAllowAlterationsToResourceArt:(BOOL)allow;
- (void)setIconResource:(id)resource;
- (void)setSuggestedRecipe:(id)recipe;
@end

@interface IFImage : NSObject
- (instancetype)initWithCGImage:(CGImageRef)image scale:(double)scale;
@end

@interface IFImageBag : NSObject
- (instancetype)initWithImages:(NSArray *)images;
@end

@interface LSApplicationRecord : NSObject
- (instancetype)initWithURL:(NSURL *)url allowPlaceholder:(BOOL)allowPlaceholder error:(NSError **)error;
- (NSString *)bundleIdentifier;
@end

@interface LSApplicationIdentity : NSObject
- (instancetype)initWithIdentityString:(NSString *)identityString;
- (NSString *)bundleIdentifier;
@end

static BOOL LMHooksInstalled;
static BOOL LMLocalHooksInstalled;
static Ivar LMDigestIvar;
static Class LMProviderClass;
static Class LMRecipeClass;
static NSCache *LMImageBags;
static NSCache *LMAppURLIdentifiers;
static char LMIconEntryKey;
static char LMLocalArtworkKey;
static _Thread_local BOOL LMReadingStockImage;

#pragma mark - Digests

static NSUUID *LMThemedDigest(NSUUID *stockDigest, NSString *token) {
  uuid_t bytes;
  [stockDigest getUUIDBytes:bytes];
  NSData *tokenData = [token dataUsingEncoding:NSUTF8StringEncoding];
  CC_SHA256_CTX context;
  CC_SHA256_Init(&context);
  CC_SHA256_Update(&context, "lumenboard-theme-icon", 21);
  CC_SHA256_Update(&context, bytes, sizeof(bytes));
  CC_SHA256_Update(&context, tokenData.bytes, (CC_LONG)tokenData.length);
  unsigned char hash[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(hash, &context);
  // shaped like a name-based (v5) UUID
  hash[6] = (hash[6] & 0x0F) | 0x50;
  hash[8] = (hash[8] & 0x3F) | 0x80;
  return [[NSUUID alloc] initWithUUIDBytes:hash];
}

static void LMMarkThemed(ISConcreteIcon *icon, NSString *bundleIdentifier) {
  if (!icon) return;
  NSDictionary *entry = [[LMIconStore sharedStore] iconForBundleIdentifier:bundleIdentifier];
  if (!entry) return;
  id stockDigest = object_getIvar(icon, LMDigestIvar);
  if (![stockDigest isKindOfClass:[NSUUID class]]) return;
  object_setIvarWithStrongDefault(icon, LMDigestIvar, LMThemedDigest(stockDigest, entry[LMIconToken]));
}

static NSString *LMBundleIdentifierForAppURL(NSURL *url) {
  if (!url.isFileURL || [url.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) return nil;
  NSString *cached = [LMAppURLIdentifiers objectForKey:url.path];
  if (cached) return cached.length ? cached : nil;
  NSString *bundleIdentifier = nil;
  Class recordClass = objc_getClass("LSApplicationRecord");
  if ([recordClass instancesRespondToSelector:@selector(initWithURL:allowPlaceholder:error:)])
    bundleIdentifier = [[[recordClass alloc] initWithURL:url allowPlaceholder:YES error:nil] bundleIdentifier];
  if (!bundleIdentifier) bundleIdentifier = [NSBundle bundleWithURL:url].bundleIdentifier;
  [LMAppURLIdentifiers setObject:(bundleIdentifier ? : @"") forKey:url.path];
  return bundleIdentifier;
}

static NSString *LMBundleIdentifierForIdentity(id identity) {
  return [identity respondsToSelector:@selector(bundleIdentifier)] ? [identity bundleIdentifier] : nil;
}

#pragma mark - Artwork

static id LMImageBag(NSString *path, NSString *token) {
  if (!path.length || !token.length) return nil;
  NSArray *key = @[path, token];
  id bag = [LMImageBags objectForKey:key];
  if (bag) return bag;

  CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:path isDirectory:NO], NULL);
  CGImageRef image = (source && CGImageSourceGetCount(source)) ? CGImageSourceCreateImageAtIndex(source, 0, NULL) : NULL;
  if (source) CFRelease(source);
  if (!image) return nil;

  NSString *name = path.lastPathComponent.lowercaseString;
  double scale = [name containsString:@"@3x"] ? 3.0 : ([name containsString:@"@2x"] ? 2.0 : 1.0);
  IFImage *artwork = (CGImageGetWidth(image) && CGImageGetHeight(image)) ? [[objc_getClass("IFImage") alloc] initWithCGImage:image scale:scale] : nil;
  CGImageRelease(image);
  if (!artwork) return nil;

  bag = [[objc_getClass("IFImageBag") alloc] initWithImages:@[artwork]];
  if (bag) [LMImageBags setObject:bag forKey:key];
  return bag;
}

// LMThemeIconProvider: use the theme's -dark / -tinted png if there is one
static void LMProviderConfigure(ISResourceProvider *self, SEL _cmd, id descriptor) {
  NSDictionary *entry = objc_getAssociatedObject(self, &LMIconEntryKey);
  long long appearance = [descriptor respondsToSelector:@selector(appearance)] ? ((long long (*)(id, SEL))objc_msgSend)(descriptor, @selector(appearance)) : 0;
  NSString *variant = (appearance == 1) ? entry[LMIconDark] : ((appearance == 2) ? entry[LMIconTinted] : nil);
  id bag = LMImageBag(variant.length ? variant : entry[LMIconLight], entry[LMIconToken]);
  if (bag) {
    [self setIconResource:bag];
    // the theme drew this appearance itself, don't let iOS derive it again
    if ([self respondsToSelector:@selector(setAllowAlterationsToResourceArt:)]) [self setAllowAlterationsToResourceArt:!variant.length];
  }
  struct objc_super superclass = { self, class_getSuperclass(LMProviderClass) };
  ((void (*)(struct objc_super *, SEL, id))objc_msgSendSuper)(&superclass, _cmd, descriptor);
}

// LMThemeIconRecipe: app icon recipe without the mask
static BOOL LMRecipeShouldApplyMask(id self, SEL _cmd) {
  return NO;
}

// and without the white/black plate behind the icon
static id LMRecipePrimaryEffect(id self, SEL _cmd, id __autoreleasing *backgroundContent) {
  struct objc_super superclass = { self, class_getSuperclass(LMRecipeClass) };
  id effect = ((id (*)(struct objc_super *, SEL, id __autoreleasing *))objc_msgSendSuper)(&superclass, _cmd, backgroundContent);
  if (backgroundContent) *backgroundContent = nil;
  return effect;
}

static ISResourceProvider *LMMakeProvider(NSDictionary *entry) {
  id bag = LMImageBag(entry[LMIconLight], entry[LMIconToken]);
  if (!bag || !LMProviderClass) return nil;
  ISResourceProvider *provider = [[LMProviderClass alloc] initWithResource:bag templateResource:nil];
  if (!provider) return nil;
  objc_setAssociatedObject(provider, &LMIconEntryKey, entry, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

  LMIconStore *store = [LMIconStore sharedStore];
  // 1 = app icon
  if ([provider respondsToSelector:@selector(setResourceType:)]) [provider setResourceType:1];
  if ([provider respondsToSelector:@selector(setAllowNonDefaultAppearances:)]) [provider setAllowNonDefaultAppearances:!store.keepsIconsInDarkAndTinted];
  if ([provider respondsToSelector:@selector(setAllowAlterationsToResourceArt:)]) [provider setAllowAlterationsToResourceArt:YES];
  // only used if the descriptor doesn't ask for a shape itself
  if (!store.usesSystemIconShape && LMRecipeClass && [provider respondsToSelector:@selector(setSuggestedRecipe:)]) [provider setSuggestedRecipe:[LMRecipeClass new]];
  return provider;
}

// only for requests with the themed digest, a process without the tweak wants the stock icon
static ISResourceProvider *LMProviderForRequest(ISConcreteIcon *request, NSString *bundleIdentifier, ISConcreteIcon *(^themedTwin)(void)) {
  if (!bundleIdentifier) return nil;
  // the requesting process may already use a newer map
  [[LMIconStore sharedStore] reloadIfMapChanged];
  NSDictionary *entry = [[LMIconStore sharedStore] iconForBundleIdentifier:bundleIdentifier];
  if (!entry) return nil;
  NSUUID *expected = [themedTwin() digest];
  if (!expected || ![expected isEqual:[request digest]]) return nil;
  return LMMakeProvider(entry);
}

#pragma mark - Local rendering

static BOOL LMIsLocalRenderingProcess(void) {
  static BOOL local;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    NSString *bundle = [NSBundle mainBundle].bundleIdentifier;
    local = [bundle isEqual:@"com.apple.springboard"] || [bundle isEqual:@"com.apple.Preferences"];
  });
  return local;
}

BOOL LMLocalIconRenderingIsReady(void) { return LMLocalHooksInstalled; }
BOOL LMImageWasRenderedLocally(id image) { return [objc_getAssociatedObject(image, &LMLocalArtworkKey) boolValue]; }

static id LMLocalImage(id icon, id descriptor) {
  if (LMReadingStockImage || !LMLocalHooksInstalled || ![descriptor respondsToSelector:@selector(size)] || ![descriptor respondsToSelector:@selector(scale)]) return nil;
  NSString *bundleID = nil;
  if ([icon respondsToSelector:@selector(bundleIdentifier)]) bundleID = [icon bundleIdentifier];
  else if ([icon respondsToSelector:@selector(url)]) {
    // Only application artwork, never a bundle's symbol or tagged resource.
    for (NSString *name in @[@"type", @"tag", @"tagClass"]) {
      SEL selector = NSSelectorFromString(name);
      if ([icon respondsToSelector:selector] && ((id (*)(id, SEL))objc_msgSend)(icon, selector)) return nil;
    }
    bundleID = LMBundleIdentifierForAppURL([icon url]);
  } else if ([icon respondsToSelector:@selector(identityString)]) {
    Class identityClass = objc_getClass("LSApplicationIdentity");
    if ([identityClass instancesRespondToSelector:@selector(initWithIdentityString:)]) {
      id identity = [[identityClass alloc] initWithIdentityString:[icon identityString]];
      bundleID = LMBundleIdentifierForIdentity(identity);
    }
  }
  LMIconStore *store = [LMIconStore sharedStore];
  [store reloadIfMapChanged];
  if ([store shouldSkipBundleIdentifier:bundleID]) return nil;
  NSDictionary *entry = [store iconForBundleIdentifier:bundleID];
  NSDictionary *effects = store.iconEffects;
  BOOL decoratesStock = effects.count > 0;
  if (store.usesSystemIconShape && effects[LMEffectMask]) {
    NSMutableDictionary *layers = [effects mutableCopy];
    [layers removeObjectForKey:LMEffectMask];
    effects = layers;
  }
  if (!bundleID.length || (!entry && !decoratesStock)) return nil;
  CGSize size = ((CGSize (*)(id, SEL))objc_msgSend)(descriptor, @selector(size));
  double scale = ((double (*)(id, SEL))objc_msgSend)(descriptor, @selector(scale));
  NSInteger appearance = [descriptor respondsToSelector:@selector(appearance)] ? ((NSInteger (*)(id, SEL))objc_msgSend)(descriptor, @selector(appearance)) : 0;
  BOOL mask = store.usesSystemIconShape && (![descriptor respondsToSelector:@selector(shouldApplyMask)] || ((BOOL (*)(id, SEL))objc_msgSend)(descriptor, @selector(shouldApplyMask)));
  CGImageRef image = NULL;
  if (entry) {
    image = [[LMIconArtwork sharedCache] copyImageForEntry:entry size:size scale:scale appearance:appearance applyMask:mask effects:effects];
  } else if ([icon respondsToSelector:@selector(CGImageForDescriptor:)]) {
    // A shape pack can also decorate the original app artwork. Fetch the
    // original through the same client API, with recursion disabled per thread.
    CGImageRef stock = NULL;
    id stockDescriptor = descriptor;
    if (effects[LMEffectMask] && [descriptor respondsToSelector:@selector(copyWithZone:)]) {
      id unmasked = [descriptor copy];
      if ([unmasked respondsToSelector:@selector(setShouldApplyMask:)]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(unmasked, @selector(setShouldApplyMask:), NO);
        stockDescriptor = unmasked;
      }
    }
    LMReadingStockImage = YES;
    @try {
      id stockImage = ((id (*)(id, SEL, id))objc_msgSend)(icon, @selector(imageForDescriptor:), stockDescriptor);
      BOOL placeholder = [stockImage respondsToSelector:@selector(placeholder)] && ((BOOL (*)(id, SEL))objc_msgSend)(stockImage, @selector(placeholder));
      if (stockImage && !placeholder) {
        CGImageRef borrowed = ((CGImageRef (*)(id, SEL, id))objc_msgSend)(icon, @selector(CGImageForDescriptor:), stockDescriptor);
        if (borrowed) stock = CGImageRetain(borrowed);
      }
    } @finally { LMReadingStockImage = NO; }
    if (stock) {
      NSString *digest = [icon respondsToSelector:@selector(digest)] ? [[icon digest] UUIDString] : @"";
      image = [[LMIconArtwork sharedCache] copyImageFromImage:stock cacheKey:@[@"stock", bundleID, digest ?: @""] size:size scale:scale appearance:appearance applyMask:mask effects:effects];
      CGImageRelease(stock);
    }
  }
  if (!image) return nil;
  id artwork = [[objc_getClass("IFImage") alloc] initWithCGImage:image scale:scale];
  CGImageRelease(image);
  if (artwork) objc_setAssociatedObject(artwork, &LMLocalArtworkKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  return artwork;
}

%group LocalImages
%hook ISConcreteIcon
- (id)imageForDescriptor:(id)descriptor { return LMLocalImage(self, descriptor) ?: %orig; }
%end
%end

%group LocalCachedImages
%hook ISConcreteIcon
- (id)_cachedImageForDescriptor:(id)descriptor { return LMLocalImage(self, descriptor) ?: %orig; }
%end
%end

%group LocalCompatibilityImages
%hook ISConcreteIcon
- (id)imageForImageDescriptor:(id)descriptor { return LMLocalImage(self, descriptor) ?: %orig; }
%end
%end

static BOOL LMHasImageMethod(Class cls, SEL selector) {
  Method method = class_getInstanceMethod(cls, selector);
  if (!method || method_getNumberOfArguments(method) != 3) return NO;
  char type[16];
  method_getReturnType(method, type, sizeof(type));
  if (type[0] != '@') return NO;
  method_getArgumentType(method, 2, type, sizeof(type));
  return type[0] == '@';
}

static void LMInstallLocalIconHooks(void) {
  if (LMLocalHooksInstalled || !LMIsLocalRenderingProcess()) return;
  Class icon = objc_getClass("ISConcreteIcon");
  Class image = objc_getClass("IFImage");
  if (!LMHasImageMethod(icon, @selector(imageForDescriptor:)) || ![image instancesRespondToSelector:@selector(initWithCGImage:scale:)]) return;
  if (!LMAppURLIdentifiers) LMAppURLIdentifiers = [NSCache new];
  %init(LocalImages);
  if (LMHasImageMethod(icon, @selector(_cachedImageForDescriptor:))) { %init(LocalCachedImages); }
  if (LMHasImageMethod(icon, @selector(imageForImageDescriptor:))) { %init(LocalCompatibilityImages); }
  LMLocalHooksInstalled = YES;
  NSLog(@"[LumenBoard] local icon renderer ready in %@", [NSBundle mainBundle].bundleIdentifier);
}

#pragma mark - Provider hooks

%group Icons

%hook ISBundleIdentifierIcon

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier {
  self = %orig;
  LMMarkThemed(self, bundleIdentifier);
  return self;
}

// allowFallback NO = -makeSymbolResourceProvider, leave it alone
- (id)_makeResourceProviderAllowIconResourceFallback:(BOOL)allowFallback {
  if (allowFallback) {
    NSString *bundleIdentifier = [self bundleIdentifier];
    ISResourceProvider *provider = LMProviderForRequest(self, bundleIdentifier, ^ISConcreteIcon *{
      return [[%c(ISBundleIdentifierIcon) alloc] initWithBundleIdentifier:bundleIdentifier];
    });
    if (provider) return provider;
  }
  return %orig;
}

%end

%hook ISBundleIcon

- (instancetype)initWithBundleURL:(NSURL *)url type:(NSString *)type tag:(NSString *)tag tagClass:(NSString *)tagClass {
  self = %orig;
  // no type/tag = the app icon of the bundle
  if (!type && !(tag && tagClass)) LMMarkThemed(self, LMBundleIdentifierForAppURL(url));
  return self;
}

- (id)_makeAppResourceProvider {
  NSURL *url = [self url];
  ISResourceProvider *provider = LMProviderForRequest(self, LMBundleIdentifierForAppURL(url), ^ISConcreteIcon *{
    return [[%c(ISBundleIcon) alloc] initWithBundleURL:url type:nil tag:nil tagClass:nil];
  });
  return provider ? : %orig;
}

%end

%hook ISApplicationIdentityIcon

- (instancetype)initWithApplicationIdentity:(id)identity {
  self = %orig;
  LMMarkThemed(self, LMBundleIdentifierForIdentity(identity));
  return self;
}

- (id)_makeResourceProviderAllowIconResourceFallback:(BOOL)allowFallback {
  Class identityClass = objc_getClass("LSApplicationIdentity");
  NSString *identityString = [self identityString];
  if (allowFallback && identityString && [identityClass instancesRespondToSelector:@selector(initWithIdentityString:)]) {
    id identity = [[identityClass alloc] initWithIdentityString:identityString];
    ISResourceProvider *provider = LMProviderForRequest(self, LMBundleIdentifierForIdentity(identity), ^ISConcreteIcon *{
      return [[%c(ISApplicationIdentityIcon) alloc] initWithApplicationIdentity:identity];
    });
    if (provider) return provider;
  }
  return %orig;
}

%end

%end

#pragma mark - Setup

static Class LMSubclass(Class base, const char *name) {
  Class existing = objc_getClass(name);
  if (existing) return existing;
  Class subclass = base ? objc_allocateClassPair(base, name, 0) : Nil;
  return subclass;
}

static void LMInstallIconHooks(void) {
  if (LMHooksInstalled) return;
  Class concreteIcon = objc_getClass("ISConcreteIcon");
  Class providerBase = objc_getClass("ISResourceProvider");
  if (!concreteIcon || !providerBase || !objc_getClass("ISBundleIdentifierIcon") || !objc_getClass("IFImage") || !objc_getClass("IFImageBag")) return;
  // no _digest, no way to keep themed and stock icons apart
  Ivar digest = class_getInstanceVariable(concreteIcon, "_digest");
  if (!digest || ![providerBase instancesRespondToSelector:@selector(initWithResource:templateResource:)]) return;
  LMHooksInstalled = YES;
  LMDigestIvar = digest;
  LMImageBags = [NSCache new];
  LMImageBags.countLimit = 300;
  if (!LMAppURLIdentifiers) LMAppURLIdentifiers = [NSCache new];

  Class provider = LMSubclass(providerBase, "LMThemeIconProvider");
  if (provider && !objc_getClass("LMThemeIconProvider")) {
    class_addMethod(provider, @selector(configureProviderFromDescriptor:), (IMP)LMProviderConfigure, "v@:@");
    objc_registerClassPair(provider);
  }
  LMProviderClass = provider;

  Class appRecipe = objc_getClass("ISiOSAppRecipe");
  Class recipe = LMSubclass(appRecipe, "LMThemeIconRecipe");
  if (recipe && !objc_getClass("LMThemeIconRecipe")) {
    class_addMethod(recipe, @selector(shouldApplyMask), (IMP)LMRecipeShouldApplyMask, "B@:");
    SEL primaryEffect = @selector(primaryResourceEffectReturningBackgroundContentOverride:);
    if (class_getInstanceMethod(appRecipe, primaryEffect)) class_addMethod(recipe, primaryEffect, (IMP)LMRecipePrimaryEffect, "@@:^@");
    objc_registerClassPair(recipe);
  }
  LMRecipeClass = recipe;

  %init(Icons);
}

static void LMImageAdded(const struct mach_header *header, intptr_t slide) {
  if (LMHooksInstalled && (!LMIsLocalRenderingProcess() || LMLocalHooksInstalled)) return;
  Dl_info info;
  if (!dladdr(header, &info) || !info.dli_fname || !strstr(info.dli_fname, "/IconServices.framework/")) return;
  // IconServices got loaded after us
  dispatch_async(dispatch_get_main_queue(), ^{ LMInstallLocalIconHooks(); LMInstallIconHooks(); });
}

%ctor {
  @autoreleasepool {
    if (![[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){17, 0, 0}]) return;
    LMInstallLocalIconHooks();
    LMInstallIconHooks();
    if (!LMHooksInstalled || (LMIsLocalRenderingProcess() && !LMLocalHooksInstalled)) _dyld_register_func_for_add_image(LMImageAdded);
  }
}
