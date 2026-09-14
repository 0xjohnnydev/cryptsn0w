#import <Foundation/Foundation.h>

static NSString *MGHexStringForData(NSData *data) {
    const uint8_t *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger index = 0; index < data.length; index++) {
        [hex appendFormat:@"%02x", bytes[index]];
    }
    return hex;
}

// Kept byte-for-byte equivalent to the recent MGCacheProbe transformation.
static BOOL MGNuggetIPadOSNibble(NSData *cacheData,
                                 NSUInteger *offsetOut,
                                 unichar *valueOut,
                                 NSString **errorOut) {
    NSString *hex = MGHexStringForData(cacheData);
    const NSUInteger sliceStart = 1616;
    const NSUInteger sliceLength = 200;
    if (hex.length <= sliceStart) {
        if (errorOut) *errorOut = @"iPadOS CacheData is too short.";
        return NO;
    }

    NSError *regexError = nil;
    NSRegularExpression *regex = [NSRegularExpression
        regularExpressionWithPattern:@"0+(?:5555)*([0-9a-f]{4})"
                              options:0
                                error:&regexError];
    if (!regex) {
        if (errorOut) *errorOut = regexError.description ?: @"iPadOS pattern is invalid.";
        return NO;
    }

    NSRange searchRange = NSMakeRange(sliceStart,
        MIN(sliceLength, hex.length - sliceStart));
    NSArray<NSTextCheckingResult *> *matches = [regex matchesInString:hex
                                                              options:0
                                                                range:searchRange];
    NSUInteger matchOffset = NSNotFound;
    for (NSTextCheckingResult *match in matches) {
        NSRange valueRange = [match rangeAtIndex:1];
        NSString *value = [hex substringWithRange:valueRange];
        NSUInteger nonzero = 0;
        for (NSUInteger index = 0; index < value.length; index++) {
            if ([value characterAtIndex:index] != '0') nonzero++;
        }
        if (nonzero >= 3) {
            matchOffset = valueRange.location;
            break;
        }
    }
    if (matchOffset == NSNotFound || matchOffset < 67) {
        if (errorOut) *errorOut = @"Nugget's iPadOS CacheData pattern was not found.";
        return NO;
    }

    NSUInteger leftOffset = matchOffset - 67;
    NSUInteger rightOffset = matchOffset + 13;
    if (rightOffset + 1 >= hex.length || leftOffset == 0 || leftOffset + 1 >= hex.length) {
        if (errorOut) *errorOut = @"Nugget's iPadOS CacheData offsets are out of range.";
        return NO;
    }
    for (NSNumber *number in @[ @(leftOffset), @(rightOffset) ]) {
        NSUInteger offset = number.unsignedIntegerValue;
        unichar value = [hex characterAtIndex:offset];
        if ((value != '1' && value != '3') ||
            [hex characterAtIndex:offset - 1] != '0' ||
            [hex characterAtIndex:offset + 1] != '0') {
            if (errorOut) *errorOut = @"Nugget's iPadOS CacheData validation failed.";
            return NO;
        }
    }

    if (offsetOut) *offsetOut = leftOffset;
    if (valueOut) *valueOut = [hex characterAtIndex:leftOffset];
    return YES;
}

static NSData *MGNuggetIPadOSCacheData(NSData *cacheData, NSString **errorOut) {
    NSUInteger nibbleOffset = 0;
    if (!MGNuggetIPadOSNibble(cacheData, &nibbleOffset, NULL, errorOut)) return nil;

    NSMutableData *patched = [cacheData mutableCopy];
    uint8_t *bytes = patched.mutableBytes;
    NSUInteger byteOffset = nibbleOffset / 2;
    if ((nibbleOffset & 1) == 0) {
        bytes[byteOffset] = (uint8_t)((bytes[byteOffset] & 0x0f) | 0x30);
    } else {
        bytes[byteOffset] = (uint8_t)((bytes[byteOffset] & 0xf0) | 0x03);
    }
    return patched;
}

static NSArray<NSString *> *RiskyKeys(void) {
    return @[
        @"mG0AnH/Vy1veoqoLRAIgTA",
        @"UCG5MkVahJxG1YULbbd5Bg",
        @"ZYqko/XM5zD3XBfN5RmaXA",
        @"nVh/gwNpy7Jv1NOk00CMrw",
        @"uKc7FPnEO++lVhHWHFlGbQ",
    ];
}

static int Fail(NSString *message) {
    NSDictionary *result = @{ @"ok": @NO, @"error": message ?: @"unknown error" };
    NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    fwrite(json.bytes, 1, json.length, stdout);
    fputc('\n', stdout);
    return 2;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3) return Fail(@"usage: mgcache_risky_transform INPUT OUTPUT");

        NSString *inputPath = [NSString stringWithUTF8String:argv[1]];
        NSString *outputPath = [NSString stringWithUTF8String:argv[2]];
        NSError *error = nil;
        NSData *input = [NSData dataWithContentsOfFile:inputPath
                                               options:0
                                                 error:&error];
        if (!input) return Fail(error.description ?: @"input read failed");
        if (input.length < 8 ||
            memcmp(input.bytes, "bplist00", 8) != 0 ||
            input.length > 1024 * 1024) {
            return Fail(@"binary-plist safety gate rejected input");
        }

        NSPropertyListFormat format = NSPropertyListBinaryFormat_v1_0;
        NSMutableDictionary *cache = [NSPropertyListSerialization
            propertyListWithData:input
                         options:NSPropertyListMutableContainersAndLeaves
                          format:&format
                           error:&error];
        if (![cache isKindOfClass:NSMutableDictionary.class] ||
            format != NSPropertyListBinaryFormat_v1_0) {
            return Fail(error.description ?: @"cache parse failed");
        }
        NSMutableDictionary *extra = cache[@"CacheExtra"];
        NSData *cacheData = cache[@"CacheData"];
        if (![extra isKindOfClass:NSMutableDictionary.class] ||
            ![cacheData isKindOfClass:NSData.class] ||
            ![extra[@"0+nc/Udy4WNG8S+Q7a/s1A"] isEqual:@"iPhone18,2"] ||
            ![cache[@"CacheVersion"] isKindOfClass:NSString.class] ||
            ![cache[@"CacheUUID"] isKindOfClass:NSString.class]) {
            return Fail(@"iPhone18,2 cache identity gate rejected input");
        }

        NSString *patchError = nil;
        NSData *patchedData = MGNuggetIPadOSCacheData(cacheData, &patchError);
        if (!patchedData) return Fail(patchError);
        for (NSString *key in RiskyKeys()) extra[key] = @1;
        cache[@"CacheData"] = patchedData;

        NSData *replacement = [NSPropertyListSerialization
            dataWithPropertyList:cache
                          format:NSPropertyListBinaryFormat_v1_0
                         options:0
                           error:&error];
        if (!replacement) return Fail(error.description ?: @"serialization failed");

        NSDictionary *verify = [NSPropertyListSerialization
            propertyListWithData:replacement
                         options:NSPropertyListImmutable
                          format:&format
                           error:&error];
        NSDictionary *verifyExtra = verify[@"CacheExtra"];
        unichar nibble = 0;
        if (![verify isKindOfClass:NSDictionary.class] ||
            !MGNuggetIPadOSNibble(verify[@"CacheData"], NULL, &nibble, &patchError) ||
            nibble != '3') {
            return Fail(patchError ?: error.description ?: @"CacheData verification failed");
        }
        for (NSString *key in RiskyKeys()) {
            if (![verifyExtra[key] isEqual:@1]) return Fail(@"CacheExtra verification failed");
        }

        NSURL *outputURL = [NSURL fileURLWithPath:outputPath];
        if (![replacement writeToURL:outputURL
                             options:NSDataWritingAtomic
                               error:&error]) {
            return Fail(error.description ?: @"output write failed");
        }
        NSDictionary *result = @{
            @"ok": @YES,
            @"inputLength": @(input.length),
            @"outputLength": @(replacement.length),
            @"cacheVersion": cache[@"CacheVersion"],
            @"cacheUUID": cache[@"CacheUUID"],
            @"cacheDataNibble": @"3",
            @"keysEnabled": @(RiskyKeys().count),
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:result
                                                       options:0
                                                         error:nil];
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
        return 0;
    }
}
