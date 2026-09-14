#import <Foundation/Foundation.h>
#include <signal.h>
#include <unistd.h>

typedef void *ATHostConnectionRef;

extern ATHostConnectionRef ATHostConnectionCreate(CFStringRef deviceIdentifier);
extern void ATHostConnectionRelease(ATHostConnectionRef connection);
extern void ATHostConnectionSendHostInfo(ATHostConnectionRef connection,
                                         CFDictionaryRef hostInfo);
extern void ATHostConnectionSendSyncRequest(ATHostConnectionRef connection,
                                            CFArrayRef dataclasses,
                                            CFDictionaryRef anchors,
                                            CFDictionaryRef hostInfo);
extern void ATHostConnectionSendMetadataSyncFinished(
    ATHostConnectionRef connection,
    CFDictionaryRef syncTypes,
    CFDictionaryRef anchors);
extern void ATHostConnectionSendAssetCompleted(ATHostConnectionRef connection,
                                               CFStringRef assetIdentifier,
                                               CFStringRef dataclass,
                                               CFStringRef assetPath);
extern CFDictionaryRef ATHostConnectionReadMessage(ATHostConnectionRef connection);
extern CFStringRef ATCFMessageGetName(CFDictionaryRef message);
extern CFTypeRef ATCFMessageGetParam(CFDictionaryRef message, CFStringRef key);

static void TimeoutHandler(int signalNumber) {
    (void)signalNumber;
    const char message[] = "{\"ok\":false,\"error\":\"timeout\"}\n";
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(124);
}

static void PrintJSON(NSDictionary *object) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:nil];
    if (data) {
        (void)write(STDOUT_FILENO, data.bytes, data.length);
        (void)write(STDOUT_FILENO, "\n", 1);
    }
}

static NSDictionary *HostInfo(void) {
    return @{
        @"Type": @"iTunes",
        @"Version": @"13.7.0.161",
        @"MacOSVersion": [[NSProcessInfo processInfo] operatingSystemVersionString],
        @"SyncHostName": @"24A435 canary host",
        @"LibraryID": [[NSUUID UUID] UUIDString],
        @"SyncedDataclasses": @[ @"Book" ],
        @"SyncedAssetTypes": @[ @"Book" ],
        @"Wakeable": @NO,
    };
}

static BOOL ManifestContains(NSDictionary *manifest, NSString *identifier) {
    NSArray *books = [manifest[@"Book"] isKindOfClass:[NSArray class]]
                         ? manifest[@"Book"]
                         : nil;
    for (id entry in books) {
        if ([entry isKindOfClass:[NSDictionary class]] &&
            [entry[@"AssetID"] isEqual:identifier] &&
            [entry[@"IsDownload"] boolValue]) {
            return YES;
        }
    }
    return NO;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2 && argc != 6 && argc != 8 && argc != 9) {
            PrintJSON(@{ @"ok": @NO, @"error": @"usage" });
            return 64;
        }

        if (argc == 2) {
            signal(SIGALRM, TimeoutHandler);
            alarm(20);
            NSString *deviceIdentifier = [NSString stringWithUTF8String:argv[1]];
            ATHostConnectionRef connection = deviceIdentifier.length
                ? ATHostConnectionCreate((__bridge CFStringRef)deviceIdentifier)
                : NULL;
            if (!connection) {
                PrintJSON(@{ @"ok": @NO, @"error": @"connection create failed" });
                return 2;
            }
            ATHostConnectionRelease(connection);
            alarm(0);
            PrintJSON(@{ @"ok": @YES, @"connectOnly": @YES });
            return 0;
        }

        signal(SIGALRM, TimeoutHandler);
        alarm(argc == 9 ? 130 : 75);

        NSString *deviceIdentifier = [NSString stringWithUTF8String:argv[1]];
        NSString *linkIdentifier = [NSString stringWithUTF8String:argv[2]];
        NSString *linkDestination = [NSString stringWithUTF8String:argv[3]];
        NSString *payloadIdentifier = [NSString stringWithUTF8String:argv[4]];
        NSString *payloadDestination = [NSString stringWithUTF8String:argv[5]];
        BOOL hasRollback = argc >= 8;
        BOOL hasGate = argc == 9;
        NSString *rollbackIdentifier =
            hasRollback ? [NSString stringWithUTF8String:argv[6]] : nil;
        NSString *rollbackDestination =
            hasRollback ? [NSString stringWithUTF8String:argv[7]] : nil;
        NSString *gatePath =
            hasGate ? [NSString stringWithUTF8String:argv[8]] : nil;
        if (!deviceIdentifier.length || !linkIdentifier.length ||
            !linkDestination.length || !payloadIdentifier.length ||
            !payloadDestination.length ||
            (hasRollback && (!rollbackIdentifier.length || !rollbackDestination.length)) ||
            (hasGate && !gatePath.length)) {
            PrintJSON(@{ @"ok": @NO, @"error": @"empty argument" });
            return 64;
        }

        ATHostConnectionRef connection =
            ATHostConnectionCreate((__bridge CFStringRef)deviceIdentifier);
        if (!connection) {
            PrintJSON(@{ @"ok": @NO, @"error": @"connection create failed" });
            return 2;
        }

        BOOL sawSyncAllowed = NO;
        for (NSUInteger index = 0; index < 8 && !sawSyncAllowed; index++) {
            CFDictionaryRef raw = ATHostConnectionReadMessage(connection);
            if (!raw) continue;
            NSString *name = (__bridge NSString *)ATCFMessageGetName(raw);
            sawSyncAllowed = [name isEqual:@"SyncAllowed"];
            CFRelease(raw);
        }
        if (!sawSyncAllowed) {
            ATHostConnectionRelease(connection);
            PrintJSON(@{ @"ok": @NO, @"error": @"SyncAllowed not observed" });
            return 3;
        }

        NSDictionary *hostInfo = HostInfo();
        ATHostConnectionSendHostInfo(connection, (__bridge CFDictionaryRef)hostInfo);
        usleep(200000);
        ATHostConnectionSendSyncRequest(connection,
                                        (__bridge CFArrayRef)@[ @"Book" ],
                                        (__bridge CFDictionaryRef)@{},
                                        (__bridge CFDictionaryRef)hostInfo);

        BOOL sawReady = NO;
        for (NSUInteger index = 0; index < 12 && !sawReady; index++) {
            CFDictionaryRef raw = ATHostConnectionReadMessage(connection);
            if (!raw) continue;
            NSString *name = (__bridge NSString *)ATCFMessageGetName(raw);
            sawReady = [name isEqual:@"ReadyForSync"];
            CFRelease(raw);
        }
        if (!sawReady) {
            ATHostConnectionRelease(connection);
            PrintJSON(@{ @"ok": @NO, @"error": @"ReadyForSync not observed" });
            return 4;
        }

        ATHostConnectionSendMetadataSyncFinished(
            connection,
            (__bridge CFDictionaryRef)@{ @"Book": @1 },
            (__bridge CFDictionaryRef)@{});

        NSDictionary *manifest = nil;
        for (NSUInteger index = 0; index < 16 && !manifest; index++) {
            CFDictionaryRef raw = ATHostConnectionReadMessage(connection);
            if (!raw) continue;
            NSString *name = (__bridge NSString *)ATCFMessageGetName(raw);
            if ([name isEqual:@"AssetManifest"]) {
                id value = (__bridge id)ATCFMessageGetParam(raw, CFSTR("AssetManifest"));
                if ([value isKindOfClass:[NSDictionary class]]) {
                    manifest = [value copy];
                }
            } else if ([name isEqual:@"SyncFailed"] ||
                       [name isEqual:@"SyncFinished"]) {
                CFRelease(raw);
                break;
            }
            CFRelease(raw);
        }

        BOOL linkFound = ManifestContains(manifest, linkIdentifier);
        BOOL payloadFound = ManifestContains(manifest, payloadIdentifier);
        BOOL rollbackFound = !hasRollback || ManifestContains(manifest, rollbackIdentifier);
        if (!linkFound || !payloadFound || !rollbackFound) {
            ATHostConnectionRelease(connection);
            PrintJSON(@{
                @"ok": @NO,
                @"error": @"expected assets absent from manifest",
                @"bookAssetCount": @([manifest[@"Book"] count]),
                @"linkFound": @(linkFound),
                @"payloadFound": @(payloadFound),
                @"rollbackFound": @(rollbackFound),
            });
            return 5;
        }

        ATHostConnectionSendAssetCompleted(connection,
                                            (__bridge CFStringRef)linkIdentifier,
                                            CFSTR("Book"),
                                            (__bridge CFStringRef)linkDestination);
        usleep(750000);
        ATHostConnectionSendAssetCompleted(connection,
                                            (__bridge CFStringRef)payloadIdentifier,
                                            CFSTR("Book"),
                                            (__bridge CFStringRef)payloadDestination);
        BOOL gateTimedOut = NO;
        if (hasRollback) {
            usleep(750000);
            if (hasGate) {
                NSString *readyPath = [gatePath stringByAppendingString:@".ready"];
                [@"ready\n" writeToFile:readyPath
                              atomically:YES
                                encoding:NSUTF8StringEncoding
                                   error:nil];
                PrintJSON(@{ @"ok": @YES, @"stage": @"payload-complete" });
                NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:45.0];
                NSFileManager *fileManager = [NSFileManager defaultManager];
                while (![fileManager fileExistsAtPath:gatePath] &&
                       [deadline timeIntervalSinceNow] > 0) {
                    usleep(100000);
                }
                gateTimedOut = ![fileManager fileExistsAtPath:gatePath];
            }
            ATHostConnectionSendAssetCompleted(
                connection,
                (__bridge CFStringRef)rollbackIdentifier,
                CFSTR("Book"),
                (__bridge CFStringRef)rollbackDestination);
        }
        sleep(2);
        ATHostConnectionRelease(connection);
        alarm(0);
        PrintJSON(@{
            @"ok": @YES,
            @"syncAllowed": @YES,
            @"readyForSync": @YES,
            @"bookAssetCount": @([manifest[@"Book"] count]),
            @"linkFound": @YES,
            @"payloadFound": @YES,
            @"rollbackFound": @(rollbackFound),
            @"fileCompleteMessages": @(hasRollback ? 3 : 2),
            @"gatedRollback": @(hasGate),
            @"gateTimedOut": @(gateTimedOut),
        });
        return 0;
    }
}
