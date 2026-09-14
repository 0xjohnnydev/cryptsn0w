#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
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
extern void ATHostConnectionSendFileError(ATHostConnectionRef connection,
                                          CFStringRef assetIdentifier,
                                          CFStringRef dataclass,
                                          int errorCode);
extern uint32_t ATHostConnectionGetCurrentSessionNumber(
    ATHostConnectionRef connection);
extern void ATHostConnectionSendMessage(ATHostConnectionRef connection,
                                        CFDictionaryRef message);
extern void ATHostConnectionSendPing(ATHostConnectionRef connection);
extern CFDictionaryRef ATCFMessageCreate(uint32_t sessionNumber,
                                        CFStringRef command,
                                        CFDictionaryRef parameters);
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
    if (!data) return;
    (void)write(STDOUT_FILENO, data.bytes, data.length);
    (void)write(STDOUT_FILENO, "\n", 1);
}

static NSDictionary *HostInfo(void) {
    return @{
        @"Type": @"iTunes",
        @"Version": @"13.7.0.161",
        @"MacOSVersion": NSProcessInfo.processInfo.operatingSystemVersionString,
        @"SyncHostName": @"24A435 cfprefs race host",
        @"LibraryID": NSUUID.UUID.UUIDString,
        @"SyncedDataclasses": @[ @"Book" ],
        @"SyncedAssetTypes": @[ @"Book" ],
        @"Wakeable": @NO,
    };
}

static BOOL ManifestContains(NSDictionary *manifest, NSString *identifier) {
    NSArray *books = [manifest[@"Book"] isKindOfClass:NSArray.class]
        ? manifest[@"Book"] : nil;
    for (id entry in books) {
        if ([entry isKindOfClass:NSDictionary.class] &&
            [entry[@"AssetID"] isEqual:identifier] &&
            [entry[@"IsDownload"] boolValue]) return YES;
    }
    return NO;
}

static uint64_t MonotonicNanoseconds(void) {
    struct timespec value = {0};
    clock_gettime(CLOCK_MONOTONIC_RAW, &value);
    return (uint64_t)value.tv_sec * NSEC_PER_SEC + (uint64_t)value.tv_nsec;
}

static NSString *DerivedPath(NSString *base, NSString *suffix) {
    return [base stringByAppendingString:suffix];
}

static BOOL WriteMarker(NSString *path, NSString *value) {
    return [value writeToFile:path
                    atomically:YES
                      encoding:NSUTF8StringEncoding
                         error:nil];
}

static NSString *WaitForControl(NSString *path, NSTimeInterval seconds) {
    NSFileManager *manager = NSFileManager.defaultManager;
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while (![manager fileExistsAtPath:path] &&
           deadline.timeIntervalSinceNow > 0) {
        usleep(1000);
    }
    if (![manager fileExistsAtPath:path]) return nil;
    NSString *value = [NSString stringWithContentsOfFile:path
                                                 encoding:NSUTF8StringEncoding
                                                    error:nil];
    return [value stringByTrimmingCharactersInSet:
        NSCharacterSet.whitespaceAndNewlineCharacterSet].lowercaseString;
}

static CFDictionaryRef FileCompleteMessage(
    ATHostConnectionRef connection,
    NSString *identifier,
    NSString *destination) {
    NSDictionary *parameters = @{
        @"AssetID": identifier,
        @"Dataclass": @"Book",
        @"AssetPath": destination,
    };
    return ATCFMessageCreate(
        ATHostConnectionGetCurrentSessionNumber(connection),
        CFSTR("FileComplete"),
        (__bridge CFDictionaryRef)parameters);
}

/*
 * ATHostConnectionSendAssetCompleted constructs and queues each message
 * separately.  On the 24A435 host framework that left a multi-millisecond
 * window between the two device-side moves.  Build both immutable messages
 * first, then append both while holding the message-link access queue.  A
 * trailing Ping makes the framework drain the already-coalesced pair in one
 * send pass.  The offsets are exact for AirTrafficHost 116 on this test Mac;
 * every pointer and the empty pending array are checked before use.
 */
static BOOL SendCoalescedPair(
    ATHostConnectionRef connection,
    NSString *firstIdentifier,
    NSString *firstDestination,
    NSString *secondIdentifier,
    NSString *secondDestination) {
    CFDictionaryRef first = FileCompleteMessage(
        connection, firstIdentifier, firstDestination);
    CFDictionaryRef second = FileCompleteMessage(
        connection, secondIdentifier, secondDestination);
    if (!first || !second) {
        if (first) CFRelease(first);
        if (second) CFRelease(second);
        return NO;
    }

    uint8_t *connectionBytes = (uint8_t *)connection;
    uint8_t *messageLink = *(uint8_t **)(connectionBytes + 64);
    void *rawAccessQueue = messageLink
        ? *(void **)(messageLink + 64) : NULL;
    dispatch_queue_t accessQueue = rawAccessQueue
        ? (__bridge dispatch_queue_t)rawAccessQueue : nil;
    CFMutableArrayRef pending = messageLink
        ? *(CFMutableArrayRef *)(messageLink + 80) : NULL;
    __block BOOL queued = NO;
    if (accessQueue && pending) {
        dispatch_sync(accessQueue, ^{
            if (CFGetTypeID(pending) == CFArrayGetTypeID() &&
                CFArrayGetCount(pending) == 0) {
                CFArrayAppendValue(pending, first);
                CFArrayAppendValue(pending, second);
                queued = YES;
            }
        });
    }
    if (queued) ATHostConnectionSendPing(connection);
    CFRelease(first);
    CFRelease(second);
    return queued;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        BOOL transactionMode = argc == 12;
        if (argc != 7 && !transactionMode) {
            PrintJSON(@{ @"ok": @NO,
                         @"error":
                             @"usage: udid id1 dst1 id2 dst2 gate; or "
                              "udid prelude-id prelude-dst target-id "
                              "backup-dst payload-id canonical-dst "
                              "rollback-target-id rollback-backup-id "
                              "discard-dst control-base" });
            return 64;
        }
        NSString *deviceIdentifier = [NSString stringWithUTF8String:argv[1]];
        NSString *preludeIdentifier = transactionMode
            ? [NSString stringWithUTF8String:argv[2]] : nil;
        NSString *preludeDestination = transactionMode
            ? [NSString stringWithUTF8String:argv[3]] : nil;
        NSString *firstIdentifier = [NSString stringWithUTF8String:
            argv[transactionMode ? 4 : 2]];
        NSString *firstDestination = [NSString stringWithUTF8String:
            argv[transactionMode ? 5 : 3]];
        NSString *secondIdentifier = [NSString stringWithUTF8String:
            argv[transactionMode ? 6 : 4]];
        NSString *secondDestination = [NSString stringWithUTF8String:
            argv[transactionMode ? 7 : 5]];
        NSString *rollbackIdentifier = transactionMode
            ? [NSString stringWithUTF8String:argv[8]] : nil;
        NSString *rollbackBackupIdentifier = transactionMode
            ? [NSString stringWithUTF8String:argv[9]] : nil;
        NSString *discardDestination = transactionMode
            ? [NSString stringWithUTF8String:argv[10]] : nil;
        NSString *gatePath = [NSString stringWithUTF8String:
            argv[transactionMode ? 11 : 6]];
        if (!deviceIdentifier.length || !firstIdentifier.length ||
            !firstDestination.length || !secondIdentifier.length ||
            !secondDestination.length || !gatePath.length ||
            (transactionMode &&
             (!preludeIdentifier.length || !preludeDestination.length ||
              !rollbackIdentifier.length || !rollbackBackupIdentifier.length ||
              !discardDestination.length))) {
            PrintJSON(@{ @"ok": @NO, @"error": @"empty argument" });
            return 64;
        }

        if (transactionMode) {
            NSArray<NSString *> *controlPaths = @[
                gatePath,
                DerivedPath(gatePath, @".ready"),
                DerivedPath(gatePath, @".committed"),
                DerivedPath(gatePath, @".decision"),
                DerivedPath(gatePath, @".rolledback"),
            ];
            for (NSString *path in controlPaths) {
                if ([NSFileManager.defaultManager fileExistsAtPath:path]) {
                    PrintJSON(@{ @"ok": @NO,
                                 @"error": @"stale transaction control path" });
                    return 64;
                }
            }
        }

        signal(SIGALRM, TimeoutHandler);
        alarm(transactionMode ? 150 : 80);
        ATHostConnectionRef connection = ATHostConnectionCreate(
            (__bridge CFStringRef)deviceIdentifier);
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
        for (NSUInteger index = 0; index < 20 && !manifest; index++) {
            CFDictionaryRef raw = ATHostConnectionReadMessage(connection);
            if (!raw) continue;
            NSString *name = (__bridge NSString *)ATCFMessageGetName(raw);
            if ([name isEqual:@"AssetManifest"]) {
                id value = (__bridge id)ATCFMessageGetParam(
                    raw, CFSTR("AssetManifest"));
                if ([value isKindOfClass:NSDictionary.class]) manifest = [value copy];
            } else if ([name isEqual:@"SyncFailed"] ||
                       [name isEqual:@"SyncFinished"]) {
                CFRelease(raw);
                break;
            }
            CFRelease(raw);
        }
        BOOL manifestReady = ManifestContains(manifest, firstIdentifier) &&
            ManifestContains(manifest, secondIdentifier);
        if (transactionMode) {
            manifestReady = manifestReady &&
                ManifestContains(manifest, preludeIdentifier) &&
                ManifestContains(manifest, rollbackIdentifier) &&
                ManifestContains(manifest, rollbackBackupIdentifier);
        }
        if (!manifestReady) {
            ATHostConnectionRelease(connection);
            PrintJSON(@{ @"ok": @NO,
                         @"error": @"transaction assets absent from manifest" });
            return 5;
        }

        if (transactionMode) {
            ATHostConnectionSendAssetCompleted(
                connection,
                (__bridge CFStringRef)preludeIdentifier,
                CFSTR("Book"),
                (__bridge CFStringRef)preludeDestination);
            usleep(250000);
            NSString *readyPath = DerivedPath(gatePath, @".ready");
            if (!WriteMarker(readyPath, @"prelude-sent\n")) {
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)firstIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)secondIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackBackupIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionRelease(connection);
                PrintJSON(@{ @"ok": @NO,
                             @"error": @"transaction ready marker failed" });
                return 6;
            }
            PrintJSON(@{ @"ok": @YES,
                         @"stage": @"transaction-prelude-sent" });
            NSString *authorization = WaitForControl(gatePath, 45.0);
            if (![authorization isEqual:@"commit"]) {
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)firstIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)secondIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackBackupIdentifier,
                    CFSTR("Book"), 1);
                usleep(500000);
                ATHostConnectionRelease(connection);
                alarm(0);
                PrintJSON(@{ @"ok": @([authorization isEqual:@"abort"]),
                             @"aborted": @YES,
                             @"canonicalMutationAttempted": @NO,
                             @"authorization": authorization ?: @"timeout" });
                return [authorization isEqual:@"abort"] ? 0 : 6;
            }

            uint64_t start = MonotonicNanoseconds();
            BOOL coalesced = SendCoalescedPair(
                connection,
                firstIdentifier,
                firstDestination,
                secondIdentifier,
                secondDestination);
            uint64_t dispatchDone = MonotonicNanoseconds();
            if (!coalesced) {
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)firstIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)secondIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackBackupIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionRelease(connection);
                PrintJSON(@{ @"ok": @NO,
                             @"error": @"transaction coalescing gate failed",
                             @"canonicalMutationAttempted": @NO });
                return 7;
            }
            usleep(300000);
            NSString *committedPath = DerivedPath(gatePath, @".committed");
            WriteMarker(committedPath, @"commit-sent\n");
            PrintJSON(@{
                @"ok": @YES,
                @"stage": @"transaction-commit-sent",
                @"dispatchMicroseconds": @((dispatchDone - start) / 1000),
            });

            NSString *decisionPath = DerivedPath(gatePath, @".decision");
            NSString *decision = WaitForControl(decisionPath, 45.0);
            if ([decision isEqual:@"accept"]) {
                /* Account for the two rollback-only manifest rows. */
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackIdentifier,
                    CFSTR("Book"), 1);
                ATHostConnectionSendFileError(
                    connection, (__bridge CFStringRef)rollbackBackupIdentifier,
                    CFSTR("Book"), 1);
                usleep(1500000);
                ATHostConnectionRelease(connection);
                alarm(0);
                PrintJSON(@{
                    @"ok": @YES,
                    @"syncAllowed": @YES,
                    @"readyForSync": @YES,
                    @"preludeMessage": @YES,
                    @"canonicalMutationAttempted": @YES,
                    @"accepted": @YES,
                    @"fileCompleteMessages": @3,
                    @"interMessageMicroseconds": @0,
                    @"coalescedHostQueue": @YES,
                    @"dispatchMicroseconds": @((dispatchDone - start) / 1000),
                });
                return 0;
            }

            uint64_t rollbackStart = MonotonicNanoseconds();
            BOOL rolledBack = SendCoalescedPair(
                connection,
                rollbackIdentifier,
                discardDestination,
                rollbackBackupIdentifier,
                secondDestination);
            uint64_t rollbackDone = MonotonicNanoseconds();
            usleep(500000);
            WriteMarker(DerivedPath(gatePath, @".rolledback"),
                        rolledBack ? @"rollback-sent\n" : @"rollback-failed\n");
            ATHostConnectionRelease(connection);
            alarm(0);
            PrintJSON(@{
                @"ok": @(rolledBack),
                @"syncAllowed": @YES,
                @"readyForSync": @YES,
                @"preludeMessage": @YES,
                @"canonicalMutationAttempted": @YES,
                @"accepted": @NO,
                @"rollbackRequested": @YES,
                @"rollbackDecision": decision ?: @"timeout",
                @"rollbackCoalesced": @(rolledBack),
                @"rollbackDispatchMicroseconds":
                    @((rollbackDone - rollbackStart) / 1000),
                @"dispatchMicroseconds": @((dispatchDone - start) / 1000),
            });
            return rolledBack ? 0 : 8;
        }

        NSString *readyPath = DerivedPath(gatePath, @".ready");
        WriteMarker(readyPath, @"ready\n");
        PrintJSON(@{ @"ok": @YES, @"stage": @"race-ready" });
        NSString *authorization = WaitForControl(gatePath, 45.0);
        if (!authorization) {
            ATHostConnectionRelease(connection);
            PrintJSON(@{ @"ok": @NO, @"error": @"race gate timed out" });
            return 6;
        }

        uint64_t start = MonotonicNanoseconds();
        PrintJSON(@{ @"ok": @YES, @"stage": @"coalesce-start" });
        BOOL coalesced = SendCoalescedPair(
            connection,
            firstIdentifier,
            firstDestination,
            secondIdentifier,
            secondDestination);
        uint64_t dispatchDone = MonotonicNanoseconds();
        PrintJSON(@{ @"ok": @(coalesced),
                     @"stage": @"coalesce-returned",
                     @"dispatchMicroseconds":
                         @((dispatchDone - start) / 1000) });
        if (!coalesced) {
            ATHostConnectionRelease(connection);
            PrintJSON(@{ @"ok": @NO,
                         @"error": @"host message coalescing gate failed" });
            return 7;
        }
        usleep(1500000);
        PrintJSON(@{ @"ok": @YES, @"stage": @"release-start" });
        ATHostConnectionRelease(connection);
        alarm(0);
        PrintJSON(@{
            @"ok": @YES,
            @"syncAllowed": @YES,
            @"readyForSync": @YES,
            @"fileCompleteMessages": @2,
            @"interMessageMicroseconds": @0,
            @"coalescedHostQueue": @YES,
            @"dispatchMicroseconds": @((dispatchDone - start) / 1000),
        });
        return 0;
    }
}
