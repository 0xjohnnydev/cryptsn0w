#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <sys/socket.h>
#import <unistd.h>

typedef const void *AMDeviceRef;
typedef const void *AMDeviceNotificationRef;
typedef void *AMDServiceConnectionRef;
typedef void *AFCConnectionRef;
typedef void *AFCKeyValueRef;
typedef void *AFCFileRef;
typedef void *AFCDirectoryRef;

typedef struct { AMDeviceRef device; unsigned int message; }
    AMDeviceNotificationCallbackInfo;

extern int AMDeviceNotificationSubscribeWithOptions(
    void (*callback)(AMDeviceNotificationCallbackInfo *, void *),
    int unused, unsigned int connectionType, void *context,
    AMDeviceNotificationRef *subscription, CFDictionaryRef options);
extern int AMDeviceNotificationUnsubscribe(AMDeviceNotificationRef subscription);
extern CFStringRef AMDeviceCopyDeviceIdentifier(AMDeviceRef device);
extern CFTypeRef AMDeviceCopyValue(AMDeviceRef device, CFStringRef domain,
                                   CFStringRef key);
extern int AMDeviceConnect(AMDeviceRef device);
extern int AMDeviceDisconnect(AMDeviceRef device);
extern int AMDeviceIsPaired(AMDeviceRef device);
extern int AMDeviceValidatePairing(AMDeviceRef device);
extern int AMDeviceStartSession(AMDeviceRef device);
extern int AMDeviceStopSession(AMDeviceRef device);
extern int AMDeviceSecureStartService(AMDeviceRef device,
                                      CFStringRef serviceName,
                                      CFDictionaryRef options,
                                      AMDServiceConnectionRef *connection);
extern int AMDServiceConnectionGetSocket(AMDServiceConnectionRef connection);
extern void *AMDServiceConnectionGetSecureIOContext(AMDServiceConnectionRef connection);
extern int AMDServiceConnectionInvalidate(AMDServiceConnectionRef connection);
extern int AMDServiceConnectionSend(AMDServiceConnectionRef connection,
                                    const void *bytes, size_t length);
extern int AMDServiceConnectionSendMessage(AMDServiceConnectionRef connection,
                                           CFTypeRef message,
                                           CFPropertyListFormat format);
extern int AMDServiceConnectionReceiveMessage(AMDServiceConnectionRef connection,
                                              CFTypeRef *message,
                                              CFPropertyListFormat *format);

extern int AFCConnectionOpen(int socket, unsigned int ioTimeout,
                             AFCConnectionRef *connection);
extern int AFCConnectionClose(AFCConnectionRef connection);
extern int AFCConnectionSetSecureContext(AFCConnectionRef connection,
                                         void *secureContext);
extern int AFCConnectionSetDisposeSecureContextOnInvalidate(
    AFCConnectionRef connection, int dispose);
extern int AFCConnectionSetIOTimeout(AFCConnectionRef connection,
                                     unsigned int timeout);
extern int AFCFileInfoOpen(AFCConnectionRef connection, const char *path,
                           AFCKeyValueRef *dictionary);
extern int AFCKeyValueRead(AFCKeyValueRef dictionary, char **key, char **value);
extern int AFCKeyValueClose(AFCKeyValueRef dictionary);
extern int AFCFileRefOpen(AFCConnectionRef connection, const char *path,
                          unsigned long long mode, AFCFileRef *file);
extern int AFCFileRefRead(AFCConnectionRef connection, AFCFileRef file,
                          void *bytes, long *length);
extern int AFCFileRefWrite(AFCConnectionRef connection, AFCFileRef file,
                           const void *bytes, long length);
extern int AFCFileRefClose(AFCConnectionRef connection, AFCFileRef file);
extern int AFCDirectoryOpen(AFCConnectionRef connection, const char *path,
                            AFCDirectoryRef *directory);
extern int AFCDirectoryRead(AFCConnectionRef connection,
                            AFCDirectoryRef directory, char **entry);
extern int AFCDirectoryClose(AFCConnectionRef connection,
                             AFCDirectoryRef directory);
extern int AFCDirectoryCreate(AFCConnectionRef connection, const char *path);
extern int AFCRemovePath(AFCConnectionRef connection, const char *path);
extern int AFCRenamePath(AFCConnectionRef connection, const char *source,
                         const char *destination);
extern int AFCLinkPath(AFCConnectionRef connection, unsigned long long linkType,
                       const char *target, const char *linkName);

static const char *TrackedBooksFiles[] = {
    "Books/Books.plist",
    "Books/Sync/Books.plist",
    "Books/Sync/Upload.plist",
    "Books/Sync/Database/OutstandingAssets_4.sqlite",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-shm",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-wal",
};

static CFStringRef TargetIdentifier;
static AMDeviceRef TargetDevice;

typedef struct {
    AMDeviceRef device;
    BOOL connected;
    BOOL sessionStarted;
    AMDServiceConnectionRef afcService;
    AFCConnectionRef afc;
    int subscribeStatus;
    int connectStatus;
    int validateStatus;
    int sessionStatus;
    int serviceStatus;
    int afcStatus;
} DeviceSession;

static void DeviceCallback(AMDeviceNotificationCallbackInfo *info, void *context) {
    (void)context;
    if (!info || !info->device || info->message != 1 || TargetDevice) return;
    CFStringRef identifier = AMDeviceCopyDeviceIdentifier(info->device);
    BOOL matches = identifier && CFEqual(identifier, TargetIdentifier);
    if (identifier) CFRelease(identifier);
    if (!matches) return;
    TargetDevice = CFRetain(info->device);
    CFRunLoopStop(CFRunLoopGetMain());
}

static int FindTarget(void) {
    NSDictionary *options = @{
        @"NotificationOptionSearchForPairedDevices": @YES,
        @"NotificationOptionSearchForPairedDevicesViaDirectConnectionsOnly": @NO,
        @"NotificationOptionSearchForWiFiPairableDevices": @NO,
        @"NotificationOptionEnableRemoteXPC": @YES,
        @"NotificationOptionEnableUSBMux": @YES,
    };
    AMDeviceNotificationRef subscription = NULL;
    int status = AMDeviceNotificationSubscribeWithOptions(
        DeviceCallback, 0, 0, NULL, &subscription,
        (__bridge CFDictionaryRef)options);
    if (status == 0) CFRunLoopRunInMode(kCFRunLoopDefaultMode, 30.0, false);
    if (subscription) AMDeviceNotificationUnsubscribe(subscription);
    return status;
}

static void PrintResult(NSDictionary *result) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    if (!json) return;
    fwrite(json.bytes, 1, json.length, stdout);
    fwrite("\n", 1, 1, stdout);
}

static void OpenSession(DeviceSession *session) {
    memset(session, 0, sizeof(*session));
    session->connectStatus = session->validateStatus = -1;
    session->sessionStatus = session->serviceStatus = session->afcStatus = -1;
    session->subscribeStatus = FindTarget();
    session->device = TargetDevice;
    if (!session->device) return;
    session->connectStatus = AMDeviceConnect(session->device);
    session->connected = session->connectStatus == 0;
    if (!session->connected || !AMDeviceIsPaired(session->device)) return;
    session->validateStatus = AMDeviceValidatePairing(session->device);
    if (session->validateStatus != 0) return;
    session->sessionStatus = AMDeviceStartSession(session->device);
    session->sessionStarted = session->sessionStatus == 0;
    if (!session->sessionStarted) return;
    session->serviceStatus = AMDeviceSecureStartService(
        session->device, CFSTR("com.apple.afc"), NULL, &session->afcService);
    if (session->serviceStatus != 0 || !session->afcService) return;
    session->afcStatus = AFCConnectionOpen(
        AMDServiceConnectionGetSocket(session->afcService), 0, &session->afc);
    void *secureContext = AMDServiceConnectionGetSecureIOContext(session->afcService);
    if (session->afcStatus == 0 && session->afc && secureContext) {
        AFCConnectionSetSecureContext(session->afc, secureContext);
        AFCConnectionSetDisposeSecureContextOnInvalidate(session->afc, 0);
        AFCConnectionSetIOTimeout(session->afc, 30);
    }
}

static void CloseSession(DeviceSession *session) {
    if (session->afc) AFCConnectionClose(session->afc);
    if (session->afcService) AMDServiceConnectionInvalidate(session->afcService);
    if (session->sessionStarted) AMDeviceStopSession(session->device);
    if (session->connected) AMDeviceDisconnect(session->device);
    if (session->device) CFRelease(session->device);
    TargetDevice = NULL;
}

static BOOL AFCExists(AFCConnectionRef afc, NSString *path) {
    AFCKeyValueRef info = NULL;
    int status = AFCFileInfoOpen(afc, path.fileSystemRepresentation, &info);
    if (info) AFCKeyValueClose(info);
    return status == 0;
}

static long long AFCFileSize(AFCConnectionRef afc, NSString *path) {
    AFCKeyValueRef info = NULL;
    if (AFCFileInfoOpen(afc, path.fileSystemRepresentation, &info) != 0 || !info)
        return -1;
    long long size = -1;
    char *key = NULL;
    char *value = NULL;
    while (AFCKeyValueRead(info, &key, &value) == 0 && key && value) {
        if (strcmp(key, "st_size") == 0) size = strtoll(value, NULL, 10);
        key = NULL;
        value = NULL;
    }
    AFCKeyValueClose(info);
    return size;
}

static NSDictionary *AFCFileInfoDictionary(AFCConnectionRef afc,
                                           NSString *path);

static NSData *AFCReadFile(AFCConnectionRef afc, NSString *path) {
    long long size = AFCFileSize(afc, path);
    if (size < 0 || size > 16 * 1024 * 1024) return nil;
    AFCFileRef file = NULL;
    if (AFCFileRefOpen(afc, path.fileSystemRepresentation, 1, &file) != 0 || !file)
        return nil;
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)size];
    long length = (long)size;
    int status = size == 0 ? 0 : AFCFileRefRead(afc, file, data.mutableBytes, &length);
    AFCFileRefClose(afc, file);
    if (status != 0 || length < 0 || length > size) return nil;
    data.length = (NSUInteger)length;
    return data;
}

static NSDictionary *AFCReadFileDirect(AFCConnectionRef afc, NSString *path,
                                       NSData **dataOut) {
    AFCFileRef file = NULL;
    int openStatus = AFCFileRefOpen(afc, path.fileSystemRepresentation, 1, &file);
    if (openStatus != 0 || !file)
        return @{ @"ok": @NO, @"openStatus": @(openStatus),
                  @"observedLength": @0 };

    NSMutableData *data = [NSMutableData data];
    int readStatus = 0;
    BOOL exceededLimit = NO;
    uint8_t chunk[64 * 1024];
    while (YES) {
        long length = sizeof(chunk);
        readStatus = AFCFileRefRead(afc, file, chunk, &length);
        if (readStatus != 0 || length <= 0) break;
        if (data.length + (NSUInteger)length > 16 * 1024 * 1024) {
            exceededLimit = YES;
            break;
        }
        [data appendBytes:chunk length:(NSUInteger)length];
    }
    int closeStatus = AFCFileRefClose(afc, file);
    BOOL ok = !exceededLimit && readStatus == 0 && closeStatus == 0;
    if (ok && dataOut) *dataOut = [data copy];
    return @{ @"ok": @(ok), @"openStatus": @(openStatus),
              @"readStatus": @(readStatus), @"closeStatus": @(closeStatus),
              @"exceededLimit": @(exceededLimit),
              @"observedLength": @(data.length) };
}

/*
 * Prove that an existing regular file can be opened and read without copying
 * its contents off-device.  At most 4096 bytes are consumed and only the byte
 * count/statuses are returned; the buffer itself is deliberately discarded.
 */
static NSDictionary *AFCProbeReadPrefix(AFCConnectionRef afc, NSString *path) {
    NSDictionary *info = AFCFileInfoDictionary(afc, path);
    NSString *kind = [info[@"values"] isKindOfClass:NSDictionary.class]
        ? info[@"values"][@"st_ifmt"] : nil;
    BOOL regularFile = [kind isEqual:@"S_IFREG"];
    long long expectedLength = AFCFileSize(afc, path);
    AFCFileRef file = NULL;
    int openStatus = regularFile
        ? AFCFileRefOpen(afc, path.fileSystemRepresentation, 1, &file) : -1;
    uint8_t buffer[4096];
    long length = 0;
    int readStatus = -1;
    if (openStatus == 0 && file) {
        length = sizeof(buffer);
        readStatus = AFCFileRefRead(afc, file, buffer, &length);
    }
    int closeStatus = file ? AFCFileRefClose(afc, file) : -1;
    BOOL boundedReadSucceeded = regularFile && openStatus == 0 &&
        readStatus == 0 && closeStatus == 0 && length >= 0 &&
        length <= (long)sizeof(buffer);
    return @{ @"ok": @(boundedReadSucceeded),
              @"regularFile": @(regularFile),
              @"openStatus": @(openStatus),
              @"readStatus": @(readStatus),
              @"closeStatus": @(closeStatus),
              @"expectedLength": @(expectedLength),
              @"bytesRead": @(length >= 0 ? length : 0),
              @"readLimit": @(sizeof(buffer)),
              @"contentReturned": @NO,
              @"info": info };
}

static BOOL AFCWriteFile(AFCConnectionRef afc, NSString *path, NSData *data) {
    AFCFileRef file = NULL;
    int status = AFCFileRefOpen(afc, path.fileSystemRepresentation, 3, &file);
    if (status != 0 || !file) return NO;
    status = data.length == 0 ? 0
        : AFCFileRefWrite(afc, file, data.bytes, (long)data.length);
    int closeStatus = AFCFileRefClose(afc, file);
    return status == 0 && closeStatus == 0;
}

static BOOL EnsureDirectory(AFCConnectionRef afc, NSString *path) {
    return AFCExists(afc, path) ||
           AFCDirectoryCreate(afc, path.fileSystemRepresentation) == 0;
}

static BOOL RemoveIfPresent(AFCConnectionRef afc, NSString *path) {
    if (!AFCExists(afc, path)) return YES;
    return AFCRemovePath(afc, path.fileSystemRepresentation) == 0 &&
           !AFCExists(afc, path);
}

/*
 * Exact, fail-closed full-file replacement through the generated AirTraffic
 * directory pivot.  The canonical leaf is never opened with a truncating
 * mode.  A replacement is first written to a fresh sibling, read back, and
 * only then atomically renamed over the leaf.  Both local preimage files are
 * bounded and the live target must exactly equal the supplied preimage.
 */
static NSDictionary *ReplaceGeneratedMGCacheFromLocal(
    DeviceSession *session, NSArray<NSString *> *arguments) {
    NSString *target = arguments[0];
    NSString *temporary = arguments[1];
    NSString *expectedPath = arguments[2];
    NSString *replacementPath = arguments[3];
    BOOL targetShape =
        [target hasPrefix:@"codex-dir-link-24A435-"] &&
        [target hasSuffix:@"/Preferences/com.apple.MobileGestalt.plist"];
    BOOL temporaryShape =
        [temporary hasPrefix:@"codex-dir-link-24A435-"] &&
        [temporary containsString:@"/Preferences/.codex-mg-roundtrip-"] &&
        [temporary hasSuffix:@".tmp"];
    if (!targetShape || !temporaryShape ||
        ![[target stringByDeletingLastPathComponent]
            isEqual:[temporary stringByDeletingLastPathComponent]]) {
        return @{ @"ok": @NO, @"error": @"generated path gate rejected" };
    }

    NSData *expected = [NSData dataWithContentsOfFile:expectedPath];
    NSData *replacement = [NSData dataWithContentsOfFile:replacementPath];
    if (!expected || !replacement || expected.length == 0 ||
        expected.length > 1024 * 1024 || replacement.length == 0 ||
        replacement.length > 1024 * 1024 || [expected isEqual:replacement]) {
        return @{ @"ok": @NO, @"error": @"local data gate rejected" };
    }
    id expectedPlist = [NSPropertyListSerialization
        propertyListWithData:expected options:0 format:NULL error:nil];
    id replacementPlist = [NSPropertyListSerialization
        propertyListWithData:replacement options:0 format:NULL error:nil];
    if (![expectedPlist isKindOfClass:[NSDictionary class]] ||
        ![replacementPlist isKindOfClass:[NSDictionary class]]) {
        return @{ @"ok": @NO, @"error": @"plist gate rejected" };
    }

    NSData *liveBefore = AFCReadFile(session->afc, target);
    BOOL preimageMatched = liveBefore && [liveBefore isEqual:expected];
    if (!preimageMatched) {
        return @{ @"ok": @NO, @"preimageMatched": @NO,
                  @"liveBeforeLength": @(liveBefore.length),
                  @"expectedLength": @(expected.length) };
    }
    if (AFCExists(session->afc, temporary)) {
        return @{ @"ok": @NO, @"preimageMatched": @YES,
                  @"error": @"temporary sibling already exists" };
    }

    BOOL temporaryWriteSucceeded =
        AFCWriteFile(session->afc, temporary, replacement);
    NSData *temporaryReadback = temporaryWriteSucceeded
        ? AFCReadFile(session->afc, temporary) : nil;
    BOOL temporaryVerified =
        temporaryReadback && [temporaryReadback isEqual:replacement];
    int renameStatus = -1;
    if (temporaryVerified) {
        renameStatus = AFCRenamePath(
            session->afc, temporary.fileSystemRepresentation,
            target.fileSystemRepresentation);
    }

    NSData *liveAfter = AFCReadFile(session->afc, target);
    BOOL replacementVerified = liveAfter && [liveAfter isEqual:replacement];
    BOOL originalPreserved = liveAfter && [liveAfter isEqual:expected];
    int cleanupStatus = 0;
    if (AFCExists(session->afc, temporary)) {
        cleanupStatus = AFCRemovePath(
            session->afc, temporary.fileSystemRepresentation);
    }
    return @{
        @"ok": @(replacementVerified),
        @"preimageMatched": @YES,
        @"expectedLength": @(expected.length),
        @"replacementLength": @(replacement.length),
        @"temporaryWriteSucceeded": @(temporaryWriteSucceeded),
        @"temporaryVerified": @(temporaryVerified),
        @"renameStatus": @(renameStatus),
        @"replacementVerified": @(replacementVerified),
        @"originalPreserved": @(originalPreserved),
        @"liveAfterLength": @(liveAfter.length),
        @"temporaryCleanupStatus": @(cleanupStatus),
        @"temporaryAbsent": @(!AFCExists(session->afc, temporary)),
    };
}

static NSDictionary *SessionSummary(DeviceSession *session) {
    id productType = session->connected
        ? CFBridgingRelease(AMDeviceCopyValue(
              session->device, NULL, CFSTR("ProductType"))) : nil;
    id productVersion = session->connected
        ? CFBridgingRelease(AMDeviceCopyValue(
              session->device, NULL, CFSTR("ProductVersion"))) : nil;
    id buildVersion = session->connected
        ? CFBridgingRelease(AMDeviceCopyValue(
              session->device, NULL, CFSTR("BuildVersion"))) : nil;
    return @{
        @"subscribeStatus": @(session->subscribeStatus),
        @"targetObserved": @(session->device != NULL),
        @"connectStatus": @(session->connectStatus),
        @"validateStatus": @(session->validateStatus),
        @"sessionStatus": @(session->sessionStatus),
        @"serviceStatus": @(session->serviceStatus),
        @"afcStatus": @(session->afcStatus),
        @"productType": [productType isKindOfClass:[NSString class]]
            ? productType : @"(nil)",
        @"productVersion": [productVersion isKindOfClass:[NSString class]]
            ? productVersion : @"(nil)",
        @"buildVersion": [buildVersion isKindOfClass:[NSString class]]
            ? buildVersion : @"(nil)",
    };
}

static BOOL SendAll(AMDServiceConnectionRef service, NSData *data) {
    const uint8_t *cursor = data.bytes;
    size_t remaining = data.length;
    while (remaining) {
        int sent = AMDServiceConnectionSend(service, cursor, remaining);
        if (sent <= 0) return NO;
        cursor += sent;
        remaining -= (size_t)sent;
    }
    return YES;
}

static BOOL IsSafeNestedName(NSString *value, NSString *prefix);
static NSDictionary *AFCFileInfoDictionary(AFCConnectionRef afc,
                                           NSString *path);

static NSDictionary *Stage(DeviceSession *session, NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1], *recovered = args[2];
    NSData *archive = [NSData dataWithContentsOfFile:args[3]];
    NSData *books = [NSData dataWithContentsOfFile:args[4]];
    BOOL booksPreimageAbsent = YES;
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
        if (AFCExists(session->afc,
                      [NSString stringWithUTF8String:TrackedBooksFiles[i]]))
            booksPreimageAbsent = NO;
    }
    BOOL freshPaths = !AFCExists(session->afc, source) &&
                      !AFCExists(session->afc, linkDestination) &&
                      !AFCExists(session->afc, recovered);
    if (!archive || !books || !booksPreimageAbsent || !freshPaths) {
        return @{ @"ok": @NO,
                  @"booksPreimageAbsent": @(booksPreimageAbsent),
                  @"freshPaths": @(freshPaths),
                  @"localInputsReadable": @(archive != nil && books != nil) };
    }

    AMDServiceConnectionRef zipService = NULL;
    int zipStatus = AMDeviceSecureStartService(
        session->device, CFSTR("com.apple.streaming_zip_conduit"), NULL,
        &zipService);
    int messageStatus = -1, responseStatus = -1;
    BOOL archiveSent = NO;
    CFTypeRef response = NULL;
    if (zipStatus == 0 && zipService) {
        messageStatus = AMDServiceConnectionSendMessage(
            zipService, (__bridge CFTypeRef)@{ @"MediaSubdir": source },
            kCFPropertyListBinaryFormat_v1_0);
        if (messageStatus == 0) archiveSent = SendAll(zipService, archive);
        if (archiveSent) {
            int socket = AMDServiceConnectionGetSocket(zipService);
            struct timeval timeout = { .tv_sec = 30, .tv_usec = 0 };
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            CFPropertyListFormat format = kCFPropertyListBinaryFormat_v1_0;
            responseStatus = AMDServiceConnectionReceiveMessage(
                zipService, &response, &format);
        }
    }
    if (response) CFRelease(response);
    if (zipService) AMDServiceConnectionInvalidate(zipService);

    BOOL sourceObjects = AFCExists(session->afc, source) &&
        (AFCExists(session->afc,
                   [source stringByAppendingPathComponent:@"pivot/link"]) ||
         AFCExists(session->afc,
                   [source stringByAppendingPathComponent:@"p0/p1/p2/link"])) &&
        AFCExists(session->afc, [source stringByAppendingPathComponent:@"payload"]);
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL booksWritten = sourceObjects && directoryReady &&
        AFCWriteFile(session->afc, @"Books/Sync/Books.plist", books);
    return @{
        @"ok": @(zipStatus == 0 && messageStatus == 0 && archiveSent &&
                  sourceObjects && booksWritten),
        @"booksPreimageAbsent": @YES, @"freshPaths": @YES,
        @"zipServiceStatus": @(zipStatus),
        @"zipMessageStatus": @(messageStatus),
        @"archiveSent": @(archiveSent),
        @"zipResponseStatus": @(responseStatus),
        @"sourceObjectsPresent": @(sourceObjects),
        @"booksWritten": @(booksWritten),
    };
}

static NSDictionary *StreamingZipOverwriteGeneratedPivot(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *outerLink = args[0], *pivotLeaf = args[1];
    NSData *archive = [NSData dataWithContentsOfFile:args[2]];
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(pivotLeaf, @"codex-dir-pivot-24A435-");
    NSString *pivotPath = [outerLink stringByAppendingPathComponent:pivotLeaf];
    BOOL generatedStateReady = safeArguments &&
        AFCExists(session->afc, outerLink) && AFCExists(session->afc, pivotPath);
    if (!archive || !generatedStateReady)
        return @{ @"ok": @NO,
                  @"safeArguments": @(safeArguments),
                  @"generatedStateReady": @(generatedStateReady),
                  @"localInputReadable": @(archive != nil) };

    AMDServiceConnectionRef zipService = NULL;
    int zipStatus = AMDeviceSecureStartService(
        session->device, CFSTR("com.apple.streaming_zip_conduit"), NULL,
        &zipService);
    int messageStatus = -1, responseStatus = -1;
    BOOL archiveSent = NO;
    CFTypeRef response = NULL;
    if (zipStatus == 0 && zipService) {
        messageStatus = AMDServiceConnectionSendMessage(
            zipService, (__bridge CFTypeRef)@{ @"MediaSubdir": outerLink },
            kCFPropertyListBinaryFormat_v1_0);
        if (messageStatus == 0) archiveSent = SendAll(zipService, archive);
        if (archiveSent) {
            int socket = AMDServiceConnectionGetSocket(zipService);
            struct timeval timeout = { .tv_sec = 30, .tv_usec = 0 };
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            CFPropertyListFormat format = kCFPropertyListBinaryFormat_v1_0;
            responseStatus = AMDServiceConnectionReceiveMessage(
                zipService, &response, &format);
        }
    }
    if (response) CFRelease(response);
    if (zipService) AMDServiceConnectionInvalidate(zipService);
    return @{
        @"ok": @(zipStatus == 0 && messageStatus == 0 && archiveSent),
        @"safeArguments": @YES,
        @"generatedStateReady": @YES,
        @"zipServiceStatus": @(zipStatus),
        @"zipMessageStatus": @(messageStatus),
        @"archiveSent": @(archiveSent),
        @"zipResponseStatus": @(responseStatus),
        @"pivotPathStillResolves": @(AFCExists(session->afc, pivotPath)),
    };
}

/*
 * Single-hop MobileGestalt writer candidate: AirTraffic has already relocated
 * outerLink directly to the fixed cache directory.  StreamingZip receives a
 * locally generated archive and a fixed generated MediaSubdir; the archive
 * itself is independently verified by exact post-write export.
 */
static NSDictionary *StreamingZipWriteGeneratedMGCache(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *outerLink = args[0];
    NSData *archive = [NSData dataWithContentsOfFile:args[1]];
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        archive.length > 0 && archive.length <= 2 * 1024 * 1024;
    NSString *target = [outerLink stringByAppendingPathComponent:
        @"com.apple.MobileGestalt.plist"];
    NSDictionary *targetBefore = safeArguments
        ? AFCFileInfoDictionary(session->afc, target)
        : @{ @"present": @NO };
    BOOL generatedStateReady = safeArguments &&
        AFCExists(session->afc, outerLink) && [targetBefore[@"present"] boolValue];
    if (!generatedStateReady)
        return @{ @"ok": @NO, @"safeArguments": @(safeArguments),
                  @"generatedStateReady": @(generatedStateReady),
                  @"targetBefore": targetBefore };

    AMDServiceConnectionRef zipService = NULL;
    int zipStatus = AMDeviceSecureStartService(
        session->device, CFSTR("com.apple.streaming_zip_conduit"), NULL,
        &zipService);
    int messageStatus = -1, responseStatus = -1;
    BOOL archiveSent = NO;
    CFTypeRef response = NULL;
    if (zipStatus == 0 && zipService) {
        messageStatus = AMDServiceConnectionSendMessage(
            zipService, (__bridge CFTypeRef)@{ @"MediaSubdir": outerLink },
            kCFPropertyListBinaryFormat_v1_0);
        if (messageStatus == 0) archiveSent = SendAll(zipService, archive);
        if (archiveSent) {
            int socket = AMDServiceConnectionGetSocket(zipService);
            struct timeval timeout = { .tv_sec = 30, .tv_usec = 0 };
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            CFPropertyListFormat format = kCFPropertyListBinaryFormat_v1_0;
            responseStatus = AMDServiceConnectionReceiveMessage(
                zipService, &response, &format);
        }
    }
    if (response) CFRelease(response);
    if (zipService) AMDServiceConnectionInvalidate(zipService);
    NSDictionary *targetAfter = AFCFileInfoDictionary(session->afc, target);
    return @{ @"ok": @(zipStatus == 0 && messageStatus == 0 && archiveSent),
              @"safeArguments": @YES, @"generatedStateReady": @YES,
              @"zipServiceStatus": @(zipStatus),
              @"zipMessageStatus": @(messageStatus),
              @"archiveSent": @(archiveSent),
              @"zipResponseStatus": @(responseStatus),
              @"targetBefore": targetBefore, @"targetAfter": targetAfter };
}

static NSDictionary *VerifyAndCleanup(DeviceSession *session,
                                      NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1], *recovered = args[2];
    NSData *expected = [NSData dataWithContentsOfFile:args[3]];
    NSData *observed = AFCReadFile(session->afc, recovered);
    BOOL recoveredPresent = observed != nil;
    BOOL bytesMatch = expected && observed && [expected isEqualToData:observed];
    NSError *plistError = nil;
    id recoveredPlist = observed ?
        [NSPropertyListSerialization propertyListWithData:observed
                                                   options:NSPropertyListImmutable
                                                    format:NULL
                                                     error:&plistError] : nil;
    NSDictionary *recoveredDictionary =
        [recoveredPlist isKindOfClass:NSDictionary.class] ? recoveredPlist : nil;
    id recoveredEnableStark = recoveredDictionary[@"EnableStark"];
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    NSArray<NSString *> *generated = @[
        linkDestination, recovered,
        [source stringByAppendingPathComponent:@"pivot/link"],
        [source stringByAppendingPathComponent:@"payload"],
        [source stringByAppendingPathComponent:@"META-INF/com.apple.ZipMetadata.plist"],
        [source stringByAppendingPathComponent:@"META-INF"],
        [source stringByAppendingPathComponent:@"Library/Preferences"],
        [source stringByAppendingPathComponent:@"Library"],
        [source stringByAppendingPathComponent:@"pivot"], source,
    ];
    for (NSString *path in generated)
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
        NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[i]];
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    }
    BOOL booksFilesAbsent = YES;
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++)
        if (AFCExists(session->afc,
                      [NSString stringWithUTF8String:TrackedBooksFiles[i]]))
            booksFilesAbsent = NO;
    return @{
        @"ok": @(recoveredPresent && bytesMatch && failures.count == 0 &&
                  booksFilesAbsent),
        @"recoveredPresent": @(recoveredPresent),
        @"recoveredBytesMatch": @(bytesMatch),
        @"observedLength": @(observed.length),
        @"recoveredRootIsDictionary": @(recoveredDictionary != nil),
        @"recoveredKeyCount": @(recoveredDictionary.count),
        @"recoveredEnableStark": recoveredEnableStark ?: [NSNull null],
        @"recoveredPlistParseError": plistError.localizedDescription ?: [NSNull null],
        @"cleanupFailureCount": @(failures.count),
        @"sourceMediaAbsent": @(!AFCExists(session->afc, source)),
        @"linkAbsent": @(!AFCExists(session->afc, linkDestination)),
        @"recoveredAbsent": @(!AFCExists(session->afc, recovered)),
        @"booksFilesAbsent": @(booksFilesAbsent),
    };
}

static BOOL IsSafeRelativePath(NSString *path) {
    if (!path.length || [path hasPrefix:@"/"] || [path hasSuffix:@"/"])
        return NO;
    for (NSString *component in [path componentsSeparatedByString:@"/"])
        if (!component.length || [component isEqual:@"."] ||
            [component isEqual:@".."])
            return NO;
    return YES;
}

static NSDictionary *VerifyMatrixAndCleanup(DeviceSession *session,
                                             NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1], *recovered = args[2];
    NSString *expectedPath = args[3];
    NSString *alternateExpectedPath = args.count == 6 ? args[4] : nil;
    NSString *targetTail = args.count == 6 ? args[5] : args[4];
    BOOL safeArguments = [source hasPrefix:@"codex-dir-src-24A435-"] &&
        [linkDestination hasPrefix:@"codex-dir-link-24A435-"] &&
        [recovered hasPrefix:@"codex-dir-recovered-24A435-"] &&
        IsSafeRelativePath(targetTail);
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSData *expected = [NSData dataWithContentsOfFile:expectedPath];
    NSData *alternateExpected = alternateExpectedPath
        ? [NSData dataWithContentsOfFile:alternateExpectedPath] : nil;
    NSData *observed = AFCReadFile(session->afc, recovered);
    BOOL recoveredPresent = observed != nil;
    BOOL bytesMatch = expected && observed && [expected isEqualToData:observed];
    BOOL alternateBytesMatch = alternateExpected && observed &&
        [alternateExpected isEqualToData:observed];
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    NSMutableArray<NSString *> *generated = [NSMutableArray arrayWithArray:@[
        linkDestination, recovered,
        [source stringByAppendingPathComponent:@"p0/p1/p2/link"],
        [source stringByAppendingPathComponent:@"payload"],
        [source stringByAppendingPathComponent:@"META-INF/com.apple.ZipMetadata.plist"],
        [source stringByAppendingPathComponent:@"META-INF"],
    ]];

    NSMutableArray<NSString *> *tailDirectories = [NSMutableArray array];
    NSString *cursor = source;
    for (NSString *component in [targetTail componentsSeparatedByString:@"/"]) {
        cursor = [cursor stringByAppendingPathComponent:component];
        [tailDirectories addObject:cursor];
    }
    for (NSString *path in [tailDirectories reverseObjectEnumerator])
        [generated addObject:path];
    [generated addObjectsFromArray:@[
        [source stringByAppendingPathComponent:@"p0/p1/p2"],
        [source stringByAppendingPathComponent:@"p0/p1"],
        [source stringByAppendingPathComponent:@"p0"],
        source,
    ]];

    for (NSString *path in generated)
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
        NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[i]];
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    }
    BOOL booksFilesAbsent = YES;
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++)
        if (AFCExists(session->afc,
                      [NSString stringWithUTF8String:TrackedBooksFiles[i]]))
            booksFilesAbsent = NO;
    return @{
        @"ok": @(recoveredPresent && (bytesMatch || alternateBytesMatch) &&
                  failures.count == 0 &&
                  booksFilesAbsent),
        @"safeArguments": @YES,
        @"recoveredPresent": @(recoveredPresent),
        @"recoveredBytesMatch": @(bytesMatch),
        @"recoveredAlternateBytesMatch": @(alternateBytesMatch),
        @"observedLength": @(observed.length),
        @"cleanupFailureCount": @(failures.count),
        @"sourceMediaAbsent": @(!AFCExists(session->afc, source)),
        @"linkAbsent": @(!AFCExists(session->afc, linkDestination)),
        @"recoveredAbsent": @(!AFCExists(session->afc, recovered)),
        @"booksFilesAbsent": @(booksFilesAbsent),
    };
}

static NSDictionary *ReadDisposableThroughLink(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *path = args[0];
    NSString *expectedPath = args[1];
    NSArray<NSString *> *components = [path componentsSeparatedByString:@"/"];
    BOOL safePath = components.count == 2 &&
        [components[0] hasPrefix:@"codex-dir-link-24A435-"] &&
        [components[1] hasPrefix:@"codex-disposable-messages-"] &&
        [components[1] hasSuffix:@".sqlite"];
    if (!safePath)
        return @{ @"ok": @NO, @"safePath": @NO };
    NSData *expected = [NSData dataWithContentsOfFile:expectedPath];
    NSData *observed = AFCReadFile(session->afc, path);
    BOOL exact = expected && observed && [expected isEqualToData:observed];
    return @{
        @"ok": @(exact),
        @"safePath": @YES,
        @"observedPresent": @(observed != nil),
        @"observedLength": @(observed.length),
        @"observedBytesMatch": @(exact),
    };
}

static BOOL IsSafeNestedName(NSString *value, NSString *prefix) {
    return value.length && [value hasPrefix:prefix] &&
        [value rangeOfString:@"/"].location == NSNotFound &&
        ![value isEqual:@"."] && ![value isEqual:@".."];
}

static NSDictionary *AFCFileInfoDictionary(AFCConnectionRef afc,
                                           NSString *path) {
    AFCKeyValueRef info = NULL;
    int status = AFCFileInfoOpen(afc, path.fileSystemRepresentation, &info);
    if (status != 0 || !info)
        return @{ @"status": @(status), @"present": @NO };
    NSMutableDictionary *values = [NSMutableDictionary dictionary];
    char *key = NULL;
    char *value = NULL;
    while (AFCKeyValueRead(info, &key, &value) == 0 && key && value) {
        values[[NSString stringWithUTF8String:key]] =
            [NSString stringWithUTF8String:value];
        key = NULL;
        value = NULL;
    }
    AFCKeyValueClose(info);
    return @{ @"status": @0, @"present": @YES, @"values": values };
}

static BOOL AllTrackedBooksFilesAbsent(AFCConnectionRef afc) {
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++)
        if (AFCExists(afc, [NSString stringWithUTF8String:TrackedBooksFiles[i]]))
            return NO;
    return YES;
}

static BOOL SpringBoardBrowserBooksAreSafe(NSData *data, NSString *source) {
    if (!data) return NO;
    id root = [NSPropertyListSerialization propertyListWithData:data
                                                        options:0
                                                         format:NULL
                                                          error:nil];
    NSArray *rows = [root isKindOfClass:NSDictionary.class] &&
        [root[@"Books"] isKindOfClass:NSArray.class] ? root[@"Books"] : nil;
    if (rows.count != 1 || ![rows[0] isKindOfClass:NSDictionary.class])
        return NO;
    NSString *expected = [NSString stringWithFormat:
        @"../../%@/p0/p1/p2/link", source];
    return [rows[0][@"Persistent ID"] isEqual:expected];
}

static BOOL BrowserSourceIsSafe(NSString *value) {
    return IsSafeNestedName(value, @"codex-sb-browser-src-24A435-") ||
           IsSafeNestedName(value, @"codex-file-browser-src-24A435-");
}

static BOOL BrowserLinkIsSafe(NSString *value) {
    return IsSafeNestedName(value, @"codex-sb-browser-link-24A435-") ||
           IsSafeNestedName(value, @"codex-file-browser-link-24A435-");
}

/* Remove a generated Media tree without ever traversing a symlink. */
static BOOL AFCRemoveGeneratedTree(AFCConnectionRef afc, NSString *path,
                                   NSUInteger depth) {
    if (depth > 32) return NO;
    NSDictionary *info = AFCFileInfoDictionary(afc, path);
    if (![info[@"present"] boolValue]) return YES;
    NSString *kind = [info[@"values"] isKindOfClass:NSDictionary.class]
        ? info[@"values"][@"st_ifmt"] : nil;
    if ([kind isEqual:@"S_IFDIR"]) {
        AFCDirectoryRef directory = NULL;
        if (AFCDirectoryOpen(afc, path.fileSystemRepresentation, &directory) != 0 ||
            !directory)
            return NO;
        NSMutableArray<NSString *> *children = [NSMutableArray array];
        BOOL readOK = YES;
        for (NSUInteger index = 0; index < 8192; index++) {
            char *rawEntry = NULL;
            int status = AFCDirectoryRead(afc, directory, &rawEntry);
            if (status != 0) { readOK = NO; break; }
            if (!rawEntry) break;
            NSString *name = [NSString stringWithUTF8String:rawEntry];
            if (!name || [name isEqual:@"."] || [name isEqual:@".."]) continue;
            [children addObject:name];
        }
        BOOL closeOK = AFCDirectoryClose(afc, directory) == 0;
        if (!readOK || !closeOK) return NO;
        for (NSString *name in children) {
            NSString *child = [path stringByAppendingPathComponent:name];
            if (!AFCRemoveGeneratedTree(afc, child, depth + 1)) return NO;
        }
    }
    return AFCRemovePath(afc, path.fileSystemRepresentation) == 0 &&
           !AFCExists(afc, path);
}

static BOOL SpringBoardLeafIsSafe(NSString *leaf) {
    return IsSafeRelativePath(leaf) &&
        [leaf rangeOfString:@"/"].location == NSNotFound &&
        [leaf hasSuffix:@".plist"];
}

static BOOL BooksHaveExactIdentifiers(NSData *data,
                                      NSArray<NSString *> *expected) {
    if (!data || !expected.count) return NO;
    id root = [NSPropertyListSerialization propertyListWithData:data
                                                        options:0
                                                         format:NULL
                                                          error:nil];
    NSArray *rows = [root isKindOfClass:NSDictionary.class] &&
        [root[@"Books"] isKindOfClass:NSArray.class] ? root[@"Books"] : nil;
    if (rows.count != expected.count) return NO;
    for (NSUInteger index = 0; index < expected.count; index++) {
        if (![rows[index] isKindOfClass:NSDictionary.class] ||
            ![rows[index][@"Persistent ID"] isEqual:expected[index]])
            return NO;
    }
    return YES;
}

static NSArray<NSString *> *SpringBoardExportIdentifiers(NSString *source,
                                                          NSString *leaf) {
    return @[
        [NSString stringWithFormat:@"../../%@/p0/p1/p2/link", source],
        [NSString stringWithFormat:@"../../../Library/SpringBoard/%@", leaf],
    ];
}

static NSString *SpringBoardBackupIdentifier(NSString *recovered) {
    return [NSString stringWithFormat:@"../../%@", recovered];
}

/* Stage a fixed known-file export from SpringBoard to a fresh Media backup. */
static NSDictionary *StageSpringBoardRoundTrip(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *recovered = args[2], *leaf = args[3];
    NSData *archive = [NSData dataWithContentsOfFile:args[4]];
    NSData *books = [NSData dataWithContentsOfFile:args[5]];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-sb-roundtrip-src-24A435-") &&
        IsSafeNestedName(linkDestination,
                         @"codex-sb-roundtrip-link-24A435-") &&
        IsSafeNestedName(recovered,
                         @"codex-sb-roundtrip-backup-24A435-") &&
        SpringBoardLeafIsSafe(leaf) &&
        BooksHaveExactIdentifiers(
            books, SpringBoardExportIdentifiers(source, leaf));
    BOOL booksPreimageAbsent = AllTrackedBooksFilesAbsent(session->afc);
    BOOL freshPaths = !AFCExists(session->afc, source) &&
                      !AFCExists(session->afc, linkDestination) &&
                      !AFCExists(session->afc, recovered);
    if (!safeArguments || !archive || !books || !booksPreimageAbsent ||
        !freshPaths) {
        return @{ @"ok": @NO, @"safeArguments": @(safeArguments),
                  @"booksPreimageAbsent": @(booksPreimageAbsent),
                  @"freshPaths": @(freshPaths),
                  @"localInputsReadable": @(archive != nil && books != nil) };
    }

    AMDServiceConnectionRef zipService = NULL;
    int zipStatus = AMDeviceSecureStartService(
        session->device, CFSTR("com.apple.streaming_zip_conduit"), NULL,
        &zipService);
    int messageStatus = -1, responseStatus = -1;
    BOOL archiveSent = NO;
    CFTypeRef response = NULL;
    if (zipStatus == 0 && zipService) {
        messageStatus = AMDServiceConnectionSendMessage(
            zipService, (__bridge CFTypeRef)@{ @"MediaSubdir": source },
            kCFPropertyListBinaryFormat_v1_0);
        if (messageStatus == 0) archiveSent = SendAll(zipService, archive);
        if (archiveSent) {
            int socket = AMDServiceConnectionGetSocket(zipService);
            struct timeval timeout = { .tv_sec = 30, .tv_usec = 0 };
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout));
            CFPropertyListFormat format = kCFPropertyListBinaryFormat_v1_0;
            responseStatus = AMDServiceConnectionReceiveMessage(
                zipService, &response, &format);
        }
    }
    if (response) CFRelease(response);
    if (zipService) AMDServiceConnectionInvalidate(zipService);

    NSString *link = [source stringByAppendingPathComponent:@"p0/p1/p2/link"];
    BOOL sourceObjects = AFCExists(session->afc, source) &&
                         AFCExists(session->afc, link);
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL booksWritten = sourceObjects && directoryReady &&
        AFCWriteFile(session->afc, @"Books/Sync/Books.plist", books);
    return @{
        @"ok": @(zipStatus == 0 && messageStatus == 0 && archiveSent &&
                  sourceObjects && booksWritten),
        @"safeArguments": @YES, @"booksPreimageAbsent": @YES,
        @"freshPaths": @YES, @"zipServiceStatus": @(zipStatus),
        @"zipMessageStatus": @(messageStatus),
        @"zipResponseStatus": @(responseStatus),
        @"archiveSent": @(archiveSent),
        @"sourceObjectsPresent": @(sourceObjects),
        @"booksWritten": @(booksWritten),
    };
}

/* Replace the generated export manifest with the exact same-object restore. */
static NSDictionary *StageSpringBoardRestoreBooks(DeviceSession *session,
                                                   NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *recovered = args[2], *leaf = args[3];
    NSData *incoming = [NSData dataWithContentsOfFile:args[4]];
    NSData *current = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    NSArray<NSString *> *exportIdentifiers =
        SpringBoardExportIdentifiers(source, leaf);
    NSArray<NSString *> *restoreIdentifiers = @[
        SpringBoardBackupIdentifier(recovered),
    ];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-sb-roundtrip-src-24A435-") &&
        IsSafeNestedName(linkDestination,
                         @"codex-sb-roundtrip-link-24A435-") &&
        IsSafeNestedName(recovered,
                         @"codex-sb-roundtrip-backup-24A435-") &&
        SpringBoardLeafIsSafe(leaf) &&
        BooksHaveExactIdentifiers(incoming, restoreIdentifiers);
    BOOL currentSafe = current == nil ||
        BooksHaveExactIdentifiers(current, exportIdentifiers) ||
        BooksHaveExactIdentifiers(current, restoreIdentifiers);
    BOOL generatedStateReady = AFCExists(session->afc, linkDestination) &&
                               AFCExists(session->afc, recovered);
    BOOL cleared = safeArguments && currentSafe && generatedStateReady;
    if (cleared) {
        for (NSUInteger index = 0;
             index < sizeof(TrackedBooksFiles) / sizeof(char *); index++) {
            NSString *path =
                [NSString stringWithUTF8String:TrackedBooksFiles[index]];
            if (!RemoveIfPresent(session->afc, path)) cleared = NO;
        }
    }
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL wrote = incoming && cleared && directoryReady &&
        AFCWriteFile(session->afc, @"Books/Sync/Books.plist", incoming);
    return @{ @"ok": @(wrote), @"safeArguments": @(safeArguments),
              @"currentBooksSafe": @(currentSafe),
              @"generatedStateReady": @(generatedStateReady),
              @"oldBooksCleared": @(cleared), @"booksWritten": @(wrote) };
}

static NSDictionary *CopySpringBoardRoundTripBackup(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *recovered = args[0], *localOutput = args[1];
    NSString *localLeaf = localOutput.lastPathComponent;
    BOOL safeArguments =
        IsSafeNestedName(recovered,
                         @"codex-sb-roundtrip-backup-24A435-") &&
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"] &&
        IsSafeNestedName(localLeaf, @"codex-springboard-read-24A435-") &&
        [localLeaf hasSuffix:@".plist"] &&
        ![NSFileManager.defaultManager fileExistsAtPath:localOutput];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSData *data = nil;
    NSMutableDictionary *result =
        [AFCReadFileDirect(session->afc, recovered, &data) mutableCopy];
    id plist = data ? [NSPropertyListSerialization
        propertyListWithData:data options:NSPropertyListImmutable
        format:NULL error:nil] : nil;
    BOOL validPlist = [plist isKindOfClass:NSDictionary.class] ||
                      [plist isKindOfClass:NSArray.class];
    NSError *error = nil;
    BOOL wrote = [result[@"ok"] boolValue] && validPlist &&
        [data writeToFile:localOutput options:NSDataWritingWithoutOverwriting
                    error:&error];
    result[@"ok"] = @(wrote);
    result[@"safeArguments"] = @YES;
    result[@"validPlist"] = @(validPlist);
    result[@"localWriteOK"] = @(wrote);
    result[@"localOutput"] = localOutput;
    result[@"localWriteError"] = error.localizedDescription ?: [NSNull null];
    result[@"deviceContentWriteAttempted"] = @NO;
    return result;
}

static NSDictionary *ProbeSpringBoardRoundTrip(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *linkDestination = args[0], *recovered = args[1];
    NSString *leaf = args[2];
    BOOL safeArguments =
        IsSafeNestedName(linkDestination,
                         @"codex-sb-roundtrip-link-24A435-") &&
        IsSafeNestedName(recovered,
                         @"codex-sb-roundtrip-backup-24A435-") &&
        SpringBoardLeafIsSafe(leaf);
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSString *target = [linkDestination stringByAppendingPathComponent:leaf];
    NSDictionary *targetInfo = AFCFileInfoDictionary(session->afc, target);
    NSDictionary *backupInfo = AFCFileInfoDictionary(session->afc, recovered);
    NSInteger targetStatus = [targetInfo[@"status"] integerValue];
    BOOL targetObserved = [targetInfo[@"present"] boolValue] ||
                          targetStatus == 10 || targetStatus == 23;
    return @{ @"ok": @YES, @"safeArguments": @YES,
              @"linkPresent": @(AFCExists(session->afc, linkDestination)),
              @"targetObserved": @(targetObserved),
              @"targetInfo": targetInfo, @"backupInfo": backupInfo,
              @"backupPresent": @([backupInfo[@"present"] boolValue]) };
}

static NSDictionary *CleanupSpringBoardRoundTrip(DeviceSession *session,
                                                  NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *recovered = args[2], *leaf = args[3];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-sb-roundtrip-src-24A435-") &&
        IsSafeNestedName(linkDestination,
                         @"codex-sb-roundtrip-link-24A435-") &&
        IsSafeNestedName(recovered,
                         @"codex-sb-roundtrip-backup-24A435-") &&
        SpringBoardLeafIsSafe(leaf);
    NSDictionary *backupInfo = AFCFileInfoDictionary(session->afc, recovered);
    if (!safeArguments || [backupInfo[@"present"] boolValue]) {
        return @{ @"ok": @NO, @"safeArguments": @(safeArguments),
                  @"backupStillPresent": @([backupInfo[@"present"] boolValue]) };
    }

    NSData *current = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL booksSafe = current == nil ||
        BooksHaveExactIdentifiers(
            current, SpringBoardExportIdentifiers(source, leaf)) ||
        BooksHaveExactIdentifiers(
            current, @[ SpringBoardBackupIdentifier(recovered) ]);
    if (!booksSafe)
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"booksSafe": @NO, @"backupStillPresent": @NO };

    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    NSArray<NSString *> *generated = @[
        linkDestination,
        [source stringByAppendingPathComponent:@"p0/p1/p2/link"],
        [source stringByAppendingPathComponent:@"payload"],
        [source stringByAppendingPathComponent:
            @"META-INF/com.apple.ZipMetadata.plist"],
        [source stringByAppendingPathComponent:@"META-INF"],
        [source stringByAppendingPathComponent:@"var/mobile/Library/SpringBoard"],
        [source stringByAppendingPathComponent:@"var/mobile/Library"],
        [source stringByAppendingPathComponent:@"var/mobile"],
        [source stringByAppendingPathComponent:@"var"],
        [source stringByAppendingPathComponent:@"p0/p1/p2"],
        [source stringByAppendingPathComponent:@"p0/p1"],
        [source stringByAppendingPathComponent:@"p0"],
        source,
    ];
    for (NSUInteger index = 0;
         index < sizeof(TrackedBooksFiles) / sizeof(char *); index++) {
        NSString *path =
            [NSString stringWithUTF8String:TrackedBooksFiles[index]];
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    }
    for (NSString *path in generated)
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    return @{ @"ok": @(failures.count == 0), @"safeArguments": @YES,
              @"booksSafe": @YES, @"backupStillPresent": @NO,
              @"cleanupFailureCount": @(failures.count),
              @"failures": failures,
              @"sourceAbsent": @(!AFCExists(session->afc, source)),
              @"linkAbsent": @(!AFCExists(session->afc, linkDestination)),
              @"booksFilesAbsent": @(AllTrackedBooksFilesAbsent(session->afc)) };
}

/*
 * Stateful IconState replacement support.  The generic directory-matrix
 * stager mints the source/link/Media names; these helpers only accept the
 * fixed SpringBoard IconState leaf and those generated names.  The original
 * live inode remains in a randomized Media backup until an explicit restore.
 */
static BOOL SpringBoardReplaceIdentifierIsSafe(NSString *identifier,
                                                NSString *source,
                                                NSString *original,
                                                NSString *verification) {
    if (![identifier isKindOfClass:NSString.class]) return NO;
    NSString *link = [NSString stringWithFormat:
        @"../../%@/p0/p1/p2/link", source];
    NSString *target = @"../../../Library/SpringBoard/IconState.plist";
    NSString *payload = [NSString stringWithFormat:@"../../%@/payload", source];
    NSString *originalIdentifier = [NSString stringWithFormat:@"../../%@", original];
    NSString *verificationIdentifier =
        [NSString stringWithFormat:@"../../%@", verification];
    return [identifier isEqual:link] || [identifier isEqual:target] ||
        [identifier isEqual:payload] ||
        [identifier isEqual:originalIdentifier] ||
        [identifier isEqual:verificationIdentifier];
}

static BOOL SpringBoardReplaceBooksAreSafe(NSData *data,
                                            NSString *source,
                                            NSString *original,
                                            NSString *verification) {
    if (!data) return YES;
    id root = [NSPropertyListSerialization propertyListWithData:data
                                                        options:0
                                                         format:NULL
                                                          error:nil];
    NSArray *rows = [root isKindOfClass:NSDictionary.class] &&
        [root[@"Books"] isKindOfClass:NSArray.class] ? root[@"Books"] : nil;
    if (!rows.count || rows.count > 2) return NO;
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    for (id row in rows) {
        NSString *identifier = [row isKindOfClass:NSDictionary.class]
            ? row[@"Persistent ID"] : nil;
        if (!SpringBoardReplaceIdentifierIsSafe(
                identifier, source, original, verification) ||
            [seen containsObject:identifier]) return NO;
        [seen addObject:identifier];
    }
    return YES;
}

static NSUInteger CountStringInPlist(id value, NSString *needle) {
    if ([value isKindOfClass:NSString.class])
        return [value isEqual:needle] ? 1 : 0;
    NSUInteger count = 0;
    if ([value isKindOfClass:NSArray.class]) {
        for (id child in (NSArray *)value)
            count += CountStringInPlist(child, needle);
    } else if ([value isKindOfClass:NSDictionary.class]) {
        for (id child in [(NSDictionary *)value allValues])
            count += CountStringInPlist(child, needle);
    }
    return count;
}

static NSDictionary *StageSpringBoardReplaceBooks(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *original = args[2], *verification = args[3];
    NSData *incoming = [NSData dataWithContentsOfFile:args[4]];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(original, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(verification, @"codex-dir-recovered-24A435-") &&
        [original hasSuffix:@".plist"] &&
        [verification hasSuffix:@".plist"] &&
        ![original isEqual:verification];
    NSData *current = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL incomingSafe = safeArguments && SpringBoardReplaceBooksAreSafe(
        incoming, source, original, verification);
    BOOL currentSafe = safeArguments && SpringBoardReplaceBooksAreSafe(
        current, source, original, verification);
    BOOL generatedStateReady = safeArguments &&
        AFCExists(session->afc, source) &&
        AFCExists(session->afc, linkDestination) &&
        (AFCExists(session->afc, original) ||
         AFCExists(session->afc, verification));
    BOOL cleared = incomingSafe && currentSafe && generatedStateReady;
    if (cleared) {
        for (NSUInteger i = 0;
             i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
            NSString *path =
                [NSString stringWithUTF8String:TrackedBooksFiles[i]];
            if (!RemoveIfPresent(session->afc, path)) cleared = NO;
        }
    }
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL wrote = incoming && cleared && directoryReady &&
        AFCWriteFile(session->afc, @"Books/Sync/Books.plist", incoming);
    return @{ @"ok": @(wrote), @"safeArguments": @(safeArguments),
              @"incomingBooksSafe": @(incomingSafe),
              @"currentBooksSafe": @(currentSafe),
              @"generatedStateReady": @(generatedStateReady),
              @"oldBooksCleared": @(cleared), @"booksWritten": @(wrote) };
}

static NSDictionary *WriteSpringBoardReplacePayload(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *original = args[2], *localPath = args[3];
    NSString *localLeaf = localPath.lastPathComponent;
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(original, @"codex-dir-recovered-24A435-") &&
        [original hasSuffix:@".plist"] && localPath.isAbsolutePath &&
        [localLeaf hasPrefix:@"IconState."] && [localLeaf hasSuffix:@".plist"];
    NSData *replacement = safeArguments
        ? [NSData dataWithContentsOfFile:localPath] : nil;
    NSDictionary *plist = replacement && replacement.length <= 1024 * 1024
        ? [NSPropertyListSerialization propertyListWithData:replacement
                                                    options:0
                                                     format:NULL
                                                      error:nil] : nil;
    NSArray *ignored = [plist isKindOfClass:NSDictionary.class] &&
        [plist[@"ignored"] isKindOfClass:NSArray.class] ? plist[@"ignored"] : nil;
    id iconLists = [plist isKindOfClass:NSDictionary.class]
        ? plist[@"iconLists"] : nil;
    id buttonBar = [plist isKindOfClass:NSDictionary.class]
        ? plist[@"buttonBar"] : nil;
    NSString *settings = @"com.apple.Preferences";
    BOOL semanticsSafe = ignored &&
        CountStringInPlist(ignored, settings) == 1 &&
        CountStringInPlist(iconLists, settings) == 0 &&
        CountStringInPlist(buttonBar, settings) == 0;
    NSString *payload = [source stringByAppendingPathComponent:@"payload"];
    BOOL generatedStateReady = safeArguments &&
        AFCExists(session->afc, source) &&
        AFCExists(session->afc, linkDestination) &&
        AFCExists(session->afc, original) && AFCExists(session->afc, payload);
    BOOL wrote = replacement && replacement.length > 0 && semanticsSafe &&
        generatedStateReady && AFCWriteFile(session->afc, payload, replacement);
    NSData *readback = wrote ? AFCReadFile(session->afc, payload) : nil;
    BOOL exact = readback && [readback isEqual:replacement];
    return @{ @"ok": @(exact), @"safeArguments": @(safeArguments),
              @"replacementPlistValid": @(plist != nil),
              @"hideSettingsSemanticsValid": @(semanticsSafe),
              @"generatedStateReady": @(generatedStateReady),
              @"payloadWriteSucceeded": @(wrote),
              @"payloadReadbackExact": @(exact),
              @"replacementLength": @(replacement.length),
              @"observedLength": @(readback.length) };
}

static NSDictionary *ProbeSpringBoardReplace(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *original = args[2], *verification = args[3];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(original, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(verification, @"codex-dir-recovered-24A435-") &&
        ![original isEqual:verification];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSString *target = [linkDestination
        stringByAppendingPathComponent:@"IconState.plist"];
    NSDictionary *targetInfo = AFCFileInfoDictionary(session->afc, target);
    NSDictionary *originalInfo = AFCFileInfoDictionary(session->afc, original);
    NSDictionary *verificationInfo =
        AFCFileInfoDictionary(session->afc, verification);
    NSInteger targetStatus = [targetInfo[@"status"] integerValue];
    BOOL targetObserved = [targetInfo[@"present"] boolValue] ||
                          targetStatus == 10 || targetStatus == 23;
    return @{ @"ok": @YES, @"safeArguments": @YES,
              @"sourcePresent": @(AFCExists(session->afc, source)),
              @"linkPresent": @(AFCExists(session->afc, linkDestination)),
              @"payloadPresent": @(AFCExists(
                  session->afc, [source stringByAppendingPathComponent:@"payload"])),
              @"targetObserved": @(targetObserved),
              @"targetInfo": targetInfo,
              @"originalInfo": originalInfo,
              @"originalPresent": @([originalInfo[@"present"] boolValue]),
              @"verificationInfo": verificationInfo,
              @"verificationPresent":
                  @([verificationInfo[@"present"] boolValue]),
              @"booksSyncPlistPresent":
                  @(AFCExists(session->afc, @"Books/Sync/Books.plist")) };
}

static NSDictionary *ClearSpringBoardReplaceBooks(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *original = args[2], *verification = args[3];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(original, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(verification, @"codex-dir-recovered-24A435-") &&
        ![original isEqual:verification];
    NSData *current = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL booksSafe = safeArguments && SpringBoardReplaceBooksAreSafe(
        current, source, original, verification);
    NSString *target = [linkDestination
        stringByAppendingPathComponent:@"IconState.plist"];
    NSDictionary *targetInfo = AFCFileInfoDictionary(session->afc, target);
    NSInteger targetStatus = [targetInfo[@"status"] integerValue];
    BOOL targetObserved = [targetInfo[@"present"] boolValue] ||
                          targetStatus == 10 || targetStatus == 23;
    BOOL retainedStateSafe = safeArguments &&
        AFCExists(session->afc, source) &&
        AFCExists(session->afc, linkDestination) &&
        AFCExists(session->afc, original) &&
        !AFCExists(session->afc, verification) && targetObserved;
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    if (booksSafe && retainedStateSafe) {
        for (NSUInteger i = 0;
             i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
            NSString *path =
                [NSString stringWithUTF8String:TrackedBooksFiles[i]];
            if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
        }
    }
    BOOL booksAbsent = AllTrackedBooksFilesAbsent(session->afc);
    return @{ @"ok": @(booksSafe && retainedStateSafe &&
                         failures.count == 0 && booksAbsent),
              @"safeArguments": @(safeArguments),
              @"booksSafe": @(booksSafe),
              @"retainedStateSafe": @(retainedStateSafe),
              @"targetObserved": @(targetObserved),
              @"originalPreserved": @(AFCExists(session->afc, original)),
              @"cleanupFailureCount": @(failures.count),
              @"failures": failures, @"booksFilesAbsent": @(booksAbsent) };
}

/* Native staging for a read-only view of the fixed SpringBoard directory. */
static NSDictionary *StageSpringBoardBrowser(DeviceSession *session,
                                              NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSData *archive = [NSData dataWithContentsOfFile:args[2]];
    NSData *books = [NSData dataWithContentsOfFile:args[3]];
    BOOL safeArguments = BrowserSourceIsSafe(source) &&
        BrowserLinkIsSafe(linkDestination) &&
        SpringBoardBrowserBooksAreSafe(books, source);
    BOOL booksPreimageAbsent = AllTrackedBooksFilesAbsent(session->afc);
    BOOL freshPaths = !AFCExists(session->afc, source) &&
                      !AFCExists(session->afc, linkDestination);
    if (!safeArguments || !archive || !books || !booksPreimageAbsent ||
        !freshPaths) {
        return @{ @"ok": @NO, @"safeArguments": @(safeArguments),
                  @"booksPreimageAbsent": @(booksPreimageAbsent),
                  @"freshPaths": @(freshPaths),
                  @"localInputsReadable": @(archive != nil && books != nil) };
    }

    AMDServiceConnectionRef zipService = NULL;
    int zipStatus = AMDeviceSecureStartService(
        session->device, CFSTR("com.apple.streaming_zip_conduit"), NULL,
        &zipService);
    int messageStatus = -1, responseStatus = -1;
    BOOL archiveSent = NO;
    CFTypeRef response = NULL;
    if (zipStatus == 0 && zipService) {
        messageStatus = AMDServiceConnectionSendMessage(
            zipService, (__bridge CFTypeRef)@{ @"MediaSubdir": source },
            kCFPropertyListBinaryFormat_v1_0);
        if (messageStatus == 0) archiveSent = SendAll(zipService, archive);
        if (archiveSent) {
            int socket = AMDServiceConnectionGetSocket(zipService);
            struct timeval timeout = { .tv_sec = 30, .tv_usec = 0 };
            setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout));
            CFPropertyListFormat format = kCFPropertyListBinaryFormat_v1_0;
            responseStatus = AMDServiceConnectionReceiveMessage(
                zipService, &response, &format);
        }
    }
    if (response) CFRelease(response);
    if (zipService) AMDServiceConnectionInvalidate(zipService);

    NSString *link = [source stringByAppendingPathComponent:@"p0/p1/p2/link"];
    BOOL sourceObjects = AFCExists(session->afc, source) &&
                         AFCExists(session->afc, link);
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL booksWritten = sourceObjects && directoryReady &&
        AFCWriteFile(session->afc, @"Books/Sync/Books.plist", books);
    return @{
        @"ok": @(zipStatus == 0 && messageStatus == 0 && archiveSent &&
                  sourceObjects && booksWritten),
        @"safeArguments": @YES,
        @"booksPreimageAbsent": @YES,
        @"freshPaths": @YES,
        @"zipServiceStatus": @(zipStatus),
        @"zipMessageStatus": @(messageStatus),
        @"archiveSent": @(archiveSent),
        @"zipResponseStatus": @(responseStatus),
        @"sourceObjectsPresent": @(sourceObjects),
        @"booksWritten": @(booksWritten),
    };
}

static NSDictionary *ListSpringBoardBrowser(DeviceSession *session,
                                             NSArray<NSString *> *args) {
    NSString *linkDestination = args[0];
    BOOL safeArguments = BrowserLinkIsSafe(linkDestination);
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    AFCDirectoryRef directory = NULL;
    int openStatus = AFCDirectoryOpen(session->afc,
                                      linkDestination.fileSystemRepresentation,
                                      &directory);
    int readStatus = openStatus == 0 ? 0 : -1;
    int closeStatus = -1;
    NSMutableArray<NSDictionary *> *entries = [NSMutableArray array];
    if (openStatus == 0 && directory) {
        for (NSUInteger index = 0; index < 1024; index++) {
            char *rawEntry = NULL;
            readStatus = AFCDirectoryRead(session->afc, directory, &rawEntry);
            if (readStatus != 0 || !rawEntry) break;
            NSString *name = [NSString stringWithUTF8String:rawEntry];
            if (!name || [name isEqual:@"."] || [name isEqual:@".."])
                continue;
            NSString *path = [linkDestination stringByAppendingPathComponent:name];
            [entries addObject:@{ @"name": name,
                                  @"info": AFCFileInfoDictionary(session->afc,
                                                                  path) }];
        }
        closeStatus = AFCDirectoryClose(session->afc, directory);
    }
    [entries sortUsingComparator:^NSComparisonResult(NSDictionary *left,
                                                      NSDictionary *right) {
        return [left[@"name"] localizedCaseInsensitiveCompare:right[@"name"]];
    }];
    BOOL ok = openStatus == 0 && readStatus == 0 && closeStatus == 0;
    return @{ @"ok": @(ok), @"safeArguments": @YES,
              @"openStatus": @(openStatus), @"readStatus": @(readStatus),
              @"closeStatus": @(closeStatus),
              @"entryCount": @(entries.count), @"entries": entries };
}

/* Native AFC view of the ordinary Media domain, with no AirTraffic staging. */
static NSDictionary *ListMediaDirectory(DeviceSession *session,
                                        NSArray<NSString *> *args) {
    NSString *path = args[0];
    BOOL safeArguments = [path isEqual:@"."] || IsSafeRelativePath(path);
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    AFCDirectoryRef directory = NULL;
    int openStatus = AFCDirectoryOpen(session->afc,
                                      path.fileSystemRepresentation,
                                      &directory);
    int readStatus = openStatus == 0 ? 0 : -1;
    int closeStatus = -1;
    NSMutableArray<NSDictionary *> *entries = [NSMutableArray array];
    if (openStatus == 0 && directory) {
        for (NSUInteger index = 0; index < 16384; index++) {
            char *rawEntry = NULL;
            readStatus = AFCDirectoryRead(session->afc, directory, &rawEntry);
            if (readStatus != 0 || !rawEntry) break;
            NSString *name = [NSString stringWithUTF8String:rawEntry];
            if (!name || [name isEqual:@"."] || [name isEqual:@".."]) continue;
            NSString *entryPath = [path isEqual:@"."] ? name
                : [path stringByAppendingPathComponent:name];
            [entries addObject:@{ @"name": name,
                                  @"info": AFCFileInfoDictionary(session->afc,
                                                                  entryPath) }];
        }
        closeStatus = AFCDirectoryClose(session->afc, directory);
    }
    [entries sortUsingComparator:^NSComparisonResult(NSDictionary *left,
                                                      NSDictionary *right) {
        return [left[@"name"] localizedCaseInsensitiveCompare:right[@"name"]];
    }];
    BOOL ok = openStatus == 0 && readStatus == 0 && closeStatus == 0;
    return @{ @"ok": @(ok), @"safeArguments": @YES,
              @"openStatus": @(openStatus), @"readStatus": @(readStatus),
              @"closeStatus": @(closeStatus),
              @"entryCount": @(entries.count), @"entries": entries };
}

/* Copy one regular file from a generated read-only directory pivot to /tmp. */
static NSDictionary *CopyFileBrowserFile(DeviceSession *session,
                                         NSArray<NSString *> *args) {
    NSString *linkDestination = args[0], *leaf = args[1];
    NSString *localOutput = args[2], *localLeaf = localOutput.lastPathComponent;
    BOOL safeLink =
        IsSafeNestedName(linkDestination, @"codex-file-browser-link-24A435-");
    BOOL safeLeaf = IsSafeRelativePath(leaf) &&
                    [leaf rangeOfString:@"/"].location == NSNotFound;
    BOOL safeOutputDirectory =
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"];
    BOOL safeOutputLeaf =
        IsSafeNestedName(localLeaf, @"codex-file-browser-read-24A435-");
    BOOL outputFresh =
        ![NSFileManager.defaultManager fileExistsAtPath:localOutput];
    BOOL safeArguments = safeLink && safeLeaf && safeOutputDirectory &&
                         safeOutputLeaf && outputFresh;
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO,
                  @"safeLink": @(safeLink), @"safeLeaf": @(safeLeaf),
                  @"safeOutputDirectory": @(safeOutputDirectory),
                  @"safeOutputLeaf": @(safeOutputLeaf),
                  @"outputFresh": @(outputFresh) };

    NSString *source = [linkDestination stringByAppendingPathComponent:leaf];
    NSString *linkPrefix = @"codex-file-browser-link-24A435-";
    NSString *token = [linkDestination substringFromIndex:linkPrefix.length];
    NSString *alias = [@"codex-file-browser-copy-24A435-"
        stringByAppendingString:token];
    NSDictionary *sourceInfo = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasBefore = AFCFileInfoDictionary(session->afc, alias);
    if ([aliasBefore[@"present"] boolValue])
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"error": @"generated read alias already exists",
                  @"sourceInfo": sourceInfo, @"aliasBefore": aliasBefore };
    int linkStatus = AFCLinkPath(session->afc, 1,
                                 source.fileSystemRepresentation,
                                 alias.fileSystemRepresentation);
    NSDictionary *aliasLinked = AFCFileInfoDictionary(session->afc, alias);
    NSString *aliasKind = [aliasLinked[@"values"] isKindOfClass:NSDictionary.class]
        ? aliasLinked[@"values"][@"st_ifmt"] : nil;
    BOOL usedHardlinkAlias = linkStatus == 0 &&
                             [aliasKind isEqual:@"S_IFREG"];
    NSString *readPath = usedHardlinkAlias ? alias : source;
    NSDictionary *readInfo = usedHardlinkAlias ? aliasLinked : sourceInfo;
    NSString *kind = [readInfo[@"values"] isKindOfClass:NSDictionary.class]
        ? readInfo[@"values"][@"st_ifmt"] : nil;
    long long expectedLength = AFCFileSize(session->afc, readPath);
    const unsigned long long limit = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    BOOL regularFile = [kind isEqual:@"S_IFREG"];
    BOOL withinLimit = expectedLength >= 0 &&
                       (unsigned long long)expectedLength <= limit;
    if (!regularFile || !withinLimit)
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"regularFile": @(regularFile),
                  @"withinLimit": @(withinLimit),
                  @"linkStatus": @(linkStatus),
                  @"usedHardlinkAlias": @(usedHardlinkAlias),
                  @"expectedLength": @(expectedLength),
                  @"sourceInfo": sourceInfo,
                  @"aliasLinked": aliasLinked };

    AFCFileRef remote = NULL;
    int openStatus = AFCFileRefOpen(session->afc,
                                    readPath.fileSystemRepresentation, 1, &remote);
    int localFD = -1;
    if (openStatus == 0 && remote)
        localFD = open(localOutput.fileSystemRepresentation,
                       O_WRONLY | O_CREAT | O_EXCL, 0600);
    int readStatus = openStatus == 0 ? 0 : -1;
    int writeStatus = localFD >= 0 ? 0 : -1;
    unsigned long long observedLength = 0;
    uint8_t buffer[256 * 1024];
    while (remote && localFD >= 0 && readStatus == 0 && writeStatus == 0) {
        long length = sizeof(buffer);
        readStatus = AFCFileRefRead(session->afc, remote, buffer, &length);
        if (readStatus != 0 || length <= 0) break;
        if (observedLength + (unsigned long long)length > limit) {
            writeStatus = EFBIG;
            break;
        }
        long offset = 0;
        while (offset < length) {
            ssize_t wrote = write(localFD, buffer + offset,
                                  (size_t)(length - offset));
            if (wrote <= 0) { writeStatus = errno ?: EIO; break; }
            offset += wrote;
        }
        if (writeStatus == 0) observedLength += (unsigned long long)length;
    }
    int remoteCloseStatus = remote ? AFCFileRefClose(session->afc, remote) : -1;
    int localCloseStatus = localFD >= 0 ? close(localFD) : -1;
    BOOL sizeMatched = observedLength == (unsigned long long)expectedLength;
    int aliasRemoveStatus = [aliasLinked[@"present"] boolValue]
        ? AFCRemovePath(session->afc, alias.fileSystemRepresentation) : 0;
    NSDictionary *aliasAfter = AFCFileInfoDictionary(session->afc, alias);
    BOOL aliasRemoved = aliasRemoveStatus == 0 &&
                        ![aliasAfter[@"present"] boolValue];
    BOOL ok = openStatus == 0 && localFD >= 0 && readStatus == 0 &&
              writeStatus == 0 && remoteCloseStatus == 0 &&
              localCloseStatus == 0 && sizeMatched && aliasRemoved;
    if (!ok) unlink(localOutput.fileSystemRepresentation);
    return @{ @"ok": @(ok), @"safeArguments": @YES,
              @"regularFile": @YES, @"withinLimit": @YES,
              @"linkStatus": @(linkStatus),
              @"usedHardlinkAlias": @(usedHardlinkAlias),
              @"openStatus": @(openStatus), @"readStatus": @(readStatus),
              @"writeStatus": @(writeStatus),
              @"remoteCloseStatus": @(remoteCloseStatus),
              @"localCloseStatus": @(localCloseStatus),
              @"expectedLength": @(expectedLength),
              @"observedLength": @(observedLength),
              @"sizeMatched": @(sizeMatched),
              @"aliasRemoveStatus": @(aliasRemoveStatus),
              @"aliasRemoved": @(aliasRemoved), @"aliasAfter": aliasAfter,
              @"localOutput": localOutput };
}

/*
 * Bounded existing-file read probe for a generated AirTraffic directory
 * pivot.  A direct open is attempted first.  If that is rejected, the same
 * temporary Media hard-link strategy used by the browser downloader is tried;
 * the alias must be removed before success is reported.
 */
static NSDictionary *ProbeFileBrowserRead(DeviceSession *session,
                                           NSArray<NSString *> *args) {
    NSString *linkDestination = args[0], *leaf = args[1];
    BOOL safeLink =
        IsSafeNestedName(linkDestination, @"codex-file-browser-link-24A435-");
    BOOL safeLeaf = IsSafeRelativePath(leaf) &&
                    [leaf rangeOfString:@"/"].location == NSNotFound;
    if (!safeLink || !safeLeaf)
        return @{ @"ok": @NO, @"safeArguments": @NO,
                  @"safeLink": @(safeLink), @"safeLeaf": @(safeLeaf) };

    NSString *source = [linkDestination stringByAppendingPathComponent:leaf];
    NSDictionary *direct = AFCProbeReadPrefix(session->afc, source);
    if ([direct[@"ok"] boolValue])
        return @{ @"ok": @YES, @"safeArguments": @YES,
                  @"pathUsed": @"direct-pivot", @"direct": direct,
                  @"aliasAttempted": @NO, @"aliasRemoved": @YES };

    NSString *prefix = @"codex-file-browser-link-24A435-";
    NSString *token = [linkDestination substringFromIndex:prefix.length];
    NSString *alias = [@"codex-file-browser-copy-24A435-"
        stringByAppendingString:token];
    NSDictionary *aliasBefore = AFCFileInfoDictionary(session->afc, alias);
    if ([aliasBefore[@"present"] boolValue])
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"direct": direct, @"aliasAttempted": @NO,
                  @"aliasRemoved": @NO,
                  @"error": @"generated read alias already exists" };

    int linkStatus = AFCLinkPath(session->afc, 1,
                                 source.fileSystemRepresentation,
                                 alias.fileSystemRepresentation);
    NSDictionary *aliased = linkStatus == 0
        ? AFCProbeReadPrefix(session->afc, alias)
        : @{ @"ok": @NO };
    int removeStatus = AFCExists(session->afc, alias)
        ? AFCRemovePath(session->afc, alias.fileSystemRepresentation) : 0;
    BOOL aliasRemoved = removeStatus == 0 && !AFCExists(session->afc, alias);
    BOOL ok = linkStatus == 0 && [aliased[@"ok"] boolValue] && aliasRemoved;
    return @{ @"ok": @(ok), @"safeArguments": @YES,
              @"pathUsed": ok ? @"temporary-hardlink" : @"none",
              @"direct": direct, @"aliasAttempted": @YES,
              @"linkStatus": @(linkStatus), @"aliased": aliased,
              @"aliasRemoveStatus": @(removeStatus),
              @"aliasRemoved": @(aliasRemoved),
              @"contentReturned": @NO };
}

/* Bounded read probe for an ordinary file in the AFC Media domain. */
static NSDictionary *ProbeMediaRead(DeviceSession *session,
                                    NSArray<NSString *> *args) {
    NSString *path = args[0];
    BOOL safeArguments = IsSafeRelativePath(path);
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSMutableDictionary *result =
        [AFCProbeReadPrefix(session->afc, path) mutableCopy];
    result[@"safeArguments"] = @YES;
    result[@"contentReturned"] = @NO;
    return result;
}

/* Stream one ordinary AFC Media file to a fresh /tmp output. */
static NSDictionary *CopyMediaFile(DeviceSession *session,
                                   NSArray<NSString *> *args) {
    NSString *source = args[0], *localOutput = args[1];
    NSString *localLeaf = localOutput.lastPathComponent;
    BOOL safeArguments = IsSafeRelativePath(source) &&
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"] &&
        IsSafeNestedName(localLeaf, @"codex-file-browser-read-24A435-") &&
        ![NSFileManager.defaultManager fileExistsAtPath:localOutput];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSDictionary *sourceInfo = AFCFileInfoDictionary(session->afc, source);
    NSString *kind = [sourceInfo[@"values"] isKindOfClass:NSDictionary.class]
        ? sourceInfo[@"values"][@"st_ifmt"] : nil;
    long long expectedLength = AFCFileSize(session->afc, source);
    const unsigned long long limit = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    BOOL regularFile = [kind isEqual:@"S_IFREG"];
    BOOL withinLimit = expectedLength >= 0 &&
                       (unsigned long long)expectedLength <= limit;
    if (!regularFile || !withinLimit)
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"regularFile": @(regularFile),
                  @"withinLimit": @(withinLimit),
                  @"expectedLength": @(expectedLength),
                  @"sourceInfo": sourceInfo };

    AFCFileRef remote = NULL;
    int openStatus = AFCFileRefOpen(session->afc,
                                    source.fileSystemRepresentation, 1, &remote);
    int localFD = -1;
    if (openStatus == 0 && remote)
        localFD = open(localOutput.fileSystemRepresentation,
                       O_WRONLY | O_CREAT | O_EXCL, 0600);
    int readStatus = openStatus == 0 ? 0 : -1;
    int writeStatus = localFD >= 0 ? 0 : -1;
    unsigned long long observedLength = 0;
    uint8_t buffer[256 * 1024];
    while (remote && localFD >= 0 && readStatus == 0 && writeStatus == 0) {
        long length = sizeof(buffer);
        readStatus = AFCFileRefRead(session->afc, remote, buffer, &length);
        if (readStatus != 0 || length <= 0) break;
        if (observedLength + (unsigned long long)length > limit) {
            writeStatus = EFBIG;
            break;
        }
        long offset = 0;
        while (offset < length) {
            ssize_t wrote = write(localFD, buffer + offset,
                                  (size_t)(length - offset));
            if (wrote <= 0) { writeStatus = errno ?: EIO; break; }
            offset += wrote;
        }
        if (writeStatus == 0) observedLength += (unsigned long long)length;
    }
    int remoteCloseStatus = remote ? AFCFileRefClose(session->afc, remote) : -1;
    int localCloseStatus = localFD >= 0 ? close(localFD) : -1;
    BOOL sizeMatched = observedLength == (unsigned long long)expectedLength;
    BOOL ok = openStatus == 0 && localFD >= 0 && readStatus == 0 &&
              writeStatus == 0 && remoteCloseStatus == 0 &&
              localCloseStatus == 0 && sizeMatched;
    if (!ok) unlink(localOutput.fileSystemRepresentation);
    return @{ @"ok": @(ok), @"safeArguments": @YES,
              @"regularFile": @YES, @"withinLimit": @YES,
              @"openStatus": @(openStatus), @"readStatus": @(readStatus),
              @"writeStatus": @(writeStatus),
              @"remoteCloseStatus": @(remoteCloseStatus),
              @"localCloseStatus": @(localCloseStatus),
              @"expectedLength": @(expectedLength),
              @"observedLength": @(observedLength),
              @"sizeMatched": @(sizeMatched), @"localOutput": localOutput };
}

static NSDictionary *CopySpringBoardBrowserPlist(DeviceSession *session,
                                                  NSArray<NSString *> *args) {
    NSString *linkDestination = args[0], *leaf = args[1];
    NSString *localOutput = args[2], *localLeaf = localOutput.lastPathComponent;
    BOOL safeLink =
        IsSafeNestedName(linkDestination, @"codex-sb-browser-link-24A435-");
    BOOL safeLeaf = IsSafeRelativePath(leaf) &&
                    [leaf rangeOfString:@"/"].location == NSNotFound &&
                    [leaf hasSuffix:@".plist"];
    BOOL safeOutputDirectory =
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"];
    BOOL safeOutputLeaf =
        IsSafeNestedName(localLeaf, @"codex-springboard-read-24A435-") &&
        [localLeaf hasSuffix:@".plist"];
    BOOL outputFresh =
        ![NSFileManager.defaultManager fileExistsAtPath:localOutput];
    BOOL safeArguments = safeLink && safeLeaf && safeOutputDirectory &&
                         safeOutputLeaf && outputFresh;
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO,
                  @"safeLink": @(safeLink), @"safeLeaf": @(safeLeaf),
                  @"safeOutputDirectory": @(safeOutputDirectory),
                  @"safeOutputLeaf": @(safeOutputLeaf),
                  @"outputFresh": @(outputFresh) };

    NSString *source = [linkDestination stringByAppendingPathComponent:leaf];
    NSData *data = nil;
    NSMutableDictionary *result =
        [AFCReadFileDirect(session->afc, source, &data) mutableCopy];
    id plist = data ? [NSPropertyListSerialization
        propertyListWithData:data options:NSPropertyListImmutable
        format:NULL error:nil] : nil;
    BOOL validPlist = [plist isKindOfClass:NSDictionary.class] ||
                      [plist isKindOfClass:NSArray.class];
    NSError *error = nil;
    BOOL wrote = [result[@"ok"] boolValue] && validPlist &&
        [data writeToFile:localOutput options:NSDataWritingWithoutOverwriting
                    error:&error];
    result[@"ok"] = @(wrote);
    result[@"safeArguments"] = @YES;
    result[@"deviceWriteAttempted"] = @NO;
    result[@"validPlist"] = @(validPlist);
    result[@"rootType"] = [plist isKindOfClass:NSDictionary.class]
        ? @"dictionary" : [plist isKindOfClass:NSArray.class] ? @"array" : @"other";
    result[@"rootCount"] = [plist respondsToSelector:@selector(count)]
        ? @([plist count]) : @0;
    result[@"localOutput"] = localOutput;
    result[@"localWriteOK"] = @(wrote);
    result[@"localWriteError"] = error.localizedDescription ?: [NSNull null];
    return result;
}

/*
 * Read one known SpringBoard plist without moving or opening the live inode
 * for write.  AFC creates a fresh Media hard-link, the alias is read, and the
 * alias is removed in the same native session.  The original link count must
 * be restored before success is reported.
 */
static NSDictionary *CopySpringBoardKnownPlist(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *linkDestination = args[0], *leaf = args[1], *alias = args[2];
    NSString *localOutput = args[3], *localLeaf = localOutput.lastPathComponent;
    BOOL safeLink =
        IsSafeNestedName(linkDestination, @"codex-sb-browser-link-24A435-");
    BOOL safeLeaf = IsSafeRelativePath(leaf) &&
                    [leaf rangeOfString:@"/"].location == NSNotFound &&
                    [leaf hasSuffix:@".plist"];
    BOOL safeAlias =
        IsSafeNestedName(alias, @"codex-sb-hardlink-24A435-") &&
        [alias hasSuffix:@".plist"];
    BOOL safeOutputDirectory =
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"];
    BOOL safeOutputLeaf =
        IsSafeNestedName(localLeaf, @"codex-springboard-read-24A435-") &&
        [localLeaf hasSuffix:@".plist"];
    BOOL outputFresh =
        ![NSFileManager.defaultManager fileExistsAtPath:localOutput];
    BOOL safeArguments = safeLink && safeLeaf && safeAlias &&
                         safeOutputDirectory && safeOutputLeaf && outputFresh;
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO,
                  @"safeLink": @(safeLink), @"safeLeaf": @(safeLeaf),
                  @"safeAlias": @(safeAlias),
                  @"safeOutputDirectory": @(safeOutputDirectory),
                  @"safeOutputLeaf": @(safeOutputLeaf),
                  @"outputFresh": @(outputFresh) };

    NSString *source = [linkDestination stringByAppendingPathComponent:leaf];
    NSDictionary *sourceBefore = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasBefore = AFCFileInfoDictionary(session->afc, alias);
    if ([aliasBefore[@"present"] boolValue]) {
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"sourceBefore": sourceBefore, @"aliasBefore": aliasBefore,
                  @"linkAttempted": @NO, @"deviceContentWriteAttempted": @NO };
    }

    int linkStatus = AFCLinkPath(session->afc, 1,
                                 source.fileSystemRepresentation,
                                 alias.fileSystemRepresentation);
    NSDictionary *aliasLinked = AFCFileInfoDictionary(session->afc, alias);
    NSString *aliasType = [aliasLinked[@"values"] isKindOfClass:NSDictionary.class]
        ? aliasLinked[@"values"][@"st_ifmt"] : nil;
    BOOL regularAlias = [aliasLinked[@"present"] boolValue] &&
                        [aliasType isEqual:@"S_IFREG"];
    NSData *data = nil;
    NSMutableDictionary *read = regularAlias
        ? [AFCReadFileDirect(session->afc, alias, &data) mutableCopy]
        : [@{ @"ok": @NO, @"observedLength": @0 } mutableCopy];
    id plist = data ? [NSPropertyListSerialization
        propertyListWithData:data options:NSPropertyListImmutable
        format:NULL error:nil] : nil;
    BOOL validPlist = [plist isKindOfClass:NSDictionary.class] ||
                      [plist isKindOfClass:NSArray.class];
    NSError *writeError = nil;
    BOOL localWriteOK = [read[@"ok"] boolValue] && validPlist &&
        [data writeToFile:localOutput options:NSDataWritingWithoutOverwriting
                    error:&writeError];
    int removeStatus = [aliasLinked[@"present"] boolValue]
        ? AFCRemovePath(session->afc, alias.fileSystemRepresentation) : 0;
    NSDictionary *sourceAfter = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasAfter = AFCFileInfoDictionary(session->afc, alias);
    NSString *linksBefore = [sourceBefore[@"values"] isKindOfClass:NSDictionary.class]
        ? sourceBefore[@"values"][@"st_nlink"] : nil;
    NSString *linksAfter = [sourceAfter[@"values"] isKindOfClass:NSDictionary.class]
        ? sourceAfter[@"values"][@"st_nlink"] : nil;
    BOOL linkCountObservable = linksBefore != nil && linksAfter != nil;
    BOOL linkCountRestored = !linkCountObservable ||
                             [linksBefore isEqual:linksAfter];
    BOOL ok = linkStatus == 0 && regularAlias && localWriteOK &&
              removeStatus == 0 && ![aliasAfter[@"present"] boolValue] &&
              linkCountRestored;
    return @{ @"ok": @(ok), @"safeArguments": @YES,
              @"linkAttempted": @YES, @"linkStatus": @(linkStatus),
              @"regularAlias": @(regularAlias), @"read": read,
              @"validPlist": @(validPlist),
              @"localWriteOK": @(localWriteOK),
              @"localOutput": localOutput,
              @"localWriteError": writeError.localizedDescription ?: [NSNull null],
              @"removeStatus": @(removeStatus),
              @"linkCountObservable": @(linkCountObservable),
              @"linkCountRestored": @(linkCountRestored),
              @"sourceBefore": sourceBefore, @"sourceAfter": sourceAfter,
              @"aliasBefore": aliasBefore, @"aliasLinked": aliasLinked,
              @"aliasAfter": aliasAfter,
              @"deviceContentWriteAttempted": @NO };
}

static NSDictionary *RemoveSpringBoardHardlink(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *alias = args[0];
    BOOL safeArguments =
        IsSafeNestedName(alias, @"codex-sb-hardlink-24A435-") &&
        [alias hasSuffix:@".plist"];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSDictionary *before = AFCFileInfoDictionary(session->afc, alias);
    int removeStatus = [before[@"present"] boolValue]
        ? AFCRemovePath(session->afc, alias.fileSystemRepresentation) : 0;
    NSDictionary *after = AFCFileInfoDictionary(session->afc, alias);
    return @{ @"ok": @(removeStatus == 0 && ![after[@"present"] boolValue]),
              @"safeArguments": @YES, @"removeStatus": @(removeStatus),
              @"before": before, @"after": after };
}

static NSDictionary *CleanupSpringBoardBrowser(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    BOOL safeArguments = BrowserSourceIsSafe(source) &&
                         BrowserLinkIsSafe(linkDestination);
    NSData *currentBooks = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL booksSafe = currentBooks == nil ||
                     SpringBoardBrowserBooksAreSafe(currentBooks, source);
    if (!safeArguments || !booksSafe)
        return @{ @"ok": @NO, @"safeArguments": @(safeArguments),
                  @"booksSafe": @(booksSafe) };

    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    if ([linkDestination hasPrefix:@"codex-file-browser-link-24A435-"]) {
        NSString *token = [linkDestination substringFromIndex:
            [@"codex-file-browser-link-24A435-" length]];
        NSString *copyAlias = [@"codex-file-browser-copy-24A435-"
            stringByAppendingString:token];
        if (!RemoveIfPresent(session->afc, copyAlias))
            [failures addObject:copyAlias];
    }
    if (!RemoveIfPresent(session->afc, linkDestination))
        [failures addObject:linkDestination];
    if (!RemoveIfPresent(session->afc, @"Books/Sync/Books.plist"))
        [failures addObject:@"Books/Sync/Books.plist"];
    if (!AFCRemoveGeneratedTree(session->afc, source, 0))
        [failures addObject:source];
    for (NSUInteger index = 0;
         index < sizeof(TrackedBooksFiles) / sizeof(char *); index++) {
        NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[index]];
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    }
    BOOL booksFilesAbsent = AllTrackedBooksFilesAbsent(session->afc);
    return @{ @"ok": @(failures.count == 0 && booksFilesAbsent),
              @"safeArguments": @YES, @"booksSafe": @YES,
              @"cleanupFailureCount": @(failures.count),
              @"failures": failures,
              @"sourceAbsent": @(!AFCExists(session->afc, source)),
              @"linkAbsent": @(!AFCExists(session->afc, linkDestination)),
              @"booksFilesAbsent": @(booksFilesAbsent) };
}

static BOOL MGUIRecoveryBooksAreSafe(NSData *data) {
    if (!data) return NO;
    id root = [NSPropertyListSerialization propertyListWithData:data
                                                        options:0
                                                         format:NULL
                                                          error:nil];
    NSArray *rows = [root isKindOfClass:NSDictionary.class] &&
        [root[@"Books"] isKindOfClass:NSArray.class] ? root[@"Books"] : nil;
    if (rows.count != 1 || ![rows[0] isKindOfClass:NSDictionary.class])
        return NO;
    return [rows[0][@"Persistent ID"]
        isEqual:@"../../../Library/Preferences/com.apple.MobileGestalt.plist"];
}

static BOOL MGUIStageBooksAreSafe(NSData *data, NSString *source) {
    if (!data) return YES;
    id root = [NSPropertyListSerialization propertyListWithData:data
                                                        options:0
                                                         format:NULL
                                                          error:nil];
    NSArray *rows = [root isKindOfClass:NSDictionary.class] &&
        [root[@"Books"] isKindOfClass:NSArray.class] ? root[@"Books"] : nil;
    if (!rows.count || rows.count > 3) return NO;
    NSString *link = [NSString stringWithFormat:@"../../%@/pivot/link", source];
    NSString *payload = [NSString stringWithFormat:@"../../%@/payload", source];
    for (id row in rows) {
        NSString *identifier = [row isKindOfClass:NSDictionary.class]
            ? row[@"Persistent ID"] : nil;
        BOOL safeBackup = [identifier hasPrefix:@"../../codex-mg-ui-backup-24A435-"] &&
            [[identifier substringFromIndex:6] rangeOfString:@"/"].location == NSNotFound;
        if (![identifier isEqual:link] && ![identifier isEqual:payload] && !safeBackup)
            return NO;
    }
    return YES;
}

/* Native-only staging for the fixed MobileGestalt source export. */
static NSDictionary *StageMGUIRecoveryBooks(DeviceSession *session,
                                             NSArray<NSString *> *args) {
    NSString *recovered = args[0];
    NSData *books = [NSData dataWithContentsOfFile:args[1]];
    BOOL safeArguments =
        IsSafeNestedName(recovered, @"codex-mg-ui-backup-24A435-") &&
        MGUIRecoveryBooksAreSafe(books);
    BOOL booksPreimageAbsent = AllTrackedBooksFilesAbsent(session->afc);
    BOOL recoveredAbsent = !AFCExists(session->afc, recovered);
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL wrote = safeArguments && booksPreimageAbsent && recoveredAbsent &&
        directoryReady && AFCWriteFile(session->afc,
                                       @"Books/Sync/Books.plist", books);
    return @{ @"ok": @(wrote), @"safeArguments": @(safeArguments),
              @"booksPreimageAbsent": @(booksPreimageAbsent),
              @"recoveredAbsent": @(recoveredAbsent),
              @"booksWritten": @(wrote) };
}

/* Remove only a fixed source-export manifest; preserve the recovered object. */
static NSDictionary *CleanupMGUIRecoveryBooks(DeviceSession *session,
                                               NSArray<NSString *> *args) {
    NSString *recovered = args[0];
    BOOL safeArguments =
        IsSafeNestedName(recovered, @"codex-mg-ui-backup-24A435-");
    NSData *current = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL booksSafe = current == nil || MGUIRecoveryBooksAreSafe(current);
    BOOL removed = safeArguments && booksSafe;
    if (removed) {
        for (NSUInteger i = 0;
             i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
            NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[i]];
            if (!RemoveIfPresent(session->afc, path)) removed = NO;
        }
    }
    return @{ @"ok": @(removed && AllTrackedBooksFilesAbsent(session->afc)),
              @"safeArguments": @(safeArguments),
              @"booksInputSafe": @(booksSafe),
              @"recoveredPresent": @(AFCExists(session->afc, recovered)),
              @"booksFilesAbsent": @(AllTrackedBooksFilesAbsent(session->afc)) };
}

/* Remove only controller-minted StreamingZip/Books staging objects. */
static NSDictionary *CleanupMGUIStage(DeviceSession *session,
                                      NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-mg-ui-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-mg-ui-link-24A435-");
    NSData *current = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL booksSafe = current == nil || MGUIStageBooksAreSafe(current, source);
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    NSArray<NSString *> *generated = @[
        linkDestination,
        [source stringByAppendingPathComponent:@"pivot/link"],
        [source stringByAppendingPathComponent:@"payload"],
        [source stringByAppendingPathComponent:@"META-INF/com.apple.ZipMetadata.plist"],
        [source stringByAppendingPathComponent:@"META-INF"],
        [source stringByAppendingPathComponent:@"Library/Preferences"],
        [source stringByAppendingPathComponent:@"Library"],
        [source stringByAppendingPathComponent:@"pivot"], source,
    ];
    if (safeArguments) {
        for (NSString *path in generated)
            if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
        if (booksSafe) {
            for (NSUInteger i = 0;
                 i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
                NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[i]];
                if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
            }
        }
    }
    BOOL booksAbsent = AllTrackedBooksFilesAbsent(session->afc);
    return @{ @"ok": @(safeArguments && booksSafe &&
                         failures.count == 0 && booksAbsent),
              @"safeArguments": @(safeArguments), @"booksInputSafe": @(booksSafe),
              @"cleanupFailureCount": @(failures.count),
              @"sourceAbsent": @(!AFCExists(session->afc, source)),
              @"linkAbsent": @(!AFCExists(session->afc, linkDestination)),
              @"booksFilesAbsent": @(booksAbsent) };
}

static NSDictionary *CopyMGUIBackupToLocal(DeviceSession *session,
                                            NSArray<NSString *> *args) {
    NSString *recovered = args[0], *localOutput = args[1];
    BOOL safeArguments =
        IsSafeNestedName(recovered, @"codex-mg-ui-backup-24A435-") &&
        localOutput.isAbsolutePath &&
        [localOutput.lastPathComponent hasPrefix:@"codex-mg-ui-readback-24A435-"];
    NSData *observed = safeArguments
        ? AFCReadFile(session->afc, recovered) : nil;
    NSError *error = nil;
    BOOL wrote = observed && [observed writeToFile:localOutput
                                          options:NSDataWritingAtomic
                                            error:&error];
    return @{ @"ok": @(safeArguments && wrote),
              @"safeArguments": @(safeArguments),
              @"recoveredPresent": @(observed != nil),
              @"observedLength": @(observed.length),
              @"localWriteError": error.localizedDescription ?: [NSNull null] };
}

static NSDictionary *ProbeMGUIBackup(DeviceSession *session,
                                     NSArray<NSString *> *args) {
    NSString *recovered = args[0];
    BOOL safeArguments =
        IsSafeNestedName(recovered, @"codex-mg-ui-backup-24A435-");
    return @{ @"ok": @(safeArguments), @"safeArguments": @(safeArguments),
              @"present": @(safeArguments && AFCExists(session->afc, recovered)) };
}

static NSDictionary *RemoveMGUIBackup(DeviceSession *session,
                                      NSArray<NSString *> *args) {
    NSString *recovered = args[0];
    BOOL safeArguments =
        IsSafeNestedName(recovered, @"codex-mg-ui-backup-24A435-");
    BOOL removed = safeArguments && RemoveIfPresent(session->afc, recovered);
    return @{ @"ok": @(removed), @"safeArguments": @(safeArguments),
              @"absent": @(!AFCExists(session->afc, recovered)) };
}

/*
 * Exact readback for a generated Media-root export or hard-link alias.  The
 * source name is constrained to the two prefixes used by the MobileGestalt
 * round-trip runner; no target-directory path is accepted here.
 */
static NSDictionary *VerifyGeneratedMGExport(DeviceSession *session,
                                              NSArray<NSString *> *args) {
    NSString *source = args[0], *expectedPath = args[1];
    BOOL safeSource =
        (IsSafeNestedName(source, @"codex-dir-recovered-24A435-") ||
         IsSafeNestedName(source, @"codex-mgcache-hardlink-24A435-"));
    NSData *expected = [NSData dataWithContentsOfFile:expectedPath];
    id expectedPlist = expected ? [NSPropertyListSerialization
        propertyListWithData:expected options:0 format:NULL error:nil] : nil;
    if (!safeSource || !expected || expected.length == 0 ||
        expected.length > 1024 * 1024 ||
        ![expectedPlist isKindOfClass:NSDictionary.class]) {
        return @{ @"ok": @NO, @"safeArguments": @(safeSource),
                  @"localExpectedValid": @NO };
    }
    NSData *observed = AFCReadFile(session->afc, source);
    id observedPlist = observed ? [NSPropertyListSerialization
        propertyListWithData:observed options:0 format:NULL error:nil] : nil;
    BOOL exact = observed && [observed isEqualToData:expected];
    return @{ @"ok": @(exact), @"safeArguments": @YES,
              @"localExpectedValid": @YES,
              @"observedPresent": @(observed != nil),
              @"observedLength": @(observed.length),
              @"observedRootIsDictionary":
                  @([observedPlist isKindOfClass:NSDictionary.class]),
              @"observedBytesMatch": @(exact) };
}

static NSDictionary *CopyGeneratedMGExportToLocal(DeviceSession *session,
                                                   NSArray<NSString *> *args) {
    NSString *source = args[0], *localOutput = args[1];
    NSString *localLeaf = localOutput.lastPathComponent;
    BOOL safeSource =
        IsSafeNestedName(source, @"codex-dir-recovered-24A435-") ||
        IsSafeNestedName(source, @"codex-mgcache-hardlink-24A435-");
    BOOL safeOutput =
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"] &&
        IsSafeNestedName(localLeaf, @"codex-mgcache-read-24A435-") &&
        [localLeaf hasSuffix:@".plist"] &&
        ![NSFileManager.defaultManager fileExistsAtPath:localOutput];
    if (!safeSource || !safeOutput)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSData *observed = AFCReadFile(session->afc, source);
    id plist = observed ? [NSPropertyListSerialization
        propertyListWithData:observed options:0 format:NULL error:nil] : nil;
    NSError *error = nil;
    BOOL wrote = observed && observed.length > 0 &&
        observed.length <= 1024 * 1024 &&
        [plist isKindOfClass:NSDictionary.class] &&
        [observed writeToFile:localOutput
                      options:NSDataWritingWithoutOverwriting
                        error:&error];
    return @{ @"ok": @(wrote), @"safeArguments": @YES,
              @"observedPresent": @(observed != nil),
              @"observedLength": @(observed.length),
              @"observedRootIsDictionary":
                  @([plist isKindOfClass:NSDictionary.class]),
              @"localWriteOK": @(wrote),
              @"localOutput": localOutput,
              @"localWriteError": error.localizedDescription ?: [NSNull null] };
}

static NSDictionary *RemoveGeneratedMGExport(DeviceSession *session,
                                              NSArray<NSString *> *args) {
    NSString *path = args[0];
    BOOL safeArguments =
        IsSafeNestedName(path, @"codex-dir-recovered-24A435-");
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSDictionary *before = AFCFileInfoDictionary(session->afc, path);
    int removeStatus = [before[@"present"] boolValue]
        ? AFCRemovePath(session->afc, path.fileSystemRepresentation) : 0;
    NSDictionary *after = AFCFileInfoDictionary(session->afc, path);
    return @{ @"ok": @(removeStatus == 0 && ![after[@"present"] boolValue]),
              @"safeArguments": @YES, @"removeStatus": @(removeStatus),
              @"before": before, @"after": after };
}

/* Remove only names minted by the direct MobileGestalt replacement runner. */
static NSDictionary *CleanupGeneratedMGReplace(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *backup = args[2], *verification = args[3];
    NSString *targetTail = args[4];
    NSString *exactTail =
        @"var/containers/Shared/SystemGroup/"
         "systemgroup.com.apple.mobilegestaltcache/Library/Caches";
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(backup, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(verification, @"codex-dir-recovered-24A435-") &&
        ![backup isEqual:verification] && [targetTail isEqual:exactTail];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    NSMutableArray<NSString *> *generated = [NSMutableArray arrayWithArray:@[
        linkDestination, backup, verification,
        [source stringByAppendingPathComponent:@"p0/p1/p2/link"],
        [source stringByAppendingPathComponent:@"payload"],
        [source stringByAppendingPathComponent:
            @"META-INF/com.apple.ZipMetadata.plist"],
        [source stringByAppendingPathComponent:@"META-INF"],
    ]];
    NSMutableArray<NSString *> *tailDirectories = [NSMutableArray array];
    NSString *cursor = source;
    for (NSString *component in [targetTail componentsSeparatedByString:@"/"]) {
        cursor = [cursor stringByAppendingPathComponent:component];
        [tailDirectories addObject:cursor];
    }
    for (NSString *path in tailDirectories.reverseObjectEnumerator)
        [generated addObject:path];
    [generated addObjectsFromArray:@[
        [source stringByAppendingPathComponent:@"p0/p1/p2"],
        [source stringByAppendingPathComponent:@"p0/p1"],
        [source stringByAppendingPathComponent:@"p0"], source,
    ]];
    for (NSString *path in generated)
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
        NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[i]];
        if (!RemoveIfPresent(session->afc, path)) [failures addObject:path];
    }
    BOOL booksFilesAbsent = YES;
    for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++)
        if (AFCExists(session->afc,
                      [NSString stringWithUTF8String:TrackedBooksFiles[i]]))
            booksFilesAbsent = NO;
    return @{ @"ok": @(failures.count == 0 && booksFilesAbsent),
              @"safeArguments": @YES,
              @"cleanupFailureCount": @(failures.count),
              @"sourceAbsent": @(!AFCExists(session->afc, source)),
              @"linkAbsent": @(!AFCExists(session->afc, linkDestination)),
              @"backupAbsent": @(!AFCExists(session->afc, backup)),
              @"verificationAbsent": @(!AFCExists(session->afc, verification)),
              @"booksFilesAbsent": @(booksFilesAbsent) };
}

static BOOL IsGeneratedMGBookIdentifier(NSString *identifier,
                                        NSString *source) {
    NSString *canonical =
        @"../../../../containers/Shared/SystemGroup/"
         "systemgroup.com.apple.mobilegestaltcache/Library/Caches/"
         "com.apple.MobileGestalt.plist";
    NSString *canonicalAlias =
        @"../../../../containers/Shared/SystemGroup/"
         "systemgroup.com.apple.mobilegestaltcache/Library/Caches/../Caches/"
         "com.apple.MobileGestalt.plist";
    NSString *link = [NSString stringWithFormat:
        @"../../%@/p0/p1/p2/link", source];
    NSString *payload = [NSString stringWithFormat:@"../../%@/payload", source];
    NSString *relativeMediaPrefix = @"../../";
    NSString *relativeMediaName = [identifier hasPrefix:relativeMediaPrefix]
        ? [identifier substringFromIndex:relativeMediaPrefix.length] : nil;
    BOOL generatedMedia = relativeMediaName &&
        IsSafeNestedName(relativeMediaName, @"codex-dir-recovered-24A435-");
    return [identifier isEqual:canonical] ||
        [identifier isEqual:canonicalAlias] ||
        [identifier isEqual:link] || [identifier isEqual:payload] ||
        generatedMedia ||
        IsSafeNestedName(identifier, @"codex-dir-recovered-24A435-");
}

static BOOL GeneratedMGBooksDataIsSafe(NSData *data, NSString *source) {
    if (!data) return YES;
    id root = [NSPropertyListSerialization propertyListWithData:data
                                                        options:0
                                                         format:NULL
                                                          error:nil];
    NSArray *rows = [root isKindOfClass:NSDictionary.class] &&
        [root[@"Books"] isKindOfClass:NSArray.class] ? root[@"Books"] : nil;
    if (!rows.count || rows.count > 8) return NO;
    for (id row in rows) {
        NSString *identifier = [row isKindOfClass:NSDictionary.class] &&
            [row[@"Persistent ID"] isKindOfClass:NSString.class]
            ? row[@"Persistent ID"] : nil;
        if (!identifier || !IsGeneratedMGBookIdentifier(identifier, source))
            return NO;
    }
    return YES;
}

static NSDictionary *StageGeneratedMGBooks(DeviceSession *session,
                                            NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *booksPath = args[2];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-");
    NSData *incoming = [NSData dataWithContentsOfFile:booksPath];
    NSData *current = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL generatedStateReady = safeArguments &&
        AFCExists(session->afc, source) && AFCExists(session->afc, linkDestination);
    BOOL inputsSafe = GeneratedMGBooksDataIsSafe(incoming, source) &&
                      GeneratedMGBooksDataIsSafe(current, source);
    BOOL cleared = generatedStateReady && inputsSafe;
    if (cleared) {
        for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
            NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[i]];
            if (![path isEqual:@"Books/Sync/Books.plist"] &&
                !RemoveIfPresent(session->afc, path)) cleared = NO;
        }
    }
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL wrote = incoming && safeArguments && generatedStateReady && inputsSafe &&
        cleared && directoryReady &&
        AFCWriteFile(session->afc, @"Books/Sync/Books.plist", incoming);
    return @{ @"ok": @(wrote), @"safeArguments": @(safeArguments),
              @"generatedStateReady": @(generatedStateReady),
              @"booksInputsSafe": @(inputsSafe),
              @"otherBooksStateCleared": @(cleared),
              @"booksWritten": @(wrote) };
}

static NSDictionary *CreateGeneratedSMSHardlink(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *outerLink = args[0], *alias = args[1];
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(alias, @"codex-sms-hardlink-24A435-");
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSString *source = [outerLink stringByAppendingPathComponent:@"sms.db"];
    NSDictionary *sourceBefore = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasBefore = AFCFileInfoDictionary(session->afc, alias);
    if (![sourceBefore[@"present"] boolValue] ||
        [aliasBefore[@"present"] boolValue]) {
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"sourceBefore": sourceBefore, @"aliasBefore": aliasBefore,
                  @"linkAttempted": @NO };
    }

    int linkStatus = AFCLinkPath(session->afc, 1,
                                 source.fileSystemRepresentation,
                                 alias.fileSystemRepresentation);
    NSDictionary *sourceAfter = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasAfter = AFCFileInfoDictionary(session->afc, alias);
    NSString *aliasType = [aliasAfter[@"values"] isKindOfClass:NSDictionary.class]
        ? aliasAfter[@"values"][@"st_ifmt"] : nil;
    BOOL regularAlias = [aliasAfter[@"present"] boolValue] &&
        [aliasType isEqual:@"S_IFREG"];
    return @{ @"ok": @(linkStatus == 0 && regularAlias),
              @"safeArguments": @YES, @"linkAttempted": @YES,
              @"linkStatus": @(linkStatus),
              @"sourceBefore": sourceBefore, @"sourceAfter": sourceAfter,
              @"aliasBefore": aliasBefore, @"aliasAfter": aliasAfter,
              @"regularAlias": @(regularAlias) };
}

static NSDictionary *RemoveGeneratedSMSHardlink(DeviceSession *session,
                                                NSArray<NSString *> *args) {
    NSString *outerLink = args[0], *alias = args[1];
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(alias, @"codex-sms-hardlink-24A435-");
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSString *source = [outerLink stringByAppendingPathComponent:@"sms.db"];
    NSDictionary *sourceBefore = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasBefore = AFCFileInfoDictionary(session->afc, alias);
    int removeStatus = [aliasBefore[@"present"] boolValue]
        ? AFCRemovePath(session->afc, alias.fileSystemRepresentation) : 0;
    NSDictionary *sourceAfter = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasAfter = AFCFileInfoDictionary(session->afc, alias);
    return @{ @"ok": @(removeStatus == 0 &&
                        ![aliasAfter[@"present"] boolValue]),
              @"safeArguments": @YES, @"removeStatus": @(removeStatus),
              @"sourceBefore": sourceBefore, @"sourceAfter": sourceAfter,
              @"aliasBefore": aliasBefore, @"aliasAfter": aliasAfter };
}

/*
 * Read-only gate for the MobileGestalt system-group cache.  The source name is
 * fixed here deliberately: callers may choose only the fresh Media alias and
 * the generated relocated-directory link.  This operation never opens either
 * inode for writing.
 */
static NSDictionary *CreateGeneratedMGCacheHardlink(DeviceSession *session,
                                                     NSArray<NSString *> *args) {
    NSString *outerLink = args[0], *alias = args[1];
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(alias, @"codex-mgcache-hardlink-24A435-") &&
        [alias hasSuffix:@".plist"];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSString *source = [outerLink stringByAppendingPathComponent:
        @"com.apple.MobileGestalt.plist"];
    NSDictionary *sourceBefore = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasBefore = AFCFileInfoDictionary(session->afc, alias);
    /* AFC metadata and hard-link requests are separate protocol operations. */
    if ([aliasBefore[@"present"] boolValue]) {
        return @{ @"ok": @NO, @"safeArguments": @YES,
                  @"sourceBefore": sourceBefore, @"aliasBefore": aliasBefore,
                  @"linkAttempted": @NO };
    }

    int linkStatus = AFCLinkPath(session->afc, 1,
                                 source.fileSystemRepresentation,
                                 alias.fileSystemRepresentation);
    NSDictionary *sourceAfter = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasAfter = AFCFileInfoDictionary(session->afc, alias);
    NSString *aliasType = [aliasAfter[@"values"] isKindOfClass:NSDictionary.class]
        ? aliasAfter[@"values"][@"st_ifmt"] : nil;
    BOOL regularAlias = [aliasAfter[@"present"] boolValue] &&
        [aliasType isEqual:@"S_IFREG"];
    return @{ @"ok": @(linkStatus == 0 && regularAlias),
              @"safeArguments": @YES, @"linkAttempted": @YES,
              @"sourceMetadataRequired": @NO,
              @"linkStatus": @(linkStatus),
              @"sourceBefore": sourceBefore, @"sourceAfter": sourceAfter,
              @"aliasBefore": aliasBefore, @"aliasAfter": aliasAfter,
              @"regularAlias": @(regularAlias) };
}

static NSDictionary *ProbeGeneratedMGCache(DeviceSession *session,
                                            NSArray<NSString *> *args) {
    NSString *outerLink = args[0];
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-");
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSString *source = [outerLink stringByAppendingPathComponent:
        @"com.apple.MobileGestalt.plist"];
    NSDictionary *info = AFCFileInfoDictionary(session->afc, source);
    NSString *type = [info[@"values"] isKindOfClass:NSDictionary.class]
        ? info[@"values"][@"st_ifmt"] : nil;
    BOOL regular = [info[@"present"] boolValue] && [type isEqual:@"S_IFREG"];
    return @{ @"ok": @(regular), @"safeArguments": @YES,
              @"regularFile": @(regular), @"fileInfo": info };
}

static NSDictionary *RemoveGeneratedMGCacheHardlink(DeviceSession *session,
                                                     NSArray<NSString *> *args) {
    NSString *outerLink = args[0], *alias = args[1];
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(alias, @"codex-mgcache-hardlink-24A435-") &&
        [alias hasSuffix:@".plist"];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };
    NSString *source = [outerLink stringByAppendingPathComponent:
        @"com.apple.MobileGestalt.plist"];
    NSDictionary *sourceBefore = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasBefore = AFCFileInfoDictionary(session->afc, alias);
    int removeStatus = [aliasBefore[@"present"] boolValue]
        ? AFCRemovePath(session->afc, alias.fileSystemRepresentation) : 0;
    NSDictionary *sourceAfter = AFCFileInfoDictionary(session->afc, source);
    NSDictionary *aliasAfter = AFCFileInfoDictionary(session->afc, alias);
    return @{ @"ok": @(removeStatus == 0 &&
                        ![aliasAfter[@"present"] boolValue]),
              @"safeArguments": @YES, @"removeStatus": @(removeStatus),
              @"sourceBefore": sourceBefore, @"sourceAfter": sourceAfter,
              @"aliasBefore": aliasBefore, @"aliasAfter": aliasAfter };
}

/*
 * Read-only direct-open gate for the canonical cache through a generated,
 * relocated directory link.  The only write is a fresh local macOS /tmp file.
 */
static NSDictionary *ReadGeneratedMGCacheDirect(DeviceSession *session,
                                                 NSArray<NSString *> *args) {
    NSString *outerLink = args[0], *localOutput = args[1];
    NSString *localLeaf = localOutput.lastPathComponent;
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"] &&
        IsSafeNestedName(localLeaf, @"codex-mgcache-read-24A435-") &&
        [localLeaf hasSuffix:@".plist"] &&
        ![[NSFileManager defaultManager] fileExistsAtPath:localOutput];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSString *source = [outerLink stringByAppendingPathComponent:
        @"com.apple.MobileGestalt.plist"];
    NSData *data = nil;
    NSMutableDictionary *result = [AFCReadFileDirect(session->afc, source,
                                                      &data) mutableCopy];
    result[@"safeArguments"] = @YES;
    result[@"deviceWriteAttempted"] = @NO;
    result[@"localOutput"] = localOutput;
    if ([result[@"ok"] boolValue]) {
        NSError *error = nil;
        BOOL wrote = [data writeToFile:localOutput
                               options:NSDataWritingWithoutOverwriting
                                 error:&error];
        result[@"localWriteOK"] = @(wrote);
        if (!wrote) {
            result[@"ok"] = @NO;
            result[@"localWriteError"] = error.localizedDescription ?: @"unknown";
        }
    } else {
        result[@"localWriteOK"] = @NO;
    }
    return result;
}

/*
 * Read-only variant for the Preferences-deputy chain.  outerLink is the
 * generated Media symlink to the disposable app's Library directory, and its
 * fixed Preferences child is the generated pivot.  No caller-controlled
 * device leaf is accepted.
 */
static NSDictionary *ReadGeneratedCFPrefsMGCacheDirect(
    DeviceSession *session, NSArray<NSString *> *args) {
    NSString *outerLink = args[0], *localOutput = args[1];
    NSString *localLeaf = localOutput.lastPathComponent;
    BOOL safeArguments =
        IsSafeNestedName(outerLink, @"codex-dir-link-24A435-") &&
        [localOutput.stringByDeletingLastPathComponent isEqual:@"/tmp"] &&
        IsSafeNestedName(localLeaf, @"codex-mgcache-read-24A435-") &&
        [localLeaf hasSuffix:@".plist"] &&
        ![NSFileManager.defaultManager fileExistsAtPath:localOutput];
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSString *source = [outerLink stringByAppendingPathComponent:
        @"Preferences/com.apple.MobileGestalt.plist"];
    NSData *data = nil;
    NSMutableDictionary *result = [AFCReadFileDirect(session->afc, source,
                                                      &data) mutableCopy];
    result[@"safeArguments"] = @YES;
    result[@"deviceWriteAttempted"] = @NO;
    result[@"localOutput"] = localOutput;
    if ([result[@"ok"] boolValue]) {
        NSError *error = nil;
        BOOL wrote = [data writeToFile:localOutput
                               options:NSDataWritingWithoutOverwriting
                                 error:&error];
        result[@"localWriteOK"] = @(wrote);
        if (!wrote) {
            result[@"ok"] = @NO;
            result[@"localWriteError"] =
                error.localizedDescription ?: @"unknown";
        }
    } else {
        result[@"localWriteOK"] = @NO;
    }
    return result;
}

static NSDictionary *ProbeNestedState(DeviceSession *session,
                                      NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *recoveredPayload = args[2], *recoveredPivot = args[3];
    NSString *pivotLeaf = args[4];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(recoveredPayload, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(recoveredPivot, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(pivotLeaf, @"codex-dir-pivot-24A435-");
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSString *pivotThroughLink =
        [linkDestination stringByAppendingPathComponent:pivotLeaf];
    NSString *sourcePivot = [source stringByAppendingPathComponent:
        @"var/containers/Shared/SystemGroup/"
         "systemgroup.com.apple.installcoordinationd/Library/"
         "InstallCoordination/PromiseStaging"];
    sourcePivot = [sourcePivot stringByAppendingPathComponent:pivotLeaf];
    return @{
        @"ok": @YES,
        @"safeArguments": @YES,
        @"sourcePresent": @(AFCExists(session->afc, source)),
        @"linkPresent": @(AFCExists(session->afc, linkDestination)),
        @"recoveredPayloadPresent": @(AFCExists(session->afc, recoveredPayload)),
        @"recoveredPivotPresent": @(AFCExists(session->afc, recoveredPivot)),
        @"sourcePivotPresent": @(AFCExists(session->afc, sourcePivot)),
        @"pivotVisibleThroughLink": @(AFCExists(session->afc, pivotThroughLink)),
        @"booksSyncPlistPresent":
            @(AFCExists(session->afc, @"Books/Sync/Books.plist")),
    };
}

static NSDictionary *ProbeNestedContainerState(DeviceSession *session,
                                               NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *recoveredPayload = args[2], *recoveredContainer = args[3];
    NSString *containerLeaf = args[4], *pivotLeaf = args[5];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(recoveredPayload, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(recoveredContainer, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(containerLeaf, @"codex-dir-container-24A435-") &&
        IsSafeNestedName(pivotLeaf, @"codex-dir-pivot-24A435-");
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSString *deepPrefix = @"deep0/deep1/deep2/deep3/deep4/deep5/deep6/deep7";
    NSString *sourceContainer = [source stringByAppendingPathComponent:deepPrefix];
    sourceContainer = [sourceContainer stringByAppendingPathComponent:containerLeaf];
    NSString *containerThroughLink =
        [linkDestination stringByAppendingPathComponent:containerLeaf];
    NSString *pivotThroughLink =
        [containerThroughLink stringByAppendingPathComponent:pivotLeaf];
    NSString *recoveredPivot =
        [recoveredContainer stringByAppendingPathComponent:pivotLeaf];
    return @{
        @"ok": @YES,
        @"safeArguments": @YES,
        @"sourcePresent": @(AFCExists(session->afc, source)),
        @"linkPresent": @(AFCExists(session->afc, linkDestination)),
        @"sourceContainerPresent": @(AFCExists(session->afc, sourceContainer)),
        @"containerVisibleThroughLink":
            @(AFCExists(session->afc, containerThroughLink)),
        @"pivotVisibleThroughLink": @(AFCExists(session->afc, pivotThroughLink)),
        @"recoveredPayloadPresent": @(AFCExists(session->afc, recoveredPayload)),
        @"recoveredContainerPresent": @(AFCExists(session->afc, recoveredContainer)),
        @"recoveredPivotPresent": @(AFCExists(session->afc, recoveredPivot)),
        @"booksSyncPlistPresent":
            @(AFCExists(session->afc, @"Books/Sync/Books.plist")),
    };
}

static NSDictionary *StageNestedRecoveryBooks(DeviceSession *session,
                                               NSArray<NSString *> *args) {
    NSString *source = args[0], *linkDestination = args[1];
    NSString *recoveredPivot = args[2], *booksPath = args[3];
    NSString *pivotLeaf = args[4];
    BOOL safeArguments =
        IsSafeNestedName(source, @"codex-dir-src-24A435-") &&
        IsSafeNestedName(linkDestination, @"codex-dir-link-24A435-") &&
        IsSafeNestedName(recoveredPivot, @"codex-dir-recovered-24A435-") &&
        IsSafeNestedName(pivotLeaf, @"codex-dir-pivot-24A435-");
    if (!safeArguments)
        return @{ @"ok": @NO, @"safeArguments": @NO };

    NSData *books = [NSData dataWithContentsOfFile:booksPath];
    NSData *preimage = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    BOOL generatedPreimage = preimage == nil;
    if (preimage) {
        id value = [NSPropertyListSerialization propertyListWithData:preimage
                                                              options:NSPropertyListImmutable
                                                               format:NULL
                                                                error:nil];
        NSArray *rows = [value isKindOfClass:NSDictionary.class] &&
            [value[@"Books"] isKindOfClass:NSArray.class] ? value[@"Books"] : nil;
        generatedPreimage = rows.count > 0;
        for (id row in rows) {
            NSString *identifier = [row isKindOfClass:NSDictionary.class] &&
                [row[@"Persistent ID"] isKindOfClass:NSString.class]
                ? row[@"Persistent ID"] : nil;
            if (!identifier.length ||
                [identifier rangeOfString:@"codex"].location == NSNotFound) {
                generatedPreimage = NO;
                break;
            }
        }
    }
    BOOL generatedStateReady = AFCExists(session->afc, source) &&
        AFCExists(session->afc, linkDestination) &&
        !AFCExists(session->afc, recoveredPivot);
    BOOL otherBooksStateCleared = generatedPreimage && generatedStateReady;
    if (otherBooksStateCleared) {
        for (NSUInteger i = 0; i < sizeof(TrackedBooksFiles) / sizeof(char *); i++) {
            NSString *path = [NSString stringWithUTF8String:TrackedBooksFiles[i]];
            if (![path isEqual:@"Books/Sync/Books.plist"] &&
                !RemoveIfPresent(session->afc, path)) otherBooksStateCleared = NO;
        }
    }
    BOOL booksPreimageSafe = generatedPreimage && otherBooksStateCleared;
    BOOL directoryReady = EnsureDirectory(session->afc, @"Books") &&
                          EnsureDirectory(session->afc, @"Books/Sync");
    BOOL booksWritten = books && booksPreimageSafe && generatedStateReady &&
        directoryReady && AFCWriteFile(session->afc, @"Books/Sync/Books.plist", books);
    return @{
        @"ok": @(booksWritten),
        @"safeArguments": @YES,
        @"booksPreimageSafe": @(booksPreimageSafe),
        @"generatedPreimage": @(generatedPreimage),
        @"otherBooksStateCleared": @(otherBooksStateCleared),
        @"generatedStateReady": @(generatedStateReady),
        @"localInputReadable": @(books != nil),
        @"booksWritten": @(booksWritten),
    };
}

static NSDictionary *InspectGeneratedBooks(DeviceSession *session) {
    NSData *data = AFCReadFile(session->afc, @"Books/Sync/Books.plist");
    NSError *error = nil;
    id value = data ?
        [NSPropertyListSerialization propertyListWithData:data
                                                  options:NSPropertyListImmutable
                                                   format:NULL
                                                    error:&error] : nil;
    NSArray *books = [value isKindOfClass:NSDictionary.class] &&
        [value[@"Books"] isKindOfClass:NSArray.class] ? value[@"Books"] : nil;
    NSMutableArray<NSString *> *identifiers = [NSMutableArray array];
    BOOL generatedOnly = books.count > 0;
    for (id row in books) {
        NSString *identifier = [row isKindOfClass:NSDictionary.class] &&
            [row[@"Persistent ID"] isKindOfClass:NSString.class]
            ? row[@"Persistent ID"] : nil;
        if (!identifier.length ||
            [identifier rangeOfString:@"codex"].location == NSNotFound) {
            generatedOnly = NO;
            break;
        }
        [identifiers addObject:identifier];
    }
    return @{
        @"ok": @(generatedOnly),
        @"generatedOnly": @(generatedOnly),
        @"identifierCount": @(identifiers.count),
        @"identifiers": generatedOnly ? identifiers : @[],
        @"parseError": error.localizedDescription ?: [NSNull null],
    };
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 3) return 64;
        NSString *command = [NSString stringWithUTF8String:argv[1]];
        TargetIdentifier = CFStringCreateWithCString(
            kCFAllocatorDefault, argv[2], kCFStringEncodingUTF8);
        if (!TargetIdentifier) return 64;
        DeviceSession session;
        OpenSession(&session);
        NSDictionary *summary = SessionSummary(&session);
        BOOL targetGatePassed =
            [summary[@"productType"] isEqual:@"iPhone18,2"] &&
            [summary[@"productVersion"] isEqual:@"27.0"] &&
            [summary[@"buildVersion"] isEqual:@"24A435"];
        NSDictionary *operation = nil;
        if (session.afcStatus == 0 && session.afc && targetGatePassed) {
            if ([command isEqual:@"probe-afc"] && argc == 3) {
                operation = @{ @"ok": @YES,
                    @"booksSyncPlistPresent":
                        @(AFCExists(session.afc, @"Books/Sync/Books.plist")) };
            } else if ([command isEqual:@"stage-springboard-browser"] &&
                       argc == 7) {
                operation = StageSpringBoardBrowser(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"stage-file-browser"] &&
                       argc == 7) {
                operation = StageSpringBoardBrowser(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"stage-springboard-roundtrip"] &&
                       argc == 9) {
                operation = StageSpringBoardRoundTrip(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                    [NSString stringWithUTF8String:argv[8]],
                ]);
            } else if ([command isEqual:@"stage-springboard-restore-books"] &&
                       argc == 8) {
                operation = StageSpringBoardRestoreBooks(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                ]);
            } else if ([command isEqual:@"copy-springboard-roundtrip-backup"] &&
                       argc == 5) {
                operation = CopySpringBoardRoundTripBackup(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"probe-springboard-roundtrip"] &&
                       argc == 6) {
                operation = ProbeSpringBoardRoundTrip(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                ]);
            } else if ([command isEqual:@"cleanup-springboard-roundtrip"] &&
                       argc == 7) {
                operation = CleanupSpringBoardRoundTrip(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"stage-springboard-replace-books"] &&
                       argc == 8) {
                operation = StageSpringBoardReplaceBooks(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                ]);
            } else if ([command isEqual:@"write-springboard-replace-payload"] &&
                       argc == 7) {
                operation = WriteSpringBoardReplacePayload(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"probe-springboard-replace"] &&
                       argc == 7) {
                operation = ProbeSpringBoardReplace(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"clear-springboard-replace-books"] &&
                       argc == 7) {
                operation = ClearSpringBoardReplaceBooks(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"list-springboard-browser"] &&
                       argc == 4) {
                operation = ListSpringBoardBrowser(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"list-file-browser"] && argc == 4) {
                operation = ListSpringBoardBrowser(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"list-media-directory"] && argc == 4) {
                operation = ListMediaDirectory(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"copy-file-browser-file"] &&
                       argc == 6) {
                operation = CopyFileBrowserFile(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                ]);
            } else if ([command isEqual:@"probe-file-browser-read"] &&
                       argc == 5) {
                operation = ProbeFileBrowserRead(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"copy-media-file"] && argc == 5) {
                operation = CopyMediaFile(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"probe-media-read"] && argc == 4) {
                operation = ProbeMediaRead(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"copy-springboard-browser-plist"] &&
                       argc == 6) {
                operation = CopySpringBoardBrowserPlist(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                ]);
            } else if ([command isEqual:@"copy-springboard-known-plist"] &&
                       argc == 7) {
                operation = CopySpringBoardKnownPlist(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"remove-springboard-hardlink"] &&
                       argc == 4) {
                operation = RemoveSpringBoardHardlink(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"cleanup-springboard-browser"] &&
                       argc == 5) {
                operation = CleanupSpringBoardBrowser(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"cleanup-file-browser"] &&
                       argc == 5) {
                operation = CleanupSpringBoardBrowser(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"inspect-generated-books"] &&
                       argc == 3) {
                operation = InspectGeneratedBooks(&session);
            } else if ([command isEqual:@"stage-mg-ui-recovery-books"] &&
                       argc == 5) {
                operation = StageMGUIRecoveryBooks(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"cleanup-mg-ui-recovery-books"] &&
                       argc == 4) {
                operation = CleanupMGUIRecoveryBooks(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"cleanup-mg-ui-stage"] && argc == 5) {
                operation = CleanupMGUIStage(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"copy-mg-ui-backup"] && argc == 5) {
                operation = CopyMGUIBackupToLocal(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"probe-mg-ui-backup"] && argc == 4) {
                operation = ProbeMGUIBackup(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"remove-mg-ui-backup"] && argc == 4) {
                operation = RemoveMGUIBackup(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"read-disposable-through-link"] &&
                       argc == 5) {
                operation = ReadDisposableThroughLink(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"streamingzip-overwrite-generated-pivot"] &&
                       argc == 6) {
                operation = StreamingZipOverwriteGeneratedPivot(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                ]);
            } else if ([command isEqual:@"streamingzip-write-generated-mgcache"] &&
                       argc == 5) {
                operation = StreamingZipWriteGeneratedMGCache(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"create-generated-sms-hardlink"] &&
                       argc == 5) {
                operation = CreateGeneratedSMSHardlink(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"remove-generated-sms-hardlink"] &&
                       argc == 5) {
                operation = RemoveGeneratedSMSHardlink(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"create-generated-mgcache-hardlink"] &&
                       argc == 5) {
                operation = CreateGeneratedMGCacheHardlink(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"probe-generated-mgcache"] &&
                       argc == 4) {
                operation = ProbeGeneratedMGCache(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"remove-generated-mgcache-hardlink"] &&
                       argc == 5) {
                operation = RemoveGeneratedMGCacheHardlink(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"verify-generated-mg-export"] &&
                       argc == 5) {
                operation = VerifyGeneratedMGExport(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"copy-generated-mg-export"] &&
                       argc == 5) {
                operation = CopyGeneratedMGExportToLocal(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"remove-generated-mg-export"] &&
                       argc == 4) {
                operation = RemoveGeneratedMGExport(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                ]);
            } else if ([command isEqual:@"cleanup-generated-mg-replace"] &&
                       argc == 8) {
                operation = CleanupGeneratedMGReplace(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                ]);
            } else if ([command isEqual:@"stage-generated-mg-books"] &&
                       argc == 6) {
                operation = StageGeneratedMGBooks(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                ]);
            } else if ([command isEqual:@"read-generated-mgcache-direct"] &&
                       argc == 5) {
                operation = ReadGeneratedMGCacheDirect(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command
                           isEqual:@"read-generated-cfprefs-mgcache-direct"] &&
                       argc == 5) {
                operation = ReadGeneratedCFPrefsMGCacheDirect(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                ]);
            } else if ([command isEqual:@"replace-generated-mgcache-from-local"] &&
                       argc == 7) {
                operation = ReplaceGeneratedMGCacheFromLocal(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"probe-nested-state"] && argc == 8) {
                operation = ProbeNestedState(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                ]);
            } else if ([command isEqual:@"probe-nested-container-state"] &&
                       argc == 9) {
                operation = ProbeNestedContainerState(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                    [NSString stringWithUTF8String:argv[8]],
                ]);
            } else if ([command isEqual:@"stage-nested-recovery-books"] &&
                       argc == 8) {
                operation = StageNestedRecoveryBooks(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                ]);
            } else if ([command isEqual:@"stage"] && argc == 8) {
                operation = Stage(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                ]);
            } else if ([command isEqual:@"verify-cleanup"] && argc == 7) {
                operation = VerifyAndCleanup(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                ]);
            } else if ([command isEqual:@"verify-matrix-cleanup"] && argc == 8) {
                operation = VerifyMatrixAndCleanup(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                ]);
            } else if ([command isEqual:@"verify-matrix-collision-cleanup"] &&
                       argc == 9) {
                operation = VerifyMatrixAndCleanup(&session, @[
                    [NSString stringWithUTF8String:argv[3]],
                    [NSString stringWithUTF8String:argv[4]],
                    [NSString stringWithUTF8String:argv[5]],
                    [NSString stringWithUTF8String:argv[6]],
                    [NSString stringWithUTF8String:argv[7]],
                    [NSString stringWithUTF8String:argv[8]],
                ]);
            }
        }
        NSMutableDictionary *result = [summary mutableCopy];
        result[@"targetGatePassed"] = @(targetGatePassed);
        result[@"command"] = command ?: @"(nil)";
        result[@"operation"] = operation ?: @{ @"ok": @NO };
        PrintResult(result);
        BOOL ok = targetGatePassed && session.afcStatus == 0 &&
                  [operation[@"ok"] boolValue];
        CloseSession(&session);
        CFRelease(TargetIdentifier);
        return ok ? 0 : 2;
    }
}
