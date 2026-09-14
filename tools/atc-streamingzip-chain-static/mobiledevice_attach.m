#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>

typedef const void *AMDeviceRef;
typedef const void *AMDeviceNotificationRef;

typedef struct {
    AMDeviceRef device;
    unsigned int message;
} AMDeviceNotificationCallbackInfo;

extern int AMDeviceNotificationSubscribeWithOptions(
    void (*callback)(AMDeviceNotificationCallbackInfo *, void *),
    int unused,
    unsigned int connectionType,
    void *context,
    AMDeviceNotificationRef *subscription,
    CFDictionaryRef options);
extern int AMDeviceNotificationUnsubscribe(AMDeviceNotificationRef subscription);
extern CFStringRef AMDeviceCopyDeviceIdentifier(AMDeviceRef device);

static CFStringRef TargetIdentifier;
static BOOL SawTarget;

static void DeviceCallback(AMDeviceNotificationCallbackInfo *info, void *context) {
    (void)context;
    if (!info || !info->device || info->message != 1) return;
    CFStringRef identifier = AMDeviceCopyDeviceIdentifier(info->device);
    if (identifier) {
        SawTarget = CFEqual(identifier, TargetIdentifier);
        CFRelease(identifier);
    }
    if (SawTarget) CFRunLoopStop(CFRunLoopGetMain());
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2 && argc != 3) return 64;
        NSTimeInterval duration = argc == 3 ? atof(argv[2]) : 15.0;
        if (duration <= 0 || duration > 120.0) return 64;
        TargetIdentifier = CFStringCreateWithCString(
            kCFAllocatorDefault, argv[1], kCFStringEncodingUTF8);
        if (!TargetIdentifier) return 64;

        NSDictionary *options = @{
            @"NotificationOptionSearchForPairedDevices": @YES,
            @"NotificationOptionSearchForPairedDevicesViaDirectConnectionsOnly": @NO,
            @"NotificationOptionSearchForWiFiPairableDevices": @NO,
            @"NotificationOptionEnableRemoteXPC": @YES,
            @"NotificationOptionEnableUSBMux": @YES,
        };
        AMDeviceNotificationRef subscription = NULL;
        int status = AMDeviceNotificationSubscribeWithOptions(
            DeviceCallback,
            0,
            0,
            NULL,
            &subscription,
            (__bridge CFDictionaryRef)options);
        if (status == 0) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, duration, false);
        }
        if (subscription) AMDeviceNotificationUnsubscribe(subscription);
        CFRelease(TargetIdentifier);
        fprintf(stdout,
                "{\"subscribeStatus\":%d,\"targetObserved\":%s}\n",
                status,
                SawTarget ? "true" : "false");
        return status == 0 ? 0 : 2;
    }
}
