// iOS 27 gates the modern embedded-app registration RPC inside lsd.  This
// fixed-trust hook is injected only into the exact /usr/libexec/lsd process and
// changes only that entitlement predicate; the bootstrap still supplies and
// verifies the complete registration dictionary.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <os/log.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static BOOL allow_embedded_registration(id object, SEL selector) {
    (void)object;
    (void)selector;
    return YES;
}

__attribute__((constructor)) static void initialize_lsd_registration_hook(void) {
    static const char markerPath[] =
        "/var/mobile/.sbinject-lsd-registration-ready";
    Class target = objc_getClass("_LSDModifyClient");
    SEL selector = NSSelectorFromString(
        @"clientIsEntitledForEmbeddedRegistrationOperations");
    Method method = target != Nil
        ? class_getInstanceMethod(target, selector) : NULL;
    if (method == NULL) {
        os_log_error(OS_LOG_DEFAULT,
                     "SBInject lsd registration predicate is unavailable");
        return;
    }
    method_setImplementation(method, (IMP)allow_embedded_registration);

    int descriptor = open(markerPath,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor >= 0) {
        char ready[32] = {0};
        int readyLength = snprintf(ready, sizeof(ready), "%d\n", getpid());
        if (readyLength > 0 && (size_t)readyLength < sizeof(ready)) {
            (void)write(descriptor, ready, (size_t)readyLength);
        }
        (void)fchown(descriptor, 501, 501);
        (void)fchmod(descriptor, 0600);
        close(descriptor);
    }
    os_log(OS_LOG_DEFAULT,
           "SBInject enabled iOS 27 embedded registration in lsd");
}
