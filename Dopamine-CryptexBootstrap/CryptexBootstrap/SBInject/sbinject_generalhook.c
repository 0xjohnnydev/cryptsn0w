// Pre-main SpringBoard hook derived from the supplied SBInject generalhook.
#include "sbinject_dyld_bypass.h"
#include "sbinject_protocol.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/objc-exception.h>
#import <objc/runtime.h>

#include <bsm/audit.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach/arm/thread_status.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <os/log.h>
#include <ptrauth.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <time.h>
#include <unistd.h>

extern kern_return_t bootstrap_look_up(mach_port_t bootstrap_port,
                                       const char *service,
                                       mach_port_t *server_port);
extern int64_t sandbox_extension_consume(const char *token);
extern char *sandbox_extension_issue_file_to_process(
    const char *extension_class, const char *path, uint32_t flags,
    audit_token_t token);

static os_log_t hook_log(void) {
    static os_log_t log;
    if (log == NULL) {
        log = os_log_create("com.openai.codex.sbinject", "generalhook");
    }
    return log;
}

static void pre_main_log(const char *stage) {
    int descriptor = open("/var/mobile/.sbinject-generalhook.log",
                          O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return;
    }
    (void)dprintf(descriptor, "pid=%d stage=%s\n", getpid(), stage);
    (void)fsync(descriptor);
    close(descriptor);
}

static NSUncaughtExceptionHandler *g_previous_exception_handler;
static BOOL g_safe_mode_alert_presented;

#define CODEX_MAX_TWEAK_IMAGES 256U
#define CODEX_MAX_TWEAK_NAME 255U

struct codex_tweak_image {
    uintptr_t start;
    uintptr_t end;
    char name[CODEX_MAX_TWEAK_NAME + 1U];
};

struct codex_signal_handler {
    int number;
    struct sigaction previous;
    bool installed;
};

static struct codex_tweak_image g_tweak_images[CODEX_MAX_TWEAK_IMAGES];
static _Atomic uint32_t g_tweak_image_count;
static struct codex_signal_handler g_signal_handlers[] = {
    {.number = SIGABRT},
    {.number = SIGBUS},
    {.number = SIGSEGV},
    {.number = SIGILL},
    {.number = SIGTRAP},
};
static __thread char g_recent_exception_tweak[CODEX_MAX_TWEAK_NAME + 1U];
static __thread uint64_t g_recent_exception_nanoseconds;
static __thread bool g_recording_exception;

static bool tweak_image_path(const char *path) {
    return path != NULL &&
        (strstr(path, "/TweakInject/") != NULL ||
         strstr(path, "/MobileSubstrate/DynamicLibraries/") != NULL);
}

static NSString *tweak_name_for_address(uintptr_t address) {
    if (address == 0) return nil;
    address = (uintptr_t)ptrauth_strip(
        (void *)address, ptrauth_key_function_pointer);
    Dl_info image = {0};
    if (dladdr((const void *)address, &image) == 0 ||
        !tweak_image_path(image.dli_fname)) return nil;
    NSString *name = [[NSString stringWithUTF8String:image.dli_fname]
        lastPathComponent];
    return name.length != 0 ? name : nil;
}

static NSString *tweak_for_method_symbol(NSString *symbol) {
    NSRange minus = [symbol rangeOfString:@"-["];
    NSRange plus = [symbol rangeOfString:@"+["];
    NSRange start = minus.location != NSNotFound ? minus : plus;
    BOOL classMethod = minus.location == NSNotFound && plus.location != NSNotFound;
    if (start.location == NSNotFound) return nil;
    NSRange tail = NSMakeRange(start.location + 2U,
                              symbol.length - start.location - 2U);
    NSRange close = [symbol rangeOfString:@"]" options:0 range:tail];
    if (close.location == NSNotFound || close.location <= tail.location) {
        return nil;
    }
    NSString *body = [symbol substringWithRange:NSMakeRange(
        tail.location, close.location - tail.location)];
    NSRange separator = [body rangeOfString:@" "];
    if (separator.location == NSNotFound || separator.location == 0 ||
        separator.location + 1U >= body.length) return nil;
    Class target = NSClassFromString([body substringToIndex:separator.location]);
    SEL selector = NSSelectorFromString(
        [body substringFromIndex:separator.location + 1U]);
    Method method = classMethod ? class_getClassMethod(target, selector)
                                : class_getInstanceMethod(target, selector);
    if (method == NULL) return nil;
    return tweak_name_for_address(
        (uintptr_t)method_getImplementation(method));
}

static NSString *single_line_text(NSString *value, NSUInteger maximum) {
    if (value == nil) {
        return @"Unknown";
    }
    NSString *line = [[value componentsSeparatedByCharactersInSet:
        [NSCharacterSet newlineCharacterSet]] componentsJoinedByString:@" "];
    return line.length <= maximum ? line : [line substringToIndex:maximum];
}

static NSString *culprit_tweak_for_exception(NSException *exception) {
    for (NSNumber *address in exception.callStackReturnAddresses) {
        NSString *name = tweak_name_for_address(
            (uintptr_t)address.unsignedLongLongValue);
        if (name.length != 0) {
            return single_line_text(name, 200U);
        }
    }
    // Some tweaks replace an Objective-C method and then call its original
    // implementation. The throw site is consequently all Apple frames even
    // though the live method IMP still identifies the replacing tweak.
    for (NSString *symbol in exception.callStackSymbols) {
        NSString *name = tweak_for_method_symbol(symbol);
        if (name.length != 0) return single_line_text(name, 200U);
    }
    return @"Unknown tweak";
}

__attribute__((noreturn)) static void sbinject_objc_exception_throw(
    id exceptionObject) {
    if (!g_recording_exception &&
        [exceptionObject isKindOfClass:NSException.class]) {
        g_recording_exception = true;
        NSString *culprit = culprit_tweak_for_exception(exceptionObject);
        if (culprit.length != 0 &&
            ![culprit isEqualToString:@"Unknown tweak"]) {
            const char *name = culprit.UTF8String;
            size_t length = strnlen(name, CODEX_MAX_TWEAK_NAME);
            memcpy(g_recent_exception_tweak, name, length);
            g_recent_exception_tweak[length] = '\0';
            struct timespec now = {0};
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
                g_recent_exception_nanoseconds =
                    (uint64_t)now.tv_sec * NSEC_PER_SEC +
                    (uint64_t)now.tv_nsec;
            }
        }
        g_recording_exception = false;
    }
    objc_exception_throw(exceptionObject);
    __builtin_unreachable();
}

static void record_tweak_exception(NSException *exception) {
    NSString *tweak = culprit_tweak_for_exception(exception);
    NSString *reason = single_line_text(exception.reason, 768U);
    NSString *contents = [NSString stringWithFormat:
        @"tweak=%@\nreason=%@\n", tweak, reason];
    int descriptor = open(CODEX_SBINJECT_SAFE_MODE_MARKER,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor >= 0) {
        NSData *data = [contents dataUsingEncoding:NSUTF8StringEncoding];
        const uint8_t *cursor = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            ssize_t amount = write(descriptor, cursor, remaining);
            if (amount < 0 && errno == EINTR) {
                continue;
            }
            if (amount <= 0) {
                break;
            }
            cursor += amount;
            remaining -= (NSUInteger)amount;
        }
        (void)fchown(descriptor, 501, 501);
        (void)fchmod(descriptor, 0600);
        (void)fsync(descriptor);
        close(descriptor);
    }
    os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                     "tweak exception armed safe mode culprit=%{public}s "
                     "reason=%{public}s",
                     tweak.UTF8String, reason.UTF8String);
    if (g_previous_exception_handler != NULL &&
        g_previous_exception_handler != record_tweak_exception) {
        g_previous_exception_handler(exception);
    }
}

static void record_tweak_image(const struct mach_header *header,
                               intptr_t slide) {
    Dl_info information = {0};
    if (header == NULL || header->magic != MH_MAGIC_64 ||
        dladdr(header, &information) == 0 ||
        !tweak_image_path(information.dli_fname)) return;
    uint32_t count = atomic_load_explicit(&g_tweak_image_count,
                                          memory_order_relaxed);
    if (count >= CODEX_MAX_TWEAK_IMAGES) return;

    const struct mach_header_64 *header64 =
        (const struct mach_header_64 *)header;
    const uint8_t *commands = (const uint8_t *)(header64 + 1);
    const uint8_t *commandsEnd = commands + header64->sizeofcmds;
    const struct load_command *command =
        (const struct load_command *)commands;
    uintptr_t start = 0;
    uintptr_t end = 0;
    for (uint32_t index = 0; index < header64->ncmds; ++index) {
        const uint8_t *next = (const uint8_t *)command + command->cmdsize;
        if ((const uint8_t *)command + sizeof(*command) > commandsEnd ||
            command->cmdsize < sizeof(*command) || next > commandsEnd) break;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_TEXT,
                        sizeof(segment->segname)) == 0 &&
                segment->vmsize != 0 &&
                segment->vmaddr <= UINTPTR_MAX - segment->vmsize) {
                start = (uintptr_t)segment->vmaddr + (uintptr_t)slide;
                end = start + (uintptr_t)segment->vmsize;
                break;
            }
        }
        command = (const struct load_command *)next;
    }
    if (start == 0 || end <= start) return;

    const char *name = strrchr(information.dli_fname, '/');
    name = name != NULL ? name + 1 : information.dli_fname;
    struct codex_tweak_image *destination = &g_tweak_images[count];
    destination->start = start;
    destination->end = end;
    size_t length = strnlen(name, CODEX_MAX_TWEAK_NAME);
    for (size_t index = 0; index < length; ++index) {
        unsigned char character = (unsigned char)name[index];
        destination->name[index] =
            character >= 0x20U && character != 0x7fU ? (char)character : '?';
    }
    destination->name[length] = '\0';
    atomic_store_explicit(&g_tweak_image_count, count + 1U,
                          memory_order_release);
    int descriptor = open("/var/mobile/.sbinject-generalhook.log",
                          O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor >= 0) {
        (void)dprintf(descriptor, "pid=%d stage=tweak-image name=%s\n",
                      getpid(), destination->name);
        close(descriptor);
    }
}

static const char *signal_tweak_name(uintptr_t address) {
    if (address == 0) return NULL;
    address = (uintptr_t)ptrauth_strip(
        (void *)address, ptrauth_key_function_pointer);
    uint32_t count = atomic_load_explicit(&g_tweak_image_count,
                                          memory_order_acquire);
    if (count > CODEX_MAX_TWEAK_IMAGES) count = CODEX_MAX_TWEAK_IMAGES;
    for (uint32_t index = 0; index < count; ++index) {
        if (address >= g_tweak_images[index].start &&
            address < g_tweak_images[index].end) {
            return g_tweak_images[index].name;
        }
    }
    return NULL;
}

static void signal_append_text(char *buffer, size_t capacity, size_t *offset,
                               const char *text) {
    if (buffer == NULL || offset == NULL || text == NULL) return;
    while (*text != '\0' && *offset + 1U < capacity) {
        buffer[(*offset)++] = *text++;
    }
}

static void signal_append_number(char *buffer, size_t capacity,
                                 size_t *offset, unsigned int value) {
    char digits[16];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10U);
        value /= 10U;
    } while (value != 0 && count < sizeof(digits));
    while (count > 0 && *offset + 1U < capacity) {
        buffer[(*offset)++] = digits[--count];
    }
}

static void write_signal_safe_mode_marker(const char *tweak, int number) {
    if (tweak == NULL || tweak[0] == '\0') return;
    int descriptor = open(CODEX_SBINJECT_SAFE_MODE_MARKER,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) return;
    char contents[512];
    size_t length = 0;
    signal_append_text(contents, sizeof(contents), &length, "tweak=");
    signal_append_text(contents, sizeof(contents), &length, tweak);
    signal_append_text(contents, sizeof(contents), &length,
                       "\nreason=fatal signal ");
    signal_append_number(contents, sizeof(contents), &length,
                         (unsigned int)number);
    signal_append_text(contents, sizeof(contents), &length,
                       " occurred in tweak code\n");
    size_t offset = 0;
    while (offset < length) {
        ssize_t amount = write(descriptor, contents + offset, length - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) break;
        offset += (size_t)amount;
    }
    (void)fchown(descriptor, 501, 501);
    (void)fchmod(descriptor, 0600);
    close(descriptor);
}

static struct codex_signal_handler *signal_handler_record(int number) {
    for (size_t index = 0;
         index < sizeof(g_signal_handlers) / sizeof(g_signal_handlers[0]);
         ++index) {
        if (g_signal_handlers[index].number == number) {
            return &g_signal_handlers[index];
        }
    }
    return NULL;
}

static void chain_previous_signal_handler(int number, siginfo_t *information,
                                          void *context) {
    struct codex_signal_handler *record = signal_handler_record(number);
    if (record == NULL || !record->installed) return;
    struct sigaction previous = record->previous;
    if (previous.sa_handler == SIG_IGN) return;
    if (previous.sa_handler == SIG_DFL || previous.sa_handler == NULL) {
        (void)sigaction(number, &previous, NULL);
        (void)kill(getpid(), number);
        return;
    }
    if ((previous.sa_flags & SA_SIGINFO) != 0) {
        previous.sa_sigaction(number, information, context);
    } else {
        previous.sa_handler(number);
    }
}

static void record_tweak_signal(int number, siginfo_t *information,
                                void *rawContext) {
    (void)information;
    const char *tweak = NULL;
#if defined(__arm64__)
    ucontext_t *context = (ucontext_t *)rawContext;
    if (context != NULL && context->uc_mcontext != NULL) {
        _STRUCT_ARM_THREAD_STATE64 state = context->uc_mcontext->__ss;
        uintptr_t programCounter =
            (uintptr_t)arm_thread_state64_get_pc(state);
        uintptr_t linkRegister =
            (uintptr_t)arm_thread_state64_get_lr(state);
        tweak = signal_tweak_name(programCounter);
        if (tweak == NULL) tweak = signal_tweak_name(linkRegister);
    }
#endif
    if (tweak == NULL && g_recent_exception_tweak[0] != '\0') {
        struct timespec now = {0};
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            uint64_t nanoseconds = (uint64_t)now.tv_sec * NSEC_PER_SEC +
                                   (uint64_t)now.tv_nsec;
            if (nanoseconds >= g_recent_exception_nanoseconds &&
                nanoseconds - g_recent_exception_nanoseconds <=
                    5U * NSEC_PER_SEC) {
                tweak = g_recent_exception_tweak;
            }
        }
    }
    write_signal_safe_mode_marker(tweak, number);
    chain_previous_signal_handler(number, information, rawContext);
}

static void install_tweak_signal_attribution(void) {
    _dyld_register_func_for_add_image(record_tweak_image);
    for (size_t index = 0;
         index < sizeof(g_signal_handlers) / sizeof(g_signal_handlers[0]);
         ++index) {
        struct codex_signal_handler *record = &g_signal_handlers[index];
        if (sigaction(record->number, NULL, &record->previous) != 0) continue;
        struct sigaction action = {0};
        sigemptyset(&action.sa_mask);
        action.sa_sigaction = record_tweak_signal;
        action.sa_flags = SA_SIGINFO |
            (record->previous.sa_flags & (SA_ONSTACK | SA_NODEFER));
        if (sigaction(record->number, &action, NULL) == 0) {
            record->installed = true;
        }
    }
}

#define CODEX_GENERALHOOK_INTERPOSE(replacement, replacee)                    \
    __attribute__((used)) static struct {                                     \
        const void *replacement;                                              \
        const void *replacee;                                                 \
    } codex_generalhook_interpose_##replacee                                  \
        __attribute__((section("__DATA,__interpose"))) = {                    \
            (const void *)(uintptr_t)&replacement,                            \
            (const void *)(uintptr_t)&replacee,                               \
        }

CODEX_GENERALHOOK_INTERPOSE(sbinject_objc_exception_throw,
                            objc_exception_throw);

static NSDictionary<NSString *, NSString *> *safe_mode_information(void) {
    struct stat status;
    if (lstat(CODEX_SBINJECT_SAFE_MODE_MARKER, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 ||
        (status.st_uid != 0 && status.st_uid != 501) || status.st_size <= 0 ||
        status.st_size > 4096 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (access(CODEX_SBINJECT_ELLEKIT_SAFE_MODE_MARKER, F_OK) == 0) {
            return @{
                @"tweak" : @"Unknown tweak",
                @"reason" : @"ElleKit reported a SpringBoard crash",
            };
        }
        return nil;
    }
    NSError *read_error = nil;
    NSString *contents = [NSString
        stringWithContentsOfFile:@CODEX_SBINJECT_SAFE_MODE_MARKER
                        encoding:NSUTF8StringEncoding
                           error:&read_error];
    if (contents == nil) {
        return nil;
    }
    NSMutableDictionary<NSString *, NSString *> *values =
        [NSMutableDictionary dictionary];
    for (NSString *line in
         [contents componentsSeparatedByCharactersInSet:
                       [NSCharacterSet newlineCharacterSet]]) {
        NSRange separator = [line rangeOfString:@"="];
        if (separator.location == NSNotFound || separator.location == 0 ||
            separator.location + 1U >= line.length) {
            continue;
        }
        NSString *key = [line substringToIndex:separator.location];
        NSString *value = [line substringFromIndex:separator.location + 1U];
        if (([key isEqualToString:@"tweak"] ||
             [key isEqualToString:@"reason"]) &&
            value.length <= 1024U) {
            values[key] = value;
        }
    }
    if (values[@"tweak"] == nil) {
        values[@"tweak"] = @"Unknown tweak";
    }
    return values;
}

static UIViewController *top_view_controller(UIViewController *controller) {
    if (controller == nil) return nil;
    UIViewController *presented = controller.presentedViewController;
    if (presented != nil && !presented.isBeingDismissed) {
        return top_view_controller(presented);
    }
    if ([controller isKindOfClass:UINavigationController.class]) {
        UIViewController *visible =
            ((UINavigationController *)controller).visibleViewController;
        if (visible != nil) return top_view_controller(visible);
    }
    if ([controller isKindOfClass:UITabBarController.class]) {
        UIViewController *selected =
            ((UITabBarController *)controller).selectedViewController;
        if (selected != nil) return top_view_controller(selected);
    }
    for (UIViewController *child in
         controller.childViewControllers.reverseObjectEnumerator) {
        if (child.isViewLoaded && child.view.window != nil) {
            return top_view_controller(child);
        }
    }
    return controller;
}

static UIViewController *safe_mode_alert_presenter(void) {
    UIApplication *application = UIApplication.sharedApplication;
    if (application.applicationState != UIApplicationStateActive) return nil;
    for (UIScene *scene in application.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            scene.activationState != UISceneActivationStateForegroundActive) {
            continue;
        }
        NSArray<UIWindow *> *windows = ((UIWindowScene *)scene).windows;
        for (NSUInteger pass = 0; pass < 2U; ++pass) {
            for (UIWindow *window in windows) {
                if (window.hidden || window.alpha <= 0.01 ||
                    window.rootViewController == nil ||
                    (pass == 0U && !window.isKeyWindow) ||
                    (pass == 1U && window.isKeyWindow)) {
                    continue;
                }
                UIViewController *presenter =
                    top_view_controller(window.rootViewController);
                if (presenter != nil && presenter.isViewLoaded &&
                    presenter.view.window == window &&
                    !presenter.isBeingDismissed &&
                    !presenter.isBeingPresented &&
                    presenter.transitionCoordinator == nil) {
                    return presenter;
                }
            }
        }
    }
    return nil;
}

static BOOL present_tweak_safe_mode_alert(
    NSDictionary<NSString *, NSString *> *information) {
    if (g_safe_mode_alert_presented) return YES;
    UIApplication *application = UIApplication.sharedApplication;
    UIViewController *presenter = safe_mode_alert_presenter();
    if (presenter == nil ||
        [presenter isKindOfClass:UIAlertController.class]) return NO;

    NSString *tweak = single_line_text(information[@"tweak"], 200U);
    NSString *display_name = [[tweak lastPathComponent]
        stringByDeletingPathExtension];
    bool known = ![tweak isEqualToString:@"Unknown tweak"];
    NSString *message = known
        ? [NSString stringWithFormat:
            @"%@ caused SpringBoard to crash. SBInject has temporarily "
             "disabled tweak injection so the phone stays usable.\n\nOpen "
             "Sileo and disable or uninstall %@. Then return here and tap "
             "‘Respring With Tweaks’, or use Sileo’s Respring SpringBoard "
             "button.",
            display_name, display_name]
        : @"A SpringBoard tweak caused a crash. SBInject has temporarily "
           "disabled tweak injection so the phone stays usable.\n\nOpen "
           "Sileo and disable the most recently installed SpringBoard tweak. "
           "Then return here and tap ‘Respring With Tweaks’, or use Sileo’s "
           "Respring SpringBoard button.";
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"SBInject Tweak Safe Mode"
                         message:message
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction
        actionWithTitle:@"Open Sileo"
                  style:UIAlertActionStyleDefault
                handler:^(__unused UIAlertAction *action) {
                  NSURL *url = [NSURL URLWithString:@"sileo://"];
                  [application openURL:url options:@{}
                     completionHandler:nil];
                }]];
    [alert addAction:[UIAlertAction
        actionWithTitle:@"Respring With Tweaks"
                  style:UIAlertActionStyleDestructive
                handler:^(__unused UIAlertAction *action) {
                  (void)unlink(CODEX_SBINJECT_SAFE_MODE_MARKER);
                  (void)unlink(CODEX_SBINJECT_ELLEKIT_SAFE_MODE_MARKER);
                  dispatch_after(
                      dispatch_time(DISPATCH_TIME_NOW,
                                    (int64_t)(0.2 * NSEC_PER_SEC)),
                      dispatch_get_main_queue(), ^{
                        (void)kill(getpid(), SIGTERM);
                      });
                }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Stay in Safe Mode"
                                             style:UIAlertActionStyleCancel
                                           handler:nil]];
    g_safe_mode_alert_presented = YES;
    [presenter presentViewController:alert animated:YES completion:nil];
    return YES;
}

static void attempt_tweak_safe_mode_alert(
    NSDictionary<NSString *, NSString *> *information, NSUInteger attempt) {
    if (present_tweak_safe_mode_alert(information)) return;
    if (attempt >= 60U) {
        os_log_with_type(hook_log(), OS_LOG_TYPE_ERROR,
                         "safe-mode alert presenter unavailable after retries");
        return;
    }
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
          attempt_tweak_safe_mode_alert(information, attempt + 1U);
        });
}

static void schedule_tweak_safe_mode_alert(
    NSDictionary<NSString *, NSString *> *information) {
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
          attempt_tweak_safe_mode_alert(information, 0U);
        });
}

static bool exact_candidate(bool *preferences_out) {
    if (preferences_out != NULL) {
        *preferences_out = false;
    }
    uint32_t size = 0;
    (void)_NSGetExecutablePath(NULL, &size);
    char *path = calloc((size_t)size + 1U, 1U);
    if (path == NULL || _NSGetExecutablePath(path, &size) != 0) {
        free(path);
        return false;
    }
    char observed[PATH_MAX] = {0};
    bool exact = false;
    if (realpath(path, observed) != NULL) {
        const char *const candidates[] = {
            CODEX_SBINJECT_SPRINGBOARD,
            CODEX_SBINJECT_PREFERENCES,
        };
        for (size_t index = 0;
             index < sizeof(candidates) / sizeof(candidates[0]); ++index) {
            char configured[PATH_MAX] = {0};
            if (realpath(candidates[index], configured) != NULL &&
                strcmp(configured, observed) == 0) {
                exact = true;
                if (preferences_out != NULL) {
                    *preferences_out = index == 1U;
                }
                break;
            }
        }
    }
    free(path);
    return exact;
}

static bool mark_self_debugged(void) {
    mach_port_t port = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE,
                          &port) != KERN_SUCCESS ||
        !MACH_PORT_VALID(port)) {
        return false;
    }
    xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
    mach_port_deallocate(mach_task_self(), port);
    if (pipe == NULL) {
        return false;
    }
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(message, "id", CODEX_SBINJECT_JIT_MESSAGE_ID);
    xpc_dictionary_set_int64(message, "pid", getpid());
    xpc_object_t reply = NULL;
    int transport = xpc_pipe_routine(pipe, message, &reply);
#if !OS_OBJECT_USE_OBJC
    xpc_release(message);
    xpc_release(pipe);
#endif
    int64_t result = reply != NULL
                         ? xpc_dictionary_get_int64(reply, "result")
                         : -1;
#if !OS_OBJECT_USE_OBJC
    if (reply != NULL) {
        xpc_release(reply);
    }
#endif
    return transport == 0 && result == 0;
}

static void consume_extension(const char *extension_class, const char *path,
                              audit_token_t token) {
    char *extension = sandbox_extension_issue_file_to_process(
        extension_class, path, 0, token);
    if (extension != NULL) {
        (void)sandbox_extension_consume(extension);
        free(extension);
    }
}

static void apply_supplied_sandbox_extensions(void) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token,
                  &count) != KERN_SUCCESS) {
        return;
    }
    consume_extension("com.apple.app-sandbox.read", "/var/jb", token);
    consume_extension("com.apple.sandbox.executable", "/var/jb", token);
    consume_extension("com.apple.app-sandbox.read-write", "/var/mobile",
                      token);
}

static const char *preference_loader_path(void) {
    static const char *const candidates[] = {
        CODEX_SBINJECT_PREFERENCELOADER,
        CODEX_SBINJECT_PREFERENCELOADER_LEGACY,
    };
    for (size_t index = 0;
         index < sizeof(candidates) / sizeof(candidates[0]); ++index) {
        if (access(candidates[index], R_OK) == 0) {
            return candidates[index];
        }
    }
    return NULL;
}

__attribute__((constructor)) static void initialize_general_hook(void) {
    bool preferences = false;
    if (!exact_candidate(&preferences)) {
        return;
    }
    os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                     "SBInject pre-main hook entered pid=%d", getpid());
    pre_main_log("entered");
    apply_supplied_sandbox_extensions();
    if (!preferences) {
        NSDictionary<NSString *, NSString *> *safe_mode =
            safe_mode_information();
        if (safe_mode != nil) {
            os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                             "SBInject tweak safe mode active culprit=%{public}s",
                             safe_mode[@"tweak"].UTF8String);
            pre_main_log("safe-mode");
            schedule_tweak_safe_mode_alert(safe_mode);
            return;
        }
        g_previous_exception_handler = NSGetUncaughtExceptionHandler();
        NSSetUncaughtExceptionHandler(record_tweak_exception);
    }
    if (!mark_self_debugged()) {
        pre_main_log("jitterd-failed");
        os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                         "jitterd refused SpringBoard; exiting for fallback");
        _exit(78);
    }
    pre_main_log("jitterd-ready");
    if (!sbinject_install_dyld_validation_bypass()) {
        pre_main_log("dyld-bypass-failed");
        os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                         "dyld validation bypass did not match target; "
                         "exiting for fallback");
        _exit(79);
    }
    pre_main_log("dyld-bypass-ready");
    dlerror();
    void *legacy_compat = dlopen(
        CODEX_SBINJECT_LEGACY_TWEAK_COMPAT, RTLD_NOW | RTLD_GLOBAL);
    if (legacy_compat == NULL) {
        const char *error = dlerror();
        os_log_with_type(hook_log(), OS_LOG_TYPE_ERROR,
                         "legacy tweak compatibility unavailable: %{public}s",
                         error != NULL ? error : "unknown");
        pre_main_log("legacy-compat-unavailable");
    } else {
        os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                         "legacy tweak compatibility loaded pre-main");
        pre_main_log("legacy-compat-ready");
    }
    dlerror();
    void *injector = dlopen(CODEX_SBINJECT_ELLEKIT, RTLD_NOW | RTLD_LOCAL);
    if (injector == NULL) {
        pre_main_log("ellekit-failed");
        const char *error = dlerror();
        os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                         "ElleKit pre-main load failed: %{public}s",
                         error != NULL ? error : "unknown");
        _exit(80);
    }
    pre_main_log("ellekit-ready");
    if (!preferences) {
        NSUncaughtExceptionHandler *current =
            NSGetUncaughtExceptionHandler();
        if (current != record_tweak_exception) {
            g_previous_exception_handler = current;
            NSSetUncaughtExceptionHandler(record_tweak_exception);
        }
        install_tweak_signal_attribution();
        pre_main_log("crash-attribution-ready");
    }
    const char *preference_loader_path_value =
        preferences ? preference_loader_path() : NULL;
    if (preferences && preference_loader_path_value != NULL) {
        dlerror();
        void *preference_loader = dlopen(
            preference_loader_path_value, RTLD_NOW | RTLD_LOCAL);
        if (preference_loader == NULL) {
            pre_main_log("preferenceloader-failed");
            const char *error = dlerror();
            os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                             "PreferenceLoader pre-main load failed: "
                             "%{public}s",
                             error != NULL ? error : "unknown");
            _exit(81);
        }
        pre_main_log("preferenceloader-ready");
        os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                         "PreferenceLoader loaded pre-main path=%{public}s",
                         preference_loader_path_value);
        dlerror();
        void *preferences_bridge = dlopen(
            CODEX_SBINJECT_PREFERENCES_BRIDGE, RTLD_NOW | RTLD_LOCAL);
        if (preferences_bridge == NULL) {
            pre_main_log("preferences-bridge-failed");
            const char *error = dlerror();
            os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                             "iOS 27 Settings bridge load failed: %{public}s",
                             error != NULL ? error : "unknown");
            _exit(82);
        }
        pre_main_log("preferences-bridge-ready");
        os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                         "iOS 27 Settings bridge loaded pre-main");
    } else if (preferences) {
        pre_main_log("preferenceloader-missing");
    }
    os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                     "SBInject ready; ElleKit loaded pre-main");
}
