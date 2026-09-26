#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <os/log.h>
#include <sandbox.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sbinject_protocol.h"

extern int64_t sandbox_extension_consume(const char *extension_token);

typedef enum {
    CompatibilityTargetNone = 0,
    CompatibilityTargetBBC,
    CompatibilityTargetNavy,
    CompatibilityTargetGeneric,
} CompatibilityTarget;

static CompatibilityTarget compatibility_target;
static bool compatibility_installed;
static IMP compatibility_replacement;

static BOOL return_not_modified(id object, SEL selector) {
    (void)object;
    (void)selector;
    return NO;
}

static void compatibility_diagnostic(NSString *message) {
    NSString *directory = [NSHomeDirectory()
        stringByAppendingPathComponent:@"Library/Caches"];
    NSString *path = [directory
        stringByAppendingPathComponent:@"codex-target-compatibility.log"];
    NSString *line = [NSString stringWithFormat:@"%.3f %@\n",
                                                NSDate.date.timeIntervalSince1970,
                                                message];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    @synchronized(NSFileHandle.class) {
        (void)[NSFileManager.defaultManager
            createDirectoryAtPath:directory
            withIntermediateDirectories:YES
            attributes:nil
            error:nil];
        if (![NSFileManager.defaultManager fileExistsAtPath:path]) {
            (void)[NSData.data writeToFile:path atomically:YES];
        }
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
        if (handle != nil) {
            [handle seekToEndOfFile];
            [handle writeData:data];
            [handle closeFile];
        }
    }
}

static bool replace_boolean_method(Class target, SEL selector,
                                   NSString *stage) {
    if (target == Nil || selector == NULL) {
        compatibility_diagnostic([NSString
            stringWithFormat:@"stage=%@ class=%p selector=%s found=false",
                             stage, target,
                             selector != NULL ? sel_getName(selector) : "none"]);
        return false;
    }
    Method method = class_getInstanceMethod(target, selector);
    if (method == NULL) {
        compatibility_diagnostic([NSString
            stringWithFormat:@"stage=%@ class=%s selector=%s method=false",
                             stage, class_getName(target),
                             sel_getName(selector)]);
        return false;
    }
    IMP before = method_getImplementation(method);
    IMP previous = before;
    if (before != compatibility_replacement) {
        previous = method_setImplementation(method, compatibility_replacement);
    }
    IMP after = method_getImplementation(method);
    compatibility_diagnostic([NSString
        stringWithFormat:@"stage=%@ class=%s selector=%s method=true "
                         "before=%p previous=%p replacement=%p after=%p "
                         "active=%s types=%s",
                         stage, class_getName(target), sel_getName(selector),
                         before, previous, compatibility_replacement, after,
                         after == compatibility_replacement ? "true" : "false",
                         method_getTypeEncoding(method)]);
    if (after != compatibility_replacement) return false;
    return true;
}

static bool selector_is_jailbreak_check(SEL selector) {
    const char *name = selector != NULL ? sel_getName(selector) : NULL;
    if (name == NULL) return false;
    static const char *const candidates[] = {
        "isJailbroken",
        "isJailBroken",
        "isDeviceJailbroken",
        "isDeviceJailBroken",
        "jailbreakDetected",
        "isRooted",
        "isCompromised",
        "isDeviceCompromised",
    };
    for (size_t index = 0;
         index < sizeof(candidates) / sizeof(candidates[0]); ++index) {
        if (strcmp(name, candidates[index]) == 0) return true;
    }
    return false;
}

static bool method_returns_boolean(Method method) {
    if (method == NULL || method_getNumberOfArguments(method) != 2) {
        return false;
    }
    const char *type = method_getTypeEncoding(method);
    if (type == NULL) return false;
    while (*type == 'r' || *type == 'n' || *type == 'N' || *type == 'o' ||
           *type == 'O' || *type == 'R' || *type == 'V') {
        ++type;
    }
    return *type == 'B' || *type == 'c';
}

static bool scan_boolean_methods(Class target, NSString *stage) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(target, &count);
    bool installed = false;
    for (unsigned int index = 0; index < count; ++index) {
        Method method = methods[index];
        SEL selector = method_getName(method);
        if (!selector_is_jailbreak_check(selector) ||
            !method_returns_boolean(method)) {
            continue;
        }
        IMP before = method_getImplementation(method);
        if (before != compatibility_replacement) {
            (void)method_setImplementation(method, compatibility_replacement);
        }
        IMP after = method_getImplementation(method);
        if (after == compatibility_replacement) {
            installed = true;
            compatibility_diagnostic([NSString
                stringWithFormat:@"stage=%@ class=%s selector=%s "
                                 "generic=true active=true types=%s",
                                 stage, class_getName(target),
                                 sel_getName(selector),
                                 method_getTypeEncoding(method)]);
        }
    }
    free(methods);
    return installed;
}

static bool install_generic_overrides(NSString *stage) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0 || count > 32768) return false;
    __unsafe_unretained Class *classes =
        (__unsafe_unretained Class *)calloc((size_t)count, sizeof(*classes));
    if (classes == NULL) return false;
    count = objc_getClassList(classes, count);
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSString *prefix = [bundle stringByAppendingString:@"/"];
    bool installed = false;
    for (int index = 0; index < count; ++index) {
        Class target = classes[index];
        const char *image = class_getImageName(target);
        if (image == NULL) continue;
        NSString *path = [NSString stringWithUTF8String:image];
        if (![path isEqual:bundle] && ![path hasPrefix:prefix]) continue;
        installed |= scan_boolean_methods(target, stage);
        Class meta = object_getClass(target);
        if (meta != Nil) installed |= scan_boolean_methods(meta, stage);
    }
    free(classes);
    return installed;
}

static bool install_compatibility_override(NSString *stage) {
    bool installed = false;
    if (compatibility_target == CompatibilityTargetBBC) {
        installed = replace_boolean_method(
            objc_getClass("JailMonkey"), sel_registerName("isJailBroken"),
            stage);
    } else if (compatibility_target == CompatibilityTargetNavy) {
        Class backbase = objc_getClass("Backbase");
        installed = replace_boolean_method(
            backbase != Nil ? object_getClass(backbase) : Nil,
            sel_registerName("isDeviceJailbroken"), stage);
    } else if (compatibility_target == CompatibilityTargetGeneric) {
        installed = install_generic_overrides(stage);
    }
    compatibility_installed = installed;
    return installed;
}

static void schedule_compatibility_checks(void) {
    static const uint64_t delays[] = {
        100ULL * NSEC_PER_MSEC,
        500ULL * NSEC_PER_MSEC,
        1ULL * NSEC_PER_SEC,
        2ULL * NSEC_PER_SEC,
        5ULL * NSEC_PER_SEC,
        10ULL * NSEC_PER_SEC,
    };
    for (size_t index = 0; index < sizeof(delays) / sizeof(delays[0]); index++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delays[index]),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            (void)install_compatibility_override(
                [NSString stringWithFormat:@"delayed-%zu", index]);
        });
    }
}

static void image_added(const struct mach_header *header,
                        intptr_t slide) {
    (void)header;
    (void)slide;
    if (compatibility_target != CompatibilityTargetNone) {
        (void)install_compatibility_override(@"image-added");
    }
}

static os_log_t bootstrap_log(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.openai.codex.sbinject",
                            "shadow-bootstrap");
    });
    return log;
}

static bool consume_extensions(void) {
    const char *value = getenv("SANDBOX_EXTENSION");
    if (value == NULL || value[0] == '\0') return false;

    char *tokens = strdup(value);
    if (tokens == NULL) return false;
    bool consumed = true;
    char *cursor = tokens;
    for (;;) {
        char *separator = strchr(cursor, '|');
        if (separator != NULL) *separator = '\0';
        if (cursor[0] == '\0' || sandbox_extension_consume(cursor) < 0) {
            consumed = false;
        }
        if (separator == NULL) break;
        cursor = separator + 1;
    }
    free(tokens);
    return consumed;
}

__attribute__((constructor)) static void load_shadow_before_app_initializers(
    void) {
    @autoreleasepool {
        NSString *identifier = NSBundle.mainBundle.bundleIdentifier;
        if ([identifier isEqualToString:@"uk.co.bbc.news"]) {
            compatibility_target = CompatibilityTargetBBC;
        } else if ([identifier
                       isEqualToString:@"org.navyfederal.nfcuforiphone"]) {
            compatibility_target = CompatibilityTargetNavy;
        } else if (identifier.length > 0) {
            compatibility_target = CompatibilityTargetGeneric;
        }
        if (compatibility_target != CompatibilityTargetNone) {
            compatibility_replacement = (IMP)return_not_modified;
            bool installed = install_compatibility_override(@"constructor");
            _dyld_register_func_for_add_image(image_added);
            schedule_compatibility_checks();
            os_log_with_type(
                bootstrap_log(),
                installed ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_INFO,
                "Target compatibility identifier=%{public}s installed=%{public}s",
                identifier.UTF8String,
                installed ? "true" : "pending");
            return;
        }
    }
    bool extensions = consume_extensions();
    void *handle = extensions
        ? dlopen(CODEX_SBINJECT_SHADOW_CORE,
                 RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE)
        : NULL;
    const char *error = handle == NULL ? dlerror() : NULL;
    os_log_with_type(bootstrap_log(),
                     handle != NULL ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_ERROR,
                     "Shadow pre-main bootstrap extensions=%{public}s "
                     "loaded=%{public}s error=%{public}s",
                     extensions ? "true" : "false",
                     handle != NULL ? "true" : "false",
                     error != NULL ? error : "none");
}
