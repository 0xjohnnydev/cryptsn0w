#import <Foundation/Foundation.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <math.h>
#include <stddef.h>
#include <unistd.h>

static NSString *const kResultPath =
    @"/var/mobile/Media/codex-jsc-data-probe.json";

@interface CodexJSCProbeTarget : NSObject
- (NSNumber *)answer;
- (void)invokeBlock:(void (^)(NSNumber *value))block;
@end

@implementation CodexJSCProbeTarget
- (NSNumber *)answer {
    return @42;
}

- (void)invokeBlock:(void (^)(NSNumber *value))block {
    if (block != nil) {
        block(@73);
    }
}
@end

@protocol CodexStaticJSExport <JSExport>
- (NSNumber *)staticAnswer;
@end

@protocol CodexTargetSignatureSource
- (NSNumber *)answer;
- (void)invokeBlock:(void (^)(NSNumber *value))block;
@end

@protocol CodexNotificationSignatureSource
- (id)addObserverForName:(NSNotificationName)name
                  object:(id)object
                   queue:(NSOperationQueue *)queue
              usingBlock:(void (^)(NSNotification *notification))block;
- (void)postNotificationName:(NSNotificationName)name object:(id)object;
@end

@interface CodexJSCStaticControlTarget : NSObject <CodexStaticJSExport>
@end

@implementation CodexJSCStaticControlTarget
- (NSNumber *)staticAnswer {
    return @11;
}
@end

static BOOL AddProtocolMethod(Protocol *protocol, Class cls, SEL selector) {
    Method method = class_getInstanceMethod(cls, selector);
    const char *types = method != NULL ? method_getTypeEncoding(method) : NULL;
    if (types == NULL) {
        return NO;
    }
    protocol_addMethodDescription(protocol, selector, types, YES, YES);
    return YES;
}

typedef const char *(*ProtocolGetMethodTypeEncodingFunction)(
    Protocol *protocol, SEL selector, BOOL required, BOOL instance);

// objc_allocateProtocol currently allocates this complete protocol_t prefix.
// Only the extended-method-types slot is written, and only while the protocol
// is still under construction.
struct CodexProtocolLayout {
    uintptr_t isa;
    const char *mangledName;
    void *protocols;
    void *instanceMethods;
    void *classMethods;
    void *optionalInstanceMethods;
    void *optionalClassMethods;
    void *instanceProperties;
    uint32_t size;
    uint32_t flags;
    const char **extendedMethodTypes;
};

_Static_assert(offsetof(struct CodexProtocolLayout, extendedMethodTypes) == 72,
               "unexpected protocol_t prefix layout");

static ProtocolGetMethodTypeEncodingFunction GetEncodingFunction(void) {
    return (ProtocolGetMethodTypeEncodingFunction)dlsym(
        RTLD_DEFAULT, "_protocol_getMethodTypeEncoding");
}

static const char **CopyExtendedMethodTypes(Protocol *signatureSource,
                                            const SEL *selectors,
                                            size_t selectorCount) {
    ProtocolGetMethodTypeEncodingFunction getEncoding =
        GetEncodingFunction();
    if (getEncoding == NULL || signatureSource == nil) {
        return NULL;
    }
    const char **types = calloc(selectorCount, sizeof(*types));
    if (types == NULL) {
        return NULL;
    }
    for (size_t index = 0; index < selectorCount; ++index) {
        const char *type = getEncoding(signatureSource, selectors[index],
                                       YES, YES);
        if (type == NULL || (types[index] = strdup(type)) == NULL) {
            for (size_t prior = 0; prior < index; ++prior) {
                free((void *)types[prior]);
            }
            free(types);
            return NULL;
        }
    }
    return types;
}

static Protocol *CreateExportProtocol(const char *name, Class providerClass,
                                      const SEL *selectors,
                                      size_t selectorCount,
                                      Protocol *signatureSource) {
    Protocol *base = objc_getProtocol("JSExport");
    Protocol *protocol = objc_allocateProtocol(name);
    if (base == nil || protocol == nil) {
        return nil;
    }
    protocol_addProtocol(protocol, base);
    for (size_t index = 0; index < selectorCount; ++index) {
        if (!AddProtocolMethod(protocol, providerClass, selectors[index])) {
            return nil;
        }
    }
    const char **extendedTypes = CopyExtendedMethodTypes(
        signatureSource, selectors, selectorCount);
    struct CodexProtocolLayout *layout =
        (struct CodexProtocolLayout *)(__bridge void *)protocol;
    if (extendedTypes == NULL ||
        layout->size < offsetof(struct CodexProtocolLayout,
                                extendedMethodTypes) +
                           sizeof(layout->extendedMethodTypes)) {
        return nil;
    }
    layout->extendedMethodTypes = extendedTypes;
    objc_registerProtocol(protocol);
    return protocol;
}

static Class CreateExportSubclass(const char *name, Class superclass,
                                  Protocol *protocol) {
    if (superclass == Nil || protocol == nil) {
        return Nil;
    }
    Class subclass = objc_allocateClassPair(superclass, name, 0);
    if (subclass == Nil) {
        return Nil;
    }
    if (!class_addProtocol(subclass, protocol)) {
        objc_disposeClassPair(subclass);
        return Nil;
    }
    objc_registerClassPair(subclass);
    return subclass;
}

static NSInvocation *CreateInvocationCallback(const char *className,
                                              SEL eventSelector,
                                              const char *eventTypes,
                                              JSValue *function,
                                              NSArray *arguments) {
    SEL callSelector = @selector(callWithArguments:);
    NSMethodSignature *signature =
        [JSValue instanceMethodSignatureForSelector:callSelector];
    if (signature == nil || function == nil || arguments == nil) {
        return nil;
    }
    NSInvocation *sampleInvocation =
        [NSInvocation invocationWithMethodSignature:signature];
    Class concreteClass = object_getClass(sampleInvocation);
    Method invokeMethod =
        class_getInstanceMethod(concreteClass, @selector(invoke));
    if (concreteClass == Nil || invokeMethod == NULL) {
        return nil;
    }
    Class callbackClass =
        objc_allocateClassPair(concreteClass, className, 0);
    if (callbackClass == Nil ||
        !class_addMethod(callbackClass, eventSelector,
                         method_getImplementation(invokeMethod), eventTypes)) {
        if (callbackClass != Nil) {
            objc_disposeClassPair(callbackClass);
        }
        return nil;
    }
    objc_registerClassPair(callbackClass);

    NSInvocation *invocation =
        [(id)callbackClass invocationWithMethodSignature:signature];
    if (invocation == nil || object_getClass(invocation) != callbackClass) {
        return nil;
    }
    invocation.target = function;
    invocation.selector = callSelector;
    id argumentObject = arguments;
    [invocation setArgument:&argumentObject atIndex:2];
    [invocation retainArguments];
    return invocation;
}

static void RecordException(NSMutableArray<NSString *> *exceptions,
                            JSValue *exception) {
    NSString *text = [exception toString];
    [exceptions addObject:text ?: @"unknown JavaScript exception"];
}

static id JSONSafeJSValue(JSValue *value) {
    if (value == nil) {
        return @{ @"kind": @"nil" };
    }
    if (value.isUndefined) {
        return @{ @"kind": @"undefined" };
    }
    if (value.isNull) {
        return [NSNull null];
    }
    if (value.isBoolean) {
        return [value toBool] ? @YES : @NO;
    }
    if (value.isNumber) {
        double number = [value toDouble];
        if (isfinite(number)) {
            return @(number);
        }
        return @{
            @"kind": @"non-finite-number",
            @"text": [value toString] ?: @"unknown",
        };
    }
    if (value.isString) {
        return [value toString] ?: @"";
    }
    return @{
        @"kind": value.isObject ? @"object" : @"unknown",
        @"text": [value toString] ?: @"unknown",
    };
}

static BOOL JSValueEqualsInteger(JSValue *value, NSInteger expected) {
    if (value == nil || !value.isNumber) {
        return NO;
    }
    double number = [value toDouble];
    return isfinite(number) && number == (double)expected;
}

static BOOL WriteCheckpoint(NSMutableDictionary *result, NSString *phase) {
    result[@"phase"] = phase;
    NSError *jsonError = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:result
                                                   options:NSJSONWritingPrettyPrinted
                                                     error:&jsonError];
    if (json == nil) {
        dprintf(STDERR_FILENO,
                "jsc-data-probe checkpoint serialization failed: %s\n",
                jsonError.localizedDescription.UTF8String ?: "unknown");
        return NO;
    }
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    if (![line writeToFile:kResultPath options:NSDataWritingAtomic
                     error:&jsonError]) {
        dprintf(STDERR_FILENO, "jsc-data-probe checkpoint write failed: %s\n",
                jsonError.localizedDescription.UTF8String ?: "unknown");
        return NO;
    }
    return YES;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    @autoreleasepool {
        // Keep this representative of a target without a JIT entitlement.
        setenv("JSC_useJIT", "false", 1);
        setenv("JSC_useDFGJIT", "false", 1);
        setenv("JSC_useFTLJIT", "false", 1);

        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        NSMutableArray<NSString *> *exceptions = [NSMutableArray array];
        result[@"pid"] = @(getpid());
        result[@"jitRequested"] = @NO;
        result[@"exceptions"] = exceptions;
        if (!WriteCheckpoint(result, @"started")) {
            return 3;
        }

        const SEL targetSelectors[] = {
            @selector(answer),
            @selector(invokeBlock:),
        };
        Protocol *targetProtocol = CreateExportProtocol(
            "CodexDynamicJSExport", [CodexJSCProbeTarget class],
            targetSelectors,
            sizeof(targetSelectors) / sizeof(targetSelectors[0]),
            @protocol(CodexTargetSignatureSource));
        Class targetClass = CreateExportSubclass(
            "CodexJSCProbeTargetExported", [CodexJSCProbeTarget class],
            targetProtocol);
        result[@"targetProtocolCreated"] = @(targetProtocol != nil);
        result[@"targetSubclassRegistered"] = @(targetClass != Nil);
        result[@"targetProtocolAttached"] = @(
            targetClass != Nil && class_conformsToProtocol(targetClass,
                                                            targetProtocol));
        result[@"targetAnswerDescribed"] = @(
            targetProtocol != nil &&
            protocol_getMethodDescription(targetProtocol, @selector(answer),
                                          YES, YES).name != NULL);

        const SEL notificationSelectors[] = {
            @selector(addObserverForName:object:queue:usingBlock:),
            @selector(postNotificationName:object:),
        };
        Protocol *notificationProtocol = CreateExportProtocol(
            "CodexNotificationJSExport", [NSNotificationCenter class],
            notificationSelectors,
            sizeof(notificationSelectors) / sizeof(notificationSelectors[0]),
            @protocol(CodexNotificationSignatureSource));
        Class notificationClass = CreateExportSubclass(
            "CodexNSNotificationCenterExported", [NSNotificationCenter class],
            notificationProtocol);
        result[@"notificationProtocolCreated"] =
            @(notificationProtocol != nil);
        result[@"notificationSubclassRegistered"] =
            @(notificationClass != Nil);
        result[@"notificationProtocolAttached"] = @(
            notificationClass != Nil &&
            class_conformsToProtocol(notificationClass, notificationProtocol));
        ProtocolGetMethodTypeEncodingFunction getEncoding =
            GetEncodingFunction();
        result[@"privateEncodingFunctionFound"] = @(getEncoding != NULL);
        if (getEncoding != NULL && targetProtocol != nil) {
            const char *answerEncoding = getEncoding(
                targetProtocol, @selector(answer), YES, YES);
            const char *blockEncoding = getEncoding(
                targetProtocol, @selector(invokeBlock:), YES, YES);
            result[@"dynamicAnswerEncoding"] = answerEncoding != NULL
                ? @(answerEncoding) : @"missing";
            result[@"dynamicBlockEncoding"] = blockEncoding != NULL
                ? @(blockEncoding) : @"missing";
        }
        if (!WriteCheckpoint(result, @"protocols-attached")) {
            return 3;
        }

        JSContext *context = [[JSContext alloc] init];
        context.exceptionHandler = ^(JSContext *ctx, JSValue *exception) {
            (void)ctx;
            RecordException(exceptions, exception);
        };

        CodexJSCStaticControlTarget *staticTarget =
            [[CodexJSCStaticControlTarget alloc] init];
        context[@"staticTarget"] = staticTarget;
        JSValue *staticAnswer =
            [context evaluateScript:@"staticTarget.staticAnswer()"];
        result[@"staticControlAnswer"] = JSONSafeJSValue(staticAnswer);
        if (!WriteCheckpoint(result, @"static-control-complete")) {
            return 3;
        }

        id target = [[targetClass alloc] init];
        context[@"target"] = target;
        JSValue *answer = [context evaluateScript:@"target.answer()"];
        result[@"answer"] = JSONSafeJSValue(answer);
        if (!WriteCheckpoint(result, @"direct-call-complete")) {
            return 3;
        }

        JSValue *blockValue = [context evaluateScript:
            @"var blockValue = 0;"
             "target.invokeBlock(function(value) { blockValue = Number(value); });"
             "blockValue;"];
        result[@"blockCallback"] = JSONSafeJSValue(blockValue);
        if (!WriteCheckpoint(result, @"block-callback-complete")) {
            return 3;
        }

        NSNotificationCenter *center = [[notificationClass alloc] init];
        context[@"center"] = center;
        JSValue *notificationValue = [context evaluateScript:
            @"var notificationValue = 0;"
             "var notificationToken = "
             "center.addObserverForNameObjectQueueUsingBlock("
             "'CodexJSCDataProbe', null, null, function(note) {"
             "notificationValue = 91; });"
             "center.postNotificationNameObject('CodexJSCDataProbe', null);"
             "notificationValue;"];
        result[@"notificationCallback"] = JSONSafeJSValue(notificationValue);
        id token = [context[@"notificationToken"] toObject];
        if (token != nil && token != [NSNull null]) {
            [center removeObserver:token];
        }
        if (!WriteCheckpoint(result, @"notification-callback-complete")) {
            return 3;
        }

        [context evaluateScript:
            @"var adaptedNotificationValue = 0;"
             "var adaptedNotificationCallback = function(value) {"
             "adaptedNotificationValue = Number(value); };"];
        SEL adaptedSelector = NSSelectorFromString(@"codexHandleNotification:");
        NSInvocation *adaptedCallback = CreateInvocationCallback(
            "CodexNotificationInvocationCallback", adaptedSelector,
            "v24@0:8@16", context[@"adaptedNotificationCallback"], @[@91]);
        NSNotificationCenter *adaptedCenter =
            [[NSNotificationCenter alloc] init];
        if (adaptedCallback != nil) {
            [adaptedCenter addObserver:adaptedCallback
                              selector:adaptedSelector
                                  name:@"CodexJSCAdaptedNotification"
                                object:nil];
            [adaptedCenter postNotificationName:@"CodexJSCAdaptedNotification"
                                         object:nil];
            [adaptedCenter removeObserver:adaptedCallback];
        }
        JSValue *adaptedNotificationValue =
            [context evaluateScript:@"adaptedNotificationValue"];
        result[@"invocationAdapterCreated"] = @(adaptedCallback != nil);
        result[@"adaptedNotificationCallback"] =
            JSONSafeJSValue(adaptedNotificationValue);
        if (!WriteCheckpoint(result, @"adapted-notification-complete")) {
            return 3;
        }

        BOOL passed = JSValueEqualsInteger(staticAnswer, 11) &&
            targetProtocol != nil && targetClass != Nil &&
            JSValueEqualsInteger(answer, 42) &&
            adaptedCallback != nil &&
            JSValueEqualsInteger(adaptedNotificationValue, 91);
        result[@"directBlockParameterSupported"] =
            @(JSValueEqualsInteger(blockValue, 73));
        result[@"directNotificationBlockSupported"] =
            @(JSValueEqualsInteger(notificationValue, 91));
        result[@"dataRuntimePassed"] = @(passed);
        result[@"allPassed"] = @(passed);

        if (!WriteCheckpoint(result, @"finished")) {
            return 2;
        }
        NSError *jsonError = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:result
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&jsonError];
        NSMutableData *line = [json mutableCopy];
        [line appendBytes:"\n" length:1];
        (void)write(STDOUT_FILENO, line.bytes, line.length);
        return passed ? 0 : 1;
    }
}
