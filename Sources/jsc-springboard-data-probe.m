#import <Foundation/Foundation.h>
#import <mach-o/dyld_images.h>
#import <mach/mach.h>
#import <spawn.h>

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#import "dyld.h"
#import "rop_inject.h"

extern char **environ;
extern int proc_pidpath(int pid, void *buffer, uint32_t bufferSize);
extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_write(vm_map_t target,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t taskPort);
extern void prepareForMagic(task_t task, vm_address_t allImageInfoAddress);
extern kern_return_t createRemotePthread(task_t task,
                                         vm_address_t allImageInfoAddress,
                                         thread_act_t *remotePthreadOut);
extern kern_return_t arbCall(task_t task, thread_act_t targetThread,
                             uint64_t *returnValue, bool willReturn,
                             vm_address_t function, int argumentCount, ...);

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kWorkerPath =
    "/var/jb/usr/libexec/codex-exec-worker";
static const char *const kPtrauthChild = "--ptrauth-child";
static NSString *const kResultPath =
    @"/var/mobile/Media/codex-jsc-springboard-probe.json";

static BOOL WriteResult(NSMutableDictionary *result, NSString *phase) {
    result[@"phase"] = phase;
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:result
                                                   options:NSJSONWritingPrettyPrinted
                                                     error:&error];
    if (json == nil) {
        dprintf(STDERR_FILENO, "jsc-springboard-probe JSON failed: %s\n",
                error.localizedDescription.UTF8String ?: "unknown");
        return NO;
    }
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    if (![line writeToFile:kResultPath options:NSDataWritingAtomic
                     error:&error]) {
        dprintf(STDERR_FILENO, "jsc-springboard-probe write failed: %s\n",
                error.localizedDescription.UTF8String ?: "unknown");
        return NO;
    }
    return YES;
}

static bool ReadExactSpringBoard(pid_t pid) {
    char path[PATH_MAX] = {0};
    return pid > 1 && proc_pidpath(pid, path, sizeof(path)) > 0 &&
        strcmp(path, kSpringBoardPath) == 0 &&
        strcmp(path, "/sbin/launchd") != 0 &&
        strcmp(path, "/usr/libexec/launchd") != 0;
}

static int WaitForChild(pid_t child) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return 70;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 71;
}

#if __arm64e__
static int SpawnPtrauthWorker(int argc, char *argv[], task_t targetTask) {
    char **childArguments = calloc((size_t)argc + 4U, sizeof(char *));
    if (childArguments == NULL) {
        return 72;
    }
    childArguments[0] = (char *)kWorkerPath;
    childArguments[1] = "--macho";
    for (int index = 0; index < argc; ++index) {
        childArguments[index + 2] = argv[index];
    }
    childArguments[argc + 2] = (char *)kPtrauthChild;

    posix_spawnattr_t attributes;
    int result = posix_spawnattr_init(&attributes);
    bool initialized = result == 0;
    if (result == 0) {
        result = posix_spawnattr_set_ptrauth_task_port_np(&attributes,
                                                          targetTask);
    }
    pid_t child = 0;
    if (result == 0) {
        result = posix_spawn(&child, kWorkerPath, NULL, &attributes,
                             childArguments, environ);
    }
    if (initialized) {
        posix_spawnattr_destroy(&attributes);
    }
    free(childArguments);
    if (result != 0 || child <= 1) {
        dprintf(STDERR_FILENO,
                "jsc-springboard-probe ptrauth worker failed: %d\n",
                result);
        return 73;
    }
    return WaitForChild(child);
}
#endif

static kern_return_t RemoteCall(task_t task, thread_act_t thread,
                                uint64_t *returnValue,
                                vm_address_t function,
                                size_t argumentCount,
                                const uint64_t arguments[6]) {
    switch (argumentCount) {
        case 0:
            return arbCall(task, thread, returnValue, true, function, 0);
        case 1:
            return arbCall(task, thread, returnValue, true, function, 1,
                           arguments[0]);
        case 2:
            return arbCall(task, thread, returnValue, true, function, 2,
                           arguments[0], arguments[1]);
        case 3:
            return arbCall(task, thread, returnValue, true, function, 3,
                           arguments[0], arguments[1], arguments[2]);
        case 4:
            return arbCall(task, thread, returnValue, true, function, 4,
                           arguments[0], arguments[1], arguments[2],
                           arguments[3]);
        case 5:
            return arbCall(task, thread, returnValue, true, function, 5,
                           arguments[0], arguments[1], arguments[2],
                           arguments[3], arguments[4]);
        case 6:
            return arbCall(task, thread, returnValue, true, function, 6,
                           arguments[0], arguments[1], arguments[2],
                           arguments[3], arguments[4], arguments[5]);
        default:
            return KERN_INVALID_ARGUMENT;
    }
}

static mach_vm_address_t WriteRemoteCString(task_t task, const char *string) {
    size_t size = strlen(string) + 1U;
    mach_vm_address_t address = 0;
    kern_return_t result = mach_vm_allocate(task, &address, size,
                                             VM_FLAGS_ANYWHERE);
    if (result != KERN_SUCCESS) {
        return 0;
    }
    result = mach_vm_write(task, address,
                           (vm_offset_t)(uintptr_t)string,
                           (mach_msg_type_number_t)size);
    if (result != KERN_SUCCESS) {
        mach_vm_deallocate(task, address, size);
        return 0;
    }
    return address;
}

static vm_address_t ResolveSymbol(task_t task, vm_address_t allImageInfo,
                                  const char *symbol) {
    return remoteDlSymFindImage(task, allImageInfo, symbol, NULL);
}

static int RunRemoteJSCProbe(task_t task, pid_t pid,
                             vm_address_t allImageInfo,
                             NSMutableDictionary *result) {
    int status = 80;
    thread_act_t remoteThread = MACH_PORT_NULL;
    mach_vm_address_t frameworkPath = 0;
    mach_vm_address_t jsContextName = 0;
    mach_vm_address_t nsStringName = 0;
    mach_vm_address_t allocName = 0;
    mach_vm_address_t initName = 0;
    mach_vm_address_t stringName = 0;
    mach_vm_address_t evaluateName = 0;
    mach_vm_address_t toInt32Name = 0;
    mach_vm_address_t scriptText = 0;

    vm_address_t libDyld = getRemoteImageAddress(
        task, allImageInfo, "/usr/lib/system/libdyld.dylib");
    vm_address_t dlopenAddress =
        libDyld != 0 ? remoteDlSym(task, libDyld, "_dlopen") : 0;
    result[@"libdyld"] = @((uint64_t)libDyld);
    result[@"dlopen"] = @((uint64_t)dlopenAddress);
    if (dlopenAddress == 0) {
        return 81;
    }

    prepareForMagic(task, allImageInfo);
    kern_return_t threadResult =
        createRemotePthread(task, allImageInfo, &remoteThread);
    result[@"remoteThreadResult"] = @(threadResult);
    result[@"remoteThread"] = @((uint32_t)remoteThread);
    if (threadResult != KERN_SUCCESS || !MACH_PORT_VALID(remoteThread)) {
        return 82;
    }

    frameworkPath = WriteRemoteCString(
        task,
        "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore");
    uint64_t callArguments[6] = {frameworkPath, RTLD_NOW | RTLD_LOCAL};
    uint64_t frameworkHandle = 0;
    kern_return_t callResult = frameworkPath != 0
        ? RemoteCall(task, remoteThread, &frameworkHandle, dlopenAddress, 2,
                     callArguments)
        : KERN_INVALID_ADDRESS;
    result[@"dlopenCallResult"] = @(callResult);
    result[@"frameworkHandle"] = @(frameworkHandle);
    if (callResult != KERN_SUCCESS || frameworkHandle == 0 ||
        !ReadExactSpringBoard(pid)) {
        status = 83;
        goto finished;
    }

    vm_address_t objcGetClass = ResolveSymbol(
        task, allImageInfo, "_objc_getClass");
    vm_address_t selRegisterName = ResolveSymbol(
        task, allImageInfo, "_sel_registerName");
    vm_address_t objcMsgSend = ResolveSymbol(
        task, allImageInfo, "_objc_msgSend");
    result[@"objcGetClass"] = @((uint64_t)objcGetClass);
    result[@"selRegisterName"] = @((uint64_t)selRegisterName);
    result[@"objcMsgSend"] = @((uint64_t)objcMsgSend);
    if (objcGetClass == 0 || selRegisterName == 0 || objcMsgSend == 0) {
        status = 84;
        goto finished;
    }

    jsContextName = WriteRemoteCString(task, "JSContext");
    nsStringName = WriteRemoteCString(task, "NSString");
    allocName = WriteRemoteCString(task, "alloc");
    initName = WriteRemoteCString(task, "init");
    stringName = WriteRemoteCString(task, "stringWithUTF8String:");
    evaluateName = WriteRemoteCString(task, "evaluateScript:");
    toInt32Name = WriteRemoteCString(task, "toInt32");
    scriptText = WriteRemoteCString(task, "40 + 2");
    if (jsContextName == 0 || nsStringName == 0 || allocName == 0 ||
        initName == 0 || stringName == 0 || evaluateName == 0 ||
        toInt32Name == 0 || scriptText == 0) {
        status = 85;
        goto finished;
    }

    uint64_t jsContextClass = 0;
    callArguments[0] = jsContextName;
    callResult = RemoteCall(task, remoteThread, &jsContextClass,
                            objcGetClass, 1, callArguments);
    uint64_t nsStringClass = 0;
    callArguments[0] = nsStringName;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &nsStringClass, objcGetClass, 1,
                     callArguments)
        : callResult;

    uint64_t allocSelector = 0;
    callArguments[0] = allocName;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &allocSelector, selRegisterName, 1,
                     callArguments)
        : callResult;
    uint64_t initSelector = 0;
    callArguments[0] = initName;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &initSelector, selRegisterName, 1,
                     callArguments)
        : callResult;
    uint64_t stringSelector = 0;
    callArguments[0] = stringName;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &stringSelector, selRegisterName, 1,
                     callArguments)
        : callResult;
    uint64_t evaluateSelector = 0;
    callArguments[0] = evaluateName;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &evaluateSelector, selRegisterName, 1,
                     callArguments)
        : callResult;
    uint64_t toInt32Selector = 0;
    callArguments[0] = toInt32Name;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &toInt32Selector, selRegisterName, 1,
                     callArguments)
        : callResult;
    if (callResult != KERN_SUCCESS || jsContextClass == 0 ||
        nsStringClass == 0 || allocSelector == 0 || initSelector == 0 ||
        stringSelector == 0 || evaluateSelector == 0 ||
        toInt32Selector == 0) {
        status = 86;
        goto finished;
    }

    uint64_t contextAllocation = 0;
    callArguments[0] = jsContextClass;
    callArguments[1] = allocSelector;
    callResult = RemoteCall(task, remoteThread, &contextAllocation,
                            objcMsgSend, 2, callArguments);
    uint64_t context = 0;
    callArguments[0] = contextAllocation;
    callArguments[1] = initSelector;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &context, objcMsgSend, 2,
                     callArguments)
        : callResult;
    uint64_t script = 0;
    callArguments[0] = nsStringClass;
    callArguments[1] = stringSelector;
    callArguments[2] = scriptText;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &script, objcMsgSend, 3,
                     callArguments)
        : callResult;
    uint64_t value = 0;
    callArguments[0] = context;
    callArguments[1] = evaluateSelector;
    callArguments[2] = script;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &value, objcMsgSend, 3,
                     callArguments)
        : callResult;
    uint64_t integer = 0;
    callArguments[0] = value;
    callArguments[1] = toInt32Selector;
    callResult = callResult == KERN_SUCCESS
        ? RemoteCall(task, remoteThread, &integer, objcMsgSend, 2,
                     callArguments)
        : callResult;
    result[@"objcCallResult"] = @(callResult);
    result[@"context"] = @(context);
    result[@"scriptValue"] = @(value);
    result[@"integer"] = @(integer);
    status = callResult == KERN_SUCCESS && integer == 42 &&
            ReadExactSpringBoard(pid)
        ? 0 : 87;

finished:
    if (MACH_PORT_VALID(remoteThread)) {
        (void)thread_terminate(remoteThread);
        (void)mach_port_deallocate(mach_task_self(), remoteThread);
    }
    mach_vm_address_t allocations[] = {
        frameworkPath, jsContextName, nsStringName, allocName, initName,
        stringName, evaluateName, toInt32Name, scriptText,
    };
    for (size_t index = 0;
         index < sizeof(allocations) / sizeof(allocations[0]); ++index) {
        if (allocations[index] != 0) {
            (void)mach_vm_deallocate(task, allocations[index], 1);
        }
    }
    return status;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        setlinebuf(stdout);
        setlinebuf(stderr);
        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        result[@"pid"] = @(getpid());
        result[@"architecture"] =
#if __arm64e__
            @"arm64e";
#else
            @"arm64";
#endif

        bool isPtrauthChild =
            argc == 3 && strcmp(argv[2], kPtrauthChild) == 0;
        if ((argc != 2 && !isPtrauthChild) || argv[1] == NULL) {
            result[@"status"] = @64;
            (void)WriteResult(result, @"bad-arguments");
            return 64;
        }
        char *end = NULL;
        errno = 0;
        long parsed = strtol(argv[1], &end, 10);
        if (errno != 0 || end == argv[1] || *end != '\0' || parsed <= 1 ||
            parsed > INT_MAX || !ReadExactSpringBoard((pid_t)parsed)) {
            result[@"status"] = @65;
            (void)WriteResult(result, @"target-rejected");
            return 65;
        }
        pid_t target = (pid_t)parsed;
        result[@"target"] = @(target);
        result[@"ptrauthChild"] = @(isPtrauthChild);
        (void)WriteResult(result, @"target-validated");

        task_t targetTask = MACH_PORT_NULL;
        kern_return_t taskResult =
            task_for_pid(mach_task_self(), target, &targetTask);
        result[@"taskResult"] = @(taskResult);
        result[@"task"] = @((uint32_t)targetTask);
        if (taskResult != KERN_SUCCESS || !MACH_PORT_VALID(targetTask)) {
            result[@"status"] = @66;
            (void)WriteResult(result, @"task-port-failed");
            return 66;
        }

#if __arm64e__
        if (!isPtrauthChild) {
            (void)WriteResult(result, @"spawning-ptrauth-worker");
            int childStatus = SpawnPtrauthWorker(argc, argv, targetTask);
            (void)mach_port_deallocate(mach_task_self(), targetTask);
            dprintf(childStatus == 0 ? STDOUT_FILENO : STDERR_FILENO,
                    "jsc-springboard-probe ptrauth child status=%d\n",
                    childStatus);
            return childStatus;
        }
#endif

        task_dyld_info_data_t dyldInfo = {0};
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        kern_return_t infoResult = task_info(
            targetTask, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
        result[@"taskInfoResult"] = @(infoResult);
        result[@"allImageInfo"] = @(dyldInfo.all_image_info_addr);
        if (infoResult != KERN_SUCCESS ||
            dyldInfo.all_image_info_addr == 0) {
            (void)mach_port_deallocate(mach_task_self(), targetTask);
            result[@"status"] = @67;
            (void)WriteResult(result, @"dyld-info-failed");
            return 67;
        }

        (void)WriteResult(result, @"remote-jsc-starting");
        int status = RunRemoteJSCProbe(
            targetTask, target, dyldInfo.all_image_info_addr, result);
        (void)mach_port_deallocate(mach_task_self(), targetTask);
        result[@"status"] = @(status);
        result[@"passed"] = @(status == 0);
        (void)WriteResult(result, @"finished");
        return status;
    }
}
