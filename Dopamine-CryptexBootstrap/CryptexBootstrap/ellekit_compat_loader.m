#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach/mach.h>
#import <spawn.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#import "dyld.h"
#import "rop_inject.h"

extern char **environ;
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t taskPort);

static const char *const kDefaultDylib =
    "/var/jb/usr/lib/ellekit/pspawn.dylib";
static const char *const kPtrauthChild = "--ptrauth-child";
static const char *const kInspect = "--inspect";
static const char *const kPreflight = "--preflight";

#if __arm64e__
static int wait_for_child(pid_t child) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            fprintf(stderr, "compat-loader: waitpid failed: %s\n",
                    strerror(errno));
            return 70;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "compat-loader: child terminated by signal %d\n",
                WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    return 71;
}

static int spawn_ptrauth_child(int argc, char *argv[], task_t targetTask) {
    char **childArguments = calloc((size_t)argc + 2, sizeof(char *));
    if (childArguments == NULL) {
        return 72;
    }
    for (int index = 0; index < argc; ++index) {
        childArguments[index] = argv[index];
    }
    childArguments[argc] = (char *)kPtrauthChild;

    uint32_t executablePathSize = 0;
    (void)_NSGetExecutablePath(NULL, &executablePathSize);
    char *executablePath = calloc((size_t)executablePathSize + 1, 1);
    if (executablePath == NULL ||
        _NSGetExecutablePath(executablePath, &executablePathSize) != 0) {
        free(childArguments);
        free(executablePath);
        return 73;
    }

    posix_spawnattr_t attributes;
    int result = posix_spawnattr_init(&attributes);
    bool attributesInitialized = result == 0;
    if (result == 0) {
        result =
            posix_spawnattr_set_ptrauth_task_port_np(&attributes, targetTask);
    }
    pid_t child = 0;
    if (result == 0) {
        result = posix_spawn(&child, executablePath, NULL, &attributes,
                             childArguments, environ);
    }
    if (attributesInitialized) {
        posix_spawnattr_destroy(&attributes);
    }
    free(childArguments);
    free(executablePath);
    if (result != 0) {
        fprintf(stderr, "compat-loader: ptrauth child spawn failed: %s\n",
                strerror(result));
        return 74;
    }
    return wait_for_child(child);
}
#endif

static bool image_is_loaded(task_t task, vm_address_t allImageInfo,
                            const char *path) {
    return getRemoteImageAddress(task, allImageInfo, path) != 0;
}

static kern_return_t read_remote(task_t task, mach_vm_address_t address,
                                 void *destination, mach_vm_size_t size) {
    vm_size_t copied = 0;
    kern_return_t result = vm_read_overwrite(
        task, (vm_address_t)address, (vm_size_t)size,
        (vm_address_t)destination, &copied);
    if (result == KERN_SUCCESS && copied != size) {
        return KERN_FAILURE;
    }
    return result;
}

static mach_vm_address_t canonical_remote_pointer(uint64_t pointer) {
    return (mach_vm_address_t)(pointer & 0x0000FFFFFFFFFFFFULL);
}

static int inspect_dyld_info(task_t task,
                             const task_dyld_info_data_t *taskDyldInfo) {
    struct dyld_all_image_infos imageInfos = {0};
    kern_return_t result = read_remote(
        task, taskDyldInfo->all_image_info_addr, &imageInfos,
        sizeof(imageInfos));
    printf("compat-loader: dyld format=%d address=0x%llx size=%llu "
           "read=%d (%s)\n",
           taskDyldInfo->all_image_info_format,
           taskDyldInfo->all_image_info_addr,
           taskDyldInfo->all_image_info_size, result,
           mach_error_string(result));
    if (result != KERN_SUCCESS) {
        return 76;
    }
    mach_vm_address_t infoArray = canonical_remote_pointer(
        (uint64_t)imageInfos.infoArray);
    printf("compat-loader: dyld version=%u count=%u array=0x%llx "
           "canonicalArray=0x%llx dyld=0x%llx\n",
           imageInfos.version, imageInfos.infoArrayCount,
           (uint64_t)imageInfos.infoArray,
           infoArray,
           (uint64_t)imageInfos.dyldImageLoadAddress);

    uint32_t limit = imageInfos.infoArrayCount < 16
                         ? imageInfos.infoArrayCount
                         : 16;
    for (uint32_t index = 0; index < limit; ++index) {
        struct dyld_image_info image = {0};
        mach_vm_address_t address =
            infoArray +
            index * sizeof(struct dyld_image_info);
        result = read_remote(task, address, &image, sizeof(image));
        if (result != KERN_SUCCESS) {
            printf("compat-loader: image[%u] read=%d (%s)\n", index,
                   result, mach_error_string(result));
            continue;
        }
        char path[PATH_MAX] = {0};
        vm_size_t copied = 0;
        result = vm_read_overwrite(
            task,
            (vm_address_t)canonical_remote_pointer(
                (uint64_t)image.imageFilePath),
            sizeof(path) - 1,
            (vm_address_t)path, &copied);
        if (result != KERN_SUCCESS) {
            snprintf(path, sizeof(path), "<unreadable:%d>", result);
        }
        printf("compat-loader: image[%u]=0x%llx %s\n", index,
               canonical_remote_pointer((uint64_t)image.imageLoadAddress),
               path);
    }
    return 0;
}

static int preflight_remote_symbols(task_t task, vm_address_t allImageInfo) {
    uint32_t loopInstruction = CFSwapInt32(0x00000014);
    vm_address_t ropLoop = scanLibrariesForMemory(
        task, allImageInfo, (char *)&loopInstruction,
        sizeof(loopInstruction), 4);
    vm_address_t libDyld = getRemoteImageAddress(
        task, allImageInfo, "/usr/lib/system/libdyld.dylib");
    vm_address_t libPthread = getRemoteImageAddress(
        task, allImageInfo, "/usr/lib/system/libsystem_pthread.dylib");
    vm_address_t dlopenAddress =
        libDyld != 0 ? remoteDlSym(task, libDyld, "_dlopen") : 0;
    vm_address_t pthreadSetSelf =
        libPthread != 0
            ? remoteDlSym(task, libPthread, "__pthread_set_self")
            : 0;
    printf("compat-loader: preflight ropLoop=0x%llx libdyld=0x%llx "
           "dlopen=0x%llx libpthread=0x%llx pthreadSetSelf=0x%llx\n",
           (unsigned long long)ropLoop,
           (unsigned long long)libDyld,
           (unsigned long long)dlopenAddress,
           (unsigned long long)libPthread,
           (unsigned long long)pthreadSetSelf);
    return ropLoop != 0 && libDyld != 0 && dlopenAddress != 0 &&
                   libPthread != 0 && pthreadSetSelf != 0
               ? 0
               : 77;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        setlinebuf(stdout);
        setlinebuf(stderr);

        bool isPtrauthChild =
            argc > 1 && strcmp(argv[argc - 1], kPtrauthChild) == 0;
        int userArgumentCount = argc - (isPtrauthChild ? 1 : 0);
        if (userArgumentCount < 1 || userArgumentCount > 2) {
            fprintf(stderr,
                    "usage: %s [--inspect|--preflight|absolute-dylib-path]\n",
                    argv[0]);
            return 64;
        }
        bool inspectOnly = userArgumentCount == 2 &&
                           strcmp(argv[1], kInspect) == 0;
        bool preflightOnly = userArgumentCount == 2 &&
                             strcmp(argv[1], kPreflight) == 0;
        const char *requestedPath = userArgumentCount == 2 && !inspectOnly &&
                                            !preflightOnly
                                        ? argv[1]
                                        : kDefaultDylib;
        if (!inspectOnly && !preflightOnly && requestedPath[0] != '/') {
            fprintf(stderr, "compat-loader: dylib path must be absolute\n");
            return 65;
        }
        char resolvedPath[PATH_MAX] = {0};
        if (!inspectOnly && !preflightOnly &&
            (realpath(requestedPath, resolvedPath) == NULL ||
             access(resolvedPath, R_OK) != 0)) {
            fprintf(stderr, "compat-loader: cannot read %s: %s\n",
                    requestedPath, strerror(errno));
            return 66;
        }
        if (getuid() != 0) {
            fprintf(stderr, "compat-loader: root is required\n");
            return 67;
        }

        task_t launchdTask = MACH_PORT_NULL;
        kern_return_t result =
            task_for_pid(mach_task_self(), 1, &launchdTask);
        if (result != KERN_SUCCESS || !MACH_PORT_VALID(launchdTask)) {
            fprintf(stderr,
                    "compat-loader: task_for_pid(1) failed: %s (%d)\n",
                    mach_error_string(result), result);
            return 68;
        }

#if __arm64e__
        if (!isPtrauthChild) {
            int childResult = spawn_ptrauth_child(argc, argv, launchdTask);
            mach_port_deallocate(mach_task_self(), launchdTask);
            return childResult;
        }
#endif

        task_dyld_info_data_t dyldInfo = {0};
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        result = task_info(launchdTask, TASK_DYLD_INFO,
                           (task_info_t)&dyldInfo, &count);
        if (result != KERN_SUCCESS || dyldInfo.all_image_info_addr == 0) {
            fprintf(stderr, "compat-loader: TASK_DYLD_INFO failed: %s (%d)\n",
                    mach_error_string(result), result);
            mach_port_deallocate(mach_task_self(), launchdTask);
            return 69;
        }

        if (inspectOnly) {
            int inspectResult = inspect_dyld_info(launchdTask, &dyldInfo);
            mach_port_deallocate(mach_task_self(), launchdTask);
            return inspectResult;
        }
        if (preflightOnly) {
            int preflightResult = preflight_remote_symbols(
                launchdTask, dyldInfo.all_image_info_addr);
            mach_port_deallocate(mach_task_self(), launchdTask);
            return preflightResult;
        }

        int preflightResult = preflight_remote_symbols(
            launchdTask, dyldInfo.all_image_info_addr);
        if (preflightResult != 0) {
            fprintf(stderr,
                    "compat-loader: remote-call preflight failed; refusing "
                    "injection\n");
            mach_port_deallocate(mach_task_self(), launchdTask);
            return preflightResult;
        }

        if (!image_is_loaded(launchdTask, dyldInfo.all_image_info_addr,
                             resolvedPath)) {
            printf("compat-loader: injecting %s into launchd\n", resolvedPath);
            injectDylibViaRop(launchdTask, 1, resolvedPath,
                              dyldInfo.all_image_info_addr);
            usleep(250 * 1000);
            count = TASK_DYLD_INFO_COUNT;
            result = task_info(launchdTask, TASK_DYLD_INFO,
                               (task_info_t)&dyldInfo, &count);
        }

        bool loaded = result == KERN_SUCCESS &&
                      image_is_loaded(launchdTask,
                                      dyldInfo.all_image_info_addr,
                                      resolvedPath);
        printf("compat-loader: launchd image loaded=%s path=%s\n",
               loaded ? "true" : "false", resolvedPath);
        mach_port_deallocate(mach_task_self(), launchdTask);
        return loaded ? 0 : 75;
    }
}
