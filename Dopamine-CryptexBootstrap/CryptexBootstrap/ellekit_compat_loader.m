#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/loader.h>
#import <mach/arm/thread_status.h>
#import <mach/exception_types.h>
#import <mach/mach.h>
#import <os/log.h>
#import <spawn.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#import "dyld.h"
#import "ring-exc-server.h"
#import "rop_inject.h"
#import "SBInject/sbinject_protocol.h"

extern char **environ;
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t taskPort);

static const char *const kDefaultDylib =
    "/var/jb/usr/lib/ellekit/libinjector.dylib";
static const char *const kShadowCore =
    "/var/jb/usr/lib/ShadowCore.dylib";
static const char *const kSBInjectLaunchdHook =
    "/var/jb/usr/lib/sbinject/launchdhook-v42.dylib";
static const char *const kSBInjectLsdRegistrationHook =
    "/var/jb/usr/lib/sbinject/lsd-registration-hook.dylib";
static const char *const kSBInjectAmfidHook =
    "/var/jb/usr/libexec/sbinject/a";
static const char *const kStockAmfid = "/usr/libexec/amfid";
static const char *const kPtrauthChild = "--ptrauth-child";
static const char *const kInspectPid = "--inspect-pid";
static const char *const kPreflightPid = "--preflight-pid";
static const char *const kCheckPidImage = "--check-pid-image";
static const char *const kInjectPid = "--inject-pid";
static const char *const kInjectAndResumePid = "--inject-and-resume-pid";
static const char *const kInjectEnabledShadowAndResumePid =
    "--inject-enabled-shadow-and-resume-pid";
static const char *const kPatchNavyAndResumePid =
    "--patch-navy-and-resume-pid";
static const char *const kProtectRingAndResumePid =
    "--protect-ring-and-resume-pid";
static const char *const kPrepareEnabledShadowPath =
    "--prepare-enabled-shadow-path";
static const char *const kInjectLaunchdHook = "--inject-launchd-hook";

#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
#define CODEX_PT_CONTINUE 7
#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_OPS_CDHASH 5
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_PROC_PIDTBSDINFO 3
#define CODEX_MAXCOMLEN 16
#define CODEX_WAIT_ATTEMPTS 500U
#define CODEX_WAIT_DELAY_USEC (10U * 1000U)
#define CODEX_RUNTIME_READY_ATTEMPTS 2000U
#define CODEX_RUNTIME_READY_DELAY_USEC 1000U
#define CODEX_IMAGE_READY_ATTEMPTS 40U
#define CODEX_IMAGE_READY_DELAY_USEC 1000U
#define CODEX_SHADOW_MANAGED_VERSION 5

static const char *const kSpringBoardCandidatePath =
    "/var/jb/System/Library/CoreServices/SpringBoard.app/notSpringBoard";

struct codex_proc_bsdinfo {
    uint32_t pbi_flags;
    uint32_t pbi_status;
    uint32_t pbi_xstatus;
    uint32_t pbi_pid;
    uint32_t pbi_ppid;
    uid_t pbi_uid;
    gid_t pbi_gid;
    uid_t pbi_ruid;
    gid_t pbi_rgid;
    uid_t pbi_svuid;
    gid_t pbi_svgid;
    uint32_t reserved;
    char pbi_comm[CODEX_MAXCOMLEN];
    char pbi_name[2 * CODEX_MAXCOMLEN];
    uint32_t pbi_nfiles;
    uint32_t pbi_pgid;
    uint32_t pbi_pjobc;
    uint32_t e_tdev;
    uint32_t e_tpgid;
    int32_t pbi_nice;
    uint64_t pbi_start_tvsec;
    uint64_t pbi_start_tvusec;
};

_Static_assert(sizeof(struct codex_proc_bsdinfo) == 136,
               "proc_bsdinfo ABI mismatch");

extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t bufferSize);
extern void prepareForMagic(task_t task, vm_address_t allImageInfoAddress);
extern bool codexPrewarmInjectionPrimitives(
    task_t task, vm_address_t allImageInfoAddress);
extern bool codexValidateInjectionPrimitives(
    task_t task, vm_address_t allImageInfoAddress);
extern kern_return_t createRemotePthread(task_t task,
                                         vm_address_t allImageInfoAddress,
                                         thread_act_t *remotePthreadOut);
extern kern_return_t arbCall(task_t task, thread_act_t targetThread,
                             uint64_t *returnValue, bool willReturn,
                             vm_address_t function, int argumentCount, ...);

static void unified_loader_log(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    char *message = NULL;
    int length = vasprintf(&message, format, arguments);
    va_end(arguments);
    if (length < 0 || message == NULL) {
        return;
    }
    os_log_t log = os_log_create("com.openai.codex.dopamine.bootstrap",
                                 "ellekit-loader");
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT, "%{public}s", message);
    int descriptor = open(CODEX_SBINJECT_LOG,
                          O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor >= 0) {
        struct stat status = {0};
        struct timespec timestamp = {0};
        if (fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) &&
            clock_gettime(CLOCK_REALTIME, &timestamp) == 0) {
            char *line = NULL;
            int lineLength = asprintf(
                &line, "%lld.%06ld ellekit-loader[%d] %s\n",
                (long long)timestamp.tv_sec,
                timestamp.tv_nsec / 1000L, getpid(), message);
            if (lineLength > 0 && line != NULL) {
                (void)write(descriptor, line, (size_t)lineLength);
            }
            free(line);
        }
        close(descriptor);
    }
    free(message);
}

struct suspended_thread_set {
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    mach_msg_type_number_t suspended;
};

static void release_suspended_threads(struct suspended_thread_set *set) {
    if (set == NULL || set->threads == NULL) return;
    for (mach_msg_type_number_t index = 0; index < set->suspended; ++index) {
        (void)thread_resume(set->threads[index]);
    }
    for (mach_msg_type_number_t index = 0; index < set->count; ++index) {
        mach_port_deallocate(mach_task_self(), set->threads[index]);
    }
    (void)vm_deallocate(mach_task_self(), (vm_address_t)set->threads,
                        (vm_size_t)(set->count * sizeof(thread_act_t)));
    memset(set, 0, sizeof(*set));
}

static bool suspend_existing_threads(task_t task,
                                     struct suspended_thread_set *set) {
    if (set == NULL) return false;
    memset(set, 0, sizeof(*set));
    kern_return_t result = task_threads(task, &set->threads, &set->count);
    if (result != KERN_SUCCESS || set->threads == NULL || set->count == 0) {
        release_suspended_threads(set);
        return false;
    }
    for (; set->suspended < set->count; ++set->suspended) {
        result = thread_suspend(set->threads[set->suspended]);
        if (result != KERN_SUCCESS) {
            release_suspended_threads(set);
            return false;
        }
    }
    return true;
}

static bool suspend_existing_threads_stable(
    task_t task, struct suspended_thread_set *set) {
    for (unsigned int attempt = 0; attempt < 50U; ++attempt) {
        if (suspend_existing_threads(task, set)) return true;
        usleep(100U);
    }
    return false;
}

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

static bool app_store_main_executable(NSString *requested,
                                      NSString **resolvedOut,
                                      NSString **bundleOut,
                                      NSString **containerOut,
                                      NSString **identifierOut,
                                      struct stat *statusOut);

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

static bool local_macho_has_uuid(NSString *path,
                                 const uint8_t expected[16],
                                 uint32_t expectedFiletype) {
    if (path.length == 0) return false;
    int descriptor = open(path.fileSystemRepresentation,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return false;
    struct stat status = {0};
    struct mach_header_64 header = {0};
    bool valid = fstat(descriptor, &status) == 0 &&
        S_ISREG(status.st_mode) && status.st_nlink == 1 &&
        pread(descriptor, &header, sizeof(header), 0) == sizeof(header) &&
        header.magic == MH_MAGIC_64 && header.filetype == expectedFiletype &&
        header.ncmds > 0 && header.ncmds <= 4096U &&
        header.sizeofcmds > 0 && header.sizeofcmds <= 4U * 1024U * 1024U &&
        (uint64_t)sizeof(header) + header.sizeofcmds <=
            (uint64_t)status.st_size;
    uint8_t *commands = valid ? malloc(header.sizeofcmds) : NULL;
    valid = valid && commands != NULL &&
        pread(descriptor, commands, header.sizeofcmds, sizeof(header)) ==
            (ssize_t)header.sizeofcmds;
    bool matched = false;
    if (valid) {
        size_t offset = 0;
        for (uint32_t index = 0; index < header.ncmds; ++index) {
            if (offset + sizeof(struct load_command) > header.sizeofcmds) break;
            struct load_command *command =
                (struct load_command *)(commands + offset);
            if (command->cmdsize < sizeof(*command) ||
                offset + command->cmdsize > header.sizeofcmds) {
                break;
            }
            if (command->cmd == LC_UUID &&
                command->cmdsize >= sizeof(struct uuid_command)) {
                struct uuid_command *uuid = (struct uuid_command *)command;
                matched = memcmp(uuid->uuid, expected, 16) == 0;
                break;
            }
            offset += command->cmdsize;
        }
    }
    free(commands);
    close(descriptor);
    return matched;
}

static bool remote_macho_has_uuid_type(task_t task,
                                       mach_vm_address_t address,
                                       const uint8_t expected[16],
                                       uint32_t expectedFiletype) {
    struct mach_header_64 header = {0};
    if (read_remote(task, address, &header, sizeof(header)) != KERN_SUCCESS ||
        header.magic != MH_MAGIC_64 || header.filetype != expectedFiletype ||
        header.ncmds == 0 || header.ncmds > 4096U ||
        header.sizeofcmds == 0 || header.sizeofcmds > 4U * 1024U * 1024U) {
        return false;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL) return false;
    bool matched = false;
    if (read_remote(task, address + sizeof(header), commands,
                    header.sizeofcmds) == KERN_SUCCESS) {
        size_t offset = 0;
        for (uint32_t index = 0; index < header.ncmds; ++index) {
            if (offset + sizeof(struct load_command) > header.sizeofcmds) break;
            struct load_command *command =
                (struct load_command *)(commands + offset);
            if (command->cmdsize < sizeof(*command) ||
                offset + command->cmdsize > header.sizeofcmds) {
                break;
            }
            if (command->cmd == LC_UUID &&
                command->cmdsize >= sizeof(struct uuid_command)) {
                struct uuid_command *uuid = (struct uuid_command *)command;
                matched = memcmp(uuid->uuid, expected, 16) == 0;
                break;
            }
            offset += command->cmdsize;
        }
    }
    free(commands);
    return matched;
}

static bool find_remote_macho_with_uuid_type(task_t task,
                                             const uint8_t expected[16],
                                             uint32_t expectedFiletype,
                                             mach_vm_address_t *addressOut) {
    if (addressOut != NULL) *addressOut = 0;
    mach_vm_address_t address = 0;
    natural_t depth = 0;
    for (unsigned int attempt = 0; attempt < 8192U; ++attempt) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        vm_address_t regionAddress = (vm_address_t)address;
        vm_size_t regionSize = (vm_size_t)size;
        kern_return_t result = vm_region_recurse_64(
            task, &regionAddress, &regionSize, &depth,
            (vm_region_recurse_info_t)&info, &count);
        address = (mach_vm_address_t)regionAddress;
        size = (mach_vm_size_t)regionSize;
        if (result != KERN_SUCCESS || size == 0) break;
        if (info.is_submap) {
            ++depth;
            continue;
        }
        if ((info.protection & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
                (VM_PROT_READ | VM_PROT_EXECUTE) &&
            remote_macho_has_uuid_type(task, address, expected,
                                       expectedFiletype)) {
            if (addressOut != NULL) *addressOut = address;
            return true;
        }
        if (address > UINT64_MAX - size) break;
        address += size;
    }
    return false;
}

static bool find_remote_macho_with_uuid(task_t task,
                                        const uint8_t expected[16],
                                        mach_vm_address_t *addressOut) {
    return find_remote_macho_with_uuid_type(task, expected, MH_EXECUTE,
                                            addressOut);
}

static vm_address_t write_remote_cstring(task_t task, const char *value,
                                         vm_size_t *sizeOut) {
    if (sizeOut != NULL) *sizeOut = 0;
    if (value == NULL) return 0;
    size_t length = strlen(value) + 1U;
    if (length > UINT32_MAX) return 0;
    vm_address_t address = 0;
    kern_return_t result = vm_allocate(task, &address, (vm_size_t)length,
                                       VM_FLAGS_ANYWHERE);
    if (result != KERN_SUCCESS) return 0;
    result = vm_write(task, address, (vm_offset_t)value,
                      (mach_msg_type_number_t)length);
    if (result != KERN_SUCCESS) {
        (void)vm_deallocate(task, address, (vm_size_t)length);
        return 0;
    }
    if (sizeOut != NULL) *sizeOut = (vm_size_t)length;
    return address;
}

static mach_vm_address_t canonical_remote_pointer(uint64_t pointer);

struct remote_objc_symbols {
    vm_address_t getClass;
    vm_address_t registerSelector;
    vm_address_t getClassMethod;
    vm_address_t getInstanceMethod;
    vm_address_t getImplementation;
    vm_address_t setImplementation;
};

static bool resolve_remote_objc_symbols(
    task_t task, vm_address_t allImageInfo,
    struct remote_objc_symbols *symbols) {
    if (symbols == NULL) return false;
    memset(symbols, 0, sizeof(*symbols));
    vm_address_t libobjc = getRemoteImageAddress(
        task, allImageInfo, "/usr/lib/libobjc.A.dylib");
    if (libobjc == 0) return false;
    symbols->getClass = remoteDlSym(task, libobjc, "_objc_getClass");
    symbols->registerSelector =
        remoteDlSym(task, libobjc, "_sel_registerName");
    symbols->getClassMethod =
        remoteDlSym(task, libobjc, "_class_getClassMethod");
    symbols->getInstanceMethod =
        remoteDlSym(task, libobjc, "_class_getInstanceMethod");
    symbols->getImplementation =
        remoteDlSym(task, libobjc, "_method_getImplementation");
    symbols->setImplementation =
        remoteDlSym(task, libobjc, "_method_setImplementation");
    return symbols->getClass != 0 && symbols->registerSelector != 0 &&
           symbols->getClassMethod != 0 &&
           symbols->getInstanceMethod != 0 &&
           symbols->getImplementation != 0 &&
           symbols->setImplementation != 0;
}

static bool remote_call(task_t task, thread_act_t thread,
                        vm_address_t function, uint64_t *resultOut,
                        int argumentCount, ...) {
    uint64_t arguments[8] = {0};
    if (argumentCount < 0 || argumentCount > 8) return false;
    va_list list;
    va_start(list, argumentCount);
    for (int index = 0; index < argumentCount; ++index) {
        arguments[index] = va_arg(list, uint64_t);
    }
    va_end(list);
    kern_return_t result = KERN_INVALID_ARGUMENT;
    switch (argumentCount) {
        case 0:
            result = arbCall(task, thread, resultOut, true, function, 0);
            break;
        case 1:
            result = arbCall(task, thread, resultOut, true, function, 1,
                             arguments[0]);
            break;
        case 2:
            result = arbCall(task, thread, resultOut, true, function, 2,
                             arguments[0], arguments[1]);
            break;
        default:
            return false;
    }
    return result == KERN_SUCCESS;
}

static bool remote_objc_class(task_t task, thread_act_t thread,
                              const struct remote_objc_symbols *symbols,
                              vm_address_t name, uint64_t *classOut) {
    uint64_t value = 0;
    bool success = remote_call(task, thread, symbols->getClass, &value, 1,
                               (uint64_t)name);
    if (classOut != NULL) *classOut = value;
    return success;
}

static bool remote_objc_selector(task_t task, thread_act_t thread,
                                 const struct remote_objc_symbols *symbols,
                                 vm_address_t name, uint64_t *selectorOut) {
    uint64_t value = 0;
    bool success = remote_call(task, thread, symbols->registerSelector,
                               &value, 1, (uint64_t)name) && value != 0;
    if (selectorOut != NULL) *selectorOut = value;
    return success;
}

static bool remote_objc_method(task_t task, thread_act_t thread,
                               vm_address_t function, uint64_t cls,
                               uint64_t selector, uint64_t *methodOut) {
    uint64_t value = 0;
    bool success = remote_call(task, thread, function, &value, 2, cls,
                               selector) && value != 0;
    if (methodOut != NULL) *methodOut = value;
    return success;
}

static int replace_navy_detector_methods(task_t task,
                                         vm_address_t allImageInfo,
                                         const char *targetPath) {
    NSString *requested = targetPath != NULL
        ? [NSString stringWithUTF8String:targetPath] : nil;
    NSString *resolved = nil;
    NSString *bundle = nil;
    NSString *container = nil;
    NSString *identifier = nil;
    struct stat status = {0};
    if (!app_store_main_executable(requested, &resolved, &bundle, &container,
                                   &identifier, &status) ||
        ![identifier isEqualToString:@"org.navyfederal.nfcuforiphone"]) {
        return 78;
    }
    static const uint8_t expectedUUID[16] = {
        0x22, 0xe7, 0x0c, 0x5a, 0x50, 0x71, 0x34, 0xf4,
        0xb4, 0x68, 0xe8, 0x78, 0x74, 0xf6, 0x02, 0x31,
    };
    mach_vm_address_t image = 0;
    if (!find_remote_macho_with_uuid(task, expectedUUID, &image)) {
        unified_loader_log(
            "navyRuntimePolicy identifier=%s matched=false",
            identifier.UTF8String);
        return 83;
    }

    struct remote_objc_symbols symbols = {0};
    if (!resolve_remote_objc_symbols(task, allImageInfo, &symbols)) {
        unified_loader_log(
            "navyRuntimePolicy identifier=%s image=0x%llx "
            "objcSymbols=false complete=false",
            identifier.UTF8String, image);
        return 84;
    }

    static const char *const strings[] = {
        "Backbase",
        "_TtC6FRCore19FRJailbreakDetector",
        "APMPNullValue",
        "isDeviceJailbroken",
        "analyze",
        "booleanValueOrError:",
        "doubleValueOrError:",
    };
    vm_address_t remoteStrings[sizeof(strings) / sizeof(strings[0])] = {0};
    vm_size_t remoteStringSizes[sizeof(strings) / sizeof(strings[0])] = {0};
    bool allocated = true;
    for (size_t index = 0; index < sizeof(strings) / sizeof(strings[0]);
         ++index) {
        remoteStrings[index] = write_remote_cstring(
            task, strings[index], &remoteStringSizes[index]);
        allocated = allocated && remoteStrings[index] != 0;
    }

    thread_act_t remoteThread = MACH_PORT_NULL;
    kern_return_t threadResult = allocated
        ? createRemotePthread(task, allImageInfo, &remoteThread)
        : KERN_RESOURCE_SHORTAGE;
    bool complete = threadResult == KERN_SUCCESS &&
                    MACH_PORT_VALID(remoteThread);
    uint64_t backbaseClass = 0;
    uint64_t detectorClass = 0;
    uint64_t zeroClass = 0;
    uint64_t backbaseSelector = 0;
    uint64_t detectorSelector = 0;
    uint64_t falseSelector = 0;
    uint64_t zeroSelector = 0;
    bool classCallsComplete = false;
    bool classesReady = false;
    if (complete) {
        bool backbaseCall = remote_objc_class(
            task, remoteThread, &symbols, remoteStrings[0], &backbaseClass);
        bool detectorCall = remote_objc_class(
            task, remoteThread, &symbols, remoteStrings[1], &detectorClass);
        bool zeroCall = remote_objc_class(
            task, remoteThread, &symbols, remoteStrings[2], &zeroClass);
        classCallsComplete = backbaseCall && detectorCall && zeroCall;
        classesReady = classCallsComplete && backbaseClass != 0 &&
                       detectorClass != 0 && zeroClass != 0;
        complete = classesReady &&
            remote_objc_selector(task, remoteThread, &symbols,
                                 remoteStrings[3], &backbaseSelector) &&
            remote_objc_selector(task, remoteThread, &symbols,
                                 remoteStrings[4], &detectorSelector) &&
            remote_objc_selector(task, remoteThread, &symbols,
                                 remoteStrings[5], &falseSelector) &&
            remote_objc_selector(task, remoteThread, &symbols,
                                 remoteStrings[6], &zeroSelector);
    }

    uint64_t backbaseMethod = 0;
    uint64_t detectorMethod = 0;
    uint64_t falseMethod = 0;
    uint64_t zeroMethod = 0;
    if (complete) {
        complete =
            remote_objc_method(task, remoteThread, symbols.getClassMethod,
                               backbaseClass, backbaseSelector,
                               &backbaseMethod) &&
            remote_objc_method(task, remoteThread,
                               symbols.getInstanceMethod, detectorClass,
                               detectorSelector, &detectorMethod) &&
            remote_objc_method(task, remoteThread,
                               symbols.getInstanceMethod, zeroClass,
                               falseSelector, &falseMethod) &&
            remote_objc_method(task, remoteThread,
                               symbols.getInstanceMethod, zeroClass,
                               zeroSelector, &zeroMethod);
    }

    uint64_t falseImplementation = 0;
    uint64_t zeroImplementation = 0;
    if (complete) {
        complete =
            remote_call(task, remoteThread, symbols.getImplementation,
                        &falseImplementation, 1, falseMethod) &&
            falseImplementation != 0 &&
            remote_call(task, remoteThread, symbols.getImplementation,
                        &zeroImplementation, 1, zeroMethod) &&
            zeroImplementation != 0;
    }

    uint64_t ignored = 0;
    uint64_t installedFalse = 0;
    uint64_t installedZero = 0;
    if (complete) {
        complete =
            remote_call(task, remoteThread, symbols.setImplementation,
                        &ignored, 2, backbaseMethod,
                        falseImplementation) &&
            remote_call(task, remoteThread, symbols.setImplementation,
                        &ignored, 2, detectorMethod,
                        zeroImplementation) &&
            remote_call(task, remoteThread, symbols.getImplementation,
                        &installedFalse, 1, backbaseMethod) &&
            remote_call(task, remoteThread, symbols.getImplementation,
                        &installedZero, 1, detectorMethod) &&
            canonical_remote_pointer(installedFalse) ==
                canonical_remote_pointer(falseImplementation) &&
            canonical_remote_pointer(installedZero) ==
                canonical_remote_pointer(zeroImplementation);
    }

    if (MACH_PORT_VALID(remoteThread)) {
        (void)thread_terminate(remoteThread);
        mach_port_deallocate(mach_task_self(), remoteThread);
    }
    for (size_t index = 0; index < sizeof(strings) / sizeof(strings[0]);
         ++index) {
        if (remoteStrings[index] != 0 && remoteStringSizes[index] != 0) {
            (void)vm_deallocate(task, remoteStrings[index],
                                remoteStringSizes[index]);
        }
    }
    unified_loader_log(
        "navyRuntimePolicy identifier=%s image=0x%llx uuidMatch=true "
        "thread=%d backbase=%s detector=%s zeroSource=%s methods=%s "
        "falseImp=0x%llx zeroImp=0x%llx complete=%s",
        identifier.UTF8String, image, threadResult,
        backbaseClass != 0 ? "true" : "false",
        detectorClass != 0 ? "true" : "false",
        zeroClass != 0 ? "true" : "false",
        backbaseMethod != 0 && detectorMethod != 0 && falseMethod != 0 &&
                zeroMethod != 0
            ? "true" : "false",
        falseImplementation, zeroImplementation,
        complete ? "true" : "false");
    if (complete) return 0;
    return threadResult == KERN_SUCCESS && classCallsComplete && !classesReady
        ? 85 : 84;
}

struct ring_exception_context {
    task_t task;
    pid_t pid;
    mach_port_t exceptionPort;
    bool active;
    bool recovered;
    mach_vm_address_t iloqImage;
    uint64_t pc;
    uint64_t lr;
    uint64_t x0;
    uint64_t x1;
    uint32_t code0;
    uint32_t code1;
    int recoveryMode;
};

static struct ring_exception_context gRingExceptionContext = {0};

kern_return_t catch_exception_raise(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, exception_data_t code,
    mach_msg_type_number_t codeCnt) {
    (void)exception_port;
    (void)thread;
    (void)task;
    (void)exception;
    (void)code;
    (void)codeCnt;
    return KERN_FAILURE;
}

kern_return_t catch_exception_raise_state(
    mach_port_t exception_port, exception_type_t exception,
    const exception_data_t code, mach_msg_type_number_t codeCnt,
    int *flavor, const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {
    (void)exception_port;
    (void)exception;
    (void)code;
    (void)codeCnt;
    (void)flavor;
    (void)old_state;
    (void)old_stateCnt;
    (void)new_state;
    (void)new_stateCnt;
    return KERN_FAILURE;
}

kern_return_t catch_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, exception_data_t code,
    mach_msg_type_number_t codeCnt, int *flavor,
    thread_state_t old_state, mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state, mach_msg_type_number_t *new_stateCnt) {
    (void)thread;
    struct ring_exception_context *context = &gRingExceptionContext;
    if (!context->active || exception_port != context->exceptionPort ||
        exception != EXC_BAD_ACCESS || flavor == NULL ||
        *flavor != ARM_THREAD_STATE64 ||
        old_stateCnt < ARM_THREAD_STATE64_COUNT || new_stateCnt == NULL ||
        *new_stateCnt < ARM_THREAD_STATE64_COUNT || codeCnt < 2 ||
        (uint32_t)code[1] != 0x60U) {
        return KERN_FAILURE;
    }

    int callbackPid = -1;
    bool taskMatches = task == context->task;
    if (!taskMatches && pid_for_task(task, &callbackPid) == KERN_SUCCESS) {
        taskMatches = callbackPid == context->pid;
    }
    if (!taskMatches) return KERN_FAILURE;

    static const uint8_t expectedIloqUUID[16] = {
        0xdd, 0x9d, 0x3e, 0x33, 0xa7, 0x51, 0x3b, 0x4a,
        0xb9, 0x99, 0x69, 0xbf, 0x81, 0x8b, 0x02, 0xa1,
    };
    mach_vm_address_t iloqImage = 0;
    if (!find_remote_macho_with_uuid_type(
            task, expectedIloqUUID, MH_DYLIB, &iloqImage)) {
        return KERN_FAILURE;
    }

    arm_thread_state64_t state = {0};
    memcpy(&state, old_state, sizeof(state));
    uint64_t pc = (uint64_t)arm_thread_state64_get_pc(state);
    uint64_t lr = (uint64_t)arm_thread_state64_get_lr(state);
    context->iloqImage = iloqImage;
    context->pc = pc;
    context->lr = lr;
    context->x0 = state.__x[0];
    context->x1 = state.__x[1];
    context->code0 = (uint32_t)code[0];
    context->code1 = (uint32_t)code[1];
    if (lr != iloqImage + 0x755b4ULL || state.__x[0] != 0x60ULL ||
        state.__x[1] != 0x2dULL) {
        return KERN_FAILURE;
    }

    void (*returnAddress)(void) = arm_thread_state64_get_lr_fptr(state);
    state.__x[0] = 0;
    if (returnAddress != NULL) {
        arm_thread_state64_set_pc_fptr(state, returnAddress);
        context->recoveryMode = 1;
    } else if ((lr & 0xFFFF000000000000ULL) == 0) {
        returnAddress = (void (*)(void))(uintptr_t)lr;
        arm_thread_state64_set_pc_presigned_fptr(state, returnAddress);
        context->recoveryMode = 2;
    } else {
        return KERN_FAILURE;
    }
    memcpy(new_state, &state, sizeof(state));
    *new_stateCnt = ARM_THREAD_STATE64_COUNT;
    context->recovered = true;
    return KERN_SUCCESS;
}

static bool restore_exception_ports(
    task_t task, const exception_mask_t *masks,
    const mach_port_t *ports, const exception_behavior_t *behaviors,
    const thread_state_flavor_t *flavors,
    mach_msg_type_number_t count) {
    bool restored = task_set_exception_ports(
        task, EXC_MASK_BAD_ACCESS, MACH_PORT_NULL, EXCEPTION_DEFAULT,
        THREAD_STATE_NONE) == KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0; index < count; ++index) {
        exception_mask_t mask = masks[index] & EXC_MASK_BAD_ACCESS;
        if (mask == 0) continue;
        if (task_set_exception_ports(task, mask, ports[index],
                                     behaviors[index], flavors[index]) !=
            KERN_SUCCESS) {
            restored = false;
        }
    }
    return restored;
}

static int protect_ring_initializer(task_t task, pid_t targetPid,
                                    const char *targetPath) {
    NSString *requested = targetPath != NULL
        ? [NSString stringWithUTF8String:targetPath] : nil;
    NSString *resolved = nil;
    NSString *bundle = nil;
    NSString *container = nil;
    NSString *identifier = nil;
    struct stat status = {0};
    if (!app_store_main_executable(requested, &resolved, &bundle, &container,
                                   &identifier, &status) ||
        ![identifier isEqualToString:@"com.ring"]) {
        return 78;
    }
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [bundle stringByAppendingPathComponent:@"Info.plist"]];
    if (![info[@"CFBundleShortVersionString"] isEqual:@"5.113.0"] ||
        ![info[@"CFBundleVersion"] isEqual:@"5.113.0.20"]) {
        unified_loader_log(
            "ringRuntimePolicy identifier=%s versionMatch=false",
            identifier.UTF8String);
        return 83;
    }

    static const uint8_t expectedMainUUID[16] = {
        0xf6, 0x14, 0xab, 0xbc, 0xdb, 0x5b, 0x30, 0xbf,
        0x97, 0x18, 0xaa, 0x1f, 0xb4, 0xe9, 0x3a, 0xdb,
    };
    if (!local_macho_has_uuid(resolved, expectedMainUUID, MH_EXECUTE)) {
        unified_loader_log(
            "ringRuntimePolicy identifier=%s mainUuidMatch=false",
            identifier.UTF8String);
        return 83;
    }

    exception_mask_t oldMasks[EXC_TYPES_COUNT] = {0};
    mach_port_t oldPorts[EXC_TYPES_COUNT] = {0};
    exception_behavior_t oldBehaviors[EXC_TYPES_COUNT] = {0};
    thread_state_flavor_t oldFlavors[EXC_TYPES_COUNT] = {0};
    mach_msg_type_number_t oldCount = EXC_TYPES_COUNT;
    kern_return_t getResult = task_get_exception_ports(
        task, EXC_MASK_BAD_ACCESS, oldMasks, &oldCount, oldPorts,
        oldBehaviors, oldFlavors);

    mach_port_t exceptionPort = MACH_PORT_NULL;
    kern_return_t allocateResult = getResult == KERN_SUCCESS
        ? mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                             &exceptionPort)
        : getResult;
    kern_return_t rightResult = allocateResult == KERN_SUCCESS
        ? mach_port_insert_right(mach_task_self(), exceptionPort,
                                 exceptionPort, MACH_MSG_TYPE_MAKE_SEND)
        : allocateResult;
    kern_return_t setResult = rightResult == KERN_SUCCESS
        ? task_set_exception_ports(task, EXC_MASK_BAD_ACCESS,
                                   exceptionPort,
                                   EXCEPTION_STATE_IDENTITY,
                                   ARM_THREAD_STATE64)
        : rightResult;

    gRingExceptionContext = (struct ring_exception_context){
        .task = task,
        .pid = targetPid,
        .exceptionPort = exceptionPort,
        .active = setResult == KERN_SUCCESS,
    };

    int resumeResult = setResult == KERN_SUCCESS ? kill(targetPid, SIGCONT)
                                                  : -1;
    int resumeError = resumeResult == 0 ? 0 : errno;
    kern_return_t receiveResult = KERN_FAILURE;
    boolean_t serverResult = FALSE;
    kern_return_t sendResult = KERN_FAILURE;
    if (resumeResult == 0) {
        union {
            mach_msg_header_t head;
            uint8_t bytes[16384];
        } request = {0}, reply = {0};
        receiveResult = mach_msg(
            &request.head,
            MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_LARGE,
            0, (mach_msg_size_t)sizeof(request), exceptionPort, 5000,
            MACH_PORT_NULL);
        if (receiveResult == MACH_MSG_SUCCESS) {
            serverResult = exc_server(&request.head, &reply.head);
            if (serverResult) {
                sendResult = mach_msg(&reply.head, MACH_SEND_MSG,
                                      reply.head.msgh_size, 0,
                                      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
                                      MACH_PORT_NULL);
            } else {
                mach_msg_destroy(&request.head);
            }
        }
    }

    gRingExceptionContext.active = false;
    bool recovered = gRingExceptionContext.recovered;
    mach_vm_address_t iloqImage = gRingExceptionContext.iloqImage;
    uint64_t pc = gRingExceptionContext.pc;
    uint64_t lr = gRingExceptionContext.lr;
    uint64_t x0 = gRingExceptionContext.x0;
    uint64_t x1 = gRingExceptionContext.x1;
    uint32_t code0 = gRingExceptionContext.code0;
    uint32_t code1 = gRingExceptionContext.code1;
    int recoveryMode = gRingExceptionContext.recoveryMode;
    bool restored = setResult == KERN_SUCCESS
        ? restore_exception_ports(task, oldMasks, oldPorts, oldBehaviors,
                                  oldFlavors, oldCount)
        : getResult == KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0; index < oldCount; ++index) {
        if (MACH_PORT_VALID(oldPorts[index])) {
            mach_port_deallocate(mach_task_self(), oldPorts[index]);
        }
    }
    if (MACH_PORT_VALID(exceptionPort)) {
        mach_port_destruct(mach_task_self(), exceptionPort,
                           rightResult == KERN_SUCCESS ? -1 : 0, 0);
    }

    bool complete = getResult == KERN_SUCCESS &&
        allocateResult == KERN_SUCCESS && rightResult == KERN_SUCCESS &&
        setResult == KERN_SUCCESS && resumeResult == 0 &&
        receiveResult == MACH_MSG_SUCCESS && serverResult &&
        sendResult == MACH_MSG_SUCCESS && recovered && restored;
    if (!complete) (void)kill(targetPid, SIGKILL);
    unified_loader_log(
        "ringRuntimePolicy pid=%d get=%d allocate=%d right=%d set=%d "
        "resume=%d resumeError=%d receive=%d server=%s send=%d "
        "iloq=0x%llx pc=0x%llx lr=0x%llx x0=0x%llx x1=0x%llx "
        "code0=0x%x code1=0x%x recoveryMode=%d recovered=%s "
        "restored=%s complete=%s",
        targetPid, getResult, allocateResult, rightResult, setResult,
        resumeResult, resumeError, receiveResult,
        serverResult ? "true" : "false", sendResult, iloqImage, pc, lr,
        x0, x1, code0, code1, recoveryMode,
        recovered ? "true" : "false", restored ? "true" : "false",
        complete ? "true" : "false");
    return complete ? 0 : 84;
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
    vm_address_t libSandbox = getRemoteImageAddress(
        task, allImageInfo, "/usr/lib/system/libsystem_sandbox.dylib");
    vm_address_t dlopenAddress =
        libDyld != 0 ? remoteDlSym(task, libDyld, "_dlopen") : 0;
    vm_address_t pthreadSetSelf =
        libPthread != 0
            ? remoteDlSym(task, libPthread, "__pthread_set_self")
            : 0;
    vm_address_t sandboxConsume =
        libSandbox != 0
            ? remoteDlSym(task, libSandbox, "_sandbox_extension_consume")
            : 0;
    printf("compat-loader: preflight ropLoop=0x%llx libdyld=0x%llx "
           "dlopen=0x%llx libpthread=0x%llx pthreadSetSelf=0x%llx "
           "libsandbox=0x%llx sandboxConsume=0x%llx\n",
           (unsigned long long)ropLoop,
           (unsigned long long)libDyld,
           (unsigned long long)dlopenAddress,
           (unsigned long long)libPthread,
           (unsigned long long)pthreadSetSelf,
           (unsigned long long)libSandbox,
           (unsigned long long)sandboxConsume);
    return ropLoop != 0 && libDyld != 0 && dlopenAddress != 0 &&
                   libPthread != 0 && pthreadSetSelf != 0 &&
                   libSandbox != 0 && sandboxConsume != 0
               ? 0
               : 77;
}

static bool remote_runtime_is_ready(task_t task,
                                    vm_address_t allImageInfo) {
    struct dyld_all_image_infos imageInfos = {0};
    return allImageInfo != 0 &&
           read_remote(task, allImageInfo, &imageInfos,
                       sizeof(imageInfos)) == KERN_SUCCESS &&
           imageInfos.version >= 15 && imageInfos.libSystemInitialized &&
           getRemoteImageAddress(task, allImageInfo,
                                 "/usr/lib/system/libdyld.dylib") != 0 &&
           getRemoteImageAddress(
               task, allImageInfo,
               "/usr/lib/system/libsystem_pthread.dylib") != 0 &&
           getRemoteImageAddress(
               task, allImageInfo,
               "/usr/lib/system/libsystem_sandbox.dylib") != 0;
}

static bool path_has_prefix(const char *path, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(path, prefix, length) == 0;
}

static bool fixed_springboard_candidate_path(const char *path) {
    char resolved[PATH_MAX] = {0};
    return strcmp(path, kSpringBoardCandidatePath) == 0 ||
           (realpath(kSpringBoardCandidatePath, resolved) != NULL &&
            strcmp(path, resolved) == 0);
}

static bool copy_bsd_info(pid_t pid, struct codex_proc_bsdinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDTBSDINFO, 0, information,
                              (int)sizeof(*information));
    return amount == (int)sizeof(*information) &&
           information->pbi_pid == (uint32_t)pid;
}


static bool supported_target_path(const char *path) {
    return strcmp(path,
                  "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ==
               0 ||
           strcmp(path, "/usr/libexec/lsd") == 0 ||
           strcmp(path, kStockAmfid) == 0 ||
           fixed_springboard_candidate_path(path) ||
           path_has_prefix(path,
                           "/private/var/containers/Bundle/Application/") ||
           path_has_prefix(path, "/var/containers/Bundle/Application/") ||
           path_has_prefix(path, "/private/var/staged_system_apps/") ||
           path_has_prefix(path, "/Applications/") ||
           path_has_prefix(path, "/var/jb/Applications/");
}

static bool read_supported_target(pid_t pid, char path[PATH_MAX]) {
    path[0] = '\0';
    if (pid <= 1 || proc_pidpath(pid, path, PATH_MAX) <= 0 ||
        strcmp(path, "/sbin/launchd") == 0 ||
        strcmp(path, "/usr/libexec/launchd") == 0 ||
        strcmp(strrchr(path, '/') != NULL ? strrchr(path, '/') + 1 : path,
               "launchd") == 0 ||
        !supported_target_path(path)) {
        return false;
    }
    return true;
}

static bool read_exact_launchd_target(pid_t pid, char path[PATH_MAX]) {
    path[0] = '\0';
    struct codex_proc_bsdinfo information = {0};
    if (pid != 1 || proc_pidpath(pid, path, PATH_MAX) <= 0 ||
        !copy_bsd_info(pid, &information) || information.pbi_uid != 0 ||
        information.pbi_ppid != 0) {
        return false;
    }
    const char *leaf = strrchr(path, '/');
    return strcmp(leaf != NULL ? leaf + 1 : path, "launchd") == 0;
}

static bool wait_for_trace_stop(pid_t pid, int *status) {
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        errno = 0;
        pid_t result = waitpid(pid, status, WUNTRACED | WNOHANG);
        if (result == pid) {
            if (WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGSTOP) {
                return true;
            }
            errno = EPROTO;
            return false;
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
    errno = ETIMEDOUT;
    return false;
}

static int detach_traced_target(pid_t pid, int *savedError) {
    int result = -1;
    *savedError = 0;
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        errno = 0;
        result = ptrace(CODEX_PT_DETACH, pid, NULL, 0);
        *savedError = result == 0 ? 0 : errno;
        if (result == 0 ||
            (*savedError != EBUSY && *savedError != EINTR)) {
            break;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
    return result;
}

static bool soften_target(pid_t pid, const char *expectedPath) {
    uint32_t before = 0;
    uint32_t after = 0;
    char initialPath[PATH_MAX];
    bool sameInitialProcess = read_supported_target(pid, initialPath) &&
                              strcmp(initialPath, expectedPath) == 0;
    if (!sameInitialProcess) {
        unified_loader_log("elleKitTargetCodesign pid=%d sameInitial=false",
                           pid);
        return false;
    }
    if (csops(pid, CODEX_CS_OPS_STATUS, &before, sizeof(before)) == 0 &&
        (before & CODEX_CS_DEBUGGED) != 0 &&
        (before & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0) {
        unified_loader_log("elleKitTargetCodesign pid=%d before=0x%08x "
                           "after=0x%08x alreadySoftened=true",
                           pid, before, before);
        return true;
    }

    errno = 0;
    if (ptrace(CODEX_PT_ATTACHEXC, pid, NULL, 0) != 0) {
        fprintf(stderr,
                "compat-loader: pid=%d codesign attach failed: %s\n", pid,
                strerror(errno));
        unified_loader_log("elleKitTargetCodesign pid=%d before=0x%08x "
                           "attach=false errno=%d",
                           pid, before, errno);
        return false;
    }
    int stopStatus = 0;
    bool traceStopped = wait_for_trace_stop(pid, &stopStatus);
    int waitError = traceStopped ? 0 : errno;

    char stoppedPath[PATH_MAX];
    bool sameStoppedProcess =
        traceStopped && read_supported_target(pid, stoppedPath) &&
        strcmp(stoppedPath, expectedPath) == 0;

    int detachError = 0;
    int detachResult = detach_traced_target(pid, &detachError);
    if (detachResult != 0) {
        fprintf(stderr,
                "compat-loader: pid=%d codesign stop=%s waitError=%d "
                "detach failed: %s\n",
                pid, traceStopped ? "true" : "false", waitError,
                strerror(detachError));
        unified_loader_log("elleKitTargetCodesign pid=%d before=0x%08x "
                           "stopped=%s waitError=%d detach=false errno=%d",
                           pid, before, traceStopped ? "true" : "false",
                           waitError, detachError);
        return false;
    }

    char currentPath[PATH_MAX];
    bool sameProcess = sameStoppedProcess &&
                       read_supported_target(pid, currentPath) &&
                       strcmp(currentPath, expectedPath) == 0;
    int continueResult = -1;
    int continueError = 0;
    if (sameProcess) {
        errno = 0;
        continueResult = kill(pid, SIGCONT);
        continueError = continueResult == 0 ? 0 : errno;
    }
    bool softened = csops(pid, CODEX_CS_OPS_STATUS, &after, sizeof(after)) ==
                        0 &&
                    (after & CODEX_CS_DEBUGGED) != 0 &&
                    (after & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    printf("compat-loader: pid=%d codesign before=0x%08x after=0x%08x "
           "stopped=%s stopSignal=%d sameProcess=%s continued=%s "
           "softened=%s\n",
           pid, before, after, traceStopped ? "true" : "false",
           traceStopped ? WSTOPSIG(stopStatus) : 0,
           sameProcess ? "true" : "false",
           continueResult == 0 ? "true" : "false",
           softened ? "true" : "false");
    unified_loader_log("elleKitTargetCodesign pid=%d before=0x%08x "
                       "after=0x%08x stopped=%s stopSignal=%d waitError=%d "
                       "sameProcess=%s continued=%s continueError=%d "
                       "softened=%s",
                       pid, before, after,
                       traceStopped ? "true" : "false",
                       traceStopped ? WSTOPSIG(stopStatus) : 0, waitError,
                       sameProcess ? "true" : "false",
                       continueResult == 0 ? "true" : "false", continueError,
                       softened ? "true" : "false");
    return traceStopped && sameProcess && continueResult == 0 && softened;
}


static bool path_is_fixed_sbinject_launchd_hook(const char *resolvedPath) {
    char fixedPath[PATH_MAX] = {0};
    struct stat status = {0};
    return resolvedPath != NULL &&
           realpath(kSBInjectLaunchdHook, fixedPath) != NULL &&
           strcmp(resolvedPath, fixedPath) == 0 &&
           lstat(fixedPath, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool path_is_fixed_sbinject_lsd_registration_hook(
    const char *resolvedPath) {
    char fixedPath[PATH_MAX] = {0};
    struct stat status = {0};
    return resolvedPath != NULL &&
           realpath(kSBInjectLsdRegistrationHook, fixedPath) != NULL &&
           strcmp(resolvedPath, fixedPath) == 0 &&
           lstat(fixedPath, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool path_is_fixed_sbinject_amfid_hook(const char *resolvedPath) {
    char fixedPath[PATH_MAX] = {0};
    struct stat status = {0};
    return resolvedPath != NULL &&
           realpath(kSBInjectAmfidHook, fixedPath) != NULL &&
           strcmp(resolvedPath, fixedPath) == 0 &&
           lstat(fixedPath, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}


static bool prewarm_local_injection_primitives(void) {
    task_dyld_info_data_t dyldInfo = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(
        mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if (result != KERN_SUCCESS || count < TASK_DYLD_INFO_COUNT ||
        dyldInfo.all_image_info_addr == 0 ||
        dyldInfo.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64 ||
        dyldInfo.all_image_info_size < sizeof(struct dyld_all_image_infos)) {
        fprintf(stderr,
                "compat-loader: local dyld info unavailable for prewarm: "
                "%s (%d)\n",
                mach_error_string(result), result);
        return false;
    }
    bool ready = codexPrewarmInjectionPrimitives(
        mach_task_self(), dyldInfo.all_image_info_addr);
    printf("compat-loader: local shared-cache prewarm=%s dyld=0x%llx\n",
           ready ? "true" : "false",
           (unsigned long long)dyldInfo.all_image_info_addr);
    return ready;
}

static bool shadow_enabled_for_target(const char *targetPath,
                                      NSString **identifierOut);
static bool generic_compatibility_enabled(NSString *identifier);
static bool broker_no_inject_identifier(NSString *identifier);
static bool broker_compatibility_identifier(NSString *identifier);

static NSString *sha256_for_path(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path
                                          options:NSDataReadingMappedIfSafe
                                            error:nil];
    if (data == nil || data.length > UINT32_MAX) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    if (CC_SHA256(data.bytes, (CC_LONG)data.length, digest) == NULL) {
        return nil;
    }
    NSMutableString *result = [NSMutableString
        stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2U];
    for (size_t index = 0; index < sizeof(digest); ++index) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static bool bbc_hbc_compatibility_patch_present(NSString *bundlePath) {
    if (bundlePath.length == 0) return false;
    NSString *bundle = [bundlePath
        stringByAppendingPathComponent:@"main.jsbundle"];
    struct stat status = {0};
    if (lstat(bundle.fileSystemRepresentation, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 || status.st_uid != 33 || status.st_gid != 33 ||
        (status.st_mode & 07777) != 0644 || status.st_size != 15822554) {
        return false;
    }
    return [[sha256_for_path(bundle) lowercaseString]
        isEqualToString:
            @"27b73e1d13d6e1cef1dd31a0332d7ee822746541aae35a1c5be7652158937a91"];
}

static bool secure_identifier(NSString *identifier) {
    if (identifier.length == 0 || identifier.length > 255) return false;
    NSCharacterSet *invalid = [[NSCharacterSet
        characterSetWithCharactersInString:
            @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"]
        invertedSet];
    return [identifier rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static bool app_store_main_executable(NSString *requested,
                                      NSString **resolvedOut,
                                      NSString **bundleOut,
                                      NSString **containerOut,
                                      NSString **identifierOut,
                                      struct stat *statusOut) {
    if (requested.length == 0 || requested.length >= PATH_MAX) return false;
    char resolvedBytes[PATH_MAX] = {0};
    if (realpath(requested.fileSystemRepresentation, resolvedBytes) == NULL) {
        return false;
    }
    NSString *resolved = [NSString stringWithUTF8String:resolvedBytes];
    bool containerPath =
        [resolved hasPrefix:@"/var/containers/Bundle/Application/"] ||
        [resolved hasPrefix:@"/private/var/containers/Bundle/Application/"];
    if (!containerPath) return false;
    NSString *bundle = resolved.stringByDeletingLastPathComponent;
    if (![[bundle pathExtension] isEqualToString:@"app"]) return false;
    NSString *container = bundle.stringByDeletingLastPathComponent;
    NSString *root = container.stringByDeletingLastPathComponent;
    if (![root isEqualToString:@"/var/containers/Bundle/Application"] &&
        ![root isEqualToString:@"/private/var/containers/Bundle/Application"]) {
        return false;
    }
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [bundle stringByAppendingPathComponent:@"Info.plist"]];
    NSString *executable = info[@"CFBundleExecutable"];
    NSString *identifier = info[@"CFBundleIdentifier"];
    if (![executable isKindOfClass:NSString.class] ||
        ![identifier isKindOfClass:NSString.class] ||
        ![executable isEqualToString:resolved.lastPathComponent] ||
        !secure_identifier(identifier)) {
        return false;
    }
    struct stat status = {0};
    if (lstat(resolved.fileSystemRepresentation, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 || status.st_size <= 0 ||
        status.st_size > 512LL * 1024LL * 1024LL ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }
    if (resolvedOut != NULL) *resolvedOut = resolved;
    if (bundleOut != NULL) *bundleOut = bundle;
    if (containerOut != NULL) *containerOut = container;
    if (identifierOut != NULL) *identifierOut = identifier;
    if (statusOut != NULL) *statusOut = status;
    return true;
}

static bool secure_root_executable(const char *path) {
    struct stat status = {0};
    return path != NULL && lstat(path, &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_nlink == 1 && status.st_uid == 0 &&
           status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
           (status.st_mode & S_IXUSR) != 0;
}

static bool ensure_root_directory(NSString *path) {
    if (path.length == 0) return false;
    NSError *error = nil;
    bool created = [[NSFileManager defaultManager]
        createDirectoryAtPath:path
  withIntermediateDirectories:YES
                   attributes:@{
                       NSFilePosixPermissions : @0700,
                       NSFileOwnerAccountID : @0,
                       NSFileGroupOwnerAccountID : @0,
                   }
                        error:&error];
    if (!created || chown(path.fileSystemRepresentation, 0, 0) != 0 ||
        chmod(path.fileSystemRepresentation, 0700) != 0) {
        return false;
    }
    struct stat status = {0};
    return lstat(path.fileSystemRepresentation, &status) == 0 &&
           S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & 07777) == 0700;
}

static bool install_root_copy(NSString *source, NSString *destination) {
    NSString *temporary = [destination stringByAppendingFormat:
        @".new.%d.%@", getpid(), NSUUID.UUID.UUIDString];
    NSError *error = nil;
    bool installed = [[NSFileManager defaultManager]
        copyItemAtPath:source toPath:temporary error:&error];
    installed = installed &&
        chown(temporary.fileSystemRepresentation, 0, 0) == 0 &&
        chmod(temporary.fileSystemRepresentation, 0600) == 0 &&
        rename(temporary.fileSystemRepresentation,
               destination.fileSystemRepresentation) == 0;
    if (!installed) (void)unlink(temporary.fileSystemRepresentation);
    return installed;
}

static bool install_root_executable_copy(NSString *source,
                                         NSString *destination) {
    NSString *temporary = [destination stringByAppendingFormat:
        @".new.%d.%@", getpid(), NSUUID.UUID.UUIDString];
    NSError *error = nil;
    bool installed = [[NSFileManager defaultManager]
        copyItemAtPath:source toPath:temporary error:&error];
    installed = installed &&
        chown(temporary.fileSystemRepresentation, 0, 0) == 0 &&
        chmod(temporary.fileSystemRepresentation, 0755) == 0 &&
        rename(temporary.fileSystemRepresentation,
               destination.fileSystemRepresentation) == 0;
    if (!installed) (void)unlink(temporary.fileSystemRepresentation);
    return installed;
}

static int wait_for_tool_bounded(pid_t pid) {
    int status = 0;
    for (unsigned int attempt = 0; attempt < 3000U; ++attempt) {
        errno = 0;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
            return 125;
        }
        if (result < 0 && errno != EINTR) return 126;
        usleep(10U * 1000U);
    }
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 124;
}

static int run_tool_bounded(const char *tool, char *const arguments[],
                            const char *standardOutput) {
    if (!secure_root_executable(tool)) return 126;
    posix_spawn_file_actions_t actions;
    int result = posix_spawn_file_actions_init(&actions);
    bool actionsReady = result == 0;
    if (result == 0 && standardOutput != NULL) {
        result = posix_spawn_file_actions_addopen(
            &actions, STDOUT_FILENO, standardOutput,
            O_WRONLY | O_CREAT | O_TRUNC, 0600);
    }
    pid_t child = 0;
    if (result == 0) {
        result = posix_spawn(&child, tool, actionsReady ? &actions : NULL,
                             NULL, arguments, environ);
    }
    if (actionsReady) posix_spawn_file_actions_destroy(&actions);
    if (result != 0 || child <= 1) return 126;
    return wait_for_tool_bounded(child);
}

static NSDictionary *extract_entitlements(NSString *executable,
                                           NSString *output) {
    char *arguments[] = {
        (char *)CODEX_SBINJECT_SHADOW_SIGNER,
        "-e",
        (char *)executable.fileSystemRepresentation,
        NULL,
    };
    int result = run_tool_bounded(CODEX_SBINJECT_SHADOW_SIGNER, arguments,
                                  output.fileSystemRepresentation);
    NSDictionary *entitlements = result == 0
        ? [NSDictionary dictionaryWithContentsOfFile:output] : nil;
    return [entitlements isKindOfClass:NSDictionary.class]
        ? entitlements : nil;
}

static bool write_root_dictionary(NSDictionary *dictionary, NSString *path,
                                  mode_t mode) {
    NSString *temporary = [path stringByAppendingFormat:
        @".new.%d.%@", getpid(), NSUUID.UUID.UUIDString];
    bool written = [dictionary writeToFile:temporary atomically:NO] &&
        chown(temporary.fileSystemRepresentation, 0, 0) == 0 &&
        chmod(temporary.fileSystemRepresentation, mode) == 0 &&
        rename(temporary.fileSystemRepresentation,
               path.fileSystemRepresentation) == 0;
    if (!written) (void)unlink(temporary.fileSystemRepresentation);
    return written;
}

static int restore_shadow_app_if_managed(NSString *resolved,
                                         NSString *markerPath,
                                         NSDictionary *marker) {
    NSInteger markerVersion = [marker[@"Version"] integerValue];
    if (![marker isKindOfClass:NSDictionary.class] || markerVersion < 1 ||
        markerVersion >= CODEX_SHADOW_MANAGED_VERSION) {
        return 75;
    }
    NSString *managedHash = marker[@"ManagedSHA256"];
    NSString *originalHash = marker[@"OriginalSHA256"];
    NSString *originalPath = marker[@"OriginalStorePath"];
    NSString *currentHash = sha256_for_path(resolved);
    struct stat originalStatus = {0};
    NSString *originalPrefix = [[NSString
        stringWithUTF8String:CODEX_SBINJECT_SHADOW_ORIGINAL_ROOT]
        stringByAppendingString:@"/"];
    if (![managedHash isKindOfClass:NSString.class] ||
        ![originalHash isKindOfClass:NSString.class] ||
        ![originalPath isKindOfClass:NSString.class] ||
        ![originalPath hasPrefix:originalPrefix] ||
        lstat(originalPath.fileSystemRepresentation, &originalStatus) != 0 ||
        !S_ISREG(originalStatus.st_mode) || S_ISLNK(originalStatus.st_mode) ||
        originalStatus.st_nlink != 1 || originalStatus.st_uid != 0 ||
        originalStatus.st_gid != 0 ||
        (originalStatus.st_mode & 07777) != 0600 ||
        ![currentHash isEqual:managedHash] ||
        ![(sha256_for_path(originalPath) ?: @"") isEqual:originalHash]) {
        return 76;
    }
    NSString *temporary = [resolved.stringByDeletingLastPathComponent
        stringByAppendingPathComponent:[NSString stringWithFormat:
            @".%@.restore.%d.%@", resolved.lastPathComponent, getpid(),
            NSUUID.UUID.UUIDString]];
    NSError *copyError = nil;
    bool restored = [[NSFileManager defaultManager] copyItemAtPath:originalPath
                                                           toPath:temporary
                                                            error:&copyError];
    uid_t owner = (uid_t)[marker[@"OriginalUID"] unsignedIntValue];
    gid_t group = (gid_t)[marker[@"OriginalGID"] unsignedIntValue];
    mode_t mode = (mode_t)[marker[@"OriginalMode"] unsignedShortValue];
    restored = restored && chown(temporary.fileSystemRepresentation,
                                 owner, group) == 0 &&
               chmod(temporary.fileSystemRepresentation, mode) == 0 &&
               rename(temporary.fileSystemRepresentation,
                      resolved.fileSystemRepresentation) == 0;
    if (!restored) {
        (void)unlink(temporary.fileSystemRepresentation);
        return 76;
    }
    (void)unlink(markerPath.fileSystemRepresentation);
    unified_loader_log("shadowBrokerRestore identifier=%s restored=true",
                       [marker[@"BundleIdentifier"] UTF8String]);
    return 75;
}

static int remove_shadow_bootstrap_if_managed(NSString *bundle,
                                               NSString *identifier,
                                               NSString *markerPath,
                                               NSDictionary *marker) {
    if (![marker isKindOfClass:NSDictionary.class] ||
        [marker[@"Version"] integerValue] != CODEX_SHADOW_MANAGED_VERSION ||
        ![marker[@"BundleIdentifier"] isEqual:identifier]) {
        return 76;
    }
    bool compatibility = [marker[@"Mode"]
        isEqualToString:@"TargetCompatibility"];
    const char *bootstrapName = compatibility
        ? CODEX_SBINJECT_COMPATIBILITY_APP_BOOTSTRAP_NAME
        : CODEX_SBINJECT_SHADOW_APP_BOOTSTRAP_NAME;
    NSString *bootstrap = [bundle stringByAppendingPathComponent:
        [NSString stringWithUTF8String:bootstrapName]];
    NSString *expectedHash = marker[@"BootstrapSHA256"];
    struct stat status = {0};
    if (lstat(bootstrap.fileSystemRepresentation, &status) == 0) {
        if (!S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
            status.st_nlink != 1 || status.st_uid != 0 ||
            status.st_gid != 0 || (status.st_mode & 07777) != 0755 ||
            ![expectedHash isKindOfClass:NSString.class] ||
            ![(sha256_for_path(bootstrap) ?: @"") isEqual:expectedHash] ||
            unlink(bootstrap.fileSystemRepresentation) != 0) {
            return 76;
        }
    } else if (errno != ENOENT) {
        return 76;
    }
    if (unlink(markerPath.fileSystemRepresentation) != 0 && errno != ENOENT) {
        return 76;
    }
    unified_loader_log(
        "shadowBrokerBootstrap identifier=%s removed=true",
        identifier.UTF8String);
    return 75;
}

static int prepare_enabled_shadow_path(const char *requestedPath) {
    if (geteuid() != 0 || requestedPath == NULL) return 67;
    NSString *requested = [NSString stringWithUTF8String:requestedPath];
    NSString *resolved = nil;
    NSString *bundle = nil;
    NSString *container = nil;
    NSString *identifier = nil;
    struct stat executableStatus = {0};
    if (!app_store_main_executable(requested, &resolved, &bundle, &container,
                                   &identifier, &executableStatus)) {
        return 78;
    }
    NSString *markerPath = [container stringByAppendingPathComponent:
        [NSString stringWithUTF8String:CODEX_SBINJECT_MANAGED_APP_MARKER]];
    struct stat markerStatus = {0};
    bool markerSecure = lstat(markerPath.fileSystemRepresentation,
                              &markerStatus) == 0 &&
        S_ISREG(markerStatus.st_mode) && !S_ISLNK(markerStatus.st_mode) &&
        markerStatus.st_nlink == 1 && markerStatus.st_uid == 0 &&
        markerStatus.st_gid == 0 &&
        (markerStatus.st_mode & 07777) == 0644 &&
        markerStatus.st_size > 0 && markerStatus.st_size <= 64 * 1024;
    NSDictionary *marker = markerSecure
        ? [NSDictionary dictionaryWithContentsOfFile:markerPath] : nil;
    bool embeddedManagedApp =
        [marker[@"SourcePath"] isKindOfClass:NSString.class] &&
        [marker[@"BundlePath"] isKindOfClass:NSString.class];
    if (embeddedManagedApp) return 75;
    bool navyRuntimePolicy =
        [identifier isEqualToString:@"org.navyfederal.nfcuforiphone"];
    bool ringRuntimePolicy = [identifier isEqualToString:@"com.ring"];
    bool genericCompatibility = !navyRuntimePolicy && !ringRuntimePolicy &&
        ![identifier isEqualToString:@"uk.co.bbc.news"] &&
        generic_compatibility_enabled(identifier);
    bool compatibility = broker_compatibility_identifier(identifier) ||
        genericCompatibility;
    bool noInject = navyRuntimePolicy ||
        broker_no_inject_identifier(identifier) ||
        ([identifier isEqualToString:@"uk.co.bbc.news"] &&
         bbc_hbc_compatibility_patch_present(bundle));
    bool enabled = !noInject && (compatibility || shadow_enabled_for_target(
        resolved.fileSystemRepresentation, NULL));
    if (noInject) {
        unified_loader_log(
            "%s identifier=%s selected=true",
            navyRuntimePolicy ? "brokerRuntimePolicy"
                            : ringRuntimePolicy ? "brokerRingRuntimePolicy"
                            : "brokerNoInjectPolicy",
            identifier.UTF8String);
    }
    NSInteger markerVersion = [marker[@"Version"] integerValue];
    if (!enabled) {
        int cleanupResult = 75;
        if (markerSecure &&
            markerVersion == CODEX_SHADOW_MANAGED_VERSION) {
            cleanupResult = remove_shadow_bootstrap_if_managed(
                bundle, identifier, markerPath, marker);
        } else {
            cleanupResult = restore_shadow_app_if_managed(
                resolved, markerPath, marker);
        }
        if (cleanupResult != 75) return cleanupResult;
        return navyRuntimePolicy ? 73 : ringRuntimePolicy ? 72 : 75;
    }

    // Versions 1-4 changed the App Store executable. Restore the exact saved
    // bytes before the new pre-main path is armed. Version 5 keeps the signed
    // executable unchanged and installs only a fixed, trust-cached bootstrap
    // beside it.
    if (markerSecure && markerVersion >= 1 &&
        markerVersion < CODEX_SHADOW_MANAGED_VERSION) {
        int restoreResult = restore_shadow_app_if_managed(
            resolved, markerPath, marker);
        if (restoreResult != 75) return restoreResult;
        marker = nil;
        markerSecure = false;
        markerVersion = 0;
    }

    NSString *desiredMode = compatibility
        ? @"TargetCompatibility" : @"PreMainBootstrap";
    if (markerSecure && markerVersion == CODEX_SHADOW_MANAGED_VERSION &&
        ![marker[@"Mode"] isEqual:desiredMode]) {
        int removeResult = remove_shadow_bootstrap_if_managed(
            bundle, identifier, markerPath, marker);
        if (removeResult != 75) return removeResult;
        marker = nil;
        markerSecure = false;
        markerVersion = 0;
    }

    NSString *currentHash = sha256_for_path(resolved);
    if (currentHash.length != CC_SHA256_DIGEST_LENGTH * 2U) return 79;
    if (!secure_root_executable(CODEX_SBINJECT_SHADOW_BOOTSTRAP)) return 79;
    NSString *bootstrapSource = [NSString
        stringWithUTF8String:CODEX_SBINJECT_SHADOW_BOOTSTRAP];
    NSString *bootstrapHash = sha256_for_path(bootstrapSource);
    if (bootstrapHash.length != CC_SHA256_DIGEST_LENGTH * 2U) return 79;
    const char *bootstrapName = compatibility
        ? CODEX_SBINJECT_COMPATIBILITY_APP_BOOTSTRAP_NAME
        : CODEX_SBINJECT_SHADOW_APP_BOOTSTRAP_NAME;
    NSString *bootstrapDestination = [bundle stringByAppendingPathComponent:
        [NSString stringWithUTF8String:bootstrapName]];

    bool replaceKnownBootstrap = false;
    if (markerSecure) {
        if (markerVersion != CODEX_SHADOW_MANAGED_VERSION ||
            ![marker[@"BundleIdentifier"] isEqual:identifier] ||
            ![marker[@"Mode"] isEqual:desiredMode] ||
            ![marker[@"OriginalSHA256"] isEqual:currentHash] ||
            ![marker[@"BootstrapSHA256"] isKindOfClass:NSString.class] ||
            ![(sha256_for_path(bootstrapDestination) ?: @"")
                isEqual:marker[@"BootstrapSHA256"]]) {
            return 76;
        }
        if ([marker[@"BootstrapSHA256"] isEqual:bootstrapHash]) {
            unified_loader_log(
                "shadowBrokerPrepare identifier=%s reused=true version=%d "
                "mode=%s",
                identifier.UTF8String, CODEX_SHADOW_MANAGED_VERSION,
                compatibility ? "target-compatibility" : "pre-main");
            return compatibility ? 74 : 0;
        }
        replaceKnownBootstrap = true;
    } else if ([[NSFileManager defaultManager]
                   fileExistsAtPath:bootstrapDestination]) {
        return 76;
    }

    if (!install_root_executable_copy(bootstrapSource,
                                      bootstrapDestination)) {
        return 79;
    }
    NSDictionary *bootstrapMarker = @{
        @"Version" : @(CODEX_SHADOW_MANAGED_VERSION),
        @"Mode" : desiredMode,
        @"BundleIdentifier" : identifier,
        @"ExecutableName" : resolved.lastPathComponent,
        @"OriginalSHA256" : currentHash,
        @"BootstrapSHA256" : bootstrapHash,
    };
    if (!write_root_dictionary(bootstrapMarker, markerPath, 0644)) {
        (void)unlink(bootstrapDestination.fileSystemRepresentation);
        return 79;
    }
    unified_loader_log(
        "shadowBrokerPrepare identifier=%s reused=false version=%d "
        "mode=%s replaced=%s",
        identifier.UTF8String, CODEX_SHADOW_MANAGED_VERSION,
        compatibility ? "target-compatibility" : "pre-main",
        replaceKnownBootstrap ? "true" : "false");
    return compatibility ? 74 : 0;

    if (!secure_root_executable(CODEX_SBINJECT_SHADOW_SIGNER)) return 79;

    bool markerKnown = markerSecure &&
        [marker isKindOfClass:NSDictionary.class] && markerVersion >= 1 &&
        markerVersion <= CODEX_SHADOW_MANAGED_VERSION &&
        [marker[@"BundleIdentifier"] isEqual:identifier];
    if (markerKnown && [marker[@"ManagedSHA256"] isEqual:currentHash]) {
        unified_loader_log(
            "shadowBrokerPrepare identifier=%s reused=true version=%ld",
            identifier.UTF8String, (long)markerVersion);
        return 0;
    }
    if (markerSecure && !markerKnown) return 76;

    NSString *originalRoot = [NSString stringWithUTF8String:
        CODEX_SBINJECT_SHADOW_ORIGINAL_ROOT];
    NSString *identifierRoot = [originalRoot
        stringByAppendingPathComponent:identifier];
    NSString *hashRoot = [identifierRoot
        stringByAppendingPathComponent:currentHash];
    if (!ensure_root_directory(originalRoot) ||
        !ensure_root_directory(identifierRoot) ||
        !ensure_root_directory(hashRoot)) {
        return 79;
    }
    NSString *originalPath = [hashRoot
        stringByAppendingPathComponent:resolved.lastPathComponent];
    if (![[NSFileManager defaultManager] fileExistsAtPath:originalPath] &&
        !install_root_copy(resolved, originalPath)) {
        return 79;
    }
    if (![(sha256_for_path(originalPath) ?: @"") isEqual:currentHash]) {
        return 79;
    }

    NSString *nonce = [NSString stringWithFormat:@"%d.%@", getpid(),
        NSUUID.UUID.UUIDString];
    NSString *stateRoot = @"/var/jb/var/lib/sbinject";
    struct stat stateStatus = {0};
    if (lstat(stateRoot.fileSystemRepresentation, &stateStatus) != 0 ||
        !S_ISDIR(stateStatus.st_mode) || S_ISLNK(stateStatus.st_mode) ||
        stateStatus.st_uid != 0 || stateStatus.st_gid != 0 ||
        (stateStatus.st_mode & 07777) != 0755) {
        return 79;
    }
    NSString *entitlementsPath = [stateRoot stringByAppendingPathComponent:
        [@"shadow-entitlements." stringByAppendingString:nonce]];
    NSString *verificationPath = [stateRoot stringByAppendingPathComponent:
        [@"shadow-verify." stringByAppendingString:nonce]];
    NSDictionary *sourceEntitlements = extract_entitlements(
        originalPath, entitlementsPath);
    if (sourceEntitlements == nil) {
        (void)unlink(entitlementsPath.fileSystemRepresentation);
        return 80;
    }
    NSMutableDictionary *managedEntitlements =
        [sourceEntitlements mutableCopy];
    managedEntitlements[@"get-task-allow"] = @YES;
    if (!write_root_dictionary(managedEntitlements, entitlementsPath, 0600)) {
        (void)unlink(entitlementsPath.fileSystemRepresentation);
        return 80;
    }

    NSString *temporary = [bundle stringByAppendingPathComponent:
        [NSString stringWithFormat:@".%@.shadow.%@",
            resolved.lastPathComponent, nonce]];
    NSError *copyError = nil;
    bool copied = [[NSFileManager defaultManager]
        copyItemAtPath:originalPath toPath:temporary error:&copyError];
    copied = copied &&
        chown(temporary.fileSystemRepresentation, executableStatus.st_uid,
              executableStatus.st_gid) == 0 &&
        chmod(temporary.fileSystemRepresentation,
              executableStatus.st_mode & 07777) == 0;
    if (!copied) {
        (void)unlink(temporary.fileSystemRepresentation);
        (void)unlink(entitlementsPath.fileSystemRepresentation);
        return 80;
    }

    NSString *identifierArgument = [@"-I" stringByAppendingString:identifier];
    NSString *entitlementsArgument = [@"-S"
        stringByAppendingString:entitlementsPath];
    char *signArguments[] = {
        (char *)CODEX_SBINJECT_SHADOW_SIGNER,
        "-Cadhoc",
        (char *)identifierArgument.UTF8String,
        "-Hsha256",
        (char *)entitlementsArgument.UTF8String,
        (char *)temporary.fileSystemRepresentation,
        NULL,
    };
    int signResult = run_tool_bounded(CODEX_SBINJECT_SHADOW_SIGNER,
                                      signArguments, NULL);
    NSDictionary *signedEntitlements = signResult == 0
        ? extract_entitlements(temporary, verificationPath) : nil;
    NSString *managedHash = [signedEntitlements[@"get-task-allow"] boolValue]
        ? sha256_for_path(temporary) : nil;
    if (managedHash.length != CC_SHA256_DIGEST_LENGTH * 2U) {
        (void)unlink(temporary.fileSystemRepresentation);
        (void)unlink(entitlementsPath.fileSystemRepresentation);
        (void)unlink(verificationPath.fileSystemRepresentation);
        unified_loader_log(
            "shadowBrokerPrepare identifier=%s sign=%d verified=false",
            identifier.UTF8String, signResult);
        return 81;
    }

    NSDictionary *managedMarker = @{
        @"Version" : @(CODEX_SHADOW_MANAGED_VERSION),
        @"BundleIdentifier" : identifier,
        @"ExecutableName" : resolved.lastPathComponent,
        @"OriginalSHA256" : currentHash,
        @"ManagedSHA256" : managedHash,
        @"OriginalStorePath" : originalPath,
        @"OriginalUID" : @(executableStatus.st_uid),
        @"OriginalGID" : @(executableStatus.st_gid),
        @"OriginalMode" : @(executableStatus.st_mode & 07777),
    };
    bool markerWritten = write_root_dictionary(managedMarker, markerPath,
                                                0644);
    bool activated = markerWritten &&
        rename(temporary.fileSystemRepresentation,
               resolved.fileSystemRepresentation) == 0;
    if (!activated) {
        (void)unlink(temporary.fileSystemRepresentation);
        if (markerWritten) (void)unlink(markerPath.fileSystemRepresentation);
    }
    (void)unlink(entitlementsPath.fileSystemRepresentation);
    (void)unlink(verificationPath.fileSystemRepresentation);
    unified_loader_log(
        "shadowBrokerPrepare identifier=%s reused=false version=%d sign=%d "
        "activated=%s",
        identifier.UTF8String, CODEX_SHADOW_MANAGED_VERSION, signResult,
        activated ? "true" : "false");
    return activated ? 0 : 81;
}

static bool shadow_enabled_for_target(const char *targetPath,
                                      NSString **identifierOut) {
    if (targetPath == NULL) return false;
    NSString *executablePath = [NSString stringWithUTF8String:targetPath];
    NSString *bundlePath = [executablePath stringByDeletingLastPathComponent];
    NSString *identifier = [NSBundle bundleWithPath:bundlePath].bundleIdentifier;
    if (identifierOut != NULL) *identifierOut = identifier;
    if (identifier.length == 0) return false;
    if (broker_no_inject_identifier(identifier)) return false;
    NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
    if (![preferences isKindOfClass:[NSDictionary class]]) return false;
    NSDictionary *app = preferences[identifier];
    if (![app isKindOfClass:[NSDictionary class]]) app = nil;
    if ([app[@"App_Disabled"] boolValue]) return false;
    if ([preferences[@"Global_Enabled"] boolValue] &&
        ![preferences[@"SingleToggleMigrated"] boolValue]) {
        return true;
    }
    return [app[@"App_Enabled"] boolValue];
}

static bool generic_compatibility_enabled(NSString *identifier) {
    if (identifier.length == 0) return false;
    NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
    NSDictionary *app = [preferences isKindOfClass:NSDictionary.class]
        ? preferences[identifier] : nil;
    return [app isKindOfClass:NSDictionary.class] &&
        [app[@"App_Enabled"] boolValue] &&
        ![app[@"App_Disabled"] boolValue];
}

static bool broker_no_inject_identifier(NSString *identifier) {
    if (identifier.length == 0) return false;
    // These apps must keep the stock sandbox and image list. The launch hook
    // treats the disabled preparation result as an intentional stock spawn.
    return [identifier isEqualToString:@"com.ring"];
}

static bool broker_compatibility_identifier(NSString *identifier) {
    if (identifier.length == 0) return false;
    return [identifier isEqualToString:@"uk.co.bbc.news"] ||
           [identifier isEqualToString:@"org.navyfederal.nfcuforiphone"];
}

static int request_jitterd_debug_state(pid_t targetPid, uint32_t *flagsOut) {
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return errno != 0 ? errno : EIO;
    struct timeval timeout = {.tv_sec = 6, .tv_usec = 0};
    int noSigpipe = 1;
    (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                     sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe,
                     sizeof(noSigpipe));

    struct sockaddr_un address = {0};
    address.sun_len = sizeof(address);
    address.sun_family = AF_UNIX;
    int pathLength = snprintf(address.sun_path, sizeof(address.sun_path),
                              "%s",
                              CODEX_SBINJECT_JITTERD_SHADOW_SOCKET);
    int result = 0;
    if (pathLength <= 0 ||
        (size_t)pathLength >= sizeof(address.sun_path)) {
        result = ENAMETOOLONG;
    } else if (connect(descriptor, (struct sockaddr *)&address,
                       sizeof(address)) != 0) {
        result = errno != 0 ? errno : EIO;
    }

    struct codex_sbinject_shadow_request request = {
        .magic = CODEX_SBINJECT_SHADOW_SOCKET_MAGIC,
        .version = CODEX_SBINJECT_SHADOW_SOCKET_VERSION,
        .pid = targetPid,
        .reserved = 0,
    };
    size_t sent = 0;
    while (result == 0 && sent < sizeof(request)) {
        ssize_t amount = send(descriptor, (const uint8_t *)&request + sent,
                              sizeof(request) - sent, 0);
        if (amount > 0) {
            sent += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            result = amount == 0 ? EPIPE : (errno != 0 ? errno : EIO);
        }
    }

    struct codex_sbinject_shadow_response response = {0};
    size_t received = 0;
    while (result == 0 && received < sizeof(response)) {
        ssize_t amount = recv(descriptor, (uint8_t *)&response + received,
                              sizeof(response) - received, 0);
        if (amount > 0) {
            received += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            result = amount == 0 ? EPIPE : (errno != 0 ? errno : EIO);
        }
    }
    close(descriptor);
    if (result == 0 &&
        (response.magic != CODEX_SBINJECT_SHADOW_SOCKET_MAGIC ||
         response.version != CODEX_SBINJECT_SHADOW_SOCKET_VERSION)) {
        result = EPROTO;
    }
    int transport = result;
    if (result == 0) result = response.result;
    uint32_t flags = 0;
    (void)csops(targetPid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags));
    unified_loader_log(
        "shadowBrokerSocket pid=%d transport=%d response=%d "
        "responseFlags=0x%08x flags=0x%08x",
        targetPid, transport, response.result, response.flags, flags);
    if (flagsOut != NULL) *flagsOut = flags;
    return result;
}


int main(int argc, char *argv[]) {
    @autoreleasepool {
        setlinebuf(stdout);
        setlinebuf(stderr);

        bool isPtrauthChild =
            argc > 1 && strcmp(argv[argc - 1], kPtrauthChild) == 0;
        int userArgumentCount = argc - (isPtrauthChild ? 1 : 0);
        bool inspectOnly = userArgumentCount == 3 &&
                           strcmp(argv[1], kInspectPid) == 0;
        bool preflightOnly = userArgumentCount == 3 &&
                             strcmp(argv[1], kPreflightPid) == 0;
        bool checkPidImage = userArgumentCount == 4 &&
                             strcmp(argv[1], kCheckPidImage) == 0;
        bool injectPid = userArgumentCount == 4 &&
                         strcmp(argv[1], kInjectPid) == 0;
        bool injectEnabledShadowAndResumePid =
            userArgumentCount == 3 &&
            strcmp(argv[1], kInjectEnabledShadowAndResumePid) == 0;
        bool patchNavyAndResumePid =
            userArgumentCount == 3 &&
            strcmp(argv[1], kPatchNavyAndResumePid) == 0;
        bool protectRingAndResumePid =
            userArgumentCount == 3 &&
            strcmp(argv[1], kProtectRingAndResumePid) == 0;
        bool prepareEnabledShadowPath =
            userArgumentCount == 3 &&
            strcmp(argv[1], kPrepareEnabledShadowPath) == 0;
        bool injectAndResumePid = injectEnabledShadowAndResumePid ||
            (userArgumentCount == 4 &&
             strcmp(argv[1], kInjectAndResumePid) == 0);
        bool injectLaunchdHook =
            userArgumentCount == 2 &&
            strcmp(argv[1], kInjectLaunchdHook) == 0;
        if (!inspectOnly && !preflightOnly && !checkPidImage && !injectPid &&
            !injectAndResumePid && !patchNavyAndResumePid &&
            !protectRingAndResumePid &&
            !prepareEnabledShadowPath &&
            !injectLaunchdHook) {
            fprintf(stderr,
                    "usage: %s --inspect-pid pid|--preflight-pid pid|"
                    "--check-pid-image pid absolute-image-path|"
                    "--inject-pid pid absolute-dylib-path|"
                    "--inject-and-resume-pid pid absolute-dylib-path|"
                    "--inject-enabled-shadow-and-resume-pid pid|"
                    "--patch-navy-and-resume-pid pid|"
                    "--protect-ring-and-resume-pid pid|"
                    "--prepare-enabled-shadow-path absolute-executable|"
                    "--inject-launchd-hook\n",
                    argv[0]);
            return 64;
        }
        bool dylibOperation = checkPidImage || injectPid ||
                              injectAndResumePid || injectLaunchdHook;
        const char *requestedPath =
            injectLaunchdHook ? kSBInjectLaunchdHook
            : injectEnabledShadowAndResumePid ? kShadowCore
            : (dylibOperation ? argv[3] : kDefaultDylib);
        if (dylibOperation && requestedPath[0] != '/') {
            fprintf(stderr, "compat-loader: dylib path must be absolute\n");
            return 65;
        }
        char resolvedPath[PATH_MAX] = {0};
        if (dylibOperation &&
            (realpath(requestedPath, resolvedPath) == NULL ||
             access(resolvedPath, R_OK) != 0)) {
            fprintf(stderr, "compat-loader: cannot read %s: %s\n",
                    requestedPath, strerror(errno));
            return 66;
        }
        if (injectLaunchdHook &&
            !path_is_fixed_sbinject_launchd_hook(resolvedPath)) {
            fprintf(stderr,
                    "compat-loader: launchd injection is restricted to the "
                    "fixed SBInject hook\n");
            return 65;
        }
        if (getuid() != 0) {
            fprintf(stderr, "compat-loader: root is required\n");
            return 67;
        }
        if (prepareEnabledShadowPath) {
            return prepare_enabled_shadow_path(argv[2]);
        }

        pid_t targetPid = 1;
        if (!injectLaunchdHook) {
            char *end = NULL;
            errno = 0;
            long value = strtol(argv[2], &end, 10);
            if (errno != 0 || end == argv[2] || *end != '\0' || value <= 1 ||
                value > INT_MAX) {
                fprintf(stderr,
                        "compat-loader: invalid/forbidden target pid: %s\n",
                        argv[2]);
                return 64;
            }
            targetPid = (pid_t)value;
        }
        char targetPath[PATH_MAX] = {0};
        bool targetAdmitted = injectLaunchdHook
                                  ? read_exact_launchd_target(targetPid,
                                                              targetPath)
                                  : read_supported_target(targetPid,
                                                          targetPath);
        if (!targetAdmitted) {
            fprintf(stderr,
                    "compat-loader: pid=%d is not an admitted %s target\n",
                    targetPid,
                    injectLaunchdHook ? "launchd" : "app");
            if (injectAndResumePid) {
                (void)kill(targetPid, SIGCONT);
            }
            if (patchNavyAndResumePid || protectRingAndResumePid) {
                (void)kill(targetPid, SIGKILL);
            }
            return 78;
        }
        if (injectEnabledShadowAndResumePid) {
            NSString *identifier = nil;
            bool enabled = shadow_enabled_for_target(targetPath, &identifier);
            unified_loader_log(
                "shadowBrokerPolicy pid=%d identifier=%s enabled=%s",
                targetPid,
                identifier.length > 0 ? identifier.UTF8String : "unknown",
                enabled ? "true" : "false");
            if (!enabled) {
                (void)kill(targetPid, SIGCONT);
                return 0;
            }
            if (!isPtrauthChild) {
                uint32_t flags = 0;
                bool reusedDebugState =
                    csops(targetPid, CODEX_CS_OPS_STATUS, &flags,
                          sizeof(flags)) == 0 &&
                    (flags & CODEX_CS_DEBUGGED) != 0;
                int debugResult = reusedDebugState
                                      ? 0
                                      : request_jitterd_debug_state(targetPid,
                                                                    &flags);
                unified_loader_log(
                    "shadowBrokerDebug pid=%d result=%d flags=0x%08x "
                    "reused=%s",
                    targetPid, debugResult, flags,
                    reusedDebugState ? "true" : "false");
                if (debugResult != 0) {
                    fprintf(stderr,
                            "compat-loader: Shadow broker could not mark "
                            "pid %d debugged: %s\n",
                            targetPid, strerror(debugResult));
                    (void)kill(targetPid, SIGCONT);
                    return 82;
                }
            }
        }
        bool springBoardTarget =
            strcmp(targetPath,
                   "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ==
                0 ||
            fixed_springboard_candidate_path(targetPath);
        bool lsdTarget = strcmp(targetPath, "/usr/libexec/lsd") == 0;
        if (lsdTarget &&
            (!injectPid || injectAndResumePid ||
             !path_is_fixed_sbinject_lsd_registration_hook(resolvedPath))) {
            fprintf(stderr,
                    "compat-loader: lsd injection is restricted to the fixed "
                    "SBInject registration hook\n");
            return 65;
        }
        bool amfidTarget = strcmp(targetPath, kStockAmfid) == 0;
        if (amfidTarget &&
            (!injectPid || injectAndResumePid ||
             !path_is_fixed_sbinject_amfid_hook(resolvedPath))) {
            fprintf(stderr,
                    "compat-loader: amfid injection is restricted to the "
                    "fixed SBInject hook\n");
            return 65;
        }
        if (injectPid && springBoardTarget) {
            fprintf(stderr,
                    "compat-loader: post-start SpringBoard mutation is disabled; "
                    "use the SBInject pre-main path\n");
            return 65;
        }
        bool runtimeMutation = injectPid || injectAndResumePid ||
                               patchNavyAndResumePid ||
                               protectRingAndResumePid || injectLaunchdHook;
        bool softened = true;
        if (runtimeMutation && !injectLaunchdHook && !amfidTarget &&
            !injectAndResumePid && !patchNavyAndResumePid &&
            !protectRingAndResumePid &&
            !isPtrauthChild) {
            softened = soften_target(targetPid, targetPath);
        }
        if (runtimeMutation && !isPtrauthChild && !softened) {
            fprintf(stderr,
                    "compat-loader: pid=%d debugged admission unavailable; "
                    "continuing with trusted-library task-port lane\n",
                    targetPid);
        }

        task_t targetTask = MACH_PORT_NULL;
        kern_return_t result =
            task_for_pid(mach_task_self(), targetPid, &targetTask);
        if (result != KERN_SUCCESS || !MACH_PORT_VALID(targetTask)) {
            fprintf(stderr,
                    "compat-loader: task_for_pid(%d) failed: %s (%d)\n",
                    targetPid, mach_error_string(result), result);
            unified_loader_log("elleKitTaskPort pid=%d result=%d valid=false",
                               targetPid, result);
            if (injectAndResumePid) {
                (void)kill(targetPid, SIGCONT);
            }
            if (patchNavyAndResumePid || protectRingAndResumePid) {
                (void)kill(targetPid, SIGKILL);
            }
            return 68;
        }
        unified_loader_log("elleKitTaskPort pid=%d result=%d valid=true child=%s",
                           targetPid, result,
                           isPtrauthChild ? "true" : "false");
#if __arm64e__
        if (!isPtrauthChild && runtimeMutation) {
            unified_loader_log("elleKitPtrauthSpawn pid=%d stage=start",
                               targetPid);
            int childResult = spawn_ptrauth_child(argc, argv, targetTask);
            unified_loader_log(
                "elleKitPtrauthSpawn pid=%d stage=complete result=%d",
                targetPid, childResult);
            mach_port_deallocate(mach_task_self(), targetTask);
            if (injectAndResumePid && childResult != 0) {
                (void)kill(targetPid, SIGCONT);
            }
            if ((patchNavyAndResumePid || protectRingAndResumePid) &&
                childResult != 0) {
                (void)kill(targetPid, SIGKILL);
            }
            return childResult;
        }
#endif

        if (protectRingAndResumePid) {
            int policyResult = protect_ring_initializer(
                targetTask, targetPid, targetPath);
            mach_port_deallocate(mach_task_self(), targetTask);
            if (policyResult != 0) (void)kill(targetPid, SIGKILL);
            return policyResult;
        }

        if (runtimeMutation) {
            unified_loader_log("elleKitPrewarm pid=%d stage=start",
                               targetPid);
        }
        if (runtimeMutation && !prewarm_local_injection_primitives()) {
            fprintf(stderr,
                    "compat-loader: shared-cache primitive prewarm failed; "
                    "refusing runtime mutation\n");
            unified_loader_log("elleKitPrewarm pid=%d stage=failed",
                               targetPid);
            mach_port_deallocate(mach_task_self(), targetTask);
            if (patchNavyAndResumePid || protectRingAndResumePid) {
                (void)kill(targetPid, SIGKILL);
            }
            return 78;
        }
        if (runtimeMutation) {
            unified_loader_log("elleKitPrewarm pid=%d stage=complete",
                               targetPid);
        }

        if (injectAndResumePid || patchNavyAndResumePid) {
            errno = 0;
            int resumeResult = kill(targetPid, SIGCONT);
            int resumeError = resumeResult == 0 ? 0 : errno;
            unified_loader_log(
                "elleKitBrokerResume pid=%d result=%d errno=%d",
                targetPid, resumeResult, resumeError);
            if (resumeResult != 0) {
                fprintf(stderr,
                        "compat-loader: could not resume pid %d: %s\n",
                        targetPid, strerror(resumeError));
                mach_port_deallocate(mach_task_self(), targetTask);
                if (patchNavyAndResumePid) (void)kill(targetPid, SIGKILL);
                return 81;
            }
        }

        task_dyld_info_data_t dyldInfo = {0};
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        bool runtimeReady = false;
        unsigned int readyAttempt = 0;
        unsigned int attempts = (injectAndResumePid || patchNavyAndResumePid)
                                    ? CODEX_RUNTIME_READY_ATTEMPTS
                                    : 1U;
        for (unsigned int attempt = 0; attempt < attempts; ++attempt) {
            count = TASK_DYLD_INFO_COUNT;
            result = task_info(targetTask, TASK_DYLD_INFO,
                               (task_info_t)&dyldInfo, &count);
            runtimeReady =
                result == KERN_SUCCESS &&
                dyldInfo.all_image_info_addr != 0 &&
                (!(injectAndResumePid || patchNavyAndResumePid) ||
                 remote_runtime_is_ready(targetTask,
                                         dyldInfo.all_image_info_addr));
            if (runtimeReady) {
                readyAttempt = attempt + 1U;
                break;
            }
            usleep(CODEX_RUNTIME_READY_DELAY_USEC);
        }
        if (!runtimeReady) {
            fprintf(stderr,
                    "compat-loader: runtime readiness for pid %d failed: "
                    "mach=%s (%d)\n",
                    targetPid, mach_error_string(result), result);
            mach_port_deallocate(mach_task_self(), targetTask);
            if (patchNavyAndResumePid) (void)kill(targetPid, SIGKILL);
            return 69;
        }
        if (injectAndResumePid || patchNavyAndResumePid) {
            // The target can run security initializers as soon as dyld maps
            // dependencies. Recheck immediately and start the one-shot
            // bootstrap. Navy needs one bounded interval for its Objective-C
            // framework classes to register on a warm launch.
            unsigned int stabilizeUsec =
                patchNavyAndResumePid ? 250U * 1000U : 0U;
            if (stabilizeUsec != 0U) usleep(stabilizeUsec);
            count = TASK_DYLD_INFO_COUNT;
            result = task_info(targetTask, TASK_DYLD_INFO,
                               (task_info_t)&dyldInfo, &count);
            runtimeReady = result == KERN_SUCCESS &&
                remote_runtime_is_ready(targetTask,
                                        dyldInfo.all_image_info_addr);
            unified_loader_log(
                "elleKitBrokerRuntime pid=%d ready=%s stabilizeUsec=%u "
                "attempt=%u",
                targetPid, runtimeReady ? "true" : "false",
                stabilizeUsec, readyAttempt);
            if (!runtimeReady) {
                mach_port_deallocate(mach_task_self(), targetTask);
                if (patchNavyAndResumePid) (void)kill(targetPid, SIGKILL);
                return 69;
            }
        }

        struct suspended_thread_set heldThreads = {0};
        bool threadsHeld = false;
        if (injectAndResumePid || patchNavyAndResumePid) {
            threadsHeld = suspend_existing_threads_stable(
                targetTask, &heldThreads);
            unified_loader_log(
                "%s thread gate pid=%d held=%s threads=%u",
                injectEnabledShadowAndResumePid ? "Shadow broker"
                                                : "compatibility broker",
                targetPid, threadsHeld ? "true" : "false",
                heldThreads.count);
            if (!threadsHeld) {
                mach_port_deallocate(mach_task_self(), targetTask);
                if (patchNavyAndResumePid) (void)kill(targetPid, SIGKILL);
                return 81;
            }
        }

        if (patchNavyAndResumePid) {
            int policyResult = 85;
            unsigned int policyAttempt = 0;
            for (; policyAttempt < 20U; ++policyAttempt) {
                policyResult = replace_navy_detector_methods(
                    targetTask, dyldInfo.all_image_info_addr, targetPath);
                release_suspended_threads(&heldThreads);
                unified_loader_log(
                    "navyRuntimePolicyAttempt pid=%d attempt=%u result=%d",
                    targetPid, policyAttempt + 1U, policyResult);
                if (policyResult != 84 && policyResult != 85) break;
                usleep(5000U);
                threadsHeld = suspend_existing_threads_stable(
                    targetTask, &heldThreads);
                if (!threadsHeld) {
                    policyResult = 81;
                    break;
                }
            }
            release_suspended_threads(&heldThreads);
            mach_port_deallocate(mach_task_self(), targetTask);
            if (policyResult != 0) (void)kill(targetPid, SIGKILL);
            unified_loader_log(
                "navyRuntimePolicyResume pid=%d result=%d resumed=%s",
                targetPid, policyResult,
                policyResult == 0 ? "true" : "false");
            return policyResult;
        }

        if (checkPidImage) {
            bool loaded = image_is_loaded(targetTask,
                                          dyldInfo.all_image_info_addr,
                                          requestedPath);
            if (!loaded && strcmp(requestedPath, resolvedPath) != 0) {
                loaded = image_is_loaded(targetTask,
                                         dyldInfo.all_image_info_addr,
                                         resolvedPath);
            }
            printf("compat-loader: pid=%d image loaded=%s path=%s "
                   "resolved=%s\n",
                   targetPid, loaded ? "true" : "false", requestedPath,
                   resolvedPath);
            mach_port_deallocate(mach_task_self(), targetTask);
            return loaded ? 0 : 75;
        }

        if (inspectOnly) {
            int inspectResult = inspect_dyld_info(targetTask, &dyldInfo);
            mach_port_deallocate(mach_task_self(), targetTask);
            return inspectResult;
        }
        if (preflightOnly) {
            int preflightResult = preflight_remote_symbols(
                targetTask, dyldInfo.all_image_info_addr);
            mach_port_deallocate(mach_task_self(), targetTask);
            return preflightResult;
        }

        int preflightResult = preflight_remote_symbols(
            targetTask, dyldInfo.all_image_info_addr);
        unified_loader_log("elleKitBrokerPreflight pid=%d result=%d",
                           targetPid, preflightResult);
        if (preflightResult != 0) {
            fprintf(stderr,
                    "compat-loader: remote-call preflight failed; refusing "
                    "injection\n");
            release_suspended_threads(&heldThreads);
            mach_port_deallocate(mach_task_self(), targetTask);
            return preflightResult;
        }

        if (!image_is_loaded(targetTask, dyldInfo.all_image_info_addr,
                             resolvedPath)) {
            char currentPath[PATH_MAX];
            bool sameTarget = injectLaunchdHook
                                  ? read_exact_launchd_target(targetPid,
                                                              currentPath)
                                  : read_supported_target(targetPid,
                                                          currentPath);
            if (!sameTarget ||
                strcmp(currentPath, targetPath) != 0) {
                release_suspended_threads(&heldThreads);
                mach_port_deallocate(mach_task_self(), targetTask);
                return 80;
            }
            printf("compat-loader: injecting %s into pid %d path=%s\n",
                   resolvedPath, targetPid, targetPath);
            injectDylibViaRop(targetTask, targetPid, resolvedPath,
                              dyldInfo.all_image_info_addr);
            for (unsigned int attempt = 0;
                 attempt < CODEX_IMAGE_READY_ATTEMPTS; ++attempt) {
                count = TASK_DYLD_INFO_COUNT;
                result = task_info(targetTask, TASK_DYLD_INFO,
                                   (task_info_t)&dyldInfo, &count);
                if (result == KERN_SUCCESS &&
                    image_is_loaded(targetTask,
                                    dyldInfo.all_image_info_addr,
                                    resolvedPath)) {
                    break;
                }
                usleep(CODEX_IMAGE_READY_DELAY_USEC);
            }
        }

        bool loaded = result == KERN_SUCCESS &&
                      image_is_loaded(targetTask,
                                      dyldInfo.all_image_info_addr,
                                      resolvedPath);
        printf("compat-loader: pid=%d image loaded=%s path=%s\n", targetPid,
               loaded ? "true" : "false", resolvedPath);
        unified_loader_log("elleKitImageAdmission pid=%d loaded=%s path=%s",
                           targetPid, loaded ? "true" : "false",
                           resolvedPath);
        release_suspended_threads(&heldThreads);
        mach_port_deallocate(mach_task_self(), targetTask);
        if (!loaded) {
            return 75;
        }
        return 0;
    }
}
