#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/loader.h>
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
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#import "dyld.h"
#import "rop_inject.h"

extern char **environ;
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t taskPort);

static const char *const kDefaultDylib =
    "/var/jb/usr/lib/ellekit/libinjector.dylib";
static const char *const kSBInjectLaunchdHook =
    "/var/jb/usr/lib/sbinject/launchdhook-v12.dylib";
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
static const char *const kInjectLaunchdHook = "--inject-launchd-hook";

#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
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
#define CODEX_RUNTIME_READY_ATTEMPTS 200U
#define CODEX_RUNTIME_READY_DELAY_USEC 1000U
#define CODEX_IMAGE_READY_ATTEMPTS 40U
#define CODEX_IMAGE_READY_DELAY_USEC 1000U

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
    free(message);
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
        bool injectLaunchdHook =
            userArgumentCount == 2 &&
            strcmp(argv[1], kInjectLaunchdHook) == 0;
        if (!inspectOnly && !preflightOnly && !checkPidImage && !injectPid &&
            !injectLaunchdHook) {
            fprintf(stderr,
                    "usage: %s --inspect-pid pid|--preflight-pid pid|"
                    "--check-pid-image pid absolute-image-path|"
                    "--inject-pid pid absolute-dylib-path|"
                    "--inject-launchd-hook\n",
                    argv[0]);
            return 64;
        }
        bool dylibOperation = checkPidImage || injectPid || injectLaunchdHook;
        const char *requestedPath = injectLaunchdHook
                                        ? kSBInjectLaunchdHook
                                        : (dylibOperation ? argv[3]
                                                          : kDefaultDylib);
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
            return 78;
        }
        bool springBoardTarget =
            strcmp(targetPath,
                   "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ==
                0 ||
            fixed_springboard_candidate_path(targetPath);
        bool lsdTarget = strcmp(targetPath, "/usr/libexec/lsd") == 0;
        if (lsdTarget &&
            (!injectPid ||
             !path_is_fixed_sbinject_lsd_registration_hook(resolvedPath))) {
            fprintf(stderr,
                    "compat-loader: lsd injection is restricted to the fixed "
                    "SBInject registration hook\n");
            return 65;
        }
        bool amfidTarget = strcmp(targetPath, kStockAmfid) == 0;
        if (amfidTarget &&
            (!injectPid ||
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
        bool runtimeMutation = injectPid || injectLaunchdHook;
        bool softened = true;
        if (runtimeMutation && !injectLaunchdHook && !amfidTarget &&
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
            return 68;
        }
#if __arm64e__
        if (!isPtrauthChild && runtimeMutation) {
            int childResult = spawn_ptrauth_child(argc, argv, targetTask);
            mach_port_deallocate(mach_task_self(), targetTask);
            return childResult;
        }
#endif

        if (runtimeMutation && !prewarm_local_injection_primitives()) {
            fprintf(stderr,
                    "compat-loader: shared-cache primitive prewarm failed; "
                    "refusing runtime mutation\n");
            mach_port_deallocate(mach_task_self(), targetTask);
            return 78;
        }

        task_dyld_info_data_t dyldInfo = {0};
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        result = task_info(targetTask, TASK_DYLD_INFO,
                           (task_info_t)&dyldInfo, &count);
        bool runtimeReady = result == KERN_SUCCESS &&
                            dyldInfo.all_image_info_addr != 0;
        if (!runtimeReady) {
            fprintf(stderr,
                    "compat-loader: runtime readiness for pid %d failed: "
                    "mach=%s (%d)\n",
                    targetPid, mach_error_string(result), result);
            mach_port_deallocate(mach_task_self(), targetTask);
            return 69;
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
        if (preflightResult != 0) {
            fprintf(stderr,
                    "compat-loader: remote-call preflight failed; refusing "
                    "injection\n");
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
                mach_port_deallocate(mach_task_self(), targetTask);
                return 80;
            }
            printf("compat-loader: injecting %s into pid %d path=%s\n",
                   resolvedPath, targetPid, targetPath);
            injectDylibViaRop(targetTask, targetPid, resolvedPath,
                              dyldInfo.all_image_info_addr);
            usleep(250 * 1000);
            count = TASK_DYLD_INFO_COUNT;
            result = task_info(targetTask, TASK_DYLD_INFO,
                               (task_info_t)&dyldInfo, &count);
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
        mach_port_deallocate(mach_task_self(), targetTask);
        if (!loaded) {
            return 75;
        }
        return 0;
    }
}
