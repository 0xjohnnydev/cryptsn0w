#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_attributes.h>
#import <os/log.h>
#import <spawn.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
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
    "/var/jb/usr/lib/sbinject/launchdhook-v3.dylib";
static const char *const kSBInjectLsdRegistrationHook =
    "/var/jb/usr/lib/sbinject/lsd-registration-hook.dylib";
static const char *const kPtrauthChild = "--ptrauth-child";
static const char *const kInspectPid = "--inspect-pid";
static const char *const kPreflightPid = "--preflight-pid";
static const char *const kCheckPidImage = "--check-pid-image";
static const char *const kInjectPid = "--inject-pid";
static const char *const kInjectLaunchdHook = "--inject-launchd-hook";
static const char *const kPageProbePid = "--page-probe-pid";

#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_OPS_CDHASH 5
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_CDHASH_SIZE 20U
#define CODEX_SHA256_SIZE 32U
#define CODEX_PROC_PIDTBSDINFO 3
#define CODEX_PROC_PIDUNIQIDENTIFIERINFO 17
#define CODEX_MAXCOMLEN 16
#define CODEX_EXPECTED_CANDIDATE_SIZE 122400ULL
#define CODEX_WAIT_ATTEMPTS 500U
#define CODEX_WAIT_DELAY_USEC (10U * 1000U)
#define CODEX_GATE_TIMEOUT_MSEC 5000
#define CODEX_RUNTIME_READY_ATTEMPTS 200U
#define CODEX_RUNTIME_READY_DELAY_USEC 1000U
#define CODEX_IMAGE_READY_ATTEMPTS 40U
#define CODEX_IMAGE_READY_DELAY_USEC 1000U

static const char *const kSpringBoardCandidatePath =
    "/var/jb/System/Library/CoreServices/SpringBoard.app/notSpringBoard";
static const uint8_t kSpringBoardCandidateCDHash[CODEX_CDHASH_SIZE] = {
    0xca, 0x63, 0x0b, 0x4f, 0xcd, 0xe8, 0x4f, 0xf2, 0x04, 0x09,
    0x5b, 0x9b, 0xb1, 0x41, 0xea, 0x05, 0xfc, 0x21, 0xf5, 0xf1,
};
static const uint8_t kSpringBoardCandidateSHA256[CODEX_SHA256_SIZE] = {
    0xa7, 0x7e, 0xf6, 0xb5, 0x9a, 0x53, 0xb1, 0x93,
    0xcd, 0xc2, 0x98, 0x6e, 0x43, 0x4b, 0x25, 0xec,
    0x31, 0x02, 0x5a, 0x6a, 0x35, 0x6e, 0x6b, 0xf1,
    0xb9, 0xc5, 0x9d, 0x0a, 0x72, 0xb5, 0x58, 0x08,
};
static const uint8_t kSpringBoardUUID[16] = {
    0xad, 0x93, 0x7f, 0xb7, 0x26, 0x64, 0x3b, 0x8f,
    0xb1, 0xc9, 0x34, 0xc4, 0xad, 0x40, 0x92, 0xd2,
};

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

struct codex_proc_uniqidentifierinfo {
    uint8_t uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_pid_version;
    uint64_t reserved2;
    uint64_t reserved3;
};

_Static_assert(sizeof(struct codex_proc_bsdinfo) == 136,
               "proc_bsdinfo ABI mismatch");
_Static_assert(sizeof(struct codex_proc_uniqidentifierinfo) == 56,
               "proc_uniqidentifierinfo ABI mismatch");

struct gated_candidate_identity {
    bool valid;
    bool cdhash_fallback;
    pid_t pid;
    pid_t tracer_pid;
    char path[PATH_MAX];
    struct codex_proc_uniqidentifierinfo unique;
    struct stat status;
    int descriptor;
};

static struct gated_candidate_identity gGatedCandidate = {
    .descriptor = -1,
};

extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t bufferSize);
extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_protect(vm_map_t target,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     boolean_t setMaximum,
                                     vm_prot_t protection);
extern kern_return_t mach_vm_write(vm_map_t target,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outSize);
extern kern_return_t mach_vm_remap(
    vm_map_t targetTask, mach_vm_address_t *targetAddress,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
    vm_map_t sourceTask, mach_vm_address_t sourceAddress, boolean_t copy,
    vm_prot_t *currentProtection, vm_prot_t *maximumProtection,
    vm_inherit_t inheritance);

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
extern kern_return_t codexArbCallHeldThread(
    task_t task, thread_act_t targetThread, uint64_t *returnValue,
    vm_address_t function, int argumentCount, ...);
extern bool codexCopyExactMainHeldThread(task_t task,
                                         thread_act_t *threadOut);
extern bool codexInjectDylibViaHeldThread(
    task_t task, thread_act_t thread, pid_t pid, const char *dylibPath,
    vm_address_t allImageInfoAddress);

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

static bool exact_springboard_candidate(pid_t pid, const char *path) {
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    return fixed_springboard_candidate_path(path) &&
           csops(pid, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) == 0 &&
           memcmp(cdhash, kSpringBoardCandidateCDHash, sizeof(cdhash)) == 0;
}

static bool copy_bsd_info(pid_t pid, struct codex_proc_bsdinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDTBSDINFO, 0, information,
                              (int)sizeof(*information));
    return amount == (int)sizeof(*information) &&
           information->pbi_pid == (uint32_t)pid;
}

static bool copy_unique_info(
    pid_t pid, struct codex_proc_uniqidentifierinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information);
}

static bool unique_identity_equal(
    const struct codex_proc_uniqidentifierinfo *left,
    const struct codex_proc_uniqidentifierinfo *right) {
    return left->unique_id == right->unique_id &&
           left->pid_version == right->pid_version &&
           left->parent_unique_id == right->parent_unique_id &&
           memcmp(left->uuid, right->uuid, sizeof(left->uuid)) == 0;
}

static bool candidate_controller_lineage_exact(
    const struct codex_proc_bsdinfo *candidate, pid_t *tracerPidOut) {
#if defined(CODEX_CANDIDATE_BRIDGE_BUILD)
    /* The carrier bridge executes directly in the ptrauth-authorized worker
       which was spawned by the candidate controller.  Bind that exact
       one-hop lineage; the normal worker-hosted loader uses the two-hop
       relationship below. */
    pid_t controllerPid = getppid();
    struct codex_proc_bsdinfo controller = {0};
    bool valid = controllerPid > 1 &&
                 copy_bsd_info(controllerPid, &controller) &&
                 controller.pbi_uid == 0 &&
                 candidate->pbi_ppid == (uint32_t)controllerPid;
    if (valid && tracerPidOut != NULL) {
        *tracerPidOut = controllerPid;
    }
    return valid;
#else
    pid_t workerPid = getppid();
    struct codex_proc_bsdinfo worker = {0};
    bool valid = workerPid > 1 && copy_bsd_info(workerPid, &worker) &&
                 worker.pbi_uid == 0 && worker.pbi_ppid > 1 &&
                 candidate->pbi_ppid == worker.pbi_ppid;
    if (valid && tracerPidOut != NULL) {
        *tracerPidOut = (pid_t)worker.pbi_ppid;
    }
    return valid;
#endif
}

static bool secure_candidate_status(const struct stat *status) {
    return S_ISREG(status->st_mode) && status->st_uid == 0 &&
           status->st_nlink == 1 && (status->st_mode & 0022) == 0 &&
           (status->st_mode & 0111) != 0 && status->st_size >= 0 &&
           (uint64_t)status->st_size == CODEX_EXPECTED_CANDIDATE_SIZE;
}

static bool candidate_status_equal(const struct stat *left,
                                   const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_size == right->st_size &&
           left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid && left->st_nlink == right->st_nlink &&
           left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static bool sha256_descriptor(int descriptor,
                              uint8_t digest[CODEX_SHA256_SIZE]) {
    if (lseek(descriptor, 0, SEEK_SET) < 0) {
        return false;
    }
    CC_SHA256_CTX context;
    if (CC_SHA256_Init(&context) != 1) {
        return false;
    }
    uint8_t buffer[64U * 1024U];
    for (;;) {
        ssize_t amount = read(descriptor, buffer, sizeof(buffer));
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0 ||
            (amount > 0 &&
             CC_SHA256_Update(&context, buffer, (CC_LONG)amount) != 1)) {
            return false;
        }
        if (amount == 0) {
            break;
        }
    }
    bool valid = CC_SHA256_Final(digest, &context) == 1;
    return lseek(descriptor, 0, SEEK_SET) >= 0 && valid;
}

static bool descriptor_has_springboard_uuid(int descriptor) {
    struct mach_header_64 header = {0};
    if (pread(descriptor, &header, sizeof(header), 0) !=
            (ssize_t)sizeof(header) ||
        header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        (header.cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E ||
        header.filetype != MH_EXECUTE || header.ncmds == 0 ||
        header.ncmds > 4096U || header.sizeofcmds == 0 ||
        header.sizeofcmds > 16U * 1024U * 1024U) {
        return false;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL) {
        return false;
    }
    bool valid = pread(descriptor, commands, header.sizeofcmds,
                       sizeof(header)) == (ssize_t)header.sizeofcmds;
    bool foundUUID = false;
    size_t offset = 0;
    for (uint32_t index = 0; valid && index < header.ncmds; ++index) {
        if (offset > header.sizeofcmds ||
            header.sizeofcmds - offset < sizeof(struct load_command)) {
            valid = false;
            break;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(*command) ||
            (command->cmdsize & 7U) != 0 ||
            command->cmdsize > header.sizeofcmds - offset) {
            valid = false;
            break;
        }
        if (command->cmd == LC_UUID) {
            if (foundUUID ||
                command->cmdsize != sizeof(struct uuid_command)) {
                valid = false;
                break;
            }
            const struct uuid_command *uuidCommand =
                (const struct uuid_command *)command;
            foundUUID = true;
            valid = memcmp(uuidCommand->uuid, kSpringBoardUUID,
                           sizeof(kSpringBoardUUID)) == 0;
        }
        offset += command->cmdsize;
    }
    valid = valid && foundUUID && offset == header.sizeofcmds;
    free(commands);
    return valid;
}

static int read_candidate_cdhash(pid_t pid,
                                 uint8_t cdhash[CODEX_CDHASH_SIZE],
                                 int *errorOut) {
    int result = -1;
    int savedError = 0;
    do {
        memset(cdhash, 0, CODEX_CDHASH_SIZE);
        errno = 0;
        result = csops(pid, CODEX_CS_OPS_CDHASH, cdhash,
                       CODEX_CDHASH_SIZE);
        savedError = result == 0 ? 0 : errno;
    } while (result != 0 && savedError == EINTR);
    if (errorOut != NULL) {
        *errorOut = savedError;
    }
    return result;
}

static bool bind_exact_gated_candidate(pid_t pid, char path[PATH_MAX]) {
    if (gGatedCandidate.descriptor >= 0) {
        close(gGatedCandidate.descriptor);
    }
    memset(&gGatedCandidate, 0, sizeof(gGatedCandidate));
    gGatedCandidate.descriptor = -1;

    char fixedPath[PATH_MAX] = {0};
    char secondPath[PATH_MAX] = {0};
    int pathLength = proc_pidpath(pid, path, PATH_MAX);
    bool pathExact = pathLength > 0 && (size_t)pathLength < PATH_MAX &&
                     realpath(kSpringBoardCandidatePath, fixedPath) != NULL &&
                     strcmp(path, fixedPath) == 0;

    struct codex_proc_bsdinfo bsd = {0};
    struct codex_proc_uniqidentifierinfo firstUnique = {0};
    struct codex_proc_uniqidentifierinfo secondUnique = {0};
    bool bsdValid = copy_bsd_info(pid, &bsd);
    pid_t tracerPid = -1;
    bool lineageValid = bsdValid && bsd.pbi_uid == 501 &&
                        candidate_controller_lineage_exact(&bsd, &tracerPid);
    bool firstUniqueValid = copy_unique_info(pid, &firstUnique);
    bool secondUniqueValid = copy_unique_info(pid, &secondUnique);
    bool uniqueValid = firstUniqueValid && secondUniqueValid &&
                       unique_identity_equal(&firstUnique, &secondUnique) &&
                       memcmp(firstUnique.uuid, kSpringBoardUUID,
                              sizeof(kSpringBoardUUID)) == 0;

    uint32_t flags = 0;
    bool flagsValid =
        csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
        (flags & (CODEX_CS_VALID | CODEX_CS_DEBUGGED)) ==
            (CODEX_CS_VALID | CODEX_CS_DEBUGGED) &&
        (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;

    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    int cdhashError = 0;
    int cdhashResult = read_candidate_cdhash(pid, cdhash, &cdhashError);
    bool cdhashMatches =
        cdhashResult == 0 &&
        memcmp(cdhash, kSpringBoardCandidateCDHash, sizeof(cdhash)) == 0;
    bool cdhashFallback = cdhashResult != 0 && cdhashError == EBADEXEC;
    bool cdhashAccepted = cdhashMatches || cdhashFallback;

    int descriptor = pathExact
                         ? open(fixedPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
                         : -1;
    struct stat descriptorStatus = {0};
    struct stat pathStatus = {0};
    uint8_t sha256[CODEX_SHA256_SIZE] = {0};
    bool fileExact =
        descriptor >= 0 && fstat(descriptor, &descriptorStatus) == 0 &&
        stat(path, &pathStatus) == 0 &&
        secure_candidate_status(&descriptorStatus) &&
        candidate_status_equal(&descriptorStatus, &pathStatus) &&
        sha256_descriptor(descriptor, sha256) &&
        memcmp(sha256, kSpringBoardCandidateSHA256, sizeof(sha256)) == 0 &&
        descriptor_has_springboard_uuid(descriptor);

    int secondPathLength = proc_pidpath(pid, secondPath, PATH_MAX);
    bool stablePath = pathExact && secondPathLength > 0 &&
                      (size_t)secondPathLength < PATH_MAX &&
                      strcmp(path, secondPath) == 0;
    bool admitted = pid > 1 && stablePath && lineageValid && uniqueValid &&
                    flagsValid && fileExact && cdhashAccepted;

    char cdhashHex[CODEX_CDHASH_SIZE * 2U + 1U] = {0};
    for (size_t index = 0; index < sizeof(cdhash); ++index) {
        (void)snprintf(cdhashHex + index * 2U, 3U, "%02x", cdhash[index]);
    }
    fprintf(stderr,
            "compat-loader: gated-candidate-admission pid=%d admitted=%s "
            "pathExact=%s fileExact=%s stablePath=%s uid=%u ppid=%u "
            "lineage=%s unique=%s pidVersion=%d flags=0x%08x "
            "flagsValid=%s cdhashResult=%d cdhashErrno=%d "
            "cdhash=%s cdhashMatches=%s fallback=%s path=%s fixed=%s\n",
            pid, admitted ? "true" : "false",
            pathExact ? "true" : "false", fileExact ? "true" : "false",
            stablePath ? "true" : "false", bsd.pbi_uid, bsd.pbi_ppid,
            lineageValid ? "true" : "false",
            uniqueValid ? "true" : "false", firstUnique.pid_version, flags,
            flagsValid ? "true" : "false", cdhashResult, cdhashError,
            cdhashHex, cdhashMatches ? "true" : "false",
            cdhashFallback && admitted ? "true" : "false", path,
            fixedPath);
    unified_loader_log(
        "elleKitGatedCandidateAdmission pid=%d admitted=%s pathExact=%s "
        "fileExact=%s stablePath=%s uid=%u ppid=%u lineage=%s unique=%s "
        "pidVersion=%d flags=0x%08x flagsValid=%s cdhashResult=%d "
        "cdhashErrno=%d cdhash=%s cdhashMatches=%s fallback=%s",
        pid, admitted ? "true" : "false", pathExact ? "true" : "false",
        fileExact ? "true" : "false", stablePath ? "true" : "false",
        bsd.pbi_uid, bsd.pbi_ppid, lineageValid ? "true" : "false",
        uniqueValid ? "true" : "false", firstUnique.pid_version, flags,
        flagsValid ? "true" : "false", cdhashResult, cdhashError, cdhashHex,
        cdhashMatches ? "true" : "false",
        cdhashFallback && admitted ? "true" : "false");
    if (!admitted) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return false;
    }

    gGatedCandidate.valid = true;
    gGatedCandidate.cdhash_fallback = cdhashFallback;
    gGatedCandidate.pid = pid;
    gGatedCandidate.tracer_pid = tracerPid;
    memcpy(gGatedCandidate.path, path, sizeof(gGatedCandidate.path));
    gGatedCandidate.unique = firstUnique;
    gGatedCandidate.status = descriptorStatus;
    gGatedCandidate.descriptor = descriptor;
    return true;
}

static bool gated_candidate_still_exact(pid_t pid, char path[PATH_MAX],
                                        bool rehash) {
    if (!gGatedCandidate.valid || gGatedCandidate.pid != pid ||
        gGatedCandidate.descriptor < 0) {
        return false;
    }
    int pathLength = proc_pidpath(pid, path, PATH_MAX);
    struct codex_proc_bsdinfo bsd = {0};
    struct codex_proc_uniqidentifierinfo unique = {0};
    struct stat descriptorStatus = {0};
    struct stat pathStatus = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    int cdhashError = 0;
    int cdhashResult = read_candidate_cdhash(pid, cdhash, &cdhashError);
    bool cdhashValid =
        (cdhashResult == 0 &&
         memcmp(cdhash, kSpringBoardCandidateCDHash, sizeof(cdhash)) == 0) ||
        (gGatedCandidate.cdhash_fallback && cdhashResult != 0 &&
         cdhashError == EBADEXEC);
    bool identityValid =
        pathLength > 0 && (size_t)pathLength < PATH_MAX &&
        strcmp(path, gGatedCandidate.path) == 0 &&
        copy_bsd_info(pid, &bsd) && bsd.pbi_uid == 501 &&
        (bsd.pbi_ppid == (uint32_t)gGatedCandidate.tracer_pid ||
         bsd.pbi_ppid == 1U) &&
        copy_unique_info(pid, &unique) &&
        unique_identity_equal(&unique, &gGatedCandidate.unique) &&
        fstat(gGatedCandidate.descriptor, &descriptorStatus) == 0 &&
        stat(path, &pathStatus) == 0 &&
        secure_candidate_status(&descriptorStatus) &&
        candidate_status_equal(&descriptorStatus, &gGatedCandidate.status) &&
        candidate_status_equal(&descriptorStatus, &pathStatus) &&
        csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
        (flags & (CODEX_CS_VALID | CODEX_CS_DEBUGGED)) ==
            (CODEX_CS_VALID | CODEX_CS_DEBUGGED) &&
        (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0 && cdhashValid;
    if (!identityValid || !rehash) {
        return identityValid;
    }
    uint8_t sha256[CODEX_SHA256_SIZE] = {0};
    return sha256_descriptor(gGatedCandidate.descriptor, sha256) &&
           memcmp(sha256, kSpringBoardCandidateSHA256, sizeof(sha256)) == 0 &&
           descriptor_has_springboard_uuid(gGatedCandidate.descriptor);
}

static bool gated_candidate_task_exact(task_t task) {
    if (!gGatedCandidate.valid || !MACH_PORT_VALID(task)) {
        return false;
    }
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t result = task_info(task, TASK_AUDIT_TOKEN,
                                     (task_info_t)&token, &count);
    return result == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT &&
           (pid_t)token.val[5] == gGatedCandidate.pid &&
           (int32_t)token.val[7] == gGatedCandidate.unique.pid_version;
}

static bool supported_target_path(const char *path) {
    return strcmp(path,
                  "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ==
               0 ||
           strcmp(path, "/usr/libexec/lsd") == 0 ||
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
    return !fixed_springboard_candidate_path(path) ||
           exact_springboard_candidate(pid, path);
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

static int run_page_probe(task_t task, pid_t pid, const char *expectedPath,
                          vm_address_t allImageInfoAddress) {
    static const uint32_t kReturn42[] = {
        0xd503245f, /* bti c */
        0x52800540, /* mov w0, #42 */
        0xd65f03c0, /* ret */
    };
    const mach_vm_size_t pageSize = (mach_vm_size_t)getpagesize();
    mach_vm_address_t executeAddress = 0;
    mach_vm_address_t verificationAddress = 0;
    thread_act_t remoteThread = MACH_PORT_NULL;
    vm_prot_t verificationCurrent = VM_PROT_NONE;
    vm_prot_t verificationMaximum = VM_PROT_NONE;
    uint32_t readback[sizeof(kReturn42) / sizeof(kReturn42[0])] = {0};
    mach_vm_size_t readSize = 0;
    uint64_t callReturn = UINT64_MAX;
    kern_return_t allocateResult = KERN_INVALID_ARGUMENT;
    kern_return_t executeProtectResult = KERN_INVALID_ARGUMENT;
    kern_return_t writeProtectResult = KERN_INVALID_ARGUMENT;
    kern_return_t codeWriteResult = KERN_INVALID_ARGUMENT;
    kern_return_t flushResult = KERN_INVALID_ARGUMENT;
    kern_return_t readResult = KERN_INVALID_ARGUMENT;
    kern_return_t verificationRemapResult = KERN_INVALID_ARGUMENT;
    kern_return_t threadResult = KERN_INVALID_ARGUMENT;
    kern_return_t callResult = KERN_INVALID_ARGUMENT;
    int status = 88;

    if (pageSize == 0 || pageSize > 64U * 1024U ||
        (pageSize & (pageSize - 1U)) != 0) {
        fprintf(stderr, "compat-loader: page probe rejected page size 0x%llx\n",
                (unsigned long long)pageSize);
        return 81;
    }

    allocateResult = mach_vm_allocate(task, &executeAddress, pageSize,
                                      VM_FLAGS_ANYWHERE);
    if (allocateResult != KERN_SUCCESS) {
        status = 82;
        goto finished;
    }

    /* Match the present hookd patch sequence: make the mapping writable with
     * copy semantics, write the bytes, and only then request RX.  The public
     * mach_vm_protect order remains task, address, size, set_maximum,
     * protection.  Requesting RX before mach_vm_write makes the write fail
     * even for an already-authorized debugger target. */
    writeProtectResult = mach_vm_protect(
        task, executeAddress, pageSize, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (writeProtectResult != KERN_SUCCESS) {
        status = 84;
        goto finished;
    }

    codeWriteResult = mach_vm_write(
        task, executeAddress, (vm_offset_t)(uintptr_t)kReturn42,
        (mach_msg_type_number_t)sizeof(kReturn42));
    if (codeWriteResult != KERN_SUCCESS) {
        status = 87;
        goto finished;
    }
    vm_machine_attribute_val_t cacheValue = MATTR_VAL_CACHE_FLUSH;
    flushResult = vm_machine_attribute(
        task, (vm_address_t)executeAddress, (vm_size_t)pageSize,
        MATTR_CACHE, &cacheValue);
    readResult = mach_vm_read_overwrite(
        task, executeAddress, sizeof(readback),
        (mach_vm_address_t)(uintptr_t)readback, &readSize);
    if (flushResult != KERN_SUCCESS || readResult != KERN_SUCCESS ||
        readSize != sizeof(readback) ||
        memcmp(readback, kReturn42, sizeof(kReturn42)) != 0) {
        status = 87;
        goto finished;
    }

    executeProtectResult = mach_vm_protect(
        task, executeAddress, pageSize, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    if (executeProtectResult != KERN_SUCCESS) {
        status = 83;
        goto finished;
    }

    /* Re-query the mapping after the RX transition. Never branch into the page
     * unless the kernel reports that execute permission actually survived. */
    verificationRemapResult = mach_vm_remap(
        task, &verificationAddress, pageSize, 0, VM_FLAGS_ANYWHERE, task,
        executeAddress, FALSE, &verificationCurrent, &verificationMaximum,
        VM_INHERIT_NONE);
    if (verificationRemapResult != KERN_SUCCESS) {
        status = 93;
        goto finished;
    }
    if ((verificationCurrent & (VM_PROT_READ | VM_PROT_EXECUTE)) !=
        (VM_PROT_READ | VM_PROT_EXECUTE)) {
        status = 94;
        goto finished;
    }

    char currentPath[PATH_MAX];
    if (!read_supported_target(pid, currentPath) ||
        strcmp(currentPath, expectedPath) != 0) {
        status = 89;
        goto finished;
    }

    prepareForMagic(task, allImageInfoAddress);
    threadResult = createRemotePthread(task, allImageInfoAddress,
                                       &remoteThread);
    if (threadResult != KERN_SUCCESS || !MACH_PORT_VALID(remoteThread)) {
        status = 90;
        goto finished;
    }
    callResult = arbCall(task, remoteThread, &callReturn, true,
                         (vm_address_t)executeAddress, 0);
    status = callResult == KERN_SUCCESS && callReturn == 42 ? 0 : 91;

finished:
    printf("compat-loader: page-probe pid=%d status=%d page=0x%llx "
           "verify=0x%llx pageSize=0x%llx allocateKr=%d writeProtectKr=%d "
           "codeWriteKr=%d flushKr=%d rxKr=%d "
           "readKr=%d readSize=0x%llx verifyRemapKr=%d verifyCurrent=0x%x "
           "verifyMaximum=0x%x threadKr=%d callKr=%d return=%llu\n",
           pid, status, (unsigned long long)executeAddress,
           (unsigned long long)verificationAddress,
           (unsigned long long)pageSize, allocateResult, writeProtectResult,
           codeWriteResult, flushResult, executeProtectResult, readResult,
           (unsigned long long)readSize, verificationRemapResult,
           verificationCurrent, verificationMaximum, threadResult, callResult,
           (unsigned long long)callReturn);
    unified_loader_log(
        "elleKitPageProbe pid=%d status=%d allocate=%d writeProtect=%d "
        "codeWrite=%d flush=%d rx=%d "
        "verifyRemap=%d verifyCurrent=0x%x call=%d return=%llu",
        pid, status, allocateResult, writeProtectResult, codeWriteResult,
        flushResult, executeProtectResult,
        verificationRemapResult, verificationCurrent, callResult,
        (unsigned long long)callReturn);
    if (MACH_PORT_VALID(remoteThread)) {
        (void)thread_terminate(remoteThread);
        (void)mach_port_deallocate(mach_task_self(), remoteThread);
    }
    if (verificationAddress != 0) {
        (void)mach_vm_deallocate(task, verificationAddress, pageSize);
    }
    if (executeAddress != 0) {
        (void)mach_vm_deallocate(task, executeAddress, pageSize);
    }
    return status;
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

static bool parse_pipe_descriptor(const char *text, bool requireWrite,
                                  int *descriptorOut) {
    if (text == NULL || descriptorOut == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= STDERR_FILENO ||
        value > INT_MAX) {
        return false;
    }
    int descriptor = (int)value;
    int statusFlags = fcntl(descriptor, F_GETFL);
    struct stat status = {0};
    if (statusFlags < 0 || fstat(descriptor, &status) != 0 ||
        !S_ISFIFO(status.st_mode)) {
        return false;
    }
    int accessMode = statusFlags & O_ACCMODE;
    if ((requireWrite && accessMode != O_WRONLY && accessMode != O_RDWR) ||
        (!requireWrite && accessMode != O_RDONLY && accessMode != O_RDWR)) {
        return false;
    }
    *descriptorOut = descriptor;
    return true;
}

static bool write_one_byte(int descriptor, uint8_t value) {
    for (;;) {
        ssize_t amount = write(descriptor, &value, sizeof(value));
        if (amount == (ssize_t)sizeof(value)) {
            return true;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
}

static int await_pair_gate(int readyDescriptor, int releaseDescriptor,
                           pid_t targetPid) {
    (void)signal(SIGPIPE, SIG_IGN);
    if (!write_one_byte(readyDescriptor, (uint8_t)'R')) {
        fprintf(stderr, "compat-loader: pid=%d gate ready write failed: %s\n",
                targetPid, strerror(errno));
        return 81;
    }
    close(readyDescriptor);

    struct pollfd releasePoll = {
        .fd = releaseDescriptor,
        .events = POLLIN,
    };
    int pollResult = 0;
    do {
        pollResult = poll(&releasePoll, 1, CODEX_GATE_TIMEOUT_MSEC);
    } while (pollResult < 0 && errno == EINTR);
    uint8_t release = 0;
    ssize_t amount = pollResult > 0 && (releasePoll.revents & POLLIN) != 0
                         ? read(releaseDescriptor, &release, sizeof(release))
                         : -1;
    close(releaseDescriptor);
    if (pollResult <= 0 || amount != (ssize_t)sizeof(release) ||
        release != (uint8_t)'G') {
        fprintf(stderr,
                "compat-loader: pid=%d gate release failed poll=%d "
                "revents=0x%x amount=%zd value=0x%02x errno=%d\n",
                targetPid, pollResult, releasePoll.revents, amount, release,
                pollResult < 0 ? errno : 0);
        return 82;
    }
    return 0;
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

static bool remote_main_uuid_exact(task_t task,
                                   vm_address_t allImageInfoAddress,
                                   const char *targetPath,
                                   vm_address_t *imageOut) {
    if (imageOut != NULL) {
        *imageOut = 0;
    }
    struct dyld_all_image_infos imageInfos = {0};
    struct dyld_image_info firstImage = {0};
    kern_return_t infosResult = read_remote(
        task, allImageInfoAddress, &imageInfos, sizeof(imageInfos));
    mach_vm_address_t infoArray =
        infosResult == KERN_SUCCESS
            ? canonical_remote_pointer((uint64_t)imageInfos.infoArray)
            : 0;
    kern_return_t firstResult =
        infosResult == KERN_SUCCESS && imageInfos.version >= 15U &&
                imageInfos.libSystemInitialized &&
                imageInfos.infoArrayCount != 0U &&
                imageInfos.infoArrayCount <= 4096U && infoArray != 0
            ? read_remote(task, infoArray, &firstImage, sizeof(firstImage))
            : KERN_INVALID_ADDRESS;
    vm_address_t image =
        firstResult == KERN_SUCCESS
            ? (vm_address_t)canonical_remote_pointer(
                  (uint64_t)firstImage.imageLoadAddress)
            : 0;
    char firstPath[PATH_MAX] = {0};
    kern_return_t firstPathResult = KERN_INVALID_ADDRESS;
    mach_vm_address_t firstPathAddress =
        firstResult == KERN_SUCCESS
            ? canonical_remote_pointer((uint64_t)firstImage.imageFilePath)
            : 0;
    if (firstPathAddress != 0) {
        firstPathResult = read_remote(task, firstPathAddress, firstPath,
                                      sizeof(firstPath) - 1U);
    }
    fprintf(stderr,
            "compat-loader: main image first-slot image=0x%llx "
            "infosKr=%d firstKr=%d pathKr=%d path=%s\n",
            (unsigned long long)image, infosResult, firstResult,
            firstPathResult,
            firstPathResult == KERN_SUCCESS ? firstPath : "<unreadable>");
    if (image == 0) {
        image = getRemoteImageAddress(task, allImageInfoAddress, targetPath);
        if (image == 0) {
            image = getRemoteImageAddress(task, allImageInfoAddress,
                                          kSpringBoardCandidatePath);
        }
    }
    struct mach_header_64 header = {0};
    if (image == 0 ||
        read_remote(task, image, &header, sizeof(header)) != KERN_SUCCESS ||
        header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        (header.cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E ||
        header.filetype != MH_EXECUTE || header.ncmds == 0 ||
        header.ncmds > 4096U || header.sizeofcmds < sizeof(struct load_command) ||
        header.sizeofcmds > 16U * 1024U * 1024U) {
        return false;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL) {
        return false;
    }
    bool valid =
        read_remote(task, image + sizeof(header), commands,
                    header.sizeofcmds) == KERN_SUCCESS;
    bool foundUUID = false;
    size_t offset = 0;
    for (uint32_t index = 0; valid && index < header.ncmds; ++index) {
        if (offset > header.sizeofcmds ||
            header.sizeofcmds - offset < sizeof(struct load_command)) {
            valid = false;
            break;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(*command) ||
            (command->cmdsize & 7U) != 0 ||
            command->cmdsize > header.sizeofcmds - offset) {
            valid = false;
            break;
        }
        if (command->cmd == LC_UUID) {
            if (foundUUID ||
                command->cmdsize != sizeof(struct uuid_command)) {
                valid = false;
                break;
            }
            const struct uuid_command *uuidCommand =
                (const struct uuid_command *)command;
            foundUUID = true;
            valid = memcmp(uuidCommand->uuid, kSpringBoardUUID,
                           sizeof(kSpringBoardUUID)) == 0;
        }
        offset += command->cmdsize;
    }
    valid = valid && foundUUID && offset == header.sizeofcmds;
    free(commands);
    if (valid && imageOut != NULL) {
        *imageOut = image;
    }
    return valid;
}

static bool gated_remote_identity_exact(task_t task, pid_t pid,
                                        const char *targetPath,
                                        vm_address_t allImageInfoAddress,
                                        bool rehash) {
    char currentPath[PATH_MAX] = {0};
    vm_address_t image = 0;
    return gated_candidate_still_exact(pid, currentPath, rehash) &&
           strcmp(currentPath, targetPath) == 0 &&
           gated_candidate_task_exact(task) &&
           remote_main_uuid_exact(task, allImageInfoAddress, targetPath,
                                  &image);
}

static bool remote_runtime_ready(task_t task, const char *targetPath,
                                 task_dyld_info_data_t *dyldInfoOut) {
    task_basic_info_data_t basicInfo = {0};
    mach_msg_type_number_t basicCount = TASK_BASIC_INFO_COUNT;
    kern_return_t basicResult = task_info(
        task, TASK_BASIC_INFO, (task_info_t)&basicInfo, &basicCount);
    if (basicResult != KERN_SUCCESS || basicCount < TASK_BASIC_INFO_COUNT ||
        basicInfo.suspend_count != 0) {
        fprintf(stderr,
                "compat-loader: runtime-ready stage=basic kr=%d count=%u "
                "suspend=%d\n",
                basicResult, basicCount, basicInfo.suspend_count);
        return false;
    }
    task_dyld_info_data_t dyldInfo = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(task, TASK_DYLD_INFO,
                                     (task_info_t)&dyldInfo, &count);
    if (result != KERN_SUCCESS || count < TASK_DYLD_INFO_COUNT ||
        dyldInfo.all_image_info_addr == 0 ||
        dyldInfo.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64 ||
        dyldInfo.all_image_info_size < sizeof(struct dyld_all_image_infos)) {
        fprintf(stderr,
                "compat-loader: runtime-ready stage=dyld-info kr=%d "
                "count=%u address=0x%llx size=%llu format=%d\n",
                result, count,
                (unsigned long long)dyldInfo.all_image_info_addr,
                (unsigned long long)dyldInfo.all_image_info_size,
                dyldInfo.all_image_info_format);
        return false;
    }
    struct dyld_all_image_infos first = {0};
    struct dyld_all_image_infos second = {0};
    kern_return_t firstResult = read_remote(
        task, dyldInfo.all_image_info_addr, &first, sizeof(first));
    if (firstResult != KERN_SUCCESS ||
        first.version < 15 || !first.libSystemInitialized ||
        first.infoArray == NULL || first.infoArrayCount == 0) {
        fprintf(stderr,
                "compat-loader: runtime-ready stage=first kr=%d version=%u "
                "libSystem=%d array=%p count=%u\n",
                firstResult, first.version, first.libSystemInitialized,
                first.infoArray, first.infoArrayCount);
        return false;
    }
    usleep(CODEX_RUNTIME_READY_DELAY_USEC);
    kern_return_t secondResult = read_remote(
        task, dyldInfo.all_image_info_addr, &second, sizeof(second));
    bool stableSnapshot =
        secondResult == KERN_SUCCESS && second.version == first.version &&
        second.libSystemInitialized && second.infoArray != NULL &&
        second.infoArrayCount != 0 && first.infoArray == second.infoArray &&
        first.infoArrayCount == second.infoArrayCount &&
        first.infoArrayChangeTimestamp == second.infoArrayChangeTimestamp &&
        first.sharedCacheBaseAddress == second.sharedCacheBaseAddress &&
        memcmp(first.sharedCacheUUID, second.sharedCacheUUID,
               sizeof(first.sharedCacheUUID)) == 0;
    if (!stableSnapshot) {
        fprintf(stderr,
                "compat-loader: runtime-ready stage=stable kr=%d "
                "versions=%u/%u libSystem=%d arrays=%p/%p counts=%u/%u "
                "timestamps=%llu/%llu cache=0x%llx/0x%llx uuidMatch=%d\n",
                secondResult, first.version, second.version,
                second.libSystemInitialized, first.infoArray,
                second.infoArray, first.infoArrayCount,
                second.infoArrayCount,
                (unsigned long long)first.infoArrayChangeTimestamp,
                (unsigned long long)second.infoArrayChangeTimestamp,
                (unsigned long long)first.sharedCacheBaseAddress,
                (unsigned long long)second.sharedCacheBaseAddress,
                memcmp(first.sharedCacheUUID, second.sharedCacheUUID,
                       sizeof(first.sharedCacheUUID)) == 0);
        return false;
    }
    vm_address_t mainImage = 0;
    bool mainExact = remote_main_uuid_exact(
        task, dyldInfo.all_image_info_addr, targetPath, &mainImage);
    bool primitivesExact =
        mainExact && codexValidateInjectionPrimitives(
                          task, dyldInfo.all_image_info_addr);
    if (!mainExact || !primitivesExact) {
        fprintf(stderr,
                "compat-loader: runtime-ready stage=identity main=%d "
                "image=0x%llx primitives=%d\n",
                mainExact, (unsigned long long)mainImage, primitivesExact);
        return false;
    }
    *dyldInfoOut = dyldInfo;
    return true;
}

static bool wait_for_remote_runtime(task_t task, pid_t targetPid,
                                    const char *targetPath,
                                    task_dyld_info_data_t *dyldInfoOut) {
    for (unsigned int attempt = 0; attempt < CODEX_RUNTIME_READY_ATTEMPTS;
         ++attempt) {
        char currentPath[PATH_MAX] = {0};
        if (!gated_candidate_still_exact(targetPid, currentPath, false) ||
            strcmp(currentPath, targetPath) != 0) {
            return false;
        }
        if (remote_runtime_ready(task, targetPath, dyldInfoOut)) {
            printf("compat-loader: pid=%d runtime ready attempt=%u "
                   "dyld=0x%llx\n",
                   targetPid, attempt + 1U,
                   (unsigned long long)dyldInfoOut->all_image_info_addr);
            return true;
        }
        usleep(CODEX_RUNTIME_READY_DELAY_USEC);
    }
    return false;
}

static bool copy_exact_controller_held_thread(task_t task,
                                              thread_act_t *threadOut) {
    return codexCopyExactMainHeldThread(task, threadOut);
}

static bool inject_image_and_wait(task_t task, pid_t targetPid,
                                  const char *targetPath,
                                  vm_address_t allImageInfoAddress,
                                  const char *resolvedPath) {
    if (!gated_remote_identity_exact(task, targetPid, targetPath,
                                     allImageInfoAddress, true)) {
        return false;
    }
    if (image_is_loaded(task, allImageInfoAddress, resolvedPath)) {
        return true;
    }
    printf("compat-loader: injecting %s into pid %d path=%s\n",
           resolvedPath, targetPid, targetPath);
    thread_act_t heldThread = MACH_PORT_NULL;
    bool injected = copy_exact_controller_held_thread(task, &heldThread) &&
                    codexInjectDylibViaHeldThread(
                        task, heldThread, targetPid, resolvedPath,
                        allImageInfoAddress);
    if (MACH_PORT_VALID(heldThread)) {
        (void)mach_port_deallocate(mach_task_self(), heldThread);
    }
    if (!injected) {
        return false;
    }
    for (unsigned int attempt = 0; attempt < CODEX_IMAGE_READY_ATTEMPTS;
         ++attempt) {
        if (!gated_remote_identity_exact(task, targetPid, targetPath,
                                         allImageInfoAddress, false)) {
            return false;
        }
        if (image_is_loaded(task, allImageInfoAddress, resolvedPath)) {
            return true;
        }
        usleep(CODEX_IMAGE_READY_DELAY_USEC);
    }
    return false;
}

static int verify_remote_dyld_hook(task_t task, pid_t pid,
                                   vm_address_t allImageInfoAddress,
                                   const char *resolvedPath,
                                   const char *targetPath,
                                   bool requireGatedIdentity) {
    vm_address_t image = getRemoteImageAddress(
        task, allImageInfoAddress, resolvedPath);
    vm_address_t statusFunction = image != 0
        ? remoteDlSym(task, image,
                      "_codex_dyld_jb_hook_status_word")
        : 0;
    thread_act_t remoteThread = MACH_PORT_NULL;
    uint64_t statusWord = UINT64_MAX;
    kern_return_t threadResult = KERN_INVALID_ARGUMENT;
    kern_return_t callResult = KERN_INVALID_ARGUMENT;
    bool borrowedThread = false;
    bool identityBeforeThread =
        !requireGatedIdentity ||
        gated_remote_identity_exact(task, pid, targetPath,
                                    allImageInfoAddress, true);
    if (statusFunction != 0 && identityBeforeThread) {
        if (requireGatedIdentity) {
            borrowedThread = copy_exact_controller_held_thread(
                task, &remoteThread);
            threadResult = borrowedThread ? KERN_SUCCESS : KERN_FAILURE;
        } else {
            prepareForMagic(task, allImageInfoAddress);
            threadResult = createRemotePthread(task, allImageInfoAddress,
                                               &remoteThread);
        }
    }
    bool identityBeforeCall =
        !requireGatedIdentity ||
        gated_remote_identity_exact(task, pid, targetPath,
                                    allImageInfoAddress, false);
    if (threadResult == KERN_SUCCESS && MACH_PORT_VALID(remoteThread) &&
        identityBeforeCall) {
        callResult = borrowedThread
                         ? codexArbCallHeldThread(
                               task, remoteThread, &statusWord,
                               statusFunction, 0)
                         : arbCall(task, remoteThread, &statusWord, true,
                                   statusFunction, 0);
    }
    uint32_t state = (uint32_t)(statusWord >> 32U);
    uint32_t error = (uint32_t)statusWord;
    bool installed = image != 0 && statusFunction != 0 &&
                     threadResult == KERN_SUCCESS &&
                     callResult == KERN_SUCCESS && identityBeforeThread &&
                     identityBeforeCall && state == 2U && error == 0U;
    printf("compat-loader: pid=%d dyld-hook image=0x%llx "
           "statusFunction=0x%llx threadKr=%d callKr=%d "
           "identityBeforeThread=%s identityBeforeCall=%s "
           "status=0x%016llx state=%u error=%u installed=%s\n",
           pid, (unsigned long long)image,
           (unsigned long long)statusFunction, threadResult, callResult,
           identityBeforeThread ? "true" : "false",
           identityBeforeCall ? "true" : "false",
           (unsigned long long)statusWord, state, error,
           installed ? "true" : "false");
    unified_loader_log(
        "elleKitDyldHookStatus pid=%d image=0x%llx symbol=0x%llx "
        "thread=%d call=%d identityBeforeThread=%s identityBeforeCall=%s "
        "state=%u error=%u installed=%s",
        pid, (unsigned long long)image,
        (unsigned long long)statusFunction, threadResult, callResult,
        identityBeforeThread ? "true" : "false",
        identityBeforeCall ? "true" : "false",
        state, error, installed ? "true" : "false");
    if (MACH_PORT_VALID(remoteThread)) {
        if (!borrowedThread) {
            (void)thread_terminate(remoteThread);
        }
        (void)mach_port_deallocate(mach_task_self(), remoteThread);
    }
    return installed ? 0 : 76;
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
        bool pageProbePid = userArgumentCount == 3 &&
                            strcmp(argv[1], kPageProbePid) == 0;
        if (!inspectOnly && !preflightOnly && !checkPidImage && !injectPid &&
            !injectLaunchdHook && !pageProbePid) {
            fprintf(stderr,
                    "usage: %s --inspect-pid pid|--preflight-pid pid|"
                    "--check-pid-image pid absolute-image-path|"
                    "--inject-pid pid absolute-dylib-path|"
                    "--inject-launchd-hook|"
                    "--page-probe-pid pid\n",
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
        if ((injectPid || pageProbePid) && springBoardTarget) {
            fprintf(stderr,
                    "compat-loader: post-start SpringBoard mutation is disabled; "
                    "use the SBInject pre-main path\n");
            return 65;
        }
        bool runtimeMutation = injectPid || injectLaunchdHook || pageProbePid;
        bool softened = true;
        if (runtimeMutation && !injectLaunchdHook && !isPtrauthChild) {
            softened = soften_target(targetPid, targetPath);
        }
        if (runtimeMutation && !isPtrauthChild && !softened) {
            if (pageProbePid) {
                fprintf(stderr,
                        "compat-loader: pid=%d debugged admission unavailable; "
                        "refusing executable-page probe\n",
                        targetPid);
                return 79;
            }
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

        if (pageProbePid) {
            int preflightResult = preflight_remote_symbols(
                targetTask, dyldInfo.all_image_info_addr);
            int pageProbeResult =
                preflightResult == 0
                    ? run_page_probe(targetTask, targetPid, targetPath,
                                     dyldInfo.all_image_info_addr)
                    : preflightResult;
            mach_port_deallocate(mach_task_self(), targetTask);
            return pageProbeResult;
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
