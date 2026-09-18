#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/arm/thread_status.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CODEX_PT_CONTINUE 7
#define CODEX_PT_KILL 8
#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_WAIT_ATTEMPTS 500U
#define CODEX_WAIT_DELAY_USEC (10U * 1000U)
#define CODEX_MAX_DYLIB_SIZE (16U * 1024U * 1024U)
#define CODEX_HWBP_CONTROL 0x1e7ULL
#define CODEX_INJECT_TIMEOUT_ATTEMPTS 3000U
#define CODEX_EXCEPTION_MESSAGE_SIZE (16U * 1024U)
#define CODEX_REMOTE_PORT_INDEX_BASE 0x7000U
#define CODEX_REMOTE_THREAD_PORT_INDEX_BASE 0x8000U
#define CODEX_REMOTE_PORT_ATTEMPTS 4096U
#define CODEX_REMOTE_THREAD_PORT_ATTEMPTS 64U
#define CODEX_HARDENED_BEHAVIOR                                      \
    ((exception_behavior_t)(EXCEPTION_STATE_IDENTITY_PROTECTED |     \
                            MACH_EXCEPTION_CODES))

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kLoaderPath =
    "/var/jb/usr/libexec/codex-ellekit-loader";
static const char *const kSocketPath =
    "/var/run/codex-runtime-broker.sock";
static const char *const kMarkerPath =
    "/var/tmp/codex-runtime-carrier.loaded";
static const char *const kLogPath =
    "/var/tmp/codex-runtime-broker.log";
static const char *const kStartupProofPath =
    "/var/jb/usr/lib/codex-springboard-dynamic-proof.dylib";

static const uint8_t kMmapPattern[8] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
static const uint8_t kMmapOriginal[20] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
    0x03, 0x01, 0x00, 0x54, 0x7f, 0x23, 0x03, 0xd5,
    0xfd, 0x7b, 0xbf, 0xa9,
};
static const uint8_t kFcntlPattern[8] = {
    0x90, 0x0b, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
static const uint8_t kResidentRuntimeUUID[16] = {
    0x55, 0xbc, 0xb2, 0x95, 0x6f, 0x34, 0x37, 0xf5,
    0xb1, 0x71, 0x9e, 0x61, 0x3a, 0x0d, 0x2d, 0x5f,
};
static const uint8_t kTrustedBlobPattern[24] = {
    0xdf, 0x24, 0x03, 0xd5, 0x90, 0x02, 0x80, 0xd2,
    0x01, 0x10, 0x00, 0xd4, 0x21, 0x02, 0x80, 0xd2,
    0xb0, 0x04, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
static const uint8_t kTrustedMmapHookPattern[16] = {
    0xdf, 0x24, 0x03, 0xd5, 0xfd, 0x7b, 0xbb, 0xa9,
    0xf3, 0x53, 0x01, 0xa9, 0xf5, 0x5b, 0x02, 0xa9,
};
static const uint8_t kTrustedFcntlHookPattern[16] = {
    0xdf, 0x24, 0x03, 0xd5, 0x3f, 0x84, 0x01, 0x71,
    0x00, 0x01, 0x00, 0x54, 0x3f, 0x88, 0x01, 0x71,
};
static const mach_vm_size_t kTrustedBlobSize = 0x1c8U;
static const char *const kCarrierExecutableSuffix =
    "/procursus/usr/libexec/codex-ellekit-loader";
static const char *const kResidentRuntimeSuffix =
    "/procursus/usr/lib/codex-runtime-carrier.dylib";

extern char **environ;
extern int csops(pid_t, unsigned int, void *, size_t);
extern int ptrace(int, pid_t, caddr_t, int);
extern int proc_listpids(uint32_t, uint32_t, void *, int);
extern int proc_pidpath(int, void *, uint32_t);
extern kern_return_t mach_vm_read_overwrite(
    vm_map_read_t, mach_vm_address_t, mach_vm_size_t,
    mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *,
                                      mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t,
                                        mach_vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t,
                                     mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t,
                                   mach_msg_type_number_t);
extern kern_return_t mach_vm_remap(
    vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int,
    vm_map_t, mach_vm_address_t, boolean_t, vm_prot_t *, vm_prot_t *,
    vm_inherit_t);

extern const uint8_t codex_remote_blob_start[];
extern const uint8_t codex_remote_adopt_gate[];
extern const uint8_t codex_remote_mmap_hook[];
extern const uint8_t codex_remote_fcntl_hook[];
extern const uint8_t codex_remote_blob_end[];

static int gLog = STDERR_FILENO;

struct hook_transaction {
    pid_t pid;
    mach_port_t task;
    mach_vm_address_t code;
    mach_vm_address_t code_page;
    mach_vm_address_t mmap_stub;
    mach_vm_address_t fcntl_stub;
    mach_vm_address_t mmap_original_page;
    mach_vm_address_t fcntl_original_page;
    uint8_t saved_mmap[20];
    uint8_t saved_fcntl[20];
    bool mmap_hooked;
    bool fcntl_hooked;
    bool integrity_lost;
};

struct hwbp_transaction {
    pid_t pid;
    mach_port_t task;
    pid_t donor_pid;
    mach_port_t donor_task;
    mach_vm_address_t donor_blob;
    mach_vm_address_t stop_gate;
    mach_vm_address_t code_page;
    mach_vm_size_t code_page_size;
    mach_vm_address_t mmap_stub;
    mach_vm_address_t fcntl_stub;
    mach_vm_address_t mmap_hook;
    mach_vm_address_t fcntl_hook;
    mach_vm_address_t adopt_gate;
    arm_debug_state64_t saved_debug;
    mach_port_t exception_port;
    mach_port_name_t target_exception_name;
    uint32_t signed_pc_key;
    atomic_uint mmap_hits;
    atomic_uint fcntl_hits;
    atomic_uint unexpected_exceptions;
    bool exception_port_installed;
    bool debug_state_installed;
    atomic_bool exception_failed;
    bool trace_attached;
    bool trace_stopped;
};

struct hardened_handler_state {
    pid_t pid;
    mach_port_t port;
    mach_port_name_t target_name;
    uint32_t signed_pc_key;
    pthread_t thread;
    bool thread_started;
};

static _Atomic(struct hwbp_transaction *) gActiveHwbpTransaction = NULL;
static atomic_uint gExceptionDispatchActive = 0;
static struct hardened_handler_state gHardenedHandler = {
    .pid = -1,
    .port = MACH_PORT_NULL,
    .target_name = MACH_PORT_NULL,
};

extern boolean_t codex_mach_exc_server(mach_msg_header_t *,
                                       mach_msg_header_t *);
extern mach_port_t codex_mach_task_self_function(void)
    __asm("_mach_task_self");

static void broker_log(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    (void)vdprintf(gLog, format, arguments);
    va_end(arguments);
    (void)fsync(gLog);
}

static bool path_has_prefix(const char *path, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(path, prefix, length) == 0;
}

static bool path_has_suffix(const char *path, const char *suffix) {
    size_t path_length = strlen(path);
    size_t suffix_length = strlen(suffix);
    return path_length >= suffix_length &&
        memcmp(path + path_length - suffix_length, suffix,
               suffix_length) == 0;
}

static bool read_exact_process(pid_t pid, const char *expected_path) {
    char path[PATH_MAX] = {0};
    return pid > 1 && proc_pidpath(pid, path, sizeof(path)) > 0 &&
        strcmp(path, expected_path) == 0 &&
        strcmp(path, "/sbin/launchd") != 0 &&
        strcmp(path, "/usr/libexec/launchd") != 0;
}

static bool read_resident_carrier_process(pid_t pid) {
    char path[PATH_MAX] = {0};
    return pid > 1 && pid != getpid() &&
        proc_pidpath(pid, path, sizeof(path)) > 0 &&
        path_has_suffix(path, kCarrierExecutableSuffix) &&
        strcmp(path, "/sbin/launchd") != 0 &&
        strcmp(path, "/usr/libexec/launchd") != 0;
}

static pid_t find_springboard(void) {
    int bytes = proc_listpids(1U, 0U, NULL, 0);
    if (bytes <= 0 || bytes > (int)(1024U * 1024U)) {
        return -1;
    }
    pid_t *pids = calloc(1, (size_t)bytes);
    if (pids == NULL) {
        return -1;
    }
    int filled = proc_listpids(1U, 0U, pids, bytes);
    pid_t result = -1;
    if (filled > 0) {
        size_t count = (size_t)filled / sizeof(pid_t);
        for (size_t index = 0; index < count; ++index) {
            if (read_exact_process(pids[index], kSpringBoardPath)) {
                result = pids[index];
                break;
            }
        }
    }
    free(pids);
    return result;
}

static bool validate_dylib_path(const char *path, char resolved[PATH_MAX]) {
    static const char *const roots[] = {
        "/var/jb/Library/MobileSubstrate/DynamicLibraries/",
        "/var/jb/usr/lib/TweakInject/",
        "/var/jb/Library/TweakInject/",
        "/var/jb/usr/lib/codex-",
    };
    if (path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX) {
        return false;
    }
    bool admitted_root = false;
    for (size_t index = 0; index < sizeof(roots) / sizeof(roots[0]); ++index) {
        if (path_has_prefix(path, roots[index])) {
            admitted_root = true;
            break;
        }
    }
    char managed_root[PATH_MAX] = {0};
    if (!admitted_root || realpath("/var/jb", managed_root) == NULL ||
        realpath(path, resolved) == NULL) {
        return false;
    }
    size_t managed_length = strlen(managed_root);
    bool inside_managed_root = managed_length > 1 &&
        strncmp(resolved, managed_root, managed_length) == 0 &&
        resolved[managed_length] == '/';
    size_t length = strlen(resolved);
    if (!inside_managed_root || length < 7 ||
        strcmp(resolved + length - 6, ".dylib") != 0) {
        return false;
    }
    int descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info = {0};
    bool secure = descriptor >= 0 && fstat(descriptor, &info) == 0 &&
        S_ISREG(info.st_mode) && info.st_uid == 0 &&
        (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 && info.st_size > 0 &&
        (uint64_t)info.st_size <= CODEX_MAX_DYLIB_SIZE;
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    return secure;
}

static kern_return_t read_remote(mach_port_t task,
                                 mach_vm_address_t address,
                                 void *buffer, mach_vm_size_t size) {
    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task, address, size, (mach_vm_address_t)(uintptr_t)buffer, &copied);
    return result == KERN_SUCCESS && copied == size ? KERN_SUCCESS
                                                    : KERN_FAILURE;
}

static mach_vm_address_t canonical_remote_address(uint64_t address) {
    return (mach_vm_address_t)(address & 0x0000ffffffffffffULL);
}

static mach_vm_address_t find_remote_pattern(mach_port_t task,
                                             mach_vm_address_t image,
                                             const uint8_t *pattern,
                                             size_t pattern_size) {
    struct mach_header_64 header = {0};
    if (pattern_size == 0 ||
        read_remote(task, image, &header, sizeof(header)) != KERN_SUCCESS ||
        header.magic != MH_MAGIC_64 || header.ncmds == 0 ||
        header.ncmds > 4096 || header.sizeofcmds == 0 ||
        header.sizeofcmds > 4U * 1024U * 1024U) {
        return 0;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL ||
        read_remote(task, image + sizeof(header), commands,
                    header.sizeofcmds) != KERN_SUCCESS) {
        free(commands);
        return 0;
    }
    uint64_t base_vm_address = 0;
    bool found_base_vm_address = false;
    size_t offset = 0;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        const struct load_command *command =
            offset + sizeof(struct load_command) <= header.sizeofcmds
                ? (const struct load_command *)(commands + offset)
                : NULL;
        if (command == NULL || command->cmdsize < sizeof(*command) ||
            offset + command->cmdsize > header.sizeofcmds) {
            free(commands);
            return 0;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if ((segment->initprot & VM_PROT_EXECUTE) != 0) {
                base_vm_address = segment->vmaddr;
                found_base_vm_address = true;
                break;
            }
        }
        offset += command->cmdsize;
    }
    if (!found_base_vm_address) {
        free(commands);
        return 0;
    }
    uint64_t slide = image - base_vm_address;
    mach_vm_address_t result = 0;
    offset = 0;
    for (uint32_t index = 0; index < header.ncmds && result == 0; ++index) {
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if ((segment->initprot & VM_PROT_EXECUTE) != 0 &&
                segment->filesize >= pattern_size &&
                segment->filesize <= 64U * 1024U * 1024U) {
                size_t segment_size = (size_t)segment->filesize;
                uint8_t *bytes = malloc(segment_size);
                mach_vm_address_t start = slide + segment->vmaddr;
                if (bytes != NULL &&
                    read_remote(task, start, bytes, segment_size) ==
                        KERN_SUCCESS) {
                    for (size_t cursor = 0;
                         cursor + pattern_size <= segment_size;
                         cursor += sizeof(uint32_t)) {
                        if (memcmp(bytes + cursor, pattern, pattern_size) ==
                            0) {
                            result = start + cursor;
                            break;
                        }
                    }
                }
                free(bytes);
            }
        }
        offset += command->cmdsize;
    }
    free(commands);
    return result;
}

static bool read_remote_path(mach_port_t task, mach_vm_address_t address,
                             char path[PATH_MAX]) {
    path[0] = '\0';
    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task, canonical_remote_address(address), PATH_MAX - 1U,
        (mach_vm_address_t)(uintptr_t)path, &copied);
    if (result != KERN_SUCCESS || copied == 0) {
        return false;
    }
    if (copied >= PATH_MAX) {
        copied = PATH_MAX - 1U;
    }
    path[copied] = '\0';
    return memchr(path, '\0', (size_t)copied + 1U) != NULL;
}

static bool remote_image_has_uuid(mach_port_t task,
                                  mach_vm_address_t image,
                                  const uint8_t expected[16]) {
    struct mach_header_64 header = {0};
    if (read_remote(task, image, &header, sizeof(header)) != KERN_SUCCESS ||
        header.magic != MH_MAGIC_64 || header.ncmds == 0 ||
        header.ncmds > 4096 || header.sizeofcmds == 0 ||
        header.sizeofcmds > 4U * 1024U * 1024U) {
        return false;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL ||
        read_remote(task, image + sizeof(header), commands,
                    header.sizeofcmds) != KERN_SUCCESS) {
        free(commands);
        return false;
    }
    bool matched = false;
    size_t offset = 0;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        const struct load_command *command =
            offset + sizeof(struct load_command) <= header.sizeofcmds
                ? (const struct load_command *)(commands + offset)
                : NULL;
        if (command == NULL || command->cmdsize < sizeof(*command) ||
            offset + command->cmdsize > header.sizeofcmds) {
            matched = false;
            break;
        }
        if (command->cmd == LC_UUID &&
            command->cmdsize == sizeof(struct uuid_command)) {
            const struct uuid_command *uuid =
                (const struct uuid_command *)command;
            matched = memcmp(uuid->uuid, expected, 16U) == 0;
            break;
        }
        offset += command->cmdsize;
    }
    free(commands);
    return matched;
}

static mach_vm_address_t find_remote_runtime_image(mach_port_t task) {
    task_dyld_info_data_t dyld_info = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t dyld_result = task_info(
        task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    struct dyld_all_image_infos infos = {0};
    if (dyld_result != KERN_SUCCESS ||
        dyld_info.all_image_info_addr == 0 ||
        read_remote(task, dyld_info.all_image_info_addr, &infos,
                    sizeof(infos)) != KERN_SUCCESS ||
        infos.infoArrayCount == 0 || infos.infoArrayCount > 4096U) {
        return 0;
    }
    mach_vm_address_t array_address = canonical_remote_address(
        (uint64_t)(uintptr_t)infos.infoArray);
    size_t array_size =
        (size_t)infos.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *images = malloc(array_size);
    if (images == NULL ||
        read_remote(task, array_address, images, array_size) !=
            KERN_SUCCESS) {
        free(images);
        return 0;
    }
    mach_vm_address_t result = 0;
    for (uint32_t index = 0; index < infos.infoArrayCount; ++index) {
        char path[PATH_MAX] = {0};
        mach_vm_address_t path_address = canonical_remote_address(
            (uint64_t)(uintptr_t)images[index].imageFilePath);
        mach_vm_address_t image = canonical_remote_address(
            (uint64_t)(uintptr_t)images[index].imageLoadAddress);
        if (read_remote_path(task, path_address, path) &&
            path_has_suffix(path, kResidentRuntimeSuffix) &&
            remote_image_has_uuid(task, image, kResidentRuntimeUUID)) {
            result = image;
            break;
        }
    }
    free(images);
    return result;
}

static bool find_trusted_code_donor(struct hwbp_transaction *transaction) {
    int bytes = proc_listpids(1U, 0U, NULL, 0);
    if (bytes <= 0 || bytes > (int)(1024U * 1024U)) {
        return false;
    }
    pid_t *pids = calloc(1, (size_t)bytes);
    if (pids == NULL) {
        return false;
    }
    int filled = proc_listpids(1U, 0U, pids, bytes);
    bool found = false;
    if (filled > 0) {
        size_t count = (size_t)filled / sizeof(pid_t);
        for (size_t index = 0; index < count && !found; ++index) {
            pid_t candidate = pids[index];
            if (!read_resident_carrier_process(candidate)) {
                continue;
            }
            mach_port_t task = MACH_PORT_NULL;
            kern_return_t task_result = task_for_pid(
                mach_task_self(), candidate, &task);
            mach_vm_address_t image = task_result == KERN_SUCCESS &&
                    MACH_PORT_VALID(task)
                ? find_remote_runtime_image(task)
                : 0;
            mach_vm_address_t blob = image != 0
                ? find_remote_pattern(task, image, kTrustedBlobPattern,
                                      sizeof(kTrustedBlobPattern))
                : 0;
            mach_vm_address_t mmap_hook = image != 0
                ? find_remote_pattern(task, image,
                                      kTrustedMmapHookPattern,
                                      sizeof(kTrustedMmapHookPattern))
                : 0;
            mach_vm_address_t fcntl_hook = image != 0
                ? find_remote_pattern(task, image,
                                      kTrustedFcntlHookPattern,
                                      sizeof(kTrustedFcntlHookPattern))
                : 0;
            mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
            bool exact_layout = page_size != 0 &&
                (page_size & (page_size - 1U)) == 0 && blob != 0 &&
                mmap_hook == blob + 0x90U &&
                fcntl_hook == blob + 0x188U &&
                (blob & (page_size - 1U)) + kTrustedBlobSize <= page_size;
            broker_log("phase=hwbp-donor-candidate pid=%d taskKr=%d "
                       "task=0x%x image=0x%llx blob=0x%llx "
                       "mmapHook=0x%llx fcntlHook=0x%llx layout=%d\n",
                       candidate, task_result, task,
                       (unsigned long long)image,
                       (unsigned long long)blob,
                       (unsigned long long)mmap_hook,
                       (unsigned long long)fcntl_hook, exact_layout);
            if (exact_layout) {
                transaction->donor_pid = candidate;
                transaction->donor_task = task;
                transaction->donor_blob = blob;
                found = true;
            } else if (MACH_PORT_VALID(task)) {
                (void)mach_port_deallocate(mach_task_self(), task);
            }
        }
    }
    free(pids);
    return found;
}

static uint32_t encode_movk(unsigned int register_number,
                            uint16_t immediate, unsigned int shift) {
    return 0xf2800000U | ((shift / 16U) << 21U) |
        ((uint32_t)immediate << 5U) | (register_number & 0x1fU);
}

static void make_absolute_branch(mach_vm_address_t target,
                                 uint8_t instructions[20]) {
    uint32_t *words = (uint32_t *)instructions;
    words[0] = encode_movk(16U, (uint16_t)(target >> 0U), 0U);
    words[1] = encode_movk(16U, (uint16_t)(target >> 16U), 16U);
    words[2] = encode_movk(16U, (uint16_t)(target >> 32U), 32U);
    words[3] = encode_movk(16U, (uint16_t)(target >> 48U), 48U);
    words[4] = 0xd61f0200U;
}

static bool write_executable_bytes(mach_port_t task,
                                   mach_vm_address_t address,
                                   const void *bytes, size_t size) {
    mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0 ||
        size == 0 || address > UINT64_MAX - size) {
        return false;
    }
    mach_vm_address_t page = address & ~(page_size - 1U);
    mach_vm_address_t end =
        (address + size + page_size - 1U) & ~(page_size - 1U);
    kern_return_t protect_result = mach_vm_protect(
        task, page, end - page, false,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    kern_return_t write_result = protect_result == KERN_SUCCESS
        ? mach_vm_write(task, address, (vm_offset_t)(uintptr_t)bytes,
                        (mach_msg_type_number_t)size)
        : protect_result;
    vm_machine_attribute_val_t cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t flush_result = write_result == KERN_SUCCESS
        ? vm_machine_attribute(task, (vm_address_t)page,
                               (vm_size_t)(end - page), MATTR_CACHE,
                               &cache_value)
        : write_result;
    kern_return_t execute_result = mach_vm_protect(
        task, page, end - page, false, VM_PROT_READ | VM_PROT_EXECUTE);
    uint8_t *readback = malloc(size);
    bool verified = readback != NULL && execute_result == KERN_SUCCESS &&
        flush_result == KERN_SUCCESS &&
        read_remote(task, address, readback, size) == KERN_SUCCESS &&
        memcmp(readback, bytes, size) == 0;
    free(readback);
    return verified;
}

static bool looks_like_codex_absolute_branch(const uint8_t bytes[20]) {
    const uint32_t *words = (const uint32_t *)bytes;
    for (size_t index = 0; index < 4U; ++index) {
        if ((words[index] & 0xff80001fU) != 0xf2800010U) {
            return false;
        }
    }
    return words[4] == 0xd61f0200U;
}

static bool repair_interrupted_mmap_patch(
    mach_port_t target_task, mach_vm_address_t dyld_header,
    bool *integrity_lost) {
    /* This offset is admitted only when the identical local dyld mapping has
     * the exact pristine prologue and the remote bytes have our five-word
     * absolute-branch shape.  It repairs an interrupted transaction by
     * replacing the whole page with the pristine shared-cache page already
     * mapped in the trusted carrier. */
    const mach_vm_address_t candidate = dyld_header + 0x147d4U;
    uint8_t local_bytes[20] = {0};
    uint8_t remote_bytes[20] = {0};
    memcpy(local_bytes, (const void *)(uintptr_t)candidate,
           sizeof(local_bytes));
    if (memcmp(local_bytes, kMmapOriginal, sizeof(local_bytes)) != 0 ||
        read_remote(target_task, candidate, remote_bytes,
                    sizeof(remote_bytes)) != KERN_SUCCESS ||
        !looks_like_codex_absolute_branch(remote_bytes)) {
        return false;
    }
    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    const mach_vm_address_t page =
        candidate & ~(mach_vm_address_t)(page_size - 1U);
    mach_vm_address_t fixed_target = page;
    vm_prot_t current = VM_PROT_NONE;
    vm_prot_t maximum = VM_PROT_NONE;
    kern_return_t overwrite_result = mach_vm_remap(
        target_task, &fixed_target, page_size, 0,
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(), page, false,
        &current, &maximum, VM_INHERIT_NONE);
    memset(remote_bytes, 0, sizeof(remote_bytes));
    bool repaired = overwrite_result == KERN_SUCCESS &&
        fixed_target == page &&
        (current & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
            (VM_PROT_READ | VM_PROT_EXECUTE) &&
        read_remote(target_task, candidate, remote_bytes,
                    sizeof(remote_bytes)) == KERN_SUCCESS &&
        memcmp(remote_bytes, kMmapOriginal, sizeof(remote_bytes)) == 0;
    kern_return_t deallocate_result = KERN_INVALID_ARGUMENT;
    kern_return_t fixed_result = KERN_INVALID_ARGUMENT;
    if (!repaired) {
        deallocate_result = mach_vm_deallocate(target_task, page, page_size);
        fixed_target = page;
        current = VM_PROT_NONE;
        maximum = VM_PROT_NONE;
        fixed_result = deallocate_result == KERN_SUCCESS
            ? mach_vm_remap(
                  target_task, &fixed_target, page_size, 0,
                  VM_FLAGS_FIXED, mach_task_self(), page, false, &current,
                  &maximum, VM_INHERIT_NONE)
            : deallocate_result;
        memset(remote_bytes, 0, sizeof(remote_bytes));
        repaired = fixed_result == KERN_SUCCESS && fixed_target == page &&
            (current & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
                (VM_PROT_READ | VM_PROT_EXECUTE) &&
            read_remote(target_task, candidate, remote_bytes,
                        sizeof(remote_bytes)) == KERN_SUCCESS &&
            memcmp(remote_bytes, kMmapOriginal, sizeof(remote_bytes)) == 0;
    }
    if (!repaired) {
        *integrity_lost = true;
    }
    broker_log("phase=interrupted-repair candidate=0x%llx page=0x%llx "
               "overwriteKr=%d deallocKr=%d fixedKr=%d fixed=0x%llx "
               "current=0x%x maximum=0x%x repaired=%d integrityLost=%d\n",
               (unsigned long long)candidate, (unsigned long long)page,
               overwrite_result, deallocate_result, fixed_result,
               (unsigned long long)fixed_target, current, maximum, repaired,
               *integrity_lost);
    return repaired;
}

static bool remap_patched_executable_page(
    mach_port_t target_task, mach_vm_address_t target_address,
    const uint8_t branch[20], mach_vm_address_t *saved_original,
    bool *integrity_lost) {
    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    const mach_vm_address_t target_page =
        target_address & ~(mach_vm_address_t)(page_size - 1U);
    const mach_vm_size_t patch_offset = target_address - target_page;
    *saved_original = 0;
    if (page_size == 0 || patch_offset + 20U > page_size) {
        return false;
    }

    vm_prot_t saved_current = VM_PROT_NONE;
    vm_prot_t saved_maximum = VM_PROT_NONE;
    kern_return_t save_result = mach_vm_remap(
        mach_task_self(), saved_original, page_size, 0, VM_FLAGS_ANYWHERE,
        target_task, target_page, false, &saved_current, &saved_maximum,
        VM_INHERIT_NONE);

    mach_vm_address_t patched_page = 0;
    kern_return_t allocate_result = save_result == KERN_SUCCESS
        ? mach_vm_allocate(mach_task_self(), &patched_page, page_size,
                           VM_FLAGS_ANYWHERE)
        : save_result;
    kern_return_t read_result = allocate_result == KERN_SUCCESS
        ? read_remote(target_task, target_page,
                      (void *)(uintptr_t)patched_page, page_size)
        : allocate_result;
    if (read_result == KERN_SUCCESS) {
        memcpy((void *)(uintptr_t)(patched_page + patch_offset), branch, 20U);
    }
    vm_machine_attribute_val_t cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t flush_result = read_result == KERN_SUCCESS
        ? vm_machine_attribute(mach_task_self(), (vm_address_t)patched_page,
                               (vm_size_t)page_size, MATTR_CACHE,
                               &cache_value)
        : read_result;
    kern_return_t protect_result = flush_result == KERN_SUCCESS
        ? mach_vm_protect(mach_task_self(), patched_page, page_size, false,
                          VM_PROT_READ | VM_PROT_EXECUTE)
        : flush_result;
    kern_return_t deallocate_result = protect_result == KERN_SUCCESS
        ? mach_vm_deallocate(target_task, target_page, page_size)
        : protect_result;
    mach_vm_address_t fixed_target = target_page;
    vm_prot_t installed_current = VM_PROT_NONE;
    vm_prot_t installed_maximum = VM_PROT_NONE;
    kern_return_t install_result = deallocate_result == KERN_SUCCESS
        ? mach_vm_remap(
              target_task, &fixed_target, page_size, 0,
              VM_FLAGS_FIXED, mach_task_self(), patched_page, false,
              &installed_current, &installed_maximum, VM_INHERIT_NONE)
        : deallocate_result;
    uint8_t readback[20] = {0};
    bool installed = install_result == KERN_SUCCESS &&
        fixed_target == target_page &&
        (installed_current & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
            (VM_PROT_READ | VM_PROT_EXECUTE) &&
        read_remote(target_task, target_address, readback,
                    sizeof(readback)) == KERN_SUCCESS &&
        memcmp(readback, branch, sizeof(readback)) == 0;
    broker_log("phase=page-replace targetPage=0x%llx offset=0x%llx "
               "saveKr=%d saved=0x%llx savedCurrent=0x%x "
               "savedMaximum=0x%x allocKr=%d readKr=%d flushKr=%d "
               "protectKr=%d deallocKr=%d installKr=%d fixed=0x%llx "
               "current=0x%x maximum=0x%x installed=%d\n",
               (unsigned long long)target_page,
               (unsigned long long)patch_offset, save_result,
               (unsigned long long)*saved_original, saved_current,
               saved_maximum, allocate_result, read_result, flush_result,
               protect_result, deallocate_result, install_result,
               (unsigned long long)fixed_target, installed_current,
               installed_maximum, installed);
    if (patched_page != 0) {
        (void)mach_vm_deallocate(mach_task_self(), patched_page, page_size);
    }
    if (!installed && *saved_original != 0) {
        kern_return_t remove_result = mach_vm_deallocate(
            target_task, target_page, page_size);
        mach_vm_address_t restore_target = target_page;
        vm_prot_t restore_current = VM_PROT_NONE;
        vm_prot_t restore_maximum = VM_PROT_NONE;
        kern_return_t restore_result =
            (remove_result == KERN_SUCCESS ||
             remove_result == KERN_INVALID_ADDRESS)
            ? mach_vm_remap(
                  target_task, &restore_target, page_size, 0,
                  VM_FLAGS_FIXED, mach_task_self(), *saved_original, false,
                  &restore_current, &restore_maximum, VM_INHERIT_NONE)
            : remove_result;
        uint8_t restored_bytes[20] = {0};
        bool original_restored = restore_result == KERN_SUCCESS &&
            restore_target == target_page &&
            read_remote(target_task, target_address, restored_bytes,
                        sizeof(restored_bytes)) == KERN_SUCCESS &&
            memcmp(restored_bytes,
                   (const void *)(uintptr_t)(*saved_original + patch_offset),
                   sizeof(restored_bytes)) == 0;
        broker_log("phase=page-replace-rollback targetPage=0x%llx "
                   "removeKr=%d restoreKr=%d restored=%d\n",
                   (unsigned long long)target_page, remove_result,
                   restore_result, original_restored);
        if (original_restored) {
            (void)mach_vm_deallocate(mach_task_self(), *saved_original,
                                     page_size);
            *saved_original = 0;
        } else {
            *integrity_lost = true;
        }
    }
    return installed;
}

static bool restore_remapped_executable_page(
    mach_port_t target_task, mach_vm_address_t target_address,
    mach_vm_address_t *saved_original, const uint8_t expected[20],
    bool *integrity_lost) {
    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    const mach_vm_address_t target_page =
        target_address & ~(mach_vm_address_t)(page_size - 1U);
    if (*saved_original == 0) {
        return true;
    }
    kern_return_t deallocate_result = mach_vm_deallocate(
        target_task, target_page, page_size);
    mach_vm_address_t fixed_target = target_page;
    vm_prot_t current = VM_PROT_NONE;
    vm_prot_t maximum = VM_PROT_NONE;
    kern_return_t result = deallocate_result == KERN_SUCCESS
        ? mach_vm_remap(target_task, &fixed_target, page_size, 0,
                        VM_FLAGS_FIXED, mach_task_self(), *saved_original,
                        false, &current, &maximum, VM_INHERIT_NONE)
        : deallocate_result;
    uint8_t readback[20] = {0};
    bool restored = result == KERN_SUCCESS && fixed_target == target_page &&
        (current & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
            (VM_PROT_READ | VM_PROT_EXECUTE) &&
        read_remote(target_task, target_address, readback,
                    sizeof(readback)) == KERN_SUCCESS &&
        memcmp(readback, expected, sizeof(readback)) == 0;
    broker_log("phase=page-restore targetPage=0x%llx source=0x%llx "
               "deallocKr=%d result=%d fixed=0x%llx current=0x%x "
               "maximum=0x%x restored=%d\n",
               (unsigned long long)target_page,
               (unsigned long long)*saved_original, deallocate_result, result,
               (unsigned long long)fixed_target, current, maximum,
               restored);
    if (restored) {
        (void)mach_vm_deallocate(mach_task_self(), *saved_original,
                                 page_size);
        *saved_original = 0;
    } else {
        *integrity_lost = true;
    }
    return restored;
}

static bool wait_for_trace_stop(pid_t pid, int *status) {
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        errno = 0;
        pid_t result = waitpid(pid, status, WUNTRACED | WNOHANG);
        if (result == pid) {
            return WIFSTOPPED(*status);
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
    errno = ETIMEDOUT;
    return false;
}

static int detach_target(pid_t pid) {
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        errno = 0;
        int result = ptrace(CODEX_PT_DETACH, pid, NULL, 0);
        if (result == 0) {
            (void)kill(pid, SIGCONT);
            return 0;
        }
        if (errno != EBUSY && errno != EINTR) {
            return -1;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
    errno = ETIMEDOUT;
    return -1;
}

static bool restart_verified_springboard(pid_t pid, const char *reason) {
    if (!read_exact_process(pid, kSpringBoardPath)) {
        broker_log("phase=fail-closed-restart pid=%d admitted=0 reason=%s\n",
                   pid, reason);
        return false;
    }
    errno = 0;
    int kill_result = kill(pid, SIGKILL);
    int kill_error = errno;
    bool exited = false;
    if (kill_result == 0) {
        for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS;
             ++attempt) {
            int status = 0;
            pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid ||
                (waited < 0 && (errno == ECHILD || errno == ESRCH))) {
                exited = true;
                break;
            }
            if (waited < 0 && errno != EINTR) {
                break;
            }
            usleep(CODEX_WAIT_DELAY_USEC);
        }
    }
    broker_log("phase=fail-closed-restart pid=%d admitted=1 kill=%d "
               "killErrno=%d exited=%d reason=%s\n",
               pid, kill_result, kill_error, exited, reason);
    return kill_result == 0;
}

static void release_local_snapshots(struct hook_transaction *transaction) {
    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    if (transaction->mmap_original_page != 0) {
        (void)mach_vm_deallocate(mach_task_self(),
                                 transaction->mmap_original_page,
                                 page_size);
        transaction->mmap_original_page = 0;
    }
    if (transaction->fcntl_original_page != 0) {
        (void)mach_vm_deallocate(mach_task_self(),
                                 transaction->fcntl_original_page,
                                 page_size);
        transaction->fcntl_original_page = 0;
    }
}

static bool target_is_softened(pid_t pid, uint32_t *code_sign_flags) {
    *code_sign_flags = 0;
    return read_exact_process(pid, kSpringBoardPath) &&
        csops(pid, CODEX_CS_OPS_STATUS, code_sign_flags,
              sizeof(*code_sign_flags)) == 0 &&
        (*code_sign_flags & CODEX_CS_DEBUGGED) != 0 &&
        (*code_sign_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
}

static bool soften_target(pid_t pid, uint32_t *code_sign_flags) {
    if (target_is_softened(pid, code_sign_flags)) {
        return true;
    }
    errno = 0;
    int attach_result = ptrace(CODEX_PT_ATTACHEXC, pid, NULL, 0);
    int attach_error = errno;
    int status = 0;
    bool stopped = attach_result == 0 && wait_for_trace_stop(pid, &status) &&
        read_exact_process(pid, kSpringBoardPath);
    int detach_result = stopped ? detach_target(pid) : -1;
    bool softened = detach_result == 0 &&
        target_is_softened(pid, code_sign_flags);
    broker_log("phase=soften pid=%d attach=%d attachErrno=%d stopped=%d "
               "status=0x%x detach=%d flags=0x%08x softened=%d\n",
               pid, attach_result, attach_error, stopped, status,
               detach_result, *code_sign_flags, softened);
    if (attach_result == 0 && !stopped) {
        (void)detach_target(pid);
    }
    return softened;
}

static bool attach_target(pid_t pid, mach_port_t *task,
                          uint32_t *code_sign_flags) {
    *task = MACH_PORT_NULL;
    *code_sign_flags = 0;
    bool softened = soften_target(pid, code_sign_flags);
    if (!read_exact_process(pid, kSpringBoardPath)) {
        return false;
    }
    errno = 0;
    int attach_result = ptrace(CODEX_PT_ATTACHEXC, pid, NULL, 0);
    int attach_error = errno;
    if (attach_result != 0) {
        broker_log("phase=patch-attach pid=%d attach=%d errno=%d\n", pid,
                   attach_result, attach_error);
        return false;
    }
    int status = 0;
    bool stopped = wait_for_trace_stop(pid, &status) && WIFSTOPPED(status) &&
        read_exact_process(pid, kSpringBoardPath);
    if (!stopped) {
        (void)detach_target(pid);
        return false;
    }
    int cs_result = csops(pid, CODEX_CS_OPS_STATUS, code_sign_flags,
                          sizeof(*code_sign_flags));
    kern_return_t task_result =
        task_for_pid(mach_task_self(), pid, task);
    bool admitted = cs_result == 0 && task_result == KERN_SUCCESS &&
        MACH_PORT_VALID(*task);
    broker_log("phase=patch-attach pid=%d attach=%d errno=%d stopped=%d "
               "cs=%d flags=0x%08x softened=%d taskKr=%d task=0x%x "
               "admitted=%d\n",
               pid, attach_result, attach_error, stopped, cs_result,
               *code_sign_flags, softened, task_result, *task, admitted);
    if (!admitted) {
        if (MACH_PORT_VALID(*task)) {
            (void)mach_port_deallocate(mach_task_self(), *task);
            *task = MACH_PORT_NULL;
        }
        (void)detach_target(pid);
    }
    return admitted;
}

static bool attach_hwbp_target(struct hwbp_transaction *transaction,
                               uint32_t *code_sign_flags) {
    transaction->task = MACH_PORT_NULL;
    transaction->trace_attached = false;
    transaction->trace_stopped = false;
    *code_sign_flags = 0;
    if (!read_exact_process(transaction->pid, kSpringBoardPath)) {
        return false;
    }
    errno = 0;
    int attach_result = ptrace(CODEX_PT_ATTACHEXC, transaction->pid,
                               NULL, 0);
    int attach_error = errno;
    if (attach_result != 0) {
        broker_log("phase=hwbp-attach pid=%d attach=%d errno=%d\n",
                   transaction->pid, attach_result, attach_error);
        return false;
    }
    transaction->trace_attached = true;
    int status = 0;
    bool stopped = wait_for_trace_stop(transaction->pid, &status) &&
        WIFSTOPPED(status) &&
        read_exact_process(transaction->pid, kSpringBoardPath);
    transaction->trace_stopped = stopped;
    uint32_t initial_code_sign_flags = 0;
    int initial_cs_result = stopped
        ? csops(transaction->pid, CODEX_CS_OPS_STATUS,
                &initial_code_sign_flags, sizeof(initial_code_sign_flags))
        : -1;

    /* The attach stop alone does not publish CS_DEBUGGED on this build.
     * Resume only long enough to deliver a broker-originated SIGSTOP, then
     * require that second traced stop before obtaining the task port or
     * mapping any carrier code.  The code-sign state is logged separately. */
    errno = 0;
    int prime_continue = stopped
        ? ptrace(CODEX_PT_CONTINUE, transaction->pid, (caddr_t)1, 0)
        : -1;
    int prime_continue_error = errno;
    if (prime_continue == 0) {
        transaction->trace_stopped = false;
    }
    errno = 0;
    int prime_signal = prime_continue == 0 &&
            read_exact_process(transaction->pid, kSpringBoardPath)
        ? kill(transaction->pid, SIGSTOP)
        : -1;
    int prime_signal_error = errno;
    int prime_status = 0;
    bool prime_stopped = prime_signal == 0 &&
        wait_for_trace_stop(transaction->pid, &prime_status) &&
        WIFSTOPPED(prime_status) && WSTOPSIG(prime_status) == SIGSTOP &&
        read_exact_process(transaction->pid, kSpringBoardPath);
    transaction->trace_stopped = prime_stopped;

    int cs_result = prime_stopped
        ? csops(transaction->pid, CODEX_CS_OPS_STATUS, code_sign_flags,
                sizeof(*code_sign_flags))
        : -1;
    bool softened = cs_result == 0 &&
        (*code_sign_flags & CODEX_CS_DEBUGGED) != 0 &&
        (*code_sign_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    /*
     * CS_DEBUGGED describes the target's invalid-code policy; it is not the
     * authorization gate for a caller carrying system-task-ports.control.
     * Keep it in the diagnostics, but let the real task_for_pid result decide
     * whether this transaction can continue.
     */
    kern_return_t task_result = prime_stopped
        ? task_for_pid(mach_task_self(), transaction->pid,
                       &transaction->task)
        : KERN_FAILURE;
    bool admitted = prime_stopped && task_result == KERN_SUCCESS &&
        MACH_PORT_VALID(transaction->task);
    broker_log("phase=hwbp-attach pid=%d attach=%d errno=%d stopped=%d "
               "status=0x%x initialCs=%d initialFlags=0x%08x "
               "primeContinue=%d primeContinueErrno=%d primeSignal=%d "
               "primeSignalErrno=%d primeStopped=%d primeStatus=0x%x "
               "cs=%d flags=0x%08x softened=%d taskKr=%d task=0x%x "
               "admitted=%d\n",
               transaction->pid, attach_result, attach_error, stopped,
               status, initial_cs_result, initial_code_sign_flags,
               prime_continue, prime_continue_error, prime_signal,
               prime_signal_error, prime_stopped, prime_status, cs_result,
               *code_sign_flags, softened, task_result, transaction->task,
               admitted);
    if (!admitted) {
        if (MACH_PORT_VALID(transaction->task)) {
            (void)mach_port_deallocate(mach_task_self(), transaction->task);
            transaction->task = MACH_PORT_NULL;
        }
        if (transaction->trace_attached) {
            (void)detach_target(transaction->pid);
            transaction->trace_attached = false;
            transaction->trace_stopped = false;
        }
    }
    return admitted;
}

static void release_thread_list(thread_act_array_t threads,
                                mach_msg_type_number_t count) {
    if (threads == NULL) {
        return;
    }
    for (mach_msg_type_number_t index = 0; index < count; ++index) {
        if (MACH_PORT_VALID(threads[index])) {
            (void)mach_port_deallocate(mach_task_self(), threads[index]);
        }
    }
    (void)mach_vm_deallocate(
        mach_task_self(), (mach_vm_address_t)(uintptr_t)threads,
        (mach_vm_size_t)count * sizeof(*threads));
}

static void destroy_local_receive_port(mach_port_t port) {
    if (!MACH_PORT_VALID(port)) {
        return;
    }
    (void)mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND,
                             -1);
    (void)mach_port_mod_refs(mach_task_self(), port,
                             MACH_PORT_RIGHT_RECEIVE, -1);
}

static bool debug_state_is_idle(const arm_debug_state64_t *state) {
    for (size_t index = 0; index < 16U; ++index) {
        if ((state->__bcr[index] & 1U) != 0 ||
            (state->__wcr[index] & 1U) != 0) {
            return false;
        }
    }
    return (state->__mdscr_el1 & 1U) == 0;
}

static bool resolve_and_map_hwbp_hooks(
    struct hwbp_transaction *transaction) {
    task_dyld_info_data_t dyld_info = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t dyld_result = task_info(
        transaction->task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    struct dyld_all_image_infos infos = {0};
    bool info_read = dyld_result == KERN_SUCCESS &&
        dyld_info.all_image_info_addr != 0 &&
        read_remote(transaction->task, dyld_info.all_image_info_addr,
                    &infos, sizeof(infos)) == KERN_SUCCESS;
    mach_vm_address_t dyld_header = info_read
        ? canonical_remote_address((uint64_t)infos.dyldImageLoadAddress)
        : 0;
    transaction->mmap_stub = dyld_header != 0
        ? find_remote_pattern(transaction->task, dyld_header, kMmapPattern,
                              sizeof(kMmapPattern))
        : 0;
    transaction->fcntl_stub = dyld_header != 0
        ? find_remote_pattern(transaction->task, dyld_header, kFcntlPattern,
                              sizeof(kFcntlPattern))
        : 0;

    uint8_t mmap_bytes[sizeof(kMmapOriginal)] = {0};
    uint8_t fcntl_bytes[sizeof(kFcntlPattern)] = {0};
    bool stubs_pristine = transaction->mmap_stub != 0 &&
        transaction->fcntl_stub != 0 &&
        read_remote(transaction->task, transaction->mmap_stub, mmap_bytes,
                    sizeof(mmap_bytes)) == KERN_SUCCESS &&
        read_remote(transaction->task, transaction->fcntl_stub, fcntl_bytes,
                    sizeof(fcntl_bytes)) == KERN_SUCCESS &&
        memcmp(mmap_bytes, kMmapOriginal, sizeof(mmap_bytes)) == 0 &&
        memcmp(fcntl_bytes, kFcntlPattern, sizeof(fcntl_bytes)) == 0;

    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    bool donor_found = stubs_pristine &&
        find_trusted_code_donor(transaction);
    const mach_vm_address_t source_page = donor_found
        ? transaction->donor_blob & ~(mach_vm_address_t)(page_size - 1U)
        : 0;
    const mach_vm_size_t blob_offset = donor_found
        ? transaction->donor_blob - source_page
        : 0;
    bool layout_ok = donor_found && page_size != 0 &&
        (page_size & (page_size - 1U)) == 0 &&
        blob_offset + kTrustedBlobSize <= page_size &&
        (transaction->mmap_stub & 3U) == 0 &&
        (transaction->fcntl_stub & 3U) == 0;

    transaction->code_page = 0;
    transaction->code_page_size = page_size;
    vm_prot_t current = VM_PROT_NONE;
    vm_prot_t maximum = VM_PROT_NONE;
    kern_return_t remap_result = layout_ok && stubs_pristine
        ? mach_vm_remap(transaction->task, &transaction->code_page,
                        page_size, 0, VM_FLAGS_ANYWHERE,
                        transaction->donor_task,
                        source_page, false, &current, &maximum,
                        VM_INHERIT_NONE)
        : KERN_INVALID_ARGUMENT;
    mach_vm_address_t remote_blob = remap_result == KERN_SUCCESS
        ? transaction->code_page + blob_offset
        : 0;
    transaction->stop_gate = remote_blob;
    transaction->mmap_hook = remote_blob != 0
        ? remote_blob + 0x90U
        : 0;
    transaction->fcntl_hook = remote_blob != 0
        ? remote_blob + 0x188U
        : 0;

    uint8_t *source = malloc((size_t)kTrustedBlobSize);
    uint8_t *readback = malloc((size_t)kTrustedBlobSize);
    bool mapped = source != NULL && readback != NULL &&
        remap_result == KERN_SUCCESS &&
        (current & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
            (VM_PROT_READ | VM_PROT_EXECUTE) &&
        read_remote(transaction->donor_task, transaction->donor_blob,
                    source, kTrustedBlobSize) == KERN_SUCCESS &&
        read_remote(transaction->task, remote_blob, readback,
                    kTrustedBlobSize) == KERN_SUCCESS &&
        memcmp(readback, source, (size_t)kTrustedBlobSize) == 0;
    free(source);
    free(readback);

    broker_log("phase=hwbp-resolve target=%d dyldKr=%d dyld=0x%llx "
               "mmap=0x%llx fcntl=0x%llx pristine=%d layout=%d "
               "donorPid=%d donorTask=0x%x donorBlob=0x%llx "
               "sourcePage=0x%llx "
               "remapKr=%d page=0x%llx current=0x%x maximum=0x%x "
               "stopGate=0x%llx mmapHook=0x%llx fcntlHook=0x%llx "
               "mapped=%d\n",
               transaction->pid, dyld_result,
               (unsigned long long)dyld_header,
               (unsigned long long)transaction->mmap_stub,
               (unsigned long long)transaction->fcntl_stub, stubs_pristine,
               layout_ok, transaction->donor_pid, transaction->donor_task,
               (unsigned long long)transaction->donor_blob,
               (unsigned long long)source_page, remap_result,
               (unsigned long long)transaction->code_page, current, maximum,
               (unsigned long long)transaction->stop_gate,
               (unsigned long long)transaction->mmap_hook,
               (unsigned long long)transaction->fcntl_hook, mapped);
    if (!mapped && transaction->code_page != 0) {
        (void)mach_vm_deallocate(transaction->task, transaction->code_page,
                                 page_size);
        transaction->code_page = 0;
        transaction->stop_gate = 0;
        transaction->mmap_hook = 0;
        transaction->fcntl_hook = 0;
    }
    return mapped;
}

static void *signed_remote_function_pointer(mach_vm_address_t address) {
    void *pointer = (void *)(uintptr_t)address;
    pointer = ptrauth_strip(pointer, ptrauth_key_function_pointer);
    return ptrauth_sign_unauthenticated(
        pointer, ptrauth_key_function_pointer, 0);
}

static mach_vm_address_t local_function_address(void *function) {
    return canonical_remote_address((uint64_t)(uintptr_t)ptrauth_strip(
        function, ptrauth_key_function_pointer));
}

static bool remote_callable_matches(mach_port_t task,
                                    mach_vm_address_t address) {
    uint8_t local[16] = {0};
    uint8_t remote[16] = {0};
    if (address == 0) {
        return false;
    }
    memcpy(local, (const void *)(uintptr_t)address, sizeof(local));
    return read_remote(task, address, remote, sizeof(remote)) ==
            KERN_SUCCESS &&
        memcmp(local, remote, sizeof(local)) == 0;
}

static kern_return_t insert_remote_exception_send_right(
    mach_port_t task, mach_port_t port, mach_port_name_t *target_name) {
    *target_name = MACH_PORT_NULL;
    kern_return_t last_result = KERN_NO_SPACE;
    for (unsigned int attempt = 0;
         attempt < CODEX_REMOTE_PORT_ATTEMPTS; ++attempt) {
        mach_port_name_t candidate =
            ((CODEX_REMOTE_PORT_INDEX_BASE + attempt) << 8U) | 0xffU;
        last_result = mach_port_insert_right(
            task, candidate, port, MACH_MSG_TYPE_COPY_SEND);
        if (last_result == KERN_SUCCESS) {
            *target_name = candidate;
            return KERN_SUCCESS;
        }
        if (last_result == KERN_INVALID_TASK ||
            last_result == KERN_INVALID_CAPABILITY ||
            last_result == KERN_NO_SPACE) {
            break;
        }
    }
    return last_result;
}

static kern_return_t insert_remote_thread_send_right(
    mach_port_t task, mach_port_t thread,
    mach_msg_type_number_t selected, mach_port_name_t *target_name) {
    *target_name = MACH_PORT_NULL;
    kern_return_t last_result = KERN_NO_SPACE;
    uint32_t first_index = CODEX_REMOTE_THREAD_PORT_INDEX_BASE +
        selected * CODEX_REMOTE_THREAD_PORT_ATTEMPTS;
    for (unsigned int attempt = 0;
         attempt < CODEX_REMOTE_THREAD_PORT_ATTEMPTS; ++attempt) {
        mach_port_name_t candidate =
            ((first_index + attempt) << 8U) | 0xffU;
        last_result = mach_port_insert_right(
            task, candidate, thread, MACH_MSG_TYPE_COPY_SEND);
        if (last_result == KERN_SUCCESS) {
            *target_name = candidate;
            return KERN_SUCCESS;
        }
        if (last_result == KERN_INVALID_TASK ||
            last_result == KERN_INVALID_CAPABILITY ||
            last_result == KERN_NO_SPACE) {
            break;
        }
    }
    return last_result;
}

static void *hardened_exception_server_main(void *argument);

static void reset_hardened_handler(void) {
    mach_port_t port = gHardenedHandler.port;
    bool join_thread = gHardenedHandler.thread_started;
    pthread_t thread = gHardenedHandler.thread;
    gHardenedHandler.pid = -1;
    gHardenedHandler.port = MACH_PORT_NULL;
    gHardenedHandler.target_name = MACH_PORT_NULL;
    gHardenedHandler.signed_pc_key = 0;
    gHardenedHandler.thread_started = false;
    if (MACH_PORT_VALID(port)) {
        destroy_local_receive_port(port);
    }
    if (join_thread) {
        (void)pthread_join(thread, NULL);
    }
}

static bool preflight_trusted_stop_gate(
    struct hwbp_transaction *transaction) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t threads_result = task_threads(
        transaction->task, &threads, &thread_count);
    bool *suspended = threads_result == KERN_SUCCESS && thread_count != 0
        ? calloc(thread_count, sizeof(*suspended))
        : NULL;
    bool suspend_ok = suspended != NULL;
    kern_return_t suspend_result = KERN_SUCCESS;
    for (mach_msg_type_number_t index = 1;
         suspend_ok && index < thread_count; ++index) {
        suspend_result = thread_suspend(threads[index]);
        suspended[index] = suspend_result == KERN_SUCCESS;
        suspend_ok = suspended[index];
    }

    arm_thread_state64_t saved_state = {0};
    mach_msg_type_number_t saved_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t get_result = suspend_ok
        ? thread_get_state(threads[0], ARM_THREAD_STATE64,
                           (thread_state_t)&saved_state, &saved_count)
        : KERN_FAILURE;
    arm_thread_state64_t gate_state = saved_state;
    arm_thread_state64_set_pc_fptr(
        gate_state,
        signed_remote_function_pointer(transaction->stop_gate));
    kern_return_t set_result = get_result == KERN_SUCCESS &&
            saved_count == ARM_THREAD_STATE64_COUNT
        ? thread_set_state(threads[0], ARM_THREAD_STATE64,
                           (thread_state_t)&gate_state,
                           ARM_THREAD_STATE64_COUNT)
        : KERN_FAILURE;
    errno = 0;
    int continue_result = set_result == KERN_SUCCESS
        ? ptrace(CODEX_PT_CONTINUE, transaction->pid, (caddr_t)1, 0)
        : -1;
    int continue_error = errno;
    if (continue_result == 0) {
        transaction->trace_stopped = false;
    }
    int status = 0;
    bool stopped = continue_result == 0 &&
        wait_for_trace_stop(transaction->pid, &status) &&
        read_exact_process(transaction->pid, kSpringBoardPath);
    transaction->trace_stopped = stopped;
    kern_return_t restore_result = stopped
        ? thread_set_state(threads[0], ARM_THREAD_STATE64,
                           (thread_state_t)&saved_state,
                           ARM_THREAD_STATE64_COUNT)
        : KERN_FAILURE;
    kern_return_t resume_result = KERN_SUCCESS;
    for (mach_msg_type_number_t index = 1; index < thread_count; ++index) {
        if (suspended != NULL && suspended[index]) {
            kern_return_t one_result = thread_resume(threads[index]);
            if (resume_result == KERN_SUCCESS) {
                resume_result = one_result;
            }
        }
    }
    bool admitted = suspend_ok && get_result == KERN_SUCCESS &&
        set_result == KERN_SUCCESS && stopped && WIFSTOPPED(status) &&
        WSTOPSIG(status) == SIGSTOP &&
        restore_result == KERN_SUCCESS && resume_result == KERN_SUCCESS;
    broker_log("phase=hwbp-trusted-page-preflight target=%d donor=%d "
               "gate=0x%llx threadsKr=%d threads=%u suspendKr=%d "
               "getKr=%d setKr=%d continue=%d continueErrno=%d "
               "stopped=%d status=0x%x restoreKr=%d resumeKr=%d "
               "admitted=%d\n",
               transaction->pid, transaction->donor_pid,
               (unsigned long long)transaction->stop_gate,
               threads_result, thread_count, suspend_result, get_result,
               set_result, continue_result, continue_error, stopped, status,
               restore_result, resume_result, admitted);
    free(suspended);
    release_thread_list(threads, thread_count);
    return admitted;
}

static bool thread_exception_handler_matches(
    thread_act_t thread, struct hwbp_transaction *transaction,
    kern_return_t *query_result_out,
    mach_msg_type_number_t *handler_count_out) {
    exception_mask_array_t masks = {0};
    exception_handler_array_t handlers = {0};
    exception_behavior_array_t behaviors = {0};
    exception_flavor_array_t flavors = {0};
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    kern_return_t query_result = thread_get_exception_ports(
        thread, EXC_MASK_BREAKPOINT, masks, &count, handlers,
        behaviors, flavors);
    bool matched = false;
    if (query_result == KERN_SUCCESS) {
        for (mach_msg_type_number_t index = 0; index < count; ++index) {
            if ((masks[index] & EXC_MASK_BREAKPOINT) != 0 &&
                MACH_PORT_VALID(handlers[index]) &&
                handlers[index] == transaction->exception_port &&
                behaviors[index] == CODEX_HARDENED_BEHAVIOR &&
                flavors[index] == ARM_THREAD_STATE64) {
                matched = true;
            }
            if (MACH_PORT_VALID(handlers[index])) {
                (void)mach_port_deallocate(mach_task_self(),
                                           handlers[index]);
            }
        }
    }
    *query_result_out = query_result;
    *handler_count_out = count;
    return matched;
}

static bool run_adoption_call_on_thread(
    struct hwbp_transaction *transaction, thread_act_array_t threads,
    mach_msg_type_number_t thread_count, mach_msg_type_number_t selected,
    mach_vm_address_t thread_adopt_address) {
    bool *suspended = calloc(thread_count, sizeof(*suspended));
    if (suspended == NULL) {
        return false;
    }
    bool suspend_ok = true;
    kern_return_t suspend_result = KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0;
         suspend_ok && index < thread_count; ++index) {
        if (index == selected) {
            continue;
        }
        suspend_result = thread_suspend(threads[index]);
        suspended[index] = suspend_result == KERN_SUCCESS;
        suspend_ok = suspended[index];
    }

    mach_port_name_t remote_thread_name = MACH_PORT_NULL;
    kern_return_t insert_result = suspend_ok
        ? insert_remote_thread_send_right(
              transaction->task, threads[selected], selected,
              &remote_thread_name)
        : suspend_result;

    arm_thread_state64_t saved_state = {0};
    mach_msg_type_number_t saved_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t get_result = insert_result == KERN_SUCCESS
        ? thread_get_state(threads[selected], ARM_THREAD_STATE64,
                           (thread_state_t)&saved_state, &saved_count)
        : insert_result;
    arm_thread_state64_t gate_state = saved_state;
    gate_state.__x[0] = remote_thread_name;
    gate_state.__x[1] = transaction->target_exception_name;
    gate_state.__x[2] = EXC_MASK_BREAKPOINT;
    gate_state.__x[3] = CODEX_HARDENED_BEHAVIOR;
    gate_state.__x[4] = ARM_THREAD_STATE64;
    arm_thread_state64_set_lr_fptr(
        gate_state,
        signed_remote_function_pointer(transaction->stop_gate));
    arm_thread_state64_set_pc_fptr(
        gate_state,
        signed_remote_function_pointer(thread_adopt_address));
    kern_return_t set_result = get_result == KERN_SUCCESS &&
            saved_count == ARM_THREAD_STATE64_COUNT
        ? thread_set_state(threads[selected], ARM_THREAD_STATE64,
                           (thread_state_t)&gate_state,
                           ARM_THREAD_STATE64_COUNT)
        : KERN_FAILURE;

    errno = 0;
    int continue_result = set_result == KERN_SUCCESS
        ? ptrace(CODEX_PT_CONTINUE, transaction->pid, (caddr_t)1, 0)
        : -1;
    int continue_error = errno;
    if (continue_result == 0) {
        transaction->trace_stopped = false;
    }
    int status = 0;
    bool stopped = continue_result == 0 &&
        wait_for_trace_stop(transaction->pid, &status) &&
        read_exact_process(transaction->pid, kSpringBoardPath);
    transaction->trace_stopped = stopped;

    kern_return_t query_result = KERN_FAILURE;
    mach_msg_type_number_t handler_count = 0;
    bool handler_verified = stopped && thread_exception_handler_matches(
        threads[selected], transaction, &query_result, &handler_count);
    kern_return_t restore_result = stopped
        ? thread_set_state(threads[selected], ARM_THREAD_STATE64,
                           (thread_state_t)&saved_state,
                           ARM_THREAD_STATE64_COUNT)
        : KERN_FAILURE;
    kern_return_t remote_name_deallocate = MACH_PORT_VALID(remote_thread_name)
        ? mach_port_deallocate(transaction->task, remote_thread_name)
        : KERN_FAILURE;

    kern_return_t resume_result = KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0; index < thread_count; ++index) {
        if (suspended[index]) {
            kern_return_t one_result = thread_resume(threads[index]);
            if (resume_result == KERN_SUCCESS) {
                resume_result = one_result;
            }
        }
    }
    free(suspended);

    bool adopted = suspend_ok && insert_result == KERN_SUCCESS &&
        get_result == KERN_SUCCESS &&
        set_result == KERN_SUCCESS && stopped && WIFSTOPPED(status) &&
        WSTOPSIG(status) == SIGSTOP && handler_verified &&
        restore_result == KERN_SUCCESS &&
        remote_name_deallocate == KERN_SUCCESS &&
        resume_result == KERN_SUCCESS;
    broker_log("phase=hwbp-exception-adopt-thread target=%d index=%u "
               "thread=0x%x suspendKr=%d insertKr=%d remoteThread=0x%x "
               "getKr=%d setKr=%d continue=%d continueErrno=%d "
               "stopped=%d status=0x%x queryKr=%d handlers=%u "
               "verified=%d restoreKr=%d remoteDeallocKr=%d "
               "resumeKr=%d adopted=%d\n",
               transaction->pid, selected, threads[selected],
               suspend_result, insert_result, remote_thread_name,
               get_result, set_result, continue_result, continue_error,
               stopped, status, query_result, handler_count,
               handler_verified, restore_result, remote_name_deallocate,
               resume_result, adopted);
    return adopted;
}

static bool adopt_hardened_handler_threads(
    struct hwbp_transaction *transaction) {
    mach_vm_address_t thread_adopt_address = local_function_address(
        (void *)(uintptr_t)&thread_adopt_exception_handler);
    bool callables_match = remote_callable_matches(
        transaction->task, thread_adopt_address);

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t threads_result = callables_match
        ? task_threads(transaction->task, &threads, &thread_count)
        : KERN_FAILURE;
    bool adopted = threads_result == KERN_SUCCESS && thread_count != 0;
    for (mach_msg_type_number_t index = 0;
         adopted && index < thread_count; ++index) {
        adopted = run_adoption_call_on_thread(
            transaction, threads, thread_count, index,
            thread_adopt_address);
    }
    broker_log("phase=hwbp-exception-adopt target=%d callables=%d "
               "adopt=0x%llx stopGate=0x%llx threadsKr=%d "
               "threads=%u adopted=%d\n",
               transaction->pid, callables_match,
               (unsigned long long)thread_adopt_address,
               (unsigned long long)transaction->stop_gate,
               threads_result, thread_count, adopted);
    release_thread_list(threads, thread_count);
    return adopted;
}

static bool start_hardened_exception_server(void) {
    int result = pthread_create(
        &gHardenedHandler.thread, NULL, hardened_exception_server_main,
        (void *)(uintptr_t)gHardenedHandler.port);
    gHardenedHandler.thread_started = result == 0;
    broker_log("phase=hwbp-exception-server-start target=%d port=0x%x "
               "result=%d started=%d\n",
               gHardenedHandler.pid, gHardenedHandler.port, result,
               gHardenedHandler.thread_started);
    return gHardenedHandler.thread_started;
}

static bool install_exception_port(struct hwbp_transaction *transaction) {
    transaction->exception_port = MACH_PORT_NULL;
    transaction->target_exception_name = MACH_PORT_NULL;
    transaction->signed_pc_key = 0;

    bool reusable = gHardenedHandler.pid == transaction->pid &&
        MACH_PORT_VALID(gHardenedHandler.port) &&
        MACH_PORT_VALID(gHardenedHandler.target_name) &&
        gHardenedHandler.thread_started;
    if (reusable) {
        transaction->exception_port = gHardenedHandler.port;
        transaction->target_exception_name =
            gHardenedHandler.target_name;
        transaction->signed_pc_key = gHardenedHandler.signed_pc_key;
        transaction->exception_port_installed = true;
        bool adopted = adopt_hardened_handler_threads(transaction);
        if (!adopted) {
            atomic_store_explicit(&transaction->exception_failed, true,
                                  memory_order_release);
        }
        broker_log("phase=hwbp-exception-install target=%d reused=1 "
                   "port=0x%x targetName=0x%x adopted=%d installed=%d\n",
                   transaction->pid, transaction->exception_port,
                   transaction->target_exception_name, adopted,
                   transaction->exception_port_installed);
        return adopted;
    }

    if (MACH_PORT_VALID(gHardenedHandler.port)) {
        reset_hardened_handler();
    }

    mach_port_options_t options = {
        .flags = MPO_INSERT_SEND_RIGHT | MPO_EXCEPTION_PORT,
    };
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t construct_result = mach_port_construct(
        mach_task_self(), &options, 0, &port);
    mach_port_name_t target_name = MACH_PORT_NULL;
    kern_return_t insert_result = construct_result == KERN_SUCCESS
        ? insert_remote_exception_send_right(
              transaction->task, port, &target_name)
        : construct_result;
    uint32_t signed_pc_key =
        ((uint32_t)arc4random_uniform(255U) + 1U) << 24U;
    kern_return_t register_result = insert_result == KERN_SUCCESS
        ? task_register_hardened_exception_handler(
              transaction->task, signed_pc_key, EXC_MASK_BREAKPOINT,
              CODEX_HARDENED_BEHAVIOR, ARM_THREAD_STATE64, port)
        : insert_result;

    bool registered = register_result == KERN_SUCCESS;
    if (registered) {
        transaction->exception_port = port;
        transaction->target_exception_name = target_name;
        transaction->signed_pc_key = signed_pc_key;
        transaction->exception_port_installed = true;
        gHardenedHandler.pid = transaction->pid;
        gHardenedHandler.port = port;
        gHardenedHandler.target_name = target_name;
        gHardenedHandler.signed_pc_key = signed_pc_key;
    }
    bool adopted = registered &&
        adopt_hardened_handler_threads(transaction);
    bool server_started = adopted && start_hardened_exception_server();
    if (registered && (!adopted || !server_started)) {
        atomic_store_explicit(&transaction->exception_failed, true,
                              memory_order_release);
    }
    broker_log("phase=hwbp-exception-install target=%d reused=0 "
               "constructKr=%d insertKr=%d registerKr=%d port=0x%x "
               "targetName=0x%x pcKey=0x%08x adopted=%d server=%d "
               "installed=%d\n",
               transaction->pid, construct_result, insert_result,
               register_result, port, target_name, signed_pc_key, adopted,
               server_started, transaction->exception_port_installed);

    if (!registered) {
        if (MACH_PORT_VALID(target_name)) {
            (void)mach_port_deallocate(transaction->task, target_name);
        }
        if (MACH_PORT_VALID(port)) {
            destroy_local_receive_port(port);
        }
        atomic_store_explicit(&transaction->exception_failed, true,
                              memory_order_release);
    }
    return registered && adopted && server_started;
}

static bool install_debug_redirects(struct hwbp_transaction *transaction) {
    mach_msg_type_number_t task_count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t task_get_result = task_get_state(
        transaction->task, ARM_DEBUG_STATE64,
        (thread_state_t)&transaction->saved_debug, &task_count);
    bool task_idle = task_get_result == KERN_SUCCESS &&
        task_count == ARM_DEBUG_STATE64_COUNT &&
        debug_state_is_idle(&transaction->saved_debug);

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t threads_result = task_idle
        ? task_threads(transaction->task, &threads, &thread_count)
        : KERN_FAILURE;
    bool threads_idle = threads_result == KERN_SUCCESS;
    kern_return_t preflight_result = KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0;
         threads_idle && index < thread_count; ++index) {
        arm_debug_state64_t state = {0};
        mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
        preflight_result = thread_get_state(
            threads[index], ARM_DEBUG_STATE64, (thread_state_t)&state,
            &count);
        threads_idle = preflight_result == KERN_SUCCESS &&
            count == ARM_DEBUG_STATE64_COUNT && debug_state_is_idle(&state) &&
            memcmp(&state, &transaction->saved_debug, sizeof(state)) == 0;
    }

    arm_debug_state64_t armed = transaction->saved_debug;
    armed.__bvr[0] = transaction->mmap_stub & ~3ULL;
    armed.__bcr[0] = CODEX_HWBP_CONTROL;
    armed.__bvr[1] = transaction->fcntl_stub & ~3ULL;
    armed.__bcr[1] = CODEX_HWBP_CONTROL;
    kern_return_t task_set_result = task_idle && threads_idle
        ? task_set_state(transaction->task, ARM_DEBUG_STATE64,
                         (thread_state_t)&armed, ARM_DEBUG_STATE64_COUNT)
        : KERN_FAILURE;
    if (task_set_result == KERN_SUCCESS) {
        transaction->debug_state_installed = true;
    }
    kern_return_t thread_set_result = KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0;
         thread_set_result == KERN_SUCCESS && index < thread_count &&
         task_set_result == KERN_SUCCESS;
         ++index) {
        thread_set_result = thread_set_state(
            threads[index], ARM_DEBUG_STATE64, (thread_state_t)&armed,
            ARM_DEBUG_STATE64_COUNT);
    }
    bool installed = task_set_result == KERN_SUCCESS &&
        thread_set_result == KERN_SUCCESS;
    broker_log("phase=hwbp-debug-install target=%d taskGetKr=%d "
               "taskCount=%u taskIdle=%d threadsKr=%d threads=%u "
               "threadsIdle=%d preflightKr=%d taskSetKr=%d "
               "threadSetKr=%d control=0x%llx installed=%d\n",
               transaction->pid, task_get_result, task_count, task_idle,
               threads_result, thread_count, threads_idle, preflight_result,
               task_set_result, thread_set_result,
               (unsigned long long)CODEX_HWBP_CONTROL, installed);
    release_thread_list(threads, thread_count);
    return installed;
}

static bool restore_debug_redirects(struct hwbp_transaction *transaction) {
    if (!transaction->debug_state_installed) {
        return true;
    }
    kern_return_t task_result = task_set_state(
        transaction->task, ARM_DEBUG_STATE64,
        (thread_state_t)&transaction->saved_debug,
        ARM_DEBUG_STATE64_COUNT);
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t threads_result = task_threads(
        transaction->task, &threads, &thread_count);
    kern_return_t set_result = KERN_SUCCESS;
    kern_return_t verify_result = KERN_SUCCESS;
    bool verified = threads_result == KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0;
         verified && index < thread_count; ++index) {
        set_result = thread_set_state(
            threads[index], ARM_DEBUG_STATE64,
            (thread_state_t)&transaction->saved_debug,
            ARM_DEBUG_STATE64_COUNT);
        arm_debug_state64_t readback = {0};
        mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
        verify_result = set_result == KERN_SUCCESS
            ? thread_get_state(threads[index], ARM_DEBUG_STATE64,
                               (thread_state_t)&readback, &count)
            : set_result;
        verified = verify_result == KERN_SUCCESS &&
            count == ARM_DEBUG_STATE64_COUNT &&
            memcmp(&readback, &transaction->saved_debug,
                   sizeof(readback)) == 0;
    }
    bool restored = task_result == KERN_SUCCESS &&
        threads_result == KERN_SUCCESS && set_result == KERN_SUCCESS &&
        verified;
    broker_log("phase=hwbp-debug-restore target=%d taskKr=%d threadsKr=%d "
               "threads=%u setKr=%d verifyKr=%d verified=%d restored=%d\n",
               transaction->pid, task_result, threads_result, thread_count,
               set_result, verify_result, verified, restored);
    release_thread_list(threads, thread_count);
    if (restored) {
        transaction->debug_state_installed = false;
    }
    return restored;
}

static bool restore_exception_port(struct hwbp_transaction *transaction) {
    bool retained = !transaction->exception_port_installed ||
        (gHardenedHandler.pid == transaction->pid &&
         gHardenedHandler.port == transaction->exception_port &&
         gHardenedHandler.thread_started);
    broker_log("phase=hwbp-exception-retain target=%d port=0x%x "
               "targetName=0x%x retained=%d\n",
               transaction->pid, transaction->exception_port,
               transaction->target_exception_name, retained);
    return retained;
}

static void release_exception_resources(
    struct hwbp_transaction *transaction) {
    transaction->exception_port = MACH_PORT_NULL;
    transaction->target_exception_name = MACH_PORT_NULL;
    transaction->signed_pc_key = 0;
    transaction->exception_port_installed = false;
}

__attribute__((visibility("default"))) kern_return_t
catch_mach_exception_raise_state_identity_protected(
    mach_port_t exception_port, uint64_t thread_id,
    mach_port_t task_id_token, exception_type_t exception,
    mach_exception_data_t code, mach_msg_type_number_t code_count,
    int *flavor, thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state, mach_msg_type_number_t *new_state_count) {
    struct hwbp_transaction *transaction = atomic_load_explicit(
        &gActiveHwbpTransaction, memory_order_acquire);
    bool shape_ok = transaction != NULL &&
        exception_port == transaction->exception_port &&
        exception == EXC_BREAKPOINT && flavor != NULL &&
        *flavor == ARM_THREAD_STATE64 &&
        old_state_count == ARM_THREAD_STATE64_COUNT &&
        new_state_count != NULL &&
        *new_state_count >= ARM_THREAD_STATE64_COUNT;
    if (!shape_ok) {
        if (transaction != NULL) {
            (void)atomic_fetch_add_explicit(
                &transaction->unexpected_exceptions, 1,
                memory_order_relaxed);
            atomic_store_explicit(&transaction->exception_failed, true,
                                  memory_order_release);
        }
        broker_log("phase=hwbp-exception admitted=0 active=%d port=0x%x "
                   "threadId=%llu token=0x%x exception=%d codeCount=%u "
                   "flavor=%d oldCount=%u capacity=%u\n",
                   transaction != NULL, exception_port,
                   (unsigned long long)thread_id, task_id_token, exception,
                   code_count,
                   flavor != NULL ? *flavor : -1, old_state_count,
                   new_state_count != NULL ? *new_state_count : 0);
        return KERN_FAILURE;
    }

    memcpy(new_state, old_state,
           (size_t)old_state_count * sizeof(natural_t));
    arm_thread_state64_t *state = (arm_thread_state64_t *)new_state;
    mach_vm_address_t pc = canonical_remote_address(
        (uint64_t)arm_thread_state64_get_pc(*state));
    mach_vm_address_t redirect = 0;
    const char *kind = "unexpected";
    if (pc == transaction->mmap_stub) {
        redirect = transaction->mmap_hook;
        (void)atomic_fetch_add_explicit(&transaction->mmap_hits, 1,
                                        memory_order_relaxed);
        kind = "mmap";
    } else if (pc == transaction->fcntl_stub) {
        redirect = transaction->fcntl_hook;
        (void)atomic_fetch_add_explicit(&transaction->fcntl_hits, 1,
                                        memory_order_relaxed);
        kind = "fcntl";
    }
    if (redirect == 0) {
        (void)atomic_fetch_add_explicit(
            &transaction->unexpected_exceptions, 1,
            memory_order_relaxed);
        atomic_store_explicit(&transaction->exception_failed, true,
                              memory_order_release);
        broker_log("phase=hwbp-exception admitted=0 threadId=%llu "
                   "token=0x%x exception=%d code0=%lld code1=%lld "
                   "pc=0x%llx\n",
                   (unsigned long long)thread_id, task_id_token, exception,
                   (long long)(code_count > 0 ? code[0] : -1),
                   (long long)(code_count > 1 ? code[1] : -1),
                   (unsigned long long)pc);
        return KERN_FAILURE;
    }

    void *signed_pc = signed_remote_function_pointer(redirect);
    arm_thread_state64_set_pc_fptr(*state, signed_pc);
    *new_state_count = ARM_THREAD_STATE64_COUNT;
    unsigned int mmap_hits = atomic_load_explicit(
        &transaction->mmap_hits, memory_order_relaxed);
    unsigned int fcntl_hits = atomic_load_explicit(
        &transaction->fcntl_hits, memory_order_relaxed);
    broker_log("phase=hwbp-exception admitted=1 kind=%s threadId=%llu "
               "token=0x%x code0=%lld code1=%lld pc=0x%llx "
               "redirect=0x%llx "
               "mmapHits=%u fcntlHits=%u\n",
               kind, (unsigned long long)thread_id, task_id_token,
               (long long)(code_count > 0 ? code[0] : -1),
               (long long)(code_count > 1 ? code[1] : -1),
               (unsigned long long)pc, (unsigned long long)redirect,
               mmap_hits, fcntl_hits);
    return KERN_SUCCESS;
}

static int dispatch_one_hardened_exception(mach_port_t exception_port) {
    union {
        uint64_t alignment;
        uint8_t bytes[CODEX_EXCEPTION_MESSAGE_SIZE];
    } request = {0}, reply = {0};
    mach_msg_header_t *request_header =
        (mach_msg_header_t *)(void *)request.bytes;
    mach_msg_return_t receive_result = mach_msg(
        request_header, MACH_RCV_MSG | MACH_RCV_LARGE, 0,
        (mach_msg_size_t)sizeof(request.bytes), exception_port,
        MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (receive_result == MACH_RCV_INTERRUPTED) {
        return 0;
    }
    if (receive_result != MACH_MSG_SUCCESS) {
        broker_log("phase=hwbp-exception-receive port=0x%x result=%d\n",
                   exception_port, receive_result);
        return -1;
    }

    mach_port_t received_token = MACH_PORT_NULL;
    size_t descriptor_offset = sizeof(mach_msg_header_t) +
        sizeof(mach_msg_body_t);
    if (request_header->msgh_id == 2410 &&
        (request_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0 &&
        request_header->msgh_size >= descriptor_offset +
            sizeof(mach_msg_port_descriptor_t)) {
        mach_msg_body_t *body = (mach_msg_body_t *)(void *)(
            request.bytes + sizeof(mach_msg_header_t));
        mach_msg_port_descriptor_t *descriptor =
            (mach_msg_port_descriptor_t *)(void *)(
                request.bytes + descriptor_offset);
        if (body->msgh_descriptor_count >= 1 &&
            descriptor->type == MACH_MSG_PORT_DESCRIPTOR) {
            received_token = descriptor->name;
        }
    }

    (void)atomic_fetch_add_explicit(&gExceptionDispatchActive, 1,
                                    memory_order_acq_rel);
    mach_msg_header_t *reply_header =
        (mach_msg_header_t *)(void *)reply.bytes;
    boolean_t handled = codex_mach_exc_server(request_header, reply_header);
    if (!handled) {
        mach_msg_destroy(request_header);
        broker_log("phase=hwbp-exception-demux handled=0 id=%d\n",
                   request_header->msgh_id);
        (void)atomic_fetch_sub_explicit(&gExceptionDispatchActive, 1,
                                        memory_order_acq_rel);
        return -1;
    }
    mach_msg_return_t send_result = mach_msg(
        reply_header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        reply_header->msgh_size, 0, MACH_PORT_NULL, 1000,
        MACH_PORT_NULL);
    if (MACH_PORT_VALID(received_token)) {
        (void)mach_port_deallocate(mach_task_self(), received_token);
    }
    if (send_result != MACH_MSG_SUCCESS) {
        mach_msg_destroy(reply_header);
        broker_log("phase=hwbp-exception-reply result=%d id=%d\n",
                   send_result, reply_header->msgh_id);
        struct hwbp_transaction *transaction = atomic_load_explicit(
            &gActiveHwbpTransaction, memory_order_acquire);
        if (transaction != NULL) {
            atomic_store_explicit(&transaction->exception_failed, true,
                                  memory_order_release);
        }
        (void)atomic_fetch_sub_explicit(&gExceptionDispatchActive, 1,
                                        memory_order_acq_rel);
        return -1;
    }
    (void)atomic_fetch_sub_explicit(&gExceptionDispatchActive, 1,
                                    memory_order_acq_rel);
    return 1;
}

static void *hardened_exception_server_main(void *argument) {
    mach_port_t port = (mach_port_t)(uintptr_t)argument;
    broker_log("phase=hwbp-exception-server state=running port=0x%x\n",
               port);
    for (;;) {
        int result = dispatch_one_hardened_exception(port);
        if (result < 0) {
            break;
        }
    }
    broker_log("phase=hwbp-exception-server state=stopped port=0x%x\n",
               port);
    return NULL;
}

static bool wait_for_exception_dispatch_idle(
    struct hwbp_transaction *transaction) {
    kern_return_t status_result = KERN_FAILURE;
    mach_port_status_t status = {0};
    unsigned int stable = 0;
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS;
         ++attempt) {
        mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
        memset(&status, 0, sizeof(status));
        status_result = mach_port_get_attributes(
            mach_task_self(), transaction->exception_port,
            MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &count);
        unsigned int active = atomic_load_explicit(
            &gExceptionDispatchActive, memory_order_acquire);
        if (status_result == KERN_SUCCESS && status.mps_msgcount == 0 &&
            active == 0) {
            if (++stable >= 2U) {
                broker_log("phase=hwbp-exception-idle target=%d "
                           "statusKr=%d queued=%u active=%u idle=1\n",
                           transaction->pid, status_result,
                           status.mps_msgcount, active);
                return true;
            }
        } else {
            stable = 0;
        }
        usleep(1000U);
    }
    broker_log("phase=hwbp-exception-idle target=%d statusKr=%d "
               "queued=%u active=%u idle=0\n",
               transaction->pid, status_result, status.mps_msgcount,
               atomic_load_explicit(&gExceptionDispatchActive,
                                    memory_order_acquire));
    return false;
}

static bool threads_outside_hook_page(
    struct hwbp_transaction *transaction, unsigned int *inside_count) {
    *inside_count = 0;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t threads_result = task_threads(
        transaction->task, &threads, &thread_count);
    bool valid = threads_result == KERN_SUCCESS;
    for (mach_msg_type_number_t index = 0;
         valid && index < thread_count; ++index) {
        arm_thread_state64_t state = {0};
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kern_return_t state_result = thread_get_state(
            threads[index], ARM_THREAD_STATE64, (thread_state_t)&state,
            &count);
        valid = state_result == KERN_SUCCESS &&
            count == ARM_THREAD_STATE64_COUNT;
        if (valid) {
            mach_vm_address_t pc = canonical_remote_address(
                (uint64_t)arm_thread_state64_get_pc(state));
            if (pc >= transaction->code_page &&
                pc < transaction->code_page +
                    transaction->code_page_size) {
                ++*inside_count;
            }
        }
    }
    release_thread_list(threads, thread_count);
    return valid && *inside_count == 0;
}

static bool quiesce_hwbp_target(struct hwbp_transaction *transaction) {
    for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
        if (!transaction->trace_stopped) {
            if (!read_exact_process(transaction->pid, kSpringBoardPath)) {
                return false;
            }
            errno = 0;
            int signal_result = kill(transaction->pid, SIGSTOP);
            int signal_error = errno;
            bool stopped = false;
            int status = 0;
            for (unsigned int wait_attempt = 0;
                 signal_result == 0 &&
                 wait_attempt < CODEX_WAIT_ATTEMPTS;
                 ++wait_attempt) {
                pid_t waited;
                do {
                    waited = waitpid(transaction->pid, &status,
                                     WUNTRACED | WNOHANG);
                } while (waited < 0 && errno == EINTR);
                if (waited == transaction->pid) {
                    stopped = WIFSTOPPED(status);
                    break;
                }
                if (waited < 0) {
                    break;
                }
                usleep(1000U);
            }
            transaction->trace_stopped = stopped;
            broker_log("phase=hwbp-quiesce-stop target=%d attempt=%u "
                       "signal=%d signalErrno=%d stopped=%d status=0x%x\n",
                       transaction->pid, attempt, signal_result,
                       signal_error, stopped, status);
            if (!stopped) {
                return false;
            }
        }
        bool dispatch_idle = wait_for_exception_dispatch_idle(transaction);
        unsigned int inside = 0;
        bool exception_failed = atomic_load_explicit(
            &transaction->exception_failed, memory_order_acquire);
        bool outside = dispatch_idle && !exception_failed &&
            threads_outside_hook_page(transaction, &inside);
        broker_log("phase=hwbp-quiesce target=%d attempt=%u idle=%d "
                   "inside=%u outside=%d exceptionFailed=%d\n",
                   transaction->pid, attempt, dispatch_idle, inside,
                   outside, exception_failed);
        if (outside) {
            return true;
        }
        errno = 0;
        int continue_result = exception_failed
            ? -1
            : ptrace(CODEX_PT_CONTINUE, transaction->pid, (caddr_t)1, 0);
        int continue_error = errno;
        broker_log("phase=hwbp-quiesce-continue target=%d attempt=%u "
                   "result=%d errno=%d\n",
                   transaction->pid, attempt, continue_result,
                   continue_error);
        if (continue_result != 0) {
            return false;
        }
        transaction->trace_stopped = false;
    }
    return false;
}

static int spawn_injector_async(pid_t target, const char *path,
                                pid_t *child) {
    char pid_text[32];
    (void)snprintf(pid_text, sizeof(pid_text), "%d", target);
    char *arguments[] = {
        (char *)kLoaderPath,
        "--inject-pid",
        pid_text,
        (char *)path,
        NULL,
    };
    posix_spawn_file_actions_t actions;
    int actions_result = posix_spawn_file_actions_init(&actions);
    if (actions_result == 0) {
        (void)posix_spawn_file_actions_adddup2(&actions, gLog,
                                               STDOUT_FILENO);
        (void)posix_spawn_file_actions_adddup2(&actions, gLog,
                                               STDERR_FILENO);
    }
    *child = -1;
    int spawn_result = actions_result == 0
        ? posix_spawn(child, kLoaderPath, &actions, NULL, arguments, environ)
        : actions_result;
    if (actions_result == 0) {
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    broker_log("phase=hwbp-injector-spawn result=%d child=%d target=%d "
               "path=%s\n",
               spawn_result, *child, target, path);
    return spawn_result == 0 && *child > 1 ? 0 : 70;
}

static int run_injector_with_hwbp(
    struct hwbp_transaction *transaction, const char *path) {
    pid_t child = -1;
    int spawn_result = spawn_injector_async(transaction->pid, path, &child);
    if (spawn_result != 0) {
        return spawn_result;
    }
    int status = 0;
    bool complete = false;
    bool event_failed = false;
    for (unsigned int attempt = 0;
         attempt < CODEX_INJECT_TIMEOUT_ATTEMPTS; ++attempt) {
        int target_status = 0;
        pid_t target_waited;
        do {
            target_waited = waitpid(transaction->pid, &target_status,
                                    WUNTRACED | WNOHANG);
        } while (target_waited < 0 && errno == EINTR);
        if (target_waited == transaction->pid) {
            bool stopped = WIFSTOPPED(target_status) &&
                read_exact_process(transaction->pid, kSpringBoardPath);
            transaction->trace_stopped = stopped;
            broker_log("phase=hwbp-target-event target=%d status=0x%x "
                       "stopped=%d signal=%d\n",
                       transaction->pid, target_status, stopped,
                       stopped ? WSTOPSIG(target_status) : 0);
            if (!stopped || !adopt_hardened_handler_threads(transaction)) {
                event_failed = true;
                break;
            }
            errno = 0;
            int continue_result = ptrace(
                CODEX_PT_CONTINUE, transaction->pid, (caddr_t)1, 0);
            int continue_error = errno;
            broker_log("phase=hwbp-target-event-continue target=%d "
                       "result=%d errno=%d\n",
                       transaction->pid, continue_result, continue_error);
            if (continue_result != 0) {
                event_failed = true;
                break;
            }
            transaction->trace_stopped = false;
        } else if (target_waited < 0 && errno != ECHILD) {
            event_failed = true;
            break;
        }

        pid_t waited;
        do {
            waited = waitpid(child, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == child) {
            complete = true;
            break;
        }
        if (waited < 0) {
            event_failed = true;
            break;
        }
        bool exception_failed = atomic_load_explicit(
            &transaction->exception_failed, memory_order_acquire);
        if (exception_failed ||
            !read_exact_process(transaction->pid, kSpringBoardPath)) {
            event_failed = true;
            break;
        }
        usleep(10U * 1000U);
    }
    if (!complete) {
        (void)kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
    }
    event_failed = event_failed || atomic_load_explicit(
        &transaction->exception_failed, memory_order_acquire);
    int result = complete && !event_failed && WIFEXITED(status)
        ? WEXITSTATUS(status)
        : 71;
    broker_log("phase=hwbp-injector-complete child=%d complete=%d "
               "eventFailed=%d status=0x%x result=%d mmapHits=%u "
               "fcntlHits=%u unexpected=%u\n",
               child, complete, event_failed, status, result,
               atomic_load_explicit(&transaction->mmap_hits,
                                    memory_order_relaxed),
               atomic_load_explicit(&transaction->fcntl_hits,
                                    memory_order_relaxed),
               atomic_load_explicit(&transaction->unexpected_exceptions,
                                    memory_order_relaxed));
    return result;
}

static bool install_hooks(struct hook_transaction *transaction) {
    task_dyld_info_data_t dyld_info = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t dyld_result = task_info(
        transaction->task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    struct dyld_all_image_infos infos = {0};
    bool info_read = dyld_result == KERN_SUCCESS &&
        dyld_info.all_image_info_addr != 0 &&
        read_remote(transaction->task, dyld_info.all_image_info_addr,
                    &infos, sizeof(infos)) == KERN_SUCCESS;
    mach_vm_address_t dyld_header = info_read
        ? canonical_remote_address((uint64_t)infos.dyldImageLoadAddress)
        : 0;
    transaction->mmap_stub = dyld_header != 0
        ? find_remote_pattern(transaction->task, dyld_header, kMmapPattern,
                              sizeof(kMmapPattern))
        : 0;
    transaction->fcntl_stub = dyld_header != 0
        ? find_remote_pattern(transaction->task, dyld_header, kFcntlPattern,
                              sizeof(kFcntlPattern))
        : 0;
    if (transaction->mmap_stub == 0 && transaction->fcntl_stub != 0 &&
        repair_interrupted_mmap_patch(transaction->task, dyld_header,
                                      &transaction->integrity_lost)) {
        transaction->mmap_stub = find_remote_pattern(
            transaction->task, dyld_header, kMmapPattern,
            sizeof(kMmapPattern));
    }

    uintptr_t blob_start = (uintptr_t)codex_remote_blob_start;
    uintptr_t blob_end = (uintptr_t)codex_remote_blob_end;
    uintptr_t mmap_local = (uintptr_t)codex_remote_mmap_hook;
    uintptr_t fcntl_local = (uintptr_t)codex_remote_fcntl_hook;
    mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    bool layout_ok = blob_end > blob_start &&
        blob_end - blob_start <= page_size && mmap_local >= blob_start &&
        mmap_local < blob_end && fcntl_local >= blob_start &&
        fcntl_local < blob_end;
    broker_log("phase=resolve target=%d dyldKr=%d dyld=0x%llx "
               "mmap=0x%llx fcntl=0x%llx layout=%d\n",
               transaction->pid, dyld_result,
               (unsigned long long)dyld_header,
               (unsigned long long)transaction->mmap_stub,
               (unsigned long long)transaction->fcntl_stub, layout_ok);
    if (!layout_ok || transaction->mmap_stub == 0 ||
        transaction->fcntl_stub == 0 ||
        read_remote(transaction->task, transaction->mmap_stub,
                    transaction->saved_mmap,
                    sizeof(transaction->saved_mmap)) != KERN_SUCCESS ||
        read_remote(transaction->task, transaction->fcntl_stub,
                    transaction->saved_fcntl,
                    sizeof(transaction->saved_fcntl)) != KERN_SUCCESS ||
        memcmp(transaction->saved_mmap, kMmapPattern,
               sizeof(kMmapPattern)) != 0 ||
        memcmp(transaction->saved_fcntl, kFcntlPattern,
               sizeof(kFcntlPattern)) != 0) {
        return false;
    }

    kern_return_t allocate_result = mach_vm_allocate(
        transaction->task, &transaction->code_page, page_size,
        VM_FLAGS_ANYWHERE);
    bool code_written = allocate_result == KERN_SUCCESS &&
        write_executable_bytes(transaction->task, transaction->code_page,
                               codex_remote_blob_start,
                               blob_end - blob_start);
    transaction->code = code_written ? transaction->code_page : 0;
    kern_return_t remap_result = KERN_INVALID_ARGUMENT;
    vm_prot_t remap_current = VM_PROT_NONE;
    vm_prot_t remap_maximum = VM_PROT_NONE;
    if (!code_written) {
        if (transaction->code_page != 0) {
            (void)mach_vm_deallocate(transaction->task,
                                     transaction->code_page, page_size);
            transaction->code_page = 0;
        }
        mach_vm_address_t source_page =
            blob_start & ~(mach_vm_address_t)(page_size - 1U);
        mach_vm_size_t blob_offset = blob_start - source_page;
        bool source_layout_ok = blob_offset + (blob_end - blob_start) <=
            page_size;
        if (source_layout_ok) {
            remap_result = mach_vm_remap(
                transaction->task, &transaction->code_page, page_size, 0,
                VM_FLAGS_ANYWHERE, mach_task_self(), source_page, false,
                &remap_current, &remap_maximum, VM_INHERIT_NONE);
            if (remap_result == KERN_SUCCESS &&
                (remap_current & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
                    (VM_PROT_READ | VM_PROT_EXECUTE)) {
                transaction->code = transaction->code_page + blob_offset;
            } else if (transaction->code_page != 0) {
                (void)mach_vm_deallocate(transaction->task,
                                         transaction->code_page, page_size);
                transaction->code_page = 0;
            }
        }
    }
    bool code_admitted = transaction->code != 0;
    uint8_t branch[20] = {0};
    make_absolute_branch(
        transaction->code + (mmap_local - blob_start), branch);
    transaction->mmap_hooked = code_admitted &&
        remap_patched_executable_page(
            transaction->task, transaction->mmap_stub, branch,
            &transaction->mmap_original_page,
            &transaction->integrity_lost);
    make_absolute_branch(
        transaction->code + (fcntl_local - blob_start), branch);
    transaction->fcntl_hooked = transaction->mmap_hooked &&
        remap_patched_executable_page(
            transaction->task, transaction->fcntl_stub, branch,
            &transaction->fcntl_original_page,
            &transaction->integrity_lost);
    broker_log("phase=hooks-install target=%d allocKr=%d remapKr=%d "
               "remapCurrent=0x%x remapMaximum=0x%x codePage=0x%llx "
               "code=0x%llx written=%d admitted=%d mmap=%d fcntl=%d\n",
               transaction->pid, allocate_result,
               remap_result, remap_current, remap_maximum,
               (unsigned long long)transaction->code_page,
               (unsigned long long)transaction->code, code_written,
               code_admitted,
               transaction->mmap_hooked, transaction->fcntl_hooked);
    if (!transaction->fcntl_hooked) {
        if (transaction->mmap_hooked) {
            (void)restore_remapped_executable_page(
                transaction->task, transaction->mmap_stub,
                &transaction->mmap_original_page,
                transaction->saved_mmap,
                &transaction->integrity_lost);
            transaction->mmap_hooked = false;
        }
        if (transaction->code_page != 0) {
            (void)mach_vm_deallocate(transaction->task,
                                     transaction->code_page, page_size);
            transaction->code = 0;
            transaction->code_page = 0;
        }
        return false;
    }
    return true;
}

static bool restore_hooks(struct hook_transaction *transaction) {
    bool fcntl_restored = !transaction->fcntl_hooked ||
        restore_remapped_executable_page(
            transaction->task, transaction->fcntl_stub,
            &transaction->fcntl_original_page, transaction->saved_fcntl,
            &transaction->integrity_lost);
    bool mmap_restored = fcntl_restored &&
        (!transaction->mmap_hooked ||
         restore_remapped_executable_page(
             transaction->task, transaction->mmap_stub,
             &transaction->mmap_original_page, transaction->saved_mmap,
             &transaction->integrity_lost));
    kern_return_t deallocate_result =
        transaction->code_page != 0 && mmap_restored
        ? mach_vm_deallocate(transaction->task, transaction->code_page,
                             (mach_vm_size_t)getpagesize())
        : (transaction->code_page == 0 ? KERN_SUCCESS : KERN_FAILURE);
    broker_log("phase=hooks-restore target=%d fcntl=%d mmap=%d "
               "deallocKr=%d\n",
               transaction->pid, fcntl_restored, mmap_restored,
               deallocate_result);
    return fcntl_restored && mmap_restored &&
        !transaction->integrity_lost &&
        deallocate_result == KERN_SUCCESS;
}

static int spawn_injector(pid_t target, const char *path) {
    char pid_text[32];
    (void)snprintf(pid_text, sizeof(pid_text), "%d", target);
    char *arguments[] = {
        (char *)kLoaderPath,
        "--inject-pid",
        pid_text,
        (char *)path,
        NULL,
    };
    posix_spawn_file_actions_t actions;
    int actions_result = posix_spawn_file_actions_init(&actions);
    if (actions_result == 0) {
        (void)posix_spawn_file_actions_adddup2(&actions, gLog,
                                                STDOUT_FILENO);
        (void)posix_spawn_file_actions_adddup2(&actions, gLog,
                                                STDERR_FILENO);
    }
    pid_t child = -1;
    int spawn_result = actions_result == 0
        ? posix_spawn(&child, kLoaderPath, &actions, NULL, arguments, environ)
        : actions_result;
    if (actions_result == 0) {
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    if (spawn_result != 0 || child <= 1) {
        broker_log("phase=injector-spawn result=%d child=%d\n",
                   spawn_result, child);
        return 70;
    }
    int status = 0;
    bool complete = false;
    for (unsigned int attempt = 0; attempt < 3000U; ++attempt) {
        pid_t waited;
        do {
            waited = waitpid(child, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == child) {
            complete = true;
            break;
        }
        if (waited < 0) {
            break;
        }
        usleep(10U * 1000U);
    }
    if (!complete) {
        (void)kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
    }
    int result = complete && WIFEXITED(status) ? WEXITSTATUS(status) : 71;
    broker_log("phase=injector-complete child=%d complete=%d status=0x%x "
               "result=%d\n",
               child, complete, status, result);
    return result;
}

__attribute__((unused)) static int
inject_springboard_legacy_page_path(const char *requested_path) {
    char path[PATH_MAX] = {0};
    if (geteuid() != 0 || access(kLoaderPath, X_OK) != 0 ||
        !validate_dylib_path(requested_path, path)) {
        broker_log("phase=inject-preflight admitted=0 errno=%d request=%s\n",
                   errno, requested_path != NULL ? requested_path : "<null>");
        return 10;
    }
    pid_t target = find_springboard();
    if (target <= 1) {
        broker_log("phase=target result=missing pid=%d\n", target);
        return 11;
    }

    struct hook_transaction transaction = {
        .pid = target,
        .task = MACH_PORT_NULL,
    };
    uint32_t flags = 0;
    bool attached = attach_target(target, &transaction.task, &flags);
    broker_log("phase=target pid=%d attached=%d flags=0x%08x task=0x%x\n",
               target, attached, flags, transaction.task);
    if (!attached) {
        return 12;
    }
    bool hooks_installed = install_hooks(&transaction);
    int first_detach = hooks_installed ? detach_target(target) : -1;
    broker_log("phase=target-resume pid=%d hooks=%d detach=%d errno=%d\n",
               target, hooks_installed, first_detach, errno);
    if (!hooks_installed || first_detach != 0) {
        bool restored = restore_hooks(&transaction);
        bool restart = !restored || transaction.integrity_lost;
        bool restarted = false;
        if (restart) {
            restarted = restart_verified_springboard(
                target, "install-or-initial-restore-failed");
        } else if (read_exact_process(target, kSpringBoardPath)) {
            (void)detach_target(target);
        }
        broker_log("phase=transaction-abort pid=%d restored=%d "
                   "integrityLost=%d restart=%d restarted=%d\n",
                   target, restored, transaction.integrity_lost, restart,
                   restarted);
        release_local_snapshots(&transaction);
        (void)mach_port_deallocate(mach_task_self(), transaction.task);
        return 13;
    }

    int injector_result = spawn_injector(target, path);

    errno = 0;
    int reattach_result = ptrace(CODEX_PT_ATTACHEXC, target, NULL, 0);
    int reattach_error = errno;
    int stop_status = 0;
    bool trace_stopped = reattach_result == 0 &&
        wait_for_trace_stop(target, &stop_status) &&
        read_exact_process(target, kSpringBoardPath);
    bool task_suspended = false;
    kern_return_t suspend_result = KERN_FAILURE;
    if (!trace_stopped) {
        suspend_result = task_suspend(transaction.task);
        task_suspended = suspend_result == KERN_SUCCESS;
    }
    bool restored = (trace_stopped || task_suspended) &&
        restore_hooks(&transaction);
    bool target_same = read_exact_process(target, kSpringBoardPath);
    bool restart = (!restored || transaction.integrity_lost) && target_same;
    bool restarted = false;
    if (restart) {
        restarted = restart_verified_springboard(
            target, "post-injection-restore-failed");
        if (task_suspended) {
            (void)task_resume(transaction.task);
        }
    } else if (trace_stopped) {
        (void)detach_target(target);
    } else if (task_suspended) {
        (void)task_resume(transaction.task);
    }
    broker_log("phase=transaction-complete pid=%d injector=%d "
               "reattach=%d reattachErrno=%d stopped=%d suspendKr=%d "
               "restored=%d integrityLost=%d same=%d "
               "failClosedRestart=%d restarted=%d path=%s\n",
               target, injector_result, reattach_result, reattach_error,
               trace_stopped, suspend_result, restored,
               transaction.integrity_lost, target_same, restart, restarted,
               path);
    release_local_snapshots(&transaction);
    (void)mach_port_deallocate(mach_task_self(), transaction.task);
    return injector_result == 0 && restored ? 0 : 14;
}

static bool restart_traced_hwbp_target(
    struct hwbp_transaction *transaction, const char *reason) {
    if (!read_exact_process(transaction->pid, kSpringBoardPath)) {
        broker_log("phase=hwbp-fail-closed-restart pid=%d admitted=0 "
                   "reason=%s\n",
                   transaction->pid, reason);
        return false;
    }
    errno = 0;
    int terminate_result = transaction->trace_attached &&
        transaction->trace_stopped
        ? ptrace(CODEX_PT_KILL, transaction->pid, NULL, 0)
        : kill(transaction->pid, SIGKILL);
    int terminate_error = errno;
    int fallback_kill = 0;
    int fallback_continue = 0;
    if (terminate_result != 0 &&
        read_exact_process(transaction->pid, kSpringBoardPath)) {
        fallback_kill = kill(transaction->pid, SIGKILL);
        if (fallback_kill == 0 && transaction->trace_stopped) {
            fallback_continue = ptrace(CODEX_PT_CONTINUE, transaction->pid,
                                       (caddr_t)1, 0);
        }
    }
    bool exited = false;
    if (terminate_result == 0 || fallback_kill == 0) {
        for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS;
             ++attempt) {
            if (!read_exact_process(transaction->pid, kSpringBoardPath)) {
                exited = true;
                break;
            }
            usleep(CODEX_WAIT_DELAY_USEC);
        }
    }
    if (exited) {
        transaction->trace_attached = false;
        transaction->trace_stopped = false;
    }
    broker_log("phase=hwbp-fail-closed-restart pid=%d admitted=1 "
               "terminate=%d terminateErrno=%d fallbackKill=%d "
               "fallbackContinue=%d exited=%d reason=%s\n",
               transaction->pid, terminate_result, terminate_error,
               fallback_kill, fallback_continue, exited, reason);
    return (terminate_result == 0 || fallback_kill == 0) && exited;
}

static int inject_springboard(const char *requested_path) {
    char path[PATH_MAX] = {0};
    if (geteuid() != 0 || access(kLoaderPath, X_OK) != 0 ||
        !validate_dylib_path(requested_path, path)) {
        broker_log("phase=hwbp-preflight admitted=0 errno=%d request=%s\n",
                   errno, requested_path != NULL ? requested_path : "<null>");
        return 10;
    }
    pid_t target = find_springboard();
    if (target <= 1) {
        broker_log("phase=hwbp-target result=missing pid=%d\n", target);
        return 11;
    }

    struct hwbp_transaction transaction = {
        .pid = target,
        .task = MACH_PORT_NULL,
        .exception_port = MACH_PORT_NULL,
    };
    uint32_t flags = 0;
    bool attached = attach_hwbp_target(&transaction, &flags);
    broker_log("phase=hwbp-target pid=%d attached=%d stopped=%d "
               "flags=0x%08x task=0x%x\n",
               target, attached, transaction.trace_stopped, flags,
               transaction.task);
    if (!attached) {
        return 12;
    }

    int result = 13;
    bool same_target = transaction.trace_stopped &&
        read_exact_process(target, kSpringBoardPath);
    if (!same_target) {
        goto cleanup;
    }
    if (!resolve_and_map_hwbp_hooks(&transaction)) {
        result = 14;
        goto cleanup;
    }
    if (!preflight_trusted_stop_gate(&transaction)) {
        result = 15;
        goto cleanup;
    }
    if (!install_exception_port(&transaction)) {
        result = 16;
        goto cleanup;
    }
    if (!install_debug_redirects(&transaction)) {
        result = 17;
        goto cleanup;
    }

    atomic_store_explicit(&gActiveHwbpTransaction, &transaction,
                          memory_order_release);
    errno = 0;
    int initial_continue = ptrace(CODEX_PT_CONTINUE, target, (caddr_t)1, 0);
    int initial_continue_error = errno;
    broker_log("phase=hwbp-continue pid=%d result=%d errno=%d\n", target,
               initial_continue, initial_continue_error);
    if (initial_continue != 0) {
        result = 18;
        goto cleanup;
    }
    transaction.trace_stopped = false;
    result = run_injector_with_hwbp(&transaction, path);
    if (!quiesce_hwbp_target(&transaction)) {
        result = 19;
    }

cleanup:
    same_target = read_exact_process(target, kSpringBoardPath);
    if (!transaction.trace_stopped && same_target &&
        (transaction.debug_state_installed ||
         transaction.exception_port_installed ||
         transaction.code_page != 0)) {
        bool stopped = quiesce_hwbp_target(&transaction);
        broker_log("phase=hwbp-cleanup-stop pid=%d stopped=%d\n", target,
                   stopped);
    }

    bool debug_restored = transaction.trace_stopped
        ? restore_debug_redirects(&transaction)
        : !transaction.debug_state_installed;
    bool exception_restored = transaction.trace_stopped && debug_restored
        ? restore_exception_port(&transaction)
        : !transaction.exception_port_installed;
    atomic_store_explicit(&gActiveHwbpTransaction, NULL,
                          memory_order_release);
    kern_return_t deallocate_result = KERN_SUCCESS;
    if (transaction.code_page != 0 && transaction.trace_stopped &&
        debug_restored && exception_restored) {
        deallocate_result = mach_vm_deallocate(
            transaction.task, transaction.code_page,
            transaction.code_page_size);
        if (deallocate_result == KERN_SUCCESS) {
            transaction.code_page = 0;
        }
    } else if (transaction.code_page != 0) {
        deallocate_result = KERN_FAILURE;
    }
    bool exception_ok = !atomic_load_explicit(
        &transaction.exception_failed, memory_order_acquire);
    bool clean = debug_restored && exception_restored &&
        deallocate_result == KERN_SUCCESS && exception_ok;
    bool detached = false;
    bool restarted = false;
    same_target = read_exact_process(target, kSpringBoardPath);
    if (clean && transaction.trace_attached &&
        transaction.trace_stopped && same_target) {
        int detach_result = detach_target(target);
        detached = detach_result == 0;
        clean = clean && detached;
        if (detached) {
            transaction.trace_attached = false;
            transaction.trace_stopped = false;
        }
        broker_log("phase=hwbp-cleanup-detach pid=%d result=%d "
                   "detached=%d\n",
                   target, detach_result, detached);
    }
    if (!clean && same_target) {
        restarted = restart_traced_hwbp_target(
            &transaction, "hwbp-transaction-cleanup-failed");
    }
    bool target_gone = !read_exact_process(target, kSpringBoardPath);
    unsigned int mmap_hits = atomic_load_explicit(
        &transaction.mmap_hits, memory_order_relaxed);
    unsigned int fcntl_hits = atomic_load_explicit(
        &transaction.fcntl_hits, memory_order_relaxed);
    unsigned int unexpected = atomic_load_explicit(
        &transaction.unexpected_exceptions, memory_order_relaxed);
    broker_log("phase=hwbp-transaction-complete pid=%d injector=%d "
               "debugRestored=%d exceptionRestored=%d deallocKr=%d "
               "exceptionOk=%d clean=%d detached=%d restart=%d gone=%d "
               "mmapHits=%u fcntlHits=%u unexpected=%u path=%s\n",
               target, result, debug_restored, exception_restored,
               deallocate_result, exception_ok, clean, detached, restarted,
               target_gone, mmap_hits, fcntl_hits, unexpected, path);

    if (clean || target_gone) {
        release_exception_resources(&transaction);
    }
    if (target_gone && gHardenedHandler.pid == target) {
        reset_hardened_handler();
    }
    if (MACH_PORT_VALID(transaction.task)) {
        (void)mach_port_deallocate(mach_task_self(), transaction.task);
    }
    if (MACH_PORT_VALID(transaction.donor_task)) {
        (void)mach_port_deallocate(mach_task_self(),
                                   transaction.donor_task);
    }
    return result == 0 && clean ? 0 : (result != 0 ? result : 19);
}

static bool write_all(int descriptor, const char *bytes, size_t size) {
    while (size != 0) {
        ssize_t amount = write(descriptor, bytes, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        bytes += amount;
        size -= (size_t)amount;
    }
    return true;
}

static void write_marker(int startup_result) {
    int descriptor = open(kMarkerPath,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return;
    }
    (void)dprintf(descriptor,
                  "codex-runtime-broker=ready pid=%d uid=%u euid=%u "
                  "socket=%s startup_injection=%d\n",
                  getpid(), getuid(), geteuid(), kSocketPath,
                  startup_result);
    (void)fsync(descriptor);
    (void)close(descriptor);
}

static int create_server_socket(void) {
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return -1;
    }
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                   kSocketPath);
    struct stat old = {0};
    if (lstat(kSocketPath, &old) == 0) {
        if (!S_ISSOCK(old.st_mode) || old.st_uid != 0) {
            (void)close(descriptor);
            errno = EPERM;
            return -1;
        }
        (void)unlink(kSocketPath);
    }
    mode_t previous_umask = umask(077);
    int bind_result = bind(descriptor, (struct sockaddr *)&address,
                           sizeof(address));
    (void)umask(previous_umask);
    if (bind_result != 0 || chmod(kSocketPath, 0600) != 0 ||
        chown(kSocketPath, 0, 0) != 0 || listen(descriptor, 4) != 0) {
        int saved_error = errno;
        (void)close(descriptor);
        (void)unlink(kSocketPath);
        errno = saved_error;
        return -1;
    }
    return descriptor;
}

static void handle_client(int client) {
    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    if (getpeereid(client, &peer_uid, &peer_gid) != 0 || peer_uid != 0) {
        static const char denied[] = "ERR unauthorized\n";
        (void)write_all(client, denied, sizeof(denied) - 1U);
        broker_log("phase=client authorized=0 uid=%u gid=%u errno=%d\n",
                   peer_uid, peer_gid, errno);
        return;
    }
    char request[PATH_MAX + 64U] = {0};
    ssize_t amount;
    do {
        amount = read(client, request, sizeof(request) - 1U);
    } while (amount < 0 && errno == EINTR);
    if (amount <= 0) {
        return;
    }
    request[amount] = '\0';
    char *newline = strchr(request, '\n');
    if (newline == NULL || newline[1] != '\0') {
        static const char malformed[] = "ERR malformed\n";
        (void)write_all(client, malformed, sizeof(malformed) - 1U);
        return;
    }
    *newline = '\0';
    if (strcmp(request, "PING") == 0) {
        static const char pong[] = "OK ready\n";
        (void)write_all(client, pong, sizeof(pong) - 1U);
        return;
    }
    static const char prefix[] = "INJECT_SPRINGBOARD ";
    if (strncmp(request, prefix, sizeof(prefix) - 1U) != 0) {
        static const char unsupported[] = "ERR unsupported\n";
        (void)write_all(client, unsupported, sizeof(unsupported) - 1U);
        return;
    }
    int result = inject_springboard(request + sizeof(prefix) - 1U);
    char response[64];
    int length = snprintf(response, sizeof(response),
                          result == 0 ? "OK injected\n" : "ERR inject %d\n",
                          result);
    if (length > 0 && (size_t)length < sizeof(response)) {
        (void)write_all(client, response, (size_t)length);
    }
}

static void *broker_main(void *unused) {
    (void)unused;
    int server = create_server_socket();
    broker_log("phase=server socket=%d errno=%d path=%s\n", server, errno,
               kSocketPath);
    if (server < 0) {
        write_marker(99);
        return NULL;
    }
    int startup_result = access(kStartupProofPath, R_OK) == 0
        ? inject_springboard(kStartupProofPath)
        : 98;
    write_marker(startup_result);
    broker_log("phase=ready pid=%d startup=%d\n", getpid(), startup_result);
    for (;;) {
        int client;
        do {
            client = accept(server, NULL, NULL);
        } while (client < 0 && errno == EINTR);
        if (client < 0) {
            broker_log("phase=accept result=failed errno=%d\n", errno);
            usleep(100U * 1000U);
            continue;
        }
        handle_client(client);
        (void)close(client);
    }
}

__attribute__((constructor)) static void codex_runtime_broker_start(void) {
    gLog = open(kLogPath,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                0600);
    if (gLog < 0) {
        gLog = STDERR_FILENO;
    }
    broker_log("phase=start pid=%d uid=%u euid=%u\n", getpid(), getuid(),
               geteuid());
    /* The controller verifies this synchronous constructor handshake before
     * it restores dyld and releases the carrier.  The broker thread replaces
     * it with its final startup result once the socket and proof transaction
     * are complete. */
    write_marker(97);
    pthread_t thread = 0;
    int result = pthread_create(&thread, NULL, broker_main, NULL);
    if (result == 0) {
        (void)pthread_detach(thread);
    }
    broker_log("phase=thread result=%d\n", result);
}
