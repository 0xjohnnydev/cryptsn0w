#import <Foundation/Foundation.h>

#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/arm/thread_status.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <ptrauth.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#import "dyld.h"

/*
 * This program is not a general remote-call utility.  customd runs it through
 * its ptrauth-matched worker lane, and it accepts exactly one transaction:
 * replace the live, launchd-owned 24A437 SpringBoard image in place with the
 * fixed get-task-allow candidate, stopped before its first instruction, while
 * carrying one secured tweak path in SpringBoard's existing environment.
 */

#ifndef POSIX_SPAWN_SETEXEC
#define POSIX_SPAWN_SETEXEC 0x0040
#endif
#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif

#define SETEXEC_CS_OPS_STATUS 0U
#define SETEXEC_CS_OPS_CDHASH 5U
#define SETEXEC_CS_VALID 0x00000001U
#define SETEXEC_CS_GET_TASK_ALLOW 0x00000004U
#define SETEXEC_PROC_PIDTBSDINFO 3
#define SETEXEC_PROC_PIDUNIQIDENTIFIERINFO 17
#define SETEXEC_PROC_STATUS_STOPPED 4U
#define SETEXEC_MAXCOMLEN 16
#define SETEXEC_CDHASH_SIZE 20U
#define SETEXEC_SHA256_SIZE CC_SHA256_DIGEST_LENGTH
#define SETEXEC_EXPECTED_CANDIDATE_SIZE UINT64_C(122400)
#define SETEXEC_USER_VA_MASK UINT64_C(0x0000ffffffffffff)
#define SETEXEC_OBSERVE_ATTEMPTS 1000U
#define SETEXEC_OBSERVE_INTERVAL_US 5000U
#define SETEXEC_REMOTE_ALLOCATION_LIMIT (64U * 1024U)
#define SETEXEC_REMOTE_THREAD_STACK_SIZE (64U * 1024U)

static const char *const kStockPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kCandidatePath =
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard";
static const char *const kDyldInsertName = "DYLD_INSERT_LIBRARIES";

static const uint8_t kExpectedSpringBoardUUID[16] = {
    0xad, 0x93, 0x7f, 0xb7, 0x26, 0x64, 0x3b, 0x8f,
    0xb1, 0xc9, 0x34, 0xc4, 0xad, 0x40, 0x92, 0xd2,
};
static const uint8_t kExpectedCandidateCDHash[SETEXEC_CDHASH_SIZE] = {
    0x9b, 0x29, 0x8e, 0x84, 0x6a, 0xb9, 0x1a, 0xaa, 0x1f, 0xba,
    0x30, 0x3f, 0x2c, 0x89, 0x2d, 0x82, 0x8e, 0x9e, 0x92, 0x1c,
};
static const uint8_t kExpectedCandidateSHA256[SETEXEC_SHA256_SIZE] = {
    0x73, 0xa2, 0xcc, 0xc2, 0x7f, 0x94, 0xec, 0xc3,
    0x52, 0x66, 0x02, 0x9d, 0xf8, 0x2d, 0x12, 0xca,
    0x7e, 0xb0, 0xf2, 0x7f, 0xf5, 0xf2, 0xe0, 0x47,
    0xbc, 0x9e, 0xa3, 0x56, 0x81, 0x87, 0x71, 0x26,
};

struct setexec_proc_bsdinfo {
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
    char pbi_comm[SETEXEC_MAXCOMLEN];
    char pbi_name[2 * SETEXEC_MAXCOMLEN];
    uint32_t pbi_nfiles;
    uint32_t pbi_pgid;
    uint32_t pbi_pjobc;
    uint32_t e_tdev;
    uint32_t e_tpgid;
    int32_t pbi_nice;
    uint64_t pbi_start_tvsec;
    uint64_t pbi_start_tvusec;
};

struct setexec_proc_unique_info {
    uint8_t uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_pid_version;
    uint64_t reserved2;
    uint64_t reserved3;
};

struct setexec_process_identity {
    pid_t pid;
    char path[PATH_MAX];
    struct setexec_proc_bsdinfo bsd;
    struct setexec_proc_unique_info unique;
    uint32_t csflags;
    uint8_t cdhash[SETEXEC_CDHASH_SIZE];
};

struct setexec_file_binding {
    int descriptor;
    struct stat status;
    char requested_path[PATH_MAX];
    char real_path[PATH_MAX];
};

struct setexec_remote_allocation {
    mach_vm_address_t address;
    mach_vm_size_t size;
};

struct setexec_remote_symbols {
    vm_address_t spawnattr_init;
    vm_address_t spawnattr_setflags;
    vm_address_t spawnattr_getflags;
    vm_address_t spawn;
    vm_address_t ns_get_environ;
    vm_address_t getenv_address;
    vm_address_t setenv_address;
    vm_address_t unsetenv_address;
};

_Static_assert(sizeof(struct setexec_proc_bsdinfo) == 136,
               "proc bsd-info ABI changed");
_Static_assert(sizeof(struct setexec_proc_unique_info) == 56,
               "proc unique-info ABI changed");

extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *out_size);
extern kern_return_t mach_vm_write(vm_map_t target,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);
extern bool codexPrewarmInjectionPrimitives(
    task_t task, vm_address_t all_image_info_address);
extern bool codexValidateInjectionPrimitives(
    task_t task, vm_address_t all_image_info_address);
extern kern_return_t createRemotePthread(
    task_t task, vm_address_t all_image_info_address,
    thread_act_t *remote_pthread_out);
extern kern_return_t arbCall(
    task_t task, thread_act_t target_thread, uint64_t *return_value,
    bool will_return, vm_address_t function, int argument_count, ...);
extern bool codexCopyExactMainHeldThread(task_t task,
                                         thread_act_t *thread_out);
extern kern_return_t codexArbCallHeldThread(
    task_t task, thread_act_t target_thread, uint64_t *return_value,
    vm_address_t function, int argument_count, ...);

static mach_vm_address_t canonical_address(uint64_t value) {
    return (mach_vm_address_t)(value & SETEXEC_USER_VA_MASK);
}

static bool parse_pid(const char *text, pid_t *pid_out) {
    if (text == NULL || pid_out == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT_MAX) {
        return false;
    }
    *pid_out = (pid_t)value;
    return true;
}

static bool copy_bsd_info(pid_t pid,
                          struct setexec_proc_bsdinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, SETEXEC_PROC_PIDTBSDINFO, 0, information,
                              (int)sizeof(*information));
    return amount == (int)sizeof(*information) &&
           information->pbi_pid == (uint32_t)pid;
}

static bool copy_unique_info(
    pid_t pid, struct setexec_proc_unique_info *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, SETEXEC_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information);
}

static bool same_process_identity(
    const struct setexec_process_identity *left,
    const struct setexec_process_identity *right) {
    return left->pid == right->pid && strcmp(left->path, right->path) == 0 &&
           left->bsd.pbi_uid == right->bsd.pbi_uid &&
           left->bsd.pbi_ppid == right->bsd.pbi_ppid &&
           left->unique.unique_id == right->unique.unique_id &&
           left->unique.parent_unique_id == right->unique.parent_unique_id &&
           left->unique.pid_version == right->unique.pid_version &&
           memcmp(left->unique.uuid, right->unique.uuid,
                  sizeof(left->unique.uuid)) == 0 &&
           left->csflags == right->csflags &&
           memcmp(left->cdhash, right->cdhash, sizeof(left->cdhash)) == 0;
}

static bool read_process_identity(pid_t pid, bool require_cdhash,
                                  struct setexec_process_identity *identity) {
    if (pid <= 1 || identity == NULL) {
        return false;
    }
    struct setexec_process_identity value = {.pid = pid};
    int path_length = proc_pidpath(pid, value.path, sizeof(value.path));
    if (path_length <= 0 || (size_t)path_length >= sizeof(value.path) ||
        !copy_bsd_info(pid, &value.bsd) ||
        !copy_unique_info(pid, &value.unique) ||
        csops(pid, SETEXEC_CS_OPS_STATUS, &value.csflags,
              sizeof(value.csflags)) != 0 ||
        (require_cdhash &&
         csops(pid, SETEXEC_CS_OPS_CDHASH, value.cdhash,
               sizeof(value.cdhash)) != 0)) {
        return false;
    }
    *identity = value;
    return true;
}

static bool read_stable_process_identity(
    pid_t pid, bool require_cdhash,
    struct setexec_process_identity *identity) {
    struct setexec_process_identity first = {0};
    struct setexec_process_identity second = {0};
    if (!read_process_identity(pid, require_cdhash, &first) ||
        !read_process_identity(pid, require_cdhash, &second) ||
        !same_process_identity(&first, &second)) {
        return false;
    }
    *identity = second;
    return true;
}

static int count_process_paths(const char *path, const char *alternate_path,
                               pid_t *only_pid_out) {
    int reported = proc_listallpids(NULL, 0);
    if (reported <= 0 || reported > 256 * 1024) {
        return -1;
    }
    int capacity = reported + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return -1;
    }
    int bytes = capacity * (int)sizeof(*pids);
    int count = proc_listallpids(pids, bytes);
    int matches = 0;
    pid_t only_pid = -1;
    for (int index = 0; index < count && index < capacity; ++index) {
        char observed[PATH_MAX] = {0};
        int length = pids[index] > 1
            ? proc_pidpath(pids[index], observed, sizeof(observed))
            : 0;
        bool matches_path = length > 0 &&
            (size_t)length < sizeof(observed) &&
            (strcmp(observed, path) == 0 ||
             (alternate_path != NULL &&
              strcmp(observed, alternate_path) == 0));
        if (matches_path) {
            ++matches;
            only_pid = pids[index];
        }
    }
    free(pids);
    if (only_pid_out != NULL) {
        *only_pid_out = matches == 1 ? only_pid : -1;
    }
    return matches;
}

static bool bind_stock_springboard(
    pid_t pid, struct setexec_process_identity *identity) {
    struct setexec_process_identity value = {0};
    pid_t unique_pid = -1;
    if (!read_stable_process_identity(pid, true, &value) ||
        strcmp(value.path, kStockPath) != 0 || value.bsd.pbi_uid != 501 ||
        value.bsd.pbi_ppid != 1 ||
        memcmp(value.unique.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) != 0 ||
        (value.csflags & SETEXEC_CS_VALID) == 0 ||
        count_process_paths(kStockPath, NULL, &unique_pid) != 1 ||
        unique_pid != pid ||
        !read_stable_process_identity(pid, true, &value) ||
        strcmp(value.path, kStockPath) != 0 || value.bsd.pbi_uid != 501 ||
        value.bsd.pbi_ppid != 1 ||
        memcmp(value.unique.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) != 0 ||
        (value.csflags & SETEXEC_CS_VALID) == 0) {
        return false;
    }
    *identity = value;
    return true;
}

static bool stock_still_exact(
    const struct setexec_process_identity *expected) {
    struct setexec_process_identity current = {0};
    return expected != NULL &&
           read_stable_process_identity(expected->pid, true, &current) &&
           same_process_identity(expected, &current);
}

static bool task_audit_matches(
    task_t task, const struct setexec_process_identity *identity) {
    audit_token_t token = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    return MACH_PORT_VALID(task) && identity != NULL &&
           task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) ==
               KERN_SUCCESS &&
           count == TASK_AUDIT_TOKEN_COUNT &&
           token.val[5] == (uint32_t)identity->pid &&
           token.val[7] == (uint32_t)identity->unique.pid_version;
}

static bool sha256_descriptor(int descriptor,
                              uint8_t digest[SETEXEC_SHA256_SIZE]) {
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
    return CC_SHA256_Final(digest, &context) == 1;
}

static bool path_has_prefix_directory(const char *path,
                                      const char *directory) {
    size_t length = strlen(directory);
    return strncmp(path, directory, length) == 0 && path[length] == '/';
}

static bool path_has_suffix(const char *path, const char *suffix) {
    size_t path_length = strlen(path);
    size_t suffix_length = strlen(suffix);
    return path_length >= suffix_length &&
           strcmp(path + path_length - suffix_length, suffix) == 0;
}

static bool bind_regular_file(const char *path, bool executable,
                              bool dylib,
                              struct setexec_file_binding *binding) {
    if (path == NULL || binding == NULL || path[0] != '/' ||
        strlen(path) >= PATH_MAX ||
        (dylib && !path_has_suffix(path, ".dylib"))) {
        return false;
    }
    memset(binding, 0, sizeof(*binding));
    binding->descriptor = -1;
    struct stat path_status = {0};
    struct stat descriptor_status = {0};
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || lstat(path, &path_status) != 0 ||
        fstat(descriptor, &descriptor_status) != 0 ||
        !S_ISREG(path_status.st_mode) ||
        !S_ISREG(descriptor_status.st_mode) ||
        path_status.st_dev != descriptor_status.st_dev ||
        path_status.st_ino != descriptor_status.st_ino ||
        descriptor_status.st_uid != 0 || descriptor_status.st_nlink != 1 ||
        (descriptor_status.st_mode & 0022) != 0 ||
        (executable && (descriptor_status.st_mode & 0111) == 0) ||
        descriptor_status.st_size <= 0 ||
        realpath(path, binding->real_path) == NULL) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return false;
    }
    if (dylib) {
        char jailbreak_root[PATH_MAX] = {0};
        if (realpath("/var/jb", jailbreak_root) == NULL ||
            !path_has_prefix_directory(binding->real_path, jailbreak_root) ||
            !path_has_suffix(binding->real_path, ".dylib")) {
            (void)close(descriptor);
            return false;
        }
    }
    binding->descriptor = descriptor;
    binding->status = descriptor_status;
    (void)strlcpy(binding->requested_path, path,
                  sizeof(binding->requested_path));
    return true;
}

static bool file_binding_still_exact(
    struct setexec_file_binding *binding) {
    if (binding == NULL || binding->descriptor < 0) {
        return false;
    }
    struct stat held = {0};
    struct stat path_status = {0};
    struct stat current = {0};
    char real_path[PATH_MAX] = {0};
    int descriptor = open(binding->requested_path,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    bool exact = descriptor >= 0 &&
                 fstat(binding->descriptor, &held) == 0 &&
                 lstat(binding->requested_path, &path_status) == 0 &&
                 fstat(descriptor, &current) == 0 &&
                 realpath(binding->requested_path, real_path) != NULL &&
                 S_ISREG(path_status.st_mode) && S_ISREG(held.st_mode) &&
                 S_ISREG(current.st_mode) && held.st_dev == current.st_dev &&
                 held.st_ino == current.st_ino &&
                 held.st_size == current.st_size &&
                 held.st_uid == current.st_uid &&
                 held.st_mode == current.st_mode && held.st_uid == 0 &&
                 held.st_nlink == 1 && current.st_nlink == 1 &&
                 (held.st_mode & 0022) == 0 &&
                 strcmp(real_path, binding->real_path) == 0 &&
                 held.st_dev == binding->status.st_dev &&
                 held.st_ino == binding->status.st_ino &&
                 held.st_size == binding->status.st_size &&
                 held.st_mode == binding->status.st_mode;
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    return exact;
}

static bool candidate_file_exact(struct setexec_file_binding *candidate) {
    uint8_t digest[SETEXEC_SHA256_SIZE] = {0};
    return bind_regular_file(kCandidatePath, true, false, candidate) &&
           (uint64_t)candidate->status.st_size ==
               SETEXEC_EXPECTED_CANDIDATE_SIZE &&
           sha256_descriptor(candidate->descriptor, digest) &&
           memcmp(digest, kExpectedCandidateSHA256, sizeof(digest)) == 0 &&
           file_binding_still_exact(candidate);
}

static bool candidate_file_still_exact(
    struct setexec_file_binding *candidate) {
    uint8_t digest[SETEXEC_SHA256_SIZE] = {0};
    return file_binding_still_exact(candidate) &&
           (uint64_t)candidate->status.st_size ==
               SETEXEC_EXPECTED_CANDIDATE_SIZE &&
           sha256_descriptor(candidate->descriptor, digest) &&
           memcmp(digest, kExpectedCandidateSHA256, sizeof(digest)) == 0;
}

static bool remote_read_exact(task_t task, mach_vm_address_t address,
                              void *destination, size_t size) {
    if (!MACH_PORT_VALID(task) || address == 0 || destination == NULL ||
        size == 0) {
        return false;
    }
    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task, address, (mach_vm_size_t)size,
        (mach_vm_address_t)(uintptr_t)destination, &copied);
    return result == KERN_SUCCESS && copied == (mach_vm_size_t)size;
}

static bool remote_allocate_write(
    task_t task, const void *bytes, size_t size,
    struct setexec_remote_allocation *allocation) {
    if (bytes == NULL || size == 0 ||
        size > SETEXEC_REMOTE_ALLOCATION_LIMIT || allocation == NULL) {
        return false;
    }
    memset(allocation, 0, sizeof(*allocation));
    kern_return_t result = mach_vm_allocate(
        task, &allocation->address, (mach_vm_size_t)size, VM_FLAGS_ANYWHERE);
    if (result == KERN_SUCCESS) {
        result = mach_vm_write(task, allocation->address,
                               (vm_offset_t)(uintptr_t)bytes,
                               (mach_msg_type_number_t)size);
    }
    if (result != KERN_SUCCESS) {
        if (allocation->address != 0) {
            (void)mach_vm_deallocate(task, allocation->address,
                                     (mach_vm_size_t)size);
        }
        memset(allocation, 0, sizeof(*allocation));
        return false;
    }
    allocation->size = (mach_vm_size_t)size;
    return true;
}

static bool remote_allocate_string(
    task_t task, const char *string,
    struct setexec_remote_allocation *allocation) {
    return remote_allocate_write(task, string, strlen(string) + 1U,
                                 allocation);
}

static void remote_deallocate(
    task_t task, struct setexec_remote_allocation *allocation) {
    if (allocation != NULL && allocation->address != 0 &&
        MACH_PORT_VALID(task)) {
        (void)mach_vm_deallocate(task, allocation->address,
                                 allocation->size);
    }
    if (allocation != NULL) {
        memset(allocation, 0, sizeof(*allocation));
    }
}

static bool remote_call(task_t task, thread_act_t thread,
                        vm_address_t function, uint64_t *result_out,
                        unsigned int argument_count,
                        const uint64_t arguments[6]) {
    uint64_t result = 0;
    kern_return_t call_result = KERN_INVALID_ARGUMENT;
    switch (argument_count) {
        case 0:
            call_result = codexArbCallHeldThread(
                task, thread, &result, function, 0);
            break;
        case 1:
            call_result = codexArbCallHeldThread(
                task, thread, &result, function, 1, arguments[0]);
            break;
        case 2:
            call_result = codexArbCallHeldThread(
                task, thread, &result, function, 2, arguments[0],
                arguments[1]);
            break;
        case 3:
            call_result = codexArbCallHeldThread(
                task, thread, &result, function, 3, arguments[0],
                arguments[1], arguments[2]);
            break;
        case 4:
            call_result = codexArbCallHeldThread(
                task, thread, &result, function, 4, arguments[0],
                arguments[1], arguments[2], arguments[3]);
            break;
        case 5:
            call_result = codexArbCallHeldThread(
                task, thread, &result, function, 5, arguments[0],
                arguments[1], arguments[2], arguments[3], arguments[4]);
            break;
        case 6:
            call_result = codexArbCallHeldThread(
                task, thread, &result, function, 6, arguments[0],
                arguments[1], arguments[2], arguments[3], arguments[4],
                arguments[5]);
            break;
        default:
            break;
    }
    if (call_result != KERN_SUCCESS) {
        return false;
    }
    if (result_out != NULL) {
        *result_out = result;
    }
    return true;
}

static vm_address_t resolve_exact_image_symbol(
    task_t task, vm_address_t all_image_info, const char *runtime_symbol,
    const char *expected_image) {
    vm_address_t remote_image_base = getRemoteImageAddress(
        task, all_image_info, expected_image);
    void *handle = dlopen(expected_image, RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
    void *local_symbol = handle != NULL ? dlsym(handle, runtime_symbol) : NULL;
    Dl_info owner = {0};
    bool owner_exact = local_symbol != NULL &&
        dladdr(local_symbol, &owner) != 0 && owner.dli_fbase != NULL &&
        owner.dli_fname != NULL && strcmp(owner.dli_fname, expected_image) == 0;
    uintptr_t local_address = owner_exact
        ? (uintptr_t)ptrauth_strip(local_symbol,
                                  ptrauth_key_function_pointer)
        : 0;
    uintptr_t local_image_base = owner_exact
        ? (uintptr_t)owner.dli_fbase
        : 0;
    uintptr_t image_offset = local_address >= local_image_base
        ? local_address - local_image_base
        : UINTPTR_MAX;
    vm_address_t exact = remote_image_base != 0 && owner_exact &&
                         image_offset < (UINT64_C(64) * 1024U * 1024U)
        ? remote_image_base + image_offset
        : 0;
    uint32_t instruction = 0;
    bool remote_readable = exact != 0 &&
        remote_read_exact(task, exact, &instruction, sizeof(instruction));
    if (!remote_readable) {
        exact = 0;
    }
    if (handle != NULL) {
        (void)dlclose(handle);
    }
    printf("springboard-setexec: symbol=%s address=0x%llx image=%s "
           "offset=0x%llx exactOwner=%d remoteReadable=%d\n",
           runtime_symbol, (unsigned long long)exact, expected_image,
           (unsigned long long)image_offset, owner_exact, remote_readable);
    return exact;
}

static bool resolve_remote_symbols(
    task_t task, vm_address_t all_image_info,
    struct setexec_remote_symbols *symbols) {
    static const char *const kernel_image =
        "/usr/lib/system/libsystem_kernel.dylib";
    static const char *const c_image =
        "/usr/lib/system/libsystem_c.dylib";
    memset(symbols, 0, sizeof(*symbols));
    symbols->spawnattr_init = resolve_exact_image_symbol(
        task, all_image_info, "posix_spawnattr_init", kernel_image);
    symbols->spawnattr_setflags = resolve_exact_image_symbol(
        task, all_image_info, "posix_spawnattr_setflags", kernel_image);
    symbols->spawnattr_getflags = resolve_exact_image_symbol(
        task, all_image_info, "posix_spawnattr_getflags", kernel_image);
    symbols->spawn = resolve_exact_image_symbol(
        task, all_image_info, "posix_spawn", kernel_image);
    symbols->ns_get_environ = resolve_exact_image_symbol(
        task, all_image_info, "_NSGetEnviron", c_image);
    symbols->getenv_address = resolve_exact_image_symbol(
        task, all_image_info, "getenv", c_image);
    symbols->setenv_address = resolve_exact_image_symbol(
        task, all_image_info, "setenv", c_image);
    symbols->unsetenv_address = resolve_exact_image_symbol(
        task, all_image_info, "unsetenv", c_image);
    return symbols->spawnattr_init != 0 &&
           symbols->spawnattr_setflags != 0 &&
           symbols->spawnattr_getflags != 0 && symbols->spawn != 0 &&
           symbols->ns_get_environ != 0 && symbols->getenv_address != 0 &&
           symbols->setenv_address != 0 && symbols->unsetenv_address != 0;
}

static bool remote_cstring_equals(task_t task, mach_vm_address_t address,
                                  const char *expected) {
    size_t size = strlen(expected) + 1U;
    if (address == 0 || size > PATH_MAX) {
        return false;
    }
    char observed[PATH_MAX] = {0};
    return remote_read_exact(task, canonical_address(address), observed,
                             size) &&
           memcmp(observed, expected, size) == 0;
}

static void release_thread_send_right(thread_act_t *thread) {
    if (thread != NULL && MACH_PORT_VALID(*thread)) {
        (void)mach_port_deallocate(mach_task_self(), *thread);
        *thread = MACH_PORT_NULL;
    }
}

static void terminate_remote_thread(task_t task, thread_act_t *thread) {
    if (!MACH_PORT_VALID(task) || thread == NULL ||
        !MACH_PORT_VALID(*thread)) {
        return;
    }
    struct arm_unified_thread_state state = {0};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    mach_vm_address_t stack = 0;
    if (thread_suspend(*thread) == KERN_SUCCESS &&
        thread_get_state(*thread, ARM_THREAD_STATE64,
                         (thread_state_t)&state.ts_64, &count) ==
            KERN_SUCCESS) {
        uint64_t sp = (uint64_t)(uintptr_t)
            __darwin_arm_thread_state64_get_sp(state.ts_64);
        if (sp > SETEXEC_REMOTE_THREAD_STACK_SIZE / 2U) {
            stack = canonical_address(
                sp - SETEXEC_REMOTE_THREAD_STACK_SIZE / 2U);
        }
    }
    (void)thread_terminate(*thread);
    release_thread_send_right(thread);
    if (stack != 0) {
        (void)mach_vm_deallocate(task, stack,
                                 SETEXEC_REMOTE_THREAD_STACK_SIZE);
    }
}

static bool candidate_path_matches(
    const struct setexec_process_identity *identity,
    const struct setexec_file_binding *candidate) {
    return strcmp(identity->path, kCandidatePath) == 0 ||
           strcmp(identity->path, candidate->real_path) == 0;
}

static bool validate_candidate_transition_once(
    const struct setexec_process_identity *stock,
    struct setexec_file_binding *candidate,
    task_t old_task, thread_act_t old_thread,
    struct setexec_process_identity *observed) {
    struct setexec_process_identity current = {0};
    if (!read_stable_process_identity(stock->pid, true, &current) ||
        !candidate_path_matches(&current, candidate) ||
        current.bsd.pbi_uid != 501 || current.bsd.pbi_ppid != 1 ||
        current.bsd.pbi_status != SETEXEC_PROC_STATUS_STOPPED ||
        current.unique.unique_id != stock->unique.unique_id ||
        current.unique.parent_unique_id != stock->unique.parent_unique_id ||
        current.unique.pid_version == stock->unique.pid_version ||
        memcmp(current.unique.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) != 0 ||
        (current.csflags &
         (SETEXEC_CS_VALID | SETEXEC_CS_GET_TASK_ALLOW)) !=
            (SETEXEC_CS_VALID | SETEXEC_CS_GET_TASK_ALLOW) ||
        memcmp(current.cdhash, kExpectedCandidateCDHash,
               sizeof(kExpectedCandidateCDHash)) != 0 ||
        !candidate_file_still_exact(candidate)) {
        return false;
    }

    task_t candidate_task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(
        mach_task_self(), current.pid, &candidate_task);
    bool task_exact = task_result == KERN_SUCCESS &&
                      candidate_task != old_task &&
                      task_audit_matches(candidate_task, &current);
    if (MACH_PORT_VALID(candidate_task)) {
        (void)mach_port_deallocate(mach_task_self(), candidate_task);
    }
    mach_port_type_t old_task_type = 0;
    mach_port_type_t old_thread_type = 0;
    bool old_task_dead = mach_port_type(mach_task_self(), old_task,
                                        &old_task_type) == KERN_SUCCESS &&
                         (old_task_type & MACH_PORT_TYPE_DEAD_NAME) != 0;
    bool old_thread_dead = mach_port_type(mach_task_self(), old_thread,
                                          &old_thread_type) == KERN_SUCCESS &&
                           (old_thread_type & MACH_PORT_TYPE_DEAD_NAME) != 0;
    if (!task_exact || !old_task_dead || !old_thread_dead) {
        return false;
    }
    *observed = current;
    return true;
}

static bool wait_for_candidate_transition(
    const struct setexec_process_identity *stock,
    struct setexec_file_binding *candidate,
    task_t old_task, thread_act_t old_thread,
    struct setexec_process_identity *observed) {
    for (unsigned int attempt = 0; attempt < SETEXEC_OBSERVE_ATTEMPTS;
         ++attempt) {
        if (validate_candidate_transition_once(
                stock, candidate, old_task, old_thread, observed)) {
            return true;
        }
        usleep(SETEXEC_OBSERVE_INTERVAL_US);
    }
    return false;
}

static bool remote_unset_environment(
    task_t task, thread_act_t thread,
    const struct setexec_remote_symbols *symbols,
    const struct setexec_remote_allocation *name) {
    uint64_t arguments[6] = {name->address};
    uint64_t result = UINT64_MAX;
    return MACH_PORT_VALID(task) && MACH_PORT_VALID(thread) &&
           remote_call(task, thread, symbols->unsetenv_address, &result, 1,
                       arguments) &&
           (int)(uint32_t)result == 0;
}

int main(int argc, char *argv[]) {
    setlinebuf(stdout);
    setlinebuf(stderr);
    @autoreleasepool {
        if (geteuid() != 0 || argc != 3) {
            fprintf(stderr,
                    "usage: customd-springboard-setexec STOCK_PID DYLIB\n");
            return 64;
        }

        pid_t target_pid = -1;
        struct setexec_process_identity stock = {0};
        struct setexec_file_binding candidate = {.descriptor = -1};
        struct setexec_file_binding dylib = {.descriptor = -1};
        if (!parse_pid(argv[1], &target_pid) ||
            !bind_stock_springboard(target_pid, &stock)) {
            fprintf(stderr,
                    "springboard-setexec: exact stock SpringBoard rejected\n");
            return 65;
        }
        if (!candidate_file_exact(&candidate)) {
            fprintf(stderr,
                    "springboard-setexec: fixed candidate artifact rejected\n");
            return 66;
        }
        if (!bind_regular_file(argv[2], false, true, &dylib)) {
            fprintf(stderr,
                    "springboard-setexec: secured /var/jb dylib rejected\n");
            (void)close(candidate.descriptor);
            return 67;
        }

        task_t task = MACH_PORT_NULL;
        kern_return_t task_result = task_for_pid(
            mach_task_self(), target_pid, &task);
        if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(task) ||
            !task_audit_matches(task, &stock) || !stock_still_exact(&stock)) {
            fprintf(stderr,
                    "springboard-setexec: exact task binding rejected "
                    "mach=%d task=0x%x\n",
                    task_result, task);
            if (MACH_PORT_VALID(task)) {
                (void)mach_port_deallocate(mach_task_self(), task);
            }
            (void)close(dylib.descriptor);
            (void)close(candidate.descriptor);
            return 68;
        }

        task_dyld_info_data_t dyld_info = {0};
        mach_msg_type_number_t dyld_count = TASK_DYLD_INFO_COUNT;
        kern_return_t dyld_result = task_info(
            task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &dyld_count);
        if (dyld_result != KERN_SUCCESS ||
            dyld_count != TASK_DYLD_INFO_COUNT ||
            dyld_info.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64 ||
            dyld_info.all_image_info_addr == 0 ||
            dyld_info.all_image_info_size <
                sizeof(struct dyld_all_image_infos) ||
            !stock_still_exact(&stock)) {
            fprintf(stderr,
                    "springboard-setexec: target DYLD info rejected mach=%d\n",
                    dyld_result);
            (void)mach_port_deallocate(mach_task_self(), task);
            (void)close(dylib.descriptor);
            (void)close(candidate.descriptor);
            return 69;
        }
        vm_address_t all_image_info =
            (vm_address_t)dyld_info.all_image_info_addr;

        if (!codexPrewarmInjectionPrimitives(task, all_image_info) ||
            !codexValidateInjectionPrimitives(task, all_image_info) ||
            !stock_still_exact(&stock) || !task_audit_matches(task, &stock)) {
            fprintf(stderr,
                    "springboard-setexec: ptrauth primitive prewarm rejected\n");
            (void)mach_port_deallocate(mach_task_self(), task);
            (void)close(dylib.descriptor);
            (void)close(candidate.descriptor);
            return 70;
        }

        struct setexec_remote_symbols symbols = {0};
        if (!resolve_remote_symbols(task, all_image_info, &symbols) ||
            !stock_still_exact(&stock)) {
            fprintf(stderr,
                    "springboard-setexec: required remote symbols rejected\n");
            (void)mach_port_deallocate(mach_task_self(), task);
            (void)close(dylib.descriptor);
            (void)close(candidate.descriptor);
            return 71;
        }

        thread_act_t remote_thread = MACH_PORT_NULL;
        kern_return_t thread_result = createRemotePthread(
            task, all_image_info, &remote_thread);
        if (thread_result != KERN_SUCCESS ||
            !MACH_PORT_VALID(remote_thread) || !stock_still_exact(&stock) ||
            !task_audit_matches(task, &stock)) {
            fprintf(stderr,
                    "springboard-setexec: remote pthread rejected mach=%d\n",
                    thread_result);
            terminate_remote_thread(task, &remote_thread);
            (void)mach_port_deallocate(mach_task_self(), task);
            (void)close(dylib.descriptor);
            (void)close(candidate.descriptor);
            return 72;
        }

        struct setexec_remote_allocation name = {0};
        struct setexec_remote_allocation dylib_path = {0};
        struct setexec_remote_allocation stock_path = {0};
        struct setexec_remote_allocation candidate_path = {0};
        struct setexec_remote_allocation attribute = {0};
        struct setexec_remote_allocation observed_flags = {0};
        struct setexec_remote_allocation returned_pid = {0};
        struct setexec_remote_allocation arguments_storage = {0};
        bool environment_set = false;
        bool old_generation_dead = false;
        int status = 73;

        uint64_t zero64 = 0;
        uint64_t argument_vector[2] = {0};
        if (!remote_allocate_string(task, kDyldInsertName, &name) ||
            !remote_allocate_string(task, dylib.requested_path,
                                    &dylib_path) ||
            !remote_allocate_string(task, kStockPath, &stock_path) ||
            !remote_allocate_string(task, kCandidatePath, &candidate_path) ||
            !remote_allocate_write(task, &zero64, sizeof(zero64),
                                   &attribute) ||
            !remote_allocate_write(task, &zero64, sizeof(zero64),
                                   &observed_flags) ||
            !remote_allocate_write(task, &zero64, sizeof(zero64),
                                   &returned_pid)) {
            fprintf(stderr,
                    "springboard-setexec: remote storage allocation failed\n");
            status = 73;
            goto finished;
        }
        argument_vector[0] = stock_path.address;
        if (!remote_allocate_write(task, argument_vector,
                                   sizeof(argument_vector),
                                   &arguments_storage)) {
            fprintf(stderr,
                    "springboard-setexec: remote argv allocation failed\n");
            status = 73;
            goto finished;
        }

        uint64_t call_arguments[6] = {name.address};
        uint64_t call_return = UINT64_MAX;
        if (!remote_call(task, remote_thread, symbols.getenv_address,
                         &call_return, 1, call_arguments) ||
            call_return != 0 || !stock_still_exact(&stock)) {
            fprintf(stderr,
                    "springboard-setexec: existing DYLD_INSERT_LIBRARIES "
                    "rejected value=0x%llx\n",
                    (unsigned long long)call_return);
            status = 74;
            goto finished;
        }

        call_arguments[0] = attribute.address;
        call_return = UINT64_MAX;
        if (!remote_call(task, remote_thread, symbols.spawnattr_init,
                         &call_return, 1, call_arguments) ||
            (int)(uint32_t)call_return != 0) {
            fprintf(stderr,
                    "springboard-setexec: spawnattr_init failed result=%d\n",
                    (int)(uint32_t)call_return);
            status = 75;
            goto finished;
        }
        call_arguments[0] = attribute.address;
        call_arguments[1] = POSIX_SPAWN_SETEXEC |
                            POSIX_SPAWN_START_SUSPENDED;
        call_return = UINT64_MAX;
        if (!remote_call(task, remote_thread, symbols.spawnattr_setflags,
                         &call_return, 2, call_arguments) ||
            (int)(uint32_t)call_return != 0) {
            fprintf(stderr,
                    "springboard-setexec: spawnattr_setflags failed "
                    "result=%d\n",
                    (int)(uint32_t)call_return);
            status = 76;
            goto finished;
        }
        call_arguments[0] = attribute.address;
        call_arguments[1] = observed_flags.address;
        call_return = UINT64_MAX;
        if (!remote_call(task, remote_thread, symbols.spawnattr_getflags,
                         &call_return, 2, call_arguments) ||
            (int)(uint32_t)call_return != 0) {
            fprintf(stderr,
                    "springboard-setexec: spawnattr_getflags failed "
                    "result=%d\n",
                    (int)(uint32_t)call_return);
            status = 77;
            goto finished;
        }
        uint16_t flags = 0;
        if (!remote_read_exact(task, observed_flags.address, &flags,
                               sizeof(flags)) ||
            flags != (POSIX_SPAWN_SETEXEC |
                      POSIX_SPAWN_START_SUSPENDED)) {
            fprintf(stderr,
                    "springboard-setexec: spawn flags verification failed "
                    "flags=0x%x\n",
                    flags);
            status = 78;
            goto finished;
        }

        call_arguments[0] = name.address;
        call_arguments[1] = dylib_path.address;
        call_arguments[2] = 1;
        call_return = UINT64_MAX;
        if (!remote_call(task, remote_thread, symbols.setenv_address,
                         &call_return, 3, call_arguments) ||
            (int)(uint32_t)call_return != 0) {
            fprintf(stderr,
                    "springboard-setexec: setenv failed result=%d\n",
                    (int)(uint32_t)call_return);
            status = 79;
            goto finished;
        }
        environment_set = true;

        call_arguments[0] = name.address;
        call_return = 0;
        if (!remote_call(task, remote_thread, symbols.getenv_address,
                         &call_return, 1, call_arguments) ||
            !remote_cstring_equals(task, call_return,
                                   dylib.requested_path)) {
            fprintf(stderr,
                    "springboard-setexec: inserted environment value "
                    "verification failed\n");
            status = 80;
            goto finished;
        }

        uint64_t environ_pointer_address = 0;
        call_return = 0;
        if (!remote_call(task, remote_thread, symbols.ns_get_environ,
                         &call_return, 0, call_arguments)) {
            fprintf(stderr,
                    "springboard-setexec: _NSGetEnviron call failed\n");
            status = 81;
            goto finished;
        }
        environ_pointer_address = canonical_address(call_return);
        uint64_t environment = 0;
        if (environ_pointer_address == 0 ||
            !remote_read_exact(task, environ_pointer_address, &environment,
                               sizeof(environment)) ||
            canonical_address(environment) == 0) {
            fprintf(stderr,
                    "springboard-setexec: existing target envp rejected\n");
            status = 81;
            goto finished;
        }
        environment = canonical_address(environment);

        /* Close every local TOCTOU gap immediately before the one-way call. */
        if (!stock_still_exact(&stock) || !task_audit_matches(task, &stock) ||
            !candidate_file_still_exact(&candidate) ||
            !file_binding_still_exact(&dylib)) {
            fprintf(stderr,
                    "springboard-setexec: final identity/file rebind failed\n");
            status = 82;
            goto finished;
        }
        call_arguments[0] = name.address;
        call_return = 0;
        if (!remote_call(task, remote_thread, symbols.getenv_address,
                         &call_return, 1, call_arguments) ||
            !remote_cstring_equals(task, call_return,
                                   dylib.requested_path)) {
            fprintf(stderr,
                    "springboard-setexec: final environment rebind failed\n");
            status = 82;
            goto finished;
        }

        call_arguments[0] = returned_pid.address;
        call_arguments[1] = candidate_path.address;
        call_arguments[2] = 0;
        call_arguments[3] = attribute.address;
        call_arguments[4] = arguments_storage.address;
        call_arguments[5] = environment;
        uint64_t spawn_return = UINT64_MAX;
        printf("springboard-setexec: committing pid=%d unique=%llu "
               "pidVersion=%d flags=0x%x dylib=%s\n",
               stock.pid, (unsigned long long)stock.unique.unique_id,
               stock.unique.pid_version, flags, dylib.requested_path);

        /*
         * SETEXEC success destroys the calling thread/task generation, so a
         * successful arbCall return means posix_spawn returned and therefore
         * the transaction failed.  A Mach error is only provisional success;
         * the process-bound checks below are the commit record.
         */
        kern_return_t spawn_mach = arbCall(
            task, remote_thread, &spawn_return, true, symbols.spawn, 6,
            call_arguments[0], call_arguments[1], call_arguments[2],
            call_arguments[3], call_arguments[4], call_arguments[5]);
        if (spawn_mach == KERN_SUCCESS) {
            bool unset = remote_unset_environment(
                task, remote_thread, &symbols, &name);
            environment_set = !unset;
            fprintf(stderr,
                    "springboard-setexec: posix_spawn returned normally "
                    "result=%d rollbackUnset=%d\n",
                    (int)(uint32_t)spawn_return, unset);
            status = 83;
            goto finished;
        }

        struct setexec_process_identity transitioned = {0};
        bool transition_exact = wait_for_candidate_transition(
            &stock, &candidate, task, remote_thread, &transitioned);
        mach_port_type_t old_task_type = 0;
        mach_port_type_t old_thread_type = 0;
        old_generation_dead =
            mach_port_type(mach_task_self(), task, &old_task_type) ==
                KERN_SUCCESS &&
            (old_task_type & MACH_PORT_TYPE_DEAD_NAME) != 0 &&
            mach_port_type(mach_task_self(), remote_thread,
                           &old_thread_type) == KERN_SUCCESS &&
            (old_thread_type & MACH_PORT_TYPE_DEAD_NAME) != 0;
        pid_t candidate_pid = -1;
        int stock_count = count_process_paths(kStockPath, NULL, NULL);
        int candidate_count = count_process_paths(
            kCandidatePath, candidate.real_path, &candidate_pid);
        if (!old_generation_dead || !transition_exact || stock_count != 0 ||
            candidate_count != 1 || candidate_pid != stock.pid) {
            fprintf(stderr,
                    "springboard-setexec: provisional Mach result did not "
                    "commit mach=%d oldDead=%d exact=%d stockCount=%d "
                    "candidateCount=%d candidatePid=%d\n",
                    spawn_mach, old_generation_dead, transition_exact,
                    stock_count,
                    candidate_count, candidate_pid);
            status = 84;
            goto finished;
        }

        environment_set = false;
        printf("springboard-setexec: committed pid=%d unique=%llu "
               "parentUnique=%llu pidVersion=%d->%d status=%u "
               "csflags=0x%08x cdhash="
               "9b298e846ab91aaa1fba303f2c892d828e9e921c mach=%d\n",
               transitioned.pid,
               (unsigned long long)transitioned.unique.unique_id,
               (unsigned long long)transitioned.unique.parent_unique_id,
               stock.unique.pid_version, transitioned.unique.pid_version,
               transitioned.bsd.pbi_status, transitioned.csflags,
               spawn_mach);
        status = 0;

finished:
        if (environment_set && stock_still_exact(&stock) &&
            task_audit_matches(task, &stock)) {
            bool unset = remote_unset_environment(
                task, remote_thread, &symbols, &name);
            fprintf(stderr,
                    "springboard-setexec: rollback environment unset=%d\n",
                    unset);
        }
        if (status != 0 && stock_still_exact(&stock)) {
            terminate_remote_thread(task, &remote_thread);
        } else if (MACH_PORT_VALID(remote_thread)) {
            (void)mach_port_deallocate(mach_task_self(), remote_thread);
            remote_thread = MACH_PORT_NULL;
        }
        /* Successful exec destroyed these mappings with the old task. */
        if (!old_generation_dead) {
            remote_deallocate(task, &arguments_storage);
            remote_deallocate(task, &returned_pid);
            remote_deallocate(task, &observed_flags);
            remote_deallocate(task, &attribute);
            remote_deallocate(task, &candidate_path);
            remote_deallocate(task, &stock_path);
            remote_deallocate(task, &dylib_path);
            remote_deallocate(task, &name);
        }
        if (MACH_PORT_VALID(task)) {
            (void)mach_port_deallocate(mach_task_self(), task);
        }
        (void)close(dylib.descriptor);
        (void)close(candidate.descriptor);
        return status;
    }
}
