#include "customd_protocol.h"

#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <mach/vm_region.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t task_port);
extern kern_return_t mach_vm_read_overwrite(
    vm_map_read_t target, mach_vm_address_t address, mach_vm_size_t size,
    mach_vm_address_t data, mach_vm_size_t *out_size);
extern kern_return_t mach_vm_protect(
    vm_map_t target, mach_vm_address_t address, mach_vm_size_t size,
    boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_write(
    vm_map_t target, mach_vm_address_t address, vm_offset_t data,
    mach_msg_type_number_t data_count);
extern kern_return_t mach_vm_region_recurse(
    vm_map_t target, mach_vm_address_t *address, mach_vm_size_t *size,
    natural_t *nesting_depth, vm_region_recurse_info_t info,
    mach_msg_type_number_t *info_count);

#define CUSTOMD_CS_OPS_STATUS 0U
#define CUSTOMD_CS_OPS_CDHASH 5U
#define CUSTOMD_CS_GET_TASK_ALLOW 0x00000004U
#define CUSTOMD_CS_HARD 0x00000100U
#define CUSTOMD_CS_KILL 0x00000200U
#define CUSTOMD_CS_DEBUGGED 0x10000000U
#define CUSTOMD_PT_CONTINUE 7
#define CUSTOMD_PT_DETACH 11
#define CUSTOMD_PT_ATTACHEXC 14
#define CUSTOMD_PT_KILL 8
#define CUSTOMD_PROC_PIDTBSDINFO 3
#define CUSTOMD_PROC_PIDUNIQIDENTIFIERINFO 17
#define CUSTOMD_PROC_STATUS_STOPPED 4U
#define CUSTOMD_MAXCOMLEN 16

#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif

#define CUSTOMD_TRACE_TIMEOUT_MSEC 5000U
#define CUSTOMD_INJECT_TIMEOUT_MSEC 15000U
#define CUSTOMD_RUN_TIMEOUT_MSEC 60000U
#define CUSTOMD_ACTIVATE_TIMEOUT_MSEC 120000U
#define CUSTOMD_ENSURE_TIMEOUT_MSEC 60000U
#define CUSTOMD_SETEXEC_TIMEOUT_MSEC 20000U
#define CUSTOMD_RUNTIME_TIMEOUT_MSEC 15000U
#define CUSTOMD_COMMAND_TIMEOUT_MSEC 5000U
#define CUSTOMD_COMMAND_OUTPUT_SIZE (16U * 1024U)
#define CUSTOMD_MAX_LOADED_MODULES 64U
#define CUSTOMD_SHA256_SIZE CC_SHA256_DIGEST_LENGTH
#define CUSTOMD_CS_VALID 0x00000001U

#ifndef CUSTOMD_EXPECTED_REGISTRAR_SHA256_HEX
#error "build must pin CUSTOMD_EXPECTED_REGISTRAR_SHA256_HEX"
#endif
#ifndef CUSTOMD_EXPECTED_WORKER_SHA256_HEX
#error "build must pin CUSTOMD_EXPECTED_WORKER_SHA256_HEX"
#endif
#ifndef CUSTOMD_EXPECTED_CANDIDATE_SHA256_HEX
#error "build must pin CUSTOMD_EXPECTED_CANDIDATE_SHA256_HEX"
#endif
#ifndef CUSTOMD_EXPECTED_CANDIDATE_INFO_SHA256_HEX
#error "build must pin CUSTOMD_EXPECTED_CANDIDATE_INFO_SHA256_HEX"
#endif
#ifndef CUSTOMD_EXPECTED_LAUNCHCTL_SHA256_HEX
#error "build must pin CUSTOMD_EXPECTED_LAUNCHCTL_SHA256_HEX"
#endif
#ifndef CUSTOMD_EXPECTED_TRACE_REEXEC_PROBE_SHA256_HEX
#error "build must pin CUSTOMD_EXPECTED_TRACE_REEXEC_PROBE_SHA256_HEX"
#endif
#ifndef CUSTOMD_EXPECTED_SETEXEC_HELPER_SHA256_HEX
#error "build must pin CUSTOMD_EXPECTED_SETEXEC_HELPER_SHA256_HEX"
#endif
#ifndef CUSTOMD_EXPECTED_CANDIDATE_SIZE
#error "build must pin CUSTOMD_EXPECTED_CANDIDATE_SIZE"
#endif
#ifndef CUSTOMD_WORKER_HAS_MACHO_INPLACE
#error "build must declare whether the pinned worker has --macho-inplace"
#endif
#ifndef CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
#error "build must declare whether the pinned worker needs the runtime patch"
#endif
#if CUSTOMD_WORKER_HAS_MACHO_INPLACE && CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
#error "native and legacy in-place worker modes are mutually exclusive"
#endif
#if !CUSTOMD_WORKER_HAS_MACHO_INPLACE && !CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
#error "worker has neither native nor admitted legacy in-place mode"
#endif

static const char *const kLockPath = "/var/jb/var/run/customd.lock";
static const char *const kManagedRoot = "/var/jb";
static const char *const kWorkerPath =
    "/var/jb/usr/libexec/codex-exec-worker";
static const char *const kLoaderPath =
    "/var/jb/usr/libexec/codex-ellekit-loader";
static const char *const kPrecursorPath =
    "/var/jb/usr/libexec/codex-springboard-live-precursor";
static const char *const kRegistrarPath =
    "/var/jb/usr/libexec/customd-candidate-registrar";
static const char *const kTraceReexecProbePath =
    "/var/jb/usr/libexec/customd-trace-me-reexec-probe";
static const char *const kSetexecHelperPath =
    "/var/jb/usr/libexec/customd-springboard-setexec";
static const char *const kLaunchctlPath = "/var/jb/usr/bin/launchctl";
static const char *const kStockSpringBoardTarget =
    "user/501/com.apple.SpringBoard";
static const char *const kCandidateTarget =
    "user/501/com.openai.codex.springboard-live-candidate";
static const char *const kCryptexdPath = "/usr/libexec/cryptexd";
static const char *const kStockSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kCandidateSpringBoardPath =
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard";
static const char *const kCandidateInfoPath =
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/Info.plist";

static const uint8_t kExpectedCryptexdUUID[16] = {
    0x26, 0x1f, 0x91, 0xf3, 0x70, 0x16, 0x35, 0xa2,
    0x9a, 0x84, 0xc8, 0x5d, 0x2b, 0x6a, 0x83, 0x4e,
};

static const uint8_t kExpectedCandidateUUID[16] = {
    0xad, 0x93, 0x7f, 0xb7, 0x26, 0x64, 0x3b, 0x8f,
    0xb1, 0xc9, 0x34, 0xc4, 0xad, 0x40, 0x92, 0xd2,
};

static const uint8_t kExpectedCandidateCdhash[20] = {
    0x9b, 0x29, 0x8e, 0x84, 0x6a, 0xb9, 0x1a, 0xaa, 0x1f, 0xba,
    0x30, 0x3f, 0x2c, 0x89, 0x2d, 0x82, 0x8e, 0x9e, 0x92, 0x1c,
};

#if CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
/* Admitted only for worker SHA-256
 * 6d346b388e844e4e8eee487ad2261f7a97ec8508e7bfaa7ed9ceab97bf697657.
 * The two writes are private COW changes in the newly spawned process.  They
 * force run_debugged_child() down its child lane without fork(), then skip
 * that lane's now-inapplicable parent handshake.  The worker's existing dyld
 * bypass and Mach-O LC_MAIN path execute unchanged in the PAC-authorized
 * process. */
static const uint8_t kExpectedLegacyWorkerUUID[16] = {
    0x7a, 0xd0, 0xe7, 0xfc, 0xfe, 0xff, 0x3e, 0x8c,
    0xa7, 0x53, 0xf3, 0xa2, 0x07, 0x3b, 0xb9, 0xa1,
};
struct legacy_instruction_patch {
    uint64_t file_offset;
    uint32_t original;
    uint32_t replacement;
};

static const struct legacy_instruction_patch kLegacyInstructionPatches[] = {
    /* fork() -> report the child return value in the current process. */
    {0x4360U, 0x940013b1U, 0x52800000U},
    /* Preserve run_child()'s return value for run_debugged_child(). */
    {0x43c4U, 0xb81a83a0U, 0xb81dc3a0U},
    /* Return through the normal stack-canary epilogue instead of _exit(). */
    {0x43c8U, 0xb85a83a0U, 0x1400013eU},
    /* Skip the parent/child handshake that no longer has a parent lane. */
    {0x4e7cU, 0xd10127a1U, 0x1400009aU},
};
#define CUSTOMD_LEGACY_PATCH_COUNT                                  \
    (sizeof(kLegacyInstructionPatches) /                            \
     sizeof(kLegacyInstructionPatches[0]))
_Static_assert(CUSTOMD_LEGACY_PATCH_COUNT == 4U,
               "legacy worker patch log assumes four instructions");
#endif

struct customd_proc_unique_info {
    uint8_t uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_pid_version;
    uint64_t reserved2;
    uint64_t reserved3;
};

struct customd_proc_bsdinfo {
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
    char pbi_comm[CUSTOMD_MAXCOMLEN];
    char pbi_name[2 * CUSTOMD_MAXCOMLEN];
    uint32_t pbi_nfiles;
    uint32_t pbi_pgid;
    uint32_t pbi_pjobc;
    uint32_t e_tdev;
    uint32_t e_tpgid;
    int32_t pbi_nice;
    uint64_t pbi_start_tvsec;
    uint64_t pbi_start_tvusec;
};

_Static_assert(sizeof(struct customd_proc_unique_info) == 56,
               "proc unique-info ABI changed");
_Static_assert(sizeof(struct customd_proc_bsdinfo) == 136,
               "proc bsd-info ABI changed");

struct process_identity {
    pid_t pid;
    char path[PATH_MAX];
    struct customd_proc_unique_info unique;
};

struct operation_result {
    int status;
    int system_error;
    uint32_t before;
    uint32_t after;
    pid_t child_pid;
    char message[CUSTOMD_MAX_MESSAGE];
};

struct managed_file_binding {
    int descriptor;
    char path[PATH_MAX];
    struct stat status;
};

struct command_result {
    int spawn_error;
    bool timed_out;
    bool standard_output_truncated;
    bool standard_error_truncated;
    int wait_status;
    int exit_code;
    char standard_output[CUSTOMD_COMMAND_OUTPUT_SIZE];
    char standard_error[CUSTOMD_COMMAND_OUTPUT_SIZE];
};

struct loaded_module {
    void *handle;
    dev_t device;
    ino_t inode;
    char path[PATH_MAX];
};

static volatile sig_atomic_t gStopping = 0;
static int gServerDescriptor = -1;
static int gLockDescriptor = -1;
static pid_t gHostParent = -1;
static struct customd_proc_unique_info gHostParentIdentity;
static struct loaded_module gLoadedModules[CUSTOMD_MAX_LOADED_MODULES];
static size_t gLoadedModuleCount = 0;

static void result_message(struct operation_result *result,
                           const char *format, ...);

static void log_message(const char *format, ...) {
    struct timespec now = {0};
    (void)clock_gettime(CLOCK_REALTIME, &now);
    dprintf(STDERR_FILENO, "customd[%d] %lld.%03lld ", getpid(),
            (long long)now.tv_sec, (long long)(now.tv_nsec / 1000000));
    va_list arguments;
    va_start(arguments, format);
    vdprintf(STDERR_FILENO, format, arguments);
    va_end(arguments);
    dprintf(STDERR_FILENO, "\n");
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static bool read_all(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = read(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return true;
}

static bool write_all(int descriptor, const void *buffer, size_t size) {
    const uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = write(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return true;
}

static void set_close_on_exec(int descriptor) {
    int flags = fcntl(descriptor, F_GETFD);
    if (flags >= 0) {
        (void)fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC);
    }
}

static bool copy_unique_info(
    pid_t pid, struct customd_proc_unique_info *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CUSTOMD_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information);
}

static bool copy_bsd_info(pid_t pid,
                          struct customd_proc_bsdinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CUSTOMD_PROC_PIDTBSDINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information) &&
           information->pbi_pid == (uint32_t)pid;
}

static bool unique_info_equal(
    const struct customd_proc_unique_info *left,
    const struct customd_proc_unique_info *right) {
    return left->unique_id == right->unique_id &&
           left->pid_version == right->pid_version &&
           left->parent_unique_id == right->parent_unique_id &&
           memcmp(left->uuid, right->uuid, sizeof(left->uuid)) == 0;
}

static bool bind_process(pid_t pid, struct process_identity *identity) {
    if (pid <= 1 || pid == getpid()) {
        errno = EPERM;
        return false;
    }
    struct process_identity first = {.pid = pid};
    struct process_identity second = {.pid = pid};
    int first_length = proc_pidpath(pid, first.path, sizeof(first.path));
    bool first_valid = first_length > 0 &&
                       (size_t)first_length < sizeof(first.path) &&
                       copy_unique_info(pid, &first.unique);
    int second_length = proc_pidpath(pid, second.path, sizeof(second.path));
    bool second_valid = second_length > 0 &&
                        (size_t)second_length < sizeof(second.path) &&
                        copy_unique_info(pid, &second.unique);
    if (!first_valid || !second_valid ||
        strcmp(first.path, second.path) != 0 ||
        !unique_info_equal(&first.unique, &second.unique)) {
        errno = ESRCH;
        return false;
    }
    *identity = second;
    return true;
}

static bool process_still_exact(const struct process_identity *expected) {
    struct process_identity current = {0};
    return bind_process(expected->pid, &current) &&
           strcmp(current.path, expected->path) == 0 &&
           unique_info_equal(&current.unique, &expected->unique);
}

static bool task_port_matches_identity(
    task_t task, const struct process_identity *identity) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    return MACH_PORT_VALID(task) && identity != NULL &&
           task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) ==
               KERN_SUCCESS &&
           count == TASK_AUDIT_TOKEN_COUNT &&
           (pid_t)token.val[5] == identity->pid &&
           (int32_t)token.val[7] == identity->unique.pid_version;
}

static bool host_parent_alive(void) {
    if (gHostParent <= 1 || getppid() != gHostParent) {
        return false;
    }
    struct customd_proc_unique_info current = {0};
    return copy_unique_info(gHostParent, &current) &&
           unique_info_equal(&current, &gHostParentIdentity);
}

static bool path_is_descendant(const char *path, const char *root) {
    size_t root_length = strlen(root);
    return root_length > 1 && strncmp(path, root, root_length) == 0 &&
           path[root_length] == '/';
}

static bool secure_parent_directories(const char *resolved,
                                      const char *managed_root) {
    char parent[PATH_MAX] = {0};
    if (snprintf(parent, sizeof(parent), "%s", resolved) < 0) {
        return false;
    }
    char *slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return false;
    }
    *slash = '\0';
    bool immediate_parent = true;
    for (;;) {
        struct stat status = {0};
        if (lstat(parent, &status) != 0 || !S_ISDIR(status.st_mode) ||
            S_ISLNK(status.st_mode) ||
            (immediate_parent ? status.st_uid != 0
                              : (status.st_uid != 0 && status.st_uid != 501)) ||
            (status.st_mode & 0022) != 0) {
            return false;
        }
        if (strcmp(parent, managed_root) == 0) {
            return true;
        }
        if (!path_is_descendant(parent, managed_root)) {
            return false;
        }
        slash = strrchr(parent, '/');
        if (slash == NULL || slash == parent) {
            return false;
        }
        *slash = '\0';
        immediate_parent = false;
    }
}

static bool has_suffix(const char *value, const char *suffix) {
    size_t value_length = strlen(value);
    size_t suffix_length = strlen(suffix);
    return value_length >= suffix_length &&
           strcmp(value + value_length - suffix_length, suffix) == 0;
}

static bool validate_managed_file(const char *requested, bool dylib,
                                  struct managed_file_binding *binding) {
    memset(binding, 0, sizeof(*binding));
    binding->descriptor = -1;
    char managed_root[PATH_MAX] = {0};
    char resolved[PATH_MAX] = {0};
    if (requested == NULL || requested[0] != '/' ||
        realpath(kManagedRoot, managed_root) == NULL ||
        realpath(requested, resolved) == NULL ||
        !path_is_descendant(resolved, managed_root) ||
        (dylib && !has_suffix(resolved, ".dylib")) ||
        !secure_parent_directories(resolved, managed_root)) {
        errno = EACCES;
        return false;
    }

    int descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat descriptor_status = {0};
    struct stat path_status = {0};
    bool valid = descriptor >= 0 && fstat(descriptor, &descriptor_status) == 0 &&
                 lstat(resolved, &path_status) == 0 &&
                 S_ISREG(descriptor_status.st_mode) &&
                 descriptor_status.st_uid == 0 &&
                 descriptor_status.st_nlink == 1 &&
                 (descriptor_status.st_mode & 0022) == 0 &&
                 descriptor_status.st_size > 0 &&
                 descriptor_status.st_dev == path_status.st_dev &&
                 descriptor_status.st_ino == path_status.st_ino;
    int saved_error = valid ? 0 : (errno != 0 ? errno : EACCES);
    if (valid) {
        binding->descriptor = descriptor;
        binding->status = descriptor_status;
        (void)snprintf(binding->path, sizeof(binding->path), "%s", resolved);
    } else if (descriptor >= 0) {
        close(descriptor);
    }
    errno = saved_error;
    return valid;
}

static bool managed_file_still_exact(
    const struct managed_file_binding *binding) {
    struct stat descriptor_status = {0};
    struct stat path_status = {0};
    return binding->descriptor >= 0 &&
           fstat(binding->descriptor, &descriptor_status) == 0 &&
           lstat(binding->path, &path_status) == 0 &&
           descriptor_status.st_dev == binding->status.st_dev &&
           descriptor_status.st_ino == binding->status.st_ino &&
           descriptor_status.st_mode == binding->status.st_mode &&
           descriptor_status.st_uid == binding->status.st_uid &&
           descriptor_status.st_gid == binding->status.st_gid &&
           descriptor_status.st_nlink == binding->status.st_nlink &&
           descriptor_status.st_size == binding->status.st_size &&
           descriptor_status.st_mtimespec.tv_sec ==
               binding->status.st_mtimespec.tv_sec &&
           descriptor_status.st_mtimespec.tv_nsec ==
               binding->status.st_mtimespec.tv_nsec &&
           descriptor_status.st_ctimespec.tv_sec ==
               binding->status.st_ctimespec.tv_sec &&
           descriptor_status.st_ctimespec.tv_nsec ==
               binding->status.st_ctimespec.tv_nsec &&
           descriptor_status.st_dev == path_status.st_dev &&
           descriptor_status.st_ino == path_status.st_ino;
}

static void close_managed_file(struct managed_file_binding *binding) {
    if (binding->descriptor >= 0) {
        close(binding->descriptor);
        binding->descriptor = -1;
    }
}

static bool sha256_descriptor(int descriptor,
                              uint8_t digest[CUSTOMD_SHA256_SIZE]) {
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

static bool file_sha256_exact(
    const char *path, const uint8_t expected[CUSTOMD_SHA256_SIZE],
    bool executable, uint64_t expected_size) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat before = {0};
    struct stat after = {0};
    struct stat path_status = {0};
    uint8_t digest[CUSTOMD_SHA256_SIZE] = {0};
    bool valid = descriptor >= 0 && fstat(descriptor, &before) == 0 &&
                 lstat(path, &path_status) == 0 &&
                 S_ISREG(before.st_mode) && before.st_uid == 0 &&
                 before.st_nlink == 1 && (before.st_mode & 0022) == 0 &&
                 (!executable || (before.st_mode & 0111) != 0) &&
                 before.st_size > 0 &&
                 (expected_size == 0 ||
                  (uint64_t)before.st_size == expected_size) &&
                 before.st_dev == path_status.st_dev &&
                 before.st_ino == path_status.st_ino &&
                 sha256_descriptor(descriptor, digest) &&
                 memcmp(digest, expected, CUSTOMD_SHA256_SIZE) == 0 &&
                 fstat(descriptor, &after) == 0 &&
                 before.st_dev == after.st_dev &&
                 before.st_ino == after.st_ino &&
                 before.st_size == after.st_size &&
                 before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
                 before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
                 before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
                 before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
    if (descriptor >= 0) {
        close(descriptor);
    }
    return valid;
}

static int hex_nibble(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    return -1;
}

static bool file_sha256_hex_exact(const char *path, const char *expected_hex,
                                  bool executable,
                                  uint64_t expected_size) {
    uint8_t expected[CUSTOMD_SHA256_SIZE] = {0};
    if (expected_hex == NULL ||
        strlen(expected_hex) != CUSTOMD_SHA256_SIZE * 2U) {
        return false;
    }
    for (size_t index = 0; index < CUSTOMD_SHA256_SIZE; ++index) {
        int high = hex_nibble(expected_hex[index * 2U]);
        int low = hex_nibble(expected_hex[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        expected[index] = (uint8_t)((high << 4) | low);
    }
    return file_sha256_exact(path, expected, executable, expected_size);
}

static bool fixed_candidate_artifacts_exact(void) {
    return file_sha256_hex_exact(
               kLaunchctlPath, CUSTOMD_EXPECTED_LAUNCHCTL_SHA256_HEX,
               true, 0) &&
           file_sha256_hex_exact(
               kWorkerPath, CUSTOMD_EXPECTED_WORKER_SHA256_HEX, true, 0) &&
           file_sha256_hex_exact(
               kRegistrarPath, CUSTOMD_EXPECTED_REGISTRAR_SHA256_HEX, true,
               0) &&
           file_sha256_hex_exact(
               kCandidateSpringBoardPath,
               CUSTOMD_EXPECTED_CANDIDATE_SHA256_HEX, true,
               CUSTOMD_EXPECTED_CANDIDATE_SIZE) &&
           file_sha256_hex_exact(
               kCandidateInfoPath,
               CUSTOMD_EXPECTED_CANDIDATE_INFO_SHA256_HEX, false, 0);
}

static bool fixed_trace_reexec_artifacts_exact(void) {
    return file_sha256_hex_exact(
               kWorkerPath, CUSTOMD_EXPECTED_WORKER_SHA256_HEX, true, 0) &&
           file_sha256_hex_exact(
               kTraceReexecProbePath,
               CUSTOMD_EXPECTED_TRACE_REEXEC_PROBE_SHA256_HEX, true, 0) &&
           file_sha256_hex_exact(
               kCandidateSpringBoardPath,
               CUSTOMD_EXPECTED_CANDIDATE_SHA256_HEX, true,
               CUSTOMD_EXPECTED_CANDIDATE_SIZE);
}

static bool fixed_setexec_artifacts_exact(void) {
    return file_sha256_hex_exact(
               kWorkerPath, CUSTOMD_EXPECTED_WORKER_SHA256_HEX, true, 0) &&
           file_sha256_hex_exact(
               kSetexecHelperPath,
               CUSTOMD_EXPECTED_SETEXEC_HELPER_SHA256_HEX, true, 0) &&
           file_sha256_hex_exact(
               kCandidateSpringBoardPath,
               CUSTOMD_EXPECTED_CANDIDATE_SHA256_HEX, true,
               CUSTOMD_EXPECTED_CANDIDATE_SIZE) &&
           file_sha256_hex_exact(
               kCandidateInfoPath,
               CUSTOMD_EXPECTED_CANDIDATE_INFO_SHA256_HEX, false, 0) &&
           file_sha256_hex_exact(
               kLaunchctlPath, CUSTOMD_EXPECTED_LAUNCHCTL_SHA256_HEX,
               true, 0);
}

static bool loaded_module_matches(
    const struct loaded_module *module,
    const struct managed_file_binding *binding) {
    return module->handle != NULL &&
           module->device == binding->status.st_dev &&
           module->inode == binding->status.st_ino &&
           strcmp(module->path, binding->path) == 0;
}

/* customd is deliberately launched through codex-exec-worker.  The worker
 * leaves its verified dyld mmap/fcntl admission hooks installed in this
 * process, so dlopen here is the persistent post-boot, no-new-TSS carrier.
 * Handles are retained for the daemon lifetime; removal takes effect after a
 * daemon/device restart, matching the accepted no-unload policy. */
static struct operation_result load_module(const char *requested_path) {
    struct operation_result result = {
        .status = CUSTOMD_STATUS_CHILD_FAILED,
        .child_pid = -1,
    };
    struct managed_file_binding binding = {.descriptor = -1};
    if (!validate_managed_file(requested_path, true, &binding)) {
        result.status = CUSTOMD_STATUS_BAD_PATH;
        result.system_error = errno;
        result_message(&result, "refusing insecure module path");
        return result;
    }

    for (size_t index = 0; index < gLoadedModuleCount; ++index) {
        if (!loaded_module_matches(&gLoadedModules[index], &binding)) {
            continue;
        }
        result.status = CUSTOMD_STATUS_OK;
        result_message(&result, "module already resident index=%zu path=%s",
                       index, binding.path);
        close_managed_file(&binding);
        return result;
    }
    if (gLoadedModuleCount >= CUSTOMD_MAX_LOADED_MODULES) {
        result.status = CUSTOMD_STATUS_INTERNAL;
        result.system_error = ENOSPC;
        result_message(&result, "resident module table is full");
        close_managed_file(&binding);
        return result;
    }

    (void)dlerror();
    void *handle = dlopen(binding.path,
                          RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
    const char *load_error = handle == NULL ? dlerror() : NULL;
    bool file_exact = managed_file_still_exact(&binding);
    if (handle == NULL) {
        result.status = CUSTOMD_STATUS_CHILD_FAILED;
        result.system_error = errno != 0 ? errno : ENOEXEC;
        result_message(&result, "dlopen failed path=%s error=%s",
                       binding.path,
                       load_error != NULL ? load_error : "unknown");
    } else if (!file_exact) {
        /* RTLD_NODELETE makes rollback impossible after constructors run.
         * Report the identity failure loudly and retain the handle; the
         * secure root-owned path policy makes this reachable only if a root
         * actor races the request. */
        result.status = CUSTOMD_STATUS_IDENTITY_CHANGED;
        result.system_error = ESTALE;
        result_message(&result,
                       "module identity changed during load; restart required");
    } else {
        struct loaded_module *module =
            &gLoadedModules[gLoadedModuleCount];
        module->handle = handle;
        module->device = binding.status.st_dev;
        module->inode = binding.status.st_ino;
        (void)snprintf(module->path, sizeof(module->path), "%s",
                       binding.path);
        size_t index = gLoadedModuleCount++;
        result.status = CUSTOMD_STATUS_OK;
        result_message(&result, "module resident index=%zu path=%s", index,
                       binding.path);
    }
    close_managed_file(&binding);
    return result;
}

static bool springboard_path_matches(const char *observed,
                                     const char *candidate_real_path) {
    return strcmp(observed, kStockSpringBoardPath) == 0 ||
           (candidate_real_path != NULL && candidate_real_path[0] != '\0' &&
            strcmp(observed, candidate_real_path) == 0);
}

static bool bind_unique_springboard(struct process_identity *identity) {
    int reported = proc_listallpids(NULL, 0);
    if (identity == NULL || reported <= 0 || reported > 256 * 1024) {
        errno = ESRCH;
        return false;
    }
    int capacity = reported + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return false;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    char candidate_real_path[PATH_MAX] = {0};
    (void)realpath(kCandidateSpringBoardPath, candidate_real_path);
    struct process_identity found = {0};
    unsigned int matches = 0;
    for (int index = 0; index < count && index < capacity; ++index) {
        if (pids[index] <= 1) {
            continue;
        }
        struct process_identity current = {0};
        if (!bind_process(pids[index], &current) ||
            !springboard_path_matches(current.path, candidate_real_path)) {
            continue;
        }
        found = current;
        ++matches;
        if (matches > 1U) {
            break;
        }
    }
    free(pids);
    if (matches != 1U) {
        errno = matches == 0 ? ESRCH : EBUSY;
        return false;
    }
    *identity = found;
    return true;
}

static bool bind_exact_stock_springboard(
    struct process_identity *identity,
    struct customd_proc_bsdinfo *bsd_out, uint32_t *flags_out) {
    int reported = proc_listallpids(NULL, 0);
    if (identity == NULL || bsd_out == NULL || flags_out == NULL ||
        reported <= 0 || reported > 256 * 1024) {
        errno = ESRCH;
        return false;
    }
    int capacity = reported + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return false;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    char candidate_real_path[PATH_MAX] = {0};
    (void)realpath(kCandidateSpringBoardPath, candidate_real_path);
    struct process_identity found = {0};
    struct customd_proc_bsdinfo found_bsd = {0};
    uint32_t found_flags = 0;
    unsigned int stock_matches = 0;
    unsigned int candidate_matches = 0;
    for (int index = 0; index < count && index < capacity; ++index) {
        struct process_identity current = {0};
        if (pids[index] <= 1 || !bind_process(pids[index], &current)) {
            continue;
        }
        if (candidate_real_path[0] != '\0' &&
            strcmp(current.path, candidate_real_path) == 0) {
            ++candidate_matches;
            continue;
        }
        if (strcmp(current.path, kStockSpringBoardPath) != 0) {
            continue;
        }
        struct customd_proc_bsdinfo first_bsd = {0};
        struct customd_proc_bsdinfo second_bsd = {0};
        uint32_t flags = 0;
        bool exact = copy_bsd_info(current.pid, &first_bsd) &&
            first_bsd.pbi_uid == 501 && first_bsd.pbi_ppid == 1 &&
            first_bsd.pbi_status != CUSTOMD_PROC_STATUS_STOPPED &&
            memcmp(current.unique.uuid, kExpectedCandidateUUID,
                   sizeof(kExpectedCandidateUUID)) == 0 &&
            csops(current.pid, CUSTOMD_CS_OPS_STATUS, &flags,
                  sizeof(flags)) == 0 &&
            (flags & CUSTOMD_CS_VALID) != 0 &&
            copy_bsd_info(current.pid, &second_bsd) &&
            memcmp(&first_bsd, &second_bsd, sizeof(first_bsd)) == 0 &&
            process_still_exact(&current);
        if (!exact) {
            continue;
        }
        found = current;
        found_bsd = second_bsd;
        found_flags = flags;
        ++stock_matches;
    }
    free(pids);
    if (stock_matches != 1U || candidate_matches != 0U) {
        errno = stock_matches == 0U ? ESRCH : EBUSY;
        return false;
    }
    *identity = found;
    *bsd_out = found_bsd;
    *flags_out = found_flags;
    return true;
}

static bool bind_cross_exec_candidate(
    const struct process_identity *stock,
    struct process_identity *candidate_out,
    struct customd_proc_bsdinfo *bsd_out, uint32_t *flags_out) {
    if (stock == NULL || candidate_out == NULL || bsd_out == NULL ||
        flags_out == NULL) {
        errno = EINVAL;
        return false;
    }
    struct process_identity candidate = {0};
    struct customd_proc_bsdinfo bsd = {0};
    uint32_t flags = 0;
    uint8_t cdhash[sizeof(kExpectedCandidateCdhash)] = {0};
    char candidate_real_path[PATH_MAX] = {0};
    bool exact = realpath(kCandidateSpringBoardPath,
                          candidate_real_path) != NULL &&
        bind_process(stock->pid, &candidate) &&
        strcmp(candidate.path, candidate_real_path) == 0 &&
        candidate.unique.unique_id == stock->unique.unique_id &&
        candidate.unique.parent_unique_id == stock->unique.parent_unique_id &&
        candidate.unique.pid_version != stock->unique.pid_version &&
        memcmp(candidate.unique.uuid, kExpectedCandidateUUID,
               sizeof(kExpectedCandidateUUID)) == 0 &&
        copy_bsd_info(candidate.pid, &bsd) && bsd.pbi_uid == 501 &&
        bsd.pbi_ppid == 1 &&
        bsd.pbi_status == CUSTOMD_PROC_STATUS_STOPPED &&
        csops(candidate.pid, CUSTOMD_CS_OPS_STATUS, &flags,
              sizeof(flags)) == 0 &&
        (flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW) &&
        csops(candidate.pid, CUSTOMD_CS_OPS_CDHASH, cdhash,
              sizeof(cdhash)) == 0 &&
        memcmp(cdhash, kExpectedCandidateCdhash, sizeof(cdhash)) == 0 &&
        process_still_exact(&candidate) && fixed_setexec_artifacts_exact();
    if (!exact) {
        errno = EAUTH;
        return false;
    }
    *candidate_out = candidate;
    *bsd_out = bsd;
    *flags_out = flags;
    return true;
}

/* The strict binder above is the success gate.  Keep a separate rollback
 * binder so a same-process SETEXEC that reached the fixed candidate but did
 * not yet acquire its expected stop/CS state cannot strand SpringBoard.  The
 * preserved unique-id tuple makes this deliberately narrower than a path-only
 * kill and rejects an unrelated process that merely reused the BSD PID. */
static bool bind_recoverable_cross_exec_candidate(
    const struct process_identity *stock,
    struct process_identity *candidate_out) {
    if (stock == NULL || candidate_out == NULL) {
        errno = EINVAL;
        return false;
    }
    struct process_identity candidate = {0};
    struct customd_proc_bsdinfo bsd = {0};
    uint8_t cdhash[sizeof(kExpectedCandidateCdhash)] = {0};
    char candidate_real_path[PATH_MAX] = {0};
    bool exact = realpath(kCandidateSpringBoardPath,
                          candidate_real_path) != NULL &&
        bind_process(stock->pid, &candidate) &&
        strcmp(candidate.path, candidate_real_path) == 0 &&
        candidate.unique.unique_id == stock->unique.unique_id &&
        candidate.unique.parent_unique_id == stock->unique.parent_unique_id &&
        candidate.unique.pid_version != stock->unique.pid_version &&
        memcmp(candidate.unique.uuid, kExpectedCandidateUUID,
               sizeof(kExpectedCandidateUUID)) == 0 &&
        copy_bsd_info(candidate.pid, &bsd) && bsd.pbi_uid == 501 &&
        bsd.pbi_ppid == 1 &&
        csops(candidate.pid, CUSTOMD_CS_OPS_CDHASH, cdhash,
              sizeof(cdhash)) == 0 &&
        memcmp(cdhash, kExpectedCandidateCdhash, sizeof(cdhash)) == 0 &&
        process_still_exact(&candidate) && fixed_setexec_artifacts_exact();
    if (!exact) {
        errno = EAUTH;
        return false;
    }
    *candidate_out = candidate;
    return true;
}

static int detach_target(pid_t pid, int *error_out) {
    int result = -1;
    *error_out = 0;
    for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
        errno = 0;
        result = ptrace(CUSTOMD_PT_DETACH, pid, NULL, 0);
        *error_out = result == 0 ? 0 : errno;
        if (result == 0 || (*error_out != EBUSY && *error_out != EINTR)) {
            break;
        }
        usleep(10000U);
    }
    return result;
}

static void result_message(struct operation_result *result,
                           const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(result->message, sizeof(result->message), format,
                    arguments);
    va_end(arguments);
}

static struct operation_result jit_process(pid_t target) {
    struct operation_result result = {
        .status = CUSTOMD_STATUS_JIT_DENIED,
        .child_pid = -1,
    };
    struct process_identity identity = {0};
    if (!bind_process(target, &identity)) {
        result.status = CUSTOMD_STATUS_NO_PROCESS;
        result.system_error = errno;
        result_message(&result, "cannot bind pid %d", target);
        return result;
    }
    if (csops(target, CUSTOMD_CS_OPS_STATUS, &result.before,
              sizeof(result.before)) != 0) {
        result.status = CUSTOMD_STATUS_NO_PROCESS;
        result.system_error = errno;
        result_message(&result, "csops before failed for pid %d", target);
        return result;
    }
    if ((result.before & CUSTOMD_CS_DEBUGGED) != 0 &&
        (result.before & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0) {
        result.status = CUSTOMD_STATUS_OK;
        result.after = result.before;
        result_message(&result, "pid %d already JIT-enabled path=%s", target,
                       identity.path);
        return result;
    }

    errno = 0;
    if (ptrace(CUSTOMD_PT_ATTACHEXC, target, NULL, 0) != 0) {
        result.system_error = errno;
        result_message(&result, "PT_ATTACHEXC denied for pid %d path=%s",
                       target, identity.path);
        return result;
    }

    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_TRACE_TIMEOUT_MSEC;
    int wait_status = 0;
    bool stopped = false;
    int wait_error = 0;
    while (!gStopping && host_parent_alive() &&
           monotonic_milliseconds() < deadline) {
        errno = 0;
        pid_t waited = waitpid(target, &wait_status, WUNTRACED | WNOHANG);
        if (waited == target) {
            stopped = WIFSTOPPED(wait_status);
            if (!stopped) {
                wait_error = EPROTO;
            }
            break;
        }
        if (waited < 0 && errno != EINTR) {
            wait_error = errno;
            break;
        }
        usleep(10000U);
    }
    if (!stopped && wait_error == 0) {
        wait_error = ETIMEDOUT;
    }

    bool exact_while_stopped = stopped && process_still_exact(&identity);
    uint32_t attached_flags = 0;
    bool flags_read = exact_while_stopped &&
                      csops(target, CUSTOMD_CS_OPS_STATUS, &attached_flags,
                            sizeof(attached_flags)) == 0;
    int detach_error = 0;
    int detach_result = detach_target(target, &detach_error);
    int continue_result = -1;
    int continue_error = 0;
    if (exact_while_stopped && detach_result == 0) {
        errno = 0;
        continue_result = kill(target, SIGCONT);
        continue_error = continue_result == 0 ? 0 : errno;
    }

    bool exact_after = exact_while_stopped && detach_result == 0 &&
                       continue_result == 0 && process_still_exact(&identity);
    bool after_read = exact_after &&
                      csops(target, CUSTOMD_CS_OPS_STATUS, &result.after,
                            sizeof(result.after)) == 0;
    bool softened = flags_read && after_read &&
                    (attached_flags & CUSTOMD_CS_DEBUGGED) != 0 &&
                    (attached_flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) ==
                        0 &&
                    (result.after & CUSTOMD_CS_DEBUGGED) != 0 &&
                    (result.after & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0;
    if (softened) {
        result.status = CUSTOMD_STATUS_OK;
        result_message(&result,
                       "pid %d JIT-enabled path=%s stop=%d", target,
                       identity.path, WSTOPSIG(wait_status));
    } else {
        result.status = !exact_while_stopped || !exact_after
                            ? CUSTOMD_STATUS_IDENTITY_CHANGED
                            : (wait_error == ETIMEDOUT
                                   ? CUSTOMD_STATUS_TIMEOUT
                                   : CUSTOMD_STATUS_JIT_DENIED);
        result.system_error = wait_error != 0
                                  ? wait_error
                                  : (detach_error != 0
                                         ? detach_error
                                         : (continue_error != 0
                                                ? continue_error
                                                : EACCES));
        result_message(
            &result,
            "pid %d not JIT-enabled stopped=%d exact=%d detach=%d "
            "continue=%d attached=0x%08x path=%s",
            target, stopped, exact_after, detach_result, continue_result,
            attached_flags, identity.path);
    }
    return result;
}

static int wait_for_spawned_process(pid_t child, unsigned int timeout_msec,
                                    int *system_error) {
    uint64_t deadline = monotonic_milliseconds() + timeout_msec;
    int status = 0;
    while (!gStopping && host_parent_alive() &&
           monotonic_milliseconds() < deadline) {
        errno = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            *system_error = EPROTO;
            return -1;
        }
        if (waited < 0 && errno != EINTR) {
            *system_error = errno;
            return -1;
        }
        usleep(10000U);
    }

    bool timed_out = !gStopping && host_parent_alive();
    (void)kill(-child, SIGTERM);
    uint64_t term_deadline = monotonic_milliseconds() + 500U;
    while (monotonic_milliseconds() < term_deadline) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            *system_error = timed_out ? ETIMEDOUT : ECANCELED;
            return -1;
        }
        usleep(10000U);
    }
    (void)kill(-child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    *system_error = timed_out ? ETIMEDOUT : ECANCELED;
    return -1;
}

static int spawn_and_wait(const char *executable, char *const arguments[],
                          unsigned int timeout_msec, pid_t *child_out,
                          int *system_error) {
    posix_spawnattr_t attributes;
    int attribute_result = posix_spawnattr_init(&attributes);
    if (attribute_result != 0) {
        *system_error = attribute_result;
        return -1;
    }
    short flags = POSIX_SPAWN_SETPGROUP;
    int flags_result = posix_spawnattr_setflags(&attributes, flags);
    int group_result = posix_spawnattr_setpgroup(&attributes, 0);
    pid_t child = -1;
    int spawn_result = flags_result == 0 && group_result == 0
                           ? posix_spawn(&child, executable, NULL, &attributes,
                                         arguments, environ)
                           : (flags_result != 0 ? flags_result : group_result);
    posix_spawnattr_destroy(&attributes);
    if (spawn_result != 0) {
        *system_error = spawn_result;
        return -1;
    }
    *child_out = child;
    return wait_for_spawned_process(child, timeout_msec, system_error);
}

static void set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL);
    if (flags >= 0) {
        (void)fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
    }
}

static void drain_descriptor(int descriptor, char *output, size_t capacity,
                             size_t *used, bool *truncated) {
    uint8_t discard[1024];
    for (;;) {
        void *destination = discard;
        size_t available = sizeof(discard);
        if (*used + 1U < capacity) {
            destination = output + *used;
            available = capacity - *used - 1U;
        }
        ssize_t amount = read(descriptor, destination, available);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        if (amount <= 0) {
            break;
        }
        if (destination == discard) {
            *truncated = true;
        } else {
            *used += (size_t)amount;
            output[*used] = '\0';
        }
    }
}

static struct command_result run_captured_command(
    const char *executable, char *const arguments[],
    unsigned int timeout_msec) {
    struct command_result result = {.exit_code = -1, .wait_status = -1};
    int output_pipe[2] = {-1, -1};
    int error_pipe[2] = {-1, -1};
    if (pipe(output_pipe) != 0 || pipe(error_pipe) != 0) {
        result.spawn_error = errno;
        goto finished;
    }
    for (size_t index = 0; index < 2U; ++index) {
        set_close_on_exec(output_pipe[index]);
        set_close_on_exec(error_pipe[index]);
    }
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int actions_result = posix_spawn_file_actions_init(&actions);
    int attributes_result = posix_spawnattr_init(&attributes);
    if (actions_result != 0 || attributes_result != 0) {
        result.spawn_error = actions_result != 0 ? actions_result
                                                 : attributes_result;
        if (actions_result == 0) {
            (void)posix_spawn_file_actions_destroy(&actions);
        }
        if (attributes_result == 0) {
            (void)posix_spawnattr_destroy(&attributes);
        }
        goto finished;
    }
    int setup_result = posix_spawn_file_actions_adddup2(
        &actions, output_pipe[1], STDOUT_FILENO);
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, error_pipe[1], STDERR_FILENO);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addclose(&actions,
                                                         output_pipe[0]);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addclose(&actions,
                                                         error_pipe[0]);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setflags(&attributes,
                                                POSIX_SPAWN_SETPGROUP);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    pid_t child = -1;
    result.spawn_error = setup_result == 0
                             ? posix_spawn(&child, executable, &actions,
                                           &attributes, arguments, environ)
                             : setup_result;
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)posix_spawnattr_destroy(&attributes);
    close(output_pipe[1]);
    output_pipe[1] = -1;
    close(error_pipe[1]);
    error_pipe[1] = -1;
    if (result.spawn_error != 0 || child <= 1) {
        goto finished;
    }

    set_nonblocking(output_pipe[0]);
    set_nonblocking(error_pipe[0]);
    size_t output_used = 0;
    size_t error_used = 0;
    uint64_t deadline = monotonic_milliseconds() + timeout_msec;
    bool reaped = false;
    while (!reaped && !gStopping && host_parent_alive() &&
           monotonic_milliseconds() < deadline) {
        drain_descriptor(output_pipe[0], result.standard_output,
                         sizeof(result.standard_output), &output_used,
                         &result.standard_output_truncated);
        drain_descriptor(error_pipe[0], result.standard_error,
                         sizeof(result.standard_error), &error_used,
                         &result.standard_error_truncated);
        pid_t waited = waitpid(child, &result.wait_status, WNOHANG);
        if (waited == child) {
            reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            result.spawn_error = errno;
            break;
        }
        usleep(10000U);
    }
    if (!reaped) {
        result.timed_out = result.spawn_error == 0 && !gStopping &&
                           host_parent_alive();
        (void)kill(-child, SIGKILL);
        while (waitpid(child, &result.wait_status, 0) < 0 && errno == EINTR) {
        }
    }
    drain_descriptor(output_pipe[0], result.standard_output,
                     sizeof(result.standard_output), &output_used,
                     &result.standard_output_truncated);
    drain_descriptor(error_pipe[0], result.standard_error,
                     sizeof(result.standard_error), &error_used,
                     &result.standard_error_truncated);
    if (WIFEXITED(result.wait_status)) {
        result.exit_code = WEXITSTATUS(result.wait_status);
    }

finished:
    for (size_t index = 0; index < 2U; ++index) {
        if (output_pipe[index] >= 0) {
            close(output_pipe[index]);
        }
        if (error_pipe[index] >= 0) {
            close(error_pipe[index]);
        }
    }
    return result;
}

static bool command_completed(const struct command_result *result) {
    return result != NULL && result->spawn_error == 0 &&
           !result->timed_out && WIFEXITED(result->wait_status);
}

static bool command_succeeded(const struct command_result *result) {
    return command_completed(result) && result->exit_code == 0;
}

static bool output_has_exact_line(const char *output, const char *expected) {
    size_t expected_length = strlen(expected);
    const char *cursor = output;
    while (cursor != NULL && *cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        if (line_end == NULL) {
            line_end = cursor + strlen(cursor);
        }
        const char *begin = cursor;
        while (begin < line_end &&
               (*begin == ' ' || *begin == '\t' || *begin == '\r')) {
            ++begin;
        }
        const char *end = line_end;
        while (end > begin &&
               (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
            --end;
        }
        if ((size_t)(end - begin) == expected_length &&
            memcmp(begin, expected, expected_length) == 0) {
            return true;
        }
        cursor = *line_end == '\0' ? line_end : line_end + 1;
    }
    return false;
}

static struct command_result print_stock_springboard_service(void) {
    char *arguments[] = {(char *)kLaunchctlPath, (char *)"print",
                         (char *)kStockSpringBoardTarget, NULL};
    return run_captured_command(kLaunchctlPath, arguments,
                                CUSTOMD_COMMAND_TIMEOUT_MSEC);
}

static bool stock_service_print_is_exact(const struct command_result *result,
                                         pid_t pid) {
    if (!command_succeeded(result) || result->standard_output_truncated ||
        result->standard_error_truncated ||
        result->standard_error[0] != '\0' || pid <= 1) {
        return false;
    }
    char header[160] = {0};
    char program[PATH_MAX + 16U] = {0};
    char pid_line[64] = {0};
    int header_length = snprintf(header, sizeof(header), "%s = {",
                                 kStockSpringBoardTarget);
    int program_length = snprintf(program, sizeof(program), "program = %s",
                                  kStockSpringBoardPath);
    int pid_length = snprintf(pid_line, sizeof(pid_line), "pid = %d", pid);
    return header_length > 0 && (size_t)header_length < sizeof(header) &&
        program_length > 0 && (size_t)program_length < sizeof(program) &&
        pid_length > 0 && (size_t)pid_length < sizeof(pid_line) &&
        output_has_exact_line(result->standard_output, header) &&
        output_has_exact_line(result->standard_output,
                              "type = LaunchDaemon") &&
        output_has_exact_line(result->standard_output, "state = running") &&
        output_has_exact_line(result->standard_output,
                              "bundle id = com.apple.springboard") &&
        output_has_exact_line(result->standard_output, program) &&
        output_has_exact_line(result->standard_output, "domain = user/501") &&
        output_has_exact_line(result->standard_output, "username = mobile") &&
        output_has_exact_line(result->standard_output, pid_line) &&
        output_has_exact_line(result->standard_output,
                              "proxy started suspended = 0") &&
        output_has_exact_line(result->standard_output, "uses proxy = 0") &&
        output_has_exact_line(result->standard_output,
                              "spawn type = app (1)") &&
        strstr(result->standard_output, "needs proxy") == NULL;
}

static bool candidate_print_is_exact_dormant(const char *output) {
    char header[160] = {0};
    char program[PATH_MAX + 16U] = {0};
    int header_length = snprintf(header, sizeof(header), "%s = {",
                                 kCandidateTarget);
    int program_length = snprintf(program, sizeof(program), "program = %s",
                                  kCandidateSpringBoardPath);
    return header_length > 0 && (size_t)header_length < sizeof(header) &&
           program_length > 0 &&
           (size_t)program_length < sizeof(program) &&
           output_has_exact_line(output, header) &&
           output_has_exact_line(output, program) &&
           output_has_exact_line(output, "active count = 0") &&
           output_has_exact_line(output, "type = Submitted") &&
           output_has_exact_line(output, "state = not running") &&
           output_has_exact_line(output,
                                 "bundle id = com.apple.springboard") &&
           output_has_exact_line(output, "username = mobile") &&
           output_has_exact_line(output, "spawn type = app (1)") &&
           output_has_exact_line(output, "runs = 0") &&
           strstr(output, "proxy started suspended") == NULL &&
           strstr(output, "uses proxy") == NULL &&
           strstr(output, "needs proxy") == NULL;
}

static struct command_result print_candidate_service(void) {
    char *arguments[] = {(char *)kLaunchctlPath, (char *)"print",
                         (char *)kCandidateTarget, NULL};
    return run_captured_command(kLaunchctlPath, arguments,
                                CUSTOMD_COMMAND_TIMEOUT_MSEC);
}

static bool candidate_process_absent(void) {
    int reported = proc_listallpids(NULL, 0);
    if (reported <= 0 || reported > 256 * 1024) {
        return false;
    }
    int capacity = reported + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return false;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    char resolved_candidate[PATH_MAX] = {0};
    (void)realpath(kCandidateSpringBoardPath, resolved_candidate);
    bool absent = count >= 0;
    for (int index = 0; absent && index < count && index < capacity; ++index) {
        if (pids[index] <= 1) {
            continue;
        }
        char path[PATH_MAX] = {0};
        int length = proc_pidpath(pids[index], path, sizeof(path));
        if (length > 0 && (size_t)length < sizeof(path) &&
            (strcmp(path, kCandidateSpringBoardPath) == 0 ||
             (resolved_candidate[0] != '\0' &&
              strcmp(path, resolved_candidate) == 0))) {
            absent = false;
        }
    }
    free(pids);
    return absent;
}

static bool exact_dormant_candidate_present(
    const struct command_result *print_result) {
    return command_succeeded(print_result) &&
           !print_result->standard_output_truncated &&
           !print_result->standard_error_truncated &&
           print_result->standard_error[0] == '\0' &&
           candidate_print_is_exact_dormant(print_result->standard_output) &&
           candidate_process_absent();
}

static bool find_unique_exact_cryptexd(struct process_identity *identity) {
    int reported = proc_listallpids(NULL, 0);
    if (identity == NULL || reported <= 0 || reported > 256 * 1024) {
        errno = ESRCH;
        return false;
    }
    int capacity = reported + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return false;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    unsigned int matches = 0;
    struct process_identity found = {0};
    for (int index = 0; index < count && index < capacity; ++index) {
        struct process_identity current = {0};
        uint32_t flags = 0;
        if (pids[index] <= 1 || !bind_process(pids[index], &current) ||
            strcmp(current.path, kCryptexdPath) != 0 ||
            memcmp(current.unique.uuid, kExpectedCryptexdUUID,
                   sizeof(kExpectedCryptexdUUID)) != 0 ||
            csops(current.pid, CUSTOMD_CS_OPS_STATUS, &flags,
                  sizeof(flags)) != 0 ||
            (flags & CUSTOMD_CS_VALID) == 0) {
            continue;
        }
        found = current;
        if (++matches > 1U) {
            break;
        }
    }
    free(pids);
    if (matches != 1U) {
        errno = matches == 0 ? ESRCH : EBUSY;
        return false;
    }
    *identity = found;
    return true;
}

static bool wait_for_owned_stop(pid_t child, int *wait_status) {
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_TRACE_TIMEOUT_MSEC;
    while (monotonic_milliseconds() < deadline) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WUNTRACED | WNOHANG);
        if (waited == child) {
            if (wait_status != NULL) {
                *wait_status = status;
            }
            return WIFSTOPPED(status) &&
                   (WSTOPSIG(status) == 0 || WSTOPSIG(status) == SIGSTOP);
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static __attribute__((unused)) bool wait_for_owned_traced_stop(
    pid_t child, int *wait_status) {
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_TRACE_TIMEOUT_MSEC;
    while (monotonic_milliseconds() < deadline) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WUNTRACED | WNOHANG);
        if (waited == child) {
            if (wait_status != NULL) {
                *wait_status = status;
            }
            return WIFSTOPPED(status);
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool wait_for_owned_signal_stop(pid_t child, int signal_number,
                                       int *wait_status) {
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_TRACE_TIMEOUT_MSEC;
    while (monotonic_milliseconds() < deadline) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WUNTRACED | WNOHANG);
        if (waited == child) {
            if (wait_status != NULL) {
                *wait_status = status;
            }
            return WIFSTOPPED(status) && WSTOPSIG(status) == signal_number;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool wait_for_owned_terminal(pid_t child, int *wait_status) {
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_TRACE_TIMEOUT_MSEC;
    while (monotonic_milliseconds() < deadline) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (wait_status != NULL) {
                *wait_status = status;
            }
            return WIFEXITED(status) || WIFSIGNALED(status);
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static void terminate_owned_process_group(pid_t child) {
    if (child <= 1) {
        return;
    }
    bool group_exact = getpgid(child) == child;
    (void)kill(group_exact ? -child : child, SIGKILL);
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_TRACE_TIMEOUT_MSEC;
    while (monotonic_milliseconds() < deadline) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                return;
            }
            if (WIFSTOPPED(status)) {
                (void)ptrace(CUSTOMD_PT_KILL, child, NULL, 0);
                (void)kill(group_exact ? -child : child, SIGKILL);
            }
        } else if (waited < 0 && errno != EINTR) {
            return;
        }
        usleep(10000U);
    }
}

#if CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
static kern_return_t read_remote_exact(task_t task,
                                       mach_vm_address_t address,
                                       void *buffer,
                                       mach_vm_size_t size) {
    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task, address, size, (mach_vm_address_t)(uintptr_t)buffer, &copied);
    return result == KERN_SUCCESS && copied == size ? KERN_SUCCESS
                                                    : KERN_FAILURE;
}

static bool translate_executable_file_offset(
    const uint8_t *commands, uint32_t command_size, uint32_t command_count,
    uint64_t slide, uint64_t file_offset, mach_vm_address_t *address_out) {
    if (commands == NULL || address_out == NULL ||
        command_size < sizeof(struct load_command)) {
        return false;
    }
    size_t cursor = 0;
    for (uint32_t index = 0; index < command_count; ++index) {
        if (cursor > command_size - sizeof(struct load_command)) {
            return false;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + cursor);
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > command_size - cursor) {
            return false;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            bool range_valid = segment->filesize >= sizeof(uint32_t) &&
                               file_offset >= segment->fileoff &&
                               file_offset - segment->fileoff <=
                                   segment->filesize - sizeof(uint32_t);
            if (range_valid &&
                (segment->initprot & (VM_PROT_READ | VM_PROT_EXECUTE)) ==
                    (VM_PROT_READ | VM_PROT_EXECUTE) &&
                (segment->initprot & VM_PROT_WRITE) == 0 &&
                slide <= UINT64_MAX - segment->vmaddr &&
                slide + segment->vmaddr <=
                    UINT64_MAX - (file_offset - segment->fileoff)) {
                *address_out = (mach_vm_address_t)(
                    slide + segment->vmaddr +
                    (file_offset - segment->fileoff));
                return true;
            }
        }
        cursor += command->cmdsize;
    }
    return false;
}

static bool inspect_legacy_worker_image(
    task_t task, mach_vm_address_t *image_out,
    mach_vm_address_t patch_addresses[CUSTOMD_LEGACY_PATCH_COUNT]) {
    mach_vm_address_t address = 0;
    mach_vm_address_t matched_image = 0;
    mach_vm_address_t matched_addresses[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    unsigned int matches = 0;
    natural_t depth = 0;
    unsigned int regions = 0;
    while (address < 0x0000ffffffffffffULL && regions++ < 262144U) {
        mach_vm_size_t region_size = 0;
        vm_region_submap_info_data_64_t region = {0};
        mach_msg_type_number_t region_count =
            VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t region_result = mach_vm_region_recurse(
            task, &address, &region_size, &depth,
            (vm_region_recurse_info_t)&region, &region_count);
        if (region_result != KERN_SUCCESS || region_size == 0) {
            break;
        }
        if (region.is_submap) {
            ++depth;
            continue;
        }

        if ((region.protection & VM_PROT_READ) != 0 &&
            region_size >= sizeof(struct mach_header_64)) {
            struct mach_header_64 header = {0};
            bool header_valid =
                read_remote_exact(task, address, &header,
                                  sizeof(header)) == KERN_SUCCESS &&
                header.magic == MH_MAGIC_64 &&
                header.cputype == CPU_TYPE_ARM64 &&
                header.filetype == MH_EXECUTE && header.ncmds > 0 &&
                header.ncmds <= 4096U &&
                header.sizeofcmds >= sizeof(struct load_command) &&
                header.sizeofcmds <= 4U * 1024U * 1024U;
            uint8_t *commands =
                header_valid ? malloc(header.sizeofcmds) : NULL;
            if (commands != NULL &&
                read_remote_exact(task, address + sizeof(header), commands,
                                  header.sizeofcmds) == KERN_SUCCESS) {
                bool commands_valid = true;
                bool uuid_matches = false;
                unsigned int uuid_count = 0;
                bool have_slide = false;
                uint64_t slide = 0;
                size_t cursor = 0;
                for (uint32_t index = 0; index < header.ncmds; ++index) {
                    if (cursor >
                        header.sizeofcmds - sizeof(struct load_command)) {
                        commands_valid = false;
                        break;
                    }
                    const struct load_command *command =
                        (const struct load_command *)(commands + cursor);
                    if (command->cmdsize < sizeof(*command) ||
                        command->cmdsize > header.sizeofcmds - cursor) {
                        commands_valid = false;
                        break;
                    }
                    if (command->cmd == LC_UUID &&
                        command->cmdsize >= sizeof(struct uuid_command)) {
                        const struct uuid_command *uuid =
                            (const struct uuid_command *)command;
                        ++uuid_count;
                        uuid_matches =
                            memcmp(uuid->uuid, kExpectedLegacyWorkerUUID,
                                   sizeof(kExpectedLegacyWorkerUUID)) == 0;
                    } else if (
                        command->cmd == LC_SEGMENT_64 &&
                        command->cmdsize >=
                            sizeof(struct segment_command_64)) {
                        const struct segment_command_64 *segment =
                            (const struct segment_command_64 *)command;
                        if (segment->fileoff == 0 &&
                            segment->filesize >=
                                sizeof(struct mach_header_64) &&
                            address >= segment->vmaddr) {
                            if (have_slide &&
                                slide != address - segment->vmaddr) {
                                commands_valid = false;
                                break;
                            }
                            slide = address - segment->vmaddr;
                            have_slide = true;
                        }
                    }
                    cursor += command->cmdsize;
                }

                mach_vm_address_t candidate_addresses
                    [CUSTOMD_LEGACY_PATCH_COUNT] = {0};
                bool candidate = commands_valid && uuid_count == 1U &&
                                 uuid_matches && have_slide;
                for (size_t index = 0;
                     candidate && index < CUSTOMD_LEGACY_PATCH_COUNT;
                     ++index) {
                    candidate = translate_executable_file_offset(
                        commands, header.sizeofcmds, header.ncmds, slide,
                        kLegacyInstructionPatches[index].file_offset,
                        &candidate_addresses[index]);
                }
                if (candidate) {
                    matched_image = address;
                    memcpy(matched_addresses, candidate_addresses,
                           sizeof(matched_addresses));
                    ++matches;
                }
            }
            free(commands);
        }
        if (address > UINT64_MAX - region_size) {
            break;
        }
        address += region_size;
    }
    if (matches != 1U || matched_image == 0) {
        return false;
    }
    *image_out = matched_image;
    memcpy(patch_addresses, matched_addresses, sizeof(matched_addresses));
    return true;
}

#if 0
static bool patch_legacy_worker_in_place_obsolete(
    const struct process_identity *worker, int *system_error) {
    if (worker == NULL || system_error == NULL ||
        memcmp(worker->unique.uuid, kExpectedLegacyWorkerUUID,
               sizeof(kExpectedLegacyWorkerUUID)) != 0 ||
        !process_still_exact(worker)) {
        if (system_error != NULL) {
            *system_error = EAUTH;
        }
        return false;
    }

    task_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(
        mach_task_self(), worker->pid, &task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(task) ||
        !process_still_exact(worker)) {
        if (MACH_PORT_VALID(task)) {
            (void)mach_port_deallocate(mach_task_self(), task);
        }
        *system_error = EPERM;
        return false;
    }

    mach_vm_address_t image = 0;
    mach_vm_address_t fork_address = 0;
    mach_vm_address_t handshake_address = 0;
    bool inspected = inspect_legacy_worker_image(
        task, worker->path, &image, &fork_address, &handshake_address);
    mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    mach_vm_address_t fork_page =
        page_size != 0 ? fork_address & ~(page_size - 1U) : 0;
    mach_vm_address_t handshake_page =
        page_size != 0 ? handshake_address & ~(page_size - 1U) : 0;
    uint32_t fork_original = 0;
    uint32_t handshake_original = 0;
    bool pristine = inspected && page_size != 0 &&
                    (page_size & (page_size - 1U)) == 0 &&
                    fork_page == handshake_page &&
                    read_remote_exact(task, fork_address, &fork_original,
                                      sizeof(fork_original)) == KERN_SUCCESS &&
                    read_remote_exact(task, handshake_address,
                                      &handshake_original,
                                      sizeof(handshake_original)) ==
                        KERN_SUCCESS &&
                    fork_original == kLegacyForkOriginal &&
                    handshake_original == kLegacyHandshakeOriginal;
    if (!pristine || !process_still_exact(worker)) {
        log_message("legacy worker rejected pid=%d image=0x%llx "
                    "fork=0x%llx word=0x%08x handshake=0x%llx "
                    "word=0x%08x",
                    worker->pid, (unsigned long long)image,
                    (unsigned long long)fork_address, fork_original,
                    (unsigned long long)handshake_address,
                    handshake_original);
        (void)mach_port_deallocate(mach_task_self(), task);
        *system_error = EPROTO;
        return false;
    }

    kern_return_t protect_result = mach_vm_protect(
        task, fork_page, page_size, false,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    kern_return_t fork_write_result = protect_result == KERN_SUCCESS
        ? mach_vm_write(task, fork_address,
                        (vm_offset_t)(uintptr_t)&kLegacyForkReplacement,
                        (mach_msg_type_number_t)
                            sizeof(kLegacyForkReplacement))
        : protect_result;
    kern_return_t handshake_write_result =
        fork_write_result == KERN_SUCCESS
            ? mach_vm_write(
                  task, handshake_address,
                  (vm_offset_t)(uintptr_t)&kLegacyHandshakeReplacement,
                  (mach_msg_type_number_t)
                      sizeof(kLegacyHandshakeReplacement))
            : fork_write_result;
    vm_machine_attribute_val_t cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t flush_result = handshake_write_result == KERN_SUCCESS
        ? vm_machine_attribute(task, (vm_address_t)fork_page,
                               (vm_size_t)page_size, MATTR_CACHE,
                               &cache_value)
        : handshake_write_result;
    kern_return_t execute_result = protect_result == KERN_SUCCESS
        ? mach_vm_protect(task, fork_page, page_size, false,
                          VM_PROT_READ | VM_PROT_EXECUTE)
        : protect_result;
    uint32_t fork_readback = 0;
    uint32_t handshake_readback = 0;
    bool patched = flush_result == KERN_SUCCESS &&
                   execute_result == KERN_SUCCESS &&
                   read_remote_exact(task, fork_address, &fork_readback,
                                     sizeof(fork_readback)) == KERN_SUCCESS &&
                   read_remote_exact(task, handshake_address,
                                     &handshake_readback,
                                     sizeof(handshake_readback)) ==
                       KERN_SUCCESS &&
                   fork_readback == kLegacyForkReplacement &&
                   handshake_readback == kLegacyHandshakeReplacement &&
                   process_still_exact(worker);

    bool rollback_ok = true;
    if (!patched && protect_result == KERN_SUCCESS) {
        kern_return_t rollback_protect = mach_vm_protect(
            task, fork_page, page_size, false,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        kern_return_t rollback_fork = rollback_protect == KERN_SUCCESS
            ? mach_vm_write(task, fork_address,
                            (vm_offset_t)(uintptr_t)&kLegacyForkOriginal,
                            (mach_msg_type_number_t)
                                sizeof(kLegacyForkOriginal))
            : rollback_protect;
        kern_return_t rollback_handshake = rollback_fork == KERN_SUCCESS
            ? mach_vm_write(
                  task, handshake_address,
                  (vm_offset_t)(uintptr_t)&kLegacyHandshakeOriginal,
                  (mach_msg_type_number_t)
                      sizeof(kLegacyHandshakeOriginal))
            : rollback_fork;
        cache_value = MATTR_VAL_CACHE_FLUSH;
        kern_return_t rollback_flush = rollback_handshake == KERN_SUCCESS
            ? vm_machine_attribute(task, (vm_address_t)fork_page,
                                   (vm_size_t)page_size, MATTR_CACHE,
                                   &cache_value)
            : rollback_handshake;
        kern_return_t rollback_execute = rollback_protect == KERN_SUCCESS
            ? mach_vm_protect(task, fork_page, page_size, false,
                              VM_PROT_READ | VM_PROT_EXECUTE)
            : rollback_protect;
        rollback_ok = rollback_fork == KERN_SUCCESS &&
                      rollback_handshake == KERN_SUCCESS &&
                      rollback_flush == KERN_SUCCESS &&
                      rollback_execute == KERN_SUCCESS;
    }
    log_message("legacy worker COW patch pid=%d image=0x%llx page=0x%llx "
                "protect=%d forkWrite=%d handshakeWrite=%d flush=%d "
                "execute=%d forkRead=0x%08x handshakeRead=0x%08x "
                "patched=%d rollback=%d",
                worker->pid, (unsigned long long)image,
                (unsigned long long)fork_page, protect_result,
                fork_write_result, handshake_write_result, flush_result,
                execute_result, fork_readback, handshake_readback, patched,
                rollback_ok);
    (void)mach_port_deallocate(mach_task_self(), task);
    *system_error = patched ? 0 : EIO;
    return patched;
}
#endif

static bool remote_range_has_protection(
    task_t task, mach_vm_address_t expected_address,
    mach_vm_size_t expected_size, vm_prot_t required,
    vm_prot_t forbidden) {
    mach_vm_address_t address = expected_address;
    natural_t depth = 0;
    for (unsigned int attempt = 0; attempt < 64U; ++attempt) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t region = {0};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            task, &address, &size, &depth,
            (vm_region_recurse_info_t)&region, &count);
        if (result != KERN_SUCCESS || size == 0) {
            return false;
        }
        if (region.is_submap) {
            ++depth;
            address = expected_address;
            continue;
        }
        return address <= expected_address &&
               expected_address - address <= size &&
               expected_size <= size - (expected_address - address) &&
               (region.protection & required) == required &&
               (region.protection & forbidden) == 0;
    }
    return false;
}

#if 0
static bool patch_legacy_worker_in_place_single_phase(
    const struct process_identity *worker, int *system_error) {
    if (worker == NULL || system_error == NULL ||
        memcmp(worker->unique.uuid, kExpectedLegacyWorkerUUID,
               sizeof(kExpectedLegacyWorkerUUID)) != 0 ||
        !process_still_exact(worker)) {
        if (system_error != NULL) {
            *system_error = EAUTH;
        }
        return false;
    }

    task_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(
        mach_task_self(), worker->pid, &task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(task) ||
        !process_still_exact(worker)) {
        if (MACH_PORT_VALID(task)) {
            (void)mach_port_deallocate(mach_task_self(), task);
        }
        *system_error = EPERM;
        return false;
    }

    audit_token_t token = {0};
    mach_msg_type_number_t token_count = TASK_AUDIT_TOKEN_COUNT;
    bool task_bound = task_info(
                          task, TASK_AUDIT_TOKEN, (task_info_t)&token,
                          &token_count) == KERN_SUCCESS &&
                      token_count == TASK_AUDIT_TOKEN_COUNT &&
                      (pid_t)token.val[5] == worker->pid &&
                      (int32_t)token.val[7] ==
                          worker->unique.pid_version;
    mach_vm_address_t image = 0;
    mach_vm_address_t addresses[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool inspected = task_bound &&
                     inspect_legacy_worker_image(task, &image, addresses);
    mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    mach_vm_address_t patch_page =
        page_size != 0 ? addresses[0] & ~(page_size - 1U) : 0;
    uint32_t originals[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool pristine = inspected && page_size != 0 &&
                    (page_size & (page_size - 1U)) == 0 && patch_page != 0 &&
                    remote_range_has_protection(
                        task, patch_page, page_size,
                        VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_WRITE);
    for (size_t index = 0;
         pristine && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
        pristine = (addresses[index] & ~(page_size - 1U)) == patch_page &&
                   read_remote_exact(task, addresses[index],
                                     &originals[index],
                                     sizeof(originals[index])) ==
                       KERN_SUCCESS &&
                   originals[index] ==
                       kLegacyInstructionPatches[index].original;
    }
    if (!pristine || !process_still_exact(worker)) {
        log_message("legacy worker rejected pid=%d image=0x%llx "
                    "taskBound=%d inspected=%d page=0x%llx "
                    "words=%08x,%08x,%08x,%08x",
                    worker->pid, (unsigned long long)image, task_bound,
                    inspected, (unsigned long long)patch_page,
                    originals[0], originals[1], originals[2], originals[3]);
        (void)mach_port_deallocate(mach_task_self(), task);
        *system_error = EPROTO;
        return false;
    }

    kern_return_t protect_result = mach_vm_protect(
        task, patch_page, page_size, false,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    kern_return_t write_result = protect_result;
    size_t writes_completed = 0;
    if (protect_result == KERN_SUCCESS) {
        write_result = KERN_SUCCESS;
        for (size_t index = 0; index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
            write_result = mach_vm_write(
                task, addresses[index],
                (vm_offset_t)(uintptr_t)
                    &kLegacyInstructionPatches[index].replacement,
                (mach_msg_type_number_t)sizeof(uint32_t));
            if (write_result != KERN_SUCCESS) {
                break;
            }
            ++writes_completed;
        }
    }
    vm_machine_attribute_val_t cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t flush_result =
        write_result == KERN_SUCCESS &&
                writes_completed == CUSTOMD_LEGACY_PATCH_COUNT
            ? vm_machine_attribute(task, (vm_address_t)patch_page,
                                   (vm_size_t)page_size, MATTR_CACHE,
                                   &cache_value)
            : write_result;
    kern_return_t execute_result = protect_result == KERN_SUCCESS
        ? mach_vm_protect(task, patch_page, page_size, false,
                          VM_PROT_READ | VM_PROT_EXECUTE)
        : protect_result;
    uint32_t readbacks[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool patched = flush_result == KERN_SUCCESS &&
                   execute_result == KERN_SUCCESS &&
                   remote_range_has_protection(
                       task, patch_page, page_size,
                       VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_WRITE);
    for (size_t index = 0;
         patched && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
        patched = read_remote_exact(task, addresses[index],
                                    &readbacks[index],
                                    sizeof(readbacks[index])) ==
                      KERN_SUCCESS &&
                  readbacks[index] ==
                      kLegacyInstructionPatches[index].replacement;
    }
    patched = patched && process_still_exact(worker);

    bool rollback_ok = true;
    if (!patched && protect_result == KERN_SUCCESS) {
        kern_return_t rollback_protect = mach_vm_protect(
            task, patch_page, page_size, false,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        kern_return_t rollback_write = rollback_protect;
        size_t rollback_writes = 0;
        if (rollback_protect == KERN_SUCCESS) {
            rollback_write = KERN_SUCCESS;
            for (size_t index = 0; index < CUSTOMD_LEGACY_PATCH_COUNT;
                 ++index) {
                rollback_write = mach_vm_write(
                    task, addresses[index],
                    (vm_offset_t)(uintptr_t)
                        &kLegacyInstructionPatches[index].original,
                    (mach_msg_type_number_t)sizeof(uint32_t));
                if (rollback_write != KERN_SUCCESS) {
                    break;
                }
                ++rollback_writes;
            }
        }
        cache_value = MATTR_VAL_CACHE_FLUSH;
        kern_return_t rollback_flush =
            rollback_write == KERN_SUCCESS &&
                    rollback_writes == CUSTOMD_LEGACY_PATCH_COUNT
                ? vm_machine_attribute(task, (vm_address_t)patch_page,
                                       (vm_size_t)page_size, MATTR_CACHE,
                                       &cache_value)
                : rollback_write;
        kern_return_t rollback_execute = rollback_protect == KERN_SUCCESS
            ? mach_vm_protect(task, patch_page, page_size, false,
                              VM_PROT_READ | VM_PROT_EXECUTE)
            : rollback_protect;
        rollback_ok = rollback_write == KERN_SUCCESS &&
                      rollback_writes == CUSTOMD_LEGACY_PATCH_COUNT &&
                      rollback_flush == KERN_SUCCESS &&
                      rollback_execute == KERN_SUCCESS &&
                      remote_range_has_protection(
                          task, patch_page, page_size,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_WRITE);
        for (size_t index = 0;
             rollback_ok && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
            uint32_t restored = 0;
            rollback_ok =
                read_remote_exact(task, addresses[index], &restored,
                                  sizeof(restored)) == KERN_SUCCESS &&
                restored == kLegacyInstructionPatches[index].original;
        }
    }
    log_message("legacy worker COW patch pid=%d image=0x%llx page=0x%llx "
                "protect=%d write=%d writes=%zu flush=%d execute=%d "
                "read=%08x,%08x,%08x,%08x patched=%d rollback=%d",
                worker->pid, (unsigned long long)image,
                (unsigned long long)patch_page, protect_result, write_result,
                writes_completed, flush_result, execute_result,
                readbacks[0], readbacks[1], readbacks[2], readbacks[3],
                patched, rollback_ok);
    (void)mach_port_deallocate(mach_task_self(), task);
    *system_error = patched ? 0 : EIO;
    return patched;
}
#endif

#if 0
struct legacy_patch_state_two_phase_nx {
    task_t task;
    mach_vm_address_t image;
    mach_vm_address_t page;
    mach_vm_size_t page_size;
    mach_vm_address_t addresses[CUSTOMD_LEGACY_PATCH_COUNT];
    bool staged;
};

static void dispose_legacy_patch_state(struct legacy_patch_state *state) {
    if (state != NULL && MACH_PORT_VALID(state->task)) {
        (void)mach_port_deallocate(mach_task_self(), state->task);
        state->task = MACH_PORT_NULL;
    }
}

static bool task_port_matches_worker(
    task_t task, const struct process_identity *worker) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    return MACH_PORT_VALID(task) && worker != NULL &&
           task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) ==
               KERN_SUCCESS &&
           count == TASK_AUDIT_TOKEN_COUNT &&
           (pid_t)token.val[5] == worker->pid &&
           (int32_t)token.val[7] == worker->unique.pid_version;
}

static bool stage_legacy_worker_patch(
    const struct process_identity *worker, struct legacy_patch_state *state,
    int *system_error) {
    if (worker == NULL || state == NULL || system_error == NULL ||
        memcmp(worker->unique.uuid, kExpectedLegacyWorkerUUID,
               sizeof(kExpectedLegacyWorkerUUID)) != 0 ||
        !process_still_exact(worker)) {
        if (system_error != NULL) {
            *system_error = EAUTH;
        }
        return false;
    }
    memset(state, 0, sizeof(*state));
    kern_return_t task_result = task_for_pid(
        mach_task_self(), worker->pid, &state->task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(state->task) ||
        !task_port_matches_worker(state->task, worker) ||
        !process_still_exact(worker)) {
        dispose_legacy_patch_state(state);
        *system_error = EPERM;
        return false;
    }

    bool inspected = inspect_legacy_worker_image(
        state->task, &state->image, state->addresses);
    state->page_size = (mach_vm_size_t)getpagesize();
    state->page = state->page_size != 0
                      ? state->addresses[0] & ~(state->page_size - 1U)
                      : 0;
    uint32_t originals[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool pristine = inspected && state->page_size != 0 &&
                    (state->page_size & (state->page_size - 1U)) == 0 &&
                    state->page != 0 && remote_range_has_protection(
                        state->task, state->page, state->page_size,
                        VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_WRITE);
    for (size_t index = 0;
         pristine && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
        pristine =
            (state->addresses[index] & ~(state->page_size - 1U)) ==
                state->page &&
            read_remote_exact(state->task, state->addresses[index],
                              &originals[index], sizeof(originals[index])) ==
                KERN_SUCCESS &&
            originals[index] == kLegacyInstructionPatches[index].original;
    }
    if (!pristine || !process_still_exact(worker)) {
        log_message("legacy worker stage rejected pid=%d image=0x%llx "
                    "page=0x%llx words=%08x,%08x,%08x,%08x",
                    worker->pid, (unsigned long long)state->image,
                    (unsigned long long)state->page, originals[0],
                    originals[1], originals[2], originals[3]);
        dispose_legacy_patch_state(state);
        *system_error = EPROTO;
        return false;
    }

    kern_return_t protect_result = mach_vm_protect(
        state->task, state->page, state->page_size, false,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    kern_return_t write_result = protect_result;
    size_t writes = 0;
    if (protect_result == KERN_SUCCESS) {
        write_result = KERN_SUCCESS;
        for (size_t index = 0; index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
            write_result = mach_vm_write(
                state->task, state->addresses[index],
                (vm_offset_t)(uintptr_t)
                    &kLegacyInstructionPatches[index].replacement,
                (mach_msg_type_number_t)sizeof(uint32_t));
            if (write_result != KERN_SUCCESS) {
                break;
            }
            ++writes;
        }
    }
    vm_machine_attribute_val_t cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t flush_result =
        write_result == KERN_SUCCESS && writes == CUSTOMD_LEGACY_PATCH_COUNT
            ? vm_machine_attribute(state->task, (vm_address_t)state->page,
                                   (vm_size_t)state->page_size, MATTR_CACHE,
                                   &cache_value)
            : write_result;
    uint32_t readbacks[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool staged = flush_result == KERN_SUCCESS &&
                  remote_range_has_protection(
                      state->task, state->page, state->page_size,
                      VM_PROT_READ | VM_PROT_WRITE, VM_PROT_EXECUTE);
    for (size_t index = 0;
         staged && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
        staged = read_remote_exact(state->task, state->addresses[index],
                                   &readbacks[index],
                                   sizeof(readbacks[index])) ==
                     KERN_SUCCESS &&
                 readbacks[index] ==
                     kLegacyInstructionPatches[index].replacement;
    }
    state->staged = staged && task_port_matches_worker(state->task, worker) &&
                    process_still_exact(worker);
    log_message("legacy worker stage pid=%d image=0x%llx page=0x%llx "
                "protect=%d write=%d writes=%zu flush=%d "
                "read=%08x,%08x,%08x,%08x staged=%d",
                worker->pid, (unsigned long long)state->image,
                (unsigned long long)state->page, protect_result, write_result,
                writes, flush_result, readbacks[0], readbacks[1],
                readbacks[2], readbacks[3], state->staged);
    if (!state->staged) {
        dispose_legacy_patch_state(state);
        *system_error = EIO;
        return false;
    }
    *system_error = 0;
    return true;
}

static bool finalize_legacy_worker_patch(
    const struct process_identity *worker, struct legacy_patch_state *state,
    int *system_error) {
    if (worker == NULL || state == NULL || system_error == NULL ||
        !state->staged || !task_port_matches_worker(state->task, worker) ||
        !process_still_exact(worker)) {
        if (system_error != NULL) {
            *system_error = EAUTH;
        }
        return false;
    }
    kern_return_t execute_result = mach_vm_protect(
        state->task, state->page, state->page_size, false,
        VM_PROT_READ | VM_PROT_EXECUTE);
    uint32_t readbacks[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool finalized = execute_result == KERN_SUCCESS &&
                     remote_range_has_protection(
                         state->task, state->page, state->page_size,
                         VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_WRITE);
    for (size_t index = 0;
         finalized && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
        finalized = read_remote_exact(state->task, state->addresses[index],
                                      &readbacks[index],
                                      sizeof(readbacks[index])) ==
                        KERN_SUCCESS &&
                    readbacks[index] ==
                        kLegacyInstructionPatches[index].replacement;
    }
    finalized = finalized && task_port_matches_worker(state->task, worker) &&
                process_still_exact(worker);
    log_message("legacy worker finalize pid=%d execute=%d "
                "read=%08x,%08x,%08x,%08x finalized=%d",
                worker->pid, execute_result, readbacks[0], readbacks[1],
                readbacks[2], readbacks[3], finalized);
    *system_error = finalized ? 0 : EACCES;
    return finalized;
}
#endif

struct legacy_patch_state {
    task_t task;
    mach_vm_address_t image;
    mach_vm_address_t page;
    mach_vm_size_t page_size;
    mach_vm_address_t addresses[CUSTOMD_LEGACY_PATCH_COUNT];
    bool suspended;
    bool prepared;
};

static void dispose_legacy_patch_state(struct legacy_patch_state *state) {
    if (state == NULL) {
        return;
    }
    if (state->suspended && MACH_PORT_VALID(state->task)) {
        (void)task_resume(state->task);
        state->suspended = false;
    }
    if (MACH_PORT_VALID(state->task)) {
        (void)mach_port_deallocate(mach_task_self(), state->task);
        state->task = MACH_PORT_NULL;
    }
}

static bool task_port_matches_worker(
    task_t task, const struct process_identity *worker) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    return MACH_PORT_VALID(task) && worker != NULL &&
           task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) ==
               KERN_SUCCESS &&
           count == TASK_AUDIT_TOKEN_COUNT &&
           (pid_t)token.val[5] == worker->pid &&
           (int32_t)token.val[7] == worker->unique.pid_version;
}

static bool prepare_legacy_worker_patch(
    const struct process_identity *worker, struct legacy_patch_state *state,
    int *system_error) {
    if (worker == NULL || state == NULL || system_error == NULL ||
        memcmp(worker->unique.uuid, kExpectedLegacyWorkerUUID,
               sizeof(kExpectedLegacyWorkerUUID)) != 0 ||
        !process_still_exact(worker)) {
        if (system_error != NULL) {
            *system_error = EAUTH;
        }
        return false;
    }
    memset(state, 0, sizeof(*state));
    kern_return_t task_result = task_for_pid(
        mach_task_self(), worker->pid, &state->task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(state->task) ||
        !task_port_matches_worker(state->task, worker) ||
        !process_still_exact(worker)) {
        dispose_legacy_patch_state(state);
        *system_error = EPERM;
        return false;
    }
    bool inspected = inspect_legacy_worker_image(
        state->task, &state->image, state->addresses);
    state->page_size = (mach_vm_size_t)getpagesize();
    state->page = state->page_size != 0
                      ? state->addresses[0] & ~(state->page_size - 1U)
                      : 0;
    uint32_t originals[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool pristine = inspected && state->page_size != 0 &&
                    (state->page_size & (state->page_size - 1U)) == 0 &&
                    state->page != 0 && remote_range_has_protection(
                        state->task, state->page, state->page_size,
                        VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_WRITE);
    for (size_t index = 0;
         pristine && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
        pristine =
            (state->addresses[index] & ~(state->page_size - 1U)) ==
                state->page &&
            read_remote_exact(state->task, state->addresses[index],
                              &originals[index], sizeof(originals[index])) ==
                KERN_SUCCESS &&
            originals[index] == kLegacyInstructionPatches[index].original;
    }
    kern_return_t suspend_result = pristine
        ? task_suspend(state->task)
        : KERN_FAILURE;
    state->suspended = suspend_result == KERN_SUCCESS;
    state->prepared = state->suspended &&
                      task_port_matches_worker(state->task, worker) &&
                      process_still_exact(worker);
    log_message("legacy worker prepare pid=%d image=0x%llx page=0x%llx "
                "inspected=%d words=%08x,%08x,%08x,%08x suspend=%d "
                "prepared=%d",
                worker->pid, (unsigned long long)state->image,
                (unsigned long long)state->page, inspected, originals[0],
                originals[1], originals[2], originals[3], suspend_result,
                state->prepared);
    if (!state->prepared) {
        dispose_legacy_patch_state(state);
        *system_error = pristine ? EBUSY : EPROTO;
        return false;
    }
    *system_error = 0;
    return true;
}

static bool apply_legacy_worker_patch(
    const struct process_identity *worker, struct legacy_patch_state *state,
    int *system_error) {
    uint32_t flags = 0;
    bool admitted = worker != NULL && state != NULL && system_error != NULL &&
                    state->prepared && state->suspended &&
                    task_port_matches_worker(state->task, worker) &&
                    process_still_exact(worker) &&
                    csops(worker->pid, CUSTOMD_CS_OPS_STATUS, &flags,
                          sizeof(flags)) == 0 &&
                    (flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED)) ==
                        (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED) &&
                    (flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0;
    if (!admitted) {
        if (system_error != NULL) {
            *system_error = EACCES;
        }
        return false;
    }

    kern_return_t protect_result = mach_vm_protect(
        state->task, state->page, state->page_size, false,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    kern_return_t write_result = protect_result;
    size_t writes = 0;
    if (protect_result == KERN_SUCCESS) {
        write_result = KERN_SUCCESS;
        for (size_t index = 0; index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
            write_result = mach_vm_write(
                state->task, state->addresses[index],
                (vm_offset_t)(uintptr_t)
                    &kLegacyInstructionPatches[index].replacement,
                (mach_msg_type_number_t)sizeof(uint32_t));
            if (write_result != KERN_SUCCESS) {
                break;
            }
            ++writes;
        }
    }
    vm_machine_attribute_val_t cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t flush_result =
        write_result == KERN_SUCCESS && writes == CUSTOMD_LEGACY_PATCH_COUNT
            ? vm_machine_attribute(state->task, (vm_address_t)state->page,
                                   (vm_size_t)state->page_size, MATTR_CACHE,
                                   &cache_value)
            : write_result;
    kern_return_t execute_result = protect_result == KERN_SUCCESS
        ? mach_vm_protect(state->task, state->page, state->page_size, false,
                          VM_PROT_READ | VM_PROT_EXECUTE)
        : protect_result;
    uint32_t readbacks[CUSTOMD_LEGACY_PATCH_COUNT] = {0};
    bool applied = flush_result == KERN_SUCCESS &&
                   execute_result == KERN_SUCCESS &&
                   remote_range_has_protection(
                       state->task, state->page, state->page_size,
                       VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_WRITE);
    for (size_t index = 0;
         applied && index < CUSTOMD_LEGACY_PATCH_COUNT; ++index) {
        applied = read_remote_exact(state->task, state->addresses[index],
                                    &readbacks[index],
                                    sizeof(readbacks[index])) ==
                      KERN_SUCCESS &&
                  readbacks[index] ==
                      kLegacyInstructionPatches[index].replacement;
    }
    applied = applied && task_port_matches_worker(state->task, worker) &&
              process_still_exact(worker);
    log_message("legacy worker apply pid=%d flags=0x%08x protect=%d "
                "write=%d writes=%zu flush=%d execute=%d "
                "read=%08x,%08x,%08x,%08x applied=%d",
                worker->pid, flags, protect_result, write_result, writes,
                flush_result, execute_result, readbacks[0], readbacks[1],
                readbacks[2], readbacks[3], applied);
    *system_error = applied ? 0 : EIO;
    return applied;
}

static bool release_legacy_worker_task(
    struct legacy_patch_state *state, int *system_error) {
    if (state == NULL || system_error == NULL || !state->suspended ||
        !MACH_PORT_VALID(state->task)) {
        if (system_error != NULL) {
            *system_error = EINVAL;
        }
        return false;
    }
    kern_return_t result = task_resume(state->task);
    if (result == KERN_SUCCESS) {
        state->suspended = false;
    }
    *system_error = result == KERN_SUCCESS ? 0 : EBUSY;
    return result == KERN_SUCCESS;
}
#endif

static int spawn_ptrauth_inplace_helper(
    const struct process_identity *donor, const char *helper_path,
    char *const helper_arguments[], size_t helper_argument_count,
    unsigned int timeout_msec, pid_t *child_out, int *system_error) {
    if (donor == NULL || helper_path == NULL || helper_arguments == NULL ||
        helper_argument_count > CUSTOMD_MAX_ARGUMENTS ||
        (strcmp(helper_path, kRegistrarPath) != 0 &&
         strcmp(helper_path, kSetexecHelperPath) != 0) ||
        !process_still_exact(donor)) {
        *system_error = ESRCH;
        return -1;
    }
    task_t donor_task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(
        mach_task_self(), donor->pid, &donor_task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(donor_task) ||
        !task_port_matches_identity(donor_task, donor) ||
        !process_still_exact(donor)) {
        if (MACH_PORT_VALID(donor_task)) {
            (void)mach_port_deallocate(mach_task_self(), donor_task);
        }
        *system_error = EPERM;
        return -1;
    }

    posix_spawnattr_t attributes;
    int result = posix_spawnattr_init(&attributes);
    if (result == 0) {
        result = posix_spawnattr_set_ptrauth_task_port_np(&attributes,
                                                          donor_task);
    }
    if (result == 0) {
        result = posix_spawnattr_setflags(&attributes,
                                          (short)(POSIX_SPAWN_START_SUSPENDED |
                                                  POSIX_SPAWN_SETPGROUP));
    }
    if (result == 0) {
        result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    char *arguments[CUSTOMD_MAX_ARGUMENTS + 4U] = {
                         (char *)kWorkerPath,
#if CUSTOMD_WORKER_HAS_MACHO_INPLACE
                         (char *)"--macho-inplace",
#else
                         (char *)"--macho",
#endif
                         (char *)helper_path};
    for (size_t index = 0; index < helper_argument_count; ++index) {
        arguments[index + 3U] = helper_arguments[index];
    }
    arguments[helper_argument_count + 3U] = NULL;
    pid_t child = -1;
    if (result == 0) {
        result = posix_spawn(&child, kWorkerPath, NULL, &attributes,
                             arguments, environ);
    }
    (void)posix_spawnattr_destroy(&attributes);
    (void)mach_port_deallocate(mach_task_self(), donor_task);
    if (result != 0 || child <= 1) {
        *system_error = result != 0 ? result : ECHILD;
        return -1;
    }
    *child_out = child;

    int wait_status = 0;
    struct process_identity worker = {0};
    char worker_real_path[PATH_MAX] = {0};
    bool start_exact = getpgid(child) == child &&
                       wait_for_owned_stop(child, &wait_status) &&
                       realpath(kWorkerPath, worker_real_path) != NULL &&
                       bind_process(child, &worker) &&
                       strcmp(worker.path, worker_real_path) == 0;
#if CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
    struct legacy_patch_state legacy_patch = {0};
    int patch_error = 0;
    bool worker_prepared = start_exact &&
        prepare_legacy_worker_patch(&worker, &legacy_patch, &patch_error);
#else
    int patch_error = 0;
    task_t worker_task = MACH_PORT_NULL;
    kern_return_t worker_task_result = start_exact
        ? task_for_pid(mach_task_self(), child, &worker_task)
        : KERN_FAILURE;
    kern_return_t worker_suspend_result =
        worker_task_result == KERN_SUCCESS &&
                task_port_matches_identity(worker_task, &worker)
            ? task_suspend(worker_task)
            : KERN_FAILURE;
    bool native_worker_held = worker_suspend_result == KERN_SUCCESS &&
        task_port_matches_identity(worker_task, &worker) &&
        process_still_exact(&worker);
    bool worker_prepared = start_exact && native_worker_held;
#endif
    log_message("ptrauth helper worker initial pid=%d helper=%s "
                "status=0x%x exact=%d prepared=%d patchError=%d",
                child, helper_path, wait_status, start_exact,
                worker_prepared, patch_error);
    errno = 0;
    int attach_result = worker_prepared
                            ? ptrace(CUSTOMD_PT_ATTACHEXC, child, NULL, 0)
                            : -1;
    int attach_error = attach_result == 0 ? 0 : errno;
#if CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
    bool patch_applied = attach_result == 0 &&
        apply_legacy_worker_patch(&worker, &legacy_patch, &patch_error);
#else
    bool patch_applied = true;
#endif
    uint32_t flags = 0;
    bool attach_held = attach_result == 0 && patch_applied &&
                       process_still_exact(&worker);
    bool softened = attach_held &&
                    csops(child, CUSTOMD_CS_OPS_STATUS, &flags,
                          sizeof(flags)) == 0 &&
                    (flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED)) ==
                        (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED) &&
                    (flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0;
    errno = 0;
    int detach_result = softened
        ? ptrace(CUSTOMD_PT_DETACH, child, (caddr_t)1, 0)
        : -1;
    int detach_error = detach_result == 0 ? 0 : errno;
    if (attach_result == 0 && detach_result != 0) {
        (void)ptrace(CUSTOMD_PT_KILL, child, NULL, 0);
    }
#if CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
    bool task_released = legacy_patch.suspended &&
        release_legacy_worker_task(&legacy_patch, &patch_error);
    dispose_legacy_patch_state(&legacy_patch);
#else
    kern_return_t worker_resume_result = native_worker_held
        ? task_resume(worker_task)
        : KERN_FAILURE;
    bool task_released = !native_worker_held ||
                         worker_resume_result == KERN_SUCCESS;
    if (MACH_PORT_VALID(worker_task)) {
        (void)mach_port_deallocate(mach_task_self(), worker_task);
    }
#endif
    bool execution_ready = worker_prepared && patch_applied && softened &&
                           detach_result == 0 && task_released;
    log_message("ptrauth helper worker attach pid=%d helper=%s attach=%d "
                "held=%d applied=%d detach=%d released=%d flags=0x%08x "
                "softened=%d",
                child, helper_path, attach_result, attach_held,
                patch_applied, detach_result, task_released, flags,
                softened);
    if (!execution_ready) {
        (void)kill(child, SIGCONT);
        terminate_owned_process_group(child);
        if (attach_result != 0) {
            *system_error = attach_error != 0 ? attach_error : EACCES;
        } else if (!patch_applied || !task_released) {
            *system_error = patch_error != 0 ? patch_error : EPROTO;
        } else {
            *system_error = detach_error != 0 ? detach_error : EACCES;
        }
        return -1;
    }

    errno = 0;
    int resume_result = kill(child, SIGCONT);
    int resume_error = resume_result == 0 ? 0 : errno;
    if (resume_result != 0 && resume_error != ESRCH) {
        terminate_owned_process_group(child);
        *system_error = resume_error != 0 ? resume_error : EPROTO;
        return -1;
    }
    return wait_for_spawned_process(child, timeout_msec, system_error);
}

static int spawn_ptrauth_registrar(
    const struct process_identity *cryptexd, pid_t *child_out,
    int *system_error) {
    char pid_text[24] = {0};
    int pid_length = cryptexd != NULL
        ? snprintf(pid_text, sizeof(pid_text), "%d", cryptexd->pid)
        : -1;
    if (pid_length <= 0 || (size_t)pid_length >= sizeof(pid_text)) {
        *system_error = EINVAL;
        return -1;
    }
    char *arguments[] = {pid_text};
    return spawn_ptrauth_inplace_helper(
        cryptexd, kRegistrarPath, arguments, 1U,
        CUSTOMD_ENSURE_TIMEOUT_MSEC, child_out, system_error);
}

static struct operation_result reexec_probe(bool setexec_suspended) {
    struct operation_result result = {
        .status = CUSTOMD_STATUS_CHILD_FAILED,
        .system_error = EPROTO,
        .child_pid = -1,
    };
    if (!fixed_trace_reexec_artifacts_exact()) {
        result.status = CUSTOMD_STATUS_BAD_PATH;
        result.system_error = EAUTH;
        result_message(&result, "fixed trace re-exec artifacts rejected");
        return result;
    }

    posix_spawnattr_t attributes;
    int setup_result = posix_spawnattr_init(&attributes);
    bool attributes_initialized = setup_result == 0;
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setflags(
            &attributes,
            (short)(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP));
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    char *arguments[] = {
        (char *)kWorkerPath,
#if CUSTOMD_WORKER_HAS_MACHO_INPLACE
        (char *)"--macho-inplace",
#else
        (char *)"--macho",
#endif
        (char *)kTraceReexecProbePath,
        (char *)(setexec_suspended ? "--setexec-child" : "--exec-child"),
        NULL,
    };
    pid_t child = -1;
    int spawn_result = setup_result == 0
        ? posix_spawn(&child, kWorkerPath, NULL, &attributes, arguments,
                      environ)
        : setup_result;
    if (attributes_initialized) {
        (void)posix_spawnattr_destroy(&attributes);
    }
    if (spawn_result != 0 || child <= 1) {
        result.system_error = spawn_result != 0 ? spawn_result : ECHILD;
        result_message(&result, "trusted worker spawn failed");
        return result;
    }
    result.child_pid = child;

    int initial_status = 0;
    struct process_identity worker = {0};
    char worker_real_path[PATH_MAX] = {0};
    bool start_exact = getpgid(child) == child &&
                       wait_for_owned_stop(child, &initial_status) &&
                       realpath(kWorkerPath, worker_real_path) != NULL &&
                       bind_process(child, &worker) &&
                       strcmp(worker.path, worker_real_path) == 0;
#if CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
    struct legacy_patch_state legacy_patch = {0};
    int patch_error = 0;
    bool worker_prepared = start_exact && prepare_legacy_worker_patch(
        &worker, &legacy_patch, &patch_error);
#else
    int patch_error = 0;
    bool worker_prepared = start_exact;
#endif
    log_message("trace reexec worker initial pid=%d status=0x%x exact=%d "
                "prepared=%d patchError=%d",
                child, initial_status, start_exact, worker_prepared,
                patch_error);

    errno = 0;
    int attach_result = worker_prepared
        ? ptrace(CUSTOMD_PT_ATTACHEXC, child, NULL, 0)
        : -1;
    int attach_error = attach_result == 0 ? 0 : errno;
    int worker_attach_status = 0;
    bool worker_attach_stopped = false;
    uint32_t worker_flags = 0;
    bool worker_softened = false;
    int worker_detach = -1;
    int worker_detach_error = 0;
#if CUSTOMD_LEGACY_WORKER_RUNTIME_PATCH
    bool patch_applied = attach_result == 0 && apply_legacy_worker_patch(
        &worker, &legacy_patch, &patch_error);
    /* PT_ATTACHEXC performs cs_allow_invalid synchronously.  Keep the
       extra task-suspend hold acquired by prepare_legacy_worker_patch while
       patching and detach before releasing it.  Waiting for ATTACHEXC's
       synthetic SIGSTOP here is racy on-device because P_LSIGEXC can route
       that stop through an absent Mach exception handler. */
    worker_attach_stopped = attach_result == 0 && patch_applied &&
        legacy_patch.suspended && process_still_exact(&worker);
    worker_softened = worker_attach_stopped &&
        csops(child, CUSTOMD_CS_OPS_STATUS, &worker_flags,
              sizeof(worker_flags)) == 0 &&
        (worker_flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED) &&
        (worker_flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0;
    errno = 0;
    worker_detach = worker_softened
        ? ptrace(CUSTOMD_PT_DETACH, child, (caddr_t)1, 0)
        : -1;
    worker_detach_error = worker_detach == 0 ? 0 : errno;
    bool task_released = legacy_patch.suspended &&
        release_legacy_worker_task(&legacy_patch, &patch_error);
    dispose_legacy_patch_state(&legacy_patch);
#else
    bool patch_applied = true;
    bool task_released = true;
    worker_attach_stopped = attach_result == 0 && patch_applied &&
        task_released &&
        wait_for_owned_traced_stop(child, &worker_attach_status);
    worker_softened = worker_attach_stopped &&
        process_still_exact(&worker) &&
        csops(child, CUSTOMD_CS_OPS_STATUS, &worker_flags,
              sizeof(worker_flags)) == 0 &&
        (worker_flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED) &&
        (worker_flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0;
    errno = 0;
    worker_detach = worker_softened
        ? ptrace(CUSTOMD_PT_DETACH, child, (caddr_t)1, 0)
        : -1;
    worker_detach_error = worker_detach == 0 ? 0 : errno;
#endif
    log_message("trace reexec worker attach pid=%d status=0x%x attach=%d "
                "held=%d applied=%d detached=%d released=%d "
                "flags=0x%08x soft=%d",
                child, worker_attach_status, attach_result,
                worker_attach_stopped, patch_applied, worker_detach,
                task_released, worker_flags, worker_softened);
    if (!worker_softened || worker_detach != 0 || !task_released) {
        if (attach_result == 0 && worker_detach != 0) {
            (void)ptrace(CUSTOMD_PT_KILL, child, NULL, 0);
        }
        terminate_owned_process_group(child);
        if (attach_result != 0) {
            result.system_error = attach_error != 0 ? attach_error : EACCES;
        } else if (!patch_applied || !task_released) {
            result.system_error = patch_error != 0 ? patch_error : EPROTO;
        } else {
            result.system_error = worker_detach_error != 0
                                      ? worker_detach_error
                                      : EPROTO;
        }
        result_message(&result,
                       "trusted worker could not enter in-place lane");
        return result;
    }

    errno = 0;
    int worker_resume = kill(child, SIGCONT);
    int worker_resume_error = worker_resume == 0 ? 0 : errno;
    if (worker_resume != 0) {
        terminate_owned_process_group(child);
        result.system_error = worker_resume_error;
        result_message(&result, "trusted worker release failed");
        return result;
    }

    int exec_status = 0;
    bool exec_stopped = setexec_suspended
        ? wait_for_owned_stop(child, &exec_status)
        : wait_for_owned_signal_stop(child, SIGTRAP, &exec_status);
    struct process_identity candidate = {0};
    char candidate_real_path[PATH_MAX] = {0};
    uint32_t exec_flags = 0;
    uint8_t exec_cdhash[sizeof(kExpectedCandidateCdhash)] = {0};
    errno = 0;
    int exec_csops = exec_stopped
        ? csops(child, CUSTOMD_CS_OPS_STATUS, &exec_flags,
                sizeof(exec_flags))
        : -1;
    int exec_csops_error = exec_csops == 0 ? 0 : errno;
    errno = 0;
    int exec_cdhash_result = exec_stopped
        ? csops(child, CUSTOMD_CS_OPS_CDHASH, exec_cdhash,
                sizeof(exec_cdhash))
        : -1;
    int exec_cdhash_error = exec_cdhash_result == 0 ? 0 : errno;
    bool candidate_exact = exec_stopped &&
        realpath(kCandidateSpringBoardPath, candidate_real_path) != NULL &&
        bind_process(child, &candidate) &&
        strcmp(candidate.path, candidate_real_path) == 0 &&
        memcmp(candidate.unique.uuid, kExpectedCandidateUUID,
               sizeof(kExpectedCandidateUUID)) == 0 &&
        exec_csops == 0 &&
        (exec_flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW) &&
        exec_cdhash_result == 0 &&
        memcmp(exec_cdhash, kExpectedCandidateCdhash,
               sizeof(exec_cdhash)) == 0 &&
        fixed_trace_reexec_artifacts_exact();
    log_message("trace reexec exec-stop pid=%d status=0x%x stopped=%d "
                "exact=%d flags=0x%08x csops=%d csopsError=%d "
                "cdhash=%d cdhashError=%d path=%s",
                child, exec_status, exec_stopped, candidate_exact,
                exec_flags, exec_csops, exec_csops_error,
                exec_cdhash_result, exec_cdhash_error,
                candidate.path[0] != '\0' ? candidate.path : "<none>");
    if (!candidate_exact) {
        if (exec_stopped) {
            (void)ptrace(CUSTOMD_PT_KILL, child, NULL, 0);
        }
        terminate_owned_process_group(child);
        result.before = exec_flags;
        result.system_error = exec_csops_error != 0
                                  ? exec_csops_error
                                  : (exec_cdhash_error != 0
                                         ? exec_cdhash_error
                                         : EAUTH);
        result_message(
            &result,
            "candidate did not reach exact %s exec stop "
            "status=0x%x flags=0x%08x",
            setexec_suspended ? "SETEXEC_SUSPENDED" : "TRACE_ME",
            exec_status, exec_flags);
        return result;
    }
    result.before = exec_flags;

    /* XNU caches the current signal's action before entering a ptrace stop.
       Replacing SIGTRAP with SIGSTOP through ptrace's data argument can
       therefore retain SIGTRAP's terminate action.  Queue a real SIGSTOP,
       suppress the current SIGTRAP with data=0, and let the signal loop
       recompute SIGSTOP's action before any user instruction can run. */
    int prime_signal = 0;
    int prime_signal_error = 0;
    int prime_continue = 0;
    int prime_continue_error = 0;
    int prime_status = setexec_suspended ? exec_status : 0;
    bool prime_stopped = setexec_suspended && exec_stopped &&
        process_still_exact(&candidate);
    if (!setexec_suspended) {
        errno = 0;
        prime_signal = kill(child, SIGSTOP);
        prime_signal_error = prime_signal == 0 ? 0 : errno;
        errno = 0;
        prime_continue = prime_signal == 0
            ? ptrace(CUSTOMD_PT_CONTINUE, child, (caddr_t)1, 0)
            : -1;
        prime_continue_error = prime_continue == 0 ? 0 : errno;
        prime_stopped = prime_continue == 0 &&
            wait_for_owned_signal_stop(child, SIGSTOP, &prime_status) &&
            process_still_exact(&candidate);
    }

    /* Queue a second, distinct SIGSTOP before suppressing the traced one.
       After PT_DETACH clears P_LTRACED, that queued stop is processed with
       its native stop action and becomes an ordinary parent-owned stop. */
    int handoff_signal = 0;
    int handoff_signal_error = 0;
    int trace_detach = 0;
    int trace_detach_error = 0;
    int handoff_status = setexec_suspended ? exec_status : 0;
    bool handoff_stopped = setexec_suspended && prime_stopped;
    if (!setexec_suspended) {
        errno = 0;
        handoff_signal = prime_stopped ? kill(child, SIGSTOP) : -1;
        handoff_signal_error = handoff_signal == 0 ? 0 : errno;
        errno = 0;
        trace_detach = handoff_signal == 0
            ? ptrace(CUSTOMD_PT_DETACH, child, (caddr_t)1, 0)
            : -1;
        trace_detach_error = trace_detach == 0 ? 0 : errno;
        handoff_stopped = trace_detach == 0 &&
            wait_for_owned_signal_stop(child, SIGSTOP, &handoff_status) &&
            process_still_exact(&candidate);
    }

    /* Hold an extra Mach task-suspend reference across ATTACHEXC.  The
       attach synchronously performs cs_allow_invalid, while the hold keeps
       its synthetic LSIGEXC SIGSTOP from reaching an absent exception
       handler.  Detach again before releasing the hold; CS_DEBUGGED remains
       set and no candidate instruction has executed. */
    task_t task = MACH_PORT_NULL;
    kern_return_t task_result = handoff_stopped
        ? task_for_pid(mach_task_self(), child, &task)
        : KERN_FAILURE;
    bool task_exact = task_result == KERN_SUCCESS &&
        task_port_matches_identity(task, &candidate);
    kern_return_t task_suspend_result = task_exact
        ? task_suspend(task)
        : KERN_FAILURE;
    bool task_held = task_suspend_result == KERN_SUCCESS &&
        task_port_matches_identity(task, &candidate) &&
        process_still_exact(&candidate);
    errno = 0;
    int candidate_attach = task_held
        ? ptrace(CUSTOMD_PT_ATTACHEXC, child, NULL, 0)
        : -1;
    int candidate_attach_error = candidate_attach == 0 ? 0 : errno;
    bool candidate_attach_held = candidate_attach == 0 && task_held &&
        task_port_matches_identity(task, &candidate) &&
        process_still_exact(&candidate);

    uint32_t attached_flags = 0;
    errno = 0;
    int attached_csops = candidate_attach_held
        ? csops(child, CUSTOMD_CS_OPS_STATUS, &attached_flags,
                sizeof(attached_flags))
        : -1;
    int attached_csops_error = attached_csops == 0 ? 0 : errno;
    uint8_t attached_cdhash[sizeof(kExpectedCandidateCdhash)] = {0};
    int attached_cdhash_result = candidate_attach_held
        ? csops(child, CUSTOMD_CS_OPS_CDHASH, attached_cdhash,
                sizeof(attached_cdhash))
        : -1;
    bool attached_cdhash_exact = attached_cdhash_result == 0 &&
        memcmp(attached_cdhash, kExpectedCandidateCdhash,
               sizeof(attached_cdhash)) == 0;
    bool debug_ready = candidate_attach_held && attached_csops == 0 &&
        attached_cdhash_exact &&
        (attached_flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW |
                           CUSTOMD_CS_DEBUGGED)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW |
             CUSTOMD_CS_DEBUGGED) &&
        (attached_flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0 &&
        task_exact;

    errno = 0;
    int debug_detach = debug_ready
        ? ptrace(CUSTOMD_PT_DETACH, child, (caddr_t)1, 0)
        : -1;
    int debug_detach_error = debug_detach == 0 ? 0 : errno;
    uint32_t detached_flags = 0;
    int detached_csops = debug_detach == 0
        ? csops(child, CUSTOMD_CS_OPS_STATUS, &detached_flags,
                sizeof(detached_flags))
        : -1;
    bool detached_ready = detached_csops == 0 &&
        process_still_exact(&candidate) &&
        task_port_matches_identity(task, &candidate) &&
        (detached_flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW |
                           CUSTOMD_CS_DEBUGGED)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW |
             CUSTOMD_CS_DEBUGGED) &&
        (detached_flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0;
    result.after = detached_csops == 0 ? detached_flags : attached_flags;

    log_message("trace reexec handoff pid=%d primeSignal=%d "
                "primeSignalError=%d prime=%d primeError=%d "
                "primeStatus=0x%x primeStopped=%d handoffSignal=%d "
                "handoffSignalError=%d detach=%d detachError=%d "
                "handoff=0x%x stopped=%d task=%d suspend=%d held=%d "
                "attach=%d attachError=%d flags=0x%08x csops=%d "
                "csopsError=%d cdhashExact=%d taskExact=%d ready=%d "
                "debugDetach=%d debugDetachError=%d detachedFlags=0x%08x "
                "detachedReady=%d",
                child, prime_signal, prime_signal_error, prime_continue,
                prime_continue_error, prime_status, prime_stopped,
                handoff_signal, handoff_signal_error, trace_detach,
                trace_detach_error, handoff_status, handoff_stopped,
                task_result, task_suspend_result, task_held,
                candidate_attach, candidate_attach_error, attached_flags,
                attached_csops, attached_csops_error,
                attached_cdhash_exact, task_exact, debug_ready,
                debug_detach, debug_detach_error, detached_flags,
                detached_ready);

    errno = 0;
    bool traced_for_cleanup =
        (candidate_attach == 0 && debug_detach != 0) ||
        (exec_stopped && trace_detach != 0);
    int kill_result = traced_for_cleanup
        ? ptrace(CUSTOMD_PT_KILL, child, NULL, 0)
        : kill(child, SIGKILL);
    int kill_error = kill_result == 0 ? 0 : errno;
    kern_return_t task_resume_result = task_held
        ? task_resume(task)
        : KERN_FAILURE;
    bool candidate_task_released =
        !task_held || task_resume_result == KERN_SUCCESS;
    if (MACH_PORT_VALID(task)) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }
    int final_status = 0;
    bool final_waited = kill_result == 0 && candidate_task_released &&
        wait_for_owned_terminal(child, &final_status);
    bool final_killed = final_waited && WIFSIGNALED(final_status) &&
        WTERMSIG(final_status) == SIGKILL;
    if (!final_killed) {
        terminate_owned_process_group(child);
    }

    if (prime_signal == 0 && prime_stopped && handoff_signal == 0 &&
        trace_detach == 0 && handoff_stopped && task_held &&
        candidate_attach == 0 && debug_ready && debug_detach == 0 &&
        detached_ready && kill_result == 0 && candidate_task_released &&
        final_killed) {
        result.status = CUSTOMD_STATUS_OK;
        result.system_error = 0;
        result_message(
            &result,
            "%s re-exec handoff proved exec=0x%x "
            "prime=0x%x handoff=0x%x flags=0x%08x->0x%08x "
            "taskExact=1 final=0x%x candidateInstructions=0",
            setexec_suspended ? "SETEXEC_SUSPENDED" : "TRACE_ME",
            exec_status, prime_status, handoff_status, exec_flags,
            detached_flags, final_status);
    } else {
        if (prime_signal != 0) {
            result.system_error = prime_signal_error;
        } else if (prime_continue != 0) {
            result.system_error = prime_continue_error;
        } else if (!prime_stopped) {
            result.system_error = EPROTO;
        } else if (handoff_signal != 0) {
            result.system_error = handoff_signal_error;
        } else if (trace_detach != 0) {
            result.system_error = trace_detach_error;
        } else if (!task_held) {
            result.system_error = EPERM;
        } else if (candidate_attach != 0) {
            result.system_error = candidate_attach_error;
        } else if (debug_detach != 0) {
            result.system_error = debug_detach_error;
        } else if (!candidate_task_released) {
            result.system_error = EBUSY;
        } else if (kill_result != 0) {
            result.system_error = kill_error;
        } else {
            result.system_error = EPROTO;
        }
        result_message(
            &result,
            "%s handoff failed exec=0x%x signal=%d prime=%d "
            "primeStatus=0x%x detach=%d handoff=0x%x "
            "taskHeld=%d attach=%d debugDetach=%d "
            "flags=0x%08x->0x%08x ready=%d detachedReady=%d "
            "final=0x%x",
            setexec_suspended ? "SETEXEC_SUSPENDED" : "TRACE_ME",
            exec_status, prime_signal, prime_continue, prime_status,
            trace_detach, handoff_status, task_held, candidate_attach,
            debug_detach, exec_flags, result.after, debug_ready,
            detached_ready, final_status);
    }
    return result;
}

static bool copy_task_suspend_count(task_t task, integer_t *count_out) {
    if (!MACH_PORT_VALID(task) || count_out == NULL) {
        return false;
    }
    task_basic_info_data_t information = {0};
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kern_return_t result = task_info(task, TASK_BASIC_INFO,
                                     (task_info_t)&information, &count);
    if (result != KERN_SUCCESS || count < TASK_BASIC_INFO_COUNT ||
        information.suspend_count < 0) {
        return false;
    }
    *count_out = information.suspend_count;
    return true;
}

static bool prime_suspended_candidate_debug(
    const struct process_identity *identity,
    uint32_t *before_out, uint32_t *after_out) {
    if (identity == NULL || before_out == NULL || after_out == NULL ||
        !process_still_exact(identity)) {
        errno = ESRCH;
        return false;
    }
    struct customd_proc_bsdinfo initial_bsd = {0};
    uint32_t before = 0;
    if (!copy_bsd_info(identity->pid, &initial_bsd) ||
        initial_bsd.pbi_status != CUSTOMD_PROC_STATUS_STOPPED ||
        csops(identity->pid, CUSTOMD_CS_OPS_STATUS, &before,
              sizeof(before)) != 0 ||
        (before & (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW)) !=
            (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW)) {
        errno = EAUTH;
        return false;
    }
    task_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(
        mach_task_self(), identity->pid, &task);
    bool task_exact = task_result == KERN_SUCCESS &&
        task_port_matches_identity(task, identity) &&
        process_still_exact(identity);
    integer_t baseline_count = -1;
    bool baseline_exact = task_exact &&
        copy_task_suspend_count(task, &baseline_count) &&
        baseline_count == 1;
    kern_return_t suspend_result = baseline_exact
        ? task_suspend(task)
        : KERN_FAILURE;
    bool legacy_hold_owned = suspend_result == KERN_SUCCESS;
    integer_t added_count = -1;
    bool held_exact = legacy_hold_owned &&
        copy_task_suspend_count(task, &added_count) && added_count == 2 &&
        task_port_matches_identity(task, identity) &&
        process_still_exact(identity);

    errno = 0;
    int attach_result = held_exact
        ? ptrace(CUSTOMD_PT_ATTACHEXC, identity->pid, NULL, 0)
        : -1;
    int attach_error = attach_result == 0 ? 0 : errno;
    integer_t attached_count = -1;
    bool attach_consumed_legacy = attach_result == 0 &&
        copy_task_suspend_count(task, &attached_count) &&
        attached_count == 1;
    if (attach_consumed_legacy) {
        legacy_hold_owned = false;
    }
    uint32_t attached = 0;
    bool flags_ready = attach_consumed_legacy && held_exact &&
        csops(identity->pid, CUSTOMD_CS_OPS_STATUS, &attached,
              sizeof(attached)) == 0 &&
        (attached & (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED) &&
        (attached & CUSTOMD_CS_GET_TASK_ALLOW) != 0 &&
        (attached & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0 &&
        task_port_matches_identity(task, identity) &&
        process_still_exact(identity);
    errno = 0;
    int detach_result = attach_result == 0
        ? ptrace(CUSTOMD_PT_DETACH, identity->pid, (caddr_t)1, 0)
        : -1;
    int detach_error = detach_result == 0 ? 0 : errno;
    if (attach_result == 0 && detach_result != 0) {
        (void)ptrace(CUSTOMD_PT_KILL, identity->pid, NULL, 0);
    }
    uint32_t detached = 0;
    integer_t detached_count = -1;
    bool detached_ready = flags_ready && detach_result == 0 &&
        copy_task_suspend_count(task, &detached_count) &&
        detached_count == 1 &&
        csops(identity->pid, CUSTOMD_CS_OPS_STATUS, &detached,
              sizeof(detached)) == 0 &&
        (detached & (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_DEBUGGED) &&
        (detached & CUSTOMD_CS_GET_TASK_ALLOW) != 0 &&
        (detached & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0 &&
        task_port_matches_identity(task, identity) &&
        process_still_exact(identity);
    kern_return_t cleanup_resume = KERN_SUCCESS;
    if (legacy_hold_owned) {
        cleanup_resume = task_resume(task);
        if (cleanup_resume == KERN_SUCCESS) {
            legacy_hold_owned = false;
        }
    }
    if (MACH_PORT_VALID(task)) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }
    *before_out = before;
    *after_out = detached_ready ? detached : attached;
    log_message("candidate-debug-prime pid=%d path=%s task=%d "
                "baseline=%d suspend=%d added=%d attach=%d "
                "attachError=%d flags=0x%08x detach=%d detachError=%d "
                "attachedCount=%d detachedCount=%d cleanupResume=%d "
                "legacyOwned=%d final=0x%08x ready=%d",
                identity->pid, identity->path, task_result, baseline_count,
                suspend_result, added_count, attach_result, attach_error,
                attached, detach_result, detach_error, attached_count,
                detached_count, cleanup_resume, legacy_hold_owned,
                *after_out, detached_ready);
    errno = detached_ready
        ? 0
        : (attach_error != 0 ? attach_error
                             : (detach_error != 0 ? detach_error : EPERM));
    return detached_ready;
}

static bool candidate_start_hold_exact(
    const struct process_identity *identity, integer_t *count_out,
    uint32_t *flags_out) {
    if (identity == NULL || !process_still_exact(identity)) {
        errno = ESRCH;
        return false;
    }
    task_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(
        mach_task_self(), identity->pid, &task);
    integer_t count = -1;
    uint32_t flags = 0;
    bool exact = task_result == KERN_SUCCESS && MACH_PORT_VALID(task) &&
        task_port_matches_identity(task, identity) &&
        copy_task_suspend_count(task, &count) && count == 1 &&
        csops(identity->pid, CUSTOMD_CS_OPS_STATUS, &flags,
              sizeof(flags)) == 0 &&
        (flags & (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW |
                  CUSTOMD_CS_DEBUGGED)) ==
            (CUSTOMD_CS_VALID | CUSTOMD_CS_GET_TASK_ALLOW |
             CUSTOMD_CS_DEBUGGED) &&
        (flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) == 0 &&
        task_port_matches_identity(task, identity) &&
        process_still_exact(identity) && fixed_setexec_artifacts_exact();
    if (MACH_PORT_VALID(task)) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }
    if (count_out != NULL) {
        *count_out = count;
    }
    if (flags_out != NULL) {
        *flags_out = flags;
    }
    errno = exact ? 0 : EPERM;
    return exact;
}

static bool copy_remote_bytes(task_t task, mach_vm_address_t address,
                              void *buffer, mach_vm_size_t size) {
    mach_vm_size_t copied = 0;
    return MACH_PORT_VALID(task) && address != 0 && buffer != NULL &&
        size != 0 &&
        mach_vm_read_overwrite(
            task, address, size,
            (mach_vm_address_t)(uintptr_t)buffer, &copied) == KERN_SUCCESS &&
        copied == size;
}

static bool copy_remote_path(task_t task, mach_vm_address_t address,
                             char output[PATH_MAX]) {
    memset(output, 0, PATH_MAX);
    size_t used = 0;
    while (used + 1U < PATH_MAX) {
        size_t amount = PATH_MAX - used - 1U;
        if (amount > 256U) {
            amount = 256U;
        }
        if (!copy_remote_bytes(task, address + used, output + used,
                               (mach_vm_size_t)amount)) {
            return false;
        }
        if (memchr(output + used, '\0', amount) != NULL) {
            return true;
        }
        used += amount;
    }
    return false;
}

static bool remote_image_loaded(task_t task, const char *path) {
    task_dyld_info_data_t dyld = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (path == NULL || task_info(task, TASK_DYLD_INFO,
                                  (task_info_t)&dyld, &count) != KERN_SUCCESS ||
        count != TASK_DYLD_INFO_COUNT || dyld.all_image_info_addr == 0 ||
        dyld.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64) {
        return false;
    }
    struct dyld_all_image_infos infos = {0};
    if (!copy_remote_bytes(task, dyld.all_image_info_addr, &infos,
                           sizeof(infos)) ||
        infos.version < 15U || !infos.libSystemInitialized ||
        infos.infoArrayCount == 0 || infos.infoArrayCount > 4096U) {
        return false;
    }
    mach_vm_address_t array =
        (mach_vm_address_t)(uintptr_t)infos.infoArray &
        UINT64_C(0x0000ffffffffffff);
    size_t bytes = (size_t)infos.infoArrayCount *
                   sizeof(struct dyld_image_info);
    struct dyld_image_info *images = malloc(bytes);
    if (images == NULL ||
        !copy_remote_bytes(task, array, images, (mach_vm_size_t)bytes)) {
        free(images);
        return false;
    }
    unsigned int matches = 0;
    for (uint32_t index = 0; index < infos.infoArrayCount; ++index) {
        mach_vm_address_t path_address =
            (mach_vm_address_t)(uintptr_t)images[index].imageFilePath &
            UINT64_C(0x0000ffffffffffff);
        char remote_path[PATH_MAX] = {0};
        if (path_address != 0 &&
            copy_remote_path(task, path_address, remote_path) &&
            strcmp(remote_path, path) == 0) {
            ++matches;
        }
    }
    free(images);
    return matches == 1U;
}

static bool wait_for_candidate_image(
    const struct process_identity *candidate, const char *dylib_path) {
    task_t task = MACH_PORT_NULL;
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_RUNTIME_TIMEOUT_MSEC;
    while (!gStopping && host_parent_alive() &&
           monotonic_milliseconds() < deadline) {
        if (!process_still_exact(candidate)) {
            break;
        }
        if (!MACH_PORT_VALID(task)) {
            task_t new_task = MACH_PORT_NULL;
            kern_return_t result = task_for_pid(
                mach_task_self(), candidate->pid, &new_task);
            if (result == KERN_SUCCESS &&
                task_port_matches_identity(new_task, candidate)) {
                task = new_task;
            } else if (MACH_PORT_VALID(new_task)) {
                (void)mach_port_deallocate(mach_task_self(), new_task);
            }
        }
        if (MACH_PORT_VALID(task) &&
            task_port_matches_identity(task, candidate) &&
            remote_image_loaded(task, dylib_path)) {
            (void)mach_port_deallocate(mach_task_self(), task);
            usleep(500U * 1000U);
            return process_still_exact(candidate);
        }
        usleep(20U * 1000U);
    }
    if (MACH_PORT_VALID(task)) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool wait_for_restored_stock(pid_t *pid_out) {
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_RUNTIME_TIMEOUT_MSEC;
    while (monotonic_milliseconds() < deadline) {
        struct process_identity stock = {0};
        struct customd_proc_bsdinfo bsd = {0};
        uint32_t flags = 0;
        if (bind_exact_stock_springboard(&stock, &bsd, &flags)) {
            struct command_result service =
                print_stock_springboard_service();
            if (stock_service_print_is_exact(&service, stock.pid)) {
                if (pid_out != NULL) {
                    *pid_out = stock.pid;
                }
                return true;
            }
        }
        usleep(50U * 1000U);
    }
    return false;
}

static bool wait_for_cross_exec_candidate(
    const struct process_identity *stock,
    struct process_identity *candidate_out,
    struct customd_proc_bsdinfo *bsd_out, uint32_t *flags_out) {
    if (stock == NULL || candidate_out == NULL || bsd_out == NULL ||
        flags_out == NULL) {
        errno = EINVAL;
        return false;
    }
    char candidate_real_path[PATH_MAX] = {0};
    if (realpath(kCandidateSpringBoardPath, candidate_real_path) == NULL) {
        return false;
    }
    uint64_t deadline = monotonic_milliseconds() +
                        CUSTOMD_TRACE_TIMEOUT_MSEC;
    while (!gStopping && host_parent_alive() &&
           monotonic_milliseconds() < deadline) {
        struct process_identity observed = {0};
        if (!bind_process(stock->pid, &observed)) {
            usleep(10000U);
            continue;
        }
        bool process_preserved =
            observed.unique.unique_id == stock->unique.unique_id &&
            observed.unique.parent_unique_id ==
                stock->unique.parent_unique_id;
        if (!process_preserved) {
            errno = ESTALE;
            return false;
        }
        if (strcmp(observed.path, candidate_real_path) == 0) {
            if (observed.unique.pid_version == stock->unique.pid_version) {
                errno = ESTALE;
                return false;
            }
            return bind_cross_exec_candidate(stock, candidate_out, bsd_out,
                                             flags_out);
        }
        if (strcmp(observed.path, kStockSpringBoardPath) != 0 ||
            observed.unique.pid_version != stock->unique.pid_version) {
            errno = EAUTH;
            return false;
        }
        usleep(10000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool rollback_exact_candidate(
    const struct process_identity *candidate, pid_t *restored_pid_out) {
    if (candidate != NULL && process_still_exact(candidate)) {
        (void)kill(candidate->pid, SIGKILL);
        (void)kill(candidate->pid, SIGCONT);
    }
    if (wait_for_restored_stock(restored_pid_out)) {
        return true;
    }
    char *arguments[] = {(char *)kLaunchctlPath, (char *)"kickstart",
                         (char *)"-k", (char *)kStockSpringBoardTarget,
                         NULL};
    struct command_result kickstart = run_captured_command(
        kLaunchctlPath, arguments, CUSTOMD_COMMAND_TIMEOUT_MSEC);
    return command_succeeded(&kickstart) &&
           wait_for_restored_stock(restored_pid_out);
}

static struct operation_result reexec_inject_springboard(
    const char *requested_path) {
    struct operation_result result = {
        .status = CUSTOMD_STATUS_CHILD_FAILED,
        .system_error = EPROTO,
        .child_pid = -1,
    };
    struct managed_file_binding dylib = {.descriptor = -1};
    if (!fixed_setexec_artifacts_exact() ||
        !validate_managed_file(requested_path, true, &dylib)) {
        result.status = CUSTOMD_STATUS_BAD_PATH;
        result.system_error = errno != 0 ? errno : EAUTH;
        result_message(&result, "fixed SETEXEC helper/candidate or dylib rejected");
        return result;
    }

    struct process_identity stock = {0};
    struct customd_proc_bsdinfo stock_bsd = {0};
    uint32_t stock_flags = 0;
    struct command_result stock_service = print_stock_springboard_service();
    bool stock_exact = bind_exact_stock_springboard(
        &stock, &stock_bsd, &stock_flags) &&
        stock_service_print_is_exact(&stock_service, stock.pid);
    if (!stock_exact) {
        close_managed_file(&dylib);
        result.status = CUSTOMD_STATUS_NO_PROCESS;
        result.system_error = errno != 0 ? errno : ESRCH;
        result_message(&result, "exact launchd-owned stock SpringBoard unavailable");
        return result;
    }

    /* Stock SpringBoard is deliberately not ptrace-softened here.  AMFI's
     * MAC policy refuses cs_allow_invalid for this platform process even to
     * our root daemon.  The PAC-matched helper needs only the donated task
     * context to execute existing signed code; the fixed GTA candidate is
    * the process softened under an audited pre-dyld stop below. */
    uint32_t stock_soft_before = stock_flags;
    stock_service = print_stock_springboard_service();
    if (!process_still_exact(&stock) ||
        !stock_service_print_is_exact(&stock_service, stock.pid) ||
        !managed_file_still_exact(&dylib) ||
        !fixed_setexec_artifacts_exact()) {
        close_managed_file(&dylib);
        result.status = CUSTOMD_STATUS_IDENTITY_CHANGED;
        result.system_error = ESTALE;
        result_message(&result, "stock SpringBoard transaction preflight changed");
        return result;
    }

    char pid_text[24] = {0};
    int pid_length = snprintf(pid_text, sizeof(pid_text), "%d", stock.pid);
    char *helper_arguments[] = {pid_text, dylib.path};
    int helper_result = pid_length > 0 &&
                                (size_t)pid_length < sizeof(pid_text)
        ? spawn_ptrauth_inplace_helper(
              &stock, kSetexecHelperPath, helper_arguments, 2U,
              CUSTOMD_SETEXEC_TIMEOUT_MSEC, &result.child_pid,
              &result.system_error)
        : -1;

    struct process_identity candidate = {0};
    struct customd_proc_bsdinfo candidate_bsd = {0};
    uint32_t candidate_flags = 0;
    bool candidate_exact = wait_for_cross_exec_candidate(
        &stock, &candidate, &candidate_bsd, &candidate_flags);
    stock_service = print_stock_springboard_service();
    bool service_preserved = candidate_exact &&
        stock_service_print_is_exact(&stock_service, stock.pid);
    if (helper_result != 0 || !candidate_exact || !service_preserved ||
        !managed_file_still_exact(&dylib)) {
        struct process_identity recoverable = {0};
        bool recoverable_exact = candidate_exact ||
            bind_recoverable_cross_exec_candidate(&stock, &recoverable);
        const struct process_identity *rollback_target = candidate_exact
            ? &candidate
            : (recoverable_exact ? &recoverable : NULL);
        pid_t restored = -1;
        bool rolled_back = rollback_target != NULL
            ? rollback_exact_candidate(rollback_target, &restored)
            : wait_for_restored_stock(&restored);
        close_managed_file(&dylib);
        result.status = helper_result < 0 &&
                                result.system_error == ETIMEDOUT
                            ? CUSTOMD_STATUS_TIMEOUT
                            : CUSTOMD_STATUS_CHILD_FAILED;
        result.before = stock_soft_before;
        result.after = candidate_flags;
        result_message(&result,
                       "SETEXEC helper failed status=%d candidateExact=%d "
                       "servicePreserved=%d recoverable=%d rollback=%d "
                       "restoredPid=%d",
                       helper_result, candidate_exact, service_preserved,
                       recoverable_exact, rolled_back, restored);
        return result;
    }

    uint32_t candidate_prime_before = 0;
    uint32_t candidate_prime_after = 0;
    bool candidate_primed = prime_suspended_candidate_debug(
        &candidate, &candidate_prime_before, &candidate_prime_after);
    integer_t release_hold_count = -1;
    uint32_t release_flags = 0;
    bool release_exact = candidate_primed &&
        candidate_start_hold_exact(&candidate, &release_hold_count,
                                   &release_flags) &&
        managed_file_still_exact(&dylib);
    int gate_error = release_exact ? 0 : (errno != 0 ? errno : EPERM);
    result.before = candidate_prime_before;
    result.after = candidate_prime_after;
    errno = 0;
    int continue_result = release_exact ? kill(candidate.pid, SIGCONT) : -1;
    int release_error = continue_result == 0
        ? 0
        : (release_exact && errno != 0 ? errno : gate_error);
    if (!release_exact || continue_result != 0) {
        pid_t restored = -1;
        bool rolled_back = rollback_exact_candidate(&candidate, &restored);
        close_managed_file(&dylib);
        result.status = CUSTOMD_STATUS_JIT_DENIED;
        result.system_error = release_error != 0 ? release_error : EPERM;
        result_message(&result,
                       "candidate pre-dyld prime/release failed primed=%d "
                       "releaseExact=%d hold=%d flags=0x%08x continue=%d "
                       "rollback=%d restoredPid=%d",
                       candidate_primed, release_exact, release_hold_count,
                       release_flags, continue_result, rolled_back, restored);
        return result;
    }

    bool loaded = wait_for_candidate_image(&candidate, dylib.path);
    stock_service = print_stock_springboard_service();
    bool final_exact = loaded && process_still_exact(&candidate) &&
        managed_file_still_exact(&dylib) &&
        stock_service_print_is_exact(&stock_service, candidate.pid);
    if (final_exact) {
        result.status = CUSTOMD_STATUS_OK;
        result.system_error = 0;
        result_message(
            &result,
            "same-PID SpringBoard SETEXEC injection live pid=%d "
            "pidVersion=%d->%d flags=0x%08x->0x%08x image=%s",
            candidate.pid, stock.unique.pid_version,
            candidate.unique.pid_version, candidate_prime_before,
            candidate_prime_after, dylib.path);
    } else {
        pid_t restored = -1;
        bool rolled_back = rollback_exact_candidate(&candidate, &restored);
        result.status = CUSTOMD_STATUS_CHILD_FAILED;
        result.system_error = loaded ? ESTALE : ETIMEDOUT;
        result_message(&result,
                       "candidate dylib verification failed loaded=%d "
                       "rollback=%d restoredPid=%d image=%s",
                       loaded, rolled_back, restored, dylib.path);
    }
    close_managed_file(&dylib);
    return result;
}

static struct operation_result ensure_candidate(void) {
    struct operation_result result = {
        .status = CUSTOMD_STATUS_CHILD_FAILED,
        .child_pid = -1,
    };
    if (!fixed_candidate_artifacts_exact()) {
        result.status = CUSTOMD_STATUS_BAD_PATH;
        result.system_error = EAUTH;
        result_message(&result, "fixed candidate artifact hash rejected");
        return result;
    }

    struct command_result before = print_candidate_service();
    if (exact_dormant_candidate_present(&before)) {
        result.status = CUSTOMD_STATUS_OK;
        result_message(&result, "candidate already exact and dormant");
        return result;
    }
    if (!command_completed(&before) || before.standard_output_truncated ||
        before.standard_error_truncated) {
        result.status = CUSTOMD_STATUS_CHILD_FAILED;
        result.system_error = before.spawn_error != 0
                                  ? before.spawn_error
                                  : (before.timed_out ? ETIMEDOUT : EIO);
        result_message(&result,
                       "candidate launchctl preflight did not complete");
        return result;
    }
    if (before.exit_code == 0 || !candidate_process_absent()) {
        result.status = CUSTOMD_STATUS_CONFLICT;
        result.system_error = EEXIST;
        result_message(&result,
                       "existing candidate job/process is not exact dormant");
        return result;
    }

    struct process_identity cryptexd = {0};
    if (!find_unique_exact_cryptexd(&cryptexd)) {
        result.status = CUSTOMD_STATUS_NO_PROCESS;
        result.system_error = errno;
        result_message(&result, "exact unique cryptexd is unavailable");
        return result;
    }
    int child_result = spawn_ptrauth_registrar(
        &cryptexd, &result.child_pid, &result.system_error);
    bool artifacts_exact = fixed_candidate_artifacts_exact();
    bool cryptexd_exact = process_still_exact(&cryptexd);
    struct command_result after = print_candidate_service();
    bool candidate_exact = exact_dormant_candidate_present(&after);
    if (artifacts_exact && cryptexd_exact && candidate_exact) {
        result.status = CUSTOMD_STATUS_OK;
        result.system_error = 0;
        result_message(
            &result,
            child_result == 0
                ? "candidate registered on-device and verified exact dormant"
                : "candidate converged exact dormant despite registrar status=%d",
            child_result);
    } else if (child_result < 0 && result.system_error == ETIMEDOUT) {
        result.status = CUSTOMD_STATUS_TIMEOUT;
        result_message(&result, "candidate registrar timed out");
    } else if (!artifacts_exact || !cryptexd_exact) {
        result.status = CUSTOMD_STATUS_IDENTITY_CHANGED;
        result.system_error = ESTALE;
        result_message(&result,
                       "candidate lane identity changed during registration");
    } else {
        result.status = command_succeeded(&after)
                            ? CUSTOMD_STATUS_CONFLICT
                            : CUSTOMD_STATUS_CHILD_FAILED;
        result_message(&result,
                       "registrar status=%d; exact dormant job not observed",
                       child_result);
    }
    return result;
}

static struct operation_result inject_dylib(pid_t target,
                                             const char *requested_path) {
    struct operation_result result = {
        .status = CUSTOMD_STATUS_CHILD_FAILED,
        .child_pid = -1,
    };
    struct process_identity identity = {0};
    if (!bind_process(target, &identity)) {
        result.status = CUSTOMD_STATUS_NO_PROCESS;
        result.system_error = errno;
        result_message(&result, "cannot bind pid %d", target);
        return result;
    }
    struct managed_file_binding binding = {.descriptor = -1};
    if (!validate_managed_file(requested_path, true, &binding)) {
        result.status = CUSTOMD_STATUS_BAD_PATH;
        result.system_error = errno;
        result_message(&result, "refusing insecure dylib path");
        return result;
    }
    char pid_text[32] = {0};
    (void)snprintf(pid_text, sizeof(pid_text), "%d", target);
    char *arguments[] = {
        (char *)kLoaderPath,
        (char *)"--inject-pid",
        pid_text,
        binding.path,
        NULL,
    };
    int child_result = spawn_and_wait(kLoaderPath, arguments,
                                      CUSTOMD_INJECT_TIMEOUT_MSEC,
                                      &result.child_pid,
                                      &result.system_error);
    bool file_exact = managed_file_still_exact(&binding);
    close_managed_file(&binding);
    if (!process_still_exact(&identity)) {
        result.status = CUSTOMD_STATUS_IDENTITY_CHANGED;
        result_message(&result, "pid %d identity changed during injection",
                       target);
        return result;
    }
    if (!file_exact) {
        result.status = CUSTOMD_STATUS_IDENTITY_CHANGED;
        result.system_error = ESTALE;
        result_message(&result, "dylib identity changed during injection");
        return result;
    }
    if (child_result == 0) {
        result.status = CUSTOMD_STATUS_OK;
        result_message(&result, "injected %s into pid %d path=%s",
                       binding.path, target, identity.path);
    } else if (child_result < 0 && result.system_error == ETIMEDOUT) {
        result.status = CUSTOMD_STATUS_TIMEOUT;
        result_message(&result, "injection timed out for pid %d", target);
    } else {
        result.status = CUSTOMD_STATUS_CHILD_FAILED;
        result_message(&result, "loader failed status=%d for pid %d",
                       child_result, target);
    }
    return result;
}

static struct operation_result run_macho_with_timeout(
    char *const client_arguments[], uint32_t argument_count,
    unsigned int timeout_msec) {
    struct operation_result result = {
        .status = CUSTOMD_STATUS_CHILD_FAILED,
        .child_pid = -1,
    };
    struct managed_file_binding binding = {.descriptor = -1};
    if (argument_count == 0 ||
        !validate_managed_file(client_arguments[0], false, &binding)) {
        result.status = CUSTOMD_STATUS_BAD_PATH;
        result.system_error = errno;
        result_message(&result, "refusing insecure Mach-O path");
        return result;
    }
    char *arguments[CUSTOMD_MAX_ARGUMENTS + 3U] = {0};
    arguments[0] = (char *)kWorkerPath;
    arguments[1] = (char *)"--macho";
    arguments[2] = binding.path;
    for (uint32_t index = 1; index < argument_count; ++index) {
        arguments[index + 2U] = client_arguments[index];
    }
    arguments[argument_count + 2U] = NULL;
    int child_result = spawn_and_wait(kWorkerPath, arguments,
                                      timeout_msec,
                                      &result.child_pid,
                                      &result.system_error);
    bool file_exact = managed_file_still_exact(&binding);
    close_managed_file(&binding);
    if (!file_exact) {
        result.status = CUSTOMD_STATUS_IDENTITY_CHANGED;
        result.system_error = ESTALE;
        result_message(&result, "Mach-O identity changed during run");
        return result;
    }
    if (child_result == 0) {
        result.status = CUSTOMD_STATUS_OK;
        result_message(&result, "ran %s successfully", binding.path);
    } else if (child_result < 0 && result.system_error == ETIMEDOUT) {
        result.status = CUSTOMD_STATUS_TIMEOUT;
        result_message(&result, "run timed out for %s", binding.path);
    } else {
        result.status = CUSTOMD_STATUS_CHILD_FAILED;
        result_message(&result, "worker failed status=%d for %s",
                       child_result, binding.path);
    }
    return result;
}

static struct operation_result run_macho(char *const client_arguments[],
                                         uint32_t argument_count) {
    return run_macho_with_timeout(client_arguments, argument_count,
                                  CUSTOMD_RUN_TIMEOUT_MSEC);
}

static struct operation_result activate_springboard(void) {
    char *arguments[] = {
        (char *)kPrecursorPath,
        (char *)"--external-live-proof",
        NULL,
    };
    struct operation_result result = run_macho_with_timeout(
        arguments, 2U, CUSTOMD_ACTIVATE_TIMEOUT_MSEC);
    if (result.status == CUSTOMD_STATUS_OK) {
        result_message(&result,
                       "SpringBoard activation committed via fixed precursor");
    } else {
        char detail[CUSTOMD_MAX_MESSAGE] = {0};
        (void)snprintf(detail, sizeof(detail), "%s", result.message);
        result_message(&result, "SpringBoard activation failed: %.900s",
                       detail);
    }
    return result;
}

static struct operation_result inject_springboard(
    const char *requested_path) {
    struct process_identity springboard = {0};
    if (!bind_unique_springboard(&springboard)) {
        struct operation_result result = {
            .status = CUSTOMD_STATUS_NO_PROCESS,
            .system_error = errno,
            .child_pid = -1,
        };
        result_message(&result,
                       "exact unique SpringBoard process is unavailable");
        return result;
    }
    return inject_dylib(springboard.pid, requested_path);
}

static bool parse_arguments(uint8_t *payload, uint32_t payload_size,
                            uint32_t argument_count,
                            char *arguments[CUSTOMD_MAX_ARGUMENTS]) {
    if (argument_count == 0) {
        return payload_size == 0;
    }
    if (argument_count > CUSTOMD_MAX_ARGUMENTS || payload_size == 0) {
        return false;
    }
    size_t offset = 0;
    for (uint32_t index = 0; index < argument_count; ++index) {
        if (offset >= payload_size) {
            return false;
        }
        void *terminator = memchr(payload + offset, '\0', payload_size - offset);
        if (terminator == NULL) {
            return false;
        }
        arguments[index] = (char *)(payload + offset);
        size_t length = (size_t)((uint8_t *)terminator - (payload + offset));
        if (index == 0 && length == 0) {
            return false;
        }
        offset += length + 1U;
    }
    return offset == payload_size;
}

static bool send_response(int client, const struct customd_request *request,
                          const struct operation_result *result) {
    size_t message_size = strnlen(result->message, sizeof(result->message));
    struct customd_response response = {
        .magic = CUSTOMD_PROTOCOL_MAGIC,
        .version = CUSTOMD_PROTOCOL_VERSION,
        .operation = request->operation,
        .request_id = request->request_id,
        .status = result->status,
        .system_error = result->system_error,
        .csflags_before = result->before,
        .csflags_after = result->after,
        .child_pid = result->child_pid,
        .message_size = (uint32_t)message_size,
        .daemon_pid = (uint64_t)getpid(),
    };
    return write_all(client, &response, sizeof(response)) &&
           (message_size == 0 ||
            write_all(client, result->message, message_size));
}

static void handle_client(int client) {
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof(timeout));
    (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                     sizeof(timeout));
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    (void)setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                     sizeof(no_sigpipe));
#endif

    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    pid_t peer_pid = -1;
    socklen_t peer_pid_size = sizeof(peer_pid);
    bool credential_valid = getpeereid(client, &peer_uid, &peer_gid) == 0 &&
                            peer_uid == 0;
#if defined(SOL_LOCAL) && defined(LOCAL_PEERPID)
    bool pid_valid = getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peer_pid,
                                &peer_pid_size) == 0 &&
                     peer_pid > 1;
#else
    bool pid_valid = false;
#endif
    char peer_path[PATH_MAX] = {0};
    bool peer_path_valid = pid_valid &&
                           proc_pidpath(peer_pid, peer_path,
                                        sizeof(peer_path)) > 0;

    struct customd_request request = {0};
    if (!read_all(client, &request, sizeof(request))) {
        log_message("short request uid=%u pid=%d", peer_uid, peer_pid);
        return;
    }
    struct operation_result result = {
        .status = CUSTOMD_STATUS_BAD_REQUEST,
        .child_pid = -1,
    };
    if (!credential_valid || !pid_valid || !peer_path_valid) {
        result.status = CUSTOMD_STATUS_UNAUTHORIZED;
        result.system_error = EACCES;
        result_message(&result, "root peer credentials are required");
        (void)send_response(client, &request, &result);
        log_message("denied uid=%u gid=%u pid=%d path=%s", peer_uid,
                    peer_gid, peer_pid,
                    peer_path_valid ? peer_path : "<unknown>");
        return;
    }
    if (request.magic != CUSTOMD_PROTOCOL_MAGIC ||
        request.version != CUSTOMD_PROTOCOL_VERSION || request.reserved != 0 ||
        request.payload_size > CUSTOMD_MAX_PAYLOAD ||
        request.argument_count > CUSTOMD_MAX_ARGUMENTS) {
        result_message(&result, "invalid protocol header");
        (void)send_response(client, &request, &result);
        return;
    }

    uint8_t *payload = NULL;
    if (request.payload_size != 0) {
        payload = calloc(1, request.payload_size);
        if (payload == NULL ||
            !read_all(client, payload, request.payload_size)) {
            free(payload);
            result.status = CUSTOMD_STATUS_INTERNAL;
            result.system_error = payload == NULL ? ENOMEM : errno;
            result_message(&result, "cannot read request payload");
            (void)send_response(client, &request, &result);
            return;
        }
    }
    char *arguments[CUSTOMD_MAX_ARGUMENTS] = {0};
    bool arguments_valid =
        parse_arguments(payload, request.payload_size,
                        request.argument_count, arguments);
    if (!arguments_valid) {
        result_message(&result, "invalid argument encoding");
    } else if (request.operation == CUSTOMD_OPERATION_STATUS &&
               request.target_pid == 0 && request.argument_count == 0) {
        uint32_t flags = 0;
        int flags_result =
            csops(getpid(), CUSTOMD_CS_OPS_STATUS, &flags, sizeof(flags));
        result.status = flags_result == 0 ? CUSTOMD_STATUS_OK
                                          : CUSTOMD_STATUS_INTERNAL;
        result.system_error = flags_result == 0 ? 0 : errno;
        result.after = flags;
        result_message(&result,
                       "ready host-parent=%d debugged=%d modules=%zu socket=%s",
                       gHostParent, (flags & CUSTOMD_CS_DEBUGGED) != 0,
                       gLoadedModuleCount, CUSTOMD_SOCKET_PATH);
    } else if (request.operation == CUSTOMD_OPERATION_JIT &&
               request.argument_count == 0) {
        result = jit_process(request.target_pid);
    } else if (request.operation == CUSTOMD_OPERATION_INJECT &&
               request.argument_count == 1) {
        result = inject_dylib(request.target_pid, arguments[0]);
    } else if (request.operation == CUSTOMD_OPERATION_RUN &&
               request.target_pid == 0 && request.argument_count > 0) {
        result = run_macho(arguments, request.argument_count);
    } else if (request.operation == CUSTOMD_OPERATION_LOAD &&
               request.target_pid == 0 && request.argument_count == 1) {
        result = load_module(arguments[0]);
    } else if (request.operation ==
                   CUSTOMD_OPERATION_ACTIVATE_SPRINGBOARD &&
               request.target_pid == 0 && request.argument_count == 0) {
        result = activate_springboard();
    } else if (request.operation ==
                   CUSTOMD_OPERATION_INJECT_SPRINGBOARD &&
               request.target_pid == 0 && request.argument_count == 1) {
        result = inject_springboard(arguments[0]);
    } else if (request.operation == CUSTOMD_OPERATION_ENSURE_CANDIDATE &&
               request.target_pid == 0 && request.argument_count == 0) {
        result = ensure_candidate();
    } else if (request.operation == CUSTOMD_OPERATION_TRACE_REEXEC_PROBE &&
               request.target_pid == 0 && request.argument_count == 0) {
        result = reexec_probe(false);
    } else if (request.operation == CUSTOMD_OPERATION_SETEXEC_REEXEC_PROBE &&
               request.target_pid == 0 && request.argument_count == 0) {
        result = reexec_probe(true);
    } else if (request.operation ==
                   CUSTOMD_OPERATION_REEXEC_INJECT_SPRINGBOARD &&
               request.target_pid == 0 && request.argument_count == 1) {
        result = reexec_inject_springboard(arguments[0]);
    } else {
        result_message(&result, "invalid operation shape");
    }

    log_message("request=%llu op=%u peer=%d path=%s target=%d status=%d "
                "errno=%d before=0x%08x after=0x%08x child=%d message=%s",
                request.request_id, request.operation, peer_pid, peer_path,
                request.target_pid, result.status, result.system_error,
                result.before, result.after, result.child_pid,
                result.message);
    (void)send_response(client, &request, &result);
    free(payload);
}

static bool ensure_directory(const char *path, mode_t mode) {
    struct stat status = {0};
    if (lstat(path, &status) == 0) {
        if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
            errno = ENOTDIR;
            return false;
        }
    } else if (errno == ENOENT) {
        if (mkdir(path, mode) != 0) {
            return false;
        }
    } else {
        return false;
    }
    return chown(path, 0, 0) == 0 && chmod(path, mode) == 0;
}

static int create_server_socket(void) {
    mode_t old_mask = umask(077);
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    umask(old_mask);
    if (descriptor < 0) {
        return -1;
    }
    set_close_on_exec(descriptor);
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    (void)setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                     sizeof(no_sigpipe));
#endif
    struct stat existing = {0};
    if (lstat(CUSTOMD_SOCKET_PATH, &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid != 0) {
            close(descriptor);
            errno = EEXIST;
            return -1;
        }
        if (unlink(CUSTOMD_SOCKET_PATH) != 0) {
            close(descriptor);
            return -1;
        }
    } else if (errno != ENOENT) {
        close(descriptor);
        return -1;
    }

    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(CUSTOMD_SOCKET_PATH) >= sizeof(address.sun_path)) {
        close(descriptor);
        errno = ENAMETOOLONG;
        return -1;
    }
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                   CUSTOMD_SOCKET_PATH);
    if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chown(CUSTOMD_SOCKET_PATH, 0, 0) != 0 ||
        chmod(CUSTOMD_SOCKET_PATH, 0600) != 0 ||
        listen(descriptor, 8) != 0) {
        int saved_error = errno;
        close(descriptor);
        (void)unlink(CUSTOMD_SOCKET_PATH);
        errno = saved_error;
        return -1;
    }
    return descriptor;
}

static void stop_handler(int signal_number) {
    (void)signal_number;
    gStopping = 1;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    setlinebuf(stdout);
    setlinebuf(stderr);
    (void)signal(SIGPIPE, SIG_IGN);
    (void)signal(SIGTERM, stop_handler);
    (void)signal(SIGINT, stop_handler);

    uint32_t self_flags = 0;
    gHostParent = getppid();
    if (geteuid() != 0 || gHostParent <= 1 ||
        !copy_unique_info(gHostParent, &gHostParentIdentity) ||
        csops(getpid(), CUSTOMD_CS_OPS_STATUS, &self_flags,
              sizeof(self_flags)) != 0 ||
        (self_flags & CUSTOMD_CS_DEBUGGED) == 0 ||
        (self_flags & (CUSTOMD_CS_HARD | CUSTOMD_CS_KILL)) != 0) {
        log_message("refusing launch uid=%u parent=%d csflags=0x%08x errno=%d",
                    geteuid(), gHostParent, self_flags, errno);
        return 77;
    }
    if (!ensure_directory("/var/jb/var/run", 0755)) {
        log_message("run directory setup failed: %s", strerror(errno));
        return 73;
    }

    gLockDescriptor =
        open(kLockPath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    struct stat lock_status = {0};
    if (gLockDescriptor < 0 || fstat(gLockDescriptor, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        (lock_status.st_mode & 0022) != 0 ||
        flock(gLockDescriptor, LOCK_EX | LOCK_NB) != 0 ||
        fchown(gLockDescriptor, 0, 0) != 0 ||
        fchmod(gLockDescriptor, 0600) != 0) {
        log_message("singleton lock failed: %s", strerror(errno));
        if (gLockDescriptor >= 0) {
            close(gLockDescriptor);
        }
        return 73;
    }

    gServerDescriptor = create_server_socket();
    if (gServerDescriptor < 0) {
        log_message("socket setup failed: %s", strerror(errno));
        close(gLockDescriptor);
        return 74;
    }
    log_message("ready socket=%s uid=%u parent=%d csflags=0x%08x",
                CUSTOMD_SOCKET_PATH, geteuid(), gHostParent, self_flags);

    while (!gStopping && host_parent_alive()) {
        struct pollfd poll_descriptor = {
            .fd = gServerDescriptor,
            .events = POLLIN,
        };
        int poll_result = poll(&poll_descriptor, 1, 1000);
        if (poll_result < 0 && errno == EINTR) {
            continue;
        }
        if (poll_result < 0) {
            log_message("poll failed: %s", strerror(errno));
            break;
        }
        if (poll_result == 0) {
            continue;
        }
        if ((poll_descriptor.revents & POLLIN) != 0) {
            int client = accept(gServerDescriptor, NULL, NULL);
            if (client < 0 && errno == EINTR) {
                continue;
            }
            if (client < 0) {
                log_message("accept failed: %s", strerror(errno));
                break;
            }
            set_close_on_exec(client);
            handle_client(client);
            close(client);
        }
        if ((poll_descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            log_message("server socket revents=0x%x", poll_descriptor.revents);
            break;
        }
    }

    log_message("stopping requested=%d parent-alive=%d", gStopping,
                host_parent_alive());
    close(gServerDescriptor);
    (void)unlink(CUSTOMD_SOCKET_PATH);
    close(gLockDescriptor);
    return 0;
}
