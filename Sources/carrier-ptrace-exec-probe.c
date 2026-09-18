#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <mach/vm_region.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CODEX_PT_DETACH 11
#define CODEX_PT_CONTINUE 7
#define CODEX_PT_KILL 8
#define CODEX_PT_ATTACHEXC 14
#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_OPS_CDHASH 5
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_CDHASH_SIZE 20U
#define CODEX_PROC_PIDTBSDINFO 3
#define CODEX_PROC_PIDUNIQIDENTIFIERINFO 17
#define CODEX_MAXCOMLEN 16
#define CODEX_PATH_SIZE 4096U

#ifndef CODEX_DIRECT_SPRINGBOARD_PROOF
#define CODEX_DIRECT_SPRINGBOARD_PROOF 0
#endif

#ifndef CODEX_CARRIER_PATH
#define CODEX_CARRIER_PATH "/var/jb/usr/lib/codex-runtime-carrier.dylib"
#endif

#ifndef CODEX_LOG_PATH
#define CODEX_LOG_PATH "/var/tmp/codex-carrier-ptrace-exec-probe.log"
#endif

#if CODEX_DIRECT_SPRINGBOARD_PROOF
static const uint8_t kLoaderUUID[16] = {
    0xad, 0x93, 0x7f, 0xb7, 0x26, 0x64, 0x3b, 0x8f,
    0xb1, 0xc9, 0x34, 0xc4, 0xad, 0x40, 0x92, 0xd2,
};
static const uint8_t kExpectedCandidateCDHash[CODEX_CDHASH_SIZE] = {
    0x12, 0xfe, 0xd0, 0xfd, 0x1d, 0xbb, 0xa6, 0xda, 0x84, 0x90,
    0x4f, 0xb4, 0xc3, 0x63, 0xd0, 0x7c, 0xb6, 0xf5, 0x13, 0x44,
};
static const uint8_t kExpectedCandidateSHA256[CC_SHA256_DIGEST_LENGTH] = {
    0xdb, 0x2d, 0x73, 0xa6, 0x17, 0x39, 0x41, 0x7c,
    0x14, 0x35, 0x9d, 0xb4, 0x41, 0x5a, 0xc5, 0xeb,
    0x0c, 0xc5, 0x9f, 0x86, 0x61, 0x1c, 0x15, 0x8e,
    0x74, 0x13, 0xd9, 0x7b, 0x04, 0x58, 0xb5, 0x5c,
};
static const uint8_t kExpectedPayloadSHA256[CC_SHA256_DIGEST_LENGTH] = {
    0x82, 0x3f, 0x17, 0x1b, 0x28, 0x0e, 0x99, 0x52,
    0x8c, 0x1a, 0xdd, 0x88, 0x94, 0x0d, 0x19, 0x12,
    0x94, 0xab, 0xaa, 0x29, 0x2f, 0xf0, 0x3a, 0x17,
    0x9c, 0xee, 0x63, 0x7e, 0x01, 0x82, 0xba, 0xf5,
};
static const uint8_t kExpectedSpringBoardMainPrefix[20] = {
    0x01, 0x00, 0x00, 0x14, 0x31, 0x00, 0x00, 0x90,
    0x31, 0x22, 0x00, 0x91, 0x30, 0x02, 0x40, 0xf9,
    0x11, 0x0a, 0x1f, 0xd7,
};
static const uint8_t kExpectedPayloadUUID[16] = {
    0xec, 0x8c, 0x70, 0x5a, 0xc8, 0x85, 0x3e, 0xd2,
    0x83, 0xac, 0xc3, 0x7a, 0xc4, 0xae, 0x3f, 0x98,
};
#else
static const uint8_t kLoaderUUID[16] = {
    0xdb, 0x09, 0xbb, 0x43, 0xf2, 0x8e, 0x3e, 0x2d,
    0xb4, 0x97, 0x95, 0x06, 0xc5, 0x0d, 0x15, 0x02,
};
#endif
static const uint8_t kMmapPattern[8] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
static const uint8_t kFcntlPattern[8] = {
    0x90, 0x0b, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};

extern char **environ;
extern int csops(pid_t, unsigned int, void *, size_t);
extern int proc_listallpids(void *, int);
extern int proc_pidinfo(int, int, uint64_t, void *, int);
extern int proc_pidpath(int, void *, uint32_t);
extern int ptrace(int, pid_t, caddr_t, int);
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
extern kern_return_t mach_vm_region_recurse(
    vm_map_t, mach_vm_address_t *, mach_vm_size_t *, natural_t *,
    vm_region_recurse_info_t, mach_msg_type_number_t *);

extern const uint8_t codex_remote_blob_start[];
extern const uint8_t codex_remote_stop_gate[];
extern const uint8_t codex_remote_entry[];
extern const uint8_t codex_remote_mmap_hook[];
extern const uint8_t codex_remote_fcntl_hook[];
extern const uint8_t codex_remote_context_pointer[];
extern const uint8_t codex_remote_blob_end[];

struct codex_remote_context {
    uint64_t dlopen_address;
    volatile uint32_t status;
    uint32_t reserved;
    uint64_t handle;
    char path[PATH_MAX];
};

#if CODEX_DIRECT_SPRINGBOARD_PROOF
static const char *const kLoaderPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kStockPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kAcceptanceNonce =
    "20260918T015615Z-0d282c34d13467d6";
#else
static const char *const kLoaderPath =
    "/var/jb/usr/libexec/codex-ellekit-loader";
#endif
static const char *const kCarrierPath = CODEX_CARRIER_PATH;
static const char *const kLogPath = CODEX_LOG_PATH;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
static const char *const kMarkerPath =
    "/var/tmp/codex-springboard-direct-live-canary.marker";
#else
static const char *const kMarkerPath =
    "/var/tmp/codex-runtime-carrier.loaded";
#endif

static int gLog = STDERR_FILENO;
static volatile sig_atomic_t gChild = -1;

#if CODEX_DIRECT_SPRINGBOARD_PROOF
struct codex_proc_uniqidentifierinfo {
    uint8_t uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_pid_version;
    uint64_t reserved2;
    uint64_t reserved3;
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

struct codex_direct_process_snapshot {
    pid_t pid;
    struct codex_proc_bsdinfo bsd;
    struct codex_proc_uniqidentifierinfo unique;
    uint32_t cs_flags;
    uint8_t cdhash[CODEX_CDHASH_SIZE];
};

_Static_assert(sizeof(struct codex_proc_uniqidentifierinfo) == 56,
               "proc unique identifier ABI mismatch");
_Static_assert(sizeof(struct codex_proc_bsdinfo) == 136,
               "proc bsd info ABI mismatch");

static struct codex_direct_process_snapshot gStockSnapshot = {0};
static char gLoaderRealPath[CODEX_PATH_SIZE] = {0};
static char gPayloadRealPath[CODEX_PATH_SIZE] = {0};
#endif

static void probe_log(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    (void)vdprintf(gLog, format, arguments);
    va_end(arguments);
    (void)fsync(gLog);
}

#if CODEX_DIRECT_SPRINGBOARD_PROOF
static bool direct_copy_path(pid_t pid, char path[CODEX_PATH_SIZE]) {
    memset(path, 0, CODEX_PATH_SIZE);
    int length = proc_pidpath(pid, path, CODEX_PATH_SIZE);
    return pid > 1 && length > 0 && (size_t)length < CODEX_PATH_SIZE;
}

static bool direct_copy_unique(
    pid_t pid, struct codex_proc_uniqidentifierinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information);
}

static bool direct_copy_bsd(pid_t pid,
                            struct codex_proc_bsdinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDTBSDINFO, 0, information,
                              (int)sizeof(*information));
    return amount == (int)sizeof(*information) &&
        information->pbi_pid == (uint32_t)pid;
}

static bool direct_unique_equal(
    const struct codex_proc_uniqidentifierinfo *left,
    const struct codex_proc_uniqidentifierinfo *right) {
    return left->unique_id == right->unique_id &&
        left->pid_version == right->pid_version &&
        left->parent_unique_id == right->parent_unique_id &&
        memcmp(left->uuid, right->uuid, sizeof(left->uuid)) == 0;
}

static bool direct_loader_path_exact(const char *path) {
    return path != NULL &&
        (strcmp(path, kLoaderPath) == 0 ||
         (gLoaderRealPath[0] != '\0' &&
          strcmp(path, gLoaderRealPath) == 0));
}

static int direct_list_all_pids(pid_t **pids_out) {
    *pids_out = NULL;
    int requested = proc_listallpids(NULL, 0);
    if (requested <= 0 || requested > 131072) {
        return -1;
    }
    int capacity = requested + 128;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return -1;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    if (count <= 0 || count >= capacity) {
        free(pids);
        return -1;
    }
    *pids_out = pids;
    return count;
}

static bool direct_count_processes(int *stock_count, pid_t *stock_pid,
                                   int *candidate_count) {
    *stock_count = 0;
    *stock_pid = -1;
    *candidate_count = 0;
    pid_t *pids = NULL;
    int count = direct_list_all_pids(&pids);
    if (count < 0) {
        return false;
    }
    for (int index = 0; index < count; ++index) {
        if (pids[index] <= 1) {
            continue;
        }
        char path[CODEX_PATH_SIZE] = {0};
        if (!direct_copy_path(pids[index], path)) {
            continue;
        }
        if (strcmp(path, kStockPath) == 0 &&
            pids[index] == gStockSnapshot.pid) {
            ++*stock_count;
            *stock_pid = pids[index];
        } else if (direct_loader_path_exact(path)) {
            ++*candidate_count;
        }
    }
    free(pids);
    return true;
}

static bool direct_read_stock(
    pid_t pid, struct codex_direct_process_snapshot *snapshot) {
    if (pid <= 1 || snapshot == NULL) {
        return false;
    }
    char first_path[CODEX_PATH_SIZE] = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    struct codex_proc_uniqidentifierinfo first_unique = {0};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    struct codex_proc_bsdinfo bsd = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    bool valid = direct_copy_path(pid, first_path) &&
        strcmp(first_path, kStockPath) == 0 &&
        direct_copy_bsd(pid, &bsd) && bsd.pbi_uid == 501 &&
        bsd.pbi_ppid == 1 &&
        direct_copy_unique(pid, &first_unique) &&
        memcmp(first_unique.uuid, kLoaderUUID, sizeof(kLoaderUUID)) == 0 &&
        csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
        (flags & CODEX_CS_VALID) != 0 &&
        csops(pid, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) == 0 &&
        memcmp(cdhash, kExpectedCandidateCDHash, sizeof(cdhash)) == 0 &&
        direct_copy_path(pid, second_path) &&
        strcmp(first_path, second_path) == 0 &&
        direct_copy_unique(pid, &second_unique) &&
        direct_unique_equal(&first_unique, &second_unique);
    if (!valid) {
        return false;
    }
    snapshot->pid = pid;
    snapshot->bsd = bsd;
    snapshot->unique = first_unique;
    snapshot->cs_flags = flags;
    memcpy(snapshot->cdhash, cdhash, sizeof(snapshot->cdhash));
    return true;
}

static bool direct_stock_still_exact(int expected_candidate_count) {
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    struct codex_direct_process_snapshot current = {0};
    return gStockSnapshot.pid > 1 &&
        direct_count_processes(&stock_count, &stock_pid, &candidate_count) &&
        stock_count == 1 && stock_pid == gStockSnapshot.pid &&
        candidate_count == expected_candidate_count &&
        direct_read_stock(stock_pid, &current) &&
        current.pid == gStockSnapshot.pid &&
        direct_unique_equal(&current.unique, &gStockSnapshot.unique) &&
        current.cs_flags == gStockSnapshot.cs_flags &&
        memcmp(current.cdhash, gStockSnapshot.cdhash,
               sizeof(current.cdhash)) == 0;
}

static bool direct_stock_settles_exact(unsigned int milliseconds) {
    unsigned int attempts = milliseconds / 10U;
    for (unsigned int attempt = 0; attempt < attempts; ++attempt) {
        if (!direct_stock_still_exact(0)) {
            return false;
        }
        usleep(10U * 1000U);
    }
    return direct_stock_still_exact(0);
}

static bool direct_candidate_exact(pid_t child) {
    char path[CODEX_PATH_SIZE] = {0};
    struct codex_proc_uniqidentifierinfo unique = {0};
    struct codex_proc_bsdinfo bsd = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    return child > 1 && direct_copy_path(child, path) &&
        direct_loader_path_exact(path) && direct_copy_bsd(child, &bsd) &&
        bsd.pbi_uid == 0 && bsd.pbi_ppid == (uint32_t)getpid() &&
        direct_copy_unique(child, &unique) &&
        memcmp(unique.uuid, kLoaderUUID, sizeof(kLoaderUUID)) == 0 &&
        csops(child, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
        (flags & (CODEX_CS_VALID | CODEX_CS_DEBUGGED)) ==
            (CODEX_CS_VALID | CODEX_CS_DEBUGGED) &&
        csops(child, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) == 0 &&
        memcmp(cdhash, kExpectedCandidateCDHash, sizeof(cdhash)) == 0;
}

static bool direct_sha256_descriptor(
    int descriptor, uint8_t digest[CC_SHA256_DIGEST_LENGTH]) {
    CC_SHA256_CTX context;
    if (CC_SHA256_Init(&context) != 1) {
        return false;
    }
    uint8_t buffer[64U * 1024U];
    off_t offset = 0;
    for (;;) {
        ssize_t amount = pread(descriptor, buffer, sizeof(buffer), offset);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0) {
            return false;
        }
        if (amount == 0) {
            break;
        }
        if (CC_SHA256_Update(&context, buffer, (CC_LONG)amount) != 1) {
            return false;
        }
        offset += amount;
    }
    return CC_SHA256_Final(digest, &context) == 1;
}

static void direct_format_hex(const uint8_t *bytes, size_t size,
                              char *output, size_t output_size) {
    static const char alphabet[] = "0123456789abcdef";
    if (output_size < size * 2U + 1U) {
        if (output_size != 0) {
            output[0] = '\0';
        }
        return;
    }
    for (size_t index = 0; index < size; ++index) {
        output[index * 2U] = alphabet[bytes[index] >> 4U];
        output[index * 2U + 1U] = alphabet[bytes[index] & 0x0fU];
    }
    output[size * 2U] = '\0';
}

static bool direct_secure_file(
    const char *path, off_t expected_size, bool executable,
    const uint8_t expected_digest[CC_SHA256_DIGEST_LENGTH]) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int open_error = descriptor >= 0 ? 0 : errno;
    struct stat information = {0};
    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    bool stat_ok = descriptor >= 0 && fstat(descriptor, &information) == 0;
    bool hashed = stat_ok && direct_sha256_descriptor(descriptor, digest);
    bool valid = stat_ok &&
        S_ISREG(information.st_mode) && information.st_uid == 0 &&
        information.st_size == expected_size &&
        (information.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        (!executable || (information.st_mode & 0111) != 0) &&
        hashed &&
        memcmp(digest, expected_digest, sizeof(digest)) == 0;
    char digest_text[CC_SHA256_DIGEST_LENGTH * 2U + 1U] = {0};
    direct_format_hex(digest, sizeof(digest), digest_text,
                      sizeof(digest_text));
    probe_log("phase=file-preflight path=%s openErrno=%d stat=%d "
              "mode=%o uid=%u size=%lld hashed=%d sha256=%s exact=%d\n",
              path, open_error, stat_ok, information.st_mode & 07777,
              information.st_uid, (long long)information.st_size, hashed,
              digest_text, valid);
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    return valid;
}

static bool direct_preflight_files(void) {
    struct stat marker_directory = {0};
    bool loader_real = realpath(kLoaderPath, gLoaderRealPath) != NULL &&
        gLoaderRealPath[0] == '/' &&
        strcmp(gLoaderRealPath, kStockPath) == 0;
    bool payload_real = realpath(kCarrierPath, gPayloadRealPath) != NULL &&
        gPayloadRealPath[0] == '/';
    bool loader_secure = direct_secure_file(
        kLoaderPath, 139712, true, kExpectedCandidateSHA256);
    bool payload_secure = direct_secure_file(
        kCarrierPath, 50576, false, kExpectedPayloadSHA256);
    bool marker_directory_secure =
        lstat("/var/tmp", &marker_directory) == 0 &&
        S_ISDIR(marker_directory.st_mode) && marker_directory.st_uid == 0 &&
        (marker_directory.st_mode & S_ISVTX) != 0;
    probe_log("phase=path-preflight loaderReal=%d loaderPath=%s "
              "payloadReal=%d payloadPath=%s tempDir=%d tempMode=%o "
              "tempUid=%u\n",
              loader_real, gLoaderRealPath, payload_real, gPayloadRealPath,
              marker_directory_secure, marker_directory.st_mode & 07777,
              marker_directory.st_uid);
    return loader_real && payload_real && loader_secure && payload_secure &&
        marker_directory_secure;
}

static bool direct_clear_marker(void) {
    struct stat information = {0};
    if (lstat(kMarkerPath, &information) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISREG(information.st_mode) || information.st_uid != 0 ||
        information.st_nlink != 1 ||
        (information.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }
    return unlink(kMarkerPath) == 0;
}
#endif

static void terminate_child(pid_t child) {
    if (child <= 1) {
        return;
    }
    (void)kill(child, SIGKILL);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
}

#if CODEX_DIRECT_SPRINGBOARD_PROOF
static bool terminate_traced_child(pid_t child, int *terminal_status,
                                   int *ptrace_result,
                                   int *ptrace_error) {
    if (child <= 1 || child != gChild) {
        return false;
    }
    errno = 0;
    *ptrace_result = ptrace(CODEX_PT_KILL, child, NULL, 0);
    *ptrace_error = *ptrace_result == 0 ? 0 : errno;
    (void)kill(child, SIGKILL);
    for (;;) {
        errno = 0;
        pid_t waited = waitpid(child, terminal_status, 0);
        if (waited == child &&
            (WIFEXITED(*terminal_status) || WIFSIGNALED(*terminal_status))) {
            gChild = -1;
            return true;
        }
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        if (waited == child && WIFSTOPPED(*terminal_status)) {
            (void)kill(child, SIGKILL);
            continue;
        }
        if (waited < 0 && errno == ECHILD) {
            errno = 0;
            if (kill(child, 0) != 0 && errno == ESRCH) {
                gChild = -1;
                return true;
            }
        }
        return false;
    }
}

static void direct_terminate_owned_child_at_exit(void) {
    pid_t child = (pid_t)gChild;
    if (child <= 1) {
        return;
    }
    for (unsigned int attempt = 0; attempt < 500; ++attempt) {
        (void)kill(child, SIGKILL);
        int status = 0;
        errno = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child &&
            (WIFEXITED(status) || WIFSIGNALED(status))) {
            gChild = -1;
            return;
        }
        if (waited < 0 && errno == ECHILD) {
            errno = 0;
            if (kill(child, 0) != 0 && errno == ESRCH) {
                gChild = -1;
                return;
            }
        }
        usleep(2U * 1000U);
    }
}
#endif

static void timeout_handler(int signal_number) {
    (void)signal_number;
    pid_t child = (pid_t)gChild;
    if (child > 1) {
        (void)kill(child, SIGKILL);
    }
    _exit(124);
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

static mach_vm_address_t find_remote_image(
    mach_port_t task, mach_vm_address_t all_image_info,
    const char *expected_path, mach_vm_address_t *dyld_header) {
    struct dyld_all_image_infos infos = {0};
    if (read_remote(task, all_image_info, &infos, sizeof(infos)) !=
            KERN_SUCCESS ||
        infos.infoArrayCount == 0 || infos.infoArrayCount > 4096) {
        return 0;
    }
    if (dyld_header != NULL) {
        *dyld_header = canonical_remote_address(
            (uint64_t)infos.dyldImageLoadAddress);
    }
    mach_vm_address_t info_array = canonical_remote_address(
        (uint64_t)infos.infoArray);
    size_t array_size =
        (size_t)infos.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *images = malloc(array_size);
    if (images == NULL ||
        read_remote(task, info_array, images, array_size) != KERN_SUCCESS) {
        free(images);
        return 0;
    }
    mach_vm_address_t result = 0;
    for (uint32_t index = 0; index < infos.infoArrayCount; ++index) {
        char path[PATH_MAX];
        if (read_remote_path(
                task, (mach_vm_address_t)(uintptr_t)images[index].imageFilePath,
                path) &&
            strcmp(path, expected_path) == 0) {
            result = canonical_remote_address(
                (uint64_t)images[index].imageLoadAddress);
            break;
        }
    }
    free(images);
    return result;
}

#if CODEX_DIRECT_SPRINGBOARD_PROOF
static bool remote_image_uuid_matches(mach_port_t task,
                                      mach_vm_address_t image,
                                      const uint8_t expected[16]) {
    struct mach_header_64 header = {0};
    if (image == 0 ||
        read_remote(task, image, &header, sizeof(header)) != KERN_SUCCESS ||
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
    bool found = false;
    size_t offset = 0;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        if (offset > header.sizeofcmds - sizeof(struct load_command)) {
            break;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > header.sizeofcmds - offset) {
            break;
        }
        if (command->cmd == LC_UUID &&
            command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid =
                (const struct uuid_command *)command;
            if (found) {
                matched = false;
                break;
            }
            found = true;
            matched = memcmp(uuid->uuid, expected, 16) == 0;
        }
        offset += command->cmdsize;
    }
    free(commands);
    return found && matched;
}
#endif

static mach_vm_address_t find_remote_symbol(mach_port_t task,
                                            mach_vm_address_t image,
                                            const char *symbol_name) {
    struct mach_header_64 header = {0};
    if (read_remote(task, image, &header, sizeof(header)) != KERN_SUCCESS ||
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
    struct segment_command_64 linkedit = {0};
    struct symtab_command symtab = {0};
    uint64_t slide = 0;
    bool have_slide = false;
    size_t offset = 0;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        if (offset + sizeof(struct load_command) > header.sizeofcmds) {
            break;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(*command) ||
            offset + command->cmdsize > header.sizeofcmds) {
            break;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (!have_slide) {
                slide = image - segment->vmaddr;
                have_slide = true;
            }
            if (strncmp(segment->segname, SEG_LINKEDIT,
                        sizeof(segment->segname)) == 0) {
                linkedit = *segment;
            }
        } else if (command->cmd == LC_SYMTAB &&
                   command->cmdsize >= sizeof(struct symtab_command)) {
            symtab = *(const struct symtab_command *)command;
        }
        offset += command->cmdsize;
    }
    free(commands);
    if (!have_slide || linkedit.cmd != LC_SEGMENT_64 ||
        symtab.cmd != LC_SYMTAB || symtab.nsyms == 0 ||
        symtab.nsyms > 4U * 1024U * 1024U || symtab.strsize == 0 ||
        symtab.strsize > 64U * 1024U * 1024U) {
        return 0;
    }
    size_t symbols_size = (size_t)symtab.nsyms * sizeof(struct nlist_64);
    struct nlist_64 *symbols = malloc(symbols_size);
    char *strings = malloc(symtab.strsize);
    mach_vm_address_t linkedit_base =
        linkedit.vmaddr + slide - linkedit.fileoff;
    if (symbols == NULL || strings == NULL ||
        read_remote(task, linkedit_base + symtab.symoff, symbols,
                    symbols_size) != KERN_SUCCESS ||
        read_remote(task, linkedit_base + symtab.stroff, strings,
                    symtab.strsize) != KERN_SUCCESS) {
        free(symbols);
        free(strings);
        return 0;
    }
    mach_vm_address_t result = 0;
    for (uint32_t index = 0; index < symtab.nsyms; ++index) {
        uint32_t string_offset = symbols[index].n_un.n_strx;
        if (string_offset == 0 || string_offset >= symtab.strsize ||
            (symbols[index].n_type & N_STAB) != 0 ||
            (symbols[index].n_type & N_TYPE) != N_SECT) {
            continue;
        }
        size_t remaining = symtab.strsize - string_offset;
        const char *candidate = strings + string_offset;
        if (memchr(candidate, '\0', remaining) != NULL &&
            strcmp(candidate, symbol_name) == 0) {
            result = canonical_remote_address(symbols[index].n_value + slide);
            break;
        }
    }
    free(symbols);
    free(strings);
    return result;
}

static bool read_uleb128(const uint8_t *bytes, size_t size, size_t *cursor,
                         uint64_t *value) {
    uint64_t result = 0;
    unsigned int shift = 0;
    while (*cursor < size && shift < 64U) {
        uint8_t byte = bytes[(*cursor)++];
        result |= (uint64_t)(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0) {
            *value = result;
            return true;
        }
        shift += 7U;
    }
    return false;
}

static mach_vm_address_t find_remote_export(mach_port_t task,
                                            mach_vm_address_t image,
                                            const char *symbol_name) {
    struct mach_header_64 header = {0};
    if (read_remote(task, image, &header, sizeof(header)) != KERN_SUCCESS ||
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
    struct segment_command_64 linkedit = {0};
    uint32_t export_offset = 0;
    uint32_t export_size = 0;
    uint64_t slide = 0;
    bool have_slide = false;
    size_t offset = 0;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        if (offset + sizeof(struct load_command) > header.sizeofcmds) {
            break;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(*command) ||
            offset + command->cmdsize > header.sizeofcmds) {
            break;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (!have_slide) {
                slide = image - segment->vmaddr;
                have_slide = true;
            }
            if (strncmp(segment->segname, SEG_LINKEDIT,
                        sizeof(segment->segname)) == 0) {
                linkedit = *segment;
            }
        } else if ((command->cmd == LC_DYLD_INFO ||
                    command->cmd == LC_DYLD_INFO_ONLY) &&
                   command->cmdsize >= sizeof(struct dyld_info_command)) {
            const struct dyld_info_command *info =
                (const struct dyld_info_command *)command;
            export_offset = info->export_off;
            export_size = info->export_size;
        } else if (command->cmd == LC_DYLD_EXPORTS_TRIE &&
                   command->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *exports =
                (const struct linkedit_data_command *)command;
            export_offset = exports->dataoff;
            export_size = exports->datasize;
        }
        offset += command->cmdsize;
    }
    free(commands);
    if (!have_slide || linkedit.cmd != LC_SEGMENT_64 || export_offset == 0 ||
        export_size == 0 || export_size > 16U * 1024U * 1024U) {
        return 0;
    }
    mach_vm_address_t linkedit_base =
        linkedit.vmaddr + slide - linkedit.fileoff;
    uint8_t *trie = malloc(export_size);
    if (trie == NULL ||
        read_remote(task, linkedit_base + export_offset, trie, export_size) !=
            KERN_SUCCESS) {
        free(trie);
        return 0;
    }

    size_t symbol_length = strlen(symbol_name);
    size_t symbol_cursor = 0;
    size_t node_offset = 0;
    mach_vm_address_t result = 0;
    for (unsigned int depth = 0; depth < 256U; ++depth) {
        if (node_offset >= export_size) {
            break;
        }
        size_t cursor = node_offset;
        uint64_t terminal_size = 0;
        if (!read_uleb128(trie, export_size, &cursor, &terminal_size) ||
            terminal_size > export_size - cursor) {
            break;
        }
        size_t terminal_start = cursor;
        size_t children = cursor + (size_t)terminal_size;
        if (symbol_cursor == symbol_length && terminal_size != 0) {
            uint64_t flags = 0;
            uint64_t value = 0;
            size_t terminal_cursor = terminal_start;
            size_t terminal_end = children;
            if (read_uleb128(trie, terminal_end, &terminal_cursor, &flags) &&
                (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) == 0 &&
                read_uleb128(trie, terminal_end, &terminal_cursor, &value) &&
                value <= UINT64_MAX - image) {
                result = canonical_remote_address(image + value);
            }
            break;
        }
        if (children >= export_size) {
            break;
        }
        uint8_t child_count = trie[children++];
        bool matched = false;
        size_t next_node = 0;
        size_t matched_length = 0;
        for (uint8_t child = 0; child < child_count; ++child) {
            size_t edge_start = children;
            while (children < export_size && trie[children] != '\0') {
                ++children;
            }
            if (children >= export_size) {
                matched = false;
                break;
            }
            size_t edge_length = children - edge_start;
            ++children;
            uint64_t child_node = 0;
            if (!read_uleb128(trie, export_size, &children, &child_node)) {
                matched = false;
                break;
            }
            if (!matched && edge_length <= symbol_length - symbol_cursor &&
                memcmp(trie + edge_start, symbol_name + symbol_cursor,
                       edge_length) == 0 &&
                child_node < export_size) {
                matched = true;
                next_node = (size_t)child_node;
                matched_length = edge_length;
            }
        }
        if (!matched) {
            break;
        }
        symbol_cursor += matched_length;
        node_offset = next_node;
    }
    free(trie);
    return result;
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
                break;
            }
        }
        offset += command->cmdsize;
    }
    if (base_vm_address == 0) {
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
    words[4] = 0xd61f0200U; /* br x16 */
}

static bool remote_address_has_protection(mach_port_t task,
                                          mach_vm_address_t address,
                                          vm_prot_t required) {
    mach_vm_address_t region = address;
    natural_t depth = 0;
    for (unsigned int attempt = 0; attempt < 16; ++attempt) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t information = {0};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            task, &region, &size, &depth,
            (vm_region_recurse_info_t)&information, &count);
        if (result != KERN_SUCCESS || size == 0 || address < region ||
            address - region >= size) {
            return false;
        }
        if (information.is_submap) {
            ++depth;
            region = address;
            continue;
        }
        return (information.protection & required) == required;
    }
    return false;
}

static bool write_executable_bytes(mach_port_t task,
                                   mach_vm_address_t address,
                                   const void *bytes, size_t size) {
    mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    if (page_size == 0 || size == 0 || address > UINT64_MAX - size) {
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
        remote_address_has_protection(
            task, address, VM_PROT_READ | VM_PROT_EXECUTE) &&
        read_remote(task, address, readback, size) == KERN_SUCCESS &&
        memcmp(readback, bytes, size) == 0;
    free(readback);
    return verified;
}

static bool carrier_file_is_secure(void) {
    struct stat info = {0};
    return lstat(kCarrierPath, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_uid == 0 && (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        info.st_size > 0 && info.st_size <= 16 * 1024 * 1024;
}

static bool marker_matches_child(pid_t child, int *startup_result) {
    *startup_result = -1;
    int descriptor = open(kMarkerPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info = {0};
    char text[512] = {0};
    ssize_t amount = descriptor >= 0 ? read(descriptor, text,
                                             sizeof(text) - 1U)
                                     : -1;
    bool secure = descriptor >= 0 && fstat(descriptor, &info) == 0 &&
        S_ISREG(info.st_mode) && info.st_uid == 0 &&
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        info.st_nlink == 1 && (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
#else
        (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
#endif
        info.st_size > 0 && info.st_size < (off_t)sizeof(text) &&
        amount == info.st_size;
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    if (!secure) {
        return false;
    }
    text[amount] = '\0';
    int marker_pid = -1;
    unsigned int uid = UINT_MAX;
    unsigned int euid = UINT_MAX;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    char nonce[128] = {0};
    int consumed = -1;
    int fields = sscanf(
        text,
        "constructor=entered nonce=%127s pid=%d uid=%u euid=%u\n%n",
        nonce, &marker_pid, &uid, &euid, &consumed);
    bool matched = fields == 4 && consumed == amount &&
        strcmp(nonce, kAcceptanceNonce) == 0 && marker_pid == child &&
        uid == 0 && euid == 0;
    if (matched) {
        *startup_result = 0;
    }
    return matched;
#else
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    int startup = -1;
    int fields = sscanf(
        text,
        "codex-runtime-broker=ready pid=%d uid=%u euid=%u "
        "socket=%103s startup_injection=%d",
        &marker_pid, &uid, &euid, socket_path, &startup);
    bool matched = fields == 5 && marker_pid == child && uid == 0 &&
        euid == 0 &&
        strcmp(socket_path, "/var/run/codex-runtime-broker.sock") == 0;
    if (matched) {
        *startup_result = startup;
    }
    return matched;
#endif
}

static mach_vm_address_t find_loader_image(mach_port_t task,
                                           uint64_t *entry_offset) {
    mach_vm_address_t address = 0;
    natural_t depth = 0;
    while (address < 0x0000ffffffffffffULL) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            task, &address, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (result != KERN_SUCCESS || size == 0) {
            break;
        }
        if (info.is_submap) {
            ++depth;
            continue;
        }
        if ((info.protection & VM_PROT_READ) != 0 &&
            size >= sizeof(struct mach_header_64)) {
            struct mach_header_64 header = {0};
            if (read_remote(task, address, &header, sizeof(header)) ==
                    KERN_SUCCESS &&
                header.magic == MH_MAGIC_64 && header.filetype == MH_EXECUTE &&
                header.ncmds > 0 && header.ncmds < 1024 &&
                header.sizeofcmds >= sizeof(struct load_command) &&
                header.sizeofcmds <= 1024U * 1024U) {
                uint8_t *commands = malloc(header.sizeofcmds);
                if (commands != NULL &&
                    read_remote(task, address + sizeof(header), commands,
                                header.sizeofcmds) == KERN_SUCCESS) {
                    bool uuid_matches = false;
                    uint64_t candidate_entry = 0;
                    size_t offset = 0;
                    for (uint32_t index = 0; index < header.ncmds; ++index) {
                        if (offset + sizeof(struct load_command) >
                            header.sizeofcmds) {
                            break;
                        }
                        const struct load_command *command =
                            (const struct load_command *)(commands + offset);
                        if (command->cmdsize < sizeof(*command) ||
                            offset + command->cmdsize > header.sizeofcmds) {
                            break;
                        }
                        if (command->cmd == LC_UUID &&
                            command->cmdsize >= sizeof(struct uuid_command)) {
                            const struct uuid_command *uuid =
                                (const struct uuid_command *)command;
                            uuid_matches = memcmp(uuid->uuid, kLoaderUUID,
                                                  sizeof(kLoaderUUID)) == 0;
                        } else if (command->cmd == LC_MAIN &&
                                   command->cmdsize >=
                                       sizeof(struct entry_point_command)) {
                            candidate_entry =
                                ((const struct entry_point_command *)command)
                                    ->entryoff;
                        }
                        offset += command->cmdsize;
                    }
                    free(commands);
                    if (uuid_matches && candidate_entry != 0) {
                        *entry_offset = candidate_entry;
                        return address;
                    }
                } else {
                    free(commands);
                }
            }
        }
        if (address > UINT64_MAX - size) {
            break;
        }
        address += size;
    }
    return 0;
}

static bool test_remote_memory_control(mach_port_t task,
                                       mach_vm_address_t main_address) {
    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    const uint32_t return_42[] = {
        0xd503245fU, /* bti c */
        0x52800540U, /* mov w0, #42 */
        0xd65f03c0U, /* ret */
    };
    uint32_t executable_readback[3] = {0};
    mach_vm_address_t executable = 0;
    kern_return_t allocate_result = mach_vm_allocate(
        task, &executable, page_size, VM_FLAGS_ANYWHERE);
    kern_return_t write_protect_result = allocate_result == KERN_SUCCESS
        ? mach_vm_protect(task, executable, page_size, false,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)
        : allocate_result;
    kern_return_t write_result = write_protect_result == KERN_SUCCESS
        ? mach_vm_write(task, executable,
                        (vm_offset_t)(uintptr_t)return_42,
                        (mach_msg_type_number_t)sizeof(return_42))
        : write_protect_result;
    vm_machine_attribute_val_t cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t flush_result = write_result == KERN_SUCCESS
        ? vm_machine_attribute(task, (vm_address_t)executable,
                               (vm_size_t)page_size, MATTR_CACHE, &cache_value)
        : write_result;
    kern_return_t execute_result = flush_result == KERN_SUCCESS
        ? mach_vm_protect(task, executable, page_size, false,
                          VM_PROT_READ | VM_PROT_EXECUTE)
        : flush_result;
    kern_return_t readback_result = execute_result == KERN_SUCCESS
        ? read_remote(task, executable, executable_readback,
                      sizeof(executable_readback))
        : execute_result;
    bool executable_protection = execute_result == KERN_SUCCESS &&
        remote_address_has_protection(
            task, executable, VM_PROT_READ | VM_PROT_EXECUTE);
    bool executable_ok = readback_result == KERN_SUCCESS &&
        executable_protection &&
        memcmp(executable_readback, return_42, sizeof(return_42)) == 0;

    uint32_t original = 0;
    uint32_t temporary = 0xd503201fU; /* nop */
    uint32_t observed = 0;
    uint32_t restored = 0;
    kern_return_t original_result =
        read_remote(task, main_address, &original, sizeof(original));
    mach_vm_address_t main_page = main_address & ~(page_size - 1U);
    kern_return_t main_write_protect_result =
        original_result == KERN_SUCCESS
        ? mach_vm_protect(task, main_page, page_size, false,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)
        : original_result;
    kern_return_t temporary_write_result =
        main_write_protect_result == KERN_SUCCESS
        ? mach_vm_write(task, main_address,
                        (vm_offset_t)(uintptr_t)&temporary,
                        (mach_msg_type_number_t)sizeof(temporary))
        : main_write_protect_result;
    kern_return_t temporary_read_result =
        temporary_write_result == KERN_SUCCESS
        ? read_remote(task, main_address, &observed, sizeof(observed))
        : temporary_write_result;
    kern_return_t restore_write_result =
        main_write_protect_result == KERN_SUCCESS
        ? mach_vm_write(task, main_address,
                        (vm_offset_t)(uintptr_t)&original,
                        (mach_msg_type_number_t)sizeof(original))
        : main_write_protect_result;
    cache_value = MATTR_VAL_CACHE_FLUSH;
    kern_return_t restore_flush_result =
        restore_write_result == KERN_SUCCESS
        ? vm_machine_attribute(task, (vm_address_t)main_page,
                               (vm_size_t)page_size, MATTR_CACHE, &cache_value)
        : restore_write_result;
    kern_return_t main_execute_result =
        restore_flush_result == KERN_SUCCESS
        ? mach_vm_protect(task, main_page, page_size, false,
                          VM_PROT_READ | VM_PROT_EXECUTE)
        : restore_flush_result;
    kern_return_t restore_read_result =
        main_execute_result == KERN_SUCCESS
        ? read_remote(task, main_address, &restored, sizeof(restored))
        : main_execute_result;
    bool main_execute_protection = main_execute_result == KERN_SUCCESS &&
        remote_address_has_protection(
            task, main_address, VM_PROT_READ | VM_PROT_EXECUTE);
    bool patch_ok = original_result == KERN_SUCCESS &&
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        original == 0x14000001U &&
#else
        original == 0xd503237fU &&
#endif
        temporary_read_result == KERN_SUCCESS &&
        observed == temporary && restore_read_result == KERN_SUCCESS &&
        main_execute_protection && restored == original;

    probe_log("phase=memory-control page=0x%llx allocateKr=%d "
              "writeProtectKr=%d writeKr=%d flushKr=%d rxKr=%d "
              "readKr=%d executableProtection=%d executableOk=%d "
              "main=0x%llx originalKr=%d "
              "original=0x%08x mainWriteProtectKr=%d temporaryWriteKr=%d "
              "temporaryReadKr=%d observed=0x%08x restoreWriteKr=%d "
              "restoreFlushKr=%d mainRxKr=%d restoreReadKr=%d "
              "restored=0x%08x mainExecuteProtection=%d patchOk=%d\n",
              (unsigned long long)executable, allocate_result,
              write_protect_result, write_result, flush_result,
              execute_result, readback_result, executable_protection,
              executable_ok,
              (unsigned long long)main_address, original_result, original,
              main_write_protect_result, temporary_write_result,
              temporary_read_result, observed, restore_write_result,
              restore_flush_result, main_execute_result, restore_read_result,
              restored, main_execute_protection, patch_ok);
    if (executable != 0) {
        (void)mach_vm_deallocate(task, executable, page_size);
    }
    return executable_ok && patch_ok;
}

static bool wait_for_child_stop(pid_t child, int *status) {
    for (unsigned int attempt = 0; attempt < 500; ++attempt) {
        pid_t waited;
        do {
            waited = waitpid(child, status, WUNTRACED | WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == child) {
            return WIFSTOPPED(*status);
        }
        if (waited < 0) {
            return false;
        }
        usleep(10U * 1000U);
    }
    errno = ETIMEDOUT;
    return false;
}

#if CODEX_DIRECT_SPRINGBOARD_PROOF
static bool direct_single_thread_pc_equals(
    mach_port_t task, mach_vm_address_t expected,
    mach_vm_address_t *observed_pc, mach_msg_type_number_t *observed_count) {
    *observed_pc = 0;
    *observed_count = 0;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t threads_result = task_threads(
        task, &threads, &thread_count);
    bool matched = false;
    if (threads_result == KERN_SUCCESS && thread_count == 1) {
        arm_thread_state64_t state = {0};
        mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
        kern_return_t state_result = thread_get_state(
            threads[0], ARM_THREAD_STATE64, (thread_state_t)&state,
            &state_count);
        if (state_result == KERN_SUCCESS) {
            *observed_pc = canonical_remote_address(
                (uint64_t)arm_thread_state64_get_pc(state));
            matched = *observed_pc == expected;
        }
    }
    *observed_count = thread_count;
    if (threads != NULL) {
        for (mach_msg_type_number_t index = 0; index < thread_count;
             ++index) {
            mach_port_deallocate(mach_task_self(), threads[index]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threads,
                      (vm_size_t)(thread_count * sizeof(thread_t)));
    }
    return matched;
}
#endif

#if !CODEX_DIRECT_SPRINGBOARD_PROOF
static int detach_child(pid_t child);
#endif

static int advance_to_loader_main(pid_t child, mach_port_t task,
                                  mach_vm_address_t main_address,
                                  mach_vm_address_t *gate_address) {
    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    const uint32_t gate_words[10] = {
        0xd50324dfU, /* bti jc */
        0xd2800290U, /* mov x16, #20 (getpid) */
        0xd4001001U, /* svc #0x80 */
        0xd2800221U, /* mov x1, #17 (SIGSTOP) */
        0xd28004b0U, /* mov x16, #37 (kill) */
        0xd4001001U, /* svc #0x80 */
        0x58000050U, /* ldr x16, literal at +0x20 */
        0xd61f0200U, /* br x16 */
        0,
        0,
    };
    uint8_t original[20] = {0};
    mach_vm_address_t gate = 0;
    kern_return_t allocate_result = mach_vm_allocate(
        task, &gate, page_size, VM_FLAGS_ANYWHERE);
    bool gate_written = allocate_result == KERN_SUCCESS &&
        write_executable_bytes(task, gate, gate_words, sizeof(gate_words));
    uint8_t branch[20] = {0};
    make_absolute_branch(gate, branch);
    bool main_read = read_remote(task, main_address, original,
                                 sizeof(original)) == KERN_SUCCESS;
    bool main_admitted = main_read &&
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        memcmp(original, kExpectedSpringBoardMainPrefix,
               sizeof(kExpectedSpringBoardMainPrefix)) == 0;
#else
        *(const uint32_t *)original == 0xd503237fU;
#endif
    bool main_hooked = gate_written && main_admitted &&
        write_executable_bytes(task, main_address, branch, sizeof(branch));
    if (!main_hooked) {
        if (gate != 0) {
            (void)mach_vm_deallocate(task, gate, page_size);
        }
        return 40;
    }
    errno = 0;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    int detach_result = ptrace(CODEX_PT_CONTINUE, child, (caddr_t)1, 0);
#else
    int detach_result = detach_child(child);
#endif
    int detach_error = errno;
    int stop_status = 0;
    bool stopped = detach_result == 0 &&
        wait_for_child_stop(child, &stop_status);
    bool stop_admitted = stopped && WSTOPSIG(stop_status) == SIGSTOP
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        && stop_status == 0x117f
#endif
        ;
    mach_vm_address_t stopped_pc = 0;
    mach_msg_type_number_t stopped_thread_count = 0;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    bool gate_pc_exact = stop_admitted && direct_single_thread_pc_equals(
        task, gate + 24U, &stopped_pc, &stopped_thread_count);
    bool restored = gate_pc_exact && write_executable_bytes(
        task, main_address, &original, sizeof(original));
#else
    bool gate_pc_exact = stop_admitted;
    bool restored = write_executable_bytes(
        task, main_address, &original, sizeof(original));
#endif
    probe_log("phase=main-stop gate=0x%llx allocateKr=%d gateWritten=%d "
              "mainRead=%d mainAdmitted=%d mainHooked=%d detach=%d "
              "detachErrno=%d stopped=%d status=0x%x signal=%d "
              "threadCount=%u stoppedPc=0x%llx gatePcExact=%d "
              "main=0x%llx restored=%d admitted=%d\n",
              (unsigned long long)gate, allocate_result, gate_written,
              main_read, main_admitted, main_hooked, detach_result,
              detach_error, stopped, stop_status,
              stopped ? WSTOPSIG(stop_status) : 0,
              stopped_thread_count, (unsigned long long)stopped_pc,
              gate_pc_exact,
              (unsigned long long)main_address, restored, stop_admitted);
    if (!stop_admitted || !gate_pc_exact || !restored) {
#if !CODEX_DIRECT_SPRINGBOARD_PROOF
        if (gate != 0) {
            (void)mach_vm_deallocate(task, gate, page_size);
        }
#endif
        return 41;
    }
    *gate_address = gate;
    return 0;
}

#if !CODEX_DIRECT_SPRINGBOARD_PROOF
static int detach_child(pid_t child) {
    for (unsigned int attempt = 0; attempt < 500; ++attempt) {
        errno = 0;
        int result = ptrace(CODEX_PT_DETACH, child, NULL, 0);
        if (result == 0) {
            (void)kill(child, SIGCONT);
            return 0;
        }
        if (errno != EBUSY && errno != EINTR) {
            return -1;
        }
        usleep(10U * 1000U);
    }
    errno = ETIMEDOUT;
    return -1;
}
#endif

static int run_carrier_takeover(pid_t child, mach_port_t task,
                                const task_dyld_info_data_t *dyld_info,
                                mach_vm_address_t gate_address) {
    mach_vm_address_t dyld_header = 0;
    mach_vm_address_t libdyld = find_remote_image(
        task, dyld_info->all_image_info_addr,
        "/usr/lib/system/libdyld.dylib", &dyld_header);
    mach_vm_address_t dlopen_address =
        libdyld != 0 ? find_remote_symbol(task, libdyld, "_dlopen") : 0;
    if (dlopen_address == 0 && libdyld != 0) {
        dlopen_address = find_remote_export(task, libdyld, "_dlopen");
    }
    mach_vm_address_t mmap_stub = dyld_header != 0
        ? find_remote_pattern(task, dyld_header, kMmapPattern,
                              sizeof(kMmapPattern))
        : 0;
    mach_vm_address_t fcntl_stub = dyld_header != 0
        ? find_remote_pattern(task, dyld_header, kFcntlPattern,
                              sizeof(kFcntlPattern))
        : 0;
    probe_log("phase=resolve dyld=0x%llx libdyld=0x%llx "
              "dlopen=0x%llx mmap=0x%llx fcntl=0x%llx\n",
              (unsigned long long)dyld_header,
              (unsigned long long)libdyld,
              (unsigned long long)dlopen_address,
              (unsigned long long)mmap_stub,
              (unsigned long long)fcntl_stub);
    if (!carrier_file_is_secure() || dyld_header == 0 || libdyld == 0 ||
        dlopen_address == 0 || mmap_stub == 0 || fcntl_stub == 0 ||
        gate_address == 0) {
        return 30;
    }

    uintptr_t blob_start = (uintptr_t)codex_remote_blob_start;
    uintptr_t blob_end = (uintptr_t)codex_remote_blob_end;
    uintptr_t entry_local = (uintptr_t)codex_remote_entry;
    uintptr_t mmap_local = (uintptr_t)codex_remote_mmap_hook;
    uintptr_t fcntl_local = (uintptr_t)codex_remote_fcntl_hook;
    uintptr_t context_pointer_local =
        (uintptr_t)codex_remote_context_pointer;
    const mach_vm_size_t page_size = (mach_vm_size_t)getpagesize();
    if (blob_end <= blob_start || blob_end - blob_start > page_size ||
        entry_local < blob_start || entry_local >= blob_end ||
        mmap_local < blob_start || mmap_local >= blob_end ||
        fcntl_local < blob_start || fcntl_local >= blob_end ||
        context_pointer_local < blob_start ||
        context_pointer_local + sizeof(uint64_t) > blob_end) {
        return 31;
    }
    size_t blob_size = blob_end - blob_start;
    size_t entry_offset = entry_local - blob_start;
    size_t mmap_offset = mmap_local - blob_start;
    size_t fcntl_offset = fcntl_local - blob_start;
    size_t context_pointer_offset = context_pointer_local - blob_start;

    mach_vm_address_t code = 0;
    mach_vm_address_t context_address = 0;
    kern_return_t code_allocate = mach_vm_allocate(
        task, &code, page_size, VM_FLAGS_ANYWHERE);
    kern_return_t context_allocate = code_allocate == KERN_SUCCESS
        ? mach_vm_allocate(task, &context_address, page_size,
                           VM_FLAGS_ANYWHERE)
        : code_allocate;
    uint8_t *blob = malloc(blob_size);
    struct codex_remote_context context = {0};
    bool prepared = code_allocate == KERN_SUCCESS &&
        context_allocate == KERN_SUCCESS && blob != NULL;
    if (prepared) {
        memcpy(blob, codex_remote_blob_start, blob_size);
        *(uint64_t *)(blob + context_pointer_offset) = context_address;
        context.dlopen_address = dlopen_address;
        snprintf(context.path, sizeof(context.path), "%s", kCarrierPath);
        kern_return_t context_protect = mach_vm_protect(
            task, context_address, page_size, false,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        kern_return_t context_write = context_protect == KERN_SUCCESS
            ? mach_vm_write(task, context_address,
                            (vm_offset_t)(uintptr_t)&context,
                            (mach_msg_type_number_t)sizeof(context))
            : context_protect;
        prepared = context_write == KERN_SUCCESS &&
            write_executable_bytes(task, code, blob, blob_size);
        probe_log("phase=remote-pages code=0x%llx context=0x%llx "
                  "blobSize=0x%zx codeAllocKr=%d contextAllocKr=%d "
                  "contextProtectKr=%d contextWriteKr=%d prepared=%d\n",
                  (unsigned long long)code,
                  (unsigned long long)context_address, blob_size,
                  code_allocate, context_allocate, context_protect,
                  context_write, prepared);
    }
    free(blob);
    if (!prepared) {
        if (context_address != 0) {
            (void)mach_vm_deallocate(task, context_address, page_size);
        }
        if (code != 0) {
            (void)mach_vm_deallocate(task, code, page_size);
        }
        return 32;
    }

    uint8_t saved_mmap[20] = {0};
    uint8_t saved_fcntl[20] = {0};
    if (read_remote(task, mmap_stub, saved_mmap, sizeof(saved_mmap)) !=
            KERN_SUCCESS ||
        read_remote(task, fcntl_stub, saved_fcntl, sizeof(saved_fcntl)) !=
            KERN_SUCCESS ||
        memcmp(saved_mmap, kMmapPattern, sizeof(kMmapPattern)) != 0 ||
        memcmp(saved_fcntl, kFcntlPattern, sizeof(kFcntlPattern)) != 0) {
        (void)mach_vm_deallocate(task, context_address, page_size);
        (void)mach_vm_deallocate(task, code, page_size);
        return 33;
    }

    uint8_t branch[20];
    make_absolute_branch(code + mmap_offset, branch);
    bool mmap_hooked = write_executable_bytes(
        task, mmap_stub, branch, sizeof(branch));
    make_absolute_branch(code + fcntl_offset, branch);
    bool fcntl_hooked = mmap_hooked && write_executable_bytes(
        task, fcntl_stub, branch, sizeof(branch));
    uint64_t entry_address = code + entry_offset;
    bool gate_armed = fcntl_hooked && write_executable_bytes(
        task, gate_address + 32U, &entry_address, sizeof(entry_address));
    probe_log("phase=install-hooks mmap=%d fcntl=%d gateArmed=%d "
              "entry=0x%llx mmapHook=0x%llx fcntlHook=0x%llx\n",
              mmap_hooked, fcntl_hooked, gate_armed,
              (unsigned long long)(code + entry_offset),
              (unsigned long long)(code + mmap_offset),
              (unsigned long long)(code + fcntl_offset));
    if (!gate_armed) {
        if (fcntl_hooked) {
            (void)write_executable_bytes(
                task, fcntl_stub, saved_fcntl, sizeof(saved_fcntl));
        }
        if (mmap_hooked) {
            (void)write_executable_bytes(
                task, mmap_stub, saved_mmap, sizeof(saved_mmap));
        }
        (void)mach_vm_deallocate(task, context_address, page_size);
        (void)mach_vm_deallocate(task, code, page_size);
        return 34;
    }

    errno = 0;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    int first_resume = ptrace(CODEX_PT_CONTINUE, child, (caddr_t)1, 0);
#else
    int first_resume = kill(child, SIGCONT);
#endif
    int first_resume_error = errno;
    if (first_resume != 0) {
        (void)write_executable_bytes(
            task, fcntl_stub, saved_fcntl, sizeof(saved_fcntl));
        (void)write_executable_bytes(
            task, mmap_stub, saved_mmap, sizeof(saved_mmap));
        return 35;
    }

    uint32_t remote_status = 0;
    uint64_t remote_handle = 0;
    for (unsigned int attempt = 0; attempt < 1000; ++attempt) {
        struct {
            uint32_t status;
            uint32_t reserved;
            uint64_t handle;
        } result = {0};
        if (read_remote(task,
                        context_address +
                            offsetof(struct codex_remote_context, status),
                        &result, sizeof(result)) == KERN_SUCCESS) {
            remote_status = result.status;
            remote_handle = result.handle;
            if (remote_status != 0) {
                break;
            }
        }
        usleep(10U * 1000U);
    }

    int second_stop_status = 0;
    bool second_stopped = wait_for_child_stop(child, &second_stop_status) &&
        WSTOPSIG(second_stop_status) == SIGSTOP
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        && second_stop_status == 0x117f
#endif
        ;
    bool fcntl_restored = second_stopped && write_executable_bytes(
        task, fcntl_stub, saved_fcntl, sizeof(saved_fcntl));
    bool mmap_restored = second_stopped && write_executable_bytes(
        task, mmap_stub, saved_mmap, sizeof(saved_mmap));
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    mach_vm_address_t payload_image = second_stopped
        ? find_remote_image(task, dyld_info->all_image_info_addr,
                            kCarrierPath, NULL)
        : 0;
    if (payload_image == 0 && second_stopped &&
        strcmp(gPayloadRealPath, kCarrierPath) != 0) {
        payload_image = find_remote_image(
            task, dyld_info->all_image_info_addr, gPayloadRealPath, NULL);
    }
    bool payload_uuid = remote_image_uuid_matches(
        task, payload_image, kExpectedPayloadUUID);
    int marker_startup = -1;
    bool marker = marker_matches_child(child, &marker_startup);
    bool candidate_exact = second_stopped && direct_candidate_exact(child);
    bool stock_during = direct_stock_still_exact(1);
    int terminal_status = 0;
    int ptrace_kill_result = -1;
    int ptrace_kill_error = 0;
    bool killed = terminate_traced_child(
        child, &terminal_status, &ptrace_kill_result, &ptrace_kill_error);
    bool stock_after_immediate = killed && direct_stock_still_exact(0);
    bool stock_after_settled = stock_after_immediate &&
        direct_stock_settles_exact(5000U);
    alarm(0);
    probe_log(
        "phase=direct-springboard-result firstContinue=%d "
        "firstContinueErrno=%d status=%u handle=0x%llx "
        "secondStopped=%d stopStatus=0x%x fcntlRestored=%d "
        "mmapRestored=%d payloadImage=0x%llx payloadUUID=%d marker=%d "
        "candidateExact=%d stockDuring=%d ptraceKill=%d "
        "ptraceKillErrno=%d killed=%d terminalStatus=0x%x "
        "stockAfterImmediate=%d stockAfterSettleMs=5000 "
        "stockAfterSettled=%d realMainEntered=0 tssRequested=0\n",
        first_resume, first_resume_error, remote_status,
        (unsigned long long)remote_handle, second_stopped,
        second_stop_status, fcntl_restored, mmap_restored,
        (unsigned long long)payload_image, payload_uuid, marker,
        candidate_exact, stock_during, ptrace_kill_result,
        ptrace_kill_error, killed, terminal_status,
        stock_after_immediate, stock_after_settled);
    return remote_status == 1 && remote_handle != 0 && second_stopped &&
            fcntl_restored && mmap_restored && payload_image != 0 &&
            payload_uuid && marker && candidate_exact && stock_during &&
            killed && stock_after_settled
        ? 0
        : 36;
#else
    kern_return_t gate_deallocate = mmap_restored
        ? mach_vm_deallocate(task, gate_address, page_size)
        : KERN_FAILURE;
    errno = 0;
    int second_resume = gate_deallocate == KERN_SUCCESS
        ? kill(child, SIGCONT)
        : -1;
    int second_resume_error = errno;
    int marker_startup = -1;
    bool marker = marker_matches_child(child, &marker_startup);
    probe_log("phase=carrier-result firstResume=%d firstResumeErrno=%d "
              "status=%u handle=0x%llx secondStopped=%d stopStatus=0x%x "
              "fcntlRestored=%d mmapRestored=%d gateDeallocKr=%d "
              "secondResume=%d secondResumeErrno=%d marker=%d "
              "markerStartup=%d\n",
              first_resume, first_resume_error, remote_status,
              (unsigned long long)remote_handle, second_stopped,
              second_stop_status, fcntl_restored, mmap_restored,
              gate_deallocate, second_resume, second_resume_error, marker,
              marker_startup);
    if (remote_status != 1 || remote_handle == 0 || !marker ||
        !second_stopped || !fcntl_restored || !mmap_restored ||
        gate_deallocate != KERN_SUCCESS || second_resume != 0) {
        terminate_child(child);
        return 36;
    }

    alarm(0);
    probe_log("phase=supervise child=%d resident=1\n", child);
    int resident_status = 0;
    pid_t resident_waited;
    do {
        resident_waited = waitpid(child, &resident_status, 0);
    } while (resident_waited < 0 && errno == EINTR);
    gChild = -1;
    probe_log("phase=supervise-exit child=%d waited=%d status=0x%x\n",
              child, resident_waited, resident_status);
    if (resident_waited != child) {
        return 37;
    }
    if (WIFEXITED(resident_status)) {
        return WEXITSTATUS(resident_status);
    }
    return WIFSIGNALED(resident_status)
        ? 128 + WTERMSIG(resident_status)
        : 38;
#endif
}

int main(int argc, char **argv) {
    gLog = open(kLogPath,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                0600);
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    struct stat log_information = {0};
    if (gLog < 0 || fstat(gLog, &log_information) != 0 ||
        !S_ISREG(log_information.st_mode) || log_information.st_uid != 0 ||
        log_information.st_nlink != 1 ||
        (log_information.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        fchmod(gLog, 0600) != 0) {
        if (gLog >= 0) {
            (void)close(gLog);
        }
        gLog = STDERR_FILENO;
        return 9;
    }
#else
    if (gLog < 0) {
        gLog = STDERR_FILENO;
    }
#endif
    probe_log("phase=start pid=%d uid=%u euid=%u\n", getpid(), getuid(),
              geteuid());
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    errno = 0;
    char *pid_end = NULL;
    long requested_stock = argc == 2
        ? strtol(argv[1], &pid_end, 10)
        : -1;
    bool direct_preflight = argc == 2 && pid_end != argv[1] &&
        pid_end != NULL && *pid_end == '\0' && errno == 0 &&
        requested_stock > 1 && requested_stock <= INT32_MAX &&
        geteuid() == 0 && direct_preflight_files() &&
        direct_read_stock((pid_t)requested_stock, &gStockSnapshot) &&
        direct_stock_still_exact(0) && direct_clear_marker();
    probe_log("phase=direct-preflight requestedStock=%ld filesAndStock=%d "
              "stockPid=%d stockUniqueId=%llu stockPidVersion=%d "
              "tssRequested=0\n",
              requested_stock, direct_preflight, gStockSnapshot.pid,
              (unsigned long long)gStockSnapshot.unique.unique_id,
              gStockSnapshot.unique.pid_version);
    if (!direct_preflight) {
        return 10;
    }
#else
    (void)argc;
    (void)argv;
    if (geteuid() != 0 || access(kLoaderPath, X_OK) != 0 ||
        !carrier_file_is_secure()) {
        probe_log("phase=preflight result=failed errno=%d\n", errno);
        return 10;
    }
#endif
    signal(SIGALRM, timeout_handler);
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    alarm(45);
#else
    alarm(20);
#endif

#if CODEX_DIRECT_SPRINGBOARD_PROOF
    char *arguments[] = {(char *)kLoaderPath, NULL};
    char *direct_environment[] = {
        (char *)"CODEX_SPRINGBOARD_DIRECT_PREMAIN_PROOF=1", NULL};
#else
    char parent[32];
    snprintf(parent, sizeof(parent), "%d", getpid());
    char *arguments[] = {
        (char *)kLoaderPath,
        "--inspect-pid",
        parent,
        NULL,
    };
#endif
    posix_spawnattr_t spawn_attributes;
    int spawn_result = posix_spawnattr_init(&spawn_attributes);
    int spawn_attributes_initialized = spawn_result == 0;
    if (spawn_result == 0) {
        spawn_result = posix_spawnattr_setflags(
            &spawn_attributes, POSIX_SPAWN_START_SUSPENDED);
    }
    pid_t child = -1;
    if (spawn_result == 0) {
        spawn_result = posix_spawn(&child, kLoaderPath, NULL,
                                   &spawn_attributes, arguments,
#if CODEX_DIRECT_SPRINGBOARD_PROOF
                                   direct_environment);
#else
                                   environ);
#endif
    }
    if (spawn_attributes_initialized) {
        (void)posix_spawnattr_destroy(&spawn_attributes);
    }
    if (spawn_result != 0) {
        probe_log("phase=spawn result=failed error=%d child=%d\n",
                  spawn_result, child);
        return 11;
    }
    if (child <= 1) {
        probe_log("phase=pid-guard result=failed child=%d\n", child);
        return 14;
    }
    gChild = child;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    (void)atexit(direct_terminate_owned_child_at_exit);
#endif

#if CODEX_DIRECT_SPRINGBOARD_PROOF
    int initial_status = 0;
    bool initial_stopped = wait_for_child_stop(child, &initial_status) &&
        initial_status == 0x7f;
    bool stock_after_spawn = direct_stock_still_exact(1);
    probe_log("phase=start-suspended child=%d stopped=%d status=0x%x "
              "stockExact=%d\n",
              child, initial_stopped, initial_status, stock_after_spawn);
    if (!initial_stopped || !stock_after_spawn) {
        terminate_child(child);
        gChild = -1;
        return 15;
    }
    errno = 0;
    int attach_result = ptrace(CODEX_PT_ATTACHEXC, child, NULL, 0);
    int attach_error = attach_result == 0 ? 0 : errno;
    int status = 0;
    bool attach_stopped = attach_result == 0 &&
        wait_for_child_stop(child, &status) && status == 0x117f;
    probe_log("phase=attach-stop attach=%d attachErrno=%d child=%d "
              "stopped=%d status=0x%x signal=%d\n",
              attach_result, attach_error, child, attach_stopped, status,
              attach_stopped ? WSTOPSIG(status) : 0);
    if (!attach_stopped) {
        if (attach_result == 0) {
            int terminal_status = 0;
            int ptrace_kill_result = -1;
            int ptrace_kill_error = 0;
            (void)terminate_traced_child(
                child, &terminal_status, &ptrace_kill_result,
                &ptrace_kill_error);
        } else {
            terminate_child(child);
            gChild = -1;
        }
        return 15;
    }
#else
    errno = 0;
    int attach_result = ptrace(CODEX_PT_ATTACHEXC, child, NULL, 0);
    int attach_error = errno;
    errno = 0;
    int continue_result = kill(child, SIGCONT);
    int continue_error = errno;

    int status = 0;
    pid_t waited = 0;
    for (unsigned int attempt = 0; attempt < 250 && waited == 0; ++attempt) {
        do {
            waited = waitpid(child, &status, WUNTRACED | WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == 0) {
            usleep(20U * 1000U);
        }
    }
    probe_log("phase=attach-stop attach=%d attachErrno=%d sigcont=%d "
              "sigcontErrno=%d waited=%d status=0x%x stopped=%d signal=%d\n",
              attach_result, attach_error, continue_result, continue_error,
              waited, status, WIFSTOPPED(status),
              WIFSTOPPED(status) ? WSTOPSIG(status) : 0);
    if (attach_result != 0 || waited != child || !WIFSTOPPED(status)) {
        terminate_child(child);
        return 15;
    }
#endif

    uint32_t flags = 0;
    int cs_result = csops(child, CODEX_CS_OPS_STATUS, &flags, sizeof(flags));
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(mach_task_self(), child, &task);
    probe_log("phase=task-port csops=%d flags=0x%08x debugged=%d "
              "taskKr=%d task=0x%x\n",
              cs_result, flags, (flags & CODEX_CS_DEBUGGED) != 0,
              task_result, task);
    if (cs_result != 0 || (flags & CODEX_CS_DEBUGGED) == 0 ||
        task_result != KERN_SUCCESS || !MACH_PORT_VALID(task)
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        || !direct_candidate_exact(child) || !direct_stock_still_exact(1)
#endif
        ) {
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        int terminal_status = 0;
        int ptrace_kill_result = -1;
        int ptrace_kill_error = 0;
        bool cleaned = terminate_traced_child(
            child, &terminal_status, &ptrace_kill_result,
            &ptrace_kill_error);
        probe_log("phase=task-port-cleanup cleaned=%d ptraceKill=%d "
                  "ptraceKillErrno=%d terminalStatus=0x%x\n",
                  cleaned, ptrace_kill_result, ptrace_kill_error,
                  terminal_status);
#else
        (void)ptrace(CODEX_PT_DETACH, child, NULL, 0);
        (void)kill(child, SIGCONT);
        terminate_child(child);
#endif
        return 16;
    }

    task_dyld_info_data_t dyld_info = {0};
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kern_return_t dyld_info_result = task_info(
        task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &dyld_info_count);
    uint64_t entry_offset = 0;
    mach_vm_address_t loader_base = find_loader_image(task, &entry_offset);
    mach_vm_address_t main_address =
        loader_base != 0 ? loader_base + entry_offset : 0;
    bool memory_control = main_address != 0 &&
        test_remote_memory_control(task, main_address);
    probe_log("phase=image-layout dyldKr=%d allImageInfo=0x%llx "
              "allImageInfoSize=0x%llx loaderBase=0x%llx "
              "entryOffset=0x%llx main=0x%llx memoryControl=%d\n",
              dyld_info_result,
              (unsigned long long)dyld_info.all_image_info_addr,
              (unsigned long long)dyld_info.all_image_info_size,
              (unsigned long long)loader_base,
              (unsigned long long)entry_offset,
              (unsigned long long)main_address, memory_control);

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t threads_result = task_threads(task, &threads, &thread_count);
    arm_thread_state64_t state = {0};
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t state_result = KERN_FAILURE;
    if (threads_result == KERN_SUCCESS && thread_count != 0) {
        state_result = thread_get_state(
            threads[0], ARM_THREAD_STATE64, (thread_state_t)&state,
            &state_count);
    }
    uint64_t pc = state_result == KERN_SUCCESS
        ? (uint64_t)arm_thread_state64_get_pc(state)
        : 0;
    uint64_t sp = state_result == KERN_SUCCESS
        ? (uint64_t)arm_thread_state64_get_sp(state)
        : 0;
    uint8_t instructions[32] = {0};
    mach_vm_size_t copied = 0;
    kern_return_t read_result = pc != 0
        ? mach_vm_read_overwrite(task, pc, sizeof(instructions),
                                 (mach_vm_address_t)instructions, &copied)
        : KERN_INVALID_ADDRESS;
    probe_log("phase=thread-state threadsKr=%d count=%u stateKr=%d "
              "pc=0x%llx sp=0x%llx readKr=%d copied=%llu "
              "bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
              threads_result, thread_count, state_result,
              (unsigned long long)pc, (unsigned long long)sp,
              read_result, (unsigned long long)copied,
              instructions[0], instructions[1], instructions[2],
              instructions[3], instructions[4], instructions[5],
              instructions[6], instructions[7]);

    if (threads != NULL) {
        for (mach_msg_type_number_t index = 0; index < thread_count; ++index) {
            mach_port_deallocate(mach_task_self(), threads[index]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threads,
                      (vm_size_t)(thread_count * sizeof(thread_t)));
    }
    mach_vm_address_t gate_address = 0;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    uint32_t flags_after_memory_test = 0;
    bool candidate_before_gate =
        csops(child, CODEX_CS_OPS_STATUS, &flags_after_memory_test,
              sizeof(flags_after_memory_test)) == 0 &&
        flags_after_memory_test == flags && direct_candidate_exact(child);
    bool stock_before_gate = direct_stock_still_exact(1);
    probe_log("phase=pre-main-admission candidateExact=%d "
              "flagsBefore=0x%08x flagsAfter=0x%08x stockExact=%d\n",
              candidate_before_gate, flags, flags_after_memory_test,
              stock_before_gate);
#endif
    int main_stop_result = memory_control
#if CODEX_DIRECT_SPRINGBOARD_PROOF
            && candidate_before_gate && stock_before_gate
#endif
        ? advance_to_loader_main(child, task, main_address, &gate_address)
        : 42;
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    bool stock_at_gate = main_stop_result == 0 &&
        direct_stock_still_exact(1);
#endif
    memset(&dyld_info, 0, sizeof(dyld_info));
    dyld_info_count = TASK_DYLD_INFO_COUNT;
    dyld_info_result = main_stop_result == 0
        ? task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info,
                    &dyld_info_count)
        : KERN_FAILURE;
    probe_log("phase=post-main-layout stopResult=%d gate=0x%llx "
              "dyldKr=%d allImageInfo=0x%llx allImageInfoSize=0x%llx\n",
              main_stop_result, (unsigned long long)gate_address,
              dyld_info_result,
              (unsigned long long)dyld_info.all_image_info_addr,
              (unsigned long long)dyld_info.all_image_info_size);
    int takeover_result =
        main_stop_result == 0 && dyld_info_result == KERN_SUCCESS &&
                state_result == KERN_SUCCESS && read_result == KERN_SUCCESS &&
                copied >= 8
#if CODEX_DIRECT_SPRINGBOARD_PROOF
                && stock_at_gate
#endif
            ? run_carrier_takeover(child, task, &dyld_info, gate_address)
            : 18;
    mach_port_deallocate(mach_task_self(), task);
    if (takeover_result != 0 && gChild == child) {
#if CODEX_DIRECT_SPRINGBOARD_PROOF
        int cleanup_status = 0;
        int cleanup_ptrace_result = -1;
        int cleanup_ptrace_error = 0;
        bool cleaned = terminate_traced_child(
            child, &cleanup_status, &cleanup_ptrace_result,
            &cleanup_ptrace_error);
        probe_log("phase=failure-cleanup cleaned=%d ptraceKill=%d "
                  "ptraceKillErrno=%d terminalStatus=0x%x\n",
                  cleaned, cleanup_ptrace_result, cleanup_ptrace_error,
                  cleanup_status);
#else
        terminate_child(child);
        gChild = -1;
#endif
        alarm(0);
    }
#if CODEX_DIRECT_SPRINGBOARD_PROOF
    probe_log("phase=complete proof=%d child=%d childReaped=%d "
              "stockUnchanged=%d realMainEntered=0 tssRequested=0\n",
              takeover_result == 0, child, gChild == -1,
              direct_stock_still_exact(0));
#else
    probe_log("phase=complete takeover=%d resident=%d child=%d\n",
              takeover_result, takeover_result == 0, child);
#endif
    return takeover_result;
}
