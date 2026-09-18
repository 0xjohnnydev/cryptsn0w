#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif
#ifndef PT_DETACH
#define PT_DETACH 11
#endif
#ifndef PT_CONTINUE
#define PT_CONTINUE 7
#endif
#ifndef PT_KILL
#define PT_KILL 8
#endif

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_OPS_CDHASH 5U
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_PROC_PIDTBSDINFO 3
#define CODEX_PROC_PIDUNIQIDENTIFIERINFO 17
#define CODEX_PROC_STATUS_RUNNABLE 2U
#define CODEX_PROC_STATUS_STOPPED 4U
#define CODEX_MAXCOMLEN 16
#define CODEX_PATH_SIZE 4096U
#define CODEX_CDHASH_SIZE 20U
#define CODEX_SHA256_SIZE 32U
#define CODEX_COMMAND_OUTPUT_SIZE 16384U
#define CODEX_GATE_READY_FD 196
#define CODEX_GATE_RELEASE_FD 197
#define CODEX_LOCK_INHERITED_FD 198
#define CODEX_COMMAND_TIMEOUT_MSEC 3000U
#define CODEX_INJECTION_TIMEOUT_MSEC 8000U
#define CODEX_BIND_TIMEOUT_MSEC 5000U
#define CODEX_TRACE_TIMEOUT_MSEC 3000U
#define CODEX_DYLD_MATURITY_TIMEOUT_MSEC 200U
#define CODEX_DYLD_MATURITY_POLL_USEC 250U
#define CODEX_REMOTE_IMAGE_LIMIT 4096U
#define CODEX_RESTORE_VERIFY_MSEC 8000U
#define CODEX_WATCHDOG_DELAY_MSEC 60000U
#define CODEX_EXTERNAL_WATCHDOG_DELAY_MSEC 45000U
#define CODEX_WATCHDOG_GRACE_MSEC 20000U
#define CODEX_WATCHDOG_FORCE_WAIT_MSEC 5000U
#define CODEX_WATCHDOG_REAP_TIMEOUT_MSEC 20000U
#define CODEX_WATCHDOG_SIGNAL_INTERVAL_MSEC 1000U
#define CODEX_HELPER_TERMINATE_MSEC 1000U
#define CODEX_HELPER_KILL_MSEC 2000U
#define CODEX_OBSERVE_MSEC 10000U
#define CODEX_EXPECTED_CANDIDATE_SIZE 122400ULL
#define CODEX_HELPER_RECORD_MAGIC 0x434f444558484c50ULL
#define CODEX_HELPER_RECORD_VERSION 1U
#define CODEX_HELPER_PHASE_SIZE 32U

#define CODEX_MAGIC "codex-springboard-live-precursor-v1"

static const char *const kServiceTarget =
    "user/501/com.apple.SpringBoard";
static const char *const kExternalCandidateTarget =
    "user/501/com.openai.codex.springboard-live-candidate";
static const char *const kLaunchctlPath =
    "/var/jb/usr/libexec/codex-apple-launchctl";
static const char *const kExternalLaunchctlPath =
    "/var/jb/usr/bin/launchctl";
static const char *const kWorkerPath =
    "/var/jb/usr/libexec/codex-exec-worker";
static const char *const kPrecursorPath =
    "/var/jb/usr/libexec/codex-springboard-live-precursor";
static const char *const kLoaderCandidatePath =
    "/var/jb/usr/libexec/codex-ellekit-loader-candidate";
static const char *const kDyldAdmissionHookPath =
    "/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib";
static const char *const kFreshCanaryPath =
    "/var/jb/usr/lib/codex-springboard-live-canary.dylib";
static const char *const kFreshCanaryMarkerPath =
    "/var/mobile/Media/codex-worker-fresh-dylib-canary.marker";
static const char *const kFreshCanaryNonce =
    "20260918T042559Z-e73aabd5726d4bee";
static const char *const kStockPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kCryptexdPath = "/usr/libexec/cryptexd";
static const char *const kSystemPlistPath =
    "/System/Library/LaunchDaemons/com.apple.SpringBoard.plist";
static const char *const kCandidatePath =
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard";
static const char *const kCandidateInfoPath =
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/Info.plist";
static const char *const kStateDirectory =
    "/var/jb/var/run/codex-springboard-live-precursor";
static const char *const kLockPath =
    "/var/jb/var/run/codex-springboard-live-precursor.lock";
static const char *const kRecoveryLockPath =
    "/var/jb/var/run/codex-springboard-live-precursor.recovery.lock";
static const char *const kJournalPath =
    "/var/jb/var/log/codex-springboard-live-precursor.log";

static const uint8_t kExpectedSpringBoardUUID[16] = {
    0xad, 0x93, 0x7f, 0xb7, 0x26, 0x64, 0x3b, 0x8f,
    0xb1, 0xc9, 0x34, 0xc4, 0xad, 0x40, 0x92, 0xd2,
};
static const uint8_t kExpectedCryptexdUUID[16] = {
    0x26, 0x1f, 0x91, 0xf3, 0x70, 0x16, 0x35, 0xa2,
    0x9a, 0x84, 0xc8, 0x5d, 0x2b, 0x6a, 0x83, 0x4e,
};
static const uint8_t kExpectedCandidateCDHash[CODEX_CDHASH_SIZE] = {
    0x9b, 0x29, 0x8e, 0x84, 0x6a, 0xb9, 0x1a, 0xaa, 0x1f, 0xba,
    0x30, 0x3f, 0x2c, 0x89, 0x2d, 0x82, 0x8e, 0x9e, 0x92, 0x1c,
};
static const uint8_t kExpectedCandidateSHA256[CODEX_SHA256_SIZE] = {
    0x73, 0xa2, 0xcc, 0xc2, 0x7f, 0x94, 0xec, 0xc3,
    0x52, 0x66, 0x02, 0x9d, 0xf8, 0x2d, 0x12, 0xca,
    0x7e, 0xb0, 0xf2, 0x7f, 0xf5, 0xf2, 0xe0, 0x47,
    0xbc, 0x9e, 0xa3, 0x56, 0x81, 0x87, 0x71, 0x26,
};
static const uint8_t kExpectedInfoSHA256[CODEX_SHA256_SIZE] = {
    0xce, 0x3b, 0xfe, 0xad, 0x94, 0x67, 0x6c, 0x8d,
    0xaf, 0x11, 0x1f, 0x00, 0x92, 0x11, 0x46, 0x7a,
    0x9c, 0x70, 0xf6, 0xcb, 0xce, 0xb7, 0x3e, 0x7a,
    0x0f, 0xcd, 0xe1, 0xf0, 0x3b, 0x32, 0x07, 0x03,
};
static const uint8_t kExpectedLaunchctlSHA256[CODEX_SHA256_SIZE] = {
    0x3e, 0xb2, 0xdb, 0xb5, 0x54, 0x96, 0x4a, 0x6c,
    0xe2, 0x21, 0xc0, 0x7d, 0x6d, 0x8a, 0x06, 0x81,
    0x56, 0x60, 0x6e, 0x27, 0x61, 0xc3, 0xcc, 0xc0,
    0x4a, 0x72, 0xf1, 0x98, 0xdf, 0xed, 0xdf, 0xdc,
};
static const uint8_t
    kExpectedExternalLaunchctlSHA256A[CODEX_SHA256_SIZE] = {
        0xa7, 0x8e, 0xa4, 0x3b, 0x8a, 0x2f, 0x16, 0x06,
        0xfa, 0x1a, 0xd6, 0xb2, 0xc5, 0x67, 0xfb, 0x93,
        0x52, 0xd7, 0xc5, 0x41, 0x56, 0xe2, 0x52, 0x59,
        0xf8, 0x8f, 0xfe, 0x32, 0x83, 0x04, 0x87, 0x04,
};
static const uint8_t
    kExpectedExternalLaunchctlSHA256B[CODEX_SHA256_SIZE] = {
        0x57, 0x20, 0xfd, 0x9b, 0x80, 0xcc, 0x8e, 0x37,
        0xd8, 0x7e, 0xa5, 0x5a, 0xcc, 0xe7, 0x10, 0xae,
        0xb9, 0x41, 0xc1, 0xc0, 0xfa, 0xc3, 0x12, 0x8e,
        0x06, 0x4d, 0xf9, 0xc9, 0xe2, 0x1b, 0x0a, 0xf0,
};
static const uint8_t kExpectedLoaderSHA256[CODEX_SHA256_SIZE] = {
    0x5b, 0x63, 0xba, 0xf3, 0x30, 0x23, 0x7a, 0xe1,
    0xe3, 0xb9, 0x5e, 0x02, 0xb2, 0xb9, 0x35, 0xb1,
    0x82, 0x54, 0x10, 0xd9, 0x4e, 0x7c, 0xb7, 0x6b,
    0xc4, 0xa1, 0x52, 0xd6, 0x11, 0x4b, 0x0c, 0x78,
};
static const uint8_t kExpectedHookSHA256[CODEX_SHA256_SIZE] = {
    0x90, 0xbd, 0xcd, 0x15, 0xdd, 0xa2, 0x2a, 0xe3,
    0x23, 0x43, 0xbe, 0x47, 0xa8, 0xd5, 0x4d, 0x94,
    0x9d, 0xea, 0xc0, 0xb0, 0x67, 0x9f, 0x3b, 0x8c,
    0x8a, 0x9b, 0xf0, 0xf9, 0xe6, 0xa6, 0x96, 0xee,
};
static const uint8_t kExpectedCanarySHA256[CODEX_SHA256_SIZE] = {
    0x57, 0x53, 0x97, 0x6c, 0x89, 0xf1, 0x64, 0x30,
    0x76, 0xb5, 0x1d, 0xe9, 0xd3, 0x4f, 0xaf, 0x79,
    0xcb, 0xd6, 0x13, 0xc1, 0x34, 0xee, 0xf0, 0x1e,
    0xc9, 0x3d, 0xf3, 0xf1, 0x84, 0x31, 0xd8, 0xbe,
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

struct process_snapshot {
    pid_t pid;
    char path[CODEX_PATH_SIZE];
    struct codex_proc_bsdinfo bsd;
    struct codex_proc_uniqidentifierinfo unique;
    uint32_t cs_flags;
    uint8_t cdhash[CODEX_CDHASH_SIZE];
};

struct candidate_pid_hold {
    pid_t pid;
    task_t task;
    struct codex_proc_uniqidentifierinfo generation;
    integer_t baseline_suspend_count;
    bool owned;
};

struct command_result {
    int spawn_error;
    bool timed_out;
    bool standard_output_truncated;
    bool standard_error_truncated;
    int wait_status;
    int exit_code;
    char standard_output[CODEX_COMMAND_OUTPUT_SIZE];
    char standard_error[CODEX_COMMAND_OUTPUT_SIZE];
};

struct helper_record {
    uint64_t magic;
    uint32_t version;
    int32_t pid;
    uint32_t uid;
    uint32_t ppid;
    int32_t pid_version;
    uint32_t reserved;
    uint64_t unique_id;
    uint64_t parent_unique_id;
    uint8_t uuid[16];
    char token[37];
    char phase[CODEX_HELPER_PHASE_SIZE];
    char path[CODEX_PATH_SIZE];
};

enum process_kind {
    PROCESS_STOCK,
    PROCESS_CANDIDATE,
};

extern char **environ;
extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int pid_suspend(int pid);
extern int pid_resume(int pid);
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t task_port);

static int gJournalDescriptor = -1;
static int gStateDirectoryDescriptor = -1;
static int gLockDescriptor = -1;
static int gRecoveryDescriptor = -1;
static int gCandidateDescriptor = -1;
static int gCandidateInfoDescriptor = -1;
static struct stat gCandidateStatus;
static struct stat gCandidateInfoStatus;
static char gCandidateRealPath[CODEX_PATH_SIZE];
static char gLaunchctlRealPath[CODEX_PATH_SIZE];
static char gExternalLaunchctlRealPath[CODEX_PATH_SIZE];
static char gWorkerRealPath[CODEX_PATH_SIZE];
static char gPrecursorRealPath[CODEX_PATH_SIZE];
static char gRunToken[37];
static const char *gRole = "controller";
static volatile sig_atomic_t gStopRequested = 0;
static bool gHonorTakeover = true;

static void stop_handler(int signal_number) {
    (void)signal_number;
    gStopRequested = 1;
}

static uint64_t monotonic_msec(void) {
    struct timespec value = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000ULL +
           (uint64_t)value.tv_nsec / 1000000ULL;
}

static bool write_all(int descriptor, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    while (length != 0) {
        ssize_t amount = write(descriptor, cursor, length);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        length -= (size_t)amount;
    }
    return true;
}

static bool journal_event(const char *format, ...) {
    if (gJournalDescriptor < 0 || format == NULL) {
        return false;
    }

    char event[1536];
    va_list arguments;
    va_start(arguments, format);
    int event_length = vsnprintf(event, sizeof(event), format, arguments);
    va_end(arguments);
    if (event_length < 0 || (size_t)event_length >= sizeof(event)) {
        return false;
    }

    struct timespec realtime = {0};
    (void)clock_gettime(CLOCK_REALTIME, &realtime);
    char line[2048];
    int line_length = snprintf(
        line, sizeof(line),
        "magic=%s rt=%lld.%09ld monoMs=%llu pid=%d role=%s token=%s %s\n",
        CODEX_MAGIC, (long long)realtime.tv_sec, realtime.tv_nsec,
        (unsigned long long)monotonic_msec(), getpid(), gRole,
        gRunToken[0] != '\0' ? gRunToken : "none", event);
    if (line_length < 0 || (size_t)line_length >= sizeof(line)) {
        return false;
    }
    return write_all(gJournalDescriptor, line, (size_t)line_length) &&
           fsync(gJournalDescriptor) == 0;
}

static void compact_command_output(const char *source, char *destination,
                                   size_t destination_size) {
    if (destination == NULL || destination_size == 0) {
        return;
    }
    destination[0] = '\0';
    if (source == NULL) {
        return;
    }
    size_t used = 0;
    bool previous_space = false;
    for (size_t index = 0; source[index] != '\0' &&
                           used + 1 < destination_size; ++index) {
        unsigned char byte = (unsigned char)source[index];
        if (byte == '\r' || byte == '\n' || byte == '\t' || byte == ' ') {
            if (!previous_space && used != 0) {
                destination[used++] = ' ';
            }
            previous_space = true;
            continue;
        }
        previous_space = false;
        destination[used++] = byte >= 0x20 && byte <= 0x7e && byte != '"' &&
                                     byte != '\\'
                                 ? (char)byte
                                 : '?';
    }
    while (used != 0 && destination[used - 1] == ' ') {
        --used;
    }
    destination[used] = '\0';
}

static bool command_output_has_exact_line(const char *output,
                                          const char *expected) {
    if (output == NULL || expected == NULL || *expected == '\0') {
        return false;
    }
    size_t expected_length = strlen(expected);
    const char *cursor = output;
    while (*cursor != '\0') {
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

static bool external_candidate_print_is_exact_dormant(const char *output) {
    char header[160];
    char program[CODEX_PATH_SIZE + 16U];
    int header_length = snprintf(header, sizeof(header), "%s = {",
                                 kExternalCandidateTarget);
    int program_length = snprintf(program, sizeof(program), "program = %s",
                                  kCandidatePath);
    return header_length > 0 && (size_t)header_length < sizeof(header) &&
           program_length > 0 &&
           (size_t)program_length < sizeof(program) &&
           command_output_has_exact_line(output, header) &&
           command_output_has_exact_line(output, program) &&
           command_output_has_exact_line(output, "active count = 0") &&
           command_output_has_exact_line(output, "type = Submitted") &&
           command_output_has_exact_line(output, "state = not running") &&
           command_output_has_exact_line(output,
                                         "bundle id = com.apple.springboard") &&
           command_output_has_exact_line(output, "username = mobile") &&
           command_output_has_exact_line(output, "spawn type = app (1)") &&
           strstr(output, "proxy started suspended") == NULL &&
           strstr(output, "uses proxy") == NULL &&
           strstr(output, "needs proxy") == NULL &&
           command_output_has_exact_line(output, "runs = 0");
}

static bool stock_service_print_is_exact(
    const char *output, const struct process_snapshot *stock) {
    if (output == NULL || stock == NULL || stock->pid <= 1) {
        return false;
    }
    char header[160];
    char program[CODEX_PATH_SIZE + 16U];
    char pid_line[64];
    int header_length = snprintf(header, sizeof(header), "%s = {",
                                 kServiceTarget);
    int program_length = snprintf(program, sizeof(program), "program = %s",
                                  kStockPath);
    int pid_length = snprintf(pid_line, sizeof(pid_line), "pid = %d",
                              stock->pid);
    return header_length > 0 && (size_t)header_length < sizeof(header) &&
           program_length > 0 &&
           (size_t)program_length < sizeof(program) && pid_length > 0 &&
           (size_t)pid_length < sizeof(pid_line) &&
           command_output_has_exact_line(output, header) &&
           command_output_has_exact_line(output, "type = LaunchDaemon") &&
           command_output_has_exact_line(output, "state = running") &&
           command_output_has_exact_line(output,
                                         "bundle id = com.apple.springboard") &&
           command_output_has_exact_line(output, program) &&
           command_output_has_exact_line(output, "domain = user/501") &&
           command_output_has_exact_line(output, "username = mobile") &&
           command_output_has_exact_line(output, pid_line) &&
           command_output_has_exact_line(output,
                                         "proxy started suspended = 0") &&
           command_output_has_exact_line(output, "uses proxy = 0") &&
           command_output_has_exact_line(output, "spawn type = app (1)") &&
           strstr(output, "needs proxy") == NULL;
}

static bool secure_existing_regular_file(const char *path, uid_t owner,
                                         bool require_executable,
                                         int *descriptor_out,
                                         struct stat *status_out) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    struct stat status = {0};
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_uid == owner &&
                 status.st_nlink == 1 && (status.st_mode & 0022) == 0 &&
                 (!require_executable || (status.st_mode & 0111) != 0);
    if (!valid) {
        close(descriptor);
        return false;
    }
    if (status_out != NULL) {
        *status_out = status;
    }
    if (descriptor_out != NULL) {
        *descriptor_out = descriptor;
    } else {
        close(descriptor);
    }
    return true;
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

static bool descriptor_has_expected_uuid(int descriptor) {
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
    bool found_uuid = false;
    size_t offset = 0;
    for (uint32_t index = 0; valid && index < header.ncmds; ++index) {
        if (offset > header.sizeofcmds - sizeof(struct load_command)) {
            valid = false;
            break;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > header.sizeofcmds - offset) {
            valid = false;
            break;
        }
        if (command->cmd == LC_UUID) {
            if (found_uuid || command->cmdsize < sizeof(struct uuid_command)) {
                valid = false;
                break;
            }
            const struct uuid_command *uuid_command =
                (const struct uuid_command *)command;
            found_uuid = true;
            valid = memcmp(uuid_command->uuid, kExpectedSpringBoardUUID,
                           sizeof(kExpectedSpringBoardUUID)) == 0;
        }
        offset += command->cmdsize;
    }
    valid = valid && found_uuid && offset == header.sizeofcmds;
    free(commands);
    return valid;
}

static bool file_sha256_exact(const char *path,
                              const uint8_t expected[CODEX_SHA256_SIZE],
                              bool executable, uint64_t expected_size,
                              int *descriptor_out,
                              struct stat *status_out) {
    int descriptor = -1;
    struct stat status = {0};
    if (!secure_existing_regular_file(path, 0, executable, &descriptor,
                                      &status) ||
        (expected_size != 0 && (uint64_t)status.st_size != expected_size)) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return false;
    }
    uint8_t digest[CODEX_SHA256_SIZE] = {0};
    if (!sha256_descriptor(descriptor, digest) ||
        memcmp(digest, expected, sizeof(digest)) != 0) {
        close(descriptor);
        return false;
    }
    if (status_out != NULL) {
        *status_out = status;
    }
    if (descriptor_out != NULL) {
        *descriptor_out = descriptor;
    } else {
        close(descriptor);
    }
    return true;
}

static bool external_launchctl_file_valid(void) {
    return file_sha256_exact(kExternalLaunchctlPath,
                             kExpectedExternalLaunchctlSHA256A, true, 0,
                             NULL, NULL) ||
           file_sha256_exact(kExternalLaunchctlPath,
                             kExpectedExternalLaunchctlSHA256B, true, 0,
                             NULL, NULL);
}

static bool copy_process_path(pid_t pid, char path[CODEX_PATH_SIZE]) {
    memset(path, 0, CODEX_PATH_SIZE);
    if (pid <= 1) {
        return false;
    }
    int length = proc_pidpath(pid, path, CODEX_PATH_SIZE);
    return length > 0 && (size_t)length < CODEX_PATH_SIZE;
}

static bool copy_unique_info(
    pid_t pid, struct codex_proc_uniqidentifierinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information);
}

static bool copy_bsd_info(pid_t pid,
                          struct codex_proc_bsdinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDTBSDINFO, 0, information,
                              (int)sizeof(*information));
    return amount == (int)sizeof(*information) &&
           information->pbi_pid == (uint32_t)pid;
}

static bool unique_identity_equal(
    const struct codex_proc_uniqidentifierinfo *left,
    const struct codex_proc_uniqidentifierinfo *right) {
    return left->unique_id == right->unique_id &&
           left->pid_version == right->pid_version &&
           left->parent_unique_id == right->parent_unique_id &&
           memcmp(left->uuid, right->uuid, sizeof(left->uuid)) == 0;
}

static bool process_generation_equal(
    const struct codex_proc_uniqidentifierinfo *left,
    const struct codex_proc_uniqidentifierinfo *right) {
    return left->unique_id == right->unique_id &&
           left->pid_version == right->pid_version &&
           memcmp(left->uuid, right->uuid, sizeof(left->uuid)) == 0;
}

static bool candidate_path_exact(const char *path) {
    return path != NULL &&
           (strcmp(path, kCandidatePath) == 0 ||
            (gCandidateRealPath[0] != '\0' &&
             strcmp(path, gCandidateRealPath) == 0));
}

static bool launchctl_path_exact(const char *path) {
    return path != NULL &&
           (strcmp(path, kLaunchctlPath) == 0 ||
            (gLaunchctlRealPath[0] != '\0' &&
             strcmp(path, gLaunchctlRealPath) == 0));
}

static bool external_launchctl_path_exact(const char *path) {
    return path != NULL &&
           (strcmp(path, kExternalLaunchctlPath) == 0 ||
            (gExternalLaunchctlRealPath[0] != '\0' &&
             strcmp(path, gExternalLaunchctlRealPath) == 0));
}

static bool any_launchctl_path_exact(const char *path) {
    return launchctl_path_exact(path) ||
           external_launchctl_path_exact(path);
}

static bool launchctl_snapshot_matches_requested_path(
    const char *requested_path, const char *snapshot_path) {
    if (launchctl_path_exact(requested_path)) {
        return launchctl_path_exact(snapshot_path);
    }
    return external_launchctl_path_exact(requested_path) &&
           external_launchctl_path_exact(snapshot_path);
}

static bool worker_path_exact(const char *path) {
    return path != NULL &&
           (strcmp(path, kWorkerPath) == 0 ||
            (gWorkerRealPath[0] != '\0' &&
             strcmp(path, gWorkerRealPath) == 0));
}

static bool precursor_argument_exact(const char *path) {
    if (path == NULL) {
        return false;
    }
    if (strcmp(path, kPrecursorPath) == 0) {
        return true;
    }
    char resolved[CODEX_PATH_SIZE] = {0};
    return realpath(path, resolved) != NULL &&
           gPrecursorRealPath[0] != '\0' &&
           strcmp(resolved, gPrecursorRealPath) == 0;
}

static bool read_controller_snapshot(pid_t pid,
                                     struct process_snapshot *snapshot) {
    if (snapshot == NULL || pid <= 1) {
        return false;
    }
    struct process_snapshot first = {.pid = pid};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    if (!copy_process_path(pid, first.path) ||
        !worker_path_exact(first.path) || !copy_bsd_info(pid, &first.bsd) ||
        first.bsd.pbi_uid != 0 || !copy_unique_info(pid, &first.unique) ||
        !copy_process_path(pid, second_path) ||
        strcmp(first.path, second_path) != 0 ||
        !copy_unique_info(pid, &second_unique) ||
        !unique_identity_equal(&first.unique, &second_unique)) {
        return false;
    }
    *snapshot = first;
    return true;
}

static bool controller_snapshot_still_exact(
    const struct process_snapshot *expected) {
    if (expected == NULL || expected->pid <= 1) {
        return false;
    }
    struct process_snapshot current = {0};
    return read_controller_snapshot(expected->pid, &current) &&
           current.pid == expected->pid &&
           strcmp(current.path, expected->path) == 0 &&
           process_generation_equal(&current.unique, &expected->unique);
}

static bool candidate_path_still_bound(void) {
    if (gCandidateDescriptor < 0 || gCandidateInfoDescriptor < 0) {
        return false;
    }
    struct stat held = {0};
    struct stat current = {0};
    struct stat held_info = {0};
    struct stat current_info = {0};
    int descriptor = -1;
    int info_descriptor = -1;
    uint8_t candidate_digest[CODEX_SHA256_SIZE] = {0};
    uint8_t info_digest[CODEX_SHA256_SIZE] = {0};
    bool valid = fstat(gCandidateDescriptor, &held) == 0 &&
                 fstat(gCandidateInfoDescriptor, &held_info) == 0 &&
                 secure_existing_regular_file(kCandidatePath, 0, true,
                                              &descriptor, &current) &&
                 secure_existing_regular_file(kCandidateInfoPath, 0, false,
                                              &info_descriptor,
                                              &current_info) &&
                 held.st_dev == current.st_dev && held.st_ino == current.st_ino &&
                 held.st_size == current.st_size &&
                 held_info.st_dev == current_info.st_dev &&
                 held_info.st_ino == current_info.st_ino &&
                 held_info.st_size == current_info.st_size &&
                 sha256_descriptor(gCandidateDescriptor, candidate_digest) &&
                 memcmp(candidate_digest, kExpectedCandidateSHA256,
                        sizeof(candidate_digest)) == 0 &&
                 sha256_descriptor(gCandidateInfoDescriptor, info_digest) &&
                 memcmp(info_digest, kExpectedInfoSHA256,
                        sizeof(info_digest)) == 0;
    if (descriptor >= 0) {
        close(descriptor);
    }
    if (info_descriptor >= 0) {
        close(info_descriptor);
    }
    return valid;
}

static bool read_stock_snapshot(pid_t pid, struct process_snapshot *snapshot) {
    if (snapshot == NULL || pid <= 1) {
        return false;
    }
    struct process_snapshot first = {.pid = pid};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    if (!copy_process_path(pid, first.path) ||
        strcmp(first.path, kStockPath) != 0 ||
        !copy_bsd_info(pid, &first.bsd) || first.bsd.pbi_uid != 501 ||
        first.bsd.pbi_ppid != 1 || !copy_unique_info(pid, &first.unique) ||
        memcmp(first.unique.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) != 0 ||
        csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) != 0 ||
        (flags & CODEX_CS_VALID) == 0 ||
        csops(pid, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) != 0 ||
        !copy_process_path(pid, second_path) ||
        strcmp(first.path, second_path) != 0 ||
        !copy_unique_info(pid, &second_unique) ||
        !unique_identity_equal(&first.unique, &second_unique)) {
        return false;
    }
    first.cs_flags = flags;
    memcpy(first.cdhash, cdhash, sizeof(first.cdhash));
    *snapshot = first;
    return true;
}

static bool read_candidate_snapshot(pid_t pid,
                                    struct process_snapshot *snapshot,
                                    uint32_t *flags_out) {
    if (snapshot == NULL || pid <= 1 || !candidate_path_still_bound()) {
        return false;
    }
    struct process_snapshot first = {.pid = pid};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    if (!copy_process_path(pid, first.path) ||
        !candidate_path_exact(first.path) ||
        !copy_bsd_info(pid, &first.bsd) || first.bsd.pbi_uid != 501 ||
        first.bsd.pbi_ppid != 1 || !copy_unique_info(pid, &first.unique) ||
        memcmp(first.unique.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) != 0 ||
        csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) != 0 ||
        (flags & CODEX_CS_VALID) == 0 ||
        csops(pid, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) != 0 ||
        memcmp(cdhash, kExpectedCandidateCDHash, sizeof(cdhash)) != 0 ||
        !copy_process_path(pid, second_path) ||
        strcmp(first.path, second_path) != 0 ||
        !copy_unique_info(pid, &second_unique) ||
        !unique_identity_equal(&first.unique, &second_unique)) {
        return false;
    }
    first.cs_flags = flags;
    memcpy(first.cdhash, cdhash, sizeof(first.cdhash));
    *snapshot = first;
    if (flags_out != NULL) {
        *flags_out = flags;
    }
    return true;
}

static bool snapshot_still_exact(const struct process_snapshot *expected,
                                 enum process_kind kind,
                                 uint32_t *flags_out) {
    if (expected == NULL || expected->pid <= 1) {
        return false;
    }
    struct process_snapshot current = {0};
    uint32_t flags = 0;
    bool valid = kind == PROCESS_STOCK
                     ? read_stock_snapshot(expected->pid, &current)
                     : read_candidate_snapshot(expected->pid, &current,
                                               &flags);
    valid = valid && current.pid == expected->pid &&
            current.bsd.pbi_uid == expected->bsd.pbi_uid &&
            current.bsd.pbi_ppid == expected->bsd.pbi_ppid &&
            strcmp(current.path, expected->path) == 0 &&
            unique_identity_equal(&current.unique, &expected->unique) &&
            (kind != PROCESS_STOCK ||
             (current.cs_flags == expected->cs_flags &&
              memcmp(current.cdhash, expected->cdhash,
                     sizeof(current.cdhash)) == 0));
    if (valid && flags_out != NULL) {
        *flags_out = flags;
    }
    return valid;
}

static int list_all_pids(pid_t **pids_out) {
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

static bool count_process_paths(int *stock_count, pid_t *stock_pid,
                                int *candidate_count,
                                pid_t *candidate_pid) {
    *stock_count = 0;
    *stock_pid = -1;
    *candidate_count = 0;
    *candidate_pid = -1;
    pid_t *pids = NULL;
    int count = list_all_pids(&pids);
    if (count < 0) {
        return false;
    }
    for (int index = 0; index < count; ++index) {
        if (pids[index] <= 1) {
            continue;
        }
        char path[CODEX_PATH_SIZE] = {0};
        if (!copy_process_path(pids[index], path)) {
            continue;
        }
        if (strcmp(path, kStockPath) == 0) {
            ++*stock_count;
            *stock_pid = pids[index];
        }
        if (candidate_path_exact(path)) {
            ++*candidate_count;
            *candidate_pid = pids[index];
        }
    }
    free(pids);
    return true;
}

static bool find_unique_stock(struct process_snapshot *snapshot) {
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    return count_process_paths(&stock_count, &stock_pid, &candidate_count,
                               &candidate_pid) &&
           stock_count == 1 && candidate_count == 0 && stock_pid > 1 &&
           read_stock_snapshot(stock_pid, snapshot) &&
           snapshot_still_exact(snapshot, PROCESS_STOCK, NULL);
}

static bool candidate_process_absent(void) {
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    return count_process_paths(&stock_count, &stock_pid, &candidate_count,
                               &candidate_pid) &&
           candidate_count == 0;
}

static bool stock_and_candidate_processes_absent(void) {
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    return count_process_paths(&stock_count, &stock_pid, &candidate_count,
                               &candidate_pid) &&
           stock_count == 0 && candidate_count == 0;
}

static bool wait_for_stock_and_candidate_processes_absent(
    uint64_t timeout_msec) {
    uint64_t deadline = monotonic_msec() + timeout_msec;
    do {
        if (stock_and_candidate_processes_absent()) {
            return true;
        }
        if (gStopRequested) {
            return false;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);
    return false;
}

static bool original_stock_still_unique(
    const struct process_snapshot *original) {
    struct process_snapshot current = {0};
    return original != NULL && find_unique_stock(&current) &&
           current.pid == original->pid &&
           strcmp(current.path, original->path) == 0 &&
           unique_identity_equal(&current.unique, &original->unique) &&
           snapshot_still_exact(original, PROCESS_STOCK, NULL);
}

/* expected_candidate_count may be -1 to admit either zero or one candidate
   while still rejecting duplicate candidate or stock generations. */
static bool original_stock_still_exact_with_candidate_count(
    const struct process_snapshot *original, int expected_candidate_count) {
    if (original == NULL || original->pid <= 1 ||
        (expected_candidate_count < -1 || expected_candidate_count > 1)) {
        return false;
    }
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    bool candidate_count_exact = false;
    if (!count_process_paths(&stock_count, &stock_pid, &candidate_count,
                             &candidate_pid)) {
        return false;
    }
    candidate_count_exact =
        expected_candidate_count < 0
            ? candidate_count >= 0 && candidate_count <= 1
            : candidate_count == expected_candidate_count;
    return stock_count == 1 && stock_pid == original->pid &&
           candidate_count_exact &&
           snapshot_still_exact(original, PROCESS_STOCK, NULL);
}

static bool candidate_snapshot_still_exact_and_stopped(
    const struct process_snapshot *expected, uint32_t *flags_out) {
    if (expected == NULL || expected->pid <= 1 ||
        expected->bsd.pbi_status != CODEX_PROC_STATUS_STOPPED) {
        return false;
    }
    struct process_snapshot current = {0};
    uint32_t flags = 0;
    bool exact = read_candidate_snapshot(expected->pid, &current, &flags) &&
                 current.pid == expected->pid &&
                 current.bsd.pbi_uid == expected->bsd.pbi_uid &&
                 current.bsd.pbi_ppid == expected->bsd.pbi_ppid &&
                 current.bsd.pbi_status == CODEX_PROC_STATUS_STOPPED &&
                 strcmp(current.path, expected->path) == 0 &&
                 unique_identity_equal(&current.unique, &expected->unique) &&
                 current.cs_flags == expected->cs_flags &&
                 memcmp(current.cdhash, expected->cdhash,
                        sizeof(current.cdhash)) == 0;
    if (exact && flags_out != NULL) {
        *flags_out = flags;
    }
    return exact;
}

static bool find_parallel_returned_candidate(
    pid_t returned_pid, const struct process_snapshot *original_stock,
    struct process_snapshot *candidate_out, uint32_t *flags_out) {
    if (returned_pid <= 1 || original_stock == NULL ||
        candidate_out == NULL ||
        !original_stock_still_exact_with_candidate_count(original_stock, 1)) {
        return false;
    }
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    struct process_snapshot candidate = {0};
    uint32_t flags = 0;
    bool valid = count_process_paths(&stock_count, &stock_pid,
                                     &candidate_count, &candidate_pid) &&
                 stock_count == 1 && stock_pid == original_stock->pid &&
                 candidate_count == 1 && candidate_pid == returned_pid &&
                 read_candidate_snapshot(returned_pid, &candidate, &flags) &&
                 candidate.bsd.pbi_status == CODEX_PROC_STATUS_STOPPED &&
                 candidate_snapshot_still_exact_and_stopped(
                     &candidate, &flags) &&
                 original_stock_still_exact_with_candidate_count(
                     original_stock, 1);
    if (valid) {
        *candidate_out = candidate;
        if (flags_out != NULL) {
            *flags_out = flags;
        }
    }
    return valid;
}

static bool find_returned_candidate(pid_t returned_pid,
                                    struct process_snapshot *snapshot,
                                    uint32_t *flags_out) {
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    return returned_pid > 1 &&
           count_process_paths(&stock_count, &stock_pid, &candidate_count,
                               &candidate_pid) &&
           stock_count == 0 && candidate_count == 1 &&
           candidate_pid == returned_pid &&
           read_candidate_snapshot(returned_pid, snapshot, flags_out) &&
           snapshot_still_exact(snapshot, PROCESS_CANDIDATE, flags_out);
}

static bool candidate_snapshot_still_unique(
    const struct process_snapshot *expected, uint32_t *flags_out) {
    if (expected == NULL || expected->pid <= 1) {
        return false;
    }
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    return count_process_paths(&stock_count, &stock_pid, &candidate_count,
                               &candidate_pid) &&
           stock_count == 0 && candidate_count == 1 &&
           candidate_pid == expected->pid &&
           snapshot_still_exact(expected, PROCESS_CANDIDATE, flags_out);
}

static bool candidate_debug_policy_still_exact(
    const struct process_snapshot *expected, uint32_t *flags_out) {
    uint32_t flags = 0;
    bool valid = candidate_snapshot_still_unique(expected, &flags) &&
                 (flags & CODEX_CS_DEBUGGED) != 0 &&
                 (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    if (valid && flags_out != NULL) {
        *flags_out = flags;
    }
    return valid;
}

/* The legacy takeover proof intentionally admits a candidate only after stock
   SpringBoard is absent.  Parallel proof mode needs the inverse invariant:
   retain the exact original stock generation and exactly one exact candidate
   throughout every ptrace, task-port, and loader operation. */
static bool parallel_candidate_snapshot_still_unique(
    const struct process_snapshot *expected,
    const struct process_snapshot *original_stock, uint32_t *flags_out) {
    if (expected == NULL || expected->pid <= 1 || original_stock == NULL ||
        original_stock->pid <= 1 || expected->pid == original_stock->pid ||
        !original_stock_still_exact_with_candidate_count(original_stock, 1)) {
        return false;
    }
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    uint32_t flags = 0;
    bool valid = count_process_paths(&stock_count, &stock_pid,
                                     &candidate_count, &candidate_pid) &&
                 stock_count == 1 && stock_pid == original_stock->pid &&
                 candidate_count == 1 && candidate_pid == expected->pid &&
                 snapshot_still_exact(expected, PROCESS_CANDIDATE, &flags) &&
                 original_stock_still_exact_with_candidate_count(
                     original_stock, 1);
    if (valid && flags_out != NULL) {
        *flags_out = flags;
    }
    return valid;
}

static bool candidate_snapshot_still_unique_for_mode(
    const struct process_snapshot *expected,
    const struct process_snapshot *original_stock, uint32_t *flags_out) {
    return original_stock != NULL
               ? parallel_candidate_snapshot_still_unique(
                     expected, original_stock, flags_out)
               : candidate_snapshot_still_unique(expected, flags_out);
}

static bool candidate_debug_policy_still_exact_for_mode(
    const struct process_snapshot *expected,
    const struct process_snapshot *original_stock, uint32_t *flags_out) {
    uint32_t flags = 0;
    bool valid = candidate_snapshot_still_unique_for_mode(
                     expected, original_stock, &flags) &&
                 (flags & CODEX_CS_DEBUGGED) != 0 &&
                 (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    if (valid && flags_out != NULL) {
        *flags_out = flags;
    }
    return valid;
}

static bool helper_snapshot(pid_t pid, const char *requested_path,
                            struct process_snapshot *snapshot) {
    if (snapshot == NULL || pid <= 1 || requested_path == NULL) {
        return false;
    }
    struct process_snapshot first = {.pid = pid};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    return copy_process_path(pid, first.path) &&
           launchctl_snapshot_matches_requested_path(requested_path,
                                                     first.path) &&
           copy_bsd_info(pid, &first.bsd) && first.bsd.pbi_uid == 0 &&
           first.bsd.pbi_ppid == (uint32_t)getpid() &&
           copy_unique_info(pid, &first.unique) &&
           copy_process_path(pid, second_path) &&
           strcmp(first.path, second_path) == 0 &&
           copy_unique_info(pid, &second_unique) &&
           unique_identity_equal(&first.unique, &second_unique) &&
           ((*snapshot = first), true);
}

static bool helper_still_exact(const struct process_snapshot *expected,
                               const char *requested_path) {
    if (expected == NULL || expected->pid <= 1 || requested_path == NULL) {
        return false;
    }
    struct process_snapshot current = {0};
    return expected->bsd.pbi_status == CODEX_PROC_STATUS_STOPPED &&
           helper_snapshot(expected->pid, requested_path, &current) &&
           current.bsd.pbi_status == CODEX_PROC_STATUS_STOPPED &&
           current.bsd.pbi_uid == expected->bsd.pbi_uid &&
           current.bsd.pbi_ppid == expected->bsd.pbi_ppid &&
           strcmp(current.path, expected->path) == 0 &&
           unique_identity_equal(&current.unique, &expected->unique);
}

static bool marker_exists(const char *prefix);
static bool publish_helper_record(
    const struct process_snapshot *helper, const char *phase,
    struct helper_record *record_out);
static bool clear_helper_record(const struct helper_record *expected);

static bool takeover_requested(void) {
    return gHonorTakeover && marker_exists("takeover");
}

static void set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL);
    if (flags >= 0) {
        (void)fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
    }
}

static void set_close_on_exec(int descriptor) {
    int flags = fcntl(descriptor, F_GETFD);
    if (flags >= 0) {
        (void)fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC);
    }
}

static void drain_descriptor(int descriptor, char *output, size_t capacity,
                             size_t *used, bool *truncated) {
    uint8_t temporary[1024];
    for (;;) {
        ssize_t amount = read(descriptor, temporary, sizeof(temporary));
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            break;
        }
        size_t available = *used < capacity - 1U
                               ? capacity - 1U - *used
                               : 0;
        size_t copied = (size_t)amount < available ? (size_t)amount
                                                   : available;
        if (copied != 0) {
            memcpy(output + *used, temporary, copied);
            *used += copied;
            output[*used] = '\0';
        }
        if ((size_t)amount > copied && truncated != NULL) {
            *truncated = true;
        }
    }
}

static bool wait_for_owned_stop(
    pid_t pid, uint64_t timeout_msec, int *status_out) {
    uint64_t deadline = monotonic_msec() + timeout_msec;
    do {
        int status = 0;
        pid_t result = waitpid(pid, &status, WUNTRACED | WNOHANG);
        if (result == pid) {
            if (status_out != NULL) {
                *status_out = status;
            }
            return WIFSTOPPED(status) &&
                   (WSTOPSIG(status) == 0 || WSTOPSIG(status) == SIGSTOP);
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    } while (monotonic_msec() < deadline);
    return false;
}

static bool terminate_and_reap_owned_child(pid_t child, int *status_out) {
    if (child <= 1) {
        return false;
    }

    int status = 0;
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child || (waited < 0 && errno == ECHILD)) {
        if (status_out != NULL && waited == child) {
            *status_out = status;
        }
        return true;
    }
    if (waited < 0 && errno != EINTR) {
        return false;
    }

    (void)kill(child, SIGTERM);
    uint64_t deadline = monotonic_msec() + CODEX_HELPER_TERMINATE_MSEC;
    while (monotonic_msec() < deadline) {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            if (status_out != NULL && waited == child) {
                *status_out = status;
            }
            return true;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    }

    /* An unreaped direct child still owns its PID, so this signal cannot hit
       a recycled process even if path inspection is temporarily unavailable. */
    (void)kill(child, SIGKILL);
    deadline = monotonic_msec() + CODEX_HELPER_KILL_MSEC;
    while (monotonic_msec() < deadline) {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            if (status_out != NULL && waited == child) {
                *status_out = status;
            }
            return true;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    }
    return false;
}

static struct command_result run_launchctl(char *const arguments[],
                                           uint64_t timeout_msec) {
    struct command_result result;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    result.wait_status = -1;

    if (arguments == NULL || arguments[0] == NULL || arguments[1] == NULL ||
        !any_launchctl_path_exact(arguments[0]) || takeover_requested()) {
        result.spawn_error = ECANCELED;
        return result;
    }

    int standard_output_pipe[2] = {-1, -1};
    int standard_error_pipe[2] = {-1, -1};
    if (pipe(standard_output_pipe) != 0 || pipe(standard_error_pipe) != 0) {
        result.spawn_error = errno;
        goto finished;
    }
    for (size_t index = 0; index < 2; ++index) {
        set_close_on_exec(standard_output_pipe[index]);
        set_close_on_exec(standard_error_pipe[index]);
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
        &actions, standard_output_pipe[1], STDOUT_FILENO);
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, standard_error_pipe[1], STDERR_FILENO);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addclose(
            &actions, standard_output_pipe[0]);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addclose(
            &actions, standard_error_pipe[0]);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setflags(
            &attributes, POSIX_SPAWN_START_SUSPENDED);
    }

    pid_t child = -1;
    result.spawn_error = setup_result == 0
                             ? posix_spawn(&child, arguments[0], &actions,
                                           &attributes, arguments,
                                           environ)
                             : setup_result;
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)posix_spawnattr_destroy(&attributes);
    close(standard_output_pipe[1]);
    standard_output_pipe[1] = -1;
    close(standard_error_pipe[1]);
    standard_error_pipe[1] = -1;
    if (result.spawn_error != 0 || child <= 1) {
        goto finished;
    }

    struct helper_record helper_record = {0};
    struct process_snapshot helper = {0};
    bool helper_record_published = false;
    bool reaped = false;
    bool stopped = wait_for_owned_stop(
        child, CODEX_HELPER_TERMINATE_MSEC, &result.wait_status);
    if (!stopped || takeover_requested() ||
        !helper_snapshot(child, arguments[0], &helper)) {
        result.spawn_error = takeover_requested() ? ECANCELED : EPROTO;
    } else if (!publish_helper_record(&helper, arguments[1],
                                      &helper_record)) {
        result.spawn_error = EIO;
    } else {
        helper_record_published = true;
        if (takeover_requested() ||
            !helper_still_exact(&helper, arguments[0])) {
            result.spawn_error = takeover_requested() ? ECANCELED : EPROTO;
        } else if (kill(child, SIGCONT) != 0) {
            result.spawn_error = errno;
        }
    }

    if (result.spawn_error != 0) {
        reaped = terminate_and_reap_owned_child(
            child, &result.wait_status);
        if (helper_record_published && reaped &&
            !clear_helper_record(&helper_record)) {
            result.spawn_error = EIO;
        }
        goto finished;
    }

    set_nonblocking(standard_output_pipe[0]);
    set_nonblocking(standard_error_pipe[0]);
    size_t standard_output_used = 0;
    size_t standard_error_used = 0;
    uint64_t deadline = monotonic_msec() + timeout_msec;
    while (!reaped && monotonic_msec() < deadline && !gStopRequested) {
        drain_descriptor(standard_output_pipe[0], result.standard_output,
                         sizeof(result.standard_output),
                         &standard_output_used,
                         &result.standard_output_truncated);
        drain_descriptor(standard_error_pipe[0], result.standard_error,
                         sizeof(result.standard_error),
                         &standard_error_used,
                         &result.standard_error_truncated);
        pid_t waited = waitpid(child, &result.wait_status, WNOHANG);
        if (waited == child) {
            reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        usleep(10U * 1000U);
    }

    if (!reaped) {
        result.timed_out = true;
        reaped = terminate_and_reap_owned_child(child, &result.wait_status);
    }

    if (helper_record_published && reaped &&
        !clear_helper_record(&helper_record)) {
        result.spawn_error = EIO;
    }

    drain_descriptor(standard_output_pipe[0], result.standard_output,
                     sizeof(result.standard_output), &standard_output_used,
                     &result.standard_output_truncated);
    drain_descriptor(standard_error_pipe[0], result.standard_error,
                     sizeof(result.standard_error), &standard_error_used,
                     &result.standard_error_truncated);
    if (reaped && WIFEXITED(result.wait_status)) {
        result.exit_code = WEXITSTATUS(result.wait_status);
    }

finished:
    for (size_t index = 0; index < 2; ++index) {
        if (standard_output_pipe[index] >= 0) {
            close(standard_output_pipe[index]);
        }
        if (standard_error_pipe[index] >= 0) {
            close(standard_error_pipe[index]);
        }
    }
    return result;
}

static bool command_succeeded(const struct command_result *result) {
    return result != NULL && result->spawn_error == 0 &&
           !result->timed_out && WIFEXITED(result->wait_status) &&
           result->exit_code == 0;
}

static bool command_completed(const struct command_result *result) {
    return result != NULL && result->spawn_error == 0 &&
           !result->timed_out && WIFEXITED(result->wait_status);
}

static void terminate_injection_process_group(pid_t child) {
    if (child <= 1) {
        return;
    }
    (void)kill(-child, SIGTERM);
    uint64_t deadline = monotonic_msec() + 500U;
    int status = 0;
    do {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            return;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);
    (void)kill(-child, SIGKILL);
    deadline = monotonic_msec() + CODEX_HELPER_KILL_MSEC;
    do {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            return;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);
}

static int run_candidate_loader_injection(
    const struct process_snapshot *candidate, const char *dylib_path,
    const struct process_snapshot *original_stock) {
    if (candidate == NULL || candidate->pid <= 1 || dylib_path == NULL ||
        !candidate_debug_policy_still_exact_for_mode(
            candidate, original_stock, NULL) ||
        !secure_existing_regular_file(kWorkerPath, 0, true, NULL, NULL) ||
        !secure_existing_regular_file(kLoaderCandidatePath, 0, true, NULL,
                                      NULL) ||
        !secure_existing_regular_file(dylib_path, 0, false, NULL, NULL)) {
        return 80;
    }

    task_t target_task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(
        mach_task_self(), candidate->pid, &target_task);
    if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(target_task)) {
        (void)journal_event("event=inject-task-port target=%d kr=%d valid=0",
                            candidate->pid, task_result);
        return 81;
    }

    char pid_text[24];
    int pid_length = snprintf(pid_text, sizeof(pid_text), "%d",
                              candidate->pid);
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int actions_result = posix_spawn_file_actions_init(&actions);
    int attributes_result = posix_spawnattr_init(&attributes);
    int setup_result = actions_result != 0 ? actions_result
                                           : attributes_result;
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, gJournalDescriptor, STDOUT_FILENO);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, gJournalDescriptor, STDERR_FILENO);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setflags(
            &attributes, POSIX_SPAWN_SETPGROUP);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_set_ptrauth_task_port_np(
            &attributes, target_task);
    }

    char *arguments[] = {
        (char *)kWorkerPath,
        (char *)"--macho",
        (char *)kLoaderCandidatePath,
        (char *)"--inject-pid",
        pid_text,
        (char *)dylib_path,
        (char *)"--ptrauth-child",
        NULL,
    };
    pid_t child = -1;
    int spawn_result =
        setup_result == 0 && pid_length > 0 &&
                (size_t)pid_length < sizeof(pid_text)
            ? posix_spawn(&child, kWorkerPath, &actions, &attributes,
                          arguments, environ)
            : (setup_result != 0 ? setup_result : EINVAL);
    if (actions_result == 0) {
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    if (attributes_result == 0) {
        (void)posix_spawnattr_destroy(&attributes);
    }
    (void)mach_port_deallocate(mach_task_self(), target_task);
    (void)journal_event("event=inject-worker-spawn target=%d child=%d "
                        "spawn=%d path=%s",
                        candidate->pid, child, spawn_result, dylib_path);
    if (spawn_result != 0 || child <= 1 || getpgid(child) != child) {
        if (child > 1) {
            (void)kill(child, SIGKILL);
            (void)waitpid(child, NULL, 0);
        }
        return 82;
    }

    int status = 0;
    bool complete = false;
    bool candidate_exact = true;
    uint64_t deadline = monotonic_msec() + CODEX_INJECTION_TIMEOUT_MSEC;
    do {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            complete = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        candidate_exact = candidate_debug_policy_still_exact_for_mode(
            candidate, original_stock, NULL);
        if (!candidate_exact || gStopRequested || takeover_requested()) {
            break;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);

    if (!complete) {
        terminate_injection_process_group(child);
    }
    int result = complete && WIFEXITED(status) ? WEXITSTATUS(status) : 83;
    (void)journal_event("event=inject-worker-final target=%d child=%d "
                        "complete=%d candidateExact=%d status=0x%x "
                        "result=%d path=%s",
                        candidate->pid, child, complete, candidate_exact,
                        status, result, dylib_path);
    return result;
}

static bool parse_printed_pid(const char *text, pid_t *pid_out) {
    if (text == NULL || pid_out == NULL) {
        return false;
    }
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        ++text;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || value <= 1 || value > INT32_MAX) {
        return false;
    }
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
        ++end;
    }
    if (*end != '\0') {
        return false;
    }
    *pid_out = (pid_t)value;
    return true;
}

static bool parse_zero_pid_sentinel(const char *text) {
    if (text == NULL) {
        return false;
    }
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        ++text;
    }
    if (*text++ != '0') {
        return false;
    }
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        ++text;
    }
    return *text == '\0';
}

static struct command_result debug_program(const char *program,
                                           bool start_suspended) {
    char *arguments_with_suspend[] = {
        (char *)kLaunchctlPath,
        (char *)"debug",
        (char *)kServiceTarget,
        (char *)"--program",
        (char *)program,
        (char *)"--start-suspended",
        (char *)"--",
        (char *)program,
        NULL,
    };
    char *arguments_without_suspend[] = {
        (char *)kLaunchctlPath,
        (char *)"debug",
        (char *)kServiceTarget,
        (char *)"--program",
        (char *)program,
        (char *)"--",
        (char *)program,
        NULL,
    };
    return run_launchctl(start_suspended ? arguments_with_suspend
                                        : arguments_without_suspend,
                         CODEX_COMMAND_TIMEOUT_MSEC);
}

static struct command_result kickstart_service(bool kill_existing) {
    char *arguments_kill[] = {
        (char *)kLaunchctlPath, (char *)"kickstart", (char *)"-k",
        (char *)"-p", (char *)kServiceTarget, NULL,
    };
    char *arguments_start[] = {
        (char *)kLaunchctlPath, (char *)"kickstart", (char *)"-p",
        (char *)kServiceTarget, NULL,
    };
    return run_launchctl(kill_existing ? arguments_kill : arguments_start,
                         CODEX_COMMAND_TIMEOUT_MSEC);
}

static struct command_result print_external_candidate_service(void) {
    char *arguments[] = {
        (char *)kExternalLaunchctlPath, (char *)"print",
        (char *)kExternalCandidateTarget, NULL,
    };
    return run_launchctl(arguments, CODEX_COMMAND_TIMEOUT_MSEC);
}

static struct command_result print_stock_service(void) {
    char *arguments[] = {
        (char *)kExternalLaunchctlPath, (char *)"print",
        (char *)kServiceTarget, NULL,
    };
    return run_launchctl(arguments, CODEX_COMMAND_TIMEOUT_MSEC);
}

static bool stock_service_and_snapshot_exact(
    const struct process_snapshot *original_stock,
    int expected_candidate_count, const char *phase) {
    struct command_result print_result;
    memset(&print_result, 0, sizeof(print_result));
    print_result.exit_code = -1;
    print_result.wait_status = -1;
    bool before_exact = original_stock_still_exact_with_candidate_count(
        original_stock, expected_candidate_count);
    bool launchctl_valid = external_launchctl_file_valid();
    if (before_exact && launchctl_valid) {
        print_result = print_stock_service();
    }
    bool print_exact = command_succeeded(&print_result) &&
                       !print_result.standard_output_truncated &&
                       !print_result.standard_error_truncated &&
                       print_result.standard_error[0] == '\0' &&
                       stock_service_print_is_exact(
                           print_result.standard_output, original_stock);
    bool after_exact = original_stock_still_exact_with_candidate_count(
        original_stock, expected_candidate_count);
    char print_output[512];
    char print_error[512];
    compact_command_output(print_result.standard_output, print_output,
                           sizeof(print_output));
    compact_command_output(print_result.standard_error, print_error,
                           sizeof(print_error));
    bool exact = before_exact && launchctl_valid && print_exact && after_exact;
    (void)journal_event(
        "event=parallel-stock-service-check phase=%s beforeExact=%d "
        "afterExact=%d expectedCandidateCount=%d launchctlValid=%d "
        "spawn=%d timeout=%d exit=%d stdoutTruncated=%d "
        "stderrTruncated=%d printExact=%d "
        "stockPid=%d stockPidVersion=%d stockUniqueId=%llu "
        "stockCsFlags=0x%08x "
        "stdout=\"%s\" stderr=\"%s\" exact=%d stockMutated=0",
        phase != NULL ? phase : "unspecified", before_exact, after_exact,
        expected_candidate_count, launchctl_valid, print_result.spawn_error,
        print_result.timed_out, print_result.exit_code,
        print_result.standard_output_truncated,
        print_result.standard_error_truncated,
        print_exact,
        original_stock != NULL ? original_stock->pid : -1,
        original_stock != NULL ? original_stock->unique.pid_version : -1,
        original_stock != NULL
            ? (unsigned long long)original_stock->unique.unique_id
            : 0ULL,
        original_stock != NULL ? original_stock->cs_flags : 0U,
        print_output, print_error, exact);
    return exact;
}

static struct command_result bootout_external_candidate_service(void) {
    char *arguments[] = {
        (char *)kExternalLaunchctlPath, (char *)"bootout",
        (char *)kExternalCandidateTarget, NULL,
    };
    return run_launchctl(arguments, CODEX_COMMAND_TIMEOUT_MSEC);
}

static struct command_result kickstart_external_candidate_service(void) {
    char *arguments[] = {
        (char *)kExternalLaunchctlPath, (char *)"kickstart", (char *)"-p",
        (char *)"-s", (char *)kExternalCandidateTarget, NULL,
    };
    return run_launchctl(arguments, CODEX_COMMAND_TIMEOUT_MSEC);
}

static struct command_result bootout_stock_service(void) {
    char *arguments[] = {
        (char *)kExternalLaunchctlPath, (char *)"bootout",
        (char *)kServiceTarget, NULL,
    };
    return run_launchctl(arguments, CODEX_COMMAND_TIMEOUT_MSEC);
}

static struct command_result bootstrap_external_stock_service(void) {
    char *arguments[] = {
        (char *)kExternalLaunchctlPath,
        (char *)"bootstrap",
        (char *)"user/501",
        (char *)kSystemPlistPath,
        NULL,
    };
    return run_launchctl(arguments, CODEX_COMMAND_TIMEOUT_MSEC);
}

static struct command_result kickstart_external_stock_service(void) {
    char *arguments[] = {
        (char *)kExternalLaunchctlPath,
        (char *)"kickstart",
        (char *)"-p",
        (char *)kServiceTarget,
        NULL,
    };
    return run_launchctl(arguments, CODEX_COMMAND_TIMEOUT_MSEC);
}

static bool watchdog_disarmed(void);

static bool wait_for_stock(uint64_t timeout_msec, bool stop_if_disarmed,
                           struct process_snapshot *stock_out) {
    uint64_t deadline = monotonic_msec() + timeout_msec;
    do {
        struct process_snapshot stock = {0};
        if (find_unique_stock(&stock)) {
            if (stock_out != NULL) {
                *stock_out = stock;
            }
            return true;
        }
        if ((stop_if_disarmed && watchdog_disarmed()) || gStopRequested) {
            return false;
        }
        usleep(50U * 1000U);
    } while (monotonic_msec() < deadline);
    return false;
}

static bool primary_restore_stock(bool stop_if_disarmed,
                                  struct process_snapshot *stock_out) {
    if (stop_if_disarmed && watchdog_disarmed()) {
        return find_unique_stock(stock_out);
    }
    struct command_result debug = debug_program(kStockPath, false);
    (void)journal_event("event=restore-debug-stock spawn=%d timeout=%d "
                        "exit=%d",
                        debug.spawn_error, debug.timed_out, debug.exit_code);
    if (!command_succeeded(&debug)) {
        return false;
    }
    if (stop_if_disarmed && watchdog_disarmed()) {
        return find_unique_stock(stock_out);
    }
    struct command_result kickstart = kickstart_service(true);
    (void)journal_event("event=restore-kickstart-stock spawn=%d timeout=%d "
                        "exit=%d",
                        kickstart.spawn_error, kickstart.timed_out,
                        kickstart.exit_code);
    return command_succeeded(&kickstart) &&
           wait_for_stock(CODEX_RESTORE_VERIFY_MSEC, stop_if_disarmed,
                          stock_out);
}

static bool fallback_restore_stock(bool stop_if_disarmed,
                                   struct process_snapshot *stock_out) {
    if (stop_if_disarmed && watchdog_disarmed()) {
        return find_unique_stock(stock_out);
    }
    char *bootout_arguments[] = {
        (char *)kLaunchctlPath, (char *)"bootout", (char *)kServiceTarget,
        NULL,
    };
    struct command_result bootout = run_launchctl(
        bootout_arguments, CODEX_COMMAND_TIMEOUT_MSEC);
    (void)journal_event("event=fallback-bootout spawn=%d timeout=%d exit=%d",
                        bootout.spawn_error, bootout.timed_out,
                        bootout.exit_code);
    if (stop_if_disarmed && watchdog_disarmed()) {
        return find_unique_stock(stock_out);
    }
    char *bootstrap_arguments[] = {
        (char *)kLaunchctlPath,
        (char *)"bootstrap",
        (char *)"user/501",
        (char *)kSystemPlistPath,
        NULL,
    };
    struct command_result bootstrap = run_launchctl(
        bootstrap_arguments, CODEX_COMMAND_TIMEOUT_MSEC);
    (void)journal_event("event=fallback-bootstrap spawn=%d timeout=%d exit=%d "
                        "plist=%s",
                        bootstrap.spawn_error, bootstrap.timed_out,
                        bootstrap.exit_code, kSystemPlistPath);
    if (!command_succeeded(&bootstrap)) {
        return false;
    }
    if (stop_if_disarmed && watchdog_disarmed()) {
        return find_unique_stock(stock_out);
    }
    struct command_result kickstart = kickstart_service(false);
    (void)journal_event("event=fallback-kickstart spawn=%d timeout=%d exit=%d",
                        kickstart.spawn_error, kickstart.timed_out,
                        kickstart.exit_code);
    return command_succeeded(&kickstart) &&
           wait_for_stock(CODEX_RESTORE_VERIFY_MSEC, stop_if_disarmed,
                          stock_out);
}

static bool restore_stock(bool stop_if_disarmed,
                          struct process_snapshot *stock_out,
                          bool *used_fallback) {
    if (used_fallback != NULL) {
        *used_fallback = false;
    }
    if (primary_restore_stock(stop_if_disarmed, stock_out)) {
        return true;
    }
    if (find_unique_stock(stock_out)) {
        (void)journal_event("event=stock-exact-after-primary-command-error");
        return true;
    }
    (void)journal_event("event=primary-restore-failed next=fallback");
    if (used_fallback != NULL) {
        *used_fallback = true;
    }
    return fallback_restore_stock(stop_if_disarmed, stock_out);
}

static bool external_candidate_service_absent(void) {
    struct command_result print_result =
        print_external_candidate_service();
    bool process_absent = candidate_process_absent();
    bool absent = command_completed(&print_result) &&
                  print_result.exit_code != 0 &&
                  process_absent;
    (void)journal_event(
        "event=external-candidate-absence spawn=%d timeout=%d exit=%d "
        "processAbsent=%d absent=%d",
        print_result.spawn_error, print_result.timed_out,
        print_result.exit_code, process_absent, absent);
    return absent;
}

static bool remove_external_candidate_preserving_stock(
    const struct process_snapshot *original_stock, const char *phase) {
    bool stock_preserved =
        original_stock_still_exact_with_candidate_count(original_stock, -1);
    bool service_absent = false;
    unsigned int attempt = 0;
    uint64_t deadline = monotonic_msec() + CODEX_RESTORE_VERIFY_MSEC;
    uint64_t next_bootout = 0;
    do {
        uint64_t now = monotonic_msec();
        if (now >= next_bootout) {
            bool before_exact = original_stock_still_exact_with_candidate_count(
                original_stock, -1);
            struct command_result bootout =
                bootout_external_candidate_service();
            bool after_exact = original_stock_still_exact_with_candidate_count(
                original_stock, -1);
            stock_preserved =
                stock_preserved && before_exact && after_exact;
            ++attempt;
            (void)journal_event(
                "event=parallel-candidate-bootout phase=%s attempt=%u "
                "spawn=%d timeout=%d exit=%d beforeStockExact=%d "
                "afterStockExact=%d stockMutated=0",
                phase != NULL ? phase : "unspecified", attempt,
                bootout.spawn_error, bootout.timed_out, bootout.exit_code,
                before_exact, after_exact);
            next_bootout = monotonic_msec() + 1000U;
        }
        bool stock_now = original_stock_still_exact_with_candidate_count(
            original_stock, -1);
        stock_preserved = stock_preserved && stock_now;
        if (candidate_process_absent()) {
            service_absent = external_candidate_service_absent();
            bool stock_after_print =
                original_stock_still_exact_with_candidate_count(
                    original_stock, service_absent ? 0 : -1);
            stock_preserved = stock_preserved && stock_after_print;
            if (service_absent) {
                break;
            }
        }
        usleep(50U * 1000U);
    } while (monotonic_msec() < deadline);

    bool final_process_exact =
        original_stock_still_exact_with_candidate_count(original_stock, 0);
    bool final_service_exact =
        service_absent && stock_service_and_snapshot_exact(
                              original_stock, 0, "candidate-cleanup-final");
    bool cleaned = stock_preserved && service_absent && final_process_exact &&
                   final_service_exact;
    (void)journal_event(
        "event=parallel-candidate-cleanup-final phase=%s attempts=%u "
        "serviceAbsent=%d stockPreserved=%d finalProcessExact=%d "
        "finalServiceExact=%d cleaned=%d stockMutated=0",
        phase != NULL ? phase : "unspecified", attempt, service_absent,
        stock_preserved, final_process_exact, final_service_exact, cleaned);
    return cleaned;
}

static bool restore_external_stock(bool stop_if_disarmed,
                                   struct process_snapshot *stock_out,
                                   bool *used_fallback) {
    if (used_fallback != NULL) {
        *used_fallback = false;
    }
    if (stop_if_disarmed && watchdog_disarmed()) {
        return find_unique_stock(stock_out) &&
               external_candidate_service_absent();
    }

    bool candidate_absent = false;
    unsigned int attempt = 0;
    uint64_t candidate_deadline =
        monotonic_msec() + CODEX_RESTORE_VERIFY_MSEC;
    uint64_t next_bootout = 0;
    do {
        uint64_t now = monotonic_msec();
        if (now >= next_bootout) {
            struct command_result bootout =
                bootout_external_candidate_service();
            ++attempt;
            (void)journal_event(
                "event=external-candidate-bootout attempt=%u spawn=%d "
                "timeout=%d exit=%d",
                attempt, bootout.spawn_error, bootout.timed_out,
                bootout.exit_code);
            next_bootout = monotonic_msec() + 1000U;
        }
        if (candidate_process_absent()) {
            candidate_absent = external_candidate_service_absent();
            if (candidate_absent) {
                break;
            }
        }
        if (stop_if_disarmed && watchdog_disarmed()) {
            return find_unique_stock(stock_out) &&
                   external_candidate_service_absent();
        }
        usleep(50U * 1000U);
    } while (monotonic_msec() < candidate_deadline);
    if (!candidate_absent) {
        return false;
    }

    if (find_unique_stock(stock_out)) {
        return true;
    }

    struct command_result bootstrap =
        bootstrap_external_stock_service();
    (void)journal_event(
        "event=external-stock-bootstrap spawn=%d timeout=%d exit=%d "
        "plist=%s",
        bootstrap.spawn_error, bootstrap.timed_out, bootstrap.exit_code,
        kSystemPlistPath);
    if ((command_succeeded(&bootstrap) || find_unique_stock(stock_out)) &&
        wait_for_stock(CODEX_RESTORE_VERIFY_MSEC, stop_if_disarmed,
                       stock_out)) {
        return external_candidate_service_absent();
    }

    struct command_result kickstart =
        kickstart_external_stock_service();
    (void)journal_event(
        "event=external-stock-kickstart spawn=%d timeout=%d exit=%d",
        kickstart.spawn_error, kickstart.timed_out, kickstart.exit_code);
    if ((command_succeeded(&kickstart) || find_unique_stock(stock_out)) &&
        wait_for_stock(CODEX_RESTORE_VERIFY_MSEC, stop_if_disarmed,
                       stock_out)) {
        return external_candidate_service_absent();
    }

    /* Keep the older debug/bootstrap lane only as a last recovery fallback;
       normal external transactions never depend on it. */
    bool restored =
        restore_stock(stop_if_disarmed, stock_out, NULL) &&
        find_unique_stock(stock_out) &&
        external_candidate_service_absent();
    if (used_fallback != NULL) {
        *used_fallback = true;
    }
    return restored;
}

static bool ensure_state_directory(void) {
    if (mkdir(kStateDirectory, 0700) != 0 && errno != EEXIST) {
        return false;
    }
    int descriptor = open(kStateDirectory,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    struct stat status = {0};
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISDIR(status.st_mode) && status.st_uid == 0 &&
                 (status.st_mode & 0077) == 0;
    if (!valid) {
        close(descriptor);
        return false;
    }
    gStateDirectoryDescriptor = descriptor;
    return true;
}

static bool marker_name(const char *prefix, char output[96]) {
    if (prefix == NULL || gRunToken[0] == '\0') {
        return false;
    }
    int length = snprintf(output, 96, "%s-%s", prefix, gRunToken);
    return length > 0 && length < 96;
}

static bool create_marker(const char *prefix) {
    if (gStateDirectoryDescriptor < 0) {
        return false;
    }
    char name[96];
    if (!marker_name(prefix, name)) {
        return false;
    }
    int descriptor = openat(gStateDirectoryDescriptor, name,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                                O_NOFOLLOW,
                            0600);
    if (descriptor < 0 && errno == EEXIST) {
        descriptor = openat(gStateDirectoryDescriptor, name,
                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0) {
            return false;
        }
        char contents[64] = {0};
        ssize_t amount = read(descriptor, contents, sizeof(contents) - 1U);
        close(descriptor);
        char expected[40];
        int expected_length = snprintf(expected, sizeof(expected), "%s\n",
                                       gRunToken);
        return expected_length > 0 && amount == expected_length &&
               memcmp(contents, expected, (size_t)expected_length) == 0;
    }
    if (descriptor < 0) {
        return false;
    }
    char contents[40];
    int length = snprintf(contents, sizeof(contents), "%s\n", gRunToken);
    bool valid = length > 0 && (size_t)length < sizeof(contents) &&
                 write_all(descriptor, contents, (size_t)length) &&
                 fsync(descriptor) == 0;
    close(descriptor);
    return valid && fsync(gStateDirectoryDescriptor) == 0;
}

static bool marker_exists(const char *prefix) {
    if (gStateDirectoryDescriptor < 0) {
        return false;
    }
    char name[96];
    if (!marker_name(prefix, name)) {
        return false;
    }
    int descriptor = openat(gStateDirectoryDescriptor, name,
                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    struct stat status = {0};
    char contents[64] = {0};
    ssize_t amount = read(descriptor, contents, sizeof(contents) - 1U);
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_uid == 0 &&
                 status.st_nlink == 1 && (status.st_mode & 0077) == 0;
    close(descriptor);
    char expected[40];
    int expected_length = snprintf(expected, sizeof(expected), "%s\n",
                                   gRunToken);
    return valid && expected_length > 0 && amount == expected_length &&
           memcmp(contents, expected, (size_t)expected_length) == 0;
}

static bool helper_record_name(const char *prefix, char output[96]) {
    return marker_name(prefix, output);
}

static bool fill_helper_record(const struct process_snapshot *helper,
                               const char *phase,
                               struct helper_record *record) {
    if (helper == NULL || phase == NULL || record == NULL ||
        helper->pid <= 1 || helper->bsd.pbi_uid != 0 ||
        helper->bsd.pbi_ppid != (uint32_t)getpid() ||
        !any_launchctl_path_exact(helper->path) ||
        strlen(phase) >= CODEX_HELPER_PHASE_SIZE) {
        return false;
    }
    memset(record, 0, sizeof(*record));
    record->magic = CODEX_HELPER_RECORD_MAGIC;
    record->version = CODEX_HELPER_RECORD_VERSION;
    record->pid = helper->pid;
    record->uid = helper->bsd.pbi_uid;
    record->ppid = helper->bsd.pbi_ppid;
    record->pid_version = helper->unique.pid_version;
    record->unique_id = helper->unique.unique_id;
    record->parent_unique_id = helper->unique.parent_unique_id;
    memcpy(record->uuid, helper->unique.uuid, sizeof(record->uuid));
    memcpy(record->token, gRunToken, sizeof(record->token));
    memcpy(record->phase, phase, strlen(phase) + 1U);
    memcpy(record->path, helper->path, strlen(helper->path) + 1U);
    return true;
}

static bool helper_record_valid(const struct helper_record *record) {
    return record != NULL &&
           record->magic == CODEX_HELPER_RECORD_MAGIC &&
           record->version == CODEX_HELPER_RECORD_VERSION &&
           record->pid > 1 && record->uid == 0 &&
           record->ppid > 1 &&
           memchr(record->token, '\0', sizeof(record->token)) != NULL &&
           strcmp(record->token, gRunToken) == 0 &&
           memchr(record->phase, '\0', sizeof(record->phase)) != NULL &&
           record->phase[0] != '\0' &&
           memchr(record->path, '\0', sizeof(record->path)) != NULL &&
           any_launchctl_path_exact(record->path);
}

static bool read_helper_record(struct helper_record *record_out,
                               bool *exists_out) {
    if (record_out == NULL || exists_out == NULL ||
        gStateDirectoryDescriptor < 0) {
        return false;
    }
    *exists_out = false;
    memset(record_out, 0, sizeof(*record_out));
    char name[96];
    if (!helper_record_name("helper", name)) {
        return false;
    }
    int descriptor = openat(gStateDirectoryDescriptor, name,
                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return errno == ENOENT;
    }
    *exists_out = true;
    struct stat status = {0};
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_uid == 0 &&
                 status.st_nlink == 1 && (status.st_mode & 0077) == 0 &&
                 status.st_size == (off_t)sizeof(*record_out);
    size_t offset = 0;
    while (valid && offset < sizeof(*record_out)) {
        ssize_t amount = read(descriptor,
                              (uint8_t *)record_out + offset,
                              sizeof(*record_out) - offset);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            valid = false;
            break;
        }
        offset += (size_t)amount;
    }
    uint8_t extra = 0;
    if (valid) {
        ssize_t amount;
        do {
            amount = read(descriptor, &extra, sizeof(extra));
        } while (amount < 0 && errno == EINTR);
        valid = amount == 0;
    }
    close(descriptor);
    return valid && helper_record_valid(record_out);
}

static bool publish_helper_record(const struct process_snapshot *helper,
                                  const char *phase,
                                  struct helper_record *record_out) {
    if (gStateDirectoryDescriptor < 0 || record_out == NULL ||
        !fill_helper_record(helper, phase, record_out)) {
        return false;
    }
    char active_name[96];
    char temporary_name[96];
    if (!helper_record_name("helper", active_name) ||
        !helper_record_name("helper-tmp", temporary_name)) {
        return false;
    }
    struct stat status = {0};
    if (fstatat(gStateDirectoryDescriptor, active_name, &status,
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        return false;
    }
    int descriptor = openat(gStateDirectoryDescriptor, temporary_name,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                                O_NOFOLLOW,
                            0600);
    if (descriptor < 0) {
        return false;
    }
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_uid == 0 &&
                 status.st_nlink == 1 && (status.st_mode & 0077) == 0 &&
                 write_all(descriptor, record_out, sizeof(*record_out)) &&
                 fsync(descriptor) == 0;
    close(descriptor);
    if (!valid) {
        (void)unlinkat(gStateDirectoryDescriptor, temporary_name, 0);
        (void)fsync(gStateDirectoryDescriptor);
        return false;
    }
    if (renameat(gStateDirectoryDescriptor, temporary_name,
                 gStateDirectoryDescriptor, active_name) != 0) {
        (void)unlinkat(gStateDirectoryDescriptor, temporary_name, 0);
        (void)fsync(gStateDirectoryDescriptor);
        return false;
    }
    if (fsync(gStateDirectoryDescriptor) != 0) {
        (void)unlinkat(gStateDirectoryDescriptor, active_name, 0);
        (void)fsync(gStateDirectoryDescriptor);
        return false;
    }
    return true;
}

static bool clear_helper_record(const struct helper_record *expected) {
    struct helper_record current = {0};
    bool exists = false;
    if (expected == NULL ||
        !read_helper_record(&current, &exists) || !exists ||
        memcmp(&current, expected, sizeof(current)) != 0) {
        return false;
    }
    char name[96];
    return helper_record_name("helper", name) &&
           unlinkat(gStateDirectoryDescriptor, name, 0) == 0 &&
           fsync(gStateDirectoryDescriptor) == 0;
}

static bool open_secure_lock(const char *path, int *descriptor_out) {
    if (path == NULL || descriptor_out == NULL) {
        return false;
    }
    int descriptor = open(path,
                          O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return false;
    }
    struct stat status = {0};
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_uid == 0 &&
                 status.st_nlink == 1 && (status.st_mode & 0077) == 0 &&
                 fchmod(descriptor, 0600) == 0;
    if (!valid) {
        close(descriptor);
        return false;
    }
    *descriptor_out = descriptor;
    return true;
}

enum recovery_lock_result {
    RECOVERY_LOCK_ERROR = -1,
    RECOVERY_LOCK_BUSY = 0,
    RECOVERY_LOCK_ACQUIRED = 1,
};

static enum recovery_lock_result try_recovery_lock(void) {
    if (gRecoveryDescriptor < 0) {
        return RECOVERY_LOCK_ERROR;
    }
    if (flock(gRecoveryDescriptor, LOCK_EX | LOCK_NB) == 0) {
        return RECOVERY_LOCK_ACQUIRED;
    }
    return errno == EWOULDBLOCK || errno == EAGAIN
               ? RECOVERY_LOCK_BUSY
               : RECOVERY_LOCK_ERROR;
}

enum recorded_helper_state {
    RECORDED_HELPER_INVALID = -1,
    RECORDED_HELPER_GONE = 0,
    RECORDED_HELPER_LIVE = 1,
};

static enum recorded_helper_state recorded_helper_state(
    const struct helper_record *record, pid_t controller_pid) {
    if (!helper_record_valid(record) || controller_pid <= 1 ||
        record->ppid != (uint32_t)controller_pid) {
        return RECORDED_HELPER_INVALID;
    }
    struct codex_proc_uniqidentifierinfo first_unique = {0};
    if (!copy_unique_info(record->pid, &first_unique)) {
        errno = 0;
        return kill(record->pid, 0) != 0 && errno == ESRCH
                   ? RECORDED_HELPER_GONE
                   : RECORDED_HELPER_INVALID;
    }
    if (first_unique.unique_id != record->unique_id ||
        first_unique.pid_version != record->pid_version ||
        memcmp(first_unique.uuid, record->uuid, sizeof(record->uuid)) != 0) {
        return RECORDED_HELPER_GONE;
    }
    char first_path[CODEX_PATH_SIZE] = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    struct codex_proc_bsdinfo bsd = {0};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    if (!copy_process_path(record->pid, first_path) ||
        strcmp(first_path, record->path) != 0 ||
        !any_launchctl_path_exact(first_path) ||
        !copy_bsd_info(record->pid, &bsd) || bsd.pbi_uid != 0 ||
        (bsd.pbi_ppid != (uint32_t)controller_pid && bsd.pbi_ppid != 1U) ||
        (bsd.pbi_ppid == (uint32_t)controller_pid &&
         first_unique.parent_unique_id != record->parent_unique_id) ||
        !copy_process_path(record->pid, second_path) ||
        strcmp(first_path, second_path) != 0 ||
        !copy_unique_info(record->pid, &second_unique) ||
        !process_generation_equal(&first_unique, &second_unique)) {
        return RECORDED_HELPER_INVALID;
    }
    return RECORDED_HELPER_LIVE;
}

static bool clear_stale_helper_record(const struct helper_record *record) {
    return clear_helper_record(record);
}

static bool neutralize_recorded_helper(pid_t controller_pid) {
    struct helper_record record = {0};
    bool exists = false;
    if (!read_helper_record(&record, &exists)) {
        return false;
    }
    if (!exists) {
        return true;
    }
    enum recorded_helper_state state =
        recorded_helper_state(&record, controller_pid);
    if (state == RECORDED_HELPER_INVALID) {
        return false;
    }
    if (state == RECORDED_HELPER_LIVE) {
        /* Re-read the full binding immediately before signaling. */
        if (recorded_helper_state(&record, controller_pid) !=
            RECORDED_HELPER_LIVE) {
            return false;
        }
        if (kill(record.pid, SIGKILL) != 0 && errno != ESRCH) {
            return false;
        }
        uint64_t deadline = monotonic_msec() + CODEX_HELPER_KILL_MSEC;
        do {
            state = recorded_helper_state(&record, controller_pid);
            if (state == RECORDED_HELPER_GONE) {
                break;
            }
            if (state == RECORDED_HELPER_INVALID) {
                return false;
            }
            usleep(20U * 1000U);
        } while (monotonic_msec() < deadline);
        if (state != RECORDED_HELPER_GONE) {
            return false;
        }
    }
    if (!clear_stale_helper_record(&record)) {
        return false;
    }

    /* The controller no longer owns the recovery lease, so a fresh record
       after this point would prove an unsafe publisher race. */
    memset(&record, 0, sizeof(record));
    exists = false;
    return read_helper_record(&record, &exists) && !exists;
}

static bool watchdog_disarmed(void) {
    return marker_exists("disarm");
}

static bool open_journal(void) {
    int descriptor = open(kJournalPath,
                          O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return false;
    }
    struct stat status = {0};
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_uid == 0 &&
                 status.st_nlink == 1 && (status.st_mode & 0077) == 0 &&
                 fchmod(descriptor, 0600) == 0;
    if (!valid) {
        close(descriptor);
        return false;
    }
    gJournalDescriptor = descriptor;
    return true;
}

static bool remove_stale_canary_marker(void) {
    struct stat status = {0};
    if (lstat(kFreshCanaryMarkerPath, &status) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode)) {
        return false;
    }
    return unlink(kFreshCanaryMarkerPath) == 0;
}

static bool fresh_canary_marker_matches(pid_t candidate_pid) {
    int descriptor = open(kFreshCanaryMarkerPath,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    struct stat status = {0};
    char contents[256] = {0};
    ssize_t amount = read(descriptor, contents, sizeof(contents) - 1U);
    bool secure = fstat(descriptor, &status) == 0 &&
                  S_ISREG(status.st_mode) && status.st_uid == 501 &&
                  status.st_nlink == 1;
    close(descriptor);
    if (!secure || amount <= 0 || (size_t)amount >= sizeof(contents)) {
        return false;
    }
    char expected[256];
    int expected_length = snprintf(
        expected, sizeof(expected),
        "constructor=entered nonce=%s pid=%d uid=501 euid=501\n",
        kFreshCanaryNonce, candidate_pid);
    return expected_length > 0 && amount == expected_length &&
           memcmp(contents, expected, (size_t)expected_length) == 0;
}

static bool validate_run_token(const char *token) {
    if (token == NULL || strlen(token) != 36U) {
        return false;
    }
    uuid_t parsed;
    char canonical[37];
    return uuid_parse(token, parsed) == 0 &&
           (uuid_unparse_lower(parsed, canonical), strcmp(token, canonical) == 0);
}

static bool prepare_common_paths(bool require_candidate) {
    int launchctl_descriptor = -1;
    int external_launchctl_descriptor = -1;
    int plist_descriptor = -1;
    int worker_descriptor = -1;
    int precursor_descriptor = -1;
    struct stat ignored_status = {0};
    bool valid = secure_existing_regular_file(
                     kLaunchctlPath, 0, true, &launchctl_descriptor,
                     &ignored_status) &&
                 realpath(kLaunchctlPath, gLaunchctlRealPath) != NULL &&
                 secure_existing_regular_file(
                     kExternalLaunchctlPath, 0, true,
                     &external_launchctl_descriptor, &ignored_status) &&
                 realpath(kExternalLaunchctlPath,
                          gExternalLaunchctlRealPath) != NULL &&
                 external_launchctl_file_valid() &&
                 secure_existing_regular_file(
                     kWorkerPath, 0, true, &worker_descriptor,
                     &ignored_status) &&
                 realpath(kWorkerPath, gWorkerRealPath) != NULL &&
                 secure_existing_regular_file(
                     kPrecursorPath, 0, true, &precursor_descriptor,
                     &ignored_status) &&
                 realpath(kPrecursorPath, gPrecursorRealPath) != NULL &&
                 secure_existing_regular_file(
                     kSystemPlistPath, 0, false, &plist_descriptor,
                     &ignored_status);
    if (launchctl_descriptor >= 0) {
        close(launchctl_descriptor);
    }
    if (external_launchctl_descriptor >= 0) {
        close(external_launchctl_descriptor);
    }
    if (plist_descriptor >= 0) {
        close(plist_descriptor);
    }
    if (worker_descriptor >= 0) {
        close(worker_descriptor);
    }
    if (precursor_descriptor >= 0) {
        close(precursor_descriptor);
    }
    if (!valid) {
        return false;
    }
    if (realpath(kCandidatePath, gCandidateRealPath) == NULL) {
        gCandidateRealPath[0] = '\0';
        return !require_candidate;
    }
    return true;
}

static bool controller_preflight(const char *invocation_path,
                                 struct process_snapshot *stock_out,
                                 bool prepare_canary,
                                 bool external_mode) {
    if (geteuid() != 0 || getpid() <= 1 ||
        !prepare_common_paths(true) || !ensure_state_directory() ||
        !open_journal() || !precursor_argument_exact(invocation_path)) {
        return false;
    }
    if (prepare_canary && !remove_stale_canary_marker()) {
        return false;
    }

    bool candidate_valid = file_sha256_exact(
                               kCandidatePath, kExpectedCandidateSHA256, true,
                               CODEX_EXPECTED_CANDIDATE_SIZE,
                               &gCandidateDescriptor, &gCandidateStatus) &&
                           descriptor_has_expected_uuid(gCandidateDescriptor) &&
                           file_sha256_exact(kCandidateInfoPath,
                                             kExpectedInfoSHA256, false, 0,
                                             &gCandidateInfoDescriptor,
                                             &gCandidateInfoStatus) &&
                           candidate_path_still_bound();
    bool launchctl_valid = file_sha256_exact(
        kLaunchctlPath, kExpectedLaunchctlSHA256, true, 0, NULL, NULL);
    bool loader_valid = file_sha256_exact(
        kLoaderCandidatePath, kExpectedLoaderSHA256, true, 0, NULL, NULL);
    bool hook_valid = file_sha256_exact(
        kDyldAdmissionHookPath, kExpectedHookSHA256, false, 0, NULL, NULL);
    bool canary_valid = file_sha256_exact(
        kFreshCanaryPath, kExpectedCanarySHA256, false, 0, NULL, NULL);
    bool injection_artifacts_valid = !prepare_canary ||
                                     (launchctl_valid && loader_valid &&
                                      hook_valid && canary_valid);
    if (!candidate_valid || !injection_artifacts_valid) {
        (void)journal_event("event=preflight-artifact-rejected candidate=%d "
                            "injectionArtifacts=%d launchctl=%d loader=%d "
                            "hook=%d canary=%d",
                            candidate_valid, injection_artifacts_valid,
                            launchctl_valid, loader_valid, hook_valid,
                            canary_valid);
        return false;
    }

    struct command_result print_result;
    const char *print_launchctl =
        external_mode ? kExternalLaunchctlPath : kLaunchctlPath;
    char *print_arguments[] = {
        (char *)print_launchctl, (char *)"print", (char *)kServiceTarget,
        NULL,
    };
    print_result = run_launchctl(print_arguments, CODEX_COMMAND_TIMEOUT_MSEC);
    bool stock_found = find_unique_stock(stock_out);
    if (!command_succeeded(&print_result) || !stock_found) {
        char print_output[512];
        char print_error[512];
        compact_command_output(print_result.standard_output, print_output,
                               sizeof(print_output));
        compact_command_output(print_result.standard_error, print_error,
                               sizeof(print_error));
        (void)journal_event(
            "event=preflight-launchctl-print-rejected spawn=%d timeout=%d "
            "exit=%d stockFound=%d launchctl=%s stdout=\"%s\" "
            "stderr=\"%s\"",
            print_result.spawn_error, print_result.timed_out,
            print_result.exit_code, stock_found, print_launchctl,
            print_output, print_error);
        return false;
    }
    return journal_event(
        "event=preflight-ok service=%s stockPid=%d stockUid=%u stockPpid=%u "
        "stockPidVersion=%d stockUniqueId=%llu candidate=%s "
        "candidateReal=%s candidateDev=%llu candidateInode=%llu "
        "infoDev=%llu infoInode=%llu "
        "launchctlSha256=3eb2dbb554964a6ce221c07d6d8a068156606e2761c3ccc04a72f198dfeddfdc "
        "loaderSha256=5b63baf330237ae1e3b95e02b2b935b1825410d94e7cb76bc4a152d6114b0c78 "
        "hookSha256=90bdcd15dda22ae32343be47a8d54d949deac0b0679f3b8c8a9bf0f9e6a696ee "
        "canarySha256=5753976c89f1643076b51de9d34faf79cbd613c134eef01ec93df3f18431d8be "
        "candidateSha256=73a2ccc27f94ecc35266029df82d12ca7eb0f27ff5f2e047bc9ea35681877126 "
        "candidateCdhash=9b298e846ab91aaa1fba303f2c892d828e9e921c "
        "uuid=AD937FB7-2664-3B8F-B1C9-34C4AD4092D2 "
        "infoSha256=ce3bfead94676c8daf111f009211467a9c70f6cbceb73e7a0fcde1f03b320703",
        kServiceTarget, stock_out->pid, stock_out->bsd.pbi_uid,
        stock_out->bsd.pbi_ppid, stock_out->unique.pid_version,
        (unsigned long long)stock_out->unique.unique_id, kCandidatePath,
        gCandidateRealPath, (unsigned long long)gCandidateStatus.st_dev,
        (unsigned long long)gCandidateStatus.st_ino,
        (unsigned long long)gCandidateInfoStatus.st_dev,
        (unsigned long long)gCandidateInfoStatus.st_ino);
}

static bool spawn_watchdog(const struct process_snapshot *controller,
                           pid_t *watchdog_pid_out, bool arm_only,
                           bool external_mode) {
    if (controller == NULL || controller->pid <= 1 ||
        !controller_snapshot_still_exact(controller)) {
        return false;
    }
    posix_spawn_file_actions_t actions;
    int actions_result = posix_spawn_file_actions_init(&actions);
    if (actions_result != 0) {
        return false;
    }
    int setup_result = posix_spawn_file_actions_adddup2(
        &actions, gLockDescriptor, CODEX_LOCK_INHERITED_FD);
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addopen(
            &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addopen(
            &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addopen(
            &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    }
    char controller_pid[24];
    char controller_pid_version[24];
    char controller_unique_id[32];
    int pid_length = snprintf(controller_pid, sizeof(controller_pid), "%d",
                              controller->pid);
    int version_length = snprintf(controller_pid_version,
                                  sizeof(controller_pid_version), "%d",
                                  controller->unique.pid_version);
    int unique_length = snprintf(controller_unique_id,
                                 sizeof(controller_unique_id), "%llu",
                                 (unsigned long long)
                                     controller->unique.unique_id);
    if (pid_length <= 0 || (size_t)pid_length >= sizeof(controller_pid) ||
        version_length <= 0 ||
        (size_t)version_length >= sizeof(controller_pid_version) ||
        unique_length <= 0 ||
        (size_t)unique_length >= sizeof(controller_unique_id)) {
        (void)posix_spawn_file_actions_destroy(&actions);
        return false;
    }
    char *arguments[] = {
        (char *)kWorkerPath,
        (char *)"--macho",
        (char *)kPrecursorPath,
        (char *)(arm_only ? "--watchdog-arm-only"
                          : (external_mode ? "--external-watchdog"
                                           : "--watchdog")),
        gRunToken,
        controller_pid,
        controller_pid_version,
        controller_unique_id,
        NULL,
    };
    pid_t child = -1;
    int spawn_result = setup_result == 0
                           ? posix_spawn(&child, kWorkerPath, &actions, NULL,
                                         arguments, environ)
                           : setup_result;
    (void)posix_spawn_file_actions_destroy(&actions);
    if (spawn_result != 0 || child <= 1) {
        return false;
    }
    *watchdog_pid_out = child;
    uint64_t deadline = monotonic_msec() + 3000U;
    do {
        if (marker_exists("ready")) {
            int status = 0;
            pid_t waited = waitpid(child, &status, WNOHANG);
            return waited == 0 &&
                   journal_event("event=watchdog-armed workerPid=%d "
                                 "controllerPid=%d deadlineMs=%u external=%d",
                                 child, controller->pid,
                                 external_mode
                                     ? CODEX_EXTERNAL_WATCHDOG_DELAY_MSEC
                                     : CODEX_WATCHDOG_DELAY_MSEC,
                                 external_mode);
        }
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            return false;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);
    return false;
}

static bool spawn_parallel_bind_watchdog(
    const struct process_snapshot *controller,
    const struct process_snapshot *original_stock, pid_t *watchdog_pid_out) {
    if (watchdog_pid_out != NULL) {
        *watchdog_pid_out = -1;
    }
    if (controller == NULL || controller->pid <= 1 ||
        original_stock == NULL || original_stock->pid <= 1 ||
        watchdog_pid_out == NULL ||
        !controller_snapshot_still_exact(controller) ||
        !original_stock_still_exact_with_candidate_count(original_stock, 0)) {
        return false;
    }

    posix_spawn_file_actions_t actions;
    int actions_result = posix_spawn_file_actions_init(&actions);
    if (actions_result != 0) {
        return false;
    }
    int setup_result = posix_spawn_file_actions_adddup2(
        &actions, gLockDescriptor, CODEX_LOCK_INHERITED_FD);
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addopen(
            &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addopen(
            &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addopen(
            &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    }

    char controller_pid[24];
    char controller_pid_version[24];
    char controller_unique_id[32];
    char stock_pid[24];
    char stock_pid_version[24];
    char stock_unique_id[32];
    char stock_cs_flags[24];
    int controller_pid_length = snprintf(
        controller_pid, sizeof(controller_pid), "%d", controller->pid);
    int controller_version_length = snprintf(
        controller_pid_version, sizeof(controller_pid_version), "%d",
        controller->unique.pid_version);
    int controller_unique_length = snprintf(
        controller_unique_id, sizeof(controller_unique_id), "%llu",
        (unsigned long long)controller->unique.unique_id);
    int stock_pid_length = snprintf(stock_pid, sizeof(stock_pid), "%d",
                                    original_stock->pid);
    int stock_version_length = snprintf(
        stock_pid_version, sizeof(stock_pid_version), "%d",
        original_stock->unique.pid_version);
    int stock_unique_length = snprintf(
        stock_unique_id, sizeof(stock_unique_id), "%llu",
        (unsigned long long)original_stock->unique.unique_id);
    int stock_flags_length = snprintf(stock_cs_flags, sizeof(stock_cs_flags),
                                      "%u", original_stock->cs_flags);
    bool arguments_valid =
        controller_pid_length > 0 &&
        (size_t)controller_pid_length < sizeof(controller_pid) &&
        controller_version_length > 0 &&
        (size_t)controller_version_length < sizeof(controller_pid_version) &&
        controller_unique_length > 0 &&
        (size_t)controller_unique_length < sizeof(controller_unique_id) &&
        stock_pid_length > 0 &&
        (size_t)stock_pid_length < sizeof(stock_pid) &&
        stock_version_length > 0 &&
        (size_t)stock_version_length < sizeof(stock_pid_version) &&
        stock_unique_length > 0 &&
        (size_t)stock_unique_length < sizeof(stock_unique_id) &&
        stock_flags_length > 0 &&
        (size_t)stock_flags_length < sizeof(stock_cs_flags);
    if (!arguments_valid) {
        (void)posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    char *arguments[] = {
        (char *)kWorkerPath,
        (char *)"--macho",
        (char *)kPrecursorPath,
        (char *)"--parallel-bind-watchdog",
        gRunToken,
        controller_pid,
        controller_pid_version,
        controller_unique_id,
        stock_pid,
        stock_pid_version,
        stock_unique_id,
        stock_cs_flags,
        NULL,
    };
    pid_t child = -1;
    int spawn_result = setup_result == 0
                           ? posix_spawn(&child, kWorkerPath, &actions, NULL,
                                         arguments, environ)
                           : setup_result;
    (void)posix_spawn_file_actions_destroy(&actions);
    if (spawn_result != 0 || child <= 1) {
        return false;
    }
    *watchdog_pid_out = child;
    uint64_t deadline = monotonic_msec() + 3000U;
    do {
        if (marker_exists("ready")) {
            int status = 0;
            pid_t waited = waitpid(child, &status, WNOHANG);
            return waited == 0 &&
                   journal_event(
                       "event=parallel-watchdog-armed workerPid=%d "
                       "controllerPid=%d stockPid=%d stockPidVersion=%d "
                       "stockUniqueId=%llu stockCsFlags=0x%08x deadlineMs=%u "
                       "stockMutated=0",
                       child, controller->pid, original_stock->pid,
                       original_stock->unique.pid_version,
                       (unsigned long long)
                           original_stock->unique.unique_id,
                       original_stock->cs_flags,
                       CODEX_EXTERNAL_WATCHDOG_DELAY_MSEC);
        }
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            return false;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);
    return false;
}

static bool wait_for_returned_candidate(
    pid_t returned_pid, struct process_snapshot *candidate_out,
    uint32_t *flags_out) {
    uint64_t deadline = monotonic_msec() + CODEX_BIND_TIMEOUT_MSEC;
    do {
        if (find_returned_candidate(returned_pid, candidate_out, flags_out)) {
            return true;
        }
        if (gStopRequested) {
            return false;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);

    char path[CODEX_PATH_SIZE] = {0};
    struct codex_proc_bsdinfo bsd = {0};
    struct codex_proc_uniqidentifierinfo unique = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    char uuid_text[37] = "unavailable";
    char cdhash_text[CODEX_CDHASH_SIZE * 2U + 1U] = {0};
    bool path_ok = copy_process_path(returned_pid, path);
    bool bsd_ok = copy_bsd_info(returned_pid, &bsd);
    bool unique_ok = copy_unique_info(returned_pid, &unique);
    bool flags_ok =
        csops(returned_pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0;
    bool cdhash_ok =
        csops(returned_pid, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) == 0;
    if (unique_ok) {
        uuid_unparse_lower(unique.uuid, uuid_text);
    }
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < sizeof(cdhash); ++index) {
        cdhash_text[index * 2U] = digits[cdhash[index] >> 4U];
        cdhash_text[index * 2U + 1U] = digits[cdhash[index] & 0x0fU];
    }
    int stock_count = -1;
    int candidate_count = -1;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    bool counts_ok = count_process_paths(
        &stock_count, &stock_pid, &candidate_count, &candidate_pid);
    errno = 0;
    int alive_result = kill(returned_pid, 0);
    int alive_error = alive_result == 0 ? 0 : errno;
    (void)journal_event(
        "event=external-candidate-bind-rejected returnedPid=%d alive=%d "
        "aliveErrno=%d pathOk=%d path=%s pathExact=%d bsdOk=%d uid=%u "
        "ppid=%u uniqueOk=%d pidVersion=%d uniqueId=%llu uuid=%s "
        "flagsOk=%d flags=0x%08x valid=%d cdhashOk=%d cdhash=%s "
        "cdhashMatch=%d countsOk=%d stockCount=%d stockPid=%d "
        "candidateCount=%d candidatePid=%d fileBound=%d",
        returned_pid, alive_result == 0, alive_error, path_ok,
        path_ok ? path : "", path_ok && candidate_path_exact(path), bsd_ok,
        bsd.pbi_uid, bsd.pbi_ppid, unique_ok, unique.pid_version,
        (unsigned long long)unique.unique_id, uuid_text, flags_ok, flags,
        flags_ok && (flags & CODEX_CS_VALID) != 0, cdhash_ok, cdhash_text,
        cdhash_ok && memcmp(cdhash, kExpectedCandidateCDHash,
                            sizeof(cdhash)) == 0,
        counts_ok, stock_count, stock_pid, candidate_count, candidate_pid,
        candidate_path_still_bound());
    return false;
}

static bool wait_for_replacement_unique_candidate(
    pid_t *candidate_pid_out, struct process_snapshot *candidate_out,
    uint32_t *flags_out) {
    if (candidate_pid_out == NULL || candidate_out == NULL) {
        return false;
    }

    uint64_t deadline = monotonic_msec() + CODEX_BIND_TIMEOUT_MSEC;
    int stock_count = -1;
    int candidate_count = -1;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    do {
        if (gStopRequested) {
            break;
        }
        if (count_process_paths(&stock_count, &stock_pid, &candidate_count,
                                &candidate_pid) &&
            stock_count == 0 && candidate_count == 1 && candidate_pid > 1 &&
            find_returned_candidate(candidate_pid, candidate_out, flags_out)) {
            *candidate_pid_out = candidate_pid;
            return true;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);

    bool counts_ok = count_process_paths(
        &stock_count, &stock_pid, &candidate_count, &candidate_pid);
    (void)journal_event(
        "event=external-candidate-discovery-rejected countsOk=%d "
        "stockCount=%d stockPid=%d candidateCount=%d candidatePid=%d "
        "fileBound=%d stopRequested=%d",
        counts_ok, stock_count, stock_pid, candidate_count, candidate_pid,
        candidate_path_still_bound(), gStopRequested != 0);
    return false;
}

static bool wait_for_parallel_returned_candidate(
    pid_t returned_pid, const struct process_snapshot *original_stock,
    struct process_snapshot *candidate_out, uint32_t *flags_out) {
    uint64_t deadline = monotonic_msec() + CODEX_BIND_TIMEOUT_MSEC;
    bool stock_exact = false;
    do {
        stock_exact = original_stock_still_exact_with_candidate_count(
            original_stock, -1);
        if (!stock_exact || gStopRequested) {
            break;
        }
        if (find_parallel_returned_candidate(
                returned_pid, original_stock, candidate_out, flags_out)) {
            return true;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);

    char path[CODEX_PATH_SIZE] = {0};
    struct codex_proc_bsdinfo bsd = {0};
    struct codex_proc_uniqidentifierinfo unique = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    char uuid_text[37] = "unavailable";
    char cdhash_text[CODEX_CDHASH_SIZE * 2U + 1U] = {0};
    bool path_ok = copy_process_path(returned_pid, path);
    bool bsd_ok = copy_bsd_info(returned_pid, &bsd);
    bool unique_ok = copy_unique_info(returned_pid, &unique);
    bool flags_ok =
        csops(returned_pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0;
    bool cdhash_ok =
        csops(returned_pid, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) == 0;
    if (unique_ok) {
        uuid_unparse_lower(unique.uuid, uuid_text);
    }
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < sizeof(cdhash); ++index) {
        cdhash_text[index * 2U] = digits[cdhash[index] >> 4U];
        cdhash_text[index * 2U + 1U] = digits[cdhash[index] & 0x0fU];
    }
    int stock_count = -1;
    int candidate_count = -1;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    bool counts_ok = count_process_paths(
        &stock_count, &stock_pid, &candidate_count, &candidate_pid);
    errno = 0;
    int alive_result = returned_pid > 1 ? kill(returned_pid, 0) : -1;
    int alive_error = alive_result == 0 ? 0 : errno;
    bool original_exact = original_stock_still_exact_with_candidate_count(
        original_stock, -1);
    (void)journal_event(
        "event=parallel-candidate-bind-rejected returnedPid=%d alive=%d "
        "aliveErrno=%d pathOk=%d path=%s pathExact=%d bsdOk=%d uid=%u "
        "ppid=%u processStatus=%u stopped=%d uniqueOk=%d pidVersion=%d "
        "uniqueId=%llu uuid=%s "
        "uuidMatch=%d flagsOk=%d flags=0x%08x valid=%d cdhashOk=%d "
        "cdhash=%s cdhashMatch=%d countsOk=%d stockCount=%d stockPid=%d "
        "candidateCount=%d candidatePid=%d originalStockExact=%d "
        "fileBound=%d stopRequested=%d",
        returned_pid, alive_result == 0, alive_error, path_ok,
        path_ok ? path : "", path_ok && candidate_path_exact(path), bsd_ok,
        bsd.pbi_uid, bsd.pbi_ppid, bsd.pbi_status,
        bsd_ok && bsd.pbi_status == CODEX_PROC_STATUS_STOPPED, unique_ok,
        unique.pid_version,
        (unsigned long long)unique.unique_id, uuid_text,
        unique_ok && memcmp(unique.uuid, kExpectedSpringBoardUUID,
                            sizeof(kExpectedSpringBoardUUID)) == 0,
        flags_ok, flags, flags_ok && (flags & CODEX_CS_VALID) != 0,
        cdhash_ok, cdhash_text,
        cdhash_ok && memcmp(cdhash, kExpectedCandidateCDHash,
                            sizeof(cdhash)) == 0,
        counts_ok, stock_count, stock_pid, candidate_count, candidate_pid,
        original_exact, candidate_path_still_bound(), gStopRequested != 0);
    return false;
}

static bool wait_for_parallel_unique_candidate(
    const struct process_snapshot *original_stock, pid_t *candidate_pid_out,
    struct process_snapshot *candidate_out, uint32_t *flags_out) {
    if (original_stock == NULL || candidate_pid_out == NULL ||
        candidate_out == NULL) {
        return false;
    }
    uint64_t deadline = monotonic_msec() + CODEX_BIND_TIMEOUT_MSEC;
    int stock_count = -1;
    int candidate_count = -1;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    do {
        if (!original_stock_still_exact_with_candidate_count(
                original_stock, -1) ||
            gStopRequested) {
            break;
        }
        if (count_process_paths(&stock_count, &stock_pid, &candidate_count,
                                &candidate_pid) &&
            stock_count == 1 && stock_pid == original_stock->pid &&
            candidate_count == 1 && candidate_pid > 1 &&
            find_parallel_returned_candidate(
                candidate_pid, original_stock, candidate_out, flags_out)) {
            *candidate_pid_out = candidate_pid;
            return true;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);

    bool counts_ok = count_process_paths(
        &stock_count, &stock_pid, &candidate_count, &candidate_pid);
    (void)journal_event(
        "event=parallel-candidate-discovery-rejected countsOk=%d "
        "stockCount=%d stockPid=%d candidateCount=%d candidatePid=%d "
        "originalStockExact=%d fileBound=%d stopRequested=%d",
        counts_ok, stock_count, stock_pid, candidate_count, candidate_pid,
        original_stock_still_exact_with_candidate_count(original_stock, -1),
        candidate_path_still_bound(), gStopRequested != 0);
    return false;
}

static bool candidate_population_still_exact_for_mode(
    pid_t expected_pid, const struct process_snapshot *original_stock) {
    int stock_count = 0;
    int candidate_count = 0;
    pid_t stock_pid = -1;
    pid_t candidate_pid = -1;
    if (expected_pid <= 1 ||
        !count_process_paths(&stock_count, &stock_pid, &candidate_count,
                             &candidate_pid) ||
        candidate_count != 1 || candidate_pid != expected_pid) {
        return false;
    }
    if (original_stock == NULL) {
        return stock_count == 0;
    }
    return stock_count == 1 && stock_pid == original_stock->pid &&
           original_stock_still_exact_with_candidate_count(original_stock, 1);
}

/* ptrace may temporarily reparent a traced launchd child to this controller.
   Bind the candidate by executable generation rather than parent identity
   while traced, then require the ordinary launchd parent again after detach. */
static bool candidate_traced_snapshot_still_exact_for_mode(
    const struct process_snapshot *expected,
    const struct process_snapshot *original_stock, bool require_stopped,
    uint32_t *flags_out) {
    pid_t tracer_pid = getpid();
    if (expected == NULL || expected->pid <= 1 || tracer_pid <= 1 ||
        geteuid() != 0 || expected->bsd.pbi_uid != 501 ||
        expected->bsd.pbi_ppid != 1 || !candidate_path_exact(expected->path) ||
        memcmp(expected->unique.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) != 0 ||
        memcmp(expected->cdhash, kExpectedCandidateCDHash,
               sizeof(kExpectedCandidateCDHash)) != 0 ||
        !candidate_path_still_bound() ||
        !candidate_population_still_exact_for_mode(expected->pid,
                                                   original_stock)) {
        return false;
    }

    struct process_snapshot first = {.pid = expected->pid};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    uint32_t flags = 0;
    uint8_t cdhash[CODEX_CDHASH_SIZE] = {0};
    bool valid =
        copy_process_path(first.pid, first.path) &&
        candidate_path_exact(first.path) &&
        copy_bsd_info(first.pid, &first.bsd) && first.bsd.pbi_uid == 501 &&
        (first.bsd.pbi_ppid == 1 ||
         first.bsd.pbi_ppid == (uint32_t)tracer_pid) &&
        (!require_stopped ||
         first.bsd.pbi_status == CODEX_PROC_STATUS_STOPPED) &&
        copy_unique_info(first.pid, &first.unique) &&
        memcmp(first.unique.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) == 0 &&
        process_generation_equal(&first.unique, &expected->unique) &&
        csops(first.pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
        (flags & CODEX_CS_VALID) != 0 &&
        csops(first.pid, CODEX_CS_OPS_CDHASH, cdhash, sizeof(cdhash)) == 0 &&
        memcmp(cdhash, kExpectedCandidateCDHash, sizeof(cdhash)) == 0 &&
        copy_process_path(first.pid, second_path) &&
        strcmp(first.path, second_path) == 0 &&
        copy_unique_info(first.pid, &second_unique) &&
        process_generation_equal(&first.unique, &second_unique) &&
        first.pid == expected->pid && strcmp(first.path, expected->path) == 0 &&
        candidate_population_still_exact_for_mode(expected->pid,
                                                  original_stock);
    if (valid && flags_out != NULL) {
        *flags_out = flags;
    }
    return valid;
}

static bool wait_for_trace_stop_event(pid_t pid, int *status_out) {
    uint64_t deadline = monotonic_msec() + CODEX_TRACE_TIMEOUT_MSEC;
    do {
        int status = 0;
        pid_t waited = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (waited == pid) {
            if (status_out != NULL) {
                *status_out = status;
            }
            return WIFSTOPPED(status) &&
                   (WSTOPSIG(status) == 0 || WSTOPSIG(status) == SIGSTOP);
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    } while (monotonic_msec() < deadline && !gStopRequested);
    return false;
}

static bool wait_for_trace_stop(
    const struct process_snapshot *candidate,
    const struct process_snapshot *original_stock, int *status_out) {
    uint64_t deadline = monotonic_msec() + CODEX_TRACE_TIMEOUT_MSEC;
    do {
        int status = 0;
        pid_t waited = waitpid(candidate->pid, &status, WNOHANG | WUNTRACED);
        if (waited == candidate->pid) {
            if (status_out != NULL) {
                *status_out = status;
            }
            return WIFSTOPPED(status) &&
                   (WSTOPSIG(status) == 0 ||
                    WSTOPSIG(status) == SIGSTOP) &&
                   candidate_traced_snapshot_still_exact_for_mode(
                       candidate, original_stock, true, NULL);
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    } while (monotonic_msec() < deadline && !gStopRequested);
    return false;
}

static bool acquire_candidate_pid_hold(
    const struct process_snapshot *candidate,
    const struct process_snapshot *original_stock,
    struct candidate_pid_hold *hold, uint32_t *flags_out);

static bool cleanup_candidate_pid_hold(
    const struct process_snapshot *candidate,
    struct candidate_pid_hold *hold, const char *phase);

static bool attach_candidate_for_injection(
    const struct process_snapshot *candidate, uint32_t *attached_flags_out,
    const struct process_snapshot *original_stock, bool hold_traced,
    struct candidate_pid_hold *candidate_hold) {
    uint32_t flags = 0;
    if (!candidate_snapshot_still_unique_for_mode(
            candidate, original_stock, &flags)) {
        return false;
    }
    (void)journal_event("event=ptrace-attach-begin candidatePid=%d "
                        "pidVersion=%d uniqueId=%llu preFlags=0x%08x",
                        candidate->pid, candidate->unique.pid_version,
                        (unsigned long long)candidate->unique.unique_id,
                        flags);
    errno = 0;
    int attach_result = ptrace(PT_ATTACHEXC, candidate->pid, NULL, 0);
    int attach_error = attach_result == 0 ? 0 : errno;
    int trace_status = 0;
    bool initial_wait_stopped =
        attach_result == 0 &&
        (hold_traced
             ? wait_for_trace_stop_event(candidate->pid, &trace_status)
             : wait_for_trace_stop(candidate, original_stock, &trace_status));
    bool hold_acquired =
        initial_wait_stopped && hold_traced && candidate_hold != NULL &&
        acquire_candidate_pid_hold(candidate, original_stock,
                                   candidate_hold, &flags);
    bool initial_stopped =
        initial_wait_stopped &&
        (hold_traced
             ? hold_acquired
             : candidate_traced_snapshot_still_exact_for_mode(
                   candidate, original_stock, true, &flags));
    uint32_t initial_flags = flags;
    bool initially_softened =
        initial_stopped && (initial_flags & CODEX_CS_DEBUGGED) != 0 &&
        (initial_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;

    /* The gated path converts the initial PT_ATTACHEXC wait event directly
       into an audited pid_suspend hold.  It must never run the candidate to
       manufacture another stop: that opens an attach-to-hold execution gap. */
    int prime_continue = -1;
    int prime_continue_error = 0;
    int prime_signal = -1;
    int prime_signal_error = 0;
    int prime_status = 0;
    bool prime_stopped = false;
    bool owned_stop_required = !hold_traced && !initially_softened;
    if (initial_stopped && owned_stop_required &&
        candidate_traced_snapshot_still_exact_for_mode(
            candidate, original_stock, true, NULL)) {
        errno = 0;
        prime_continue = ptrace(PT_CONTINUE, candidate->pid, (caddr_t)1, 0);
        prime_continue_error = prime_continue == 0 ? 0 : errno;
        if (prime_continue == 0 &&
            candidate_traced_snapshot_still_exact_for_mode(
                candidate, original_stock, false, NULL)) {
            errno = 0;
            prime_signal = kill(candidate->pid, SIGSTOP);
            prime_signal_error = prime_signal == 0 ? 0 : errno;
        }
        prime_stopped =
            prime_signal == 0 &&
            wait_for_trace_stop(candidate, original_stock, &prime_status) &&
            WIFSTOPPED(prime_status) && WSTOPSIG(prime_status) == SIGSTOP &&
            candidate_traced_snapshot_still_exact_for_mode(
                candidate, original_stock, true, &flags) &&
            (flags & CODEX_CS_DEBUGGED) != 0 &&
            (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    }
    bool debug_ready = hold_traced ? (hold_acquired && initially_softened)
                                   : (initially_softened || prime_stopped);
    struct codex_proc_bsdinfo traced_bsd = {0};
    bool traced_bsd_ok = copy_bsd_info(candidate->pid, &traced_bsd);
    (void)journal_event(
        "event=ptrace-debug-prime candidatePid=%d attach=%d attachErrno=%d "
        "initialWaitStopped=%d initialStopped=%d initialStatus=0x%x "
        "initialFlags=0x%08x initiallySoftened=%d holdAcquired=%d "
        "holdOwned=%d ownedStopRequired=%d "
        "primeContinue=%d primeContinueErrno=%d "
        "primeSignal=%d primeSignalErrno=%d primeStopped=%d "
        "primeStatus=0x%x finalFlags=0x%08x debugReady=%d "
        "tracedBsdOk=%d tracedPpid=%u tracedStatus=%u",
        candidate->pid, attach_result, attach_error, initial_wait_stopped,
        initial_stopped, trace_status, initial_flags, initially_softened,
        hold_acquired, candidate_hold != NULL && candidate_hold->owned,
        owned_stop_required,
        prime_continue, prime_continue_error, prime_signal,
        prime_signal_error, prime_stopped, prime_status, flags, debug_ready,
        traced_bsd_ok,
        traced_bsd.pbi_ppid, traced_bsd.pbi_status);
    if (!debug_ready) {
        if (candidate_hold != NULL &&
            (candidate_hold->owned || MACH_PORT_VALID(candidate_hold->task))) {
            (void)cleanup_candidate_pid_hold(
                candidate, candidate_hold, "attach-rejected");
        }
        int abort_request =
            hold_traced || original_stock != NULL ? PT_KILL : PT_DETACH;
        int abort_result = -1;
        if (attach_result == 0 &&
            candidate_traced_snapshot_still_exact_for_mode(
                candidate, original_stock, false, NULL)) {
            abort_result = ptrace(abort_request, candidate->pid, NULL, 0);
        }
        (void)journal_event(
            "event=ptrace-attach-rejected result=%d errno=%d status=0x%x "
            "flags=0x%08x abortRequest=%d abortResult=%d",
            attach_result, attach_error, trace_status, flags, abort_request,
            abort_result);
        return false;
    }
    (void)journal_event("event=ptrace-debugged status=0x%x flags=0x%08x",
                        prime_stopped ? prime_status : trace_status, flags);
    if (hold_traced) {
        if (attached_flags_out != NULL) {
            *attached_flags_out = flags;
        }
        bool held_exact = hold_acquired && candidate_hold != NULL &&
                          candidate_hold->owned &&
                          MACH_PORT_VALID(candidate_hold->task) &&
                          candidate_traced_snapshot_still_exact_for_mode(
                              candidate, original_stock, true, NULL);
        (void)journal_event(
            "event=candidate-held-for-injection candidatePid=%d "
            "flags=0x%08x exact=%d",
            candidate->pid, flags, held_exact);
        return held_exact;
    }
    if (!candidate_traced_snapshot_still_exact_for_mode(
            candidate, original_stock, true, NULL) ||
        ptrace(PT_DETACH, candidate->pid, NULL, 0) != 0) {
        return false;
    }
    if (!candidate_snapshot_still_unique_for_mode(
            candidate, original_stock, &flags) ||
        (flags & CODEX_CS_DEBUGGED) == 0 ||
        (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0) {
        return false;
    }
    if (!candidate_snapshot_still_unique_for_mode(
            candidate, original_stock, NULL) ||
        kill(candidate->pid, SIGCONT) != 0) {
        return false;
    }
    if (attached_flags_out != NULL) {
        *attached_flags_out = flags;
    }
    return journal_event("event=candidate-resumed candidatePid=%d "
                         "flags=0x%08x",
                         candidate->pid, flags);
}

static bool attach_detach_resume_candidate(
    const struct process_snapshot *candidate, uint32_t *attached_flags_out,
    const struct process_snapshot *original_stock) {
    return attach_candidate_for_injection(candidate, attached_flags_out,
                                          original_stock, false, NULL);
}

struct remote_dyld_maturity {
    mach_vm_address_t all_image_info_address;
    uint64_t all_image_info_size;
    mach_vm_address_t info_array_address;
    mach_vm_address_t shared_cache_base_address;
    uint64_t info_array_change_timestamp;
    uint32_t format;
    uint32_t version;
    uint32_t image_count;
    bool lib_system_initialized;
    bool has_libdyld;
    bool has_libpthread;
    bool has_libsandbox;
};

static mach_vm_address_t canonical_remote_address(uint64_t address) {
    return (mach_vm_address_t)(address & 0x0000FFFFFFFFFFFFULL);
}

static bool read_remote_exact(task_t task, mach_vm_address_t address,
                              void *destination, size_t size) {
    if (!MACH_PORT_VALID(task) || address == 0 || destination == NULL ||
        size == 0 || size > UINT32_MAX) {
        return false;
    }
    vm_size_t copied = 0;
    kern_return_t result = vm_read_overwrite(
        task, (vm_address_t)canonical_remote_address(address),
        (vm_size_t)size, (vm_address_t)destination, &copied);
    return result == KERN_SUCCESS && copied == (vm_size_t)size;
}

static bool remote_string_equals(task_t task, mach_vm_address_t address,
                                 const char *expected) {
    if (expected == NULL) {
        return false;
    }
    size_t length = strlen(expected) + 1U;
    if (length > CODEX_PATH_SIZE) {
        return false;
    }
    char value[CODEX_PATH_SIZE] = {0};
    return read_remote_exact(task, address, value, length) &&
           memcmp(value, expected, length) == 0;
}

static bool copy_remote_dyld_maturity(
    task_t task, struct remote_dyld_maturity *maturity_out,
    bool inspect_required_images) {
    if (maturity_out == NULL) {
        return false;
    }
    memset(maturity_out, 0, sizeof(*maturity_out));

    task_dyld_info_data_t task_dyld_info = {0};
    mach_msg_type_number_t task_dyld_count = TASK_DYLD_INFO_COUNT;
    kern_return_t result = task_info(
        task, TASK_DYLD_INFO, (task_info_t)&task_dyld_info,
        &task_dyld_count);
    if (result != KERN_SUCCESS ||
        task_dyld_count < TASK_DYLD_INFO_COUNT ||
        task_dyld_info.all_image_info_addr == 0 ||
        task_dyld_info.all_image_info_format !=
            TASK_DYLD_ALL_IMAGE_INFO_64 ||
        task_dyld_info.all_image_info_size <
            sizeof(struct dyld_all_image_infos)) {
        return false;
    }

    struct dyld_all_image_infos image_infos = {0};
    if (!read_remote_exact(task, task_dyld_info.all_image_info_addr,
                           &image_infos, sizeof(image_infos))) {
        return false;
    }
    maturity_out->all_image_info_address =
        task_dyld_info.all_image_info_addr;
    maturity_out->all_image_info_size =
        task_dyld_info.all_image_info_size;
    maturity_out->format = task_dyld_info.all_image_info_format;
    maturity_out->info_array_address = canonical_remote_address(
        (uint64_t)image_infos.infoArray);
    maturity_out->shared_cache_base_address = canonical_remote_address(
        (uint64_t)image_infos.sharedCacheBaseAddress);
    maturity_out->info_array_change_timestamp =
        image_infos.infoArrayChangeTimestamp;
    maturity_out->version = image_infos.version;
    maturity_out->image_count = image_infos.infoArrayCount;
    maturity_out->lib_system_initialized =
        image_infos.libSystemInitialized;
    if (!inspect_required_images || !image_infos.libSystemInitialized ||
        maturity_out->info_array_address == 0 ||
        image_infos.infoArrayCount == 0 ||
        image_infos.infoArrayCount > CODEX_REMOTE_IMAGE_LIMIT) {
        return true;
    }

    size_t array_size =
        (size_t)image_infos.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *images = malloc(array_size);
    if (images == NULL ||
        !read_remote_exact(task, maturity_out->info_array_address, images,
                           array_size)) {
        free(images);
        return false;
    }
    for (uint32_t index = 0; index < image_infos.infoArrayCount; ++index) {
        mach_vm_address_t path_address = canonical_remote_address(
            (uint64_t)images[index].imageFilePath);
        if (!maturity_out->has_libdyld &&
            remote_string_equals(task, path_address,
                                 "/usr/lib/system/libdyld.dylib")) {
            maturity_out->has_libdyld = true;
        }
        if (!maturity_out->has_libpthread &&
            remote_string_equals(
                task, path_address,
                "/usr/lib/system/libsystem_pthread.dylib")) {
            maturity_out->has_libpthread = true;
        }
        if (!maturity_out->has_libsandbox &&
            remote_string_equals(
                task, path_address,
                "/usr/lib/system/libsystem_sandbox.dylib")) {
            maturity_out->has_libsandbox = true;
        }
        if (maturity_out->has_libdyld &&
            maturity_out->has_libpthread &&
            maturity_out->has_libsandbox) {
            break;
        }
    }
    free(images);
    return true;
}

static bool remote_dyld_maturity_complete(
    const struct remote_dyld_maturity *maturity) {
    return maturity != NULL && maturity->all_image_info_address != 0 &&
           maturity->all_image_info_size >=
               sizeof(struct dyld_all_image_infos) &&
           maturity->info_array_address != 0 &&
           maturity->image_count != 0 &&
           maturity->image_count <= CODEX_REMOTE_IMAGE_LIMIT &&
           maturity->format == TASK_DYLD_ALL_IMAGE_INFO_64 &&
           maturity->version >= 15 && maturity->lib_system_initialized;
}

enum traced_child_wait_state {
    TRACED_CHILD_NO_EVENT,
    TRACED_CHILD_STOP_EVENT,
    TRACED_CHILD_GONE,
    TRACED_CHILD_WAIT_ERROR,
};

static enum traced_child_wait_state poll_traced_child_wait_state(
    pid_t pid, int *status_out) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, WNOHANG | WUNTRACED);
    } while (waited < 0 && errno == EINTR);
    if (waited == 0) {
        return TRACED_CHILD_NO_EVENT;
    }
    if (waited == pid) {
        if (status_out != NULL) {
            *status_out = status;
        }
        return WIFSTOPPED(status) ? TRACED_CHILD_STOP_EVENT
                                  : TRACED_CHILD_GONE;
    }
    return TRACED_CHILD_WAIT_ERROR;
}

static bool wait_for_expected_trace_sigstop_fast(pid_t pid,
                                                  int *status_out) {
    uint64_t deadline = monotonic_msec() + CODEX_TRACE_TIMEOUT_MSEC;
    do {
        int status = 0;
        pid_t waited = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (waited == pid) {
            if (status_out != NULL) {
                *status_out = status;
            }
            return WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(CODEX_DYLD_MATURITY_POLL_USEC);
    } while (monotonic_msec() < deadline);
    return false;
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

static bool task_port_audit_matches_generation(
    task_t task, pid_t pid, int32_t pid_version,
    audit_token_t *token_out, kern_return_t *result_out) {
    audit_token_t token = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t result =
        MACH_PORT_VALID(task)
            ? task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count)
            : KERN_INVALID_TASK;
    bool exact = pid > 1 && result == KERN_SUCCESS &&
                 count == TASK_AUDIT_TOKEN_COUNT &&
                 token.val[5] == (uint32_t)pid &&
                 token.val[7] == (uint32_t)pid_version;
    if (token_out != NULL) {
        *token_out = token;
    }
    if (result_out != NULL) {
        *result_out = result;
    }
    return exact;
}

static bool task_port_audit_matches_candidate(
    task_t task, const struct process_snapshot *candidate,
    audit_token_t *token_out, kern_return_t *result_out) {
    return candidate != NULL &&
           task_port_audit_matches_generation(
               task, candidate->pid, candidate->unique.pid_version,
               token_out, result_out);
}

static bool copy_stable_process_generation(
    pid_t pid, struct codex_proc_uniqidentifierinfo *generation_out) {
    struct codex_proc_uniqidentifierinfo first = {0};
    struct codex_proc_uniqidentifierinfo second = {0};
    if (pid <= 1 || generation_out == NULL ||
        !copy_unique_info(pid, &first) || !copy_unique_info(pid, &second) ||
        !process_generation_equal(&first, &second)) {
        return false;
    }
    *generation_out = second;
    return true;
}

static bool candidate_pid_hold_is_exact(
    const struct process_snapshot *candidate, task_t task,
    bool pid_hold_owned, integer_t *count_out, uint32_t *flags_out) {
    integer_t count = 0;
    uint32_t flags = 0;
    bool exact =
        pid_hold_owned &&
        task_port_audit_matches_candidate(task, candidate, NULL, NULL) &&
        copy_task_suspend_count(task, &count) && count >= 1 &&
        candidate_traced_snapshot_still_exact_for_mode(
            candidate, NULL, false, &flags) &&
        (flags & CODEX_CS_DEBUGGED) != 0 &&
        (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    if (count_out != NULL) {
        *count_out = count;
    }
    if (exact && flags_out != NULL) {
        *flags_out = flags;
    }
    return exact;
}

static bool balance_owned_pid_hold(
    pid_t pid, const struct codex_proc_uniqidentifierinfo *held_generation,
    task_t held_task, bool *pid_hold_owned_io, const char *phase) {
    if (pid_hold_owned_io == NULL || !*pid_hold_owned_io) {
        return true;
    }
    kern_return_t audit_result = KERN_INVALID_TASK;
    bool audit_exact =
        held_generation != NULL &&
        task_port_audit_matches_generation(
            held_task, pid, held_generation->pid_version, NULL,
            &audit_result);
    struct codex_proc_uniqidentifierinfo current_generation = {0};
    bool generation_query_valid = copy_stable_process_generation(
        pid, &current_generation);
    bool generation_exact =
        held_generation != NULL && generation_query_valid &&
        process_generation_equal(&current_generation, held_generation);
    int resume_result = -1;
    int resume_error = 0;
    bool held_task_destroyed =
        held_generation != NULL && generation_query_valid &&
        !generation_exact;
    if (held_task_destroyed) {
        *pid_hold_owned_io = false;
    } else if (held_generation == NULL || generation_exact || audit_exact) {
        /* A successful pid_suspend established ownership.  With no captured
           identity, immediately balance that just-acquired hold rather than
           treating an unavailable query as proof the task died. */
        errno = 0;
        resume_result = pid_resume(pid);
        resume_error = resume_result == 0 ? 0 : errno;
        if (resume_result == 0) {
            *pid_hold_owned_io = false;
        }
    }
    (void)journal_event(
        "event=gated-pair-pid-hold-balance phase=%s target=%d "
        "auditKr=%d auditExact=%d generationQueryValid=%d "
        "generationExact=%d taskDestroyed=%d identityUnknown=%d "
        "resume=%d resumeErrno=%d holdOwned=%d",
        phase != NULL ? phase : "unknown", pid, audit_result, audit_exact,
        generation_query_valid, generation_exact, held_task_destroyed,
        held_generation == NULL, resume_result, resume_error,
        *pid_hold_owned_io);
    return !*pid_hold_owned_io;
}

static bool fail_closed_candidate_pid_hold(
    const struct process_snapshot *candidate,
    const struct codex_proc_uniqidentifierinfo *held_generation,
    task_t held_task, bool *pid_hold_owned_io, const char *phase) {
    if (candidate == NULL || pid_hold_owned_io == NULL) {
        return false;
    }
    bool owned_before = *pid_hold_owned_io;
    kern_return_t terminate_result =
        MACH_PORT_VALID(held_task) ? task_terminate(held_task)
                                  : KERN_INVALID_TASK;
    if (terminate_result == KERN_SUCCESS) {
        *pid_hold_owned_io = false;
    } else if (*pid_hold_owned_io) {
        /* Revalidate after the failed termination.  Cached pre-termination
           identity must never authorize a PID-based resume. */
        (void)balance_owned_pid_hold(
            candidate->pid, held_generation, held_task,
            pid_hold_owned_io, phase);
    }
    bool resolved = !*pid_hold_owned_io;
    (void)journal_event(
        "event=gated-pair-pid-hold-cleanup phase=%s target=%d "
        "ownedBefore=%d terminate=%d resolved=%d holdOwned=%d",
        phase != NULL ? phase : "unknown", candidate->pid, owned_before,
        terminate_result, resolved, *pid_hold_owned_io);
    return resolved;
}

static bool cleanup_candidate_pid_hold(
    const struct process_snapshot *candidate,
    struct candidate_pid_hold *hold, const char *phase) {
    if (candidate == NULL || hold == NULL) {
        return false;
    }
    if (!hold->owned && !MACH_PORT_VALID(hold->task)) {
        return true;
    }
    bool resolved = fail_closed_candidate_pid_hold(
        candidate, &hold->generation, hold->task, &hold->owned, phase);
    if (resolved && MACH_PORT_VALID(hold->task)) {
        (void)mach_port_deallocate(mach_task_self(), hold->task);
        hold->task = MACH_PORT_NULL;
    }
    return resolved;
}

static bool acquire_candidate_pid_hold(
    const struct process_snapshot *candidate,
    const struct process_snapshot *original_stock,
    struct candidate_pid_hold *hold, uint32_t *flags_out) {
    if (candidate == NULL || candidate->pid <= 1 || hold == NULL ||
        hold->owned || MACH_PORT_VALID(hold->task)) {
        return false;
    }

    task_t task = MACH_PORT_NULL;
    kern_return_t task_result =
        task_for_pid(mach_task_self(), candidate->pid, &task);
    audit_token_t audit = {{0}};
    kern_return_t audit_result = KERN_INVALID_TASK;
    bool audit_exact =
        task_result == KERN_SUCCESS && MACH_PORT_VALID(task) &&
        task_port_audit_matches_candidate(task, candidate, &audit,
                                          &audit_result);
    struct codex_proc_uniqidentifierinfo generation = {0};
    bool generation_exact =
        audit_exact &&
        copy_stable_process_generation(candidate->pid, &generation) &&
        process_generation_equal(&generation, &candidate->unique);
    integer_t baseline = 0;
    bool baseline_valid =
        generation_exact && copy_task_suspend_count(task, &baseline) &&
        baseline >= 0 && baseline < INT_MAX;
    errno = 0;
    int suspend_result =
        baseline_valid ? pid_suspend(candidate->pid) : -1;
    int suspend_error = suspend_result == 0 ? 0 : errno;

    if (suspend_result == 0) {
        hold->pid = candidate->pid;
        hold->task = task;
        hold->generation = generation;
        hold->baseline_suspend_count = baseline;
        hold->owned = true;
        task = MACH_PORT_NULL;
    }

    struct codex_proc_uniqidentifierinfo held_generation = {0};
    integer_t held_count = 0;
    uint32_t flags = 0;
    bool held_generation_exact =
        hold->owned &&
        copy_stable_process_generation(candidate->pid, &held_generation) &&
        process_generation_equal(&held_generation, &hold->generation) &&
        process_generation_equal(&held_generation, &candidate->unique);
    bool held_audit_exact =
        hold->owned && task_port_audit_matches_candidate(
                           hold->task, candidate, NULL, NULL);
    bool held_count_exact =
        hold->owned && copy_task_suspend_count(hold->task, &held_count) &&
        held_count == hold->baseline_suspend_count + 1;
    bool held_candidate_exact =
        hold->owned &&
        candidate_traced_snapshot_still_exact_for_mode(
            candidate, original_stock, true, &flags) &&
        (flags & CODEX_CS_DEBUGGED) != 0 &&
        (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    bool exact = held_generation_exact && held_audit_exact &&
                 held_count_exact && held_candidate_exact;
    (void)journal_event(
        "event=attach-pid-hold target=%d taskKr=%d auditKr=%d "
        "auditPid=%u auditPidVersion=%u auditExact=%d "
        "generationExact=%d baselineValid=%d baseline=%d suspend=%d "
        "suspendErrno=%d heldGenerationExact=%d heldAuditExact=%d "
        "heldCount=%d heldCountExact=%d heldCandidateExact=%d "
        "owned=%d exact=%d flags=0x%08x",
        candidate->pid, task_result, audit_result, audit.val[5], audit.val[7],
        audit_exact, generation_exact, baseline_valid, baseline,
        suspend_result, suspend_error, held_generation_exact,
        held_audit_exact, held_count, held_count_exact, held_candidate_exact,
        hold->owned, exact, flags);

    if (MACH_PORT_VALID(task)) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }
    if (!exact) {
        if (hold->owned || MACH_PORT_VALID(hold->task)) {
            (void)cleanup_candidate_pid_hold(candidate, hold,
                                             "attach-hold-rejected");
        }
        return false;
    }
    if (flags_out != NULL) {
        *flags_out = flags;
    }
    return true;
}

static bool mature_and_restop_traced_candidate(
    const struct process_snapshot *candidate, task_t target_task,
    uint32_t *flags_out) {
    uint32_t flags = 0;
    if (candidate == NULL || candidate->pid <= 1 ||
        !MACH_PORT_VALID(target_task) ||
        !task_port_audit_matches_candidate(
            target_task, candidate, NULL, NULL)) {
        return false;
    }

    struct codex_proc_bsdinfo initial_bsd = {0};
    bool initial_bsd_valid = copy_bsd_info(candidate->pid, &initial_bsd);
    bool initially_stopped =
        initial_bsd_valid &&
        initial_bsd.pbi_status == CODEX_PROC_STATUS_STOPPED;
    struct remote_dyld_maturity maturity = {0};
    struct remote_dyld_maturity stable = {0};
    bool mature = false;
    int unexpected_wait_status = 0;
    enum traced_child_wait_state wait_state = TRACED_CHILD_NO_EVENT;
    uint64_t deadline =
        monotonic_msec() + CODEX_DYLD_MATURITY_TIMEOUT_MSEC;
    while (monotonic_msec() < deadline && !gStopRequested) {
        wait_state = poll_traced_child_wait_state(
            candidate->pid, &unexpected_wait_status);
        if (wait_state != TRACED_CHILD_NO_EVENT) {
            break;
        }
        if (copy_remote_dyld_maturity(target_task, &maturity, false) &&
            remote_dyld_maturity_complete(&maturity)) {
            usleep(CODEX_DYLD_MATURITY_POLL_USEC);
            if (copy_remote_dyld_maturity(target_task, &stable, false) &&
                stable.lib_system_initialized &&
                stable.all_image_info_address ==
                    maturity.all_image_info_address &&
                stable.all_image_info_size ==
                    maturity.all_image_info_size &&
                stable.info_array_address == maturity.info_array_address &&
                stable.shared_cache_base_address ==
                    maturity.shared_cache_base_address &&
                stable.info_array_change_timestamp ==
                    maturity.info_array_change_timestamp &&
                stable.format == maturity.format &&
                stable.version == maturity.version &&
                stable.image_count == maturity.image_count) {
                mature = true;
                break;
            }
        }
        usleep(CODEX_DYLD_MATURITY_POLL_USEC);
    }

    errno = 0;
    int stop_result =
        wait_state == TRACED_CHILD_NO_EVENT ? kill(candidate->pid, SIGSTOP)
                                            : -1;
    int stop_error = stop_result == 0 ? 0 : errno;
    int stop_status = 0;
    bool requested_stop_observed =
        stop_result == 0 &&
        wait_for_expected_trace_sigstop_fast(candidate->pid,
                                             &stop_status);
    bool stopped_by_wait_event =
        wait_state == TRACED_CHILD_STOP_EVENT;
    kern_return_t forced_termination = KERN_SUCCESS;
    if (!requested_stop_observed && !stopped_by_wait_event &&
        wait_state != TRACED_CHILD_GONE) {
        forced_termination = task_terminate(target_task);
    }
    bool restopped =
        requested_stop_observed &&
        candidate_traced_snapshot_still_exact_for_mode(
            candidate, NULL, true, &flags) &&
        (flags & CODEX_CS_DEBUGGED) != 0 &&
        (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    bool result = mature && restopped;
    (void)journal_event(
        "event=candidate-dyld-maturity candidatePid=%d "
        "initialBsdValid=%d initiallyStopped=%d executionReleased=1 "
        "mature=%d restopped=%d stop=%d stopErrno=%d "
        "stopStatus=0x%x dyld=0x%llx array=0x%llx version=%u count=%u "
        "format=%u changeTimestamp=%llu sharedCacheBase=0x%llx "
        "waitState=%d unexpectedWaitStatus=0x%x requestedStop=%d "
        "forcedTermination=%d "
        "libSystemInitialized=%d libdyld=%d libpthread=%d "
        "libsandbox=%d flags=0x%08x",
        candidate->pid, initial_bsd_valid, initially_stopped, mature,
        restopped, stop_result, stop_error, stop_status,
        (unsigned long long)maturity.all_image_info_address,
        (unsigned long long)maturity.info_array_address, maturity.version,
        maturity.image_count, maturity.format,
        (unsigned long long)maturity.info_array_change_timestamp,
        (unsigned long long)maturity.shared_cache_base_address,
        wait_state, unexpected_wait_status, requested_stop_observed,
        forced_termination,
        maturity.lib_system_initialized,
        maturity.has_libdyld, maturity.has_libpthread,
        maturity.has_libsandbox, flags);
    if (result && flags_out != NULL) {
        *flags_out = flags;
    }
    return result;
}

static int run_candidate_loader_pair_gated(
    const struct process_snapshot *candidate, uint32_t *candidate_flags_io,
    bool *candidate_attached_io, struct candidate_pid_hold *candidate_hold) {
    uint32_t flags = 0;
    if (candidate == NULL || candidate->pid <= 1 ||
        candidate_flags_io == NULL || candidate_attached_io == NULL ||
        candidate_hold == NULL || !*candidate_attached_io ||
        candidate_hold->pid != candidate->pid ||
        !candidate_hold->owned ||
        !MACH_PORT_VALID(candidate_hold->task) || geteuid() != 0) {
        return 80;
    }

    task_t target_task = candidate_hold->task;
    integer_t suspend_before = candidate_hold->baseline_suspend_count;
    struct codex_proc_uniqidentifierinfo held_generation =
        candidate_hold->generation;
    audit_token_t task_audit = {{0}};
    kern_return_t task_audit_result = KERN_INVALID_TASK;
    bool task_audit_exact = task_port_audit_matches_candidate(
        target_task, candidate, &task_audit, &task_audit_result);
    struct codex_proc_bsdinfo task_bsd = {0};
    bool task_bsd_exact =
        copy_bsd_info(candidate->pid, &task_bsd) &&
        task_bsd.pbi_uid == 501 &&
        (task_bsd.pbi_ppid == 1 ||
         task_bsd.pbi_ppid == (uint32_t)getpid()) &&
        task_bsd.pbi_status == CODEX_PROC_STATUS_STOPPED;
    bool task_flags_exact =
        csops(candidate->pid, CODEX_CS_OPS_STATUS,
              &flags, sizeof(flags)) == 0 &&
        (flags & (CODEX_CS_VALID | CODEX_CS_DEBUGGED)) ==
            (CODEX_CS_VALID | CODEX_CS_DEBUGGED) &&
        (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    integer_t suspend_after = 0;
    struct codex_proc_uniqidentifierinfo current_generation = {0};
    bool held_generation_exact =
        copy_stable_process_generation(
            candidate->pid, &current_generation) &&
        process_generation_equal(&current_generation, &held_generation) &&
        process_generation_equal(&held_generation, &candidate->unique);
    bool suspend_after_valid =
        candidate_hold->owned && task_audit_exact &&
        copy_task_suspend_count(target_task, &suspend_after);
    bool fixed_artifacts_exact =
        secure_existing_regular_file(kWorkerPath, 0, true, NULL, NULL) &&
        secure_existing_regular_file(kLoaderCandidatePath, 0, true, NULL,
                                     NULL) &&
        secure_existing_regular_file(kDyldAdmissionHookPath, 0, false, NULL,
                                     NULL) &&
        secure_existing_regular_file(kFreshCanaryPath, 0, false, NULL,
                                     NULL);
    bool pid_hold_exact =
        suspend_before >= 0 && suspend_before < INT_MAX &&
        held_generation_exact && task_audit_exact && task_bsd_exact &&
        task_flags_exact && suspend_after_valid &&
        suspend_after == suspend_before + 1 && fixed_artifacts_exact &&
        candidate_pid_hold_is_exact(candidate, target_task,
                                    candidate_hold->owned, NULL, &flags);
    (void)journal_event(
        "event=gated-pair-pid-hold target=%d source=attach-ledger "
        "auditKr=%d auditPid=%u auditPidVersion=%u auditExact=%d "
        "bsdExact=%d bsdStatus=%u flagsExact=%d generationExact=%d "
        "baseline=%d afterValid=%d after=%d artifactsExact=%d "
        "held=%d exact=%d flags=0x%08x",
        candidate->pid, task_audit_result, task_audit.val[5],
        task_audit.val[7], task_audit_exact, task_bsd_exact,
        task_bsd.pbi_status, task_flags_exact, held_generation_exact,
        suspend_before, suspend_after_valid, suspend_after,
        fixed_artifacts_exact, candidate_hold->owned, pid_hold_exact, flags);
    if (!pid_hold_exact) {
        bool cleanup_resolved = cleanup_candidate_pid_hold(
            candidate, candidate_hold, "hold-rejected");
        (void)journal_event(
            "event=gated-pair-pid-hold-rejected target=%d "
            "cleanupResolved=%d holdOwned=%d next=outer-rollback",
            candidate->pid, cleanup_resolved, candidate_hold->owned);
        return 81;
    }

    int ready_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    int pipe_result = pipe(ready_pipe) == 0 && pipe(release_pipe) == 0
                          ? 0
                          : errno;
    bool fixed_fd_collision = false;
    for (size_t index = 0; index < 2; ++index) {
        fixed_fd_collision =
            fixed_fd_collision || ready_pipe[index] == CODEX_GATE_READY_FD ||
            ready_pipe[index] == CODEX_GATE_RELEASE_FD ||
            release_pipe[index] == CODEX_GATE_READY_FD ||
            release_pipe[index] == CODEX_GATE_RELEASE_FD;
    }
    if (pipe_result != 0 || fixed_fd_collision) {
        for (size_t index = 0; index < 2; ++index) {
            if (ready_pipe[index] >= 0) {
                close(ready_pipe[index]);
            }
            if (release_pipe[index] >= 0) {
                close(release_pipe[index]);
            }
        }
        bool cleanup_resolved = cleanup_candidate_pid_hold(
            candidate, candidate_hold, "pipe-setup");
        (void)journal_event(
            "event=gated-pair-cleanup-disposition phase=pipe-setup "
            "resolved=%d next=outer-rollback",
            cleanup_resolved);
        return 82;
    }
    set_close_on_exec(ready_pipe[0]);
    set_close_on_exec(release_pipe[1]);

    char pid_text[24];
    char ready_fd_text[16];
    char release_fd_text[16];
    int pid_length = snprintf(pid_text, sizeof(pid_text), "%d",
                              candidate->pid);
    int ready_fd_length = snprintf(ready_fd_text, sizeof(ready_fd_text), "%d",
                                   CODEX_GATE_READY_FD);
    int release_fd_length = snprintf(release_fd_text,
                                     sizeof(release_fd_text), "%d",
                                     CODEX_GATE_RELEASE_FD);
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int actions_result = posix_spawn_file_actions_init(&actions);
    int attributes_result = posix_spawnattr_init(&attributes);
    int setup_result = actions_result != 0 ? actions_result
                                           : attributes_result;
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, gJournalDescriptor, STDOUT_FILENO);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, gJournalDescriptor, STDERR_FILENO);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, ready_pipe[1], CODEX_GATE_READY_FD);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, release_pipe[0], CODEX_GATE_RELEASE_FD);
    }
    for (size_t index = 0; setup_result == 0 && index < 2; ++index) {
        setup_result = posix_spawn_file_actions_addclose(
            &actions, ready_pipe[index]);
        if (setup_result == 0) {
            setup_result = posix_spawn_file_actions_addclose(
                &actions, release_pipe[index]);
        }
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setflags(
            &attributes, POSIX_SPAWN_SETPGROUP);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_set_ptrauth_task_port_np(
            &attributes, target_task);
    }

    char *arguments[] = {
        (char *)kWorkerPath,
        (char *)"--macho",
        (char *)kLoaderCandidatePath,
        (char *)"--inject-pid-pair-gated",
        pid_text,
        (char *)kDyldAdmissionHookPath,
        (char *)kFreshCanaryPath,
        ready_fd_text,
        release_fd_text,
        (char *)"--ptrauth-child",
        NULL,
    };
    bool argument_lengths_valid =
        pid_length > 0 && (size_t)pid_length < sizeof(pid_text) &&
        ready_fd_length > 0 &&
        (size_t)ready_fd_length < sizeof(ready_fd_text) &&
        release_fd_length > 0 &&
        (size_t)release_fd_length < sizeof(release_fd_text);
    pid_t child = -1;
    int spawn_result =
        setup_result == 0 && argument_lengths_valid
            ? posix_spawn(&child, kWorkerPath, &actions, &attributes,
                          arguments, environ)
            : (setup_result != 0 ? setup_result : EINVAL);
    if (actions_result == 0) {
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    if (attributes_result == 0) {
        (void)posix_spawnattr_destroy(&attributes);
    }
    close(ready_pipe[1]);
    ready_pipe[1] = -1;
    close(release_pipe[0]);
    release_pipe[0] = -1;
    (void)journal_event(
        "event=gated-pair-worker-spawn target=%d child=%d spawn=%d "
        "readyFd=%d releaseFd=%d",
        candidate->pid, child, spawn_result, CODEX_GATE_READY_FD,
        CODEX_GATE_RELEASE_FD);
    if (spawn_result != 0 || child <= 1 || getpgid(child) != child) {
        if (child > 1) {
            (void)kill(child, SIGKILL);
            (void)waitpid(child, NULL, 0);
        }
        close(ready_pipe[0]);
        close(release_pipe[1]);
        bool cleanup_resolved = cleanup_candidate_pid_hold(
            candidate, candidate_hold, "worker-spawn");
        (void)journal_event(
            "event=gated-pair-cleanup-disposition phase=worker-spawn "
            "resolved=%d next=outer-rollback",
            cleanup_resolved);
        return 82;
    }

    set_nonblocking(ready_pipe[0]);
    bool ready = false;
    bool protocol_valid = true;
    bool candidate_exact = true;
    bool complete = false;
    int status = 0;
    uint64_t ready_deadline =
        monotonic_msec() + CODEX_INJECTION_TIMEOUT_MSEC;
    do {
        uint8_t ready_byte = 0;
        ssize_t amount = read(ready_pipe[0], &ready_byte,
                              sizeof(ready_byte));
        if (amount == (ssize_t)sizeof(ready_byte)) {
            ready = ready_byte == (uint8_t)'R';
            protocol_valid = ready;
            break;
        }
        if (amount == 0 ||
            (amount < 0 && errno != EINTR && errno != EAGAIN &&
             errno != EWOULDBLOCK)) {
            protocol_valid = false;
            break;
        }
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            complete = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        candidate_exact = candidate_pid_hold_is_exact(
            candidate, target_task, candidate_hold->owned, NULL, &flags);
        if (!candidate_exact || gStopRequested || takeover_requested()) {
            break;
        }
        usleep(2U * 1000U);
    } while (monotonic_msec() < ready_deadline);

    candidate_exact =
        ready && protocol_valid && !complete &&
        candidate_pid_hold_is_exact(candidate, target_task,
                                    candidate_hold->owned, NULL, &flags);
    close(ready_pipe[0]);
    ready_pipe[0] = -1;
    if (!candidate_exact || gStopRequested || takeover_requested()) {
        close(release_pipe[1]);
        release_pipe[1] = -1;
        if (!complete) {
            terminate_injection_process_group(child);
        }
        int early_result =
            complete && WIFEXITED(status) ? WEXITSTATUS(status) : 83;
        (void)journal_event(
            "event=gated-pair-ready target=%d child=%d ready=%d "
            "protocolValid=%d candidateExact=%d complete=%d result=%d",
            candidate->pid, child, ready, protocol_valid, candidate_exact,
            complete, early_result);
        bool cleanup_resolved = cleanup_candidate_pid_hold(
            candidate, candidate_hold, "worker-ready");
        (void)journal_event(
            "event=gated-pair-cleanup-disposition phase=worker-ready "
            "resolved=%d next=outer-rollback",
            cleanup_resolved);
        return early_result;
    }

    integer_t suspend_before_resume = 0;
    integer_t suspend_after_resume = 0;
    bool before_resume_exact = candidate_pid_hold_is_exact(
        candidate, target_task, candidate_hold->owned,
        &suspend_before_resume, &flags);
    struct codex_proc_bsdinfo release_bsd = {0};
    bool release_bsd_valid =
        before_resume_exact && copy_bsd_info(candidate->pid, &release_bsd);
    bool release_was_stopped =
        release_bsd_valid &&
        release_bsd.pbi_status == CODEX_PROC_STATUS_STOPPED;
    bool pre_continue_exact =
        before_resume_exact && release_was_stopped &&
        suspend_before >= 0 && suspend_before < INT_MAX &&
        suspend_before_resume == suspend_before + 1 &&
        task_port_audit_matches_candidate(
            target_task, candidate, NULL, NULL) &&
        process_generation_equal(&candidate_hold->generation,
                                 &candidate->unique);
    errno = 0;
    int continue_result =
        pre_continue_exact
            ? ptrace(PT_CONTINUE, candidate->pid, (caddr_t)1, 0)
            : -1;
    int continue_error = continue_result == 0 ? 0 : errno;
    struct codex_proc_uniqidentifierinfo release_generation = {0};
    integer_t count_while_held = 0;
    bool continued_while_held_exact =
        continue_result == 0 && candidate_hold->owned &&
        task_port_audit_matches_candidate(
            target_task, candidate, NULL, NULL) &&
        copy_stable_process_generation(candidate->pid,
                                       &release_generation) &&
        process_generation_equal(&release_generation,
                                 &candidate_hold->generation) &&
        copy_task_suspend_count(target_task, &count_while_held) &&
        count_while_held == suspend_before + 1;
    errno = 0;
    int resume_result =
        continued_while_held_exact ? pid_resume(candidate->pid) : -1;
    int resume_error = resume_result == 0 ? 0 : errno;
    if (resume_result == 0) {
        candidate_hold->owned = false;
    }
    bool after_resume_valid =
        resume_result == 0 &&
        copy_task_suspend_count(target_task, &suspend_after_resume);
    bool suspend_count_restored =
        after_resume_valid && suspend_before >= 0 &&
        suspend_before < INT_MAX &&
        suspend_before_resume == suspend_before + 1 &&
        suspend_after_resume == suspend_before;
    bool pid_release_exact =
        continued_while_held_exact && resume_result == 0 &&
        !candidate_hold->owned && suspend_count_restored;
    (void)journal_event(
        "event=gated-pair-pid-release target=%d beforeExact=%d before=%d "
        "baseline=%d bsdValid=%d bsdStatus=%u wasStopped=%d "
        "preContinueExact=%d continue=%d continueErrno=%d "
        "continuedHeldExact=%d heldCount=%d resume=%d resumeErrno=%d "
        "afterValid=%d after=%d countRestored=%d held=%d exact=%d "
        "flags=0x%08x",
        candidate->pid, before_resume_exact, suspend_before_resume,
        suspend_before, release_bsd_valid, release_bsd.pbi_status,
        release_was_stopped, pre_continue_exact, continue_result,
        continue_error, continued_while_held_exact, count_while_held,
        resume_result, resume_error, after_resume_valid,
        suspend_after_resume, suspend_count_restored,
        candidate_hold->owned, pid_release_exact, flags);
    if (!pid_release_exact || gStopRequested || takeover_requested()) {
        close(release_pipe[1]);
        release_pipe[1] = -1;
        terminate_injection_process_group(child);
        bool cleanup_resolved = cleanup_candidate_pid_hold(
            candidate, candidate_hold, "pid-release");
        (void)journal_event(
            "event=gated-pair-cleanup-disposition phase=pid-release "
            "resolved=%d next=outer-rollback",
            cleanup_resolved);
        return 85;
    }

    bool maturity_ready = mature_and_restop_traced_candidate(
        candidate, target_task, &flags);
    if (!maturity_ready || gStopRequested || takeover_requested()) {
        close(release_pipe[1]);
        release_pipe[1] = -1;
        terminate_injection_process_group(child);
        bool cleanup_resolved = cleanup_candidate_pid_hold(
            candidate, candidate_hold, "maturity");
        (void)journal_event(
            "event=gated-pair-cleanup-disposition phase=maturity "
            "resolved=%d next=outer-rollback",
            cleanup_resolved);
        (void)journal_event(
            "event=gated-pair-maturity-rejected target=%d child=%d "
            "maturityReady=%d flags=0x%08x",
            candidate->pid, child, maturity_ready, flags);
        return 85;
    }

    uint8_t release_byte = (uint8_t)'G';
    (void)signal(SIGPIPE, SIG_IGN);
    errno = 0;
    int detach_result = ptrace(PT_DETACH, candidate->pid, NULL, 0);
    int detach_error = detach_result == 0 ? 0 : errno;
    if (detach_result == 0) {
        *candidate_attached_io = false;
        *candidate_flags_io = flags;
    }
    bool release_written =
        detach_result == 0 &&
        write_all(release_pipe[1], &release_byte,
                  sizeof(release_byte));
    close(release_pipe[1]);
    release_pipe[1] = -1;
    (void)journal_event(
        "event=gated-pair-release target=%d child=%d ready=1 "
        "releaseWritten=%d detach=%d detachErrno=%d flags=0x%08x",
        candidate->pid, child, release_written, detach_result, detach_error,
        flags);
    if (!release_written || detach_result != 0) {
        terminate_injection_process_group(child);
        (void)cleanup_candidate_pid_hold(
            candidate, candidate_hold, "detach-or-release");
        return 86;
    }
    if (!candidate_hold->owned && MACH_PORT_VALID(candidate_hold->task)) {
        (void)mach_port_deallocate(mach_task_self(), candidate_hold->task);
        candidate_hold->task = MACH_PORT_NULL;
    }

    complete = false;
    uint64_t completion_deadline =
        monotonic_msec() + CODEX_INJECTION_TIMEOUT_MSEC;
    do {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            complete = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        if (gStopRequested || takeover_requested()) {
            break;
        }
        usleep(2U * 1000U);
    } while (monotonic_msec() < completion_deadline);
    if (!complete) {
        terminate_injection_process_group(child);
    }
    int result = complete && WIFEXITED(status) ? WEXITSTATUS(status) : 83;
    bool candidate_exact_after =
        candidate_debug_policy_still_exact(candidate, candidate_flags_io);
    (void)journal_event(
        "event=gated-pair-final target=%d child=%d complete=%d "
        "status=0x%x result=%d candidateExactAfter=%d",
        candidate->pid, child, complete, status, result,
        candidate_exact_after);
    return result;
}

static bool observe_candidate(
    const struct process_snapshot *candidate,
    const struct process_snapshot *original_stock) {
    uint64_t begin = monotonic_msec();
    uint64_t deadline = begin + CODEX_OBSERVE_MSEC;
    uint32_t flags = 0;
    do {
        if (gStopRequested ||
            !candidate_snapshot_still_unique_for_mode(
                candidate, original_stock, &flags) ||
            (flags & CODEX_CS_DEBUGGED) == 0 ||
            (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0) {
            return false;
        }
        usleep(50U * 1000U);
    } while (monotonic_msec() < deadline);
    uint64_t elapsed = monotonic_msec() - begin;
    return elapsed >= CODEX_OBSERVE_MSEC &&
           candidate_snapshot_still_unique_for_mode(
               candidate, original_stock, &flags) &&
           journal_event("event=candidate-observed candidatePid=%d "
                         "elapsedMs=%llu flags=0x%08x",
                         candidate->pid, (unsigned long long)elapsed, flags);
}

static bool parse_int32_exact(const char *text, int32_t *value_out) {
    if (text == NULL || value_out == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    long long value = strtoll(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value < INT32_MIN || value > INT32_MAX) {
        return false;
    }
    *value_out = (int32_t)value;
    return true;
}

static bool parse_uint64_exact(const char *text, uint64_t *value_out) {
    if (text == NULL || value_out == NULL || *text == '\0' || *text == '-') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    *value_out = (uint64_t)value;
    return true;
}

static bool read_cryptexd_snapshot(pid_t pid,
                                   struct process_snapshot *snapshot,
                                   uint32_t *flags_out) {
    if (snapshot == NULL || pid <= 1) {
        return false;
    }
    struct process_snapshot first = {.pid = pid};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    uint32_t flags = 0;
    if (!copy_process_path(pid, first.path) ||
        strcmp(first.path, kCryptexdPath) != 0 ||
        !copy_bsd_info(pid, &first.bsd) || first.bsd.pbi_uid != 0 ||
        first.bsd.pbi_ppid != 1 || !copy_unique_info(pid, &first.unique) ||
        memcmp(first.unique.uuid, kExpectedCryptexdUUID,
               sizeof(kExpectedCryptexdUUID)) != 0 ||
        csops(pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) != 0 ||
        (flags & CODEX_CS_VALID) == 0 ||
        !copy_process_path(pid, second_path) ||
        strcmp(first.path, second_path) != 0 ||
        !copy_unique_info(pid, &second_unique) ||
        !unique_identity_equal(&first.unique, &second_unique)) {
        return false;
    }
    *snapshot = first;
    if (flags_out != NULL) {
        *flags_out = flags;
    }
    return true;
}

static bool cryptexd_snapshot_still_exact(
    const struct process_snapshot *expected, uint32_t *flags_out) {
    if (expected == NULL || expected->pid <= 1) {
        return false;
    }
    struct process_snapshot current = {0};
    uint32_t flags = 0;
    bool valid = read_cryptexd_snapshot(expected->pid, &current, &flags) &&
                 current.pid == expected->pid &&
                 current.bsd.pbi_uid == expected->bsd.pbi_uid &&
                 current.bsd.pbi_ppid == expected->bsd.pbi_ppid &&
                 strcmp(current.path, expected->path) == 0 &&
                 unique_identity_equal(&current.unique, &expected->unique);
    if (valid && flags_out != NULL) {
        *flags_out = flags;
    }
    return valid;
}

static bool cryptexd_traced_snapshot_still_exact(
    const struct process_snapshot *expected, uint32_t *flags_out) {
    pid_t tracer_pid = getpid();
    if (expected == NULL || expected->pid <= 1 || tracer_pid <= 1 ||
        geteuid() != 0 || expected->bsd.pbi_uid != 0 ||
        expected->bsd.pbi_ppid != 1 ||
        strcmp(expected->path, kCryptexdPath) != 0 ||
        memcmp(expected->unique.uuid, kExpectedCryptexdUUID,
               sizeof(kExpectedCryptexdUUID)) != 0) {
        return false;
    }

    struct process_snapshot first = {.pid = expected->pid};
    struct codex_proc_uniqidentifierinfo second_unique = {0};
    char second_path[CODEX_PATH_SIZE] = {0};
    uint32_t flags = 0;
    if (!copy_process_path(first.pid, first.path) ||
        strcmp(first.path, kCryptexdPath) != 0 ||
        !copy_bsd_info(first.pid, &first.bsd) ||
        first.bsd.pbi_uid != 0 ||
        (first.bsd.pbi_ppid != 1 &&
         first.bsd.pbi_ppid != (uint32_t)tracer_pid) ||
        !copy_unique_info(first.pid, &first.unique) ||
        memcmp(first.unique.uuid, kExpectedCryptexdUUID,
               sizeof(kExpectedCryptexdUUID)) != 0 ||
        !process_generation_equal(&first.unique, &expected->unique) ||
        csops(first.pid, CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) != 0 ||
        (flags & CODEX_CS_VALID) == 0 ||
        !copy_process_path(first.pid, second_path) ||
        strcmp(first.path, second_path) != 0 ||
        !copy_unique_info(first.pid, &second_unique) ||
        !process_generation_equal(&first.unique, &second_unique) ||
        first.pid != expected->pid ||
        strcmp(first.path, expected->path) != 0) {
        return false;
    }
    if (flags_out != NULL) {
        *flags_out = flags;
    }
    return true;
}

static bool wait_for_cryptexd_trace_stop(
    const struct process_snapshot *cryptexd, int *status_out) {
    uint64_t deadline = monotonic_msec() + CODEX_TRACE_TIMEOUT_MSEC;
    do {
        int status = 0;
        pid_t waited = waitpid(cryptexd->pid, &status,
                               WNOHANG | WUNTRACED);
        if (waited == cryptexd->pid) {
            if (status_out != NULL) {
                *status_out = status;
            }
            return WIFSTOPPED(status) &&
                   cryptexd_traced_snapshot_still_exact(cryptexd, NULL);
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    } while (monotonic_msec() < deadline);
    return false;
}

static int soften_cryptexd_main(const char *pid_text) {
    int32_t parsed_pid = -1;
    if (!parse_int32_exact(pid_text, &parsed_pid) || parsed_pid <= 1 ||
        geteuid() != 0 || getpid() <= 1) {
        return 86;
    }
    struct process_snapshot cryptexd = {0};
    uint32_t before_flags = 0;
    if (!read_cryptexd_snapshot((pid_t)parsed_pid, &cryptexd,
                                &before_flags)) {
        return 87;
    }
    if ((before_flags & CODEX_CS_DEBUGGED) != 0) {
        dprintf(STDOUT_FILENO,
                "cryptexd-soften pid=%d alreadyDebugged=1 "
                "flags=0x%08x path=%s\n",
                cryptexd.pid, before_flags, cryptexd.path);
        return 0;
    }

    errno = 0;
    int attach_result = ptrace(PT_ATTACHEXC, cryptexd.pid, NULL, 0);
    int attach_error = attach_result == 0 ? 0 : errno;
    int trace_status = 0;
    bool stopped = attach_result == 0 &&
                   wait_for_cryptexd_trace_stop(&cryptexd, &trace_status);
    uint32_t attached_flags = 0;
    bool attached_exact =
        stopped && cryptexd_traced_snapshot_still_exact(&cryptexd,
                                                        &attached_flags);
    errno = 0;
    int detach_result =
        attach_result == 0 ? ptrace(PT_DETACH, cryptexd.pid, NULL, 0) : -1;
    int detach_error = detach_result == 0 ? 0 : errno;
    int continue_result = -1;
    int continue_error = 0;
    if (detach_result == 0 &&
        cryptexd_snapshot_still_exact(&cryptexd, NULL)) {
        errno = 0;
        continue_result = kill(cryptexd.pid, SIGCONT);
        continue_error = continue_result == 0 ? 0 : errno;
    }
    usleep(20U * 1000U);
    uint32_t after_flags = 0;
    bool final_exact =
        cryptexd_snapshot_still_exact(&cryptexd, &after_flags);
    bool softened = attach_result == 0 && stopped && attached_exact &&
                    (attached_flags & CODEX_CS_DEBUGGED) != 0 &&
                    detach_result == 0 && continue_result == 0 &&
                    final_exact &&
                    (after_flags & CODEX_CS_DEBUGGED) != 0;
    dprintf(STDOUT_FILENO,
            "cryptexd-soften pid=%d attach=%d attachErrno=%d stopped=%d "
            "status=0x%x attachedFlags=0x%08x detach=%d detachErrno=%d "
            "continue=%d continueErrno=%d finalExact=%d "
            "afterFlags=0x%08x softened=%d path=%s\n",
            cryptexd.pid, attach_result, attach_error, stopped, trace_status,
            attached_flags, detach_result, detach_error, continue_result,
            continue_error, final_exact, after_flags, softened,
            cryptexd.path);
    return softened ? 0 : 88;
}

static bool disarm_proves_stock(struct process_snapshot *stock_out,
                                bool external_mode) {
    return watchdog_disarmed() && find_unique_stock(stock_out) &&
           (!external_mode || external_candidate_service_absent());
}

static bool signal_bound_controller(
    const struct process_snapshot *controller, int signal_number) {
    return controller_snapshot_still_exact(controller) &&
           kill(controller->pid, signal_number) == 0;
}

static int watchdog_main(const char *token, const char *controller_pid_text,
                         const char *controller_pid_version_text,
                         const char *controller_unique_id_text,
                         bool arm_only, bool external_mode) {
    gRole = "watchdog";
    int32_t parsed_pid = -1;
    int32_t parsed_pid_version = -1;
    uint64_t parsed_unique_id = 0;
    if (geteuid() != 0 || getpid() <= 1 || !validate_run_token(token) ||
        !parse_int32_exact(controller_pid_text, &parsed_pid) ||
        parsed_pid <= 1 ||
        !parse_int32_exact(controller_pid_version_text,
                           &parsed_pid_version) ||
        !parse_uint64_exact(controller_unique_id_text,
                            &parsed_unique_id) ||
        parsed_unique_id == 0) {
        return 90;
    }
    memcpy(gRunToken, token, sizeof(gRunToken));
    struct stat lock_status = {0};
    if (fstat(CODEX_LOCK_INHERITED_FD, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        flock(CODEX_LOCK_INHERITED_FD, LOCK_EX | LOCK_NB) != 0 ||
        !prepare_common_paths(false) || !ensure_state_directory() ||
        !open_journal() ||
        !open_secure_lock(kRecoveryLockPath, &gRecoveryDescriptor)) {
        return 91;
    }
    struct process_snapshot controller = {0};
    if (!read_controller_snapshot((pid_t)parsed_pid, &controller) ||
        controller.unique.pid_version != parsed_pid_version ||
        controller.unique.unique_id != parsed_unique_id ||
        try_recovery_lock() != RECOVERY_LOCK_BUSY) {
        return 91;
    }
    uint64_t watchdog_delay_msec =
        external_mode ? CODEX_EXTERNAL_WATCHDOG_DELAY_MSEC
                      : CODEX_WATCHDOG_DELAY_MSEC;
    if (!journal_event("event=watchdog-start controllerPid=%d "
                       "controllerPidVersion=%d controllerUniqueId=%llu "
                       "deadlineMs=%llu armOnly=%d external=%d",
                       controller.pid, controller.unique.pid_version,
                       (unsigned long long)controller.unique.unique_id,
                       (unsigned long long)watchdog_delay_msec, arm_only,
                       external_mode) ||
        !create_marker("ready")) {
        return 92;
    }

    bool recovery_owned = false;
    const char *takeover_reason = "controller-lease-released";
    uint64_t deadline = monotonic_msec() + watchdog_delay_msec;
    while (monotonic_msec() < deadline) {
        struct process_snapshot stock = {0};
        if (disarm_proves_stock(&stock, external_mode)) {
            (void)journal_event("event=watchdog-disarmed-before-deadline");
            return 0;
        }
        enum recovery_lock_result lock_result = try_recovery_lock();
        if (lock_result == RECOVERY_LOCK_ACQUIRED) {
            recovery_owned = true;
            break;
        }
        if (lock_result == RECOVERY_LOCK_ERROR) {
            return 93;
        }
        usleep(50U * 1000U);
    }
    if (!recovery_owned) {
        struct process_snapshot stock = {0};
        if (disarm_proves_stock(&stock, external_mode)) {
            (void)journal_event("event=watchdog-disarmed-at-deadline");
            return 0;
        }
        if (arm_only) {
            (void)journal_event("event=watchdog-arm-only-timeout");
            return 93;
        }
        if (!create_marker("takeover")) {
            (void)journal_event("event=watchdog-takeover-marker-failed");
            return 93;
        }
        (void)journal_event("event=watchdog-deadline action=request-handoff");
        uint64_t takeover_deadline =
            monotonic_msec() + CODEX_WATCHDOG_GRACE_MSEC;
        uint64_t next_signal = 0;
        do {
            if (disarm_proves_stock(&stock, external_mode)) {
                (void)journal_event(
                    "event=watchdog-disarmed-during-handoff");
                return 0;
            }
            enum recovery_lock_result lock_result = try_recovery_lock();
            if (lock_result == RECOVERY_LOCK_ACQUIRED) {
                recovery_owned = true;
                takeover_reason = "cooperative-handoff";
                break;
            }
            if (lock_result == RECOVERY_LOCK_ERROR) {
                return 93;
            }
            uint64_t now = monotonic_msec();
            if (now >= next_signal &&
                signal_bound_controller(&controller, SIGTERM)) {
                next_signal = now + CODEX_WATCHDOG_SIGNAL_INTERVAL_MSEC;
            }
            usleep(50U * 1000U);
        } while (monotonic_msec() < takeover_deadline);
    }
    if (!recovery_owned) {
        (void)signal_bound_controller(&controller, SIGTERM);
        uint64_t final_term_deadline =
            monotonic_msec() + CODEX_WATCHDOG_SIGNAL_INTERVAL_MSEC;
        do {
            enum recovery_lock_result lock_result = try_recovery_lock();
            if (lock_result == RECOVERY_LOCK_ACQUIRED) {
                recovery_owned = true;
                takeover_reason = "final-term-handoff";
                break;
            }
            if (lock_result == RECOVERY_LOCK_ERROR) {
                return 93;
            }
            usleep(20U * 1000U);
        } while (monotonic_msec() < final_term_deadline);
    }
    if (!recovery_owned) {
        if (controller_snapshot_still_exact(&controller) &&
            !signal_bound_controller(&controller, SIGKILL)) {
            return 93;
        }
        uint64_t force_deadline =
            monotonic_msec() + CODEX_WATCHDOG_FORCE_WAIT_MSEC;
        do {
            enum recovery_lock_result lock_result = try_recovery_lock();
            if (lock_result == RECOVERY_LOCK_ACQUIRED) {
                recovery_owned = true;
                takeover_reason = "forced-handoff";
                break;
            }
            if (lock_result == RECOVERY_LOCK_ERROR) {
                return 93;
            }
            usleep(20U * 1000U);
        } while (monotonic_msec() < force_deadline);
    }
    if (!recovery_owned) {
        return 93;
    }

    gHonorTakeover = false;
    (void)journal_event("event=watchdog-recovery-lease-acquired reason=%s",
                        takeover_reason);
    if (!neutralize_recorded_helper(controller.pid)) {
        (void)journal_event("event=watchdog-helper-neutralization-failed");
        return 93;
    }
    struct process_snapshot stock = {0};
    bool used_fallback = false;
    bool restored = find_unique_stock(&stock) &&
                    (!external_mode ||
                     external_candidate_service_absent());
    if (!restored && !arm_only) {
        (void)journal_event(
            "event=watchdog-recovery action=restore-stock external=%d",
            external_mode);
        restored = external_mode
                       ? restore_external_stock(false, &stock,
                                                &used_fallback)
                       : restore_stock(false, &stock, &used_fallback);
    }
    if (restored) {
        (void)create_marker("restored");
    }
    (void)journal_event("event=watchdog-finished restored=%d fallback=%d "
                        "stockPid=%d armOnly=%d external=%d",
                        restored, used_fallback, restored ? stock.pid : -1,
                        arm_only, external_mode);
    return restored ? 0 : 93;
}

static bool parallel_disarm_proves_original_stock(
    const struct process_snapshot *original_stock) {
    return watchdog_disarmed() &&
           original_stock_still_exact_with_candidate_count(original_stock, 0) &&
           external_candidate_service_absent() &&
           stock_service_and_snapshot_exact(original_stock, 0,
                                            "watchdog-disarm");
}

static int parallel_bind_watchdog_main(
    const char *token, const char *controller_pid_text,
    const char *controller_pid_version_text,
    const char *controller_unique_id_text, const char *stock_pid_text,
    const char *stock_pid_version_text, const char *stock_unique_id_text,
    const char *stock_cs_flags_text) {
    gRole = "parallel-bind-watchdog";
    int32_t parsed_controller_pid = -1;
    int32_t parsed_controller_pid_version = -1;
    uint64_t parsed_controller_unique_id = 0;
    int32_t parsed_stock_pid = -1;
    int32_t parsed_stock_pid_version = -1;
    uint64_t parsed_stock_unique_id = 0;
    uint64_t parsed_stock_cs_flags = 0;
    if (geteuid() != 0 || getpid() <= 1 || !validate_run_token(token) ||
        !parse_int32_exact(controller_pid_text, &parsed_controller_pid) ||
        parsed_controller_pid <= 1 ||
        !parse_int32_exact(controller_pid_version_text,
                           &parsed_controller_pid_version) ||
        !parse_uint64_exact(controller_unique_id_text,
                            &parsed_controller_unique_id) ||
        parsed_controller_unique_id == 0 ||
        !parse_int32_exact(stock_pid_text, &parsed_stock_pid) ||
        parsed_stock_pid <= 1 ||
        !parse_int32_exact(stock_pid_version_text,
                           &parsed_stock_pid_version) ||
        !parse_uint64_exact(stock_unique_id_text,
                            &parsed_stock_unique_id) ||
        parsed_stock_unique_id == 0 ||
        !parse_uint64_exact(stock_cs_flags_text,
                            &parsed_stock_cs_flags) ||
        parsed_stock_cs_flags > UINT32_MAX) {
        return 120;
    }
    memcpy(gRunToken, token, sizeof(gRunToken));

    struct stat lock_status = {0};
    if (fstat(CODEX_LOCK_INHERITED_FD, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        lock_status.st_nlink != 1 || (lock_status.st_mode & 0077) != 0 ||
        flock(CODEX_LOCK_INHERITED_FD, LOCK_EX | LOCK_NB) != 0 ||
        !prepare_common_paths(true) || !ensure_state_directory() ||
        !open_journal() ||
        !open_secure_lock(kRecoveryLockPath, &gRecoveryDescriptor)) {
        return 121;
    }

    struct process_snapshot controller = {0};
    struct process_snapshot original_stock = {0};
    bool controller_exact =
        read_controller_snapshot((pid_t)parsed_controller_pid, &controller) &&
        controller.unique.pid_version == parsed_controller_pid_version &&
        controller.unique.unique_id == parsed_controller_unique_id;
    bool stock_exact =
        read_stock_snapshot((pid_t)parsed_stock_pid, &original_stock) &&
        original_stock.unique.pid_version == parsed_stock_pid_version &&
        original_stock.unique.unique_id == parsed_stock_unique_id &&
        original_stock.cs_flags == (uint32_t)parsed_stock_cs_flags &&
        original_stock_still_exact_with_candidate_count(&original_stock, 0);
    if (!controller_exact || !stock_exact ||
        try_recovery_lock() != RECOVERY_LOCK_BUSY ||
        !stock_service_and_snapshot_exact(&original_stock, 0,
                                          "watchdog-arm") ||
        !controller_snapshot_still_exact(&controller) ||
        try_recovery_lock() != RECOVERY_LOCK_BUSY) {
        return 121;
    }
    if (!journal_event(
            "event=parallel-watchdog-start controllerPid=%d "
            "controllerPidVersion=%d controllerUniqueId=%llu stockPid=%d "
            "stockPidVersion=%d stockUniqueId=%llu stockCsFlags=0x%08x "
            "deadlineMs=%u "
            "candidateOnlyRecovery=1 stockMutationAllowed=0",
            controller.pid, controller.unique.pid_version,
            (unsigned long long)controller.unique.unique_id,
            original_stock.pid, original_stock.unique.pid_version,
            (unsigned long long)original_stock.unique.unique_id,
            original_stock.cs_flags,
            CODEX_EXTERNAL_WATCHDOG_DELAY_MSEC) ||
        !create_marker("ready")) {
        return 122;
    }

    bool recovery_owned = false;
    bool early_handoff = false;
    const char *takeover_reason = "controller-lease-released";
    uint64_t deadline =
        monotonic_msec() + CODEX_EXTERNAL_WATCHDOG_DELAY_MSEC;
    while (monotonic_msec() < deadline) {
        if (parallel_disarm_proves_original_stock(&original_stock)) {
            (void)journal_event(
                "event=parallel-watchdog-disarmed-before-deadline "
                "stockMutated=0");
            return 0;
        }
        if (!original_stock_still_exact_with_candidate_count(
                &original_stock, -1)) {
            takeover_reason = "stock-invariant-breached";
            early_handoff = true;
            break;
        }
        enum recovery_lock_result lock_result = try_recovery_lock();
        if (lock_result == RECOVERY_LOCK_ACQUIRED) {
            recovery_owned = true;
            break;
        }
        if (lock_result == RECOVERY_LOCK_ERROR) {
            return 123;
        }
        usleep(50U * 1000U);
    }

    if (!recovery_owned) {
        if (parallel_disarm_proves_original_stock(&original_stock)) {
            (void)journal_event(
                "event=parallel-watchdog-disarmed-before-handoff "
                "stockMutated=0");
            return 0;
        }
        if (!early_handoff) {
            takeover_reason = "deadline";
        }
        if (!create_marker("takeover")) {
            (void)journal_event(
                "event=parallel-watchdog-takeover-marker-failed "
                "stockMutated=0");
            return 123;
        }
        (void)journal_event(
            "event=parallel-watchdog-handoff-requested reason=%s "
            "stockMutationAllowed=0",
            takeover_reason);
        uint64_t takeover_deadline =
            monotonic_msec() + CODEX_WATCHDOG_GRACE_MSEC;
        uint64_t next_signal = 0;
        do {
            enum recovery_lock_result lock_result = try_recovery_lock();
            if (lock_result == RECOVERY_LOCK_ACQUIRED) {
                recovery_owned = true;
                takeover_reason = early_handoff
                                      ? "invariant-handoff"
                                      : "cooperative-handoff";
                break;
            }
            if (lock_result == RECOVERY_LOCK_ERROR) {
                return 123;
            }
            uint64_t now = monotonic_msec();
            if (now >= next_signal &&
                signal_bound_controller(&controller, SIGTERM)) {
                next_signal = now + CODEX_WATCHDOG_SIGNAL_INTERVAL_MSEC;
            }
            usleep(50U * 1000U);
        } while (monotonic_msec() < takeover_deadline);
    }
    if (!recovery_owned) {
        (void)signal_bound_controller(&controller, SIGTERM);
        uint64_t final_term_deadline =
            monotonic_msec() + CODEX_WATCHDOG_SIGNAL_INTERVAL_MSEC;
        do {
            enum recovery_lock_result lock_result = try_recovery_lock();
            if (lock_result == RECOVERY_LOCK_ACQUIRED) {
                recovery_owned = true;
                takeover_reason = "final-term-handoff";
                break;
            }
            if (lock_result == RECOVERY_LOCK_ERROR) {
                return 123;
            }
            usleep(20U * 1000U);
        } while (monotonic_msec() < final_term_deadline);
    }
    if (!recovery_owned) {
        if (controller_snapshot_still_exact(&controller) &&
            !signal_bound_controller(&controller, SIGKILL)) {
            return 123;
        }
        uint64_t force_deadline =
            monotonic_msec() + CODEX_WATCHDOG_FORCE_WAIT_MSEC;
        do {
            enum recovery_lock_result lock_result = try_recovery_lock();
            if (lock_result == RECOVERY_LOCK_ACQUIRED) {
                recovery_owned = true;
                takeover_reason = "forced-handoff";
                break;
            }
            if (lock_result == RECOVERY_LOCK_ERROR) {
                return 123;
            }
            usleep(20U * 1000U);
        } while (monotonic_msec() < force_deadline);
    }
    if (!recovery_owned) {
        return 123;
    }

    gHonorTakeover = false;
    (void)journal_event(
        "event=parallel-watchdog-recovery-lease-acquired reason=%s "
        "candidateOnlyRecovery=1 stockMutationAllowed=0",
        takeover_reason);
    bool helper_neutralized = false;
    uint64_t helper_deadline =
        monotonic_msec() + CODEX_COMMAND_TIMEOUT_MSEC +
        CODEX_HELPER_KILL_MSEC + 500U;
    do {
        helper_neutralized = neutralize_recorded_helper(controller.pid);
        if (helper_neutralized) {
            break;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < helper_deadline);
    if (!helper_neutralized) {
        (void)journal_event(
            "event=parallel-watchdog-helper-neutralization-failed "
            "action=candidate-cleanup-attempt stockMutated=0");
    }
    bool cleaned = remove_external_candidate_preserving_stock(
        &original_stock, "watchdog-recovery");
    bool candidate_cleaned_marker =
        cleaned && create_marker("candidate-cleaned");
    (void)journal_event(
        "event=parallel-watchdog-finished candidateAbsent=%d "
        "originalStockExact=%d candidateCleanedMarker=%d cleaned=%d "
        "stockPid=%d stockMutationAllowed=0 stockMutated=0",
        external_candidate_service_absent(),
        original_stock_still_exact_with_candidate_count(&original_stock, 0),
        candidate_cleaned_marker, cleaned, original_stock.pid);
    return helper_neutralized && cleaned && candidate_cleaned_marker ? 0
                                                                    : 123;
}

static bool owned_child_live(pid_t child) {
    if (child <= 1) {
        return false;
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    return waited == 0;
}

static bool reap_owned_child_until(pid_t child, uint64_t timeout_msec) {
    if (child <= 1) {
        return false;
    }
    uint64_t deadline = monotonic_msec() + timeout_msec;
    do {
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            return true;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < deadline);
    return false;
}

static int inject_existing_candidate_main(const char *pid_text) {
    gRole = "external-injector";
    int32_t parsed_pid = -1;
    if (!parse_int32_exact(pid_text, &parsed_pid) || parsed_pid <= 1 ||
        geteuid() != 0) {
        return 80;
    }

    uuid_t run_uuid;
    uuid_generate_random(run_uuid);
    uuid_unparse_lower(run_uuid, gRunToken);

    gLockDescriptor = open(kLockPath,
                           O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (gLockDescriptor < 0) {
        return 81;
    }
    struct stat lock_status = {0};
    if (fstat(gLockDescriptor, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        lock_status.st_nlink != 1 || (lock_status.st_mode & 0077) != 0 ||
        fchmod(gLockDescriptor, 0600) != 0 ||
        flock(gLockDescriptor, LOCK_EX | LOCK_NB) != 0 ||
        !prepare_common_paths(true) || !ensure_state_directory() ||
        !open_journal() || !remove_stale_canary_marker()) {
        return 81;
    }

    bool candidate_file_valid =
        file_sha256_exact(kCandidatePath, kExpectedCandidateSHA256, true,
                          CODEX_EXPECTED_CANDIDATE_SIZE,
                          &gCandidateDescriptor, &gCandidateStatus) &&
        descriptor_has_expected_uuid(gCandidateDescriptor) &&
        file_sha256_exact(kCandidateInfoPath, kExpectedInfoSHA256, false, 0,
                          &gCandidateInfoDescriptor,
                          &gCandidateInfoStatus) &&
        candidate_path_still_bound();
    bool launchctl_valid = file_sha256_exact(
        kLaunchctlPath, kExpectedLaunchctlSHA256, true, 0, NULL, NULL);
    bool loader_valid = file_sha256_exact(
        kLoaderCandidatePath, kExpectedLoaderSHA256, true, 0, NULL, NULL);
    bool hook_valid = file_sha256_exact(
        kDyldAdmissionHookPath, kExpectedHookSHA256, false, 0, NULL, NULL);
    bool canary_valid = file_sha256_exact(
        kFreshCanaryPath, kExpectedCanarySHA256, false, 0, NULL, NULL);
    if (!candidate_file_valid || !launchctl_valid || !loader_valid ||
        !hook_valid || !canary_valid) {
        (void)journal_event(
            "event=external-injector-artifact-rejected candidate=%d "
            "launchctl=%d loader=%d hook=%d canary=%d mutated=0",
            candidate_file_valid, launchctl_valid, loader_valid, hook_valid,
            canary_valid);
        return 82;
    }

    struct process_snapshot candidate = {0};
    uint32_t candidate_flags = 0;
    if (!find_returned_candidate((pid_t)parsed_pid, &candidate,
                                 &candidate_flags)) {
        (void)journal_event(
            "event=external-injector-candidate-rejected requestedPid=%d",
            parsed_pid);
        return 83;
    }
    (void)journal_event(
        "event=external-injector-candidate-bound candidatePid=%d uid=%u "
        "ppid=%u pidVersion=%d uniqueId=%llu flags=0x%08x path=%s",
        candidate.pid, candidate.bsd.pbi_uid, candidate.bsd.pbi_ppid,
        candidate.unique.pid_version,
        (unsigned long long)candidate.unique.unique_id, candidate_flags,
        candidate.path);

    if (!attach_detach_resume_candidate(&candidate, &candidate_flags, NULL)) {
        (void)journal_event(
            "event=external-injector-attach-failed candidatePid=%d",
            candidate.pid);
        return 84;
    }

    int hook_result = 85;
    for (unsigned int attempt = 0; attempt < 4U; ++attempt) {
        if (!candidate_debug_policy_still_exact(&candidate,
                                                &candidate_flags)) {
            break;
        }
        hook_result = run_candidate_loader_injection(
            &candidate, kDyldAdmissionHookPath, NULL);
        if (hook_result == 0) {
            break;
        }
        usleep(150U * 1000U);
    }
    bool hook_installed =
        hook_result == 0 &&
        candidate_debug_policy_still_exact(&candidate, &candidate_flags);
    int canary_result =
        hook_installed
            ? run_candidate_loader_injection(&candidate, kFreshCanaryPath,
                                             NULL)
            : 84;
    bool canary_loaded =
        canary_result == 0 &&
        candidate_debug_policy_still_exact(&candidate, &candidate_flags);
    bool marker_matches = false;
    uint64_t marker_deadline = monotonic_msec() + 1000U;
    do {
        marker_matches = fresh_canary_marker_matches(candidate.pid);
        if (marker_matches || !canary_loaded) {
            break;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < marker_deadline);

    bool live_injection_proved =
        hook_installed && canary_loaded && marker_matches;
    bool candidate_observed =
        live_injection_proved && observe_candidate(&candidate, NULL);
    (void)journal_event(
        "event=external-live-injection-proof candidatePid=%d hookResult=%d "
        "hookInstalled=%d canaryResult=%d canaryLoaded=%d "
        "markerMatches=%d observed=%d flags=0x%08x",
        candidate.pid, hook_result, hook_installed, canary_result,
        canary_loaded, marker_matches, candidate_observed, candidate_flags);
    return live_injection_proved && candidate_observed ? 0 : 85;
}

static int external_service_removal_audit_main(
    const char *invocation_path) {
    gRole = "external-removal-audit";
    uuid_t run_uuid;
    uuid_generate_random(run_uuid);
    uuid_unparse_lower(run_uuid, gRunToken);

    gLockDescriptor = open(kLockPath,
                           O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (gLockDescriptor < 0) {
        return 100;
    }
    if (gLockDescriptor == CODEX_LOCK_INHERITED_FD) {
        int replacement = fcntl(gLockDescriptor, F_DUPFD_CLOEXEC,
                                CODEX_LOCK_INHERITED_FD + 1);
        if (replacement < 0) {
            return 100;
        }
        close(gLockDescriptor);
        gLockDescriptor = replacement;
    }
    struct stat lock_status = {0};
    if (fstat(gLockDescriptor, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        lock_status.st_nlink != 1 || (lock_status.st_mode & 0077) != 0 ||
        fchmod(gLockDescriptor, 0600) != 0 ||
        flock(gLockDescriptor, LOCK_EX | LOCK_NB) != 0) {
        return 100;
    }

    struct process_snapshot original_stock = {0};
    if (!controller_preflight(invocation_path, &original_stock, false,
                              true)) {
        if (gJournalDescriptor >= 0) {
            (void)journal_event(
                "event=external-removal-audit-base-preflight-failed "
                "stockMutated=0");
        }
        return 101;
    }

    struct command_result candidate_print =
        print_external_candidate_service();
    bool process_absent = candidate_process_absent();
    bool print_exact = command_succeeded(&candidate_print) &&
                       !candidate_print.standard_output_truncated &&
                       !candidate_print.standard_error_truncated &&
                       candidate_print.standard_error[0] == '\0' &&
                       external_candidate_print_is_exact_dormant(
                           candidate_print.standard_output);
    bool stock_unchanged = original_stock_still_unique(&original_stock);
    bool preflight = print_exact && process_absent && stock_unchanged &&
                     external_launchctl_file_valid();
    char print_output[512];
    char print_error[512];
    compact_command_output(candidate_print.standard_output, print_output,
                           sizeof(print_output));
    compact_command_output(candidate_print.standard_error, print_error,
                           sizeof(print_error));
    (void)journal_event(
        "event=external-removal-audit-preflight spawn=%d timeout=%d exit=%d "
        "printExact=%d processAbsent=%d stockUnchanged=%d ready=%d "
        "target=%s stdout=\"%s\" stderr=\"%s\" stockMutated=0",
        candidate_print.spawn_error, candidate_print.timed_out,
        candidate_print.exit_code, print_exact, process_absent,
        stock_unchanged, preflight, kExternalCandidateTarget, print_output,
        print_error);
    if (!preflight) {
        return 102;
    }

    struct command_result bootout =
        bootout_external_candidate_service();
    stock_unchanged = original_stock_still_unique(&original_stock);
    (void)journal_event(
        "event=external-removal-audit-bootout spawn=%d timeout=%d exit=%d "
        "stockUnchanged=%d stockMutated=0",
        bootout.spawn_error, bootout.timed_out, bootout.exit_code,
        stock_unchanged);
    if (!command_succeeded(&bootout) || !stock_unchanged) {
        return 103;
    }

    bool service_absent = false;
    for (unsigned int attempt = 0; attempt < 2U; ++attempt) {
        service_absent = external_candidate_service_absent();
        stock_unchanged = original_stock_still_unique(&original_stock);
        if (service_absent || !stock_unchanged) {
            break;
        }
        usleep(50U * 1000U);
    }
    bool final_exact = service_absent && stock_unchanged &&
                       candidate_process_absent() &&
                       original_stock_still_unique(&original_stock);
    bool final_logged = journal_event(
        "event=external-removal-audit-final serviceAbsent=%d "
        "stockUnchanged=%d stockPid=%d stockPidVersion=%d "
        "stockUniqueId=%llu stockMutated=0 result=%d",
        service_absent, stock_unchanged,
        final_exact ? original_stock.pid : -1,
        final_exact ? original_stock.unique.pid_version : -1,
        final_exact
            ? (unsigned long long)original_stock.unique.unique_id
            : 0ULL,
        final_exact);
    int result = final_exact && final_logged ? 0 : 104;
    dprintf(STDOUT_FILENO,
            "external-service-removal-audit status=%d serviceAbsent=%d "
            "stockUnchanged=%d stockPid=%d stockMutated=0\n",
            result, service_absent, stock_unchanged,
            final_exact ? original_stock.pid : -1);
    return result;
}

static int external_parallel_candidate_main(const char *invocation_path,
                                            bool prove_live_injection) {
    gRole = prove_live_injection ? "external-parallel-live-proof"
                                 : "external-parallel-bind-audit";
    uuid_t run_uuid;
    uuid_generate_random(run_uuid);
    uuid_unparse_lower(run_uuid, gRunToken);

    gLockDescriptor = open(kLockPath,
                           O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (gLockDescriptor < 0) {
        return 110;
    }
    if (gLockDescriptor == CODEX_LOCK_INHERITED_FD) {
        int replacement = fcntl(gLockDescriptor, F_DUPFD_CLOEXEC,
                                CODEX_LOCK_INHERITED_FD + 1);
        if (replacement < 0) {
            return 110;
        }
        close(gLockDescriptor);
        gLockDescriptor = replacement;
    }
    struct stat lock_status = {0};
    if (fstat(gLockDescriptor, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        lock_status.st_nlink != 1 || (lock_status.st_mode & 0077) != 0 ||
        fchmod(gLockDescriptor, 0600) != 0 ||
        flock(gLockDescriptor, LOCK_EX | LOCK_NB) != 0 ||
        !open_secure_lock(kRecoveryLockPath, &gRecoveryDescriptor) ||
        try_recovery_lock() != RECOVERY_LOCK_ACQUIRED) {
        return 110;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGHUP, &action, NULL);

    struct process_snapshot original_stock = {0};
    if (!controller_preflight(invocation_path, &original_stock,
                              prove_live_injection,
                              true)) {
        if (gJournalDescriptor >= 0) {
            (void)journal_event(
                "event=parallel-base-preflight-failed candidateMutated=0 "
                "stockMutated=0");
        }
        return 111;
    }

    struct command_result candidate_print =
        print_external_candidate_service();
    bool candidate_process_is_absent = candidate_process_absent();
    bool candidate_print_exact =
        command_succeeded(&candidate_print) &&
        !candidate_print.standard_output_truncated &&
        !candidate_print.standard_error_truncated &&
        candidate_print.standard_error[0] == '\0' &&
        external_candidate_print_is_exact_dormant(
            candidate_print.standard_output);
    bool stock_preflight_exact = stock_service_and_snapshot_exact(
        &original_stock, 0, "controller-preflight");
    bool candidate_ready = candidate_print_exact &&
                           candidate_process_is_absent &&
                           external_launchctl_file_valid() &&
                           stock_preflight_exact;
    char candidate_print_output[512];
    char candidate_print_error[512];
    compact_command_output(candidate_print.standard_output,
                           candidate_print_output,
                           sizeof(candidate_print_output));
    compact_command_output(candidate_print.standard_error,
                           candidate_print_error,
                           sizeof(candidate_print_error));
    (void)journal_event(
        "event=parallel-candidate-preflight spawn=%d timeout=%d exit=%d "
        "stdoutTruncated=%d stderrTruncated=%d printExact=%d processAbsent=%d "
        "stockServiceExact=%d ready=%d target=%s stdout=\"%s\" "
        "stderr=\"%s\" candidateMutated=0 stockMutated=0",
        candidate_print.spawn_error, candidate_print.timed_out,
        candidate_print.exit_code,
        candidate_print.standard_output_truncated,
        candidate_print.standard_error_truncated,
        candidate_print_exact,
        candidate_process_is_absent, stock_preflight_exact, candidate_ready,
        kExternalCandidateTarget, candidate_print_output,
        candidate_print_error);
    if (!candidate_ready) {
        return 112;
    }

    struct process_snapshot controller = {0};
    if (!read_controller_snapshot(getpid(), &controller)) {
        (void)journal_event(
            "event=parallel-controller-bind-failed candidateMutated=0 "
            "stockMutated=0");
        return 113;
    }
    pid_t watchdog_pid = -1;
    if (!spawn_parallel_bind_watchdog(&controller, &original_stock,
                                      &watchdog_pid)) {
        bool watchdog_terminated = true;
        if (watchdog_pid > 1 && owned_child_live(watchdog_pid)) {
            watchdog_terminated =
                terminate_and_reap_owned_child(watchdog_pid, NULL);
        }
        (void)journal_event(
            "event=parallel-watchdog-arm-failed watchdogWorkerPid=%d "
            "watchdogTerminated=%d candidateMutated=0 stockMutated=0",
            watchdog_pid, watchdog_terminated);
        return 114;
    }

    /* Close the arm/preflight race. No candidate operation is allowed until
       both the original stock generation and dormant submitted job are
       re-proven after the independent watchdog publishes ready. */
    candidate_print = print_external_candidate_service();
    candidate_print_exact =
        command_succeeded(&candidate_print) &&
        !candidate_print.standard_output_truncated &&
        !candidate_print.standard_error_truncated &&
        candidate_print.standard_error[0] == '\0' &&
        external_candidate_print_is_exact_dormant(
            candidate_print.standard_output);
    candidate_process_is_absent = candidate_process_absent();
    bool post_arm_exact =
        candidate_print_exact && candidate_process_is_absent &&
        stock_service_and_snapshot_exact(&original_stock, 0,
                                         "controller-post-arm");
    (void)journal_event(
        "event=parallel-post-arm-preflight printExact=%d processAbsent=%d "
        "stockExact=%d candidateMutated=0 stockMutated=0",
        candidate_print_exact, candidate_process_is_absent, post_arm_exact);
    if (!post_arm_exact || gStopRequested) {
        (void)journal_event(
            "event=parallel-abort-before-mutation action=watchdog-handoff "
            "watchdogWorkerPid=%d candidateMutated=0 stockMutated=0",
            watchdog_pid);
        return 117;
    }

    bool candidate_mutated = true;
    bool candidate_identity_bound = false;
    bool stock_exact_while_candidate_live = false;
    bool live_injection_proved = false;
    bool candidate_observed = false;
    bool candidate_softened = false;
    bool hook_installed = false;
    bool canary_loaded = false;
    bool marker_matches = false;
    int hook_result = 85;
    int canary_result = 84;
    struct process_snapshot candidate = {0};
    uint32_t candidate_flags = 0;
    pid_t returned_pid = -1;
    (void)journal_event(
        "event=parallel-candidate-kickstart-begin startSuspended=1 "
        "printPid=1 candidateMutated=1 stockMutationAllowed=0");
    struct command_result candidate_kickstart =
        kickstart_external_candidate_service();
    bool kickstart_output_exact =
        command_succeeded(&candidate_kickstart) &&
        !candidate_kickstart.standard_output_truncated &&
        !candidate_kickstart.standard_error_truncated &&
        candidate_kickstart.standard_error[0] == '\0';
    bool printed_pid =
        kickstart_output_exact &&
        parse_printed_pid(candidate_kickstart.standard_output,
                          &returned_pid);
    bool zero_pid_sentinel =
        kickstart_output_exact &&
        parse_zero_pid_sentinel(candidate_kickstart.standard_output);
    bool stock_exact_after_kickstart =
        original_stock_still_exact_with_candidate_count(&original_stock, -1);
    char kickstart_output[512];
    char kickstart_error[512];
    compact_command_output(candidate_kickstart.standard_output,
                           kickstart_output, sizeof(kickstart_output));
    compact_command_output(candidate_kickstart.standard_error,
                           kickstart_error, sizeof(kickstart_error));
    (void)journal_event(
        "event=parallel-candidate-kickstart spawn=%d timeout=%d exit=%d "
        "stdoutTruncated=%d stderrTruncated=%d printedPidValid=%d "
        "zeroPidSentinel=%d returnedPid=%d "
        "startSuspended=1 stockExact=%d stdout=\"%s\" stderr=\"%s\" "
        "candidateMutated=1 stockMutated=0",
        candidate_kickstart.spawn_error, candidate_kickstart.timed_out,
        candidate_kickstart.exit_code,
        candidate_kickstart.standard_output_truncated,
        candidate_kickstart.standard_error_truncated, printed_pid,
        zero_pid_sentinel, returned_pid, stock_exact_after_kickstart,
        kickstart_output,
        kickstart_error);
    if (stock_exact_after_kickstart && !gStopRequested) {
        if (printed_pid) {
            candidate_identity_bound = wait_for_parallel_returned_candidate(
                returned_pid, &original_stock, &candidate,
                &candidate_flags);
        } else if (zero_pid_sentinel) {
            candidate_identity_bound = wait_for_parallel_unique_candidate(
                &original_stock, &returned_pid, &candidate,
                &candidate_flags);
        }
    }
    if (candidate_identity_bound) {
        char candidate_uuid[37];
        uuid_unparse_lower(candidate.unique.uuid, candidate_uuid);
        stock_exact_while_candidate_live =
            stock_service_and_snapshot_exact(&original_stock, 1,
                                             "candidate-live") &&
            candidate_snapshot_still_exact_and_stopped(
                &candidate, &candidate_flags) &&
            original_stock_still_exact_with_candidate_count(
                &original_stock, 1);
        (void)journal_event(
            "event=parallel-candidate-bound candidatePid=%d path=%s uid=%u "
            "ppid=%u pidVersion=%d uniqueId=%llu uuid=%s "
            "cdhash=9b298e846ab91aaa1fba303f2c892d828e9e921c "
            "flags=0x%08x processStatus=%u stopped=%d stockPid=%d "
            "stockExact=%d suspendedRequested=1 "
            "stockMutated=0",
            candidate.pid, candidate.path, candidate.bsd.pbi_uid,
            candidate.bsd.pbi_ppid, candidate.unique.pid_version,
            (unsigned long long)candidate.unique.unique_id, candidate_uuid,
            candidate_flags, candidate.bsd.pbi_status,
            candidate.bsd.pbi_status == CODEX_PROC_STATUS_STOPPED,
            original_stock.pid,
            stock_exact_while_candidate_live);
    }

    if (prove_live_injection && candidate_identity_bound &&
        stock_exact_while_candidate_live && !gStopRequested) {
        candidate_softened = attach_detach_resume_candidate(
            &candidate, &candidate_flags, &original_stock);
        bool stock_exact_after_soften =
            candidate_softened &&
            stock_service_and_snapshot_exact(&original_stock, 1,
                                             "candidate-softened") &&
            candidate_debug_policy_still_exact_for_mode(
                &candidate, &original_stock, &candidate_flags);
        if (stock_exact_after_soften) {
            for (unsigned int attempt = 0; attempt < 2U; ++attempt) {
                if (!candidate_debug_policy_still_exact_for_mode(
                        &candidate, &original_stock, &candidate_flags)) {
                    break;
                }
                hook_result = run_candidate_loader_injection(
                    &candidate, kDyldAdmissionHookPath, &original_stock);
                if (hook_result == 0) {
                    break;
                }
                usleep(150U * 1000U);
            }
            hook_installed =
                hook_result == 0 &&
                candidate_debug_policy_still_exact_for_mode(
                    &candidate, &original_stock, &candidate_flags);
            canary_result =
                hook_installed
                    ? run_candidate_loader_injection(
                          &candidate, kFreshCanaryPath, &original_stock)
                    : 84;
            canary_loaded =
                canary_result == 0 &&
                candidate_debug_policy_still_exact_for_mode(
                    &candidate, &original_stock, &candidate_flags);
            uint64_t marker_deadline = monotonic_msec() + 1000U;
            do {
                if (!candidate_debug_policy_still_exact_for_mode(
                        &candidate, &original_stock, &candidate_flags)) {
                    canary_loaded = false;
                    break;
                }
                marker_matches = fresh_canary_marker_matches(candidate.pid);
                if (marker_matches || !canary_loaded) {
                    break;
                }
                usleep(20U * 1000U);
            } while (monotonic_msec() < marker_deadline);
            live_injection_proved =
                hook_installed && canary_loaded && marker_matches &&
                candidate_debug_policy_still_exact_for_mode(
                    &candidate, &original_stock, &candidate_flags) &&
                original_stock_still_exact_with_candidate_count(
                    &original_stock, 1);
            candidate_observed =
                live_injection_proved &&
                parallel_candidate_snapshot_still_unique(
                    &candidate, &original_stock, &candidate_flags);
        }
        bool stock_exact_after_injection =
            stock_service_and_snapshot_exact(&original_stock, 1,
                                             "candidate-after-injection");
        stock_exact_while_candidate_live =
            stock_exact_while_candidate_live && stock_exact_after_injection;
        (void)journal_event(
            "event=parallel-live-injection-proof candidatePid=%d "
            "softened=%d hookResult=%d hookInstalled=%d canaryResult=%d "
            "canaryLoaded=%d markerMatches=%d liveInjectionProved=%d "
            "observed=%d stockExact=%d stockPid=%d flags=0x%08x "
            "stockMutationAllowed=0 stockMutated=0",
            candidate.pid, candidate_softened, hook_result, hook_installed,
            canary_result, canary_loaded, marker_matches,
            live_injection_proved, candidate_observed,
            stock_exact_after_injection, original_stock.pid,
            candidate_flags);
    }

    gStopRequested = 0;
    if (takeover_requested() && owned_child_live(watchdog_pid)) {
        (void)journal_event(
            "event=parallel-cleanup-handed-to-watchdog watchdogWorkerPid=%d "
            "candidateMutated=%d stockMutationAllowed=0",
            watchdog_pid, candidate_mutated);
        return 117;
    }
    if (takeover_requested()) {
        gHonorTakeover = false;
        (void)journal_event(
            "event=parallel-takeover-marker-without-live-watchdog "
            "action=candidate-only-cleanup stockMutationAllowed=0");
    }

    bool cleaned = remove_external_candidate_preserving_stock(
        &original_stock, "controller-final");
    if (!cleaned && owned_child_live(watchdog_pid)) {
        (void)journal_event(
            "event=parallel-controller-cleanup-failed "
            "watchdogWorkerPid=%d action=handoff stockMutationAllowed=0",
            watchdog_pid);
        return 117;
    }
    if (!cleaned && takeover_requested()) {
        gHonorTakeover = false;
        gStopRequested = 0;
        (void)journal_event(
            "event=parallel-controller-retry-after-watchdog-exit "
            "action=candidate-only-cleanup stockMutationAllowed=0");
        cleaned = remove_external_candidate_preserving_stock(
            &original_stock, "controller-watchdog-exit-retry");
    }
    if (!cleaned) {
        (void)journal_event(
            "event=parallel-controller-cleanup-failed watchdogLive=0 "
            "stockMutationAllowed=0");
        return 118;
    }

    bool disarmed = create_marker("disarm");
    bool watchdog_reaped =
        disarmed && reap_owned_child_until(
                        watchdog_pid, CODEX_WATCHDOG_REAP_TIMEOUT_MSEC);
    bool final_candidate_absent = external_candidate_service_absent();
    bool final_stock_exact = stock_service_and_snapshot_exact(
        &original_stock, 0, "controller-final");
    bool live_requirement_met =
        !prove_live_injection ||
        (candidate_softened && hook_installed && canary_loaded &&
         marker_matches && live_injection_proved && candidate_observed);
    bool proof = candidate_identity_bound &&
                 stock_exact_while_candidate_live && live_requirement_met;
    bool final_logged = journal_event(
        "event=%s proof=%d candidateBound=%d "
        "stockExactWhileCandidateLive=%d cleaned=%d candidateAbsent=%d "
        "finalStockExact=%d disarmed=%d watchdogReaped=%d stockPid=%d "
        "stockPidVersion=%d stockUniqueId=%llu liveRequired=%d softened=%d "
        "hookInstalled=%d canaryLoaded=%d markerMatches=%d "
        "liveInjectionProved=%d candidateObserved=%d "
        "stockMutationAllowed=0 stockMutated=0",
        prove_live_injection ? "parallel-live-proof-final"
                             : "parallel-bind-audit-final",
        proof, candidate_identity_bound, stock_exact_while_candidate_live,
        cleaned, final_candidate_absent, final_stock_exact, disarmed,
        watchdog_reaped, original_stock.pid,
        original_stock.unique.pid_version,
        (unsigned long long)original_stock.unique.unique_id,
        prove_live_injection, candidate_softened, hook_installed,
        canary_loaded, marker_matches, live_injection_proved,
        candidate_observed);
    int result = 119;
    if (proof && cleaned && final_candidate_absent && final_stock_exact &&
        disarmed && watchdog_reaped && final_logged) {
        result = 0;
    } else if (!candidate_identity_bound) {
        result = 115;
    } else if (!stock_exact_while_candidate_live) {
        result = 116;
    } else if (!live_requirement_met) {
        result = 125;
    }
    dprintf(STDOUT_FILENO,
            "%s status=%d candidateBound=%d "
            "candidatePid=%d stockExactWhileCandidateLive=%d "
            "candidateAbsent=%d originalStockUnchanged=%d stockPid=%d "
            "liveInjectionProved=%d markerMatches=%d stockMutated=0 "
            "disarmed=%d watchdogReaped=%d\n",
            prove_live_injection ? "external-parallel-live-proof"
                                 : "external-parallel-bind-audit",
            result, candidate_identity_bound,
            candidate_identity_bound ? candidate.pid : -1,
            stock_exact_while_candidate_live, final_candidate_absent,
            final_stock_exact, original_stock.pid, live_injection_proved,
            marker_matches, disarmed,
            watchdog_reaped);
    return result;
}

static int external_controller_main(const char *invocation_path) {
    gRole = "external-controller";
    uuid_t run_uuid;
    uuid_generate_random(run_uuid);
    uuid_unparse_lower(run_uuid, gRunToken);

    gLockDescriptor = open(kLockPath,
                           O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (gLockDescriptor < 0) {
        return 70;
    }
    if (gLockDescriptor == CODEX_LOCK_INHERITED_FD) {
        int replacement = fcntl(gLockDescriptor, F_DUPFD_CLOEXEC,
                                CODEX_LOCK_INHERITED_FD + 1);
        if (replacement < 0) {
            return 70;
        }
        close(gLockDescriptor);
        gLockDescriptor = replacement;
    }
    struct stat lock_status = {0};
    if (fstat(gLockDescriptor, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        lock_status.st_nlink != 1 || (lock_status.st_mode & 0077) != 0 ||
        fchmod(gLockDescriptor, 0600) != 0 ||
        flock(gLockDescriptor, LOCK_EX | LOCK_NB) != 0) {
        return 71;
    }
    if (!open_secure_lock(kRecoveryLockPath, &gRecoveryDescriptor) ||
        try_recovery_lock() != RECOVERY_LOCK_ACQUIRED) {
        return 71;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGHUP, &action, NULL);

    struct process_snapshot original_stock = {0};
    if (!controller_preflight(invocation_path, &original_stock, true,
                              true)) {
        if (gJournalDescriptor >= 0) {
            (void)journal_event(
                "event=external-preflight-failed rollbackArmed=0 mutated=0");
        }
        return 72;
    }

    struct command_result candidate_print =
        print_external_candidate_service();
    char candidate_print_output[512];
    char candidate_print_error[512];
    compact_command_output(candidate_print.standard_output,
                           candidate_print_output,
                           sizeof(candidate_print_output));
    compact_command_output(candidate_print.standard_error,
                           candidate_print_error,
                           sizeof(candidate_print_error));
    bool candidate_process_is_absent = candidate_process_absent();
    bool external_launchctl_valid = external_launchctl_file_valid();
    bool candidate_print_exact =
        !candidate_print.standard_output_truncated &&
        !candidate_print.standard_error_truncated &&
        candidate_print.standard_error[0] == '\0' &&
        external_candidate_print_is_exact_dormant(
            candidate_print.standard_output);
    bool candidate_ready = command_succeeded(&candidate_print) &&
                           candidate_process_is_absent &&
                           external_launchctl_valid && candidate_print_exact &&
                           original_stock_still_unique(&original_stock);
    (void)journal_event(
        "event=external-candidate-preflight spawn=%d timeout=%d exit=%d "
        "ready=%d processAbsent=%d launchctlValid=%d printExact=%d target=%s "
        "stdout=\"%s\" stderr=\"%s\" "
        "rollbackArmed=0 mutated=0",
        candidate_print.spawn_error, candidate_print.timed_out,
        candidate_print.exit_code, candidate_ready,
        candidate_process_is_absent, external_launchctl_valid,
        candidate_print_exact, kExternalCandidateTarget,
        candidate_print_output, candidate_print_error);
    if (!candidate_ready) {
        return 72;
    }

    struct process_snapshot controller = {0};
    if (!read_controller_snapshot(getpid(), &controller)) {
        (void)journal_event(
            "event=external-controller-bind-failed rollbackArmed=0 "
            "mutated=0");
        return 73;
    }
    pid_t watchdog_pid = -1;
    bool watchdog_armed =
        spawn_watchdog(&controller, &watchdog_pid, false, true);
    if (!watchdog_armed) {
        (void)create_marker("disarm");
        (void)journal_event(
            "event=external-watchdog-arm-failed rollbackArmed=0 mutated=0");
        return 74;
    }

    bool rollback_armed = false;
    bool candidate_observed = false;
    bool live_injection_proved = false;
    bool candidate_attached = false;
    int gated_pair_result = 85;
    struct process_snapshot candidate = {0};
    struct candidate_pid_hold candidate_hold = {
        .task = MACH_PORT_NULL,
    };
    uint32_t candidate_flags = 0;

    if (gStopRequested ||
        !original_stock_still_unique(&original_stock)) {
        (void)journal_event(
            "event=external-stock-changed-before-mutation "
            "rollbackArmed=0 mutated=0");
        goto rollback;
    }

    /* Arm recovery immediately before the first operation that can remove
       stock SpringBoard. Preflight failures above cannot restart it. */
    rollback_armed = true;
    (void)journal_event(
        "event=external-rollback-armed next=stock-bootout mutated=0");
    struct command_result stock_bootout = bootout_stock_service();
    (void)journal_event(
        "event=external-stock-bootout spawn=%d timeout=%d exit=%d "
        "rollbackArmed=1",
        stock_bootout.spawn_error, stock_bootout.timed_out,
        stock_bootout.exit_code);
    if (!command_succeeded(&stock_bootout) || gStopRequested ||
        !wait_for_stock_and_candidate_processes_absent(
            CODEX_RESTORE_VERIFY_MSEC)) {
        goto rollback;
    }

    struct command_result candidate_kickstart =
        kickstart_external_candidate_service();
    pid_t returned_pid = -1;
    bool kickstart_output_exact =
        command_succeeded(&candidate_kickstart) &&
        !candidate_kickstart.standard_output_truncated &&
        !candidate_kickstart.standard_error_truncated &&
        candidate_kickstart.standard_error[0] == '\0';
    bool printed_pid =
        kickstart_output_exact &&
        parse_printed_pid(candidate_kickstart.standard_output,
                          &returned_pid);
    bool zero_pid_sentinel =
        kickstart_output_exact &&
        parse_zero_pid_sentinel(candidate_kickstart.standard_output);
    char kickstart_output[512];
    char kickstart_error[512];
    compact_command_output(candidate_kickstart.standard_output,
                           kickstart_output, sizeof(kickstart_output));
    compact_command_output(candidate_kickstart.standard_error,
                           kickstart_error, sizeof(kickstart_error));
    (void)journal_event(
        "event=external-candidate-kickstart spawn=%d timeout=%d exit=%d "
        "stdoutTruncated=%d stderrTruncated=%d printedPidValid=%d "
        "zeroPidSentinel=%d returnedPid=%d startSuspended=1 "
        "stdout=\"%s\" stderr=\"%s\"",
        candidate_kickstart.spawn_error, candidate_kickstart.timed_out,
        candidate_kickstart.exit_code,
        candidate_kickstart.standard_output_truncated,
        candidate_kickstart.standard_error_truncated, printed_pid,
        zero_pid_sentinel, returned_pid, kickstart_output, kickstart_error);
    bool candidate_identity_bound = false;
    if (!gStopRequested) {
        if (printed_pid) {
            candidate_identity_bound = wait_for_returned_candidate(
                returned_pid, &candidate, &candidate_flags);
        } else if (zero_pid_sentinel) {
            candidate_identity_bound = wait_for_replacement_unique_candidate(
                &returned_pid, &candidate, &candidate_flags);
        }
    }
    if (!candidate_identity_bound) {
        goto rollback;
    }
    (void)journal_event(
        "event=external-candidate-bound candidatePid=%d uid=%u ppid=%u "
        "pidVersion=%d uniqueId=%llu flags=0x%08x path=%s",
        candidate.pid, candidate.bsd.pbi_uid, candidate.bsd.pbi_ppid,
        candidate.unique.pid_version,
        (unsigned long long)candidate.unique.unique_id, candidate_flags,
        candidate.path);

    candidate_attached = true;
    if (!attach_candidate_for_injection(&candidate, &candidate_flags, NULL,
                                        true, &candidate_hold)) {
        goto rollback;
    }
    gated_pair_result = run_candidate_loader_pair_gated(
        &candidate, &candidate_flags, &candidate_attached, &candidate_hold);
    bool hook_installed = gated_pair_result == 0;
    bool canary_loaded = gated_pair_result == 0;
    bool marker_matches = false;
    uint64_t marker_deadline = monotonic_msec() + 75U;
    do {
        marker_matches = fresh_canary_marker_matches(candidate.pid);
        if (marker_matches || !canary_loaded) {
            break;
        }
        usleep(2U * 1000U);
    } while (monotonic_msec() < marker_deadline);
    live_injection_proved =
        candidate_identity_bound && hook_installed && canary_loaded &&
        marker_matches;
    candidate_observed =
        live_injection_proved &&
        candidate_debug_policy_still_exact(&candidate, &candidate_flags);
    (void)journal_event(
        "event=external-live-injection-proof candidatePid=%d pairResult=%d "
        "hookInstalled=%d canaryResult=%d canaryLoaded=%d "
        "markerMatches=%d survivedPair=%d flags=0x%08x",
        candidate.pid, gated_pair_result, hook_installed,
        gated_pair_result,
        canary_loaded, marker_matches, candidate_observed,
        candidate_flags);

rollback:
    if (candidate.pid > 1 &&
        (candidate_hold.owned || MACH_PORT_VALID(candidate_hold.task))) {
        bool hold_cleanup_resolved = cleanup_candidate_pid_hold(
            &candidate, &candidate_hold, "outer-rollback");
        (void)journal_event(
            "event=external-rollback-pid-hold candidatePid=%d "
            "resolved=%d holdOwned=%d taskValid=%d",
            candidate.pid, hold_cleanup_resolved, candidate_hold.owned,
            MACH_PORT_VALID(candidate_hold.task));
    }
    if (candidate_attached &&
        candidate_traced_snapshot_still_exact_for_mode(
            &candidate, NULL, false, NULL)) {
        errno = 0;
        int trace_kill_result = ptrace(PT_KILL, candidate.pid, NULL, 0);
        int trace_kill_error = trace_kill_result == 0 ? 0 : errno;
        if (trace_kill_result == 0) {
            candidate_attached = false;
        }
        (void)journal_event(
            "event=external-rollback-trace-kill candidatePid=%d "
            "result=%d errno=%d attachedAfter=%d",
            candidate.pid, trace_kill_result, trace_kill_error,
            candidate_attached);
    }
    gStopRequested = 0;
    if (takeover_requested() && owned_child_live(watchdog_pid)) {
        (void)journal_event(
            "event=external-rollback-handed-to-watchdog "
            "watchdogWorkerPid=%d rollbackArmed=%d",
            watchdog_pid, rollback_armed);
        return 77;
    }
    if (takeover_requested()) {
        gHonorTakeover = false;
        (void)journal_event(
            "event=external-takeover-marker-without-live-watchdog "
            "action=controller-restore");
    }

    struct process_snapshot restored_stock = {0};
    bool used_fallback = false;
    bool restored = false;
    if (!rollback_armed) {
        struct command_result candidate_bootout =
            bootout_external_candidate_service();
        (void)journal_event(
            "event=external-pre-mutation-cleanup spawn=%d timeout=%d "
            "exit=%d stockRestarted=0",
            candidate_bootout.spawn_error, candidate_bootout.timed_out,
            candidate_bootout.exit_code);
        restored = external_candidate_service_absent() &&
                   original_stock_still_unique(&original_stock);
    } else {
        (void)journal_event(
            "event=external-rollback-begin candidateObserved=%d "
            "rollbackArmed=1",
            candidate_observed);
        restored = restore_external_stock(false, &restored_stock,
                                          &used_fallback);
    }
    if (!restored && owned_child_live(watchdog_pid)) {
        (void)journal_event(
            "event=external-controller-restore-failed "
            "watchdogWorkerPid=%d",
            watchdog_pid);
        return 77;
    }
    if (restored && !rollback_armed) {
        restored_stock = original_stock;
    }
    bool final_candidate_absent = false;
    if (restored) {
        final_candidate_absent = external_candidate_service_absent();
        restored = snapshot_still_exact(&restored_stock, PROCESS_STOCK,
                                        NULL) &&
                   find_unique_stock(&restored_stock) &&
                   final_candidate_absent;
    }
    bool disarmed = restored && create_marker("disarm");
    bool watchdog_reaped = watchdog_pid <= 1;
    if (disarmed && watchdog_pid > 1) {
        watchdog_reaped = reap_owned_child_until(
            watchdog_pid, CODEX_WATCHDOG_REAP_TIMEOUT_MSEC);
    }
    bool final_logged = journal_event(
        "event=external-final candidateObserved=%d liveInjectionProved=%d "
        "restored=%d fallback=%d stockPid=%d stockPidVersion=%d "
        "stockUniqueId=%llu candidateAbsent=%d disarmed=%d "
        "watchdogReaped=%d rollbackArmed=%d committed=0",
        candidate_observed, live_injection_proved, restored,
        used_fallback, restored ? restored_stock.pid : -1,
        restored ? restored_stock.unique.pid_version : -1,
        restored
            ? (unsigned long long)restored_stock.unique.unique_id
            : 0ULL,
        final_candidate_absent, disarmed, watchdog_reaped,
        rollback_armed);
    int final_status =
        live_injection_proved && restored &&
                final_candidate_absent && disarmed && watchdog_reaped &&
                final_logged
            ? 0
            : (restored ? 76 : 77);
    dprintf(STDOUT_FILENO,
            "external-live-proof status=%d candidateObserved=%d "
            "liveInjectionProved=%d markerRequired=1 restored=%d "
            "candidateAbsent=%d stockCount=1 stockPid=%d stockUid=501 "
            "stockPpid=1 stockPath=%s "
            "stockUuid=AD937FB7-2664-3B8F-B1C9-34C4AD4092D2 "
            "disarmed=%d watchdogReaped=%d rollbackArmed=%d\n",
            final_status, candidate_observed, live_injection_proved,
            restored, final_candidate_absent,
            restored ? restored_stock.pid : -1, kStockPath, disarmed,
            watchdog_reaped, rollback_armed);
    return final_status;
}

static int controller_main(const char *invocation_path, bool arm_only) {
    uuid_t run_uuid;
    uuid_generate_random(run_uuid);
    uuid_unparse_lower(run_uuid, gRunToken);

    gLockDescriptor = open(kLockPath,
                           O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (gLockDescriptor < 0) {
        return 70;
    }
    if (gLockDescriptor == CODEX_LOCK_INHERITED_FD) {
        int replacement = fcntl(gLockDescriptor, F_DUPFD_CLOEXEC,
                                CODEX_LOCK_INHERITED_FD + 1);
        if (replacement < 0) {
            return 70;
        }
        close(gLockDescriptor);
        gLockDescriptor = replacement;
    }
    struct stat lock_status = {0};
    if (fstat(gLockDescriptor, &lock_status) != 0 ||
        !S_ISREG(lock_status.st_mode) || lock_status.st_uid != 0 ||
        lock_status.st_nlink != 1 || (lock_status.st_mode & 0077) != 0 ||
        fchmod(gLockDescriptor, 0600) != 0 ||
        flock(gLockDescriptor, LOCK_EX | LOCK_NB) != 0) {
        return 71;
    }
    if (!open_secure_lock(kRecoveryLockPath, &gRecoveryDescriptor) ||
        try_recovery_lock() != RECOVERY_LOCK_ACQUIRED) {
        return 71;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGHUP, &action, NULL);

    struct process_snapshot original_stock = {0};
    bool external_arm_test = arm_only;
    if (!controller_preflight(invocation_path, &original_stock, !arm_only,
                              external_arm_test)) {
        if (gJournalDescriptor >= 0) {
            (void)journal_event("event=preflight-failed mutated=0");
        }
        return 72;
    }

    struct process_snapshot controller = {0};
    if (!read_controller_snapshot(getpid(), &controller)) {
        (void)journal_event("event=controller-bind-failed mutated=0");
        return 73;
    }
    pid_t watchdog_pid = -1;
    bool watchdog_armed = spawn_watchdog(&controller, &watchdog_pid,
                                         arm_only, external_arm_test);
    if (!watchdog_armed) {
        (void)create_marker("disarm");
        (void)journal_event("event=watchdog-arm-failed mutated=0");
        return 74;
    }

    if (arm_only) {
        bool stock_unchanged = original_stock_still_unique(&original_stock);
        bool disarmed = stock_unchanged && create_marker("disarm");
        bool reaped = disarmed &&
                      reap_owned_child_until(
                          watchdog_pid,
                          CODEX_WATCHDOG_REAP_TIMEOUT_MSEC);
        bool final_stock = reaped && original_stock_still_unique(&original_stock);
        bool logged = journal_event(
            "event=watchdog-arm-test-final stockUnchanged=%d disarmed=%d "
            "watchdogReaped=%d finalStock=%d mutated=0",
            stock_unchanged, disarmed, reaped, final_stock);
        return stock_unchanged && disarmed && reaped && final_stock && logged
                   ? 0
                   : 75;
    }

    bool candidate_observed = false;
    bool live_injection_proved = false;
    bool candidate_attached = false;
    struct process_snapshot candidate = {0};
    uint32_t candidate_flags = 0;

    if (!original_stock_still_unique(&original_stock)) {
        (void)journal_event("event=stock-changed-before-debug mutated=0");
        goto rollback;
    }
    struct command_result debug = debug_program(kCandidatePath, true);
    char debug_output[512];
    char debug_error[512];
    compact_command_output(debug.standard_output, debug_output,
                           sizeof(debug_output));
    compact_command_output(debug.standard_error, debug_error,
                           sizeof(debug_error));
    (void)journal_event("event=candidate-debug-override spawn=%d timeout=%d "
                        "exit=%d program=%s startSuspended=1 stdout=\"%s\" "
                        "stderr=\"%s\"",
                        debug.spawn_error, debug.timed_out, debug.exit_code,
                        kCandidatePath, debug_output, debug_error);
    if (!command_succeeded(&debug) || gStopRequested) {
        goto rollback;
    }
    if (!original_stock_still_unique(&original_stock)) {
        (void)journal_event("event=stock-changed-before-kickstart");
        goto rollback;
    }
    struct command_result kickstart = kickstart_service(true);
    pid_t returned_pid = -1;
    bool printed_pid = command_succeeded(&kickstart) &&
                       parse_printed_pid(kickstart.standard_output,
                                         &returned_pid);
    (void)journal_event("event=candidate-kickstart spawn=%d timeout=%d "
                        "exit=%d printedPidValid=%d returnedPid=%d",
                        kickstart.spawn_error, kickstart.timed_out,
                        kickstart.exit_code, printed_pid, returned_pid);
    if (!printed_pid || gStopRequested ||
        !wait_for_returned_candidate(returned_pid, &candidate,
                                     &candidate_flags)) {
        goto rollback;
    }
    (void)journal_event("event=candidate-bound candidatePid=%d uid=%u ppid=%u "
                        "pidVersion=%d uniqueId=%llu flags=0x%08x path=%s",
                        candidate.pid, candidate.bsd.pbi_uid,
                        candidate.bsd.pbi_ppid,
                        candidate.unique.pid_version,
                        (unsigned long long)candidate.unique.unique_id,
                        candidate_flags, candidate.path);

    candidate_attached = true;
    if (!attach_detach_resume_candidate(&candidate, &candidate_flags, NULL)) {
        goto rollback;
    }
    candidate_attached = false;
    int hook_result = 85;
    for (unsigned int attempt = 0; attempt < 4U; ++attempt) {
        if (!candidate_debug_policy_still_exact(&candidate,
                                                &candidate_flags)) {
            break;
        }
        hook_result = run_candidate_loader_injection(
            &candidate, kDyldAdmissionHookPath, NULL);
        if (hook_result == 0) {
            break;
        }
        usleep(150U * 1000U);
    }
    bool hook_installed = hook_result == 0 &&
        candidate_debug_policy_still_exact(&candidate, &candidate_flags);
    int canary_result = hook_installed
        ? run_candidate_loader_injection(&candidate, kFreshCanaryPath, NULL)
        : 84;
    bool canary_loaded = canary_result == 0 &&
        candidate_debug_policy_still_exact(&candidate, &candidate_flags);
    bool marker_matches = false;
    uint64_t marker_deadline = monotonic_msec() + 1000U;
    do {
        marker_matches = fresh_canary_marker_matches(candidate.pid);
        if (marker_matches || !canary_loaded) {
            break;
        }
        usleep(20U * 1000U);
    } while (monotonic_msec() < marker_deadline);
    live_injection_proved =
        hook_installed && canary_loaded && marker_matches;
    (void)journal_event("event=live-injection-proof candidatePid=%d "
                        "hookResult=%d hookInstalled=%d canaryResult=%d "
                        "canaryLoaded=%d markerMatches=%d flags=0x%08x",
                        candidate.pid, hook_result, hook_installed,
                        canary_result, canary_loaded, marker_matches,
                        candidate_flags);
    candidate_observed =
        live_injection_proved && observe_candidate(&candidate, NULL);

rollback:
    if (candidate_attached &&
        candidate_traced_snapshot_still_exact_for_mode(
            &candidate, NULL, false, NULL)) {
        (void)ptrace(PT_DETACH, candidate.pid, NULL, 0);
    }
    /* A stop request aborts the experiment, never the safety rollback. */
    gStopRequested = 0;
    if (takeover_requested() && owned_child_live(watchdog_pid)) {
        (void)journal_event("event=rollback-handed-to-watchdog "
                            "watchdogWorkerPid=%d",
                            watchdog_pid);
        return 77;
    }
    if (takeover_requested()) {
        /* A dead watchdog cannot own recovery. The controller still holds the
           exclusive recovery lease, so it may safely finish rollback. */
        gHonorTakeover = false;
        (void)journal_event("event=takeover-marker-without-live-watchdog "
                            "action=controller-restore");
    }
    (void)journal_event("event=rollback-begin candidateObserved=%d "
                        "defaultRollback=1",
                        candidate_observed);
    struct process_snapshot restored_stock = {0};
    bool used_fallback = false;
    bool restored = restore_stock(false, &restored_stock, &used_fallback);
    if (!restored) {
        (void)journal_event("event=controller-restore-failed "
                            "waitingForWatchdog=1");
        restored = wait_for_stock(CODEX_WATCHDOG_GRACE_MSEC, false,
                                  &restored_stock);
    }
    if (!restored && takeover_requested() &&
        owned_child_live(watchdog_pid)) {
        (void)journal_event("event=restore-handed-to-watchdog "
                            "watchdogWorkerPid=%d",
                            watchdog_pid);
        return 77;
    }
    if (restored) {
        restored = snapshot_still_exact(&restored_stock, PROCESS_STOCK, NULL);
    }
    bool disarmed = restored && create_marker("disarm");
    bool final_logged = journal_event(
                        "event=final candidateObserved=%d "
                        "liveInjectionProved=%d restored=%d "
                        "fallback=%d stockPid=%d stockPidVersion=%d "
                        "stockUniqueId=%llu disarmed=%d committed=0",
                        candidate_observed, live_injection_proved, restored,
                        used_fallback,
                        restored ? restored_stock.pid : -1,
                        restored ? restored_stock.unique.pid_version : -1,
                        restored
                            ? (unsigned long long)restored_stock.unique.unique_id
                            : 0ULL,
                        disarmed);

    if (restored && watchdog_pid > 1) {
        uint64_t reap_deadline = monotonic_msec() + 2000U;
        do {
            int status = 0;
            pid_t waited = waitpid(watchdog_pid, &status, WNOHANG);
            if (waited == watchdog_pid || (waited < 0 && errno == ECHILD)) {
                break;
            }
            usleep(20U * 1000U);
        } while (monotonic_msec() < reap_deadline);
    }
    return candidate_observed && live_injection_proved && restored &&
                   disarmed && final_logged
               ? 0
               : (restored ? 76 : 77);
}

int main(int argc, char **argv) {
    if (argc == 10 &&
        strcmp(argv[1], "--parallel-bind-watchdog") == 0) {
        return parallel_bind_watchdog_main(
            argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            argv[9]);
    }
    if (argc == 6 &&
        (strcmp(argv[1], "--watchdog") == 0 ||
         strcmp(argv[1], "--watchdog-arm-only") == 0 ||
         strcmp(argv[1], "--external-watchdog") == 0)) {
        return watchdog_main(argv[2], argv[3], argv[4], argv[5],
                             strcmp(argv[1], "--watchdog-arm-only") == 0,
                             strcmp(argv[1], "--external-watchdog") == 0);
    }
    if (argc == 2 && strcmp(argv[1], "--first-live-precursor") == 0) {
        return controller_main(argv[0], false);
    }
    if (argc == 2 && strcmp(argv[1], "--watchdog-arm-test") == 0) {
        return controller_main(argv[0], true);
    }
    if (argc == 2 && strcmp(argv[1], "--external-live-proof") == 0) {
        return external_controller_main(argv[0]);
    }
    if (argc == 2 &&
        strcmp(argv[1], "--external-service-removal-audit") == 0) {
        return external_service_removal_audit_main(argv[0]);
    }
    if (argc == 2 &&
        strcmp(argv[1], "--external-parallel-bind-audit") == 0) {
        return external_parallel_candidate_main(argv[0], false);
    }
    if (argc == 2 &&
        strcmp(argv[1], "--external-parallel-live-proof") == 0) {
        return external_parallel_candidate_main(argv[0], true);
    }
    if (argc == 3 &&
        strcmp(argv[1], "--inject-existing-candidate") == 0) {
        return inject_existing_candidate_main(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "--soften-cryptexd") == 0) {
        return soften_cryptexd_main(argv[2]);
    }
    {
        fprintf(stderr,
                "usage: %s --first-live-precursor|--watchdog-arm-test|"
                "--external-live-proof|--external-service-removal-audit|"
                "--external-parallel-bind-audit|"
                "--external-parallel-live-proof|"
                "--inject-existing-candidate PID|"
                "--soften-cryptexd PID\n"
                "This precursor restores or preserves exact stock "
                "SpringBoard according to the selected mode.\n",
                argv[0]);
        return 64;
    }
}
