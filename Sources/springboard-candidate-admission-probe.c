#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <uuid/uuid.h>

#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif
#ifndef PT_KILL
#define PT_KILL 8
#endif

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_OPS_CDHASH 5U
#define CODEX_CS_OPS_IDENTITY 11U
#define CODEX_CS_OPS_TEAMID 14U
#define CODEX_CS_OPS_VALIDATION_CATEGORY 17U
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_CDHASH_SIZE 20U
#define CODEX_IDENTITY_BUFFER_SIZE 512U
#define CODEX_PATH_SIZE 1024U
#define CODEX_PROC_PIDUNIQIDENTIFIERINFO 17
#define CODEX_STATIC_SETTLE_ATTEMPTS 250U
#define CODEX_CLEANUP_ATTEMPTS 500U
#define CODEX_EXPECTED_CANDIDATE_SIZE 122400ULL

#define CODEX_REPORT_MAGIC "codex-springboard-candidate-admission-v2-bundle"

static const char *const kLiveSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kCandidatePath =
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard";
static const char *const kReportPath =
    "/private/var/mobile/Media/"
    "codex-springboard-candidate-admission-probe.txt";
static const uint8_t kExpectedSpringBoardUUID[16] = {
    0xad, 0x93, 0x7f, 0xb7, 0x26, 0x64, 0x3b, 0x8f,
    0xb1, 0xc9, 0x34, 0xc4, 0xad, 0x40, 0x92, 0xd2,
};
static const uint8_t kExpectedCandidateCDHash[CODEX_CDHASH_SIZE] = {
    0x9b, 0x29, 0x8e, 0x84, 0x6a, 0xb9, 0x1a, 0xaa, 0x1f, 0xba,
    0x30, 0x3f, 0x2c, 0x89, 0x2d, 0x82, 0x8e, 0x9e, 0x92, 0x1c,
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

typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef allocator,
                                                audit_token_t token);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task,
                                                 CFStringRef entitlement,
                                                 CFErrorRef *error);
extern CFStringRef SecTaskCopySigningIdentifier(SecTaskRef task,
                                                 CFErrorRef *error);
extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);

static pid_t gOwnedChild = -1;

static bool bounded_wait(pid_t child, int options, unsigned int attempts,
                         int *status, pid_t *wait_result, int *wait_error) {
    for (unsigned int attempt = 0; attempt < attempts; ++attempt) {
        errno = 0;
        pid_t result = waitpid(child, status, options | WNOHANG);
        int result_error = result < 0 ? errno : 0;
        if (result == child || (result < 0 && result_error != EINTR)) {
            if (wait_result != NULL) {
                *wait_result = result;
            }
            if (wait_error != NULL) {
                *wait_error = result_error;
            }
            return result == child;
        }
        usleep(2U * 1000U);
    }
    if (wait_result != NULL) {
        *wait_result = 0;
    }
    if (wait_error != NULL) {
        *wait_error = ETIMEDOUT;
    }
    return false;
}

static bool terminate_and_reap(pid_t child, bool ptrace_stopped,
                               int *ptrace_kill_result,
                               int *ptrace_kill_error, int *signal_result,
                               int *signal_error, pid_t *wait_result,
                               int *wait_error, int *wait_status) {
    if (child <= 1 || child != gOwnedChild) {
        return false;
    }

    *ptrace_kill_result = -1;
    *ptrace_kill_error = 0;
    if (ptrace_stopped) {
        errno = 0;
        *ptrace_kill_result = ptrace(PT_KILL, child, NULL, 0);
        *ptrace_kill_error = *ptrace_kill_result == 0 ? 0 : errno;
    }

    *signal_result = -1;
    *signal_error = 0;
    if (!ptrace_stopped || *ptrace_kill_result != 0) {
        errno = 0;
        *signal_result = kill(child, SIGKILL);
        *signal_error = *signal_result == 0 ? 0 : errno;
    }

    bool reaped = bounded_wait(child, 0, CODEX_CLEANUP_ATTEMPTS,
                               wait_status, wait_result, wait_error);
    if (!reaped) {
        (void)kill(child, SIGKILL);
        reaped = bounded_wait(child, 0, CODEX_CLEANUP_ATTEMPTS,
                              wait_status, wait_result, wait_error);
    }
    if (reaped) {
        gOwnedChild = -1;
    }
    return reaped;
}

static void terminate_owned_child_at_exit(void) {
    pid_t child = gOwnedChild;
    if (child <= 1) {
        return;
    }
    (void)kill(child, SIGKILL);
    int status = 0;
    pid_t wait_result = 0;
    int wait_error = 0;
    if (bounded_wait(child, 0, CODEX_CLEANUP_ATTEMPTS, &status,
                     &wait_result, &wait_error)) {
        gOwnedChild = -1;
    }
}

static int parse_pid(const char *text, pid_t *result) {
    if (text == NULL || result == NULL || *text == '\0') {
        return EINVAL;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT32_MAX) {
        return EINVAL;
    }
    *result = (pid_t)value;
    return 0;
}

static bool exact_process_path(pid_t pid, const char *expected,
                               char observed[CODEX_PATH_SIZE]) {
    memset(observed, 0, CODEX_PATH_SIZE);
    if (pid <= 1 || expected == NULL) {
        return false;
    }
    int length = proc_pidpath(pid, observed, CODEX_PATH_SIZE);
    return length > 0 && (size_t)length < CODEX_PATH_SIZE &&
           strcmp(observed, expected) == 0;
}

static bool candidate_process_path(pid_t pid, const char *real_path,
                                   char observed[CODEX_PATH_SIZE]) {
    memset(observed, 0, CODEX_PATH_SIZE);
    if (pid <= 1 || real_path == NULL) {
        return false;
    }
    int length = proc_pidpath(pid, observed, CODEX_PATH_SIZE);
    return length > 0 && (size_t)length < CODEX_PATH_SIZE &&
           (strcmp(observed, kCandidatePath) == 0 ||
            strcmp(observed, real_path) == 0);
}

static bool copy_unique_info(pid_t pid,
                             struct codex_proc_uniqidentifierinfo *info) {
    memset(info, 0, sizeof(*info));
    int result = proc_pidinfo(pid, CODEX_PROC_PIDUNIQIDENTIFIERINFO, 0, info,
                              (int)sizeof(*info));
    return result == (int)sizeof(*info);
}

static void format_uuid(const uint8_t bytes[16], char output[37]) {
    uuid_string_t temporary = {0};
    uuid_unparse_upper(bytes, temporary);
    memcpy(output, temporary, sizeof(temporary));
}

static bool verify_candidate_macho(int descriptor, char uuid_text[37]) {
    struct mach_header_64 header = {0};
    ssize_t header_amount = pread(descriptor, &header, sizeof(header), 0);
    if (header_amount != (ssize_t)sizeof(header) ||
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
    ssize_t command_amount =
        pread(descriptor, commands, header.sizeofcmds, sizeof(header));
    bool valid = command_amount == (ssize_t)header.sizeofcmds;
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
            if (valid) {
                format_uuid(uuid_command->uuid, uuid_text);
            }
        }
        offset += command->cmdsize;
    }
    valid = valid && found_uuid && offset == header.sizeofcmds;
    free(commands);
    return valid;
}

static int copy_cs_string(pid_t pid, unsigned int operation, char *output,
                          size_t output_size) {
    uint8_t buffer[CODEX_IDENTITY_BUFFER_SIZE] = {0};
    errno = 0;
    int result = csops(pid, operation, buffer, sizeof(buffer));
    int result_error = result == 0 ? 0 : errno;
    if (result != 0 || output_size == 0) {
        if (output_size > 0) {
            output[0] = '\0';
        }
        return result_error;
    }

    uint32_t network_length = 0;
    memcpy(&network_length, buffer + 4, sizeof(network_length));
    uint32_t length = ntohl(network_length);
    if (length <= 8U || length > sizeof(buffer) || buffer[length - 1U] != 0) {
        output[0] = '\0';
        return EPROTO;
    }
    size_t string_length = length - 8U;
    if (string_length > output_size) {
        output[0] = '\0';
        return ERANGE;
    }
    memcpy(output, buffer + 8, string_length);
    return 0;
}

static void format_hex(const uint8_t *bytes, size_t length, char *output,
                       size_t output_size) {
    static const char alphabet[] = "0123456789abcdef";
    if (output_size < length * 2U + 1U) {
        if (output_size > 0) {
            output[0] = '\0';
        }
        return;
    }
    for (size_t index = 0; index < length; ++index) {
        output[index * 2U] = alphabet[bytes[index] >> 4U];
        output[index * 2U + 1U] = alphabet[bytes[index] & 0x0fU];
    }
    output[length * 2U] = '\0';
}

static void copy_cf_description(CFTypeRef value, char *output,
                                size_t output_size) {
    if (value == NULL || output_size == 0) {
        return;
    }
    if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
        snprintf(output, output_size, "%s",
                 CFBooleanGetValue((CFBooleanRef)value) ? "true" : "false");
        return;
    }
    CFStringRef description = CFCopyDescription(value);
    if (description == NULL ||
        !CFStringGetCString(description, output, (CFIndex)output_size,
                            kCFStringEncodingUTF8)) {
        snprintf(output, output_size, "<unprintable>");
    }
    if (description != NULL) {
        CFRelease(description);
    }
    for (size_t index = 0; output[index] != '\0'; ++index) {
        if (output[index] == '\n' || output[index] == '\r' ||
            output[index] == '=') {
            output[index] = '_';
        }
    }
}

static bool report_sectask(FILE *report, audit_token_t token) {
    SecTaskRef task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, token);
    fprintf(report, "secTaskCreated=%d\n", task != NULL);
    if (task == NULL) {
        return false;
    }

    CFErrorRef identifier_error = NULL;
    CFStringRef identifier =
        SecTaskCopySigningIdentifier(task, &identifier_error);
    char identifier_text[CODEX_IDENTITY_BUFFER_SIZE] = {0};
    copy_cf_description(identifier, identifier_text, sizeof(identifier_text));
    fprintf(report, "secTaskSigningIdentifier=%s\n",
            identifier != NULL ? identifier_text : "<unavailable>");
    fprintf(report, "secTaskSigningIdentifierError=%ld\n",
            identifier_error != NULL ? (long)CFErrorGetCode(identifier_error)
                                     : 0L);
    bool signing_identifier_exact =
        identifier != NULL &&
        CFStringCompare(identifier, CFSTR("com.apple.springboard"), 0) ==
            kCFCompareEqualTo;
    fprintf(report, "secTaskSigningIdentifierExact=%d\n",
            signing_identifier_exact);
    if (identifier != NULL) {
        CFRelease(identifier);
    }
    if (identifier_error != NULL) {
        CFRelease(identifier_error);
    }

    static const char *const entitlement_names[] = {
        "application-identifier",
        "get-task-allow",
        "com.apple.private.cs.debugger",
        "com.apple.security.cs.allow-jit",
        "dynamic-codesigning",
        "com.apple.private.skip-library-validation",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "platform-application",
        "task_for_pid-allow",
    };
    bool required_entitlements_exact = true;
    for (size_t index = 0;
         index < sizeof(entitlement_names) / sizeof(entitlement_names[0]);
         ++index) {
        CFStringRef name = CFStringCreateWithCString(
            kCFAllocatorDefault, entitlement_names[index],
            kCFStringEncodingUTF8);
        CFErrorRef value_error = NULL;
        CFTypeRef value = name != NULL
            ? SecTaskCopyValueForEntitlement(task, name, &value_error)
            : NULL;
        char value_text[512] = {0};
        copy_cf_description(value, value_text, sizeof(value_text));
        fprintf(report, "entitlement.%s=%s\n", entitlement_names[index],
                value != NULL ? value_text : "<missing>");
        fprintf(report, "entitlementError.%s=%ld\n",
                entitlement_names[index],
                value_error != NULL ? (long)CFErrorGetCode(value_error) : 0L);
        bool value_exact;
        if (index == 0) {
            value_exact = value != NULL &&
                CFGetTypeID(value) == CFStringGetTypeID() &&
                CFStringCompare((CFStringRef)value,
                                CFSTR("com.apple.springboard"), 0) ==
                    kCFCompareEqualTo;
        } else if (strcmp(entitlement_names[index],
                          "com.apple.security.cs."
                          "allow-dyld-environment-variables") == 0) {
            /* Diagnostic only: the candidate does not rely on DYLD_* input. */
            value_exact = true;
        } else {
            value_exact = value != NULL &&
                CFGetTypeID(value) == CFBooleanGetTypeID() &&
                CFBooleanGetValue((CFBooleanRef)value);
        }
        fprintf(report, "entitlementExact.%s=%d\n",
                entitlement_names[index], value_exact);
        required_entitlements_exact =
            required_entitlements_exact && value_exact;
        if (value != NULL) {
            CFRelease(value);
        }
        if (value_error != NULL) {
            CFRelease(value_error);
        }
        if (name != NULL) {
            CFRelease(name);
        }
    }
    fprintf(report, "requiredEntitlementsExact=%d\n",
            required_entitlements_exact);
    CFRelease(task);
    return signing_identifier_exact && required_entitlements_exact;
}

int main(int argc, char **argv) {
    if (argc != 2 || getpid() <= 1 || geteuid() != 0) {
        return 70;
    }

    pid_t live_pid = -1;
    if (parse_pid(argv[1], &live_pid) != 0 || live_pid == getpid()) {
        return 71;
    }

    char live_path_before[CODEX_PATH_SIZE] = {0};
    struct codex_proc_uniqidentifierinfo live_info_before = {0};
    if (!exact_process_path(live_pid, kLiveSpringBoardPath,
                            live_path_before) ||
        !copy_unique_info(live_pid, &live_info_before) ||
        memcmp(live_info_before.uuid, kExpectedSpringBoardUUID,
               sizeof(kExpectedSpringBoardUUID)) != 0) {
        return 72;
    }

    int candidate_descriptor =
        open(kCandidatePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (candidate_descriptor < 0) {
        return 73;
    }
    struct stat candidate_status = {0};
    char candidate_uuid[37] = {0};
    char candidate_real_path[CODEX_PATH_SIZE] = {0};
    bool candidate_valid =
        fstat(candidate_descriptor, &candidate_status) == 0 &&
        S_ISREG(candidate_status.st_mode) && candidate_status.st_uid == 0 &&
        (uint64_t)candidate_status.st_size == CODEX_EXPECTED_CANDIDATE_SIZE &&
        (candidate_status.st_mode & 0111) != 0 &&
        (candidate_status.st_mode & 0022) == 0 &&
        realpath(kCandidatePath, candidate_real_path) != NULL &&
        candidate_real_path[0] == '/' &&
        strcmp(candidate_real_path, kLiveSpringBoardPath) != 0 &&
        verify_candidate_macho(candidate_descriptor, candidate_uuid);
    if (!candidate_valid) {
        close(candidate_descriptor);
        return 74;
    }

    int report_descriptor =
        open(kReportPath,
             O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (report_descriptor < 0) {
        close(candidate_descriptor);
        return 75;
    }
    struct stat report_status = {0};
    if (fstat(report_descriptor, &report_status) != 0 ||
        !S_ISREG(report_status.st_mode) ||
        fchmod(report_descriptor, 0600) != 0) {
        close(report_descriptor);
        close(candidate_descriptor);
        return 76;
    }
    FILE *report = fdopen(report_descriptor, "w");
    if (report == NULL) {
        close(report_descriptor);
        close(candidate_descriptor);
        return 77;
    }
    setvbuf(report, NULL, _IONBF, 0);

    char live_uuid_before[37] = {0};
    format_uuid(live_info_before.uuid, live_uuid_before);
    fprintf(report,
            "magic=%s\nprobePid=%d\nprobeEuid=%u\nlivePid=%d\n"
            "livePathBefore=%s\nliveUUIDBefore=%s\n"
            "liveUniqueIdBefore=%llu\nlivePidVersionBefore=%d\n"
            "candidatePath=%s\ncandidateRealPath=%s\n"
            "candidateDevice=%llu\ncandidateInode=%llu\n"
            "candidateSize=%llu\ncandidateMode=%o\ncandidateUid=%u\n"
            "candidateUUID=%s\n",
            CODEX_REPORT_MAGIC, getpid(), geteuid(), live_pid,
            live_path_before, live_uuid_before,
            (unsigned long long)live_info_before.unique_id,
            live_info_before.pid_version, kCandidatePath, candidate_real_path,
            (unsigned long long)candidate_status.st_dev,
            (unsigned long long)candidate_status.st_ino,
            (unsigned long long)candidate_status.st_size,
            candidate_status.st_mode & 07777, candidate_status.st_uid,
            candidate_uuid);

    posix_spawnattr_t attributes;
    int attribute_init = posix_spawnattr_init(&attributes);
    int attribute_flags = attribute_init == 0
        ? posix_spawnattr_setflags(&attributes,
                                   POSIX_SPAWN_START_SUSPENDED)
        : attribute_init;
    char *const child_arguments[] = {(char *)kCandidatePath, NULL};
    char *const child_environment[] = {
        (char *)"CODEX_SPRINGBOARD_CANDIDATE_PROBE=1", NULL};
    pid_t child = -1;
    int spawn_result = attribute_flags == 0
        ? posix_spawn(&child, kCandidatePath, NULL, &attributes,
                      child_arguments, child_environment)
        : attribute_flags;
    if (attribute_init == 0) {
        (void)posix_spawnattr_destroy(&attributes);
    }
    fprintf(report,
            "spawnAttributeInit=%d\nspawnAttributeFlags=%d\n"
            "spawnResult=%d\nspawnResultText=%s\nchildPid=%d\n",
            attribute_init, attribute_flags, spawn_result,
            spawn_result == 0 ? "success" : strerror(spawn_result), child);
    if (spawn_result != 0 || child <= 1 || child == live_pid ||
        child == getpid()) {
        fprintf(report, "verdict=spawn-failed\n");
        (void)fsync(report_descriptor);
        fclose(report);
        close(candidate_descriptor);
        return 78;
    }
    gOwnedChild = child;
    (void)atexit(terminate_owned_child_at_exit);

    int suspended_status = 0;
    pid_t suspended_wait = 0;
    int suspended_wait_error = 0;
    bool suspended_waited =
        bounded_wait(child, WUNTRACED, CODEX_CLEANUP_ATTEMPTS,
                     &suspended_status, &suspended_wait,
                     &suspended_wait_error);
    bool suspended_status_stopped =
        suspended_waited && WIFSTOPPED(suspended_status);
    int suspended_stop_signal = suspended_status_stopped
        ? WSTOPSIG(suspended_status)
        : -1;
    bool start_suspended_synthetic =
        suspended_status_stopped && suspended_stop_signal == 0;
    bool start_suspended =
        suspended_status_stopped &&
        (suspended_stop_signal == SIGSTOP || start_suspended_synthetic);
    fprintf(report,
            "suspendedWaitResult=%d\nsuspendedWaitErrno=%d\n"
            "suspendedWaitStatus=0x%08x\n"
            "suspendedStopSignal=%d\n"
            "startSuspendedSynthetic=%d\nstartSuspended=%d\n",
            suspended_wait, suspended_wait_error, suspended_status,
            suspended_stop_signal, start_suspended_synthetic,
            start_suspended);

    char preattach_path[CODEX_PATH_SIZE] = {0};
    struct codex_proc_uniqidentifierinfo preattach_info = {0};
    bool preattach_path_exact =
        candidate_process_path(child, candidate_real_path, preattach_path);
    bool preattach_info_ok = copy_unique_info(child, &preattach_info);
    uint32_t preattach_flags = 0;
    errno = 0;
    int preattach_csops =
        csops(child, CODEX_CS_OPS_STATUS, &preattach_flags,
              sizeof(preattach_flags));
    int preattach_csops_error = preattach_csops == 0 ? 0 : errno;
    uint8_t preattach_cdhash[CODEX_CDHASH_SIZE] = {0};
    errno = 0;
    int preattach_cdhash_result =
        csops(child, CODEX_CS_OPS_CDHASH, preattach_cdhash,
              sizeof(preattach_cdhash));
    int preattach_cdhash_error =
        preattach_cdhash_result == 0 ? 0 : errno;
    char preattach_cdhash_text[CODEX_CDHASH_SIZE * 2U + 1U] = {0};
    format_hex(preattach_cdhash, sizeof(preattach_cdhash),
               preattach_cdhash_text, sizeof(preattach_cdhash_text));
    char preattach_identity[CODEX_IDENTITY_BUFFER_SIZE] = {0};
    int preattach_identity_error = copy_cs_string(
        child, CODEX_CS_OPS_IDENTITY, preattach_identity,
        sizeof(preattach_identity));
    unsigned int preattach_validation_category = 0;
    errno = 0;
    int preattach_validation_result = csops(
        child, CODEX_CS_OPS_VALIDATION_CATEGORY,
        &preattach_validation_category,
        sizeof(preattach_validation_category));
    int preattach_validation_error =
        preattach_validation_result == 0 ? 0 : errno;
    fprintf(report,
            "preattachPath=%s\npreattachPathExact=%d\n"
            "preattachUniqueInfo=%d\npreattachPidVersion=%d\n"
            "preattachUUIDExact=%d\npreattachCsops=%d\n"
            "preattachCsopsErrno=%d\npreattachFlags=0x%08x\n"
            "preattachValid=%d\npreattachDebugged=%d\n"
            "preattachCdhashResult=%d\npreattachCdhashErrno=%d\n"
            "preattachCdhash=%s\npreattachIdentityErrno=%d\n"
            "preattachIdentity=%s\npreattachValidationResult=%d\n"
            "preattachValidationErrno=%d\n"
            "preattachValidationCategory=%u\n",
            preattach_path, preattach_path_exact, preattach_info_ok,
            preattach_info.pid_version,
            preattach_info_ok &&
                memcmp(preattach_info.uuid, kExpectedSpringBoardUUID,
                       sizeof(kExpectedSpringBoardUUID)) == 0,
            preattach_csops, preattach_csops_error, preattach_flags,
            (preattach_flags & CODEX_CS_VALID) != 0,
            (preattach_flags & CODEX_CS_DEBUGGED) != 0,
            preattach_cdhash_result, preattach_cdhash_error,
            preattach_cdhash_text, preattach_identity_error,
            preattach_identity, preattach_validation_result,
            preattach_validation_error, preattach_validation_category);

    bool survived_settle = start_suspended;
    int settle_status = 0;
    pid_t settle_wait = 0;
    int settle_wait_error = 0;
    for (unsigned int attempt = 0;
         survived_settle && attempt < CODEX_STATIC_SETTLE_ATTEMPTS;
         ++attempt) {
        errno = 0;
        pid_t result = waitpid(child, &settle_status, WNOHANG);
        int result_error = result < 0 ? errno : 0;
        if (result == child) {
            survived_settle = false;
            settle_wait = result;
            break;
        }
        if (result < 0 && result_error != EINTR) {
            survived_settle = false;
            settle_wait = result;
            settle_wait_error = result_error;
            break;
        }
        usleep(2U * 1000U);
    }
    fprintf(report,
            "staticSettleMilliseconds=%u\nstaticSettleSurvived=%d\n"
            "staticSettleWaitResult=%d\nstaticSettleWaitErrno=%d\n"
            "staticSettleWaitStatus=0x%08x\n",
            CODEX_STATIC_SETTLE_ATTEMPTS * 2U, survived_settle,
            settle_wait, settle_wait_error, settle_status);
    if (!survived_settle) {
        bool early_reaped = settle_wait == child;
        if (settle_wait == child) {
            gOwnedChild = -1;
        } else {
            int early_ptrace_kill_result = -1;
            int early_ptrace_kill_error = 0;
            int early_signal_result = -1;
            int early_signal_error = 0;
            pid_t early_wait_result = 0;
            int early_wait_error = 0;
            int early_wait_status = 0;
            early_reaped = terminate_and_reap(
                child, false, &early_ptrace_kill_result,
                &early_ptrace_kill_error, &early_signal_result,
                &early_signal_error, &early_wait_result, &early_wait_error,
                &early_wait_status);
            fprintf(report,
                    "earlySignalKillResult=%d\n"
                    "earlySignalKillErrno=%d\n"
                    "earlyCleanupWaitResult=%d\n"
                    "earlyCleanupWaitErrno=%d\n"
                    "earlyCleanupWaitStatus=0x%08x\n",
                    early_signal_result, early_signal_error,
                    early_wait_result, early_wait_error, early_wait_status);
        }
        fprintf(report,
                "cleanup=%s\nverdict=failed-before-debug-attach\n",
                early_reaped ? "reaped" : "failed");
        (void)fsync(report_descriptor);
        fclose(report);
        close(candidate_descriptor);
        return 79;
    }

    errno = 0;
    int attach_result = ptrace(PT_ATTACHEXC, child, NULL, 0);
    int attach_error = attach_result == 0 ? 0 : errno;
    int attach_status = 0;
    pid_t attach_wait = 0;
    int attach_wait_error = 0;
    bool attach_stopped = attach_result == 0 &&
        bounded_wait(child, WUNTRACED, CODEX_CLEANUP_ATTEMPTS,
                     &attach_status, &attach_wait, &attach_wait_error) &&
        WIFSTOPPED(attach_status);
    fprintf(report,
            "attachResult=%d\nattachErrno=%d\nattachWaitResult=%d\n"
            "attachWaitErrno=%d\nattachWaitStatus=0x%08x\n"
            "attachStopped=%d\nattachStopSignal=%d\n",
            attach_result, attach_error, attach_wait, attach_wait_error,
            attach_status, attach_stopped,
            attach_stopped ? WSTOPSIG(attach_status) : 0);

    char attached_path[CODEX_PATH_SIZE] = {0};
    bool attached_path_exact =
        attach_stopped &&
        candidate_process_path(child, candidate_real_path, attached_path);
    struct codex_proc_uniqidentifierinfo attached_info = {0};
    bool attached_info_ok =
        attach_stopped && copy_unique_info(child, &attached_info);
    uint32_t attached_flags = 0;
    errno = 0;
    int attached_csops = attach_stopped
        ? csops(child, CODEX_CS_OPS_STATUS, &attached_flags,
                sizeof(attached_flags))
        : -1;
    int attached_csops_error = attached_csops == 0 ? 0 : errno;
    uint8_t attached_cdhash[CODEX_CDHASH_SIZE] = {0};
    errno = 0;
    int attached_cdhash_result = attach_stopped
        ? csops(child, CODEX_CS_OPS_CDHASH, attached_cdhash,
                sizeof(attached_cdhash))
        : -1;
    int attached_cdhash_error = attached_cdhash_result == 0 ? 0 : errno;
    char attached_cdhash_text[CODEX_CDHASH_SIZE * 2U + 1U] = {0};
    format_hex(attached_cdhash, sizeof(attached_cdhash),
               attached_cdhash_text, sizeof(attached_cdhash_text));
    char attached_identity[CODEX_IDENTITY_BUFFER_SIZE] = {0};
    int attached_identity_error = attach_stopped
        ? copy_cs_string(child, CODEX_CS_OPS_IDENTITY, attached_identity,
                         sizeof(attached_identity))
        : ESRCH;
    char attached_team[CODEX_IDENTITY_BUFFER_SIZE] = {0};
    int attached_team_error = attach_stopped
        ? copy_cs_string(child, CODEX_CS_OPS_TEAMID, attached_team,
                         sizeof(attached_team))
        : ESRCH;
    fprintf(report,
            "attachedPath=%s\nattachedPathExact=%d\n"
            "attachedUniqueInfo=%d\nattachedPidVersion=%d\n"
            "attachedUUIDExact=%d\nattachedCsops=%d\n"
            "attachedCsopsErrno=%d\nattachedFlags=0x%08x\n"
            "attachedValid=%d\nattachedDebugged=%d\n"
            "attachedHardKill=%d\nattachedCdhashResult=%d\n"
            "attachedCdhashErrno=%d\nattachedCdhash=%s\n"
            "cdhashStable=%d\nattachedIdentityErrno=%d\n"
            "attachedIdentity=%s\nidentityStable=%d\n"
            "attachedTeamErrno=%d\nattachedTeam=%s\n",
            attached_path, attached_path_exact, attached_info_ok,
            attached_info.pid_version,
            attached_info_ok &&
                memcmp(attached_info.uuid, kExpectedSpringBoardUUID,
                       sizeof(kExpectedSpringBoardUUID)) == 0,
            attached_csops, attached_csops_error, attached_flags,
            (attached_flags & CODEX_CS_VALID) != 0,
            (attached_flags & CODEX_CS_DEBUGGED) != 0,
            (attached_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0,
            attached_cdhash_result, attached_cdhash_error,
            attached_cdhash_text,
            preattach_cdhash_result == 0 && attached_cdhash_result == 0 &&
                memcmp(preattach_cdhash, attached_cdhash,
                       sizeof(attached_cdhash)) == 0,
            attached_identity_error, attached_identity,
            preattach_identity_error == 0 && attached_identity_error == 0 &&
                strcmp(preattach_identity, attached_identity) == 0,
            attached_team_error, attached_team);

    audit_token_t audit_token = {{0}};
    mach_port_t child_task = MACH_PORT_NULL;
    kern_return_t task_for_pid_result = attach_stopped
        ? task_for_pid(mach_task_self(), child, &child_task)
        : KERN_INVALID_TASK;
    mach_msg_type_number_t audit_count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t audit_result = task_for_pid_result == KERN_SUCCESS
        ? task_info(child_task, TASK_AUDIT_TOKEN,
                    (task_info_t)&audit_token, &audit_count)
        : KERN_INVALID_TASK;
    bool audit_exact = audit_result == KERN_SUCCESS &&
                       audit_count == TASK_AUDIT_TOKEN_COUNT &&
                       audit_token.val[5] == (uint32_t)child &&
                       attached_info_ok &&
                       audit_token.val[7] ==
                           (uint32_t)attached_info.pid_version;
    fprintf(report,
            "taskForPidResult=%d\nauditTaskInfoResult=%d\n"
            "auditTaskInfoCount=%u\nauditToken=%08x:%08x:%08x:%08x:"
            "%08x:%08x:%08x:%08x\nauditPid=%u\nauditPidVersion=%u\n"
            "auditExact=%d\n",
            task_for_pid_result, audit_result, audit_count,
            audit_token.val[0], audit_token.val[1], audit_token.val[2],
            audit_token.val[3], audit_token.val[4], audit_token.val[5],
            audit_token.val[6], audit_token.val[7], audit_token.val[5],
            audit_token.val[7], audit_exact);
    bool sec_task_policy_exact = audit_result == KERN_SUCCESS &&
        report_sectask(report, audit_token);
    fprintf(report, "secTaskPolicyExact=%d\n", sec_task_policy_exact);
    if (child_task != MACH_PORT_NULL) {
        (void)mach_port_deallocate(mach_task_self(), child_task);
    }

    struct stat candidate_status_after = {0};
    struct stat candidate_path_status_after = {0};
    bool candidate_stable =
        fstat(candidate_descriptor, &candidate_status_after) == 0 &&
        lstat(kCandidatePath, &candidate_path_status_after) == 0 &&
        S_ISREG(candidate_path_status_after.st_mode) &&
        candidate_status_after.st_dev == candidate_status.st_dev &&
        candidate_status_after.st_ino == candidate_status.st_ino &&
        candidate_status_after.st_size == candidate_status.st_size &&
        candidate_path_status_after.st_dev == candidate_status.st_dev &&
        candidate_path_status_after.st_ino == candidate_status.st_ino &&
        candidate_path_status_after.st_size == candidate_status.st_size;
    fprintf(report, "candidateFileStable=%d\n", candidate_stable);

    int ptrace_kill_result = -1;
    int ptrace_kill_error = 0;
    int signal_result = -1;
    int signal_error = 0;
    pid_t cleanup_wait = 0;
    int cleanup_wait_error = 0;
    int cleanup_status = 0;
    bool reaped = terminate_and_reap(
        child, attach_stopped, &ptrace_kill_result, &ptrace_kill_error,
        &signal_result, &signal_error, &cleanup_wait, &cleanup_wait_error,
        &cleanup_status);
    fprintf(report,
            "ptraceKillResult=%d\nptraceKillErrno=%d\n"
            "signalKillResult=%d\nsignalKillErrno=%d\n"
            "cleanupWaitResult=%d\ncleanupWaitErrno=%d\n"
            "cleanupWaitStatus=0x%08x\ncleanup=%s\n",
            ptrace_kill_result, ptrace_kill_error, signal_result,
            signal_error, cleanup_wait, cleanup_wait_error, cleanup_status,
            reaped ? "reaped" : "failed");

    char live_path_after[CODEX_PATH_SIZE] = {0};
    struct codex_proc_uniqidentifierinfo live_info_after = {0};
    bool live_path_after_exact =
        exact_process_path(live_pid, kLiveSpringBoardPath, live_path_after);
    bool live_info_after_ok = copy_unique_info(live_pid, &live_info_after);
    bool live_unchanged =
        live_path_after_exact && live_info_after_ok &&
        live_info_after.unique_id == live_info_before.unique_id &&
        live_info_after.pid_version == live_info_before.pid_version &&
        memcmp(live_info_after.uuid, live_info_before.uuid,
               sizeof(live_info_before.uuid)) == 0;
    fprintf(report,
            "livePathAfter=%s\nlivePathAfterExact=%d\n"
            "liveUniqueInfoAfter=%d\nliveUniqueIdAfter=%llu\n"
            "livePidVersionAfter=%d\nliveUnchanged=%d\n",
            live_path_after, live_path_after_exact, live_info_after_ok,
            (unsigned long long)live_info_after.unique_id,
            live_info_after.pid_version, live_unchanged);

    bool admitted =
        start_suspended && survived_settle && preattach_path_exact &&
        preattach_info_ok && preattach_csops == 0 &&
        (preattach_flags & CODEX_CS_VALID) != 0 &&
        (preattach_flags & CODEX_CS_DEBUGGED) == 0 &&
        preattach_cdhash_result == 0 &&
        memcmp(preattach_cdhash, kExpectedCandidateCDHash,
               sizeof(kExpectedCandidateCDHash)) == 0 &&
        preattach_identity_error == 0 &&
        strcmp(preattach_identity, "com.apple.springboard") == 0 &&
        preattach_validation_result == 0;
    bool gta_debug_ready =
        attach_stopped && attached_path_exact && attached_info_ok &&
        attached_csops == 0 &&
        (attached_flags & (CODEX_CS_VALID | CODEX_CS_DEBUGGED)) ==
            (CODEX_CS_VALID | CODEX_CS_DEBUGGED) &&
        (attached_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0 &&
        attached_cdhash_result == 0 &&
        memcmp(preattach_cdhash, attached_cdhash,
               sizeof(attached_cdhash)) == 0 &&
        attached_identity_error == 0 &&
        strcmp(attached_identity, "com.apple.springboard") == 0;
    bool success = admitted && gta_debug_ready && audit_exact &&
                   sec_task_policy_exact && candidate_stable && reaped &&
                   live_unchanged;
    fprintf(report,
            "admitted=%d\ngtaDebugReady=%d\nzeroUserInstructions=1\n"
            "verdict=%s\n",
            admitted, gta_debug_ready, success ? "success" : "failed");

    bool report_synced = fsync(report_descriptor) == 0;
    fclose(report);
    close(candidate_descriptor);
    return success && report_synced ? 0 : 80;
}
