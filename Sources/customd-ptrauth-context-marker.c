#include "customd-ptrauth-context-probe.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_PROC_PIDUNIQIDENTIFIERINFO 17

extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);

struct codex_proc_unique_info {
    uint8_t uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_pid_version;
    uint64_t reserved2;
    uint64_t reserved3;
};

_Static_assert(sizeof(struct codex_proc_unique_info) == 56,
               "proc unique-info ABI changed");

static bool parse_int32(const char *text, int32_t minimum, int32_t maximum,
                        int32_t *value_out) {
    if (text == NULL || *text == '\0' || value_out == NULL) {
        return false;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < minimum ||
        value > maximum) {
        return false;
    }
    *value_out = (int32_t)value;
    return true;
}

static bool parse_uint64(const char *text, uint64_t *value_out) {
    if (text == NULL || *text == '\0' || value_out == NULL || *text == '-') {
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

static bool write_all(int descriptor, const void *bytes, size_t size) {
    const uint8_t *cursor = bytes;
    while (size != 0U) {
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

static bool exact_process_path(pid_t pid, const char *expected) {
    char path[PATH_MAX] = {0};
    return pid > 1 && proc_pidpath(pid, path, sizeof(path)) > 0 &&
           strcmp(path, expected) == 0;
}

static bool same_file_path(const char *left, const char *right) {
    struct stat left_status = {0};
    struct stat right_status = {0};
    return left != NULL && right != NULL && stat(left, &left_status) == 0 &&
           stat(right, &right_status) == 0 &&
           S_ISREG(left_status.st_mode) && S_ISREG(right_status.st_mode) &&
           left_status.st_dev == right_status.st_dev &&
           left_status.st_ino == right_status.st_ino;
}

__attribute__((constructor)) static void report_ptrauth_context(void) {
    struct customd_ptrauth_probe_report report = {
        .magic = CODEX_PTRAUTH_PROBE_REPORT_MAGIC,
        .version = CODEX_PTRAUTH_PROBE_REPORT_VERSION,
        .size = sizeof(report),
        .self_pid = getpid(),
        .parent_pid = getppid(),
        .real_uid = getuid(),
        .effective_uid = geteuid(),
        .csops_result = -1,
        .csops_error = EINVAL,
        .task_for_pid_result = KERN_INVALID_ARGUMENT,
        .task_info_result = KERN_INVALID_ARGUMENT,
        .task_audit_pid = -1,
        .task_audit_pid_version = -1,
    };

    int32_t report_fd = -1;
    int32_t expected_parent = -1;
    int32_t donor_pid = -1;
    int32_t expected_pid_version = -1;
    uint64_t expected_unique_id = 0;
    bool environment_exact =
        parse_int32(getenv(CODEX_PTRAUTH_PROBE_ENV_REPORT_FD),
                    CODEX_PTRAUTH_PROBE_REPORT_FD,
                    CODEX_PTRAUTH_PROBE_REPORT_FD, &report_fd) &&
        parse_int32(getenv(CODEX_PTRAUTH_PROBE_ENV_PARENT_PID), 2, INT_MAX,
                    &expected_parent) &&
        parse_int32(getenv(CODEX_PTRAUTH_PROBE_ENV_DONOR_PID), 2, INT_MAX,
                    &donor_pid) &&
        parse_uint64(getenv(CODEX_PTRAUTH_PROBE_ENV_DONOR_UNIQUE_ID),
                     &expected_unique_id) &&
        parse_int32(getenv(CODEX_PTRAUTH_PROBE_ENV_DONOR_PID_VERSION), 0,
                    INT_MAX, &expected_pid_version);
    report.donor_pid = donor_pid;
    report.donor_pid_version = expected_pid_version;
    report.donor_unique_id = expected_unique_id;

    struct stat pipe_status = {0};
    if (environment_exact && fstat(report_fd, &pipe_status) == 0 &&
        S_ISFIFO(pipe_status.st_mode)) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_ENVIRONMENT;
    } else {
        return;
    }

    char self_path[PATH_MAX] = {0};
    if (proc_pidpath(report.self_pid, self_path, sizeof(self_path)) > 0 &&
        same_file_path(self_path, CODEX_PTRAUTH_PROBE_LOADER_PATH)) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_SELF_PATH;
    }
    Dl_info image = {0};
    if (dladdr((const void *)&report_ptrauth_context, &image) != 0 &&
        same_file_path(image.dli_fname, CODEX_PTRAUTH_PROBE_MARKER_PATH)) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_MARKER_IMAGE;
    }
    if (report.parent_pid == expected_parent && expected_parent > 1) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_PARENT;
    }
    if (exact_process_path(donor_pid, CODEX_PTRAUTH_PROBE_CRYPTEXD_PATH)) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_DONOR_PATH;
    }

    struct codex_proc_unique_info donor_unique = {0};
    int unique_size = proc_pidinfo(donor_pid,
                                   CODEX_PROC_PIDUNIQIDENTIFIERINFO, 0,
                                   &donor_unique, sizeof(donor_unique));
    if (unique_size == (int)sizeof(donor_unique) &&
        donor_unique.unique_id == expected_unique_id &&
        donor_unique.pid_version == expected_pid_version) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_DONOR_IDENTITY;
    }

    errno = 0;
    report.csops_result = csops(report.self_pid, CODEX_CS_OPS_STATUS,
                                &report.csflags, sizeof(report.csflags));
    report.csops_error = report.csops_result == 0 ? 0 : errno;
    if (report.csops_result == 0) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_CSOPS;
    }

    task_t donor_task = MACH_PORT_NULL;
    report.task_for_pid_result =
        task_for_pid(mach_task_self(), donor_pid, &donor_task);
    if (report.task_for_pid_result == KERN_SUCCESS &&
        MACH_PORT_VALID(donor_task)) {
        report.flags |= CODEX_PTRAUTH_PROBE_FLAG_TASK_PORT;
        audit_token_t token = {0};
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        report.task_info_result = task_info(
            donor_task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
        if (report.task_info_result == KERN_SUCCESS &&
            count == TASK_AUDIT_TOKEN_COUNT) {
            report.task_audit_pid = (int32_t)token.val[5];
            report.task_audit_pid_version = (int32_t)token.val[7];
            if (report.task_audit_pid == donor_pid &&
                report.task_audit_pid_version == expected_pid_version) {
                report.flags |= CODEX_PTRAUTH_PROBE_FLAG_TASK_AUDIT;
            }
        }
        (void)mach_port_deallocate(mach_task_self(), donor_task);
    }

    (void)write_all(report_fd, &report, sizeof(report));
    (void)close(report_fd);
}
