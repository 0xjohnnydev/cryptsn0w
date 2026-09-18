#ifndef CUSTOMD_PTRAUTH_CONTEXT_PROBE_H
#define CUSTOMD_PTRAUTH_CONTEXT_PROBE_H

#include <stdint.h>

#define CODEX_PTRAUTH_PROBE_LOADER_PATH \
    "/var/jb/usr/libexec/codex-ellekit-loader"
#define CODEX_PTRAUTH_PROBE_MARKER_PATH \
    "/var/jb/usr/lib/customd-ptrauth-context-marker.dylib"
#define CODEX_PTRAUTH_PROBE_CRYPTEXD_PATH "/usr/libexec/cryptexd"
#define CODEX_PTRAUTH_PROBE_SPRINGBOARD_PATH \
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard"

#define CODEX_PTRAUTH_PROBE_REPORT_FD 198
#define CODEX_PTRAUTH_PROBE_REPORT_MAGIC UINT32_C(0x43505458)
#define CODEX_PTRAUTH_PROBE_REPORT_VERSION UINT32_C(1)

#define CODEX_PTRAUTH_PROBE_ENV_REPORT_FD \
    "CODEX_PTRAUTH_PROBE_REPORT_FD"
#define CODEX_PTRAUTH_PROBE_ENV_PARENT_PID \
    "CODEX_PTRAUTH_PROBE_PARENT_PID"
#define CODEX_PTRAUTH_PROBE_ENV_DONOR_PID \
    "CODEX_PTRAUTH_PROBE_DONOR_PID"
#define CODEX_PTRAUTH_PROBE_ENV_DONOR_UNIQUE_ID \
    "CODEX_PTRAUTH_PROBE_DONOR_UNIQUE_ID"
#define CODEX_PTRAUTH_PROBE_ENV_DONOR_PID_VERSION \
    "CODEX_PTRAUTH_PROBE_DONOR_PID_VERSION"

enum customd_ptrauth_probe_flags {
    CODEX_PTRAUTH_PROBE_FLAG_ENVIRONMENT = 1U << 0,
    CODEX_PTRAUTH_PROBE_FLAG_SELF_PATH = 1U << 1,
    CODEX_PTRAUTH_PROBE_FLAG_MARKER_IMAGE = 1U << 2,
    CODEX_PTRAUTH_PROBE_FLAG_PARENT = 1U << 3,
    CODEX_PTRAUTH_PROBE_FLAG_DONOR_PATH = 1U << 4,
    CODEX_PTRAUTH_PROBE_FLAG_DONOR_IDENTITY = 1U << 5,
    CODEX_PTRAUTH_PROBE_FLAG_CSOPS = 1U << 6,
    CODEX_PTRAUTH_PROBE_FLAG_TASK_PORT = 1U << 7,
    CODEX_PTRAUTH_PROBE_FLAG_TASK_AUDIT = 1U << 8,
};

#define CODEX_PTRAUTH_PROBE_REQUIRED_FLAGS                               \
    (CODEX_PTRAUTH_PROBE_FLAG_ENVIRONMENT |                             \
     CODEX_PTRAUTH_PROBE_FLAG_SELF_PATH |                               \
     CODEX_PTRAUTH_PROBE_FLAG_MARKER_IMAGE |                            \
     CODEX_PTRAUTH_PROBE_FLAG_PARENT |                                  \
     CODEX_PTRAUTH_PROBE_FLAG_DONOR_PATH |                              \
     CODEX_PTRAUTH_PROBE_FLAG_DONOR_IDENTITY |                          \
     CODEX_PTRAUTH_PROBE_FLAG_CSOPS |                                   \
     CODEX_PTRAUTH_PROBE_FLAG_TASK_PORT |                               \
     CODEX_PTRAUTH_PROBE_FLAG_TASK_AUDIT)

struct customd_ptrauth_probe_report {
    uint32_t magic;
    uint32_t version;
    uint32_t size;
    uint32_t flags;
    int32_t self_pid;
    int32_t parent_pid;
    int32_t donor_pid;
    int32_t donor_pid_version;
    uint64_t donor_unique_id;
    uint32_t real_uid;
    uint32_t effective_uid;
    uint32_t csflags;
    int32_t csops_result;
    int32_t csops_error;
    int32_t task_for_pid_result;
    int32_t task_info_result;
    int32_t task_audit_pid;
    int32_t task_audit_pid_version;
    uint32_t reserved[5];
};

_Static_assert(sizeof(struct customd_ptrauth_probe_report) == 96,
               "ptrauth probe wire ABI changed");

#endif
