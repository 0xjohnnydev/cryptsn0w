#ifndef CODEX_CUSTOMD_PROTOCOL_H
#define CODEX_CUSTOMD_PROTOCOL_H

#include <stdint.h>

#define CUSTOMD_PROTOCOL_MAGIC 0x43555354U
#define CUSTOMD_PROTOCOL_VERSION 2U

#define CUSTOMD_SOCKET_PATH "/var/jb/var/run/customd.sock"
#define CUSTOMD_MAX_PAYLOAD (64U * 1024U)
#define CUSTOMD_MAX_ARGUMENTS 32U
#define CUSTOMD_MAX_MESSAGE 1024U

enum customd_operation {
    CUSTOMD_OPERATION_STATUS = 1,
    CUSTOMD_OPERATION_JIT = 2,
    CUSTOMD_OPERATION_INJECT = 3,
    CUSTOMD_OPERATION_RUN = 4,
    CUSTOMD_OPERATION_LOAD = 5,
    CUSTOMD_OPERATION_ACTIVATE_SPRINGBOARD = 6,
    CUSTOMD_OPERATION_INJECT_SPRINGBOARD = 7,
    CUSTOMD_OPERATION_ENSURE_CANDIDATE = 8,
    CUSTOMD_OPERATION_TRACE_REEXEC_PROBE = 9,
    CUSTOMD_OPERATION_SETEXEC_REEXEC_PROBE = 10,
    CUSTOMD_OPERATION_REEXEC_INJECT_SPRINGBOARD = 11,
};

enum customd_status {
    CUSTOMD_STATUS_OK = 0,
    CUSTOMD_STATUS_BAD_REQUEST = 64,
    CUSTOMD_STATUS_BAD_PATH = 65,
    CUSTOMD_STATUS_NO_PROCESS = 66,
    CUSTOMD_STATUS_JIT_DENIED = 67,
    CUSTOMD_STATUS_CHILD_FAILED = 68,
    CUSTOMD_STATUS_IDENTITY_CHANGED = 69,
    CUSTOMD_STATUS_TIMEOUT = 70,
    CUSTOMD_STATUS_INTERNAL = 71,
    CUSTOMD_STATUS_CONFLICT = 73,
    CUSTOMD_STATUS_UNAUTHORIZED = 77,
};

struct customd_request {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint64_t request_id;
    uint32_t payload_size;
    int32_t target_pid;
    uint32_t argument_count;
    uint32_t reserved;
};

struct customd_response {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint64_t request_id;
    int32_t status;
    int32_t system_error;
    uint32_t csflags_before;
    uint32_t csflags_after;
    int32_t child_pid;
    uint32_t message_size;
    uint64_t daemon_pid;
};

_Static_assert(sizeof(struct customd_request) == 32,
               "customd request ABI changed");
_Static_assert(sizeof(struct customd_response) == 48,
               "customd response ABI changed");

#endif
