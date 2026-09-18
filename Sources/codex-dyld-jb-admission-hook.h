#ifndef CODEX_DYLD_JB_ADMISSION_HOOK_H
#define CODEX_DYLD_JB_ADMISSION_HOOK_H

#include <stddef.h>
#include <stdint.h>

#define CODEX_DYLD_JB_HOOK_ABI_VERSION 1U

enum codex_dyld_jb_hook_state {
    CODEX_DYLD_JB_HOOK_UNINITIALIZED = 0,
    CODEX_DYLD_JB_HOOK_INSTALLING = 1,
    CODEX_DYLD_JB_HOOK_INSTALLED = 2,
    CODEX_DYLD_JB_HOOK_RESTORING = 3,
    CODEX_DYLD_JB_HOOK_RESTORED = 4,
    CODEX_DYLD_JB_HOOK_FAILED = 5,
    CODEX_DYLD_JB_HOOK_PARTIAL = 6,
};

enum codex_dyld_jb_hook_error {
    CODEX_DYLD_JB_HOOK_ERROR_NONE = 0,
    CODEX_DYLD_JB_HOOK_ERROR_BUSY = 1,
    CODEX_DYLD_JB_HOOK_ERROR_CSOPS = 2,
    CODEX_DYLD_JB_HOOK_ERROR_HOST_POLICY = 3,
    CODEX_DYLD_JB_HOOK_ERROR_SELF_PATH = 4,
    CODEX_DYLD_JB_HOOK_ERROR_DYLD_INFO = 5,
    CODEX_DYLD_JB_HOOK_ERROR_DYLD_MACHO = 6,
    CODEX_DYLD_JB_HOOK_ERROR_MMAP_PATTERN = 7,
    CODEX_DYLD_JB_HOOK_ERROR_FCNTL_PATTERN = 8,
    CODEX_DYLD_JB_HOOK_ERROR_MMAP_PATCH = 9,
    CODEX_DYLD_JB_HOOK_ERROR_FCNTL_PATCH = 10,
    CODEX_DYLD_JB_HOOK_ERROR_ROLLBACK = 11,
    CODEX_DYLD_JB_HOOK_ERROR_RESTORE = 12,
    CODEX_DYLD_JB_HOOK_ERROR_DYLD_UUID = 13,
    CODEX_DYLD_JB_HOOK_ERROR_MMAP_PREFIX = 14,
    CODEX_DYLD_JB_HOOK_ERROR_FCNTL_PREFIX = 15,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_ID = 16,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_ENUMERATION = 17,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_CAPACITY = 18,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_SUSPEND = 19,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_STATE = 20,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_IN_PATCH_PAGE = 21,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_UNSTABLE = 22,
    CODEX_DYLD_JB_HOOK_ERROR_THREAD_RESUME = 23,
};

struct codex_dyld_jb_hook_status_v1 {
    uint32_t size;
    uint32_t version;
    uint32_t state;
    uint32_t error;
    int32_t pid;
    uint32_t cs_flags;
    uint32_t mmap_pattern_count;
    uint32_t fcntl_pattern_count;
    uint64_t dyld_header;
    uint64_t mmap_stub;
    uint64_t fcntl_stub;
    uint8_t dyld_uuid[16];
    uint8_t expected_dyld_uuid[16];
    uint8_t expected_dyld_sha256[32];
    uint8_t expected_mmap_prefix[20];
    uint8_t observed_mmap_prefix[20];
    uint8_t expected_fcntl_prefix[20];
    uint8_t observed_fcntl_prefix[20];
    uint64_t anonymous_rx_mappings;
    uint64_t signature_bypasses;
    uint64_t policy_rejections;
    uint32_t quiesce_attempts;
    uint32_t quiesce_passes;
    uint32_t threads_observed;
    uint32_t threads_suspended;
    uint32_t threads_resumed;
    int32_t quiesce_kern_return;
    int32_t resume_kern_return;
    uint32_t quiesce_reserved;
    uint64_t unsafe_thread_id;
    uint64_t unsafe_thread_pc;
    int32_t marker_errno;
    uint32_t reserved;
};

#ifdef __cplusplus
extern "C" {
#endif

extern const char codex_dyld_jb_hook_marker[];

int codex_dyld_jb_hook_install(void);
int codex_dyld_jb_hook_restore(void);
int codex_dyld_jb_hook_copy_status(
    struct codex_dyld_jb_hook_status_v1 *status, size_t status_size);
uint64_t codex_dyld_jb_hook_status_word(void);

#ifdef __cplusplus
}
#endif

#endif
