#ifndef CODEX_JIT_PROTOCOL_H
#define CODEX_JIT_PROTOCOL_H

#include <stdint.h>

#define CODEX_JIT_MAGIC 0x434A4954U
#define CODEX_JIT_VERSION 1U
#define CODEX_JIT_SOCKET_PATH "/var/jb/var/lib/codex-jit/broker.sock"

struct codex_jit_request {
    uint32_t magic;
    uint32_t version;
    int32_t pid;
};

#endif
