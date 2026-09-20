#ifndef CODEX_SILEO_ROOT_BROKER_PROTOCOL_H
#define CODEX_SILEO_ROOT_BROKER_PROTOCOL_H

#include <stdint.h>

#define CODEX_ROOT_BROKER_MAGIC 0x43445242U
#define CODEX_ROOT_BROKER_VERSION 1U
#define CODEX_ROOT_BROKER_MAX_ARGUMENTS 256U
#define CODEX_ROOT_BROKER_MAX_PAYLOAD (64U * 1024U)
#define CODEX_ROOT_BROKER_MAX_FDS 6U
#define CODEX_ROOT_BROKER_MAX_ENVIRONMENT 2U
#define CODEX_ROOT_BROKER_MACH_SERVICE                                      \
    "com.openai.codex.dopamine.sileo-root-broker"

struct codex_root_broker_header {
    uint32_t magic;
    uint32_t version;
    uint32_t argument_count;
    uint32_t payload_length;
    uint32_t descriptor_count;
    int32_t descriptor_numbers[CODEX_ROOT_BROKER_MAX_FDS];
};

#endif
