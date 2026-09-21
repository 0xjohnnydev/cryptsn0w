#include "sileo_root_broker_protocol.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CODEX_TROLLSTORE_HELPER_PAYLOAD \
    "/var/jb/Applications/TrollStoreLite.app/.sbinject-root-helper"
#define CODEX_ROOT_BROKER_SOCKET "/var/mobile/.codex-broker"

static bool write_all(int descriptor, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    while (length != 0) {
        ssize_t amount = write(descriptor, cursor, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return false;
        cursor += amount;
        length -= (size_t)amount;
    }
    return true;
}

static bool read_all(int descriptor, void *bytes, size_t length) {
    uint8_t *cursor = bytes;
    while (length != 0) {
        ssize_t amount = read(descriptor, cursor, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return false;
        cursor += amount;
        length -= (size_t)amount;
    }
    return true;
}

static int decoded_wait_status(int32_t status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return status >= 0 && status <= 255 ? status : 126;
}

int main(int argc, char *argv[]) {
    if (argc <= 1 || argc > (int)CODEX_ROOT_BROKER_MAX_ARGUMENTS) {
        fprintf(stderr, "trollstore-broker-client: invalid arguments\n");
        return 64;
    }
    uint32_t argument_count = (uint32_t)argc;
    size_t payload_length = sizeof(uint32_t) +
        strlen(CODEX_TROLLSTORE_HELPER_PAYLOAD) + 1U;
    for (int index = 1; index < argc; ++index) {
        size_t length = argv[index] != NULL
            ? strnlen(argv[index], PATH_MAX * 4U) : PATH_MAX * 4U;
        if (length == PATH_MAX * 4U ||
            payload_length > CODEX_ROOT_BROKER_MAX_PAYLOAD -
                                 sizeof(uint32_t) - length - 1U) {
            fprintf(stderr,
                    "trollstore-broker-client: oversized argument\n");
            return 65;
        }
        payload_length += sizeof(uint32_t) + length + 1U;
    }
    uint8_t *payload = calloc(payload_length, 1U);
    if (payload == NULL) return 71;
    uint8_t *cursor = payload;
    for (uint32_t index = 0; index < argument_count; ++index) {
        const char *argument = index == 0
            ? CODEX_TROLLSTORE_HELPER_PAYLOAD : argv[index];
        uint32_t length = (uint32_t)strlen(argument) + 1U;
        memcpy(cursor, &length, sizeof(length));
        cursor += sizeof(length);
        memcpy(cursor, argument, length);
        cursor += length;
    }

    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    address.sun_len = sizeof(address);
    strlcpy(address.sun_path, CODEX_ROOT_BROKER_SOCKET,
            sizeof(address.sun_path));
    if (client < 0 ||
        connect(client, (const struct sockaddr *)&address,
                sizeof(address)) != 0) {
        fprintf(stderr, "trollstore-broker-client: connect failed: %s\n",
                strerror(errno));
        free(payload);
        if (client >= 0) close(client);
        return 69;
    }
    struct codex_root_broker_header header = {
        .magic = CODEX_ROOT_BROKER_MAGIC,
        .version = CODEX_ROOT_BROKER_VERSION,
        .argument_count = argument_count,
        .payload_length = (uint32_t)payload_length,
        .descriptor_count = 3,
        .descriptor_numbers = {0, 1, 2},
    };
    int descriptors[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    uint8_t control[CMSG_SPACE(sizeof(descriptors))] = {0};
    struct iovec vector = {
        .iov_base = &header,
        .iov_len = sizeof(header),
    };
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *rights = CMSG_FIRSTHDR(&message);
    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN(sizeof(descriptors));
    memcpy(CMSG_DATA(rights), descriptors, sizeof(descriptors));
    ssize_t sent;
    do {
        sent = sendmsg(client, &message, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)sizeof(header) ||
        !write_all(client, payload, payload_length)) {
        fprintf(stderr, "trollstore-broker-client: send failed: %s\n",
                strerror(errno));
        free(payload);
        close(client);
        return 70;
    }
    free(payload);
    int32_t status = 126 << 8;
    bool replied = read_all(client, &status, sizeof(status));
    close(client);
    if (!replied) {
        fprintf(stderr, "trollstore-broker-client: broker closed request\n");
        return 126;
    }
    return decoded_wait_status(status);
}
