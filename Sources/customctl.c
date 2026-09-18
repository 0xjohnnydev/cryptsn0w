#include "customd_protocol.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static bool read_all(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = read(descriptor, cursor, size);
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

static bool write_all(int descriptor, const void *buffer, size_t size) {
    const uint8_t *cursor = buffer;
    while (size != 0) {
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

static bool parse_pid(const char *text, pid_t *pid_out) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT_MAX) {
        return false;
    }
    *pid_out = (pid_t)value;
    return true;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s status|jit PID|inject PID DYLIB|"
            "inject-springboard DYLIB|load DYLIB|activate|"
            "ensure-candidate|trace-reexec-probe|setexec-reexec-probe|"
            "reexec-inject-springboard DYLIB|"
            "run MACHO [ARG ...]\n",
            program);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 64;
    }
    struct customd_request request = {
        .magic = CUSTOMD_PROTOCOL_MAGIC,
        .version = CUSTOMD_PROTOCOL_VERSION,
        .request_id = ((uint64_t)time(NULL) << 32U) ^ (uint32_t)getpid(),
    };
    char **arguments = NULL;
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        request.operation = CUSTOMD_OPERATION_STATUS;
    } else if (argc == 3 && strcmp(argv[1], "jit") == 0 &&
               parse_pid(argv[2], &request.target_pid)) {
        request.operation = CUSTOMD_OPERATION_JIT;
    } else if (argc == 4 && strcmp(argv[1], "inject") == 0 &&
               parse_pid(argv[2], &request.target_pid)) {
        request.operation = CUSTOMD_OPERATION_INJECT;
        request.argument_count = 1;
        arguments = argv + 3;
    } else if (argc == 3 &&
               strcmp(argv[1], "inject-springboard") == 0) {
        request.operation = CUSTOMD_OPERATION_INJECT_SPRINGBOARD;
        request.argument_count = 1;
        arguments = argv + 2;
    } else if (argc == 3 && strcmp(argv[1], "load") == 0) {
        request.operation = CUSTOMD_OPERATION_LOAD;
        request.argument_count = 1;
        arguments = argv + 2;
    } else if (argc == 2 && strcmp(argv[1], "activate") == 0) {
        request.operation = CUSTOMD_OPERATION_ACTIVATE_SPRINGBOARD;
    } else if (argc == 2 && strcmp(argv[1], "ensure-candidate") == 0) {
        request.operation = CUSTOMD_OPERATION_ENSURE_CANDIDATE;
    } else if (argc == 2 && strcmp(argv[1], "trace-reexec-probe") == 0) {
        request.operation = CUSTOMD_OPERATION_TRACE_REEXEC_PROBE;
    } else if (argc == 2 && strcmp(argv[1], "setexec-reexec-probe") == 0) {
        request.operation = CUSTOMD_OPERATION_SETEXEC_REEXEC_PROBE;
    } else if (argc == 3 &&
               strcmp(argv[1], "reexec-inject-springboard") == 0) {
        request.operation = CUSTOMD_OPERATION_REEXEC_INJECT_SPRINGBOARD;
        request.argument_count = 1;
        arguments = argv + 2;
    } else if (argc >= 3 && strcmp(argv[1], "run") == 0 &&
               argc - 2 <= (int)CUSTOMD_MAX_ARGUMENTS) {
        request.operation = CUSTOMD_OPERATION_RUN;
        request.argument_count = (uint32_t)(argc - 2);
        arguments = argv + 2;
    } else {
        usage(argv[0]);
        return 64;
    }

    for (uint32_t index = 0; index < request.argument_count; ++index) {
        size_t length = strlen(arguments[index]) + 1U;
        if (length > CUSTOMD_MAX_PAYLOAD - request.payload_size) {
            fprintf(stderr, "customctl: request is too large\n");
            return 64;
        }
        request.payload_size += (uint32_t)length;
    }
    uint8_t *payload = request.payload_size != 0
                           ? malloc(request.payload_size)
                           : NULL;
    if (request.payload_size != 0 && payload == NULL) {
        perror("customctl: malloc");
        return 71;
    }
    size_t offset = 0;
    for (uint32_t index = 0; index < request.argument_count; ++index) {
        size_t length = strlen(arguments[index]) + 1U;
        memcpy(payload + offset, arguments[index], length);
        offset += length;
    }

    int descriptor = -1;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                   CUSTOMD_SOCKET_PATH);
    int connect_error = 0;
    for (unsigned int attempt = 0; attempt < 160U; ++attempt) {
        descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        if (descriptor < 0) {
            connect_error = errno;
            break;
        }
        if (connect(descriptor, (struct sockaddr *)&address,
                    sizeof(address)) == 0) {
            connect_error = 0;
            break;
        }
        connect_error = errno;
        close(descriptor);
        descriptor = -1;
        if (connect_error != ENOENT && connect_error != ECONNREFUSED) {
            break;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        (void)nanosleep(&delay, NULL);
    }
    if (descriptor < 0) {
        errno = connect_error;
        perror("customctl: connect");
        free(payload);
        return 71;
    }
    bool sent = write_all(descriptor, &request, sizeof(request)) &&
                (request.payload_size == 0 ||
                 write_all(descriptor, payload, request.payload_size));
    free(payload);
    if (!sent) {
        perror("customctl: write");
        close(descriptor);
        return 71;
    }

    struct customd_response response = {0};
    if (!read_all(descriptor, &response, sizeof(response)) ||
        response.magic != CUSTOMD_PROTOCOL_MAGIC ||
        response.version != CUSTOMD_PROTOCOL_VERSION ||
        response.operation != request.operation ||
        response.request_id != request.request_id ||
        response.message_size >= CUSTOMD_MAX_MESSAGE) {
        fprintf(stderr, "customctl: invalid response\n");
        close(descriptor);
        return 71;
    }
    char message[CUSTOMD_MAX_MESSAGE] = {0};
    if (response.message_size != 0 &&
        !read_all(descriptor, message, response.message_size)) {
        fprintf(stderr, "customctl: truncated response\n");
        close(descriptor);
        return 71;
    }
    close(descriptor);
    FILE *stream = response.status == CUSTOMD_STATUS_OK ? stdout : stderr;
    fprintf(stream,
            "customd: status=%d errno=%d daemon=%llu child=%d "
            "csflags=0x%08x->0x%08x %s\n",
            response.status, response.system_error, response.daemon_pid,
            response.child_pid, response.csflags_before,
            response.csflags_after, message);
    return response.status >= 0 && response.status <= 125
               ? response.status
               : 71;
}
