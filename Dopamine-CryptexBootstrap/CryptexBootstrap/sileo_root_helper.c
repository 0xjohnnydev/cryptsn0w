#include "sileo_root_broker_protocol.h"
#include "io_helpers.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);

#define CODEX_PROC_PIDPATH_MAX 4096

static bool expected_parent_path(char *expected, size_t expectedSize) {
    uint32_t helperSize = PATH_MAX;
    char helper[PATH_MAX];
    if (_NSGetExecutablePath(helper, &helperSize) != 0) {
        return false;
    }
    char resolved[PATH_MAX];
    if (realpath(helper, resolved) == NULL) {
        return false;
    }
    char *lastSlash = strrchr(resolved, '/');
    if (lastSlash == NULL || lastSlash == resolved) {
        return false;
    }
    *lastSlash = '\0';
    int length = snprintf(expected, expectedSize, "%s/Sileo", resolved);
    return length >= 0 && (size_t)length < expectedSize;
}

static int connect_to_broker(void) {
    const char *home = getenv("HOME");
    if (home == NULL || home[0] != '/' || strstr(home, "/../") != NULL ||
        strstr(home, "/./") != NULL) {
        errno = EINVAL;
        return -1;
    }
    char socketPath[PATH_MAX];
    int socketPathLength =
        snprintf(socketPath, sizeof(socketPath), "%s/.codex-broker", home);
    if (socketPathLength < 0 ||
        (size_t)socketPathLength >= sizeof(socketPath)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    struct sockaddr_un address = {0};
    if ((size_t)socketPathLength >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int broker = socket(AF_UNIX, SOCK_STREAM, 0);
    if (broker < 0) {
        return -1;
    }
    int noSigpipe = 1;
    (void)setsockopt(broker, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe,
                     sizeof(noSigpipe));
    address.sun_family = AF_UNIX;
    address.sun_len = sizeof(address);
    strlcpy(address.sun_path, socketPath, sizeof(address.sun_path));
    if (connect(broker, (const struct sockaddr *)&address, sizeof(address)) !=
        0) {
        int savedError = errno;
        close(broker);
        errno = savedError;
        return -1;
    }
    return broker;
}

static int relay_command(char *const arguments[], uint32_t argumentCount) {
    if (argumentCount == 0 ||
        argumentCount > CODEX_ROOT_BROKER_MAX_ARGUMENTS) {
        errno = E2BIG;
        return -1;
    }

    size_t payloadLength = 0;
    for (uint32_t index = 0; index < argumentCount; ++index) {
        size_t argumentLength = strnlen(arguments[index], PATH_MAX * 4U);
        if (argumentLength == PATH_MAX * 4U ||
            argumentLength > UINT32_MAX - 1U ||
            payloadLength > CODEX_ROOT_BROKER_MAX_PAYLOAD -
                                sizeof(uint32_t) - argumentLength - 1U) {
            errno = E2BIG;
            return -1;
        }
        payloadLength += sizeof(uint32_t) + argumentLength + 1U;
    }

    struct codex_root_broker_header header = {
        .magic = CODEX_ROOT_BROKER_MAGIC,
        .version = CODEX_ROOT_BROKER_VERSION,
        .argument_count = argumentCount,
        .payload_length = (uint32_t)payloadLength,
    };
    static const int candidateDescriptors[] = {0, 1, 2, 3, 5, 6};
    int descriptors[CODEX_ROOT_BROKER_MAX_FDS];
    for (size_t index = 0;
         index < sizeof(candidateDescriptors) / sizeof(candidateDescriptors[0]);
         ++index) {
        int number = candidateDescriptors[index];
        if (fcntl(number, F_GETFD) < 0) {
            continue;
        }
        uint32_t outputIndex = header.descriptor_count++;
        header.descriptor_numbers[outputIndex] = number;
        descriptors[outputIndex] = number;
    }
    if (header.descriptor_count == 0) {
        errno = EBADF;
        return -1;
    }

    size_t requestLength = sizeof(header) + payloadLength;
    unsigned char *request = calloc(1, requestLength);
    if (request == NULL) {
        return -1;
    }
    memcpy(request, &header, sizeof(header));
    unsigned char *cursor = request + sizeof(header);
    for (uint32_t index = 0; index < argumentCount; ++index) {
        uint32_t length = (uint32_t)strlen(arguments[index]) + 1U;
        memcpy(cursor, &length, sizeof(length));
        cursor += sizeof(length);
        memcpy(cursor, arguments[index], length);
        cursor += length;
    }

    int broker = connect_to_broker();
    if (broker < 0) {
        free(request);
        return -1;
    }
    unsigned char control[CMSG_SPACE(sizeof(descriptors))] = {0};
    struct iovec vector = {.iov_base = request, .iov_len = requestLength};
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = CMSG_SPACE(header.descriptor_count * sizeof(int)),
    };
    struct cmsghdr *controlHeader = CMSG_FIRSTHDR(&message);
    controlHeader->cmsg_level = SOL_SOCKET;
    controlHeader->cmsg_type = SCM_RIGHTS;
    controlHeader->cmsg_len =
        CMSG_LEN(header.descriptor_count * sizeof(int));
    memcpy(CMSG_DATA(controlHeader), descriptors,
           header.descriptor_count * sizeof(int));
    ssize_t sent;
    do {
        sent = sendmsg(broker, &message, 0);
    } while (sent < 0 && errno == EINTR);
    bool sentRequest = sent > 0 && (size_t)sent <= requestLength &&
                       write_all(broker, request + sent,
                                 requestLength - (size_t)sent);
    free(request);
    if (!sentRequest) {
        int savedError = sent < 0 ? errno : EIO;
        close(broker);
        errno = savedError;
        return -1;
    }

    int32_t status = 0;
    bool receivedStatus = read_all(broker, &status, sizeof(status));
    close(broker);
    if (!receivedStatus) {
        errno = EIO;
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 125;
}

int main(int argc, char *argv[]) {
    char expectedParent[PATH_MAX];
    char actualParent[CODEX_PROC_PIDPATH_MAX];
    if (!expected_parent_path(expectedParent, sizeof(expectedParent))) {
        fputs("Error: failed to resolve sibling Sileo path\n", stderr);
        return 72;
    }
    if (proc_pidpath(getppid(), actualParent, sizeof(actualParent)) <= 0) {
        fputs("Error: failed to retrieve parent process path\n", stderr);
        return 72;
    }
    if (strcmp(expectedParent, actualParent) != 0) {
        fputs("Error: permission denied, parent process is not sibling Sileo\n",
              stderr);
        return 77;
    }

    char *preflightArguments[] = {"/var/jb/usr/bin/whoami", NULL};
    char *const *commandArguments = NULL;
    uint32_t commandArgumentCount = 0;
    if (argc == 2 && strcmp(argv[1], "whoami") == 0) {
        commandArguments = preflightArguments;
        commandArgumentCount = 1;
    } else if (argc >= 2) {
        commandArguments = &argv[1];
        commandArgumentCount = (uint32_t)(argc - 1);
    } else {
        fputs("Error: missing broker command\n", stderr);
        return 64;
    }

    int result = relay_command(commandArguments, commandArgumentCount);
    if (result < 0) {
        fprintf(stderr, "Error: root broker request failed: %s\n",
                strerror(errno));
        return 71;
    }
    return result;
}
