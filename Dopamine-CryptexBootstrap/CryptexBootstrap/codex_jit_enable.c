#include "codex_jit_protocol.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);

#define CODEX_PROC_PIDPATH_MAX 4096

static bool write_all(int descriptor, const void *bytes, size_t length) {
    const unsigned char *cursor = bytes;
    while (length > 0) {
        ssize_t written = write(descriptor, cursor, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        cursor += written;
        length -= (size_t)written;
    }
    return true;
}

static bool read_all(int descriptor, void *bytes, size_t length) {
    unsigned char *cursor = bytes;
    while (length > 0) {
        ssize_t received = read(descriptor, cursor, length);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return false;
        }
        cursor += received;
        length -= (size_t)received;
    }
    return true;
}

/*
 * Native JIT request for the LiveContainer host: only the caller's own parent
 * process may be targeted, and the parent must be the fixed host app, so a
 * compromised mobile process cannot ask the root broker to debug arbitrary
 * processes.  The root broker independently revalidates the target path and
 * the peer identity before running the attach.
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fputs("usage: codex-jit-enable <parent-pid>\n", stderr);
        return 64;
    }
    char *end = NULL;
    long parsed = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || parsed <= 1 ||
        parsed > (long)INT32_MAX) {
        fputs("codex-jit-enable: invalid pid\n", stderr);
        return 64;
    }
    pid_t target = (pid_t)parsed;
    if (target != getppid()) {
        fputs("codex-jit-enable: pid is not the parent process\n", stderr);
        return 77;
    }
    char parentPath[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(target, parentPath, sizeof(parentPath)) <= 0 ||
        strstr(parentPath, "/LiveContainer.app/") == NULL) {
        fputs("codex-jit-enable: parent is not the LiveContainer host\n",
              stderr);
        return 77;
    }

    int broker = socket(AF_UNIX, SOCK_STREAM, 0);
    if (broker < 0) {
        fprintf(stderr, "codex-jit-enable: socket failed: %s\n",
                strerror(errno));
        return 71;
    }
    struct sockaddr_un address = {0};
    const char *path = CODEX_JIT_SOCKET_PATH;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(broker);
        return 71;
    }
    int noSigpipe = 1;
    (void)setsockopt(broker, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe,
                     sizeof(noSigpipe));
    address.sun_family = AF_UNIX;
    address.sun_len = sizeof(address);
    strlcpy(address.sun_path, path, sizeof(address.sun_path));
    if (connect(broker, (const struct sockaddr *)&address,
                sizeof(address)) != 0) {
        int savedError = errno;
        close(broker);
        fprintf(stderr, "codex-jit-enable: broker connect failed: %s\n",
                strerror(savedError));
        return 71;
    }

    struct codex_jit_request request = {
        .magic = CODEX_JIT_MAGIC,
        .version = CODEX_JIT_VERSION,
        .pid = target,
    };
    int32_t status = 0;
    if (!write_all(broker, &request, sizeof(request)) ||
        !read_all(broker, &status, sizeof(status))) {
        close(broker);
        fputs("codex-jit-enable: broker reply failed\n", stderr);
        return 71;
    }
    close(broker);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 125;
}
