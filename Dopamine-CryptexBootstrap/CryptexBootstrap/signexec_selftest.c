#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || argv[1] == NULL || argv[1][0] != '/') {
        dprintf(STDERR_FILENO, "usage: signexec-selftest /absolute/marker\n");
        return 64;
    }

    int descriptor = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          0644);
    if (descriptor < 0) {
        dprintf(STDERR_FILENO, "signexec-selftest open failed: %s\n",
                strerror(errno));
        return 1;
    }
    int result = dprintf(descriptor,
                         "SIGNEXEC_SELFTEST pid=%d uid=%u gid=%u\n",
                         getpid(), getuid(), getgid());
    int savedError = errno;
    if (result >= 0 && fsync(descriptor) != 0) {
        result = -1;
        savedError = errno;
    }
    if (close(descriptor) != 0 && result >= 0) {
        result = -1;
        savedError = errno;
    }
    if (result < 0) {
        dprintf(STDERR_FILENO, "signexec-selftest write failed: %s\n",
                strerror(savedError));
        return 1;
    }
    return 0;
}
