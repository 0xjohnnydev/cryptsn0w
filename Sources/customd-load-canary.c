#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef CUSTOMD_LOAD_CANARY_NONCE
#define CUSTOMD_LOAD_CANARY_NONCE "unset"
#endif

static const char *const kMarkerPath =
    "/var/jb/var/run/customd-load-canary.marker";

__attribute__((constructor)) static void customd_load_canary(void) {
    int descriptor = open(kMarkerPath,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return;
    }
    struct stat status = {0};
    bool valid = fstat(descriptor, &status) == 0 &&
                 S_ISREG(status.st_mode) && status.st_uid == 0 &&
                 status.st_nlink == 1 && fchmod(descriptor, 0600) == 0;
    if (valid) {
        (void)dprintf(descriptor,
                      "marker=customd-load-canary-v1\n"
                      "nonce=%s\n"
                      "pid=%d\nppid=%d\nuid=%u\neuid=%u\n",
                      CUSTOMD_LOAD_CANARY_NONCE, getpid(), getppid(),
                      getuid(), geteuid());
        (void)fsync(descriptor);
    }
    (void)close(descriptor);
}
