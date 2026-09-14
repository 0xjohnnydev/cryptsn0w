#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void codex_launchd_injection_canary(void) {
    static const char marker[] =
        "codex launchd injection canary: constructor reached\n";
    int descriptor = open("/var/tmp/codex-launchd-injection-canary",
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return;
    }
    size_t remaining = sizeof(marker) - 1;
    const char *cursor = marker;
    while (remaining > 0) {
        ssize_t written = write(descriptor, cursor, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            break;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    (void)fsync(descriptor);
    (void)close(descriptor);
}
