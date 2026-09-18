#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void codex_carrier_probe(void) {
    static const char marker[] =
        "codex-entitled-carrier-probe=loaded\n";
    (void)write(STDERR_FILENO, marker, sizeof(marker) - 1U);

    const char *home = getenv("HOME");
    if (home != NULL) {
        char path[PATH_MAX] = {0};
        int length = snprintf(path, sizeof(path),
                              "%s/Documents/codex-entitled-carrier-probe.loaded",
                              home);
        if (length > 0 && (size_t)length < sizeof(path)) {
            int home_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (home_fd >= 0) {
                (void)write(home_fd, marker, sizeof(marker) - 1U);
                (void)close(home_fd);
            }
        }
    }

    int fd = open("/var/tmp/codex-entitled-carrier-probe.loaded",
                  O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        (void)write(fd, marker, sizeof(marker) - 1U);
        (void)close(fd);
    }
}
