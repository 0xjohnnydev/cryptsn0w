#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor)) static void codex_runtime_carrier_probe(void) {
    int descriptor = open("/var/tmp/codex-runtime-carrier.loaded",
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return;
    }
    dprintf(descriptor,
            "codex-runtime-carrier=loaded pid=%d uid=%u euid=%u\n",
            getpid(), getuid(), geteuid());
    (void)fsync(descriptor);
    (void)close(descriptor);
}
