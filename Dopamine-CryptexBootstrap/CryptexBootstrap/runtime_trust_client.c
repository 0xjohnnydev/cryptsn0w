#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const kRootBrokerExecutable =
    "/var/jb/usr/libexec/codex-sileo-root-broker";

int main(void) {
    if (geteuid() != 0) {
        fputs("codex runtime admission client requires uid 0\n", stderr);
        return 77;
    }

    /*
     * Preserve APT's stdin verbatim and hand validation to the fixed,
     * trust-cached root-broker image.  This avoids a second Mach-service
     * authentication hop while retaining the broker's bounded extraction and
     * malformed-archive rejection before dpkg executes maintainer scripts.
     */
    char *arguments[] = {
        (char *)kRootBrokerExecutable,
        "--trust-debs-stdin",
        NULL,
    };
    execv(kRootBrokerExecutable, arguments);
    fprintf(stderr, "codex runtime admission validator launch failed: %s\n",
            strerror(errno));
    return 76;
}
