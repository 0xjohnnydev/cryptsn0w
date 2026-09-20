#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const kRootBrokerExecutable =
    "/var/jb/usr/libexec/codex-sileo-root-broker";

int main(void) {
    if (geteuid() != 0) {
        fputs("SBInject package validator requires uid 0\n", stderr);
        return 77;
    }

    /*
     * Preserve APT's version-1 path stream verbatim. The fixed broker performs
     * bounded extraction, rejects malformed archives, identifies standard
     * SpringBoard tweak dylibs, and records whether a respring is needed. No
     * package payload is submitted to AMFI or a trust-cache service.
     */
    char *arguments[] = {
        (char *)kRootBrokerExecutable,
        "--sbinject-debs-stdin",
        NULL,
    };
    execv(kRootBrokerExecutable, arguments);
    fprintf(stderr, "SBInject package validator launch failed: %s\n",
            strerror(errno));
    return 76;
}
