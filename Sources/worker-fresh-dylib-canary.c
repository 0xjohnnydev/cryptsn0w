#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef CODEX_ACCEPTANCE_NONCE
#define CODEX_ACCEPTANCE_NONCE "20260918T015615Z-0d282c34d13467d6"
#endif
#ifndef CODEX_EXPECTED_UID
#define CODEX_EXPECTED_UID 0U
#endif
#ifndef CODEX_MARKER_PATH
#define CODEX_MARKER_PATH \
    "/var/mobile/Media/codex-worker-fresh-dylib-canary.marker"
#endif

__attribute__((constructor)) static void codex_acceptance_constructor(void) {
    uid_t processUid = getuid();
    uid_t effectiveUid = geteuid();
    uid_t expectedUid = (uid_t)CODEX_EXPECTED_UID;
    char marker[256];
    int markerLength = snprintf(
        marker, sizeof(marker),
        "constructor=entered nonce=%s pid=%d uid=%d euid=%d\n",
        CODEX_ACCEPTANCE_NONCE, getpid(), processUid, effectiveUid);

    bool identityExact = processUid == expectedUid &&
                         effectiveUid == expectedUid;
    int descriptor = identityExact
        ? open(CODEX_MARKER_PATH,
               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
               0600)
        : -1;
    struct stat markerStatus = {0};
    bool markerSecure = descriptor >= 0 &&
        fstat(descriptor, &markerStatus) == 0 &&
        S_ISREG(markerStatus.st_mode) &&
        markerStatus.st_uid == expectedUid &&
        markerStatus.st_nlink == 1 &&
        (markerStatus.st_mode & (S_IWGRP | S_IWOTH)) == 0;
    if (markerSecure && markerLength > 0 &&
        (size_t)markerLength < sizeof(marker)) {
        (void)write(descriptor, marker, (size_t)markerLength);
        (void)fsync(descriptor);
    }
    if (descriptor >= 0) {
        (void)close(descriptor);
    }

    dprintf(STDOUT_FILENO,
            "codex-worker-fresh-dylib-canary constructor=entered nonce=%s "
            "markerFd=%d\n",
            CODEX_ACCEPTANCE_NONCE, descriptor);
    dprintf(STDERR_FILENO,
            "codex-worker-fresh-dylib-canary stderr-sentinel=present "
            "nonce=%s\n",
            CODEX_ACCEPTANCE_NONCE);
}
