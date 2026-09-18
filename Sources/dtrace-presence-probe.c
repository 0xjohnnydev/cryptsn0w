#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const kReportPath =
    "/var/mobile/Media/codex-dtrace-presence-report.txt";

static void report_path(int report, const char *path) {
    struct stat status = {0};
    errno = 0;
    int statResult = lstat(path, &status);
    int statError = statResult == 0 ? 0 : errno;

    errno = 0;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int openError = descriptor >= 0 ? 0 : errno;
    struct stat openedStatus = {0};
    int fstatResult = descriptor >= 0 ? fstat(descriptor, &openedStatus) : -1;
    int fstatError = fstatResult == 0 ? 0 : errno;
    if (descriptor >= 0) {
        close(descriptor);
    }

    dprintf(report,
            "path=%s stat=%d statErrno=%d mode=0%o rdev=%llu "
            "open=%d openErrno=%d fstat=%d fstatErrno=%d "
            "openedMode=0%o openedRdev=%llu\n",
            path, statResult, statError,
            statResult == 0 ? status.st_mode : 0,
            statResult == 0 ? (unsigned long long)status.st_rdev : 0,
            descriptor >= 0 ? 0 : -1, openError, fstatResult, fstatError,
            fstatResult == 0 ? openedStatus.st_mode : 0,
            fstatResult == 0 ? (unsigned long long)openedStatus.st_rdev : 0);
}

int main(void) {
    int report = open(kReportPath,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (report < 0) {
        return 70;
    }
    struct stat reportStatus = {0};
    if (fstat(report, &reportStatus) != 0 ||
        !S_ISREG(reportStatus.st_mode)) {
        close(report);
        return 71;
    }

    dprintf(report,
            "magic=codex-dtrace-presence-v1\npid=%d\nuid=%u\neuid=%u\n",
            getpid(), getuid(), geteuid());
    static const char *const paths[] = {
        "/dev/dtrace",
        "/dev/dtrace/dtrace",
        "/dev/fasttrap",
        "/dev/dtracehelper",
        "/dev/dtrace/helper",
        "/usr/sbin/dtrace",
        "/usr/bin/dtrace",
        "/var/jb/usr/sbin/dtrace",
        "/var/jb/usr/bin/dtrace",
        "/usr/bin/true",
        "/bin/ls",
        "/usr/bin/id",
        "/usr/libexec/xpcproxy",
        "/bin/launchctl",
        "/var/jb/usr/bin/launchctl",
    };
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); index++) {
        report_path(report, paths[index]);
    }

    bool reportOk = fsync(report) == 0;
    close(report);
    return reportOk ? 0 : 72;
}
