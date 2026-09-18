#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const kReportPath =
    "/var/mobile/Media/codex-amfid-admission-canary-report.txt";

int main(void) {
    int report = open(kReportPath,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (report < 0) {
        return 70;
    }
    struct stat status = {0};
    if (fstat(report, &status) != 0 || !S_ISREG(status.st_mode)) {
        close(report);
        return 71;
    }
    dprintf(report,
            "magic=codex-amfid-admission-canary-v1\n"
            "pid=%d\nuid=%u\neuid=%u\n",
            getpid(), getuid(), geteuid());
    int result = fsync(report);
    close(report);
    return result == 0 ? 0 : 72;
}
