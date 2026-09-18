#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_OPS_SET_STATUS 9U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_PID_PATH_SIZE 1024U

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kReportPath =
    "/var/mobile/Media/codex-springboard-csops-status-report.txt";

extern int csops(pid_t pid, unsigned int ops, void *useraddr,
                 size_t usersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

static bool exact_springboard(pid_t pid, char path[CODEX_PID_PATH_SIZE]) {
    if (pid <= 1 || pid == getpid()) {
        return false;
    }
    memset(path, 0, CODEX_PID_PATH_SIZE);
    int length = proc_pidpath(pid, path, CODEX_PID_PATH_SIZE);
    return length > 0 && (uint32_t)length < CODEX_PID_PATH_SIZE &&
           strcmp(path, kSpringBoardPath) == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 69;
    }
    char *end = NULL;
    errno = 0;
    long parsed = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || parsed <= 1 ||
        parsed > INT32_MAX) {
        return 70;
    }
    pid_t target = (pid_t)parsed;
    char beforePath[CODEX_PID_PATH_SIZE];
    if (!exact_springboard(target, beforePath)) {
        return 71;
    }

    int report = open(kReportPath,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (report < 0) {
        return 72;
    }
    struct stat reportStatus = {0};
    if (fstat(report, &reportStatus) != 0 ||
        !S_ISREG(reportStatus.st_mode)) {
        close(report);
        return 73;
    }

    uint32_t beforeFlags = 0;
    errno = 0;
    int beforeResult = csops(target, CODEX_CS_OPS_STATUS, &beforeFlags,
                             sizeof(beforeFlags));
    int beforeError = beforeResult == 0 ? 0 : errno;

    uint32_t requestedFlags = CODEX_CS_DEBUGGED;
    errno = 0;
    int setResult = beforeResult == 0
        ? csops(target, CODEX_CS_OPS_SET_STATUS, &requestedFlags,
                sizeof(requestedFlags))
        : -1;
    int setError = setResult == 0 ? 0 : errno;

    uint32_t afterFlags = 0;
    errno = 0;
    int afterResult = csops(target, CODEX_CS_OPS_STATUS, &afterFlags,
                            sizeof(afterFlags));
    int afterError = afterResult == 0 ? 0 : errno;
    char afterPath[CODEX_PID_PATH_SIZE];
    bool stillExact = exact_springboard(target, afterPath);

    dprintf(report,
            "magic=codex-springboard-csops-status-v1\ncallerPid=%d\n"
            "callerUid=%u\ntargetPid=%d\ntargetPathBefore=%s\n"
            "beforeResult=%d\nbeforeErrno=%d\nbeforeFlags=0x%08x\n"
            "beforeDebugged=%d\nrequestedFlags=0x%08x\nsetResult=%d\n"
            "setErrno=%d\nafterResult=%d\nafterErrno=%d\n"
            "afterFlags=0x%08x\nafterDebugged=%d\nflagsChanged=%d\n"
            "targetStillExact=%d\ntargetPathAfter=%s\n",
            getpid(), getuid(), target, beforePath, beforeResult, beforeError,
            beforeFlags, (beforeFlags & CODEX_CS_DEBUGGED) != 0,
            requestedFlags, setResult, setError, afterResult, afterError,
            afterFlags, (afterFlags & CODEX_CS_DEBUGGED) != 0,
            afterFlags != beforeFlags, stillExact,
            stillExact ? afterPath : "");
    bool reportOk = fsync(report) == 0;
    close(report);
    return reportOk && stillExact ? 0 : 74;
}
