#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_PROC_PIDEXITREASONBASICINFO 25
#define CODEX_REPORT_MAGIC "codex-springboard-copy-spawn-v1"
#define CODEX_PID_PATH_SIZE 1024U

struct codex_proc_exitreasonbasicinfo {
    uint32_t reasonNamespace;
    uint64_t reasonCode;
    uint64_t reasonFlags;
    uint32_t reasonBufferSize;
} __attribute__((packed));

extern char **environ;
extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer,
                        int buffersize);
static const char *const kLiveSpringBoard =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char *const kSpringBoardCopy =
    "/var/jb/usr/libexec/codex-sb-test";
static const char *const kReportPath =
    "/var/mobile/Media/codex-sb-copy-spawn-report.txt";

static pid_t gOwnedChild = -1;

static void terminate_owned_child(void) {
    pid_t child = gOwnedChild;
    if (child <= 1) {
        return;
    }
    (void)kill(child, SIGKILL);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    gOwnedChild = -1;
}

static bool exact_process_path(pid_t pid, const char *expected,
                               char *observed, size_t observedSize) {
    if (pid <= 1 || observed == NULL || observedSize == 0) {
        return false;
    }
    memset(observed, 0, observedSize);
    int length = proc_pidpath(pid, observed, (uint32_t)observedSize);
    return length > 0 && (size_t)length < observedSize &&
           strcmp(observed, expected) == 0;
}

static int parse_pid(const char *text, pid_t *result) {
    if (text == NULL || result == NULL || *text == '\0') {
        return EINVAL;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT32_MAX) {
        return EINVAL;
    }
    *result = (pid_t)value;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || getpid() <= 1 || geteuid() != 0) {
        return 70;
    }

    pid_t livePid = -1;
    if (parse_pid(argv[1], &livePid) != 0) {
        return 71;
    }

    char livePathBefore[CODEX_PID_PATH_SIZE] = {0};
    if (!exact_process_path(livePid, kLiveSpringBoard, livePathBefore,
                            sizeof(livePathBefore))) {
        return 72;
    }

    struct stat copyStatus;
    if (lstat(kSpringBoardCopy, &copyStatus) != 0 ||
        !S_ISREG(copyStatus.st_mode) || (copyStatus.st_mode & 0111) == 0) {
        return 73;
    }

    int report = open(kReportPath,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (report < 0) {
        return 74;
    }

    posix_spawnattr_t attributes;
    int initResult = posix_spawnattr_init(&attributes);
    int flagsResult = initResult == 0
        ? posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED)
        : initResult;

    char *childArguments[] = {(char *)kSpringBoardCopy, NULL};
    pid_t child = -1;
    int spawnResult = flagsResult == 0
        ? posix_spawn(&child, kSpringBoardCopy, NULL, &attributes,
                      childArguments, environ)
        : flagsResult;
    if (initResult == 0) {
        (void)posix_spawnattr_destroy(&attributes);
    }

    dprintf(report,
            "magic=%s\nprobePid=%d\nlivePid=%d\nlivePathBefore=%s\n"
            "copyPath=%s\ncopyDevice=%llu\ncopyInode=%llu\n"
            "spawnResult=%d\nspawnResultText=%s\nchildPid=%d\n",
            CODEX_REPORT_MAGIC, getpid(), livePid, livePathBefore,
            kSpringBoardCopy, (unsigned long long)copyStatus.st_dev,
            (unsigned long long)copyStatus.st_ino, spawnResult,
            spawnResult == 0 ? "success" : strerror(spawnResult), child);

    if (spawnResult != 0) {
        char livePathAfter[CODEX_PID_PATH_SIZE] = {0};
        bool liveUnchanged = exact_process_path(
            livePid, kLiveSpringBoard, livePathAfter, sizeof(livePathAfter));
        dprintf(report,
                "childCreated=0\nlivePathAfter=%s\nliveUnchanged=%d\n"
                "cleanup=not-needed\n",
                livePathAfter, liveUnchanged);
        bool reportOk = fsync(report) == 0;
        close(report);
        return liveUnchanged && reportOk ? 0 : 75;
    }

    if (child <= 1 || child == livePid) {
        dprintf(report, "childValidation=invalid-pid\n");
        if (child > 1 && child != livePid) {
            gOwnedChild = child;
            terminate_owned_child();
        }
        (void)fsync(report);
        close(report);
        return 76;
    }
    gOwnedChild = child;
    (void)atexit(terminate_owned_child);

    char childPath[CODEX_PID_PATH_SIZE] = {0};
    bool childPathExact = false;
    uint32_t childCsFlags = 0;
    int csopsResult = -1;
    int csopsError = 0;
    struct codex_proc_exitreasonbasicinfo exitReason = {0};
    int exitReasonResult = -1;
    int exitReasonError = 0;
    unsigned int observationAttempts = 0;
    for (; observationAttempts < 50U; ++observationAttempts) {
        childPathExact = exact_process_path(
            child, kSpringBoardCopy, childPath, sizeof(childPath));
        errno = 0;
        csopsResult = csops(child, CODEX_CS_OPS_STATUS, &childCsFlags,
                            sizeof(childCsFlags));
        csopsError = csopsResult == 0 ? 0 : errno;
        memset(&exitReason, 0, sizeof(exitReason));
        errno = 0;
        exitReasonResult = proc_pidinfo(
            child, CODEX_PROC_PIDEXITREASONBASICINFO, 1, &exitReason,
            (int)sizeof(exitReason));
        exitReasonError = exitReasonResult == (int)sizeof(exitReason)
            ? 0
            : errno;
        if (childPathExact ||
            exitReasonResult == (int)sizeof(exitReason)) {
            break;
        }
        usleep(2U * 1000U);
    }

    errno = 0;
    int existenceResult = kill(child, 0);
    int existenceError = existenceResult == 0 ? 0 : errno;

    dprintf(report,
            "childCreated=1\nchildPath=%s\nchildPathExact=%d\n"
            "observationAttempts=%u\ncsopsResult=%d\ncsopsErrno=%d\n"
            "csflags=0x%08x\nexitReasonResult=%d\nexitReasonErrno=%d\n"
            "exitReasonNamespace=%u\nexitReasonCode=0x%llx\n"
            "exitReasonFlags=0x%llx\nexistenceResult=%d\n"
            "existenceErrno=%d\n",
            childPath, childPathExact, observationAttempts + 1U,
            csopsResult, csopsError, childCsFlags, exitReasonResult,
            exitReasonError, exitReason.reasonNamespace,
            (unsigned long long)exitReason.reasonCode,
            (unsigned long long)exitReason.reasonFlags, existenceResult,
            existenceError);

    int childWaitStatus = 0;
    errno = 0;
    pid_t preCleanupWaitResult = waitpid(
        child, &childWaitStatus, WNOHANG | WUNTRACED);
    int preCleanupWaitError = preCleanupWaitResult >= 0 ? 0 : errno;
    int killResult = 0;
    int killError = 0;
    pid_t waitResult = preCleanupWaitResult;
    int waitError = preCleanupWaitError;
    if (preCleanupWaitResult == 0) {
        errno = 0;
        killResult = kill(child, SIGKILL);
        killError = killResult == 0 ? 0 : errno;
    }
    if (preCleanupWaitResult == 0 && killResult == 0) {
    do {
        waitResult = waitpid(child, &childWaitStatus, 0);
    } while (waitResult < 0 && errno == EINTR);
        waitError = waitResult == child ? 0 : errno;
    }
    gOwnedChild = -1;

    char livePathAfter[CODEX_PID_PATH_SIZE] = {0};
    bool liveUnchanged = exact_process_path(
        livePid, kLiveSpringBoard, livePathAfter, sizeof(livePathAfter));
    dprintf(report,
            "preCleanupWaitResult=%d\npreCleanupWaitErrno=%d\n"
            "killResult=%d\nkillErrno=%d\nwaitResult=%d\nwaitErrno=%d\n"
            "childWaitStatus=0x%08x\ncleanup=%s\nlivePathAfter=%s\n"
            "liveUnchanged=%d\n",
            preCleanupWaitResult, preCleanupWaitError, killResult, killError,
            waitResult, waitError, childWaitStatus,
            waitResult == child ? "reaped" : "failed", livePathAfter,
            liveUnchanged);

    bool reportOk = fsync(report) == 0;
    close(report);
    return waitResult == child && liveUnchanged && reportOk
        ? 0
        : 77;
}
