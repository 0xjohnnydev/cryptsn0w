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

extern char **environ;
extern int proc_pidpath(int, void *, uint32_t);

static const char *const kStagedController =
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe";
static const char *const kController =
    "/var/jb/usr/libexec/codex-carrier-ptrace-exec-probe";
static const char *const kStagedCarrier =
    "/var/mobile/Media/codex-runtime-carrier.dylib";
static const char *const kCarrier =
    "/var/jb/usr/lib/codex-runtime-carrier.dylib";
static const char *const kStagedProof =
    "/var/mobile/Media/codex-springboard-dynamic-proof.dylib";
static const char *const kProof =
    "/var/jb/usr/lib/codex-springboard-dynamic-proof.dylib";
static const char *const kWorker =
    "/var/jb/usr/libexec/codex-exec-worker";
static const char *const kCarrierProcess =
    "/var/jb/usr/libexec/codex-ellekit-loader";
static const char *const kLog =
    "/var/tmp/codex-carrier-test-installer.log";

static bool write_all(int descriptor, const void *buffer, size_t size) {
    const uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = write(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return true;
}

static bool install_file(const char *staged, const char *destination,
                         mode_t mode) {
    int input = open(staged, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char temporary[512];
    int length = snprintf(temporary, sizeof(temporary), "%s.%d.tmp",
                          destination, getpid());
    if (input < 0 || length < 0 || (size_t)length >= sizeof(temporary)) {
        if (input >= 0) {
            close(input);
        }
        return false;
    }
    (void)unlink(temporary);
    int output = open(temporary,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                      0700);
    bool success = output >= 0;
    uint8_t buffer[64 * 1024];
    while (success) {
        ssize_t amount;
        do {
            amount = read(input, buffer, sizeof(buffer));
        } while (amount < 0 && errno == EINTR);
        if (amount < 0) {
            success = false;
        } else if (amount == 0) {
            break;
        } else {
            success = write_all(output, buffer, (size_t)amount);
        }
    }
    if (success) {
        success = fsync(output) == 0 && fchown(output, 0, 0) == 0 &&
                  fchmod(output, mode) == 0;
    }
    int saved_error = errno;
    close(input);
    if (output >= 0) {
        close(output);
    }
    if (success) {
        success = rename(temporary, destination) == 0;
        saved_error = errno;
    }
    if (!success) {
        (void)unlink(temporary);
    }
    errno = saved_error;
    return success;
}

static pid_t stop_prior_carrier(void) {
    int descriptor = open("/var/tmp/codex-runtime-carrier.loaded",
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char marker[512] = {0};
    ssize_t amount = descriptor >= 0
        ? read(descriptor, marker, sizeof(marker) - 1U)
        : -1;
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    if (amount <= 0) {
        return -1;
    }
    marker[amount] = '\0';
    char *pid_field = strstr(marker, "pid=");
    if (pid_field == NULL) {
        return -1;
    }
    char *end = NULL;
    errno = 0;
    long value = strtol(pid_field + 4, &end, 10);
    if (errno != 0 || end == pid_field + 4 || value <= 1 ||
        value > INT32_MAX) {
        return -1;
    }
    pid_t pid = (pid_t)value;
    char path[512] = {0};
    if (proc_pidpath(pid, path, sizeof(path)) <= 0 ||
        strcmp(path, kCarrierProcess) != 0) {
        return -1;
    }
    (void)kill(pid, SIGTERM);
    for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
        errno = 0;
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            return pid;
        }
        usleep(10U * 1000U);
    }
    memset(path, 0, sizeof(path));
    if (proc_pidpath(pid, path, sizeof(path)) > 0 &&
        strcmp(path, kCarrierProcess) == 0) {
        (void)kill(pid, SIGKILL);
    }
    return pid;
}

__attribute__((constructor)) static void run_installer_test(void) {
    int log = open(kLog,
                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                   0600);
    if (log < 0) {
        return;
    }
    dprintf(log, "phase=start pid=%d uid=%u euid=%u\n", getpid(), getuid(),
            geteuid());
    bool installed = geteuid() == 0 && access(kWorker, X_OK) == 0 &&
                     install_file(kStagedController, kController, 0755) &&
                     install_file(kStagedCarrier, kCarrier, 0644) &&
                     install_file(kStagedProof, kProof, 0644);
    dprintf(log, "phase=install installed=%d errno=%d controller=%s "
                 "carrier=%s proof=%s\n",
            installed, installed ? 0 : errno, kController, kCarrier,
            kProof);
    if (!installed) {
        close(log);
        return;
    }
    pid_t prior_carrier = stop_prior_carrier();
    dprintf(log, "phase=replace priorCarrier=%d\n", prior_carrier);
    (void)unlink("/var/tmp/codex-runtime-carrier.loaded");
    (void)unlink("/var/tmp/codex-springboard-dynamic.loaded");

    posix_spawn_file_actions_t actions;
    int actions_result = posix_spawn_file_actions_init(&actions);
    if (actions_result == 0) {
        posix_spawn_file_actions_adddup2(&actions, log, STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, log, STDERR_FILENO);
    }
    char *arguments[] = {
        (char *)kWorker,
        "--macho",
        (char *)kController,
        NULL,
    };
    pid_t child = 0;
    int spawn_result = actions_result == 0
        ? posix_spawn(&child, kWorker, &actions, NULL, arguments, environ)
        : actions_result;
    if (actions_result == 0) {
        posix_spawn_file_actions_destroy(&actions);
    }
    dprintf(log, "phase=spawn result=%d child=%d\n", spawn_result, child);
    int status = 0;
    if (spawn_result == 0 && child > 1) {
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
    }
    dprintf(log, "phase=complete status=0x%x exited=%d code=%d "
                 "signaled=%d signal=%d\n",
            status, WIFEXITED(status),
            WIFEXITED(status) ? WEXITSTATUS(status) : -1,
            WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    fsync(log);
    close(log);
}
