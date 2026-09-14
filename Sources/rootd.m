#import <Foundation/Foundation.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "embedded_payload.h"

static const char *const kStateDirectory = "/var/tmp/untitled-state";
static const char *const kPrivilegeDirectory = "/var/tmp/untitled";
static const char *const kStateHostKey =
    "/var/tmp/untitled-state/ssh_host_ed25519_key";
static const char *const kStateAuthorizedKeys =
    "/var/tmp/untitled-state/authorized_keys";
static const char *const kStateConfig =
    "/var/tmp/untitled-state/sshd_config";
static const char *const kPidFile = "/var/tmp/untitled-state/sshd.pid";
static const char *const kReadyFile = "/var/tmp/untitled-state/root.json";

static os_log_t gLog;

static void Report(const char *message) {
    os_log(gLog, "%{public}s", message);
    dprintf(STDERR_FILENO, "%s\n", message);
}

static bool EnsureDirectory(const char *path, mode_t mode) {
    struct stat status;
    if (lstat(path, &status) == 0) {
        if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
            errno = ENOTDIR;
            return false;
        }
    } else if (errno == ENOENT) {
        if (mkdir(path, mode) != 0) {
            return false;
        }
    } else {
        return false;
    }
    return chown(path, 0, 0) == 0 && chmod(path, mode) == 0;
}

static bool WriteFile(const char *destination, const unsigned char *bytes,
                      size_t length, mode_t mode) {
    int output = open(destination,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      mode);
    if (output < 0) {
        return false;
    }

    bool writtenAll = true;
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(output, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            writtenAll = false;
            break;
        }
        offset += (size_t)written;
    }
    if (writtenAll) {
        writtenAll = fchown(output, 0, 0) == 0 &&
                     fchmod(output, mode) == 0 && fsync(output) == 0;
    }
    int savedError = errno;
    close(output);
    errno = savedError;
    return writtenAll;
}

static bool WriteReadyMarker(void) {
    int descriptor = open(kReadyFile,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return false;
    }
    char payload[192];
    int length = snprintf(payload, sizeof(payload),
                          "{\"uid\":%u,\"euid\":%u,\"pid\":%d," 
                          "\"sshPort\":2222}\n",
                          getuid(), geteuid(), getpid());
    bool valid = length > 0 && (size_t)length < sizeof(payload);
    bool written = valid && write(descriptor, payload, (size_t)length) == length;
    if (written) {
        written = fchown(descriptor, 0, 0) == 0 &&
                  fchmod(descriptor, 0600) == 0 && fsync(descriptor) == 0;
    }
    int savedError = errno;
    close(descriptor);
    errno = savedError;
    return written;
}

static bool ResolveServer(char server[PATH_MAX]) {
    char executable[PATH_MAX] = {0};
    uint32_t size = sizeof(executable);
    if (_NSGetExecutablePath(executable, &size) != 0) {
        errno = ENAMETOOLONG;
        return false;
    }
    char resolved[PATH_MAX] = {0};
    const char *path = realpath(executable, resolved) != NULL
                           ? resolved
                           : executable;
    NSString *mountRoot = [NSString stringWithUTF8String:path];
    if (mountRoot == nil) {
        errno = EINVAL;
        return false;
    }
    for (NSUInteger index = 0; index < 4; ++index) {
        mountRoot = [mountRoot stringByDeletingLastPathComponent];
    }
    NSString *serverPath = [mountRoot
        stringByAppendingPathComponent:
            @"usr/local/libexec/untitled/bin/sshd"];
    if (![serverPath getFileSystemRepresentation:server maxLength:PATH_MAX]) {
        errno = ENAMETOOLONG;
        return false;
    }
    return true;
}

static bool ValidateServer(const char *server) {
    int descriptors[2];
    if (pipe(descriptors) != 0) {
        return false;
    }
    pid_t child = fork();
    if (child < 0) {
        int savedError = errno;
        close(descriptors[0]);
        close(descriptors[1]);
        errno = savedError;
        return false;
    }
    if (child == 0) {
        close(descriptors[0]);
        (void)dup2(descriptors[1], STDOUT_FILENO);
        (void)dup2(descriptors[1], STDERR_FILENO);
        close(descriptors[1]);
        execl(server, server, "-t", "-f", kStateConfig, NULL);
        dprintf(STDERR_FILENO, "sshd validation exec failed: %s\n",
                strerror(errno));
        _exit(127);
    }

    close(descriptors[1]);
    char output[2048] = {0};
    size_t used = 0;
    while (used + 1 < sizeof(output)) {
        ssize_t count = read(descriptors[0], output + used,
                             sizeof(output) - used - 1);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        used += (size_t)count;
    }
    close(descriptors[0]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    if (used != 0) {
        while (used != 0 && (output[used - 1] == '\n' ||
                             output[used - 1] == '\r')) {
            output[--used] = '\0';
        }
        Report(output);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EINVAL;
        return false;
    }
    return true;
}

static int RunServer(const char *server) {
    int descriptors[2];
    if (pipe(descriptors) != 0) {
        return 71;
    }
    pid_t child = fork();
    if (child < 0) {
        int savedError = errno;
        close(descriptors[0]);
        close(descriptors[1]);
        errno = savedError;
        return 71;
    }
    if (child == 0) {
        close(descriptors[0]);
        (void)dup2(descriptors[1], STDOUT_FILENO);
        (void)dup2(descriptors[1], STDERR_FILENO);
        close(descriptors[1]);
        execl(server, server, "-D", "-e", "-f", kStateConfig, NULL);
        dprintf(STDERR_FILENO, "sshd exec failed: %s\n", strerror(errno));
        _exit(127);
    }

    close(descriptors[1]);
    char buffer[2048];
    for (;;) {
        ssize_t count = read(descriptors[0], buffer, sizeof(buffer) - 1);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        buffer[count] = '\0';
        char *cursor = buffer;
        while (*cursor != '\0') {
            char *newline = strpbrk(cursor, "\r\n");
            if (newline != NULL) {
                *newline = '\0';
            }
            if (*cursor != '\0') {
                Report(cursor);
            }
            if (newline == NULL) {
                break;
            }
            cursor = newline + 1;
            while (*cursor == '\r' || *cursor == '\n') {
                ++cursor;
            }
        }
    }
    close(descriptors[0]);
    int childStatus = 0;
    while (waitpid(child, &childStatus, 0) < 0) {
        if (errno != EINTR) {
            return 71;
        }
    }
    char exitMessage[128];
    if (WIFEXITED(childStatus)) {
        snprintf(exitMessage, sizeof(exitMessage),
                 "sshd exited status=%d", WEXITSTATUS(childStatus));
    } else if (WIFSIGNALED(childStatus)) {
        snprintf(exitMessage, sizeof(exitMessage),
                 "sshd exited signal=%d", WTERMSIG(childStatus));
    } else {
        snprintf(exitMessage, sizeof(exitMessage), "sshd exited unexpectedly");
    }
    Report(exitMessage);
    return 71;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    @autoreleasepool {
        gLog = os_log_create("com.0xjohnnydev.untitled", "rootd");
        char start[160];
        snprintf(start, sizeof(start),
                 "rootd start uid=%u euid=%u gid=%u egid=%u pid=%d",
                 getuid(), geteuid(), getgid(), getegid(), getpid());
        Report(start);

        if (geteuid() != 0) {
            Report("refusing non-root launch");
            return 77;
        }
        if (!EnsureDirectory(kStateDirectory, 0700) ||
            !EnsureDirectory(kPrivilegeDirectory, 0755)) {
            Report("state directory setup failed");
            return 73;
        }
        if (!WriteFile(kStateHostKey, kUntitledHostKey,
                       kUntitledHostKeyLength, 0600)) {
            char failure[320];
            snprintf(failure, sizeof(failure),
                     "host-key staging failed (%s): %s", kStateHostKey,
                     strerror(errno));
            Report(failure);
            return 74;
        }
        if (!WriteFile(kStateAuthorizedKeys, kUntitledAuthorizedKeys,
                       kUntitledAuthorizedKeysLength, 0600)) {
            char failure[320];
            snprintf(failure, sizeof(failure),
                     "authorized-key staging failed (%s): %s",
                     kStateAuthorizedKeys, strerror(errno));
            Report(failure);
            return 74;
        }
        if (!WriteFile(kStateConfig, kUntitledSshdConfig,
                       kUntitledSshdConfigLength, 0600)) {
            char failure[320];
            snprintf(failure, sizeof(failure),
                     "sshd-config staging failed (%s): %s", kStateConfig,
                     strerror(errno));
            Report(failure);
            return 74;
        }
        char server[PATH_MAX] = {0};
        if (!ResolveServer(server) || access(server, X_OK) != 0) {
            char failure[PATH_MAX + 96];
            snprintf(failure, sizeof(failure),
                     "SSH payload is incomplete path=%s error=%s", server,
                     strerror(errno));
            Report(failure);
            return 72;
        }
        if (!ValidateServer(server)) {
            Report("sshd preflight failed");
            return 76;
        }
        unlink(kPidFile);
        if (!WriteReadyMarker()) {
            Report("root proof marker failed");
            return 75;
        }

        setenv("HOME", "/var/root", 1);
        setenv("SHELL", "/bin/sh", 1);
        setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1);
        Report("root proof ready; starting localhost SSH on port 2222");
        return RunServer(server);
    }
}
