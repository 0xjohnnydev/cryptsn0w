#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags,
                                void *buffer, size_t buffersize);
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

#define UNTITLED_MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK 5
#define UNTITLED_MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES 7
#define UNTITLED_MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES 8
#define UNTITLED_FRIDA_MEMORY_LIMIT_MB 256
#define UNTITLED_FRIDA_MINIMUM_MEMORY_LIMIT_MB 128

typedef struct untitled_memlimit_properties {
    int32_t memlimit_active;
    uint32_t memlimit_active_attr;
    int32_t memlimit_inactive;
    uint32_t memlimit_inactive_attr;
} untitled_memlimit_properties_t;

static const char *const kTargetServer = "/var/jb/usr/sbin/frida-server";
static const char *const kTargetAgent =
    "/var/jb/usr/lib/frida-1.0/frida-agent.dylib";
static const char *const kLegacyPlist =
    "/var/jb/Library/LaunchDaemons/re.frida.server.plist";

static bool ProcessHasPath(pid_t pid, const char *expectedPath) {
    char actualPath[PATH_MAX] = {0};
    return pid > 1 && proc_pidpath(pid, actualPath, sizeof(actualPath)) > 0 &&
           strcmp(actualPath, expectedPath) == 0;
}

static bool ProcessIsInstalledServer(pid_t pid,
                                     const char *resolvedTargetPath) {
    return ProcessHasPath(pid, kTargetServer) ||
           (resolvedTargetPath[0] != '\0' &&
            ProcessHasPath(pid, resolvedTargetPath));
}

static int CopyInstalledServerPids(const char *resolvedTargetPath,
                                   pid_t **serverPids) {
    *serverPids = NULL;
    int capacity = proc_listallpids(NULL, 0);
    if (capacity <= 0 || capacity > 1024 * 1024) {
        errno = EIO;
        return -1;
    }
    capacity += 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    pid_t *matches = calloc((size_t)capacity, sizeof(*matches));
    if (pids == NULL || matches == NULL) {
        free(pids);
        free(matches);
        errno = ENOMEM;
        return -1;
    }

    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    if (count < 0) {
        int savedError = errno;
        free(pids);
        free(matches);
        errno = savedError;
        return -1;
    }
    if (count > capacity) {
        count = capacity;
    }

    int matchCount = 0;
    for (int index = 0; index < count; index++) {
        pid_t pid = pids[index];
        if (pid != getpid() && ProcessIsInstalledServer(
                                   pid, resolvedTargetPath)) {
            matches[matchCount++] = pid;
        }
    }
    free(pids);
    *serverPids = matches;
    return matchCount;
}

static bool StopExistingServer(const char *resolvedTargetPath,
                               int *stoppedCount) {
    *stoppedCount = 0;
    pid_t *targets = NULL;
    int targetCount =
        CopyInstalledServerPids(resolvedTargetPath, &targets);
    if (targetCount < 0) {
        return false;
    }
    for (int index = 0; index < targetCount; index++) {
        if (!ProcessIsInstalledServer(targets[index],
                                      resolvedTargetPath)) {
            continue;
        }
        if (kill(targets[index], SIGTERM) != 0 && errno != ESRCH) {
            int savedError = errno;
            free(targets);
            errno = savedError;
            return false;
        }
    }

    for (int attempt = 0; attempt < 40; attempt++) {
        bool anyAlive = false;
        for (int index = 0; index < targetCount; index++) {
            if (ProcessIsInstalledServer(targets[index],
                                         resolvedTargetPath)) {
                anyAlive = true;
                break;
            }
        }
        if (!anyAlive) {
            pid_t *remaining = NULL;
            int remainingCount =
                CopyInstalledServerPids(resolvedTargetPath, &remaining);
            if (remainingCount < 0) {
                int savedError = errno;
                free(targets);
                errno = savedError;
                return false;
            }
            free(remaining);
            if (remainingCount == 0) {
                *stoppedCount = targetCount;
                free(targets);
                return true;
            }
        }
        usleep(50 * 1000);
    }

    free(targets);
    errno = EBUSY;
    return false;
}

static bool ResolveInstalledServer(char resolvedTargetPath[PATH_MAX]) {
    if (realpath(kTargetServer, resolvedTargetPath) != NULL) {
        return true;
    }
    int savedError = errno;
    resolvedTargetPath[0] = '\0';
    if (savedError == ENOENT) {
        return true;
    }
    errno = savedError;
    return false;
}

static bool PrintServerStatus(const char *resolvedTargetPath) {
    pid_t *servers = NULL;
    int serverCount =
        CopyInstalledServerPids(resolvedTargetPath, &servers);
    if (serverCount < 0) {
        return false;
    }
    dprintf(STDOUT_FILENO, "fridaServerStatus count=%d", serverCount);
    for (int index = 0; index < serverCount; index++) {
        dprintf(STDOUT_FILENO, " pid=%d", servers[index]);
    }
    dprintf(STDOUT_FILENO, "\n");
    free(servers);
    return true;
}

static bool ParseInspectablePid(const char *text, pid_t *pid) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT_MAX) {
        errno = EINVAL;
        return false;
    }
    *pid = (pid_t)value;
    return true;
}

static bool PrintProcessStatus(pid_t pid) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc process;
    memset(&process, 0, sizeof(process));
    size_t processSize = sizeof(process);
    if (sysctl(mib, (u_int)(sizeof(mib) / sizeof(mib[0])), &process,
               &processSize, NULL, 0) != 0) {
        return false;
    }
    if (processSize == 0 || process.kp_proc.p_pid != pid) {
        errno = ESRCH;
        return false;
    }

    char path[PATH_MAX] = {0};
    errno = 0;
    int pathLength = proc_pidpath(pid, path, sizeof(path));
    int pathError = pathLength > 0 ? 0 : errno;
    dprintf(STDOUT_FILENO,
            "processStatus pid=%d ppid=%d state=%d zombie=%d traced=%d "
            "flags=0x%08x pathStatus=%d pathErrno=%d path=%s\n",
            pid, process.kp_eproc.e_ppid, process.kp_proc.p_stat,
            process.kp_proc.p_stat == SZOMB,
            (process.kp_proc.p_flag & P_TRACED) != 0,
            (unsigned int)process.kp_proc.p_flag, pathLength, pathError,
            pathLength > 0 ? path : "-");
    return true;
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

static bool ResolveSourceDirectory(char directory[PATH_MAX]) {
    char executable[PATH_MAX] = {0};
    uint32_t length = sizeof(executable);
    if (_NSGetExecutablePath(executable, &length) != 0) {
        errno = ENAMETOOLONG;
        return false;
    }
    if (realpath(executable, directory) == NULL) {
        if (strlcpy(directory, executable, PATH_MAX) >= PATH_MAX) {
            errno = ENAMETOOLONG;
            return false;
        }
    }
    char *separator = strrchr(directory, '/');
    if (separator == NULL || separator == directory) {
        errno = EINVAL;
        return false;
    }
    *separator = '\0';
    return true;
}

static bool CopyAtomically(const char *source, const char *destination,
                           mode_t mode) {
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) {
        return false;
    }
    struct stat status;
    if (fstat(input, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size <= 0 || status.st_size > 128 * 1024 * 1024) {
        int savedError = errno != 0 ? errno : EINVAL;
        close(input);
        errno = savedError;
        return false;
    }

    char temporary[PATH_MAX];
    int temporaryLength = snprintf(temporary, sizeof(temporary),
                                   "%s.untitled-new.%d", destination,
                                   getpid());
    if (temporaryLength < 0 || (size_t)temporaryLength >= sizeof(temporary)) {
        close(input);
        errno = ENAMETOOLONG;
        return false;
    }
    int output = open(temporary,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                      mode);
    if (output < 0) {
        close(input);
        return false;
    }

    bool succeeded = true;
    char buffer[64 * 1024];
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            succeeded = false;
            break;
        }
        if (count == 0) {
            break;
        }
        size_t offset = 0;
        while (offset < (size_t)count) {
            ssize_t written =
                write(output, buffer + offset, (size_t)count - offset);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                succeeded = false;
                break;
            }
            offset += (size_t)written;
        }
        if (!succeeded) {
            break;
        }
    }
    if (succeeded) {
        succeeded = fchown(output, 0, 0) == 0 &&
                    fchmod(output, mode) == 0 && fsync(output) == 0;
    }
    int savedError = errno;
    close(input);
    close(output);
    if (succeeded) {
        succeeded = rename(temporary, destination) == 0;
        savedError = errno;
    }
    if (!succeeded) {
        unlink(temporary);
    }
    errno = savedError;
    return succeeded;
}

static int ReadLimits(untitled_memlimit_properties_t *limits) {
    memset(limits, 0, sizeof(*limits));
    return memorystatus_control(
        UNTITLED_MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, getpid(), 0,
        limits, sizeof(*limits));
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        dprintf(STDERR_FILENO, "frida-launcher: UID 0 is required\n");
        return 77;
    }

    char resolvedTargetPath[PATH_MAX] = {0};
    if (!ResolveInstalledServer(resolvedTargetPath)) {
        dprintf(STDERR_FILENO,
                "frida-launcher: cannot resolve existing server: %s\n",
                strerror(errno));
        return 75;
    }
    if (argc == 2 && strcmp(argv[1], "--status") == 0) {
        if (!PrintServerStatus(resolvedTargetPath)) {
            dprintf(STDERR_FILENO,
                    "frida-launcher: cannot inspect existing server: %s\n",
                    strerror(errno));
            return 75;
        }
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--inspect-pid") == 0) {
        pid_t pid = -1;
        if (!ParseInspectablePid(argv[2], &pid)) {
            dprintf(STDERR_FILENO,
                    "frida-launcher: refusing unsafe process id\n");
            return 64;
        }
        if (!PrintProcessStatus(pid)) {
            dprintf(STDERR_FILENO,
                    "frida-launcher: cannot inspect pid %d: %s\n", pid,
                    strerror(errno));
            return 75;
        }
        return 0;
    }
    if (argc != 1) {
        dprintf(STDERR_FILENO,
                "usage: frida-launcher [--status | --inspect-pid PID]\n");
        return 64;
    }

    char sourceDirectory[PATH_MAX] = {0};
    char sourceServer[PATH_MAX] = {0};
    char sourceAgent[PATH_MAX] = {0};
    if (!ResolveSourceDirectory(sourceDirectory) ||
        snprintf(sourceServer, sizeof(sourceServer), "%s/frida-server",
                 sourceDirectory) >= (int)sizeof(sourceServer) ||
        snprintf(sourceAgent, sizeof(sourceAgent), "%s/frida-agent.dylib",
                 sourceDirectory) >= (int)sizeof(sourceAgent)) {
        dprintf(STDERR_FILENO,
                "frida-launcher: cannot resolve trusted payload: %s\n",
                strerror(errno));
        return 65;
    }
    if (!EnsureDirectory("/var/jb/usr/sbin", 0755) ||
        !EnsureDirectory("/var/jb/usr/lib/frida-1.0", 0755)) {
        dprintf(STDERR_FILENO, "frida-launcher: staging path failed: %s\n",
                strerror(errno));
        return 73;
    }

    int stoppedServerCount = 0;
    if (!StopExistingServer(resolvedTargetPath, &stoppedServerCount)) {
        dprintf(STDERR_FILENO,
                "frida-launcher: cannot retire existing server: %s\n",
                strerror(errno));
        return 75;
    }
    dprintf(STDOUT_FILENO, "fridaStoppedExisting=%d\n", stoppedServerCount);

    if (!CopyAtomically(sourceServer, kTargetServer, 0755) ||
        !CopyAtomically(sourceAgent, kTargetAgent, 0755)) {
        dprintf(STDERR_FILENO, "frida-launcher: payload staging failed: %s\n",
                strerror(errno));
        return 73;
    }
    if (unlink(kLegacyPlist) != 0 && errno != ENOENT) {
        dprintf(STDERR_FILENO,
                "frida-launcher: legacy plist removal failed: %s\n",
                strerror(errno));
        return 73;
    }

    untitled_memlimit_properties_t initial = {0};
    errno = 0;
    int initialStatus = ReadLimits(&initial);
    int initialError = errno;

    bool initialLimitIsUsable =
        initialStatus == 0 &&
        (initial.memlimit_active == -1 ||
         initial.memlimit_active >= UNTITLED_FRIDA_MINIMUM_MEMORY_LIMIT_MB) &&
        (initial.memlimit_inactive == -1 ||
         initial.memlimit_inactive >= UNTITLED_FRIDA_MINIMUM_MEMORY_LIMIT_MB);
    untitled_memlimit_properties_t requested = {
        .memlimit_active = UNTITLED_FRIDA_MEMORY_LIMIT_MB,
        .memlimit_active_attr = 0,
        .memlimit_inactive = UNTITLED_FRIDA_MEMORY_LIMIT_MB,
        .memlimit_inactive_attr = 0,
    };
    int setStatus = 0;
    int setError = 0;
    if (!initialLimitIsUsable) {
        errno = 0;
        setStatus = memorystatus_control(
            UNTITLED_MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, getpid(), 0,
            &requested, sizeof(requested));
        setError = errno;
    }

    int fallbackStatus = 0;
    int fallbackError = 0;
    if (!initialLimitIsUsable && setStatus != 0) {
        errno = 0;
        fallbackStatus = memorystatus_control(
            UNTITLED_MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid(),
            UNTITLED_FRIDA_MEMORY_LIMIT_MB, NULL, 0);
        fallbackError = errno;
    }

    untitled_memlimit_properties_t effective = {0};
    errno = 0;
    int effectiveStatus = ReadLimits(&effective);
    int effectiveError = errno;
    dprintf(STDOUT_FILENO,
            "fridaJetsam initialStatus=%d initialErrno=%d initialActive=%d "
            "initialInactive=%d setStatus=%d setErrno=%d fallbackStatus=%d "
            "fallbackErrno=%d effectiveStatus=%d effectiveErrno=%d "
            "effectiveActive=%d effectiveInactive=%d\n",
            initialStatus, initialError, initial.memlimit_active,
            initial.memlimit_inactive, setStatus, setError, fallbackStatus,
            fallbackError, effectiveStatus, effectiveError,
            effective.memlimit_active, effective.memlimit_inactive);

    if (effectiveStatus != 0 ||
        (effective.memlimit_active != -1 &&
         effective.memlimit_active < UNTITLED_FRIDA_MINIMUM_MEMORY_LIMIT_MB) ||
        (effective.memlimit_inactive != -1 &&
         effective.memlimit_inactive < UNTITLED_FRIDA_MINIMUM_MEMORY_LIMIT_MB)) {
        dprintf(STDERR_FILENO,
                "frida-launcher: refusing to start below %d MB\n",
                UNTITLED_FRIDA_MINIMUM_MEMORY_LIMIT_MB);
        return 78;
    }

    char *serverArguments[] = {
        (char *)kTargetServer,
        "--daemonize",
        "--policy-softener",
        "internal",
        "--ignore-crashes",
        "--listen",
        "127.0.0.1:27042",
        NULL,
    };
    dprintf(STDOUT_FILENO,
            "fridaLaunchMode=direct-opt-in policySoftener=internal "
            "endpoint=127.0.0.1:27042\n");
    execv(kTargetServer, serverArguments);
    dprintf(STDERR_FILENO, "frida-launcher: exec failed: %s\n",
            strerror(errno));
    return 127;
}
