#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STAGE_ROOT "/usr/local/share/codex-stage-ssh/root"
#define STAGE_STATE "/private/var/tmp/codex-stage-ssh"
#define CREATED_MARKER STAGE_STATE "/created-var-jb"
#define STAGE_EXECUTABLE "/usr/local/bin/codex-dopamine-bootstrap"

extern char **environ;

static int run(char *const arguments[]) {
    pid_t child = 0;
    int result = posix_spawn(&child, arguments[0], NULL, NULL, arguments,
                             environ);
    if (result != 0) return result;
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return errno;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static bool ensure_directory(const char *path, mode_t mode) {
    if (mkdir(path, mode) != 0 && errno != EEXIST) return false;
    struct stat status;
    return lstat(path, &status) == 0 && S_ISDIR(status.st_mode) &&
           !S_ISLNK(status.st_mode) && chmod(path, mode) == 0;
}

static int cleanup(void) {
    if (access(CREATED_MARKER, F_OK) == 0) {
        char target[PATH_MAX] = {0};
        ssize_t length = readlink("/var/jb", target, sizeof(target) - 1U);
        if (length <= 0 || (size_t)length >= sizeof(target) ||
            strcmp(target, STAGE_ROOT) != 0 || unlink("/var/jb") != 0) {
            return 1;
        }
        (void)unlink(CREATED_MARKER);
    }

    FILE *pid_file = fopen(STAGE_STATE "/sshd.pid", "r");
    long raw_pid = 0;
    struct stat original;
    if (pid_file == NULL || fscanf(pid_file, "%ld", &raw_pid) != 1 ||
        raw_pid <= 1 || raw_pid > INT_MAX ||
        stat(STAGE_EXECUTABLE, &original) != 0) {
        if (pid_file != NULL) fclose(pid_file);
        return 1;
    }
    fclose(pid_file);
    pid_t watchdog = fork();
    if (watchdog < 0) return 1;
    if (watchdog == 0) {
        (void)setsid();
        for (int descriptor = 0; descriptor < 1024; ++descriptor) {
            close(descriptor);
        }
        for (unsigned int attempt = 0; attempt < 300U; ++attempt) {
            struct stat current;
            if (stat(STAGE_EXECUTABLE, &current) != 0 ||
                current.st_dev != original.st_dev ||
                current.st_ino != original.st_ino) {
                (void)kill((pid_t)raw_pid, SIGTERM);
                _exit(0);
            }
            sleep(1);
        }
        _exit(1);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (geteuid() != 0) return 1;
    if (argc == 2 && strcmp(argv[1], "--cleanup") == 0) return cleanup();
    if (argc != 1 || !ensure_directory(STAGE_STATE, 0700)) return 1;

    struct stat status;
    if (lstat("/var/jb", &status) != 0) {
        if (errno != ENOENT || symlink(STAGE_ROOT, "/var/jb") != 0) return 1;
        int marker = open(CREATED_MARKER,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker < 0) {
            (void)unlink("/var/jb");
            return 1;
        }
        close(marker);
    }

    const char *host_key = STAGE_STATE "/ssh_host_ed25519_key";
    if (access(host_key, R_OK) != 0) {
        char *keygen[] = {
            STAGE_ROOT "/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
            "-N", "", "-f", (char *)host_key, NULL};
        if (run(keygen) != 0) return 1;
    }

    setenv("PATH", "/var/jb/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin", 1);
    char *sshd[] = {
        STAGE_ROOT "/usr/sbin/sshd", "-D", "-e", "-f",
        "/usr/local/share/codex-stage-ssh/sshd_config", NULL};
    execve(sshd[0], sshd, environ);
    return 1;
}
