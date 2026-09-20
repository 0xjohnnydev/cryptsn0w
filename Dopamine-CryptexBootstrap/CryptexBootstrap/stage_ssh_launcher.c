#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STAGE_STATE "/private/var/tmp/codex-stage-ssh"
#define CREATED_MARKER STAGE_STATE "/created-var-jb"
#define CLEANUP_EXECUTABLE STAGE_STATE "/cleanup"

extern char **environ;
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);

static os_log_t stage_log(void) {
    static os_log_t log;
    if (log == NULL) {
        log = os_log_create("com.openai.codex.dopamine.bootstrap", "ssh-stage");
    }
    return log;
}

static bool ensure_directory(const char *path, mode_t mode) {
    if (mkdir(path, mode) != 0 && errno != EEXIST) return false;
    struct stat status;
    return lstat(path, &status) == 0 && S_ISDIR(status.st_mode) &&
           !S_ISLNK(status.st_mode) && chown(path, 0, 0) == 0 &&
           chmod(path, mode) == 0;
}

static bool secure_privilege_separation_directory(void) {
    static const char path[] = "/var/jb/var/empty";
    struct stat status;
    if (lstat(path, &status) != 0 || !S_ISDIR(status.st_mode) ||
        S_ISLNK(status.st_mode)) {
        return false;
    }
    return chown(path, 0, 0) == 0 && chmod(path, 0755) == 0;
}

static bool write_all(int descriptor, const void *bytes, size_t size) {
    const unsigned char *cursor = bytes;
    while (size != 0) {
        ssize_t amount = write(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return false;
        cursor += amount;
        size -= (size_t)amount;
    }
    return true;
}

static bool executable_and_stage_root(char executable[PATH_MAX],
                                      char stage_root[PATH_MAX]) {
    static const char suffix[] =
        "/usr/local/bin/codex-dopamine-bootstrap";
    if (proc_pidpath(getpid(), executable, PATH_MAX) <= 0) {
        uint32_t size = PATH_MAX;
        if (_NSGetExecutablePath(executable, &size) != 0) return false;
    }
    char *location = strstr(executable, suffix);
    if (location == NULL || location[strlen(suffix)] != '\0') return false;
    *location = '\0';
    int length = snprintf(stage_root, PATH_MAX,
                          "%s/usr/local/share/codex-stage-ssh/root",
                          executable);
    *location = '/';
    return length > 0 && length < PATH_MAX;
}

static bool install_cleanup_copy(const char *source) {
    char temporary[] = STAGE_STATE "/.cleanup.XXXXXX";
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int output = mkstemp(temporary);
    if (input < 0 || output < 0) {
        if (input >= 0) close(input);
        if (output >= 0) close(output);
        return false;
    }
    unsigned char buffer[64U * 1024U];
    bool copied = true;
    for (;;) {
        ssize_t amount = read(input, buffer, sizeof(buffer));
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) copied = false;
        if (amount <= 0) break;
        if (!write_all(output, buffer, (size_t)amount)) {
            copied = false;
            break;
        }
    }
    copied = copied && fchmod(output, 0700) == 0 && fchown(output, 0, 0) == 0;
    close(input);
    close(output);
    if (!copied || rename(temporary, CLEANUP_EXECUTABLE) != 0) {
        (void)unlink(temporary);
        return false;
    }
    return true;
}

static int run_and_log(char *const arguments[]) {
    int descriptors[2];
    if (pipe(descriptors) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(descriptors[0]);
        (void)dup2(descriptors[1], STDOUT_FILENO);
        (void)dup2(descriptors[1], STDERR_FILENO);
        close(descriptors[1]);
        execve(arguments[0], arguments, environ);
        dprintf(STDERR_FILENO, "exec failed errno=%d\n", errno);
        _exit(127);
    }
    close(descriptors[1]);
    char buffer[2048];
    for (;;) {
        ssize_t amount = read(descriptors[0], buffer, sizeof(buffer) - 1U);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) break;
        buffer[amount] = '\0';
        os_log(stage_log(), "sshd: %{public}s", buffer);
    }
    close(descriptors[0]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static int cleanup(void) {
    FILE *marker = fopen(CREATED_MARKER, "r");
    if (marker != NULL) {
        char expected[PATH_MAX] = {0};
        char target[PATH_MAX] = {0};
        bool read_expected = fgets(expected, sizeof(expected), marker) != NULL;
        fclose(marker);
        expected[strcspn(expected, "\r\n")] = '\0';
        ssize_t length = readlink("/var/jb", target, sizeof(target) - 1U);
        if (!read_expected || length <= 0 || (size_t)length >= sizeof(target) ||
            strcmp(target, expected) != 0 || unlink("/var/jb") != 0) {
            return 1;
        }
        (void)unlink(CREATED_MARKER);
    }
    if (!write_all(STDOUT_FILENO, "handoff-ready\n", 14U)) return 1;

    unsigned char trigger = 0;
    ssize_t amount;
    do {
        amount = read(STDIN_FILENO, &trigger, sizeof(trigger));
    } while (amount < 0 && errno == EINTR);
    if (amount != 1) return 2;

    FILE *pid_file = fopen(STAGE_STATE "/sshd.pid", "r");
    long raw_pid = 0;
    if (pid_file == NULL || fscanf(pid_file, "%ld", &raw_pid) != 1 ||
        raw_pid <= 1 || raw_pid > INT_MAX) {
        if (pid_file != NULL) fclose(pid_file);
        return 1;
    }
    fclose(pid_file);
    pid_t killer = fork();
    if (killer < 0) return 1;
    if (killer == 0) {
        (void)setsid();
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        usleep(500U * 1000U);
        _exit(kill((pid_t)raw_pid, SIGTERM) == 0 ? 0 : 1);
    }
    return write_all(STDOUT_FILENO, "handoff-armed\n", 14U) ? 0 : 1;
}

int main(int argc, char **argv) {
    os_log(stage_log(), "start pid=%d uid=%u euid=%u argc=%d", getpid(),
           getuid(), geteuid(), argc);
    if (geteuid() != 0) return 1;
    if (argc == 2 && strcmp(argv[1], "--cleanup") == 0) return cleanup();
    if (argc != 1 || !ensure_directory(STAGE_STATE, 0700)) return 1;

    char executable[PATH_MAX] = {0};
    char stage_root[PATH_MAX] = {0};
    if (!executable_and_stage_root(executable, stage_root) ||
        !install_cleanup_copy(executable)) {
        os_log_error(stage_log(), "stage path setup failed errno=%d", errno);
        return 1;
    }

    struct stat status;
    if (lstat("/var/jb", &status) != 0) {
        if (errno != ENOENT || symlink(stage_root, "/var/jb") != 0) return 1;
        int marker = open(CREATED_MARKER,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker < 0 || !write_all(marker, stage_root, strlen(stage_root)) ||
            !write_all(marker, "\n", 1U)) {
            if (marker >= 0) close(marker);
            (void)unlink("/var/jb");
            return 1;
        }
        close(marker);
    }
    if (!secure_privilege_separation_directory()) {
        os_log_error(stage_log(),
                     "could not secure sshd privilege-separation directory");
        return 1;
    }

    char payload_root[PATH_MAX], sshd[PATH_MAX], config[PATH_MAX];
    char host_key[PATH_MAX], authorized_keys[PATH_MAX];
    char host_option[PATH_MAX + 16U], authorized_option[PATH_MAX + 32U];
    size_t root_length = strlen(stage_root);
    if (root_length <= strlen("/root")) return 1;
    int mount_prefix = (int)(root_length - strlen("/root"));
    if (snprintf(payload_root, sizeof(payload_root), "%.*s", mount_prefix,
                 stage_root) >= (int)sizeof(payload_root) ||
        snprintf(sshd, sizeof(sshd), "%s/usr/sbin/sshd", stage_root) >=
            (int)sizeof(sshd) ||
        snprintf(config, sizeof(config), "%s/sshd_config", payload_root) >=
            (int)sizeof(config) ||
        snprintf(host_key, sizeof(host_key), "%s/host-key", payload_root) >=
            (int)sizeof(host_key) ||
        snprintf(authorized_keys, sizeof(authorized_keys), "%s/authorized_keys",
                 payload_root) >= (int)sizeof(authorized_keys) ||
        snprintf(host_option, sizeof(host_option), "HostKey=%s", host_key) >=
            (int)sizeof(host_option) ||
        snprintf(authorized_option, sizeof(authorized_option),
                 "AuthorizedKeysFile=%s", authorized_keys) >=
            (int)sizeof(authorized_option)) {
        return 1;
    }
    setenv("PATH", "/var/jb/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin", 1);
    char *preflight[] = {sshd, "-t", "-f", config, "-o", host_option,
                         "-o", authorized_option, NULL};
    int server_status = run_and_log(preflight);
    if (server_status != 0) {
        os_log_error(stage_log(), "sshd preflight failed status=%d",
                     server_status);
        return server_status;
    }
    char *server[] = {sshd, "-D", "-e", "-f", config, "-o", host_option,
                      "-o", authorized_option, NULL};
    os_log(stage_log(), "starting sshd path=%{public}s", sshd);
    server_status = run_and_log(server);
    os_log_error(stage_log(), "sshd exited status=%d", server_status);
    return server_status;
}
