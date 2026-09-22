#include <dirent.h>
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
#define LINK_ROOT STAGE_STATE "/jb"

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

static bool mirror_entries(const char *source, const char *destination,
                           const char *skip) {
    DIR *directory = opendir(source);
    if (directory == NULL) return false;
    bool mirrored = true;
    const struct dirent *entry;
    while (mirrored && (entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            (skip != NULL && strcmp(entry->d_name, skip) == 0)) {
            continue;
        }
        char target[PATH_MAX];
        char link[PATH_MAX];
        if (snprintf(target, sizeof(target), "%s/%s", source, entry->d_name) >=
                (int)sizeof(target) ||
            snprintf(link, sizeof(link), "%s/%s", destination,
                     entry->d_name) >= (int)sizeof(link)) {
            mirrored = false;
            break;
        }
        if (symlink(target, link) == 0) continue;
        if (errno != EEXIST) {
            mirrored = false;
            break;
        }
        // Repoint a stale symlink from an earlier install's mount path; keep
        // a real file, which the caller copied in deliberately.
        struct stat existing;
        if (lstat(link, &existing) == 0 && S_ISLNK(existing.st_mode) &&
            (unlink(link) != 0 || symlink(target, link) != 0)) {
            mirrored = false;
        }
    }
    closedir(directory);
    return mirrored;
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

static bool copy_regular_file(const char *source, const char *destination,
                              mode_t mode) {
    int input = open(source, O_RDONLY | O_CLOEXEC);
    if (input < 0) return false;
    int output = open(destination,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      mode);
    if (output < 0) {
        close(input);
        return false;
    }
    unsigned char buffer[64U * 1024U];
    bool copied = true;
    for (;;) {
        ssize_t amount = read(input, buffer, sizeof(buffer));
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) {
            copied = false;
            break;
        }
        if (amount == 0) break;
        if (!write_all(output, buffer, (size_t)amount)) {
            copied = false;
            break;
        }
    }
    copied = copied && fchown(output, 0, 0) == 0 && fchmod(output, mode) == 0;
    close(input);
    close(output);
    if (!copied) (void)unlink(destination);
    return copied;
}

// /var/jb cannot point straight into the read-only cryptex mount: iOS 27.2
// denies file-write-owner there, so sshd's root-owned privilege-separation
// directory cannot be prepared, and pwd_mkdb cannot write the user databases
// libiosexec's ie_getpwnam requires.  Build a small writable root instead and
// symlink everything else back into the image.
static bool build_jailbreak_overlay(const char *stage_root) {
    char stage_var[PATH_MAX];
    char stage_etc[PATH_MAX];
    char source[PATH_MAX];
    if (!ensure_directory(LINK_ROOT, 0755) ||
        !ensure_directory(LINK_ROOT "/var", 0755) ||
        !ensure_directory(LINK_ROOT "/var/empty", 0755) ||
        !ensure_directory(LINK_ROOT "/etc", 0755) ||
        snprintf(stage_var, sizeof(stage_var), "%s/var", stage_root) >=
            (int)sizeof(stage_var) ||
        snprintf(stage_etc, sizeof(stage_etc), "%s/etc", stage_root) >=
            (int)sizeof(stage_etc)) {
        return false;
    }
    // pwd_mkdb's input, and the group file libiosexec reads, must be real
    // files here rather than symlinks into the read-only mount.
    static const char *const copied[] = {"master.passwd", "group"};
    static const mode_t copied_modes[] = {0600, 0644};
    for (size_t index = 0; index < sizeof(copied) / sizeof(copied[0]);
         ++index) {
        char destination[PATH_MAX];
        if (snprintf(source, sizeof(source), "%s/%s", stage_etc,
                     copied[index]) >= (int)sizeof(source) ||
            snprintf(destination, sizeof(destination), "%s/%s",
                     LINK_ROOT "/etc", copied[index]) >=
                (int)sizeof(destination) ||
            !copy_regular_file(source, destination, copied_modes[index])) {
            return false;
        }
    }
    // pwd_mkdb -p regenerates "passwd", so it must not be a symlink.
    return mirror_entries(stage_root, LINK_ROOT, "var") &&
           mirror_entries(stage_var, LINK_ROOT "/var", "empty") &&
           mirror_entries(stage_etc, LINK_ROOT "/etc", "passwd");
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

    // An OS update repoints the active preboot directory, orphaning any
    // /var/jb a previous install left behind; lstat() does not follow
    // symlinks, so such a link used to be adopted silently.  Replace it, and
    // always rebuild our own, whose entries point at a cryptex mount path
    // that changes with every install.  A link belonging to a live install
    // still resolves and is left alone, as is a real directory.
    struct stat status;
    bool create_link = false;
    if (lstat("/var/jb", &status) != 0) {
        if (errno != ENOENT) return 1;
        create_link = true;
    } else if (S_ISLNK(status.st_mode)) {
        char existing[PATH_MAX];
        ssize_t length = readlink("/var/jb", existing, sizeof(existing) - 1U);
        if (length > 0) existing[length] = '\0';
        bool ours = length > 0 && strcmp(existing, LINK_ROOT) == 0;
        bool orphaned = stat("/var/jb", &status) != 0 && errno == ENOENT;
        if (ours || orphaned) {
            os_log(stage_log(), "replacing %{public}s /var/jb symlink",
                   ours ? "this launcher's own" : "an orphaned");
            if (unlink("/var/jb") != 0) return 1;
            create_link = true;
        }
    }
    if (create_link) {
        if (!build_jailbreak_overlay(stage_root)) {
            os_log_error(stage_log(),
                         "could not build the /var/jb overlay errno=%d", errno);
            return 1;
        }
        if (symlink(LINK_ROOT, "/var/jb") != 0) return 1;
        // A marker from an earlier install would fail the O_EXCL open below.
        (void)unlink(CREATED_MARKER);
        int marker = open(CREATED_MARKER,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker < 0 || !write_all(marker, LINK_ROOT, strlen(LINK_ROOT)) ||
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
    // Generate the databases ie_getpwnam reads, the same way prep_bootstrap.sh
    // does; without them sshd's privilege-separation lookup returns NULL.
    // Only for our own overlay: a live install has its own.
    if (create_link) {
        char pwd_mkdb[PATH_MAX];
        if (snprintf(pwd_mkdb, sizeof(pwd_mkdb), "%s/usr/sbin/pwd_mkdb",
                     stage_root) >= (int)sizeof(pwd_mkdb)) {
            return 1;
        }
        char *make_databases[] = {pwd_mkdb, "-p", "/var/jb/etc/master.passwd",
                                  NULL};
        int database_status = run_and_log(make_databases);
        if (database_status != 0) {
            os_log_error(stage_log(), "pwd_mkdb failed status=%d",
                         database_status);
            return database_status;
        }
    }

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
