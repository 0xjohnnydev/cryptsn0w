#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;
extern int64_t sandbox_extension_consume(const char *extension_token);

static int read_jailbreak_root(os_log_t log, char *root, size_t rootSize) {
    const char *home = getenv("HOME");
    if (home == NULL || home[0] != '/') {
        os_log_error(log, "HOME is unavailable");
        return -1;
    }
    char path[4096];
    int length = snprintf(path, sizeof(path),
                          "%s/Library/CodexBootstrap/jailbreak-root", home);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        os_log_error(log, "jailbreak-root path is too long");
        return -1;
    }
    FILE *stream = fopen(path, "r");
    if (stream == NULL || fgets(root, (int)rootSize, stream) == NULL) {
        os_log_error(log, "jailbreak-root file unavailable: %{public}s",
                     strerror(errno));
        if (stream != NULL) {
            fclose(stream);
        }
        return -1;
    }
    bool hasExtraData = fgets(path, sizeof(path), stream) != NULL;
    int readError = ferror(stream) ? errno : 0;
    fclose(stream);
    root[strcspn(root, "\r\n")] = '\0';
    if (readError != 0 || hasExtraData ||
        strncmp(root, "/private/preboot/", 17) != 0 ||
        strstr(root, "/../") != NULL || strstr(root, "/./") != NULL) {
        os_log_error(log, "jailbreak-root file is invalid");
        memset(root, 0, rootSize);
        return -1;
    }
    return 0;
}

static int consume_sandbox_extensions(os_log_t log) {
    const char *home = getenv("HOME");
    if (home == NULL || home[0] != '/') {
        os_log_error(log, "HOME is unavailable");
        return -1;
    }
    char directory[4096];
    char request[4096];
    char response[4096];
    pid_t pid = getpid();
    int lengths[] = {
        snprintf(directory, sizeof(directory),
                 "%s/Library/CodexBootstrap", home),
        snprintf(request, sizeof(request),
                 "%s/Library/CodexBootstrap/broker-request-%d", home, pid),
        snprintf(response, sizeof(response),
                 "%s/Library/CodexBootstrap/broker-response-%d", home, pid),
    };
    size_t capacities[] = {sizeof(directory), sizeof(request),
                           sizeof(response)};
    for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]);
         ++index) {
        if (lengths[index] < 0 ||
            (size_t)lengths[index] >= capacities[index]) {
            os_log_error(log, "sandbox broker file path is too long");
            return -1;
        }
    }
    (void)unlink(request);
    (void)unlink(response);
    int requestFile = open(request,
                           O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                               O_NOFOLLOW,
                           0600);
    if (requestFile < 0 || dprintf(requestFile, "%d\n", pid) < 0 ||
        close(requestFile) != 0) {
        os_log_error(log, "sandbox broker request failed: %{public}s",
                     strerror(errno));
        if (requestFile >= 0) {
            close(requestFile);
        }
        (void)unlink(request);
        return -1;
    }

    FILE *stream = NULL;
    for (unsigned int attempt = 0; attempt < 500; ++attempt) {
        stream = fopen(response, "r");
        if (stream != NULL) {
            break;
        }
        if (errno != ENOENT) {
            break;
        }
        usleep(10 * 1000);
    }
    if (stream == NULL) {
        os_log_error(log, "sandbox broker response unavailable: %{public}s",
                     strerror(errno));
        (void)unlink(request);
        return -1;
    }
    char token[4096];
    unsigned int count = 0;
    while (fgets(token, sizeof(token), stream) != NULL) {
        size_t tokenLength = strcspn(token, "\r\n");
        token[tokenLength] = '\0';
        if (tokenLength == 0) {
            continue;
        }
        int64_t handle = sandbox_extension_consume(token);
        memset(token, 0, sizeof(token));
        if (handle < 0) {
            os_log_error(log, "sandbox extension consume failed");
            fclose(stream);
            (void)unlink(request);
            (void)unlink(response);
            return -1;
        }
        ++count;
    }
    int readError = ferror(stream) ? errno : 0;
    fclose(stream);
    (void)unlink(request);
    (void)unlink(response);
    memset(token, 0, sizeof(token));
    if (readError != 0 || count != 4) {
        os_log_error(log,
                     "sandbox broker response invalid: count=%{public}u "
                     "error=%{public}s",
                     count, readError == 0 ? "none" : strerror(readError));
        return -1;
    }
    os_log(log, "consumed %{public}u sandbox extensions", count);
    return 0;
}

int main(int argc, char *argv[]) {
    os_log_t log = os_log_create("com.openai.codex.dopamine.bootstrap",
                                 "sileo-launcher");
    char jailbreakRoot[4096];
    if (read_jailbreak_root(log, jailbreakRoot, sizeof(jailbreakRoot)) != 0) {
        return 126;
    }
    if (consume_sandbox_extensions(log) != 0) {
        return 126;
    }
    char target[4096];
    char executablePath[4096];
    char appDirectory[4096];
    char pathEnvironment[8192];
    char shell[4096];
    char libraryPath[4096];
    uint32_t executablePathSize = sizeof(executablePath);
    if (_NSGetExecutablePath(executablePath, &executablePathSize) != 0 ||
        executablePath[0] != '/') {
        os_log_error(log, "registered executable path is unavailable");
        return 126;
    }
    char *lastSlash = strrchr(executablePath, '/');
    if (lastSlash == NULL || lastSlash == executablePath) {
        os_log_error(log, "registered executable path is invalid");
        return 126;
    }
    *lastSlash = '\0';
    int lengths[] = {
        snprintf(target, sizeof(target), "%s/Sileo.real", executablePath),
        snprintf(appDirectory, sizeof(appDirectory), "%s", executablePath),
        snprintf(pathEnvironment, sizeof(pathEnvironment),
                 "%s/usr/bin:%s/bin:%s/usr/sbin:%s/sbin:"
                 "/usr/bin:/bin:/usr/sbin:/sbin",
                 jailbreakRoot, jailbreakRoot, jailbreakRoot, jailbreakRoot),
        snprintf(shell, sizeof(shell), "%s/bin/sh", jailbreakRoot),
        snprintf(libraryPath, sizeof(libraryPath), "%s/usr/lib",
                 jailbreakRoot),
    };
    size_t capacities[] = {sizeof(target), sizeof(appDirectory),
                           sizeof(pathEnvironment), sizeof(shell),
                           sizeof(libraryPath)};
    for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]);
         ++index) {
        if (lengths[index] < 0 ||
            (size_t)lengths[index] >= capacities[index]) {
            os_log_error(log, "resolved bootstrap path is too long");
            return 126;
        }
    }
    (void)chdir(appDirectory);
    setenv("PATH", pathEnvironment, 1);
    setenv("SHELL", shell, 1);
    setenv("DYLD_LIBRARY_PATH", libraryPath, 1);

    char **targetArgv = calloc((size_t)argc + 1, sizeof(char *));
    if (targetArgv == NULL) {
        os_log_error(log, "argv allocation failed");
        return 125;
    }
    targetArgv[0] = target;
    for (int index = 1; index < argc; ++index) {
        targetArgv[index] = argv[index];
    }
    os_log(log, "execing same-bundle Cryptex-trusted Sileo directly");
    execve(target, targetArgv, environ);
    int savedError = errno;
    os_log_error(log, "execve failed: %{public}s", strerror(savedError));
    free(targetArgv);
    return savedError == ENOEXEC || savedError == EACCES ? 126 : 127;
}
