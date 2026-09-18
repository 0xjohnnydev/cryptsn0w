#include "sileo_root_broker_protocol.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include <pthread.h>
#include <stdarg.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xpc/xpc.h>

extern char **environ;
extern int64_t sandbox_extension_consume(const char *extension_token);
extern int sandbox_check(pid_t pid, const char *operation, int filter, ...);

#define CODEX_SANDBOX_FILTER_GLOBAL_NAME 2

#define CODEX_MAX_DUP_ACTIONS 16U
#define CODEX_FAKE_PID_FIRST ((pid_t)0x3f000000)

struct codex_dup_action {
    int source;
    int target;
};

struct codex_action_record {
    const posix_spawn_file_actions_t *key;
    uint32_t count;
    struct codex_dup_action actions[CODEX_MAX_DUP_ACTIONS];
    struct codex_action_record *next;
};

struct codex_virtual_job {
    pid_t pid;
    uint32_t argument_count;
    char *arguments[CODEX_ROOT_BROKER_MAX_ARGUMENTS + 1U];
    uint32_t environment_count;
    char *environment[CODEX_ROOT_BROKER_MAX_ENVIRONMENT + 1U];
    uint32_t descriptor_count;
    int descriptors[CODEX_ROOT_BROKER_MAX_FDS];
    int descriptor_numbers[CODEX_ROOT_BROKER_MAX_FDS];
    bool complete;
    int32_t status;
    pthread_cond_t condition;
    struct codex_virtual_job *next;
};

static pthread_mutex_t gStateLock = PTHREAD_MUTEX_INITIALIZER;
static struct codex_action_record *gActionRecords;
static struct codex_virtual_job *gVirtualJobs;
static pid_t gNextFakePid = CODEX_FAKE_PID_FIRST;
static os_log_t gConstructorLog;
static __thread bool gFilesystemTraceActive;
static char gJailbreakRoot[PATH_MAX];

static bool is_apt_list_path(const char *path) {
    return path != NULL &&
           (strstr(path, "/var/jb/var/lib/apt/lists") != NULL ||
            strstr(path, "/procursus/var/lib/apt/lists") != NULL ||
            strstr(path, "apt.procurs.us_dists_") != NULL ||
            strstr(path, "_Packages") != NULL);
}

static void trace_filesystem_result(const char *operation, const char *path,
                                    int result, int savedError, int flags) {
    if (gConstructorLog == NULL || gFilesystemTraceActive ||
        !is_apt_list_path(path)) {
        return;
    }
    gFilesystemTraceActive = true;
    os_log(gConstructorLog,
           "apt filesystem trace operation=%{public}s path=%{public}s "
           "result=%{public}d errno=%{public}d flags=%{public}d",
           operation, path, result, savedError, flags);
    gFilesystemTraceActive = false;
}

static int codex_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    bool hasMode = (flags & O_CREAT) != 0;
    if (hasMode) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    errno = 0;
    // An __interpose tuple is not applied to binds originating in the image
    // that owns the tuple.  Call libSystem through this image's normal stub;
    // RTLD_NEXT can resolve back to this shim on dyld4 and recurse before any
    // constructor has run.
    int result = hasMode ? open(path, flags, mode) : open(path, flags);
    int savedError = errno;
    trace_filesystem_result("open", path, result, savedError, flags);
    errno = savedError;
    return result;
}

static FILE *codex_fopen(const char *path, const char *mode) {
    errno = 0;
    FILE *result = fopen(path, mode);
    int savedError = errno;
    trace_filesystem_result("fopen", path, result != NULL ? 0 : -1,
                            savedError, 0);
    errno = savedError;
    return result;
}

static int codex_stat(const char *path, struct stat *status) {
    errno = 0;
    int result = stat(path, status);
    int savedError = errno;
    trace_filesystem_result("stat", path, result, savedError, 0);
    errno = savedError;
    return result;
}

static int codex_access(const char *path, int mode) {
    errno = 0;
    int result = access(path, mode);
    int savedError = errno;
    trace_filesystem_result("access", path, result, savedError, mode);
    errno = savedError;
    return result;
}

static bool run_broker_request(char *const arguments[], uint32_t argumentCount,
                               char *const environment[],
                               uint32_t environmentCount,
                               const int descriptors[],
                               const int descriptorNumbers[],
                               uint32_t descriptorCount,
                               int32_t *statusOut) {
    if (argumentCount == 0 ||
        argumentCount > CODEX_ROOT_BROKER_MAX_ARGUMENTS ||
        environmentCount > CODEX_ROOT_BROKER_MAX_ENVIRONMENT ||
        descriptorCount == 0 || descriptorCount > CODEX_ROOT_BROKER_MAX_FDS) {
        errno = E2BIG;
        return false;
    }
    for (uint32_t index = 0; index < argumentCount; ++index) {
        size_t argumentLength = strnlen(arguments[index], PATH_MAX * 4U);
        if (argumentLength == PATH_MAX * 4U) {
            errno = E2BIG;
            return false;
        }
    }
    for (uint32_t index = 0; index < environmentCount; ++index) {
        size_t environmentLength = strnlen(environment[index], 64U);
        if (environmentLength == 64U) {
            errno = E2BIG;
            return false;
        }
    }

    typedef xpc_connection_t (*xpc_create_mach_service_function)(
        const char *, dispatch_queue_t, uint64_t);
    xpc_create_mach_service_function createMachService =
        (xpc_create_mach_service_function)dlsym(
            RTLD_DEFAULT, "xpc_connection_create_mach_service");
    xpc_connection_t connection =
        createMachService != NULL
            ? createMachService(CODEX_ROOT_BROKER_MACH_SERVICE, NULL, 0)
            : NULL;
    if (connection == NULL) {
        errno = ECONNREFUSED;
        return false;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t argumentArray = xpc_array_create(NULL, 0);
    xpc_object_t environmentArray = xpc_array_create(NULL, 0);
    xpc_object_t descriptorArray = xpc_array_create(NULL, 0);
    for (uint32_t index = 0; index < argumentCount; ++index) {
        xpc_array_set_string(argumentArray, XPC_ARRAY_APPEND,
                             arguments[index]);
    }
    for (uint32_t index = 0; index < environmentCount; ++index) {
        xpc_array_set_string(environmentArray, XPC_ARRAY_APPEND,
                             environment[index]);
    }
    for (uint32_t index = 0; index < descriptorCount; ++index) {
        xpc_array_set_int64(descriptorArray, XPC_ARRAY_APPEND,
                            descriptorNumbers[index]);
        char key[32];
        int keyLength = snprintf(key, sizeof(key), "descriptor-%u", index);
        if (keyLength < 0 || (size_t)keyLength >= sizeof(key)) {
            xpc_connection_cancel(connection);
            xpc_release(descriptorArray);
            xpc_release(environmentArray);
            xpc_release(argumentArray);
            xpc_release(message);
            xpc_release(connection);
            errno = EINVAL;
            return false;
        }
        xpc_dictionary_set_fd(message, key, descriptors[index]);
    }
    xpc_dictionary_set_value(message, "arguments", argumentArray);
    xpc_dictionary_set_value(message, "control-environment", environmentArray);
    xpc_dictionary_set_value(message, "descriptor-numbers", descriptorArray);
    xpc_object_t reply =
        xpc_connection_send_message_with_reply_sync(connection, message);
    bool validReply = reply != NULL &&
                      xpc_get_type(reply) == XPC_TYPE_DICTIONARY &&
                      xpc_dictionary_get_bool(reply, "accepted") &&
                      xpc_dictionary_get_bool(reply, "valid") &&
                      xpc_dictionary_get_bool(reply, "allowed");
    if (reply != NULL && xpc_get_type(reply) == XPC_TYPE_ERROR) {
        const char *description =
            xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION);
        os_log_error(gConstructorLog, "root broker XPC error: %{public}s",
                     description != NULL ? description : "unknown");
    } else if (reply != NULL && xpc_get_type(reply) == XPC_TYPE_DICTIONARY &&
               !validReply) {
        os_log_error(
            gConstructorLog,
            "root broker rejected: accepted=%{public}s valid=%{public}s "
            "allowed=%{public}s",
            xpc_dictionary_get_bool(reply, "accepted") ? "true" : "false",
            xpc_dictionary_get_bool(reply, "valid") ? "true" : "false",
            xpc_dictionary_get_bool(reply, "allowed") ? "true" : "false");
    }
    if (validReply && statusOut != NULL) {
        *statusOut = (int32_t)xpc_dictionary_get_int64(reply, "status");
    }
    if (reply != NULL) {
        xpc_release(reply);
    }
    xpc_connection_cancel(connection);
    xpc_release(descriptorArray);
    xpc_release(environmentArray);
    xpc_release(argumentArray);
    xpc_release(message);
    xpc_release(connection);
    if (!validReply) {
        errno = EPERM;
    }
    return validReply;
}

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

static int consume_process_bound_extensions(os_log_t log) {
    const char *home = getenv("HOME");
    if (home == NULL || home[0] != '/') {
        os_log_error(log, "HOME is unavailable");
        return -1;
    }
    char request[4096];
    char response[4096];
    pid_t pid = getpid();
    int requestLength = snprintf(
        request, sizeof(request),
        "%s/Library/CodexBootstrap/broker-request-%d", home, pid);
    int responseLength = snprintf(
        response, sizeof(response),
        "%s/Library/CodexBootstrap/broker-response-%d", home, pid);
    if (requestLength < 0 || (size_t)requestLength >= sizeof(request) ||
        responseLength < 0 || (size_t)responseLength >= sizeof(response)) {
        os_log_error(log, "sandbox broker path is too long");
        return -1;
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
    if (readError != 0 || count != 6) {
        os_log_error(log,
                     "sandbox broker response invalid: count=%{public}u "
                     "error=%{public}s",
                     count, readError == 0 ? "none" : strerror(readError));
        return -1;
    }
    os_log(log, "constructor consumed %{public}u sandbox extensions", count);
    errno = 0;
    int machLookup = sandbox_check(
        getpid(), "mach-lookup", CODEX_SANDBOX_FILTER_GLOBAL_NAME,
        CODEX_ROOT_BROKER_MACH_SERVICE);
    int machLookupError = errno;
    os_log(log,
           "root broker sandbox_check result=%{public}d errno=%{public}d",
           machLookup, machLookupError);
    return 0;
}

static void probe_apt_lists_access(os_log_t log, const char *jailbreakRoot) {
    static const char packagesLeaf[] =
        "apt.procurs.us_dists_1900_main_binary-iphoneos-arm64_Packages";
    char canonicalDirectory[PATH_MAX];
    int canonicalLength = snprintf(canonicalDirectory,
                                   sizeof(canonicalDirectory),
                                   "%s/var/lib/apt/lists", jailbreakRoot);
    if (canonicalLength < 0 ||
        (size_t)canonicalLength >= sizeof(canonicalDirectory)) {
        os_log_error(log, "apt lists canonical path is too long");
        return;
    }
    const char *directories[] = {
        "/var/jb/var/lib/apt/lists",
        canonicalDirectory,
    };
    for (size_t index = 0;
         index < sizeof(directories) / sizeof(directories[0]); ++index) {
        const char *directory = directories[index];
        struct stat status;
        errno = 0;
        int statResult = stat(directory, &status);
        int statError = errno;
        errno = 0;
        DIR *stream = opendir(directory);
        int directoryError = errno;

        char packagesPath[PATH_MAX];
        int packagesLength = snprintf(packagesPath, sizeof(packagesPath),
                                      "%s/%s", directory, packagesLeaf);
        int fileDescriptor = -1;
        int openError = ENAMETOOLONG;
        ssize_t readResult = -1;
        int readError = 0;
        if (packagesLength >= 0 &&
            (size_t)packagesLength < sizeof(packagesPath)) {
            errno = 0;
            fileDescriptor = open(packagesPath,
                                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            openError = errno;
            if (fileDescriptor >= 0) {
                unsigned char byte = 0;
                errno = 0;
                readResult = read(fileDescriptor, &byte, sizeof(byte));
                readError = errno;
                close(fileDescriptor);
            }
        }
        if (stream != NULL) {
            closedir(stream);
        }
        os_log(log,
               "apt lists probe path=%{public}s stat=%{public}d "
               "statErrno=%{public}d mode=%{public}o opendir=%{public}s "
               "dirErrno=%{public}d packagesOpen=%{public}s "
               "openErrno=%{public}d read=%{public}lld "
               "readErrno=%{public}d",
               directory, statResult, statError,
               statResult == 0 ? (unsigned int)status.st_mode : 0U,
               stream != NULL ? "true" : "false", directoryError,
               fileDescriptor >= 0 ? "true" : "false", openError,
               (long long)readResult, readError);
    }
}

static int verify_root_broker(os_log_t log) {
    int outputPipe[2];
    if (pipe(outputPipe) != 0) {
        os_log_error(log, "root broker pipe failed: %{public}s",
                     strerror(errno));
        return -1;
    }
    char *arguments[] = {"/var/jb/usr/bin/whoami", NULL};
    int descriptors[] = {outputPipe[1]};
    int descriptorNumbers[] = {STDOUT_FILENO};
    int32_t status = 0;
    bool ran = run_broker_request(arguments, 1, NULL, 0, descriptors,
                                  descriptorNumbers, 1, &status);
    close(outputPipe[1]);
    if (!ran) {
        close(outputPipe[0]);
        os_log_error(log, "root broker preflight request failed: %{public}s",
                     strerror(errno));
        return -1;
    }
    char output[32] = {0};
    ssize_t outputLength;
    do {
        outputLength = read(outputPipe[0], output, sizeof(output) - 1);
    } while (outputLength < 0 && errno == EINTR);
    close(outputPipe[0]);
    if (outputLength < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        (strcmp(output, "root\n") != 0 && strcmp(output, "root") != 0)) {
        os_log_error(log,
                     "root broker preflight failed: status=%{public}d "
                     "output=%{public}s",
                     status, outputLength >= 0 ? output : "read-error");
        return -1;
    }
    os_log(log, "root broker preflight complete");
    return 0;
}

static bool is_hex_character(char character) {
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f') ||
           (character >= 'A' && character <= 'F');
}

static bool is_managed_documents_deb_path(const char *path) {
    static const char prefix[] =
        "/private/var/mobile/Containers/Data/Application/";
    static const char documents[] = "/Documents/";
    if (path == NULL || strncmp(path, prefix, sizeof(prefix) - 1U) != 0 ||
        strstr(path, "/../") != NULL || strstr(path, "/./") != NULL) {
        return false;
    }
    const char *identifier = path + sizeof(prefix) - 1U;
    for (size_t index = 0; index < 36U; ++index) {
        bool separator = index == 8U || index == 13U || index == 18U ||
                         index == 23U;
        if ((separator && identifier[index] != '-') ||
            (!separator && !is_hex_character(identifier[index]))) {
            return false;
        }
    }
    const char *leaf = identifier + 36U;
    if (strncmp(leaf, documents, sizeof(documents) - 1U) != 0) {
        return false;
    }
    leaf += sizeof(documents) - 1U;
    size_t leafLength = strnlen(leaf, NAME_MAX + 1U);
    return leafLength > strlen(".deb") && leafLength <= NAME_MAX &&
           strchr(leaf, '/') == NULL &&
           strcmp(leaf + leafLength - strlen(".deb"), ".deb") == 0;
}

static bool parse_debugserver_loopback_port(const char *text,
                                            unsigned int *portOut) {
    if (text == NULL || text[0] == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 49152UL ||
        value > 65535UL) {
        return false;
    }
    *portOut = (unsigned int)value;
    return true;
}

static bool run_postboot_driver(os_log_t log, int *exitCode) {
    const char *mode = getenv("CODEX_POSTBOOT_DRIVER");
    if (mode == NULL) {
        return false;
    }
    const char *debPath = getenv("CODEX_POSTBOOT_INSTALL_DEB");
    bool installDeb = strcmp(mode, "install-deb-v1") == 0;
    bool debugserverLoopback =
        strcmp(mode, "debugserver-loopback-v1") == 0;
    unsigned int debugserverPort = 0;
    const char *debugserverPortText =
        getenv("CODEX_POSTBOOT_DEBUGSERVER_PORT");
    if ((!installDeb && !debugserverLoopback) ||
        (installDeb && !is_managed_documents_deb_path(debPath)) ||
        (debugserverLoopback &&
         !parse_debugserver_loopback_port(debugserverPortText,
                                          &debugserverPort))) {
        os_log_error(log,
                     "postboot driver rejected mode=%{public}s "
                     "path=%{public}s port=%{public}s",
                     mode, debPath != NULL ? debPath : "none",
                     debugserverPortText != NULL ? debugserverPortText
                                                 : "none");
        dprintf(STDERR_FILENO,
                "codex-postboot-driver rejected mode=%s path=%s port=%s\n",
                mode, debPath != NULL ? debPath : "none",
                debugserverPortText != NULL ? debugserverPortText : "none");
        *exitCode = 126;
        return true;
    }

    char environmentPath[PATH_MAX];
    char endpoint[64];
    char *arguments[5] = {0};
    uint32_t argumentCount = 0;
    if (installDeb) {
        arguments[0] = "/var/jb/usr/bin/dpkg";
        arguments[1] = "-i";
        arguments[2] = (char *)debPath;
        argumentCount = 3;
    } else {
        int environmentLength = snprintf(environmentPath,
                                         sizeof(environmentPath),
                                         "%s/usr/bin/env", gJailbreakRoot);
        int endpointLength = snprintf(endpoint, sizeof(endpoint),
                                      "127.0.0.1:%u", debugserverPort);
        if (environmentLength < 0 ||
            (size_t)environmentLength >= sizeof(environmentPath) ||
            endpointLength < 0 || (size_t)endpointLength >= sizeof(endpoint)) {
            *exitCode = 126;
            return true;
        }
        arguments[0] = environmentPath;
        arguments[1] = "-i";
        arguments[2] = "/usr/libexec/debugserver";
        arguments[3] = endpoint;
        argumentCount = 4;
    }
    int descriptors[2];
    int descriptorNumbers[2];
    uint32_t descriptorCount = 0;
    for (int descriptor = STDOUT_FILENO; descriptor <= STDERR_FILENO;
         ++descriptor) {
        if (fcntl(descriptor, F_GETFD) >= 0) {
            descriptors[descriptorCount] = descriptor;
            descriptorNumbers[descriptorCount] = descriptor;
            ++descriptorCount;
        }
    }
    int32_t status = 126 << 8;
    bool ran = descriptorCount != 0 &&
        run_broker_request(arguments, argumentCount, NULL, 0, descriptors,
                           descriptorNumbers, descriptorCount, &status);
    if (!ran) {
        int savedError = errno;
        os_log_error(log,
                     "postboot driver broker request failed: %{public}s",
                     strerror(savedError));
        dprintf(STDERR_FILENO,
                "codex-postboot-driver broker-failed errno=%d\n",
                savedError);
        *exitCode = 126;
        return true;
    }
    if (WIFEXITED(status)) {
        *exitCode = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *exitCode = 128 + WTERMSIG(status);
    } else {
        *exitCode = 126;
    }
    os_log(log, "postboot driver complete mode=%{public}s "
                "path=%{public}s port=%{public}u status=%{public}d "
                "exit=%{public}d",
           mode, debPath != NULL ? debPath : "none", debugserverPort, status,
           *exitCode);
    dprintf(STDERR_FILENO,
            "codex-postboot-driver complete mode=%s path=%s port=%u "
            "status=%d exit=%d\n",
            mode, debPath != NULL ? debPath : "none", debugserverPort, status,
            *exitCode);
    return true;
}

static struct codex_action_record *find_action_record_locked(
    const posix_spawn_file_actions_t *key) {
    for (struct codex_action_record *record = gActionRecords; record != NULL;
         record = record->next) {
        if (record->key == key) {
            return record;
        }
    }
    return NULL;
}

static void remove_action_record_locked(
    const posix_spawn_file_actions_t *key) {
    struct codex_action_record **cursor = &gActionRecords;
    while (*cursor != NULL) {
        if ((*cursor)->key == key) {
            struct codex_action_record *removed = *cursor;
            *cursor = removed->next;
            free(removed);
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static bool allowed_target_descriptor(int descriptor) {
    return descriptor == 0 || descriptor == 1 || descriptor == 2 ||
           descriptor == 3 || descriptor == 5 || descriptor == 6;
}

static bool path_is_registered_helper(const char *path) {
    if (path == NULL || path[0] != '/') {
        return false;
    }
    char executable[PATH_MAX];
    uint32_t executableSize = sizeof(executable);
    if (_NSGetExecutablePath(executable, &executableSize) != 0) {
        return false;
    }
    char resolvedExecutable[PATH_MAX];
    char resolvedCandidate[PATH_MAX];
    if (realpath(executable, resolvedExecutable) == NULL ||
        realpath(path, resolvedCandidate) == NULL) {
        return false;
    }
    char *lastSlash = strrchr(resolvedExecutable, '/');
    if (lastSlash == NULL || lastSlash == resolvedExecutable) {
        return false;
    }
    int length = snprintf(lastSlash + 1,
                          sizeof(resolvedExecutable) -
                              (size_t)(lastSlash + 1 - resolvedExecutable),
                          "giveMeRoot");
    return length == (int)strlen("giveMeRoot") &&
           strcmp(resolvedExecutable, resolvedCandidate) == 0;
}

static bool path_is_below_jailbreak_root(const char *resolved) {
    if (resolved == NULL || gJailbreakRoot[0] == '\0') {
        return false;
    }
    size_t rootLength = strlen(gJailbreakRoot);
    return strncmp(resolved, gJailbreakRoot, rootLength) == 0 &&
           resolved[rootLength] == '/';
}

static bool resolve_managed_spawn_command(const char *path,
                                          char resolved[PATH_MAX],
                                          bool *compatibilityMapped) {
    if (compatibilityMapped != NULL) {
        *compatibilityMapped = false;
    }
    if (path == NULL || path[0] != '/' || gJailbreakRoot[0] == '\0') {
        return false;
    }
    if (realpath(path, resolved) != NULL &&
        path_is_below_jailbreak_root(resolved)) {
        return true;
    }

    // When bootstrap detection falls back to a legacy rootful flavor, Sileo
    // selects these sealed-system paths. Map only its fixed file-operation
    // set to the equivalent executable already covered by the Cryptex trust
    // cache and by the root broker's managed-root policy.
    static const char *legacyPaths[] = {
        "/bin/mv", "/bin/chmod", "/bin/ln",
        "/bin/rm", "/bin/mkdir", "/bin/cp",
    };
    const char *leaf = NULL;
    for (size_t index = 0;
         index < sizeof(legacyPaths) / sizeof(legacyPaths[0]); ++index) {
        if (strcmp(path, legacyPaths[index]) == 0) {
            leaf = strrchr(legacyPaths[index], '/');
            break;
        }
    }
    if (leaf == NULL || leaf[1] == '\0') {
        return false;
    }
    char candidate[PATH_MAX];
    int length = snprintf(candidate, sizeof(candidate), "%s/usr/bin/%s",
                          gJailbreakRoot, leaf + 1);
    if (length < 0 || (size_t)length >= sizeof(candidate) ||
        realpath(candidate, resolved) == NULL ||
        !path_is_below_jailbreak_root(resolved)) {
        return false;
    }
    if (compatibilityMapped != NULL) {
        *compatibilityMapped = true;
    }
    return true;
}

static bool resolve_managed_apt_simulation(
    const char *path, char *const argv[], char resolved[PATH_MAX]) {
    if (argv == NULL || argv[0] == NULL || argv[1] == NULL ||
        strcmp(argv[0], "apt-get") != 0 || strcmp(argv[1], "-sqf") != 0) {
        return false;
    }

    bool compatibilityMapped = false;
    if (!resolve_managed_spawn_command(path, resolved,
                                       &compatibilityMapped) ||
        compatibilityMapped) {
        return false;
    }
    char expectedPath[PATH_MAX];
    char expectedResolved[PATH_MAX];
    int expectedLength = snprintf(expectedPath, sizeof(expectedPath),
                                  "%s/usr/bin/apt-get", gJailbreakRoot);
    if (expectedLength < 0 || (size_t)expectedLength >= sizeof(expectedPath) ||
        realpath(expectedPath, expectedResolved) == NULL ||
        strcmp(resolved, expectedResolved) != 0) {
        return false;
    }

    bool hasJsonOutput = false;
    bool hasSileoLists = false;
    bool hasInstall = false;
    bool hasReinstall = false;
    for (uint32_t index = 2;
         index < CODEX_ROOT_BROKER_MAX_ARGUMENTS && argv[index] != NULL;
         ++index) {
        const char *argument = argv[index];
        if (strcmp(argument, "-oAPT::Format::JSON=true") == 0) {
            hasJsonOutput = true;
        } else if (strcmp(argument,
                          "-oDir::State::lists=sileolists/") == 0) {
            hasSileoLists = true;
        } else if (strcmp(argument, "install") == 0) {
            hasInstall = true;
        } else if (strcmp(argument, "--reinstall") == 0) {
            hasReinstall = true;
        }
        // The leading -s in -sqf is what makes this brokered apt invocation
        // read-only. Refuse any later option which could override simulation.
        if (strstr(argument, "APT::Get::Simulate") != NULL ||
            strcmp(argument, "--no-simulate") == 0) {
            return false;
        }
    }
    return hasJsonOutput && hasSileoLists && hasInstall && hasReinstall;
}

static void free_virtual_job(struct codex_virtual_job *job) {
    for (uint32_t index = 0; index < job->argument_count; ++index) {
        free(job->arguments[index]);
    }
    for (uint32_t index = 0; index < job->environment_count; ++index) {
        free(job->environment[index]);
    }
    for (uint32_t index = 0; index < job->descriptor_count; ++index) {
        if (job->descriptors[index] >= 0) {
            close(job->descriptors[index]);
        }
    }
    pthread_cond_destroy(&job->condition);
    free(job);
}

static bool add_job_descriptor(struct codex_virtual_job *job, int source,
                               int target) {
    if (!allowed_target_descriptor(target)) {
        return true;
    }
    int duplicate = fcntl(source, F_DUPFD_CLOEXEC, 64);
    if (duplicate < 0) {
        return false;
    }
    for (uint32_t index = 0; index < job->descriptor_count; ++index) {
        if (job->descriptor_numbers[index] == target) {
            close(job->descriptors[index]);
            job->descriptors[index] = duplicate;
            return true;
        }
    }
    if (job->descriptor_count >= CODEX_ROOT_BROKER_MAX_FDS) {
        close(duplicate);
        errno = E2BIG;
        return false;
    }
    uint32_t index = job->descriptor_count++;
    job->descriptors[index] = duplicate;
    job->descriptor_numbers[index] = target;
    return true;
}

static void *run_virtual_job(void *context) {
    struct codex_virtual_job *job = context;
    pid_t jobPid = job->pid;
    int32_t status = 127 << 8;
    bool ran = run_broker_request(job->arguments, job->argument_count,
                                  job->environment, job->environment_count,
                                  job->descriptors, job->descriptor_numbers,
                                  job->descriptor_count, &status);
    for (uint32_t index = 0; index < job->descriptor_count; ++index) {
        close(job->descriptors[index]);
        job->descriptors[index] = -1;
    }
    pthread_mutex_lock(&gStateLock);
    job->status = ran ? status : (127 << 8);
    int32_t finalStatus = job->status;
    job->complete = true;
    pthread_cond_broadcast(&job->condition);
    pthread_mutex_unlock(&gStateLock);
    if (gConstructorLog != NULL) {
        os_log(gConstructorLog,
               "virtual root task complete pid=%{public}d ran=%{public}s "
               "status=%{public}d",
               jobPid, ran ? "true" : "false", finalStatus);
    }
    return NULL;
}

static int codex_actions_init(posix_spawn_file_actions_t *actions) {
    // dyld does not apply an __interpose tuple to calls originating in the
    // image that owns that tuple.  A direct call therefore reaches libSystem;
    // RTLD_NEXT can resolve back through this re-exporting shim on dyld4.
    int result = posix_spawn_file_actions_init(actions);
    if (result == 0) {
        pthread_mutex_lock(&gStateLock);
        remove_action_record_locked(actions);
        pthread_mutex_unlock(&gStateLock);
    }
    return result;
}

static int codex_actions_adddup2(posix_spawn_file_actions_t *actions,
                                 int source, int target) {
    int result = posix_spawn_file_actions_adddup2(actions, source, target);
    if (result != 0) {
        return result;
    }
    pthread_mutex_lock(&gStateLock);
    struct codex_action_record *record = find_action_record_locked(actions);
    if (record == NULL) {
        record = calloc(1, sizeof(*record));
        if (record != NULL) {
            record->key = actions;
            record->next = gActionRecords;
            gActionRecords = record;
        }
    }
    if (record != NULL && record->count < CODEX_MAX_DUP_ACTIONS) {
        record->actions[record->count++] =
            (struct codex_dup_action){.source = source, .target = target};
    }
    pthread_mutex_unlock(&gStateLock);
    return result;
}

static int codex_actions_destroy(posix_spawn_file_actions_t *actions) {
    int result = posix_spawn_file_actions_destroy(actions);
    pthread_mutex_lock(&gStateLock);
    remove_action_record_locked(actions);
    pthread_mutex_unlock(&gStateLock);
    return result;
}

static int codex_posix_spawn(pid_t *restrict pid, const char *restrict path,
                             const posix_spawn_file_actions_t *actions,
                             const posix_spawnattr_t *restrict attributes,
                             char *const argv[restrict],
                             char *const envp[restrict]) {
    bool helperSpawn = path_is_registered_helper(path);
    // Sileo 2.x uses a root persona on iOS 13 and later and directly spawns
    // commands from the jailbreak root.  A provisioned app cannot perform
    // that persona transition, so route only attributed spawns whose exact
    // executable resolves below the managed root through the same broker.
    char brokerCommand[PATH_MAX] = {0};
    bool compatibilityMapped = false;
    bool managedPersonaSpawn =
        !helperSpawn && attributes != NULL &&
        resolve_managed_spawn_command(path, brokerCommand,
                                      &compatibilityMapped);
    // Sileo's dependency preview intentionally invokes apt-get without a root
    // persona. A provisioned app is denied that exec even though the Cryptex
    // trust cache covers apt-get. Route only Sileo's exact read-only JSON
    // simulation shape; package installation continues to use the attributed
    // root path above.
    bool managedSimulationSpawn =
        !helperSpawn && attributes == NULL &&
        resolve_managed_apt_simulation(path, argv, brokerCommand);
    if (!helperSpawn && !managedPersonaSpawn && !managedSimulationSpawn) {
        return posix_spawn(pid, path, actions, attributes, argv, envp);
    }
    if (pid == NULL || argv == NULL || argv[0] == NULL ||
        (helperSpawn && argv[1] == NULL)) {
        return EINVAL;
    }
    struct codex_virtual_job *job = calloc(1, sizeof(*job));
    if (job == NULL) {
        return ENOMEM;
    }
    for (uint32_t index = 0; index < CODEX_ROOT_BROKER_MAX_FDS; ++index) {
        job->descriptors[index] = -1;
    }
    pthread_cond_init(&job->condition, NULL);
    if (managedPersonaSpawn || managedSimulationSpawn) {
        job->arguments[0] = strdup(brokerCommand);
        if (job->arguments[0] == NULL) {
            free_virtual_job(job);
            return ENOMEM;
        }
        job->argument_count = 1;
    }
    for (uint32_t index = 1; argv[index] != NULL; ++index) {
        if (job->argument_count >= CODEX_ROOT_BROKER_MAX_ARGUMENTS) {
            free_virtual_job(job);
            return E2BIG;
        }
        job->arguments[job->argument_count] = strdup(argv[index]);
        if (job->arguments[job->argument_count] == NULL) {
            free_virtual_job(job);
            return ENOMEM;
        }
        ++job->argument_count;
    }
    job->arguments[job->argument_count] = NULL;

    for (uint32_t index = 0; envp != NULL && envp[index] != NULL; ++index) {
        const char *entry = envp[index];
        bool isControlEnvironment =
            strncmp(entry, "SILEO=", strlen("SILEO=")) == 0 ||
            strncmp(entry, "CYDIA=", strlen("CYDIA=")) == 0;
        if (!isControlEnvironment) {
            continue;
        }
        if (job->environment_count >= CODEX_ROOT_BROKER_MAX_ENVIRONMENT ||
            strnlen(entry, 64U) == 64U) {
            free_virtual_job(job);
            return E2BIG;
        }
        job->environment[job->environment_count] = strdup(entry);
        if (job->environment[job->environment_count] == NULL) {
            free_virtual_job(job);
            return ENOMEM;
        }
        ++job->environment_count;
    }
    job->environment[job->environment_count] = NULL;

    for (int descriptor = 0; descriptor <= 2; ++descriptor) {
        if (fcntl(descriptor, F_GETFD) >= 0 &&
            !add_job_descriptor(job, descriptor, descriptor)) {
            free_virtual_job(job);
            return errno == 0 ? EBADF : errno;
        }
    }
    pthread_mutex_lock(&gStateLock);
    struct codex_action_record *record = find_action_record_locked(actions);
    struct codex_dup_action captured[CODEX_MAX_DUP_ACTIONS];
    uint32_t capturedCount = record != NULL ? record->count : 0;
    if (capturedCount > 0) {
        memcpy(captured, record->actions,
               capturedCount * sizeof(captured[0]));
    }
    pthread_mutex_unlock(&gStateLock);
    for (uint32_t index = 0; index < capturedCount; ++index) {
        if (!add_job_descriptor(job, captured[index].source,
                                captured[index].target)) {
            int savedError = errno;
            free_virtual_job(job);
            return savedError == 0 ? EBADF : savedError;
        }
    }
    if (job->descriptor_count == 0) {
        free_virtual_job(job);
        return EBADF;
    }

    pthread_mutex_lock(&gStateLock);
    job->pid = gNextFakePid++;
    job->next = gVirtualJobs;
    gVirtualJobs = job;
    pthread_mutex_unlock(&gStateLock);
    pthread_t worker;
    int threadResult = pthread_create(&worker, NULL, run_virtual_job, job);
    if (threadResult != 0) {
        pthread_mutex_lock(&gStateLock);
        if (gVirtualJobs == job) {
            gVirtualJobs = job->next;
        } else {
            struct codex_virtual_job *cursor = gVirtualJobs;
            while (cursor != NULL && cursor->next != job) {
                cursor = cursor->next;
            }
            if (cursor != NULL) {
                cursor->next = job->next;
            }
        }
        pthread_mutex_unlock(&gStateLock);
        free_virtual_job(job);
        return threadResult;
    }
    pthread_detach(worker);
    *pid = job->pid;
    if (gConstructorLog != NULL) {
        os_log(gConstructorLog,
               "virtualized root spawn pid=%{public}d mode=%{public}s "
               "command=%{public}s requested=%{public}s",
               job->pid,
               helperSpawn
                   ? "helper"
                   : (managedSimulationSpawn
                          ? "simulation"
                          : (compatibilityMapped ? "persona-remap"
                                                 : "persona")),
               job->arguments[0], path);
    }
    return 0;
}

static pid_t codex_waitpid(pid_t pid, int *status, int options) {
    pthread_mutex_lock(&gStateLock);
    struct codex_virtual_job **cursor = &gVirtualJobs;
    while (*cursor != NULL && (*cursor)->pid != pid) {
        cursor = &(*cursor)->next;
    }
    struct codex_virtual_job *job = *cursor;
    if (job == NULL) {
        pthread_mutex_unlock(&gStateLock);
        return waitpid(pid, status, options);
    }
    if ((options & ~WNOHANG) != 0) {
        pthread_mutex_unlock(&gStateLock);
        errno = EINVAL;
        return -1;
    }
    if (!job->complete && (options & WNOHANG) != 0) {
        pthread_mutex_unlock(&gStateLock);
        return 0;
    }
    while (!job->complete) {
        pthread_cond_wait(&job->condition, &gStateLock);
    }
    if (status != NULL) {
        *status = job->status;
    }
    *cursor = job->next;
    pthread_mutex_unlock(&gStateLock);
    free_virtual_job(job);
    return pid;
}

static int verify_spawn_bridge(os_log_t log) {
    char executable[PATH_MAX];
    char resolvedExecutable[PATH_MAX];
    uint32_t executableSize = sizeof(executable);
    if (_NSGetExecutablePath(executable, &executableSize) != 0 ||
        realpath(executable, resolvedExecutable) == NULL) {
        os_log_error(log, "spawn bridge executable path is unavailable");
        return -1;
    }
    memcpy(executable, resolvedExecutable, strlen(resolvedExecutable) + 1U);
    char *lastSlash = strrchr(executable, '/');
    if (lastSlash == NULL ||
        (size_t)(lastSlash + 1 - executable) + strlen("giveMeRoot") + 1U >
            sizeof(executable)) {
        os_log_error(log, "spawn bridge helper path is invalid");
        return -1;
    }
    strcpy(lastSlash + 1, "giveMeRoot");

    int outputPipe[2];
    if (pipe(outputPipe) != 0) {
        os_log_error(log, "spawn bridge pipe failed: %{public}s",
                     strerror(errno));
        return -1;
    }
    posix_spawn_file_actions_t actions = NULL;
    int actionResult = codex_actions_init(&actions);
    if (actionResult == 0) {
        actionResult =
            codex_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO);
    }
    pid_t virtualPid = -1;
    char *arguments[] = {executable, "/var/jb/usr/bin/whoami", NULL};
    int spawnResult =
        actionResult == 0
            ? codex_posix_spawn(&virtualPid, executable, &actions, NULL,
                                arguments, environ)
            : actionResult;
    int destroyResult =
        actions != NULL ? codex_actions_destroy(&actions) : 0;
    close(outputPipe[1]);
    if (spawnResult != 0 || destroyResult != 0) {
        close(outputPipe[0]);
        os_log_error(log,
                     "spawn bridge setup failed: spawn=%{public}d "
                     "destroy=%{public}d",
                     spawnResult, destroyResult);
        return -1;
    }

    int status = 0;
    pid_t waited = codex_waitpid(virtualPid, &status, 0);
    char output[32] = {0};
    ssize_t outputLength;
    do {
        outputLength = read(outputPipe[0], output, sizeof(output) - 1U);
    } while (outputLength < 0 && errno == EINTR);
    close(outputPipe[0]);
    if (waited != virtualPid || outputLength < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 ||
        (strcmp(output, "root\n") != 0 && strcmp(output, "root") != 0)) {
        os_log_error(log,
                     "spawn bridge preflight failed: waited=%{public}d "
                     "status=%{public}d output=%{public}s",
                     waited, status,
                     outputLength >= 0 ? output : "read-error");
        return -1;
    }
    os_log(log, "spawn bridge preflight complete");
    return 0;
}

#define CODEX_INTERPOSE(replacement, replacee)                                \
    __attribute__((used)) static struct {                                     \
        const void *replacement;                                              \
        const void *replacee;                                                 \
    } codex_interpose_##replacee                                              \
        __attribute__((section("__DATA,__interpose"))) = {                    \
            (const void *)(uintptr_t)&replacement,                            \
            (const void *)(uintptr_t)&replacee,                               \
        }

CODEX_INTERPOSE(codex_actions_init, posix_spawn_file_actions_init);
CODEX_INTERPOSE(codex_actions_adddup2, posix_spawn_file_actions_adddup2);
CODEX_INTERPOSE(codex_actions_destroy, posix_spawn_file_actions_destroy);
CODEX_INTERPOSE(codex_posix_spawn, posix_spawn);
CODEX_INTERPOSE(codex_waitpid, waitpid);
CODEX_INTERPOSE(codex_open, open);
CODEX_INTERPOSE(codex_fopen, fopen);
CODEX_INTERPOSE(codex_stat, stat);
CODEX_INTERPOSE(codex_access, access);

__attribute__((constructor)) static void initialize_sileo_broker(void) {
    gConstructorLog = os_log_create("com.openai.codex.dopamine.bootstrap",
                                    "sileo-constructor");
    char jailbreakRoot[4096];
    if (read_jailbreak_root(gConstructorLog, jailbreakRoot,
                            sizeof(jailbreakRoot)) != 0 ||
        consume_process_bound_extensions(gConstructorLog) != 0) {
        os_log_error(gConstructorLog,
                     "constructor broker initialization failed");
        _exit(126);
    }
    memcpy(gJailbreakRoot, jailbreakRoot, strlen(jailbreakRoot) + 1U);
    char pathEnvironment[8192];
    char shell[4096];
    char libraryPath[4096];
    int lengths[] = {
        snprintf(pathEnvironment, sizeof(pathEnvironment),
                 "%s/usr/bin:%s/bin:%s/usr/sbin:%s/sbin:"
                 "/usr/bin:/bin:/usr/sbin:/sbin",
                 jailbreakRoot, jailbreakRoot, jailbreakRoot, jailbreakRoot),
        snprintf(shell, sizeof(shell), "%s/bin/sh", jailbreakRoot),
        snprintf(libraryPath, sizeof(libraryPath), "%s/usr/lib",
                 jailbreakRoot),
    };
    size_t capacities[] = {sizeof(pathEnvironment), sizeof(shell),
                           sizeof(libraryPath)};
    for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]);
         ++index) {
        if (lengths[index] < 0 ||
            (size_t)lengths[index] >= capacities[index]) {
            os_log_error(gConstructorLog,
                         "resolved environment path is too long");
            _exit(126);
        }
    }
    setenv("PATH", pathEnvironment, 1);
    setenv("SHELL", shell, 1);
    setenv("DYLD_LIBRARY_PATH", libraryPath, 1);
    probe_apt_lists_access(gConstructorLog, jailbreakRoot);
    if (verify_root_broker(gConstructorLog) != 0) {
        os_log_error(gConstructorLog,
                     "constructor root broker preflight failed");
        _exit(126);
    }
    int driverExitCode = 0;
    if (run_postboot_driver(gConstructorLog, &driverExitCode)) {
        _exit(driverExitCode);
    }
    if (verify_spawn_bridge(gConstructorLog) != 0) {
        os_log_error(gConstructorLog,
                     "constructor spawn bridge preflight failed");
        _exit(126);
    }
    os_log(gConstructorLog, "constructor broker initialization complete");
}
