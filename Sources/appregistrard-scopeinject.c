#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>

typedef int (*domain_routine_fn)(uint64_t, xpc_object_t, xpc_object_t *);

static const char *const kEnvironmentName = "DYLD_INSERT_LIBRARIES";
static const char *const kHookPath =
    "/private/var/db/com.apple.securityresearchd/lib/"
    "libAppRegistrarHooks/libAppRegistrarHooks.dylib";
static const char *const kInstalldService = "com.apple.mobile.installd";

static volatile sig_atomic_t g_control_fd = -1;

static int executable_path(char path[PATH_MAX]);

static void
terminate_parent(int signo)
{
    int fd = (int)g_control_fd;
    if (fd >= 0) {
        (void)close(fd);
    }
    _exit(128 + signo);
}

static int64_t
monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void
sleep_milliseconds(unsigned milliseconds)
{
    struct timespec requested = {
        .tv_sec = (time_t)(milliseconds / 1000),
        .tv_nsec = (long)(milliseconds % 1000) * 1000000L,
    };
    while (nanosleep(&requested, &requested) != 0 && errno == EINTR) {
    }
}

static int
write_byte(int fd, char value)
{
    for (;;) {
        ssize_t count = write(fd, &value, 1);
        if (count == 1) {
            return 0;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return count < 0 ? errno : EIO;
    }
}

static int
read_byte_with_timeout(int fd, char *value, int timeout_ms)
{
    struct pollfd descriptor = {
        .fd = fd,
        .events = POLLIN | POLLHUP,
        .revents = 0,
    };
    for (;;) {
        int result = poll(&descriptor, 1, timeout_ms);
        if (result == 0) {
            return ETIMEDOUT;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        ssize_t count = read(fd, value, 1);
        if (count == 1) {
            return 0;
        }
        if (count == 0) {
            return ECONNRESET;
        }
        if (errno != EINTR) {
            return errno;
        }
    }
}

static domain_routine_fn
resolve_domain_routine(void)
{
    return (domain_routine_fn)dlsym(RTLD_DEFAULT, "_xpc_domain_routine");
}

static xpc_object_t
domain_message(void)
{
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(request, "handle", 501);
    xpc_dictionary_set_uint64(request, "type", 2);
    return request;
}

static int
set_insert(domain_routine_fn routine, const char *value)
{
    xpc_object_t environment = xpc_dictionary_create(NULL, NULL, 0);
    if (value != NULL) {
        xpc_dictionary_set_string(environment, kEnvironmentName, value);
    } else {
        xpc_object_t null_value = xpc_null_create();
        xpc_dictionary_set_value(environment, kEnvironmentName, null_value);
        xpc_release(null_value);
    }

    xpc_object_t request = domain_message();
    xpc_dictionary_set_value(request, "envvars", environment);
    xpc_object_t reply = NULL;
    int result = routine(819, request, &reply);
    if (reply != NULL) {
        xpc_release(reply);
    }
    xpc_release(request);
    xpc_release(environment);
    return result;
}

static int
read_insert(domain_routine_fn routine, char **value_out, bool *present_out)
{
    *value_out = NULL;
    *present_out = false;

    xpc_object_t request = domain_message();
    xpc_dictionary_set_string(request, "envvar", kEnvironmentName);
    xpc_object_t reply = NULL;
    int result = routine(820, request, &reply);
    xpc_release(request);

    if (result == 3) {
        if (reply != NULL) {
            xpc_release(reply);
        }
        return 0;
    }
    if (result != 0) {
        if (reply != NULL) {
            xpc_release(reply);
        }
        return result;
    }
    if (reply == NULL || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
        if (reply != NULL) {
            xpc_release(reply);
        }
        return EPROTO;
    }

    const char *value = xpc_dictionary_get_string(reply, "value");
    if (value == NULL) {
        xpc_release(reply);
        return EPROTO;
    }
    char *copy = strdup(value);
    xpc_release(reply);
    if (copy == NULL) {
        return ENOMEM;
    }
    *value_out = copy;
    *present_out = true;
    return 0;
}

static char *
filter_environment(const char *input, bool *changed_out)
{
    size_t input_length = strlen(input);
    size_t hook_length = strlen(kHookPath);
    char *output = calloc(input_length + 1, 1);
    if (output == NULL) {
        return NULL;
    }

    size_t output_length = 0;
    bool changed = false;
    const char *component = input;
    for (const char *cursor = input;; cursor++) {
        if (*cursor != ':' && *cursor != '\0') {
            continue;
        }
        size_t length = (size_t)(cursor - component);
        bool is_hook = length == hook_length &&
            memcmp(component, kHookPath, hook_length) == 0;
        if (length == 0 || is_hook) {
            changed = true;
        } else {
            if (output_length != 0) {
                output[output_length++] = ':';
            }
            memcpy(output + output_length, component, length);
            output_length += length;
        }
        if (*cursor == '\0') {
            break;
        }
        component = cursor + 1;
    }
    output[output_length] = '\0';
    *changed_out = changed || strcmp(input, output) != 0;
    return output;
}

static int
sanitize_existing_environment(domain_routine_fn routine,
    bool *unexpected_value_out)
{
    *unexpected_value_out = false;
    char *current = NULL;
    bool present = false;
    int result = read_insert(routine, &current, &present);
    if (result != 0 || !present) {
        free(current);
        return result;
    }

    bool changed = false;
    char *filtered = filter_environment(current, &changed);
    free(current);
    if (filtered == NULL) {
        return ENOMEM;
    }
    if (changed) {
        result = set_insert(routine, filtered[0] == '\0' ? NULL : filtered);
        if (result != 0) {
            free(filtered);
            return result;
        }
    }

    char *verified = NULL;
    bool verified_present = false;
    result = read_insert(routine, &verified, &verified_present);
    if (result == 0) {
        if (filtered[0] == '\0') {
            if (verified_present) {
                result = EBUSY;
            }
        } else if (!verified_present || strcmp(filtered, verified) != 0) {
            result = EBUSY;
        }
    }
    if (result == 0) {
        *unexpected_value_out = filtered[0] != '\0';
    }
    free(verified);
    free(filtered);
    return result;
}

static bool
force_unset(domain_routine_fn routine, unsigned attempts,
    unsigned delay_ms, bool hold_full_duration)
{
    bool clean = false;
    for (unsigned attempt = 0; attempt < attempts; attempt++) {
        (void)set_insert(routine, NULL);

        char *value = NULL;
        bool present = true;
        int result = read_insert(routine, &value, &present);
        free(value);
        clean = result == 0 && !present;
        if (clean && !hold_full_duration) {
            return true;
        }
        if (attempt + 1 < attempts) {
            sleep_milliseconds(delay_ms);
        }
    }
    return clean;
}

static int
kickstart_installd(domain_routine_fn routine, int64_t *pid_out)
{
    *pid_out = -1;
    xpc_object_t request = domain_message();
    xpc_dictionary_set_bool(request, "kill", true);
    xpc_dictionary_set_bool(request, "unthrottle", true);
    xpc_dictionary_set_string(request, "name", kInstalldService);
    xpc_object_t reply = NULL;
    int result = routine(702, request, &reply);
    xpc_release(request);
    if (result == 0) {
        if (reply == NULL || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
            result = EPROTO;
        } else {
            *pid_out = xpc_dictionary_get_int64(reply, "pid");
            if (*pid_out <= 1) {
                result = EPROTO;
            }
        }
    }
    if (reply != NULL) {
        xpc_release(reply);
    }
    return result;
}

static int
watchdog_main(int control_fd)
{
    (void)setsid();
    (void)signal(SIGPIPE, SIG_IGN);
    domain_routine_fn routine = resolve_domain_routine();
    if (routine == NULL ||
        !force_unset(routine, 100, 20, false)) {
        (void)write_byte(control_fd, 'E');
        return 70;
    }
    if (write_byte(control_fd, 'R') != 0) {
        return 71;
    }

    char command = '\0';
    if (read_byte_with_timeout(control_fd, &command, 5000) != 0 ||
        command != 'A') {
        (void)force_unset(routine, 600, 50, true);
        return 72;
    }
    if (write_byte(control_fd, 'G') != 0) {
        (void)force_unset(routine, 600, 50, true);
        return 73;
    }

    bool normal_completion =
        read_byte_with_timeout(control_fd, &command, 1500) == 0 &&
        command == 'D';
    bool clean;
    if (normal_completion) {
        clean = force_unset(routine, 50, 20, false);
    } else {
        clean = force_unset(routine, 600, 50, true);
    }
    (void)write_byte(control_fd, clean ? 'C' : 'E');
    return clean ? 0 : 74;
}

static int
acquire_transaction_lock(void)
{
    char path[PATH_MAX];
    int path_result = executable_path(path);
    if (path_result != 0) {
        errno = path_result;
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int
executable_path(char path[PATH_MAX])
{
    extern int _NSGetExecutablePath(char *, uint32_t *);
    uint32_t size = PATH_MAX;
    if (_NSGetExecutablePath(path, &size) != 0) {
        return ENAMETOOLONG;
    }
    return 0;
}

static int
spawn_watchdog(const char *self_path, int sockets[2], pid_t *pid_out)
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return errno;
    }

    char fd_string[32];
    (void)snprintf(fd_string, sizeof(fd_string), "%d", sockets[1]);
    char *const arguments[] = {
        (char *)self_path,
        "--watchdog-fd",
        fd_string,
        NULL,
    };
    char *const environment[] = {
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL,
    };
    posix_spawn_file_actions_t actions;
    int result = posix_spawn_file_actions_init(&actions);
    if (result == 0) {
        int action_result = posix_spawn_file_actions_addclose(
            &actions, sockets[0]);
        if (action_result == 0) {
            result = posix_spawn(pid_out, self_path, &actions, NULL,
                arguments, environment);
        } else {
            result = action_result;
        }
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    if (result != 0) {
        (void)close(sockets[0]);
        (void)close(sockets[1]);
        sockets[0] = -1;
        sockets[1] = -1;
        return result;
    }
    (void)close(sockets[1]);
    sockets[1] = -1;
    return 0;
}

static int
cleanup_only(domain_routine_fn routine)
{
    bool unexpected = false;
    int result = sanitize_existing_environment(routine, &unexpected);
    if (result != 0) {
        fprintf(stderr, "scopeinject: cleanup failed: %d\n", result);
        return 72;
    }
    if (unexpected) {
        fprintf(stderr,
            "scopeinject: preserved an unrelated %s value\n",
            kEnvironmentName);
    } else {
        fprintf(stderr, "scopeinject: %s is clean\n", kEnvironmentName);
    }
    return 0;
}

static int
injector_main(const char *self_path, domain_routine_fn routine)
{
    if (access(kHookPath, R_OK) != 0) {
        perror("scopeinject: hook is not readable");
        return 71;
    }

    bool unexpected = false;
    int result = sanitize_existing_environment(routine, &unexpected);
    if (result != 0) {
        fprintf(stderr, "scopeinject: preflight cleanup failed: %d\n",
            result);
        return 72;
    }
    if (unexpected) {
        fprintf(stderr,
            "scopeinject: refusing unexpected preflight %s value\n",
            kEnvironmentName);
        return 73;
    }

    int sockets[2] = {-1, -1};
    pid_t watchdog_pid = -1;
    result = spawn_watchdog(self_path, sockets, &watchdog_pid);
    if (result != 0) {
        fprintf(stderr, "scopeinject: watchdog spawn failed: %d\n", result);
        return 74;
    }
    g_control_fd = sockets[0];
    (void)signal(SIGPIPE, SIG_IGN);
    (void)signal(SIGINT, terminate_parent);
    (void)signal(SIGTERM, terminate_parent);
    (void)signal(SIGHUP, terminate_parent);
    (void)signal(SIGQUIT, terminate_parent);

    char response = '\0';
    bool set_attempted = false;
    bool parent_clean = false;
    int64_t installd_pid = -1;
    int exit_code = 74;

    result = read_byte_with_timeout(sockets[0], &response, 3000);
    if (result != 0 || response != 'R') {
        fprintf(stderr, "scopeinject: watchdog did not become ready: %d/%c\n",
            result, response == '\0' ? '?' : response);
        goto finish;
    }
    if (write_byte(sockets[0], 'A') != 0 ||
        read_byte_with_timeout(sockets[0], &response, 3000) != 0 ||
        response != 'G') {
        fprintf(stderr, "scopeinject: watchdog lease failed\n");
        goto finish;
    }

    int64_t go_time = monotonic_milliseconds();
    int watchdog_status = 0;
    if (go_time < 0 ||
        waitpid(watchdog_pid, &watchdog_status, WNOHANG) != 0 ||
        monotonic_milliseconds() - go_time > 250) {
        fprintf(stderr, "scopeinject: watchdog lease was not live\n");
        goto finish;
    }

    set_attempted = true;
    result = set_insert(routine, kHookPath);
    if (result != 0) {
        fprintf(stderr, "scopeinject: injection setup failed: %d\n", result);
        exit_code = 75;
        goto finish;
    }

    char *verified = NULL;
    bool verified_present = false;
    result = read_insert(routine, &verified, &verified_present);
    bool exact_value = result == 0 && verified_present &&
        strcmp(verified, kHookPath) == 0;
    free(verified);
    if (!exact_value) {
        fprintf(stderr, "scopeinject: injection setup verification failed\n");
        exit_code = 76;
        goto finish;
    }

    result = kickstart_installd(routine, &installd_pid);
    if (result != 0) {
        fprintf(stderr, "scopeinject: installd kickstart failed: %d\n",
            result);
        exit_code = 77;
        goto finish;
    }
    exit_code = 0;

finish:
    if (set_attempted || exit_code == 0) {
        parent_clean = force_unset(routine, 100, 20, false);
    } else {
        char *value = NULL;
        bool present = true;
        parent_clean = read_insert(routine, &value, &present) == 0 &&
            !present;
        free(value);
    }
    if (!parent_clean) {
        fprintf(stderr, "scopeinject: parent rollback did not verify\n");
        exit_code = 78;
    }

    (void)write_byte(sockets[0], 'D');
    response = '\0';
    int watchdog_result = read_byte_with_timeout(
        sockets[0], &response, 3000);
    if (watchdog_result != 0 || response != 'C') {
        fprintf(stderr, "scopeinject: watchdog rollback did not verify\n");
        exit_code = 79;
    }
    (void)close(sockets[0]);
    g_control_fd = -1;
    (void)waitpid(watchdog_pid, NULL, 0);

    if (exit_code == 0) {
        fprintf(stderr,
            "scopeinject: kickstarted %s pid=%lld; %s withdrawn twice\n",
            kInstalldService, (long long)installd_pid, kEnvironmentName);
    }
    return exit_code;
}

int
main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--watchdog-fd") == 0) {
        char *end = NULL;
        long value = strtol(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0' || value < 0 || value > INT_MAX) {
            return 64;
        }
        return watchdog_main((int)value);
    }

    int lock_fd = acquire_transaction_lock();
    if (lock_fd < 0) {
        perror("scopeinject: transaction lock");
        return 69;
    }
    domain_routine_fn routine = resolve_domain_routine();
    if (routine == NULL) {
        fprintf(stderr, "scopeinject: _xpc_domain_routine unavailable\n");
        (void)close(lock_fd);
        return 70;
    }
    if (argc == 2 && strcmp(argv[1], "--cleanup-only") == 0) {
        int result = cleanup_only(routine);
        (void)close(lock_fd);
        return result;
    }
    if (argc != 1) {
        fprintf(stderr,
            "usage: %s [--cleanup-only]\n", argv[0]);
        (void)close(lock_fd);
        return 64;
    }

    char self_path[PATH_MAX];
    int result = executable_path(self_path);
    if (result != 0) {
        fprintf(stderr, "scopeinject: executable path failed: %d\n", result);
        (void)close(lock_fd);
        return 70;
    }
    result = injector_main(self_path, routine);
    (void)close(lock_fd);
    return result;
}
