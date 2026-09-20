// Narrowed service implementation derived from the supplied SBInject jitterd.
#import <Foundation/Foundation.h>

#include "sbinject_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <os/log.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CODEX_PT_DETACH 11
#define CODEX_PT_ATTACHEXC 14
#define CODEX_PROC_PIDPATH_MAX 4096

extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern kern_return_t bootstrap_check_in(mach_port_t bootstrap_port,
                                        const char *service,
                                        mach_port_t *server_port);

static os_log_t service_log(void) {
    static os_log_t log;
    if (log == NULL) {
        log = os_log_create("com.openai.codex.sbinject", "jitterd");
    }
    return log;
}

static bool safe_candidate(pid_t requested, audit_token_t token) {
    pid_t caller = (pid_t)token.val[5];
    uid_t effective_user = (uid_t)token.val[1];
    if (requested <= 1 || requested != caller ||
        (effective_user != 0 && effective_user != 501)) {
        return false;
    }
    char path[CODEX_PROC_PIDPATH_MAX] = {0};
    char observed[CODEX_PROC_PIDPATH_MAX] = {0};
    if (proc_pidpath(requested, path, sizeof(path)) <= 0 ||
        realpath(path, observed) == NULL) {
        return false;
    }
    const char *const candidates[] = {
        CODEX_SBINJECT_SPRINGBOARD,
        CODEX_SBINJECT_PREFERENCES,
    };
    char configured[CODEX_PROC_PIDPATH_MAX] = {0};
    bool exact = false;
    for (size_t index = 0;
         index < sizeof(candidates) / sizeof(candidates[0]); ++index) {
        if (realpath(candidates[index], configured) != NULL &&
            strcmp(configured, observed) == 0) {
            exact = true;
            break;
        }
    }
    if (!exact) {
        return false;
    }
    struct stat status;
    return lstat(configured, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static int mark_debugged(pid_t pid) {
    errno = 0;
    if (ptrace(CODEX_PT_ATTACHEXC, pid, NULL, 0) != 0) {
        return errno != 0 ? errno : EPERM;
    }
    int status = 0;
    bool stopped = false;
    for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
        pid_t waited = waitpid(pid, &status, WUNTRACED | WNOHANG);
        if (waited == pid) {
            stopped = WIFSTOPPED(status);
            break;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        usleep(10U * 1000U);
    }
    int detach_result = ptrace(CODEX_PT_DETACH, pid, NULL, 0);
    int detach_error = detach_result == 0 ? 0 : errno;
    (void)kill(pid, SIGCONT);
    if (!stopped) {
        return ETIMEDOUT;
    }
    return detach_result == 0 ? 0 : (detach_error != 0 ? detach_error : EPERM);
}

static void receive_message(mach_port_t port) {
    @autoreleasepool {
        xpc_object_t message = NULL;
        if (xpc_pipe_receive(port, &message) != 0 || message == NULL) {
            return;
        }
        xpc_object_t reply = xpc_dictionary_create_reply(message);
        int64_t result = EINVAL;
        pid_t requested = -1;
        if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
            audit_token_t token = {0};
            xpc_dictionary_get_audit_token(message, &token);
            int64_t identifier = xpc_dictionary_get_int64(message, "id");
            int64_t raw_pid = xpc_dictionary_get_int64(message, "pid");
            if (identifier == CODEX_SBINJECT_JIT_MESSAGE_ID && raw_pid > 1 &&
                raw_pid <= INT_MAX) {
                requested = (pid_t)raw_pid;
                result = safe_candidate(requested, token)
                             ? mark_debugged(requested)
                             : EPERM;
            }
        }
        if (reply != NULL) {
            xpc_dictionary_set_int64(reply, "result", result);
            (void)xpc_pipe_routine_reply(reply);
            xpc_release(reply);
        }
        xpc_release(message);
        os_log_with_type(service_log(),
                         result == 0 ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_ERROR,
                         "JIT request pid=%d result=%lld", requested, result);
    }
}

int main(void) {
    @autoreleasepool {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t result = bootstrap_check_in(
            bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE, &port);
        if (result != KERN_SUCCESS || !MACH_PORT_VALID(port)) {
            os_log_with_type(service_log(), OS_LOG_TYPE_FAULT,
                             "bootstrap_check_in failed: %d", result);
            return 1;
        }
        dispatch_source_t source = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)port, 0,
            dispatch_get_main_queue());
        if (source == NULL) {
            return 1;
        }
        dispatch_source_set_event_handler(source, ^{
            receive_message((mach_port_t)dispatch_source_get_handle(source));
        });
        dispatch_resume(source);
        os_log_with_type(service_log(), OS_LOG_TYPE_DEFAULT,
                         "jitterd ready service=%{public}s",
                         CODEX_SBINJECT_JITTERD_SERVICE);
        dispatch_main();
    }
}
