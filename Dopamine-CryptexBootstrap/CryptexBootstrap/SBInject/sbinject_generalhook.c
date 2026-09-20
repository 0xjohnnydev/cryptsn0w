// Pre-main SpringBoard hook derived from the supplied SBInject generalhook.
#include "sbinject_dyld_bypass.h"
#include "sbinject_protocol.h"

#include <bsm/audit.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern kern_return_t bootstrap_look_up(mach_port_t bootstrap_port,
                                       const char *service,
                                       mach_port_t *server_port);
extern int64_t sandbox_extension_consume(const char *token);
extern char *sandbox_extension_issue_file_to_process(
    const char *extension_class, const char *path, uint32_t flags,
    audit_token_t token);

static os_log_t hook_log(void) {
    static os_log_t log;
    if (log == NULL) {
        log = os_log_create("com.openai.codex.sbinject", "generalhook");
    }
    return log;
}

static bool exact_executable(void) {
    uint32_t size = 0;
    (void)_NSGetExecutablePath(NULL, &size);
    char *path = calloc((size_t)size + 1U, 1U);
    if (path == NULL || _NSGetExecutablePath(path, &size) != 0) {
        free(path);
        return false;
    }
    char configured[PATH_MAX] = {0};
    char observed[PATH_MAX] = {0};
    bool exact = realpath(CODEX_SBINJECT_SPRINGBOARD, configured) != NULL &&
                 realpath(path, observed) != NULL &&
                 strcmp(configured, observed) == 0;
    free(path);
    return exact;
}

static bool mark_self_debugged(void) {
    mach_port_t port = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, CODEX_SBINJECT_JITTERD_SERVICE,
                          &port) != KERN_SUCCESS ||
        !MACH_PORT_VALID(port)) {
        return false;
    }
    xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
    mach_port_deallocate(mach_task_self(), port);
    if (pipe == NULL) {
        return false;
    }
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(message, "id", CODEX_SBINJECT_JIT_MESSAGE_ID);
    xpc_dictionary_set_int64(message, "pid", getpid());
    xpc_object_t reply = NULL;
    int transport = xpc_pipe_routine(pipe, message, &reply);
    xpc_release(message);
    xpc_release(pipe);
    int64_t result = reply != NULL
                         ? xpc_dictionary_get_int64(reply, "result")
                         : -1;
    if (reply != NULL) {
        xpc_release(reply);
    }
    return transport == 0 && result == 0;
}

static void consume_extension(const char *extension_class, const char *path,
                              audit_token_t token) {
    char *extension = sandbox_extension_issue_file_to_process(
        extension_class, path, 0, token);
    if (extension != NULL) {
        (void)sandbox_extension_consume(extension);
        free(extension);
    }
}

static void apply_supplied_sandbox_extensions(void) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token,
                  &count) != KERN_SUCCESS) {
        return;
    }
    consume_extension("com.apple.app-sandbox.read", "/var/jb", token);
    consume_extension("com.apple.sandbox.executable", "/var/jb", token);
    consume_extension("com.apple.app-sandbox.read-write", "/var/mobile",
                      token);
}

__attribute__((constructor)) static void initialize_general_hook(void) {
    if (!exact_executable()) {
        return;
    }
    os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                     "SBInject pre-main hook entered pid=%d", getpid());
    if (!mark_self_debugged()) {
        os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                         "jitterd refused SpringBoard; exiting for fallback");
        _exit(78);
    }
    apply_supplied_sandbox_extensions();
    if (!sbinject_install_dyld_validation_bypass()) {
        os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                         "dyld validation bypass did not match target; "
                         "exiting for fallback");
        _exit(79);
    }
    dlerror();
    void *injector = dlopen(CODEX_SBINJECT_ELLEKIT, RTLD_NOW | RTLD_LOCAL);
    if (injector == NULL) {
        const char *error = dlerror();
        os_log_with_type(hook_log(), OS_LOG_TYPE_FAULT,
                         "ElleKit pre-main load failed: %{public}s",
                         error != NULL ? error : "unknown");
        _exit(80);
    }
    os_log_with_type(hook_log(), OS_LOG_TYPE_DEFAULT,
                     "SBInject ready; ElleKit loaded pre-main");
}

