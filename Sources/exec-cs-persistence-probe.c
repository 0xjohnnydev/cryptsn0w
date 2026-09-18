#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/arm/thread_status.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif
#define PT_CONTINUE 7
#define PT_KILL 8
#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif

#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_OBSERVER_MAX_SAMPLES 3000000U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U

#ifndef CODEX_RESULT_PATH
#define CODEX_RESULT_PATH                                                    \
    "/private/var/mobile/Media/codex-exec-cs-persistence-probe.txt"
#endif
#ifndef CODEX_OBSERVER_RESULT_PATH
#define CODEX_OBSERVER_RESULT_PATH                                           \
    "/private/var/mobile/Media/codex-exec-cs-observer.txt"
#endif
#ifndef CODEX_EXEC_TARGET_PATH
#define CODEX_EXEC_TARGET_PATH                                               \
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
#endif

extern int csops(pid_t pid, unsigned int ops, void *useraddr,
                 size_t usersize);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);

static bool wait_for_child(pid_t child, int *status) {
    for (unsigned int attempt = 0; attempt < 500; ++attempt) {
        pid_t result = waitpid(child, status, WUNTRACED | WNOHANG);
        if (result == child) {
            return true;
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(10 * 1000);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool wait_for_terminal_child(pid_t child, int *status) {
    for (unsigned int attempt = 0; attempt < 500; ++attempt) {
        pid_t result = waitpid(child, status, WUNTRACED | WNOHANG);
        if (result == child) {
            if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
                return true;
            }
            continue;
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(10 * 1000);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool paths_match_canonically(const char *left, const char *right) {
    char resolved_left[PATH_MAX] = {0};
    char resolved_right[PATH_MAX] = {0};
    if (left == NULL || right == NULL || left[0] == '\0' ||
        right[0] == '\0') {
        return false;
    }
    if (realpath(left, resolved_left) != NULL &&
        realpath(right, resolved_right) != NULL) {
        return strcmp(resolved_left, resolved_right) == 0;
    }
    return strcmp(left, right) == 0;
}

static bool write_all(int descriptor, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t written = write(descriptor, cursor, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        cursor += written;
        length -= (size_t)written;
    }
    return true;
}

static bool write_result(const char *result) {
    int descriptor =
        open(CODEX_RESULT_PATH,
             O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return false;
    }

    struct stat attributes;
    bool regular = fstat(descriptor, &attributes) == 0 &&
                   S_ISREG(attributes.st_mode);
    bool written = regular && fchmod(descriptor, 0600) == 0 &&
                   write_all(descriptor, result, strlen(result)) &&
                   write_all(descriptor, "\n", 1);
    if (written) {
        written = fsync(descriptor) == 0;
    }
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return written;
}

static bool write_result_at_path(const char *path, const char *result) {
    int descriptor =
        open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
             0600);
    if (descriptor < 0) {
        return false;
    }

    struct stat attributes;
    bool regular = fstat(descriptor, &attributes) == 0 &&
                   S_ISREG(attributes.st_mode);
    bool written = regular && fchmod(descriptor, 0600) == 0 &&
                   write_all(descriptor, result, strlen(result)) &&
                   write_all(descriptor, "\n", 1);
    if (written) {
        written = fsync(descriptor) == 0;
    }
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return written;
}

static void run_probe(char *result, size_t result_size) {
    result[0] = '\0';

    sigset_t blocked_signals;
    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, SIGPIPE);
    int mask_result =
        pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
    if (mask_result != 0) {
        snprintf(result, result_size, "phase=sigmask error=%d", mask_result);
        return;
    }

    int gate[2] = {-1, -1};
    if (pipe(gate) != 0) {
        snprintf(result, result_size, "phase=pipe errno=%d", errno);
        return;
    }

    pid_t child = fork();
    if (child < 0) {
        int saved_errno = errno;
        close(gate[0]);
        close(gate[1]);
        snprintf(result, result_size, "phase=fork errno=%d", saved_errno);
        return;
    }

    if (child == 0) {
        close(gate[1]);
        uint8_t command = 0;
        ssize_t amount;
        do {
            amount = read(gate[0], &command, sizeof(command));
        } while (amount < 0 && errno == EINTR);
        close(gate[0]);
        if (amount != (ssize_t)sizeof(command) || command != 0x43) {
            _exit(70);
        }

        const char *path = CODEX_EXEC_TARGET_PATH;
        char *const argv[] = {(char *)path, NULL};
        char *const envp[] = {(char *)"CODEX_EXEC_CS_PROBE=1", NULL};
        execve(path, argv, envp);
        _exit(71);
    }

    close(gate[0]);
    errno = 0;
    int attach_result = ptrace(PT_ATTACHEXC, child, NULL, 0);
    int attach_errno = errno;
    int attach_status = 0;
    bool attach_waited =
        attach_result == 0 && wait_for_child(child, &attach_status);

    uint32_t before_flags = 0;
    errno = 0;
    int before_result =
        attach_waited
            ? csops(child, CODEX_CS_OPS_STATUS, &before_flags,
                    sizeof(before_flags))
            : -1;
    int before_errno = errno;

    uint8_t command = 0x43;
    bool released = attach_waited &&
                    write(gate[1], &command, sizeof(command)) ==
                        (ssize_t)sizeof(command);
    close(gate[1]);

    errno = 0;
    int continue_result =
        released ? ptrace(PT_CONTINUE, child, (caddr_t)1, 0) : -1;
    int continue_errno = errno;
    int exec_status = 0;
    bool exec_waited =
        continue_result == 0 && wait_for_child(child, &exec_status);

    uint32_t after_flags = 0;
    errno = 0;
    int after_result =
        exec_waited && WIFSTOPPED(exec_status)
            ? csops(child, CODEX_CS_OPS_STATUS, &after_flags,
                    sizeof(after_flags))
            : -1;
    int after_errno = errno;
    char after_path[PATH_MAX] = {0};
    int after_path_length = exec_waited && WIFSTOPPED(exec_status)
        ? proc_pidpath(child, after_path, sizeof(after_path))
        : 0;

    errno = 0;
    int kill_result =
        exec_waited && WIFSTOPPED(exec_status)
            ? ptrace(PT_KILL, child, NULL, 0)
            : kill(child, SIGKILL);
    int kill_errno = errno;
    int final_status = 0;
    (void)wait_for_child(child, &final_status);

    snprintf(
        result, result_size,
        "child=%d attach=%d attachErrno=%d attachWaited=%d "
        "attachStatus=0x%x beforeCsops=%d beforeErrno=%d "
        "beforeFlags=0x%08x beforeDebugged=%d released=%d continue=%d "
        "continueErrno=%d execWaited=%d execStatus=0x%x afterCsops=%d "
        "afterErrno=%d afterFlags=0x%08x afterDebugged=%d afterHardKill=%d "
        "afterPathLength=%d afterPath=%s "
        "kill=%d killErrno=%d finalStatus=0x%x",
        child, attach_result, attach_errno, attach_waited, attach_status,
        before_result, before_errno, before_flags,
        (before_flags & CODEX_CS_DEBUGGED) != 0, released, continue_result,
        continue_errno, exec_waited, exec_status, after_result, after_errno,
        after_flags, (after_flags & CODEX_CS_DEBUGGED) != 0,
        (after_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0,
        after_path_length, after_path_length > 0 ? after_path : "<none>",
        kill_result, kill_errno, final_status);
}

#if defined(CODEX_STANDALONE_PROBE) && CODEX_STANDALONE_PROBE
extern boolean_t exc_server(mach_msg_header_t *request,
                            mach_msg_header_t *reply);

struct codex_exception_observation {
    pid_t child;
    bool received;
    bool expected;
    bool state_copied;
    exception_type_t type;
    mach_msg_type_number_t code_count;
    integer_t code_zero;
    integer_t code_one;
    int flavor;
    mach_msg_type_number_t state_count;
    int path_length;
    char path[PATH_MAX];
    bool candidate;
    int csops_result;
    int csops_errno;
    uint32_t csflags;
    int ptrace_kill_result;
    int ptrace_kill_errno;
    int signal_kill_result;
    int signal_kill_errno;
};

static struct codex_exception_observation g_exception_observation;

static kern_return_t reject_unexpected_exception(pid_t child) {
    if (child > 1) {
        (void)kill(child, SIGKILL);
    }
    return KERN_FAILURE;
}

kern_return_t catch_exception_raise(mach_port_t exception_port,
                                    mach_port_t thread, mach_port_t task,
                                    exception_type_t exception,
                                    exception_data_t code,
                                    mach_msg_type_number_t code_count) {
    (void)exception_port;
    (void)thread;
    (void)task;
    (void)exception;
    (void)code;
    (void)code_count;
    return reject_unexpected_exception(g_exception_observation.child);
}

kern_return_t catch_exception_raise_state(
    mach_port_t exception_port, exception_type_t exception,
    const exception_data_t code, mach_msg_type_number_t code_count,
    int *flavor, const thread_state_t old_state,
    mach_msg_type_number_t old_state_count, thread_state_t new_state,
    mach_msg_type_number_t *new_state_count) {
    (void)exception_port;
    struct codex_exception_observation *observation =
        &g_exception_observation;
    observation->received = true;
    observation->type = exception;
    observation->code_count = code_count;
    observation->code_zero = code_count > 0 ? code[0] : 0;
    observation->code_one = code_count > 1 ? code[1] : 0;
    observation->flavor = flavor != NULL ? *flavor : 0;
    observation->state_count = old_state_count;
    observation->expected = exception == EXC_SOFTWARE && code_count >= 2 &&
        code[0] == EXC_SOFT_SIGNAL && code[1] == SIGTRAP;

    observation->state_copied = new_state_count != NULL &&
        old_state != NULL && new_state != NULL &&
        *new_state_count >= old_state_count;
    if (observation->state_copied) {
        memcpy(new_state, old_state,
               (size_t)old_state_count * sizeof(natural_t));
        *new_state_count = old_state_count;
    }

    observation->path_length = proc_pidpath(
        observation->child, observation->path, sizeof(observation->path));
    observation->candidate = observation->expected &&
        observation->path_length > 0 &&
        paths_match_canonically(observation->path, CODEX_EXEC_TARGET_PATH);
    errno = 0;
    observation->csops_result = observation->candidate
        ? csops(observation->child, CODEX_CS_OPS_STATUS,
                &observation->csflags, sizeof(observation->csflags))
        : -1;
    observation->csops_errno = errno;

    errno = 0;
    observation->ptrace_kill_result = observation->child > 1
        ? ptrace(PT_KILL, observation->child, NULL, 0)
        : -1;
    observation->ptrace_kill_errno = errno;
    errno = 0;
    observation->signal_kill_result =
        observation->ptrace_kill_result == 0
        ? 0
        : kill(observation->child, SIGKILL);
    observation->signal_kill_errno = errno;

    return observation->state_copied ? KERN_SUCCESS : KERN_FAILURE;
}

kern_return_t catch_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, exception_data_t code,
    mach_msg_type_number_t code_count, int *flavor,
    thread_state_t old_state, mach_msg_type_number_t old_state_count,
    thread_state_t new_state, mach_msg_type_number_t *new_state_count) {
    (void)exception_port;
    (void)thread;
    (void)task;
    (void)exception;
    (void)code;
    (void)code_count;
    (void)flavor;
    (void)old_state;
    (void)old_state_count;
    (void)new_state;
    (void)new_state_count;
    return reject_unexpected_exception(g_exception_observation.child);
}

static void run_spawn_probe(char *result, size_t result_size) {
    result[0] = '\0';
    memset(&g_exception_observation, 0,
           sizeof(g_exception_observation));
    g_exception_observation.csops_result = -1;
    g_exception_observation.ptrace_kill_result = -1;
    g_exception_observation.signal_kill_result = -1;

    static const char shell_path[] = "/var/jb/bin/sh";
    char *const arguments[] = {
        (char *)shell_path,
        (char *)"-c",
        (char *)"exec \"$1\"",
        (char *)"codex-exec-probe",
        (char *)CODEX_EXEC_TARGET_PATH,
        NULL,
    };
    char *const environment[] = {
        (char *)"CODEX_EXEC_CS_PROBE=1",
        (char *)"PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin",
        NULL,
    };

    posix_spawnattr_t attributes;
    int attribute_init = posix_spawnattr_init(&attributes);
    int attribute_flags = attribute_init == 0
        ? posix_spawnattr_setflags(&attributes,
                                   POSIX_SPAWN_START_SUSPENDED)
        : attribute_init;
    pid_t child = -1;
    int spawn_result = attribute_flags == 0
        ? posix_spawn(&child, shell_path, NULL, &attributes, arguments,
                      environment)
        : attribute_flags;
    if (attribute_init == 0) {
        (void)posix_spawnattr_destroy(&attributes);
    }

    int initial_status = 0;
    bool initial_waited = spawn_result == 0 && child > 1 &&
        wait_for_child(child, &initial_status);
    bool initial_stopped = initial_waited && WIFSTOPPED(initial_status) &&
        (WSTOPSIG(initial_status) == 0 ||
         WSTOPSIG(initial_status) == SIGSTOP);

    errno = 0;
    int attach_result = initial_stopped
        ? ptrace(PT_ATTACHEXC, child, NULL, 0)
        : -1;
    int attach_errno = errno;
    int attach_status = 0;
    bool attach_waited = attach_result == 0 &&
        wait_for_child(child, &attach_status);
    bool attach_stopped = attach_waited && WIFSTOPPED(attach_status);
    g_exception_observation.child = child;

    uint32_t before_flags = 0;
    errno = 0;
    int before_result = attach_stopped
        ? csops(child, CODEX_CS_OPS_STATUS, &before_flags,
                sizeof(before_flags))
        : -1;
    int before_errno = errno;

    mach_port_t child_task = MACH_PORT_NULL;
    kern_return_t task_result = attach_stopped
        ? task_for_pid(mach_task_self(), child, &child_task)
        : KERN_FAILURE;
    mach_port_t exception_port = MACH_PORT_NULL;
    kern_return_t port_allocate_result = task_result == KERN_SUCCESS &&
        MACH_PORT_VALID(child_task)
        ? mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                             &exception_port)
        : KERN_FAILURE;
    kern_return_t port_insert_result = port_allocate_result == KERN_SUCCESS
        ? mach_port_insert_right(mach_task_self(), exception_port,
                                 exception_port, MACH_MSG_TYPE_MAKE_SEND)
        : KERN_FAILURE;
    kern_return_t set_exception_result = port_insert_result == KERN_SUCCESS
        ? task_set_exception_ports(
              child_task, EXC_MASK_SOFTWARE, exception_port,
              EXCEPTION_STATE, ARM_THREAD_STATE64)
        : KERN_FAILURE;

    errno = 0;
    int continue_result = set_exception_result == KERN_SUCCESS
        ? ptrace(PT_CONTINUE, child, (caddr_t)1, 0)
        : -1;
    int continue_errno = errno;

    union __RequestUnion__exc_subsystem request;
    union __ReplyUnion__exc_subsystem reply;
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    mach_msg_return_t receive_result = continue_result == 0
        ? mach_msg(&request.Request_exception_raise.Head,
                   MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                   (mach_msg_size_t)sizeof(request), exception_port,
                   5000, MACH_PORT_NULL)
        : KERN_FAILURE;
    boolean_t demuxed = receive_result == MACH_MSG_SUCCESS
        ? exc_server(&request.Request_exception_raise.Head,
                     &reply.Reply_exception_raise.Head)
        : false;
    mach_msg_return_t reply_result = demuxed &&
        MACH_PORT_VALID(reply.Reply_exception_raise.Head.msgh_remote_port)
        ? mach_msg(&reply.Reply_exception_raise.Head,
                   MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                   reply.Reply_exception_raise.Head.msgh_size, 0,
                   MACH_PORT_NULL, 5000, MACH_PORT_NULL)
        : KERN_FAILURE;

    int cleanup_kill_result = -1;
    int cleanup_kill_errno = 0;
    if (!g_exception_observation.received && child > 1) {
        errno = 0;
        cleanup_kill_result = kill(child, SIGKILL);
        cleanup_kill_errno = errno;
    }
    int final_status = 0;
    bool final_waited = child > 1 &&
        wait_for_terminal_child(child, &final_status);

    if (MACH_PORT_VALID(child_task)) {
        (void)mach_port_deallocate(mach_task_self(), child_task);
    }
    if (MACH_PORT_VALID(exception_port)) {
        (void)mach_port_mod_refs(mach_task_self(), exception_port,
                                 MACH_PORT_RIGHT_RECEIVE, -1);
        (void)mach_port_deallocate(mach_task_self(), exception_port);
    }

    snprintf(
        result, result_size,
        "mode=mach-exception child=%d attrInit=%d attrFlags=%d spawn=%d "
        "initialWaited=%d initialStatus=0x%x initialStopped=%d "
        "attach=%d attachErrno=%d attachWaited=%d attachStatus=0x%x "
        "attachStopped=%d beforeCsops=%d beforeErrno=%d "
        "beforeFlags=0x%08x beforeDebugged=%d taskKr=%d task=0x%x "
        "portAllocateKr=%d portInsertKr=%d setExceptionKr=%d "
        "continue=%d continueErrno=%d receiveKr=0x%x demuxed=%d "
        "replyKr=0x%x exceptionReceived=%d expected=%d type=%d "
        "codeCount=%u code0=%d code1=%d flavor=%d stateCount=%u "
        "stateCopied=%d candidateStop=%d afterCsops=%d afterErrno=%d "
        "afterFlags=0x%08x afterDebugged=%d afterHardKill=%d "
        "afterPathLength=%d afterPath=%s ptraceKill=%d "
        "ptraceKillErrno=%d signalKill=%d signalKillErrno=%d "
        "cleanupKill=%d cleanupKillErrno=%d finalWaited=%d "
        "finalTerminal=%d finalStatus=0x%x",
        child, attribute_init, attribute_flags, spawn_result,
        initial_waited, initial_status, initial_stopped, attach_result,
        attach_errno, attach_waited, attach_status, attach_stopped,
        before_result, before_errno, before_flags,
        (before_flags & CODEX_CS_DEBUGGED) != 0, task_result, child_task,
        port_allocate_result, port_insert_result, set_exception_result,
        continue_result, continue_errno, receive_result, demuxed,
        reply_result, g_exception_observation.received,
        g_exception_observation.expected, g_exception_observation.type,
        g_exception_observation.code_count,
        g_exception_observation.code_zero,
        g_exception_observation.code_one,
        g_exception_observation.flavor,
        g_exception_observation.state_count,
        g_exception_observation.state_copied,
        g_exception_observation.candidate,
        g_exception_observation.csops_result,
        g_exception_observation.csops_errno,
        g_exception_observation.csflags,
        (g_exception_observation.csflags & CODEX_CS_DEBUGGED) != 0,
        (g_exception_observation.csflags &
         (CODEX_CS_HARD | CODEX_CS_KILL)) != 0,
        g_exception_observation.path_length,
        g_exception_observation.path_length > 0
            ? g_exception_observation.path
            : "<none>",
        g_exception_observation.ptrace_kill_result,
        g_exception_observation.ptrace_kill_errno,
        g_exception_observation.signal_kill_result,
        g_exception_observation.signal_kill_errno,
        cleanup_kill_result, cleanup_kill_errno, final_waited,
        final_waited &&
            (WIFEXITED(final_status) || WIFSIGNALED(final_status)),
        final_status);
}

int main(void) {
    char result[2048];
    run_spawn_probe(result, sizeof(result));
    bool written = write_result(result);
    dprintf(written ? STDOUT_FILENO : STDERR_FILENO,
            "codex-exec-candidate-trace-runner written=%d %s\n",
            written, result);
    return written ? 0 : 1;
}
#endif

__attribute__((visibility("default")))
const char *codex_exec_cs_persistence_probe(void) {
    static char result[1024];
    run_probe(result, sizeof(result));
    return result;
}

static _Atomic bool async_probe_running = false;

static void *async_probe_main(void *context) {
    (void)context;
    usleep(250 * 1000);

    char result[1024];
    run_probe(result, sizeof(result));
    (void)write_result(result);
    atomic_store_explicit(&async_probe_running, false, memory_order_release);
    return NULL;
}

__attribute__((visibility("default")))
int codex_exec_cs_persistence_probe_start_async(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &async_probe_running, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) {
        return EBUSY;
    }

    pthread_t thread;
    int create_result = pthread_create(&thread, NULL, async_probe_main, NULL);
    if (create_result != 0) {
        atomic_store_explicit(&async_probe_running, false,
                              memory_order_release);
        return create_result;
    }
    int detach_result = pthread_detach(thread);
    if (detach_result != 0) {
        return detach_result;
    }
    return 0;
}

__attribute__((visibility("default")))
const char *codex_exec_cs_persistence_probe_result_path(void) {
    return CODEX_RESULT_PATH;
}

struct observer_context {
    pid_t pid;
};

static _Atomic bool observer_running = false;

static void *observer_main(void *opaque_context) {
    struct observer_context context = *(struct observer_context *)opaque_context;
    free(opaque_context);

    bool armed = false;
    uint32_t baseline_flags = 0;
    uint32_t transition_flags = 0;
    uint32_t stopped_flags = 0;
    int transition_csops = -1;
    int transition_errno = 0;
    int stop_result = -1;
    int stop_errno = 0;
    int stopped_csops = -1;
    int stopped_errno = 0;
    unsigned int samples = 0;
    const char *phase = "timeout";

    for (samples = 0; samples < CODEX_OBSERVER_MAX_SAMPLES; ++samples) {
        uint32_t flags = 0;
        errno = 0;
        int result = csops(context.pid, CODEX_CS_OPS_STATUS, &flags,
                           sizeof(flags));
        int result_errno = errno;

        if (result != 0) {
            if (armed && result_errno == ESRCH) {
                phase = "exited";
                transition_csops = result;
                transition_errno = result_errno;
                break;
            }
            usleep(100);
            continue;
        }

        if (!armed) {
            if ((flags & CODEX_CS_DEBUGGED) != 0 &&
                (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0) {
                baseline_flags = flags;
                armed = true;
            }
            usleep(100);
            continue;
        }

        if (flags == baseline_flags) {
            usleep(100);
            continue;
        }

        phase = "transition";
        transition_flags = flags;
        transition_csops = result;
        transition_errno = result_errno;

        errno = 0;
        stop_result = kill(context.pid, SIGSTOP);
        stop_errno = errno;
        usleep(2 * 1000);

        errno = 0;
        stopped_csops = csops(context.pid, CODEX_CS_OPS_STATUS,
                              &stopped_flags, sizeof(stopped_flags));
        stopped_errno = errno;
        break;
    }

    char result[1024];
    snprintf(result, sizeof(result),
             "phase=%s pid=%d armed=%d samples=%u baseline=0x%08x "
             "transitionCsops=%d transitionErrno=%d transition=0x%08x "
             "transitionDebugged=%d transitionHardKill=%d stop=%d "
             "stopErrno=%d stoppedCsops=%d stoppedErrno=%d "
             "stopped=0x%08x stoppedDebugged=%d stoppedHardKill=%d",
             phase, context.pid, armed, samples, baseline_flags,
             transition_csops, transition_errno, transition_flags,
             (transition_flags & CODEX_CS_DEBUGGED) != 0,
             (transition_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0,
             stop_result, stop_errno, stopped_csops, stopped_errno,
             stopped_flags, (stopped_flags & CODEX_CS_DEBUGGED) != 0,
             (stopped_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0);
    (void)write_result_at_path(CODEX_OBSERVER_RESULT_PATH, result);
    atomic_store_explicit(&observer_running, false, memory_order_release);
    return NULL;
}

__attribute__((visibility("default")))
int codex_exec_cs_observer_start_async(pid_t pid) {
    if (pid <= 1 || pid == getpid()) {
        return EINVAL;
    }

    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &observer_running, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) {
        return EBUSY;
    }

    struct observer_context *context = malloc(sizeof(*context));
    if (context == NULL) {
        atomic_store_explicit(&observer_running, false, memory_order_release);
        return ENOMEM;
    }
    context->pid = pid;

    pthread_t thread;
    int create_result = pthread_create(&thread, NULL, observer_main, context);
    if (create_result != 0) {
        free(context);
        atomic_store_explicit(&observer_running, false, memory_order_release);
        return create_result;
    }
    int detach_result = pthread_detach(thread);
    if (detach_result != 0) {
        return detach_result;
    }
    return 0;
}

__attribute__((visibility("default")))
const char *codex_exec_cs_observer_result_path(void) {
    return CODEX_OBSERVER_RESULT_PATH;
}
