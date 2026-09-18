#include "customd-ptrauth-context-probe.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif

#ifndef CODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SHA256_HEX
#error "build must pin the intended codex-ellekit-loader SHA-256"
#endif
#ifndef CODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SHA256_HEX
#error "build must pin the intended marker dylib SHA-256"
#endif
#ifndef CODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SIZE
#error "build must pin the intended codex-ellekit-loader size"
#endif
#ifndef CODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SIZE
#error "build must pin the intended marker dylib size"
#endif

#define CODEX_PROC_PIDUNIQIDENTIFIERINFO 17
#define CODEX_PROBE_START_TIMEOUT_MSEC 5000U
#define CODEX_PROBE_RUN_TIMEOUT_MSEC 15000U
#define CODEX_SHA256_SIZE CC_SHA256_DIGEST_LENGTH

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern int posix_spawnattr_set_ptrauth_task_port_np(
    posix_spawnattr_t *restrict attributes, mach_port_t task_port);

struct codex_proc_unique_info {
    uint8_t uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_pid_version;
    uint64_t reserved2;
    uint64_t reserved3;
};

struct process_identity {
    pid_t pid;
    char path[PATH_MAX];
    struct codex_proc_unique_info unique;
};

_Static_assert(sizeof(struct codex_proc_unique_info) == 56,
               "proc unique-info ABI changed");

static volatile sig_atomic_t g_child = -1;

static uint64_t monotonic_msec(void) {
    struct timespec now = {0};
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0
               ? (uint64_t)now.tv_sec * UINT64_C(1000) +
                     (uint64_t)now.tv_nsec / UINT64_C(1000000)
               : 0;
}

static void stop_handler(int signal_number) {
    pid_t child = (pid_t)g_child;
    if (child > 1) {
        (void)kill(-child, SIGKILL);
    }
    _exit(128 + signal_number);
}

static int hex_nibble(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    return -1;
}

static bool parse_sha256(const char *text,
                         uint8_t digest[CODEX_SHA256_SIZE]) {
    if (text == NULL || strlen(text) != CODEX_SHA256_SIZE * 2U) {
        return false;
    }
    for (size_t index = 0; index < CODEX_SHA256_SIZE; ++index) {
        int high = hex_nibble(text[index * 2U]);
        int low = hex_nibble(text[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        digest[index] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static bool sha256_descriptor(int descriptor,
                              uint8_t digest[CODEX_SHA256_SIZE]) {
    if (lseek(descriptor, 0, SEEK_SET) < 0) {
        return false;
    }
    CC_SHA256_CTX context;
    if (CC_SHA256_Init(&context) != 1) {
        return false;
    }
    uint8_t buffer[64U * 1024U];
    for (;;) {
        ssize_t amount = read(descriptor, buffer, sizeof(buffer));
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0 ||
            (amount > 0 &&
             CC_SHA256_Update(&context, buffer, (CC_LONG)amount) != 1)) {
            return false;
        }
        if (amount == 0) {
            break;
        }
    }
    return CC_SHA256_Final(digest, &context) == 1;
}

static bool pinned_file_exact(const char *path, const char *expected_hex,
                              uint64_t expected_size, bool executable) {
    uint8_t expected[CODEX_SHA256_SIZE] = {0};
    uint8_t observed[CODEX_SHA256_SIZE] = {0};
    struct stat path_status = {0};
    struct stat descriptor_status = {0};
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    bool exact = descriptor >= 0 && parse_sha256(expected_hex, expected) &&
                 lstat(path, &path_status) == 0 &&
                 fstat(descriptor, &descriptor_status) == 0 &&
                 S_ISREG(path_status.st_mode) &&
                 S_ISREG(descriptor_status.st_mode) &&
                 path_status.st_dev == descriptor_status.st_dev &&
                 path_status.st_ino == descriptor_status.st_ino &&
                 descriptor_status.st_uid == 0 &&
                 descriptor_status.st_nlink == 1 &&
                 (descriptor_status.st_mode & 0022) == 0 &&
                 (!executable || (descriptor_status.st_mode & 0111) != 0) &&
                 descriptor_status.st_size >= 0 &&
                 (uint64_t)descriptor_status.st_size == expected_size &&
                 sha256_descriptor(descriptor, observed) &&
                 memcmp(observed, expected, sizeof(observed)) == 0;
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    return exact;
}

static bool copy_unique_info(pid_t pid,
                             struct codex_proc_unique_info *unique) {
    memset(unique, 0, sizeof(*unique));
    int amount = proc_pidinfo(pid, CODEX_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              unique, sizeof(*unique));
    return amount == (int)sizeof(*unique);
}

static bool identities_equal(const struct process_identity *left,
                             const struct process_identity *right) {
    return left->pid == right->pid && strcmp(left->path, right->path) == 0 &&
           left->unique.unique_id == right->unique.unique_id &&
           left->unique.pid_version == right->unique.pid_version &&
           left->unique.parent_unique_id == right->unique.parent_unique_id &&
           memcmp(left->unique.uuid, right->unique.uuid,
                  sizeof(left->unique.uuid)) == 0;
}

static bool bind_process(pid_t pid, struct process_identity *identity) {
    struct process_identity first = {.pid = pid};
    struct process_identity second = {.pid = pid};
    if (pid <= 1 || proc_pidpath(pid, first.path, sizeof(first.path)) <= 0 ||
        !copy_unique_info(pid, &first.unique) ||
        proc_pidpath(pid, second.path, sizeof(second.path)) <= 0 ||
        !copy_unique_info(pid, &second.unique) ||
        !identities_equal(&first, &second)) {
        return false;
    }
    *identity = first;
    return true;
}

static bool process_still_exact(const struct process_identity *expected) {
    struct process_identity current = {0};
    return expected != NULL && bind_process(expected->pid, &current) &&
           identities_equal(expected, &current);
}

static bool find_unique_process(const char *path,
                                struct process_identity *identity) {
    int reported = proc_listallpids(NULL, 0);
    if (reported <= 0 || reported > 256 * 1024) {
        return false;
    }
    int capacity = reported + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return false;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    bool found = false;
    for (int index = 0; index < count && index < capacity; ++index) {
        struct process_identity candidate = {0};
        if (pids[index] <= 1 || !bind_process(pids[index], &candidate) ||
            strcmp(candidate.path, path) != 0) {
            continue;
        }
        if (found) {
            found = false;
            break;
        }
        *identity = candidate;
        found = true;
    }
    free(pids);
    return found;
}

static bool task_matches_process(task_t task,
                                 const struct process_identity *identity) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    return MACH_PORT_VALID(task) && identity != NULL &&
           task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) ==
               KERN_SUCCESS &&
           count == TASK_AUDIT_TOKEN_COUNT &&
           (pid_t)token.val[5] == identity->pid &&
           (int32_t)token.val[7] == identity->unique.pid_version;
}

static bool wait_for_stop(pid_t child, int *status) {
    uint64_t deadline = monotonic_msec() + CODEX_PROBE_START_TIMEOUT_MSEC;
    while (monotonic_msec() < deadline) {
        pid_t waited = waitpid(child, status, WUNTRACED | WNOHANG);
        if (waited == child) {
            return WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGSTOP;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool wait_for_exit(pid_t child, int *exit_code) {
    uint64_t deadline = monotonic_msec() + CODEX_PROBE_RUN_TIMEOUT_MSEC;
    while (monotonic_msec() < deadline) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (WIFEXITED(status)) {
                *exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                *exit_code = 128 + WTERMSIG(status);
            } else {
                *exit_code = 255;
            }
            return true;
        }
        if (waited < 0 && errno != EINTR) {
            return false;
        }
        usleep(10U * 1000U);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool read_report(int descriptor,
                        struct customd_ptrauth_probe_report *report) {
    int flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
        return false;
    }
    uint8_t *cursor = (uint8_t *)report;
    size_t used = 0;
    uint64_t deadline = monotonic_msec() + CODEX_PROBE_RUN_TIMEOUT_MSEC;
    while (used < sizeof(*report) && monotonic_msec() < deadline) {
        int remaining = (int)(deadline - monotonic_msec());
        struct pollfd poll_descriptor = {
            .fd = descriptor,
            .events = POLLIN | POLLHUP,
        };
        int poll_result = poll(&poll_descriptor, 1, remaining);
        if (poll_result < 0 && errno == EINTR) {
            continue;
        }
        if (poll_result <= 0) {
            return false;
        }
        ssize_t amount = read(descriptor, cursor + used,
                              sizeof(*report) - used);
        if (amount > 0) {
            used += (size_t)amount;
            continue;
        }
        if (amount < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        return false;
    }
    uint8_t extra = 0;
    ssize_t extra_amount = read(descriptor, &extra, sizeof(extra));
    return used == sizeof(*report) && extra_amount <= 0 &&
           (extra_amount == 0 || errno == EAGAIN);
}

static void terminate_child(pid_t child) {
    if (child <= 1) {
        return;
    }
    (void)kill(-child, SIGKILL);
    for (unsigned int attempt = 0; attempt < 500U; ++attempt) {
        pid_t waited = waitpid(child, NULL, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            return;
        }
        if (waited < 0 && errno != EINTR) {
            return;
        }
        usleep(10U * 1000U);
    }
}

int main(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "ptrauth-context-probe: root is required\n");
        return 64;
    }
    struct sigaction action = {0};
    action.sa_handler = stop_handler;
    (void)sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0) {
        return 65;
    }

    bool artifacts_exact = pinned_file_exact(
        CODEX_PTRAUTH_PROBE_LOADER_PATH,
        CODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SHA256_HEX,
        CODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SIZE, true) &&
        pinned_file_exact(CODEX_PTRAUTH_PROBE_MARKER_PATH,
                          CODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SHA256_HEX,
                          CODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SIZE, false);
    if (!artifacts_exact) {
        fprintf(stderr,
                "ptrauth-context-probe: pinned loader/marker rejected\n");
        return 66;
    }

    struct process_identity cryptexd = {0};
    struct process_identity springboard = {0};
    if (!find_unique_process(CODEX_PTRAUTH_PROBE_CRYPTEXD_PATH,
                             &cryptexd) ||
        !find_unique_process(CODEX_PTRAUTH_PROBE_SPRINGBOARD_PATH,
                             &springboard)) {
        fprintf(stderr,
                "ptrauth-context-probe: exact donor/inspection target is not "
                "unique\n");
        return 67;
    }

    task_t donor_task = MACH_PORT_NULL;
    kern_return_t task_result =
        task_for_pid(mach_task_self(), cryptexd.pid, &donor_task);
    if (task_result != KERN_SUCCESS || !task_matches_process(donor_task,
                                                              &cryptexd) ||
        !process_still_exact(&cryptexd)) {
        if (MACH_PORT_VALID(donor_task)) {
            (void)mach_port_deallocate(mach_task_self(), donor_task);
        }
        fprintf(stderr,
                "ptrauth-context-probe: cryptexd task binding failed mach=%d\n",
                task_result);
        return 68;
    }

    int report_pipe[2] = {-1, -1};
    if (pipe(report_pipe) != 0 ||
        report_pipe[0] == CODEX_PTRAUTH_PROBE_REPORT_FD ||
        report_pipe[1] == CODEX_PTRAUTH_PROBE_REPORT_FD) {
        if (report_pipe[0] >= 0) {
            (void)close(report_pipe[0]);
        }
        if (report_pipe[1] >= 0) {
            (void)close(report_pipe[1]);
        }
        (void)mach_port_deallocate(mach_task_self(), donor_task);
        return 69;
    }
    (void)fcntl(report_pipe[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(report_pipe[1], F_SETFD, FD_CLOEXEC);

    char loader_real_path[PATH_MAX] = {0};
    char springboard_pid[24] = {0};
    char report_fd_environment[64] = {0};
    char parent_environment[64] = {0};
    char donor_environment[64] = {0};
    char unique_environment[96] = {0};
    char version_environment[64] = {0};
    char dyld_environment[PATH_MAX + 32] = {0};
    bool text_exact =
        realpath(CODEX_PTRAUTH_PROBE_LOADER_PATH, loader_real_path) != NULL &&
        snprintf(springboard_pid, sizeof(springboard_pid), "%d",
                 springboard.pid) > 0 &&
        snprintf(report_fd_environment, sizeof(report_fd_environment),
                 CODEX_PTRAUTH_PROBE_ENV_REPORT_FD "=%d",
                 CODEX_PTRAUTH_PROBE_REPORT_FD) > 0 &&
        snprintf(parent_environment, sizeof(parent_environment),
                 CODEX_PTRAUTH_PROBE_ENV_PARENT_PID "=%d", getpid()) > 0 &&
        snprintf(donor_environment, sizeof(donor_environment),
                 CODEX_PTRAUTH_PROBE_ENV_DONOR_PID "=%d", cryptexd.pid) > 0 &&
        snprintf(unique_environment, sizeof(unique_environment),
                 CODEX_PTRAUTH_PROBE_ENV_DONOR_UNIQUE_ID "=%llu",
                 cryptexd.unique.unique_id) > 0 &&
        snprintf(version_environment, sizeof(version_environment),
                 CODEX_PTRAUTH_PROBE_ENV_DONOR_PID_VERSION "=%d",
                 cryptexd.unique.pid_version) > 0 &&
        snprintf(dyld_environment, sizeof(dyld_environment),
                 "DYLD_INSERT_LIBRARIES=%s",
                 CODEX_PTRAUTH_PROBE_MARKER_PATH) > 0;

    char *arguments[] = {
        (char *)CODEX_PTRAUTH_PROBE_LOADER_PATH,
        (char *)"--inspect-pid",
        springboard_pid,
        (char *)"--ptrauth-child",
        NULL,
    };
    char *environment[] = {
        (char *)"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        (char *)"HOME=/var/root",
        (char *)"TMPDIR=/var/tmp",
        dyld_environment,
        report_fd_environment,
        parent_environment,
        donor_environment,
        unique_environment,
        version_environment,
        NULL,
    };

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int actions_result = posix_spawn_file_actions_init(&actions);
    int attributes_result = posix_spawnattr_init(&attributes);
    int setup_result = actions_result != 0 ? actions_result
                                           : attributes_result;
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_adddup2(
            &actions, report_pipe[1], CODEX_PTRAUTH_PROBE_REPORT_FD);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addclose(&actions,
                                                         report_pipe[0]);
    }
    if (setup_result == 0) {
        setup_result = posix_spawn_file_actions_addclose(&actions,
                                                         report_pipe[1]);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setflags(
            &attributes,
            (short)(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP));
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_setpgroup(&attributes, 0);
    }
    if (setup_result == 0) {
        setup_result = posix_spawnattr_set_ptrauth_task_port_np(&attributes,
                                                                donor_task);
    }

    pid_t child = -1;
    int spawn_result =
        setup_result == 0 && text_exact
            ? posix_spawn(&child, CODEX_PTRAUTH_PROBE_LOADER_PATH, &actions,
                          &attributes, arguments, environment)
            : (setup_result != 0 ? setup_result : EINVAL);
    if (actions_result == 0) {
        (void)posix_spawn_file_actions_destroy(&actions);
    }
    if (attributes_result == 0) {
        (void)posix_spawnattr_destroy(&attributes);
    }
    (void)mach_port_deallocate(mach_task_self(), donor_task);
    (void)close(report_pipe[1]);
    report_pipe[1] = -1;
    if (spawn_result != 0 || child <= 1 || getpgid(child) != child) {
        terminate_child(child);
        (void)close(report_pipe[0]);
        fprintf(stderr,
                "ptrauth-context-probe: loader spawn failed result=%d "
                "child=%d\n",
                spawn_result, child);
        return 70;
    }
    g_child = child;

    int stop_status = 0;
    struct process_identity child_identity = {0};
    bool stopped_exact = wait_for_stop(child, &stop_status) &&
                         bind_process(child, &child_identity) &&
                         strcmp(child_identity.path, loader_real_path) == 0 &&
                         getpgid(child) == child;
    if (!stopped_exact || kill(child, SIGCONT) != 0) {
        terminate_child(child);
        g_child = -1;
        (void)close(report_pipe[0]);
        fprintf(stderr,
                "ptrauth-context-probe: suspended loader identity/resume "
                "failed status=0x%x\n",
                stop_status);
        return 71;
    }

    struct customd_ptrauth_probe_report report = {0};
    bool report_exact = read_report(report_pipe[0], &report);
    (void)close(report_pipe[0]);
    int loader_exit = 255;
    bool child_reaped = wait_for_exit(child, &loader_exit);
    if (!child_reaped) {
        terminate_child(child);
    }
    g_child = -1;

    bool final_artifacts = pinned_file_exact(
        CODEX_PTRAUTH_PROBE_LOADER_PATH,
        CODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SHA256_HEX,
        CODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SIZE, true) &&
        pinned_file_exact(CODEX_PTRAUTH_PROBE_MARKER_PATH,
                          CODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SHA256_HEX,
                          CODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SIZE, false);
    uint32_t required = CODEX_PTRAUTH_PROBE_REQUIRED_FLAGS;
    bool success = report_exact && child_reaped && loader_exit == 0 &&
                   report.magic == CODEX_PTRAUTH_PROBE_REPORT_MAGIC &&
                   report.version == CODEX_PTRAUTH_PROBE_REPORT_VERSION &&
                   report.size == sizeof(report) &&
                   (report.flags & required) == required &&
                   report.self_pid == child &&
                   report.parent_pid == getpid() &&
                   report.donor_pid == cryptexd.pid &&
                   report.donor_unique_id == cryptexd.unique.unique_id &&
                   report.donor_pid_version == cryptexd.unique.pid_version &&
                   report.real_uid == 0 && report.effective_uid == 0 &&
                   report.csops_result == 0 &&
                   report.task_for_pid_result == KERN_SUCCESS &&
                   report.task_info_result == KERN_SUCCESS &&
                   report.task_audit_pid == cryptexd.pid &&
                   report.task_audit_pid_version ==
                       cryptexd.unique.pid_version &&
                   process_still_exact(&cryptexd) &&
                   process_still_exact(&springboard) && final_artifacts;
    if (!success) {
        fprintf(stderr,
                "ptrauth-context-probe: failed report=%d reaped=%d exit=%d "
                "flags=0x%08x required=0x%08x task=%d audit=%d "
                "artifacts=%d\n",
                report_exact, child_reaped, loader_exit, report.flags,
                required, report.task_for_pid_result,
                report.task_info_result, final_artifacts);
        return 72;
    }

    printf("customd-ptrauth-context-probe=success loader-pid=%d "
           "donor-pid=%d inspect-pid=%d flags=0x%08x csflags=0x%08x "
           "loader-exit=%d\n",
           child, cryptexd.pid, springboard.pid, report.flags,
           report.csflags, loader_exit);
    return 0;
}
