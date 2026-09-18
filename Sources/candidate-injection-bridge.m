#import <Foundation/Foundation.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CODEX_CANDIDATE_PID_ENV "CODEX_CANDIDATE_PID"
#define CODEX_CANDIDATE_RESULT_FD 195
#define CODEX_CANDIDATE_GATE_READY_FD 196
#define CODEX_CANDIDATE_GATE_RELEASE_FD 197

#define CODEX_CANDIDATE_RESULT_MAGIC 0x43494252U
#define CODEX_CANDIDATE_RESULT_VERSION 1U

static const char *const kCandidateHookPath =
    "/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib";
static const char *const kCandidateCanaryPath =
    "/var/jb/usr/lib/codex-springboard-live-canary.dylib";

/* One native-endian, fixed-width 16-byte record is emitted exactly once. */
struct codex_candidate_injection_result {
    uint32_t magic;
    uint32_t version;
    int32_t status;
    int32_t pid;
};

_Static_assert(sizeof(struct codex_candidate_injection_result) == 16,
               "candidate injection result ABI changed");

extern int codex_ellekit_compat_loader_main(int argc, char *argv[]);

static bool parse_candidate_pid(const char *text, pid_t *pid_out) {
    if (text == NULL || pid_out == NULL) {
        return false;
    }

    /* INT_MAX is ten decimal digits on the supported Darwin ABI.  A bounded
     * length check also rejects an unterminated or unreasonably large value
     * before the arithmetic loop touches it. */
    size_t length = strnlen(text, 11);
    if (length == 0 || length > 10) {
        return false;
    }

    uint64_t value = 0;
    for (size_t index = 0; index < length; ++index) {
        unsigned char character = (unsigned char)text[index];
        if (character < (unsigned char)'0' ||
            character > (unsigned char)'9') {
            return false;
        }
        value = value * 10U + (uint64_t)(character - (unsigned char)'0');
        if (value > (uint64_t)INT_MAX) {
            return false;
        }
    }
    if (value <= 1U) {
        return false;
    }

    *pid_out = (pid_t)value;
    return true;
}

static bool result_descriptor_is_exact_pipe_writer(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL);
    struct stat status = {0};
    if (flags < 0 || fstat(descriptor, &status) != 0 ||
        !S_ISFIFO(status.st_mode)) {
        return false;
    }
    int access_mode = flags & O_ACCMODE;
    return access_mode == O_WRONLY || access_mode == O_RDWR;
}

static bool write_all(int descriptor, const void *buffer, size_t length) {
    const uint8_t *cursor = buffer;
    while (length != 0) {
        ssize_t amount = write(descriptor, cursor, length);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        length -= (size_t)amount;
    }
    return true;
}

static void *codex_candidate_injection_bridge_thread(void *context) {
    (void)context;
    @autoreleasepool {
        setlinebuf(stdout);
        setlinebuf(stderr);

        if (!result_descriptor_is_exact_pipe_writer(
                CODEX_CANDIDATE_RESULT_FD)) {
            fprintf(stderr,
                    "candidate-bridge: result fd %d is not an exact pipe "
                    "writer; refusing injection\n",
                    CODEX_CANDIDATE_RESULT_FD);
            return NULL;
        }

        /* Keep a vanished reader from delivering SIGPIPE to the carrier. */
        (void)fcntl(CODEX_CANDIDATE_RESULT_FD, F_SETNOSIGPIPE, 1);

        struct codex_candidate_injection_result result = {
            .magic = CODEX_CANDIDATE_RESULT_MAGIC,
            .version = CODEX_CANDIDATE_RESULT_VERSION,
            .status = 64,
            .pid = 0,
        };

        pid_t candidate_pid = 0;
        const char *candidate_pid_environment =
            getenv(CODEX_CANDIDATE_PID_ENV);
        if (!parse_candidate_pid(candidate_pid_environment, &candidate_pid)) {
            fprintf(stderr,
                    "candidate-bridge: missing or invalid %s; refusing "
                    "injection\n",
                    CODEX_CANDIDATE_PID_ENV);
        } else {
            char candidate_pid_text[16];
            int length = snprintf(candidate_pid_text,
                                  sizeof(candidate_pid_text), "%d",
                                  candidate_pid);
            if (length <= 0 || (size_t)length >= sizeof(candidate_pid_text)) {
                result.status = 71;
                fprintf(stderr,
                        "candidate-bridge: could not canonicalize candidate "
                        "pid; refusing injection\n");
            } else {
                char *arguments[] = {
                    (char *)"codex-candidate-injection-bridge",
                    (char *)"--inject-pid-pair-gated",
                    candidate_pid_text,
                    (char *)kCandidateHookPath,
                    (char *)kCandidateCanaryPath,
                    (char *)"196",
                    (char *)"197",
                    (char *)"--ptrauth-child",
                    NULL,
                };
                result.pid = candidate_pid;
                fprintf(stdout,
                        "candidate-bridge: invoking fixed gated injection "
                        "for pid=%d ready-fd=%d release-fd=%d\n",
                        candidate_pid, CODEX_CANDIDATE_GATE_READY_FD,
                        CODEX_CANDIDATE_GATE_RELEASE_FD);
                result.status = codex_ellekit_compat_loader_main(8, arguments);
                fprintf(stdout,
                        "candidate-bridge: gated injection completed "
                        "pid=%d status=%d\n",
                        candidate_pid, result.status);
            }
        }

        if (!write_all(CODEX_CANDIDATE_RESULT_FD, &result,
                       sizeof(result))) {
            fprintf(stderr,
                    "candidate-bridge: result write failed: %s\n",
                    strerror(errno));
        }
        (void)close(CODEX_CANDIDATE_RESULT_FD);
    }
    return NULL;
}

__attribute__((constructor))
static void codex_candidate_injection_bridge_start(void) {
    setlinebuf(stdout);
    setlinebuf(stderr);
    if (!result_descriptor_is_exact_pipe_writer(
            CODEX_CANDIDATE_RESULT_FD)) {
        fprintf(stderr,
                "candidate-bridge: constructor rejected result fd %d\n",
                CODEX_CANDIDATE_RESULT_FD);
        return;
    }

    pthread_attr_t attributes;
    int attribute_result = pthread_attr_init(&attributes);
    if (attribute_result == 0) {
        attribute_result = pthread_attr_setdetachstate(
            &attributes, PTHREAD_CREATE_DETACHED);
    }
    pthread_t thread = NULL;
    int create_result = attribute_result == 0
                            ? pthread_create(
                                  &thread, &attributes,
                                  codex_candidate_injection_bridge_thread,
                                  NULL)
                            : attribute_result;
    if (attribute_result == 0) {
        (void)pthread_attr_destroy(&attributes);
    }
    if (create_result == 0) {
        fprintf(stdout,
                "candidate-bridge: detached injection thread started\n");
        return;
    }

    struct codex_candidate_injection_result result = {
        .magic = CODEX_CANDIDATE_RESULT_MAGIC,
        .version = CODEX_CANDIDATE_RESULT_VERSION,
        .status = 70,
        .pid = 0,
    };
    fprintf(stderr,
            "candidate-bridge: detached thread creation failed: %s\n",
            strerror(create_result));
    (void)write_all(CODEX_CANDIDATE_RESULT_FD, &result, sizeof(result));
    (void)close(CODEX_CANDIDATE_RESULT_FD);
}
