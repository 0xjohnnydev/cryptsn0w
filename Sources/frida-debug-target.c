#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef UNTITLED_EXPECT_GET_TASK_ALLOW
#define UNTITLED_EXPECT_GET_TASK_ALLOW 0
#endif

#define CS_OPS_STATUS 0

extern int csops(pid_t pid, unsigned int ops, void *useraddr,
                 size_t usersize);

static volatile sig_atomic_t keepRunning = 1;

static void Stop(int signalNumber) {
    (void)signalNumber;
    keepRunning = 0;
}

int main(int argc, char **argv) {
    if (argc != 1) {
        dprintf(STDERR_FILENO, "usage: %s\n", argv[0]);
        return 64;
    }

    struct sigaction action = {
        .sa_handler = Stop,
    };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        signal(SIGHUP, SIG_IGN) == SIG_ERR) {
        dprintf(STDERR_FILENO, "frida-debug-target: signal setup failed: %s\n",
                strerror(errno));
        return 71;
    }

    uint32_t flags = 0;
    errno = 0;
    int status = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    int statusError = errno;
    dprintf(STDOUT_FILENO,
            "fridaDebugTarget pid=%d expectedGetTaskAllow=%d "
            "csopsStatus=%d csopsErrno=%d csflags=0x%08x\n",
            getpid(), UNTITLED_EXPECT_GET_TASK_ALLOW, status, statusError,
            flags);

    while (keepRunning) {
        if (pause() == -1 && errno != EINTR) {
            dprintf(STDERR_FILENO, "frida-debug-target: pause failed: %s\n",
                    strerror(errno));
            return 74;
        }
    }

    dprintf(STDOUT_FILENO, "fridaDebugTarget stopped pid=%d\n", getpid());
    return 0;
}
