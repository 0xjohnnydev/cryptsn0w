#include <fcntl.h>
#include <os/log.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const kMarkerPath =
    "/var/jb/var/lib/codex-broker-probe/postinst.txt";
static const char *const kLoadedMarkerPath =
    "/var/mobile/Library/Caches/codex-broker-probe-loaded.txt";

__attribute__((constructor)) static void codex_broker_probe_loaded(void) {
    char marker[256] = "missing";
    int descriptor = open(kMarkerPath, O_RDONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        ssize_t amount = read(descriptor, marker, sizeof(marker) - 1);
        close(descriptor);
        if (amount > 0) {
            marker[amount] = '\0';
            marker[strcspn(marker, "\r\n")] = '\0';
        } else {
            snprintf(marker, sizeof(marker), "unreadable");
        }
    }

    os_log_t log =
        os_log_create("com.openai.codex.broker-probe", "tweak");
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT,
                     "BROKER_PROBE_LOADED version=1.0.18 pid=%d uid=%u gid=%u marker=%{public}s",
                     getpid(), getuid(), getgid(), marker);

    int loaded = open(kLoadedMarkerPath,
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (loaded >= 0) {
        dprintf(loaded, "BROKER_PROBE_LOADED version=1.0.18 pid=%d uid=%u gid=%u %s\n",
                getpid(), getuid(), getgid(), marker);
        fsync(loaded);
        close(loaded);
    }
}
