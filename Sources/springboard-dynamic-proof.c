#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int proc_pidpath(int, void *, uint32_t);

__attribute__((constructor)) static void codex_springboard_dynamic_proof(void) {
    static const char expected[] =
        "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
    char process_path[PATH_MAX] = {0};
    if (getpid() <= 1 ||
        proc_pidpath(getpid(), process_path, sizeof(process_path)) <= 0 ||
        strcmp(process_path, expected) != 0) {
        return;
    }
    int descriptor = open("/var/tmp/codex-springboard-dynamic.loaded",
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return;
    }
    (void)dprintf(descriptor,
                  "codex-springboard-dynamic=loaded pid=%d uid=%u euid=%u "
                  "path=%s\n",
                  getpid(), getuid(), geteuid(), process_path);
    (void)fsync(descriptor);
    (void)close(descriptor);
}
