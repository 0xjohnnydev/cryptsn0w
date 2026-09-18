#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CODEX_CS_OPS_STATUS 0U

static const char *const kSpringBoardPath =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";

extern int csops(pid_t, unsigned int, void *, size_t);
extern int proc_listallpids(void *, int);
extern int proc_pidpath(int, void *, uint32_t);

static pid_t find_springboard(void) {
    int bytes = proc_listallpids(NULL, 0);
    if (bytes <= 0 || bytes > 1024 * 1024) {
        return -1;
    }
    int capacity = bytes / (int)sizeof(pid_t) + 32;
    pid_t *pids = calloc((size_t)capacity, sizeof(*pids));
    if (pids == NULL) {
        return -1;
    }
    int count = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    pid_t found = -1;
    for (int index = 0; index < count && index < capacity; ++index) {
        if (pids[index] <= 1) {
            continue;
        }
        char path[PATH_MAX] = {0};
        if (proc_pidpath(pids[index], path, sizeof(path)) > 0 &&
            strcmp(path, kSpringBoardPath) == 0) {
            if (found > 1) {
                found = -1;
                break;
            }
            found = pids[index];
        }
    }
    free(pids);
    return found;
}

int main(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "worker-host-probe euid=%u admitted=0\n", geteuid());
        return 10;
    }
    pid_t target = find_springboard();
    if (target <= 1) {
        fprintf(stderr, "worker-host-probe springboard=%d admitted=0\n",
                target);
        return 11;
    }
    uint32_t flags = 0;
    int cs_result = csops(target, CODEX_CS_OPS_STATUS, &flags, sizeof(flags));
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t task_result =
        task_for_pid(mach_task_self(), target, &task);
    bool admitted = cs_result == 0 && task_result == KERN_SUCCESS &&
        MACH_PORT_VALID(task);
    printf("worker-host-probe pid=%d cs=%d flags=0x%08x taskKr=%d "
           "task=0x%x admitted=%d\n",
           target, cs_result, flags, task_result, task, admitted);
    if (MACH_PORT_VALID(task)) {
        (void)mach_port_deallocate(mach_task_self(), task);
    }
    return admitted ? 0 : 12;
}
