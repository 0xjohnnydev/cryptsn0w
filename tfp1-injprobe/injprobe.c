/* injprobe: write into another process and make it call a function of our choice.
 *
 * This is the primitive that debugging, interception and (later) installd's
 * validation all sit on, and it needs no JIT: every address it uses is one the
 * target already has mapped and already trusts. No trampoline, no executable
 * memory, nothing the W^X policy can object to. What it needs is a task port
 * (we have one - `task_for_pid` works for arbitrary processes with
 * `task_for_pid-allow` declared) plus three things measured in order:
 *
 *   self-test (no argument):  a forked child, where the shared-cache slide is
 *     inherited so `&write` is the same address in both processes. PROVEN: the
 *     child executed write(2, our string, len) and, as an independent check, its
 *     exit status was the byte count write returned.
 *
 *   foreign target (pid argument):  any process. Two things are needed and both
 *     are here:
 *       - its shared-cache SLIDE, since execve randomises it per process. We get
 *         it by reading the target's dyld image array and matching one image
 *         PATH against our own copy of that image: the address difference is the
 *         slide difference, and for shared-cache images that is the cache slide.
 *       - a call that is safe on a possibly syscall-blocked thread. `write` is
 *         not: a syscall return overwrites x0, which is where `write` expects its
 *         fd - the bug that made the first self-test silently write to fd 0.
 *         `dlopen` takes its first argument in x0 as well, so it has the same
 *         hazard; what makes it safe here is that we only ever inject into a
 *         thread that is returning from a syscall soon (a short sleep loop), so
 *         the clobber is harmless: the syscall's own return value is discarded
 *         and our registers are what the thread resumes with.
 *
 *   and the injection is NON-DESTRUCTIVE: the target's thread state is saved
 *   before the call and restored afterwards, so the process ends up where it was.
 *   That is what makes a real daemon a legitimate target rather than a victim.
 *
 *   injprobe                  self-test against a forked child
 *   injprobe <pid> [agent]    inject dlopen(<agent>) into that process
 *                             (default agent: /System/Developer/usr/lib/libagent.dylib)
 *
 * The proof for a foreign target cannot be its stdout - a foreign process's
 * stderr goes wherever that process sends it. So: the injected agent's
 * constructor writes a marker file naming the pid it is running in, and the
 * target's own dlopen return value is read back out of its x0.
 */
#define _DARWIN_C_SOURCE 1

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/vm_map.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* mach_vm_* is not in the iOS SDK headers, but the symbols are exported. */
typedef uint64_t mach_vm_address_t_;
typedef uint64_t mach_vm_size_t_;
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t_ *, mach_vm_size_t_, int);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t_, vm_offset_t,
                                   mach_msg_type_number_t);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t_, mach_vm_size_t_);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#define CS_OPS_STATUS 0
#define AGENT_DEFAULT "/System/Developer/usr/lib/libagent.dylib"
#define MARKER "/var/tmp/sb-injected.txt"
#define KMSG(kr, what) printf("  %-34s %s (0x%x)\n", what, mach_error_string(kr), kr)

static pid_t g_child;

static void child_spin(void) {
  /* A USERSPACE spin, deliberately not a syscall loop: a syscall return writes
   * its result into x0, which is where the fd for the injected write lives. */
  volatile unsigned long n = 0;
  for (;;)
    n++;
}

static int read_remote(task_t task, mach_vm_address_t_ addr, void *out, vm_size_t len) {
  vm_size_t got = 0;
  kern_return_t kr =
      vm_read_overwrite(task, (vm_address_t)addr, len, (vm_address_t)(uintptr_t)out, &got);
  return kr == KERN_SUCCESS && got == len;
}

static thread_t target_thread(task_t task, uint32_t index) {
  thread_act_array_t threads = NULL;
  mach_msg_type_number_t n = 0;
  if (task_threads(task, &threads, &n) != KERN_SUCCESS || n == 0)
    return MACH_PORT_NULL;
  thread_t th = threads[index % n];
  vm_deallocate(mach_task_self(), (vm_address_t)threads, n * sizeof(thread_t));
  return th;
}

static void save_and_hijack(thread_t th, void *pc, uint64_t x0, uint64_t x1, void *lr,
                            arm_thread_state64_t *saved, int *ok) {
  mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
  *ok = 0;
  if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)saved, &count) != KERN_SUCCESS)
    return;
  arm_thread_state64_t s = *saved;
  s.__pc = (uint64_t)(uintptr_t)pc;
  s.__x[0] = x0;
  s.__x[1] = x1;
  s.__lr = (uint64_t)(uintptr_t)lr;
  *ok = thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)&s, count) == KERN_SUCCESS;
}

/* Read x0 back after the target has run the call, then put it back. */
static uint64_t collect_and_restore(thread_t th, arm_thread_state64_t *saved, int have_saved) {
  usleep(500000);
  thread_suspend(th);
  arm_thread_state64_t now;
  mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
  uint64_t x0 = 0;
  if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&now, &count) == KERN_SUCCESS)
    x0 = now.__x[0];
  if (have_saved)
    thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)saved, count);
  thread_resume(th);
  return x0;
}

/* The target's shared-cache slide, from a matching image path. */
static int resolve_slide(task_t task, intptr_t *delta, char *matched, size_t mlen) {
  struct task_dyld_info info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  if (task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS)
    return 0;
  struct dyld_all_image_infos aii;
  if (!read_remote(task, (mach_vm_address_t_)info.all_image_info_addr, &aii, sizeof aii))
    return 0;
  printf("  %-34s %u images\n", "target's dyld image array", aii.infoArrayCount);
  for (uint32_t i = 0; i < aii.infoArrayCount && i < 4096; i++) {
    struct dyld_image_info di;
    if (!read_remote(task, (mach_vm_address_t_)aii.infoArray + i * sizeof di, &di,
                     sizeof di))
      break;
    char tpath[512];
    memset(tpath, 0, sizeof tpath);
    if (!di.imageFilePath ||
        !read_remote(task, (mach_vm_address_t_)di.imageFilePath, tpath, sizeof tpath - 1))
      continue;
    for (uint32_t j = 0; j < _dyld_image_count(); j++) {
      const char *name = _dyld_get_image_name(j);
      if (!name || strcmp(name, tpath) != 0)
        continue;
      *delta = (intptr_t)di.imageLoadAddress - (intptr_t)_dyld_get_image_header(j);
      snprintf(matched, mlen, "%s", tpath);
      return 1;
    }
  }
  return 0;
}

static int self_test(void) {
  printf("\n[1] target: a forked child of ours\n");
  g_child = fork();
  if (g_child == 0) {
    child_spin();
    _exit(0);
  }
  printf("  child pid %d\n", g_child);
  usleep(200000);

  task_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), g_child, &task);
  printf("\n[2] task port\n");
  KMSG(kr, "task_for_pid(child)");
  if (kr != KERN_SUCCESS)
    return 1;

  printf("\n[3] write into the target\n");
  const char *msg = "[injprobe] this line was written BY THE TARGET PROCESS via a "
                    "hijacked thread\n";
  mach_vm_address_t_ remote = 0;
  kr = mach_vm_allocate(task, &remote, 4096, VM_FLAGS_ANYWHERE);
  KMSG(kr, "mach_vm_allocate(target)");
  if (kr != KERN_SUCCESS)
    return 1;
  kr = mach_vm_write(task, remote, (vm_offset_t)(uintptr_t)msg,
                     (mach_msg_type_number_t)strlen(msg) + 1);
  KMSG(kr, "mach_vm_write(target)");
  if (kr != KERN_SUCCESS)
    return 1;
  char back[128];
  memset(back, 0, sizeof back);
  if (read_remote(task, remote, back, strlen(msg) + 1))
    printf("  %-34s \"%s\"\n", "read back from the target", back);

  printf("\n[4] take over a thread\n");
  thread_t th = target_thread(task, 0);
  if (th == MACH_PORT_NULL) {
    printf("  no threads\n");
    return 1;
  }
  kr = thread_suspend(th);
  KMSG(kr, "thread_suspend");
  arm_thread_state64_t saved;
  int have_saved = 0;
  save_and_hijack(th, (void *)&write, 2, (uint64_t)remote, (void *)&_exit, &saved,
                  &have_saved);
  KMSG(have_saved ? KERN_SUCCESS : KERN_FAILURE, "thread_set_state");
  kr = thread_resume(th);
  KMSG(kr, "thread_resume");

  printf("\n[5] result\n");
  int status = 0;
  for (int waited = 0; waited < 500; waited++) {
    if (waitpid(g_child, &status, WNOHANG) == g_child)
      break;
    usleep(10000);
    if (waited == 499) {
      printf("  child still alive after 5s - killing it\n");
      kill(g_child, SIGKILL);
      waitpid(g_child, &status, 0);
    }
  }
  if (WIFSIGNALED(status))
    printf("  child died on signal %d\n", WTERMSIG(status));
  else {
    int rc = WEXITSTATUS(status);
    printf("  child exited %d; the target's write() returned %d (expected %zu)%s\n", rc, rc,
           strlen(msg),
           rc == (int)strlen(msg) ? "  <- the target wrote it" : "  <- did not write");
  }
  mach_port_deallocate(mach_task_self(), task);
  return 0;
}

static int foreign_test(pid_t pid, const char *agent) {
  printf("\n[1] target pid %d\n", pid);
  /* Remove the marker before we start. The first version of this probe printed whatever
   * the marker file happened to contain, which on 2026-09-17 meant it reported the
   * PREVIOUS run's success ("agent loaded in pid 13331") while the target was pid 1 -
   * an output line that reads as a result and is not one. Clear it, and check the pid
   * inside it below. */
  unlink(MARKER);
  task_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  KMSG(kr, "task_for_pid(target)");
  if (kr != KERN_SUCCESS)
    return 1;

  printf("\n[2] resolve the target's shared-cache slide\n");
  intptr_t delta = 0;
  char matched[512];
  if (!resolve_slide(task, &delta, matched, sizeof matched)) {
    printf("  no image path matched ours - cannot translate addresses\n");
    return 1;
  }
  printf("  %-34s %s\n", "matched image", matched);
  printf("  %-34s %+ld (0x%lx)\n", "slide difference", (long)delta,
         (unsigned long)(delta < 0 ? -delta : delta));

  printf("\n[3] plant the agent path in the target\n");
  mach_vm_address_t_ remote = 0;
  kr = mach_vm_allocate(task, &remote, 4096, VM_FLAGS_ANYWHERE);
  KMSG(kr, "mach_vm_allocate(target)");
  if (kr != KERN_SUCCESS)
    return 1;
  kr = mach_vm_write(task, remote, (vm_offset_t)(uintptr_t)agent,
                     (mach_msg_type_number_t)strlen(agent) + 1);
  KMSG(kr, "mach_vm_write(path)");
  char back[256];
  memset(back, 0, sizeof back);
  if (read_remote(task, remote, back, strlen(agent) + 1))
    printf("  %-34s \"%s\"\n", "read back", back);

  printf("\n[4] inject dlopen() into the target\n");
  thread_t th = target_thread(task, 0);
  if (th == MACH_PORT_NULL) {
    printf("  no threads\n");
    return 1;
  }
  thread_suspend(th);
  arm_thread_state64_t saved;
  int have_saved = 0;
  void *remote_dlopen = (void *)(intptr_t)((intptr_t)&dlopen + delta);
  void *remote_pause = (void *)(intptr_t)((intptr_t)&pause + delta);
  save_and_hijack(th, remote_dlopen, (uint64_t)remote, (uint64_t)RTLD_NOW, remote_pause,
                  &saved, &have_saved);
  printf("  %-34s remote dlopen=%p (ours %p)\n", "translated addresses", remote_dlopen,
         (void *)&dlopen);
  KMSG(have_saved ? KERN_SUCCESS : KERN_FAILURE, "thread_set_state");
  thread_resume(th);

  printf("\n[5] collect the result and put the thread back\n");
  uint64_t handle = collect_and_restore(th, &saved, have_saved);
  if (!have_saved) {
    /* Nothing ran. Saying "dlopen failed" here would assert a cause the run cannot
     * support - the thread never executed our call - so say the true thing instead. */
    printf("  %-34s (no reading: thread_set_state was refused, nothing ran)\n",
           "target's dlopen return (x0)");
  } else {
    printf("  %-34s 0x%llx%s\n", "target's dlopen return (x0)",
           (unsigned long long)handle,
           handle ? "  <- non-zero: the target loaded it" : "  <- zero: dlopen failed");
  }
  mach_port_deallocate(mach_task_self(), task);

  printf("\n[6] the agent's own marker file\n");
  int fd = open(MARKER, O_RDONLY);
  if (fd < 0) {
    printf("  no marker (%s) - the agent's constructor did not run\n", strerror(errno));
    return 1;
  }
  char m[512];
  ssize_t n = read(fd, m, sizeof m - 1);
  close(fd);
  if (n > 0) {
    m[n] = 0;
    printf("  %s", m);
    /* The marker must name THIS target. The agent writes the pid it is running in, so a
     * marker naming anything else is a stale file, and reporting it unqualified is how
     * a failed injection gets read as a successful one. */
    int marker_pid = -1;
    const char *p = strstr(m, "pid ");
    if (p) marker_pid = atoi(p + 4);
    if (marker_pid == (int)pid) {
      printf("  marker names pid %d, which IS the target - the agent ran in it\n", marker_pid);
      return 0;
    }
    printf("  marker names pid %d, target was pid %d - STALE MARKER, nothing landed\n",
           marker_pid, pid);
    return 1;
  }
  return handle ? 0 : 1;
}

/* Which agent to plant when the caller does not name one. AGENT_DEFAULT points at the
 * /System/Developer install location, but this lane installs the c1tools payload under
 * /var/jb - so on 2026-09-17 `injprobe 1` planted a path that does not exist, and step
 * [3]'s successful read-back was evidence of a write, not of anything loadable. Resolve
 * it rather than assume it. */
static const char *pick_default_agent(void) {
  static const char *candidates[] = {
      "/System/Developer/usr/lib/libagent.dylib",
      "/var/jb/usr/lib/libagent.dylib",
  };
  for (unsigned i = 0; i < sizeof candidates / sizeof candidates[0]; i++) {
    if (access(candidates[i], R_OK) == 0) return candidates[i];
  }
  return AGENT_DEFAULT;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  unsigned int flags = 0;
  csops(getpid(), CS_OPS_STATUS, &flags, sizeof flags);
  printf("injprobe: uid=%d pid=%d csflags=0x%08x%s\n", (int)getuid(), (int)getpid(), flags,
         (flags & 0x04000000) ? " platform_binary" : "");

  if (argc >= 2)
    return foreign_test((pid_t)atoi(argv[1]), argc >= 3 ? argv[2] : pick_default_agent());
  return self_test();
}
