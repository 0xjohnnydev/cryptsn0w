/* tfpid: how much of another task can a platform-binary root process reach?
 *
 * This answers, in one run, the question that gates any on-device debugger on a
 * non-jailbroken phone. Apple's own /usr/libexec/debugserver cannot be launched
 * by us (launch-restricted: sigkill even with no arguments), so if we want a
 * debugger we have to write one - and that needs a task port.
 *
 * For each target (self, a child we spawn, launchd, pid 0 = the kernel, and any
 * pid on the command line) it reports:
 *   task_for_pid          - the full task port, the debugger primitive
 *   task_name_for_pid     - the weaker port a plain root process normally gets
 *   a real memory read    - TASK_DYLD_INFO -> dyld image array -> the target's
 *                           Mach-O header, read straight out of its address
 *                           space. Reading the target's own header is proof of
 *                           read capability, not just of a port.
 *
 * Ships in the cryptex image and runs from the shell, because executables only
 * run from inside the cryptex mount:
 *   /System/Developer/usr/bin/tfpid                # self, child, launchd
 *   /System/Developer/usr/bin/tfpid <pid-of-SpringBoard>
 */
#include <errno.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/vm_map.h>  /* mach_vm.h is unsupported in the iOS SDK */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define CS_OPS_STATUS 0
#define CS_OPS_ENTITLEMENTS_BLOB 7

static const char *kr_name(kern_return_t kr) {
  switch (kr) {
  case KERN_SUCCESS:
    return "KERN_SUCCESS";
  case KERN_FAILURE:
    return "KERN_FAILURE";
  case KERN_INVALID_ARGUMENT:
    return "KERN_INVALID_ARGUMENT";
  case KERN_PROTECTION_FAILURE:
    return "KERN_PROTECTION_FAILURE";
  case KERN_NO_ACCESS:
    return "KERN_NO_ACCESS";
  case MACH_SEND_INVALID_DEST:
    return "MACH_SEND_INVALID_DEST";
  default:
    return "?";
  }
}

/* Read `len` bytes from `task` at `addr`. 1 on success. */
static int read_remote(mach_port_t task, vm_address_t addr, void *out,
                       vm_size_t len) {
  vm_size_t got = 0; /* vm_*: mach_vm_* is not in the iOS SDK */
  kern_return_t kr = vm_read_overwrite(task, addr, len,
                                      (vm_address_t)(uintptr_t)out, &got);
  return kr == KERN_SUCCESS && got == len;
}

/* Follow TASK_DYLD_INFO into the target and read its own Mach-O header. Proves
 * the port can actually read the target's memory. */
static void prove_read(mach_port_t task) {
  struct task_dyld_info info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  if (task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &count) !=
      KERN_SUCCESS) {
    printf("  task_info(TASK_DYLD_INFO) failed\n");
    return;
  }
  struct dyld_all_image_infos aii;
  if (!read_remote(task, info.all_image_info_addr, &aii, sizeof aii)) {
    printf("  read of dyld_all_image_infos @0x%llx failed\n",
           (unsigned long long)info.all_image_info_addr);
    return;
  }
  if (!aii.infoArray || aii.infoArrayCount == 0) {
    printf("  image array empty (count=%u)\n", aii.infoArrayCount);
    return;
  }
  struct dyld_image_info first;
  if (!read_remote(task, (vm_address_t)(uintptr_t)aii.infoArray, &first,
                   sizeof first)) {
    printf("  read of image array failed\n");
    return;
  }
  uint32_t magic = 0;
  if (!read_remote(task, (vm_address_t)(uintptr_t)first.imageLoadAddress,
                   &magic, sizeof magic)) {
    printf("  read of image header @%p failed\n", first.imageLoadAddress);
    return;
  }
  const char *what = magic == MH_MAGIC_64 ? "MH_MAGIC_64" : "?";
  printf("  READ OK: %u images, first @%p magic=0x%08x (%s)", aii.infoArrayCount,
         first.imageLoadAddress, magic, what);
  if (first.imageFilePath) {
    char path[256];
    if (read_remote(task, (vm_address_t)(uintptr_t)first.imageFilePath,
                    path, sizeof path - 1)) {
      path[sizeof path - 1] = 0;
      printf(" %s", path);
    }
  }
  printf("\n");
}

static void probe(pid_t pid, const char *label) {
  mach_port_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  printf("%-12s pid=%-6d task_for_pid=%-18s", label, pid, kr_name(kr));
  if (kr != KERN_SUCCESS) {
    mach_port_t name = MACH_PORT_NULL;
    kern_return_t kr2 = task_name_for_pid(mach_task_self(), pid, &name);
    printf(" task_name_for_pid=%s (%s)\n", kr_name(kr2),
           kr2 == KERN_SUCCESS ? "name port only, no memory access"
                               : "weaker port also denied");
    if (kr2 == KERN_SUCCESS)
      mach_port_deallocate(mach_task_self(), name);
    return;
  }
  printf("  <-- TASK PORT\n");
  if (pid == 0) { /* the kernel task has no dyld image array */
    struct task_basic_info bi;
    mach_msg_type_number_t bcount = TASK_BASIC_INFO_COUNT;
    kern_return_t bkr =
        task_info(task, TASK_BASIC_INFO, (task_info_t)&bi, &bcount);
    printf("  kernel task port usable=%s", bkr == KERN_SUCCESS ? "yes" : "no");
    if (bkr == KERN_SUCCESS)
      printf(" (virtual=%lu MB resident=%lu MB)",
             (unsigned long)(bi.virtual_size >> 20),
             (unsigned long)(bi.resident_size >> 20));
    printf("\n");
  } else {
    prove_read(task);
  }
  mach_port_deallocate(mach_task_self(), task);
}

int main(int argc, char **argv) {
  unsigned int flags = 0;
  int have_flags = csops(getpid(), CS_OPS_STATUS, &flags, sizeof flags) == 0;
  printf("tfpid: uid=%d euid=%d pid=%d csflags=0x%08x%s\n", (int)getuid(),
         (int)geteuid(), (int)getpid(), flags,
         have_flags && (flags & 0x04000000) ? " (platform_binary)" : "");

  /* Did the kernel KEEP the entitlements this binary declares? They are in the
   * ad-hoc signature; whether AMFI honours them for trust-cached code is the
   * open question, and this is the cheap half of the answer. A failing csops
   * (or a blob without our keys) means they were dropped, and then task_for_pid
   * below cannot succeed no matter what the signature says. */
  char ents[8192];
  memset(ents, 0, sizeof ents);
  int ent_rc = csops(getpid(), CS_OPS_ENTITLEMENTS_BLOB, ents, sizeof ents);
  if (ent_rc != 0) {
    printf("entitlements: csops(CS_OPS_ENTITLEMENTS_BLOB) -> %s (%d) "
           "=> NOT retained\n", strerror(errno), errno);
  } else {
    const char *keys[] = {"task_for_pid-allow", "get-task-allow",
                          "cs.debugger", "thread-set-state"};
    printf("entitlements: blob retained, keys:");
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
      printf(" %s=%s", keys[i], strstr(ents, keys[i]) ? "yes" : "no");
    printf("\n");
  }

  /* Our own child: the case a plain debugger would use most. */
  pid_t child = fork();
  if (child == 0) {
    pause();
    _exit(0);
  }

  probe(getpid(), "self");
  if (child > 0)
    probe(child, "our child");
  probe(1, "launchd");
  probe(0, "kernel"); /* pid 0 is the kernel task: tfp0, the whole primitive the
                       * xnusp toolkit is built on (ctx.port + kread/kwrite) */
  for (int i = 1; i < argc; i++) {
    pid_t pid = (pid_t)atoi(argv[i]);
    if (pid > 0)
      probe(pid, "argv");
  }

  if (child > 0) {
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
  }
  return 0;
}
