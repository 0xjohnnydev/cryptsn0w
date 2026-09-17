/* agent: the dylib injected into another process.
 *
 * Its whole job is to be undeniable evidence. A constructor that runs on dlopen
 * writes a marker file naming the process it is running *in*, so the proof does
 * not depend on the target's stdout reaching our session (it does not - a
 * foreign process's stderr goes wherever that process sends it):
 *
 *   cat /var/tmp/sb-injected.txt   ->  "agent loaded in pid N ..."
 *
 * and N must be the TARGET's pid, which is neither our pid nor any process we
 * spawned for this purpose.
 *
 * It is deliberately trivial. The interesting question is whether a foreign
 * process can be made to load our code at all; once it can, an agent is ordinary
 * reverse-engineering tooling (fishhook, method_setImplementation, a debugger's
 * memory access) and grows as needed.
 */
#define _DARWIN_C_SOURCE 1

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#define MARKER "/var/tmp/sb-injected.txt"

__attribute__((constructor)) static void agent_ctor(void) {
  unsigned int flags = 0;
  csops(getpid(), 0 /* CS_OPS_STATUS */, &flags, sizeof flags);

  char buf[512];
  int n = snprintf(buf, sizeof buf,
                   "agent loaded in pid %d (uid %d, csflags 0x%08x)%s\n",
                   (int)getpid(), (int)getuid(), flags,
                   (flags & 0x04000000) ? " platform_binary" : "");

  int fd = open(MARKER, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    ssize_t w = write(fd, buf, (size_t)n);
    (void)w;
    close(fd);
  }
  /* Also to stderr, in case the target happens to share our session. */
  ssize_t w2 = write(2, buf, (size_t)n);
  (void)w2;
}

/* An exported entry the injector can call next, after proving dlopen worked. */
int agent_main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  return 42;
}
