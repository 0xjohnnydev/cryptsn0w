/* cs-loader: run an untrusted Mach-O by making it the code of a child we own.
 *
 * The premise, established by measurement rather than by argument: the one thing that
 * has ever admitted new code on this device is (a) a CDHash in a loaded trust cache,
 * (b) an app launched through installd with a provisioning profile, or (c) the
 * debug-authorisation exemption that route A produces. On 2026-09-17 (a) and (b) were
 * both measured closed for a loose file - a dylib signed with the host app's own
 * certificate is refused at F_ADDFILESIGS_RETURN with EPERM, before library validation
 * is even consulted, and the lane refuses it with errno=1 the same as an ad-hoc one.
 * So (c) is the remaining route, and this program is it:
 *
 *   parent: fork a child; the child inherits this binary's get-task-allow
 *   parent: ptrace(PT_ATTACHEXC) -> cs_allow_invalid -> CS_DEBUGGED, then PT_DETACH
 *           (a child, so waitpid consumes the stop and PT_DETACH actually succeeds -
 *           which is exactly why this shape works on a foreign target it would not)
 *   parent: task_for_pid, then lay the payload out with mach_vm_allocate/write:
 *           every executable byte is an ANONYMOUS page the parent wrote, so nothing is
 *           signed, nothing is hashed, and no trust cache is involved
 *   parent: apply the chained fixups itself, from outside the child
 *   child:  runs the initialisers and calls the payload's main
 *
 * The child computes nothing. That is deliberate: everything it does is read out of the
 * shared page the parent filled in, so a failure is always the parent's to report, and
 * the child cannot fail before it has said why.
 *
 * Scope, stated honestly. This is a loader for OUR OWN payloads and it says so by
 * failing loudly rather than by loading something subtly wrong:
 *   - both fixup encodings are implemented: LC_DYLD_CHAINED_FIXUPS and legacy
 *     LC_DYLD_INFO rebase/bind/weak/lazy. An opcode or bind type that is NOT
 *     implemented is a loud failure, never a skip - a skipped fixup is a wrong
 *     pointer that looks like a payload bug.
 *   - dependencies are resolved from the payload's own LC_LOAD_DYLIB entries and
 *     mapped before the fork; @rpath/@loader_path are honoured, and DYLD_LIBRARY_PATH
 *     and PATH are searched as well so the loader resolves the way the shell would.
 *     A missing dependency is reported and the unresolved-symbol report decides.
 *   - no TLS, no unwinding, no Swift runtime. Nyxian's own loader has the same gap and
 *     still lists thread-local storage as unfixed.
 *
 * Usage:
 *   cs-loader [-v] <macho> [args...]   load and run, propagating the payload's exit status
 *   cs-loader [-v] --sigtest <path>    the F_ADDFILESIGS/F_CHECK_LV probe, for the lane
 *
 * -v comes BEFORE the payload path so that everything after the path is the payload's,
 * including arguments that look like our own flags. Silent on success without it; see the
 * comment on logf_/errf_ for why failures still speak.
 */
#define _DARWIN_C_SOURCE 1

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach-o/fixup-chains.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

extern int ptrace(int request, pid_t pid, void *addr, int data);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                     boolean_t, vm_prot_t);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t,
                                   mach_msg_type_number_t);
extern kern_return_t mach_vm_read(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                  vm_offset_t *, mach_msg_type_number_t *);
extern char **environ;

#define CS_OPS_STATUS 0
#define CS_GET_TASK_ALLOW 0x00000004
#define CS_HARD 0x00000100
#define CS_KILL 0x00000200
#define CS_DEBUGGED 0x10000000
#define CS_PLATFORM_BINARY 0x04000000

#define PT_ATTACHEXC 14
#define PT_DETACH 11

/* Everything the child needs. Filled by the parent, read by the child, one cache line
 * apart from nothing. */
typedef struct {
  volatile int ready;        /* child -> parent: I am forked and spinning */
  volatile int go;           /* parent -> child: image is laid out and fixed up */
  volatile int status;       /* parent -> child: 0 = run it, non-zero = refuse */
  volatile uint64_t entry;   /* the payload's main */
  volatile uint64_t inits;   /* array of initialiser function pointers, in the child */
  volatile uint32_t init_count;
  volatile uint32_t argc;
  volatile uint64_t argv;    /* char **, in the child */
} sync_t;

/* Two levels, because they serve different readers.
 *
 * `logf_` is the trace: what was laid out, what bound, what was skipped. It is silent
 * unless -v is given, which is what makes cs-loader usable as a drop-in runner whose own
 * noise does not get mixed into the payload's output.
 *
 * `errf_` is the answer to "why did nothing run". It always prints, and it always goes to
 * stderr, never stdout - so a payload's stdout stays its own either way. A runner that
 * fails silently is the exact failure mode this campaign has been bitten by repeatedly:
 * an empty result that is consistent with success and with nothing having happened. If
 * you want cs-loader entirely silent, redirect stderr; do not make silence the default.
 *
 * -v must come BEFORE the payload path, so `cs-loader ./x -v` hands `-v` to the payload.
 */
static int g_verbose;

static void logv(const char *fmt, va_list ap) {
  char line[512];
  int n = vsnprintf(line, sizeof line, fmt, ap);
  if (n > 0) {
    ssize_t w = write(2, line, (size_t)n);
    (void)w;
  }
}

static void logf_(const char *fmt, ...) {
  if (!g_verbose) return;
  va_list ap;
  va_start(ap, fmt);
  logv(fmt, ap);
  va_end(ap);
}

static void errf_(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  logv(fmt, ap);
  va_end(ap);
}

static sync_t *sync_new(void) {
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  return (p == MAP_FAILED) ? NULL : (sync_t *)p;
}

/* ------------------------------------------------------------------ image side --- */

typedef struct {
  const uint8_t *file;
  size_t size;
  const struct mach_header_64 *mh;
  const struct segment_command_64 *text;   /* __TEXT, for the LC_MAIN base */
  intptr_t slide_pending;                  /* filled by the parent after allocation */
  /* dlopen handles for the declared dependencies, in LC_LOAD_DYLIB order, so a legacy
   * bind's dylib ordinal can be resolved against the library it actually named rather
   * than against whatever happens to be first in the global scope. Ordinal 1 is
   * dep_handles[0]; the special ordinals (self, flat, weak) fall back to RTLD_DEFAULT. */
  void *dep_handles[64];
  uint32_t dep_count;
} image_t;

static const struct load_command *lc_first(const image_t *im) {
  return (const struct load_command *)((const uint8_t *)im->mh + sizeof(struct mach_header_64));
}

static const struct load_command *lc_find(const image_t *im, uint32_t cmd) {
  const struct load_command *lc = lc_first(im);
  for (uint32_t i = 0; i < im->mh->ncmds; i++) {
    if (lc->cmd == cmd) return lc;
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }
  return NULL;
}

static int image_open(const char *path, image_t *im) {
  memset(im, 0, sizeof *im);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { errf_("cs-loader: open(%s): %s\n", path, strerror(errno)); return -1; }
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < 4096) {
    errf_("cs-loader: %s is too small to be a Mach-O\n", path);
    close(fd);
    return -1;
  }
  im->size = (size_t)st.st_size;
  void *m = mmap(NULL, im->size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (m == MAP_FAILED) { errf_("cs-loader: mmap: %s\n", strerror(errno)); return -1; }
  im->file = m;
  im->mh = (const struct mach_header_64 *)m;

  if (im->mh->magic != MH_MAGIC_64) {
    errf_("cs-loader: not a 64-bit little-endian Mach-O (magic 0x%x)\n", im->mh->magic);
    return -1;
  }
  if (im->mh->filetype != MH_EXECUTE && im->mh->filetype != MH_DYLIB) {
    errf_("cs-loader: filetype %u is neither MH_EXECUTE nor MH_DYLIB\n", im->mh->filetype);
    return -1;
  }
  if (im->mh->cputype != CPU_TYPE_ARM64) {
    errf_("cs-loader: not arm64\n");
    return -1;
  }
  /* Both encodings are implemented now, so the requirement is that the image declares
   * ONE of them. An image with neither was not linked the way we expect, and saying so
   * is more useful than loading it and jumping into unrelocated code. */
  if (lc_find(im, LC_DYLD_CHAINED_FIXUPS) == NULL &&
      lc_find(im, LC_DYLD_INFO) == NULL &&
      lc_find(im, LC_DYLD_INFO_ONLY) == NULL) {
    errf_("cs-loader: neither LC_DYLD_CHAINED_FIXUPS nor legacy LC_DYLD_INFO is present,\n"
          "           so there is nothing to apply. For a linked image that means it was\n"
          "           not linked the way we expect.\n");
    return -1;
  }

  const struct load_command *lc = lc_first(im);
  for (uint32_t i = 0; i < im->mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
      if (strncmp(sc->segname, SEG_TEXT, 16) == 0) im->text = sc;
    }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }
  if (im->text == NULL) { errf_("cs-loader: no __TEXT segment\n"); return -1; }
  return 0;
}

/* The payload's own address space accounting. __PAGEZERO is skipped on purpose: it is a
 * four-gigabyte hole with no file backing, and treating it as part of the image would
 * make the reservation absurd rather than merely wrong. */
static int image_bounds(const image_t *im, uint64_t *lo, uint64_t *hi) {
  uint64_t start = UINT64_MAX, end = 0;
  const struct load_command *lc = lc_first(im);
  for (uint32_t i = 0; i < im->mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
      if (sc->vmsize != 0 && sc->filesize != 0) {
        if (sc->vmaddr < start) start = sc->vmaddr;
        if (sc->vmaddr + sc->vmsize > end) end = sc->vmaddr + sc->vmsize;
      }
    }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }
  if (end == 0) return -1;
  *lo = start;
  *hi = end;
  return 0;
}

/* ----------------------------------------------------------------- fixups ------- */

/* ----------------------------------------------------------------- dependencies --- */

/* The payload names the libraries it needs in LC_LOAD_DYLIB, and until it runs nothing
 * has mapped them - dlsym(RTLD_DEFAULT) only sees what is already in this process. So we
 * map them ourselves, BEFORE the fork, because fork preserves addresses: a dependency
 * loaded here is at the same address in the child, which is what makes the parent's
 * resolution valid there.
 *
 * Best-effort on purpose. A missing dependency is reported and the load continues, so
 * that the authority on whether it mattered stays the unresolved-symbol report at the
 * end rather than a guess made here. A *weak* dylib is allowed to be missing by
 * definition.
 *
 * RTLD_GLOBAL is required, not stylistic: RTLD_DEFAULT searches the global namespace, and
 * a dlopen'd image is local to this process unless it was loaded with RTLD_GLOBAL.
 */
static const char *const kRpathFallbacks[] = {
    "/var/jb/usr/lib",
    "/usr/lib",
    "/usr/local/lib",
};

/* Where else to look, taken from the environment, so the loader resolves a dependency
 * the way the shell the user is standing in would. DYLD_LIBRARY_PATH is the variable
 * that means "extra dylib search directories" on Darwin; PATH is honoured as well
 * because that is where a lane user's mental model of "the paths" lives, and looking in
 * a few extra directories cannot make a correct resolution wrong.
 *
 * Order: the payload's own rpaths, then these, then the fixed fallbacks above. Reported
 * on failure so the search is visible rather than magic. */
#define MAX_SEARCH_DIRS 64
static const char *g_search_dirs[MAX_SEARCH_DIRS];
static uint32_t g_search_dir_count;

static void collect_search_dirs(void) {
  const char *vars[] = {"DYLD_LIBRARY_PATH", "PATH"};
  g_search_dir_count = 0;
  for (unsigned v = 0; v < sizeof vars / sizeof vars[0]; v++) {
    const char *val = getenv(vars[v]);
    if (val == NULL) continue;
    const char *p = val;
    while (*p && g_search_dir_count < MAX_SEARCH_DIRS) {
      const char *colon = strchr(p, ':');
      size_t n = colon ? (size_t)(colon - p) : strlen(p);
      if (n > 0 && n < 512) {
        char *dir = malloc(n + 1);
        if (dir) {
          memcpy(dir, p, n);
          dir[n] = 0;
          /* drop duplicates so the log stays readable */
          int seen = 0;
          for (uint32_t i = 0; i < g_search_dir_count; i++)
            if (strcmp(g_search_dirs[i], dir) == 0) seen = 1;
          if (seen) free(dir);
          else g_search_dirs[g_search_dir_count++] = dir;
        }
      }
      if (!colon) break;
      p = colon + 1;
    }
  }
  if (g_search_dir_count)
    logf_("  search path: %u dirs from DYLD_LIBRARY_PATH/PATH\n", g_search_dir_count);
  else
    logf_("  search path: neither DYLD_LIBRARY_PATH nor PATH is set\n");
}

static int path_is(const char *p, const char *prefix) {
  return strncmp(p, prefix, strlen(prefix)) == 0;
}

static void *try_dlopen(const image_t *im, const char *name, const char *payload_dir,
                        char *why, size_t why_len) {
  char path[1024];

  if (path_is(name, "@rpath/")) {
    const char *rest = name + strlen("@rpath/");
    /* rpaths the payload declares, then our fallbacks. */
    const struct load_command *lc = lc_first(im);
    for (uint32_t i = 0; i < im->mh->ncmds; i++) {
      if (lc->cmd == LC_RPATH) {
        const struct rpath_command *rc = (const struct rpath_command *)lc;
        const char *rp = (const char *)lc + rc->path.offset;
        snprintf(path, sizeof path, "%s/%s", rp, rest);
        void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
        if (h) return h;
      }
      lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    for (unsigned i = 0; i < g_search_dir_count; i++) {
      snprintf(path, sizeof path, "%s/%s", g_search_dirs[i], rest);
      void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
      if (h) return h;
    }
    for (unsigned i = 0; i < sizeof kRpathFallbacks / sizeof kRpathFallbacks[0]; i++) {
      snprintf(path, sizeof path, "%s/%s", kRpathFallbacks[i], rest);
      void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
      if (h) return h;
    }
    snprintf(why, why_len, "no @rpath candidate loaded");
    return NULL;
  }

  if (path_is(name, "@loader_path/") || path_is(name, "@executable_path/")) {
    const char *rest = strchr(name + 1, '/') + 1;
    snprintf(path, sizeof path, "%s/%s", payload_dir, rest);
    void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (h) return h;
    snprintf(why, why_len, "%s", dlerror() ? dlerror() : "dlopen failed");
    return NULL;
  }

  void *h = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
  if (h) return h;

  /* Not at its recorded path. Before giving up, try the basename in the search
   * directories - this is the case the PATH support exists for: a payload built against
   * a layout whose libraries live somewhere else on this device. */
  const char *base = strrchr(name, '/');
  base = base ? base + 1 : name;
  for (unsigned i = 0; i < g_search_dir_count; i++) {
    snprintf(path, sizeof path, "%s/%s", g_search_dirs[i], base);
    h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (h) return h;
  }

  const char *e = dlerror();
  snprintf(why, why_len, "%s", e ? e : "dlopen failed");
  return NULL;
}

static void load_dependencies(image_t *im, const char *payload_path) {
  char payload_dir[1024];
  snprintf(payload_dir, sizeof payload_dir, "%s", payload_path);
  char *slash = strrchr(payload_dir, '/');
  if (slash) *slash = 0; else snprintf(payload_dir, sizeof payload_dir, ".");

  uint32_t declared = 0, mapped = 0, missing = 0;
  const struct load_command *lc = lc_first(im);
  for (uint32_t i = 0; i < im->mh->ncmds; i++) {
    uint32_t cmd = lc->cmd;
    if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB ||
        cmd == LC_REEXPORT_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB) {
      const struct dylib_command *dc = (const struct dylib_command *)lc;
      if (dc->dylib.name.offset < lc->cmdsize) {
        const char *name = (const char *)lc + dc->dylib.name.offset;
        declared++;
        char why[256] = {0};
        void *h = try_dlopen(im, name, payload_dir, why, sizeof why);
        if (h != NULL) {
          mapped++;
        } else {
          missing++;
          errf_("  dependency %-40s NOT MAPPED (%s)%s\n", name, why,
                cmd == LC_LOAD_WEAK_DYLIB ? " [weak]" : "");
        }
        /* Record the handle even when it failed, so a legacy bind's ordinal still lines
         * up with the library it named rather than shifting by one. */
        if (im->dep_count < sizeof im->dep_handles / sizeof im->dep_handles[0])
          im->dep_handles[im->dep_count++] = h;
      }
    }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }
  logf_("  dependencies: %u declared, %u mapped, %u not mapped\n", declared, mapped, missing);
}

static const void *resolve_symbol(const char *name) {
  if (name == NULL || name[0] == 0) return NULL;
  const char *lookup = (name[0] == '_') ? name + 1 : name;
  void *p = dlsym(RTLD_DEFAULT, lookup);
  if (p == NULL) p = dlsym(RTLD_DEFAULT, name);
  return p;
}

/* Walk the payload's chained fixups in the FILE, compute what each slot must hold, and
 * write it straight into the child. Doing it from outside is the one advantage this
 * loader has over Nyxian's: the child's pages never have to be writable, so there is no
 * window in which the payload's own data is exposed to it, and no reseal step.
 *
 * Two encoding details that are easy to get wrong and that this function is written
 * around:
 *   - `segment_offset` is the segment's UNSLID vmaddr minus the image base, so a slot's
 *     file offset comes from matching the owning segment exactly, not by containment.
 *   - `high8` holds bits 56..63 of the target, so it scales by 2^56 and not by 2^32.
 *     For DYLD_CHAINED_PTR_64 the stored target is an UNSLID address and the slide is
 *     ours to add; for _64_OFFSET it is already an offset from the image base.
 */
static int apply_chained_fixups(image_t *im, task_t task, mach_vm_address_t image_base) {
  const struct load_command *lc = lc_find(im, LC_DYLD_CHAINED_FIXUPS);
  const struct linkedit_data_command *ldc = (const struct linkedit_data_command *)lc;
  if ((uint64_t)ldc->dataoff + ldc->datasize > im->size) {
    errf_("cs-loader: chained fixups extend past the file\n");
    return -1;
  }
  const uint8_t *fixups = im->file + ldc->dataoff;
  const struct dyld_chained_fixups_header *h = (const struct dyld_chained_fixups_header *)fixups;

  if (h->symbols_format != 0) {
    errf_("cs-loader: symbols_format %u is zlib-compressed, which this loader does not do\n",
          h->symbols_format);
    return -1;
  }
  const char *sym_pool = (const char *)fixups + h->symbols_offset;
  const uint8_t *imports_base = fixups + h->imports_offset;
  const struct dyld_chained_starts_in_image *si =
      (const struct dyld_chained_starts_in_image *)(fixups + h->starts_offset);

  const uint64_t image_base_vmaddr = im->text->vmaddr;   /* lo, by construction */
  uint32_t rebases = 0, binds = 0, unresolved = 0;

  for (uint32_t seg = 0; seg < si->seg_count; seg++) {
    if (si->seg_info_offset[seg] == 0) continue;   /* this segment carries no fixups */
    const struct dyld_chained_starts_in_segment *ss =
        (const struct dyld_chained_starts_in_segment *)((const uint8_t *)si + si->seg_info_offset[seg]);

    if (ss->pointer_format != DYLD_CHAINED_PTR_64 &&
        ss->pointer_format != DYLD_CHAINED_PTR_64_OFFSET) {
      errf_("cs-loader: segment %u uses pointer_format %u; this loader handles\n"
            "           DYLD_CHAINED_PTR_64 and _64_OFFSET only\n", seg, ss->pointer_format);
      return -1;
    }

    /* The segment that owns this chain, matched exactly rather than by containment. */
    const struct segment_command_64 *owner = NULL;
    const struct load_command *l2 = lc_first(im);
    for (uint32_t i = 0; i < im->mh->ncmds; i++) {
      if (l2->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc = (const struct segment_command_64 *)l2;
        if (sc->vmaddr - image_base_vmaddr == ss->segment_offset) owner = sc;
      }
      l2 = (const struct load_command *)((const uint8_t *)l2 + l2->cmdsize);
    }
    if (owner == NULL) {
      errf_("cs-loader: no segment matches chain segment_offset 0x%llx\n",
            (unsigned long long)ss->segment_offset);
      return -1;
    }

    const uint64_t seg_addr = image_base + ss->segment_offset;   /* in the child */
    const uint64_t seg_file = owner->fileoff;                    /* in the file */

    for (uint32_t page = 0; page < ss->page_count; page++) {
      uint16_t start = ss->page_start[page];
      if (start == DYLD_CHAINED_PTR_START_NONE) continue;
      if (start & DYLD_CHAINED_PTR_START_MULTI) {
        errf_("cs-loader: multi-start page chains are not implemented (segment %u page %u)\n",
              seg, page);
        return -1;
      }

      uint64_t chain_off = (uint64_t)page * ss->page_size + start;
      while (1) {
        if (seg_file + chain_off + 8 > im->size) {
          errf_("cs-loader: a chain slot runs past the end of the file\n");
          return -1;
        }
        uint64_t raw;
        memcpy(&raw, im->file + seg_file + chain_off, 8);

        const struct dyld_chained_ptr_64_rebase *rb =
            (const struct dyld_chained_ptr_64_rebase *)&raw;
        const struct dyld_chained_ptr_64_bind *bd =
            (const struct dyld_chained_ptr_64_bind *)&raw;
        const uint64_t next = rb->next;
        uint64_t newval = 0;

        if (bd->bind) {
          if (bd->ordinal >= h->imports_count) {
            errf_("cs-loader: bind ordinal %u out of range (%u imports)\n",
                  bd->ordinal, h->imports_count);
            return -1;
          }
          const struct dyld_chained_import *imp =
              (const struct dyld_chained_import *)(imports_base +
                  (size_t)bd->ordinal * sizeof(struct dyld_chained_import));
          const char *name = sym_pool + imp->name_offset;
          uint64_t addend = bd->addend;
          if (h->imports_format == DYLD_CHAINED_IMPORT_ADDEND ||
              h->imports_format == DYLD_CHAINED_IMPORT_ADDEND64) {
            const uint32_t *extra = (const uint32_t *)imp + 1;
            addend = *extra;
          }
          const void *addr = resolve_symbol(name);
          if (addr == NULL) {
            errf_("cs-loader: UNRESOLVED external '%s' (import %u)\n", name, bd->ordinal);
            unresolved++;
          } else {
            newval = (uint64_t)(uintptr_t)addr + addend;
          }
          binds++;
        } else {
          const uint64_t high = ((uint64_t)rb->high8) << 56;
          if (ss->pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
            newval = image_base + rb->target + high;
          } else {
            newval = (uint64_t)im->slide_pending + rb->target + high;
          }
          rebases++;
        }

        kern_return_t kr = mach_vm_write(task, seg_addr + chain_off, (vm_offset_t)&newval, 8);
        if (kr != KERN_SUCCESS) {
          errf_("cs-loader: writing a fixup failed: %s\n", mach_error_string(kr));
          return -1;
        }
        if (next == 0) break;
        chain_off += next * 4;
      }
    }
  }
  logf_("  fixups: %u rebases, %u binds, %u unresolved\n", rebases, binds, unresolved);
  return unresolved ? -1 : 0;
}

/* ------------------------------------------------------- legacy LC_DYLD_INFO fixups --- */

/* The older encoding, still emitted by some linkers. Same idea as the chained form -
 * compute each slot's value and write it into the child - but the work is spread over
 * two opcode streams instead of a linked list per page.
 *
 * Opcode semantics follow dyld's compressed image loader. The rule this file keeps
 * everywhere applies here most of all: an opcode or a bind type this loader does not
 * implement is a LOUD FAILURE, never a skip. A silently-skipped fixup produces a pointer
 * that is wrong in a way that looks like a payload bug, and the whole reason to write a
 * loader rather than patch bytes is to not have that failure mode.
 */
#define BIND_TYPE_POINTER 1

static uint64_t read_uleb(const uint8_t **p, const uint8_t *end) {
  uint64_t r = 0;
  int shift = 0;
  while (*p < end) {
    uint8_t b = *(*p)++;
    r |= (uint64_t)(b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7;
    if (shift > 63) break;
  }
  return r;
}

static int64_t read_sleb(const uint8_t **p, const uint8_t *end) {
  int64_t r = 0;
  int shift = 0;
  uint8_t b = 0;
  while (*p < end) {
    b = *(*p)++;
    r |= (int64_t)(b & 0x7f) << shift;
    shift += 7;
    if (!(b & 0x80)) break;
    if (shift > 63) break;
  }
  if (shift < 64 && (b & 0x40)) r |= -((int64_t)1 << shift);
  return r;
}

static const struct segment_command_64 *seg_at(const image_t *im, uint32_t idx) {
  const struct load_command *lc = lc_first(im);
  uint32_t n = 0;
  for (uint32_t i = 0; i < im->mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      if (n == idx) return (const struct segment_command_64 *)lc;
      n++;
    }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }
  return NULL;
}

static int write_slot(task_t task, uint64_t addr, uint64_t val) {
  kern_return_t kr = mach_vm_write(task, addr, (vm_offset_t)&val, 8);
  if (kr != KERN_SUCCESS) {
    errf_("cs-loader: writing a fixup at 0x%llx failed: %s\n",
          (unsigned long long)addr, mach_error_string(kr));
    return -1;
  }
  return 0;
}

/* dyld provides `dyld_stub_binder` itself and exports it to nobody, so no dlsym can
 * reach it - verified on both platforms. It exists to be the initial value of a lazy
 * symbol pointer, and a real dyld installs it so the first call resolves the symbol.
 *
 * This loader binds every lazy pointer EAGERLY, so the binder should never run: each
 * __la_symbol_ptr gets its real target from the same stream. Binding it to zero would
 * turn "should never be called" into "jumps to 0 if it is", so it gets a sentinel that
 * says what happened instead. If this ever prints, eager binding missed a lazy symbol
 * and that is worth knowing rather than debugging as a random crash. */
static void cs_should_never_run(void) {
  static const char msg[] =
      "\ncs-loader: dyld_stub_binder was called, which means a lazy symbol was not\n"
      "           bound eagerly. Exiting rather than jumping to an unresolved pointer.\n";
  ssize_t w = write(2, msg, sizeof msg - 1);
  (void)w;
  _exit(99);
}

static const void *resolve_for_ordinal(const image_t *im, int ordinal, const char *name) {
  if (strcmp(name, "dyld_stub_binder") == 0)
    return (const void *)(uintptr_t)&cs_should_never_run;
  /* The two-level namespace: bind against the library the payload actually named when
   * we have it, and fall back to the flat lookup otherwise. Getting this wrong binds a
   * symbol to a same-named one from a different library. */
  if (ordinal > 0 && (uint32_t)ordinal <= im->dep_count) {
    void *h = im->dep_handles[ordinal - 1];
    if (h != NULL) {
      const char *lookup = (name[0] == '_') ? name + 1 : name;
      void *p = dlsym(h, lookup);
      if (p == NULL) p = dlsym(h, name);
      if (p != NULL) return p;
    }
  }
  return resolve_symbol(name);
}

static int apply_rebases(image_t *im, task_t task, mach_vm_address_t image_base,
                         uint32_t off, uint32_t size, uint32_t *out_count) {
  const uint8_t *p = im->file + off;
  const uint8_t *end = p + size;
  uint32_t idx = 0;
  uint64_t seg_off = 0;
  uint32_t type = 0, n = 0;

  while (p < end) {
    uint8_t b = *p++;
    switch (b & 0xF0) {
      case 0x00: /* DONE: for a non-lazy stream this is the end */
        *out_count += n;
        return 0;
      case 0x10: /* SET_TYPE_IMM */
        type = b & 0x0F;
        break;
      case 0x20: /* SET_SEGMENT_AND_OFFSET_ULEB */
        idx = b & 0x0F;
        seg_off = read_uleb(&p, end);
        break;
      case 0x30: /* ADD_ADDR_ULEB */
        seg_off += read_uleb(&p, end);
        break;
      case 0x40: /* ADD_ADDR_IMM_SCALED */
        seg_off += (uint64_t)(b & 0x0F) * 8;
        break;
      case 0x50:   /* DO_REBASE_IMM_TIMES */
      case 0x60:   /* DO_REBASE_ULEB_TIMES */
      case 0x70:   /* DO_REBASE_ADD_ADDR_ULEB */
      case 0x80: { /* DO_REBASE_ULEB_TIMES_SKIPPING_ULEB */
        uint64_t times = 1, skip = 0;
        if ((b & 0xF0) == 0x50) times = b & 0x0F;
        else if ((b & 0xF0) == 0x60) times = read_uleb(&p, end);
        else if ((b & 0xF0) == 0x70) { times = 1; skip = read_uleb(&p, end); }
        else { times = read_uleb(&p, end); skip = read_uleb(&p, end); }
        if (type != 0 && type != 1) {
          errf_("cs-loader: legacy rebase type %u is not implemented (only POINTER)\n", type);
          return -1;
        }
        const struct segment_command_64 *sc = seg_at(im, idx);
        if (sc == NULL) { errf_("cs-loader: legacy rebase names segment %u\n", idx); return -1; }
        for (uint64_t i = 0; i < times; i++) {
          uint64_t slot_file = sc->fileoff + seg_off;
          uint64_t slot_addr = image_base + (sc->vmaddr - im->text->vmaddr) + seg_off;
          if (slot_file + 8 > im->size) { errf_("cs-loader: rebase past end of file\n"); return -1; }
          uint64_t raw;
          memcpy(&raw, im->file + slot_file, 8);
          if (write_slot(task, slot_addr, raw + (uint64_t)im->slide_pending) != 0) return -1;
          n++;
          seg_off += skip + 8;
        }
        break;
      }
      default:
        errf_("cs-loader: unknown legacy rebase opcode 0x%02x - refusing rather than\n"
              "           skipping it, because a skipped rebase is a wrong pointer\n", b);
        return -1;
    }
  }
  *out_count += n;
  return 0;
}

static int apply_binds(image_t *im, task_t task, mach_vm_address_t image_base,
                       uint32_t off, uint32_t size, int weak, uint32_t *out_count) {
  const uint8_t *p = im->file + off;
  const uint8_t *end = p + size;
  uint32_t idx = 0;
  uint64_t seg_off = 0;
  int ordinal = 0;
  uint32_t type = 1;
  int64_t addend = 0;
  const char *sym = NULL;
  uint32_t n = 0, unresolved = 0;

  while (p < end) {
    uint8_t b = *p++;
    switch (b & 0xF0) {
      case 0x00: /* DONE: end of this entry (lazy) or of the stream */
        continue;
      case 0x10: /* SET_DYLIB_ORDINAL_IMM */
        ordinal = b & 0x0F;
        break;
      case 0x20: /* SET_DYLIB_ORDINAL_ULEB */
        ordinal = (int)read_uleb(&p, end);
        break;
      case 0x30: /* SET_DYLIB_SPECIAL_IMM */
        ordinal = (b & 0x0F) ? (int8_t)(0xF0 | (b & 0x0F)) : 0;
        break;
      case 0x40: /* SET_SYMBOL_TRAILING_FLAGS_IMM */
        sym = (const char *)p;
        {
          const uint8_t *z = (const uint8_t *)memchr(p, 0, (size_t)(end - p));
          if (z == NULL) { errf_("cs-loader: unterminated bind symbol\n"); return -1; }
          p = z + 1;
        }
        break;
      case 0x50: /* SET_TYPE_IMM */
        type = b & 0x0F;
        break;
      case 0x60: /* SET_ADDEND_SLEB */
        addend = read_sleb(&p, end);
        break;
      case 0x70: /* SET_SEGMENT_AND_OFFSET_ULEB */
        idx = b & 0x0F;
        seg_off = read_uleb(&p, end);
        break;
      case 0x80: /* ADD_ADDR_ULEB */
        seg_off += read_uleb(&p, end);
        break;
      case 0x90:   /* DO_BIND */
      case 0xA0:   /* DO_BIND_ADD_ADDR_ULEB */
      case 0xB0:   /* DO_BIND_ADD_ADDR_IMM_SCALED */
      case 0xC0: { /* DO_BIND_ULEB_TIMES_SKIPPING_ULEB */
        uint64_t times = 1, skip = 0;
        if ((b & 0xF0) == 0xA0) skip = read_uleb(&p, end);
        else if ((b & 0xF0) == 0xB0) skip = (uint64_t)(b & 0x0F) * 8;
        else if ((b & 0xF0) == 0xC0) { times = read_uleb(&p, end); skip = read_uleb(&p, end); }
        if (type != BIND_TYPE_POINTER) {
          errf_("cs-loader: legacy bind type %u is not implemented (only POINTER)\n", type);
          return -1;
        }
        const struct segment_command_64 *sc = seg_at(im, idx);
        if (sc == NULL) { errf_("cs-loader: legacy bind names segment %u\n", idx); return -1; }
        for (uint64_t i = 0; i < times; i++) {
          uint64_t slot_addr = image_base + (sc->vmaddr - im->text->vmaddr) + seg_off;
          uint64_t val = 0;
          if (sym == NULL) {
            errf_("cs-loader: legacy bind with no symbol name\n");
            return -1;
          }
          const void *addr = resolve_for_ordinal(im, ordinal, sym);
          if (addr == NULL) {
            if (weak) {
              val = 0;   /* a weak bind of a missing symbol is 0 by definition */
            } else {
              errf_("cs-loader: UNRESOLVED external '%s' (ordinal %d)\n", sym, ordinal);
              unresolved++;
            }
          } else {
            val = (uint64_t)(uintptr_t)addr + (uint64_t)addend;
          }
          if (write_slot(task, slot_addr, val) != 0) return -1;
          n++;
          seg_off += skip + 8;
        }
        break;
      }
      default:
        errf_("cs-loader: unknown legacy bind opcode 0x%02x - refusing rather than\n"
              "           skipping it, because a skipped bind is a null function pointer\n", b);
        return -1;
    }
  }
  *out_count += n;
  return unresolved ? -1 : 0;
}

static int apply_legacy_fixups(image_t *im, task_t task, mach_vm_address_t image_base) {
  const struct load_command *lc = lc_find(im, LC_DYLD_INFO_ONLY);
  if (lc == NULL) lc = lc_find(im, LC_DYLD_INFO);
  if (lc == NULL) { errf_("cs-loader: no legacy dyld info\n"); return -1; }
  const struct dyld_info_command *di = (const struct dyld_info_command *)lc;

  struct { uint32_t off, size; } rebases = {di->rebase_off, di->rebase_size};
  uint32_t n_rebase = 0, n_bind = 0, n_weak = 0, n_lazy = 0;

  if (rebases.size) {
    if (apply_rebases(im, task, image_base, rebases.off, rebases.size, &n_rebase) != 0) {
      errf_("cs-loader: legacy rebases failed\n");
      return -1;
    }
  }
  if (di->bind_size) {
    if (apply_binds(im, task, image_base, di->bind_off, di->bind_size, 0, &n_bind) != 0) {
      errf_("cs-loader: legacy binds failed\n");
      return -1;
    }
  }
  if (di->weak_bind_size) {
    /* A weak bind of a symbol that is not there is 0, so this cannot fail on resolution */
    if (apply_binds(im, task, image_base, di->weak_bind_off, di->weak_bind_size, 1,
                    &n_weak) != 0) {
      errf_("cs-loader: legacy weak binds failed\n");
      return -1;
    }
  }
  if (di->lazy_bind_size) {
    /* Applied eagerly. A real dyld defers these until first use, but we are the loader
     * and there is no lazy-binder machinery to defer to: binding them now is the
     * behaviour a non-lazy image would get, and it means a missing symbol is reported
     * before the payload runs rather than at the moment it calls it. */
    if (apply_binds(im, task, image_base, di->lazy_bind_off, di->lazy_bind_size, 0,
                    &n_lazy) != 0) {
      errf_("cs-loader: legacy lazy binds failed\n");
      return -1;
    }
  }
  logf_("  legacy fixups: %u rebases, %u binds, %u weak, %u lazy, 0 unresolved\n",
        n_rebase, n_bind, n_weak, n_lazy);
  return 0;
}

/* ------------------------------------------------------------------ parent ------- */

static int run_parent(const char *path, int argc, char **argv) {
  image_t im;
  if (image_open(path, &im) != 0) return 1;

  uint64_t lo = 0, hi = 0;
  if (image_bounds(&im, &lo, &hi) != 0) { errf_("cs-loader: no loadable segments\n"); return 1; }
  const uint64_t image_len = hi - lo;
  logf_("cs-loader: %s, %zu bytes, image 0x%llx..0x%llx (%llu bytes)\n",
        path, im.size, (unsigned long long)lo, (unsigned long long)hi,
        (unsigned long long)image_len);

  /* Before the fork, so the child inherits these mappings at the same addresses. */
  load_dependencies(&im, path);

  sync_t *sync = sync_new();
  if (sync == NULL) { errf_("cs-loader: shared page: %s\n", strerror(errno)); return 1; }

  pid_t child = fork();
  if (child < 0) { errf_("cs-loader: fork: %s\n", strerror(errno)); return 1; }

  if (child == 0) {
    /* The child does nothing but wait, and then do exactly what it is told. */
    alarm(60);
    sync->ready = 1;
    for (int i = 0; i < 12000 && !sync->go; i++) usleep(5000);
    if (!sync->go) _exit(70);
    if (sync->status != 0) _exit(71);
    for (uint32_t i = 0; i < sync->init_count; i++) {
      void (*fn)(void) = (void (*)(void))(uintptr_t)((uint64_t *)sync->inits)[i];
      fn();
    }
    int (*main_fn)(int, char **, char **, char **) =
        (int (*)(int, char **, char **, char **))(uintptr_t)sync->entry;
    _exit(main_fn((int)sync->argc, (char **)(uintptr_t)sync->argv, environ, NULL));
  }

  logf_("  child pid %d\n", child);

  /* Soften it. It is our child, so waitpid consumes the stop and PT_DETACH works - the
   * same shape as the anchor's cow mode. */
  if (ptrace(PT_ATTACHEXC, child, NULL, 0) != 0) {
    errf_("cs-loader: PT_ATTACHEXC failed: %s\n", strerror(errno));
    kill(child, SIGKILL);
    return 1;
  }
  int st = 0;
  for (int i = 0; i < 200; i++) {
    if (waitpid(child, &st, WUNTRACED | WNOHANG) == child) break;
    usleep(10000);
  }
  ptrace(PT_DETACH, child, NULL, 0);
  kill(child, SIGCONT);

  task_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), child, &task);
  if (kr != KERN_SUCCESS) {
    errf_("cs-loader: task_for_pid: %s\n", mach_error_string(kr));
    kill(child, SIGKILL);
    return 1;
  }

  mach_vm_address_t base = 0;
  kr = mach_vm_allocate(task, &base, image_len, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    errf_("cs-loader: mach_vm_allocate: %s\n", mach_error_string(kr));
    kill(child, SIGKILL);
    return 1;
  }
  im.slide_pending = (intptr_t)(base - lo);
  logf_("  image based at 0x%llx, slide %+lld\n", (unsigned long long)base,
        (long long)im.slide_pending);

  /* Segments: write the file bytes into anonymous pages. Nothing here is signed, and
   * nothing needs to be - that is the point of the whole exercise. */
  const struct load_command *lc = lc_first(&im);
  for (uint32_t i = 0; i < im.mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
      if (sc->filesize == 0) { lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize); continue; }
      mach_vm_address_t dst = base + (sc->vmaddr - lo);
      kr = mach_vm_write(task, dst, (vm_offset_t)(uintptr_t)(im.file + sc->fileoff),
                         (mach_msg_type_number_t)sc->filesize);
      if (kr != KERN_SUCCESS) {
        errf_("cs-loader: writing %s failed: %s\n", sc->segname, mach_error_string(kr));
        kill(child, SIGKILL);
        return 1;
      }
      /* Writable while we patch it; the real protections go on at the end. */
      mach_vm_protect(task, dst, sc->vmsize, FALSE, VM_PROT_READ | VM_PROT_WRITE);
      logf_("  %-14s %8llu bytes -> 0x%llx\n", sc->segname,
            (unsigned long long)sc->filesize, (unsigned long long)dst);
    }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }

  int fixup_rc = (lc_find(&im, LC_DYLD_CHAINED_FIXUPS) != NULL)
                     ? apply_chained_fixups(&im, task, base)
                     : apply_legacy_fixups(&im, task, base);
  if (fixup_rc != 0) {
    errf_("cs-loader: fixups failed; not running anything\n");
    kill(child, SIGKILL);
    return 1;
  }

  /* Entry point. */
  const struct entry_point_command *ep =
      (const struct entry_point_command *)lc_find(&im, LC_MAIN);
  if (ep == NULL) {
    errf_("cs-loader: no LC_MAIN: this image has no entry point to call\n");
    kill(child, SIGKILL);
    return 1;
  }
  uint64_t entry = base + (im.text->vmaddr - lo) + ep->entryoff;
  logf_("  entry 0x%llx (entryoff %llu)\n", (unsigned long long)entry,
        (unsigned long long)ep->entryoff);

  /* Initialisers: collect their values AFTER the fixups, by reading them back out of
   * the child - for S_MOD_INIT_FUNC_POINTERS the slots are themselves fixed up, so
   * reading them from the file would give us unrebased zeros. */
  uint64_t init_addrs[256];
  uint32_t init_count = 0;
  lc = lc_first(&im);
  for (uint32_t i = 0; i < im.mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
      const struct section_64 *sects = (const struct section_64 *)(sc + 1);
      for (uint32_t s = 0; s < sc->nsects; s++) {
        uint32_t type = sects[s].flags & SECTION_TYPE;
        if (type == S_MOD_INIT_FUNC_POINTERS) {
          uint64_t n = sects[s].size / 8;
          for (uint64_t k = 0; k < n && init_count < 256; k++) {
            uint64_t slot = base + (sects[s].addr - lo) + k * 8;
            uint64_t val = 0;
            mach_msg_type_number_t got = 0;
            vm_offset_t buf = 0;
            if (mach_vm_read(task, slot, 8, &buf, &got) == KERN_SUCCESS && got == 8) {
              memcpy(&val, (const void *)(uintptr_t)buf, 8);
              mach_vm_deallocate(mach_task_self(), buf, got);
              init_addrs[init_count++] = val;
            }
          }
        } else if (type == S_INIT_FUNC_OFFSETS) {
          uint64_t n = sects[s].size / 4;
          for (uint64_t k = 0; k < n && init_count < 256; k++) {
            uint32_t off = 0;
            memcpy(&off, im.file + sects[s].offset + k * 4, 4);
            init_addrs[init_count++] = entry - ep->entryoff + off; /* image base + off */
          }
        }
      }
    }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }

  /* argv, in the child, and the initialiser array, in the child. */
  /* argv[0] is the payload's own path, exactly as a shell would have passed it, and the
   * arguments follow. This is not cosmetic: a multi-call binary - busybox and several
   * Procursus tools - decides which program to be from argv[0], so passing the first
   * ARGUMENT as argv[0] silently makes it run the wrong applet. */
  uint32_t nargs = (uint32_t)argc;
  size_t argv_need = 4096;
  mach_vm_address_t argv_page = 0;
  kr = mach_vm_allocate(task, &argv_page, argv_need, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) { errf_("cs-loader: argv page: %s\n", mach_error_string(kr)); kill(child, SIGKILL); return 1; }
  uint8_t argv_buf[4096];
  uint64_t ptrs[64];
  uint32_t nptr = 0;
  size_t str_off = (nargs + 1) * 8;
  for (uint32_t i = 0; i < nargs && nptr < 63; i++) {
    const char *a = argv[i];
    size_t l = strlen(a) + 1;
    if (str_off + l > sizeof argv_buf) break;
    memcpy(argv_buf + str_off, a, l);
    ptrs[nptr++] = argv_page + str_off;
    str_off += l;
  }
  ptrs[nptr] = 0;
  memcpy(argv_buf, ptrs, (nptr + 1) * 8);
  mach_vm_write(task, argv_page, (vm_offset_t)(uintptr_t)argv_buf, (mach_msg_type_number_t)str_off);

  mach_vm_address_t init_page = 0;
  if (init_count) {
    mach_vm_allocate(task, &init_page, 4096, VM_FLAGS_ANYWHERE);
    mach_vm_write(task, init_page, (vm_offset_t)(uintptr_t)init_addrs, init_count * 8);
  }

  /* Final protections. EXEC only where the payload asked for it, and only after every
   * write is done. */
  lc = lc_first(&im);
  for (uint32_t i = 0; i < im.mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
      if (sc->vmsize) {
        vm_prot_t p = 0;
        if (sc->initprot & VM_PROT_READ) p |= VM_PROT_READ;
        if (sc->initprot & VM_PROT_WRITE) p |= VM_PROT_WRITE;
        if (sc->initprot & VM_PROT_EXECUTE) p |= VM_PROT_EXECUTE | VM_PROT_READ;
        mach_vm_protect(task, base + (sc->vmaddr - lo), sc->vmsize, FALSE, p);
      }
    }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }

  sync->entry = entry;
  sync->inits = init_page;
  sync->init_count = init_count;
  sync->argc = nargs;
  sync->argv = argv_page;
  sync->status = 0;
  sync->go = 1;

  int status = 0;
  if (waitpid(child, &status, 0) == child) {
    if (WIFEXITED(status))
      logf_("cs-loader: payload exited %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
      errf_("cs-loader: payload died on signal %d%s\n", WTERMSIG(status),
            WTERMSIG(status) == SIGKILL ? " (code-signing kill?)" : "");
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* -------------------------------------------------------------- sigtest mode ---- */

/* The F_ADDFILESIGS/F_CHECK_LV probe, to be run in the LANE - unsandboxed root, the
 * context where Nyxian's loader is said to work and where our app measured EPERM. Same
 * two fcntls, same order, so the two results are comparable. */
static int sigtest(const char *path) {
  errf_("sigtest: %s\n", path);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { errf_("  open: %s\n", strerror(errno)); return 1; }
  struct stat st;
  fstat(fd, &st);
  void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (m == MAP_FAILED) { errf_("  mmap: %s\n", strerror(errno)); close(fd); return 1; }
  const struct mach_header_64 *mh = m;
  const struct load_command *lc = (const struct load_command *)((const uint8_t *)mh + sizeof(*mh));
  const struct linkedit_data_command *sig = NULL;
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_CODE_SIGNATURE) { sig = (const struct linkedit_data_command *)lc; break; }
    lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
  }
  if (sig == NULL) {
    errf_("  no LC_CODE_SIGNATURE\n");
  } else {
    errf_("  LC_CODE_SIGNATURE: %u bytes at %u\n", sig->datasize, sig->dataoff);
    fsignatures_t si = {.fs_file_start = 0, .fs_blob_start = (void *)(long)sig->dataoff,
                        .fs_blob_size = sig->datasize};
    errno = 0;
    int r = fcntl(fd, F_ADDFILESIGS_RETURN, &si);
    errf_("  F_ADDFILESIGS_RETURN -> %d%s\n", r, r == 0 ? "  (accepted)" : "");
    if (r != 0) errf_("    errno %d (%s)\n", errno, strerror(errno));
  }
  fchecklv_t ci;
  memset(&ci, 0, sizeof ci);
  errno = 0;
  int r2 = fcntl(fd, F_CHECK_LV, &ci);
  errf_("  F_CHECK_LV -> %d%s\n", r2, r2 == 0 ? "  (allowed)" : "");
  if (r2 != 0) errf_("    errno %d (%s)\n", errno, strerror(errno));
  errno = 0;
  void *h = dlopen(path, RTLD_NOW);
  errf_("  dlopen -> %s\n", h ? "HANDLE" : "NULL");
  if (!h) errf_("    %s\n", dlerror() ? dlerror() : "(no dlerror)");
  return 0;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);

  /* cs-loader's own options must come BEFORE the payload path, and everything from the
   * path onward belongs to the payload - including things that look like our flags. So
   * `cs-loader ./x -v` runs ./x with the argument "-v", and `cs-loader -v ./x -v` runs it
   * verbosely with the same argument. The parse stops at the first argument that is not
   * one of ours; that argument is the payload. */
  int i = 1;
  const char *sigtest_path = NULL;
  int want_help = 0;
  for (; i < argc; i++) {
    const char *a = argv[i];
    if (a[0] != '-' || a[1] == 0) break;                    /* the payload path */
    if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) { g_verbose = 1; continue; }
    if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { want_help = 1; continue; }
    if (strcmp(a, "--") == 0) { i++; break; }               /* end of our options */
    if (strcmp(a, "--sigtest") == 0) {
      i++;
      if (i >= argc) { errf_("cs-loader: --sigtest needs a path\n"); return 2; }
      sigtest_path = argv[i];
      i++;
      break;
    }
    /* An unrecognised leading option with no slash in it is nearly always a mistyped
     * cs-loader flag rather than a payload path, and trying to load "-x" as a file would
     * produce a confusing errno. Say what the grammar is instead. */
    if (strchr(a, '/') == NULL) {
      errf_("cs-loader: unknown option '%s'.\n"
            "           cs-loader's own options come BEFORE the payload:\n"
            "             cs-loader [-v] <macho> [args...]\n"
            "           everything after <macho> is passed to the payload unchanged.\n", a);
      return 2;
    }
    break;
  }

  uint32_t f = 0;
  csops(getpid(), CS_OPS_STATUS, &f, sizeof f);
  logf_("cs-loader: uid=%d pid=%d csflags=0x%08x%s%s%s\n", (int)getuid(), (int)getpid(), f,
        (f & CS_GET_TASK_ALLOW) ? " get-task-allow" : "",
        (f & CS_PLATFORM_BINARY) ? " platform" : "",
        (f & CS_DEBUGGED) ? " DEBUGGED" : "");

  if (sigtest_path != NULL) return sigtest(sigtest_path);

  if (want_help || i >= argc) {
    errf_("usage: cs-loader [-v|--verbose] <macho> [args...]\n"
          "       cs-loader [-v|--verbose] --sigtest <path>\n"
          "  Options come before <macho>; everything after it goes to the payload, so\n"
          "  `cs-loader ./x -v` gives the payload the argument \"-v\".\n"
          "  Without -v cs-loader is silent on success. Failures still report on stderr,\n"
          "  because a loader that fails silently is indistinguishable from one that\n"
          "  succeeded; redirect stderr if you want it fully quiet.\n");
    return want_help ? 0 : 2;
  }

  collect_search_dirs();
  return run_parent(argv[i], argc - i, argv + i);
}
