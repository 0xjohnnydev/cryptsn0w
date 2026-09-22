// Root-only control utility for the installed jailbreak.  It owns no
// privileged primitive of its own: it manages the SBInject marker files and
// drives the tools that already ship in the image.
#import <Foundation/Foundation.h>

#include "SBInject/sbinject_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern int proc_pidpath(int pid, void *buffer, uint32_t size);

#define CODEX_PROC_PIDPATH_MAX 4096

static NSString *const kApplications = @"/var/jb/Applications";
static const char *const kExecWorker =
    "/var/jb/usr/libexec/codex-exec-worker";
static const char *const kInjector =
    "/var/jb/usr/libexec/codex-ellekit-loader";
static const char *const kLaunchctl = "/var/jb/usr/bin/launchctl";
static const char *const kTail = "/var/jb/usr/bin/tail";
static const char *const kBootstrapLog =
    "/var/tmp/codex-dopamine-cryptex-bootstrap.log";
// cryptexd submits the boot daemon into the mobile user's domain, not system.
static const char *const kDaemonService =
    "user/501/com.openai.codex.dopamine.bootstrap";

// The same shape sbinject_launchdhook.c requires before it will honour a
// marker; writing anything else silently disables the lane.
static bool marker_present(const char *path) {
    struct stat status;
    return lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
           !S_ISLNK(status.st_mode) && status.st_nlink == 1 &&
           status.st_uid == 0 && status.st_gid == 0 && status.st_size == 0 &&
           (status.st_mode & 07777) == 0644;
}

static bool marker_set(const char *path) {
    int file = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (file < 0) return false;
    bool ready = ftruncate(file, 0) == 0 && fchown(file, 0, 0) == 0 &&
                 fchmod(file, 0644) == 0 && fsync(file) == 0;
    close(file);
    return ready && marker_present(path);
}

static bool marker_clear(const char *path) {
    return unlink(path) == 0 || errno == ENOENT;
}

static int run_tool(const char *const *arguments) {
    pid_t child = 0;
    if (posix_spawn(&child, arguments[0], NULL, NULL,
                    (char *const *)(uintptr_t)arguments, environ) != 0) {
        fprintf(stderr, "customctl: cannot run %s: %s\n", arguments[0],
                strerror(errno));
        return 71;
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 71;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 70;
}

// proc_listallpids() returns nothing to an unentitled caller, so enumerate the
// way ps(1) does.  Both "SpringBoard" and "notSpringBoard" fit p_comm.
static pid_t springboard_pid(char *path, size_t size) {
    int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t bytes = 0;
    if (sysctl(name, 4, NULL, &bytes, NULL, 0) != 0 || bytes == 0) return -1;
    bytes += bytes / 8U + sizeof(struct kinfo_proc);
    struct kinfo_proc *entries = malloc(bytes);
    if (entries == NULL) return -1;
    if (sysctl(name, 4, entries, &bytes, NULL, 0) != 0) {
        free(entries);
        return -1;
    }
    pid_t found = -1;
    for (size_t index = 0; index < bytes / sizeof(struct kinfo_proc); ++index) {
        const char *comm = entries[index].kp_proc.p_comm;
        if (strcmp(comm, "SpringBoard") != 0 &&
            strcmp(comm, "notSpringBoard") != 0) {
            continue;
        }
        found = entries[index].kp_proc.p_pid;
        if (path != NULL && size != 0) {
            path[0] = '\0';
            if (proc_pidpath(found, path, (uint32_t)size) <= 0) {
                strlcpy(path, comm, size);
            }
        }
        break;
    }
    free(entries);
    return found;
}

static int respring(void) {
    char path[CODEX_PROC_PIDPATH_MAX] = {0};
    pid_t pid = springboard_pid(path, sizeof(path));
    if (pid <= 1) {
        fprintf(stderr, "customctl: SpringBoard is not running\n");
        return 69;
    }
    if (kill(pid, SIGTERM) != 0) {
        fprintf(stderr, "customctl: respring failed: %s\n", strerror(errno));
        return 71;
    }
    printf("respring pid=%d path=%s\n", pid, path);
    return 0;
}

// Registration lives in the boot daemon with no IPC of its own, so re-running
// it means restarting the daemon.  That re-bootstraps com.openssh.sshd on its
// way through, which drops any SSH session issuing this command.
static int refresh(void) {
    fprintf(stderr, "customctl: restarting the boot daemon; an SSH session "
                    "issuing this will drop\n");
    const char *const arguments[] = {kLaunchctl, "kickstart", "-k",
                                     kDaemonService, NULL};
    int status = run_tool(arguments);
    printf("refresh service=%s status=%d\n", kDaemonService, status);
    return status;
}

static bool normalize_tree(NSString *root) {
    NSFileManager *manager = NSFileManager.defaultManager;
    NSMutableArray<NSString *> *paths = [@[ root ] mutableCopy];
    NSDirectoryEnumerator *walker = [manager enumeratorAtPath:root];
    for (NSString *entry in walker) {
        [paths addObject:[root stringByAppendingPathComponent:entry]];
    }
    for (NSString *path in paths) {
        const char *raw = path.fileSystemRepresentation;
        struct stat status;
        if (lstat(raw, &status) != 0 || lchown(raw, 0, 0) != 0) return false;
        if (S_ISLNK(status.st_mode)) continue;
        mode_t mode = S_ISDIR(status.st_mode)
                          ? 0755
                          : ((status.st_mode & S_IXUSR) ? 0755 : 0644);
        if (chmod(raw, mode) != 0) return false;
    }
    return true;
}

static NSString *bundle_identifier(NSString *bundle) {
    NSDictionary *info = [NSDictionary
        dictionaryWithContentsOfFile:
            [bundle stringByAppendingPathComponent:@"Info.plist"]];
    NSString *identifier = info[@"CFBundleIdentifier"];
    return [identifier isKindOfClass:NSString.class] && identifier.length != 0
               ? identifier
               : nil;
}

static int list_applications(void) {
    NSArray<NSString *> *entries =
        [[NSFileManager.defaultManager contentsOfDirectoryAtPath:kApplications
                                                           error:nil]
            sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *entry in entries) {
        if ([entry.pathExtension caseInsensitiveCompare:@"app"] !=
            NSOrderedSame) {
            continue;
        }
        NSString *bundle = [kApplications stringByAppendingPathComponent:entry];
        NSString *identifier = bundle_identifier(bundle);
        NSString *payload = [bundle
            stringByAppendingPathComponent:@CODEX_SBINJECT_APP_PAYLOAD_NAME];
        printf("%-34s prepared=%s path=%s\n",
               identifier != nil ? identifier.UTF8String : "(no identifier)",
               [NSFileManager.defaultManager fileExistsAtPath:payload] ? "yes"
                                                                       : "no",
               bundle.UTF8String);
    }
    return 0;
}

static int install_application(const char *source) {
    NSString *from = [NSString stringWithUTF8String:source]
                         .stringByStandardizingPath;
    BOOL directory = NO;
    if (![NSFileManager.defaultManager fileExistsAtPath:from
                                            isDirectory:&directory] ||
        !directory ||
        [from.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) {
        fprintf(stderr, "customctl: not an .app bundle: %s\n", source);
        return 64;
    }
    NSString *identifier = bundle_identifier(from);
    if (identifier == nil) {
        fprintf(stderr, "customctl: bundle has no CFBundleIdentifier\n");
        return 65;
    }
    NSString *to =
        [kApplications stringByAppendingPathComponent:from.lastPathComponent];
    NSError *error = nil;
    if ([NSFileManager.defaultManager fileExistsAtPath:to] &&
        ![NSFileManager.defaultManager removeItemAtPath:to error:&error]) {
        fprintf(stderr, "customctl: cannot replace %s: %s\n", to.UTF8String,
                error.description.UTF8String);
        return 73;
    }
    if (![NSFileManager.defaultManager copyItemAtPath:from
                                               toPath:to
                                                error:&error]) {
        fprintf(stderr, "customctl: copy failed: %s\n",
                error.description.UTF8String);
        return 73;
    }
    if (!normalize_tree(to)) {
        fprintf(stderr, "customctl: could not normalize ownership: %s\n",
                strerror(errno));
        return 73;
    }
    printf("installed identifier=%s path=%s\n", identifier.UTF8String,
           to.UTF8String);
    return refresh();
}

static int uninstall_application(const char *wanted) {
    NSString *identifier = [NSString stringWithUTF8String:wanted];
    NSArray<NSString *> *entries =
        [NSFileManager.defaultManager contentsOfDirectoryAtPath:kApplications
                                                          error:nil];
    for (NSString *entry in entries) {
        if ([entry.pathExtension caseInsensitiveCompare:@"app"] !=
            NSOrderedSame) {
            continue;
        }
        NSString *bundle = [kApplications stringByAppendingPathComponent:entry];
        if (![bundle_identifier(bundle) isEqual:identifier]) continue;
        NSError *error = nil;
        if (![NSFileManager.defaultManager removeItemAtPath:bundle
                                                      error:&error]) {
            fprintf(stderr, "customctl: remove failed: %s\n",
                    error.description.UTF8String);
            return 73;
        }
        printf("removed identifier=%s path=%s\n", identifier.UTF8String,
               bundle.UTF8String);
        return refresh();
    }
    fprintf(stderr, "customctl: no managed app with identifier %s\n", wanted);
    return 69;
}

static int show_status(void) {
    char path[CODEX_PROC_PIDPATH_MAX] = {0};
    pid_t pid = springboard_pid(path, sizeof(path));
    char root[PATH_MAX] = {0};
    ssize_t length = readlink("/var/jb", root, sizeof(root) - 1U);
    if (length > 0) root[length] = '\0';

    printf("jailbreakRoot      %s\n", length > 0 ? root : "(absent)");
    printf("springBoard        pid=%d path=%s\n", pid,
           pid > 1 ? path : "(not running)");
    printf("springBoardRedirect %s\n",
           marker_present(CODEX_SBINJECT_ENABLE_MARKER) ? "enabled"
                                                        : "disabled");
    printf("springBoardCrash   %s\n",
           access(CODEX_SBINJECT_CRASH_MARKER, F_OK) == 0 ? "TRIPPED" : "clear");
    printf("preferences        %s\n",
           marker_present(CODEX_SBINJECT_PREFERENCES_ENABLE_MARKER)
               ? "enabled"
               : "disabled");
    printf("preferencesCrash   %s\n",
           access(CODEX_SBINJECT_PREFERENCES_CRASH_MARKER, F_OK) == 0
               ? "TRIPPED"
               : "clear");
    printf("tweakSafeMode      %s\n",
           access(CODEX_SBINJECT_SAFE_MODE_MARKER, F_OK) == 0 ? "active"
                                                              : "inactive");
    printf("amfidHook          %s\n",
           access(CODEX_SBINJECT_AMFID_READY_MARKER, F_OK) == 0 ? "ready"
                                                                : "not-ready");
    printf("amfidInjection     %s\n",
           marker_present(CODEX_SBINJECT_AMFID_ENABLE_MARKER) ? "enabled"
                                                              : "disabled");
    printf("launchdHook        %s\n",
           access(CODEX_SBINJECT_LAUNCHD_READY_MARKER, F_OK) == 0 ? "ready"
                                                                  : "not-ready");
    return 0;
}

static int set_springboard(bool enabled) {
    if (!enabled) {
        if (!marker_clear(CODEX_SBINJECT_ENABLE_MARKER)) {
            fprintf(stderr, "customctl: %s\n", strerror(errno));
            return 73;
        }
        printf("springBoardRedirect disabled\n");
        return respring();
    }
    // The crash-loop marker outlives a reboot and gates activation, so arming
    // the lane has to clear it or the next boot disables the redirect again.
    if (!marker_clear(CODEX_SBINJECT_CRASH_MARKER) ||
        !marker_set(CODEX_SBINJECT_ENABLE_MARKER)) {
        fprintf(stderr, "customctl: %s\n", strerror(errno));
        return 73;
    }
    printf("springBoardRedirect enabled\n");
    return respring();
}

static int set_preferences(bool enabled) {
    bool ready = enabled ? (marker_clear(CODEX_SBINJECT_PREFERENCES_CRASH_MARKER) &&
                            marker_set(CODEX_SBINJECT_PREFERENCES_ENABLE_MARKER))
                         : marker_clear(CODEX_SBINJECT_PREFERENCES_ENABLE_MARKER);
    if (!ready) {
        fprintf(stderr, "customctl: %s\n", strerror(errno));
        return 73;
    }
    printf("preferences %s\n", enabled ? "enabled" : "disabled");
    return 0;
}

static int set_safe_mode(bool enabled) {
    if (!enabled) {
        if (!marker_clear(CODEX_SBINJECT_SAFE_MODE_MARKER) ||
            !marker_clear(CODEX_SBINJECT_ELLEKIT_SAFE_MODE_MARKER)) {
            fprintf(stderr, "customctl: %s\n", strerror(errno));
            return 73;
        }
        printf("tweakSafeMode inactive\n");
        return respring();
    }
    static const char body[] = "tweak=Unknown tweak\nreason=customctl\n";
    int file = open(CODEX_SBINJECT_SAFE_MODE_MARKER,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    if (file < 0 ||
        write(file, body, sizeof(body) - 1U) != (ssize_t)(sizeof(body) - 1U)) {
        if (file >= 0) close(file);
        fprintf(stderr, "customctl: %s\n", strerror(errno));
        return 73;
    }
    (void)fchown(file, 0, 0);
    (void)fchmod(file, 0600);
    close(file);
    printf("tweakSafeMode active\n");
    return respring();
}

static int clear_crash(void) {
    if (!marker_clear(CODEX_SBINJECT_CRASH_MARKER) ||
        !marker_clear(CODEX_SBINJECT_PREFERENCES_CRASH_MARKER) ||
        !marker_clear(CODEX_SBINJECT_AMFID_CRASH_MARKER)) {
        fprintf(stderr, "customctl: %s\n", strerror(errno));
        return 73;
    }
    printf("crash markers cleared\n");
    return 0;
}

static int show_log(const char *which) {
    const char *path = kBootstrapLog;
    if (which != NULL && strcmp(which, "sbinject") == 0) {
        path = CODEX_SBINJECT_LOG;
    } else if (which != NULL && strcmp(which, "amfid") == 0) {
        path = CODEX_SBINJECT_AMFID_LOG;
    } else if (which != NULL && strcmp(which, "bootstrap") != 0) {
        fprintf(stderr, "customctl: unknown log %s\n", which);
        return 64;
    }
    const char *const arguments[] = {kTail, "-n", "200", path, NULL};
    return run_tool(arguments);
}

static bool parse_pid(const char *text, pid_t *out) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT_MAX) {
        return false;
    }
    *out = (pid_t)value;
    return true;
}

static void usage(void) {
    fprintf(stderr,
            "usage: customctl <command>\n"
            "  status                       report the installed lane state\n"
            "  respring                     restart SpringBoard\n"
            "  springboard on|off           SpringBoard redirect + respring\n"
            "  preferences on|off           Settings redirect\n"
            "  safemode on|off              run without tweaks\n"
            "  clear-crash                  clear the sticky crash markers\n"
            "  run MACHO [ARG ...]          run an ad-hoc Mach-O under /var/jb\n"
            "  inject PID DYLIB             inject into a running app, lsd or\n"
            "                               amfid; the dylib must be readable\n"
            "                               by the target.  A live SpringBoard\n"
            "                               is refused: tweaks load pre-main\n"
            "  refresh                      re-register managed applications\n"
            "                               (restarts the daemon; drops SSH)\n"
            "  apps                         list managed applications\n"
            "  install PATH.app             install into /var/jb/Applications\n"
            "  uninstall BUNDLEID           remove a managed application\n"
            "  log [bootstrap|sbinject|amfid]\n");
}

static bool is_toggle(int argc, char **argv, const char *name, bool *enabled) {
    if (argc != 3 || strcmp(argv[1], name) != 0) return false;
    if (strcmp(argv[2], "on") == 0) {
        *enabled = true;
        return true;
    }
    if (strcmp(argv[2], "off") == 0) {
        *enabled = false;
        return true;
    }
    return false;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) {
            usage();
            return 64;
        }
        if (geteuid() != 0) {
            fprintf(stderr, "customctl: must run as root\n");
            return 77;
        }
        bool enabled = false;
        if (argc == 2 && strcmp(argv[1], "status") == 0) {
            return show_status();
        }
        if (argc == 2 && strcmp(argv[1], "respring") == 0) {
            return respring();
        }
        if (argc == 2 && strcmp(argv[1], "refresh") == 0) {
            return refresh();
        }
        if (argc == 2 && strcmp(argv[1], "apps") == 0) {
            return list_applications();
        }
        if (argc == 2 && strcmp(argv[1], "clear-crash") == 0) {
            return clear_crash();
        }
        if (is_toggle(argc, argv, "springboard", &enabled)) {
            return set_springboard(enabled);
        }
        if (is_toggle(argc, argv, "preferences", &enabled)) {
            return set_preferences(enabled);
        }
        if (is_toggle(argc, argv, "safemode", &enabled)) {
            return set_safe_mode(enabled);
        }
        if (argc == 3 && strcmp(argv[1], "install") == 0) {
            return install_application(argv[2]);
        }
        if (argc == 3 && strcmp(argv[1], "uninstall") == 0) {
            return uninstall_application(argv[2]);
        }
        if ((argc == 2 || argc == 3) && strcmp(argv[1], "log") == 0) {
            return show_log(argc == 3 ? argv[2] : NULL);
        }
        pid_t target = 0;
        if (argc == 4 && strcmp(argv[1], "inject") == 0 &&
            parse_pid(argv[2], &target)) {
            char text[32] = {0};
            snprintf(text, sizeof(text), "%d", target);
            const char *const arguments[] = {kInjector, "--inject-pid", text,
                                             argv[3], NULL};
            return run_tool(arguments);
        }
        if (argc >= 3 && strcmp(argv[1], "run") == 0) {
            const char **arguments =
                calloc((size_t)argc + 1U, sizeof(*arguments));
            if (arguments == NULL) return 71;
            arguments[0] = kExecWorker;
            arguments[1] = "--macho";
            for (int index = 2; index < argc; ++index) {
                arguments[index] = argv[index];
            }
            arguments[argc] = NULL;
            int status = run_tool(arguments);
            free(arguments);
            return status;
        }
        usage();
        return 64;
    }
}
