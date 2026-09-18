#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const kReportPath =
    "/var/mobile/Media/codex-cryptex-mount-topology-report.txt";

static void report_statfs(int report, const char *path) {
    struct statfs fs = {0};
    errno = 0;
    int result = statfs(path, &fs);
    int savedError = result == 0 ? 0 : errno;
    dprintf(report,
            "statfs path=%s result=%d errno=%d from=%s on=%s type=%s "
            "flags=0x%x fsid=%d:%d\n",
            path, result, savedError, result == 0 ? fs.f_mntfromname : "",
            result == 0 ? fs.f_mntonname : "",
            result == 0 ? fs.f_fstypename : "", result == 0 ? fs.f_flags : 0,
            result == 0 ? fs.f_fsid.val[0] : 0,
            result == 0 ? fs.f_fsid.val[1] : 0);
}

static void report_directory(int report, const char *path) {
    errno = 0;
    DIR *directory = opendir(path);
    if (directory == NULL) {
        dprintf(report, "directory path=%s open=-1 errno=%d\n", path, errno);
        return;
    }
    dprintf(report, "directory path=%s open=0\n", path);
    struct dirent *entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child[PATH_MAX] = {0};
        int amount = snprintf(child, sizeof(child), "%s/%s", path,
                              entry->d_name);
        if (amount <= 0 || (size_t)amount >= sizeof(child)) {
            dprintf(report, "entry name=%s path-too-long=true\n",
                    entry->d_name);
            continue;
        }
        struct stat status = {0};
        errno = 0;
        int statResult = lstat(child, &status);
        dprintf(report,
                "entry name=%s type=%u stat=%d errno=%d mode=0%o dev=%llu "
                "ino=%llu\n",
                entry->d_name, entry->d_type, statResult,
                statResult == 0 ? 0 : errno,
                statResult == 0 ? status.st_mode : 0,
                statResult == 0 ? (unsigned long long)status.st_dev : 0,
                statResult == 0 ? (unsigned long long)status.st_ino : 0);
        report_statfs(report, child);
    }
    closedir(directory);
}

int main(void) {
    int report = open(kReportPath,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (report < 0) {
        return 70;
    }
    struct stat reportStatus = {0};
    if (fstat(report, &reportStatus) != 0 ||
        !S_ISREG(reportStatus.st_mode)) {
        close(report);
        return 71;
    }

    dprintf(report,
            "magic=codex-cryptex-mount-topology-v1\npid=%d\nuid=%u\neuid=%u\n",
            getpid(), getuid(), geteuid());

    char linkTarget[PATH_MAX] = {0};
    errno = 0;
    ssize_t linkLength = readlink("/var/jb", linkTarget,
                                  sizeof(linkTarget) - 1);
    int linkError = linkLength >= 0 ? 0 : errno;
    if (linkLength >= 0) {
        linkTarget[linkLength] = '\0';
    }
    dprintf(report, "varJbReadlink=%zd errno=%d target=%s\n", linkLength,
            linkError, linkLength >= 0 ? linkTarget : "");

    char resolvedVarJb[PATH_MAX] = {0};
    errno = 0;
    char *resolved = realpath("/var/jb", resolvedVarJb);
    dprintf(report, "varJbRealpath=%s errno=%d\n",
            resolved != NULL ? resolvedVarJb : "", resolved != NULL ? 0 : errno);

    static const char *const paths[] = {
        "/",
        "/private/preboot",
        "/var/jb",
        "/private/var/run/com.apple.security.cryptexd",
        "/private/var/run/com.apple.security.cryptexd/mnt",
    };
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); index++) {
        report_statfs(report, paths[index]);
    }
    if (resolved != NULL) {
        report_statfs(report, resolvedVarJb);
    }

    int mountCount = getfsstat(NULL, 0, MNT_NOWAIT);
    dprintf(report, "getfsstatCount=%d errno=%d\n", mountCount,
            mountCount >= 0 ? 0 : errno);
    if (mountCount > 0 && mountCount < 4096) {
        size_t allocationSize = (size_t)mountCount * sizeof(struct statfs);
        struct statfs *mounts = calloc((size_t)mountCount,
                                      sizeof(struct statfs));
        if (mounts != NULL) {
            int observed = getfsstat(mounts, (int)allocationSize, MNT_NOWAIT);
            dprintf(report, "getfsstatObserved=%d errno=%d\n", observed,
                    observed >= 0 ? 0 : errno);
            if (observed > mountCount) {
                observed = mountCount;
            }
            for (int index = 0; index < observed; index++) {
                const struct statfs *fs = &mounts[index];
                if (strstr(fs->f_mntonname, "cryptex") == NULL &&
                    strstr(fs->f_mntfromname, "cryptex") == NULL &&
                    strstr(fs->f_mntonname, "/private/preboot") == NULL &&
                    strstr(fs->f_mntfromname, "/private/preboot") == NULL &&
                    strstr(fs->f_mntonname, "/var/jb") == NULL) {
                    continue;
                }
                dprintf(report,
                        "mount index=%d from=%s on=%s type=%s flags=0x%x "
                        "fsid=%d:%d\n",
                        index, fs->f_mntfromname, fs->f_mntonname,
                        fs->f_fstypename, fs->f_flags, fs->f_fsid.val[0],
                        fs->f_fsid.val[1]);
            }
            free(mounts);
        } else {
            dprintf(report, "getfsstatAllocation=false errno=%d\n", errno);
        }
    }

    report_directory(report, "/private/var/run/com.apple.security.cryptexd/mnt");

    bool reportOk = fsync(report) == 0;
    close(report);
    return reportOk ? 0 : 72;
}
