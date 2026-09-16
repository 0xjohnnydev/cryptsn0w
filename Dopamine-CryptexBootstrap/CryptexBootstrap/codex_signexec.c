#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <limits.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <os/log.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CODEX_SIGNEXEC_EXIT_PREPARE_FAILED 75
#define CODEX_SIGNEXEC_MAX_PATH_READ 8192U

static const char *const kStoreRoot = "/var/jb/var/lib/codex-signexec/store";
static const char *const kRuntimeTrustPath =
    "/var/jb/usr/libexec/codex-runtime-trust";
static const char *const kLdidPath = "/var/jb/usr/libexec/codex-signexec-ldid";
static const char *const kPayloadEntitlementsPath =
    "/var/jb/usr/share/codex-runtime-admission/"
    "signexec-payload-entitlements.plist";
static const char *const kWorkerPath = "/var/jb/usr/libexec/codex-exec-worker";
static const char *const kInterposerPath =
    "/var/jb/usr/lib/codex-exec-interposer.dylib";
static const char *const kModePath =
    "/var/jb/usr/share/codex-runtime-admission/admission-mode";
static const char *const kTrustUnavailablePath =
    "/var/jb/var/lib/codex-signexec/trust-unavailable";

/*
 * The JIT/debugged-worker lane is fully local; only runtime trust-cache
 * personalization depends on Apple's TSS service.  Two overrides keep the
 * worker the effective default when the server side becomes unavailable:
 * an operator-pinned mode file ("worker-first") and a per-boot negative
 * cache written after the first trust failure, so later prepares fall back
 * immediately instead of paying a doomed personalization round trip per
 * spawn.
 */
static bool worker_first_forced(void) {
    int descriptor = open(kModePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    char contents[64];
    ssize_t amount = read(descriptor, contents, sizeof(contents) - 1U);
    close(descriptor);
    if (amount <= 0) {
        return false;
    }
    contents[amount] = '\0';
    return strncmp(contents, "worker-first", 12U) == 0;
}

static bool trust_marked_unavailable(int64_t bootSeconds) {
    int descriptor = open(kTrustUnavailablePath,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    char contents[64];
    ssize_t amount = read(descriptor, contents, sizeof(contents) - 1U);
    close(descriptor);
    if (amount <= 0) {
        return false;
    }
    contents[amount] = '\0';
    char expected[32];
    int length = snprintf(expected, sizeof(expected), "%lld\n",
                          (long long)bootSeconds);
    return length > 0 && (size_t)length < sizeof(expected) &&
           strcmp(contents, expected) == 0;
}

static void mark_trust_unavailable(int64_t bootSeconds) {
    int descriptor = open(kTrustUnavailablePath,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (descriptor < 0) {
        return;
    }
    (void)dprintf(descriptor, "%lld\n", (long long)bootSeconds);
    close(descriptor);
}

static void clear_trust_unavailable(void) {
    (void)unlink(kTrustUnavailablePath);
}

static void log_failure(const char *operation, const char *path, int error) {
    dprintf(STDERR_FILENO,
            "codex-signexec operation=%s path=%s error=%s\n", operation,
            path != NULL ? path : "none",
            error != 0 ? strerror(error) : "none");
    os_log(OS_LOG_DEFAULT,
           "codex-signexec operation=%{public}s path=%{public}s "
           "error=%{public}s",
           operation, path != NULL ? path : "none",
           error != 0 ? strerror(error) : "none");
}

static bool path_is_descendant(const char *path, const char *root) {
    size_t rootLength = strlen(root);
    return rootLength > 1U && strncmp(path, root, rootLength) == 0 &&
           path[rootLength] == '/';
}

static bool path_is_managed_macho(const char *path, char resolved[PATH_MAX]) {
    char managedRoot[PATH_MAX];
    struct stat status;
    if (path == NULL || path[0] != '/' ||
        realpath("/var/jb", managedRoot) == NULL ||
        realpath(path, resolved) == NULL ||
        !path_is_descendant(resolved, managedRoot) ||
        path_is_descendant(resolved, kStoreRoot) ||
        lstat(resolved, &status) != 0 || !S_ISREG(status.st_mode) ||
        access(resolved, X_OK) != 0) {
        return false;
    }
    int descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    uint32_t magic = 0;
    ssize_t amount = descriptor >= 0 ? read(descriptor, &magic, sizeof(magic))
                                     : -1;
    if (descriptor >= 0) {
        close(descriptor);
    }
    return amount == (ssize_t)sizeof(magic) &&
           (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
            magic == FAT_MAGIC || magic == FAT_CIGAM
#ifdef FAT_MAGIC_64
            || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64
#endif
           );
}

static bool sha256_path(const char *path, uint8_t digest[CC_SHA256_DIGEST_LENGTH]) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    uint8_t buffer[65536];
    bool ok = true;
    for (;;) {
        ssize_t amount = read(descriptor, buffer, sizeof(buffer));
        if (amount > 0) {
            CC_SHA256_Update(&context, buffer, (CC_LONG)amount);
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        ok = amount == 0;
        break;
    }
    close(descriptor);
    if (ok) {
        CC_SHA256_Final(digest, &context);
    }
    return ok;
}

static void hex_encode(const uint8_t *input, size_t length, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < length; ++index) {
        output[index * 2U] = digits[input[index] >> 4U];
        output[index * 2U + 1U] = digits[input[index] & 0xfU];
    }
    output[length * 2U] = '\0';
}

static bool current_boot_time(int64_t *seconds, int64_t *microseconds) {
    struct timeval boot = {0};
    size_t size = sizeof(boot);
    if (sysctlbyname("kern.boottime", &boot, &size, NULL, 0) != 0 ||
        size != sizeof(boot)) {
        return false;
    }
    *seconds = (int64_t)boot.tv_sec;
    *microseconds = (int64_t)boot.tv_usec;
    return true;
}

static int spawn_capture(const char *executable, char *const arguments[],
                         char *output, size_t outputCapacity) {
    int pipeDescriptors[2] = {-1, -1};
    if (pipe(pipeDescriptors) != 0) {
        return errno;
    }
    (void)fcntl(pipeDescriptors[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(pipeDescriptors[1], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addinherit_np(&actions, STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipeDescriptors[0]);
    posix_spawn_file_actions_adddup2(&actions, pipeDescriptors[1],
                                     STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipeDescriptors[1],
                                     STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipeDescriptors[1]);
    static char *const environment[] = {
        (char *)"PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:"
                "/usr/bin:/bin:/usr/sbin:/sbin",
        (char *)"DYLD_LIBRARY_PATH=/var/jb/usr/lib",
        (char *)"HOME=/var/root",
        (char *)"TMPDIR=/var/tmp",
        NULL,
    };
    pid_t child = 0;
    int result = posix_spawn(&child, executable, &actions, NULL, arguments,
                             environment);
    posix_spawn_file_actions_destroy(&actions);
    close(pipeDescriptors[1]);
    if (result != 0) {
        close(pipeDescriptors[0]);
        return result;
    }
    size_t used = 0;
    if (output != NULL && outputCapacity > 0U) {
        while (used < outputCapacity - 1U) {
            ssize_t amount = read(pipeDescriptors[0], output + used,
                                  outputCapacity - 1U - used);
            if (amount > 0) {
                used += (size_t)amount;
                continue;
            }
            if (amount < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        output[used] = '\0';
    } else {
        char discard[4096];
        while (read(pipeDescriptors[0], discard, sizeof(discard)) > 0) {
        }
    }
    close(pipeDescriptors[0]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return errno;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        os_log(OS_LOG_DEFAULT,
               "codex-signexec child-failed executable=%{public}s status=%d "
               "output=%{public}s",
               executable, status,
               output != NULL && used > 0U ? output : "none");
        return EIO;
    }
    return 0;
}

static int spawn_and_wait(const char *executable, char *const arguments[]) {
    return spawn_capture(executable, arguments, NULL, 0);
}

static bool copy_file(const char *source, const char *destination) {
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) {
        return false;
    }
    char temporary[PATH_MAX];
    int length = snprintf(temporary, sizeof(temporary), "%s.tmp.%d",
                          destination, getpid());
    if (length <= 0 || (size_t)length >= sizeof(temporary)) {
        close(input);
        return false;
    }
    int output = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                      0755);
    if (output < 0) {
        close(input);
        return false;
    }
    uint8_t buffer[65536];
    bool ok = true;
    for (;;) {
        ssize_t amount = read(input, buffer, sizeof(buffer));
        if (amount > 0) {
            ssize_t written = 0;
            while (written < amount) {
                ssize_t step = write(output, buffer + written,
                                     (size_t)(amount - written));
                if (step < 0 && errno == EINTR) {
                    continue;
                }
                if (step <= 0) {
                    ok = false;
                    break;
                }
                written += step;
            }
            if (!ok) {
                break;
            }
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        ok = amount == 0;
        break;
    }
    if (ok && fsync(output) != 0) {
        ok = false;
    }
    close(output);
    close(input);
    if (ok && rename(temporary, destination) != 0) {
        ok = false;
    }
    if (!ok) {
        unlink(temporary);
        return false;
    }
    (void)chown(destination, 0, 0);
    (void)chmod(destination, 0755);
    return true;
}

static bool read_record(const char *recordPath, const char *expectedHex,
                        int64_t bootSeconds, int64_t bootMicroseconds) {
    int descriptor = open(recordPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    char contents[1024];
    ssize_t amount = read(descriptor, contents, sizeof(contents) - 1U);
    close(descriptor);
    if (amount <= 0) {
        return false;
    }
    contents[amount] = '\0';
    char expected[256];
    int length = snprintf(expected, sizeof(expected),
                          "sha256=%s\nboot=%lld.%06lld\n", expectedHex,
                          (long long)bootSeconds, (long long)bootMicroseconds);
    return length > 0 && (size_t)length < sizeof(expected) &&
           strstr(contents, expected) != NULL;
}

/*
 * Payload dependencies: a resigned copy still loads its /var/jb dylibs from
 * their original locations, and package-installed libraries can carry
 * legacy-format signatures that iOS 27 rejects at load time.  Re-sign those
 * dependencies in place with a current ad-hoc CodeDirectory, keeping any
 * declared entitlements.  Baseline libraries whose cdhash is already covered
 * by the immutable Cryptex trust cache must never be re-signed in place, so
 * they are skipped via the deployed base-cdhashes manifest.
 */
#define CODEX_SIGNEXEC_MAX_DEPS 64U
#define CODEX_CDHASH_SIZE 20U
#define CODEX_CSMAGIC_CODEDIRECTORY 0xfade0c02U
#define CODEX_CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CODEX_CSSLOT_CODEDIRECTORY 0U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT 0x1005U

struct codex_blob_index {
    uint32_t type;
    uint32_t offset;
} __attribute__((packed));

struct codex_generic_blob {
    uint32_t magic;
    uint32_t length;
} __attribute__((packed));

struct codex_superblob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    struct codex_blob_index index[];
} __attribute__((packed));

struct codex_code_directory_prefix {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    uint32_t spare2;
} __attribute__((packed));

static const char *const kBaseCdhashesPath =
    "/var/jb/usr/share/codex-runtime-admission/base-cdhashes.txt";
static const char *const kLibraryRecordRoot =
    "/var/jb/var/lib/codex-signexec/libs";

static bool path_is_in_base_cdhashes(const uint8_t *cdhash) {
    int descriptor = open(kBaseCdhashesPath, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return true;
    }
    char hex[CODEX_CDHASH_SIZE * 2U + 1U];
    hex_encode(cdhash, CODEX_CDHASH_SIZE, hex);
    char buffer[65536];
    ssize_t amount = read(descriptor, buffer, sizeof(buffer) - 1U);
    close(descriptor);
    if (amount <= 0) {
        return true;
    }
    buffer[amount] = '\0';
    return strstr(buffer, hex) != NULL;
}

static bool slice_cdhash(const uint8_t *slice, size_t sliceSize,
                         uint8_t digest[CODEX_CDHASH_SIZE]) {
    if (sliceSize < sizeof(struct mach_header_64)) {
        return false;
    }
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)slice;
    if (header->magic != MH_MAGIC_64 ||
        header->sizeofcmds > sliceSize - sizeof(*header)) {
        return false;
    }
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *commandsEnd = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(commandsEnd - cursor) < sizeof(struct load_command)) {
            return false;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(commandsEnd - cursor)) {
            return false;
        }
        if (command->cmd == LC_CODE_SIGNATURE &&
            command->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *codesign =
                (const struct linkedit_data_command *)command;
            if (codesign->dataoff > sliceSize ||
                codesign->datasize > sliceSize - codesign->dataoff ||
                codesign->datasize <
                    sizeof(struct codex_generic_blob)) {
                return false;
            }
            const uint8_t *signature = slice + codesign->dataoff;
            const struct codex_generic_blob *generic =
                (const struct codex_generic_blob *)signature;
            uint32_t available = codesign->datasize;
            uint32_t magic = OSSwapBigToHostInt32(generic->magic);
            if (magic == CODEX_CSMAGIC_EMBEDDED_SIGNATURE &&
                available >= sizeof(struct codex_superblob)) {
                const struct codex_superblob *superblob =
                    (const struct codex_superblob *)signature;
                uint32_t count = OSSwapBigToHostInt32(superblob->count);
                for (uint32_t slot = 0; slot < count; ++slot) {
                    uint32_t type =
                        OSSwapBigToHostInt32(superblob->index[slot].type);
                    if (type != CODEX_CSSLOT_CODEDIRECTORY) {
                        continue;
                    }
                    uint32_t offset =
                        OSSwapBigToHostInt32(superblob->index[slot].offset);
                    if (offset >= available ||
                        available - offset <
                            sizeof(struct codex_code_directory_prefix)) {
                        continue;
                    }
                    const struct codex_code_directory_prefix *directory =
                        (const struct codex_code_directory_prefix *)(signature +
                                                                     offset);
                    uint32_t length =
                        OSSwapBigToHostInt32(directory->length);
                    if (OSSwapBigToHostInt32(directory->magic) !=
                            CODEX_CSMAGIC_CODEDIRECTORY ||
                        length > available - offset) {
                        continue;
                    }
                    if (directory->hashType == 2U ||
                        directory->hashType == 3U) {
                        CC_SHA256(signature + offset, (CC_LONG)length,
                                  digest);
                        return true;
                    }
                    if (directory->hashType == 1U) {
                        CC_SHA1(signature + offset, (CC_LONG)length, digest);
                        return true;
                    }
                }
            }
            return false;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static bool file_is_baseline_trusted(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return true;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || status.st_size <= 0 ||
        (uint64_t)status.st_size > 64 * 1024 * 1024) {
        close(descriptor);
        return true;
    }
    size_t size = (size_t)status.st_size;
    uint8_t *contents = malloc(size);
    if (contents == NULL) {
        close(descriptor);
        return true;
    }
    ssize_t amount = read(descriptor, contents, size);
    close(descriptor);
    if (amount != (ssize_t)size) {
        free(contents);
        return true;
    }
    uint8_t digest[CODEX_CDHASH_SIZE];
    bool trusted = true;
    uint32_t magic = size >= 4U ? *(const uint32_t *)contents : 0;
    if (magic == MH_MAGIC_64) {
        trusted = !slice_cdhash(contents, size, digest) ||
                  path_is_in_base_cdhashes(digest);
    } else if (magic == FAT_CIGAM) {
        /* Not expected for Procursus libraries; refuse to re-sign. */
        trusted = true;
    }
    free(contents);
    return trusted;
}

static size_t collect_dependencies(const char *path,
                                   char dependencies[][PATH_MAX],
                                   size_t capacity) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return 0;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || status.st_size <= 0 ||
        (uint64_t)status.st_size > 64 * 1024 * 1024) {
        close(descriptor);
        return 0;
    }
    size_t size = (size_t)status.st_size;
    uint8_t *contents = malloc(size);
    if (contents == NULL) {
        close(descriptor);
        return 0;
    }
    ssize_t amount = read(descriptor, contents, size);
    close(descriptor);
    if (amount != (ssize_t)size) {
        free(contents);
        return 0;
    }
    size_t count = 0;
    uint32_t magic = size >= 4U ? *(const uint32_t *)contents : 0;
    uint64_t sliceOffsets[8];
    uint32_t sliceSizes[8];
    size_t sliceCount = 0;
    if (magic == MH_MAGIC_64) {
        sliceOffsets[0] = 0;
        sliceSizes[0] = (uint32_t)size;
        sliceCount = 1;
    } else if (magic == FAT_CIGAM && size >= sizeof(struct fat_header)) {
        const struct fat_header *header = (const struct fat_header *)contents;
        uint32_t archCount = OSSwapBigToHostInt32(header->nfat_arch);
        if (archCount > 8U) {
            archCount = 8U;
        }
        for (uint32_t index = 0; index < archCount; ++index) {
            if (sizeof(struct fat_header) +
                    (index + 1U) * sizeof(struct fat_arch) > size) {
                break;
            }
            const struct fat_arch *arch =
                (const struct fat_arch *)(contents + sizeof(*header)) + index;
            uint64_t offset = OSSwapBigToHostInt32(arch->offset);
            uint64_t sliceSize = OSSwapBigToHostInt32(arch->size);
            if (offset < size && sliceSize <= size - offset) {
                sliceOffsets[sliceCount] = offset;
                sliceSizes[sliceCount] = (uint32_t)sliceSize;
                ++sliceCount;
            }
        }
    }
    for (size_t slice = 0; slice < sliceCount; ++slice) {
        const uint8_t *base = contents + sliceOffsets[slice];
        size_t sliceSize = sliceSizes[slice];
        if (sliceSize < sizeof(struct mach_header_64)) {
            continue;
        }
        const struct mach_header_64 *header =
            (const struct mach_header_64 *)base;
        if (header->magic != MH_MAGIC_64 ||
            header->sizeofcmds > sliceSize - sizeof(*header)) {
            continue;
        }
        const uint8_t *cursor = (const uint8_t *)(header + 1);
        const uint8_t *commandsEnd = cursor + header->sizeofcmds;
        for (uint32_t index = 0; index < header->ncmds; ++index) {
            if ((size_t)(commandsEnd - cursor) < sizeof(struct load_command)) {
                break;
            }
            const struct load_command *command =
                (const struct load_command *)cursor;
            if (command->cmdsize < sizeof(*command) ||
                command->cmdsize > (uint32_t)(commandsEnd - cursor)) {
                break;
            }
            if ((command->cmd == LC_LOAD_DYLIB ||
                 command->cmd == LC_LOAD_WEAK_DYLIB ||
                 command->cmd == LC_REEXPORT_DYLIB) &&
                command->cmdsize >= sizeof(struct dylib_command)) {
                const struct dylib_command *dylib =
                    (const struct dylib_command *)command;
                uint32_t nameOffset = dylib->dylib.name.offset;
                if (nameOffset < command->cmdsize) {
                    const char *name = (const char *)cursor + nameOffset;
                    size_t available = command->cmdsize - nameOffset;
                    size_t nameLength = strnlen(name, available);
                    if (nameLength > 0U && nameLength < available &&
                        nameLength < PATH_MAX && count < capacity) {
                        bool duplicate = false;
                        for (size_t existing = 0; existing < count;
                             ++existing) {
                            if (strcmp(dependencies[existing], name) == 0) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            memcpy(dependencies[count], name, nameLength + 1U);
                            ++count;
                        }
                    }
                }
            }
            cursor += command->cmdsize;
        }
    }
    free(contents);
    return count;
}

static bool resign_library_in_place(const char *resolved) {
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    CC_SHA256_Update(&context, resolved, (CC_LONG)strlen(resolved));
    uint8_t keyDigest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(keyDigest, &context);
    char keyHex[CC_SHA256_DIGEST_LENGTH * 2U + 1U];
    hex_encode(keyDigest, CC_SHA256_DIGEST_LENGTH, keyHex);

    char recordPath[PATH_MAX];
    int length = snprintf(recordPath, sizeof(recordPath), "%s/%s",
                          kLibraryRecordRoot, keyHex);
    if (length <= 0 || (size_t)length >= sizeof(recordPath)) {
        return false;
    }
    uint8_t contentDigest[CC_SHA256_DIGEST_LENGTH];
    if (!sha256_path(resolved, contentDigest)) {
        return false;
    }
    char currentHex[CC_SHA256_DIGEST_LENGTH * 2U + 1U];
    hex_encode(contentDigest, CC_SHA256_DIGEST_LENGTH, currentHex);
    int record = open(recordPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (record >= 0) {
        char stored[128];
        ssize_t storedLength = read(record, stored, sizeof(stored) - 1U);
        close(record);
        if (storedLength > 0) {
            stored[storedLength] = '\0';
            if (strncmp(stored, currentHex, 64U) == 0) {
                return true;
            }
        }
    }

    if (file_is_baseline_trusted(resolved)) {
        log_failure("dependency-baseline", resolved, 0);
        return true;
    }

    char entitlements[8192];
    char *extractArguments[] = {
        (char *)kLdidPath, (char *)"-e", (char *)resolved, NULL};
    entitlements[0] = '\0';
    (void)spawn_capture(kLdidPath, extractArguments, entitlements,
                        sizeof(entitlements));

    char staging[PATH_MAX];
    length = snprintf(staging, sizeof(staging), "%s.codex-sign.%d", resolved,
                      getpid());
    if (length <= 0 || (size_t)length >= sizeof(staging)) {
        return false;
    }
    if (!copy_file(resolved, staging)) {
        log_failure("dependency-copy", resolved, errno);
        return false;
    }
    char entitlementsPath[PATH_MAX] = {0};
    char signOption[PATH_MAX + 3U];
    const char *signArgument = "-S";
    if (strstr(entitlements, "<plist") != NULL) {
        length = snprintf(entitlementsPath, sizeof(entitlementsPath),
                          "%s.ents", staging);
        int entitlementsFile = open(entitlementsPath,
                                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                    0644);
        if (entitlementsFile >= 0) {
            size_t entitlementsLength = strlen(entitlements);
            bool written =
                write(entitlementsFile, entitlements, entitlementsLength) ==
                (ssize_t)entitlementsLength;
            close(entitlementsFile);
            if (written &&
                snprintf(signOption, sizeof(signOption), "-S%s",
                         entitlementsPath) > 0) {
                signArgument = signOption;
            }
        }
    }
    char *signArguments[] = {
        (char *)kLdidPath, (char *)signArgument, staging, NULL};
    int signResult = spawn_and_wait(kLdidPath, signArguments);
    if (entitlementsPath[0] != '\0') {
        unlink(entitlementsPath);
    }
    if (signResult != 0) {
        log_failure("dependency-sign", resolved, signResult);
        unlink(staging);
        return false;
    }
    if (rename(staging, resolved) != 0) {
        log_failure("dependency-install", resolved, errno);
        unlink(staging);
        return false;
    }
    uint8_t signedDigest[CC_SHA256_DIGEST_LENGTH];
    if (!sha256_path(resolved, signedDigest)) {
        return false;
    }
    char signedHex[CC_SHA256_DIGEST_LENGTH * 2U + 1U];
    hex_encode(signedDigest, CC_SHA256_DIGEST_LENGTH, signedHex);
    int recordOut = open(recordPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                         0644);
    if (recordOut >= 0) {
        (void)write(recordOut, signedHex, 64U);
        close(recordOut);
    }
    log_failure("dependency-resigned", resolved, 0);
    return true;
}

static bool resign_payload_dependencies(const char *copyPath) {
    static char dependencies[CODEX_SIGNEXEC_MAX_DEPS][PATH_MAX];
    size_t count = collect_dependencies(copyPath, dependencies,
                                        CODEX_SIGNEXEC_MAX_DEPS);
    if (count == 0U) {
        return true;
    }
    char managedRoot[PATH_MAX];
    if (realpath("/var/jb", managedRoot) == NULL) {
        return false;
    }
    if (mkdir("/var/jb/var/lib/codex-signexec", 0755) != 0 &&
        errno != EEXIST) {
        return false;
    }
    if (mkdir(kLibraryRecordRoot, 0755) != 0 && errno != EEXIST) {
        return false;
    }
    for (size_t index = 0; index < count; ++index) {
        const char *name = dependencies[index];
        char candidate[PATH_MAX];
        if (strncmp(name, "@rpath/", 7U) == 0) {
            int length = snprintf(candidate, sizeof(candidate),
                                  "/var/jb/usr/lib/%s", name + 7U);
            if (length <= 0 || (size_t)length >= sizeof(candidate)) {
                continue;
            }
        } else if (strncmp(name, "/var/jb/", 8U) == 0) {
            if (strlcpy(candidate, name, sizeof(candidate)) >=
                sizeof(candidate)) {
                continue;
            }
        } else {
            continue;
        }
        char resolved[PATH_MAX];
        struct stat status;
        if (realpath(candidate, resolved) == NULL ||
            !path_is_descendant(resolved, managedRoot) ||
            lstat(resolved, &status) != 0 || !S_ISREG(status.st_mode)) {
            continue;
        }
        int descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        uint32_t magic = 0;
        ssize_t amount = descriptor >= 0
                             ? read(descriptor, &magic, sizeof(magic))
                             : -1;
        if (descriptor >= 0) {
            close(descriptor);
        }
        if (amount != (ssize_t)sizeof(magic) ||
            (magic != MH_MAGIC_64 && magic != FAT_CIGAM)) {
            continue;
        }
        if (!resign_library_in_place(resolved)) {
            log_failure("dependencies", resolved, 0);
            return false;
        }
    }
    return true;
}

static bool write_record(const char *recordPath, const char *source,
                         const char *hex, int64_t bootSeconds,
                         int64_t bootMicroseconds) {
    char temporary[PATH_MAX];
    int length = snprintf(temporary, sizeof(temporary), "%s.tmp.%d",
                          recordPath, getpid());
    if (length <= 0 || (size_t)length >= sizeof(temporary)) {
        return false;
    }
    int descriptor = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          0644);
    if (descriptor < 0) {
        return false;
    }
    int written = dprintf(descriptor,
                          "source=%s\nsha256=%s\nboot=%lld.%06lld\n"
                          "signedAt=%lld\n",
                          source, hex, (long long)bootSeconds,
                          (long long)bootMicroseconds,
                          (long long)time(NULL));
    bool ok = written > 0 && fsync(descriptor) == 0;
    close(descriptor);
    if (ok && rename(temporary, recordPath) != 0) {
        ok = false;
    }
    if (!ok) {
        unlink(temporary);
    }
    return ok;
}

static bool sign_and_trust(const char *copyPath) {
    char entitlementsArgument[PATH_MAX + 3U];
    int length = snprintf(entitlementsArgument, sizeof(entitlementsArgument),
                          "-S%s", kPayloadEntitlementsPath);
    if (length <= 0 || (size_t)length >= sizeof(entitlementsArgument)) {
        return false;
    }
    char *signArguments[] = {
        (char *)kLdidPath, entitlementsArgument, (char *)copyPath, NULL};
    int result = spawn_and_wait(kLdidPath, signArguments);
    if (result != 0) {
        log_failure("sign", copyPath, result);
        return false;
    }
    char *trustArguments[] = {
        (char *)kRuntimeTrustPath, (char *)"trust", (char *)copyPath, NULL};
    result = spawn_and_wait(kRuntimeTrustPath, trustArguments);
    if (result != 0) {
        log_failure("trust", copyPath, result);
        return false;
    }
    return true;
}

/*
 * Copy a managed Mach-O into the content-addressed store, resign the copy
 * ad-hoc with the get-task-allow payload entitlements, and load a
 * personalized runtime trust cache covering its cdhash through the fixed
 * codex-runtime-trust helper.  The copy then executes as a real process while
 * remaining debugger-attachable.  Runtime trust-cache entries do not survive
 * a reboot, so the record pins the boot time and a later prepare re-trusts
 * the unchanged copy without re-signing it.
 */
static int prepare(const char *target, char copyPath[PATH_MAX]) {
    char resolved[PATH_MAX];
    if (!path_is_managed_macho(target, resolved)) {
        log_failure("validate", target, EINVAL);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    char runtimeTrustResolved[PATH_MAX];
    char ldidResolved[PATH_MAX];
    char workerResolved[PATH_MAX];
    if ((realpath(kRuntimeTrustPath, runtimeTrustResolved) != NULL &&
         strcmp(resolved, runtimeTrustResolved) == 0) ||
        (realpath(kLdidPath, ldidResolved) != NULL &&
         strcmp(resolved, ldidResolved) == 0) ||
        (realpath(kWorkerPath, workerResolved) != NULL &&
         strcmp(resolved, workerResolved) == 0)) {
        log_failure("validate-control-plane", resolved, EPERM);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    if (!sha256_path(resolved, digest)) {
        log_failure("hash", resolved, errno);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    char hex[CC_SHA256_DIGEST_LENGTH * 2U + 1U];
    hex_encode(digest, CC_SHA256_DIGEST_LENGTH, hex);

    int64_t bootSeconds = 0;
    int64_t bootMicroseconds = 0;
    if (!current_boot_time(&bootSeconds, &bootMicroseconds)) {
        log_failure("boottime", resolved, errno);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    if (worker_first_forced()) {
        log_failure("mode-worker-first", resolved, 0);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    if (trust_marked_unavailable(bootSeconds)) {
        log_failure("trust-unavailable-cached", resolved, 0);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }

    if (mkdir("/var/jb/var/lib/codex-signexec", 0755) != 0 && errno != EEXIST) {
        log_failure("store-root", resolved, errno);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    if (mkdir(kStoreRoot, 0755) != 0 && errno != EEXIST) {
        log_failure("store-root", resolved, errno);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    char storeDirectory[PATH_MAX];
    int length = snprintf(storeDirectory, sizeof(storeDirectory), "%s/%s",
                          kStoreRoot, hex);
    if (length <= 0 || (size_t)length >= sizeof(storeDirectory)) {
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    if (mkdir(storeDirectory, 0755) != 0 && errno != EEXIST) {
        log_failure("store-directory", resolved, errno);
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    const char *baseName = strrchr(resolved, '/');
    baseName = baseName != NULL ? baseName + 1 : resolved;
    length = snprintf(copyPath, PATH_MAX, "%s/%s", storeDirectory, baseName);
    if (length <= 0 || length >= PATH_MAX) {
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    char recordPath[PATH_MAX];
    length = snprintf(recordPath, sizeof(recordPath), "%s/record",
                      storeDirectory);
    if (length <= 0 || (size_t)length >= sizeof(recordPath)) {
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    char lockPath[PATH_MAX];
    length = snprintf(lockPath, sizeof(lockPath), "%s/lock", storeDirectory);
    if (length <= 0 || (size_t)length >= sizeof(lockPath)) {
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    int lock = open(lockPath, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (lock < 0 || flock(lock, LOCK_EX) != 0) {
        log_failure("lock", resolved, errno);
        if (lock >= 0) {
            close(lock);
        }
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }

    int result = 0;
    struct stat copyStatus;
    bool copyPresent = lstat(copyPath, &copyStatus) == 0 &&
                       S_ISREG(copyStatus.st_mode);
    bool trustedThisBoot = copyPresent &&
        read_record(recordPath, hex, bootSeconds, bootMicroseconds);
    if (trustedThisBoot) {
        goto finish;
    }
    if (!copyPresent) {
        if (!copy_file(resolved, copyPath)) {
            log_failure("copy", resolved, errno);
            result = CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
            goto finish;
        }
        if (!sign_and_trust(copyPath)) {
            unlink(copyPath);
            mark_trust_unavailable(bootSeconds);
            result = CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
            goto finish;
        }
        clear_trust_unavailable();
        if (!resign_payload_dependencies(copyPath)) {
            log_failure("dependencies", copyPath, 0);
            result = CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
            goto finish;
        }
    } else {
        /* Unchanged signed copy from an earlier boot: re-trust only. */
        char *trustArguments[] = {(char *)kRuntimeTrustPath, (char *)"trust",
                                  (char *)copyPath, NULL};
        int trustResult = spawn_and_wait(kRuntimeTrustPath, trustArguments);
        if (trustResult != 0) {
            log_failure("retrust", copyPath, trustResult);
            mark_trust_unavailable(bootSeconds);
            result = CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
            goto finish;
        }
        clear_trust_unavailable();
    }
    if (!write_record(recordPath, resolved, hex, bootSeconds,
                      bootMicroseconds)) {
        log_failure("record", resolved, errno);
        result = CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
        goto finish;
    }
    log_failure("prepared", copyPath, 0);

finish:
    flock(lock, LOCK_UN);
    close(lock);
    return result;
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fputs("codex-signexec requires uid 0\n", stderr);
        return 77;
    }
    if (argc >= 3 && strcmp(argv[1], "prepare") == 0 && argc == 3) {
        char copyPath[PATH_MAX] = {0};
        int result = prepare(argv[2], copyPath);
        if (result == 0) {
            dprintf(STDOUT_FILENO, "%s\n", copyPath);
        }
        return result;
    }
    if (argc >= 3 && strcmp(argv[1], "exec") == 0) {
        char copyPath[PATH_MAX] = {0};
        if (prepare(argv[2], copyPath) == 0) {
            if (getenv("DYLD_INSERT_LIBRARIES") == NULL) {
                setenv("DYLD_INSERT_LIBRARIES", kInterposerPath, 0);
            }
            char **childArguments = calloc((size_t)argc, sizeof(char *));
            if (childArguments == NULL) {
                return 75;
            }
            childArguments[0] = argv[2];
            for (int index = 3; index < argc; ++index) {
                childArguments[index - 2] = argv[index];
            }
            childArguments[argc - 2] = NULL;
            execv(copyPath, childArguments);
            log_failure("exec", copyPath, errno);
            return 75;
        }
        const char *marker = getenv("CODEX_RUNTIME_ADMISSION");
        if (marker != NULL && strcmp(marker, "debugged-worker-v1") == 0) {
            char **workerArguments = calloc((size_t)argc + 1U,
                                            sizeof(char *));
            if (workerArguments == NULL) {
                return 75;
            }
            workerArguments[0] = (char *)kWorkerPath;
            workerArguments[1] = (char *)"--macho";
            for (int index = 2; index < argc; ++index) {
                workerArguments[index] = argv[index];
            }
            workerArguments[argc] = NULL;
            execv(kWorkerPath, workerArguments);
            log_failure("worker-fallback", argv[2], errno);
        }
        return CODEX_SIGNEXEC_EXIT_PREPARE_FAILED;
    }
    fprintf(stderr, "usage: %s prepare <macho>\n       %s exec <macho> "
                    "[arguments...]\n", argv[0], argv[0]);
    return 64;
}
