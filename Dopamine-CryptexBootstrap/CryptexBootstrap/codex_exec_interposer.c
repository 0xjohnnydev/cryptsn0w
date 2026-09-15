#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <libkern/OSCacheControl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <pthread.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define CODEX_MAX_ARGUMENTS 1024U
#define CODEX_RUNTIME_MARKER "CODEX_RUNTIME_ADMISSION=debugged-worker-v1"
#define CODEX_MAX_BASE_CDHASHES 2048U
#define CODEX_CDHASH_SIZE 20U
#define CODEX_CSMAGIC_CODEDIRECTORY 0xfade0c02U
#define CODEX_CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CODEX_CSSLOT_CODEDIRECTORY 0U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT 0x1005U
#define CODEX_CS_HASHTYPE_SHA1 1U
#define CODEX_CS_HASHTYPE_SHA256 2U
#define CODEX_CS_HASHTYPE_SHA256_TRUNCATED 3U
#define CODEX_CS_HASHTYPE_SHA384 4U

static const char *const kWorkerPath =
    "/var/jb/usr/libexec/codex-exec-worker";
static const char *const kRuntimeTrustClientPath =
    "/var/jb/usr/libexec/codex-runtime-trust-client";
static const char *const kBaseCdhashesPath =
    "/var/jb/usr/share/codex-runtime-admission/base-cdhashes.txt";

struct codex_blob_index {
    uint32_t type;
    uint32_t offset;
} __attribute__((packed));

struct codex_superblob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    struct codex_blob_index index[];
} __attribute__((packed));

struct codex_generic_blob {
    uint32_t magic;
    uint32_t length;
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

typedef int (*execve_function)(const char *, char *const[], char *const[]);
typedef int (*posix_spawn_function)(
    pid_t *restrict, const char *restrict,
    const posix_spawn_file_actions_t *, const posix_spawnattr_t *restrict,
    char *const[restrict], char *const[restrict]);

/*
 * The public execve symbol can resolve to libiosexec when this dylib is a
 * pinned dependency of a Procursus executable.  Calling that result after
 * rebinding libiosexec's import would recurse back into codex_execve.  XNU's
 * libsyscall exports __execve with the same ABI as the public wrapper, so use
 * that syscall boundary directly.  The public spawn wrappers need to build an
 * internal _posix_spawn_args_desc first; resolve those from their defining
 * libsystem_kernel image rather than with RTLD_NEXT for the same reason.
 */
extern int __execve(const char *, char *const[], char *const[]);

extern kern_return_t mach_vm_region(
    vm_map_t targetTask, mach_vm_address_t *address, mach_vm_size_t *size,
    vm_region_flavor_t flavor, vm_region_info_t info,
    mach_msg_type_number_t *infoCount, mach_port_t *objectName);
extern kern_return_t mach_vm_protect(vm_map_t targetTask,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     boolean_t setMaximum,
                                     vm_prot_t protection);

static execve_function gOriginalExecve;
static posix_spawn_function gOriginalPosixSpawn;
static posix_spawn_function gOriginalPosixSpawnp;
static void *gLibsystemKernelHandle;
static __thread unsigned int gInterposeDepth;
static pthread_once_t gBaseCdhashesOnce = PTHREAD_ONCE_INIT;
static uint8_t gBaseCdhashes[CODEX_MAX_BASE_CDHASHES][CODEX_CDHASH_SIZE];
static size_t gBaseCdhashCount;
static bool gBaseCdhashesReady;

static void resolve_originals(void) {
    if (gOriginalExecve == NULL) {
        gOriginalExecve = __execve;
    }
    if (gLibsystemKernelHandle == NULL) {
        gLibsystemKernelHandle = dlopen(
            "/usr/lib/system/libsystem_kernel.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (gLibsystemKernelHandle == NULL) {
            gLibsystemKernelHandle = dlopen(
                "/usr/lib/libSystem.B.dylib", RTLD_LAZY | RTLD_LOCAL);
        }
    }
    if (gOriginalPosixSpawn == NULL && gLibsystemKernelHandle != NULL) {
        gOriginalPosixSpawn =
            (posix_spawn_function)dlsym(gLibsystemKernelHandle,
                                        "posix_spawn");
    }
    if (gOriginalPosixSpawnp == NULL && gLibsystemKernelHandle != NULL) {
        gOriginalPosixSpawnp =
            (posix_spawn_function)dlsym(gLibsystemKernelHandle,
                                        "posix_spawnp");
    }
}

static bool environment_is_admitted(char *const environment[]) {
    if (geteuid() != 0 || environment == NULL) {
        return false;
    }
    for (size_t index = 0; index < 4096U && environment[index] != NULL;
         ++index) {
        if (strcmp(environment[index], CODEX_RUNTIME_MARKER) == 0) {
            return true;
        }
    }
    return false;
}

static bool current_process_is_admitted(void) {
    const char *marker = getenv("CODEX_RUNTIME_ADMISSION");
    return geteuid() == 0 && marker != NULL &&
           strcmp(marker, "debugged-worker-v1") == 0;
}

static int hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static void load_base_cdhashes(void) {
    FILE *manifest = fopen(kBaseCdhashesPath, "r");
    if (manifest == NULL) {
        return;
    }
    char line[128];
    while (gBaseCdhashCount < CODEX_MAX_BASE_CDHASHES &&
           fgets(line, sizeof(line), manifest) != NULL) {
        size_t length = strcspn(line, "\r\n");
        if (length != CODEX_CDHASH_SIZE * 2U) {
            continue;
        }
        uint8_t parsed[CODEX_CDHASH_SIZE];
        bool valid = true;
        for (size_t index = 0; index < CODEX_CDHASH_SIZE; ++index) {
            int high = hex_nibble(line[index * 2U]);
            int low = hex_nibble(line[index * 2U + 1U]);
            if (high < 0 || low < 0) {
                valid = false;
                break;
            }
            parsed[index] = (uint8_t)((high << 4) | low);
        }
        if (valid) {
            memcpy(gBaseCdhashes[gBaseCdhashCount++], parsed,
                   sizeof(parsed));
        }
    }
    bool complete = !ferror(manifest) && !feof(manifest)
                        ? false
                        : gBaseCdhashCount != 0;
    fclose(manifest);
    gBaseCdhashesReady = complete;
}

static bool cdhash_is_in_baseline(const uint8_t hash[CODEX_CDHASH_SIZE]) {
    for (size_t index = 0; index < gBaseCdhashCount; ++index) {
        if (memcmp(gBaseCdhashes[index], hash, CODEX_CDHASH_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

static bool code_directory_is_in_baseline(const uint8_t *blob,
                                          size_t available) {
    if (available < sizeof(struct codex_code_directory_prefix)) {
        return false;
    }
    const struct codex_code_directory_prefix *directory =
        (const struct codex_code_directory_prefix *)blob;
    uint32_t length = OSSwapBigToHostInt32(directory->length);
    if (OSSwapBigToHostInt32(directory->magic) !=
            CODEX_CSMAGIC_CODEDIRECTORY ||
        length < sizeof(*directory) || length > available) {
        return false;
    }

    uint8_t digest[CC_SHA512_DIGEST_LENGTH] = {0};
    const uint8_t *result = NULL;
    switch (directory->hashType) {
        case CODEX_CS_HASHTYPE_SHA1:
            result = CC_SHA1(blob, (CC_LONG)length, digest);
            break;
        case CODEX_CS_HASHTYPE_SHA256:
        case CODEX_CS_HASHTYPE_SHA256_TRUNCATED:
            result = CC_SHA256(blob, (CC_LONG)length, digest);
            break;
        case CODEX_CS_HASHTYPE_SHA384:
            result = CC_SHA384(blob, (CC_LONG)length, digest);
            break;
        default:
            return false;
    }
    return result != NULL && cdhash_is_in_baseline(digest);
}

static bool signature_is_in_baseline(const uint8_t *signature,
                                     size_t available) {
    if (available < sizeof(struct codex_generic_blob)) {
        return false;
    }
    const struct codex_generic_blob *generic =
        (const struct codex_generic_blob *)signature;
    uint32_t magic = OSSwapBigToHostInt32(generic->magic);
    uint32_t length = OSSwapBigToHostInt32(generic->length);
    if (length > available) {
        return false;
    }
    if (magic == CODEX_CSMAGIC_CODEDIRECTORY) {
        return code_directory_is_in_baseline(signature, length);
    }
    if (magic != CODEX_CSMAGIC_EMBEDDED_SIGNATURE ||
        length < sizeof(struct codex_superblob)) {
        return false;
    }

    const struct codex_superblob *superblob =
        (const struct codex_superblob *)signature;
    uint32_t count = OSSwapBigToHostInt32(superblob->count);
    if (count > (length - sizeof(*superblob)) /
                    sizeof(struct codex_blob_index)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t type = OSSwapBigToHostInt32(superblob->index[index].type);
        if (type != CODEX_CSSLOT_CODEDIRECTORY &&
            (type < CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES ||
             type >= CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            continue;
        }
        uint32_t offset =
            OSSwapBigToHostInt32(superblob->index[index].offset);
        if (offset <= length &&
            code_directory_is_in_baseline(signature + offset,
                                          length - offset)) {
            return true;
        }
    }
    return false;
}

static bool macho_slice_is_in_baseline(const uint8_t *slice,
                                       size_t sliceSize) {
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
            if (codesign->dataoff <= sliceSize &&
                codesign->datasize <= sliceSize - codesign->dataoff) {
                return signature_is_in_baseline(
                    slice + codesign->dataoff, codesign->datasize);
            }
            return false;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static uint32_t fat_u32(uint32_t value, bool swapped) {
    return swapped ? OSSwapBigToHostInt32(value) : value;
}

static uint64_t fat_u64(uint64_t value, bool swapped) {
    return swapped ? OSSwapBigToHostInt64(value) : value;
}

static bool mapped_macho_is_in_baseline(const uint8_t *mapping,
                                        size_t size) {
    if (size < sizeof(uint32_t)) {
        return false;
    }
    uint32_t magic = *(const uint32_t *)mapping;
    if (magic == MH_MAGIC_64) {
        return macho_slice_is_in_baseline(mapping, size);
    }
    bool fat64 = false;
    bool swapped = false;
    if (magic == FAT_CIGAM) {
        swapped = true;
    } else if (magic == FAT_MAGIC) {
        swapped = false;
#ifdef FAT_CIGAM_64
    } else if (magic == FAT_CIGAM_64) {
        fat64 = true;
        swapped = true;
    } else if (magic == FAT_MAGIC_64) {
        fat64 = true;
        swapped = false;
#endif
    } else {
        return false;
    }
    if (size < sizeof(struct fat_header)) {
        return false;
    }
    const struct fat_header *header = (const struct fat_header *)mapping;
    uint32_t count = fat_u32(header->nfat_arch, swapped);
    if (count == 0 || count > 64) {
        return false;
    }
    if (fat64) {
#ifdef FAT_MAGIC_64
        size_t tableSize = sizeof(*header) +
                           (size_t)count * sizeof(struct fat_arch_64);
        if (tableSize > size) {
            return false;
        }
        const struct fat_arch_64 *architectures =
            (const struct fat_arch_64 *)(mapping + sizeof(*header));
        for (uint32_t index = 0; index < count; ++index) {
            uint64_t offset = fat_u64(architectures[index].offset, swapped);
            uint64_t sliceSize = fat_u64(architectures[index].size, swapped);
            if (offset <= size && sliceSize <= size - offset &&
                macho_slice_is_in_baseline(mapping + offset,
                                           (size_t)sliceSize)) {
                return true;
            }
        }
#endif
        return false;
    }
    size_t tableSize = sizeof(*header) +
                       (size_t)count * sizeof(struct fat_arch);
    if (tableSize > size) {
        return false;
    }
    const struct fat_arch *architectures =
        (const struct fat_arch *)(mapping + sizeof(*header));
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t offset = fat_u32(architectures[index].offset, swapped);
        uint32_t sliceSize = fat_u32(architectures[index].size, swapped);
        if (offset <= size && sliceSize <= size - offset &&
            macho_slice_is_in_baseline(mapping + offset, sliceSize)) {
            return true;
        }
    }
    return false;
}

static bool path_is_in_baseline(const char *resolved) {
    pthread_once(&gBaseCdhashesOnce, load_base_cdhashes);
    if (!gBaseCdhashesReady) {
        return true;
    }
    int descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        status.st_size <= 0 || (uint64_t)status.st_size > SIZE_MAX) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return false;
    }
    size_t size = (size_t)status.st_size;
    void *mapping = mmap(NULL, size, PROT_READ, MAP_PRIVATE, descriptor, 0);
    close(descriptor);
    if (mapping == MAP_FAILED) {
        return false;
    }
    bool trusted = mapped_macho_is_in_baseline(mapping, size);
    munmap(mapping, size);
    return trusted;
}

static bool path_is_descendant(const char *path, const char *root) {
    size_t rootLength = strlen(root);
    return rootLength > 1U && strncmp(path, root, rootLength) == 0 &&
           path[rootLength] == '/';
}

static bool path_is_managed_macho(const char *path,
                                  char resolvedOutput[PATH_MAX]) {
    char managedRoot[PATH_MAX];
    char resolved[PATH_MAX];
    char worker[PATH_MAX];
    struct stat status;
    if (path == NULL || path[0] != '/' ||
        realpath("/var/jb", managedRoot) == NULL ||
        realpath(path, resolved) == NULL ||
        !path_is_descendant(resolved, managedRoot) ||
        lstat(resolved, &status) != 0 || !S_ISREG(status.st_mode) ||
        access(resolved, X_OK) != 0 ||
        (realpath(kWorkerPath, worker) != NULL &&
         strcmp(resolved, worker) == 0)) {
        return false;
    }

    int descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    uint32_t magic = 0;
    ssize_t amount = descriptor >= 0 ? read(descriptor, &magic, sizeof(magic))
                                     : -1;
    if (descriptor >= 0) {
        close(descriptor);
    }
    bool macho = amount == (ssize_t)sizeof(magic) &&
                 (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
                  magic == FAT_MAGIC || magic == FAT_CIGAM
#ifdef FAT_MAGIC_64
                  || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64
#endif
                 );
    if (macho && resolvedOutput != NULL) {
        strlcpy(resolvedOutput, resolved, PATH_MAX);
    }
    return macho;
}

static bool path_is_fixed_control_plane(const char *resolved) {
    char runtimeTrustClient[PATH_MAX];
    return resolved != NULL &&
           realpath(kRuntimeTrustClientPath, runtimeTrustClient) != NULL &&
           strcmp(resolved, runtimeTrustClient) == 0;
}

static bool path_requires_worker(const char *path,
                                 char *const environment[]) {
    char resolved[PATH_MAX];
    return environment_is_admitted(environment) &&
           path_is_managed_macho(path, resolved) &&
           !path_is_fixed_control_plane(resolved) &&
           !path_is_in_baseline(resolved);
}

static bool admission_error(int error) {
    if (error == EACCES || error == EPERM || error == ENOEXEC) {
        return true;
    }
#ifdef EBADARCH
    if (error == EBADARCH) {
        return true;
    }
#endif
    return false;
}

static bool make_worker_arguments(const char *path, char *const arguments[],
                                  char *workerArguments[], size_t capacity) {
    if (path == NULL || arguments == NULL || arguments[0] == NULL ||
        capacity < 4U) {
        return false;
    }
    workerArguments[0] = (char *)kWorkerPath;
    workerArguments[1] = "--macho";
    workerArguments[2] = (char *)path;
    size_t output = 3U;
    for (size_t input = 1U;
         input < CODEX_MAX_ARGUMENTS && arguments[input] != NULL; ++input) {
        if (output + 1U >= capacity) {
            return false;
        }
        workerArguments[output++] = arguments[input];
    }
    workerArguments[output] = NULL;
    return output < capacity;
}

static int worker_execve(const char *path, char *const arguments[],
                         char *const environment[], const char *reason,
                         int directError) {
    char *workerArguments[CODEX_MAX_ARGUMENTS + 3U] = {0};
    if (!make_worker_arguments(path, arguments, workerArguments,
                               sizeof(workerArguments) /
                                   sizeof(workerArguments[0])) ||
        gOriginalExecve == NULL) {
        errno = directError != 0 ? directError : E2BIG;
        return -1;
    }
    dprintf(STDERR_FILENO,
            "codex-exec-interposer operation=execve path=%s "
            "reason=%s directError=%s backend=debugged-worker\n",
            path, reason, directError != 0 ? strerror(directError) : "none");
    ++gInterposeDepth;
    int result = gOriginalExecve(kWorkerPath, workerArguments, environment);
    int workerError = errno;
    --gInterposeDepth;
    errno = workerError;
    return result;
}

static int worker_spawn(posix_spawn_function function, pid_t *restrict pid,
                        const char *restrict path,
                        const posix_spawn_file_actions_t *actions,
                        const posix_spawnattr_t *restrict attributes,
                        char *const arguments[restrict],
                        char *const environment[restrict],
                        const char *reason, int directError,
                        const char *operation) {
    if (function == NULL) {
        return directError != 0 ? directError : ENOSYS;
    }
    char *workerArguments[CODEX_MAX_ARGUMENTS + 3U] = {0};
    if (!make_worker_arguments(path, arguments, workerArguments,
                               sizeof(workerArguments) /
                                   sizeof(workerArguments[0]))) {
        return directError != 0 ? directError : E2BIG;
    }
    dprintf(STDERR_FILENO,
            "codex-exec-interposer operation=%s path=%s "
            "reason=%s directError=%s backend=debugged-worker\n",
            operation, path, reason,
            directError != 0 ? strerror(directError) : "none");
    ++gInterposeDepth;
    int result = function(pid, kWorkerPath, actions, attributes,
                          workerArguments, environment);
    --gInterposeDepth;
    return result;
}

static int fallback_execve(const char *path, char *const arguments[],
                           char *const environment[], int directError) {
    if (!admission_error(directError) ||
        !environment_is_admitted(environment) ||
        !path_is_managed_macho(path, NULL)) {
        errno = directError;
        return -1;
    }
    return worker_execve(path, arguments, environment, "direct-admission",
                         directError);
}

static int fallback_spawn(posix_spawn_function function, pid_t *restrict pid,
                          const char *restrict path,
                          const posix_spawn_file_actions_t *actions,
                          const posix_spawnattr_t *restrict attributes,
                          char *const arguments[restrict],
                          char *const environment[restrict], int directError,
                          const char *operation) {
    if (!admission_error(directError) ||
        !environment_is_admitted(environment) ||
        !path_is_managed_macho(path, NULL)) {
        return directError;
    }
    return worker_spawn(function, pid, path, actions, attributes, arguments,
                        environment, "direct-admission", directError,
                        operation);
}

static const char *environment_value(char *const environment[],
                                     const char *name) {
    if (environment == NULL || name == NULL) {
        return NULL;
    }
    size_t length = strlen(name);
    for (size_t index = 0; index < 4096U && environment[index] != NULL;
         ++index) {
        if (strncmp(environment[index], name, length) == 0 &&
            environment[index][length] == '=') {
            return environment[index] + length + 1U;
        }
    }
    return NULL;
}

static bool resolve_search_path(const char *file, char *const environment[],
                                char resolved[PATH_MAX]) {
    if (file == NULL || file[0] == '\0') {
        return false;
    }
    if (strchr(file, '/') != NULL) {
        return realpath(file, resolved) != NULL;
    }
    const char *search = environment_value(environment, "PATH");
    if (search == NULL || search[0] == '\0') {
        search = "/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:"
                 "/usr/bin:/bin:/usr/sbin:/sbin";
    }
    const char *cursor = search;
    while (true) {
        const char *separator = strchr(cursor, ':');
        size_t directoryLength = separator != NULL
                                     ? (size_t)(separator - cursor)
                                     : strlen(cursor);
        const char *directory = cursor;
        if (directoryLength == 0U) {
            directory = ".";
            directoryLength = 1U;
        }
        int length = snprintf(resolved, PATH_MAX, "%.*s/%s",
                              (int)directoryLength, directory, file);
        if (length > 0 && length < PATH_MAX && access(resolved, X_OK) == 0) {
            char canonical[PATH_MAX];
            if (realpath(resolved, canonical) != NULL) {
                strlcpy(resolved, canonical, PATH_MAX);
                return true;
            }
        }
        if (separator == NULL) {
            break;
        }
        cursor = separator + 1U;
    }
    return false;
}

static int codex_execve(const char *path, char *const arguments[],
                        char *const environment[]) {
    resolve_originals();
    if (gOriginalExecve == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (gInterposeDepth != 0U) {
        return gOriginalExecve(path, arguments, environment);
    }
    if (path_requires_worker(path, environment)) {
        return worker_execve(path, arguments, environment,
                             "cdhash-not-in-baseline", 0);
    }
    ++gInterposeDepth;
    int result = gOriginalExecve(path, arguments, environment);
    int directError = errno;
    --gInterposeDepth;
    return result == -1
               ? fallback_execve(path, arguments, environment, directError)
               : result;
}

static int codex_posix_spawn(
    pid_t *restrict pid, const char *restrict path,
    const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *restrict attributes,
    char *const arguments[restrict], char *const environment[restrict]) {
    resolve_originals();
    if (gOriginalPosixSpawn == NULL) {
        return ENOSYS;
    }
    if (gInterposeDepth != 0U) {
        return gOriginalPosixSpawn(pid, path, actions, attributes, arguments,
                                   environment);
    }
    if (path_requires_worker(path, environment)) {
        return worker_spawn(gOriginalPosixSpawn, pid, path, actions,
                            attributes, arguments, environment,
                            "cdhash-not-in-baseline", 0, "posix_spawn");
    }
    ++gInterposeDepth;
    int result = gOriginalPosixSpawn(pid, path, actions, attributes, arguments,
                                     environment);
    --gInterposeDepth;
    return result == 0
               ? 0
               : fallback_spawn(gOriginalPosixSpawn, pid, path, actions,
                                attributes, arguments, environment, result,
                                "posix_spawn");
}

static int codex_posix_spawnp(
    pid_t *restrict pid, const char *restrict file,
    const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *restrict attributes,
    char *const arguments[restrict], char *const environment[restrict]) {
    resolve_originals();
    if (gOriginalPosixSpawnp == NULL) {
        return ENOSYS;
    }
    if (gInterposeDepth != 0U) {
        return gOriginalPosixSpawnp(pid, file, actions, attributes, arguments,
                                    environment);
    }
    char path[PATH_MAX];
    if (environment_is_admitted(environment) &&
        resolve_search_path(file, environment, path) &&
        path_requires_worker(path, environment)) {
        return worker_spawn(gOriginalPosixSpawn, pid, path, actions,
                            attributes, arguments, environment,
                            "cdhash-not-in-baseline", 0, "posix_spawnp");
    }
    ++gInterposeDepth;
    int result = gOriginalPosixSpawnp(pid, file, actions, attributes, arguments,
                                      environment);
    --gInterposeDepth;
    if (result == 0 || !admission_error(result) ||
        !environment_is_admitted(environment)) {
        return result;
    }
    if (!resolve_search_path(file, environment, path)) {
        return result;
    }
    return fallback_spawn(gOriginalPosixSpawn, pid, path, actions, attributes,
                          arguments, environment, result, "posix_spawnp");
}

/*
 * Procursus links its command-line tools to libiosexec, whose ie_exec* and
 * ie_posix_spawn* entry points eventually call libc through that dylib's own
 * lazy/non-lazy symbol pointers.  AMFI can allow an inserted library while
 * disabling dyld's __interpose processing for a platformized executable, so
 * the ordinary interpose tuples below are not sufficient for dash/dpkg.
 *
 * Rebind only libiosexec's three libc boundaries.  This preserves all of
 * libiosexec's shebang and root-prefix behavior while sending the final image
 * admission decision through the same bounded worker policy above.
 */
struct codex_rebind_target {
    const char *name;
    void *replacement;
    unsigned int count;
};

static bool write_rebound_pointer(void **slot, void *replacement) {
    mach_vm_address_t regionAddress = (mach_vm_address_t)(uintptr_t)slot;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objectName = MACH_PORT_NULL;
    kern_return_t regionResult = mach_vm_region(
        mach_task_self(), &regionAddress, &regionSize,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCount,
        &objectName);
    if (objectName != MACH_PORT_NULL) {
        (void)mach_port_deallocate(mach_task_self(), objectName);
    }
    if (regionResult != KERN_SUCCESS) {
        return false;
    }

    mach_vm_size_t pageSize = (mach_vm_size_t)getpagesize();
    mach_vm_address_t page =
        (mach_vm_address_t)((uintptr_t)slot & ~(uintptr_t)(pageSize - 1U));
    kern_return_t writeResult = mach_vm_protect(
        mach_task_self(), page, pageSize, false,
        info.protection | VM_PROT_WRITE | VM_PROT_COPY);
    if (writeResult != KERN_SUCCESS) {
        return false;
    }
    __atomic_store_n(slot, replacement, __ATOMIC_RELEASE);
    kern_return_t restoreResult = mach_vm_protect(
        mach_task_self(), page, pageSize, false, info.protection);
    return restoreResult == KERN_SUCCESS;
}

static void rebind_pointer_section(
    const struct section_64 *section, intptr_t slide,
    const struct nlist_64 *symbols, const char *strings, uint32_t stringSize,
    const uint32_t *indirectSymbols, uint32_t indirectSymbolCount,
    struct codex_rebind_target targets[], size_t targetCount) {
    size_t pointerCount = (size_t)(section->size / sizeof(void *));
    if (section->reserved1 > indirectSymbolCount ||
        pointerCount > indirectSymbolCount - section->reserved1) {
        return;
    }
    void **pointers = (void **)(uintptr_t)(slide + section->addr);
    for (size_t pointerIndex = 0; pointerIndex < pointerCount;
         ++pointerIndex) {
        uint32_t symbolIndex =
            indirectSymbols[section->reserved1 + pointerIndex];
        if ((symbolIndex & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) !=
            0) {
            continue;
        }
        uint32_t stringIndex = symbols[symbolIndex].n_un.n_strx;
        if (stringIndex >= stringSize) {
            continue;
        }
        const char *symbolName = strings + stringIndex;
        if (symbolName[0] == '_') {
            ++symbolName;
        }
        for (size_t targetIndex = 0; targetIndex < targetCount;
             ++targetIndex) {
            if (targets[targetIndex].replacement != NULL &&
                strcmp(symbolName, targets[targetIndex].name) == 0 &&
                write_rebound_pointer(&pointers[pointerIndex],
                                      targets[targetIndex].replacement)) {
                ++targets[targetIndex].count;
            }
        }
    }
}

static void rebind_libiosexec_image(
    const struct mach_header_64 *header, intptr_t slide,
    struct codex_rebind_target targets[], size_t targetCount) {
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return;
    }
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;
    const struct segment_command_64 *linkedit = NULL;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *commandsEnd = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(commandsEnd - cursor) < sizeof(struct load_command)) {
            return;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(commandsEnd - cursor)) {
            return;
        }
        if (command->cmd == LC_SYMTAB &&
            command->cmdsize >= sizeof(struct symtab_command)) {
            symtab = (const struct symtab_command *)command;
        } else if (command->cmd == LC_DYSYMTAB &&
                   command->cmdsize >= sizeof(struct dysymtab_command)) {
            dysymtab = (const struct dysymtab_command *)command;
        } else if (command->cmd == LC_SEGMENT_64 &&
                   command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_LINKEDIT,
                        sizeof(segment->segname)) == 0) {
                linkedit = segment;
            }
        }
        cursor += command->cmdsize;
    }
    if (symtab == NULL || dysymtab == NULL || linkedit == NULL) {
        return;
    }

    uintptr_t linkeditBase =
        (uintptr_t)(slide + (intptr_t)linkedit->vmaddr -
                    (intptr_t)linkedit->fileoff);
    const struct nlist_64 *symbols =
        (const struct nlist_64 *)(linkeditBase + symtab->symoff);
    const char *strings = (const char *)(linkeditBase + symtab->stroff);
    const uint32_t *indirectSymbols =
        (const uint32_t *)(linkeditBase + dysymtab->indirectsymoff);

    cursor = (const uint8_t *)(header + 1);
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            size_t sectionBytes =
                (size_t)segment->nsects * sizeof(struct section_64);
            if (sectionBytes <= command->cmdsize - sizeof(*segment)) {
                const struct section_64 *sections =
                    (const struct section_64 *)(segment + 1);
                for (uint32_t sectionIndex = 0;
                     sectionIndex < segment->nsects; ++sectionIndex) {
                    uint32_t type = sections[sectionIndex].flags & SECTION_TYPE;
                    if (type == S_LAZY_SYMBOL_POINTERS ||
                        type == S_NON_LAZY_SYMBOL_POINTERS) {
                        rebind_pointer_section(
                            &sections[sectionIndex], slide, symbols, strings,
                            symtab->strsize, indirectSymbols,
                            dysymtab->nindirectsyms, targets, targetCount);
                    }
                }
            }
        }
        cursor += command->cmdsize;
    }
}

static void install_libiosexec_rebindings(void) {
    struct codex_rebind_target targets[] = {
        {.name = "execve", .replacement = (void *)codex_execve},
        {.name = "posix_spawn",
         .replacement = gOriginalPosixSpawn != NULL
                            ? (void *)codex_posix_spawn
                            : NULL},
        {.name = "posix_spawnp",
         .replacement = gOriginalPosixSpawnp != NULL
                            ? (void *)codex_posix_spawnp
                            : NULL},
    };
    uint32_t imageCount = _dyld_image_count();
    unsigned int matchedImages = 0;
    for (uint32_t index = 0; index < imageCount; ++index) {
        const char *name = _dyld_get_image_name(index);
        if (name == NULL || strstr(name, "libiosexec.1.dylib") == NULL) {
            continue;
        }
        ++matchedImages;
        rebind_libiosexec_image(
            (const struct mach_header_64 *)_dyld_get_image_header(index),
            _dyld_get_image_vmaddr_slide(index), targets,
            sizeof(targets) / sizeof(targets[0]));
    }
    dprintf(STDERR_FILENO,
            "codex-exec-interposer pid=%d phase=libiosexec-rebind "
            "images=%u execve=%u posix_spawn=%u posix_spawnp=%u\n",
            getpid(), matchedImages, targets[0].count, targets[1].count,
            targets[2].count);
}

/*
 * A fixed, trust-cached copy of this dylib is also injected ahead of ElleKit's
 * loader.  The root helper patches dyld's two private syscall boundaries to
 * branch to these exports.  Keep the bypass process-local and limited to file
 * descriptors whose canonical path is beneath /var/jb: system images and all
 * other mappings retain their normal AMFI and library-validation behavior.
 */
static bool descriptor_is_in_jailbreak_root(int descriptor) {
    char descriptorPath[PATH_MAX];
    char managedRoot[PATH_MAX];
    char resolvedPath[PATH_MAX];
    return descriptor >= 0 &&
           fcntl(descriptor, F_GETPATH, descriptorPath) == 0 &&
           realpath("/var/jb", managedRoot) != NULL &&
           realpath(descriptorPath, resolvedPath) != NULL &&
           path_is_descendant(resolvedPath, managedRoot);
}

static unsigned int gTweakAnonymousExecutableMappings;
static unsigned int gTweakSignatureBypasses;

__attribute__((noinline, visibility("default"))) void *
codex_tweak_dyld_mmap(void *address, size_t length, int protection, int flags,
                      int descriptor, off_t offset) {
    void *mapping = mmap(address, length, protection, flags, descriptor,
                         offset);
    if (mapping != MAP_FAILED || descriptor < 0 ||
        (protection & PROT_EXEC) == 0 ||
        !descriptor_is_in_jailbreak_root(descriptor)) {
        return mapping;
    }

    int originalError = errno;
    int anonymousFlags = MAP_PRIVATE | MAP_ANON;
    if ((flags & MAP_FIXED) != 0) {
        anonymousFlags |= MAP_FIXED;
    }
    mapping = mmap(address, length, PROT_READ | PROT_WRITE, anonymousFlags,
                   -1, 0);
    if (mapping == MAP_FAILED) {
        return MAP_FAILED;
    }

    size_t copied = 0;
    while (copied < length) {
        ssize_t amount = pread(descriptor, (uint8_t *)mapping + copied,
                               length - copied, offset + (off_t)copied);
        if (amount > 0) {
            copied += (size_t)amount;
            continue;
        }
        if (amount == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        int savedError = errno;
        munmap(mapping, length);
        errno = savedError;
        return MAP_FAILED;
    }
    if (mprotect(mapping, length, protection) != 0) {
        int savedError = errno;
        munmap(mapping, length);
        errno = savedError;
        return MAP_FAILED;
    }
    __atomic_add_fetch(&gTweakAnonymousExecutableMappings, 1U,
                       __ATOMIC_RELAXED);
    errno = originalError;
    return mapping;
}

__attribute__((noinline, visibility("default"))) int
codex_tweak_dyld_fcntl(int descriptor, int command, void *parameter) {
    if (descriptor_is_in_jailbreak_root(descriptor)) {
        if (command == F_ADDFILESIGS_RETURN) {
            fsignatures_t *signature = (fsignatures_t *)parameter;
            if (signature != NULL) {
                signature->fs_file_start = (off_t)UINT64_MAX;
            }
            __atomic_add_fetch(&gTweakSignatureBypasses, 1U,
                               __ATOMIC_RELAXED);
            return 0;
        }
        if (command == F_CHECK_LV) {
            __atomic_add_fetch(&gTweakSignatureBypasses, 1U,
                               __ATOMIC_RELAXED);
            return 0;
        }
    }
    return fcntl(descriptor, command, parameter);
}

__attribute__((noinline, visibility("default"))) uint64_t
codex_tweak_admission_status(void) {
    uint64_t mappings = __atomic_load_n(&gTweakAnonymousExecutableMappings,
                                        __ATOMIC_RELAXED);
    uint64_t signatures =
        __atomic_load_n(&gTweakSignatureBypasses, __ATOMIC_RELAXED);
    return (signatures << 32U) | mappings;
}

__attribute__((constructor)) static void codex_exec_interposer_start(void) {
    resolve_originals();
    if (current_process_is_admitted()) {
        install_libiosexec_rebindings();
    }
}

#define CODEX_DYLD_INTERPOSE(replacement, replacee)                         \
    __attribute__((used)) static struct {                                   \
        const void *replacement;                                            \
        const void *replacee;                                               \
    } _codex_interpose_##replacee                                           \
        __attribute__((section("__DATA,__interpose"))) = {                 \
            (const void *)(uintptr_t)&replacement,                          \
            (const void *)(uintptr_t)&replacee,                             \
        }

CODEX_DYLD_INTERPOSE(codex_execve, execve);
CODEX_DYLD_INTERPOSE(codex_posix_spawn, posix_spawn);
CODEX_DYLD_INTERPOSE(codex_posix_spawnp, posix_spawnp);
