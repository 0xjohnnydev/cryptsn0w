#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* sys/ptrace.h is not part of the public iPhoneOS SDK. */
#define PT_DETACH 11
#define PT_ATTACHEXC 14

#define CODEX_CS_OPS_STATUS 0
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_MAX_PAYLOAD (16U * 1024U * 1024U)
#define CODEX_WAIT_ATTEMPTS 500U
#define CODEX_WAIT_DELAY_USEC (10U * 1000U)
#define CODEX_HANDSHAKE_TIMEOUT_SECONDS 15U

#define CODEX_CSMAGIC_CODEDIRECTORY 0xfade0c02U
#define CODEX_CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CODEX_CSMAGIC_REQUIREMENTS 0xfade0c01U
#define CODEX_CSMAGIC_BLOBWRAPPER 0xfade0b01U
#define CODEX_CSSLOT_CODEDIRECTORY 0U
#define CODEX_CSSLOT_REQUIREMENTS 2U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT 0x1005U
#define CODEX_CSSLOT_SIGNATURE 0x10000U
#define CODEX_CS_HASHTYPE_SHA1 1U
#define CODEX_CS_HASHTYPE_SHA256 2U
#define CODEX_CS_HASHTYPE_SHA256_TRUNCATED 3U
#define CODEX_CS_HASHTYPE_SHA384 4U
#define CODEX_CS_SUPPORTSCODELIMIT64 0x20300U
#define CODEX_CS_SUPPORTSEXECSEG 0x20400U
#define CODEX_CS_ADHOC 0x00000002U
#define CODEX_CS_EXECSEG_MAIN_BINARY 0x00000001U

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

struct codex_requirements_blob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
} __attribute__((packed));

struct codex_code_directory {
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
    uint32_t scatterOffset;
    uint32_t teamOffset;
    uint32_t spare3;
    uint64_t codeLimit64;
    uint64_t execSegBase;
    uint64_t execSegLimit;
    uint64_t execSegFlags;
} __attribute__((packed));

extern char **environ;
extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int ptrace(int request, pid_t pid, caddr_t address, int data);
extern kern_return_t mach_vm_protect(vm_map_t target,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     boolean_t setMaximum,
                                     vm_prot_t protection);
struct codex_child_report {
    int32_t status;
};

struct codex_parent_reply {
    int32_t status;
};

static volatile sig_atomic_t gOwnedChild = -1;

static bool write_all(int descriptor, const void *buffer, size_t size) {
    const uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = write(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return true;
}

static bool read_all(int descriptor, void *buffer, size_t size) {
    uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = read(descriptor, cursor, size);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return false;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return true;
}

static bool path_is_descendant(const char *path, const char *root) {
    size_t rootLength = strlen(root);
    return rootLength > 1 && strncmp(path, root, rootLength) == 0 &&
           path[rootLength] == '/';
}

static bool path_is_managed(const char *path, char resolved[PATH_MAX]) {
    char managedRoot[PATH_MAX];
    if (path == NULL || path[0] != '/' ||
        realpath("/var/jb", managedRoot) == NULL ||
        realpath(path, resolved) == NULL) {
        return false;
    }
    struct stat status;
    return path_is_descendant(resolved, managedRoot) &&
           lstat(resolved, &status) == 0 && S_ISREG(status.st_mode) &&
           status.st_size > 0 &&
           (uint64_t)status.st_size <= (uint64_t)CODEX_MAX_PAYLOAD * 16U;
}

static bool copy_file_exclusive(const char *source, const char *destination) {
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int output = open(destination,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                      0700);
    bool copied = input >= 0 && output >= 0;
    uint8_t buffer[64 * 1024];
    while (copied) {
        ssize_t amount;
        do {
            amount = read(input, buffer, sizeof(buffer));
        } while (amount < 0 && errno == EINTR);
        if (amount < 0) {
            copied = false;
            break;
        }
        if (amount == 0) {
            break;
        }
        copied = write_all(output, buffer, (size_t)amount);
    }
    if (copied) {
        copied = fsync(output) == 0;
    }
    int savedError = errno;
    if (input >= 0) {
        close(input);
    }
    if (output >= 0) {
        close(output);
    }
    if (!copied) {
        unlink(destination);
        errno = savedError;
    }
    return copied;
}

static bool digest_page(uint8_t hashType, const uint8_t *bytes, size_t size,
                        uint8_t digest[CC_SHA512_DIGEST_LENGTH],
                        size_t *digestSize) {
    if (size > UINT32_MAX) {
        return false;
    }
    switch (hashType) {
        case CODEX_CS_HASHTYPE_SHA1:
            *digestSize = CC_SHA1_DIGEST_LENGTH;
            return CC_SHA1(bytes, (CC_LONG)size, digest) != NULL;
        case CODEX_CS_HASHTYPE_SHA256:
        case CODEX_CS_HASHTYPE_SHA256_TRUNCATED:
            *digestSize = CC_SHA256_DIGEST_LENGTH;
            return CC_SHA256(bytes, (CC_LONG)size, digest) != NULL;
        case CODEX_CS_HASHTYPE_SHA384:
            *digestSize = CC_SHA384_DIGEST_LENGTH;
            return CC_SHA384(bytes, (CC_LONG)size, digest) != NULL;
        default:
            return false;
    }
}

static bool rehash_code_directory(uint8_t *slice, size_t sliceSize,
                                  uint8_t *blob, size_t blobAvailable,
                                  const uint8_t *requirements,
                                  size_t requirementsSize) {
    if (blobAvailable < sizeof(struct codex_code_directory)) {
        return false;
    }
    struct codex_code_directory *directory =
        (struct codex_code_directory *)blob;
    uint32_t blobLength = OSSwapBigToHostInt32(directory->length);
    uint32_t version = OSSwapBigToHostInt32(directory->version);
    uint32_t hashOffset = OSSwapBigToHostInt32(directory->hashOffset);
    uint32_t specialSlots =
        OSSwapBigToHostInt32(directory->nSpecialSlots);
    uint32_t codeSlots = OSSwapBigToHostInt32(directory->nCodeSlots);
    uint64_t codeLimit = OSSwapBigToHostInt32(directory->codeLimit);
    if (OSSwapBigToHostInt32(directory->magic) !=
            CODEX_CSMAGIC_CODEDIRECTORY ||
        blobLength > blobAvailable || hashOffset > blobLength ||
        directory->hashSize == 0) {
        return false;
    }
    uint64_t specialHashesSize =
        (uint64_t)specialSlots * directory->hashSize;
    if (specialHashesSize > hashOffset) {
        return false;
    }
    if (version >= CODEX_CS_SUPPORTSCODELIMIT64 && codeLimit == UINT32_MAX) {
        codeLimit = OSSwapBigToHostInt64(directory->codeLimit64);
    }
    uint32_t flags = OSSwapBigToHostInt32(directory->flags);
    directory->flags = OSSwapHostToBigInt32(flags | CODEX_CS_ADHOC);
    if (version >= CODEX_CS_SUPPORTSEXECSEG) {
        uint64_t execFlags = OSSwapBigToHostInt64(directory->execSegFlags);
        directory->execSegFlags = OSSwapHostToBigInt64(
            execFlags & ~(uint64_t)CODEX_CS_EXECSEG_MAIN_BINARY);
    }
    if (codeLimit > sliceSize || directory->pageSize >= 63) {
        return false;
    }
    size_t nativePageSize = (size_t)getpagesize();
    if (nativePageSize != 0 &&
        (nativePageSize & (nativePageSize - 1U)) == 0) {
        uint8_t nativeShift = 0;
        for (size_t value = nativePageSize; value > 1U; value >>= 1U) {
            ++nativeShift;
        }
        uint64_t nativeSlots =
            (codeLimit + nativePageSize - 1U) / nativePageSize;
        uint64_t availableSlots =
            (blobLength - hashOffset) / directory->hashSize;
        if (nativeSlots != 0 && nativeSlots <= availableSlots &&
            nativeSlots <= UINT32_MAX) {
            directory->pageSize = nativeShift;
            directory->nCodeSlots = OSSwapHostToBigInt32(
                (uint32_t)nativeSlots);
            codeSlots = (uint32_t)nativeSlots;
        }
    }
    uint64_t pageSize = directory->pageSize == 0
                            ? codeLimit
                            : UINT64_C(1) << directory->pageSize;
    if (pageSize == 0) {
        return false;
    }
    uint64_t expectedSlots = (codeLimit + pageSize - 1U) / pageSize;
    uint64_t hashesSize = (uint64_t)codeSlots * directory->hashSize;
    if (expectedSlots != codeSlots || hashesSize > blobLength - hashOffset) {
        return false;
    }

    uint8_t *hashes = blob + hashOffset;
    if (requirements != NULL && requirementsSize != 0 &&
        specialSlots >= CODEX_CSSLOT_REQUIREMENTS) {
        uint8_t digest[CC_SHA512_DIGEST_LENGTH] = {0};
        size_t digestSize = 0;
        if (!digest_page(directory->hashType, requirements,
                         requirementsSize, digest, &digestSize) ||
            directory->hashSize > digestSize) {
            return false;
        }
        memcpy(hashes - CODEX_CSSLOT_REQUIREMENTS * directory->hashSize,
               digest, directory->hashSize);
    }
    for (uint32_t slot = 0; slot < codeSlots; ++slot) {
        uint64_t offset = (uint64_t)slot * pageSize;
        size_t amount = (size_t)((codeLimit - offset) < pageSize
                                     ? (codeLimit - offset)
                                     : pageSize);
        uint8_t digest[CC_SHA512_DIGEST_LENGTH] = {0};
        size_t digestSize = 0;
        if (!digest_page(directory->hashType, slice + offset, amount, digest,
                         &digestSize) ||
            directory->hashSize > digestSize) {
            return false;
        }
        memcpy(hashes + (size_t)slot * directory->hashSize, digest,
               directory->hashSize);
    }
    return true;
}

static bool rehash_execute_slice(uint8_t *slice, size_t sliceSize) {
    if (sliceSize < sizeof(struct mach_header_64)) {
        return false;
    }
    struct mach_header_64 *header = (struct mach_header_64 *)slice;
    if (header->magic != MH_MAGIC_64 ||
        header->sizeofcmds > sliceSize - sizeof(*header)) {
        return false;
    }

    struct linkedit_data_command *signature = NULL;
    uint8_t *cursor = (uint8_t *)(header + 1);
    uint8_t *commandsEnd = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(commandsEnd - cursor) < sizeof(struct load_command)) {
            return false;
        }
        struct load_command *command = (struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(commandsEnd - cursor)) {
            return false;
        }
        if (command->cmd == LC_CODE_SIGNATURE &&
            command->cmdsize >= sizeof(struct linkedit_data_command)) {
            signature = (struct linkedit_data_command *)command;
        }
        cursor += command->cmdsize;
    }
    if (signature == NULL || signature->dataoff > sliceSize ||
        signature->datasize > sliceSize - signature->dataoff ||
        signature->datasize < sizeof(struct codex_superblob)) {
        return false;
    }

    uint8_t *signatureBytes = slice + signature->dataoff;
    struct codex_superblob *superblob =
        (struct codex_superblob *)signatureBytes;
    uint32_t superLength = OSSwapBigToHostInt32(superblob->length);
    uint32_t count = OSSwapBigToHostInt32(superblob->count);
    if (OSSwapBigToHostInt32(superblob->magic) !=
            CODEX_CSMAGIC_EMBEDDED_SIGNATURE ||
        superLength > signature->datasize ||
        count > (superLength - sizeof(*superblob)) /
                    sizeof(struct codex_blob_index)) {
        return false;
    }

    uint32_t bestDirectory = UINT32_MAX;
    uint32_t spareDirectory = UINT32_MAX;
    uint32_t signatureIndex = UINT32_MAX;
    unsigned int bestRank = 0;
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t type = OSSwapBigToHostInt32(superblob->index[index].type);
        uint32_t offset =
            OSSwapBigToHostInt32(superblob->index[index].offset);
        if (offset > superLength) {
            return false;
        }
        if (type == CODEX_CSSLOT_SIGNATURE) {
            signatureIndex = index;
            continue;
        }
        if (type != CODEX_CSSLOT_CODEDIRECTORY &&
            (type < CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES ||
             type >= CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            continue;
        }
        if (superLength - offset < sizeof(struct codex_code_directory)) {
            return false;
        }
        struct codex_code_directory *directory =
            (struct codex_code_directory *)(signatureBytes + offset);
        if (OSSwapBigToHostInt32(directory->magic) !=
            CODEX_CSMAGIC_CODEDIRECTORY) {
            return false;
        }
        unsigned int rank = 0;
        switch (directory->hashType) {
            case CODEX_CS_HASHTYPE_SHA1:
                rank = 1;
                break;
            case CODEX_CS_HASHTYPE_SHA256_TRUNCATED:
                rank = 2;
                break;
            case CODEX_CS_HASHTYPE_SHA256:
                rank = 3;
                break;
            case CODEX_CS_HASHTYPE_SHA384:
                rank = 4;
                break;
            default:
                return false;
        }
        if (bestDirectory == UINT32_MAX || rank > bestRank) {
            if (bestDirectory != UINT32_MAX) {
                spareDirectory = bestDirectory;
            }
            bestDirectory = index;
            bestRank = rank;
        } else {
            spareDirectory = index;
        }
    }
    if (bestDirectory == UINT32_MAX) {
        return false;
    }

    if (signatureIndex == UINT32_MAX && spareDirectory != UINT32_MAX) {
        signatureIndex = spareDirectory;
        superblob->index[signatureIndex].type =
            OSSwapHostToBigInt32(CODEX_CSSLOT_SIGNATURE);
    }

    uint8_t *requirements = NULL;
    size_t requirementsSize = 0;
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t type = OSSwapBigToHostInt32(superblob->index[index].type);
        uint32_t offset =
            OSSwapBigToHostInt32(superblob->index[index].offset);
        size_t available = superLength - offset;
        if (type == CODEX_CSSLOT_REQUIREMENTS) {
            if (available < sizeof(struct codex_requirements_blob)) {
                return false;
            }
            struct codex_requirements_blob *blob =
                (struct codex_requirements_blob *)(signatureBytes + offset);
            blob->magic =
                OSSwapHostToBigInt32(CODEX_CSMAGIC_REQUIREMENTS);
            blob->length = OSSwapHostToBigInt32((uint32_t)sizeof(*blob));
            blob->count = 0;
            requirements = (uint8_t *)blob;
            requirementsSize = sizeof(*blob);
        } else if (type == CODEX_CSSLOT_SIGNATURE) {
            if (available < sizeof(struct codex_generic_blob)) {
                return false;
            }
            struct codex_generic_blob *blob =
                (struct codex_generic_blob *)(signatureBytes + offset);
            blob->magic = OSSwapHostToBigInt32(CODEX_CSMAGIC_BLOBWRAPPER);
            blob->length = OSSwapHostToBigInt32((uint32_t)sizeof(*blob));
        }
    }

    for (uint32_t index = 0; index < count; ++index) {
        uint32_t type = OSSwapBigToHostInt32(superblob->index[index].type);
        bool isDirectory =
            type == CODEX_CSSLOT_CODEDIRECTORY ||
            (type >= CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES &&
             type < CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT);
        if (!isDirectory) {
            continue;
        }
        if (index != bestDirectory) {
            superblob->index[index].type = OSSwapHostToBigInt32(0x20000U);
            continue;
        }
        superblob->index[index].type =
            OSSwapHostToBigInt32(CODEX_CSSLOT_CODEDIRECTORY);
        uint32_t offset =
            OSSwapBigToHostInt32(superblob->index[index].offset);
        if (!rehash_code_directory(slice, sliceSize,
                                   signatureBytes + offset,
                                   superLength - offset, requirements,
                                   requirementsSize)) {
            return false;
        }
    }
    return true;
}

static bool patch_execute_slice(struct mach_header_64 *header,
                                size_t sliceSize, const char *path) {
    if (sliceSize < sizeof(*header) || header->magic != MH_MAGIC_64 ||
        header->cputype != CPU_TYPE_ARM64 ||
        header->sizeofcmds > sliceSize - sizeof(*header)) {
        return false;
    }

    uint8_t *cursor = (uint8_t *)(header + 1);
    uint8_t *commandsEnd = cursor + header->sizeofcmds;
    struct dylinker_command *dylinker = NULL;
    bool hasIdentifier = false;
    bool hasEntry = false;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(commandsEnd - cursor) < sizeof(struct load_command)) {
            return false;
        }
        struct load_command *command = (struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(commandsEnd - cursor)) {
            return false;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            struct segment_command_64 *segment =
                (struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_PAGEZERO,
                        sizeof(segment->segname)) == 0 &&
                segment->vmaddr == 0) {
                segment->vmaddr = 0x100000000ULL - 0x4000ULL;
                segment->vmsize = 0x4000ULL;
            }
        } else if (command->cmd == LC_LOAD_DYLINKER) {
            dylinker = (struct dylinker_command *)command;
        } else if (command->cmd == LC_ID_DYLIB) {
            hasIdentifier = true;
        } else if (command->cmd == LC_MAIN) {
            hasEntry = true;
        }
        cursor += command->cmdsize;
    }
    if (cursor != commandsEnd || !hasEntry) {
        return false;
    }

    if (!hasIdentifier) {
        if (dylinker == NULL ||
            dylinker->cmdsize < sizeof(struct dylib_command) + 2U) {
            return false;
        }
        uint32_t commandSize = dylinker->cmdsize;
        memset(dylinker, 0, commandSize);
        struct dylib_command *identifier = (struct dylib_command *)dylinker;
        identifier->cmd = LC_ID_DYLIB;
        identifier->cmdsize = commandSize;
        identifier->dylib.name.offset = sizeof(*identifier);
        identifier->dylib.current_version = 0x10000;
        identifier->dylib.compatibility_version = 0x10000;
        const char *name = strrchr(path, '/');
        name = name != NULL ? name + 1 : path;
        size_t capacity = commandSize - sizeof(*identifier);
        strlcpy((char *)identifier + sizeof(*identifier), name, capacity);
    }

    header->filetype = MH_DYLIB;
    header->flags |= MH_NO_REEXPORTED_DYLIBS;
    header->flags &= ~MH_PIE;
#ifdef CPU_SUBTYPE_LIB64
    if ((header->cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
        header->cpusubtype |= CPU_SUBTYPE_LIB64;
    }
#endif
    return true;
}

static bool patch_execute_copy(const char *path) {
    int descriptor = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        status.st_size < (off_t)sizeof(uint32_t)) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return false;
    }
    size_t size = (size_t)status.st_size;
    void *mapping = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                         descriptor, 0);
    if (mapping == MAP_FAILED) {
        close(descriptor);
        return false;
    }

    bool patched = false;
    uint32_t magic = *(uint32_t *)mapping;
    if (magic == MH_MAGIC_64) {
        patched = patch_execute_slice(mapping, size, path) &&
                  rehash_execute_slice(mapping, size);
    } else if (magic == FAT_CIGAM && size >= sizeof(struct fat_header)) {
        struct fat_header *fat = mapping;
        uint32_t count = OSSwapBigToHostInt32(fat->nfat_arch);
        size_t tableSize = sizeof(*fat) + (size_t)count * sizeof(struct fat_arch);
        if (count > 0 && count <= 32 && tableSize <= size) {
            patched = true;
            struct fat_arch *architectures =
                (struct fat_arch *)((uint8_t *)mapping + sizeof(*fat));
            bool foundArm64 = false;
            for (uint32_t index = 0; index < count; ++index) {
                cpu_type_t cpu = (cpu_type_t)OSSwapBigToHostInt32(
                    (uint32_t)architectures[index].cputype);
                if (cpu != CPU_TYPE_ARM64) {
                    continue;
                }
                uint32_t offset = OSSwapBigToHostInt32(
                    architectures[index].offset);
                uint32_t sliceSize = OSSwapBigToHostInt32(
                    architectures[index].size);
                if (offset > size || sliceSize > size - offset ||
                    !patch_execute_slice(
                        (struct mach_header_64 *)((uint8_t *)mapping + offset),
                        sliceSize, path) ||
                    !rehash_execute_slice((uint8_t *)mapping + offset,
                                          sliceSize)) {
                    patched = false;
                    break;
                }
                foundArm64 = true;
            }
            patched = patched && foundArm64;
        }
    }

    if (patched) {
        patched = msync(mapping, size, MS_SYNC) == 0 && fsync(descriptor) == 0;
    }
    int savedError = errno;
    munmap(mapping, size);
    close(descriptor);
    errno = savedError;
    return patched;
}

static bool make_macho_copy(const char *source, char destination[PATH_MAX]) {
    char directory[PATH_MAX];
    if (strlcpy(directory, source, sizeof(directory)) >= sizeof(directory)) {
        errno = ENAMETOOLONG;
        return false;
    }
    char *separator = strrchr(directory, '/');
    if (separator == NULL || separator == directory) {
        errno = EINVAL;
        return false;
    }
    *separator = '\0';
    const char *name = separator + 1;
    int length = snprintf(destination, PATH_MAX,
                          "%s/.%s.codex-runtime.%d.%08x", directory, name,
                          getpid(), arc4random());
    if (length <= 0 || length >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return false;
    }
    if (!copy_file_exclusive(source, destination)) {
        return false;
    }
    if (!patch_execute_copy(destination)) {
        int savedError = errno != 0 ? errno : ENOEXEC;
        unlink(destination);
        errno = savedError;
        return false;
    }
    return true;
}

static bool attach_slice_signature(int descriptor, const uint8_t *slice,
                                   size_t sliceSize, off_t sliceOffset) {
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
                codesign->datasize > sliceSize - codesign->dataoff) {
                return false;
            }
            fsignatures_t signature = {
                .fs_file_start = sliceOffset,
                .fs_blob_start = (void *)(uintptr_t)codesign->dataoff,
                .fs_blob_size = codesign->datasize,
            };
            errno = 0;
            int result = fcntl(descriptor, F_ADDFILESIGS_RETURN, &signature);
            int error = result == 0 ? 0 : errno;
            dprintf(result == 0 ? STDOUT_FILENO : STDERR_FILENO,
                    "codex-exec-worker child=%d phase=attach-signature "
                    "slice=0x%llx result=%d errno=%d end=0x%llx\n",
                    getpid(), (unsigned long long)sliceOffset, result, error,
                    (unsigned long long)signature.fs_file_start);
            return result == 0;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static bool attach_macho_signatures(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        status.st_size < (off_t)sizeof(uint32_t)) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return false;
    }
    size_t size = (size_t)status.st_size;
    void *mapping = mmap(NULL, size, PROT_READ, MAP_PRIVATE, descriptor, 0);
    if (mapping == MAP_FAILED) {
        close(descriptor);
        return false;
    }
    uint8_t *bytes = mapping;
    uint32_t magic = *(uint32_t *)mapping;
    bool attached = false;
    if (magic == MH_MAGIC_64) {
        attached = attach_slice_signature(descriptor, bytes, size, 0);
    } else if (magic == FAT_CIGAM && size >= sizeof(struct fat_header)) {
        const struct fat_header *fat = mapping;
        uint32_t count = OSSwapBigToHostInt32(fat->nfat_arch);
        size_t tableSize = sizeof(*fat) +
                           (size_t)count * sizeof(struct fat_arch);
        if (count > 0 && count <= 32 && tableSize <= size) {
            const struct fat_arch *architectures =
                (const struct fat_arch *)(bytes + sizeof(*fat));
            for (uint32_t index = 0; index < count; ++index) {
                uint32_t offset =
                    OSSwapBigToHostInt32(architectures[index].offset);
                uint32_t sliceSize =
                    OSSwapBigToHostInt32(architectures[index].size);
                if (offset <= size && sliceSize <= size - offset &&
                    attach_slice_signature(descriptor, bytes + offset,
                                           sliceSize, (off_t)offset)) {
                    attached = true;
                }
            }
        }
    }
    munmap(mapping, size);
    close(descriptor);
    return attached;
}

#if defined(__arm64__)

/*
 * dyld normally asks the kernel to attach a CodeDirectory before it maps an
 * executable segment. A CS_DEBUGGED process may execute anonymous pages, but
 * AMFI still rejects F_ADDFILESIGS_RETURN for an untrusted cdhash. Keep dyld
 * as the loader and replace only those two boundary operations in this short-
 * lived worker child: report the signature/LV checks as satisfied, and copy a
 * rejected executable file mapping into anonymous memory before making it RX.
 * This is the same useful separation as LiveContainer's JIT loader: the fixed,
 * trusted loader is the policy anchor; package payloads never enter a static
 * trust cache.
 */
static const uint8_t kDyldMmapSyscall[] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
static const uint8_t kDyldFcntlSyscall[] = {
    0x90, 0x0b, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};

static unsigned int gAnonymousExecutableMappings;

static void *codex_dyld_mmap(void *address, size_t length, int protection,
                             int flags, int descriptor, off_t offset) {
    void *mapping = mmap(address, length, protection, flags, descriptor,
                         offset);
    if (mapping != MAP_FAILED || descriptor < 0 ||
        (protection & PROT_EXEC) == 0) {
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

    ++gAnonymousExecutableMappings;
    dprintf(STDOUT_FILENO,
            "codex-exec-worker child=%d phase=dyld-anonymous-exec "
            "index=%u address=%p length=0x%zx offset=0x%llx "
            "originalErrno=%d\n",
            getpid(), gAnonymousExecutableMappings, mapping, length,
            (unsigned long long)offset, originalError);
    return mapping;
}

static int codex_dyld_fcntl(int descriptor, int command, void *parameter) {
    if (command == F_ADDFILESIGS_RETURN) {
        fsignatures_t *signature = (fsignatures_t *)parameter;
        if (signature != NULL) {
            signature->fs_file_start = (off_t)UINT64_MAX;
        }
        dprintf(STDOUT_FILENO,
                "codex-exec-worker child=%d phase=dyld-signature-bypass "
                "fd=%d\n",
                getpid(), descriptor);
        return 0;
    }
    if (command == F_CHECK_LV) {
        return 0;
    }
    return fcntl(descriptor, command, parameter);
}

static uint32_t arm64_movk(unsigned int registerNumber, uint16_t immediate,
                           unsigned int shift) {
    return 0xf2800000U | ((shift / 16U) << 21U) |
           ((uint32_t)immediate << 5U) | (registerNumber & 0x1fU);
}

static bool hook_arm64_function(void *source, void *target,
                                kern_return_t *writeResult,
                                kern_return_t *executeResult) {
    uintptr_t sourceAddress = (uintptr_t)source;
    uintptr_t targetAddress = (uintptr_t)target;
    vm_size_t pageSize = (vm_size_t)getpagesize();
    vm_address_t page =
        (vm_address_t)(sourceAddress & ~(uintptr_t)(pageSize - 1U));
    vm_size_t span = (vm_size_t)(
        ((sourceAddress + 20U + pageSize - 1U) &
         ~(uintptr_t)(pageSize - 1U)) -
        (uintptr_t)page);

    kern_return_t writable = mach_vm_protect(
        mach_task_self(), (mach_vm_address_t)page, (mach_vm_size_t)span,
        false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (writeResult != NULL) {
        *writeResult = writable;
    }
    if (writable != KERN_SUCCESS) {
        return false;
    }

    uint32_t *instructions = (uint32_t *)sourceAddress;
    instructions[0] = arm64_movk(16U, (uint16_t)(targetAddress >> 0U), 0U);
    instructions[1] = arm64_movk(16U, (uint16_t)(targetAddress >> 16U), 16U);
    instructions[2] = arm64_movk(16U, (uint16_t)(targetAddress >> 32U), 32U);
    instructions[3] = arm64_movk(16U, (uint16_t)(targetAddress >> 48U), 48U);
    instructions[4] = 0xd61f0200U; /* br x16 */

    kern_return_t executable = mach_vm_protect(
        mach_task_self(), (mach_vm_address_t)page, (mach_vm_size_t)span,
        false, VM_PROT_READ | VM_PROT_EXECUTE);
    if (executeResult != NULL) {
        *executeResult = executable;
    }
    if (executable != KERN_SUCCESS) {
        return false;
    }
    sys_icache_invalidate((void *)sourceAddress, 20U);
    return true;
}

static uint8_t *find_dyld_pattern(const struct mach_header_64 *header,
                                  const uint8_t *pattern,
                                  size_t patternSize) {
    if (header == NULL || header->magic != MH_MAGIC_64 ||
        header->sizeofcmds > (16U * 1024U * 1024U)) {
        return NULL;
    }
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *commandsEnd = cursor + header->sizeofcmds;
    uint64_t baseVmAddress = 0;
    bool foundBaseVmAddress = false;

    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(commandsEnd - cursor) < sizeof(struct load_command)) {
            return NULL;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(commandsEnd - cursor)) {
            return NULL;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            /*
             * An optimized in-cache Mach-O need not have a segment whose
             * fileoff is zero. dyld's runtime header is at the beginning of
             * its first executable segment, which is the stable slide anchor.
             */
            if ((segment->initprot & VM_PROT_EXECUTE) != 0) {
                baseVmAddress = segment->vmaddr;
                foundBaseVmAddress = true;
                break;
            }
        }
        cursor += command->cmdsize;
    }
    if (!foundBaseVmAddress) {
        return NULL;
    }

    uintptr_t slide = (uintptr_t)header - (uintptr_t)baseVmAddress;
    cursor = (const uint8_t *)(header + 1);
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if ((segment->initprot & VM_PROT_EXECUTE) != 0 &&
                segment->filesize >= patternSize &&
                segment->filesize <= SIZE_MAX) {
                uint8_t *start =
                    (uint8_t *)(slide + (uintptr_t)segment->vmaddr);
                size_t size = (size_t)segment->filesize;
                for (size_t offset = 0; offset + patternSize <= size;
                     offset += sizeof(uint32_t)) {
                    if (memcmp(start + offset, pattern, patternSize) == 0) {
                        return start + offset;
                    }
                }
            }
        }
        cursor += command->cmdsize;
    }
    return NULL;
}

static bool install_dyld_validation_bypass(void) {
    task_dyld_info_data_t dyldInfo = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t infoResult = task_info(
        mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if (infoResult != KERN_SUCCESS || dyldInfo.all_image_info_addr == 0) {
        dprintf(STDERR_FILENO,
                "codex-exec-worker child=%d phase=dyld-hook "
                "infoResult=%d installed=0\n",
                getpid(), infoResult);
        return false;
    }

    const struct dyld_all_image_infos *infos =
        (const struct dyld_all_image_infos *)(uintptr_t)
            dyldInfo.all_image_info_addr;
    const struct mach_header_64 *dyldHeader =
        (const struct mach_header_64 *)infos->dyldImageLoadAddress;
    uint8_t *mmapStub = find_dyld_pattern(
        dyldHeader, kDyldMmapSyscall, sizeof(kDyldMmapSyscall));
    uint8_t *fcntlStub = find_dyld_pattern(
        dyldHeader, kDyldFcntlSyscall, sizeof(kDyldFcntlSyscall));
    if (mmapStub == NULL || fcntlStub == NULL) {
        dprintf(STDERR_FILENO,
                "codex-exec-worker child=%d phase=dyld-hook base=%p "
                "mmap=%p fcntl=%p installed=0\n",
                getpid(), (const void *)dyldHeader, mmapStub, fcntlStub);
        return false;
    }

    kern_return_t mmapWrite = KERN_FAILURE;
    kern_return_t mmapExecute = KERN_FAILURE;
    kern_return_t fcntlWrite = KERN_FAILURE;
    kern_return_t fcntlExecute = KERN_FAILURE;
    bool mmapHooked = hook_arm64_function(
        mmapStub, (void *)codex_dyld_mmap, &mmapWrite, &mmapExecute);
    bool fcntlHooked = hook_arm64_function(
        fcntlStub, (void *)codex_dyld_fcntl, &fcntlWrite, &fcntlExecute);
    bool installed = mmapHooked && fcntlHooked;
    dprintf(installed ? STDOUT_FILENO : STDERR_FILENO,
            "codex-exec-worker child=%d phase=dyld-hook base=%p "
            "mmap=%p mmapWrite=%d mmapExecute=%d "
            "fcntl=%p fcntlWrite=%d fcntlExecute=%d installed=%d\n",
            getpid(), (const void *)dyldHeader, mmapStub, mmapWrite,
            mmapExecute, fcntlStub, fcntlWrite, fcntlExecute, installed);
    return installed;
}

#else

static bool install_dyld_validation_bypass(void) {
    return false;
}

#endif

static const struct mach_header_64 *find_loaded_header(const char *path) {
    char wanted[PATH_MAX];
    if (realpath(path, wanted) == NULL) {
        return NULL;
    }
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; ++index) {
        const char *name = _dyld_get_image_name(index);
        char resolved[PATH_MAX];
        if (name != NULL && realpath(name, resolved) != NULL &&
            strcmp(wanted, resolved) == 0) {
            return (const struct mach_header_64 *)_dyld_get_image_header(index);
        }
    }
    return NULL;
}

static void *find_main_entry(const struct mach_header_64 *header) {
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return NULL;
    }
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) {
            return NULL;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(end - cursor)) {
            return NULL;
        }
        if (command->cmd == LC_MAIN &&
            command->cmdsize >= sizeof(struct entry_point_command)) {
            const struct entry_point_command *entry =
                (const struct entry_point_command *)command;
            return (uint8_t *)header + entry->entryoff;
        }
        cursor += command->cmdsize;
    }
    return NULL;
}

static int run_child(int control, const char *loadPath, int guestArgc,
                     char **guestArgv) {
    uint8_t ready = 1;
    if (!write_all(control, &ready, sizeof(ready))) {
        return 70;
    }

    struct codex_parent_reply start = {0};
    if (!read_all(control, &start, sizeof(start))) {
        return 71;
    }
    struct codex_child_report report = {
        .status = start.status,
    };
    if (!write_all(control, &report, sizeof(report))) {
        return 72;
    }

    struct codex_parent_reply reply = {0};
    bool received = read_all(control, &reply, sizeof(reply));
    uint8_t resumed = 1;
    bool acknowledged = write_all(control, &resumed, sizeof(resumed));
    close(control);
    if (!received) {
        return 73;
    }
    if (!acknowledged) {
        return 74;
    }
    if (report.status != 0 || reply.status != 0) {
        return report.status != 0 ? report.status : reply.status;
    }

    bool dyldBypassInstalled = install_dyld_validation_bypass();
    bool signatureAttached =
        !dyldBypassInstalled && attach_macho_signatures(loadPath);
    dprintf(dyldBypassInstalled || signatureAttached ? STDOUT_FILENO
                                                     : STDERR_FILENO,
            "codex-exec-worker child=%d mode=macho dyldBypass=%d "
            "signatureAttached=%d path=%s\n",
            getpid(), dyldBypassInstalled, signatureAttached, loadPath);
    void *handle = dlopen(loadPath, RTLD_LAZY | RTLD_GLOBAL | RTLD_FIRST);
    if (handle == NULL) {
        const char *error = dlerror();
        dprintf(STDERR_FILENO,
                "codex-exec-worker child=%d mode=macho dlopen=false path=%s "
                "error=%s\n",
                getpid(), loadPath, error != NULL ? error : "unknown");
        return 79;
    }

    const struct mach_header_64 *header = find_loaded_header(loadPath);
    void *entry = find_main_entry(header);
    if (entry == NULL) {
        dprintf(STDERR_FILENO,
            "codex-exec-worker child=%d mode=macho entry=false path=%s\n",
                getpid(), loadPath);
        return 83;
    }
    dprintf(STDOUT_FILENO,
            "codex-exec-worker child=%d mode=macho entry=%p path=%s\n",
            getpid(), entry, loadPath);
    int result = ((int (*)(int, char **, char **))entry)(
        guestArgc, guestArgv, environ);
    return result & 0xff;
}

static void handshake_timeout_handler(int signalNumber) {
    (void)signalNumber;
    pid_t child = (pid_t)gOwnedChild;
    if (child > 1) {
        (void)kill(child, SIGKILL);
    }
    _exit(99);
}

static bool start_handshake_watchdog(pid_t child) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handshake_timeout_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) != 0) {
        return false;
    }
    gOwnedChild = (sig_atomic_t)child;
    alarm(CODEX_HANDSHAKE_TIMEOUT_SECONDS);
    return true;
}

static void stop_handshake_watchdog(void) {
    alarm(0);
    gOwnedChild = -1;
}

static void terminate_own_child(pid_t child) {
    if (child <= 1) {
        return;
    }
    (void)kill(child, SIGKILL);
    int status = 0;
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child || (result < 0 && errno == ECHILD)) {
            return;
        }
        if (result < 0 && errno != EINTR) {
            return;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
}

static bool wait_for_stop(pid_t child, int *status) {
    for (unsigned int attempt = 0; attempt < CODEX_WAIT_ATTEMPTS; ++attempt) {
        pid_t result = waitpid(child, status, WUNTRACED | WNOHANG);
        if (result == child) {
            return WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGSTOP;
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        usleep(CODEX_WAIT_DELAY_USEC);
    }
    errno = ETIMEDOUT;
    return false;
}

static bool wait_for_resume_ack(int control) {
    struct pollfd descriptor = {
        .fd = control,
        .events = POLLIN,
    };
    int result;
    do {
        result = poll(&descriptor, 1,
                      (int)(CODEX_WAIT_ATTEMPTS *
                            CODEX_WAIT_DELAY_USEC / 1000U));
    } while (result < 0 && errno == EINTR);
    uint8_t resumed = 0;
    return result == 1 && (descriptor.revents & POLLIN) != 0 &&
           read_all(control, &resumed, sizeof(resumed)) && resumed == 1;
}

static int run_debugged_child(const char *loadPath, int guestArgc,
                              char **guestArgv) {
    int control[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, control) != 0) {
        return 90;
    }
    pid_t child = fork();
    if (child < 0) {
        close(control[0]);
        close(control[1]);
        return 91;
    }
    if (child == 0) {
        close(control[0]);
        int result = run_child(control[1], loadPath, guestArgc, guestArgv);
        _exit(result);
    }
    close(control[1]);
    if (child <= 1 || !start_handshake_watchdog(child)) {
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        return 92;
    }

    uint8_t ready = 0;
    if (!read_all(control[0], &ready, sizeof(ready)) || ready != 1) {
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        return 93;
    }

    errno = 0;
    if (ptrace(PT_ATTACHEXC, child, NULL, 0) != 0) {
        int savedError = errno;
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        dprintf(STDERR_FILENO,
                "codex-exec-worker child=%d attach=false errno=%d\n",
                child, savedError);
        return 94;
    }
    int stopStatus = 0;
    if (!wait_for_stop(child, &stopStatus)) {
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        return 95;
    }

    uint32_t flags = 0;
    errno = 0;
    int csStatus = csops(child, CODEX_CS_OPS_STATUS, &flags, sizeof(flags));
    bool debugged = csStatus == 0 && (flags & CODEX_CS_DEBUGGED) != 0 &&
                    (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
    dprintf(STDOUT_FILENO,
            "codex-exec-worker parent=%d child=%d phase=debugged "
            "csops=%d errno=%d flags=0x%08x debugged=%d\n",
            getpid(), child, csStatus, csStatus == 0 ? 0 : errno, flags,
            debugged);

    struct codex_parent_reply start = {
        .status = debugged ? 0 : 96,
    };
    errno = 0;
    if (ptrace(PT_DETACH, child, NULL, 0) != 0) {
        int savedError = errno;
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        dprintf(STDERR_FILENO,
                "codex-exec-worker child=%d detach=false errno=%d\n",
                child, savedError);
        return 97;
    }
    (void)kill(child, SIGCONT);
    if (!write_all(control[0], &start, sizeof(start))) {
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        return 98;
    }

    struct codex_child_report report = {0};
    if (!read_all(control[0], &report, sizeof(report))) {
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        return 99;
    }

    struct codex_parent_reply reply = {
        .status = report.status,
    };
    if (!write_all(control[0], &reply, sizeof(reply))) {
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        return 100;
    }
    if (!wait_for_resume_ack(control[0])) {
        close(control[0]);
        terminate_own_child(child);
        stop_handshake_watchdog();
        return 101;
    }
    close(control[0]);
    stop_handshake_watchdog();

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return 102;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 103;
}

int main(int argc, char *argv[]) {
    setlinebuf(stdout);
    setlinebuf(stderr);
    if (argc >= 3 && strcmp(argv[1], "--macho") == 0) {
        char source[PATH_MAX];
        char runtimeCopy[PATH_MAX] = {0};
        if (!path_is_managed(argv[2], source) ||
            !make_macho_copy(source, runtimeCopy)) {
            dprintf(STDERR_FILENO,
                    "codex-exec-worker mode=macho prepare=false path=%s "
                    "errno=%d\n",
                    argv[2], errno);
            return 67;
        }
        argv[2] = source;
        int result = run_debugged_child(runtimeCopy, argc - 2, argv + 2);
        unlink(runtimeCopy);
        return result;
    }
    dprintf(STDERR_FILENO,
            "usage: %s --macho executable [arguments...]\n",
            argv[0]);
    return 64;
}
