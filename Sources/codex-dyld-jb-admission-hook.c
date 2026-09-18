#include "codex-dyld-jb-admission-hook.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <libkern/OSCacheControl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <mach-o/dyld_images.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_VALID 0x00000001U
#define CODEX_CS_HARD 0x00000100U
#define CODEX_CS_KILL 0x00000200U
#define CODEX_CS_DEBUGGED 0x10000000U
#define CODEX_MAX_LOAD_COMMANDS 4096U
#define CODEX_MAX_LOAD_COMMAND_BYTES (16U * 1024U * 1024U)
#define CODEX_MAX_MACHO_SIZE (512ULL * 1024ULL * 1024ULL)
#define CODEX_STUB_SIZE 20U
#define CODEX_MAX_QUIESCED_THREADS 1024U
#define CODEX_MAX_QUIESCE_ATTEMPTS 3U
#define CODEX_MAX_QUIESCE_PASSES 8U
#define CODEX_REQUIRED_STABLE_QUIESCE_PASSES 2U
#define CODEX_MAX_RESUME_ATTEMPTS 3U

static const char *const kFixedInstallPath =
    "/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib";
static const char *const kStatusMarkerPath =
    "/var/jb/var/run/codex-dyld-jb-admission-hook.status";

/*
 * Exact iOS 27 build 24A437 dyld profile.  The exported device artifact has
 * SHA-256 ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608
 * and UUID D3F59B02-EE07-371B-B091-3F150A078ED8.  Its private raw mmap and
 * fcntl syscall anchors and full 20-byte prefixes each occur exactly once.
 * Runtime installation rechecks the UUID, anchor uniqueness, full prefixes,
 * and original bytes before writing anything.
 */
static const uint8_t kExpectedDyldUUID[16] = {
    0xd3, 0xf5, 0x9b, 0x02, 0xee, 0x07, 0x37, 0x1b,
    0xb0, 0x91, 0x3f, 0x15, 0x0a, 0x07, 0x8e, 0xd8,
};
static const uint8_t kExpectedDyldSHA256[32] = {
    0xab, 0x98, 0x87, 0xed, 0x96, 0xc9, 0xc0, 0x8a,
    0xd6, 0x8d, 0x4c, 0x6a, 0x5c, 0x27, 0xe8, 0x28,
    0x9f, 0xb0, 0xc9, 0xe5, 0x5e, 0xc3, 0xe1, 0x34,
    0x54, 0x72, 0x92, 0xa1, 0xec, 0x57, 0x96, 0x08,
};
static const uint8_t kMmapStubPrefix[CODEX_STUB_SIZE] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
    0x03, 0x01, 0x00, 0x54, 0x7f, 0x23, 0x03, 0xd5,
    0xfd, 0x7b, 0xbf, 0xa9,
};
static const uint8_t kFcntlStubPrefix[CODEX_STUB_SIZE] = {
    0x90, 0x0b, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
    0x03, 0x01, 0x00, 0x54, 0x7f, 0x23, 0x03, 0xd5,
    0xfd, 0x7b, 0xbf, 0xa9,
};

__attribute__((visibility("default"))) const char
    codex_dyld_jb_hook_marker[] = "codex-dyld-jb-admission-hook-v1";

extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern kern_return_t mach_vm_region(
    vm_map_t target_task, mach_vm_address_t *address,
    mach_vm_size_t *size, vm_region_flavor_t flavor,
    vm_region_info_t info, mach_msg_type_number_t *info_count,
    mach_port_t *object_name);
extern kern_return_t mach_vm_protect(
    vm_map_t target_task, mach_vm_address_t address,
    mach_vm_size_t size, boolean_t set_maximum,
    vm_prot_t new_protection);

static _Atomic uint32_t gState = CODEX_DYLD_JB_HOOK_UNINITIALIZED;
static _Atomic uint64_t gAnonymousRxMappings;
static _Atomic uint64_t gSignatureBypasses;
static _Atomic uint64_t gPolicyRejections;
static struct codex_dyld_jb_hook_status_v1 gStatus = {
    .size = sizeof(struct codex_dyld_jb_hook_status_v1),
    .version = CODEX_DYLD_JB_HOOK_ABI_VERSION,
    .state = CODEX_DYLD_JB_HOOK_UNINITIALIZED,
};
static uint8_t *gMmapStub;
static uint8_t *gFcntlStub;
static uint8_t gMmapPatch[CODEX_STUB_SIZE];
static uint8_t gFcntlPatch[CODEX_STUB_SIZE];

static bool add_u64(uint64_t left, uint64_t right, uint64_t *result) {
    return !__builtin_add_overflow(left, right, result);
}

static bool multiply_size(size_t left, size_t right, size_t *result) {
    return !__builtin_mul_overflow(left, right, result);
}

static bool path_is_descendant(const char *path, const char *root) {
    if (path == NULL || root == NULL) {
        return false;
    }
    size_t root_length = strlen(root);
    return root_length > 1U && strncmp(path, root, root_length) == 0 &&
           path[root_length] == '/';
}

static bool admission_errno(int value) {
    if (value == EACCES || value == EPERM || value == ENOEXEC) {
        return true;
    }
#ifdef EBADARCH
    if (value == EBADARCH) {
        return true;
    }
#endif
    return false;
}

static bool host_debug_policy(uint32_t *flags_out) {
    uint32_t flags = 0;
    errno = 0;
    int result = csops(getpid(), CODEX_CS_OPS_STATUS, &flags, sizeof(flags));
    if (flags_out != NULL) {
        *flags_out = flags;
    }
    return result == 0 &&
           (flags & (CODEX_CS_VALID | CODEX_CS_DEBUGGED)) ==
               (CODEX_CS_VALID | CODEX_CS_DEBUGGED) &&
           (flags & (CODEX_CS_HARD | CODEX_CS_KILL)) == 0;
}

static bool fixed_self_path(void) {
    Dl_info image = {0};
    char fixed_real[PATH_MAX] = {0};
    char loaded_real[PATH_MAX] = {0};
    struct stat fixed_status = {0};
    struct stat loaded_status = {0};
    if (dladdr((const void *)&codex_dyld_jb_hook_install, &image) == 0 ||
        image.dli_fname == NULL || realpath(kFixedInstallPath, fixed_real) == NULL ||
        realpath(image.dli_fname, loaded_real) == NULL ||
        strcmp(fixed_real, loaded_real) != 0 ||
        lstat(kFixedInstallPath, &fixed_status) != 0 ||
        stat(loaded_real, &loaded_status) != 0) {
        return false;
    }
    return S_ISREG(fixed_status.st_mode) && S_ISREG(loaded_status.st_mode) &&
           fixed_status.st_uid == 0 && fixed_status.st_nlink == 1 &&
           (fixed_status.st_mode & 0022) == 0 &&
           fixed_status.st_dev == loaded_status.st_dev &&
           fixed_status.st_ino == loaded_status.st_ino &&
           fixed_status.st_size == loaded_status.st_size &&
           fixed_status.st_size > 0;
}

static void format_uuid(const uint8_t uuid[16], char output[37]) {
    static const char digits[] = "0123456789abcdef";
    size_t output_index = 0;
    for (size_t index = 0; index < 16U; ++index) {
        if (index == 4U || index == 6U || index == 8U || index == 10U) {
            output[output_index++] = '-';
        }
        output[output_index++] = digits[uuid[index] >> 4U];
        output[output_index++] = digits[uuid[index] & 0x0fU];
    }
    output[output_index] = '\0';
}

static void format_hex(const uint8_t *bytes, size_t size, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < size; ++index) {
        output[index * 2U] = digits[bytes[index] >> 4U];
        output[index * 2U + 1U] = digits[bytes[index] & 0x0fU];
    }
    output[size * 2U] = '\0';
}

static int write_status_marker(void) {
    if (geteuid() != 0) {
        return EACCES;
    }
    if (unlink(kStatusMarkerPath) != 0 && errno != ENOENT) {
        return errno;
    }
    int descriptor = open(kStatusMarkerPath,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return errno;
    }
    struct stat status = {0};
    int result_error = 0;
    if (fstat(descriptor, &status) != 0) {
        result_error = errno;
    } else if (!S_ISREG(status.st_mode) || status.st_uid != 0 ||
               status.st_nlink != 1) {
        result_error = EINVAL;
    } else if (fchmod(descriptor, 0600) != 0) {
        result_error = errno;
    }
    char uuid[37] = {0};
    char expected_uuid[37] = {0};
    char expected_sha256[65] = {0};
    char expected_mmap[CODEX_STUB_SIZE * 2U + 1U] = {0};
    char observed_mmap[CODEX_STUB_SIZE * 2U + 1U] = {0};
    char expected_fcntl[CODEX_STUB_SIZE * 2U + 1U] = {0};
    char observed_fcntl[CODEX_STUB_SIZE * 2U + 1U] = {0};
    format_uuid(gStatus.dyld_uuid, uuid);
    format_uuid(gStatus.expected_dyld_uuid, expected_uuid);
    format_hex(gStatus.expected_dyld_sha256,
               sizeof(gStatus.expected_dyld_sha256), expected_sha256);
    format_hex(gStatus.expected_mmap_prefix,
               sizeof(gStatus.expected_mmap_prefix), expected_mmap);
    format_hex(gStatus.observed_mmap_prefix,
               sizeof(gStatus.observed_mmap_prefix), observed_mmap);
    format_hex(gStatus.expected_fcntl_prefix,
               sizeof(gStatus.expected_fcntl_prefix), expected_fcntl);
    format_hex(gStatus.observed_fcntl_prefix,
               sizeof(gStatus.observed_fcntl_prefix), observed_fcntl);
    if (result_error == 0 &&
        dprintf(descriptor,
                "marker=%s\npid=%d\nstate=%u\nerror=%u\n"
                "csFlags=0x%08x\ndyldUUID=%s\n"
                "expectedDyldUUID=%s\nexpectedDyldSHA256=%s\n"
                "mmapMatches=%u\nfcntlMatches=%u\n"
                "expectedMmapPrefix=%s\nobservedMmapPrefix=%s\n"
                "expectedFcntlPrefix=%s\nobservedFcntlPrefix=%s\n"
                "mmapStub=0x%llx\nfcntlStub=0x%llx\n"
                "quiesceAttempts=%u\nquiescePasses=%u\n"
                "threadsObserved=%u\nthreadsSuspended=%u\n"
                "threadsResumed=%u\nquiesceKernReturn=0x%x\n"
                "resumeKernReturn=0x%x\nunsafeThreadID=%llu\n"
                "unsafeThreadPC=0x%llx\n",
                codex_dyld_jb_hook_marker, gStatus.pid, gStatus.state,
                gStatus.error, gStatus.cs_flags, uuid, expected_uuid,
                expected_sha256,
                gStatus.mmap_pattern_count, gStatus.fcntl_pattern_count,
                expected_mmap, observed_mmap, expected_fcntl,
                observed_fcntl,
                (unsigned long long)gStatus.mmap_stub,
                (unsigned long long)gStatus.fcntl_stub,
                gStatus.quiesce_attempts, gStatus.quiesce_passes,
                gStatus.threads_observed, gStatus.threads_suspended,
                gStatus.threads_resumed,
                (unsigned int)gStatus.quiesce_kern_return,
                (unsigned int)gStatus.resume_kern_return,
                (unsigned long long)gStatus.unsafe_thread_id,
                (unsigned long long)gStatus.unsafe_thread_pc) < 0) {
        result_error = errno;
    }
    if (result_error == 0 && fsync(descriptor) != 0) {
        result_error = errno;
    }
    if (close(descriptor) != 0 && result_error == 0) {
        result_error = errno;
    }
    return result_error;
}

static int publish_status(uint32_t state, uint32_t error) {
    gStatus.state = state;
    gStatus.error = error;
    gStatus.anonymous_rx_mappings =
        atomic_load_explicit(&gAnonymousRxMappings, memory_order_relaxed);
    gStatus.signature_bypasses =
        atomic_load_explicit(&gSignatureBypasses, memory_order_relaxed);
    gStatus.policy_rejections =
        atomic_load_explicit(&gPolicyRejections, memory_order_relaxed);
    gStatus.marker_errno = write_status_marker();
    atomic_store_explicit(&gState, state, memory_order_release);
    char uuid[37] = {0};
    format_uuid(gStatus.dyld_uuid, uuid);
    dprintf(state == CODEX_DYLD_JB_HOOK_INSTALLED ? STDOUT_FILENO
                                                  : STDERR_FILENO,
            "codex-dyld-jb-hook pid=%d state=%u error=%u flags=0x%08x "
            "dyld=%p uuid=%s mmap=%p/%u fcntl=%p/%u "
            "quiesce=%u/%u suspended=%u resumed=%u markerErrno=%d\n",
            getpid(), state, error, gStatus.cs_flags,
            (void *)(uintptr_t)gStatus.dyld_header, uuid,
            (void *)(uintptr_t)gStatus.mmap_stub,
            gStatus.mmap_pattern_count,
            (void *)(uintptr_t)gStatus.fcntl_stub,
            gStatus.fcntl_pattern_count, gStatus.quiesce_attempts,
            gStatus.quiesce_passes, gStatus.threads_suspended,
            gStatus.threads_resumed, gStatus.marker_errno);
    return error == CODEX_DYLD_JB_HOOK_ERROR_NONE ? 0 : (int)error;
}

struct codex_pattern_result {
    uint8_t *address;
    uint32_t count;
    uint8_t prefix[CODEX_STUB_SIZE];
};

static bool valid_arm64_subtype(cpu_subtype_t subtype);

static bool scan_dyld_patterns(
    const struct mach_header_64 *header,
    struct codex_pattern_result *mmap_result,
    struct codex_pattern_result *fcntl_result, uint8_t uuid[16]) {
    memset(mmap_result, 0, sizeof(*mmap_result));
    memset(fcntl_result, 0, sizeof(*fcntl_result));
    memset(uuid, 0, 16U);
    if (header == NULL || header->magic != MH_MAGIC_64 ||
        header->cputype != CPU_TYPE_ARM64 ||
        !valid_arm64_subtype(header->cpusubtype) ||
        header->filetype != MH_DYLINKER ||
        header->ncmds == 0 || header->ncmds > CODEX_MAX_LOAD_COMMANDS ||
        header->sizeofcmds > CODEX_MAX_LOAD_COMMAND_BYTES) {
        return false;
    }

    uintptr_t commands_start = (uintptr_t)(header + 1);
    uintptr_t commands_end = 0;
    if (__builtin_add_overflow(commands_start, (uintptr_t)header->sizeofcmds,
                               &commands_end)) {
        return false;
    }
    const uint8_t *cursor = (const uint8_t *)commands_start;
    uint64_t base_vm_address = 0;
    uint32_t uuid_count = 0;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((uintptr_t)cursor > commands_end ||
            commands_end - (uintptr_t)cursor < sizeof(struct load_command)) {
            return false;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            (command->cmdsize & 7U) != 0 ||
            command->cmdsize > commands_end - (uintptr_t)cursor) {
            return false;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (base_vm_address == 0 &&
                (segment->initprot & VM_PROT_EXECUTE) != 0) {
                base_vm_address = segment->vmaddr;
            }
        } else if (command->cmd == LC_UUID &&
                   command->cmdsize == sizeof(struct uuid_command)) {
            const struct uuid_command *uuid_command =
                (const struct uuid_command *)command;
            memcpy(uuid, uuid_command->uuid, 16U);
            ++uuid_count;
        }
        cursor += command->cmdsize;
    }
    if (base_vm_address == 0 || uuid_count != 1U) {
        return false;
    }

    uintptr_t slide = (uintptr_t)header - (uintptr_t)base_vm_address;
    cursor = (const uint8_t *)commands_start;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if ((segment->initprot & VM_PROT_EXECUTE) != 0 &&
                segment->filesize >= CODEX_STUB_SIZE &&
                segment->filesize <= CODEX_MAX_MACHO_SIZE &&
                segment->vmaddr <= UINTPTR_MAX - slide) {
                const uint8_t *start =
                    (const uint8_t *)(slide + (uintptr_t)segment->vmaddr);
                size_t size = (size_t)segment->filesize;
                for (size_t offset = 0;
                     offset + CODEX_STUB_SIZE <= size;
                     offset += sizeof(uint32_t)) {
                    const uint8_t *candidate = start + offset;
                    if (memcmp(candidate, kMmapStubPrefix, 8U) == 0) {
                        if (mmap_result->count == 0) {
                            mmap_result->address = (uint8_t *)candidate;
                            memcpy(mmap_result->prefix, candidate,
                                   CODEX_STUB_SIZE);
                        }
                        ++mmap_result->count;
                    }
                    if (memcmp(candidate, kFcntlStubPrefix, 8U) == 0) {
                        if (fcntl_result->count == 0) {
                            fcntl_result->address = (uint8_t *)candidate;
                            memcpy(fcntl_result->prefix, candidate,
                                   CODEX_STUB_SIZE);
                        }
                        ++fcntl_result->count;
                    }
                }
            }
        }
        cursor += command->cmdsize;
    }
    return true;
}

static bool pread_exact(int descriptor, void *buffer, size_t size,
                        uint64_t offset) {
    if (offset > (uint64_t)INT64_MAX ||
        size > (size_t)((uint64_t)INT64_MAX - offset)) {
        return false;
    }
    size_t copied = 0;
    while (copied < size) {
        ssize_t amount = pread(descriptor, (uint8_t *)buffer + copied,
                               size - copied,
                               (off_t)(offset + (uint64_t)copied));
        if (amount > 0) {
            copied += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

static bool valid_arm64_subtype(cpu_subtype_t subtype) {
    cpu_subtype_t base = subtype & ~CPU_SUBTYPE_MASK;
    return base == CPU_SUBTYPE_ARM64_ALL || base == CPU_SUBTYPE_ARM64E;
}

static bool round_up_u64(uint64_t value, uint64_t alignment,
                         uint64_t *result) {
    if (alignment == 0 || (alignment & (alignment - 1U)) != 0 ||
        value > UINT64_MAX - (alignment - 1U)) {
        return false;
    }
    *result = (value + alignment - 1U) & ~(alignment - 1U);
    return true;
}

static bool validate_macho_slice(int descriptor, uint64_t descriptor_size,
                                 uint64_t slice_offset,
                                 uint64_t slice_size,
                                 bool require_mapping,
                                 uint64_t mapping_offset,
                                 uint64_t mapping_length) {
    uint64_t slice_end = 0;
    if (slice_size < sizeof(struct mach_header_64) ||
        !add_u64(slice_offset, slice_size, &slice_end) ||
        slice_end > descriptor_size) {
        return false;
    }

    struct mach_header_64 header = {0};
    if (!pread_exact(descriptor, &header, sizeof(header), slice_offset) ||
        header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        !valid_arm64_subtype(header.cpusubtype) ||
        (header.filetype != MH_DYLIB && header.filetype != MH_BUNDLE) ||
        header.ncmds == 0 || header.ncmds > CODEX_MAX_LOAD_COMMANDS ||
        header.sizeofcmds > CODEX_MAX_LOAD_COMMAND_BYTES) {
        return false;
    }

    uint64_t commands_offset = 0;
    uint64_t commands_end = 0;
    if (!add_u64(slice_offset, sizeof(header), &commands_offset) ||
        !add_u64(commands_offset, header.sizeofcmds, &commands_end) ||
        commands_end > slice_end) {
        return false;
    }

    int page_size_value = getpagesize();
    if (page_size_value <= 0) {
        return false;
    }
    uint64_t page_size = (uint64_t)page_size_value;
    bool header_covered = false;
    bool mapping_covered = !require_mapping;
    uint32_t executable_segments = 0;
    uint32_t code_signatures = 0;
    uint64_t cursor = commands_offset;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        struct load_command command = {0};
        if (!pread_exact(descriptor, &command, sizeof(command), cursor) ||
            command.cmdsize < sizeof(command) ||
            (command.cmdsize & 7U) != 0 || command.cmdsize > commands_end - cursor) {
            return false;
        }

        if (command.cmd == LC_SEGMENT_64) {
            struct segment_command_64 segment = {0};
            size_t section_bytes = 0;
            if (command.cmdsize < sizeof(segment) ||
                !pread_exact(descriptor, &segment, sizeof(segment), cursor) ||
                !multiply_size((size_t)segment.nsects,
                               sizeof(struct section_64), &section_bytes) ||
                section_bytes > command.cmdsize - sizeof(segment) ||
                segment.filesize > segment.vmsize ||
                segment.fileoff > slice_size ||
                segment.filesize > slice_size - segment.fileoff) {
                return false;
            }
            uint64_t header_bytes = sizeof(header) + header.sizeofcmds;
            if (segment.fileoff == 0 && segment.filesize >= header_bytes) {
                header_covered = true;
            }
            if ((segment.initprot & VM_PROT_EXECUTE) != 0) {
                if ((segment.initprot & VM_PROT_READ) == 0 ||
                    (segment.initprot & VM_PROT_WRITE) != 0 ||
                    segment.filesize == 0) {
                    return false;
                }
                ++executable_segments;
                if (require_mapping) {
                    uint64_t rounded_filesize = 0;
                    uint64_t segment_start = 0;
                    uint64_t segment_end = 0;
                    uint64_t mapping_end = 0;
                    if (!round_up_u64(segment.filesize, page_size,
                                      &rounded_filesize) ||
                        !add_u64(slice_offset, segment.fileoff,
                                 &segment_start) ||
                        !add_u64(segment_start, rounded_filesize,
                                 &segment_end) ||
                        !add_u64(mapping_offset, mapping_length,
                                 &mapping_end)) {
                        return false;
                    }
                    if (mapping_offset >= segment_start &&
                        mapping_end <= segment_end) {
                        mapping_covered = true;
                    }
                }
            }
        } else if (command.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command signature = {0};
            if (command.cmdsize != sizeof(signature) ||
                !pread_exact(descriptor, &signature, sizeof(signature),
                             cursor) ||
                signature.dataoff > slice_size ||
                signature.datasize > slice_size - signature.dataoff) {
                return false;
            }
            ++code_signatures;
            if (code_signatures > 1U) {
                return false;
            }
        }
        cursor += command.cmdsize;
    }
    return cursor <= commands_end && header_covered &&
           executable_segments != 0 && mapping_covered;
}

static uint32_t maybe_swap32(uint32_t value, bool swapped) {
    return swapped ? OSSwapInt32(value) : value;
}

static uint64_t maybe_swap64(uint64_t value, bool swapped) {
    return swapped ? OSSwapInt64(value) : value;
}

static bool validate_macho_descriptor(int descriptor,
                                      bool require_mapping,
                                      uint64_t mapping_offset,
                                      uint64_t mapping_length,
                                      uint64_t *descriptor_size_out) {
    struct stat status = {0};
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != 0 || status.st_nlink != 1 ||
        (status.st_mode & 0022) != 0 || status.st_size <= 0 ||
        (uint64_t)status.st_size > CODEX_MAX_MACHO_SIZE) {
        return false;
    }
    uint64_t descriptor_size = (uint64_t)status.st_size;
    if (descriptor_size_out != NULL) {
        *descriptor_size_out = descriptor_size;
    }
    if (require_mapping) {
        uint64_t mapping_end = 0;
        if (mapping_length == 0 ||
            !add_u64(mapping_offset, mapping_length, &mapping_end) ||
            mapping_offset > descriptor_size) {
            return false;
        }
    }

    uint32_t magic = 0;
    if (!pread_exact(descriptor, &magic, sizeof(magic), 0)) {
        return false;
    }
    if (magic == MH_MAGIC_64) {
        return validate_macho_slice(descriptor, descriptor_size, 0,
                                    descriptor_size, require_mapping,
                                    mapping_offset, mapping_length);
    }

    bool is_fat64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    bool is_fat32 = magic == FAT_MAGIC || magic == FAT_CIGAM;
    bool swapped = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
    if (!is_fat32 && !is_fat64) {
        return false;
    }
    struct fat_header fat_header = {0};
    if (descriptor_size < sizeof(fat_header) ||
        !pread_exact(descriptor, &fat_header, sizeof(fat_header), 0)) {
        return false;
    }
    uint32_t architecture_count =
        maybe_swap32(fat_header.nfat_arch, swapped);
    if (architecture_count == 0 || architecture_count > 32U) {
        return false;
    }
    size_t architecture_size =
        is_fat64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
    size_t table_bytes = 0;
    if (!multiply_size(architecture_count, architecture_size, &table_bytes) ||
        table_bytes > descriptor_size - sizeof(fat_header)) {
        return false;
    }

    bool found_valid_arm64 = false;
    for (uint32_t index = 0; index < architecture_count; ++index) {
        uint64_t entry_offset = sizeof(fat_header) +
            (uint64_t)index * (uint64_t)architecture_size;
        cpu_type_t cpu_type = 0;
        cpu_subtype_t cpu_subtype = 0;
        uint64_t slice_offset = 0;
        uint64_t slice_size = 0;
        if (is_fat64) {
            struct fat_arch_64 architecture = {0};
            if (!pread_exact(descriptor, &architecture,
                             sizeof(architecture), entry_offset)) {
                return false;
            }
            cpu_type = (cpu_type_t)maybe_swap32(
                (uint32_t)architecture.cputype, swapped);
            cpu_subtype = (cpu_subtype_t)maybe_swap32(
                (uint32_t)architecture.cpusubtype, swapped);
            slice_offset = maybe_swap64(architecture.offset, swapped);
            slice_size = maybe_swap64(architecture.size, swapped);
        } else {
            struct fat_arch architecture = {0};
            if (!pread_exact(descriptor, &architecture,
                             sizeof(architecture), entry_offset)) {
                return false;
            }
            cpu_type = (cpu_type_t)maybe_swap32(
                (uint32_t)architecture.cputype, swapped);
            cpu_subtype = (cpu_subtype_t)maybe_swap32(
                (uint32_t)architecture.cpusubtype, swapped);
            slice_offset = maybe_swap32(architecture.offset, swapped);
            slice_size = maybe_swap32(architecture.size, swapped);
        }
        if (cpu_type != CPU_TYPE_ARM64 ||
            !valid_arm64_subtype(cpu_subtype)) {
            continue;
        }
        if (validate_macho_slice(descriptor, descriptor_size, slice_offset,
                                 slice_size, require_mapping,
                                 mapping_offset, mapping_length)) {
            found_valid_arm64 = true;
            if (!require_mapping) {
                break;
            }
            return true;
        }
    }
    return found_valid_arm64;
}

static bool descriptor_is_managed_macho(int descriptor,
                                        bool require_mapping,
                                        uint64_t mapping_offset,
                                        uint64_t mapping_length,
                                        uint64_t *descriptor_size_out) {
    char descriptor_path[PATH_MAX] = {0};
    char managed_root[PATH_MAX] = {0};
    char resolved_path[PATH_MAX] = {0};
    struct stat descriptor_status = {0};
    struct stat path_status = {0};
    if (descriptor < 0 ||
        fcntl(descriptor, F_GETPATH, descriptor_path) != 0 ||
        realpath("/var/jb", managed_root) == NULL ||
        realpath(descriptor_path, resolved_path) == NULL ||
        !path_is_descendant(resolved_path, managed_root) ||
        fstat(descriptor, &descriptor_status) != 0 ||
        stat(resolved_path, &path_status) != 0 ||
        descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino ||
        descriptor_status.st_size != path_status.st_size ||
        !validate_macho_descriptor(descriptor, require_mapping,
                                   mapping_offset, mapping_length,
                                   descriptor_size_out)) {
        atomic_fetch_add_explicit(&gPolicyRejections, 1U,
                                  memory_order_relaxed);
        return false;
    }
    return true;
}

__attribute__((noinline)) static void *
codex_managed_dyld_mmap(void *address, size_t length, int protection,
                        int flags, int descriptor, off_t offset) {
    void *mapping = mmap(address, length, protection, flags, descriptor,
                         offset);
    if (mapping != MAP_FAILED || descriptor < 0 || offset < 0 ||
        protection != (PROT_READ | PROT_EXEC) ||
        (flags & MAP_PRIVATE) == 0 || (flags & MAP_ANON) != 0 ||
        !admission_errno(errno) ||
        atomic_load_explicit(&gState, memory_order_acquire) !=
            CODEX_DYLD_JB_HOOK_INSTALLED) {
        return mapping;
    }

    int original_error = errno;
    int page_size_value = getpagesize();
    uint32_t current_flags = 0;
    uint64_t descriptor_size = 0;
    if (page_size_value <= 0 ||
        ((uint64_t)offset % (uint64_t)page_size_value) != 0 ||
        ((flags & MAP_FIXED) != 0 &&
         ((uintptr_t)address % (uintptr_t)page_size_value) != 0) ||
        !host_debug_policy(&current_flags) ||
        !descriptor_is_managed_macho(descriptor, true, (uint64_t)offset,
                                     (uint64_t)length,
                                     &descriptor_size)) {
        errno = original_error;
        return MAP_FAILED;
    }

    int anonymous_flags = MAP_PRIVATE | MAP_ANON;
    if ((flags & MAP_FIXED) != 0) {
        anonymous_flags |= MAP_FIXED;
    }
    mapping = mmap(address, length, PROT_READ | PROT_WRITE,
                   anonymous_flags, -1, 0);
    if (mapping == MAP_FAILED) {
        return MAP_FAILED;
    }

    uint64_t available = descriptor_size - (uint64_t)offset;
    size_t copy_size = length;
    if (available < (uint64_t)copy_size) {
        copy_size = (size_t)available;
    }
    size_t copied = 0;
    while (copied < copy_size) {
        ssize_t amount = pread(descriptor, (uint8_t *)mapping + copied,
                               copy_size - copied, offset + (off_t)copied);
        if (amount > 0) {
            copied += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        int read_error = amount == 0 ? EIO : errno;
        (void)munmap(mapping, length);
        errno = read_error;
        return MAP_FAILED;
    }
    if (mprotect(mapping, length, PROT_READ | PROT_EXEC) != 0) {
        int protection_error = errno;
        (void)munmap(mapping, length);
        errno = protection_error;
        return MAP_FAILED;
    }

    uint64_t event = atomic_fetch_add_explicit(
                         &gAnonymousRxMappings, 1U,
                         memory_order_relaxed) +
                     1U;
    dprintf(STDERR_FILENO,
            "codex-dyld-jb-hook pid=%d event=anonymous-rx index=%llu "
            "fd=%d address=%p length=0x%zx offset=0x%llx "
            "originalErrno=%d\n",
            getpid(), (unsigned long long)event, descriptor, mapping, length,
            (unsigned long long)offset, original_error);
    errno = original_error;
    return mapping;
}

__attribute__((noinline)) static int
codex_managed_dyld_fcntl(int descriptor, int command, void *parameter) {
    int result = fcntl(descriptor, command, parameter);
    if (result == 0 ||
        (command != F_ADDFILESIGS_RETURN && command != F_CHECK_LV) ||
        !admission_errno(errno) ||
        atomic_load_explicit(&gState, memory_order_acquire) !=
            CODEX_DYLD_JB_HOOK_INSTALLED) {
        return result;
    }
    int original_error = errno;
    uint32_t current_flags = 0;
    if (!host_debug_policy(&current_flags) ||
        !descriptor_is_managed_macho(descriptor, false, 0, 0, NULL) ||
        (command == F_ADDFILESIGS_RETURN && parameter == NULL)) {
        errno = original_error;
        return result;
    }
    if (command == F_ADDFILESIGS_RETURN) {
        fsignatures_t *signature = (fsignatures_t *)parameter;
        signature->fs_file_start = (off_t)UINT64_MAX;
    }
    uint64_t event = atomic_fetch_add_explicit(
                         &gSignatureBypasses, 1U,
                         memory_order_relaxed) +
                     1U;
    dprintf(STDERR_FILENO,
            "codex-dyld-jb-hook pid=%d event=signature-bypass index=%llu "
            "fd=%d command=%d originalErrno=%d\n",
            getpid(), (unsigned long long)event, descriptor, command,
            original_error);
    errno = original_error;
    return 0;
}

static uint32_t arm64_movk(unsigned int register_number, uint16_t immediate,
                           unsigned int shift) {
    return 0xf2800000U | ((shift / 16U) << 21U) |
           ((uint32_t)immediate << 5U) | (register_number & 0x1fU);
}

static void make_branch_patch(void *target,
                              uint8_t patch[CODEX_STUB_SIZE]) {
    uintptr_t address = (uintptr_t)ptrauth_strip(
        target, ptrauth_key_function_pointer);
    uint32_t instructions[CODEX_STUB_SIZE / sizeof(uint32_t)] = {
        arm64_movk(16U, (uint16_t)(address >> 0U), 0U),
        arm64_movk(16U, (uint16_t)(address >> 16U), 16U),
        arm64_movk(16U, (uint16_t)(address >> 32U), 32U),
        arm64_movk(16U, (uint16_t)(address >> 48U), 48U),
        0xd61f0200U, /* br x16 */
    };
    memcpy(patch, instructions, sizeof(instructions));
}

enum codex_stub_mutation_result {
    CODEX_STUB_MUTATION_OK = 0,
    CODEX_STUB_MUTATION_FAILED_CLEAN = 1,
    CODEX_STUB_MUTATION_PARTIAL = 2,
};

static enum codex_stub_mutation_result replace_stub_bytes(
    uint8_t *stub, const uint8_t expected[CODEX_STUB_SIZE],
    const uint8_t replacement[CODEX_STUB_SIZE]) {
    if (stub == NULL || memcmp(stub, expected, CODEX_STUB_SIZE) != 0) {
        return CODEX_STUB_MUTATION_FAILED_CLEAN;
    }
    size_t page_size = (size_t)getpagesize();
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0 ||
        ((uintptr_t)stub & (page_size - 1U)) >
            page_size - CODEX_STUB_SIZE) {
        return CODEX_STUB_MUTATION_FAILED_CLEAN;
    }

    mach_vm_address_t region_address = (mach_vm_address_t)(uintptr_t)stub;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t region_info = {0};
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t region_result = mach_vm_region(
        mach_task_self(), &region_address, &region_size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region_info,
        &region_count, &object_name);
    if (object_name != MACH_PORT_NULL) {
        (void)mach_port_deallocate(mach_task_self(), object_name);
    }
    uint64_t region_end = 0;
    uint64_t stub_end = 0;
    if (region_result != KERN_SUCCESS ||
        !add_u64(region_address, region_size, &region_end) ||
        !add_u64((uint64_t)(uintptr_t)stub, CODEX_STUB_SIZE, &stub_end) ||
        region_address > (mach_vm_address_t)(uintptr_t)stub ||
        stub_end > region_end ||
        (region_info.protection &
         (VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE)) !=
            (VM_PROT_READ | VM_PROT_EXECUTE)) {
        return CODEX_STUB_MUTATION_FAILED_CLEAN;
    }

    mach_vm_address_t page =
        (mach_vm_address_t)((uintptr_t)stub & ~(page_size - 1U));
    kern_return_t writable = mach_vm_protect(
        mach_task_self(), page, (mach_vm_size_t)page_size, false,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (writable != KERN_SUCCESS) {
        return CODEX_STUB_MUTATION_FAILED_CLEAN;
    }
    if (memcmp(stub, expected, CODEX_STUB_SIZE) != 0) {
        kern_return_t restore_protection = mach_vm_protect(
            mach_task_self(), page, (mach_vm_size_t)page_size, false,
            region_info.protection);
        return restore_protection == KERN_SUCCESS
            ? CODEX_STUB_MUTATION_FAILED_CLEAN
            : CODEX_STUB_MUTATION_PARTIAL;
    }

    memcpy(stub, replacement, CODEX_STUB_SIZE);
    sys_icache_invalidate(stub, CODEX_STUB_SIZE);
    kern_return_t restored = mach_vm_protect(
        mach_task_self(), page, (mach_vm_size_t)page_size, false,
        region_info.protection);
    if (restored == KERN_SUCCESS &&
        memcmp(stub, replacement, CODEX_STUB_SIZE) == 0) {
        return CODEX_STUB_MUTATION_OK;
    }

    if (restored == KERN_SUCCESS) {
        writable = mach_vm_protect(
            mach_task_self(), page, (mach_vm_size_t)page_size, false,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (writable != KERN_SUCCESS) {
            return CODEX_STUB_MUTATION_PARTIAL;
        }
    }
    memcpy(stub, expected, CODEX_STUB_SIZE);
    sys_icache_invalidate(stub, CODEX_STUB_SIZE);
    restored = mach_vm_protect(
        mach_task_self(), page, (mach_vm_size_t)page_size, false,
        region_info.protection);
    return restored == KERN_SUCCESS &&
                   memcmp(stub, expected, CODEX_STUB_SIZE) == 0
        ? CODEX_STUB_MUTATION_FAILED_CLEAN
        : CODEX_STUB_MUTATION_PARTIAL;
}

static bool current_bytes_equal(const uint8_t *stub,
                                const uint8_t bytes[CODEX_STUB_SIZE]) {
    return stub != NULL && memcmp(stub, bytes, CODEX_STUB_SIZE) == 0;
}

/*
 * A 20-byte branch sequence is not an atomic arm64 text update.  Keep every
 * other task thread stopped for the complete two-stub transaction, and do
 * not even make the dyld pages writable until two consecutive task_threads
 * snapshots contain no untracked thread.  THREAD_IDENTIFIER_INFO provides a
 * system-wide identity for the current thread and avoids relying on whether
 * two send rights happen to have the same name in this IPC space.
 *
 * The fixed array deliberately avoids allocation while peers are suspended.
 * A host with more threads fails closed before any text is changed.
 */
struct codex_suspended_thread {
    thread_act_t port;
    uint64_t identifier;
};

struct codex_thread_quiescence {
    struct codex_suspended_thread threads[CODEX_MAX_QUIESCED_THREADS];
    uint32_t count;
    uint32_t resumed;
    uint32_t observed;
    uint32_t attempts;
    uint32_t passes;
    uint32_t stable_passes;
    kern_return_t quiesce_kern_return;
    kern_return_t resume_kern_return;
    uint64_t unsafe_thread_id;
    uintptr_t unsafe_thread_pc;
};

static kern_return_t thread_identifier(thread_act_t thread,
                                       uint64_t *identifier) {
    thread_identifier_info_data_t info = {0};
    mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
    kern_return_t result = thread_info(
        thread, THREAD_IDENTIFIER_INFO, (thread_info_t)&info, &count);
    if (result != KERN_SUCCESS) {
        return result;
    }
    if (count != THREAD_IDENTIFIER_INFO_COUNT || info.thread_id == 0) {
        return KERN_FAILURE;
    }
    *identifier = info.thread_id;
    return KERN_SUCCESS;
}

static bool quiescence_contains_thread(
    const struct codex_thread_quiescence *quiescence,
    uint64_t identifier) {
    for (uint32_t index = 0; index < quiescence->count; ++index) {
        if (quiescence->threads[index].identifier == identifier) {
            return true;
        }
    }
    return false;
}

static void deallocate_thread_array_storage(thread_act_array_t threads,
                                            mach_msg_type_number_t count) {
    if (threads == NULL) {
        return;
    }
    vm_size_t size = (vm_size_t)count * (vm_size_t)sizeof(*threads);
    (void)vm_deallocate(mach_task_self(), (vm_address_t)threads, size);
}

static uint32_t quiesce_other_threads_once(
    struct codex_thread_quiescence *quiescence,
    uintptr_t mmap_page, uintptr_t fcntl_page) {
    mach_port_t current_thread = mach_thread_self();
    if (current_thread == MACH_PORT_NULL) {
        quiescence->quiesce_kern_return = KERN_FAILURE;
        return CODEX_DYLD_JB_HOOK_ERROR_THREAD_ID;
    }

    uint64_t current_identifier = 0;
    kern_return_t result = thread_identifier(current_thread,
                                               &current_identifier);
    if (result != KERN_SUCCESS) {
        quiescence->quiesce_kern_return = result;
        (void)mach_port_deallocate(mach_task_self(), current_thread);
        return CODEX_DYLD_JB_HOOK_ERROR_THREAD_ID;
    }

    uint32_t error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_UNSTABLE;
    for (uint32_t pass = 1; pass <= CODEX_MAX_QUIESCE_PASSES; ++pass) {
        quiescence->passes = pass;
        thread_act_array_t threads = NULL;
        mach_msg_type_number_t thread_count = 0;
        result = task_threads(mach_task_self(), &threads, &thread_count);
        if (result != KERN_SUCCESS) {
            quiescence->quiesce_kern_return = result;
            error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_ENUMERATION;
            break;
        }
        if (thread_count > quiescence->observed) {
            quiescence->observed = thread_count;
        }
        if (thread_count > CODEX_MAX_QUIESCED_THREADS + 1U) {
            for (mach_msg_type_number_t index = 0;
                 index < thread_count; ++index) {
                (void)mach_port_deallocate(mach_task_self(), threads[index]);
            }
            deallocate_thread_array_storage(threads, thread_count);
            error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_CAPACITY;
            break;
        }

        bool saw_current = false;
        uint32_t newly_suspended = 0;
        uint32_t pass_error = CODEX_DYLD_JB_HOOK_ERROR_NONE;
        for (mach_msg_type_number_t index = 0;
             index < thread_count; ++index) {
            thread_act_t thread = threads[index];
            if (pass_error != CODEX_DYLD_JB_HOOK_ERROR_NONE) {
                (void)mach_port_deallocate(mach_task_self(), thread);
                continue;
            }

            uint64_t identifier = 0;
            result = thread_identifier(thread, &identifier);
            if (result != KERN_SUCCESS) {
                quiescence->quiesce_kern_return = result;
                pass_error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_ID;
                (void)mach_port_deallocate(mach_task_self(), thread);
                continue;
            }
            if (identifier == current_identifier) {
                saw_current = true;
                (void)mach_port_deallocate(mach_task_self(), thread);
                continue;
            }
            if (quiescence_contains_thread(quiescence, identifier)) {
                (void)mach_port_deallocate(mach_task_self(), thread);
                continue;
            }
            if (quiescence->count >= CODEX_MAX_QUIESCED_THREADS) {
                pass_error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_CAPACITY;
                (void)mach_port_deallocate(mach_task_self(), thread);
                continue;
            }

            result = thread_suspend(thread);
            if (result != KERN_SUCCESS) {
                quiescence->quiesce_kern_return = result;
                pass_error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_SUSPEND;
                (void)mach_port_deallocate(mach_task_self(), thread);
                continue;
            }
            struct codex_suspended_thread *retained =
                &quiescence->threads[quiescence->count++];
            retained->port = thread;
            retained->identifier = identifier;
            ++newly_suspended;

            arm_thread_state64_t state = {0};
            mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
            result = thread_get_state(
                thread, ARM_THREAD_STATE64, (thread_state_t)&state,
                &state_count);
            if (result != KERN_SUCCESS ||
                state_count != ARM_THREAD_STATE64_COUNT) {
                quiescence->quiesce_kern_return =
                    result == KERN_SUCCESS ? KERN_FAILURE : result;
                pass_error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_STATE;
                continue;
            }
            uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(state);
            int page_size_value = getpagesize();
            if (page_size_value <= 0 ||
                ((size_t)page_size_value &
                 ((size_t)page_size_value - 1U)) != 0) {
                quiescence->quiesce_kern_return = KERN_FAILURE;
                pass_error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_STATE;
                continue;
            }
            uintptr_t page_mask = ~((uintptr_t)page_size_value - 1U);
            uintptr_t pc_page = pc & page_mask;
            if (pc_page == mmap_page || pc_page == fcntl_page) {
                quiescence->unsafe_thread_id = identifier;
                quiescence->unsafe_thread_pc = pc;
                pass_error =
                    CODEX_DYLD_JB_HOOK_ERROR_THREAD_IN_PATCH_PAGE;
            }
        }
        deallocate_thread_array_storage(threads, thread_count);

        if (pass_error != CODEX_DYLD_JB_HOOK_ERROR_NONE) {
            error = pass_error;
            break;
        }
        if (!saw_current) {
            quiescence->quiesce_kern_return = KERN_FAILURE;
            error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_ID;
            break;
        }
        if (newly_suspended == 0) {
            ++quiescence->stable_passes;
        } else {
            quiescence->stable_passes = 0;
        }
        if (quiescence->stable_passes >=
            CODEX_REQUIRED_STABLE_QUIESCE_PASSES) {
            error = CODEX_DYLD_JB_HOOK_ERROR_NONE;
            break;
        }
    }

    (void)mach_port_deallocate(mach_task_self(), current_thread);
    return error;
}

static uint32_t resume_quiesced_threads(
    struct codex_thread_quiescence *quiescence) {
    quiescence->resumed = 0;
    quiescence->resume_kern_return = KERN_SUCCESS;
    for (uint32_t reverse = quiescence->count; reverse > 0; --reverse) {
        struct codex_suspended_thread *entry =
            &quiescence->threads[reverse - 1U];
        kern_return_t result = KERN_FAILURE;
        for (uint32_t attempt = 0;
             attempt < CODEX_MAX_RESUME_ATTEMPTS; ++attempt) {
            result = thread_resume(entry->port);
            if (result == KERN_SUCCESS) {
                break;
            }
        }
        if (result == KERN_SUCCESS) {
            ++quiescence->resumed;
        } else if (quiescence->resume_kern_return == KERN_SUCCESS) {
            quiescence->resume_kern_return = result;
        }
        (void)mach_port_deallocate(mach_task_self(), entry->port);
        entry->port = MACH_PORT_NULL;
    }
    return quiescence->resume_kern_return == KERN_SUCCESS
        ? CODEX_DYLD_JB_HOOK_ERROR_NONE
        : CODEX_DYLD_JB_HOOK_ERROR_THREAD_RESUME;
}

static uint32_t acquire_patch_quiescence(
    struct codex_thread_quiescence *quiescence,
    uint8_t *mmap_stub, uint8_t *fcntl_stub) {
    int page_size_value = getpagesize();
    if (page_size_value <= 0 ||
        ((size_t)page_size_value & ((size_t)page_size_value - 1U)) != 0 ||
        mmap_stub == NULL || fcntl_stub == NULL) {
        memset(quiescence, 0, sizeof(*quiescence));
        quiescence->quiesce_kern_return = KERN_FAILURE;
        return CODEX_DYLD_JB_HOOK_ERROR_THREAD_STATE;
    }
    uintptr_t page_mask = ~((uintptr_t)page_size_value - 1U);
    uintptr_t mmap_page = (uintptr_t)mmap_stub & page_mask;
    uintptr_t fcntl_page = (uintptr_t)fcntl_stub & page_mask;
    uint32_t error = CODEX_DYLD_JB_HOOK_ERROR_THREAD_UNSTABLE;
    for (uint32_t attempt = 1;
         attempt <= CODEX_MAX_QUIESCE_ATTEMPTS; ++attempt) {
        memset(quiescence, 0, sizeof(*quiescence));
        quiescence->attempts = attempt;
        error = quiesce_other_threads_once(
            quiescence, mmap_page, fcntl_page);
        if (error == CODEX_DYLD_JB_HOOK_ERROR_NONE) {
            return error;
        }
        uint32_t resume_error = resume_quiesced_threads(quiescence);
        if (resume_error != CODEX_DYLD_JB_HOOK_ERROR_NONE) {
            return resume_error;
        }
        if (attempt < CODEX_MAX_QUIESCE_ATTEMPTS) {
            (void)sched_yield();
        }
    }
    return error;
}

static void record_quiescence_status(
    const struct codex_thread_quiescence *quiescence) {
    gStatus.quiesce_attempts = quiescence->attempts;
    gStatus.quiesce_passes = quiescence->passes;
    gStatus.threads_observed = quiescence->observed;
    gStatus.threads_suspended = quiescence->count;
    gStatus.threads_resumed = quiescence->resumed;
    gStatus.quiesce_kern_return = quiescence->quiesce_kern_return;
    gStatus.resume_kern_return = quiescence->resume_kern_return;
    gStatus.unsafe_thread_id = quiescence->unsafe_thread_id;
    gStatus.unsafe_thread_pc = quiescence->unsafe_thread_pc;
}

__attribute__((visibility("default"))) int
codex_dyld_jb_hook_install(void) {
    uint32_t observed = atomic_load_explicit(&gState, memory_order_acquire);
    if (observed == CODEX_DYLD_JB_HOOK_INSTALLED) {
        return 0;
    }
    uint32_t expected = observed == CODEX_DYLD_JB_HOOK_RESTORED
        ? CODEX_DYLD_JB_HOOK_RESTORED
        : CODEX_DYLD_JB_HOOK_UNINITIALIZED;
    if (observed != expected ||
        !atomic_compare_exchange_strong_explicit(
            &gState, &expected, CODEX_DYLD_JB_HOOK_INSTALLING,
            memory_order_acq_rel, memory_order_acquire)) {
        return observed == CODEX_DYLD_JB_HOOK_FAILED ||
                       observed == CODEX_DYLD_JB_HOOK_PARTIAL
            ? (int)gStatus.error
            : CODEX_DYLD_JB_HOOK_ERROR_BUSY;
    }

    memset(&gStatus, 0, sizeof(gStatus));
    gStatus.size = sizeof(gStatus);
    gStatus.version = CODEX_DYLD_JB_HOOK_ABI_VERSION;
    gStatus.state = CODEX_DYLD_JB_HOOK_INSTALLING;
    gStatus.pid = getpid();
    memcpy(gStatus.expected_dyld_uuid, kExpectedDyldUUID,
           sizeof(kExpectedDyldUUID));
    memcpy(gStatus.expected_dyld_sha256, kExpectedDyldSHA256,
           sizeof(kExpectedDyldSHA256));
    memcpy(gStatus.expected_mmap_prefix, kMmapStubPrefix,
           sizeof(kMmapStubPrefix));
    memcpy(gStatus.expected_fcntl_prefix, kFcntlStubPrefix,
           sizeof(kFcntlStubPrefix));
    errno = 0;
    int csops_result = csops(getpid(), CODEX_CS_OPS_STATUS,
                             &gStatus.cs_flags,
                             sizeof(gStatus.cs_flags));
    if (csops_result != 0) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_CSOPS);
    }
    if ((gStatus.cs_flags & (CODEX_CS_VALID | CODEX_CS_DEBUGGED)) !=
            (CODEX_CS_VALID | CODEX_CS_DEBUGGED) ||
        (gStatus.cs_flags & (CODEX_CS_HARD | CODEX_CS_KILL)) != 0) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_HOST_POLICY);
    }
    if (!fixed_self_path()) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_SELF_PATH);
    }

    task_dyld_info_data_t dyld_info = {0};
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kern_return_t dyld_info_result = task_info(
        mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info,
        &dyld_info_count);
    if (dyld_info_result != KERN_SUCCESS ||
        dyld_info_count != TASK_DYLD_INFO_COUNT ||
        dyld_info.all_image_info_addr == 0) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_DYLD_INFO);
    }
    const struct dyld_all_image_infos *all_image_infos =
        (const struct dyld_all_image_infos *)(uintptr_t)
            dyld_info.all_image_info_addr;
    const struct mach_header_64 *dyld_header =
        (const struct mach_header_64 *)all_image_infos->dyldImageLoadAddress;
    gStatus.dyld_header = (uint64_t)(uintptr_t)dyld_header;

    struct codex_pattern_result mmap_result = {0};
    struct codex_pattern_result fcntl_result = {0};
    if (!scan_dyld_patterns(dyld_header, &mmap_result, &fcntl_result,
                            gStatus.dyld_uuid)) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_DYLD_MACHO);
    }
    gStatus.mmap_pattern_count = mmap_result.count;
    gStatus.fcntl_pattern_count = fcntl_result.count;
    gStatus.mmap_stub = (uint64_t)(uintptr_t)mmap_result.address;
    gStatus.fcntl_stub = (uint64_t)(uintptr_t)fcntl_result.address;
    memcpy(gStatus.observed_mmap_prefix, mmap_result.prefix,
           sizeof(mmap_result.prefix));
    memcpy(gStatus.observed_fcntl_prefix, fcntl_result.prefix,
           sizeof(fcntl_result.prefix));
    if (memcmp(gStatus.dyld_uuid, kExpectedDyldUUID,
               sizeof(kExpectedDyldUUID)) != 0) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_DYLD_UUID);
    }
    if (mmap_result.count != 1U || mmap_result.address == NULL) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_MMAP_PATTERN);
    }
    if (fcntl_result.count != 1U || fcntl_result.address == NULL ||
        fcntl_result.address == mmap_result.address) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_FCNTL_PATTERN);
    }
    if (memcmp(mmap_result.prefix, kMmapStubPrefix,
               sizeof(kMmapStubPrefix)) != 0) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_MMAP_PREFIX);
    }
    if (memcmp(fcntl_result.prefix, kFcntlStubPrefix,
               sizeof(kFcntlStubPrefix)) != 0) {
        return publish_status(CODEX_DYLD_JB_HOOK_FAILED,
                              CODEX_DYLD_JB_HOOK_ERROR_FCNTL_PREFIX);
    }

    gMmapStub = mmap_result.address;
    gFcntlStub = fcntl_result.address;
    make_branch_patch((void *)&codex_managed_dyld_mmap, gMmapPatch);
    make_branch_patch((void *)&codex_managed_dyld_fcntl, gFcntlPatch);

    struct codex_thread_quiescence quiescence = {0};
    uint32_t quiesce_error = acquire_patch_quiescence(
        &quiescence, gMmapStub, gFcntlStub);
    record_quiescence_status(&quiescence);
    if (quiesce_error != CODEX_DYLD_JB_HOOK_ERROR_NONE) {
        return publish_status(
            quiesce_error == CODEX_DYLD_JB_HOOK_ERROR_THREAD_RESUME
                ? CODEX_DYLD_JB_HOOK_PARTIAL
                : CODEX_DYLD_JB_HOOK_FAILED,
            quiesce_error);
    }

    uint32_t final_state = CODEX_DYLD_JB_HOOK_INSTALLED;
    uint32_t final_error = CODEX_DYLD_JB_HOOK_ERROR_NONE;
    enum codex_stub_mutation_result mmap_patch = replace_stub_bytes(
        gMmapStub, kMmapStubPrefix, gMmapPatch);
    if (mmap_patch != CODEX_STUB_MUTATION_OK) {
        final_state = mmap_patch == CODEX_STUB_MUTATION_PARTIAL
                ? CODEX_DYLD_JB_HOOK_PARTIAL
                : CODEX_DYLD_JB_HOOK_FAILED;
        final_error = CODEX_DYLD_JB_HOOK_ERROR_MMAP_PATCH;
    } else {
        enum codex_stub_mutation_result fcntl_patch = replace_stub_bytes(
            gFcntlStub, kFcntlStubPrefix, gFcntlPatch);
        if (fcntl_patch != CODEX_STUB_MUTATION_OK) {
            enum codex_stub_mutation_result fcntl_rollback =
                current_bytes_equal(gFcntlStub, gFcntlPatch)
                    ? replace_stub_bytes(gFcntlStub, gFcntlPatch,
                                         kFcntlStubPrefix)
                    : (current_bytes_equal(gFcntlStub, kFcntlStubPrefix)
                           ? CODEX_STUB_MUTATION_OK
                           : CODEX_STUB_MUTATION_PARTIAL);
            enum codex_stub_mutation_result mmap_rollback =
                replace_stub_bytes(gMmapStub, gMmapPatch,
                                   kMmapStubPrefix);
            bool rollback_clean =
                fcntl_rollback != CODEX_STUB_MUTATION_PARTIAL &&
                mmap_rollback == CODEX_STUB_MUTATION_OK &&
                current_bytes_equal(gFcntlStub, kFcntlStubPrefix) &&
                current_bytes_equal(gMmapStub, kMmapStubPrefix);
            final_state = rollback_clean ? CODEX_DYLD_JB_HOOK_FAILED
                                         : CODEX_DYLD_JB_HOOK_PARTIAL;
            final_error = rollback_clean
                ? CODEX_DYLD_JB_HOOK_ERROR_FCNTL_PATCH
                : CODEX_DYLD_JB_HOOK_ERROR_ROLLBACK;
        }
    }

    uint32_t resume_error = resume_quiesced_threads(&quiescence);
    record_quiescence_status(&quiescence);
    if (resume_error != CODEX_DYLD_JB_HOOK_ERROR_NONE) {
        final_state = CODEX_DYLD_JB_HOOK_PARTIAL;
        final_error = resume_error;
    }
    return publish_status(final_state, final_error);
}

__attribute__((visibility("default"))) int
codex_dyld_jb_hook_restore(void) {
    uint32_t expected = CODEX_DYLD_JB_HOOK_INSTALLED;
    if (!atomic_compare_exchange_strong_explicit(
            &gState, &expected, CODEX_DYLD_JB_HOOK_RESTORING,
            memory_order_acq_rel, memory_order_acquire)) {
        return expected == CODEX_DYLD_JB_HOOK_RESTORED ||
                       expected == CODEX_DYLD_JB_HOOK_UNINITIALIZED
            ? 0
            : CODEX_DYLD_JB_HOOK_ERROR_BUSY;
    }
    gStatus.state = CODEX_DYLD_JB_HOOK_RESTORING;

    struct codex_thread_quiescence quiescence = {0};
    uint32_t quiesce_error = acquire_patch_quiescence(
        &quiescence, gMmapStub, gFcntlStub);
    record_quiescence_status(&quiescence);
    if (quiesce_error != CODEX_DYLD_JB_HOOK_ERROR_NONE) {
        /* A clean quiescence failure leaves both live hooks untouched. */
        return publish_status(
            quiesce_error == CODEX_DYLD_JB_HOOK_ERROR_THREAD_RESUME
                ? CODEX_DYLD_JB_HOOK_PARTIAL
                : CODEX_DYLD_JB_HOOK_INSTALLED,
            quiesce_error);
    }

    enum codex_stub_mutation_result fcntl_restore = replace_stub_bytes(
        gFcntlStub, gFcntlPatch, kFcntlStubPrefix);
    enum codex_stub_mutation_result mmap_restore = replace_stub_bytes(
        gMmapStub, gMmapPatch, kMmapStubPrefix);
    bool restored = fcntl_restore == CODEX_STUB_MUTATION_OK &&
                    mmap_restore == CODEX_STUB_MUTATION_OK &&
                    current_bytes_equal(gFcntlStub, kFcntlStubPrefix) &&
                    current_bytes_equal(gMmapStub, kMmapStubPrefix);

    uint32_t resume_error = resume_quiesced_threads(&quiescence);
    record_quiescence_status(&quiescence);
    if (resume_error != CODEX_DYLD_JB_HOOK_ERROR_NONE) {
        return publish_status(CODEX_DYLD_JB_HOOK_PARTIAL,
                              resume_error);
    }
    return publish_status(
        restored ? CODEX_DYLD_JB_HOOK_RESTORED
                 : CODEX_DYLD_JB_HOOK_PARTIAL,
        restored ? CODEX_DYLD_JB_HOOK_ERROR_NONE
                 : CODEX_DYLD_JB_HOOK_ERROR_RESTORE);
}

__attribute__((visibility("default"))) int
codex_dyld_jb_hook_copy_status(
    struct codex_dyld_jb_hook_status_v1 *status, size_t status_size) {
    if (status == NULL ||
        status_size < sizeof(struct codex_dyld_jb_hook_status_v1)) {
        return EINVAL;
    }
    uint32_t before = atomic_load_explicit(&gState, memory_order_acquire);
    if (before == CODEX_DYLD_JB_HOOK_INSTALLING ||
        before == CODEX_DYLD_JB_HOOK_RESTORING) {
        return EBUSY;
    }
    struct codex_dyld_jb_hook_status_v1 snapshot = gStatus;
    snapshot.state = before;
    snapshot.anonymous_rx_mappings =
        atomic_load_explicit(&gAnonymousRxMappings, memory_order_relaxed);
    snapshot.signature_bypasses =
        atomic_load_explicit(&gSignatureBypasses, memory_order_relaxed);
    snapshot.policy_rejections =
        atomic_load_explicit(&gPolicyRejections, memory_order_relaxed);
    atomic_thread_fence(memory_order_acquire);
    if (before != atomic_load_explicit(&gState, memory_order_acquire)) {
        return EAGAIN;
    }
    memcpy(status, &snapshot, sizeof(snapshot));
    return 0;
}

__attribute__((visibility("default"))) uint64_t
codex_dyld_jb_hook_status_word(void) {
    uint32_t state = atomic_load_explicit(&gState, memory_order_acquire);
    return ((uint64_t)state << 32U) | (uint64_t)gStatus.error;
}

__attribute__((constructor)) static void codex_dyld_jb_hook_start(void) {
    (void)codex_dyld_jb_hook_install();
}

__attribute__((destructor)) static void codex_dyld_jb_hook_stop(void) {
    if (atomic_load_explicit(&gState, memory_order_acquire) ==
        CODEX_DYLD_JB_HOOK_INSTALLED) {
        (void)codex_dyld_jb_hook_restore();
    }
}
