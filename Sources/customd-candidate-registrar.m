#import <Foundation/Foundation.h>

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * This executable is deliberately single-purpose.  customd loads it through
 * codex-exec-worker after spawning that worker with cryptexd's ptrauth task
 * port.  The resulting process can sign the call targets below for this exact
 * cryptexd build; no caller-controlled plist, session, label, or program is
 * accepted here.
 */

#define REGISTRAR_CS_OPS_STATUS 0U
#define REGISTRAR_CS_VALID 0x00000001U
#define REGISTRAR_PROC_PIDTBSDINFO 3
#define REGISTRAR_PROC_PIDUNIQIDENTIFIERINFO 17
#define REGISTRAR_MAXCOMLEN 16
#define REGISTRAR_MAX_LOAD_COMMANDS 4096U
#define REGISTRAR_MAX_LOAD_COMMAND_BYTES (16U * 1024U * 1024U)
#define REGISTRAR_REMOTE_STACK_SIZE 65536U
#define REGISTRAR_USER_VA_MASK UINT64_C(0x0000ffffffffffff)

#define CRYPTEXD_LAUNCHD_SESSION_CREATE_JOB_OFFSET UINT64_C(0x4a7e8)
#define CRYPTEXD_XPC_CREATE_FROM_PLIST_OFFSET UINT64_C(0x6d754)
#define CRYPTEXD_XPC_RELEASE_OFFSET UINT64_C(0x6d974)
#define CRYPTEXD_POOL_POP_OFFSET UINT64_C(0x6cbc4)
#define CRYPTEXD_POOL_PUSH_OFFSET UINT64_C(0x6cbd4)
#define CRYPTEXD_NSARRAY_ONE_OBJECT_OFFSET UINT64_C(0x6dce0)
#define CRYPTEXD_SUBMIT_ALL_OFFSET UINT64_C(0x6efc0)
#define CRYPTEXD_NSARRAY_CLASS_SLOT_OFFSET UINT64_C(0x8cde0)
#define CRYPTEXD_OSLAUNCHDJOB_CLASS_SLOT_OFFSET UINT64_C(0x8cfb8)

static const char *const kCryptexdPath = "/usr/libexec/cryptexd";
static const char *const kLibobjcPath = "/usr/lib/libobjc.A.dylib";
static const char *const kCandidateLabel =
    "com.openai.codex.springboard-live-candidate";
static const char *const kCandidateProgram =
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard";
static const char *const kCandidateSession =
    "com.openai.codex.springboard-live-proof";
static const char kCandidatePlist[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\"><dict>\n"
    "<key>Label</key><string>"
    "com.openai.codex.springboard-live-candidate</string>\n"
    "<key>Program</key><string>"
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard</string>\n"
    "<key>UserName</key><string>mobile</string>\n"
    "<key>POSIXSpawnType</key><string>App</string>\n"
    "<key>CFBundleIdentifier</key><string>com.apple.springboard</string>\n"
    "<key>_LaunchType</key><integer>1</integer>\n"
    "</dict></plist>";

static const uint8_t kExpectedCryptexdUUID[16] = {
    0x26, 0x1f, 0x91, 0xf3, 0x70, 0x16, 0x35, 0xa2,
    0x9a, 0x84, 0xc8, 0x5d, 0x2b, 0x6a, 0x83, 0x4e,
};

struct registrar_expected_code {
    uint64_t offset;
    const uint8_t *bytes;
    size_t size;
};

static const uint8_t kCreateJobCode[] = {
    0x7f, 0x23, 0x03, 0xd5, 0xff, 0x43, 0x02, 0xd1,
    0xfa, 0x67, 0x04, 0xa9, 0xf8, 0x5f, 0x05, 0xa9,
    0xf6, 0x57, 0x06, 0xa9, 0xf4, 0x4f, 0x07, 0xa9,
    0xfd, 0x7b, 0x08, 0xa9, 0xfd, 0x03, 0x02, 0x91,
};
static const uint8_t kXpcCreateCode[] = {
    0xf1, 0x00, 0x00, 0xf0, 0x31, 0xa2, 0x27, 0x91,
    0x30, 0x02, 0x40, 0xf9, 0x11, 0x0a, 0x1f, 0xd7,
};
static const uint8_t kXpcReleaseCode[] = {
    0xf1, 0x00, 0x00, 0xf0, 0x31, 0xe2, 0x2b, 0x91,
    0x30, 0x02, 0x40, 0xf9, 0x11, 0x0a, 0x1f, 0xd7,
};
static const uint8_t kPoolPopCode[] = {
    0xf1, 0x00, 0x00, 0xf0, 0x31, 0x42, 0x35, 0x91,
    0x30, 0x02, 0x40, 0xf9, 0x11, 0x0a, 0x1f, 0xd7,
};
static const uint8_t kPoolPushCode[] = {
    0xf1, 0x00, 0x00, 0xf0, 0x31, 0x62, 0x35, 0x91,
    0x30, 0x02, 0x40, 0xf9, 0x11, 0x0a, 0x1f, 0xd7,
};
static const uint8_t kNSArrayCode[] = {
    0x21, 0x01, 0x00, 0x90, 0x21, 0xe8, 0x42, 0xf9,
    0xf1, 0x00, 0x00, 0xd0, 0x31, 0x82, 0x36, 0x91,
    0x30, 0x02, 0x40, 0xf9, 0x11, 0x0a, 0x1f, 0xd7,
};
static const uint8_t kSubmitAllCode[] = {
    0x01, 0x01, 0x00, 0xf0, 0x21, 0x44, 0x45, 0xf9,
    0xf1, 0x00, 0x00, 0xb0, 0x31, 0x82, 0x36, 0x91,
    0x30, 0x02, 0x40, 0xf9, 0x11, 0x0a, 0x1f, 0xd7,
};

static const struct registrar_expected_code kExpectedCode[] = {
    {CRYPTEXD_LAUNCHD_SESSION_CREATE_JOB_OFFSET, kCreateJobCode,
     sizeof(kCreateJobCode)},
    {CRYPTEXD_XPC_CREATE_FROM_PLIST_OFFSET, kXpcCreateCode,
     sizeof(kXpcCreateCode)},
    {CRYPTEXD_XPC_RELEASE_OFFSET, kXpcReleaseCode,
     sizeof(kXpcReleaseCode)},
    {CRYPTEXD_POOL_POP_OFFSET, kPoolPopCode, sizeof(kPoolPopCode)},
    {CRYPTEXD_POOL_PUSH_OFFSET, kPoolPushCode, sizeof(kPoolPushCode)},
    {CRYPTEXD_NSARRAY_ONE_OBJECT_OFFSET, kNSArrayCode,
     sizeof(kNSArrayCode)},
    {CRYPTEXD_SUBMIT_ALL_OFFSET, kSubmitAllCode,
     sizeof(kSubmitAllCode)},
};

struct registrar_proc_bsdinfo {
    uint32_t pbi_flags;
    uint32_t pbi_status;
    uint32_t pbi_xstatus;
    uint32_t pbi_pid;
    uint32_t pbi_ppid;
    uid_t pbi_uid;
    gid_t pbi_gid;
    uid_t pbi_ruid;
    gid_t pbi_rgid;
    uid_t pbi_svuid;
    gid_t pbi_svgid;
    uint32_t reserved;
    char pbi_comm[REGISTRAR_MAXCOMLEN];
    char pbi_name[2 * REGISTRAR_MAXCOMLEN];
    uint32_t pbi_nfiles;
    uint32_t pbi_pgid;
    uint32_t pbi_pjobc;
    uint32_t e_tdev;
    uint32_t e_tpgid;
    int32_t pbi_nice;
    uint64_t pbi_start_tvsec;
    uint64_t pbi_start_tvusec;
};

struct registrar_proc_unique_info {
    uint8_t uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_pid_version;
    uint64_t reserved2;
    uint64_t reserved3;
};

struct registrar_process_identity {
    pid_t pid;
    char path[PATH_MAX];
    struct registrar_proc_bsdinfo bsd;
    struct registrar_proc_unique_info unique;
    uint32_t csflags;
};

struct registrar_remote_allocation {
    mach_vm_address_t address;
    mach_vm_size_t size;
};

_Static_assert(sizeof(struct registrar_proc_bsdinfo) == 136,
               "proc bsd-info ABI changed");
_Static_assert(sizeof(struct registrar_proc_unique_info) == 56,
               "proc unique-info ABI changed");

extern int csops(pid_t pid, unsigned int operation, void *address,
                 size_t size);
extern int proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer,
                        int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffer_size);
extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *out_size);
extern kern_return_t mach_vm_write(vm_map_t target,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);
extern vm_address_t getRemoteImageAddress(task_t task,
                                           vm_address_t imageStartPtr,
                                           const char *imageName);
extern vm_address_t remoteDlSym(task_t task, vm_address_t imageStartPtr,
                                const char *symbolName);
extern bool codexPrewarmInjectionPrimitives(
    task_t task, vm_address_t allImageInfoAddress);
extern kern_return_t createRemotePthread(task_t task,
                                         vm_address_t allImageInfoAddress,
                                         thread_act_t *remotePthreadOut);
extern kern_return_t arbCall(task_t task, thread_act_t targetThread,
                             uint64_t *returnValue, bool willReturn,
                             vm_address_t function, int argumentCount, ...);

static mach_vm_address_t canonical_address(uint64_t value) {
    return (mach_vm_address_t)(value & REGISTRAR_USER_VA_MASK);
}

static bool parse_pid(const char *text, pid_t *pid_out) {
    if (text == NULL || pid_out == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 1 ||
        value > INT_MAX) {
        return false;
    }
    *pid_out = (pid_t)value;
    return true;
}

static bool read_remote_exact(task_t task, mach_vm_address_t address,
                              void *destination, size_t size) {
    if (!MACH_PORT_VALID(task) || address == 0 || destination == NULL ||
        size == 0 || size > UINT32_MAX) {
        return false;
    }
    mach_vm_size_t copied = 0;
    kern_return_t result = mach_vm_read_overwrite(
        task, address, (mach_vm_size_t)size,
        (mach_vm_address_t)(uintptr_t)destination, &copied);
    return result == KERN_SUCCESS && copied == (mach_vm_size_t)size;
}

static bool copy_bsd_info(pid_t pid,
                          struct registrar_proc_bsdinfo *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, REGISTRAR_PROC_PIDTBSDINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information) &&
           information->pbi_pid == (uint32_t)pid;
}

static bool copy_unique_info(
    pid_t pid, struct registrar_proc_unique_info *information) {
    memset(information, 0, sizeof(*information));
    int amount = proc_pidinfo(pid, REGISTRAR_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              information, (int)sizeof(*information));
    return amount == (int)sizeof(*information);
}

static bool identities_equal(const struct registrar_process_identity *left,
                             const struct registrar_process_identity *right) {
    return left->pid == right->pid && strcmp(left->path, right->path) == 0 &&
           left->bsd.pbi_uid == right->bsd.pbi_uid &&
           left->bsd.pbi_ppid == right->bsd.pbi_ppid &&
           left->unique.unique_id == right->unique.unique_id &&
           left->unique.parent_unique_id == right->unique.parent_unique_id &&
           left->unique.pid_version == right->unique.pid_version &&
           memcmp(left->unique.uuid, right->unique.uuid,
                  sizeof(left->unique.uuid)) == 0;
}

static bool bind_exact_cryptexd(pid_t pid,
                                struct registrar_process_identity *identity) {
    if (pid <= 1 || identity == NULL) {
        return false;
    }
    struct registrar_process_identity first = {.pid = pid};
    struct registrar_process_identity second = {.pid = pid};
    int first_length = proc_pidpath(pid, first.path, sizeof(first.path));
    bool first_valid = first_length > 0 &&
                       (size_t)first_length < sizeof(first.path) &&
                       strcmp(first.path, kCryptexdPath) == 0 &&
                       copy_bsd_info(pid, &first.bsd) &&
                       first.bsd.pbi_uid == 0 && first.bsd.pbi_ppid == 1 &&
                       copy_unique_info(pid, &first.unique) &&
                       memcmp(first.unique.uuid, kExpectedCryptexdUUID,
                              sizeof(kExpectedCryptexdUUID)) == 0 &&
                       csops(pid, REGISTRAR_CS_OPS_STATUS, &first.csflags,
                             sizeof(first.csflags)) == 0 &&
                       (first.csflags & REGISTRAR_CS_VALID) != 0;
    int second_length = proc_pidpath(pid, second.path, sizeof(second.path));
    bool second_valid = second_length > 0 &&
                        (size_t)second_length < sizeof(second.path) &&
                        strcmp(second.path, kCryptexdPath) == 0 &&
                        copy_bsd_info(pid, &second.bsd) &&
                        copy_unique_info(pid, &second.unique) &&
                        csops(pid, REGISTRAR_CS_OPS_STATUS, &second.csflags,
                              sizeof(second.csflags)) == 0;
    if (!first_valid || !second_valid || !identities_equal(&first, &second) ||
        second.csflags != first.csflags) {
        return false;
    }
    *identity = second;
    return true;
}

static bool process_still_exact(
    const struct registrar_process_identity *expected) {
    struct registrar_process_identity current = {0};
    return expected != NULL && bind_exact_cryptexd(expected->pid, &current) &&
           identities_equal(expected, &current);
}

static bool task_audit_token_matches(
    task_t task, const struct registrar_process_identity *identity) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t result = task_info(task, TASK_AUDIT_TOKEN,
                                     (task_info_t)&token, &count);
    return result == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT &&
           token.val[5] == (uint32_t)identity->pid &&
           token.val[7] == (uint32_t)identity->unique.pid_version;
}

static bool copy_remote_cstring(task_t task, mach_vm_address_t address,
                                char output[PATH_MAX]) {
    memset(output, 0, PATH_MAX);
    size_t used = 0;
    while (used + 1U < PATH_MAX) {
        size_t amount = PATH_MAX - used - 1U;
        if (amount > 256U) {
            amount = 256U;
        }
        if (!read_remote_exact(task, address + used, output + used,
                               amount)) {
            return false;
        }
        void *terminator = memchr(output + used, '\0', amount);
        if (terminator != NULL) {
            return true;
        }
        used += amount;
    }
    return false;
}

static bool validate_cryptexd_image(task_t task,
                                    mach_vm_address_t all_image_info_address,
                                    mach_vm_address_t *base_out) {
    struct dyld_all_image_infos infos = {0};
    if (!read_remote_exact(task, all_image_info_address, &infos,
                           sizeof(infos)) ||
        infos.version < 15U || !infos.libSystemInitialized ||
        infos.infoArrayCount == 0 || infos.infoArrayCount > 4096U) {
        fprintf(stderr,
                "candidate-registrar: cryptexd image stage=infos rejected "
                "version=%u count=%u initialized=%d\n",
                infos.version, infos.infoArrayCount,
                infos.libSystemInitialized);
        return false;
    }
    mach_vm_address_t info_array = canonical_address(
        (uint64_t)(uintptr_t)infos.infoArray);
    if (info_array == 0) {
        fprintf(stderr,
                "candidate-registrar: cryptexd image stage=array-address "
                "rejected count=%u\n",
                infos.infoArrayCount);
        return false;
    }
    size_t image_array_size =
        (size_t)infos.infoArrayCount * sizeof(struct dyld_image_info);
    struct dyld_image_info *images = malloc(image_array_size);
    if (images == NULL ||
        !read_remote_exact(task, info_array, images, image_array_size)) {
        fprintf(stderr,
                "candidate-registrar: cryptexd image stage=array-read "
                "rejected count=%u\n",
                infos.infoArrayCount);
        free(images);
        return false;
    }

    mach_vm_address_t base = 0;
    unsigned int matches = 0;
    unsigned int unreadable_paths = 0;
    for (uint32_t index = 0; index < infos.infoArrayCount; ++index) {
        mach_vm_address_t path_address = canonical_address(
            (uint64_t)(uintptr_t)images[index].imageFilePath);
        char path[PATH_MAX] = {0};
        if (path_address == 0 ||
            !copy_remote_cstring(task, path_address, path)) {
            ++unreadable_paths;
            continue;
        }
        if (strcmp(path, kCryptexdPath) != 0) {
            continue;
        }
        base = canonical_address(
            (uint64_t)(uintptr_t)images[index].imageLoadAddress);
        ++matches;
    }
    free(images);
    if (matches != 1U || base == 0) {
        fprintf(stderr,
                "candidate-registrar: cryptexd image stage=path-search "
                "rejected count=%u matches=%u unreadable=%u\n",
                infos.infoArrayCount, matches, unreadable_paths);
        return false;
    }

    struct mach_header_64 header = {0};
    if (!read_remote_exact(task, base, &header, sizeof(header)) ||
        header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        (header.cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E ||
        header.filetype != MH_EXECUTE || header.ncmds == 0 ||
        header.ncmds > REGISTRAR_MAX_LOAD_COMMANDS ||
        header.sizeofcmds == 0 ||
        header.sizeofcmds > REGISTRAR_MAX_LOAD_COMMAND_BYTES) {
        fprintf(stderr,
                "candidate-registrar: cryptexd image stage=header "
                "rejected magic=0x%x cpu=%d subtype=%d filetype=%u "
                "commands=%u bytes=%u\n",
                header.magic, header.cputype,
                header.cpusubtype & ~CPU_SUBTYPE_MASK, header.filetype,
                header.ncmds, header.sizeofcmds);
        return false;
    }
    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL ||
        !read_remote_exact(task, base + sizeof(header), commands,
                           header.sizeofcmds)) {
        fprintf(stderr,
                "candidate-registrar: cryptexd image "
                "stage=load-command-read rejected commands=%u bytes=%u\n",
                header.ncmds, header.sizeofcmds);
        free(commands);
        return false;
    }
    bool valid = true;
    bool found_uuid = false;
    size_t offset = 0;
    for (uint32_t index = 0; valid && index < header.ncmds; ++index) {
        if (offset > header.sizeofcmds - sizeof(struct load_command)) {
            valid = false;
            break;
        }
        const struct load_command *command =
            (const struct load_command *)(commands + offset);
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > header.sizeofcmds - offset) {
            valid = false;
            break;
        }
        if (command->cmd == LC_UUID) {
            if (found_uuid || command->cmdsize < sizeof(struct uuid_command)) {
                valid = false;
                break;
            }
            const struct uuid_command *uuid_command =
                (const struct uuid_command *)command;
            found_uuid = true;
            valid = memcmp(uuid_command->uuid, kExpectedCryptexdUUID,
                           sizeof(kExpectedCryptexdUUID)) == 0;
        }
        offset += command->cmdsize;
    }
    free(commands);
    if (!valid || !found_uuid || offset != header.sizeofcmds) {
        fprintf(stderr,
                "candidate-registrar: cryptexd image stage=uuid rejected "
                "valid=%d found=%d consumed=%zu bytes=%u\n",
                valid, found_uuid, offset, header.sizeofcmds);
        return false;
    }
    for (size_t index = 0;
         index < sizeof(kExpectedCode) / sizeof(kExpectedCode[0]); ++index) {
        uint8_t observed[sizeof(kCreateJobCode)] = {0};
        const struct registrar_expected_code *expected =
            &kExpectedCode[index];
        if (expected->size > sizeof(observed) ||
            !read_remote_exact(task, base + expected->offset, observed,
                               expected->size) ||
            memcmp(observed, expected->bytes, expected->size) != 0) {
            fprintf(stderr,
                    "candidate-registrar: cryptexd code mismatch "
                    "offset=0x%llx\n",
                    (unsigned long long)expected->offset);
            return false;
        }
    }
    *base_out = base;
    return true;
}

static bool remote_allocate_write(
    task_t task, const void *bytes, size_t size,
    struct registrar_remote_allocation *allocation) {
    if (bytes == NULL || size == 0 || size > UINT32_MAX ||
        allocation == NULL) {
        return false;
    }
    memset(allocation, 0, sizeof(*allocation));
    mach_vm_address_t address = 0;
    kern_return_t result = mach_vm_allocate(
        task, &address, (mach_vm_size_t)size, VM_FLAGS_ANYWHERE);
    if (result == KERN_SUCCESS) {
        result = mach_vm_write(task, address,
                               (vm_offset_t)(uintptr_t)bytes,
                               (mach_msg_type_number_t)size);
    }
    if (result != KERN_SUCCESS) {
        if (address != 0) {
            (void)mach_vm_deallocate(task, address, (mach_vm_size_t)size);
        }
        return false;
    }
    allocation->address = address;
    allocation->size = (mach_vm_size_t)size;
    return true;
}

static bool remote_allocate_string(
    task_t task, const char *string,
    struct registrar_remote_allocation *allocation) {
    return remote_allocate_write(task, string, strlen(string) + 1U,
                                 allocation);
}

static void remote_deallocate(
    task_t task, struct registrar_remote_allocation *allocation) {
    if (allocation != NULL && allocation->address != 0) {
        (void)mach_vm_deallocate(task, allocation->address,
                                 allocation->size);
        allocation->address = 0;
        allocation->size = 0;
    }
}

static bool remote_call(thread_act_t thread, task_t task,
                        mach_vm_address_t function, uint64_t *result_out,
                        unsigned int argument_count,
                        const uint64_t arguments[4]) {
    uint64_t result = 0;
    kern_return_t call_result = KERN_INVALID_ARGUMENT;
    switch (argument_count) {
        case 0:
            call_result = arbCall(task, thread, &result, true,
                                  (vm_address_t)function, 0);
            break;
        case 1:
            call_result = arbCall(task, thread, &result, true,
                                  (vm_address_t)function, 1, arguments[0]);
            break;
        case 2:
            call_result = arbCall(task, thread, &result, true,
                                  (vm_address_t)function, 2, arguments[0],
                                  arguments[1]);
            break;
        case 3:
            call_result = arbCall(task, thread, &result, true,
                                  (vm_address_t)function, 3, arguments[0],
                                  arguments[1], arguments[2]);
            break;
        case 4:
            call_result = arbCall(task, thread, &result, true,
                                  (vm_address_t)function, 4, arguments[0],
                                  arguments[1], arguments[2], arguments[3]);
            break;
        default:
            return false;
    }
    if (call_result != KERN_SUCCESS) {
        fprintf(stderr,
                "candidate-registrar: remote call failed function=0x%llx "
                "mach=%d\n",
                (unsigned long long)function, call_result);
        return false;
    }
    if (result_out != NULL) {
        *result_out = result;
    }
    return true;
}

static void terminate_remote_thread(task_t task, thread_act_t *thread) {
    if (thread == NULL || !MACH_PORT_VALID(*thread)) {
        return;
    }
    struct arm_unified_thread_state state = {0};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    mach_vm_address_t stack = 0;
    if (thread_suspend(*thread) == KERN_SUCCESS &&
        thread_get_state(*thread, ARM_THREAD_STATE64,
                         (thread_state_t)&state.ts_64, &count) ==
            KERN_SUCCESS) {
        uint64_t sp = (uint64_t)(uintptr_t)
            __darwin_arm_thread_state64_get_sp(state.ts_64);
        if (sp > REGISTRAR_REMOTE_STACK_SIZE / 2U) {
            stack = canonical_address(
                sp - REGISTRAR_REMOTE_STACK_SIZE / 2U);
        }
    }
    (void)thread_terminate(*thread);
    (void)mach_port_deallocate(mach_task_self(), *thread);
    *thread = MACH_PORT_NULL;
    if (stack != 0) {
        (void)mach_vm_deallocate(task, stack,
                                 REGISTRAR_REMOTE_STACK_SIZE);
    }
}

static bool register_candidate(task_t task, thread_act_t thread,
                               mach_vm_address_t cryptexd_base,
                               mach_vm_address_t all_image_info_address) {
    struct registrar_remote_allocation plist = {0};
    struct registrar_remote_allocation session = {0};
    struct registrar_remote_allocation nsarray_name = {0};
    struct registrar_remote_allocation job_class_name = {0};
    struct registrar_remote_allocation storage = {0};
    uint8_t storage_bytes[24] = {0};
    bool allocations_ready =
        remote_allocate_string(task, kCandidatePlist, &plist) &&
        remote_allocate_string(task, kCandidateSession, &session) &&
        remote_allocate_string(task, "NSArray", &nsarray_name) &&
        remote_allocate_string(task, "OSLaunchdJob", &job_class_name) &&
        remote_allocate_write(task, storage_bytes, sizeof(storage_bytes),
                              &storage);
    if (!allocations_ready) {
        fprintf(stderr,
                "candidate-registrar: remote allocation failed\n");
        goto failed;
    }

    vm_address_t libobjc = getRemoteImageAddress(
        task, (vm_address_t)all_image_info_address, kLibobjcPath);
    vm_address_t objc_get_class = libobjc != 0
                                      ? remoteDlSym(task, libobjc,
                                                    "_objc_getClass")
                                      : 0;
    if (libobjc == 0 || objc_get_class == 0) {
        fprintf(stderr,
                "candidate-registrar: objc_getClass resolution failed\n");
        goto failed;
    }

    uint64_t no_arguments[4] = {0};
    uint64_t pool = 0;
    if (!remote_call(thread, task,
                     cryptexd_base + CRYPTEXD_POOL_PUSH_OFFSET, &pool, 0,
                     no_arguments) ||
        pool == 0) {
        goto failed;
    }

    bool success = false;
    uint64_t dictionary = 0;
    uint64_t nsarray_class = 0;
    uint64_t job_class = 0;
    uint64_t class_argument[4] = {nsarray_name.address, 0, 0, 0};
    if (!remote_call(thread, task, objc_get_class, &nsarray_class, 1,
                     class_argument)) {
        goto cleanup_lifetime;
    }
    class_argument[0] = job_class_name.address;
    if (!remote_call(thread, task, objc_get_class, &job_class, 1,
                     class_argument)) {
        goto cleanup_lifetime;
    }
    uint64_t bound_nsarray = 0;
    uint64_t bound_job_class = 0;
    if (nsarray_class == 0 || job_class == 0 ||
        !read_remote_exact(task,
                           cryptexd_base +
                               CRYPTEXD_NSARRAY_CLASS_SLOT_OFFSET,
                           &bound_nsarray, sizeof(bound_nsarray)) ||
        !read_remote_exact(task,
                           cryptexd_base +
                               CRYPTEXD_OSLAUNCHDJOB_CLASS_SLOT_OFFSET,
                           &bound_job_class, sizeof(bound_job_class)) ||
        bound_nsarray != nsarray_class || bound_job_class != job_class) {
        fprintf(stderr,
                "candidate-registrar: Objective-C class binding mismatch\n");
        goto cleanup_lifetime;
    }

    uint64_t plist_arguments[4] = {
        plist.address, sizeof(kCandidatePlist) - 1U, 0, 0};
    if (!remote_call(thread, task,
                     cryptexd_base + CRYPTEXD_XPC_CREATE_FROM_PLIST_OFFSET,
                     &dictionary, 2, plist_arguments) ||
        dictionary == 0) {
        goto cleanup_lifetime;
    }

    uint64_t create_arguments[4] = {
        dictionary, 0, session.address, storage.address};
    uint64_t create_error = 0;
    uint64_t job = 0;
    if (!remote_call(
            thread, task,
            cryptexd_base + CRYPTEXD_LAUNCHD_SESSION_CREATE_JOB_OFFSET,
            &create_error, 4, create_arguments) ||
        !read_remote_exact(task, storage.address, &job, sizeof(job)) ||
        create_error != 0 || job == 0) {
        fprintf(stderr,
                "candidate-registrar: launchd_session_create_job failed "
                "error=0x%llx job=0x%llx\n",
                (unsigned long long)create_error,
                (unsigned long long)job);
        goto cleanup_lifetime;
    }

    uint64_t array_arguments[4] = {
        bound_nsarray, 0, storage.address, 1};
    uint64_t jobs = 0;
    if (!remote_call(
            thread, task,
            cryptexd_base + CRYPTEXD_NSARRAY_ONE_OBJECT_OFFSET, &jobs, 4,
            array_arguments) ||
        jobs == 0) {
        goto cleanup_lifetime;
    }
    uint64_t zero = 0;
    if (mach_vm_write(task, storage.address + sizeof(uint64_t),
                      (vm_offset_t)(uintptr_t)&zero,
                      (mach_msg_type_number_t)sizeof(zero)) != KERN_SUCCESS) {
        goto cleanup_lifetime;
    }
    uint64_t submit_arguments[4] = {
        bound_job_class, 0, jobs, storage.address + sizeof(uint64_t)};
    uint64_t submit_result = 0;
    uint64_t submit_error = 0;
    if (!remote_call(thread, task,
                     cryptexd_base + CRYPTEXD_SUBMIT_ALL_OFFSET,
                     &submit_result, 4, submit_arguments) ||
        !read_remote_exact(task, storage.address + sizeof(uint64_t),
                           &submit_error, sizeof(submit_error)) ||
        (submit_result & UINT32_MAX) == 0 || submit_error != 0) {
        fprintf(stderr,
                "candidate-registrar: OSLaunchdJob submit failed "
                "result=0x%llx error=0x%llx\n",
                (unsigned long long)submit_result,
                (unsigned long long)submit_error);
        goto cleanup_lifetime;
    }
    success = true;

cleanup_lifetime: {
        bool cleanup_ok = true;
        if (dictionary != 0) {
            uint64_t release_arguments[4] = {dictionary, 0, 0, 0};
            cleanup_ok = remote_call(
                             thread, task,
                             cryptexd_base + CRYPTEXD_XPC_RELEASE_OFFSET,
                             NULL, 1, release_arguments) &&
                         cleanup_ok;
        }
        uint64_t pop_arguments[4] = {pool, 0, 0, 0};
        cleanup_ok = remote_call(
                         thread, task,
                         cryptexd_base + CRYPTEXD_POOL_POP_OFFSET, NULL, 1,
                         pop_arguments) &&
                     cleanup_ok;
        success = success && cleanup_ok;
    }

    if (success) {
        printf("candidate-registrar: registration=success label=%s "
               "session=%s program=%s launch-type=1 run-at-load=false "
               "keep-alive=false\n",
               kCandidateLabel, kCandidateSession, kCandidateProgram);
    }
    remote_deallocate(task, &storage);
    remote_deallocate(task, &job_class_name);
    remote_deallocate(task, &nsarray_name);
    remote_deallocate(task, &session);
    remote_deallocate(task, &plist);
    return success;

failed:
    remote_deallocate(task, &storage);
    remote_deallocate(task, &job_class_name);
    remote_deallocate(task, &nsarray_name);
    remote_deallocate(task, &session);
    remote_deallocate(task, &plist);
    return false;
}

int main(int argc, char *argv[]) {
    setlinebuf(stdout);
    setlinebuf(stderr);
    @autoreleasepool {
        if (geteuid() != 0 || argc != 2) {
            fprintf(stderr,
                    "usage: customd-candidate-registrar CRYPTEXD_PID\n");
            return 64;
        }
        pid_t target_pid = -1;
        struct registrar_process_identity identity = {0};
        if (!parse_pid(argv[1], &target_pid) ||
            !bind_exact_cryptexd(target_pid, &identity)) {
            fprintf(stderr,
                    "candidate-registrar: exact cryptexd identity rejected\n");
            return 65;
        }

        task_t task = MACH_PORT_NULL;
        kern_return_t task_result = task_for_pid(
            mach_task_self(), target_pid, &task);
        if (task_result != KERN_SUCCESS || !MACH_PORT_VALID(task) ||
            !task_audit_token_matches(task, &identity) ||
            !process_still_exact(&identity)) {
            fprintf(stderr,
                    "candidate-registrar: task binding failed mach=%d "
                    "task=0x%x\n",
                    task_result, task);
            if (MACH_PORT_VALID(task)) {
                (void)mach_port_deallocate(mach_task_self(), task);
            }
            return 66;
        }

        task_dyld_info_data_t dyld_info = {0};
        mach_msg_type_number_t dyld_count = TASK_DYLD_INFO_COUNT;
        kern_return_t dyld_result = task_info(
            task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &dyld_count);
        if (dyld_result != KERN_SUCCESS ||
            dyld_count != TASK_DYLD_INFO_COUNT ||
            dyld_info.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64 ||
            dyld_info.all_image_info_addr == 0 ||
            dyld_info.all_image_info_size < sizeof(struct dyld_all_image_infos)) {
            fprintf(stderr,
                    "candidate-registrar: target dyld info rejected mach=%d\n",
                    dyld_result);
            (void)mach_port_deallocate(mach_task_self(), task);
            return 67;
        }

        mach_vm_address_t cryptexd_base = 0;
        if (!validate_cryptexd_image(
                task, dyld_info.all_image_info_addr, &cryptexd_base) ||
            !process_still_exact(&identity)) {
            fprintf(stderr,
                    "candidate-registrar: exact cryptexd image rejected\n");
            (void)mach_port_deallocate(mach_task_self(), task);
            return 68;
        }
        printf("candidate-registrar: cryptexd-validated pid=%d base=0x%llx "
               "uuid=261f91f3-7016-35a2-9a84-c85d2b6a834e\n",
               target_pid, (unsigned long long)cryptexd_base);

        if (!codexPrewarmInjectionPrimitives(
                task, (vm_address_t)dyld_info.all_image_info_addr)) {
            fprintf(stderr,
                    "candidate-registrar: injection primitive prewarm "
                    "failed\n");
            (void)mach_port_deallocate(mach_task_self(), task);
            return 69;
        }
        thread_act_t remote_thread = MACH_PORT_NULL;
        kern_return_t thread_result = createRemotePthread(
            task, (vm_address_t)dyld_info.all_image_info_addr,
            &remote_thread);
        if (thread_result != KERN_SUCCESS ||
            !MACH_PORT_VALID(remote_thread)) {
            fprintf(stderr,
                    "candidate-registrar: remote pthread failed mach=%d\n",
                    thread_result);
            (void)mach_port_deallocate(mach_task_self(), task);
            return 70;
        }

        bool registered = register_candidate(
            task, remote_thread, cryptexd_base,
            dyld_info.all_image_info_addr);
        terminate_remote_thread(task, &remote_thread);
        bool identity_exact = process_still_exact(&identity) &&
                              task_audit_token_matches(task, &identity);
        (void)mach_port_deallocate(mach_task_self(), task);
        if (!registered || !identity_exact) {
            fprintf(stderr,
                    "candidate-registrar: registration failed registered=%d "
                    "identityExact=%d\n",
                    registered, identity_exact);
            return identity_exact ? 71 : 72;
        }
        return 0;
    }
}
