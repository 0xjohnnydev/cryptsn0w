/*
 * Header-free translation unit for LLDB's persistent expression JIT.
 *
 * This deliberately mirrors codex3_exec_worker's dyld boundary shim.  LLDB's
 * remote expression compiler does not have an iPhone SDK include path, so all
 * ABI types and constants used here are defined locally.  The hooks are
 * reversible: codex3_restore_bypass() puts dyld's original instructions
 * back after a test load.
 */

typedef unsigned char codex3_u8;
typedef unsigned int codex3_u32;
typedef unsigned short codex3_u16;
typedef unsigned long long codex3_u64;
typedef signed long long codex3_i64;
typedef unsigned long codex3_size_t;
typedef signed long codex3_ssize_t;

struct codex3_mach_header_64 {
    codex3_u32 magic;
    codex3_u32 cputype;
    codex3_u32 cpusubtype;
    codex3_u32 filetype;
    codex3_u32 ncmds;
    codex3_u32 sizeofcmds;
    codex3_u32 flags;
    codex3_u32 reserved;
};

struct codex3_load_command {
    codex3_u32 cmd;
    codex3_u32 cmdsize;
};

struct codex3_segment_command_64 {
    codex3_u32 cmd;
    codex3_u32 cmdsize;
    char segname[16];
    codex3_u64 vmaddr;
    codex3_u64 vmsize;
    codex3_u64 fileoff;
    codex3_u64 filesize;
    int maxprot;
    int initprot;
    codex3_u32 nsects;
    codex3_u32 flags;
};

struct codex3_fsignatures {
    codex3_i64 fs_file_start;
    void *fs_blob_start;
    codex3_size_t fs_blob_size;
};

extern "C" {
int codex3_sys_dprintf(int, const char *, ...) __asm("dprintf");
int codex3_sys_fcntl(int, int, ...) __asm("fcntl");
int codex3_sys_getpagesize(void) __asm("getpagesize");
int codex3_sys_getpid(void) __asm("getpid");
void *codex3_sys_mmap(void *, codex3_size_t, int, int, int, codex3_i64)
    __asm("mmap");
int codex3_sys_mprotect(void *, codex3_size_t, int) __asm("mprotect");
int codex3_sys_munmap(void *, codex3_size_t) __asm("munmap");
codex3_ssize_t codex3_sys_pread(int, void *, codex3_size_t, codex3_i64)
    __asm("pread");
int codex3_sys_mach_vm_protect(unsigned int, codex3_u64, codex3_u64, int, int)
    __asm("mach_vm_protect");
unsigned int codex3_sys_mach_task_self(void) __asm("mach_task_self");
void codex3_sys_icache_invalidate(void *, codex3_size_t)
    __asm("sys_icache_invalidate");
void *codex3_sys_dlopen(const char *, int) __asm("dlopen");
char *codex3_sys_dlerror(void) __asm("dlerror");
}

static const int CODEX3_PROT_READ = 0x01;
static const int CODEX3_PROT_WRITE = 0x02;
static const int CODEX3_PROT_EXEC = 0x04;
static const int CODEX3_MAP_PRIVATE = 0x0002;
static const int CODEX3_MAP_FIXED = 0x0010;
static const int CODEX3_MAP_ANON = 0x1000;
static const int CODEX3_VM_PROT_COPY = 0x10;
static const int CODEX3_F_ADDFILESIGS_RETURN = 97;
static const int CODEX3_F_CHECK_LV = 98;
static const int CODEX3_RTLD_NOW = 0x2;
static const int CODEX3_RTLD_GLOBAL = 0x8;
static const codex3_u32 CODEX3_MH_MAGIC_64 = 0xfeedfacfU;
static const codex3_u32 CODEX3_LC_SEGMENT_64 = 0x19U;

extern "C" codex3_u8 codex3_mmap_pattern[8] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
extern "C" codex3_u8 codex3_fcntl_pattern[8] = {
    0x90, 0x0b, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};

extern "C" codex3_u8 codex3_saved_mmap[20] = {};
extern "C" codex3_u8 codex3_saved_fcntl[20] = {};
extern "C" void *codex3_mmap_stub = 0;
extern "C" void *codex3_fcntl_stub = 0;
extern "C" int codex3_mmap_installed = 0;
extern "C" int codex3_fcntl_installed = 0;
extern "C" unsigned int codex3_anonymous_exec_count = 0;

extern "C" int codex3_bytes_equal(const codex3_u8 *left,
                                        const codex3_u8 *right,
                                        codex3_size_t size) {
    for (codex3_size_t index = 0; index < size; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

extern "C" void codex3_copy(codex3_u8 *destination,
                                  const codex3_u8 *source,
                                  codex3_size_t size) {
    for (codex3_size_t index = 0; index < size; ++index) {
        destination[index] = source[index];
    }
}

extern "C" void *codex3_dyld_mmap(void *address, codex3_size_t length,
                                    int protection, int flags,
                                    int descriptor, codex3_i64 offset) {
    void *mapping = codex3_sys_mmap(address, length, protection, flags,
                                   descriptor, offset);
    if (mapping != (void *)(~(codex3_u64)0) || descriptor < 0 ||
        (protection & CODEX3_PROT_EXEC) == 0) {
        return mapping;
    }

    int anonymous_flags = CODEX3_MAP_PRIVATE | CODEX3_MAP_ANON;
    if ((flags & CODEX3_MAP_FIXED) != 0) {
        anonymous_flags |= CODEX3_MAP_FIXED;
    }
    mapping = codex3_sys_mmap(address, length,
                             CODEX3_PROT_READ | CODEX3_PROT_WRITE,
                             anonymous_flags, -1, 0);
    if (mapping == (void *)(~(codex3_u64)0)) {
        return mapping;
    }

    codex3_size_t copied = 0;
    while (copied < length) {
        codex3_ssize_t amount = codex3_sys_pread(
            descriptor, (codex3_u8 *)mapping + copied, length - copied,
            offset + (codex3_i64)copied);
        if (amount > 0) {
            copied += (codex3_size_t)amount;
            continue;
        }
        if (amount == 0) {
            break;
        }
        codex3_sys_munmap(mapping, length);
        return (void *)(~(codex3_u64)0);
    }

    if (codex3_sys_mprotect(mapping, length, protection) != 0) {
        codex3_sys_munmap(mapping, length);
        return (void *)(~(codex3_u64)0);
    }

    ++codex3_anonymous_exec_count;
    codex3_sys_dprintf(2,
                      "codex-lldb-loader pid=%d anonymous-exec=%u "
                      "address=%p length=0x%lx offset=0x%llx\n",
                      codex3_sys_getpid(), codex3_anonymous_exec_count,
                      mapping, (unsigned long)length,
                      (unsigned long long)offset);
    return mapping;
}

extern "C" int codex3_dyld_fcntl(int descriptor, int command,
                                   void *parameter) {
    if (command == CODEX3_F_ADDFILESIGS_RETURN) {
        codex3_fsignatures *signature = (codex3_fsignatures *)parameter;
        if (signature != 0) {
            signature->fs_file_start = -1;
        }
        codex3_sys_dprintf(
            2, "codex-lldb-loader pid=%d signature-bypass fd=%d\n",
            codex3_sys_getpid(), descriptor);
        return 0;
    }
    if (command == CODEX3_F_CHECK_LV) {
        return 0;
    }
    return codex3_sys_fcntl(descriptor, command, parameter);
}

extern "C" codex3_u32 codex3_movk(unsigned int register_number,
                                      codex3_u16 immediate,
                                      unsigned int shift) {
    return 0xf2800000U | ((shift / 16U) << 21U) |
           ((codex3_u32)immediate << 5U) | (register_number & 0x1fU);
}

extern "C" int codex3_set_page_writable(void *source) {
    codex3_u64 source_address = (codex3_u64)source;
    codex3_u64 page_size = (codex3_u64)codex3_sys_getpagesize();
    codex3_u64 page = source_address & ~(page_size - 1U);
    codex3_u64 end = (source_address + 20U + page_size - 1U) &
                    ~(page_size - 1U);
    return codex3_sys_mach_vm_protect(
        codex3_sys_mach_task_self(), page, end - page, 0,
        CODEX3_PROT_READ | CODEX3_PROT_WRITE | CODEX3_VM_PROT_COPY);
}

extern "C" int codex3_set_page_executable(void *source) {
    codex3_u64 source_address = (codex3_u64)source;
    codex3_u64 page_size = (codex3_u64)codex3_sys_getpagesize();
    codex3_u64 page = source_address & ~(page_size - 1U);
    codex3_u64 end = (source_address + 20U + page_size - 1U) &
                    ~(page_size - 1U);
    return codex3_sys_mach_vm_protect(
        codex3_sys_mach_task_self(), page, end - page, 0,
        CODEX3_PROT_READ | CODEX3_PROT_EXEC);
}

extern "C" int codex3_hook(void *source, void *target,
                                codex3_u8 saved[20]) {
    codex3_copy(saved, (const codex3_u8 *)source, 20U);
    int writable = codex3_set_page_writable(source);
    if (writable != 0) {
        return 1000 + writable;
    }

    codex3_u64 target_address =
        (codex3_u64)__builtin_ptrauth_strip(target, 0);
    codex3_u32 *instructions = (codex3_u32 *)source;
    instructions[0] = codex3_movk(
        16U, (codex3_u16)(target_address >> 0U), 0U);
    instructions[1] = codex3_movk(
        16U, (codex3_u16)(target_address >> 16U), 16U);
    instructions[2] = codex3_movk(
        16U, (codex3_u16)(target_address >> 32U), 32U);
    instructions[3] = codex3_movk(
        16U, (codex3_u16)(target_address >> 48U), 48U);
    instructions[4] = 0xd61f0200U;

    int executable = codex3_set_page_executable(source);
    if (executable != 0) {
        return 2000 + executable;
    }
    codex3_sys_icache_invalidate(source, 20U);
    return 0;
}

extern "C" int codex3_unhook(void *source,
                                  const codex3_u8 saved[20]) {
    if (source == 0) {
        return 0;
    }
    int writable = codex3_set_page_writable(source);
    if (writable != 0) {
        return 1000 + writable;
    }
    codex3_copy((codex3_u8 *)source, saved, 20U);
    int executable = codex3_set_page_executable(source);
    if (executable != 0) {
        return 2000 + executable;
    }
    codex3_sys_icache_invalidate(source, 20U);
    return 0;
}

extern "C" codex3_u8 *codex3_find_pattern(
    const codex3_mach_header_64 *header, const codex3_u8 *pattern,
    codex3_size_t pattern_size) {
    if (header == 0 || header->magic != CODEX3_MH_MAGIC_64 ||
        header->sizeofcmds > (16U * 1024U * 1024U)) {
        return 0;
    }

    const codex3_u8 *cursor = (const codex3_u8 *)(header + 1);
    const codex3_u8 *commands_end = cursor + header->sizeofcmds;
    codex3_u64 base_vm_address = 0;
    for (codex3_u32 index = 0; index < header->ncmds; ++index) {
        if ((codex3_size_t)(commands_end - cursor) <
            sizeof(codex3_load_command)) {
            return 0;
        }
        const codex3_load_command *command =
            (const codex3_load_command *)cursor;
        if (command->cmdsize < sizeof(codex3_load_command) ||
            command->cmdsize > (codex3_u32)(commands_end - cursor)) {
            return 0;
        }
        if (command->cmd == CODEX3_LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(codex3_segment_command_64)) {
            const codex3_segment_command_64 *segment =
                (const codex3_segment_command_64 *)command;
            if ((segment->initprot & CODEX3_PROT_EXEC) != 0) {
                base_vm_address = segment->vmaddr;
                break;
            }
        }
        cursor += command->cmdsize;
    }
    if (base_vm_address == 0) {
        return 0;
    }

    codex3_u64 slide = (codex3_u64)header - base_vm_address;
    cursor = (const codex3_u8 *)(header + 1);
    for (codex3_u32 index = 0; index < header->ncmds; ++index) {
        const codex3_load_command *command =
            (const codex3_load_command *)cursor;
        if (command->cmd == CODEX3_LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(codex3_segment_command_64)) {
            const codex3_segment_command_64 *segment =
                (const codex3_segment_command_64 *)command;
            if ((segment->initprot & CODEX3_PROT_EXEC) != 0 &&
                segment->filesize >= pattern_size) {
                codex3_u8 *start =
                    (codex3_u8 *)(slide + segment->vmaddr);
                codex3_size_t size = (codex3_size_t)segment->filesize;
                for (codex3_size_t offset = 0;
                     offset + pattern_size <= size;
                     offset += sizeof(codex3_u32)) {
                    if (codex3_bytes_equal(start + offset, pattern,
                                               pattern_size)) {
                        return start + offset;
                    }
                }
            }
        }
        cursor += command->cmdsize;
    }
    return 0;
}

extern "C" int codex3_install_bypass(void *dyld_header) {
    if (codex3_mmap_installed || codex3_fcntl_installed) {
        return -10;
    }

    codex3_mmap_stub = codex3_find_pattern(
        (const codex3_mach_header_64 *)dyld_header,
        codex3_mmap_pattern, sizeof(codex3_mmap_pattern));
    codex3_fcntl_stub = codex3_find_pattern(
        (const codex3_mach_header_64 *)dyld_header,
        codex3_fcntl_pattern, sizeof(codex3_fcntl_pattern));
    if (codex3_mmap_stub == 0 || codex3_fcntl_stub == 0) {
        return -20;
    }

    int mmap_result = codex3_hook(
        codex3_mmap_stub, (void *)codex3_dyld_mmap,
        codex3_saved_mmap);
    if (mmap_result != 0) {
        return 10000 + mmap_result;
    }
    codex3_mmap_installed = 1;

    int fcntl_result = codex3_hook(
        codex3_fcntl_stub, (void *)codex3_dyld_fcntl,
        codex3_saved_fcntl);
    if (fcntl_result != 0) {
        codex3_unhook(codex3_mmap_stub,
                          codex3_saved_mmap);
        codex3_mmap_installed = 0;
        return 20000 + fcntl_result;
    }
    codex3_fcntl_installed = 1;

    codex3_sys_dprintf(
        2, "codex-lldb-loader pid=%d dyld=%p mmap=%p fcntl=%p "
           "installed=1\n",
        codex3_sys_getpid(), dyld_header, codex3_mmap_stub,
        codex3_fcntl_stub);
    return 0;
}

extern "C" int codex3_restore_bypass(void) {
    int mmap_result = 0;
    int fcntl_result = 0;
    if (codex3_mmap_installed) {
        mmap_result = codex3_unhook(codex3_mmap_stub,
                                        codex3_saved_mmap);
        if (mmap_result == 0) {
            codex3_mmap_installed = 0;
        }
    }
    if (codex3_fcntl_installed) {
        fcntl_result = codex3_unhook(codex3_fcntl_stub,
                                         codex3_saved_fcntl);
        if (fcntl_result == 0) {
            codex3_fcntl_installed = 0;
        }
    }
    return mmap_result != 0 ? mmap_result : fcntl_result;
}

extern "C" void *codex3_load_unsigned(const char *path) {
    return codex3_sys_dlopen(path, CODEX3_RTLD_NOW | CODEX3_RTLD_GLOBAL);
}

extern "C" const char *codex3_last_dyld_error(void) {
    return codex3_sys_dlerror();
}
