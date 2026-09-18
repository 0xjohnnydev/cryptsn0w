/*
 * Header-free translation unit for LLDB's persistent expression JIT.
 *
 * This deliberately mirrors codex_exec_worker's dyld boundary shim.  LLDB's
 * remote expression compiler does not have an iPhone SDK include path, so all
 * ABI types and constants used here are defined locally.  The hooks are
 * reversible: codex_lldb_restore_bypass() puts dyld's original instructions
 * back after a test load.
 */

typedef unsigned char codex_u8;
typedef unsigned int codex_u32;
typedef unsigned short codex_u16;
typedef unsigned long long codex_u64;
typedef signed long long codex_i64;
typedef unsigned long codex_size_t;
typedef signed long codex_ssize_t;

struct codex_mach_header_64 {
    codex_u32 magic;
    codex_u32 cputype;
    codex_u32 cpusubtype;
    codex_u32 filetype;
    codex_u32 ncmds;
    codex_u32 sizeofcmds;
    codex_u32 flags;
    codex_u32 reserved;
};

struct codex_load_command {
    codex_u32 cmd;
    codex_u32 cmdsize;
};

struct codex_segment_command_64 {
    codex_u32 cmd;
    codex_u32 cmdsize;
    char segname[16];
    codex_u64 vmaddr;
    codex_u64 vmsize;
    codex_u64 fileoff;
    codex_u64 filesize;
    int maxprot;
    int initprot;
    codex_u32 nsects;
    codex_u32 flags;
};

struct codex_fsignatures {
    codex_i64 fs_file_start;
    void *fs_blob_start;
    codex_size_t fs_blob_size;
};

extern "C" {
int codex_sys_dprintf(int, const char *, ...) __asm("dprintf");
int codex_sys_fcntl(int, int, ...) __asm("fcntl");
int codex_sys_getpagesize(void) __asm("getpagesize");
int codex_sys_getpid(void) __asm("getpid");
void *codex_sys_mmap(void *, codex_size_t, int, int, int, codex_i64)
    __asm("mmap");
int codex_sys_mprotect(void *, codex_size_t, int) __asm("mprotect");
int codex_sys_munmap(void *, codex_size_t) __asm("munmap");
codex_ssize_t codex_sys_pread(int, void *, codex_size_t, codex_i64)
    __asm("pread");
int codex_sys_mach_vm_protect(unsigned int, codex_u64, codex_u64, int, int)
    __asm("mach_vm_protect");
unsigned int codex_sys_mach_task_self(void) __asm("mach_task_self");
void codex_sys_icache_invalidate(void *, codex_size_t)
    __asm("sys_icache_invalidate");
void *codex_sys_dlopen(const char *, int) __asm("dlopen");
char *codex_sys_dlerror(void) __asm("dlerror");
}

static const int CODEX_PROT_READ = 0x01;
static const int CODEX_PROT_WRITE = 0x02;
static const int CODEX_PROT_EXEC = 0x04;
static const int CODEX_MAP_PRIVATE = 0x0002;
static const int CODEX_MAP_FIXED = 0x0010;
static const int CODEX_MAP_ANON = 0x1000;
static const int CODEX_VM_PROT_COPY = 0x10;
static const int CODEX_F_ADDFILESIGS_RETURN = 97;
static const int CODEX_F_CHECK_LV = 98;
static const int CODEX_RTLD_NOW = 0x2;
static const int CODEX_RTLD_GLOBAL = 0x8;
static const codex_u32 CODEX_MH_MAGIC_64 = 0xfeedfacfU;
static const codex_u32 CODEX_LC_SEGMENT_64 = 0x19U;

extern "C" codex_u8 codex_lldb_mmap_pattern[8] = {
    0xb0, 0x18, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};
extern "C" codex_u8 codex_lldb_fcntl_pattern[8] = {
    0x90, 0x0b, 0x80, 0xd2, 0x01, 0x10, 0x00, 0xd4,
};

extern "C" codex_u8 codex_lldb_saved_mmap[20] = {};
extern "C" codex_u8 codex_lldb_saved_fcntl[20] = {};
extern "C" void *codex_lldb_mmap_stub = 0;
extern "C" void *codex_lldb_fcntl_stub = 0;
extern "C" int codex_lldb_mmap_installed = 0;
extern "C" int codex_lldb_fcntl_installed = 0;
extern "C" unsigned int codex_lldb_anonymous_exec_count = 0;

extern "C" int codex_lldb_bytes_equal(const codex_u8 *left,
                                        const codex_u8 *right,
                                        codex_size_t size) {
    for (codex_size_t index = 0; index < size; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

extern "C" void codex_lldb_copy(codex_u8 *destination,
                                  const codex_u8 *source,
                                  codex_size_t size) {
    for (codex_size_t index = 0; index < size; ++index) {
        destination[index] = source[index];
    }
}

extern "C" void *codex2_dyld_mmap(void *address, codex_size_t length,
                                    int protection, int flags,
                                    int descriptor, codex_i64 offset) {
    void *mapping = codex_sys_mmap(address, length, protection, flags,
                                   descriptor, offset);
    if (mapping != (void *)(~(codex_u64)0) || descriptor < 0 ||
        (protection & CODEX_PROT_EXEC) == 0) {
        return mapping;
    }

    int anonymous_flags = CODEX_MAP_PRIVATE | CODEX_MAP_ANON;
    if ((flags & CODEX_MAP_FIXED) != 0) {
        anonymous_flags |= CODEX_MAP_FIXED;
    }
    mapping = codex_sys_mmap(address, length,
                             CODEX_PROT_READ | CODEX_PROT_WRITE,
                             anonymous_flags, -1, 0);
    if (mapping == (void *)(~(codex_u64)0)) {
        return mapping;
    }

    codex_size_t copied = 0;
    while (copied < length) {
        codex_ssize_t amount = codex_sys_pread(
            descriptor, (codex_u8 *)mapping + copied, length - copied,
            offset + (codex_i64)copied);
        if (amount > 0) {
            copied += (codex_size_t)amount;
            continue;
        }
        if (amount == 0) {
            break;
        }
        codex_sys_munmap(mapping, length);
        return (void *)(~(codex_u64)0);
    }

    if (codex_sys_mprotect(mapping, length, protection) != 0) {
        codex_sys_munmap(mapping, length);
        return (void *)(~(codex_u64)0);
    }

    ++codex_lldb_anonymous_exec_count;
    codex_sys_dprintf(2,
                      "codex-lldb-loader pid=%d anonymous-exec=%u "
                      "address=%p length=0x%lx offset=0x%llx\n",
                      codex_sys_getpid(), codex_lldb_anonymous_exec_count,
                      mapping, (unsigned long)length,
                      (unsigned long long)offset);
    return mapping;
}

extern "C" int codex2_dyld_fcntl(int descriptor, int command,
                                   void *parameter) {
    if (command == CODEX_F_ADDFILESIGS_RETURN) {
        codex_fsignatures *signature = (codex_fsignatures *)parameter;
        if (signature != 0) {
            signature->fs_file_start = -1;
        }
        codex_sys_dprintf(
            2, "codex-lldb-loader pid=%d signature-bypass fd=%d\n",
            codex_sys_getpid(), descriptor);
        return 0;
    }
    if (command == CODEX_F_CHECK_LV) {
        return 0;
    }
    return codex_sys_fcntl(descriptor, command, parameter);
}

extern "C" codex_u32 codex_lldb_movk(unsigned int register_number,
                                      codex_u16 immediate,
                                      unsigned int shift) {
    return 0xf2800000U | ((shift / 16U) << 21U) |
           ((codex_u32)immediate << 5U) | (register_number & 0x1fU);
}

extern "C" int codex_lldb_set_page_writable(void *source) {
    codex_u64 source_address = (codex_u64)source;
    codex_u64 page_size = (codex_u64)codex_sys_getpagesize();
    codex_u64 page = source_address & ~(page_size - 1U);
    codex_u64 end = (source_address + 20U + page_size - 1U) &
                    ~(page_size - 1U);
    return codex_sys_mach_vm_protect(
        codex_sys_mach_task_self(), page, end - page, 0,
        CODEX_PROT_READ | CODEX_PROT_WRITE | CODEX_VM_PROT_COPY);
}

extern "C" int codex_lldb_set_page_executable(void *source) {
    codex_u64 source_address = (codex_u64)source;
    codex_u64 page_size = (codex_u64)codex_sys_getpagesize();
    codex_u64 page = source_address & ~(page_size - 1U);
    codex_u64 end = (source_address + 20U + page_size - 1U) &
                    ~(page_size - 1U);
    return codex_sys_mach_vm_protect(
        codex_sys_mach_task_self(), page, end - page, 0,
        CODEX_PROT_READ | CODEX_PROT_EXEC);
}

extern "C" int codex_lldb_hook(void *source, void *target,
                                codex_u8 saved[20]) {
    codex_lldb_copy(saved, (const codex_u8 *)source, 20U);
    int writable = codex_lldb_set_page_writable(source);
    if (writable != 0) {
        return 1000 + writable;
    }

    codex_u64 target_address = (codex_u64)target;
    codex_u32 *instructions = (codex_u32 *)source;
    instructions[0] = codex_lldb_movk(
        16U, (codex_u16)(target_address >> 0U), 0U);
    instructions[1] = codex_lldb_movk(
        16U, (codex_u16)(target_address >> 16U), 16U);
    instructions[2] = codex_lldb_movk(
        16U, (codex_u16)(target_address >> 32U), 32U);
    instructions[3] = codex_lldb_movk(
        16U, (codex_u16)(target_address >> 48U), 48U);
    instructions[4] = 0xd61f0200U;

    int executable = codex_lldb_set_page_executable(source);
    if (executable != 0) {
        return 2000 + executable;
    }
    codex_sys_icache_invalidate(source, 20U);
    return 0;
}

extern "C" int codex_lldb_unhook(void *source,
                                  const codex_u8 saved[20]) {
    if (source == 0) {
        return 0;
    }
    int writable = codex_lldb_set_page_writable(source);
    if (writable != 0) {
        return 1000 + writable;
    }
    codex_lldb_copy((codex_u8 *)source, saved, 20U);
    int executable = codex_lldb_set_page_executable(source);
    if (executable != 0) {
        return 2000 + executable;
    }
    codex_sys_icache_invalidate(source, 20U);
    return 0;
}

extern "C" codex_u8 *codex_lldb_find_pattern(
    const codex_mach_header_64 *header, const codex_u8 *pattern,
    codex_size_t pattern_size) {
    if (header == 0 || header->magic != CODEX_MH_MAGIC_64 ||
        header->sizeofcmds > (16U * 1024U * 1024U)) {
        return 0;
    }

    const codex_u8 *cursor = (const codex_u8 *)(header + 1);
    const codex_u8 *commands_end = cursor + header->sizeofcmds;
    codex_u64 base_vm_address = 0;
    for (codex_u32 index = 0; index < header->ncmds; ++index) {
        if ((codex_size_t)(commands_end - cursor) <
            sizeof(codex_load_command)) {
            return 0;
        }
        const codex_load_command *command =
            (const codex_load_command *)cursor;
        if (command->cmdsize < sizeof(codex_load_command) ||
            command->cmdsize > (codex_u32)(commands_end - cursor)) {
            return 0;
        }
        if (command->cmd == CODEX_LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(codex_segment_command_64)) {
            const codex_segment_command_64 *segment =
                (const codex_segment_command_64 *)command;
            if ((segment->initprot & CODEX_PROT_EXEC) != 0) {
                base_vm_address = segment->vmaddr;
                break;
            }
        }
        cursor += command->cmdsize;
    }
    if (base_vm_address == 0) {
        return 0;
    }

    codex_u64 slide = (codex_u64)header - base_vm_address;
    cursor = (const codex_u8 *)(header + 1);
    for (codex_u32 index = 0; index < header->ncmds; ++index) {
        const codex_load_command *command =
            (const codex_load_command *)cursor;
        if (command->cmd == CODEX_LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(codex_segment_command_64)) {
            const codex_segment_command_64 *segment =
                (const codex_segment_command_64 *)command;
            if ((segment->initprot & CODEX_PROT_EXEC) != 0 &&
                segment->filesize >= pattern_size) {
                codex_u8 *start =
                    (codex_u8 *)(slide + segment->vmaddr);
                codex_size_t size = (codex_size_t)segment->filesize;
                for (codex_size_t offset = 0;
                     offset + pattern_size <= size;
                     offset += sizeof(codex_u32)) {
                    if (codex_lldb_bytes_equal(start + offset, pattern,
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

extern "C" int codex2_install_bypass(void *dyld_header) {
    if (codex_lldb_mmap_installed || codex_lldb_fcntl_installed) {
        return -10;
    }

    codex_lldb_mmap_stub = codex_lldb_find_pattern(
        (const codex_mach_header_64 *)dyld_header,
        codex_lldb_mmap_pattern, sizeof(codex_lldb_mmap_pattern));
    codex_lldb_fcntl_stub = codex_lldb_find_pattern(
        (const codex_mach_header_64 *)dyld_header,
        codex_lldb_fcntl_pattern, sizeof(codex_lldb_fcntl_pattern));
    if (codex_lldb_mmap_stub == 0 || codex_lldb_fcntl_stub == 0) {
        return -20;
    }

    int mmap_result = codex_lldb_hook(
        codex_lldb_mmap_stub, (void *)codex2_dyld_mmap,
        codex_lldb_saved_mmap);
    if (mmap_result != 0) {
        return 10000 + mmap_result;
    }
    codex_lldb_mmap_installed = 1;

    int fcntl_result = codex_lldb_hook(
        codex_lldb_fcntl_stub, (void *)codex2_dyld_fcntl,
        codex_lldb_saved_fcntl);
    if (fcntl_result != 0) {
        codex_lldb_unhook(codex_lldb_mmap_stub,
                          codex_lldb_saved_mmap);
        codex_lldb_mmap_installed = 0;
        return 20000 + fcntl_result;
    }
    codex_lldb_fcntl_installed = 1;

    codex_sys_dprintf(
        2, "codex-lldb-loader pid=%d dyld=%p mmap=%p fcntl=%p "
           "installed=1\n",
        codex_sys_getpid(), dyld_header, codex_lldb_mmap_stub,
        codex_lldb_fcntl_stub);
    return 0;
}

extern "C" int codex2_restore_bypass(void) {
    int mmap_result = 0;
    int fcntl_result = 0;
    if (codex_lldb_mmap_installed) {
        mmap_result = codex_lldb_unhook(codex_lldb_mmap_stub,
                                        codex_lldb_saved_mmap);
        if (mmap_result == 0) {
            codex_lldb_mmap_installed = 0;
        }
    }
    if (codex_lldb_fcntl_installed) {
        fcntl_result = codex_lldb_unhook(codex_lldb_fcntl_stub,
                                         codex_lldb_saved_fcntl);
        if (fcntl_result == 0) {
            codex_lldb_fcntl_installed = 0;
        }
    }
    return mmap_result != 0 ? mmap_result : fcntl_result;
}

extern "C" void *codex2_load_unsigned(const char *path) {
    return codex_sys_dlopen(path, CODEX_RTLD_NOW | CODEX_RTLD_GLOBAL);
}

extern "C" const char *codex2_last_dyld_error(void) {
    return codex_sys_dlerror();
}
