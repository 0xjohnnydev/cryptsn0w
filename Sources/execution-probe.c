#include <arpa/inet.h>
#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach/vm_map.h>
#include <mach/vm_statistics.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int (*ProbeFunction)(void);

enum {
    kCsOpsEntitlementsBlob = 7,
    kCsDebugged = 0x10000000U,
    kEntitlementsBufferSize = 64 * 1024,
    kDebuggerWaitAttempts = 600,
};

extern char **environ;

extern int csops(pid_t pid, unsigned int operation, void *userAddress,
                 size_t userSize);

static const uint32_t kReturn42[] = {
    0xd503245f, /* bti c */
    0x52800540, /* mov w0, #42 */
    0xd65f03c0, /* ret */
};

struct JitWriteContext {
    void *page;
};

static int WriteReturn42(void *opaqueContext) {
    struct JitWriteContext *context = opaqueContext;
    memcpy(context->page, kReturn42, sizeof(kReturn42));
    sys_icache_invalidate(context->page, sizeof(kReturn42));
    return 0;
}

PTHREAD_JIT_WRITE_ALLOW_CALLBACKS_NP(WriteReturn42);

__attribute__((noinline, optnone, naked))
static void *JIT26PrepareRegion(void *address, size_t length) {
    __asm__("mov x16, #1\n"
            "brk #0xf00d\n"
            "ret\n");
}

__attribute__((noinline, optnone, naked))
static void JIT26Detach(void) {
    __asm__("mov x16, #0\n"
            "brk #0xf00d\n"
            "ret\n");
}

static void ReportCodeSigningState(const char *phase) {
    uint32_t flags = 0;
    int status = csops(getpid(), 0, &flags, sizeof(flags));
    dprintf(STDOUT_FILENO,
            "executionProbe phase=%s pid=%d csops=%d flags=0x%08x path=%s\n",
            phase, getpid(), status, flags, getprogname());
}

static void ReportCodeSigningSysctl(const char *name) {
    uint64_t value = 0;
    size_t size = sizeof(value);
    errno = 0;
    int status = sysctlbyname(name, &value, &size, NULL, 0);
    dprintf(STDOUT_FILENO,
            "executionProbe sysctl=%s status=%d errno=%d size=%zu "
            "value=0x%llx\n",
            name, status, status == 0 ? 0 : errno, size,
            (unsigned long long)value);
}

static bool BufferContains(const uint8_t *buffer, size_t bufferSize,
                           const char *needle) {
    size_t needleSize = strlen(needle);
    if (needleSize == 0 || needleSize > bufferSize) {
        return false;
    }
    for (size_t offset = 0; offset <= bufferSize - needleSize; offset++) {
        if (memcmp(buffer + offset, needle, needleSize) == 0) {
            return true;
        }
    }
    return false;
}

static void ReportRuntimeEntitlements(void) {
    uint8_t *buffer = calloc(1, kEntitlementsBufferSize);
    if (buffer == NULL) {
        dprintf(STDERR_FILENO,
                "executionProbe runtimeEntitlements allocation=failed\n");
        return;
    }

    errno = 0;
    int status = csops(getpid(), kCsOpsEntitlementsBlob, buffer,
                       kEntitlementsBufferSize);
    int savedError = status == 0 ? 0 : errno;
    size_t blobSize = 0;
    if (status == 0) {
        uint32_t encodedSize = 0;
        memcpy(&encodedSize, buffer + sizeof(uint32_t), sizeof(encodedSize));
        blobSize = ntohl(encodedSize);
        if (blobSize > kEntitlementsBufferSize) {
            blobSize = kEntitlementsBufferSize;
        }
    }

    dprintf(STDOUT_FILENO,
            "executionProbe runtimeEntitlements status=%d errno=%d size=%zu "
            "platform=%d dynamic=%d webcontent=%d allowJit=%d\n",
            status, savedError, blobSize,
            BufferContains(buffer, blobSize, "platform-application"),
            BufferContains(buffer, blobSize, "dynamic-codesigning"),
            BufferContains(buffer, blobSize,
                           "com.apple.developer.web-browser-engine.webcontent"),
            BufferContains(buffer, blobSize,
                           "com.apple.developer.cs.allow-jit"));
    free(buffer);
}

static void ReportExistingJitRegions(void) {
    vm_address_t address = (vm_address_t)_dyld_get_image_header(0);
    unsigned int matchingRegions = 0;
    for (;;) {
        vm_address_t regionAddress = address;
        vm_size_t regionSize = 0;
        vm_region_extended_info_data_t info = {0};
        mach_msg_type_number_t infoCount = VM_REGION_EXTENDED_INFO_COUNT;
        mach_port_t objectName = MACH_PORT_NULL;
        kern_return_t status = vm_region_64(
            mach_task_self(), &regionAddress, &regionSize,
            VM_REGION_EXTENDED_INFO, (vm_region_info_t)&info, &infoCount,
            &objectName);
        if (MACH_PORT_VALID(objectName)) {
            mach_port_deallocate(mach_task_self(), objectName);
        }
        if (status != KERN_SUCCESS) {
            dprintf(STDOUT_FILENO,
                    "executionProbe existingJitRegions status=%d count=%u\n",
                    status, matchingRegions);
            return;
        }

        bool hasJitTag =
            info.user_tag == VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR;
        bool isWritableExecutable =
            (info.protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) ==
            (VM_PROT_WRITE | VM_PROT_EXECUTE);
        if (hasJitTag || isWritableExecutable) {
            matchingRegions++;
            dprintf(STDOUT_FILENO,
                    "executionProbe existingJitRegion address=0x%llx "
                    "size=0x%llx protection=0x%x tag=%u\n",
                    (unsigned long long)regionAddress,
                    (unsigned long long)regionSize, info.protection,
                    info.user_tag);
        }

        if (regionSize == 0 || regionAddress > UINTPTR_MAX - regionSize) {
            dprintf(STDOUT_FILENO,
                    "executionProbe existingJitRegions status=overflow "
                    "count=%u\n",
                    matchingRegions);
            return;
        }
        address = regionAddress + regionSize;
    }
}

static int ExecuteMprotect(void) {
    size_t pageSize = (size_t)getpagesize();
    void *page = mmap(NULL, pageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=mprotect-rx operation=mmap errno=%d\n",
                errno);
        return 10;
    }
    memcpy(page, kReturn42, sizeof(kReturn42));
    sys_icache_invalidate(page, sizeof(kReturn42));
    if (mprotect(page, pageSize, PROT_READ | PROT_EXEC) != 0) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=mprotect-rx operation=mprotect errno=%d\n",
                errno);
        munmap(page, pageSize);
        return 11;
    }
    int value = ((ProbeFunction)page)();
    munmap(page, pageSize);
    return value == 42 ? 0 : 12;
}

static int ExecuteMapJit(void) {
    size_t pageSize = (size_t)getpagesize();
    const int jitVmTag =
        VM_MAKE_TAG(VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR);
    void *page = mmap(NULL, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANON | MAP_JIT, jitVmTag, 0);
    if (page == MAP_FAILED) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=map-jit operation=mmap errno=%d\n",
                errno);
        return 20;
    }

    struct JitWriteContext context = {.page = page};
    int writeStatus = 0;
    if (__builtin_available(iOS 17.4, *)) {
        writeStatus = pthread_jit_write_with_callback_np(WriteReturn42,
                                                          &context);
    } else {
        dprintf(STDERR_FILENO,
                "executionProbe mode=map-jit operation=callback "
                "error=unavailable\n");
        munmap(page, pageSize);
        return 21;
    }
    if (writeStatus != 0) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=map-jit operation=callback status=%d\n",
                writeStatus);
        munmap(page, pageSize);
        return 22;
    }

    int value = ((ProbeFunction)page)();
    munmap(page, pageSize);
    return value == 42 ? 0 : 23;
}

static int ExecuteDebuggerBlessed(void) {
    dprintf(STDOUT_FILENO,
            "executionProbe mode=jit26 state=waiting pid=%d\n", getpid());

    uint32_t flags = 0;
    int attempt = 0;
    for (; attempt < kDebuggerWaitAttempts; attempt++) {
        if (csops(getpid(), 0, &flags, sizeof(flags)) == 0 &&
            (flags & kCsDebugged) != 0) {
            break;
        }
        usleep(50 * 1000);
    }
    if (attempt == kDebuggerWaitAttempts) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=jit26 state=timeout flags=0x%08x\n",
                flags);
        return 30;
    }

    size_t pageSize = (size_t)getpagesize();
    dprintf(STDOUT_FILENO,
            "executionProbe mode=jit26 state=debugged flags=0x%08x "
            "pageSize=%zu\n",
            flags, pageSize);

    void *executePage = JIT26PrepareRegion(NULL, pageSize);
    if (executePage == NULL) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=jit26 operation=prepare error=null\n");
        return 31;
    }
    dprintf(STDOUT_FILENO,
            "executionProbe mode=jit26 operation=prepare execute=%p\n",
            executePage);

    vm_address_t writeAddress = 0;
    vm_prot_t currentProtection = VM_PROT_NONE;
    vm_prot_t maximumProtection = VM_PROT_NONE;
    kern_return_t status = vm_remap(
        mach_task_self(), &writeAddress, pageSize, 0, VM_FLAGS_ANYWHERE,
        mach_task_self(), (vm_address_t)executePage, FALSE,
        &currentProtection, &maximumProtection, VM_INHERIT_NONE);
    if (status != KERN_SUCCESS) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=jit26 operation=vm-remap status=%d\n",
                status);
        return 32;
    }
    dprintf(STDOUT_FILENO,
            "executionProbe mode=jit26 operation=vm-remap write=0x%llx "
            "current=0x%x maximum=0x%x\n",
            (unsigned long long)writeAddress, currentProtection,
            maximumProtection);

    status = vm_protect(mach_task_self(), writeAddress, pageSize, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    if (status != KERN_SUCCESS) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=jit26 operation=vm-protect-rw "
                "status=%d\n",
                status);
        vm_deallocate(mach_task_self(), writeAddress, pageSize);
        return 33;
    }

    memcpy((void *)writeAddress, kReturn42, sizeof(kReturn42));
    sys_icache_invalidate(executePage, sizeof(kReturn42));
    JIT26Detach();

    int value = ((ProbeFunction)executePage)();
    dprintf(STDOUT_FILENO,
            "executionProbe mode=jit26 operation=execute value=%d\n", value);
    vm_deallocate(mach_task_self(), writeAddress, pageSize);
    vm_deallocate(mach_task_self(), (vm_address_t)executePage, pageSize);
    return value == 42 ? 0 : 34;
}

static bool RunIsolated(const char *executable, const char *name,
                        const char *mode) {
    char *const childArguments[] = {
        (char *)executable,
        (char *)mode,
        NULL,
    };
    pid_t child = -1;
    int spawnError =
        posix_spawn(&child, executable, NULL, NULL, childArguments, environ);
    if (spawnError != 0) {
        dprintf(STDERR_FILENO,
                "executionProbe mode=%s spawnError=%d\n", name, spawnError);
        return false;
    }

    int status = 0;
    pid_t waited = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            break;
        }
        if (waited == 0 || (waited < 0 && errno == EINTR)) {
            usleep(50 * 1000);
            continue;
        }
        dprintf(STDERR_FILENO,
                "executionProbe mode=%s waitError=%d child=%d\n", name,
                errno, child);
        return false;
    }
    if (waited != child) {
        int killStatus = kill(child, SIGKILL);
        int killError = killStatus == 0 ? 0 : errno;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        dprintf(STDOUT_FILENO,
                "executionProbe mode=%s child=%d timeout=1 kill=%d "
                "killError=%d result=rejected\n",
                name, child, killStatus, killError);
        return false;
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        dprintf(STDOUT_FILENO,
                "executionProbe mode=%s child=%d exited=%d result=%s\n",
                name, child, code, code == 0 ? "supported" : "rejected");
        return code == 0;
    }
    if (WIFSIGNALED(status)) {
        dprintf(STDOUT_FILENO,
                "executionProbe mode=%s child=%d signal=%d result=rejected\n",
                name, child, WTERMSIG(status));
        return false;
    }
    dprintf(STDOUT_FILENO,
            "executionProbe mode=%s child=%d status=0x%x result=rejected\n",
            name, child, status);
    return false;
}

int main(int argc, char **argv) {
    ReportCodeSigningState(argc == 1 ? "parent" : "child");
    if (argc == 1) {
        ReportCodeSigningSysctl("security.codesigning.monitor");
        ReportCodeSigningSysctl("security.codesigning.config");
        ReportRuntimeEntitlements();
        ReportExistingJitRegions();
        if (__builtin_available(iOS 17.4, *)) {
            dprintf(STDOUT_FILENO,
                    "executionProbe jitWriteProtectSupported=%d\n",
                    pthread_jit_write_protect_supported_np());
        }
    }

    if (argc == 2 && strcmp(argv[1], "--internal-mprotect-rx") == 0) {
        return ExecuteMprotect();
    }
    if (argc == 2 && strcmp(argv[1], "--internal-map-jit") == 0) {
        return ExecuteMapJit();
    }
    if (argc == 2 && strcmp(argv[1], "--jit26") == 0) {
        ReportRuntimeEntitlements();
        return ExecuteDebuggerBlessed();
    }
    if (argc != 1) {
        dprintf(STDERR_FILENO, "usage: %s [--jit26]\n", argv[0]);
        return 64;
    }

    char executable[PATH_MAX];
    uint32_t executableSize = sizeof(executable);
    if (_NSGetExecutablePath(executable, &executableSize) != 0) {
        dprintf(STDERR_FILENO,
                "executionProbe executablePathError=buffer-too-small "
                "required=%u\n",
                executableSize);
        return 71;
    }

    bool mprotectSupported = RunIsolated(
        executable, "mprotect-rx", "--internal-mprotect-rx");
    bool mapJitSupported =
        RunIsolated(executable, "map-jit", "--internal-map-jit");
    dprintf(STDOUT_FILENO,
            "executionProbe summary mprotectRx=%d mapJit=%d\n",
            mprotectSupported, mapJitSupported);
    return (mprotectSupported || mapJitSupported) ? 0 : 1;
}
