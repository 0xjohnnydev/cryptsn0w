#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <os/log.h>
#include <ptrauth.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* iPhone14,5 / 24A435 launchd, copied from the target device. */
static const uint8_t kLaunchdUuid[16] = {
    0xca, 0x54, 0x23, 0x0d, 0x40, 0x05, 0x31, 0x31,
    0x8d, 0xc3, 0xcc, 0xb7, 0xe7, 0xef, 0x18, 0xe6,
};
static const uintptr_t kPosixSpawnSlotVmaddr = 0x1000824f8ULL;
static const uintptr_t kPosixSpawnpSlotVmaddr = 0x1000826a0ULL;
static const char kOriginalSpringBoard[] =
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard";
static const char kHookSuffix[] =
    "/usr/local/lib/codex-launchd-spawn-redirect.dylib";
static const char kSpringBoardSuffix[] =
    "/usr/local/share/codex-bootstrap/SpringBoard.app/SpringBoard";

typedef int (*spawn_function)(pid_t *restrict, const char *restrict,
                              const posix_spawn_file_actions_t *restrict,
                              const posix_spawnattr_t *restrict,
                              char *const argv[restrict],
                              char *const envp[restrict]);

extern kern_return_t mach_vm_protect(vm_map_t task, mach_vm_address_t address,
                                     mach_vm_size_t size, boolean_t set_maximum,
                                     vm_prot_t protection);

static spawn_function gOriginalSpawn;
static spawn_function gOriginalSpawnp;
static char gSpringBoardPath[4096];
static os_log_t gLog;
/* Kept in writable data so a separate task-port probe can inspect failures. */
static volatile int gInstallStage;
static volatile kern_return_t gProtectResult;

static void log_result(const char *event, int value) {
    os_log(gLog, "launchd-spawn-redirect %{public}s value=%{public}d",
           event, value);
}

static bool launchd_uuid_matches(const struct mach_header_64 *header) {
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return false;
    }
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) {
            return false;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (size_t)(end - cursor)) {
            return false;
        }
        if (command->cmd == LC_UUID &&
            command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid =
                (const struct uuid_command *)command;
            return memcmp(uuid->uuid, kLaunchdUuid, sizeof(kLaunchdUuid)) == 0;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static bool resolve_springboard_path(void) {
    Dl_info info = {0};
    if (dladdr((void *)&resolve_springboard_path, &info) == 0 ||
        info.dli_fname == NULL) {
        return false;
    }
    size_t path_length = strlen(info.dli_fname);
    size_t hook_suffix_length = sizeof(kHookSuffix) - 1;
    if (path_length <= hook_suffix_length ||
        strcmp(info.dli_fname + path_length - hook_suffix_length,
               kHookSuffix) != 0) {
        return false;
    }
    size_t root_length = path_length - hook_suffix_length;
    if (root_length + sizeof(kSpringBoardSuffix) >
        sizeof(gSpringBoardPath)) {
        return false;
    }
    memcpy(gSpringBoardPath, info.dli_fname, root_length);
    memcpy(gSpringBoardPath + root_length, kSpringBoardSuffix,
           sizeof(kSpringBoardSuffix));
    struct stat status;
    return stat(gSpringBoardPath, &status) == 0 &&
           S_ISREG(status.st_mode) &&
           access(gSpringBoardPath, X_OK) == 0;
}

static int redirect_spawn(spawn_function original, pid_t *restrict pid,
                          const char *restrict path,
                          const posix_spawn_file_actions_t *restrict actions,
                          const posix_spawnattr_t *restrict attributes,
                          char *const argv[restrict],
                          char *const envp[restrict]) {
    if (path == NULL || strcmp(path, kOriginalSpringBoard) != 0) {
        return original(pid, path, actions, attributes, argv, envp);
    }
    /* Only this exact launchd job is redirected. Preserve its argument tail. */
    char *replacement_argv[257] = {(char *)gSpringBoardPath};
    size_t index = 0;
    if (argv != NULL) {
        while (index < 256 && argv[index] != NULL) {
            ++index;
        }
        if (index == 256) {
            log_result("argument-overflow", 0);
            return original(pid, path, actions, attributes, argv, envp);
        }
        for (size_t argument = 1; argument < index; ++argument) {
            replacement_argv[argument] = argv[argument];
        }
    }
    log_result("redirect-attempt", 0);
    int result = original(pid, gSpringBoardPath, actions, attributes,
                          replacement_argv, envp);
    log_result("redirect-result", result);
    return result;
}

static int redirected_spawn(pid_t *restrict pid, const char *restrict path,
                            const posix_spawn_file_actions_t *restrict actions,
                            const posix_spawnattr_t *restrict attributes,
                            char *const argv[restrict],
                            char *const envp[restrict]) {
    return redirect_spawn(gOriginalSpawn, pid, path, actions, attributes,
                          argv, envp);
}

static int redirected_spawnp(pid_t *restrict pid, const char *restrict path,
                             const posix_spawn_file_actions_t *restrict actions,
                             const posix_spawnattr_t *restrict attributes,
                             char *const argv[restrict],
                             char *const envp[restrict]) {
    return redirect_spawn(gOriginalSpawnp, pid, path, actions, attributes,
                          argv, envp);
}

__attribute__((constructor)) static void install_launchd_spawn_redirect(void) {
    if (getpid() != 1) {
        return;
    }
    gLog = os_log_create("com.openai.codex.dopamine.bootstrap",
                         "launchd-spawn-redirect");
    gInstallStage = 1;
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!launchd_uuid_matches(header) || !resolve_springboard_path()) {
        log_result("preflight-rejected", 0);
        return;
    }
    gInstallStage = 2;
    gOriginalSpawn = (spawn_function)dlsym(RTLD_DEFAULT, "posix_spawn");
    gOriginalSpawnp = (spawn_function)dlsym(RTLD_DEFAULT, "posix_spawnp");
    if (gOriginalSpawn == NULL || gOriginalSpawnp == NULL) {
        log_result("original-unavailable", 0);
        return;
    }
    gInstallStage = 3;

    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    void **slot = (void **)(uintptr_t)(slide + kPosixSpawnSlotVmaddr);
    void **slotp = (void **)(uintptr_t)(slide + kPosixSpawnpSlotVmaddr);
    void *current = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
    void *currentp = __atomic_load_n(slotp, __ATOMIC_ACQUIRE);
    if (ptrauth_strip(current, ptrauth_key_asia) !=
            ptrauth_strip((void *)gOriginalSpawn, ptrauth_key_asia) ||
        ptrauth_strip(currentp, ptrauth_key_asia) !=
            ptrauth_strip((void *)gOriginalSpawnp, ptrauth_key_asia)) {
        log_result("slot-mismatch", 0);
        return;
    }
    gInstallStage = 4;
    uintptr_t page_size = (uintptr_t)getpagesize();
    mach_vm_address_t page = (mach_vm_address_t)(uintptr_t)slot &
                             ~(mach_vm_address_t)(page_size - 1);
    if ((((mach_vm_address_t)(uintptr_t)slotp) &
         ~(mach_vm_address_t)(page_size - 1)) != page) {
        log_result("slots-not-same-page", 0);
        return;
    }
    gInstallStage = 5;
    kern_return_t result = mach_vm_protect(
        mach_task_self(), page, page_size, false,
        VM_PROT_READ | VM_PROT_WRITE);
    gProtectResult = result;
    if (result != KERN_SUCCESS) {
        log_result("write-protection-denied", result);
        return;
    }
    gInstallStage = 6;
    void *replacement = ptrauth_sign_unauthenticated(
        (void *)&redirected_spawn, ptrauth_key_asia,
        ptrauth_blend_discriminator(slot, 0));
    void *replacementp = ptrauth_sign_unauthenticated(
        (void *)&redirected_spawnp, ptrauth_key_asia,
        ptrauth_blend_discriminator(slotp, 0));
    __atomic_store_n(slot, replacement, __ATOMIC_RELEASE);
    __atomic_store_n(slotp, replacementp, __ATOMIC_RELEASE);
    result = mach_vm_protect(mach_task_self(), page, page_size, false,
                             VM_PROT_READ);
    gProtectResult = result;
    gInstallStage = 7;
    log_result("installed", result);
}
