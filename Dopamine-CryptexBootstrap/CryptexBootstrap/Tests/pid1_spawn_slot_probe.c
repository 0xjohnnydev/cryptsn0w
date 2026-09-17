#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool read_target(task_t task, uint64_t address, void *output,
                        size_t length) {
    vm_size_t received = 0;
    return vm_read_overwrite(task, (vm_address_t)address, (vm_size_t)length,
                             (vm_address_t)(uintptr_t)output,
                             &received) == KERN_SUCCESS &&
           received == length;
}

__attribute__((constructor)) static void inspect_launchd_spawn_slots(void) {
    task_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(mach_task_self(), 1, &task);
    if (result != KERN_SUCCESS) {
        dprintf(STDOUT_FILENO, "pid1-slot-probe task_for_pid=%d\n", result);
        return;
    }
    task_dyld_info_data_t dyld = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    result = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld, &count);
    struct dyld_all_image_infos images = {0};
    if (result != KERN_SUCCESS ||
        !read_target(task, dyld.all_image_info_addr, &images,
                     sizeof(images)) ||
        images.infoArrayCount > 4096) {
        dprintf(STDOUT_FILENO, "pid1-slot-probe image-info-failed=%d\n",
                result);
        mach_port_deallocate(mach_task_self(), task);
        return;
    }
    uint64_t launchd = 0;
    uint64_t hook = 0;
    uint64_t original_spawn = 0;
    uint64_t original_spawnp = 0;
    for (uint32_t index = 0; index < images.infoArrayCount; ++index) {
        struct dyld_image_info image = {0};
        char path[1024] = {0};
        uint64_t item = (uint64_t)(uintptr_t)images.infoArray +
                        (uint64_t)index * sizeof(image);
        if (!read_target(task, item, &image, sizeof(image))) {
            continue;
        }
        if (index == 0) {
            launchd = (uint64_t)(uintptr_t)image.imageLoadAddress;
        }
        if (!read_target(task, (uint64_t)(uintptr_t)image.imageFilePath,
                         path, 255)) {
            continue;
        }
        if (strcmp(path, "/sbin/launchd") == 0) {
            launchd = (uint64_t)(uintptr_t)image.imageLoadAddress;
        }
        if (strstr(path, "/codex-launchd-spawn-redirect.dylib") != NULL) {
            hook = (uint64_t)(uintptr_t)image.imageLoadAddress;
        }
    }
    dprintf(STDOUT_FILENO,
            "pid1-slot-probe launchd=0x%llx hook=0x%llx images=%u\n",
            (unsigned long long)launchd, (unsigned long long)hook,
            images.infoArrayCount);
    if (hook != 0) {
        uint64_t log_pointer = 0;
        uint64_t spawn_pointer = 0;
        uint64_t spawnp_pointer = 0;
        int install_stage = 0;
        kern_return_t protect_result = 0;
        char springboard_path[512] = {0};
        bool globals_read =
            read_target(task, hook + 0x10000ULL, &log_pointer,
                        sizeof(log_pointer)) &&
            read_target(task, hook + 0x10008ULL, &install_stage,
                        sizeof(install_stage)) &&
            read_target(task, hook + 0x10010ULL, &spawn_pointer,
                        sizeof(spawn_pointer)) &&
            read_target(task, hook + 0x10018ULL, &spawnp_pointer,
                        sizeof(spawnp_pointer)) &&
            read_target(task, hook + 0x10020ULL, &protect_result,
                        sizeof(protect_result));
        if (globals_read) {
            original_spawn = (uint64_t)(uintptr_t)ptrauth_strip(
                (void *)(uintptr_t)spawn_pointer, ptrauth_key_asia);
            original_spawnp = (uint64_t)(uintptr_t)ptrauth_strip(
                (void *)(uintptr_t)spawnp_pointer, ptrauth_key_asia);
        }
        bool path_read = read_target(task, hook + 0x10024ULL,
                                     springboard_path,
                                     sizeof(springboard_path) - 1);
        dprintf(STDOUT_FILENO,
                "pid1-slot-probe hook-globals read=%d stage=%d protect=%d "
                "log=0x%llx "
                "spawn=0x%llx spawnp=0x%llx stripped=0x%llx/0x%llx "
                "path-read=%d path=%s\n",
                globals_read, install_stage, protect_result,
                (unsigned long long)log_pointer,
                (unsigned long long)spawn_pointer,
                (unsigned long long)spawnp_pointer,
                (unsigned long long)original_spawn,
                (unsigned long long)original_spawnp, path_read,
                path_read ? springboard_path : "<unavailable>");
    }
    if (launchd != 0) {
        vm_address_t region_address = (vm_address_t)(launchd + 0x824f8ULL);
        vm_size_t region_size = 0;
        vm_region_basic_info_data_64_t region = {0};
        mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t region_object = MACH_PORT_NULL;
        kern_return_t region_result = vm_region_64(
            task, &region_address, &region_size, VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&region, &region_count, &region_object);
        dprintf(STDOUT_FILENO,
                "pid1-slot-probe slot-region result=%d start=0x%llx "
                "size=0x%llx protection=%d max=%d shared=%d\n",
                region_result, (unsigned long long)region_address,
                (unsigned long long)region_size, region.protection,
                region.max_protection, region.shared);
        if (region_object != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), region_object);
        }
        static const uint64_t offsets[] = {0x824f8ULL, 0x826a0ULL};
        static const char *const names[] = {"posix_spawn", "posix_spawnp"};
        for (size_t index = 0; index < 2; ++index) {
            uint64_t raw = 0;
            uint64_t slot = launchd + offsets[index];
            bool read = read_target(task, slot, &raw, sizeof(raw));
            uintptr_t stripped = read
                ? (uintptr_t)ptrauth_strip((void *)(uintptr_t)raw,
                                           ptrauth_key_asia)
                : 0;
            dprintf(STDOUT_FILENO,
                    "pid1-slot-probe %s slot=0x%llx read=%d "
                    "raw=0x%llx stripped=0x%llx matches-dlsym=%d "
                    "points-into-hook=%d\n",
                    names[index], (unsigned long long)slot, read,
                    (unsigned long long)raw, (unsigned long long)stripped,
                    stripped == (index == 0 ? original_spawn
                                           : original_spawnp),
                    hook != 0 && stripped >= hook &&
                        stripped - hook < 0x100000ULL);
        }
    }
    mach_port_deallocate(mach_task_self(), task);
}
