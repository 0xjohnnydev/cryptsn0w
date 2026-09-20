#import "PLHeap.h"
#import <malloc/malloc.h>
#import <mach/mach.h>
#import <objc/runtime.h>

typedef struct {
    uintptr_t target;
    uintptr_t *slots;
    NSUInteger capacity;
    NSUInteger count;
} PLScan;

// Enumeration happens in this process, so a "remote" read is just the address itself.
static kern_return_t PLReader(task_t task, vm_address_t addr, vm_size_t size, void **out) {
    (void)task; (void)size;
    *out = (void *)addr;
    return KERN_SUCCESS;
}

static void PLRange(task_t task, void *ctx, unsigned type, vm_range_t *ranges, unsigned count) {
    (void)task;
    if (type != MALLOC_PTR_IN_USE_RANGE_TYPE) return;
    PLScan *scan = (PLScan *)ctx;
    for (unsigned i = 0; i < count; i++) {
        // Every range handed back is a live allocation, so reading its first word is safe. An
        // object smaller than isa plus one field cannot be one of the model classes.
        if (ranges[i].size < 2 * sizeof(void *)) continue;
        uintptr_t isa = *(uintptr_t *)ranges[i].address;
        // arm64 packs flags and the refcount around the class pointer.
        if ((isa & 0x0000000ffffffff8ULL) != scan->target && isa != scan->target) continue;
        if (scan->count >= scan->capacity) return;
        scan->slots[scan->count++] = (uintptr_t)ranges[i].address;
    }
}

NSUInteger PLHeapFindInstances(Class cls, __unsafe_unretained id *out, NSUInteger capacity) {
    if (!cls || !out || capacity == 0) return 0;

    vm_address_t *zones = NULL;
    unsigned int zoneCount = 0;
    if (malloc_get_all_zones(mach_task_self(), NULL, &zones, &zoneCount) != KERN_SUCCESS) return 0;

    // Stack memory on purpose: the callback runs while the zone it walks is locked, so it
    // must not allocate.
    uintptr_t slots[256];
    PLScan scan = {
        .target   = (uintptr_t)cls,
        .slots    = slots,
        .capacity = capacity < 256 ? capacity : 256,
        .count    = 0,
    };

    for (unsigned int i = 0; i < zoneCount; i++) {
        malloc_zone_t *zone = (malloc_zone_t *)zones[i];
        if (!zone || !zone->introspect || !zone->introspect->enumerator) continue;
        zone->introspect->enumerator(mach_task_self(), &scan, MALLOC_PTR_IN_USE_RANGE_TYPE,
                                     (vm_address_t)zone, PLReader, PLRange);
    }

    for (NSUInteger i = 0; i < scan.count; i++) out[i] = (__bridge id)(void *)slots[i];
    return scan.count;
}
