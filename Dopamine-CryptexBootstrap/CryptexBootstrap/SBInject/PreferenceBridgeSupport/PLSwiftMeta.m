#import "PLSwiftMeta.h"
#import <dlfcn.h>
#import <ptrauth.h>

// On arm64e the pointers inside Swift metadata are signed: the value witness table and the
// nominal type descriptor with the data key, the individual witnesses with the function key.
// Dereferencing one raw faults. Stripping suffices because nothing is re-signed and written
// back. On arm64 both macros expand to the pointer unchanged.
#define PL_STRIP_DATA(p) ptrauth_strip((p), ptrauth_key_process_independent_data)
#define PL_STRIP_CODE(p) ptrauth_strip((p), ptrauth_key_function_pointer)

// Stripping is enough to read a witness pointer, not to call one. This file is built with
// -fptrauth-calls, so an indirect call emits blraaz and the CPU authenticates with the IA key
// and a zero discriminator. A stripped pointer fails that check without trapping -- the failure
// sets bit 61, so the branch lands far out of range and the process spins there. Swift signs
// value witnesses with a different key and a per-witness discriminator, so the pointer is
// re-signed for exactly what the call site checks rather than matching Swift's scheme.
#define PL_CALLABLE(p) ptrauth_sign_unauthenticated(PL_STRIP_CODE(p), ptrauth_key_function_pointer, 0)

// --- Swift ABI constants ------------------------------------------------------------
// Documented in the Swift repository under docs/ABI. These offsets are part of the stable ABI
// and have not moved since Swift 5; changing them would be a platform-wide ABI break rather
// than a Settings.app change. That is why this file exists instead of a table of per-version
// struct offsets.

// Native Swift array buffer: HeapObject header (isa, refcount), then _ArrayBody (count,
// capacityAndFlags), then the elements. The low bit of capacityAndFlags is a flag, not part of
// the capacity, so it is preserved rather than recomputed.
enum { kPLArrayCount = 16, kPLArrayCapacity = 24, kPLArrayElements = 32 };

enum { kPLVWTDestroy = 8, kPLVWTInitializeWithCopy = 16,
       kPLVWTSize = 64, kPLVWTStride = 72,
       kPLVWTGetEnumTag = 88, kPLVWTProjectEnumData = 96, kPLVWTInjectEnumTag = 104 };

// Nominal type descriptors: shared prefix, then per-kind fields.
enum {
    kPLDescFlags       = 0,
    kPLDescParent      = 4,
    kPLDescName        = 8,
    kPLDescAccessor    = 12,
    kPLDescFields      = 16,
    kPLDescNumFields   = 20,   // struct only
    kPLDescFieldVector = 24,   // struct only, in pointer-sized words from the metadata
};

// Reflection field descriptor, pointed at by kPLDescFields.
enum {
    kPLFieldDescNumFields  = 12,
    kPLFieldDescRecords    = 16,
    kPLFieldRecordSize     = 12,
    kPLFieldRecordType     = 4,
    kPLFieldRecordName     = 8,
};

typedef const void *(*PLTypeByNameFn)(const char *, size_t, const void *, const void *const *);
typedef unsigned (*PLGetEnumTagFn)(const void *, const void *);
typedef void (*PLProjectEnumFn)(void *, const void *);
typedef void (*PLInjectEnumFn)(void *, unsigned, const void *);
typedef void *(*PLCopyFn)(void *, const void *, const void *);
typedef void *(*PLAllocObjectFn)(const void *, size_t, size_t);

// Relative pointers are 32-bit signed displacements from their own address. A set low bit marks
// an indirect reference; both forms are handled so the helper stays reusable.
static const void *PLRelative(const void *base, int32_t offset, BOOL allowIndirect) {
    if (offset == 0) return NULL;
    BOOL indirect = allowIndirect && (offset & 1);
    if (indirect) offset &= ~1;
    const void *target = (const uint8_t *)base + offset;
    return indirect ? *(const void *const *)target : target;
}

// Class metadata, past the Objective-C interop header: isa, superclass, two cache words and the
// rodata pointer, then the class's own fields. InstanceSize and InstanceAlignMask are what
// swift_allocObject wants; Description is where the layout is described.
enum {
    kPLClassInstanceSize      = 48,
    kPLClassInstanceAlignMask = 52,
    kPLClassDescription       = 64,
};

// Class descriptor, after the prefix shared with structs and enums.
enum {
    kPLClassDescNumFields         = 36,
    kPLClassDescFieldVectorOffset = 40,   // in pointer-sized words from the metadata
};

// A class's first word is its isa, a pointer; every other metadata kind puts a small integer
// there. Kinds run to 0x501, so anything above that range is a class.
enum { kPLMetadataKindLastNonClass = 0x7ff };

static BOOL PLIsClassMetadata(const void *metadata) {
    if (!metadata) return NO;
    return (uintptr_t)*(const void *const *)metadata > kPLMetadataKindLastNonClass;
}

// Structs and enums keep their nominal type descriptor at the second word of their metadata; a
// class keeps it past the interop header. Everything reading a field descriptor goes through here,
// so the distinction is drawn once: getting it wrong for a class reads names out of the superclass
// pointer and matches nothing.
static const void *PLDescriptor(const void *metadata) {
    if (!metadata) return NULL;
    if (PLIsClassMetadata(metadata))
        return PL_STRIP_DATA(*(const void *const *)((const uint8_t *)metadata + kPLClassDescription));
    return PL_STRIP_DATA(((const void *const *)metadata)[1]);
}

static const void *PLFieldDescriptor(const void *metadata) {
    const void *desc = PLDescriptor(metadata);
    if (!desc) return NULL;
    const uint8_t *fieldsSlot = (const uint8_t *)desc + kPLDescFields;
    return PLRelative(fieldsSlot, *(const int32_t *)fieldsSlot, NO);
}

static const void *PLValueWitnesses(const void *metadata) {
    if (!metadata) return NULL;
    return PL_STRIP_DATA(((const void *const *)metadata)[-1]);
}

const void *PLSwiftTypeByMangledName(const char *mangledName) {
    static PLTypeByNameFn fn;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fn = (PLTypeByNameFn)dlsym(RTLD_DEFAULT, "swift_getTypeByMangledNameInContext");
    });
    if (!fn || !mangledName) return NULL;
    return fn(mangledName, strlen(mangledName), NULL, NULL);
}

size_t PLSwiftTypeSize(const void *metadata) {
    const void *vwt = PLValueWitnesses(metadata);
    return vwt ? *(const size_t *)((const uint8_t *)vwt + kPLVWTSize) : 0;
}

size_t PLSwiftTypeStride(const void *metadata) {
    const void *vwt = PLValueWitnesses(metadata);
    return vwt ? *(const size_t *)((const uint8_t *)vwt + kPLVWTStride) : 0;
}

static uint32_t PLSwiftStructFieldCount(const void *metadata) {
    const void *desc = PLDescriptor(metadata);
    return desc ? *(const uint32_t *)((const uint8_t *)desc + kPLDescNumFields) : 0;
}

static uint32_t PLSwiftStructFieldOffset(const void *metadata, uint32_t index) {
    const void *desc = PLDescriptor(metadata);
    if (!desc || index >= PLSwiftStructFieldCount(metadata)) return 0;
    uint32_t vectorWord = *(const uint32_t *)((const uint8_t *)desc + kPLDescFieldVector);
    const uint32_t *offsets = (const uint32_t *)((const void *const *)metadata + vectorWord);
    return offsets[index];
}

// Fields and cases both live in the reflection field descriptor, which stores one fixed-size
// record per field or case. The record size is read rather than assumed, because a future
// runtime may add words to it.
static const uint8_t *PLRecord(const void *metadata, uint32_t index) {
    const void *fd = PLFieldDescriptor(metadata);
    if (!fd) return NULL;
    uint32_t count = *(const uint32_t *)((const uint8_t *)fd + kPLFieldDescNumFields);
    if (index >= count) return NULL;
    uint16_t recordSize = *(const uint16_t *)((const uint8_t *)fd + 10);
    if (recordSize == 0) recordSize = kPLFieldRecordSize;
    return (const uint8_t *)fd + kPLFieldDescRecords + (size_t)index * recordSize;
}

// The name is the third word of the record.
static const char *PLRecordName(const void *metadata, uint32_t index) {
    const uint8_t *record = PLRecord(metadata, index);
    if (!record) return NULL;
    const uint8_t *nameSlot = record + kPLFieldRecordName;
    return (const char *)PLRelative(nameSlot, *(const int32_t *)nameSlot, NO);
}

int32_t PLSwiftStructOffsetOfField(const void *metadata, const char *name) {
    uint32_t count = PLSwiftStructFieldCount(metadata);
    for (uint32_t i = 0; i < count; i++) {
        const char *field = PLRecordName(metadata, i);
        if (field && strcmp(field, name) == 0) return (int32_t)PLSwiftStructFieldOffset(metadata, i);
    }
    return -1;
}

int32_t PLSwiftClassOffsetOfField(const void *metadata, const char *name) {
    if (!PLIsClassMetadata(metadata) || !name) return -1;
    const void *desc = PLDescriptor(metadata);
    if (!desc) return -1;
    uint32_t count = *(const uint32_t *)((const uint8_t *)desc + kPLClassDescNumFields);
    uint32_t vectorWord = *(const uint32_t *)((const uint8_t *)desc + kPLClassDescFieldVectorOffset);
    if (count == 0 || vectorWord == 0) return -1;

    // Pointer-sized entries, unlike a struct's, and read through the metadata: with a resilient
    // superclass the offsets are only known once the metadata has been built.
    const uintptr_t *offsets = (const uintptr_t *)((const void *const *)metadata + vectorWord);
    uint32_t instanceSize = *(const uint32_t *)((const uint8_t *)metadata + kPLClassInstanceSize);

    // The field descriptor lists the properties in the same order as the offset vector.
    for (uint32_t i = 0; i < count; i++) {
        const char *field = PLRecordName(metadata, i);
        if (!field || strcmp(field, name) != 0) continue;
        uintptr_t offset = offsets[i];
        // A plausible offset is inside the object and past its header; anything else means the
        // vector was not where it was expected.
        if (offset < 16 || offset >= instanceSize) return -1;
        return (int32_t)offset;
    }
    return -1;
}

void *PLSwiftAllocObject(const void *metadata) {
    static PLAllocObjectFn fn;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fn = (PLAllocObjectFn)dlsym(RTLD_DEFAULT, "swift_allocObject");
    });
    if (!fn || !PLIsClassMetadata(metadata)) return NULL;
    uint32_t size = *(const uint32_t *)((const uint8_t *)metadata + kPLClassInstanceSize);
    uint16_t alignMask = *(const uint16_t *)((const uint8_t *)metadata + kPLClassInstanceAlignMask);
    if (size < 16) return NULL;
    return fn(metadata, size, alignMask);
}

uint32_t PLSwiftEnumTag(const void *value, const void *metadata) {
    const void *vwt = PLValueWitnesses(metadata);
    if (!vwt || !value) return UINT32_MAX;
    void *raw = *(void **)((const uint8_t *)vwt + kPLVWTGetEnumTag);
    if (!raw) return UINT32_MAX;
    PLGetEnumTagFn fn = (PLGetEnumTagFn)PL_CALLABLE(raw);
    return fn(value, metadata);
}

static void *PLWitness(const void *metadata, size_t offset) {
    const void *vwt = PLValueWitnesses(metadata);
    if (!vwt) return NULL;
    void *raw = *(void **)((const uint8_t *)vwt + offset);
    return raw ? PL_CALLABLE(raw) : NULL;
}

typedef void (*PLDestroyFn)(void *, const void *);

void PLSwiftValueDestroy(void *value, const void *metadata) {
    PLDestroyFn fn = (PLDestroyFn)PLWitness(metadata, kPLVWTDestroy);
    if (fn) fn(value, metadata);
}

void PLSwiftValueInitializeWithCopy(void *destination, const void *source, const void *metadata) {
    PLCopyFn fn = (PLCopyFn)PLWitness(metadata, kPLVWTInitializeWithCopy);
    if (fn) fn(destination, source, metadata);
}

// The buffer's class pointer is its isa, masked before use: a packed or tagged isa read raw
// would hand swift_allocObject something that is not a class.
//
// Taking the class from an existing array is what makes this possible at all. There is no way
// to name _ContiguousArrayStorage<Element> for an element type internal to another module, but
// the array already in the model is exactly the right specialisation.
void *PLSwiftArrayAllocate(const void *templateField, NSInteger count,
                           size_t stride, size_t alignmentMask) {
    static PLAllocObjectFn allocate;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        allocate = (PLAllocObjectFn)dlsym(RTLD_DEFAULT, "swift_allocObject");
    });
    if (!allocate || !templateField || count <= 0 || stride == 0) return NULL;

    uintptr_t template = *(const uintptr_t *)templateField;
    if (!template) return NULL;
    const void *storageClass = (const void *)(*(const uintptr_t *)template & 0x0000000ffffffff8ULL);
    if (!storageClass) return NULL;

    size_t bytes = kPLArrayElements + (size_t)count * stride;
    uintptr_t buffer = (uintptr_t)allocate(storageClass, bytes,
                                           alignmentMask < 7 ? 7 : alignmentMask);
    if (!buffer) return NULL;

    *(NSInteger *)(buffer + kPLArrayCount) = count;
    // Capacity is stored shifted left by one; the low bit is a runtime flag, carried over from
    // the template rather than invented.
    uintptr_t templateFlags = *(const uintptr_t *)(template + kPLArrayCapacity) & 1;
    *(uintptr_t *)(buffer + kPLArrayCapacity) = ((uintptr_t)count << 1) | templateFlags;
    return (void *)buffer;
}

size_t PLSwiftArrayElementOffset(void) { return kPLArrayElements; }

NSInteger PLSwiftArrayCapacity(const void *arrayField) {
    if (!arrayField) return -1;
    uintptr_t storage = *(const uintptr_t *)arrayField;
    if (!storage) return -1;
    return (NSInteger)(*(const uintptr_t *)(storage + kPLArrayCapacity) >> 1);
}

void PLSwiftEnumProject(void *value, const void *metadata) {
    PLProjectEnumFn fn = (PLProjectEnumFn)PLWitness(metadata, kPLVWTProjectEnumData);
    if (fn) fn(value, metadata);
}

void PLSwiftEnumInject(void *value, uint32_t tag, const void *metadata) {
    PLInjectEnumFn fn = (PLInjectEnumFn)PLWitness(metadata, kPLVWTInjectEnumTag);
    if (fn) fn(value, tag, metadata);
}

// Tags number the payload cases first, then the empty ones, each group in declaration order.
// Every enum this tweak reads declares its payload cases first, so a straight index into the
// record list matches; one that interleaved them would not.
const char *PLSwiftEnumCaseName(const void *metadata, uint32_t tag) {
    if (tag == UINT32_MAX) return NULL;
    return PLRecordName(metadata, tag);
}

uint32_t PLSwiftEnumCaseCount(const void *metadata) {
    const void *fd = PLFieldDescriptor(metadata);
    return fd ? *(const uint32_t *)((const uint8_t *)fd + kPLFieldDescNumFields) : 0;
}

// The second word of a case's record points at the mangled name of what the case carries, and is
// null for a case that carries nothing.
BOOL PLSwiftEnumCaseHasPayload(const void *metadata, uint32_t tag) {
    const uint8_t *record = PLRecord(metadata, tag);
    return record && *(const int32_t *)(record + kPLFieldRecordType) != 0;
}

uint32_t PLSwiftEnumTagNamed(const void *metadata, const char *caseName) {
    if (!caseName) return UINT32_MAX;
    uint32_t count = PLSwiftEnumCaseCount(metadata);
    for (uint32_t i = 0; i < count; i++) {
        const char *name = PLRecordName(metadata, i);
        if (name && strcmp(name, caseName) == 0) return i;
    }
    return UINT32_MAX;
}

// --- Native Swift arrays -------------------------------------------------------------
// The count sits at a fixed offset and is independent of the element type, so a list length can
// be read before any element can be decoded.

NSInteger PLSwiftArrayCount(const void *arrayField) {
    if (!arrayField) return -1;
    uintptr_t storage = *(const uintptr_t *)arrayField;
    if (storage == 0) return -1;
    return *(const NSInteger *)(storage + kPLArrayCount);
}

const void *PLSwiftArrayElement(const void *arrayField, NSInteger index, size_t stride) {
    NSInteger count = PLSwiftArrayCount(arrayField);
    if (count < 0 || index < 0 || index >= count || stride == 0) return NULL;
    uintptr_t storage = *(const uintptr_t *)arrayField;
    return (const void *)(storage + kPLArrayElements + (size_t)index * stride);
}
