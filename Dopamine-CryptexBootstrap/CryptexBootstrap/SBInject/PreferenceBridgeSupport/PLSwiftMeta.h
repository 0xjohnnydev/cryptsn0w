#import <Foundation/Foundation.h>

// A minimal reader for Swift's runtime type metadata.
//
// Everything the root list is made of -- the section array, the item array, the two identifier
// enums -- is internal to the SettingsApp module: no ObjC bridging, no exported symbols, and
// layouts Apple is free to change between releases. Rather than hardcode offsets per iOS
// version, the tweak asks the Swift runtime for them, so a renamed or restructured type fails
// to resolve instead of producing plausible nonsense at a stale offset.
//
// Only the pieces the tweak needs are implemented.

#ifdef __cplusplus
extern "C" {
#endif

// Resolves a type from its mangled name without the "$s" prefix, e.g.
// "11SettingsApp31PrimarySettingsListSectionModelV". NULL when unresolvable.
const void *PLSwiftTypeByMangledName(const char *mangledName);

// Value witness facts. Stride is what array indexing needs; size is not, because a struct may
// be padded.
size_t PLSwiftTypeSize(const void *metadata);
size_t PLSwiftTypeStride(const void *metadata);

// Byte offset of a struct field, or -1 if there is no such field. Offsets come from the
// metadata's field offset vector, names from the reflection field descriptor.
int32_t PLSwiftStructOffsetOfField(const void *metadata, const char *name);

// Byte offset of a stored property of a class, or -1 if there is no such property. Separate from
// the struct reader: a class keeps its descriptor past the ObjC-interop header and its field
// offsets are pointer-sized rather than 32-bit.
int32_t PLSwiftClassOffsetOfField(const void *metadata, const char *name);

// Allocates an instance of a Swift class with the header set up and the stored properties left
// uninitialised; every one has to be written before the object is handed anywhere. NULL when the
// metadata is not a class.
//
// Needed because the classes worth building come from a module shipped without Swift symbols, so
// there is no initialiser to call.
void *PLSwiftAllocObject(const void *metadata);

// Enum case of the value at `value`, and the name for a case index.
uint32_t PLSwiftEnumTag(const void *value, const void *metadata);
const char *PLSwiftEnumCaseName(const void *metadata, uint32_t tag);

// How many cases the enum declares. Lets a caller walk them all rather than name one.
uint32_t PLSwiftEnumCaseCount(const void *metadata);

// Whether the case carries a payload. An empty case can be written into a value with nothing
// more than its tag; one with a payload would need that payload built as well.
BOOL PLSwiftEnumCaseHasPayload(const void *metadata, uint32_t tag);

// The tag of the case with this name, or UINT32_MAX if the enum has no such case.
//
// Tags are positions in the case list and Apple reorders that list between releases:
// connectedHeadphones is tag 13 on iOS 26 and 11 on iOS 18, because iOS 26 added a payload case
// ahead of it. A tag written down against one release therefore names a different case on
// another, so they are always resolved by name.
uint32_t PLSwiftEnumTagNamed(const void *metadata, const char *caseName);

// Enum payload access. A multi-payload enum may keep its tag in spare bits inside the payload,
// so the payload cannot simply be read at offset zero: it is projected first and the tag
// injected back afterwards, which is what Swift itself does.
void PLSwiftEnumProject(void *value, const void *metadata);
void PLSwiftEnumInject(void *value, uint32_t tag, const void *metadata);

// Copies a value of `metadata`'s type, honouring its retain/release semantics. The models hold
// Strings and other references that a memcpy would not retain.
void PLSwiftValueInitializeWithCopy(void *destination, const void *source, const void *metadata);

// Releases what a value of `metadata`'s type holds, without freeing the storage itself. Needed
// before overwriting a field that owns references.
void PLSwiftValueDestroy(void *value, const void *metadata);

// Allocates a native Swift array buffer for `count` elements of the same type as the array at
// `templateField`, with the element storage left uninitialised. The buffer class is taken from
// the template: there is no way to name _ContiguousArrayStorage<Element> for an element type
// internal to another module, but the array already in the model is the right specialisation.
// NULL if the template has no buffer.
void *PLSwiftArrayAllocate(const void *templateField, NSInteger count,
                           size_t stride, size_t alignmentMask);

// Byte offset of the first element inside an array buffer.
size_t PLSwiftArrayElementOffset(void);

// Element count and allocated capacity of a native Swift array whose storage pointer sits at
// `arrayField`. Both return -1 for a nil Optional array field. Capacity matters because an
// array grown by repeated appends usually has room to spare, and spare room is the difference
// between appending a section in place and having to replace the buffer.
NSInteger PLSwiftArrayCount(const void *arrayField);
NSInteger PLSwiftArrayCapacity(const void *arrayField);

// Address of element `index`, or NULL when out of range.
const void *PLSwiftArrayElement(const void *arrayField, NSInteger index, size_t stride);

// Implemented in PLSwiftToggle.swift; see there for why they are not plain C.
typedef void (*PLBoolCallback)(const void *token, BOOL value);
BOOL PLSwiftObservationRegistrarInitialize(void *out);
NSInteger PLSwiftObservationRegistrarSize(void);
void PLSwiftBoolClosureInitialize(void *out, PLBoolCallback callback, const void *token);
void PLSwiftBoolClosureDestroy(void *pointer);
NSInteger PLSwiftBoolClosureSize(void);

// Implemented in PLSwiftString.swift; see there for why they are not plain C.
void PLSwiftStringInitialize(const char *cString, void *out);
void PLSwiftStringAssign(void *pointer, const char *cString);
char *PLSwiftStringCopyUTF8(const void *pointer);

#ifdef __cplusplus
}
#endif
