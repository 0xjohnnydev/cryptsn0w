// Darwin, not Foundation: the only thing needed from outside the stdlib is strdup, and
// importing Foundation would add libswiftFoundation and its dependencies to every launch of
// Settings for nothing.
import Darwin

// A Swift String cannot be built from C. String.init(cString:) and Foundation's
// _unconditionallyBridgeFromObjectiveC are both local symbols in the shared cache, so dlsym
// cannot reach them, and hand-assembling _StringObject would pin the tweak to an internal
// layout. Three functions of Swift are cheaper and use public API only.
//
// Every other value the root list needs is copied from one that already exists, so these are
// the only constructions the tweak performs.

/// Writes a Swift String built from `cString` into `out`, which must point at uninitialised
/// storage the size of a String. Ownership passes to the caller, who must eventually let the
/// value witness of the containing type destroy it.
@_cdecl("PLSwiftStringInitialize")
public func PLSwiftStringInitialize(_ cString: UnsafePointer<CChar>, _ out: UnsafeMutableRawPointer) {
    out.assumingMemoryBound(to: String.self).initialize(to: String(cString: cString))
}

/// Reads the Swift String at `pointer` and returns a copy the caller must free.
@_cdecl("PLSwiftStringCopyUTF8")
public func PLSwiftStringCopyUTF8(_ pointer: UnsafeRawPointer) -> UnsafeMutablePointer<CChar>? {
    return strdup(pointer.load(as: String.self))
}

/// Replaces the Swift String at `pointer` with one built from `cString`. Assignment rather than
/// initialisation because the old value has to be released, and going through Swift is the only
/// way to get that right without reimplementing String's value witness.
@_cdecl("PLSwiftStringAssign")
public func PLSwiftStringAssign(_ pointer: UnsafeMutableRawPointer, _ cString: UnsafePointer<CChar>) {
    pointer.assumingMemoryBound(to: String.self).pointee = String(cString: cString)
}
