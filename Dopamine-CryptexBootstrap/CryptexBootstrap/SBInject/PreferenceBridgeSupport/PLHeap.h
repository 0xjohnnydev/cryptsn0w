#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

// Finds live instances of a class by walking the malloc zones.
//
// The SwiftUI Settings model classes descend from _TtCs12_SwiftObject, not NSObject: they are
// allocated through swift_allocObject and never send +alloc, so there is no initialiser to
// hook, and none of them is reachable from an ObjC-visible property either. Zone enumeration
// is the only way in that does not depend on a stripped Swift symbol.
//
// Writes at most `capacity` instances into `out` and returns how many were found. Main thread
// only: the enumerator holds each zone's lock, so an allocation on another thread inside the
// callback would deadlock.
NSUInteger PLHeapFindInstances(Class cls, __unsafe_unretained id *out, NSUInteger capacity);

#ifdef __cplusplus
}
#endif
