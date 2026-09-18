# iPhone 12 mini no-TSS dynamic-trust boundary, 2026-09-16

## Required acceptance condition

A newly installed native tweak must become loadable after boot while Apple TSS
is unavailable. Replaying a previously personalized cache does not satisfy this
condition, and neither does executing data inside the fixed GTA/debugger worker.

## What currently works

The broker can scan package Mach-Os, generate a version-1 cache, request an
Apple-personalized Generic Cryptex1 `gtcd` manifest, load the stitched IMG4
through AMFI, and only then allow package configuration. Accepted caches are
journaled and replayed after reboot. This path works, including CylinderReborn
inside SpringBoard, but a new native cdhash still requires TSS.

## The actual local Dopamine mechanism

Dopamine's `jb_trustcache_add_cdhashes` adds cdhashes to a jailbreak-managed
cache and publishes that allocation into the live trust-cache list. On
SPTM/TXM, `_trustcache_list_get_start` follows `txm_trustcache_root` and commit
`123eef3689c1610d3c3718646ece50b8354c6b90` changes insertion to the list tail:
TXM prepends signed caches and cannot write the `prevptr` in Dopamine's
read-only allocation. This is the relevant "swapped order" clue.

This route does not contact TSS, but it depends on retained `kread`, `kwrite`,
and `kalloc`, normally served through Dopamine's jbserver/libjailbreak stack.

## On-device provider probe

A root package `com.openai.codex.local-trust-probe` checked the active `/var/jb`
environment. None of these provider components exists:

- `/var/jb/basebin/jbctl`
- `/var/jb/usr/bin/jbctl`
- `/var/jb/basebin/libjailbreak.dylib`
- `/var/jb/usr/lib/libjailbreak.dylib`
- `/var/jb/basebin/jbserver`
- `/var/jb/Library/LaunchDaemons/com.opa334.jailbreakd.plist`

A second package decoded a probe only inside the already trusted execution
worker, so package admission itself could not invoke runtime TSS. As root with
platform/debugger entitlements, it observed:

```text
taskForPidSelf result=0
taskForPidZero result=5 (os/kern failure) port=0 valid=false
hostSpecial slot=4 result=0 port=0 valid=false
hostSpecial slot=5 result=0 port=0 valid=false
hostSpecial slot=6 result=0 port=0 valid=false
hostSpecial slot=7 result=0 port=0 valid=false
```

The current environment therefore has neither a kernel task port nor a retained
special-port kernel read/write provider. Root and a SpringBoard task port are
not substitutes for this capability.

## AMFI/TXM alternate-loader result

Exact-build static analysis closed the apparent AMFI user-client shortcut.
Selector 2 accepts a complete Image4 trust-cache object. Selector 7 accepts the
cache and external manifest as separate buffers. Both reach the same kernel
trust-cache loader and TXM Image4 evaluation; TXM performs CoreTrust chain and
signature verification. Reversing the selector-7 buffer order can repair a
malformed call, but cannot turn it into an unsigned/raw-cache loader.

## Implementation boundary

The project has not yet achieved TSS-free admission of a newly installed native
Mach-O tweak. For literal native-dylib admission, the next required primitive is
still retained kernel/SPTM read-write (or an equivalent ability to mutate TXM's
live trust-cache state). Once that exists, the broker can port Dopamine's
tail-insertion logic and add each new package cdhash locally. Until then, the
TSS-backed broker path must be described only as a compatibility fallback,
never as completion of the native no-TSS goal.

## TSS-free in-process data runtime, 2026-09-17

A separate route now works and materially changes the functional-tweak design
space. The fixed trusted loader was spawned with SpringBoard's pointer-auth
context using `posix_spawnattr_set_ptrauth_task_port_np`. From that helper, the
probe obtained the exact SpringBoard task port, created a genuine SpringBoard
pthread, and signed a fixed self-loop as its start routine. The helper's bounded
call path was adjusted in memory so calls use that pthread's real stack rather
than an anonymous VM stack; the arm64e opaque SP was stripped and then signed
once by the existing thread-state setter. All helper patches were guarded by
exact original bytes and restored before detach.

On SpringBoard PID 3592, the complete sequence succeeded:

```text
springboard-real-pthread=success
springboard-three-argument-call=success
JSContext_init return=<non-null context>
springboard-jsc-evaluation=success expression='40 + 2' result=42
jsc-worker-pthread-cleanup=success
```

SpringBoard remained the same healthy PID after the probe and the dedicated
pthread returned to its original count. This path made no TSS request and did
not admit new native code: it reused fixed trusted code plus a dynamic script as
data. It therefore does not yet satisfy literal dylib admission, but it is a
credible TSS-free substrate for implementing tweak behavior without loading
each tweak as a new Mach-O.

The immediate engineering work is to move the proven sequence from the host
debug controller into the resident on-device broker, retain a SpringBoard-side
JS context, expose a deliberately narrow Objective-C bridge, and prove one
reversible UI hook. PID 1 remains categorically out of scope; every target must
continue to resolve to the exact SpringBoard executable path.

## Cross-process executable-page donor result, 2026-09-17

The debug child was also tested as an executable-page donor. The child held a
small anonymous RX page containing a BTI-compatible function that returns 42.
The SpringBoard helper discovered the donor region, verified its source bytes,
remapped it into SpringBoard, and verified both the destination bytes and the
resulting `current=RX, maximum=RWX` protection. A genuine SpringBoard pthread
and the already proven native-call stack were then used to call the remapped
function.

The remap itself succeeded, but the first instruction fetch killed SpringBoard.
The exact launchd exit record was:

```text
namespace: 3 code: 0x2 - OS_REASON_CODESIGNING
```

In the matching XNU headers, code 2 in that namespace is
`CODESIGNING_EXIT_REASON_INVALID_PAGE`. This distinguishes the failure from
pointer authentication, return signing, stack setup, remap protection, or byte
copying. Executable trust from a debugged donor is not transferable into
SpringBoard's address space.

## Exact AMFI run-invalid policy

The reusable headless database for the device's 24A437 AMFI image matches SHA-256
`6a3439f00d2ef0389c1e56eaad3765b5a7ed830ece2cd767c9334749fd0c56c7`.
Mapping its MAC operation vector against the matching XNU
`struct mac_policy_ops` identifies `0xfffffff008e535bc` as
`mpo_proc_check_run_cs_invalid`.

The retail hook has only one usable route:

1. Developer Mode must be enabled.
2. The process that will run invalid code must itself have `get-task-allow`.

The alternative `research.com.apple.license-to-operate` branch is guarded by a
research-configuration helper that is compiled in this image as an unconditional
`return 0`. The tracer's root identity, `com.apple.private.cs.debugger`,
`task_for_pid-allow`, and system-task-port entitlements do not satisfy this
target-side check. This explains why the broker can attach and control
SpringBoard while its `CS_HARD|CS_KILL` flags remain unchanged. Direct DDI
`debugserver` attach was independently rejected with `E96`; changing debugger
identity is not a shortcut around the target policy.

## Local-signing and compilation-service gates

AMFI exposes real TSS-free local-signing machinery: policy selectors 99 and 100
set a 97-byte P-384 public key and authorize a cdhash, gated respectively by
`com.apple.private.playgrounds-local-signing-allowed` and
`com.apple.private.enable-swift-playgrounds-validation`. Selector 98 confirms a
local public key is available, while copying the private key is explicitly
unsupported on this platform.

This is not a usable iPhone bypass. During AMFI initialization the local-JIT
feature byte is first enabled and then explicitly cleared when the DeviceTree
model begins with `iPhone`. Local-signature validation checks that byte before
consulting the public key. The compilation-service cdhash set and
`com.apple.private.amfi.can-execute-cdhash` override use the same byte, so adding
the private entitlements to the fixed root helper would still leave validation
disabled. The byte has no runtime setter in the AMFI image; its only writes are
the early initialization sequence.

## Next bounded architecture test

The remaining userland-only design worth testing is not donor remapping. It is
an in-place re-exec of SpringBoard into a fixed, already admitted copy whose own
signature contains `get-task-allow` and disabled library validation. If the
process retains its launch bootstrap identity and reaches a healthy UI, a normal
debug attach should then set `CS_DEBUGGED` and `allowsInvalidCode`; newly
installed ad-hoc dylibs could be admitted without rebuilding a trust cache.

This remains unproven and requires a fixed bootstrap artifact to be admitted
once. It would solve future post-boot package admission without TSS, not create
an unsigned local trust-cache loader. The first experiment must use a separate
copied bundle and exact process/path guards; it must not select, attach to, or
modify PID 1.
