# TXM debugger-region gates on iPhone18,2 24A435

This note records static analysis of the exact
`Firmware/txm.iphoneos.release` shipped for iPhone18,2 build 24A435. It separates
the primitive that works in the installed fixed worker from the authorization
still missing for arbitrary executable pages in SpringBoard.

## Artifact and database

- TXM SHA-256:
  `e058931840ac000f6d050578fd7fc4ddb8c640125d92a713f61433be793fbf04`
- Reusable IDA database: `build/ida/txm.24A435.i64`
- Database processor: ARM little-endian, 64-bit
- Completed function analysis: 1,492 functions

The IDA names below are analysis annotations, not claimed original symbols:

| Address | Annotation | API selector |
| --- | --- | --- |
| `0xfffffff017033590` | `txm_allow_invalid_code` | 41, `AllowInvalidCode` |
| `0xfffffff0170333a4` | `txm_associate_debug_region` | 42, `AssociateDebugRegion` |
| `0xfffffff017033274` | `txm_associate_jit_region` | 40, `AssociateJITRegion` |
| `0xfffffff017020395` | `txm_research_configuration_enabled` | policy state |
| `0xfffffff017020396` | `txm_extended_research_configuration_enabled` | policy state |
| `0xfffffff017088db4` | `txm_developer_mode_enabled` | policy state |

## Selector 41: authorize the address space

`AllowInvalidCode` first requires developer mode. It then sets the target
address space's `allowsInvalidCode` byte at offset `+0x30` through one of these
routes:

1. the target has `get-task-allow`;
2. the current caller has `research.com.apple.license-to-operate` **and** the
   runtime security-research configuration is enabled; or
3. a separate development/release override is enabled.

[REDACTED: Related request, payload, or installation details omitted.]

## Selector 42: authorize each executable region

`AssociateDebugRegion` validates page alignment and range, checks
`com.apple.private.cs.debugger` on the current caller, and then checks the
target address space's `allowsInvalidCode` byte. A caller without the debugger
entitlement is rejected before the target-state check; a target without
`allowsInvalidCode` is also rejected.

XNU's surrounding path can strip execute permission after this denial while
the outer `vm_protect` operation still returns success. A page probe must inspect
the resulting protection rather than treating `KERN_SUCCESS` as execution
proof.

## Two different order constraints

The public `vm_protect` order remains:

`task, address, size, set_maximum, new_protection`

The current hook-daemon
[`sender`](../Dopamine-upstream/BaseBin/libjailbreak/src/hookd.c#L104-L110)
serializes the final fields as `set_maximum` and `prot`; its
[`receiver`](../Dopamine-upstream/BaseBin/hookd/src/main.c#L71-L80) passes them
to `vm_protect` in that same order. The first public revision containing this
path is already correct.

The page-operation bug reproduced on the iPhone 12 mini was not an ABI-field
swap. Requesting RX before the first `mach_vm_write` let the
protection call return 0 but made the write fail with `KERN_INVALID_ADDRESS`.
The corrected probe follows hookd's
[`apply_hook`](../Dopamine-upstream/BaseBin/hookd/src/main.c#L30-L65): request
`RW|COPY`, write and flush the bytes, then request RX. On 24A437 all stages
returned 0, the resulting protection was `0x5`, and the generated function
returned 42.

That observation is separate from opa's relevant trust-cache order change.
Upstream commit `123eef3689c1610d3c3718646ece50b8354c6b90` appends Dopamine's
cache at the tail of the SPTM/TXM live trust-cache list so that TXM can continue
prepending signed caches without trying to write the jailbreak allocation's
`prevptr`. The trust-cache mechanism works without TSS when a jailbreak retains
kernel read/write; the page-operation result neither provides nor replaces that
primitive.

## Consequence for this environment

The installed fixed worker path works now because its child has
`get-task-allow`, the attach path establishes `allowsInvalidCode`, and the page
operation runs from a fixed binary with `com.apple.private.cs.debugger`. Root is
the coordinator for those admitted binaries, not the source of either TXM
authorization.

SpringBoard is a separate case. A task port and a loaded trust-cached library do
not give that address space `allowsInvalidCode`; it has no `get-task-allow`, and
the retail configuration does not activate the LTO research route. Arbitrary
SpringBoard executable pages therefore remain unproven without a kernel-level
state change or another equivalent authorization primitive.
