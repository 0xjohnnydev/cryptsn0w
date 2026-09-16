# iPhone 12 mini no-TSS dynamic-trust boundary, 2026-09-16

## Required acceptance condition

[REDACTED: Related request, payload, or installation details omitted.]

## What currently works
[REDACTED: TSS/Cryptex personalization and installation details are redacted from this educational source release.]

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

[REDACTED: Related request, payload, or installation details omitted.]
