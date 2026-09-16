# iPhone 12 mini runtime acceptance — 2026-09-15

This record separates three independently measured boundaries on the validated
iPhone13,1 / iPhone 12 mini running iOS 27.0 build 24A437: executable-page
operation order, root package execution, and protected-process dylib trust.

## Matched Cryptex replacement

The latest replacement run
`Dopamine-upstream/CryptexBootstrap/out/runs/20260916T033815Z-dcb25276`
completed with `result=success`, replaced
`1.0.20260916021819.873389`, and installed:

[REDACTED: Related request, payload, or installation details omitted.]

The host observed the mounted daemon, root broker, and provisioned Sileo app
after installation. The clean-reboot/remount path remains a separate pending
acceptance test.

## Executable-page order proof

The pre-correction page probe requested RX before attempting its first remote
write. The target was already debugger-softened, RX returned 0, but
`mach_vm_write` returned `KERN_INVALID_ADDRESS`; the probe ended with status 84.

The rebuilt probe mirrors current hookd:

1. allocate the target page;
2. request `VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY`;
3. write and flush the AArch64 `return 42` function;
4. request `VM_PROT_READ|VM_PROT_EXECUTE`;
5. remap-query the effective protection before branching; and
6. call the generated function only when execute permission survived.

The device log for Sileo PID 959 was:

```text
elleKitTargetCodesign pid=959 before=0x32003005 after=0x32003005 alreadySoftened=true
elleKitPageProbe pid=959 status=0 allocate=0 writeProtect=0 codeWrite=0 flush=0 rx=0 verifyRemap=0 verifyCurrent=0x5 call=0 return=42
```

This proves the present `RW|COPY -> write -> RX` mechanism on 24A437. It also
shows why checking only the protection call's return value is insufficient: the
probe verifies the kernel-reported effective protection before execution.

## BrokerProbe package boundary

BrokerProbe 1.0.14, SHA-256
`72b889776e1e971dee04be3912e234681ecc7d4b78769078912114fe785412d3`,
was installed through Sileo while matched Cryptex version
`1.0.20260916021819.873389` was active. The Sileo virtual job and `apt-get`
both returned 0. Preserved post-install evidence reported:

```text
postinst-uid=0 gid=0 package=com.openai.codex.broker-probe version=1.0.14 runtime-admission=pinned-load arbitrary-exec=passed
ARBITRARY_EXEC_PROBE version=1.0.14 pid=846 uid=0 gid=0
```

`dpkg` also reported `install ok installed`. This proves package unpack, root
`postinst`, and root execution of one non-baseline package Mach-O without adding
that payload to the static Cryptex trust cache. It does not yet prove complete
Mach-O or transparent child-process compatibility for arbitrary packages.

BrokerProbe's new `TweakInject/BrokerProbe.dylib` crossed a different boundary.
AMFI reported that it had no CMS blob, an unrecoverable CoreTrust signature
issue, and failed code-signature validation. Its SpringBoard constructor did
not run. The result must not be described as arbitrary unsigned SpringBoard
dylib injection; only the fixed trust-cached ElleKit injector passed.

## Cleanup and final state

After preserving the evidence, the exact test package was removed with
`apt=0`, `/var/mobile/.eksafemode` was removed with `marker=0`, and a normal
`sbreload` was requested through the process-bound Sileo root broker. The final
stable SpringBoard was PID 1013. The Cryptex daemon recorded:

```text
elleKitPerProcessInjection lane=springboard pid=1013 ... elleKitStatus=0 status=0
elleKitPerProcessInjectorHeartbeat lane=springboard ... safeMode=false
```

The Cryptex daemon and root broker remained running. PID 1 stayed
`/sbin/launchd` and was never selected for attach, injection, termination, or
respring. A final ordinary FrontBoard launch also started Sileo normally as PID
1027 alongside stable SpringBoard PID 1013.
