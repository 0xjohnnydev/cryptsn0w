# iPhone 12 mini clean-reboot runtime-trust replay

## Result

The post-boot dynamic trust cache now survives a full device reboot without a
new TSS request. The accepted personalized IMG4 is persisted in a nonce-bound,
root-owned journal and replayed before the root broker or injection lanes become
available. After reboot, BrokerProbe 1.0.18 loaded automatically in Apple
SpringBoard PID 37 even though its CDHash was absent from the Cryptex's static
trust cache. PID 1 was never selected or modified.

The accepted deployment is Cryptex version `1.0.20260916131317.993376`. Its
459-entry static trust cache has SHA-256
`4c8d76c52cfc0d111ce17e1b7ee9c0db12382b11ab34882a46965dc888db4c19`.
The runtime-trust helper has SHA-256
`3ed965eb83c6ca207b9fdb3366508fea20b8e6a1502fc025a82985d5002e58f0`
and CDHash `79f622d1933399a79df8da466fc91d0ec10cf778`.

## Persistence and security properties

The helper persists a runtime cache only after AMFI accepts it. The journal is
`/var/jb/var/lib/codex-runtime-admission/trust-cache-v1/<nonce-epoch>` with a
mode-0700, root-owned directory. Each mode-0600 entry is named by its SHA-256
and is rejected unless it is a root-owned regular file with one link, safe
permissions, a bounded size, and a matching digest. Replay is limited to 256
entries and 64 MiB total and is recorded once per `kern.bootsessionuuid`.

BrokerProbe admission persisted this accepted cache:

```text
/var/jb/var/lib/codex-runtime-admission/trust-cache-v1/2d73b634d25a5996/74d4020c4d878e6f2622249d39e445feba8a9acf50a4cd850da2b00b3e94a6c2.img4
```

The package SHA-256 was
`ebd11b5bbdba0249f8d6dc3dafa67a2a0f4d3a4c5ce695316cb1fc56207c50f9`,
and BrokerProbe.dylib's CDHash was
`19dcf02f0ddf1a82695426b50c1819d6739f861a`. That CDHash is not present in the
459-entry static cache.

## Reboot evidence

Apple `devicectl` performed a full reboot. After reconnect, cryptexd reported
the exact version above still installed with the same nonce-domain-3 value. The
observable sequence was:

```text
06:20:42.021  elleKitImageAdmission pid=37 loaded=false .../BrokerProbe.dylib
06:20:43.431  event=sileo-root-broker-start uid=0 euid=0 pid=487
06:20:43.584  runtimeTrustReplay reason=broker-start status=0 backend=postboot-gtcd-v1
06:20:43.584  runtimeTrustReplayStartup=success backend=postboot-gtcd-v1
06:20:43.587  sileoRootBrokerModeReady=true ...
06:20:47.302  BROKER_PROBE_LOADED version=1.0.18 pid=37 uid=501 gid=501 ...
06:20:48.025  elleKitPerProcessInjection lane=springboard pid=37 ... status=0
06:22:06.967  elleKitPerProcessInjectorHeartbeat ... safeMode=false
```

The failed load before replay and constructor success after replay establish the
dynamic cache as the changed admission state. The post-reboot log contains no
runtime-helper personalization, TSS, CFNetwork, or Network activity before the
constructor event. The system used the already personalized journal entry.

The final process inventory still showed SpringBoard PID 37, the Cryptex daemon,
Sileo, and root broker PID 487. Repeated injector heartbeats stayed
`safeMode=false`, and no SpringBoard termination or crash was observed.

Raw evidence is in `findings/clean-reboot-runtime-trust-postboot-20260916.log`.
The pre-reboot seed and corrected journal-write evidence is in
`findings/clean-reboot-runtime-trust-20260916.log`. The full reproducible
appregistrard delta is `Patches/appregistrard-ios27-postboot-full.patch`.
