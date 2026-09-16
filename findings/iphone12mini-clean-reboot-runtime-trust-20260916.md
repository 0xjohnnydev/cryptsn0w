# iPhone 12 mini clean-reboot runtime-trust replay

## Result

[REDACTED: Related request, payload, or installation details omitted.]

The accepted deployment is Cryptex version `1.0.20260916131317.993376`. Its
459-entry static trust cache has SHA-256
`4c8d76c52cfc0d111ce17e1b7ee9c0db12382b11ab34882a46965dc888db4c19`.
The runtime-trust helper has SHA-256
`3ed965eb83c6ca207b9fdb3366508fea20b8e6a1502fc025a82985d5002e58f0`
and CDHash `79f622d1933399a79df8da466fc91d0ec10cf778`.

## Persistence and security properties

[REDACTED: Related request, payload, or installation details omitted.]

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

[REDACTED: Related request, payload, or installation details omitted.]

```text
[REDACTED: Related request, payload, or installation details omitted.]
```

[REDACTED: Related request, payload, or installation details omitted.]

The final process inventory still showed SpringBoard PID 37, the Cryptex daemon,
Sileo, and root broker PID 487. Repeated injector heartbeats stayed
`safeMode=false`, and no SpringBoard termination or crash was observed.

Raw evidence is in `findings/clean-reboot-runtime-trust-postboot-20260916.log`.
The pre-reboot seed and corrected journal-write evidence is in
`findings/clean-reboot-runtime-trust-20260916.log`. The full reproducible
appregistrard delta is `Patches/appregistrard-ios27-postboot-full.patch`.
