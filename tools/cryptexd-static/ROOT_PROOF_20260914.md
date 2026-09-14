# Generic Cryptex1 root-execution canary (2026-09-14)

## Result

[REDACTED: Related request, payload, or installation details omitted.]

```text
codex-cryptex1-uid-canary marker=80fe8236-0a89-46e9-b1e4-f9aa2cf6b814 uid=0 euid=0 gid=0 egid=0 pid=901
```

The canary performed no file writes, network operations, shell execution, or
persistence. It logged its process credentials and exited successfully.

## Confirmed chain
[REDACTED: TSS/Cryptex personalization and installation details are redacted from this educational source release.]

This chain did not require a MobileGestalt/SRD flag change, an AirTraffic or
StreamingZip filesystem primitive, appregistrard, AltStore, or a modified
DeveloperDiskImage. Those may be alternate discovery or delivery paths, but
they are not prerequisites for this reproduced root-execution path.

## Canary inputs

[REDACTED: Related request, payload, or installation details omitted.]

## Evidence hashes

Stable copies of the log, preflight/install records, binary, BuildManifest,
ticket, and signed metadata objects are in
`root-proof-artifacts-20260914/`. The 64 MB disk image is intentionally not
duplicated there.

```text
2d7d67704a64968a8b553649db3e245648e5722b497c6419a65cf60bcf3c4abd  cryptex-uid-log-canary
1e63ab0884c58d3c87302aaa343ff60ab104317c333437ca9482fc33f853d01f  im4m
cfbbd030fc0708c594751ea15c46fc2350b9210d60142bd0576518d527ee0c56  device-uid-canary.ndjson
ea0a3ecfbf268e63f098c38c9e99e7a16e7726987509ace79d5e39c1268d18bc  preflight.json
3dbbda9c00d8dc8a59d37695b061700570b4da7cdb910a618178331f9e71a431  install.json
```

## Cleanup verification

The exact UID-canary cryptex and the earlier inert canary were both
uninstalled. A final `copy-installed` returned only Apple's existing
`com.apple.MobileAsset.DDI` entry. The root canary was installed with all
persistence controls disabled.
