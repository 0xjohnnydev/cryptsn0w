# Generic Cryptex1 root-execution canary (2026-09-14)

## Result

A retail `iPhone18,2` on iOS 27.0 (`24A435`), whose live personalization
identity reported `img4_chip_rsch = 0`, accepted and mounted a locally created
generic Cryptex1. During cryptex bootstrap, launchd ran the cryptex's one-shot
logging canary as root:

```text
codex-cryptex1-uid-canary marker=80fe8236-0a89-46e9-b1e4-f9aa2cf6b814 uid=0 euid=0 gid=0 egid=0 pid=901
```

The canary performed no file writes, network operations, shell execution, or
persistence. It logged its process credentials and exited successfully.

## Confirmed chain

1. `cryptexctl.research create` emitted the generic Cryptex1 identity:
   `FCHP=0xff10`, `TYPE=3`, `STYP=0`, `CLAS=0xf2`, `NDOM=3`,
   `UseProductClass=true`, and version/preauthorization version
   `999.999.999.999.999,999`.
2. Apple TSS returned a 2,991-byte Cryptex1 IM4M for the exact SHA-384 digests
   of the custom `ginf`, `gtcd`, and `gtgv`. The returned IM4M was checked
   locally for the nonce, UDID binding, chip family, product class, type,
   subtype, nonce domain, version fields, and all three payload digests.
3. The `gdmg` was a sealed 64,000,000-byte APFS image. Its trust cache had one
   entry and only one entry: cdhash
   `9ed1027ba01de753344dc8cefc186bac34f7bb2a`.
4. The direct cryptexd install used image type index 10 with `auth=0`,
   `persistence=0`, and `noncePersistence=0`.
5. cryptexd mounted the image below
   `/private/var/run/com.apple.security.cryptexd/mnt/`, rewrote the absolute
   `ProgramArguments[0]` into that mount, and submitted the plist from
   `Library/LaunchDaemons` to launchd's system session. No `UserName` was
   injected, so the LaunchDaemon ran with UID/EUID/GID/EGID 0.

This chain did not require a MobileGestalt/SRD flag change, an AirTraffic or
StreamingZip filesystem primitive, appregistrard, AltStore, or a modified
DeveloperDiskImage. Those may be alternate discovery or delivery paths, but
they are not prerequisites for this reproduced root-execution path.

## Canary inputs

- Binary source: `cryptex_uid_log_canary.c`
- LaunchDaemon plist: `com.openai.codex.cryptex1.uidcanary.plist`
- Personalizer: `personalize_generic_cryptex1.py`
- Guarded installer: `install_generic_cryptex1_canary.py`
- Cryptex identifier: `com.openai.codex.cryptex1.uidcanary`
- Cryptex version: `1.0.20260914074406`

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
