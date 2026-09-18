# SpringBoard candidate bundle admission — 24A437

Date: 2026-09-17

Device: iPhone13,1 on iOS 27.0 build 24A437

## Fixed bundle

- Executable: `/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard.app/SpringBoard`
- Info.plist: `/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard.app/Info.plist`
- Executable SHA-256: `73a2ccc27f94ecc35266029df82d12ca7eb0f27ff5f2e047bc9ea35681877126`
- Executable CDHash: `9b298e846ab91aaa1fba303f2c892d828e9e921c`
- Mach-O UUID: `AD937FB7-2664-3B8F-B1C9-34C4AD4092D2`
- Exact live Info.plist SHA-256: `ce3bfead94676c8daf111f009211467a9c70f6cbceb73e7a0fcde1f03b320703`

The live 24A437 Info.plist was copied byte-for-byte from the sealed system
bundle. Its identity, platform, device-family, principal-class, initialization,
and frontboard service-domain keys were validated without reserialization. The
candidate and Info.plist were copied back from the dormant rootless bundle and
both host/device byte comparisons succeeded.

No new runtime-trust request was made. The executable bytes and CDHash are
identical to the candidate admitted in the earlier one-time request; only its
bundle path changed.

## Stopped-child admission result

Probe report:
`/private/tmp/codex-springboard-candidate-admission-probe-bundle-run3.txt`

The v2 bundled-path probe succeeded with:

- exact logical/preboot-resolved candidate path;
- `POSIX_SPAWN_START_SUSPENDED` recognized before candidate instructions;
- pre-attach flags `0x26003305`, `VALID=1`, `DEBUGGED=0`;
- validation category 1 and identity `com.apple.springboard`;
- exact CDHash `9b298e846ab91aaa1fba303f2c892d828e9e921c`;
- successful `PT_ATTACHEXC` and attached flags `0x36003005`;
- `VALID=1`, `DEBUGGED=1`, and neither `HARD` nor `KILL`;
- exact task audit token and required live entitlements;
- stable candidate inode/file identity;
- owned child killed with `PT_KILL` and reaped;
- `admitted=1`, `gtaDebugReady=1`, `zeroUserInstructions=1`, and
  `verdict=success`.

Afterward, DVT still showed only stock SpringBoard PID 3713, parent PID 1, UID
501, start absolute time 2055993338324, at the sealed system executable path.
The resident root carrier remained PID 2341, parent PID 1. No candidate or
probe process remained.

## Scope

This proves that the exact bundle-form candidate remains admitted and can be
made a debugged host without executing candidate code. It does not yet prove a
live launchd service replacement, dyld-hook installation, tweak loading, or UI
health. Those require the separately guarded one-shot launchd precursor and
automatic stock rollback.
