# SpringBoard candidate admission probe: successful stopped-child proof

Date: 2026-09-17

## Outcome

The fixed candidate at
`/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard` was admitted by
AMFI, stopped before any candidate user instruction, transitioned from a clean
non-debugged state to a GTA/debug-ready state under `PT_ATTACHEXC`, inspected,
then killed and reaped. The stock live SpringBoard was only used as an exact
PID/path/UUID/pidversion invariant and was unchanged.

This proves the candidate can be used as a statically admitted GTA/JIT/library-
validation host after its one-time runtime-trust admission. It does **not** by
itself prove live SpringBoard replacement, tweak injection, reboot persistence,
or a TSS-free way to admit a newly signed candidate.

## Run 2 evidence

- Probe PID 4568 ran as euid 0. Live SpringBoard was PID 3713 at the stock
  system path, UUID `AD937FB7-2664-3B8F-B1C9-34C4AD4092D2`, unique ID 3713,
  pidversion 8053 before and after (`liveUnchanged=1`).
- Candidate PID 4569 resolved to the expected rootless preboot target. Its
  held file and path matched (device 16777223, inode 66576), with uid 0, mode
  0755, size 122400, and the expected UUID.
- `POSIX_SPAWN_START_SUSPENDED` produced Darwin's synthetic stopped wait status
  `0x0000007f`: `WIFSTOPPED=1`, stop signal 0,
  `startSuspendedSynthetic=1`, and `startSuspended=1`.
- Before debugger attachment, the candidate survived a 500 ms stopped settle,
  had csflags `0x26003305`, `CS_VALID=1`, `CS_DEBUGGED=0`, validation category
  1, signing identity `com.apple.springboard`, and exact CDHash
  `9b298e846ab91aaa1fba303f2c892d828e9e921c`.
- `PT_ATTACHEXC` succeeded and yielded stopped status `0x0000117f`. Attached
  csflags were `0x36003005`: `CS_VALID=1`, `CS_DEBUGGED=1`, and neither
  `CS_HARD` nor `CS_KILL` remained set. CDHash and identity were stable.
- `task_for_pid` and `TASK_AUDIT_TOKEN` succeeded. The audit PID 4569 and
  pidversion 10028 exactly matched `proc_pidinfo`.
- `SecTask` returned exact signing/application identifiers and true values for
  `get-task-allow`, `com.apple.private.cs.debugger`, allow-jit,
  dynamic-codesigning, skip-library-validation, disable-library-validation,
  platform-application, and task_for_pid-allow. The optional dyld-environment
  entitlement was absent and diagnostic only. `secTaskPolicyExact=1`.
- Candidate file stability passed. `PT_KILL` succeeded, wait status was signal
  9, and the child was reaped. The probe never issued `PT_CONTINUE` and reported
  `zeroUserInstructions=1`, `admitted=1`, `gtaDebugReady=1`, `verdict=success`.
- Pre/post process snapshots contained only the unchanged stock SpringBoard at
  PID 3713; no disposable candidate survived cleanup.

## Run 1 diagnostic

Run 1 used the same safely admitted candidate but rejected wait status
`0x0000007f` because it required `WSTOPSIG == SIGSTOP`. It failed closed with
exit 79 and reaped PID 4556 via SIGKILL before debugger attachment. The probe
was then changed to accept and explicitly label Darwin's synthetic signal-0
stopped status. No candidate or live-SpringBoard state leaked across runs.

## Runtime-trust prerequisite

Runtime trust was invoked exactly once for only the fixed candidate; it was not
repeated for Run 2. Its 221-byte log reported `platform=true`, pmap array
present, generic pmap entry true, count 13, and successful trust-cache loading
for the fixed candidate. Future harness runs capture this log first at the
fixed root-owned path and require a separate export action to Media.

## Artifact and evidence hashes

- Candidate SHA-256:
  `73a2ccc27f94ecc35266029df82d12ca7eb0f27ff5f2e047bc9ea35681877126`
- Candidate CDHash:
  `9b298e846ab91aaa1fba303f2c892d828e9e921c`
- Final Run 2 probe SHA-256:
  `1e0995e8374ff49612c4ce8fd5f49e5e91ddb4739b10dd1d6d74ab68d3ee8d24`
- Final Run 2 probe ad-hoc CDHash:
  `36cfa844a223d5e66ed0798a4f142f500342db66`
- Run 1 exported report SHA-256:
  `df38f411c6e7d4b2c66b202771ec4bc62d03e97fb2845c278788f9f142e923f7`
- Run 2 exported report SHA-256:
  `df8287f4990e65b651b78b813b0c6f8e36775feec284b96069c05a060c49e153`
- Runtime-trust log SHA-256:
  `2308e498b088476bd02e6f0b0259f5647e9bc8d316317fe47363dd452db96c30`

Local captured evidence at completion:

- `/private/tmp/codex-springboard-candidate-admission-probe-run1.txt`
- `/private/tmp/codex-springboard-candidate-admission-probe-run2.txt`
- `/private/tmp/codex-springboard-candidate-runtime-trust.log`
- `/private/tmp/codex-sb-before-candidate-probe-run2.json`
- `/private/tmp/codex-sb-after-candidate-probe-run2.json`
