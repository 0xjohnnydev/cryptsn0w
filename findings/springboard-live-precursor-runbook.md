# First live SpringBoard candidate precursor

Status: race-hardened, rebuilt, and host-analyzed on 2026-09-17. Nothing in
this runbook has been executed on the phone. A complete clone of the exact
SpringBoard resource bundle remains a live-run blocker: the executable and
Info.plist alone are not a sufficient bundle.

Verified local artifact:

- SHA-256: `0eafa600774d9c9837a8075539f0372065ac7f2ddd15fdb2d2087ac3551e4449`
- CDHash: `e263c40a0b955e3b69c7ab5594435e3a0477d4e7`
- identifier: `com.openai.codex.springboard-live-precursor`
- format: thin arm64e Mach-O executable, deterministic across two clean
  compile/sign runs
- validation: `-Wall -Wextra -Werror`, strict codesign verification, valid
  entitlement plist, and Clang static analyzer with zero diagnostics

## 2026-09-17 race-hardening addendum

The precursor is not a standalone process when invoked in the supported
configuration: its `main` runs inside `codex-exec-worker`. Both public modes
must therefore be launched as:

```sh
/var/jb/usr/libexec/codex-exec-worker --macho \
    /var/jb/usr/libexec/codex-springboard-live-precursor MODE
```

Use `MODE=--watchdog-arm-test` first. That mode performs the full read-only
preflight, arms a nested worker -> `--macho` -> precursor watchdog, durably
disarms it, reaps its worker host, and revalidates the unchanged stock process.
It cannot issue a mutating launchctl command. Only after that passes and the
full SpringBoard resource clone is independently verified may
`MODE=--first-live-precursor` be considered.

The controller now holds a separate recovery lease continuously across the
candidate transaction and stock rollback. The watchdog opens that lock through
a fresh, non-inherited file description, so it cannot mutate while the
controller is alive and owns recovery. Every start-suspended launchctl helper
is bound, atomically recorded, and fsynced before `SIGCONT`; the record is
cleared only after reap. At deadline the watchdog fsyncs a takeover marker and
signals only the bound controller generation. After bounded takeover it must
acquire the recovery lease, re-read and neutralize any exact recorded helper,
and only then restore stock. Once it owns recovery it ignores disarm until an
exact stock process is proven. This closes the prior bootout/disarm race.

## Scope

`codex-springboard-live-precursor` is intentionally incapable of committing a
candidate SpringBoard. Its sole public mode performs one bounded candidate
launch, observes that exact process for ten seconds, and restores the stock
service on every path. A separately exec'd root watchdog holds the same run
lock and restores stock if the controller dies or misses its deadline.

The fixed inputs are:

- service: `user/501/com.apple.SpringBoard`
- stock executable:
  `/System/Library/CoreServices/SpringBoard.app/SpringBoard`
- sealed fallback plist:
  `/System/Library/LaunchDaemons/com.apple.SpringBoard.plist`
- candidate executable:
  `/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard.app/SpringBoard`
- candidate bundle metadata:
  `/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard.app/Info.plist`
- candidate SHA-256:
  `73a2ccc27f94ecc35266029df82d12ca7eb0f27ff5f2e047bc9ea35681877126`
- candidate CDHash: `9b298e846ab91aaa1fba303f2c892d828e9e921c`
- candidate/stock UUID: `AD937FB7-2664-3B8F-B1C9-34C4AD4092D2`
- Info.plist SHA-256:
  `ce3bfead94676c8daf111f009211467a9c70f6cbceb73e7a0fcde1f03b320703`

## Build

From the repository root:

```sh
Scripts/build_springboard_live_precursor.sh
```

The script emits a thin arm64e executable, applies both XML and DER
entitlements, performs strict signature verification, and prints its SHA-256
and CDHash. The executable and its CDHash must be added to the same static
artifact/trust-cache build as the candidate before any live test. Do not use a
runtime trust request merely to test this controller.

The controller intentionally has no JIT, library-validation-bypass,
task-port-control, or `task_for_pid` entitlement. Its signing policy is limited
to platform/debugger status and escaping the application container/sandbox;
it never requests a task port or maps code into the candidate.

## Required deployment preflight

Before a future device run, independently verify all of the following:

1. The full stock `SpringBoard.app` resource tree has been cloned under the
   fixed rootless bundle path. Only the bundle executable is replaced; the
   cloned Info.plist must retain the exact hash above.
2. The candidate and controller are fixed, root-owned, non-writable static
   trust-cache entries. The controller refuses a symlink or mutable final
   component and holds the candidate vnode open through the transaction.
3. The controller binary is launched as root from a persistent process that
   survives a SpringBoard restart. The controller's own exec'd watchdog is the
   rollback authority; no host connection is part of the safety mechanism.
4. The journal path
   `/var/jb/var/log/codex-springboard-live-precursor.log` and state directory
   `/var/jb/var/run/codex-springboard-live-precursor` are root-owned and not
   group/other accessible. A pre-existing insecure path causes a no-mutation
   failure.
5. There is exactly one stock SpringBoard, with PID greater than one, ppid 1,
   uid 501, and the exact UUID. The service must already be registered in the
   `user/501` launchd domain.

## First run

Only after the static build and bundle staging are verified:

```sh
/var/jb/usr/libexec/codex-exec-worker --macho \
    /var/jb/usr/libexec/codex-springboard-live-precursor \
    --first-live-precursor
```

There is no commit flag. The controller executes this sequence:

1. It takes an exclusive lock and fsyncs the preflight journal record.
2. It execs an independent watchdog, waits for the watchdog's fsynced `ready`
   marker, and only then permits a service mutation.
3. It revalidates the original stock PID by path, pidversion, unique ID, ppid,
   uid, and UUID.
4. It issues exactly
   `launchctl debug user/501/com.apple.SpringBoard --program CANDIDATE
   --start-suspended -- CANDIDATE`, revalidates the original stock instance,
   then issues `launchctl kickstart -k -p` for the exact service.
5. It accepts the printed PID only if it is the sole candidate and there is no
   stock-path process. The PID must match the fixed/canonical path, uid 501,
   ppid 1, UUID, CDHash, candidate vnode, pidversion, and unique ID.
6. It performs `PT_ATTACHEXC`, requires `CS_VALID|CS_DEBUGGED` with neither
   `CS_HARD` nor `CS_KILL`, identity-checks again, detaches, identity-checks
   again, and sends `SIGCONT`.
7. It observes the same PID/unique-ID generation and security state for at
   least ten seconds.
8. It always applies a one-shot stock program override and `kickstart -k -p`,
   then requires exactly one stock process and zero candidate processes. If
   that fails, it performs a bounded `bootout` plus `bootstrap` using only the
   exact sealed system plist, then verifies stock again.

Every launchctl helper is itself spawned start-suspended and is bound by exact
path, uid/ppid, UUID-bearing unique record, pidversion, and unique ID before it
is resumed. Timeout termination is attempted only while that same binding is
still valid. The controller and watchdog never signal PID 1 and never send a
signal or ptrace request to an unbound service PID.

## Result interpretation

Exit 0 means the exact candidate remained alive and debug-ready for the full
ten-second window **and** an exact stock SpringBoard was restored afterward.
It does not mean the candidate was committed. Exit 76 means the experiment
failed but stock was restored. Exit 77 means local restoration could not be
proven; in that case the independent watchdog remains armed and makes its own
bounded stock restore attempt. The fsynced journal is authoritative for which
path ran and whether the sealed-plist fallback was used.

The complete public-mode exit map is:

- 0: candidate observation passed, stock restoration was proven, the watchdog
  was durably disarmed, and the final journal record was fsynced.
- 64: invalid invocation; no preflight and no mutation occurred.
- 70: the exclusive lock could not be opened; no mutation occurred.
- 71: the lock was insecure, malformed, or already held; no mutation occurred.
- 72: candidate/bundle/service/process/file/hash preflight failed; no mutating
  launchctl command occurred.
- 73: the controller could not bind its own executable path; no mutation
  occurred.
- 74: the independently exec'd watchdog did not produce a valid fsynced ready
  marker; no mutating launchctl command occurred.
- 76: the candidate phase or durable finalization failed, but exact stock
  restoration was proven.
- 77: exact stock restoration was not proven by the controller. The watchdog
  retains the lock and performs its independent deadline restore.

Exit codes 90 through 93 belong only to the private watchdog mode and indicate,
respectively, invalid watchdog identity/token, insecure inherited state,
failure to durably arm, or inability to prove stock restoration.

The append-only, mode-0600 journal is
`/var/jb/var/log/codex-springboard-live-precursor.log`. Each fsynced record has
the magic, realtime and monotonic timestamps, writer PID, controller/watchdog
role, random run token, and a named event. The final controller event includes
`candidateObserved`, `restored`, `fallback`, stock PID/pidversion/unique ID,
`disarmed`, and the invariant `committed=0`. Per-run `ready`, `disarm`, and
watchdog `restored` markers are stored under the root-only state directory and
contain the same random token.
