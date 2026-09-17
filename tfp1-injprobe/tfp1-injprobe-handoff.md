# Session handoff: task ports on PID 1, and code injection into a foreign process

Written 2026-09-17. Device throughout: iPhone16,1 (iPhone 15 Pro), iOS 27.0 build 24A435,
jailbreak lane (`/var/jb`, root SSH on `127.0.0.1:2222` via a usbmux forward).

[REDACTED: Related request, payload, or installation details omitted.]

---

## 1. The two tools

| on device | source | what it does |
| --- | --- | --- |
| `/var/jb/usr/bin/tfpid` | `poc/tfpid_probe.c` | `task_for_pid` against self, a child, launchd, pid 0, and any pid given; on success it follows `TASK_DYLD_INFO` → `dyld_all_image_infos` → the image array → `imageLoadAddress` and reads the target's Mach-O magic and image path **out of the target's address space** |
| `/var/jb/usr/bin/injprobe` | `poc/injprobe.c` | the injection test: task port, then `mach_vm_allocate` + `mach_vm_write` a dylib path into the target, then `thread_set_state` to make one of its threads call `dlopen` on it |

Both are built by `poc/build_toolkit_deb.sh` and signed with
`poc/entitlements/debug-client.entitlements`. Usage:

```
tfpid                 # self, child, launchd, pid 0
tfpid <pid>
injprobe              # self test: our own forked child
injprobe <pid> [agent-path]
```

## 2. What has been measured

### tfpid: the differential that makes it a measurement

Same probe, same device, two builds one flag apart:

```
before (no entitlements):
self    KERN_FAILURE   child KERN_FAILURE   launchd KERN_FAILURE   pid 0 KERN_FAILURE
after  (task_for_pid-allow):
self    KERN_SUCCESS   child KERN_SUCCESS   launchd KERN_SUCCESS   pid 0 KERN_FAILURE
  launchd: READ OK: 91 images, first @0x102edc000 magic=0xfeedfacf (MH_MAGIC_64) /sbin/launchd
```

`READ OK` is a real cross-process read, not a count: the probe reads launchd's own Mach-O
header and its image path out of launchd's memory. Two further rows matter: with nothing
declared **not even self works** (no self-exception on iOS, unlike macOS), and with only
`get-task-allow` the probe reaches self and children but **launchd is refused**.

### injprobe: three targets, three different outcomes

```
target `yes`      everything succeeded; the agent's constructor ran and wrote its marker
target `sleep 600` everything reported success, NOTHING ran - the thread was parked in a
                   long syscall, and planted state only takes effect on return to userspace
                   (x0 was the syscall's own argument, not a return value)
target `launchd`  (2026-09-17) task port OK, allocate/write OK, read-back OK,
                   thread_set_state -> KERN_FAILURE (0x5)
                   nothing executed. No panic; launchd untouched.
```

So on the system's init: **the port and the write work, the thread takeover is refused.**
That is where the open question lives (section 4).

## 3. Entitlements: which one does what

- **`task_for_pid-allow` is the entitlement that reaches other processes.** It is a *bare*
  key, not `com.apple.private.*`, and bare keys are honoured in an ad-hoc signature - which
  is the only reason any of this works, since `com.apple.developer.*` keys are fatal at exec.
- **`get-task-allow`** reaches your own process and your children, and nothing else.
- **`task_name_for_pid` needs no entitlement at all** - it returned `KERN_SUCCESS` even in
  the bare build - but it is the name port: identity, no memory access.
- **pid 0 is refused with every entitlement set.** `tfp0` is a kernel check that a
  jailbreak patches, not an entitlement question.

Two warts to know about:

- `poc/entitlements/debug-client.entitlements` declares
  `com.apple.security.get-task-allow`, which is the **macOS spelling and does NOT set
  `CS_GET_TASK_ALLOW`** on iOS. The bare key does. So the shipped `injprobe`/`tfpid` are
  probably not GTA processes at all. Irrelevant to `task_for_pid`, but it matters the moment
  you want one of them to be softenable.
- `csops(CS_OPS_ENTITLEMENTS_BLOB)` is **not** a check: it reported every key absent in the
  very build where `task_for_pid` demonstrably consulted one. Trust the differential, not
  the blob readback.

## 4. Open questions, and the one experiment that settles the important one

**Why is `thread_set_state` refused on launchd while it succeeded on `yes`?** The most
likely answer is the same **target-side gate already measured for softening**: mutating a
foreign task is allowed only when the *target* carries `get-task-allow`. On 2026-09-16 we
measured exactly that shape from the ptrace side - `distnoted` (no GTA) refused, `Sileo`
(GTA) allowed - so the hypothesis is that launchd is an instance of a rule rather than a
special case.

The experiment, no new binary needed:

```
injprobe <Sileo pid>    /var/jb/usr/lib/libagent.dylib    expect: succeeds if the rule holds
injprobe <distnoted pid> /var/jb/usr/lib/libagent.dylib   expect: KERN_FAILURE
injprobe <yes pid>      /var/jb/usr/lib/libagent.dylib    expect: succeeds (it did on 09-15)
```

If Sileo succeeds and the other two fail, the target-GTA gate is confirmed. If Sileo also
fails, look at the flavour gating in AMFI's task-port hook instead of the target's flags.

**Do NOT run `anchor attach 1`** to read launchd's csflags. That mode prints the flags and
then attaches, and on a foreign target `PT_DETACH` returns `EBUSY` (measured 3 of 3), after
which the target dies with the tracer. On pid 1 that is a panic. There is currently no
admitted tool that reads a foreign process's csflags without attaching, which is a gap
worth naming.

## 5. How to add a binary to the cryptex bundle

[REDACTED: Related request, payload, or installation details omitted.]

[REDACTED: Related request, payload, or installation details omitted.]

The other half: `build_toolkit_deb.sh` signs each payload with **the same flags the lane
normalizes with** (`codesign --force --sign - --timestamp=none --pagesize 4096
--identifier X --entitlements Y`), and asserts that `ldid -e` can read the entitlements back.
That is what makes the CDHash we print the CDHash that lands in the cache. If that
assertion ever fails, the lane would silently re-sign without entitlements and the tool
would be weaker than it looks.

### Steps

**1. Write the source** in `poc/<tool>.c`. Declare anything the iOS SDK lacks yourself -
`mach_vm_*`, `csops`, `ptrace`, `bootstrap_look_up`/`bootstrap_port` are all exported by
libSystem but not in the SDK headers; `anchor.c`, `cs-loader.c` and `ipcprobe.c` all show
the pattern.

**2. Add a build line** to `poc/build_toolkit_deb.sh`, next to the others:

```bash
build "$script_dir/<tool>.c"   usr/bin/<tool>   com.example.c1sh-<tool>   debug-client.entitlements
```

`build()` is `build <src.c> <dest-relative> <identifier> <entitlements|-> [extra clang args]`.
Put entitlements in `poc/entitlements/`, and remember the two rules from section 3: bare
keys are honoured, `com.apple.developer.*` is fatal at exec.

**3. Build the deb** and note the sha it prints:

```bash
cd research/audit/cryptex-srd-bug
./poc/build_toolkit_deb.sh
#   usr/bin/<tool>   <cdhash>
#   sha256: <DEBSHA>
```

**4. Clear the deb cache.** `fetch_pinned` skips the download when the destination file
already exists, so a stale cached copy fails with `cached hash mismatch` rather than being
refreshed:

```bash
rm -f jb-variant/Dopamine-upstream/CryptexBootstrap/cache/c1tools_1.0_iphoneos-arm64.deb
```

(Today's run failed exactly here before I cleared it. The error names the deb, not the
cache, which is slightly misleading.)

[REDACTED: Related request, payload, or installation details omitted.]

```bash
cd jb-variant
export C1TOOLS_SHA256=<DEBSHA from step 3>
./Dopamine-CryptexBootstrap/setup.sh --install \
    --device 00008130-0018055201D8001C --allow-unverified-device --no-brew
```

Useful flags: `--prepare` (preflight only, no device), `--build` (build without installing),
`--no-replace`, and `--allow-unverified-device` which is required because our device is
outside the script's validated matrix.

**6. Put the files where they belong.** The cryptex and the files are separate: the install
puts the *trust* in place, and `dpkg` puts the *bytes* in `/var/jb`. Both are required.

```bash
K=.../jb-variant/build/ssh/id_ed25519
L() { ssh -i "$K" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1 "$@"; }

L 'cat > /var/jb/tmp/c1tools.deb' < build/c1tools_1.0_iphoneos-arm64.deb
L 'dpkg --instdir=/var/jb --admindir=/var/jb/Library/dpkg -i /var/jb/tmp/c1tools.deb'
```

**7. Verify** both that it exists and that it runs:

```bash
L 'ls -l /var/jb/usr/bin/<tool>; /var/jb/usr/bin/<tool>'
```

A tool that appears but is SIGKILLed on execution means the CDHash did not land - which
almost always means the deb was not actually the one that went into the build (step 4), or
the source changed after the deb was built.

### Cost, so nobody spends it twice

Everything above is per-*binary*. Once a tool is in, **payloads it consumes are free**: that
is the whole design, and `cs-loader` is the worked example - one rebuild, then arbitrary
unsigned Mach-Os run as data.

## 6. Environment gotchas that cost time this session

- **`scp`/SFTP are not available** on the lane's sshd. Move files with
  `ssh 'cat > /path' < localfile`.
- **zsh does not word-split unquoted variables.** `FLAGS="-a -b"; cmd $FLAGS` passes one
  argument. Inline the flags, or use an array.
- **The device has no `strings`, `nm`, `awk`, `pgrep`, or BSD `stat`** (the coreutils one
  shadows it and rejects `-f%z`; use `wc -c`). `grep -a` on a binary is the substitute for
  `strings`.
- **`log` on the device is a zsh builtin, not Apple's tool**, and there is no `dmesg`. That
  is why code-signing kills here are evidenced by crash reports rather than by syslog. Crash
  reports land in `/var/mobile/Library/Logs/CrashReporter/` even for root processes, and a
  kill at a *page* produces one while a kill at *exec* has not (two observed, none filed).
- **`uicache` on this lane refuses to register anything**, including apps that demonstrably
  work, and there is no `appregistrard` in `/var/jb/usr/bin` or `/usr/libexec`. The only
  working app-registration path on this build is installd.
- **A device that drops off USB** makes every lane command return empty output rather than
  an error (`usbmux has no device matching udid` is the real message; the SSH forward just
  closes). Check the forwarder before debugging the tool.

## 7. Files in this bundle

- `tfp1-injprobe-handoff.md` - this document
- `injprobe.c` - the injection probe, with the three fixes of 2026-09-17 (marker cleared and
  its pid checked against the target, step 5 no longer annotates a cause when step 4 failed,
  default agent path resolved rather than assumed)
- `tfpid_probe.c` - the task-port and cross-process-read probe
- `debug-client.entitlements` - the entitlement set both are signed with (see the wart in
  section 3)
