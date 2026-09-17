# c1tools: what it is, what it proves, and how it fits the lanes in this repo

Written 2026-09-17 for agents picking this up cold. Everything here was measured on
**iPhone16,1 (iPhone 15 Pro), iOS 27.0 build 24A435**, in a root lane of the same
Dopamine-cryptex shape this repository builds. Where a claim is inference rather than
measurement it says so. The evidence tree lives in the sibling `cryptex-srd-bug` checkout
under `evidence/device/24A435/` and `report/`.

The code is in `tools/c1tools/` — see its `README.md` for the file-by-file inventory and
`HANDOFF.md` for the long-form walkthrough.

---

## 1. The one distinction that matters: two tiers of "new code"

Getting this wrong is what costs the most time here, so it is first.

**Tier 1 — admitted by the cryptex trust cache.** A cryptex trust cache is built at
personalization time and is **immutable afterwards**. `build_cryptex.sh` hashes every
Mach-O under `trusted-packages-normalized` into it. A binary that arrives any other way —
plain `dpkg`, `apt install` — has a **CDHash in no cache and is SIGKILLed at exec**
(`rc=137`). Measured, repeatedly: `unzip` after `apt install unzip` dies exactly this way.
So adding anything to tier 1 costs a **lane rebuild, i.e. a TSS round trip**.

**Tier 2 — payloads.** Once `cs-loader` is tier 1, the code *it* runs needs no admission
at all. It maps the payload's segments into **anonymous** pages inside a child that has
been debug-authorised, applies the fixups from outside through the task port, and calls
the entry point. Nothing is signed, nothing is hashed, no trust cache is consulted, and
the payload's own CDHash is irrelevant.

> **One rebuild admits the loader. Every payload after that is free.**

## 2. What `cs-loader` is, and why it exists

`cs-loader <macho> [args...]` runs an **unsigned** Mach-O as a program.

```
parent: fork a child; the child inherits this binary's get-task-allow
parent: ptrace(PT_ATTACHEXC) -> cs_allow_invalid -> CS_DEBUGGED, then PT_DETACH
        (it is our own child, so waitpid consumes the stop and the detach SUCCEEDS -
         which is exactly why this shape works where the same call on a foreign target
         returns EBUSY and kills the target)
parent: task_for_pid, then mach_vm_allocate + mach_vm_write each segment into
        ANONYMOUS pages; chained fixups and legacy LC_DYLD_INFO both applied from
        outside; dependencies dlopen'd from the payload's own LC_LOAD_DYLIB
parent: nothing else - the child reads entry/inits/argv out of a shared page and calls
```

**Measured results.** An unsigned 49 KB Mach-O that the kernel SIGKILLs at exec
(`rc=137`) ran and exited 42. Then a real third-party binary: `unzip`, 192 KB, 308 rebases
and 85 binds resolved, extracted an actual archive with correct contents. Same file, same
user, seconds apart: direct exec kills it, `cs-loader` runs it.

**Why the signed route was not used instead.** It was measured closed, twice. A dylib
signed with the host app's *own* Personal Team certificate is refused at
`F_ADDFILESIGS_RETURN` with `EPERM` — **before library validation is even consulted** —
and the lane refuses it with `errno=1` exactly as it does an ad-hoc one. A developer
certificate buys nothing for a loose file.

**Limits, stated so nothing here is trusted further than it goes.** Both fixup encodings
are implemented; an opcode or bind type that is not is a loud failure, never a skip. One
image at a time; a missing dependency aborts with the name printed. No TLS, no unwinding,
no Swift runtime — Nyxian's own loader has the same gap. And it runs *code*, not a
process: the child already has a pid and a runtime, so a payload that behaves like a
program because it *is* one will notice. For real apps, use the app lane (§4).

## 3. What else is in the box

| tool | what it establishes |
| --- | --- |
| `cs-loader` | an arbitrary **unsigned** Mach-O runs, with no signature, no trust cache entry and no TSS. The measured controls: the same file SIGKILLs at exec, then runs and exits 42 through the loader; and `unzip` (192 KB, 308 rebases, 85 binds) extracts a real archive |
| `tfpid` | `task_for_pid` reaches arbitrary processes **including pid 1**, and a real cross-process read works: it walks launchd's `dyld_all_image_infos` and reads its Mach-O header and image path out of launchd's memory. The one-key differential (`task_for_pid-allow`) is what makes it a measurement |
| `injprobe` | injection into a process we did not spawn, and the instrument for the **task-mutation gate**. It reports the target's thread suspend count and refuses to read a stale `x0`, because a planted thread state on a suspended target never runs |
| `agent.c` | the dylib `injprobe` injects. Its constructor names the pid it ran in, which is what makes a stale marker detectable rather than readable as a success |

### The privilege model these produced, in one paragraph

Three gates, two of them on different sides of the call. **The caller's
`task_for_pid-allow` buys the port** (without it nothing is reachable, not even self;
`get-task-allow` on the caller reaches only self and children). **The target's
`get-task-allow` buys anything that changes the target** — measured twice, once from the
ptrace side (`distnoted` refused softening, Sileo allowed it) and once from the thread
side (`distnoted` refused `thread_set_state`, Sileo allowed it). And **pid 0 is refused
with every entitlement set**; that is a jailbreak patch, not an entitlement. The
practical consequence: **injection into Apple's own daemons is closed**, not because the
port is unavailable — it is available, and their memory is readable — but because a
system daemon will never carry `get-task-allow`.

## 4. How this composes with the lanes already in this repo

They are **alternatives, not layers**, and the difference is which gate each satisfies.

- **`codex-signexec`** admits a payload by ad-hoc resigning a copy and having TSS
  personalize a **runtime trust cache** for its new CDHash. Cost: one TSS round trip per
  binary content per boot. `cs-loader` needs **no TSS after the loader itself** and no
  signing, at the price of running the payload inside a hosted child rather than as its
  own process.
- **The worker / debugger lane** is the same primitive as `anchor`: soften a process, then
  write pages. `cs-loader` is that plus a loader, and it is self-contained — it forks its
  own target rather than needing a separate worker.
- **The app lane** (re-sign an app bundle with our certificate, install through installd)
  is what makes *applications* launchable, and it is measured working: the running Sileo
  on the test device is `C4V7A9K2V6.com.research.poc.sileo`. Re-signing also confers
  `get-task-allow`, which makes those apps **injectable** — the devcert lane and the
  mutation gate are the same lever.
- **A caveat worth knowing before designing around an app:** an app we re-sign is
  `CS_REQUIRE_LV`, so **every dylib it loads must also be re-signed**. And the free
  Personal Team profile carries **no wildcard**: profiles are per-App-ID, they expire in
  about a week, and the device's own profile store shows our team holding exactly two
  explicit identifiers. Arbitrary-app coverage is capped by App-ID supply, not by crypto.

## 5. Build and ship, in this repository

```sh
cd tools/c1tools
./build_toolkit_deb.sh          # prints every CDHash and the deb sha256
```

That writes `build/c1tools_1.0_iphoneos-arm64.deb`, which
`Dopamine-CryptexBootstrap/CryptexBootstrap/build_cryptex.sh` now picks up by default
(`C1TOOLS_URL` / `C1TOOLS_SHA256` at the top of that file, `dpkg-deb -x` into the trusted
package root next to ellekit and the rest). **Bump `C1TOOLS_SHA256` whenever the tools
change** — the build script prints the new value — or the fetch will refuse the deb.

Then the lane rebuild, which is the TSS step, and the file install:

```sh
rm -f Dopamine-upstream/CryptexBootstrap/cache/c1tools_1.0_iphoneos-arm64.deb
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID> --allow-unverified-device
./tools/c1tools/lane.sh push build/c1tools_1.0_iphoneos-arm64.deb /var/jb/tmp/c1tools.deb
./tools/c1tools/lane.sh run  'dpkg --instdir=/var/jb --admindir=/var/jb/Library/dpkg \
                              -i /var/jb/tmp/c1tools.deb'
```

Four traps, each of which has already cost a rebuild here:

1. **Clear the cached deb.** `fetch_pinned` skips the download when the destination
   exists, then dies with `cached hash mismatch`, naming the deb rather than the cache.
2. **The cryptex and the files land separately.** The lane install puts the *trust* in
   place; `dpkg` puts the *bytes* in `/var/jb`. Both are required.
3. **The normalization must stay idempotent.** `build_cryptex.sh` re-signs every Mach-O
   with `--force --sign - --timestamp=none --pagesize 4096 --identifier X --entitlements
   Y` where Y comes from `ldid -e`. `build_toolkit_deb.sh` signs with the same flags and
   **asserts the `ldid` round-trip**; if that assertion ever fails, the lane would
   silently re-sign without entitlements and the tool would be weaker than it looks.
4. **Nothing here is signed with a developer certificate, and that is deliberate.** A
   dylib signed with our own team's certificate is refused just as an ad-hoc one is, so
   there is no benefit to it - and the payloads `cs-loader` runs are unsigned on purpose.

## 6. What is deliberately not here

This port carries the loader and the two probes that measure the primitives around it,
and nothing else. The wider campaign toolkit stays in the `cryptex-srd-bug` workbench:
`ipcprobe` (Mach service lookup and a task's port namespace with right kinds),
`anchor` (route A as a standalone worker and as a dev-signed app), `tcpusher` (cryptexd's
own AMFI trust-cache load path), `dlrun`/`dllrun`/`fsx`, and `tcauthor.py`.

One line of that is worth carrying even without the tool, because it is a trap rather
than a result: **every selector-7 `KERN_SUCCESS` the project ever saw was a duplicate-UUID
early return.** AMFI answers a load for a cache whose UUID is already loaded with success
and loads nothing (`loading duplicate trust cache (success)` in the syslog), so a success
code proves nothing on its own.

## 7. Evidence pointers

In the sibling `cryptex-srd-bug` checkout, all device-measured unless noted:

- `evidence/device/24A435/cs-loader-proven-24A435.md` — the loader, with its control
- `evidence/device/24A435/library-validation-route-closed-24A435.md` — why signing does not work
- `evidence/device/24A435/task-mutation-gate-24A435.md` — the `get-task-allow` gate, 5-target differential
- `evidence/device/24A435/exec-refusal-owner-24A435.md` — the path rule is the caller's profile, not the file's location
- `evidence/device/24A435/exemption-survives-detach-24A435.md` — the exemption is sticky; the tracer is the problem
- `evidence/device/24A435/vm-prot-copy-measured-24A435.md` — the protect is free, the write fault is the door
- `report/why-safari-gets-jit-24A435.md` — the kernel chain, sections 0-10
- `report/amfi-userclient-trustcache-load-24A437.md` — the AMFI selector table
