# iOS 27 runtime debugging and arbitrary-execution strategy

This note records what has actually been measured on the project iPhone18,2
running iOS 27.0 (24A435) and the iPhone13,1 (iPhone 12 mini) running iOS 27.0
(24A437), what the result means for LiveContainer-style execution, and what
still requires a separate proof. It does not treat a successful API return or
a favorable entitlement dump as execution proof.

## Installed iPhone 12 mini result

Cryptex version `1.0.20260915200055.800872` installs the runtime under `/var/jb`
and starts the root broker as the system launch daemon
`com.openai.codex.dopamine.sileo-root-broker`. The installed acceptance results
were:

- on-device runtime-admission worker self-test: exit 0;
- Sileo root-broker `whoami`: exit 0;
- SpringBoard load of the trust-cached ElleKit `libinjector.dylib`: status 0;
- package configuration and `apt-get check`: exit 0; and
- launchd/PID 1 injection: disabled, with explicit PID and path guards.

Sileo deliberately does not receive the late generic ElleKit injection. Its
launch-time constructor already installs the package-manager filesystem and
spawn bridges; injecting ElleKit after those worker threads started was both
redundant and caused the app to exit. Other eligible non-platform app targets
and SpringBoard remain on the per-process ElleKit path.

[REDACTED: Related request, payload, or installation details omitted.]

After that accepted deployment, three BrokerProbe 1.0.14 update attempts failed
before payload unpack and `postinst`: the installed image's APT pre-install
client returned 100. The working tree removes the obsolete pre-install hook and
keeps runtime admission at executable boundaries through the fixed interposer
and debugger-softened worker. That revision is not yet rebuilt or installed, so
BrokerProbe arbitrary execution and tweak delivery remain pending proofs.

## Bottom line

The useful no-per-payload-trust primitive now works in two forms:

1. Start one stable, signed, trust-cached worker with kernel-accepted
   `get-task-allow`.
2. Let the iOS 26+ debugger protocol authorize executable pages in that
   worker's address space.
3. Submit page plans for every runtime-generated executable allocation.
4. Supply scripts, bytecode, PIC modules, or manually loaded code as data.

The original host-driven form is the patched Frida/Fruity route described
below. The installed form is `codex-exec-worker`, invoked by the root broker
when direct `posix_spawn` fails with an image-admission error. Its `--macho`
mode makes a private same-directory copy, changes `MH_EXECUTE` to `MH_DYLIB`,
loads it into the already admitted worker, locates `LC_MAIN`, and invokes that
entry point with the requested arguments. It also exposes bounded `--raw` and
`--dylib` modes.

For executable-memory admission, the worker attaches to an expendable child
with `PT_ATTACHEXC`. The child creates and initializes a page while writable,
flushes it, and changes it to RX; the debugger then performs the proven COW
rewrite and restores RX before execution. A bounded handshake prevents the
earlier stopped-child deadlock.

Two independent end-to-end tests passed:

- `Scripts/bless_jit26_probe.py` created an RX page, remapped a writable alias,
  wrote a hard-coded AArch64 `return 42` function, and executed it.
- Frida 17.17.0 over native USB/RSD attached to the disposable worker, installed
  an `Interceptor` hook on `getpid`, observed the hook callback, and called the
  function through `NativeFunction`. The checked-in result summary is
  `findings/frida-ios27-fruity-interceptor-24A435.json`; the full local run is
  `build/frida-ios27-usb-smoke-owned-proxy.json`.

This establishes arbitrary native computation *inside a stable admitted
process*, including the installed USB-free worker path. It does not establish
a global arbitrary new-Mach-O `execve` policy. AMFI and the code-signing
monitor still evaluate every new main image; the broker routes admission
failures into its fixed admitted worker instead of changing that kernel policy.

## Measured state

| Question | Device result | Consequence |
| --- | --- | --- |
| Does entitlement-only `MAP_JIT` work in the probe? | No; `mmap` returned `EINVAL` | A plist alone is not the runtime authorization mechanism on this build |
| Does RW-to-RX `mprotect` work unaided? | No; the child was code-sign killed | Ordinary anonymous executable transitions remain enforced |
| Can debugger-authorized pages execute? | Yes; the manual probe returned 42 | The debugger/TXM page-plan path is the working primitive |
| Does stock Frida 17.17 basic injection work? | Yes | Fruity can bootstrap the exact GTA worker |
| Did stock Gum Interceptor work initially? | No; its generated trampoline was NX | Frida omitted allocator-owned code pages from the plan |
| Does patched Gum Interceptor work? | Yes, with the untouched official host binding | Only the Gadget/Gum allocator needed the fix |
| Does appregistrard make a Cryptex app discoverable? | Yes | Registration and FrontBoard launch are solved separately |
| Does appregistrard bypass AMFI for arbitrary code? | No | It is a LaunchServices mechanism, not image admission policy |
| Is a device-side `frida-server` required for the working path? | No | Native Fruity USB/RSD is the proven route |
| Does the installed worker authorize and execute a generated RX page without the Mac? | Yes; self-test exited 0 on the iPhone 12 mini | The debugger/COW primitive now has an on-device implementation |
| Can Sileo execute root package-manager commands through the daemon? | Yes; brokered `whoami` and package setup exited 0 | Sileo no longer depends on direct execution succeeding for every child Mach-O |
| Can the guarded ElleKit lane load its trusted injector into SpringBoard? | Yes; image verification returned status 0 | Tweak loading no longer requires injecting `pspawn.dylib` into launchd |
| Has the corrected no-APT-hook BrokerProbe package path passed? | Not yet; the installed older hook returned 100 before unpack | Rebuild/install the current policy before claiming arbitrary package payload execution |

The disposable worker began with `csflags=0x26803b0d`, including
`CS_GET_TASK_ALLOW`. PID 1 remained `/sbin/launchd` before attach, after detach,
and after worker cleanup.

## The Frida bug and fix

Frida 17.17 already contains Apple's iOS 26+ debugger-mapping protocol. Gum
uses a custom breakpoint and a page-plan payload so Fruity/debugserver can
authorize the pages that will become executable. Existing memory-patching code
submitted plans for original image pages.

`gum_code_allocator_commit()`, however, changed Gum's newly generated code
batches to RX without submitting those allocator-owned pages. Basic scripts and
native symbol resolution therefore worked, while the first Interceptor
trampoline faulted as non-executable.

The checked-in patch
`Patches/frida-gum-17.17.0-ios27-code-page-plan.patch` does two things:

- submits a debugger page plan for every allocator-owned code page when Darwin
  debugger mapping enforcement is active; and
- forces those known code pages into the plan instead of applying the ordinary
  "code signing already out of the way" heuristic, which incorrectly skipped
  the first generated page through its writable alias.

The fix was built from exact Frida 17.17.0 sources:

- Frida: `03f16b3b11c5bb945cdb7f6158a84dd57655de4c`
- frida-core: `c812943c457376c906802f7bb79d13c67a6e4d22`
- frida-gum: `ddc10c5559cbb41a3dd72866bfba6ff3945ffa5c`

Artifacts currently staged on this Mac are:

| Artifact | SHA-256 |
| --- | --- |
| Proven patched universal arm64/arm64e Gadget | `10a34a745f3e2342004847ee921119ff50fc41ea6ffc949b0c6a4ccd37182c71` |
| Untouched official Frida 17.17.0 rollback Gadget | `1c5855bacfbe2e2ed3029b15a44110967609416676c2e3f9e998a83b1c3a4bf5` |

The patched Gadget is selected at `~/.cache/frida/gadget-ios.dylib`. The
official host Python binding was not patched; its tested SHA-256 is
`31417ee99504b14c0698a5058f3a6f0cbe8eefcb88c64734f1f068fe1c0c72e1`.

Use the selection helper for an explicit switch or rollback:

```sh
Scripts/select-frida-ios27-gadget.zsh patched
Scripts/select-frida-ios27-gadget.zsh official
```

`Scripts/build-frida-ios27-gadget.zsh` performs a source-pinned rebuild into a
separate `.rebuilt.dylib`. It requires `IOS_CERTID` to identify a valid local
Apple Development certificate. A signing timestamp can change the whole-file
hash even when the code is identical, so a rebuilt file must pass the runtime
smoke test before replacing the proven artifact.

## Running the native USB proof

Install the pinned host packages into the existing host venv, select the
patched Gadget, and require the exact device UDID:

```sh
uv pip install --python build/frida-host-venv/bin/python \
  -r requirements-frida.txt
Scripts/select-frida-ios27-gadget.zsh patched
Scripts/run-frida-ios27-usb-smoke.zsh \
  --udid <validated-24A435-UDID>
```

After that proof passes, the pinned interactive path is:

```sh
Scripts/frida-ios27-usb.zsh -p <disposable-pid>
```

The wrapper rejects PID 1/launchd, ambiguous device selection, alternate
devices, options files, and remote-server selectors.

The wrapper intentionally runs Apple's `/usr/bin/python3` while importing the
Frida abi3 module from the host venv. On this macOS 27 installation, Apple's
Python receives the TCP PCB data Fruity needs to detect the RSD port; the
Homebrew Python 3.14 process receives an empty result and reports
`unable to detect RSD port`. `typing_extensions` supplies two annotation names
missing from the system Python 3.9 runtime.

The smoke test refuses all of the following:

- an omitted or ambiguous UDID;
- PID 1 or a PID/name/path mismatch;
- a GTA bit missing from the disposable worker;
- a device-side listener on TCP 27042;
- an unexpected cached or staged Gadget hash; or
- cleanup after the PID has changed identity.

It does not start/restart `frida-server` or policyd. The legacy `/var/jb`
Frida server should remain stopped during this path because Fruity can prefer
it and thereby test a different injection route.

Installing a Frida `.deb` is therefore not the missing fix. A package can
provide a convenient server and tools, but the server does not repair Gum's
unplanned generated-code pages, and a listener on 27042 masks the proven
native debugger/Gadget route.

## What the panics mean

The cable was the transport, not the demonstrated root cause. The dangerous
earlier experiment allowed a Frida injection attempt to reach the critical PID
1 path. If anonymous bootstrap code remains non-executable and launchd is
terminated, XNU panics because init exited.

No panic occurred during the manual blessed-page proof or the patched native
USB Interceptor runs. The permanent boundary is still strict: never inject,
suspend, signal, or use PID 1 as a dynamic-code test target. Reproduce launchd
behavior in a disposable worker and use logs/kdebug for the real launchd.

## What LiveContainer contributes

[LiveContainer](https://github.com/LiveContainer/LiveContainer) is the right
architectural reference for turning an admitted host into a loader, but its
security and iOS-version boundaries matter:

- it converts a guest `MH_EXECUTE` into a loadable image, adjusts the guest
  environment, `dlopen`s it, finds `LC_MAIN`, and enters it inside the host;
- below iOS 26, its JIT route can bypass guest signing;
- its current iOS 26+ code explicitly requires JIT-less signing for the normal
  launch path;
- guest entitlements are not applied to the host process;
- guest permissions are effectively the host's permissions; and
- guests are not isolated from one another as separate sandboxed processes.

So the screenshot's core idea is sound with one correction: make the
LiveContainer-like *loader operations* part of a stable worker/runtime service,
but do not assume that ordinary LiveContainer JIT mode already bypasses iOS 27
code signing. On 24A435, our debugger page broker is the component that makes
new executable pages usable.

A root service also cannot manufacture arbitrary kernel-accepted entitlements
at runtime. The stable host receives the entitlements accepted from its own
signature/admission. Code loaded into that address space operates with that
host context; it does not bring a guest entitlement set with it.

## Why “platformization” is not a global allowlist

Platform status can relax particular checks and is useful for a carefully
scoped anchor, but it does not cause every future executable to become trusted.
On `execve`, AMFI and the code-signing monitor evaluate the new main image. A
platformized parent, root UID, broad host entitlements, or skip-library-
validation does not turn an arbitrary child Mach-O into an admitted image.

That is why the useful design keeps payload code as data inside a small number
of fixed admitted binaries. Platformization may improve what the fixed daemon
can do; it is not the mechanism that removes per-payload image admission.

## Installed runtime architecture

The implementation separates coordination from execution:

```text
Sileo constructor ---- sandbox/file bridge ----+
                                                v
                                  system root broker launch daemon
                                      |                    |
                         direct spawn succeeds      admission-like failure
                                      |                    |
                                      |                    v
                                      |          fixed GTA exec worker
                                      |          debugger/COW + loader
                                      v                    v
                                  command result returned to Sileo

root broker process watcher ---- guarded task port/ROP ---- trusted ElleKit
               |                                             injector
               +---- PID 1/launchd forbidden
               +---- Sileo excluded (dedicated constructor path)
               +---- platform apps excluded except SpringBoard
```

The coordinator, worker, ElleKit loader, and injector library are the fixed
artifacts that must be admitted by the Cryptex trust cache. Each fallback
request gets a fresh worker; the design does not assume that a softened
parent's TXM state survives `fork`. XNU's current
`txm_fork_prepare(old_pmap, new_pmap)` is a no-op/TODO, while invalid-code
permission belongs to the address space.

Initial payload formats should be intentionally smaller than arbitrary Mach-O:

1. GumJS or a compact bytecode VM for control logic.
2. Precompiled position-independent AArch64 modules with a versioned entry ABI.
3. A relocatable-object or Wasm format after bounds and import policies exist.
4. A bounded Mach-O loader only after relocations, chained fixups, arm64e
   pointers, initializers, thread-local state, and unwind behavior are tested.

The initial ABI should pass a capability table rather than ambient filesystem
or task ports. Bound module size, executable-page count, runtime, memory,
threads, descriptors, output, and IPC peers. Validate everything before asking
the page broker to authorize execution.

The on-device worker now implements the minimal debugger/COW operation and has
passed its executable-page self-test. Fruity/debugserver remains the richer
interactive debugging route; the daemon does not embed Frida or expose a
general remote-debug service.

## App registration and execution policy stay separate

The modern direct LaunchServices path in appregistrard works for the mobile
user when plugins are flattened and HookInjection is absent. A generic Cryptex
app became registered and FrontBoard reached its executable. Its later
`SIGTRAP` was in scene lifecycle, not AMFI image admission.

That result is valuable for discoverability, icons, scenes, and launching a
fixed container host. It is not an AMFI bypass. The clean composition is:

- appregistrard registers the fixed host app;
- FrontBoard launches that already admitted host;
- the debugger page broker enables its runtime code pages; and
- the host loader runs payloads as in-process data.

AppRegistrar/AppSync-style registration should not be asked to authorize a new
untrusted main executable; that is a different policy layer.

## Two meanings of arbitrary execution

| Goal | What is now viable | What remains unresolved |
| --- | --- | --- |
| Arbitrary native computation | Installed fixed worker plus on-device debugger/COW page authorization and runtime loader; no trust-cache entry per submitted module | A versioned public module ABI, authentication, and broader loader hardening |
| Jailbreak command-line Mach-O through Sileo | Root broker first tries normal spawn, then routes admission failures through the worker's LiveContainer-style `--macho` mode | Full compatibility with every Mach-O feature and exact child-process semantics |
| Arbitrary command-line Mach-O with transparent system-wide `execve` semantics | Not provided; the daemon is an explicit process-container strategy | Real signing, per-image trust, or a deliberate research/custom AMFI and code-signing-monitor policy |

A userland loader can eventually emulate much of dyld, but it does not
automatically reproduce process identity, sandbox construction, entitlements,
signals, `posix_spawn`, jetsam accounting, or every assumption made by ordinary
Procursus tools. Claiming transparent `/var/jb` command execution requires
testing those semantics, not just executing one function.

## Next milestones

1. Rebuild and install the no-APT-hook revision, then pass BrokerProbe 1.0.14
   through unpack, `postinst`, executable launch, and tweak activation.
2. Perform and record a clean-reboot acceptance pass for Cryptex remount, trust
   cache availability, broker startup, worker self-test, and Sileo launch.
3. Expand `--macho` compatibility deliberately: chained fixups, arm64e pointer
   cases, initializers, TLS, unwind state, and commands that assume a distinct
   process identity.
4. Add an authenticated, capability-limited general module API instead of
   widening Sileo's command broker.
5. Keep Frida as the interactive debugging path and port only demonstrated Gum
   primitives into the worker when they are needed in production.
6. Treat transparent system-wide arbitrary `execve` as a separate kernel/AMFI
   policy project; platformization alone does not provide it.

The installed KDK and local XNU source are useful for symbols, panic triage,
and checking the TXM/AMFI boundary. They are not prerequisites for the now-
working runtime path, and they do not themselves alter the device's admission
policy.
