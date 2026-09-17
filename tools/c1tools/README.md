# c1tools - the lane's admitted binaries, and the payloads they run

Everything in this directory ships inside `c1tools_1.0_iphoneos-arm64.deb`, which the lane
build embeds in its cryptex. Nothing here depends on a checkout outside this repo.

## The one thing to understand first

There are **two tiers**, and confusing them is the single most common way to waste time
here.

**Tier 1, admitted.** The lane's cryptex trust cache is built at personalization time and
is **immutable afterwards**. Every Mach-O under the trusted package root gets its CDHash
hashed into that cache. A binary that arrives any other way - a plain `dpkg`, an
`apt install` - has a CDHash in no cache and is **SIGKILLed at exec** (`rc=137`). That is
not a sandbox denial and not a signature problem; it is the trust cache missing an entry,
and it is why `unzip` dies and why adding a tool costs a lane rebuild.

**Tier 2, payloads.** Once `cs-loader` is admitted, the code *it* runs needs no admission
at all. It maps the payload's segments into **anonymous** pages in a child that has been
debug-authorised, applies the fixups from outside through the task port, and calls the
entry point. Nothing is signed, nothing is hashed, no trust cache is involved, and the
payload's own CDHash is irrelevant. **One rebuild admits the loader; every payload after
that is free.**

So the rule of thumb: changing a file in this directory costs one lane rebuild (one TSS
round trip). Changing a *payload* costs nothing.

## What is here

| file | tier | what it is |
| --- | --- | --- |
| `cs-loader.c` | 1 | **the loader.** Runs an arbitrary **unsigned** Mach-O as the code of a child it owns. Both fixup encodings, dependency resolution from the payload's own `LC_LOAD_DYLIB`, quiet unless `-v` |
| `tfpid_probe.c` | 1 | task ports and **real** cross-process reads: walks a target's `dyld_all_image_infos` and reads its Mach-O header and image path out of its memory, including for pid 1 |
| `injprobe.c` | 1 | injection into a process we did not spawn: task port, plant a dylib path, `thread_set_state` to call `dlopen`. Reports the target's suspend count and refuses to read a stale `x0` |
| `agent.c` | 1 | the dylib `injprobe` injects. Its constructor writes a marker naming the pid it ran in, which is what makes a stale marker detectable |
| `entitlements/` | - | two plists: `anchor-worker` (bare `get-task-allow` plus the debug-client set) for cs-loader, `debug-client` for tfpid and injprobe. Bare keys are honoured in ad-hoc signatures; `com.apple.developer.*` is fatal at exec |
| `lane.sh` | - | run commands and move files to and from the device (`check`/`run`/`push`/`pull`/`ls`/`shell`) |
| `HANDOFF.md` | - | the task-port and injection session handoff, with the full add-a-binary walkthrough |

This is deliberately the small set. The wider campaign toolkit - `ipcprobe`, `anchor`,
`tcpusher`, `dlrun`/`dllrun`, `tcauthor.py` and the rest - lives in the
`cryptex-srd-bug` workbench alongside the evidence tree; what ships here is what the
loader needs and what measures the primitives around it.

## Build and ship

```sh
./build_toolkit_deb.sh            # prints every CDHash and the deb's sha256
```

Then, to put a changed binary on the device - this is the TSS step:

```sh
cd ../..                                       # the repo root
rm -f Dopamine-upstream/CryptexBootstrap/cache/c1tools_1.0_iphoneos-arm64.deb
C1TOOLS_SHA256=<sha from the build> \
  ./Dopamine-CryptexBootstrap/setup.sh --install \
      --device <UDID> --allow-unverified-device --no-brew

./tools/c1tools/lane.sh push build/c1tools_1.0_iphoneos-arm64.deb /var/jb/tmp/c1tools.deb
./tools/c1tools/lane.sh run  'dpkg --instdir=/var/jb --admindir=/var/jb/Library/dpkg \
                              -i /var/jb/tmp/c1tools.deb'
```

Two details that will otherwise cost a rebuild each:

- **Clear the cached deb.** `fetch_pinned` skips the download when a cached file already
  exists, and then fails with `cached hash mismatch` naming the deb rather than the cache.
- **The cryptex and the files land separately.** The lane install puts the *trust* in
  place; `dpkg` puts the *bytes* in `/var/jb`. Both are required, and skipping the second
  gives you a build that succeeded and a tool that is not there.

`HANDOFF.md` has the long version, including what each step proves and the environment
gotchas (no `scp`, zsh word-splitting, the device returning empty output when it has
dropped off USB).

## Payloads need none of this

To run something without touching the trust cache or spending a TSS:

```sh
cs-loader /var/jb/usr/bin/<tool> [args...]        # arbitrary unsigned Mach-O
cs-loader -v /var/jb/usr/bin/<tool> [args...]     # and the layout trace
```

Options come **before** the payload path, so `cs-loader ./x -v` passes `-v` to the payload.
