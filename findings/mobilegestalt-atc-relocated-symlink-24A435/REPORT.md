# ATAirlock relocated-symlink chosen-value write on iOS 27 RC 24A435

Date: 2026-09-13

Target: iPhone 17 Pro Max (`iPhone18,2`), iOS 27.0 RC, build `24A435`

## Verdict

Confirmed on the exact retail device over its existing paired Wi-Fi connection.
A paired host can compose three independently incomplete behaviors to place an
attacker-chosen binary property list at the real MobileGestalt preference input:

```text
/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist
```

The runtime payload was the 59-byte binary-plist encoding of
`{"EnableStark": true}` (SHA-256
`b40a788ae2767a9ea5900fb869d0ddbd5e4ae4a2c5ea85857c564ea7b15a8fd2`).
The write was followed by a third-asset recovery move. A newly established
MobileDevice host process read 59 bytes from the fresh recovery path and found
an exact byte match. Generated Media objects and Books input were then removed,
and a separately launched app process proved that the original absent
MobileGestalt-source preimage was restored.

This confirms modification of the real MobileGestalt plist input with a chosen
key/value. It does **not** establish that a cached or already running
MobileGestalt consumer changed its answer during the brief test window.
`StarkCapability` was already true on this hardware, while ordinary app access
to the newly present source file was denied.

## Root cause and chain

The chain is a relocated-relative-symlink containment failure, not a direct
absolute-path bypass.

1. `com.apple.streaming_zip_conduit` accepts a relative symlink that resolves
   inside its fresh extraction root. The tested link was created as
   `pivot/link -> ../Library/Preferences`, while the archive also contained the
   matching in-root `Library/Preferences` directory. This is safe at creation
   time and passes StreamingZip's symlink validation.
2. Normal Books reconciliation accepts caller-staged `Books/Sync/Books.plist`
   records whose `Persistent ID` contains `..` components. The value becomes
   the download asset identifier without path-component validation.
3. Books uses `+[ATAsset downloadAssetWithIdentifier:dataclass:prettyName:]`
   (`0x251d98ccc`), which marks the asset legacy. Consequently
   `-[ATLegacyAssetLink canEnqueueAsset:]` (`0x229606c5c`) accepts it even
   though `storeInfoForItem:` (`0x7168`) leaves `ATStoreInfo.syncID` nil.
4. `-[ATAirlock processCompletedAsset:]` (`0x251da6158`) constructs its source
   as `/var/mobile/Media/Airlock/<dataclass>/<syncID-or-identifier>`. It does
   not standardize the resulting source or check that it remains below the
   Airlock root. A `Persistent ID` beginning with `../../` therefore selects
   the StreamingZip-created objects in the Media root.
5. ATAirlock does standardize the destination and requires the resulting
   string to begin with `/var/mobile/Media/`. The first transfer therefore
   moves only `pivot/link` to a fresh, shallower name directly below Media.
6. Moving the relative symlink changes its meaning without changing its link
   text. At its original location it resolves to
   `/var/mobile/Media/<source>/Library/Preferences`; after relocation it
   resolves to `/var/mobile/Library/Preferences`.
7. The second transfer selects the regular archive payload through another
   traversing identifier. Its lexical destination,
   `<relocated-link>/com.apple.MobileGestalt.plist`, passes ATAirlock's Media
   prefix check. Foundation's path-based move follows the relocated ancestor
   symlink and places the payload at the real preferences path.
8. A third traversing identifier selects that real destination as ATAirlock's
   unchecked source and moves it to a fresh recovery name below Media. This
   supplies exact recovery and byte verification without depending on an
   ordinary app being allowed to read the protected preference path.

The first two runtime near misses mattered directly. StreamingZip correctly
rejects a symlink that is already outbound, but it cannot anticipate a later
cross-directory move. ATAirlock correctly rejects a lexically outbound
destination, but it neither confines its source nor prevents an intermediate
symlink from changing the destination's inode resolution. The Books identifier
traversal and the symlink relocation join those two gaps.

## Runtime evidence

The mutation run was gated on all of the following before staging:

- exact product, OS version, and build: `iPhone18,2 / 27.0 / 24A435`;
- reuse of an existing pairing, with no automatic pairing;
- an absent source-plist preimage, observed by a fresh process as
  `lstat/stat/access -> ENOENT` and direct NSData error 260;
- absent fixed `Books/Sync/Books.plist`; and
- fresh generated source, relocated-link, and recovery names below Media.

The live sequence then observed:

- StreamingZip success and both source objects present;
- Books normal sync accepted all three crafted records;
- the AirTraffic host received a three-entry Book manifest;
- the link, payload, and rollback identifiers all matched live assets;
- all three `FileComplete` messages succeeded;
- the payload-completion gate fired before rollback and did not time out;
- a separately launched app changed from ENOENT/Cocoa 260 to
  EPERM/Cocoa 257 at the exact source path, proving the absent-to-protected-
  presence transition;
- brokered `CFPreferences` and `MGCopyAnswer("EnableStark")` remained nil,
  while hardware `StarkCapability` remained true;
- the rollback asset moved the protected object to the fresh Media recovery
  path;
- a new MobileDevice host process recovered exactly 59 bytes and matched the
  chosen payload byte-for-byte;
- the source path returned to ENOENT in another fresh app process;
- every generated Media path and every tracked Books file returned to its
  preimage; cleanup reported zero failures; and
- the canonical MobileGestalt system-group cache was not touched.

A final read-only postflight after the changed-value readback independently
returned `freshProcessSourceAbsent=true`, `nativeTargetGatePassed=true`,
`nativeOperationOK=true`, and `booksSyncPlistPresent=false`.

The independent presence transition and recovery-byte equality are important:
the first proves that an object appeared at the protected target during the
gate, and the second proves that this object contained the exact chosen plist
bytes. No inference from a cached MobileGestalt answer is required.

### Changed-value parse/readback follow-up

A separate authorized run wrote the 59-byte binary-plist encoding of
`{"EnableStark": false}` (SHA-256
`fcfa7ffa0bf561c7d0332fa3e6042ef9ce566fdaab46139b44d0f157e460d560`).
After the fresh-process protected-presence observation, the rollback asset
moved the real source file to a fresh Media recovery path. A newly established
native MobileDevice host process read and parsed that recovered file before
cleanup. It reported:

```text
recoveredPresent             = true
observedLength               = 59
recoveredBytesMatch          = true
recoveredRootIsDictionary    = true
recoveredKeyCount            = 1
recoveredEnableStark         = false
recoveredPlistParseError     = null
freshHostReadBackChosenValue = true
chosenWriteProven            = true
exactRollback                = true
outcome                      = confirmed
```

The while-present app process again saw ENOENT/Cocoa 260 change to
EPERM/Cocoa 257, but `MGCopyAnswer("EnableStark")` and brokered CFPreferences
still returned nil. The readback therefore proves the changed value in the
actual plist file, while deliberately making no claim that MobileGestalt
reloaded or surfaced that optional preference during the test window. Cleanup
again removed all generated paths and Books files with zero failures, and the
fresh post-rollback process observed the source absent.

### Escaped-directory authority matrix

A follow-up used the same write-and-recovery primitive with a generalized,
three-level relative link. Each archive created
`p0/p1/p2/link -> ../../../<absolute-target-without-leading-slash>` plus a
matching in-root directory tree. StreamingZip therefore saw an initially
contained link. After ATAirlock relocated it directly below Media, the same
link text resolved to the selected absolute directory.

Every target used a fresh 128-bit-random canary leaf and a unique payload. No
existing file was selected. A positive result required ATAirlock to move the
payload into the target, move that exact target object back below Media, and a
new native host process to read an exact byte match. Negative results received
a second, independently staged link-and-recovery pass for the same canary leaf.
All primary and recovery attempts reported zero cleanup failures, absent
generated Media/Books artifacts, and an absent recovery file after cleanup.

Exact write-and-recovery was confirmed for:

- `/var/mobile/Library`, including `Preferences`, `Caches`, `SpringBoard`, and
  `Logs`, plus the expanded children `Accounts`, `AddressBook`,
  `Application Support`, `Assistant`, `Biome`, `BulletinBoard`, `Calendar`,
  `CallHistoryDB`, `Carrier Bundles`, `Cookies`, `CoreDuet`, `DataAccess`,
  `FrontBoard`, `Health`, `IdentityServices`, `Keyboard`, `Mail`,
  `MobileInstallation`, `Passes`, `Photos`, `Safari`, `SMS`, `Shortcuts`,
  `Spotlight`, `Suggestions`, `Trial`, and `UserNotifications`;
- `/var/mobile/Documents`;
- `/var/mobile/Containers`, including `Data/Application` and
  `Shared/AppGroup`;
- `/var/tmp`; and
- `/var/mobile/Media/Books` as an in-Media control.

No write was observed in either the primary attempt or dedicated recovery pass
for:

- mobile-home subtrees `Library/ConfigurationProfiles`,
  `Library/Managed Preferences/mobile`, `Library/UserConfigurationProfiles`,
  `Library/AppleMediaServices`, `Library/HomeKit`, `Library/WebClips`, and
  `Containers/Data/System`;
- `/var/db`, `/var/root`, `/var/containers`, and tested Bundle/Application,
  Data/System, and Shared/SystemGroup descendants;
- `/Library`, `/Library/Preferences`, and `/Library/Caches`;
- `/System/Library` and `/System/Library/Caches`; and
- the same mobile Preferences and system-container paths expressed under
  `/private/var`, plus `/tmp`.

The spelling difference is reproducible: `/var/mobile/Library/Preferences`
and `/var/tmp` were writable, while their `/private/var/mobile/...` and `/tmp`
aliases were not. This supports a lexical sandbox/path-policy boundary rather
than a decision made after canonicalizing filesystem aliases. A fresh,
unrelated canary leaf in the MobileGestalt system-group Caches directory was
negative using both `/var/containers/...` and `/private/var/containers/...`;
the canonical cache leaf itself was never targeted or touched.

The final independent postflight returned
`freshProcessSourceAbsent=true`, `sourceProbeExitCode=0`,
`nativeTargetGatePassed=true`, `nativeOperationOK=true`, and
`booksSyncPlistPresent=false`.

The `/var/mobile/Library` expansion covered 30 additional children: 27
produced exact write-and-recovery evidence and three produced no write in both
the primary and dedicated recovery passes. Combined with the earlier matrix,
31 tested Library children were confirmed writable and six had no write
observed. A negative result does not by itself distinguish an absent directory
from a present but denied directory.

### Disposable Messages SQLite collision

An occupied-destination follow-up exercised `/var/mobile/Library/SMS` without
selecting the live `sms.db`, its WAL/SHM files, attachments, or any other user
file. The harness generated a fresh random leaf and two valid SQLite databases:
an 8,192-byte preimage and a distinct 24,576-byte replacement.

The controlled sequence was:

1. create the disposable SQLite preimage at the fresh SMS leaf;
2. move it back below Media and recover an exact preimage byte match, proving
   the creation control;
3. repeat the same successful preimage-creation operation at the now-fresh
   leaf;
4. move the distinct replacement to that same leaf; and
5. move the resulting target back below Media and compare it against both
   inputs.

The final recovery matched the replacement exactly and did not match the
preimage. The run reported
`creationControlRecoveredExact=true`,
`occupiedCreationDispatched=true`,
`directOccupiedDestinationOverwrite=true`, and
`allGeneratedArtifactsAccountedFor=true`. This confirms replacement semantics
for a disposable preexisting SQLite file in the Messages directory. It does
not claim that the live, potentially open and file-protected `sms.db` was
modified or that its runtime locking behavior is identical.

The ordinary AFC client could not independently read the disposable file
through the relocated link while it was in place. Accordingly, the occupied
precondition is supported by the immediately preceding exact creation/recovery
control and identical recreation operation, rather than by an AFC read of the
in-place target. The postflight again found the MobileGestalt source absent,
Books staging absent, and all generated paths removed.

## Static anchors

All addresses are unslid addresses in the exact 24A435 artifacts, except for
the standalone Books bundle whose image base is zero.

| Behavior | Artifact / address |
|---|---|
| Legacy asset admission | `ATLegacyAssetLink canEnqueueAsset:` / `0x229606c5c` |
| Download factory sets legacy state | `ATAsset downloadAssetWithIdentifier:dataclass:prettyName:` / `0x251d98ccc` |
| Legacy getter | `ATAsset isLegacy` / `0x251d9ae2c` |
| Store info initialization | `ATStoreInfo init` / `0x251d9ba44` |
| Books store-info construction; no `syncID` setter | `storeInfoForItem:` / `0x7168` |
| Unconfined Airlock source and lexical destination check | `ATAirlock processCompletedAsset:` / `0x251da6158` |
| Host `FileComplete.AssetPath` replacement | `ATLegacyAssetLink` block / `0x229607a50` |
| MobileGestalt source read | `libMobileGestalt` / `sub_1AFA292CC` and `sub_1AFA2E450` |

`ATAirlock` constructs the destination in this effective form:

```objc
dest = [[@"/var/mobile/Media/" stringByAppendingPathComponent:asset.path]
        stringByStandardizingPath];
if (![dest hasPrefix:@"/var/mobile/Media/"])
    reject;
```

The source constructed immediately beforehand has no corresponding
standardization, prefix test, `realpath`, directory-FD walk, or all-component
nofollow enforcement. The final move is
`-[NSFileManager moveItemAtPath:toPath:error:]`.

## Distinctness and public prior art

A public-web search on 2026-09-13 covered the exact class names, method names,
service name, Books sync pathname, `Persistent ID` traversal, MobileGestalt
target, build number, and combinations of AirTraffic, StreamingZip, and
symlink relocation. No matching public disclosure or exploit description was
found.

The nearest public prior art is Apple's iOS 8.4.1 advisory for
[CVE-2015-5766](https://support.apple.com/en-asia/103656), which says only that
AirTraffic had an asset-handling path traversal and that Apple added improved
validation. The present 24A435 code contains a destination standardization and
prefix check, and the new chain does not bypass that check with a direct `..`
destination. It instead combines an unchecked source identifier with a
relocated, initially in-root relative symlink so that the checked lexical
destination resolves through an outbound ancestor only after relocation.

That evidence supports describing this as distinct from the public description
of CVE-2015-5766. It cannot prove that Apple or another researcher has no
nonpublic knowledge of the same root cause. The defensible novelty statement
is: **no matching public disclosure was found in the searched corpus as of
2026-09-13**.

## Impact and constraints

- Confirmed impact is an attacker-chosen regular-file write at the real
  MobileGestalt source-preference pathname under `/var/mobile/Library`.
- The runtime matrix additionally confirms chosen-file creation in broad
  mobile-user data, including app data-container roots, shared AppGroups,
  SpringBoard state storage, Logs, and `/var/tmp`. Explicitly protected mobile
  configuration/profile directories and system-container roots remained
  negative in the tested process profile.
- The disposable Messages-directory SQLite control confirms that the same
  destination operation can replace a preexisting regular file. No live user
  database was selected, so behavior specific to an open or file-protected
  database remains outside the tested claim.
- The tested entry condition is a paired host that can start the relevant
  MobileDevice services over the existing Wi-Fi pairing. This report does not
  claim zero-click remote or ordinary-App-Store-app reachability.
- The canonical system-group MobileGestalt cache was not writable through this
  process profile and was not touched.
- The run proved chosen plist bytes at the input path, not a semantic
  MobileGestalt answer change. `EnableStark` is a narrow optional source input,
  and this hardware already reported `StarkCapability=true`.

## Remediation

ATAirlock should treat both operands as untrusted and bind their resolution to
pinned directory descriptors:

1. reject asset identifiers containing `/`, `.` components, or `..`
   components and use only framework-generated opaque leaves for the source;
2. reject non-regular source objects, including symlinks, before any move;
3. resolve every source and destination component beneath pinned Airlock/Media
   directory FDs with all-component nofollow semantics; and
4. perform the final rename using descriptor-relative APIs, rather than
   re-resolving Foundation path strings.

Books should independently restrict `Persistent ID` to its expected opaque-ID
grammar and never reuse it as a filesystem component. Either fix breaks the
confirmed chain; applying both gives defense in depth.

## Reproduction and supporting artifacts

- Runtime orchestrator: `tools/atc-streamingzip-chain-static/chain_canary.py`
- Escaped-directory matrix:
  `tools/atc-streamingzip-chain-static/directory_matrix.py`
- Disposable Messages SQLite collision probe:
  `tools/atc-streamingzip-chain-static/sms_disposable_collision.py`
- AirTraffic host: `tools/atc-streamingzip-chain-static/atc_host.m`
- Native paired-device transport and recovery verifier:
  `tools/atc-streamingzip-chain-static/mobiledevice_io.m`
- Fresh-process MobileGestalt probe:
  `tools/mobilegestalt-stark-baseline-probe/Probe/AppDelegate.m`
- Earlier AirTraffic/Books near-miss analysis:
  `tools/atc-mg-write-static/ATC-CLIENT-PLUGIN-AUDIT-24A435.md`
- Earlier trigger/provenance near miss:
  `tools/atc-mg-write-static/BOOKS-LEGACY-TRIGGER-AUDIT-24A435.md`
- StreamingZip symlink controls:
  `tools/streaming-zip-mg-write-canary/EXTRACTION-DIAGNOSIS-24A435.md`

Current source hashes after the parsed-value readback and directory-matrix
additions:

| File | SHA-256 |
|---|---|
| `chain_canary.py` | `a52c10b2e39e893a8f55161e1e40c975838be30cbb7a48bd4a3b123b1565533e` |
| `directory_matrix.py` | `8b6832afaf073df1db48fe429746710dc112c66565d129ac1edcf6f82156fdac` |
| `sms_disposable_collision.py` | `f999c0fd88994e528e94c381accb18aedef893548de2ca5895122f7640d1b951` |
| `atc_host` | `571060a3e5e4da69b04b24f0e35279557ed2365c18349ccbc0b2f58b36c1d6ff` |
| `atc_host.m` | `bc5ff8bbd3a2fa3be330d1ccb7c58559c9752ba017e8915e6df18b29e46abbed` |
| `mobiledevice_io` | `10678dde64c8e0ebf6cee9396f5b830a95f72d1b0cfc898b39cbe442f91a8cf0` |
| `mobiledevice_io.m` | `855509f3b94966f7f7ba4a9391e07f9dd0021b2fc2fadaeabe6529d381c8d459` |
| `Probe/AppDelegate.m` | `c3debeed6194f77ae74d255564e251c5d20bf45ba7b2adcdf90b2244689704cf` |
