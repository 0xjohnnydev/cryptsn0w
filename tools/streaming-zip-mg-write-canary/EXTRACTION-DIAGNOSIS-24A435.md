# Streaming-zip extraction diagnosis — 24A435

Date: 2026-09-13

Runtime: `pymobiledevice3 11.12.4`, `pmd-pytcp 0.3.7`

## Conclusion

The sibling-escape archive is rejected during the helper's **initial symlink
entry validation**, before the later directory or payload entries are
processed. It does not reach the regular-file open, so this run tests neither
an open-time sandbox decision nor the final archive-wide symlink rescan.

The three controls distinguish the phase:

| Case | Full terminal reply | Exact bytes observed | Cleanup |
|---|---|---|---|
| Same-root regular file | `{"Status":"DataComplete"}` | yes, at the regular in-root path | root absent, zero failures |
| Initially dangling symlink whose final target remains in-root | `{"Status":"DataComplete"}` | yes, through the activated symlink | root absent, zero failures |
| Initially dangling symlink whose lexical target is a fresh sibling | `{"Error":"ExtractionFailed"}` | no | source and destination absent, zero failures |

All three used a fresh generated root below `/var/mobile/Media`, the identical
length-prefixed initial plist plus raw ZIP framing, binary Version 2 stream
metadata, the same `SZ` Unix-mode extra field, and the same fixed canary bytes.
No path parameter was introduced.

## Control details

### Same-root regular archive

The archive contained the metadata entries followed by a regular
`canary-24A435.txt`. The helper returned `DataComplete`; AFC observed the file
with the expected SHA-256 and byte-for-byte contents. This proves the host
plist framing, raw ZIP transfer, central directory, Version 2 metadata, mode
extra field, extraction root extension, and ordinary file creation all work.

### In-root dangling-symlink activation

The symlink target was `missing/../inside`. `missing/` and `inside/` were later
created, then `link/canary-24A435.txt` was supplied. The helper returned
`DataComplete`, and AFC observed the exact bytes at
`inside/canary-24A435.txt`. This proves the helper accepts an initially
dangling relative symlink and subsequently writes through it when its final
resolution remains under the extraction root.

### Sibling escape

The target had the existing fixed shape
`missing/../../<fresh-sibling-directory>`. The full reply was
`{"Error":"ExtractionFailed"}`. Before cleanup, AFC observed only the
pre-created sibling directory; the helper had already removed the extraction
root, and neither the symlink, `missing/`, nor the target file was present.

The filtered live log sequence is decisive:

1. setup completes with offset 0 and no error;
2. the 756-byte archive block is received;
3. Version 2 metadata is parsed;
4. the symlink record is recognized as mode `0120777` and retained in memory;
5. the helper logs `Invalid symlink`, transitions directly from
   `CompleteLFData` to `Error`, and reports `SZExtractorErrorDomain Code=5`
   with source line 1489;
6. no later local-file record is processed.

The relevant redacted activity-stream sequence is preserved in
`evidence/streaming-zip-sibling-escape-sanitized.log`.

## Safety invariants

- The exact `iPhone18,2 / 27.0 / 24A435` identity and build gates passed before
  each service start.
- Existing pairing was reused with `autopair=False`; no pairing state changed.
- Only fresh generated paths below `/var/mobile/Media` were used.
- Each cleanup unlinked the symlink first and removed only its enumerated case
  paths; every generated root was verified absent with zero failures.
- No backup was created, and backup encryption state was not queried or
  changed.

## Implication for the static candidate

The runtime result falsifies the proposed trigger on this exact device/build:
an outward-resolving target with the tested `missing/../../sibling` shape is
not temporarily admitted on `ENOENT`. The helper rejects it immediately. A
later payload write and final-rescan failure cannot be inferred from the
generic conduit reply alone.
