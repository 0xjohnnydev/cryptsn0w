# Wi-Fi transport result — 24A435

Date: 2026-09-13

Runtime: `pymobiledevice3 11.12.4`, `pmd-pytcp 0.3.7`

## Result

The harness now reaches the exact paired `iPhone18,2` running `27.0
(24A435)` over Wi-Fi without relying on `NativeRemotedTunnel` or creating a
new pairing.

The proven path is:

`CoreDevice inventory -> Apple usbmux ReadPairRecord -> mobdev2
TcpLockdownClient -> CoreDeviceTunnelProxy -> UserspaceTun -> in-process RSD`

No identifier, network address, or pair-record material is emitted by the
harness. `autopair` is hard-disabled. No backup was created and backup
encryption state was not queried or changed.

## Transport evidence

- CoreDevice reported exactly one matching target as paired, connected, and
  using `localNetwork` transport.
- usbmux listed no connected mux device, but `ReadPairRecord` succeeded for
  the target UDID resolved in memory from CoreDevice.
- Bonjour advertised mobdev2 endpoints. The first candidate failed closed;
  the second authenticated using the existing pair record.
- The authenticated `TcpLockdownClient` matched the CoreDevice UDID and the
  exact product, version, and build gate before `CoreDeviceTunnelProxy` was
  started.
- The userspace tunnel completed an RSD handshake with
  `is_in_process_tunnel == True` and advertised
  `com.apple.streaming_zip_conduit.shim.remote`.

## Authorized canary run

One fresh `/var/mobile/Media` sibling canary was run after the transport-only
probe.

- Product/version/build gate: passed (`iPhone18,2`, `27.0`, `24A435`).
- Fresh source and destination preflight: both absent.
- Service response: `ExtractionFailed`.
- Canary outside the extraction root: not observed.
- Exact cleanup: zero failures; both generated directories verified absent.

Therefore the transport issue is resolved. Follow-up controls and a filtered
live activity stream narrowed the rejection to initial symlink-entry
validation, before any payload open. See `EXTRACTION-DIAGNOSIS-24A435.md`.

## Files

- `canary.py`: transport selection, existing-pair authentication, userspace
  RSD construction, and address-aware redaction.
- `README.md`: updated transport and backup-state guarantees.
