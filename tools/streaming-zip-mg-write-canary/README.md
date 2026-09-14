# StreamingZip dangling-symlink activation canary

This harness is for a reversible, non-MobileGestalt validation of the 24A435
`StreamingUnzipService` `realpath(3)`/`ENOENT` containment flaw.

The first runtime stage must target only two fresh sibling directories below
`/var/mobile/Media`.  It must not name either MobileGestalt plist, any existing
preference file, or any path outside `Media`.  Promotion beyond that stage
requires a separately verified sandbox result, a preimage backup, and an exact
restore plan.

`canary.py` has no path arguments. It generates two fresh names, refuses any
device other than `iPhone18,2` on `27.0 (24A435)`, and deletes only seven exact
paths. Without `--run` it performs a local archive-layout dry run.

The runtime path resolves the one already-paired, connected local-network
target from CoreDevice, reads its existing pair record through Apple's usbmux
daemon, authenticates a mobdev2 `TcpLockdownClient` with `autopair=False`, and
starts `CoreDeviceTunnelProxy` through pymobiledevice3's in-process userspace
stack. Identifiers, addresses, and pair-record material are never printed or
written by the harness. It does not create a backup or change backup-encryption
state.

Runtime controls on 24A435 show that ordinary in-root extraction and an
initially dangling symlink whose final target remains in-root both complete,
but the sibling target is rejected during its initial symlink-entry validation
before the later directory or payload record is processed. See
`EXTRACTION-DIAGNOSIS-24A435.md`; this harness is not evidence of a confirmed
sibling write.
