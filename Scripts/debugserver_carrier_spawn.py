#!/usr/bin/env python3
"""Transactionally call posix_spawn from the exact resident root carrier.

Mutation modes are intentionally allowlisted to exact commands, including:

    /var/jb/usr/libexec/codex-exec-worker --self-test
    /var/jb/usr/bin/install -m 0644 /var/tmp/codex-runtime-broker.log \
        /var/mobile/Media/codex-runtime-broker-live.log
    /var/jb/usr/bin/install -m 0644 \
        /var/jb/usr/lib/codex-runtime-carrier.dylib \
        /var/mobile/Media/codex-runtime-carrier-live.dylib
    /var/jb/usr/bin/install -m 0644 \
        /var/jb/usr/libexec/codex-carrier-ptrace-exec-probe \
        /var/mobile/Media/codex-carrier-ptrace-exec-probe-live
    /var/jb/usr/libexec/codex-exec-worker --macho \
        /var/jb/usr/libexec/codex-carrier-ptrace-exec-probe
    /var/jb/usr/bin/install -m 0644 \
        /var/tmp/codex-carrier-ptrace-exec-probe.log \
        /var/mobile/Media/codex-carrier-ptrace-exec-probe-live.log
    /var/jb/usr/bin/install -m 0644 \
        /var/jb/usr/lib/codex-runtime-carrier.dylib \
        /var/jb/usr/lib/codex-runtime-carrier.f3510cc6.rollback.dylib
    /var/jb/usr/bin/install -m 0644 \
        /var/mobile/Media/codex-runtime-carrier-v21.dylib \
        /var/jb/usr/lib/.codex-runtime-carrier.2ffc0da2.new
    /var/jb/usr/bin/install -m 0644 \
        /var/jb/usr/lib/.codex-runtime-carrier.2ffc0da2.new \
        /var/mobile/Media/codex-runtime-carrier-staged-v21.dylib
    /var/jb/usr/bin/mv -f \
        /var/jb/usr/lib/.codex-runtime-carrier.2ffc0da2.new \
        /var/jb/usr/lib/codex-runtime-carrier.dylib
    /var/jb/usr/bin/install -m 0644 \
        /var/jb/usr/lib/codex-runtime-carrier.f3510cc6.rollback.dylib \
        /var/jb/usr/lib/.codex-runtime-carrier.2ffc0da2.new
    /var/jb/usr/bin/install -m 0644 \
        /var/mobile/Media/codex-runtime-carrier-v22.dylib \
        /var/jb/usr/lib/codex-runtime-carrier-v22.dylib
    /var/jb/usr/bin/install -m 0644 \
        /var/jb/usr/lib/codex-runtime-carrier-v22.dylib \
        /var/mobile/Media/codex-runtime-carrier-v22-installed.dylib
    /var/jb/usr/bin/install -m 0755 \
        /var/mobile/Media/codex-carrier-ptrace-exec-probe-v22 \
        /var/jb/usr/libexec/codex-carrier-ptrace-exec-probe-v22
    /var/jb/usr/bin/install -m 0644 \
        /var/jb/usr/libexec/codex-carrier-ptrace-exec-probe-v22 \
        /var/mobile/Media/codex-carrier-ptrace-exec-probe-v22-installed
    /var/jb/usr/libexec/codex-exec-worker --macho \
        /var/jb/usr/libexec/codex-carrier-ptrace-exec-probe-v22
    /var/jb/usr/bin/install -m 0644 \
        /var/tmp/codex-carrier-ptrace-exec-probe-v22.log \
        /var/mobile/Media/codex-carrier-ptrace-exec-probe-v22-live.log
    /var/jb/usr/bin/install -m 0644 \
        /var/tmp/codex-runtime-carrier.loaded \
        /var/mobile/Media/codex-runtime-carrier-v22-live.marker
    /var/jb/usr/libexec/codex-ellekit-loader --inspect-pid SPRINGBOARD_PID
    /var/jb/usr/libexec/codex-ellekit-loader --page-probe-pid SPRINGBOARD_PID
    suspended /var/jb/usr/libexec/codex-ellekit-loader --inspect-pid \
        SPRINGBOARD_PID --ptrauth-child, with SpringBoard's ptrauth task port
    /var/jb/usr/bin/kill -CONT OWNED_CHILD_PID
    /var/jb/usr/libexec/codex-exec-worker --macho \
        /var/jb/usr/libexec/codex-jsc-data-probe
    /var/jb/usr/bin/install -m 0755 \
        /var/mobile/Media/codex-jsc-data-probe \
        /var/jb/usr/libexec/codex-jsc-data-probe
    /var/jb/usr/bin/install -m 0755 \
        /var/mobile/Media/codex-jsc-springboard-probe \
        /var/jb/usr/libexec/codex-jsc-springboard-probe
    /var/jb/usr/libexec/codex-exec-worker --macho \
        /var/jb/usr/libexec/codex-jsc-springboard-probe SPRINGBOARD_PID
    /var/jb/usr/bin/install -m 0644 \
        /var/mobile/Media/codex-worker-fresh-dylib-canary.dylib \
        /var/jb/usr/lib/codex-worker-fresh-dylib-canary.dylib
    /var/jb/usr/bin/sh -c 'exec /var/jb/usr/libexec/codex-exec-worker --dylib \
        /var/jb/usr/lib/codex-worker-fresh-dylib-canary.dylib \
        >/var/mobile/Media/codex-worker-fresh-dylib-canary.stdout \
        2>/var/mobile/Media/codex-worker-fresh-dylib-canary.stderr'
    /var/jb/usr/bin/rm -f \
        /var/jb/usr/lib/codex-worker-fresh-dylib-canary.dylib

Before changing state, the harness verifies the attached PID, the carrier's
fixed stop PC, its in-memory Mach-O UUID, the deliberate spin instruction at
that PC, and the exact arm64e authenticated posix_spawn stub.  It uses
debugserver-owned scratch memory and QSave/QRestoreRegisterState, removes its
hardware breakpoint, deallocates scratch memory, and detaches on every bounded
exit path.  PID 1 is always rejected.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import struct
import sys
import uuid
from dataclasses import dataclass

from pymobiledevice3.remote.remote_service_discovery import (
    RemoteServiceDiscoveryService,
)
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel


DEBUG_PROXY_SERVICE = "com.apple.internal.dt.remote.debugproxy"
WORKER_PATH = "/var/jb/usr/libexec/codex-exec-worker"
WORKER_ARGUMENTS = (WORKER_PATH, "--self-test")
LOADER_PATH = "/var/jb/usr/libexec/codex-ellekit-loader"
INSTALL_PATH = "/var/jb/usr/bin/install"
MV_PATH = "/var/jb/usr/bin/mv"
RM_PATH = "/var/jb/usr/bin/rm"
KILL_PATH = "/var/jb/usr/bin/kill"
BROKER_LOG_SOURCE = "/var/tmp/codex-runtime-broker.log"
BROKER_LOG_DESTINATION = "/var/mobile/Media/codex-runtime-broker-live.log"
LIVE_RUNTIME_SOURCE = "/var/jb/usr/lib/codex-runtime-carrier.dylib"
LIVE_RUNTIME_DESTINATION = "/var/mobile/Media/codex-runtime-carrier-live.dylib"
LIVE_LAUNCHER_SOURCE = "/var/jb/usr/libexec/codex-carrier-ptrace-exec-probe"
LIVE_LAUNCHER_DESTINATION = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-live"
)
LIVE_LAUNCHER_LOG_SOURCE = "/var/tmp/codex-carrier-ptrace-exec-probe.log"
LIVE_LAUNCHER_LOG_DESTINATION = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-live.log"
)
COPY_BROKER_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    BROKER_LOG_SOURCE,
    BROKER_LOG_DESTINATION,
)
COPY_LIVE_RUNTIME_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    LIVE_RUNTIME_SOURCE,
    LIVE_RUNTIME_DESTINATION,
)
COPY_LIVE_LAUNCHER_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    LIVE_LAUNCHER_SOURCE,
    LIVE_LAUNCHER_DESTINATION,
)
LAUNCH_RUNTIME_BROKER_ARGUMENTS = (
    WORKER_PATH,
    "--macho",
    LIVE_LAUNCHER_SOURCE,
)
COPY_LIVE_LAUNCHER_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    LIVE_LAUNCHER_LOG_SOURCE,
    LIVE_LAUNCHER_LOG_DESTINATION,
)
RUNTIME_ROLLBACK_PATH = (
    "/var/jb/usr/lib/codex-runtime-carrier.f3510cc6.rollback.dylib"
)
RUNTIME_V21_UPLOAD_PATH = (
    "/var/mobile/Media/codex-runtime-carrier-v21.dylib"
)
RUNTIME_STAGE_PATH = (
    "/var/jb/usr/lib/.codex-runtime-carrier.2ffc0da2.new"
)
RUNTIME_STAGE_VERIFY_PATH = (
    "/var/mobile/Media/codex-runtime-carrier-staged-v21.dylib"
)
BACKUP_RUNTIME_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    LIVE_RUNTIME_SOURCE,
    RUNTIME_ROLLBACK_PATH,
)
STAGE_RUNTIME_V21_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    RUNTIME_V21_UPLOAD_PATH,
    RUNTIME_STAGE_PATH,
)
COPY_STAGED_RUNTIME_V21_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    RUNTIME_STAGE_PATH,
    RUNTIME_STAGE_VERIFY_PATH,
)
ACTIVATE_STAGED_RUNTIME_ARGUMENTS = (
    MV_PATH,
    "-f",
    RUNTIME_STAGE_PATH,
    LIVE_RUNTIME_SOURCE,
)
STAGE_RUNTIME_ROLLBACK_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    RUNTIME_ROLLBACK_PATH,
    RUNTIME_STAGE_PATH,
)
RUNTIME_V22_UPLOAD_PATH = (
    "/var/mobile/Media/codex-runtime-carrier-v22.dylib"
)
RUNTIME_V22_PATH = "/var/jb/usr/lib/codex-runtime-carrier-v22.dylib"
RUNTIME_V22_VERIFY_PATH = (
    "/var/mobile/Media/codex-runtime-carrier-v22-installed.dylib"
)
LAUNCHER_V22_UPLOAD_PATH = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-v22"
)
LAUNCHER_V22_PATH = (
    "/var/jb/usr/libexec/codex-carrier-ptrace-exec-probe-v22"
)
LAUNCHER_V22_VERIFY_PATH = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-v22-installed"
)
LAUNCHER_V22_LOG_SOURCE = (
    "/var/tmp/codex-carrier-ptrace-exec-probe-v22.log"
)
LAUNCHER_V22_LOG_DESTINATION = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-v22-live.log"
)
RUNTIME_MARKER_SOURCE = "/var/tmp/codex-runtime-carrier.loaded"
RUNTIME_V22_MARKER_DESTINATION = (
    "/var/mobile/Media/codex-runtime-carrier-v22-live.marker"
)
STAGE_RUNTIME_V22_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    RUNTIME_V22_UPLOAD_PATH,
    RUNTIME_V22_PATH,
)
COPY_RUNTIME_V22_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    RUNTIME_V22_PATH,
    RUNTIME_V22_VERIFY_PATH,
)
STAGE_LAUNCHER_V22_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    LAUNCHER_V22_UPLOAD_PATH,
    LAUNCHER_V22_PATH,
)
COPY_LAUNCHER_V22_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    LAUNCHER_V22_PATH,
    LAUNCHER_V22_VERIFY_PATH,
)
LAUNCH_RUNTIME_BROKER_V22_ARGUMENTS = (
    WORKER_PATH,
    "--macho",
    LAUNCHER_V22_PATH,
)
COPY_LAUNCHER_V22_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    LAUNCHER_V22_LOG_SOURCE,
    LAUNCHER_V22_LOG_DESTINATION,
)
COPY_RUNTIME_V22_MARKER_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    RUNTIME_MARKER_SOURCE,
    RUNTIME_V22_MARKER_DESTINATION,
)
WORKER_FRESH_DYLIB_UPLOAD_PATH = (
    "/var/mobile/Media/codex-worker-fresh-dylib-canary.dylib"
)
WORKER_FRESH_DYLIB_PATH = (
    "/var/jb/usr/lib/codex-worker-fresh-dylib-canary.dylib"
)
WORKER_FRESH_DYLIB_STDOUT_PATH = (
    "/var/mobile/Media/codex-worker-fresh-dylib-canary.stdout"
)
WORKER_FRESH_DYLIB_STDERR_PATH = (
    "/var/mobile/Media/codex-worker-fresh-dylib-canary.stderr"
)
WORKER_FRESH_DYLIB_VERIFY_PATH = (
    "/var/mobile/Media/codex-worker-fresh-dylib-canary.installed.dylib"
)
STAGE_WORKER_FRESH_DYLIB_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    WORKER_FRESH_DYLIB_UPLOAD_PATH,
    WORKER_FRESH_DYLIB_PATH,
)
COPY_WORKER_FRESH_DYLIB_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    WORKER_FRESH_DYLIB_PATH,
    WORKER_FRESH_DYLIB_VERIFY_PATH,
)
RUN_WORKER_FRESH_DYLIB_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "exec /var/jb/usr/libexec/codex-exec-worker --dylib "
    "/var/jb/usr/lib/codex-worker-fresh-dylib-canary.dylib "
    ">/var/mobile/Media/codex-worker-fresh-dylib-canary.stdout "
    "2>/var/mobile/Media/codex-worker-fresh-dylib-canary.stderr",
)
CLEANUP_WORKER_FRESH_DYLIB_ARGUMENTS = (
    RM_PATH,
    "-f",
    WORKER_FRESH_DYLIB_PATH,
)
JSC_DATA_PROBE_UPLOAD_PATH = "/var/mobile/Media/codex-jsc-data-probe"
JSC_DATA_PROBE_PATH = "/var/jb/usr/libexec/codex-jsc-data-probe"
STAGE_JSC_DATA_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    JSC_DATA_PROBE_UPLOAD_PATH,
    JSC_DATA_PROBE_PATH,
)
RUN_JSC_DATA_PROBE_ARGUMENTS = (
    WORKER_PATH,
    "--macho",
    JSC_DATA_PROBE_PATH,
)
JSC_SPRINGBOARD_PROBE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-jsc-springboard-probe"
)
JSC_SPRINGBOARD_PROBE_PATH = (
    "/var/jb/usr/libexec/codex-jsc-springboard-probe"
)
STAGE_JSC_SPRINGBOARD_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    JSC_SPRINGBOARD_PROBE_UPLOAD_PATH,
    JSC_SPRINGBOARD_PROBE_PATH,
)
DONOR_REMAP_PAGE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-donor-remap-page.bin"
)
DONOR_REMAP_PAGE_PATH = (
    "/var/jb/usr/share/codex-donor-remap-page.bin"
)
STAGE_DONOR_REMAP_PAGE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    DONOR_REMAP_PAGE_UPLOAD_PATH,
    DONOR_REMAP_PAGE_PATH,
)
LAUNCH_DONOR_REMAP_PAGE_ARGUMENTS = (
    WORKER_PATH,
    "--raw",
    DONOR_REMAP_PAGE_PATH,
)
DONOR_REMAP_HOST_UPLOAD_PATH = (
    "/var/mobile/Media/codex-donor-remap-host"
)
DONOR_REMAP_HOST_PATH = (
    "/var/jb/usr/libexec/codex-donor-remap-host"
)
STAGE_DONOR_REMAP_HOST_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    DONOR_REMAP_HOST_UPLOAD_PATH,
    DONOR_REMAP_HOST_PATH,
)
LAUNCH_DONOR_REMAP_HOST_ARGUMENTS = (
    WORKER_PATH,
    "--macho",
    DONOR_REMAP_HOST_PATH,
)
SPRINGBOARD_COPY_UPLOAD_PATH = "/var/mobile/Media/codex-sb-test"
SPRINGBOARD_COPY_PATH = "/var/jb/usr/libexec/codex-sb-test"
STAGE_SPRINGBOARD_COPY_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    SPRINGBOARD_COPY_UPLOAD_PATH,
    SPRINGBOARD_COPY_PATH,
)
SPRINGBOARD_COPY_SPAWN_PROBE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-sb-copy-spawn-probe"
)
SPRINGBOARD_COPY_SPAWN_PROBE_PATH = (
    "/var/jb/usr/libexec/codex-sb-copy-spawn-probe"
)
STAGE_SPRINGBOARD_COPY_SPAWN_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    SPRINGBOARD_COPY_SPAWN_PROBE_UPLOAD_PATH,
    SPRINGBOARD_COPY_SPAWN_PROBE_PATH,
)
SPRINGBOARD_CANDIDATE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-springboard-candidate"
)
SPRINGBOARD_CANDIDATE_PATH = (
    "/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard"
)
STAGE_SPRINGBOARD_CANDIDATE_ARGUMENTS = (
    INSTALL_PATH,
    "-D",
    "-m",
    "0755",
    SPRINGBOARD_CANDIDATE_UPLOAD_PATH,
    SPRINGBOARD_CANDIDATE_PATH,
)
SPRINGBOARD_CANDIDATE_VERIFY_PATH = (
    "/var/mobile/Media/codex-springboard-candidate-installed"
)
COPY_SPRINGBOARD_CANDIDATE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_CANDIDATE_PATH,
    SPRINGBOARD_CANDIDATE_VERIFY_PATH,
)
SPRINGBOARD_CANDIDATE_BUNDLE_PATH = (
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard"
)
SPRINGBOARD_CANDIDATE_BUNDLE_INFO_PATH = (
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/Info.plist"
)
STAGE_SPRINGBOARD_CANDIDATE_BUNDLE_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "set -eu; umask 022; "
    "/var/jb/usr/bin/install -D -m 0644 "
    "/var/mobile/Media/SpringBoard-24A437-Info.plist "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/Info.plist; "
    "exec /var/jb/usr/bin/install -D -m 0755 "
    "/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard",
)
SPRINGBOARD_CANDIDATE_BUNDLE_VERIFY_PATH = (
    "/var/mobile/Media/codex-springboard-candidate-bundle-installed"
)
SPRINGBOARD_CANDIDATE_BUNDLE_INFO_VERIFY_PATH = (
    "/var/mobile/Media/SpringBoard-24A437-Info-installed.plist"
)
COPY_SPRINGBOARD_CANDIDATE_BUNDLE_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "set -eu; umask 022; "
    "/var/jb/usr/bin/install -m 0644 "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard "
    "/var/mobile/Media/codex-springboard-candidate-bundle-installed; "
    "exec /var/jb/usr/bin/install -m 0644 "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/Info.plist "
    "/var/mobile/Media/SpringBoard-24A437-Info-installed.plist",
)
RUNTIME_TRUST_PATH = "/var/jb/usr/libexec/codex-runtime-trust"
SPRINGBOARD_CANDIDATE_TRUST_LOG_SOURCE = (
    "/var/jb/var/log/codex-springboard-candidate-runtime-trust.log"
)
SPRINGBOARD_CANDIDATE_TRUST_LOG_PATH = (
    "/var/mobile/Media/codex-springboard-candidate-runtime-trust.log"
)
TRUST_SPRINGBOARD_CANDIDATE_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "umask 077; "
    "exec /var/jb/usr/libexec/codex-runtime-trust trust "
    "/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard "
    ">/var/jb/var/log/codex-springboard-candidate-runtime-trust.log 2>&1",
)
COPY_SPRINGBOARD_CANDIDATE_TRUST_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_CANDIDATE_TRUST_LOG_SOURCE,
    SPRINGBOARD_CANDIDATE_TRUST_LOG_PATH,
)
SPRINGBOARD_CANDIDATE_PROBE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-springboard-candidate-admission-probe"
)
SPRINGBOARD_CANDIDATE_PROBE_PATH = (
    "/var/jb/usr/libexec/codex-springboard-candidate-admission-probe"
)
STAGE_SPRINGBOARD_CANDIDATE_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    SPRINGBOARD_CANDIDATE_PROBE_UPLOAD_PATH,
    SPRINGBOARD_CANDIDATE_PROBE_PATH,
)
SPRINGBOARD_CANDIDATE_PROBE_VERIFY_PATH = (
    "/var/mobile/Media/codex-springboard-candidate-admission-probe-installed"
)
COPY_SPRINGBOARD_CANDIDATE_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_CANDIDATE_PROBE_PATH,
    SPRINGBOARD_CANDIDATE_PROBE_VERIFY_PATH,
)
SPRINGBOARD_CANDIDATE_PROBE_REPORT_PATH = (
    "/private/var/mobile/Media/"
    "codex-springboard-candidate-admission-probe.txt"
)
SPRINGBOARD_CANDIDATE_PROBE_REPORT_EXPORT_PATH = (
    "/var/mobile/Media/"
    "codex-springboard-candidate-admission-probe-export.txt"
)
ELLEKIT_LOADER_CANDIDATE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-ellekit-loader-candidate"
)
ELLEKIT_LOADER_CANDIDATE_PATH = (
    "/var/jb/usr/libexec/codex-ellekit-loader-candidate"
)
STAGE_ELLEKIT_LOADER_CANDIDATE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    ELLEKIT_LOADER_CANDIDATE_UPLOAD_PATH,
    ELLEKIT_LOADER_CANDIDATE_PATH,
)
ELLEKIT_LOADER_CANDIDATE_VERIFY_PATH = (
    "/var/mobile/Media/codex-ellekit-loader-candidate-installed"
)
COPY_ELLEKIT_LOADER_CANDIDATE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    ELLEKIT_LOADER_CANDIDATE_PATH,
    ELLEKIT_LOADER_CANDIDATE_VERIFY_PATH,
)
COPY_SPRINGBOARD_CANDIDATE_PROBE_REPORT_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_CANDIDATE_PROBE_REPORT_PATH,
    SPRINGBOARD_CANDIDATE_PROBE_REPORT_EXPORT_PATH,
)
SPRINGBOARD_DIRECT_PROOF_LOG_SOURCE = (
    "/var/tmp/codex-springboard-direct-pre-main-proof.log"
)
SPRINGBOARD_DIRECT_PROOF_LOG_EXPORT_PATH = (
    "/var/mobile/Media/codex-springboard-direct-pre-main-proof.log"
)
COPY_SPRINGBOARD_DIRECT_PROOF_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_DIRECT_PROOF_LOG_SOURCE,
    SPRINGBOARD_DIRECT_PROOF_LOG_EXPORT_PATH,
)
SPRINGBOARD_DIRECT_WRAPPER_LOG_SOURCE = (
    "/var/jb/var/log/codex-springboard-direct-wrapper.log"
)
SPRINGBOARD_DIRECT_WRAPPER_LOG_EXPORT_PATH = (
    "/var/mobile/Media/codex-springboard-direct-wrapper.log"
)
COPY_SPRINGBOARD_DIRECT_WRAPPER_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_DIRECT_WRAPPER_LOG_SOURCE,
    SPRINGBOARD_DIRECT_WRAPPER_LOG_EXPORT_PATH,
)
DYLD_JB_ADMISSION_HOOK_UPLOAD_PATH = (
    "/var/mobile/Media/codex-dyld-jb-admission-hook.dylib"
)
DYLD_JB_ADMISSION_HOOK_PATH = (
    "/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib"
)
STAGE_DYLD_JB_ADMISSION_HOOK_ARGUMENTS = (
    INSTALL_PATH,
    "-D",
    "-m",
    "0644",
    DYLD_JB_ADMISSION_HOOK_UPLOAD_PATH,
    DYLD_JB_ADMISSION_HOOK_PATH,
)
DYLD_JB_ADMISSION_HOOK_VERIFY_PATH = (
    "/var/mobile/Media/codex-dyld-jb-admission-hook-installed.dylib"
)
COPY_DYLD_JB_ADMISSION_HOOK_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    DYLD_JB_ADMISSION_HOOK_PATH,
    DYLD_JB_ADMISSION_HOOK_VERIFY_PATH,
)
DYLD_JB_ADMISSION_HOOK_TRUST_LOG_SOURCE = (
    "/var/jb/var/log/codex-dyld-jb-admission-hook-runtime-trust.log"
)
DYLD_JB_ADMISSION_HOOK_TRUST_LOG_PATH = (
    "/var/mobile/Media/"
    "codex-dyld-jb-admission-hook-runtime-trust.log"
)
TRUST_DYLD_JB_ADMISSION_HOOK_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "umask 077; "
    "exec /var/jb/usr/libexec/codex-runtime-trust trust "
    "/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib "
    ">/var/jb/var/log/"
    "codex-dyld-jb-admission-hook-runtime-trust.log 2>&1",
)
COPY_DYLD_JB_ADMISSION_HOOK_TRUST_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    DYLD_JB_ADMISSION_HOOK_TRUST_LOG_SOURCE,
    DYLD_JB_ADMISSION_HOOK_TRUST_LOG_PATH,
)
DYLD_JB_ADMISSION_HOOK_STATUS_SOURCE = (
    "/var/jb/var/run/codex-dyld-jb-admission-hook.status"
)
DYLD_JB_ADMISSION_HOOK_STATUS_PATH = (
    "/var/mobile/Media/codex-dyld-jb-admission-hook.status"
)
COPY_DYLD_JB_ADMISSION_HOOK_STATUS_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    DYLD_JB_ADMISSION_HOOK_STATUS_SOURCE,
    DYLD_JB_ADMISSION_HOOK_STATUS_PATH,
)
SPRINGBOARD_LIVE_PRECURSOR_UPLOAD_PATH = (
    "/var/mobile/Media/codex-springboard-live-precursor"
)
SPRINGBOARD_LIVE_PRECURSOR_PATH = (
    "/var/jb/usr/libexec/codex-springboard-live-precursor"
)
SPRINGBOARD_LIVE_CANARY_UPLOAD_PATH = (
    "/var/mobile/Media/codex-springboard-live-canary.dylib"
)
SPRINGBOARD_LIVE_CANARY_PATH = (
    "/var/jb/usr/lib/codex-springboard-live-canary.dylib"
)
STAGE_SPRINGBOARD_LIVE_CANARY_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_LIVE_CANARY_UPLOAD_PATH,
    SPRINGBOARD_LIVE_CANARY_PATH,
)
SPRINGBOARD_LIVE_CANARY_BACKUP_PATH = (
    "/var/mobile/Media/codex-springboard-live-canary.pre-direct-backup.dylib"
)
COPY_SPRINGBOARD_LIVE_CANARY_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_LIVE_CANARY_PATH,
    SPRINGBOARD_LIVE_CANARY_BACKUP_PATH,
)
STAGE_SPRINGBOARD_LIVE_PRECURSOR_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    SPRINGBOARD_LIVE_PRECURSOR_UPLOAD_PATH,
    SPRINGBOARD_LIVE_PRECURSOR_PATH,
)
SPRINGBOARD_LIVE_PRECURSOR_VERIFY_PATH = (
    "/var/mobile/Media/codex-springboard-live-precursor-installed"
)
COPY_SPRINGBOARD_LIVE_PRECURSOR_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_LIVE_PRECURSOR_PATH,
    SPRINGBOARD_LIVE_PRECURSOR_VERIFY_PATH,
)
RUN_SPRINGBOARD_WATCHDOG_ARM_TEST_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "exec /var/jb/usr/libexec/codex-exec-worker --macho "
    "/var/jb/usr/libexec/codex-springboard-live-precursor "
    "--watchdog-arm-test "
    ">/var/mobile/Media/codex-springboard-watchdog-arm-test.txt 2>&1",
)
RUN_SPRINGBOARD_LIVE_PRECURSOR_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "exec /var/jb/usr/libexec/codex-exec-worker --macho "
    "/var/jb/usr/libexec/codex-springboard-live-precursor "
    "--first-live-precursor "
    ">/var/mobile/Media/codex-springboard-live-precursor-run.txt 2>&1",
)
SPRINGBOARD_CANDIDATE_SERVICE_PLIST_UPLOAD_PATH = (
    "/var/mobile/Media/com.apple.SpringBoard.candidate.plist"
)
SPRINGBOARD_CANDIDATE_SERVICE_PLIST_PATH = (
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "com.apple.SpringBoard.candidate.plist"
)
STAGE_SPRINGBOARD_CANDIDATE_SERVICE_PLIST_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_CANDIDATE_SERVICE_PLIST_UPLOAD_PATH,
    SPRINGBOARD_CANDIDATE_SERVICE_PLIST_PATH,
)
SPRINGBOARD_CANDIDATE_SERVICE_PLIST_VERIFY_PATH = (
    "/var/mobile/Media/com.apple.SpringBoard.candidate.installed.plist"
)
COPY_SPRINGBOARD_CANDIDATE_SERVICE_PLIST_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_CANDIDATE_SERVICE_PLIST_PATH,
    SPRINGBOARD_CANDIDATE_SERVICE_PLIST_VERIFY_PATH,
)
RUN_SPRINGBOARD_EXTERNAL_LIVE_PROOF_ARGUMENTS = (
    "/var/jb/usr/bin/dash",
    "-c",
    "umask 077; "
    "exec >/var/mobile/Media/codex-springboard-external-live-proof.txt 2>&1; "
    "exec /var/jb/usr/libexec/codex-exec-worker --macho "
    "/var/jb/usr/libexec/codex-springboard-live-precursor "
    "--external-live-proof",
)
RUN_SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_ARGUMENTS = (
    "/var/jb/usr/bin/dash",
    "-c",
    "umask 077; "
    "exec >/var/mobile/Media/"
    "codex-springboard-external-parallel-bind-audit.txt 2>&1; "
    "exec /var/jb/usr/libexec/codex-exec-worker --macho "
    "/var/jb/usr/libexec/codex-springboard-live-precursor "
    "--external-parallel-bind-audit",
)
RUN_SPRINGBOARD_EXTERNAL_PARALLEL_LIVE_PROOF_ARGUMENTS = (
    "/var/jb/usr/libexec/codex-exec-worker",
    "--macho",
    "/var/jb/usr/libexec/codex-springboard-live-precursor",
    "--external-parallel-live-proof",
)
SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_LOG_SOURCE = (
    "/var/mobile/Media/codex-springboard-external-parallel-bind-audit.txt"
)
SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_LOG_PATH = (
    "/var/mobile/Media/"
    "codex-springboard-external-parallel-bind-audit-export.txt"
)
COPY_SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_LOG_SOURCE,
    SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_LOG_PATH,
)
CAPTURE_SPRINGBOARD_EXTERNAL_CANDIDATE_PRINT_ARGUMENTS = (
    "/var/jb/usr/bin/dash",
    "-c",
    "umask 022; exec /var/jb/usr/bin/launchctl print "
    "user/501/com.openai.codex.springboard-live-candidate "
    ">/var/mobile/Media/codex-springboard-external-candidate-print.txt 2>&1",
)
RUN_SPRINGBOARD_EXTERNAL_SERVICE_REMOVAL_AUDIT_ARGUMENTS = (
    "/var/jb/usr/bin/dash",
    "-c",
    "umask 022; "
    "exec >/var/mobile/Media/"
    "codex-springboard-external-service-removal-audit.txt 2>&1; "
    "exec /var/jb/usr/libexec/codex-exec-worker --macho "
    "/var/jb/usr/libexec/codex-springboard-live-precursor "
    "--external-service-removal-audit",
)
SPRINGBOARD_EXTERNAL_LIVE_PROOF_LOG_SOURCE = (
    "/var/mobile/Media/codex-springboard-external-live-proof.txt"
)
SPRINGBOARD_EXTERNAL_LIVE_PROOF_LOG_PATH = (
    "/var/mobile/Media/codex-springboard-external-live-proof-export.txt"
)
COPY_SPRINGBOARD_EXTERNAL_LIVE_PROOF_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_EXTERNAL_LIVE_PROOF_LOG_SOURCE,
    SPRINGBOARD_EXTERNAL_LIVE_PROOF_LOG_PATH,
)
CAPTURE_LAUNCHCTL_DEBUG_HELP_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "/var/jb/usr/bin/launchctl help debug "
    ">/var/mobile/Media/codex-launchctl-debug-help.txt 2>&1; exit 0",
)
APPLE_LAUNCHCTL_UPLOAD_PATH = "/var/mobile/Media/codex-apple-launchctl"
APPLE_LAUNCHCTL_PATH = "/var/jb/usr/libexec/codex-apple-launchctl"
APPLE_LAUNCHCTL_VERIFY_PATH = (
    "/var/mobile/Media/codex-apple-launchctl-installed"
)
STAGE_APPLE_LAUNCHCTL_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    APPLE_LAUNCHCTL_UPLOAD_PATH,
    APPLE_LAUNCHCTL_PATH,
)
COPY_APPLE_LAUNCHCTL_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    APPLE_LAUNCHCTL_PATH,
    APPLE_LAUNCHCTL_VERIFY_PATH,
)
CAPTURE_APPLE_LAUNCHCTL_DEBUG_HELP_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "exec /var/jb/usr/libexec/codex-apple-launchctl help debug "
    ">/var/mobile/Media/codex-apple-launchctl-debug-help.txt 2>&1",
)
CAPTURE_SYSTEM_LAUNCHCTL_PATHS_ARGUMENTS = (
    "/var/jb/usr/bin/dash",
    "-c",
    "umask 022; out=/var/mobile/Media/codex-system-launchctl-paths.txt; "
    ": >\"$out\"; "
    "for p in /bin/launchctl /usr/bin/launchctl /usr/libexec/launchctl "
    "/System/Cryptexes/OS/bin/launchctl "
    "/System/Cryptexes/OS/usr/bin/launchctl "
    "/System/Cryptexes/OS/usr/libexec/launchctl "
    "/System/Library/CoreServices/launchctl; do "
    "if [ -e \"$p\" ]; then "
    "if [ -x \"$p\" ]; then state=executable; else state=present; fi; "
    "echo \"$p $state\" >>\"$out\"; "
    "\"$p\" help debug >>\"$out\" 2>&1; "
    "echo \"status=$? path=$p\" >>\"$out\"; "
    "else echo \"$p absent\" >>\"$out\"; fi; done; "
    "chmod 0644 \"$out\"",
)
SPRINGBOARD_LIVE_PRECURSOR_LOG_SOURCE = (
    "/var/jb/var/log/codex-springboard-live-precursor.log"
)
SPRINGBOARD_LIVE_PRECURSOR_LOG_PATH = (
    "/var/mobile/Media/codex-springboard-live-precursor.log"
)
COPY_SPRINGBOARD_LIVE_PRECURSOR_LOG_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    SPRINGBOARD_LIVE_PRECURSOR_LOG_SOURCE,
    SPRINGBOARD_LIVE_PRECURSOR_LOG_PATH,
)
DYLD_INTERPOSE_PROBE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-dyld-interpose-probe"
)
DYLD_INTERPOSE_PROBE_PATH = (
    "/var/jb/usr/libexec/codex-dyld-interpose-probe"
)
STAGE_DYLD_INTERPOSE_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    DYLD_INTERPOSE_PROBE_UPLOAD_PATH,
    DYLD_INTERPOSE_PROBE_PATH,
)
RUN_DYLD_INTERPOSE_PROBE_ARGUMENTS = (
    WORKER_PATH,
    "--macho",
    DYLD_INTERPOSE_PROBE_PATH,
)
DTRACE_PRESENCE_PROBE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-dtrace-presence-probe"
)
DTRACE_PRESENCE_PROBE_PATH = (
    "/var/jb/usr/libexec/codex-dtrace-presence-probe"
)
STAGE_DTRACE_PRESENCE_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    DTRACE_PRESENCE_PROBE_UPLOAD_PATH,
    DTRACE_PRESENCE_PROBE_PATH,
)
RUN_DTRACE_PRESENCE_PROBE_ARGUMENTS = (
    WORKER_PATH,
    "--macho",
    DTRACE_PRESENCE_PROBE_PATH,
)
CRYPTEX_MOUNT_TOPOLOGY_PROBE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-cryptex-mount-topology-probe"
)
CRYPTEX_MOUNT_TOPOLOGY_PROBE_PATH = (
    "/var/jb/usr/libexec/codex-cryptex-mount-topology-probe"
)
STAGE_CRYPTEX_MOUNT_TOPOLOGY_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    CRYPTEX_MOUNT_TOPOLOGY_PROBE_UPLOAD_PATH,
    CRYPTEX_MOUNT_TOPOLOGY_PROBE_PATH,
)
RUN_CRYPTEX_MOUNT_TOPOLOGY_PROBE_ARGUMENTS = (
    WORKER_PATH,
    "--macho",
    CRYPTEX_MOUNT_TOPOLOGY_PROBE_PATH,
)
AMFID_ADMISSION_CANARY_UPLOAD_PATH = (
    "/var/mobile/Media/codex-amfid-admission-canary"
)
AMFID_ADMISSION_CANARY_PATH = (
    "/var/jb/usr/libexec/codex-amfid-admission-canary"
)
STAGE_AMFID_ADMISSION_CANARY_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    AMFID_ADMISSION_CANARY_UPLOAD_PATH,
    AMFID_ADMISSION_CANARY_PATH,
)
RUN_AMFID_ADMISSION_CANARY_ARGUMENTS = (AMFID_ADMISSION_CANARY_PATH,)
SPRINGBOARD_CSOPS_STATUS_PROBE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-springboard-csops-status-probe"
)
SPRINGBOARD_CSOPS_STATUS_PROBE_PATH = (
    "/var/jb/usr/libexec/codex-springboard-csops-status-probe"
)
STAGE_SPRINGBOARD_CSOPS_STATUS_PROBE_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    SPRINGBOARD_CSOPS_STATUS_PROBE_UPLOAD_PATH,
    SPRINGBOARD_CSOPS_STATUS_PROBE_PATH,
)
LAUNCHCTL_PATH = "/var/jb/usr/bin/launchctl"
AMFID_LAUNCH_SERVICE = "system/com.apple.MobileFileIntegrity"
KICKSTART_AMFID_ARGUMENTS = (
    LAUNCHCTL_PATH,
    "kickstart",
    AMFID_LAUNCH_SERVICE,
)
LAUNCH_TYPE_CANARY_COPY_PATH = (
    "/var/jb/usr/libexec/codex-xpcproxy-launch-canary"
)
LAUNCH_TYPE_CANARY_PLIST_UPLOAD_PATH = (
    "/var/mobile/Media/com.openai.codex.launch-type-canary.plist"
)
LAUNCH_TYPE_CANARY_PLIST_PATH = (
    "/var/jb/Library/LaunchDaemons/com.openai.codex.launch-type-canary.plist"
)
LAUNCH_TYPE_CANARY_SERVICE = "user/501/com.openai.codex.launch-type-canary"
STAGE_LAUNCH_TYPE_CANARY_COPY_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0755",
    "/usr/libexec/xpcproxy",
    LAUNCH_TYPE_CANARY_COPY_PATH,
)
STAGE_LAUNCH_TYPE_CANARY_PLIST_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    LAUNCH_TYPE_CANARY_PLIST_UPLOAD_PATH,
    LAUNCH_TYPE_CANARY_PLIST_PATH,
)
BOOTSTRAP_LAUNCH_TYPE_CANARY_ARGUMENTS = (
    LAUNCHCTL_PATH,
    "bootstrap",
    "system",
    LAUNCH_TYPE_CANARY_PLIST_PATH,
)
BOOTOUT_LAUNCH_TYPE_CANARY_ARGUMENTS = (
    LAUNCHCTL_PATH,
    "bootout",
    LAUNCH_TYPE_CANARY_SERVICE,
)
LAUNCH_TYPE_CANARY_PRINT_PATH = (
    "/var/mobile/Media/codex-launch-type-canary-print.txt"
)
PRINT_LAUNCH_TYPE_CANARY_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "exec /var/jb/usr/bin/launchctl print "
    "user/501/com.openai.codex.launch-type-canary "
    ">/var/mobile/Media/codex-launch-type-canary-print.txt 2>&1",
)
SPRINGBOARD_LAUNCH_SERVICE = "user/501/com.apple.SpringBoard"
SPRINGBOARD_LAUNCH_PRINT_PATH = (
    "/var/mobile/Media/codex-springboard-launch-print.txt"
)
PRINT_SPRINGBOARD_LAUNCH_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "exec /var/jb/usr/bin/launchctl print "
    "user/501/com.apple.SpringBoard "
    ">/var/mobile/Media/codex-springboard-launch-print.txt 2>&1",
)
KICKSTART_LAUNCH_TYPE_CANARY_ARGUMENTS = (
    LAUNCHCTL_PATH,
    "kickstart",
    LAUNCH_TYPE_CANARY_SERVICE,
)
SEALED_SPRINGBOARD_JOB_LABEL = (
    "com.openai.codex.springboard-sealed-admission-24a437"
)
SEALED_SPRINGBOARD_JOB_SERVICE = (
    f"user/501/{SEALED_SPRINGBOARD_JOB_LABEL}"
)
SEALED_SPRINGBOARD_JOB_PRINT_PATH = (
    "/var/mobile/Media/"
    "codex-springboard-sealed-admission-24a437-print.txt"
)
PRINT_SEALED_SPRINGBOARD_JOB_ARGUMENTS = (
    "/var/jb/usr/bin/dash",
    "-c",
    "umask 022; exec /var/jb/usr/bin/launchctl print "
    f"{SEALED_SPRINGBOARD_JOB_SERVICE} "
    f">{SEALED_SPRINGBOARD_JOB_PRINT_PATH} 2>&1",
)
SEALED_SPRINGBOARD_JOB_PID_PATH = (
    "/var/mobile/Media/"
    "codex-springboard-sealed-admission-24a437-pid.txt"
)
SEALED_SPRINGBOARD_JOB_KICKSTART_ERROR_PATH = (
    "/var/mobile/Media/"
    "codex-springboard-sealed-admission-24a437-kickstart.stderr.txt"
)
KICKSTART_SEALED_SPRINGBOARD_JOB_ARGUMENTS = (
    "/var/jb/usr/bin/dash",
    "-c",
    "umask 022; "
    f"codex_pid_path={SEALED_SPRINGBOARD_JOB_PID_PATH}; "
    f"codex_error_path={SEALED_SPRINGBOARD_JOB_KICKSTART_ERROR_PATH}; "
    ': >"$codex_pid_path"; : >"$codex_error_path"; '
    "codex_pid=$(/var/jb/usr/bin/launchctl kickstart -p -s "
    f"{SEALED_SPRINGBOARD_JOB_SERVICE} 2>\"$codex_error_path\"); "
    "codex_status=$?; "
    'if [ "$codex_status" -ne 0 ]; then exit "$codex_status"; fi; '
    'case "$codex_pid" in \'\'|*[!0-9]*) '
    "printf 'invalid-kickstart-pid=%s\\n' \"$codex_pid\" "
    '>>"$codex_error_path"; exit 65;; esac; '
    'if [ "$codex_pid" -eq 0 ]; then '
    'printf \'0\\n\' >"$codex_pid_path"; exit 0; fi; '
    'if [ "$codex_pid" -le 1 ]; then '
    "printf 'invalid-kickstart-pid=%s\\n' \"$codex_pid\" "
    '>>"$codex_error_path"; exit 65; fi; '
    "printf '%s\\n' \"$codex_pid\" >\"$codex_pid_path\"",
)
BOOTOUT_SEALED_SPRINGBOARD_JOB_ARGUMENTS = (
    LAUNCHCTL_PATH,
    "bootout",
    SEALED_SPRINGBOARD_JOB_SERVICE,
)
SYSTEM_LAUNCHD_ARTIFACT_PATH = (
    "/var/mobile/Media/codex-launchd-24A437"
)
COPY_SYSTEM_LAUNCHD_ARTIFACT_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    "/sbin/launchd",
    SYSTEM_LAUNCHD_ARTIFACT_PATH,
)
SYSTEM_CRYPTEXD_ARTIFACT_PATH = (
    "/var/mobile/Media/codex-cryptexd-24A437"
)
COPY_SYSTEM_CRYPTEXD_ARTIFACT_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    "/usr/libexec/cryptexd",
    SYSTEM_CRYPTEXD_ARTIFACT_PATH,
)
SYSTEM_DYLD_ARTIFACT_PATH = "/var/mobile/Media/codex-dyld-24A437"
COPY_SYSTEM_DYLD_ARTIFACT_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    "/usr/lib/dyld",
    SYSTEM_DYLD_ARTIFACT_PATH,
)
SYSTEM_SPRINGBOARD_PLIST_ARTIFACT_PATH = (
    "/var/mobile/Media/com.apple.SpringBoard.24A437.plist"
)
COPY_SYSTEM_SPRINGBOARD_PLIST_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    "/System/Library/LaunchDaemons/com.apple.SpringBoard.plist",
    SYSTEM_SPRINGBOARD_PLIST_ARTIFACT_PATH,
)
SYSTEM_SPRINGBOARD_INFO_ARTIFACT_PATH = (
    "/var/mobile/Media/SpringBoard-24A437-Info.plist"
)
COPY_SYSTEM_SPRINGBOARD_INFO_ARGUMENTS = (
    INSTALL_PATH,
    "-m",
    "0644",
    "/System/Library/CoreServices/SpringBoard.app/Info.plist",
    SYSTEM_SPRINGBOARD_INFO_ARTIFACT_PATH,
)
SYSTEM_SPRINGBOARD_BUNDLE_MANIFEST_PATH = (
    "/var/mobile/Media/SpringBoard-24A437-live-bundle-manifest.txt"
)
COPY_SYSTEM_SPRINGBOARD_BUNDLE_MANIFEST_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "set -eu; umask 077; "
    "cd /System/Library/CoreServices/SpringBoard.app; "
    "{ /var/jb/usr/bin/find . -xdev "
    "-printf '%y|%s|%m|%U|%G|%p|%l\\n' | "
    "/var/jb/usr/bin/sort; "
    "/var/jb/usr/bin/find . -xdev -type f "
    "-exec /var/jb/usr/bin/sha256sum '{}' ';' | "
    "/var/jb/usr/bin/sort; } "
    ">/var/mobile/Media/"
    "SpringBoard-24A437-live-bundle-manifest.txt; "
    "/var/jb/usr/bin/chmod 0644 /var/mobile/Media/"
    "SpringBoard-24A437-live-bundle-manifest.txt",
)
CLONE_SPRINGBOARD_CANDIDATE_BUNDLE_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "set -eu; umask 022; "
    "/var/jb/usr/bin/mkdir -p "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app; "
    "/var/jb/usr/bin/cp -a "
    "/System/Library/CoreServices/SpringBoard.app/. "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/; "
    "/var/jb/usr/bin/install -m 0644 "
    "/var/mobile/Media/SpringBoard-24A437-Info.plist "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/Info.plist; "
    "exec /var/jb/usr/bin/install -m 0755 "
    "/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard "
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard",
)
SPRINGBOARD_CANDIDATE_BUNDLE_MANIFEST_PATH = (
    "/var/mobile/Media/SpringBoard-24A437-candidate-bundle-manifest.txt"
)
COPY_SPRINGBOARD_CANDIDATE_BUNDLE_MANIFEST_ARGUMENTS = (
    "/var/jb/usr/bin/sh",
    "-c",
    "set -eu; umask 077; "
    "cd /var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app; "
    "{ /var/jb/usr/bin/find . -xdev "
    "-printf '%y|%s|%m|%U|%G|%p|%l\\n' | "
    "/var/jb/usr/bin/sort; "
    "/var/jb/usr/bin/find . -xdev -type f "
    "-exec /var/jb/usr/bin/sha256sum '{}' ';' | "
    "/var/jb/usr/bin/sort; } "
    ">/var/mobile/Media/"
    "SpringBoard-24A437-candidate-bundle-manifest.txt; "
    "/var/jb/usr/bin/chmod 0644 /var/mobile/Media/"
    "SpringBoard-24A437-candidate-bundle-manifest.txt",
)

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 2
MH_EXECUTE = 2
LC_UUID = 0x1B
LC_SEGMENT_64 = 0x19

EXPECTED_CARRIER_UUID = uuid.UUID("DB09BB43-F28E-3E2D-B497-9506C50D1502")
EXPECTED_RUNTIME_CARRIER_UUID = uuid.UUID(
    "55BCB295-6F34-37F5-B171-9E613A0D2D5F"
)
RECOVERY_RUNTIME_CARRIER_UUID = uuid.UUID(
    "F3510CC6-524E-3C8F-8541-7F8DEEC78FE6"
)
# The resident carrier parks in the exact two-instruction tail of the
# installed remote blob.  An asynchronous attach may stop on either the WFE
# or its backwards branch, so bind the validator to the complete loop rather
# than to only one sampling point within it.
EXPECTED_SPIN_LOOP = bytes.fromhex("5f2003d5ffffff17")
EXPECTED_SPIN_WFE = EXPECTED_SPIN_LOOP[:4]
EXPECTED_SPIN_BRANCH = EXPECTED_SPIN_LOOP[4:]
POSIX_SPAWN_STUB_OFFSET = 0xB388
EXPECTED_POSIX_SPAWN_STUB = bytes.fromhex(
    "510000b031620d91300240f9110a1fd7"
)
MACH_PORT_DEALLOCATE_STUB_OFFSET = 0xB278
EXPECTED_MACH_PORT_DEALLOCATE_STUB = bytes.fromhex(
    "510000b031a20b91300240f9110a1fd7"
)
POSIX_SPAWNATTR_DESTROY_STUB_OFFSET = 0xB398
EXPECTED_POSIX_SPAWNATTR_DESTROY_STUB = bytes.fromhex(
    "510000b031820d91300240f9110a1fd7"
)
POSIX_SPAWNATTR_INIT_STUB_OFFSET = 0xB3A8
EXPECTED_POSIX_SPAWNATTR_INIT_STUB = bytes.fromhex(
    "510000b031a20d91300240f9110a1fd7"
)
POSIX_SPAWNATTR_SET_PTRAUTH_STUB_OFFSET = 0xB3B8
EXPECTED_POSIX_SPAWNATTR_SET_PTRAUTH_STUB = bytes.fromhex(
    "510000b031c20d91300240f9110a1fd7"
)
PROC_PIDPATH_STUB_OFFSET = 0xB3D8
EXPECTED_PROC_PIDPATH_STUB = bytes.fromhex(
    "510000b031020e91300240f9110a1fd7"
)
TASK_FOR_PID_STUB_OFFSET = 0xB4A8
EXPECTED_TASK_FOR_PID_STUB = bytes.fromhex(
    "510000b031a20f91300240f9110a1fd7"
)
WAITPID_STUB_OFFSET = 0xB5D8
EXPECTED_WAITPID_STUB = bytes.fromhex(
    "510000b031021291300240f9110a1fd7"
)
MACH_TASK_SELF_GOT_OFFSET = 0x144D0
POSIX_SPAWN_START_SUSPENDED = 0x0080
SPRINGBOARD_PATH = "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
CRYPTEXD_PATH = "/usr/libexec/cryptexd"
AMFID_PATH = "/usr/libexec/amfid"
PTRAUTH_CHILD_PATH_BUFFER_OFFSET = 0x400
PTRAUTH_CHILD_PATH_BUFFER_SIZE = 0x400
PTRAUTH_CHILD_ATTR_STORAGE_OFFSET = 0x900
PTRAUTH_CHILD_TASK_STORAGE_OFFSET = 0x908
PTRAUTH_CHILD_STATUS_STORAGE_OFFSET = 0x910
RUNTIME_REMOTE_BLOB_SIZE = 0x230
RUNTIME_REMOTE_BLOB_PREFIX = bytes.fromhex(
    "df2403d5900280d2011000d4210280d2b00480d2011000d4"
)
MAX_RUNTIME_EXECUTABLE_SCAN = 4 * 1024 * 1024

SCRATCH_SIZE = 0x1000
MAX_LOAD_COMMANDS = 512
MAX_LOAD_COMMAND_BYTES = 0x10000
MEMORY_CHUNK = 0x400


class ProtocolError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument(
        "--userspace-udid",
        help=(
            "establish a no-root in-process USB tunnel for this UDID; "
            "host and port are ignored"
        ),
    )
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=30.0)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--validate-only",
        action="store_true",
        help="verify the carrier identity and detach without mutation",
    )
    mode.add_argument(
        "--inspect-runtime-blob",
        action="store_true",
        help="verify the fixed trusted remote-code blob in resident memory",
    )
    mode.add_argument(
        "--allocation-cycle",
        action="store_true",
        help="allocate, verify, and deallocate one RW scratch page",
    )
    mode.add_argument(
        "--self-test",
        action="store_true",
        help="spawn only codex-exec-worker --self-test",
    )
    mode.add_argument(
        "--copy-broker-log",
        action="store_true",
        help="copy only the root broker log to the fixed Media destination",
    )
    mode.add_argument(
        "--copy-live-runtime",
        action="store_true",
        help="copy only the installed runtime dylib to the fixed Media destination",
    )
    mode.add_argument(
        "--copy-live-launcher",
        action="store_true",
        help="copy only the installed carrier launcher to the fixed Media destination",
    )
    mode.add_argument(
        "--launch-runtime-broker",
        action="store_true",
        help="run only the fixed installed carrier launcher and wait for it",
    )
    mode.add_argument(
        "--copy-live-launcher-log",
        action="store_true",
        help="copy only the fixed carrier-launcher log to Media",
    )
    mode.add_argument(
        "--backup-runtime",
        action="store_true",
        help="copy the active runtime to the fixed root-owned rollback path",
    )
    mode.add_argument(
        "--stage-runtime-v21",
        action="store_true",
        help="install the fixed Media upload at the fixed non-active stage path",
    )
    mode.add_argument(
        "--copy-staged-runtime-v21",
        action="store_true",
        help="copy the fixed staged runtime back to Media for host verification",
    )
    mode.add_argument(
        "--activate-staged-runtime",
        action="store_true",
        help="atomically rename the fixed stage path over the active runtime",
    )
    mode.add_argument(
        "--stage-runtime-rollback",
        action="store_true",
        help="copy the fixed rollback runtime to the fixed non-active stage path",
    )
    mode.add_argument(
        "--stage-runtime-v22",
        action="store_true",
        help="install the fixed v22 Media upload at its versioned runtime path",
    )
    mode.add_argument(
        "--copy-runtime-v22",
        action="store_true",
        help="copy the installed v22 runtime back to Media for verification",
    )
    mode.add_argument(
        "--stage-launcher-v22",
        action="store_true",
        help="install the fixed v22 Media upload at its versioned launcher path",
    )
    mode.add_argument(
        "--copy-launcher-v22",
        action="store_true",
        help="copy the installed v22 launcher back to Media for verification",
    )
    mode.add_argument(
        "--launch-runtime-broker-v22-resident",
        action="store_true",
        help="spawn the fixed supervised v22 launcher without waiting for exit",
    )
    mode.add_argument(
        "--copy-launcher-v22-log",
        action="store_true",
        help="copy only the fixed v22 launcher log to Media",
    )
    mode.add_argument(
        "--copy-runtime-v22-marker",
        action="store_true",
        help="copy only the root runtime marker to the fixed v22 Media path",
    )
    mode.add_argument(
        "--stage-worker-fresh-dylib-canary",
        action="store_true",
        help=(
            "install only the fixed Media acceptance dylib at its fixed "
            "worker-managed path"
        ),
    )
    mode.add_argument(
        "--run-worker-fresh-dylib-canary",
        action="store_true",
        help=(
            "run codex-exec-worker --dylib on the fixed acceptance dylib "
            "with stdout and stderr captured to fixed Media paths"
        ),
    )
    mode.add_argument(
        "--copy-worker-fresh-dylib-canary",
        action="store_true",
        help=(
            "copy only the fixed staged acceptance dylib back to its fixed "
            "Media verification path"
        ),
    )
    mode.add_argument(
        "--cleanup-worker-fresh-dylib-canary",
        action="store_true",
        help="remove only the fixed staged acceptance dylib",
    )
    mode.add_argument(
        "--springboard-inspect-pid",
        metavar="PID",
        type=int,
        help="run the installed loader's read-only task-port inspection",
    )
    mode.add_argument(
        "--springboard-page-probe",
        metavar="PID",
        type=int,
        help="run the installed loader's bounded page probe on SpringBoard",
    )
    mode.add_argument(
        "--springboard-resident-hook",
        metavar="PID",
        type=int,
        help=(
            "load the fixed admission hook into SpringBoard without "
            "closing its remote dlopen handle"
        ),
    )
    mode.add_argument(
        "--springboard-resident-canary",
        metavar="PID",
        type=int,
        help=(
            "load the fixed live canary into SpringBoard without closing "
            "its remote dlopen handle"
        ),
    )
    mode.add_argument(
        "--spawn-suspended-ptrauth-loader",
        metavar="PID",
        type=int,
        help=(
            "spawn the exact trusted loader suspended with the exact "
            "SpringBoard PID's pointer-authentication task context"
        ),
    )
    mode.add_argument(
        "--spawn-suspended-ptrauth-loader-amfid",
        metavar="PID",
        type=int,
        help=(
            "spawn the exact trusted loader suspended with the exact amfid "
            "PID's pointer-authentication task context"
        ),
    )
    mode.add_argument(
        "--spawn-suspended-ptrauth-loader-cryptexd",
        metavar="PID",
        type=int,
        help=(
            "spawn the exact trusted loader suspended with the exact "
            "cryptexd PID's pointer-authentication task context"
        ),
    )
    mode.add_argument(
        "--inspect-cryptexd-task-port",
        metavar="PID",
        type=int,
        help=(
            "validate the exact cryptexd PID/path, obtain its task port with "
            "the carrier, and immediately deallocate it without mutation"
        ),
    )
    mode.add_argument(
        "--inspect-amfid-task-port",
        metavar="PID",
        type=int,
        help=(
            "validate the exact amfid PID/path, obtain its task port with "
            "the carrier, and immediately deallocate it without mutation"
        ),
    )
    mode.add_argument(
        "--reap-self-test",
        metavar="PID",
        type=int,
        help="nonblocking waitpid/reap of an exact self-test child",
    )
    mode.add_argument(
        "--resume-owned-child",
        metavar="PID",
        type=int,
        help=(
            "send SIGCONT only after waitpid proves the exact PID is a live "
            "child of the validated carrier"
        ),
    )
    mode.add_argument(
        "--terminate-owned-child",
        metavar="PID",
        type=int,
        help=(
            "after waitpid proves ownership, send SIGKILL only to the exact "
            "validated carrier child"
        ),
    )
    mode.add_argument(
        "--terminate-verified-orphan",
        metavar="PID",
        type=int,
        help=(
            "send SIGKILL to one externally path-verified orphan PID; "
            "PID 1 is always rejected"
        ),
    )
    mode.add_argument(
        "--stage-jsc-data-probe",
        action="store_true",
        help="install only the fixed Media JSC probe at its managed path",
    )
    mode.add_argument(
        "--stage-donor-remap-page",
        action="store_true",
        help=(
            "install only the fixed anonymous-page probe bytes from Media "
            "at the worker-managed path"
        ),
    )
    mode.add_argument(
        "--launch-donor-remap-page",
        action="store_true",
        help=(
            "spawn the fixed raw donor page through codex-exec-worker "
            "without waiting for the bounded remap test to finish"
        ),
    )
    mode.add_argument(
        "--stage-donor-remap-host",
        action="store_true",
        help=(
            "install only the fixed unsigned donor-page host from Media at "
            "the worker-managed path"
        ),
    )
    mode.add_argument(
        "--launch-donor-remap-host",
        action="store_true",
        help=(
            "spawn the fixed donor-page host through codex-exec-worker "
            "without waiting for its bounded remap test to finish"
        ),
    )
    mode.add_argument(
        "--stage-springboard-copy",
        action="store_true",
        help=(
            "install only the exact 24A437 SpringBoard copy from Media at "
            "the fixed non-system preflight path"
        ),
    )
    mode.add_argument(
        "--stage-springboard-copy-spawn-probe",
        action="store_true",
        help=(
            "install only the fixed unsigned copied-SpringBoard spawn probe "
            "from Media at the worker-managed path"
        ),
    )
    mode.add_argument(
        "--run-springboard-copy-spawn-probe",
        metavar="PID",
        type=int,
        help=(
            "run the bounded root spawn probe using the exact live "
            "SpringBoard PID only as an invariant"
        ),
    )
    mode.add_argument(
        "--stage-springboard-candidate",
        action="store_true",
        help="install only the fixed SpringBoard candidate from Media",
    )
    mode.add_argument(
        "--copy-springboard-candidate",
        action="store_true",
        help="copy the fixed installed SpringBoard candidate back to Media",
    )
    mode.add_argument(
        "--stage-springboard-candidate-bundle",
        action="store_true",
        help=(
            "install the already-admitted candidate and exact live Info.plist "
            "into the fixed dormant SpringBoard.app clone"
        ),
    )
    mode.add_argument(
        "--copy-springboard-candidate-bundle",
        action="store_true",
        help="copy the fixed dormant candidate bundle files back to Media",
    )
    mode.add_argument(
        "--trust-springboard-candidate",
        action="store_true",
        help=(
            "invoke the fixed runtime-trust helper once for only the fixed "
            "SpringBoard candidate and write its combined root-owned log"
        ),
    )
    mode.add_argument(
        "--copy-springboard-candidate-trust-log",
        action="store_true",
        help="copy the fixed root-owned runtime-trust log to Media",
    )
    mode.add_argument(
        "--stage-springboard-candidate-probe",
        action="store_true",
        help="install only the fixed SpringBoard candidate admission probe",
    )
    mode.add_argument(
        "--copy-springboard-candidate-probe",
        action="store_true",
        help="copy the fixed installed candidate admission probe to Media",
    )
    mode.add_argument(
        "--copy-springboard-candidate-probe-report",
        action="store_true",
        help="export the fixed root-owned candidate probe report to Media",
    )
    mode.add_argument(
        "--copy-springboard-direct-proof-log",
        action="store_true",
        help="export the root-owned direct pre-main proof log to Media",
    )
    mode.add_argument(
        "--copy-springboard-direct-wrapper-log",
        action="store_true",
        help="export the root-owned direct proof wrapper log to Media",
    )
    mode.add_argument(
        "--run-springboard-candidate-probe",
        metavar="PID",
        type=int,
        help=(
            "run the bounded suspended/traced candidate probe using the "
            "exact live SpringBoard PID only as an invariant"
        ),
    )
    mode.add_argument(
        "--stage-ellekit-loader-candidate",
        action="store_true",
        help="install only the fixed locally rebuilt ElleKit loader candidate",
    )
    mode.add_argument(
        "--copy-ellekit-loader-candidate",
        action="store_true",
        help="copy the fixed loader candidate back to Media",
    )
    mode.add_argument(
        "--inspect-with-ellekit-loader-candidate",
        metavar="PID",
        type=int,
        help=(
            "launch the fixed candidate loader through the worker and inspect "
            "only an admitted target PID"
        ),
    )
    mode.add_argument(
        "--stage-dyld-jb-admission-hook",
        action="store_true",
        help="install only the fixed dyld /var/jb admission hook from Media",
    )
    mode.add_argument(
        "--copy-dyld-jb-admission-hook",
        action="store_true",
        help="copy the fixed installed dyld admission hook back to Media",
    )
    mode.add_argument(
        "--trust-dyld-jb-admission-hook",
        action="store_true",
        help=(
            "invoke runtime trust once for only the fixed dyld admission "
            "hook and capture its root-owned log"
        ),
    )
    mode.add_argument(
        "--copy-dyld-jb-admission-hook-trust-log",
        action="store_true",
        help="copy the fixed root-owned dyld hook trust log to Media",
    )
    mode.add_argument(
        "--copy-dyld-jb-admission-hook-status",
        action="store_true",
        help="copy the fixed root-owned dyld hook status marker to Media",
    )
    mode.add_argument(
        "--stage-springboard-live-precursor",
        action="store_true",
        help="install only the fixed rollback-safe live precursor from Media",
    )
    mode.add_argument(
        "--stage-springboard-live-canary",
        action="store_true",
        help="install only the fixed fresh canary from Media without trusting it",
    )
    mode.add_argument(
        "--copy-springboard-live-canary",
        action="store_true",
        help="back up the installed fresh canary to Media",
    )
    mode.add_argument(
        "--stage-springboard-candidate-service-plist",
        action="store_true",
        help="install the dormant candidate SpringBoard launchd plist",
    )
    mode.add_argument(
        "--copy-springboard-candidate-service-plist",
        action="store_true",
        help="copy the installed candidate SpringBoard launchd plist to Media",
    )
    mode.add_argument(
        "--copy-springboard-live-precursor",
        action="store_true",
        help="copy the fixed installed live precursor back to Media",
    )
    mode.add_argument(
        "--run-springboard-watchdog-arm-test",
        action="store_true",
        help=(
            "run only the non-mutating nested-worker watchdog arm/disarm "
            "test after full SpringBoard preflight"
        ),
    )
    mode.add_argument(
        "--run-springboard-live-precursor",
        action="store_true",
        help=(
            "perform one rollback-mandatory candidate SpringBoard launch "
            "through the fixed debug-authorized worker"
        ),
    )
    mode.add_argument(
        "--soften-cryptexd",
        metavar="PID",
        type=int,
        help=(
            "run the fixed precursor's attach/detach softening pass on the "
            "exact 24A437 cryptexd PID"
        ),
    )
    mode.add_argument(
        "--run-springboard-external-live-proof",
        action="store_true",
        help=(
            "run one carrier-owned candidate/injection/stock-rollback "
            "transaction with an independent root rollback watchdog; "
            "requires --timeout 120"
        ),
    )
    mode.add_argument(
        "--run-springboard-external-parallel-bind-audit",
        action="store_true",
        help=(
            "bind and clean up only a parallel suspended candidate while "
            "proving the stock SpringBoard generation is unchanged"
        ),
    )
    mode.add_argument(
        "--run-springboard-external-parallel-live-proof",
        action="store_true",
        help=(
            "load the fresh never-trusted canary into only a parallel "
            "candidate while proving stock SpringBoard stays unchanged"
        ),
    )
    mode.add_argument(
        "--copy-springboard-external-parallel-bind-audit-log",
        action="store_true",
        help="export the root-owned parallel-bind audit transcript",
    )
    mode.add_argument(
        "--capture-springboard-external-candidate-print",
        action="store_true",
        help="capture the exact dormant candidate launchctl print output",
    )
    mode.add_argument(
        "--run-springboard-external-service-removal-audit",
        action="store_true",
        help=(
            "remove only the exact dormant external candidate service and "
            "prove stock SpringBoard remained the same process generation"
        ),
    )
    mode.add_argument(
        "--copy-springboard-external-live-proof-log",
        action="store_true",
        help="export the root-owned external live-proof transcript",
    )
    mode.add_argument(
        "--copy-springboard-live-precursor-log",
        action="store_true",
        help="copy the fixed root-owned precursor journal to Media",
    )
    mode.add_argument(
        "--capture-launchctl-debug-help",
        action="store_true",
        help="capture the device launchctl debug help text without mutation",
    )
    mode.add_argument(
        "--stage-apple-launchctl",
        action="store_true",
        help="install the exact Apple-signed firmware launchctl",
    )
    mode.add_argument(
        "--copy-apple-launchctl",
        action="store_true",
        help="copy the installed Apple-signed launchctl back to Media",
    )
    mode.add_argument(
        "--capture-apple-launchctl-debug-help",
        action="store_true",
        help="execute only help debug using the Apple-signed launchctl",
    )
    mode.add_argument(
        "--capture-system-launchctl-paths",
        action="store_true",
        help="probe fixed sealed launchctl paths and capture help status",
    )
    mode.add_argument(
        "--stage-dyld-interpose-probe",
        action="store_true",
        help=(
            "install only the fixed unsigned dyld interpose probe from "
            "Media at the worker-managed path"
        ),
    )
    mode.add_argument(
        "--run-dyld-interpose-probe",
        choices=(
            "standard",
            "reversed",
            "stripped",
            "stripped-reversed",
        ),
        metavar="MODE",
        help=(
            "run dyld_dynamic_interpose only inside a disposable "
            "debug-authorized worker child"
        ),
    )
    mode.add_argument(
        "--stage-dtrace-presence-probe",
        action="store_true",
        help=(
            "install only the fixed unsigned DTrace presence probe from "
            "Media at the worker-managed path"
        ),
    )
    mode.add_argument(
        "--run-dtrace-presence-probe",
        action="store_true",
        help=(
            "run the read-only DTrace device-node probe only inside a "
            "disposable debug-authorized worker child"
        ),
    )
    mode.add_argument(
        "--stage-cryptex-mount-topology-probe",
        action="store_true",
        help=(
            "install only the fixed unsigned cryptex mount-topology probe "
            "from Media at the worker-managed path"
        ),
    )
    mode.add_argument(
        "--run-cryptex-mount-topology-probe",
        action="store_true",
        help=(
            "run the read-only cryptex mount-topology probe only inside a "
            "disposable debug-authorized worker child"
        ),
    )
    mode.add_argument(
        "--stage-amfid-admission-canary",
        action="store_true",
        help=(
            "install only the fixed ad-hoc AMFI admission canary from Media "
            "at its managed path"
        ),
    )
    mode.add_argument(
        "--run-amfid-admission-canary",
        action="store_true",
        help=(
            "spawn the fixed AMFI admission canary directly, without the "
            "debug-authorized worker, and report its exact wait status"
        ),
    )
    mode.add_argument(
        "--kickstart-amfid",
        action="store_true",
        help=(
            "ask launchd through the fixed trusted launchctl to start only "
            "system/com.apple.MobileFileIntegrity"
        ),
    )
    mode.add_argument(
        "--stage-springboard-csops-status-probe",
        action="store_true",
        help=(
            "install only the fixed unsigned SpringBoard csops status probe "
            "from Media at the worker-managed path"
        ),
    )
    mode.add_argument(
        "--run-springboard-csops-status-probe",
        metavar="PID",
        type=int,
        help=(
            "request only CS_DEBUGGED through CS_OPS_SET_STATUS after exact "
            "SpringBoard PID/path validation"
        ),
    )
    mode.add_argument(
        "--stage-launch-type-canary-copy",
        action="store_true",
        help=(
            "copy the exact system xpcproxy to the fixed non-system launch "
            "constraint canary path"
        ),
    )
    mode.add_argument(
        "--stage-launch-type-canary-plist",
        action="store_true",
        help=(
            "install the fixed one-shot launch-type canary LaunchDaemon plist"
        ),
    )
    mode.add_argument(
        "--bootstrap-launch-type-canary",
        action="store_true",
        help=(
            "ask launchd through launchctl to run the fixed one-shot copied "
            "xpcproxy canary"
        ),
    )
    mode.add_argument(
        "--bootout-launch-type-canary",
        action="store_true",
        help="unregister only the fixed launch-type canary service",
    )
    mode.add_argument(
        "--print-launch-type-canary",
        action="store_true",
        help="print only the fixed registered launch-type canary service",
    )
    mode.add_argument(
        "--print-springboard-launch-service",
        action="store_true",
        help="print only SpringBoard's live launchd service definition",
    )
    mode.add_argument(
        "--kickstart-launch-type-canary",
        action="store_true",
        help="start only the fixed inert launch-type canary service",
    )
    mode.add_argument(
        "--print-sealed-springboard-job",
        action="store_true",
        help=(
            "print only the fixed dormant sealed-SpringBoard launch-type-1 "
            "job to its Media transcript"
        ),
    )
    mode.add_argument(
        "--kickstart-sealed-springboard-job",
        action="store_true",
        help=(
            "start only the fixed dormant sealed-SpringBoard job with "
            "launchctl -p -s and require either a numeric target PID or "
            "launchctl's documented-by-observation zero sentinel"
        ),
    )
    mode.add_argument(
        "--bootout-sealed-springboard-job",
        action="store_true",
        help="unregister only the fixed dormant sealed-SpringBoard job",
    )
    mode.add_argument(
        "--copy-system-launchd-artifact",
        action="store_true",
        help=(
            "copy only the exact system launchd image to Media for static "
            "analysis"
        ),
    )
    mode.add_argument(
        "--copy-system-cryptexd-artifact",
        action="store_true",
        help=(
            "copy only the exact system cryptexd image to Media for static "
            "analysis"
        ),
    )
    mode.add_argument(
        "--copy-system-dyld-artifact",
        action="store_true",
        help="copy only the exact live /usr/lib/dyld image to Media",
    )
    mode.add_argument(
        "--copy-system-springboard-plist",
        action="store_true",
        help="copy only the exact system SpringBoard launch plist to Media",
    )
    mode.add_argument(
        "--copy-system-springboard-info",
        action="store_true",
        help="copy only the exact live SpringBoard.app Info.plist to Media",
    )
    mode.add_argument(
        "--copy-system-springboard-bundle-manifest",
        action="store_true",
        help=(
            "write only a deterministic type/size/mode/owner/hash manifest "
            "of the exact live SpringBoard.app tree to Media"
        ),
    )
    mode.add_argument(
        "--clone-system-springboard-candidate-bundle",
        action="store_true",
        help=(
            "clone the exact live SpringBoard.app resource tree into the "
            "fixed dormant candidate bundle, then restore the pinned "
            "candidate executable and Info.plist"
        ),
    )
    mode.add_argument(
        "--copy-springboard-candidate-bundle-manifest",
        action="store_true",
        help=(
            "write only a deterministic type/size/mode/owner/hash manifest "
            "of the fixed dormant candidate SpringBoard.app tree to Media"
        ),
    )
    mode.add_argument(
        "--run-jsc-data-probe",
        action="store_true",
        help="run only the fixed Media JSC data-runtime probe and wait for it",
    )
    mode.add_argument(
        "--stage-jsc-springboard-probe",
        action="store_true",
        help="install only the fixed Media JSC SpringBoard probe",
    )
    mode.add_argument(
        "--run-jsc-springboard-probe",
        metavar="PID",
        type=int,
        help="run the fixed JSC probe against the exact SpringBoard PID",
    )
    mode.add_argument(
        "--inspect-owned-child-status",
        metavar="PID",
        type=int,
        help=(
            "use waitpid(WNOHANG|WUNTRACED) on an exact validated-carrier "
            "child and report whether it is running, stopped, or exited"
        ),
    )
    return parser.parse_args()


def frame_packet(payload: str) -> bytes:
    encoded = payload.encode("ascii")
    checksum = sum(encoded) & 0xFF
    return b"$" + encoded + b"#" + f"{checksum:02x}".encode("ascii")


def parse_key_values(response: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in response.split(";"):
        if ":" in item:
            key, value = item.split(":", 1)
            result[key] = value
    return result


def decode_hex_le(value: str) -> int:
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ProtocolError(f"invalid little-endian value: {value!r}") from error
    if len(raw) != 8:
        raise ProtocolError(f"expected 64-bit register value, got {value!r}")
    return int.from_bytes(raw, "little")


def encode_hex_le(value: int) -> str:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError(f"register value out of range: {value}")
    return value.to_bytes(8, "little").hex()


def align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & -alignment


def find_inventory_images(
    response: str, expected_uuid: uuid.UUID, expected_suffix: str
) -> list[tuple[int, str]]:
    """Parse stable image prefixes from Apple's malformed segment JSON.

    This iOS 27 debugserver emits an extra closing bracket between segment
    objects, so strict JSON decoding fails even though each image prefix is
    well-formed and unambiguous.  Limit parsing to the ordered load-address,
    path, and UUID prefix; in-memory Mach-O parsing below remains authoritative.
    """

    pattern = re.compile(
        r'\{"load_address":(?P<address>[0-9]+),'
        r'"mod_date":[0-9]+,'
        r'"pathname":(?P<path>"(?:\\.|[^"\\])*")'
        r',"uuid":"'
        + re.escape(str(expected_uuid))
        + r'"',
        re.IGNORECASE,
    )
    result: list[tuple[int, str]] = []
    for match in pattern.finditer(response):
        try:
            pathname = json.loads(match.group("path"))
        except json.JSONDecodeError as error:
            raise ProtocolError("invalid image pathname in debugserver inventory") from error
        if isinstance(pathname, str) and pathname.endswith(expected_suffix):
            result.append((int(match.group("address")), pathname))
    return result


def find_inventory_images_by_leaf(
    response: str, expected_leaf: str
) -> list[tuple[int, str, uuid.UUID]]:
    pattern = re.compile(
        r'\{"load_address":(?P<address>[0-9]+),'
        r'"mod_date":[0-9]+,'
        r'"pathname":(?P<path>"(?:\\.|[^"\\])*")'
        r',"uuid":"(?P<uuid>[0-9a-fA-F-]{36})"'
    )
    result: list[tuple[int, str, uuid.UUID]] = []
    for match in pattern.finditer(response):
        try:
            pathname = json.loads(match.group("path"))
            identifier = uuid.UUID(match.group("uuid"))
        except (json.JSONDecodeError, ValueError) as error:
            raise ProtocolError(
                "invalid image identity in debugserver inventory"
            ) from error
        if isinstance(pathname, str) and pathname.endswith(expected_leaf):
            result.append((int(match.group("address")), pathname, identifier))
    return result


@dataclass(frozen=True)
class StopState:
    signal: int
    thread: str
    x0: int
    pc: int

    @classmethod
    def parse(cls, response: str) -> "StopState":
        if not re.match(r"^T[0-9a-fA-F]{2}", response):
            raise ProtocolError(f"expected detailed stop reply, got {response!r}")
        fields = parse_key_values(response[3:])
        missing = [key for key in ("thread", "00", "20") if key not in fields]
        if missing:
            raise ProtocolError(f"stop reply omitted {missing}: {response!r}")
        return cls(
            signal=int(response[1:3], 16),
            thread=fields["thread"],
            x0=decode_hex_le(fields["00"]),
            pc=decode_hex_le(fields["20"]),
        )


class GDBRemote:
    def __init__(self, connection, timeout: float) -> None:
        self.connection = connection
        self.timeout = timeout
        self.buffer = bytearray()

    async def _fill(self) -> None:
        chunk = await asyncio.wait_for(
            self.connection.recv_any(65536), self.timeout
        )
        if not chunk:
            raise ProtocolError("debugserver closed the connection")
        self.buffer.extend(chunk)

    async def packet(self) -> str:
        while True:
            while self.buffer and self.buffer[0] in (ord("+"), ord("-")):
                marker = self.buffer.pop(0)
                if marker == ord("-"):
                    raise ProtocolError(
                        "debugserver rejected the previous packet checksum"
                    )

            start = self.buffer.find(b"$")
            if start < 0:
                self.buffer.clear()
                await self._fill()
                continue
            if start:
                del self.buffer[:start]

            checksum_offset = self.buffer.find(b"#", 1)
            if checksum_offset < 0 or len(self.buffer) < checksum_offset + 3:
                await self._fill()
                continue

            payload = bytes(self.buffer[1:checksum_offset])
            checksum_text = bytes(
                self.buffer[checksum_offset + 1 : checksum_offset + 3]
            )
            del self.buffer[: checksum_offset + 3]
            try:
                received_checksum = int(checksum_text, 16)
            except ValueError as error:
                raise ProtocolError(
                    f"invalid packet checksum {checksum_text!r}"
                ) from error
            if (sum(payload) & 0xFF) != received_checksum:
                await self.connection.sendall(b"-")
                raise ProtocolError("debugserver response checksum mismatch")
            await self.connection.sendall(b"+")
            return payload.decode("ascii")

    async def command(self, payload: str) -> str:
        await self.connection.sendall(frame_packet(payload))
        return await self.packet()

    async def continue_thread(self, thread: str) -> str:
        await self.connection.sendall(frame_packet(f"vCont;c:{thread}"))
        while True:
            response = await self.packet()
            if response.startswith("O") and len(response) > 1:
                try:
                    output = bytes.fromhex(response[1:]).decode(
                        "utf-8", "replace"
                    )
                except ValueError:
                    output = response
                print(f"carrier-output={output.rstrip()}")
                continue
            if response[:1] in {"T", "S", "W", "X"}:
                return response
            raise ProtocolError(
                f"unexpected continue response: {response!r}"
            )

    async def interrupt(self) -> str:
        await self.connection.sendall(b"\x03")
        while True:
            response = await self.packet()
            if response.startswith("O"):
                continue
            if response[:1] in {"T", "S", "W", "X"}:
                return response
            raise ProtocolError(f"unexpected interrupt response: {response!r}")


async def expect_ok(remote: GDBRemote, payload: str) -> None:
    response = await remote.command(payload)
    if response != "OK":
        raise ProtocolError(f"{payload!r} failed: {response!r}")


async def read_memory(remote: GDBRemote, address: int, size: int) -> bytes:
    if address <= 0 or size <= 0 or size > MAX_LOAD_COMMAND_BYTES:
        raise ProtocolError(
            f"refusing invalid memory read address=0x{address:x} size=0x{size:x}"
        )
    result = bytearray()
    while len(result) < size:
        length = min(MEMORY_CHUNK, size - len(result))
        response = await remote.command(
            f"m{address + len(result):x},{length:x}"
        )
        if response.startswith("E"):
            raise ProtocolError(
                f"memory read failed at 0x{address + len(result):x}: {response!r}"
            )
        try:
            chunk = bytes.fromhex(response)
        except ValueError as error:
            raise ProtocolError(f"invalid memory response: {response!r}") from error
        if len(chunk) != length:
            raise ProtocolError(
                f"short memory read: expected {length}, got {len(chunk)}"
            )
        result.extend(chunk)
    return bytes(result)


async def write_memory(remote: GDBRemote, address: int, data: bytes) -> None:
    if address <= 0 or not data or len(data) > SCRATCH_SIZE:
        raise ProtocolError(
            f"refusing invalid memory write address=0x{address:x} size=0x{len(data):x}"
        )
    for offset in range(0, len(data), MEMORY_CHUNK):
        chunk = data[offset : offset + MEMORY_CHUNK]
        await expect_ok(
            remote,
            f"M{address + offset:x},{len(chunk):x}:{chunk.hex()}",
        )
    observed = await read_memory(remote, address, len(data))
    if observed != data:
        raise ProtocolError("scratch-memory verification failed")


async def read_register(remote: GDBRemote, register: str, thread: str) -> int:
    response = await remote.command(f"p{register};thread:{thread};")
    return decode_hex_le(response)


async def find_resident_runtime_blob(
    remote: GDBRemote, image_base: int
) -> int:
    header = await read_memory(remote, image_base, 32)
    (
        magic,
        cpu_type,
        _cpu_subtype,
        _file_type,
        command_count,
        command_bytes,
        _flags,
        _reserved,
    ) = struct.unpack("<IiiIIIII", header)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_ARM64:
        raise ProtocolError("resident runtime has an invalid Mach-O header")
    if not (0 < command_count <= MAX_LOAD_COMMANDS) or not (
        0 < command_bytes <= MAX_LOAD_COMMAND_BYTES
    ):
        raise ProtocolError("resident runtime has invalid load commands")
    commands = await read_memory(remote, image_base + 32, command_bytes)
    segments: list[tuple[str, int, int, int]] = []
    text_vmaddr: int | None = None
    cursor = 0
    for _ in range(command_count):
        if cursor + 8 > len(commands):
            raise ProtocolError("resident runtime load commands are truncated")
        command, command_size = struct.unpack_from("<II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            raise ProtocolError("resident runtime has an invalid load command")
        if command == LC_SEGMENT_64 and command_size >= 72:
            segment_name = (
                commands[cursor + 8 : cursor + 24]
                .split(b"\0", 1)[0]
                .decode("ascii", "replace")
            )
            vmaddr, vmsize = struct.unpack_from("<QQ", commands, cursor + 24)
            initprot = struct.unpack_from("<i", commands, cursor + 60)[0]
            segments.append((segment_name, vmaddr, vmsize, initprot))
            if segment_name == "__TEXT":
                text_vmaddr = vmaddr
        cursor += command_size
    if cursor != len(commands) or text_vmaddr is None:
        raise ProtocolError("resident runtime has no usable __TEXT segment")

    matches: list[int] = []
    for segment_name, vmaddr, vmsize, initprot in segments:
        if (initprot & 4) == 0 or vmsize == 0:
            continue
        if vmsize > MAX_RUNTIME_EXECUTABLE_SCAN or vmaddr < text_vmaddr:
            raise ProtocolError(
                f"refusing resident executable segment {segment_name} "
                f"vmaddr=0x{vmaddr:x} size=0x{vmsize:x}"
            )
        segment_address = image_base + vmaddr - text_vmaddr
        overlap = len(RUNTIME_REMOTE_BLOB_PREFIX) - 1
        tail = b""
        offset = 0
        while offset < vmsize:
            amount = min(0x4000, vmsize - offset)
            chunk = await read_memory(remote, segment_address + offset, amount)
            window = tail + chunk
            search_from = 0
            while True:
                found = window.find(RUNTIME_REMOTE_BLOB_PREFIX, search_from)
                if found < 0:
                    break
                matches.append(segment_address + offset - len(tail) + found)
                search_from = found + 1
            tail = window[-overlap:] if overlap else b""
            offset += amount
    unique_matches = sorted(set(matches))
    if len(unique_matches) != 1:
        raise ProtocolError(
            "expected exactly one resident remote-code blob prefix; "
            f"found {len(unique_matches)}"
        )
    return unique_matches[0]


async def set_register(
    remote: GDBRemote, register: str, value: int, thread: str
) -> None:
    await expect_ok(
        remote,
        f"P{register}={encode_hex_le(value)};thread:{thread};",
    )


def validate_process_info(response: str, expected_pid: int) -> None:
    fields = parse_key_values(response)
    if "pid" not in fields:
        raise ProtocolError(f"qProcessInfo omitted pid: {response!r}")
    actual_pid = int(fields["pid"], 16)
    if actual_pid != expected_pid or actual_pid <= 1:
        raise ProtocolError(
            f"attached PID mismatch: expected {expected_pid}, got {actual_pid}"
        )

    for key in ("uid", "euid"):
        if key in fields and int(fields[key], 16) != 0:
            raise ProtocolError(
                f"carrier is not root: {key}={int(fields[key], 16)}"
            )
    reported = ",".join(
        f"{key}={fields[key]}"
        for key in ("pid", "parent-pid", "uid", "euid", "name")
        if key in fields
    )
    print(f"process-info {reported}")


async def validate_carrier(
    remote: GDBRemote, state: StopState
) -> tuple[int, int, int, int]:
    region_response = await remote.command(f"qMemoryRegionInfo:{state.pc:x}")
    region = parse_key_values(region_response)
    try:
        region_start = int(region["start"], 16)
        region_size = int(region["size"], 16)
    except (KeyError, ValueError) as error:
        raise ProtocolError(
            f"invalid carrier PC memory region: {region_response!r}"
        ) from error
    if (
        region_start != state.pc & ~0x3FFF
        or region_size != 0x4000
        or region.get("permissions") != "rx"
        or not (region_start <= state.pc < region_start + region_size)
    ):
        raise ProtocolError(
            f"unexpected carrier spin region for pc=0x{state.pc:x}: "
            f"{region_response!r}"
        )

    spin_instruction = await read_memory(remote, state.pc, 4)
    if spin_instruction == EXPECTED_SPIN_WFE:
        spin_start = state.pc
    elif spin_instruction == EXPECTED_SPIN_BRANCH:
        spin_start = state.pc - 4
    else:
        raise ProtocolError(
            "carrier spin instruction mismatch at "
            f"0x{state.pc:x}: {spin_instruction.hex()}"
        )
    if spin_start < region_start or spin_start + len(EXPECTED_SPIN_LOOP) > (
        region_start + region_size
    ):
        raise ProtocolError(
            f"carrier spin loop crosses its RX region: 0x{spin_start:x}"
        )
    spin_loop = await read_memory(remote, spin_start, len(EXPECTED_SPIN_LOOP))
    if spin_loop != EXPECTED_SPIN_LOOP:
        raise ProtocolError(
            f"carrier spin loop mismatch at 0x{spin_start:x}: "
            f"{spin_loop.hex()}"
        )

    libraries_request = json.dumps(
        {"fetch_all_solibs": True}, separators=(",", ":")
    )
    libraries_response = await remote.command(
        f"jGetLoadedDynamicLibrariesInfos:{libraries_request}"
    )
    executable_images = find_inventory_images(
        libraries_response,
        EXPECTED_CARRIER_UUID,
        "/procursus/usr/libexec/codex-ellekit-loader",
    )
    runtime_records: list[tuple[int, str, uuid.UUID]] = []
    for runtime_identifier in (
        EXPECTED_RUNTIME_CARRIER_UUID,
        RECOVERY_RUNTIME_CARRIER_UUID,
    ):
        for runtime_suffix in (
            "/procursus/usr/lib/codex-runtime-carrier.dylib",
            "/var/jb/usr/lib/codex-runtime-carrier.dylib",
        ):
            runtime_records.extend(
                (
                    address,
                    path,
                    runtime_identifier,
                )
                for address, path in find_inventory_images(
                    libraries_response,
                    runtime_identifier,
                    runtime_suffix,
                )
            )
    runtime_records = list(dict.fromkeys(runtime_records))
    if len(executable_images) != 1 or len(runtime_records) != 1:
        runtime_candidates = find_inventory_images_by_leaf(
            libraries_response, "/codex-runtime-carrier.dylib"
        )
        raise ProtocolError(
            "expected exactly one matching carrier executable and runtime dylib; "
            f"found executable={len(executable_images)} "
            f"runtime={len(runtime_records)} candidates={runtime_candidates!r}"
        )
    image_base, executable_path = executable_images[0]
    runtime_base, runtime_path, runtime_identifier = runtime_records[0]
    if image_base <= 0 or image_base & 0x3FFF:
        raise ProtocolError(f"invalid carrier load address: 0x{image_base:x}")

    header = await read_memory(remote, image_base, 32)
    (
        magic,
        cpu_type,
        cpu_subtype,
        file_type,
        command_count,
        command_bytes,
        _flags,
        _reserved,
    ) = struct.unpack("<IiiIIIII", header)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_ARM64:
        raise ProtocolError(
            f"unexpected Mach-O header at 0x{image_base:x} "
            f"for pc=0x{state.pc:x}: magic=0x{magic:x} cpu=0x{cpu_type:x}"
        )
    if (cpu_subtype & 0x00FFFFFF) != CPU_SUBTYPE_ARM64E:
        raise ProtocolError(f"carrier is not arm64e: subtype=0x{cpu_subtype:x}")
    if file_type != MH_EXECUTE:
        raise ProtocolError(f"carrier is not MH_EXECUTE: type={file_type}")
    if not (0 < command_count <= MAX_LOAD_COMMANDS):
        raise ProtocolError(f"invalid load-command count: {command_count}")
    if not (0 < command_bytes <= MAX_LOAD_COMMAND_BYTES):
        raise ProtocolError(f"invalid load-command size: {command_bytes}")

    commands = await read_memory(remote, image_base + 32, command_bytes)
    cursor = 0
    observed_uuid: uuid.UUID | None = None
    for _ in range(command_count):
        if cursor + 8 > len(commands):
            raise ProtocolError("truncated Mach-O load commands")
        command, command_size = struct.unpack_from("<II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            raise ProtocolError("invalid Mach-O load command size")
        if command == LC_UUID:
            if command_size != 24 or observed_uuid is not None:
                raise ProtocolError("invalid or duplicate LC_UUID")
            observed_uuid = uuid.UUID(bytes=commands[cursor + 8 : cursor + 24])
        cursor += command_size
    if cursor != len(commands):
        raise ProtocolError("Mach-O load-command size mismatch")
    if observed_uuid != EXPECTED_CARRIER_UUID:
        raise ProtocolError(
            f"carrier UUID mismatch: expected {EXPECTED_CARRIER_UUID}, "
            f"got {observed_uuid}"
        )

    spawn_stub = image_base + POSIX_SPAWN_STUB_OFFSET
    stub = await read_memory(remote, spawn_stub, len(EXPECTED_POSIX_SPAWN_STUB))
    if stub != EXPECTED_POSIX_SPAWN_STUB:
        raise ProtocolError(
            f"authenticated posix_spawn stub mismatch at 0x{spawn_stub:x}: "
            f"{stub.hex()}"
        )
    additional_stubs = (
        (
            "mach_port_deallocate",
            MACH_PORT_DEALLOCATE_STUB_OFFSET,
            EXPECTED_MACH_PORT_DEALLOCATE_STUB,
        ),
        (
            "posix_spawnattr_destroy",
            POSIX_SPAWNATTR_DESTROY_STUB_OFFSET,
            EXPECTED_POSIX_SPAWNATTR_DESTROY_STUB,
        ),
        (
            "posix_spawnattr_init",
            POSIX_SPAWNATTR_INIT_STUB_OFFSET,
            EXPECTED_POSIX_SPAWNATTR_INIT_STUB,
        ),
        (
            "posix_spawnattr_set_ptrauth_task_port_np",
            POSIX_SPAWNATTR_SET_PTRAUTH_STUB_OFFSET,
            EXPECTED_POSIX_SPAWNATTR_SET_PTRAUTH_STUB,
        ),
        (
            "proc_pidpath",
            PROC_PIDPATH_STUB_OFFSET,
            EXPECTED_PROC_PIDPATH_STUB,
        ),
        (
            "task_for_pid",
            TASK_FOR_PID_STUB_OFFSET,
            EXPECTED_TASK_FOR_PID_STUB,
        ),
    )
    for name, offset, expected in additional_stubs:
        address = image_base + offset
        observed = await read_memory(remote, address, len(expected))
        if observed != expected:
            raise ProtocolError(
                f"authenticated {name} stub mismatch at 0x{address:x}: "
                f"{observed.hex()}"
            )
    waitpid_stub = image_base + WAITPID_STUB_OFFSET
    waitpid_bytes = await read_memory(
        remote, waitpid_stub, len(EXPECTED_WAITPID_STUB)
    )
    if waitpid_bytes != EXPECTED_WAITPID_STUB:
        raise ProtocolError(
            f"authenticated waitpid stub mismatch at 0x{waitpid_stub:x}: "
            f"{waitpid_bytes.hex()}"
        )
    print(
        f"validated-carrier thread={state.thread} pc=0x{state.pc:x} "
        f"spin-region=0x{region_start:x} base=0x{image_base:x} "
        f"uuid={observed_uuid} runtime-uuid={runtime_identifier} "
        f"runtime-base=0x{runtime_base:x} runtime-path={runtime_path} "
        f"posix_spawn=0x{spawn_stub:x} waitpid=0x{waitpid_stub:x} "
        f"path={executable_path}"
    )
    return image_base, spawn_stub, waitpid_stub, runtime_base


async def allocate_scratch(remote: GDBRemote) -> int:
    response = await remote.command(f"_M{SCRATCH_SIZE:x},rw")
    if not re.fullmatch(r"[0-9a-fA-F]+", response):
        raise ProtocolError(f"scratch allocation failed: {response!r}")
    address = int(response, 16)
    if address <= 0 or address & 0x3FFF:
        raise ProtocolError(f"invalid scratch address: 0x{address:x}")
    return address


def build_spawn_payload(
    base: int, arguments: tuple[str, ...]
) -> tuple[bytes, int, int, int]:
    payload = bytearray(SCRATCH_SIZE)
    cursor = 0
    string_addresses: list[int] = []
    for argument in arguments:
        encoded = argument.encode("utf-8") + b"\0"
        string_addresses.append(base + cursor)
        payload[cursor : cursor + len(encoded)] = encoded
        cursor = align(cursor + len(encoded))

    argv_offset = align(cursor, 16)
    argv = b"".join(
        struct.pack("<Q", address) for address in string_addresses
    ) + struct.pack("<Q", 0)
    payload[argv_offset : argv_offset + len(argv)] = argv

    envp_offset = align(argv_offset + len(argv), 8)
    payload[envp_offset : envp_offset + 8] = b"\0" * 8
    pid_offset = align(envp_offset + 8, 8)
    payload[pid_offset : pid_offset + 8] = b"\0" * 8
    used = align(pid_offset + 8, 16)
    if used > SCRATCH_SIZE:
        raise ProtocolError("spawn payload exceeds scratch allocation")
    return (
        bytes(payload[:used]),
        base + argv_offset,
        base + envp_offset,
        base + pid_offset,
    )


async def run(args: argparse.Namespace) -> int:
    if args.pid <= 1:
        raise ProtocolError("refusing to attach to PID 1 or an invalid PID")
    if args.resume_owned_child is not None and args.resume_owned_child <= 1:
        raise ProtocolError("refusing to resume PID 1 or an invalid PID")
    if (
        args.terminate_owned_child is not None
        and args.terminate_owned_child <= 1
    ):
        raise ProtocolError("refusing to terminate PID 1 or an invalid PID")
    if (
        args.terminate_verified_orphan is not None
        and args.terminate_verified_orphan <= 1
    ):
        raise ProtocolError("refusing to terminate PID 1 or an invalid PID")
    if (
        args.inspect_owned_child_status is not None
        and args.inspect_owned_child_status <= 1
    ):
        raise ProtocolError("refusing to inspect PID 1 or an invalid PID")
    for target_pid in (
        args.springboard_inspect_pid,
        args.springboard_page_probe,
        args.springboard_resident_hook,
        args.springboard_resident_canary,
        args.run_jsc_springboard_probe,
        args.spawn_suspended_ptrauth_loader,
        args.spawn_suspended_ptrauth_loader_amfid,
        args.spawn_suspended_ptrauth_loader_cryptexd,
        args.inspect_cryptexd_task_port,
        args.inspect_amfid_task_port,
    ):
        if target_pid is not None and target_pid <= 1:
            raise ProtocolError("refusing PID 1 or an invalid SpringBoard PID")
    if args.timeout <= 0 or args.timeout > 120:
        raise ProtocolError("timeout must be in the range (0, 120]")
    if (
        args.run_springboard_external_live_proof
        or args.run_springboard_external_parallel_bind_audit
        or args.run_springboard_external_parallel_live_proof
    ) and args.timeout != 120:
        raise ProtocolError(
            "external SpringBoard proof actions require --timeout 120"
        )

    rsd_context = (
        PreferredRsdTunnel(
            serial=args.userspace_udid,
            prefer_native=False,
        )
        if args.userspace_udid
        else RemoteServiceDiscoveryService((args.host, args.port))
    )
    async with rsd_context as rsd:
        connection = await rsd.create_service_connection(
            rsd.get_service_port(DEBUG_PROXY_SERVICE)
        )
        remote = GDBRemote(connection, args.timeout)
        attached = False
        stopped = False
        state_saved = False
        save_identifier: str | None = None
        scratch: int | None = None
        breakpoint_address: int | None = None
        primary_error: BaseException | None = None
        try:
            await connection.sendall(b"+")
            supported = await remote.command("qSupported")
            print(f"debugserver-supported={supported}")
            optional = await remote.command("QEnableErrorStrings")
            if optional not in {"", "OK"}:
                raise ProtocolError(
                    f"QEnableErrorStrings failed: {optional!r}"
                )

            attach_response = await remote.command(f"vAttach;{args.pid:x}")
            attached = True
            stopped = True
            initial = StopState.parse(attach_response)
            validate_process_info(
                await remote.command("qProcessInfo"), args.pid
            )
            (
                image_base,
                spawn_stub,
                waitpid_stub,
                runtime_base,
            ) = await validate_carrier(remote, initial)

            if args.validate_only:
                print("validate-only=success")
                return 0
            if args.inspect_runtime_blob:
                blob_address = await find_resident_runtime_blob(
                    remote, runtime_base
                )
                blob = await read_memory(
                    remote, blob_address, RUNTIME_REMOTE_BLOB_SIZE
                )
                digest = hashlib.sha256(blob).hexdigest()
                print(
                    f"runtime-blob-inspect=success address=0x{blob_address:x} "
                    f"offset=0x{blob_address - runtime_base:x} "
                    f"size=0x{len(blob):x} sha256={digest} "
                    f"bytes={blob.hex()}"
                )
                return 0

            save_response = await remote.command(
                f"QSaveRegisterState;thread:{initial.thread};"
            )
            if not re.fullmatch(r"[0-9]+", save_response):
                raise ProtocolError(
                    f"QSaveRegisterState failed: {save_response!r}"
                )
            save_identifier = save_response
            state_saved = True
            scratch = await allocate_scratch(remote)
            print(
                f"scratch-allocated address=0x{scratch:x} size=0x{SCRATCH_SIZE:x}"
            )

            if (
                args.spawn_suspended_ptrauth_loader is not None
                or args.spawn_suspended_ptrauth_loader_amfid is not None
                or args.spawn_suspended_ptrauth_loader_cryptexd is not None
                or args.inspect_cryptexd_task_port is not None
                or args.inspect_amfid_task_port is not None
            ):
                target_pid = (
                    args.spawn_suspended_ptrauth_loader
                    if args.spawn_suspended_ptrauth_loader is not None
                    else (
                        args.spawn_suspended_ptrauth_loader_amfid
                        if args.spawn_suspended_ptrauth_loader_amfid is not None
                        else (
                            args.spawn_suspended_ptrauth_loader_cryptexd
                            if args.spawn_suspended_ptrauth_loader_cryptexd
                            is not None
                            else (
                                args.inspect_cryptexd_task_port
                                if args.inspect_cryptexd_task_port is not None
                                else args.inspect_amfid_task_port
                            )
                        )
                    )
                )
                child_arguments = (
                    LOADER_PATH,
                    "--inspect-pid",
                    str(target_pid),
                    "--ptrauth-child",
                )
                payload, argv_address, envp_address, pid_address = (
                    build_spawn_payload(scratch, child_arguments)
                )
                if len(payload) > PTRAUTH_CHILD_PATH_BUFFER_OFFSET:
                    raise ProtocolError(
                        "suspended-child payload overlaps its path buffer"
                    )
                await write_memory(remote, scratch, payload)

                path_address = scratch + PTRAUTH_CHILD_PATH_BUFFER_OFFSET
                attr_address = scratch + PTRAUTH_CHILD_ATTR_STORAGE_OFFSET
                task_address = scratch + PTRAUTH_CHILD_TASK_STORAGE_OFFSET
                status_address = scratch + PTRAUTH_CHILD_STATUS_STORAGE_OFFSET
                await write_memory(
                    remote,
                    path_address,
                    b"\0" * PTRAUTH_CHILD_PATH_BUFFER_SIZE,
                )
                await write_memory(remote, attr_address, b"\0" * 8)
                await write_memory(remote, task_address, b"\0" * 8)
                await write_memory(remote, status_address, b"\0" * 8)
                await expect_ok(remote, f"Z1,{initial.pc:x},4")
                breakpoint_address = initial.pc

                async def call_carrier(
                    name: str, function: int, arguments: tuple[int, ...]
                ) -> int:
                    nonlocal stopped
                    if len(arguments) > 8:
                        raise ProtocolError(
                            f"too many register arguments for {name}"
                        )
                    register_values = {
                        f"{index:x}": value
                        for index, value in enumerate(arguments)
                    }
                    register_values["1e"] = initial.pc
                    register_values["20"] = function
                    for register, value in register_values.items():
                        await set_register(
                            remote, register, value, initial.thread
                        )
                    for register, expected in register_values.items():
                        observed = await read_register(
                            remote, register, initial.thread
                        )
                        if observed != expected:
                            raise ProtocolError(
                                f"{name} register {register} verification "
                                f"failed: expected 0x{expected:x}, "
                                f"got 0x{observed:x}"
                            )
                    stopped = False
                    response = await remote.continue_thread(initial.thread)
                    returned = StopState.parse(response)
                    stopped = True
                    if returned.thread.lower() != initial.thread.lower():
                        raise ProtocolError(
                            f"{name} stopped unexpected thread "
                            f"{returned.thread}"
                        )
                    if returned.pc != initial.pc:
                        raise ProtocolError(
                            f"{name} did not return to the carrier spin "
                            f"breakpoint: pc=0x{returned.pc:x}"
                        )
                    print(
                        f"carrier-call name={name} function=0x{function:x} "
                        f"result=0x{returned.x0:x}"
                    )
                    return returned.x0

                attr_initialized = False
                target_task = 0
                child_pid = 0
                stop_signal = 0
                branch_error: BaseException | None = None
                try:
                    path_result_raw = await call_carrier(
                        "proc_pidpath",
                        image_base + PROC_PIDPATH_STUB_OFFSET,
                        (
                            target_pid,
                            path_address,
                            PTRAUTH_CHILD_PATH_BUFFER_SIZE,
                        ),
                    )
                    path_result = struct.unpack(
                        "<i", struct.pack("<I", path_result_raw & 0xFFFFFFFF)
                    )[0]
                    if path_result <= 0 or path_result >= PTRAUTH_CHILD_PATH_BUFFER_SIZE:
                        raise ProtocolError(
                            f"proc_pidpath failed for PID {target_pid}: "
                            f"result={path_result}"
                        )
                    path_bytes = await read_memory(
                        remote, path_address, path_result + 1
                    )
                    target_path = path_bytes.split(b"\0", 1)[0].decode(
                        "utf-8", "strict"
                    )
                    expected_target_path = (
                        SPRINGBOARD_PATH
                        if args.spawn_suspended_ptrauth_loader is not None
                        else (
                            AMFID_PATH
                            if (
                                args.spawn_suspended_ptrauth_loader_amfid
                                is not None
                                or args.inspect_amfid_task_port is not None
                            )
                            else CRYPTEXD_PATH
                        )
                    )
                    if target_path != expected_target_path:
                        raise ProtocolError(
                            f"refusing unexpected target PID {target_pid}: "
                            f"expected {expected_target_path!r}, got "
                            f"{target_path!r}"
                        )
                    print(
                        f"target-validated pid={target_pid} "
                        f"path={target_path}"
                    )

                    task_self_pointer_raw = struct.unpack(
                        "<Q",
                        await read_memory(
                            remote,
                            image_base + MACH_TASK_SELF_GOT_OFFSET,
                            8,
                        ),
                    )[0]
                    task_self_pointer = (
                        task_self_pointer_raw & 0x0000FFFFFFFFFFFF
                    )
                    if task_self_pointer == 0 or task_self_pointer & 3:
                        raise ProtocolError(
                            "carrier mach_task_self_ pointer is invalid: "
                            f"0x{task_self_pointer_raw:x}"
                        )
                    task_self = struct.unpack(
                        "<I", await read_memory(remote, task_self_pointer, 4)
                    )[0]
                    if task_self == 0:
                        raise ProtocolError(
                            "carrier mach_task_self_ port is null"
                        )

                    task_result = await call_carrier(
                        "task_for_pid",
                        image_base + TASK_FOR_PID_STUB_OFFSET,
                        (task_self, target_pid, task_address),
                    )
                    if task_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            f"task_for_pid({target_pid}) failed: "
                            f"{task_result & 0xFFFFFFFF}"
                        )
                    target_task = struct.unpack(
                        "<I", await read_memory(remote, task_address, 4)
                    )[0]
                    if target_task == 0:
                        raise ProtocolError(
                            "task_for_pid returned a null task port"
                        )
                    print(
                        f"ptrauth-target-task pid={target_pid} "
                        f"port=0x{target_task:x}"
                    )
                    if args.inspect_cryptexd_task_port is not None:
                        print(
                            "cryptexd-task-port-inspect=success "
                            f"pid={target_pid} path={target_path}"
                        )
                        return 0
                    if args.inspect_amfid_task_port is not None:
                        print(
                            "amfid-task-port-inspect=success "
                            f"pid={target_pid} path={target_path}"
                        )
                        return 0

                    init_result = await call_carrier(
                        "posix_spawnattr_init",
                        image_base + POSIX_SPAWNATTR_INIT_STUB_OFFSET,
                        (attr_address,),
                    )
                    if init_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "posix_spawnattr_init failed: "
                            f"{init_result & 0xFFFFFFFF}"
                        )
                    attr_initialized = True
                    attr_pointer_raw = struct.unpack(
                        "<Q", await read_memory(remote, attr_address, 8)
                    )[0]
                    attr_pointer = attr_pointer_raw & 0x0000FFFFFFFFFFFF
                    if attr_pointer == 0 or attr_pointer & 7:
                        raise ProtocolError(
                            "initialized spawn attribute pointer is invalid: "
                            f"0x{attr_pointer_raw:x}"
                        )
                    region_response = await remote.command(
                        f"qMemoryRegionInfo:{attr_pointer:x}"
                    )
                    region = parse_key_values(region_response)
                    try:
                        region_start = int(region["start"], 16)
                        region_size = int(region["size"], 16)
                    except (KeyError, ValueError) as error:
                        raise ProtocolError(
                            "invalid spawn-attribute memory region: "
                            f"{region_response!r}"
                        ) from error
                    permissions = region.get("permissions", "")
                    if (
                        "r" not in permissions
                        or "w" not in permissions
                        or not (
                            region_start
                            <= attr_pointer
                            < region_start + region_size - 1
                        )
                    ):
                        raise ProtocolError(
                            "spawn attribute is not in writable memory: "
                            f"{region_response!r}"
                        )
                    initial_flags = struct.unpack(
                        "<H", await read_memory(remote, attr_pointer, 2)
                    )[0]
                    if initial_flags != 0:
                        raise ProtocolError(
                            "new spawn attribute has unexpected flags: "
                            f"0x{initial_flags:04x}"
                        )
                    await write_memory(
                        remote,
                        attr_pointer,
                        struct.pack("<H", POSIX_SPAWN_START_SUSPENDED),
                    )

                    ptrauth_result = await call_carrier(
                        "posix_spawnattr_set_ptrauth_task_port_np",
                        image_base
                        + POSIX_SPAWNATTR_SET_PTRAUTH_STUB_OFFSET,
                        (attr_address, target_task),
                    )
                    if ptrauth_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "posix_spawnattr_set_ptrauth_task_port_np "
                            f"failed: {ptrauth_result & 0xFFFFFFFF}"
                        )
                    observed_flags = struct.unpack(
                        "<H", await read_memory(remote, attr_pointer, 2)
                    )[0]
                    if observed_flags != POSIX_SPAWN_START_SUSPENDED:
                        raise ProtocolError(
                            "ptrauth task-port setter changed spawn flags: "
                            f"0x{observed_flags:04x}"
                        )

                    spawn_result = await call_carrier(
                        "posix_spawn_suspended_ptrauth_loader",
                        spawn_stub,
                        (
                            pid_address,
                            scratch,
                            0,
                            attr_address,
                            argv_address,
                            envp_address,
                        ),
                    )
                    if spawn_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "suspended ptrauth loader spawn failed: "
                            f"{spawn_result & 0xFFFFFFFF}"
                        )
                    child_pid = struct.unpack(
                        "<i", await read_memory(remote, pid_address, 4)
                    )[0]
                    if child_pid <= 1 or child_pid == target_pid:
                        raise ProtocolError(
                            f"spawn returned invalid child PID {child_pid}"
                        )

                    wait_result = 0
                    wait_status = 0
                    for _ in range(20):
                        await write_memory(remote, status_address, b"\0" * 4)
                        wait_result_raw = await call_carrier(
                            "waitpid_suspended_child",
                            waitpid_stub,
                            (child_pid, status_address, 3),
                        )
                        wait_result = struct.unpack(
                            "<i",
                            struct.pack(
                                "<I", wait_result_raw & 0xFFFFFFFF
                            ),
                        )[0]
                        wait_status = struct.unpack(
                            "<I",
                            await read_memory(remote, status_address, 4),
                        )[0]
                        if wait_result != 0:
                            break
                        await asyncio.sleep(0.05)
                    if wait_result != child_pid:
                        raise ProtocolError(
                            f"waitpid did not confirm suspended child "
                            f"{child_pid}: result={wait_result} "
                            f"status=0x{wait_status:08x}"
                        )
                    if (wait_status & 0x7F) != 0x7F:
                        raise ProtocolError(
                            f"ptrauth loader child {child_pid} is not "
                            f"stopped: status=0x{wait_status:08x}"
                        )
                    stop_signal = (wait_status >> 8) & 0xFF
                except BaseException as error:
                    branch_error = error
                    raise
                finally:
                    branch_cleanup_errors: list[str] = []
                    if stopped and attr_initialized:
                        try:
                            destroy_result = await call_carrier(
                                "posix_spawnattr_destroy",
                                image_base
                                + POSIX_SPAWNATTR_DESTROY_STUB_OFFSET,
                                (attr_address,),
                            )
                            if destroy_result & 0xFFFFFFFF:
                                raise ProtocolError(
                                    "posix_spawnattr_destroy failed: "
                                    f"{destroy_result & 0xFFFFFFFF}"
                                )
                            attr_initialized = False
                        except BaseException as error:
                            branch_cleanup_errors.append(
                                f"spawn attribute: {error}"
                            )
                    if stopped and target_task != 0:
                        try:
                            deallocate_result = await call_carrier(
                                "mach_port_deallocate_target_task",
                                image_base
                                + MACH_PORT_DEALLOCATE_STUB_OFFSET,
                                (task_self, target_task),
                            )
                            if deallocate_result & 0xFFFFFFFF:
                                raise ProtocolError(
                                    "mach_port_deallocate failed: "
                                    f"{deallocate_result & 0xFFFFFFFF}"
                                )
                            target_task = 0
                        except BaseException as error:
                            branch_cleanup_errors.append(
                                f"target task port: {error}"
                            )
                    if branch_cleanup_errors:
                        message = "; ".join(branch_cleanup_errors)
                        print(
                            f"ptrauth-child-cleanup-error: {message}",
                            file=sys.stderr,
                        )
                        if branch_error is None:
                            raise ProtocolError(message)
                print(
                    f"suspended-ptrauth-loader=success child-pid="
                    f"{child_pid} target-pid={target_pid} "
                    f"stop-signal={stop_signal}"
                )
                return 0

            if args.allocation_cycle:
                marker = b"codex-carrier-allocation-cycle\0"
                await write_memory(remote, scratch, marker)
                print("allocation-cycle=success")
                return 0

            if args.reap_self_test is not None:
                child = args.reap_self_test
                if child <= 1:
                    raise ProtocolError(
                        "refusing waitpid for PID 1 or an invalid PID"
                    )
                await write_memory(remote, scratch, b"\0" * 8)
                await expect_ok(remote, f"Z1,{initial.pc:x},4")
                breakpoint_address = initial.pc
                wait_registers = {
                    "0": child,
                    "1": scratch,
                    "2": 1,
                    "1e": initial.pc,
                    "20": waitpid_stub,
                }
                for register, value in wait_registers.items():
                    await set_register(remote, register, value, initial.thread)
                stopped = False
                returned = StopState.parse(
                    await remote.continue_thread(initial.thread)
                )
                stopped = True
                if (
                    returned.thread.lower() != initial.thread.lower()
                    or returned.pc != initial.pc
                ):
                    raise ProtocolError(
                        "waitpid did not return to the carrier breakpoint"
                    )
                wait_result = struct.unpack(
                    "<i", struct.pack("<I", returned.x0 & 0xFFFFFFFF)
                )[0]
                wait_status = struct.unpack(
                    "<I", await read_memory(remote, scratch, 4)
                )[0]
                if wait_result == child:
                    if wait_status & 0x7F:
                        disposition = f"signal={wait_status & 0x7f}"
                    else:
                        disposition = f"exit={(wait_status >> 8) & 0xff}"
                elif wait_result == 0:
                    disposition = "still-running"
                else:
                    disposition = "waitpid-error"
                print(
                    f"waitpid-result requested={child} result={wait_result} "
                    f"status=0x{wait_status:08x} {disposition}"
                )
                if wait_result not in {0, child}:
                    raise ProtocolError(
                        f"waitpid returned unexpected result {wait_result}"
                    )
                return 0

            if args.inspect_owned_child_status is not None:
                child = args.inspect_owned_child_status
                await write_memory(remote, scratch, b"\0" * 8)
                await expect_ok(remote, f"Z1,{initial.pc:x},4")
                breakpoint_address = initial.pc
                wait_registers = {
                    "0": child,
                    "1": scratch,
                    "2": 3,
                    "1e": initial.pc,
                    "20": waitpid_stub,
                }
                for register, value in wait_registers.items():
                    await set_register(
                        remote, register, value, initial.thread
                    )
                stopped = False
                returned = StopState.parse(
                    await remote.continue_thread(initial.thread)
                )
                stopped = True
                if (
                    returned.thread.lower() != initial.thread.lower()
                    or returned.pc != initial.pc
                ):
                    raise ProtocolError(
                        "owned-child status check did not return to the "
                        "carrier breakpoint"
                    )
                wait_result = struct.unpack(
                    "<i", struct.pack("<I", returned.x0 & 0xFFFFFFFF)
                )[0]
                wait_status = struct.unpack(
                    "<I", await read_memory(remote, scratch, 4)
                )[0]
                if wait_result == 0:
                    disposition = "running"
                elif wait_result == child and (wait_status & 0x7F) == 0x7F:
                    disposition = f"stopped signal={(wait_status >> 8) & 0xff}"
                elif wait_result == child and (wait_status & 0x7F) != 0:
                    disposition = f"signaled signal={wait_status & 0x7f}"
                elif wait_result == child:
                    disposition = f"exited status={(wait_status >> 8) & 0xff}"
                else:
                    disposition = "not-owned-or-error"
                print(
                    f"owned-child-status requested={child} result="
                    f"{wait_result} status=0x{wait_status:08x} "
                    f"{disposition}"
                )
                return 0

            if (
                args.resume_owned_child is not None
                or args.terminate_owned_child is not None
            ):
                child = (
                    args.resume_owned_child
                    if args.resume_owned_child is not None
                    else args.terminate_owned_child
                )
                await write_memory(remote, scratch, b"\0" * 8)
                await expect_ok(remote, f"Z1,{initial.pc:x},4")
                breakpoint_address = initial.pc
                wait_registers = {
                    "0": child,
                    "1": scratch,
                    "2": 1,
                    "1e": initial.pc,
                    "20": waitpid_stub,
                }
                for register, value in wait_registers.items():
                    await set_register(
                        remote, register, value, initial.thread
                    )
                stopped = False
                returned = StopState.parse(
                    await remote.continue_thread(initial.thread)
                )
                stopped = True
                if (
                    returned.thread.lower() != initial.thread.lower()
                    or returned.pc != initial.pc
                ):
                    raise ProtocolError(
                        "owned-child validation did not return to the "
                        "carrier breakpoint"
                    )
                wait_result = struct.unpack(
                    "<i", struct.pack("<I", returned.x0 & 0xFFFFFFFF)
                )[0]
                wait_status = struct.unpack(
                    "<I", await read_memory(remote, scratch, 4)
                )[0]
                if wait_result != 0:
                    disposition = (
                        f"reaped status=0x{wait_status:08x}"
                        if wait_result == child
                        else f"waitpid-result={wait_result}"
                    )
                    raise ProtocolError(
                        f"PID {child} is not a live child of the validated "
                        f"carrier ({disposition})"
                    )
                print(
                    f"owned-child-validation pid={child} live=1 parent="
                    f"{args.pid}"
                )

            if args.copy_broker_log:
                spawn_arguments = COPY_BROKER_LOG_ARGUMENTS
            elif args.copy_live_runtime:
                spawn_arguments = COPY_LIVE_RUNTIME_ARGUMENTS
            elif args.copy_live_launcher:
                spawn_arguments = COPY_LIVE_LAUNCHER_ARGUMENTS
            elif args.launch_runtime_broker:
                spawn_arguments = LAUNCH_RUNTIME_BROKER_ARGUMENTS
            elif args.copy_live_launcher_log:
                spawn_arguments = COPY_LIVE_LAUNCHER_LOG_ARGUMENTS
            elif args.backup_runtime:
                spawn_arguments = BACKUP_RUNTIME_ARGUMENTS
            elif args.stage_runtime_v21:
                spawn_arguments = STAGE_RUNTIME_V21_ARGUMENTS
            elif args.copy_staged_runtime_v21:
                spawn_arguments = COPY_STAGED_RUNTIME_V21_ARGUMENTS
            elif args.activate_staged_runtime:
                spawn_arguments = ACTIVATE_STAGED_RUNTIME_ARGUMENTS
            elif args.stage_runtime_rollback:
                spawn_arguments = STAGE_RUNTIME_ROLLBACK_ARGUMENTS
            elif args.stage_runtime_v22:
                spawn_arguments = STAGE_RUNTIME_V22_ARGUMENTS
            elif args.copy_runtime_v22:
                spawn_arguments = COPY_RUNTIME_V22_ARGUMENTS
            elif args.stage_launcher_v22:
                spawn_arguments = STAGE_LAUNCHER_V22_ARGUMENTS
            elif args.copy_launcher_v22:
                spawn_arguments = COPY_LAUNCHER_V22_ARGUMENTS
            elif args.launch_runtime_broker_v22_resident:
                spawn_arguments = LAUNCH_RUNTIME_BROKER_V22_ARGUMENTS
            elif args.copy_launcher_v22_log:
                spawn_arguments = COPY_LAUNCHER_V22_LOG_ARGUMENTS
            elif args.copy_runtime_v22_marker:
                spawn_arguments = COPY_RUNTIME_V22_MARKER_ARGUMENTS
            elif args.stage_worker_fresh_dylib_canary:
                spawn_arguments = STAGE_WORKER_FRESH_DYLIB_ARGUMENTS
            elif args.copy_worker_fresh_dylib_canary:
                spawn_arguments = COPY_WORKER_FRESH_DYLIB_ARGUMENTS
            elif args.run_worker_fresh_dylib_canary:
                spawn_arguments = RUN_WORKER_FRESH_DYLIB_ARGUMENTS
            elif args.cleanup_worker_fresh_dylib_canary:
                spawn_arguments = CLEANUP_WORKER_FRESH_DYLIB_ARGUMENTS
            elif args.stage_jsc_data_probe:
                spawn_arguments = STAGE_JSC_DATA_PROBE_ARGUMENTS
            elif args.stage_donor_remap_page:
                spawn_arguments = STAGE_DONOR_REMAP_PAGE_ARGUMENTS
            elif args.launch_donor_remap_page:
                spawn_arguments = LAUNCH_DONOR_REMAP_PAGE_ARGUMENTS
            elif args.stage_donor_remap_host:
                spawn_arguments = STAGE_DONOR_REMAP_HOST_ARGUMENTS
            elif args.launch_donor_remap_host:
                spawn_arguments = LAUNCH_DONOR_REMAP_HOST_ARGUMENTS
            elif args.stage_springboard_copy:
                spawn_arguments = STAGE_SPRINGBOARD_COPY_ARGUMENTS
            elif args.stage_springboard_copy_spawn_probe:
                spawn_arguments = STAGE_SPRINGBOARD_COPY_SPAWN_PROBE_ARGUMENTS
            elif args.run_springboard_copy_spawn_probe is not None:
                if args.run_springboard_copy_spawn_probe <= 1:
                    raise ProtocolError("refusing PID 1 or invalid SpringBoard PID")
                spawn_arguments = (
                    WORKER_PATH,
                    "--macho",
                    SPRINGBOARD_COPY_SPAWN_PROBE_PATH,
                    str(args.run_springboard_copy_spawn_probe),
                )
            elif args.stage_springboard_candidate:
                spawn_arguments = STAGE_SPRINGBOARD_CANDIDATE_ARGUMENTS
            elif args.copy_springboard_candidate:
                spawn_arguments = COPY_SPRINGBOARD_CANDIDATE_ARGUMENTS
            elif args.stage_springboard_candidate_bundle:
                spawn_arguments = STAGE_SPRINGBOARD_CANDIDATE_BUNDLE_ARGUMENTS
            elif args.copy_springboard_candidate_bundle:
                spawn_arguments = COPY_SPRINGBOARD_CANDIDATE_BUNDLE_ARGUMENTS
            elif args.trust_springboard_candidate:
                spawn_arguments = TRUST_SPRINGBOARD_CANDIDATE_ARGUMENTS
            elif args.copy_springboard_candidate_trust_log:
                spawn_arguments = COPY_SPRINGBOARD_CANDIDATE_TRUST_LOG_ARGUMENTS
            elif args.stage_springboard_candidate_probe:
                spawn_arguments = STAGE_SPRINGBOARD_CANDIDATE_PROBE_ARGUMENTS
            elif args.copy_springboard_candidate_probe:
                spawn_arguments = COPY_SPRINGBOARD_CANDIDATE_PROBE_ARGUMENTS
            elif args.copy_springboard_candidate_probe_report:
                spawn_arguments = (
                    COPY_SPRINGBOARD_CANDIDATE_PROBE_REPORT_ARGUMENTS
                )
            elif args.copy_springboard_direct_proof_log:
                spawn_arguments = COPY_SPRINGBOARD_DIRECT_PROOF_LOG_ARGUMENTS
            elif args.copy_springboard_direct_wrapper_log:
                spawn_arguments = COPY_SPRINGBOARD_DIRECT_WRAPPER_LOG_ARGUMENTS
            elif args.run_springboard_candidate_probe is not None:
                if args.run_springboard_candidate_probe <= 1:
                    raise ProtocolError("refusing PID 1 or invalid SpringBoard PID")
                spawn_arguments = (
                    "/var/jb/usr/bin/dash",
                    "-c",
                    "exec /var/jb/usr/libexec/codex-exec-worker --macho "
                    "/var/jb/usr/libexec/"
                    "codex-springboard-candidate-admission-probe "
                    f"{args.run_springboard_candidate_probe} "
                    ">/dev/null 2>&1",
                )
            elif args.stage_ellekit_loader_candidate:
                spawn_arguments = STAGE_ELLEKIT_LOADER_CANDIDATE_ARGUMENTS
            elif args.copy_ellekit_loader_candidate:
                spawn_arguments = COPY_ELLEKIT_LOADER_CANDIDATE_ARGUMENTS
            elif args.inspect_with_ellekit_loader_candidate is not None:
                if args.inspect_with_ellekit_loader_candidate <= 1:
                    raise ProtocolError("refusing PID 1 or invalid target PID")
                spawn_arguments = (
                    WORKER_PATH,
                    "--macho",
                    ELLEKIT_LOADER_CANDIDATE_PATH,
                    "--inspect-pid",
                    str(args.inspect_with_ellekit_loader_candidate),
                )
            elif args.stage_dyld_jb_admission_hook:
                spawn_arguments = STAGE_DYLD_JB_ADMISSION_HOOK_ARGUMENTS
            elif args.copy_dyld_jb_admission_hook:
                spawn_arguments = COPY_DYLD_JB_ADMISSION_HOOK_ARGUMENTS
            elif args.trust_dyld_jb_admission_hook:
                spawn_arguments = TRUST_DYLD_JB_ADMISSION_HOOK_ARGUMENTS
            elif args.copy_dyld_jb_admission_hook_trust_log:
                spawn_arguments = (
                    COPY_DYLD_JB_ADMISSION_HOOK_TRUST_LOG_ARGUMENTS
                )
            elif args.copy_dyld_jb_admission_hook_status:
                spawn_arguments = COPY_DYLD_JB_ADMISSION_HOOK_STATUS_ARGUMENTS
            elif args.stage_springboard_live_precursor:
                spawn_arguments = STAGE_SPRINGBOARD_LIVE_PRECURSOR_ARGUMENTS
            elif args.stage_springboard_live_canary:
                spawn_arguments = STAGE_SPRINGBOARD_LIVE_CANARY_ARGUMENTS
            elif args.copy_springboard_live_canary:
                spawn_arguments = COPY_SPRINGBOARD_LIVE_CANARY_ARGUMENTS
            elif args.stage_springboard_candidate_service_plist:
                spawn_arguments = (
                    STAGE_SPRINGBOARD_CANDIDATE_SERVICE_PLIST_ARGUMENTS
                )
            elif args.copy_springboard_candidate_service_plist:
                spawn_arguments = (
                    COPY_SPRINGBOARD_CANDIDATE_SERVICE_PLIST_ARGUMENTS
                )
            elif args.copy_springboard_live_precursor:
                spawn_arguments = COPY_SPRINGBOARD_LIVE_PRECURSOR_ARGUMENTS
            elif args.run_springboard_watchdog_arm_test:
                spawn_arguments = RUN_SPRINGBOARD_WATCHDOG_ARM_TEST_ARGUMENTS
            elif args.run_springboard_live_precursor:
                spawn_arguments = RUN_SPRINGBOARD_LIVE_PRECURSOR_ARGUMENTS
            elif args.soften_cryptexd is not None:
                if args.soften_cryptexd <= 1:
                    raise ProtocolError("refusing PID 1 or invalid cryptexd PID")
                spawn_arguments = (
                    "/var/jb/usr/bin/sh",
                    "-c",
                    "exec /var/jb/usr/libexec/codex-exec-worker --macho "
                    "/var/jb/usr/libexec/codex-springboard-live-precursor "
                    f"--soften-cryptexd {args.soften_cryptexd} "
                    ">/var/mobile/Media/codex-cryptexd-soften.txt 2>&1",
                )
            elif args.run_springboard_external_live_proof:
                spawn_arguments = RUN_SPRINGBOARD_EXTERNAL_LIVE_PROOF_ARGUMENTS
            elif args.run_springboard_external_parallel_bind_audit:
                spawn_arguments = (
                    RUN_SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_ARGUMENTS
                )
            elif args.run_springboard_external_parallel_live_proof:
                spawn_arguments = (
                    RUN_SPRINGBOARD_EXTERNAL_PARALLEL_LIVE_PROOF_ARGUMENTS
                )
            elif args.copy_springboard_external_parallel_bind_audit_log:
                spawn_arguments = (
                    COPY_SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_LOG_ARGUMENTS
                )
            elif args.capture_springboard_external_candidate_print:
                spawn_arguments = (
                    CAPTURE_SPRINGBOARD_EXTERNAL_CANDIDATE_PRINT_ARGUMENTS
                )
            elif args.run_springboard_external_service_removal_audit:
                spawn_arguments = (
                    RUN_SPRINGBOARD_EXTERNAL_SERVICE_REMOVAL_AUDIT_ARGUMENTS
                )
            elif args.copy_springboard_external_live_proof_log:
                spawn_arguments = (
                    COPY_SPRINGBOARD_EXTERNAL_LIVE_PROOF_LOG_ARGUMENTS
                )
            elif args.copy_springboard_live_precursor_log:
                spawn_arguments = COPY_SPRINGBOARD_LIVE_PRECURSOR_LOG_ARGUMENTS
            elif args.capture_launchctl_debug_help:
                spawn_arguments = CAPTURE_LAUNCHCTL_DEBUG_HELP_ARGUMENTS
            elif args.stage_apple_launchctl:
                spawn_arguments = STAGE_APPLE_LAUNCHCTL_ARGUMENTS
            elif args.copy_apple_launchctl:
                spawn_arguments = COPY_APPLE_LAUNCHCTL_ARGUMENTS
            elif args.capture_apple_launchctl_debug_help:
                spawn_arguments = CAPTURE_APPLE_LAUNCHCTL_DEBUG_HELP_ARGUMENTS
            elif args.capture_system_launchctl_paths:
                spawn_arguments = CAPTURE_SYSTEM_LAUNCHCTL_PATHS_ARGUMENTS
            elif args.stage_dyld_interpose_probe:
                spawn_arguments = STAGE_DYLD_INTERPOSE_PROBE_ARGUMENTS
            elif args.run_dyld_interpose_probe is not None:
                spawn_arguments = (
                    *RUN_DYLD_INTERPOSE_PROBE_ARGUMENTS,
                    args.run_dyld_interpose_probe,
                )
            elif args.stage_dtrace_presence_probe:
                spawn_arguments = STAGE_DTRACE_PRESENCE_PROBE_ARGUMENTS
            elif args.run_dtrace_presence_probe:
                spawn_arguments = RUN_DTRACE_PRESENCE_PROBE_ARGUMENTS
            elif args.stage_cryptex_mount_topology_probe:
                spawn_arguments = STAGE_CRYPTEX_MOUNT_TOPOLOGY_PROBE_ARGUMENTS
            elif args.run_cryptex_mount_topology_probe:
                spawn_arguments = RUN_CRYPTEX_MOUNT_TOPOLOGY_PROBE_ARGUMENTS
            elif args.stage_amfid_admission_canary:
                spawn_arguments = STAGE_AMFID_ADMISSION_CANARY_ARGUMENTS
            elif args.run_amfid_admission_canary:
                spawn_arguments = RUN_AMFID_ADMISSION_CANARY_ARGUMENTS
            elif args.kickstart_amfid:
                spawn_arguments = KICKSTART_AMFID_ARGUMENTS
            elif args.stage_springboard_csops_status_probe:
                spawn_arguments = STAGE_SPRINGBOARD_CSOPS_STATUS_PROBE_ARGUMENTS
            elif args.run_springboard_csops_status_probe is not None:
                if args.run_springboard_csops_status_probe <= 1:
                    raise ProtocolError("refusing PID 1 or invalid SpringBoard PID")
                spawn_arguments = (
                    WORKER_PATH,
                    "--macho",
                    SPRINGBOARD_CSOPS_STATUS_PROBE_PATH,
                    str(args.run_springboard_csops_status_probe),
                )
            elif args.stage_launch_type_canary_copy:
                spawn_arguments = STAGE_LAUNCH_TYPE_CANARY_COPY_ARGUMENTS
            elif args.stage_launch_type_canary_plist:
                spawn_arguments = STAGE_LAUNCH_TYPE_CANARY_PLIST_ARGUMENTS
            elif args.bootstrap_launch_type_canary:
                spawn_arguments = BOOTSTRAP_LAUNCH_TYPE_CANARY_ARGUMENTS
            elif args.bootout_launch_type_canary:
                spawn_arguments = BOOTOUT_LAUNCH_TYPE_CANARY_ARGUMENTS
            elif args.print_launch_type_canary:
                spawn_arguments = PRINT_LAUNCH_TYPE_CANARY_ARGUMENTS
            elif args.print_springboard_launch_service:
                spawn_arguments = PRINT_SPRINGBOARD_LAUNCH_ARGUMENTS
            elif args.kickstart_launch_type_canary:
                spawn_arguments = KICKSTART_LAUNCH_TYPE_CANARY_ARGUMENTS
            elif args.print_sealed_springboard_job:
                spawn_arguments = PRINT_SEALED_SPRINGBOARD_JOB_ARGUMENTS
            elif args.kickstart_sealed_springboard_job:
                spawn_arguments = KICKSTART_SEALED_SPRINGBOARD_JOB_ARGUMENTS
            elif args.bootout_sealed_springboard_job:
                spawn_arguments = BOOTOUT_SEALED_SPRINGBOARD_JOB_ARGUMENTS
            elif args.copy_system_launchd_artifact:
                spawn_arguments = COPY_SYSTEM_LAUNCHD_ARTIFACT_ARGUMENTS
            elif args.copy_system_cryptexd_artifact:
                spawn_arguments = COPY_SYSTEM_CRYPTEXD_ARTIFACT_ARGUMENTS
            elif args.copy_system_dyld_artifact:
                spawn_arguments = COPY_SYSTEM_DYLD_ARTIFACT_ARGUMENTS
            elif args.copy_system_springboard_plist:
                spawn_arguments = COPY_SYSTEM_SPRINGBOARD_PLIST_ARGUMENTS
            elif args.copy_system_springboard_info:
                spawn_arguments = COPY_SYSTEM_SPRINGBOARD_INFO_ARGUMENTS
            elif args.copy_system_springboard_bundle_manifest:
                spawn_arguments = (
                    COPY_SYSTEM_SPRINGBOARD_BUNDLE_MANIFEST_ARGUMENTS
                )
            elif args.clone_system_springboard_candidate_bundle:
                spawn_arguments = CLONE_SPRINGBOARD_CANDIDATE_BUNDLE_ARGUMENTS
            elif args.copy_springboard_candidate_bundle_manifest:
                spawn_arguments = (
                    COPY_SPRINGBOARD_CANDIDATE_BUNDLE_MANIFEST_ARGUMENTS
                )
            elif args.run_jsc_data_probe:
                spawn_arguments = RUN_JSC_DATA_PROBE_ARGUMENTS
            elif args.stage_jsc_springboard_probe:
                spawn_arguments = STAGE_JSC_SPRINGBOARD_PROBE_ARGUMENTS
            elif args.run_jsc_springboard_probe is not None:
                spawn_arguments = (
                    WORKER_PATH,
                    "--macho",
                    JSC_SPRINGBOARD_PROBE_PATH,
                    str(args.run_jsc_springboard_probe),
                )
            elif args.resume_owned_child is not None:
                spawn_arguments = (
                    KILL_PATH,
                    "-CONT",
                    str(args.resume_owned_child),
                )
            elif args.terminate_owned_child is not None:
                spawn_arguments = (
                    KILL_PATH,
                    "-KILL",
                    str(args.terminate_owned_child),
                )
            elif args.terminate_verified_orphan is not None:
                spawn_arguments = (
                    KILL_PATH,
                    "-KILL",
                    str(args.terminate_verified_orphan),
                )
            elif args.springboard_inspect_pid is not None:
                spawn_arguments = (
                    LOADER_PATH,
                    "--inspect-pid",
                    str(args.springboard_inspect_pid),
                )
            elif args.springboard_page_probe is not None:
                spawn_arguments = (
                    LOADER_PATH,
                    "--page-probe-pid",
                    str(args.springboard_page_probe),
                )
            elif args.springboard_resident_hook is not None:
                spawn_arguments = (
                    "/var/jb/usr/bin/sh",
                    "-c",
                    f"exec {LOADER_PATH} --inject-pid "
                    f"{args.springboard_resident_hook} "
                    f"{DYLD_JB_ADMISSION_HOOK_PATH} "
                    ">/var/mobile/Media/"
                    "codex-springboard-resident-hook-run.txt 2>&1",
                )
            elif args.springboard_resident_canary is not None:
                spawn_arguments = (
                    "/var/jb/usr/bin/sh",
                    "-c",
                    f"exec {LOADER_PATH} --inject-pid "
                    f"{args.springboard_resident_canary} "
                    f"{SPRINGBOARD_LIVE_CANARY_PATH} "
                    ">/var/mobile/Media/"
                    "codex-springboard-resident-canary-run.txt 2>&1",
                )
            else:
                spawn_arguments = WORKER_ARGUMENTS
            payload, argv_address, envp_address, pid_address = (
                build_spawn_payload(scratch, spawn_arguments)
            )
            await write_memory(remote, scratch, payload)

            await expect_ok(remote, f"Z1,{initial.pc:x},4")
            breakpoint_address = initial.pc

            register_values = {
                "0": pid_address,
                "1": scratch,
                "2": 0,
                "3": 0,
                "4": argv_address,
                "5": envp_address,
                "1e": initial.pc,
                "20": spawn_stub,
            }
            for register, value in register_values.items():
                await set_register(remote, register, value, initial.thread)
            for register, expected in register_values.items():
                observed = await read_register(remote, register, initial.thread)
                if observed != expected:
                    raise ProtocolError(
                        f"register {register} verification failed: "
                        f"expected 0x{expected:x}, got 0x{observed:x}"
                    )

            stopped = False
            returned = StopState.parse(
                await remote.continue_thread(initial.thread)
            )
            stopped = True
            if returned.thread.lower() != initial.thread.lower():
                raise ProtocolError(
                    f"unexpected stopped thread: {returned.thread}"
                )
            if returned.pc != initial.pc:
                raise ProtocolError(
                    f"posix_spawn did not return to carrier breakpoint: "
                    f"pc=0x{returned.pc:x} expected=0x{initial.pc:x}"
                )

            spawn_result = returned.x0 & 0xFFFFFFFF
            child_pid = struct.unpack(
                "<i", await read_memory(remote, pid_address, 4)
            )[0]
            print(
                f"spawn-return result={spawn_result} child-pid={child_pid} "
                f"command={' '.join(spawn_arguments)}"
            )
            if spawn_result != 0:
                raise ProtocolError(
                    f"posix_spawn returned error {spawn_result}"
                )
            if child_pid <= 1:
                raise ProtocolError(
                    f"posix_spawn returned invalid child PID {child_pid}"
                )
            if (
                args.copy_broker_log
                or args.copy_live_runtime
                or args.copy_live_launcher
                or args.launch_runtime_broker
                or args.copy_live_launcher_log
                or args.backup_runtime
                or args.stage_runtime_v21
                or args.copy_staged_runtime_v21
                or args.activate_staged_runtime
                or args.stage_runtime_rollback
                or args.stage_runtime_v22
                or args.copy_runtime_v22
                or args.stage_launcher_v22
                or args.copy_launcher_v22
                or args.copy_launcher_v22_log
                or args.copy_runtime_v22_marker
                or args.stage_worker_fresh_dylib_canary
                or args.copy_worker_fresh_dylib_canary
                or args.run_worker_fresh_dylib_canary
                or args.cleanup_worker_fresh_dylib_canary
                or args.stage_jsc_data_probe
                or args.stage_donor_remap_page
                or args.stage_donor_remap_host
                or args.stage_springboard_copy
                or args.stage_springboard_copy_spawn_probe
                or args.run_springboard_copy_spawn_probe is not None
                or args.stage_springboard_candidate
                or args.copy_springboard_candidate
                or args.stage_springboard_candidate_bundle
                or args.copy_springboard_candidate_bundle
                or args.trust_springboard_candidate
                or args.copy_springboard_candidate_trust_log
                or args.stage_springboard_candidate_probe
                or args.copy_springboard_candidate_probe
                or args.copy_springboard_candidate_probe_report
                or args.copy_springboard_direct_proof_log
                or args.copy_springboard_direct_wrapper_log
                or args.run_springboard_candidate_probe is not None
                or args.stage_ellekit_loader_candidate
                or args.copy_ellekit_loader_candidate
                or args.inspect_with_ellekit_loader_candidate is not None
                or args.stage_dyld_jb_admission_hook
                or args.copy_dyld_jb_admission_hook
                or args.trust_dyld_jb_admission_hook
                or args.copy_dyld_jb_admission_hook_trust_log
                or args.copy_dyld_jb_admission_hook_status
                or args.stage_springboard_live_precursor
                or args.stage_springboard_live_canary
                or args.copy_springboard_live_canary
                or args.stage_springboard_candidate_service_plist
                or args.copy_springboard_candidate_service_plist
                or args.copy_springboard_live_precursor
                or args.run_springboard_watchdog_arm_test
                or args.run_springboard_live_precursor
                or args.soften_cryptexd is not None
                or args.run_springboard_external_live_proof
                or args.run_springboard_external_parallel_bind_audit
                or args.run_springboard_external_parallel_live_proof
                or args.copy_springboard_external_parallel_bind_audit_log
                or args.capture_springboard_external_candidate_print
                or args.run_springboard_external_service_removal_audit
                or args.copy_springboard_external_live_proof_log
                or args.copy_springboard_live_precursor_log
                or args.stage_dyld_interpose_probe
                or args.run_dyld_interpose_probe is not None
                or args.stage_dtrace_presence_probe
                or args.run_dtrace_presence_probe
                or args.stage_cryptex_mount_topology_probe
                or args.run_cryptex_mount_topology_probe
                or args.stage_amfid_admission_canary
                or args.run_amfid_admission_canary
                or args.kickstart_amfid
                or args.stage_springboard_csops_status_probe
                or args.run_springboard_csops_status_probe is not None
                or args.stage_launch_type_canary_copy
                or args.stage_launch_type_canary_plist
                or args.bootstrap_launch_type_canary
                or args.bootout_launch_type_canary
                or args.print_launch_type_canary
                or args.print_springboard_launch_service
                or args.kickstart_launch_type_canary
                or args.print_sealed_springboard_job
                or args.kickstart_sealed_springboard_job
                or args.bootout_sealed_springboard_job
                or args.copy_system_launchd_artifact
                or args.copy_system_cryptexd_artifact
                or args.copy_system_dyld_artifact
                or args.copy_system_springboard_plist
                or args.copy_system_springboard_info
                or args.copy_system_springboard_bundle_manifest
                or args.clone_system_springboard_candidate_bundle
                or args.copy_springboard_candidate_bundle_manifest
                or args.run_jsc_data_probe
                or args.stage_jsc_springboard_probe
                or args.run_jsc_springboard_probe is not None
                or args.resume_owned_child is not None
                or args.terminate_owned_child is not None
                or args.terminate_verified_orphan is not None
                or args.springboard_inspect_pid is not None
                or args.springboard_page_probe is not None
                or args.springboard_resident_hook is not None
                or args.springboard_resident_canary is not None
            ):
                await write_memory(remote, scratch, b"\0" * 8)
                wait_registers = {
                    "0": child_pid,
                    "1": scratch,
                    "2": 0,
                    "1e": initial.pc,
                    "20": waitpid_stub,
                }
                for register, value in wait_registers.items():
                    await set_register(remote, register, value, initial.thread)
                stopped = False
                waited = StopState.parse(
                    await remote.continue_thread(initial.thread)
                )
                stopped = True
                if (
                    waited.thread.lower() != initial.thread.lower()
                    or waited.pc != initial.pc
                ):
                    raise ProtocolError(
                        "waitpid did not return to the carrier breakpoint"
                    )
                wait_result = struct.unpack(
                    "<i", struct.pack("<I", waited.x0 & 0xFFFFFFFF)
                )[0]
                wait_status = struct.unpack(
                    "<I", await read_memory(remote, scratch, 4)
                )[0]
                if wait_result != child_pid:
                    raise ProtocolError(
                        f"waitpid returned {wait_result}, expected {child_pid}"
                    )
                if args.run_amfid_admission_canary:
                    if (wait_status & 0x7F) == 0x7F:
                        canary_disposition = (
                            f"stopped-signal={(wait_status >> 8) & 0xFF}"
                        )
                    elif wait_status & 0x7F:
                        canary_disposition = f"signal={wait_status & 0x7F}"
                    else:
                        canary_disposition = (
                            f"exit={(wait_status >> 8) & 0xFF}"
                        )
                    print(
                        "amfid-admission-canary-wait "
                        f"child-pid={child_pid} "
                        f"status=0x{wait_status:08x} "
                        f"{canary_disposition}"
                    )
                elif wait_status & 0x7F or ((wait_status >> 8) & 0xFF) != 0:
                    raise ProtocolError(
                        f"allowlisted child failed with wait status "
                        f"0x{wait_status:08x}"
                    )
                if args.copy_broker_log:
                    print(
                        f"broker-log-copy=success child-pid={child_pid} "
                        f"destination={BROKER_LOG_DESTINATION}"
                    )
                elif args.copy_live_runtime:
                    print(
                        f"live-runtime-copy=success child-pid={child_pid} "
                        f"destination={LIVE_RUNTIME_DESTINATION}"
                    )
                elif args.copy_live_launcher:
                    print(
                        f"live-launcher-copy=success child-pid={child_pid} "
                        f"destination={LIVE_LAUNCHER_DESTINATION}"
                    )
                elif args.launch_runtime_broker:
                    print(
                        f"runtime-broker-launch=success child-pid={child_pid}"
                    )
                elif args.copy_live_launcher_log:
                    print(
                        f"live-launcher-log-copy=success child-pid={child_pid} "
                        f"destination={LIVE_LAUNCHER_LOG_DESTINATION}"
                    )
                elif args.backup_runtime:
                    print(
                        f"runtime-backup=success child-pid={child_pid} "
                        f"destination={RUNTIME_ROLLBACK_PATH}"
                    )
                elif args.stage_runtime_v21:
                    print(
                        f"runtime-v21-stage=success child-pid={child_pid} "
                        f"destination={RUNTIME_STAGE_PATH}"
                    )
                elif args.copy_staged_runtime_v21:
                    print(
                        f"runtime-v21-stage-copy=success child-pid={child_pid} "
                        f"destination={RUNTIME_STAGE_VERIFY_PATH}"
                    )
                elif args.activate_staged_runtime:
                    print(
                        f"runtime-stage-activate=success child-pid={child_pid} "
                        f"destination={LIVE_RUNTIME_SOURCE}"
                    )
                elif args.stage_runtime_rollback:
                    print(
                        f"runtime-rollback-stage=success child-pid={child_pid} "
                        f"destination={RUNTIME_STAGE_PATH}"
                    )
                elif args.stage_runtime_v22:
                    print(
                        f"runtime-v22-stage=success child-pid={child_pid} "
                        f"destination={RUNTIME_V22_PATH}"
                    )
                elif args.copy_runtime_v22:
                    print(
                        f"runtime-v22-copy=success child-pid={child_pid} "
                        f"destination={RUNTIME_V22_VERIFY_PATH}"
                    )
                elif args.stage_launcher_v22:
                    print(
                        f"launcher-v22-stage=success child-pid={child_pid} "
                        f"destination={LAUNCHER_V22_PATH}"
                    )
                elif args.copy_launcher_v22:
                    print(
                        f"launcher-v22-copy=success child-pid={child_pid} "
                        f"destination={LAUNCHER_V22_VERIFY_PATH}"
                    )
                elif args.copy_launcher_v22_log:
                    print(
                        f"launcher-v22-log-copy=success child-pid={child_pid} "
                        f"destination={LAUNCHER_V22_LOG_DESTINATION}"
                    )
                elif args.copy_runtime_v22_marker:
                    print(
                        f"runtime-v22-marker-copy=success child-pid={child_pid} "
                        f"destination={RUNTIME_V22_MARKER_DESTINATION}"
                    )
                elif args.stage_worker_fresh_dylib_canary:
                    print(
                        "worker-fresh-dylib-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={WORKER_FRESH_DYLIB_PATH}"
                    )
                elif args.copy_worker_fresh_dylib_canary:
                    print(
                        "worker-fresh-dylib-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={WORKER_FRESH_DYLIB_VERIFY_PATH}"
                    )
                elif args.run_worker_fresh_dylib_canary:
                    print(
                        "worker-fresh-dylib-run=success "
                        f"child-pid={child_pid} "
                        f"stdout={WORKER_FRESH_DYLIB_STDOUT_PATH} "
                        f"stderr={WORKER_FRESH_DYLIB_STDERR_PATH}"
                    )
                elif args.cleanup_worker_fresh_dylib_canary:
                    print(
                        "worker-fresh-dylib-cleanup=success "
                        f"child-pid={child_pid} "
                        f"path={WORKER_FRESH_DYLIB_PATH}"
                    )
                elif args.stage_jsc_data_probe:
                    print(
                        f"jsc-data-probe-stage=success child-pid={child_pid} "
                        f"destination={JSC_DATA_PROBE_PATH}"
                    )
                elif args.stage_donor_remap_page:
                    print(
                        "donor-remap-page-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={DONOR_REMAP_PAGE_PATH}"
                    )
                elif args.stage_donor_remap_host:
                    print(
                        "donor-remap-host-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={DONOR_REMAP_HOST_PATH}"
                    )
                elif args.stage_springboard_copy:
                    print(
                        "springboard-copy-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_COPY_PATH}"
                    )
                elif args.stage_springboard_copy_spawn_probe:
                    print(
                        "springboard-copy-spawn-probe-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_COPY_SPAWN_PROBE_PATH}"
                    )
                elif args.run_springboard_copy_spawn_probe is not None:
                    print(
                        "springboard-copy-spawn-probe=complete "
                        f"child-pid={child_pid} "
                        f"live-springboard-pid="
                        f"{args.run_springboard_copy_spawn_probe}"
                    )
                elif args.stage_springboard_candidate:
                    print(
                        "springboard-candidate-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_CANDIDATE_PATH}"
                    )
                elif args.copy_springboard_candidate:
                    print(
                        "springboard-candidate-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_CANDIDATE_VERIFY_PATH}"
                    )
                elif args.stage_springboard_candidate_bundle:
                    print(
                        "springboard-candidate-bundle-stage=success "
                        f"child-pid={child_pid} "
                        f"executable={SPRINGBOARD_CANDIDATE_BUNDLE_PATH} "
                        f"info={SPRINGBOARD_CANDIDATE_BUNDLE_INFO_PATH}"
                    )
                elif args.copy_springboard_candidate_bundle:
                    print(
                        "springboard-candidate-bundle-copy=success "
                        f"child-pid={child_pid} "
                        f"executable={SPRINGBOARD_CANDIDATE_BUNDLE_VERIFY_PATH} "
                        f"info={SPRINGBOARD_CANDIDATE_BUNDLE_INFO_VERIFY_PATH}"
                    )
                elif args.trust_springboard_candidate:
                    print(
                        "springboard-candidate-runtime-trust=success "
                        f"child-pid={child_pid} "
                        f"log={SPRINGBOARD_CANDIDATE_TRUST_LOG_SOURCE}"
                    )
                elif args.copy_springboard_candidate_trust_log:
                    print(
                        "springboard-candidate-runtime-trust-log-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_CANDIDATE_TRUST_LOG_PATH}"
                    )
                elif args.stage_springboard_candidate_probe:
                    print(
                        "springboard-candidate-probe-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_CANDIDATE_PROBE_PATH}"
                    )
                elif args.copy_springboard_candidate_probe:
                    print(
                        "springboard-candidate-probe-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_CANDIDATE_PROBE_VERIFY_PATH}"
                    )
                elif args.copy_springboard_candidate_probe_report:
                    print(
                        "springboard-candidate-probe-report-copy=success "
                        f"child-pid={child_pid} "
                        "destination="
                        f"{SPRINGBOARD_CANDIDATE_PROBE_REPORT_EXPORT_PATH}"
                    )
                elif args.copy_springboard_direct_proof_log:
                    print(
                        "springboard-direct-proof-log-copy=success "
                        f"child-pid={child_pid} destination="
                        f"{SPRINGBOARD_DIRECT_PROOF_LOG_EXPORT_PATH}"
                    )
                elif args.copy_springboard_direct_wrapper_log:
                    print(
                        "springboard-direct-wrapper-log-copy=success "
                        f"child-pid={child_pid} destination="
                        f"{SPRINGBOARD_DIRECT_WRAPPER_LOG_EXPORT_PATH}"
                    )
                elif args.run_springboard_candidate_probe is not None:
                    print(
                        "springboard-candidate-probe=complete "
                        f"child-pid={child_pid} "
                        "report=/private/var/mobile/Media/"
                        "codex-springboard-candidate-admission-probe.txt"
                    )
                elif args.stage_ellekit_loader_candidate:
                    print(
                        "ellekit-loader-candidate-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={ELLEKIT_LOADER_CANDIDATE_PATH}"
                    )
                elif args.copy_ellekit_loader_candidate:
                    print(
                        "ellekit-loader-candidate-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={ELLEKIT_LOADER_CANDIDATE_VERIFY_PATH}"
                    )
                elif args.inspect_with_ellekit_loader_candidate is not None:
                    print(
                        "ellekit-loader-candidate-inspect=success "
                        f"child-pid={child_pid} "
                        f"target={args.inspect_with_ellekit_loader_candidate}"
                    )
                elif args.stage_dyld_jb_admission_hook:
                    print(
                        "dyld-jb-admission-hook-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={DYLD_JB_ADMISSION_HOOK_PATH}"
                    )
                elif args.copy_dyld_jb_admission_hook:
                    print(
                        "dyld-jb-admission-hook-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={DYLD_JB_ADMISSION_HOOK_VERIFY_PATH}"
                    )
                elif args.trust_dyld_jb_admission_hook:
                    print(
                        "dyld-jb-admission-hook-runtime-trust=success "
                        f"child-pid={child_pid} "
                        f"log={DYLD_JB_ADMISSION_HOOK_TRUST_LOG_SOURCE}"
                    )
                elif args.copy_dyld_jb_admission_hook_trust_log:
                    print(
                        "dyld-jb-admission-hook-trust-log-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={DYLD_JB_ADMISSION_HOOK_TRUST_LOG_PATH}"
                    )
                elif args.copy_dyld_jb_admission_hook_status:
                    print(
                        "dyld-jb-admission-hook-status-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={DYLD_JB_ADMISSION_HOOK_STATUS_PATH}"
                    )
                elif args.stage_springboard_live_precursor:
                    print(
                        "springboard-live-precursor-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_LIVE_PRECURSOR_PATH}"
                    )
                elif args.stage_springboard_live_canary:
                    print(
                        "springboard-live-canary-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_LIVE_CANARY_PATH} trusted=0"
                    )
                elif args.copy_springboard_live_canary:
                    print(
                        "springboard-live-canary-copy=success "
                        f"child-pid={child_pid} destination="
                        f"{SPRINGBOARD_LIVE_CANARY_BACKUP_PATH}"
                    )
                elif args.stage_springboard_candidate_service_plist:
                    print(
                        "springboard-candidate-service-plist-stage=success "
                        f"child-pid={child_pid} destination="
                        f"{SPRINGBOARD_CANDIDATE_SERVICE_PLIST_PATH}"
                    )
                elif args.copy_springboard_candidate_service_plist:
                    print(
                        "springboard-candidate-service-plist-copy=success "
                        f"child-pid={child_pid} destination="
                        f"{SPRINGBOARD_CANDIDATE_SERVICE_PLIST_VERIFY_PATH}"
                    )
                elif args.copy_springboard_live_precursor:
                    print(
                        "springboard-live-precursor-copy=success "
                        f"child-pid={child_pid} "
                        "destination="
                        f"{SPRINGBOARD_LIVE_PRECURSOR_VERIFY_PATH}"
                    )
                elif args.run_springboard_watchdog_arm_test:
                    print(
                        "springboard-watchdog-arm-test=success "
                        f"child-pid={child_pid} mutated=0"
                    )
                elif args.run_springboard_live_precursor:
                    print(
                        "springboard-live-precursor=success "
                        f"child-pid={child_pid} committed=0"
                    )
                elif args.soften_cryptexd is not None:
                    print(
                        "cryptexd-soften=success "
                        f"child-pid={child_pid} target-pid={args.soften_cryptexd} "
                        "output=/var/mobile/Media/codex-cryptexd-soften.txt"
                    )
                elif args.run_springboard_external_live_proof:
                    print(
                        "springboard-external-live-proof=success "
                        f"child-pid={child_pid} "
                        "child-exit-contract=exact-commit-or-exact-rollback"
                    )
                elif args.run_springboard_external_parallel_bind_audit:
                    print(
                        "springboard-external-parallel-bind-audit=success "
                        f"child-pid={child_pid} stock-mutated=0 "
                        "candidate-cleaned=1"
                    )
                elif args.run_springboard_external_parallel_live_proof:
                    print(
                        "springboard-external-parallel-live-proof=success "
                        f"child-pid={child_pid} stock-mutated=0 "
                        "fresh-canary-loaded=1 candidate-cleaned=1"
                    )
                elif args.copy_springboard_external_parallel_bind_audit_log:
                    print(
                        "springboard-external-parallel-bind-audit-log-copy="
                        f"success child-pid={child_pid} destination="
                        f"{SPRINGBOARD_EXTERNAL_PARALLEL_BIND_AUDIT_LOG_PATH}"
                    )
                elif args.capture_springboard_external_candidate_print:
                    print(
                        "springboard-external-candidate-print-capture=success "
                        f"child-pid={child_pid} destination=/var/mobile/Media/"
                        "codex-springboard-external-candidate-print.txt"
                    )
                elif args.run_springboard_external_service_removal_audit:
                    print(
                        "springboard-external-service-removal-audit=success "
                        f"child-pid={child_pid} stock-mutated=0 "
                        "service-absent=1 stock-generation-unchanged=1"
                    )
                elif args.copy_springboard_external_live_proof_log:
                    print(
                        "springboard-external-live-proof-log-copy=success "
                        f"child-pid={child_pid} destination="
                        f"{SPRINGBOARD_EXTERNAL_LIVE_PROOF_LOG_PATH}"
                    )
                elif args.copy_springboard_live_precursor_log:
                    print(
                        "springboard-live-precursor-log-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_LIVE_PRECURSOR_LOG_PATH}"
                    )
                elif args.capture_launchctl_debug_help:
                    print(
                        "launchctl-debug-help-capture=success "
                        f"child-pid={child_pid} destination="
                        "/var/mobile/Media/codex-launchctl-debug-help.txt"
                    )
                elif args.stage_apple_launchctl:
                    print(
                        "apple-launchctl-stage=success "
                        f"child-pid={child_pid} destination={APPLE_LAUNCHCTL_PATH}"
                    )
                elif args.copy_apple_launchctl:
                    print(
                        "apple-launchctl-copy=success "
                        f"child-pid={child_pid} destination="
                        f"{APPLE_LAUNCHCTL_VERIFY_PATH}"
                    )
                elif args.capture_apple_launchctl_debug_help:
                    print(
                        "apple-launchctl-debug-help=success "
                        f"child-pid={child_pid} destination="
                        "/var/mobile/Media/codex-apple-launchctl-debug-help.txt"
                    )
                elif args.capture_system_launchctl_paths:
                    print(
                        "system-launchctl-paths-capture=success "
                        f"child-pid={child_pid} destination="
                        "/var/mobile/Media/codex-system-launchctl-paths.txt"
                    )
                elif args.stage_dyld_interpose_probe:
                    print(
                        "dyld-interpose-probe-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={DYLD_INTERPOSE_PROBE_PATH}"
                    )
                elif args.run_dyld_interpose_probe is not None:
                    print(
                        "dyld-interpose-probe=success "
                        f"child-pid={child_pid} "
                        f"mode={args.run_dyld_interpose_probe}"
                    )
                elif args.stage_dtrace_presence_probe:
                    print(
                        "dtrace-presence-probe-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={DTRACE_PRESENCE_PROBE_PATH}"
                    )
                elif args.run_dtrace_presence_probe:
                    print(
                        "dtrace-presence-probe=success "
                        f"child-pid={child_pid}"
                    )
                elif args.stage_cryptex_mount_topology_probe:
                    print(
                        "cryptex-mount-topology-probe-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={CRYPTEX_MOUNT_TOPOLOGY_PROBE_PATH}"
                    )
                elif args.run_cryptex_mount_topology_probe:
                    print(
                        "cryptex-mount-topology-probe=success "
                        f"child-pid={child_pid}"
                    )
                elif args.stage_amfid_admission_canary:
                    print(
                        "amfid-admission-canary-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={AMFID_ADMISSION_CANARY_PATH}"
                    )
                elif args.run_amfid_admission_canary:
                    print(
                        "amfid-admission-canary-spawn=complete "
                        f"child-pid={child_pid}"
                    )
                elif args.kickstart_amfid:
                    print(
                        "amfid-kickstart=success "
                        f"child-pid={child_pid} "
                        f"service={AMFID_LAUNCH_SERVICE}"
                    )
                elif args.stage_springboard_csops_status_probe:
                    print(
                        "springboard-csops-status-probe-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={SPRINGBOARD_CSOPS_STATUS_PROBE_PATH}"
                    )
                elif args.run_springboard_csops_status_probe is not None:
                    print(
                        "springboard-csops-status-probe=complete "
                        f"child-pid={child_pid} "
                        f"target-pid="
                        f"{args.run_springboard_csops_status_probe}"
                    )
                elif args.stage_launch_type_canary_copy:
                    print(
                        "launch-type-canary-copy-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={LAUNCH_TYPE_CANARY_COPY_PATH}"
                    )
                elif args.stage_launch_type_canary_plist:
                    print(
                        "launch-type-canary-plist-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={LAUNCH_TYPE_CANARY_PLIST_PATH}"
                    )
                elif args.bootstrap_launch_type_canary:
                    print(
                        "launch-type-canary-bootstrap=success "
                        f"child-pid={child_pid}"
                    )
                elif args.bootout_launch_type_canary:
                    print(
                        "launch-type-canary-bootout=success "
                        f"child-pid={child_pid}"
                    )
                elif args.print_launch_type_canary:
                    print(
                        "launch-type-canary-print=success "
                        f"child-pid={child_pid} "
                        f"output={LAUNCH_TYPE_CANARY_PRINT_PATH}"
                    )
                elif args.print_springboard_launch_service:
                    print(
                        "springboard-launch-print=success "
                        f"child-pid={child_pid} "
                        f"output={SPRINGBOARD_LAUNCH_PRINT_PATH}"
                    )
                elif args.kickstart_launch_type_canary:
                    print(
                        "launch-type-canary-kickstart=success "
                        f"child-pid={child_pid}"
                    )
                elif args.print_sealed_springboard_job:
                    print(
                        "sealed-springboard-job-print=success "
                        f"child-pid={child_pid} service="
                        f"{SEALED_SPRINGBOARD_JOB_SERVICE} output="
                        f"{SEALED_SPRINGBOARD_JOB_PRINT_PATH}"
                    )
                elif args.kickstart_sealed_springboard_job:
                    print(
                        "sealed-springboard-job-kickstart=success "
                        f"child-pid={child_pid} service="
                        f"{SEALED_SPRINGBOARD_JOB_SERVICE} "
                        "launchctl-options=-p,-s pid-or-zero-output="
                        f"{SEALED_SPRINGBOARD_JOB_PID_PATH}"
                    )
                elif args.bootout_sealed_springboard_job:
                    print(
                        "sealed-springboard-job-bootout=success "
                        f"child-pid={child_pid} service="
                        f"{SEALED_SPRINGBOARD_JOB_SERVICE}"
                    )
                elif args.copy_system_launchd_artifact:
                    print(
                        "system-launchd-artifact-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SYSTEM_LAUNCHD_ARTIFACT_PATH}"
                    )
                elif args.copy_system_cryptexd_artifact:
                    print(
                        "system-cryptexd-artifact-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SYSTEM_CRYPTEXD_ARTIFACT_PATH}"
                    )
                elif args.copy_system_dyld_artifact:
                    print(
                        "system-dyld-artifact-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SYSTEM_DYLD_ARTIFACT_PATH}"
                    )
                elif args.copy_system_springboard_plist:
                    print(
                        "system-springboard-plist-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SYSTEM_SPRINGBOARD_PLIST_ARTIFACT_PATH}"
                    )
                elif args.copy_system_springboard_info:
                    print(
                        "system-springboard-info-copy=success "
                        f"child-pid={child_pid} "
                        f"destination={SYSTEM_SPRINGBOARD_INFO_ARTIFACT_PATH}"
                    )
                elif args.copy_system_springboard_bundle_manifest:
                    print(
                        "system-springboard-bundle-manifest=success "
                        f"child-pid={child_pid} "
                        "destination="
                        f"{SYSTEM_SPRINGBOARD_BUNDLE_MANIFEST_PATH}"
                    )
                elif args.clone_system_springboard_candidate_bundle:
                    print(
                        "springboard-candidate-full-bundle-clone=success "
                        f"child-pid={child_pid} "
                        "destination=/var/jb/usr/libexec/"
                        "codex-springboard-candidate/SpringBoard.app"
                    )
                elif args.copy_springboard_candidate_bundle_manifest:
                    print(
                        "springboard-candidate-bundle-manifest=success "
                        f"child-pid={child_pid} "
                        "destination="
                        f"{SPRINGBOARD_CANDIDATE_BUNDLE_MANIFEST_PATH}"
                    )
                elif args.run_jsc_data_probe:
                    print(
                        f"jsc-data-probe=success child-pid={child_pid} "
                        f"path={JSC_DATA_PROBE_PATH}"
                    )
                elif args.stage_jsc_springboard_probe:
                    print(
                        f"jsc-springboard-probe-stage=success "
                        f"child-pid={child_pid} "
                        f"destination={JSC_SPRINGBOARD_PROBE_PATH}"
                    )
                elif args.run_jsc_springboard_probe is not None:
                    print(
                        f"jsc-springboard-probe=success "
                        f"child-pid={child_pid} "
                        f"target-pid={args.run_jsc_springboard_probe}"
                    )
                elif args.resume_owned_child is not None:
                    print(
                        f"owned-child-resume=success pid="
                        f"{args.resume_owned_child} helper-pid={child_pid}"
                    )
                elif args.terminate_owned_child is not None:
                    print(
                        f"owned-child-terminate=success pid="
                        f"{args.terminate_owned_child} helper-pid={child_pid}"
                    )
                elif args.terminate_verified_orphan is not None:
                    print(
                        f"verified-orphan-terminate=success pid="
                        f"{args.terminate_verified_orphan} "
                        f"helper-pid={child_pid}"
                    )
                elif args.springboard_inspect_pid is not None:
                    print(
                        f"springboard-inspect=success child-pid={child_pid} "
                        f"target-pid={args.springboard_inspect_pid}"
                    )
                elif args.springboard_resident_hook is not None:
                    print(
                        "springboard-resident-hook=success "
                        f"child-pid={child_pid} "
                        f"target-pid={args.springboard_resident_hook} "
                        "dlclose=omitted removal=reboot"
                    )
                elif args.springboard_resident_canary is not None:
                    print(
                        "springboard-resident-canary=success "
                        f"child-pid={child_pid} "
                        f"target-pid={args.springboard_resident_canary} "
                        "dlclose=omitted removal=reboot"
                    )
                else:
                    print(
                        f"springboard-page-probe=success child-pid={child_pid} "
                        f"target-pid={args.springboard_page_probe}"
                    )
            else:
                if args.launch_runtime_broker_v22_resident:
                    print(
                        f"runtime-broker-v22-resident-spawn=success "
                        f"child-pid={child_pid}"
                    )
                elif args.launch_donor_remap_host:
                    print(
                        "donor-remap-host-spawn=success "
                        f"child-pid={child_pid}"
                    )
                elif args.launch_donor_remap_page:
                    print(
                        "donor-remap-page-spawn=success "
                        f"child-pid={child_pid}"
                    )
                else:
                    print("carrier-self-test-spawn=success")
            return 0
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors: list[str] = []
            if attached and not stopped:
                try:
                    response = await remote.interrupt()
                    stopped = response[:1] in {"T", "S"}
                    print(f"cleanup-interrupt={response}")
                except BaseException as error:
                    cleanup_errors.append(f"interrupt: {error}")

            if attached and stopped:
                if breakpoint_address is not None:
                    try:
                        await expect_ok(
                            remote, f"z1,{breakpoint_address:x},4"
                        )
                        print("cleanup-breakpoint=removed")
                    except BaseException as error:
                        cleanup_errors.append(f"breakpoint: {error}")

                if state_saved and save_identifier is not None:
                    try:
                        await expect_ok(
                            remote,
                            f"QRestoreRegisterState:{save_identifier};"
                            f"thread:{initial.thread};",
                        )
                        state_saved = False
                        print("cleanup-register-state=restored")
                    except BaseException as error:
                        cleanup_errors.append(f"register restore: {error}")

                if scratch is not None:
                    try:
                        await expect_ok(remote, f"_m{scratch:x}")
                        scratch = None
                        print("cleanup-scratch=deallocated")
                    except BaseException as error:
                        cleanup_errors.append(f"scratch deallocation: {error}")

                try:
                    await expect_ok(remote, "D")
                    attached = False
                    print("cleanup-detach=success")
                except BaseException as error:
                    cleanup_errors.append(f"detach: {error}")

            try:
                await connection.close()
            except BaseException as error:
                cleanup_errors.append(f"connection close: {error}")

            if cleanup_errors:
                message = "; ".join(cleanup_errors)
                print(f"cleanup-error: {message}", file=sys.stderr)
                if primary_error is None:
                    raise ProtocolError(message)


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run(args))
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
