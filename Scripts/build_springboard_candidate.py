#!/usr/bin/env python3
"""Build and verify the pinned iPhone 13/iOS 27 SpringBoard replacement.

This is deliberately a local-only operation.  It copies the exact extracted
SpringBoard executable, merges the requested debugging/runtime-code policy
into its original entitlements, and emits a deterministic ad-hoc signature.
It does not contact a device, request a ticket, create a Cryptex, or install
anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import tempfile
from typing import Any


EXPECTED_SOURCE_SHA256 = (
    "db2d73a61739417c14359db4415ac5eb0cc59f86611c158e7413d97b0458b55c"
)
EXPECTED_IDENTIFIER = "com.apple.springboard"
EXPECTED_ARCHITECTURE = "arm64e"
EXPECTED_UUID = "AD937FB7-2664-3B8F-B1C9-34C4AD4092D2"
EXPECTED_INFO_SHA256 = (
    "ce3bfead94676c8daf111f009211467a9c70f6cbceb73e7a0fcde1f03b320703"
)

EXPECTED_INFO_VALUES = {
    "CFBundleExecutable": "SpringBoard",
    "CFBundleIdentifier": "com.apple.springboard",
    "CFBundlePackageType": "APPL",
    "CFBundleName": "SpringBoard",
    "CFBundleVersion": "50",
    "CFBundleShortVersionString": "1.0",
    "MinimumOSVersion": "27.0",
    "DTPlatformName": "iphoneos",
    "DTPlatformVersion": "27.0",
    "NSPrincipalClass": "SpringBoard",
    "UIApplicationInitializationContextFactoryClass": "SpringBoard",
}

ADDED_ENTITLEMENTS = (
    "get-task-allow",
    "com.apple.private.cs.debugger",
    "task_for_pid-allow",
    "platform-application",
    "com.apple.private.skip-library-validation",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-jit",
    "dynamic-codesigning",
)


class BuildError(RuntimeError):
    pass


def run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        raise BuildError(f"missing required tool: {arguments[0]}") from error
    except subprocess.CalledProcessError as error:
        output = (error.stdout + error.stderr).decode("utf-8", "replace").strip()
        raise BuildError(f"command failed: {' '.join(arguments)}\n{output}") from error


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def code_signature_details(path: pathlib.Path) -> dict[str, str]:
    completed = run("codesign", "-d", "--verbose=6", str(path))
    output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    details: dict[str, str] = {}
    for key in ("Identifier", "CDHash", "CandidateCDHashFull sha256"):
        match = re.search(rf"^{re.escape(key)}=(.+)$", output, re.MULTILINE)
        if match is not None:
            details[key] = match.group(1).strip()
    for slot, name in (("-5", "xmlEntitlementsSlotSha256"),
                       ("-7", "derEntitlementsSlotSha256")):
        match = re.search(rf"^\s*{re.escape(slot)}=([0-9a-f]{{64}})$",
                          output, re.MULTILINE)
        if match is not None:
            details[name] = match.group(1)
    return details


def entitlements(path: pathlib.Path) -> dict[str, Any]:
    completed = run("ldid", "-e", str(path))
    try:
        value = plistlib.loads(completed.stdout)
    except Exception as error:  # plistlib reports several concrete parse errors.
        raise BuildError(f"could not parse entitlements from {path}: {error}") from error
    if not isinstance(value, dict):
        raise BuildError(f"entitlements are not a dictionary: {path}")
    return value


def macho_identity(path: pathlib.Path) -> tuple[str, str]:
    file_output = run("file", "-b", str(path)).stdout.decode().strip()
    if "Mach-O 64-bit executable arm64e" not in file_output:
        raise BuildError(f"expected a thin arm64e executable, got: {file_output}")
    uuid_output = run("dwarfdump", "--uuid", str(path)).stdout.decode().strip()
    match = re.search(r"UUID: ([0-9A-F-]+) \(([^)]+)\)", uuid_output)
    if match is None:
        raise BuildError(f"could not parse Mach-O UUID: {uuid_output}")
    return match.group(1), match.group(2)


def validate_info_plist(path: pathlib.Path) -> dict[str, Any]:
    observed_hash = sha256(path)
    if observed_hash != EXPECTED_INFO_SHA256:
        raise BuildError(
            "SpringBoard Info.plist hash mismatch: "
            f"expected {EXPECTED_INFO_SHA256}, got {observed_hash}"
        )
    try:
        value = plistlib.loads(path.read_bytes())
    except Exception as error:
        raise BuildError(f"could not parse SpringBoard Info.plist: {error}") from error
    if not isinstance(value, dict):
        raise BuildError("SpringBoard Info.plist is not a dictionary")
    for key, expected in EXPECTED_INFO_VALUES.items():
        if value.get(key) != expected:
            raise BuildError(
                f"SpringBoard Info.plist {key} mismatch: "
                f"expected {expected!r}, got {value.get(key)!r}"
            )
    if value.get("CFBundleSupportedPlatforms") != ["iPhoneOS"]:
        raise BuildError("SpringBoard Info.plist has unexpected platforms")
    device_family = value.get("UIDeviceFamily")
    if not isinstance(device_family, list) or not {1, 2}.issubset(device_family):
        raise BuildError("SpringBoard Info.plist lacks iPhone/iPad device families")
    try:
        frontboard_mach_name = value["BSServiceDomains"]["com.apple.frontboard"][
            "MachName"
        ]
    except (KeyError, TypeError) as error:
        raise BuildError("SpringBoard Info.plist lacks its frontboard domain") from error
    if frontboard_mach_name != "com.apple.frontboard.systemappservices":
        raise BuildError("SpringBoard Info.plist has an unexpected frontboard Mach name")
    return value


def sign_candidate(
    source: pathlib.Path,
    destination: pathlib.Path,
    entitlement_path: pathlib.Path,
    *,
    load_dylib: str | None,
    load_dylib_patcher: pathlib.Path | None,
) -> None:
    shutil.copyfile(source, destination)
    destination.chmod(0o755)
    if load_dylib is not None:
        if load_dylib_patcher is None:
            raise BuildError("--load-dylib requires --load-dylib-patcher")
        run(
            os.fspath(pathlib.Path(os.sys.executable)),
            os.fspath(load_dylib_patcher),
            os.fspath(destination),
            load_dylib,
        )
    run(
        "codesign",
        "--force",
        "--sign",
        "-",
        "--timestamp=none",
        "--pagesize",
        "4096",
        "--generate-entitlement-der",
        "--identifier",
        EXPECTED_IDENTIFIER,
        "--entitlements",
        str(entitlement_path),
        str(destination),
    )
    run("codesign", "--verify", "--strict", "--all-architectures", str(destination))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output_directory", type=pathlib.Path)
    parser.add_argument(
        "--info-plist",
        type=pathlib.Path,
        help=(
            "exact live 24A435 SpringBoard.app Info.plist to validate and "
            "write beside the candidate"
        ),
    )
    parser.add_argument(
        "--executable-name",
        default="SpringBoard",
        help="output executable basename (default: SpringBoard)",
    )
    parser.add_argument(
        "--bundle-executable",
        help="replacement CFBundleExecutable value for the emitted Info.plist",
    )
    parser.add_argument(
        "--load-dylib",
        help="absolute LC_LOAD_DYLIB path added before the deterministic signature",
    )
    parser.add_argument(
        "--load-dylib-patcher",
        type=pathlib.Path,
        help="path to the pinned patch_load_dylib.py implementation",
    )
    arguments = parser.parse_args()

    source = arguments.source.resolve()
    output_directory = arguments.output_directory.resolve()
    if (
        pathlib.PurePath(arguments.executable_name).name
        != arguments.executable_name
        or arguments.executable_name in {"", ".", ".."}
    ):
        raise BuildError("executable name must be a basename")
    if arguments.bundle_executable is not None and (
        pathlib.PurePath(arguments.bundle_executable).name
        != arguments.bundle_executable
        or arguments.bundle_executable in {"", ".", ".."}
    ):
        raise BuildError("bundle executable must be a basename")
    if arguments.load_dylib is not None and (
        (
            not arguments.load_dylib.startswith("/")
            and not arguments.load_dylib.startswith("@loader_path/")
        )
        or "\0" in arguments.load_dylib
    ):
        raise BuildError("load dylib must be absolute or use @loader_path")
    load_dylib_patcher = None
    if arguments.load_dylib_patcher is not None:
        load_dylib_patcher = arguments.load_dylib_patcher.resolve()
        if not load_dylib_patcher.is_file():
            raise BuildError(f"load-command patcher is missing: {load_dylib_patcher}")
    if not source.is_file():
        raise BuildError(f"SpringBoard source is missing: {source}")
    if sha256(source) != EXPECTED_SOURCE_SHA256:
        raise BuildError(
            "SpringBoard source hash mismatch: "
            f"expected {EXPECTED_SOURCE_SHA256}, got {sha256(source)}"
        )

    info_source: pathlib.Path | None = None
    info_value: dict[str, Any] | None = None
    if arguments.info_plist is not None:
        info_source = arguments.info_plist.resolve()
        if not info_source.is_file():
            raise BuildError(f"SpringBoard Info.plist is missing: {info_source}")
        info_value = validate_info_plist(info_source)

    source_details = code_signature_details(source)
    if source_details.get("Identifier") != EXPECTED_IDENTIFIER:
        raise BuildError(
            "SpringBoard source identifier mismatch: "
            f"{source_details.get('Identifier', '<missing>')}"
        )
    source_uuid, source_architecture = macho_identity(source)
    if source_uuid != EXPECTED_UUID or source_architecture != EXPECTED_ARCHITECTURE:
        raise BuildError(
            "SpringBoard source identity mismatch: "
            f"uuid={source_uuid} architecture={source_architecture}"
        )

    original_entitlements = entitlements(source)
    merged_entitlements = dict(original_entitlements)
    for key in ADDED_ENTITLEMENTS:
        prior = merged_entitlements.get(key)
        if prior not in (None, True):
            raise BuildError(f"refusing to replace non-true entitlement {key}: {prior!r}")
        merged_entitlements[key] = True

    output_directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".springboard-candidate.", dir=output_directory
    ) as temporary_directory_string:
        temporary_directory = pathlib.Path(temporary_directory_string)
        entitlement_path = temporary_directory / "entitlements.plist"
        candidate_path = temporary_directory / arguments.executable_name
        second_candidate_path = temporary_directory / (
            arguments.executable_name + ".determinism-check"
        )
        info_path = temporary_directory / "Info.plist"

        entitlement_path.write_bytes(
            plistlib.dumps(merged_entitlements, fmt=plistlib.FMT_XML, sort_keys=False)
        )
        entitlement_path.chmod(0o644)
        sign_candidate(
            source,
            candidate_path,
            entitlement_path,
            load_dylib=arguments.load_dylib,
            load_dylib_patcher=load_dylib_patcher,
        )
        sign_candidate(
            source,
            second_candidate_path,
            entitlement_path,
            load_dylib=arguments.load_dylib,
            load_dylib_patcher=load_dylib_patcher,
        )
        deterministic = candidate_path.read_bytes() == second_candidate_path.read_bytes()
        if not deterministic:
            raise BuildError("the ad-hoc signing recipe produced different binaries")

        candidate_uuid, candidate_architecture = macho_identity(candidate_path)
        if (candidate_uuid, candidate_architecture) != (
            source_uuid,
            source_architecture,
        ):
            raise BuildError(
                "candidate changed the Mach-O UUID/architecture: "
                f"uuid={candidate_uuid} architecture={candidate_architecture}"
            )
        candidate_details = code_signature_details(candidate_path)
        if candidate_details.get("Identifier") != EXPECTED_IDENTIFIER:
            raise BuildError("candidate lost the com.apple.springboard identifier")
        cdhash = candidate_details.get("CDHash", "")
        if re.fullmatch(r"[0-9a-f]{40}", cdhash) is None:
            raise BuildError(f"candidate has an invalid CDHash: {cdhash!r}")
        der_slot = candidate_details.get("derEntitlementsSlotSha256", "")
        if re.fullmatch(r"[0-9a-f]{64}", der_slot) is None or set(der_slot) == {"0"}:
            raise BuildError("candidate is missing its DER-entitlements special slot")

        signed_entitlements = entitlements(candidate_path)
        if signed_entitlements != merged_entitlements:
            missing_or_changed = sorted(
                key
                for key, value in merged_entitlements.items()
                if signed_entitlements.get(key) != value
            )
            unexpected = sorted(set(signed_entitlements) - set(merged_entitlements))
            raise BuildError(
                "signed entitlement round trip changed values: "
                f"missingOrChanged={missing_or_changed} unexpected={unexpected}"
            )

        final_candidate = output_directory / arguments.executable_name
        final_entitlements = output_directory / "entitlements.plist"
        final_info = output_directory / "Info.plist"
        manifest_path = output_directory / "build-manifest.json"
        manifest = {
            "addedEntitlements": list(ADDED_ENTITLEMENTS),
            "architecture": candidate_architecture,
            "candidate": {
                "cdhash": cdhash,
                "path": str(final_candidate),
                "sha256": sha256(candidate_path),
                "size": candidate_path.stat().st_size,
            },
            "deterministicAdHocSignature": deterministic,
            "entitlements": {
                "count": len(signed_entitlements),
                "derSpecialSlotSha256": der_slot,
                "path": str(final_entitlements),
                "sha256": sha256(entitlement_path),
                "xmlSpecialSlotSha256": candidate_details.get(
                    "xmlEntitlementsSlotSha256", ""
                ),
            },
            "identifier": EXPECTED_IDENTIFIER,
            "loadDylib": arguments.load_dylib,
            "source": {
                "cdhash": source_details.get("CDHash", ""),
                "entitlementCount": len(original_entitlements),
                "path": str(source),
                "sha256": EXPECTED_SOURCE_SHA256,
            },
            "uuid": candidate_uuid,
        }
        if info_source is not None and info_value is not None:
            emitted_info = dict(info_value)
            if arguments.bundle_executable is not None:
                emitted_info["CFBundleExecutable"] = arguments.bundle_executable
            info_path.write_bytes(
                plistlib.dumps(
                    emitted_info,
                    fmt=plistlib.FMT_BINARY,
                    sort_keys=False,
                )
            )
            info_path.chmod(0o644)
            manifest["bundleInfo"] = {
                "dtPlatformBuild": info_value.get("DTPlatformBuild", ""),
                "executable": emitted_info.get("CFBundleExecutable", ""),
                "path": str(final_info),
                "sha256": sha256(info_path),
                "source": str(info_source),
                "sourceSha256": EXPECTED_INFO_SHA256,
            }
        manifest_path_temporary = temporary_directory / "build-manifest.json"
        manifest_path_temporary.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest_path_temporary.chmod(0o644)

        os.replace(candidate_path, final_candidate)
        os.replace(entitlement_path, final_entitlements)
        if info_source is not None:
            os.replace(info_path, final_info)
        os.replace(manifest_path_temporary, manifest_path)

    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        raise SystemExit(f"error: {error}") from error
