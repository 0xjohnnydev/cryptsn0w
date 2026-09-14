#!/usr/bin/env python3
"""Select a valid local Apple Development profile and generate Sileo entitlements."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


IDENTITY_RE = re.compile(r'\b([0-9A-Fa-f]{40})\b\s+"([^"]+)"')
PROFILE_DIRECTORIES = (
    Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles",
    Path.home() / "Library/MobileDevice/Provisioning Profiles",
)


class SigningError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    profile: Path
    profile_data: dict[str, Any]
    identity_sha1: str
    identity_name: str
    application_pattern: str
    exact_bundle_match: bool
    expiration: dt.datetime


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def installed_identities() -> dict[str, str]:
    completed = subprocess.run(
        ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
        check=True,
        capture_output=True,
        text=True,
    )
    identities: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        match = IDENTITY_RE.search(line)
        if match is not None:
            identities[match.group(1).upper()] = match.group(2)
    if not identities:
        raise SigningError(
            "no valid code-signing identity is installed; add an Apple "
            "Development account in Xcode first"
        )
    return identities


def decode_profile(path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        ["/usr/bin/security", "cms", "-D", "-i", str(path)],
        check=True,
        capture_output=True,
    )
    value = plistlib.loads(completed.stdout)
    if not isinstance(value, dict):
        raise SigningError(f"profile did not decode to a dictionary: {path}")
    return value


def utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def profile_paths(requested: Path | None) -> list[Path]:
    if requested is not None:
        requested = requested.expanduser().resolve()
        if not requested.is_file():
            raise SigningError(f"provisioning profile does not exist: {requested}")
        return [requested]

    paths: set[Path] = set()
    for directory in PROFILE_DIRECTORIES:
        if directory.is_dir():
            paths.update(path.resolve() for path in directory.glob("*.mobileprovision"))
    if not paths:
        raise SigningError(
            "no provisioning profiles were found; let Xcode manage signing "
            "for any development app, then run this command again"
        )
    return sorted(paths)


def identity_filter(selector: str | None, identities: dict[str, str]) -> set[str]:
    if selector is None:
        return set(identities)
    normalized = selector.strip()
    if re.fullmatch(r"[0-9A-Fa-f]{40}", normalized):
        sha1 = normalized.upper()
        if sha1 not in identities:
            raise SigningError(f"requested signing identity is not installed: {sha1}")
        return {sha1}
    matches = {
        sha1
        for sha1, name in identities.items()
        if normalized.casefold() in name.casefold()
    }
    if len(matches) != 1:
        names = [identities[sha1] for sha1 in sorted(matches)]
        raise SigningError(
            f"identity selector {selector!r} matched {len(matches)} identities: {names}"
        )
    return matches


def application_pattern(profile: dict[str, Any]) -> tuple[str, str]:
    entitlements = profile.get("Entitlements")
    if not isinstance(entitlements, dict):
        raise SigningError("profile has no Entitlements dictionary")
    application_identifier = entitlements.get("application-identifier")
    if not isinstance(application_identifier, str) or "." not in application_identifier:
        raise SigningError("profile has no usable application-identifier")
    prefix, pattern = application_identifier.split(".", 1)
    return prefix, pattern


def candidate_for_profile(
    path: Path,
    bundle_id: str,
    identities: dict[str, str],
    allowed_identities: set[str],
) -> list[Candidate]:
    profile = decode_profile(path)
    entitlements = profile.get("Entitlements", {})
    if entitlements.get("get-task-allow") is not True:
        return []
    expiration = profile.get("ExpirationDate")
    if (
        not isinstance(expiration, dt.datetime)
        or utc(expiration) <= dt.datetime.now(dt.timezone.utc)
    ):
        return []
    _, pattern = application_pattern(profile)
    if not fnmatch.fnmatchcase(bundle_id, pattern):
        return []

    certificate_hashes = {
        hashlib.sha1(certificate).hexdigest().upper()
        for certificate in profile.get("DeveloperCertificates", [])
        if isinstance(certificate, bytes)
    }
    matching = sorted(certificate_hashes & set(identities) & allowed_identities)
    return [
        Candidate(
            profile=path,
            profile_data=profile,
            identity_sha1=sha1,
            identity_name=identities[sha1],
            application_pattern=pattern,
            exact_bundle_match=pattern == bundle_id,
            expiration=utc(expiration),
        )
        for sha1 in matching
    ]


def select_candidate(
    profile: Path | None,
    identity: str | None,
    bundle_id: str,
) -> Candidate:
    identities = installed_identities()
    allowed = identity_filter(identity, identities)
    candidates: list[Candidate] = []
    decode_failures: list[str] = []
    for path in profile_paths(profile):
        try:
            candidates.extend(
                candidate_for_profile(path, bundle_id, identities, allowed)
            )
        except (
            OSError,
            plistlib.InvalidFileException,
            subprocess.CalledProcessError,
            SigningError,
        ) as error:
            if profile is not None:
                raise SigningError(
                    f"could not use provisioning profile {path}: {error}"
                ) from error
            decode_failures.append(f"{path}: {error}")
    if not candidates:
        detail = (
            f" ({len(decode_failures)} unreadable profiles skipped)"
            if decode_failures
            else ""
        )
        raise SigningError(
            f"no unexpired development profile for {bundle_id} matches an "
            f"installed certificate{detail}"
        )
    candidates.sort(
        key=lambda item: (item.exact_bundle_match, item.expiration, item.profile.name),
        reverse=True,
    )
    return candidates[0]


def generated_entitlements(candidate: Candidate, bundle_id: str) -> dict[str, Any]:
    profile = candidate.profile_data
    profile_entitlements = profile["Entitlements"]
    prefixes = profile.get("ApplicationIdentifierPrefix")
    if isinstance(prefixes, list) and prefixes and isinstance(prefixes[0], str):
        prefix = prefixes[0]
    else:
        prefix, _ = application_pattern(profile)
    teams = profile.get("TeamIdentifier")
    team = (
        teams[0]
        if isinstance(teams, list) and teams and isinstance(teams[0], str)
        else profile_entitlements.get("com.apple.developer.team-identifier")
    )
    if not isinstance(team, str) or not team:
        raise SigningError("selected profile has no team identifier")

    result: dict[str, Any] = {
        "application-identifier": f"{prefix}.{bundle_id}",
        "com.apple.developer.team-identifier": team,
        "get-task-allow": True,
    }
    keychain_groups = profile_entitlements.get("keychain-access-groups")
    if isinstance(keychain_groups, list) and all(isinstance(item, str) for item in keychain_groups):
        result["keychain-access-groups"] = keychain_groups
    return result


def validate_custom_entitlements(
    entitlements: dict[str, Any], candidate: Candidate, bundle_id: str
) -> None:
    expected = generated_entitlements(candidate, bundle_id)
    for key in (
        "application-identifier",
        "com.apple.developer.team-identifier",
        "get-task-allow",
    ):
        if entitlements.get(key) != expected[key]:
            raise SigningError(
                f"custom entitlements contain an unexpected {key}: {entitlements.get(key)!r}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-id", default="org.coolstar.SileoStore")
    parser.add_argument(
        "--identity",
        default=os.environ.get("CODEX_SILEO_DEVELOPMENT_IDENTITY"),
    )
    profile_default = os.environ.get("CODEX_SILEO_PROVISIONING_PROFILE")
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path(profile_default) if profile_default else None,
    )
    entitlements_default = os.environ.get("CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS")
    parser.add_argument(
        "--entitlements",
        type=Path,
        default=Path(entitlements_default) if entitlements_default else None,
        help="optional custom entitlements; identity/team fields are still validated",
    )
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument("--output-entitlements", required=True, type=Path)
    args = parser.parse_args()

    candidate = select_candidate(args.profile, args.identity, args.bundle_id)
    if args.entitlements is not None:
        source = args.entitlements.expanduser().resolve()
        if not source.is_file():
            raise SigningError(f"custom entitlements do not exist: {source}")
        entitlements = plistlib.loads(source.read_bytes())
        if not isinstance(entitlements, dict):
            raise SigningError("custom entitlements are not a dictionary")
        validate_custom_entitlements(entitlements, candidate, args.bundle_id)
    else:
        entitlements = generated_entitlements(candidate, args.bundle_id)

    args.output_entitlements.parent.mkdir(parents=True, exist_ok=True)
    args.output_entitlements.write_bytes(
        plistlib.dumps(entitlements, fmt=plistlib.FMT_XML, sort_keys=True)
    )
    profile = candidate.profile_data
    result = {
        "bundleIdentifier": args.bundle_id,
        "identityName": candidate.identity_name,
        "identitySha1": candidate.identity_sha1,
        "profile": str(candidate.profile),
        "profileName": profile.get("Name"),
        "profileUuid": profile.get("UUID"),
        "profileExpiration": candidate.expiration.isoformat(),
        "profileSha256": sha256(candidate.profile),
        "applicationPattern": candidate.application_pattern,
        "entitlements": str(args.output_entitlements.resolve()),
        "entitlementsSha256": sha256(args.output_entitlements),
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        plistlib.InvalidFileException,
        SigningError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
