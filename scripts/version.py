#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synchronize package metadata with VERSION; edit that file and run this script."""

import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"
# ponytail: Stable X.Y.Z releases work unchanged across Cargo, Python, and npm.
# Add cross-ecosystem prerelease normalization if prereleases are published.
# 2026-09-09: Python's \d accepted Unicode digits; package versions stay ASCII.
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
PACKAGE_BLOCK = re.compile(
    r'(?m)^(\[\[package\]\]\nname = "gdb-ai(?:-core|-mi)?"\nversion = ")[^"]+("$)'
)
# Protocol, provider, and fixture versions are independent of package releases.
TEXT_TARGETS = (
    ("Cargo.toml", re.compile(r'(?m)^(version = ")[^"]+("$)'), 1),
    ("Cargo.lock", PACKAGE_BLOCK, 3),
    ("fuzz/Cargo.lock", PACKAGE_BLOCK, 2),
    ("sdk/python/pyproject.toml", re.compile(r'(?m)^(version = ")[^"]+("$)'), 1),
    (
        "sdk/python/src/gdb_ai/client.py",
        re.compile(r'("clientInfo": \{"name": self\.client_name, "version": ")[^"]+("\})'),
        1,
    ),
    ("sdk/typescript/package.json", re.compile(r'(?m)^(  "version": ")[^"]+(",$)'), 1),
    (
        "sdk/typescript/src/index.ts",
        re.compile(r'(clientInfo: \{ name: this\.clientName, version: ")[^"]+(" \},)'),
        1,
    ),
)


def replace_versions(
    relative: str, pattern: re.Pattern[str], count: int, version: str, write: bool
) -> bool:
    path = ROOT / relative
    original = path.read_text()
    updated, replacements = pattern.subn(
        lambda match: f"{match.group(1)}{version}{match.group(2)}", original
    )
    if replacements != count:
        raise SystemExit(f"{relative}: expected {count} version fields, found {replacements}")
    if updated != original and write:
        path.write_text(updated)
    return updated != original


def replace_package_lock(version: str, write: bool) -> bool:
    path = ROOT / "sdk/typescript/package-lock.json"
    original = path.read_text()
    data = json.loads(original)
    package = data.get("packages", {}).get("", {})
    if (
        data.get("name") != "@gdb-ai/sdk"
        or package.get("name") != "@gdb-ai/sdk"
    ):
        raise SystemExit("sdk/typescript/package-lock.json: unexpected root package")
    changed = data.get("version") != version or package.get("version") != version
    if not changed or not write:
        return changed
    data["version"] = version
    package["version"] = version
    updated = json.dumps(data, indent=2) + "\n"
    path.write_text(updated)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="new X.Y.Z version; defaults to VERSION")
    parser.add_argument("--check", action="store_true", help="report drift without changing files")
    arguments = parser.parse_args()
    if arguments.check and arguments.version is not None:
        parser.error("--check does not accept a version")

    version = arguments.version if arguments.version is not None else VERSION_FILE.read_text().strip()
    if VERSION_PATTERN.fullmatch(version) is None:
        raise SystemExit("version must use X.Y.Z with no leading zeroes")

    # 2026-09-09: A moved version field left earlier files already bumped.
    # Validate every metadata target before writing any of the release version.
    if not arguments.check:
        for target in TEXT_TARGETS:
            replace_versions(*target, version, False)
        replace_package_lock(version, False)

    expected_version_file = f"{version}\n"
    changed = []
    if VERSION_FILE.read_text() != expected_version_file:
        if arguments.check:
            changed.append("VERSION")
        else:
            VERSION_FILE.write_text(expected_version_file)
    for target in TEXT_TARGETS:
        if replace_versions(*target, version, not arguments.check) and arguments.check:
            changed.append(target[0])
    if replace_package_lock(version, not arguments.check) and arguments.check:
        changed.append("sdk/typescript/package-lock.json")

    if arguments.check and changed:
        raise SystemExit(
            "version metadata differs from VERSION: "
            + ", ".join(changed)
            + "; run python3 scripts/version.py"
        )
    print(f"version metadata is synchronized at {version}")


if __name__ == "__main__":
    main()
