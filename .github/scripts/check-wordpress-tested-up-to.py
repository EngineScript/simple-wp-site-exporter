#!/usr/bin/env python3
"""Check WordPress "Tested up to" metadata against the latest release."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


WORDPRESS_LATEST_VERSION = os.environ.get("WORDPRESS_LATEST_VERSION")
WORDPRESS_VERSION_CHECK_FILE = Path("wordpress-version-check.json")
SCAN_EXTENSIONS = {".php", ".md", ".txt"}
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "plugin-check-build",
    "__pycache__",
    "vendor",
}
TESTED_UP_TO_PATTERN = re.compile(
    r"\btested\s+up\s+to\s*:\s*([0-9]+(?:\.[0-9]+){1,2})\b",
    re.IGNORECASE,
)
TESTED_UP_TO_LABEL_PATTERN = re.compile(r"\btested\s+up\s+to\s*:", re.IGNORECASE)
VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){1,2}$")


def main() -> int:
    latest_version = get_latest_wordpress_major_minor()
    excluded_dirs = get_excluded_dirs()
    findings = find_tested_up_to_entries(excluded_dirs)

    if not findings:
        message = "No Tested up to metadata was found in PHP, Markdown, or text files."
        print_github_error(message)
        write_summary(latest_version, [], [message])
        return 1

    failures = []
    for finding in findings:
        if finding["version"] is None:
            failures.append(
                f"{finding['path']}:{finding['line']}: Could not parse Tested up to version."
            )
            print_github_error(
                "Could not parse Tested up to version.",
                finding["path"],
                finding["line"],
            )
            continue

        tested_version = normalize_major_minor(finding["version"])
        if tested_version != latest_version:
            message = (
                f"Tested up to is {finding['version']}; expected {latest_version} "
                "for the latest WordPress release."
            )
            failures.append(f"{finding['path']}:{finding['line']}: {message}")
            print_github_error(message, finding["path"], finding["line"])

    write_summary(latest_version, findings, failures)

    if failures:
        entry_label = "entry" if len(failures) == 1 else "entries"
        print(f"Found {len(failures)} stale or invalid Tested up to {entry_label}.")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"All Tested up to entries match WordPress {latest_version}.")
    return 0


def get_latest_wordpress_major_minor() -> str:
    if WORDPRESS_LATEST_VERSION:
        return normalize_major_minor(WORDPRESS_LATEST_VERSION)

    if not WORDPRESS_VERSION_CHECK_FILE.is_file():
        raise RuntimeError(
            "WORDPRESS_LATEST_VERSION must be set, or wordpress-version-check.json must exist."
        )

    payload = json.loads(WORDPRESS_VERSION_CHECK_FILE.read_text(encoding="utf-8"))
    versions = []

    for offer in payload.get("offers", []):
        version = offer.get("current") or offer.get("version")
        if isinstance(version, str) and VERSION_PATTERN.match(version):
            versions.append(version)

    if not versions:
        raise RuntimeError("Could not determine the latest WordPress version.")

    latest = max(versions, key=version_sort_key)
    return normalize_major_minor(latest)


def normalize_major_minor(version: str) -> str:
    parts = version.split(".")

    if len(parts) < 2 or not all(part.isdigit() for part in parts):
        raise ValueError(f"Invalid WordPress version: {version}")

    return ".".join(parts[:2])


def version_sort_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def get_excluded_dirs() -> set[str]:
    configured = os.environ.get("WORDPRESS_TESTED_UP_TO_EXCLUDE_DIRS", "")
    extra_dirs = {item.strip() for item in configured.split(",") if item.strip()}

    return DEFAULT_EXCLUDED_DIRS | extra_dirs


def find_tested_up_to_entries(
    excluded_dirs: set[str],
) -> list[dict[str, str | int | None]]:
    findings = []

    for path in get_scanned_files(excluded_dirs):
        if not should_scan(path, excluded_dirs):
            continue

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

        for line_number, line in enumerate(lines, 1):
            if not TESTED_UP_TO_LABEL_PATTERN.search(line):
                continue

            match = TESTED_UP_TO_PATTERN.search(line)
            findings.append(
                {
                    "path": path.as_posix(),
                    "line": line_number,
                    "version": match.group(1) if match else None,
                }
            )

    return findings


def get_scanned_files(excluded_dirs: set[str]) -> list[Path]:
    root = Path.cwd()
    paths = []

    for current_dir, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            dirname for dirname in dirnames if dirname not in excluded_dirs
        ]

        current_path = Path(current_dir)
        for filename in filenames:
            path = current_path / filename
            relative_path = path.relative_to(root)

            if should_scan(relative_path, excluded_dirs):
                paths.append(relative_path)

    return sorted(paths)


def should_scan(path: Path, excluded_dirs: set[str]) -> bool:
    if path.suffix.lower() not in SCAN_EXTENSIONS:
        return False

    return not any(part in excluded_dirs for part in path.parts)


def write_summary(
    latest_version: str,
    findings: list[dict[str, str | int | None]],
    failures: list[str],
) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "# WordPress Tested Up To Check",
        "",
        f"Latest WordPress major.minor release: `{latest_version}`",
        f"Metadata entries checked: `{len(findings)}`",
        "",
    ]

    if failures:
        lines.append("## Failures")
        lines.extend(f"- {failure}" for failure in failures)
    else:
        lines.append("All Tested up to entries are current.")

    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines))
        summary.write("\n")


def print_github_error(message: str, path: str | None = None, line: int | None = None) -> None:
    if path is None:
        print(f"::error::{escape_github_command_data(message)}")
        return

    properties = f"file={escape_github_command_property(path)}"
    if line is not None:
        properties += f",line={line}"

    print(f"::error {properties}::{escape_github_command_data(message)}")


def escape_github_command_property(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def escape_github_command_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print_github_error(str(exc))
        sys.exit(1)
