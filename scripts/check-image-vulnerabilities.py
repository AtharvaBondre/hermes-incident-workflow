#!/usr/bin/env python3
"""Fail when pinned-image HIGH/CRITICAL findings drift or exceptions expire."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "security" / "image-vulnerability-baseline.json"
PIN_SOURCES = (
    *sorted(ROOT.glob("compose*.yaml")),
    ROOT / "docker" / "incident-poc" / "Dockerfile",
    ROOT / "hermes-profile" / "config.yaml",
)
IMAGE_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}"
)


def read_baseline() -> dict[str, Any]:
    value = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "scanner",
        "qualified_on",
        "expires_on",
        "severity",
        "images",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise ValueError("image vulnerability baseline schema is invalid")
    if value["severity"] != ["CRITICAL", "HIGH"]:
        raise ValueError("image vulnerability severity policy is invalid")
    return value


def discovered_images() -> set[str]:
    images: set[str] = set()
    for path in PIN_SOURCES:
        images.update(IMAGE_PATTERN.findall(path.read_text(encoding="utf-8")))
    return images


def trivy_environment() -> dict[str, str]:
    allowed = ("HOME", "LANG", "LC_ALL", "PATH", "SSL_CERT_FILE", "TMPDIR")
    return {name: os.environ[name] for name in allowed if name in os.environ}


def trivy_version() -> str:
    result = subprocess.run(
        ["trivy", "--version"],
        env=trivy_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Trivy is unavailable")
    match = re.search(r"^Version:\s*([^\s]+)", result.stdout, re.MULTILINE)
    if match is None:
        raise RuntimeError("Trivy version output is unrecognized")
    return f"trivy {match.group(1)}"


def scan(image: str) -> tuple[dict[str, int], str]:
    result = subprocess.run(
        [
            "trivy",
            "image",
            "--quiet",
            "--severity",
            "HIGH,CRITICAL",
            "--format",
            "json",
            image,
        ],
        env=trivy_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Trivy failed for {image}: {result.stderr[-1000:]}")
    report = json.loads(result.stdout)
    records: list[list[str]] = []
    for target in report.get("Results") or []:
        for finding in target.get("Vulnerabilities") or []:
            records.append(
                [
                    str(target.get("Target", "")),
                    str(target.get("Class", "")),
                    str(target.get("Type", "")),
                    str(finding.get("VulnerabilityID", "")),
                    str(finding.get("PkgName", "")),
                    str(finding.get("InstalledVersion", "")),
                    str(finding.get("FixedVersion", "")),
                    str(finding.get("Severity", "")),
                ]
            )
    records.sort()
    payload = json.dumps(records, separators=(",", ":"), ensure_ascii=True).encode()
    counts = {
        "critical": sum(record[-1] == "CRITICAL" for record in records),
        "high": sum(record[-1] == "HIGH" for record in records),
    }
    return counts, f"sha256:{hashlib.sha256(payload).hexdigest()}"


def main() -> int:
    issues: list[str] = []
    baseline = read_baseline()
    actual_scanner = trivy_version()
    if actual_scanner != baseline["scanner"]:
        issues.append(
            f"scanner mismatch: expected {baseline['scanner']}, found {actual_scanner}"
        )
    if date.today() > date.fromisoformat(baseline["expires_on"]):
        issues.append(f"vulnerability exceptions expired on {baseline['expires_on']}")

    entries = baseline["images"]
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise ValueError("image vulnerability entries are invalid")
    by_image = {entry.get("image"): entry for entry in entries}
    if None in by_image or len(by_image) != len(entries):
        raise ValueError("image vulnerability entries are duplicated or unnamed")
    pinned = discovered_images()
    if pinned != set(by_image):
        issues.append(
            "pinned image set differs from baseline: "
            f"missing={sorted(pinned - set(by_image))}, stale={sorted(set(by_image) - pinned)}"
        )

    results: list[dict[str, Any]] = []
    for image in sorted(pinned & set(by_image)):
        counts, digest = scan(image)
        expected = by_image[image]
        matches = (
            counts["critical"] == expected.get("critical")
            and counts["high"] == expected.get("high")
            and digest == expected.get("finding_digest")
        )
        if not matches:
            issues.append(f"vulnerability findings changed for {image}")
        results.append(
            {
                "image": image,
                **counts,
                "finding_digest": digest,
                "matches_baseline": matches,
            }
        )

    print(
        json.dumps(
            {
                "ok": not issues,
                "scanner": actual_scanner,
                "baseline_expires_on": baseline["expires_on"],
                "results": results,
                "issues": issues,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not issues else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        raise SystemExit(1) from None
