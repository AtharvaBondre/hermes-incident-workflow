#!/usr/bin/env python3
"""Fail closed on common disclosure and packaging mistakes."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "artifacts", "__pycache__", "dist", "build"}
REQUIRED = {
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    "config/workflow.json",
    "hermes-profile/distribution.yaml",
    "hermes-profile/config.yaml",
    "hermes-profile/skills/hermes-incident-remediation/SKILL.md",
    "schemas/workflow.schema.json",
    "security/image-vulnerability-baseline.json",
    "scripts/check-image-vulnerabilities.py",
    "scripts/runner.py",
}


def source_files() -> list[Path]:
    files: list[Path] = []
    for current, directory_names, file_names in os.walk(ROOT, followlinks=False):
        directory_names[:] = [
            name for name in directory_names if name not in SKIP_PARTS
        ]
        current_path = Path(current)
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(ROOT)
            if any(part in SKIP_PARTS for part in relative.parts):
                continue
            files.append(path)
    return sorted(files)


def text_content(path: Path) -> str | None:
    payload = path.read_bytes()
    if b"\x00" in payload:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def main() -> int:
    issues: list[str] = []
    present = {path.relative_to(ROOT).as_posix() for path in source_files()}
    for missing in sorted(REQUIRED - present):
        issues.append(f"missing required public file: {missing}")

    secret_patterns = (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"(?<![A-Za-z0-9])/(?:Users|home)/[A-Za-z0-9._-]+/"),
    )

    for path in source_files():
        relative = path.relative_to(ROOT).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            issues.append(f"irregular public file: {relative}")
            continue
        if path.stat().st_size > 1_000_000:
            issues.append(f"public file exceeds 1 MB: {relative}")
        text = text_content(path)
        if text is None:
            issues.append(f"unexpected non-UTF-8 or binary public file: {relative}")
            continue
        lowered = text.lower()
        for pattern in secret_patterns:
            if pattern.search(text):
                issues.append(f"credential-like value found in {relative}: {pattern.pattern}")
        if ("[" + "to" + "do") in lowered or ("to" + "do:") in lowered:
            issues.append(f"unfinished placeholder found in {relative}")
        if relative.endswith(".json"):
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                issues.append(f"invalid JSON in {relative}: {exc}")

    skill = ROOT / "hermes-profile/skills/hermes-incident-remediation/SKILL.md"
    if skill.is_file():
        content = skill.read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
        if not match:
            issues.append("skill frontmatter is missing or malformed")
        else:
            fields = {
                line.split(":", 1)[0].strip()
                for line in match.group(1).splitlines()
                if ":" in line
            }
            if fields != {"name", "description"}:
                issues.append("skill frontmatter must contain only name and description")

    for executable in (
        "scripts/run-local.sh",
        "scripts/bootstrap-pinned-images.sh",
        "scripts/install-hermes-profile.sh",
        "scripts/check-public-surface.py",
        "scripts/check-image-vulnerabilities.py",
        "integration/postgres-init/001-incident-schema.sh",
    ):
        path = ROOT / executable
        if path.is_file() and not os.access(path, os.X_OK):
            issues.append(f"script is not executable: {executable}")

    result = {"ok": not issues, "files_checked": len(present), "issues": sorted(set(issues))}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
