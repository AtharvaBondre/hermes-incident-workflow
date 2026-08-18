#!/usr/bin/env python3
"""Synthetic repair task executed only inside the Hermes Docker sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path


INPUT = Path("/input")
OUTPUT = Path("/output")
WORKSPACE = OUTPUT / "workspace"
PROOF = OUTPUT / "sandbox-proof.json"
ALLOWED_ENVIRONMENT_NAMES = {
    "HIW_SANDBOX_MODE",
    "GPG_KEY",
    "HOME",
    "HOSTNAME",
    "LANG",
    "OLDPWD",
    "PATH",
    "PWD",
    "PYTHON_SHA256",
    "PYTHON_VERSION",
    "SHLVL",
    "_",
}


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    files = (
        item
        for item in root.rglob("*")
        if item.is_file()
        and "__pycache__" not in item.parts
        and item.suffix not in {".pyc", ".pyo"}
    )
    for path in sorted(files):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    working_directory = Path.cwd()
    if working_directory != Path("/workspace"):
        raise RuntimeError(f"unexpected Hermes sandbox working directory: {working_directory}")
    if os.environ.get("HIW_SANDBOX_MODE") != "local-fixture":
        raise RuntimeError("sandbox marker is missing")

    environment_names = sorted(os.environ)
    unexpected_environment_names = sorted(set(environment_names) - ALLOWED_ENVIRONMENT_NAMES)
    if unexpected_environment_names:
        raise RuntimeError(
            "unapproved environment names reached the sandbox: "
            f"{unexpected_environment_names}"
        )

    input_read_only = False
    try:
        (INPUT / ".write-probe").write_text("must fail", encoding="utf-8")
    except OSError:
        input_read_only = True
    if not input_read_only:
        raise RuntimeError("read-only input mount accepted a write")

    network_blocked = False
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=1):
            pass
    except OSError:
        network_blocked = True
    if not network_blocked:
        raise RuntimeError("sandbox unexpectedly reached an external network")

    if WORKSPACE.exists():
        shutil.rmtree(WORKSPACE)
    shutil.copytree(
        INPUT,
        WORKSPACE,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    subject = WORKSPACE / "app" / "subject.py"
    original = subject.read_text(encoding="utf-8")
    expected = "    return value.strip()\n"
    replacement = '    return " ".join(value.split()).lower()\n'
    if expected not in original:
        raise RuntimeError("synthetic bug fixture has changed")
    subject.write_text(original.replace(expected, replacement), encoding="utf-8")

    test = subprocess.run(
        ["python", "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=WORKSPACE,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(WORKSPACE),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    cache_files = sorted(
        str(path.relative_to(WORKSPACE))
        for path in WORKSPACE.rglob("*")
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
    )
    if cache_files:
        raise RuntimeError(f"cache files polluted the candidate workspace: {cache_files}")
    proof = {
        "schema_version": 1,
        "kind": "scripted-hermes-sandbox-smoke",
        "working_directory": str(working_directory),
        "input_read_only": input_read_only,
        "network_blocked": network_blocked,
        "environment_names": environment_names,
        "unexpected_environment_names": unexpected_environment_names,
        "cache_files": cache_files,
        "changed_paths": ["app/subject.py"],
        "candidate_digest": tree_digest(WORKSPACE),
        "test_exit_code": test.returncode,
        "test_passed": test.returncode == 0,
        "test_output": test.stdout[-4000:],
    }
    PROOF.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if test.returncode != 0:
        raise RuntimeError("synthetic candidate did not pass its unit tests")
    print(json.dumps({"status": "sandbox-task-complete", "proof": str(PROOF)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
