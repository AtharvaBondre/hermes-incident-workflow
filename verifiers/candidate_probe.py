#!/usr/bin/env python3
"""Run candidate Python calls without giving candidate code verifier authority."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any


PROTOCOL_VERSION = 1
MAX_CALLS = 256
MAX_REQUEST_BYTES = 128 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
TRUSTED_VERIFIER_COMPLETION = "HIW_TRUSTED_VERIFIER_COMPLETED:v1"
_MODULE_PATTERN = re.compile(r"app(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_CALLABLE_PATTERN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
)


class CandidateProbeError(RuntimeError):
    """Candidate execution did not produce a trustworthy result packet."""


def _validate_target(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"module", "callable"}:
        raise ValueError(f"{label} must contain only module and callable")
    module = value["module"]
    callable_name = value["callable"]
    if not isinstance(module, str) or _MODULE_PATTERN.fullmatch(module) is None:
        raise ValueError(f"{label} module is invalid")
    if (
        not isinstance(callable_name, str)
        or _CALLABLE_PATTERN.fullmatch(callable_name) is None
    ):
        raise ValueError(f"{label} callable is invalid")
    return {"module": module, "callable": callable_name}


def _validate_calls(calls: Any) -> list[dict[str, Any]]:
    if not isinstance(calls, list) or not 1 <= len(calls) <= MAX_CALLS:
        raise ValueError(f"calls must contain between 1 and {MAX_CALLS} operations")
    validated: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            raise ValueError(f"call {index} must be an object")
        allowed = {"module", "callable", "argument", "factory"}
        if set(call) not in (
            {"module", "callable", "argument"},
            allowed,
        ):
            raise ValueError(f"call {index} fields are invalid")
        target = _validate_target(
            {"module": call["module"], "callable": call["callable"]},
            f"call {index}",
        )
        record: dict[str, Any] = {**target, "argument": call["argument"]}
        if "factory" in call:
            record["factory"] = _validate_target(
                call["factory"],
                f"call {index} factory",
            )
        validated.append(record)
    return validated


def _child_environment() -> dict[str, str]:
    return {
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONUNBUFFERED": "1",
        "TMPDIR": "/tmp",
        "USER": "nobody",
    }


def _kill_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        process.kill()


def _decode_json(raw: str, label: str) -> Any:
    if len(raw.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise CandidateProbeError(f"{label} exceeds the trusted size limit")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CandidateProbeError(f"{label} is malformed") from exc


def run_candidate_calls(
    repository: Path,
    calls: list[dict[str, Any]],
    *,
    timeout_seconds: float,
) -> list[Any]:
    """Return untrusted call values only after a trusted supervisor completes."""
    repository = repository.resolve(strict=True)
    if not repository.is_dir() or not (repository / "app").is_dir():
        raise ValueError("candidate repository must contain an app package")
    if not 0 < timeout_seconds <= 30:
        raise ValueError(
            "candidate timeout must be greater than zero and at most 30 seconds"
        )
    validated_calls = _validate_calls(calls)
    nonce = secrets.token_hex(32)
    request = {
        "protocol": PROTOCOL_VERSION,
        "nonce": nonce,
        "calls": validated_calls,
    }
    serialized = json.dumps(request, separators=(",", ":"), sort_keys=True)
    if len(serialized.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ValueError("candidate request exceeds the trusted size limit")

    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--supervisor",
            str(repository),
        ],
        cwd=repository,
        env=_child_environment(),
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, _stderr = process.communicate(
            serialized + "\n",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(process)
        process.communicate()
        raise CandidateProbeError("candidate process timed out") from exc

    if process.returncode != 0:
        raise CandidateProbeError(
            f"candidate supervisor exited without trusted completion ({process.returncode})"
        )
    response = _decode_json(stdout, "trusted supervisor response")
    if not isinstance(response, dict) or set(response) != {
        "protocol",
        "nonce",
        "status",
        "results",
    }:
        raise CandidateProbeError("trusted supervisor response fields are invalid")
    if response["protocol"] != PROTOCOL_VERSION or response["nonce"] != nonce:
        raise CandidateProbeError("trusted supervisor response does not match request")
    if response["status"] != "completed":
        raise CandidateProbeError("trusted supervisor did not complete")
    results = response["results"]
    if not isinstance(results, list) or len(results) != len(validated_calls):
        raise CandidateProbeError("candidate response result count is invalid")
    return results


def _read_request(expected_fields: set[str]) -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("worker request exceeds limit")
    request = json.loads(raw)
    if not isinstance(request, dict) or set(request) != expected_fields:
        raise ValueError("worker request fields are invalid")
    if request["protocol"] != PROTOCOL_VERSION:
        raise ValueError("worker protocol is unsupported")
    return request


def _run_executor(repository: Path, calls: list[dict[str, Any]]) -> list[Any]:
    request = json.dumps(
        {"protocol": PROTOCOL_VERSION, "calls": calls},
        separators=(",", ":"),
        sort_keys=True,
    )
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--executor",
            str(repository),
        ],
        cwd=repository,
        env=_child_environment(),
        text=True,
        input=request + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise CandidateProbeError(
            f"candidate executor exited without results ({process.returncode})"
        )
    results = _decode_json(process.stdout, "candidate result data")
    if not isinstance(results, list) or len(results) != len(calls):
        raise CandidateProbeError("candidate result data has the wrong result count")
    return results


def _supervisor(repository: Path) -> int:
    request = _read_request({"protocol", "nonce", "calls"})
    nonce = request["nonce"]
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError("supervisor nonce is invalid")
    calls = _validate_calls(request["calls"])
    results = _run_executor(repository, calls)
    response = {
        "protocol": PROTOCOL_VERSION,
        "nonce": nonce,
        "status": "completed",
        "results": results,
    }
    sys.stdout.write(json.dumps(response, separators=(",", ":"), sort_keys=True))
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


def _resolve_callable(target: dict[str, str]):
    value: Any = importlib.import_module(target["module"])
    for part in target["callable"].split("."):
        value = getattr(value, part)
    if not callable(value):
        raise TypeError("candidate target is not callable")
    return value


def _executor(repository: Path) -> int:
    request = _read_request({"protocol", "calls"})
    calls = _validate_calls(request["calls"])
    repository = repository.resolve(strict=True)
    if not repository.is_dir() or not (repository / "app").is_dir():
        raise ValueError("executor repository is invalid")
    sys.path.insert(0, str(repository))

    results: list[Any] = []
    for call in calls:
        argument = call["argument"]
        if "factory" in call:
            argument = _resolve_callable(call["factory"])(argument)
        results.append(
            _resolve_callable(
                {"module": call["module"], "callable": call["callable"]}
            )(argument)
        )
    sys.stdout.write(json.dumps(results, separators=(",", ":"), sort_keys=True))
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--supervisor", type=Path)
    modes.add_argument("--executor", type=Path)
    args = parser.parse_args()
    try:
        if args.supervisor is not None:
            return _supervisor(args.supervisor)
        return _executor(args.executor)
    except BaseException as exc:
        print(f"candidate probe failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
