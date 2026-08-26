#!/usr/bin/env python3
"""Controller-owned verifier for the synthetic subject-normalization fixture."""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

try:
    from candidate_probe import TRUSTED_VERIFIER_COMPLETION, run_candidate_calls
except ModuleNotFoundError:  # Support direct imports from the repository test suite.
    from verifiers.candidate_probe import (
        TRUSTED_VERIFIER_COMPLETION,
        run_candidate_calls,
    )


DEFAULT_REPOSITORY = Path(__file__).resolve().parents[1] / "fixtures" / "repository"


def verify_repository(repository: Path, *, timeout_seconds: float = 5) -> None:
    token = secrets.token_hex(12)
    cases = [
        ("  Payment   FAILED  ", "payment failed"),
        ("   ", ""),
        (f"  {token.upper()}\tQUEUED  ", f"{token} queued"),
        ("Already-normalized", "already-normalized"),
    ]
    results = run_candidate_calls(
        repository,
        [
            {
                "module": "app.subject",
                "callable": "normalize_subject",
                "argument": value,
            }
            for value, _expected in cases
        ],
        timeout_seconds=timeout_seconds,
    )
    expected = [value for _input, value in cases]
    if results != expected:
        raise AssertionError(
            "normalize_subject did not satisfy controller-owned semantic cases"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=DEFAULT_REPOSITORY)
    args = parser.parse_args()
    try:
        verify_repository(args.repository)
    except Exception as exc:
        print(f"controller verifier failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(TRUSTED_VERIFIER_COMPLETION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
