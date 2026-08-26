#!/usr/bin/env python3
"""Controller-owned acceptance verifier for the record-identity fixture."""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path
from typing import Any

try:
    from candidate_probe import TRUSTED_VERIFIER_COMPLETION, run_candidate_calls
except ModuleNotFoundError:  # Support direct imports from the repository test suite.
    from verifiers.candidate_probe import (
        TRUSTED_VERIFIER_COMPLETION,
        run_candidate_calls,
    )


DEFAULT_REPOSITORY = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "repositories"
    / "event-indexing-collision"
)
EVENT_FACTORY = {"module": "app.events", "callable": "RecordEvent.from_mapping"}


def record_events() -> list[dict[str, Any]]:
    suffix = secrets.token_hex(8)
    base = {
        "event_type": "record.ready",
        "tenant_id": f"org-{suffix}",
        "provider": "source-a",
        "external_record_id": f"record-{suffix}",
        "revision": 7,
    }
    return [
        base,
        dict(base),
        {**base, "tenant_id": f"org-other-{suffix}"},
        {**base, "revision": 8},
        {**base, "event_type": "record.redacted"},
        {**base, "provider": "source-b"},
    ]


def _calls(
    module: str,
    callable_name: str,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "module": module,
            "callable": callable_name,
            "factory": EVENT_FACTORY,
            "argument": event,
        }
        for event in events
        for _repeat in range(2)
    ]


def _validated_pairs(name: str, values: list[Any], expected: int) -> list[str]:
    if len(values) != expected * 2:
        raise AssertionError(f"{name} returned the wrong result count")
    checked: list[str] = []
    for index in range(expected):
        first, second = values[index * 2 : index * 2 + 2]
        if not isinstance(first, str) or not first.strip():
            raise AssertionError(f"{name} must return a non-empty string")
        if len(first.encode("utf-8")) > 512:
            raise AssertionError(f"{name} must be at most 512 UTF-8 bytes")
        if first != second:
            raise AssertionError(f"{name} must be deterministic")
        checked.append(first)
    return checked


def verify_repository(repository: Path) -> None:
    events = record_events()
    results = run_candidate_calls(
        repository,
        [
            *_calls("app.idempotency", "event_identity", events),
            *_calls("app.search_documents", "document_identity", events),
        ],
        timeout_seconds=5,
    )
    split = len(events) * 2
    event_keys = _validated_pairs("event_identity", results[:split], len(events))
    document_ids = _validated_pairs(
        "document_identity", results[split:], len(events)
    )

    if event_keys[0] != event_keys[1]:
        raise AssertionError("an exact replay must retain the same event key")
    if len(set(event_keys)) != 5:
        raise AssertionError(
            "tenant, revision, event type, and provider must contribute to event identity"
        )
    if not all(event_keys[0] != event_keys[index] for index in range(2, 6)):
        raise AssertionError("distinct event dimensions must receive distinct event keys")

    if len({document_ids[index] for index in (0, 1, 3, 4)}) != 1:
        raise AssertionError("revision and event type must retain document identity")
    if document_ids[0] in {document_ids[2], document_ids[5]}:
        raise AssertionError("tenant and provider must contribute to document identity")
    if len(set(document_ids)) != 3:
        raise AssertionError("the controller cases must produce three document IDs")

    ledger: set[str] = set()
    documents: dict[str, dict[str, Any]] = {}
    outcomes: list[str] = []
    for index in (0, 2, 1, 3):
        key = event_keys[index]
        if key in ledger:
            outcomes.append("duplicate")
            continue
        ledger.add(key)
        documents[document_ids[index]] = events[index]
        outcomes.append("indexed")
    if outcomes != ["indexed", "indexed", "duplicate", "indexed"]:
        raise AssertionError("trusted in-memory processing produced unexpected outcomes")
    if len(ledger) != 3 or len(documents) != 2:
        raise AssertionError("trusted ledger or document cardinality is incorrect")
    revisions = {event["tenant_id"]: event["revision"] for event in documents.values()}
    if revisions != {events[0]["tenant_id"]: 8, events[2]["tenant_id"]: 7}:
        raise AssertionError("trusted document replacement behavior is incorrect")


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
