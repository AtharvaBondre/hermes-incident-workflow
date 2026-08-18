#!/usr/bin/env python3
"""Controller-owned acceptance verifier for the record identity fixture.

This verifier intentionally lives outside the editable fixture repository. It
checks behavior without importing or trusting the repository's visible tests.
"""

from __future__ import annotations

import argparse
import importlib
import sys
import unittest
from dataclasses import replace
from pathlib import Path


DEFAULT_REPOSITORY = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "repositories"
    / "event-indexing-collision"
)


def load_fixture(repository: Path):
    repository = repository.resolve()
    if not (repository / "app").is_dir():
        raise ValueError(f"fixture repository has no app package: {repository}")

    for name in tuple(sys.modules):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    sys.path.insert(0, str(repository))

    events = importlib.import_module("app.events")
    idempotency = importlib.import_module("app.idempotency")
    search_documents = importlib.import_module("app.search_documents")
    consumer = importlib.import_module("app.consumer")
    return events, idempotency, search_documents, consumer


def build_suite(repository: Path) -> unittest.TestSuite:
    events, idempotency, search_documents, consumer = load_fixture(repository)
    RecordEvent = events.RecordEvent
    event_identity = idempotency.event_identity
    document_identity = search_documents.document_identity

    class ControllerOwnedIdentityVerification(unittest.TestCase):
        def setUp(self) -> None:
            self.base = RecordEvent("org-alpha", "source-a", "shared-42", 7)

        def test_event_identity_contract(self) -> None:
            self.assertEqual(event_identity(self.base), event_identity(replace(self.base)))
            self.assertNotEqual(
                event_identity(self.base),
                event_identity(replace(self.base, tenant_id="org-beta")),
            )
            self.assertNotEqual(
                event_identity(self.base),
                event_identity(replace(self.base, revision=8)),
            )
            self.assertNotEqual(
                event_identity(self.base),
                event_identity(replace(self.base, event_type="record.redacted")),
            )
            self.assertNotEqual(
                event_identity(self.base),
                event_identity(replace(self.base, provider="teams")),
            )

        def test_document_identity_contract(self) -> None:
            self.assertNotEqual(
                document_identity(self.base),
                document_identity(replace(self.base, tenant_id="org-beta")),
            )
            self.assertEqual(
                document_identity(self.base),
                document_identity(replace(self.base, revision=8)),
            )
            self.assertEqual(
                document_identity(self.base),
                document_identity(replace(self.base, event_type="record.redacted")),
            )
            self.assertNotEqual(
                document_identity(self.base),
                document_identity(replace(self.base, provider="teams")),
            )

        def test_end_to_end_processing_contract(self) -> None:
            ledger = consumer.InMemoryEventLedger()
            search = consumer.InMemorySearchIndex()
            processor = consumer.RecordConsumer(ledger, search)
            gold = replace(self.base, tenant_id="org-beta")
            newer_blue = replace(self.base, revision=8)

            outcomes = processor.process_all([self.base, gold, self.base, newer_blue])

            self.assertEqual(outcomes, ["indexed", "indexed", "duplicate", "indexed"])
            self.assertEqual(len(ledger), 3)
            self.assertEqual(len(search.documents), 2)
            revisions = {
                str(document["tenant_id"]): document["revision"]
                for document in search.documents.values()
            }
            self.assertEqual(revisions, {"org-alpha": 8, "org-beta": 7})

    return unittest.defaultTestLoader.loadTestsFromTestCase(
        ControllerOwnedIdentityVerification
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=DEFAULT_REPOSITORY)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(build_suite(args.repository))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
