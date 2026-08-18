import unittest

from app.consumer import InMemoryEventLedger, InMemorySearchIndex, RecordConsumer
from app.events import RecordEvent


class RecordConsumerTests(unittest.TestCase):
    def test_cross_tenant_replay_and_revision_sequence(self) -> None:
        ledger = InMemoryEventLedger()
        search = InMemorySearchIndex()
        consumer = RecordConsumer(ledger, search)

        blue_revision_7 = RecordEvent("org-alpha", "source-a", "shared-42", 7)
        gold_revision_7 = RecordEvent("org-beta", "source-a", "shared-42", 7)
        blue_revision_8 = RecordEvent("org-alpha", "source-a", "shared-42", 8)

        outcomes = consumer.process_all(
            [
                blue_revision_7,
                gold_revision_7,
                blue_revision_7,
                blue_revision_8,
            ]
        )

        self.assertEqual(outcomes, ["indexed", "indexed", "duplicate", "indexed"])
        self.assertEqual(len(ledger), 3)
        self.assertEqual(len(search.documents), 2)
        documents_by_tenant = {
            str(document["tenant_id"]): document for document in search.documents.values()
        }
        self.assertEqual(documents_by_tenant["org-alpha"]["revision"], 8)
        self.assertEqual(documents_by_tenant["org-beta"]["revision"], 7)


if __name__ == "__main__":
    unittest.main()
