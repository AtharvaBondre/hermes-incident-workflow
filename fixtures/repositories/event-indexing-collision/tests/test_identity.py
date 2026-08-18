import unittest
from dataclasses import replace

from app.events import RecordEvent
from app.idempotency import event_identity
from app.search_documents import document_identity


class IdentityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.event = RecordEvent(
            tenant_id="org-alpha",
            provider="source-a",
            external_record_id="shared-42",
            revision=7,
        )

    def test_exact_replay_has_the_same_event_identity(self) -> None:
        self.assertEqual(event_identity(self.event), event_identity(replace(self.event)))

    def test_event_identity_is_tenant_scoped(self) -> None:
        other_tenant = replace(self.event, tenant_id="org-beta")
        self.assertNotEqual(event_identity(self.event), event_identity(other_tenant))

    def test_event_identity_is_revision_sensitive(self) -> None:
        newer_revision = replace(self.event, revision=8)
        self.assertNotEqual(event_identity(self.event), event_identity(newer_revision))

    def test_event_identity_is_event_type_sensitive(self) -> None:
        redacted = replace(self.event, event_type="record.redacted")
        self.assertNotEqual(event_identity(self.event), event_identity(redacted))

    def test_event_identity_is_provider_scoped(self) -> None:
        other_provider = replace(self.event, provider="teams")
        self.assertNotEqual(event_identity(self.event), event_identity(other_provider))

    def test_document_identity_is_tenant_scoped(self) -> None:
        other_tenant = replace(self.event, tenant_id="org-beta")
        self.assertNotEqual(document_identity(self.event), document_identity(other_tenant))

    def test_document_identity_is_stable_across_revisions(self) -> None:
        newer_revision = replace(self.event, revision=8)
        self.assertEqual(document_identity(self.event), document_identity(newer_revision))

    def test_document_identity_is_stable_across_event_types(self) -> None:
        redacted = replace(self.event, event_type="record.redacted")
        self.assertEqual(document_identity(self.event), document_identity(redacted))

    def test_document_identity_is_provider_scoped(self) -> None:
        other_provider = replace(self.event, provider="teams")
        self.assertNotEqual(document_identity(self.event), document_identity(other_provider))


if __name__ == "__main__":
    unittest.main()
