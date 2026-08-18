"""Dependency-free model of the record indexing consumer."""

from __future__ import annotations

from dataclasses import asdict
from typing import Iterable

from app.events import RecordEvent
from app.idempotency import event_identity
from app.search_documents import document_identity


class InMemoryEventLedger:
    def __init__(self) -> None:
        self._completed: set[str] = set()

    def contains(self, identity: str) -> bool:
        return identity in self._completed

    def complete(self, identity: str) -> None:
        self._completed.add(identity)

    def __len__(self) -> int:
        return len(self._completed)


class InMemorySearchIndex:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, object]] = {}

    def upsert(self, identity: str, event: RecordEvent) -> None:
        self.documents[identity] = asdict(event)


class RecordConsumer:
    def __init__(self, ledger: InMemoryEventLedger, search: InMemorySearchIndex) -> None:
        self._ledger = ledger
        self._search = search

    def process(self, event: RecordEvent) -> str:
        event_key = event_identity(event)
        if self._ledger.contains(event_key):
            return "duplicate"

        self._search.upsert(document_identity(event), event)
        self._ledger.complete(event_key)
        return "indexed"

    def process_all(self, events: Iterable[RecordEvent]) -> list[str]:
        return [self.process(event) for event in events]
