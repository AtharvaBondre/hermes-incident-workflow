"""Domain event used by the synthetic record-indexing consumer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class RecordEvent:
    tenant_id: str
    provider: str
    external_record_id: str
    revision: int
    event_type: str = "record.ready"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RecordEvent":
        required = (
            "tenant_id",
            "provider",
            "external_record_id",
            "revision",
        )
        missing = [name for name in required if name not in value]
        if missing:
            raise ValueError(f"event missing fields: {', '.join(missing)}")

        strings = {
            "tenant_id": value["tenant_id"],
            "provider": value["provider"],
            "external_record_id": value["external_record_id"],
            "event_type": value.get("event_type", "record.ready"),
        }
        for name, item in strings.items():
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"event {name} must be a non-empty string")

        revision = value["revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise ValueError("event revision must be a positive integer")

        return cls(
            tenant_id=strings["tenant_id"].strip(),
            provider=strings["provider"].strip().lower(),
            external_record_id=strings["external_record_id"].strip(),
            revision=revision,
            event_type=strings["event_type"].strip().lower(),
        )
