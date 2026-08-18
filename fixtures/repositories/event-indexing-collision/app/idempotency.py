"""Event idempotency identity.

This implementation intentionally contains the incident bug: it assumes a
provider record identifier is globally unique and ignores event revision.
"""

from app.events import RecordEvent


def event_identity(event: RecordEvent) -> str:
    """Return the key used to suppress exact event replays."""
    return f"{event.event_type}:{event.provider}:{event.external_record_id}"
