"""Search document identity.

This implementation intentionally contains two incident bugs: it omits the
tenant boundary and makes the entity identity change with every revision.
"""

from app.events import RecordEvent


def document_identity(event: RecordEvent) -> str:
    """Return the stable OpenSearch document identity for a tenant record."""
    return f"{event.provider}:{event.external_record_id}:{event.revision}"
