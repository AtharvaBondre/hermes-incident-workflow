#!/usr/bin/env python3
"""Near-real synthetic record incident verifier.

The candidate supplies two pure identity functions. This verifier pushes real
JSON events through Kafka, records idempotency decisions in PostgreSQL, and
indexes/query-checks the resulting record state in OpenSearch.
"""

from __future__ import annotations

import importlib
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import psycopg
from kafka import KafkaAdminClient, KafkaConsumer, KafkaProducer
from kafka.admin import NewTopic
from kafka.errors import TopicAlreadyExistsError


SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class Settings:
    candidate_root: str
    pg_host: str
    pg_port: int
    pg_database: str
    evidence_user: str
    evidence_password: str
    app_user: str
    app_password: str
    kafka_bootstrap_servers: str
    opensearch_url: str
    timeout_seconds: float


def load_settings() -> Settings:
    return Settings(
        candidate_root=os.environ.get("CANDIDATE_ROOT", "/candidate"),
        pg_host=os.environ.get("PGHOST", "postgres"),
        pg_port=int(os.environ.get("PGPORT", "5432")),
        pg_database=os.environ.get("PGDATABASE", "incident_poc"),
        evidence_user=os.environ.get("EVIDENCE_READER_USER", "evidence_reader"),
        evidence_password=os.environ["EVIDENCE_READER_PASSWORD"],
        app_user=os.environ.get("INCIDENT_APP_USER", "incident_app"),
        app_password=os.environ["INCIDENT_APP_PASSWORD"],
        kafka_bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"),
        opensearch_url=os.environ.get("OPENSEARCH_URL", "http://opensearch:9200").rstrip("/"),
        timeout_seconds=float(os.environ.get("INCIDENT_TIMEOUT_SECONDS", "90")),
    )


def candidate_functions(candidate_root: str) -> tuple[Callable[[dict[str, Any]], str], Callable[[dict[str, Any]], str]]:
    sys.path.insert(0, candidate_root)
    try:
        event_type = importlib.import_module("app.events").RecordEvent
        event_identity = importlib.import_module("app.idempotency").event_identity
        document_identity = importlib.import_module("app.search_documents").document_identity
    except (ImportError, AttributeError) as exc:
        raise AssertionError(
            "candidate must expose RecordEvent, event_identity(event), and "
            "document_identity(event)"
        ) from exc
    if not callable(event_type) or not callable(event_identity) or not callable(document_identity):
        raise AssertionError("candidate identity API attributes must be callable")

    def event_key(value: dict[str, Any]) -> str:
        return event_identity(event_type.from_mapping(value))

    def document_id(value: dict[str, Any]) -> str:
        return document_identity(event_type.from_mapping(value))

    return event_key, document_id


def record_events() -> list[dict[str, Any]]:
    original = {
        "event_type": "record.ready",
        "tenant_id": "org-alpha",
        "provider": "source-a",
        "external_record_id": "shared-42",
        "revision": 7,
        "content": "Customer asked for onboarding assistance.",
        "occurred_at": "2026-08-17T08:00:00Z",
    }
    replay = dict(original)
    new_revision = {
        **original,
        "revision": 8,
        "content": "Customer confirmed onboarding and requested a follow-up.",
        "occurred_at": "2026-08-17T08:05:00Z",
    }
    cross_tenant = {
        **original,
        "tenant_id": "org-beta",
        "content": "Customer asked for a renewal summary.",
        "occurred_at": "2026-08-17T08:10:00Z",
    }
    return [original, replay, new_revision, cross_tenant]


def checked_identity(name: str, function: Callable[[dict[str, Any]], str], event: dict[str, Any]) -> str:
    first = function(dict(event))
    second = function(dict(event))
    if not isinstance(first, str) or not first.strip():
        raise AssertionError(f"{name} must return a non-empty string")
    if len(first.encode("utf-8")) > 512:
        raise AssertionError(f"{name} must be at most 512 UTF-8 bytes")
    if first != second:
        raise AssertionError(f"{name} must be deterministic")
    return first


def verify_candidate_semantics(
    event_key: Callable[[dict[str, Any]], str],
    document_id: Callable[[dict[str, Any]], str],
    events: list[dict[str, Any]],
) -> dict[str, list[str]]:
    event_keys = [checked_identity("event_key", event_key, event) for event in events]
    document_ids = [checked_identity("document_id", document_id, event) for event in events]

    if event_keys[0] != event_keys[1]:
        raise AssertionError("an exact replay must retain the same event key")
    if event_keys[0] == event_keys[2]:
        raise AssertionError("a new record revision must receive a new event key")
    if event_keys[0] == event_keys[3]:
        raise AssertionError("the same record in another tenant must receive a new event key")
    if len(set(event_keys)) != 3:
        raise AssertionError("the four-event scenario must produce exactly three event keys")

    if document_ids[0] != document_ids[1]:
        raise AssertionError("an exact replay must target the same search document")
    if document_ids[0] != document_ids[2]:
        raise AssertionError("a new revision must replace the tenant record document")
    if document_ids[0] == document_ids[3]:
        raise AssertionError("cross-tenant records must never share a search document")
    if len(set(document_ids)) != 2:
        raise AssertionError("the four-event scenario must produce exactly two document IDs")

    return {"event_keys": event_keys, "document_ids": document_ids}


def pg_dsn(settings: Settings, *, user: str, password: str) -> str:
    return (
        f"host={settings.pg_host} port={settings.pg_port} dbname={settings.pg_database} "
        f"user={user} password={password} connect_timeout=5"
    )


def verify_read_only_evidence(settings: Settings) -> list[dict[str, Any]]:
    dsn = pg_dsn(settings, user=settings.evidence_user, password=settings.evidence_password)
    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT tenant_id, provider, external_record_id,
                       observed_revision, observed_state
                FROM evidence.record_evidence
                ORDER BY tenant_id
                """
            )
            rows = cursor.fetchall()
            if rows != [
                ("org-alpha", "source-a", "shared-42", 7, "indexed"),
                ("org-beta", "source-a", "shared-42", 7, "missing"),
            ]:
                raise AssertionError(f"unexpected synthetic evidence rows: {rows!r}")

            update_rejected = False
            try:
                cursor.execute(
                    "UPDATE evidence.record_evidence SET observed_state = 'tampered'"
                )
            except psycopg.errors.InsufficientPrivilege:
                update_rejected = True
                connection.rollback()
            if not update_rejected:
                raise AssertionError("evidence_reader unexpectedly acquired UPDATE permission")

    return [
        {
            "tenant_id": row[0],
            "provider": row[1],
            "external_record_id": row[2],
            "revision": row[3],
            "state": row[4],
        }
        for row in rows
    ]


def create_topic(bootstrap_servers: str, topic: str) -> None:
    admin = KafkaAdminClient(
        bootstrap_servers=bootstrap_servers,
        client_id="incident-poc-admin",
        request_timeout_ms=10_000,
    )
    try:
        try:
            admin.create_topics([NewTopic(name=topic, num_partitions=1, replication_factor=1)])
        except TopicAlreadyExistsError:
            pass
    finally:
        admin.close()


def publish_events(bootstrap_servers: str, topic: str, events: list[dict[str, Any]]) -> None:
    producer = KafkaProducer(
        bootstrap_servers=bootstrap_servers,
        client_id="incident-poc-producer",
        acks="all",
        retries=3,
        request_timeout_ms=10_000,
        value_serializer=lambda value: json.dumps(value, sort_keys=True).encode("utf-8"),
    )
    try:
        futures = [producer.send(topic, key=event["tenant_id"].encode("utf-8"), value=event) for event in events]
        for future in futures:
            future.get(timeout=15)
        producer.flush(timeout=15)
    finally:
        producer.close(timeout=15)


def consume_events(bootstrap_servers: str, topic: str, expected: int, deadline: float) -> list[Any]:
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=bootstrap_servers,
        client_id="incident-poc-consumer",
        group_id=f"incident-poc-{uuid.uuid4().hex}",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        consumer_timeout_ms=1_000,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
    )
    records: list[Any] = []
    try:
        while len(records) < expected and time.monotonic() < deadline:
            records.extend(list(consumer))
    finally:
        consumer.close(autocommit=False)
    if len(records) != expected:
        raise AssertionError(f"expected {expected} Kafka records, consumed {len(records)}")
    return records


def http_json(method: str, url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1_000]
        raise AssertionError(f"OpenSearch {method} {url} failed with HTTP {exc.code}: {detail}") from exc
    return json.loads(data) if data else {}


def create_index(opensearch_url: str, index: str) -> None:
    http_json(
        "PUT",
        f"{opensearch_url}/{urllib.parse.quote(index, safe='')}",
        {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "tenant_id": {"type": "keyword"},
                    "provider": {"type": "keyword"},
                    "external_record_id": {"type": "keyword"},
                    "revision": {"type": "integer"},
                    "content": {"type": "text"},
                    "event_key": {"type": "keyword"},
                    "occurred_at": {"type": "date"},
                }
            },
        },
    )


def index_event(opensearch_url: str, index: str, doc_id: str, event_key: str, event: dict[str, Any]) -> None:
    document = {
        "tenant_id": event["tenant_id"],
        "provider": event["provider"],
        "external_record_id": event["external_record_id"],
        "revision": event["revision"],
        "content": event["content"],
        "event_key": event_key,
        "occurred_at": event["occurred_at"],
    }
    http_json(
        "PUT",
        (
            f"{opensearch_url}/{urllib.parse.quote(index, safe='')}/_doc/"
            f"{urllib.parse.quote(doc_id, safe='')}"
        ),
        document,
    )


def record_idempotency(
    connection: psycopg.Connection[Any],
    event_key: str,
    record: Any,
) -> bool:
    event = record.value
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO incident.idempotency_ledger (
              event_key, tenant_id, provider, external_record_id, revision,
              kafka_topic, kafka_partition, kafka_offset, event_payload
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (event_key) DO NOTHING
            RETURNING event_key
            """,
            (
                event_key,
                event["tenant_id"],
                event["provider"],
                event["external_record_id"],
                event["revision"],
                record.topic,
                record.partition,
                record.offset,
                json.dumps(event, sort_keys=True),
            ),
        )
        inserted = cursor.fetchone() is not None
    connection.commit()
    return inserted


def verify_ledger(connection: psycopg.Connection[Any]) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT event_key, tenant_id, provider, external_record_id, revision
            FROM incident.idempotency_ledger
            ORDER BY tenant_id, provider, external_record_id, revision
            """
        )
        rows = cursor.fetchall()
    if len(rows) != 3:
        raise AssertionError(f"idempotency ledger must contain exactly 3 entries, found {len(rows)}")
    if sorted((row[1], row[2], row[3], row[4]) for row in rows) != [
        ("org-alpha", "source-a", "shared-42", 7),
        ("org-alpha", "source-a", "shared-42", 8),
        ("org-beta", "source-a", "shared-42", 7),
    ]:
        raise AssertionError(f"idempotency ledger contains unexpected identities: {rows!r}")
    return [
        {
            "event_key": row[0],
            "tenant_id": row[1],
            "provider": row[2],
            "external_record_id": row[3],
            "revision": row[4],
        }
        for row in rows
    ]


def reset_disposable_ledger(connection: psycopg.Connection[Any]) -> None:
    """Make repeated local runs deterministic without touching evidence."""
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM incident.idempotency_ledger")
    connection.commit()


def verify_search(opensearch_url: str, index: str) -> list[dict[str, Any]]:
    http_json(
        "POST",
        f"{opensearch_url}/{urllib.parse.quote(index, safe='')}/_refresh",
    )
    response = http_json(
        "POST",
        f"{opensearch_url}/{urllib.parse.quote(index, safe='')}/_search",
        {"size": 10, "sort": [{"tenant_id": "asc"}], "query": {"match_all": {}}},
    )
    hits = response.get("hits", {}).get("hits", [])
    if len(hits) != 2:
        raise AssertionError(f"search index must contain exactly 2 documents, found {len(hits)}")
    sources = [hit["_source"] for hit in hits]
    by_tenant = {source["tenant_id"]: source for source in sources}
    if set(by_tenant) != {"org-alpha", "org-beta"}:
        raise AssertionError(f"unexpected indexed tenants: {sorted(by_tenant)}")
    if by_tenant["org-alpha"]["revision"] != 8:
        raise AssertionError("org-alpha search document was not replaced by revision 8")
    if "follow-up" not in by_tenant["org-alpha"]["content"]:
        raise AssertionError("org-alpha search document does not contain revision 8 content")
    if by_tenant["org-beta"]["revision"] != 7:
        raise AssertionError("org-beta search document has the wrong revision")

    tenant_query = http_json(
        "POST",
        f"{opensearch_url}/{urllib.parse.quote(index, safe='')}/_search",
        {"query": {"term": {"tenant_id": "org-alpha"}}},
    )
    if tenant_query.get("hits", {}).get("total", {}).get("value") != 1:
        raise AssertionError("tenant-scoped OpenSearch query did not return exactly one document")
    return sources


def wait_for_dns(settings: Settings, deadline: float) -> None:
    for host in (settings.pg_host, settings.kafka_bootstrap_servers.split(":", 1)[0], urllib.parse.urlparse(settings.opensearch_url).hostname):
        if not host:
            raise AssertionError("service hostname is missing")
        while True:
            try:
                socket.getaddrinfo(host, None)
                break
            except socket.gaierror:
                if time.monotonic() >= deadline:
                    raise AssertionError(f"service hostname did not resolve: {host}")
                time.sleep(0.25)


def run() -> dict[str, Any]:
    settings = load_settings()
    deadline = time.monotonic() + settings.timeout_seconds
    wait_for_dns(settings, deadline)

    event_key, document_id = candidate_functions(settings.candidate_root)
    events = record_events()
    identities = verify_candidate_semantics(event_key, document_id, events)
    evidence = verify_read_only_evidence(settings)

    run_id = uuid.uuid4().hex[:12]
    topic = f"record-events-{run_id}"
    index = f"records-{run_id}"
    create_topic(settings.kafka_bootstrap_servers, topic)
    create_index(settings.opensearch_url, index)
    publish_events(settings.kafka_bootstrap_servers, topic, events)
    records = consume_events(settings.kafka_bootstrap_servers, topic, len(events), deadline)

    app_dsn = pg_dsn(settings, user=settings.app_user, password=settings.app_password)
    insert_results: list[bool] = []
    with psycopg.connect(app_dsn) as app_connection:
        reset_disposable_ledger(app_connection)
        for record in records:
            event = record.value
            key = checked_identity("event_key", event_key, event)
            doc_id = checked_identity("document_id", document_id, event)
            insert_results.append(record_idempotency(app_connection, key, record))
            index_event(settings.opensearch_url, index, doc_id, key, event)
        ledger = verify_ledger(app_connection)

    if insert_results != [True, False, True, True]:
        raise AssertionError(f"unexpected replay insertion decisions: {insert_results!r}")
    search_documents = verify_search(settings.opensearch_url, index)

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "scope": "synthetic record incident; internal disposable services only",
        "services": {
            "postgres": {"evidence_rows": len(evidence), "ledger_entries": len(ledger), "reader_update_rejected": True},
            "kafka": {"topic": topic, "published": len(events), "consumed": len(records)},
            "opensearch": {"index": index, "documents": len(search_documents), "tenant_query_count": 1},
        },
        "semantics": {
            "replay_deduplicated": True,
            "new_revision_distinct_event": True,
            "new_revision_replaced_document": True,
            "cross_tenant_isolated": True,
            "unique_event_keys": len(set(identities["event_keys"])),
            "unique_document_ids": len(set(identities["document_ids"])),
        },
    }


def main() -> int:
    started = time.monotonic()
    try:
        report = run()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
