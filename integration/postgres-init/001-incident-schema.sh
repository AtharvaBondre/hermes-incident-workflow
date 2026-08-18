#!/usr/bin/env bash
set -euo pipefail

psql \
  --set=ON_ERROR_STOP=1 \
  --set=evidence_reader_password="${EVIDENCE_READER_PASSWORD:?missing EVIDENCE_READER_PASSWORD}" \
  --set=incident_app_password="${INCIDENT_APP_PASSWORD:?missing INCIDENT_APP_PASSWORD}" \
  --username "${POSTGRES_USER}" \
  --dbname "${POSTGRES_DB}" \
  --file /docker-entrypoint-initdb.d/001-incident-schema.sql.in
