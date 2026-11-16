FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89

COPY requirements.txt /tmp/verifier-requirements.txt

RUN python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --only-binary=:all: \
      --require-hashes \
      --requirement /tmp/verifier-requirements.txt \
    && rm /tmp/verifier-requirements.txt \
    && addgroup -S incident \
    && adduser -S -G incident -h /nonexistent -s /sbin/nologin incident

USER incident:incident
WORKDIR /work

ENTRYPOINT ["python", "/verifier/event_indexing_verifier.py"]
