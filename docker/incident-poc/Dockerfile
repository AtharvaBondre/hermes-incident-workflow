FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

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
