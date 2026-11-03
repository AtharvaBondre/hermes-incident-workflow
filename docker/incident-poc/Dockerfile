FROM python:3.15-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211

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
