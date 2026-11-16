FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd

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
