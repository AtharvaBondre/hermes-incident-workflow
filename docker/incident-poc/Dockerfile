FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc

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
