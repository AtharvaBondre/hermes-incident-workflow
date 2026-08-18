# Container security baseline

All runtime images are pinned by multi-architecture OCI index digest. The
candidate-test and verifier image had no HIGH or CRITICAL findings when scanned
with Trivy 0.70.0 on 2026-08-18. The Hermes terminal image had no *fixable* HIGH
or CRITICAL finding; its retained findings had no upstream fix in that scan.

The disposable PostgreSQL, Kafka, and OpenSearch images retain upstream
findings even at the current stable versions used for qualification. They are
accepted only for this synthetic local POC because they expose no host ports,
run on an internal disposable network, receive no credentials or customer data,
and are destroyed after the run. This is not a production exception.

The exact finding sets are hash-bound in
`security/image-vulnerability-baseline.json`. Exceptions expire on 2026-09-18.
The check fails when a pin changes, a finding is added or altered, the scanner
version changes, or the exception expires:

```bash
python3 scripts/check-image-vulnerabilities.py
```

Refresh an image and requalify the full workflow before changing the baseline.
Do not extend an exception solely to make CI pass.
