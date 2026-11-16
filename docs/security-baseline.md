# Container security baseline

All runtime images are pinned by multi-architecture OCI index digest. The
current images were reviewed with Trivy 0.70.0 on 2026-11-16. The exact image,
count, and normalized finding-set digest are recorded in
`security/image-vulnerability-baseline.json`:

- Python 3.12 Alpine candidate/verifier: 0 CRITICAL, 16 HIGH;
- Python 3.12 slim Hermes terminal: 2 CRITICAL, 100 HIGH;
- PostgreSQL 14.25 Alpine: 1 CRITICAL, 25 HIGH;
- Kafka 4.3.2: 1 CRITICAL, 7 HIGH; and
- OpenSearch 3.9.0: 0 CRITICAL, 82 HIGH.

The disposable PostgreSQL, Kafka, and OpenSearch images retain upstream
findings even at the current stable versions used for qualification. They are
accepted only for this synthetic local POC because they expose no host ports,
run on an internal disposable network, receive no credentials or customer data,
and are destroyed after the run. This is not a production exception.

The exact finding sets are hash-bound in
`security/image-vulnerability-baseline.json`. Exceptions expire on 2026-12-16.
The check fails when a pin changes, a finding is added or altered, the scanner
version changes, or the exception expires:

```bash
python3 scripts/check-image-vulnerabilities.py
```

Refresh an image and requalify the full workflow before changing the baseline.
Do not extend an exception solely to make CI pass.

The Hermes terminal's two critical Debian findings had no available fix at
qualification. The PostgreSQL critical finding is in bundled `gosu`; Kafka's
critical Brotli finding has a package fix but no rebuilt official image at the
qualified digest. Those residual findings, and all HIGH findings, are accepted
only for the exact disposable synthetic boundaries described in the baseline.
They remain production blockers. Any expiry, changed pin, changed count, or
changed finding digest fails closed and requires a new review and complete
requalification.
