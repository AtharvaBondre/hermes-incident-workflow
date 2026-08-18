# Threat model

## Protected assets

- Provider, source-control, database, cloud, and notification credentials
- Trusted workflow policy and acceptance tests
- Host filesystem outside the run directory
- Protected branches and deployment configuration
- Production data and service availability
- Integrity of the accepted patch and retained evidence

## Primary threats and controls

| Threat | Current control |
|---|---|
| Prompt injection in incident, logs, rows, repository, or test output | Data is marked untrusted; known intake markers are denied; the skill forbids treating data as policy. |
| Agent expands scope | Trusted policy fixes repository, path prefixes, tests, attempts, and deadline. |
| Agent accesses host secrets | Terminal tools run in Docker; forwarded environment is empty; inputs are read-only. |
| Agent exfiltrates through the terminal | Docker network mode is `none`; web, browser, MCP, memory, and delegation toolsets are disabled. |
| Agent changes its own tests | Controller-owned verification lives outside the writable repository. |
| Candidate code executes on the controller host | Repository and controller-owned Python gates execute only in a pinned, network-disabled, non-root Docker sandbox with read-only inputs and bounded resources. |
| Model claims false success | Host derives the patch and runs deterministic gates; proposal text is non-authoritative. |
| Candidate uses links, binary content, mode changes, or oversized output | Host workspace and patch policy reject them. |
| Different code is delivered than tested | Patch SHA and candidate-tree digest are bound through test, verification, and delivery artifacts. |
| Duplicate or stale retry context | Every semantic attempt gets a fresh session and bounded redacted feedback. |
| Runaway attempts or time | Hard attempt ceiling and monotonic deadline. |
| Temporary resources remain | Scoped cleanup runs in `finally`; cleanup failure prevents clean closeout. |
| Agent performs privileged delivery | Current delivery sinks only write draft JSON and expose no privileged operation. |

## Residual risk

- The host inference process necessarily contacts the selected model provider and sends the supplied prompt context.
- Local artifacts are hash-linked but are not signed, immutable, or remotely attested.
- Denylist redaction is not comprehensive data-loss prevention.
- Docker Desktop resource controls and filesystem isolation are not equivalent to a dedicated hardened worker host.
- The generic path policy permits the configured prefix, not semantic review of every possible change beneath it.
- Fixture and service tests cannot prove correctness for an unrelated real repository.
- Pinned third-party service images retain time-limited upstream findings recorded in the [container security baseline](security-baseline.md); they are accepted only for the isolated synthetic POC.
- Cancellation, host crash, concurrent orchestration, and durable restart recovery are not fully implemented.

## Production boundary

Adding any live connector requires a separate threat model covering authentication, authorization, tenant isolation, query allowlists, rate limits, data retention, network paths, audit storage, failure recovery, and human ownership.

Do not give the model raw production credentials. Put live access behind narrow deterministic brokers.
