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
| Agent expands scope | Trusted policy fixes repository, package path prefixes, tests, attempts, and deadline; each incident exact-path list must equal its trusted scenario list before a worker request is built. |
| Agent accesses host secrets | Terminal tools run in Docker; forwarded environment is empty; inputs are read-only. |
| Agent exfiltrates through the terminal | Docker network mode is `none`; web, browser, MCP, memory, and delegation toolsets are disabled. |
| Agent changes its own tests | A required verifier lives outside the writable repository, keeps assertions in a parent process, and treats the candidate child response as untrusted data. |
| Candidate code executes on the controller host | Repository and controller-owned Python gates execute only in a pinned, network-disabled, non-root Docker sandbox with read-only inputs and bounded resources. |
| Model or candidate claims false success | `candidate_ready` requires a zero test exit claim and proposal paths exactly matching the host-derived patch; a trusted verifier parent still validates behavior and emits the completion marker. |
| Candidate uses links, binary content, mode changes, or oversized output | Host workspace and patch policy reject them. |
| Different code is delivered than tested | Patch SHA and candidate-tree digest are bound through test, verification, and delivery artifacts. |
| Duplicate, stale, or rewritten retry context | A required retry checks each fresh workspace against the original baseline, uses a fresh session, rejects duplicate candidate digests, and carries only bounded feedback reconstructed from an independent replay of the exact rejected patch. Post-run verification derives scenario and provider source from retained request, candidate, event, and Hermes artifacts instead of trusting mutable control labels. |
| Retained evidence is altered or leaks local paths | A terminal-state allowlist, package/home path redaction, privacy scan, and SHA-256 manifest are verified after cleanup. |
| Runaway attempts or time | Hard attempt ceiling and monotonic deadline. |
| Temporary resources remain | Scoped cleanup runs in `finally`; cleanup failure or any retained remaining-container ID prevents clean closeout. |
| Agent performs privileged delivery | Current delivery sinks only write draft JSON and expose no privileged operation. |

## Residual risk

- The host inference process must be able to contact the selected model provider
  and sends the supplied prompt context; this project does not enforce or
  allowlist host egress.
- Local artifacts are hash-linked but are not signed, immutable, or remotely attested.
- Denylist redaction is not comprehensive data-loss prevention.
- Docker Desktop resource controls and filesystem isolation are not equivalent to a dedicated hardened worker host.
- Exact incident paths constrain file selection but do not provide semantic
  review of an otherwise permitted change.
- Fixture and service tests cannot prove correctness for an unrelated real repository.
- Pinned third-party service images retain time-limited upstream findings recorded in the [container security baseline](security-baseline.md); they are accepted only for the isolated synthetic POC.
- Cancellation, host crash, concurrent orchestration, and durable restart recovery are not fully implemented.

## Production boundary

Adding any live connector requires a separate threat model covering authentication, authorization, tenant isolation, query allowlists, rate limits, data retention, network paths, audit storage, failure recovery, and human ownership.

Do not give the model raw production credentials. Put live access behind narrow deterministic brokers.
