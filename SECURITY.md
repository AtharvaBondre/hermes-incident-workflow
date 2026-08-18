# Security policy

## Supported versions

Until the first stable release, security fixes are applied only to the latest commit on the default branch.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or exposed credential. Use GitHub's private vulnerability reporting feature after the repository is published. If that feature is unavailable, contact the repository owner through a private channel listed in the GitHub organization profile.

Include the affected revision, reproduction steps, impact, and any suggested mitigation. Do not include real customer data, access tokens, production logs, or exploit traffic against systems you do not own.

## Security boundary

This project is an experimental local reference implementation, not a production incident responder. Its default paths use synthetic data, fixture repositories, network-disabled editing containers, file-based delivery mocks, and no live-system connector.

A deployment that adds production evidence, source-control, notification, or cloud connectors creates a new security boundary and requires an independent review.

Digest pins and expiring vulnerability exceptions for disposable images are
documented in [Container security baseline](docs/security-baseline.md).
