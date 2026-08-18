# Release checklist

- [ ] Confirm the repository owner has the right to publish and license every original file.
- [ ] Confirm the project name and Hermes references comply with applicable trademark guidance.
- [ ] Confirm no customer agreement, confidential architecture, or proprietary code is represented.
- [ ] Run `python3 scripts/check-public-surface.py`.
- [ ] Run `./scripts/run-local.sh test` twice from a clean clone.
- [ ] Run the event-indexing Docker scenario and `verify --latest`.
- [ ] Confirm no run container, network, or volume remains.
- [ ] Validate the Hermes skill and scripted sandbox smoke.
- [ ] Review pinned image indexes for supported architectures.
- [ ] Review dependencies and update `THIRD_PARTY_NOTICES.md`.
- [ ] Run the pinned-image vulnerability check and review every unexpired exception.
- [ ] Review GitHub Actions permissions and pinned action commits.
- [ ] Confirm generated artifacts, sessions, credentials, and local paths are ignored and absent from Git.
- [ ] Confirm README limitations match the tested release.
- [ ] Tag only after CI passes on the published commit.
