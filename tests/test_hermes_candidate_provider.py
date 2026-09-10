import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "runner.py"
SPEC = importlib.util.spec_from_file_location("hiw_candidate_runner", RUNNER_PATH)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class HermesCandidateProviderTests(unittest.TestCase):
    def qualified_runtime_identity(self) -> dict[str, object]:
        return {
            "version": runner.HERMES_REQUIRED_VERSION,
            "revision": runner.HERMES_QUALIFIED_REVISION,
            "checkout_clean": True,
            "pyproject_sha256": runner.HERMES_PYPROJECT_SHA256,
            "lock_sha256": runner.HERMES_LOCK_SHA256,
            "qualified": True,
            "problems": [],
        }

    @contextlib.contextmanager
    def installed_profile_patch(
        self,
        root: Path,
        runtime_identity: dict[str, object] | None = None,
    ):
        source_profile = root / "installed-hermes-profile"
        source_profile.mkdir()
        prepare = runner.prepare_disposable_hermes_profile
        with (
            mock.patch.object(
                runner,
                "prepare_disposable_hermes_profile",
                side_effect=lambda worker_root, profile: prepare(
                    worker_root,
                    profile,
                    source_profile=source_profile,
                ),
            ),
            mock.patch.object(
                runner,
                "inspect_hermes_runtime",
                return_value=runtime_identity or self.qualified_runtime_identity(),
            ),
        ):
            yield

    def fixture_context(
        self, artifact_dir: Path, attempt: int = 1, feedback: list[dict] | None = None
    ) -> dict:
        incident = runner.read_json(
            runner.FIXTURES / "incidents" / "retry-success.json"
        )
        evidence = runner.collect_evidence(incident)
        packet = runner.build_hermes_request(
            run_id="20260817T000000Z-test",
            attempt=attempt,
            incident=incident,
            evidence=evidence,
            feedback=feedback or [],
            deadline=time.monotonic() + 30,
        )
        return {"artifact_dir": artifact_dir, "packet": packet}

    def write_ready_proposal(
        self,
        output_dir: Path,
        *,
        attempt: int = 1,
        changed_paths: list[str] | None = None,
    ) -> None:
        runner.write_json(
            output_dir / "proposal.json",
            {
                "schema_version": 1,
                "attempt": attempt,
                "status": "candidate_ready",
                "changed_paths": changed_paths or ["app/subject.py"],
                "required_test": {
                    "command": runner.HERMES_REQUIRED_TEST,
                    "exit_code": 0,
                },
                "rationale": "Prepare the smallest bounded correction.",
                "uncertainty": [],
            },
        )

    def verified_hermes_run(self, artifact_root: Path) -> Path:
        scenarios = runner.read_json(runner.FIXTURES / "scenarios.json")
        scenario = scenarios["event-indexing-collision"]
        repository = runner.scenario_repository(scenario)
        trusted_patch = runner.FIXTURES / scenario["patches"][0]
        patch_payload = trusted_patch.read_bytes()
        patch_sha256 = runner.hashlib.sha256(patch_payload).hexdigest()
        changed_paths = runner.validate_hermes_patch_bytes(patch_payload)[1]
        digest_root = artifact_root / "digest-work"
        digest_workspace = runner.create_workspace(
            digest_root,
            "candidate",
            repository,
        )
        applied = runner.apply_candidate(
            digest_workspace,
            trusted_patch,
            time.monotonic() + 10,
        )
        candidate_digest = applied["candidate_digest"]
        runner.shutil.rmtree(digest_root)

        run_dir = artifact_root / "hermes-run"
        run_dir.mkdir()
        patch_name = "attempt-1-hermes.patch"
        session_id = "20260817_120000_ab12cd"
        incident = runner.read_json(runner.FIXTURES / scenario["incident"])
        request = runner.build_hermes_request(
            run_id="verified-hermes-run",
            attempt=1,
            incident=incident,
            evidence=runner.collect_evidence(incident),
            feedback=[],
            deadline=time.monotonic() + 30,
            independent_diagnosis=False,
            session_usage_required=True,
        )
        trusted_test = {
            "passed": True,
            "checks": [
                {
                    "exit_code": 0,
                    "process_exit_code": 0,
                    "passed": True,
                    "trusted_verifier_completed": True,
                    "output": runner.TRUSTED_VERIFIER_COMPLETION + "\n",
                }
            ],
        }
        (run_dir / patch_name).write_bytes(patch_payload)
        runner.write_json(
            run_dir / "control.json",
            {
                "run_id": "verified-hermes-run",
                "attempts": 1,
                "scenario": "event-indexing-collision",
                "outcome": "SUCCEEDED",
                "candidate_source": "hermes-real-model",
                "candidate_digest": candidate_digest,
                "issue_id": incident["issue_id"],
                "repository": incident["repository"],
                "base_revision": incident["base_revision"],
            },
        )
        (run_dir / "events.jsonl").write_text(
            json.dumps(
                {"event": "RECEIVED", "scenario": "event-indexing-collision"}
            )
            + "\n"
            + json.dumps(
                {
                    "event": "PATCHING",
                    "attempt": 1,
                    "candidate_source": "hermes-real-model",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        runner.write_json(run_dir / "attempt-1-request.json", request)
        runner.write_json(run_dir / "attempt-1-hermes-request.json", request)
        usage = {
            "schema_version": 1,
            "available": True,
            "session_id": session_id,
            "api_call_count": 1,
            "input_tokens": 10,
            "cache_read_tokens": 20,
            "cache_write_tokens": 5,
            "output_tokens": 4,
            "reasoning_tokens": 1,
            "total_tokens": 39,
            "reasoning_tokens_are_subset_of_output": True,
            "estimated_cost_usd": None,
            "actual_cost_usd": None,
            "routes": [
                {
                    "session_id": session_id,
                    "model": "example-model",
                    "billing_provider": "example-provider",
                    "billing_mode": "provider",
                    "task": "candidate",
                    "api_call_count": 1,
                    "input_tokens": 10,
                    "cache_read_tokens": 20,
                    "cache_write_tokens": 5,
                    "output_tokens": 4,
                    "reasoning_tokens": 1,
                    "total_tokens": 39,
                    "estimated_cost_usd": None,
                    "actual_cost_usd": None,
                    "cost_status": "unknown",
                    "cost_source": "none",
                }
            ],
        }
        runner.write_json(run_dir / "attempt-1-hermes-usage.json", usage)
        usage_sha256 = runner.hashlib.sha256(
            (run_dir / "attempt-1-hermes-usage.json").read_bytes()
        ).hexdigest()
        runner.write_json(
            run_dir / "attempt-1-candidate.json",
            {
                "schema_version": runner.CANDIDATE_CONTRACT_VERSION,
                "source": "hermes-real-model",
                "attempt": 1,
                "patch": patch_name,
                "patch_sha256": patch_sha256,
                "changed_paths": changed_paths,
                "candidate_digest": candidate_digest,
            },
        )
        runner.write_json(
            run_dir / "attempt-1-hermes-execution.json",
            {
                "schema_version": 1,
                "kind": "hermes-candidate-execution",
                "attempt": 1,
                "profile": "example-profile",
                "provider": "example-provider",
                "model": "example-model",
                "fresh_session": True,
                "controller_is_sole_acceptor": True,
                "strict_proposal_required": True,
                "session_usage_required": True,
                "disposable_profile": True,
                "credential_files_bridged": [],
                "runtime_identity": self.qualified_runtime_identity(),
                "outcome": "CANDIDATE_RETURNED",
                "session_id": session_id,
                "proposal": {
                    "schema_version": 1,
                    "attempt": 1,
                    "status": "candidate_ready",
                    "changed_paths": changed_paths,
                    "required_test": {
                        "command": runner.HERMES_REQUIRED_TEST,
                        "exit_code": 0,
                    },
                    "rationale": "Prepare the smallest bounded correction.",
                    "uncertainty": [],
                },
                "proposal_paths_match_patch": True,
                "usage_artifact": "attempt-1-hermes-usage.json",
                "usage_sha256": usage_sha256,
                "patch_sha256": patch_sha256,
                "candidate_digest": candidate_digest,
                "cleanup": {
                    "complete": True,
                    "scoped_container_ids": [],
                    "removed_container_ids": [],
                    "observation_errors": [],
                    "remaining_container_ids": [],
                    "profile_state": {
                        "complete": True,
                        "remaining": [],
                        "removed": ["hermes_root", "launcher_home"],
                    },
                    "worker_directory": {"complete": True, "remaining": []},
                },
            },
        )
        runner.write_json(
            run_dir / "attempt-1-result.json",
            {
                "attempt": 1,
                "baseline_digest": runner.tree_digest(repository),
                "candidate_digest": candidate_digest,
                "test": trusted_test,
            },
        )
        runner.write_json(
            run_dir / "verification.json",
            {
                "accepted": True,
                "candidate_digest": candidate_digest,
                "tested_digest": candidate_digest,
                "test": trusted_test,
            },
        )
        runner.write_json(
            run_dir / "mock-github.json",
            {
                "draft": True,
                "candidate_digest": candidate_digest,
                "operations": [
                    "create_branch",
                    "create_commit",
                    "create_pull_request",
                ],
            },
        )
        runner.write_json(run_dir / "mock-slack.json", {"kind": "mock_slack_delivery"})
        runner.write_json(
            run_dir / "closeout.json",
            {
                "cleanup_complete": True,
                "evidence_complete": True,
                "evidence_manifest": runner.EVIDENCE_MANIFEST_NAME,
            },
        )
        runner.write_json(
            run_dir / "hermes-usage-summary.json",
            runner.aggregate_hermes_usage(run_dir),
        )
        runner.write_evidence_manifest(run_dir)
        return run_dir

    def test_request_packet_is_redacted_bounded_and_controller_owned(self) -> None:
        incident = runner.read_json(
            runner.FIXTURES / "incidents" / "retry-success.json"
        )
        evidence = runner.read_json(runner.FIXTURES / "evidence.json")
        feedback = [
            {
                "attempt": number,
                "stage": "controller_test",
                "output": "person@example.invalid token=synthetic-sensitive-value " + "x" * 4000,
                "extra_untrusted_field": "must not cross the boundary",
            }
            for number in range(1, 8)
        ]

        packet = runner.build_hermes_request(
            run_id="bounded-request",
            attempt=2,
            incident=incident,
            evidence=evidence,
            feedback=feedback,
            deadline=time.monotonic() + 30,
        )
        serialized = json.dumps(packet)

        self.assertEqual(packet["schema_version"], 1)
        self.assertTrue(packet["policy"]["controller_is_sole_acceptor"])
        self.assertEqual(len(packet["feedback"]), runner.MAX_HERMES_FEEDBACK_ITEMS)
        self.assertNotIn("extra_untrusted_field", serialized)
        self.assertNotIn("person@example.invalid", serialized)
        self.assertNotIn("synthetic-sensitive-value", serialized)
        self.assertLessEqual(
            len(packet["feedback"][-1]["output"]),
            runner.MAX_HERMES_FEEDBACK_OUTPUT,
        )
        self.assertEqual(packet["incident"]["allowed_paths"], ["app/subject.py"])
        self.assertNotIn("required_test_command", packet["incident"])
        self.assertEqual(
            packet["policy"]["allowed_paths"],
            ["app/subject.py"],
        )

    def test_independent_diagnosis_omits_prior_diagnosis_and_plan(self) -> None:
        incident = runner.read_json(
            runner.FIXTURES / "incidents" / "retry-success.json"
        )
        packet = runner.build_hermes_request(
            run_id="independent-diagnosis",
            attempt=1,
            incident=incident,
            evidence=runner.collect_evidence(incident),
            feedback=[],
            deadline=time.monotonic() + 30,
            independent_diagnosis=True,
        )

        self.assertTrue(packet["policy"]["independent_diagnosis"])
        self.assertNotIn("diagnosis", packet)
        self.assertNotIn("controller_approved_execution_plan", packet)
        with self.assertRaisesRegex(runner.PolicyDenied, "independent diagnosis"):
            runner.build_hermes_request(
                run_id="independent-diagnosis",
                attempt=1,
                incident=incident,
                evidence=runner.collect_evidence(incident),
                feedback=[],
                deadline=time.monotonic() + 30,
                diagnosis={"summary": "untrusted prior conclusion"},
                independent_diagnosis=True,
            )

    def test_incident_allowlist_must_equal_the_trusted_scenario_policy(self) -> None:
        scenario = runner.read_json(runner.FIXTURES / "scenarios.json")[
            "retry-success"
        ]
        runner.validate_scenario_candidate_paths(
            scenario,
            ["app/subject.py"],
            ["app/subject.py"],
        )
        with self.assertRaisesRegex(runner.PolicyDenied, "trusted scenario policy"):
            runner.validate_scenario_candidate_paths(
                scenario,
                [],
                ["app/other.py"],
            )
        with self.assertRaisesRegex(runner.PolicyDenied, "incident policy"):
            runner.validate_incident_path_allowlist(
                ["app/other.py"],
                ["app/subject.py"],
            )

    def test_usage_preserves_exact_buckets_and_unknown_cost(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            hermes_root = Path(temporary) / "hermes-root"
            database = runner.hermes_profile_state_path(
                "example-profile",
                hermes_root=hermes_root,
            )
            database.parent.mkdir(parents=True)
            connection = runner.sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE sessions (
                    id TEXT PRIMARY KEY,
                    parent_session_id TEXT,
                    pricing_version TEXT
                );
                CREATE TABLE session_model_usage (
                    session_id TEXT,
                    model TEXT,
                    billing_provider TEXT,
                    billing_mode TEXT,
                    task TEXT,
                    api_call_count INTEGER,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    cache_read_tokens INTEGER,
                    cache_write_tokens INTEGER,
                    reasoning_tokens INTEGER,
                    estimated_cost_usd REAL,
                    actual_cost_usd REAL,
                    cost_status TEXT,
                    cost_source TEXT
                );
                """
            )
            session_id = "20260910_120000_abcdef"
            connection.execute(
                "INSERT INTO sessions VALUES (?, NULL, NULL)",
                (session_id,),
            )
            connection.execute(
                "INSERT INTO session_model_usage VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    "example-model",
                    "example-provider",
                    "provider",
                    "candidate",
                    2,
                    100,
                    20,
                    300,
                    7,
                    5,
                    0.0,
                    0.0,
                    "unknown",
                    "none",
                ),
            )
            connection.commit()
            connection.close()

            usage = runner.read_hermes_session_usage(
                "example-profile",
                session_id,
                hermes_root=hermes_root,
            )
            run_dir = Path(temporary) / "run"
            run_dir.mkdir()
            runner.write_json(run_dir / "attempt-1-hermes-usage.json", usage)
            summary = runner.aggregate_hermes_usage(run_dir)

        self.assertTrue(usage["available"])
        self.assertEqual(usage["input_tokens"], 100)
        self.assertEqual(usage["cache_read_tokens"], 300)
        self.assertEqual(usage["cache_write_tokens"], 7)
        self.assertEqual(usage["output_tokens"], 20)
        self.assertEqual(usage["reasoning_tokens"], 5)
        self.assertEqual(usage["total_tokens"], 427)
        self.assertTrue(usage["reasoning_tokens_are_subset_of_output"])
        self.assertIsNone(usage["estimated_cost_usd"])
        self.assertIsNone(usage["actual_cost_usd"])
        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["total_tokens"], 427)
        self.assertIsNone(summary["estimated_cost_usd"])
        self.assertEqual(
            runner._reported_cost(0.0, status="included", source="none"),
            0.0,
        )
        self.assertIsNone(
            runner._reported_cost(0.0, status="unknown", source="none")
        )

    def test_manifest_hashes_only_sanitized_allowlisted_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            run_dir.mkdir()
            runner.write_json(run_dir / "control.json", {"state": "CLOSED"})
            runner.write_json(
                run_dir / "closeout.json",
                {"cleanup_complete": True, "evidence_manifest": runner.EVIDENCE_MANIFEST_NAME},
            )
            manifest = runner.write_evidence_manifest(run_dir)

            self.assertEqual(runner.verify_evidence_manifest(run_dir), [])
            self.assertEqual(
                [record["path"] for record in manifest["files"]],
                ["closeout.json", "control.json"],
            )
            runner.write_json(run_dir / "control.json", {"state": "TAMPERED"})
            self.assertTrue(
                any(
                    "manifest" in issue and "control.json" in issue
                    for issue in runner.verify_evidence_manifest(run_dir)
                )
            )

            runner.write_evidence_manifest(run_dir)
            (run_dir / "debug.log").write_text("not proof\n", encoding="utf-8")
            self.assertIn(
                "unexpected retained artifact: debug.log",
                runner.verify_evidence_manifest(run_dir),
            )

    def test_manifest_failure_revokes_delivery_and_marks_terminal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            run_dir.mkdir()
            control = {
                "run_id": "manifest-failure",
                "issue_id": "DEMO-001",
                "outcome": "SUCCEEDED",
                "attempts": 1,
                "cleanup_complete": False,
            }
            runner.write_json(run_dir / "control.json", control)
            runner.write_json(
                run_dir / "attempt-1-result.json",
                {"output": str(runner.PACKAGE_ROOT / "private")},
            )
            runner.write_json(run_dir / "mock-github.json", {"draft": True})
            runner.mock_notify(run_dir, control)

            closeout = runner.closeout(run_dir, control, [])

            self.assertEqual(control["state"], "EVIDENCE_FAILED")
            self.assertEqual(control["outcome"], "FAILED")
            self.assertFalse(closeout["evidence_complete"])
            self.assertIsNone(closeout["evidence_manifest"])
            self.assertFalse((run_dir / runner.EVIDENCE_MANIFEST_NAME).exists())
            self.assertFalse((run_dir / "mock-github.json").exists())
            self.assertEqual(
                runner.read_json(run_dir / "mock-slack.json")["outcome"],
                "FAILED",
            )

    def test_retained_output_redacts_package_and_home_paths(self) -> None:
        package_path = str(runner.PACKAGE_ROOT / "fixtures" / "evidence.json")
        home_path = str(Path.home() / "outside-package" / "example.txt")
        redacted = runner.redact_text(f"package={package_path} home={home_path}")

        self.assertNotIn(str(runner.PACKAGE_ROOT), redacted)
        self.assertNotIn(str(Path.home()), redacted)
        self.assertIn("<package>/fixtures/evidence.json", redacted)
        self.assertIn("<home>/outside-package/example.txt", redacted)

        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "control.json"
            artifact.write_text(package_path, encoding="utf-8")
            self.assertEqual(
                runner.retained_artifact_privacy_issues([artifact]),
                ["local absolute path retained in control.json"],
            )

    def test_execution_plan_is_bound_to_incident_test_and_path_policy(self) -> None:
        incident = runner.read_json(
            runner.FIXTURES / "incidents" / "event-indexing-collision.json"
        )
        evidence = runner.read_json(
            runner.FIXTURES / "evidence" / "event-indexing-collision.json"
        )
        original = runner.read_json(
            runner.FIXTURES / "execution-plans" / "event-indexing-collision.json"
        )

        valid = runner.build_hermes_request(
            run_id="plan-binding",
            attempt=1,
            incident=incident,
            evidence=evidence,
            feedback=[],
            deadline=time.monotonic() + 30,
            execution_plan=original,
        )
        self.assertEqual(
            valid["controller_approved_execution_plan"]["issue_id"],
            incident["issue_id"],
        )

        mutations = (
            ("does not match", lambda plan: plan.update(issue_id="DEMO-INC-OTHER")),
            ("changed the required test", lambda plan: plan.update(required_test="true")),
            (
                "forbidden path",
                lambda plan: plan["edits"][0].update(path=".github/workflows/ci.yml"),
            ),
        )
        for message, mutate in mutations:
            with self.subTest(message=message):
                plan = json.loads(json.dumps(original))
                mutate(plan)
                with self.assertRaisesRegex(runner.PolicyDenied, message):
                    runner.build_hermes_request(
                        run_id="plan-binding",
                        attempt=1,
                        incident=incident,
                        evidence=evidence,
                        feedback=[],
                        deadline=time.monotonic() + 30,
                        execution_plan=plan,
                    )

    def test_session_parser_requires_exactly_one_id(self) -> None:
        self.assertEqual(
            runner.parse_hermes_session_id("\nsession_id: 20260817_120000_ab12cd\n"),
            "20260817_120000_ab12cd",
        )
        for value in (
            "no session here",
            "session_id: first_session\nsession_id: second_session\n",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(runner.PolicyDenied, "exactly one"):
                    runner.parse_hermes_session_id(value)

    def test_hermes_environment_never_forwards_provider_keys(self) -> None:
        paths = {
            "input_dir": Path("/tmp/hiw-input"),
            "task_path": Path("/tmp/hiw-task.json"),
            "output_dir": Path("/tmp/hiw-output"),
            "hermes_root": Path("/tmp/hiw-hermes-root"),
            "launcher_home": Path("/tmp/hiw-launcher-home"),
        }
        with mock.patch.dict(
            os.environ,
            {
                "AZURE_OPENAI_API_KEY": "synthetic-azure-key",
                "OPENAI_API_KEY": "synthetic-openai-key",
                "GITHUB_TOKEN": "synthetic-github-token",
                "PATH": "/usr/bin",
            },
            clear=True,
        ):
            for provider in (None, "example-provider", "provider-a", "provider-b"):
                with self.subTest(provider=provider):
                    environment = runner.hermes_process_environment(
                        **paths,
                        provider=provider,
                    )
                    self.assertNotIn("AZURE_OPENAI_API_KEY", environment)
                    self.assertNotIn("OPENAI_API_KEY", environment)
                    self.assertNotIn("GITHUB_TOKEN", environment)
                    self.assertEqual(
                        environment["HOME"], str(Path("/tmp/hiw-launcher-home").resolve())
                    )
                    self.assertEqual(
                        environment["HERMES_HOME"], str(Path("/tmp/hiw-hermes-root").resolve())
                    )

    def test_disposable_profile_copies_only_allowlisted_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "installed-profile"
            source.mkdir()
            (source / ".env").write_text(
                "MODEL_API_KEY=synthetic\nHERMES_HOME=/must-not-copy\n",
                encoding="utf-8",
            )
            (source / "auth.json").write_text("{}\n", encoding="utf-8")
            (source / "state.db").write_text("must-not-copy\n", encoding="utf-8")
            (source / "logs").mkdir()
            (source / "logs" / "agent.log").write_text("must-not-copy\n", encoding="utf-8")

            prepared = runner.prepare_disposable_hermes_profile(
                root / "worker",
                runner.HERMES_PROFILE,
                source_profile=source,
            )
            profile = prepared["profile_dir"]
            self.assertEqual(prepared["credential_files"], [".env", "auth.json"])
            self.assertEqual((profile / ".env").stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (profile / ".env").read_text(encoding="utf-8"),
                "MODEL_API_KEY=synthetic\n",
            )
            self.assertFalse((profile / "state.db").exists())
            self.assertFalse((profile / "logs").exists())
            self.assertTrue(
                all(
                    (profile / item).is_dir()
                    for item in runner.HERMES_CACHE_DIRECTORIES
                )
            )

            cleanup = runner.cleanup_disposable_hermes_profile(prepared)
            self.assertTrue(cleanup["complete"])
            self.assertFalse(prepared["hermes_root"].exists())
            self.assertFalse(prepared["launcher_home"].exists())

    def test_disposable_profile_rejects_symlinked_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "installed-profile"
            source.mkdir()
            target = root / "credential-target"
            target.write_text("MODEL_API_KEY=synthetic\n", encoding="utf-8")
            (source / ".env").symlink_to(target)

            with self.assertRaisesRegex(runner.PolicyDenied, "safe regular file"):
                runner.prepare_disposable_hermes_profile(
                    root / "worker",
                    runner.HERMES_PROFILE,
                    source_profile=source,
                )
            self.assertFalse((root / "worker" / "hermes-home").exists())

    def test_proposal_parser_is_strict_and_attempt_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proposal_path = Path(temporary) / "proposal.json"
            proposal = {
                "schema_version": 1,
                "attempt": 2,
                "status": "candidate_ready",
                "changed_paths": ["app/subject.py"],
                "required_test": {
                    "command": runner.HERMES_REQUIRED_TEST,
                    "exit_code": 0,
                },
                "rationale": "Normalize whitespace and case.",
                "uncertainty": [],
            }
            runner.write_json(proposal_path, proposal)
            self.assertEqual(
                runner.parse_hermes_proposal(proposal_path, 2)["status"],
                "candidate_ready",
            )

            proposal["unexpected"] = True
            runner.write_json(proposal_path, proposal)
            with self.assertRaisesRegex(runner.PolicyDenied, "fields"):
                runner.parse_hermes_proposal(proposal_path, 2)

            proposal.pop("unexpected")
            proposal["required_test"]["exit_code"] = 1
            runner.write_json(proposal_path, proposal)
            with self.assertRaisesRegex(runner.PolicyDenied, "failing required test"):
                runner.parse_hermes_proposal(proposal_path, 2)

            for field, value, expected_attempt in (
                ("schema_version", True, 2),
                ("attempt", True, 1),
            ):
                with self.subTest(field=field):
                    proposal[field] = value
                    proposal["required_test"]["exit_code"] = 0
                    if field != "schema_version":
                        proposal["schema_version"] = 1
                    runner.write_json(proposal_path, proposal)
                    with self.assertRaises(runner.PolicyDenied):
                        runner.parse_hermes_proposal(proposal_path, expected_attempt)
                    proposal[field] = 2 if field == "attempt" else 1

            proposal["schema_version"] = 1
            proposal["attempt"] = 2
            proposal["required_test"]["exit_code"] = False
            runner.write_json(proposal_path, proposal)
            with self.assertRaisesRegex(runner.PolicyDenied, "exit code"):
                runner.parse_hermes_proposal(proposal_path, 2)

    def test_patch_policy_rejects_mode_change_and_oversize(self) -> None:
        mode_change = (
            "diff --git a/app/subject.py b/app/subject.py\n"
            "old mode 100644\n"
            "new mode 100755\n"
        ).encode()
        with self.assertRaisesRegex(runner.PolicyDenied, "mode change"):
            runner.validate_hermes_patch_bytes(mode_change)
        with self.assertRaisesRegex(runner.PolicyDenied, "128 KiB"):
            runner.validate_hermes_patch_bytes(
                b"x" * (runner.MAX_HERMES_PATCH_BYTES + 1)
            )
        too_many_paths = "".join(
            (
                f"diff --git a/app/file_{number}.py b/app/file_{number}.py\n"
                "--- /dev/null\n"
                f"+++ b/app/file_{number}.py\n"
                "@@ -0,0 +1 @@\n"
                "+value = 1\n"
            )
            for number in range(runner.MAX_HERMES_CHANGED_PATHS + 1)
        ).encode()
        with self.assertRaisesRegex(runner.PolicyDenied, "more than 20"):
            runner.validate_hermes_patch_bytes(too_many_paths)

    def test_workspace_policy_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            (workspace / "regular.py").write_text("value = 1\n", encoding="utf-8")
            (workspace / "linked.py").symlink_to(workspace / "regular.py")

            with self.assertRaisesRegex(runner.PolicyDenied, "linked or irregular"):
                runner.validate_hermes_workspace(workspace)

    def test_real_provider_host_computes_and_applies_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run"
            artifact_dir.mkdir()
            workspace = runner.create_workspace(artifact_dir, "attempt-1")
            original = (workspace / "app" / "subject.py").read_text(encoding="utf-8")
            provider = runner.HermesCandidateProvider(
                provider="example-provider",
                model="example-model",
            )
            observed: dict[str, object] = {}

            def invoke(args, *, cwd, environment, timeout):
                observed["args"] = args
                observed["environment"] = environment
                sandbox = Path(environment["HIW_HERMES_OUTPUT"]) / "workspace"
                subject = sandbox / "app" / "subject.py"
                subject.write_text(
                    subject.read_text(encoding="utf-8").replace(
                        "    return value.strip()\n",
                        '    return " ".join(value.split()).lower()\n',
                    ),
                    encoding="utf-8",
                )
                runner.write_json(
                    Path(environment["HIW_HERMES_OUTPUT"]) / "proposal.json",
                    {
                        "schema_version": 1,
                        "attempt": 1,
                        "status": "candidate_ready",
                        "changed_paths": ["app/subject.py"],
                        "required_test": {
                            "command": runner.HERMES_REQUIRED_TEST,
                            "exit_code": 0,
                        },
                        "rationale": "Normalize repeated whitespace and case.",
                        "uncertainty": [],
                    },
                )
                return subprocess.CompletedProcess(
                    args,
                    0,
                    '{"status":"candidate-ready"}\n',
                    "\nsession_id: 20260817_120000_ab12cd\n",
                )

            with (
                mock.patch.object(
                    runner.shutil,
                    "which",
                    side_effect=lambda name: f"/mock/bin/{name}",
                ),
                mock.patch.object(runner, "run_hermes_process", side_effect=invoke),
                mock.patch.object(runner, "hermes_container_ids", return_value=set()),
                self.installed_profile_patch(Path(temporary)),
                mock.patch.object(
                    runner,
                    "cleanup_hermes_containers",
                    return_value={
                        "scoped_container_ids": [],
                        "removed_container_ids": [],
                        "remaining_container_ids": [],
                        "complete": True,
                    },
                ),
            ):
                candidate = provider.create_candidate(
                    attempt=1,
                    workspace=workspace,
                    deadline=time.monotonic() + 30,
                    request=self.fixture_context(artifact_dir),
                )

            self.assertEqual(candidate.record["source"], "hermes-real-model")
            self.assertEqual(candidate.record["changed_paths"], ["app/subject.py"])
            self.assertNotEqual(
                (workspace / "app" / "subject.py").read_text(encoding="utf-8"),
                original,
            )
            self.assertTrue(candidate.patch_path.is_file())
            self.assertTrue((artifact_dir / "attempt-1-hermes-request.json").is_file())
            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "CANDIDATE_RETURNED")
            self.assertTrue(execution["cleanup"]["complete"])
            self.assertTrue(execution["cleanup"]["profile_state"]["complete"])
            self.assertTrue(execution["cleanup"]["worker_directory"]["complete"])
            environment = observed["environment"]
            self.assertNotIn("OPENAI_API_KEY", environment)
            self.assertFalse(Path(environment["HERMES_HOME"]).exists())
            self.assertFalse(Path(environment["HOME"]).exists())
            command = observed["args"]
            self.assertEqual(command[command.index("-p") + 1], runner.HERMES_PROFILE)
            self.assertIn("--provider", command)
            self.assertIn("example-provider", command)
            self.assertIn("--model", command)
            self.assertIn("example-model", command)
            self.assertIn("--skills", command)
            self.assertIn("hermes-incident-remediation", command)
            self.assertNotIn("--resume", command)

    def test_real_provider_rejects_proposal_paths_that_differ_from_host_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run"
            artifact_dir.mkdir()
            workspace = runner.create_workspace(artifact_dir, "attempt-1")
            provider = runner.HermesCandidateProvider(
                provider="example-provider",
                model="example-model",
            )

            def invoke(args, *, cwd, environment, timeout):
                del cwd, timeout
                sandbox = Path(environment["HIW_HERMES_OUTPUT"]) / "workspace"
                subject = sandbox / "app" / "subject.py"
                subject.write_text(
                    subject.read_text(encoding="utf-8").replace(
                        "    return value.strip()\n",
                        '    return " ".join(value.split()).lower()\n',
                    ),
                    encoding="utf-8",
                )
                self.write_ready_proposal(
                    Path(environment["HIW_HERMES_OUTPUT"]),
                    changed_paths=["app/different.py"],
                )
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "candidate ready\n",
                    "\nsession_id: 20260817_120000_ab12cd\n",
                )

            with (
                mock.patch.object(
                    runner.shutil,
                    "which",
                    side_effect=lambda name: f"/mock/bin/{name}",
                ),
                mock.patch.object(runner, "run_hermes_process", side_effect=invoke),
                mock.patch.object(runner, "hermes_container_ids", return_value=set()),
                self.installed_profile_patch(Path(temporary)),
                mock.patch.object(
                    runner,
                    "cleanup_hermes_containers",
                    return_value={
                        "scoped_container_ids": [],
                        "removed_container_ids": [],
                        "remaining_container_ids": [],
                        "complete": True,
                    },
                ),
            ):
                with self.assertRaisesRegex(runner.PolicyDenied, "host diff"):
                    provider.create_candidate(
                        attempt=1,
                        workspace=workspace,
                        deadline=time.monotonic() + 30,
                        request=self.fixture_context(artifact_dir),
                    )

            self.assertFalse((artifact_dir / "attempt-1-hermes.patch").exists())
            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "FAILED")

    def test_real_provider_rejects_unqualified_runtime_before_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run"
            artifact_dir.mkdir()
            workspace = runner.create_workspace(artifact_dir, "attempt-1")
            provider = runner.HermesCandidateProvider(
                provider="example-provider",
                model="example-model",
            )
            unqualified = self.qualified_runtime_identity()
            unqualified.update(
                {
                    "revision": "0" * 40,
                    "qualified": False,
                    "problems": ["Hermes source checkout revision is not qualified"],
                }
            )

            with (
                mock.patch.object(
                    runner.shutil,
                    "which",
                    side_effect=lambda name: f"/mock/bin/{name}",
                ),
                mock.patch.object(runner, "run_hermes_process") as invoke,
                mock.patch.object(runner, "hermes_container_ids", return_value=set()),
                self.installed_profile_patch(
                    Path(temporary), runtime_identity=unqualified
                ),
                mock.patch.object(
                    runner,
                    "cleanup_hermes_containers",
                    return_value={
                        "scoped_container_ids": [],
                        "removed_container_ids": [],
                        "remaining_container_ids": [],
                        "complete": True,
                    },
                ),
            ):
                with self.assertRaisesRegex(
                    runner.PolicyDenied, "failed qualification immediately before execution"
                ):
                    provider.create_candidate(
                        attempt=1,
                        workspace=workspace,
                        deadline=time.monotonic() + 30,
                        request=self.fixture_context(artifact_dir),
                    )

            invoke.assert_not_called()
            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "FAILED")
            self.assertFalse(execution["runtime_identity"]["qualified"])
            self.assertTrue(execution["cleanup"]["complete"])

    def test_real_provider_rejects_missing_container_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run"
            artifact_dir.mkdir()
            workspace = runner.create_workspace(artifact_dir, "attempt-1")
            provider = runner.HermesCandidateProvider(
                provider="example-provider",
                model="example-model",
            )

            with (
                mock.patch.object(
                    runner.shutil,
                    "which",
                    side_effect=lambda name: f"/mock/bin/{name}",
                ),
                mock.patch.object(
                    runner,
                    "hermes_container_ids",
                    side_effect=runner.FlowError(
                        "Docker container enumeration failed"
                    ),
                ),
                mock.patch.object(
                    runner, "prepare_disposable_hermes_profile"
                ) as prepare,
                mock.patch.object(runner, "run_hermes_process") as invoke,
            ):
                with self.assertRaisesRegex(
                    runner.FlowError, "Docker container enumeration failed"
                ):
                    provider.create_candidate(
                        attempt=1,
                        workspace=workspace,
                        deadline=time.monotonic() + 30,
                        request=self.fixture_context(artifact_dir),
                    )

            prepare.assert_not_called()
            invoke.assert_not_called()
            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "FAILED")
            self.assertFalse(execution["cleanup"]["complete"])
            self.assertEqual(
                execution["cleanup"]["observation_errors"],
                ["initial Docker container baseline is unavailable"],
            )

    def test_disposable_profile_cleanup_failure_blocks_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run"
            artifact_dir.mkdir()
            workspace = runner.create_workspace(artifact_dir, "attempt-1")
            provider = runner.HermesCandidateProvider(
                provider="example-provider",
                model="example-model",
            )

            def invoke(args, *, cwd, environment, timeout):
                del cwd, timeout
                sandbox = Path(environment["HIW_HERMES_OUTPUT"]) / "workspace"
                subject = sandbox / "app" / "subject.py"
                subject.write_text(
                    subject.read_text(encoding="utf-8").replace(
                        "    return value.strip()\n",
                        '    return " ".join(value.split()).lower()\n',
                    ),
                    encoding="utf-8",
                )
                self.write_ready_proposal(Path(environment["HIW_HERMES_OUTPUT"]))
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "candidate ready\n",
                    "\nsession_id: 20260817_120000_ab12cd\n",
                )

            with (
                mock.patch.object(
                    runner.shutil,
                    "which",
                    side_effect=lambda name: f"/mock/bin/{name}",
                ),
                mock.patch.object(runner, "run_hermes_process", side_effect=invoke),
                mock.patch.object(runner, "hermes_container_ids", return_value=set()),
                self.installed_profile_patch(Path(temporary)),
                mock.patch.object(
                    runner,
                    "cleanup_hermes_containers",
                    return_value={
                        "scoped_container_ids": [],
                        "removed_container_ids": [],
                        "remaining_container_ids": [],
                        "complete": True,
                    },
                ),
                mock.patch.object(
                    runner,
                    "cleanup_disposable_hermes_profile",
                    return_value={
                        "removed": ["launcher_home"],
                        "remaining": ["hermes_root"],
                        "complete": False,
                    },
                ),
            ):
                with self.assertRaisesRegex(runner.FlowError, "attempt cleanup"):
                    provider.create_candidate(
                        attempt=1,
                        workspace=workspace,
                        deadline=time.monotonic() + 30,
                        request=self.fixture_context(artifact_dir),
                    )

            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "FAILED")
            self.assertFalse(execution["cleanup"]["complete"])

    def test_stdout_success_without_patch_is_rejected_without_applying(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run"
            artifact_dir.mkdir()
            workspace = runner.create_workspace(artifact_dir, "attempt-1")
            before = runner.tree_digest(workspace)
            provider = runner.HermesCandidateProvider(
                provider="example-provider",
                model="example-model",
            )
            def invoke(args, *, cwd, environment, timeout):
                del cwd, timeout
                self.write_ready_proposal(Path(environment["HIW_HERMES_OUTPUT"]))
                return subprocess.CompletedProcess(
                    args,
                    0,
                    '{"status":"success"}\n',
                    "\nsession_id: 20260817_120000_ab12cd\n",
                )
            with (
                mock.patch.object(
                    runner.shutil,
                    "which",
                    side_effect=lambda name: f"/mock/bin/{name}",
                ),
                mock.patch.object(runner, "run_hermes_process", side_effect=invoke),
                mock.patch.object(runner, "hermes_container_ids", return_value=set()),
                self.installed_profile_patch(Path(temporary)),
                mock.patch.object(
                    runner,
                    "cleanup_hermes_containers",
                    return_value={
                        "scoped_container_ids": [],
                        "removed_container_ids": [],
                        "remaining_container_ids": [],
                        "complete": True,
                    },
                ),
            ):
                with self.assertRaisesRegex(runner.PolicyDenied, "no patch"):
                    provider.create_candidate(
                        attempt=1,
                        workspace=workspace,
                        deadline=time.monotonic() + 30,
                        request=self.fixture_context(artifact_dir),
                    )

            self.assertEqual(runner.tree_digest(workspace), before)
            self.assertFalse((artifact_dir / "attempt-1-hermes.patch").exists())
            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "FAILED")

    def test_missing_proposal_blocks_a_host_derived_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run"
            artifact_dir.mkdir()
            workspace = runner.create_workspace(artifact_dir, "attempt-1")
            provider = runner.HermesCandidateProvider(
                provider="example-provider",
                model="example-model",
            )

            def invoke(args, *, cwd, environment, timeout):
                sandbox = Path(environment["HIW_HERMES_OUTPUT"]) / "workspace"
                subject = sandbox / "app" / "subject.py"
                original = subject.read_text(encoding="utf-8")
                subject.with_suffix(".py.bak").write_text(original, encoding="utf-8")
                subject.write_text(
                    original.replace(
                        "    return value.strip()\n",
                        '    return " ".join(value.split()).lower()\n',
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "model claimed success only on stdout\n",
                    "\nsession_id: 20260817_120000_ab12cd\n",
                )

            with (
                mock.patch.object(
                    runner.shutil,
                    "which",
                    side_effect=lambda name: f"/mock/bin/{name}",
                ),
                mock.patch.object(runner, "run_hermes_process", side_effect=invoke),
                mock.patch.object(runner, "hermes_container_ids", return_value=set()),
                self.installed_profile_patch(Path(temporary)),
                mock.patch.object(
                    runner,
                    "cleanup_hermes_containers",
                    return_value={
                        "scoped_container_ids": [],
                        "removed_container_ids": [],
                        "remaining_container_ids": [],
                        "complete": True,
                    },
                ),
            ):
                with self.assertRaisesRegex(
                    runner.PolicyDenied, "did not write proposal.json"
                ):
                    provider.create_candidate(
                        attempt=1,
                        workspace=workspace,
                        deadline=time.monotonic() + 30,
                        request=self.fixture_context(artifact_dir),
                    )

            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "FAILED")
            self.assertIn("proposal.json", execution["failure"])
            self.assertFalse((artifact_dir / "attempt-1-hermes.patch").exists())

    def test_cleanup_removes_only_new_container_with_exact_output_mount(self) -> None:
        completed = subprocess.CompletedProcess(
            ["docker", "rm", "-f", "target"], 0, "target\n", ""
        )
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "output"
            with (
                mock.patch.object(
                    runner,
                    "hermes_container_ids",
                    side_effect=[
                        {"preexisting", "target", "unrelated"},
                        {"preexisting", "unrelated"},
                    ],
                ),
                mock.patch.object(
                    runner,
                    "hermes_container_has_output_mount",
                    side_effect=lambda container_id, _: container_id == "target",
                ),
                mock.patch.object(runner.subprocess, "run", return_value=completed) as run_mock,
            ):
                result = runner.cleanup_hermes_containers(
                    {"preexisting"}, output_dir, grace_seconds=0
                )

        self.assertTrue(result["complete"])
        self.assertEqual(result["removed_container_ids"], ["target"])
        self.assertEqual(result["observation_errors"], [])
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.args[0], ["docker", "rm", "-f", "target"])

    def test_cleanup_fails_closed_when_container_listing_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                runner,
                "hermes_container_ids",
                side_effect=runner.FlowError("Docker container enumeration failed"),
            ):
                result = runner.cleanup_hermes_containers(
                    set(), Path(temporary), grace_seconds=0
                )

        self.assertFalse(result["complete"])
        self.assertEqual(
            result["observation_errors"],
            ["Docker container enumeration failed"],
        )

    def test_cleanup_fails_closed_when_container_inspection_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(
                    runner, "hermes_container_ids", return_value={"candidate"}
                ),
                mock.patch.object(
                    runner,
                    "hermes_container_has_output_mount",
                    side_effect=runner.FlowError(
                        "Docker container inspection failed"
                    ),
                ),
            ):
                result = runner.cleanup_hermes_containers(
                    set(), Path(temporary), grace_seconds=0
                )

        self.assertFalse(result["complete"])
        self.assertEqual(
            result["observation_errors"],
            ["Docker container inspection failed"],
        )

    def test_timeout_terminates_the_fresh_hermes_process_group(self) -> None:
        process = mock.Mock(pid=4321, returncode=-15)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["hermes"], 0.1),
            ("partial stdout", "partial stderr"),
        ]
        with (
            mock.patch.object(runner.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(runner.os, "killpg") as killpg,
        ):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                runner.run_hermes_process(
                    ["hermes"],
                    cwd=runner.PACKAGE_ROOT,
                    environment={"PATH": ""},
                    timeout=0.1,
                )

        self.assertEqual(raised.exception.output, "partial stdout")
        self.assertEqual(raised.exception.stderr, "partial stderr")
        killpg.assert_called_once_with(4321, runner.signal.SIGTERM)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_controller_feedback_is_carried_to_second_attempt(self) -> None:
        class RecordingFixtureProvider(runner.FixtureCandidateProvider):
            def __init__(self) -> None:
                super().__init__(
                    [
                        runner.FIXTURES / "patches" / "incomplete.patch",
                        runner.FIXTURES / "patches" / "correct.patch",
                    ],
                    repeat_last_patch=False,
                )
                self.requests: list[dict] = []

            def create_candidate(self, **kwargs):
                self.requests.append(kwargs["request"])
                return super().create_candidate(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            provider = RecordingFixtureProvider()
            def independent_verify(_run_dir, _patch, digest, _deadline, **_kwargs):
                return {
                    "accepted": True,
                    "candidate_digest": digest,
                    "tested_digest": digest,
                    "test": {
                        "passed": True,
                        "checks": [
                            {
                                "exit_code": 0,
                                "process_exit_code": 0,
                                "passed": True,
                                "trusted_verifier_completed": True,
                                "output": runner.TRUSTED_VERIFIER_COMPLETION + "\n",
                            }
                        ],
                    },
                }

            with (
                mock.patch.object(
                    runner,
                    "candidate_test_environment_problems",
                    return_value=("test|arm64", []),
                ),
                mock.patch.object(
                    runner,
                    "independent_verify",
                    side_effect=independent_verify,
                ),
            ):
                run_dir, control = runner.run_flow(
                    "retry-success",
                    artifact_root=Path(temporary),
                    candidate_provider=provider,
                )

            self.assertEqual(control["outcome"], "SUCCEEDED")
            self.assertEqual(len(provider.requests), 2)
            self.assertEqual(provider.requests[0]["packet"]["feedback"], [])
            second_feedback = provider.requests[1]["packet"]["feedback"]
            self.assertEqual(second_feedback[0]["attempt"], 1)
            self.assertEqual(second_feedback[0]["stage"], "controller_test")
            self.assertFalse(second_feedback[0]["passed"])
            first_candidate = runner.read_json(run_dir / "attempt-1-candidate.json")
            second_candidate = runner.read_json(run_dir / "attempt-2-candidate.json")
            first_result = runner.read_json(run_dir / "attempt-1-result.json")
            second_result = runner.read_json(run_dir / "attempt-2-result.json")
            feedback = runner.read_json(run_dir / "attempt-1-feedback.json")
            second_request = runner.read_json(run_dir / "attempt-2-request.json")
            self.assertNotEqual(
                first_candidate["candidate_digest"],
                second_candidate["candidate_digest"],
            )
            self.assertEqual(
                first_result["baseline_digest"],
                second_result["baseline_digest"],
            )
            self.assertEqual(
                feedback["candidate_digest"],
                first_candidate["candidate_digest"],
            )
            self.assertEqual(second_request["feedback"], [feedback])
            self.assertEqual(runner.verify_run(run_dir), [])

            control_path = run_dir / "control.json"
            original_control = runner.read_json(control_path)
            changed_control = dict(original_control)
            changed_control["scenario"] = "exhausted"
            runner.write_json(control_path, changed_control)
            runner.write_evidence_manifest(run_dir)
            scenario_issues = runner.verify_run(run_dir)
            self.assertIn(
                "control scenario does not match retained incident evidence",
                scenario_issues,
            )
            runner.write_json(control_path, original_control)

            first_result_path = run_dir / "attempt-1-result.json"
            first_result = runner.read_json(first_result_path)
            first_result["test"]["command"] = "forged command"
            runner.write_json(first_result_path, first_result)
            feedback["command"] = "forged command"
            feedback["unexpected"] = "x" * 10_000
            runner.write_json(run_dir / "attempt-1-feedback.json", feedback)
            second_request["feedback"] = [feedback]
            runner.write_json(run_dir / "attempt-2-request.json", second_request)
            runner.write_evidence_manifest(run_dir)
            tamper_issues = runner.verify_run(run_dir)
            self.assertIn(
                "retry feedback is not the exact bounded attempt-one result",
                tamper_issues,
            )
            self.assertIn(
                "attempt-1 retained test differs from independent replay",
                tamper_issues,
            )
            self.assertIn(
                "attempt-two request does not carry exact bounded attempt-one feedback",
                tamper_issues,
            )

    def test_retry_rejects_a_fresh_workspace_that_drifted_from_baseline(self) -> None:
        class CountingFixtureProvider(runner.FixtureCandidateProvider):
            def __init__(self) -> None:
                super().__init__(
                    [
                        runner.FIXTURES / "patches" / "incomplete.patch",
                        runner.FIXTURES / "patches" / "correct.patch",
                    ],
                    repeat_last_patch=False,
                )
                self.calls = 0

            def create_candidate(self, **kwargs):
                self.calls += 1
                return super().create_candidate(**kwargs)

        failed_test = {
            "command": "repository tests && controller verifier",
            "exit_code": 1,
            "passed": False,
            "output": "controller-owned check failed",
            "checks": [
                {
                    "command": "repository tests",
                    "exit_code": 0,
                    "passed": True,
                    "output": "ok",
                },
                {
                    "command": "controller verifier",
                    "exit_code": 1,
                    "passed": False,
                    "output": "held-out failure",
                },
            ],
        }
        original_create_workspace = runner.create_workspace
        workspace_calls = 0

        def drifting_workspace(*args, **kwargs):
            nonlocal workspace_calls
            workspace_calls += 1
            workspace = original_create_workspace(*args, **kwargs)
            if workspace_calls == 2:
                subject = workspace / "app" / "subject.py"
                subject.write_text(
                    subject.read_text(encoding="utf-8") + "\n# unexpected drift\n",
                    encoding="utf-8",
                )
            return workspace

        with tempfile.TemporaryDirectory() as temporary:
            provider = CountingFixtureProvider()
            with (
                mock.patch.object(
                    runner,
                    "candidate_test_environment_problems",
                    return_value=("test|arm64", []),
                ),
                mock.patch.object(runner, "scenario_test", return_value=failed_test),
                mock.patch.object(
                    runner,
                    "create_workspace",
                    side_effect=drifting_workspace,
                ),
            ):
                with self.assertRaisesRegex(
                    runner.FlowError,
                    "fresh attempt workspace does not match the original baseline",
                ):
                    runner.run_flow(
                        "retry-success",
                        artifact_root=Path(temporary),
                        candidate_provider=provider,
                    )
            run_dir = next(Path(temporary).iterdir())
            control = runner.read_json(run_dir / "control.json")
            self.assertEqual(control["outcome"], "REJECTED")
            self.assertEqual(provider.calls, 1)
            self.assertFalse((run_dir / "mock-github.json").exists())

    def test_retry_verifier_recomputes_the_delivered_fixture_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=("test|arm64", []),
            ):
                run_dir, control = runner.run_flow(
                    "retry-success",
                    artifact_root=Path(temporary),
                )
            self.assertEqual(control["outcome"], "SUCCEEDED")

            forged_digest = "f" * 64
            for name in (
                "control.json",
                "attempt-2-candidate.json",
                "attempt-2-result.json",
                "verification.json",
                "mock-github.json",
            ):
                path = run_dir / name
                record = runner.read_json(path)
                if "candidate_digest" in record:
                    record["candidate_digest"] = forged_digest
                if "tested_digest" in record:
                    record["tested_digest"] = forged_digest
                runner.write_json(path, record)
            runner.write_evidence_manifest(run_dir)

            issues = runner.verify_run(run_dir)

        self.assertIn("retry attempt 2 candidate digest is not reproducible", issues)

    def test_retry_contract_rejects_an_early_success(self) -> None:
        provider = runner.FixtureCandidateProvider(
            [runner.FIXTURES / "patches" / "correct.patch"],
            repeat_last_patch=False,
        )
        successful_test = {
            "command": "repository tests && controller verifier",
            "exit_code": 0,
            "passed": True,
            "output": runner.TRUSTED_VERIFIER_COMPLETION + "\n",
            "checks": [
                {"command": "repository tests", "exit_code": 0, "passed": True},
                {
                    "command": "controller verifier",
                    "exit_code": 0,
                    "process_exit_code": 0,
                    "passed": True,
                    "trusted_verifier_completed": True,
                    "output": runner.TRUSTED_VERIFIER_COMPLETION + "\n",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(
                    runner,
                    "candidate_test_environment_problems",
                    return_value=("test|arm64", []),
                ),
                mock.patch.object(
                    runner,
                    "scenario_test",
                    return_value=successful_test,
                ),
                mock.patch.object(runner, "independent_verify") as verify,
            ):
                with self.assertRaisesRegex(runner.FlowError, "got REJECTED"):
                    runner.run_flow(
                        "retry-success",
                        artifact_root=Path(temporary),
                        candidate_provider=provider,
                    )
            run_dir = next(Path(temporary).iterdir())
            control = runner.read_json(run_dir / "control.json")

        verify.assert_not_called()
        self.assertEqual(control["outcome"], "REJECTED")
        self.assertIn("held-out check", control["failure_reason"])
        self.assertFalse((run_dir / "mock-github.json").exists())

    def test_verified_real_model_artifact_chain_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))

            self.assertEqual(runner.verify_run(run_dir), [])

    def test_verifier_rechecks_retained_request_path_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            request_path = run_dir / "attempt-1-request.json"
            request = runner.read_json(request_path)
            request["incident"]["allowed_paths"] = ["app/other.py"]
            request["run_id"] = "wrong-run"
            request["attempt"] = 2
            runner.write_json(request_path, request)

            mounted_path = run_dir / "attempt-1-hermes-request.json"
            mounted = runner.read_json(mounted_path)
            mounted["run_id"] = "wrong-mounted-run"
            mounted["attempt"] = 2
            runner.write_json(mounted_path, mounted)

            issues = runner.verify_run(run_dir)

        self.assertIn(
            "retained request path policy differs from trusted scenario on attempt 1",
            issues,
        )
        self.assertIn("retained request run ID differs on attempt 1", issues)
        self.assertIn("retained request attempt differs on attempt 1", issues)
        self.assertIn("mounted request run ID differs on attempt 1", issues)
        self.assertIn("mounted request attempt differs on attempt 1", issues)

    def test_source_downgrade_cannot_bypass_hermes_patch_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            control_path = run_dir / "control.json"
            control = runner.read_json(control_path)
            control["candidate_source"] = "fixture-simulated-hermes"
            runner.write_json(control_path, control)
            candidate_path = run_dir / "attempt-1-candidate.json"
            candidate = runner.read_json(candidate_path)
            candidate["source"] = "fixture-simulated-hermes"
            runner.write_json(candidate_path, candidate)
            patch_path = run_dir / "attempt-1-hermes.patch"
            patch_path.write_bytes(patch_path.read_bytes() + b"\n# tampered\n")
            runner.write_evidence_manifest(run_dir)

            issues = runner.verify_run(run_dir)

        self.assertIn(
            "Hermes artifacts disagree with the retained candidate source",
            issues,
        )
        self.assertIn("Hermes candidate source is invalid on attempt 1", issues)
        self.assertTrue(
            "Hermes patch cannot be reapplied on attempt 1" in issues
            or "Hermes patch SHA differs on attempt 1" in issues
        )

    def test_verifier_requires_empty_remaining_hermes_containers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            execution_path = run_dir / "attempt-1-hermes-execution.json"
            execution = runner.read_json(execution_path)
            execution["cleanup"]["remaining_container_ids"] = ["a" * 12]
            execution["cleanup"]["complete"] = True
            runner.write_json(execution_path, execution)
            runner.write_evidence_manifest(run_dir)

            issues = runner.verify_run(run_dir)

        self.assertIn("Hermes cleanup did not complete on attempt 1", issues)
        self.assertIn("Hermes execution cleanup did not complete", issues)

    def test_verifier_recomputes_usage_bucket_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            usage_path = run_dir / "attempt-1-hermes-usage.json"
            usage = runner.read_json(usage_path)
            usage["total_tokens"] += usage["reasoning_tokens"]
            runner.write_json(usage_path, usage)
            execution_path = run_dir / "attempt-1-hermes-execution.json"
            execution = runner.read_json(execution_path)
            execution["usage_sha256"] = runner.hashlib.sha256(
                usage_path.read_bytes()
            ).hexdigest()
            runner.write_json(execution_path, execution)
            runner.write_json(
                run_dir / "hermes-usage-summary.json",
                runner.aggregate_hermes_usage(run_dir),
            )
            runner.write_evidence_manifest(run_dir)

            issues = runner.verify_run(run_dir)

        self.assertIn(
            "Hermes attempt 1 usage total does not match exact token buckets",
            issues,
        )
        self.assertIn(
            "Hermes attempt 1 usage buckets do not equal the route aggregate",
            issues,
        )

        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            usage_path = run_dir / "attempt-1-hermes-usage.json"
            usage = runner.read_json(usage_path)
            usage["routes"] = []
            runner.write_json(usage_path, usage)
            execution_path = run_dir / "attempt-1-hermes-execution.json"
            execution = runner.read_json(execution_path)
            execution["usage_sha256"] = runner.hashlib.sha256(
                usage_path.read_bytes()
            ).hexdigest()
            runner.write_json(execution_path, execution)
            runner.write_json(
                run_dir / "hermes-usage-summary.json",
                runner.aggregate_hermes_usage(run_dir),
            )
            runner.write_evidence_manifest(run_dir)
            empty_route_issues = runner.verify_run(run_dir)

        self.assertIn("Hermes attempt 1 usage routes are invalid", empty_route_issues)

    def test_verifier_reapplies_patch_before_trusting_coordinated_digests(self) -> None:
        forged_digest = "f" * 64
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            control_path = run_dir / "control.json"
            control = runner.read_json(control_path)
            control["candidate_digest"] = forged_digest
            runner.write_json(control_path, control)
            for name in (
                "attempt-1-candidate.json",
                "attempt-1-hermes-execution.json",
                "attempt-1-result.json",
                "verification.json",
                "mock-github.json",
            ):
                path = run_dir / name
                artifact = runner.read_json(path)
                if "candidate_digest" in artifact:
                    artifact["candidate_digest"] = forged_digest
                if "tested_digest" in artifact:
                    artifact["tested_digest"] = forged_digest
                runner.write_json(path, artifact)
            runner.write_evidence_manifest(run_dir)

            issues = runner.verify_run(run_dir)

        self.assertIn(
            "Hermes candidate digest cannot be reproduced on attempt 1",
            issues,
        )

    def test_real_model_verifier_detects_linkage_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            candidate_path = run_dir / "attempt-1-candidate.json"
            candidate = runner.read_json(candidate_path)
            candidate["changed_paths"] = ["app/other.py"]
            runner.write_json(candidate_path, candidate)

            execution_path = run_dir / "attempt-1-hermes-execution.json"
            execution = runner.read_json(execution_path)
            execution.update(
                {
                    "outcome": "FAILED",
                    "session_id": "bad",
                    "profile": "bad profile",
                    "provider": "",
                    "model": "bad model",
                    "disposable_profile": False,
                    "credential_files_bridged": ["../../secret"],
                    "runtime_identity": {"qualified": False},
                    "patch_sha256": "0" * 64,
                    "candidate_digest": "1" * 64,
                    "cleanup": {"complete": False},
                }
            )
            runner.write_json(execution_path, execution)

            result_path = run_dir / "attempt-1-result.json"
            result = runner.read_json(result_path)
            result["candidate_digest"] = "2" * 64
            result["test"]["passed"] = False
            runner.write_json(result_path, result)

            verification_path = run_dir / "verification.json"
            verification = runner.read_json(verification_path)
            verification["tested_digest"] = "3" * 64
            verification["accepted"] = False
            runner.write_json(verification_path, verification)

            issues = runner.verify_run(run_dir)

        for expected in (
            "Hermes patch paths do not match candidate contract",
            "Hermes execution did not return the accepted candidate",
            "Hermes execution session ID is invalid",
            "Hermes execution profile is invalid",
            "Hermes execution provider is invalid",
            "Hermes execution model is invalid",
            "Hermes execution did not use a disposable profile",
            "Hermes execution runtime identity is not qualified",
            "Hermes execution credential bridge is invalid",
            "Hermes execution cleanup did not complete",
            "Hermes execution patch SHA does not match candidate",
            "Hermes execution digest does not match candidate",
            "Hermes result digest does not match candidate",
            "Hermes accepted attempt did not pass controller tests",
            "Hermes independent verification did not accept candidate",
            "Hermes verification tested digest does not match candidate",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, issues)

    def test_real_model_verifier_detects_patch_byte_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))
            patch_path = run_dir / "attempt-1-hermes.patch"
            patch_path.write_bytes(patch_path.read_bytes() + b"\n# tampered\n")

            issues = runner.verify_run(run_dir)

        self.assertIn("Hermes patch SHA does not match candidate contract", issues)

    def test_cli_exposes_real_candidate_provider_without_changing_default(self) -> None:
        default = runner.parser().parse_args(["run"])
        selected = runner.parser().parse_args(
            [
                "run",
                "--candidate-provider",
                "hermes",
                "--hermes-provider",
                "provider-a",
                "--hermes-model",
                "example-model",
                "--hermes-profile",
                "example-profile",
            ]
        )

        self.assertEqual(default.candidate_provider, "fixture")
        self.assertEqual(default.hermes_profile, runner.HERMES_PROFILE)
        self.assertEqual(selected.candidate_provider, "hermes")
        self.assertEqual(selected.hermes_provider, "provider-a")
        self.assertEqual(selected.hermes_model, "example-model")
        self.assertEqual(selected.hermes_profile, "example-profile")

    def test_cli_forwards_custom_hermes_profile_to_provider(self) -> None:
        provider = mock.Mock(source="hermes-real-model")
        control = {"outcome": "SUCCEEDED", "attempts": 1}
        stdout = io.StringIO()
        with (
            mock.patch.object(
                runner.sys,
                "argv",
                [
                    "runner.py",
                    "run",
                    "--candidate-provider",
                    "hermes",
                    "--hermes-provider",
                    "example-provider",
                    "--hermes-model",
                    "example-model",
                    "--hermes-profile",
                    "example-profile",
                ],
            ),
            mock.patch.object(
                runner,
                "HermesCandidateProvider",
                return_value=provider,
            ) as constructor,
            mock.patch.object(
                runner,
                "run_flow",
                return_value=(Path("/tmp/hermes-incident-workflow-test-run"), control),
            ) as run_flow,
            contextlib.redirect_stdout(stdout),
        ):
            exit_code = runner.main()

        self.assertEqual(exit_code, 0)
        constructor.assert_called_once_with(
            provider="example-provider",
            model="example-model",
            profile="example-profile",
            max_turns=20,
        )
        self.assertIs(run_flow.call_args.kwargs["candidate_provider"], provider)

    def test_runtime_identity_uses_checkout_and_lock_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "hermes-agent"
            install_root.mkdir()
            pyproject = install_root / "pyproject.toml"
            lock = install_root / "uv.lock"
            pyproject.write_text("qualified project\n", encoding="utf-8")
            lock.write_text("qualified lock\n", encoding="utf-8")
            pyproject_digest = runner.hashlib.sha256(pyproject.read_bytes()).hexdigest()
            lock_digest = runner.hashlib.sha256(lock.read_bytes()).hexdigest()

            def command(args, **_):
                if args == ["hermes", "--version"]:
                    return subprocess.CompletedProcess(
                        args,
                        0,
                        (
                            "Hermes Agent v0.20.6 (test) · upstream moving123\n"
                            f"Install directory: {install_root}\n"
                        ),
                        "",
                    )
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(
                        args, 0, runner.HERMES_QUALIFIED_REVISION + "\n", ""
                    )
                if "status" in args:
                    return subprocess.CompletedProcess(args, 0, "", "")
                raise AssertionError(f"unexpected command: {args}")

            with (
                mock.patch.object(runner, "command", side_effect=command),
                mock.patch.object(runner, "HERMES_PYPROJECT_SHA256", pyproject_digest),
                mock.patch.object(runner, "HERMES_LOCK_SHA256", lock_digest),
            ):
                identity = runner.inspect_hermes_runtime()

        self.assertTrue(identity["qualified"])
        self.assertEqual(identity["revision"], runner.HERMES_QUALIFIED_REVISION)
        self.assertTrue(identity["checkout_clean"])

    def test_runtime_identity_rejects_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "hermes-agent"
            install_root.mkdir()
            (install_root / "pyproject.toml").write_text("changed\n", encoding="utf-8")
            (install_root / "uv.lock").write_text("changed\n", encoding="utf-8")

            def command(args, **_):
                if args == ["hermes", "--version"]:
                    return subprocess.CompletedProcess(
                        args,
                        0,
                        f"Hermes Agent v0.20.6\nInstall directory: {install_root}\n",
                        "",
                    )
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(
                        args, 0, runner.HERMES_QUALIFIED_REVISION + "\n", ""
                    )
                if "status" in args:
                    return subprocess.CompletedProcess(args, 0, " M pyproject.toml\n", "")
                raise AssertionError(f"unexpected command: {args}")

            with mock.patch.object(runner, "command", side_effect=command):
                identity = runner.inspect_hermes_runtime()

        self.assertFalse(identity["qualified"])
        self.assertIn(
            "Hermes source checkout has tracked or untracked changes",
            identity["problems"],
        )

    def test_runtime_identity_rejects_untracked_source_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "hermes-agent"
            install_root.mkdir()
            pyproject = install_root / "pyproject.toml"
            lock = install_root / "uv.lock"
            pyproject.write_text("qualified project\n", encoding="utf-8")
            lock.write_text("qualified lock\n", encoding="utf-8")

            def command(args, **_):
                if args == ["hermes", "--version"]:
                    return subprocess.CompletedProcess(
                        args,
                        0,
                        f"Hermes Agent v0.20.6\nInstall directory: {install_root}\n",
                        "",
                    )
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(
                        args, 0, runner.HERMES_QUALIFIED_REVISION + "\n", ""
                    )
                if "status" in args:
                    return subprocess.CompletedProcess(
                        args, 0, "?? sitecustomize.py\n", ""
                    )
                raise AssertionError(f"unexpected command: {args}")

            with (
                mock.patch.object(runner, "command", side_effect=command),
                mock.patch.object(
                    runner,
                    "HERMES_PYPROJECT_SHA256",
                    runner.hashlib.sha256(pyproject.read_bytes()).hexdigest(),
                ),
                mock.patch.object(
                    runner,
                    "HERMES_LOCK_SHA256",
                    runner.hashlib.sha256(lock.read_bytes()).hexdigest(),
                ),
            ):
                identity = runner.inspect_hermes_runtime()

        self.assertFalse(identity["qualified"])
        self.assertFalse(identity["checkout_clean"])
        self.assertIn(
            "Hermes source checkout has tracked or untracked changes",
            identity["problems"],
        )

    def test_preflight_checks_the_selected_hermes_profile(self) -> None:
        def command(args, **_):
            if args == ["hermes", "profile", "info", "example-profile"]:
                return subprocess.CompletedProcess(args, 0, "profile available\n", "")
            raise AssertionError(f"unexpected command: {args}")

        with (
            mock.patch.object(runner, "sensitive_environment_names", return_value=[]),
            mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=("test|arm64", []),
            ),
            mock.patch.object(runner.shutil, "which", return_value="/usr/bin/example"),
            mock.patch.object(
                runner,
                "inspect_hermes_runtime",
                return_value={
                    "version_line": "Hermes Agent v0.20.6 (test)",
                    "qualified": True,
                    "problems": [],
                },
            ),
            mock.patch.object(runner, "command", side_effect=command),
        ):
            result = runner.preflight(False, True, "example-profile")

        self.assertTrue(result["ok"])
        self.assertEqual(
            result["hermes_profile"],
            {"name": "example-profile", "status": "available"},
        )

    def test_preflight_with_docker_requires_an_explicit_service_contract(self) -> None:
        def executable(name: str) -> str | None:
            return None if name == "hermes" else f"/usr/bin/{name}"

        with (
            mock.patch.object(runner, "sensitive_environment_names", return_value=[]),
            mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=("test|arm64", []),
            ),
            mock.patch.object(runner.shutil, "which", side_effect=executable),
            mock.patch.object(
                runner,
                "service_stack_environment_problems",
                return_value=[],
            ),
        ):
            missing_scenario = runner.preflight(True)
            missing_contract = runner.preflight(
                True,
                scenario_name="retry-success",
            )
            valid_contract = runner.preflight(
                True,
                scenario_name="event-indexing-collision",
            )

        self.assertIn(
            "--with-docker requires --scenario with a service-stack contract",
            missing_scenario["problems"],
        )
        self.assertIn(
            "--with-docker requires a scenario with an explicit service-stack contract",
            missing_contract["problems"],
        )
        self.assertTrue(valid_contract["ok"])

    def test_service_stack_preflight_checks_every_pinned_runtime_image(self) -> None:
        scenario = runner.read_json(runner.FIXTURES / "scenarios.json")[
            "event-indexing-collision"
        ]
        repository = runner.scenario_repository(scenario)
        missing_image = (
            "postgres:14.24-alpine@sha256:"
            "727876d274666da0b92a445390ba093c84b8e9f8343e1c53cd4e9a7ab2d85310"
        )

        def command(args, **_kwargs):
            if args[-3:] == ["config", "--format", "json"]:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    json.dumps(
                        {
                            "services": {
                                "database": {"image": missing_image},
                                "verifier": {
                                    "build": {
                                        "context": str(
                                            runner.PACKAGE_ROOT / "docker" / "incident-poc"
                                        ),
                                        "dockerfile": "Dockerfile",
                                    }
                                },
                            }
                        }
                    ),
                    "",
                )
            if args[:3] == ["docker", "image", "inspect"]:
                return subprocess.CompletedProcess(
                    args,
                    1 if args[-1] == missing_image else 0,
                    "",
                    "",
                )
            raise AssertionError(f"unexpected command: {args}")

        with mock.patch.object(runner, "command", side_effect=command):
            issues = runner.service_stack_environment_problems(
                scenario,
                repository,
                "hiw-preflight-test",
            )

        self.assertEqual(
            issues,
            [
                f"pinned service-stack image is unavailable: {missing_image}; "
                "run ./scripts/bootstrap-pinned-images.sh all"
            ],
        )

        missing_service = dict(scenario)
        missing_service["compose_service"] = "missing-verifier"
        with mock.patch.object(runner, "command", side_effect=command):
            issues = runner.service_stack_environment_problems(
                missing_service,
                repository,
                "hiw-preflight-test",
            )
        self.assertEqual(
            issues,
            ["declared Compose verification service is missing: missing-verifier"],
        )

    def test_run_fails_before_candidate_when_pinned_image_is_unavailable(self) -> None:
        provider = mock.Mock(source="fixture")
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=(
                    "test|arm64",
                    ["pinned candidate test image is unavailable"],
                ),
            ):
                with self.assertRaisesRegex(runner.FlowError, "got FAILED"):
                    runner.run_flow(
                        "retry-success",
                        artifact_root=Path(temporary),
                        candidate_provider=provider,
                    )
            run_dir = next(Path(temporary).iterdir())
            control = runner.read_json(run_dir / "control.json")

        provider.has_candidate.assert_not_called()
        provider.create_candidate.assert_not_called()
        self.assertEqual(control["attempts"], 0)
        self.assertIn("pinned candidate test image", control["failure_reason"])

    def test_run_checks_service_images_before_evidence_or_candidate(self) -> None:
        provider = mock.Mock(source="fixture")
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(
                    runner,
                    "candidate_test_environment_problems",
                    return_value=("test|arm64", []),
                ),
                mock.patch.object(
                    runner,
                    "service_stack_environment_problems",
                    return_value=["pinned service-stack image is unavailable"],
                ),
            ):
                with self.assertRaisesRegex(runner.FlowError, "got FAILED"):
                    runner.run_flow(
                        "event-indexing-collision",
                        with_docker=True,
                        artifact_root=Path(temporary),
                        candidate_provider=provider,
                    )
            run_dir = next(Path(temporary).iterdir())
            control = runner.read_json(run_dir / "control.json")

        provider.has_candidate.assert_not_called()
        provider.create_candidate.assert_not_called()
        self.assertEqual(control["attempts"], 0)
        self.assertFalse((run_dir / "evidence.json").exists())
        self.assertIn("service-stack image", control["failure_reason"])

    def test_failure_reason_is_redacted_before_evidence_finalization(self) -> None:
        provider = mock.Mock(source="fixture")
        provider.has_candidate.return_value = True
        provider.create_candidate.side_effect = runner.FlowError(
            f"failed below {runner.PACKAGE_ROOT}/private and {Path.home()}/other"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=("test|arm64", []),
            ):
                run_dir, control = runner.run_flow(
                    "exhausted",
                    artifact_root=Path(temporary),
                    candidate_provider=provider,
                )

            retained = json.dumps(control)
            self.assertNotIn(str(runner.PACKAGE_ROOT), retained)
            self.assertNotIn(str(Path.home()), retained)
            self.assertIn("<package>/private", retained)
            self.assertEqual(runner.verify_evidence_manifest(run_dir), [])

    def test_preflight_reports_a_missing_hermes_profile(self) -> None:
        def command(args, **_):
            return subprocess.CompletedProcess(
                args,
                1,
                "",
                "",
            )

        with (
            mock.patch.object(runner, "sensitive_environment_names", return_value=[]),
            mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=("test|arm64", []),
            ),
            mock.patch.object(runner.shutil, "which", return_value="/usr/bin/example"),
            mock.patch.object(
                runner,
                "inspect_hermes_runtime",
                return_value={
                    "version_line": "Hermes Agent v0.20.6 (test)",
                    "qualified": True,
                    "problems": [],
                },
            ),
            mock.patch.object(runner, "command", side_effect=command),
        ):
            result = runner.preflight(False, True, "missing-profile")

        self.assertFalse(result["ok"])
        self.assertEqual(result["hermes_profile"]["status"], "missing")
        self.assertTrue(any("install-hermes-profile.sh" in item for item in result["problems"]))

    def test_preflight_rejects_unqualified_hermes_revision(self) -> None:
        def command(args, **_):
            if args == ["hermes", "profile", "info", "example-profile"]:
                return subprocess.CompletedProcess(args, 0, "profile available\n", "")
            raise AssertionError(f"unexpected command: {args}")

        with (
            mock.patch.object(runner, "sensitive_environment_names", return_value=[]),
            mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=("test|arm64", []),
            ),
            mock.patch.object(runner.shutil, "which", return_value="/usr/bin/example"),
            mock.patch.object(
                runner,
                "inspect_hermes_runtime",
                return_value={
                    "version_line": "Hermes Agent v0.20.6 (test)",
                    "qualified": False,
                    "problems": [
                        "Hermes source checkout is not qualified revision "
                        + runner.HERMES_QUALIFIED_REVISION
                    ],
                },
            ),
            mock.patch.object(runner, "command", side_effect=command),
        ):
            result = runner.preflight(False, True, "example-profile")

        self.assertFalse(result["ok"])
        self.assertTrue(
            any(runner.HERMES_QUALIFIED_REVISION in item for item in result["problems"])
        )

    def test_preflight_rejects_failed_hermes_version_command(self) -> None:
        def command(args, **_):
            if args == ["hermes", "profile", "info", "example-profile"]:
                return subprocess.CompletedProcess(args, 0, "profile available\n", "")
            raise AssertionError(f"unexpected command: {args}")

        with (
            mock.patch.object(runner, "sensitive_environment_names", return_value=[]),
            mock.patch.object(
                runner,
                "candidate_test_environment_problems",
                return_value=("test|arm64", []),
            ),
            mock.patch.object(runner.shutil, "which", return_value="/usr/bin/example"),
            mock.patch.object(
                runner,
                "inspect_hermes_runtime",
                return_value={
                    "version_line": "unknown",
                    "qualified": False,
                    "problems": ["Hermes version command failed"],
                },
            ),
            mock.patch.object(runner, "command", side_effect=command),
        ):
            result = runner.preflight(False, True, "example-profile")

        self.assertFalse(result["ok"])
        self.assertIn("Hermes version command failed", result["problems"])


if __name__ == "__main__":
    unittest.main()
