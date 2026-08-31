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

    def verified_hermes_run(self, artifact_root: Path) -> Path:
        patch_payload = (runner.FIXTURES / "patches" / "correct.patch").read_bytes()
        patch_sha256 = runner.hashlib.sha256(patch_payload).hexdigest()
        changed_paths = runner.validate_hermes_patch_bytes(patch_payload)[1]
        digest_root = artifact_root / "digest-work"
        digest_workspace = runner.create_workspace(digest_root, "candidate")
        applied = runner.apply_candidate(
            digest_workspace,
            runner.FIXTURES / "patches" / "correct.patch",
            time.monotonic() + 10,
        )
        candidate_digest = applied["candidate_digest"]
        runner.shutil.rmtree(digest_root)

        run_dir = artifact_root / "hermes-run"
        run_dir.mkdir()
        patch_name = "attempt-1-hermes.patch"
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
                "attempts": 1,
                "outcome": "SUCCEEDED",
                "candidate_source": "hermes-real-model",
                "candidate_digest": candidate_digest,
            },
        )
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
                "disposable_profile": True,
                "credential_files_bridged": [],
                "runtime_identity": self.qualified_runtime_identity(),
                "outcome": "CANDIDATE_RETURNED",
                "session_id": "20260817_120000_ab12cd",
                "patch_sha256": patch_sha256,
                "candidate_digest": candidate_digest,
                "cleanup": {
                    "complete": True,
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
        runner.write_json(run_dir / "closeout.json", {"cleanup_complete": True})
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
        self.assertNotIn("allowed_paths", packet["incident"])
        self.assertNotIn("required_test_command", packet["incident"])
        self.assertEqual(
            packet["policy"]["allowed_paths"],
            list(runner.ALLOWED_PATCH_PREFIXES),
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
            self.assertTrue(all((profile / item).is_dir() for item in runner.HERMES_CACHE_DIRECTORIES))

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
            completed = subprocess.CompletedProcess(
                ["hermes"],
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
                mock.patch.object(runner, "run_hermes_process", return_value=completed),
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

    def test_missing_proposal_cannot_block_a_host_verified_patch(self) -> None:
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
                candidate = provider.create_candidate(
                    attempt=1,
                    workspace=workspace,
                    deadline=time.monotonic() + 30,
                    request=self.fixture_context(artifact_dir),
                )

            self.assertEqual(candidate.record["changed_paths"], ["app/subject.py"])
            execution = runner.read_json(
                artifact_dir / "attempt-1-hermes-execution.json"
            )
            self.assertEqual(execution["outcome"], "CANDIDATE_RETURNED")
            self.assertIn("proposal.json", execution["proposal_validation_error"])
            self.assertEqual(
                execution["discarded_identical_editor_backups"],
                ["app/subject.py.bak"],
            )

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
            self.assertEqual(runner.verify_run(run_dir), [])

    def test_verified_real_model_artifact_chain_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.verified_hermes_run(Path(temporary))

            self.assertEqual(runner.verify_run(run_dir), [])

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
