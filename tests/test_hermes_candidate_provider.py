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
                "outcome": "CANDIDATE_RETURNED",
                "session_id": "20260817_120000_ab12cd",
                "patch_sha256": patch_sha256,
                "candidate_digest": candidate_digest,
                "cleanup": {
                    "complete": True,
                    "remaining_container_ids": [],
                },
            },
        )
        runner.write_json(
            run_dir / "attempt-1-result.json",
            {
                "attempt": 1,
                "candidate_digest": candidate_digest,
                "test": {"passed": True},
            },
        )
        runner.write_json(
            run_dir / "verification.json",
            {
                "accepted": True,
                "candidate_digest": candidate_digest,
                "tested_digest": candidate_digest,
                "test": {"passed": True},
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
            command = observed["args"]
            self.assertEqual(command[command.index("-p") + 1], runner.HERMES_PROFILE)
            self.assertIn("--provider", command)
            self.assertIn("example-provider", command)
            self.assertIn("--model", command)
            self.assertIn("example-model", command)
            self.assertIn("--skills", command)
            self.assertIn("hermes-incident-remediation", command)
            self.assertNotIn("--resume", command)

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
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.args[0], ["docker", "rm", "-f", "target"])

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


if __name__ == "__main__":
    unittest.main()
