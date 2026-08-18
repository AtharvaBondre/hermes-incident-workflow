import importlib.util
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "runner.py"
SPEC = importlib.util.spec_from_file_location("hiw_local_runner", RUNNER_PATH)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class LocalFlowAcceptanceTests(unittest.TestCase):
    def artifact_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, Path(temporary.name)

    def test_retry_success_publishes_only_after_second_candidate(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)

        run_dir, control = runner.run_flow("retry-success", artifact_root=artifacts)

        self.assertEqual(control["outcome"], "SUCCEEDED")
        self.assertEqual(control["attempts"], 2)
        self.assertEqual(runner.verify_run(run_dir), [])
        github = json.loads((run_dir / "mock-github.json").read_text())
        self.assertTrue(github["draft"])
        self.assertEqual(
            set(github["operations"]),
            {"create_branch", "create_commit", "create_pull_request"},
        )
        self.assertNotIn("merge", github["operations"])

    def test_five_failures_do_not_publish(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)

        run_dir, control = runner.run_flow("exhausted", artifact_root=artifacts)

        self.assertEqual(control["outcome"], "FAILED")
        self.assertEqual(control["attempts"], 5)
        self.assertFalse((run_dir / "mock-github.json").exists())
        self.assertTrue((run_dir / "mock-slack.json").exists())
        self.assertEqual(runner.verify_run(run_dir), [])

    def test_injection_is_rejected_before_evidence_or_patching(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)

        run_dir, control = runner.run_flow("reject-injection", artifact_root=artifacts)

        self.assertEqual(control["outcome"], "REJECTED")
        self.assertEqual(control["attempts"], 0)
        self.assertFalse((run_dir / "evidence.json").exists())
        self.assertFalse((run_dir / "mock-github.json").exists())
        self.assertEqual(runner.verify_run(run_dir), [])

    def test_monotonic_deadline_stops_before_evidence(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)

        run_dir, control = runner.run_flow(
            "timeout",
            budget_seconds=0.005,
            artifact_root=artifacts,
        )

        self.assertEqual(control["outcome"], "TIMED_OUT")
        self.assertEqual(control["attempts"], 0)
        self.assertFalse((run_dir / "evidence.json").exists())
        self.assertEqual(runner.verify_run(run_dir), [])

    def test_evidence_is_scoped_and_redacted(self) -> None:
        incident = runner.read_json(runner.FIXTURES / "incidents/retry-success.json")
        packet = runner.collect_evidence(incident)
        serialized = json.dumps(packet)

        self.assertEqual(len(packet["logs"]), 2)
        self.assertEqual(packet["database"]["view"], "incident_context")
        for marker in runner.RAW_SENSITIVE_MARKERS:
            self.assertNotIn(marker, serialized)
        self.assertIn("[REDACTED", serialized)

    def test_fixture_candidate_provider_returns_versioned_contract(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        run_dir = artifacts / "provider-contract"
        run_dir.mkdir()
        workspace = runner.create_workspace(run_dir, "attempt-1")
        patch_path = runner.FIXTURES / "patches/correct.patch"
        provider = runner.FixtureCandidateProvider(
            [patch_path],
            repeat_last_patch=False,
        )

        candidate = provider.create_candidate(
            attempt=1,
            workspace=workspace,
            deadline=time.monotonic() + 10,
        )

        self.assertTrue(provider.has_candidate(1))
        self.assertFalse(provider.has_candidate(2))
        self.assertEqual(candidate.patch_path, patch_path)
        self.assertEqual(
            candidate.record,
            {
                "schema_version": runner.CANDIDATE_CONTRACT_VERSION,
                "source": "fixture-simulated-hermes",
                "attempt": 1,
                "patch": "correct.patch",
                "patch_sha256": runner.hashlib.sha256(patch_path.read_bytes()).hexdigest(),
                "changed_paths": ["app/subject.py"],
                "candidate_digest": candidate.record["candidate_digest"],
            },
        )
        runner.validate_candidate_contract(candidate.record)
        tampered = dict(candidate.record)
        tampered["patch_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            runner.PolicyDenied,
            "candidate patch digest does not match verification input",
        ):
            runner.Candidate(tampered, patch_path)

    def test_run_flow_uses_injected_candidate_provider(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        provider = runner.FixtureCandidateProvider(
            [
                runner.FIXTURES / "patches/incomplete.patch",
                runner.FIXTURES / "patches/correct.patch",
            ],
            repeat_last_patch=False,
        )

        with mock.patch.object(
            provider,
            "create_candidate",
            wraps=provider.create_candidate,
        ) as create_candidate:
            run_dir, control = runner.run_flow(
                "retry-success",
                artifact_root=artifacts,
                candidate_provider=provider,
            )

        self.assertEqual(create_candidate.call_count, 2)
        self.assertEqual(control["candidate_source"], provider.source)
        first_candidate = runner.read_json(run_dir / "attempt-1-candidate.json")
        second_candidate = runner.read_json(run_dir / "attempt-2-candidate.json")
        self.assertEqual(first_candidate["schema_version"], 1)
        self.assertEqual(first_candidate["attempt"], 1)
        self.assertEqual(second_candidate["attempt"], 2)
        self.assertEqual(runner.verify_run(run_dir), [])

    def test_candidate_contract_rejects_unsupported_schema(self) -> None:
        record = {
            "schema_version": runner.CANDIDATE_CONTRACT_VERSION + 1,
            "source": "fixture-simulated-hermes",
            "attempt": 1,
            "patch": "correct.patch",
            "patch_sha256": "0" * 64,
            "changed_paths": ["app/subject.py"],
            "candidate_digest": "1" * 64,
        }

        with self.assertRaisesRegex(
            runner.PolicyDenied,
            "unsupported candidate contract schema",
        ):
            runner.Candidate(record, runner.FIXTURES / "patches/correct.patch")

    def test_wrong_repository_and_patch_path_are_denied(self) -> None:
        incident = runner.read_json(runner.FIXTURES / "incidents/retry-success.json")
        incident["repository"] = "Hermes Incident Workflow/another-repository"
        with self.assertRaises(runner.PolicyDenied):
            runner.validate_incident(incident)

        malicious = "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n"
        with self.assertRaises(runner.PolicyDenied):
            runner.validate_patch(malicious)

    def test_mixed_patch_cannot_hide_forbidden_deletion(self) -> None:
        patch_text = (
            runner.FIXTURES / "patches/mixed-forbidden-delete.patch"
        ).read_text(encoding="utf-8")

        with self.assertRaisesRegex(
            runner.PolicyDenied,
            "candidate path is not allowlisted: tests/test_subject.py",
        ):
            runner.validate_patch(patch_text)

    def test_subprocess_environment_strips_sensitive_names(self) -> None:
        inherited = {
            "AWS_ACCESS_KEY_ID": "synthetic-aws-value",
            "GRAFANA_TOKEN": "synthetic-grafana-value",
            "PGPASSWORD": "synthetic-database-value",
            "GITHUB_TOKEN": "synthetic-github-value",
            "SAFE_LOCAL_FLAG": "preserved",
        }
        with mock.patch.dict(os.environ, inherited, clear=True):
            environment = runner.subprocess_environment({"RUN_SCOPE": "fixture-only"})

        for name in inherited:
            if name != "SAFE_LOCAL_FLAG":
                self.assertNotIn(name, environment)
        self.assertEqual(environment["SAFE_LOCAL_FLAG"], "preserved")
        self.assertEqual(environment["RUN_SCOPE"], "fixture-only")

    def test_unit_test_uses_exact_locked_down_container_command(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        workspace = runner.create_workspace(artifacts, "unit-sandbox")
        completed = subprocess.CompletedProcess([], 0, "sandbox unit output")
        sandbox_id = "0" * 32
        container_name = f"hiw-candidate-test-{sandbox_id}"
        cleanup_result = {"complete": True, "removed": False}

        with (
            mock.patch.object(runner.uuid, "uuid4", return_value=mock.Mock(hex=sandbox_id)),
            mock.patch.object(
                runner,
                "_cleanup_candidate_test_container",
                return_value=cleanup_result,
            ) as cleanup,
            mock.patch.object(runner, "command", return_value=completed) as execute,
        ):
            result = runner.unit_test(workspace, time.monotonic() + 10)

        actual = execute.call_args.args[0]
        cidfile_argument = next(item for item in actual if item.startswith("--cidfile="))
        cidfile = Path(cidfile_argument.removeprefix("--cidfile="))
        expected = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            f"--name={container_name}",
            f"--label=hermes-incident-workflow.candidate-test={sandbox_id}",
            cidfile_argument,
            "--init",
            "--stop-timeout=1",
            "--network=none",
            "--read-only",
            "--user=65534:65534",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,uid=65534,gid=65534,mode=1777",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=64",
            "--memory=128m",
            "--memory-swap=128m",
            "--cpus=0.5",
            f"--mount=type=bind,src={workspace.resolve()},dst=/workspace,readonly",
            "--workdir=/workspace",
            "--entrypoint=/usr/bin/env",
            (
                "python:3.12-alpine@sha256:"
                "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
            ),
            "-i",
            "HOME=/tmp",
            "LANG=C.UTF-8",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONHASHSEED=0",
            "PYTHONPATH=/workspace",
            "PYTHONUNBUFFERED=1",
            "TMPDIR=/tmp",
            "USER=nobody",
            "python",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-v",
        ]
        execute.assert_called_once_with(expected, cwd=runner.PACKAGE_ROOT, timeout=mock.ANY)
        cleanup.assert_called_once_with(
            cidfile,
            container_name=container_name,
            sandbox_id=sandbox_id,
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["output"], "sandbox unit output")
        self.assertEqual(result["cleanup"], cleanup_result)

    def test_controller_test_adds_only_read_only_verifier_mount(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        workspace = runner.create_workspace(artifacts, "controller-sandbox")
        verifier = runner.PACKAGE_ROOT / "verifiers" / "event_indexing_logic.py"
        completed = subprocess.CompletedProcess([], 0, "sandbox verifier output")
        sandbox_id = "1" * 32
        container_name = f"hiw-candidate-test-{sandbox_id}"
        cleanup_result = {"complete": True, "removed": False}

        with (
            mock.patch.object(runner.uuid, "uuid4", return_value=mock.Mock(hex=sandbox_id)),
            mock.patch.object(
                runner,
                "_cleanup_candidate_test_container",
                return_value=cleanup_result,
            ) as cleanup,
            mock.patch.object(runner, "command", return_value=completed) as execute,
        ):
            result = runner.controller_test(
                workspace,
                verifier,
                time.monotonic() + 10,
            )

        actual = execute.call_args.args[0]
        cidfile_argument = next(item for item in actual if item.startswith("--cidfile="))
        cidfile = Path(cidfile_argument.removeprefix("--cidfile="))
        expected = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            f"--name={container_name}",
            f"--label=hermes-incident-workflow.candidate-test={sandbox_id}",
            cidfile_argument,
            "--init",
            "--stop-timeout=1",
            "--network=none",
            "--read-only",
            "--user=65534:65534",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,uid=65534,gid=65534,mode=1777",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=64",
            "--memory=128m",
            "--memory-swap=128m",
            "--cpus=0.5",
            f"--mount=type=bind,src={workspace.resolve()},dst=/workspace,readonly",
            f"--mount=type=bind,src={verifier.resolve()},dst=/verifier/controller.py,readonly",
            "--workdir=/workspace",
            "--entrypoint=/usr/bin/env",
            (
                "python:3.12-alpine@sha256:"
                "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
            ),
            "-i",
            "HOME=/tmp",
            "LANG=C.UTF-8",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONHASHSEED=0",
            "PYTHONPATH=/workspace",
            "PYTHONUNBUFFERED=1",
            "TMPDIR=/tmp",
            "USER=nobody",
            "python",
            "/verifier/controller.py",
            "--repository",
            "/workspace",
        ]
        execute.assert_called_once_with(expected, cwd=runner.PACKAGE_ROOT, timeout=mock.ANY)
        cleanup.assert_called_once_with(
            cidfile,
            container_name=container_name,
            sandbox_id=sandbox_id,
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result["passed"])
        self.assertEqual(result["output"], "sandbox verifier output")
        self.assertEqual(result["cleanup"], cleanup_result)

    def test_candidate_test_timeout_always_runs_scoped_cleanup(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        workspace = runner.create_workspace(artifacts, "timeout-sandbox")
        sandbox_id = "2" * 32
        container_name = f"hiw-candidate-test-{sandbox_id}"
        timeout = subprocess.TimeoutExpired(["docker", "run"], 1)

        with (
            mock.patch.object(runner.uuid, "uuid4", return_value=mock.Mock(hex=sandbox_id)),
            mock.patch.object(
                runner,
                "_cleanup_candidate_test_container",
                return_value={"complete": True, "removed": True},
            ) as cleanup,
            mock.patch.object(runner, "command", side_effect=timeout) as execute,
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.unit_test(workspace, time.monotonic() + 10)

        actual = execute.call_args.args[0]
        cidfile_argument = next(item for item in actual if item.startswith("--cidfile="))
        cleanup.assert_called_once_with(
            Path(cidfile_argument.removeprefix("--cidfile=")),
            container_name=container_name,
            sandbox_id=sandbox_id,
        )

    def test_candidate_test_cleanup_removes_only_owned_container_id(self) -> None:
        temporary, root = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        sandbox_id = "3" * 32
        candidate_id = "a" * 64
        cidfile = root / "container.cid"
        cidfile.write_text(candidate_id + "\n", encoding="utf-8")
        inspect_format = (
            '{{.Id}}|{{index .Config.Labels '
            '"hermes-incident-workflow.candidate-test"}}'
        )
        inspected = subprocess.CompletedProcess(
            [],
            0,
            f"{candidate_id}|{sandbox_id}\n",
        )
        removed = subprocess.CompletedProcess([], 0, candidate_id + "\n")

        with mock.patch.object(
            runner,
            "command",
            side_effect=[inspected, removed],
        ) as execute:
            cleanup = runner._cleanup_candidate_test_container(
                cidfile,
                container_name=f"hiw-candidate-test-{sandbox_id}",
                sandbox_id=sandbox_id,
            )

        self.assertEqual(
            execute.call_args_list,
            [
                mock.call(
                    [
                        "docker",
                        "inspect",
                        f"--format={inspect_format}",
                        candidate_id,
                    ],
                    cwd=runner.PACKAGE_ROOT,
                    timeout=15,
                ),
                mock.call(
                    ["docker", "rm", "--force", candidate_id],
                    cwd=runner.PACKAGE_ROOT,
                    timeout=15,
                ),
            ],
        )
        self.assertEqual(
            cleanup,
            {
                "complete": True,
                "removed": True,
                "container_id": candidate_id[:12],
            },
        )

    def test_candidate_test_cleanup_refuses_mismatched_owner_label(self) -> None:
        temporary, root = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        sandbox_id = "4" * 32
        candidate_id = "b" * 64
        cidfile = root / "container.cid"
        cidfile.write_text(candidate_id + "\n", encoding="utf-8")
        inspected = subprocess.CompletedProcess(
            [],
            0,
            f"{candidate_id}|another-owner\n",
        )

        with mock.patch.object(
            runner,
            "command",
            return_value=inspected,
        ) as execute:
            cleanup = runner._cleanup_candidate_test_container(
                cidfile,
                container_name=f"hiw-candidate-test-{sandbox_id}",
                sandbox_id=sandbox_id,
            )

        self.assertEqual(execute.call_count, 1)
        self.assertEqual(
            cleanup,
            {
                "complete": False,
                "removed": False,
                "reason": "candidate test container ownership label did not match",
            },
        )

    def test_independent_verifier_rejects_wrong_candidate_digest(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        run_dir = artifacts / "wrong-digest"
        run_dir.mkdir()

        verification = runner.independent_verify(
            run_dir,
            runner.FIXTURES / "patches/correct.patch",
            "0" * 64,
            time.monotonic() + 10,
        )

        self.assertTrue(verification["test"]["passed"])
        self.assertFalse(verification["accepted"])
        self.assertNotEqual(
            verification["candidate_digest"],
            verification["tested_digest"],
        )
        self.assertFalse((run_dir / "independent-verifier").exists())

    def test_verifier_rejects_tampered_delivery_and_sensitive_artifact(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        run_dir, _ = runner.run_flow("retry-success", artifact_root=artifacts)
        github_path = run_dir / "mock-github.json"
        github = json.loads(github_path.read_text(encoding="utf-8"))
        github["operations"].append("merge")
        github["draft"] = False
        github["candidate_digest"] = "0" * 64
        runner.write_json(github_path, github)
        (run_dir / "unsafe-retained.txt").write_text(
            runner.RAW_SENSITIVE_MARKERS[0],
            encoding="utf-8",
        )

        issues = runner.verify_run(run_dir)

        self.assertIn("mock GitHub operations differ from allowlist", issues)
        self.assertIn("mock pull request is not a draft", issues)
        self.assertIn("published digest does not match accepted digest", issues)
        self.assertIn("sensitive marker retained in unsafe-retained.txt", issues)

    def test_cleanup_is_idempotent(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)

        run_dir, _ = runner.run_flow("retry-success", artifact_root=artifacts)
        first = runner.cleanup_existing(run_dir)
        second = runner.cleanup_existing(run_dir)

        self.assertTrue(first["cleanup_complete"])
        self.assertTrue(second["cleanup_complete"])
        self.assertEqual(runner.verify_run(run_dir), [])

    def test_latest_run_ignores_newer_non_controller_artifacts(self) -> None:
        temporary, artifacts = self.artifact_root()
        self.addCleanup(temporary.cleanup)
        controller_run = artifacts / "controller-run"
        controller_run.mkdir()
        runner.write_json(controller_run / "control.json", {"run_id": "controller-run"})
        sandbox_smoke = artifacts / "sandbox-smoke-newer"
        sandbox_smoke.mkdir()

        self.assertEqual(runner.latest_run(artifacts), controller_run)


if __name__ == "__main__":
    unittest.main()
