import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "hermes_sandbox_smoke.py"
)
SPEC = importlib.util.spec_from_file_location("hermes_sandbox_smoke", SCRIPT_PATH)
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class HermesSandboxSmokeTests(unittest.TestCase):
    def test_output_mount_match_requires_exact_destination_and_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "output"
            output_dir.mkdir()
            cases = (
                ("/output", output_dir, True),
                ("/output", output_dir.parent / "other", False),
                ("/other", output_dir, False),
            )
            for destination, source, expected in cases:
                with self.subTest(destination=destination, source=source):
                    inspection = [
                        {
                            "Mounts": [
                                {"Destination": destination, "Source": str(source)}
                            ]
                        }
                    ]
                    completed = subprocess.CompletedProcess(
                        args=["docker", "inspect", "candidate"],
                        returncode=0,
                        stdout=json.dumps(inspection),
                        stderr="",
                    )
                    with mock.patch.object(
                        smoke.subprocess,
                        "run",
                        return_value=completed,
                    ):
                        self.assertEqual(
                            smoke.container_has_output_mount("candidate", output_dir),
                            expected,
                        )

    def test_cleanup_ignores_preexisting_and_new_unrelated_containers(self) -> None:
        before = {"preexisting"}
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "output"
            with (
                mock.patch.object(
                    smoke,
                    "docker_ids",
                    return_value={"preexisting", "unrelated"},
                ),
                mock.patch.object(
                    smoke,
                    "container_has_output_mount",
                    return_value=False,
                ) as mount_mock,
                mock.patch.object(smoke.time, "monotonic", side_effect=[0.0, 0.1]),
                mock.patch.object(smoke.time, "sleep") as sleep_mock,
                mock.patch.object(smoke.subprocess, "run") as run_mock,
            ):
                result = smoke.wait_and_cleanup_new_containers(
                    before,
                    output_dir,
                    grace_seconds=0.5,
                )

        self.assertEqual(result, ([], [], []))
        mount_mock.assert_called_once_with("unrelated", output_dir)
        sleep_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_cleanup_force_removes_only_new_exact_output_container(self) -> None:
        before = {"preexisting"}
        discovered = {"preexisting", "target", "unrelated"}
        after_removal = {"preexisting", "unrelated"}
        completed = subprocess.CompletedProcess(
            args=["docker", "rm", "-f", "target"],
            returncode=0,
            stdout="target\n",
            stderr="",
        )
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "output"
            with (
                mock.patch.object(
                    smoke,
                    "docker_ids",
                    side_effect=[discovered, after_removal],
                ),
                mock.patch.object(
                    smoke,
                    "container_has_output_mount",
                    side_effect=lambda container_id, _: container_id == "target",
                ),
                mock.patch.object(
                    smoke.time,
                    "monotonic",
                    side_effect=[0.0, 0.1, 1.0],
                ),
                mock.patch.object(smoke.time, "sleep"),
                mock.patch.object(
                    smoke.subprocess,
                    "run",
                    return_value=completed,
                ) as run_mock,
            ):
                result = smoke.wait_and_cleanup_new_containers(
                    before,
                    output_dir,
                    grace_seconds=0.5,
                )

        self.assertEqual(result, (["target"], ["target"], []))
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.args[0], ["docker", "rm", "-f", "target"])

    def test_malformed_sandbox_proof_is_reported_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proof_path = Path(temporary) / "sandbox-proof.json"
            for value, expected_error in (
                ("{not-json", "JSONDecodeError"),
                ("[]", "ValueError"),
            ):
                with self.subTest(value=value):
                    proof_path.write_text(value, encoding="utf-8")
                    proof, error = smoke.parse_sandbox_proof(proof_path)
                    self.assertIsNone(proof)
                    self.assertIsNotNone(error)
                    self.assertIn(expected_error, error)


if __name__ == "__main__":
    unittest.main()
