#!/usr/bin/env python3
"""Run a real Hermes tool call through an isolated Docker backend."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "hiw_sandbox_runner",
    PACKAGE_ROOT / "scripts" / "runner.py",
)
assert RUNNER_SPEC and RUNNER_SPEC.loader
workflow_runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(workflow_runner)
FIXTURE_REPOSITORY = PACKAGE_ROOT / "fixtures" / "repository"
SANDBOX_TASK = PACKAGE_ROOT / "scripts" / "sandbox_task.py"
ARTIFACTS = PACKAGE_ROOT / "artifacts"
PROFILE = "hermes-incident-workflow"
MODEL = "mock-model"
PORT = 8000
IMAGE = (
    "python:3.12-slim-bookworm@sha256:"
    "a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134"
)
SKILL_SENTINEL = "the outer controller alone counts attempts, enforces the deadline"
EXPECTED_TOOL_NAMES = {
    "process",
    "terminal",
}
EXPECTED_CONTAINER_ENVIRONMENT_NAMES = {
    "HIW_SANDBOX_MODE",
    "GPG_KEY",
    "LANG",
    "PATH",
    "PYTHON_SHA256",
    "PYTHON_VERSION",
}
EXPECTED_HERMES_ENVIRONMENT = {
    "AI_AGENT": "hermes-agent",
    "GIT_PAGER": "cat",
    "HERMES_AGENT": "true",
    "PAGER": "cat",
}


def docker_ids() -> set[str]:
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=hermes-profile={PROFILE}",
                "--format",
                "{{.ID}}",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Docker container enumeration failed") from exc
    if result.returncode != 0:
        raise RuntimeError("Docker container enumeration failed")
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def container_has_output_mount(container_id: str, output_dir: Path) -> bool:
    try:
        result = subprocess.run(
            ["docker", "inspect", container_id],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Docker container inspection failed") from exc
    if result.returncode != 0:
        raise RuntimeError("Docker container inspection failed")
    try:
        inspected = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Docker container inspection failed") from exc
    if (
        not isinstance(inspected, list)
        or len(inspected) != 1
        or not isinstance(inspected[0], dict)
        or not isinstance(inspected[0].get("Mounts"), list)
    ):
        raise RuntimeError("Docker container inspection returned an invalid result")
    data = inspected[0]
    return any(
        item.get("Destination") == "/output"
        and Path(str(item.get("Source", ""))).resolve() == output_dir.resolve()
        for item in data.get("Mounts", [])
    )


def wait_and_cleanup_new_containers(
    before: set[str], output_dir: Path, grace_seconds: float = 15.0
) -> tuple[list[str], list[str], list[str], list[str]]:
    observation_errors: list[str] = []

    def observe_scoped() -> list[str]:
        try:
            current = docker_ids()
        except RuntimeError as exc:
            observation_errors.append(str(exc))
            return []
        observed: list[str] = []
        for container_id in current - before:
            try:
                if container_has_output_mount(container_id, output_dir):
                    observed.append(container_id)
            except RuntimeError as exc:
                observation_errors.append(str(exc))
        return sorted(observed)

    deadline = time.monotonic() + grace_seconds
    remaining: list[str] = []
    while time.monotonic() < deadline:
        remaining = observe_scoped()
        if observation_errors:
            break
        if not remaining:
            return [], [], [], []
        time.sleep(0.25)

    forced: list[str] = []
    for container_id in remaining:
        try:
            result = subprocess.run(
                ["docker", "rm", "-f", container_id],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            observation_errors.append(
                f"Docker container removal failed: {type(exc).__name__}"
            )
            continue
        if result.returncode == 0:
            forced.append(container_id)
    final_remaining = observe_scoped()
    return (
        remaining,
        forced,
        final_remaining,
        sorted(set(observation_errors)),
    )


def inspect_new_container(before: set[str]) -> dict[str, Any]:
    candidates = sorted(docker_ids() - before)
    if len(candidates) != 1:
        return {"found": False, "candidate_count": len(candidates)}
    container_id = candidates[0]
    result = subprocess.run(
        ["docker", "inspect", container_id],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        return {"found": False, "inspect_error": result.stderr[-1000:]}
    data = json.loads(result.stdout)[0]
    environment = {
        item.split("=", 1)[0]: item.split("=", 1)[1]
        for item in data.get("Config", {}).get("Env", [])
        if "=" in item
    }
    mounts = sorted(
        (
            {
                "destination": item.get("Destination"),
                "source": item.get("Source"),
                "read_write": item.get("RW"),
                "type": item.get("Type"),
            }
            for item in data.get("Mounts", [])
        ),
        key=lambda item: str(item.get("destination")),
    )
    return {
        "found": True,
        "container_id_prefix": container_id[:12],
        "image": data.get("Config", {}).get("Image"),
        "working_directory": data.get("Config", {}).get("WorkingDir"),
        "network_mode": data.get("HostConfig", {}).get("NetworkMode"),
        "auto_remove": data.get("HostConfig", {}).get("AutoRemove"),
        "privileged": data.get("HostConfig", {}).get("Privileged"),
        "read_only_rootfs": data.get("HostConfig", {}).get("ReadonlyRootfs"),
        "security_opt": data.get("HostConfig", {}).get("SecurityOpt") or [],
        "memory_bytes": data.get("HostConfig", {}).get("Memory"),
        "nano_cpus": data.get("HostConfig", {}).get("NanoCpus"),
        "pids_limit": data.get("HostConfig", {}).get("PidsLimit"),
        "cap_drop": data.get("HostConfig", {}).get("CapDrop") or [],
        "cap_add": data.get("HostConfig", {}).get("CapAdd") or [],
        "environment": environment,
        "environment_names": sorted(environment),
        "tmpfs": data.get("HostConfig", {}).get("Tmpfs") or {},
        "mounts": mounts,
    }


def parse_sandbox_proof(proof_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not proof_path.exists():
        return None, None
    try:
        value = json.loads(proof_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("sandbox proof must be a JSON object")
        return value, None
    except (OSError, UnicodeError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


class ModelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    request_count = 0
    agent_request_count = 0
    tool_names: list[str] = []
    skill_loaded = False
    container_inspection: dict[str, Any] = {}
    tool_result_summaries: list[str] = []
    containers_before: set[str] = set()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/v1/models":
            self.send_error(404)
            return
        self.write_json(
            {
                "object": "list",
                "data": [{"id": MODEL, "object": "model", "created": 0, "owned_by": "local-smoke"}],
            }
        )

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/v1/chat/completions":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        type(self).request_count += 1
        tools = request.get("tools") or []
        if tools:
            type(self).agent_request_count += 1
        type(self).tool_names = sorted(
            tool.get("function", {}).get("name", "") for tool in tools if tool.get("function")
        )
        message_text = "\n".join(
            str(message.get("content", ""))
            for message in request.get("messages") or []
        ).lower()
        type(self).skill_loaded = SKILL_SENTINEL in message_text
        has_tool_result = any(message.get("role") == "tool" for message in request.get("messages") or [])
        if has_tool_result:
            type(self).tool_result_summaries = [
                str(message.get("content", ""))[-2000:]
                for message in request.get("messages") or []
                if message.get("role") == "tool"
            ]
            type(self).container_inspection = inspect_new_container(type(self).containers_before)
            self.write_completion(request, content='{"status":"sandbox-task-complete"}')
            return

        terminal = next(
            (
                tool.get("function", {})
                for tool in tools
                if tool.get("function", {}).get("name") == "terminal"
            ),
            None,
        )
        if terminal is None:
            self.write_completion(request, content='{"status":"terminal-tool-unavailable"}')
            return
        properties = terminal.get("parameters", {}).get("properties", {})
        if "command" in properties:
            arguments: dict[str, Any] = {"command": "python /task/sandbox_task.py"}
        elif "commands" in properties:
            arguments = {"commands": ["python /task/sandbox_task.py"]}
        else:
            self.write_completion(request, content='{"status":"terminal-schema-unsupported"}')
            return
        self.write_completion(
            request,
            tool_call={
                "index": 0,
                "id": "call_hiw_sandbox_smoke",
                "type": "function",
                "function": {"name": "terminal", "arguments": json.dumps(arguments)},
            },
        )

    def write_completion(
        self,
        request: dict[str, Any],
        *,
        content: str | None = None,
        tool_call: dict[str, Any] | None = None,
    ) -> None:
        if request.get("stream"):
            delta: dict[str, Any] = {"role": "assistant"}
            finish_reason = "stop"
            if tool_call is not None:
                delta["tool_calls"] = [tool_call]
                finish_reason = "tool_calls"
            else:
                delta["content"] = content
            chunks = [
                {
                    "id": "chatcmpl-hiw-sandbox",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": MODEL,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                },
                {
                    "id": "chatcmpl-hiw-sandbox",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": MODEL,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
                },
            ]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
                self.wfile.flush()
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True
            return

        message: dict[str, Any] = {"role": "assistant", "content": content}
        finish_reason = "stop"
        if tool_call is not None:
            message["tool_calls"] = [tool_call]
            finish_reason = "tool_calls"
        self.write_json(
            {
                "id": "chatcmpl-hiw-sandbox",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": MODEL,
                "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
        )

    def write_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> int:
    hermes = shutil.which("hermes")
    if not hermes:
        raise SystemExit("hermes is not on PATH")
    docker = shutil.which("docker")
    if not docker:
        raise SystemExit("docker is not on PATH")
    runtime_identity = workflow_runner.inspect_hermes_runtime(hermes)
    if runtime_identity.get("qualified") is not True:
        problems = runtime_identity.get("problems") or []
        detail = "; ".join(str(item) for item in problems)
        raise SystemExit(
            "Hermes runtime is not qualified for the sandbox smoke"
            + (f": {detail}" if detail else "")
        )

    containers_before = docker_ids()
    ModelHandler.containers_before = containers_before
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ModelHandler)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = ARTIFACTS / f"{timestamp}-hermes-sandbox"
    output_dir = run_dir / "output"
    disposable_profile: dict[str, Any] | None = None
    thread: threading.Thread | None = None
    try:
        output_dir.mkdir(parents=True)
        disposable_profile = workflow_runner.prepare_disposable_hermes_profile(
            run_dir,
            PROFILE,
            credential_files=(),
        )
        profile_dir = disposable_profile["profile_dir"]
        smoke_env = profile_dir / ".env"
        smoke_env.write_text(
            "OPENAI_API_KEY=local-smoke-no-secret\n", encoding="utf-8"
        )
        smoke_env.chmod(0o600)
        environment = workflow_runner.hermes_process_environment(
            input_dir=FIXTURE_REPOSITORY,
            task_path=SANDBOX_TASK,
            output_dir=output_dir,
            hermes_root=disposable_profile["hermes_root"],
            launcher_home=disposable_profile["launcher_home"],
        )
        command = [
            hermes,
            "-p",
            PROFILE,
            "chat",
            "--skills",
            "hermes-incident-remediation",
            "--quiet",
            "--yolo",
            "--source",
            "tool",
            "--max-turns",
            "4",
            "--query",
            (
                "Run the local synthetic remediation sandbox smoke. Use the preloaded "
                "Hermes Incident Workflow remediation skill, execute only the bounded "
                "task supplied by the local scripted provider, and return its "
                "completion status."
            ),
        ]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    except Exception as exc:
        if thread is not None and thread.is_alive():
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()
        setup_cleanup = (
            workflow_runner.cleanup_disposable_hermes_profile(disposable_profile)
            if disposable_profile is not None
            else {"removed": [], "remaining": [], "complete": True}
        )
        if run_dir.exists():
            failure_record = {
                "schema_version": 1,
                "kind": "hermes-scripted-provider-sandbox-proof",
                "ok": False,
                "setup_error": f"{type(exc).__name__}: {exc}",
                "disposable_profile_cleanup": setup_cleanup,
            }
            (run_dir / "hermes-runtime-proof.json").write_text(
                json.dumps(failure_record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        raise
    started = time.monotonic()
    returncode: int | None = None
    stdout = ""
    stderr = ""
    run_error: str | None = None
    try:
        result = subprocess.run(
            command,
            cwd=PACKAGE_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        returncode = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as exc:
        run_error = "Hermes smoke timed out after 180 seconds"
        stdout = str(exc.stdout or "")[-4000:]
        stderr = str(exc.stderr or "")[-4000:]
    except Exception as exc:
        run_error = f"{type(exc).__name__}: {exc}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    elapsed = round(time.monotonic() - started, 3)
    proof_path = output_dir / "sandbox-proof.json"
    (
        grace_remaining,
        harness_removed,
        final_remaining,
        cleanup_observation_errors,
    ) = wait_and_cleanup_new_containers(containers_before, output_dir)
    sandbox_proof, proof_parse_error = parse_sandbox_proof(proof_path)
    runtime = ModelHandler.container_inspection
    expected_mounts = {
        "/input": {"source": str(FIXTURE_REPOSITORY.resolve()), "read_write": False, "type": "bind"},
        "/task/sandbox_task.py": {"source": str(SANDBOX_TASK.resolve()), "read_write": False, "type": "bind"},
        "/output": {"source": str(output_dir.resolve()), "read_write": True, "type": "bind"},
        "/root/.hermes/skills": {
            "source": str((profile_dir / "skills").resolve()),
            "read_write": False,
            "type": "bind",
        },
    }
    for relative in workflow_runner.HERMES_CACHE_DIRECTORIES:
        expected_mounts[f"/root/.hermes/{relative}"] = {
            "source": str((profile_dir / relative).resolve()),
            "read_write": False,
            "type": "bind",
        }
    observed_mounts = {
        item.get("destination"): {
            "source": item.get("source"),
            "read_write": item.get("read_write"),
            "type": item.get("type"),
        }
        for item in runtime.get("mounts", [])
        if item.get("type") == "bind"
    }
    cache_mount_sources_empty = all(
        (profile_dir / relative).is_dir()
        and not any((profile_dir / relative).iterdir())
        for relative in workflow_runner.HERMES_CACHE_DIRECTORIES
    )
    profile_cleanup = workflow_runner.cleanup_disposable_hermes_profile(
        disposable_profile
    )
    checks = {
        "hermes_runtime_qualified": runtime_identity["qualified"],
        "hermes_exit_zero": returncode == 0,
        "two_agent_model_turns": ModelHandler.agent_request_count == 2,
        "tool_surface_exact": set(ModelHandler.tool_names) == EXPECTED_TOOL_NAMES,
        "hiw_skill_loaded": ModelHandler.skill_loaded,
        "container_inspected": runtime.get("found") is True,
        "container_image_pinned": runtime.get("image") == IMAGE,
        "container_working_directory": runtime.get("working_directory") == "/workspace",
        "container_network_none": runtime.get("network_mode") == "none",
        "container_auto_remove": runtime.get("auto_remove") is True,
        "container_mounts_exact": observed_mounts == expected_mounts,
        "container_env_exact": set(runtime.get("environment_names", []))
        == EXPECTED_CONTAINER_ENVIRONMENT_NAMES,
        "container_hermes_env_values_exact": bool(
            sandbox_proof
            and sandbox_proof.get("hermes_environment") == EXPECTED_HERMES_ENVIRONMENT
        ),
        "container_cache_sources_empty": cache_mount_sources_empty,
        "container_has_no_credential_mounts": all(
            item.get("destination")
            not in {"/root/.hermes/.env", "/root/.hermes/auth.json"}
            for item in runtime.get("mounts", [])
        ),
        "container_not_privileged": runtime.get("privileged") is False,
        "container_rootfs_read_only": runtime.get("read_only_rootfs") is True,
        "container_no_new_privileges": any(
            item.startswith("no-new-privileges") for item in runtime.get("security_opt", [])
        ),
        "container_capabilities_exact": set(runtime.get("cap_drop", [])) == {"ALL"}
        and set(runtime.get("cap_add", []))
        == {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"},
        "container_pids_limited": runtime.get("pids_limit") == 256,
        "container_cpu_limited": runtime.get("nano_cpus") == 1_000_000_000,
        "container_memory_limited": runtime.get("memory_bytes") == 1_073_741_824,
        "sandbox_proof_written": sandbox_proof is not None,
        "sandbox_proof_parseable": proof_parse_error is None,
        "input_read_only": bool(sandbox_proof and sandbox_proof.get("input_read_only")),
        "network_blocked_in_task": bool(sandbox_proof and sandbox_proof.get("network_blocked")),
        "sandbox_env_exact": bool(
            sandbox_proof and sandbox_proof.get("unexpected_environment_names") == []
        ),
        "candidate_cache_clean": bool(sandbox_proof is not None and sandbox_proof.get("cache_files") == []),
        "tests_passed_in_task": bool(sandbox_proof and sandbox_proof.get("test_passed")),
        "container_removed_after_run": not grace_remaining,
        "failure_cleanup_complete": not final_remaining
        and not cleanup_observation_errors,
        "disposable_profile_cleanup_complete": profile_cleanup["complete"],
    }
    record = {
        "schema_version": 1,
        "kind": "hermes-scripted-provider-sandbox-proof",
        "scope": "local arm64 synthetic fixture only",
        "hermes_profile": PROFILE,
        "model_source": "local scripted OpenAI-compatible test provider",
        "real_model_inference": False,
        "elapsed_seconds": elapsed,
        "model_request_count": ModelHandler.request_count,
        "agent_model_request_count": ModelHandler.agent_request_count,
        "run_error": run_error,
        "proof_parse_error": proof_parse_error,
        "checks": checks,
        "runtime": runtime,
        "tool_names": ModelHandler.tool_names,
        "tool_result_summaries": ModelHandler.tool_result_summaries,
        "sandbox_proof": sandbox_proof,
        "containers_remaining_after_grace": [item[:12] for item in grace_remaining],
        "containers_removed_by_harness": [item[:12] for item in harness_removed],
        "containers_remaining_after_harness_cleanup": [item[:12] for item in final_remaining],
        "cleanup_observation_errors": cleanup_observation_errors,
        "disposable_profile_cleanup": profile_cleanup,
        "hermes_stdout": stdout[-4000:],
        "hermes_stderr": stderr[-4000:],
    }
    record_path = run_dir / "hermes-runtime-proof.json"
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": all(checks.values()), "run_dir": str(run_dir), "checks": checks}, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
