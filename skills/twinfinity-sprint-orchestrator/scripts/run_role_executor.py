#!/usr/bin/env python3
"""Launch one fresh role executor from an atomically reserved attempt."""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import tomllib
from typing import Any, Callable

from coordination_store import (
    ACTIVE_EXECUTION_STATUSES,
    claimed_no_delivery_park_evidence,
    digest_json,
    parse_coordination_envelope,
    terminal_watch_key,
)
from executor_registry import (
    AttemptLineage,
    DEFAULT_CONFIG,
    DEFAULT_DATABASE,
    EXECUTION_ROLES,
    PLANNER_PARK_PROTOCOL,
    RegistryError,
    SystemdUnitEvidence,
    UUID,
    applied_endpoint_rotation_chain,
    attempt_lineage_for_target,
    canonical_json,
    current_endpoint,
    digest_json,
    identity_role,
    load_registry_config,
    open_registry_database,
    probe_systemd_unit,
    registry_config_scope,
    reserve_attempt,
    stable_systemd_unit,
    target_progress_digest,
    transition_attempt,
    utc_now,
    validate_launch_systemd_evidence,
)
from role_executor_broker import (
    BROKER_PROTOCOL,
    BrokerError,
    BrokerRuntimePaths,
    execute_brokered_readiness,
)
from admission_source_equivalence import admission_lineage_source_is_current


HEARTBEAT_SECONDS = 30
PARK_CAPABILITY_SCHEMA = "twinfinity-planner-park-capability/v1"
PARK_CAPABILITY_SOCKET_ENV = "TWINFINITY_PARK_CAPABILITY_SOCKET"
PARK_CAPABILITY_STATES = {
    "CREATED",
    "ARMED",
    "PROMPT_RELEASED",
    "INNER_SEEN",
    "CONSUMED",
    "ADOPTED",
    "FAILED",
}
PARK_ADOPTION_WAIT_SECONDS = 10.0
PARK_SOCKET_REQUEST_LIMIT = 64 * 1024
PARK_HOOK_EVENT_LIMIT = 32 * 1024
PARK_CODEX_VERSION = "codex-cli 0.147.0"
PARK_CODEX_SHA256 = "cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40"
PARK_REQUIREMENTS_PATH = Path("/etc/codex/requirements.toml")
PARK_CHILD_FIXED_ENVIRONMENT = {
    "HOME": "/home/ubuntu",
    "USER": "ubuntu",
    "LOGNAME": "ubuntu",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "SHELL": "/bin/bash",
    "SSL_CERT_DIR": "/etc/ssl/certs",
    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
}


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def parse_park_hook_event(raw: bytes) -> dict[str, Any]:
    """Parse one bounded, duplicate-free Codex PreToolUse event."""

    if not raw or len(raw) > PARK_HOOK_EVENT_LIMIT:
        raise RegistryError("PARK_HOOK_EVENT_INVALID")
    try:
        event = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RegistryError("PARK_HOOK_EVENT_INVALID") from exc
    required = {
        "cwd",
        "hook_event_name",
        "model",
        "permission_mode",
        "session_id",
        "tool_input",
        "tool_name",
        "tool_use_id",
        "transcript_path",
        "turn_id",
    }
    if (
        not isinstance(event, dict)
        or set(event) != required
        or event.get("hook_event_name") != "PreToolUse"
        or any(
            not isinstance(event.get(field), str) or not event[field]
            for field in (
                "cwd",
                "model",
                "permission_mode",
                "session_id",
                "tool_name",
                "tool_use_id",
                "turn_id",
            )
        )
        or not (
            event.get("transcript_path") is None
            or isinstance(event.get("transcript_path"), str)
        )
        or not isinstance(event.get("tool_input"), dict)
    ):
        raise RegistryError("PARK_HOOK_EVENT_INVALID")
    return event


def _park_socket_request(
    environ: dict[str, str], payload: dict[str, Any]
) -> dict[str, Any]:
    path_value = environ.get(PARK_CAPABILITY_SOCKET_ENV, "")
    path = Path(path_value)
    if not path_value or not path.is_absolute() or "\x00" in path_value:
        raise RegistryError("PARK_CAPABILITY_REQUIRED")
    request = canonical_json(payload).encode("utf-8") + b"\n"
    if len(request) > PARK_SOCKET_REQUEST_LIMIT:
        raise RegistryError("PARK_CAPABILITY_REQUEST_INVALID")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(PARK_ADOPTION_WAIT_SECONDS)
    try:
        client.connect(path_value)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        raw = b""
        while True:
            block = client.recv(4096)
            if not block:
                break
            raw += block
            if len(raw) > PARK_SOCKET_REQUEST_LIMIT:
                raise RegistryError("PARK_CAPABILITY_RESPONSE_INVALID")
    except (OSError, TimeoutError) as exc:
        raise RegistryError("PARK_CAPABILITY_UNAVAILABLE") from exc
    finally:
        client.close()
    try:
        response = json.loads(raw, object_pairs_hook=_reject_duplicate_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RegistryError("PARK_CAPABILITY_RESPONSE_INVALID") from exc
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise RegistryError("PARK_CAPABILITY_DENIED")
    return response


def authorize_park_nested_hook(
    raw_event: bytes, *, environ: dict[str, str]
) -> dict[str, Any]:
    """Ask the runner to adopt one exact real nested Bash PreToolUse event."""

    event = parse_park_hook_event(raw_event)
    response = _park_socket_request(
        environ,
        {
            "kind": "nested_hook",
            "event_base64": base64.b64encode(raw_event).decode("ascii"),
            "event_sha256": hashlib.sha256(raw_event).hexdigest(),
        },
    )
    if response.get("state") != "INNER_SEEN":
        raise RegistryError("PARK_CAPABILITY_DENIED")
    return event


def consume_park_controller_capability(
    *, environ: dict[str, str]
) -> dict[str, Any]:
    """Independently reauthenticate the exact controller before any DB open."""

    response = _park_socket_request(environ, {"kind": "controller_consume"})
    credential = response.get("credential")
    binding = response.get("binding")
    if (
        response.get("state") != "CONSUMED"
        or not isinstance(credential, str)
        or not credential
        or not isinstance(binding, dict)
    ):
        raise RegistryError("PARK_CAPABILITY_DENIED")
    return {"credential": credential, "binding": binding}


def adopt_park_controller_capability(*, environ: dict[str, str]) -> dict[str, Any]:
    """Acknowledge the immutable read phase before writable SQLite is opened."""

    response = _park_socket_request(environ, {"kind": "controller_adopt"})
    if response.get("state") != "ADOPTED":
        raise RegistryError("PARK_CAPABILITY_DENIED")
    return response


def _process_identity(pid: int) -> tuple[int, int]:
    if type(pid) is not int or pid <= 1:
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID")
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        tail = raw[raw.rindex(")") + 2 :].split()
        return int(tail[1]), int(tail[19])
    except (OSError, ValueError, IndexError) as exc:
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID") from exc


def _process_argv(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return [part.decode("utf-8") for part in raw.rstrip(b"\0").split(b"\0")]
    except (OSError, UnicodeDecodeError) as exc:
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID") from exc


def _process_cwd(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError as exc:
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID") from exc


def _process_executable(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError as exc:
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID") from exc


def _process_environment(pid: int) -> dict[str, str]:
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
        values: dict[str, str] = {}
        for item in raw.rstrip(b"\0").split(b"\0"):
            key, separator, value = item.partition(b"=")
            if not separator:
                raise ValueError
            decoded_key = key.decode("utf-8")
            if not decoded_key or decoded_key in values:
                raise ValueError
            values[decoded_key] = value.decode("utf-8")
        return values
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID") from exc


def _process_control_group(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID") from exc
    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::"):
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID")
    control_group = lines[0][3:]
    if not control_group.startswith("/"):
        raise RegistryError("PARK_PROCESS_IDENTITY_INVALID")
    return control_group


def _process_descends_from(pid: int, ancestor_pid: int, ancestor_start: int) -> bool:
    current = pid
    seen: set[int] = set()
    for _ in range(64):
        if current in seen or current <= 1:
            return False
        seen.add(current)
        try:
            parent, start = _process_identity(current)
        except RegistryError:
            return False
        if current == ancestor_pid:
            return start == ancestor_start
        current = parent
    return False


def _sha256_file(path: Path, *, maximum: int = 512 * 1024 * 1024) -> str:
    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_size <= 0 or metadata.st_size > maximum:
            raise OSError
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT") from exc


def _python_source_closure(entry_paths: tuple[Path, ...]) -> list[dict[str, str]]:
    """Hash the exact recursively imported repository-local Python closure."""

    pending = [
        (path.resolve(strict=True), path.resolve(strict=True).parent)
        for path in entry_paths
    ]
    observed: dict[Path, str] = {}
    try:
        while pending:
            path, scripts_root = pending.pop()
            if path in observed:
                continue
            if path.parent != scripts_root or path.suffix != ".py":
                raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT")
            raw = path.read_bytes()
            tree = ast.parse(raw, filename=os.fspath(path))
            observed[path] = hashlib.sha256(raw).hexdigest()
            module_names: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    module_names.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    module_names.add(node.module.split(".", 1)[0])
            for module_name in sorted(module_names):
                candidate = scripts_root / f"{module_name}.py"
                if candidate.is_file():
                    pending.append((candidate.resolve(strict=True), scripts_root))
    except (OSError, SyntaxError, ValueError) as exc:
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT") from exc
    return [
        {"path": os.fspath(path), "sha256": observed[path]}
        for path in sorted(observed, key=os.fspath)
    ]


class ParkCapabilityBroker:
    """Runner-owned, expiring, one-use authority for Planner PARK."""

    def __init__(self, root: Path, *, credential: str) -> None:
        if not credential or not root.is_absolute() or not root.is_dir():
            raise RegistryError("PARK_CAPABILITY_CREATE_FAILED")
        directory: Path | None = None
        listener: socket.socket | None = None
        try:
            directory = Path(tempfile.mkdtemp(prefix="park-cap-", dir=root))
            os.chmod(directory, 0o700)
            codex_cwd = directory / "codex-worktree"
            initialized = subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "init.defaultBranch=main",
                    "init",
                    "--quiet",
                    os.fspath(codex_cwd),
                ],
                check=False,
                capture_output=True,
                timeout=5,
                env={
                    **PARK_CHILD_FIXED_ENVIRONMENT,
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_NOSYSTEM": "1",
                },
            )
            if initialized.returncode != 0:
                raise OSError("git init failed")
            path = directory / "gate.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(os.fspath(path))
            os.chmod(path, 0o600)
            listener.listen(4)
            listener.settimeout(0.1)

            self._credential = credential
            self._directory = directory
            self.codex_cwd = codex_cwd
            self.path = path
            self._listener = listener
            self._lock = threading.Lock()
            self._stop = threading.Event()
            self._state = "CREATED"
            self._error: str | None = None
            self._manifest: dict[str, Any] | None = None
            self._manifest_sha256: str | None = None
            self._events: list[dict[str, Any]] = []
            self._hook_identity: tuple[str, str, str] | None = None
            self._hook_process_identity: tuple[int, int] | None = None
            self._controller_identity: tuple[int, int] | None = None
            self._thread = threading.Thread(
                target=self._serve,
                name="twinfinity-park-capability",
                daemon=True,
            )
            self._thread.start()
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            if listener is not None:
                listener.close()
            if directory is not None:
                shutil.rmtree(directory, ignore_errors=True)
            raise RegistryError("PARK_CAPABILITY_CREATE_FAILED") from exc

    def arm(self, manifest: dict[str, Any]) -> None:
        required = {
            "schema",
            "attempt_id",
            "instance_id",
            "endpoint_id",
            "target_kind",
            "target_key",
            "request_payload_sha256",
            "repository_observation_sha256",
            "repository",
            "issue_number",
            "generation",
            "lease_manifest_sha256",
            "source_payload_sha256",
            "branch",
            "worktree",
            "command",
            "controller_argv",
            "controller_cwd",
            "runner_pid",
            "runner_start_time",
            "runner_argv",
            "codex_pid",
            "codex_start_time",
            "codex_argv",
            "codex_cwd",
            "codex_version",
            "codex_binary_sha256",
            "codex_home",
            "child_environment_sha256",
            "immutable_files",
            "python_source_closure",
            "python_source_closure_sha256",
            "hook_config_sha256",
            "runner_control_group",
            "codex_control_group",
            "systemd_invocation_id",
            "systemd_control_group",
            "expires_monotonic",
            "one_use",
        }
        with self._lock:
            if (
                self._state != "CREATED"
                or set(manifest) != required
                or manifest.get("schema") != PARK_CAPABILITY_SCHEMA
                or manifest.get("one_use") is not True
                or not isinstance(manifest.get("expires_monotonic"), float)
                or manifest["expires_monotonic"] <= time.monotonic()
                or not self._immutable_manifest_matches(manifest)
            ):
                self._fail_locked("PARK_RUNTIME_MANIFEST_DRIFT")
                raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT")
            self._manifest = json.loads(canonical_json(manifest))
            self._manifest_sha256 = digest_json(manifest)
            self._state = "ARMED"
            self._events.append(
                {
                    "kind": "CAPABILITY_ARMED",
                    "pid": os.getpid(),
                    "monotonic": time.monotonic(),
                    "manifest_sha256": self._manifest_sha256,
                }
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self._state,
                "error": self._error,
                "events": json.loads(canonical_json(self._events)),
                "manifest_sha256": self._manifest_sha256,
            }

    def release_prompt(self, stream: Any, prompt: bytes) -> None:
        """Release stdin while holding the same lock that adopts the first hook."""

        with self._lock:
            if (
                self._state != "ARMED"
                or not isinstance(prompt, bytes)
                or not prompt
            ):
                self._fail_locked("PARK_PROMPT_RELEASE_STATE_CONFLICT")
                raise RegistryError("PARK_PROMPT_RELEASE_STATE_CONFLICT")
            try:
                stream.write(prompt)
                stream.flush()
                stream.close()
            except (AttributeError, OSError, ValueError) as exc:
                self._fail_locked("PARK_PROMPT_RELEASE_FAILED")
                raise RegistryError("PARK_PROMPT_RELEASE_FAILED") from exc
            self._state = "PROMPT_RELEASED"
            self._events.append(
                {
                    "kind": "PROMPT_RELEASED",
                    "pid": os.getpid(),
                    "monotonic": time.monotonic(),
                }
            )

    def close(self) -> None:
        self._stop.set()
        wake: socket.socket | None = None
        try:
            wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            wake.connect(os.fspath(self.path))
        except OSError:
            pass
        finally:
            if wake is not None:
                wake.close()
        self._thread.join(timeout=2)
        self._listener.close()
        try:
            self.path.unlink()
        except OSError:
            pass
        shutil.rmtree(self._directory, ignore_errors=True)
        self._credential = ""

    def _fail_locked(self, error: str) -> None:
        self._state = "FAILED"
        self._error = error
        self._events.append(
            {
                "kind": "CAPABILITY_FAILED",
                "error": error,
                "monotonic": time.monotonic(),
            }
        )

    def _immutable_manifest_matches(self, manifest: dict[str, Any]) -> bool:
        files = manifest.get("immutable_files")
        if (
            not isinstance(files, list)
            or len(files) != 8
            or {item.get("kind") for item in files if isinstance(item, dict)}
            != {
                "codex",
                "runner",
                "controller",
                "guard",
                "profile",
                "requirements",
                "config",
                "python",
            }
        ):
            return False
        try:
            if any(
                not isinstance(item, dict)
                or set(item) != {"kind", "path", "sha256"}
                or item.get("kind")
                not in {
                    "codex",
                    "runner",
                    "controller",
                    "guard",
                    "profile",
                    "requirements",
                    "config",
                    "python",
                }
                or _sha256_file(Path(str(item["path"]))) != item["sha256"]
                for item in files
            ):
                return False
            codex_file = next(item for item in files if item["kind"] == "codex")
            profile_file = next(item for item in files if item["kind"] == "profile")
            requirements_file = next(
                item for item in files if item["kind"] == "requirements"
            )
            config_file = next(item for item in files if item["kind"] == "config")
            python_file = next(item for item in files if item["kind"] == "python")
            closure = _python_source_closure(
                tuple(
                    Path(str(item["path"]))
                    for item in files
                    if item["kind"] in {"runner", "controller", "guard"}
                )
            )
            _guard, effective_requirements, hook_config_sha256 = (
                _planner_runtime_hook_binding(Path(str(profile_file["path"])))
            )
            codex_argv = _process_argv(int(manifest["codex_pid"]))
            return bool(
                manifest.get("codex_version") == PARK_CODEX_VERSION
                and manifest.get("codex_binary_sha256") == PARK_CODEX_SHA256
                and codex_file["sha256"] == PARK_CODEX_SHA256
                and requirements_file["path"] == os.fspath(effective_requirements)
                and config_file["path"]
                == os.fspath(Path(str(manifest["codex_home"])) / "config.toml")
                and manifest.get("hook_config_sha256") == hook_config_sha256
                and manifest.get("child_environment_sha256")
                == digest_json(_process_environment(int(manifest["codex_pid"])))
                and manifest.get("python_source_closure") == closure
                and manifest.get("python_source_closure_sha256")
                == digest_json(closure)
                and _process_executable(int(manifest["codex_pid"]))
                == codex_file["path"]
                and _process_executable(int(manifest["runner_pid"]))
                == python_file["path"]
                and codex_argv == manifest.get("codex_argv")
                and _process_cwd(int(manifest["codex_pid"]))
                == manifest.get("codex_cwd")
                and _process_identity(int(manifest["codex_pid"]))[1]
                == manifest.get("codex_start_time")
                and _process_identity(int(manifest["runner_pid"]))[1]
                == manifest.get("runner_start_time")
                and _process_argv(int(manifest["runner_pid"]))
                == manifest.get("runner_argv")
                and _process_control_group(int(manifest["runner_pid"]))
                == manifest.get("runner_control_group")
                and _process_control_group(int(manifest["codex_pid"]))
                == manifest.get("codex_control_group")
            )
        except (RegistryError, TypeError, ValueError):
            return False

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                self._handle(connection)

    def _handle(self, connection: socket.socket) -> None:
        response: dict[str, Any]
        try:
            peer_pid, peer_uid, _peer_gid = struct.unpack(
                "3i",
                connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                ),
            )
            raw = b""
            while True:
                block = connection.recv(4096)
                if not block:
                    break
                raw += block
                if len(raw) > PARK_SOCKET_REQUEST_LIMIT:
                    raise RegistryError("PARK_CAPABILITY_REQUEST_INVALID")
            if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
                raise RegistryError("PARK_CAPABILITY_REQUEST_INVALID")
            request = json.loads(
                raw[:-1], object_pairs_hook=_reject_duplicate_json_pairs
            )
            if not isinstance(request, dict):
                raise RegistryError("PARK_CAPABILITY_REQUEST_INVALID")
            with self._lock:
                response = self._authorize_locked(request, peer_pid, peer_uid)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            RegistryError,
        ) as exc:
            with self._lock:
                if self._state != "FAILED":
                    self._fail_locked(str(exc) or "PARK_CAPABILITY_REQUEST_INVALID")
                response = {"ok": False, "error": self._error}
        try:
            connection.sendall(canonical_json(response).encode("utf-8"))
        except OSError:
            pass

    def _authorize_locked(
        self, request: dict[str, Any], peer_pid: int, peer_uid: int
    ) -> dict[str, Any]:
        manifest = self._manifest
        if (
            manifest is None
            or self._state == "FAILED"
            or peer_uid != os.getuid()
            or time.monotonic() >= manifest["expires_monotonic"]
            or not self._immutable_manifest_matches(manifest)
            or not _process_descends_from(
                peer_pid, manifest["codex_pid"], manifest["codex_start_time"]
            )
        ):
            raise RegistryError("PARK_CAPABILITY_BINDING_MISMATCH")
        kind = request.get("kind")
        if kind == "nested_hook":
            return self._authorize_hook_locked(request, peer_pid, manifest)
        if kind == "controller_consume":
            return self._consume_controller_locked(request, peer_pid, manifest)
        if kind == "controller_adopt":
            return self._adopt_controller_locked(request, peer_pid, manifest)
        raise RegistryError("PARK_CAPABILITY_REQUEST_INVALID")

    def _authorize_hook_locked(
        self, request: dict[str, Any], peer_pid: int, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        if self._state != "PROMPT_RELEASED" or set(request) != {
            "kind",
            "event_base64",
            "event_sha256",
        }:
            raise RegistryError("PARK_CAPABILITY_REPLAY")
        try:
            event_raw = base64.b64decode(request["event_base64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise RegistryError("PARK_HOOK_EVENT_INVALID") from exc
        event = parse_park_hook_event(event_raw)
        identity = (
            event["session_id"],
            event["turn_id"],
            event["tool_use_id"],
        )
        guard_paths = [
            item["path"]
            for item in manifest["immutable_files"]
            if item.get("kind") == "guard"
        ]
        expected_guard = guard_paths[0] if len(guard_paths) == 1 else None
        python_paths = [
            item["path"]
            for item in manifest["immutable_files"]
            if item.get("kind") == "python"
        ]
        expected_python = python_paths[0] if len(python_paths) == 1 else None
        argv = _process_argv(peer_pid)
        _parent, peer_start = _process_identity(peer_pid)
        if (
            hashlib.sha256(event_raw).hexdigest() != request["event_sha256"]
            or event["tool_name"] != "Bash"
            or event["model"] != "gpt-5.6-sol"
            or event["permission_mode"] != "default"
            or set(event["tool_input"]) != {"command"}
            or event["tool_input"]["command"] != manifest["command"]
            or event["cwd"] != manifest["codex_cwd"]
            or self._hook_identity is not None
            or expected_guard is None
            or expected_python is None
            or argv != ["/usr/bin/python3", expected_guard]
            or _process_executable(peer_pid) != expected_python
            or _process_control_group(peer_pid) != manifest["codex_control_group"]
        ):
            raise RegistryError("PARK_HOOK_BINDING_MISMATCH")
        self._hook_identity = identity
        self._hook_process_identity = (peer_pid, peer_start)
        self._state = "INNER_SEEN"
        self._events.append(
            {
                "kind": "NESTED_BASH_PRETOOLUSE",
                "pid": peer_pid,
                "start_time": peer_start,
                "executable": expected_python,
                "control_group": manifest["codex_control_group"],
                "monotonic": time.monotonic(),
                "event_sha256": request["event_sha256"],
                "session_id": identity[0],
                "turn_id": identity[1],
                "tool_use_id": identity[2],
            }
        )
        return {"ok": True, "state": self._state}

    def _controller_peer_matches(
        self, peer_pid: int, manifest: dict[str, Any]
    ) -> bool:
        python_paths = [
            item["path"]
            for item in manifest["immutable_files"]
            if item.get("kind") == "python"
        ]
        if len(python_paths) != 1:
            return False
        _parent, peer_start = _process_identity(peer_pid)
        return bool(
            _process_argv(peer_pid) == manifest["controller_argv"]
            and _process_cwd(peer_pid) == manifest["controller_cwd"]
            and _process_executable(peer_pid) == python_paths[0]
            and _process_control_group(peer_pid) == manifest["codex_control_group"]
            and self._hook_process_identity is not None
            and (peer_pid, peer_start) != self._hook_process_identity
        )

    def _consume_controller_locked(
        self, request: dict[str, Any], peer_pid: int, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        if (
            set(request) != {"kind"}
            or self._state != "INNER_SEEN"
            or self._hook_identity is None
            or not self._controller_peer_matches(peer_pid, manifest)
        ):
            raise RegistryError("PARK_CONTROLLER_REAUTHENTICATION_FAILED")
        _parent, start = _process_identity(peer_pid)
        self._controller_identity = (peer_pid, start)
        self._state = "CONSUMED"
        self._events.append(
            {
                "kind": "CONTROLLER_CONSUMED",
                "pid": peer_pid,
                "start_time": start,
                "executable": _process_executable(peer_pid),
                "control_group": _process_control_group(peer_pid),
                "monotonic": time.monotonic(),
            }
        )
        binding = {
            key: manifest[key]
            for key in (
                "attempt_id",
                "instance_id",
                "endpoint_id",
                "target_kind",
                "target_key",
                "request_payload_sha256",
                "repository_observation_sha256",
            )
        }
        return {
            "ok": True,
            "state": self._state,
            "credential": self._credential,
            "binding": binding,
        }

    def _adopt_controller_locked(
        self, request: dict[str, Any], peer_pid: int, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        if (
            set(request) != {"kind"}
            or self._state != "CONSUMED"
            or self._controller_identity is None
            or self._controller_identity != (peer_pid, _process_identity(peer_pid)[1])
            or not self._controller_peer_matches(peer_pid, manifest)
        ):
            raise RegistryError("PARK_CONTROLLER_ADOPTION_FAILED")
        self._state = "ADOPTED"
        self._events.append(
            {
                "kind": "CONTROLLER_ADOPTED",
                "pid": peer_pid,
                "monotonic": time.monotonic(),
            }
        )
        return {"ok": True, "state": self._state}


def build_fresh_command(command_prefix: list[str], prompt: str) -> list[str]:
    if (
        not command_prefix
        or command_prefix[:2] != ["/home/ubuntu/.local/bin/codex", "exec"]
        or "resume" in command_prefix
        or any(UUID.fullmatch(token) for token in command_prefix)
        or any("bypass" in token.casefold() for token in command_prefix)
        or not prompt
    ):
        raise RegistryError("EXECUTOR_COMMAND_INVALID")
    return [*command_prefix, prompt]


def build_endpoint_runtime_command(configured, prompt: str) -> list[str]:
    """Launch through the endpoint's immutable versioned Codex profile."""

    command = list(configured.command_prefix)
    try:
        profile_index = command.index("--profile") + 1
    except ValueError as exc:
        raise RegistryError("EXECUTOR_COMMAND_INVALID") from exc
    if (
        profile_index >= len(command)
        or command[profile_index] != configured.codex_profile
    ):
        raise RegistryError("EXECUTOR_COMMAND_INVALID")
    command[profile_index] = configured.runtime_codex_profile
    return build_fresh_command(command, prompt)


def build_child_environment(
    base: dict[str, str],
    *,
    attempt_id: str,
    instance_id: str,
    role: str,
    endpoint_id: str,
    token: str,
    target_kind: str,
    target_key: str,
    include_token: bool = True,
) -> dict[str, str]:
    """Bind the child to one exact opaque attempt and target without logging it."""

    if (
        UUID.fullmatch(attempt_id) is None
        or UUID.fullmatch(instance_id) is None
        or role not in EXECUTION_ROLES
        or not endpoint_id
        or not token
        or target_kind not in {"message", "terminal_watch", "hosted_operation"}
        or not target_key
        or type(include_token) is not bool
    ):
        raise RegistryError("EXECUTOR_CHILD_ENVIRONMENT_INVALID")
    environment = dict(base)
    environment.update({
        "TWINFINITY_EXECUTOR_ATTEMPT_ID": attempt_id,
        "TWINFINITY_EXECUTOR_INSTANCE_ID": instance_id,
        "TWINFINITY_EXECUTOR_ROLE": role,
        "TWINFINITY_ROLE_ENDPOINT": endpoint_id,
        "TWINFINITY_EXECUTOR_TARGET_KIND": target_kind,
        "TWINFINITY_EXECUTOR_TARGET_KEY": target_key,
    })
    if include_token:
        environment["TWINFINITY_EXECUTOR_TOKEN"] = token
    else:
        environment.pop("TWINFINITY_EXECUTOR_TOKEN", None)
    return environment


def _planner_park_request_binding(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
    configured: Any,
) -> dict[str, Any] | None:
    if (
        role != "planner"
        or configured.version != 3
        or endpoint_id != "role.planner.v3"
        or target_kind != "message"
    ):
        return None
    try:
        message_id = int(target_key)
    except ValueError as exc:
        raise RegistryError("PARK_TARGET_INVALID") from exc
    row = connection.execute(
        "SELECT topic,payload_json,payload_sha256,state,recipient_session_id "
        "FROM coordination_messages WHERE id=?",
        (message_id,),
    ).fetchone()
    if (
        row is None
        or row["topic"] != "coordination.notice"
        or row["state"] not in {"PREPARED", "CLAIMED"}
        or row["recipient_session_id"] != endpoint_id
    ):
        return None
    try:
        envelope = parse_coordination_envelope(row["payload_json"])
        if envelope.reserved_handler != "claimed_no_delivery_park":
            return None
        evidence = claimed_no_delivery_park_evidence(envelope.payload)
    except Exception as exc:
        raise RegistryError("PARK_TARGET_INVALID") from exc
    if envelope.payload_sha256 != row["payload_sha256"]:
        raise RegistryError("PARK_TARGET_INVALID")
    admission = connection.execute(
        "SELECT payload_json,payload_sha256 FROM coordination_messages WHERE id=?",
        (int(evidence["admission_message_id"]),),
    ).fetchone()
    if admission is None:
        raise RegistryError("PARK_TARGET_INVALID")
    try:
        admission_envelope = parse_coordination_envelope(admission["payload_json"])
        admission_payload = admission_envelope.payload
    except Exception as exc:
        raise RegistryError("PARK_TARGET_INVALID") from exc
    if (
        admission_envelope.payload_sha256 != admission["payload_sha256"]
        or admission["payload_sha256"] != evidence["admission_payload_sha256"]
        or not isinstance(admission_payload, dict)
        or not isinstance(admission_payload.get("branch"), str)
        or not admission_payload["branch"]
        or not isinstance(admission_payload.get("worktree_path"), str)
        or not Path(admission_payload["worktree_path"]).is_absolute()
    ):
        raise RegistryError("PARK_TARGET_INVALID")
    return {
        "request_payload_sha256": envelope.payload_sha256,
        "repository_observation_sha256": str(
            evidence["repository_observation_sha256"]
        ),
        "repository": evidence["repository"],
        "issue_number": int(evidence["issue_number"]),
        "generation": int(evidence["generation"]),
        "lease_manifest_sha256": evidence["lease_manifest_sha256"],
        "source_payload_sha256": evidence["bound_source_sha256"],
        "branch": admission_payload["branch"],
        "worktree": admission_payload["worktree_path"],
    }


def _database_parent(connection: sqlite3.Connection) -> Path:
    row = connection.execute("PRAGMA database_list").fetchone()
    try:
        database = Path(str(row[2]))
    except (IndexError, TypeError) as exc:
        raise RegistryError("EXECUTOR_DATABASE_INVALID") from exc
    if not database.is_absolute() or not database.parent.is_dir():
        raise RegistryError("EXECUTOR_DATABASE_INVALID")
    return database.parent


def _park_controller_command() -> str:
    return (
        "/usr/bin/python3 /home/ubuntu/.codex/skills/"
        "twinfinity-sprint-orchestrator/scripts/kanban_pull_buffer.py park-commit "
        '--message-id "$TWINFINITY_EXECUTOR_TARGET_KEY" '
        '--request-sha256 "$TWINFINITY_PARK_REQUEST_SHA256" '
        '--repository-observation-sha256 '
        '"$TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256" '
        '--planner-session-id "$TWINFINITY_ROLE_ENDPOINT"'
    )


def _park_controller_argv(binding: dict[str, Any]) -> list[str]:
    return [
        "/usr/bin/python3",
        "/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/"
        "kanban_pull_buffer.py",
        "park-commit",
        "--message-id",
        str(binding["target_key"]),
        "--request-sha256",
        str(binding["request_payload_sha256"]),
        "--repository-observation-sha256",
        str(binding["repository_observation_sha256"]),
        "--planner-session-id",
        str(binding["endpoint_id"]),
    ]


def _planner_profile_hook_binding(profile_path: Path) -> tuple[Path, str]:
    try:
        raw = profile_path.read_bytes()
        profile = tomllib.loads(raw.decode("utf-8"))
        pretool = profile["hooks"]["PreToolUse"]
        group = pretool[0]
        handler = group["hooks"][0]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, IndexError, TypeError) as exc:
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT") from exc
    expected_handler_keys = {"type", "command", "timeout", "statusMessage"}
    if (
        profile.get("sandbox_mode") != "read-only"
        or "sandbox_workspace_write" in profile
        or profile.get("features") != {"hooks": True, "multi_agent": False}
        or not isinstance(pretool, list)
        or len(pretool) != 1
        or set(group) != {"matcher", "hooks"}
        or group.get("matcher") != "*"
        or not isinstance(group.get("hooks"), list)
        or len(group["hooks"]) != 1
        or set(handler) != expected_handler_keys
        or handler.get("type") != "command"
        or handler.get("timeout") != 10
        or handler.get("command")
        != (
            "/usr/bin/python3 /home/ubuntu/.codex/skills/"
            "twinfinity-sprint-orchestrator/scripts/delivery_guard.py"
        )
    ):
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT")
    return (
        Path(str(handler["command"]).split(" ", 1)[1]),
        digest_json(profile["hooks"]),
    )


def _planner_runtime_hook_binding(profile_path: Path) -> tuple[Path, Path, str]:
    """Bind the trusted managed hook that Codex actually executes to the profile."""

    guard_path, profile_hook_sha256 = _planner_profile_hook_binding(profile_path)
    try:
        raw = PARK_REQUIREMENTS_PATH.read_bytes()
        requirements = tomllib.loads(raw.decode("utf-8"))
        features = requirements["features"]
        hooks = requirements["hooks"]
        pretool = hooks["PreToolUse"]
        mcp_servers = requirements["mcp_servers"]
        plugins = requirements["plugins"]
        tomllib.loads(
            (profile_path.parent / "config.toml").read_text(encoding="utf-8")
        )
    except (
        OSError,
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        KeyError,
        TypeError,
        IndexError,
    ) as exc:
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT") from exc
    expected_hook = [
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"/usr/bin/python3 {guard_path}",
                    "timeout": 10,
                    "statusMessage": "Checking Planner SQLite delivery evidence",
                }
            ],
        }
    ]
    expected_features = {
        "hooks": True,
        "apps": False,
        "computer_use": False,
        "goals": False,
        "memories": False,
        "multi_agent": False,
        "plugins": False,
        "remote_plugin": False,
        "shell_snapshot": False,
        "skill_mcp_dependency_install": False,
        "workspace_dependencies": False,
    }
    if (
        set(requirements)
        != {
            "allow_managed_hooks_only",
            "allow_login_shell",
            "check_for_update_on_startup",
            "allowed_sandbox_modes",
            "allowed_approval_policies",
            "allowed_approvals_reviewers",
            "allowed_web_search_modes",
            "features",
            "mcp_servers",
            "plugins",
            "hooks",
        }
        or requirements.get("allow_managed_hooks_only") is not True
        or requirements.get("allow_login_shell") is not False
        or requirements.get("check_for_update_on_startup") is not False
        or requirements.get("allowed_sandbox_modes") != ["read-only"]
        or requirements.get("allowed_approval_policies") != ["on-request"]
        or requirements.get("allowed_approvals_reviewers") != ["auto_review"]
        or requirements.get("allowed_web_search_modes") != []
        or features != expected_features
        or mcp_servers != {}
        or plugins != {}
        or not isinstance(hooks, dict)
        or set(hooks) != {"managed_dir", "PreToolUse"}
        or hooks.get("managed_dir") != os.fspath(guard_path.parent)
        or pretool != expected_hook
        or profile_hook_sha256 != digest_json({"PreToolUse": expected_hook})
    ):
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT")
    return (
        guard_path,
        PARK_REQUIREMENTS_PATH,
        digest_json(
            {
                "profile_hook_sha256": profile_hook_sha256,
                "managed_requirements_sha256": hashlib.sha256(raw).hexdigest(),
                "effective_hooks": hooks,
            }
        ),
    )


def build_park_launch_manifest(
    *,
    binding: dict[str, Any],
    profile_path: Path,
    command: list[str],
    process_id: int,
    child_environment: dict[str, str],
    systemd_invocation_id: str,
    systemd_control_group: str,
) -> dict[str, Any]:
    """Bind every immutable runtime byte and process identity before prompt release."""

    if command[-1:] != ["-"]:
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT")
    codex_path = Path(command[0]).resolve(strict=True)
    try:
        version = subprocess.run(
            [os.fspath(codex_path), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT") from exc
    guard_path, requirements_path, hook_config_sha256 = (
        _planner_runtime_hook_binding(profile_path)
    )
    runner_path = Path(__file__).resolve()
    codex_home = Path(child_environment.get("CODEX_HOME", ""))
    if (
        not codex_home.is_absolute()
        or profile_path.parent != codex_home
        or set(child_environment)
        != set(PARK_CHILD_FIXED_ENVIRONMENT)
        | {
            "CODEX_HOME",
            "TWINFINITY_EXECUTOR_ATTEMPT_ID",
            "TWINFINITY_EXECUTOR_INSTANCE_ID",
            "TWINFINITY_EXECUTOR_ROLE",
            "TWINFINITY_ROLE_ENDPOINT",
            "TWINFINITY_EXECUTOR_TARGET_KIND",
            "TWINFINITY_EXECUTOR_TARGET_KEY",
            "TWINFINITY_EXECUTOR_PROFILE_PATH",
            "TWINFINITY_EXECUTOR_PROFILE_SHA256",
            "TWINFINITY_EXECUTOR_ENDPOINT_CONFIG_SHA256",
            PARK_CAPABILITY_SOCKET_ENV,
            "TWINFINITY_PARK_REQUEST_SHA256",
            "TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256",
        }
        or any(child_environment.get(key) != value for key, value in PARK_CHILD_FIXED_ENVIRONMENT.items())
        or "TWINFINITY_EXECUTOR_TOKEN" in child_environment
        or "TWINFINITY_COORDINATION_DATABASE" in child_environment
    ):
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT")
    config_path = codex_home / "config.toml"
    controller_path = Path(_park_controller_argv({
        **binding,
        "target_key": binding["target_key"],
        "endpoint_id": binding["endpoint_id"],
    })[1])
    runner_pid = os.getpid()
    python_path = Path(_process_executable(runner_pid))
    immutable_paths = (
        ("codex", codex_path),
        ("python", python_path),
        ("runner", runner_path),
        ("controller", controller_path),
        ("guard", guard_path),
        ("profile", profile_path),
        ("requirements", requirements_path),
        ("config", config_path),
    )
    python_source_closure = _python_source_closure(
        (runner_path, controller_path, guard_path)
    )
    codex_sha256 = _sha256_file(codex_path)
    if version != PARK_CODEX_VERSION or codex_sha256 != PARK_CODEX_SHA256:
        raise RegistryError("PARK_RUNTIME_MANIFEST_DRIFT")
    _runner_parent, runner_start = _process_identity(runner_pid)
    _codex_parent, codex_start = _process_identity(process_id)
    manifest = {
        "schema": PARK_CAPABILITY_SCHEMA,
        **binding,
        "command": _park_controller_command(),
        "controller_argv": _park_controller_argv(binding),
        "controller_cwd": "/home/ubuntu",
        "runner_pid": runner_pid,
        "runner_start_time": runner_start,
        "runner_argv": _process_argv(runner_pid),
        "codex_pid": process_id,
        "codex_start_time": codex_start,
        "codex_argv": _process_argv(process_id),
        "codex_cwd": _process_cwd(process_id),
        "codex_version": version,
        "codex_binary_sha256": codex_sha256,
        "codex_home": os.fspath(codex_home),
        "child_environment_sha256": digest_json(child_environment),
        "immutable_files": [
            {"kind": kind, "path": os.fspath(path), "sha256": _sha256_file(path)}
            for kind, path in immutable_paths
        ],
        "python_source_closure": python_source_closure,
        "python_source_closure_sha256": digest_json(python_source_closure),
        "hook_config_sha256": hook_config_sha256,
        "runner_control_group": _process_control_group(runner_pid),
        "codex_control_group": _process_control_group(process_id),
        "systemd_invocation_id": systemd_invocation_id,
        "systemd_control_group": systemd_control_group,
        "expires_monotonic": time.monotonic() + PARK_ADOPTION_WAIT_SECONDS,
        "one_use": True,
    }
    return manifest


def _prepare_park_prompt_release(
    connection: sqlite3.Connection,
    *,
    token: str,
    attempt: dict[str, Any],
    process_id: int,
    transitioner: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """Persist the final heartbeat and reserve the zero-WAL writer barrier."""

    heartbeat = transitioner(
        connection,
        attempt_id=attempt["attempt_id"],
        token=token,
        expected_version=attempt["version"],
        new_state="RUNNING",
        now=utc_now(),
        process_id=process_id,
    )
    checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if (
        checkpoint is None
        or len(checkpoint) < 3
        or tuple(int(value) for value in checkpoint[:3]) != (0, 0, 0)
    ):
        raise RegistryError("PARK_ADOPTION_CHECKPOINT_NOT_ZERO")
    database = Path(str(connection.execute("PRAGMA database_list").fetchone()[2]))
    wal = Path(os.fspath(database) + "-wal")
    if wal.exists() and wal.stat().st_size != 0:
        raise RegistryError("PARK_ADOPTION_WAL_NOT_ZERO")
    try:
        connection.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        raise RegistryError("PARK_ADOPTION_BARRIER_FAILED") from exc
    if wal.exists() and wal.stat().st_size != 0:
        connection.execute("ROLLBACK")
        raise RegistryError("PARK_ADOPTION_WAL_NOT_ZERO")
    return heartbeat


def _owned_process_group(process: subprocess.Popen[Any]) -> int | None:
    try:
        pid = int(process.pid)
        return pid if os.getpgid(pid) == pid else None
    except (OSError, TypeError, ValueError, AttributeError):
        return None


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _terminate_untracked_child(
    process: subprocess.Popen[Any],
    *,
    process_group_id: int | None = None,
    terminate_leader: bool = True,
) -> bool:
    """Terminate the exact owned session and prove no descendant survives."""

    if process_group_id is not None:
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            return False
    elif terminate_leader:
        try:
            process.terminate()
        except (OSError, AttributeError):
            pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.SubprocessError, AttributeError):
        if process_group_id is not None:
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        elif terminate_leader:
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.SubprocessError, AttributeError):
                pass
    if process_group_id is not None:
        deadline = time.monotonic() + 2.0
        while _process_group_exists(process_group_id) and time.monotonic() < deadline:
            time.sleep(0.02)
        if _process_group_exists(process_group_id):
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            deadline = time.monotonic() + 2.0
            while _process_group_exists(process_group_id) and time.monotonic() < deadline:
                time.sleep(0.02)
    try:
        if process.stdin is not None:
            process.stdin.close()
    except (OSError, ValueError, AttributeError):
        pass
    return process_group_id is None or not _process_group_exists(process_group_id)


def _validate_target(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
    allowed_topics: set[str],
) -> AttemptLineage | None:
    endpoint = current_endpoint(connection, role)
    if endpoint is None or endpoint["endpoint_id"] != endpoint_id:
        raise RegistryError("EXECUTOR_ENDPOINT_NOT_CURRENT")
    if target_kind == "message":
        try:
            message_id = int(target_key)
        except ValueError as exc:
            raise RegistryError("EXECUTOR_TARGET_INVALID") from exc
        row = connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] not in {"PREPARED", "CLAIMED"}
            or row["topic"] not in allowed_topics
            or identity_role(connection, row["recipient_session_id"]) != role
        ):
            raise RegistryError("EXECUTOR_TARGET_INVALID")
        canonical = current_endpoint(connection, role)
        if (
            row["recipient_session_id"] != endpoint_id
            and canonical is not None
            and row["recipient_session_id"] != canonical["endpoint_id"]
        ):
            alias_role = connection.execute(
                "SELECT role FROM executor_role_endpoint_aliases WHERE alias=? AND endpoint_id=?",
                (row["recipient_session_id"], endpoint_id),
            ).fetchone()
            if alias_role is None:
                raise RegistryError("EXECUTOR_TARGET_ENDPOINT_MISMATCH")
        return attempt_lineage_for_target(connection, target_kind, target_key)
    if target_kind == "terminal_watch":
        row = connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
            (target_key,),
        ).fetchone()
        if (
            row is None
            or row["state"] != "ACTIVE"
            or identity_role(connection, row["accountable_session_id"]) != role
            or row["accountable_session_id"] != endpoint_id
        ):
            raise RegistryError("EXECUTOR_TARGET_INVALID")
        admission = connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (row["admission_message_id"],),
        ).fetchone()
        try:
            admission_payload = (
                None
                if admission is None
                else json.loads(admission["payload_json"])
            )
        except (TypeError, json.JSONDecodeError):
            admission_payload = None
        admission_source = (
            admission_payload.get("source")
            if isinstance(admission_payload, dict)
            else None
        )
        expected_admission_topics = (
            {"development.admission", "development.recovery_commit"}
            if role == "development"
            else {"sre.admission"}
        )
        claim_attempt = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?",
            (row["claim_attempt_id"],),
        ).fetchone()
        packet = connection.execute(
            "SELECT 1 FROM coordination_terminal_closeout_packets "
            "WHERE terminal_watch_key=?",
            (target_key,),
        ).fetchone()
        original_endpoint = (
            None if admission is None else admission["recipient_session_id"]
        )
        rotated_proven = bool(
            original_endpoint != endpoint_id
            and (
                admission is not None
                and _historical_rotated_admission_target_valid(
                    connection,
                    message=admission,
                    message_id=int(row["admission_message_id"]),
                    role=role,
                    current_endpoint_id=endpoint_id,
                )
            )
        )
        historical_rotation_valid = bool(
            original_endpoint == endpoint_id or rotated_proven
        )
        if (
            admission is None
            or admission["topic"] not in expected_admission_topics
            or admission["topic"] not in allowed_topics
            or not isinstance(admission_payload, dict)
            or not isinstance(admission_source, dict)
            or digest_json(admission_payload) != admission["payload_sha256"]
            or admission["payload_sha256"] != row["admission_payload_sha256"]
            or admission["state"] not in {"CLAIMED", "COMPLETE"}
            or identity_role(connection, str(original_endpoint)) != role
            or admission["claimed_by"] != original_endpoint
            or not historical_rotation_valid
            or admission_source.get("repository") != row["repository"]
            or admission_source.get("object_kind") != "issue"
            or admission_source.get("object_number") != int(row["issue_number"])
            or admission_payload.get("issue_number") != int(row["issue_number"])
            or admission_payload.get("generation") != int(row["generation"])
            or admission_payload.get("accountable_session_id") != original_endpoint
            or admission_payload.get("lease_manifest_sha256")
            != row["lease_manifest_sha256"]
            or claim_attempt is None
            or claim_attempt["role"] != role
            or claim_attempt["endpoint_id"] != original_endpoint
            or claim_attempt["state"] not in (
                {"RUNNING", "COMPLETE", "HOLD"}
                if packet is not None or rotated_proven
                else {"RUNNING", "COMPLETE"}
            )
            or claim_attempt["target_kind"] != "message"
            or claim_attempt["target_key"] != str(row["admission_message_id"])
            or claim_attempt["lineage_repository"] != row["repository"]
            or int(claim_attempt["lineage_issue_number"] or -1)
            != int(row["issue_number"])
            or int(
                claim_attempt["lineage_generation"]
                if claim_attempt["lineage_generation"] is not None
                else -1
            )
            != int(row["generation"])
            or claim_attempt["lineage_lease_sha256"]
            != row["lease_manifest_sha256"]
        ):
            raise RegistryError("EXECUTOR_TARGET_INVALID")
        item = connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (row["repository"], row["issue_number"]),
        ).fetchone()
        current_source = connection.execute(
            """
            SELECT payload_sha256 FROM github_current
            WHERE repository=? AND object_kind='issue' AND object_number=?
            """,
            (row["repository"], row["issue_number"]),
        ).fetchone()
        admission = connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (row["admission_message_id"],)
        ).fetchone()
        expected_watch_key = terminal_watch_key(
            str(row["repository"]), int(row["issue_number"]), int(row["generation"])
        )
        if (
            target_key != expected_watch_key
            or item is None
            or current_source is None
            or admission is None
            or not admission_lineage_source_is_current(
                connection, item=item, message=admission, watch=row,
                current_source_sha256=str(current_source["payload_sha256"]),
            )
            or item["allocation_class"] != "ACTIVE"
            or item["status"] not in ACTIVE_EXECUTION_STATUSES
            or int(item["generation"]) != int(row["generation"])
            or item["accountable_session_id"] != endpoint_id
            or item["accountable_session_id"] != row["accountable_session_id"]
            or item["lease_manifest_sha256"] != row["lease_manifest_sha256"]
            or (role == "development" and int(item["sre_units"]) != 0)
            or (
                role == "sre"
                and (
                    int(item["development_units"]) != 0
                    or int(item["shared_units"]) != 0
                    or int(item["sre_units"]) <= 0
                )
            )
        ):
            raise RegistryError("EXECUTOR_TERMINAL_WATCH_CONTRACT_INVALID")
        return attempt_lineage_for_target(connection, target_kind, target_key)
    if target_kind == "hosted_operation":
        if role != "sre":
            raise RegistryError("EXECUTOR_TARGET_INVALID")
        try:
            operation_id = int(target_key)
        except ValueError as exc:
            raise RegistryError("EXECUTOR_TARGET_INVALID") from exc
        row = connection.execute(
            "SELECT id, recipient_session_id, state FROM hosted_operations WHERE id=?",
            (operation_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] not in {"PREPARED", "CLAIMED"}
            or identity_role(connection, row["recipient_session_id"]) != "sre"
            or row["recipient_session_id"] != endpoint_id
        ):
            raise RegistryError("EXECUTOR_TARGET_INVALID")
        return attempt_lineage_for_target(connection, target_kind, target_key)
    raise RegistryError("EXECUTOR_TARGET_INVALID")


def _historical_rotated_admission_target_valid(
    connection: sqlite3.Connection,
    *,
    message: sqlite3.Row,
    message_id: int,
    role: str,
    current_endpoint_id: str,
) -> bool:
    """Consume exact historical admission provenance after applied rotation."""

    if (
        message["state"] != "CLAIMED"
        or message["claimed_by"] != message["recipient_session_id"]
        or identity_role(connection, str(message["recipient_session_id"])) != role
        or message["topic"]
        not in (
            {"development.admission"}
            if role == "development"
            else {"sre.admission"}
        )
    ):
        return False
    try:
        payload = json.loads(message["payload_json"])
    except (TypeError, json.JSONDecodeError):
        return False
    source = payload.get("source") if isinstance(payload, dict) else None
    capacity = payload.get("capacity") if isinstance(payload, dict) else None
    if (
        not isinstance(source, dict)
        or not isinstance(capacity, dict)
        or digest_json(payload) != message["payload_sha256"]
        or payload.get("accountable_session_id")
        != message["recipient_session_id"]
        or source.get("object_kind") != "issue"
        or type(source.get("object_number")) is not int
        or payload.get("issue_number") != source.get("object_number")
        or type(payload.get("generation")) is not int
        or type(payload.get("item_version")) is not int
    ):
        return False
    repository = source.get("repository")
    issue_number = source["object_number"]
    item = connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (repository, issue_number),
    ).fetchone()
    watch_key = terminal_watch_key(repository, issue_number, payload["generation"])
    watch = connection.execute(
        "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
        (watch_key,),
    ).fetchone()
    current_source = connection.execute(
        "SELECT payload_sha256 FROM github_current "
        "WHERE repository=? AND object_kind='issue' AND object_number=?",
        (repository, issue_number),
    ).fetchone()
    claim_attempt = (
        None
        if watch is None
        else connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?",
            (watch["claim_attempt_id"],),
        ).fetchone()
    )
    if (
        item is None
        or watch is None
        or current_source is None
        or item["status"] not in ACTIVE_EXECUTION_STATUSES
        or item["allocation_class"] != "ACTIVE"
        or int(item["generation"]) != payload["generation"]
        or item["accountable_session_id"] != current_endpoint_id
        or item["lease_manifest_sha256"] != payload.get("lease_manifest_sha256")
        or item["source_payload_sha256"] != source.get("payload_sha256")
        or not admission_lineage_source_is_current(
            connection, item=item, message=message, watch=watch,
            current_source_sha256=str(current_source["payload_sha256"]),
        )
        or int(item["development_units"]) != capacity.get("development_units")
        or int(item["shared_units"]) != capacity.get("shared_units")
        or int(item["sre_units"]) != capacity.get("sre_units")
        or watch["watch_key"] != watch_key
        or watch["repository"] != repository
        or int(watch["issue_number"]) != issue_number
        or int(watch["generation"]) != payload["generation"]
        or watch["state"] != "ACTIVE"
        or watch["accountable_session_id"] != current_endpoint_id
        or watch["lease_manifest_sha256"] != payload.get("lease_manifest_sha256")
        or int(watch["admission_message_id"] or 0) != message_id
        or watch["admission_payload_sha256"] != message["payload_sha256"]
        or claim_attempt is None
        or claim_attempt["role"] != role
        or claim_attempt["endpoint_id"] != message["recipient_session_id"]
        or claim_attempt["state"] not in {"COMPLETE", "HOLD"}
        or claim_attempt["target_kind"] != "message"
        or claim_attempt["target_key"] != str(message_id)
        or claim_attempt["lineage_repository"] != repository
        or int(claim_attempt["lineage_issue_number"] or -1) != issue_number
        or int(
            claim_attempt["lineage_generation"]
            if claim_attempt["lineage_generation"] is not None
            else -1
        )
        != payload["generation"]
        or claim_attempt["lineage_lease_sha256"]
        != payload.get("lease_manifest_sha256")
    ):
        return False
    return applied_endpoint_rotation_chain(
        connection,
        repository=str(repository),
        issue_number=issue_number,
        before_identity=str(message["recipient_session_id"]),
        before_item_version=int(payload["item_version"])
        + (1 if message["topic"] == "development.recovery_commit" else 0),
        after_identity=current_endpoint_id,
        after_item_version=int(item["version"]),
        watch_key=watch_key,
        expected_watch_state="ACTIVE",
        not_before=str(claim_attempt["created_at"]),
    ) is not None


def execute_role(
    connection: sqlite3.Connection,
    *,
    config_path: Path,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
    prompt: str,
    systemd_invocation_id: str,
    systemd_evidence: SystemdUnitEvidence,
    popen: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
    transitioner: Callable[..., dict[str, Any]] = transition_attempt,
    heartbeat_seconds: int = HEARTBEAT_SECONDS,
    broker_runtime: BrokerRuntimePaths | None = None,
) -> dict[str, Any]:
    """Reserve, launch, heartbeat, and terminally record a fresh executor."""

    if role not in EXECUTION_ROLES or heartbeat_seconds <= 0:
        raise RegistryError("EXECUTOR_ROLE_INVALID")
    validate_launch_systemd_evidence(
        role=role,
        target_kind=target_kind,
        target_key=target_key,
        invocation_id=systemd_invocation_id,
        evidence=systemd_evidence,
    )
    config = load_registry_config(
        config_path, selected_current_endpoint_id=endpoint_id
    )
    configured = config.roles.get(role)
    if configured is None or configured.endpoint_id != endpoint_id:
        raise RegistryError("EXECUTOR_CONFIG_ENDPOINT_MISMATCH")
    endpoint = current_endpoint(connection, role)
    if (
        endpoint is None
        or endpoint["endpoint_id"] != endpoint_id
        or endpoint["config_sha256"] != configured.config_sha256
        or endpoint["config_json"] != canonical_json(configured.payload)
        or json.loads(endpoint["command_json"]) != list(configured.command_prefix)
    ):
        raise RegistryError("EXECUTOR_CONFIG_ENDPOINT_MISMATCH")
    park_request_binding = _planner_park_request_binding(
        connection,
        role=role,
        endpoint_id=endpoint_id,
        target_kind=target_kind,
        target_key=target_key,
        configured=configured,
    )
    with registry_config_scope(config):
        target_validator = lambda candidate: _validate_target(
            candidate,
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            allowed_topics=set(configured.allowed_topics),
        )
        if configured.execution_protocol == BROKER_PROTOCOL:
            return execute_brokered_readiness(
                connection,
                configured=configured,
                profile_path=(
                    Path(config.codex_home)
                    / f"{configured.runtime_codex_profile}.config.toml"
                ),
                target_kind=target_kind,
                target_key=target_key,
                systemd_evidence=systemd_evidence,
                target_precondition=target_validator,
                runtime=broker_runtime,
                popen=popen,
                heartbeat_seconds=heartbeat_seconds,
            )
        if configured.execution_protocol not in {None, PLANNER_PARK_PROTOCOL}:
            raise RegistryError("EXECUTOR_PROTOCOL_INVALID")
        reserved, token = reserve_attempt(
            connection,
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            now=utc_now(),
            precondition=target_validator,
        )
    park_binding: dict[str, Any] | None = None
    if park_request_binding is not None:
        park_binding = {
            **park_request_binding,
            "attempt_id": reserved["attempt_id"],
            "instance_id": reserved["instance_id"],
            "endpoint_id": endpoint_id,
            "target_kind": target_kind,
            "target_key": target_key,
        }
    command = build_endpoint_runtime_command(
        configured, "-" if park_binding is not None else prompt
    )
    child_environment_base = (
        {**PARK_CHILD_FIXED_ENVIRONMENT, "CODEX_HOME": config.codex_home}
        if park_binding is not None
        else os.environ.copy()
    )
    environment = build_child_environment(
        child_environment_base,
        attempt_id=reserved["attempt_id"],
        instance_id=reserved["instance_id"],
        role=role,
        endpoint_id=endpoint_id,
        token=token,
        target_kind=target_kind,
        target_key=target_key,
        include_token=park_binding is None,
    )
    environment.update(
        {
            "TWINFINITY_EXECUTOR_PROFILE_PATH": os.fspath(
                Path(config.codex_home)
                / f"{configured.runtime_codex_profile}.config.toml"
            ),
            "TWINFINITY_EXECUTOR_PROFILE_SHA256": configured.profile_sha256,
            "TWINFINITY_EXECUTOR_ENDPOINT_CONFIG_SHA256": configured.config_sha256,
        }
    )
    park_broker: ParkCapabilityBroker | None = None
    if park_binding is not None:
        environment.pop("TWINFINITY_COORDINATION_DATABASE", None)
    try:
        launching = transitioner(
            connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            now=utc_now(),
            systemd_unit=systemd_evidence.unit,
            systemd_invocation_id=systemd_invocation_id,
            systemd_control_group=systemd_evidence.control_group,
        )
    except Exception as exc:
        if park_broker is not None:
            park_broker.close()
        try:
            transition_attempt(
                connection,
                attempt_id=reserved["attempt_id"],
                token=token,
                expected_version=reserved["version"],
                new_state="LAUNCH_FAILED",
                now=utc_now(),
                last_error="EXECUTOR_LAUNCHING_TRANSITION_FAILED",
            )
        except Exception:
            pass
        raise RegistryError("EXECUTOR_LAUNCHING_TRANSITION_FAILED") from exc
    if park_binding is not None:
        try:
            park_broker = ParkCapabilityBroker(
                _database_parent(connection), credential=token
            )
        except (OSError, RegistryError, subprocess.SubprocessError):
            failed = transitioner(
                connection,
                attempt_id=launching["attempt_id"],
                token=token,
                expected_version=launching["version"],
                new_state="LAUNCH_FAILED",
                now=utc_now(),
                last_error="PARK_CAPABILITY_CREATE_FAILED",
            )
            return {
                "phase": "HOLD",
                "attempt_id": failed["attempt_id"],
                "state": failed["state"],
                "error": failed["last_error"],
            }
        environment[PARK_CAPABILITY_SOCKET_ENV] = os.fspath(park_broker.path)
        environment["TWINFINITY_PARK_REQUEST_SHA256"] = park_binding[
            "request_payload_sha256"
        ]
        environment["TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256"] = (
            park_binding["repository_observation_sha256"]
        )
    try:
        with registry_config_scope(config):
            process = popen(
                command,
                env=environment,
                stdin=(subprocess.PIPE if park_broker is not None else subprocess.DEVNULL),
                stdout=None,
                stderr=None,
                start_new_session=True,
                cwd=(
                    os.fspath(park_broker.codex_cwd)
                    if park_broker is not None
                    else None
                ),
            )
    except OSError:
        if park_broker is not None:
            park_broker.close()
        failed = transitioner(
            connection,
            attempt_id=launching["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="LAUNCH_FAILED",
            now=utc_now(),
            last_error="EXECUTOR_PROCESS_LAUNCH_FAILED",
        )
        return {
            "phase": "HOLD",
            "attempt_id": failed["attempt_id"],
            "state": failed["state"],
            "error": failed["last_error"],
        }
    process_group_id = _owned_process_group(process)
    if park_broker is not None and process_group_id is None:
        _terminate_untracked_child(process)
        park_broker.close()
        failed = transitioner(
            connection,
            attempt_id=launching["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="HOLD",
            now=utc_now(),
            last_error="PARK_PROCESS_GROUP_INVALID",
        )
        return {
            "phase": "HOLD",
            "attempt_id": failed["attempt_id"],
            "state": failed["state"],
            "error": failed["last_error"],
        }
    try:
        attempt = transitioner(
            connection,
            attempt_id=launching["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            now=utc_now(),
            process_id=int(process.pid),
        )
    except Exception as exc:
        _terminate_untracked_child(
            process, process_group_id=process_group_id
        )
        if park_broker is not None:
            park_broker.close()
        try:
            transition_attempt(
                connection,
                attempt_id=launching["attempt_id"],
                token=token,
                expected_version=launching["version"],
                new_state="HOLD",
                now=utc_now(),
                last_error="EXECUTOR_POST_LAUNCH_TRANSITION_FAILED",
            )
        except Exception:
            pass
        raise RegistryError("EXECUTOR_POST_LAUNCH_TRANSITION_FAILED") from exc
    park_setup_error: str | None = None
    park_deadline: float | None = None
    park_barrier_active = False
    if park_broker is not None and park_binding is not None:
        try:
            attempt = _prepare_park_prompt_release(
                connection,
                token=token,
                attempt=attempt,
                process_id=int(process.pid),
                transitioner=transitioner,
            )
            park_barrier_active = True
            manifest = build_park_launch_manifest(
                binding=park_binding,
                profile_path=Path(environment["TWINFINITY_EXECUTOR_PROFILE_PATH"]),
                command=command,
                process_id=int(process.pid),
                child_environment=environment,
                systemd_invocation_id=systemd_invocation_id,
                systemd_control_group=systemd_evidence.control_group,
            )
            park_deadline = float(manifest["expires_monotonic"])
            park_broker.arm(manifest)
            if process.stdin is None:
                raise RegistryError("PARK_PROMPT_PIPE_REQUIRED")
            park_broker.release_prompt(
                process.stdin, (prompt + "\n").encode("utf-8")
            )
        except (OSError, RegistryError, subprocess.SubprocessError) as exc:
            park_setup_error = str(exc) or "PARK_PROMPT_RELEASE_FAILED"
            if park_barrier_active:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    park_setup_error = "PARK_ADOPTION_BARRIER_RELEASE_FAILED"
                park_barrier_active = False
            refreshed_attempt = connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (attempt["attempt_id"],),
            ).fetchone()
            if refreshed_attempt is not None:
                attempt = dict(refreshed_attempt)
            _terminate_untracked_child(
                process, process_group_id=process_group_id
            )
    next_heartbeat = time.monotonic() + heartbeat_seconds
    while True:
        exit_code = process.poll()
        if exit_code is not None:
            break
        if park_broker is None:
            time.sleep(heartbeat_seconds)
            attempt = transitioner(
                connection,
                attempt_id=attempt["attempt_id"],
                token=token,
                expected_version=attempt["version"],
                new_state="RUNNING",
                now=utc_now(),
                process_id=int(process.pid),
            )
            continue
        capability = park_broker.snapshot()
        if capability["state"] == "ADOPTED" and park_barrier_active:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                park_setup_error = "PARK_ADOPTION_BARRIER_RELEASE_FAILED"
                _terminate_untracked_child(
                    process, process_group_id=process_group_id
                )
                exit_code = process.poll()
                break
            park_barrier_active = False
        if capability["state"] == "FAILED" or (
            capability["state"] != "ADOPTED"
            and park_deadline is not None
            and time.monotonic() >= park_deadline
        ):
            if park_setup_error is None:
                park_setup_error = (
                    capability["error"] or "PARK_CAPABILITY_ADOPTION_TIMEOUT"
                )
            _terminate_untracked_child(
                process, process_group_id=process_group_id
            )
            exit_code = process.poll()
            break
        if capability["state"] == "ADOPTED" and time.monotonic() >= next_heartbeat:
            try:
                attempt = transitioner(
                    connection,
                    attempt_id=attempt["attempt_id"],
                    token=token,
                    expected_version=attempt["version"],
                    new_state="RUNNING",
                    now=utc_now(),
                    process_id=int(process.pid),
                )
            except Exception:
                park_setup_error = "PARK_POST_ADOPTION_HEARTBEAT_FAILED"
                _terminate_untracked_child(
                    process, process_group_id=process_group_id
                )
                exit_code = process.poll()
                break
            next_heartbeat = time.monotonic() + heartbeat_seconds
        # ARMED, PROMPT_RELEASED, INNER_SEEN, and CONSUMED deliberately suppress
        # every later
        # heartbeat until the exact controller acknowledges its read phase.
        time.sleep(min(0.05, max(0.01, heartbeat_seconds / 10)))
    if park_barrier_active:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            park_setup_error = "PARK_ADOPTION_BARRIER_RELEASE_FAILED"
        park_barrier_active = False
    if park_broker is not None and not _terminate_untracked_child(
        process,
        process_group_id=process_group_id,
        terminate_leader=False,
    ):
        park_setup_error = park_setup_error or "PARK_PROCESS_GROUP_NOT_QUIESCENT"
    if exit_code is None:
        exit_code = process.poll()
    if exit_code is None:
        exit_code = -int(signal.SIGKILL)
    park_adoption: dict[str, Any] | None = None
    if park_broker is not None:
        capability = park_broker.snapshot()
        park_adoption = {
            "state": capability["state"],
            "events": capability["events"],
            "manifest_sha256": capability["manifest_sha256"],
            "evidence_sha256": digest_json(capability),
        }
    try:
        terminal_progress_sha256 = target_progress_digest(
            connection, target_kind, target_key
        )
    except (RegistryError, sqlite3.Error):
        terminal_progress_sha256 = None
    if park_setup_error is not None:
        state = "HOLD"
        terminal_error = park_setup_error
    elif park_adoption is not None and park_adoption["state"] != "ADOPTED":
        state = "HOLD"
        terminal_error = park_setup_error or "PARK_ADOPTION_INCOMPLETE"
    elif exit_code != 0:
        state = "HOLD"
        terminal_error = "EXECUTOR_PROCESS_FAILED"
    elif terminal_progress_sha256 is None or reserved["target_progress_sha256"] is None:
        state = "HOLD"
        terminal_error = "EXECUTOR_TARGET_READBACK_FAILED"
    elif terminal_progress_sha256 == reserved["target_progress_sha256"]:
        state = "HOLD"
        terminal_error = "EXECUTOR_TARGET_NO_PROGRESS"
    else:
        state = "COMPLETE"
        terminal_error = None
    terminal = transitioner(
        connection,
        attempt_id=attempt["attempt_id"],
        token=token,
        expected_version=attempt["version"],
        new_state=state,
        now=utc_now(),
        exit_code=int(exit_code),
        last_error=terminal_error,
        terminal_progress_sha256=terminal_progress_sha256,
    )
    result = {
        "phase": "PASS" if state == "COMPLETE" else "HOLD",
        "attempt_id": terminal["attempt_id"],
        "instance_id": terminal["instance_id"],
        "role": terminal["role"],
        "endpoint_id": terminal["endpoint_id"],
        "target_kind": terminal["target_kind"],
        "target_key": terminal["target_key"],
        "state": terminal["state"],
        "exit_code": terminal["exit_code"],
        "target_progress_sha256": terminal["target_progress_sha256"],
        "terminal_progress_sha256": terminal["terminal_progress_sha256"],
        "error": terminal["last_error"],
        "token_persisted": False,
    }
    if park_adoption is not None:
        result["park_adoption"] = park_adoption
    if park_broker is not None:
        park_broker.close()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--role", required=True, choices=sorted(EXECUTION_ROLES))
    parser.add_argument("--endpoint-id", required=True)
    parser.add_argument("--systemd-unit", required=True)
    parser.add_argument(
        "--target-kind",
        required=True,
        choices=("message", "terminal_watch", "hosted_operation"),
    )
    parser.add_argument("--target-key", required=True)
    parser.add_argument("--prompt", required=True)
    args = parser.parse_args()
    connection: sqlite3.Connection | None = None
    try:
        connection = open_registry_database(DEFAULT_DATABASE)
        expected_unit = stable_systemd_unit(
            args.role, args.target_kind, args.target_key
        )
        invocation_id = os.environ.get("INVOCATION_ID", "")
        if args.systemd_unit != expected_unit:
            raise RegistryError("SYSTEMD_LAUNCH_IDENTITY_INVALID")
        evidence = probe_systemd_unit(expected_unit)
        result = execute_role(
            connection,
            config_path=args.config,
            role=args.role,
            endpoint_id=args.endpoint_id,
            target_kind=args.target_kind,
            target_key=args.target_key,
            prompt=args.prompt,
            systemd_invocation_id=invocation_id,
            systemd_evidence=evidence,
        )
        print(canonical_json(result))
        return 0 if result["phase"] == "PASS" else 1
    except BrokerError as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    except (OSError, RegistryError, sqlite3.Error):
        print(canonical_json({"phase": "HOLD", "error": "ROLE_EXECUTOR_FAILED"}))
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
