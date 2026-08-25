#!/usr/bin/env python3
"""Launch one fresh role executor from an atomically reserved attempt."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from typing import Any, Callable

from executor_registry import (
    AttemptLineage,
    DEFAULT_CONFIG,
    DEFAULT_DATABASE,
    EXECUTION_ROLES,
    RegistryError,
    SystemdUnitEvidence,
    UUID,
    attempt_lineage_for_target,
    canonical_json,
    current_endpoint,
    digest_json,
    identity_role,
    load_registry_config,
    open_registry_database,
    probe_systemd_unit,
    reserve_attempt,
    stable_systemd_unit,
    target_progress_digest,
    transition_attempt,
    utc_now,
    validate_launch_systemd_evidence,
)


HEARTBEAT_SECONDS = 30


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
    ):
        raise RegistryError("EXECUTOR_CHILD_ENVIRONMENT_INVALID")
    environment = dict(base)
    environment.update({
        "TWINFINITY_EXECUTOR_ATTEMPT_ID": attempt_id,
        "TWINFINITY_EXECUTOR_INSTANCE_ID": instance_id,
        "TWINFINITY_EXECUTOR_ROLE": role,
        "TWINFINITY_ROLE_ENDPOINT": endpoint_id,
        "TWINFINITY_EXECUTOR_TOKEN": token,
        "TWINFINITY_EXECUTOR_TARGET_KIND": target_kind,
        "TWINFINITY_EXECUTOR_TARGET_KEY": target_key,
    })
    return environment


def _terminate_untracked_child(process: subprocess.Popen[Any]) -> None:
    """Ensure a child cannot continue after its RUNNING CAS failed."""

    try:
        process.terminate()
        process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError, AttributeError):
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError, AttributeError):
            pass


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
            "SELECT recipient_session_id, topic, state FROM coordination_messages WHERE id=?",
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
            "SELECT accountable_session_id, state FROM coordination_terminal_watches WHERE watch_key=?",
            (target_key,),
        ).fetchone()
        if (
            row is None
            or row["state"] != "ACTIVE"
            or identity_role(connection, row["accountable_session_id"]) != role
            or row["accountable_session_id"] != endpoint_id
        ):
            raise RegistryError("EXECUTOR_TARGET_INVALID")
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
    config = load_registry_config(config_path)
    configured = config.endpoints.get(endpoint_id)
    if configured is None or configured.role != role:
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
    target_validator = lambda candidate: _validate_target(
        candidate,
        role=role,
        endpoint_id=endpoint_id,
        target_kind=target_kind,
        target_key=target_key,
        allowed_topics=set(configured.allowed_topics),
    )
    reserved, token = reserve_attempt(
        connection,
        role=role,
        endpoint_id=endpoint_id,
        target_kind=target_kind,
        target_key=target_key,
        now=utc_now(),
        precondition=target_validator,
    )
    command = build_endpoint_runtime_command(configured, prompt)
    environment = build_child_environment(
        os.environ.copy(),
        attempt_id=reserved["attempt_id"],
        instance_id=reserved["instance_id"],
        role=role,
        endpoint_id=endpoint_id,
        token=token,
        target_kind=target_kind,
        target_key=target_key,
    )
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
    try:
        process = popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None,
            start_new_session=True,
        )
    except OSError:
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
        _terminate_untracked_child(process)
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
    while True:
        exit_code = process.poll()
        if exit_code is not None:
            break
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
    try:
        terminal_progress_sha256 = target_progress_digest(
            connection, target_kind, target_key
        )
    except (RegistryError, sqlite3.Error):
        terminal_progress_sha256 = None
    if exit_code != 0:
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
    return {
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
    except (OSError, RegistryError, sqlite3.Error):
        print(canonical_json({"phase": "HOLD", "error": "ROLE_EXECUTOR_FAILED"}))
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
