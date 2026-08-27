#!/usr/bin/env python3
"""Construct and launch one fresh, transient role-executor service."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Callable

from executor_registry import (
    BROKERED_READINESS_PROTOCOL,
    DEFAULT_CONFIG,
    DEFAULT_PROFILE_TEMPLATE_ROOT,
    ENDPOINT_ID,
    ROLES,
    RegistryError,
    load_registry_config,
    stable_systemd_unit,
)


RUNNER = Path(__file__).resolve().parent / "run_role_executor.py"
BROKER_SYSTEMD_MEMORY_MAX_BYTES = 2 * 1024 * 1024 * 1024
BROKER_SYSTEMD_TASKS_MAX = 64
BROKER_SYSTEMD_RUNTIME_MAX_SECONDS = 660
BROKER_SYSTEMD_CPU_QUOTA_PERCENT = 100
SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS = 5


def broker_systemd_properties(endpoint_id: str) -> tuple[str, ...]:
    """Return exact attempt-wide cgroup limits for a reviewed broker endpoint."""

    config = load_registry_config(
        DEFAULT_CONFIG,
        codex_home=DEFAULT_PROFILE_TEMPLATE_ROOT,
        profile_template_root=DEFAULT_PROFILE_TEMPLATE_ROOT,
    )
    configured = config.endpoints.get(endpoint_id)
    if configured is None:
        # The inner runner remains the catalog-authority boundary. Historical
        # test/migration identities receive no broker-only resource contract
        # here and will still fail closed unless the runner catalog admits them.
        return ()
    if configured.execution_protocol is None:
        return ()
    if configured.execution_protocol != BROKERED_READINESS_PROTOCOL:
        raise RegistryError("ROLE_EXECUTOR_TRANSPORT_PROTOCOL_INVALID")
    return (
        f"--property=MemoryMax={BROKER_SYSTEMD_MEMORY_MAX_BYTES}",
        f"--property=TasksMax={BROKER_SYSTEMD_TASKS_MAX}",
        f"--property=RuntimeMaxSec={BROKER_SYSTEMD_RUNTIME_MAX_SECONDS}s",
        f"--property=CPUQuota={BROKER_SYSTEMD_CPU_QUOTA_PERCENT}%",
    )


def role_executor_command(
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
    prompt: str,
) -> list[str]:
    if (
        role not in ROLES
        or ENDPOINT_ID.fullmatch(endpoint_id) is None
        or endpoint_id.split(".")[1] != role
        or not target_key
        or not prompt
    ):
        raise RegistryError("ROLE_EXECUTOR_TRANSPORT_INVALID")
    return [
        "/usr/bin/python3",
        str(RUNNER),
        "--config",
        str(DEFAULT_CONFIG),
        "--role",
        role,
        "--endpoint-id",
        endpoint_id,
        "--systemd-unit",
        stable_systemd_unit(role, target_kind, target_key),
        "--target-kind",
        target_kind,
        "--target-key",
        target_key,
        "--prompt",
        prompt,
    ]


def launch_role_executor(
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
    prompt: str,
    working_directory: Path | None = None,
    runner: Callable[..., object] = subprocess.run,
) -> int:
    resolved_working_directory = (working_directory or Path.cwd()).resolve()
    if not resolved_working_directory.is_dir():
        raise RegistryError("ROLE_EXECUTOR_WORKING_DIRECTORY_INVALID")
    command = [
        "/usr/bin/systemd-run",
        "--user",
        "--quiet",
        f"--unit={stable_systemd_unit(role, target_kind, target_key)}",
        f"--working-directory={resolved_working_directory}",
        *broker_systemd_properties(endpoint_id),
        *role_executor_command(
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            prompt=prompt,
        ),
    ]
    try:
        completed = runner(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return 1
    return int(getattr(completed, "returncode", 1))
