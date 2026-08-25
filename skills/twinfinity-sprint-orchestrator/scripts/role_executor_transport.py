#!/usr/bin/env python3
"""Construct and launch one fresh, transient role-executor service."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Callable

from executor_registry import (
    DEFAULT_CONFIG,
    ENDPOINT_ID,
    ROLES,
    RegistryError,
    stable_systemd_unit,
)


RUNNER = Path(__file__).resolve().parent / "run_role_executor.py"


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
        *role_executor_command(
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            prompt=prompt,
        ),
    ]
    completed = runner(
        command,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return int(getattr(completed, "returncode", 1))
