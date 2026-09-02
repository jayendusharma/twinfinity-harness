#!/usr/bin/env python3
"""Construct and launch one fresh, transient role-executor service."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import time
from typing import Any, Callable

from executor_registry import (
    BROKERED_READINESS_PROTOCOL,
    DEFAULT_CONFIG,
    DEFAULT_PROFILE_TEMPLATE_ROOT,
    ENDPOINT_ID,
    ROLES,
    RegistryError,
    SYSTEMD_INVOCATION_ID,
    SYSTEMD_UNIT,
    canonical_json,
    digest_json,
    load_registry_config,
    stable_systemd_unit,
)


RUNNER = Path(__file__).resolve().parent / "run_role_executor.py"
BROKER_SYSTEMD_MEMORY_MAX_BYTES = 2 * 1024 * 1024 * 1024
BROKER_SYSTEMD_TASKS_MAX = 64
BROKER_SYSTEMD_RUNTIME_MAX_SECONDS = 660
BROKER_SYSTEMD_CPU_QUOTA_PERCENT = 100
SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS = 5
ROLE_EXECUTOR_MANAGER_SUBMISSION_MAXIMUM_RESPONSE_BYTES = 512
ROLE_EXECUTOR_MANAGER_REAP_TIMEOUT_SECONDS = 1
ROLE_EXECUTOR_TRANSPORT_PREFLIGHT_TIMEOUT_SECONDS = 5
TRANSPORT_PREFLIGHT_SOURCE_REPOSITORY = "jayendusharma/twinfinity-harness"
TRANSPORT_PREFLIGHT_SOURCE_ISSUE_NUMBER = 149
TRANSPORT_PREFLIGHT_SOURCE_BODY_SHA256 = (
    "11b5f6cb7dad020e1194d6989cfa57b058e83f189131d4d39d18372f428d2dab"
)
ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE = "ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE"
ROLE_EXECUTOR_TRANSPORT_TIMED_OUT = "ROLE_EXECUTOR_TRANSPORT_TIMED_OUT"
ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS = "ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS"
ROLE_EXECUTOR_TRANSPORT_MALFORMED = "ROLE_EXECUTOR_TRANSPORT_MALFORMED"
ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED = "ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED"
ROLE_EXECUTOR_TRANSPORT_FAILURES = frozenset(
    {
        ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE,
        ROLE_EXECUTOR_TRANSPORT_TIMED_OUT,
        ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS,
        ROLE_EXECUTOR_TRANSPORT_MALFORMED,
        ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED,
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MANAGER_SUBMISSION_RESPONSE = re.compile(
    r"\ARunning as unit: "
    r"(?P<systemd_unit>[A-Za-z0-9_.@:-]{1,255}\.service); "
    r"invocation ID: (?P<systemd_invocation_id>[0-9a-f]{32})\n\Z"
)
_SYSTEMCTL_MANAGER_PROPERTIES = (
    "Architecture",
    "ControlGroup",
    "SystemState",
    "UserspaceTimestampMonotonic",
    "Version",
)
_SYSTEMCTL_MANAGER_COMMAND = (
    "/usr/bin/systemctl",
    "--user",
    "show",
    "--no-pager",
    *tuple(f"--property={name}" for name in _SYSTEMCTL_MANAGER_PROPERTIES),
)
_SYSTEMD_RUN_PREFIX = ("/usr/bin/systemd-run", "--user", "--quiet")
_SYSTEMD_RUN_DIRECT_SUBMISSION_PREFIX = ("/usr/bin/systemd-run", "--user")
_ROLE_EXECUTOR_RUNNER_PREFIX = (
    "/usr/bin/python3",
    str(RUNNER),
    "--config",
    str(DEFAULT_CONFIG),
)
_TRANSPORT_CLIENT_ENVIRONMENT_POLICY = {
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/{effective_uid}/bus",
    "HOME": "passwd-home-for-{effective_uid}",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "XDG_RUNTIME_DIR": "/run/user/{effective_uid}",
}
_TRANSPORT_PROBE_CONTRACT = {
    "schema": "twinfinity-role-executor-transport-probe/v1",
    "manager_command": list(_SYSTEMCTL_MANAGER_COMMAND),
    "manager_properties": list(_SYSTEMCTL_MANAGER_PROPERTIES),
    "timeout_seconds": ROLE_EXECUTOR_TRANSPORT_PREFLIGHT_TIMEOUT_SECONDS,
    "response_encoding": "utf-8",
    "maximum_response_bytes": 8192,
    "client_environment": _TRANSPORT_CLIENT_ENVIRONMENT_POLICY,
}
ROLE_EXECUTOR_TRANSPORT_PROBE_CONTRACT_SHA256 = digest_json(
    _TRANSPORT_PROBE_CONTRACT
)
_MANAGER_SUBMISSION_CONTRACT = {
    "schema": "twinfinity-role-executor-manager-submission-contract/v1",
    "manager_command_prefix": list(_SYSTEMD_RUN_DIRECT_SUBMISSION_PREFIX),
    "timeout_seconds": SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS,
    "reap_timeout_seconds": ROLE_EXECUTOR_MANAGER_REAP_TIMEOUT_SECONDS,
    "response_encoding": "utf-8",
    "response_channels": "exactly_one_of_stdout_or_stderr",
    "response_format": (
        "Running as unit: <systemd_unit>; invocation ID: "
        "<systemd_invocation_id>\\n"
    ),
    "maximum_combined_response_bytes": (
        ROLE_EXECUTOR_MANAGER_SUBMISSION_MAXIMUM_RESPONSE_BYTES
    ),
}
ROLE_EXECUTOR_MANAGER_SUBMISSION_CONTRACT_SHA256 = digest_json(
    _MANAGER_SUBMISSION_CONTRACT
)
_TRANSPORT_CONFIGURATION = {
    "schema": "twinfinity-role-executor-transport-configuration/v1",
    "manager_probe_sha256": ROLE_EXECUTOR_TRANSPORT_PROBE_CONTRACT_SHA256,
    "manager_submission_sha256": (
        ROLE_EXECUTOR_MANAGER_SUBMISSION_CONTRACT_SHA256
    ),
    "systemd_run_prefix": list(_SYSTEMD_RUN_PREFIX),
    "runner_prefix": list(_ROLE_EXECUTOR_RUNNER_PREFIX),
    "client_environment": _TRANSPORT_CLIENT_ENVIRONMENT_POLICY,
    "submission_timeout_seconds": SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS,
}
ROLE_EXECUTOR_TRANSPORT_CONFIGURATION_SHA256 = digest_json(
    _TRANSPORT_CONFIGURATION
)


@dataclass(frozen=True)
class RoleExecutorManagerSubmission:
    """Closed manager receipt for one exact transient-unit submission."""

    systemd_unit: str
    systemd_invocation_id: str

    def __post_init__(self) -> None:
        if (
            type(self.systemd_unit) is not str
            or SYSTEMD_UNIT.fullmatch(self.systemd_unit) is None
            or type(self.systemd_invocation_id) is not str
            or SYSTEMD_INVOCATION_ID.fullmatch(self.systemd_invocation_id) is None
        ):
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)

    @property
    def payload(self) -> dict[str, str]:
        return {
            "schema": "twinfinity-role-executor-manager-submission/v1",
            "systemd_invocation_id": self.systemd_invocation_id,
            "systemd_unit": self.systemd_unit,
        }

    @property
    def receipt_sha256(self) -> str:
        return digest_json(self.payload)


class RoleExecutorManagerNotSubmitted(RegistryError):
    """Positive proof that process creation failed before manager submission."""

    def __init__(self) -> None:
        super().__init__(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE)


class _ManagerSubmissionOutputOverflow(Exception):
    """Value-free internal signal for aggregate manager output overflow."""


@dataclass(frozen=True)
class EndpointTransportIdentity:
    """Privacy-safe immutable identity for one current endpoint row."""

    role: str
    endpoint_id: str
    pointer_version: int
    endpoint_config_sha256: str
    endpoint_config_json_sha256: str
    profile_sha256: str
    registered_launch_sha256: str

    @property
    def payload(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RoleExecutorTransportPreflight:
    """Closed source/current-endpoint identity presented to one fresh probe."""

    schema: str
    source_repository: str
    source_issue_number: int
    source_body_sha256: str
    registry_source_sha256: str
    runner_source_sha256: str
    transport_configuration_sha256: str
    probe_contract_sha256: str
    owner_identity_sha256: str
    endpoint_identities: tuple[EndpointTransportIdentity, ...]

    @property
    def payload(self) -> dict[str, object]:
        value = asdict(self)
        value["endpoint_identities"] = [
            identity.payload for identity in self.endpoint_identities
        ]
        return value

    @property
    def request_sha256(self) -> str:
        return digest_json(self.payload)

    @property
    def endpoint_identity_sha256(self) -> str:
        return digest_json(
            [identity.payload for identity in self.endpoint_identities]
        )

    @property
    def profile_identity_sha256(self) -> str:
        return digest_json(
            [
                {
                    "role": identity.role,
                    "endpoint_id": identity.endpoint_id,
                    "profile_sha256": identity.profile_sha256,
                }
                for identity in self.endpoint_identities
            ]
        )

    @property
    def registered_launch_sha256(self) -> str:
        return digest_json(
            [
                {
                    "role": identity.role,
                    "endpoint_id": identity.endpoint_id,
                    "registered_launch_sha256": identity.registered_launch_sha256,
                }
                for identity in self.endpoint_identities
            ]
        )


@dataclass(frozen=True)
class RoleExecutorTransportAttestation:
    """Complete privacy-safe result of one fresh read-only transport probe."""

    schema: str
    status: str
    request_sha256: str
    probe_contract_sha256: str
    owner_identity_sha256: str
    user_manager_identity_sha256: str
    evidence_sha256: str

    @classmethod
    def pass_for(
        cls,
        preflight: RoleExecutorTransportPreflight,
        *,
        user_manager_identity_sha256: str,
    ) -> "RoleExecutorTransportAttestation":
        evidence = {
            "schema": "twinfinity-role-executor-transport-attestation/v1",
            "status": "PASS",
            "request_sha256": preflight.request_sha256,
            "probe_contract_sha256": preflight.probe_contract_sha256,
            "owner_identity_sha256": preflight.owner_identity_sha256,
            "user_manager_identity_sha256": user_manager_identity_sha256,
        }
        return cls(**evidence, evidence_sha256=digest_json(evidence))


@dataclass(frozen=True)
class RoleExecutorUserBusContext:
    """Private filesystem-bound identity for the current user's live bus."""

    effective_uid: int
    home: str
    runtime_directory: str
    runtime_identity: tuple[int, ...]
    bus_identity: tuple[int, ...]

    @property
    def environment(self) -> dict[str, str]:
        return _manager_environment(
            self.effective_uid,
            home=self.home,
            runtime_directory=self.runtime_directory,
        )

    @property
    def identity_sha256(self) -> str:
        return digest_json(
            {
                "schema": "twinfinity-role-executor-user-bus/v1",
                "effective_uid": self.effective_uid,
                "runtime_identity": list(self.runtime_identity),
                "bus_identity": list(self.bus_identity),
            }
        )


def _owner_identity(effective_uid: int) -> tuple[str, str]:
    if type(effective_uid) is not int or effective_uid < 0:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    control_group = (
        f"/user.slice/user-{effective_uid}.slice/user@{effective_uid}.service"
    )
    return control_group, digest_json(
        {
            "schema": "twinfinity-role-executor-owner-identity/v1",
            "effective_uid": effective_uid,
            "user_manager_control_group": control_group,
        }
    )


def _endpoint_transport_identity(
    role: str, row: Any
) -> EndpointTransportIdentity:
    try:
        endpoint_id = row["endpoint_id"]
        row_role = row["role"]
        pointer_version = row["pointer_version"]
        endpoint_config_sha256 = row["config_sha256"]
        config_json = row["config_json"]
        command_json = row["command_json"]
    except (KeyError, TypeError, IndexError) as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED) from exc
    if (
        row_role != role
        or type(endpoint_id) is not str
        or ENDPOINT_ID.fullmatch(endpoint_id) is None
        or endpoint_id.split(".")[1] != role
        or type(pointer_version) is not int
        or pointer_version <= 0
        or type(endpoint_config_sha256) is not str
        or _SHA256.fullmatch(endpoint_config_sha256) is None
        or type(config_json) is not str
        or type(command_json) is not str
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    try:
        config_payload = json.loads(config_json)
        registered_launch = json.loads(command_json)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED) from exc
    profile_sha256 = (
        config_payload.get("profile_sha256")
        if type(config_payload) is dict
        else None
    )
    if (
        type(config_payload) is not dict
        or type(profile_sha256) is not str
        or _SHA256.fullmatch(profile_sha256) is None
        or type(registered_launch) is not list
        or not registered_launch
        or any(type(item) is not str or not item for item in registered_launch)
        or config_payload.get("role") != role
        or config_payload.get("endpoint_id") != endpoint_id
        or config_payload.get("command_prefix") != registered_launch
        or config_json != canonical_json(config_payload)
        or digest_json(config_payload) != endpoint_config_sha256
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    return EndpointTransportIdentity(
        role=role,
        endpoint_id=endpoint_id,
        pointer_version=pointer_version,
        endpoint_config_sha256=endpoint_config_sha256,
        endpoint_config_json_sha256=hashlib.sha256(
            config_json.encode("utf-8")
        ).hexdigest(),
        profile_sha256=profile_sha256,
        registered_launch_sha256=digest_json(registered_launch),
    )


def build_role_executor_transport_preflight(
    connection: Any,
    *,
    effective_uid: int | None = None,
) -> RoleExecutorTransportPreflight:
    """Build one complete read-only request from the exact current pointer set."""

    uid = os.geteuid() if effective_uid is None else effective_uid
    _control_group, owner_identity_sha256 = _owner_identity(uid)
    identities: list[EndpointTransportIdentity] = []
    try:
        rows = connection.execute(
            """
            SELECT endpoint.*, current.pointer_version,
                   current.updated_at AS pointer_updated_at
            FROM executor_role_endpoint_current current
            JOIN executor_role_endpoints endpoint
              ON endpoint.endpoint_id=current.endpoint_id
            ORDER BY current.role
            """
        ).fetchall()
        if tuple(str(row["role"]) for row in rows) != tuple(sorted(ROLES)):
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
        for row in rows:
            identities.append(
                _endpoint_transport_identity(str(row["role"]), row)
            )
        registry_bytes = DEFAULT_CONFIG.read_bytes()
        runner_bytes = RUNNER.read_bytes()
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE) from exc
    return RoleExecutorTransportPreflight(
        schema="twinfinity-role-executor-transport-preflight/v1",
        source_repository=TRANSPORT_PREFLIGHT_SOURCE_REPOSITORY,
        source_issue_number=TRANSPORT_PREFLIGHT_SOURCE_ISSUE_NUMBER,
        source_body_sha256=TRANSPORT_PREFLIGHT_SOURCE_BODY_SHA256,
        registry_source_sha256=hashlib.sha256(registry_bytes).hexdigest(),
        runner_source_sha256=hashlib.sha256(runner_bytes).hexdigest(),
        transport_configuration_sha256=(
            ROLE_EXECUTOR_TRANSPORT_CONFIGURATION_SHA256
        ),
        probe_contract_sha256=ROLE_EXECUTOR_TRANSPORT_PROBE_CONTRACT_SHA256,
        owner_identity_sha256=owner_identity_sha256,
        endpoint_identities=tuple(identities),
    )


def _validate_endpoint_transport_identity(
    preflight: RoleExecutorTransportPreflight,
    identity: EndpointTransportIdentity,
    *,
    config_loader: Callable[..., Any],
) -> None:
    try:
        config = config_loader(
            DEFAULT_CONFIG, selected_current_endpoint_id=identity.endpoint_id
        )
        configured = config.roles.get(identity.role)
        if configured is None:
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
        configured_payload = configured.payload
        configured_launch = tuple(configured.command_prefix)
    except Exception as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED) from exc
    if (
        config.source_sha256 != preflight.registry_source_sha256
        or configured.role != identity.role
        or configured.endpoint_id != identity.endpoint_id
        or configured.config_sha256 != identity.endpoint_config_sha256
        or hashlib.sha256(
            canonical_json(configured_payload).encode("utf-8")
        ).hexdigest()
        != identity.endpoint_config_json_sha256
        or configured.profile_sha256 != identity.profile_sha256
        or digest_json(list(configured_launch))
        != identity.registered_launch_sha256
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)


def _validate_preflight_contract(
    preflight: RoleExecutorTransportPreflight,
    *,
    config_loader: Callable[..., Any],
    effective_uid: int,
) -> str:
    if type(preflight) is not RoleExecutorTransportPreflight:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    digest_fields = (
        preflight.source_body_sha256,
        preflight.registry_source_sha256,
        preflight.runner_source_sha256,
        preflight.transport_configuration_sha256,
        preflight.probe_contract_sha256,
        preflight.owner_identity_sha256,
    )
    if (
        type(preflight.schema) is not str
        or type(preflight.source_repository) is not str
        or type(preflight.source_issue_number) is not int
        or any(type(value) is not str for value in digest_fields)
        or any(_SHA256.fullmatch(value) is None for value in digest_fields)
        or type(preflight.endpoint_identities) is not tuple
        or any(
            type(identity) is not EndpointTransportIdentity
            for identity in preflight.endpoint_identities
        )
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    expected_control_group, owner_identity_sha256 = _owner_identity(effective_uid)
    try:
        runner_source_sha256 = hashlib.sha256(RUNNER.read_bytes()).hexdigest()
    except OSError as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE) from exc
    if (
        preflight.schema != "twinfinity-role-executor-transport-preflight/v1"
        or preflight.source_repository != TRANSPORT_PREFLIGHT_SOURCE_REPOSITORY
        or preflight.source_issue_number
        != TRANSPORT_PREFLIGHT_SOURCE_ISSUE_NUMBER
        or preflight.source_body_sha256
        != TRANSPORT_PREFLIGHT_SOURCE_BODY_SHA256
        or preflight.runner_source_sha256 != runner_source_sha256
        or preflight.transport_configuration_sha256
        != ROLE_EXECUTOR_TRANSPORT_CONFIGURATION_SHA256
        or preflight.probe_contract_sha256
        != ROLE_EXECUTOR_TRANSPORT_PROBE_CONTRACT_SHA256
        or preflight.owner_identity_sha256 != owner_identity_sha256
        or tuple(identity.role for identity in preflight.endpoint_identities)
        != tuple(sorted(ROLES))
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    for identity in preflight.endpoint_identities:
        _validate_endpoint_transport_identity(
            preflight, identity, config_loader=config_loader
        )
    return expected_control_group


def _manager_environment(
    effective_uid: int,
    *,
    home: str | None = None,
    runtime_directory: str | None = None,
) -> dict[str, str]:
    if type(effective_uid) is not int or effective_uid < 0:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if home is None:
        try:
            home = pwd.getpwuid(effective_uid).pw_dir
        except (KeyError, OSError) as exc:
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED) from exc
    if type(home) is not str or not home.startswith("/") or "\0" in home:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    runtime_directory = (
        f"/run/user/{effective_uid}"
        if runtime_directory is None
        else runtime_directory
    )
    if (
        type(runtime_directory) is not str
        or not runtime_directory.startswith("/")
        or "\0" in runtime_directory
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    return {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_directory}/bus",
        "HOME": home,
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": runtime_directory,
    }


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if stat.S_ISLNK(current.lstat().st_mode):
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)


def role_executor_user_bus_context(
    effective_uid: int,
    *,
    runtime_root: Path = Path("/run/user"),
) -> RoleExecutorUserBusContext:
    """Bind the derived user bus to safe owner-only filesystem identities."""

    if type(effective_uid) is not int or effective_uid < 0:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    runtime_directory = runtime_root / str(effective_uid)
    bus = runtime_directory / "bus"
    try:
        _reject_symlink_components(runtime_directory)
        runtime_metadata = runtime_directory.lstat()
        _reject_symlink_components(bus)
        bus_metadata = bus.lstat()
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE) from exc
    runtime_mode = stat.S_IMODE(runtime_metadata.st_mode)
    if (
        not stat.S_ISDIR(runtime_metadata.st_mode)
        or runtime_metadata.st_uid != effective_uid
        or runtime_mode != 0o700
        or not stat.S_ISSOCK(bus_metadata.st_mode)
        or bus_metadata.st_uid != effective_uid
        or bus_metadata.st_nlink != 1
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    try:
        home = pwd.getpwuid(effective_uid).pw_dir
    except (KeyError, OSError) as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED) from exc
    _manager_environment(effective_uid, home=home)
    return RoleExecutorUserBusContext(
        effective_uid=effective_uid,
        home=home,
        runtime_directory=str(runtime_directory),
        runtime_identity=(
            runtime_metadata.st_dev,
            runtime_metadata.st_ino,
            runtime_metadata.st_mode,
            runtime_metadata.st_uid,
            runtime_metadata.st_nlink,
        ),
        bus_identity=(
            bus_metadata.st_dev,
            bus_metadata.st_ino,
            bus_metadata.st_mode,
            bus_metadata.st_uid,
            bus_metadata.st_nlink,
        ),
    )


def _parse_manager_response(raw: object, expected_control_group: str) -> dict[str, str]:
    if type(raw) is not bytes or not raw or len(raw) > 8192 or b"\0" in raw:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED) from exc
    if not text.endswith("\n"):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    properties: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if not separator or not name or not value:
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
        if name in properties or name not in _SYSTEMCTL_MANAGER_PROPERTIES:
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS)
        properties[name] = value
    if set(properties) != set(_SYSTEMCTL_MANAGER_PROPERTIES):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if properties["ControlGroup"] != expected_control_group:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    if properties["SystemState"] not in {"running", "degraded"}:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE)
    if (
        re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", properties["Architecture"])
        is None
        or re.fullmatch(r"[ -~]{1,128}", properties["Version"]) is None
        or not properties["UserspaceTimestampMonotonic"].isdigit()
        or int(properties["UserspaceTimestampMonotonic"]) <= 0
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    return properties


def attest_role_executor_transport(
    preflight: RoleExecutorTransportPreflight,
    *,
    runner: Callable[..., object] = subprocess.run,
    config_loader: Callable[..., Any] = load_registry_config,
    euid_reader: Callable[[], int] = os.geteuid,
    user_bus_reader: Callable[[int], RoleExecutorUserBusContext] = (
        role_executor_user_bus_context
    ),
) -> RoleExecutorTransportAttestation:
    """Perform one bounded current-user-manager read without creating a unit."""

    try:
        effective_uid = euid_reader()
    except Exception as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED) from exc
    expected_control_group = _validate_preflight_contract(
        preflight,
        config_loader=config_loader,
        effective_uid=effective_uid,
    )
    try:
        user_bus = user_bus_reader(effective_uid)
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE) from exc
    except Exception as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED) from exc
    if (
        type(user_bus) is not RoleExecutorUserBusContext
        or user_bus.effective_uid != effective_uid
        or user_bus.runtime_directory != f"/run/user/{effective_uid}"
        or len(user_bus.runtime_identity) != 5
        or len(user_bus.bus_identity) != 5
        or any(
            type(value) is not int
            for value in user_bus.runtime_identity + user_bus.bus_identity
        )
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    try:
        completed = runner(
            list(_SYSTEMCTL_MANAGER_COMMAND),
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=ROLE_EXECUTOR_TRANSPORT_PREFLIGHT_TIMEOUT_SECONDS,
            env=user_bus.environment,
        )
    except (subprocess.TimeoutExpired, TimeoutError) as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_TIMED_OUT) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE) from exc
    return_code = getattr(completed, "returncode", None)
    stdout = getattr(completed, "stdout", None)
    stderr = getattr(completed, "stderr", None)
    if type(return_code) is not int:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if return_code != 0:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE)
    if type(stderr) is not bytes:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if stderr:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS)
    properties = _parse_manager_response(stdout, expected_control_group)
    try:
        rebound_user_bus = user_bus_reader(effective_uid)
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE) from exc
    except Exception as exc:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED) from exc
    if rebound_user_bus != user_bus:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    _validate_preflight_contract(
        preflight,
        config_loader=config_loader,
        effective_uid=effective_uid,
    )
    manager_identity_sha256 = digest_json(
        {
            "schema": "twinfinity-role-executor-user-manager-identity/v1",
            "request_sha256": preflight.request_sha256,
            "user_bus_identity_sha256": user_bus.identity_sha256,
            "properties": properties,
        }
    )
    return RoleExecutorTransportAttestation.pass_for(
        preflight, user_manager_identity_sha256=manager_identity_sha256
    )


def validate_role_executor_transport_attestation(
    preflight: RoleExecutorTransportPreflight,
    attestation: object,
) -> RoleExecutorTransportAttestation:
    """Reject caller-substituted, incomplete, or malformed PASS evidence."""

    if type(attestation) is not RoleExecutorTransportAttestation:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    evidence = {
        "schema": attestation.schema,
        "status": attestation.status,
        "request_sha256": attestation.request_sha256,
        "probe_contract_sha256": attestation.probe_contract_sha256,
        "owner_identity_sha256": attestation.owner_identity_sha256,
        "user_manager_identity_sha256": attestation.user_manager_identity_sha256,
    }
    structural_values = (
        attestation.schema,
        attestation.status,
        attestation.request_sha256,
        attestation.probe_contract_sha256,
        attestation.owner_identity_sha256,
        attestation.user_manager_identity_sha256,
        attestation.evidence_sha256,
    )
    if (
        any(type(value) is not str for value in structural_values)
        or attestation.schema
        != "twinfinity-role-executor-transport-attestation/v1"
        or attestation.status != "PASS"
        or _SHA256.fullmatch(attestation.user_manager_identity_sha256) is None
        or attestation.evidence_sha256 != digest_json(evidence)
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if (
        attestation.request_sha256 != preflight.request_sha256
        or attestation.probe_contract_sha256 != preflight.probe_contract_sha256
        or attestation.owner_identity_sha256 != preflight.owner_identity_sha256
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    return attestation


def revalidate_role_executor_transport_preflight(
    connection: Any,
    preflight: RoleExecutorTransportPreflight,
    *,
    effective_uid: int | None = None,
) -> RoleExecutorTransportPreflight:
    """Atomically re-read every current pointer after the manager round trip."""

    uid = os.geteuid() if effective_uid is None else effective_uid
    current = build_role_executor_transport_preflight(
        connection, effective_uid=uid
    )
    if current.request_sha256 != preflight.request_sha256:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    return current


def injected_role_executor_transport_attestation(
    preflight: RoleExecutorTransportPreflight,
) -> RoleExecutorTransportAttestation:
    """Return deterministic evidence for an explicitly injected mock launcher."""

    return RoleExecutorTransportAttestation.pass_for(
        preflight,
        user_manager_identity_sha256=digest_json(
            {
                "schema": "twinfinity-injected-role-transport/v1",
                "request_sha256": preflight.request_sha256,
            }
        ),
    )


def role_executor_transport_failure_reason(error: BaseException) -> str:
    """Collapse failures to the closed privacy-safe public reason set."""

    if isinstance(error, RegistryError) and str(error) in ROLE_EXECUTOR_TRANSPORT_FAILURES:
        return str(error)
    if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)):
        return ROLE_EXECUTOR_TRANSPORT_TIMED_OUT
    if isinstance(error, (OSError, subprocess.SubprocessError)):
        return ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE
    return ROLE_EXECUTOR_TRANSPORT_MALFORMED


def role_executor_transport_failure_notice(
    preflight: RoleExecutorTransportPreflight,
    *,
    source_payload_sha256: str,
    reason: str,
    config_loader: Callable[..., Any] = load_registry_config,
) -> tuple[str, str, dict[str, object]]:
    """Build one stable non-authorizing notice without raw host evidence."""

    if (
        type(preflight) is not RoleExecutorTransportPreflight
        or type(source_payload_sha256) is not str
        or _SHA256.fullmatch(source_payload_sha256) is None
        or type(reason) is not str
        or reason not in ROLE_EXECUTOR_TRANSPORT_FAILURES
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    planner = next(
        (
            identity
            for identity in preflight.endpoint_identities
            if identity.role == "planner"
        ),
        None,
    )
    if planner is None:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    _validate_endpoint_transport_identity(
        preflight, planner, config_loader=config_loader
    )
    evidence = {
        "schema": "twinfinity-role-executor-transport-failure/v1",
        "reason": reason,
        "source_body_sha256": preflight.source_body_sha256,
        "endpoint_identity_sha256": preflight.endpoint_identity_sha256,
        "profile_identity_sha256": preflight.profile_identity_sha256,
        "registry_config_sha256": preflight.registry_source_sha256,
        "transport_runner_sha256": preflight.runner_source_sha256,
        "registered_launch_sha256": preflight.registered_launch_sha256,
        "transport_configuration_sha256": (
            preflight.transport_configuration_sha256
        ),
        "transport_probe_sha256": preflight.probe_contract_sha256,
    }
    notice_identity = {
        "source_repository": preflight.source_repository,
        "source_issue_number": preflight.source_issue_number,
        **evidence,
    }
    idempotency_key = (
        "role-executor-transport-preflight:" + digest_json(notice_identity)
    )
    payload: dict[str, object] = {
        "source": {
            "repository": preflight.source_repository,
            "object_kind": "issue",
            "object_number": preflight.source_issue_number,
            "payload_sha256": source_payload_sha256,
        },
        "notice_kind": "status",
        "mutation_authority": False,
        "subject": "Role transport preflight unavailable",
        "summary": (
            "Current role-executor transport is not attested; every "
            "dispatch-affecting write remains fenced."
        ),
        "evidence": evidence,
        "next_observation": (
            "A fresh supervisor pass will re-attest the same bounded transport identity."
        ),
    }
    return idempotency_key, planner.endpoint_id, payload


def enqueue_role_executor_transport_failure_notice(
    store: Any,
    preflight: RoleExecutorTransportPreflight,
    *,
    reason: str,
    now: str,
) -> int | None:
    """Best-effort one-row outage signal after exact read-only revalidation."""

    try:
        with store.transaction():
            current = build_role_executor_transport_preflight(store.connection)
            if current.request_sha256 != preflight.request_sha256:
                return None
            source = store.current_snapshot(
                preflight.source_repository,
                "issue",
                preflight.source_issue_number,
            )
            if source is None or source.payload_sha256 is None:
                return None
            payload = source.payload
            body = payload.get("body") if type(payload) is dict else None
            if (
                type(body) is not str
                or hashlib.sha256(body.encode("utf-8")).hexdigest()
                != preflight.source_body_sha256
                or payload.get("number") != preflight.source_issue_number
            ):
                return None
            idempotency_key, planner_endpoint_id, notice = (
                role_executor_transport_failure_notice(
                    preflight,
                    source_payload_sha256=source.payload_sha256,
                    reason=reason,
                )
            )
            return store.enqueue_message(
                idempotency_key=idempotency_key,
                recipient_session_id=planner_endpoint_id,
                topic="coordination.notice",
                payload=notice,
                now=now,
                _transaction=False,
            )
    except Exception:
        # The notice is optional. Failure to prove its exact source or recipient
        # must never weaken the dispatch fence or touch a due target.
        return None


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
        *_ROLE_EXECUTOR_RUNNER_PREFIX,
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


def _parse_manager_submission_response(
    stdout: object,
    stderr: object,
    *,
    expected_systemd_unit: str,
) -> RoleExecutorManagerSubmission:
    """Parse exactly one bounded manager channel into a closed receipt."""

    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if (
        len(stdout) + len(stderr)
        > ROLE_EXECUTOR_MANAGER_SUBMISSION_MAXIMUM_RESPONSE_BYTES
    ):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if bool(stdout) == bool(stderr):
        if stdout and stderr:
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS)
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    raw = stdout or stderr
    if b"\0" in raw:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    try:
        response = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED) from None
    match = _MANAGER_SUBMISSION_RESPONSE.fullmatch(response)
    if match is None:
        if response.count("Running as unit:") > 1:
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS)
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    unit = match.group("systemd_unit")
    if unit != expected_systemd_unit:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED)
    return RoleExecutorManagerSubmission(
        systemd_unit=unit,
        systemd_invocation_id=match.group("systemd_invocation_id"),
    )


def _bounded_manager_submission_run(
    command: list[str],
    *,
    timeout: float,
    env: dict[str, str],
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    monotonic: Callable[[], float] = time.monotonic,
) -> subprocess.CompletedProcess[bytes]:
    """Read both manager pipes under one pre-buffer byte and time ceiling."""

    if (
        type(command) is not list
        or not command
        or any(type(value) is not str or not value for value in command)
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or float(timeout) <= 0
        or type(env) is not dict
    ):
        raise subprocess.SubprocessError("manager submission input invalid")

    def sample(previous: float | None = None) -> float:
        value = monotonic()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
            or (previous is not None and float(value) < previous)
        ):
            raise subprocess.SubprocessError("manager submission clock invalid")
        return float(value)

    started_at = sample()
    deadline = started_at + float(timeout)
    if not math.isfinite(deadline):
        raise subprocess.SubprocessError("manager submission clock invalid")
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    buffers: dict[object, bytearray] = {}
    total = 0

    def stop_and_reap() -> None:
        if process is None:
            return
        try:
            if process.poll() is None:
                process.kill()
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            process.wait(timeout=ROLE_EXECUTOR_MANAGER_REAP_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            pass

    try:
        try:
            process = popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except OSError:
            raise RoleExecutorManagerNotSubmitted() from None
        if process.stdout is None or process.stderr is None:
            raise subprocess.SubprocessError("manager submission pipe missing")
        for stream in (process.stdout, process.stderr):
            buffers[stream] = bytearray()
            selector.register(stream, selectors.EVENT_READ)

        previous = started_at
        while selector.get_map():
            observed_at = sample(previous)
            previous = observed_at
            remaining = deadline - observed_at
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            ready = selector.select(remaining)
            if not ready:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _mask in ready:
                stream = key.fileobj
                read_limit = (
                    ROLE_EXECUTOR_MANAGER_SUBMISSION_MAXIMUM_RESPONSE_BYTES
                    + 1
                    - total
                )
                chunk = os.read(stream.fileno(), max(1, read_limit))
                if not chunk:
                    selector.unregister(stream)
                    continue
                total += len(chunk)
                if (
                    total
                    > ROLE_EXECUTOR_MANAGER_SUBMISSION_MAXIMUM_RESPONSE_BYTES
                ):
                    raise _ManagerSubmissionOutputOverflow
                buffers[stream].extend(chunk)

        observed_at = sample(previous)
        remaining = deadline - observed_at
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        return_code = process.wait(timeout=remaining)
        return subprocess.CompletedProcess(
            command,
            return_code,
            stdout=bytes(buffers[process.stdout]),
            stderr=bytes(buffers[process.stderr]),
        )
    except Exception:
        stop_and_reap()
        raise
    finally:
        try:
            selector.close()
        except (OSError, ValueError, AttributeError):
            pass
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError, AttributeError):
                        pass


def submit_role_executor(
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
    prompt: str,
    working_directory: Path | None = None,
) -> RoleExecutorManagerSubmission:
    """Submit once and require the manager's exact unit/invocation receipt."""

    resolved_working_directory = (working_directory or Path.cwd()).resolve()
    if not resolved_working_directory.is_dir():
        raise RegistryError("ROLE_EXECUTOR_WORKING_DIRECTORY_INVALID")
    systemd_unit = stable_systemd_unit(role, target_kind, target_key)
    command = [
        *_SYSTEMD_RUN_DIRECT_SUBMISSION_PREFIX,
        f"--unit={systemd_unit}",
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
        completed = _bounded_manager_submission_run(
            command,
            timeout=SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS,
            env=_manager_environment(os.geteuid()),
        )
    except RoleExecutorManagerNotSubmitted:
        raise
    except _ManagerSubmissionOutputOverflow:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED) from None
    except (subprocess.TimeoutExpired, TimeoutError):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_TIMED_OUT) from None
    except (OSError, subprocess.SubprocessError):
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE) from None
    return_code = getattr(completed, "returncode", None)
    if type(return_code) is not int:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED)
    if return_code != 0:
        raise RegistryError(ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS)
    return _parse_manager_submission_response(
        getattr(completed, "stdout", None),
        getattr(completed, "stderr", None),
        expected_systemd_unit=systemd_unit,
    )


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
        *_SYSTEMD_RUN_PREFIX,
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
            env=_manager_environment(os.geteuid()),
        )
    except (OSError, subprocess.SubprocessError):
        return 1
    return int(getattr(completed, "returncode", 1))
