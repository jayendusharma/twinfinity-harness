#!/usr/bin/env python3
"""Immutable role endpoints and ephemeral executor-attempt registry."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import stat
import subprocess
import tomllib
import uuid
from typing import Any, Callable, Iterator

from owner_safe_sqlite import UnsafeSQLitePathError, prepare_owner_database


DEFAULT_DATABASE = (
    Path(pwd.getpwuid(os.getuid()).pw_dir)
    / ".codex"
    / "twinfinity-coordination"
    / "ack-transactions.sqlite3"
)
DEFAULT_CONFIG = (
    Path(__file__).resolve().parent.parent
    / "references"
    / "twinfinity-executor-registry.toml"
)
DEFAULT_LEGACY_ALIASES = (
    Path(__file__).resolve().parent.parent
    / "references"
    / "twinfinity-legacy-role-aliases.json"
)
DEFAULT_PROFILE_TEMPLATE_ROOT = DEFAULT_CONFIG.parent
ROLES = ("planner", "development", "sre")
EXECUTION_ROLES = set(ROLES)
ENDPOINT_ID = re.compile(r"^role\.(planner|development|sre)\.v[1-9][0-9]*$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SYSTEMD_INVOCATION_ID = re.compile(r"^[0-9a-f]{32}$")
SYSTEMD_UNIT = re.compile(
    r"^twinfinity-role-executor-(planner|development|sre)-"
    r"(message|terminal-watch|hosted-operation)-[0-9a-f]{16}\.service$"
)
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
SQLITE_INTEGER_TARGET = re.compile(
    r"^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$"
)
CANONICAL_INTEGER_TARGET = re.compile(r"^[1-9][0-9]*$")
ROLE_EXECUTOR_CHILD_ACK_FENCE_SCHEMA = (
    "twinfinity-role-executor-child-ack-fence/v1"
)
ROLE_EXECUTOR_CHILD_ACK_EXPECTATION_SCHEMA = (
    "twinfinity-role-executor-child-ack-expectation/v1"
)
ROLE_EXECUTOR_CHILD_ACK_SCHEMA = "twinfinity-role-executor-child-ack/v1"
ROLE_EXECUTOR_MANAGER_SUBMISSION_SCHEMA = (
    "twinfinity-role-executor-manager-submission/v1"
)
ROLE_EXECUTOR_DIRECT_EXECUTION_CLASS = "DIRECT_MANAGER_CHILD"
ROLE_EXECUTOR_DEFAULT_ACK_WINDOW_SECONDS = 900
ROLE_EXECUTOR_MANAGER_RECEIPT_IDENTITY_SOURCE = "MANAGER_SUBMISSION_RECEIPT"
ROLE_EXECUTOR_CHILD_RECOVERY_IDENTITY_SOURCE = "AUTHENTICATED_CHILD_RECOVERY"
EXECUTOR_PRIVATE_ERROR_REDACTED = "EXECUTOR_PRIVATE_ERROR_REDACTED"
ATTEMPT_STATES = {
    "RESERVED",
    "LAUNCHING",
    "RUNNING",
    "COMPLETE",
    "HOLD",
    "LAUNCH_FAILED",
}
ACTIVE_ATTEMPT_STATES = {"RESERVED", "LAUNCHING", "RUNNING"}
TARGET_KINDS = {"message", "terminal_watch", "hosted_operation"}
NONMUTATING_MESSAGE_TOPIC = "coordination.notice"
ROOT_KEYS = {
    "schema_version",
    "roles",
    "historical_endpoints",
    "staged_endpoints",
}
LEGACY_ROOT_KEYS = ROOT_KEYS - {"staged_endpoints"}
COMMON_ROLE_KEYS = {
    "endpoint_id",
    "version",
    "executor_profile",
    "codex_profile",
    "command_prefix",
    "allowed_topics",
}
PROFILED_ROLE_KEYS = COMMON_ROLE_KEYS | {"profile_sha256"}
BROKERED_ROLE_KEYS = PROFILED_ROLE_KEYS | {"execution_protocol"}
BROKERED_READINESS_PROTOCOL = "readiness/v1"
PLANNER_PARK_PROTOCOL = "planner-park/v1"
RUNTIME_ROLLBACK_ENDPOINT_IDS = frozenset(
    {"role.planner.v2", "role.development.v3", "role.sre.v3"}
)
EXPECTED_CODEX_PROFILES = {
    "planner": "twinfinity-planner",
    "development": "twinfinity-development",
    "sre": "twinfinity-sre",
}
CODEX_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class RegistryError(RuntimeError):
    """Typed, value-free registry failure."""


@dataclass(frozen=True)
class OwnerFileEvidence:
    """Identity and content evidence captured from one owner-safe descriptor."""

    path: str
    device: int
    inode: int
    mode: int
    uid: int
    link_count: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


@dataclass(frozen=True)
class AttemptLineage:
    """Immutable logical delivery identity shared across executor target kinds."""

    repository: str
    issue_number: int
    generation: int
    lease_manifest_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository, str)
            or not self.repository
            or type(self.issue_number) is not int
            or self.issue_number <= 0
            or type(self.generation) is not int
            or self.generation < 0
            or not isinstance(self.lease_manifest_sha256, str)
            or SHA256.fullmatch(self.lease_manifest_sha256) is None
        ):
            raise RegistryError("EXECUTOR_LINEAGE_INVALID")

    @property
    def sha256(self) -> str:
        return digest_json(
            {
                "generation": self.generation,
                "issue_number": self.issue_number,
                "lease_manifest_sha256": self.lease_manifest_sha256,
                "repository": self.repository,
            }
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp_before(timestamp: str, seconds: int) -> str:
    instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (instant - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def canonical_repository_scope(repository: str) -> str:
    """Return the case-insensitive canonical identity for one GitHub repository."""

    if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
        raise RegistryError("EXECUTOR_REPOSITORY_SCOPE_INVALID")
    owner, name = repository.split("/", 1)
    return f"{owner.casefold()}/{name.casefold()}"


@dataclass(frozen=True)
class EndpointConfig:
    role: str
    endpoint_id: str
    version: int
    executor_profile: str
    codex_profile: str
    profile_sha256: str
    command_prefix: tuple[str, ...]
    allowed_topics: tuple[str, ...]
    execution_protocol: str | None = None

    @property
    def payload(self) -> dict[str, Any]:
        value = asdict(self)
        if not self.profile_sha256:
            value.pop("profile_sha256")
        if self.execution_protocol is None:
            value.pop("execution_protocol")
        value["command_prefix"] = list(self.command_prefix)
        value["allowed_topics"] = list(self.allowed_topics)
        return value

    @property
    def config_sha256(self) -> str:
        return digest_json(self.payload)

    @property
    def runtime_codex_profile(self) -> str:
        """Return the immutable on-disk profile name for this endpoint version."""

        return f"{self.codex_profile}-v{self.version}"


@dataclass(frozen=True)
class RegistryConfig:
    schema_version: int
    roles: dict[str, EndpointConfig]
    endpoints: dict[str, EndpointConfig]
    staged_endpoint_ids: tuple[str, ...]
    source_sha256: str
    source_evidence: OwnerFileEvidence
    profile_evidence: tuple[OwnerFileEvidence, ...]
    profile_validation_scope: str
    selected_profile_endpoint_id: str | None
    codex_home: str
    profile_template_root: str


_REGISTRY_CONFIG_SCOPE: ContextVar[RegistryConfig | None] = ContextVar(
    "twinfinity_registry_config_scope", default=None
)


@contextmanager
def registry_config_scope(config: RegistryConfig) -> Iterator[None]:
    """Temporarily bind one explicitly validated source/staged catalog.

    The binding is process-local and never mutates ``CODEX_HOME`` or another
    ambient configuration path.
    """

    token = _REGISTRY_CONFIG_SCOPE.set(config)
    try:
        yield
    finally:
        _REGISTRY_CONFIG_SCOPE.reset(token)


@dataclass(frozen=True)
class LegacyAliasSet:
    aliases: dict[str, str]
    source_sha256: str
    source_evidence: OwnerFileEvidence


@dataclass(frozen=True)
class SystemdUnitEvidence:
    unit: str
    load_state: str
    active_state: str
    sub_state: str
    invocation_id: str
    control_group: str
    result: str
    memory_max: str = ""
    tasks_max: str = ""
    runtime_max_usec: str = ""
    cpu_quota_per_sec_usec: str = ""

    @property
    def payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RoleExecutorChildAckFence:
    """Exact endpoint, target, and attempt inventory before submission."""

    schema: str
    execution_class: str
    role: str
    endpoint_id: str
    endpoint_pointer_version: int
    endpoint_config_sha256: str
    profile_sha256: str
    execution_protocol: str | None
    target_kind: str
    target_key: str
    target_progress_sha256: str
    preexisting_attempt_ids: tuple[str, ...]
    lineage_repository: str | None
    lineage_issue_number: int | None
    lineage_generation: int | None
    lineage_lease_sha256: str | None
    lineage_sha256: str | None

    @property
    def payload(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def sha256(self) -> str:
        return digest_json(self.payload)


@dataclass(frozen=True)
class RoleExecutorChildAckExpectation:
    """One exact manager receipt bound to its immutable pre-submit fence."""

    schema: str
    execution_class: str
    role: str
    endpoint_id: str
    endpoint_pointer_version: int
    endpoint_config_sha256: str
    profile_sha256: str
    execution_protocol: str | None
    target_kind: str
    target_key: str
    target_progress_sha256: str
    preexisting_attempt_ids: tuple[str, ...]
    lineage_repository: str | None
    lineage_issue_number: int | None
    lineage_generation: int | None
    lineage_lease_sha256: str | None
    lineage_sha256: str | None
    fence_sha256: str
    systemd_unit: str
    systemd_invocation_id: str
    manager_identity_source: str
    manager_identity_sha256: str
    manager_receipt_sha256: str | None
    intent_recorded_at: str
    observation_deadline_at: str

    @property
    def payload(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def sha256(self) -> str:
        return digest_json(self.payload)


@dataclass(frozen=True)
class RoleExecutorChildAcknowledgement:
    """Closed privacy-safe evidence for one exact token-authenticated child."""

    schema: str
    expectation_sha256: str
    fence_sha256: str
    manager_identity_source: str
    manager_identity_sha256: str
    manager_receipt_sha256: str | None
    intent_recorded_at: str
    observation_deadline_at: str
    attempt_id: str
    instance_id: str
    token_sha256: str
    event_chain_sha256: str
    execution_class: str
    execution_ownership_sha256: str
    role: str
    endpoint_id: str
    endpoint_pointer_version: int
    endpoint_config_sha256: str
    profile_sha256: str
    execution_protocol: str | None
    target_kind: str
    target_key: str
    target_progress_sha256: str
    lineage_sha256: str | None
    state: str
    version: int
    process_id: int
    systemd_unit: str
    systemd_invocation_id: str
    systemd_control_group: str
    token_authenticated: bool
    token_persisted: bool

    @property
    def payload(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def sha256(self) -> str:
        return digest_json(self.payload)


def stable_systemd_unit(role: str, target_kind: str, target_key: str) -> str:
    """Return the deterministic bounded unit name for one exact target."""

    if (
        not isinstance(role, str)
        or role not in ROLES
        or not isinstance(target_kind, str)
        or target_kind not in TARGET_KINDS
        or not isinstance(target_key, str)
        or not target_key
    ):
        raise RegistryError("EXECUTOR_TARGET_INVALID")
    target_label = target_kind.replace("_", "-")
    target_digest = hashlib.sha256(
        canonical_json([role, target_kind, target_key]).encode("utf-8")
    ).hexdigest()[:16]
    return f"twinfinity-role-executor-{role}-{target_label}-{target_digest}.service"


def probe_systemd_unit(
    unit: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> SystemdUnitEvidence:
    """Read one exact user-unit identity without process-list inference."""

    if not isinstance(unit, str) or SYSTEMD_UNIT.fullmatch(unit) is None:
        raise RegistryError("SYSTEMD_EVIDENCE_UNIT_INVALID")
    try:
        completed = runner(
            [
                "/usr/bin/systemctl",
                "--user",
                "show",
                unit,
                "--no-pager",
                "--property=Id",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=InvocationID",
                "--property=ControlGroup",
                "--property=Result",
                "--property=MemoryMax",
                "--property=TasksMax",
                "--property=RuntimeMaxUSec",
                "--property=CPUQuotaPerSecUSec",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RegistryError("SYSTEMD_EVIDENCE_QUERY_FAILED") from exc
    if completed.returncode != 0:
        raise RegistryError("SYSTEMD_EVIDENCE_QUERY_FAILED")
    fields: dict[str, str] = {}
    for raw_line in completed.stdout.splitlines():
        if "=" not in raw_line:
            raise RegistryError("SYSTEMD_EVIDENCE_AMBIGUOUS")
        key, value = raw_line.split("=", 1)
        if key in fields:
            raise RegistryError("SYSTEMD_EVIDENCE_AMBIGUOUS")
        fields[key] = value
    expected = {
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "InvocationID",
        "ControlGroup",
        "Result",
        "MemoryMax",
        "TasksMax",
        "RuntimeMaxUSec",
        "CPUQuotaPerSecUSec",
    }
    if set(fields) != expected:
        raise RegistryError("SYSTEMD_EVIDENCE_AMBIGUOUS")
    return SystemdUnitEvidence(
        unit=fields["Id"],
        load_state=fields["LoadState"],
        active_state=fields["ActiveState"],
        sub_state=fields["SubState"],
        invocation_id=fields["InvocationID"],
        control_group=fields["ControlGroup"],
        result=fields["Result"],
        memory_max=fields["MemoryMax"],
        tasks_max=fields["TasksMax"],
        runtime_max_usec=fields["RuntimeMaxUSec"],
        cpu_quota_per_sec_usec=fields["CPUQuotaPerSecUSec"],
    )


def validate_launch_systemd_evidence(
    *,
    role: str,
    target_kind: str,
    target_key: str,
    invocation_id: str,
    evidence: SystemdUnitEvidence,
) -> None:
    unit = stable_systemd_unit(role, target_kind, target_key)
    if (
        SYSTEMD_INVOCATION_ID.fullmatch(invocation_id) is None
        or evidence.unit != unit
        or evidence.invocation_id != invocation_id
        or evidence.load_state != "loaded"
        or evidence.active_state not in {"active", "activating"}
        or evidence.sub_state not in {"running", "start"}
        or not evidence.control_group.startswith("/")
        or not evidence.control_group.endswith(f"/{unit}")
    ):
        raise RegistryError("SYSTEMD_LAUNCH_IDENTITY_INVALID")


def load_legacy_aliases(path: Path = DEFAULT_LEGACY_ALIASES) -> LegacyAliasSet:
    """Load the closed-schema reviewed mapping used before and after migration."""

    raw, evidence = _read_regular_owner_file(path, "LEGACY_ALIAS_FILE")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError("LEGACY_ALIAS_FILE_INVALID_JSON") from exc
    if type(value) is not dict or set(value) != {"schema_version", "aliases"}:
        raise RegistryError("LEGACY_ALIAS_FILE_SCHEMA_INVALID")
    if value.get("schema_version") != 1 or type(value.get("aliases")) is not list:
        raise RegistryError("LEGACY_ALIAS_FILE_SCHEMA_INVALID")
    aliases: dict[str, str] = {}
    roles: set[str] = set()
    for item in value["aliases"]:
        if type(item) is not dict or set(item) != {"alias", "role"}:
            raise RegistryError("LEGACY_ALIAS_FILE_SCHEMA_INVALID")
        alias = item.get("alias")
        role = item.get("role")
        if (
            type(alias) is not str
            or UUID.fullmatch(alias) is None
            or type(role) is not str
            or role not in ROLES
            or alias in aliases
            or role in roles
        ):
            raise RegistryError("LEGACY_ALIAS_FILE_VALUE_INVALID")
        aliases[alias] = role
        roles.add(role)
    if roles != set(ROLES):
        raise RegistryError("LEGACY_ALIAS_FILE_ROLES_INVALID")
    return LegacyAliasSet(
        aliases=aliases,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_evidence=evidence,
    )


def _validate_string_list(value: Any, error: str) -> tuple[str, ...]:
    if (
        type(value) is not list
        or not value
        or any(type(item) is not str or not item for item in value)
    ):
        raise RegistryError(error)
    return tuple(value)


def _default_codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            raise RegistryError("REGISTRY_CODEX_HOME_INVALID")
        return candidate
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".codex"


def _metadata_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular_owner_file(
    path: Path, error_prefix: str
) -> tuple[bytes, OwnerFileEvidence]:
    """Read one file through O_NOFOLLOW and bind path, descriptor, and bytes."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise RegistryError(f"{error_prefix}_MISSING") from exc
    except OSError as exc:
        raise RegistryError(f"{error_prefix}_UNSAFE") from exc
    try:
        before = os.fstat(descriptor)
        try:
            path_metadata = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise RegistryError(f"{error_prefix}_DRIFT") from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or _metadata_tuple(path_metadata) != _metadata_tuple(before)
        ):
            raise RegistryError(f"{error_prefix}_UNSAFE")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            final_path_metadata = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise RegistryError(f"{error_prefix}_DRIFT") from exc
        if (
            _metadata_tuple(before) != _metadata_tuple(after)
            or _metadata_tuple(after) != _metadata_tuple(final_path_metadata)
            or len(raw) != after.st_size
        ):
            raise RegistryError(f"{error_prefix}_DRIFT")
        evidence = OwnerFileEvidence(
            path=os.path.abspath(os.fspath(path)),
            device=after.st_dev,
            inode=after.st_ino,
            mode=after.st_mode,
            uid=after.st_uid,
            link_count=after.st_nlink,
            size=after.st_size,
            mtime_ns=after.st_mtime_ns,
            ctime_ns=after.st_ctime_ns,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
        return raw, evidence
    finally:
        os.close(descriptor)


def _validate_profile_directory(value: Any, error_prefix: str) -> Path:
    """Reject profile roots that traverse links or mutable shared directories."""

    try:
        path = Path(os.fspath(value))
    except TypeError as exc:
        raise RegistryError(f"{error_prefix}_INVALID") from exc
    if not path.is_absolute():
        raise RegistryError(f"{error_prefix}_INVALID")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    anchor_metadata = current.lstat()

    def component_is_safe(
        component: Path, metadata: os.stat_result, *, is_final: bool
    ) -> bool:
        shared_sticky_ancestor = not is_final and bool(
            metadata.st_mode & stat.S_ISVTX
        )
        mapped_namespace_ancestor = (
            not is_final
            and component in {Path("/"), Path("/home")}
            and metadata.st_uid == 65534
            and stat.S_IMODE(metadata.st_mode) == 0o755
        )
        owner_is_trusted = (
            metadata.st_uid in {0, os.getuid()}
            or shared_sticky_ancestor
            or mapped_namespace_ancestor
        )
        return not (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (is_final and metadata.st_uid != os.getuid())
            or (not is_final and not owner_is_trusted)
            or (
                metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                and not shared_sticky_ancestor
            )
        )

    if not component_is_safe(
        current, anchor_metadata, is_final=absolute == current
    ):
        raise RegistryError(f"{error_prefix}_UNSAFE")
    parts = absolute.parts[1:]
    for ordinal, part in enumerate(parts):
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise RegistryError(f"{error_prefix}_MISSING") from exc
        is_final = ordinal == len(parts) - 1
        if not component_is_safe(current, metadata, is_final=is_final):
            raise RegistryError(f"{error_prefix}_UNSAFE")
    return absolute


def revalidate_owner_file_evidence(
    evidence: OwnerFileEvidence, error_prefix: str
) -> bytes:
    """Reread one reviewed source and reject metadata or content replacement."""

    raw, current = _read_regular_owner_file(Path(evidence.path), error_prefix)
    if current != evidence:
        raise RegistryError(f"{error_prefix}_DRIFT")
    return raw


def revalidate_registry_inputs(config: RegistryConfig) -> RegistryConfig:
    """Descriptor-reread and reparse every source controlling a migration."""

    current = load_registry_config(
        Path(config.source_evidence.path),
        codex_home=Path(config.codex_home),
        profile_template_root=Path(config.profile_template_root),
        profile_validation_scope=config.profile_validation_scope,
        selected_current_endpoint_id=config.selected_profile_endpoint_id,
    )
    if current.source_evidence != config.source_evidence:
        raise RegistryError("REGISTRY_CONFIG_DRIFT")
    if current.profile_evidence != config.profile_evidence:
        raise RegistryError("REGISTRY_PROFILE_DRIFT")
    if (
        current.schema_version != config.schema_version
        or current.roles != config.roles
        or current.endpoints != config.endpoints
        or current.staged_endpoint_ids != config.staged_endpoint_ids
        or current.source_sha256 != config.source_sha256
        or current.profile_validation_scope != config.profile_validation_scope
        or current.selected_profile_endpoint_id
        != config.selected_profile_endpoint_id
        or current.codex_home != config.codex_home
        or current.profile_template_root != config.profile_template_root
    ):
        raise RegistryError("REGISTRY_MIGRATION_INPUT_DRIFT")
    return current


def _validate_role_profiles(
    endpoints: dict[str, EndpointConfig],
    *,
    codex_home: Path,
    profile_template_root: Path,
) -> tuple[OwnerFileEvidence, ...]:
    evidence: list[OwnerFileEvidence] = []
    for endpoint_id in sorted(endpoints):
        endpoint = endpoints[endpoint_id]
        role = endpoint.role
        expected_name = EXPECTED_CODEX_PROFILES[role]
        if (
            endpoint.codex_profile != expected_name
            or CODEX_PROFILE_NAME.fullmatch(endpoint.codex_profile) is None
            or SHA256.fullmatch(endpoint.profile_sha256) is None
        ):
            raise RegistryError("REGISTRY_PROFILE_CONTRACT_INVALID")
        profile_filename = f"{endpoint.runtime_codex_profile}.config.toml"
        template, template_evidence = _read_regular_owner_file(
            profile_template_root / profile_filename,
            "REGISTRY_PROFILE_TEMPLATE",
        )
        installed, installed_evidence = _read_regular_owner_file(
            codex_home / profile_filename,
            "REGISTRY_PROFILE",
        )
        if hashlib.sha256(template).hexdigest() != endpoint.profile_sha256:
            raise RegistryError("REGISTRY_PROFILE_TEMPLATE_DIGEST_MISMATCH")
        if installed != template:
            raise RegistryError("REGISTRY_PROFILE_DIGEST_MISMATCH")
        evidence.extend((template_evidence, installed_evidence))
    return tuple(evidence)


def _parse_endpoint_config(role: str, value: Any) -> EndpointConfig:
    """Parse one exact reviewed endpoint manifest without syntax-only authority."""

    if not isinstance(value, dict) or set(value) not in (
        PROFILED_ROLE_KEYS,
        BROKERED_ROLE_KEYS,
    ):
        raise RegistryError("REGISTRY_CONFIG_ROLE_SCHEMA_INVALID")
    endpoint_id = value.get("endpoint_id")
    version = value.get("version")
    executor_profile = value.get("executor_profile")
    codex_profile = value.get("codex_profile")
    profile_sha256 = value.get("profile_sha256", "")
    execution_protocol = value.get("execution_protocol")
    if (
        role not in ROLES
        or type(endpoint_id) is not str
        or ENDPOINT_ID.fullmatch(endpoint_id) is None
        or endpoint_id != f"role.{role}.v{version}"
        or type(version) is not int
        or version <= 0
        or type(executor_profile) is not str
        or executor_profile != role
        or type(codex_profile) is not str
        or type(profile_sha256) is not str
        or SHA256.fullmatch(profile_sha256) is None
        or (
            execution_protocol is not None
            and (
                execution_protocol != BROKERED_READINESS_PROTOCOL
                or role not in {"development", "sre"}
                or version != 5
            )
        )
        or (
            role in {"development", "sre"}
            and version == 5
            and execution_protocol != BROKERED_READINESS_PROTOCOL
        )
        or (role == "planner" and execution_protocol is not None)
    ):
        raise RegistryError("REGISTRY_CONFIG_ROLE_INVALID")
    command_prefix = _validate_string_list(
        value.get("command_prefix"), "REGISTRY_CONFIG_COMMAND_INVALID"
    )
    allowed_topics = _validate_string_list(
        value.get("allowed_topics"), "REGISTRY_CONFIG_TOPICS_INVALID"
    )
    if (
        execution_protocol == BROKERED_READINESS_PROTOCOL
        and allowed_topics != (NONMUTATING_MESSAGE_TOPIC,)
    ):
        raise RegistryError("REGISTRY_CONFIG_TOPICS_INVALID")
    if role == "planner" and version == 3 and allowed_topics != (
        NONMUTATING_MESSAGE_TOPIC,
    ):
        raise RegistryError("REGISTRY_CONFIG_TOPICS_INVALID")
    expected_name = EXPECTED_CODEX_PROFILES[role]
    expected_command = (
        "/home/ubuntu/.local/bin/codex",
        "exec",
        "--profile",
        expected_name,
        "--strict-config",
        "--json",
    )
    if (
        command_prefix != expected_command
        or codex_profile != expected_name
        or "resume" in command_prefix
        or any(UUID.fullmatch(token) for token in command_prefix)
        or any("bypass" in token.casefold() for token in command_prefix)
        or len(set(allowed_topics)) != len(allowed_topics)
    ):
        raise RegistryError("REGISTRY_CONFIG_COMMAND_INVALID")
    role_mutating = {
        topic for topic in allowed_topics if topic != NONMUTATING_MESSAGE_TOPIC
    }
    if role == "development" and any(
        not topic.startswith("development.") for topic in role_mutating
    ):
        raise RegistryError("REGISTRY_PROFILE_NOT_EXCLUSIVE")
    if role == "sre" and any(
        not topic.startswith("sre.") for topic in role_mutating
    ):
        raise RegistryError("REGISTRY_PROFILE_NOT_EXCLUSIVE")
    if role == "planner" and role_mutating:
        raise RegistryError("REGISTRY_PROFILE_NOT_EXCLUSIVE")
    return EndpointConfig(
        role=role,
        endpoint_id=endpoint_id,
        version=version,
        executor_profile=executor_profile,
        codex_profile=codex_profile,
        profile_sha256=profile_sha256,
        command_prefix=command_prefix,
        allowed_topics=allowed_topics,
        execution_protocol=(
            PLANNER_PARK_PROTOCOL
            if role == "planner" and version == 3
            else execution_protocol
        ),
    )


def load_registry_config(
    path: Path = DEFAULT_CONFIG,
    *,
    codex_home: Path | None = None,
    profile_template_root: Path | None = DEFAULT_PROFILE_TEMPLATE_ROOT,
    profile_validation_scope: str = "current",
    selected_current_endpoint_id: str | None = None,
) -> RegistryConfig:
    """Load the closed current-and-rollback endpoint catalog."""

    raw, source_evidence = _read_regular_owner_file(path, "REGISTRY_CONFIG")
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RegistryError("REGISTRY_CONFIG_INVALID_TOML") from exc
    if set(parsed) not in {frozenset(ROOT_KEYS), frozenset(LEGACY_ROOT_KEYS)} or parsed.get("schema_version") != 2:
        raise RegistryError("REGISTRY_CONFIG_SCHEMA_INVALID")
    role_values = parsed.get("roles")
    historical_values = parsed.get("historical_endpoints")
    staged_values = parsed.get("staged_endpoints", [])
    if not isinstance(role_values, dict) or set(role_values) != set(ROLES):
        raise RegistryError("REGISTRY_CONFIG_ROLES_INVALID")
    if not isinstance(historical_values, list) or not isinstance(staged_values, list):
        raise RegistryError("REGISTRY_CONFIG_HISTORY_INVALID")

    roles = {
        role: _parse_endpoint_config(role, role_values[role]) for role in ROLES
    }
    endpoints: dict[str, EndpointConfig] = {
        endpoint.endpoint_id: endpoint for endpoint in roles.values()
    }
    versions = {(endpoint.role, endpoint.version) for endpoint in roles.values()}
    for value in historical_values:
        if not isinstance(value, dict) or type(value.get("role")) is not str:
            raise RegistryError("REGISTRY_CONFIG_HISTORY_INVALID")
        role = str(value["role"])
        endpoint = _parse_endpoint_config(
            role, {key: item for key, item in value.items() if key != "role"}
        )
        if (
            endpoint.endpoint_id in endpoints
            or (endpoint.role, endpoint.version) in versions
            or endpoint.version >= roles[endpoint.role].version
        ):
            raise RegistryError("REGISTRY_CONFIG_HISTORY_INVALID")
        endpoints[endpoint.endpoint_id] = endpoint
        versions.add((endpoint.role, endpoint.version))

    staged_endpoint_ids: list[str] = []
    for value in staged_values:
        if not isinstance(value, dict) or type(value.get("role")) is not str:
            raise RegistryError("REGISTRY_CONFIG_STAGED_INVALID")
        role = str(value["role"])
        endpoint = _parse_endpoint_config(
            role, {key: item for key, item in value.items() if key != "role"}
        )
        if (
            endpoint.endpoint_id in endpoints
            or (endpoint.role, endpoint.version) in versions
            or endpoint.version <= roles[endpoint.role].version
        ):
            raise RegistryError("REGISTRY_CONFIG_STAGED_INVALID")
        endpoints[endpoint.endpoint_id] = endpoint
        versions.add((endpoint.role, endpoint.version))
        staged_endpoint_ids.append(endpoint.endpoint_id)

    current_mutating = {
        role: {
            topic
            for topic in endpoint.allowed_topics
            if topic != NONMUTATING_MESSAGE_TOPIC
        }
        for role, endpoint in roles.items()
    }
    if current_mutating["development"] & current_mutating["sre"]:
        raise RegistryError("REGISTRY_PROFILE_NOT_EXCLUSIVE")
    if profile_validation_scope not in {"current", "catalog"}:
        raise RegistryError("REGISTRY_PROFILE_VALIDATION_SCOPE_INVALID")
    runtime_roles = roles
    if selected_current_endpoint_id is not None:
        selected = endpoints.get(selected_current_endpoint_id)
        source_current = (
            selected is not None
            and roles[selected.role].endpoint_id == selected_current_endpoint_id
        )
        if (
            profile_validation_scope != "current"
            or selected is None
            or selected_current_endpoint_id in staged_endpoint_ids
            or (
                not source_current
                and selected_current_endpoint_id
                not in RUNTIME_ROLLBACK_ENDPOINT_IDS
            )
        ):
            raise RegistryError("REGISTRY_PROFILE_ENDPOINT_NOT_CURRENT")
        runtime_roles = dict(roles)
        runtime_roles[selected.role] = selected
        profiled_endpoints = {selected_current_endpoint_id: selected}
    elif profile_validation_scope == "catalog":
        profiled_endpoints = endpoints
    else:
        profiled_endpoints = {
            endpoint.endpoint_id: endpoint for endpoint in roles.values()
        }
    effective_codex_home = _validate_profile_directory(
        _default_codex_home() if codex_home is None else codex_home,
        "REGISTRY_CODEX_HOME",
    )
    effective_template_root = _validate_profile_directory(
        DEFAULT_PROFILE_TEMPLATE_ROOT
        if profile_template_root is None
        else profile_template_root,
        "REGISTRY_PROFILE_ROOT",
    )
    profile_evidence = _validate_role_profiles(
        profiled_endpoints,
        codex_home=effective_codex_home,
        profile_template_root=effective_template_root,
    )
    return RegistryConfig(
        schema_version=2,
        roles=runtime_roles,
        endpoints=endpoints,
        staged_endpoint_ids=tuple(sorted(staged_endpoint_ids)),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_evidence=source_evidence,
        profile_evidence=profile_evidence,
        profile_validation_scope=profile_validation_scope,
        selected_profile_endpoint_id=selected_current_endpoint_id,
        codex_home=os.path.abspath(os.fspath(effective_codex_home)),
        profile_template_root=os.path.abspath(os.fspath(effective_template_root)),
    )


def _execute_schema_script(connection: sqlite3.Connection, script: str) -> None:
    """Execute a schema script without sqlite3.executescript's implicit COMMIT."""

    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if not sqlite3.complete_statement(pending):
            continue
        statement = pending.strip()
        if statement:
            connection.execute(statement)
        pending = ""
    if pending.strip():
        raise RegistryError("EXECUTOR_REGISTRY_SCHEMA_SCRIPT_INVALID")


def ensure_executor_registry_schema(connection: sqlite3.Connection) -> None:
    """Install only additive registry tables and immutability triggers."""

    attempts_existed = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='executor_attempts'"
    ).fetchone() is not None
    _execute_schema_script(
        connection,
        """
        CREATE TABLE IF NOT EXISTS executor_role_endpoints (
            endpoint_id TEXT PRIMARY KEY,
            role TEXT NOT NULL CHECK(role IN ('planner','development','sre')),
            version INTEGER NOT NULL CHECK(version > 0),
            executor_profile TEXT NOT NULL,
            codex_profile TEXT NOT NULL,
            config_sha256 TEXT NOT NULL,
            config_json TEXT NOT NULL,
            command_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(role, version)
        );
        CREATE TABLE IF NOT EXISTS executor_registry_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            cutover_state TEXT NOT NULL CHECK(cutover_state IN ('PRE_CUTOVER','CUTOVER_COMPLETE')),
            version INTEGER NOT NULL CHECK(version > 0),
            completed_at TEXT
        );
        INSERT OR IGNORE INTO executor_registry_state(
            singleton, cutover_state, version, completed_at
        ) VALUES (1, 'PRE_CUTOVER', 1, NULL);
        CREATE TABLE IF NOT EXISTS executor_role_endpoint_current (
            role TEXT PRIMARY KEY CHECK(role IN ('planner','development','sre')),
            endpoint_id TEXT NOT NULL,
            pointer_version INTEGER NOT NULL CHECK(pointer_version > 0),
            updated_at TEXT NOT NULL,
            FOREIGN KEY(endpoint_id) REFERENCES executor_role_endpoints(endpoint_id)
        );
        CREATE TABLE IF NOT EXISTS executor_role_endpoint_aliases (
            alias TEXT PRIMARY KEY,
            role TEXT NOT NULL CHECK(role IN ('planner','development','sre')),
            endpoint_id TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(endpoint_id) REFERENCES executor_role_endpoints(endpoint_id)
        );
        CREATE TABLE IF NOT EXISTS executor_attempts (
            attempt_id TEXT PRIMARY KEY,
            role TEXT NOT NULL CHECK(role IN ('planner','development','sre')),
            endpoint_id TEXT NOT NULL,
            instance_id TEXT NOT NULL UNIQUE,
            token_sha256 TEXT NOT NULL,
            target_kind TEXT NOT NULL CHECK(target_kind IN ('message','terminal_watch','hosted_operation')),
            target_key TEXT NOT NULL,
            repository_scope TEXT,
            target_progress_sha256 TEXT,
            terminal_progress_sha256 TEXT,
            lineage_repository TEXT,
            lineage_issue_number INTEGER,
            lineage_generation INTEGER,
            lineage_lease_sha256 TEXT,
            lineage_sha256 TEXT,
            state TEXT NOT NULL CHECK(state IN ('RESERVED','LAUNCHING','RUNNING','COMPLETE','HOLD','LAUNCH_FAILED')),
            process_id INTEGER,
            exit_code INTEGER,
            systemd_unit TEXT,
            systemd_invocation_id TEXT,
            systemd_control_group TEXT,
            heartbeat_at TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_error TEXT,
            CHECK (target_progress_sha256 IS NULL OR length(target_progress_sha256)=64),
            CHECK (terminal_progress_sha256 IS NULL OR length(terminal_progress_sha256)=64),
            CHECK (
                (lineage_sha256 IS NULL
                 AND lineage_repository IS NULL
                 AND lineage_issue_number IS NULL
                 AND lineage_generation IS NULL
                 AND lineage_lease_sha256 IS NULL)
                OR
                (length(lineage_sha256)=64
                 AND lineage_repository IS NOT NULL
                 AND lineage_issue_number > 0
                 AND lineage_generation >= 0
                 AND length(lineage_lease_sha256)=64)
            ),
            FOREIGN KEY(endpoint_id) REFERENCES executor_role_endpoints(endpoint_id)
        );
        CREATE TABLE IF NOT EXISTS executor_attempt_events (
            event_id TEXT PRIMARY KEY,
            attempt_id TEXT NOT NULL,
            from_state TEXT,
            to_state TEXT NOT NULL,
            from_version INTEGER,
            to_version INTEGER NOT NULL,
            reason TEXT,
            evidence_sha256 TEXT,
            evidence_json TEXT,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id)
        );
        CREATE TABLE IF NOT EXISTS executor_registry_changes (
            change_id TEXT PRIMARY KEY,
            operation_key TEXT NOT NULL UNIQUE,
            config_sha256 TEXT NOT NULL,
            before_state_sha256 TEXT NOT NULL,
            before_state_json TEXT NOT NULL,
            after_state_sha256 TEXT NOT NULL,
            after_state_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('APPLIED','ROLLED_BACK')),
            version INTEGER NOT NULL CHECK(version > 0),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS executor_role_endpoint_immutable_update
        BEFORE UPDATE ON executor_role_endpoints
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ENDPOINT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS executor_role_endpoint_immutable_delete
        BEFORE DELETE ON executor_role_endpoints
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ENDPOINT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS executor_registry_state_monotonic_update
        BEFORE UPDATE ON executor_registry_state
        WHEN NEW.singleton IS NOT OLD.singleton
          OR OLD.cutover_state='CUTOVER_COMPLETE'
          OR NEW.cutover_state!='CUTOVER_COMPLETE'
          OR NEW.version!=OLD.version+1
          OR NEW.completed_at IS NULL
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_CUTOVER_STATE_MONOTONIC'); END;
        CREATE TRIGGER IF NOT EXISTS executor_registry_state_immutable_delete
        BEFORE DELETE ON executor_registry_state
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_CUTOVER_STATE_MONOTONIC'); END;
        CREATE TRIGGER IF NOT EXISTS executor_current_endpoint_role_insert
        BEFORE INSERT ON executor_role_endpoint_current
        WHEN NOT EXISTS (
            SELECT 1 FROM executor_role_endpoints endpoint
            WHERE endpoint.endpoint_id=NEW.endpoint_id AND endpoint.role=NEW.role
        )
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_POINTER_ROLE_MISMATCH'); END;
        CREATE TRIGGER IF NOT EXISTS executor_current_endpoint_role_update
        BEFORE UPDATE OF role, endpoint_id ON executor_role_endpoint_current
        WHEN NOT EXISTS (
            SELECT 1 FROM executor_role_endpoints endpoint
            WHERE endpoint.endpoint_id=NEW.endpoint_id AND endpoint.role=NEW.role
        )
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_POINTER_ROLE_MISMATCH'); END;
        CREATE TRIGGER IF NOT EXISTS executor_current_endpoint_cutover_insert
        AFTER INSERT ON executor_role_endpoint_current
        WHEN (SELECT cutover_state FROM executor_registry_state WHERE singleton=1)='PRE_CUTOVER'
        BEGIN
            UPDATE executor_registry_state
            SET cutover_state='CUTOVER_COMPLETE', version=version+1,
                completed_at=NEW.updated_at
            WHERE singleton=1 AND cutover_state='PRE_CUTOVER';
        END;
        CREATE TRIGGER IF NOT EXISTS executor_current_endpoint_monotonic_delete
        BEFORE DELETE ON executor_role_endpoint_current
        WHEN (SELECT cutover_state FROM executor_registry_state WHERE singleton=1)='CUTOVER_COMPLETE'
        BEGIN SELECT RAISE(ABORT, 'REGISTRY_ROLLBACK_PRECUTOVER_FORBIDDEN'); END;
        CREATE TRIGGER IF NOT EXISTS executor_role_alias_immutable_update
        BEFORE UPDATE ON executor_role_endpoint_aliases
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ALIAS_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS executor_role_alias_immutable_delete
        BEFORE DELETE ON executor_role_endpoint_aliases
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ALIAS_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS executor_attempt_identity_immutable
        BEFORE UPDATE ON executor_attempts
        WHEN NEW.attempt_id IS NOT OLD.attempt_id
          OR NEW.role IS NOT OLD.role
          OR NEW.endpoint_id IS NOT OLD.endpoint_id
          OR NEW.instance_id IS NOT OLD.instance_id
          OR NEW.token_sha256 IS NOT OLD.token_sha256
          OR NEW.target_kind IS NOT OLD.target_kind
          OR NEW.target_key IS NOT OLD.target_key
          OR NEW.repository_scope IS NOT OLD.repository_scope
          OR NEW.target_progress_sha256 IS NOT OLD.target_progress_sha256
          OR (OLD.terminal_progress_sha256 IS NOT NULL AND NEW.terminal_progress_sha256 IS NOT OLD.terminal_progress_sha256)
          OR NEW.lineage_repository IS NOT OLD.lineage_repository
          OR NEW.lineage_issue_number IS NOT OLD.lineage_issue_number
          OR NEW.lineage_generation IS NOT OLD.lineage_generation
          OR NEW.lineage_lease_sha256 IS NOT OLD.lineage_lease_sha256
          OR NEW.lineage_sha256 IS NOT OLD.lineage_sha256
          OR NEW.created_at IS NOT OLD.created_at
          OR (OLD.systemd_unit IS NOT NULL AND NEW.systemd_unit IS NOT OLD.systemd_unit)
          OR (OLD.systemd_invocation_id IS NOT NULL AND NEW.systemd_invocation_id IS NOT OLD.systemd_invocation_id)
          OR (OLD.systemd_control_group IS NOT NULL AND NEW.systemd_control_group IS NOT OLD.systemd_control_group)
          OR (OLD.process_id IS NOT NULL AND NEW.process_id IS NOT OLD.process_id)
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ATTEMPT_IDENTITY_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS executor_attempt_event_immutable_update
        BEFORE UPDATE ON executor_attempt_events
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ATTEMPT_EVENT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS executor_attempt_event_immutable_delete
        BEFORE DELETE ON executor_attempt_events
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ATTEMPT_EVENT_IMMUTABLE'); END;
        """
    )
    existing_pointer = connection.execute(
        "SELECT updated_at FROM executor_role_endpoint_current ORDER BY role LIMIT 1"
    ).fetchone()
    if existing_pointer is not None:
        connection.execute(
            """
            UPDATE executor_registry_state
            SET cutover_state='CUTOVER_COMPLETE', version=version+1, completed_at=?
            WHERE singleton=1 AND cutover_state='PRE_CUTOVER'
            """,
            (str(existing_pointer[0]),),
        )
    if not attempts_existed:
        connection.execute(
            """CREATE UNIQUE INDEX executor_one_active_attempt_per_target
            ON executor_attempts(role, target_kind, target_key)
            WHERE state IN ('RESERVED','LAUNCHING','RUNNING')"""
        )
        connection.execute(
            """CREATE UNIQUE INDEX executor_one_active_attempt_per_lineage
            ON executor_attempts(lineage_sha256)
            WHERE lineage_sha256 IS NOT NULL
              AND state IN ('RESERVED','LAUNCHING','RUNNING')"""
        )
        connection.execute(
            """CREATE UNIQUE INDEX executor_one_active_planner_per_repository
            ON executor_attempts(repository_scope)
            WHERE role='planner' AND repository_scope IS NOT NULL
              AND state IN ('RESERVED','LAUNCHING','RUNNING')"""
        )


def attempts_support_hosted_operation(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='executor_attempts'"
    ).fetchone()
    return row is not None and "hosted_operation" in str(row[0])


def attempt_active_uniqueness(connection: sqlite3.Connection) -> str:
    """Classify the active partial-unique attempt index fail closed."""

    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='executor_attempts'"
    ).fetchone() is None:
        return "MISSING"
    active_indexes: list[tuple[str, tuple[str, ...]]] = []
    for index in connection.execute("PRAGMA index_list(executor_attempts)").fetchall():
        if not bool(index[2]) or not bool(index[4]):
            continue
        name = str(index[1])
        sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (name,)
        ).fetchone()
        normalized = (
            "" if sql_row is None else re.sub(r"\s+", "", str(sql_row[0]).lower())
        )
        if (
            "where" not in normalized
            or "statein('reserved','launching','running')" not in normalized
        ):
            continue
        columns = tuple(
            str(column[0])
            for column in connection.execute(
                "SELECT name FROM pragma_index_info(?) ORDER BY seqno", (name,)
            ).fetchall()
        )
        active_indexes.append((name, columns))
    indexed = {name: columns for name, columns in active_indexes}
    if indexed == {
        "executor_one_active_attempt_per_target": (
            "role", "target_kind", "target_key"
        ),
        "executor_one_active_attempt_per_lineage": ("lineage_sha256",),
        "executor_one_active_planner_per_repository": ("repository_scope",),
    }:
        return "ROLE_TARGET"
    if any(columns == ("role",) for _name, columns in active_indexes):
        return "ROLE_LEGACY"
    return "UPGRADE_REQUIRED"


def attempt_schema_is_current(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='executor_attempts'"
    ).fetchone()
    if row is None:
        return False
    sql = str(row[0])
    columns = {
        str(item[1]) for item in connection.execute("PRAGMA table_info(executor_attempts)")
    }
    required = {
        "systemd_unit",
        "systemd_invocation_id",
        "systemd_control_group",
        "repository_scope",
        "target_progress_sha256",
        "terminal_progress_sha256",
        "lineage_repository",
        "lineage_issue_number",
        "lineage_generation",
        "lineage_lease_sha256",
        "lineage_sha256",
    }
    return (
        "hosted_operation" in sql
        and "LAUNCHING" in sql
        and required <= columns
        and attempt_active_uniqueness(connection) == "ROLE_TARGET"
    )


def upgrade_attempt_schema(connection: sqlite3.Connection) -> None:
    """Upgrade attempts transactionally while preserving every historical row."""

    if attempt_schema_is_current(connection):
        return
    if connection.execute(
        "SELECT 1 FROM executor_attempts WHERE state IN ('RESERVED','LAUNCHING','RUNNING') LIMIT 1"
    ).fetchone():
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_ACTIVE_CONFLICT")
    old_columns = {
        str(item[1]) for item in connection.execute("PRAGMA table_info(executor_attempts)")
    }
    required_old = {
        "attempt_id", "role", "endpoint_id", "instance_id", "token_sha256",
        "target_kind", "target_key", "state", "process_id", "exit_code",
        "heartbeat_at", "version", "created_at", "updated_at", "last_error",
    }
    if not required_old <= old_columns:
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_DRIFT")
    events_present = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='executor_attempt_events'"
    ).fetchone() is not None
    required_events = {
        "event_id", "attempt_id", "from_state", "to_state", "from_version",
        "to_version", "reason", "evidence_sha256", "evidence_json", "recorded_at",
    }
    if events_present and not required_events <= {
        str(item[1])
        for item in connection.execute("PRAGMA table_info(executor_attempt_events)")
    }:
        raise RegistryError("EXECUTOR_ATTEMPT_EVENT_SCHEMA_CONFLICT")
    systemd_unit = "systemd_unit" if "systemd_unit" in old_columns else "NULL"
    invocation_id = (
        "systemd_invocation_id" if "systemd_invocation_id" in old_columns else "NULL"
    )
    control_group = (
        "systemd_control_group" if "systemd_control_group" in old_columns else "NULL"
    )
    repository_scope = (
        "lower(repository_scope)" if "repository_scope" in old_columns else "NULL"
    )
    target_progress_sha256 = (
        "target_progress_sha256" if "target_progress_sha256" in old_columns else "NULL"
    )
    terminal_progress_sha256 = (
        "terminal_progress_sha256"
        if "terminal_progress_sha256" in old_columns else "NULL"
    )
    lineage_repository = (
        "lineage_repository" if "lineage_repository" in old_columns else "NULL"
    )
    lineage_issue_number = (
        "lineage_issue_number" if "lineage_issue_number" in old_columns else "NULL"
    )
    lineage_generation = (
        "lineage_generation" if "lineage_generation" in old_columns else "NULL"
    )
    lineage_lease_sha256 = (
        "lineage_lease_sha256" if "lineage_lease_sha256" in old_columns else "NULL"
    )
    lineage_sha256 = "lineage_sha256" if "lineage_sha256" in old_columns else "NULL"
    statements = (
        "DROP TRIGGER IF EXISTS executor_attempt_event_immutable_update",
        "DROP TRIGGER IF EXISTS executor_attempt_event_immutable_delete",
        *(
            ("ALTER TABLE executor_attempt_events RENAME TO executor_attempt_events_legacy_schema",)
            if events_present else ()
        ),
        "DROP TRIGGER IF EXISTS executor_attempt_identity_immutable",
        "DROP INDEX IF EXISTS executor_one_active_attempt_per_role",
        "DROP INDEX IF EXISTS executor_one_active_attempt_per_target",
        "DROP INDEX IF EXISTS executor_one_active_attempt_per_lineage",
        "DROP INDEX IF EXISTS executor_one_active_planner_per_repository",
        "ALTER TABLE executor_attempts RENAME TO executor_attempts_legacy_schema",
        """CREATE TABLE executor_attempts (
            attempt_id TEXT PRIMARY KEY,
            role TEXT NOT NULL CHECK(role IN ('planner','development','sre')),
            endpoint_id TEXT NOT NULL,
            instance_id TEXT NOT NULL UNIQUE,
            token_sha256 TEXT NOT NULL,
            target_kind TEXT NOT NULL CHECK(target_kind IN ('message','terminal_watch','hosted_operation')),
            target_key TEXT NOT NULL,
            repository_scope TEXT,
            target_progress_sha256 TEXT,
            terminal_progress_sha256 TEXT,
            lineage_repository TEXT,
            lineage_issue_number INTEGER,
            lineage_generation INTEGER,
            lineage_lease_sha256 TEXT,
            lineage_sha256 TEXT,
            state TEXT NOT NULL CHECK(state IN ('RESERVED','LAUNCHING','RUNNING','COMPLETE','HOLD','LAUNCH_FAILED')),
            process_id INTEGER,
            exit_code INTEGER,
            systemd_unit TEXT,
            systemd_invocation_id TEXT,
            systemd_control_group TEXT,
            heartbeat_at TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_error TEXT,
            CHECK (target_progress_sha256 IS NULL OR length(target_progress_sha256)=64),
            CHECK (terminal_progress_sha256 IS NULL OR length(terminal_progress_sha256)=64),
            CHECK (
                (lineage_sha256 IS NULL
                 AND lineage_repository IS NULL
                 AND lineage_issue_number IS NULL
                 AND lineage_generation IS NULL
                 AND lineage_lease_sha256 IS NULL)
                OR
                (length(lineage_sha256)=64
                 AND lineage_repository IS NOT NULL
                 AND lineage_issue_number > 0
                 AND lineage_generation >= 0
                 AND length(lineage_lease_sha256)=64)
            ),
            FOREIGN KEY(endpoint_id) REFERENCES executor_role_endpoints(endpoint_id)
        )""",
        f"""INSERT INTO executor_attempts(
            attempt_id, role, endpoint_id, instance_id, token_sha256,
            target_kind, target_key, repository_scope, target_progress_sha256,
            terminal_progress_sha256,
            lineage_repository, lineage_issue_number,
            lineage_generation, lineage_lease_sha256, lineage_sha256,
            state, process_id, exit_code,
            systemd_unit, systemd_invocation_id, systemd_control_group,
            heartbeat_at, version, created_at, updated_at, last_error
        ) SELECT attempt_id, role, endpoint_id, instance_id, token_sha256,
                 target_kind, target_key, {repository_scope},
                 {target_progress_sha256}, {terminal_progress_sha256},
                 {lineage_repository},
                 {lineage_issue_number}, {lineage_generation},
                 {lineage_lease_sha256}, {lineage_sha256},
                 state, process_id, exit_code,
                 {systemd_unit}, {invocation_id}, {control_group},
                 heartbeat_at, version, created_at, updated_at, last_error
          FROM executor_attempts_legacy_schema""",
        """CREATE UNIQUE INDEX executor_one_active_attempt_per_target
            ON executor_attempts(role, target_kind, target_key)
            WHERE state IN ('RESERVED','LAUNCHING','RUNNING')""",
        """CREATE UNIQUE INDEX executor_one_active_attempt_per_lineage
            ON executor_attempts(lineage_sha256)
            WHERE lineage_sha256 IS NOT NULL
              AND state IN ('RESERVED','LAUNCHING','RUNNING')""",
        """CREATE UNIQUE INDEX executor_one_active_planner_per_repository
            ON executor_attempts(repository_scope)
            WHERE role='planner' AND repository_scope IS NOT NULL
              AND state IN ('RESERVED','LAUNCHING','RUNNING')""",
        """CREATE TRIGGER executor_attempt_identity_immutable
        BEFORE UPDATE ON executor_attempts
        WHEN NEW.attempt_id IS NOT OLD.attempt_id
          OR NEW.role IS NOT OLD.role
          OR NEW.endpoint_id IS NOT OLD.endpoint_id
          OR NEW.instance_id IS NOT OLD.instance_id
          OR NEW.token_sha256 IS NOT OLD.token_sha256
          OR NEW.target_kind IS NOT OLD.target_kind
          OR NEW.target_key IS NOT OLD.target_key
          OR NEW.repository_scope IS NOT OLD.repository_scope
          OR NEW.target_progress_sha256 IS NOT OLD.target_progress_sha256
          OR (OLD.terminal_progress_sha256 IS NOT NULL AND NEW.terminal_progress_sha256 IS NOT OLD.terminal_progress_sha256)
          OR NEW.lineage_repository IS NOT OLD.lineage_repository
          OR NEW.lineage_issue_number IS NOT OLD.lineage_issue_number
          OR NEW.lineage_generation IS NOT OLD.lineage_generation
          OR NEW.lineage_lease_sha256 IS NOT OLD.lineage_lease_sha256
          OR NEW.lineage_sha256 IS NOT OLD.lineage_sha256
          OR NEW.created_at IS NOT OLD.created_at
          OR (OLD.systemd_unit IS NOT NULL AND NEW.systemd_unit IS NOT OLD.systemd_unit)
          OR (OLD.systemd_invocation_id IS NOT NULL AND NEW.systemd_invocation_id IS NOT OLD.systemd_invocation_id)
          OR (OLD.systemd_control_group IS NOT NULL AND NEW.systemd_control_group IS NOT OLD.systemd_control_group)
          OR (OLD.process_id IS NOT NULL AND NEW.process_id IS NOT OLD.process_id)
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ATTEMPT_IDENTITY_IMMUTABLE'); END""",
        """CREATE TABLE executor_attempt_events (
            event_id TEXT PRIMARY KEY,
            attempt_id TEXT NOT NULL,
            from_state TEXT,
            to_state TEXT NOT NULL,
            from_version INTEGER,
            to_version INTEGER NOT NULL,
            reason TEXT,
            evidence_sha256 TEXT,
            evidence_json TEXT,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id)
        )""",
        *(
            ("""INSERT INTO executor_attempt_events(
                event_id, attempt_id, from_state, to_state, from_version,
                to_version, reason, evidence_sha256, evidence_json, recorded_at
            ) SELECT event_id, attempt_id, from_state, to_state, from_version,
                     to_version, reason, evidence_sha256, evidence_json, recorded_at
              FROM executor_attempt_events_legacy_schema""",
             "DROP TABLE executor_attempt_events_legacy_schema")
            if events_present else ()
        ),
        "DROP TABLE executor_attempts_legacy_schema",
        """CREATE TRIGGER executor_attempt_event_immutable_update
        BEFORE UPDATE ON executor_attempt_events
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ATTEMPT_EVENT_IMMUTABLE'); END""",
        """CREATE TRIGGER executor_attempt_event_immutable_delete
        BEFORE DELETE ON executor_attempt_events
        BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ATTEMPT_EVENT_IMMUTABLE'); END""",
    )
    for statement in statements:
        connection.execute(statement)
    if not attempt_schema_is_current(connection):
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_DRIFT")


# Backward-compatible import name for older migration callers.
upgrade_attempt_target_schema = upgrade_attempt_schema


def identity_role(connection: sqlite3.Connection, identity: str) -> str | None:
    """Resolve only an exact reviewed endpoint; syntax never grants a role."""

    if not isinstance(identity, str):
        return None
    configured_role = configured_identity_role(identity)
    if configured_role is None:
        return None
    endpoint_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='executor_role_endpoints'"
    ).fetchone()
    if endpoint_table is None:
        return configured_role
    endpoint = connection.execute(
        "SELECT role FROM executor_role_endpoints WHERE endpoint_id=?", (identity,)
    ).fetchone()
    if endpoint is None:
        return None
    if str(endpoint[0]) != configured_role:
        raise RegistryError("EXECUTOR_ENDPOINT_CATALOG_DRIFT")
    return configured_role


def _historical_identity_role(
    connection: sqlite3.Connection, identity: str
) -> str | None:
    """Resolve an exact endpoint or installed alias for readback/migration only."""

    role = identity_role(connection, identity)
    if role is not None:
        return role
    if not isinstance(identity, str):
        return None
    alias_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='executor_role_endpoint_aliases'"
    ).fetchone()
    if alias_table is None:
        return None
    alias = connection.execute(
        "SELECT role FROM executor_role_endpoint_aliases WHERE alias=?", (identity,)
    ).fetchone()
    return None if alias is None else str(alias[0])


def configured_identity_role(identity: str) -> str | None:
    """Resolve only endpoint IDs present in the reviewed versioned catalog."""

    if not isinstance(identity, str):
        return None
    scoped = _REGISTRY_CONFIG_SCOPE.get()
    endpoint = (scoped or load_registry_config()).endpoints.get(identity)
    return None if endpoint is None else endpoint.role


def identities_role_equivalent(
    connection: sqlite3.Connection, left: str, right: str
) -> bool:
    """Compare immutable historical identities by registered role.

    This compatibility relation is for migration, readback, and consuming
    historical rows.  It must not be used to validate a new mutable route.
    """

    left_role = _historical_identity_role(connection, left)
    return (
        left_role is not None
        and left_role == _historical_identity_role(connection, right)
    )


def applied_endpoint_rotation_chain(
    connection: sqlite3.Connection,
    *,
    repository: str,
    issue_number: int,
    before_identity: str,
    before_item_version: int,
    after_identity: str,
    after_item_version: int,
    watch_key: str | None = None,
    expected_watch_state: str | None = None,
    not_before: str | None = None,
    change_id: str | None = None,
    change_version: int | None = None,
) -> tuple[dict[str, Any], ...] | None:
    """Prove one immutable admission survived exact applied endpoint rotation.

    This is a consumption-only compatibility relation.  It never selects an
    endpoint or makes a historical identity current.  Every accepted hop must
    be an intact official migration-ledger row, an exact item transition, an
    exact same-role pointer transition, and (when requested) the matching
    terminal-watch transition from that same change.
    """

    if (
        REPOSITORY.fullmatch(repository) is None
        or type(issue_number) is not int
        or issue_number <= 0
        or type(before_item_version) is not int
        or before_item_version <= 0
        or type(after_item_version) is not int
        or after_item_version <= before_item_version
        or not isinstance(before_identity, str)
        or not isinstance(after_identity, str)
        or (watch_key is None) != (expected_watch_state is None)
        or (change_id is None) != (change_version is None)
        or (
            change_version is not None
            and (type(change_version) is not int or change_version <= 0)
        )
    ):
        return None
    role = identity_role(connection, before_identity)
    if role is None or identity_role(connection, after_identity) != role:
        return None
    if not all(
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        for table in (
            "executor_registry_changes",
            "executor_role_endpoints",
        )
    ):
        return None
    parameters: tuple[Any, ...] = ()
    predicate = "state='APPLIED'"
    if change_id is not None:
        predicate += " AND change_id=? AND version=?"
        parameters = (change_id, change_version)
    rows = connection.execute(
        f"SELECT * FROM executor_registry_changes WHERE {predicate} "
        "ORDER BY created_at, change_id",
        parameters,
    ).fetchall()
    cursor_identity = before_identity
    cursor_version = before_item_version
    steps: list[dict[str, Any]] = []
    for row in rows:
        if not_before is not None:
            try:
                if datetime.fromisoformat(
                    str(row["created_at"]).replace("Z", "+00:00")
                ) < datetime.fromisoformat(not_before.replace("Z", "+00:00")):
                    continue
            except (TypeError, ValueError):
                return None
        try:
            plan = json.loads(row["before_state_json"])
            after_state = json.loads(row["after_state_json"])
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(plan, dict) or not isinstance(after_state, dict):
            return None
        if any(
            not isinstance(container, list)
            for container in (
                plan.get("item_changes"),
                plan.get("watch_changes"),
                plan.get("pointer_changes"),
                after_state.get("items"),
                after_state.get("watches"),
                after_state.get("pointers"),
            )
        ):
            return None
        plan_digest_input = dict(plan)
        embedded_plan_sha256 = plan_digest_input.pop("plan_sha256", None)
        if (
            row["state"] != "APPLIED"
            or type(row["version"]) is not int
            or int(row["version"]) != 1
            or row["created_at"] != row["updated_at"]
            or not isinstance(row["operation_key"], str)
            or not row["operation_key"]
            or row["change_id"]
            != hashlib.sha256(
                f"{row['operation_key']}\0{row['before_state_sha256']}".encode(
                    "utf-8"
                )
            ).hexdigest()
            or canonical_json(plan) != row["before_state_json"]
            or canonical_json(after_state) != row["after_state_json"]
            or embedded_plan_sha256 != row["before_state_sha256"]
            or digest_json(plan_digest_input) != row["before_state_sha256"]
            or digest_json(after_state) != row["after_state_sha256"]
            or plan.get("kind") != "TWINFINITY_ROLE_ENDPOINT_MIGRATION_V1"
            or plan.get("config_sha256") != row["config_sha256"]
        ):
            return None
        item_changes = plan.get("item_changes")
        if not isinstance(item_changes, list):
            return None
        matching = [
            candidate
            for candidate in item_changes
            if isinstance(candidate, dict)
            and candidate.get("repository") == repository
            and candidate.get("issue_number") == issue_number
            and candidate.get("before_identity") == cursor_identity
            and candidate.get("before_version") == cursor_version
        ]
        if not matching:
            continue
        if len(matching) != 1:
            return None
        candidate = matching[0]
        if set(candidate) != {
            "repository",
            "issue_number",
            "before_identity",
            "after_identity",
            "before_version",
            "after_version",
        }:
            return None
        next_identity = candidate.get("after_identity")
        next_version = candidate.get("after_version")
        if (
            not isinstance(next_identity, str)
            or identity_role(connection, next_identity) != role
            or type(next_version) is not int
            or next_version != cursor_version + 1
        ):
            return None
        pointer_matches = [
            pointer
            for pointer in plan.get("pointer_changes", [])
            if isinstance(pointer, dict)
            and set(pointer)
            == {
                "role",
                "before_endpoint_id",
                "before_pointer_version",
                "after_endpoint_id",
                "after_pointer_version",
            }
            and pointer.get("role") == role
            and pointer.get("before_endpoint_id") == cursor_identity
            and pointer.get("after_endpoint_id") == next_identity
        ]
        after_item_matches = [
            item
            for item in after_state.get("items", [])
            if isinstance(item, dict)
            and set(item)
            == {
                "repository",
                "issue_number",
                "accountable_session_id",
                "version",
            }
            and item.get("repository") == repository
            and item.get("issue_number") == issue_number
            and item.get("accountable_session_id") == next_identity
            and item.get("version") == next_version
        ]
        after_pointer_matches = [
            pointer
            for pointer in after_state.get("pointers", [])
            if isinstance(pointer, dict)
            and set(pointer) == {"role", "endpoint_id", "pointer_version"}
            and pointer.get("role") == role
            and pointer.get("endpoint_id") == next_identity
            and pointer.get("pointer_version")
            == pointer_matches[0].get("after_pointer_version")
        ] if len(pointer_matches) == 1 else []
        if (
            len(pointer_matches) != 1
            or type(pointer_matches[0].get("before_pointer_version")) is not int
            or type(pointer_matches[0].get("after_pointer_version")) is not int
            or pointer_matches[0]["after_pointer_version"]
            != pointer_matches[0]["before_pointer_version"] + 1
            or len(after_pointer_matches) != 1
            or len(after_item_matches) != 1
        ):
            return None
        watch_transition: dict[str, Any] | None = None
        if watch_key is not None:
            watch_matches = [
                watch
                for watch in plan.get("watch_changes", [])
                if isinstance(watch, dict)
                and set(watch)
                == {
                    "watch_key",
                    "before_identity",
                    "after_identity",
                    "expected_state",
                    "expected_updated_at",
                }
                and watch.get("watch_key") == watch_key
                and watch.get("before_identity") == cursor_identity
                and watch.get("after_identity") == next_identity
                and watch.get("expected_state") == expected_watch_state
                and isinstance(watch.get("expected_updated_at"), str)
            ]
            after_watch_matches = [
                watch
                for watch in after_state.get("watches", [])
                if isinstance(watch, dict)
                and set(watch)
                == {
                    "watch_key",
                    "accountable_session_id",
                    "state",
                    "updated_at",
                }
                and watch.get("watch_key") == watch_key
                and watch.get("accountable_session_id") == next_identity
                and watch.get("state") == expected_watch_state
                and isinstance(watch.get("updated_at"), str)
            ]
            if len(watch_matches) != 1 or len(after_watch_matches) != 1:
                return None
            watch_transition = watch_matches[0]
        steps.append(
            {
                "change_id": str(row["change_id"]),
                "change_version": int(row["version"]),
                "before_identity": cursor_identity,
                "before_item_version": cursor_version,
                "after_identity": next_identity,
                "after_item_version": next_version,
                "watch_transition": watch_transition,
            }
        )
        cursor_identity = next_identity
        cursor_version = next_version
    if (
        not steps
        or cursor_identity != after_identity
        or cursor_version != after_item_version
        or (change_id is not None and len(steps) != 1)
    ):
        return None
    return tuple(steps)


def select_role_equivalent_identity(
    connection: sqlite3.Connection,
    requested_identity: str,
    candidates: list[str],
) -> str:
    """Prefer the current endpoint, otherwise one immutable alias of its role."""

    if _historical_identity_role(connection, requested_identity) is None:
        raise RegistryError("REGISTRY_IDENTITY_ROLE_UNKNOWN")
    canonical = canonical_endpoint_id(connection, requested_identity) or requested_identity
    equivalent = sorted({
        candidate
        for candidate in candidates
        if identities_role_equivalent(connection, candidate, canonical)
    })
    return canonical if canonical in equivalent or not equivalent else equivalent[0]


def registry_cutover_complete(connection: sqlite3.Connection) -> bool:
    """Return the monotonic cutover mode, inferring old installed registries."""

    state_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='executor_registry_state'"
    ).fetchone()
    if state_table is not None:
        row = connection.execute(
            "SELECT cutover_state FROM executor_registry_state WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise RegistryError("REGISTRY_CUTOVER_STATE_INVALID")
        return str(row[0]) == "CUTOVER_COMPLETE"
    pointer_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='executor_role_endpoint_current'"
    ).fetchone()
    if pointer_table is None:
        return False
    return bool(
        connection.execute(
            "SELECT 1 FROM executor_role_endpoint_current LIMIT 1"
        ).fetchone()
    )


def _require_complete_current_pointer_set(connection: sqlite3.Connection) -> None:
    if not registry_cutover_complete(connection):
        return
    rows = connection.execute(
        """
        SELECT current.role AS pointer_role, current.endpoint_id,
               endpoint.role AS endpoint_role
        FROM executor_role_endpoint_current current
        LEFT JOIN executor_role_endpoints endpoint
          ON endpoint.endpoint_id=current.endpoint_id
        ORDER BY current.role
        """
    ).fetchall()
    if (
        len(rows) != len(ROLES)
        or {str(row["pointer_role"]) for row in rows} != set(ROLES)
        or any(
            row["endpoint_role"] != row["pointer_role"]
            or ENDPOINT_ID.fullmatch(str(row["endpoint_id"])) is None
            for row in rows
        )
    ):
        raise RegistryError("REGISTRY_CURRENT_POINTER_SET_INCOMPLETE")


def current_endpoint(connection: sqlite3.Connection, role: str) -> sqlite3.Row | None:
    if role not in ROLES:
        raise RegistryError("REGISTRY_ROLE_INVALID")
    _require_complete_current_pointer_set(connection)
    return connection.execute(
        """
        SELECT endpoint.*, current.pointer_version, current.updated_at AS pointer_updated_at
        FROM executor_role_endpoint_current current
        JOIN executor_role_endpoints endpoint ON endpoint.endpoint_id=current.endpoint_id
        WHERE current.role=?
        """,
        (role,),
    ).fetchone()


def require_current_endpoint_identity(
    connection: sqlite3.Connection,
    identity: str,
    *,
    expected_role: str | None = None,
) -> str:
    """Require one exact registered current endpoint and a complete pointer set."""

    if not isinstance(identity, str) or (
        ENDPOINT_ID.fullmatch(identity) is None and UUID.fullmatch(identity) is None
    ):
        raise RegistryError("REGISTRY_IDENTITY_INVALID")
    if expected_role is not None and expected_role not in ROLES:
        raise RegistryError("REGISTRY_ROLE_INVALID")

    role = identity_role(connection, identity)
    if role is None:
        raise RegistryError("CURRENT_ROLE_ENDPOINT_REQUIRED")
    if expected_role is not None and role != expected_role:
        raise RegistryError("REGISTRY_IDENTITY_ROLE_MISMATCH")
    endpoint = current_endpoint(connection, role)
    if endpoint is None or str(endpoint["endpoint_id"]) != identity:
        raise RegistryError("CURRENT_ROLE_ENDPOINT_REQUIRED")
    return identity


def canonical_endpoint_id(connection: sqlite3.Connection, identity: str) -> str | None:
    role = _historical_identity_role(connection, identity)
    if role is None:
        return None
    endpoint = current_endpoint(connection, role)
    return None if endpoint is None else str(endpoint["endpoint_id"])


def endpoint_is_current(connection: sqlite3.Connection, endpoint_id: str) -> bool:
    role = identity_role(connection, endpoint_id)
    if role is None:
        return False
    endpoint = current_endpoint(connection, role)
    return endpoint is not None and endpoint["endpoint_id"] == endpoint_id


@contextmanager
def immediate_transaction(connection: sqlite3.Connection) -> Iterator[None]:
    if connection.in_transaction:
        savepoint = f"executor_registry_{uuid.uuid4().hex}"
        connection.execute(f"SAVEPOINT {savepoint}")
        try:
            yield
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        except Exception:
            connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        return
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def _insert_attempt_event(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    from_state: str | None,
    to_state: str,
    from_version: int | None,
    to_version: int,
    reason: str | None,
    evidence: dict[str, Any] | None,
    recorded_at: str,
) -> None:
    evidence_json = None if evidence is None else canonical_json(evidence)
    evidence_sha256 = (
        None
        if evidence_json is None
        else hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    )
    connection.execute(
        """
        INSERT INTO executor_attempt_events(
            event_id, attempt_id, from_state, to_state, from_version, to_version,
            reason, evidence_sha256, evidence_json, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()), attempt_id, from_state, to_state, from_version,
            to_version, reason, evidence_sha256, evidence_json, recorded_at,
        ),
    )


def attempt_lineage_for_target(
    connection: sqlite3.Connection, target_kind: str, target_key: str
) -> AttemptLineage | None:
    """Resolve the immutable delivery lineage from current typed target rows.

    Nonmutating coordination notices are deliberately lineage-free so they can
    fan out concurrently. Hosted operations retain their independent target
    fence because their schema does not carry a delivery generation and lease.
    """

    if target_kind == "message":
        try:
            message_id = int(target_key)
        except (TypeError, ValueError) as exc:
            raise RegistryError("EXECUTOR_LINEAGE_INVALID") from exc
        row = connection.execute(
            "SELECT topic, payload_json FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        if row is None:
            raise RegistryError("EXECUTOR_LINEAGE_INVALID")
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise RegistryError("EXECUTOR_LINEAGE_INVALID") from exc
        if row["topic"] == NONMUTATING_MESSAGE_TOPIC:
            if not isinstance(payload, dict) or payload.get("mutation_authority") is not False:
                raise RegistryError("EXECUTOR_LINEAGE_INVALID")
            return None
        source = payload.get("source") if isinstance(payload, dict) else None
        issue_number = payload.get("issue_number") if isinstance(payload, dict) else None
        if (
            not isinstance(source, dict)
            or source.get("object_kind") != "issue"
            or source.get("object_number") != issue_number
        ):
            raise RegistryError("EXECUTOR_LINEAGE_INVALID")
        return AttemptLineage(
            repository=source.get("repository"),
            issue_number=issue_number,
            generation=payload.get("generation"),
            lease_manifest_sha256=payload.get("lease_manifest_sha256"),
        )
    if target_kind == "terminal_watch":
        row = connection.execute(
            """SELECT repository, issue_number, generation, lease_manifest_sha256
            FROM coordination_terminal_watches WHERE watch_key=?""",
            (target_key,),
        ).fetchone()
        if row is None:
            raise RegistryError("EXECUTOR_LINEAGE_INVALID")
        return AttemptLineage(
            repository=row["repository"],
            issue_number=int(row["issue_number"]),
            generation=int(row["generation"]),
            lease_manifest_sha256=row["lease_manifest_sha256"],
        )
    if target_kind == "hosted_operation":
        return None
    raise RegistryError("EXECUTOR_LINEAGE_INVALID")


def repository_scope_for_target(
    connection: sqlite3.Connection, target_kind: str, target_key: str
) -> str | None:
    """Resolve a target's canonical immutable repository scope without writes."""

    if target_kind == "message":
        try:
            message_id = int(target_key)
        except (TypeError, ValueError):
            return None
        row = connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise RegistryError("EXECUTOR_REPOSITORY_SCOPE_INVALID") from exc
        source = payload.get("source") if isinstance(payload, dict) else None
        repository = source.get("repository") if isinstance(source, dict) else None
        return canonical_repository_scope(repository)
    if target_kind == "terminal_watch":
        row = connection.execute(
            "SELECT repository FROM coordination_terminal_watches WHERE watch_key=?",
            (target_key,),
        ).fetchone()
        return None if row is None else canonical_repository_scope(row["repository"])
    if target_kind == "hosted_operation":
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hosted_operations'"
        ).fetchone()
        if table is None:
            return None
        hosted_columns = {
            str(column[1])
            for column in connection.execute("PRAGMA table_info(hosted_operations)")
        }
        if "repository" not in hosted_columns:
            return None
        try:
            operation_id = int(target_key)
        except (TypeError, ValueError):
            return None
        row = connection.execute(
            "SELECT repository FROM hosted_operations WHERE id=?", (operation_id,)
        ).fetchone()
        return None if row is None else canonical_repository_scope(row["repository"])
    raise RegistryError("EXECUTOR_REPOSITORY_SCOPE_INVALID")


def target_progress_digest(
    connection: sqlite3.Connection, target_kind: str, target_key: str
) -> str:
    """Digest authoritative target progress while excluding scheduler bookkeeping."""

    if target_kind == "message":
        try:
            message_id = int(target_key)
        except (TypeError, ValueError) as exc:
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID") from exc
        row = connection.execute(
            "SELECT topic,payload_sha256,payload_json,state,claimed_by "
            "FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        if row is None:
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID")
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID") from exc
        source = payload.get("source") if isinstance(payload, dict) else None
        repository = source.get("repository") if isinstance(source, dict) else None
        issue_number = (
            payload.get("issue_number")
            if isinstance(payload, dict)
            else None
        )
        if type(issue_number) is not int and isinstance(source, dict):
            issue_number = source.get("object_number")
        progress: dict[str, Any] = {
            "claimed_by": row["claimed_by"],
            "payload_sha256": row["payload_sha256"],
            "state": row["state"],
            "topic": row["topic"],
        }
        if (
            row["topic"] != NONMUTATING_MESSAGE_TOPIC
            and isinstance(repository, str)
            and type(issue_number) is int
        ):
            item_row = connection.execute(
                """SELECT status,allocation_class,generation,accountable_session_id,
                          lease_manifest_sha256,source_payload_sha256,version
                   FROM coordination_items WHERE repository=? AND issue_number=?""",
                (repository, issue_number),
            ).fetchone()
            progress["item"] = None if item_row is None else dict(item_row)
            generation = payload.get("generation")
            watch_row = None
            if type(generation) is int:
                watch_row = connection.execute(
                    """SELECT state,last_heartbeat_at,generation,
                              accountable_session_id,lease_manifest_sha256
                       FROM coordination_terminal_watches
                       WHERE repository=? AND issue_number=? AND generation=?""",
                    (repository, issue_number, generation),
                ).fetchone()
            progress["terminal_watch"] = (
                None if watch_row is None else dict(watch_row)
            )
        return digest_json(progress)
    if target_kind == "terminal_watch":
        watch = connection.execute(
            """SELECT repository,issue_number,generation,accountable_session_id,
                      lease_manifest_sha256,state,last_heartbeat_at
               FROM coordination_terminal_watches WHERE watch_key=?""",
            (target_key,),
        ).fetchone()
        if watch is None:
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID")
        item = connection.execute(
            """SELECT status,allocation_class,generation,accountable_session_id,
                      lease_manifest_sha256,source_payload_sha256,version
               FROM coordination_items WHERE repository=? AND issue_number=?""",
            (watch["repository"], watch["issue_number"]),
        ).fetchone()
        return digest_json(
            {
                "item": None if item is None else dict(item),
                "watch": dict(watch),
            }
        )
    if target_kind == "hosted_operation":
        try:
            operation_id = int(target_key)
        except (TypeError, ValueError) as exc:
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID") from exc
        row = connection.execute(
            "SELECT * FROM hosted_operations WHERE id=?", (operation_id,)
        ).fetchone()
        if row is None:
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID")
        values = dict(row)
        progress_fields = (
            "state",
            "claimed_by",
            "scope_sha256",
            "receipt_outbox_id",
            "remote_receipt",
            "receipt_outcome",
            "receipt_payload_sha256",
            "retired_by_idempotency_key",
            "retired_at",
        )
        return digest_json(
            {field: values.get(field) for field in progress_fields if field in values}
        )
    raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID")


def planner_repository_for_target(
    connection: sqlite3.Connection, target_kind: str, target_key: str
) -> str | None:
    """Resolve the canonical repository scope for one Planner target."""

    if target_kind != "message":
        return None
    try:
        message_id = int(target_key)
    except (TypeError, ValueError) as exc:
        raise RegistryError("EXECUTOR_REPOSITORY_SCOPE_INVALID") from exc
    row = connection.execute(
        "SELECT recipient_session_id FROM coordination_messages WHERE id=?",
        (message_id,),
    ).fetchone()
    if row is None or identity_role(connection, row["recipient_session_id"]) != "planner":
        return None
    return repository_scope_for_target(connection, target_kind, target_key)


def _role_executor_child_ack_timestamp(
    value: str, *, error: str = "EXECUTOR_CHILD_ACK_OBSERVATION_INVALID"
) -> datetime:
    """Parse only canonical UTC RFC3339 timestamps used by ACK evidence."""

    if type(value) is not str or RFC3339_UTC.fullmatch(value) is None:
        raise RegistryError(error)
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise RegistryError(error) from None
    if instant.tzinfo is None or instant.utcoffset() != timedelta(0):
        raise RegistryError(error)
    return instant.astimezone(timezone.utc)


def _role_executor_integer_target_value(value: Any) -> Decimal | None:
    """Recognize integral SQLite numeric aliases without integer truncation."""

    if type(value) is not str:
        return None
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > 128
        or SQLITE_INTEGER_TARGET.fullmatch(candidate) is None
    ):
        return None
    try:
        number = Decimal(candidate)
    except InvalidOperation:
        return None
    if not number.is_finite() or number != number.to_integral_value():
        return None
    return number


def _role_executor_manager_receipt_sha256(
    systemd_unit: str, systemd_invocation_id: str
) -> str:
    return digest_json(
        {
            "schema": ROLE_EXECUTOR_MANAGER_SUBMISSION_SCHEMA,
            "systemd_invocation_id": systemd_invocation_id,
            "systemd_unit": systemd_unit,
        }
    )


def _validate_role_executor_child_ack_fence(
    fence: RoleExecutorChildAckFence,
) -> None:
    if (
        type(fence) is not RoleExecutorChildAckFence
        or fence.schema != ROLE_EXECUTOR_CHILD_ACK_FENCE_SCHEMA
        or fence.execution_class != ROLE_EXECUTOR_DIRECT_EXECUTION_CLASS
        or type(fence.role) is not str
        or fence.role not in ROLES
        or type(fence.endpoint_id) is not str
        or ENDPOINT_ID.fullmatch(fence.endpoint_id) is None
        or fence.endpoint_id.split(".")[1] != fence.role
        or type(fence.endpoint_pointer_version) is not int
        or fence.endpoint_pointer_version <= 0
        or type(fence.endpoint_config_sha256) is not str
        or SHA256.fullmatch(fence.endpoint_config_sha256) is None
        or type(fence.profile_sha256) is not str
        or SHA256.fullmatch(fence.profile_sha256) is None
        or (
            fence.execution_protocol is not None
            and (
                type(fence.execution_protocol) is not str
                or not fence.execution_protocol
            )
        )
        or type(fence.target_kind) is not str
        or fence.target_kind not in TARGET_KINDS
        or type(fence.target_key) is not str
        or not fence.target_key
        or type(fence.target_progress_sha256) is not str
        or SHA256.fullmatch(fence.target_progress_sha256) is None
        or type(fence.preexisting_attempt_ids) is not tuple
        or any(
            type(attempt_id) is not str or UUID.fullmatch(attempt_id) is None
            for attempt_id in fence.preexisting_attempt_ids
        )
        or tuple(sorted(fence.preexisting_attempt_ids))
        != fence.preexisting_attempt_ids
        or len(set(fence.preexisting_attempt_ids))
        != len(fence.preexisting_attempt_ids)
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_FENCE_INVALID")
    if fence.execution_protocol == BROKERED_READINESS_PROTOCOL:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXECUTION_CLASS_MISMATCH")
    if fence.target_kind in {"message", "hosted_operation"}:
        try:
            target_number = int(fence.target_key)
        except (TypeError, ValueError):
            raise RegistryError("EXECUTOR_CHILD_ACK_FENCE_INVALID") from None
        if target_number <= 0 or str(target_number) != fence.target_key:
            raise RegistryError("EXECUTOR_CHILD_ACK_FENCE_INVALID")
    lineage_values = (
        fence.lineage_repository,
        fence.lineage_issue_number,
        fence.lineage_generation,
        fence.lineage_lease_sha256,
        fence.lineage_sha256,
    )
    if all(value is None for value in lineage_values):
        return
    if any(value is None for value in lineage_values):
        raise RegistryError("EXECUTOR_CHILD_ACK_FENCE_INVALID")
    try:
        lineage = AttemptLineage(
            repository=fence.lineage_repository,
            issue_number=fence.lineage_issue_number,
            generation=fence.lineage_generation,
            lease_manifest_sha256=fence.lineage_lease_sha256,
        )
    except RegistryError:
        raise RegistryError("EXECUTOR_CHILD_ACK_FENCE_INVALID") from None
    if not secrets.compare_digest(lineage.sha256, str(fence.lineage_sha256)):
        raise RegistryError("EXECUTOR_CHILD_ACK_FENCE_INVALID")


def _role_executor_child_ack_endpoint_binding(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
) -> dict[str, Any]:
    if (
        type(role) is not str
        or role not in ROLES
        or type(endpoint_id) is not str
        or ENDPOINT_ID.fullmatch(endpoint_id) is None
        or endpoint_id.split(".")[1] != role
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_ENDPOINT_INVALID")
    endpoint = current_endpoint(connection, role)
    if endpoint is None or str(endpoint["endpoint_id"]) != endpoint_id:
        raise RegistryError("EXECUTOR_CHILD_ACK_ENDPOINT_NOT_CURRENT")
    try:
        payload = json.loads(endpoint["config_json"])
    except (TypeError, json.JSONDecodeError):
        raise RegistryError("EXECUTOR_CHILD_ACK_ENDPOINT_INVALID") from None
    profile_sha256 = payload.get("profile_sha256") if type(payload) is dict else None
    execution_protocol = (
        payload.get("execution_protocol") if type(payload) is dict else None
    )
    pointer_version = endpoint["pointer_version"]
    config_sha256 = endpoint["config_sha256"]
    if (
        type(payload) is not dict
        or payload.get("role") != role
        or payload.get("endpoint_id") != endpoint_id
        or canonical_json(payload) != endpoint["config_json"]
        or type(config_sha256) is not str
        or SHA256.fullmatch(config_sha256) is None
        or not secrets.compare_digest(digest_json(payload), config_sha256)
        or type(profile_sha256) is not str
        or SHA256.fullmatch(profile_sha256) is None
        or (
            execution_protocol is not None
            and (type(execution_protocol) is not str or not execution_protocol)
        )
        or type(pointer_version) is not int
        or pointer_version <= 0
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_ENDPOINT_INVALID")
    return {
        "endpoint_pointer_version": pointer_version,
        "endpoint_config_sha256": config_sha256,
        "profile_sha256": profile_sha256,
        "execution_protocol": execution_protocol,
    }


def _validate_role_executor_child_ack_target_route(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
) -> None:
    """Require the target's durable receiver to resolve to this endpoint."""

    try:
        if target_kind == "message":
            target_id = int(target_key)
            row = connection.execute(
                "SELECT recipient_session_id FROM coordination_messages WHERE id=?",
                (target_id,),
            ).fetchone()
            identity = None if row is None else row["recipient_session_id"]
        elif target_kind == "terminal_watch":
            row = connection.execute(
                "SELECT accountable_session_id FROM coordination_terminal_watches "
                "WHERE watch_key=?",
                (target_key,),
            ).fetchone()
            identity = None if row is None else row["accountable_session_id"]
        elif target_kind == "hosted_operation":
            target_id = int(target_key)
            row = connection.execute(
                "SELECT recipient_session_id FROM hosted_operations WHERE id=?",
                (target_id,),
            ).fetchone()
            identity = None if row is None else row["recipient_session_id"]
        else:
            raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_INVALID")
    except (TypeError, ValueError, sqlite3.Error):
        raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_INVALID") from None
    if type(identity) is not str or identity_role(connection, identity) != role:
        raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_INVALID")
    if target_kind in {"terminal_watch", "hosted_operation"}:
        if identity != endpoint_id:
            raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_INVALID")
        return
    if identity == endpoint_id:
        return
    alias = connection.execute(
        "SELECT role FROM executor_role_endpoint_aliases "
        "WHERE alias=? AND endpoint_id=?",
        (identity, endpoint_id),
    ).fetchone()
    if alias is None or alias["role"] != role:
        raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_INVALID")


def _role_executor_child_ack_fence_from_attempt(
    row: sqlite3.Row,
    *,
    endpoint_binding: dict[str, Any],
    preexisting_attempt_ids: tuple[str, ...],
) -> RoleExecutorChildAckFence:
    try:
        fence = RoleExecutorChildAckFence(
            schema=ROLE_EXECUTOR_CHILD_ACK_FENCE_SCHEMA,
            execution_class=ROLE_EXECUTOR_DIRECT_EXECUTION_CLASS,
            role=row["role"],
            endpoint_id=row["endpoint_id"],
            endpoint_pointer_version=endpoint_binding["endpoint_pointer_version"],
            endpoint_config_sha256=endpoint_binding["endpoint_config_sha256"],
            profile_sha256=endpoint_binding["profile_sha256"],
            execution_protocol=endpoint_binding["execution_protocol"],
            target_kind=row["target_kind"],
            target_key=row["target_key"],
            target_progress_sha256=row["target_progress_sha256"],
            preexisting_attempt_ids=preexisting_attempt_ids,
            lineage_repository=row["lineage_repository"],
            lineage_issue_number=row["lineage_issue_number"],
            lineage_generation=row["lineage_generation"],
            lineage_lease_sha256=row["lineage_lease_sha256"],
            lineage_sha256=row["lineage_sha256"],
        )
        _validate_role_executor_child_ack_fence(fence)
    except (KeyError, IndexError, TypeError, RegistryError):
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID") from None
    return fence


@contextmanager
def _role_executor_child_ack_read_snapshot(
    connection: sqlite3.Connection,
) -> Iterator[None]:
    """Hold one coherent SQLite view while deriving an ACK fence or receipt."""

    owns_snapshot = not connection.in_transaction
    if owns_snapshot:
        connection.execute("BEGIN")
    try:
        yield
    finally:
        if owns_snapshot and connection.in_transaction:
            connection.execute("ROLLBACK")


def _role_executor_logical_target_attempts(
    connection: sqlite3.Connection, *, target_kind: str, target_key: str
) -> list[sqlite3.Row]:
    """Return attempts for one durable target, including numeric aliases."""

    if target_kind == "terminal_watch":
        return connection.execute(
            "SELECT * FROM executor_attempts "
            "WHERE target_kind=? AND target_key=? ORDER BY created_at,attempt_id",
            (target_kind, target_key),
        ).fetchall()
    if target_kind not in {"message", "hosted_operation"}:
        raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_INVALID")
    expected_number = _role_executor_integer_target_value(target_key)
    if expected_number is None:
        raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_INVALID") from None
    rows = connection.execute(
        "SELECT * FROM executor_attempts WHERE target_kind=? "
        "ORDER BY created_at,attempt_id",
        (target_kind,),
    ).fetchall()
    matches: list[sqlite3.Row] = []
    for row in rows:
        candidate_number = _role_executor_integer_target_value(row["target_key"])
        if candidate_number is None:
            continue
        if candidate_number == expected_number:
            matches.append(row)
    return matches


def _snapshot_role_executor_child_ack_fence(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
) -> RoleExecutorChildAckFence:
    if (
        type(target_kind) is not str
        or target_kind not in TARGET_KINDS
        or type(target_key) is not str
        or not target_key
        or not attempt_schema_is_current(connection)
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_FENCE_INVALID")
    endpoint_binding = _role_executor_child_ack_endpoint_binding(
        connection, role=role, endpoint_id=endpoint_id
    )
    _validate_role_executor_child_ack_target_route(
        connection,
        role=role,
        endpoint_id=endpoint_id,
        target_kind=target_kind,
        target_key=target_key,
    )
    logical_attempts = _role_executor_logical_target_attempts(
        connection, target_kind=target_kind, target_key=target_key
    )
    if any(row["state"] in ACTIVE_ATTEMPT_STATES for row in logical_attempts):
        raise RegistryError("EXECUTOR_CHILD_ACK_PREEXISTING_ACTIVE")
    preexisting_attempt_ids = tuple(
        sorted(str(row["attempt_id"]) for row in logical_attempts)
    )
    target_progress_sha256 = target_progress_digest(
        connection, target_kind, target_key
    )
    lineage = attempt_lineage_for_target(connection, target_kind, target_key)
    fence = RoleExecutorChildAckFence(
        schema=ROLE_EXECUTOR_CHILD_ACK_FENCE_SCHEMA,
        execution_class=ROLE_EXECUTOR_DIRECT_EXECUTION_CLASS,
        role=role,
        endpoint_id=endpoint_id,
        endpoint_pointer_version=endpoint_binding["endpoint_pointer_version"],
        endpoint_config_sha256=endpoint_binding["endpoint_config_sha256"],
        profile_sha256=endpoint_binding["profile_sha256"],
        execution_protocol=endpoint_binding["execution_protocol"],
        target_kind=target_kind,
        target_key=target_key,
        target_progress_sha256=target_progress_sha256,
        preexisting_attempt_ids=preexisting_attempt_ids,
        lineage_repository=None if lineage is None else lineage.repository,
        lineage_issue_number=None if lineage is None else lineage.issue_number,
        lineage_generation=None if lineage is None else lineage.generation,
        lineage_lease_sha256=(
            None if lineage is None else lineage.lease_manifest_sha256
        ),
        lineage_sha256=None if lineage is None else lineage.sha256,
    )
    _validate_role_executor_child_ack_fence(fence)
    return fence


def snapshot_role_executor_child_ack_fence(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
) -> RoleExecutorChildAckFence:
    """Capture one coherent all-role attempt inventory before submission."""

    with _role_executor_child_ack_read_snapshot(connection):
        return _snapshot_role_executor_child_ack_fence(
            connection,
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
        )


def _role_executor_child_ack_fence_from_expectation(
    expectation: RoleExecutorChildAckExpectation,
) -> RoleExecutorChildAckFence:
    return RoleExecutorChildAckFence(
        schema=ROLE_EXECUTOR_CHILD_ACK_FENCE_SCHEMA,
        execution_class=expectation.execution_class,
        role=expectation.role,
        endpoint_id=expectation.endpoint_id,
        endpoint_pointer_version=expectation.endpoint_pointer_version,
        endpoint_config_sha256=expectation.endpoint_config_sha256,
        profile_sha256=expectation.profile_sha256,
        execution_protocol=expectation.execution_protocol,
        target_kind=expectation.target_kind,
        target_key=expectation.target_key,
        target_progress_sha256=expectation.target_progress_sha256,
        preexisting_attempt_ids=expectation.preexisting_attempt_ids,
        lineage_repository=expectation.lineage_repository,
        lineage_issue_number=expectation.lineage_issue_number,
        lineage_generation=expectation.lineage_generation,
        lineage_lease_sha256=expectation.lineage_lease_sha256,
        lineage_sha256=expectation.lineage_sha256,
    )


def _validate_role_executor_child_ack_expectation(
    expectation: RoleExecutorChildAckExpectation,
) -> None:
    if (
        type(expectation) is not RoleExecutorChildAckExpectation
        or expectation.schema != ROLE_EXECUTOR_CHILD_ACK_EXPECTATION_SCHEMA
        or expectation.execution_class != ROLE_EXECUTOR_DIRECT_EXECUTION_CLASS
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")
    try:
        fence = _role_executor_child_ack_fence_from_expectation(expectation)
        _validate_role_executor_child_ack_fence(fence)
        _role_executor_child_ack_timestamp(
            expectation.intent_recorded_at,
            error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
        )
        deadline_instant = _role_executor_child_ack_timestamp(
            expectation.observation_deadline_at,
            error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
        )
        intent_instant = _role_executor_child_ack_timestamp(
            expectation.intent_recorded_at,
            error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
        )
        expected_unit = stable_systemd_unit(
            expectation.role, expectation.target_kind, expectation.target_key
        )
    except RegistryError as exc:
        if str(exc) == "EXECUTOR_CHILD_ACK_EXECUTION_CLASS_MISMATCH":
            raise RegistryError(
                "EXECUTOR_CHILD_ACK_EXECUTION_CLASS_MISMATCH"
            ) from None
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID") from None
    expected_identity_sha256 = _role_executor_manager_receipt_sha256(
        expectation.systemd_unit, expectation.systemd_invocation_id
    )
    if (
        type(expectation.fence_sha256) is not str
        or SHA256.fullmatch(expectation.fence_sha256) is None
        or not secrets.compare_digest(expectation.fence_sha256, fence.sha256)
        or type(expectation.systemd_unit) is not str
        or expectation.systemd_unit != expected_unit
        or type(expectation.systemd_invocation_id) is not str
        or SYSTEMD_INVOCATION_ID.fullmatch(expectation.systemd_invocation_id) is None
        or expectation.manager_identity_source
        not in {
            ROLE_EXECUTOR_MANAGER_RECEIPT_IDENTITY_SOURCE,
            ROLE_EXECUTOR_CHILD_RECOVERY_IDENTITY_SOURCE,
        }
        or type(expectation.manager_identity_sha256) is not str
        or SHA256.fullmatch(expectation.manager_identity_sha256) is None
        or not secrets.compare_digest(
            expectation.manager_identity_sha256, expected_identity_sha256
        )
        or (
            expectation.manager_identity_source
            == ROLE_EXECUTOR_MANAGER_RECEIPT_IDENTITY_SOURCE
            and (
                type(expectation.manager_receipt_sha256) is not str
                or SHA256.fullmatch(expectation.manager_receipt_sha256) is None
                or not secrets.compare_digest(
                    expectation.manager_receipt_sha256, expected_identity_sha256
                )
            )
        )
        or (
            expectation.manager_identity_source
            == ROLE_EXECUTOR_CHILD_RECOVERY_IDENTITY_SOURCE
            and expectation.manager_receipt_sha256 is not None
        )
        or deadline_instant < intent_instant
        or deadline_instant - intent_instant
        > timedelta(seconds=ROLE_EXECUTOR_DEFAULT_ACK_WINDOW_SECONDS)
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")


def bind_role_executor_child_ack_expectation(
    fence: RoleExecutorChildAckFence,
    *,
    systemd_unit: str,
    systemd_invocation_id: str,
    intent_recorded_at: str,
    manager_receipt_sha256: str | None = None,
    observation_deadline_at: str | None = None,
    manager_identity_source: str = ROLE_EXECUTOR_MANAGER_RECEIPT_IDENTITY_SOURCE,
) -> RoleExecutorChildAckExpectation:
    """Bind a committed intent and exact manager receipt to one ACK fence."""

    _validate_role_executor_child_ack_fence(fence)
    identity_sha256 = _role_executor_manager_receipt_sha256(
        systemd_unit, systemd_invocation_id
    )
    if manager_identity_source not in {
        ROLE_EXECUTOR_MANAGER_RECEIPT_IDENTITY_SOURCE,
        ROLE_EXECUTOR_CHILD_RECOVERY_IDENTITY_SOURCE,
    }:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")
    if manager_identity_source == ROLE_EXECUTOR_MANAGER_RECEIPT_IDENTITY_SOURCE:
        if (
            type(manager_receipt_sha256) is not str
            or SHA256.fullmatch(manager_receipt_sha256) is None
            or not secrets.compare_digest(
                manager_receipt_sha256, identity_sha256
            )
        ):
            raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")
        bound_receipt_sha256: str | None = identity_sha256
    else:
        if manager_receipt_sha256 is not None:
            raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")
        bound_receipt_sha256 = None
    try:
        intent_instant = _role_executor_child_ack_timestamp(
            intent_recorded_at,
            error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
        )
        if observation_deadline_at is None:
            observation_deadline_at = (
                intent_instant
                + timedelta(seconds=ROLE_EXECUTOR_DEFAULT_ACK_WINDOW_SECONDS)
            ).isoformat().replace("+00:00", "Z")
        deadline_instant = _role_executor_child_ack_timestamp(
            observation_deadline_at,
            error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
        )
    except RegistryError:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID") from None
    if (
        deadline_instant < intent_instant
        or deadline_instant - intent_instant
        > timedelta(seconds=ROLE_EXECUTOR_DEFAULT_ACK_WINDOW_SECONDS)
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")
    expectation = RoleExecutorChildAckExpectation(
        schema=ROLE_EXECUTOR_CHILD_ACK_EXPECTATION_SCHEMA,
        execution_class=fence.execution_class,
        role=fence.role,
        endpoint_id=fence.endpoint_id,
        endpoint_pointer_version=fence.endpoint_pointer_version,
        endpoint_config_sha256=fence.endpoint_config_sha256,
        profile_sha256=fence.profile_sha256,
        execution_protocol=fence.execution_protocol,
        target_kind=fence.target_kind,
        target_key=fence.target_key,
        target_progress_sha256=fence.target_progress_sha256,
        preexisting_attempt_ids=fence.preexisting_attempt_ids,
        lineage_repository=fence.lineage_repository,
        lineage_issue_number=fence.lineage_issue_number,
        lineage_generation=fence.lineage_generation,
        lineage_lease_sha256=fence.lineage_lease_sha256,
        lineage_sha256=fence.lineage_sha256,
        fence_sha256=fence.sha256,
        systemd_unit=systemd_unit,
        systemd_invocation_id=systemd_invocation_id,
        manager_identity_source=manager_identity_source,
        manager_identity_sha256=identity_sha256,
        manager_receipt_sha256=bound_receipt_sha256,
        intent_recorded_at=intent_recorded_at,
        observation_deadline_at=observation_deadline_at,
    )
    _validate_role_executor_child_ack_expectation(expectation)
    return expectation


def _validate_role_executor_child_ack_event_chain(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> tuple[str, datetime, datetime | None, datetime]:
    """Validate the immutable lifecycle and return its digest and time bounds."""

    try:
        if type(row["version"]) is not int:
            raise TypeError
        version = row["version"]
        attempt_id = str(row["attempt_id"])
        instance_id = str(row["instance_id"])
        state = str(row["state"])
        token_sha256 = str(row["token_sha256"])
        process_id = row["process_id"]
        unit = str(row["systemd_unit"] or "")
        invocation_id = str(row["systemd_invocation_id"] or "")
        control_group = str(row["systemd_control_group"] or "")
        created_at = _role_executor_child_ack_timestamp(str(row["created_at"]))
        updated_at = _role_executor_child_ack_timestamp(str(row["updated_at"]))
        heartbeat_at = _role_executor_child_ack_timestamp(str(row["heartbeat_at"]))
    except (KeyError, IndexError, TypeError, ValueError, RegistryError):
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID") from None
    if (
        UUID.fullmatch(attempt_id) is None
        or UUID.fullmatch(instance_id) is None
        or SHA256.fullmatch(token_sha256) is None
        or state not in ATTEMPT_STATES
        or version <= 0
        or type(row["last_error"]) not in {str, type(None)}
        or (
            type(row["last_error"]) is str
            and secrets.compare_digest(
                hashlib.sha256(row["last_error"].encode("utf-8")).hexdigest(),
                token_sha256,
            )
        )
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID")
    launch_identity_present = bool(unit or invocation_id or control_group)
    if launch_identity_present and (
        unit
        != stable_systemd_unit(
            str(row["role"]), str(row["target_kind"]), str(row["target_key"])
        )
        or SYSTEMD_INVOCATION_ID.fullmatch(invocation_id) is None
        or not control_group.startswith("/")
        or not control_group.endswith(f"/{unit}")
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID")
    if state == "RESERVED" and (
        version != 1 or process_id is not None or launch_identity_present
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID")
    if state == "LAUNCHING" and (
        version != 2 or process_id is not None or not launch_identity_present
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID")
    if state == "RUNNING" and (
        version < 3
        or type(process_id) is not int
        or process_id <= 0
        or not launch_identity_present
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID")

    events = connection.execute(
        "SELECT * FROM executor_attempt_events WHERE attempt_id=? ORDER BY rowid",
        (attempt_id,),
    ).fetchall()
    if len(events) != version:
        raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_CHAIN_INVALID")
    allowed = {
        "RESERVED": {"LAUNCHING", "LAUNCH_FAILED", "HOLD"},
        "LAUNCHING": {"RUNNING", "LAUNCH_FAILED", "HOLD"},
        "RUNNING": {"RUNNING", "COMPLETE", "HOLD"},
        "COMPLETE": set(),
        "HOLD": set(),
        "LAUNCH_FAILED": set(),
    }
    projection: list[dict[str, Any]] = []
    event_instants: list[datetime] = []
    previous_state: str | None = None
    previous_version: int | None = None
    previous_instant: datetime | None = None
    running_instant: datetime | None = None
    for ordinal, event in enumerate(events, 1):
        try:
            if type(event["to_version"]) is not int or (
                event["from_version"] is not None
                and type(event["from_version"]) is not int
            ):
                raise TypeError
            to_version = event["to_version"]
            from_version = (
                None
                if event["from_version"] is None
                else event["from_version"]
            )
            recorded_instant = _role_executor_child_ack_timestamp(
                str(event["recorded_at"])
            )
        except (TypeError, ValueError, RegistryError):
            raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_CHAIN_INVALID") from None
        if (
            UUID.fullmatch(str(event["event_id"])) is None
            or type(event["reason"]) not in {str, type(None)}
            or (
                type(event["reason"]) is str
                and secrets.compare_digest(
                    hashlib.sha256(event["reason"].encode("utf-8")).hexdigest(),
                    token_sha256,
                )
            )
            or (previous_instant is not None and recorded_instant < previous_instant)
        ):
            raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_CHAIN_INVALID")
        if ordinal == 1:
            if (
                event["from_state"] is not None
                or event["from_version"] is not None
                or to_version != 1
                or event["to_state"] != "RESERVED"
                or event["reason"] != "ATTEMPT_RESERVED"
                or recorded_instant != created_at
            ):
                raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_CHAIN_INVALID")
        elif (
            event["from_state"] != previous_state
            or from_version != previous_version
            or to_version != int(previous_version) + 1
            or event["to_state"] not in allowed.get(str(previous_state), set())
        ):
            raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_CHAIN_INVALID")

        evidence_json = event["evidence_json"]
        evidence_sha256 = event["evidence_sha256"]
        if (evidence_json is None) != (evidence_sha256 is None):
            raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_EVIDENCE_INVALID")
        evidence = None
        if evidence_json is not None:
            try:
                evidence = json.loads(evidence_json)
            except (TypeError, json.JSONDecodeError):
                raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_EVIDENCE_INVALID") from None
            if (
                canonical_json(evidence) != evidence_json
                or type(evidence_sha256) is not str
                or SHA256.fullmatch(evidence_sha256) is None
                or not secrets.compare_digest(
                    hashlib.sha256(evidence_json.encode("utf-8")).hexdigest(),
                    evidence_sha256,
                )
            ):
                raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_EVIDENCE_INVALID")
        expected_evidence = None
        if event["to_state"] == "LAUNCHING":
            expected_evidence = {
                "systemd_control_group": control_group,
                "systemd_invocation_id": invocation_id,
                "systemd_unit": unit,
            }
            if event["reason"] is not None:
                raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_EVIDENCE_INVALID")
        elif (
            event["to_state"] in {"COMPLETE", "HOLD", "LAUNCH_FAILED"}
            and row["terminal_progress_sha256"] is not None
        ):
            expected_evidence = {
                "target_progress_sha256": row["target_progress_sha256"],
                "terminal_progress_sha256": row["terminal_progress_sha256"],
            }
        elif (
            event["from_state"] == "RUNNING"
            and event["to_state"] == "HOLD"
            and event["reason"] == "RECOVERED_STALE_ACTIVE_SYSTEMD_INACTIVE"
        ):
            recovery_keys = {
                "unit",
                "load_state",
                "active_state",
                "sub_state",
                "invocation_id",
                "control_group",
                "result",
                "memory_max",
                "tasks_max",
                "runtime_max_usec",
                "cpu_quota_per_sec_usec",
            }
            if (
                type(evidence) is not dict
                or set(evidence) != recovery_keys
                or any(type(value) is not str for value in evidence.values())
                or evidence["unit"] != unit
                or evidence["invocation_id"] != invocation_id
                or evidence["control_group"] != control_group
                or evidence["load_state"] != "loaded"
                or evidence["active_state"] != "inactive"
                or evidence["sub_state"] != "dead"
                or evidence["result"]
                not in {
                    "success",
                    "exit-code",
                    "signal",
                    "core-dump",
                    "watchdog",
                    "timeout",
                    "resources",
                    "protocol",
                }
            ):
                raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_EVIDENCE_INVALID")
            expected_evidence = evidence
        if evidence != expected_evidence:
            raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_EVIDENCE_INVALID")
        if event["to_state"] == "RUNNING" and running_instant is None:
            if event["from_state"] != "LAUNCHING" or to_version != 3:
                raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_CHAIN_INVALID")
            running_instant = recorded_instant
        projection.append(
            {
                "event_id": event["event_id"],
                "attempt_id": event["attempt_id"],
                "from_state": event["from_state"],
                "to_state": event["to_state"],
                "from_version": event["from_version"],
                "to_version": event["to_version"],
                "reason": event["reason"],
                "evidence_sha256": evidence_sha256,
                "evidence_json": evidence_json,
                "recorded_at": event["recorded_at"],
            }
        )
        previous_state = str(event["to_state"])
        previous_version = to_version
        previous_instant = recorded_instant
        event_instants.append(recorded_instant)
    if (
        previous_state != state
        or previous_version != version
        or previous_instant != updated_at
        or heartbeat_at not in event_instants
        or heartbeat_at > updated_at
        or (state == "RESERVED" and row["last_error"] is not None)
        or (state != "RESERVED" and events[-1]["reason"] != row["last_error"])
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_EVENT_CHAIN_INVALID")
    if state in {"COMPLETE", "HOLD"} and running_instant is not None:
        if type(process_id) is not int or process_id <= 0 or not launch_identity_present:
            raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID")
    assert previous_instant is not None
    return digest_json(projection), created_at, running_instant, previous_instant


def _observe_role_executor_child_ack(
    connection: sqlite3.Connection,
    *,
    expectation: RoleExecutorChildAckExpectation,
    not_after: str,
) -> RoleExecutorChildAcknowledgement | None:
    if not attempt_schema_is_current(connection):
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_MIGRATION_REQUIRED")
    _validate_role_executor_child_ack_expectation(expectation)
    intent_instant = _role_executor_child_ack_timestamp(
        expectation.intent_recorded_at,
        error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
    )
    bound_deadline_instant = _role_executor_child_ack_timestamp(
        expectation.observation_deadline_at,
        error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
    )
    observation_instant = _role_executor_child_ack_timestamp(not_after)
    if observation_instant < intent_instant:
        raise RegistryError("EXECUTOR_CHILD_ACK_OBSERVATION_INVALID")
    if observation_instant > bound_deadline_instant:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPIRED")

    endpoint_binding = _role_executor_child_ack_endpoint_binding(
        connection, role=expectation.role, endpoint_id=expectation.endpoint_id
    )
    if endpoint_binding != {
        "endpoint_pointer_version": expectation.endpoint_pointer_version,
        "endpoint_config_sha256": expectation.endpoint_config_sha256,
        "profile_sha256": expectation.profile_sha256,
        "execution_protocol": expectation.execution_protocol,
    }:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_DRIFT")
    _validate_role_executor_child_ack_target_route(
        connection,
        role=expectation.role,
        endpoint_id=expectation.endpoint_id,
        target_kind=expectation.target_kind,
        target_key=expectation.target_key,
    )
    candidates = _role_executor_logical_target_attempts(
        connection,
        target_kind=expectation.target_kind,
        target_key=expectation.target_key,
    )
    candidate_ids = tuple(sorted(str(row["attempt_id"]) for row in candidates))
    if not set(expectation.preexisting_attempt_ids).issubset(candidate_ids):
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_DRIFT")
    reused_receipt = connection.execute(
        "SELECT attempt_id,target_kind,target_key FROM executor_attempts "
        "WHERE (systemd_invocation_id=? OR systemd_unit=?) "
        "AND NOT (target_kind=? AND target_key=?) LIMIT 1",
        (
            expectation.systemd_invocation_id,
            expectation.systemd_unit,
            expectation.target_kind,
            expectation.target_key,
        ),
    ).fetchone()
    if reused_receipt is not None:
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    invocation_users = connection.execute(
        "SELECT attempt_id FROM executor_attempts "
        "WHERE systemd_invocation_id=? ORDER BY attempt_id",
        (expectation.systemd_invocation_id,),
    ).fetchall()
    fresh = [
        row
        for row in candidates
        if str(row["attempt_id"]) not in expectation.preexisting_attempt_ids
    ]
    if len(fresh) > 1:
        raise RegistryError("EXECUTOR_CHILD_ACK_AMBIGUOUS")
    if not fresh:
        if invocation_users:
            raise RegistryError("EXECUTOR_CHILD_ACK_REPLAY")
        return None
    row = fresh[0]
    if (
        row["role"] != expectation.role
        or row["endpoint_id"] != expectation.endpoint_id
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    invocation_attempt_ids = [str(item["attempt_id"]) for item in invocation_users]
    if row["state"] == "RESERVED" and invocation_attempt_ids:
        raise RegistryError("EXECUTOR_CHILD_ACK_REPLAY")
    if row["state"] != "RESERVED" and invocation_attempt_ids != [
        str(row["attempt_id"])
    ]:
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    temp_broker_shadow = connection.execute(
        "SELECT 1 FROM temp.sqlite_master "
        "WHERE type='table' AND name='role_executor_broker_runs'"
    ).fetchone() is not None
    if temp_broker_shadow:
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    broker_table_present = connection.execute(
        "SELECT 1 FROM main.sqlite_master "
        "WHERE type='table' AND name='role_executor_broker_runs'"
    ).fetchone() is not None
    broker_rows: list[sqlite3.Row] = []
    if broker_table_present:
        try:
            broker_rows = connection.execute(
                "SELECT attempt_id FROM main.role_executor_broker_runs "
                "WHERE attempt_id=?",
                (row["attempt_id"],),
            ).fetchall()
        except sqlite3.Error:
            raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED") from None
    if broker_rows:
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    execution_ownership_sha256 = digest_json(
        {
            "schema": "twinfinity-role-executor-execution-ownership/v1",
            "attempt_id": row["attempt_id"],
            "broker_table_present": broker_table_present,
            "broker_ownership_rows": [],
        }
    )
    event_chain_sha256, created_instant, running_instant, latest_instant = (
        _validate_role_executor_child_ack_event_chain(connection, row)
    )
    if created_instant < intent_instant:
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    if latest_instant > bound_deadline_instant:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPIRED")
    if latest_instant > observation_instant:
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    candidate_fence = _role_executor_child_ack_fence_from_attempt(
        row,
        endpoint_binding=endpoint_binding,
        preexisting_attempt_ids=expectation.preexisting_attempt_ids,
    )
    if candidate_fence != _role_executor_child_ack_fence_from_expectation(
        expectation
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    if row["state"] != "RESERVED" and (
        row["systemd_unit"] != expectation.systemd_unit
        or row["systemd_invocation_id"] != expectation.systemd_invocation_id
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    if row["state"] == "LAUNCH_FAILED":
        if not row["systemd_unit"] or not row["systemd_invocation_id"]:
            raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
        raise RegistryError("EXECUTOR_CHILD_ACK_LAUNCH_FAILED")
    if row["state"] in {"RESERVED", "LAUNCHING"}:
        if created_instant > bound_deadline_instant:
            raise RegistryError("EXECUTOR_CHILD_ACK_EXPIRED")
        return None
    if running_instant is None:
        raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
    if running_instant > bound_deadline_instant:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPIRED")
    derived_expectation = bind_role_executor_child_ack_expectation(
        candidate_fence,
        systemd_unit=str(row["systemd_unit"] or ""),
        systemd_invocation_id=str(row["systemd_invocation_id"] or ""),
        manager_receipt_sha256=expectation.manager_receipt_sha256,
        intent_recorded_at=expectation.intent_recorded_at,
        observation_deadline_at=expectation.observation_deadline_at,
        manager_identity_source=expectation.manager_identity_source,
    )
    if derived_expectation != expectation:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_DRIFT")

    current_progress_sha256 = target_progress_digest(
        connection, expectation.target_kind, expectation.target_key
    )
    accepted_progress_sha256 = expectation.target_progress_sha256
    if row["state"] in {"COMPLETE", "HOLD"} and row["terminal_progress_sha256"]:
        accepted_progress_sha256 = str(row["terminal_progress_sha256"])
    current_lineage = attempt_lineage_for_target(
        connection, expectation.target_kind, expectation.target_key
    )
    current_lineage_sha256 = (
        None if current_lineage is None else current_lineage.sha256
    )
    if (
        not secrets.compare_digest(current_progress_sha256, accepted_progress_sha256)
        or current_lineage_sha256 != expectation.lineage_sha256
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_TARGET_DRIFT")
    token_sha256 = str(row["token_sha256"])
    if SHA256.fullmatch(token_sha256) is None:
        raise RegistryError("EXECUTOR_CHILD_ACK_ATTEMPT_INVALID")
    return RoleExecutorChildAcknowledgement(
        schema=ROLE_EXECUTOR_CHILD_ACK_SCHEMA,
        expectation_sha256=expectation.sha256,
        fence_sha256=expectation.fence_sha256,
        manager_identity_source=expectation.manager_identity_source,
        manager_identity_sha256=expectation.manager_identity_sha256,
        manager_receipt_sha256=expectation.manager_receipt_sha256,
        intent_recorded_at=expectation.intent_recorded_at,
        observation_deadline_at=expectation.observation_deadline_at,
        attempt_id=str(row["attempt_id"]),
        instance_id=str(row["instance_id"]),
        token_sha256=token_sha256,
        event_chain_sha256=event_chain_sha256,
        execution_class=expectation.execution_class,
        execution_ownership_sha256=execution_ownership_sha256,
        role=expectation.role,
        endpoint_id=expectation.endpoint_id,
        endpoint_pointer_version=expectation.endpoint_pointer_version,
        endpoint_config_sha256=expectation.endpoint_config_sha256,
        profile_sha256=expectation.profile_sha256,
        execution_protocol=expectation.execution_protocol,
        target_kind=expectation.target_kind,
        target_key=expectation.target_key,
        target_progress_sha256=expectation.target_progress_sha256,
        lineage_sha256=expectation.lineage_sha256,
        state=str(row["state"]),
        version=int(row["version"]),
        process_id=int(row["process_id"]),
        systemd_unit=expectation.systemd_unit,
        systemd_invocation_id=expectation.systemd_invocation_id,
        systemd_control_group=str(row["systemd_control_group"]),
        token_authenticated=True,
        token_persisted=False,
    )


def observe_role_executor_child_ack(
    connection: sqlite3.Connection,
    *,
    expectation: RoleExecutorChildAckExpectation,
    not_after: str,
) -> RoleExecutorChildAcknowledgement | None:
    """Read and validate one exact child ACK in one coherent SQLite view."""

    with _role_executor_child_ack_read_snapshot(connection):
        return _observe_role_executor_child_ack(
            connection, expectation=expectation, not_after=not_after
        )


def recover_role_executor_child_ack_expectation(
    connection: sqlite3.Connection,
    *,
    fence: RoleExecutorChildAckFence,
    intent_recorded_at: str,
    observation_deadline_at: str,
    not_after: str,
) -> tuple[
    RoleExecutorChildAckExpectation, RoleExecutorChildAcknowledgement
] | None:
    """Recover an ambiguous submission only from its unique exact child ACK.

    The receipt identity is derived from the authenticated child's immutable
    launch event, never from a return code or reconstructed manager stdout.
    """

    _validate_role_executor_child_ack_fence(fence)
    try:
        intent_instant = _role_executor_child_ack_timestamp(
            intent_recorded_at,
            error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
        )
        deadline_instant = _role_executor_child_ack_timestamp(
            observation_deadline_at,
            error="EXECUTOR_CHILD_ACK_EXPECTATION_INVALID",
        )
        observation_instant = _role_executor_child_ack_timestamp(not_after)
    except RegistryError:
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID") from None
    if (
        deadline_instant < intent_instant
        or deadline_instant - intent_instant
        > timedelta(seconds=ROLE_EXECUTOR_DEFAULT_ACK_WINDOW_SECONDS)
        or observation_instant < intent_instant
        or observation_instant > deadline_instant
    ):
        raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")

    with _role_executor_child_ack_read_snapshot(connection):
        endpoint_binding = _role_executor_child_ack_endpoint_binding(
            connection, role=fence.role, endpoint_id=fence.endpoint_id
        )
        if endpoint_binding != {
            "endpoint_pointer_version": fence.endpoint_pointer_version,
            "endpoint_config_sha256": fence.endpoint_config_sha256,
            "profile_sha256": fence.profile_sha256,
            "execution_protocol": fence.execution_protocol,
        }:
            raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_DRIFT")
        _validate_role_executor_child_ack_target_route(
            connection,
            role=fence.role,
            endpoint_id=fence.endpoint_id,
            target_kind=fence.target_kind,
            target_key=fence.target_key,
        )
        candidates = _role_executor_logical_target_attempts(
            connection,
            target_kind=fence.target_kind,
            target_key=fence.target_key,
        )
        candidate_ids = {str(row["attempt_id"]) for row in candidates}
        if not set(fence.preexisting_attempt_ids).issubset(candidate_ids):
            raise RegistryError("EXECUTOR_CHILD_ACK_EXPECTATION_DRIFT")
        fresh = [
            row
            for row in candidates
            if str(row["attempt_id"]) not in fence.preexisting_attempt_ids
        ]
        if len(fresh) > 1:
            raise RegistryError("EXECUTOR_CHILD_ACK_AMBIGUOUS")
        if not fresh:
            return None
        row = fresh[0]
        if row["role"] != fence.role or row["endpoint_id"] != fence.endpoint_id:
            raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED")
        if row["state"] in {"RESERVED", "LAUNCHING"}:
            return None
        try:
            expectation = bind_role_executor_child_ack_expectation(
                fence,
                systemd_unit=row["systemd_unit"],
                systemd_invocation_id=row["systemd_invocation_id"],
                intent_recorded_at=intent_recorded_at,
                observation_deadline_at=observation_deadline_at,
                manager_identity_source=(
                    ROLE_EXECUTOR_CHILD_RECOVERY_IDENTITY_SOURCE
                ),
            )
        except RegistryError:
            raise RegistryError("EXECUTOR_CHILD_ACK_SUBSTITUTED") from None
        acknowledgement = _observe_role_executor_child_ack(
            connection,
            expectation=expectation,
            not_after=not_after,
        )
        if acknowledgement is None:
            return None
        return expectation, acknowledgement


def reserve_attempt(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
    now: str,
    precondition: Callable[[sqlite3.Connection], AttemptLineage | None],
) -> tuple[dict[str, Any], str]:
    """Reserve one exact target and its logical delivery lineage atomically."""

    if (
        not isinstance(role, str)
        or role not in ROLES
        or not isinstance(target_kind, str)
        or target_kind not in TARGET_KINDS
        or not isinstance(target_key, str)
        or not target_key
    ):
        raise RegistryError("EXECUTOR_ATTEMPT_INVALID")
    if target_kind in {"message", "hosted_operation"}:
        target_number = _role_executor_integer_target_value(target_key)
        # Low-level registry tests may use non-Planner synthetic keys. Numeric
        # durable identifiers, however, have one canonical positive form.
        if target_number is not None and (
            target_number <= 0
            or CANONICAL_INTEGER_TARGET.fullmatch(target_key) is None
        ):
            raise RegistryError("EXECUTOR_ATTEMPT_INVALID")
    try:
        _role_executor_child_ack_timestamp(now, error="EXECUTOR_ATTEMPT_INVALID")
    except RegistryError:
        raise RegistryError("EXECUTOR_ATTEMPT_INVALID") from None
    ensure_executor_registry_schema(connection)
    if not attempt_schema_is_current(connection):
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_MIGRATION_REQUIRED")
    token = secrets.token_urlsafe(32)
    token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
    attempt_id = str(uuid.uuid4())
    instance_id = str(uuid.uuid4())
    with immediate_transaction(connection):
        lineage = precondition(connection)
        if lineage is not None and not isinstance(lineage, AttemptLineage):
            raise RegistryError("EXECUTOR_LINEAGE_INVALID")
        repository_scope = repository_scope_for_target(
            connection, target_kind, target_key
        )
        try:
            target_progress_sha256 = target_progress_digest(
                connection, target_kind, target_key
            )
        except RegistryError:
            # Low-level registry callers may reserve synthetic non-Planner
            # targets behind their own precondition. Canonical role executors
            # always validate a concrete row and therefore persist a digest.
            target_progress_sha256 = None
        if role == "planner" and repository_scope is None:
            raise RegistryError("EXECUTOR_REPOSITORY_SCOPE_INVALID")
        endpoint = current_endpoint(connection, role)
        if endpoint is None or endpoint["endpoint_id"] != endpoint_id:
            raise RegistryError("EXECUTOR_ENDPOINT_NOT_CURRENT")
        active = connection.execute(
            "SELECT attempt_id FROM executor_attempts WHERE role=? AND target_kind=? "
            "AND target_key=? AND state IN ('RESERVED','LAUNCHING','RUNNING')",
            (role, target_kind, target_key),
        ).fetchone()
        if active is not None:
            raise RegistryError("EXECUTOR_TARGET_BUSY")
        if lineage is not None:
            active_lineage = connection.execute(
                "SELECT attempt_id FROM executor_attempts WHERE lineage_sha256=? "
                "AND state IN ('RESERVED','LAUNCHING','RUNNING')",
                (lineage.sha256,),
            ).fetchone()
            if active_lineage is not None:
                raise RegistryError("EXECUTOR_LINEAGE_BUSY")
        if role == "planner" and connection.execute(
            """
            SELECT 1 FROM executor_attempts
            WHERE role='planner' AND repository_scope=?
              AND state IN ('RESERVED','LAUNCHING','RUNNING')
            """,
            (repository_scope,),
        ).fetchone() is not None:
            raise RegistryError("EXECUTOR_REPOSITORY_BUSY")
        connection.execute(
            """
            INSERT INTO executor_attempts(
                attempt_id, role, endpoint_id, instance_id, token_sha256,
                target_kind, target_key, repository_scope,
                target_progress_sha256, terminal_progress_sha256,
                lineage_repository, lineage_issue_number,
                lineage_generation, lineage_lease_sha256, lineage_sha256,
                state, process_id, exit_code,
                heartbeat_at, version, created_at, updated_at, last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?,
                      'RESERVED', NULL, NULL, ?, 1, ?, ?, NULL)
            """,
            (
                attempt_id,
                role,
                endpoint_id,
                instance_id,
                token_sha256,
                target_kind,
                target_key,
                repository_scope,
                target_progress_sha256,
                None if lineage is None else lineage.repository,
                None if lineage is None else lineage.issue_number,
                None if lineage is None else lineage.generation,
                None if lineage is None else lineage.lease_manifest_sha256,
                None if lineage is None else lineage.sha256,
                now,
                now,
                now,
            ),
        )
        _insert_attempt_event(
            connection,
            attempt_id=attempt_id,
            from_state=None,
            to_state="RESERVED",
            from_version=None,
            to_version=1,
            reason="ATTEMPT_RESERVED",
            evidence=None,
            recorded_at=now,
        )
        row = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
    return dict(row), token


def active_attempt_for_lineage(
    connection: sqlite3.Connection, lineage_sha256: str
) -> sqlite3.Row | None:
    """Return the sole active attempt for one immutable logical lineage."""

    if (
        not isinstance(lineage_sha256, str)
        or SHA256.fullmatch(lineage_sha256) is None
        or not attempt_schema_is_current(connection)
    ):
        raise RegistryError("EXECUTOR_LINEAGE_FENCE_UNAVAILABLE")
    return connection.execute(
        """
        SELECT * FROM executor_attempts
        WHERE lineage_sha256=?
          AND state IN ('RESERVED','LAUNCHING','RUNNING')
        """,
        (lineage_sha256,),
    ).fetchone()


def active_planner_attempt_for_repository(
    connection: sqlite3.Connection, repository: str
) -> sqlite3.Row | None:
    """Return the sole active Planner attempt for one canonical repository."""

    repository_scope = canonical_repository_scope(repository)
    if repository_scope is None or not attempt_schema_is_current(connection):
        raise RegistryError("EXECUTOR_REPOSITORY_FENCE_UNAVAILABLE")
    return connection.execute(
        """
        SELECT * FROM executor_attempts
        WHERE role='planner' AND repository_scope=?
          AND state IN ('RESERVED','LAUNCHING','RUNNING')
        """,
        (repository_scope,),
    ).fetchone()


def transition_attempt(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    token: str,
    expected_version: int,
    new_state: str,
    now: str,
    process_id: int | None = None,
    exit_code: int | None = None,
    last_error: str | None = None,
    systemd_unit: str | None = None,
    systemd_invocation_id: str | None = None,
    systemd_control_group: str | None = None,
    terminal_progress_sha256: str | None = None,
) -> dict[str, Any]:
    """Apply a token-bound optimistic transition or heartbeat."""

    if (
        type(attempt_id) is not str
        or UUID.fullmatch(attempt_id) is None
        or type(token) is not str
        or not token
        or type(expected_version) is not int
        or expected_version <= 0
        or type(new_state) is not str
        or new_state not in ATTEMPT_STATES
        or type(now) is not str
        or type(last_error) not in {str, type(None)}
        or type(exit_code) not in {int, type(None)}
        or isinstance(exit_code, bool)
        or type(process_id) not in {int, type(None)}
        or isinstance(process_id, bool)
        or type(systemd_unit) not in {str, type(None)}
        or type(systemd_invocation_id) not in {str, type(None)}
        or type(systemd_control_group) not in {str, type(None)}
        or type(terminal_progress_sha256) not in {str, type(None)}
    ):
        raise RegistryError("EXECUTOR_ATTEMPT_INVALID")
    effective_last_error = last_error
    if last_error is not None and token in last_error:
        effective_last_error = EXECUTOR_PRIVATE_ERROR_REDACTED
    durable_inputs = (
        now,
        systemd_unit,
        systemd_invocation_id,
        systemd_control_group,
        terminal_progress_sha256,
        None if exit_code is None else str(exit_code),
        None if process_id is None else str(process_id),
    )
    if any(type(value) is str and token in value for value in durable_inputs):
        raise RegistryError("EXECUTOR_PRIVATE_VALUE_REJECTED")
    try:
        _role_executor_child_ack_timestamp(
            now, error="EXECUTOR_ATTEMPT_INVALID"
        )
    except RegistryError:
        raise RegistryError("EXECUTOR_ATTEMPT_INVALID") from None
    token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
    ensure_executor_registry_schema(connection)
    if not attempt_schema_is_current(connection):
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_MIGRATION_REQUIRED")
    with immediate_transaction(connection):
        row = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise RegistryError("EXECUTOR_ATTEMPT_NOT_FOUND")
        if not secrets.compare_digest(str(row["token_sha256"]), token_sha256):
            raise RegistryError("EXECUTOR_TOKEN_MISMATCH")
        if any(
            type(value) is str and token in value
            for value in dict(row).values()
        ):
            raise RegistryError("EXECUTOR_PRIVATE_VALUE_REJECTED")
        if type(row["version"]) is not int or row["version"] != expected_version:
            raise RegistryError("EXECUTOR_ATTEMPT_VERSION_CONFLICT")
        try:
            prior_instant = _role_executor_child_ack_timestamp(
                str(row["updated_at"]), error="EXECUTOR_ATTEMPT_INVALID"
            )
            current_instant = _role_executor_child_ack_timestamp(
                now, error="EXECUTOR_ATTEMPT_INVALID"
            )
        except RegistryError:
            raise RegistryError("EXECUTOR_ATTEMPT_INVALID") from None
        if current_instant < prior_instant:
            raise RegistryError("EXECUTOR_ATTEMPT_TIMESTAMP_REGRESSION")
        old_state = str(row["state"])
        allowed = {
            "RESERVED": {"LAUNCHING", "LAUNCH_FAILED", "HOLD"},
            "LAUNCHING": {"RUNNING", "LAUNCH_FAILED", "HOLD"},
            "RUNNING": {"RUNNING", "COMPLETE", "HOLD"},
            "COMPLETE": {"COMPLETE"},
            "HOLD": {"HOLD"},
            "LAUNCH_FAILED": {"LAUNCH_FAILED"},
        }
        if new_state not in allowed[old_state]:
            raise RegistryError("EXECUTOR_ATTEMPT_STATE_CONFLICT")
        if terminal_progress_sha256 is not None and (
            new_state not in {"COMPLETE", "HOLD", "LAUNCH_FAILED"}
            or SHA256.fullmatch(terminal_progress_sha256) is None
        ):
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_INVALID")
        prior_terminal_progress = row["terminal_progress_sha256"]
        if (
            prior_terminal_progress is not None
            and terminal_progress_sha256 is not None
            and terminal_progress_sha256 != prior_terminal_progress
        ):
            raise RegistryError("EXECUTOR_TARGET_PROGRESS_CONFLICT")
        effective_terminal_progress = (
            prior_terminal_progress
            if terminal_progress_sha256 is None
            else terminal_progress_sha256
        )
        unit = row["systemd_unit"] if systemd_unit is None else systemd_unit
        invocation_id = (
            row["systemd_invocation_id"]
            if systemd_invocation_id is None
            else systemd_invocation_id
        )
        control_group = (
            row["systemd_control_group"]
            if systemd_control_group is None
            else systemd_control_group
        )
        if new_state == "LAUNCHING":
            if (
                old_state != "RESERVED"
                or unit != stable_systemd_unit(
                    str(row["role"]), str(row["target_kind"]), str(row["target_key"])
                )
                or not isinstance(invocation_id, str)
                or SYSTEMD_INVOCATION_ID.fullmatch(invocation_id) is None
                or not isinstance(control_group, str)
                or not control_group.startswith("/")
                or not control_group.endswith(f"/{unit}")
                or process_id is not None
            ):
                raise RegistryError("EXECUTOR_LAUNCH_IDENTITY_INVALID")
        if old_state in {"LAUNCHING", "RUNNING"} and (
            unit != row["systemd_unit"]
            or invocation_id != row["systemd_invocation_id"]
            or control_group != row["systemd_control_group"]
        ):
            raise RegistryError("EXECUTOR_LAUNCH_IDENTITY_CONFLICT")
        if old_state in {"COMPLETE", "HOLD", "LAUNCH_FAILED"}:
            replay_values_match = (
                now == row["updated_at"]
                and process_id == row["process_id"]
                and systemd_unit == row["systemd_unit"]
                and systemd_invocation_id == row["systemd_invocation_id"]
                and systemd_control_group == row["systemd_control_group"]
                and exit_code == row["exit_code"]
                and effective_last_error == row["last_error"]
                and terminal_progress_sha256 == row["terminal_progress_sha256"]
            )
            if not replay_values_match:
                raise RegistryError("EXECUTOR_ATTEMPT_STATE_CONFLICT")
            return dict(row)
        old_process_id = row["process_id"]
        if new_state == "RUNNING":
            effective_process_id = (
                int(old_process_id) if process_id is None and old_process_id is not None
                else process_id
            )
            if (
                old_state == "LAUNCHING"
                and (type(effective_process_id) is not int or effective_process_id <= 0)
            ) or (
                old_state == "RUNNING" and effective_process_id != old_process_id
            ):
                raise RegistryError("EXECUTOR_PROCESS_ID_INVALID")
        else:
            effective_process_id = old_process_id
            if process_id is not None:
                raise RegistryError("EXECUTOR_PROCESS_ID_INVALID")
        version = expected_version + 1
        cursor = connection.execute(
            """
            UPDATE executor_attempts
            SET state=?, process_id=?, exit_code=?, systemd_unit=?,
                systemd_invocation_id=?, systemd_control_group=?, heartbeat_at=?,
                terminal_progress_sha256=?, version=?, updated_at=?, last_error=?
            WHERE attempt_id=? AND version=?
            """,
            (
                new_state,
                effective_process_id,
                exit_code,
                unit,
                invocation_id,
                control_group,
                now,
                effective_terminal_progress,
                version,
                now,
                effective_last_error,
                attempt_id,
                expected_version,
            ),
        )
        if cursor.rowcount != 1:
            raise RegistryError("EXECUTOR_ATTEMPT_VERSION_CONFLICT")
        evidence = None
        if new_state == "LAUNCHING":
            evidence = {
                "systemd_unit": unit,
                "systemd_invocation_id": invocation_id,
                "systemd_control_group": control_group,
            }
        elif terminal_progress_sha256 is not None:
            evidence = {
                "target_progress_sha256": row["target_progress_sha256"],
                "terminal_progress_sha256": terminal_progress_sha256,
            }
        _insert_attempt_event(
            connection,
            attempt_id=attempt_id,
            from_state=old_state,
            to_state=new_state,
            from_version=expected_version,
            to_version=version,
            reason=effective_last_error,
            evidence=evidence,
            recorded_at=now,
        )
        updated = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
    return dict(updated)


def recover_reserved_attempts(
    connection: sqlite3.Connection,
    *,
    before: str,
    now: str,
) -> list[str]:
    """Fail closed on stale pre-launch reservations without retrying launch."""

    ensure_executor_registry_schema(connection)
    if not attempt_schema_is_current(connection):
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_MIGRATION_REQUIRED")
    recovered: list[str] = []
    with immediate_transaction(connection):
        broker_table = connection.execute(
            """
            SELECT 1 FROM main.sqlite_master
            WHERE type='table' AND name='role_executor_broker_runs'
            """
        ).fetchone() is not None
        broker_fence = (
            " AND NOT EXISTS (SELECT 1 FROM main.role_executor_broker_runs broker "
            "WHERE broker.attempt_id=executor_attempts.attempt_id "
            "AND broker.state IN ('PREPARING','LAUNCHING','RUNNING'))"
            if broker_table
            else ""
        )
        rows = connection.execute(
            "SELECT attempt_id, version FROM executor_attempts "
            "WHERE state='RESERVED' AND heartbeat_at<?"
            + broker_fence
            + " ORDER BY created_at",
            (before,),
        ).fetchall()
        for row in rows:
            cursor = connection.execute(
                """
                UPDATE executor_attempts
                SET state='LAUNCH_FAILED', version=version+1, updated_at=?,
                    last_error='RECOVERED_RESERVED_LAUNCH_FAILURE'
                WHERE attempt_id=? AND state='RESERVED' AND version=?
                """,
                (now, row["attempt_id"], row["version"]),
            )
            if cursor.rowcount == 1:
                _insert_attempt_event(
                    connection,
                    attempt_id=str(row["attempt_id"]),
                    from_state="RESERVED",
                    to_state="LAUNCH_FAILED",
                    from_version=int(row["version"]),
                    to_version=int(row["version"]) + 1,
                    reason="RECOVERED_RESERVED_LAUNCH_FAILURE",
                    evidence=None,
                    recorded_at=now,
                )
                recovered.append(str(row["attempt_id"]))
    return recovered


def recover_stale_active_attempts(
    connection: sqlite3.Connection,
    *,
    before: str,
    now: str,
    evidence_reader: Callable[[str], SystemdUnitEvidence] = probe_systemd_unit,
) -> list[dict[str, str]]:
    """Recover only identity-exact stale attempts proven inactive by systemd."""

    ensure_executor_registry_schema(connection)
    if not attempt_schema_is_current(connection):
        raise RegistryError("EXECUTOR_ATTEMPT_SCHEMA_MIGRATION_REQUIRED")
    broker_table = connection.execute(
        """
        SELECT 1 FROM main.sqlite_master
        WHERE type='table' AND name='role_executor_broker_runs'
        """
    ).fetchone() is not None
    broker_fence = (
        " AND NOT EXISTS (SELECT 1 FROM main.role_executor_broker_runs broker "
        "WHERE broker.attempt_id=executor_attempts.attempt_id "
        "AND broker.state IN ('PREPARING','LAUNCHING','RUNNING'))"
        if broker_table
        else ""
    )
    candidates = connection.execute(
        "SELECT * FROM executor_attempts "
        "WHERE state IN ('LAUNCHING','RUNNING') AND heartbeat_at<?"
        + broker_fence
        + " ORDER BY created_at",
        (before,),
    ).fetchall()
    results: list[dict[str, str]] = []
    for candidate in candidates:
        attempt_id = str(candidate["attempt_id"])
        unit = str(candidate["systemd_unit"] or "")
        invocation_id = str(candidate["systemd_invocation_id"] or "")
        control_group = str(candidate["systemd_control_group"] or "")
        expected_unit = stable_systemd_unit(
            str(candidate["role"]),
            str(candidate["target_kind"]),
            str(candidate["target_key"]),
        )
        if (
            unit != expected_unit
            or SYSTEMD_INVOCATION_ID.fullmatch(invocation_id) is None
            or not control_group.startswith("/")
            or not control_group.endswith(f"/{unit}")
        ):
            results.append({
                "attempt_id": attempt_id,
                "phase": "HOLD",
                "error": "STALE_RECOVERY_STORED_IDENTITY_INVALID",
            })
            continue
        try:
            evidence = evidence_reader(unit)
        except (OSError, subprocess.SubprocessError, RegistryError):
            results.append({
                "attempt_id": attempt_id,
                "phase": "HOLD",
                "error": "STALE_RECOVERY_SYSTEMD_EVIDENCE_FAILED",
            })
            continue
        if type(evidence) is not SystemdUnitEvidence:
            results.append({
                "attempt_id": attempt_id,
                "phase": "HOLD",
                "error": "STALE_RECOVERY_SYSTEMD_EVIDENCE_FAILED",
            })
            continue
        evidence_payload = evidence.payload
        if (
            type(evidence_payload) is not dict
            or any(type(value) is not str for value in evidence_payload.values())
        ):
            results.append({
                "attempt_id": attempt_id,
                "phase": "HOLD",
                "error": "STALE_RECOVERY_SYSTEMD_EVIDENCE_FAILED",
            })
            continue
        if (
            evidence.unit != unit
            or evidence.invocation_id != invocation_id
            or evidence.control_group != control_group
        ):
            results.append({
                "attempt_id": attempt_id,
                "phase": "HOLD",
                "error": "STALE_RECOVERY_SYSTEMD_IDENTITY_MISMATCH",
            })
            continue
        if (
            evidence.load_state != "loaded"
            or evidence.active_state != "inactive"
            or evidence.sub_state != "dead"
            or evidence.result not in {
                "success",
                "exit-code",
                "signal",
                "core-dump",
                "watchdog",
                "timeout",
                "resources",
                "protocol",
            }
        ):
            results.append({
                "attempt_id": attempt_id,
                "phase": "HOLD",
                "error": "STALE_RECOVERY_SYSTEMD_NOT_PROVEN_INACTIVE",
            })
            continue
        with immediate_transaction(connection):
            current = connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            broker_active = (
                connection.execute(
                    """
                    SELECT 1 FROM main.role_executor_broker_runs
                    WHERE attempt_id=? AND state IN ('PREPARING','LAUNCHING','RUNNING')
                    """,
                    (attempt_id,),
                ).fetchone()
                if broker_table
                else None
            )
            if broker_active is not None:
                results.append({
                    "attempt_id": attempt_id,
                    "phase": "HOLD",
                    "error": "STALE_RECOVERY_BROKER_OWNS_ATTEMPT",
                })
                continue
            if (
                current is None
                or current["state"] != candidate["state"]
                or current["version"] != candidate["version"]
                or current["heartbeat_at"] != candidate["heartbeat_at"]
                or current["heartbeat_at"] >= before
                or current["systemd_unit"] != unit
                or current["systemd_invocation_id"] != invocation_id
                or current["systemd_control_group"] != control_group
            ):
                results.append({
                    "attempt_id": attempt_id,
                    "phase": "HOLD",
                    "error": "STALE_RECOVERY_ATTEMPT_CAS_CONFLICT",
                })
                continue
            latest_event = connection.execute(
                "SELECT * FROM executor_attempt_events WHERE attempt_id=? "
                "ORDER BY rowid DESC LIMIT 1",
                (attempt_id,),
            ).fetchone()
            launch_event = connection.execute(
                "SELECT * FROM executor_attempt_events "
                "WHERE attempt_id=? AND to_state='LAUNCHING' "
                "ORDER BY rowid DESC LIMIT 1",
                (attempt_id,),
            ).fetchone()
            launch_evidence = canonical_json({
                "systemd_control_group": control_group,
                "systemd_invocation_id": invocation_id,
                "systemd_unit": unit,
            })
            if (
                latest_event is None
                or latest_event["to_state"] != current["state"]
                or int(latest_event["to_version"]) != int(current["version"])
                or launch_event is None
                or launch_event["evidence_json"] != launch_evidence
            ):
                results.append({
                    "attempt_id": attempt_id,
                    "phase": "HOLD",
                    "error": "STALE_RECOVERY_EVENT_HISTORY_INCOMPLETE",
                })
                continue
            cursor = connection.execute(
                """
                UPDATE executor_attempts
                SET state='HOLD', version=version+1, updated_at=?,
                    last_error='RECOVERED_STALE_ACTIVE_SYSTEMD_INACTIVE'
                WHERE attempt_id=? AND state=? AND version=? AND heartbeat_at=?
                """,
                (
                    now, attempt_id, candidate["state"], candidate["version"],
                    candidate["heartbeat_at"],
                ),
            )
            if cursor.rowcount != 1:
                raise RegistryError("EXECUTOR_ATTEMPT_VERSION_CONFLICT")
            _insert_attempt_event(
                connection,
                attempt_id=attempt_id,
                from_state=str(candidate["state"]),
                to_state="HOLD",
                from_version=int(candidate["version"]),
                to_version=int(candidate["version"]) + 1,
                reason="RECOVERED_STALE_ACTIVE_SYSTEMD_INACTIVE",
                evidence=evidence_payload,
                recorded_at=now,
            )
        results.append({
            "attempt_id": attempt_id,
            "phase": "RECOVERED",
            "state": "HOLD",
        })
    return results


def active_attempt_for_target(
    connection: sqlite3.Connection,
    identity: str,
    target_kind: str,
    target_key: str,
) -> sqlite3.Row | None:
    """Return an active attempt only for the exact role-bound target."""

    role = identity_role(connection, identity)
    if (
        role is None
        or not isinstance(target_kind, str)
        or target_kind not in TARGET_KINDS
        or not isinstance(target_key, str)
        or not target_key
    ):
        return None
    return connection.execute(
        """
        SELECT * FROM executor_attempts
        WHERE role=? AND target_kind=? AND target_key=?
          AND state IN ('RESERVED','LAUNCHING','RUNNING')
        ORDER BY created_at DESC LIMIT 1
        """,
        (role, target_kind, target_key),
    ).fetchone()


def _validate_existing_owner_database(path: Path) -> None:
    """Validate an existing database without creating or changing filesystem state."""

    try:
        for directory in [*reversed(path.parent.parents), path.parent]:
            directory_metadata = directory.lstat()
            if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(
                directory_metadata.st_mode
            ):
                raise RegistryError("DATABASE_PARENT_UNSAFE")
        parent = path.parent.lstat()
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise RegistryError("DATABASE_MISSING") from exc
    if (
        parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise RegistryError("DATABASE_PARENT_UNSAFE")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RegistryError("DATABASE_UNSAFE")


def open_registry_database(
    path: Path = DEFAULT_DATABASE,
    *,
    read_only: bool = False,
    initialize_schema: bool = True,
) -> sqlite3.Connection:
    if read_only:
        _validate_existing_owner_database(path)
        connection = sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, isolation_level=None, timeout=5
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection
    try:
        prepare_owner_database(path)
    except UnsafeSQLitePathError as exc:
        raise RegistryError(str(exc)) from exc
    connection = sqlite3.connect(path, isolation_level=None, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    if initialize_schema:
        ensure_executor_registry_schema(connection)
    return connection


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--profile-root",
        type=Path,
        help=(
            "read both portable and staged installed profile bytes from this "
            "directory; audit-config only"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("audit-config")
    recover = subparsers.add_parser("recover-reserved")
    recover.add_argument("--older-than-seconds", type=int, default=120)
    recover_active = subparsers.add_parser("recover-active")
    recover_active.add_argument("--older-than-seconds", type=int, default=120)
    args = parser.parse_args()
    try:
        if args.command == "audit-config":
            if args.profile_root is None:
                config = load_registry_config(args.config)
            else:
                config = load_registry_config(
                    args.config,
                    codex_home=args.profile_root,
                    profile_template_root=args.profile_root,
                    profile_validation_scope="catalog",
                )
            print(canonical_json({
                "phase": "PASS",
                "config_sha256": config.source_sha256,
                "endpoints": {role: value.endpoint_id for role, value in config.roles.items()},
                "staged_endpoints": list(config.staged_endpoint_ids),
            }))
            return 0
        if args.profile_root is not None:
            raise RegistryError("REGISTRY_PROFILE_ROOT_AUDIT_ONLY")
        if args.older_than_seconds <= 0:
            raise RegistryError("RECOVERY_WINDOW_INVALID")
        now = utc_now()
        connection = open_registry_database(DEFAULT_DATABASE)
        try:
            before = timestamp_before(now, args.older_than_seconds)
            if args.command == "recover-reserved":
                recovered = recover_reserved_attempts(
                    connection, before=before, now=now
                )
            else:
                recovered = recover_stale_active_attempts(
                    connection, before=before, now=now
                )
        finally:
            connection.close()
        print(canonical_json({"phase": "PASS", "recovered_attempts": recovered}))
        return 0
    except (OSError, RegistryError) as exc:
        error = str(exc) if isinstance(exc, RegistryError) else "REGISTRY_IO_ERROR"
        print(canonical_json({"phase": "HOLD", "error": error}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
