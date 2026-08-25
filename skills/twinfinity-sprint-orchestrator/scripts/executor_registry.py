#!/usr/bin/env python3
"""Immutable role endpoints and ephemeral executor-attempt registry."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
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
ROOT_KEYS = {"schema_version", "roles", "historical_endpoints"}
COMMON_ROLE_KEYS = {
    "endpoint_id",
    "version",
    "executor_profile",
    "codex_profile",
    "command_prefix",
    "allowed_topics",
}
PROFILED_ROLE_KEYS = COMMON_ROLE_KEYS | {"profile_sha256"}
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

    @property
    def payload(self) -> dict[str, Any]:
        value = asdict(self)
        if not self.profile_sha256:
            value.pop("profile_sha256")
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
    source_sha256: str
    source_evidence: OwnerFileEvidence
    profile_evidence: tuple[OwnerFileEvidence, ...]
    codex_home: str
    profile_template_root: str


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

    @property
    def payload(self) -> dict[str, str]:
        return asdict(self)


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
    )
    if current.source_evidence != config.source_evidence:
        raise RegistryError("REGISTRY_CONFIG_DRIFT")
    if current.profile_evidence != config.profile_evidence:
        raise RegistryError("REGISTRY_PROFILE_DRIFT")
    if (
        current.schema_version != config.schema_version
        or current.roles != config.roles
        or current.endpoints != config.endpoints
        or current.source_sha256 != config.source_sha256
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

    if not isinstance(value, dict) or set(value) != PROFILED_ROLE_KEYS:
        raise RegistryError("REGISTRY_CONFIG_ROLE_SCHEMA_INVALID")
    endpoint_id = value.get("endpoint_id")
    version = value.get("version")
    executor_profile = value.get("executor_profile")
    codex_profile = value.get("codex_profile")
    profile_sha256 = value.get("profile_sha256", "")
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
    ):
        raise RegistryError("REGISTRY_CONFIG_ROLE_INVALID")
    command_prefix = _validate_string_list(
        value.get("command_prefix"), "REGISTRY_CONFIG_COMMAND_INVALID"
    )
    allowed_topics = _validate_string_list(
        value.get("allowed_topics"), "REGISTRY_CONFIG_TOPICS_INVALID"
    )
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
    )


def load_registry_config(
    path: Path = DEFAULT_CONFIG,
    *,
    codex_home: Path | None = None,
    profile_template_root: Path = DEFAULT_PROFILE_TEMPLATE_ROOT,
) -> RegistryConfig:
    """Load the closed current-and-rollback endpoint catalog."""

    raw, source_evidence = _read_regular_owner_file(path, "REGISTRY_CONFIG")
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RegistryError("REGISTRY_CONFIG_INVALID_TOML") from exc
    if set(parsed) != ROOT_KEYS or parsed.get("schema_version") != 2:
        raise RegistryError("REGISTRY_CONFIG_SCHEMA_INVALID")
    role_values = parsed.get("roles")
    historical_values = parsed.get("historical_endpoints")
    if not isinstance(role_values, dict) or set(role_values) != set(ROLES):
        raise RegistryError("REGISTRY_CONFIG_ROLES_INVALID")
    if not isinstance(historical_values, list):
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
    effective_codex_home = codex_home or _default_codex_home()
    profile_evidence = _validate_role_profiles(
        endpoints,
        codex_home=effective_codex_home,
        profile_template_root=profile_template_root,
    )
    return RegistryConfig(
        schema_version=2,
        roles=roles,
        endpoints=endpoints,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_evidence=source_evidence,
        profile_evidence=profile_evidence,
        codex_home=os.path.abspath(os.fspath(effective_codex_home)),
        profile_template_root=os.path.abspath(os.fspath(profile_template_root)),
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
    endpoint = load_registry_config().endpoints.get(identity)
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

    if new_state not in ATTEMPT_STATES or expected_version <= 0:
        raise RegistryError("EXECUTOR_ATTEMPT_INVALID")
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
        if int(row["version"]) != expected_version:
            raise RegistryError("EXECUTOR_ATTEMPT_VERSION_CONFLICT")
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
        version = (
            expected_version
            if new_state == old_state and old_state not in ACTIVE_ATTEMPT_STATES
            else expected_version + 1
        )
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
                last_error,
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
            reason=last_error,
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
        rows = connection.execute(
            """
            SELECT attempt_id, version FROM executor_attempts
            WHERE state='RESERVED' AND heartbeat_at<? ORDER BY created_at
            """,
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
    candidates = connection.execute(
        """
        SELECT * FROM executor_attempts
        WHERE state IN ('LAUNCHING','RUNNING') AND heartbeat_at<?
        ORDER BY created_at
        """,
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
                evidence=evidence.payload,
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
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("audit-config")
    recover = subparsers.add_parser("recover-reserved")
    recover.add_argument("--older-than-seconds", type=int, default=120)
    recover_active = subparsers.add_parser("recover-active")
    recover_active.add_argument("--older-than-seconds", type=int, default=120)
    args = parser.parse_args()
    try:
        if args.command == "audit-config":
            config = load_registry_config(args.config)
            print(canonical_json({
                "phase": "PASS",
                "config_sha256": config.source_sha256,
                "endpoints": {role: value.endpoint_id for role, value in config.roles.items()},
            }))
            return 0
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
