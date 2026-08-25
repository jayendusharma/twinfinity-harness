#!/usr/bin/env python3
"""Create or validate one manifest-authenticated clean coordination database."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
from typing import Any

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    canonical_json,
    parse_structured_lease_manifest,
)
from approval_ledger import ensure_schema as ensure_approval_schema
from executor_registry import RegistryError, load_registry_config, registry_config_scope
from hosted_operation_control import HostedOperationControl
from kanban_pull_buffer import ensure_pull_buffer_schema
from kanban_readiness import ensure_schema as ensure_readiness_schema
from owner_safe_sqlite import (
    UnsafeSQLitePathError,
    open_owner_database_readonly,
    validate_owner_database,
)
from reconcile_routing_artifacts import (
    _verify_or_insert_endpoint,
    apply_plan,
    build_plan,
)
from role_executor_broker import ensure_broker_schema


DEFAULT_CANONICAL_DATABASE = (
    Path.home() / ".codex" / "twinfinity-coordination" / "ack-transactions.sqlite3"
)
SCHEMA = "twinfinity-clean-control-plane-bootstrap/v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
EXPECTED_ENDPOINTS = {
    "planner": "role.planner.v2",
    "development": "role.development.v3",
    "sre": "role.sre.v3",
}
SOURCE_HARNESS_REPOSITORY = "jayendusharma/twinfinity-harness"
STRANDED_IDENTITIES = {
    328: (2, "c448fd19-40a6-4511-bdf7-9ca7bbbb2788"),
    329: (1, "d7f69b5a-dc4c-4d1e-b434-da4ab6cdb2d5"),
}
ARCHIVE_CAMPAIGN_BASE_COLUMNS = (
    "id",
    "repository",
    "issue_number",
    "generation",
    "item_version",
    "source_payload_sha256",
    "accepted_main_sha",
    "graph_version",
    "capacity_policy_version",
    "candidate_sha256",
    "worker_role",
    "phase_summary",
    "plan_sha256",
    "plan_json",
)
ARCHIVE_CAMPAIGN_TRANSITION_COLUMNS = (
    "parent_campaign_id",
    "transition_kind",
    "resolution_ordinal",
)
ARCHIVE_CAMPAIGN_CURRENT_ONLY_COLUMNS = (
    "changed_evidence_sha256",
    "resolution_action_set_sha256",
    "approval_proposal_sha256",
    "approval_decision_sha256",
    "approval_recipient_session_id",
    "approval_execution_scope_sha256",
)
ARCHIVE_LEGACY_CAMPAIGN_COLUMNS = frozenset(
    (*ARCHIVE_CAMPAIGN_BASE_COLUMNS, "created_at")
)
ARCHIVE_CURRENT_CAMPAIGN_COLUMNS = frozenset(
    (
        *ARCHIVE_CAMPAIGN_BASE_COLUMNS,
        *ARCHIVE_CAMPAIGN_TRANSITION_COLUMNS,
        *ARCHIVE_CAMPAIGN_CURRENT_ONLY_COLUMNS,
        "created_at",
    )
)
ARCHIVE_LEGACY_TRANSITION_SENTINELS = {
    field: f"LEGACY_SCHEMA_FIELD_ABSENT:{field}"
    for field in ARCHIVE_CAMPAIGN_TRANSITION_COLUMNS
}
ARCHIVE_CAMPAIGN_FIELDS = (
    "campaign_id",
    "repository",
    "issue_number",
    "generation",
    "item_version",
    "source_payload_sha256",
    "accepted_main_sha",
    "graph_version",
    "capacity_policy_version",
    "candidate_sha256",
    "worker_role",
    "phase_summary",
    "plan_sha256",
    "plan_json",
    "parent_campaign_id",
    "transition_kind",
    "resolution_ordinal",
    "campaign_state",
    "message_id",
    "attempt_id",
    "endpoint_id",
    "current_version",
)
ARCHIVE_LINEAGE_KEYS = {
    "repository",
    "issue_number",
    "campaign_id",
    "attempt_id",
    "source_payload_sha256",
    "campaign_sha256",
    "candidate_sha256",
    "plan_sha256",
    "message_payload_sha256",
    "campaign_state",
    "candidate_state",
    "message_id",
    "message_state",
    "attempt_state",
    "disposition",
    "receipt_fabricated",
}


class CleanControlPlaneError(RuntimeError):
    """A closed manifest or clean database invariant failed."""


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def archive_campaign_digest(row: sqlite3.Row) -> str:
    """Digest the exact archived campaign and current-pointer projection."""

    return digest_json({field: row[field] for field in ARCHIVE_CAMPAIGN_FIELDS})


def _archive_campaign_schema(connection: sqlite3.Connection) -> str:
    columns = frozenset(
        str(row["name"])
        for row in connection.execute(
            "PRAGMA table_info(portfolio_readiness_campaigns)"
        )
    )
    if columns == ARCHIVE_CURRENT_CAMPAIGN_COLUMNS:
        return "current"
    if columns == ARCHIVE_LEGACY_CAMPAIGN_COLUMNS:
        return "legacy"
    raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_CAMPAIGN_SCHEMA_INVALID")


def manifest_digest(manifest: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    return digest_json(unsigned)


def _require_keys(value: Any, keys: set[str], error: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CleanControlPlaneError(error)
    return value


def _require_sha(value: Any, error: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise CleanControlPlaneError(error)
    return value


def _require_git_sha(value: Any, error: str) -> str:
    if not isinstance(value, str) or GIT_SHA.fullmatch(value) is None:
        raise CleanControlPlaneError(error)
    return value


def _require_timestamp(value: Any, error: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CleanControlPlaneError(error)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CleanControlPlaneError(error) from exc
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CleanControlPlaneError("BOOTSTRAP_MANIFEST_UNREADABLE") from exc
    if not isinstance(value, dict):
        raise CleanControlPlaneError("BOOTSTRAP_MANIFEST_SCHEMA_INVALID")
    return value


def _source_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise CleanControlPlaneError("BOOTSTRAP_SOURCE_PATH_UNSAFE")
    candidate = Path(os.path.abspath(root / relative))
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        metadata = candidate.lstat()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise CleanControlPlaneError("BOOTSTRAP_SOURCE_PATH_UNSAFE") from exc
    if (
        candidate != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise CleanControlPlaneError("BOOTSTRAP_SOURCE_PATH_UNSAFE")
    return candidate


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _archive_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _git_repository_from_remote(value: str) -> str | None:
    normalized = value.strip()
    for prefix in (
        "https://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ):
        if normalized.startswith(prefix):
            repository = normalized[len(prefix) :].removesuffix(".git")
            return repository if REPOSITORY.fullmatch(repository) else None
    return None


def _validate_source_git(
    source_root: Path,
    *,
    repository: str,
    commit: str,
    bound_paths: list[str],
) -> None:
    """Bind the source root and every reviewed input to one exact Git commit."""

    environment = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}

    def git(*arguments: str) -> bytes:
        try:
            return subprocess.run(
                ["git", "-C", str(source_root), *arguments],
                check=True,
                capture_output=True,
                env=environment,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise CleanControlPlaneError("BOOTSTRAP_SOURCE_GIT_INVALID") from exc

    try:
        declared_root = source_root.resolve(strict=True)
        top = Path(
            git("rev-parse", "--show-toplevel").decode().strip()
        ).resolve(strict=True)
        head = git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        remote = git("config", "--get", "remote.origin.url").decode().strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise CleanControlPlaneError("BOOTSTRAP_SOURCE_GIT_INVALID") from exc
    if (
        top != declared_root
        or head != commit
        or _git_repository_from_remote(remote) != repository
    ):
        raise CleanControlPlaneError("BOOTSTRAP_SOURCE_GIT_MISMATCH")
    for relative in bound_paths:
        path = _source_file(source_root, relative)
        try:
            committed = git("show", f"{commit}:{relative}")
        except CleanControlPlaneError as exc:
            raise CleanControlPlaneError("BOOTSTRAP_SOURCE_GIT_MISMATCH") from exc
        if path.read_bytes() != committed:
            raise CleanControlPlaneError("BOOTSTRAP_SOURCE_GIT_MISMATCH")


def _validate_archive_lineages(
    connection: sqlite3.Connection,
    lineages: list[dict[str, Any]],
    application_repository: str,
) -> None:
    campaign_schema = _archive_campaign_schema(connection)
    if campaign_schema == "current":
        transition_projection = """
                   campaign.parent_campaign_id,campaign.transition_kind,
                   campaign.resolution_ordinal,
        """
        transition_parameters: tuple[str, ...] = ()
    else:
        transition_projection = """
                   ? AS parent_campaign_id,? AS transition_kind,
                   ? AS resolution_ordinal,
        """
        transition_parameters = tuple(
            ARCHIVE_LEGACY_TRANSITION_SENTINELS[field]
            for field in ARCHIVE_CAMPAIGN_TRANSITION_COLUMNS
        )
    for lineage in lineages:
        campaign = connection.execute(
            f"""
            SELECT campaign.repository,campaign.issue_number,campaign.generation,
                   campaign.id AS campaign_id,
                   campaign.item_version,campaign.source_payload_sha256,
                   campaign.accepted_main_sha,campaign.graph_version,
                   campaign.capacity_policy_version,campaign.candidate_sha256,
                   campaign.worker_role,campaign.phase_summary,
                   campaign.plan_sha256,campaign.plan_json,
                   {transition_projection}
                   current.state AS campaign_state,
                   current.message_id,current.attempt_id,current.endpoint_id,
                   current.version AS current_version
            FROM portfolio_readiness_campaigns AS campaign
            JOIN portfolio_readiness_current AS current
              ON current.campaign_id=campaign.id
            WHERE campaign.id=? AND campaign.repository=?
              AND campaign.issue_number=?
            """,
            (
                *transition_parameters,
                lineage["campaign_id"],
                application_repository,
                lineage["issue_number"],
            ),
        ).fetchall()
        if len(campaign) != 1:
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_LINEAGE_MISSING")
        campaign_row = campaign[0]
        try:
            plan = json.loads(campaign_row["plan_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_PLAN_INVALID") from exc
        if (
            not isinstance(plan, dict)
            or canonical_json(plan) != campaign_row["plan_json"]
            or digest_json(plan) != campaign_row["plan_sha256"]
            or campaign_row["source_payload_sha256"]
            != lineage["source_payload_sha256"]
            or campaign_row["candidate_sha256"] != lineage["candidate_sha256"]
            or campaign_row["plan_sha256"] != lineage["plan_sha256"]
            or archive_campaign_digest(campaign_row)
            != lineage["campaign_sha256"]
            or campaign_row["campaign_state"] != lineage["campaign_state"]
            or campaign_row["message_id"] != lineage["message_id"]
            or campaign_row["attempt_id"] != lineage["attempt_id"]
        ):
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_LINEAGE_MISMATCH")
        candidates = connection.execute(
            """
            SELECT state FROM portfolio_pull_buffer_candidates
            WHERE repository=? AND issue_number=? AND candidate_sha256=?
            """,
            (
                application_repository,
                lineage["issue_number"],
                lineage["candidate_sha256"],
            ),
        ).fetchall()
        if len(candidates) != 1 or candidates[0]["state"] != lineage["candidate_state"]:
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_CANDIDATE_MISMATCH")
        messages = connection.execute(
            "SELECT state,payload_sha256 FROM coordination_messages WHERE id=?",
            (lineage["message_id"],),
        ).fetchall()
        if (
            len(messages) != 1
            or messages[0]["state"] != lineage["message_state"]
            or messages[0]["payload_sha256"]
            != lineage["message_payload_sha256"]
        ):
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_MESSAGE_MISMATCH")
        attempts = connection.execute(
            """
            SELECT state,target_kind,target_key,endpoint_id
            FROM executor_attempts WHERE attempt_id=?
            """,
            (lineage["attempt_id"],),
        ).fetchall()
        if (
            len(attempts) != 1
            or attempts[0]["state"] != lineage["attempt_state"]
            or attempts[0]["target_kind"] != "message"
            or attempts[0]["target_key"] != str(lineage["message_id"])
            or attempts[0]["endpoint_id"] != campaign_row["endpoint_id"]
        ):
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_ATTEMPT_MISMATCH")
        if int(
            connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_receipts WHERE campaign_id=?",
                (lineage["campaign_id"],),
            ).fetchone()[0]
        ) != 0:
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_RECEIPT_PRESENT")


def _validate_archive(
    value: dict[str, Any], database: Path, application_repository: str
) -> None:
    if not isinstance(value["archive_path"], str) or not value["archive_path"]:
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_PATH_INVALID")
    archive = Path(value["archive_path"])
    archive = Path(os.path.abspath(archive))
    if (
        not Path(value["archive_path"]).is_absolute()
        or archive == database
        or archive == DEFAULT_CANONICAL_DATABASE
    ):
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_PATH_INVALID")
    try:
        validate_owner_database(archive)
    except UnsafeSQLitePathError as exc:
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_UNSAFE") from exc
    if any(Path(f"{archive}{suffix}").exists() for suffix in ("-wal", "-shm")):
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_SIDECAR_PRESENT")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(archive, flags)
    except OSError as exc:
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_UNSAFE") from exc
    connection: sqlite3.Connection | None = None
    try:
        initial_descriptor = os.fstat(descriptor)
        initial_path = archive.stat(follow_symlinks=False)
        if (
            _archive_identity(initial_descriptor) != _archive_identity(initial_path)
            or not stat.S_ISREG(initial_descriptor.st_mode)
            or initial_descriptor.st_uid != os.getuid()
            or initial_descriptor.st_nlink != 1
            or stat.S_IMODE(initial_descriptor.st_mode) != 0o600
        ):
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_UNSAFE")
        if _descriptor_sha256(descriptor) != value["archive_sha256"]:
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_DIGEST_MISMATCH")
        try:
            preopen_path = archive.stat(follow_symlinks=False)
        except OSError as exc:
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_DRIFT") from exc
        if _archive_identity(initial_descriptor) != _archive_identity(preopen_path):
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_DRIFT")
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
            timeout=5,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA foreign_keys=ON")
            integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
            if integrity == ["ok"]:
                _validate_archive_lineages(
                    connection, value["excluded_lineages"], application_repository
                )
        finally:
            connection.close()
            connection = None
        try:
            final_path = archive.stat(follow_symlinks=False)
        except OSError as exc:
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_DRIFT") from exc
        final_descriptor = os.fstat(descriptor)
        if (
            _archive_identity(initial_descriptor)
            != _archive_identity(final_descriptor)
            or _archive_identity(final_descriptor) != _archive_identity(final_path)
            or _descriptor_sha256(descriptor) != value["archive_sha256"]
            or any(Path(f"{archive}{suffix}").exists() for suffix in ("-wal", "-shm"))
        ):
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_DRIFT")
    except sqlite3.Error as exc:
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_UNREADABLE") from exc
    finally:
        if connection is not None:
            connection.close()
        os.close(descriptor)
    if integrity != ["ok"]:
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_INTEGRITY_INVALID")


def _validate_manifest_closed(
    manifest: dict[str, Any],
    *,
    source_root: Path,
    database: Path,
    harness_main_sha: str,
) -> tuple[Any, list[dict[str, Any]]]:
    _require_keys(
        manifest,
        {
            "schema",
            "manifest_sha256",
            "bootstrap_id",
            "created_at",
            "source_harness",
            "approved_goal",
            "application",
            "capacity_policy",
            "current_endpoints",
            "retained_item",
            "old_control_plane",
        },
        "BOOTSTRAP_MANIFEST_SCHEMA_INVALID",
    )
    if manifest["schema"] != SCHEMA or not isinstance(manifest["bootstrap_id"], str) or not manifest["bootstrap_id"]:
        raise CleanControlPlaneError("BOOTSTRAP_MANIFEST_SCHEMA_INVALID")
    _require_timestamp(manifest["created_at"], "BOOTSTRAP_TIMESTAMP_INVALID")
    _require_sha(manifest["manifest_sha256"], "BOOTSTRAP_MANIFEST_DIGEST_INVALID")
    if manifest_digest(manifest) != manifest["manifest_sha256"]:
        raise CleanControlPlaneError("BOOTSTRAP_MANIFEST_DIGEST_MISMATCH")

    source = _require_keys(
        manifest["source_harness"],
        {"repository", "main_sha", "registry_path", "registry_sha256", "profiles"},
        "BOOTSTRAP_SOURCE_SCHEMA_INVALID",
    )
    if source["repository"] != SOURCE_HARNESS_REPOSITORY:
        raise CleanControlPlaneError("BOOTSTRAP_SOURCE_SCHEMA_INVALID")
    if _require_git_sha(source["main_sha"], "BOOTSTRAP_SOURCE_MAIN_INVALID") != harness_main_sha:
        raise CleanControlPlaneError("BOOTSTRAP_SOURCE_MAIN_MISMATCH")
    bound_source_paths = [source["registry_path"]]
    registry_path = _source_file(source_root, source["registry_path"])
    if _file_sha256(registry_path) != _require_sha(source["registry_sha256"], "BOOTSTRAP_REGISTRY_DIGEST_INVALID"):
        raise CleanControlPlaneError("BOOTSTRAP_REGISTRY_DIGEST_MISMATCH")

    profiles = source["profiles"]
    if not isinstance(profiles, list) or len(profiles) != 3:
        raise CleanControlPlaneError("BOOTSTRAP_PROFILE_SCHEMA_INVALID")
    profile_root: Path | None = None
    seen_roles: set[str] = set()
    for profile in profiles:
        _require_keys(profile, {"role", "endpoint_id", "path", "sha256"}, "BOOTSTRAP_PROFILE_SCHEMA_INVALID")
        role = profile["role"]
        if role not in EXPECTED_ENDPOINTS or role in seen_roles or profile["endpoint_id"] != EXPECTED_ENDPOINTS[role]:
            raise CleanControlPlaneError("BOOTSTRAP_PROFILE_SCHEMA_INVALID")
        seen_roles.add(role)
        path = _source_file(source_root, profile["path"])
        bound_source_paths.append(profile["path"])
        if _file_sha256(path) != _require_sha(profile["sha256"], "BOOTSTRAP_PROFILE_DIGEST_INVALID"):
            raise CleanControlPlaneError("BOOTSTRAP_PROFILE_DIGEST_MISMATCH")
        if profile_root is None:
            profile_root = path.parent
        elif path.parent != profile_root:
            raise CleanControlPlaneError("BOOTSTRAP_PROFILE_ROOT_INVALID")
    if profile_root is None:
        raise CleanControlPlaneError("BOOTSTRAP_PROFILE_SCHEMA_INVALID")
    try:
        config = load_registry_config(
            registry_path,
            codex_home=profile_root,
            profile_template_root=profile_root,
        )
    except RegistryError as exc:
        raise CleanControlPlaneError(str(exc)) from exc
    current = {role: endpoint.endpoint_id for role, endpoint in config.roles.items()}
    if current != EXPECTED_ENDPOINTS or manifest["current_endpoints"] != EXPECTED_ENDPOINTS:
        raise CleanControlPlaneError("BOOTSTRAP_CURRENT_ENDPOINTS_INVALID")
    declared_profiles = {entry["role"]: entry["sha256"] for entry in profiles}
    if declared_profiles != {role: config.roles[role].profile_sha256 for role in EXPECTED_ENDPOINTS}:
        raise CleanControlPlaneError("BOOTSTRAP_PROFILE_BINDING_MISMATCH")

    goal = _require_keys(manifest["approved_goal"], {"path", "sha256"}, "BOOTSTRAP_GOAL_SCHEMA_INVALID")
    goal_path = _source_file(source_root, goal["path"])
    bound_source_paths.append(goal["path"])
    if _file_sha256(goal_path) != _require_sha(goal["sha256"], "BOOTSTRAP_GOAL_DIGEST_INVALID"):
        raise CleanControlPlaneError("BOOTSTRAP_GOAL_DIGEST_MISMATCH")
    _validate_source_git(
        source_root,
        repository=source["repository"],
        commit=source["main_sha"],
        bound_paths=bound_source_paths,
    )

    application = _require_keys(manifest["application"], {"repository", "main_sha", "snapshots"}, "BOOTSTRAP_APPLICATION_SCHEMA_INVALID")
    if REPOSITORY.fullmatch(str(application["repository"])) is None:
        raise CleanControlPlaneError("BOOTSTRAP_APPLICATION_SCHEMA_INVALID")
    _require_git_sha(application["main_sha"], "BOOTSTRAP_APPLICATION_MAIN_INVALID")
    snapshots = application["snapshots"]
    if not isinstance(snapshots, list):
        raise CleanControlPlaneError("BOOTSTRAP_SNAPSHOT_SCHEMA_INVALID")
    snapshot_keys: set[tuple[str, int]] = set()
    for snapshot in snapshots:
        _require_keys(
            snapshot,
            {"object_kind", "object_number", "payload", "payload_sha256", "source_updated_at", "fetched_at"},
            "BOOTSTRAP_SNAPSHOT_SCHEMA_INVALID",
        )
        key = (snapshot["object_kind"], snapshot["object_number"])
        if (
            snapshot["object_kind"] not in {"issue", "pull_request"}
            or type(snapshot["object_number"]) is not int
            or snapshot["object_number"] <= 0
            or not isinstance(snapshot["payload"], dict)
            or key in snapshot_keys
        ):
            raise CleanControlPlaneError("BOOTSTRAP_SNAPSHOT_SCHEMA_INVALID")
        snapshot_keys.add(key)
        if digest_json(snapshot["payload"]) != _require_sha(snapshot["payload_sha256"], "BOOTSTRAP_SNAPSHOT_DIGEST_INVALID"):
            raise CleanControlPlaneError("BOOTSTRAP_SNAPSHOT_DIGEST_MISMATCH")
        _require_timestamp(snapshot["source_updated_at"], "BOOTSTRAP_TIMESTAMP_INVALID")
        _require_timestamp(snapshot["fetched_at"], "BOOTSTRAP_TIMESTAMP_INVALID")

    policy = _require_keys(
        manifest["capacity_policy"],
        {"repository", "version", "development_limit", "shared_limit", "sre_limit", "authority_sha256"},
        "BOOTSTRAP_CAPACITY_SCHEMA_INVALID",
    )
    if (
        policy["repository"] != application["repository"]
        or policy["version"] != 1
        or type(policy["development_limit"]) is not int
        or policy["development_limit"] <= 0
        or type(policy["shared_limit"]) is not int
        or policy["shared_limit"] < 0
        or type(policy["sre_limit"]) is not int
        or policy["sre_limit"] < 0
    ):
        raise CleanControlPlaneError("BOOTSTRAP_CAPACITY_SCHEMA_INVALID")
    _require_sha(policy["authority_sha256"], "BOOTSTRAP_CAPACITY_AUTHORITY_INVALID")

    retained = manifest["retained_item"]
    artifacts: list[dict[str, Any]] = []
    if retained is not None:
        _require_keys(
            retained,
            {
                "issue_number", "generation", "accountable_endpoint_id",
                "source_payload_sha256", "lease_manifest_path",
                "lease_manifest_sha256", "lease_bindings",
                "development_units", "shared_units",
                "sre_units", "artifacts",
            },
            "BOOTSTRAP_RETAINED_SCHEMA_INVALID",
        )
        if (
            retained["issue_number"] != 320
            or type(retained["generation"]) is not int
            or retained["generation"] < 0
            or retained["accountable_endpoint_id"] != "role.sre.v3"
            or retained["development_units"] != 0
            or retained["shared_units"] != 0
            or retained["sre_units"] != 1
            or ("issue", 320) not in snapshot_keys
        ):
            raise CleanControlPlaneError("BOOTSTRAP_RETAINED_SCHEMA_INVALID")
        _require_sha(retained["source_payload_sha256"], "BOOTSTRAP_RETAINED_SOURCE_INVALID")
        _require_sha(retained["lease_manifest_sha256"], "BOOTSTRAP_LEASE_DIGEST_INVALID")
        issue_snapshot = next(item for item in snapshots if item["object_kind"] == "issue" and item["object_number"] == 320)
        if retained["source_payload_sha256"] != issue_snapshot["payload_sha256"]:
            raise CleanControlPlaneError("BOOTSTRAP_RETAINED_SOURCE_MISMATCH")
        if not isinstance(retained["artifacts"], list) or not retained["artifacts"]:
            raise CleanControlPlaneError("BOOTSTRAP_ARTIFACT_SCHEMA_INVALID")
        seen_paths: set[str] = set()
        for artifact in retained["artifacts"]:
            _require_keys(artifact, {"path", "sha256", "retention_class"}, "BOOTSTRAP_ARTIFACT_SCHEMA_INVALID")
            if artifact["path"] in seen_paths or artifact["retention_class"] not in {"CLOSEOUT_EVIDENCE", "RETAINED"}:
                raise CleanControlPlaneError("BOOTSTRAP_ARTIFACT_SCHEMA_INVALID")
            seen_paths.add(artifact["path"])
            path = _source_file(database.parent, artifact["path"])
            if _file_sha256(path) != _require_sha(artifact["sha256"], "BOOTSTRAP_ARTIFACT_DIGEST_INVALID"):
                raise CleanControlPlaneError("BOOTSTRAP_ARTIFACT_DIGEST_MISMATCH")
            artifacts.append(artifact)
        if retained["lease_manifest_path"] not in seen_paths:
            raise CleanControlPlaneError("BOOTSTRAP_LEASE_ARTIFACT_MISSING")
        lease_path = _source_file(database.parent, retained["lease_manifest_path"])
        if _file_sha256(lease_path) != retained["lease_manifest_sha256"]:
            raise CleanControlPlaneError("BOOTSTRAP_LEASE_DIGEST_MISMATCH")
        try:
            parsed_lease = parse_structured_lease_manifest(lease_path.read_bytes())
        except (CoordinationError, OSError) as exc:
            raise CleanControlPlaneError("BOOTSTRAP_LEASE_MANIFEST_INVALID") from exc
        if (
            parsed_lease["repository"] != application["repository"]
            or parsed_lease["issue_number"] != 320
            or parsed_lease["generation"] != retained["generation"]
            or parsed_lease["base_sha"] != application["main_sha"]
            or not isinstance(retained["lease_bindings"], list)
            or parsed_lease["paths"] != retained["lease_bindings"]
        ):
            raise CleanControlPlaneError("BOOTSTRAP_LEASE_BINDING_MISMATCH")

    old = _require_keys(
        manifest["old_control_plane"],
        {"archive_path", "archive_sha256", "archive_integrity", "disposition", "excluded_lineages"},
        "BOOTSTRAP_ARCHIVE_SCHEMA_INVALID",
    )
    if (
        old["archive_integrity"] != "ok"
        or old["disposition"] != "IMMUTABLE_ARCHIVE_SUPERSEDED"
        or not isinstance(old["excluded_lineages"], list)
        or len(old["excluded_lineages"]) != 2
    ):
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_SCHEMA_INVALID")
    observed_issues: set[int] = set()
    for lineage in old["excluded_lineages"]:
        _require_keys(
            lineage, ARCHIVE_LINEAGE_KEYS, "BOOTSTRAP_ARCHIVE_LINEAGE_SCHEMA_INVALID"
        )
        issue_number = lineage["issue_number"]
        expected_identity = STRANDED_IDENTITIES.get(issue_number)
        if (
            expected_identity is None
            or issue_number in observed_issues
            or lineage["repository"] != application["repository"]
            or (lineage["campaign_id"], lineage["attempt_id"])
            != expected_identity
            or type(lineage["message_id"]) is not int
            or lineage["message_id"] <= 0
            or lineage["campaign_state"]
            not in {
                "PENDING",
                "RUNNING",
                "RESOLUTION_PENDING",
                "APPROVAL_PENDING",
                "READY_ELIGIBLE",
                "FINALIZED",
                "HOLD",
                "STALE",
            }
            or lineage["candidate_state"] not in {"PREPARED_NOT_READY", "READY"}
            or lineage["message_state"]
            not in {"PREPARED", "CLAIMED", "COMPLETE", "HOLD"}
            or lineage["attempt_state"]
            not in {
                "RESERVED",
                "LAUNCHING",
                "RUNNING",
                "COMPLETE",
                "HOLD",
                "LAUNCH_FAILED",
            }
            or lineage["disposition"] != "SUPERSEDED_WITHOUT_REPLAY"
            or lineage["receipt_fabricated"] is not False
        ):
            raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_LINEAGE_SCHEMA_INVALID")
        for key in (
            "source_payload_sha256",
            "campaign_sha256",
            "candidate_sha256",
            "plan_sha256",
            "message_payload_sha256",
        ):
            _require_sha(
                lineage[key], "BOOTSTRAP_ARCHIVE_LINEAGE_DIGEST_INVALID"
            )
        observed_issues.add(issue_number)
    if observed_issues != set(STRANDED_IDENTITIES):
        raise CleanControlPlaneError("BOOTSTRAP_ARCHIVE_LINEAGE_SCHEMA_INVALID")
    _require_sha(old["archive_sha256"], "BOOTSTRAP_ARCHIVE_DIGEST_INVALID")
    _validate_archive(old, database, application["repository"])
    return config, artifacts


def _validate_manifest(
    manifest: dict[str, Any],
    *,
    source_root: Path,
    database: Path,
    harness_main_sha: str,
) -> tuple[Any, list[dict[str, Any]]]:
    """Validate arbitrary manifest input without exposing type errors."""

    try:
        return _validate_manifest_closed(
            manifest,
            source_root=source_root,
            database=database,
            harness_main_sha=harness_main_sha,
        )
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise CleanControlPlaneError("BOOTSTRAP_MANIFEST_SCHEMA_INVALID") from exc


def _validate_target(path: Path) -> Path:
    if not path.is_absolute():
        raise CleanControlPlaneError("BOOTSTRAP_DATABASE_PATH_NOT_ABSOLUTE")
    path = Path(os.path.abspath(path))
    if path == DEFAULT_CANONICAL_DATABASE:
        raise CleanControlPlaneError("BOOTSTRAP_CANONICAL_DATABASE_FORBIDDEN")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise CleanControlPlaneError("BOOTSTRAP_DATABASE_PARENT_UNSAFE") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise CleanControlPlaneError("BOOTSTRAP_DATABASE_PARENT_UNSAFE")
    parent = path.parent.lstat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise CleanControlPlaneError("BOOTSTRAP_DATABASE_PARENT_UNSAFE")
    associated = [path, Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal"), path.with_name(f"{path.name}.schema.lock")]
    if any(candidate.exists() or candidate.is_symlink() for candidate in associated):
        raise CleanControlPlaneError("BOOTSTRAP_DATABASE_EXISTS")
    return path


def _create_target(path: Path) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    old_umask = os.umask(0o077)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CleanControlPlaneError("BOOTSTRAP_DATABASE_CREATE_FAILED") from exc
    finally:
        os.umask(old_umask)
    os.close(descriptor)


def _cleanup_failed_target(path: Path) -> None:
    for candidate in (Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal"), path, path.with_name(f"{path.name}.schema.lock")):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and metadata.st_nlink == 1:
            candidate.unlink()


def _quiesce_database(path: Path) -> None:
    connection = sqlite3.connect(path, isolation_level=None, timeout=5)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower()
        if mode != "delete":
            raise CleanControlPlaneError("BOOTSTRAP_JOURNAL_MODE_INVALID")
    finally:
        connection.close()
    if any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal")):
        raise CleanControlPlaneError("BOOTSTRAP_DATABASE_SIDECAR_PRESENT")


def _zero_count(connection: sqlite3.Connection, query: str, error: str) -> None:
    if int(connection.execute(query).fetchone()[0]) != 0:
        raise CleanControlPlaneError(error)


def validate_database(
    *,
    database: Path,
    manifest: dict[str, Any],
    source_root: Path,
    harness_main_sha: str,
) -> dict[str, Any]:
    config, artifacts = _validate_manifest(
        manifest,
        source_root=source_root,
        database=database,
        harness_main_sha=harness_main_sha,
    )
    try:
        connection = open_owner_database_readonly(database)
    except (UnsafeSQLitePathError, sqlite3.Error) as exc:
        raise CleanControlPlaneError("BOOTSTRAP_DATABASE_UNREADABLE") from exc
    try:
        if [str(row[0]) for row in connection.execute("PRAGMA integrity_check")] != ["ok"]:
            raise CleanControlPlaneError("BOOTSTRAP_DATABASE_INTEGRITY_INVALID")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise CleanControlPlaneError("BOOTSTRAP_DATABASE_REFERENTIAL_INVALID")
        provenance = connection.execute(
            "SELECT * FROM coordination_bootstrap_provenance"
        ).fetchall()
        source = manifest["source_harness"]
        application = manifest["application"]
        old = manifest["old_control_plane"]
        expected_provenance = {
            "bootstrap_id": manifest["bootstrap_id"],
            "manifest_sha256": manifest["manifest_sha256"],
            "manifest_json": canonical_json(manifest),
            "source_harness_repository": source["repository"],
            "source_harness_main_sha": source["main_sha"],
            "source_registry_sha256": source["registry_sha256"],
            "approved_goal_sha256": manifest["approved_goal"]["sha256"],
            "application_repository": application["repository"],
            "application_main_sha": application["main_sha"],
            "archived_database_sha256": old["archive_sha256"],
            "created_at": manifest["created_at"],
        }
        if len(provenance) != 1 or any(
            provenance[0][key] != value
            for key, value in expected_provenance.items()
        ):
            raise CleanControlPlaneError("BOOTSTRAP_PROVENANCE_READBACK_INVALID")
        pointers = {
            str(item["role"]): str(item["endpoint_id"])
            for item in connection.execute("SELECT role, endpoint_id FROM executor_role_endpoint_current")
        }
        if pointers != EXPECTED_ENDPOINTS:
            raise CleanControlPlaneError("BOOTSTRAP_CURRENT_ENDPOINTS_INVALID")
        endpoint_rows = {
            str(item["endpoint_id"]): item
            for item in connection.execute("SELECT * FROM executor_role_endpoints")
        }
        if set(endpoint_rows) != set(config.endpoints):
            raise CleanControlPlaneError("BOOTSTRAP_ENDPOINT_CATALOG_INVALID")
        for endpoint_id, endpoint in config.endpoints.items():
            actual = endpoint_rows[endpoint_id]
            payload = endpoint.payload
            if any(
                (
                    actual["role"] != endpoint.role,
                    int(actual["version"]) != endpoint.version,
                    actual["executor_profile"] != endpoint.executor_profile,
                    actual["codex_profile"] != endpoint.codex_profile,
                    actual["config_sha256"] != digest_json(payload),
                    actual["config_json"] != canonical_json(payload),
                    actual["command_json"]
                    != canonical_json(list(endpoint.command_prefix)),
                )
            ):
                raise CleanControlPlaneError("BOOTSTRAP_ENDPOINT_CATALOG_INVALID")
        snapshots = connection.execute("SELECT object_kind, object_number, payload_sha256, source_updated_at, fetched_at, payload_json FROM github_snapshots WHERE repository=? ORDER BY object_kind, object_number", (application["repository"],)).fetchall()
        expected_snapshots = sorted(application["snapshots"], key=lambda item: (item["object_kind"], item["object_number"]))
        if len(snapshots) != len(expected_snapshots):
            raise CleanControlPlaneError("BOOTSTRAP_SNAPSHOT_READBACK_INVALID")
        for actual, expected in zip(snapshots, expected_snapshots, strict=True):
            if (
                actual["object_kind"] != expected["object_kind"]
                or int(actual["object_number"]) != expected["object_number"]
                or actual["payload_sha256"] != expected["payload_sha256"]
                or actual["source_updated_at"] != expected["source_updated_at"]
                or actual["fetched_at"] != expected["fetched_at"]
                or actual["payload_json"] != canonical_json(expected["payload"])
            ):
                raise CleanControlPlaneError("BOOTSTRAP_SNAPSHOT_READBACK_INVALID")
        policy = manifest["capacity_policy"]
        actual_policy = connection.execute("SELECT p.* FROM coordination_capacity_current c JOIN coordination_capacity_policies p USING(repository, version) WHERE c.repository=?", (application["repository"],)).fetchone()
        if actual_policy is None or any(int(actual_policy[key]) != policy[key] for key in ("version", "development_limit", "shared_limit", "sre_limit")) or actual_policy["authority_sha256"] != policy["authority_sha256"]:
            raise CleanControlPlaneError("BOOTSTRAP_CAPACITY_READBACK_INVALID")
        items = connection.execute("SELECT * FROM coordination_items ORDER BY issue_number").fetchall()
        retained = manifest["retained_item"]
        if retained is None:
            if items:
                raise CleanControlPlaneError("BOOTSTRAP_RETAINED_READBACK_INVALID")
        elif len(items) != 1 or any(
            (
                int(items[0]["issue_number"]) != 320,
                items[0]["status"] != "HOLD",
                items[0]["allocation_class"] != "RETAINED",
                items[0]["accountable_session_id"] != "role.sre.v3",
                items[0]["lease_manifest_sha256"] != retained["lease_manifest_sha256"],
                int(items[0]["development_units"]) != 0,
                int(items[0]["shared_units"]) != 0,
                int(items[0]["sre_units"]) != 1,
            )
        ):
            raise CleanControlPlaneError("BOOTSTRAP_RETAINED_READBACK_INVALID")
        occupancy = connection.execute(
            "SELECT COALESCE(SUM(development_units),0), "
            "COALESCE(SUM(shared_units),0), COALESCE(SUM(sre_units),0) "
            "FROM coordination_items WHERE allocation_class IN ('ACTIVE','RETAINED')"
        ).fetchone()
        if (
            int(occupancy[0]) > policy["development_limit"]
            or int(occupancy[1]) > policy["shared_limit"]
            or int(occupancy[2]) > policy["sre_limit"]
        ):
            raise CleanControlPlaneError("BOOTSTRAP_CAPACITY_INVARIANT_INVALID")
        artifact_rows = connection.execute(
            "SELECT repository,issue_number,generation,relative_path,content_sha256,"
            "retention_class,state FROM coordination_artifacts ORDER BY relative_path"
        ).fetchall()
        expected_artifacts = sorted(artifacts, key=lambda item: item["path"])
        if len(artifact_rows) != len(expected_artifacts) or any(
            (
                actual["repository"] != application["repository"]
                or int(actual["issue_number"]) != 320
                or int(actual["generation"]) != retained["generation"]
                or actual["relative_path"] != expected["path"]
                or actual["content_sha256"] != expected["sha256"]
                or actual["retention_class"] != expected["retention_class"]
                or actual["state"] != "REGISTERED"
            )
            for actual, expected in zip(
                artifact_rows, expected_artifacts, strict=True
            )
        ):
            raise CleanControlPlaneError("BOOTSTRAP_ARTIFACT_READBACK_INVALID")
        _zero_count(connection, "SELECT COUNT(*) FROM executor_attempts", "BOOTSTRAP_ATTEMPTS_NOT_EMPTY")
        _zero_count(connection, "SELECT COUNT(*) FROM coordination_terminal_watches", "BOOTSTRAP_WATCHES_NOT_EMPTY")
        _zero_count(connection, "SELECT COUNT(*) FROM hosted_operations", "BOOTSTRAP_HOSTED_NOT_EMPTY")
        _zero_count(connection, "SELECT COUNT(*) FROM github_outbox", "BOOTSTRAP_OUTBOX_NOT_EMPTY")
        _zero_count(connection, "SELECT COUNT(*) FROM coordination_messages", "BOOTSTRAP_MESSAGES_NOT_EMPTY")
        _zero_count(connection, "SELECT COUNT(*) FROM portfolio_readiness_campaigns", "BOOTSTRAP_CAMPAIGNS_NOT_EMPTY")
        _zero_count(connection, "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates", "BOOTSTRAP_CANDIDATES_NOT_EMPTY")
        _zero_count(connection, "SELECT COUNT(*) FROM approval_decisions", "BOOTSTRAP_APPROVALS_NOT_EMPTY")
        return {
            "database": str(database),
            "database_sha256": _file_sha256(database),
            "manifest_sha256": manifest["manifest_sha256"],
            "retained_issue_320": retained is not None,
            "schema": SCHEMA,
            "state": "PASS",
        }
    except sqlite3.Error as exc:
        raise CleanControlPlaneError("BOOTSTRAP_DATABASE_READBACK_FAILED") from exc
    finally:
        connection.close()


def bootstrap_database(
    *,
    database: Path,
    manifest: dict[str, Any],
    source_root: Path,
    harness_main_sha: str,
) -> dict[str, Any]:
    database = _validate_target(database)
    config, artifacts = _validate_manifest(
        manifest,
        source_root=source_root,
        database=database,
        harness_main_sha=harness_main_sha,
    )
    created = False
    store: CoordinationStore | None = None
    try:
        _create_target(database)
        created = True
        store = CoordinationStore(database)
        store.close()
        store = None
        hosted = HostedOperationControl(database)
        hosted.close()
        store = CoordinationStore(database)
        ensure_approval_schema(store.connection)
        ensure_pull_buffer_schema(store.connection)
        ensure_readiness_schema(store.connection)
        ensure_broker_schema(store.connection)
        aliases: list[dict[str, str]] = []
        aliases_sha256 = digest_json(aliases)
        with registry_config_scope(config), store.transaction():
            plan = build_plan(
                store.connection,
                config,
                aliases,
                alias_fixture_sha256=aliases_sha256,
            )
            apply_plan(
                store.connection,
                plan=plan,
                operation_key=f"clean-bootstrap:{manifest['manifest_sha256']}",
                expected_plan_sha256=plan["plan_sha256"],
                now=manifest["created_at"],
                _within_immediate_transaction=True,
            )
            for endpoint_id in sorted(config.staged_endpoint_ids):
                _verify_or_insert_endpoint(
                    store.connection,
                    config.endpoints[endpoint_id].payload,
                    manifest["created_at"],
                )
            application = manifest["application"]
            for snapshot in application["snapshots"]:
                store.ingest_snapshot_in_transaction(
                    repository=application["repository"],
                    object_kind=snapshot["object_kind"],
                    object_number=snapshot["object_number"],
                    payload=snapshot["payload"],
                    source_updated_at=snapshot["source_updated_at"],
                    fetched_at=snapshot["fetched_at"],
                    expected_payload_sha256=snapshot["payload_sha256"],
                )
            policy = manifest["capacity_policy"]
            store.bootstrap_capacity_policy(
                repository=policy["repository"],
                development_limit=policy["development_limit"],
                shared_limit=policy["shared_limit"],
                sre_limit=policy["sre_limit"],
                authority_sha256=policy["authority_sha256"],
                now=manifest["created_at"],
                _transaction=False,
            )
            retained = manifest["retained_item"]
            if retained is not None:
                store.set_issue_status(
                    repository=application["repository"],
                    issue_number=320,
                    status="HOLD",
                    allocation_class="RETAINED",
                    generation=retained["generation"],
                    accountable_session_id=retained["accountable_endpoint_id"],
                    lease_manifest_sha256=retained["lease_manifest_sha256"],
                    development_units=0,
                    shared_units=0,
                    sre_units=1,
                    expected_source_sha256=retained["source_payload_sha256"],
                    expected_version=0,
                    now=manifest["created_at"],
                    _transaction=False,
                )
                registered = store.register_artifacts(
                    [
                        {
                            "repository": application["repository"],
                            "issue_number": 320,
                            "generation": retained["generation"],
                            "path": artifact["path"],
                            "retention_class": artifact["retention_class"],
                        }
                        for artifact in artifacts
                    ],
                    now=manifest["created_at"],
                    _transaction=False,
                )
                if {item["relative_path"]: item["content_sha256"] for item in registered} != {item["path"]: item["sha256"] for item in artifacts}:
                    raise CleanControlPlaneError("BOOTSTRAP_ARTIFACT_READBACK_INVALID")
            source = manifest["source_harness"]
            goal = manifest["approved_goal"]
            old = manifest["old_control_plane"]
            store.record_bootstrap_provenance(
                bootstrap_id=manifest["bootstrap_id"],
                manifest_sha256=manifest["manifest_sha256"],
                manifest=manifest,
                source_harness_repository=source["repository"],
                source_harness_main_sha=source["main_sha"],
                source_registry_sha256=source["registry_sha256"],
                approved_goal_sha256=goal["sha256"],
                application_repository=application["repository"],
                application_main_sha=application["main_sha"],
                archived_database_sha256=old["archive_sha256"],
                now=manifest["created_at"],
            )
        store.close()
        store = None
        _quiesce_database(database)
        os.chmod(database, 0o600, follow_symlinks=False)
        return validate_database(
            database=database,
            manifest=manifest,
            source_root=source_root,
            harness_main_sha=harness_main_sha,
        )
    except Exception:
        if store is not None:
            store.close()
        if created:
            _cleanup_failed_target(database)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest = subparsers.add_parser("digest")
    digest.add_argument("--manifest", type=Path, required=True)
    for command in ("bootstrap", "validate"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--database", type=Path, required=True)
        subparser.add_argument("--manifest", type=Path, required=True)
        subparser.add_argument("--source-root", type=Path, required=True)
        subparser.add_argument("--harness-main-sha", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = _read_json(args.manifest)
        if args.command == "digest":
            print(canonical_json({"manifest_sha256": manifest_digest(manifest), "state": "PASS"}))
            return 0
        harness_main_sha = _require_git_sha(args.harness_main_sha, "BOOTSTRAP_SOURCE_MAIN_INVALID")
        if args.command == "bootstrap":
            result = bootstrap_database(
                database=args.database,
                manifest=manifest,
                source_root=args.source_root,
                harness_main_sha=harness_main_sha,
            )
        else:
            result = validate_database(
                database=args.database,
                manifest=manifest,
                source_root=args.source_root,
                harness_main_sha=harness_main_sha,
            )
        print(canonical_json(result))
        return 0
    except (CleanControlPlaneError, CoordinationError, RegistryError, OSError, sqlite3.Error) as exc:
        error = str(exc) if isinstance(exc, (CleanControlPlaneError, CoordinationError, RegistryError)) else "BOOTSTRAP_IO_ERROR"
        print(canonical_json({"error": error, "state": "HOLD"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
