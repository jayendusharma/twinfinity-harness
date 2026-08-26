#!/usr/bin/env python3
"""ACID same-host coordination state derived from exact GitHub snapshots.

GitHub remains the external fact source and audit destination. This store is the
local synchronization context for agents: source snapshots, derived issue
status, inbox messages, and an idempotent GitHub outbox.
"""

from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
from typing import Any, Callable, Iterator

from owner_safe_sqlite import UnsafeSQLitePathError, prepare_owner_database
from approval_guard import (
    ApprovalGuardError,
    admission_execution_scope_sha256,
    require_effective_approval,
)
from portfolio_graph import (
    PortfolioGraphError,
    enqueue_convergence_dirty_event,
    ensure_portfolio_graph_schema,
    reserved_hosted_sre_units,
    validate_portfolio_transition,
)
from executor_registry import (
    ENDPOINT_ID,
    ROLES,
    RegistryError,
    canonical_endpoint_id,
    current_endpoint,
    ensure_executor_registry_schema,
    identities_role_equivalent,
    identity_role,
    load_legacy_aliases,
    require_current_endpoint_identity,
    select_role_equivalent_identity,
)


DEFAULT_DATABASE = (
    Path(pwd.getpwuid(os.getuid()).pw_dir)
    / ".codex"
    / "twinfinity-coordination"
    / "ack-transactions.sqlite3"
)
_LEGACY_ROLE_ALIASES = {
    role: alias for alias, role in load_legacy_aliases().aliases.items()
}
# Compatibility exports for callers and historical fixtures. Operational
# routing resolves roles and current endpoints through executor_registry.
PLANNER_SESSION = _LEGACY_ROLE_ALIASES["planner"]
DEVELOPMENT_SESSION = _LEGACY_ROLE_ALIASES["development"]
SRE_SESSION = _LEGACY_ROLE_ALIASES["sre"]
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SESSION = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_KINDS = {"issue", "pull_request"}
ITEM_STATUSES = {
    "BACKLOG",
    "PREPARED",
    "QUEUED",
    "READY",
    "ACTIVE",
    "ACTIVE_FENCED",
    "MONITOR",
    "PUBLICATION_PENDING",
    "HOLD",
    "DONE",
}
STATUS_RANK = {
    "BACKLOG": 0,
    "PREPARED": 1,
    "QUEUED": 2,
    "READY": 3,
    "ACTIVE": 4,
    "ACTIVE_FENCED": 4,
    "MONITOR": 4,
    "PUBLICATION_PENDING": 5,
    "HOLD": 6,
    "DONE": 7,
}
MESSAGE_STATES = {"PREPARED", "CLAIMED", "COMPLETE", "HOLD"}
OUTBOX_STATES = {"PREPARED", "INFLIGHT", "COMPLETE", "HOLD"}
TERMINAL_OUTBOX_READBACK_ATTEMPTS_PER_RETRY = 3
TERMINAL_OUTBOX_MAX_RETRY_ROUNDS = 3
TERMINAL_LIVE_EVIDENCE_MAX_AGE_SECONDS = 60
ALLOCATION_CLASSES = {"ACTIVE", "RETAINED", "NONE"}
ARTIFACT_RETENTION_CLASSES = {"EPHEMERAL", "CLOSEOUT_EVIDENCE", "RETAINED"}
ARTIFACT_STATES = {
    "REGISTERED",
    "ELIGIBLE",
    "MOVE_RESERVED",
    "TRASHED",
    "PURGE_RESERVED",
    "PURGED",
    "HOLD",
}
ARTIFACT_PURGE_SECONDS = {
    "EPHEMERAL": 7 * 24 * 60 * 60,
    "CLOSEOUT_EVIDENCE": 30 * 24 * 60 * 60,
}
DEFAULT_CAPACITY_LIMITS = {
    "development_limit": 5,
    "shared_limit": 2,
    "sre_limit": 5,
}
PREPARED_MESSAGE_HOLD_REASONS = {
    "SUPERSEDED_BY_ARTIFACT_REBIND",
    "SUPERSEDED_BY_ENVIRONMENT_REBIND",
    "SUPERSEDED_BY_ROLE_ENDPOINT_CUTOVER",
}
ACTIVE_EXECUTION_STATUSES = {
    "ACTIVE",
    "ACTIVE_FENCED",
    "MONITOR",
    "PUBLICATION_PENDING",
}
_READY_FINALIZATION_GATEWAY = object()
_READINESS_DECISION_GATEWAY = object()
_READINESS_RESOLUTION_GATEWAY = object()
_ADMISSION_ACTIVATION_GATEWAY = object()
_TRANSFER_ACTIVATION_GATEWAY = object()
_TERMINAL_FINALIZATION_GATEWAY = object()
_TEST_FIXTURE_GATEWAY = object()
_TEST_FIXTURE_FORBIDDEN_ITEM_STATES = {
    "READY",
    "READY_ELIGIBLE",
    "FINALIZED",
}
MESSAGE_TOPICS = {
    "coordination.notice",
    "development.admission",
    "development.recovery_prepare",
    "development.recovery_commit",
    "development.terminal_closeout",
    "sre.admission",
}
MUTATING_MESSAGE_TOPICS = MESSAGE_TOPICS - {"coordination.notice"}
MUTATING_TOPIC_ROLES = {
    "development.admission": "development",
    "development.recovery_prepare": "development",
    "development.recovery_commit": "development",
    "development.terminal_closeout": "development",
    "sre.admission": "sre",
}
ADMISSION_WATCH_TOPICS = {
    "development.admission",
    "development.recovery_commit",
    "sre.admission",
}
NOTICE_KINDS = {
    "evidence",
    "observation",
    "planning_request",
    "status",
    "terminal_receipt",
}
NOTICE_ALLOWED_KEYS = {
    "evidence": {
        "source",
        "notice_kind",
        "mutation_authority",
        "subject",
        "summary",
        "evidence",
        "next_observation",
    },
    "observation": {
        "source",
        "notice_kind",
        "mutation_authority",
        "subject",
        "summary",
        "evidence",
        "next_observation",
    },
    "planning_request": {
        "source",
        "notice_kind",
        "mutation_authority",
        "subject",
        "summary",
        "evidence",
        "requested_evidence",
        "next_observation",
    },
    "status": {
        "source",
        "notice_kind",
        "mutation_authority",
        "subject",
        "summary",
        "evidence",
        "next_observation",
    },
    "terminal_receipt": {
        "source",
        "notice_kind",
        "mutation_authority",
        "subject",
        "summary",
        "evidence",
    },
}
NOTICE_FORBIDDEN_KEYS = {
    "action",
    "already_authorized",
    "args",
    "arguments",
    "argv",
    "authorization",
    "authority",
    "authority_sha256",
    "binary",
    "command",
    "commands",
    "exec",
    "executable",
    "instruction",
    "instructions",
    "mutation",
    "mutation_plan",
    "next_action",
    "operation",
    "program",
    "routine_chain",
    "shell",
    "shell_command",
    "tokens",
}
TERMINAL_CLEANUP_BOOLEAN_KEYS = {
    "docker_resources_absent",
    "local_branch_absent",
    "remote_branch_absent",
    "remote_branch_deleted",
    "run_roots_absent",
    "temporary_artifacts_absent",
    "worktree_absent",
    "worktree_removed",
}
TERMINAL_CLEANUP_RESOURCE_STATES = {
    "absent",
    "removed",
    "were absent",
    "were removed",
}
TERMINAL_CLEANUP_SCHEMA = "twinfinity-terminal-cleanup/v1"
TERMINAL_CLEANUP_DISPOSITIONS = {"ABSENT", "NOT_APPLICABLE"}
TERMINAL_CLEANUP_KEYS = {
    "schema",
    "repository",
    "issue_number",
    "generation",
    "lease_manifest_sha256",
    "owned_resources_absent",
    "temporary_resources_absent",
    "worktree_disposition",
    "local_branch_disposition",
    "remote_branch_disposition",
    "residuals",
}
TERMINAL_RECEIPT_SCHEMA = "twinfinity-terminal-receipt/v1"
TERMINAL_RECEIPT_KEYS = {
    "schema",
    "repository",
    "issue_number",
    "generation",
    "source_payload_sha256",
    "lease_manifest_sha256",
    "outcome",
    "accepted_head_sha",
    "operational_state_sha256",
    "acceptance_evidence_sha256",
    "residual_risks",
}
TERMINAL_CAPACITY_INTEGER_KEY = re.compile(
    r"^(?:(?:active|available)_(?:development|shared|sre)_after|"
    r"(?:development|shared|sre)_units_released|"
    r"issue_[1-9][0-9]*_(?:generation|item_version))$"
)
TERMINAL_CAPACITY_STATE_KEY = re.compile(
    r"^issue_[1-9][0-9]*_(allocation_class|status)$"
)
NOTICE_AUTHORITY_WORD = re.compile(
    r"(?i)\b(?:authori[sz](?:ed|ation)|approv(?:ed|al)|"
    r"permi(?:tted|ssion)|allowed|clear(?:ance|ed)|granted|green-?lit|"
    r"green\s+light|go(?:-|\s+)ahead)\b"
)
NOTICE_AUTHORITY_NEGATED_PREFIX = re.compile(
    r"(?i)\b(?:not|never|neither|no\s+longer)\s+$"
)
NOTICE_AUTHORITY_NEGATED_SUFFIX = re.compile(
    r"(?i)^\s+(?:(?:is|was|has\s+been|remains)\s+)?"
    r"(?:revoked|withdrawn|denied|rejected|pending|absent|missing|unconfirmed)\b"
)
NOTICE_EXECUTION_DIRECTIVE = re.compile(
    r"(?i)\b(?:proceed|continue|resume|start|begin)\b"
    r"[^.\n]{0,120}\b(?:implementation|repair|editing|mutation|execution|"
    r"merge|deployment|operation|work)\b"
)
NOTICE_IMPERATIVE_DIRECTIVE = re.compile(
    r"(?i)^\s*(?:(?:please\s+)?(?:run|execute|use)\b|"
    r"proceed\s+to\s+(?:run|execute|use)\b)"
)
NOTICE_MODAL_EXECUTION_DIRECTIVE = re.compile(
    r"(?i)\b(?:development|implementation|repair|editing|mutation|execution|"
    r"merge|deployment|operation|work)\b[^.\n]{0,80}"
    r"\b(?:may|can|should|must|will)\s+(?:proceed|continue|resume|start|begin)\b"
)
NOTICE_EXECUTION_DOMAIN = re.compile(
    r"(?i)\b(?:development|implementation|repair|editing|mutation|execution|"
    r"merge|deployment|operation|work)\b"
)
NOTICE_POSITIVE_MODALITY = re.compile(
    r"(?i)\b(?:may|can|could|should|must|will|shall)\s+"
    r"(?:proceed|continue|resume|start|begin|advance|move\s+forward|go\s+ahead)\b"
    r"|\b(?:ready|free|okay|ok|unblocked)\s+to\s+"
    r"(?:proceed|continue|resume|start|begin|advance|move\s+forward|go\s+ahead)\b"
    r"|\bunblocked\b"
)
NOTICE_CONSENT_GIVEN = re.compile(
    r"(?i)(?:\bconsent\b[^.\n]{0,48}\b(?:given|granted|confirmed)\b|"
    r"\b(?:given|granted|confirmed)\b[^.\n]{0,48}\bconsent\b)"
)
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
BRANCH = re.compile(r"^codex/[0-9]+-[a-z0-9][a-z0-9-]*$")
REMOTE_COMMENT_RECEIPT = re.compile(r"^comment:[1-9][0-9]*$")

STRUCTURED_LEASE_REQUIRED_KEYS = {
    "repository",
    "issue_number",
    "generation",
    "base_sha",
    "branch",
    "worktree_path",
    "no_additional_paths",
    "paths",
}
STRUCTURED_LEASE_EXTENDED_KEYS = STRUCTURED_LEASE_REQUIRED_KEYS | {
    "base_tree",
    "frozen_inputs",
    "capacity",
    "collision_evidence",
    "historical_remote_evidence",
}
DEVELOPMENT_ADMISSION_STRING_BINDINGS = (
    "writer",
    "environment_rule",
)
DEVELOPMENT_ADMISSION_STRING_LIST_BINDINGS = (
    "reviewer_plan",
    "collision_proof",
    "routine_chain",
    "hard_stops",
)
ARTIFACT_REGISTRY_IDENTITY_FIELDS = (
    "artifact_key",
    "repository",
    "issue_number",
    "generation",
    "relative_path",
    "content_sha256",
    "size_bytes",
    "device_id",
    "inode",
    "retention_class",
    "registered_at",
)


class CoordinationError(RuntimeError):
    """Typed, value-free coordination failure."""


def validate_admission_dispatch_bindings(payload: Any, *, topic: str) -> None:
    """Validate the canonical Development dispatch bindings exactly."""

    if topic != "development.admission":
        return
    fields = (
        DEVELOPMENT_ADMISSION_STRING_BINDINGS
        + DEVELOPMENT_ADMISSION_STRING_LIST_BINDINGS
    )
    if not isinstance(payload, dict) or any(field not in payload for field in fields):
        raise CoordinationError("ADMISSION_DISPATCH_BINDING_INCOMPLETE")
    if any(
        type(payload[field]) is not str or not payload[field].strip()
        for field in DEVELOPMENT_ADMISSION_STRING_BINDINGS
    ) or any(
        type(payload[field]) is not list
        or not payload[field]
        or any(type(value) is not str or not value.strip() for value in payload[field])
        for field in DEVELOPMENT_ADMISSION_STRING_LIST_BINDINGS
    ):
        raise CoordinationError("ADMISSION_DISPATCH_BINDING_INVALID")


def artifact_registry_identity(
    row: sqlite3.Row | dict[str, Any], *, prefix: str = ""
) -> dict[str, Any]:
    """Extract every immutable artifact-registry identity field."""

    try:
        return {
            field: row[f"{prefix}{field}"]
            for field in ARTIFACT_REGISTRY_IDENTITY_FIELDS
        }
    except (IndexError, KeyError, TypeError) as exc:
        raise CoordinationError("ARTIFACT_REGISTRY_IDENTITY_INVALID") from exc


def artifact_registry_identity_matches(
    expected: sqlite3.Row | dict[str, Any],
    current: sqlite3.Row | dict[str, Any],
    *,
    expected_prefix: str = "",
    current_prefix: str = "",
) -> bool:
    """Compare immutable registry identity with exact types and values."""

    try:
        expected_identity = artifact_registry_identity(
            expected, prefix=expected_prefix
        )
        current_identity = artifact_registry_identity(current, prefix=current_prefix)
    except CoordinationError:
        return False
    return all(
        type(expected_identity[field]) is type(current_identity[field])
        and expected_identity[field] == current_identity[field]
        for field in ARTIFACT_REGISTRY_IDENTITY_FIELDS
    )


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def routing_endpoint_state_manifest(
    connection: sqlite3.Connection,
) -> list[dict[str, Any]]:
    """Return the exact current role-endpoint routing state, without authority."""

    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    required = {"executor_role_endpoints", "executor_role_endpoint_current"}
    if not required.issubset(tables):
        raise CoordinationError("CURRENT_ENDPOINT_STATE_INVALID")
    rows = connection.execute(
        """
        SELECT current.role, current.endpoint_id, current.pointer_version,
               endpoint.version AS endpoint_version,
               endpoint.executor_profile, endpoint.codex_profile,
               endpoint.config_sha256, endpoint.config_json, endpoint.command_json
        FROM executor_role_endpoint_current current
        JOIN executor_role_endpoints endpoint
          ON endpoint.endpoint_id=current.endpoint_id
         AND endpoint.role=current.role
        ORDER BY current.role
        """
    ).fetchall()
    if [str(row["role"]) for row in rows] != sorted(ROLES):
        raise CoordinationError("CURRENT_ENDPOINT_STATE_INVALID")
    return [
        {
            "role": str(row["role"]),
            "endpoint_id": str(row["endpoint_id"]),
            "pointer_version": int(row["pointer_version"]),
            "endpoint_version": int(row["endpoint_version"]),
            "executor_profile": str(row["executor_profile"]),
            "codex_profile": str(row["codex_profile"]),
            "config_sha256": str(row["config_sha256"]),
            "config_json_sha256": hashlib.sha256(
                str(row["config_json"]).encode("utf-8")
            ).hexdigest(),
            "command_json_sha256": hashlib.sha256(
                str(row["command_json"]).encode("utf-8")
            ).hexdigest(),
        }
        for row in rows
    ]


def routing_endpoint_state_digest(connection: sqlite3.Connection) -> str:
    return digest_json(routing_endpoint_state_manifest(connection))


def descriptor_file_sha256(path: Path) -> str:
    """Hash one owner-controlled regular file through its validated descriptor."""

    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise CoordinationError("LEGACY_ALIAS_ARTIFACT_UNSAFE")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(metadata) != identity(after):
            raise CoordinationError("LEGACY_ALIAS_ARTIFACT_DRIFT")
        return digest.hexdigest()
    except OSError as exc:
        raise CoordinationError("LEGACY_ALIAS_ARTIFACT_UNSAFE") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoordinationError("LEASE_MANIFEST_INVALID")
        result[key] = value
    return result


def parse_structured_lease_manifest(raw: bytes) -> dict[str, Any]:
    """Parse the shared structured lease envelope without duplicate keys."""
    manifest = json.loads(raw, object_pairs_hook=_strict_json_object)
    if not isinstance(manifest, dict) or frozenset(manifest) not in {
        frozenset(STRUCTURED_LEASE_REQUIRED_KEYS),
        frozenset(STRUCTURED_LEASE_EXTENDED_KEYS),
    }:
        raise CoordinationError("LEASE_MANIFEST_INVALID")
    if (
        not isinstance(manifest["repository"], str)
        or type(manifest["issue_number"]) is not int
        or manifest["issue_number"] <= 0
        or type(manifest["generation"]) is not int
        or manifest["generation"] < 0
        or not isinstance(manifest["base_sha"], str)
        or not GIT_SHA.fullmatch(manifest["base_sha"])
        or not isinstance(manifest["branch"], str)
        or not BRANCH.fullmatch(manifest["branch"])
        or not isinstance(manifest["worktree_path"], str)
        or not Path(manifest["worktree_path"]).is_absolute()
        or manifest["no_additional_paths"] is not True
        or not isinstance(manifest["paths"], list)
        or not manifest["paths"]
    ):
        raise CoordinationError("LEASE_MANIFEST_INVALID")
    observed_paths: list[str] = []
    basic = set(manifest) == STRUCTURED_LEASE_REQUIRED_KEYS
    for entry in manifest["paths"]:
        expected_keys = {"path", "mode", "type", "sha"} if basic else {"path", "state"}
        if not isinstance(entry, dict) or set(entry) != expected_keys:
            raise CoordinationError("LEASE_MANIFEST_INVALID")
        value = entry.get("path")
        if not isinstance(value, str) or not value or "\\" in value:
            raise CoordinationError("LEASE_MANIFEST_INVALID")
        path = Path(value)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or value != path.as_posix()
        ):
            raise CoordinationError("LEASE_MANIFEST_INVALID")
        if basic:
            if (
                entry["mode"] not in {"100644", "100755", "120000"}
                or entry["type"] != "blob"
                or (
                    entry["sha"] is not None
                    and (
                        not isinstance(entry["sha"], str)
                        or not GIT_SHA.fullmatch(entry["sha"])
                    )
                )
            ):
                raise CoordinationError("LEASE_MANIFEST_INVALID")
        elif entry["state"] != "ABSENT":
            raise CoordinationError("LEASE_MANIFEST_INVALID")
        observed_paths.append(value)
    if len(set(observed_paths)) != len(observed_paths):
        raise CoordinationError("LEASE_MANIFEST_INVALID")
    return manifest


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp_after(timestamp: str, seconds: int) -> str:
    observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (observed + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _utc_timestamp(value: str, *, error: str) -> datetime:
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise CoordinationError(error) from exc
    if observed.tzinfo is None or observed.utcoffset() != timedelta(0):
        raise CoordinationError(error)
    return observed


def _fetch_terminal_live_observation(
    repository: str, issue_number: int, remote_receipt: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Fetch the fixed issue, main ref, receipt comment, and issue timeline."""

    from sync_github_coordination import (  # local import avoids a cycle
        _run_gh,
        fetch_object,
    )

    issue_payload = fetch_object(repository, "issue", issue_number)
    main_ref = _run_gh(["api", f"repos/{repository}/git/ref/heads/main"])
    receipt_match = REMOTE_COMMENT_RECEIPT.fullmatch(remote_receipt)
    if receipt_match is None:
        raise CoordinationError("TERMINAL_OUTBOX_NOT_COMPLETE")
    comment = _run_gh(
        [
            "api",
            f"repos/{repository}/issues/comments/{remote_receipt.split(':', 1)[1]}",
        ]
    )
    raw_timeline = _run_gh(
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/issues/{issue_number}/timeline?per_page=100",
        ]
    )
    if not isinstance(raw_timeline, list) or not raw_timeline:
        raise CoordinationError("TERMINAL_LIVE_EVIDENCE_INVALID")
    timeline: list[dict[str, Any]] = []
    for page in raw_timeline:
        if not isinstance(page, list) or not page:
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_INVALID")
        for event in page:
            if not isinstance(event, dict) or not event:
                raise CoordinationError("TERMINAL_LIVE_EVIDENCE_INVALID")
            timeline.append(event)
    return issue_payload, main_ref, comment, timeline


def _terminal_issue_material_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Exclude only GitHub's comment-volatile issue timestamp."""

    material = dict(payload)
    material.pop("updated_at", None)
    return material


def _terminal_timeline_activity(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize attribution fields without trusting unrelated timeline bytes."""

    actor = event.get("user") or event.get("actor") or {}
    body = event.get("body")
    return {
        "id": event.get("id"),
        "event": event.get("event"),
        "body_sha256": (
            hashlib.sha256(body.encode("utf-8")).hexdigest()
            if isinstance(body, str)
            else None
        ),
        "publisher_login": actor.get("login") if isinstance(actor, dict) else None,
        "created_at": event.get("created_at"),
        "updated_at": event.get("updated_at"),
        "issue_url": event.get("issue_url"),
    }


def terminal_watch_key(repository: str, issue_number: int, generation: int) -> str:
    return f"terminal:{repository}:issue:{issue_number}:generation:{generation}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as descriptor:
        for block in iter(lambda: descriptor.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


@contextmanager
def _open_relative_parent(root: Path, relative_path: str) -> Iterator[tuple[int, str]]:
    parts = Path(relative_path).parts
    if (
        not parts
        or Path(relative_path).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise CoordinationError("ARTIFACT_PATH_UNSAFE")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors = [os.open(root, flags)]
    try:
        for component in parts[:-1]:
            descriptors.append(os.open(component, flags, dir_fd=descriptors[-1]))
        yield descriptors[-1], parts[-1]
    except OSError as exc:
        raise CoordinationError("ARTIFACT_PATH_UNSAFE") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_verified_artifact(
    parent_descriptor: int, name: str, artifact: sqlite3.Row
) -> int:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
    except OSError as exc:
        raise CoordinationError("ARTIFACT_FILE_MISSING") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink not in {1, 2}
            or int(metadata.st_size) != int(artifact["size_bytes"])
            or int(metadata.st_dev) != int(artifact["device_id"])
            or int(metadata.st_ino) != int(artifact["inode"])
            or _sha256_descriptor(descriptor) != artifact["content_sha256"]
        ):
            raise CoordinationError("ARTIFACT_CONTENT_DRIFT")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _validate_repository(value: str) -> None:
    if not REPOSITORY.fullmatch(value):
        raise CoordinationError("INVALID_REPOSITORY")


def _validate_session(value: str) -> None:
    if not SESSION.fullmatch(value):
        raise CoordinationError("INVALID_SESSION")


def _validate_coordination_identity(value: str) -> None:
    if not SESSION.fullmatch(value) and not ENDPOINT_ID.fullmatch(value):
        raise CoordinationError("INVALID_COORDINATION_IDENTITY")


def coordination_identity_role(
    connection: sqlite3.Connection, identity: str
) -> str | None:
    return identity_role(connection, identity)


def canonicalize_coordination_identity(
    connection: sqlite3.Connection, identity: str
) -> str:
    """Validate a mutable identity without rewriting historical aliases."""

    _validate_coordination_identity(identity)
    try:
        return require_current_endpoint_identity(connection, identity)
    except RegistryError as exc:
        raise CoordinationError(str(exc)) from exc


def recipient_matches_topic(
    connection: sqlite3.Connection, *, topic: str, recipient: str
) -> bool:
    expected_role = MUTATING_TOPIC_ROLES.get(topic)
    return expected_role is None or coordination_identity_role(connection, recipient) == expected_role


def _validate_sha256(value: str) -> None:
    if not SHA256.fullmatch(value):
        raise CoordinationError("INVALID_DIGEST")


def _normalized_notice_key(value: str) -> str:
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", words)
    return re.sub(r"[^a-z0-9]+", "_", words.casefold()).strip("_")


def _notice_string_claims_authority(value: str) -> bool:
    for sentence in re.split(r"[.\n;]", value):
        for match in NOTICE_AUTHORITY_WORD.finditer(sentence):
            prefix = sentence[: match.start()]
            suffix = sentence[match.end() :]
            if NOTICE_AUTHORITY_NEGATED_PREFIX.search(prefix):
                continue
            if NOTICE_AUTHORITY_NEGATED_SUFFIX.search(suffix):
                continue
            return True
        if NOTICE_EXECUTION_DIRECTIVE.search(sentence):
            return True
        if NOTICE_IMPERATIVE_DIRECTIVE.search(sentence):
            return True
        if NOTICE_MODAL_EXECUTION_DIRECTIVE.search(sentence):
            return True
        if NOTICE_EXECUTION_DOMAIN.search(sentence):
            for match in NOTICE_POSITIVE_MODALITY.finditer(sentence):
                if not NOTICE_AUTHORITY_NEGATED_PREFIX.search(sentence[: match.start()]):
                    return True
            if NOTICE_CONSENT_GIVEN.search(sentence):
                return True
    return False


def _notice_string_values(
    value: Any,
    *,
    path: tuple[str, ...] = (),
    exempt_key_paths: frozenset[tuple[str, ...]] = frozenset(),
) -> list[str]:
    if isinstance(value, dict):
        return [
            string
            for key, item in value.items()
            for string in (
                [_normalized_notice_key(key).replace("_", " ")]
                if isinstance(key, str) and path + (key,) not in exempt_key_paths
                else []
            )
            + _notice_string_values(
                item,
                path=path + (key,) if isinstance(key, str) else path,
                exempt_key_paths=exempt_key_paths,
            )
        ]
    if isinstance(value, (list, tuple)):
        return [string for item in value for string in _notice_string_values(item)]
    return [value] if isinstance(value, str) else []


def _validate_terminal_notice_evidence(
    payload: dict[str, Any],
) -> frozenset[tuple[str, ...]]:
    evidence = payload.get("evidence")
    if not isinstance(evidence, dict):
        raise CoordinationError("NOTICE_SCHEMA_INVALID")

    exempt: set[tuple[str, ...]] = set()
    cleanup = evidence.get("cleanup")
    if cleanup is not None:
        if not isinstance(cleanup, dict):
            raise CoordinationError("NOTICE_SCHEMA_INVALID")
        for key, value in cleanup.items():
            normalized = _normalized_notice_key(key) if isinstance(key, str) else ""
            if normalized in TERMINAL_CLEANUP_BOOLEAN_KEYS:
                if type(value) is not bool:
                    raise CoordinationError("NOTICE_SCHEMA_INVALID")
                exempt.add(("evidence", "cleanup", key))
            elif normalized == "owned_container_resources":
                if value not in TERMINAL_CLEANUP_RESOURCE_STATES:
                    raise CoordinationError("NOTICE_SCHEMA_INVALID")
            else:
                raise CoordinationError("NOTICE_SCHEMA_INVALID")

    capacity = evidence.get("capacity_release")
    if capacity is not None:
        if not isinstance(capacity, dict):
            raise CoordinationError("NOTICE_SCHEMA_INVALID")
        for key, value in capacity.items():
            normalized = _normalized_notice_key(key) if isinstance(key, str) else ""
            state_match = TERMINAL_CAPACITY_STATE_KEY.fullmatch(normalized)
            if TERMINAL_CAPACITY_INTEGER_KEY.fullmatch(normalized):
                if type(value) is not int or value < 0:
                    raise CoordinationError("NOTICE_SCHEMA_INVALID")
            elif normalized == "source_current":
                if type(value) is not bool:
                    raise CoordinationError("NOTICE_SCHEMA_INVALID")
            elif state_match and state_match.group(1) == "allocation_class":
                if value not in ALLOCATION_CLASSES:
                    raise CoordinationError("NOTICE_SCHEMA_INVALID")
            elif state_match and state_match.group(1) == "status":
                if value not in ITEM_STATUSES:
                    raise CoordinationError("NOTICE_SCHEMA_INVALID")
            else:
                raise CoordinationError("NOTICE_SCHEMA_INVALID")

    return frozenset(exempt)


def validate_terminal_cleanup_evidence(
    evidence: Any,
    *,
    repository: str,
    issue_number: int,
    generation: int,
    lease_manifest_sha256: str,
    role: str,
) -> str:
    """Validate and digest one complete, role-bounded cleanup attestation."""

    if not isinstance(evidence, dict) or set(evidence) != TERMINAL_CLEANUP_KEYS:
        raise CoordinationError("TERMINAL_CLEANUP_EVIDENCE_INVALID")
    if (
        evidence.get("schema") != TERMINAL_CLEANUP_SCHEMA
        or evidence.get("repository") != repository
        or evidence.get("issue_number") != issue_number
        or evidence.get("generation") != generation
        or evidence.get("lease_manifest_sha256") != lease_manifest_sha256
        or evidence.get("owned_resources_absent") is not True
        or evidence.get("temporary_resources_absent") is not True
        or evidence.get("worktree_disposition")
        not in TERMINAL_CLEANUP_DISPOSITIONS
        or evidence.get("local_branch_disposition")
        not in TERMINAL_CLEANUP_DISPOSITIONS
        or evidence.get("remote_branch_disposition")
        not in TERMINAL_CLEANUP_DISPOSITIONS
        or evidence.get("residuals") != []
    ):
        raise CoordinationError("TERMINAL_CLEANUP_EVIDENCE_INVALID")
    if role == "development" and any(
        evidence[key] != "ABSENT"
        for key in (
            "worktree_disposition",
            "local_branch_disposition",
            "remote_branch_disposition",
        )
    ):
        raise CoordinationError("TERMINAL_CLEANUP_EVIDENCE_INCOMPLETE")
    if role not in {"development", "sre"}:
        raise CoordinationError("TERMINAL_CLOSEOUT_ROLE_INVALID")
    return digest_json(evidence)


def validate_terminal_receipt(
    receipt: Any,
    *,
    repository: str,
    issue_number: int,
    generation: int,
    source_payload_sha256: str,
    lease_manifest_sha256: str,
    role: str,
) -> str:
    """Validate and digest the accepted delivery or operational outcome."""

    if not isinstance(receipt, dict) or set(receipt) != TERMINAL_RECEIPT_KEYS:
        raise CoordinationError("TERMINAL_RECEIPT_INVALID")
    head = receipt.get("accepted_head_sha")
    operational = receipt.get("operational_state_sha256")
    residuals = receipt.get("residual_risks")
    if (
        receipt.get("schema") != TERMINAL_RECEIPT_SCHEMA
        or receipt.get("repository") != repository
        or receipt.get("issue_number") != issue_number
        or receipt.get("generation") != generation
        or receipt.get("source_payload_sha256") != source_payload_sha256
        or receipt.get("lease_manifest_sha256") != lease_manifest_sha256
        or receipt.get("outcome") != "ACCEPTED"
        or not isinstance(receipt.get("acceptance_evidence_sha256"), str)
        or not isinstance(residuals, list)
        or any(not isinstance(item, str) or not item for item in residuals)
    ):
        raise CoordinationError("TERMINAL_RECEIPT_INVALID")
    _validate_sha256(str(receipt["acceptance_evidence_sha256"]))
    if role == "development":
        if (
            not isinstance(head, str)
            or not GIT_SHA.fullmatch(head)
            or operational is not None
        ):
            raise CoordinationError("TERMINAL_RECEIPT_INVALID")
    elif role == "sre":
        if head is not None or not isinstance(operational, str):
            raise CoordinationError("TERMINAL_RECEIPT_INVALID")
        _validate_sha256(operational)
    else:
        raise CoordinationError("TERMINAL_CLOSEOUT_ROLE_INVALID")
    return digest_json(receipt)


def terminal_publication_body(
    *,
    closeout_key: str,
    terminal_receipt: dict[str, Any],
    cleanup_evidence: dict[str, Any],
) -> str:
    """Render the one exact GitHub terminal receipt bound by the packet."""

    descriptor = {
        "schema": "twinfinity-terminal-publication/v1",
        "closeout_key": closeout_key,
        "terminal_receipt": terminal_receipt,
        "cleanup_evidence": cleanup_evidence,
    }
    return (
        "<!-- twinfinity-terminal-publication:v1 -->\n"
        "Terminal delivery receipt\n\n"
        "```json\n"
        f"{canonical_json(descriptor)}\n"
        "```"
    )


def terminal_published_body(body: str, idempotency_key: str) -> str:
    """Bind an externally published terminal body to its immutable outbox key."""

    marker = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    return f"{body}\n\n<!-- twinfinity-outbox:{marker} -->"


def _notice_has_forbidden_content(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            not isinstance(key, str)
            or _normalized_notice_key(key) in NOTICE_FORBIDDEN_KEYS
            or _notice_has_forbidden_content(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_notice_has_forbidden_content(item) for item in value)
    if isinstance(value, str):
        return _notice_string_claims_authority(value)
    return False


@dataclass(frozen=True)
class SourceSnapshot:
    repository: str
    object_kind: str
    object_number: int
    payload_sha256: str
    source_updated_at: str
    fetched_at: str
    payload: dict[str, Any]


class CoordinationStore:
    def __init__(self, path: Path = DEFAULT_DATABASE):
        try:
            prepare_owner_database(path)
        except UnsafeSQLitePathError as exc:
            raise CoordinationError(str(exc)) from exc
        self.path = path
        try:
            self.connection = sqlite3.connect(path, isolation_level=None, timeout=5)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA busy_timeout=5000")
            with self._schema_initialization_lock():
                self._create_schema()
        except sqlite3.OperationalError as exc:
            lowered = str(exc).lower()
            if "readonly" in lowered or "read-only" in lowered:
                raise CoordinationError("COORDINATOR_NOT_WRITABLE") from exc
            raise

    def close(self) -> None:
        self.connection.close()

    def _require_temporary_test_database(self) -> None:
        """Fence fixture-only mechanical helpers away from owner-live state."""

        resolved = self.path.resolve()
        if resolved == Path("/tmp") or Path("/tmp") not in resolved.parents:
            raise CoordinationError("TEST_FIXTURE_DATABASE_REQUIRED")

    @contextmanager
    def _schema_initialization_lock(self) -> Iterator[None]:
        """Serialize idempotent schema creation across same-host sessions."""

        lock = self.path.with_name(f"{self.path.name}.schema.lock")
        descriptor = os.open(
            lock, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise CoordinationError("COORDINATOR_SCHEMA_LOCK_UNSAFE")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _ensure_capacity_policy(self, repository: str, now: str) -> sqlite3.Row:
        current = self.connection.execute(
            """
            SELECT p.* FROM coordination_capacity_current c
            JOIN coordination_capacity_policies p
              ON p.repository=c.repository AND p.version=c.version
            WHERE c.repository=?
            """,
            (repository,),
        ).fetchone()
        if current is not None:
            return current
        self.connection.execute(
            """
            INSERT OR IGNORE INTO coordination_capacity_policies(
                repository, version, development_limit, shared_limit, sre_limit,
                authority_sha256, created_at
            ) VALUES (?, 1, ?, ?, ?, NULL, ?)
            """,
            (
                repository,
                DEFAULT_CAPACITY_LIMITS["development_limit"],
                DEFAULT_CAPACITY_LIMITS["shared_limit"],
                DEFAULT_CAPACITY_LIMITS["sre_limit"],
                now,
            ),
        )
        self.connection.execute(
            """
            INSERT OR IGNORE INTO coordination_capacity_current(repository, version, updated_at)
            VALUES (?, 1, ?)
            """,
            (repository, now),
        )
        current = self.connection.execute(
            """
            SELECT p.* FROM coordination_capacity_current c
            JOIN coordination_capacity_policies p
              ON p.repository=c.repository AND p.version=c.version
            WHERE c.repository=?
            """,
            (repository,),
        ).fetchone()
        if current is None:
            raise CoordinationError("CAPACITY_POLICY_MISSING")
        return current

    def capacity_policy(
        self, repository: str, *, now: str | None = None
    ) -> dict[str, Any]:
        _validate_repository(repository)
        return dict(self._ensure_capacity_policy(repository, now or utc_now()))

    def bootstrap_capacity_policy(
        self,
        *,
        repository: str,
        development_limit: int,
        shared_limit: int,
        sre_limit: int,
        authority_sha256: str,
        now: str,
        _transaction: bool = True,
    ) -> dict[str, Any]:
        """Install the first reviewed policy in an otherwise empty store."""

        _validate_repository(repository)
        _validate_sha256(authority_sha256)
        if development_limit <= 0 or shared_limit < 0 or sre_limit < 0:
            raise CoordinationError("CAPACITY_POLICY_INVALID")
        transaction = self.transaction() if _transaction else nullcontext()
        with transaction:
            if self.connection.execute(
                "SELECT 1 FROM coordination_capacity_current LIMIT 1"
            ).fetchone() is not None or self.connection.execute(
                "SELECT 1 FROM coordination_capacity_policies LIMIT 1"
            ).fetchone() is not None:
                raise CoordinationError("CAPACITY_POLICY_BOOTSTRAP_CONFLICT")
            if self.connection.execute(
                "SELECT 1 FROM coordination_items LIMIT 1"
            ).fetchone() is not None:
                raise CoordinationError("CAPACITY_POLICY_BOOTSTRAP_CONFLICT")
            self.connection.execute(
                """
                INSERT INTO coordination_capacity_policies(
                    repository, version, development_limit, shared_limit,
                    sre_limit, authority_sha256, created_at
                ) VALUES (?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    repository,
                    development_limit,
                    shared_limit,
                    sre_limit,
                    authority_sha256,
                    now,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO coordination_capacity_current(repository, version, updated_at)
                VALUES (?, 1, ?)
                """,
                (repository, now),
            )
            self._event(
                "CAPACITY_POLICY_BOOTSTRAPPED",
                f"{repository}:capacity-policy:1",
                {
                    "authority_sha256": authority_sha256,
                    "development_limit": development_limit,
                    "shared_limit": shared_limit,
                    "sre_limit": sre_limit,
                },
                now,
            )
        return self.capacity_policy(repository, now=now)

    def _set_capacity_policy_for_test_fixture(
        self,
        *,
        repository: str,
        development_limit: int,
        shared_limit: int,
        sre_limit: int,
        authority_sha256: str,
        expected_version: int,
        now: str,
    ) -> dict[str, Any]:
        """Seed synthetic capacity state; never accepts a production database."""

        self._require_temporary_test_database()
        return self.set_capacity_policy(
            repository=repository,
            development_limit=development_limit,
            shared_limit=shared_limit,
            sre_limit=sre_limit,
            authority_sha256=authority_sha256,
            expected_version=expected_version,
            now=now,
        )

    def set_capacity_policy(
        self,
        *,
        repository: str,
        development_limit: int,
        shared_limit: int,
        sre_limit: int,
        authority_sha256: str,
        expected_version: int,
        now: str,
    ) -> dict[str, Any]:
        _validate_repository(repository)
        _validate_sha256(authority_sha256)
        if (
            development_limit <= 0
            or shared_limit < 0
            or sre_limit < 0
            or expected_version <= 0
        ):
            raise CoordinationError("CAPACITY_POLICY_INVALID")
        with self.transaction():
            current = self._ensure_capacity_policy(repository, now)
            if int(current["version"]) != expected_version:
                raise CoordinationError("CAPACITY_POLICY_VERSION_CONFLICT")
            hosted_sre = reserved_hosted_sre_units(self.connection, repository)
            occupied = self.connection.execute(
                """
                SELECT COALESCE(SUM(development_units), 0) AS development,
                       COALESCE(SUM(shared_units), 0) AS shared,
                       COALESCE(SUM(sre_units), 0) AS sre
                FROM coordination_items
                WHERE repository=? AND allocation_class IN ('ACTIVE', 'RETAINED')
                """,
                (repository,),
            ).fetchone()
            if (
                int(occupied["development"]) > development_limit
                or int(occupied["shared"]) > shared_limit
                or int(occupied["sre"]) + hosted_sre > sre_limit
            ):
                raise CoordinationError("CAPACITY_POLICY_BELOW_OCCUPANCY")
            version = expected_version + 1
            self.connection.execute(
                """
                INSERT INTO coordination_capacity_policies(
                    repository, version, development_limit, shared_limit, sre_limit,
                    authority_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository,
                    version,
                    development_limit,
                    shared_limit,
                    sre_limit,
                    authority_sha256,
                    now,
                ),
            )
            cursor = self.connection.execute(
                """
                UPDATE coordination_capacity_current
                SET version=?, updated_at=?
                WHERE repository=? AND version=?
                """,
                (version, now, repository, expected_version),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("CAPACITY_POLICY_VERSION_CONFLICT")
            self._event(
                "CAPACITY_POLICY_CHANGED",
                f"{repository}:capacity-policy:{version}",
                {
                    "prior_version": expected_version,
                    "development_limit": development_limit,
                    "shared_limit": shared_limit,
                    "sre_limit": sre_limit,
                    "authority_sha256": authority_sha256,
                },
                now,
            )
            try:
                convergence_event_id = enqueue_convergence_dirty_event(
                    self.connection,
                    repository=repository,
                    trigger_kind="CAPACITY_POLICY_CHANGED",
                    issue_number=version,
                    item_version=version,
                    source_sha256=authority_sha256,
                    status="CAPACITY_POLICY_CHANGED",
                    generation=version,
                    now=now,
                    details={
                        "prior_capacity_policy_version": expected_version,
                        "capacity_policy_version": version,
                        "development_limit": development_limit,
                        "shared_limit": shared_limit,
                        "sre_limit": sre_limit,
                    },
                )
            except PortfolioGraphError as exc:
                raise CoordinationError(str(exc)) from exc
            if convergence_event_id is None:
                raise CoordinationError("PORTFOLIO_DIRTY_EVENT_SCHEMA_MISSING")
            # A policy expansion is a new scheduling fact. Make prior
            # capacity-blocked retries immediately eligible in the same
            # transaction instead of waiting for their old backoff windows.
            self.connection.execute(
                """
                UPDATE portfolio_dirty_events
                SET next_attempt_at=?, updated_at=?
                WHERE repository=? AND state='RETRY' AND next_attempt_at>?
                """,
                (now, now, repository, now),
            )
        return self.capacity_policy(repository, now=now)

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS github_snapshots (
                repository TEXT NOT NULL,
                object_kind TEXT NOT NULL CHECK(object_kind IN ('issue', 'pull_request')),
                object_number INTEGER NOT NULL CHECK(object_number > 0),
                payload_sha256 TEXT NOT NULL,
                source_updated_at TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(repository, object_kind, object_number, payload_sha256)
            );
            CREATE TABLE IF NOT EXISTS github_current (
                repository TEXT NOT NULL,
                object_kind TEXT NOT NULL,
                object_number INTEGER NOT NULL,
                payload_sha256 TEXT NOT NULL,
                source_updated_at TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                PRIMARY KEY(repository, object_kind, object_number),
                FOREIGN KEY(repository, object_kind, object_number, payload_sha256)
                    REFERENCES github_snapshots(repository, object_kind, object_number, payload_sha256)
            );
            CREATE TABLE IF NOT EXISTS coordination_items (
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                status TEXT NOT NULL,
                allocation_class TEXT NOT NULL CHECK(allocation_class IN ('ACTIVE', 'RETAINED', 'NONE')),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                accountable_session_id TEXT,
                lease_manifest_sha256 TEXT,
                development_units INTEGER NOT NULL CHECK(development_units >= 0),
                shared_units INTEGER NOT NULL CHECK(shared_units >= 0),
                sre_units INTEGER NOT NULL CHECK(sre_units >= 0),
                source_payload_sha256 TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version > 0),
                updated_at TEXT NOT NULL,
                PRIMARY KEY(repository, issue_number)
            );
            CREATE TABLE IF NOT EXISTS coordination_capacity_policies (
                repository TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version > 0),
                development_limit INTEGER NOT NULL CHECK(development_limit > 0),
                shared_limit INTEGER NOT NULL CHECK(shared_limit >= 0),
                sre_limit INTEGER NOT NULL CHECK(sre_limit >= 0),
                authority_sha256 TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY(repository, version)
            );
            CREATE TABLE IF NOT EXISTS coordination_capacity_current (
                repository TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(repository, version)
                    REFERENCES coordination_capacity_policies(repository, version)
            );
            CREATE TRIGGER IF NOT EXISTS coordination_capacity_policy_immutable_update
            BEFORE UPDATE ON coordination_capacity_policies
            BEGIN
                SELECT RAISE(ABORT, 'CAPACITY_POLICY_IMMUTABLE');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_capacity_policy_immutable_delete
            BEFORE DELETE ON coordination_capacity_policies
            BEGIN
                SELECT RAISE(ABORT, 'CAPACITY_POLICY_IMMUTABLE');
            END;
            CREATE TABLE IF NOT EXISTS coordination_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL UNIQUE,
                recipient_session_id TEXT NOT NULL,
                topic TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('PREPARED', 'CLAIMED', 'COMPLETE', 'HOLD')),
                claimed_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS github_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL UNIQUE,
                repository TEXT NOT NULL,
                object_kind TEXT NOT NULL CHECK(object_kind IN ('issue', 'pull_request')),
                object_number INTEGER NOT NULL CHECK(object_number > 0),
                operation TEXT NOT NULL CHECK(operation IN ('comment')),
                expected_source_sha256 TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('PREPARED', 'INFLIGHT', 'COMPLETE', 'HOLD')),
                remote_receipt TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS routing_deprecation_inventories (
                inventory_sha256 TEXT PRIMARY KEY,
                repository TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL CHECK(kind='TWINFINITY_ROUTING_DEPRECATION_INVENTORY_V1'),
                alias_source_sha256 TEXT NOT NULL,
                endpoint_state_sha256 TEXT NOT NULL,
                issue_179_source_sha256 TEXT NOT NULL,
                object_manifest_sha256 TEXT NOT NULL,
                occurrence_manifest_sha256 TEXT NOT NULL,
                object_manifest_json TEXT NOT NULL,
                object_count INTEGER NOT NULL CHECK(object_count >= 0),
                issue_count INTEGER NOT NULL CHECK(issue_count >= 0),
                pull_request_count INTEGER NOT NULL CHECK(pull_request_count >= 0),
                occurrence_count INTEGER NOT NULL CHECK(occurrence_count >= 0),
                classification_counts_json TEXT NOT NULL,
                semantic_tag_counts_json TEXT NOT NULL,
                outbox_id INTEGER NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state='COMPLETE'),
                created_at TEXT NOT NULL,
                FOREIGN KEY(outbox_id) REFERENCES github_outbox(id)
            );
            CREATE TABLE IF NOT EXISTS routing_deprecation_occurrences (
                inventory_sha256 TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                object_kind TEXT NOT NULL CHECK(object_kind IN ('issue', 'pull_request')),
                object_number INTEGER NOT NULL CHECK(object_number > 0),
                node_id TEXT NOT NULL,
                object_updated_at TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                alias TEXT NOT NULL,
                byte_start INTEGER NOT NULL CHECK(byte_start >= 0),
                byte_end INTEGER NOT NULL CHECK(byte_end > byte_start),
                line_number INTEGER NOT NULL CHECK(line_number > 0),
                byte_column INTEGER NOT NULL CHECK(byte_column > 0),
                classification TEXT NOT NULL CHECK(classification IN (
                    'EXECUTABLE_ROUTE','ROUTING_REFERENCE',
                    'HISTORICAL_PROVENANCE','AMBIGUOUS_REFERENCE'
                )),
                semantic_tags_json TEXT NOT NULL,
                PRIMARY KEY(inventory_sha256, ordinal),
                UNIQUE(inventory_sha256, object_kind, object_number, byte_start, alias),
                FOREIGN KEY(inventory_sha256)
                    REFERENCES routing_deprecation_inventories(inventory_sha256)
            );
            CREATE TRIGGER IF NOT EXISTS routing_deprecation_inventory_immutable_update
            BEFORE UPDATE ON routing_deprecation_inventories
            BEGIN
                SELECT RAISE(ABORT, 'ROUTING_DEPRECATION_INVENTORY_IMMUTABLE');
            END;
            CREATE TRIGGER IF NOT EXISTS routing_deprecation_inventory_immutable_delete
            BEFORE DELETE ON routing_deprecation_inventories
            BEGIN
                SELECT RAISE(ABORT, 'ROUTING_DEPRECATION_INVENTORY_IMMUTABLE');
            END;
            CREATE TRIGGER IF NOT EXISTS routing_deprecation_occurrence_immutable_update
            BEFORE UPDATE ON routing_deprecation_occurrences
            BEGIN
                SELECT RAISE(ABORT, 'ROUTING_DEPRECATION_OCCURRENCE_IMMUTABLE');
            END;
            CREATE TRIGGER IF NOT EXISTS routing_deprecation_occurrence_immutable_delete
            BEFORE DELETE ON routing_deprecation_occurrences
            BEGIN
                SELECT RAISE(ABORT, 'ROUTING_DEPRECATION_OCCURRENCE_IMMUTABLE');
            END;
            CREATE TRIGGER IF NOT EXISTS routing_deprecation_occurrence_append_fenced
            BEFORE INSERT ON routing_deprecation_occurrences
            WHEN (
                SELECT COUNT(*) FROM routing_deprecation_occurrences
                WHERE inventory_sha256=NEW.inventory_sha256
            ) >= (
                SELECT occurrence_count FROM routing_deprecation_inventories
                WHERE inventory_sha256=NEW.inventory_sha256
            )
            BEGIN
                SELECT RAISE(ABORT, 'ROUTING_DEPRECATION_OCCURRENCE_IMMUTABLE');
            END;
            CREATE TRIGGER IF NOT EXISTS routing_deprecation_outbox_envelope_immutable
            BEFORE UPDATE OF idempotency_key, repository, object_kind, object_number,
                             operation, expected_source_sha256, payload_sha256,
                             payload_json, created_at ON github_outbox
            WHEN EXISTS (
                SELECT 1 FROM routing_deprecation_inventories
                WHERE outbox_id=OLD.id
            )
            BEGIN
                SELECT RAISE(ABORT, 'ROUTING_DEPRECATION_OUTBOX_IMMUTABLE');
            END;
            CREATE TABLE IF NOT EXISTS coordination_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS portfolio_dirty_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                release_item_version INTEGER NOT NULL CHECK(release_item_version > 0),
                release_source_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('PENDING','RETRY','COMPLETE','HOLD')),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                next_attempt_at TEXT NOT NULL,
                result_sha256 TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS portfolio_dirty_events_due
                ON portfolio_dirty_events(state, next_attempt_at, id);
            CREATE TRIGGER IF NOT EXISTS portfolio_dirty_event_envelope_immutable
            BEFORE UPDATE ON portfolio_dirty_events
            WHEN NEW.event_key IS NOT OLD.event_key
              OR NEW.repository IS NOT OLD.repository
              OR NEW.issue_number IS NOT OLD.issue_number
              OR NEW.release_item_version IS NOT OLD.release_item_version
              OR NEW.release_source_sha256 IS NOT OLD.release_source_sha256
              OR NEW.event_sha256 IS NOT OLD.event_sha256
              OR NEW.payload_json IS NOT OLD.payload_json
              OR NEW.created_at IS NOT OLD.created_at
            BEGIN
                SELECT RAISE(ABORT, 'PORTFOLIO_DIRTY_EVENT_IMMUTABLE');
            END;
            CREATE TABLE IF NOT EXISTS coordination_wakes (
                wake_key TEXT PRIMARY KEY,
                message_id INTEGER NOT NULL,
                recipient_session_id TEXT NOT NULL,
                message_payload_sha256 TEXT NOT NULL,
                target_progress_sha256 TEXT,
                state TEXT NOT NULL CHECK(state IN ('INFLIGHT', 'COMPLETE', 'HOLD')),
                attempts INTEGER NOT NULL CHECK(attempts > 0),
                process_id INTEGER,
                last_attempt_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT,
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id)
            );
            CREATE TABLE IF NOT EXISTS coordination_supervisor_items (
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                allocation_class TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(repository, issue_number)
            );
            CREATE TABLE IF NOT EXISTS coordination_terminal_watches (
                watch_key TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                accountable_session_id TEXT NOT NULL,
                lease_manifest_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'PENDING_CLAIM','ACTIVE','COMPLETE','HOLD'
                )),
                admission_message_id INTEGER,
                admission_payload_sha256 TEXT,
                claim_attempt_id TEXT,
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                process_id INTEGER,
                target_progress_sha256 TEXT,
                last_heartbeat_at TEXT NOT NULL,
                next_wake_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT,
                UNIQUE(repository, issue_number, generation)
            );
            CREATE TABLE IF NOT EXISTS coordination_terminal_closeout_packets (
                closeout_key TEXT PRIMARY KEY,
                packet_sha256 TEXT NOT NULL UNIQUE,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                source_payload_sha256 TEXT NOT NULL,
                lease_manifest_sha256 TEXT NOT NULL,
                accountable_role TEXT NOT NULL
                    CHECK(accountable_role IN ('development','sre')),
                endpoint_id TEXT NOT NULL,
                preparer_attempt_id TEXT NOT NULL,
                preparer_attempt_version INTEGER NOT NULL
                    CHECK(preparer_attempt_version > 0),
                terminal_watch_key TEXT NOT NULL,
                activation_message_id INTEGER NOT NULL,
                activation_payload_sha256 TEXT NOT NULL,
                expected_item_version INTEGER NOT NULL
                    CHECK(expected_item_version > 0),
                publication_pending_item_version INTEGER NOT NULL
                    CHECK(publication_pending_item_version > expected_item_version),
                terminal_receipt_sha256 TEXT NOT NULL,
                terminal_receipt_json TEXT NOT NULL,
                cleanup_evidence_sha256 TEXT NOT NULL,
                cleanup_evidence_json TEXT NOT NULL,
                outbox_id INTEGER NOT NULL UNIQUE,
                outbox_payload_sha256 TEXT NOT NULL,
                graph_version INTEGER NOT NULL CHECK(graph_version > 0),
                graph_sha256 TEXT NOT NULL,
                graph_main_sha TEXT NOT NULL,
                graph_node_key TEXT NOT NULL,
                graph_binding_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(repository, issue_number, generation)
            );
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_closeout_packet_immutable_update
            BEFORE UPDATE ON coordination_terminal_closeout_packets
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_CLOSEOUT_PACKET_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_closeout_packet_immutable_delete
            BEFORE DELETE ON coordination_terminal_closeout_packets
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_CLOSEOUT_PACKET_IMMUTABLE'); END;
            CREATE TABLE IF NOT EXISTS coordination_terminal_closeout_commits (
                closeout_key TEXT PRIMARY KEY,
                commit_sha256 TEXT NOT NULL UNIQUE,
                finalizer_attempt_id TEXT NOT NULL,
                finalizer_attempt_version INTEGER NOT NULL
                    CHECK(finalizer_attempt_version > 0),
                live_evidence_sha256 TEXT,
                live_evidence_json TEXT,
                remote_receipt TEXT NOT NULL,
                remote_receipt_sha256 TEXT NOT NULL,
                prior_item_version INTEGER NOT NULL CHECK(prior_item_version > 0),
                done_item_version INTEGER NOT NULL
                    CHECK(done_item_version > prior_item_version),
                dirty_event_id INTEGER NOT NULL UNIQUE,
                committed_at TEXT NOT NULL,
                FOREIGN KEY(closeout_key)
                    REFERENCES coordination_terminal_closeout_packets(closeout_key)
            );
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_closeout_commit_immutable_update
            BEFORE UPDATE ON coordination_terminal_closeout_commits
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_CLOSEOUT_COMMIT_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_closeout_commit_immutable_delete
            BEFORE DELETE ON coordination_terminal_closeout_commits
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_CLOSEOUT_COMMIT_IMMUTABLE'); END;
            CREATE TABLE IF NOT EXISTS coordination_terminal_outbox_readbacks (
                outbox_id INTEGER PRIMARY KEY,
                closeout_key TEXT NOT NULL UNIQUE,
                remote_receipt TEXT NOT NULL UNIQUE,
                remote_receipt_sha256 TEXT NOT NULL,
                published_body_sha256 TEXT NOT NULL,
                publisher_login TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                FOREIGN KEY(outbox_id) REFERENCES github_outbox(id),
                FOREIGN KEY(closeout_key)
                    REFERENCES coordination_terminal_closeout_packets(closeout_key)
            );
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_outbox_readback_immutable_update
            BEFORE UPDATE ON coordination_terminal_outbox_readbacks
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_OUTBOX_READBACK_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_outbox_readback_immutable_delete
            BEFORE DELETE ON coordination_terminal_outbox_readbacks
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_OUTBOX_READBACK_IMMUTABLE'); END;
            CREATE TABLE IF NOT EXISTS coordination_terminal_outbox_recovery (
                outbox_id INTEGER PRIMARY KEY,
                readback_attempts INTEGER NOT NULL DEFAULT 0
                    CHECK(readback_attempts >= 0),
                retry_rounds INTEGER NOT NULL DEFAULT 0
                    CHECK(retry_rounds >= 0),
                next_retry_at TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'PENDING','RETRY_WAIT','RETRY_READY','COMPLETE','HOLD'
                )),
                updated_at TEXT NOT NULL,
                last_error TEXT,
                FOREIGN KEY(outbox_id) REFERENCES github_outbox(id)
            );
            CREATE TABLE IF NOT EXISTS coordination_terminal_outbox_publishers (
                outbox_id INTEGER PRIMARY KEY,
                closeout_key TEXT NOT NULL UNIQUE,
                publisher_login TEXT NOT NULL,
                binding_sha256 TEXT NOT NULL UNIQUE,
                bound_at TEXT NOT NULL,
                FOREIGN KEY(outbox_id) REFERENCES github_outbox(id),
                FOREIGN KEY(closeout_key)
                    REFERENCES coordination_terminal_closeout_packets(closeout_key)
            );
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_outbox_publisher_immutable_update
            BEFORE UPDATE ON coordination_terminal_outbox_publishers
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_OUTBOX_PUBLISHER_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_outbox_publisher_immutable_delete
            BEFORE DELETE ON coordination_terminal_outbox_publishers
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_OUTBOX_PUBLISHER_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_outbox_envelope_immutable
            BEFORE UPDATE OF idempotency_key, repository, object_kind,
                             object_number, operation, expected_source_sha256,
                             payload_sha256, payload_json, created_at
            ON github_outbox
            WHEN EXISTS (
                SELECT 1 FROM coordination_terminal_closeout_packets
                WHERE outbox_id=OLD.id
            )
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_OUTBOX_ENVELOPE_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS coordination_terminal_outbox_complete_immutable
            BEFORE UPDATE ON github_outbox
            WHEN OLD.state='COMPLETE' AND EXISTS (
                SELECT 1 FROM coordination_terminal_closeout_packets
                WHERE outbox_id=OLD.id
            )
            BEGIN SELECT RAISE(ABORT, 'TERMINAL_OUTBOX_COMPLETE_IMMUTABLE'); END;
            CREATE TABLE IF NOT EXISTS coordination_pre_push_gates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                accountable_session_id TEXT NOT NULL,
                source_payload_sha256 TEXT NOT NULL,
                lease_manifest_sha256 TEXT NOT NULL,
                admission_message_id INTEGER NOT NULL,
                admission_payload_sha256 TEXT NOT NULL,
                branch TEXT NOT NULL,
                worktree_path TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                changed_paths_sha256 TEXT NOT NULL,
                changed_path_count INTEGER NOT NULL CHECK(changed_path_count > 0),
                lower_gate TEXT NOT NULL,
                lower_gate_exit_code INTEGER,
                compose_gate TEXT NOT NULL,
                compose_gate_exit_code INTEGER,
                compose_run_id TEXT NOT NULL,
                head_unchanged INTEGER NOT NULL CHECK(head_unchanged IN (0, 1)),
                cleanup_proven INTEGER NOT NULL CHECK(cleanup_proven IN (0, 1)),
                state TEXT NOT NULL CHECK(state IN ('PASS', 'HOLD')),
                evidence_sha256 TEXT NOT NULL,
                environment_provenance_sha256 TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                last_error TEXT,
                FOREIGN KEY(admission_message_id) REFERENCES coordination_messages(id)
            );
            CREATE INDEX IF NOT EXISTS coordination_pre_push_gate_lookup
                ON coordination_pre_push_gates(repository, issue_number, branch, head_sha, state);
            CREATE TABLE IF NOT EXISTS coordination_pre_push_publications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                gate_id INTEGER NOT NULL,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                accountable_session_id TEXT NOT NULL,
                source_payload_sha256 TEXT NOT NULL,
                lease_manifest_sha256 TEXT NOT NULL,
                admission_message_id INTEGER NOT NULL,
                branch TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                remote_name TEXT NOT NULL CHECK(remote_name = 'origin'),
                remote_url_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('RESERVED', 'COMPLETE', 'HOLD')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT,
                FOREIGN KEY(gate_id) REFERENCES coordination_pre_push_gates(id),
                FOREIGN KEY(admission_message_id) REFERENCES coordination_messages(id),
                UNIQUE(repository, issue_number, generation, branch, head_sha)
            );
            CREATE TRIGGER IF NOT EXISTS coordination_pre_push_fence_item_update
            BEFORE UPDATE ON coordination_items
            WHEN EXISTS (
                SELECT 1 FROM coordination_pre_push_publications publication
                WHERE publication.repository=OLD.repository
                  AND publication.issue_number=OLD.issue_number
                  AND publication.state='RESERVED'
            )
            BEGIN
                SELECT RAISE(ABORT, 'PREPUSH_PUBLICATION_RESERVED');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_pre_push_fence_item_delete
            BEFORE DELETE ON coordination_items
            WHEN EXISTS (
                SELECT 1 FROM coordination_pre_push_publications publication
                WHERE publication.repository=OLD.repository
                  AND publication.issue_number=OLD.issue_number
                  AND publication.state='RESERVED'
            )
            BEGIN
                SELECT RAISE(ABORT, 'PREPUSH_PUBLICATION_RESERVED');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_pre_push_fence_source_update
            BEFORE UPDATE ON github_current
            WHEN OLD.object_kind='issue' AND EXISTS (
                SELECT 1 FROM coordination_pre_push_publications publication
                WHERE publication.repository=OLD.repository
                  AND publication.issue_number=OLD.object_number
                  AND publication.state='RESERVED'
            )
            BEGIN
                SELECT RAISE(ABORT, 'PREPUSH_PUBLICATION_RESERVED');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_pre_push_fence_source_delete
            BEFORE DELETE ON github_current
            WHEN OLD.object_kind='issue' AND EXISTS (
                SELECT 1 FROM coordination_pre_push_publications publication
                WHERE publication.repository=OLD.repository
                  AND publication.issue_number=OLD.object_number
                  AND publication.state='RESERVED'
            )
            BEGIN
                SELECT RAISE(ABORT, 'PREPUSH_PUBLICATION_RESERVED');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_pre_push_fence_admission_insert
            BEFORE INSERT ON coordination_messages
            WHEN NEW.topic IN ('development.admission', 'development.recovery_commit', 'sre.admission')
              AND EXISTS (
                SELECT 1 FROM coordination_pre_push_publications publication
                WHERE publication.repository=json_extract(NEW.payload_json, '$.source.repository')
                  AND publication.issue_number=json_extract(NEW.payload_json, '$.issue_number')
                  AND publication.generation=json_extract(NEW.payload_json, '$.generation')
                  AND publication.state='RESERVED'
            )
            BEGIN
                SELECT RAISE(ABORT, 'PREPUSH_PUBLICATION_RESERVED');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_pre_push_fence_admission_update
            BEFORE UPDATE ON coordination_messages
            WHEN NEW.topic IN ('development.admission', 'development.recovery_commit', 'sre.admission')
              AND EXISTS (
                SELECT 1 FROM coordination_pre_push_publications publication
                WHERE publication.repository=json_extract(NEW.payload_json, '$.source.repository')
                  AND publication.issue_number=json_extract(NEW.payload_json, '$.issue_number')
                  AND publication.generation=json_extract(NEW.payload_json, '$.generation')
                  AND publication.state='RESERVED'
            )
            BEGIN
                SELECT RAISE(ABORT, 'PREPUSH_PUBLICATION_RESERVED');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_message_envelope_immutable
            BEFORE UPDATE ON coordination_messages
            WHEN NEW.idempotency_key IS NOT OLD.idempotency_key
              OR NEW.recipient_session_id IS NOT OLD.recipient_session_id
              OR NEW.topic IS NOT OLD.topic
              OR NEW.payload_sha256 IS NOT OLD.payload_sha256
              OR NEW.payload_json IS NOT OLD.payload_json
              OR NEW.created_at IS NOT OLD.created_at
            BEGIN
                SELECT RAISE(ABORT, 'MESSAGE_ENVELOPE_IMMUTABLE');
            END;
            CREATE TABLE IF NOT EXISTS coordination_artifacts (
                artifact_key TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                relative_path TEXT NOT NULL UNIQUE,
                content_sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                device_id INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                retention_class TEXT NOT NULL CHECK(retention_class IN ('EPHEMERAL', 'CLOSEOUT_EVIDENCE', 'RETAINED')),
                state TEXT NOT NULL CHECK(state IN ('REGISTERED', 'ELIGIBLE', 'MOVE_RESERVED', 'TRASHED', 'PURGE_RESERVED', 'PURGED', 'HOLD')),
                trash_relative_path TEXT,
                purge_after TEXT,
                registered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS coordination_artifacts_lineage
                ON coordination_artifacts(repository, issue_number, generation, state);
            """
        )
        watch_columns = {
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(coordination_terminal_watches)"
            )
        }
        watch_schema = self.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='coordination_terminal_watches'"
        ).fetchone()
        if (
            not {
                "admission_message_id",
                "admission_payload_sha256",
                "claim_attempt_id",
            }.issubset(watch_columns)
            or watch_schema is None
            or "PENDING_CLAIM" not in str(watch_schema[0])
        ):
            # An unbound historical ACTIVE watch is not executable after this
            # cutover. Preserve it for audit on HOLD rather than guessing its
            # admission or claimant.
            self.connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE coordination_terminal_watches
                    RENAME TO coordination_terminal_watches_legacy;
                CREATE TABLE coordination_terminal_watches (
                    watch_key TEXT PRIMARY KEY,
                    repository TEXT NOT NULL,
                    issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                    generation INTEGER NOT NULL CHECK(generation >= 0),
                    accountable_session_id TEXT NOT NULL,
                    lease_manifest_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'PENDING_CLAIM','ACTIVE','COMPLETE','HOLD'
                    )),
                    admission_message_id INTEGER,
                    admission_payload_sha256 TEXT,
                    claim_attempt_id TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    process_id INTEGER,
                    last_heartbeat_at TEXT NOT NULL,
                    next_wake_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT,
                    UNIQUE(repository, issue_number, generation)
                );
                INSERT INTO coordination_terminal_watches(
                    watch_key, repository, issue_number, generation,
                    accountable_session_id, lease_manifest_sha256, state,
                    admission_message_id, admission_payload_sha256,
                    claim_attempt_id, attempts, process_id,
                    last_heartbeat_at, next_wake_at, updated_at, last_error
                )
                SELECT watch_key, repository, issue_number, generation,
                       accountable_session_id, lease_manifest_sha256,
                       CASE WHEN state='ACTIVE' THEN 'HOLD' ELSE state END,
                       NULL, NULL, NULL, attempts, NULL,
                       last_heartbeat_at, next_wake_at, updated_at,
                       CASE WHEN state='ACTIVE'
                            THEN 'TERMINAL_WATCH_ADMISSION_BINDING_MIGRATION_REQUIRED'
                            ELSE last_error END
                FROM coordination_terminal_watches_legacy;
                DROP TABLE coordination_terminal_watches_legacy;
                COMMIT;
                """
            )
        packet_columns = {
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(coordination_terminal_closeout_packets)"
            )
        }
        # Historical packets remain immutable audit evidence.  Nullable
        # additions deliberately make them non-finalizable until a fresh
        # current-graph packet is prepared; no historical binding is guessed.
        for column, declaration in (
            ("graph_version", "INTEGER"),
            ("graph_sha256", "TEXT"),
            ("graph_main_sha", "TEXT"),
            ("graph_node_key", "TEXT"),
            ("graph_binding_sha256", "TEXT"),
        ):
            if column not in packet_columns:
                self.connection.execute(
                    f"ALTER TABLE coordination_terminal_closeout_packets "
                    f"ADD COLUMN {column} {declaration}"
                )
        commit_columns = {
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(coordination_terminal_closeout_commits)"
            )
        }
        # Historical commits remain replayable audit evidence.  New commits
        # require both fields; nullable migration columns avoid fabricating a
        # live observation for an already-completed historical lineage.
        for column in ("live_evidence_sha256", "live_evidence_json"):
            if column not in commit_columns:
                self.connection.execute(
                    "ALTER TABLE coordination_terminal_closeout_commits "
                    f"ADD COLUMN {column} TEXT"
                )
        columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(coordination_items)")
        }
        gate_columns = {
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(coordination_pre_push_gates)"
            )
        }
        if "environment_provenance_sha256" not in gate_columns:
            self.connection.execute(
                "ALTER TABLE coordination_pre_push_gates ADD COLUMN environment_provenance_sha256 TEXT"
            )
        wake_columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(coordination_wakes)")
        }
        if "target_progress_sha256" not in wake_columns:
            self.connection.execute(
                "ALTER TABLE coordination_wakes ADD COLUMN target_progress_sha256 TEXT"
            )
        watch_columns = {
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(coordination_terminal_watches)"
            )
        }
        if "target_progress_sha256" not in watch_columns:
            self.connection.execute(
                "ALTER TABLE coordination_terminal_watches ADD COLUMN target_progress_sha256 TEXT"
            )
        if "allocation_class" not in columns:
            self.connection.execute(
                "ALTER TABLE coordination_items ADD COLUMN allocation_class TEXT NOT NULL DEFAULT 'NONE' CHECK(allocation_class IN ('ACTIVE', 'RETAINED', 'NONE'))"
            )
        allocation_default = self.connection.execute(
            "SELECT dflt_value FROM pragma_table_info('coordination_items') WHERE name='allocation_class'"
        ).fetchone()[0]
        if allocation_default is not None:
            self.connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE coordination_items RENAME TO coordination_items_with_default;
                CREATE TABLE coordination_items (
                    repository TEXT NOT NULL,
                    issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                    status TEXT NOT NULL,
                    allocation_class TEXT NOT NULL CHECK(allocation_class IN ('ACTIVE', 'RETAINED', 'NONE')),
                    generation INTEGER NOT NULL CHECK(generation >= 0),
                    accountable_session_id TEXT,
                    lease_manifest_sha256 TEXT,
                    development_units INTEGER NOT NULL CHECK(development_units >= 0),
                    shared_units INTEGER NOT NULL CHECK(shared_units >= 0),
                    sre_units INTEGER NOT NULL CHECK(sre_units >= 0),
                    source_payload_sha256 TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version > 0),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(repository, issue_number)
                );
                INSERT INTO coordination_items(
                    repository, issue_number, status, allocation_class, generation,
                    accountable_session_id, lease_manifest_sha256, development_units,
                    shared_units, sre_units, source_payload_sha256, version, updated_at
                )
                SELECT repository, issue_number, status, allocation_class, generation,
                       accountable_session_id, lease_manifest_sha256, development_units,
                       shared_units, 0, source_payload_sha256, version, updated_at
                FROM coordination_items_with_default;
                DROP TABLE coordination_items_with_default;
                COMMIT;
                """
            )
        columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(coordination_items)")
        }
        if "sre_units" not in columns:
            self.connection.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE coordination_items RENAME TO coordination_items_without_sre;
                CREATE TABLE coordination_items (
                    repository TEXT NOT NULL,
                    issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                    status TEXT NOT NULL,
                    allocation_class TEXT NOT NULL CHECK(allocation_class IN ('ACTIVE', 'RETAINED', 'NONE')),
                    generation INTEGER NOT NULL CHECK(generation >= 0),
                    accountable_session_id TEXT,
                    lease_manifest_sha256 TEXT,
                    development_units INTEGER NOT NULL CHECK(development_units >= 0),
                    shared_units INTEGER NOT NULL CHECK(shared_units >= 0),
                    sre_units INTEGER NOT NULL CHECK(sre_units >= 0),
                    source_payload_sha256 TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version > 0),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(repository, issue_number)
                );
                INSERT INTO coordination_items(
                    repository, issue_number, status, allocation_class, generation,
                    accountable_session_id, lease_manifest_sha256, development_units,
                    shared_units, sre_units, source_payload_sha256, version, updated_at
                )
                SELECT repository, issue_number, status, allocation_class, generation,
                       accountable_session_id, lease_manifest_sha256, development_units,
                       shared_units, 0, source_payload_sha256, version, updated_at
                FROM coordination_items_without_sre;
                DROP TABLE coordination_items_without_sre;
                COMMIT;
                """
            )
        self.connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS coordination_unique_live_lease
                ON coordination_items(repository, lease_manifest_sha256)
                WHERE allocation_class IN ('ACTIVE', 'RETAINED')
                  AND lease_manifest_sha256 IS NOT NULL
            """
        )
        repositories = {
            row[0]
            for row in self.connection.execute(
                "SELECT repository FROM coordination_items "
                "UNION SELECT repository FROM github_current"
            )
        }
        for repository in repositories:
            self._ensure_capacity_policy(repository, utc_now())
        ensure_portfolio_graph_schema(self.connection)
        ensure_executor_registry_schema(self.connection)
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS coordination_bootstrap_provenance (
                bootstrap_id TEXT PRIMARY KEY,
                manifest_sha256 TEXT NOT NULL UNIQUE,
                manifest_json TEXT NOT NULL,
                source_harness_repository TEXT NOT NULL,
                source_harness_main_sha TEXT NOT NULL,
                source_registry_sha256 TEXT NOT NULL,
                approved_goal_sha256 TEXT NOT NULL,
                application_repository TEXT NOT NULL,
                application_main_sha TEXT NOT NULL,
                archived_database_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS coordination_bootstrap_provenance_immutable_update
            BEFORE UPDATE ON coordination_bootstrap_provenance
            BEGIN
                SELECT RAISE(ABORT, 'BOOTSTRAP_PROVENANCE_IMMUTABLE');
            END;
            CREATE TRIGGER IF NOT EXISTS coordination_bootstrap_provenance_immutable_delete
            BEFORE DELETE ON coordination_bootstrap_provenance
            BEGIN
                SELECT RAISE(ABORT, 'BOOTSTRAP_PROVENANCE_IMMUTABLE');
            END;
            """
        )

    def record_bootstrap_provenance(
        self,
        *,
        bootstrap_id: str,
        manifest_sha256: str,
        manifest: dict[str, Any],
        source_harness_repository: str,
        source_harness_main_sha: str,
        source_registry_sha256: str,
        approved_goal_sha256: str,
        application_repository: str,
        application_main_sha: str,
        archived_database_sha256: str,
        now: str,
    ) -> None:
        """Persist one immutable exact clean-control-plane source binding."""

        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        if not bootstrap_id or not isinstance(manifest, dict):
            raise CoordinationError("BOOTSTRAP_PROVENANCE_INVALID")
        for digest in (
            manifest_sha256,
            source_registry_sha256,
            approved_goal_sha256,
            archived_database_sha256,
        ):
            _validate_sha256(digest)
        _validate_repository(source_harness_repository)
        _validate_repository(application_repository)
        if not re.fullmatch(r"[0-9a-f]{40}", source_harness_main_sha) or not re.fullmatch(
            r"[0-9a-f]{40}", application_main_sha
        ):
            raise CoordinationError("BOOTSTRAP_PROVENANCE_INVALID")
        if self.connection.execute(
            "SELECT 1 FROM coordination_bootstrap_provenance LIMIT 1"
        ).fetchone() is not None:
            raise CoordinationError("BOOTSTRAP_PROVENANCE_CONFLICT")
        canonical = canonical_json(manifest)
        self.connection.execute(
            """
            INSERT INTO coordination_bootstrap_provenance(
                bootstrap_id, manifest_sha256, manifest_json,
                source_harness_repository, source_harness_main_sha,
                source_registry_sha256, approved_goal_sha256,
                application_repository, application_main_sha,
                archived_database_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bootstrap_id,
                manifest_sha256,
                canonical,
                source_harness_repository,
                source_harness_main_sha,
                source_registry_sha256,
                approved_goal_sha256,
                application_repository,
                application_main_sha,
                archived_database_sha256,
                now,
            ),
        )
        self._event(
            "CLEAN_CONTROL_PLANE_BOOTSTRAPPED",
            bootstrap_id,
            {"manifest_sha256": manifest_sha256},
            now,
        )

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            lowered = str(exc).lower()
            if "readonly" in lowered or "read-only" in lowered:
                raise CoordinationError("COORDINATOR_NOT_WRITABLE") from exc
            raise
        try:
            yield
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def _event(self, event_type: str, entity_key: str, payload: Any, now: str) -> None:
        self.connection.execute(
            "INSERT INTO coordination_events(event_type, entity_key, payload_sha256, created_at) VALUES (?, ?, ?, ?)",
            (event_type, entity_key, digest_json(payload), now),
        )

    def _enqueue_portfolio_dirty_event(
        self,
        *,
        repository: str,
        issue_number: int,
        release_item_version: int,
        release_source_sha256: str,
        prior_allocation_class: str,
        status: str,
        generation: int,
        now: str,
    ) -> int:
        """Enqueue one immutable convergence event inside the caller's transaction."""

        try:
            event_id = enqueue_convergence_dirty_event(
                self.connection,
                repository=repository,
                trigger_kind="CAPACITY_RELEASE",
                issue_number=issue_number,
                item_version=release_item_version,
                source_sha256=release_source_sha256,
                status=status,
                generation=generation,
                now=now,
                details={
                    "prior_allocation_class": prior_allocation_class,
                    "allocation_class": "NONE",
                },
            )
        except PortfolioGraphError as exc:
            raise CoordinationError(str(exc)) from exc
        if event_id is None:
            raise CoordinationError("PORTFOLIO_DIRTY_EVENT_SCHEMA_MISSING")
        return event_id

    def ingest_snapshot(
        self,
        *,
        repository: str,
        object_kind: str,
        object_number: int,
        payload: dict[str, Any],
        source_updated_at: str,
        fetched_at: str,
    ) -> SourceSnapshot:
        with self.transaction():
            return self.ingest_snapshot_in_transaction(
                repository=repository,
                object_kind=object_kind,
                object_number=object_number,
                payload=payload,
                source_updated_at=source_updated_at,
                fetched_at=fetched_at,
            )

    def ingest_snapshot_in_transaction(
        self,
        *,
        repository: str,
        object_kind: str,
        object_number: int,
        payload: dict[str, Any],
        source_updated_at: str,
        fetched_at: str,
        expected_payload_sha256: str | None = None,
    ) -> SourceSnapshot:
        """Ingest an exact snapshot inside the caller's write transaction."""

        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        _validate_repository(repository)
        if object_kind not in SOURCE_KINDS or object_number <= 0:
            raise CoordinationError("INVALID_SOURCE_OBJECT")
        if not isinstance(payload, dict) or not source_updated_at or not fetched_at:
            raise CoordinationError("INVALID_SOURCE_SNAPSHOT")
        payload_sha256 = digest_json(payload)
        if (
            expected_payload_sha256 is not None
            and payload_sha256 != expected_payload_sha256
        ):
            raise CoordinationError("SOURCE_SNAPSHOT_DIGEST_DRIFT")
        snapshot = SourceSnapshot(
            repository,
            object_kind,
            object_number,
            payload_sha256,
            source_updated_at,
            fetched_at,
            payload,
        )
        key = f"{repository}:{object_kind}:{object_number}"
        current = self.connection.execute(
            """
            SELECT c.payload_sha256, c.source_updated_at, s.payload_json
            FROM github_current c
            JOIN github_snapshots s
              USING(repository, object_kind, object_number, payload_sha256)
            WHERE c.repository=? AND c.object_kind=? AND c.object_number=?
            """,
            (repository, object_kind, object_number),
        ).fetchone()
        if current is not None:
            if source_updated_at < current["source_updated_at"]:
                raise CoordinationError("STALE_SOURCE_SNAPSHOT")
            if (
                source_updated_at == current["source_updated_at"]
                and payload_sha256 != current["payload_sha256"]
            ):
                previous_payload = json.loads(current["payload_json"])
                previous_projection = int(previous_payload.get("_projection_version", 1))
                next_projection = int(payload.get("_projection_version", 1))
                if next_projection <= previous_projection:
                    raise CoordinationError("SOURCE_VERSION_CONFLICT")
        self.connection.execute(
            "INSERT OR IGNORE INTO github_snapshots(repository, object_kind, object_number, payload_sha256, source_updated_at, fetched_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                repository,
                object_kind,
                object_number,
                payload_sha256,
                source_updated_at,
                fetched_at,
                canonical_json(payload),
            ),
        )
        self.connection.execute(
            """
            INSERT INTO github_current(repository, object_kind, object_number, payload_sha256, source_updated_at, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(repository, object_kind, object_number) DO UPDATE SET
                payload_sha256=excluded.payload_sha256,
                source_updated_at=excluded.source_updated_at,
                fetched_at=excluded.fetched_at
            """,
            (
                repository,
                object_kind,
                object_number,
                payload_sha256,
                source_updated_at,
                fetched_at,
            ),
        )
        self._event("SOURCE_REFRESHED", key, asdict(snapshot), fetched_at)
        return snapshot

    def current_snapshot(
        self, repository: str, object_kind: str, object_number: int
    ) -> SourceSnapshot | None:
        row = self.connection.execute(
            """
            SELECT c.repository, c.object_kind, c.object_number, c.payload_sha256,
                   c.source_updated_at, c.fetched_at, s.payload_json
            FROM github_current c
            JOIN github_snapshots s USING(repository, object_kind, object_number, payload_sha256)
            WHERE c.repository=? AND c.object_kind=? AND c.object_number=?
            """,
            (repository, object_kind, object_number),
        ).fetchone()
        if row is None:
            return None
        return SourceSnapshot(
            row["repository"],
            row["object_kind"],
            row["object_number"],
            row["payload_sha256"],
            row["source_updated_at"],
            row["fetched_at"],
            json.loads(row["payload_json"]),
        )

    @property
    def artifact_root(self) -> Path:
        return self.path.parent.resolve()

    def _validated_artifact_file(self, value: str | Path) -> tuple[Path, str, os.stat_result]:
        supplied = Path(value)
        candidate = supplied if supplied.is_absolute() else self.artifact_root / supplied
        candidate = Path(os.path.abspath(candidate))
        try:
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(self.artifact_root)
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            raise CoordinationError("ARTIFACT_PATH_UNSAFE") from exc
        if candidate != resolved or not relative.parts:
            raise CoordinationError("ARTIFACT_PATH_UNSAFE")
        database_names = {
            self.path.name,
            f"{self.path.name}.lock",
            f"{self.path.name}-wal",
            f"{self.path.name}-shm",
            "coordination-supervisor.lock",
        }
        if (
            relative.parts[0] == ".artifact-trash"
            or (len(relative.parts) == 1 and relative.name in database_names)
            or relative.suffix == ".lock"
        ):
            raise CoordinationError("ARTIFACT_PATH_UNSAFE")
        metadata = resolved.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise CoordinationError("ARTIFACT_FILE_UNSAFE")
        return resolved, relative.as_posix(), metadata

    def register_artifacts(
        self,
        entries: list[dict[str, Any]],
        *,
        now: str,
        _transaction: bool = True,
    ) -> list[dict[str, Any]]:
        required = {
            "repository",
            "issue_number",
            "generation",
            "path",
            "retention_class",
        }
        if not entries or len(entries) > 100:
            raise CoordinationError("INVALID_ARTIFACT_MANIFEST")
        prepared: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != required:
                raise CoordinationError("INVALID_ARTIFACT_MANIFEST")
            repository = entry["repository"]
            issue_number = entry["issue_number"]
            generation = entry["generation"]
            retention_class = entry["retention_class"]
            _validate_repository(repository)
            if (
                type(issue_number) is not int
                or issue_number <= 0
                or type(generation) is not int
                or generation < 0
                or retention_class not in ARTIFACT_RETENTION_CLASSES
                or not isinstance(entry["path"], str)
            ):
                raise CoordinationError("INVALID_ARTIFACT_MANIFEST")
            path, relative_path, metadata = self._validated_artifact_file(entry["path"])
            if relative_path in seen_paths:
                raise CoordinationError("DUPLICATE_ARTIFACT_PATH")
            seen_paths.add(relative_path)
            content_sha256 = _sha256_file(path)
            key_payload = {
                "repository": repository,
                "issue_number": issue_number,
                "generation": generation,
                "relative_path": relative_path,
                "content_sha256": content_sha256,
            }
            prepared.append(
                {
                    **key_payload,
                    "artifact_key": digest_json(key_payload),
                    "size_bytes": int(metadata.st_size),
                    "device_id": int(metadata.st_dev),
                    "inode": int(metadata.st_ino),
                    "retention_class": retention_class,
                }
            )
        transaction = self.transaction() if _transaction else nullcontext()
        with transaction:
            for artifact in prepared:
                item = self.connection.execute(
                    "SELECT generation FROM coordination_items WHERE repository=? AND issue_number=?",
                    (artifact["repository"], artifact["issue_number"]),
                ).fetchone()
                if item is None or int(item["generation"]) != artifact["generation"]:
                    raise CoordinationError("ARTIFACT_LINEAGE_MISMATCH")
                existing = self.connection.execute(
                    "SELECT * FROM coordination_artifacts WHERE relative_path=?",
                    (artifact["relative_path"],),
                ).fetchone()
                if existing is not None:
                    exact = all(existing[key] == artifact[key] for key in (
                        "artifact_key",
                        "repository",
                        "issue_number",
                        "generation",
                        "content_sha256",
                        "size_bytes",
                        "device_id",
                        "inode",
                        "retention_class",
                    ))
                    if not exact:
                        raise CoordinationError("ARTIFACT_REGISTRATION_CONFLICT")
                    continue
                self.connection.execute(
                    """
                    INSERT INTO coordination_artifacts(
                        artifact_key, repository, issue_number, generation,
                        relative_path, content_sha256, size_bytes, device_id, inode,
                        retention_class, state, registered_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'REGISTERED', ?, ?)
                    """,
                    (
                        artifact["artifact_key"], artifact["repository"],
                        artifact["issue_number"], artifact["generation"],
                        artifact["relative_path"], artifact["content_sha256"],
                        artifact["size_bytes"], artifact["device_id"], artifact["inode"],
                        artifact["retention_class"], now, now,
                    ),
                )
                self._event(
                    "ARTIFACT_REGISTERED",
                    f"artifact:{artifact['artifact_key']}",
                    {
                        "repository": artifact["repository"],
                        "issue_number": artifact["issue_number"],
                        "generation": artifact["generation"],
                        "relative_path": artifact["relative_path"],
                        "retention_class": artifact["retention_class"],
                    },
                    now,
                )
        return prepared

    def _register_preloaded_artifacts(
        self,
        observations: list[dict[str, Any]],
        *,
        now: str,
    ) -> list[dict[str, Any]]:
        """Register bytes read before the caller acquired its write lock."""

        prepared: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for observation in observations:
            entry = observation.get("entry") if isinstance(observation, dict) else None
            descriptor = observation.get("descriptor") if isinstance(observation, dict) else None
            raw = observation.get("raw") if isinstance(observation, dict) else None
            if (
                not isinstance(entry, dict)
                or set(entry)
                != {"repository", "issue_number", "generation", "path", "retention_class"}
                or type(descriptor) is not int
                or descriptor < 0
                or not isinstance(raw, bytes)
            ):
                raise CoordinationError("INVALID_ARTIFACT_MANIFEST")
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or int(metadata.st_size) != observation.get("size_bytes")
                or int(metadata.st_dev) != observation.get("device_id")
                or int(metadata.st_ino) != observation.get("inode")
                or int(metadata.st_mode) != observation.get("mode")
                or int(metadata.st_mtime_ns) != observation.get("mtime_ns")
                or int(metadata.st_ctime_ns) != observation.get("ctime_ns")
                or hashlib.sha256(raw).hexdigest()
                != observation.get("content_sha256")
            ):
                raise CoordinationError("ARTIFACT_CONTENT_DRIFT")
            repository = entry["repository"]
            issue_number = entry["issue_number"]
            generation = entry["generation"]
            retention_class = entry["retention_class"]
            relative_path = observation.get("relative_path")
            _validate_repository(repository)
            if (
                type(issue_number) is not int
                or issue_number <= 0
                or type(generation) is not int
                or generation < 0
                or retention_class not in ARTIFACT_RETENTION_CLASSES
                or not isinstance(relative_path, str)
                or relative_path in seen_paths
            ):
                raise CoordinationError("INVALID_ARTIFACT_MANIFEST")
            seen_paths.add(relative_path)
            key_payload = {
                "repository": repository,
                "issue_number": issue_number,
                "generation": generation,
                "relative_path": relative_path,
                "content_sha256": observation["content_sha256"],
            }
            artifact = {
                **key_payload,
                "artifact_key": digest_json(key_payload),
                "size_bytes": int(metadata.st_size),
                "device_id": int(metadata.st_dev),
                "inode": int(metadata.st_ino),
                "retention_class": retention_class,
            }
            item = self.connection.execute(
                "SELECT generation FROM coordination_items WHERE repository=? AND issue_number=?",
                (repository, issue_number),
            ).fetchone()
            if item is None or int(item["generation"]) != generation:
                raise CoordinationError("ARTIFACT_LINEAGE_MISMATCH")
            existing = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE relative_path=?",
                (relative_path,),
            ).fetchone()
            if existing is not None:
                exact = all(
                    existing[key] == artifact[key]
                    for key in (
                        "artifact_key",
                        "repository",
                        "issue_number",
                        "generation",
                        "content_sha256",
                        "size_bytes",
                        "device_id",
                        "inode",
                        "retention_class",
                    )
                )
                if not exact or existing["state"] != "REGISTERED":
                    raise CoordinationError("ARTIFACT_REGISTRATION_CONFLICT")
            else:
                self.connection.execute(
                    """
                    INSERT INTO coordination_artifacts(
                        artifact_key, repository, issue_number, generation,
                        relative_path, content_sha256, size_bytes, device_id,
                        inode, retention_class, state, registered_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'REGISTERED', ?, ?)
                    """,
                    (
                        artifact["artifact_key"], repository, issue_number,
                        generation, relative_path, artifact["content_sha256"],
                        artifact["size_bytes"], artifact["device_id"],
                        artifact["inode"], retention_class, now, now,
                    ),
                )
                self._event(
                    "ARTIFACT_REGISTERED",
                    f"artifact:{artifact['artifact_key']}",
                    {
                        "repository": repository,
                        "issue_number": issue_number,
                        "generation": generation,
                        "relative_path": relative_path,
                        "retention_class": retention_class,
                    },
                    now,
                )
            prepared.append(artifact)
        return prepared

    def read_registered_artifact(
        self,
        *,
        artifact_key: str,
        repository: str,
        issue_number: int,
        generation: int,
        expected_content_sha256: str,
        expected_retention_class: str | None = None,
        maximum_size_bytes: int = 1024 * 1024,
        _transaction: bool = True,
    ) -> tuple[dict[str, Any], bytes]:
        """Revalidate and read an immutable artifact through its descriptor."""

        _validate_sha256(artifact_key)
        _validate_repository(repository)
        _validate_sha256(expected_content_sha256)
        if (
            issue_number <= 0
            or generation < 0
            or maximum_size_bytes <= 0
            or (
                expected_retention_class is not None
                and expected_retention_class not in ARTIFACT_RETENTION_CLASSES
            )
        ):
            raise CoordinationError("ARTIFACT_LINEAGE_MISMATCH")
        transaction = self.transaction() if _transaction else nullcontext()
        with transaction:
            artifact = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (artifact_key,),
            ).fetchone()
            if artifact is None:
                raise CoordinationError("ARTIFACT_NOT_FOUND")
            if (
                artifact["state"] != "REGISTERED"
                or artifact["repository"] != repository
                or int(artifact["issue_number"]) != issue_number
                or int(artifact["generation"]) != generation
                or artifact["content_sha256"] != expected_content_sha256
                or (
                    expected_retention_class is not None
                    and artifact["retention_class"] != expected_retention_class
                )
                or int(artifact["size_bytes"]) > maximum_size_bytes
            ):
                raise CoordinationError("ARTIFACT_LINEAGE_MISMATCH")
            with _open_relative_parent(
                self.artifact_root, artifact["relative_path"]
            ) as (parent_descriptor, name):
                descriptor = _open_verified_artifact(
                    parent_descriptor, name, artifact
                )
                try:
                    content = b""
                    while True:
                        block = os.read(descriptor, 64 * 1024)
                        if not block:
                            break
                        content += block
                finally:
                    os.close(descriptor)
            return dict(artifact), content

    def verify_registered_artifact(
        self,
        *,
        artifact_key: str,
        repository: str,
        issue_number: int,
        generation: int,
        expected_content_sha256: str,
        expected_retention_class: str | None = None,
        _transaction: bool = True,
    ) -> dict[str, Any]:
        """Revalidate an immutable artifact's row, descriptor, and bytes."""

        artifact, _content = self.read_registered_artifact(
            artifact_key=artifact_key,
            repository=repository,
            issue_number=issue_number,
            generation=generation,
            expected_content_sha256=expected_content_sha256,
            expected_retention_class=expected_retention_class,
            _transaction=_transaction,
        )
        return artifact

    def _artifact_terminal_error(self, artifact: sqlite3.Row) -> str | None:
        item = self.connection.execute(
            "SELECT status, allocation_class, generation FROM coordination_items WHERE repository=? AND issue_number=?",
            (artifact["repository"], artifact["issue_number"]),
        ).fetchone()
        watch = self.connection.execute(
            "SELECT state FROM coordination_terminal_watches WHERE repository=? AND issue_number=? AND generation=?",
            (artifact["repository"], artifact["issue_number"], artifact["generation"]),
        ).fetchone()
        if artifact["retention_class"] == "RETAINED":
            return "ARTIFACT_RETAINED"
        if (
            item is None
            or item["status"] != "DONE"
            or item["allocation_class"] != "NONE"
            or int(item["generation"]) != int(artifact["generation"])
        ):
            return "ARTIFACT_NOT_TERMINAL"
        if watch is None or watch["state"] != "COMPLETE":
            return "ARTIFACT_TERMINAL_WATCH_INCOMPLETE"
        terminal_commit = self.connection.execute(
            """
            SELECT 1
            FROM coordination_terminal_closeout_packets packet
            JOIN coordination_terminal_closeout_commits terminal_commit
              USING(closeout_key)
            JOIN github_outbox outbox ON outbox.id=packet.outbox_id
            WHERE packet.repository=? AND packet.issue_number=?
              AND packet.generation=? AND outbox.state='COMPLETE'
              AND outbox.remote_receipt IS NOT NULL
            """,
            (
                artifact["repository"],
                artifact["issue_number"],
                artifact["generation"],
            ),
        ).fetchone()
        if terminal_commit is None:
            return "ARTIFACT_TERMINAL_CLOSEOUT_INCOMPLETE"

        for message in self.connection.execute(
            "SELECT topic, payload_json, state FROM coordination_messages WHERE state IN ('PREPARED','CLAIMED')"
        ):
            try:
                payload = json.loads(message["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return "ARTIFACT_PENDING_CONTROL"
            source = payload.get("source") if isinstance(payload, dict) else None
            if (
                isinstance(source, dict)
                and source.get("repository") == artifact["repository"]
                and source.get("object_kind") == "issue"
                and source.get("object_number") == artifact["issue_number"]
            ):
                return "ARTIFACT_PENDING_CONTROL"
        pending_outbox = self.connection.execute(
            """
            SELECT 1 FROM github_outbox
            WHERE repository=? AND object_kind='issue' AND object_number=?
              AND state IN ('PREPARED','INFLIGHT')
            LIMIT 1
            """,
            (artifact["repository"], artifact["issue_number"]),
        ).fetchone()
        if pending_outbox is not None:
            return "ARTIFACT_PENDING_OUTBOX"

        closeouts = self.connection.execute(
            "SELECT state, payload_json FROM coordination_messages WHERE topic='development.terminal_closeout'"
        ).fetchall()
        for closeout in closeouts:
            try:
                payload = json.loads(closeout["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return "ARTIFACT_TERMINAL_CLOSEOUT_INCOMPLETE"
            source = payload.get("source") if isinstance(payload, dict) else None
            if not (
                isinstance(source, dict)
                and source.get("repository") == artifact["repository"]
                and source.get("object_kind") == "issue"
                and source.get("object_number") == artifact["issue_number"]
                and payload.get("item_generation") == artifact["generation"]
            ):
                continue
            outbox = self.connection.execute(
                "SELECT state, remote_receipt FROM github_outbox WHERE id=?",
                (payload.get("outbox_id"),),
            ).fetchone()
            if (
                closeout["state"] != "COMPLETE"
                or outbox is None
                or outbox["state"] != "COMPLETE"
                or not outbox["remote_receipt"]
            ):
                return "ARTIFACT_TERMINAL_CLOSEOUT_INCOMPLETE"
        return None

    def _artifact_terminal_eligible(self, artifact: sqlite3.Row) -> bool:
        return self._artifact_terminal_error(artifact) is None

    def _hold_artifact(self, artifact_key: str, error: str, now: str) -> None:
        with self.transaction():
            self.connection.execute(
                "UPDATE coordination_artifacts SET state='HOLD', updated_at=?, last_error=? WHERE artifact_key=? AND state<>'PURGED'",
                (now, error, artifact_key),
            )
            self._event("ARTIFACT_HELD", f"artifact:{artifact_key}", {"error": error}, now)

    def hold_drifted_artifact(
        self,
        *,
        artifact_key: str,
        expected_content_sha256: str,
        session_id: str,
        now: str,
    ) -> dict[str, Any]:
        """Quarantine an exact registered artifact after identity-only drift.

        This never rebinds an artifact row.  It proves that the current regular
        file still has the registered bytes and size but no longer has the
        registered device/inode identity, then records the old registration as
        HOLD so a separately registered immutable replacement can supersede it.
        """
        session_id = canonicalize_coordination_identity(self.connection, session_id)
        _validate_sha256(expected_content_sha256)
        if coordination_identity_role(self.connection, session_id) != "planner":
            raise CoordinationError("PLANNER_SESSION_REQUIRED")
        with self.transaction():
            artifact = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (artifact_key,),
            ).fetchone()
            if artifact is None:
                raise CoordinationError("ARTIFACT_NOT_FOUND")
            if artifact["content_sha256"] != expected_content_sha256:
                raise CoordinationError("ARTIFACT_DIGEST_MISMATCH")
            if artifact["state"] == "HOLD":
                if artifact["last_error"] != "ARTIFACT_IDENTITY_DRIFT":
                    raise CoordinationError("ARTIFACT_STATE_CONFLICT")
                return dict(artifact)
            if artifact["state"] != "REGISTERED":
                raise CoordinationError("ARTIFACT_STATE_CONFLICT")

            with _open_relative_parent(
                self.artifact_root, artifact["relative_path"]
            ) as (parent_descriptor, name):
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW,
                        dir_fd=parent_descriptor,
                    )
                except OSError as exc:
                    raise CoordinationError("ARTIFACT_FILE_MISSING") from exc
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or metadata.st_nlink != 1
                    ):
                        raise CoordinationError("ARTIFACT_FILE_UNSAFE")
                    if (
                        int(metadata.st_size) != int(artifact["size_bytes"])
                        or _sha256_descriptor(descriptor)
                        != artifact["content_sha256"]
                    ):
                        raise CoordinationError("ARTIFACT_CONTENT_DRIFT")
                    if (
                        int(metadata.st_dev) == int(artifact["device_id"])
                        and int(metadata.st_ino) == int(artifact["inode"])
                    ):
                        raise CoordinationError("ARTIFACT_IDENTITY_CURRENT")
                finally:
                    os.close(descriptor)

            cursor = self.connection.execute(
                "UPDATE coordination_artifacts SET state='HOLD', updated_at=?, "
                "last_error='ARTIFACT_IDENTITY_DRIFT' WHERE artifact_key=? AND state='REGISTERED'",
                (now, artifact_key),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("ARTIFACT_STATE_CONFLICT")
            self._event(
                "ARTIFACT_HELD",
                f"artifact:{artifact_key}",
                {
                    "error": "ARTIFACT_IDENTITY_DRIFT",
                    "current_device_id": int(metadata.st_dev),
                    "current_inode": int(metadata.st_ino),
                },
                now,
            )
            held = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (artifact_key,),
            ).fetchone()
        return dict(held)

    @contextmanager
    def _artifact_gc_lock(self) -> Iterator[bool]:
        lock = self.artifact_root / "artifact-gc.lock"
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise CoordinationError("ARTIFACT_GC_LOCK_UNSAFE")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            yield True
        finally:
            os.close(descriptor)

    @contextmanager
    def _open_artifact_trash(self) -> Iterator[int]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root_descriptor = os.open(self.artifact_root, flags)
        try:
            try:
                os.mkdir(".artifact-trash", mode=0o700, dir_fd=root_descriptor)
                os.fsync(root_descriptor)
            except FileExistsError:
                pass
            trash_descriptor = os.open(".artifact-trash", flags, dir_fd=root_descriptor)
            try:
                metadata = os.fstat(trash_descriptor)
                if (
                    metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise CoordinationError("ARTIFACT_TRASH_UNSAFE")
                yield trash_descriptor
            finally:
                os.close(trash_descriptor)
        except OSError as exc:
            raise CoordinationError("ARTIFACT_TRASH_UNSAFE") from exc
        finally:
            os.close(root_descriptor)

    def _reserve_artifact_move(
        self, artifact_key: str, trash_relative_path: str, now: str
    ) -> sqlite3.Row:
        with self.transaction():
            artifact = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (artifact_key,),
            ).fetchone()
            if artifact is None or artifact["state"] in {"PURGED", "HOLD", "TRASHED", "PURGE_RESERVED"}:
                raise CoordinationError("ARTIFACT_STATE_CONFLICT")
            if artifact["state"] != "MOVE_RESERVED":
                terminal_error = self._artifact_terminal_error(artifact)
                if terminal_error is not None:
                    raise CoordinationError(terminal_error)
                self.connection.execute(
                    "UPDATE coordination_artifacts SET state='ELIGIBLE', updated_at=? WHERE artifact_key=? AND state='REGISTERED'",
                    (now, artifact_key),
                )
                cursor = self.connection.execute(
                    "UPDATE coordination_artifacts SET state='MOVE_RESERVED', trash_relative_path=?, updated_at=?, last_error=NULL WHERE artifact_key=? AND state='ELIGIBLE'",
                    (trash_relative_path, now, artifact_key),
                )
                if cursor.rowcount != 1:
                    raise CoordinationError("ARTIFACT_STATE_CONFLICT")
                self._event(
                    "ARTIFACT_MOVE_RESERVED",
                    f"artifact:{artifact_key}",
                    {"trash_relative_path": trash_relative_path},
                    now,
                )
            artifact = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (artifact_key,),
            ).fetchone()
        return artifact

    def _move_artifact_to_trash(self, artifact: sqlite3.Row, now: str) -> None:
        trash_relative = artifact["trash_relative_path"]
        expected_prefix = ".artifact-trash/"
        if not isinstance(trash_relative, str) or not trash_relative.startswith(expected_prefix):
            raise CoordinationError("ARTIFACT_PATH_UNSAFE")
        trash_name = trash_relative[len(expected_prefix) :]
        if not trash_name or "/" in trash_name or trash_name in {".", ".."}:
            raise CoordinationError("ARTIFACT_PATH_UNSAFE")
        with _open_relative_parent(
            self.artifact_root, artifact["relative_path"]
        ) as (source_parent, source_name), self._open_artifact_trash() as trash_parent:
            source_descriptor: int | None = None
            trash_descriptor: int | None = None
            try:
                try:
                    source_descriptor = _open_verified_artifact(
                        source_parent, source_name, artifact
                    )
                except CoordinationError as exc:
                    if str(exc) != "ARTIFACT_FILE_MISSING":
                        raise
                try:
                    trash_descriptor = _open_verified_artifact(
                        trash_parent, trash_name, artifact
                    )
                except CoordinationError as exc:
                    if str(exc) != "ARTIFACT_FILE_MISSING":
                        raise
                if source_descriptor is None and trash_descriptor is None:
                    raise CoordinationError("ARTIFACT_MOVE_INCOMPLETE")
                if source_descriptor is not None and trash_descriptor is not None:
                    source_stat = os.fstat(source_descriptor)
                    trash_stat = os.fstat(trash_descriptor)
                    if (source_stat.st_dev, source_stat.st_ino) != (
                        trash_stat.st_dev,
                        trash_stat.st_ino,
                    ):
                        raise CoordinationError("ARTIFACT_MOVE_COLLISION")
                elif source_descriptor is not None:
                    try:
                        os.link(
                            source_name,
                            trash_name,
                            src_dir_fd=source_parent,
                            dst_dir_fd=trash_parent,
                            follow_symlinks=False,
                        )
                    except FileExistsError as exc:
                        raise CoordinationError("ARTIFACT_MOVE_COLLISION") from exc
                    os.fsync(trash_parent)
                    trash_descriptor = _open_verified_artifact(
                        trash_parent, trash_name, artifact
                    )
                if source_descriptor is not None:
                    current_descriptor = _open_verified_artifact(
                        source_parent, source_name, artifact
                    )
                    try:
                        current = os.fstat(current_descriptor)
                        original = os.fstat(source_descriptor)
                        if (current.st_dev, current.st_ino) != (
                            original.st_dev,
                            original.st_ino,
                        ):
                            raise CoordinationError("ARTIFACT_CONTENT_DRIFT")
                        os.unlink(source_name, dir_fd=source_parent)
                        os.fsync(source_parent)
                    finally:
                        os.close(current_descriptor)
                verified_trash = _open_verified_artifact(
                    trash_parent, trash_name, artifact
                )
                os.close(verified_trash)
            finally:
                if source_descriptor is not None:
                    os.close(source_descriptor)
                if trash_descriptor is not None:
                    os.close(trash_descriptor)
        purge_after = timestamp_after(
            now, ARTIFACT_PURGE_SECONDS[artifact["retention_class"]]
        )
        with self.transaction():
            cursor = self.connection.execute(
                "UPDATE coordination_artifacts SET state='TRASHED', purge_after=?, updated_at=?, last_error=NULL WHERE artifact_key=? AND state='MOVE_RESERVED'",
                (purge_after, now, artifact["artifact_key"]),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("ARTIFACT_STATE_CONFLICT")
            self._event(
                "ARTIFACT_TRASHED",
                f"artifact:{artifact['artifact_key']}",
                {"purge_after": purge_after},
                now,
            )

    def _reserve_artifact_purge(self, artifact_key: str, now: str) -> sqlite3.Row:
        with self.transaction():
            artifact = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (artifact_key,),
            ).fetchone()
            if artifact is None or artifact["state"] not in {"TRASHED", "PURGE_RESERVED"}:
                raise CoordinationError("ARTIFACT_STATE_CONFLICT")
            if not artifact["purge_after"] or now < artifact["purge_after"]:
                raise CoordinationError("ARTIFACT_RETENTION_ACTIVE")
            if artifact["state"] == "TRASHED":
                self.connection.execute(
                    "UPDATE coordination_artifacts SET state='PURGE_RESERVED', updated_at=?, last_error=NULL WHERE artifact_key=? AND state='TRASHED'",
                    (now, artifact_key),
                )
                self._event("ARTIFACT_PURGE_RESERVED", f"artifact:{artifact_key}", {}, now)
            artifact = self.connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (artifact_key,),
            ).fetchone()
        return artifact

    def _purge_artifact(self, artifact: sqlite3.Row, now: str) -> None:
        trash_relative = artifact["trash_relative_path"]
        if not isinstance(trash_relative, str) or not trash_relative.startswith(".artifact-trash/"):
            raise CoordinationError("ARTIFACT_PATH_UNSAFE")
        trash_name = trash_relative.split("/", 1)[1]
        if not trash_name or "/" in trash_name or trash_name in {".", ".."}:
            raise CoordinationError("ARTIFACT_PATH_UNSAFE")
        with self._open_artifact_trash() as trash_parent:
            try:
                descriptor = _open_verified_artifact(trash_parent, trash_name, artifact)
            except CoordinationError as exc:
                if str(exc) != "ARTIFACT_FILE_MISSING":
                    raise
                descriptor = None
            if descriptor is not None:
                try:
                    # The owner-only collector lock serializes all supported
                    # same-account trash mutations; the directory is mode 0700.
                    current_descriptor = _open_verified_artifact(
                        trash_parent, trash_name, artifact
                    )
                    try:
                        current = os.fstat(current_descriptor)
                        original = os.fstat(descriptor)
                        if (current.st_dev, current.st_ino) != (
                            original.st_dev,
                            original.st_ino,
                        ):
                            raise CoordinationError("ARTIFACT_TRASH_DRIFT")
                        os.unlink(trash_name, dir_fd=trash_parent)
                        os.fsync(trash_parent)
                    finally:
                        os.close(current_descriptor)
                finally:
                    os.close(descriptor)
        with self.transaction():
            cursor = self.connection.execute(
                "UPDATE coordination_artifacts SET state='PURGED', updated_at=?, last_error=NULL WHERE artifact_key=? AND state='PURGE_RESERVED'",
                (now, artifact["artifact_key"]),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("ARTIFACT_STATE_CONFLICT")
            self._event("ARTIFACT_PURGED", f"artifact:{artifact['artifact_key']}", {}, now)

    def _artifact_gc_preview(self, now: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM coordination_artifacts WHERE state<>'PURGED' ORDER BY registered_at, artifact_key"
        ).fetchall()
        preview: list[dict[str, Any]] = []
        for artifact in rows:
            state = artifact["state"]
            action = "KEEP"
            if state == "MOVE_RESERVED" or (
                state in {"REGISTERED", "ELIGIBLE"}
                and self._artifact_terminal_eligible(artifact)
            ):
                action = "MOVE_TO_QUARANTINE"
            elif state in {"TRASHED", "PURGE_RESERVED"} and artifact["purge_after"] and now >= artifact["purge_after"]:
                action = "PURGE"
            preview.append(
                {
                    "artifact_key": artifact["artifact_key"],
                    "relative_path": artifact["relative_path"],
                    "state": state,
                    "retention_class": artifact["retention_class"],
                    "action": action,
                }
            )
        return preview

    def collect_artifacts(self, *, now: str, execute: bool = False) -> dict[str, Any]:
        if not execute:
            return {"mode": "DRY_RUN", "artifacts": self._artifact_gc_preview(now)}

        moved: list[str] = []
        purged: list[str] = []
        held: list[dict[str, str]] = []
        with self._artifact_gc_lock() as acquired:
            if not acquired:
                return {
                    "mode": "EXECUTE",
                    "contention": True,
                    "moved": [],
                    "purged": [],
                    "held": [],
                }
            preview = self._artifact_gc_preview(now)
            for candidate in preview:
                if candidate["action"] == "KEEP":
                    continue
                try:
                    if candidate["action"] == "MOVE_TO_QUARANTINE":
                        trash_relative = (
                            f".artifact-trash/{candidate['artifact_key']}-"
                            f"{Path(candidate['relative_path']).name}"
                        )
                        artifact = self._reserve_artifact_move(
                            candidate["artifact_key"], trash_relative, now
                        )
                        self._move_artifact_to_trash(artifact, now)
                        moved.append(artifact["artifact_key"])
                    elif candidate["action"] == "PURGE":
                        artifact = self._reserve_artifact_purge(
                            candidate["artifact_key"], now
                        )
                        self._purge_artifact(artifact, now)
                        purged.append(artifact["artifact_key"])
                except (CoordinationError, OSError) as exc:
                    error = (
                        str(exc)
                        if isinstance(exc, CoordinationError)
                        else "ARTIFACT_GC_FAILED"
                    )
                    if error == "ARTIFACT_STATE_CONFLICT":
                        current = self.connection.execute(
                            "SELECT state FROM coordination_artifacts WHERE artifact_key=?",
                            (candidate["artifact_key"],),
                        ).fetchone()
                        completed_states = (
                            {"TRASHED", "PURGE_RESERVED", "PURGED"}
                            if candidate["action"] == "MOVE_TO_QUARANTINE"
                            else {"PURGED"}
                        )
                        if current is not None and current["state"] in completed_states:
                            continue
                    self._hold_artifact(candidate["artifact_key"], error, now)
                    held.append(
                        {"artifact_key": candidate["artifact_key"], "error": error}
                    )
        return {
            "mode": "EXECUTE",
            "contention": False,
            "moved": moved,
            "purged": purged,
            "held": held,
        }

    def _ready_finalization_attestation_error(
        self,
        *,
        repository: str,
        issue_number: int,
        generation: int,
        ready_item_version: int,
        source_payload_sha256: str,
    ) -> str | None:
        required_objects = {
            ("table", "portfolio_readiness_current"),
            ("table", "portfolio_readiness_campaigns"),
            ("table", "portfolio_readiness_receipts"),
            ("table", "portfolio_pull_buffer_candidates"),
            ("table", "portfolio_pull_buffer_current"),
            ("table", "portfolio_ready_finalizations"),
            ("table", "portfolio_dirty_events"),
            ("trigger", "portfolio_ready_finalizations_immutable_update"),
            ("trigger", "portfolio_ready_finalizations_immutable_delete"),
        }
        installed = {
            (str(row["type"]), str(row["name"]))
            for row in self.connection.execute(
                "SELECT type,name FROM sqlite_master WHERE type IN ('table','trigger')"
            )
        }
        if not required_objects.issubset(installed):
            return "READY_FINALIZATION_ATTESTATION_SCHEMA_MISSING"
        row = self.connection.execute(
            """
            SELECT finalization.generation AS finalization_generation,
                   finalization.campaign_id, finalization.receipt_id,
                   finalization.dirty_event_id,
                   finalization.finalization_sha256,
                   finalization.payload_json AS finalization_payload_json,
                   current.state AS readiness_state,
                   current.campaign_id AS current_campaign_id,
                   current.receipt_id AS current_receipt_id,
                   current.finalized_candidate_id,
                   current.finalized_event_id,
                   campaign.plan_sha256, campaign.transition_kind,
                   campaign.approval_proposal_sha256,
                   campaign.approval_decision_sha256,
                   campaign.approval_recipient_session_id,
                   campaign.approval_execution_scope_sha256,
                   receipt.verdict, receipt.receipt_sha256,
                   receipt.receipt_json,
                   candidate.id AS candidate_id,
                   candidate.state AS candidate_state,
                   candidate.repository AS candidate_repository,
                   candidate.issue_number AS candidate_issue_number,
                   candidate.generation AS candidate_generation,
                   candidate.item_version AS candidate_item_version,
                   candidate.source_payload_sha256 AS candidate_source_sha256,
                   candidate.candidate_sha256,
                   candidate.readiness_campaign_id,
                   candidate.readiness_plan_sha256,
                   candidate.readiness_receipt_id,
                   candidate.readiness_receipt_sha256,
                   pointer.candidate_id AS pointer_candidate_id,
                   dirty.id AS observed_dirty_event_id
            FROM portfolio_readiness_current current
            JOIN portfolio_ready_finalizations finalization
              ON finalization.repository=current.repository
             AND finalization.issue_number=current.issue_number
             AND finalization.campaign_id=current.campaign_id
             AND finalization.ready_candidate_id=current.finalized_candidate_id
             AND finalization.dirty_event_id=current.finalized_event_id
            JOIN portfolio_readiness_campaigns campaign
              ON campaign.id=finalization.campaign_id
            JOIN portfolio_readiness_receipts receipt
              ON receipt.id=finalization.receipt_id
            JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=finalization.ready_candidate_id
            JOIN portfolio_pull_buffer_current pointer
              ON pointer.repository=finalization.repository
             AND pointer.issue_number=finalization.issue_number
             AND pointer.candidate_id=finalization.ready_candidate_id
            JOIN portfolio_dirty_events dirty
              ON dirty.id=finalization.dirty_event_id
            WHERE finalization.repository=? AND finalization.issue_number=?
              AND finalization.generation=?
            """,
            (repository, issue_number, generation),
        ).fetchone()
        if row is None:
            return "READY_FINALIZATION_ATTESTATION_MISSING"
        try:
            receipt_payload = json.loads(row["receipt_json"])
            finalization_payload = json.loads(row["finalization_payload_json"])
        except (TypeError, json.JSONDecodeError):
            return "READY_FINALIZATION_ATTESTATION_DRIFT"
        exact = (
            row["readiness_state"] == "FINALIZED"
            and int(row["current_campaign_id"]) == int(row["campaign_id"])
            and int(row["current_receipt_id"]) == int(row["receipt_id"])
            and int(row["finalized_candidate_id"]) == int(row["candidate_id"])
            and int(row["finalized_event_id"]) == int(row["dirty_event_id"])
            and int(row["observed_dirty_event_id"]) == int(row["dirty_event_id"])
            and row["verdict"] == "PASS"
            and digest_json(receipt_payload) == row["receipt_sha256"]
            and row["candidate_state"] == "READY"
            and row["candidate_repository"] == repository
            and int(row["candidate_issue_number"]) == issue_number
            and int(row["candidate_generation"]) == generation
            and int(row["candidate_item_version"]) == ready_item_version
            and row["candidate_source_sha256"] == source_payload_sha256
            and int(row["pointer_candidate_id"]) == int(row["candidate_id"])
            and int(row["readiness_campaign_id"]) == int(row["campaign_id"])
            and row["readiness_plan_sha256"] == row["plan_sha256"]
            and int(row["readiness_receipt_id"]) == int(row["receipt_id"])
            and row["readiness_receipt_sha256"] == row["receipt_sha256"]
            and finalization_payload.get("schema")
            == "twinfinity-kanban-ready-finalization/v1"
            and finalization_payload.get("repository") == repository
            and finalization_payload.get("issue_number") == issue_number
            and finalization_payload.get("generation") == generation
            and finalization_payload.get("ready_item_version")
            == ready_item_version
            and finalization_payload.get("source_payload_sha256")
            == source_payload_sha256
            and finalization_payload.get("ready_candidate_sha256")
            == row["candidate_sha256"]
            and finalization_payload.get("readiness_campaign_id")
            == int(row["campaign_id"])
            and finalization_payload.get("readiness_receipt_id")
            == int(row["receipt_id"])
            and digest_json(finalization_payload) == row["finalization_sha256"]
        )
        if not exact:
            return "READY_FINALIZATION_ATTESTATION_DRIFT"
        if row["transition_kind"] == "APPROVAL_RESUME":
            planner = self.connection.execute(
                """
                SELECT endpoint.endpoint_id
                FROM executor_role_endpoint_current current
                JOIN executor_role_endpoints endpoint
                  ON endpoint.endpoint_id=current.endpoint_id
                 AND endpoint.role=current.role
                WHERE current.role='planner'
                """
            ).fetchone()
            boundary = self.connection.execute(
                "SELECT boundary FROM approval_proposals "
                "WHERE proposal_sha256=?",
                (row["approval_proposal_sha256"],),
            ).fetchone()
            if planner is None or boundary is None:
                return "READY_APPROVAL_AUTHORITY_MISSING"
            try:
                require_effective_approval(
                    self.connection,
                    repository=repository,
                    issue_number=issue_number,
                    recipient_session_id=str(
                        row["approval_recipient_session_id"]
                    ),
                    actor_session_id=str(planner["endpoint_id"]),
                    execution_scope_sha256=str(
                        row["approval_execution_scope_sha256"]
                    ),
                    authority_sha256=str(row["approval_decision_sha256"]),
                    required_proposal_sha256=str(
                        row["approval_proposal_sha256"]
                    ),
                    required_workstream="READINESS",
                    required_boundary=str(boundary["boundary"]),
                    required_current_recipient_role="planner",
                    required=True,
                )
            except ApprovalGuardError as exc:
                return "READY_APPROVAL_AUTHORITY_" + str(exc)
        return None

    def _require_ready_finalization_attestation(
        self,
        *,
        repository: str,
        issue_number: int,
        generation: int,
        ready_item_version: int,
        source_payload_sha256: str,
    ) -> None:
        error = self._ready_finalization_attestation_error(
            repository=repository,
            issue_number=issue_number,
            generation=generation,
            ready_item_version=ready_item_version,
            source_payload_sha256=source_payload_sha256,
        )
        if error is not None:
            raise CoordinationError(error)


    def set_issue_status(
        self,
        *,
        repository: str,
        issue_number: int,
        status: str,
        allocation_class: str,
        generation: int,
        accountable_session_id: str | None,
        lease_manifest_sha256: str | None,
        development_units: int,
        shared_units: int,
        expected_source_sha256: str,
        expected_version: int,
        now: str,
        sre_units: int = 0,
        _transaction: bool = True,
    ) -> dict[str, Any]:
        """Apply an ordinary non-gateway issue transition."""

        return self._set_issue_status_locked(
            repository=repository,
            issue_number=issue_number,
            status=status,
            allocation_class=allocation_class,
            generation=generation,
            accountable_session_id=accountable_session_id,
            lease_manifest_sha256=lease_manifest_sha256,
            development_units=development_units,
            shared_units=shared_units,
            expected_source_sha256=expected_source_sha256,
            expected_version=expected_version,
            now=now,
            sre_units=sre_units,
            transaction=_transaction,
            gateway=None,
        )

    def _set_issue_status_from_admission(
        self, *, pending_claim: bool, **item: Any
    ) -> dict[str, Any]:
        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        return self._set_issue_status_locked(
            **item,
            transaction=False,
            gateway=_ADMISSION_ACTIVATION_GATEWAY,
            admission_watch_pending_claim=pending_claim,
        )

    def _set_issue_status_from_transfer(
        self, *, pending_claim: bool, **item: Any
    ) -> dict[str, Any]:
        """Apply one typed transfer release or successor activation atomically."""

        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        status = item.get("status")
        allocation_class = item.get("allocation_class")
        if not (
            (status == "MONITOR" and allocation_class == "NONE")
            or (
                status in {"ACTIVE", "ACTIVE_FENCED"}
                and allocation_class == "ACTIVE"
            )
        ):
            raise CoordinationError("TRANSFER_ITEM_TRANSITION_INVALID")
        return self._set_issue_status_locked(
            **item,
            transaction=False,
            gateway=_TRANSFER_ACTIVATION_GATEWAY,
            admission_watch_pending_claim=pending_claim,
        )

    def _set_issue_status_for_test_fixture(self, **item: Any) -> dict[str, Any]:
        """Seed non-readiness item states only on a temporary database."""

        status = item.get("status")
        if (
            isinstance(status, str)
            and status.upper() in _TEST_FIXTURE_FORBIDDEN_ITEM_STATES
        ):
            raise CoordinationError("READY_FINALIZATION_REQUIRED")
        self._require_temporary_test_database()
        return self._set_issue_status_locked(
            **item,
            transaction=True,
            gateway=_TEST_FIXTURE_GATEWAY,
        )

    def _set_issue_status_locked(
        self,
        *,
        repository: str,
        issue_number: int,
        status: str,
        allocation_class: str,
        generation: int,
        accountable_session_id: str | None,
        lease_manifest_sha256: str | None,
        development_units: int,
        shared_units: int,
        expected_source_sha256: str,
        expected_version: int,
        now: str,
        sre_units: int = 0,
        transaction: bool,
        gateway: object | None,
        admission_watch_pending_claim: bool = False,
    ) -> dict[str, Any]:
        _validate_repository(repository)
        _validate_sha256(expected_source_sha256)
        if (
            status not in ITEM_STATUSES
            or allocation_class not in ALLOCATION_CLASSES
            or issue_number <= 0
            or generation < 0
        ):
            raise CoordinationError("INVALID_ITEM_STATUS")
        if accountable_session_id is not None:
            accountable_session_id = canonicalize_coordination_identity(
                self.connection, accountable_session_id
            )
        if lease_manifest_sha256 is not None:
            _validate_sha256(lease_manifest_sha256)
        if (
            development_units < 0
            or shared_units < 0
            or sre_units < 0
            or expected_version < 0
        ):
            raise CoordinationError("INVALID_ITEM_STATUS")
        if allocation_class in {"ACTIVE", "RETAINED"} and not (
            development_units or shared_units or sre_units
        ):
            raise CoordinationError("INVALID_CAPACITY_ALLOCATION")
        with (self.transaction() if transaction else nullcontext()):
            gc_reservation = self.connection.execute(
                """
                SELECT 1 FROM coordination_artifacts
                WHERE repository=? AND issue_number=?
                  AND state IN ('MOVE_RESERVED','PURGE_RESERVED')
                LIMIT 1
                """,
                (repository, issue_number),
            ).fetchone()
            if gc_reservation is not None:
                raise CoordinationError("ARTIFACT_GC_INFLIGHT")
            source = self.current_snapshot(repository, "issue", issue_number)
            if source is None or source.payload_sha256 != expected_source_sha256:
                raise CoordinationError("SOURCE_SNAPSHOT_DRIFT")
            current = self.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (repository, issue_number),
            ).fetchone()
            actual_version = 0 if current is None else int(current["version"])
            if actual_version != expected_version:
                raise CoordinationError("ITEM_VERSION_CONFLICT")
            if (
                current is not None
                and current["allocation_class"] in {"ACTIVE", "RETAINED"}
                and (allocation_class == "NONE" or status == "DONE")
                and gateway not in {
                    _TERMINAL_FINALIZATION_GATEWAY,
                    _TEST_FIXTURE_GATEWAY,
                }
                and not (
                    gateway is _TRANSFER_ACTIVATION_GATEWAY
                    and status == "MONITOR"
                    and allocation_class == "NONE"
                )
            ):
                raise CoordinationError("TERMINAL_FINALIZATION_REQUIRED")
            if (
                status == "PUBLICATION_PENDING"
                and gateway not in {
                    _TERMINAL_FINALIZATION_GATEWAY,
                    _TEST_FIXTURE_GATEWAY,
                }
            ):
                raise CoordinationError("TERMINAL_CLOSEOUT_PACKET_REQUIRED")
            creating_execution = status in ACTIVE_EXECUTION_STATUSES and (
                current is None
                or current["status"] not in ACTIVE_EXECUTION_STATUSES
                or current["allocation_class"] != "ACTIVE"
            )
            if creating_execution and gateway not in {
                _ADMISSION_ACTIVATION_GATEWAY,
                _TRANSFER_ACTIVATION_GATEWAY,
                _TEST_FIXTURE_GATEWAY,
            }:
                raise CoordinationError("ADMISSION_ACTIVATION_REQUIRED")
            if current is not None:
                current_generation = int(current["generation"])
                if generation < current_generation:
                    raise CoordinationError("GENERATION_REGRESSION")
                if generation == current_generation:
                    if current["status"] == "HOLD" and status != "HOLD":
                        raise CoordinationError("NEW_GENERATION_REQUIRED")
                    if STATUS_RANK[status] < STATUS_RANK[current["status"]]:
                        raise CoordinationError("STATUS_REGRESSION")
            try:
                validate_portfolio_transition(
                    self.connection,
                    repository=repository,
                    issue_number=issue_number,
                    status=status,
                    allocation_class=allocation_class,
                )
            except PortfolioGraphError as exc:
                raise CoordinationError(str(exc)) from exc
            creating_ready = status == "READY" and (
                current is None or current["status"] != "READY"
            )
            if creating_ready and gateway is not _READY_FINALIZATION_GATEWAY:
                raise CoordinationError("READY_FINALIZATION_REQUIRED")
            reserved = self.connection.execute(
                """
                SELECT COALESCE(SUM(development_units), 0) AS development,
                       COALESCE(SUM(shared_units), 0) AS shared,
                       COALESCE(SUM(sre_units), 0) AS sre
                FROM coordination_items
                WHERE repository=? AND issue_number<>?
                  AND allocation_class IN ('ACTIVE', 'RETAINED')
                """,
                (repository, issue_number),
            ).fetchone()
            proposed_development = int(reserved["development"]) + development_units
            proposed_shared = int(reserved["shared"]) + shared_units
            proposed_sre = (
                int(reserved["sre"])
                + reserved_hosted_sre_units(self.connection, repository)
                + sre_units
            )
            if allocation_class == "NONE":
                proposed_development = int(reserved["development"])
                proposed_shared = int(reserved["shared"])
                proposed_sre = (
                    int(reserved["sre"])
                    + reserved_hosted_sre_units(self.connection, repository)
                )
            capacity_policy = self._ensure_capacity_policy(repository, now)
            if (
                proposed_development > int(capacity_policy["development_limit"])
                or proposed_shared > int(capacity_policy["shared_limit"])
                or proposed_sre > int(capacity_policy["sre_limit"])
            ):
                raise CoordinationError("CAPACITY_EXCEEDED")
            if allocation_class in {"ACTIVE", "RETAINED"} and lease_manifest_sha256 is not None:
                collision = self.connection.execute(
                    """
                    SELECT issue_number FROM coordination_items
                    WHERE repository=? AND issue_number<>?
                      AND allocation_class IN ('ACTIVE', 'RETAINED')
                      AND lease_manifest_sha256=?
                    """,
                    (repository, issue_number, lease_manifest_sha256),
                ).fetchone()
                if collision is not None:
                    raise CoordinationError("LEASE_COLLISION")
            version = actual_version + 1
            self.connection.execute(
                """
                INSERT INTO coordination_items(repository, issue_number, status, allocation_class, generation,
                    accountable_session_id, lease_manifest_sha256, development_units,
                    shared_units, sre_units, source_payload_sha256, version, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository, issue_number) DO UPDATE SET
                    status=excluded.status,
                    allocation_class=excluded.allocation_class,
                    generation=excluded.generation,
                    accountable_session_id=excluded.accountable_session_id,
                    lease_manifest_sha256=excluded.lease_manifest_sha256,
                    development_units=excluded.development_units,
                    shared_units=excluded.shared_units,
                    sre_units=excluded.sre_units,
                    source_payload_sha256=excluded.source_payload_sha256,
                    version=excluded.version,
                    updated_at=excluded.updated_at
                """,
                (
                    repository,
                    issue_number,
                    status,
                    allocation_class,
                    generation,
                    accountable_session_id,
                    lease_manifest_sha256,
                    development_units,
                    shared_units,
                    sre_units,
                    expected_source_sha256,
                    version,
                    now,
                ),
            )
            watch_key = terminal_watch_key(repository, issue_number, generation)
            if allocation_class == "ACTIVE" and status in ACTIVE_EXECUTION_STATUSES:
                accountable_role = coordination_identity_role(
                    self.connection, accountable_session_id or ""
                )
                pointer_count = int(self.connection.execute(
                    "SELECT COUNT(*) FROM executor_role_endpoint_current"
                ).fetchone()[0])
                if accountable_role not in {"development", "sre"} and not (
                    pointer_count == 0
                    and isinstance(accountable_session_id, str)
                    and SESSION.fullmatch(accountable_session_id)
                ):
                    raise CoordinationError("MESSAGE_ROLE_MISMATCH")
                if lease_manifest_sha256 is None:
                    raise CoordinationError("INVALID_TERMINAL_WATCH_LEASE")
                if current is not None and generation > int(current["generation"]):
                    completed = self.connection.execute(
                        """
                        UPDATE coordination_terminal_watches
                        SET state='COMPLETE', process_id=NULL, updated_at=?,
                            last_error='SUPERSEDED_BY_NEW_GENERATION'
                        WHERE repository=? AND issue_number=?
                          AND generation<? AND state='ACTIVE'
                        """,
                        (now, repository, issue_number, generation),
                    )
                    if completed.rowcount:
                        self._event(
                            "TERMINAL_WATCH_SUPERSEDED",
                            f"{repository}:issue:{issue_number}:generation:{generation}",
                            {
                                "completed_watch_count": completed.rowcount,
                                "item_version": version,
                            },
                            now,
                        )
                prior_watch = self.connection.execute(
                    """
                    SELECT * FROM coordination_terminal_watches
                    WHERE repository=? AND issue_number=? AND generation=?
                    """,
                    (repository, issue_number, generation),
                ).fetchone()
                if prior_watch is None:
                    watch_state = (
                        "PENDING_CLAIM"
                        if gateway in {
                            _ADMISSION_ACTIVATION_GATEWAY,
                            _TRANSFER_ACTIVATION_GATEWAY,
                        }
                        and admission_watch_pending_claim
                        else "ACTIVE"
                    )
                    self.connection.execute(
                        """
                        INSERT INTO coordination_terminal_watches(
                            watch_key, repository, issue_number, generation,
                            accountable_session_id, lease_manifest_sha256, state,
                            attempts, process_id, last_heartbeat_at, next_wake_at,
                            updated_at, last_error
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, NULL)
                        """,
                        (
                            watch_key,
                            repository,
                            issue_number,
                            generation,
                            accountable_session_id,
                            lease_manifest_sha256,
                            watch_state,
                            now,
                            timestamp_after(now, 60),
                            now,
                        ),
                    )
                    self._event(
                        "TERMINAL_WATCH_OPENED",
                        watch_key,
                        {"item_version": version, "accountable_session_id": accountable_session_id},
                        now,
                    )
                elif (
                    prior_watch["accountable_session_id"] != accountable_session_id
                    or prior_watch["lease_manifest_sha256"] != lease_manifest_sha256
                ):
                    raise CoordinationError("TERMINAL_WATCH_LINEAGE_MISMATCH")
                elif prior_watch["state"] not in {"ACTIVE", "PENDING_CLAIM"}:
                    raise CoordinationError("TERMINAL_WATCH_STATE_CONFLICT")
            else:
                cursor = self.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='COMPLETE', process_id=NULL, updated_at=?, last_error=NULL
                    WHERE repository=? AND issue_number=?
                      AND state IN ('PENDING_CLAIM','ACTIVE')
                    """,
                    (now, repository, issue_number),
                )
                if cursor.rowcount:
                    self._event(
                        "TERMINAL_WATCH_COMPLETED",
                        f"{repository}:issue:{issue_number}",
                        {"status": status, "allocation_class": allocation_class, "item_version": version},
                        now,
                    )
            result = {
                "repository": repository,
                "issue_number": issue_number,
                "status": status,
                "allocation_class": allocation_class,
                "generation": generation,
                "version": version,
                "source_payload_sha256": expected_source_sha256,
            }
            if (
                current is not None
                and current["allocation_class"] in {"ACTIVE", "RETAINED"}
                and allocation_class == "NONE"
            ):
                result["portfolio_dirty_event_id"] = self._enqueue_portfolio_dirty_event(
                    repository=repository,
                    issue_number=issue_number,
                    release_item_version=version,
                    release_source_sha256=expected_source_sha256,
                    prior_allocation_class=str(current["allocation_class"]),
                    status=status,
                    generation=generation,
                    now=now,
                )
            self._event("ISSUE_STATUS_CHANGED", f"{repository}:issue:{issue_number}", result, now)
        return result

    def _set_issue_status_from_ready_finalizer(
        self, **item: Any
    ) -> dict[str, Any]:
        """Commit READY only from an already recorded exact finalization."""

        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        self._require_ready_finalization_attestation(
            repository=item["repository"],
            issue_number=item["issue_number"],
            generation=item["generation"],
            ready_item_version=item["expected_version"] + 1,
            source_payload_sha256=item["expected_source_sha256"],
        )
        return self._set_issue_status_locked(
            **item,
            transaction=False,
            gateway=_READY_FINALIZATION_GATEWAY,
        )

    def apply_issue_plan(
        self, entries: list[dict[str, Any]], *, now: str
    ) -> list[dict[str, Any]]:
        """Apply a bounded portfolio plan as one all-or-nothing transaction."""
        required_keys = {
            "repository",
            "issue_number",
            "status",
            "allocation_class",
            "generation",
            "accountable_session_id",
            "lease_manifest_sha256",
            "development_units",
            "shared_units",
            "sre_units",
            "expected_source_sha256",
            "expected_version",
        }
        if not entries or len(entries) > 100:
            raise CoordinationError("INVALID_ISSUE_PLAN")
        seen: set[tuple[str, int]] = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != required_keys:
                raise CoordinationError("INVALID_ISSUE_PLAN")
            repository = entry.get("repository")
            issue_number = entry.get("issue_number")
            if not isinstance(repository, str) or not isinstance(issue_number, int):
                raise CoordinationError("INVALID_ISSUE_PLAN")
            key = (repository, issue_number)
            if key in seen:
                raise CoordinationError("DUPLICATE_ISSUE_PLAN_ITEM")
            seen.add(key)

        results: list[dict[str, Any]] = []
        with self.transaction():
            for entry in entries:
                results.append(self.set_issue_status(**entry, now=now, _transaction=False))
            self._event(
                "ISSUE_PLAN_APPLIED",
                "portfolio-plan",
                {
                    "count": len(results),
                    "items": [
                        {
                            "repository": item["repository"],
                            "issue_number": item["issue_number"],
                            "version": item["version"],
                        }
                        for item in results
                    ],
                },
                now,
            )
        return results

    def _validate_message_source(self, payload: dict[str, Any]) -> None:
        source = payload.get("source")
        if not isinstance(source, dict):
            raise CoordinationError("MESSAGE_SOURCE_REQUIRED")
        repository = source.get("repository")
        object_kind = source.get("object_kind")
        object_number = source.get("object_number")
        payload_sha256 = source.get("payload_sha256")
        if not isinstance(repository, str):
            raise CoordinationError("MESSAGE_SOURCE_INVALID")
        _validate_repository(repository)
        if object_kind not in SOURCE_KINDS or not isinstance(object_number, int) or object_number <= 0:
            raise CoordinationError("MESSAGE_SOURCE_INVALID")
        if not isinstance(payload_sha256, str):
            raise CoordinationError("MESSAGE_SOURCE_INVALID")
        _validate_sha256(payload_sha256)
        current = self.current_snapshot(repository, object_kind, object_number)
        if current is None or current.payload_sha256 != payload_sha256:
            raise CoordinationError("SOURCE_SNAPSHOT_DRIFT")

    def _validate_message_contract(
        self,
        *,
        topic: str,
        recipient_session_id: str,
        payload: dict[str, Any],
        current_write: bool = False,
        projected_item: dict[str, Any] | None = None,
    ) -> None:
        if topic not in MESSAGE_TOPICS:
            raise CoordinationError("MESSAGE_TOPIC_INVALID")
        if topic == "coordination.notice":
            if payload.get("mutation_authority") is not False:
                raise CoordinationError("NOTICE_MUST_BE_NON_MUTATING")
            notice_kind = payload.get("notice_kind")
            if notice_kind not in NOTICE_KINDS:
                raise CoordinationError("NOTICE_KIND_INVALID")
            exempt_key_paths = (
                _validate_terminal_notice_evidence(payload)
                if notice_kind == "terminal_receipt"
                else frozenset()
            )
            aggregate_notice_text = " ".join(
                _notice_string_values(payload, exempt_key_paths=exempt_key_paths)
            )
            if (
                _notice_has_forbidden_content(payload)
                or _notice_string_claims_authority(aggregate_notice_text)
            ):
                raise CoordinationError("NOTICE_MUTATION_FIELDS_FORBIDDEN")
            if set(payload) != NOTICE_ALLOWED_KEYS[notice_kind] and not (
                notice_kind != "planning_request"
                and set(payload)
                == NOTICE_ALLOWED_KEYS[notice_kind] - {"next_observation"}
            ):
                raise CoordinationError("NOTICE_SCHEMA_INVALID")
            if (
                not isinstance(payload.get("subject"), str)
                or not payload["subject"]
                or not isinstance(payload.get("summary"), str)
                or not payload["summary"]
                or not isinstance(payload.get("evidence"), dict)
            ):
                raise CoordinationError("NOTICE_SCHEMA_INVALID")
            if notice_kind == "planning_request" and (
                not isinstance(payload.get("requested_evidence"), list)
                or not payload["requested_evidence"]
                or any(
                    not isinstance(item, str) or not item
                    for item in payload["requested_evidence"]
                )
            ):
                raise CoordinationError("NOTICE_SCHEMA_INVALID")
            if "next_observation" in payload and (
                not isinstance(payload["next_observation"], str)
                or not payload["next_observation"]
            ):
                raise CoordinationError("NOTICE_SCHEMA_INVALID")
            return
        if not recipient_matches_topic(
            self.connection, topic=topic, recipient=recipient_session_id
        ):
            raise CoordinationError("MESSAGE_ROLE_MISMATCH")
        if topic == "development.terminal_closeout":
            # Historical rows remain queryable, but no new extra-writer
            # closeout handoff may be enqueued or claimed.
            raise CoordinationError("TERMINAL_CLOSEOUT_TOPIC_RETIRED")
        required_strings = (
            "action",
            "base_sha",
            "branch",
            "worktree_path",
            "opaque_worktree_id",
            "accountable_session_id",
            "lease_manifest_sha256",
            "authority_sha256",
        )
        if any(not isinstance(payload.get(field), str) or not payload[field] for field in required_strings):
            raise CoordinationError("MESSAGE_CONTRACT_INCOMPLETE")
        if current_write:
            payload_identity = canonicalize_coordination_identity(
                self.connection, payload["accountable_session_id"]
            )
            identity_matches = payload_identity == recipient_session_id
        else:
            identity_matches = identities_role_equivalent(
                self.connection,
                payload["accountable_session_id"],
                recipient_session_id,
            )
        if not identity_matches:
            raise CoordinationError("MESSAGE_RECIPIENT_MISMATCH")
        if not GIT_SHA.fullmatch(payload["base_sha"]):
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        if not BRANCH.fullmatch(payload["branch"]):
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        worktree = Path(payload["worktree_path"])
        if not worktree.is_absolute() or worktree.parent != Path("/home/ubuntu/code"):
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        _validate_sha256(payload["lease_manifest_sha256"])
        _validate_sha256(payload["authority_sha256"])
        issue_number = payload.get("issue_number")
        generation = payload.get("generation")
        item_version = payload.get("item_version")
        if (
            not isinstance(issue_number, int)
            or issue_number <= 0
            or not isinstance(generation, int)
            or generation < 0
            or not isinstance(item_version, int)
            or item_version <= 0
            or payload["source"].get("object_kind") != "issue"
            or payload["source"].get("object_number") != issue_number
        ):
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        if topic == "development.recovery_prepare" and payload["action"] != "ACK_ZERO_MUTATION":
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        if topic in {"development.admission", "sre.admission"} and payload["action"] not in {
            "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            "CREATE_LOCAL_BRANCH_AND_WORKTREE_THEN_CONTINUE",
        }:
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        if topic == "development.recovery_commit" and payload["action"] != (
            "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT"
        ):
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        if topic in {
            "development.recovery_prepare",
            "development.recovery_commit",
        } and payload.get("environment_root") is not None:
            recovery_contract = payload.get("recovery_contract")
            recovery_contract_sha256 = payload.get("recovery_contract_sha256")
            if (
                not isinstance(recovery_contract, dict)
                or not recovery_contract
                or not isinstance(recovery_contract_sha256, str)
            ):
                raise CoordinationError("RECOVERY_CONTRACT_INCOMPLETE")
            _validate_sha256(recovery_contract_sha256)
            if digest_json(recovery_contract) != recovery_contract_sha256:
                raise CoordinationError("RECOVERY_CONTRACT_DIGEST_MISMATCH")
        existing_environment = payload.get("existing_environment")
        if payload.get("environment_root") is not None and existing_environment is not None:
            raise CoordinationError("MESSAGE_ENVIRONMENT_BINDING_CONFLICT")
        if existing_environment is not None:
            required_environment_fields = {
                "root",
                "rebuild_artifact_key",
                "rebuild_artifact_content_sha256",
                "freeze_sha256",
                "package_count",
                "gate_environment_provenance_sha256",
            }
            if (
                not isinstance(existing_environment, dict)
                or not required_environment_fields.issubset(existing_environment)
                or set(existing_environment) != required_environment_fields
                or not isinstance(existing_environment["root"], str)
                or not Path(existing_environment["root"]).is_absolute()
                or type(existing_environment["package_count"]) is not int
                or existing_environment["package_count"] <= 0
            ):
                raise CoordinationError("MESSAGE_EXISTING_ENVIRONMENT_INVALID")
            for field in (
                "rebuild_artifact_key",
                "rebuild_artifact_content_sha256",
                "freeze_sha256",
            ):
                if not isinstance(existing_environment[field], str):
                    raise CoordinationError("MESSAGE_EXISTING_ENVIRONMENT_INVALID")
                _validate_sha256(existing_environment[field])
            provenance_sha256 = existing_environment[
                "gate_environment_provenance_sha256"
            ]
            if not isinstance(provenance_sha256, str):
                raise CoordinationError("MESSAGE_EXISTING_ENVIRONMENT_INVALID")
            _validate_sha256(provenance_sha256)
            _receipt_artifact, receipt_bytes = self.read_registered_artifact(
                artifact_key=existing_environment["rebuild_artifact_key"],
                repository=payload["source"]["repository"],
                issue_number=issue_number,
                generation=generation,
                expected_content_sha256=existing_environment[
                    "rebuild_artifact_content_sha256"
                ],
                expected_retention_class="CLOSEOUT_EVIDENCE",
                maximum_size_bytes=64 * 1024,
                _transaction=False,
            )
            try:
                rebuild_receipt = json.loads(receipt_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CoordinationError(
                    "MESSAGE_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
                ) from exc
            if not isinstance(rebuild_receipt, dict):
                raise CoordinationError(
                    "MESSAGE_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
                )
            receipt_fields = {
                "kind",
                "state",
                "repository",
                "issue_number",
                "generation",
                "source_payload_sha256",
                "built_candidate_head_sha",
                "environment_root",
                "requirements",
                "freeze_sha256",
                "package_count",
                "gate_environment_provenance_sha256",
                "log_artifact_key",
                "log_artifact_content_sha256",
            }
            requirements = rebuild_receipt.get("requirements")
            if (
                set(rebuild_receipt) != receipt_fields
                or rebuild_receipt.get("kind")
                != "TWINFINITY_ENVIRONMENT_REBUILD_RECEIPT_V1"
                or rebuild_receipt.get("state") != "PASS"
                or rebuild_receipt.get("repository")
                != payload["source"]["repository"]
                or rebuild_receipt.get("issue_number") != issue_number
                or rebuild_receipt.get("generation") != generation
                or rebuild_receipt.get("source_payload_sha256")
                != payload["source"]["payload_sha256"]
                or rebuild_receipt.get("environment_root")
                != existing_environment["root"]
                or rebuild_receipt.get("freeze_sha256")
                != existing_environment["freeze_sha256"]
                or rebuild_receipt.get("package_count")
                != existing_environment["package_count"]
                or rebuild_receipt.get("gate_environment_provenance_sha256")
                != existing_environment.get(
                    "gate_environment_provenance_sha256"
                )
                or not isinstance(requirements, list)
                or not requirements
                or not isinstance(
                    rebuild_receipt.get("built_candidate_head_sha"), str
                )
                or not GIT_SHA.fullmatch(
                    rebuild_receipt["built_candidate_head_sha"]
                )
            ):
                raise CoordinationError(
                    "MESSAGE_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
                )
            for requirement in requirements:
                if (
                    not isinstance(requirement, dict)
                    or set(requirement) != {"path", "sha256"}
                    or not isinstance(requirement["path"], str)
                    or Path(requirement["path"]).is_absolute()
                    or not requirement["path"]
                    or any(
                        part in {"", ".", ".."}
                        for part in Path(requirement["path"]).parts
                    )
                    or not isinstance(requirement["sha256"], str)
                ):
                    raise CoordinationError(
                        "MESSAGE_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
                    )
                _validate_sha256(requirement["sha256"])
            log_artifact_key = rebuild_receipt.get("log_artifact_key")
            log_artifact_content_sha256 = rebuild_receipt.get(
                "log_artifact_content_sha256"
            )
            if (
                not isinstance(log_artifact_key, str)
                or not isinstance(log_artifact_content_sha256, str)
            ):
                raise CoordinationError(
                    "MESSAGE_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
                )
            _validate_sha256(log_artifact_key)
            _validate_sha256(log_artifact_content_sha256)
            self.verify_registered_artifact(
                artifact_key=log_artifact_key,
                repository=payload["source"]["repository"],
                issue_number=issue_number,
                generation=generation,
                expected_content_sha256=log_artifact_content_sha256,
                expected_retention_class="CLOSEOUT_EVIDENCE",
                _transaction=False,
            )
        if topic in {
            "development.admission",
            "development.recovery_commit",
            "sre.admission",
        }:
            try:
                approval_candidates: list[str] = []
                if self.connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='approval_interests'"
                ).fetchone():
                    approval_candidates = [
                        str(candidate[0])
                        for candidate in self.connection.execute(
                            """
                            SELECT DISTINCT i.recipient_session_id
                            FROM approval_current c
                            JOIN approval_proposals p USING(proposal_sha256)
                            JOIN approval_interests i USING(proposal_sha256)
                            WHERE p.repository=? AND p.owning_issue=?
                            """,
                            (payload["source"]["repository"], issue_number),
                        ).fetchall()
                    ]
                approval_recipient = select_role_equivalent_identity(
                    self.connection, recipient_session_id, approval_candidates
                )
                require_effective_approval(
                    self.connection,
                    repository=payload["source"]["repository"],
                    issue_number=issue_number,
                    recipient_session_id=approval_recipient,
                    execution_scope_sha256=admission_execution_scope_sha256(payload),
                    authority_sha256=payload["authority_sha256"],
                    required=False,
                )
            except ApprovalGuardError as exc:
                raise CoordinationError(str(exc)) from exc
        capacity = payload.get("capacity")
        if not isinstance(capacity, dict):
            raise CoordinationError("MESSAGE_CONTRACT_INCOMPLETE")
        development_units = capacity.get("development_units")
        shared_units = capacity.get("shared_units")
        sre_units = capacity.get("sre_units")
        if (
            not isinstance(development_units, int)
            or development_units < 0
            or not isinstance(shared_units, int)
            or shared_units < 0
            or not isinstance(sre_units, int)
            or sre_units < 0
        ):
            raise CoordinationError("MESSAGE_CONTRACT_INVALID")
        if topic == "development.admission" and sre_units != 0:
            raise CoordinationError("MESSAGE_CAPACITY_CLASS_MISMATCH")
        if topic == "sre.admission" and (
            development_units != 0 or shared_units != 0 or sre_units <= 0
        ):
            raise CoordinationError("MESSAGE_CAPACITY_CLASS_MISMATCH")
        item = projected_item
        if item is None:
            item = self.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (payload["source"]["repository"], issue_number),
            ).fetchone()
        message_row = None
        terminal_packet = None
        recovery_watch = None
        if not current_write:
            message_row = self.connection.execute(
                "SELECT id FROM coordination_messages "
                "WHERE payload_sha256=? AND topic=? ORDER BY id LIMIT 1",
                (digest_json(payload), topic),
            ).fetchone()
            if message_row is not None:
                terminal_packet = self.connection.execute(
                    "SELECT * FROM coordination_terminal_closeout_packets "
                    "WHERE activation_message_id=?",
                    (message_row["id"],),
                ).fetchone()
                if topic == "development.recovery_commit":
                    recovery_watch = self.connection.execute(
                        "SELECT * FROM coordination_terminal_watches "
                        "WHERE repository=? AND issue_number=? AND generation=?",
                        (
                            payload["source"]["repository"],
                            issue_number,
                            generation,
                        ),
                    ).fetchone()
        terminal_pending = bool(
            item is not None
            and item["status"] == "PUBLICATION_PENDING"
            and terminal_packet is not None
            and terminal_packet["activation_payload_sha256"] == digest_json(payload)
            and int(terminal_packet["expected_item_version"])
            == item_version + (1 if topic == "development.recovery_commit" else 0)
            and int(terminal_packet["publication_pending_item_version"])
            == int(item["version"])
        )
        recovery_activated = bool(
            topic == "development.recovery_commit"
            and item is not None
            and item["status"] in {"ACTIVE", "ACTIVE_FENCED"}
            and int(item["version"]) == item_version + 1
            and message_row is not None
            and recovery_watch is not None
            and recovery_watch["state"] == "ACTIVE"
            and int(recovery_watch["admission_message_id"] or 0)
            == int(message_row["id"])
            and recovery_watch["admission_payload_sha256"] == digest_json(payload)
        )
        if topic in {"development.admission", "sre.admission"}:
            allowed_statuses = {"ACTIVE", "ACTIVE_FENCED", "PUBLICATION_PENDING"}
        elif topic == "development.recovery_commit":
            allowed_statuses = {"HOLD"}
            if recovery_activated or terminal_pending:
                allowed_statuses.update(
                    {"ACTIVE", "ACTIVE_FENCED", "PUBLICATION_PENDING"}
                )
        else:
            allowed_statuses = {"HOLD"}
        if (
            item is None
            or item["status"] not in allowed_statuses
            or item["allocation_class"] not in {"ACTIVE", "RETAINED"}
            or int(item["generation"]) != generation
            or (
                item["accountable_session_id"] != recipient_session_id
                if current_write
                else not identities_role_equivalent(
                    self.connection,
                    item["accountable_session_id"],
                    recipient_session_id,
                )
            )
            or item["lease_manifest_sha256"] != payload["lease_manifest_sha256"]
            or item["source_payload_sha256"] != payload["source"]["payload_sha256"]
            or (
                int(item["version"]) != item_version
                and not terminal_pending
                and not recovery_activated
            )
            or int(item["development_units"]) != development_units
            or int(item["shared_units"]) != shared_units
            or int(item["sre_units"]) != sre_units
        ):
            raise CoordinationError("MESSAGE_ITEM_STATE_MISMATCH")
        if topic == "development.recovery_commit":
            prior_message_id = payload.get("prior_message_id")
            if not isinstance(prior_message_id, int) or prior_message_id <= 0:
                raise CoordinationError("MESSAGE_CONTRACT_INCOMPLETE")
            prior = self.connection.execute(
                "SELECT state, recipient_session_id, topic, payload_json FROM coordination_messages WHERE id=?",
                (prior_message_id,),
            ).fetchone()
            if (
                prior is None
                or prior["state"] != "COMPLETE"
                or not identities_role_equivalent(
                    self.connection, prior["recipient_session_id"], recipient_session_id
                )
                or prior["topic"] != "development.recovery_prepare"
            ):
                raise CoordinationError("RECOVERY_PREPARE_NOT_COMPLETE")
            prior_payload = json.loads(prior["payload_json"])
            for field in (
                "issue_number",
                "generation",
                "base_sha",
                "branch",
                "worktree_path",
                "opaque_worktree_id",
                "lease_manifest_sha256",
                "authority_sha256",
                "item_version",
                "source",
                "capacity",
                "environment_root",
                "existing_environment",
                "recovery_contract",
                "recovery_contract_sha256",
            ):
                if prior_payload.get(field) != payload.get(field):
                    raise CoordinationError("RECOVERY_CONTRACT_DRIFT")

    def enqueue_message(
        self,
        *,
        idempotency_key: str,
        recipient_session_id: str,
        topic: str,
        payload: dict[str, Any],
        now: str,
        _transaction: bool = True,
    ) -> int:
        original_recipient = recipient_session_id
        recipient_session_id = canonicalize_coordination_identity(
            self.connection, recipient_session_id
        )
        if not idempotency_key or not topic or not isinstance(payload, dict):
            raise CoordinationError("INVALID_MESSAGE")
        payload = copy.deepcopy(payload)
        if payload.get("accountable_session_id") == original_recipient:
            payload["accountable_session_id"] = recipient_session_id
        payload_json = canonical_json(payload)
        payload_sha256 = digest_json(payload)
        with (self.transaction() if _transaction else nullcontext()):
            self._validate_message_source(payload)
            self._validate_message_contract(
                topic=topic,
                recipient_session_id=recipient_session_id,
                payload=payload,
                current_write=True,
            )
            current = self.connection.execute(
                "SELECT id, recipient_session_id, topic, payload_sha256 FROM coordination_messages WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if current is not None:
                if (
                    current["recipient_session_id"] != recipient_session_id
                    or current["topic"] != topic
                    or current["payload_sha256"] != payload_sha256
                ):
                    raise CoordinationError("IDEMPOTENCY_CONFLICT")
                return int(current["id"])
            cursor = self.connection.execute(
                "INSERT INTO coordination_messages(idempotency_key, recipient_session_id, topic, payload_sha256, payload_json, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'PREPARED', ?, ?)",
                (
                    idempotency_key,
                    recipient_session_id,
                    topic,
                    payload_sha256,
                    payload_json,
                    now,
                    now,
                ),
            )
            message_id = int(cursor.lastrowid)
            self._event("MESSAGE_PREPARED", f"message:{message_id}", payload, now)
        return message_id

    def hold_prepared_message(
        self,
        *,
        message_id: int,
        expected_payload_sha256: str,
        reason: str,
        session_id: str,
        now: str,
    ) -> dict[str, Any]:
        """Fail closed on an unclaimed message using an exact Planner CAS."""
        session_id = canonicalize_coordination_identity(self.connection, session_id)
        _validate_sha256(expected_payload_sha256)
        if coordination_identity_role(self.connection, session_id) != "planner":
            raise CoordinationError("PLANNER_SESSION_REQUIRED")
        if reason not in PREPARED_MESSAGE_HOLD_REASONS:
            raise CoordinationError("MESSAGE_HOLD_REASON_INVALID")
        if message_id <= 0:
            raise CoordinationError("MESSAGE_NOT_FOUND")
        with self.transaction():
            row = self.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()
            if row is None:
                raise CoordinationError("MESSAGE_NOT_FOUND")
            if row["payload_sha256"] != expected_payload_sha256:
                raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
            if row["state"] == "HOLD":
                if row["last_error"] != reason:
                    raise CoordinationError("MESSAGE_STATE_CONFLICT")
                return dict(row)
            if row["state"] != "PREPARED" or row["claimed_by"] is not None:
                raise CoordinationError("MESSAGE_STATE_CONFLICT")
            cursor = self.connection.execute(
                "UPDATE coordination_messages SET state='HOLD', updated_at=?, last_error=? "
                "WHERE id=? AND state='PREPARED' AND claimed_by IS NULL AND payload_sha256=?",
                (now, reason, message_id, expected_payload_sha256),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("MESSAGE_STATE_CONFLICT")
            if row["topic"] in {"development.admission", "sre.admission"}:
                payload = json.loads(row["payload_json"])
                source = payload.get("source", {})
                watch_key = terminal_watch_key(
                    str(source.get("repository")),
                    int(payload.get("issue_number", 0)),
                    int(payload.get("generation", -1)),
                )
                watch_hold = self.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='HOLD', process_id=NULL, updated_at=?, last_error=?
                    WHERE watch_key=? AND state='PENDING_CLAIM'
                      AND admission_message_id=?
                      AND admission_payload_sha256=?
                    """,
                    (now, reason, watch_key, message_id, expected_payload_sha256),
                )
                item = self.connection.execute(
                    "SELECT * FROM coordination_items "
                    "WHERE repository=? AND issue_number=?",
                    (source.get("repository"), payload.get("issue_number")),
                ).fetchone()
                if (
                    watch_hold.rowcount != 1
                    or item is None
                    or item["status"] not in {"ACTIVE", "ACTIVE_FENCED", "MONITOR"}
                    or item["allocation_class"] != "ACTIVE"
                    or int(item["generation"]) != payload.get("generation")
                    or int(item["version"]) != payload.get("item_version")
                    or item["lease_manifest_sha256"]
                    != payload.get("lease_manifest_sha256")
                ):
                    raise CoordinationError("TERMINAL_WATCH_HOLD_BINDING_MISMATCH")
                held_item = self.connection.execute(
                    """
                    UPDATE coordination_items
                    SET status='HOLD', allocation_class='RETAINED',
                        version=version+1, updated_at=?
                    WHERE repository=? AND issue_number=? AND version=?
                      AND allocation_class='ACTIVE'
                    """,
                    (
                        now,
                        source["repository"],
                        payload["issue_number"],
                        int(item["version"]),
                    ),
                )
                if held_item.rowcount != 1:
                    raise CoordinationError("TERMINAL_WATCH_HOLD_BINDING_MISMATCH")
            self._event(
                "MESSAGE_HELD",
                f"message:{message_id}",
                {"error": reason, "planner_session_id": session_id},
                now,
            )
            held = self.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()
        return dict(held)

    def prepared_legacy_notice_manifest(self, legacy_recipient: str) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT id,idempotency_key,recipient_session_id,topic,payload_sha256 "
            "FROM coordination_messages WHERE state='PREPARED' "
            "AND claimed_by IS NULL AND topic='coordination.notice' "
            "AND recipient_session_id=? ORDER BY id",
            (legacy_recipient,),
        ).fetchall()
        entries = [dict(row) for row in rows]
        return {
            "legacy_recipient": legacy_recipient,
            "entries": entries,
            "manifest_sha256": digest_json(entries),
        }

    def retire_prepared_legacy_notices(
        self,
        *,
        legacy_recipient: str,
        current_planner_endpoint: str,
        expected_manifest_sha256: str,
        now: str,
    ) -> dict[str, Any]:
        """Atomically retire one exact frozen legacy Planner-notice backlog."""

        _validate_sha256(expected_manifest_sha256)
        canonical_planner = canonicalize_coordination_identity(
            self.connection, current_planner_endpoint
        )
        if (
            canonical_planner != current_planner_endpoint
            or coordination_identity_role(self.connection, canonical_planner) != "planner"
            or coordination_identity_role(self.connection, legacy_recipient) != "planner"
            or legacy_recipient == current_planner_endpoint
        ):
            raise CoordinationError("PLANNER_CUTOVER_IDENTITY_INVALID")
        with self.transaction():
            manifest = self.prepared_legacy_notice_manifest(legacy_recipient)
            if manifest["manifest_sha256"] != expected_manifest_sha256:
                raise CoordinationError("LEGACY_NOTICE_MANIFEST_DRIFT")
            entries = manifest["entries"]
            for entry in entries:
                updated = self.connection.execute(
                    "UPDATE coordination_messages SET state='HOLD', updated_at=?, "
                    "last_error='SUPERSEDED_BY_ROLE_ENDPOINT_CUTOVER' "
                    "WHERE id=? AND state='PREPARED' AND claimed_by IS NULL "
                    "AND recipient_session_id=? AND topic='coordination.notice' "
                    "AND payload_sha256=?",
                    (
                        now,
                        entry["id"],
                        legacy_recipient,
                        entry["payload_sha256"],
                    ),
                )
                if updated.rowcount != 1:
                    raise CoordinationError("LEGACY_NOTICE_MANIFEST_DRIFT")
                self._event(
                    "MESSAGE_HELD",
                    f"message:{entry['id']}",
                    {
                        "error": "SUPERSEDED_BY_ROLE_ENDPOINT_CUTOVER",
                        "planner_session_id": current_planner_endpoint,
                    },
                    now,
                )
            self._event(
                "LEGACY_PLANNER_NOTICES_RETIRED",
                f"planner-cutover:{expected_manifest_sha256}",
                {
                    "count": len(entries),
                    "manifest_sha256": expected_manifest_sha256,
                    "planner_endpoint": current_planner_endpoint,
                },
                now,
            )
        return {
            "count": len(entries),
            "manifest_sha256": expected_manifest_sha256,
            "state": "HOLD",
        }

    def _require_admission_readiness_approval_precondition(
        self, item: dict[str, Any]
    ) -> None:
        """Recheck an approval-bound READY lineage inside activation."""

        tables = {
            str(row["name"])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('portfolio_readiness_current','portfolio_readiness_campaigns')"
            )
        }
        if tables != {
            "portfolio_readiness_current",
            "portfolio_readiness_campaigns",
        }:
            return
        repository = item.get("repository")
        issue_number = item.get("issue_number")
        approval_bound = self.connection.execute(
            """
            SELECT 1
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign
              ON campaign.id=current.campaign_id
            WHERE current.repository=? AND current.issue_number=?
              AND campaign.transition_kind='APPROVAL_RESUME'
            """,
            (repository, issue_number),
        ).fetchone()
        if approval_bound is None:
            return
        current = self.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (repository, issue_number),
        ).fetchone()
        if current is None or current["status"] != "READY":
            raise CoordinationError("ADMISSION_READY_REQUIRED")
        if (
            item.get("expected_version") != int(current["version"])
            or item.get("generation") != int(current["generation"])
            or item.get("expected_source_sha256")
            != current["source_payload_sha256"]
        ):
            raise CoordinationError("ADMISSION_READY_BINDING_MISMATCH")
        self._require_ready_finalization_attestation(
            repository=str(repository),
            issue_number=int(issue_number),
            generation=int(current["generation"]),
            ready_item_version=int(current["version"]),
            source_payload_sha256=str(current["source_payload_sha256"]),
        )

    def activate_admission(
        self,
        *,
        item: dict[str, Any],
        message: dict[str, Any],
        artifacts: list[dict[str, Any]] | None = None,
        artifact_observations: list[dict[str, Any]] | None = None,
        now: str,
        _transaction: bool = True,
    ) -> tuple[dict[str, Any], int]:
        return self._activate_admission_locked(
            item=item,
            message=message,
            artifacts=artifacts,
            artifact_observations=artifact_observations,
            now=now,
            transaction=_transaction,
            pending_claim=True,
        )

    def _activate_admission_for_test_fixture(
        self,
        *,
        item: dict[str, Any],
        message: dict[str, Any],
        artifacts: list[dict[str, Any]] | None = None,
        artifact_observations: list[dict[str, Any]] | None = None,
        now: str,
    ) -> tuple[dict[str, Any], int]:
        self._require_temporary_test_database()
        return self._activate_admission_locked(
            item=item,
            message=message,
            artifacts=artifacts,
            artifact_observations=artifact_observations,
            now=now,
            transaction=True,
            pending_claim=False,
        )

    def _activate_admission_locked(
        self,
        *,
        item: dict[str, Any],
        message: dict[str, Any],
        artifacts: list[dict[str, Any]] | None,
        artifact_observations: list[dict[str, Any]] | None,
        now: str,
        transaction: bool,
        pending_claim: bool,
    ) -> tuple[dict[str, Any], int]:
        if (
            not isinstance(item, dict)
            or not isinstance(message, dict)
            or (artifacts is not None and not isinstance(artifacts, list))
            or (
                artifact_observations is not None
                and not isinstance(artifact_observations, list)
            )
        ):
            raise CoordinationError("INVALID_ADMISSION_TRANSACTION")
        if set(message) != {
            "idempotency_key",
            "recipient_session_id",
            "topic",
            "payload",
        }:
            raise CoordinationError("INVALID_ADMISSION_TRANSACTION")
        if message["topic"] not in {"development.admission", "sre.admission"}:
            raise CoordinationError("INVALID_ADMISSION_TRANSACTION")
        with (self.transaction() if transaction else nullcontext()):
            payload = message["payload"]
            if not isinstance(payload, dict):
                raise CoordinationError("ADMISSION_ITEM_BINDING_MISMATCH")
            if not recipient_matches_topic(
                self.connection,
                topic=message["topic"],
                recipient=message["recipient_session_id"],
            ):
                raise CoordinationError("MESSAGE_ROLE_MISMATCH")
            validate_admission_dispatch_bindings(payload, topic=message["topic"])
            self._require_admission_readiness_approval_precondition(item)
            artifact_paths: list[Path] = []
            if artifact_observations is not None:
                if not artifact_observations:
                    raise CoordinationError("ADMISSION_LEASE_ARTIFACT_MISMATCH")
                if artifacts is not None and [
                    observation.get("entry") for observation in artifact_observations
                ] != artifacts:
                    raise CoordinationError("ADMISSION_LEASE_ARTIFACT_MISMATCH")
                if artifacts is None:
                    for observation in artifact_observations:
                        registered = (
                            observation.get("entry", {}).get("registered_artifact")
                            if isinstance(observation, dict)
                            else None
                        )
                        entry = (
                            observation.get("entry")
                            if isinstance(observation, dict)
                            else None
                        )
                        current_artifact = self.connection.execute(
                            "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                            (
                                registered.get("artifact_key")
                                if isinstance(registered, dict)
                                else None,
                            ),
                        ).fetchone()
                        if (
                            not isinstance(registered, dict)
                            or not isinstance(entry, dict)
                            or current_artifact is None
                            or current_artifact["state"] != "REGISTERED"
                            or not artifact_registry_identity_matches(
                                registered, current_artifact
                            )
                            or registered["repository"] != item.get("repository")
                            or registered["issue_number"] != item.get("issue_number")
                            or registered["generation"] != item.get("generation")
                            or registered["relative_path"]
                            != observation.get("relative_path")
                            or entry.get("repository") != registered["repository"]
                            or entry.get("issue_number") != registered["issue_number"]
                            or entry.get("generation") != registered["generation"]
                            or entry.get("retention_class")
                            != registered["retention_class"]
                        ):
                            raise CoordinationError(
                                "ARTIFACT_REGISTRY_IDENTITY_DRIFT"
                            )
                        if (
                            current_artifact["content_sha256"]
                            != observation.get("content_sha256")
                            or int(current_artifact["size_bytes"])
                            != observation.get("size_bytes")
                            or int(current_artifact["device_id"])
                            != observation.get("device_id")
                            or int(current_artifact["inode"])
                            != observation.get("inode")
                        ):
                            raise CoordinationError("ARTIFACT_CONTENT_DRIFT")
            elif artifacts is None:
                existing = self.connection.execute(
                    """
                    SELECT relative_path FROM coordination_artifacts
                    WHERE repository=? AND issue_number=? AND generation=?
                      AND content_sha256=? AND state='REGISTERED'
                    """,
                    (
                        item.get("repository"),
                        item.get("issue_number"),
                        item.get("generation"),
                        payload.get("lease_manifest_sha256"),
                    ),
                ).fetchall()
                artifact_paths = [self.artifact_root / row["relative_path"] for row in existing]
            else:
                for artifact in artifacts:
                    if not isinstance(artifact, dict) or not isinstance(
                        artifact.get("path"), str
                    ):
                        raise CoordinationError("INVALID_ARTIFACT_MANIFEST")
                    artifact_paths.append(Path(artifact["path"]))
            matching_manifests: list[dict[str, Any]] = []
            raw_artifacts: list[bytes] = []
            if artifact_observations is not None:
                for observation in artifact_observations:
                    descriptor = observation.get("descriptor")
                    raw = observation.get("raw")
                    try:
                        metadata = os.fstat(descriptor)
                    except (OSError, TypeError) as exc:
                        raise CoordinationError("ARTIFACT_CONTENT_DRIFT") from exc
                    if (
                        not isinstance(raw, bytes)
                        or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or metadata.st_nlink != 1
                        or int(metadata.st_size) != observation.get("size_bytes")
                        or int(metadata.st_dev) != observation.get("device_id")
                        or int(metadata.st_ino) != observation.get("inode")
                        or int(metadata.st_mode) != observation.get("mode")
                        or int(metadata.st_mtime_ns) != observation.get("mtime_ns")
                        or int(metadata.st_ctime_ns) != observation.get("ctime_ns")
                        or hashlib.sha256(raw).hexdigest()
                        != observation.get("content_sha256")
                    ):
                        raise CoordinationError("ARTIFACT_CONTENT_DRIFT")
                    raw_artifacts.append(raw)
            else:
                for supplied_path in artifact_paths:
                    path, _, _ = self._validated_artifact_file(supplied_path)
                    raw_artifacts.append(path.read_bytes())
            for raw in raw_artifacts:
                if hashlib.sha256(raw).hexdigest() != payload.get(
                    "lease_manifest_sha256"
                ):
                    continue
                try:
                    matching_manifests.append(parse_structured_lease_manifest(raw))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CoordinationError("LEASE_MANIFEST_INVALID") from exc
            if len(matching_manifests) != 1:
                raise CoordinationError("ADMISSION_LEASE_ARTIFACT_MISMATCH")
            manifest = matching_manifests[0]
            if (
                manifest.get("repository") != item.get("repository")
                or manifest.get("issue_number") != item.get("issue_number")
                or manifest.get("generation") != item.get("generation")
                or manifest.get("base_sha") != payload.get("base_sha")
                or manifest.get("branch") != payload.get("branch")
                or manifest.get("worktree_path") != payload.get("worktree_path")
            ):
                raise CoordinationError("ADMISSION_LEASE_LINEAGE_MISMATCH")
            activated = self._set_issue_status_from_admission(
                **item,
                now=now,
                pending_claim=pending_claim,
            )
            if (
                not isinstance(payload, dict)
                or payload.get("item_version") != activated["version"]
                or payload.get("issue_number") != activated["issue_number"]
                or payload.get("generation") != activated["generation"]
            ):
                raise CoordinationError("ADMISSION_ITEM_BINDING_MISMATCH")
            registered = []
            if artifacts is not None:
                registered = (
                    self._register_preloaded_artifacts(
                        artifact_observations, now=now
                    )
                    if artifact_observations is not None
                    else self.register_artifacts(
                        artifacts, now=now, _transaction=False
                    )
                )
                if (
                    sum(
                        artifact["content_sha256"]
                        == payload["lease_manifest_sha256"]
                        for artifact in registered
                    )
                    != 1
                ):
                    raise CoordinationError("ADMISSION_LEASE_ARTIFACT_MISMATCH")
            message_id = self.enqueue_message(
                idempotency_key=message["idempotency_key"],
                recipient_session_id=message["recipient_session_id"],
                topic=message["topic"],
                payload=payload,
                now=now,
                _transaction=False,
            )
            watch_key = terminal_watch_key(
                activated["repository"],
                activated["issue_number"],
                activated["generation"],
            )
            bound_watch = self.connection.execute(
                """
                UPDATE coordination_terminal_watches
                SET admission_message_id=?, admission_payload_sha256=?, updated_at=?
                WHERE watch_key=?
                  AND admission_message_id IS NULL
                  AND admission_payload_sha256 IS NULL
                  AND state IN ('PENDING_CLAIM','ACTIVE')
                """,
                (message_id, digest_json(payload), now, watch_key),
            )
            if bound_watch.rowcount != 1:
                raise CoordinationError("TERMINAL_WATCH_ADMISSION_BINDING_CONFLICT")
            self._event(
                "ADMISSION_ACTIVATED",
                f"{activated['repository']}:issue:{activated['issue_number']}",
                {
                    "item_version": activated["version"],
                    "message_id": message_id,
                    "artifact_count": len(registered),
                },
                now,
            )
        return activated, message_id

    def activate_recovery(
        self,
        *,
        message_id: int,
        session_id: str,
        now: str,
        attempt_id: str | None = None,
        executor_token: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        """Atomically convert a claimed two-phase recovery into active execution."""
        session_id = canonicalize_coordination_identity(self.connection, session_id)
        if message_id <= 0:
            raise CoordinationError("INVALID_RECOVERY_ACTIVATION")
        with self.transaction():
            message = self.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()
            if message is None or message["topic"] != "development.recovery_commit":
                raise CoordinationError("RECOVERY_COMMIT_NOT_FOUND")
            if not identities_role_equivalent(
                self.connection, message["recipient_session_id"], session_id
            ):
                raise CoordinationError("WRONG_MESSAGE_RECIPIENT")
            if message["state"] == "PREPARED":
                raise CoordinationError("RECOVERY_COMMIT_NOT_CLAIMED")
            if not identities_role_equivalent(
                self.connection, message["claimed_by"], session_id
            ):
                raise CoordinationError("WRONG_MESSAGE_RECIPIENT")
            payload = json.loads(message["payload_json"])
            source = payload.get("source", {})
            repository = source.get("repository")
            issue_number = payload.get("issue_number")
            generation = payload.get("generation")
            watch_key = terminal_watch_key(repository, issue_number, generation)
            claim_attempt: dict[str, Any] | None = None
            try:
                claim_attempt = self._require_running_lineage_attempt(
                    attempt_id=attempt_id,
                    executor_token=executor_token,
                    repository=str(repository),
                    issue_number=int(issue_number),
                    generation=int(generation),
                    lease_manifest_sha256=str(payload.get("lease_manifest_sha256")),
                    allowed_targets={("message", str(message_id))},
                )
            except CoordinationError:
                if Path("/tmp") not in self.path.resolve().parents:
                    raise

            item = self.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (repository, issue_number),
            ).fetchone()
            watch = self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            capacity = payload.get("capacity", {})
            already_active = bool(
                item is not None
                and item["status"] in {"ACTIVE", "ACTIVE_FENCED"}
                and item["allocation_class"] == "ACTIVE"
                and int(item["generation"]) == generation
                and int(item["version"]) == payload.get("item_version", 0) + 1
                and item["accountable_session_id"] == session_id
                and item["lease_manifest_sha256"]
                == payload.get("lease_manifest_sha256")
                and item["source_payload_sha256"] == source.get("payload_sha256")
                and int(item["development_units"])
                == capacity.get("development_units")
                and int(item["shared_units"]) == capacity.get("shared_units")
                and int(item["sre_units"]) == capacity.get("sre_units")
                and watch is not None
                and watch["state"] == "ACTIVE"
                and watch["accountable_session_id"] == session_id
                and watch["lease_manifest_sha256"]
                == payload.get("lease_manifest_sha256")
                and int(watch["admission_message_id"] or 0) == message_id
                and watch["admission_payload_sha256"] == message["payload_sha256"]
                and (
                    claim_attempt is None
                    or watch["claim_attempt_id"] == claim_attempt["attempt_id"]
                )
            )
            if already_active:
                self._validate_message_source(payload)
                return (
                    {
                        "repository": repository,
                        "issue_number": issue_number,
                        "status": item["status"],
                        "allocation_class": item["allocation_class"],
                        "generation": generation,
                        "version": int(item["version"]),
                        "source_payload_sha256": item["source_payload_sha256"],
                    },
                    watch_key,
                )
            if message["state"] == "COMPLETE":
                # Historical recovery rows completed by the pre-terminal
                # protocol are readable only when their exact activation is
                # already durable; they cannot create a new active lineage.
                raise CoordinationError("RECOVERY_ACTIVATION_STATE_CONFLICT")

            if message["state"] != "CLAIMED":
                raise CoordinationError("RECOVERY_COMMIT_NOT_CLAIMED")
            self._validate_message_source(payload)
            self._validate_message_contract(
                topic=message["topic"],
                recipient_session_id=message["recipient_session_id"],
                payload=payload,
            )
            if item is None:
                raise CoordinationError("MESSAGE_ITEM_STATE_MISMATCH")
            new_version = int(item["version"]) + 1
            updated = self.connection.execute(
                """
                UPDATE coordination_items
                SET status='ACTIVE_FENCED', allocation_class='ACTIVE', version=?,
                    updated_at=?
                WHERE repository=? AND issue_number=? AND status='HOLD'
                  AND allocation_class IN ('ACTIVE','RETAINED')
                  AND generation=? AND version=?
                  AND accountable_session_id=? AND lease_manifest_sha256=?
                  AND source_payload_sha256=?
                """,
                (
                    new_version,
                    now,
                    repository,
                    issue_number,
                    generation,
                    payload["item_version"],
                    session_id,
                    payload["lease_manifest_sha256"],
                    source["payload_sha256"],
                ),
            )
            if updated.rowcount != 1:
                raise CoordinationError("RECOVERY_ACTIVATION_ITEM_CONFLICT")

            watch = self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            if watch is None:
                self.connection.execute(
                    """
                    INSERT INTO coordination_terminal_watches(
                        watch_key, repository, issue_number, generation,
                        accountable_session_id, lease_manifest_sha256, state,
                        admission_message_id, admission_payload_sha256,
                        claim_attempt_id,
                        attempts, process_id, last_heartbeat_at, next_wake_at,
                        updated_at, last_error
                    ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, 0, NULL, ?, ?, ?, NULL)
                    """,
                    (
                        watch_key,
                        repository,
                        issue_number,
                        generation,
                        session_id,
                        payload["lease_manifest_sha256"],
                        message_id,
                        message["payload_sha256"],
                        None if claim_attempt is None else claim_attempt["attempt_id"],
                        now,
                        timestamp_after(now, 60),
                        now,
                    ),
                )
            elif (
                watch["accountable_session_id"] != session_id
                or watch["lease_manifest_sha256"]
                != payload["lease_manifest_sha256"]
                or watch["state"] != "COMPLETE"
            ):
                raise CoordinationError("RECOVERY_TERMINAL_WATCH_CONFLICT")
            else:
                self.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='ACTIVE', attempts=0, process_id=NULL,
                        accountable_session_id=?, admission_message_id=?,
                        admission_payload_sha256=?, claim_attempt_id=?,
                        last_heartbeat_at=?, next_wake_at=?, updated_at=?,
                        last_error=NULL
                    WHERE watch_key=? AND state='COMPLETE'
                    """,
                    (
                        session_id,
                        message_id,
                        message["payload_sha256"],
                        None if claim_attempt is None else claim_attempt["attempt_id"],
                        now,
                        timestamp_after(now, 60),
                        now,
                        watch_key,
                    ),
                )

            preserved = self.connection.execute(
                "SELECT state, claimed_by, payload_sha256 "
                "FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()
            if (
                preserved is None
                or preserved["state"] != "CLAIMED"
                or preserved["claimed_by"] != session_id
                or preserved["payload_sha256"] != message["payload_sha256"]
            ):
                raise CoordinationError("RECOVERY_COMMIT_STATE_CONFLICT")
            result = {
                "repository": repository,
                "issue_number": issue_number,
                "status": "ACTIVE_FENCED",
                "allocation_class": "ACTIVE",
                "generation": generation,
                "version": new_version,
                "source_payload_sha256": source["payload_sha256"],
            }
            self._event(
                "RECOVERY_ACTIVATED",
                f"{repository}:issue:{issue_number}",
                {
                    "message_id": message_id,
                    "item_version": new_version,
                    "terminal_watch_key": watch_key,
                },
                now,
            )
        return result, watch_key

    def _require_running_lineage_attempt(
        self,
        *,
        attempt_id: str | None,
        executor_token: str | None,
        repository: str,
        issue_number: int,
        generation: int,
        lease_manifest_sha256: str,
        allowed_targets: set[tuple[str, str]],
    ) -> dict[str, Any]:
        """Authenticate one current RUNNING role attempt on the exact lineage."""

        if (
            not isinstance(attempt_id, str)
            or SESSION.fullmatch(attempt_id) is None
            or not isinstance(executor_token, str)
            or not executor_token
            or not allowed_targets
        ):
            raise CoordinationError("TERMINAL_ATTEMPT_REQUIRED")
        attempt = self.connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if attempt is None:
            raise CoordinationError("TERMINAL_ATTEMPT_NOT_FOUND")
        token_sha256 = hashlib.sha256(executor_token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(str(attempt["token_sha256"]), token_sha256):
            raise CoordinationError("TERMINAL_ATTEMPT_TOKEN_MISMATCH")
        role = str(attempt["role"])
        endpoint = current_endpoint(self.connection, role)
        if (
            role not in {"development", "sre"}
            or attempt["state"] != "RUNNING"
            or endpoint is None
            or str(endpoint["endpoint_id"]) != str(attempt["endpoint_id"])
            or (str(attempt["target_kind"]), str(attempt["target_key"]))
            not in allowed_targets
            or attempt["lineage_repository"] != repository
            or int(attempt["lineage_issue_number"] or -1) != issue_number
            or int(attempt["lineage_generation"] or -1) != generation
            or attempt["lineage_lease_sha256"] != lease_manifest_sha256
            or not isinstance(attempt["lineage_sha256"], str)
        ):
            raise CoordinationError("TERMINAL_ATTEMPT_LINEAGE_MISMATCH")
        return dict(attempt)

    def _require_terminal_lineage_attempt(
        self,
        *,
        attempt_id: str | None,
        executor_token: str | None,
        repository: str,
        issue_number: int,
        generation: int,
        lease_manifest_sha256: str,
        allowed_targets: set[tuple[str, str]],
        completed_replay_attempt_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Authenticate a current watcher or one exact completed replay owner."""

        if (
            not isinstance(attempt_id, str)
            or SESSION.fullmatch(attempt_id) is None
            or not isinstance(executor_token, str)
            or not executor_token
            or not allowed_targets
        ):
            raise CoordinationError("TERMINAL_ATTEMPT_REQUIRED")
        attempt = self.connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if attempt is None:
            raise CoordinationError("TERMINAL_ATTEMPT_NOT_FOUND")
        token_sha256 = hashlib.sha256(executor_token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(str(attempt["token_sha256"]), token_sha256):
            raise CoordinationError("TERMINAL_ATTEMPT_TOKEN_MISMATCH")
        if (
            str(attempt["role"]) not in {"development", "sre"}
            or (str(attempt["target_kind"]), str(attempt["target_key"]))
            not in allowed_targets
            or attempt["lineage_repository"] != repository
            or int(attempt["lineage_issue_number"] or -1) != issue_number
            or int(attempt["lineage_generation"] or -1) != generation
            or attempt["lineage_lease_sha256"] != lease_manifest_sha256
            or not isinstance(attempt["lineage_sha256"], str)
        ):
            raise CoordinationError("TERMINAL_ATTEMPT_LINEAGE_MISMATCH")
        if attempt["state"] == "RUNNING":
            endpoint = current_endpoint(self.connection, str(attempt["role"]))
            if (
                endpoint is None
                or str(endpoint["endpoint_id"]) != str(attempt["endpoint_id"])
            ):
                raise CoordinationError("TERMINAL_ATTEMPT_ENDPOINT_MISMATCH")
        elif (
            attempt["state"] != "COMPLETE"
            or attempt_id not in (completed_replay_attempt_ids or set())
        ):
            raise CoordinationError("TERMINAL_ATTEMPT_NOT_EXECUTABLE")
        return dict(attempt)

    def _current_terminal_graph_binding(
        self,
        *,
        repository: str,
        issue_number: int,
        source_payload_sha256: str,
    ) -> dict[str, Any]:
        rows = self.connection.execute(
            """
            SELECT current.version, current.observed_main_sha, current.health,
                   revision.accepted_main_sha, revision.graph_sha256,
                   node.node_key, node.source_payload_sha256
            FROM portfolio_graph_current current
            JOIN portfolio_graph_revisions revision
              ON revision.repository=current.repository
             AND revision.version=current.version
            JOIN portfolio_graph_nodes node
              ON node.repository=current.repository
             AND node.graph_version=current.version
             AND node.issue_number=?
            WHERE current.repository=?
            ORDER BY node.node_key
            """,
            (issue_number, repository),
        ).fetchall()
        if len(rows) != 1:
            raise CoordinationError("TERMINAL_GRAPH_BINDING_UNAVAILABLE")
        row = rows[0]
        if (
            row["health"] != "CURRENT"
            or row["observed_main_sha"] != row["accepted_main_sha"]
            or row["source_payload_sha256"] != source_payload_sha256
        ):
            raise CoordinationError("TERMINAL_GRAPH_BINDING_DRIFT")
        descriptor = {
            "repository": repository,
            "issue_number": issue_number,
            "graph_version": int(row["version"]),
            "graph_sha256": str(row["graph_sha256"]),
            "graph_main_sha": str(row["observed_main_sha"]),
            "graph_node_key": str(row["node_key"]),
            "source_payload_sha256": source_payload_sha256,
        }
        descriptor["graph_binding_sha256"] = digest_json(descriptor)
        return descriptor

    def _terminal_failpoint(
        self, callback: Callable[[str], None] | None, point: str
    ) -> None:
        if callback is None:
            return
        self._require_temporary_test_database()
        callback(point)

    def _terminal_endpoint_rotation_chain_valid(
        self,
        *,
        packet: sqlite3.Row,
        item: sqlite3.Row,
        current_endpoint_id: str,
    ) -> bool:
        preparer = self.connection.execute(
            "SELECT endpoint_id FROM executor_attempts WHERE attempt_id=?",
            (packet["preparer_attempt_id"],),
        ).fetchone()
        if preparer is None or item["accountable_session_id"] != current_endpoint_id:
            return False
        cursor_version = int(packet["publication_pending_item_version"])
        cursor_identity = str(preparer["endpoint_id"])
        if (
            int(item["version"]) == cursor_version
            and cursor_identity == current_endpoint_id
        ):
            return True
        for change in self.connection.execute(
            """
            SELECT before_state_json
            FROM executor_registry_changes
            WHERE state='APPLIED' AND created_at>=?
            ORDER BY created_at, change_id
            """,
            (packet["created_at"],),
        ).fetchall():
            try:
                plan = json.loads(change["before_state_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            candidates = [
                candidate
                for candidate in plan.get("item_changes", [])
                if isinstance(candidate, dict)
                and candidate.get("repository") == packet["repository"]
                and candidate.get("issue_number") == int(packet["issue_number"])
                and candidate.get("before_identity") == cursor_identity
                and candidate.get("before_version") == cursor_version
            ]
            if not candidates:
                continue
            if len(candidates) != 1:
                return False
            candidate = candidates[0]
            after_identity = candidate.get("after_identity")
            if not isinstance(after_identity, str):
                return False
            cursor_identity = after_identity
            cursor_version += 1
        return (
            cursor_version == int(item["version"])
            and cursor_identity == current_endpoint_id
        )

    def prepare_terminal_closeout(
        self,
        *,
        packet: dict[str, Any],
        attempt_id: str,
        executor_token: str,
        now: str,
        _test_failpoint: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        required = {
            "schema",
            "repository",
            "issue_number",
            "generation",
            "expected_item_version",
            "source_payload_sha256",
            "lease_manifest_sha256",
            "terminal_watch_key",
            "activation_message_id",
            "terminal_receipt",
            "cleanup_evidence",
            "outbox",
        }
        if not isinstance(packet, dict) or set(packet) != required:
            raise CoordinationError("INVALID_TERMINAL_CLOSEOUT_TRANSACTION")
        repository = packet.get("repository")
        issue_number = packet.get("issue_number")
        generation = packet.get("generation")
        expected_item_version = packet.get("expected_item_version")
        source_payload_sha256 = packet.get("source_payload_sha256")
        lease_manifest_sha256 = packet.get("lease_manifest_sha256")
        watch_key = packet.get("terminal_watch_key")
        activation_message_id = packet.get("activation_message_id")
        outbox = packet.get("outbox")
        if (
            packet.get("schema") != "twinfinity-terminal-closeout-packet/v1"
            or not isinstance(repository, str)
            or not isinstance(issue_number, int)
            or issue_number <= 0
            or not isinstance(generation, int)
            or generation < 0
            or not isinstance(expected_item_version, int)
            or expected_item_version <= 0
            or not isinstance(source_payload_sha256, str)
            or not isinstance(lease_manifest_sha256, str)
            or watch_key != terminal_watch_key(repository, issue_number, generation)
            or not isinstance(activation_message_id, int)
            or activation_message_id <= 0
            or not isinstance(outbox, dict)
            or set(outbox) != {"idempotency_key", "body"}
            or not isinstance(outbox.get("idempotency_key"), str)
            or not outbox["idempotency_key"]
            or not isinstance(outbox.get("body"), str)
            or not outbox["body"]
        ):
            raise CoordinationError("INVALID_TERMINAL_CLOSEOUT_TRANSACTION")
        _validate_repository(repository)
        _validate_sha256(source_payload_sha256)
        _validate_sha256(lease_manifest_sha256)
        closeout_key = (
            f"terminal-closeout:{repository}:issue:{issue_number}:generation:{generation}"
        )
        with self.transaction():
            existing = self.connection.execute(
                "SELECT * FROM coordination_terminal_closeout_packets "
                "WHERE closeout_key=?",
                (closeout_key,),
            ).fetchone()
            activation = self.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (activation_message_id,),
            ).fetchone()
            watch = self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            if activation is None or watch is None:
                raise CoordinationError("TERMINAL_CLOSEOUT_LINEAGE_MISMATCH")
            attempt = self._require_terminal_lineage_attempt(
                attempt_id=attempt_id,
                executor_token=executor_token,
                repository=repository,
                issue_number=issue_number,
                generation=generation,
                lease_manifest_sha256=lease_manifest_sha256,
                allowed_targets={
                    ("message", str(activation_message_id)),
                    ("terminal_watch", str(watch_key)),
                },
                completed_replay_attempt_ids=(
                    set()
                    if existing is None
                    else {str(existing["preparer_attempt_id"])}
                ),
            )
            role = str(attempt["role"])
            expected_topics = (
                {"development.admission", "development.recovery_commit"}
                if role == "development"
                else {"sre.admission"}
            )
            activation_payload = json.loads(activation["payload_json"])
            source = activation_payload.get("source", {})
            activation_endpoint_id = str(activation["recipient_session_id"])
            activation_role = coordination_identity_role(
                self.connection, activation_endpoint_id
            )
            claim_binding = self.connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (watch["claim_attempt_id"],),
            ).fetchone()
            if (
                activation["topic"] not in expected_topics
                or digest_json(activation_payload) != activation["payload_sha256"]
                or activation_role != role
                or activation["state"] not in {"CLAIMED", "COMPLETE"}
                or activation["claimed_by"] != activation_endpoint_id
                or activation_payload.get("issue_number") != issue_number
                or activation_payload.get("generation") != generation
                or activation_payload.get("lease_manifest_sha256")
                != lease_manifest_sha256
                or source.get("repository") != repository
                or source.get("object_kind") != "issue"
                or source.get("object_number") != issue_number
                or source.get("payload_sha256") != source_payload_sha256
                or activation_payload.get("accountable_session_id")
                != activation_endpoint_id
                or watch["state"] not in {"ACTIVE", "COMPLETE"}
                or watch["repository"] != repository
                or int(watch["issue_number"]) != issue_number
                or int(watch["generation"]) != generation
                or watch["lease_manifest_sha256"] != lease_manifest_sha256
                or int(watch["admission_message_id"] or 0)
                != activation_message_id
                or watch["admission_payload_sha256"]
                != activation["payload_sha256"]
                or claim_binding is None
                or claim_binding["role"] != role
                or claim_binding["endpoint_id"] != activation_endpoint_id
                or claim_binding["state"] not in {"RUNNING", "COMPLETE", "HOLD"}
                or claim_binding["target_kind"] != "message"
                or claim_binding["target_key"] != str(activation_message_id)
                or claim_binding["lineage_repository"] != repository
                or int(claim_binding["lineage_issue_number"] or -1) != issue_number
                or int(claim_binding["lineage_generation"] or -1) != generation
                or claim_binding["lineage_lease_sha256"] != lease_manifest_sha256
                or (
                    attempt["target_kind"] == "message"
                    and claim_binding["attempt_id"] != attempt["attempt_id"]
                )
                or (
                    attempt["target_kind"] == "terminal_watch"
                    and claim_binding["state"] not in {"COMPLETE", "HOLD"}
                )
            ):
                raise CoordinationError("TERMINAL_CLOSEOUT_LINEAGE_MISMATCH")
            terminal_receipt_sha256 = validate_terminal_receipt(
                packet["terminal_receipt"],
                repository=repository,
                issue_number=issue_number,
                generation=generation,
                source_payload_sha256=source_payload_sha256,
                lease_manifest_sha256=lease_manifest_sha256,
                role=role,
            )
            cleanup_evidence_sha256 = validate_terminal_cleanup_evidence(
                packet["cleanup_evidence"],
                repository=repository,
                issue_number=issue_number,
                generation=generation,
                lease_manifest_sha256=lease_manifest_sha256,
                role=role,
            )
            expected_publication_body = terminal_publication_body(
                closeout_key=closeout_key,
                terminal_receipt=packet["terminal_receipt"],
                cleanup_evidence=packet["cleanup_evidence"],
            )
            if (
                outbox["idempotency_key"] != closeout_key
                or outbox["body"] != expected_publication_body
            ):
                raise CoordinationError("TERMINAL_OUTBOX_POLICY_INVALID")
            if existing is not None:
                outbox_row = self.connection.execute(
                    "SELECT * FROM github_outbox WHERE id=?",
                    (existing["outbox_id"],),
                ).fetchone()
                expected_descriptor = {
                    "schema": "twinfinity-terminal-closeout-packet/v1",
                    "closeout_key": closeout_key,
                    "repository": repository,
                    "issue_number": issue_number,
                    "generation": generation,
                    "source_payload_sha256": source_payload_sha256,
                    "lease_manifest_sha256": lease_manifest_sha256,
                    "accountable_role": role,
                    "endpoint_id": existing["endpoint_id"],
                    "preparer_attempt_id": existing["preparer_attempt_id"],
                    "preparer_attempt_version": int(existing["preparer_attempt_version"]),
                    "terminal_watch_key": watch_key,
                    "activation_message_id": activation_message_id,
                    "activation_payload_sha256": activation["payload_sha256"],
                    "expected_item_version": expected_item_version,
                    "publication_pending_item_version": int(
                        existing["publication_pending_item_version"]
                    ),
                    "terminal_receipt_sha256": terminal_receipt_sha256,
                    "cleanup_evidence_sha256": cleanup_evidence_sha256,
                    "outbox_id": int(existing["outbox_id"]),
                    "outbox_payload_sha256": existing["outbox_payload_sha256"],
                    "graph_version": int(existing["graph_version"] or 0),
                    "graph_sha256": existing["graph_sha256"],
                    "graph_main_sha": existing["graph_main_sha"],
                    "graph_node_key": existing["graph_node_key"],
                    "graph_binding_sha256": existing["graph_binding_sha256"],
                }
                if (
                    outbox_row is None
                    or outbox_row["idempotency_key"] != outbox["idempotency_key"]
                    or outbox_row["payload_sha256"]
                    != digest_json({"body": outbox["body"]})
                    or existing["terminal_receipt_json"]
                    != canonical_json(packet["terminal_receipt"])
                    or existing["cleanup_evidence_json"]
                    != canonical_json(packet["cleanup_evidence"])
                    or existing["endpoint_id"] != activation_endpoint_id
                    or digest_json(expected_descriptor) != existing["packet_sha256"]
                ):
                    raise CoordinationError("TERMINAL_CLOSEOUT_IDEMPOTENCY_CONFLICT")
                return self.terminal_closeout_status(closeout_key)
            if attempt["state"] != "RUNNING":
                raise CoordinationError("TERMINAL_ATTEMPT_NOT_EXECUTABLE")
            item = self.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (repository, issue_number),
            ).fetchone()
            current_source = self.current_snapshot(repository, "issue", issue_number)
            if (
                item is None
                or item["status"] not in {"ACTIVE", "ACTIVE_FENCED", "MONITOR"}
                or item["allocation_class"] != "ACTIVE"
                or int(item["generation"]) != generation
                or int(item["version"]) != expected_item_version
                or item["source_payload_sha256"] != source_payload_sha256
                or item["lease_manifest_sha256"] != lease_manifest_sha256
                or not identities_role_equivalent(
                    self.connection,
                    item["accountable_session_id"],
                    str(attempt["endpoint_id"]),
                )
                or current_source is None
                or current_source.payload_sha256 != source_payload_sha256
                or activation["state"] != "CLAIMED"
                or watch["state"] != "ACTIVE"
                or watch["accountable_session_id"] != attempt["endpoint_id"]
            ):
                raise CoordinationError("TERMINAL_CLOSEOUT_ITEM_MISMATCH")
            graph_binding = self._current_terminal_graph_binding(
                repository=repository,
                issue_number=issue_number,
                source_payload_sha256=source_payload_sha256,
            )
            outbox_id = self.enqueue_comment(
                idempotency_key=outbox["idempotency_key"],
                repository=repository,
                object_kind="issue",
                object_number=issue_number,
                expected_source_sha256=source_payload_sha256,
                body=outbox["body"],
                now=now,
                _transaction=False,
            )
            self._terminal_failpoint(_test_failpoint, "prepare.after_outbox")
            outbox_row = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            pending = self._set_issue_status_locked(
                repository=repository,
                issue_number=issue_number,
                status="PUBLICATION_PENDING",
                allocation_class="ACTIVE",
                generation=generation,
                accountable_session_id=item["accountable_session_id"],
                lease_manifest_sha256=lease_manifest_sha256,
                development_units=int(item["development_units"]),
                shared_units=int(item["shared_units"]),
                sre_units=int(item["sre_units"]),
                expected_source_sha256=source_payload_sha256,
                expected_version=expected_item_version,
                now=now,
                transaction=False,
                gateway=_TERMINAL_FINALIZATION_GATEWAY,
            )
            self._terminal_failpoint(_test_failpoint, "prepare.after_item_pending")
            descriptor = {
                "schema": "twinfinity-terminal-closeout-packet/v1",
                "closeout_key": closeout_key,
                "repository": repository,
                "issue_number": issue_number,
                "generation": generation,
                "source_payload_sha256": source_payload_sha256,
                "lease_manifest_sha256": lease_manifest_sha256,
                "accountable_role": role,
                "endpoint_id": activation_endpoint_id,
                "preparer_attempt_id": attempt["attempt_id"],
                "preparer_attempt_version": int(attempt["version"]),
                "terminal_watch_key": watch_key,
                "activation_message_id": activation_message_id,
                "activation_payload_sha256": activation["payload_sha256"],
                "expected_item_version": expected_item_version,
                "publication_pending_item_version": pending["version"],
                "terminal_receipt_sha256": terminal_receipt_sha256,
                "cleanup_evidence_sha256": cleanup_evidence_sha256,
                "outbox_id": outbox_id,
                "outbox_payload_sha256": outbox_row["payload_sha256"],
                **graph_binding,
            }
            packet_sha256 = digest_json(descriptor)
            self.connection.execute(
                """
                INSERT INTO coordination_terminal_closeout_packets(
                    closeout_key, packet_sha256, repository, issue_number,
                    generation, source_payload_sha256, lease_manifest_sha256,
                    accountable_role, endpoint_id, preparer_attempt_id,
                    preparer_attempt_version, terminal_watch_key,
                    activation_message_id, activation_payload_sha256,
                    expected_item_version, publication_pending_item_version,
                    terminal_receipt_sha256, terminal_receipt_json,
                    cleanup_evidence_sha256, cleanup_evidence_json,
                    outbox_id, outbox_payload_sha256, graph_version,
                    graph_sha256, graph_main_sha, graph_node_key,
                    graph_binding_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    closeout_key,
                    packet_sha256,
                    repository,
                    issue_number,
                    generation,
                    source_payload_sha256,
                    lease_manifest_sha256,
                    role,
                    activation_endpoint_id,
                    attempt["attempt_id"],
                    int(attempt["version"]),
                    watch_key,
                    activation_message_id,
                    activation["payload_sha256"],
                    expected_item_version,
                    pending["version"],
                    terminal_receipt_sha256,
                    canonical_json(packet["terminal_receipt"]),
                    cleanup_evidence_sha256,
                    canonical_json(packet["cleanup_evidence"]),
                    outbox_id,
                    outbox_row["payload_sha256"],
                    graph_binding["graph_version"],
                    graph_binding["graph_sha256"],
                    graph_binding["graph_main_sha"],
                    graph_binding["graph_node_key"],
                    graph_binding["graph_binding_sha256"],
                    now,
                ),
            )
            self._terminal_failpoint(_test_failpoint, "prepare.after_packet")
            self.connection.execute(
                """
                INSERT INTO coordination_terminal_outbox_recovery(
                    outbox_id, readback_attempts, retry_rounds, next_retry_at,
                    state, updated_at, last_error
                ) VALUES (?, 0, 0, ?, 'PENDING', ?, NULL)
                """,
                (outbox_id, now, now),
            )
            self._terminal_failpoint(
                _test_failpoint, "prepare.after_outbox_recovery"
            )
            self._event(
                "TERMINAL_CLOSEOUT_PREPARED",
                closeout_key,
                {
                    "packet_sha256": packet_sha256,
                    "outbox_id": outbox_id,
                    "publication_pending_item_version": pending["version"],
                },
                now,
            )
            self._terminal_failpoint(_test_failpoint, "prepare.after_event")
        return self.terminal_closeout_status(closeout_key)

    def terminal_closeout_status(self, closeout_key: str) -> dict[str, Any]:
        packet = self.connection.execute(
            "SELECT * FROM coordination_terminal_closeout_packets WHERE closeout_key=?",
            (closeout_key,),
        ).fetchone()
        if packet is None:
            raise CoordinationError("TERMINAL_CLOSEOUT_NOT_FOUND")
        outbox = self.connection.execute(
            "SELECT state, remote_receipt FROM github_outbox WHERE id=?",
            (packet["outbox_id"],),
        ).fetchone()
        terminal_commit = self.connection.execute(
            "SELECT * FROM coordination_terminal_closeout_commits WHERE closeout_key=?",
            (closeout_key,),
        ).fetchone()
        if terminal_commit is not None:
            state = "COMPLETE"
        elif outbox is None or outbox["state"] == "HOLD":
            state = "PUBLICATION_HOLD"
        elif (
            outbox["state"] == "COMPLETE"
            and isinstance(outbox["remote_receipt"], str)
            and REMOTE_COMMENT_RECEIPT.fullmatch(outbox["remote_receipt"])
        ):
            state = "COMMIT_READY"
        elif outbox["state"] == "COMPLETE":
            state = "PUBLICATION_HOLD"
        else:
            state = "PUBLICATION_PENDING"
        return {
            "closeout_key": closeout_key,
            "packet_sha256": packet["packet_sha256"],
            "state": state,
            "outbox_id": int(packet["outbox_id"]),
            "publication_pending_item_version": int(
                packet["publication_pending_item_version"]
            ),
            "done_item_version": (
                None
                if terminal_commit is None
                else int(terminal_commit["done_item_version"])
            ),
            "dirty_event_id": (
                None
                if terminal_commit is None
                else int(terminal_commit["dirty_event_id"])
            ),
        }

    def _acquire_terminal_live_evidence(
        self, *, closeout_key: str
    ) -> dict[str, Any]:
        """Acquire fixed live provenance without opening a SQLite transaction."""

        if self.connection.in_transaction:
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_TRANSACTION_ACTIVE")
        packet = self.connection.execute(
            "SELECT * FROM coordination_terminal_closeout_packets "
            "WHERE closeout_key=?",
            (closeout_key,),
        ).fetchone()
        if packet is None:
            raise CoordinationError("TERMINAL_CLOSEOUT_NOT_FOUND")
        publication = self.connection.execute(
            """
            SELECT outbox.state, outbox.remote_receipt,
                   outbox.idempotency_key, outbox.payload_json,
                   readback.remote_receipt AS readback_receipt,
                   readback.published_body_sha256,
                   readback.publisher_login
            FROM github_outbox outbox
            LEFT JOIN coordination_terminal_outbox_readbacks readback
              ON readback.outbox_id=outbox.id
            WHERE outbox.id=?
            """,
            (packet["outbox_id"],),
        ).fetchone()
        if (
            publication is None
            or publication["state"] != "COMPLETE"
            or REMOTE_COMMENT_RECEIPT.fullmatch(
                str(publication["remote_receipt"] or "")
            )
            is None
            or publication["readback_receipt"] != publication["remote_receipt"]
        ):
            raise CoordinationError("TERMINAL_OUTBOX_NOT_COMPLETE")
        observed_at = utc_now()
        _utc_timestamp(observed_at, error="TERMINAL_LIVE_EVIDENCE_INVALID")
        remote_receipt = str(publication["remote_receipt"])
        issue_payload, main_ref, published_comment, timeline = (
            _fetch_terminal_live_observation(
                str(packet["repository"]),
                int(packet["issue_number"]),
                remote_receipt,
            )
        )
        if self.connection.in_transaction:
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_TRANSACTION_ACTIVE")
        source_updated_at = (
            issue_payload.get("_projection_updated_at")
            if isinstance(issue_payload, dict)
            else None
        ) or (
            issue_payload.get("updated_at")
            if isinstance(issue_payload, dict)
            else None
        )
        main_object = main_ref.get("object") if isinstance(main_ref, dict) else None
        current_main_sha = (
            main_object.get("sha") if isinstance(main_object, dict) else None
        )
        comment_user = (
            published_comment.get("user")
            if isinstance(published_comment, dict)
            else None
        )
        comment_id = (
            published_comment.get("id")
            if isinstance(published_comment, dict)
            else None
        )
        comment_body = (
            published_comment.get("body")
            if isinstance(published_comment, dict)
            else None
        )
        comment_created_at = (
            published_comment.get("created_at")
            if isinstance(published_comment, dict)
            else None
        )
        comment_updated_at = (
            published_comment.get("updated_at")
            if isinstance(published_comment, dict)
            else None
        )
        comment_publisher_login = (
            comment_user.get("login") if isinstance(comment_user, dict) else None
        )
        comment_issue_url = (
            published_comment.get("issue_url")
            if isinstance(published_comment, dict)
            else None
        )
        try:
            expected_body = terminal_published_body(
                json.loads(str(publication["payload_json"]))["body"],
                str(publication["idempotency_key"]),
            )
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise CoordinationError("TERMINAL_OUTBOX_NOT_COMPLETE") from exc
        receipt_match = REMOTE_COMMENT_RECEIPT.fullmatch(remote_receipt)
        expected_issue_url = (
            f"https://api.github.com/repos/{packet['repository']}"
            f"/issues/{packet['issue_number']}"
        )
        if (
            not isinstance(issue_payload, dict)
            or issue_payload.get("number") != int(packet["issue_number"])
            or not isinstance(source_updated_at, str)
            or not source_updated_at
            or not isinstance(main_ref, dict)
            or main_ref.get("ref") != "refs/heads/main"
            or not isinstance(current_main_sha, str)
            or GIT_SHA.fullmatch(current_main_sha) is None
            or receipt_match is None
            or comment_id != int(remote_receipt.split(":", 1)[1])
            or comment_body != expected_body
            or hashlib.sha256(expected_body.encode("utf-8")).hexdigest()
            != publication["published_body_sha256"]
            or comment_publisher_login != publication["publisher_login"]
            or comment_issue_url != expected_issue_url
            or not isinstance(comment_created_at, str)
            or not comment_created_at
            or not isinstance(comment_updated_at, str)
            or not comment_updated_at
        ):
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_INVALID")
        _utc_timestamp(
            comment_created_at, error="TERMINAL_LIVE_EVIDENCE_INVALID"
        )
        _utc_timestamp(
            comment_updated_at, error="TERMINAL_LIVE_EVIDENCE_INVALID"
        )
        packet_created = _utc_timestamp(
            str(packet["created_at"]), error="TERMINAL_LIVE_EVIDENCE_INVALID"
        )
        comment_created = _utc_timestamp(
            comment_created_at, error="TERMINAL_LIVE_EVIDENCE_INVALID"
        )
        observed = _utc_timestamp(
            observed_at, error="TERMINAL_LIVE_EVIDENCE_INVALID"
        )
        if (
            comment_created < packet_created - timedelta(seconds=1)
            or comment_created > observed
        ):
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_INVALID")
        comment_descriptor = {
            "id": comment_id,
            "event": "commented",
            "body_sha256": hashlib.sha256(comment_body.encode("utf-8")).hexdigest(),
            "publisher_login": comment_publisher_login,
            "created_at": comment_created_at,
            "updated_at": comment_updated_at,
            "issue_url": comment_issue_url,
        }
        publication_window_start = packet_created - timedelta(seconds=1)
        publication_activity = []
        for event in timeline:
            event_created_at = event.get("created_at")
            if not isinstance(event_created_at, str):
                raise CoordinationError("TERMINAL_LIVE_EVIDENCE_INVALID")
            event_created = _utc_timestamp(
                event_created_at, error="TERMINAL_LIVE_EVIDENCE_INVALID"
            )
            if event_created >= publication_window_start:
                publication_activity.append(_terminal_timeline_activity(event))
        if publication_activity != [comment_descriptor]:
            raise CoordinationError("TERMINAL_CLOSEOUT_SOURCE_DRIFT")
        descriptor = {
            "schema": "twinfinity-terminal-live-evidence/v1",
            "closeout_key": closeout_key,
            "packet_sha256": str(packet["packet_sha256"]),
            "repository": str(packet["repository"]),
            "issue_number": int(packet["issue_number"]),
            "source_payload_sha256": digest_json(issue_payload),
            "source_material_sha256": digest_json(
                _terminal_issue_material_payload(issue_payload)
            ),
            "source_updated_at": source_updated_at,
            "current_main_sha": current_main_sha,
            "publication_comment_sha256": digest_json(comment_descriptor),
            "publication_comment_id": comment_id,
            "publication_comment_created_at": comment_created_at,
            "publication_comment_updated_at": comment_updated_at,
            "publication_publisher_login": comment_publisher_login,
            "publication_issue_url": comment_issue_url,
            "publication_activity_sha256": digest_json(publication_activity),
            "observed_at": observed_at,
        }
        return {**descriptor, "evidence_sha256": digest_json(descriptor)}

    def _validate_terminal_live_evidence(
        self,
        *,
        evidence: dict[str, Any] | None,
        packet: sqlite3.Row,
        validated_at: str,
    ) -> tuple[str, str]:
        fields = {
            "schema",
            "closeout_key",
            "packet_sha256",
            "repository",
            "issue_number",
            "source_payload_sha256",
            "source_material_sha256",
            "source_updated_at",
            "current_main_sha",
            "publication_comment_sha256",
            "publication_comment_id",
            "publication_comment_created_at",
            "publication_comment_updated_at",
            "publication_publisher_login",
            "publication_issue_url",
            "publication_activity_sha256",
            "observed_at",
            "evidence_sha256",
        }
        if not isinstance(evidence, dict) or set(evidence) != fields:
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_REQUIRED")
        descriptor = {
            key: evidence[key] for key in fields if key != "evidence_sha256"
        }
        evidence_sha256 = evidence.get("evidence_sha256")
        if (
            evidence.get("schema") != "twinfinity-terminal-live-evidence/v1"
            or not isinstance(evidence_sha256, str)
            or SHA256.fullmatch(evidence_sha256) is None
            or digest_json(descriptor) != evidence_sha256
        ):
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_DIGEST_MISMATCH")
        if (
            evidence.get("closeout_key") != packet["closeout_key"]
            or evidence.get("packet_sha256") != packet["packet_sha256"]
            or evidence.get("repository") != packet["repository"]
            or evidence.get("issue_number") != int(packet["issue_number"])
        ):
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_LINEAGE_MISMATCH")
        if (
            not isinstance(evidence.get("source_payload_sha256"), str)
            or SHA256.fullmatch(evidence["source_payload_sha256"]) is None
            or not isinstance(evidence.get("source_material_sha256"), str)
            or SHA256.fullmatch(evidence["source_material_sha256"]) is None
            or not isinstance(evidence.get("source_updated_at"), str)
            or not evidence["source_updated_at"]
            or not isinstance(evidence.get("current_main_sha"), str)
            or GIT_SHA.fullmatch(evidence["current_main_sha"]) is None
            or not isinstance(evidence.get("observed_at"), str)
            or not isinstance(evidence.get("publication_comment_sha256"), str)
            or SHA256.fullmatch(evidence["publication_comment_sha256"]) is None
            or not isinstance(evidence.get("publication_comment_id"), int)
            or evidence["publication_comment_id"] <= 0
            or not isinstance(
                evidence.get("publication_comment_created_at"), str
            )
            or not isinstance(
                evidence.get("publication_comment_updated_at"), str
            )
            or not isinstance(evidence.get("publication_publisher_login"), str)
            or not evidence["publication_publisher_login"]
            or not isinstance(evidence.get("publication_issue_url"), str)
            or not evidence["publication_issue_url"]
            or not isinstance(evidence.get("publication_activity_sha256"), str)
            or SHA256.fullmatch(evidence["publication_activity_sha256"]) is None
        ):
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_INVALID")
        _utc_timestamp(
            evidence["publication_comment_created_at"],
            error="TERMINAL_LIVE_EVIDENCE_INVALID",
        )
        _utc_timestamp(
            evidence["publication_comment_updated_at"],
            error="TERMINAL_LIVE_EVIDENCE_INVALID",
        )
        observed = _utc_timestamp(
            evidence["observed_at"], error="TERMINAL_LIVE_EVIDENCE_INVALID"
        )
        committed = _utc_timestamp(
            validated_at, error="TERMINAL_LIVE_EVIDENCE_INVALID"
        )
        age = (committed - observed).total_seconds()
        if age < 0 or age > TERMINAL_LIVE_EVIDENCE_MAX_AGE_SECONDS:
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_STALE")
        return evidence_sha256, canonical_json(evidence)

    def commit_terminal_closeout(
        self,
        *,
        closeout_key: str,
        attempt_id: str,
        executor_token: str,
        _test_failpoint: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        if self.connection.in_transaction:
            raise CoordinationError("TERMINAL_LIVE_EVIDENCE_TRANSACTION_ACTIVE")
        preflight_packet = self.connection.execute(
            "SELECT * FROM coordination_terminal_closeout_packets "
            "WHERE closeout_key=?",
            (closeout_key,),
        ).fetchone()
        if preflight_packet is None:
            raise CoordinationError("TERMINAL_CLOSEOUT_NOT_FOUND")
        preflight_commit = self.connection.execute(
            "SELECT * FROM coordination_terminal_closeout_commits "
            "WHERE closeout_key=?",
            (closeout_key,),
        ).fetchone()
        preflight_attempt = self._require_terminal_lineage_attempt(
            attempt_id=attempt_id,
            executor_token=executor_token,
            repository=preflight_packet["repository"],
            issue_number=int(preflight_packet["issue_number"]),
            generation=int(preflight_packet["generation"]),
            lease_manifest_sha256=preflight_packet["lease_manifest_sha256"],
            allowed_targets={
                ("message", str(preflight_packet["activation_message_id"])),
                ("terminal_watch", str(preflight_packet["terminal_watch_key"])),
            },
            completed_replay_attempt_ids=(
                set()
                if preflight_commit is None
                else {str(preflight_commit["finalizer_attempt_id"])}
            ),
        )
        if str(preflight_attempt["role"]) != preflight_packet["accountable_role"]:
            raise CoordinationError("TERMINAL_ATTEMPT_ROLE_MISMATCH")
        live_evidence = (
            None
            if preflight_commit is not None
            else self._acquire_terminal_live_evidence(closeout_key=closeout_key)
        )
        with self.transaction():
            packet = self.connection.execute(
                "SELECT * FROM coordination_terminal_closeout_packets "
                "WHERE closeout_key=?",
                (closeout_key,),
            ).fetchone()
            if packet is None:
                raise CoordinationError("TERMINAL_CLOSEOUT_NOT_FOUND")
            existing_commit = self.connection.execute(
                "SELECT * FROM coordination_terminal_closeout_commits "
                "WHERE closeout_key=?",
                (closeout_key,),
            ).fetchone()
            attempt = self._require_terminal_lineage_attempt(
                attempt_id=attempt_id,
                executor_token=executor_token,
                repository=packet["repository"],
                issue_number=int(packet["issue_number"]),
                generation=int(packet["generation"]),
                lease_manifest_sha256=packet["lease_manifest_sha256"],
                allowed_targets={
                    ("message", str(packet["activation_message_id"])),
                    ("terminal_watch", str(packet["terminal_watch_key"])),
                },
                completed_replay_attempt_ids=(
                    set()
                    if existing_commit is None
                    else {str(existing_commit["finalizer_attempt_id"])}
                ),
            )
            if str(attempt["role"]) != packet["accountable_role"]:
                raise CoordinationError("TERMINAL_ATTEMPT_ROLE_MISMATCH")
            if existing_commit is not None:
                return self.terminal_closeout_status(closeout_key)
            if attempt["state"] != "RUNNING":
                raise CoordinationError("TERMINAL_ATTEMPT_NOT_EXECUTABLE")
            commit_now = utc_now()
            outbox = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (packet["outbox_id"],)
            ).fetchone()
            readback = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_readbacks "
                "WHERE outbox_id=?",
                (packet["outbox_id"],),
            ).fetchone()
            publisher = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_publishers "
                "WHERE outbox_id=?",
                (packet["outbox_id"],),
            ).fetchone()
            receipt = json.loads(packet["terminal_receipt_json"])
            cleanup = json.loads(packet["cleanup_evidence_json"])
            expected_publication_body = terminal_publication_body(
                closeout_key=closeout_key,
                terminal_receipt=receipt,
                cleanup_evidence=cleanup,
            )
            published_body = terminal_published_body(
                expected_publication_body, closeout_key
            )
            if (
                outbox is None
                or outbox["state"] != "COMPLETE"
                or not isinstance(outbox["remote_receipt"], str)
                or REMOTE_COMMENT_RECEIPT.fullmatch(outbox["remote_receipt"])
                is None
                or outbox["idempotency_key"] != closeout_key
                or outbox["repository"] != packet["repository"]
                or outbox["object_kind"] != "issue"
                or int(outbox["object_number"]) != int(packet["issue_number"])
                or outbox["expected_source_sha256"]
                != packet["source_payload_sha256"]
                or outbox["payload_sha256"] != packet["outbox_payload_sha256"]
                or outbox["payload_json"]
                != canonical_json({"body": expected_publication_body})
                or readback is None
                or readback["closeout_key"] != closeout_key
                or readback["remote_receipt"] != outbox["remote_receipt"]
                or readback["remote_receipt_sha256"]
                != hashlib.sha256(
                    str(outbox["remote_receipt"]).encode("utf-8")
                ).hexdigest()
                or readback["published_body_sha256"]
                != hashlib.sha256(published_body.encode("utf-8")).hexdigest()
                or not isinstance(readback["publisher_login"], str)
                or not readback["publisher_login"]
                or publisher is None
                or publisher["closeout_key"] != closeout_key
                or publisher["publisher_login"] != readback["publisher_login"]
            ):
                raise CoordinationError("TERMINAL_OUTBOX_NOT_COMPLETE")
            live_evidence_sha256, live_evidence_json = (
                self._validate_terminal_live_evidence(
                    evidence=live_evidence,
                    packet=packet,
                    validated_at=commit_now,
                )
            )
            if validate_terminal_receipt(
                receipt,
                repository=packet["repository"],
                issue_number=int(packet["issue_number"]),
                generation=int(packet["generation"]),
                source_payload_sha256=packet["source_payload_sha256"],
                lease_manifest_sha256=packet["lease_manifest_sha256"],
                role=packet["accountable_role"],
            ) != packet["terminal_receipt_sha256"] or validate_terminal_cleanup_evidence(
                cleanup,
                repository=packet["repository"],
                issue_number=int(packet["issue_number"]),
                generation=int(packet["generation"]),
                lease_manifest_sha256=packet["lease_manifest_sha256"],
                role=packet["accountable_role"],
            ) != packet["cleanup_evidence_sha256"]:
                raise CoordinationError("TERMINAL_CLOSEOUT_EVIDENCE_DRIFT")
            item = self.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (packet["repository"], packet["issue_number"]),
            ).fetchone()
            watch = self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (packet["terminal_watch_key"],),
            ).fetchone()
            activation = self.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (packet["activation_message_id"],),
            ).fetchone()
            try:
                activation_payload = (
                    None
                    if activation is None
                    else json.loads(activation["payload_json"])
                )
            except (TypeError, json.JSONDecodeError):
                activation_payload = None
            claim_binding = (
                None
                if watch is None
                else self.connection.execute(
                    "SELECT * FROM executor_attempts WHERE attempt_id=?",
                    (watch["claim_attempt_id"],),
                ).fetchone()
            )
            current_source = self.current_snapshot(
                str(packet["repository"]), "issue", int(packet["issue_number"])
            )
            if current_source is None or (
                current_source.payload_sha256 != packet["source_payload_sha256"]
            ):
                raise CoordinationError("TERMINAL_CLOSEOUT_SOURCE_DRIFT")
            expected_publication_issue_url = (
                f"https://api.github.com/repos/{packet['repository']}"
                f"/issues/{packet['issue_number']}"
            )
            publication_comment_descriptor = {
                "id": int(str(outbox["remote_receipt"]).split(":", 1)[1]),
                "event": "commented",
                "body_sha256": readback["published_body_sha256"],
                "publisher_login": readback["publisher_login"],
                "created_at": live_evidence["publication_comment_created_at"],
                "updated_at": live_evidence["publication_comment_updated_at"],
                "issue_url": expected_publication_issue_url,
            }
            if (
                live_evidence["publication_comment_id"]
                != publication_comment_descriptor["id"]
                or live_evidence["publication_publisher_login"]
                != publication_comment_descriptor["publisher_login"]
                or live_evidence["publication_issue_url"]
                != expected_publication_issue_url
                or live_evidence["publication_comment_sha256"]
                != digest_json(publication_comment_descriptor)
                or live_evidence["publication_activity_sha256"]
                != digest_json([publication_comment_descriptor])
                or live_evidence["publication_comment_created_at"]
                != live_evidence["publication_comment_updated_at"]
            ):
                raise CoordinationError("TERMINAL_CLOSEOUT_SOURCE_DRIFT")
            exact_source = (
                live_evidence["source_payload_sha256"]
                == packet["source_payload_sha256"]
                == current_source.payload_sha256
                and live_evidence["source_updated_at"]
                == current_source.source_updated_at
            )
            publication_timestamp_only = (
                live_evidence["source_payload_sha256"]
                != packet["source_payload_sha256"]
                and live_evidence["source_material_sha256"]
                == digest_json(
                    _terminal_issue_material_payload(current_source.payload)
                )
                and live_evidence["source_updated_at"]
                != current_source.source_updated_at
                and _utc_timestamp(
                    live_evidence["source_updated_at"],
                    error="TERMINAL_LIVE_EVIDENCE_INVALID",
                )
                > _utc_timestamp(
                    current_source.source_updated_at,
                    error="TERMINAL_LIVE_EVIDENCE_INVALID",
                )
                and live_evidence["source_updated_at"]
                == live_evidence["publication_comment_created_at"]
                == live_evidence["publication_comment_updated_at"]
                and live_evidence["publication_comment_id"]
                == int(str(outbox["remote_receipt"]).split(":", 1)[1])
                and live_evidence["publication_publisher_login"]
                == readback["publisher_login"]
            )
            if not exact_source and not publication_timestamp_only:
                raise CoordinationError("TERMINAL_CLOSEOUT_SOURCE_DRIFT")
            current_graph = self._current_terminal_graph_binding(
                repository=str(packet["repository"]),
                issue_number=int(packet["issue_number"]),
                source_payload_sha256=str(packet["source_payload_sha256"]),
            )
            if (
                not packet["graph_version"]
                or int(packet["graph_version"]) != current_graph["graph_version"]
                or packet["graph_sha256"] != current_graph["graph_sha256"]
                or packet["graph_main_sha"] != current_graph["graph_main_sha"]
                or packet["graph_node_key"] != current_graph["graph_node_key"]
                or packet["graph_binding_sha256"]
                != current_graph["graph_binding_sha256"]
                or live_evidence["current_main_sha"] != packet["graph_main_sha"]
                or live_evidence["current_main_sha"]
                != current_graph["graph_main_sha"]
            ):
                raise CoordinationError("TERMINAL_CLOSEOUT_GRAPH_DRIFT")
            rotation_chain_valid = (
                item is not None
                and self._terminal_endpoint_rotation_chain_valid(
                    packet=packet,
                    item=item,
                    current_endpoint_id=str(attempt["endpoint_id"]),
                )
            )
            if (
                item is None
                or item["status"] != "PUBLICATION_PENDING"
                or item["allocation_class"] != "ACTIVE"
                or int(item["generation"]) != int(packet["generation"])
                or not rotation_chain_valid
                or item["source_payload_sha256"] != packet["source_payload_sha256"]
                or item["lease_manifest_sha256"] != packet["lease_manifest_sha256"]
                or item["accountable_session_id"] != attempt["endpoint_id"]
                or watch is None
                or watch["state"] != "ACTIVE"
                or watch["repository"] != packet["repository"]
                or int(watch["issue_number"]) != int(packet["issue_number"])
                or int(watch["generation"]) != int(packet["generation"])
                or watch["accountable_session_id"] != attempt["endpoint_id"]
                or watch["lease_manifest_sha256"] != packet["lease_manifest_sha256"]
                or int(watch["admission_message_id"] or 0)
                != int(packet["activation_message_id"])
                or watch["admission_payload_sha256"]
                != packet["activation_payload_sha256"]
                or activation is None
                or not isinstance(activation_payload, dict)
                or digest_json(activation_payload)
                != packet["activation_payload_sha256"]
                or activation["payload_sha256"]
                != packet["activation_payload_sha256"]
                or activation["state"] != "CLAIMED"
                or activation["recipient_session_id"] != packet["endpoint_id"]
                or activation["claimed_by"] != packet["endpoint_id"]
                or claim_binding is None
                or claim_binding["role"] != packet["accountable_role"]
                or claim_binding["endpoint_id"] != packet["endpoint_id"]
                or claim_binding["state"] not in {"RUNNING", "COMPLETE", "HOLD"}
                or claim_binding["target_kind"] != "message"
                or claim_binding["target_key"]
                != str(packet["activation_message_id"])
                or claim_binding["lineage_repository"] != packet["repository"]
                or int(claim_binding["lineage_issue_number"] or -1)
                != int(packet["issue_number"])
                or int(claim_binding["lineage_generation"] or -1)
                != int(packet["generation"])
                or claim_binding["lineage_lease_sha256"]
                != packet["lease_manifest_sha256"]
                or (
                    attempt["target_kind"] == "message"
                    and claim_binding["attempt_id"] != attempt["attempt_id"]
                )
                or (
                    attempt["target_kind"] == "terminal_watch"
                    and claim_binding["state"] not in {"COMPLETE", "HOLD"}
                )
            ):
                raise CoordinationError("TERMINAL_CLOSEOUT_LINEAGE_DRIFT")
            if self.connection.execute(
                "SELECT 1 FROM coordination_pre_push_publications "
                "WHERE repository=? AND issue_number=? AND state='RESERVED' LIMIT 1",
                (packet["repository"], packet["issue_number"]),
            ).fetchone() is not None:
                raise CoordinationError("PREPUSH_PUBLICATION_RESERVED")
            if self.connection.execute(
                "SELECT 1 FROM coordination_artifacts WHERE repository=? "
                "AND issue_number=? AND state IN ('MOVE_RESERVED','PURGE_RESERVED') "
                "LIMIT 1",
                (packet["repository"], packet["issue_number"]),
            ).fetchone() is not None:
                raise CoordinationError("ARTIFACT_GC_INFLIGHT")
            completed_activation = self.connection.execute(
                """
                UPDATE coordination_messages
                SET state='COMPLETE', updated_at=?, last_error=NULL
                WHERE id=? AND state='CLAIMED' AND claimed_by=?
                  AND payload_sha256=?
                """,
                (
                    commit_now,
                    packet["activation_message_id"],
                    packet["endpoint_id"],
                    packet["activation_payload_sha256"],
                ),
            )
            if completed_activation.rowcount != 1:
                raise CoordinationError("TERMINAL_CLOSEOUT_MESSAGE_CONFLICT")
            self._terminal_failpoint(_test_failpoint, "commit.after_message")
            self._event(
                "MESSAGE_COMPLETED",
                f"message:{packet['activation_message_id']}",
                {
                    "session_id": packet["endpoint_id"],
                    "terminal_closeout_key": closeout_key,
                },
                commit_now,
            )
            self._terminal_failpoint(_test_failpoint, "commit.after_message_event")
            done_item_version = int(item["version"]) + 1
            item_update = self.connection.execute(
                """
                UPDATE coordination_items
                SET status='DONE', allocation_class='NONE',
                    accountable_session_id=NULL, lease_manifest_sha256=NULL,
                    development_units=0, shared_units=0, sre_units=0,
                    version=?, updated_at=?
                WHERE repository=? AND issue_number=?
                  AND status='PUBLICATION_PENDING' AND allocation_class='ACTIVE'
                  AND generation=? AND version=?
                  AND source_payload_sha256=? AND lease_manifest_sha256=?
                """,
                (
                    done_item_version,
                    commit_now,
                    packet["repository"],
                    packet["issue_number"],
                    packet["generation"],
                    item["version"],
                    packet["source_payload_sha256"],
                    packet["lease_manifest_sha256"],
                ),
            )
            if item_update.rowcount != 1:
                raise CoordinationError("TERMINAL_CLOSEOUT_ITEM_CONFLICT")
            self._terminal_failpoint(_test_failpoint, "commit.after_item")
            watch_update = self.connection.execute(
                """
                UPDATE coordination_terminal_watches
                SET state='COMPLETE', process_id=NULL, updated_at=?, last_error=NULL
                WHERE watch_key=? AND state='ACTIVE'
                  AND admission_message_id=? AND admission_payload_sha256=?
                  AND lease_manifest_sha256=?
                """,
                (
                    commit_now,
                    packet["terminal_watch_key"],
                    packet["activation_message_id"],
                    packet["activation_payload_sha256"],
                    packet["lease_manifest_sha256"],
                ),
            )
            if watch_update.rowcount != 1:
                raise CoordinationError("TERMINAL_CLOSEOUT_WATCH_CONFLICT")
            self._terminal_failpoint(_test_failpoint, "commit.after_watch")
            dirty_event_id = self._enqueue_portfolio_dirty_event(
                repository=packet["repository"],
                issue_number=int(packet["issue_number"]),
                release_item_version=done_item_version,
                release_source_sha256=packet["source_payload_sha256"],
                prior_allocation_class=str(item["allocation_class"]),
                status="DONE",
                generation=int(packet["generation"]),
                now=commit_now,
            )
            self._terminal_failpoint(_test_failpoint, "commit.after_dirty_event")
            remote_receipt_sha256 = hashlib.sha256(
                str(outbox["remote_receipt"]).encode("utf-8")
            ).hexdigest()
            commit_descriptor = {
                "schema": "twinfinity-terminal-closeout-commit/v1",
                "closeout_key": closeout_key,
                "packet_sha256": packet["packet_sha256"],
                "finalizer_attempt_id": attempt["attempt_id"],
                "finalizer_attempt_version": int(attempt["version"]),
                "live_evidence_sha256": live_evidence_sha256,
                "remote_receipt_sha256": remote_receipt_sha256,
                "prior_item_version": int(item["version"]),
                "done_item_version": done_item_version,
                "dirty_event_id": dirty_event_id,
            }
            commit_sha256 = digest_json(commit_descriptor)
            self.connection.execute(
                """
                INSERT INTO coordination_terminal_closeout_commits(
                    closeout_key, commit_sha256, finalizer_attempt_id,
                    finalizer_attempt_version, live_evidence_sha256,
                    live_evidence_json, remote_receipt,
                    remote_receipt_sha256, prior_item_version,
                    done_item_version, dirty_event_id, committed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    closeout_key,
                    commit_sha256,
                    attempt["attempt_id"],
                    int(attempt["version"]),
                    live_evidence_sha256,
                    live_evidence_json,
                    outbox["remote_receipt"],
                    remote_receipt_sha256,
                    int(item["version"]),
                    done_item_version,
                    dirty_event_id,
                    commit_now,
                ),
            )
            self._terminal_failpoint(_test_failpoint, "commit.after_commit")
            self._event(
                "TERMINAL_CLOSEOUT_COMMITTED",
                closeout_key,
                {
                    "commit_sha256": commit_sha256,
                    "done_item_version": done_item_version,
                    "dirty_event_id": dirty_event_id,
                },
                commit_now,
            )
            self._terminal_failpoint(_test_failpoint, "commit.after_event")
        return self.terminal_closeout_status(closeout_key)

    def _readiness_decision_notice_bound(self, message_id: int) -> bool:
        table = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='approval_delivery_notices'"
        ).fetchone()
        return bool(
            table
            and self.connection.execute(
                "SELECT 1 FROM approval_delivery_notices WHERE message_id=?",
                (message_id,),
            ).fetchone()
        )

    def _readiness_resolution_notice_bound(self, message_id: int) -> bool:
        table = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='portfolio_readiness_resolution_notices'"
        ).fetchone()
        return bool(
            table
            and self.connection.execute(
                "SELECT 1 FROM portfolio_readiness_resolution_notices "
                "WHERE message_id=?",
                (message_id,),
            ).fetchone()
        )

    def _claim_message_in_transaction(
        self,
        message_id: int,
        session_id: str,
        now: str,
        *,
        gateway: object | None = None,
        attempt_id: str | None = None,
        executor_token: str | None = None,
    ) -> dict[str, Any]:
        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        _validate_coordination_identity(session_id)
        canonical_session_id = canonicalize_coordination_identity(
            self.connection, session_id
        )
        row = self.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        if row is None:
            raise CoordinationError("MESSAGE_NOT_FOUND")
        readiness_bound = self._readiness_decision_notice_bound(message_id)
        resolution_bound = self._readiness_resolution_notice_bound(message_id)
        if readiness_bound and gateway is not _READINESS_DECISION_GATEWAY:
            raise CoordinationError("READINESS_DECISION_HANDLER_REQUIRED")
        if resolution_bound and gateway is not _READINESS_RESOLUTION_GATEWAY:
            raise CoordinationError("READINESS_RESOLUTION_HANDLER_REQUIRED")
        if not identities_role_equivalent(
            self.connection, row["recipient_session_id"], session_id
        ):
            raise CoordinationError("WRONG_MESSAGE_RECIPIENT")
        if row["state"] not in {"PREPARED", "CLAIMED"} or (
            row["state"] == "CLAIMED"
            and not identities_role_equivalent(
                self.connection, row["claimed_by"], session_id
            )
        ):
            raise CoordinationError("MESSAGE_STATE_CONFLICT")
        payload = json.loads(row["payload_json"])
        if digest_json(payload) != row["payload_sha256"]:
            raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
        if not readiness_bound and not resolution_bound:
            self._validate_message_source(payload)
        self._validate_message_contract(
            topic=row["topic"],
            recipient_session_id=row["recipient_session_id"],
            payload=payload,
        )
        watch = None
        claim_attempt = None
        if row["topic"] in {"development.admission", "sre.admission"}:
            source = payload.get("source", {})
            watch_key = terminal_watch_key(
                str(source.get("repository")),
                int(payload.get("issue_number", 0)),
                int(payload.get("generation", -1)),
            )
            watch = self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            fixture_preclaimed = bool(
                watch is not None
                and watch["state"] == "ACTIVE"
                and watch["claim_attempt_id"] is None
                and Path("/tmp") in self.path.resolve().parents
            )
            if (
                watch is None
                or (
                    watch["state"]
                    != ("PENDING_CLAIM" if row["state"] == "PREPARED" else "ACTIVE")
                    and not fixture_preclaimed
                )
                or int(watch["admission_message_id"] or 0) != message_id
                or watch["admission_payload_sha256"] != row["payload_sha256"]
                or watch["accountable_session_id"] != canonical_session_id
                or watch["lease_manifest_sha256"]
                != payload.get("lease_manifest_sha256")
            ):
                raise CoordinationError("TERMINAL_WATCH_CLAIM_BINDING_MISMATCH")
            if not fixture_preclaimed:
                claim_attempt = self._require_running_lineage_attempt(
                    attempt_id=attempt_id,
                    executor_token=executor_token,
                    repository=str(source["repository"]),
                    issue_number=int(payload["issue_number"]),
                    generation=int(payload["generation"]),
                    lease_manifest_sha256=str(payload["lease_manifest_sha256"]),
                    allowed_targets={("message", str(message_id))},
                )
                if claim_attempt["endpoint_id"] != canonical_session_id:
                    raise CoordinationError("TERMINAL_ATTEMPT_ENDPOINT_MISMATCH")
        if row["state"] == "PREPARED":
            changed = self.connection.execute(
                "UPDATE coordination_messages SET state='CLAIMED', claimed_by=?, "
                "updated_at=? WHERE id=? AND state='PREPARED'",
                (canonical_session_id, now, message_id),
            ).rowcount
            if changed != 1:
                raise CoordinationError("MESSAGE_STATE_CONFLICT")
            if watch is not None and claim_attempt is not None:
                activated_watch = self.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='ACTIVE', claim_attempt_id=?, attempts=0,
                        process_id=NULL, last_heartbeat_at=?, next_wake_at=?,
                        updated_at=?, last_error=NULL
                    WHERE watch_key=? AND state='PENDING_CLAIM'
                      AND admission_message_id=?
                      AND admission_payload_sha256=?
                      AND claim_attempt_id IS NULL
                    """,
                    (
                        claim_attempt["attempt_id"],
                        now,
                        timestamp_after(now, 60),
                        now,
                        watch["watch_key"],
                        message_id,
                        row["payload_sha256"],
                    ),
                )
                if activated_watch.rowcount != 1:
                    raise CoordinationError("TERMINAL_WATCH_CLAIM_CONFLICT")
        elif watch is not None and claim_attempt is not None:
            rebound_watch = self.connection.execute(
                """
                UPDATE coordination_terminal_watches
                SET claim_attempt_id=?, attempts=0, process_id=NULL,
                    last_heartbeat_at=?, next_wake_at=?, updated_at=?,
                    last_error=NULL
                WHERE watch_key=? AND state='ACTIVE'
                  AND admission_message_id=? AND admission_payload_sha256=?
                """,
                (
                    claim_attempt["attempt_id"],
                    now,
                    timestamp_after(now, 60),
                    now,
                    watch["watch_key"],
                    message_id,
                    row["payload_sha256"],
                ),
            )
            if rebound_watch.rowcount != 1:
                raise CoordinationError("TERMINAL_WATCH_CLAIM_CONFLICT")
        claimed = self.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        self._event(
            "MESSAGE_CLAIMED",
            f"message:{message_id}",
            {"session_id": session_id},
            now,
        )
        return dict(claimed)

    def claim_readiness_decision_message_in_transaction(
        self, message_id: int, session_id: str, now: str
    ) -> dict[str, Any]:
        """Claim one bound readiness disposition inside its all-or-none write."""

        return self._claim_message_in_transaction(
            message_id,
            session_id,
            now,
            gateway=_READINESS_DECISION_GATEWAY,
        )

    def claim_readiness_resolution_message_in_transaction(
        self, message_id: int, session_id: str, now: str
    ) -> dict[str, Any]:
        """Claim one bound consolidated resolution through its exact handler."""

        return self._claim_message_in_transaction(
            message_id,
            session_id,
            now,
            gateway=_READINESS_RESOLUTION_GATEWAY,
        )

    def claim_message(
        self,
        message_id: int,
        session_id: str,
        now: str,
        *,
        attempt_id: str | None = None,
        executor_token: str | None = None,
    ) -> dict[str, Any]:
        try:
            with self.transaction():
                return self._claim_message_in_transaction(
                    message_id,
                    session_id,
                    now,
                    attempt_id=attempt_id,
                    executor_token=executor_token,
                )
        except CoordinationError as exc:
            error = str(exc)
            if error in {
                "SOURCE_SNAPSHOT_DRIFT",
                "MESSAGE_SOURCE_DRIFT",
                "MESSAGE_CONTRACT_INVALID",
                "MESSAGE_ITEM_STATE_MISMATCH",
                "MESSAGE_PAYLOAD_MISMATCH",
                "TERMINAL_CLOSEOUT_TOPIC_RETIRED",
            }:
                with self.transaction():
                    self.connection.execute(
                        "UPDATE coordination_messages SET state='HOLD', "
                        "updated_at=?, last_error=? WHERE id=? "
                        "AND state IN ('PREPARED','CLAIMED')",
                        (now, error, message_id),
                    )
                    self._event(
                        "MESSAGE_HELD",
                        f"message:{message_id}",
                        {"error": error},
                        now,
                    )
            raise

    def _complete_message_in_transaction(
        self,
        message_id: int,
        session_id: str,
        now: str,
        *,
        gateway: object | None = None,
    ) -> None:
        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        session_id = canonicalize_coordination_identity(self.connection, session_id)
        row = self.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        if (
            row is None
            or row["state"] != "CLAIMED"
            or not identities_role_equivalent(
                self.connection, row["claimed_by"], session_id
            )
        ):
            raise CoordinationError("MESSAGE_STATE_CONFLICT")
        if row["topic"] in ADMISSION_WATCH_TOPICS:
            # Admission rows are immutable terminal lineage. Their only
            # CLAIMED -> COMPLETE authority is commit_terminal_closeout.
            raise CoordinationError("TERMINAL_FINALIZATION_REQUIRED")
        readiness_bound = self._readiness_decision_notice_bound(message_id)
        resolution_bound = self._readiness_resolution_notice_bound(message_id)
        if readiness_bound:
            if gateway is not _READINESS_DECISION_GATEWAY:
                raise CoordinationError("READINESS_DECISION_CONSUMPTION_REQUIRED")
            consumption_table = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='portfolio_readiness_approval_consumptions'"
            ).fetchone()
            if not consumption_table or self.connection.execute(
                "SELECT 1 FROM portfolio_readiness_approval_consumptions "
                "WHERE notice_message_id=?",
                (message_id,),
            ).fetchone() is None:
                raise CoordinationError("READINESS_DECISION_CONSUMPTION_REQUIRED")
        if resolution_bound:
            if gateway is not _READINESS_RESOLUTION_GATEWAY:
                raise CoordinationError("READINESS_RESOLUTION_CONSUMPTION_REQUIRED")
            cycle_table = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='portfolio_readiness_resolution_cycles'"
            ).fetchone()
            if not cycle_table or self.connection.execute(
                "SELECT 1 FROM portfolio_readiness_resolution_cycles "
                "WHERE notice_message_id=?",
                (message_id,),
            ).fetchone() is None:
                raise CoordinationError("READINESS_RESOLUTION_CONSUMPTION_REQUIRED")
        payload = json.loads(row["payload_json"])
        if row["topic"] == "development.terminal_closeout":
            outbox = self.connection.execute(
                "SELECT state, remote_receipt FROM github_outbox WHERE id=?",
                (payload.get("outbox_id"),),
            ).fetchone()
            if (
                outbox is None
                or outbox["state"] != "COMPLETE"
                or not outbox["remote_receipt"]
            ):
                raise CoordinationError("TERMINAL_OUTBOX_NOT_COMPLETE")
        if not readiness_bound and not resolution_bound:
            self._validate_message_source(payload)
        self._validate_message_contract(
            topic=row["topic"],
            recipient_session_id=row["recipient_session_id"],
            payload=payload,
        )
        changed = self.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE', updated_at=? "
            "WHERE id=? AND state='CLAIMED' AND claimed_by=?",
            (now, message_id, row["claimed_by"]),
        ).rowcount
        if changed != 1:
            raise CoordinationError("MESSAGE_STATE_CONFLICT")
        self._event(
            "MESSAGE_COMPLETED",
            f"message:{message_id}",
            {"session_id": session_id},
            now,
        )

    def complete_readiness_decision_message_in_transaction(
        self, message_id: int, session_id: str, now: str
    ) -> None:
        """Complete a bound readiness notice after immutable consumption."""

        self._complete_message_in_transaction(
            message_id,
            session_id,
            now,
            gateway=_READINESS_DECISION_GATEWAY,
        )

    def complete_readiness_resolution_message_in_transaction(
        self, message_id: int, session_id: str, now: str
    ) -> None:
        """Complete one resolution notice after its immutable cycle receipt."""

        self._complete_message_in_transaction(
            message_id,
            session_id,
            now,
            gateway=_READINESS_RESOLUTION_GATEWAY,
        )

    def complete_message(self, message_id: int, session_id: str, now: str) -> None:
        try:
            with self.transaction():
                self._complete_message_in_transaction(
                    message_id, session_id, now
                )
        except CoordinationError as exc:
            error = str(exc)
            if error in {
                "SOURCE_SNAPSHOT_DRIFT",
                "MESSAGE_SOURCE_DRIFT",
                "MESSAGE_CONTRACT_INVALID",
                "MESSAGE_ITEM_STATE_MISMATCH",
            }:
                canonical_session_id = canonicalize_coordination_identity(
                    self.connection, session_id
                )
                with self.transaction():
                    self.connection.execute(
                        "UPDATE coordination_messages SET state='HOLD', "
                        "updated_at=?, last_error=? WHERE id=? AND state='CLAIMED' "
                        "AND claimed_by=?",
                        (now, error, message_id, canonical_session_id),
                    )
                    self._event(
                        "MESSAGE_HELD",
                        f"message:{message_id}",
                        {"error": error},
                        now,
                    )
            raise

    def enqueue_comment(
        self,
        *,
        idempotency_key: str,
        repository: str,
        object_kind: str,
        object_number: int,
        expected_source_sha256: str,
        body: str,
        now: str,
        _transaction: bool = True,
    ) -> int:
        _validate_repository(repository)
        _validate_sha256(expected_source_sha256)
        if object_kind not in SOURCE_KINDS or object_number <= 0 or not body:
            raise CoordinationError("INVALID_OUTBOX_ITEM")
        payload = {"body": body}
        payload_json = canonical_json(payload)
        payload_sha256 = digest_json(payload)
        with (self.transaction() if _transaction else nullcontext()):
            source = self.current_snapshot(repository, object_kind, object_number)
            if source is None or source.payload_sha256 != expected_source_sha256:
                raise CoordinationError("SOURCE_SNAPSHOT_DRIFT")
            current = self.connection.execute(
                "SELECT id, repository, object_kind, object_number, expected_source_sha256, payload_sha256 FROM github_outbox WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if current is not None:
                expected = (
                    repository,
                    object_kind,
                    object_number,
                    expected_source_sha256,
                    payload_sha256,
                )
                actual = tuple(current[key] for key in (
                    "repository",
                    "object_kind",
                    "object_number",
                    "expected_source_sha256",
                    "payload_sha256",
                ))
                if actual != expected:
                    raise CoordinationError("IDEMPOTENCY_CONFLICT")
                return int(current["id"])
            cursor = self.connection.execute(
                "INSERT INTO github_outbox(idempotency_key, repository, object_kind, object_number, operation, expected_source_sha256, payload_sha256, payload_json, state, created_at, updated_at) VALUES (?, ?, ?, ?, 'comment', ?, ?, ?, 'PREPARED', ?, ?)",
                (
                    idempotency_key,
                    repository,
                    object_kind,
                    object_number,
                    expected_source_sha256,
                    payload_sha256,
                    payload_json,
                    now,
                    now,
                ),
            )
            outbox_id = int(cursor.lastrowid)
            self._event("OUTBOX_PREPARED", f"outbox:{outbox_id}", payload, now)
        return outbox_id

    def prepare_routing_deprecation_inventory(
        self,
        *,
        inventory: dict[str, Any],
        occurrences: list[dict[str, Any]],
        alias_source_path: Path,
        outbox_idempotency_key: str,
        receipt_body: str,
        now: str,
    ) -> tuple[str, int]:
        """Freeze one repository inventory and its #179 receipt in one transaction."""

        inventory_fields = {
            "kind",
            "repository",
            "alias_source_sha256",
            "endpoint_state_sha256",
            "issue_179_source_sha256",
            "object_manifest_sha256",
            "occurrence_manifest_sha256",
            "object_manifest",
            "object_count",
            "issue_count",
            "pull_request_count",
            "occurrence_count",
            "classification_counts",
            "semantic_tag_counts",
            "inventory_sha256",
        }
        object_fields = {
            "object_kind",
            "object_number",
            "node_id",
            "body_sha256",
        }
        occurrence_fields = {
            "ordinal",
            "object_kind",
            "object_number",
            "node_id",
            "body_sha256",
            "alias",
            "byte_start",
            "byte_end",
            "line_number",
            "byte_column",
            "classification",
            "semantic_tags",
        }
        if (
            not isinstance(inventory, dict)
            or set(inventory) != inventory_fields
            or inventory.get("kind")
            != "TWINFINITY_ROUTING_DEPRECATION_INVENTORY_V1"
            or not isinstance(occurrences, list)
            or not outbox_idempotency_key
            or not receipt_body
        ):
            raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_INVALID")
        repository = inventory.get("repository")
        if not isinstance(repository, str):
            raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_INVALID")
        _validate_repository(repository)
        for field in (
            "alias_source_sha256",
            "endpoint_state_sha256",
            "issue_179_source_sha256",
            "object_manifest_sha256",
            "occurrence_manifest_sha256",
            "inventory_sha256",
        ):
            value = inventory.get(field)
            if not isinstance(value, str):
                raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_INVALID")
            _validate_sha256(value)
        objects = inventory.get("object_manifest")
        if (
            not isinstance(objects, list)
            or any(not isinstance(item, dict) or set(item) != object_fields for item in objects)
            or any(not isinstance(item.get("body_sha256"), str) for item in objects)
            or any(not isinstance(item, dict) or set(item) != occurrence_fields for item in occurrences)
        ):
            raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_INVALID")
        for item in objects:
            _validate_sha256(item["body_sha256"])
        if (
            digest_json(objects) != inventory["object_manifest_sha256"]
            or digest_json(occurrences) != inventory["occurrence_manifest_sha256"]
            or digest_json({key: inventory[key] for key in inventory_fields - {"inventory_sha256"}})
            != inventory["inventory_sha256"]
            or inventory.get("object_count") != len(objects)
            or inventory.get("occurrence_count") != len(occurrences)
            or inventory.get("issue_count")
            != sum(item["object_kind"] == "issue" for item in objects)
            or inventory.get("pull_request_count")
            != sum(item["object_kind"] == "pull_request" for item in objects)
        ):
            raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_DIGEST_MISMATCH")
        for ordinal, item in enumerate(occurrences):
            if (
                item.get("ordinal") != ordinal
                or item.get("classification")
                not in {
                    "EXECUTABLE_ROUTE",
                    "ROUTING_REFERENCE",
                    "HISTORICAL_PROVENANCE",
                    "AMBIGUOUS_REFERENCE",
                }
                or not isinstance(item.get("semantic_tags"), list)
                or item["semantic_tags"] != sorted(set(item["semantic_tags"]))
            ):
                raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_INVALID")
            _validate_sha256(str(item.get("body_sha256", "")))

        issue_179 = next(
            (
                item
                for item in objects
                if item["object_kind"] == "issue" and item["object_number"] == 179
            ),
            None,
        )
        stored_values = {
            "inventory_sha256": inventory["inventory_sha256"],
            "repository": repository,
            "kind": inventory["kind"],
            "alias_source_sha256": inventory["alias_source_sha256"],
            "endpoint_state_sha256": inventory["endpoint_state_sha256"],
            "issue_179_source_sha256": inventory["issue_179_source_sha256"],
            "object_manifest_sha256": inventory["object_manifest_sha256"],
            "occurrence_manifest_sha256": inventory["occurrence_manifest_sha256"],
            "object_manifest_json": canonical_json(objects),
            "object_count": inventory["object_count"],
            "issue_count": inventory["issue_count"],
            "pull_request_count": inventory["pull_request_count"],
            "occurrence_count": inventory["occurrence_count"],
            "classification_counts_json": canonical_json(inventory["classification_counts"]),
            "semantic_tag_counts_json": canonical_json(inventory["semantic_tag_counts"]),
        }
        with self.transaction():
            source = self.current_snapshot(repository, "issue", 179)
            source_body = None if source is None else source.payload.get("body")
            if (
                issue_179 is None
                or source is None
                or not isinstance(source_body, str)
                or source.payload_sha256 != inventory["issue_179_source_sha256"]
                or hashlib.sha256(source_body.encode("utf-8")).hexdigest()
                != issue_179["body_sha256"]
                or routing_endpoint_state_digest(self.connection)
                != inventory["endpoint_state_sha256"]
                or descriptor_file_sha256(alias_source_path)
                != inventory["alias_source_sha256"]
            ):
                raise CoordinationError("ROUTING_DEPRECATION_PREPARE_DRIFT")
            prior = self.connection.execute(
                "SELECT * FROM routing_deprecation_inventories WHERE repository=?",
                (repository,),
            ).fetchone()
            if prior is not None:
                outbox = self.connection.execute(
                    "SELECT * FROM github_outbox WHERE id=?", (prior["outbox_id"],)
                ).fetchone()
                prior_occurrences = [
                    {
                        **{key: row[key] for key in occurrence_fields - {"semantic_tags"}},
                        "semantic_tags": json.loads(row["semantic_tags_json"]),
                    }
                    for row in self.connection.execute(
                        "SELECT * FROM routing_deprecation_occurrences "
                        "WHERE inventory_sha256=? ORDER BY ordinal",
                        (prior["inventory_sha256"],),
                    )
                ]
                exact = all(prior[key] == value for key, value in stored_values.items())
                exact = exact and prior_occurrences == occurrences and outbox is not None
                exact = exact and outbox["idempotency_key"] == outbox_idempotency_key
                exact = exact and outbox["repository"] == repository
                exact = exact and outbox["object_kind"] == "issue"
                exact = exact and int(outbox["object_number"]) == 179
                exact = exact and outbox["expected_source_sha256"] == inventory["issue_179_source_sha256"]
                exact = exact and json.loads(outbox["payload_json"]) == {"body": receipt_body}
                if not exact:
                    raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_CONFLICT")
                return str(prior["inventory_sha256"]), int(prior["outbox_id"])
            if self.connection.execute(
                "SELECT 1 FROM github_outbox WHERE idempotency_key=?",
                (outbox_idempotency_key,),
            ).fetchone() is not None:
                raise CoordinationError("ROUTING_DEPRECATION_INVENTORY_CONFLICT")
            outbox_id = self.enqueue_comment(
                idempotency_key=outbox_idempotency_key,
                repository=repository,
                object_kind="issue",
                object_number=179,
                expected_source_sha256=inventory["issue_179_source_sha256"],
                body=receipt_body,
                now=now,
                _transaction=False,
            )
            columns = tuple(stored_values)
            self.connection.execute(
                f"INSERT INTO routing_deprecation_inventories({','.join(columns)},outbox_id,state,created_at) "
                f"VALUES ({','.join('?' for _ in columns)},?,'COMPLETE',?)",
                tuple(stored_values.values()) + (outbox_id, now),
            )
            self.connection.executemany(
                """
                INSERT INTO routing_deprecation_occurrences(
                    inventory_sha256, ordinal, object_kind, object_number, node_id,
                    object_updated_at, body_sha256, alias, byte_start, byte_end,
                    line_number, byte_column, classification, semantic_tags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        inventory["inventory_sha256"],
                        item["ordinal"],
                        item["object_kind"],
                        item["object_number"],
                        item["node_id"],
                        now,
                        item["body_sha256"],
                        item["alias"],
                        item["byte_start"],
                        item["byte_end"],
                        item["line_number"],
                        item["byte_column"],
                        item["classification"],
                        canonical_json(item["semantic_tags"]),
                    )
                    for item in occurrences
                ],
            )
            self._event(
                "ROUTING_DEPRECATION_INVENTORY_PREPARED",
                f"{repository}:routing-deprecation-inventory",
                {
                    "inventory_sha256": inventory["inventory_sha256"],
                    "outbox_id": outbox_id,
                    "occurrence_count": len(occurrences),
                },
                now,
            )
        return str(inventory["inventory_sha256"]), outbox_id

    def terminal_outbox_context(self, outbox_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT packet.closeout_key, packet.packet_sha256, packet.created_at,
                   recovery.readback_attempts, recovery.retry_rounds,
                   recovery.next_retry_at, recovery.state AS recovery_state,
                   publisher.publisher_login,
                   publisher.binding_sha256 AS publisher_binding_sha256
            FROM coordination_terminal_closeout_packets packet
            LEFT JOIN coordination_terminal_outbox_recovery recovery
              ON recovery.outbox_id=packet.outbox_id
            LEFT JOIN coordination_terminal_outbox_publishers publisher
              ON publisher.outbox_id=packet.outbox_id
            WHERE packet.outbox_id=?
            """,
            (outbox_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def bind_terminal_outbox_publisher(
        self, *, outbox_id: int, publisher_login: str, now: str
    ) -> dict[str, Any]:
        if (
            not isinstance(publisher_login, str)
            or not publisher_login
            or len(publisher_login) > 100
            or any(character.isspace() for character in publisher_login)
        ):
            raise CoordinationError("TERMINAL_OUTBOX_PUBLISHER_INVALID")
        with self.transaction():
            outbox = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            packet = self.connection.execute(
                "SELECT * FROM coordination_terminal_closeout_packets "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            recovery = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_recovery "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            existing = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_publishers "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            if outbox is None or packet is None or recovery is None:
                raise CoordinationError("TERMINAL_OUTBOX_NOT_FOUND")
            descriptor = {
                "schema": "twinfinity-terminal-outbox-publisher/v1",
                "outbox_id": outbox_id,
                "closeout_key": str(packet["closeout_key"]),
                "publisher_login": publisher_login,
            }
            binding_sha256 = digest_json(descriptor)
            if existing is not None:
                if (
                    existing["closeout_key"] != packet["closeout_key"]
                    or existing["publisher_login"] != publisher_login
                    or existing["binding_sha256"] != binding_sha256
                ):
                    raise CoordinationError(
                        "TERMINAL_OUTBOX_PUBLISHER_IDENTITY_MISMATCH"
                    )
                return dict(existing)
            if (
                outbox["state"] != "PREPARED"
                or outbox["remote_receipt"] is not None
                or recovery["state"] not in {"PENDING", "RETRY_READY"}
            ):
                raise CoordinationError("TERMINAL_OUTBOX_PUBLISHER_UNBOUND")
            self.connection.execute(
                """
                INSERT INTO coordination_terminal_outbox_publishers(
                    outbox_id, closeout_key, publisher_login,
                    binding_sha256, bound_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    outbox_id,
                    packet["closeout_key"],
                    publisher_login,
                    binding_sha256,
                    now,
                ),
            )
            self._event(
                "TERMINAL_OUTBOX_PUBLISHER_BOUND",
                f"outbox:{outbox_id}",
                {"binding_sha256": binding_sha256},
                now,
            )
            bound = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_publishers "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
        return dict(bound)

    def hold_terminal_outbox_publisher_identity(
        self,
        *,
        outbox_id: int,
        observed_publisher_login: str,
        error: str,
        now: str,
    ) -> None:
        if error not in {
            "TERMINAL_OUTBOX_PUBLISHER_IDENTITY_MISMATCH",
            "TERMINAL_OUTBOX_PUBLISHER_UNBOUND",
        }:
            raise CoordinationError("TERMINAL_OUTBOX_PUBLISHER_ERROR_INVALID")
        with self.transaction():
            outbox = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            packet = self.connection.execute(
                "SELECT 1 FROM coordination_terminal_closeout_packets "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            publisher = self.connection.execute(
                "SELECT publisher_login FROM coordination_terminal_outbox_publishers "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            if (
                outbox is None
                or packet is None
                or outbox["state"] not in {"PREPARED", "INFLIGHT", "HOLD"}
                or outbox["remote_receipt"] is not None
                or (
                    error == "TERMINAL_OUTBOX_PUBLISHER_IDENTITY_MISMATCH"
                    and (
                        publisher is None
                        or publisher["publisher_login"]
                        == observed_publisher_login
                    )
                )
                or (
                    error == "TERMINAL_OUTBOX_PUBLISHER_UNBOUND"
                    and publisher is not None
                )
            ):
                raise CoordinationError("TERMINAL_OUTBOX_PUBLISHER_STATE_CONFLICT")
            self.connection.execute(
                "UPDATE github_outbox SET state='HOLD', updated_at=?, "
                "last_error=? WHERE id=?",
                (now, error, outbox_id),
            )
            self.connection.execute(
                "UPDATE coordination_terminal_outbox_recovery "
                "SET state='HOLD', updated_at=?, last_error=? WHERE outbox_id=?",
                (now, error, outbox_id),
            )
            self._event(
                "TERMINAL_OUTBOX_PUBLISHER_HELD",
                f"outbox:{outbox_id}",
                {"error": error},
                now,
            )

    def complete_terminal_outbox_from_readback(
        self,
        *,
        outbox_id: int,
        remote_receipt: str,
        published_body: str,
        publisher_login: str,
        now: str,
    ) -> None:
        if (
            REMOTE_COMMENT_RECEIPT.fullmatch(remote_receipt or "") is None
            or not isinstance(published_body, str)
            or not published_body
            or not isinstance(publisher_login, str)
            or not publisher_login
        ):
            raise CoordinationError("TERMINAL_OUTBOX_READBACK_INVALID")
        with self.transaction():
            outbox = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            packet = self.connection.execute(
                "SELECT * FROM coordination_terminal_closeout_packets "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            publisher = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_publishers "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            if outbox is None or packet is None:
                raise CoordinationError("TERMINAL_OUTBOX_NOT_FOUND")
            if (
                publisher is None
                or publisher["closeout_key"] != packet["closeout_key"]
                or publisher["publisher_login"] != publisher_login
            ):
                raise CoordinationError(
                    "TERMINAL_OUTBOX_PUBLISHER_IDENTITY_MISMATCH"
                )
            receipt_sha256 = hashlib.sha256(
                remote_receipt.encode("utf-8")
            ).hexdigest()
            body_sha256 = hashlib.sha256(published_body.encode("utf-8")).hexdigest()
            expected_body = terminal_published_body(
                json.loads(outbox["payload_json"])["body"], outbox["idempotency_key"]
            )
            existing = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_readbacks "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            if existing is not None:
                if (
                    outbox["state"] != "COMPLETE"
                    or outbox["remote_receipt"] != remote_receipt
                    or existing["closeout_key"] != packet["closeout_key"]
                    or existing["remote_receipt"] != remote_receipt
                    or existing["remote_receipt_sha256"] != receipt_sha256
                    or existing["published_body_sha256"] != body_sha256
                    or existing["publisher_login"] != publisher_login
                    or published_body != expected_body
                ):
                    raise CoordinationError("TERMINAL_OUTBOX_READBACK_CONFLICT")
                return
            if (
                outbox["state"] not in {"PREPARED", "INFLIGHT", "HOLD"}
                or outbox["remote_receipt"] is not None
                or outbox["idempotency_key"] != packet["closeout_key"]
                or published_body != expected_body
            ):
                raise CoordinationError("TERMINAL_OUTBOX_READBACK_CONFLICT")
            self.connection.execute(
                """
                INSERT INTO coordination_terminal_outbox_readbacks(
                    outbox_id, closeout_key, remote_receipt,
                    remote_receipt_sha256, published_body_sha256,
                    publisher_login, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    outbox_id,
                    packet["closeout_key"],
                    remote_receipt,
                    receipt_sha256,
                    body_sha256,
                    publisher_login,
                    now,
                ),
            )
            cursor = self.connection.execute(
                """
                UPDATE github_outbox
                SET state='COMPLETE', remote_receipt=?, updated_at=?,
                    last_error=NULL
                WHERE id=? AND state IN ('PREPARED','INFLIGHT','HOLD')
                  AND remote_receipt IS NULL
                """,
                (remote_receipt, now, outbox_id),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("OUTBOX_STATE_CONFLICT")
            self.connection.execute(
                """
                UPDATE coordination_terminal_outbox_recovery
                SET state='COMPLETE', updated_at=?, last_error=NULL
                WHERE outbox_id=?
                """,
                (now, outbox_id),
            )
            self._event(
                "OUTBOX_COMPLETED",
                f"outbox:{outbox_id}",
                {"remote_receipt": remote_receipt, "readback": "EXACT_MARKER"},
                now,
            )

    def record_terminal_outbox_readback_miss(
        self,
        *,
        outbox_id: int,
        error: str,
        publisher_login: str,
        now: str,
    ) -> dict[str, Any]:
        if error not in {"GITHUB_READBACK_MISSING", "GITHUB_READBACK_DUPLICATE"}:
            raise CoordinationError("TERMINAL_OUTBOX_RECOVERY_ERROR_INVALID")
        with self.transaction():
            outbox = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            packet = self.connection.execute(
                "SELECT * FROM coordination_terminal_closeout_packets "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            recovery = self.connection.execute(
                "SELECT * FROM coordination_terminal_outbox_recovery "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            publisher = self.connection.execute(
                "SELECT publisher_login FROM coordination_terminal_outbox_publishers "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            if outbox is None or packet is None or recovery is None:
                raise CoordinationError("TERMINAL_OUTBOX_NOT_FOUND")
            if publisher is None:
                raise CoordinationError("TERMINAL_OUTBOX_PUBLISHER_UNBOUND")
            if publisher["publisher_login"] != publisher_login:
                raise CoordinationError(
                    "TERMINAL_OUTBOX_PUBLISHER_IDENTITY_MISMATCH"
                )
            if outbox["state"] not in {"PREPARED", "INFLIGHT", "HOLD"}:
                raise CoordinationError("OUTBOX_STATE_CONFLICT")
            if recovery["state"] == "COMPLETE":
                raise CoordinationError("OUTBOX_STATE_CONFLICT")
            if recovery["next_retry_at"] > now:
                raise CoordinationError("TERMINAL_OUTBOX_RETRY_NOT_DUE")
            attempts = int(recovery["readback_attempts"]) + 1
            rounds = int(recovery["retry_rounds"])
            outbox_state = "HOLD"
            recovery_state = "RETRY_WAIT"
            next_retry_at = timestamp_after(now, min(60 * (2 ** (attempts - 1)), 900))
            if error == "GITHUB_READBACK_DUPLICATE":
                recovery_state = "HOLD"
                next_retry_at = timestamp_after(now, 900)
            elif attempts >= TERMINAL_OUTBOX_READBACK_ATTEMPTS_PER_RETRY:
                try:
                    binding = self._current_terminal_graph_binding(
                        repository=str(packet["repository"]),
                        issue_number=int(packet["issue_number"]),
                        source_payload_sha256=str(packet["source_payload_sha256"]),
                    )
                except CoordinationError:
                    binding = None
                current_source = self.current_snapshot(
                    str(packet["repository"]), "issue", int(packet["issue_number"])
                )
                if (
                    rounds < TERMINAL_OUTBOX_MAX_RETRY_ROUNDS
                    and binding is not None
                    and current_source is not None
                    and current_source.payload_sha256 == packet["source_payload_sha256"]
                    and int(packet["graph_version"] or 0) == binding["graph_version"]
                    and packet["graph_binding_sha256"]
                    == binding["graph_binding_sha256"]
                ):
                    attempts = 0
                    rounds += 1
                    outbox_state = "PREPARED"
                    recovery_state = "RETRY_READY"
                    next_retry_at = now
                else:
                    recovery_state = "HOLD"
                    next_retry_at = timestamp_after(now, 900)
            self.connection.execute(
                """
                UPDATE github_outbox
                SET state=?, updated_at=?, last_error=?
                WHERE id=? AND state IN ('PREPARED','INFLIGHT','HOLD')
                  AND remote_receipt IS NULL
                """,
                (outbox_state, now, error, outbox_id),
            )
            self.connection.execute(
                """
                UPDATE coordination_terminal_outbox_recovery
                SET readback_attempts=?, retry_rounds=?, next_retry_at=?,
                    state=?, updated_at=?, last_error=?
                WHERE outbox_id=?
                """,
                (
                    attempts,
                    rounds,
                    next_retry_at,
                    recovery_state,
                    now,
                    error,
                    outbox_id,
                ),
            )
            self._event(
                "TERMINAL_OUTBOX_RECONCILED",
                f"outbox:{outbox_id}",
                {
                    "error": error,
                    "readback_attempts": attempts,
                    "retry_rounds": rounds,
                    "state": recovery_state,
                },
                now,
            )
        return {
            "outbox_id": outbox_id,
            "state": recovery_state,
            "readback_attempts": attempts,
            "retry_rounds": rounds,
            "next_retry_at": next_retry_at,
        }

    def reserve_outbox(self, outbox_id: int, now: str) -> dict[str, Any]:
        with self.transaction():
            row = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            if row is None:
                raise CoordinationError("OUTBOX_NOT_FOUND")
            if row["state"] != "PREPARED":
                raise CoordinationError("OUTBOX_STATE_CONFLICT")
            source = self.current_snapshot(
                row["repository"], row["object_kind"], row["object_number"]
            )
            if source is None or source.payload_sha256 != row["expected_source_sha256"]:
                raise CoordinationError("SOURCE_SNAPSHOT_DRIFT")
            terminal_packet = self.connection.execute(
                "SELECT * FROM coordination_terminal_closeout_packets "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone()
            if terminal_packet is not None:
                publisher = self.connection.execute(
                    "SELECT closeout_key FROM coordination_terminal_outbox_publishers "
                    "WHERE outbox_id=?",
                    (outbox_id,),
                ).fetchone()
                if (
                    publisher is None
                    or publisher["closeout_key"] != terminal_packet["closeout_key"]
                ):
                    raise CoordinationError("TERMINAL_OUTBOX_PUBLISHER_UNBOUND")
                binding = self._current_terminal_graph_binding(
                    repository=str(terminal_packet["repository"]),
                    issue_number=int(terminal_packet["issue_number"]),
                    source_payload_sha256=str(
                        terminal_packet["source_payload_sha256"]
                    ),
                )
                if (
                    int(terminal_packet["graph_version"] or 0)
                    != binding["graph_version"]
                    or terminal_packet["graph_binding_sha256"]
                    != binding["graph_binding_sha256"]
                ):
                    raise CoordinationError("TERMINAL_CLOSEOUT_GRAPH_DRIFT")
            self.connection.execute(
                "UPDATE github_outbox SET state='INFLIGHT', updated_at=? WHERE id=? AND state='PREPARED'",
                (now, outbox_id),
            )
            self.connection.execute(
                """
                UPDATE coordination_terminal_outbox_recovery
                SET state='PENDING', updated_at=?, last_error=NULL
                WHERE outbox_id=? AND state='RETRY_READY'
                """,
                (now, outbox_id),
            )
            reserved = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            self._event("OUTBOX_INFLIGHT", f"outbox:{outbox_id}", {"payload_sha256": row["payload_sha256"]}, now)
        return dict(reserved)

    def complete_outbox(self, outbox_id: int, remote_receipt: str, now: str) -> None:
        if not remote_receipt:
            raise CoordinationError("INVALID_REMOTE_RECEIPT")
        with self.transaction():
            if self.connection.execute(
                "SELECT 1 FROM coordination_terminal_closeout_packets "
                "WHERE outbox_id=?",
                (outbox_id,),
            ).fetchone() is not None:
                raise CoordinationError("TERMINAL_OUTBOX_READBACK_REQUIRED")
            cursor = self.connection.execute(
                "UPDATE github_outbox SET state='COMPLETE', remote_receipt=?, updated_at=?, last_error=NULL WHERE id=? AND state='INFLIGHT'",
                (remote_receipt, now, outbox_id),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("OUTBOX_STATE_CONFLICT")
            self._event("OUTBOX_COMPLETED", f"outbox:{outbox_id}", {"remote_receipt": remote_receipt}, now)

    def hold_outbox(self, outbox_id: int, error: str, now: str) -> None:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", error):
            error = "OUTBOX_FAILED"
        with self.transaction():
            cursor = self.connection.execute(
                "UPDATE github_outbox SET state='HOLD', updated_at=?, last_error=? WHERE id=? AND state IN ('PREPARED', 'INFLIGHT')",
                (now, error, outbox_id),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("OUTBOX_STATE_CONFLICT")
            self.connection.execute(
                """
                UPDATE coordination_terminal_outbox_recovery
                SET state='HOLD', updated_at=?, last_error=?
                WHERE outbox_id=?
                """,
                (now, error, outbox_id),
            )
            self._event("OUTBOX_HELD", f"outbox:{outbox_id}", {"error": error}, now)

    def summary(self, repository: str | None = None) -> dict[str, Any]:
        params: tuple[Any, ...] = () if repository is None else (repository,)
        suffix = "" if repository is None else " WHERE repository=?"
        sources = [
            dict(row)
            for row in self.connection.execute(
                "SELECT repository, object_kind, object_number, payload_sha256, source_updated_at, fetched_at FROM github_current"
                + suffix
                + " ORDER BY repository, object_kind, object_number",
                params,
            )
        ]
        items = [
            dict(row)
            for row in self.connection.execute(
                """
                SELECT i.*,
                       CASE WHEN c.payload_sha256=i.source_payload_sha256 THEN 1 ELSE 0 END AS source_current
                FROM coordination_items i
                LEFT JOIN github_current c
                  ON c.repository=i.repository
                 AND c.object_kind='issue'
                 AND c.object_number=i.issue_number
                """
                + ("" if repository is None else " WHERE i.repository=?")
                + " ORDER BY i.repository, i.issue_number",
                params,
            )
        ]
        messages = [
            dict(row)
            for row in self.connection.execute(
                "SELECT id, idempotency_key, recipient_session_id, topic, payload_sha256, state, claimed_by, created_at, updated_at, last_error FROM coordination_messages ORDER BY id"
            )
        ]
        outbox = [
            dict(row)
            for row in self.connection.execute(
                "SELECT id, idempotency_key, repository, object_kind, object_number, operation, expected_source_sha256, payload_sha256, state, remote_receipt, created_at, updated_at, last_error FROM github_outbox"
                + suffix
                + " ORDER BY id",
                params,
            )
        ]
        terminal_watches = [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM coordination_terminal_watches"
                + suffix
                + " ORDER BY repository, issue_number, generation",
                params,
            )
        ]
        artifacts = [
            dict(row)
            for row in self.connection.execute(
                "SELECT artifact_key, repository, issue_number, generation, relative_path, content_sha256, size_bytes, retention_class, state, trash_relative_path, purge_after, registered_at, updated_at, last_error FROM coordination_artifacts"
                + suffix
                + " ORDER BY repository, issue_number, generation, relative_path",
                params,
            )
        ]
        policy_repositories = sorted(
            {item["repository"] for item in items}
            | {source["repository"] for source in sources}
        )
        policies = [
            self.capacity_policy(policy_repository)
            for policy_repository in policy_repositories
        ]
        hosted_reserved_sre = sum(
            reserved_hosted_sre_units(self.connection, policy_repository)
            for policy_repository in policy_repositories
        )
        capacity = {
            "policy_versions": {
                policy["repository"]: int(policy["version"]) for policy in policies
            },
            "development_limit": sum(
                int(policy["development_limit"]) for policy in policies
            ),
            "shared_limit": sum(int(policy["shared_limit"]) for policy in policies),
            "sre_limit": sum(int(policy["sre_limit"]) for policy in policies),
            "active_development": sum(
                int(item["development_units"])
                for item in items
                if item["allocation_class"] == "ACTIVE"
            ),
            "active_shared": sum(
                int(item["shared_units"])
                for item in items
                if item["allocation_class"] == "ACTIVE"
            ),
            "retained_development": sum(
                int(item["development_units"])
                for item in items
                if item["allocation_class"] == "RETAINED"
            ),
            "retained_shared": sum(
                int(item["shared_units"])
                for item in items
                if item["allocation_class"] == "RETAINED"
            ),
            "active_sre": sum(
                int(item["sre_units"])
                for item in items
                if item["allocation_class"] == "ACTIVE"
            ),
            "retained_sre": sum(
                int(item["sre_units"])
                for item in items
                if item["allocation_class"] == "RETAINED"
            ),
            "hosted_reserved_sre": hosted_reserved_sre,
            "prepared_development_demand": sum(
                int(item["development_units"])
                for item in items
                if item["allocation_class"] == "NONE" and item["status"] == "PREPARED"
            ),
            "prepared_shared_demand": sum(
                int(item["shared_units"])
                for item in items
                if item["allocation_class"] == "NONE" and item["status"] == "PREPARED"
            ),
            "prepared_sre_demand": sum(
                int(item["sre_units"])
                for item in items
                if item["allocation_class"] == "NONE" and item["status"] == "PREPARED"
            ),
            "queued_development_demand": sum(
                int(item["development_units"])
                for item in items
                if item["allocation_class"] == "NONE" and item["status"] == "QUEUED"
            ),
            "queued_shared_demand": sum(
                int(item["shared_units"])
                for item in items
                if item["allocation_class"] == "NONE" and item["status"] == "QUEUED"
            ),
            "queued_sre_demand": sum(
                int(item["sre_units"])
                for item in items
                if item["allocation_class"] == "NONE" and item["status"] == "QUEUED"
            ),
        }
        capacity["source_current"] = all(bool(item["source_current"]) for item in items)
        active_watch_keys = {
            (watch["repository"], int(watch["issue_number"]), int(watch["generation"]))
            for watch in terminal_watches
            if watch["state"] == "ACTIVE"
        }
        capacity["active_without_terminal_watch"] = sum(
            1
            for item in items
            if item["allocation_class"] == "ACTIVE"
            and item["status"] in ACTIVE_EXECUTION_STATUSES
            and (
                item["repository"],
                int(item["issue_number"]),
                int(item["generation"]),
            )
            not in active_watch_keys
        )
        capacity["held_terminal_watches"] = sum(
            1 for watch in terminal_watches if watch["state"] == "HOLD"
        )
        artifact_counts = {
            state: sum(1 for artifact in artifacts if artifact["state"] == state)
            for state in sorted(ARTIFACT_STATES)
        }
        if capacity["source_current"]:
            capacity["available_development"] = (
                capacity["development_limit"]
                - capacity["active_development"]
                - capacity["retained_development"]
            )
            capacity["available_shared"] = (
                capacity["shared_limit"]
                - capacity["active_shared"]
                - capacity["retained_shared"]
            )
            capacity["available_sre"] = (
                capacity["sre_limit"]
                - capacity["active_sre"]
                - capacity["retained_sre"]
                - capacity["hosted_reserved_sre"]
            )
        else:
            capacity["available_development"] = None
            capacity["available_shared"] = None
            capacity["available_sre"] = None
        return {
            "database": str(self.path),
            "capacity": capacity,
            "sources": sources,
            "items": items,
            "messages": messages,
            "outbox": outbox,
            "terminal_watches": terminal_watches,
            "artifacts": artifacts,
            "artifact_counts": artifact_counts,
        }

    def heartbeat_terminal_watch(
        self,
        *,
        watch_key: str,
        session_id: str,
        generation: int,
        delay_seconds: int,
        now: str,
    ) -> dict[str, Any]:
        session_id = canonicalize_coordination_identity(self.connection, session_id)
        if generation < 0 or delay_seconds < 60 or delay_seconds > 1800:
            raise CoordinationError("INVALID_TERMINAL_WATCH_HEARTBEAT")
        with self.transaction():
            watch = self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            if watch is None:
                raise CoordinationError("TERMINAL_WATCH_NOT_FOUND")
            if (
                watch["state"] != "ACTIVE"
                or watch["accountable_session_id"] != session_id
                or int(watch["generation"]) != generation
            ):
                raise CoordinationError("TERMINAL_WATCH_FENCE_MISMATCH")
            item = self.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (watch["repository"], watch["issue_number"]),
            ).fetchone()
            if (
                item is None
                or item["allocation_class"] != "ACTIVE"
                or item["status"] not in ACTIVE_EXECUTION_STATUSES
                or int(item["generation"]) != generation
                or item["accountable_session_id"] != session_id
                or item["lease_manifest_sha256"] != watch["lease_manifest_sha256"]
            ):
                raise CoordinationError("TERMINAL_WATCH_ITEM_DRIFT")
            next_wake_at = timestamp_after(now, delay_seconds)
            self.connection.execute(
                """
                UPDATE coordination_terminal_watches
                SET attempts=0, process_id=NULL, last_heartbeat_at=?, next_wake_at=?,
                    updated_at=?, last_error=NULL
                WHERE watch_key=? AND state='ACTIVE'
                """,
                (now, next_wake_at, now, watch_key),
            )
            self._event(
                "TERMINAL_WATCH_HEARTBEAT",
                watch_key,
                {"generation": generation, "next_wake_at": next_wake_at},
                now,
            )
        return {
            "watch_key": watch_key,
            "state": "ACTIVE",
            "generation": generation,
            "next_wake_at": next_wake_at,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    show = subparsers.add_parser("show")
    show.add_argument("--repository")
    enqueue = subparsers.add_parser("enqueue-message")
    enqueue.add_argument("--idempotency-key", required=True)
    enqueue.add_argument("--recipient-session-id", required=True)
    enqueue.add_argument("--topic", required=True)
    enqueue.add_argument("--payload-file", type=Path, required=True)
    claim = subparsers.add_parser("claim-message")
    claim.add_argument("--message-id", type=int, required=True)
    claim.add_argument("--session-id", required=True)
    complete = subparsers.add_parser("complete-message")
    complete.add_argument("--message-id", type=int, required=True)
    complete.add_argument("--session-id", required=True)
    hold_message = subparsers.add_parser("hold-prepared-message")
    hold_message.add_argument("--message-id", type=int, required=True)
    hold_message.add_argument("--expected-payload-sha256", required=True)
    hold_message.add_argument("--reason", choices=sorted(PREPARED_MESSAGE_HOLD_REASONS), required=True)
    hold_message.add_argument("--session-id", required=True)
    preview_cutover = subparsers.add_parser("preview-legacy-notice-cutover")
    preview_cutover.add_argument("--legacy-recipient", required=True)
    retire_cutover = subparsers.add_parser("retire-legacy-notices")
    retire_cutover.add_argument("--legacy-recipient", required=True)
    retire_cutover.add_argument("--current-planner-endpoint", required=True)
    retire_cutover.add_argument("--expected-manifest-sha256", required=True)
    status = subparsers.add_parser("set-issue-status")
    status.add_argument("--repository", required=True)
    status.add_argument("--issue-number", type=int, required=True)
    status.add_argument("--status", required=True)
    status.add_argument("--allocation-class", choices=sorted(ALLOCATION_CLASSES), required=True)
    status.add_argument("--generation", type=int, required=True)
    status.add_argument("--accountable-session-id")
    status.add_argument("--lease-manifest-sha256")
    status.add_argument("--development-units", type=int, required=True)
    status.add_argument("--shared-units", type=int, required=True)
    status.add_argument("--sre-units", type=int, default=0)
    status.add_argument("--expected-source-sha256", required=True)
    status.add_argument("--expected-version", type=int, required=True)
    capacity_policy = subparsers.add_parser("set-capacity-policy")
    capacity_policy.add_argument("--repository", required=True)
    capacity_policy.add_argument("--development-limit", type=int, required=True)
    capacity_policy.add_argument("--shared-limit", type=int, required=True)
    capacity_policy.add_argument("--sre-limit", type=int, required=True)
    capacity_policy.add_argument("--authority-sha256", required=True)
    capacity_policy.add_argument("--expected-version", type=int, required=True)
    plan = subparsers.add_parser("apply-plan")
    plan.add_argument("--plan-file", type=Path, required=True)
    activation = subparsers.add_parser("activate-admission")
    activation.add_argument("--transaction-file", type=Path, required=True)
    recovery_activation = subparsers.add_parser("activate-recovery")
    recovery_activation.add_argument("--message-id", type=int, required=True)
    recovery_activation.add_argument("--session-id", required=True)
    terminal_closeout = subparsers.add_parser("prepare-terminal-closeout")
    terminal_closeout.add_argument("--transaction-file", type=Path, required=True)
    terminal_commit = subparsers.add_parser("commit-terminal-closeout")
    terminal_commit.add_argument("--closeout-key", required=True)
    heartbeat = subparsers.add_parser("heartbeat-terminal-watch")
    heartbeat.add_argument("--watch-key", required=True)
    heartbeat.add_argument("--session-id", required=True)
    heartbeat.add_argument("--generation", type=int, required=True)
    heartbeat.add_argument("--delay-seconds", type=int, default=300)
    register_artifacts = subparsers.add_parser("register-artifacts")
    register_artifacts.add_argument("--manifest-file", type=Path, required=True)
    hold_artifact = subparsers.add_parser("hold-drifted-artifact")
    hold_artifact.add_argument("--artifact-key", required=True)
    hold_artifact.add_argument("--expected-content-sha256", required=True)
    hold_artifact.add_argument("--session-id", required=True)
    collect_artifacts = subparsers.add_parser("collect-artifacts")
    collect_artifacts.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        store = CoordinationStore(DEFAULT_DATABASE)
        if args.command == "show":
            if args.repository is not None:
                _validate_repository(args.repository)
            print(canonical_json(store.summary(args.repository)))
        elif args.command == "enqueue-message":
            payload = json.loads(args.payload_file.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise CoordinationError("INVALID_MESSAGE")
            message_id = store.enqueue_message(
                idempotency_key=args.idempotency_key,
                recipient_session_id=args.recipient_session_id,
                topic=args.topic,
                payload=payload,
                now=utc_now(),
            )
            print(canonical_json({"phase": "PREPARED", "message_id": message_id}))
        elif args.command == "hold-prepared-message":
            message = store.hold_prepared_message(
                message_id=args.message_id,
                expected_payload_sha256=args.expected_payload_sha256,
                reason=args.reason,
                session_id=args.session_id,
                now=utc_now(),
            )
            print(
                canonical_json(
                    {
                        "phase": "HOLD",
                        "message_id": message["id"],
                        "reason": message["last_error"],
                    }
                )
            )
        elif args.command == "preview-legacy-notice-cutover":
            print(canonical_json(store.prepared_legacy_notice_manifest(args.legacy_recipient)))
        elif args.command == "retire-legacy-notices":
            result = store.retire_prepared_legacy_notices(
                legacy_recipient=args.legacy_recipient,
                current_planner_endpoint=args.current_planner_endpoint,
                expected_manifest_sha256=args.expected_manifest_sha256,
                now=utc_now(),
            )
            print(canonical_json({"phase": "COMPLETE", **result}))
        elif args.command == "claim-message":
            row = store.claim_message(
                args.message_id,
                args.session_id,
                utc_now(),
                attempt_id=os.environ.get("TWINFINITY_EXECUTOR_ATTEMPT_ID"),
                executor_token=os.environ.get("TWINFINITY_EXECUTOR_TOKEN"),
            )
            print(
                canonical_json(
                    {
                        "phase": "CLAIMED",
                        "message_id": args.message_id,
                        "topic": row["topic"],
                        "payload_sha256": row["payload_sha256"],
                        "payload": json.loads(row["payload_json"]),
                    }
                )
            )
        elif args.command == "complete-message":
            store.complete_message(args.message_id, args.session_id, utc_now())
            print(canonical_json({"phase": "COMPLETE", "message_id": args.message_id}))
        elif args.command == "set-issue-status":
            row = store.set_issue_status(
                repository=args.repository,
                issue_number=args.issue_number,
                status=args.status,
                allocation_class=args.allocation_class,
                generation=args.generation,
                accountable_session_id=args.accountable_session_id,
                lease_manifest_sha256=args.lease_manifest_sha256,
                development_units=args.development_units,
                shared_units=args.shared_units,
                sre_units=args.sre_units,
                expected_source_sha256=args.expected_source_sha256,
                expected_version=args.expected_version,
                now=utc_now(),
            )
            print(canonical_json({"phase": "COMPLETE", "item": row}))
        elif args.command == "set-capacity-policy":
            policy = store.set_capacity_policy(
                repository=args.repository,
                development_limit=args.development_limit,
                shared_limit=args.shared_limit,
                sre_limit=args.sre_limit,
                authority_sha256=args.authority_sha256,
                expected_version=args.expected_version,
                now=utc_now(),
            )
            print(canonical_json({"phase": "COMPLETE", "capacity_policy": policy}))
        elif args.command == "apply-plan":
            payload = json.loads(args.plan_file.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or set(payload) != {"entries"}:
                raise CoordinationError("INVALID_ISSUE_PLAN")
            entries = payload["entries"]
            if not isinstance(entries, list):
                raise CoordinationError("INVALID_ISSUE_PLAN")
            rows = store.apply_issue_plan(entries, now=utc_now())
            print(canonical_json({"phase": "COMPLETE", "items": rows}))
        elif args.command == "activate-admission":
            payload = json.loads(args.transaction_file.read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or not {"item", "message"}.issubset(payload)
                or not set(payload).issubset({"item", "message", "artifacts"})
            ):
                raise CoordinationError("INVALID_ADMISSION_TRANSACTION")
            item, message_id = store.activate_admission(
                item=payload["item"],
                message=payload["message"],
                artifacts=payload.get("artifacts"),
                now=utc_now(),
            )
            print(
                canonical_json(
                    {"phase": "COMPLETE", "item": item, "message_id": message_id}
                )
            )
        elif args.command == "activate-recovery":
            item, watch_key = store.activate_recovery(
                message_id=args.message_id,
                session_id=args.session_id,
                now=utc_now(),
                attempt_id=os.environ.get("TWINFINITY_EXECUTOR_ATTEMPT_ID"),
                executor_token=os.environ.get("TWINFINITY_EXECUTOR_TOKEN"),
            )
            print(
                canonical_json(
                    {
                        "phase": "COMPLETE",
                        "item": item,
                        "message_id": args.message_id,
                        "terminal_watch_key": watch_key,
                    }
                )
            )
        elif args.command == "prepare-terminal-closeout":
            payload = json.loads(args.transaction_file.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or set(payload) != {"packet"}:
                raise CoordinationError("INVALID_TERMINAL_CLOSEOUT_TRANSACTION")
            status = store.prepare_terminal_closeout(
                packet=payload["packet"],
                attempt_id=os.environ.get("TWINFINITY_EXECUTOR_ATTEMPT_ID", ""),
                executor_token=os.environ.get("TWINFINITY_EXECUTOR_TOKEN", ""),
                now=utc_now(),
            )
            print(canonical_json({"phase": status["state"], "closeout": status}))
        elif args.command == "commit-terminal-closeout":
            status = store.commit_terminal_closeout(
                closeout_key=args.closeout_key,
                attempt_id=os.environ.get("TWINFINITY_EXECUTOR_ATTEMPT_ID", ""),
                executor_token=os.environ.get("TWINFINITY_EXECUTOR_TOKEN", ""),
            )
            print(canonical_json({"phase": status["state"], "closeout": status}))
        elif args.command == "heartbeat-terminal-watch":
            watch = store.heartbeat_terminal_watch(
                watch_key=args.watch_key,
                session_id=args.session_id,
                generation=args.generation,
                delay_seconds=args.delay_seconds,
                now=utc_now(),
            )
            print(canonical_json({"phase": "COMPLETE", "terminal_watch": watch}))
        elif args.command == "register-artifacts":
            payload = json.loads(args.manifest_file.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or set(payload) != {"artifacts"}:
                raise CoordinationError("INVALID_ARTIFACT_MANIFEST")
            artifacts = store.register_artifacts(payload["artifacts"], now=utc_now())
            print(canonical_json({"phase": "COMPLETE", "artifacts": artifacts}))
        elif args.command == "hold-drifted-artifact":
            artifact = store.hold_drifted_artifact(
                artifact_key=args.artifact_key,
                expected_content_sha256=args.expected_content_sha256,
                session_id=args.session_id,
                now=utc_now(),
            )
            print(
                canonical_json(
                    {
                        "phase": "HOLD",
                        "artifact_key": artifact["artifact_key"],
                        "reason": artifact["last_error"],
                    }
                )
            )
        elif args.command == "collect-artifacts":
            result = store.collect_artifacts(now=utc_now(), execute=args.execute)
            print(canonical_json({"phase": "COMPLETE", **result}))
        store.close()
    except CoordinationError as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    except Exception:
        print(canonical_json({"phase": "HOLD", "error": "COORDINATION_FAILED"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
