#!/usr/bin/env python3
"""Validate and persist the rolling two-candidate Kanban pull buffer."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from typing import Any, Callable

from coordination_store import (
    DEFAULT_DATABASE,
    UNCLAIMED_ADMISSION_RECOVERY_NOTICE_SCHEMA,
    UNCLAIMED_ADMISSION_RETRY_REASON,
    CoordinationError,
    CoordinationStore,
    artifact_registry_identity,
    artifact_registry_identity_matches,
    canonical_json,
    parse_structured_lease_manifest,
    terminal_watch_key,
    unclaimed_admission_exhaustion_payload,
    unclaimed_admission_recovery_notice_payload,
    validate_admission_dispatch_bindings,
)
from executor_registry import (
    RegistryError,
    applied_endpoint_rotation_chain,
    canonical_repository_scope,
    canonical_endpoint_id,
    configured_identity_role,
    current_endpoint,
    identity_role,
    require_current_endpoint_identity,
)
from owner_safe_sqlite import open_owner_database_readonly, prepare_owner_database
from portfolio_graph import (
    PortfolioGraphError,
    _schedule_decision,
    enqueue_convergence_dirty_event,
    ensure_portfolio_graph_schema,
    evaluate_graph,
    graph_payload,
    replace_graph,
    reserved_hosted_sre_units,
    validate_graph_plan,
)
from repository_delivery_policy import (
    HARNESS_REPOSITORY,
    canonical_harness_standing_controls,
    harness_standing_authority_error,
    harness_standing_authority_provenance_error,
)


SCHEMA = "twinfinity-kanban-pull-buffer/v2"
READY_SCHEMA = "twinfinity-kanban-pull-buffer/v3"
FINALIZATION_SCHEMA = "twinfinity-kanban-ready-finalization/v1"
DRIFT_RECOVERY_SCHEMA = "twinfinity-kanban-ready-drift-recovery/v1"
UNCLAIMED_ADMISSION_RECOVERY_SCHEMA = "twinfinity-unclaimed-admission-recovery/v1"
UNCLAIMED_ADMISSION_REFILL_TRIGGER = "UNCLAIMED_ADMISSION_RECOVERY_REFILL"
ZERO_WIP_PREPARATION_SCHEMA = "twinfinity-repository-zero-wip-prepare/v1"
LEGACY_UNCLAIMED_ADMISSION_RECOVERY_REASON = (
    "LEGACY_UNCLAIMED_ADMISSION_RECOVERY"
)
LEGACY_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA = (
    "twinfinity-legacy-unclaimed-admission-recovery-descriptor/v1"
)
LEGACY_UNCLAIMED_ADMISSION_HOLD_REASON = "WAKE_RETRY_EXHAUSTED"
LEGACY_UNCLAIMED_ADMISSION_ATTEMPT_ERROR = "EXECUTOR_TARGET_NO_PROGRESS"
CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON = (
    "CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY"
)
CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA = (
    "twinfinity-cutover-held-unclaimed-admission-recovery-descriptor/v1"
)
CUTOVER_HELD_UNCLAIMED_ADMISSION_HOLD_REASON = (
    "SUPERSEDED_BY_ROLE_ENDPOINT_CUTOVER"
)
UNCLAIMED_RECOVERY_REQUEST_KEYS = set("""
schema repository issue_number planner_session_id generation retained_item_version
source_payload_sha256 current_source_payload_sha256 accountable_session_id
lease_manifest_sha256 admission_message_id admission_payload_sha256 wake_key
wake_attempts target_progress_sha256 watch_key recovery_notice_message_id
recovery_reason
""".split())
LEGACY_RECOVERY_DESCRIPTOR_KEYS = {"schema", "evidence", "evidence_sha256"}
LEGACY_RECOVERY_EVIDENCE_KEYS = set("""
repository issue_number generation retained_item_version source_payload_sha256
accountable_session_id lease_manifest_sha256 admission_message_id
admission_payload_sha256 wake_key wake_attempts target_progress_sha256 watch_key
historical_recipient hold_reason wake_last_attempt_at watch_updated_at
item_updated_at ready_candidate_id ready_finalization_id readiness_campaign_id
readiness_receipt_id finalization_dirty_event_id ready_finalization_sha256
normalization_events endpoint_rotation executor_attempt
""".split())
LEGACY_RECOVERY_EVENT_KEYS = {
    "id", "event_type", "entity_key", "payload_sha256", "created_at"
}
LEGACY_RECOVERY_ROTATION_KEYS = {
    "change_id", "change_version", "before_item_version", "not_before"
}
LEGACY_RECOVERY_ATTEMPT_KEYS = {
    "attempt_id", "role", "endpoint_id", "target_kind", "target_key",
    "state", "exit_code", "last_error",
}
CUTOVER_HELD_RECOVERY_DESCRIPTOR_KEYS = {
    "schema", "evidence", "evidence_sha256"
}
CUTOVER_HELD_RECOVERY_EVIDENCE_KEYS = set("""
repository issue_number generation retained_item_version source_payload_sha256
current_source_payload_sha256 accountable_session_id lease_manifest_sha256
admission_message_id admission_payload_sha256 wake_key wake_attempts
target_progress_sha256 watch_key role historical_recipient hold_reason
message_updated_at wake_last_attempt_at wake_updated_at watch_updated_at
item_updated_at capacity ready_candidate_id ready_finalization_id
readiness_campaign_id readiness_receipt_id finalization_dirty_event_id
ready_finalization_sha256 cutover_events endpoint_rotation executor_attempt
""".split())
CUTOVER_HELD_RECOVERY_EVENT_KEYS = {
    "id", "event_type", "entity_key", "payload_sha256", "created_at"
}
CUTOVER_HELD_RECOVERY_ATTEMPT_KEYS = {
    "attempt_id", "role", "endpoint_id", "target_kind", "target_key",
    "target_progress_sha256", "terminal_progress_sha256",
    "lineage_repository", "lineage_issue_number", "lineage_generation",
    "lineage_lease_sha256", "lineage_sha256", "state", "exit_code",
    "updated_at", "last_error",
}
CUTOVER_HELD_RECOVERY_CAPACITY_KEYS = {
    "development_units", "shared_units", "sre_units"
}
STATES = {"PREPARED_NOT_READY", "READY"}
VERTICALITY = {"END_TO_END", "BOUNDED_ENABLER"}
ZERO_WIP_STATUSES = {"PREPARED", "QUEUED", "READY"}


class PullBufferError(ValueError):
    """Typed fail-closed pull-buffer validation error."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PullBufferError("PULL_BUFFER_PACKET_DUPLICATE_KEY")
        result[key] = value
    return result


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _legacy_recovery_stable_source(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip only the non-authorizing dashboard projection fields."""

    stable = {
        key: value
        for key, value in payload.items()
        if key != "updated_at" and not key.startswith("_projection_")
    }
    labels = stable.get("labels")
    if isinstance(labels, list):
        stable["labels"] = [
            label
            for label in labels
            if not (
                label == "agent-ready"
                or (isinstance(label, dict) and label.get("name") == "agent-ready")
            )
        ]
    return stable


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


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _descriptor_observation(descriptor: int, raw: bytes) -> dict[str, Any]:
    metadata = os.fstat(descriptor)
    return {
        "descriptor": descriptor,
        "raw": raw,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": int(metadata.st_size),
        "device_id": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "mode": int(metadata.st_mode),
        "uid": int(metadata.st_uid),
        "nlink": int(metadata.st_nlink),
        "mtime_ns": int(metadata.st_mtime_ns),
        "ctime_ns": int(metadata.st_ctime_ns),
    }


def _descriptor_is_current(observation: dict[str, Any]) -> bool:
    descriptor = observation.get("descriptor")
    if type(descriptor) is not int or descriptor < 0:
        return False
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_nlink == 1
        and int(metadata.st_size) == observation.get("size_bytes")
        and int(metadata.st_dev) == observation.get("device_id")
        and int(metadata.st_ino) == observation.get("inode")
        and int(metadata.st_mode) == observation.get("mode")
        and int(metadata.st_uid) == observation.get("uid")
        and int(metadata.st_nlink) == observation.get("nlink")
        and int(metadata.st_mtime_ns) == observation.get("mtime_ns")
        and int(metadata.st_ctime_ns) == observation.get("ctime_ns")
    )


def _observation_snapshot_is_authentic(
    connection: sqlite3.Connection, observation: dict[str, Any] | None
) -> bool:
    """Reject caller-mutated prereads before they can authorize recovery."""

    if not isinstance(observation, dict) or not _descriptor_is_current(observation):
        return False
    raw = observation.get("raw")
    packet = observation.get("packet")
    if not isinstance(raw, bytes) or not isinstance(packet, dict):
        return False
    try:
        if (
            _read_descriptor(observation["descriptor"]) != raw
            or json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
            != packet
        ):
            return False
    except (OSError, UnicodeError, json.JSONDecodeError, PullBufferError):
        return False
    artifacts = observation.get("admission_artifacts")
    if not isinstance(artifacts, list):
        return False
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not _descriptor_is_current(artifact):
            return False
        try:
            if _read_descriptor(artifact["descriptor"]) != artifact.get("raw"):
                return False
        except OSError:
            return False
        if not artifact.get("existing_only"):
            continue
        registered = artifact.get("entry", {}).get("registered_artifact")
        if not isinstance(registered, dict):
            return False
        current = connection.execute(
            "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
            (registered.get("artifact_key"),),
        ).fetchone()
        if current is None or not artifact_registry_identity_matches(
            registered, current
        ):
            return False
    return True


def close_candidate_observations(observations: dict[int, dict[str, Any]]) -> None:
    """Close descriptors retained for in-transaction identity revalidation."""

    for observation in observations.values():
        descriptors = [observation]
        descriptors.extend(observation.get("admission_artifacts") or [])
        for item in descriptors:
            descriptor = item.get("descriptor") if isinstance(item, dict) else None
            if type(descriptor) is int and descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                item["descriptor"] = -1


def _require_finalizer_descriptors_current(
    packet_observation: dict[str, Any],
    admission_observations: list[dict[str, Any]],
    prepared_observation: dict[str, Any] | None,
) -> None:
    """Close the finalizer TOCTOU window for both first-run and replay paths."""

    if (
        not _descriptor_is_current(packet_observation)
        or _read_descriptor(packet_observation["descriptor"])
        != packet_observation["raw"]
        or prepared_observation is None
        or prepared_observation.get("error") is not None
        or not _descriptor_is_current(prepared_observation)
        or any(
            not _descriptor_is_current(observation)
            for observation in admission_observations
        )
    ):
        raise PullBufferError("PULL_BUFFER_ARTIFACT_DRIFT")


def _database_path(connection: sqlite3.Connection) -> Path:
    row = connection.execute("PRAGMA database_list").fetchone()
    if row is None or not row[2]:
        raise PullBufferError("PULL_BUFFER_DATABASE_PATH_MISSING")
    return Path(row[2])


def _open_relative_file(root: Path, relative_path: str) -> int:
    parts = Path(relative_path).parts
    if (
        not parts
        or Path(relative_path).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise PullBufferError("PULL_BUFFER_ARTIFACT_UNSAFE")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    descriptors = [os.open(root, directory_flags)]
    try:
        for component in parts[:-1]:
            descriptors.append(os.open(component, directory_flags, dir_fd=descriptors[-1]))
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        descriptor = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
    except OSError as exc:
        raise PullBufferError("PULL_BUFFER_ARTIFACT_UNSAFE") from exc
    finally:
        for directory in reversed(descriptors):
            os.close(directory)
    return descriptor


def _open_packet(database: Path, packet_path: Path) -> tuple[int, str]:
    root = database.parent.resolve()
    supplied = packet_path if packet_path.is_absolute() else Path.cwd() / packet_path
    absolute = Path(os.path.abspath(supplied))
    try:
        relative = absolute.relative_to(root).as_posix()
    except ValueError as exc:
        raise PullBufferError("PULL_BUFFER_ARTIFACT_UNSAFE") from exc
    descriptor = _open_relative_file(root, relative)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise PullBufferError("PULL_BUFFER_ARTIFACT_UNSAFE")
    return descriptor, relative


def ensure_pull_buffer_schema(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        raise PullBufferError("PULL_BUFFER_SCHEMA_TRANSACTION_CONFLICT")
    try:
        connection.executescript(
            """
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS portfolio_pull_buffer_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            issue_number INTEGER NOT NULL CHECK(issue_number > 0),
            generation INTEGER NOT NULL CHECK(generation >= 0),
            item_version INTEGER NOT NULL CHECK(item_version >= 0),
            source_payload_sha256 TEXT NOT NULL,
            accepted_main_sha TEXT NOT NULL,
            graph_version INTEGER NOT NULL CHECK(graph_version > 0),
            capacity_policy_version INTEGER NOT NULL CHECK(capacity_policy_version > 0),
            lane_key TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('PREPARED_NOT_READY','READY')),
            verticality TEXT NOT NULL CHECK(verticality IN ('END_TO_END','BOUNDED_ENABLER')),
            development_units INTEGER NOT NULL CHECK(development_units >= 0),
            shared_units INTEGER NOT NULL CHECK(shared_units >= 0),
            sre_units INTEGER NOT NULL CHECK(sre_units >= 0),
            promotion_trigger TEXT NOT NULL,
            artifact_relative_path TEXT NOT NULL,
            artifact_content_sha256 TEXT NOT NULL,
            candidate_sha256 TEXT NOT NULL,
            readiness_campaign_id INTEGER,
            readiness_current_version INTEGER,
            readiness_plan_sha256 TEXT,
            readiness_receipt_id INTEGER,
            readiness_receipt_sha256 TEXT,
            registered_at TEXT NOT NULL,
            UNIQUE(repository, issue_number, candidate_sha256)
        );
        CREATE TABLE IF NOT EXISTS portfolio_pull_buffer_current (
            repository TEXT NOT NULL,
            issue_number INTEGER NOT NULL CHECK(issue_number > 0),
            candidate_id INTEGER NOT NULL UNIQUE,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(repository, issue_number),
            FOREIGN KEY(candidate_id) REFERENCES portfolio_pull_buffer_candidates(id)
        );
        CREATE TABLE IF NOT EXISTS portfolio_pull_buffer_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            graph_version INTEGER NOT NULL CHECK(graph_version > 0),
            capacity_policy_version INTEGER NOT NULL CHECK(capacity_policy_version > 0),
            accepted_main_sha TEXT NOT NULL,
            target_depth INTEGER NOT NULL CHECK(target_depth >= 0),
            healthy_depth INTEGER NOT NULL CHECK(healthy_depth >= 0),
            state TEXT NOT NULL CHECK(state IN ('HEALTHY','PULL_BUFFER_DEFICIT')),
            audit_sha256 TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(repository, audit_sha256)
        );
        CREATE TABLE IF NOT EXISTS portfolio_pull_buffer_retirements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            issue_number INTEGER NOT NULL CHECK(issue_number > 0),
            candidate_id INTEGER NOT NULL UNIQUE,
            reason_sha256 TEXT NOT NULL,
            reasons_json TEXT NOT NULL,
            retired_at TEXT NOT NULL,
            FOREIGN KEY(candidate_id) REFERENCES portfolio_pull_buffer_candidates(id)
        );
        CREATE TABLE IF NOT EXISTS portfolio_ready_finalizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            issue_number INTEGER NOT NULL CHECK(issue_number > 0),
            generation INTEGER NOT NULL CHECK(generation >= 0),
            prepared_candidate_id INTEGER NOT NULL UNIQUE,
            ready_candidate_id INTEGER NOT NULL UNIQUE,
            campaign_id INTEGER NOT NULL UNIQUE,
            receipt_id INTEGER NOT NULL UNIQUE,
            dirty_event_id INTEGER NOT NULL UNIQUE,
            finalization_sha256 TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(prepared_candidate_id) REFERENCES portfolio_pull_buffer_candidates(id),
            FOREIGN KEY(ready_candidate_id) REFERENCES portfolio_pull_buffer_candidates(id),
            FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
            FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id),
            FOREIGN KEY(dirty_event_id) REFERENCES portfolio_dirty_events(id)
        );
        CREATE TRIGGER IF NOT EXISTS portfolio_pull_buffer_candidates_immutable_update
        BEFORE UPDATE ON portfolio_pull_buffer_candidates
        BEGIN SELECT RAISE(ABORT, 'PULL_BUFFER_CANDIDATE_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_pull_buffer_candidates_immutable_delete
        BEFORE DELETE ON portfolio_pull_buffer_candidates
        BEGIN SELECT RAISE(ABORT, 'PULL_BUFFER_CANDIDATE_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_pull_buffer_audits_immutable_update
        BEFORE UPDATE ON portfolio_pull_buffer_audits
        BEGIN SELECT RAISE(ABORT, 'PULL_BUFFER_AUDIT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_pull_buffer_audits_immutable_delete
        BEFORE DELETE ON portfolio_pull_buffer_audits
        BEGIN SELECT RAISE(ABORT, 'PULL_BUFFER_AUDIT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_pull_buffer_retirements_immutable_update
        BEFORE UPDATE ON portfolio_pull_buffer_retirements
        BEGIN SELECT RAISE(ABORT, 'PULL_BUFFER_RETIREMENT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_pull_buffer_retirements_immutable_delete
        BEFORE DELETE ON portfolio_pull_buffer_retirements
        BEGIN SELECT RAISE(ABORT, 'PULL_BUFFER_RETIREMENT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_ready_finalizations_immutable_update
        BEFORE UPDATE ON portfolio_ready_finalizations
        BEGIN SELECT RAISE(ABORT, 'READY_FINALIZATION_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_ready_finalizations_immutable_delete
        BEFORE DELETE ON portfolio_ready_finalizations
        BEGIN SELECT RAISE(ABORT, 'READY_FINALIZATION_IMMUTABLE'); END;
            """
        )
        candidate_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(portfolio_pull_buffer_candidates)"
            )
        }
        for column, declaration in {
            "readiness_campaign_id": "INTEGER",
            "readiness_current_version": "INTEGER",
            "readiness_plan_sha256": "TEXT",
            "readiness_receipt_id": "INTEGER",
            "readiness_receipt_sha256": "TEXT",
        }.items():
            if column not in candidate_columns:
                connection.execute(
                    f"ALTER TABLE portfolio_pull_buffer_candidates "
                    f"ADD COLUMN {column} {declaration}"
                )
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def require_pull_buffer_schema(connection: sqlite3.Connection) -> None:
    required = {
        "portfolio_pull_buffer_candidates", "portfolio_pull_buffer_current",
        "portfolio_pull_buffer_audits", "portfolio_pull_buffer_retirements",
        "portfolio_ready_finalizations",
    }
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND (name LIKE 'portfolio_pull_buffer_%' "
            "OR name='portfolio_ready_finalizations')"
        )
    }
    if not required.issubset(present):
        raise PullBufferError("PULL_BUFFER_SCHEMA_MISSING")


def _require_nonempty_strings(value: Any, code: str) -> None:
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise PullBufferError(code)


def _validate_packet(packet: Any) -> None:
    if not isinstance(packet, dict) or packet.get("schema") not in {SCHEMA, READY_SCHEMA}:
        raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    ready_v3 = packet.get("schema") == READY_SCHEMA
    required_scalars = {
        "repository": str,
        "issue_number": int,
        "generation": int,
        "item_version_at_preparation": int,
        "source_payload_sha256": str,
        "accepted_main_at_preparation": str,
        "portfolio_graph_version": int,
        "state": str,
        "verticality": str,
        "owner_visible_outcome": str,
        "promotion_trigger": str,
    }
    expected_keys = set(required_scalars) | {
        "schema",
        "capacity_policy",
        "capacity_on_activation",
        "precomputed_collision_matrix",
        "preparation_complete",
        "promotion_checks_after_predecessor",
        "hard_stops",
    }
    if packet.get("verticality") == "BOUNDED_ENABLER":
        expected_keys.add("immediate_product_consumer")
    if "admission_transaction" in packet:
        expected_keys.add("admission_transaction")
    if ready_v3:
        expected_keys.update({"prepared_candidate", "readiness_binding"})
    if set(packet) != expected_keys:
        raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    for key, kind in required_scalars.items():
        value = packet.get(key)
        if type(value) is not kind or (kind is str and not value.strip()):
            raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    if packet["issue_number"] <= 0 or packet["generation"] < 0:
        raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    if packet["state"] not in STATES or packet["verticality"] not in VERTICALITY:
        raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    if ready_v3 and (
        packet["state"] != "READY" or "admission_transaction" not in packet
    ):
        raise PullBufferError("PULL_BUFFER_READY_FINALIZATION_INVALID")
    if packet["verticality"] == "BOUNDED_ENABLER" and not str(
        packet.get("immediate_product_consumer") or ""
    ).strip():
        raise PullBufferError("PULL_BUFFER_CONSUMER_MISSING")
    admission = packet.get("admission_transaction")
    if admission is not None:
        if (
            packet["state"] != "READY"
            or not isinstance(admission, dict)
            or not {"item", "message"}.issubset(admission)
            or not set(admission).issubset({"item", "message", "artifacts"})
            or not isinstance(admission["item"], dict)
            or not isinstance(admission["message"], dict)
            or (
                "artifacts" in admission
                and not isinstance(admission["artifacts"], list)
            )
        ):
            raise PullBufferError("PULL_BUFFER_ADMISSION_INVALID")
    if ready_v3:
        prepared = packet.get("prepared_candidate")
        readiness = packet.get("readiness_binding")
        if (
            not isinstance(prepared, dict)
            or set(prepared) != {"candidate_id", "candidate_sha256"}
            or type(prepared.get("candidate_id")) is not int
            or prepared["candidate_id"] <= 0
            or not isinstance(prepared.get("candidate_sha256"), str)
            or len(prepared["candidate_sha256"]) != 64
            or not isinstance(readiness, dict)
            or set(readiness) != {
                "campaign_id", "current_version", "plan_sha256",
                "receipt_id", "receipt_sha256",
            }
            or any(
                type(readiness.get(field)) is not int or readiness[field] <= 0
                for field in ("campaign_id", "current_version", "receipt_id")
            )
            or any(
                not isinstance(readiness.get(field), str)
                or len(readiness[field]) != 64
                for field in ("plan_sha256", "receipt_sha256")
            )
        ):
            raise PullBufferError("PULL_BUFFER_READINESS_BINDING_INVALID")
    policy = packet.get("capacity_policy")
    capacity = packet.get("capacity_on_activation")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"version", "development_limit", "shared_limit", "sre_limit"}
        or not isinstance(capacity, dict)
        or set(capacity) != {"development_units", "shared_units", "sre_units"}
    ):
        raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    for key in ("version", "development_limit", "shared_limit", "sre_limit"):
        minimum = 1 if key == "version" else 0
        if type(policy.get(key)) is not int or int(policy[key]) < minimum:
            raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    for key in ("development_units", "shared_units", "sre_units"):
        if type(capacity.get(key)) is not int or int(capacity[key]) < 0:
            raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
    _require_nonempty_strings(packet.get("preparation_complete"), "PULL_BUFFER_PREP_MISSING")
    _require_nonempty_strings(
        packet.get("promotion_checks_after_predecessor"),
        "PULL_BUFFER_PROMOTION_CHECKS_MISSING",
    )
    _require_nonempty_strings(packet.get("hard_stops"), "PULL_BUFFER_HARD_STOPS_MISSING")
    collisions = packet.get("precomputed_collision_matrix")
    if (
        not isinstance(collisions, list)
        or (not collisions and packet.get("repository") != HARNESS_REPOSITORY)
        or any(
        not isinstance(item, dict)
        or set(item) != {"other_issue", "disposition", "reason"}
        or type(item.get("other_issue")) is not int
        or item["other_issue"] <= 0
        or not str(item.get("disposition") or "").strip()
        or not str(item.get("reason") or "").strip()
        for item in collisions
        )
    ):
        raise PullBufferError("PULL_BUFFER_COLLISION_MATRIX_MISSING")


_PREPARED_PROMOTION_FIELDS = (
    "repository",
    "issue_number",
    "generation",
    "item_version_at_preparation",
    "source_payload_sha256",
    "accepted_main_at_preparation",
    "portfolio_graph_version",
    "capacity_policy",
    "capacity_on_activation",
)

_HARNESS_PREPARED_PROMOTION_FIELDS = (
    "verticality",
    "owner_visible_outcome",
    "precomputed_collision_matrix",
    "preparation_complete",
    "promotion_checks_after_predecessor",
    "hard_stops",
    "promotion_trigger",
)


def _require_prepared_promotion_preserved(
    prepared_packet: Any, ready_packet: dict[str, Any]
) -> None:
    strict_fields = _PREPARED_PROMOTION_FIELDS
    if ready_packet.get("repository") == HARNESS_REPOSITORY:
        strict_fields = strict_fields + _HARNESS_PREPARED_PROMOTION_FIELDS
    if (
        not isinstance(prepared_packet, dict)
        or prepared_packet.get("schema") != SCHEMA
        or prepared_packet.get("state") != "PREPARED_NOT_READY"
        or any(
            prepared_packet.get(field) != ready_packet.get(field)
            for field in strict_fields
        )
        or (
            ready_packet.get("repository") == HARNESS_REPOSITORY
            and prepared_packet.get("immediate_product_consumer")
            != ready_packet.get("immediate_product_consumer")
        )
    ):
        raise PullBufferError("PULL_BUFFER_PREPARED_PROMOTION_DRIFT")


def _graph_collision_matrix(
    connection: sqlite3.Connection,
    repository: str,
    graph_version: int,
    issue_number: int,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT other.issue_number AS other_issue, relation.reason
        FROM portfolio_graph_nodes target
        JOIN portfolio_graph_relations relation
          ON relation.repository=target.repository
         AND relation.graph_version=target.graph_version
         AND (relation.left_node_key=target.node_key
              OR relation.right_node_key=target.node_key)
        JOIN portfolio_graph_nodes other
          ON other.repository=target.repository
         AND other.graph_version=target.graph_version
         AND other.node_key=CASE
             WHEN relation.left_node_key=target.node_key
             THEN relation.right_node_key ELSE relation.left_node_key END
        WHERE target.repository=? AND target.graph_version=?
          AND target.issue_number=? AND relation.relation_kind='COLLISION'
        ORDER BY other.issue_number
        """,
        (repository, graph_version, issue_number),
    ).fetchall()
    matrix = [
        {
            "other_issue": int(row["other_issue"]),
            "disposition": "COLLISION",
            "reason": str(row["reason"]),
        }
        for row in rows
    ]
    if len({entry["other_issue"] for entry in matrix}) != len(matrix):
        raise PullBufferError("PULL_BUFFER_GRAPH_COLLISION_AMBIGUOUS")
    return matrix


def _registered_artifact(
    connection: sqlite3.Connection,
    descriptor: int,
    relative: str,
    *,
    repository: str,
    issue_number: int,
    generation: int,
) -> str:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise PullBufferError("PULL_BUFFER_ARTIFACT_UNSAFE")
    content_sha256 = _sha256_descriptor(descriptor)
    row = connection.execute(
        """
        SELECT content_sha256, size_bytes, device_id, inode, state
        FROM coordination_artifacts
        WHERE repository=? AND issue_number=? AND generation=? AND relative_path=?
        """,
        (repository, issue_number, generation, relative),
    ).fetchone()
    if (
        row is None
        or row["state"] != "REGISTERED"
        or row["content_sha256"] != content_sha256
        or int(row["size_bytes"]) != int(metadata.st_size)
        or int(row["device_id"]) != int(metadata.st_dev)
        or int(row["inode"]) != int(metadata.st_ino)
    ):
        raise PullBufferError("PULL_BUFFER_ARTIFACT_NOT_REGISTERED")
    return content_sha256


def _retire_pointer(
    connection: sqlite3.Connection,
    *,
    repository: str,
    issue_number: int,
    candidate_id: int,
    reasons: list[str],
    now: str,
) -> None:
    normalized = sorted(set(reasons))
    connection.execute(
        """
        INSERT OR IGNORE INTO portfolio_pull_buffer_retirements(
            repository, issue_number, candidate_id, reason_sha256,
            reasons_json, retired_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            repository,
            issue_number,
            candidate_id,
            digest_json(normalized),
            canonical_json(normalized),
            now,
        ),
    )
    connection.execute(
        "DELETE FROM portfolio_pull_buffer_current "
        "WHERE repository=? AND issue_number=? AND candidate_id=?",
        (repository, issue_number, candidate_id),
    )


def _load_admission_artifacts(
    connection: sqlite3.Connection,
    database: Path,
    admission: Any,
) -> list[dict[str, Any]]:
    if not isinstance(admission, dict):
        return []
    item = admission.get("item")
    message = admission.get("message")
    payload = message.get("payload") if isinstance(message, dict) else None
    if not isinstance(item, dict) or not isinstance(payload, dict):
        return []
    entries = admission.get("artifacts")
    existing_only = entries is None
    if existing_only:
        rows = connection.execute(
            """
            SELECT artifact_key, repository, issue_number, generation,
                   relative_path, content_sha256, size_bytes, device_id,
                   inode, retention_class, registered_at, state
            FROM coordination_artifacts
            WHERE repository=? AND issue_number=? AND generation=?
              AND content_sha256=? AND state='REGISTERED'
            ORDER BY artifact_key
            """,
            (
                item.get("repository"),
                item.get("issue_number"),
                item.get("generation"),
                payload.get("lease_manifest_sha256"),
            ),
        ).fetchall()
        entries = [
            {
                "repository": row["repository"],
                "issue_number": int(row["issue_number"]),
                "generation": int(row["generation"]),
                "path": str(database.parent / row["relative_path"]),
                "retention_class": row["retention_class"],
                "registered_artifact": artifact_registry_identity(row),
            }
            for row in rows
        ]
    if not isinstance(entries, list):
        return []
    observations: list[dict[str, Any]] = []
    try:
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise PullBufferError("PULL_BUFFER_ADMISSION_INVALID")
            descriptor, relative = _open_packet(database, Path(entry["path"]))
            try:
                raw = _read_descriptor(descriptor)
                observation = _descriptor_observation(descriptor, raw)
            except Exception:
                os.close(descriptor)
                raise
            observations.append(
                {
                    **observation,
                    "entry": dict(entry),
                    "relative_path": relative,
                    "existing_only": existing_only,
                }
            )
        return observations
    except Exception:
        close_candidate_observations({0: {"admission_artifacts": observations}})
        raise


def admission_binding_error(
    admission: Any,
    *,
    candidate: dict[str, Any],
    observed_main_sha: str,
    observation: dict[str, Any] | None,
    connection: sqlite3.Connection | None = None,
) -> str | None:
    """Validate the complete pre-activation envelope without mutating WIP."""

    if not isinstance(admission, dict):
        return "ADMISSION_PACKET_MISSING"
    if not {"item", "message"}.issubset(admission) or not set(admission).issubset(
        {"item", "message", "artifacts"}
    ):
        return "ADMISSION_PACKET_INVALID"
    item = admission.get("item")
    message = admission.get("message")
    if not isinstance(item, dict) or not isinstance(message, dict):
        return "ADMISSION_PACKET_INVALID"
    if set(message) != {"idempotency_key", "recipient_session_id", "topic", "payload"}:
        return "ADMISSION_PACKET_INVALID"
    payload = message.get("payload")
    source = payload.get("source") if isinstance(payload, dict) else None
    capacity = payload.get("capacity") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or not isinstance(source, dict) or not isinstance(capacity, dict):
        return "ADMISSION_PACKET_INVALID"
    issue_number = int(candidate["issue_number"])
    generation = int(candidate["generation"])
    item_version = int(candidate["item_version"])
    source_sha = candidate["source_payload_sha256"]
    if (
        candidate.get("accepted_main_sha") != observed_main_sha
        or item.get("repository") != candidate["repository"]
        or item.get("issue_number") != issue_number
        or item.get("generation") != generation
        or item.get("expected_version") != item_version
        or item.get("expected_source_sha256") != source_sha
        or item.get("status") not in {"ACTIVE", "ACTIVE_FENCED"}
        or item.get("allocation_class") != "ACTIVE"
        or payload.get("issue_number") != issue_number
        or payload.get("generation") != generation
        or payload.get("item_version") != item_version + 1
        or payload.get("base_sha") != observed_main_sha
        or source
        != {
            "repository": candidate["repository"],
            "object_kind": "issue",
            "object_number": issue_number,
            "payload_sha256": source_sha,
        }
    ):
        return "ADMISSION_PACKET_BINDING_DRIFT"
    recipient = message.get("recipient_session_id")
    topic = message.get("topic")
    expected_role = {
        "development.admission": "development",
        "sre.admission": "sre",
    }.get(topic)
    identities = (
        recipient,
        item.get("accountable_session_id"),
        payload.get("accountable_session_id"),
    )
    roles = [
        identity_role(connection, value)
        if connection is not None and isinstance(value, str)
        else configured_identity_role(value) if isinstance(value, str) else None
        for value in identities
    ]
    if expected_role is None or any(role != expected_role for role in roles):
        return "ADMISSION_RECIPIENT_DRIFT"
    if connection is not None:
        endpoint = current_endpoint(connection, expected_role)
        if endpoint is not None and any(
            canonical_endpoint_id(connection, value) != endpoint["endpoint_id"]
            or value != endpoint["endpoint_id"]
            for value in identities
        ):
            return "ADMISSION_RECIPIENT_NOT_CURRENT"
    try:
        validate_admission_dispatch_bindings(payload, topic=topic)
    except CoordinationError as exc:
        return str(exc)
    standing_authority_error = harness_standing_authority_error(payload)
    if standing_authority_error is not None:
        return standing_authority_error
    if connection is not None:
        provenance_error = harness_standing_authority_provenance_error(
            connection, payload
        )
        if provenance_error is not None:
            return provenance_error
    units = ("development_units", "shared_units", "sre_units")
    if any(type(item.get(field)) is not int or item.get(field) != capacity.get(field) for field in units):
        return "ADMISSION_CAPACITY_DRIFT"
    if (
        (topic == "development.admission" and int(item["sre_units"]) != 0)
        or (
            topic == "sre.admission"
            and (
                int(item["development_units"]) != 0
                or int(item["shared_units"]) != 0
                or int(item["sre_units"]) <= 0
            )
        )
    ):
        return "ADMISSION_CAPACITY_DRIFT"
    if (
        candidate.get("repository") == HARNESS_REPOSITORY
        and (
            topic != "development.admission"
            or int(item["development_units"]) != 0
            or int(item["shared_units"]) != 1
            or int(item["sre_units"]) != 0
            or payload.get("environment_root") is not None
            or payload.get("existing_environment") is not None
        )
    ):
        return "ADMISSION_HARNESS_SOURCE_CLASS_MISMATCH"
    lease_sha = payload.get("lease_manifest_sha256")
    if (
        not isinstance(lease_sha, str)
        or len(lease_sha) != 64
        or item.get("lease_manifest_sha256") != lease_sha
        or not isinstance(payload.get("branch"), str)
        or not isinstance(payload.get("worktree_path"), str)
    ):
        return "ADMISSION_LEASE_BINDING_DRIFT"
    artifact_observations = (
        observation.get("admission_artifacts")
        if isinstance(observation, dict)
        else None
    )
    if not isinstance(artifact_observations, list):
        return "ADMISSION_LEASE_ARTIFACT_MISSING"
    matching: list[dict[str, Any]] = []
    for artifact in artifact_observations:
        if not isinstance(artifact, dict) or not _descriptor_is_current(artifact):
            return "ADMISSION_LEASE_ARTIFACT_DRIFT"
        entry = artifact.get("entry")
        if (
            not isinstance(entry, dict)
            or entry.get("repository") != candidate["repository"]
            or entry.get("issue_number") != issue_number
            or entry.get("generation") != generation
        ):
            return "ADMISSION_LEASE_ARTIFACT_DRIFT"
        if artifact.get("existing_only"):
            registered = artifact.get("entry", {}).get("registered_artifact")
            if not isinstance(registered, dict) or connection is None:
                return "ADMISSION_LEASE_ARTIFACT_DRIFT"
            current_artifact = connection.execute(
                "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
                (registered.get("artifact_key"),),
            ).fetchone()
            if (
                current_artifact is None
                or current_artifact["state"] != "REGISTERED"
                or not artifact_registry_identity_matches(
                    registered, current_artifact
                )
                or registered.get("relative_path") != artifact.get("relative_path")
                or current_artifact["content_sha256"] != artifact.get("content_sha256")
                or int(current_artifact["size_bytes"]) != artifact.get("size_bytes")
                or int(current_artifact["device_id"]) != artifact.get("device_id")
                or int(current_artifact["inode"]) != artifact.get("inode")
            ):
                return "ADMISSION_LEASE_ARTIFACT_DRIFT"
        if artifact.get("content_sha256") != lease_sha:
            continue
        try:
            manifest = parse_structured_lease_manifest(artifact["raw"])
        except (CoordinationError, UnicodeDecodeError, json.JSONDecodeError):
            return "ADMISSION_LEASE_ARTIFACT_INVALID"
        matching.append(manifest)
    if len(matching) != 1:
        return "ADMISSION_LEASE_ARTIFACT_MISMATCH"
    manifest = matching[0]
    if (
        manifest.get("repository") != candidate["repository"]
        or manifest.get("issue_number") != issue_number
        or manifest.get("generation") != generation
        or manifest.get("base_sha") != observed_main_sha
        or manifest.get("branch") != payload.get("branch")
        or manifest.get("worktree_path") != payload.get("worktree_path")
    ):
        return "ADMISSION_LEASE_LINEAGE_MISMATCH"
    return None


def _ready_dirty_event_error(
    row: sqlite3.Row, candidate: dict[str, Any], finalization_payload: dict[str, Any]
) -> str | None:
    try:
        dirty_payload = json.loads(
            row["dirty_payload_json"], object_pairs_hook=_strict_object
        )
    except (TypeError, json.JSONDecodeError, PullBufferError):
        return "READINESS_ATTESTATION_DRIFT"
    try:
        expected_dirty_payload = {
            "trigger_kind": "CANDIDATE_PROMOTED",
            "repository": candidate["repository"],
            "issue_number": int(candidate["issue_number"]),
            "release_item_version": int(finalization_payload["ready_item_version"]),
            "release_source_sha256": finalization_payload["source_payload_sha256"],
            "status": "READY",
            "generation": int(candidate["generation"]),
            "candidate_id": int(candidate["id"]),
            "candidate_sha256": candidate["candidate_sha256"],
            "candidate_state": "READY",
            "finalization_sha256": row["finalization_sha256"],
        }
    except (KeyError, TypeError, ValueError):
        return "READINESS_ATTESTATION_DRIFT"
    if (
        row["dirty_state"] not in {"PENDING", "RETRY", "COMPLETE", "HOLD"}
        or dirty_payload != expected_dirty_payload
        or digest_json(dirty_payload) != row["dirty_event_sha256"]
    ):
        return "READINESS_ATTESTATION_DRIFT"
    return None


def ready_attestation_error(
    connection: sqlite3.Connection, candidate: dict[str, Any]
) -> str | None:
    """Require the immutable PASS-to-READY finalization for one READY candidate."""

    if candidate.get("state") != "READY":
        return None
    row = connection.execute(
        """
        SELECT finalization.*, current.state AS readiness_state,
               current.campaign_id AS current_campaign_id,
               current.receipt_id AS current_receipt_id,
               current.finalized_candidate_id, current.finalized_event_id,
               campaign.plan_sha256, receipt.verdict,
               receipt.receipt_sha256, receipt.receipt_json,
               dirty.id AS observed_dirty_event_id,
               dirty.state AS dirty_state,
               dirty.event_sha256 AS dirty_event_sha256,
               dirty.payload_json AS dirty_payload_json
        FROM portfolio_ready_finalizations finalization
        JOIN portfolio_readiness_current current
          ON current.repository=finalization.repository
         AND current.issue_number=finalization.issue_number
        JOIN portfolio_readiness_campaigns campaign
          ON campaign.id=finalization.campaign_id
        JOIN portfolio_readiness_receipts receipt
          ON receipt.id=finalization.receipt_id
        LEFT JOIN portfolio_dirty_events dirty
          ON dirty.id=finalization.dirty_event_id
        WHERE finalization.ready_candidate_id=?
        """,
        (int(candidate["id"]),),
    ).fetchone()
    if row is None:
        return "READINESS_ATTESTATION_MISSING"
    try:
        receipt_payload = json.loads(
            row["receipt_json"], object_pairs_hook=_strict_object
        )
        finalization_payload = json.loads(
            row["payload_json"], object_pairs_hook=_strict_object
        )
    except (TypeError, json.JSONDecodeError, PullBufferError):
        return "READINESS_ATTESTATION_INVALID"
    expected = (
        row["readiness_state"] == "FINALIZED"
        and int(row["current_campaign_id"]) == int(row["campaign_id"])
        and int(row["current_receipt_id"]) == int(row["receipt_id"])
        and int(row["finalized_candidate_id"] or -1) == int(candidate["id"])
        and int(row["finalized_event_id"] or -1) == int(row["dirty_event_id"])
        and int(row["observed_dirty_event_id"] or -1) == int(row["dirty_event_id"])
        and row["verdict"] == "PASS"
        and digest_json(receipt_payload) == row["receipt_sha256"]
        and candidate.get("readiness_campaign_id") == int(row["campaign_id"])
        and candidate.get("readiness_receipt_id") == int(row["receipt_id"])
        and candidate.get("readiness_plan_sha256") == row["plan_sha256"]
        and candidate.get("readiness_receipt_sha256") == row["receipt_sha256"]
        and finalization_payload.get("ready_candidate_sha256")
        == candidate.get("candidate_sha256")
        and finalization_payload.get("schema") == FINALIZATION_SCHEMA
        and digest_json(finalization_payload) == row["finalization_sha256"]
        and _ready_dirty_event_error(row, candidate, finalization_payload) is None
    )
    return None if expected else "READINESS_ATTESTATION_DRIFT"


def _validate_zero_wip_preparation_request(request: Any) -> None:
    if not isinstance(request, dict) or set(request) != {
        "schema",
        "repository",
        "observed_main_sha",
        "expected_graph_version",
        "expected_item_version",
        "expected_capacity_policy",
        "issue_sources",
        "scope",
        "graph",
        "candidate",
    }:
        raise PullBufferError("ZERO_WIP_PREPARATION_INVALID")
    if (
        request.get("schema") != ZERO_WIP_PREPARATION_SCHEMA
        or request.get("repository") != HARNESS_REPOSITORY
        or not isinstance(request.get("observed_main_sha"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", request["observed_main_sha"])
        or type(request.get("expected_graph_version")) is not int
        or request["expected_graph_version"] < 0
        or type(request.get("expected_item_version")) is not int
        or request["expected_item_version"] < 0
    ):
        raise PullBufferError("ZERO_WIP_PREPARATION_INVALID")
    expected_policy = request.get("expected_capacity_policy")
    if (
        not isinstance(expected_policy, dict)
        or set(expected_policy)
        != {
            "version",
            "development_limit",
            "shared_limit",
            "sre_limit",
            "authority_sha256",
        }
        or any(
            type(expected_policy.get(key)) is not int or expected_policy[key] < 0
            for key in (
                "version",
                "development_limit",
                "shared_limit",
                "sre_limit",
            )
        )
        or expected_policy["version"] <= 0
        or not isinstance(expected_policy.get("authority_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_policy["authority_sha256"])
        is None
    ):
        raise PullBufferError("ZERO_WIP_CAPACITY_POLICY_INVALID")
    scope = request.get("scope")
    if (
        not isinstance(scope, dict)
        or set(scope) != {"kind", "issue_numbers"}
        or scope.get("kind") != "ISSUE_SET"
        or not isinstance(scope.get("issue_numbers"), list)
        or not scope["issue_numbers"]
        or scope["issue_numbers"] != sorted(scope["issue_numbers"])
        or len(set(scope["issue_numbers"])) != len(scope["issue_numbers"])
        or any(type(number) is not int or number <= 0 for number in scope["issue_numbers"])
    ):
        raise PullBufferError("ZERO_WIP_SCOPE_INVALID")
    sources = request.get("issue_sources")
    if (
        not isinstance(sources, list)
        or any(
            not isinstance(source, dict)
            or set(source) != {"issue_number", "payload_sha256"}
            or type(source.get("issue_number")) is not int
            or source["issue_number"] <= 0
            or not isinstance(source.get("payload_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", source["payload_sha256"])
            for source in sources
        )
        or sorted(source["issue_number"] for source in sources)
        != scope["issue_numbers"]
    ):
        raise PullBufferError("ZERO_WIP_SOURCE_INVENTORY_INVALID")
    graph = request.get("graph")
    if not isinstance(graph, dict) or set(graph) != {
        "nodes",
        "relations",
        "excluded_issues",
    }:
        raise PullBufferError("ZERO_WIP_GRAPH_INVALID")
    node_keys = {
        "node_key",
        "issue_number",
        "role",
        "root_kind",
        "root_reason",
        "lane_key",
        "lane_order",
        "dispatchable",
        "priority_rank",
        "estimate_units",
        "development_units",
        "shared_units",
        "sre_units",
    }
    if (
        not isinstance(graph["nodes"], list)
        or not graph["nodes"]
        or any(not isinstance(node, dict) or set(node) != node_keys for node in graph["nodes"])
        or not isinstance(graph["relations"], list)
        or any(
            not isinstance(relation, dict)
            or set(relation)
            != {
                "left_node_key",
                "right_node_key",
                "relation_kind",
                "reason",
                "source_issue_number",
            }
            or type(relation.get("source_issue_number")) is not int
            or relation["source_issue_number"] <= 0
            for relation in graph["relations"]
        )
        or not isinstance(graph["excluded_issues"], list)
        or any(
            not isinstance(exclusion, dict)
            or set(exclusion) != {"issue_number", "reason"}
            for exclusion in graph["excluded_issues"]
        )
    ):
        raise PullBufferError("ZERO_WIP_GRAPH_INVALID")
    candidate = request.get("candidate")
    expected_candidate = {
        "issue_number",
        "generation",
        "verticality",
        "owner_visible_outcome",
        "preparation_complete",
        "promotion_checks_after_predecessor",
        "hard_stops",
        "promotion_trigger",
    }
    if isinstance(candidate, dict) and candidate.get("verticality") == "BOUNDED_ENABLER":
        expected_candidate.add("immediate_product_consumer")
    if (
        not isinstance(candidate, dict)
        or set(candidate) != expected_candidate
        or type(candidate.get("issue_number")) is not int
        or candidate["issue_number"] <= 0
        or type(candidate.get("generation")) is not int
        or candidate["generation"] < 0
        or candidate.get("verticality") not in VERTICALITY
        or not isinstance(candidate.get("owner_visible_outcome"), str)
        or not candidate["owner_visible_outcome"].strip()
    ):
        raise PullBufferError("ZERO_WIP_CANDIDATE_INVALID")
    if candidate["verticality"] == "BOUNDED_ENABLER" and not isinstance(
        candidate.get("immediate_product_consumer"), str
    ):
        raise PullBufferError("ZERO_WIP_CANDIDATE_INVALID")
    for field in (
        "preparation_complete",
        "promotion_checks_after_predecessor",
        "hard_stops",
    ):
        _require_nonempty_strings(candidate.get(field), "ZERO_WIP_CANDIDATE_INVALID")
    if candidate["hard_stops"] != canonical_harness_standing_controls()["hard_stops"]:
        raise PullBufferError("ZERO_WIP_HARNESS_CONTROL_DRIFT")
    if not isinstance(candidate.get("promotion_trigger"), str) or not candidate[
        "promotion_trigger"
    ].strip():
        raise PullBufferError("ZERO_WIP_CANDIDATE_INVALID")


def _zero_wip_packet_path(store: CoordinationStore, request_sha256: str, issue: int) -> Path:
    root = store.path.parent / "preparations"
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    else:
        _fsync_zero_wip_directory(root.parent)
    metadata = root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or root.is_symlink()
    ):
        raise PullBufferError("ZERO_WIP_ARTIFACT_ROOT_UNSAFE")
    return root / f"harness-issue-{issue}-{request_sha256}.json"


def _fsync_zero_wip_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(directory, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise PullBufferError("ZERO_WIP_ARTIFACT_ROOT_UNSAFE")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _zero_wip_directory_identity(directory: Path) -> tuple[int, int, int, int]:
    """Capture the owner namespace inode used by later destructive cleanup."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise PullBufferError("ZERO_WIP_ARTIFACT_ROOT_UNSAFE") from exc
    try:
        opened = os.fstat(descriptor)
        current = directory.lstat()
        identity = (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or identity
            != (current.st_dev, current.st_ino, current.st_mode, current.st_uid)
        ):
            raise PullBufferError("ZERO_WIP_ARTIFACT_ROOT_UNSAFE")
        return identity
    finally:
        os.close(descriptor)


def _zero_wip_packet_is_exact(path: Path, raw: bytes) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT") from exc
    try:
        before = os.fstat(descriptor)
        observed = _read_descriptor(descriptor)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or path.is_symlink()
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino, after.st_size)
            != (path_metadata.st_dev, path_metadata.st_ino, path_metadata.st_size)
            or observed != raw
        ):
            raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT")
        return True
    finally:
        os.close(descriptor)


def _recover_linked_zero_wip_packet(path: Path, raw: bytes) -> bool:
    """Finish the durable-link sequence left by a process interruption."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT") from exc
    try:
        before = os.fstat(descriptor)
        if before.st_nlink == 1:
            return False
        observed = _read_descriptor(descriptor)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 2
            or stat.S_IMODE(before.st_mode) != 0o600
            or path.is_symlink()
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino, after.st_size)
            != (path_metadata.st_dev, path_metadata.st_ino, path_metadata.st_size)
            or observed != raw
        ):
            raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT")
        linked_temporaries = []
        prefix = f".{path.name}."
        with os.scandir(path.parent) as entries:
            for entry in entries:
                if not entry.name.startswith(prefix):
                    continue
                metadata = entry.stat(follow_symlinks=False)
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino)
                    == (before.st_dev, before.st_ino)
                ):
                    linked_temporaries.append(path.parent / entry.name)
        if len(linked_temporaries) != 1:
            raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT")
        try:
            os.unlink(linked_temporaries[0])
            _fsync_zero_wip_directory(path.parent)
        except OSError as exc:
            raise PullBufferError("ZERO_WIP_ARTIFACT_RECOVERY_FAILED") from exc
        final = os.fstat(descriptor)
        if (
            final.st_nlink != 1
            or (final.st_dev, final.st_ino, final.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise PullBufferError("ZERO_WIP_ARTIFACT_RECOVERY_FAILED")
        return True
    finally:
        os.close(descriptor)


def _clean_unlinked_zero_wip_temporaries(path: Path, _raw: bytes) -> None:
    """Remove owner-created unlinked remnants while the owner DB lock is held.

    A process can die before, during, or after writing the temporary.  Its
    contents therefore are not evidence of ownership.  The deterministic
    packet-specific prefix, owner-only preparation directory, owner UID,
    regular-file type, single link, and mode are the ownership boundary.
    """

    removed = False
    prefix = f".{path.name}."
    with os.scandir(path.parent) as entries:
        candidates = [path.parent / entry.name for entry in entries if entry.name.startswith(prefix)]
    for candidate in candidates:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(candidate, flags)
        except OSError as exc:
            raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT") from exc
        try:
            before = os.fstat(descriptor)
            after = os.fstat(descriptor)
            path_metadata = candidate.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or (after.st_dev, after.st_ino, after.st_size, after.st_nlink)
                != (before.st_dev, before.st_ino, before.st_size, before.st_nlink)
                or (path_metadata.st_dev, path_metadata.st_ino, path_metadata.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
            ):
                raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT")
            os.unlink(candidate)
            removed = True
        finally:
            os.close(descriptor)
    if removed:
        _fsync_zero_wip_directory(path.parent)


def _materialize_zero_wip_packet(path: Path, raw: bytes) -> bool:
    if _recover_linked_zero_wip_packet(path, raw):
        return True
    _clean_unlinked_zero_wip_temporaries(path, raw)
    if _zero_wip_packet_is_exact(path, raw):
        return False
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    linked = False
    linked_identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
            linked = True
            linked_metadata = os.fstat(descriptor)
            linked_identity = (linked_metadata.st_dev, linked_metadata.st_ino)
        except FileExistsError:
            if not _zero_wip_packet_is_exact(path, raw):
                raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT")
            os.unlink(temporary)
            _fsync_zero_wip_directory(path.parent)
            return False
        _fsync_zero_wip_directory(path.parent)
        os.unlink(temporary)
        _fsync_zero_wip_directory(path.parent)
        if not _zero_wip_packet_is_exact(path, raw):
            raise PullBufferError("ZERO_WIP_ARTIFACT_CONFLICT")
        return True
    except BaseException as exc:
        cleanup_failed = False
        try:
            if linked and linked_identity is not None:
                final_metadata = path.lstat()
                if (final_metadata.st_dev, final_metadata.st_ino) == linked_identity:
                    os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_failed = True
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_failed = True
        try:
            _fsync_zero_wip_directory(path.parent)
        except (OSError, PullBufferError):
            cleanup_failed = True
        if cleanup_failed:
            raise PullBufferError("ZERO_WIP_ARTIFACT_CLEANUP_FAILED") from exc
        raise
    finally:
        os.close(descriptor)


def _retire_stale_zero_wip_orphans(
    store: CoordinationStore,
    keep_path: Path,
    expected_directory_identity: tuple[int, int, int, int],
) -> None:
    """Retire unregistered owner packet remnants across the preparation namespace."""

    directory = keep_path.parent
    final_pattern = re.compile(
        r"^harness-issue-[1-9][0-9]*-[0-9a-f]{64}\.json$"
    )
    temporary_pattern = re.compile(
        r"^\.harness-issue-[1-9][0-9]*-[0-9a-f]{64}\.json\..+$"
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_descriptor = os.open(directory, flags)
    except OSError as exc:
        raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE") from exc
    try:
        opened = os.fstat(directory_descriptor)
        try:
            current_directory = directory.lstat()
        except OSError as exc:
            raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE") from exc
        if (
            (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid)
            != expected_directory_identity
            or (
                current_directory.st_dev,
                current_directory.st_ino,
                current_directory.st_mode,
                current_directory.st_uid,
            )
            != expected_directory_identity
        ):
            raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE")
        with os.scandir(directory_descriptor) as entries:
            candidates = [
                entry.name
                for entry in entries
                if (
                    final_pattern.fullmatch(entry.name) is not None
                    or temporary_pattern.fullmatch(entry.name) is not None
                )
                and entry.name != keep_path.name
                and not entry.name.startswith(f".{keep_path.name}.")
            ]
        groups: dict[tuple[int, int], list[tuple[str, os.stat_result]]] = {}
        for name in candidates:
            try:
                path_metadata = os.stat(
                    name, dir_fd=directory_descriptor, follow_symlinks=False
                )
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE") from exc
            try:
                descriptor_metadata = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            identity = (
                path_metadata.st_dev,
                path_metadata.st_ino,
                path_metadata.st_mode,
                path_metadata.st_uid,
                path_metadata.st_size,
                path_metadata.st_nlink,
                path_metadata.st_mtime_ns,
                path_metadata.st_ctime_ns,
            )
            if (
                not stat.S_ISREG(path_metadata.st_mode)
                or path_metadata.st_uid != os.getuid()
                or stat.S_IMODE(path_metadata.st_mode) != 0o600
                or identity
                != (
                    descriptor_metadata.st_dev,
                    descriptor_metadata.st_ino,
                    descriptor_metadata.st_mode,
                    descriptor_metadata.st_uid,
                    descriptor_metadata.st_size,
                    descriptor_metadata.st_nlink,
                    descriptor_metadata.st_mtime_ns,
                    descriptor_metadata.st_ctime_ns,
                )
            ):
                raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE")
            groups.setdefault((path_metadata.st_dev, path_metadata.st_ino), []).append(
                (name, path_metadata)
            )
        removed = False
        relative_directory = directory.relative_to(store.path.parent)
        for group in groups.values():
            if int(group[0][1].st_nlink) != len(group):
                raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE")
            if any(
                store.connection.execute(
                    "SELECT 1 FROM coordination_artifacts WHERE relative_path=?",
                    ((relative_directory / name).as_posix(),),
                ).fetchone()
                is not None
                for name, _metadata in group
            ):
                continue
            verified: list[tuple[str, os.stat_result, int]] = []
            try:
                for name, metadata in group:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory_descriptor,
                    )
                    descriptor_metadata = os.fstat(descriptor)
                    current = os.stat(
                        name, dir_fd=directory_descriptor, follow_symlinks=False
                    )
                    expected = (
                        metadata.st_dev,
                        metadata.st_ino,
                        metadata.st_mode,
                        metadata.st_uid,
                        metadata.st_size,
                        metadata.st_nlink,
                        metadata.st_mtime_ns,
                        metadata.st_ctime_ns,
                    )
                    observed = (
                        current.st_dev,
                        current.st_ino,
                        current.st_mode,
                        current.st_uid,
                        current.st_size,
                        current.st_nlink,
                        current.st_mtime_ns,
                        current.st_ctime_ns,
                    )
                    descriptor_observed = (
                        descriptor_metadata.st_dev,
                        descriptor_metadata.st_ino,
                        descriptor_metadata.st_mode,
                        descriptor_metadata.st_uid,
                        descriptor_metadata.st_size,
                        descriptor_metadata.st_nlink,
                        descriptor_metadata.st_mtime_ns,
                        descriptor_metadata.st_ctime_ns,
                    )
                    if observed != expected or descriptor_observed != expected:
                        os.close(descriptor)
                        raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE")
                    verified.append((name, metadata, descriptor))
                for index, (name, _metadata, descriptor) in enumerate(verified):
                    current = os.stat(
                        name, dir_fd=directory_descriptor, follow_symlinks=False
                    )
                    descriptor_metadata = os.fstat(descriptor)
                    current_identity = (
                        current.st_dev,
                        current.st_ino,
                        current.st_mode,
                        current.st_uid,
                        current.st_size,
                        current.st_nlink,
                        current.st_mtime_ns,
                        current.st_ctime_ns,
                    )
                    descriptor_identity = (
                        descriptor_metadata.st_dev,
                        descriptor_metadata.st_ino,
                        descriptor_metadata.st_mode,
                        descriptor_metadata.st_uid,
                        descriptor_metadata.st_size,
                        descriptor_metadata.st_nlink,
                        descriptor_metadata.st_mtime_ns,
                        descriptor_metadata.st_ctime_ns,
                    )
                    if current_identity != descriptor_identity:
                        raise PullBufferError("ZERO_WIP_STALE_ARTIFACT_UNSAFE")
                    os.unlink(name, dir_fd=directory_descriptor)
                    removed = True
            finally:
                for _name, _metadata, descriptor in verified:
                    os.close(descriptor)
        if removed:
            os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _retire_zero_wip_orphans_after_commit(
    store: CoordinationStore,
    keep_path: Path,
    expected_directory_identity: tuple[int, int, int, int],
) -> str:
    """Run best-effort orphan retirement only after candidate durability."""

    try:
        with store.transaction():
            _retire_stale_zero_wip_orphans(
                store, keep_path, expected_directory_identity
            )
    except (OSError, PullBufferError, sqlite3.Error):
        return "HOLD"
    return "COMPLETE"


def _remove_zero_wip_packet(path: Path, raw: bytes) -> None:
    if not _zero_wip_packet_is_exact(path, raw):
        raise PullBufferError("ZERO_WIP_ARTIFACT_CLEANUP_FAILED")
    try:
        os.unlink(path)
        _fsync_zero_wip_directory(path.parent)
    except (OSError, PullBufferError) as exc:
        raise PullBufferError("ZERO_WIP_ARTIFACT_CLEANUP_FAILED") from exc


def _commit_zero_wip(connection: sqlite3.Connection) -> None:
    """Named seam for proving ambiguous post-COMMIT interruption behavior."""

    connection.execute("COMMIT")


def prepare_zero_wip_candidate(
    store: CoordinationStore,
    request: dict[str, Any],
    *,
    now: str,
    canonical_main_reader: Callable[[str], str] | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Atomically prepare one harness graph/item/candidate without writer WIP."""

    _validate_zero_wip_preparation_request(request)
    if store.connection.in_transaction:
        raise PullBufferError("ZERO_WIP_TRANSACTION_CONFLICT")
    if canonical_main_reader is None:
        from portfolio_convergence import read_canonical_local_main

        canonical_main_reader = read_canonical_local_main
    try:
        main_before = canonical_main_reader(request["repository"])
    except Exception as exc:
        raise PullBufferError("ZERO_WIP_MAIN_EVIDENCE_INVALID") from exc
    if main_before != request["observed_main_sha"]:
        raise PullBufferError("ZERO_WIP_MAIN_DRIFT")
    ensure_portfolio_graph_schema(store.connection)
    ensure_pull_buffer_schema(store.connection)
    repository = request["repository"]
    sources = {entry["issue_number"]: entry["payload_sha256"] for entry in request["issue_sources"]}
    snapshots = {
        issue: store.current_snapshot(repository, "issue", issue)
        for issue in sources
    }
    if any(
        snapshot is None or snapshot.payload_sha256 != sources[issue]
        for issue, snapshot in snapshots.items()
    ):
        raise PullBufferError("ZERO_WIP_SOURCE_DRIFT")
    graph_request = request["graph"]
    node_by_key = {node["node_key"]: node for node in graph_request["nodes"]}
    if len(node_by_key) != len(graph_request["nodes"]):
        raise PullBufferError("ZERO_WIP_GRAPH_INVALID")
    nodes = [
        {
            **node,
            "source_payload_sha256": sources[node["issue_number"]],
            "ready_at": snapshots[node["issue_number"]].source_updated_at,
        }
        for node in graph_request["nodes"]
        if node.get("issue_number") in sources
    ]
    if len(nodes) != len(graph_request["nodes"]):
        raise PullBufferError("ZERO_WIP_GRAPH_INVALID")
    exclusions = [
        {
            **exclusion,
            "source_payload_sha256": sources[exclusion["issue_number"]],
        }
        for exclusion in graph_request["excluded_issues"]
        if exclusion.get("issue_number") in sources
    ]
    if len(exclusions) != len(graph_request["excluded_issues"]):
        raise PullBufferError("ZERO_WIP_GRAPH_INVALID")
    relations: list[dict[str, Any]] = []
    for relation in graph_request["relations"]:
        left = node_by_key.get(relation["left_node_key"])
        right = node_by_key.get(relation["right_node_key"])
        source_issue = relation["source_issue_number"]
        if (
            left is None
            or right is None
            or source_issue not in {left["issue_number"], right["issue_number"]}
            or source_issue not in sources
        ):
            raise PullBufferError("ZERO_WIP_RELATION_SOURCE_INVALID")
        relations.append(
            {
                key: relation[key]
                for key in (
                    "left_node_key",
                    "right_node_key",
                    "relation_kind",
                    "reason",
                )
            }
            | {"source_payload_sha256": sources[source_issue]}
        )
    graph_plan = {
        "repository": repository,
        "accepted_main_sha": request["observed_main_sha"],
        "expected_current_version": request["expected_graph_version"],
        "scope": request["scope"],
        "excluded_issues": exclusions,
        "nodes": nodes,
        "relations": relations,
    }
    try:
        validate_graph_plan(graph_plan)
    except PortfolioGraphError as exc:
        raise PullBufferError(str(exc)) from exc
    dispatchable_keys = sorted(
        node["node_key"] for node in nodes if node["dispatchable"]
    )
    required_collision_pairs = {
        (left, right)
        for index, left in enumerate(dispatchable_keys)
        for right in dispatchable_keys[index + 1 :]
    }
    observed_collision_pairs = {
        tuple(sorted((relation["left_node_key"], relation["right_node_key"])))
        for relation in relations
        if relation["relation_kind"] == "COLLISION"
    }
    if observed_collision_pairs != required_collision_pairs:
        raise PullBufferError("ZERO_WIP_HARNESS_COLLISION_INCOMPLETE")
    candidate_issue = int(request["candidate"]["issue_number"])
    candidate_nodes = [
        node for node in nodes if int(node["issue_number"]) == candidate_issue
    ]
    if len(candidate_nodes) != 1 or not candidate_nodes[0]["dispatchable"]:
        raise PullBufferError("ZERO_WIP_CANDIDATE_NODE_INVALID")
    candidate_node_key = str(candidate_nodes[0]["node_key"])
    for relation in relations:
        if (
            relation["relation_kind"] != "HARD_BLOCK"
            or relation["right_node_key"] != candidate_node_key
        ):
            continue
        predecessor = node_by_key[relation["left_node_key"]]
        predecessor_issue = int(predecessor["issue_number"])
        predecessor_item = store.connection.execute(
            "SELECT status, allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=?",
            (repository, predecessor_issue),
        ).fetchone()
        predecessor_payload = snapshots[predecessor_issue].payload
        terminal = bool(
            (
                predecessor_item is not None
                and predecessor_item["status"] == "DONE"
                and predecessor_item["allocation_class"] == "NONE"
            )
            or predecessor_payload.get("state") == "closed"
        )
        if not terminal:
            raise PullBufferError("ZERO_WIP_CANDIDATE_HARD_BLOCKED")
    candidate_request = request["candidate"]
    candidate_nodes = [
        node for node in nodes if node["issue_number"] == candidate_request["issue_number"]
    ]
    source_units = {
        "development_units": 0,
        "shared_units": 1,
        "sre_units": 0,
    }
    if any(
        node["dispatchable"]
        and {
            key: int(node[key])
            for key in ("development_units", "shared_units", "sre_units")
        }
        != source_units
        for node in nodes
    ):
        raise PullBufferError("ZERO_WIP_HARNESS_CAPACITY_INVALID")
    if len(candidate_nodes) != 1 or not candidate_nodes[0]["dispatchable"]:
        raise PullBufferError("ZERO_WIP_CANDIDATE_NODE_INVALID")
    candidate_node = candidate_nodes[0]
    units = {
        key: int(candidate_node[key])
        for key in ("development_units", "shared_units", "sre_units")
    }
    if units != source_units:
        raise PullBufferError("ZERO_WIP_HARNESS_CAPACITY_INVALID")
    policy = store.connection.execute(
        """
        SELECT p.* FROM coordination_capacity_current c
        JOIN coordination_capacity_policies p
          ON p.repository=c.repository AND p.version=c.version
        WHERE c.repository=?
        """,
        (repository,),
    ).fetchone()
    if (
        policy is None
        or not isinstance(policy["authority_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", policy["authority_sha256"]) is None
    ):
        raise PullBufferError("ZERO_WIP_CAPACITY_POLICY_MISSING")
    expected_policy = request["expected_capacity_policy"]
    if any(
        policy[key] != expected_policy[key]
        for key in (
            "version",
            "development_limit",
            "shared_limit",
            "sre_limit",
            "authority_sha256",
        )
    ):
        raise PullBufferError("ZERO_WIP_CAPACITY_POLICY_DRIFT")
    collisions = []
    for relation in relations:
        if relation["relation_kind"] != "COLLISION" or candidate_node["node_key"] not in {
            relation["left_node_key"], relation["right_node_key"]
        }:
            continue
        other_key = (
            relation["right_node_key"]
            if relation["left_node_key"] == candidate_node["node_key"]
            else relation["left_node_key"]
        )
        collisions.append(
            {
                "other_issue": int(node_by_key[other_key]["issue_number"]),
                "disposition": "COLLISION",
                "reason": relation["reason"],
            }
        )
    collisions.sort(key=lambda item: item["other_issue"])
    graph_version = int(request["expected_graph_version"]) + 1
    item_version = int(request["expected_item_version"]) + 1
    packet = {
        "schema": SCHEMA,
        "repository": repository,
        "issue_number": int(candidate_request["issue_number"]),
        "generation": int(candidate_request["generation"]),
        "item_version_at_preparation": item_version,
        "source_payload_sha256": sources[candidate_request["issue_number"]],
        "accepted_main_at_preparation": request["observed_main_sha"],
        "portfolio_graph_version": graph_version,
        "state": "PREPARED_NOT_READY",
        "verticality": candidate_request["verticality"],
        "owner_visible_outcome": candidate_request["owner_visible_outcome"],
        "capacity_policy": {
            key: int(policy[key])
            for key in ("version", "development_limit", "shared_limit", "sre_limit")
        },
        "capacity_on_activation": units,
        "precomputed_collision_matrix": collisions,
        "preparation_complete": candidate_request["preparation_complete"],
        "promotion_checks_after_predecessor": candidate_request[
            "promotion_checks_after_predecessor"
        ],
        "hard_stops": candidate_request["hard_stops"],
        "promotion_trigger": candidate_request["promotion_trigger"],
    }
    if candidate_request["verticality"] == "BOUNDED_ENABLER":
        packet["immediate_product_consumer"] = candidate_request[
            "immediate_product_consumer"
        ]
    _validate_packet(packet)
    request_sha256 = digest_json(request)
    packet_raw = (canonical_json(packet) + "\n").encode("utf-8")
    packet_path = _zero_wip_packet_path(
        store, request_sha256, int(candidate_request["issue_number"])
    )
    preparation_directory_identity = _zero_wip_directory_identity(packet_path.parent)
    graph_sha256 = digest_json(graph_payload(graph_plan))
    candidate_sha256 = digest_json(packet)
    created_packet = False
    cleanup_packet = False
    try:
        store.connection.execute("BEGIN IMMEDIATE")
        registered_packet = store.connection.execute(
            "SELECT 1 FROM coordination_artifacts WHERE relative_path=?",
            (packet_path.relative_to(store.path.parent).as_posix(),),
        ).fetchone()
        # Any exact file at this request-specific path that is not registered
        # belongs to this preparation attempt (including a crash remnant).
        cleanup_packet = registered_packet is None or not _zero_wip_packet_is_exact(
            packet_path, packet_raw
        )
        created_packet = _materialize_zero_wip_packet(packet_path, packet_raw)
        if registered_packet is None:
            # Adopt an exact unregistered artifact left by a process death
            # after its durable link but before the SQLite transaction.
            cleanup_packet = True
        try:
            main_after = canonical_main_reader(repository)
        except Exception as exc:
            raise PullBufferError("ZERO_WIP_MAIN_EVIDENCE_INVALID") from exc
        if main_after != main_before:
            raise PullBufferError("ZERO_WIP_MAIN_DRIFT")
        current_policy = store.connection.execute(
            """
            SELECT p.* FROM coordination_capacity_current c
            JOIN coordination_capacity_policies p
              ON p.repository=c.repository AND p.version=c.version
            WHERE c.repository=?
            """,
            (repository,),
        ).fetchone()
        if current_policy is None or any(
            int(current_policy[key]) != int(policy[key])
            for key in (
                "version",
                "development_limit",
                "shared_limit",
                "sre_limit",
            )
        ):
            raise PullBufferError("ZERO_WIP_CAPACITY_POLICY_DRIFT")
        before_counts = {
            table: int(
                store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
            )
            for table in (
                "coordination_messages",
                "coordination_terminal_watches",
                "executor_attempts",
                "coordination_pre_push_gates",
                "coordination_pre_push_publications",
                "portfolio_dirty_events",
            )
        }
        occupied = store.connection.execute(
            "SELECT 1 FROM coordination_items WHERE repository=? "
            "AND allocation_class IN ('ACTIVE','RETAINED') LIMIT 1",
            (repository,),
        ).fetchone()
        if occupied is not None:
            raise PullBufferError("ZERO_WIP_ALLOCATION_PRESENT")
        if reserved_hosted_sre_units(store.connection, repository) != 0:
            raise PullBufferError("ZERO_WIP_HOSTED_SRE_PRESENT")
        residual_queries = (
            (
                "coordination_messages",
                "SELECT 1 FROM coordination_messages "
                "WHERE (json_extract(payload_json, '$.source.repository')=? "
                "OR json_extract(payload_json, '$.repository')=?) "
                "AND topic IN ('development.admission',"
                "'development.recovery_prepare','development.recovery_commit',"
                "'development.terminal_closeout') "
                "AND state IN ('PREPARED','CLAIMED') LIMIT 1",
                2,
            ),
            (
                "coordination_terminal_watches",
                "SELECT 1 FROM coordination_terminal_watches "
                "WHERE repository=? AND state IN ('PENDING_CLAIM','ACTIVE') LIMIT 1",
                1,
            ),
            (
                "executor_attempts",
                "SELECT 1 FROM executor_attempts attempt "
                "WHERE attempt.lineage_repository=? "
                "AND attempt.state IN ('RESERVED','LAUNCHING','RUNNING') "
                "AND (attempt.target_kind='terminal_watch' OR EXISTS ("
                "SELECT 1 FROM coordination_messages message "
                "WHERE attempt.target_kind='message' "
                "AND CAST(message.id AS TEXT)=attempt.target_key "
                "AND message.topic IN ('development.admission',"
                "'development.recovery_prepare','development.recovery_commit',"
                "'development.terminal_closeout'))) LIMIT 1",
                1,
            ),
            (
                "coordination_pre_push_publications",
                "SELECT 1 FROM coordination_pre_push_publications "
                "WHERE repository=? AND state='RESERVED' LIMIT 1",
                1,
            ),
        )
        for table, query, parameter_count in residual_queries:
            if store.connection.execute(
                query, (repository,) * parameter_count
            ).fetchone() is not None:
                raise PullBufferError(f"ZERO_WIP_RESIDUAL_STATE:{table}")
        current_graph = store.connection.execute(
            "SELECT current.version, current.health, current.observed_main_sha, "
            "revision.graph_sha256 "
            "FROM portfolio_graph_current current "
            "JOIN portfolio_graph_revisions revision "
            "ON revision.repository=current.repository AND revision.version=current.version "
            "WHERE current.repository=?",
            (repository,),
        ).fetchone()
        current_item = store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (repository, candidate_request["issue_number"]),
        ).fetchone()
        current_candidate = store.connection.execute(
            "SELECT candidate.* FROM portfolio_pull_buffer_current pointer "
            "JOIN portfolio_pull_buffer_candidates candidate ON candidate.id=pointer.candidate_id "
            "WHERE pointer.repository=? AND pointer.issue_number=?",
            (repository, candidate_request["issue_number"]),
        ).fetchone()
        exact_replay = (
            current_graph is not None
            and int(current_graph["version"]) == graph_version
            and current_graph["health"] == "CURRENT"
            and current_graph["observed_main_sha"] == request["observed_main_sha"]
            and current_graph["graph_sha256"] == graph_sha256
            and current_item is not None
            and int(current_item["version"]) == item_version
            and current_item["status"] == "PREPARED"
            and current_item["allocation_class"] == "NONE"
            and current_item["accountable_session_id"] is None
            and current_item["lease_manifest_sha256"] is None
            and current_item["source_payload_sha256"]
            == sources[candidate_request["issue_number"]]
            and tuple(int(current_item[key]) for key in units) == tuple(units.values())
            and current_candidate is not None
            and current_candidate["candidate_sha256"] == candidate_sha256
            and current_candidate["state"] == "PREPARED_NOT_READY"
            and int(current_candidate["graph_version"]) == graph_version
            and int(current_candidate["capacity_policy_version"])
            == int(policy["version"])
            and current_candidate["artifact_content_sha256"]
            == hashlib.sha256(packet_raw).hexdigest()
            and current_candidate["artifact_relative_path"]
            == packet_path.relative_to(store.path.parent).as_posix()
        )
        if exact_replay:
            replay_descriptor = -1
            try:
                replay_descriptor, replay_relative = _open_packet(
                    store.path, packet_path
                )
                replay_artifact_sha = _registered_artifact(
                    store.connection,
                    replay_descriptor,
                    replay_relative,
                    repository=repository,
                    issue_number=int(candidate_request["issue_number"]),
                    generation=int(candidate_request["generation"]),
                )
                if (
                    replay_relative != current_candidate["artifact_relative_path"]
                    or replay_artifact_sha
                    != current_candidate["artifact_content_sha256"]
                ):
                    raise PullBufferError("ZERO_WIP_REPLAY_ARTIFACT_DRIFT")
            except PullBufferError as exc:
                raise PullBufferError("ZERO_WIP_REPLAY_ARTIFACT_DRIFT") from exc
            finally:
                if replay_descriptor >= 0:
                    os.close(replay_descriptor)
            try:
                main_final = canonical_main_reader(repository)
            except Exception as exc:
                raise PullBufferError("ZERO_WIP_MAIN_EVIDENCE_INVALID") from exc
            if main_final != main_before:
                raise PullBufferError("ZERO_WIP_MAIN_DRIFT")
            _commit_zero_wip(store.connection)
            orphan_retirement = _retire_zero_wip_orphans_after_commit(
                store, packet_path, preparation_directory_identity
            )
            return {
                "repository": repository,
                "issue_number": int(candidate_request["issue_number"]),
                "request_sha256": request_sha256,
                "graph_version": graph_version,
                "graph_sha256": graph_sha256,
                "item_version": item_version,
                "candidate_sha256": candidate_sha256,
                "artifact_relative_path": str(packet_path.relative_to(store.path.parent)),
                "state": "PREPARED_NOT_READY",
                "replay": True,
                "orphan_retirement": orphan_retirement,
            }
        try:
            replace_graph(
                store.connection,
                graph_plan,
                now=now,
                _transaction=False,
                _ensure_schema=False,
            )
        except PortfolioGraphError as exc:
            raise PullBufferError(str(exc)) from exc
        if failpoint is not None:
            failpoint("after_graph")
        item = store.set_issue_status(
            repository=repository,
            issue_number=int(candidate_request["issue_number"]),
            status="PREPARED",
            allocation_class="NONE",
            generation=int(candidate_request["generation"]),
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=units["development_units"],
            shared_units=units["shared_units"],
            sre_units=units["sre_units"],
            expected_source_sha256=sources[candidate_request["issue_number"]],
            expected_version=int(request["expected_item_version"]),
            now=now,
            _transaction=False,
        )
        if failpoint is not None:
            failpoint("after_item")
        store.register_artifacts(
            [
                {
                    "repository": repository,
                    "issue_number": int(candidate_request["issue_number"]),
                    "generation": int(candidate_request["generation"]),
                    "path": str(packet_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now=now,
            _transaction=False,
        )
        if failpoint is not None:
            failpoint("after_artifact")
        candidate = register_candidate(
            store.connection,
            store.path,
            packet_path,
            now=now,
            _transaction=False,
            _ensure_schema=False,
        )
        if failpoint is not None:
            failpoint("after_candidate")
        after_counts = {
            table: int(store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in before_counts
        }
        if after_counts != before_counts:
            raise PullBufferError("ZERO_WIP_WRITER_SIDE_EFFECT")
        try:
            main_final = canonical_main_reader(repository)
        except Exception as exc:
            raise PullBufferError("ZERO_WIP_MAIN_EVIDENCE_INVALID") from exc
        if main_final != main_before:
            raise PullBufferError("ZERO_WIP_MAIN_DRIFT")
        _commit_zero_wip(store.connection)
    except BaseException as exc:
        cleanup_error = None
        # Only a provably live transaction owns rollback cleanup.  If COMMIT
        # completed but the interpreter was interrupted before sqlite returned,
        # the registered evidence must remain durable.
        rollback_live = store.connection.in_transaction
        if cleanup_packet and rollback_live and packet_path.exists():
            try:
                _remove_zero_wip_packet(packet_path, packet_raw)
            except PullBufferError as error:
                cleanup_error = error
        if rollback_live and store.connection.in_transaction:
            store.connection.execute("ROLLBACK")
        if cleanup_error is not None:
            raise cleanup_error from exc
        raise
    orphan_retirement = _retire_zero_wip_orphans_after_commit(
        store, packet_path, preparation_directory_identity
    )
    return {
        "repository": repository,
        "issue_number": int(candidate_request["issue_number"]),
        "request_sha256": request_sha256,
        "graph_version": graph_version,
        "graph_sha256": graph_sha256,
        "item_version": int(item["version"]),
        "candidate_sha256": candidate["candidate_sha256"],
        "artifact_relative_path": str(packet_path.relative_to(store.path.parent)),
        "state": "PREPARED_NOT_READY",
        "replay": False,
        "orphan_retirement": orphan_retirement,
    }


def register_candidate(
    connection: sqlite3.Connection,
    database: Path,
    packet_path: Path,
    *,
    now: str,
    _transaction: bool = True,
    _ensure_schema: bool = True,
) -> dict[str, Any]:
    if not _transaction and (_ensure_schema or not connection.in_transaction):
        raise PullBufferError("PULL_BUFFER_TRANSACTION_REQUIRED")
    if _ensure_schema:
        ensure_pull_buffer_schema(connection)
    descriptor, relative_path = _open_packet(database, packet_path)
    admission_observations: list[dict[str, Any]] = []
    try:
        try:
            initial_metadata = os.fstat(descriptor)
            raw = _read_descriptor(descriptor)
            packet = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PullBufferError("PULL_BUFFER_PACKET_INVALID") from exc
        _validate_packet(packet)
        if packet["schema"] != SCHEMA or packet["state"] != "PREPARED_NOT_READY":
            raise PullBufferError("PULL_BUFFER_READY_FINALIZER_REQUIRED")
        admission_observations = _load_admission_artifacts(
            connection,
            database,
            packet.get("admission_transaction"),
        )
        if _transaction:
            connection.execute("BEGIN IMMEDIATE")
        repository = packet["repository"]
        issue_number = int(packet["issue_number"])
        current = connection.execute(
            "SELECT version, observed_main_sha, health FROM portfolio_graph_current WHERE repository=?",
            (repository,),
        ).fetchone()
        if current is None or current["health"] != "CURRENT":
            raise PullBufferError("PULL_BUFFER_GRAPH_STALE")
        policy = connection.execute(
            """
            SELECT p.* FROM coordination_capacity_current c
            JOIN coordination_capacity_policies p
              ON p.repository=c.repository AND p.version=c.version
            WHERE c.repository=?
            """,
            (repository,),
        ).fetchone()
        item = connection.execute(
            """
            SELECT i.*,
                   CASE WHEN current.payload_sha256=i.source_payload_sha256 THEN 1 ELSE 0 END
                       AS source_current
            FROM coordination_items i
            LEFT JOIN github_current current
              ON current.repository=i.repository
             AND current.object_kind='issue'
             AND current.object_number=i.issue_number
            WHERE i.repository=? AND i.issue_number=?
            """,
            (repository, issue_number),
        ).fetchone()
        node = connection.execute(
            """
            SELECT * FROM portfolio_graph_nodes
            WHERE repository=? AND graph_version=? AND issue_number=? AND dispatchable=1
            """,
            (repository, int(current["version"]), issue_number),
        ).fetchone()
        if policy is None or item is None or node is None:
            raise PullBufferError("PULL_BUFFER_BINDING_MISSING")
        expected = (
            int(packet["portfolio_graph_version"]) == int(current["version"])
            and packet["accepted_main_at_preparation"] == current["observed_main_sha"]
            and int(packet["capacity_policy"]["version"]) == int(policy["version"])
            and int(packet["capacity_policy"]["development_limit"]) == int(policy["development_limit"])
            and int(packet["capacity_policy"]["shared_limit"]) == int(policy["shared_limit"])
            and int(packet["capacity_policy"]["sre_limit"]) == int(policy["sre_limit"])
            and int(packet["generation"]) == int(item["generation"])
            and int(packet["item_version_at_preparation"]) == int(item["version"])
            and packet["source_payload_sha256"] == item["source_payload_sha256"]
            and item["source_current"] == 1
            and item["allocation_class"] == "NONE"
            and item["status"] in ZERO_WIP_STATUSES
            and (
                (packet["state"] == "READY" and item["status"] == "READY")
                or (
                    packet["state"] == "PREPARED_NOT_READY"
                    and item["status"] in {"PREPARED", "QUEUED"}
                )
            )
            and int(packet["capacity_on_activation"]["development_units"]) == int(item["development_units"])
            and int(packet["capacity_on_activation"]["shared_units"]) == int(item["shared_units"])
            and int(packet["capacity_on_activation"]["sre_units"]) == int(item["sre_units"])
        )
        if not expected:
            raise PullBufferError("PULL_BUFFER_BINDING_DRIFT")
        if packet["state"] == "READY":
            binding_error = admission_binding_error(
                packet.get("admission_transaction"),
                candidate={
                    "repository": repository,
                    "issue_number": issue_number,
                    "generation": int(item["generation"]),
                    "item_version": int(item["version"]),
                    "source_payload_sha256": item["source_payload_sha256"],
                    "accepted_main_sha": packet["accepted_main_at_preparation"],
                },
                observed_main_sha=str(current["observed_main_sha"]),
                observation={"admission_artifacts": admission_observations},
                connection=connection,
            )
            if binding_error is not None:
                raise PullBufferError(binding_error)
            selected_now = set(
                _schedule_decision(
                    connection,
                    repository,
                    current_main=str(current["observed_main_sha"]),
                    record=False,
                    now=now,
                )["selected"]
            )
            if node["node_key"] not in selected_now:
                raise PullBufferError("PULL_BUFFER_READY_NOT_DISPATCHABLE")
        artifact_sha = _registered_artifact(
            connection,
            descriptor,
            relative_path,
            repository=repository,
            issue_number=issue_number,
            generation=int(packet["generation"]),
        )
        candidate_sha = digest_json(packet)
        connection.execute(
            """
            INSERT OR IGNORE INTO portfolio_pull_buffer_candidates(
                repository, issue_number, generation, item_version,
                source_payload_sha256, accepted_main_sha, graph_version,
                capacity_policy_version, lane_key, state, verticality,
                development_units, shared_units, sre_units, promotion_trigger,
                artifact_relative_path, artifact_content_sha256,
                candidate_sha256, registered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                repository, issue_number, int(packet["generation"]), int(item["version"]),
                packet["source_payload_sha256"], packet["accepted_main_at_preparation"],
                int(current["version"]), int(policy["version"]), node["lane_key"],
                packet["state"], packet["verticality"], int(item["development_units"]),
                int(item["shared_units"]), int(item["sre_units"]),
                packet["promotion_trigger"], relative_path, artifact_sha,
                candidate_sha, now,
            ),
        )
        row = connection.execute(
            "SELECT id FROM portfolio_pull_buffer_candidates WHERE repository=? AND issue_number=? AND candidate_sha256=?",
            (repository, issue_number, candidate_sha),
        ).fetchone()
        retired = connection.execute(
            "SELECT 1 FROM portfolio_pull_buffer_retirements WHERE candidate_id=?",
            (int(row["id"]),),
        ).fetchone()
        if retired is not None:
            raise PullBufferError("PULL_BUFFER_CANDIDATE_RETIRED")
        prior = connection.execute(
            """
            SELECT pointer.candidate_id, candidate.state
            FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=pointer.candidate_id
            WHERE pointer.repository=? AND pointer.issue_number=?
            """,
            (repository, issue_number),
        ).fetchone()
        if prior is not None and int(prior["candidate_id"]) != int(row["id"]):
            _retire_pointer(
                connection,
                repository=repository,
                issue_number=issue_number,
                candidate_id=int(prior["candidate_id"]),
                reasons=["SUPERSEDED"],
                now=now,
            )
        connection.execute(
            """
            INSERT INTO portfolio_pull_buffer_current(repository, issue_number, candidate_id, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(repository, issue_number) DO UPDATE SET
                candidate_id=excluded.candidate_id, updated_at=excluded.updated_at
            """,
            (repository, issue_number, int(row["id"]), now),
        )
        final_raw = _read_descriptor(descriptor)
        final_metadata = os.fstat(descriptor)
        if (
            final_raw != raw
            or not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.getuid()
            or final_metadata.st_nlink != 1
            or int(final_metadata.st_size) != int(initial_metadata.st_size)
            or int(final_metadata.st_dev) != int(initial_metadata.st_dev)
            or int(final_metadata.st_ino) != int(initial_metadata.st_ino)
        ):
            raise PullBufferError("PULL_BUFFER_ARTIFACT_DRIFT")
        if any(not _descriptor_is_current(item) for item in admission_observations):
            raise PullBufferError("ADMISSION_LEASE_ARTIFACT_DRIFT")
        dirty_event_id = None
        commit_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(commit_metadata.st_mode)
            or commit_metadata.st_uid != os.getuid()
            or commit_metadata.st_nlink != 1
            or int(commit_metadata.st_size) != int(final_metadata.st_size)
            or int(commit_metadata.st_dev) != int(final_metadata.st_dev)
            or int(commit_metadata.st_ino) != int(final_metadata.st_ino)
        ):
            raise PullBufferError("PULL_BUFFER_ARTIFACT_DRIFT")
        if _transaction:
            connection.execute("COMMIT")
    except Exception:
        if _transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        close_candidate_observations(
            {0: {"admission_artifacts": admission_observations}}
        )
        os.close(descriptor)
    return {
        "repository": repository,
        "issue_number": issue_number,
        "candidate_sha256": candidate_sha,
        "state": packet["state"],
        "lane_key": node["lane_key"],
        "portfolio_dirty_event_id": dirty_event_id,
    }


def finalize_ready(
    store: CoordinationStore,
    packet_path: Path,
    *,
    now: str,
    failpoint: Any | None = None,
) -> dict[str, Any]:
    """Atomically bind PASS readiness, READY state, packet, pointer, and wake."""

    from kanban_readiness import (
        _binding_reasons as readiness_binding_reasons,
        _campaign as readiness_campaign,
        _graph_stale_only_for_equivalent_source as readiness_graph_equivalent,
        _event as readiness_event,
        approval_source_equivalent as readiness_source_equivalent,
        ensure_schema as ensure_readiness_schema,
    )

    connection = store.connection
    ensure_readiness_schema(connection)
    ensure_pull_buffer_schema(connection)
    descriptor, relative_path = _open_packet(store.path, packet_path)
    admission_observations: list[dict[str, Any]] = []
    prepared_observations: dict[int, dict[str, Any]] = {}
    packet_observation: dict[str, Any] | None = None
    try:
        try:
            initial_metadata = os.fstat(descriptor)
            raw = _read_descriptor(descriptor)
            packet_observation = _descriptor_observation(descriptor, raw)
            packet = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PullBufferError("PULL_BUFFER_PACKET_INVALID") from exc
        _validate_packet(packet)
        if packet["schema"] != READY_SCHEMA or packet["state"] != "READY":
            raise PullBufferError("PULL_BUFFER_READY_FINALIZATION_INVALID")
        repository = str(packet["repository"])
        issue_number = int(packet["issue_number"])
        candidate_sha = digest_json(packet)
        admission = packet["admission_transaction"]
        prepared_binding = packet["prepared_candidate"]
        admission_observations = _load_admission_artifacts(
            connection, store.path, admission
        )
        prepared_observations = load_candidate_packets(
            connection,
            repository,
            database=store.path,
            keep_descriptors=True,
            candidate_ids={int(prepared_binding["candidate_id"])},
        )
        prepared_observation = prepared_observations.get(
            int(prepared_binding["candidate_id"])
        )
        if (
            not isinstance(prepared_observation, dict)
            or prepared_observation.get("error") is not None
        ):
            raise PullBufferError("PULL_BUFFER_PREPARED_ARTIFACT_DRIFT")
        _require_prepared_promotion_preserved(
            prepared_observation.get("packet"), packet
        )

        with store.transaction():
            artifact_sha = _registered_artifact(
                connection,
                descriptor,
                relative_path,
                repository=repository,
                issue_number=issue_number,
                generation=int(packet["generation"]),
            )
            readiness = packet["readiness_binding"]
            phase = connection.execute(
                """
                SELECT current.state, current.version AS current_version,
                       current.campaign_id, current.receipt_id,
                       current.finalized_candidate_id, current.finalized_event_id,
                       campaign.plan_sha256, campaign.candidate_sha256,
                       campaign.repository, campaign.issue_number,
                       campaign.generation, campaign.item_version,
                       campaign.source_payload_sha256, campaign.accepted_main_sha,
                       campaign.graph_version, campaign.capacity_policy_version,
                       receipt.verdict, receipt.receipt_sha256,
                       receipt.receipt_json, receipt.campaign_id AS receipt_campaign_id
                FROM portfolio_readiness_current current
                JOIN portfolio_readiness_campaigns campaign
                  ON campaign.id=current.campaign_id
                LEFT JOIN portfolio_readiness_receipts receipt
                  ON receipt.id=current.receipt_id
                WHERE current.repository=? AND current.issue_number=?
                """,
                (repository, issue_number),
            ).fetchone()
            if phase is None:
                raise PullBufferError("READINESS_CAMPAIGN_NOT_FOUND")
            current_phase = readiness_campaign(
                connection, repository, issue_number
            )
            readiness_reasons = readiness_binding_reasons(
                connection, current_phase
            )
            if readiness_reasons:
                raise PullBufferError(
                    "PULL_BUFFER_READINESS_BINDING_DRIFT:"
                    + ",".join(readiness_reasons)
                )
            receipt_payload: dict[str, Any] | None = None
            try:
                receipt_payload = json.loads(
                    phase["receipt_json"], object_pairs_hook=_strict_object
                )
            except (TypeError, json.JSONDecodeError):
                pass
            if (
                int(readiness["campaign_id"]) != int(phase["campaign_id"])
                or int(readiness["current_version"])
                != int(phase["current_version"])
                - (1 if phase["state"] == "FINALIZED" else 0)
                or readiness["plan_sha256"] != phase["plan_sha256"]
                or int(readiness["receipt_id"]) != int(phase["receipt_id"] or -1)
                or readiness["receipt_sha256"] != phase["receipt_sha256"]
                or phase["verdict"] != "PASS"
                or int(phase["receipt_campaign_id"] or -1) != int(phase["campaign_id"])
                or not isinstance(receipt_payload, dict)
                or digest_json(receipt_payload) != phase["receipt_sha256"]
            ):
                raise PullBufferError("PULL_BUFFER_READINESS_ATTESTATION_DRIFT")

            finalization = connection.execute(
                """
                SELECT finalization.*, candidate.candidate_sha256,
                       candidate.artifact_content_sha256,
                       prepared.candidate_sha256 AS prepared_candidate_sha256,
                       dirty.state AS dirty_state,
                       dirty.event_sha256 AS dirty_event_sha256,
                       dirty.payload_json AS dirty_payload_json
                FROM portfolio_ready_finalizations finalization
                JOIN portfolio_pull_buffer_candidates candidate
                  ON candidate.id=finalization.ready_candidate_id
                JOIN portfolio_pull_buffer_candidates prepared
                  ON prepared.id=finalization.prepared_candidate_id
                LEFT JOIN portfolio_dirty_events dirty
                  ON dirty.id=finalization.dirty_event_id
                WHERE finalization.campaign_id=?
                """,
                (int(phase["campaign_id"]),),
            ).fetchone()
            if phase["state"] == "FINALIZED":
                if finalization is None:
                    raise PullBufferError("PULL_BUFFER_FINALIZATION_DRIFT")
                try:
                    final_payload = json.loads(
                        finalization["payload_json"], object_pairs_hook=_strict_object
                    )
                except (TypeError, json.JSONDecodeError, PullBufferError) as exc:
                    raise PullBufferError("PULL_BUFFER_FINALIZATION_DRIFT") from exc
                if (
                    int(phase["finalized_candidate_id"] or -1)
                    != int(finalization["ready_candidate_id"])
                    or int(phase["finalized_event_id"] or -1)
                    != int(finalization["dirty_event_id"])
                    or final_payload.get("ready_candidate_sha256") != candidate_sha
                    or finalization["candidate_sha256"] != candidate_sha
                    or finalization["artifact_content_sha256"] != artifact_sha
                    or int(finalization["prepared_candidate_id"])
                    != int(prepared_binding["candidate_id"])
                    or finalization["prepared_candidate_sha256"]
                    != prepared_binding["candidate_sha256"]
                    or final_payload.get("schema") != FINALIZATION_SCHEMA
                    or digest_json(final_payload)
                    != finalization["finalization_sha256"]
                    or _ready_dirty_event_error(
                        finalization,
                        {
                            "repository": repository,
                            "issue_number": issue_number,
                            "generation": int(packet["generation"]),
                            "id": int(finalization["ready_candidate_id"]),
                            "candidate_sha256": candidate_sha,
                        },
                        final_payload,
                    )
                    is not None
                ):
                    raise PullBufferError("PULL_BUFFER_FINALIZATION_DRIFT")
                if failpoint is not None:
                    failpoint("before_replay_commit")
                if packet_observation is None:
                    raise PullBufferError("PULL_BUFFER_ARTIFACT_DRIFT")
                _require_finalizer_descriptors_current(
                    packet_observation,
                    admission_observations,
                    prepared_observations.get(int(prepared_binding["candidate_id"])),
                )
                return {
                    "repository": repository,
                    "issue_number": issue_number,
                    "state": "FINALIZED",
                    "candidate_id": int(finalization["ready_candidate_id"]),
                    "candidate_sha256": candidate_sha,
                    "portfolio_dirty_event_id": int(finalization["dirty_event_id"]),
                    "portfolio_dirty_event_state": finalization["dirty_state"],
                    "finalization_sha256": finalization["finalization_sha256"],
                    "replay": True,
                }
            if phase["state"] != "READY_ELIGIBLE" or finalization is not None:
                raise PullBufferError("PULL_BUFFER_READINESS_STATE_CONFLICT")

            graph = connection.execute(
                "SELECT * FROM portfolio_graph_current WHERE repository=?",
                (repository,),
            ).fetchone()
            policy = connection.execute(
                """
                SELECT policy.* FROM coordination_capacity_current current
                JOIN coordination_capacity_policies policy
                  ON policy.repository=current.repository AND policy.version=current.version
                WHERE current.repository=?
                """,
                (repository,),
            ).fetchone()
            item = connection.execute(
                """
                SELECT item.*,
                       source.payload_sha256 AS observed_source_sha256,
                       CASE WHEN source.payload_sha256=item.source_payload_sha256
                            THEN 1 ELSE 0 END AS source_current
                FROM coordination_items item
                LEFT JOIN github_current source
                  ON source.repository=item.repository
                 AND source.object_kind='issue'
                 AND source.object_number=item.issue_number
                WHERE item.repository=? AND item.issue_number=?
                """,
                (repository, issue_number),
            ).fetchone()
            prepared = connection.execute(
                """
                SELECT candidate.* FROM portfolio_pull_buffer_current pointer
                JOIN portfolio_pull_buffer_candidates candidate
                  ON candidate.id=pointer.candidate_id
                WHERE pointer.repository=? AND pointer.issue_number=?
                """,
                (repository, issue_number),
            ).fetchone()
            if graph is None or policy is None or item is None or prepared is None:
                raise PullBufferError("PULL_BUFFER_BINDING_MISSING")
            source_equivalent = bool(
                item["observed_source_sha256"] is not None
                and readiness_source_equivalent(
                    connection,
                    current_phase,
                    str(item["source_payload_sha256"]),
                    str(item["observed_source_sha256"]),
                )
            )
            graph_equivalent = readiness_graph_equivalent(
                connection, current_phase, graph
            )
            if repository == HARNESS_REPOSITORY and packet[
                "precomputed_collision_matrix"
            ] != _graph_collision_matrix(
                connection,
                repository,
                int(graph["version"]),
                issue_number,
            ):
                raise PullBufferError("PULL_BUFFER_GRAPH_COLLISION_DRIFT")
            if (
                (graph["health"] != "CURRENT" and not graph_equivalent)
                or int(graph["version"]) != int(phase["graph_version"])
                or graph["observed_main_sha"] != phase["accepted_main_sha"]
                or int(policy["version"]) != int(phase["capacity_policy_version"])
                or int(prepared["id"]) != int(prepared_binding["candidate_id"])
                or prepared["candidate_sha256"] != prepared_binding["candidate_sha256"]
                or prepared["candidate_sha256"] != phase["candidate_sha256"]
                or prepared["state"] != "PREPARED_NOT_READY"
                or int(item["generation"]) != int(phase["generation"])
                or int(item["version"]) != int(phase["item_version"])
                or item["status"] != "PREPARED"
                or item["allocation_class"] != "NONE"
                or item["source_payload_sha256"] != phase["source_payload_sha256"]
                or (item["source_current"] != 1 and not source_equivalent)
                or packet["source_payload_sha256"] != item["source_payload_sha256"]
                or int(packet["generation"]) != int(item["generation"])
                or int(packet["item_version_at_preparation"]) != int(item["version"])
                or packet["accepted_main_at_preparation"] != graph["observed_main_sha"]
                or int(packet["portfolio_graph_version"]) != int(graph["version"])
                or int(packet["capacity_policy"]["version"]) != int(policy["version"])
                or any(
                    int(packet["capacity_policy"][field]) != int(policy[field])
                    for field in (
                        "development_limit", "shared_limit", "sre_limit"
                    )
                )
                or any(
                    int(packet["capacity_on_activation"][field]) != int(item[field])
                    for field in (
                        "development_units", "shared_units", "sre_units"
                    )
                )
            ):
                raise PullBufferError("PULL_BUFFER_BINDING_DRIFT")
            prepared_observation = prepared_observations.get(int(prepared["id"]))
            if (
                not isinstance(prepared_observation, dict)
                or prepared_observation.get("error") is not None
                or not _descriptor_is_current(prepared_observation)
                or prepared_observation.get("content_sha256")
                != prepared["artifact_content_sha256"]
            ):
                raise PullBufferError("PULL_BUFFER_PREPARED_ARTIFACT_DRIFT")

            projected_ready_version = int(item["version"]) + 1
            binding_error = admission_binding_error(
                admission,
                candidate={
                    "repository": repository,
                    "issue_number": issue_number,
                    "generation": int(item["generation"]),
                    "item_version": projected_ready_version,
                    "source_payload_sha256": item["source_payload_sha256"],
                    "accepted_main_sha": graph["observed_main_sha"],
                },
                observed_main_sha=str(graph["observed_main_sha"]),
                observation={"admission_artifacts": admission_observations},
                connection=connection,
            )
            if binding_error is not None:
                raise PullBufferError(binding_error)
            message = admission["message"]
            payload = message["payload"]
            if repository == HARNESS_REPOSITORY and payload.get(
                "hard_stops"
            ) != packet["hard_stops"]:
                raise PullBufferError("PULL_BUFFER_ADMISSION_CONTROL_DRIFT")
            projected_active = {
                "repository": repository,
                "issue_number": issue_number,
                "status": admission["item"]["status"],
                "allocation_class": "ACTIVE",
                "generation": int(item["generation"]),
                "accountable_session_id": message["recipient_session_id"],
                "lease_manifest_sha256": payload["lease_manifest_sha256"],
                "development_units": int(item["development_units"]),
                "shared_units": int(item["shared_units"]),
                "sre_units": int(item["sre_units"]),
                "source_payload_sha256": item["source_payload_sha256"],
                "version": int(payload["item_version"]),
            }
            store._validate_message_contract(
                topic=message["topic"],
                recipient_session_id=message["recipient_session_id"],
                payload=payload,
                current_write=True,
                projected_item=projected_active,
            )

            connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_candidates(
                    repository, issue_number, generation, item_version,
                    source_payload_sha256, accepted_main_sha, graph_version,
                    capacity_policy_version, lane_key, state, verticality,
                    development_units, shared_units, sre_units, promotion_trigger,
                    artifact_relative_path, artifact_content_sha256,
                    candidate_sha256, readiness_campaign_id,
                    readiness_current_version, readiness_plan_sha256,
                    readiness_receipt_id, readiness_receipt_sha256, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'READY', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository, issue_number, int(item["generation"]),
                    projected_ready_version, item["source_payload_sha256"],
                    graph["observed_main_sha"], int(graph["version"]),
                    int(policy["version"]), prepared["lane_key"],
                    packet["verticality"], int(item["development_units"]),
                    int(item["shared_units"]), int(item["sre_units"]),
                    packet["promotion_trigger"], relative_path, artifact_sha,
                    candidate_sha, int(phase["campaign_id"]),
                    int(phase["current_version"]), phase["plan_sha256"],
                    int(phase["receipt_id"]), phase["receipt_sha256"], now,
                ),
            )
            ready_candidate = connection.execute(
                "SELECT * FROM portfolio_pull_buffer_candidates "
                "WHERE repository=? AND issue_number=? AND candidate_sha256=?",
                (repository, issue_number, candidate_sha),
            ).fetchone()
            if failpoint is not None:
                failpoint("after_ready_candidate")
            _retire_pointer(
                connection,
                repository=repository,
                issue_number=issue_number,
                candidate_id=int(prepared["id"]),
                reasons=["SUPERSEDED"],
                now=now,
            )
            if failpoint is not None:
                failpoint("after_prepared_retirement")
            connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_current(
                    repository, issue_number, candidate_id, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(repository, issue_number) DO UPDATE SET
                    candidate_id=excluded.candidate_id, updated_at=excluded.updated_at
                """,
                (repository, issue_number, int(ready_candidate["id"]), now),
            )
            if failpoint is not None:
                failpoint("after_ready_pointer")
            finalization_payload = {
                "schema": FINALIZATION_SCHEMA,
                "repository": repository,
                "issue_number": issue_number,
                "generation": int(item["generation"]),
                "prepared_item_version": int(item["version"]),
                "ready_item_version": projected_ready_version,
                "source_payload_sha256": item["source_payload_sha256"],
                "accepted_main_sha": graph["observed_main_sha"],
                "graph_version": int(graph["version"]),
                "capacity_policy_version": int(policy["version"]),
                "prepared_candidate_id": int(prepared["id"]),
                "prepared_candidate_sha256": prepared["candidate_sha256"],
                "readiness_campaign_id": int(phase["campaign_id"]),
                "readiness_current_version": int(phase["current_version"]),
                "readiness_plan_sha256": phase["plan_sha256"],
                "readiness_receipt_id": int(phase["receipt_id"]),
                "readiness_receipt_sha256": phase["receipt_sha256"],
                "ready_packet_content_sha256": artifact_sha,
                "ready_candidate_sha256": candidate_sha,
                "admission_transaction_sha256": digest_json(admission),
                "lease_manifest_sha256": payload["lease_manifest_sha256"],
            }
            finalization_sha = digest_json(finalization_payload)
            dirty_event_id = enqueue_convergence_dirty_event(
                connection,
                repository=repository,
                trigger_kind="CANDIDATE_PROMOTED",
                issue_number=issue_number,
                item_version=projected_ready_version,
                source_sha256=item["source_payload_sha256"],
                status="READY",
                generation=int(item["generation"]),
                now=now,
                details={
                    "candidate_id": int(ready_candidate["id"]),
                    "candidate_sha256": candidate_sha,
                    "candidate_state": "READY",
                    "finalization_sha256": finalization_sha,
                },
                require_pending=True,
            )
            if failpoint is not None:
                failpoint("after_dirty_event")
            connection.execute(
                """
                INSERT INTO portfolio_ready_finalizations(
                    repository, issue_number, generation, prepared_candidate_id,
                    ready_candidate_id, campaign_id, receipt_id, dirty_event_id,
                    finalization_sha256, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository, issue_number, int(item["generation"]),
                    int(prepared["id"]), int(ready_candidate["id"]),
                    int(phase["campaign_id"]), int(phase["receipt_id"]),
                    dirty_event_id, finalization_sha,
                    canonical_json(finalization_payload), now,
                ),
            )
            if failpoint is not None:
                failpoint("after_finalization")
            changed = connection.execute(
                """
                UPDATE portfolio_readiness_current
                SET state='FINALIZED', finalized_candidate_id=?,
                    finalized_event_id=?, finalized_at=?, version=version+1,
                    updated_at=?, last_error=NULL
                WHERE repository=? AND issue_number=? AND campaign_id=?
                  AND state='READY_ELIGIBLE' AND version=? AND receipt_id=?
                """,
                (
                    int(ready_candidate["id"]), dirty_event_id, now, now,
                    repository, issue_number, int(phase["campaign_id"]),
                    int(phase["current_version"]), int(phase["receipt_id"]),
                ),
            ).rowcount
            if changed != 1:
                raise PullBufferError("PULL_BUFFER_READINESS_FENCE_LOST")
            ready_item = store._set_issue_status_from_ready_finalizer(
                repository=repository,
                issue_number=issue_number,
                status="READY",
                allocation_class="NONE",
                generation=int(item["generation"]),
                accountable_session_id=None,
                lease_manifest_sha256=None,
                development_units=int(item["development_units"]),
                shared_units=int(item["shared_units"]),
                sre_units=int(item["sre_units"]),
                expected_source_sha256=item["source_payload_sha256"],
                expected_version=int(item["version"]),
                now=now,
            )
            if int(ready_item["version"]) != projected_ready_version:
                raise PullBufferError("PULL_BUFFER_READY_VERSION_DRIFT")
            node = connection.execute(
                """
                SELECT node_key FROM portfolio_graph_nodes
                WHERE repository=? AND graph_version=? AND issue_number=?
                  AND dispatchable=1
                """,
                (repository, int(graph["version"]), issue_number),
            ).fetchone()
            selected = set(
                _schedule_decision(
                    connection,
                    repository,
                    current_main=str(graph["observed_main_sha"]),
                    record=False,
                    now=now,
                )["selected"]
            )
            if node is None or node["node_key"] not in selected:
                raise PullBufferError("PULL_BUFFER_READY_NOT_DISPATCHABLE")
            if failpoint is not None:
                failpoint("after_item_ready")
            readiness_event(
                connection,
                int(phase["campaign_id"]),
                "READINESS_READY_FINALIZED",
                {
                    "ready_candidate_id": int(ready_candidate["id"]),
                    "dirty_event_id": dirty_event_id,
                    "finalization_sha256": finalization_sha,
                },
                now,
            )
            if packet_observation is None:
                raise PullBufferError("PULL_BUFFER_ARTIFACT_DRIFT")
            _require_finalizer_descriptors_current(
                packet_observation,
                admission_observations,
                prepared_observation,
            )
            if failpoint is not None:
                failpoint("before_commit")
        return {
            "repository": repository,
            "issue_number": issue_number,
            "state": "FINALIZED",
            "candidate_id": int(ready_candidate["id"]),
            "candidate_sha256": candidate_sha,
            "portfolio_dirty_event_id": dirty_event_id,
            "portfolio_dirty_event_state": "PENDING",
            "finalization_sha256": finalization_sha,
            "replay": False,
        }
    finally:
        close_candidate_observations(prepared_observations)
        close_candidate_observations(
            {0: {"admission_artifacts": admission_observations}}
        )
        os.close(descriptor)


def load_candidate_packets(
    connection: sqlite3.Connection,
    repository: str,
    *,
    database: Path | None = None,
    keep_descriptors: bool = True,
    candidate_ids: set[int] | None = None,
) -> dict[int, dict[str, Any]]:
    """Read current candidate artifacts before a reconciliation write lock."""

    require_pull_buffer_schema(connection)
    database = database or _database_path(connection)
    select = """
        SELECT c.id, c.artifact_relative_path, c.artifact_content_sha256,
               a.state AS artifact_state,
               a.artifact_key AS registry_artifact_key,
               a.repository AS registry_repository,
               a.issue_number AS registry_issue_number,
               a.generation AS registry_generation,
               a.relative_path AS registry_relative_path,
               a.content_sha256 AS registry_content_sha256,
               a.size_bytes AS registry_size_bytes,
               a.device_id AS registry_device_id,
               a.inode AS registry_inode,
               a.retention_class AS registry_retention_class,
               a.registered_at AS registry_registered_at
        FROM portfolio_pull_buffer_candidates c
        LEFT JOIN coordination_artifacts a
          ON a.relative_path=c.artifact_relative_path
    """
    if candidate_ids is None:
        rows = connection.execute(
            select
            + " JOIN portfolio_pull_buffer_current pointer ON pointer.candidate_id=c.id"
            + " WHERE pointer.repository=? ORDER BY c.id",
            (repository,),
        ).fetchall()
    else:
        normalized_ids = sorted(
            candidate_id
            for candidate_id in candidate_ids
            if type(candidate_id) is int and candidate_id > 0
        )
        if len(normalized_ids) != len(candidate_ids):
            raise PullBufferError("PULL_BUFFER_CANDIDATE_ID_INVALID")
        if not normalized_ids:
            return {}
        placeholders = ",".join("?" for _ in normalized_ids)
        rows = connection.execute(
            select
            + f" WHERE c.repository=? AND c.id IN ({placeholders}) ORDER BY c.id",
            (repository, *normalized_ids),
        ).fetchall()
    observations: dict[int, dict[str, Any]] = {}
    for row in rows:
        candidate_id = int(row["id"])
        observation: dict[str, Any] = {"error": "ARTIFACT_DRIFT", "packet": None}
        if row["artifact_state"] != "REGISTERED":
            observations[candidate_id] = observation
            continue
        try:
            descriptor = _open_relative_file(
                database.parent.resolve(), row["artifact_relative_path"]
            )
            try:
                metadata = os.fstat(descriptor)
                raw = _read_descriptor(descriptor)
                final_metadata = os.fstat(descriptor)
                content_sha256 = hashlib.sha256(raw).hexdigest()
                safe = (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_uid == os.getuid()
                    and metadata.st_nlink == 1
                    and int(metadata.st_size) == int(row["registry_size_bytes"])
                    and int(metadata.st_dev) == int(row["registry_device_id"])
                    and int(metadata.st_ino) == int(row["registry_inode"])
                    and content_sha256 == row["artifact_content_sha256"]
                    and int(final_metadata.st_size) == int(metadata.st_size)
                    and int(final_metadata.st_dev) == int(metadata.st_dev)
                    and int(final_metadata.st_ino) == int(metadata.st_ino)
                    and final_metadata.st_nlink == 1
                )
                if not safe:
                    observations[candidate_id] = observation
                    continue
                packet = json.loads(
                    raw.decode("utf-8"), object_pairs_hook=_strict_object
                )
                _validate_packet(packet)
                admission_artifacts = _load_admission_artifacts(
                    connection,
                    database,
                    packet.get("admission_transaction"),
                )
                observations[candidate_id] = {
                    **_descriptor_observation(descriptor, raw),
                    "error": None,
                    "packet": packet,
                    "registered_artifact": artifact_registry_identity(
                        row, prefix="registry_"
                    ),
                    "content_sha256": content_sha256,
                    "size_bytes": int(metadata.st_size),
                    "device_id": int(metadata.st_dev),
                    "inode": int(metadata.st_ino),
                    "admission_artifacts": admission_artifacts,
                }
                if keep_descriptors:
                    descriptor = -1
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        except (OSError, UnicodeError, json.JSONDecodeError, PullBufferError):
            observations[candidate_id] = observation
    if not keep_descriptors:
        close_candidate_observations(observations)
    return observations


def _recover_finalized_ready_candidate(
    store: CoordinationStore | None,
    candidate: sqlite3.Row,
    reasons: list[str],
    *,
    now: str,
    failpoint: Callable[[str], None] | None,
) -> dict[str, Any]:
    """Atomically retire one invalid attested READY packet into fresh discovery."""

    if store is None:
        raise PullBufferError("PULL_BUFFER_RECOVERY_STORE_REQUIRED")
    connection = store.connection
    if not connection.in_transaction:
        raise PullBufferError("PULL_BUFFER_RECOVERY_TRANSACTION_REQUIRED")
    repository = str(candidate["repository"])
    issue_number = int(candidate["issue_number"])
    candidate_id = int(candidate["id"])
    current = connection.execute(
        """
        SELECT item.*, source.payload_sha256 AS observed_source_sha256,
               pointer.candidate_id AS pointer_candidate_id,
               readiness.campaign_id AS current_campaign_id,
               readiness.state AS readiness_state,
               readiness.version AS readiness_version,
               readiness.finalized_candidate_id,
               readiness.finalized_event_id,
               finalization.id AS finalization_id,
               finalization.finalization_sha256
        FROM coordination_items item
        LEFT JOIN github_current source
          ON source.repository=item.repository
         AND source.object_kind='issue'
         AND source.object_number=item.issue_number
        LEFT JOIN portfolio_pull_buffer_current pointer
          ON pointer.repository=item.repository
         AND pointer.issue_number=item.issue_number
        LEFT JOIN portfolio_readiness_current readiness
          ON readiness.repository=item.repository
         AND readiness.issue_number=item.issue_number
        LEFT JOIN portfolio_ready_finalizations finalization
          ON finalization.ready_candidate_id=pointer.candidate_id
        WHERE item.repository=? AND item.issue_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if (
        current is None
        or int(current["pointer_candidate_id"] or -1) != candidate_id
        or current["status"] != "READY"
        or current["allocation_class"] != "NONE"
        or current["accountable_session_id"] is not None
        or current["lease_manifest_sha256"] is not None
        or int(current["generation"]) != int(candidate["generation"])
        or int(current["version"]) != int(candidate["item_version"])
        or current["readiness_state"] != "FINALIZED"
        or int(current["current_campaign_id"] or -1)
        != int(candidate["readiness_campaign_id"] or -1)
        or int(current["finalized_candidate_id"] or -1) != candidate_id
        or int(current["finalized_event_id"] or -1) <= 0
        or current["finalization_id"] is None
        or not isinstance(current["observed_source_sha256"], str)
        or len(current["observed_source_sha256"]) != 64
        or ready_attestation_error(connection, dict(candidate)) is not None
    ):
        raise PullBufferError("PULL_BUFFER_RECOVERY_FENCE_LOST")

    message_guard = connection.execute(
        """
        SELECT id FROM coordination_messages
        WHERE topic IN (
            'development.admission','development.recovery_prepare',
            'development.recovery_commit','sre.admission'
        )
          AND json_extract(payload_json, '$.source.repository')=?
          AND json_extract(payload_json, '$.issue_number')=?
          AND json_extract(payload_json, '$.generation')=?
        LIMIT 1
        """,
        (repository, issue_number, int(candidate["generation"])),
    ).fetchone()
    watch_guard = connection.execute(
        """
        SELECT watch_key FROM coordination_terminal_watches
        WHERE repository=? AND issue_number=? AND generation=? LIMIT 1
        """,
        (repository, issue_number, int(candidate["generation"])),
    ).fetchone()
    if message_guard is not None or watch_guard is not None:
        raise PullBufferError("PULL_BUFFER_RECOVERY_RUNTIME_GUARD")

    planner = current_endpoint(connection, "planner")
    if planner is None:
        raise PullBufferError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
    normalized_reasons = sorted(set(reasons))
    next_generation = int(current["generation"]) + 1
    next_item_version = int(current["version"]) + 1
    recovery_payload = {
        "schema": DRIFT_RECOVERY_SCHEMA,
        "repository": repository,
        "issue_number": issue_number,
        "retired_candidate_id": candidate_id,
        "retired_candidate_sha256": candidate["candidate_sha256"],
        "finalization_id": int(current["finalization_id"]),
        "finalization_sha256": current["finalization_sha256"],
        "prior_generation": int(current["generation"]),
        "next_generation": next_generation,
        "prior_item_version": int(current["version"]),
        "next_item_version": next_item_version,
        "prior_source_payload_sha256": current["source_payload_sha256"],
        "next_source_payload_sha256": current["observed_source_sha256"],
        "reasons": normalized_reasons,
    }
    recovery_sha256 = digest_json(recovery_payload)

    _retire_pointer(
        connection,
        repository=repository,
        issue_number=issue_number,
        candidate_id=candidate_id,
        reasons=normalized_reasons,
        now=now,
    )
    if failpoint is not None:
        failpoint("after_recovery_pointer")
    changed = connection.execute(
        """
        UPDATE coordination_items
        SET status='PREPARED', allocation_class='NONE', generation=?,
            accountable_session_id=NULL, lease_manifest_sha256=NULL,
            source_payload_sha256=?, version=?, updated_at=?
        WHERE repository=? AND issue_number=? AND status='READY'
          AND allocation_class='NONE' AND accountable_session_id IS NULL
          AND lease_manifest_sha256 IS NULL AND generation=? AND version=?
        """,
        (
            next_generation,
            current["observed_source_sha256"],
            next_item_version,
            now,
            repository,
            issue_number,
            int(current["generation"]),
            int(current["version"]),
        ),
    ).rowcount
    if changed != 1:
        raise PullBufferError("PULL_BUFFER_RECOVERY_ITEM_FENCE_LOST")
    if failpoint is not None:
        failpoint("after_recovery_item")
    changed = connection.execute(
        """
        UPDATE portfolio_readiness_current
        SET state='STALE', version=version+1, updated_at=?, last_error=?
        WHERE repository=? AND issue_number=? AND campaign_id=?
          AND state='FINALIZED' AND version=?
          AND finalized_candidate_id=? AND finalized_event_id=?
        """,
        (
            now,
            "FINALIZED_READY_DRIFT:" + ",".join(normalized_reasons),
            repository,
            issue_number,
            int(current["current_campaign_id"]),
            int(current["readiness_version"]),
            candidate_id,
            int(current["finalized_event_id"]),
        ),
    ).rowcount
    if changed != 1:
        raise PullBufferError("PULL_BUFFER_RECOVERY_READINESS_FENCE_LOST")
    if failpoint is not None:
        failpoint("after_recovery_readiness")

    notice = {
        "source": {
            "repository": repository,
            "object_kind": "issue",
            "object_number": issue_number,
            "payload_sha256": current["observed_source_sha256"],
        },
        "notice_kind": "planning_request",
        "mutation_authority": False,
        "subject": f"Issue {issue_number} finalized READY drift recovery",
        "summary": (
            "An attested zero-WIP READY candidate drifted before admission and "
            "was returned atomically to fresh discovery."
        ),
        "evidence": {
            "drift_recovery_sha256": recovery_sha256,
            "retired_candidate_id": candidate_id,
            "prior_generation": int(current["generation"]),
            "next_generation": next_generation,
            "reason_count": len(normalized_reasons),
            "reasons": normalized_reasons,
        },
        "requested_evidence": [
            "One refreshed immutable PREPARED packet and one candidate-level "
            "readiness campaign bound to the new generation."
        ],
        "next_observation": (
            "Fresh pull-buffer preparation and the complete all-gates readiness "
            "phase remain pending."
        ),
    }
    planner_message_id = store.enqueue_message(
        idempotency_key=f"kanban-ready-drift-recovery:{recovery_sha256}",
        recipient_session_id=str(planner["endpoint_id"]),
        topic="coordination.notice",
        payload=notice,
        now=now,
        _transaction=False,
    )
    if failpoint is not None:
        failpoint("after_recovery_planner_notice")

    from kanban_readiness import _event as readiness_event

    readiness_event(
        connection,
        int(current["current_campaign_id"]),
        "READINESS_FINALIZED_READY_REQUEUED",
        {
            **recovery_payload,
            "drift_recovery_sha256": recovery_sha256,
            "planner_message_id": planner_message_id,
        },
        now,
    )
    store._event(
        "READY_CANDIDATE_DRIFT_RECOVERED",
        f"{repository}:issue:{issue_number}:generation:{next_generation}",
        {
            "drift_recovery_sha256": recovery_sha256,
            "planner_message_id": planner_message_id,
        },
        now,
    )
    if failpoint is not None:
        failpoint("before_recovery_commit")
    return {
        "state": "REQUEUED",
        "drift_recovery_sha256": recovery_sha256,
        "next_generation": next_generation,
        "next_item_version": next_item_version,
        "planner_message_id": planner_message_id,
    }


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and not set(value).difference("0123456789abcdef")
    )


def legacy_unclaimed_admission_recovery_notice_payload(
    request: dict[str, Any], descriptor_sha256: str
) -> dict[str, Any]:
    """Build the non-authorizing Planner notice bound to legacy evidence."""

    issue_number = int(request["issue_number"])
    return {
        "source": {
            "repository": request["repository"],
            "object_kind": "issue",
            "object_number": issue_number,
            "payload_sha256": request["current_source_payload_sha256"],
        },
        "notice_kind": "planning_request",
        "mutation_authority": False,
        "subject": f"Issue {issue_number} legacy admission recovery review",
        "summary": (
            "An external digest-bound descriptor proves one retained, "
            "unclaimed admission is eligible for Planner recovery."
        ),
        "evidence": {
            "schema": LEGACY_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA,
            "descriptor_sha256": descriptor_sha256,
            "recovery_reason": LEGACY_UNCLAIMED_ADMISSION_RECOVERY_REASON,
            "admission_message_id": request["admission_message_id"],
            "wake_key": request["wake_key"],
            "watch_key": request["watch_key"],
            "generation": request["generation"],
            "retained_item_version": request["retained_item_version"],
            "lease_manifest_sha256": request["lease_manifest_sha256"],
        },
        "requested_evidence": [
            "Exact relational proof that the historical admission was never "
            "claimed and that its delivery lineage is terminal."
        ],
        "next_observation": (
            "The current Planner may recover only through the claimed notice "
            "and its exact running executor attempt."
        ),
    }


def _validate_legacy_recovery_descriptor(
    descriptor: Any, request: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    """Validate the closed external compatibility descriptor without writes."""

    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != LEGACY_RECOVERY_DESCRIPTOR_KEYS
        or descriptor.get("schema")
        != LEGACY_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA
        or not isinstance(descriptor.get("evidence"), dict)
        or set(descriptor["evidence"]) != LEGACY_RECOVERY_EVIDENCE_KEYS
        or not _is_sha256(descriptor.get("evidence_sha256"))
        or digest_json(descriptor["evidence"]) != descriptor["evidence_sha256"]
    ):
        raise PullBufferError("LEGACY_RECOVERY_DESCRIPTOR_INVALID")
    evidence = descriptor["evidence"]
    binding_keys = (
        "repository", "issue_number", "generation", "retained_item_version",
        "source_payload_sha256", "accountable_session_id",
        "lease_manifest_sha256", "admission_message_id",
        "admission_payload_sha256", "wake_key", "wake_attempts",
        "target_progress_sha256", "watch_key",
    )
    integers = (
        "issue_number", "generation", "retained_item_version",
        "admission_message_id", "wake_attempts", "ready_candidate_id",
        "ready_finalization_id", "readiness_campaign_id",
        "readiness_receipt_id", "finalization_dirty_event_id",
    )
    strings = (
        "repository", "accountable_session_id", "wake_key", "watch_key",
        "historical_recipient", "hold_reason", "wake_last_attempt_at",
        "watch_updated_at", "item_updated_at",
    )
    hashes = (
        "source_payload_sha256", "lease_manifest_sha256",
        "admission_payload_sha256", "target_progress_sha256",
        "ready_finalization_sha256",
    )
    events = evidence.get("normalization_events")
    rotation = evidence.get("endpoint_rotation")
    attempt = evidence.get("executor_attempt")
    valid = bool(
        all(evidence.get(key) == request.get(key) for key in binding_keys)
        and all(type(evidence.get(key)) is int for key in integers)
        and all(isinstance(evidence.get(key), str) and evidence[key] for key in strings)
        and all(_is_sha256(evidence.get(key)) for key in hashes)
        and evidence["historical_recipient"] != evidence["accountable_session_id"]
        and evidence["hold_reason"] == LEGACY_UNCLAIMED_ADMISSION_HOLD_REASON
        and isinstance(events, list)
        and len(events) == 2
        and all(isinstance(event, dict) and set(event) == LEGACY_RECOVERY_EVENT_KEYS
                for event in events)
        and [event.get("event_type") for event in events]
        == ["TERMINAL_WATCH_COMPLETED", "ISSUE_STATUS_CHANGED"]
        and all(type(event.get("id")) is int and event["id"] > 0 for event in events)
        and events[0]["id"] < events[1]["id"]
        and all(_is_sha256(event.get("payload_sha256")) for event in events)
        and all(isinstance(event.get("created_at"), str) and event["created_at"]
                for event in events)
        and events[0]["created_at"] == evidence["watch_updated_at"]
        and events[1]["created_at"] == evidence["watch_updated_at"]
        and evidence["wake_last_attempt_at"] <= evidence["watch_updated_at"]
        and isinstance(rotation, dict)
        and set(rotation) == LEGACY_RECOVERY_ROTATION_KEYS
        and _is_sha256(rotation.get("change_id"))
        and type(rotation.get("change_version")) is int
        and rotation["change_version"] > 0
        and rotation.get("before_item_version")
        == evidence["retained_item_version"] - 1
        and rotation.get("not_before") == events[1]["created_at"]
        and isinstance(attempt, dict)
        and set(attempt) == LEGACY_RECOVERY_ATTEMPT_KEYS
        and all(isinstance(attempt.get(key), str) and attempt[key] for key in (
            "attempt_id", "role", "endpoint_id", "target_kind", "target_key",
            "state", "last_error",
        ))
        and type(attempt.get("exit_code")) is int
        and attempt["role"] == "development"
        and attempt["state"] == "HOLD"
        and attempt["exit_code"] == 0
        and attempt["last_error"] == LEGACY_UNCLAIMED_ADMISSION_ATTEMPT_ERROR
    )
    if not valid:
        raise PullBufferError("LEGACY_RECOVERY_DESCRIPTOR_INVALID")
    descriptor_sha256 = digest_json(descriptor)
    return evidence, descriptor_sha256


def cutover_held_unclaimed_admission_recovery_notice_payload(
    request: dict[str, Any], descriptor_sha256: str
) -> dict[str, Any]:
    """Build the non-authorizing Planner notice for one cutover-held lineage."""

    issue_number = int(request["issue_number"])
    return {
        "source": {
            "repository": request["repository"],
            "object_kind": "issue",
            "object_number": issue_number,
            "payload_sha256": request["current_source_payload_sha256"],
        },
        "notice_kind": "planning_request",
        "mutation_authority": False,
        "subject": f"Issue {issue_number} cutover-held admission recovery review",
        "summary": (
            "A closed digest-bound descriptor proves one never-claimed "
            "admission was retained solely for same-role endpoint cutover."
        ),
        "evidence": {
            "schema": CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA,
            "descriptor_sha256": descriptor_sha256,
            "recovery_reason": CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON,
            "admission_message_id": request["admission_message_id"],
            "wake_key": request["wake_key"],
            "watch_key": request["watch_key"],
            "generation": request["generation"],
            "retained_item_version": request["retained_item_version"],
            "lease_manifest_sha256": request["lease_manifest_sha256"],
        },
        "requested_evidence": [
            "Exact relational proof of zero claims, one terminal no-progress "
            "attempt, and the applied same-role endpoint rotation."
        ],
        "next_observation": (
            "The current Planner may recover only through the claimed notice "
            "and its exact running executor attempt."
        ),
    }


def _validate_cutover_held_recovery_descriptor(
    descriptor: Any, request: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    """Validate the distinct closed cutover-held descriptor without writes."""

    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != CUTOVER_HELD_RECOVERY_DESCRIPTOR_KEYS
        or descriptor.get("schema")
        != CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA
        or not isinstance(descriptor.get("evidence"), dict)
        or set(descriptor["evidence"]) != CUTOVER_HELD_RECOVERY_EVIDENCE_KEYS
        or not _is_sha256(descriptor.get("evidence_sha256"))
        or digest_json(descriptor["evidence"]) != descriptor["evidence_sha256"]
    ):
        raise PullBufferError("CUTOVER_HELD_RECOVERY_DESCRIPTOR_INVALID")
    evidence = descriptor["evidence"]
    binding_keys = (
        "repository", "issue_number", "generation", "retained_item_version",
        "source_payload_sha256", "current_source_payload_sha256",
        "accountable_session_id", "lease_manifest_sha256",
        "admission_message_id", "admission_payload_sha256", "wake_key",
        "wake_attempts", "target_progress_sha256", "watch_key",
    )
    integers = (
        "issue_number", "generation", "retained_item_version",
        "admission_message_id", "wake_attempts", "ready_candidate_id",
        "ready_finalization_id", "readiness_campaign_id",
        "readiness_receipt_id", "finalization_dirty_event_id",
    )
    strings = (
        "repository", "accountable_session_id", "wake_key", "watch_key",
        "role", "historical_recipient", "hold_reason", "message_updated_at",
        "wake_last_attempt_at", "wake_updated_at", "watch_updated_at",
        "item_updated_at",
    )
    hashes = (
        "source_payload_sha256", "current_source_payload_sha256",
        "lease_manifest_sha256", "admission_payload_sha256",
        "target_progress_sha256", "ready_finalization_sha256",
    )
    role = evidence.get("role")
    capacity = evidence.get("capacity")
    events = evidence.get("cutover_events")
    rotation = evidence.get("endpoint_rotation")
    attempt = evidence.get("executor_attempt")
    lineage_sha256 = digest_json({
        "generation": evidence.get("generation"),
        "issue_number": evidence.get("issue_number"),
        "lease_manifest_sha256": evidence.get("lease_manifest_sha256"),
        "repository": evidence.get("repository"),
    })
    valid = bool(
        all(evidence.get(key) == request.get(key) for key in binding_keys)
        and all(type(evidence.get(key)) is int for key in integers)
        and all(isinstance(evidence.get(key), str) and evidence[key] for key in strings)
        and all(_is_sha256(evidence.get(key)) for key in hashes)
        and evidence["source_payload_sha256"]
        == evidence["current_source_payload_sha256"]
        and role in {"development", "sre"}
        and evidence["historical_recipient"] != evidence["accountable_session_id"]
        and evidence["hold_reason"]
        == CUTOVER_HELD_UNCLAIMED_ADMISSION_HOLD_REASON
        and evidence["wake_attempts"] == 1
        and isinstance(capacity, dict)
        and set(capacity) == CUTOVER_HELD_RECOVERY_CAPACITY_KEYS
        and all(type(capacity.get(key)) is int and capacity[key] >= 0
                for key in CUTOVER_HELD_RECOVERY_CAPACITY_KEYS)
        and sum(capacity.values()) > 0
        and (
            (role == "development" and capacity["sre_units"] == 0)
            or (
                role == "sre"
                and capacity == {
                    "development_units": 0,
                    "shared_units": 0,
                    "sre_units": capacity["sre_units"],
                }
                and capacity["sre_units"] > 0
            )
        )
        and isinstance(events, list)
        and len(events) == 2
        and all(isinstance(event, dict)
                and set(event) == CUTOVER_HELD_RECOVERY_EVENT_KEYS
                for event in events)
        and [event.get("event_type") for event in events]
        == ["MESSAGE_HELD", "WAKE_COMPLETED"]
        and all(type(event.get("id")) is int and event["id"] > 0 for event in events)
        and events[0]["id"] < events[1]["id"]
        and all(_is_sha256(event.get("payload_sha256")) for event in events)
        and all(isinstance(event.get("created_at"), str) and event["created_at"]
                for event in events)
        and events[0]["entity_key"]
        == f"message:{evidence['admission_message_id']}"
        and events[0]["payload_sha256"] == digest_json({
            "error": CUTOVER_HELD_UNCLAIMED_ADMISSION_HOLD_REASON,
            "planner_session_id": request["planner_session_id"],
        })
        and events[0]["created_at"] == evidence["message_updated_at"]
        and events[1]["entity_key"] == evidence["wake_key"]
        and events[1]["payload_sha256"] == digest_json({})
        and events[1]["created_at"] == evidence["wake_updated_at"]
        and evidence["wake_last_attempt_at"] <= evidence["message_updated_at"]
        and evidence["message_updated_at"] <= evidence["wake_updated_at"]
        and evidence["wake_updated_at"] <= evidence["item_updated_at"]
        and evidence["watch_updated_at"] == evidence["item_updated_at"]
        and isinstance(rotation, dict)
        and set(rotation) == LEGACY_RECOVERY_ROTATION_KEYS
        and _is_sha256(rotation.get("change_id"))
        and type(rotation.get("change_version")) is int
        and rotation["change_version"] > 0
        and rotation.get("before_item_version")
        == evidence["retained_item_version"] - 1
        and rotation.get("not_before") == events[0]["created_at"]
        and isinstance(attempt, dict)
        and set(attempt) == CUTOVER_HELD_RECOVERY_ATTEMPT_KEYS
        and all(isinstance(attempt.get(key), str) and attempt[key] for key in (
            "attempt_id", "role", "endpoint_id", "target_kind", "target_key",
            "target_progress_sha256", "terminal_progress_sha256",
            "lineage_repository", "lineage_lease_sha256", "lineage_sha256",
            "state", "updated_at", "last_error",
        ))
        and type(attempt.get("lineage_issue_number")) is int
        and type(attempt.get("lineage_generation")) is int
        and type(attempt.get("exit_code")) is int
        and attempt["role"] == role
        and attempt["endpoint_id"] == evidence["historical_recipient"]
        and attempt["target_kind"] == "message"
        and attempt["target_key"] == str(evidence["admission_message_id"])
        and attempt["target_progress_sha256"] == evidence["target_progress_sha256"]
        and attempt["terminal_progress_sha256"] == evidence["target_progress_sha256"]
        and attempt["lineage_repository"] == evidence["repository"]
        and attempt["lineage_issue_number"] == evidence["issue_number"]
        and attempt["lineage_generation"] == evidence["generation"]
        and attempt["lineage_lease_sha256"] == evidence["lease_manifest_sha256"]
        and attempt["lineage_sha256"] == lineage_sha256
        and attempt["state"] == "HOLD"
        and attempt["exit_code"] == 0
        and attempt["last_error"] == LEGACY_UNCLAIMED_ADMISSION_ATTEMPT_ERROR
        and attempt["updated_at"] <= evidence["message_updated_at"]
    )
    if not valid:
        raise PullBufferError("CUTOVER_HELD_RECOVERY_DESCRIPTOR_INVALID")
    descriptor_sha256 = digest_json(descriptor)
    return evidence, descriptor_sha256


def _validate_unclaimed_recovery_request(request: dict[str, Any]) -> bool:
    if set(request) != UNCLAIMED_RECOVERY_REQUEST_KEYS:
        return False
    recovery_reason = request.get("recovery_reason")
    expected_wake_attempts = (
        1
        if recovery_reason == CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON
        else 3
    )
    integers = (
        type(request.get("issue_number")) is int and request["issue_number"] > 0,
        type(request.get("generation")) is int and request["generation"] >= 0,
        type(request.get("retained_item_version")) is int
        and request["retained_item_version"] > 0,
        type(request.get("admission_message_id")) is int
        and request["admission_message_id"] > 0,
        request.get("wake_attempts") == expected_wake_attempts,
    )
    notice_id = request.get("recovery_notice_message_id")
    notice_valid = type(notice_id) is int and notice_id > 0
    return bool(
        request.get("schema") == UNCLAIMED_ADMISSION_RECOVERY_SCHEMA
        and isinstance(request.get("repository"), str)
        and all(integers)
        and request.get("wake_key")
        == f"message:{request['admission_message_id']}:prepared"
        and request.get("watch_key")
        == terminal_watch_key(
            request["repository"], request["issue_number"], request["generation"]
        )
        and all(
            isinstance(request.get(key), str) and bool(request[key])
            for key in ("planner_session_id", "accountable_session_id")
        )
        and all(
            _is_sha256(request.get(key))
            for key in (
                "source_payload_sha256",
                "current_source_payload_sha256",
                "lease_manifest_sha256",
                "admission_payload_sha256",
                "target_progress_sha256",
            )
        )
        and request.get("recovery_reason")
        in {
            UNCLAIMED_ADMISSION_RETRY_REASON,
            LEGACY_UNCLAIMED_ADMISSION_RECOVERY_REASON,
            CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON,
        }
        and notice_valid
    )


def _load_unclaimed_recovery_rows(
    connection: sqlite3.Connection, request: dict[str, Any]
) -> dict[str, sqlite3.Row]:
    issue = (request["repository"], request["issue_number"])
    queries = {
        "message": ("SELECT * FROM coordination_messages WHERE id=?",
                    (request["admission_message_id"],)),
        "wake": ("SELECT * FROM coordination_wakes WHERE wake_key=?",
                 (request["wake_key"],)),
        "watch": ("SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                  (request["watch_key"],)),
        "item": ("SELECT * FROM coordination_items WHERE repository=? AND issue_number=?", issue),
        "readiness": ("SELECT * FROM portfolio_readiness_current "
                      "WHERE repository=? AND issue_number=?", issue),
    }
    rows = {name: connection.execute(sql, values).fetchone()
            for name, (sql, values) in queries.items()}
    if any(row is None for row in rows.values()):
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_FENCE_MISMATCH")
    admitted = connection.execute(
        "SELECT finalization.id FROM portfolio_ready_finalizations finalization "
        "JOIN portfolio_dirty_events dirty ON dirty.id=finalization.dirty_event_id "
        "WHERE finalization.repository=? AND finalization.issue_number=? "
        "AND finalization.generation=? AND dirty.state='COMPLETE' "
        "AND json_extract(dirty.result_json,'$.outcome')='ADMITTED' "
        "AND json_extract(dirty.result_json,'$.admitted_issue_number')=? "
        "AND json_extract(dirty.result_json,'$.message_id')=?",
        (*issue, request["generation"], request["issue_number"],
         request["admission_message_id"]),
    ).fetchall()
    if len(admitted) != 1:
        raise PullBufferError("UNCLAIMED_ADMISSION_FINALIZATION_DRIFT")
    finalization = connection.execute(
        "SELECT * FROM portfolio_ready_finalizations WHERE id=?", (admitted[0][0],)
    ).fetchone()
    dirty = connection.execute(
        "SELECT * FROM portfolio_dirty_events WHERE id=?",
        (finalization["dirty_event_id"],),
    ).fetchone()
    try:
        result = json.loads(dirty["result_json"], object_pairs_hook=_strict_object)
    except (TypeError, json.JSONDecodeError, PullBufferError) as exc:
        raise PullBufferError("UNCLAIMED_ADMISSION_FINALIZATION_DRIFT") from exc
    if digest_json(result) != dirty["result_sha256"]:
        raise PullBufferError("UNCLAIMED_ADMISSION_FINALIZATION_DRIFT")
    candidate = connection.execute(
        "SELECT * FROM portfolio_pull_buffer_candidates WHERE id=?",
        (finalization["ready_candidate_id"],),
    ).fetchone()
    if candidate is None:
        raise PullBufferError("UNCLAIMED_ADMISSION_FINALIZATION_DRIFT")
    rows.update({"finalization": finalization, "dirty": dirty, "candidate": candidate})
    return rows


def _recovery_sources(
    connection: sqlite3.Connection, request: dict[str, Any], *, legacy: bool
) -> None:
    payloads: list[dict[str, Any]] = []
    for payload_sha256 in (
        request["source_payload_sha256"],
        request["current_source_payload_sha256"],
    ):
        row = connection.execute(
            "SELECT payload_json FROM github_snapshots WHERE repository=? "
            "AND object_kind='issue' AND object_number=? AND payload_sha256=?",
            (request["repository"], request["issue_number"], payload_sha256),
        ).fetchone()
        try:
            payload = json.loads(row["payload_json"], object_pairs_hook=_strict_object)
        except (TypeError, json.JSONDecodeError, PullBufferError) as exc:
            raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_SOURCE_DRIFT") from exc
        if digest_json(payload) != payload_sha256:
            raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_SOURCE_DRIFT")
        payloads.append(payload)
    bound, current = payloads
    bound_stable = digest_json(_legacy_recovery_stable_source(bound))
    current_stable = digest_json(_legacy_recovery_stable_source(current))
    if legacy:
        if bound_stable != current_stable:
            raise PullBufferError("LEGACY_RECOVERY_MATERIAL_SOURCE_DRIFT")
    elif request["source_payload_sha256"] != request["current_source_payload_sha256"]:
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_SOURCE_DRIFT")


def _recovery_terminal_error(
    connection: sqlite3.Connection, request: dict[str, Any]
) -> str | None:
    message_key = f"message:{request['admission_message_id']}"
    if connection.execute(
        "SELECT 1 FROM coordination_events WHERE event_type='MESSAGE_CLAIMED' "
        "AND entity_key=? LIMIT 1",
        (message_key,),
    ).fetchone():
        return "UNCLAIMED_ADMISSION_CLAIM_EVIDENCE_PRESENT"
    attempts = connection.execute(
        """
        SELECT state FROM executor_attempts
        WHERE (target_kind='message' AND target_key=?)
           OR (lineage_repository=? AND lineage_issue_number=?
               AND lineage_generation=? AND lineage_lease_sha256=?)
        """,
        (
            str(request["admission_message_id"]), request["repository"],
            request["issue_number"], request["generation"],
            request["lease_manifest_sha256"],
        ),
    ).fetchall()
    if any(row["state"] not in {"COMPLETE", "HOLD", "LAUNCH_FAILED"} for row in attempts):
        return "UNCLAIMED_ADMISSION_TERMINAL_LINEAGE_PRESENT"
    lineage = (request["repository"], request["issue_number"], request["generation"])
    if connection.execute(
        """
        SELECT 1 FROM coordination_terminal_closeout_packets
        WHERE repository=? AND issue_number=? AND generation=?
        UNION ALL SELECT 1 FROM coordination_pre_push_gates
        WHERE repository=? AND issue_number=? AND generation=?
        UNION ALL SELECT 1 FROM coordination_pre_push_publications
        WHERE repository=? AND issue_number=? AND generation=? LIMIT 1
        """,
        lineage * 3,
    ).fetchone():
        return "UNCLAIMED_ADMISSION_TERMINAL_LINEAGE_PRESENT"
    if connection.execute(
        "SELECT 1 FROM coordination_messages "
        "WHERE topic='development.terminal_closeout' "
        "AND json_extract(payload_json,'$.source.repository')=? "
        "AND json_extract(payload_json,'$.issue_number')=? "
        "AND json_extract(payload_json,'$.generation')=? LIMIT 1",
        lineage,
    ).fetchone():
        return "UNCLAIMED_ADMISSION_TERMINAL_LINEAGE_PRESENT"
    return None


def _validate_recovery_notice(
    store: CoordinationStore,
    request: dict[str, Any],
    *,
    compatibility_descriptor_sha256: str | None,
    replay: bool,
) -> sqlite3.Row:
    connection = store.connection
    notice_id = int(request["recovery_notice_message_id"])
    notice = connection.execute(
        "SELECT * FROM coordination_messages WHERE id=?", (notice_id,)
    ).fetchone()
    if notice is None:
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_NOTICE_DRIFT")
    try:
        observed_payload = json.loads(
            notice["payload_json"], object_pairs_hook=_strict_object
        )
    except (TypeError, json.JSONDecodeError, PullBufferError) as exc:
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_NOTICE_DRIFT") from exc
    if compatibility_descriptor_sha256 is None:
        exhaustion = unclaimed_admission_exhaustion_payload({
            **request, "item_version": request["retained_item_version"] - 1,
        })
        exhaustion_sha256 = digest_json(exhaustion)
        expected_payload = unclaimed_admission_recovery_notice_payload(
            exhaustion, request["source_payload_sha256"]
        )
        expected_idempotency_key = (
            f"unclaimed-admission-recovery:{exhaustion_sha256}"
        )
        event_count = connection.execute(
            "SELECT COUNT(*) FROM coordination_events "
            "WHERE event_type='UNCLAIMED_ADMISSION_RETRY_EXHAUSTED' "
            "AND entity_key=? AND payload_sha256=?",
            (
                f"{request['repository']}:issue:{request['issue_number']}:"
                f"generation:{request['generation']}",
                digest_json({
                    "exhaustion_sha256": exhaustion_sha256,
                    "planner_message_id": notice_id,
                    "reason": UNCLAIMED_ADMISSION_RETRY_REASON,
                }),
            ),
        ).fetchone()[0]
    elif request["recovery_reason"] == LEGACY_UNCLAIMED_ADMISSION_RECOVERY_REASON:
        expected_payload = legacy_unclaimed_admission_recovery_notice_payload(
            request, compatibility_descriptor_sha256
        )
        expected_idempotency_key = (
            "legacy-unclaimed-admission-recovery:"
            f"{compatibility_descriptor_sha256}"
        )
        event_count = 1
    elif (
        request["recovery_reason"]
        == CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON
    ):
        expected_payload = cutover_held_unclaimed_admission_recovery_notice_payload(
            request, compatibility_descriptor_sha256
        )
        expected_idempotency_key = (
            "cutover-held-unclaimed-admission-recovery:"
            f"{compatibility_descriptor_sha256}"
        )
        event_count = 1
    else:
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_NOTICE_DRIFT")
    valid = bool(
        notice["idempotency_key"] == expected_idempotency_key
        and observed_payload == expected_payload
        and event_count == 1
    )
    if (
        not valid
        or digest_json(observed_payload) != notice["payload_sha256"]
        or notice["recipient_session_id"] != request["planner_session_id"]
        or notice["topic"] != "coordination.notice"
    ):
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_NOTICE_DRIFT")
    if notice["state"] != ("COMPLETE" if replay else "CLAIMED"):
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_NOTICE_NOT_CLAIMED")
    if notice["claimed_by"] != request["planner_session_id"]:
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_NOTICE_DRIFT")
    return notice


def _authenticate_recovery_attempt(
    connection: sqlite3.Connection,
    request: dict[str, Any],
    notice: sqlite3.Row,
    *,
    attempt_id: str | None,
    executor_token: str | None,
) -> None:
    """Authenticate the current Planner's exact running notice attempt."""

    if (
        not isinstance(attempt_id, str)
        or not attempt_id
        or not isinstance(executor_token, str)
        or not executor_token
    ):
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_ATTEMPT_REQUIRED")
    attempt = connection.execute(
        "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if attempt is None:
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_ATTEMPT_NOT_FOUND")
    token_sha256 = hashlib.sha256(executor_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(str(attempt["token_sha256"]), token_sha256):
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_TOKEN_MISMATCH")
    if (
        attempt["role"] != "planner"
        or attempt["endpoint_id"] != request["planner_session_id"]
        or attempt["state"] != "RUNNING"
        or attempt["target_kind"] != "message"
        or attempt["target_key"] != str(notice["id"])
        or attempt["repository_scope"]
        != canonical_repository_scope(request["repository"])
    ):
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_ATTEMPT_BINDING_MISMATCH")


def _legacy_recovery_fence(
    connection: sqlite3.Connection,
    rows: dict[str, sqlite3.Row],
    request: dict[str, Any],
    evidence: dict[str, Any],
    *,
    replay: bool,
) -> None:
    """Verify one historical unclaimed admission from external exact evidence."""

    message, wake, watch = rows["message"], rows["wake"], rows["watch"]
    candidate, finalization = rows["candidate"], rows["finalization"]
    events_descriptor = evidence["normalization_events"]
    event_ids = tuple(event["id"] for event in events_descriptor)
    events = connection.execute(
        "SELECT id,event_type,entity_key,payload_sha256,created_at "
        "FROM coordination_events WHERE id IN (?,?) ORDER BY id",
        event_ids,
    ).fetchall()
    normalized_version = request["retained_item_version"] - 1
    entity_key = f"{request['repository']}:issue:{request['issue_number']}"
    normalized = (
        digest_json({"allocation_class": "RETAINED", "item_version": normalized_version,
                     "status": "HOLD"}),
        digest_json({
            "allocation_class": "RETAINED", "generation": request["generation"],
            "issue_number": request["issue_number"],
            "repository": request["repository"],
            "source_payload_sha256": request["source_payload_sha256"],
            "status": "HOLD", "version": normalized_version,
        }),
    )
    exact = (
        (message["recipient_session_id"], message["state"], message["last_error"])
        == (evidence["historical_recipient"], "HOLD", evidence["hold_reason"]),
        (wake["state"], wake["last_error"], wake["last_attempt_at"])
        == ("HOLD", evidence["hold_reason"], evidence["wake_last_attempt_at"]),
        (watch["state"], watch["accountable_session_id"], watch["process_id"],
         watch["claim_attempt_id"], int(watch["attempts"]), watch["updated_at"],
         watch["last_error"])
        == ("COMPLETE", evidence["historical_recipient"], None, None, 0,
            evidence["watch_updated_at"], None),
        (int(candidate["id"]), int(finalization["id"]),
         int(finalization["campaign_id"]), int(finalization["receipt_id"]),
         int(finalization["dirty_event_id"]), finalization["finalization_sha256"])
        == tuple(evidence[key] for key in (
            "ready_candidate_id", "ready_finalization_id", "readiness_campaign_id",
            "readiness_receipt_id", "finalization_dirty_event_id",
            "ready_finalization_sha256",
        )),
        [dict(row) for row in events] == events_descriptor,
        all(event["entity_key"] == entity_key for event in events_descriptor),
        normalized == tuple(event["payload_sha256"] for event in events_descriptor),
        replay or rows["item"]["updated_at"] == evidence["item_updated_at"],
    )
    if not all(exact):
        raise PullBufferError("LEGACY_RECOVERY_FENCE_MISMATCH")
    rotation_descriptor = evidence["endpoint_rotation"]
    rotation = applied_endpoint_rotation_chain(
        connection,
        repository=request["repository"],
        issue_number=request["issue_number"],
        before_identity=evidence["historical_recipient"],
        before_item_version=normalized_version,
        after_identity=request["accountable_session_id"],
        after_item_version=request["retained_item_version"],
        not_before=rotation_descriptor["not_before"],
        change_id=rotation_descriptor["change_id"],
        change_version=rotation_descriptor["change_version"],
    )
    attempts = connection.execute(
        "SELECT attempt_id,role,endpoint_id,target_kind,target_key,state,"
        "exit_code,last_error FROM executor_attempts "
        "WHERE target_kind='message' AND target_key=? ORDER BY attempt_id",
        (str(request["admission_message_id"]),),
    ).fetchall()
    attempt = None if len(attempts) != 1 else dict(attempts[0])
    attempt_descriptor = evidence["executor_attempt"]
    historical_role = identity_role(connection, evidence["historical_recipient"])
    if (
        rotation is None
        or historical_role != "development"
        or identity_role(connection, request["accountable_session_id"])
        != historical_role
        or attempt != attempt_descriptor
        or attempt_descriptor["role"] != historical_role
        or attempt_descriptor["endpoint_id"] != evidence["historical_recipient"]
        or attempt_descriptor["target_kind"] != "message"
        or attempt_descriptor["target_key"] != str(request["admission_message_id"])
        or attempt_descriptor["state"] != "HOLD"
    ):
        raise PullBufferError("LEGACY_RECOVERY_FENCE_MISMATCH")


def _cutover_held_recovery_fence(
    connection: sqlite3.Connection,
    rows: dict[str, sqlite3.Row],
    request: dict[str, Any],
    evidence: dict[str, Any],
    *,
    replay: bool,
) -> None:
    """Verify one never-claimed admission held for exact endpoint cutover."""

    message, wake, watch = rows["message"], rows["wake"], rows["watch"]
    item, candidate, finalization = (
        rows["item"], rows["candidate"], rows["finalization"]
    )
    events_descriptor = evidence["cutover_events"]
    event_ids = tuple(event["id"] for event in events_descriptor)
    events = connection.execute(
        "SELECT id,event_type,entity_key,payload_sha256,created_at "
        "FROM coordination_events WHERE id IN (?,?) ORDER BY id",
        event_ids,
    ).fetchall()
    attempt_descriptor = evidence["executor_attempt"]
    attempts = connection.execute(
        "SELECT attempt_id,role,endpoint_id,target_kind,target_key,"
        "target_progress_sha256,terminal_progress_sha256,lineage_repository,"
        "lineage_issue_number,lineage_generation,lineage_lease_sha256,"
        "lineage_sha256,state,exit_code,updated_at,last_error "
        "FROM executor_attempts WHERE "
        "(target_kind='message' AND target_key=?) OR "
        "(lineage_repository=? AND lineage_issue_number=? "
        "AND lineage_generation=? AND lineage_lease_sha256=?) "
        "ORDER BY attempt_id",
        (
            str(request["admission_message_id"]), request["repository"],
            request["issue_number"], request["generation"],
            request["lease_manifest_sha256"],
        ),
    ).fetchall()
    role = evidence["role"]
    capacity = evidence["capacity"]
    exact = (
        (
            message["recipient_session_id"], message["topic"], message["state"],
            message["last_error"], message["updated_at"],
        ) == (
            evidence["historical_recipient"], f"{role}.admission", "HOLD",
            evidence["hold_reason"], evidence["message_updated_at"],
        ),
        (
            wake["message_id"], wake["recipient_session_id"],
            wake["message_payload_sha256"], wake["state"], int(wake["attempts"]),
            wake["process_id"], wake["last_attempt_at"], wake["updated_at"],
            wake["last_error"],
        ) == (
            request["admission_message_id"], evidence["historical_recipient"],
            request["admission_payload_sha256"], "COMPLETE", 1, None,
            evidence["wake_last_attempt_at"], evidence["wake_updated_at"], None,
        ),
        (
            watch["state"], watch["accountable_session_id"], watch["process_id"],
            watch["claim_attempt_id"], int(watch["attempts"]),
            watch["updated_at"], watch["last_error"],
        ) == (
            "HOLD", request["accountable_session_id"], None, None, 0,
            evidence["watch_updated_at"], evidence["hold_reason"],
        ),
        replay or (
            item["status"], item["allocation_class"], item["updated_at"],
        ) == ("HOLD", "RETAINED", evidence["item_updated_at"]),
        (
            int(item["development_units"]), int(item["shared_units"]),
            int(item["sre_units"]),
        ) == (
            capacity["development_units"], capacity["shared_units"],
            capacity["sre_units"],
        ),
        (
            int(candidate["id"]), int(finalization["id"]),
            int(finalization["campaign_id"]), int(finalization["receipt_id"]),
            int(finalization["dirty_event_id"]),
            finalization["finalization_sha256"],
        ) == tuple(evidence[key] for key in (
            "ready_candidate_id", "ready_finalization_id",
            "readiness_campaign_id", "readiness_receipt_id",
            "finalization_dirty_event_id", "ready_finalization_sha256",
        )),
        [dict(row) for row in events] == events_descriptor,
        len(attempts) == 1 and dict(attempts[0]) == attempt_descriptor,
    )
    if not all(exact):
        raise PullBufferError("CUTOVER_HELD_RECOVERY_FENCE_MISMATCH")
    try:
        require_current_endpoint_identity(
            connection,
            request["accountable_session_id"],
            expected_role=role,
        )
    except RegistryError as exc:
        raise PullBufferError("CUTOVER_HELD_RECOVERY_FENCE_MISMATCH") from exc
    rotation_descriptor = evidence["endpoint_rotation"]
    rotation = applied_endpoint_rotation_chain(
        connection,
        repository=request["repository"],
        issue_number=request["issue_number"],
        before_identity=evidence["historical_recipient"],
        before_item_version=rotation_descriptor["before_item_version"],
        after_identity=request["accountable_session_id"],
        after_item_version=request["retained_item_version"],
        watch_key=request["watch_key"],
        expected_watch_state="HOLD",
        not_before=rotation_descriptor["not_before"],
        change_id=rotation_descriptor["change_id"],
        change_version=rotation_descriptor["change_version"],
    )
    historical_role = identity_role(connection, evidence["historical_recipient"])
    if (
        rotation is None
        or len(rotation) != 1
        or historical_role != role
        or identity_role(connection, request["accountable_session_id"]) != role
        or rotation[0]["watch_transition"] is None
        or rotation[0]["watch_transition"]["expected_updated_at"]
        != evidence["message_updated_at"]
    ):
        raise PullBufferError("CUTOVER_HELD_RECOVERY_FENCE_MISMATCH")


def recover_unclaimed_admission(
    store: CoordinationStore,
    request: dict[str, Any],
    *,
    now: str,
    attempt_id: str | None = None,
    executor_token: str | None = None,
    compatibility_descriptor: dict[str, Any] | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Planner-only, exact, replay-safe rebaseline of one unclaimed admission."""

    if not isinstance(request, dict) or not _validate_unclaimed_recovery_request(request):
        raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_REQUEST_INVALID")
    legacy = (
        request["recovery_reason"]
        == LEGACY_UNCLAIMED_ADMISSION_RECOVERY_REASON
    )
    cutover_held = (
        request["recovery_reason"]
        == CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON
    )
    compatibility_evidence: dict[str, Any] | None = None
    compatibility_descriptor_sha256: str | None = None
    if legacy:
        compatibility_evidence, compatibility_descriptor_sha256 = (
            _validate_legacy_recovery_descriptor(compatibility_descriptor, request)
        )
    elif cutover_held:
        compatibility_evidence, compatibility_descriptor_sha256 = (
            _validate_cutover_held_recovery_descriptor(
                compatibility_descriptor, request
            )
        )
    elif compatibility_descriptor is not None:
        raise PullBufferError("LEGACY_RECOVERY_DESCRIPTOR_UNEXPECTED")
    connection = store.connection
    with store.transaction():
        try:
            require_current_endpoint_identity(
                connection,
                request["planner_session_id"],
                expected_role="planner",
            )
        except RegistryError as exc:
            raise PullBufferError("CURRENT_PLANNER_ENDPOINT_REQUIRED") from exc
        rows = _load_unclaimed_recovery_rows(connection, request)
        message, wake, watch = rows["message"], rows["wake"], rows["watch"]
        item, readiness = rows["item"], rows["readiness"]
        candidate, finalization = rows["candidate"], rows["finalization"]
        try:
            payload = json.loads(message["payload_json"], object_pairs_hook=_strict_object)
        except (TypeError, json.JSONDecodeError, PullBufferError) as exc:
            raise PullBufferError("UNCLAIMED_ADMISSION_FINALIZATION_DRIFT") from exc
        source = payload.get("source") if isinstance(payload, dict) else None
        capacity = payload.get("capacity") if isinstance(payload, dict) else None
        admission_item_version = request["retained_item_version"] - (
            2 if legacy or cutover_held else 1
        )
        expected_watch_owner = (
            message["recipient_session_id"] if legacy else request["accountable_session_id"]
        )
        unit_keys = ("development_units", "shared_units", "sre_units")
        if (
            not isinstance(source, dict)
            or not isinstance(capacity, dict)
            or message["topic"] not in {"development.admission", "sre.admission"}
            or message["claimed_by"] is not None
            or message["payload_sha256"] != request["admission_payload_sha256"]
            or digest_json(payload) != message["payload_sha256"]
            or source != {
                "repository": request["repository"],
                "object_kind": "issue",
                "object_number": request["issue_number"],
                "payload_sha256": request["source_payload_sha256"],
            }
            or (
                payload.get("issue_number"), payload.get("generation"),
                payload.get("lease_manifest_sha256"), payload.get("item_version"),
            ) != (
                request["issue_number"], request["generation"],
                request["lease_manifest_sha256"],
                admission_item_version,
            )
            or type(payload.get("item_version")) is not int
            or (
                wake["message_id"], wake["recipient_session_id"],
                wake["message_payload_sha256"], int(wake["attempts"]),
                wake["target_progress_sha256"], wake["process_id"],
            ) != (
                request["admission_message_id"], message["recipient_session_id"],
                message["payload_sha256"], request["wake_attempts"],
                request["target_progress_sha256"], None,
            )
            or (
                watch["repository"], int(watch["issue_number"]),
                int(watch["generation"]), int(watch["admission_message_id"] or 0),
                watch["admission_payload_sha256"], watch["lease_manifest_sha256"],
                watch["accountable_session_id"], watch["claim_attempt_id"],
            ) != (
                request["repository"], request["issue_number"], request["generation"],
                request["admission_message_id"], message["payload_sha256"],
                request["lease_manifest_sha256"], expected_watch_owner, None,
            )
            or any(
                type(capacity.get(key)) is not int
                or capacity[key] != int(item[key]) for key in unit_keys
            )
            or (
                candidate["repository"], int(candidate["issue_number"]),
                int(candidate["generation"]), candidate["state"],
                candidate["source_payload_sha256"],
                int(candidate["readiness_campaign_id"] or -1),
            ) != (
                request["repository"], request["issue_number"],
                request["generation"], "READY",
                request["source_payload_sha256"], int(finalization["campaign_id"]),
            )
        ):
            raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_FENCE_MISMATCH")
        _recovery_sources(connection, request, legacy=legacy)
        recovery_fence: dict[str, Any] = {
            "request": request,
            "ready_candidate_id": int(candidate["id"]),
            "ready_finalization_id": int(finalization["id"]),
            "ready_finalization_sha256": finalization["finalization_sha256"],
        }
        if compatibility_descriptor_sha256 is not None:
            recovery_fence["compatibility_descriptor_sha256"] = (
                compatibility_descriptor_sha256
            )
        recovery_sha256 = digest_json(recovery_fence)
        next_generation = request["generation"] + 1
        next_item_version = request["retained_item_version"] + 1
        refill_details = {
            "prior_allocation_class": "RETAINED",
            "allocation_class": "NONE",
            "prior_generation": request["generation"],
            "recovery_sha256": recovery_sha256,
        }
        refill_payload = {
            "trigger_kind": UNCLAIMED_ADMISSION_REFILL_TRIGGER,
            "repository": request["repository"],
            "issue_number": request["issue_number"],
            "release_item_version": next_item_version,
            "release_source_sha256": request["current_source_payload_sha256"],
            "status": "PREPARED",
            "generation": next_generation,
            **refill_details,
        }
        refill_sha256 = digest_json(refill_payload)
        refill_key = (
            f"portfolio-dirty:{UNCLAIMED_ADMISSION_REFILL_TRIGGER}:"
            f"{request['repository']}:{refill_sha256}"
        )
        refill = connection.execute(
            "SELECT * FROM portfolio_dirty_events WHERE event_key=?", (refill_key,)
        ).fetchone()
        replay = refill is not None
        if not replay:
            current_source = connection.execute(
                "SELECT payload_sha256 FROM github_current WHERE repository=? "
                "AND object_kind='issue' AND object_number=?",
                (request["repository"], request["issue_number"]),
            ).fetchone()
            if (
                current_source is None
                or current_source["payload_sha256"]
                != request["current_source_payload_sha256"]
            ):
                raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_SOURCE_DRIFT")
        if legacy:
            if compatibility_evidence is None:
                raise PullBufferError("LEGACY_RECOVERY_DESCRIPTOR_INVALID")
            _legacy_recovery_fence(
                connection,
                rows,
                request,
                compatibility_evidence,
                replay=replay,
            )
        elif cutover_held:
            if compatibility_evidence is None:
                raise PullBufferError("CUTOVER_HELD_RECOVERY_DESCRIPTOR_INVALID")
            _cutover_held_recovery_fence(
                connection,
                rows,
                request,
                compatibility_evidence,
                replay=replay,
            )
        elif (
            message["recipient_session_id"] != request["accountable_session_id"]
            or message["state"] != "HOLD"
            or message["last_error"] != UNCLAIMED_ADMISSION_RETRY_REASON
            or wake["state"] != "HOLD"
            or wake["last_error"] != UNCLAIMED_ADMISSION_RETRY_REASON
            or watch["state"] != "HOLD"
            or watch["last_error"] != UNCLAIMED_ADMISSION_RETRY_REASON
        ):
            raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_FENCE_MISMATCH")
        terminal_error = _recovery_terminal_error(connection, request)
        if terminal_error is not None:
            raise PullBufferError(terminal_error)
        notice = _validate_recovery_notice(
            store,
            request,
            compatibility_descriptor_sha256=compatibility_descriptor_sha256,
            replay=replay,
        )
        _authenticate_recovery_attempt(
            connection,
            request,
            notice,
            attempt_id=attempt_id,
            executor_token=executor_token,
        )
        notice_id = int(notice["id"])
        result = {
            "schema": UNCLAIMED_ADMISSION_RECOVERY_SCHEMA,
            "state": "RECOVERED",
            "recovery_sha256": recovery_sha256,
            "prior_generation": request["generation"],
            "next_generation": next_generation,
            "prior_item_version": request["retained_item_version"],
            "next_item_version": next_item_version,
            "planner_message_id": notice_id,
            "ready_candidate_id": int(candidate["id"]),
        }
        if replay:
            result["refill_event_id"] = int(refill["id"])
            retirement = connection.execute(
                "SELECT * FROM portfolio_pull_buffer_retirements WHERE candidate_id=?",
                (candidate["id"],),
            ).fetchone()
            readiness_payload = {
                "recovery_sha256": recovery_sha256,
                "prior_generation": request["generation"],
                "next_generation": next_generation,
                "ready_candidate_id": int(candidate["id"]),
                "planner_message_id": notice_id,
                "refill_event_id": int(refill["id"]),
            }
            readiness_event_count = connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_events "
                "WHERE campaign_id=? "
                "AND event_type='READINESS_UNCLAIMED_ADMISSION_REBASELINED' "
                "AND payload_sha256=? AND payload_json=?",
                (
                    finalization["campaign_id"],
                    digest_json(readiness_payload),
                    canonical_json(readiness_payload),
                ),
            ).fetchone()[0]
            recovery_event_count = connection.execute(
                "SELECT COUNT(*) FROM coordination_events "
                "WHERE event_type='UNCLAIMED_ADMISSION_RECOVERED' "
                "AND entity_key=? AND payload_sha256=?",
                (
                    f"{request['repository']}:issue:{request['issue_number']}:"
                    f"generation:{next_generation}",
                    digest_json(result),
                ),
            ).fetchone()[0]
            if (
                refill["event_sha256"] != refill_sha256
                or refill["payload_json"] != canonical_json(refill_payload)
                or refill["state"] not in {"PENDING", "RETRY", "COMPLETE", "HOLD"}
                or retirement is None
                or retirement["repository"] != request["repository"]
                or int(retirement["issue_number"]) != request["issue_number"]
                or retirement["reasons_json"] != canonical_json(["ADMITTED"])
                or retirement["reason_sha256"] != digest_json(["ADMITTED"])
                or (
                    (pointer := connection.execute(
                        "SELECT candidate_id FROM portfolio_pull_buffer_current "
                        "WHERE repository=? AND issue_number=?",
                        (request["repository"], request["issue_number"]),
                    ).fetchone())
                    is not None
                    and int(pointer["candidate_id"]) == int(candidate["id"])
                )
                or int(item["generation"]) < next_generation
                or int(item["version"]) < next_item_version
                or notice["state"] != "COMPLETE"
                or readiness_event_count != 1
                or recovery_event_count != 1
            ):
                raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_REPLAY_DRIFT")
            return result

        if (
            item["status"] != "HOLD"
            or item["allocation_class"] != "RETAINED"
            or int(item["generation"]) != request["generation"]
            or int(item["version"]) != request["retained_item_version"]
            or item["accountable_session_id"] != request["accountable_session_id"]
            or item["lease_manifest_sha256"] != request["lease_manifest_sha256"]
            or item["source_payload_sha256"] != request["source_payload_sha256"]
            or readiness["state"] != "FINALIZED"
            or ready_attestation_error(connection, dict(candidate)) is not None
            or notice["state"] != "CLAIMED"
        ):
            raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_FENCE_MISMATCH")
        retirement = connection.execute(
            "SELECT * FROM portfolio_pull_buffer_retirements WHERE candidate_id=?",
            (candidate["id"],),
        ).fetchone()
        pointer = connection.execute(
            "SELECT candidate_id FROM portfolio_pull_buffer_current "
            "WHERE repository=? AND issue_number=?",
            (request["repository"], request["issue_number"]),
        ).fetchone()
        if retirement is None and pointer is not None and int(pointer[0]) == int(candidate["id"]):
            _retire_pointer(
                connection,
                repository=request["repository"],
                issue_number=request["issue_number"],
                candidate_id=int(candidate["id"]),
                reasons=["ADMITTED"],
                now=now,
            )
            store._terminal_failpoint(failpoint, "recovery.after_retirement")
            retirement = connection.execute(
                "SELECT * FROM portfolio_pull_buffer_retirements WHERE candidate_id=?",
                (candidate["id"],),
            ).fetchone()
            pointer = None
        if (
            retirement is None
            or retirement["repository"] != request["repository"]
            or int(retirement["issue_number"]) != request["issue_number"]
            or retirement["reasons_json"] != canonical_json(["ADMITTED"])
            or retirement["reason_sha256"] != digest_json(["ADMITTED"])
            or pointer is not None
        ):
            raise PullBufferError("UNCLAIMED_ADMISSION_RETIREMENT_DRIFT")
        changed = connection.execute(
            """
            UPDATE coordination_items
            SET status='PREPARED', allocation_class='NONE', generation=?,
                accountable_session_id=NULL, lease_manifest_sha256=NULL,
                source_payload_sha256=?, version=version+1, updated_at=?
            WHERE repository=? AND issue_number=? AND status='HOLD'
              AND allocation_class='RETAINED' AND generation=? AND version=?
              AND accountable_session_id=? AND lease_manifest_sha256=?
              AND source_payload_sha256=?
            """,
            (
                next_generation,
                request["current_source_payload_sha256"],
                now,
                request["repository"],
                request["issue_number"],
                request["generation"],
                request["retained_item_version"],
                request["accountable_session_id"],
                request["lease_manifest_sha256"],
                request["source_payload_sha256"],
            ),
        ).rowcount
        if changed != 1:
            raise PullBufferError("UNCLAIMED_ADMISSION_RECOVERY_FENCE_MISMATCH")
        store._terminal_failpoint(failpoint, "recovery.after_item")
        changed = connection.execute(
            """
            UPDATE portfolio_readiness_current
            SET state='STALE', version=version+1, updated_at=?, last_error=?
            WHERE repository=? AND issue_number=? AND campaign_id=?
              AND state='FINALIZED' AND version=?
              AND finalized_candidate_id=? AND finalized_event_id=?
            """,
            (
                now,
                f"UNCLAIMED_ADMISSION_RECOVERY:{recovery_sha256}",
                request["repository"],
                request["issue_number"],
                readiness["campaign_id"],
                readiness["version"],
                candidate["id"],
                finalization["dirty_event_id"],
            ),
        ).rowcount
        if changed != 1:
            raise PullBufferError("UNCLAIMED_ADMISSION_READINESS_DRIFT")
        store._terminal_failpoint(failpoint, "recovery.after_readiness")
        try:
            refill_id = enqueue_convergence_dirty_event(
                connection,
                repository=request["repository"],
                trigger_kind=UNCLAIMED_ADMISSION_REFILL_TRIGGER,
                issue_number=request["issue_number"],
                item_version=next_item_version,
                source_sha256=request["current_source_payload_sha256"],
                status="PREPARED",
                generation=next_generation,
                now=now,
                details=refill_details,
                require_pending=True,
            )
        except PortfolioGraphError as exc:
            raise PullBufferError(str(exc)) from exc
        if refill_id is None:
            raise PullBufferError("PORTFOLIO_DIRTY_EVENT_SCHEMA_MISSING")
        store._terminal_failpoint(failpoint, "recovery.after_refill_event")
        store._complete_message_in_transaction(
            notice_id, request["planner_session_id"], now
        )
        store._terminal_failpoint(failpoint, "recovery.after_notice_complete")
        result["refill_event_id"] = int(refill_id)
        readiness_payload = {
            "recovery_sha256": recovery_sha256,
            "prior_generation": request["generation"],
            "next_generation": next_generation,
            "ready_candidate_id": int(candidate["id"]),
            "planner_message_id": notice_id,
            "refill_event_id": int(refill_id),
        }
        from kanban_readiness import _event as readiness_event

        readiness_event(
            connection,
            int(readiness["campaign_id"]),
            "READINESS_UNCLAIMED_ADMISSION_REBASELINED",
            readiness_payload,
            now,
        )
        store._terminal_failpoint(failpoint, "recovery.after_readiness_event")
        store._event(
            "UNCLAIMED_ADMISSION_RECOVERED",
            f"{request['repository']}:issue:{request['issue_number']}:"
            f"generation:{next_generation}",
            result,
            now,
        )
        store._terminal_failpoint(failpoint, "recovery.after_audit_event")
        return result


def audit_pull_buffer(
    connection: sqlite3.Connection,
    repository: str,
    *,
    record: bool,
    now: str,
    database: Path | None = None,
    artifact_observations: dict[int, dict[str, Any]] | None = None,
    store: CoordinationStore | None = None,
    recovery_failpoint: Callable[[str], None] | None = None,
    _transaction: bool = True,
    _ensure_schema: bool = True,
) -> dict[str, Any]:
    if store is not None and store.connection is not connection:
        raise PullBufferError("PULL_BUFFER_RECOVERY_STORE_MISMATCH")
    if _ensure_schema:
        if record:
            ensure_pull_buffer_schema(connection)
        else:
            require_pull_buffer_schema(connection)
    database = database or _database_path(connection)
    owns_observations = artifact_observations is None
    if owns_observations:
        artifact_observations = load_candidate_packets(
            connection, repository, database=database, keep_descriptors=True
        )
    write_transaction = _transaction and record
    if write_transaction:
        connection.execute("BEGIN IMMEDIATE")
    try:
        current = connection.execute(
            "SELECT version, observed_main_sha, health FROM portfolio_graph_current WHERE repository=?",
            (repository,),
        ).fetchone()
        policy = connection.execute(
            """
            SELECT p.* FROM coordination_capacity_current c
            JOIN coordination_capacity_policies p
              ON p.repository=c.repository AND p.version=c.version
            WHERE c.repository=?
            """,
            (repository,),
        ).fetchone()
        if current is None or policy is None:
            raise PullBufferError("PULL_BUFFER_BINDING_MISSING")
        graph_version = int(current["version"])
        structurally_ready: dict[str, bool] = {}
        if current["health"] == "CURRENT":
            try:
                structurally_ready = {
                    str(node["node_key"]): bool(node["structurally_ready"])
                    for node in evaluate_graph(
                        connection,
                        repository,
                        current_main=str(current["observed_main_sha"]),
                        _ensure_schema=False,
                    )["nodes"]
                }
            except PortfolioGraphError:
                structurally_ready = {}
        potential_lanes = connection.execute(
            """
            SELECT COUNT(DISTINCT n.lane_key)
            FROM portfolio_graph_nodes n
            JOIN coordination_items i
              ON i.repository=n.repository AND i.issue_number=n.issue_number
            WHERE n.repository=? AND n.graph_version=? AND n.dispatchable=1
              AND i.allocation_class='NONE' AND i.status<>'DONE'
            """,
            (repository, graph_version),
        ).fetchone()[0]
        target_depth = min(2, int(potential_lanes))
        rows = connection.execute(
            """
            SELECT c.*, n.node_key, n.priority_rank, n.ready_at, n.lane_order,
                   i.status AS item_status, i.allocation_class,
                   i.generation AS current_generation, i.version AS current_item_version,
                   i.source_payload_sha256 AS current_source_sha256,
                   CASE WHEN source.payload_sha256=i.source_payload_sha256 THEN 1 ELSE 0 END
                       AS source_current,
                   a.state AS artifact_state,
                   a.artifact_key AS registry_artifact_key,
                   a.repository AS registry_repository,
                   a.issue_number AS registry_issue_number,
                   a.generation AS registry_generation,
                   a.relative_path AS registry_relative_path,
                   a.content_sha256 AS registry_content_sha256,
                   a.size_bytes AS registry_size_bytes,
                   a.device_id AS registry_device_id,
                   a.inode AS registry_inode,
                   a.retention_class AS registry_retention_class,
                   a.registered_at AS registry_registered_at,
                   a.content_sha256 AS current_artifact_sha256,
                   a.size_bytes AS artifact_size_bytes,
                   a.device_id AS artifact_device_id,
                   a.inode AS artifact_inode
            FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates c ON c.id=pointer.candidate_id
            LEFT JOIN portfolio_graph_nodes n
              ON n.repository=c.repository AND n.graph_version=? AND n.issue_number=c.issue_number
            LEFT JOIN coordination_items i
              ON i.repository=c.repository AND i.issue_number=c.issue_number
            LEFT JOIN github_current source
              ON source.repository=i.repository
             AND source.object_kind='issue'
             AND source.object_number=i.issue_number
            LEFT JOIN coordination_artifacts a
              ON a.relative_path=c.artifact_relative_path
            WHERE pointer.repository=?
            ORDER BY n.priority_rank, n.lane_order, n.ready_at, c.issue_number
            """,
            (graph_version, repository),
        ).fetchall()
        valid: list[dict[str, Any]] = []
        invalid: list[dict[str, Any]] = []
        for row in rows:
            reasons: list[str] = []
            if current["health"] != "CURRENT":
                reasons.append("GRAPH_STALE")
            if row["accepted_main_sha"] != current["observed_main_sha"]:
                reasons.append("MAIN_DRIFT")
            if int(row["graph_version"]) != graph_version or row["priority_rank"] is None:
                reasons.append("GRAPH_DRIFT")
            if (
                current["health"] == "CURRENT"
                and row["node_key"] is not None
                and not structurally_ready.get(str(row["node_key"]), False)
            ):
                reasons.append("DEPENDENCY_DRIFT")
            if int(row["capacity_policy_version"]) != int(policy["version"]):
                reasons.append("CAPACITY_POLICY_DRIFT")
            if row["current_generation"] is None or int(row["generation"]) != int(row["current_generation"]):
                reasons.append("GENERATION_DRIFT")
            if row["current_item_version"] is None or int(row["item_version"]) != int(row["current_item_version"]):
                reasons.append("ITEM_VERSION_DRIFT")
            if row["current_source_sha256"] != row["source_payload_sha256"] or row["source_current"] != 1:
                reasons.append("SOURCE_DRIFT")
            if row["allocation_class"] != "NONE" or row["item_status"] not in ZERO_WIP_STATUSES:
                reasons.append("NOT_ZERO_WIP_PREP")
            observation = artifact_observations.get(int(row["id"]))
            registered_artifact = (
                observation.get("registered_artifact")
                if isinstance(observation, dict)
                else None
            )
            current_registry_identity = artifact_registry_identity(
                row, prefix="registry_"
            )
            if (
                row["artifact_state"] != "REGISTERED"
                or row["current_artifact_sha256"] != row["artifact_content_sha256"]
                or observation is None
                or observation.get("error") is not None
                or not artifact_registry_identity_matches(
                    registered_artifact, current_registry_identity
                )
                or current_registry_identity["repository"] != row["repository"]
                or int(current_registry_identity["issue_number"])
                != int(row["issue_number"])
                or int(current_registry_identity["generation"])
                != int(row["generation"])
                or current_registry_identity["relative_path"]
                != row["artifact_relative_path"]
                or observation.get("content_sha256") != row["artifact_content_sha256"]
                or int(observation.get("size_bytes", -1)) != int(row["artifact_size_bytes"])
                or int(observation.get("device_id", -1)) != int(row["artifact_device_id"])
                or int(observation.get("inode", -1)) != int(row["artifact_inode"])
                or not _descriptor_is_current(observation)
            ):
                reasons.append("ARTIFACT_DRIFT")
            packet = (
                observation.get("packet")
                if isinstance(observation, dict)
                else None
            )
            binding_error = None
            attestation_error = None
            if row["state"] == "READY":
                binding_error = admission_binding_error(
                    packet.get("admission_transaction")
                    if isinstance(packet, dict)
                    else None,
                    candidate=dict(row),
                    observed_main_sha=str(current["observed_main_sha"]),
                    observation=observation,
                    connection=connection,
                )
                attestation_error = ready_attestation_error(
                    connection, dict(row)
                )
                if attestation_error is not None:
                    reasons.append(attestation_error)
                if binding_error is not None:
                    reasons.append(binding_error)
            observation_authentic = _observation_snapshot_is_authentic(
                connection, observation
            )
            candidate = {
                "candidate_id": int(row["id"]),
                "node_key": row["node_key"],
                "issue_number": int(row["issue_number"]),
                "lane_key": row["lane_key"],
                "state": row["state"],
                "item_status": row["item_status"],
                "verticality": row["verticality"],
                "candidate_sha256": row["candidate_sha256"],
                "admission_binding_error": binding_error,
                "admission_prepared": row["state"] == "READY" and binding_error is None,
            }
            if reasons:
                normalized = sorted(set(reasons))
                recovery = None
                if record:
                    recovery_forbidden = {
                        "GENERATION_DRIFT",
                        "ITEM_VERSION_DRIFT",
                        "NOT_ZERO_WIP_PREP",
                        "READINESS_ATTESTATION_MISSING",
                        "READINESS_ATTESTATION_INVALID",
                        "READINESS_ATTESTATION_DRIFT",
                    }
                    if (
                        row["state"] == "READY"
                        and row["item_status"] == "READY"
                        and row["allocation_class"] == "NONE"
                        and attestation_error is None
                        and observation_authentic
                        and not recovery_forbidden.intersection(normalized)
                        and not any(
                            reason.startswith("HARNESS_STANDING_AUTHORITY_")
                            for reason in normalized
                        )
                    ):
                        recovery = _recover_finalized_ready_candidate(
                            store,
                            row,
                            normalized,
                            now=now,
                            failpoint=recovery_failpoint,
                        )
                    else:
                        _retire_pointer(
                            connection,
                            repository=repository,
                            issue_number=int(row["issue_number"]),
                            candidate_id=int(row["id"]),
                            reasons=normalized,
                            now=now,
                        )
                invalid.append(
                    {
                        **candidate,
                        "reasons": normalized,
                        **({} if recovery is None else {"recovery": recovery}),
                    }
                )
            else:
                valid.append(candidate)
        selected: list[dict[str, Any]] = []
        selected_lanes: set[str] = set()
        for candidate in valid:
            if candidate["lane_key"] in selected_lanes:
                continue
            selected.append(candidate)
            selected_lanes.add(candidate["lane_key"])
            if len(selected) == target_depth:
                break
        deficit_reasons: list[str] = []
        if len(selected) < target_depth:
            deficit_reasons.append(f"PULL_BUFFER_DEPTH_{len(selected)}_OF_{target_depth}")
        prepared_or_queued_depth = sum(
            candidate["item_status"] in {"PREPARED", "QUEUED"}
            for candidate in selected
        )
        executable = [
            candidate
            for candidate in selected
            if candidate["state"] == "READY" and candidate["item_status"] == "READY"
        ]
        executable_ready_depth = len(executable)
        if target_depth and executable_ready_depth == 0:
            deficit_reasons.append("READY_DEPTH_ZERO")
        scheduler_selected: set[str] = set()
        if current["health"] == "CURRENT":
            try:
                scheduler_selected = set(
                    _schedule_decision(
                        connection,
                        repository,
                        current_main=str(current["observed_main_sha"]),
                        record=False,
                        now=now,
                    )["selected"]
                )
            except PortfolioGraphError:
                scheduler_selected = set()
        dispatchable_now_depth = sum(
            candidate["node_key"] in scheduler_selected
            and candidate["admission_binding_error"] is None
            for candidate in executable
        )
        deficit_reasons.extend(
            f"{candidate['admission_binding_error']}:issue:{candidate['issue_number']}"
            for candidate in executable
            if candidate["admission_binding_error"] is not None
        )
        state = "HEALTHY" if not deficit_reasons else "PULL_BUFFER_DEFICIT"
        payload = {
            "repository": repository,
            "graph_version": graph_version,
            "capacity_policy_version": int(policy["version"]),
            "accepted_main_sha": current["observed_main_sha"],
            "target_depth": target_depth,
            "healthy_depth": len(selected),
            "reviewed_candidate_depth": len(selected),
            "prepared_or_queued_depth": prepared_or_queued_depth,
            "executable_ready_depth": executable_ready_depth,
            "dispatchable_now_depth": dispatchable_now_depth,
            "state": state,
            "selected": selected,
            "invalid": invalid,
            "deficit_reasons": deficit_reasons,
        }
        audit_sha = digest_json(payload)
        if record:
            connection.execute(
                """
                INSERT OR IGNORE INTO portfolio_pull_buffer_audits(
                    repository, graph_version, capacity_policy_version,
                    accepted_main_sha, target_depth, healthy_depth, state,
                    audit_sha256, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository, graph_version, int(policy["version"]),
                    current["observed_main_sha"], target_depth, len(selected), state,
                    audit_sha, canonical_json(payload), now,
                ),
            )
        if write_transaction:
            connection.execute("COMMIT")
    except Exception:
        if write_transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        if owns_observations:
            close_candidate_observations(artifact_observations)
    return {**payload, "audit_sha256": audit_sha}


def show_pull_buffer(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    require_pull_buffer_schema(connection)
    candidates = [dict(row) for row in connection.execute(
        """
        SELECT c.* FROM portfolio_pull_buffer_current pointer
        JOIN portfolio_pull_buffer_candidates c ON c.id=pointer.candidate_id
        WHERE pointer.repository=? ORDER BY c.issue_number
        """,
        (repository,),
    )]
    audit = connection.execute(
        "SELECT payload_json, audit_sha256, created_at FROM portfolio_pull_buffer_audits WHERE repository=? ORDER BY id DESC LIMIT 1",
        (repository,),
    ).fetchone()
    return {
        "repository": repository,
        "candidates": candidates,
        "latest_audit": None if audit is None else {
            **json.loads(audit["payload_json"]),
            "audit_sha256": audit["audit_sha256"],
            "created_at": audit["created_at"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    register = subparsers.add_parser("register")
    register.add_argument("--packet", type=Path, required=True)
    prepare = subparsers.add_parser("prepare-zero-wip")
    prepare.add_argument("--request", type=Path, required=True)
    finalize = subparsers.add_parser("finalize-ready")
    finalize.add_argument("--packet", type=Path, required=True)
    recover = subparsers.add_parser("recover-unclaimed-admission")
    recover.add_argument("--transaction-file", type=Path, required=True)
    recover.add_argument("--compatibility-descriptor-file", type=Path)
    subparsers.add_parser("initialize")
    audit = subparsers.add_parser("audit")
    audit.add_argument("--repository", required=True)
    audit.add_argument("--record", action="store_true")
    show = subparsers.add_parser("show")
    show.add_argument("--repository", required=True)
    readiness_discover = subparsers.add_parser("readiness-discover")
    readiness_discover.add_argument("--repository", required=True)
    readiness_discover.add_argument("--limit", type=int, default=2)
    readiness_register = subparsers.add_parser("readiness-register")
    readiness_register.add_argument("--plan", type=Path, required=True)
    readiness_dispatch = subparsers.add_parser("readiness-dispatch")
    readiness_dispatch.add_argument("--repository", required=True)
    readiness_dispatch.add_argument("--max-parallel", type=int, required=True)
    readiness_attach = subparsers.add_parser("readiness-attach")
    readiness_attach.add_argument("--repository", required=True)
    readiness_attach.add_argument("--issue", type=int, required=True)
    readiness_attach.add_argument("--message-id", type=int, required=True)
    readiness_attach.add_argument("--attempt-id", required=True)
    readiness_stage = subparsers.add_parser("readiness-stage-receipt")
    readiness_stage.add_argument("--receipt", type=Path, required=True)
    readiness_stage.add_argument("--message-id", type=int, required=True)
    readiness_stage.add_argument("--attempt-id", required=True)
    readiness_reopen = subparsers.add_parser("readiness-reopen-terminal-hold")
    readiness_reopen.add_argument("--repository", required=True)
    readiness_reopen.add_argument("--issue", type=int, required=True)
    readiness_reopen.add_argument("--expected-campaign-id", type=int, required=True)
    readiness_reopen.add_argument("--expected-current-version", type=int, required=True)
    readiness_reopen.add_argument(
        "--expected-terminal-receipt-id", type=int, required=True
    )
    readiness_reopen.add_argument(
        "--expected-terminal-receipt-sha256", required=True
    )
    readiness_decision = subparsers.add_parser("readiness-apply-decision")
    readiness_decision.add_argument("--message-id", type=int, required=True)
    readiness_decision.add_argument("--planner-session-id", required=True)
    readiness_decision.add_argument("--source", type=Path, required=True)
    readiness_context = subparsers.add_parser("readiness-resolution-context")
    readiness_context.add_argument("--message-id", type=int, required=True)
    readiness_context.add_argument("--planner-session-id", required=True)
    readiness_resolution = subparsers.add_parser("readiness-apply-resolution")
    readiness_resolution.add_argument("--message-id", type=int, required=True)
    readiness_resolution.add_argument("--planner-session-id", required=True)
    readiness_resolution.add_argument(
        "--expected-context-sha256", required=True
    )
    readiness_action = subparsers.add_parser(
        "readiness-execute-resolution-action"
    )
    readiness_action.add_argument("--message-id", type=int, required=True)
    readiness_action.add_argument("--planner-session-id", required=True)
    readiness_action.add_argument("--expected-context-sha256", required=True)
    readiness_action.add_argument("--action-sha256", required=True)
    readiness_action.add_argument("--expected-digest", required=True)
    readiness_action.add_argument("--action-input", type=Path, required=True)
    readiness_evaluate = subparsers.add_parser("readiness-evaluate")
    readiness_evaluate.add_argument("--repository", required=True)
    readiness_evaluate.add_argument("--issue", type=int, required=True)
    readiness_evaluate.add_argument("--record", action="store_true")
    readiness_show = subparsers.add_parser("readiness-show")
    readiness_show.add_argument("--repository", required=True)
    args = parser.parse_args()
    read_only = (
        args.command in {
            "show", "readiness-discover", "readiness-show",
        }
        or (args.command == "audit" and not args.record)
        or (args.command == "readiness-evaluate" and not args.record)
    )
    audit_store: CoordinationStore | None = None
    if args.command == "audit" and args.record:
        audit_store = CoordinationStore(DEFAULT_DATABASE)
        connection = audit_store.connection
    elif read_only:
        connection = open_owner_database_readonly(DEFAULT_DATABASE)
    else:
        prepare_owner_database(DEFAULT_DATABASE)
        connection = sqlite3.connect(DEFAULT_DATABASE)
        connection.row_factory = sqlite3.Row
    try:
        if args.command.startswith("readiness-"):
            from kanban_readiness import (
                attach as attach_readiness,
                apply_readiness_decision,
                apply_readiness_resolution,
                claim_readiness_resolution_context,
                discover as discover_readiness,
                dispatch as dispatch_readiness,
                evaluate as evaluate_readiness,
                execute_readiness_resolution_action,
                read_json as read_readiness_json,
                register as register_readiness,
                reopen_terminal_hold,
                show as show_readiness,
                stage_receipt as stage_readiness_receipt,
            )

            if args.command == "readiness-discover":
                result = discover_readiness(connection, args.repository, limit=args.limit)
            elif args.command == "readiness-register":
                result = register_readiness(
                    connection, read_readiness_json(args.plan), now=utc_now()
                )
            elif args.command == "readiness-dispatch":
                dispatch_store = CoordinationStore(DEFAULT_DATABASE)
                try:
                    result = dispatch_readiness(
                        dispatch_store,
                        args.repository,
                        max_parallel=args.max_parallel,
                        now=utc_now(),
                    )
                finally:
                    dispatch_store.close()
            elif args.command == "readiness-attach":
                result = attach_readiness(
                    connection, args.repository, args.issue, args.message_id,
                    args.attempt_id, now=utc_now(),
                )
            elif args.command == "readiness-stage-receipt":
                result = stage_readiness_receipt(
                    connection,
                    DEFAULT_DATABASE,
                    args.receipt,
                    message_id=args.message_id,
                    attempt_id=args.attempt_id,
                    now=utc_now(),
                )
            elif args.command == "readiness-reopen-terminal-hold":
                result = reopen_terminal_hold(
                    connection,
                    args.repository,
                    args.issue,
                    expected_campaign_id=args.expected_campaign_id,
                    expected_current_version=args.expected_current_version,
                    expected_terminal_receipt_id=(
                        args.expected_terminal_receipt_id
                    ),
                    expected_terminal_receipt_sha256=(
                        args.expected_terminal_receipt_sha256
                    ),
                    now=utc_now(),
                )
            elif args.command == "readiness-apply-decision":
                decision_store = CoordinationStore(DEFAULT_DATABASE)
                try:
                    refreshed_source = read_readiness_json(args.source)
                    result = apply_readiness_decision(
                        decision_store,
                        message_id=args.message_id,
                        planner_session_id=args.planner_session_id,
                        refreshed_payload=refreshed_source,
                        refreshed_payload_sha256=digest_json(refreshed_source),
                        now=utc_now(),
                    )
                finally:
                    decision_store.close()
            elif args.command == "readiness-resolution-context":
                resolution_store = CoordinationStore(DEFAULT_DATABASE)
                try:
                    result = claim_readiness_resolution_context(
                        resolution_store,
                        message_id=args.message_id,
                        planner_session_id=args.planner_session_id,
                        now=utc_now(),
                    )
                finally:
                    resolution_store.close()
            elif args.command == "readiness-apply-resolution":
                resolution_store = CoordinationStore(DEFAULT_DATABASE)
                try:
                    result = apply_readiness_resolution(
                        resolution_store,
                        message_id=args.message_id,
                        planner_session_id=args.planner_session_id,
                        expected_context_sha256=args.expected_context_sha256,
                        now=utc_now(),
                    )
                finally:
                    resolution_store.close()
            elif args.command == "readiness-execute-resolution-action":
                resolution_store = CoordinationStore(DEFAULT_DATABASE)
                try:
                    result = execute_readiness_resolution_action(
                        resolution_store,
                        message_id=args.message_id,
                        planner_session_id=args.planner_session_id,
                        expected_context_sha256=args.expected_context_sha256,
                        action_sha256=args.action_sha256,
                        expected_digest=args.expected_digest,
                        action_input=read_readiness_json(args.action_input),
                        now=utc_now(),
                    )
                finally:
                    resolution_store.close()
            elif args.command == "readiness-evaluate":
                result = evaluate_readiness(
                    connection, args.repository, args.issue,
                    now=utc_now(), record_state=args.record,
                )
            else:
                result = show_readiness(connection, args.repository)
        elif args.command == "prepare-zero-wip":
            descriptor, _relative = _open_packet(DEFAULT_DATABASE, args.request)
            try:
                request = json.loads(
                    _read_descriptor(descriptor).decode("utf-8"),
                    object_pairs_hook=_strict_object,
                )
            finally:
                os.close(descriptor)
            preparation_store = CoordinationStore(DEFAULT_DATABASE)
            try:
                result = prepare_zero_wip_candidate(
                    preparation_store, request, now=utc_now()
                )
            finally:
                preparation_store.close()
        elif args.command == "register":
            result = register_candidate(connection, DEFAULT_DATABASE, args.packet, now=utc_now())
        elif args.command == "finalize-ready":
            finalize_store = CoordinationStore(DEFAULT_DATABASE)
            try:
                result = finalize_ready(
                    finalize_store, args.packet, now=utc_now()
                )
            finally:
                finalize_store.close()
        elif args.command == "recover-unclaimed-admission":
            descriptor, _relative = _open_packet(
                DEFAULT_DATABASE, args.transaction_file
            )
            try:
                request = json.loads(
                    _read_descriptor(descriptor).decode("utf-8"),
                    object_pairs_hook=_strict_object,
                )
            finally:
                os.close(descriptor)
            compatibility_descriptor = None
            if args.compatibility_descriptor_file is not None:
                compatibility_file, _relative = _open_packet(
                    DEFAULT_DATABASE, args.compatibility_descriptor_file
                )
                try:
                    compatibility_descriptor = json.loads(
                        _read_descriptor(compatibility_file).decode("utf-8"),
                        object_pairs_hook=_strict_object,
                    )
                finally:
                    os.close(compatibility_file)
            recovery_store = CoordinationStore(DEFAULT_DATABASE)
            try:
                result = recover_unclaimed_admission(
                    recovery_store,
                    request,
                    now=utc_now(),
                    attempt_id=os.environ.get("TWINFINITY_EXECUTOR_ATTEMPT_ID"),
                    executor_token=os.environ.get("TWINFINITY_EXECUTOR_TOKEN"),
                    compatibility_descriptor=compatibility_descriptor,
                )
            finally:
                recovery_store.close()
        elif args.command == "initialize":
            from kanban_readiness import ensure_schema as ensure_readiness_schema

            ensure_pull_buffer_schema(connection)
            ensure_readiness_schema(connection)
            result = {"state": "INITIALIZED"}
        elif args.command == "audit":
            result = audit_pull_buffer(
                connection, args.repository, record=args.record, now=utc_now(),
                database=DEFAULT_DATABASE,
                store=audit_store,
            )
        else:
            result = show_pull_buffer(connection, args.repository)
        print(canonical_json({"phase": "COMPLETE", "result": result}))
        return 0
    except (
        CoordinationError,
        PullBufferError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        if audit_store is not None:
            audit_store.close()
        else:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
