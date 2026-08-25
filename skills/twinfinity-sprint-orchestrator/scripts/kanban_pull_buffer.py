#!/usr/bin/env python3
"""Validate and persist the rolling two-candidate Kanban pull buffer."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from coordination_store import (
    DEFAULT_DATABASE,
    CoordinationError,
    artifact_registry_identity,
    artifact_registry_identity_matches,
    canonical_json,
    parse_structured_lease_manifest,
    validate_admission_dispatch_bindings,
)
from executor_registry import (
    canonical_endpoint_id,
    configured_identity_role,
    current_endpoint,
    identity_role,
)
from owner_safe_sqlite import prepare_owner_database
from portfolio_graph import (
    PortfolioGraphError,
    _schedule_decision,
    enqueue_convergence_dirty_event,
)


SCHEMA = "twinfinity-kanban-pull-buffer/v2"
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
        COMMIT;
            """
        )
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _require_nonempty_strings(value: Any, code: str) -> None:
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise PullBufferError(code)


def _validate_packet(packet: Any) -> None:
    if not isinstance(packet, dict) or packet.get("schema") != SCHEMA:
        raise PullBufferError("PULL_BUFFER_PACKET_INVALID")
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
        if type(policy.get(key)) is not int or int(policy[key]) <= 0:
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
    if not isinstance(collisions, list) or not collisions or any(
        not isinstance(item, dict)
        or set(item) != {"other_issue", "disposition", "reason"}
        or type(item.get("other_issue")) is not int
        or item["other_issue"] <= 0
        or not str(item.get("disposition") or "").strip()
        or not str(item.get("reason") or "").strip()
        for item in collisions
    ):
        raise PullBufferError("PULL_BUFFER_COLLISION_MATRIX_MISSING")


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


def register_candidate(
    connection: sqlite3.Connection,
    database: Path,
    packet_path: Path,
    *,
    now: str,
) -> dict[str, Any]:
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
        admission_observations = _load_admission_artifacts(
            connection,
            database,
            packet.get("admission_transaction"),
        )
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
        trigger_kind = (
            "CANDIDATE_PROMOTED"
            if prior is not None
            and prior["state"] == "PREPARED_NOT_READY"
            and packet["state"] == "READY"
            else "CANDIDATE_REGISTERED"
        )
        dirty_event_id = enqueue_convergence_dirty_event(
            connection,
            repository=repository,
            trigger_kind=trigger_kind,
            issue_number=issue_number,
            item_version=int(item["version"]),
            source_sha256=item["source_payload_sha256"],
            status=str(item["status"]),
            generation=int(item["generation"]),
            now=now,
            details={
                "candidate_id": int(row["id"]),
                "candidate_sha256": candidate_sha,
                "candidate_state": packet["state"],
            },
        )
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
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
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


def load_candidate_packets(
    connection: sqlite3.Connection,
    repository: str,
    *,
    database: Path | None = None,
    keep_descriptors: bool = True,
) -> dict[int, dict[str, Any]]:
    """Read current candidate artifacts before a reconciliation write lock."""

    ensure_pull_buffer_schema(connection)
    database = database or _database_path(connection)
    rows = connection.execute(
        """
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
        FROM portfolio_pull_buffer_current pointer
        JOIN portfolio_pull_buffer_candidates c ON c.id=pointer.candidate_id
        LEFT JOIN coordination_artifacts a
          ON a.relative_path=c.artifact_relative_path
        WHERE pointer.repository=?
        ORDER BY c.id
        """,
        (repository,),
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


def audit_pull_buffer(
    connection: sqlite3.Connection,
    repository: str,
    *,
    record: bool,
    now: str,
    database: Path | None = None,
    artifact_observations: dict[int, dict[str, Any]] | None = None,
    _transaction: bool = True,
    _ensure_schema: bool = True,
) -> dict[str, Any]:
    if _ensure_schema:
        ensure_pull_buffer_schema(connection)
    database = database or _database_path(connection)
    owns_observations = artifact_observations is None
    if owns_observations:
        artifact_observations = load_candidate_packets(
            connection, repository, database=database, keep_descriptors=True
        )
    if _transaction:
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
            ORDER BY n.priority_rank, n.ready_at, n.lane_order, c.issue_number
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
                invalid.append({**candidate, "reasons": normalized})
                _retire_pointer(
                    connection,
                    repository=repository,
                    issue_number=int(row["issue_number"]),
                    candidate_id=int(row["id"]),
                    reasons=normalized,
                    now=now,
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
        if _transaction:
            connection.execute("COMMIT")
    except Exception:
        if _transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        if owns_observations:
            close_candidate_observations(artifact_observations)
    return {**payload, "audit_sha256": audit_sha}


def show_pull_buffer(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    ensure_pull_buffer_schema(connection)
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
    readiness_record = subparsers.add_parser("readiness-record")
    readiness_record.add_argument("--receipt", type=Path, required=True)
    readiness_evaluate = subparsers.add_parser("readiness-evaluate")
    readiness_evaluate.add_argument("--repository", required=True)
    readiness_evaluate.add_argument("--issue", type=int, required=True)
    readiness_evaluate.add_argument("--record", action="store_true")
    readiness_show = subparsers.add_parser("readiness-show")
    readiness_show.add_argument("--repository", required=True)
    args = parser.parse_args()
    prepare_owner_database(DEFAULT_DATABASE)
    connection = sqlite3.connect(DEFAULT_DATABASE)
    connection.row_factory = sqlite3.Row
    try:
        if args.command.startswith("readiness-"):
            from kanban_readiness import (
                attach as attach_readiness,
                discover as discover_readiness,
                dispatch as dispatch_readiness,
                evaluate as evaluate_readiness,
                read_json as read_readiness_json,
                record as record_readiness,
                register as register_readiness,
                show as show_readiness,
            )

            if args.command == "readiness-discover":
                result = discover_readiness(connection, args.repository, limit=args.limit)
            elif args.command == "readiness-register":
                result = register_readiness(
                    connection, read_readiness_json(args.plan), now=utc_now()
                )
            elif args.command == "readiness-dispatch":
                from coordination_store import CoordinationStore

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
            elif args.command == "readiness-record":
                from coordination_store import CoordinationStore

                record_store = CoordinationStore(DEFAULT_DATABASE)
                try:
                    result = record_readiness(
                        record_store, read_readiness_json(args.receipt), now=utc_now()
                    )
                finally:
                    record_store.close()
            elif args.command == "readiness-evaluate":
                result = evaluate_readiness(
                    connection, args.repository, args.issue,
                    now=utc_now(), record_state=args.record,
                )
            else:
                result = show_readiness(connection, args.repository)
        elif args.command == "register":
            result = register_candidate(connection, DEFAULT_DATABASE, args.packet, now=utc_now())
        elif args.command == "audit":
            result = audit_pull_buffer(
                connection, args.repository, record=args.record, now=utc_now(),
                database=DEFAULT_DATABASE,
            )
        else:
            result = show_pull_buffer(connection, args.repository)
        print(canonical_json({"phase": "COMPLETE", "result": result}))
        return 0
    except (PullBufferError, OSError, sqlite3.Error, ValueError) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
