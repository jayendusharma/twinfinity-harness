#!/usr/bin/env python3
"""Trusted owner-side broker for kernel-isolated readiness executors."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import sqlite3
import stat
import subprocess
import time
from typing import Any, Callable

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
)
from executor_registry import (
    BROKERED_READINESS_PROTOCOL,
    EndpointConfig,
    RegistryError,
    SHA256,
    SYSTEMD_INVOCATION_ID,
    SystemdUnitEvidence,
    _insert_attempt_event,
    current_endpoint,
    probe_systemd_unit,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
    utc_now,
)
from kanban_readiness import (
    RECEIPT_JSON_SCHEMA_ID,
    RECEIPT_SCHEMA,
    ReadinessError,
    _artifact_matches_pickup,
    _assert_artifact_current,
    _binding_reasons,
    _campaign,
    _close_artifact,
    _event as readiness_event,
    _mark_stale,
    _open_staged_artifact,
    _receipt_directory,
    _receipt_locator,
    _validate_attempt,
    _validate_receipt,
    ensure_schema as ensure_readiness_schema,
    pickup_receipt as pickup_readiness_receipt,
)
from role_executor_transport import (
    BROKER_SYSTEMD_CPU_QUOTA_PERCENT,
    BROKER_SYSTEMD_MEMORY_MAX_BYTES,
    BROKER_SYSTEMD_RUNTIME_MAX_SECONDS,
    BROKER_SYSTEMD_TASKS_MAX,
)


CONTRACT_SCHEMA = "twinfinity-role-broker-contract/v1"
INPUT_SCHEMA = "twinfinity-role-broker-input/v1"
ISOLATION_SCHEMA = "twinfinity-role-broker-isolation/v1"
RESULT_PATH = "/run/twinfinity-attempt/out/receipt.json"
RESULT_MAX_BYTES = 1_048_576
RESULT_SCHEMA_PATH = "/run/twinfinity-attempt/receipt.schema.json"
INSTRUCTION_PATH = "/run/twinfinity-attempt/instructions/SKILL.md"
INSTRUCTION_BUNDLE_SCHEMA = "twinfinity-readiness-instruction-bundle/v1"
PICKUP_CONSUMPTION_SCHEMA = "twinfinity-role-broker-pickup-consumption/v1"
MODEL_TRANSPORT_SCHEMA = "twinfinity-attempt-bound-responses-proxy/v1"
BROKER_WALL_SECONDS = 600
BROKER_CPU_SECONDS = 300
BROKER_NOFILE_LIMIT = 64
BROKER_LOG_BYTES = 0
BROKER_TERMINATION_GRACE_SECONDS = 5
BROKER_STATES = {"PREPARING", "LAUNCHING", "RUNNING", "COMPLETE", "HOLD"}
BROKER_ACTIVE_STATES = {"PREPARING", "LAUNCHING", "RUNNING"}
BROKER_TERMINAL_SYSTEMD_RESULTS = {
    "success",
    "exit-code",
    "signal",
    "core-dump",
    "watchdog",
    "timeout",
    "resources",
    "protocol",
}
BROKER_PROTOCOL = BROKERED_READINESS_PROTOCOL
REFERENCE_ROOT = Path(__file__).resolve().parents[1] / "references"


class BrokerError(RegistryError):
    """Typed, secret-free broker boundary failure."""


@dataclass(frozen=True)
class BrokerRuntimePaths:
    """Host paths that are bound explicitly into one private child mount tree."""

    spool_root: Path
    bwrap_path: Path
    setpriv_path: Path
    codex_binary_path: Path


@dataclass(frozen=True)
class BrokerSpool:
    """Non-authorizing host-side files for one broker attempt."""

    root: Path
    contract_path: Path
    input_path: Path
    instruction_path: Path
    receipt_schema_path: Path
    runtime_profile_path: Path
    receipt_path: Path
    masked_coordination_root: Path


@dataclass(frozen=True)
class BrokerEvaluatorInactivity:
    """Positive proof that the isolated evaluator can no longer mutate output."""

    kind: str
    process_id: int | None = None
    exit_code: int | None = None
    systemd_evidence: SystemdUnitEvidence | None = None

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "process_id": self.process_id,
            "exit_code": self.exit_code,
            "systemd_evidence": (
                None
                if self.systemd_evidence is None
                else self.systemd_evidence.payload
            ),
        }


def default_runtime_paths() -> BrokerRuntimePaths:
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    return BrokerRuntimePaths(
        spool_root=Path(f"/run/user/{os.getuid()}/twinfinity-role-broker"),
        bwrap_path=Path("/usr/bin/bwrap"),
        setpriv_path=Path("/usr/bin/setpriv"),
        codex_binary_path=(home / ".local/bin/codex").resolve(),
    )


def _store_for_connection(connection: sqlite3.Connection) -> CoordinationStore:
    store = CoordinationStore.__new__(CoordinationStore)
    store.connection = connection
    row = connection.execute(
        "SELECT file FROM pragma_database_list WHERE name='main'"
    ).fetchone()
    store.path = Path(str(row[0])) if row is not None and row[0] else Path("/:memory:")
    return store


def ensure_broker_schema(connection: sqlite3.Connection) -> None:
    """Install the owner-only broker run, pickup, and event ledgers."""

    try:
        connection.executescript(
            """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS role_executor_broker_runs (
                attempt_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK(role IN ('development','sre')),
                endpoint_id TEXT NOT NULL,
                target_kind TEXT NOT NULL CHECK(target_kind='message'),
                target_key TEXT NOT NULL,
                message_id INTEGER NOT NULL,
                message_topic TEXT NOT NULL CHECK(message_topic='coordination.notice'),
                message_payload_sha256 TEXT NOT NULL,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                campaign_id INTEGER NOT NULL,
                readiness_plan_sha256 TEXT NOT NULL,
                candidate_sha256 TEXT NOT NULL,
                source_payload_sha256 TEXT NOT NULL,
                accepted_main_sha TEXT NOT NULL,
                graph_version INTEGER NOT NULL CHECK(graph_version > 0),
                graph_sha256 TEXT NOT NULL,
                capacity_policy_version INTEGER NOT NULL CHECK(capacity_policy_version > 0),
                capacity_policy_sha256 TEXT NOT NULL,
                gate_set_sha256 TEXT NOT NULL,
                input_projection_sha256 TEXT NOT NULL,
                input_projection_json TEXT NOT NULL,
                contract_sha256 TEXT NOT NULL UNIQUE,
                contract_json TEXT NOT NULL,
                profile_sha256 TEXT NOT NULL,
                isolation_sha256 TEXT NOT NULL,
                result_path TEXT NOT NULL,
                result_max_bytes INTEGER NOT NULL CHECK(result_max_bytes > 0),
                state TEXT NOT NULL CHECK(state IN (
                    'PREPARING','LAUNCHING','RUNNING','COMPLETE','HOLD'
                )),
                process_id INTEGER,
                receipt_sha256 TEXT,
                version INTEGER NOT NULL CHECK(version > 0),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT,
                FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS role_broker_one_active_message
            ON role_executor_broker_runs(message_id)
            WHERE state IN ('PREPARING','LAUNCHING','RUNNING');
            CREATE TABLE IF NOT EXISTS role_executor_broker_receipt_pickups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id TEXT NOT NULL UNIQUE,
                campaign_id INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                receipt_sha256 TEXT NOT NULL UNIQUE,
                receipt_json TEXT NOT NULL,
                observation_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                staged_at TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state='STAGED'),
                FOREIGN KEY(attempt_id) REFERENCES role_executor_broker_runs(attempt_id),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id)
            );
            CREATE TABLE IF NOT EXISTS role_executor_broker_pickup_consumptions (
                attempt_id TEXT PRIMARY KEY,
                campaign_id INTEGER NOT NULL,
                receipt_sha256 TEXT NOT NULL UNIQUE,
                outcome_sha256 TEXT NOT NULL,
                outcome_json TEXT NOT NULL,
                consumed_at TEXT NOT NULL,
                FOREIGN KEY(attempt_id)
                    REFERENCES role_executor_broker_receipt_pickups(attempt_id),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id)
            );
            CREATE TABLE IF NOT EXISTS role_executor_broker_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                from_version INTEGER,
                to_version INTEGER NOT NULL,
                reason TEXT,
                payload_sha256 TEXT,
                payload_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(attempt_id) REFERENCES role_executor_broker_runs(attempt_id)
            );
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_binding_immutable
            BEFORE UPDATE ON role_executor_broker_runs
            WHEN NEW.attempt_id IS NOT OLD.attempt_id
              OR NEW.instance_id IS NOT OLD.instance_id
              OR NEW.role IS NOT OLD.role
              OR NEW.endpoint_id IS NOT OLD.endpoint_id
              OR NEW.target_kind IS NOT OLD.target_kind
              OR NEW.target_key IS NOT OLD.target_key
              OR NEW.message_id IS NOT OLD.message_id
              OR NEW.message_topic IS NOT OLD.message_topic
              OR NEW.message_payload_sha256 IS NOT OLD.message_payload_sha256
              OR NEW.repository IS NOT OLD.repository
              OR NEW.issue_number IS NOT OLD.issue_number
              OR NEW.campaign_id IS NOT OLD.campaign_id
              OR NEW.readiness_plan_sha256 IS NOT OLD.readiness_plan_sha256
              OR NEW.candidate_sha256 IS NOT OLD.candidate_sha256
              OR NEW.source_payload_sha256 IS NOT OLD.source_payload_sha256
              OR NEW.accepted_main_sha IS NOT OLD.accepted_main_sha
              OR NEW.graph_version IS NOT OLD.graph_version
              OR NEW.graph_sha256 IS NOT OLD.graph_sha256
              OR NEW.capacity_policy_version IS NOT OLD.capacity_policy_version
              OR NEW.capacity_policy_sha256 IS NOT OLD.capacity_policy_sha256
              OR NEW.gate_set_sha256 IS NOT OLD.gate_set_sha256
              OR NEW.input_projection_sha256 IS NOT OLD.input_projection_sha256
              OR NEW.input_projection_json IS NOT OLD.input_projection_json
              OR NEW.contract_sha256 IS NOT OLD.contract_sha256
              OR NEW.contract_json IS NOT OLD.contract_json
              OR NEW.profile_sha256 IS NOT OLD.profile_sha256
              OR NEW.isolation_sha256 IS NOT OLD.isolation_sha256
              OR NEW.result_path IS NOT OLD.result_path
              OR NEW.result_max_bytes IS NOT OLD.result_max_bytes
            BEGIN SELECT RAISE(ABORT, 'BROKER_RUN_BINDING_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_state_transition
            BEFORE UPDATE OF state ON role_executor_broker_runs
            WHEN NOT (
                (OLD.state='PREPARING' AND NEW.state IN ('LAUNCHING','HOLD'))
                OR (OLD.state='LAUNCHING' AND NEW.state IN ('RUNNING','HOLD'))
                OR (OLD.state='RUNNING' AND NEW.state IN ('RUNNING','COMPLETE','HOLD'))
            )
            BEGIN SELECT RAISE(ABORT, 'BROKER_RUN_STATE_CONFLICT'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_run_delete
            BEFORE DELETE ON role_executor_broker_runs
            BEGIN SELECT RAISE(ABORT, 'BROKER_RUN_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_pickup_update
            BEFORE UPDATE ON role_executor_broker_receipt_pickups
            BEGIN SELECT RAISE(ABORT, 'BROKER_RECEIPT_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_pickup_delete
            BEFORE DELETE ON role_executor_broker_receipt_pickups
            BEGIN SELECT RAISE(ABORT, 'BROKER_RECEIPT_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_consumption_update
            BEFORE UPDATE ON role_executor_broker_pickup_consumptions
            BEGIN SELECT RAISE(ABORT, 'BROKER_CONSUMPTION_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_consumption_delete
            BEFORE DELETE ON role_executor_broker_pickup_consumptions
            BEGIN SELECT RAISE(ABORT, 'BROKER_CONSUMPTION_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_event_update
            BEFORE UPDATE ON role_executor_broker_events
            BEGIN SELECT RAISE(ABORT, 'BROKER_EVENT_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS role_executor_broker_event_delete
            BEFORE DELETE ON role_executor_broker_events
            BEGIN SELECT RAISE(ABORT, 'BROKER_EVENT_IMMUTABLE'); END;
            COMMIT;
            """
        )
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _broker_event(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    from_state: str | None,
    to_state: str,
    from_version: int | None,
    to_version: int,
    reason: str | None,
    payload: dict[str, Any] | None,
    now: str,
) -> None:
    payload_json = None if payload is None else canonical_json(payload)
    connection.execute(
        """
        INSERT INTO role_executor_broker_events(
            attempt_id, from_state, to_state, from_version, to_version,
            reason, payload_sha256, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            attempt_id,
            from_state,
            to_state,
            from_version,
            to_version,
            reason,
            None if payload is None else digest_json(payload),
            payload_json,
            now,
        ),
    )


def isolation_manifest(configured: EndpointConfig) -> dict[str, Any]:
    """Return the stable kernel boundary contract whose digest is child-bound."""

    return {
        "schema": ISOLATION_SCHEMA,
        "engine": "bubblewrap",
        "broker_protocol": BROKER_PROTOCOL,
        "capabilities": "DROP_ALL",
        "no_new_privileges": True,
        "namespaces": ["user", "pid", "ipc", "uts", "cgroup"],
        "network_namespace": "HOST_FOR_FUTURE_ATTEMPT_BOUND_RESPONSES_PROXY",
        "credential_transport": "NOT_IMPLEMENTED",
        "private_mounts": ["/proc", "/tmp", "/run", "/dev"],
        "coordination_root": "MASKED_READ_ONLY",
        "owner_database": "ABSENT",
        "user_dbus": "ABSENT",
        "persistent_writes": [RESULT_PATH],
        "limits": {
            "wall_seconds": BROKER_WALL_SECONDS,
            "cpu_seconds": BROKER_CPU_SECONDS,
            "file_bytes": RESULT_MAX_BYTES,
            "open_files": BROKER_NOFILE_LIMIT,
            "captured_log_bytes": BROKER_LOG_BYTES,
            "attempt_cgroup": {
                "MemoryMax": BROKER_SYSTEMD_MEMORY_MAX_BYTES,
                "TasksMax": BROKER_SYSTEMD_TASKS_MAX,
                "RuntimeMaxSec": BROKER_SYSTEMD_RUNTIME_MAX_SECONDS,
                "CPUQuotaPercent": BROKER_SYSTEMD_CPU_QUOTA_PERCENT,
            },
        },
        "profile_sha256": configured.profile_sha256,
    }


def _json_row(row: sqlite3.Row | None, error: str) -> dict[str, Any]:
    if row is None:
        raise BrokerError(error)
    return dict(row)


def _parse_canonical_json(raw: str, expected_sha256: str, error: str) -> Any:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise BrokerError(error) from exc
    if digest_json(value) != expected_sha256 or canonical_json(value) != raw:
        raise BrokerError(error)
    return value


def _instruction_source(role: str) -> Path:
    if role == "development":
        return REFERENCE_ROOT / "readiness-evaluator-development.md"
    if role == "sre":
        return REFERENCE_ROOT / "readiness-evaluator-sre.md"
    raise BrokerError("BROKER_ROLE_INVALID")


def _read_reviewed_reference(path: Path, code: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        raw = b"".join(chunks)
    except OSError as exc:
        raise BrokerError(code) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(raw) != before.st_size
    ):
        raise BrokerError(code)
    return raw


def instruction_bundle(role: str) -> dict[str, Any]:
    """Load the complete reviewed evaluator closure as digest-bound bytes."""

    instruction_raw = _read_reviewed_reference(
        _instruction_source(role), "BROKER_INSTRUCTION_BUNDLE_INVALID"
    )
    schema_raw = _read_reviewed_reference(
        REFERENCE_ROOT / "twinfinity-kanban-readiness-receipt-v2.schema.json",
        "BROKER_RECEIPT_SCHEMA_INVALID",
    )
    try:
        instruction_text = instruction_raw.decode("utf-8")
        schema_text = schema_raw.decode("utf-8")
        schema = json.loads(schema_text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("BROKER_INSTRUCTION_BUNDLE_INVALID") from exc
    if (
        not isinstance(schema, dict)
        or schema.get("$id") != RECEIPT_JSON_SCHEMA_ID
        or schema.get("additionalProperties") is not False
    ):
        raise BrokerError("BROKER_RECEIPT_SCHEMA_INVALID")
    return {
        "schema": INSTRUCTION_BUNDLE_SCHEMA,
        "instruction": {
            "path": INSTRUCTION_PATH,
            "sha256": hashlib.sha256(instruction_raw).hexdigest(),
            "text": instruction_text,
        },
        "receipt_schema": {
            "path": RESULT_SCHEMA_PATH,
            "sha256": hashlib.sha256(schema_raw).hexdigest(),
            "text": schema_text,
        },
    }


def _build_input_projection(
    connection: sqlite3.Connection,
    *,
    role: str,
    endpoint_id: str,
    target_kind: str,
    target_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a path-free, canonical projection from current owner SQLite rows."""

    if target_kind != "message":
        raise BrokerError("BROKER_RPC_NOT_IMPLEMENTED")
    try:
        message_id = int(target_key)
    except (TypeError, ValueError) as exc:
        raise BrokerError("BROKER_RPC_NOT_IMPLEMENTED") from exc
    message = _json_row(
        connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone(),
        "BROKER_MESSAGE_MISSING",
    )
    if (
        message["recipient_session_id"] != endpoint_id
        or message["topic"] != "coordination.notice"
    ):
        raise BrokerError("BROKER_RPC_NOT_IMPLEMENTED")
    if message["state"] != "PREPARED" or message["claimed_by"] is not None:
        raise BrokerError("BROKER_MESSAGE_NOT_PREPARED")
    payload = _parse_canonical_json(
        str(message["payload_json"]),
        str(message["payload_sha256"]),
        "BROKER_MESSAGE_INVALID",
    )
    if (
        not isinstance(payload, dict)
        or payload.get("notice_kind") != "planning_request"
        or payload.get("mutation_authority") is not False
        or not isinstance(payload.get("source"), dict)
        or not isinstance(payload.get("evidence"), dict)
        or not isinstance(payload["evidence"].get("readiness_plan_sha256"), str)
    ):
        raise BrokerError("BROKER_RPC_NOT_IMPLEMENTED")
    source = payload["source"]
    repository = source.get("repository")
    issue_number = source.get("object_number")
    if (
        not isinstance(repository, str)
        or type(issue_number) is not int
        or issue_number <= 0
        or source.get("object_kind") != "issue"
    ):
        raise BrokerError("BROKER_MESSAGE_INVALID")
    campaign = _json_row(
        connection.execute(
            """
            SELECT campaign.*, current.state, current.message_id,
                   current.attempt_id, current.endpoint_id,
                   current.version AS current_version
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign
              ON campaign.id=current.campaign_id
            WHERE current.repository=? AND current.issue_number=?
            """,
            (repository, issue_number),
        ).fetchone(),
        "BROKER_READINESS_CAMPAIGN_MISSING",
    )
    if campaign["attempt_id"] is not None:
        raise BrokerError("BROKER_READINESS_ALREADY_ATTACHED")
    if (
        campaign["worker_role"] != role
        or campaign["state"] != "RUNNING"
        or int(campaign["message_id"] or -1) != message_id
        or campaign["endpoint_id"] != endpoint_id
        or campaign["plan_sha256"]
        != payload["evidence"]["readiness_plan_sha256"]
        or campaign["source_payload_sha256"] != source.get("payload_sha256")
    ):
        raise BrokerError("BROKER_READINESS_BINDING_INVALID")
    reasons = _binding_reasons(connection, campaign)
    if reasons:
        raise BrokerError("BROKER_READINESS_BINDING_DRIFT:" + ",".join(reasons))

    snapshot = _json_row(
        connection.execute(
            """
            SELECT snapshot.* FROM github_current current
            JOIN github_snapshots snapshot
              ON snapshot.repository=current.repository
             AND snapshot.object_kind=current.object_kind
             AND snapshot.object_number=current.object_number
             AND snapshot.payload_sha256=current.payload_sha256
            WHERE current.repository=? AND current.object_kind='issue'
              AND current.object_number=?
            """,
            (repository, issue_number),
        ).fetchone(),
        "BROKER_SOURCE_SNAPSHOT_MISSING",
    )
    snapshot_payload = _parse_canonical_json(
        str(snapshot["payload_json"]),
        str(snapshot["payload_sha256"]),
        "BROKER_SOURCE_SNAPSHOT_INVALID",
    )
    graph_current = _json_row(
        connection.execute(
            "SELECT * FROM portfolio_graph_current WHERE repository=?",
            (repository,),
        ).fetchone(),
        "BROKER_GRAPH_MISSING",
    )
    graph_revision = _json_row(
        connection.execute(
            """
            SELECT * FROM portfolio_graph_revisions
            WHERE repository=? AND version=?
            """,
            (repository, int(campaign["graph_version"])),
        ).fetchone(),
        "BROKER_GRAPH_MISSING",
    )
    graph_nodes = [
        dict(row)
        for row in connection.execute(
            """
            SELECT * FROM portfolio_graph_nodes
            WHERE repository=? AND graph_version=?
            ORDER BY node_key
            """,
            (repository, int(campaign["graph_version"])),
        )
    ]
    graph_relations = [
        dict(row)
        for row in connection.execute(
            """
            SELECT * FROM portfolio_graph_relations
            WHERE repository=? AND graph_version=?
            ORDER BY left_node_key, right_node_key, relation_kind
            """,
            (repository, int(campaign["graph_version"])),
        )
    ]
    policy = _json_row(
        connection.execute(
            """
            SELECT policy.* FROM coordination_capacity_current current
            JOIN coordination_capacity_policies policy
              ON policy.repository=current.repository
             AND policy.version=current.version
            WHERE current.repository=?
            """,
            (repository,),
        ).fetchone(),
        "BROKER_CAPACITY_POLICY_MISSING",
    )
    candidate = _json_row(
        connection.execute(
            """
            SELECT candidate.* FROM portfolio_pull_buffer_current current
            JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=current.candidate_id
            WHERE current.repository=? AND current.issue_number=?
            """,
            (repository, issue_number),
        ).fetchone(),
        "BROKER_CANDIDATE_MISSING",
    )
    gates = [
        {
            "gate_key": str(row["gate_key"]),
            "description": str(row["description"]),
            "requested_evidence": json.loads(str(row["requested_evidence_json"])),
            "gate_sha256": str(row["gate_sha256"]),
        }
        for row in connection.execute(
            """
            SELECT gate_key, description, requested_evidence_json, gate_sha256
            FROM portfolio_readiness_gates
            WHERE campaign_id=? ORDER BY gate_key
            """,
            (int(campaign["id"]),),
        )
    ]
    plan = _parse_canonical_json(
        str(campaign["plan_json"]),
        str(campaign["plan_sha256"]),
        "BROKER_READINESS_PLAN_INVALID",
    )
    if (
        graph_current["health"] != "CURRENT"
        or int(graph_current["version"]) != int(campaign["graph_version"])
        or graph_current["observed_main_sha"] != campaign["accepted_main_sha"]
        or graph_revision["accepted_main_sha"] != campaign["accepted_main_sha"]
        or int(policy["version"]) != int(campaign["capacity_policy_version"])
        or candidate["candidate_sha256"] != campaign["candidate_sha256"]
        or snapshot["payload_sha256"] != campaign["source_payload_sha256"]
        or not gates
    ):
        raise BrokerError("BROKER_READINESS_BINDING_INVALID")

    bundle = instruction_bundle(role)
    projection = {
        "schema": INPUT_SCHEMA,
        "message": {
            "id": message_id,
            "recipient_endpoint": endpoint_id,
            "topic": message["topic"],
            "payload_sha256": message["payload_sha256"],
            "payload": payload,
        },
        "issue_snapshot": {
            "repository": repository,
            "object_kind": "issue",
            "object_number": issue_number,
            "payload_sha256": snapshot["payload_sha256"],
            "source_updated_at": snapshot["source_updated_at"],
            "fetched_at": snapshot["fetched_at"],
            "payload": snapshot_payload,
        },
        "readiness_campaign": {
            "id": int(campaign["id"]),
            "plan_sha256": campaign["plan_sha256"],
            "plan": plan,
        },
        "gates": gates,
        "graph": {
            "current": graph_current,
            "revision": graph_revision,
            "nodes": graph_nodes,
            "relations": graph_relations,
        },
        "capacity_policy": policy,
        "candidate": candidate,
        "instruction_bundle": bundle,
    }
    binding = {
        "message_id": message_id,
        "message_topic": str(message["topic"]),
        "message_payload_sha256": str(message["payload_sha256"]),
        "repository": repository,
        "issue_number": issue_number,
        "campaign_id": int(campaign["id"]),
        "readiness_plan_sha256": str(campaign["plan_sha256"]),
        "delivery_identity_sha256": str(
            plan["delivery_identity_sha256"]
        ),
        "candidate_sha256": str(campaign["candidate_sha256"]),
        "source_payload_sha256": str(campaign["source_payload_sha256"]),
        "accepted_main_sha": str(campaign["accepted_main_sha"]),
        "graph_version": int(campaign["graph_version"]),
        "graph_sha256": str(graph_revision["graph_sha256"]),
        "capacity_policy_version": int(campaign["capacity_policy_version"]),
        "capacity_policy_sha256": digest_json(policy),
        "gate_set_sha256": digest_json(gates),
        "instruction_closure_sha256": digest_json(bundle),
        "instruction_sha256": bundle["instruction"]["sha256"],
        "receipt_schema_sha256": bundle["receipt_schema"]["sha256"],
    }
    return projection, binding


def _build_contract(
    *,
    configured: EndpointConfig,
    attempt: dict[str, Any],
    binding: dict[str, Any],
    input_projection_sha256: str,
) -> dict[str, Any]:
    isolation_sha256 = digest_json(isolation_manifest(configured))
    return {
        "schema": CONTRACT_SCHEMA,
        "protocol": BROKER_PROTOCOL,
        "role": configured.role,
        "endpoint_id": configured.endpoint_id,
        "attempt_id": attempt["attempt_id"],
        "instance_id": attempt["instance_id"],
        "target_kind": attempt["target_kind"],
        "target_key": attempt["target_key"],
        **binding,
        "input_projection_sha256": input_projection_sha256,
        "result_schema": RECEIPT_SCHEMA,
        "result_path": RESULT_PATH,
        "result_max_bytes": RESULT_MAX_BYTES,
        "instruction_path": INSTRUCTION_PATH,
        "receipt_schema_path": RESULT_SCHEMA_PATH,
        "model_transport": {
            "schema": MODEL_TRANSPORT_SCHEMA,
            "state": "NOT_IMPLEMENTED",
            "kind": "ATTEMPT_BOUND_HOST_RESPONSES_PROXY",
            "requires_openai_auth": False,
            "environment_key": None,
            "credential_mount": None,
        },
        "runtime_profile_path": (
            f"/tmp/codex-home/{configured.runtime_codex_profile}.config.toml"
        ),
        "isolation_sha256": isolation_sha256,
        "profile_sha256": configured.profile_sha256,
    }


def prepare_broker_run(
    connection: sqlite3.Connection,
    *,
    configured: EndpointConfig,
    attempt_id: str,
    profile_path: Path,
    now: str,
) -> dict[str, Any]:
    """Persist one immutable PREPARING contract before any child exists."""

    if configured.execution_protocol != BROKER_PROTOCOL:
        raise BrokerError("BROKER_PROTOCOL_INVALID")
    ensure_readiness_schema(connection)
    ensure_broker_schema(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        prior = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if prior is not None:
            if (
                prior["role"] != configured.role
                or prior["endpoint_id"] != configured.endpoint_id
                or prior["profile_sha256"] != configured.profile_sha256
                or prior["result_path"] != RESULT_PATH
                or int(prior["result_max_bytes"]) != RESULT_MAX_BYTES
            ):
                raise BrokerError("BROKER_RUN_BINDING_INVALID")
            connection.execute("COMMIT")
            return dict(prior)
        attempt = _json_row(
            connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone(),
            "BROKER_ATTEMPT_MISSING",
        )
        if (
            attempt["state"] != "RESERVED"
            or attempt["role"] != configured.role
            or attempt["endpoint_id"] != configured.endpoint_id
            or attempt["target_kind"] != "message"
        ):
            raise BrokerError("BROKER_ATTEMPT_BINDING_INVALID")
        projection, binding = _build_input_projection(
            connection,
            role=configured.role,
            endpoint_id=configured.endpoint_id,
            target_kind=str(attempt["target_kind"]),
            target_key=str(attempt["target_key"]),
        )
        profile_raw = _read_reviewed_reference(
            profile_path, "BROKER_PROFILE_INVALID"
        )
        if hashlib.sha256(profile_raw).hexdigest() != configured.profile_sha256:
            raise BrokerError("BROKER_PROFILE_DIGEST_MISMATCH")
        try:
            profile_text = profile_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BrokerError("BROKER_PROFILE_INVALID") from exc
        projection["runtime_profile"] = {
            "path": f"/tmp/codex-home/{configured.runtime_codex_profile}.config.toml",
            "sha256": configured.profile_sha256,
            "text": profile_text,
        }
        projection_json = canonical_json(projection)
        projection_sha256 = hashlib.sha256(projection_json.encode("utf-8")).hexdigest()
        contract = _build_contract(
            configured=configured,
            attempt=attempt,
            binding=binding,
            input_projection_sha256=projection_sha256,
        )
        contract_json = canonical_json(contract)
        contract_sha256 = hashlib.sha256(contract_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO role_executor_broker_runs(
                attempt_id, instance_id, role, endpoint_id, target_kind, target_key,
                message_id, message_topic, message_payload_sha256,
                repository, issue_number, campaign_id, readiness_plan_sha256,
                candidate_sha256, source_payload_sha256, accepted_main_sha,
                graph_version, graph_sha256, capacity_policy_version,
                capacity_policy_sha256, gate_set_sha256,
                input_projection_sha256, input_projection_json,
                contract_sha256, contract_json, profile_sha256,
                isolation_sha256, result_path, result_max_bytes,
                state, process_id, receipt_sha256, version,
                created_at, updated_at, last_error
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARING', NULL, NULL, 1, ?, ?, NULL
            )
            """,
            (
                attempt["attempt_id"],
                attempt["instance_id"],
                configured.role,
                configured.endpoint_id,
                attempt["target_kind"],
                attempt["target_key"],
                binding["message_id"],
                binding["message_topic"],
                binding["message_payload_sha256"],
                binding["repository"],
                binding["issue_number"],
                binding["campaign_id"],
                binding["readiness_plan_sha256"],
                binding["candidate_sha256"],
                binding["source_payload_sha256"],
                binding["accepted_main_sha"],
                binding["graph_version"],
                binding["graph_sha256"],
                binding["capacity_policy_version"],
                binding["capacity_policy_sha256"],
                binding["gate_set_sha256"],
                projection_sha256,
                projection_json,
                contract_sha256,
                contract_json,
                configured.profile_sha256,
                contract["isolation_sha256"],
                RESULT_PATH,
                RESULT_MAX_BYTES,
                now,
                now,
            ),
        )
        _broker_event(
            connection,
            attempt_id=attempt_id,
            from_state=None,
            to_state="PREPARING",
            from_version=None,
            to_version=1,
            reason="BROKER_RUN_PREPARED",
            payload={
                "contract_sha256": contract_sha256,
                "input_projection_sha256": projection_sha256,
            },
            now=now,
        )
        row = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return dict(row)


def _safe_directory(path: Path, *, create: bool) -> None:
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise BrokerError("BROKER_SPOOL_UNSAFE") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise BrokerError("BROKER_SPOOL_UNSAFE")


def _write_immutable_file(path: Path, raw: bytes, mode: int) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
        )
    except FileExistsError:
        try:
            if path.read_bytes() != raw:
                raise BrokerError("BROKER_SPOOL_CONFLICT")
            metadata = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise BrokerError("BROKER_SPOOL_UNSAFE") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise BrokerError("BROKER_SPOOL_UNSAFE")
        return
    except OSError as exc:
        raise BrokerError("BROKER_SPOOL_UNSAFE") from exc
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BrokerError("BROKER_SPOOL_WRITE_FAILED")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare_spool(runtime: BrokerRuntimePaths, run: dict[str, Any]) -> BrokerSpool:
    """Materialize canonical non-authorizing inputs and one writable result file."""

    _safe_directory(runtime.spool_root, create=True)
    root = runtime.spool_root / str(run["attempt_id"])
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _safe_directory(root, create=False)
    projection = _parse_canonical_json(
        str(run["input_projection_json"]),
        str(run["input_projection_sha256"]),
        "BROKER_INPUT_PROJECTION_INVALID",
    )
    contract = _parse_canonical_json(
        str(run["contract_json"]),
        str(run["contract_sha256"]),
        "BROKER_CONTRACT_INVALID",
    )
    bundle = projection.get("instruction_bundle") if isinstance(projection, dict) else None
    if (
        not isinstance(bundle, dict)
        or digest_json(bundle)
        != contract.get("instruction_closure_sha256")
        or not isinstance(bundle.get("instruction"), dict)
        or not isinstance(bundle.get("receipt_schema"), dict)
        or bundle["instruction"].get("path") != contract.get("instruction_path")
        or bundle["instruction"].get("sha256")
        != contract.get("instruction_sha256")
        or bundle["receipt_schema"].get("path")
        != contract.get("receipt_schema_path")
        or bundle["receipt_schema"].get("sha256")
        != contract.get("receipt_schema_sha256")
    ):
        raise BrokerError("BROKER_INSTRUCTION_BUNDLE_INVALID")
    runtime_profile = (
        projection.get("runtime_profile") if isinstance(projection, dict) else None
    )
    if (
        not isinstance(runtime_profile, dict)
        or runtime_profile.get("sha256") != run["profile_sha256"]
        or runtime_profile.get("path") != contract.get("runtime_profile_path")
    ):
        raise BrokerError("BROKER_PROFILE_INVALID")
    input_root = root / "input"
    instruction_root = root / "instructions"
    output_root = root / "out"
    masked = root / "masked-coordination"
    for directory in (input_root, instruction_root, output_root, masked):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _safe_directory(directory, create=False)
    contract_path = root / "contract.json"
    input_path = input_root / "input.json"
    instruction_path = instruction_root / "SKILL.md"
    receipt_schema_path = root / "receipt.schema.json"
    runtime_profile_path = root / "runtime-profile.config.toml"
    receipt_path = output_root / "receipt.json"
    _write_immutable_file(
        contract_path, str(run["contract_json"]).encode("utf-8"), 0o400
    )
    _write_immutable_file(
        input_path, str(run["input_projection_json"]).encode("utf-8"), 0o400
    )
    instruction_text = bundle["instruction"].get("text")
    schema_text = bundle["receipt_schema"].get("text")
    if not isinstance(instruction_text, str) or not isinstance(schema_text, str):
        raise BrokerError("BROKER_INSTRUCTION_BUNDLE_INVALID")
    if (
        hashlib.sha256(instruction_text.encode("utf-8")).hexdigest()
        != bundle["instruction"].get("sha256")
        or hashlib.sha256(schema_text.encode("utf-8")).hexdigest()
        != bundle["receipt_schema"].get("sha256")
    ):
        raise BrokerError("BROKER_INSTRUCTION_BUNDLE_INVALID")
    _write_immutable_file(instruction_path, instruction_text.encode("utf-8"), 0o400)
    _write_immutable_file(receipt_schema_path, schema_text.encode("utf-8"), 0o400)
    profile_text = runtime_profile.get("text")
    profile_target = runtime_profile.get("path")
    if (
        not isinstance(profile_text, str)
        or not isinstance(profile_target, str)
        or not profile_target.startswith("/tmp/codex-home/twinfinity-")
        or not profile_target.endswith(".config.toml")
        or hashlib.sha256(profile_text.encode("utf-8")).hexdigest()
        != run["profile_sha256"]
    ):
        raise BrokerError("BROKER_PROFILE_INVALID")
    _write_immutable_file(runtime_profile_path, profile_text.encode("utf-8"), 0o400)
    if not receipt_path.exists():
        _write_immutable_file(receipt_path, b"", 0o600)
    return BrokerSpool(
        root=root,
        contract_path=contract_path,
        input_path=input_path,
        instruction_path=instruction_path,
        receipt_schema_path=receipt_schema_path,
        runtime_profile_path=runtime_profile_path,
        receipt_path=receipt_path,
        masked_coordination_root=masked,
    )


def _require_runtime_path(path: Path, *, directory: bool, code: str) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise BrokerError(code) from exc
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise BrokerError(code)
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise BrokerError(code)


def broker_prompt(role: str) -> str:
    if role not in {"development", "sre"}:
        raise BrokerError("BROKER_ROLE_INVALID")
    return (
        f"Read and apply {INSTRUCTION_PATH} completely. Then read the exact "
        "broker contract and canonical input projection at the paths named by "
        "TWINFINITY_BROKER_CONTRACT and TWINFINITY_BROKER_INPUT. "
        "Evaluate every gate once without mutation. Write exactly one strict "
        f"{RECEIPT_SCHEMA} JSON object to {RESULT_PATH}; do not write any other "
        "persistent file."
    )


def build_bwrap_command(
    *,
    configured: EndpointConfig,
    runtime: BrokerRuntimePaths,
    spool: BrokerSpool,
    start_gate_fd: int,
) -> list[str]:
    """Build the exact kernel-enforced child command; no shell is involved."""

    if (
        configured.execution_protocol != BROKER_PROTOCOL
        or configured.role not in {"development", "sre"}
        or start_gate_fd < 3
    ):
        raise BrokerError("BROKER_COMMAND_INVALID")
    for path, directory, code in (
        (runtime.bwrap_path, False, "BROKER_BWRAP_MISSING"),
        (runtime.setpriv_path, False, "BROKER_SETPRIV_MISSING"),
        (runtime.codex_binary_path, False, "BROKER_CODEX_MISSING"),
        (spool.runtime_profile_path, False, "BROKER_PROFILE_MISSING"),
        (spool.root, True, "BROKER_SPOOL_UNSAFE"),
        (spool.contract_path, False, "BROKER_SPOOL_UNSAFE"),
        (spool.input_path, False, "BROKER_SPOOL_UNSAFE"),
        (spool.instruction_path, False, "BROKER_SPOOL_UNSAFE"),
        (spool.receipt_schema_path, False, "BROKER_SPOOL_UNSAFE"),
        (spool.receipt_path, False, "BROKER_SPOOL_UNSAFE"),
        (spool.masked_coordination_root, True, "BROKER_SPOOL_UNSAFE"),
    ):
        _require_runtime_path(path, directory=directory, code=code)
    command = [
        os.fspath(runtime.setpriv_path),
        "--no-new-privs",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--",
        os.fspath(runtime.bwrap_path),
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--assert-userns-disabled",
        "--cap-drop",
        "ALL",
        "--block-fd",
        str(start_gate_fd),
        "--clearenv",
        "--setenv",
        "HOME",
        "/tmp/broker-home",
        "--setenv",
        "CODEX_HOME",
        "/tmp/codex-home",
        "--setenv",
        "PATH",
        "/home/ubuntu/.local/bin:/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TWINFINITY_BROKER_CONTRACT",
        "/run/twinfinity-attempt/contract.json",
        "--setenv",
        "TWINFINITY_BROKER_INPUT",
        "/run/twinfinity-attempt/input/input.json",
        "--setenv",
        "TWINFINITY_BROKER_RESULT",
        RESULT_PATH,
        "--setenv",
        "TWINFINITY_BROKER_RESULT_SCHEMA",
        RESULT_SCHEMA_PATH,
        "--tmpfs",
        "/",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--dir",
        "/etc",
        "--dir",
        "/home",
        "--dir",
        "/home/ubuntu",
        "--dir",
        "/home/ubuntu/.local",
        "--dir",
        "/home/ubuntu/.local/bin",
        "--dir",
        "/home/ubuntu/.codex",
        "--dir",
        "/home/ubuntu/.codex/twinfinity-coordination",
        "--ro-bind",
        os.fspath(spool.masked_coordination_root),
        "/home/ubuntu/.codex/twinfinity-coordination",
        "--ro-bind",
        os.fspath(runtime.codex_binary_path),
        "/home/ubuntu/.local/bin/codex",
        "--dir",
        "/tmp/broker-home",
        "--dir",
        "/tmp/codex-home",
        "--ro-bind",
        os.fspath(spool.runtime_profile_path),
        f"/tmp/codex-home/{configured.runtime_codex_profile}.config.toml",
    ]
    for source, target in (
        (Path("/etc/ssl/certs"), "/etc/ssl/certs"),
        (Path("/etc/resolv.conf"), "/etc/resolv.conf"),
        (Path("/etc/hosts"), "/etc/hosts"),
        (Path("/etc/nsswitch.conf"), "/etc/nsswitch.conf"),
    ):
        if source.exists():
            parent = str(Path(target).parent)
            if parent not in {"/", "/etc"}:
                command.extend(["--dir", parent])
            command.extend(["--ro-bind", os.fspath(source), target])
    command.extend(
        [
            "--ro-bind",
            os.fspath(spool.root),
            "/run/twinfinity-attempt",
            "--bind",
            os.fspath(spool.receipt_path),
            RESULT_PATH,
            "--chdir",
            "/run/twinfinity-attempt/input",
            "--",
            "/home/ubuntu/.local/bin/codex",
            "exec",
            "--profile",
            configured.runtime_codex_profile,
            "--strict-config",
            "--json",
            broker_prompt(configured.role),
        ]
    )
    return command


def attest_bwrap_command(command: list[str]) -> dict[str, Any]:
    """Validate and digest the exact pre-launch isolation command."""

    required_once = {
        "--no-new-privs",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--assert-userns-disabled",
        "--cap-drop",
        "--block-fd",
        "--clearenv",
    }
    if any(command.count(flag) != 1 for flag in required_once):
        raise BrokerError("BROKER_NAMESPACE_POLICY_INVALID")
    joined = "\n".join(command)
    if (
        "auth.json" in joined
        or "TWINFINITY_EXECUTOR_TOKEN" in joined
        or "DBUS_SESSION_BUS_ADDRESS" in joined
        or "--unshare-cgroup-try" in command
        or command.count("--bind") != 1
        or RESULT_PATH not in command
        or INSTRUCTION_PATH not in joined
        or RESULT_SCHEMA_PATH not in joined
    ):
        raise BrokerError("BROKER_NAMESPACE_POLICY_INVALID")
    return {
        "schema": "twinfinity-role-broker-command-attestation/v1",
        "command_sha256": digest_json(command),
        "required_flags": sorted(required_once),
        "credential_mount": None,
        "writable_paths": [RESULT_PATH],
        "limits": {
            "wall_seconds": BROKER_WALL_SECONDS,
            "cpu_seconds": BROKER_CPU_SECONDS,
            "file_bytes": RESULT_MAX_BYTES,
            "open_files": BROKER_NOFILE_LIMIT,
            "captured_log_bytes": BROKER_LOG_BYTES,
            "attempt_cgroup": {
                "MemoryMax": BROKER_SYSTEMD_MEMORY_MAX_BYTES,
                "TasksMax": BROKER_SYSTEMD_TASKS_MAX,
                "RuntimeMaxSec": BROKER_SYSTEMD_RUNTIME_MAX_SECONDS,
                "CPUQuotaPercent": BROKER_SYSTEMD_CPU_QUOTA_PERCENT,
            },
        },
    }


_SYSTEMD_TIMESPAN_PART = re.compile(
    r"\s*(?P<value>[0-9]+(?:\.[0-9]+)?)\s*"
    r"(?P<unit>us|ms|s|min|h|d)"
)
_SYSTEMD_TIMESPAN_MULTIPLIERS = {
    "us": Decimal(1),
    "ms": Decimal(1_000),
    "s": Decimal(1_000_000),
    "min": Decimal(60_000_000),
    "h": Decimal(3_600_000_000),
    "d": Decimal(86_400_000_000),
}


def _systemd_usec(value: str) -> int:
    """Parse the stable `systemctl show` finite-timespan representation."""

    if not isinstance(value, str) or not value or value == "infinity":
        raise BrokerError("BROKER_SYSTEMD_LIMITS_INVALID")
    if value.isdecimal():
        return int(value)
    position = 0
    total = Decimal(0)
    try:
        while position < len(value):
            match = _SYSTEMD_TIMESPAN_PART.match(value, position)
            if match is None:
                raise BrokerError("BROKER_SYSTEMD_LIMITS_INVALID")
            total += (
                Decimal(match.group("value"))
                * _SYSTEMD_TIMESPAN_MULTIPLIERS[match.group("unit")]
            )
            position = match.end()
    except (InvalidOperation, KeyError) as exc:
        raise BrokerError("BROKER_SYSTEMD_LIMITS_INVALID") from exc
    if total != total.to_integral_value():
        raise BrokerError("BROKER_SYSTEMD_LIMITS_INVALID")
    return int(total)


def attest_broker_systemd_limits(evidence: SystemdUnitEvidence) -> dict[str, int]:
    """Require the outer attempt cgroup to attest every aggregate limit exactly."""

    try:
        memory_max = int(evidence.memory_max)
        tasks_max = int(evidence.tasks_max)
        runtime_max_usec = _systemd_usec(evidence.runtime_max_usec)
        cpu_quota_per_sec_usec = _systemd_usec(
            evidence.cpu_quota_per_sec_usec
        )
    except (TypeError, ValueError) as exc:
        raise BrokerError("BROKER_SYSTEMD_LIMITS_INVALID") from exc
    expected = {
        "MemoryMax": BROKER_SYSTEMD_MEMORY_MAX_BYTES,
        "TasksMax": BROKER_SYSTEMD_TASKS_MAX,
        "RuntimeMaxUSec": BROKER_SYSTEMD_RUNTIME_MAX_SECONDS * 1_000_000,
        "CPUQuotaPerSecUSec": (
            BROKER_SYSTEMD_CPU_QUOTA_PERCENT * 10_000
        ),
    }
    observed = {
        "MemoryMax": memory_max,
        "TasksMax": tasks_max,
        "RuntimeMaxUSec": runtime_max_usec,
        "CPUQuotaPerSecUSec": cpu_quota_per_sec_usec,
    }
    if observed != expected:
        raise BrokerError("BROKER_SYSTEMD_LIMITS_INVALID")
    return observed


def _attempt_transition(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    new_state: str,
    now: str,
    reason: str | None,
    process_id: int | None = None,
    exit_code: int | None = None,
    evidence: SystemdUnitEvidence | None = None,
) -> sqlite3.Row:
    old_state = str(row["state"])
    allowed = {
        "RESERVED": {"LAUNCHING", "LAUNCH_FAILED"},
        "LAUNCHING": {"RUNNING", "LAUNCH_FAILED"},
        "RUNNING": {"RUNNING", "COMPLETE", "HOLD"},
    }
    if new_state not in allowed.get(old_state, set()):
        raise BrokerError("BROKER_ATTEMPT_STATE_CONFLICT")
    version = int(row["version"]) + 1
    unit = row["systemd_unit"]
    invocation_id = row["systemd_invocation_id"]
    control_group = row["systemd_control_group"]
    effective_pid = row["process_id"]
    event_evidence: dict[str, Any] | None = None
    if new_state == "LAUNCHING":
        if evidence is None:
            raise BrokerError("BROKER_SYSTEMD_IDENTITY_INVALID")
        expected_unit = stable_systemd_unit(
            str(row["role"]), str(row["target_kind"]), str(row["target_key"])
        )
        if (
            evidence.unit != expected_unit
            or not evidence.invocation_id
            or not evidence.control_group.endswith(f"/{expected_unit}")
        ):
            raise BrokerError("BROKER_SYSTEMD_IDENTITY_INVALID")
        unit = evidence.unit
        invocation_id = evidence.invocation_id
        control_group = evidence.control_group
        event_evidence = {
            "systemd_unit": unit,
            "systemd_invocation_id": invocation_id,
            "systemd_control_group": control_group,
        }
    elif new_state == "RUNNING":
        if old_state == "LAUNCHING":
            if type(process_id) is not int or process_id <= 0:
                raise BrokerError("BROKER_PROCESS_ID_INVALID")
            effective_pid = process_id
        elif process_id is not None and process_id != effective_pid:
            raise BrokerError("BROKER_PROCESS_ID_INVALID")
    cursor = connection.execute(
        """
        UPDATE executor_attempts
        SET state=?, process_id=?, exit_code=?, systemd_unit=?,
            systemd_invocation_id=?, systemd_control_group=?, heartbeat_at=?,
            version=?, updated_at=?, last_error=?
        WHERE attempt_id=? AND version=?
        """,
        (
            new_state,
            effective_pid,
            exit_code,
            unit,
            invocation_id,
            control_group,
            now,
            version,
            now,
            reason,
            row["attempt_id"],
            row["version"],
        ),
    )
    if cursor.rowcount != 1:
        raise BrokerError("BROKER_ATTEMPT_VERSION_CONFLICT")
    _insert_attempt_event(
        connection,
        attempt_id=str(row["attempt_id"]),
        from_state=old_state,
        to_state=new_state,
        from_version=int(row["version"]),
        to_version=version,
        reason=reason,
        evidence=event_evidence,
        recorded_at=now,
    )
    return connection.execute(
        "SELECT * FROM executor_attempts WHERE attempt_id=?",
        (row["attempt_id"],),
    ).fetchone()


def _require_attempt_token(row: sqlite3.Row, token: str) -> None:
    token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(str(row["token_sha256"]), token_sha256):
        raise BrokerError("BROKER_ATTEMPT_TOKEN_MISMATCH")


def mark_broker_launching(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    token: str,
    evidence: SystemdUnitEvidence,
    command_attestation: dict[str, Any],
    now: str,
) -> dict[str, Any]:
    """Atomically bind systemd identity and enter broker LAUNCHING."""

    ensure_broker_schema(connection)
    systemd_limits = attest_broker_systemd_limits(evidence)
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        attempt = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if run is None or attempt is None or run["state"] != "PREPARING":
            raise BrokerError("BROKER_RUN_STATE_CONFLICT")
        _require_attempt_token(attempt, token)
        if (
            evidence.load_state != "loaded"
            or evidence.active_state not in {"active", "activating"}
            or evidence.sub_state not in {"running", "start"}
            or command_attestation.get("schema")
            != "twinfinity-role-broker-command-attestation/v1"
            or not SHA256.fullmatch(str(command_attestation.get("command_sha256", "")))
            or command_attestation.get("credential_mount") is not None
        ):
            raise BrokerError("BROKER_COMMAND_ATTESTATION_INVALID")
        _attempt_transition(
            connection,
            attempt,
            new_state="LAUNCHING",
            now=now,
            reason=None,
            evidence=evidence,
        )
        new_version = int(run["version"]) + 1
        updated = connection.execute(
            """
            UPDATE role_executor_broker_runs
            SET state='LAUNCHING', version=?, updated_at=?, last_error=NULL
            WHERE attempt_id=? AND state='PREPARING' AND version=?
            """,
            (new_version, now, attempt_id, int(run["version"])),
        )
        if updated.rowcount != 1:
            raise BrokerError("BROKER_RUN_VERSION_CONFLICT")
        _broker_event(
            connection,
            attempt_id=attempt_id,
            from_state="PREPARING",
            to_state="LAUNCHING",
            from_version=int(run["version"]),
            to_version=new_version,
            reason="BROKER_CHILD_GATED",
            payload={
                **command_attestation,
                "observed_attempt_cgroup": systemd_limits,
            },
            now=now,
        )
        updated = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return dict(updated)


def _validate_message_for_claim(
    store: CoordinationStore,
    run: sqlite3.Row,
    message: sqlite3.Row,
) -> dict[str, Any]:
    if (
        int(message["id"]) != int(run["message_id"])
        or message["state"] != "PREPARED"
        or message["recipient_session_id"] != run["endpoint_id"]
        or message["topic"] != "coordination.notice"
        or message["payload_sha256"] != run["message_payload_sha256"]
        or message["claimed_by"] is not None
    ):
        raise BrokerError("BROKER_MESSAGE_BINDING_INVALID")
    try:
        payload = json.loads(str(message["payload_json"]))
        if canonical_json(payload) != message["payload_json"]:
            raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
        store._validate_message_source(payload)
        store._validate_message_contract(
            topic=str(message["topic"]),
            recipient_session_id=str(message["recipient_session_id"]),
            payload=payload,
        )
    except (CoordinationError, json.JSONDecodeError) as exc:
        raise BrokerError("BROKER_MESSAGE_BINDING_INVALID") from exc
    return payload


def claim_attach_and_start(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    token: str,
    process_id: int,
    now: str,
) -> dict[str, Any]:
    """Atomically claim, attach, and mark RUNNING before releasing the gate."""

    store = _store_for_connection(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        attempt = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if run is None or attempt is None or run["state"] != "LAUNCHING":
            raise BrokerError("BROKER_RUN_STATE_CONFLICT")
        _require_attempt_token(attempt, token)
        message = connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (int(run["message_id"]),),
        ).fetchone()
        if message is None:
            raise BrokerError("BROKER_MESSAGE_MISSING")
        _validate_message_for_claim(store, run, message)
        campaign = _campaign(
            connection, str(run["repository"]), int(run["issue_number"])
        )
        if (
            int(campaign["id"]) != int(run["campaign_id"])
            or campaign["state"] != "RUNNING"
            or int(campaign["message_id"] or -1) != int(run["message_id"])
            or campaign["attempt_id"] is not None
            or campaign["endpoint_id"] != run["endpoint_id"]
        ):
            raise BrokerError("BROKER_READINESS_BINDING_INVALID")
        reasons = _binding_reasons(connection, campaign)
        if reasons:
            raise BrokerError("BROKER_READINESS_BINDING_DRIFT:" + ",".join(reasons))
        readiness_pickup = connection.execute(
            "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
            (int(run["campaign_id"]),),
        ).fetchone()
        readiness_locator = _receipt_locator(campaign)
        if (
            readiness_pickup is None
            or int(readiness_pickup["message_id"]) != int(run["message_id"])
            or readiness_pickup["locator_sha256"] != digest_json(readiness_locator)
            or readiness_pickup["relative_path"] != readiness_locator["relative_path"]
            or readiness_pickup["state"] != "PENDING"
            or readiness_pickup["attempt_id"] is not None
        ):
            raise BrokerError("BROKER_READINESS_PICKUP_BINDING_INVALID")
        _validate_attempt(
            connection,
            campaign,
            int(run["message_id"]),
            attempt_id,
            terminal=False,
        )
        claimed = connection.execute(
            """
            UPDATE coordination_messages
            SET state='CLAIMED', claimed_by=?, updated_at=?, last_error=NULL
            WHERE id=? AND state='PREPARED' AND claimed_by IS NULL
            """,
            (run["endpoint_id"], now, int(run["message_id"])),
        )
        if claimed.rowcount != 1:
            raise BrokerError("BROKER_MESSAGE_CLAIM_CONFLICT")
        store._event(
            "MESSAGE_CLAIMED",
            f"message:{int(run['message_id'])}",
            {"session_id": run["endpoint_id"], "broker_attempt_id": attempt_id},
            now,
        )
        attached = connection.execute(
            """
            UPDATE portfolio_readiness_current
            SET attempt_id=?, version=version+1, updated_at=?, last_error=NULL
            WHERE campaign_id=? AND state='RUNNING' AND message_id=?
              AND endpoint_id=? AND attempt_id IS NULL
            """,
            (
                attempt_id,
                now,
                int(run["campaign_id"]),
                int(run["message_id"]),
                run["endpoint_id"],
            ),
        )
        if attached.rowcount != 1:
            raise BrokerError("BROKER_READINESS_ATTACH_CONFLICT")
        pickup_attached = connection.execute(
            """
            UPDATE portfolio_readiness_receipt_pickups
            SET attempt_id=?, version=version+1, updated_at=?, last_error=NULL
            WHERE campaign_id=? AND message_id=? AND state='PENDING'
              AND attempt_id IS NULL AND version=?
            """,
            (
                attempt_id,
                now,
                int(run["campaign_id"]),
                int(run["message_id"]),
                int(readiness_pickup["version"]),
            ),
        )
        if pickup_attached.rowcount != 1:
            raise BrokerError("BROKER_READINESS_PICKUP_ATTACH_CONFLICT")
        readiness_event(
            connection,
            int(run["campaign_id"]),
            "READINESS_PHASE_ATTACHED",
            {"message_id": int(run["message_id"]), "attempt_id": attempt_id},
            now,
        )
        _attempt_transition(
            connection,
            attempt,
            new_state="RUNNING",
            now=now,
            reason=None,
            process_id=process_id,
        )
        new_version = int(run["version"]) + 1
        updated = connection.execute(
            """
            UPDATE role_executor_broker_runs
            SET state='RUNNING', process_id=?, version=?, updated_at=?,
                last_error=NULL
            WHERE attempt_id=? AND state='LAUNCHING' AND version=?
            """,
            (process_id, new_version, now, attempt_id, int(run["version"])),
        )
        if updated.rowcount != 1:
            raise BrokerError("BROKER_RUN_VERSION_CONFLICT")
        _broker_event(
            connection,
            attempt_id=attempt_id,
            from_state="LAUNCHING",
            to_state="RUNNING",
            from_version=int(run["version"]),
            to_version=new_version,
            reason="BROKER_START_GATE_READY",
            payload={"process_id": process_id},
            now=now,
        )
        result = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return dict(result)


def heartbeat_broker_run(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    token: str,
    process_id: int,
    now: str,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        attempt = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if (
            run is None
            or attempt is None
            or run["state"] != "RUNNING"
            or int(run["process_id"] or -1) != process_id
        ):
            raise BrokerError("BROKER_RUN_STATE_CONFLICT")
        _require_attempt_token(attempt, token)
        _attempt_transition(
            connection,
            attempt,
            new_state="RUNNING",
            now=now,
            reason=None,
            process_id=process_id,
        )
        new_version = int(run["version"]) + 1
        updated = connection.execute(
            """
            UPDATE role_executor_broker_runs
            SET state='RUNNING', version=?, updated_at=?
            WHERE attempt_id=? AND state='RUNNING' AND version=?
            """,
            (new_version, now, attempt_id, int(run["version"])),
        )
        if updated.rowcount != 1:
            raise BrokerError("BROKER_RUN_VERSION_CONFLICT")
        _broker_event(
            connection,
            attempt_id=attempt_id,
            from_state="RUNNING",
            to_state="RUNNING",
            from_version=int(run["version"]),
            to_version=new_version,
            reason="BROKER_HEARTBEAT",
            payload={"process_id": process_id},
            now=now,
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _not_started_inactivity() -> BrokerEvaluatorInactivity:
    return BrokerEvaluatorInactivity(kind="NOT_STARTED")


def _process_exit_inactivity(
    process_id: int, exit_code: int
) -> BrokerEvaluatorInactivity:
    if type(process_id) is not int or process_id <= 0 or type(exit_code) is not int:
        raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID")
    return BrokerEvaluatorInactivity(
        kind="PROCESS_EXIT", process_id=process_id, exit_code=exit_code
    )


def _systemd_inactivity(
    evidence: SystemdUnitEvidence,
) -> BrokerEvaluatorInactivity:
    return BrokerEvaluatorInactivity(
        kind="SYSTEMD_INACTIVE", systemd_evidence=evidence
    )


def _validate_inactive_systemd_snapshot(
    attempt: sqlite3.Row, evidence: SystemdUnitEvidence
) -> None:
    unit = str(attempt["systemd_unit"] or "")
    invocation_id = str(attempt["systemd_invocation_id"] or "")
    control_group = str(attempt["systemd_control_group"] or "")
    expected_unit = stable_systemd_unit(
        str(attempt["role"]), str(attempt["target_kind"]), str(attempt["target_key"])
    )
    if (
        unit != expected_unit
        or SYSTEMD_INVOCATION_ID.fullmatch(invocation_id) is None
        or not control_group.startswith("/")
        or not control_group.endswith(f"/{unit}")
        or evidence.unit != unit
        or evidence.invocation_id != invocation_id
        or evidence.control_group != control_group
        or evidence.load_state != "loaded"
        or evidence.active_state != "inactive"
        or evidence.sub_state != "dead"
        or evidence.result not in BROKER_TERMINAL_SYSTEMD_RESULTS
    ):
        raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID")
    try:
        attest_broker_systemd_limits(evidence)
    except BrokerError as exc:
        raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID") from exc


def _require_evaluator_inactive(
    attempt: sqlite3.Row,
    run: sqlite3.Row,
    observation: BrokerEvaluatorInactivity | None,
) -> dict[str, Any]:
    """Validate positive inactivity proof against the exact immutable attempt."""

    if observation is None:
        raise BrokerError("BROKER_EVALUATOR_INACTIVITY_REQUIRED")
    if observation.kind == "NOT_STARTED":
        if (
            observation.process_id is not None
            or observation.exit_code is not None
            or observation.systemd_evidence is not None
            or attempt["process_id"] is not None
            or run["process_id"] is not None
            or run["state"] not in {"PREPARING", "LAUNCHING"}
        ):
            raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID")
    elif observation.kind == "PROCESS_EXIT":
        if (
            type(observation.process_id) is not int
            or observation.process_id <= 0
            or type(observation.exit_code) is not int
            or observation.systemd_evidence is not None
        ):
            raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID")
        stored_process_ids = {
            int(value)
            for value in (attempt["process_id"], run["process_id"])
            if value is not None
        }
        if stored_process_ids and stored_process_ids != {observation.process_id}:
            raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID")
    elif observation.kind == "SYSTEMD_INACTIVE":
        if (
            observation.process_id is not None
            or observation.exit_code is not None
            or observation.systemd_evidence is None
        ):
            raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID")
        _validate_inactive_systemd_snapshot(attempt, observation.systemd_evidence)
    else:
        raise BrokerError("BROKER_EVALUATOR_INACTIVITY_INVALID")
    return observation.payload


def hold_broker_run(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    error: str,
    now: str,
    exit_code: int | None,
    evaluator_inactivity: BrokerEvaluatorInactivity,
) -> dict[str, Any]:
    """Apply the exact before-claim or after-attach terminal HOLD transaction."""

    store = _store_for_connection(connection)
    ensure_broker_schema(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        attempt = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if run is None or attempt is None:
            raise BrokerError("BROKER_RUN_MISSING")
        if run["state"] == "HOLD":
            if run["last_error"] != error:
                raise BrokerError("BROKER_RUN_STATE_CONFLICT")
            connection.execute("COMMIT")
            return dict(run)
        if run["state"] == "COMPLETE":
            raise BrokerError("BROKER_RUN_STATE_CONFLICT")
        inactivity_payload = _require_evaluator_inactive(
            attempt, run, evaluator_inactivity
        )
        message = connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (int(run["message_id"]),),
        ).fetchone()
        campaign = _campaign(
            connection, str(run["repository"]), int(run["issue_number"])
        )
        after_attach = campaign["attempt_id"] == attempt_id
        if after_attach:
            if (
                run["state"] != "RUNNING"
                or attempt["state"] != "RUNNING"
                or message is None
                or message["state"] != "CLAIMED"
                or message["claimed_by"] != run["endpoint_id"]
            ):
                raise BrokerError("BROKER_ATTEMPT_STATE_CONFLICT")
            held_message = connection.execute(
                """
                UPDATE coordination_messages
                SET state='HOLD', updated_at=?, last_error=?
                WHERE id=? AND state='CLAIMED' AND claimed_by=?
                """,
                (now, error, int(run["message_id"]), run["endpoint_id"]),
            )
            if held_message.rowcount != 1:
                raise BrokerError("BROKER_MESSAGE_STATE_CONFLICT")
            held_readiness = connection.execute(
                """
                UPDATE portfolio_readiness_current
                SET state='HOLD', version=version+1, updated_at=?, last_error=?
                WHERE campaign_id=? AND state='RUNNING' AND attempt_id=?
                """,
                (now, error, int(run["campaign_id"]), attempt_id),
            )
            if held_readiness.rowcount != 1:
                raise BrokerError("BROKER_READINESS_STATE_CONFLICT")
            readiness_event(
                connection,
                int(run["campaign_id"]),
                "READINESS_BROKER_HELD",
                {"attempt_id": attempt_id, "error": error},
                now,
            )
            _attempt_transition(
                connection,
                attempt,
                new_state="HOLD",
                now=now,
                reason=error,
                exit_code=exit_code,
            )
        else:
            if attempt["state"] not in {"RESERVED", "LAUNCHING", "RUNNING"}:
                raise BrokerError("BROKER_PRECLAIM_STATE_CONFLICT")
            _attempt_transition(
                connection,
                attempt,
                new_state=(
                    "LAUNCH_FAILED"
                    if attempt["state"] in {"RESERVED", "LAUNCHING"}
                    else "HOLD"
                ),
                now=now,
                reason=error,
                exit_code=exit_code,
            )
        old_state = str(run["state"])
        old_version = int(run["version"])
        new_version = old_version + 1
        updated = connection.execute(
            """
            UPDATE role_executor_broker_runs
            SET state='HOLD', version=?, updated_at=?, last_error=?
            WHERE attempt_id=? AND state=? AND version=?
            """,
            (new_version, now, error, attempt_id, old_state, old_version),
        )
        if updated.rowcount != 1:
            raise BrokerError("BROKER_RUN_VERSION_CONFLICT")
        _broker_event(
            connection,
            attempt_id=attempt_id,
            from_state=old_state,
            to_state="HOLD",
            from_version=old_version,
            to_version=new_version,
            reason=error,
            payload={
                "after_attach": after_attach,
                "exit_code": exit_code,
                "observed_message_state": None if message is None else message["state"],
                "observed_message_claimed_by": (
                    None if message is None else message["claimed_by"]
                ),
                "observed_readiness_attempt_id": campaign["attempt_id"],
                "evaluator_inactivity": inactivity_payload,
            },
            now=now,
        )
        result = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return dict(result)


def _receipt_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerError("BROKER_RECEIPT_DUPLICATE_KEY")
        result[key] = value
    return result


def read_receipt_file(path: Path, *, observed_at: str) -> tuple[dict[str, Any], str, dict[str, Any]]:
    """Read one owner-created result file through a stable descriptor."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise BrokerError("BROKER_RECEIPT_MISSING") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > RESULT_MAX_BYTES
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise BrokerError("BROKER_RECEIPT_FILE_INVALID")
        chunks: list[bytes] = []
        remaining = RESULT_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or len(raw) > RESULT_MAX_BYTES
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise BrokerError("BROKER_RECEIPT_FILE_DRIFT")
    finally:
        os.close(descriptor)
    try:
        receipt = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_receipt_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("BROKER_RECEIPT_INVALID") from exc
    if not isinstance(receipt, dict):
        raise BrokerError("BROKER_RECEIPT_INVALID")
    try:
        _validate_receipt(receipt)
    except ReadinessError as exc:
        raise BrokerError(str(exc)) from exc
    receipt_json = canonical_json(receipt)
    receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
    observation = {
        "observed_at": observed_at,
        "device": int(after.st_dev),
        "inode": int(after.st_ino),
        "mode": int(after.st_mode),
        "uid": int(after.st_uid),
        "link_count": int(after.st_nlink),
        "size": int(after.st_size),
        "mtime_ns": int(after.st_mtime_ns),
        "ctime_ns": int(after.st_ctime_ns),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": receipt_sha256,
    }
    return receipt, receipt_json, observation


def complete_broker_receipt(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    receipt: dict[str, Any],
    receipt_json: str,
    observation: dict[str, Any],
    now: str,
    evaluator_inactivity: BrokerEvaluatorInactivity | None = None,
) -> dict[str, Any]:
    """Atomically stage the receipt and terminalize message, attempt, and run."""

    try:
        _validate_receipt(receipt)
    except ReadinessError as exc:
        raise BrokerError(str(exc)) from exc
    if canonical_json(receipt) != receipt_json:
        raise BrokerError("BROKER_RECEIPT_NOT_CANONICAL")
    receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
    store = _store_for_connection(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if run is None:
            raise BrokerError("BROKER_RUN_MISSING")
        if run["state"] == "COMPLETE":
            pickup = connection.execute(
                """
                SELECT * FROM role_executor_broker_receipt_pickups
                WHERE attempt_id=?
                """,
                (attempt_id,),
            ).fetchone()
            if (
                pickup is None
                or pickup["receipt_sha256"] != receipt_sha256
                or pickup["receipt_json"] != receipt_json
            ):
                raise BrokerError("BROKER_RECEIPT_REPLAY_CONFLICT")
            connection.execute("COMMIT")
            return {
                "attempt_id": attempt_id,
                "state": "COMPLETE",
                "receipt_sha256": receipt_sha256,
                "pickup_state": "STAGED",
            }
        if run["state"] != "RUNNING":
            raise BrokerError("BROKER_RUN_STATE_CONFLICT")
        attempt = connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        message = connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (int(run["message_id"]),),
        ).fetchone()
        campaign = _campaign(
            connection, str(run["repository"]), int(run["issue_number"])
        )
        if (
            attempt is None
            or attempt["state"] != "RUNNING"
            or attempt["instance_id"] != run["instance_id"]
            or attempt["endpoint_id"] != run["endpoint_id"]
            or attempt["target_kind"] != run["target_kind"]
            or attempt["target_key"] != run["target_key"]
            or message is None
            or message["state"] != "CLAIMED"
            or message["claimed_by"] != run["endpoint_id"]
            or message["payload_sha256"] != run["message_payload_sha256"]
            or int(campaign["id"]) != int(run["campaign_id"])
            or campaign["state"] != "RUNNING"
            or campaign["attempt_id"] != attempt_id
        ):
            raise BrokerError("BROKER_TERMINAL_BINDING_INVALID")
        inactivity_payload = _require_evaluator_inactive(
            attempt, run, evaluator_inactivity
        )
        try:
            message_payload = json.loads(str(message["payload_json"]))
            if (
                canonical_json(message_payload) != message["payload_json"]
                or digest_json(message_payload) != message["payload_sha256"]
            ):
                raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
            store._validate_message_source(message_payload)
            store._validate_message_contract(
                topic=str(message["topic"]),
                recipient_session_id=str(message["recipient_session_id"]),
                payload=message_payload,
            )
        except (CoordinationError, json.JSONDecodeError) as exc:
            raise BrokerError("BROKER_TERMINAL_BINDING_INVALID") from exc
        if (
            hashlib.sha256(str(run["contract_json"]).encode("utf-8")).hexdigest()
            != run["contract_sha256"]
            or hashlib.sha256(
                str(run["input_projection_json"]).encode("utf-8")
            ).hexdigest()
            != run["input_projection_sha256"]
        ):
            raise BrokerError("BROKER_TERMINAL_BINDING_INVALID")
        reasons = _binding_reasons(connection, campaign)
        if reasons:
            raise BrokerError("BROKER_READINESS_BINDING_DRIFT:" + ",".join(reasons))
        try:
            campaign_plan = json.loads(str(campaign["plan_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise BrokerError("BROKER_TERMINAL_BINDING_INVALID") from exc
        expected_receipt_binding = {
            "repository": run["repository"],
            "issue_number": int(run["issue_number"]),
            "readiness_plan_sha256": run["readiness_plan_sha256"],
            "delivery_identity_sha256": campaign_plan.get(
                "delivery_identity_sha256"
            ),
            "worker_role": run["role"],
            "message_id": int(run["message_id"]),
            "attempt_id": attempt_id,
        }
        if any(receipt.get(key) != value for key, value in expected_receipt_binding.items()):
            raise BrokerError("BROKER_RECEIPT_BINDING_INVALID")
        expected_gates = {
            str(row["gate_key"])
            for row in connection.execute(
                """
                SELECT gate_key FROM portfolio_readiness_gates
                WHERE campaign_id=?
                """,
                (int(run["campaign_id"]),),
            )
        }
        if expected_gates != {
            str(result["gate_key"]) for result in receipt["gate_results"]
        }:
            raise BrokerError("BROKER_RECEIPT_GATE_COVERAGE_INVALID")
        _validate_attempt(
            connection,
            campaign,
            int(run["message_id"]),
            attempt_id,
            terminal=False,
        )
        connection.execute(
            """
            INSERT INTO role_executor_broker_receipt_pickups(
                attempt_id, campaign_id, message_id, receipt_sha256,
                receipt_json, observation_json, observed_at, staged_at, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'STAGED')
            """,
            (
                attempt_id,
                int(run["campaign_id"]),
                int(run["message_id"]),
                receipt_sha256,
                receipt_json,
                canonical_json(observation),
                receipt["observed_at"],
                now,
            ),
        )
        completed_message = connection.execute(
            """
            UPDATE coordination_messages
            SET state='COMPLETE', updated_at=?, last_error=NULL
            WHERE id=? AND state='CLAIMED' AND claimed_by=?
            """,
            (now, int(run["message_id"]), run["endpoint_id"]),
        )
        if completed_message.rowcount != 1:
            raise BrokerError("BROKER_MESSAGE_STATE_CONFLICT")
        store._event(
            "MESSAGE_COMPLETED",
            f"message:{int(run['message_id'])}",
            {"session_id": run["endpoint_id"], "broker_attempt_id": attempt_id},
            now,
        )
        _attempt_transition(
            connection,
            attempt,
            new_state="COMPLETE",
            now=now,
            reason=None,
            exit_code=0,
        )
        old_version = int(run["version"])
        new_version = old_version + 1
        completed = connection.execute(
            """
            UPDATE role_executor_broker_runs
            SET state='COMPLETE', receipt_sha256=?, version=?, updated_at=?,
                last_error=NULL
            WHERE attempt_id=? AND state='RUNNING' AND version=?
            """,
            (receipt_sha256, new_version, now, attempt_id, old_version),
        )
        if completed.rowcount != 1:
            raise BrokerError("BROKER_RUN_VERSION_CONFLICT")
        _broker_event(
            connection,
            attempt_id=attempt_id,
            from_state="RUNNING",
            to_state="COMPLETE",
            from_version=old_version,
            to_version=new_version,
            reason="BROKER_RECEIPT_STAGED",
            payload={
                "receipt_sha256": receipt_sha256,
                "pickup_state": "STAGED",
                "evaluator_inactivity": inactivity_payload,
            },
            now=now,
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return {
        "attempt_id": attempt_id,
        "state": "COMPLETE",
        "receipt_sha256": receipt_sha256,
        "pickup_state": "STAGED",
    }


def replay_broker_receipt(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    runtime: BrokerRuntimePaths | None = None,
    now: str,
    evaluator_inactivity: BrokerEvaluatorInactivity | None = None,
) -> dict[str, Any]:
    """Recover a crashed broker from the isolated output or exact staged pickup."""

    run = connection.execute(
        "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if run is None:
        raise BrokerError("BROKER_RUN_MISSING")
    if run["state"] == "COMPLETE":
        pickup = connection.execute(
            """
            SELECT receipt_sha256, receipt_json, observation_json
            FROM role_executor_broker_receipt_pickups WHERE attempt_id=?
            """,
            (attempt_id,),
        ).fetchone()
        if pickup is None:
            raise BrokerError("BROKER_PICKUP_MISSING")
        receipt = json.loads(str(pickup["receipt_json"]))
        return complete_broker_receipt(
            connection,
            attempt_id=attempt_id,
            receipt=receipt,
            receipt_json=str(pickup["receipt_json"]),
            observation=json.loads(str(pickup["observation_json"])),
            now=now,
            evaluator_inactivity=evaluator_inactivity,
        )
    runtime = runtime or default_runtime_paths()
    receipt_path = runtime.spool_root / attempt_id / "out" / "receipt.json"
    receipt, receipt_json, observation = read_receipt_file(receipt_path, observed_at=now)
    return complete_broker_receipt(
        connection,
        attempt_id=attempt_id,
        receipt=receipt,
        receipt_json=receipt_json,
        observation=observation,
        now=now,
        evaluator_inactivity=evaluator_inactivity,
    )


def _persist_pickup_disposition(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    error: str,
    now: str,
    verdict: str | None,
) -> dict[str, Any]:
    """Durably retire one poison pickup without blocking later supervisor work."""

    safe_error = _error_code(BrokerError(error), "BROKER_PICKUP_CONSUMPTION_FAILED")
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = connection.execute(
            "SELECT * FROM role_executor_broker_pickup_consumptions WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if existing is not None:
            outcome = _parse_canonical_json(
                str(existing["outcome_json"]),
                str(existing["outcome_sha256"]),
                "BROKER_CONSUMPTION_INVALID",
            )
            connection.execute("COMMIT")
            return outcome
        pickup = connection.execute(
            """
            SELECT pickup.*, run.repository, run.issue_number,
                   run.campaign_id AS run_campaign_id,
                   run.receipt_sha256 AS run_receipt_sha256
            FROM role_executor_broker_receipt_pickups pickup
            JOIN role_executor_broker_runs run ON run.attempt_id=pickup.attempt_id
            WHERE pickup.attempt_id=?
            """,
            (attempt_id,),
        ).fetchone()
        if pickup is None:
            raise BrokerError("BROKER_PICKUP_MISSING")
        current = connection.execute(
            """
            SELECT * FROM portfolio_readiness_current WHERE campaign_id=?
            """,
            (int(pickup["campaign_id"]),),
        ).fetchone()
        readiness_state = None if current is None else str(current["state"])
        disposition = "ERROR"
        reasons: list[str] = []
        if current is not None:
            try:
                campaign = _campaign(
                    connection,
                    str(pickup["repository"]),
                    int(pickup["issue_number"]),
                )
            except ReadinessError:
                campaign = None
            if campaign is not None and int(campaign["id"]) == int(
                pickup["campaign_id"]
            ):
                reasons = _binding_reasons(connection, campaign)
                if readiness_state == "RUNNING" and reasons:
                    _mark_stale(connection, campaign, reasons, now)
                    readiness_state = "STALE"
                if readiness_state == "STALE":
                    disposition = "STALE"
                    safe_error = (
                        "READINESS_BINDING_DRIFT:" + ",".join(reasons)
                        if reasons
                        else str(current["last_error"] or safe_error)
                    )
                elif readiness_state == "RUNNING":
                    updated = connection.execute(
                        """
                        UPDATE portfolio_readiness_current
                        SET state='HOLD', version=version+1, updated_at=?,
                            last_error=?
                        WHERE campaign_id=? AND state='RUNNING' AND version=?
                        """,
                        (
                            now,
                            safe_error,
                            int(campaign["id"]),
                            int(campaign["current_version"]),
                        ),
                    )
                    if updated.rowcount != 1:
                        raise BrokerError("BROKER_PICKUP_DISPOSITION_RACE")
                    readiness_event(
                        connection,
                        int(campaign["id"]),
                        "READINESS_BROKER_PICKUP_HELD",
                        {"attempt_id": attempt_id, "error": safe_error},
                        now,
                    )
                    readiness_state = "HOLD"
                    disposition = "HOLD"
                elif readiness_state == "HOLD":
                    disposition = "HOLD"
        outcome = {
            "schema": PICKUP_CONSUMPTION_SCHEMA,
            "attempt_id": attempt_id,
            "campaign_id": int(pickup["campaign_id"]),
            "receipt_sha256": str(pickup["receipt_sha256"]),
            "readiness_state": readiness_state,
            "verdict": verdict,
            "disposition": disposition,
            "error": safe_error,
        }
        outcome_json = canonical_json(outcome)
        outcome_sha256 = hashlib.sha256(outcome_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO role_executor_broker_pickup_consumptions(
                attempt_id, campaign_id, receipt_sha256, outcome_sha256,
                outcome_json, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                int(pickup["campaign_id"]),
                str(pickup["receipt_sha256"]),
                outcome_sha256,
                outcome_json,
                now,
            ),
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return outcome


def _stage_terminal_readiness_receipt(
    connection: sqlite3.Connection,
    receipt: dict[str, Any],
    *,
    now: str,
) -> int:
    """Bridge one terminal broker pickup into readiness's durable artifact lane."""

    _validate_receipt(receipt)
    store = _store_for_connection(connection)
    campaign = _campaign(
        connection, str(receipt["repository"]), int(receipt["issue_number"])
    )
    message_id = int(receipt["message_id"])
    attempt_id = str(receipt["attempt_id"])
    try:
        plan = json.loads(campaign["plan_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReadinessError("READINESS_PLAN_INVALID") from exc
    if (
        campaign["state"] != "RUNNING"
        or campaign["attempt_id"] != attempt_id
        or int(campaign["message_id"]) != message_id
        or receipt["readiness_plan_sha256"] != campaign["plan_sha256"]
        or receipt["delivery_identity_sha256"]
        != plan.get("delivery_identity_sha256")
        or receipt["worker_role"] != campaign["worker_role"]
    ):
        raise ReadinessError("READINESS_RECEIPT_ATTEMPT_DRIFT")
    if _binding_reasons(connection, campaign):
        raise ReadinessError("READINESS_RECEIPT_CAMPAIGN_DRIFT")
    _message, attempt = _validate_attempt(
        connection, campaign, message_id, attempt_id, terminal=True
    )
    token_sha256 = attempt["token_sha256"]
    if not isinstance(token_sha256, str) or SHA256.fullmatch(token_sha256) is None:
        raise ReadinessError("READINESS_RECEIPT_PICKUP_TOKEN_INVALID")
    pickup = connection.execute(
        "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
        (int(campaign["id"]),),
    ).fetchone()
    locator = _receipt_locator(campaign)
    if (
        pickup is None
        or pickup["state"] not in {"PENDING", "STAGED"}
        or pickup["attempt_id"] != attempt_id
        or int(pickup["message_id"]) != message_id
        or pickup["relative_path"] != locator["relative_path"]
        or pickup["locator_sha256"] != digest_json(locator)
    ):
        raise ReadinessError("READINESS_RECEIPT_PICKUP_BINDING_INVALID")

    canonical_bytes = canonical_json(receipt).encode("utf-8")
    root = _receipt_directory(store.path, create=True)
    path = Path(store.path).parent / str(pickup["relative_path"])
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError:
        artifact = _open_staged_artifact(store.path, str(pickup["relative_path"]))
        if artifact["raw"] != canonical_bytes:
            _close_artifact(artifact)
            raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CONFLICT")
    except OSError as exc:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_UNSAFE") from exc
    else:
        try:
            offset = 0
            while offset < len(canonical_bytes):
                offset += os.write(descriptor, canonical_bytes[offset:])
            os.fsync(descriptor)
        except Exception:
            os.close(descriptor)
            try:
                path.unlink()
            except OSError:
                pass
            raise
        else:
            os.close(descriptor)
        directory_descriptor = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        artifact = _open_staged_artifact(store.path, str(pickup["relative_path"]))

    try:
        if artifact["raw"] != canonical_bytes:
            raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CHANGED")
        _assert_artifact_current(artifact)
        with store.transaction():
            current_campaign = _campaign(
                connection,
                str(receipt["repository"]),
                int(receipt["issue_number"]),
            )
            if (
                int(current_campaign["id"]) != int(campaign["id"])
                or current_campaign["state"] != "RUNNING"
            ):
                raise ReadinessError("READINESS_RECEIPT_CAMPAIGN_DRIFT")
            _current_message, current_attempt = _validate_attempt(
                connection,
                current_campaign,
                message_id,
                attempt_id,
                terminal=True,
            )
            if not secrets.compare_digest(
                str(current_attempt["token_sha256"]), token_sha256
            ):
                raise ReadinessError("READINESS_RECEIPT_PICKUP_TOKEN_INVALID")
            current_pickup = connection.execute(
                "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
                (int(campaign["id"]),),
            ).fetchone()
            if current_pickup is None:
                raise ReadinessError("READINESS_RECEIPT_PICKUP_MISSING")
            if current_pickup["state"] == "STAGED":
                if (
                    current_pickup["attempt_token_sha256"] != token_sha256
                    or not _artifact_matches_pickup(current_pickup, artifact)
                ):
                    raise ReadinessError("READINESS_RECEIPT_PICKUP_REPLAY_INVALID")
            elif current_pickup["state"] == "PENDING":
                changed = connection.execute(
                    """
                    UPDATE portfolio_readiness_receipt_pickups
                    SET state='STAGED', attempt_token_sha256=?, artifact_sha256=?,
                        artifact_size_bytes=?, artifact_device_id=?, artifact_inode=?,
                        artifact_mode=?, artifact_uid=?, artifact_nlink=?,
                        artifact_mtime_ns=?, artifact_ctime_ns=?,
                        version=version+1, updated_at=?, last_error=NULL
                    WHERE campaign_id=? AND state='PENDING' AND version=?
                    """,
                    (
                        token_sha256,
                        artifact["artifact_sha256"],
                        artifact["size_bytes"],
                        artifact["device_id"],
                        artifact["inode"],
                        artifact["mode"],
                        artifact["uid"],
                        artifact["nlink"],
                        artifact["mtime_ns"],
                        artifact["ctime_ns"],
                        now,
                        int(campaign["id"]),
                        int(current_pickup["version"]),
                    ),
                ).rowcount
                if changed != 1:
                    raise ReadinessError("READINESS_RECEIPT_PICKUP_FENCE_LOST")
            else:
                raise ReadinessError("READINESS_RECEIPT_PICKUP_STATE_CONFLICT")
            _assert_artifact_current(artifact)
    finally:
        _close_artifact(artifact)
    return int(campaign["id"])


def _record_brokered_readiness_receipt(
    connection: sqlite3.Connection,
    receipt: dict[str, Any],
    *,
    now: str,
) -> dict[str, Any]:
    """Record or replay one broker receipt through current readiness semantics."""

    campaign = _campaign(
        connection, str(receipt["repository"]), int(receipt["issue_number"])
    )
    receipt_sha256 = digest_json(receipt)
    prior = connection.execute(
        """
        SELECT receipt.verdict, receipt.receipt_sha256, current.state
        FROM portfolio_readiness_current current
        JOIN portfolio_readiness_receipts receipt ON receipt.id=current.receipt_id
        WHERE current.campaign_id=?
        """,
        (int(campaign["id"]),),
    ).fetchone()
    if prior is not None:
        if prior["receipt_sha256"] != receipt_sha256:
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        return {
            "repository": receipt["repository"],
            "issue_number": receipt["issue_number"],
            "verdict": str(prior["verdict"]),
            "receipt_sha256": receipt_sha256,
            "state": str(prior["state"]),
            "replay": True,
        }
    campaign_id = _stage_terminal_readiness_receipt(
        connection, receipt, now=now
    )
    return pickup_readiness_receipt(
        _store_for_connection(connection), campaign_id, now=now
    )


def consume_broker_pickup(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    now: str,
) -> dict[str, Any]:
    """Record only the immutable SQLite pickup into readiness, idempotently."""

    ensure_broker_schema(connection)
    existing = connection.execute(
        "SELECT * FROM role_executor_broker_pickup_consumptions WHERE attempt_id=?",
        (attempt_id,),
    ).fetchone()
    if existing is not None:
        outcome = _parse_canonical_json(
            str(existing["outcome_json"]),
            str(existing["outcome_sha256"]),
            "BROKER_CONSUMPTION_INVALID",
        )
        return outcome
    pickup = connection.execute(
        """
        SELECT pickup.*, run.state AS run_state,
               run.receipt_sha256 AS run_receipt_sha256
        FROM role_executor_broker_receipt_pickups pickup
        JOIN role_executor_broker_runs run ON run.attempt_id=pickup.attempt_id
        WHERE pickup.attempt_id=?
        """,
        (attempt_id,),
    ).fetchone()
    if pickup is None:
        raise BrokerError("BROKER_PICKUP_MISSING")
    try:
        if (
            pickup["run_state"] != "COMPLETE"
            or pickup["state"] != "STAGED"
            or pickup["receipt_sha256"] != pickup["run_receipt_sha256"]
        ):
            raise BrokerError("BROKER_PICKUP_BINDING_INVALID")
        receipt = _parse_canonical_json(
            str(pickup["receipt_json"]),
            str(pickup["receipt_sha256"]),
            "BROKER_PICKUP_BINDING_INVALID",
        )
        if not isinstance(receipt, dict) or receipt.get("attempt_id") != attempt_id:
            raise BrokerError("BROKER_PICKUP_BINDING_INVALID")
    except BrokerError as exc:
        return _persist_pickup_disposition(
            connection,
            attempt_id=attempt_id,
            error=str(exc),
            now=now,
            verdict=None,
        )
    try:
        recorded = _record_brokered_readiness_receipt(
            connection, receipt, now=now
        )
    except (ReadinessError, OSError, sqlite3.Error) as exc:
        return _persist_pickup_disposition(
            connection,
            attempt_id=attempt_id,
            error=_error_code(exc, "BROKER_PICKUP_CONSUMPTION_FAILED"),
            now=now,
            verdict=str(receipt.get("verdict")),
        )
    if recorded.get("state") == "STALE" or recorded.get("verdict") is None:
        return _persist_pickup_disposition(
            connection,
            attempt_id=attempt_id,
            error="READINESS_BINDING_DRIFT",
            now=now,
            verdict=str(receipt.get("verdict")),
        )
    outcome = {
        "schema": PICKUP_CONSUMPTION_SCHEMA,
        "attempt_id": attempt_id,
        "campaign_id": int(pickup["campaign_id"]),
        "receipt_sha256": str(pickup["receipt_sha256"]),
        "readiness_state": str(recorded["state"]),
        "verdict": str(recorded["verdict"]),
    }
    outcome_json = canonical_json(outcome)
    outcome_sha256 = hashlib.sha256(outcome_json.encode("utf-8")).hexdigest()
    connection.execute("BEGIN IMMEDIATE")
    try:
        current_pickup = connection.execute(
            """
            SELECT pickup.receipt_sha256, run.state AS run_state
            FROM role_executor_broker_receipt_pickups pickup
            JOIN role_executor_broker_runs run ON run.attempt_id=pickup.attempt_id
            WHERE pickup.attempt_id=?
            """,
            (attempt_id,),
        ).fetchone()
        if (
            current_pickup is None
            or current_pickup["run_state"] != "COMPLETE"
            or current_pickup["receipt_sha256"] != pickup["receipt_sha256"]
        ):
            raise BrokerError("BROKER_PICKUP_BINDING_INVALID")
        connection.execute(
            """
            INSERT OR IGNORE INTO role_executor_broker_pickup_consumptions(
                attempt_id, campaign_id, receipt_sha256, outcome_sha256,
                outcome_json, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                int(pickup["campaign_id"]),
                str(pickup["receipt_sha256"]),
                outcome_sha256,
                outcome_json,
                now,
            ),
        )
        stored = connection.execute(
            "SELECT * FROM role_executor_broker_pickup_consumptions WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if (
            stored is None
            or stored["receipt_sha256"] != pickup["receipt_sha256"]
            or stored["outcome_sha256"] != outcome_sha256
            or stored["outcome_json"] != outcome_json
        ):
            raise BrokerError("BROKER_CONSUMPTION_CONFLICT")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return outcome


def consume_staged_broker_pickups(
    connection: sqlite3.Connection, *, now: str
) -> list[dict[str, Any]]:
    """Consume all canonical staged pickups; caller bytes are never accepted."""

    ensure_broker_schema(connection)
    attempt_ids = [
        str(row["attempt_id"])
        for row in connection.execute(
            """
            SELECT pickup.attempt_id
            FROM role_executor_broker_receipt_pickups pickup
            LEFT JOIN role_executor_broker_pickup_consumptions consumed
              ON consumed.attempt_id=pickup.attempt_id
            WHERE pickup.state='STAGED' AND consumed.attempt_id IS NULL
            ORDER BY pickup.id
            """
        )
    ]
    results: list[dict[str, Any]] = []
    for attempt_id in attempt_ids:
        try:
            results.append(
                consume_broker_pickup(
                    connection, attempt_id=attempt_id, now=now
                )
            )
        except BrokerError as exc:
            # One malformed pickup cannot serialize later pickups or ordinary
            # supervisor work. Known binding/readiness failures are durably
            # consumed above; this reports only a storage-level residual.
            results.append(
                {
                    "schema": PICKUP_CONSUMPTION_SCHEMA,
                    "attempt_id": attempt_id,
                    "disposition": "ERROR",
                    "error": _error_code(
                        exc, "BROKER_PICKUP_CONSUMPTION_FAILED"
                    ),
                }
            )
    return results


def _observed_process_exit(
    process: subprocess.Popen[Any], *, timeout: float | None
) -> int | None:
    try:
        if timeout is None:
            value = process.poll()
        else:
            value = process.wait(timeout=timeout)
    except (OSError, subprocess.SubprocessError, AttributeError):
        return None
    if type(value) is int:
        return value
    return None


def _terminate_child(
    process: subprocess.Popen[Any],
) -> BrokerEvaluatorInactivity:
    """Stop one child and return only after positive process-exit observation."""

    process_id = int(process.pid)
    observed = _observed_process_exit(process, timeout=None)
    if observed is not None:
        return _process_exit_inactivity(process_id, observed)
    try:
        process.terminate()
    except (OSError, subprocess.SubprocessError, AttributeError):
        pass
    observed = _observed_process_exit(
        process, timeout=BROKER_TERMINATION_GRACE_SECONDS
    )
    if observed is not None:
        return _process_exit_inactivity(process_id, observed)
    try:
        process.kill()
    except (OSError, subprocess.SubprocessError, AttributeError):
        pass
    observed = _observed_process_exit(
        process, timeout=BROKER_TERMINATION_GRACE_SECONDS
    )
    if observed is None:
        observed = _observed_process_exit(process, timeout=None)
    if observed is None:
        raise BrokerError("BROKER_CHILD_TERMINATION_UNCONFIRMED")
    return _process_exit_inactivity(process_id, observed)


def _apply_child_resource_limits() -> None:
    """Install non-expandable kernel limits before setpriv/bwrap executes."""

    resource.setrlimit(resource.RLIMIT_FSIZE, (RESULT_MAX_BYTES, RESULT_MAX_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (BROKER_CPU_SECONDS, BROKER_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_NOFILE, (BROKER_NOFILE_LIMIT, BROKER_NOFILE_LIMIT))


def _error_code(exc: BaseException, fallback: str) -> str:
    value = str(exc)
    if (
        value
        and len(value) <= 256
        and value.startswith(("BROKER_", "READINESS_"))
        and all(character.isalnum() or character in "_:,-" for character in value)
    ):
        return value
    return fallback


def broker_terminal_readback(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
) -> dict[str, Any]:
    """Read exact terminal/active row truth; never infer it from control flow."""

    attempt = connection.execute(
        "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if attempt is None:
        raise BrokerError("BROKER_ATTEMPT_MISSING")
    run = connection.execute(
        "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    message = None
    readiness = None
    if run is not None:
        message = connection.execute(
            "SELECT state, claimed_by FROM coordination_messages WHERE id=?",
            (int(run["message_id"]),),
        ).fetchone()
        readiness = connection.execute(
            """
            SELECT state, attempt_id FROM portfolio_readiness_current
            WHERE campaign_id=?
            """,
            (int(run["campaign_id"]),),
        ).fetchone()
    elif attempt["target_kind"] == "message":
        try:
            message_id = int(attempt["target_key"])
        except (TypeError, ValueError):
            message_id = -1
        message = connection.execute(
            "SELECT state, claimed_by FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
    return {
        "state": str(attempt["state"]),
        "broker_state": None if run is None else str(run["state"]),
        "message_state": None if message is None else str(message["state"]),
        "message_claimed_by": None if message is None else message["claimed_by"],
        "readiness_state": None if readiness is None else str(readiness["state"]),
        "readiness_attempt_id": (
            None if readiness is None else readiness["attempt_id"]
        ),
    }


def _inactive_systemd_evidence(
    attempt: sqlite3.Row,
    evidence_reader: Callable[[str], SystemdUnitEvidence],
) -> tuple[SystemdUnitEvidence | None, str | None]:
    unit = str(attempt["systemd_unit"] or "")
    invocation_id = str(attempt["systemd_invocation_id"] or "")
    control_group = str(attempt["systemd_control_group"] or "")
    expected_unit = stable_systemd_unit(
        str(attempt["role"]), str(attempt["target_kind"]), str(attempt["target_key"])
    )
    if (
        unit != expected_unit
        or SYSTEMD_INVOCATION_ID.fullmatch(invocation_id) is None
        or not control_group.startswith("/")
        or not control_group.endswith(f"/{unit}")
    ):
        return None, "BROKER_RECOVERY_STORED_IDENTITY_INVALID"
    try:
        evidence = evidence_reader(unit)
    except (OSError, subprocess.SubprocessError, RegistryError):
        return None, "BROKER_RECOVERY_SYSTEMD_EVIDENCE_FAILED"
    if (
        evidence.unit != unit
        or evidence.invocation_id != invocation_id
        or evidence.control_group != control_group
    ):
        return None, "BROKER_RECOVERY_SYSTEMD_IDENTITY_MISMATCH"
    try:
        _validate_inactive_systemd_snapshot(attempt, evidence)
    except BrokerError:
        return None, "BROKER_RECOVERY_SYSTEMD_NOT_PROVEN_INACTIVE"
    return evidence, None


def recover_stale_broker_runs(
    connection: sqlite3.Connection,
    *,
    before: str,
    now: str,
    runtime: BrokerRuntimePaths | None = None,
    evidence_reader: Callable[[str], SystemdUnitEvidence] = probe_systemd_unit,
) -> list[dict[str, Any]]:
    """Recover active broker rows without letting generic recovery split truth."""

    ensure_broker_schema(connection)
    candidates = connection.execute(
        """
        SELECT run.attempt_id, run.state AS broker_state, run.updated_at AS broker_updated,
               attempt.*
        FROM role_executor_broker_runs run
        JOIN executor_attempts attempt ON attempt.attempt_id=run.attempt_id
        WHERE run.state IN ('PREPARING','LAUNCHING','RUNNING')
          AND attempt.heartbeat_at<?
        ORDER BY run.created_at
        """,
        (before,),
    ).fetchall()
    results: list[dict[str, Any]] = []
    for candidate in candidates:
        attempt_id = str(candidate["attempt_id"])
        broker_state = str(candidate["broker_state"])
        evaluator_inactivity = _not_started_inactivity()
        if broker_state != "PREPARING":
            evidence, evidence_error = _inactive_systemd_evidence(
                candidate, evidence_reader
            )
            if evidence_error is not None:
                results.append(
                    {
                        "attempt_id": attempt_id,
                        "phase": "HOLD",
                        "error": evidence_error,
                        **broker_terminal_readback(connection, attempt_id=attempt_id),
                    }
                )
                continue
            if evidence is None:
                raise BrokerError("BROKER_RECOVERY_SYSTEMD_EVIDENCE_FAILED")
            evaluator_inactivity = _systemd_inactivity(evidence)
        if broker_state == "RUNNING":
            try:
                replayed = replay_broker_receipt(
                    connection,
                    attempt_id=attempt_id,
                    runtime=runtime,
                    now=now,
                    evaluator_inactivity=evaluator_inactivity,
                )
                consumed = consume_broker_pickup(
                    connection, attempt_id=attempt_id, now=now
                )
                results.append(
                    {
                        "attempt_id": attempt_id,
                        "phase": "RECOVERED",
                        "receipt_sha256": replayed["receipt_sha256"],
                        "readiness_state": consumed["readiness_state"],
                        **broker_terminal_readback(connection, attempt_id=attempt_id),
                    }
                )
                continue
            except BrokerError as exc:
                recovery_error = _error_code(
                    exc, "BROKER_RECOVERY_RECEIPT_UNAVAILABLE"
                )
        else:
            recovery_error = "BROKER_RECOVERED_STALE_PRECLAIM"
        try:
            hold_broker_run(
                connection,
                attempt_id=attempt_id,
                error=recovery_error,
                now=now,
                exit_code=None,
                evaluator_inactivity=evaluator_inactivity,
            )
            readback = broker_terminal_readback(connection, attempt_id=attempt_id)
            results.append(
                {
                    "attempt_id": attempt_id,
                    "phase": "RECOVERED",
                    "error": recovery_error,
                    **readback,
                }
            )
        except BrokerError as exc:
            readback = broker_terminal_readback(connection, attempt_id=attempt_id)
            if readback["state"] in {"COMPLETE", "HOLD", "LAUNCH_FAILED"}:
                results.append(
                    {
                        "attempt_id": attempt_id,
                        "phase": "OBSERVED_TERMINAL",
                        "error": _error_code(exc, "BROKER_RECOVERY_RACE"),
                        **readback,
                    }
                )
            else:
                results.append(
                    {
                        "attempt_id": attempt_id,
                        "phase": "HOLD",
                        "error": "BROKER_RECOVERY_TERMINALIZATION_FAILED",
                        "terminalization_error": _error_code(
                            exc, "BROKER_RECOVERY_TERMINALIZATION_FAILED"
                        ),
                        **readback,
                    }
                )
    return results


def execute_brokered_readiness(
    connection: sqlite3.Connection,
    *,
    configured: EndpointConfig,
    profile_path: Path,
    target_kind: str,
    target_key: str,
    systemd_evidence: SystemdUnitEvidence,
    target_precondition: Callable[[sqlite3.Connection], Any],
    runtime: BrokerRuntimePaths | None = None,
    popen: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
    heartbeat_seconds: int = 30,
) -> dict[str, Any]:
    """Run one readiness child while retaining every authority in the broker."""

    if configured.execution_protocol != BROKER_PROTOCOL:
        raise BrokerError("BROKER_PROTOCOL_INVALID")
    if heartbeat_seconds <= 0:
        raise BrokerError("BROKER_HEARTBEAT_INVALID")
    attest_broker_systemd_limits(systemd_evidence)
    # Prove this is the implemented readiness RPC before consuming an attempt.
    try:
        _build_input_projection(
            connection,
            role=configured.role,
            endpoint_id=configured.endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
        )
    except BrokerError:
        raise
    except Exception as exc:
        raise BrokerError("BROKER_INPUT_PROJECTION_INVALID") from exc
    # Codex currently needs model credentials, but mounting auth.json would
    # expose the same credential to every tool child in the sandbox.  A later
    # exact attempt-bound local Responses proxy may satisfy the contract with
    # requires_openai_auth=false.  Until then, never reserve or claim work.
    raise BrokerError("BROKER_CREDENTIAL_TRANSPORT_NOT_IMPLEMENTED")


def _execute_brokered_readiness_mechanics(
    connection: sqlite3.Connection,
    *,
    configured: EndpointConfig,
    profile_path: Path,
    target_kind: str,
    target_key: str,
    systemd_evidence: SystemdUnitEvidence,
    target_precondition: Callable[[sqlite3.Connection], Any],
    runtime: BrokerRuntimePaths,
    popen: Callable[..., subprocess.Popen[Any]],
    heartbeat_seconds: int,
    evidence_reader: Callable[[str], SystemdUnitEvidence] = probe_systemd_unit,
) -> dict[str, Any]:
    """Latent owner mechanics; production dispatch is fenced by preflight."""

    def reservation_precondition(candidate: sqlite3.Connection) -> Any:
        _build_input_projection(
            candidate,
            role=configured.role,
            endpoint_id=configured.endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
        )
        return target_precondition(candidate)

    attest_broker_systemd_limits(systemd_evidence)
    reserved, token = reserve_attempt(
        connection,
        role=configured.role,
        endpoint_id=configured.endpoint_id,
        target_kind=target_kind,
        target_key=target_key,
        now=utc_now(),
        precondition=reservation_precondition,
    )
    attempt_id = str(reserved["attempt_id"])
    process: subprocess.Popen[Any] | None = None
    gate_read = -1
    gate_write = -1
    run_created = False
    evaluator_inactivity: BrokerEvaluatorInactivity | None = None
    try:
        run = prepare_broker_run(
            connection,
            configured=configured,
            attempt_id=attempt_id,
            profile_path=profile_path,
            now=utc_now(),
        )
        run_created = True
        spool = prepare_spool(runtime, run)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        command = build_bwrap_command(
            configured=configured,
            runtime=runtime,
            spool=spool,
            start_gate_fd=gate_read,
        )
        command_attestation = attest_bwrap_command(command)
        mark_broker_launching(
            connection,
            attempt_id=attempt_id,
            token=token,
            evidence=systemd_evidence,
            command_attestation=command_attestation,
            now=utc_now(),
        )
        process = popen(
            command,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            pass_fds=(gate_read,),
            preexec_fn=_apply_child_resource_limits,
        )
        os.close(gate_read)
        gate_read = -1
        claim_attach_and_start(
            connection,
            attempt_id=attempt_id,
            token=token,
            process_id=int(process.pid),
            now=utc_now(),
        )
        os.write(gate_write, b"1")
        os.close(gate_write)
        gate_write = -1
        deadline = time.monotonic() + BROKER_WALL_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrokerError("BROKER_CHILD_DEADLINE_EXCEEDED")
            try:
                exit_code = process.wait(
                    timeout=min(float(heartbeat_seconds), remaining)
                )
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    raise BrokerError("BROKER_CHILD_DEADLINE_EXCEEDED")
            else:
                evaluator_inactivity = _process_exit_inactivity(
                    int(process.pid), int(exit_code)
                )
                break
            heartbeat_broker_run(
                connection,
                attempt_id=attempt_id,
                token=token,
                process_id=int(process.pid),
                now=utc_now(),
            )
        if int(exit_code) != 0:
            error = "BROKER_CHILD_FAILED"
            hold_broker_run(
                connection,
                attempt_id=attempt_id,
                error=error,
                now=utc_now(),
                exit_code=int(exit_code),
                evaluator_inactivity=evaluator_inactivity,
            )
            return {
                "phase": "HOLD",
                "attempt_id": attempt_id,
                "error": error,
                **broker_terminal_readback(connection, attempt_id=attempt_id),
            }
        receipt, receipt_json, observation = read_receipt_file(
            spool.receipt_path, observed_at=utc_now()
        )
        completed = complete_broker_receipt(
            connection,
            attempt_id=attempt_id,
            receipt=receipt,
            receipt_json=receipt_json,
            observation=observation,
            now=utc_now(),
            evaluator_inactivity=evaluator_inactivity,
        )
        consumed = consume_broker_pickup(
            connection, attempt_id=attempt_id, now=utc_now()
        )
        return {
            "phase": "PASS",
            "attempt_id": attempt_id,
            "instance_id": reserved["instance_id"],
            "role": configured.role,
            "endpoint_id": configured.endpoint_id,
            "target_kind": target_kind,
            "target_key": target_key,
            "state": "COMPLETE",
            "exit_code": 0,
            "receipt_sha256": completed["receipt_sha256"],
            "pickup_state": "STAGED",
            "readiness_state": consumed["readiness_state"],
            "token_persisted": False,
        }
    except Exception as exc:
        error = _error_code(exc, "BROKER_BOUNDARY_FAILED")
        if process is not None:
            try:
                evaluator_inactivity = _terminate_child(process)
            except BrokerError:
                attempt = connection.execute(
                    "SELECT * FROM executor_attempts WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()
                evidence = None
                evidence_error = "BROKER_CHILD_TERMINATION_UNCONFIRMED"
                if attempt is not None and attempt["systemd_unit"] is not None:
                    evidence, evidence_error = _inactive_systemd_evidence(
                        attempt, evidence_reader
                    )
                if evidence is not None and evidence_error is None:
                    evaluator_inactivity = _systemd_inactivity(evidence)
                else:
                    readback = broker_terminal_readback(
                        connection, attempt_id=attempt_id
                    )
                    return {
                        "phase": "RECOVERY_REQUIRED",
                        "attempt_id": attempt_id,
                        "error": "BROKER_CHILD_TERMINATION_UNCONFIRMED",
                        "boundary_error": error,
                        "cleanup_error": evidence_error,
                        **readback,
                    }
        elif run_created:
            evaluator_inactivity = _not_started_inactivity()
        cleanup_error: str | None = None
        try:
            if run_created:
                hold_broker_run(
                    connection,
                    attempt_id=attempt_id,
                    error=error,
                    now=utc_now(),
                    exit_code=None,
                    evaluator_inactivity=evaluator_inactivity,
                )
            else:
                transition_attempt(
                    connection,
                    attempt_id=attempt_id,
                    token=token,
                    expected_version=int(reserved["version"]),
                    new_state="LAUNCH_FAILED",
                    now=utc_now(),
                    last_error=error,
                )
        except Exception as cleanup_exc:
            cleanup_error = _error_code(cleanup_exc, "BROKER_CLEANUP_FAILED")
        readback = broker_terminal_readback(connection, attempt_id=attempt_id)
        return {
            "phase": "HOLD",
            "attempt_id": attempt_id,
            "error": error if cleanup_error is None else "BROKER_CLEANUP_FAILED",
            "boundary_error": error,
            "cleanup_error": cleanup_error,
            **readback,
        }
    finally:
        for descriptor in (gate_read, gate_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
