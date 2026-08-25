#!/usr/bin/env python3
"""One candidate-level PREPARED-to-READY Kanban phase."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from coordination_store import CoordinationStore, canonical_json, digest_json
from executor_registry import current_endpoint, identity_role
from portfolio_graph import PortfolioGraphError, evaluate_graph


PLAN_SCHEMA = "twinfinity-kanban-readiness-phase/v1"
RECEIPT_SCHEMA = "twinfinity-kanban-readiness-receipt/v1"
WORKER_ROLES = {"development", "sre"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
GATE_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ReadinessError(ValueError):
    """Typed fail-closed Kanban readiness error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadinessError("READINESS_DUPLICATE_KEY")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadinessError("READINESS_ARTIFACT_INVALID") from exc
    if not isinstance(value, dict):
        raise ReadinessError("READINESS_ARTIFACT_INVALID")
    return value


def ensure_schema(connection: sqlite3.Connection) -> None:
    """Install an append-only phase ledger and one mutable current pointer."""

    try:
        connection.executescript(
            """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS portfolio_readiness_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                item_version INTEGER NOT NULL CHECK(item_version > 0),
                source_payload_sha256 TEXT NOT NULL,
                accepted_main_sha TEXT NOT NULL,
                graph_version INTEGER NOT NULL CHECK(graph_version > 0),
                capacity_policy_version INTEGER NOT NULL CHECK(capacity_policy_version > 0),
                candidate_sha256 TEXT NOT NULL,
                worker_role TEXT NOT NULL CHECK(worker_role IN ('development','sre')),
                phase_summary TEXT NOT NULL,
                plan_sha256 TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS portfolio_readiness_gates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                gate_key TEXT NOT NULL,
                description TEXT NOT NULL,
                requested_evidence_json TEXT NOT NULL,
                gate_sha256 TEXT NOT NULL,
                UNIQUE(campaign_id, gate_key),
                UNIQUE(campaign_id, gate_sha256),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id)
            );
            CREATE TABLE IF NOT EXISTS portfolio_readiness_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                verdict TEXT NOT NULL CHECK(verdict IN (
                    'PASS','ACTIONABLE_HOLD','APPROVAL_REQUIRED','TERMINAL_HOLD'
                )),
                worker_role TEXT NOT NULL CHECK(worker_role IN ('development','sre')),
                message_id INTEGER NOT NULL,
                attempt_id TEXT NOT NULL,
                resolution_role TEXT,
                receipt_sha256 TEXT NOT NULL UNIQUE,
                receipt_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id)
            );
            CREATE TABLE IF NOT EXISTS portfolio_readiness_current (
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                campaign_id INTEGER NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN (
                    'PENDING','RUNNING','RESOLUTION_PENDING','APPROVAL_PENDING',
                    'READY_ELIGIBLE','HOLD','STALE'
                )),
                message_id INTEGER,
                attempt_id TEXT,
                endpoint_id TEXT,
                receipt_id INTEGER,
                resolution_cycles INTEGER NOT NULL DEFAULT 0 CHECK(resolution_cycles >= 0),
                version INTEGER NOT NULL CHECK(version > 0),
                updated_at TEXT NOT NULL,
                last_error TEXT,
                PRIMARY KEY(repository, issue_number),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id),
                FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id)
            );
            CREATE TABLE IF NOT EXISTS portfolio_readiness_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id)
            );
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_campaigns_immutable_update
            BEFORE UPDATE ON portfolio_readiness_campaigns
            BEGIN SELECT RAISE(ABORT, 'READINESS_CAMPAIGN_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_campaigns_immutable_delete
            BEFORE DELETE ON portfolio_readiness_campaigns
            BEGIN SELECT RAISE(ABORT, 'READINESS_CAMPAIGN_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_gates_immutable_update
            BEFORE UPDATE ON portfolio_readiness_gates
            BEGIN SELECT RAISE(ABORT, 'READINESS_GATE_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_gates_immutable_delete
            BEFORE DELETE ON portfolio_readiness_gates
            BEGIN SELECT RAISE(ABORT, 'READINESS_GATE_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_receipts_immutable_update
            BEFORE UPDATE ON portfolio_readiness_receipts
            BEGIN SELECT RAISE(ABORT, 'READINESS_RECEIPT_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_receipts_immutable_delete
            BEFORE DELETE ON portfolio_readiness_receipts
            BEGIN SELECT RAISE(ABORT, 'READINESS_RECEIPT_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_events_immutable_update
            BEFORE UPDATE ON portfolio_readiness_events
            BEGIN SELECT RAISE(ABORT, 'READINESS_EVENT_IMMUTABLE'); END;
            CREATE TRIGGER IF NOT EXISTS portfolio_readiness_events_immutable_delete
            BEFORE DELETE ON portfolio_readiness_events
            BEGIN SELECT RAISE(ABORT, 'READINESS_EVENT_IMMUTABLE'); END;
            COMMIT;
            """
        )
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _require_pull_buffer_schema(connection: sqlite3.Connection) -> None:
    required = {"portfolio_pull_buffer_candidates", "portfolio_pull_buffer_current"}
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'portfolio_pull_buffer_%'"
        )
    }
    if not required.issubset(present):
        raise ReadinessError("PULL_BUFFER_SCHEMA_MISSING")


def _event(
    connection: sqlite3.Connection,
    campaign_id: int,
    event_type: str,
    payload: dict[str, Any],
    now: str,
) -> None:
    connection.execute(
        """
        INSERT INTO portfolio_readiness_events(
            campaign_id, event_type, payload_sha256, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (campaign_id, event_type, digest_json(payload), canonical_json(payload), now),
    )


def _validate_plan(plan: dict[str, Any]) -> None:
    expected = {
        "schema", "repository", "issue_number", "generation", "item_version",
        "source_payload_sha256", "accepted_main_sha", "graph_version",
        "capacity_policy_version", "candidate_sha256", "worker_role",
        "phase_summary", "gates",
    }
    if set(plan) != expected or plan.get("schema") != PLAN_SCHEMA:
        raise ReadinessError("READINESS_PLAN_INVALID")
    if not isinstance(plan.get("repository"), str) or not REPOSITORY.fullmatch(plan["repository"]):
        raise ReadinessError("READINESS_PLAN_INVALID")
    for field in ("issue_number", "item_version", "graph_version", "capacity_policy_version"):
        if type(plan.get(field)) is not int or int(plan[field]) <= 0:
            raise ReadinessError("READINESS_PLAN_INVALID")
    if type(plan.get("generation")) is not int or int(plan["generation"]) < 0:
        raise ReadinessError("READINESS_PLAN_INVALID")
    for field in ("source_payload_sha256", "candidate_sha256"):
        if not isinstance(plan.get(field), str) or not SHA256.fullmatch(plan[field]):
            raise ReadinessError("READINESS_PLAN_INVALID")
    if not isinstance(plan.get("accepted_main_sha"), str) or not GIT_SHA.fullmatch(plan["accepted_main_sha"]):
        raise ReadinessError("READINESS_PLAN_INVALID")
    if plan.get("worker_role") not in WORKER_ROLES:
        raise ReadinessError("READINESS_WORKER_ROLE_INVALID")
    if not isinstance(plan.get("phase_summary"), str) or not plan["phase_summary"].strip():
        raise ReadinessError("READINESS_PLAN_INVALID")
    gates = plan.get("gates")
    if not isinstance(gates, list) or not gates:
        raise ReadinessError("READINESS_GATES_REQUIRED")
    seen: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) != {
            "gate_key", "description", "requested_evidence"
        }:
            raise ReadinessError("READINESS_GATE_INVALID")
        key = gate.get("gate_key")
        if not isinstance(key, str) or not GATE_KEY.fullmatch(key) or key in seen:
            raise ReadinessError("READINESS_GATE_INVALID")
        seen.add(key)
        if not isinstance(gate.get("description"), str) or not gate["description"].strip():
            raise ReadinessError("READINESS_GATE_INVALID")
        evidence = gate.get("requested_evidence")
        if not isinstance(evidence, list) or not evidence or any(
            not isinstance(value, str) or not value.strip() for value in evidence
        ):
            raise ReadinessError("READINESS_GATE_INVALID")


def _campaign(
    connection: sqlite3.Connection, repository: str, issue_number: int
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT campaign.*, current.state, current.message_id, current.attempt_id,
               current.endpoint_id, current.receipt_id, current.resolution_cycles,
               current.version AS current_version, current.updated_at,
               current.last_error
        FROM portfolio_readiness_current current
        JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
        WHERE current.repository=? AND current.issue_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if row is None:
        raise ReadinessError("READINESS_CAMPAIGN_NOT_FOUND")
    return row


def _binding_reasons(connection: sqlite3.Connection, campaign: Any) -> list[str]:
    repository = str(campaign["repository"])
    issue_number = int(campaign["issue_number"])
    reasons: list[str] = []
    graph = connection.execute(
        "SELECT * FROM portfolio_graph_current WHERE repository=?", (repository,)
    ).fetchone()
    if graph is None or graph["health"] != "CURRENT":
        reasons.append("GRAPH_STALE")
    else:
        if int(graph["version"]) != int(campaign["graph_version"]):
            reasons.append("GRAPH_VERSION_DRIFT")
        if graph["observed_main_sha"] != campaign["accepted_main_sha"]:
            reasons.append("MAIN_DRIFT")
    policy = connection.execute(
        "SELECT version FROM coordination_capacity_current WHERE repository=?", (repository,)
    ).fetchone()
    if policy is None or int(policy["version"]) != int(campaign["capacity_policy_version"]):
        reasons.append("CAPACITY_POLICY_DRIFT")
    item = connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (repository, issue_number),
    ).fetchone()
    if item is None:
        reasons.append("ITEM_MISSING")
    else:
        if int(item["generation"]) != int(campaign["generation"]):
            reasons.append("ITEM_GENERATION_DRIFT")
        if int(item["version"]) != int(campaign["item_version"]):
            reasons.append("ITEM_VERSION_DRIFT")
        if item["source_payload_sha256"] != campaign["source_payload_sha256"]:
            reasons.append("ITEM_SOURCE_DRIFT")
        if item["status"] != "PREPARED" or item["allocation_class"] != "NONE":
            reasons.append("ITEM_NOT_ZERO_WIP_PREPARED")
    source = connection.execute(
        """
        SELECT payload_sha256 FROM github_current
        WHERE repository=? AND object_kind='issue' AND object_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if source is None or source["payload_sha256"] != campaign["source_payload_sha256"]:
        reasons.append("SOURCE_SNAPSHOT_DRIFT")
    candidate = connection.execute(
        """
        SELECT candidate.* FROM portfolio_pull_buffer_current pointer
        JOIN portfolio_pull_buffer_candidates candidate ON candidate.id=pointer.candidate_id
        WHERE pointer.repository=? AND pointer.issue_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if candidate is None:
        reasons.append("PULL_BUFFER_CANDIDATE_MISSING")
    else:
        if candidate["candidate_sha256"] != campaign["candidate_sha256"]:
            reasons.append("PULL_BUFFER_CANDIDATE_DRIFT")
        if candidate["state"] != "PREPARED_NOT_READY":
            reasons.append("PULL_BUFFER_CANDIDATE_STATE_DRIFT")
    if graph is not None and graph["health"] == "CURRENT":
        try:
            evaluation = evaluate_graph(
                connection,
                repository,
                current_main=str(graph["observed_main_sha"]),
                _ensure_schema=False,
            )
        except PortfolioGraphError:
            reasons.append("GRAPH_EVALUATION_FAILED")
        else:
            projection = next(
                (node for node in evaluation["nodes"] if int(node["issue_number"]) == issue_number),
                None,
            )
            if projection is None or not projection["structurally_ready"]:
                reasons.append("DEPENDENCY_NOT_READY")
    endpoint_id = campaign.get("endpoint_id") if isinstance(campaign, dict) else campaign["endpoint_id"]
    if endpoint_id is not None:
        endpoint = current_endpoint(connection, str(campaign["worker_role"]))
        if endpoint is None or endpoint["endpoint_id"] != endpoint_id:
            reasons.append("ENDPOINT_DRIFT")
    return sorted(set(reasons))


def discover(
    connection: sqlite3.Connection, repository: str, *, limit: int
) -> dict[str, Any]:
    """Rank zero-WIP DAG-ready candidates; parallelism is across candidates."""

    if limit <= 0:
        raise ReadinessError("READINESS_LIMIT_INVALID")
    ensure_schema(connection)
    _require_pull_buffer_schema(connection)
    graph = connection.execute(
        "SELECT * FROM portfolio_graph_current WHERE repository=?", (repository,)
    ).fetchone()
    if graph is None or graph["health"] != "CURRENT":
        raise ReadinessError("GRAPH_STALE")
    evaluation = evaluate_graph(
        connection,
        repository,
        current_main=str(graph["observed_main_sha"]),
        _ensure_schema=False,
    )
    nodes = {
        row["node_key"]: row
        for row in connection.execute(
            "SELECT * FROM portfolio_graph_nodes WHERE repository=? AND graph_version=?",
            (repository, int(graph["version"])),
        )
    }
    collisions = {
        frozenset((row["left_node_key"], row["right_node_key"]))
        for row in connection.execute(
            """
            SELECT * FROM portfolio_graph_relations
            WHERE repository=? AND graph_version=? AND relation_kind='COLLISION'
            """,
            (repository, int(graph["version"])),
        )
    }
    occupied = {
        row["node_key"]
        for row in connection.execute(
            """
            SELECT node.node_key FROM portfolio_graph_nodes node
            JOIN coordination_items item
              ON item.repository=node.repository AND item.issue_number=node.issue_number
            WHERE node.repository=? AND node.graph_version=?
              AND item.allocation_class IN ('ACTIVE','RETAINED')
            """,
            (repository, int(graph["version"])),
        )
    }
    projections = {
        item["node_key"]: item
        for item in evaluation["nodes"]
        if item["structurally_ready"] and item["item_status"] == "PREPARED"
    }
    ordered = sorted(
        projections,
        key=lambda key: (
            int(nodes[key]["priority_rank"]),
            str(nodes[key]["ready_at"]),
            int(nodes[key]["lane_order"]),
            -int(projections[key]["critical_path_units"]),
            -int(projections[key]["immediate_unlocks"]),
            -int(projections[key]["descendant_count"]),
            key,
        ),
    )
    selected: list[dict[str, Any]] = []
    selected_keys: set[str] = set()
    skipped: list[dict[str, Any]] = []
    for key in ordered:
        node = nodes[key]
        candidate = connection.execute(
            """
            SELECT candidate.* FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates candidate ON candidate.id=pointer.candidate_id
            WHERE pointer.repository=? AND pointer.issue_number=?
            """,
            (repository, int(node["issue_number"])),
        ).fetchone()
        reason = None
        if candidate is None or candidate["state"] != "PREPARED_NOT_READY":
            reason = "PREPARED_CANDIDATE_MISSING"
        elif any(frozenset((key, other)) in collisions for other in occupied | selected_keys):
            reason = "COLLISION"
        if reason is not None:
            skipped.append({"node_key": key, "reason": reason})
            continue
        current = connection.execute(
            """
            SELECT campaign.plan_sha256, pointer.state
            FROM portfolio_readiness_current pointer
            JOIN portfolio_readiness_campaigns campaign ON campaign.id=pointer.campaign_id
            WHERE pointer.repository=? AND pointer.issue_number=?
            """,
            (repository, int(node["issue_number"])),
        ).fetchone()
        selected.append(
            {
                "node_key": key,
                "issue_number": int(node["issue_number"]),
                "lane_key": node["lane_key"],
                "priority_rank": int(node["priority_rank"]),
                "item_status": projections[key]["item_status"],
                "candidate_sha256": candidate["candidate_sha256"],
                "campaign": None if current is None else dict(current),
            }
        )
        selected_keys.add(key)
        if len(selected) >= limit:
            break
    return {
        "repository": repository,
        "graph_version": int(graph["version"]),
        "accepted_main_sha": graph["observed_main_sha"],
        "selected": selected,
        "skipped": skipped,
    }


def register(
    connection: sqlite3.Connection, plan: dict[str, Any], *, now: str
) -> dict[str, Any]:
    _validate_plan(plan)
    ensure_schema(connection)
    _require_pull_buffer_schema(connection)
    plan_sha = digest_json(plan)
    connection.execute("BEGIN IMMEDIATE")
    try:
        binding = {**plan, "id": -1, "endpoint_id": None}
        reasons = _binding_reasons(connection, binding)
        if reasons:
            raise ReadinessError("READINESS_BINDING_DRIFT:" + ",".join(reasons))
        connection.execute(
            """
            INSERT OR IGNORE INTO portfolio_readiness_campaigns(
                repository, issue_number, generation, item_version,
                source_payload_sha256, accepted_main_sha, graph_version,
                capacity_policy_version, candidate_sha256, worker_role,
                phase_summary, plan_sha256, plan_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                plan["repository"], plan["issue_number"], plan["generation"],
                plan["item_version"], plan["source_payload_sha256"],
                plan["accepted_main_sha"], plan["graph_version"],
                plan["capacity_policy_version"], plan["candidate_sha256"],
                plan["worker_role"], plan["phase_summary"], plan_sha,
                canonical_json(plan), now,
            ),
        )
        campaign = connection.execute(
            "SELECT * FROM portfolio_readiness_campaigns WHERE plan_sha256=?", (plan_sha,)
        ).fetchone()
        prior = connection.execute(
            """
            SELECT * FROM portfolio_readiness_current
            WHERE repository=? AND issue_number=?
            """,
            (plan["repository"], plan["issue_number"]),
        ).fetchone()
        if (
            prior is not None
            and int(prior["campaign_id"]) == int(campaign["id"])
            and prior["state"] in {"RESOLUTION_PENDING", "APPROVAL_PENDING", "HOLD"}
        ):
            raise ReadinessError("READINESS_RESOLUTION_NO_CHANGE")
        cycles = 0 if prior is None else int(prior["resolution_cycles"])
        if prior is not None and prior["state"] == "RESOLUTION_PENDING":
            cycles += 1
        if cycles > 2:
            raise ReadinessError("READINESS_RESOLUTION_CYCLE_LIMIT")
        connection.execute(
            """
            INSERT INTO portfolio_readiness_current(
                repository, issue_number, campaign_id, state, version, updated_at
            ) VALUES (?, ?, ?, 'PENDING', 1, ?)
            ON CONFLICT(repository, issue_number) DO UPDATE SET
                campaign_id=excluded.campaign_id, state='PENDING', message_id=NULL,
                attempt_id=NULL, endpoint_id=NULL, receipt_id=NULL,
                resolution_cycles=?,
                version=portfolio_readiness_current.version+1,
                updated_at=excluded.updated_at, last_error=NULL
            """,
            (
                plan["repository"], plan["issue_number"], int(campaign["id"]),
                now, cycles,
            ),
        )
        for gate in plan["gates"]:
            connection.execute(
                """
                INSERT OR IGNORE INTO portfolio_readiness_gates(
                    campaign_id, gate_key, description, requested_evidence_json, gate_sha256
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    int(campaign["id"]), gate["gate_key"], gate["description"],
                    canonical_json(gate["requested_evidence"]), digest_json(gate),
                ),
            )
        _event(
            connection,
            int(campaign["id"]),
            "READINESS_PHASE_REGISTERED",
            {"plan_sha256": plan_sha, "gate_count": len(plan["gates"])},
            now,
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return {
        "repository": plan["repository"],
        "issue_number": int(plan["issue_number"]),
        "campaign_id": int(campaign["id"]),
        "plan_sha256": plan_sha,
        "state": "PENDING",
    }


def _notice_payload(connection: sqlite3.Connection, campaign: sqlite3.Row) -> dict[str, Any]:
    gates = connection.execute(
        """
        SELECT gate_key, description, requested_evidence_json
        FROM portfolio_readiness_gates WHERE campaign_id=? ORDER BY id
        """,
        (int(campaign["id"]),),
    ).fetchall()
    requested = [
        f"{gate['gate_key']}: {gate['description']} Evidence: "
        + "; ".join(json.loads(gate["requested_evidence_json"]))
        for gate in gates
    ]
    return {
        "source": {
            "repository": campaign["repository"],
            "object_kind": "issue",
            "object_number": int(campaign["issue_number"]),
            "payload_sha256": campaign["source_payload_sha256"],
        },
        "notice_kind": "planning_request",
        "mutation_authority": False,
        "subject": f"Issue {int(campaign['issue_number'])} Kanban readiness phase",
        "summary": campaign["phase_summary"],
        "evidence": {
            "readiness_plan_sha256": campaign["plan_sha256"],
            "candidate_sha256": campaign["candidate_sha256"],
            "accepted_main_sha": campaign["accepted_main_sha"],
            "graph_version": int(campaign["graph_version"]),
            "capacity_policy_version": int(campaign["capacity_policy_version"]),
        },
        "requested_evidence": requested,
        "next_observation": "One terminal evidence bundle covers every listed gate.",
    }


def dispatch(
    store: CoordinationStore,
    repository: str,
    *,
    max_parallel: int,
    now: str,
) -> dict[str, Any]:
    """Dispatch one fresh readiness attempt per candidate, never per gate."""

    if max_parallel <= 0:
        raise ReadinessError("READINESS_LIMIT_INVALID")
    connection = store.connection
    ensure_schema(connection)
    active = int(
        connection.execute(
            "SELECT COUNT(*) FROM portfolio_readiness_current WHERE state='RUNNING'"
        ).fetchone()[0]
    )
    slots = max(0, max_parallel - active)
    dispatched: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    with store.transaction():
        campaigns = connection.execute(
            """
            SELECT campaign.*, current.state, current.endpoint_id,
                   current.version AS current_version
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
            JOIN portfolio_graph_nodes node
              ON node.repository=campaign.repository
             AND node.graph_version=campaign.graph_version
             AND node.issue_number=campaign.issue_number
            WHERE campaign.repository=? AND current.state='PENDING'
            ORDER BY node.priority_rank, node.ready_at, node.lane_order, campaign.issue_number
            """,
            (repository,),
        ).fetchall()
        for campaign in campaigns:
            reasons = _binding_reasons(connection, campaign)
            if reasons:
                _mark_stale(connection, campaign, reasons, now)
                stale.append({"issue_number": int(campaign["issue_number"]), "reasons": reasons})
                continue
            if slots <= 0:
                break
            endpoint = current_endpoint(connection, str(campaign["worker_role"]))
            if endpoint is None:
                raise ReadinessError("CURRENT_ENDPOINT_REQUIRED")
            message_id = store.enqueue_message(
                idempotency_key=(
                    f"kanban-readiness:{campaign['plan_sha256']}:{endpoint['endpoint_id']}"
                ),
                recipient_session_id=str(endpoint["endpoint_id"]),
                topic="coordination.notice",
                payload=_notice_payload(connection, campaign),
                now=now,
                _transaction=False,
            )
            cursor = connection.execute(
                """
                UPDATE portfolio_readiness_current
                SET state='RUNNING', message_id=?, endpoint_id=?,
                    version=version+1, updated_at=?, last_error=NULL
                WHERE campaign_id=? AND state='PENDING' AND version=?
                """,
                (
                    message_id, endpoint["endpoint_id"], now, int(campaign["id"]),
                    int(campaign["current_version"]),
                ),
            )
            if cursor.rowcount != 1:
                raise ReadinessError("READINESS_PHASE_FENCE_LOST")
            _event(
                connection,
                int(campaign["id"]),
                "READINESS_PHASE_DISPATCHED",
                {"message_id": message_id, "endpoint_id": endpoint["endpoint_id"]},
                now,
            )
            dispatched.append(
                {
                    "issue_number": int(campaign["issue_number"]),
                    "message_id": message_id,
                    "endpoint_id": endpoint["endpoint_id"],
                }
            )
            slots -= 1
    return {
        "repository": repository,
        "max_parallel_candidates": max_parallel,
        "active_before": active,
        "dispatched": dispatched,
        "stale": stale,
        "available_after": slots,
    }


def _validate_attempt(
    connection: sqlite3.Connection,
    campaign: sqlite3.Row,
    message_id: int,
    attempt_id: str,
    *,
    terminal: bool,
) -> tuple[sqlite3.Row, sqlite3.Row]:
    message = connection.execute(
        "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
    ).fetchone()
    attempt = connection.execute(
        "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if message is None or attempt is None:
        raise ReadinessError("READINESS_ATTEMPT_MISSING")
    try:
        payload = json.loads(message["payload_json"])
    except json.JSONDecodeError as exc:
        raise ReadinessError("READINESS_MESSAGE_INVALID") from exc
    source = payload.get("source") if isinstance(payload, dict) else None
    message_states = {"COMPLETE"} if terminal else {"PREPARED", "CLAIMED", "COMPLETE"}
    attempt_states = {"COMPLETE"} if terminal else {
        "RESERVED", "LAUNCHING", "RUNNING", "COMPLETE"
    }
    if (
        identity_role(connection, str(message["recipient_session_id"])) != campaign["worker_role"]
        or attempt["role"] != campaign["worker_role"]
        or attempt["endpoint_id"] != message["recipient_session_id"]
        or attempt["target_kind"] != "message"
        or attempt["target_key"] != str(message_id)
        or not isinstance(source, dict)
        or source.get("repository") != campaign["repository"]
        or source.get("object_kind") != "issue"
        or source.get("object_number") != int(campaign["issue_number"])
        or source.get("payload_sha256") != campaign["source_payload_sha256"]
        or message["state"] not in message_states
        or attempt["state"] not in attempt_states
    ):
        raise ReadinessError("READINESS_ATTEMPT_BINDING_INVALID")
    return message, attempt


def attach(
    connection: sqlite3.Connection,
    repository: str,
    issue_number: int,
    message_id: int,
    attempt_id: str,
    *,
    now: str,
) -> dict[str, Any]:
    """Adopt one existing candidate-level phase after exact validation."""

    ensure_schema(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        campaign = _campaign(connection, repository, issue_number)
        if campaign["state"] not in {"PENDING", "RUNNING"}:
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if campaign["state"] == "RUNNING" and (
            int(campaign["message_id"]) != message_id
            or campaign["endpoint_id"] is None
            or (
                campaign["attempt_id"] is not None
                and campaign["attempt_id"] != attempt_id
            )
        ):
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if campaign["attempt_id"] == attempt_id:
            connection.execute("COMMIT")
            return {
                "repository": repository,
                "issue_number": issue_number,
                "message_id": message_id,
                "attempt_id": attempt_id,
                "state": "RUNNING",
            }
        reasons = _binding_reasons(connection, campaign)
        if reasons:
            _mark_stale(connection, campaign, reasons, now)
            raise ReadinessError("READINESS_BINDING_DRIFT:" + ",".join(reasons))
        _message, attempt = _validate_attempt(
            connection, campaign, message_id, attempt_id, terminal=False
        )
        cursor = connection.execute(
            """
            UPDATE portfolio_readiness_current
            SET state='RUNNING', message_id=?, attempt_id=?, endpoint_id=?,
                version=version+1, updated_at=?, last_error=NULL
            WHERE campaign_id=? AND state IN ('PENDING','RUNNING') AND version=?
            """,
            (
                message_id, attempt_id, attempt["endpoint_id"], now,
                int(campaign["id"]), int(campaign["current_version"]),
            ),
        )
        if cursor.rowcount != 1:
            raise ReadinessError("READINESS_PHASE_FENCE_LOST")
        _event(
            connection,
            int(campaign["id"]),
            "READINESS_PHASE_ATTACHED",
            {"message_id": message_id, "attempt_id": attempt_id},
            now,
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return {
        "repository": repository,
        "issue_number": issue_number,
        "message_id": message_id,
        "attempt_id": attempt_id,
        "state": "RUNNING",
    }


def _validate_receipt(receipt: dict[str, Any]) -> None:
    expected = {
        "schema", "repository", "issue_number", "readiness_plan_sha256",
        "verdict", "worker_role", "message_id", "attempt_id", "gate_results",
        "resolution", "summary", "observed_at",
    }
    if set(receipt) != expected or receipt.get("schema") != RECEIPT_SCHEMA:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    verdict = receipt.get("verdict")
    if verdict not in {"PASS", "ACTIONABLE_HOLD", "APPROVAL_REQUIRED", "TERMINAL_HOLD"}:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if receipt.get("worker_role") not in WORKER_ROLES:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if type(receipt.get("issue_number")) is not int or receipt["issue_number"] <= 0:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if type(receipt.get("message_id")) is not int or not isinstance(receipt.get("attempt_id"), str):
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if not isinstance(receipt.get("readiness_plan_sha256"), str) or not SHA256.fullmatch(
        receipt["readiness_plan_sha256"]
    ):
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if not isinstance(receipt.get("summary"), str) or not receipt["summary"].strip():
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if not isinstance(receipt.get("observed_at"), str) or not receipt["observed_at"].strip():
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    results = receipt.get("gate_results")
    if not isinstance(results, list) or not results:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    seen: set[str] = set()
    for result in results:
        if not isinstance(result, dict) or set(result) != {
            "gate_key", "verdict", "evidence_sha256", "summary"
        }:
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        key = result.get("gate_key")
        if not isinstance(key, str) or not GATE_KEY.fullmatch(key) or key in seen:
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        seen.add(key)
        if result.get("verdict") not in {"PASS", "HOLD"}:
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        if not isinstance(result.get("evidence_sha256"), str) or not SHA256.fullmatch(
            result["evidence_sha256"]
        ):
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        if not isinstance(result.get("summary"), str) or not result["summary"].strip():
            raise ReadinessError("READINESS_RECEIPT_INVALID")
    gate_verdicts = {result["verdict"] for result in results}
    if (verdict == "PASS" and gate_verdicts != {"PASS"}) or (
        verdict != "PASS" and "HOLD" not in gate_verdicts
    ):
        raise ReadinessError("READINESS_RECEIPT_VERDICT_MISMATCH")
    resolution = receipt.get("resolution")
    if not isinstance(resolution, dict) or set(resolution) != {
        "role", "actions", "approval_proposal_sha256"
    }:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    role = resolution.get("role")
    actions = resolution.get("actions")
    proposal = resolution.get("approval_proposal_sha256")
    if verdict == "PASS":
        if role is not None or actions != [] or proposal is not None:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    elif verdict == "ACTIONABLE_HOLD":
        if role != "planner" or not isinstance(actions, list) or not actions:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
        if proposal is not None:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    elif verdict == "APPROVAL_REQUIRED":
        if role != "planner" or not isinstance(actions, list) or not actions:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
        if not isinstance(proposal, str) or not SHA256.fullmatch(proposal):
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    elif role is not None or actions != [] or proposal is not None:
        raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    if not isinstance(actions, list) or any(
        not isinstance(action, str) or not action.strip() for action in actions
    ):
        raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")


def _planner_notice(
    store: CoordinationStore,
    campaign: sqlite3.Row,
    receipt: dict[str, Any],
    receipt_sha: str,
    *,
    now: str,
) -> int:
    planner = current_endpoint(store.connection, "planner")
    if planner is None:
        raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
    verdict = str(receipt["verdict"])
    evidence = {
        "readiness_plan_sha256": campaign["plan_sha256"],
        "readiness_receipt_sha256": receipt_sha,
        "verdict": verdict,
        "resolution_role": receipt["resolution"]["role"],
        "resolution_item_count": len(receipt["resolution"]["actions"]),
    }
    if receipt["resolution"]["approval_proposal_sha256"] is not None:
        evidence["proposal_sha256"] = receipt["resolution"]["approval_proposal_sha256"]
    payload = {
        "source": {
            "repository": campaign["repository"],
            "object_kind": "issue",
            "object_number": int(campaign["issue_number"]),
            "payload_sha256": campaign["source_payload_sha256"],
        },
        "notice_kind": "status",
        "mutation_authority": False,
        "subject": f"Issue {int(campaign['issue_number'])} readiness phase result",
        "summary": "One bounded candidate-level readiness evidence bundle is complete.",
        "evidence": evidence,
        "next_observation": (
            "Planner guard review remains pending."
            if verdict == "PASS"
            else "One consolidated Planner review remains pending."
            if verdict == "ACTIONABLE_HOLD"
            else "The approval ledger remains the only pending decision path."
            if verdict == "APPROVAL_REQUIRED"
            else "The terminal blocker remains preserved for portfolio disposition."
        ),
    }
    return store.enqueue_message(
        idempotency_key=f"kanban-readiness-planner:{receipt_sha}",
        recipient_session_id=str(planner["endpoint_id"]),
        topic="coordination.notice",
        payload=payload,
        now=now,
        _transaction=False,
    )


def record(
    store: CoordinationStore, receipt: dict[str, Any], *, now: str
) -> dict[str, Any]:
    """Commit one all-gates result and exactly one Planner continuation."""

    _validate_receipt(receipt)
    connection = store.connection
    ensure_schema(connection)
    receipt_sha = digest_json(receipt)
    with store.transaction():
        campaign = _campaign(
            connection, str(receipt["repository"]), int(receipt["issue_number"])
        )
        if campaign["plan_sha256"] != receipt["readiness_plan_sha256"]:
            raise ReadinessError("READINESS_RECEIPT_CAMPAIGN_DRIFT")
        if campaign["state"] in {
            "READY_ELIGIBLE", "RESOLUTION_PENDING", "APPROVAL_PENDING", "HOLD"
        }:
            prior = connection.execute(
                "SELECT receipt_sha256 FROM portfolio_readiness_receipts WHERE id=?",
                (campaign["receipt_id"],),
            ).fetchone()
            if prior is not None and prior["receipt_sha256"] == receipt_sha:
                return {
                    "repository": receipt["repository"],
                    "issue_number": receipt["issue_number"],
                    "verdict": receipt["verdict"],
                    "receipt_sha256": receipt_sha,
                    "state": campaign["state"],
                }
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if campaign["state"] != "RUNNING":
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if (
            campaign["worker_role"] != receipt["worker_role"]
            or int(campaign["message_id"]) != int(receipt["message_id"])
            or campaign["attempt_id"] != receipt["attempt_id"]
        ):
            raise ReadinessError("READINESS_RECEIPT_ATTEMPT_DRIFT")
        reasons = _binding_reasons(connection, campaign)
        if reasons:
            _mark_stale(connection, campaign, reasons, now)
            raise ReadinessError("READINESS_BINDING_DRIFT:" + ",".join(reasons))
        _validate_attempt(
            connection,
            campaign,
            int(receipt["message_id"]),
            str(receipt["attempt_id"]),
            terminal=True,
        )
        expected_gates = {
            row["gate_key"]
            for row in connection.execute(
                "SELECT gate_key FROM portfolio_readiness_gates WHERE campaign_id=?",
                (int(campaign["id"]),),
            )
        }
        received_gates = {result["gate_key"] for result in receipt["gate_results"]}
        if expected_gates != received_gates:
            raise ReadinessError("READINESS_RECEIPT_GATE_COVERAGE_INVALID")
        proposal = receipt["resolution"]["approval_proposal_sha256"]
        if receipt["verdict"] == "APPROVAL_REQUIRED":
            approval = connection.execute(
                "SELECT proposal_sha256 FROM approval_proposals WHERE proposal_sha256=?",
                (proposal,),
            ).fetchone()
            if approval is None:
                raise ReadinessError("READINESS_APPROVAL_PROPOSAL_MISSING")
        connection.execute(
            """
            INSERT OR IGNORE INTO portfolio_readiness_receipts(
                campaign_id, verdict, worker_role, message_id, attempt_id,
                resolution_role, receipt_sha256, receipt_json, observed_at, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(campaign["id"]), receipt["verdict"], receipt["worker_role"],
                receipt["message_id"], receipt["attempt_id"],
                receipt["resolution"]["role"], receipt_sha,
                canonical_json(receipt), receipt["observed_at"], now,
            ),
        )
        receipt_row = connection.execute(
            "SELECT id FROM portfolio_readiness_receipts WHERE receipt_sha256=?",
            (receipt_sha,),
        ).fetchone()
        state = {
            "PASS": "READY_ELIGIBLE",
            "ACTIONABLE_HOLD": "RESOLUTION_PENDING",
            "APPROVAL_REQUIRED": "APPROVAL_PENDING",
            "TERMINAL_HOLD": "HOLD",
        }[receipt["verdict"]]
        cursor = connection.execute(
            """
            UPDATE portfolio_readiness_current
            SET state=?, receipt_id=?, version=version+1, updated_at=?, last_error=?
            WHERE campaign_id=? AND state='RUNNING' AND version=?
            """,
            (
                state, int(receipt_row["id"]), now,
                None if state == "READY_ELIGIBLE" else receipt["summary"],
                int(campaign["id"]), int(campaign["current_version"]),
            ),
        )
        if cursor.rowcount != 1:
            raise ReadinessError("READINESS_PHASE_FENCE_LOST")
        planner_message_id = _planner_notice(
            store, campaign, receipt, receipt_sha, now=now
        )
        _event(
            connection,
            int(campaign["id"]),
            "READINESS_PHASE_COMPLETED",
            {
                "verdict": receipt["verdict"],
                "receipt_sha256": receipt_sha,
                "planner_message_id": planner_message_id,
            },
            now,
        )
    return {
        "repository": receipt["repository"],
        "issue_number": receipt["issue_number"],
        "verdict": receipt["verdict"],
        "receipt_sha256": receipt_sha,
        "state": state,
        "planner_message_id": planner_message_id,
    }


def _mark_stale(
    connection: sqlite3.Connection,
    campaign: sqlite3.Row,
    reasons: list[str],
    now: str,
) -> None:
    error = ",".join(sorted(set(reasons)))
    connection.execute(
        """
        UPDATE portfolio_readiness_current
        SET state='STALE', version=version+1, updated_at=?, last_error=?
        WHERE campaign_id=? AND state!='STALE'
        """,
        (now, error, int(campaign["id"])),
    )
    _event(
        connection,
        int(campaign["id"]),
        "READINESS_PHASE_STALE",
        {"reasons": sorted(set(reasons))},
        now,
    )


def evaluate(
    connection: sqlite3.Connection,
    repository: str,
    issue_number: int,
    *,
    now: str,
    record_state: bool,
) -> dict[str, Any]:
    ensure_schema(connection)
    if record_state:
        connection.execute("BEGIN IMMEDIATE")
    try:
        campaign = _campaign(connection, repository, issue_number)
        reasons = _binding_reasons(connection, campaign)
        state = "STALE" if reasons else campaign["state"]
        if record_state and reasons:
            _mark_stale(connection, campaign, reasons, now)
        if record_state:
            connection.execute("COMMIT")
    except Exception:
        if record_state and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    gates = [
        {
            "gate_key": row["gate_key"],
            "description": row["description"],
            "requested_evidence": json.loads(row["requested_evidence_json"]),
        }
        for row in connection.execute(
            """
            SELECT gate_key, description, requested_evidence_json
            FROM portfolio_readiness_gates WHERE campaign_id=? ORDER BY id
            """,
            (int(campaign["id"]),),
        )
    ]
    return {
        "repository": repository,
        "issue_number": issue_number,
        "plan_sha256": campaign["plan_sha256"],
        "state": state,
        "binding_reasons": reasons,
        "gates": gates,
        "promotion_allowed": state == "READY_ELIGIBLE",
    }


def show(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    ensure_schema(connection)
    rows = connection.execute(
        """
        SELECT campaign.issue_number, campaign.generation, campaign.plan_sha256,
               campaign.candidate_sha256, campaign.worker_role, current.state,
               current.message_id, current.attempt_id, current.endpoint_id,
               current.resolution_cycles, current.version, current.updated_at,
               current.last_error
        FROM portfolio_readiness_current current
        JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
        WHERE current.repository=? ORDER BY campaign.issue_number
        """,
        (repository,),
    ).fetchall()
    return {"repository": repository, "campaigns": [dict(row) for row in rows]}
