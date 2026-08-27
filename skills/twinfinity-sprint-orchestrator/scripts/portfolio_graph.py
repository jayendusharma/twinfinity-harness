#!/usr/bin/env python3
"""Lightweight, versioned portfolio DAG and dependency-aware FIFO scheduler."""

from __future__ import annotations

import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import pwd
import os
import re
import sqlite3
from typing import Any

from owner_safe_sqlite import UnsafeSQLitePathError, prepare_owner_database
from repository_delivery_policy import HARNESS_REPOSITORY, policy_for_repository
from admission_source_equivalence import admission_lineage_source_is_current


DEFAULT_DATABASE = (
    Path(pwd.getpwuid(os.getuid()).pw_dir)
    / ".codex"
    / "twinfinity-coordination"
    / "ack-transactions.sqlite3"
)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
NODE_KEY = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
ROLES = {"DELIVERY", "SERIAL_GATE", "CONTROL", "MONITOR", "TRACKER", "EPIC"}
ROOT_KINDS = {"NORMAL", "INTENTIONAL", "STANDALONE"}
RELATION_KINDS = {"HARD_BLOCK", "ORDER_AFTER", "COLLISION"}
STABLE_PARK_STATUSES = {"BACKLOG", "PREPARED", "QUEUED", "MONITOR"}
EXECUTION_STATUSES = {"READY", "ACTIVE", "ACTIVE_FENCED"}
TERMINAL_STATUSES = {"DONE"}


class PortfolioGraphError(ValueError):
    """Typed fail-closed graph validation error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def enqueue_convergence_dirty_event(
    connection: sqlite3.Connection,
    *,
    repository: str,
    trigger_kind: str,
    issue_number: int,
    item_version: int,
    source_sha256: str,
    status: str,
    generation: int,
    now: str,
    details: dict[str, Any] | None = None,
    require_pending: bool = False,
) -> int | None:
    """Append an idempotent wake when the coordination schema is installed."""

    installed = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='portfolio_dirty_events'"
    ).fetchone()
    if installed is None:
        return None
    payload = {
        "trigger_kind": trigger_kind,
        "repository": repository,
        "issue_number": issue_number,
        "release_item_version": item_version,
        "release_source_sha256": source_sha256,
        "status": status,
        "generation": generation,
        **(details or {}),
    }
    event_sha256 = digest_json(payload)
    event_key = f"portfolio-dirty:{trigger_kind}:{repository}:{event_sha256}"
    inserted = connection.execute(
        """
        INSERT OR IGNORE INTO portfolio_dirty_events(
            event_key, repository, issue_number, release_item_version,
            release_source_sha256, event_sha256, payload_json, state,
            attempts, next_attempt_at, result_sha256, result_json,
            created_at, updated_at, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, NULL, NULL, ?, ?, NULL)
        """,
        (
            event_key,
            repository,
            issue_number,
            item_version,
            source_sha256,
            event_sha256,
            canonical_json(payload),
            now,
            now,
            now,
        ),
    )
    row = connection.execute(
        "SELECT id, event_sha256, payload_json, state "
        "FROM portfolio_dirty_events WHERE event_key=?",
        (event_key,),
    ).fetchone()
    if (
        row is None
        or row["event_sha256"] != event_sha256
        or row["payload_json"] != canonical_json(payload)
    ):
        raise PortfolioGraphError("PORTFOLIO_DIRTY_EVENT_CONFLICT")
    if require_pending and row["state"] != "PENDING":
        raise PortfolioGraphError("PORTFOLIO_DIRTY_EVENT_NOT_PENDING")
    events_installed = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='coordination_events'"
    ).fetchone()
    if events_installed is not None and inserted.rowcount == 1:
        connection.execute(
            "INSERT INTO coordination_events(event_type, entity_key, payload_sha256, created_at) "
            "VALUES ('PORTFOLIO_DIRTY_ENQUEUED', ?, ?, ?)",
            (event_key, digest_json({"event_id": int(row["id"]), "event_sha256": event_sha256}), now),
        )
    return int(row["id"])


def ensure_portfolio_graph_schema(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        raise PortfolioGraphError("GRAPH_SCHEMA_TRANSACTION_CONFLICT")
    try:
        connection.executescript(
            """
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS portfolio_graph_revisions (
            repository TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            parent_version INTEGER,
            accepted_main_sha TEXT NOT NULL,
            graph_sha256 TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            exclusions_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(repository, version)
        );
        CREATE TABLE IF NOT EXISTS portfolio_graph_current (
            repository TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            observed_main_sha TEXT NOT NULL,
            health TEXT NOT NULL CHECK(health IN ('CURRENT', 'STALE')),
            updated_at TEXT NOT NULL,
            last_error TEXT,
            FOREIGN KEY(repository, version)
                REFERENCES portfolio_graph_revisions(repository, version)
        );
        CREATE TABLE IF NOT EXISTS portfolio_graph_nodes (
            repository TEXT NOT NULL,
            graph_version INTEGER NOT NULL,
            node_key TEXT NOT NULL,
            issue_number INTEGER NOT NULL CHECK(issue_number > 0),
            role TEXT NOT NULL CHECK(role IN ('DELIVERY','SERIAL_GATE','CONTROL','MONITOR','TRACKER','EPIC')),
            root_kind TEXT NOT NULL CHECK(root_kind IN ('NORMAL','INTENTIONAL','STANDALONE')),
            root_reason TEXT,
            milestone_title TEXT,
            milestone_rank INTEGER,
            lane_key TEXT NOT NULL,
            lane_order INTEGER NOT NULL CHECK(lane_order >= 0),
            dispatchable INTEGER NOT NULL CHECK(dispatchable IN (0,1)),
            priority_rank INTEGER NOT NULL CHECK(priority_rank > 0),
            estimate_units INTEGER NOT NULL CHECK(estimate_units > 0),
            development_units INTEGER NOT NULL CHECK(development_units >= 0),
            shared_units INTEGER NOT NULL CHECK(shared_units >= 0),
            sre_units INTEGER NOT NULL CHECK(sre_units >= 0),
            source_payload_sha256 TEXT NOT NULL,
            ready_at TEXT NOT NULL,
            PRIMARY KEY(repository, graph_version, node_key),
            FOREIGN KEY(repository, graph_version)
                REFERENCES portfolio_graph_revisions(repository, version)
        );
        CREATE INDEX IF NOT EXISTS portfolio_graph_node_issue
            ON portfolio_graph_nodes(repository, graph_version, issue_number);
        CREATE TABLE IF NOT EXISTS portfolio_graph_relations (
            repository TEXT NOT NULL,
            graph_version INTEGER NOT NULL,
            left_node_key TEXT NOT NULL,
            right_node_key TEXT NOT NULL,
            relation_kind TEXT NOT NULL CHECK(relation_kind IN ('HARD_BLOCK','ORDER_AFTER','COLLISION')),
            reason TEXT NOT NULL,
            source_payload_sha256 TEXT NOT NULL,
            PRIMARY KEY(repository, graph_version, left_node_key, right_node_key, relation_kind),
            FOREIGN KEY(repository, graph_version, left_node_key)
                REFERENCES portfolio_graph_nodes(repository, graph_version, node_key),
            FOREIGN KEY(repository, graph_version, right_node_key)
                REFERENCES portfolio_graph_nodes(repository, graph_version, node_key)
        );
        CREATE TABLE IF NOT EXISTS portfolio_scheduler_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            graph_version INTEGER NOT NULL,
            decision_sha256 TEXT NOT NULL,
            node_key TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('READY','SKIP','SELECT','STALE')),
            reason_code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(repository, graph_version, decision_sha256, node_key, event_type)
        );
        CREATE TRIGGER IF NOT EXISTS portfolio_graph_revisions_immutable_update
        BEFORE UPDATE ON portfolio_graph_revisions
        BEGIN SELECT RAISE(ABORT, 'PORTFOLIO_GRAPH_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_graph_revisions_immutable_delete
        BEFORE DELETE ON portfolio_graph_revisions
        BEGIN SELECT RAISE(ABORT, 'PORTFOLIO_GRAPH_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_graph_nodes_immutable_update
        BEFORE UPDATE ON portfolio_graph_nodes
        BEGIN SELECT RAISE(ABORT, 'PORTFOLIO_GRAPH_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_graph_nodes_immutable_delete
        BEFORE DELETE ON portfolio_graph_nodes
        BEGIN SELECT RAISE(ABORT, 'PORTFOLIO_GRAPH_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_graph_relations_immutable_update
        BEFORE UPDATE ON portfolio_graph_relations
        BEGIN SELECT RAISE(ABORT, 'PORTFOLIO_GRAPH_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS portfolio_graph_relations_immutable_delete
        BEFORE DELETE ON portfolio_graph_relations
        BEGIN SELECT RAISE(ABORT, 'PORTFOLIO_GRAPH_IMMUTABLE'); END;
        DROP TRIGGER IF EXISTS portfolio_graph_stale_on_issue_update;
        CREATE TRIGGER portfolio_graph_stale_on_issue_update
        AFTER UPDATE OF payload_sha256 ON github_current
        WHEN NEW.object_kind='issue' AND NEW.payload_sha256<>OLD.payload_sha256
        BEGIN
            UPDATE portfolio_graph_current
            SET health='STALE', updated_at=NEW.fetched_at, last_error='GRAPH_SOURCE_DRIFT'
            WHERE repository=NEW.repository
              AND (
                  EXISTS (
                      SELECT 1 FROM portfolio_graph_nodes n
                      WHERE n.repository=NEW.repository
                        AND n.graph_version=portfolio_graph_current.version
                        AND n.issue_number=NEW.object_number
                        AND n.source_payload_sha256<>NEW.payload_sha256
                  )
                  OR (
                      EXISTS (
                          SELECT 1
                          FROM portfolio_graph_revisions r,
                               json_each(json_extract(r.scope_json, '$.milestones')) scoped
                          JOIN github_snapshots s
                            ON s.repository=NEW.repository
                           AND s.object_kind=NEW.object_kind
                           AND s.object_number=NEW.object_number
                           AND s.payload_sha256=NEW.payload_sha256
                          WHERE r.repository=NEW.repository
                            AND r.version=portfolio_graph_current.version
                            AND scoped.value=json_extract(s.payload_json, '$.milestone.title')
                            AND json_extract(s.payload_json, '$.state')='open'
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM portfolio_graph_nodes n
                          WHERE n.repository=NEW.repository
                            AND n.graph_version=portfolio_graph_current.version
                            AND n.issue_number=NEW.object_number
                      )
                  )
                  OR (
                      EXISTS (
                          SELECT 1
                          FROM portfolio_graph_revisions r,
                               json_each(json_extract(r.scope_json, '$.issue_numbers')) scoped
                          WHERE r.repository=NEW.repository
                            AND r.version=portfolio_graph_current.version
                            AND json_extract(r.scope_json, '$.kind')='ISSUE_SET'
                            AND CAST(scoped.value AS INTEGER)=NEW.object_number
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM portfolio_graph_nodes n
                          WHERE n.repository=NEW.repository
                            AND n.graph_version=portfolio_graph_current.version
                            AND n.issue_number=NEW.object_number
                      )
                  )
              );
        END;
        DROP TRIGGER IF EXISTS portfolio_graph_stale_on_scoped_issue_insert;
        CREATE TRIGGER portfolio_graph_stale_on_scoped_issue_insert
        AFTER INSERT ON github_current
        WHEN NEW.object_kind='issue'
        BEGIN
            UPDATE portfolio_graph_current
            SET health='STALE', updated_at=NEW.fetched_at, last_error='GRAPH_SCOPE_INVENTORY_DRIFT'
            WHERE repository=NEW.repository
              AND (
                  EXISTS (
                      SELECT 1
                      FROM portfolio_graph_revisions r,
                           json_each(json_extract(r.scope_json, '$.milestones')) scoped
                      JOIN github_snapshots s
                        ON s.repository=NEW.repository
                       AND s.object_kind=NEW.object_kind
                       AND s.object_number=NEW.object_number
                       AND s.payload_sha256=NEW.payload_sha256
                      WHERE r.repository=NEW.repository
                        AND r.version=portfolio_graph_current.version
                        AND scoped.value=json_extract(s.payload_json, '$.milestone.title')
                        AND json_extract(s.payload_json, '$.state')='open'
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM portfolio_graph_revisions r,
                           json_each(json_extract(r.scope_json, '$.issue_numbers')) scoped
                      WHERE r.repository=NEW.repository
                        AND r.version=portfolio_graph_current.version
                        AND json_extract(r.scope_json, '$.kind')='ISSUE_SET'
                        AND CAST(scoped.value AS INTEGER)=NEW.object_number
                  )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM portfolio_graph_nodes n
                  WHERE n.repository=NEW.repository
                    AND n.graph_version=portfolio_graph_current.version
                    AND n.issue_number=NEW.object_number
              );
        END;
        DROP TRIGGER IF EXISTS portfolio_graph_stale_on_issue_delete;
        CREATE TRIGGER portfolio_graph_stale_on_issue_delete
        AFTER DELETE ON github_current
        WHEN OLD.object_kind='issue'
        BEGIN
            UPDATE portfolio_graph_current
            SET health='STALE', updated_at=OLD.fetched_at,
                last_error='GRAPH_SOURCE_MISSING'
            WHERE repository=OLD.repository
              AND (
                  EXISTS (
                      SELECT 1 FROM portfolio_graph_nodes n
                      WHERE n.repository=OLD.repository
                        AND n.graph_version=portfolio_graph_current.version
                        AND n.issue_number=OLD.object_number
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM portfolio_graph_revisions r,
                           json_each(json_extract(r.scope_json, '$.issue_numbers')) scoped
                      WHERE r.repository=OLD.repository
                        AND r.version=portfolio_graph_current.version
                        AND json_extract(r.scope_json, '$.kind')='ISSUE_SET'
                        AND CAST(scoped.value AS INTEGER)=OLD.object_number
                  )
              );
        END;
        COMMIT;
        """
        )
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _validate_repository(repository: str) -> None:
    if not REPOSITORY.fullmatch(repository):
        raise PortfolioGraphError("GRAPH_REPOSITORY_INVALID")


def _snapshot(
    connection: sqlite3.Connection, repository: str, issue_number: int
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT c.payload_sha256, c.source_updated_at, c.fetched_at, s.payload_json
        FROM github_current c
        JOIN github_snapshots s
          ON s.repository=c.repository
         AND s.object_kind=c.object_kind
         AND s.object_number=c.object_number
         AND s.payload_sha256=c.payload_sha256
        WHERE c.repository=? AND c.object_kind='issue' AND c.object_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if row is None:
        raise PortfolioGraphError("GRAPH_SOURCE_MISSING")
    return row


def _require_issue_set_snapshot(snapshot: sqlite3.Row) -> None:
    try:
        payload = json.loads(snapshot["payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise PortfolioGraphError("GRAPH_SOURCE_INVALID") from exc
    if not isinstance(payload, dict) or payload.get("milestone") is not None:
        raise PortfolioGraphError("GRAPH_ISSUE_SET_MILESTONE_CONFLICT")


def _current_version(connection: sqlite3.Connection, repository: str) -> int:
    row = connection.execute(
        "SELECT version FROM portfolio_graph_current WHERE repository=?",
        (repository,),
    ).fetchone()
    return 0 if row is None else int(row["version"])


def _scope_details(
    plan: dict[str, Any],
) -> tuple[str, dict[str, int], set[int]]:
    """Return one validated legacy milestone or explicit issue-set scope."""

    if "scope_milestones" in plan:
        if not isinstance(plan["scope_milestones"], list) or not plan["scope_milestones"]:
            raise PortfolioGraphError("GRAPH_SCOPE_INVALID")
        milestone_titles: set[str] = set()
        milestone_ranks: set[int] = set()
        milestones: dict[str, int] = {}
        for milestone in plan["scope_milestones"]:
            if (
                not isinstance(milestone, dict)
                or set(milestone) != {"title", "rank"}
                or not isinstance(milestone["title"], str)
                or not milestone["title"]
                or type(milestone["rank"]) is not int
                or milestone["rank"] < 0
                or milestone["title"] in milestone_titles
                or milestone["rank"] in milestone_ranks
            ):
                raise PortfolioGraphError("GRAPH_SCOPE_INVALID")
            milestone_titles.add(milestone["title"])
            milestone_ranks.add(milestone["rank"])
            milestones[milestone["title"]] = milestone["rank"]
        return "MILESTONE", milestones, set()
    scope = plan.get("scope")
    if plan.get("repository") != HARNESS_REPOSITORY:
        raise PortfolioGraphError("GRAPH_ISSUE_SET_REPOSITORY_FORBIDDEN")
    if (
        not isinstance(scope, dict)
        or set(scope) != {"kind", "issue_numbers"}
        or scope.get("kind") != "ISSUE_SET"
        or not isinstance(scope.get("issue_numbers"), list)
        or not scope["issue_numbers"]
        or any(type(number) is not int or number <= 0 for number in scope["issue_numbers"])
        or len(set(scope["issue_numbers"])) != len(scope["issue_numbers"])
        or scope["issue_numbers"] != sorted(scope["issue_numbers"])
    ):
        raise PortfolioGraphError("GRAPH_SCOPE_INVALID")
    return "ISSUE_SET", {}, set(scope["issue_numbers"])


def issue_set_scope_numbers(repository: str, scope: Any) -> list[int]:
    """Validate and return the exact repository-local issue-set scope."""

    plan = {"repository": repository, "scope": scope}
    kind, _milestones, numbers = _scope_details(plan)
    if kind != "ISSUE_SET":  # defensive: the synthetic plan cannot select legacy scope
        raise PortfolioGraphError("GRAPH_SCOPE_INVALID")
    return sorted(numbers)


def graph_payload(plan: dict[str, Any]) -> dict[str, Any]:
    """Return the immutable graph bytes while preserving legacy digests."""

    scope_key = "scope_milestones" if "scope_milestones" in plan else "scope"
    payload = {
        key: plan[key]
        for key in (
            "repository",
            scope_key,
            "excluded_issues",
            "nodes",
            "relations",
        )
    }
    if scope_key == "scope":
        # The harness issue-set plan is a point-in-time bootstrap envelope.
        # Binding main here prevents readiness recomputation from substituting
        # topology accepted against another head.  Legacy milestone graph bytes
        # remain exactly unchanged.
        payload["accepted_main_sha"] = plan["accepted_main_sha"]
    return payload


def _validate_plan(plan: dict[str, Any]) -> None:
    common = {
        "repository",
        "accepted_main_sha",
        "expected_current_version",
        "excluded_issues",
        "nodes",
        "relations",
    }
    if set(plan) not in {frozenset(common | {"scope_milestones"}), frozenset(common | {"scope"})}:
        raise PortfolioGraphError("GRAPH_PLAN_INVALID")
    _validate_repository(plan["repository"])
    if not isinstance(plan["accepted_main_sha"], str) or not GIT_SHA.fullmatch(
        plan["accepted_main_sha"]
    ):
        raise PortfolioGraphError("GRAPH_MAIN_INVALID")
    if type(plan["expected_current_version"]) is not int or plan["expected_current_version"] < 0:
        raise PortfolioGraphError("GRAPH_PLAN_INVALID")
    scope_kind, _milestones, scoped_issue_numbers = _scope_details(plan)
    if not isinstance(plan["excluded_issues"], list):
        raise PortfolioGraphError("GRAPH_EXCLUSION_INVALID")
    excluded: set[int] = set()
    for exclusion in plan["excluded_issues"]:
        if (
            not isinstance(exclusion, dict)
            or set(exclusion)
            != (
                {"issue_number", "reason", "source_payload_sha256"}
                if scope_kind == "ISSUE_SET"
                else {"issue_number", "reason"}
            )
            or type(exclusion["issue_number"]) is not int
            or exclusion["issue_number"] <= 0
            or not isinstance(exclusion["reason"], str)
            or not exclusion["reason"]
            or exclusion["issue_number"] in excluded
        ):
            raise PortfolioGraphError("GRAPH_EXCLUSION_INVALID")
        if scope_kind == "ISSUE_SET" and (
            not isinstance(exclusion["source_payload_sha256"], str)
            or not SHA256.fullmatch(exclusion["source_payload_sha256"])
        ):
            raise PortfolioGraphError("GRAPH_EXCLUSION_INVALID")
        excluded.add(exclusion["issue_number"])
    if not isinstance(plan["nodes"], list) or not plan["nodes"]:
        raise PortfolioGraphError("GRAPH_NODE_INVALID")
    node_keys: set[str] = set()
    node_issues: set[int] = set()
    lane_positions: set[tuple[str, int]] = set()
    required_node_keys = {
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
        "source_payload_sha256",
        "ready_at",
    }
    for node in plan["nodes"]:
        if not isinstance(node, dict) or set(node) != required_node_keys:
            raise PortfolioGraphError("GRAPH_NODE_INVALID")
        if (
            not isinstance(node["node_key"], str)
            or not NODE_KEY.fullmatch(node["node_key"])
            or node["node_key"] in node_keys
            or type(node["issue_number"]) is not int
            or node["issue_number"] <= 0
            or node["role"] not in ROLES
            or node["root_kind"] not in ROOT_KINDS
            or not isinstance(node["lane_key"], str)
            or not node["lane_key"]
            or type(node["lane_order"]) is not int
            or node["lane_order"] < 0
            or type(node["dispatchable"]) is not bool
            or type(node["priority_rank"]) is not int
            or node["priority_rank"] <= 0
            or type(node["estimate_units"]) is not int
            or node["estimate_units"] <= 0
            or any(
                type(node[key]) is not int or node[key] < 0
                for key in ("development_units", "shared_units", "sre_units")
            )
            or not isinstance(node["source_payload_sha256"], str)
            or not SHA256.fullmatch(node["source_payload_sha256"])
            or not isinstance(node["ready_at"], str)
            or not node["ready_at"]
        ):
            raise PortfolioGraphError("GRAPH_NODE_INVALID")
        if scope_kind == "ISSUE_SET" and node["issue_number"] in node_issues:
            raise PortfolioGraphError("GRAPH_NODE_ISSUE_DUPLICATE")
        if node["root_kind"] in {"INTENTIONAL", "STANDALONE"} and (
            not isinstance(node["root_reason"], str) or not node["root_reason"]
        ):
            raise PortfolioGraphError("GRAPH_ROOT_REASON_REQUIRED")
        if node["root_kind"] == "NORMAL" and node["root_reason"] is not None:
            raise PortfolioGraphError("GRAPH_NODE_INVALID")
        position = (node["lane_key"], node["lane_order"])
        if position in lane_positions:
            raise PortfolioGraphError("GRAPH_LANE_POSITION_DUPLICATE")
        lane_positions.add(position)
        node_keys.add(node["node_key"])
        node_issues.add(node["issue_number"])
    if not isinstance(plan["relations"], list):
        raise PortfolioGraphError("GRAPH_RELATION_INVALID")
    relations: set[tuple[str, str, str]] = set()
    for relation in plan["relations"]:
        if (
            not isinstance(relation, dict)
            or set(relation) != {
                "left_node_key",
                "right_node_key",
                "relation_kind",
                "reason",
                "source_payload_sha256",
            }
            or relation["left_node_key"] not in node_keys
            or relation["right_node_key"] not in node_keys
            or relation["left_node_key"] == relation["right_node_key"]
            or relation["relation_kind"] not in RELATION_KINDS
            or not isinstance(relation["reason"], str)
            or not relation["reason"]
            or not isinstance(relation["source_payload_sha256"], str)
            or not SHA256.fullmatch(relation["source_payload_sha256"])
        ):
            raise PortfolioGraphError("GRAPH_RELATION_INVALID")
        if relation["relation_kind"] == "COLLISION" and (
            relation["left_node_key"] > relation["right_node_key"]
        ):
            raise PortfolioGraphError("GRAPH_COLLISION_NOT_CANONICAL")
        key = (
            relation["left_node_key"],
            relation["right_node_key"],
            relation["relation_kind"],
        )
        if key in relations:
            raise PortfolioGraphError("GRAPH_RELATION_DUPLICATE")
        relations.add(key)
    if scope_kind == "ISSUE_SET":
        represented = {int(node["issue_number"]) for node in plan["nodes"]}
        if represented & excluded:
            raise PortfolioGraphError("GRAPH_SCOPE_CONFLICT")
        if represented | excluded != scoped_issue_numbers:
            raise PortfolioGraphError("GRAPH_SCOPE_INCOMPLETE")


def validate_graph_plan(plan: dict[str, Any]) -> None:
    """Validate a complete graph plan without writing repository state."""

    _validate_plan(plan)


def _topological_order(
    node_keys: set[str], hard_edges: list[tuple[str, str]]
) -> list[str]:
    outgoing: dict[str, list[str]] = defaultdict(list)
    indegree = {key: 0 for key in node_keys}
    for left, right in hard_edges:
        outgoing[left].append(right)
        indegree[right] += 1
    ready = sorted(key for key, degree in indegree.items() if degree == 0)
    order: list[str] = []
    while ready:
        key = ready.pop(0)
        order.append(key)
        for successor in sorted(outgoing[key]):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
                ready.sort()
    if len(order) != len(node_keys):
        remaining = sorted(key for key, degree in indegree.items() if degree > 0)
        raise PortfolioGraphError("GRAPH_CYCLE:" + "->".join(remaining))
    return order


def replace_graph(
    connection: sqlite3.Connection,
    plan: dict[str, Any],
    *,
    now: str,
    _transaction: bool = True,
    _ensure_schema: bool = True,
) -> dict[str, Any]:
    if not _transaction and (_ensure_schema or not connection.in_transaction):
        raise PortfolioGraphError("GRAPH_TRANSACTION_REQUIRED")
    if _ensure_schema:
        ensure_portfolio_graph_schema(connection)
    _validate_plan(plan)
    repository = plan["repository"]
    expected = plan["expected_current_version"]
    if _current_version(connection, repository) != expected:
        raise PortfolioGraphError("GRAPH_VERSION_CONFLICT")
    scope_kind, milestones, scoped_issue_numbers = _scope_details(plan)
    nodes = {node["node_key"]: node for node in plan["nodes"]}
    represented_issues = {node["issue_number"] for node in plan["nodes"]}
    excluded = {item["issue_number"] for item in plan["excluded_issues"]}
    for node in plan["nodes"]:
        source = _snapshot(connection, repository, node["issue_number"])
        if source["payload_sha256"] != node["source_payload_sha256"]:
            raise PortfolioGraphError("GRAPH_SOURCE_DRIFT")
        if scope_kind == "ISSUE_SET":
            _require_issue_set_snapshot(source)
    for exclusion in plan["excluded_issues"]:
        if scope_kind == "ISSUE_SET":
            source = _snapshot(connection, repository, exclusion["issue_number"])
            if source["payload_sha256"] != exclusion["source_payload_sha256"]:
                raise PortfolioGraphError("GRAPH_SOURCE_DRIFT")
            _require_issue_set_snapshot(source)
    scoped_open = (
        {
            int(row["object_number"])
            for row in connection.execute(
                """
                SELECT c.object_number
                FROM github_current c
                JOIN github_snapshots s
                  ON s.repository=c.repository
                 AND s.object_kind=c.object_kind
                 AND s.object_number=c.object_number
                 AND s.payload_sha256=c.payload_sha256
                WHERE c.repository=? AND c.object_kind='issue'
                  AND json_extract(s.payload_json, '$.state')='open'
                  AND json_extract(s.payload_json, '$.milestone.title') IN (
                      SELECT value FROM json_each(?)
                  )
                """,
                (repository, canonical_json(list(milestones))),
            )
        }
        if scope_kind == "MILESTONE"
        else set(scoped_issue_numbers)
    )
    if scoped_open - represented_issues - excluded:
        raise PortfolioGraphError(
            "GRAPH_SCOPE_INCOMPLETE:"
            + ",".join(str(number) for number in sorted(scoped_open - represented_issues - excluded))
        )
    hard_edges = [
        (relation["left_node_key"], relation["right_node_key"])
        for relation in plan["relations"]
        if relation["relation_kind"] == "HARD_BLOCK"
    ]
    _topological_order(set(nodes), hard_edges)
    incoming: dict[str, int] = defaultdict(int)
    outgoing: dict[str, int] = defaultdict(int)
    for left, right in hard_edges:
        incoming[right] += 1
        outgoing[left] += 1
    for key, node in nodes.items():
        if node["root_kind"] == "NORMAL" and incoming[key] == 0:
            raise PortfolioGraphError("GRAPH_ACTIONABLE_ORPHAN:" + key)
        if node["root_kind"] == "STANDALONE" and (incoming[key] or outgoing[key]):
            raise PortfolioGraphError("GRAPH_STANDALONE_HAS_EDGES:" + key)
    if scope_kind == "ISSUE_SET":
        for relation in plan["relations"]:
            endpoint_digests = {
                nodes[relation["left_node_key"]]["source_payload_sha256"],
                nodes[relation["right_node_key"]]["source_payload_sha256"],
            }
            if relation["source_payload_sha256"] not in endpoint_digests:
                raise PortfolioGraphError("GRAPH_RELATION_SOURCE_DRIFT")
    immutable_graph_payload = graph_payload(plan)
    graph_sha256 = digest_json(immutable_graph_payload)
    version = expected + 1
    if _transaction:
        connection.execute("BEGIN IMMEDIATE")
    try:
        if _current_version(connection, repository) != expected:
            raise PortfolioGraphError("GRAPH_VERSION_CONFLICT")
        for node in plan["nodes"]:
            source = _snapshot(connection, repository, node["issue_number"])
            if source["payload_sha256"] != node["source_payload_sha256"]:
                raise PortfolioGraphError("GRAPH_SOURCE_DRIFT")
            if scope_kind == "ISSUE_SET":
                _require_issue_set_snapshot(source)
        for exclusion in plan["excluded_issues"]:
            if scope_kind == "ISSUE_SET":
                source = _snapshot(connection, repository, exclusion["issue_number"])
                if source["payload_sha256"] != exclusion["source_payload_sha256"]:
                    raise PortfolioGraphError("GRAPH_SOURCE_DRIFT")
                _require_issue_set_snapshot(source)
        scoped_open_in_transaction = (
            {
                int(row["object_number"])
                for row in connection.execute(
                    """
                    SELECT c.object_number
                    FROM github_current c
                    JOIN github_snapshots s
                      ON s.repository=c.repository
                     AND s.object_kind=c.object_kind
                     AND s.object_number=c.object_number
                     AND s.payload_sha256=c.payload_sha256
                    WHERE c.repository=? AND c.object_kind='issue'
                      AND json_extract(s.payload_json, '$.state')='open'
                      AND json_extract(s.payload_json, '$.milestone.title') IN (
                          SELECT value FROM json_each(?)
                      )
                    """,
                    (repository, canonical_json(list(milestones))),
                )
            }
            if scope_kind == "MILESTONE"
            else set(scoped_issue_numbers)
        )
        if scoped_open_in_transaction - represented_issues - excluded:
            raise PortfolioGraphError("GRAPH_SCOPE_INCOMPLETE")
        connection.execute(
            """
            INSERT INTO portfolio_graph_revisions(
                repository, version, parent_version, accepted_main_sha,
                graph_sha256, scope_json, exclusions_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                repository,
                version,
                expected or None,
                plan["accepted_main_sha"],
                graph_sha256,
                canonical_json(
                    {"milestones": list(milestones)}
                    if scope_kind == "MILESTONE"
                    else {"kind": "ISSUE_SET", "issue_numbers": sorted(scoped_issue_numbers)}
                ),
                canonical_json(plan["excluded_issues"]),
                now,
            ),
        )
        prior_ready = {
            row["node_key"]: row["ready_at"]
            for row in connection.execute(
                """
                SELECT node_key, ready_at FROM portfolio_graph_nodes
                WHERE repository=? AND graph_version=?
                """,
                (repository, expected),
            )
        } if expected else {}
        for node in plan["nodes"]:
            payload = json.loads(_snapshot(connection, repository, node["issue_number"])["payload_json"])
            milestone = payload.get("milestone")
            milestone_title = milestone.get("title") if isinstance(milestone, dict) else None
            ready_at = prior_ready.get(node["node_key"], node["ready_at"])
            connection.execute(
                """
                INSERT INTO portfolio_graph_nodes(
                    repository, graph_version, node_key, issue_number, role, root_kind,
                    root_reason, milestone_title, milestone_rank, lane_key, lane_order,
                    dispatchable, priority_rank, estimate_units, development_units,
                    shared_units, sre_units, source_payload_sha256, ready_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository, version, node["node_key"], node["issue_number"],
                    node["role"], node["root_kind"], node["root_reason"],
                    milestone_title, milestones.get(milestone_title), node["lane_key"],
                    node["lane_order"], int(node["dispatchable"]),
                    node["priority_rank"], node["estimate_units"],
                    node["development_units"], node["shared_units"], node["sre_units"],
                    node["source_payload_sha256"], ready_at,
                ),
            )
        for relation in plan["relations"]:
            connection.execute(
                """
                INSERT INTO portfolio_graph_relations(
                    repository, graph_version, left_node_key, right_node_key,
                    relation_kind, reason, source_payload_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository, version, relation["left_node_key"],
                    relation["right_node_key"], relation["relation_kind"],
                    relation["reason"], relation["source_payload_sha256"],
                ),
            )
        connection.execute(
            """
            INSERT INTO portfolio_graph_current(
                repository, version, observed_main_sha, health, updated_at, last_error
            ) VALUES (?, ?, ?, 'CURRENT', ?, NULL)
            ON CONFLICT(repository) DO UPDATE SET
                version=excluded.version,
                observed_main_sha=excluded.observed_main_sha,
                health='CURRENT',
                updated_at=excluded.updated_at,
                last_error=NULL
            """,
            (repository, version, plan["accepted_main_sha"], now),
        )
        if _transaction:
            connection.execute("COMMIT")
    except Exception:
        if _transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return {
        "repository": repository,
        "version": version,
        "graph_sha256": graph_sha256,
        "node_count": len(nodes),
        "relation_count": len(plan["relations"]),
    }


def sync_head(
    connection: sqlite3.Connection,
    repository: str,
    sha: str,
    *,
    expected_version: int,
    expected_observed_main_sha: str,
    now: str,
    _ensure_schema: bool = True,
    _transaction: bool = True,
) -> dict[str, Any]:
    _validate_repository(repository)
    if (
        not GIT_SHA.fullmatch(sha)
        or type(expected_version) is not int
        or expected_version <= 0
        or not GIT_SHA.fullmatch(expected_observed_main_sha)
    ):
        raise PortfolioGraphError("GRAPH_MAIN_INVALID")
    if _ensure_schema:
        ensure_portfolio_graph_schema(connection)
    if _transaction:
        if connection.in_transaction:
            raise PortfolioGraphError("GRAPH_TRANSACTION_CONFLICT")
        connection.execute("BEGIN IMMEDIATE")
    elif not connection.in_transaction:
        raise PortfolioGraphError("GRAPH_TRANSACTION_REQUIRED")
    try:
        row = connection.execute(
            """
            SELECT c.version, c.observed_main_sha, c.health, c.last_error,
                   r.accepted_main_sha, r.scope_json
            FROM portfolio_graph_current c
            JOIN portfolio_graph_revisions r
              ON r.repository=c.repository AND r.version=c.version
            WHERE c.repository=?
            """,
            (repository,),
        ).fetchone()
        if row is None:
            raise PortfolioGraphError("GRAPH_NOT_FOUND")
        if (
            int(row["version"]) != expected_version
            or row["observed_main_sha"] != expected_observed_main_sha
        ):
            raise PortfolioGraphError("GRAPH_MAIN_CAS_DRIFT")
        try:
            scope = json.loads(row["scope_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise PortfolioGraphError("GRAPH_SCOPE_INVALID") from exc
        issue_set_scope = isinstance(scope, dict) and scope.get("kind") == "ISSUE_SET"
        # accepted_main_sha is immutable review provenance. Legacy milestone
        # graphs keep their historical mutable scheduling cursor, while
        # ISSUE_SET graphs are point-in-time inputs replaced after main moves.
        legacy_main_stale = (
            not issue_set_scope
            and row["health"] == "STALE"
            and row["last_error"] == "GRAPH_MAIN_DRIFT"
        )
        if issue_set_scope and sha != row["accepted_main_sha"]:
            health = "STALE"
            error = (
                row["last_error"]
                if row["health"] == "STALE"
                and row["last_error"] not in {None, "GRAPH_MAIN_DRIFT"}
                else "GRAPH_MAIN_DRIFT"
            )
        elif issue_set_scope and row["last_error"] == "GRAPH_MAIN_DRIFT":
            health = "CURRENT"
            error = None
        else:
            health = "CURRENT" if legacy_main_stale else row["health"]
            error = None if legacy_main_stale else row["last_error"]
        previous_main_sha = str(row["observed_main_sha"])
        changed = connection.execute(
            """
            UPDATE portfolio_graph_current
            SET observed_main_sha=?, health=?, updated_at=?, last_error=?
            WHERE repository=? AND version=? AND observed_main_sha=?
            """,
            (
                sha,
                health,
                now,
                error,
                repository,
                expected_version,
                expected_observed_main_sha,
            ),
        ).rowcount
        if changed != 1:
            raise PortfolioGraphError("GRAPH_MAIN_CAS_DRIFT")
        dirty_event_id = None
        if previous_main_sha != sha:
            trigger_issue = connection.execute(
                "SELECT MIN(issue_number) FROM portfolio_graph_nodes "
                "WHERE repository=? AND graph_version=?",
                (repository, int(row["version"])),
            ).fetchone()[0]
            if trigger_issue is None:
                raise PortfolioGraphError("GRAPH_NODE_INVALID")
            dirty_event_id = enqueue_convergence_dirty_event(
                connection,
                repository=repository,
                trigger_kind="MAIN_CURSOR_ADVANCED",
                issue_number=int(trigger_issue),
                item_version=int(row["version"]),
                source_sha256=digest_json({"observed_main_sha": sha}),
                status="CURSOR",
                generation=int(row["version"]),
                now=now,
                details={
                    "previous_main_sha": previous_main_sha,
                    "observed_main_sha": sha,
                },
            )
        result = {
            "repository": repository,
            "version": int(row["version"]),
            "health": health,
            "portfolio_dirty_event_id": dirty_event_id,
        }
        if _transaction:
            connection.execute("COMMIT")
        return result
    except BaseException:
        if _transaction and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _load_graph(
    connection: sqlite3.Connection, repository: str, *, ensure_schema: bool = True
) -> tuple[sqlite3.Row, dict[str, sqlite3.Row], list[sqlite3.Row]]:
    if ensure_schema:
        ensure_portfolio_graph_schema(connection)
    current = connection.execute(
        """
        SELECT c.*, r.accepted_main_sha, r.graph_sha256, r.scope_json,
               r.exclusions_json
        FROM portfolio_graph_current c
        JOIN portfolio_graph_revisions r
          ON r.repository=c.repository AND r.version=c.version
        WHERE c.repository=?
        """,
        (repository,),
    ).fetchone()
    if current is None:
        raise PortfolioGraphError("GRAPH_NOT_FOUND")
    nodes = {
        row["node_key"]: row
        for row in connection.execute(
            """
            SELECT * FROM portfolio_graph_nodes
            WHERE repository=? AND graph_version=?
            """,
            (repository, current["version"]),
        )
    }
    relations = list(
        connection.execute(
            """
            SELECT * FROM portfolio_graph_relations
            WHERE repository=? AND graph_version=?
            """,
            (repository, current["version"]),
        )
    )
    return current, nodes, relations


def _terminal(
    connection: sqlite3.Connection, repository: str, issue_number: int
) -> bool:
    item = connection.execute(
        """
        SELECT status FROM coordination_items
        WHERE repository=? AND issue_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if item is not None:
        return item["status"] in TERMINAL_STATUSES
    try:
        snapshot = _snapshot(connection, repository, issue_number)
    except PortfolioGraphError:
        return False
    payload = json.loads(snapshot["payload_json"])
    return payload.get("state") == "closed"


def evaluate_graph(
    connection: sqlite3.Connection,
    repository: str,
    *,
    current_main: str,
    _ensure_schema: bool = True,
) -> dict[str, Any]:
    _validate_repository(repository)
    if not GIT_SHA.fullmatch(current_main):
        raise PortfolioGraphError("GRAPH_MAIN_INVALID")
    current, nodes, relations = _load_graph(
        connection, repository, ensure_schema=_ensure_schema
    )
    stale_reasons: list[str] = []
    if current["health"] != "CURRENT":
        stale_reasons.append(str(current["last_error"] or "GRAPH_STALE"))
    if current["observed_main_sha"] != current_main:
        stale_reasons.append("GRAPH_CURSOR_DRIFT")
    for node in nodes.values():
        try:
            source = _snapshot(connection, repository, int(node["issue_number"]))
        except PortfolioGraphError:
            stale_reasons.append(f"GRAPH_SOURCE_MISSING:{node['node_key']}")
            continue
        if source["payload_sha256"] != node["source_payload_sha256"]:
            stale_reasons.append(f"GRAPH_SOURCE_DRIFT:{node['node_key']}")
    try:
        scope = json.loads(current["scope_json"])
        exclusions = json.loads(current["exclusions_json"])
    except (TypeError, json.JSONDecodeError):
        stale_reasons.append("GRAPH_SCOPE_INVALID")
        scope = {}
        exclusions = []
    if isinstance(scope, dict) and scope.get("kind") == "ISSUE_SET":
        if not isinstance(exclusions, list):
            stale_reasons.append("GRAPH_SCOPE_INVALID")
            exclusions = []
        for exclusion in exclusions:
            if not isinstance(exclusion, dict):
                stale_reasons.append("GRAPH_SCOPE_INVALID")
                continue
            issue_number = exclusion.get("issue_number")
            expected_source = exclusion.get("source_payload_sha256")
            try:
                source = _snapshot(connection, repository, int(issue_number))
            except (PortfolioGraphError, TypeError, ValueError):
                stale_reasons.append(f"GRAPH_SOURCE_MISSING:issue:{issue_number}")
                continue
            if source["payload_sha256"] != expected_source:
                stale_reasons.append(f"GRAPH_SOURCE_DRIFT:issue:{issue_number}")
    hard_edges = [
        (row["left_node_key"], row["right_node_key"])
        for row in relations
        if row["relation_kind"] == "HARD_BLOCK"
    ]
    order = _topological_order(set(nodes), hard_edges)
    predecessors: dict[str, list[str]] = defaultdict(list)
    successors: dict[str, list[str]] = defaultdict(list)
    for left, right in hard_edges:
        predecessors[right].append(left)
        successors[left].append(right)
    terminal = {
        key: _terminal(connection, repository, int(node["issue_number"]))
        for key, node in nodes.items()
    }
    critical: dict[str, int] = {}
    descendants: dict[str, set[str]] = defaultdict(set)
    for key in reversed(order):
        critical[key] = 0 if terminal[key] else int(nodes[key]["estimate_units"]) + max(
            (critical[child] for child in successors[key]), default=0
        )
        for child in successors[key]:
            descendants[key].add(child)
            descendants[key].update(descendants[child])
    items = {
        int(row["issue_number"]): row
        for row in connection.execute(
            "SELECT * FROM coordination_items WHERE repository=?",
            (repository,),
        )
    }
    projections: list[dict[str, Any]] = []
    for key in order:
        node = nodes[key]
        blockers = [
            predecessor for predecessor in sorted(predecessors[key])
            if not terminal[predecessor]
        ]
        item = items.get(int(node["issue_number"]))
        item_status = None if item is None else item["status"]
        structurally_ready = (
            bool(node["dispatchable"]) and not terminal[key] and not blockers
        )
        immediate_unlocks = sum(
            1
            for child in successors[key]
            if all(
                terminal[pred] or pred == key
                for pred in predecessors[child]
            )
        )
        orphan = (
            not terminal[key]
            and node["root_kind"] == "NORMAL"
            and not predecessors[key]
        )
        projections.append(
            {
                "node_key": key,
                "issue_number": int(node["issue_number"]),
                "role": node["role"],
                "milestone_title": node["milestone_title"],
                "milestone_rank": node["milestone_rank"],
                "item_status": item_status,
                "terminal": terminal[key],
                "blocked_by": blockers,
                "structurally_ready": structurally_ready,
                "executable_ready": structurally_ready and item_status == "READY",
                "actionable_orphan": orphan,
                "critical_path_units": critical[key],
                "descendant_count": len(descendants[key]),
                "immediate_unlocks": immediate_unlocks,
                "critical_hold": (
                    node["role"] == "SERIAL_GATE"
                    and item_status == "HOLD"
                    and bool(descendants[key])
                ),
            }
        )
    inversions = [
        {
            "predecessor": left,
            "successor": right,
            "predecessor_milestone": nodes[left]["milestone_title"],
            "successor_milestone": nodes[right]["milestone_title"],
        }
        for left, right in hard_edges
        if nodes[left]["milestone_rank"] is not None
        and nodes[right]["milestone_rank"] is not None
        and int(nodes[left]["milestone_rank"]) > int(nodes[right]["milestone_rank"])
    ]
    return {
        "repository": repository,
        "version": int(current["version"]),
        "graph_sha256": current["graph_sha256"],
        "health": "STALE" if stale_reasons else "CURRENT",
        "stale_reasons": sorted(set(stale_reasons)),
        "milestone_inversions": inversions,
        "critical_path_holds": [
            item["node_key"] for item in projections if item["critical_hold"]
        ],
        "nodes": projections,
    }


def evaluate_graph_for_admission_lineage(
    connection: sqlite3.Connection,
    repository: str,
    *,
    current_main: str,
    item: sqlite3.Row,
    message: sqlite3.Row,
    watch: sqlite3.Row,
) -> dict[str, Any]:
    """Permit only the exact receipt-bound source reason for one admission."""

    result = evaluate_graph(connection, repository, current_main=current_main, _ensure_schema=False)
    if result["health"] == "CURRENT":
        return result
    current = connection.execute(
        "SELECT payload_sha256 FROM github_current WHERE repository=? AND object_kind='issue' AND object_number=?",
        (repository, item["issue_number"]),
    ).fetchone()
    node = connection.execute(
        "SELECT node_key FROM portfolio_graph_nodes WHERE repository=? AND graph_version=? AND issue_number=?",
        (repository, result["version"], item["issue_number"]),
    ).fetchone()
    allowed = {"GRAPH_SOURCE_DRIFT", f"GRAPH_SOURCE_DRIFT:issue:{int(item['issue_number'])}"}
    if node is not None:
        allowed.add(f"GRAPH_SOURCE_DRIFT:{node['node_key']}")
    if (current is not None and result["stale_reasons"]
            and set(result["stale_reasons"]).issubset(allowed)
            and admission_lineage_source_is_current(
                connection, item=item, message=message, watch=watch,
                current_source_sha256=str(current["payload_sha256"]),
            )):
        return {**result, "health": "CURRENT", "stale_reasons": [], "source_equivalence": True}
    return result


def _capacity_policy(connection: sqlite3.Connection, repository: str) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT p.* FROM coordination_capacity_current c
        JOIN coordination_capacity_policies p
          ON p.repository=c.repository AND p.version=c.version
        WHERE c.repository=?
        """,
        (repository,),
    ).fetchone()
    if row is None:
        raise PortfolioGraphError("CAPACITY_POLICY_MISSING")
    return row


def reserved_hosted_sre_units(
    connection: sqlite3.Connection, repository: str
) -> int:
    """Return SRE units fenced by hosted operations, if that module is installed."""
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hosted_operations'"
    ).fetchone()
    if table is None:
        return 0
    row = connection.execute(
        """
        SELECT COALESCE(SUM(sre_units), 0)
        FROM hosted_operations
        WHERE repository=? AND state IN ('PREPARED','CLAIMED')
        """,
        (repository,),
    ).fetchone()
    return int(row[0])


def _schedule_decision(
    connection: sqlite3.Connection,
    repository: str,
    *,
    current_main: str,
    record: bool,
    now: str,
) -> dict[str, Any]:
    evaluation = evaluate_graph(
        connection,
        repository,
        current_main=current_main,
        _ensure_schema=False,
    )
    if evaluation["health"] != "CURRENT":
        raise PortfolioGraphError("GRAPH_STALE")
    current, nodes, relations = _load_graph(
        connection, repository, ensure_schema=False
    )
    projections = {item["node_key"]: item for item in evaluation["nodes"]}
    collisions: set[frozenset[str]] = {
        frozenset((row["left_node_key"], row["right_node_key"]))
        for row in relations
        if row["relation_kind"] == "COLLISION"
    }
    issue_to_keys: dict[int, list[str]] = defaultdict(list)
    for key, node in nodes.items():
        issue_to_keys[int(node["issue_number"])].append(key)
    occupied = connection.execute(
        """
        SELECT COALESCE(SUM(development_units),0) AS development,
               COALESCE(SUM(shared_units),0) AS shared,
               COALESCE(SUM(sre_units),0) AS sre
        FROM coordination_items
        WHERE repository=? AND allocation_class IN ('ACTIVE','RETAINED')
        """,
        (repository,),
    ).fetchone()
    policy = _capacity_policy(connection, repository)
    remaining = {
        "development": int(policy["development_limit"]) - int(occupied["development"]),
        "shared": int(policy["shared_limit"]) - int(occupied["shared"]),
        "sre": (
            int(policy["sre_limit"])
            - int(occupied["sre"])
            - reserved_hosted_sre_units(connection, repository)
        ),
    }
    active_keys: set[str] = set()
    active_allocation_count = 0
    for row in connection.execute(
        """
        SELECT issue_number FROM coordination_items
        WHERE repository=? AND allocation_class IN ('ACTIVE','RETAINED')
        """,
        (repository,),
    ):
        active_allocation_count += 1
        active_keys.update(issue_to_keys.get(int(row["issue_number"]), []))
    repository_policy = policy_for_repository(repository)
    exclusive_repository_writer = bool(
        repository_policy is not None
        and repository_policy.exclusive_repository_writer
    )
    candidates = [
        key for key, projection in projections.items()
        if projection["executable_ready"]
    ]
    candidates.sort(
        key=lambda key: (
            int(nodes[key]["priority_rank"]),
            int(nodes[key]["lane_order"]),
            str(nodes[key]["ready_at"]),
            -int(projections[key]["critical_path_units"]),
            -int(projections[key]["immediate_unlocks"]),
            -int(projections[key]["descendant_count"]),
            key,
        )
    )
    selected: list[str] = []
    skipped: list[dict[str, str]] = []
    for key in candidates:
        node = nodes[key]
        reason = None
        if exclusive_repository_writer and (active_allocation_count or selected):
            reason = "REPOSITORY_WRITER_MUTEX"
        elif any(frozenset((key, other)) in collisions for other in active_keys | set(selected)):
            reason = "COLLISION"
        elif int(node["development_units"]) > remaining["development"]:
            reason = "DEVELOPMENT_CAPACITY"
        elif int(node["shared_units"]) > remaining["shared"]:
            reason = "SHARED_CAPACITY"
        elif int(node["sre_units"]) > remaining["sre"]:
            reason = "SRE_CAPACITY"
        if reason is not None:
            skipped.append({"node_key": key, "reason": reason})
            continue
        selected.append(key)
        remaining["development"] -= int(node["development_units"])
        remaining["shared"] -= int(node["shared_units"])
        remaining["sre"] -= int(node["sre_units"])
    decision = {
        "repository": repository,
        "graph_version": evaluation["version"],
        "capacity_policy_version": int(policy["version"]),
        "ordered_ready": candidates,
        "selected": selected,
        "skipped": skipped,
        "remaining_capacity": remaining,
    }
    decision_sha256 = digest_json(decision)
    if record:
        for key in candidates:
            connection.execute(
                """
                INSERT OR IGNORE INTO portfolio_scheduler_events(
                    repository, graph_version, decision_sha256, node_key,
                    event_type, reason_code, created_at
                ) VALUES (?, ?, ?, ?, 'READY', 'DEPENDENCIES_SATISFIED', ?)
                """,
                (repository, evaluation["version"], decision_sha256, key, now),
            )
        for key in selected:
            connection.execute(
                """
                INSERT OR IGNORE INTO portfolio_scheduler_events(
                    repository, graph_version, decision_sha256, node_key,
                    event_type, reason_code, created_at
                ) VALUES (?, ?, ?, ?, 'SELECT', 'FIFO_CAPACITY_FIT', ?)
                """,
                (repository, evaluation["version"], decision_sha256, key, now),
            )
        for skipped_item in skipped:
            connection.execute(
                """
                INSERT OR IGNORE INTO portfolio_scheduler_events(
                    repository, graph_version, decision_sha256, node_key,
                    event_type, reason_code, created_at
                ) VALUES (?, ?, ?, ?, 'SKIP', ?, ?)
                """,
                (
                    repository,
                    evaluation["version"],
                    decision_sha256,
                    skipped_item["node_key"],
                    skipped_item["reason"],
                    now,
                ),
            )
    return {**decision, "decision_sha256": decision_sha256}


def schedule(
    connection: sqlite3.Connection,
    repository: str,
    *,
    current_main: str,
    record: bool,
    now: str,
) -> dict[str, Any]:
    ensure_portfolio_graph_schema(connection)
    if not record:
        return _schedule_decision(
            connection,
            repository,
            current_main=current_main,
            record=False,
            now=now,
        )
    connection.execute("BEGIN IMMEDIATE")
    try:
        decision = _schedule_decision(
            connection,
            repository,
            current_main=current_main,
            record=True,
            now=now,
        )
        connection.execute("COMMIT")
        return decision
    except Exception:
        connection.execute("ROLLBACK")
        raise


def validate_portfolio_transition(
    connection: sqlite3.Connection,
    *,
    repository: str,
    issue_number: int,
    status: str,
    allocation_class: str,
    current_main: str | None = None,
) -> None:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
            "('portfolio_graph_current','portfolio_graph_nodes')"
        )
    }
    if len(tables) != 2:
        return
    current = connection.execute(
        """
        SELECT c.*, r.accepted_main_sha
        FROM portfolio_graph_current c
        JOIN portfolio_graph_revisions r
          ON r.repository=c.repository AND r.version=c.version
        WHERE c.repository=?
        """,
        (repository,),
    ).fetchone()
    if current is None:
        return
    nodes = list(
        connection.execute(
            """
            SELECT * FROM portfolio_graph_nodes
            WHERE repository=? AND graph_version=? AND issue_number=?
            """,
            (repository, current["version"], issue_number),
        )
    )
    if not nodes:
        return
    if status == "DONE" and allocation_class == "NONE":
        item = connection.execute(
            """
            SELECT allocation_class FROM coordination_items
            WHERE repository=? AND issue_number=?
            """,
            (repository, issue_number),
        ).fetchone()
        source = _snapshot(connection, repository, issue_number)
        if (
            item is not None
            and item["allocation_class"] in {"ACTIVE", "RETAINED"}
            and json.loads(source["payload_json"]).get("state") == "closed"
        ):
            # Closing verified WIP is monotonic and frees capacity. A stale
            # graph may stop new admission, but must not retain closed work.
            return
    if current["health"] != "CURRENT":
        raise PortfolioGraphError("GRAPH_STALE")
    if current_main is not None and current["observed_main_sha"] != current_main:
        raise PortfolioGraphError("GRAPH_CURSOR_DRIFT")
    for node in nodes:
        source = _snapshot(connection, repository, issue_number)
        if source["payload_sha256"] != node["source_payload_sha256"]:
            raise PortfolioGraphError("GRAPH_SOURCE_DRIFT")
        predecessor_rows = connection.execute(
            """
            SELECT predecessor.issue_number
            FROM portfolio_graph_relations relation
            JOIN portfolio_graph_nodes predecessor
              ON predecessor.repository=relation.repository
             AND predecessor.graph_version=relation.graph_version
             AND predecessor.node_key=relation.left_node_key
            WHERE relation.repository=? AND relation.graph_version=?
              AND relation.right_node_key=? AND relation.relation_kind='HARD_BLOCK'
            """,
            (repository, current["version"], node["node_key"]),
        )
        blockers = [
            int(row["issue_number"])
            for row in predecessor_rows
            if not _terminal(connection, repository, int(row["issue_number"]))
        ]
        if status in EXECUTION_STATUSES and blockers:
            raise PortfolioGraphError(
                "GRAPH_HARD_PREDECESSOR_UNSATISFIED:"
                + ",".join(str(number) for number in sorted(blockers))
            )
        if status in {"ACTIVE", "ACTIVE_FENCED"}:
            collision = connection.execute(
                """
                SELECT other.issue_number
                FROM portfolio_graph_relations relation
                JOIN portfolio_graph_nodes other
                  ON other.repository=relation.repository
                 AND other.graph_version=relation.graph_version
                 AND other.node_key=CASE
                     WHEN relation.left_node_key=? THEN relation.right_node_key
                     ELSE relation.left_node_key
                 END
                JOIN coordination_items item
                  ON item.repository=other.repository
                 AND item.issue_number=other.issue_number
                 AND item.allocation_class IN ('ACTIVE','RETAINED')
                WHERE relation.repository=? AND relation.graph_version=?
                  AND relation.relation_kind='COLLISION'
                  AND (relation.left_node_key=? OR relation.right_node_key=?)
                  AND other.issue_number<>?
                LIMIT 1
                """,
                (
                    node["node_key"],
                    repository,
                    current["version"],
                    node["node_key"],
                    node["node_key"],
                    issue_number,
                ),
            ).fetchone()
            if collision is not None:
                raise PortfolioGraphError(
                    f"GRAPH_COLLISION_ACTIVE:{int(collision['issue_number'])}"
                )
        if node["role"] == "SERIAL_GATE":
            descendants = connection.execute(
                """
                WITH RECURSIVE descendants(node_key) AS (
                    SELECT right_node_key FROM portfolio_graph_relations
                    WHERE repository=? AND graph_version=?
                      AND left_node_key=? AND relation_kind='HARD_BLOCK'
                    UNION
                    SELECT relation.right_node_key
                    FROM portfolio_graph_relations relation
                    JOIN descendants d ON d.node_key=relation.left_node_key
                    WHERE relation.repository=? AND relation.graph_version=?
                      AND relation.relation_kind='HARD_BLOCK'
                )
                SELECT node.issue_number
                FROM descendants
                JOIN portfolio_graph_nodes node
                  ON node.repository=? AND node.graph_version=?
                 AND node.node_key=descendants.node_key
                """,
                (
                    repository, current["version"], node["node_key"],
                    repository, current["version"], repository, current["version"],
                ),
            )
            unfinished = [
                int(row["issue_number"])
                for row in descendants
                if not _terminal(connection, repository, int(row["issue_number"]))
            ]
            if unfinished and (
                status in STABLE_PARK_STATUSES
                or (
                    allocation_class == "NONE"
                    and status not in {"READY", "DONE"}
                )
            ):
                raise PortfolioGraphError("GRAPH_SERIAL_GATE_PARKED")


def _connect(path: Path) -> sqlite3.Connection:
    try:
        prepare_owner_database(path)
    except UnsafeSQLitePathError as exc:
        raise PortfolioGraphError(str(exc)) from exc
    connection = sqlite3.connect(path, isolation_level=None, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA busy_timeout=5000")
    ensure_portfolio_graph_schema(connection)
    return connection


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    commands = parser.add_subparsers(dest="command", required=True)
    replace = commands.add_parser("replace")
    replace.add_argument("--file", type=Path, required=True)
    sync = commands.add_parser("sync-head")
    sync.add_argument("--repository", required=True)
    sync.add_argument("--sha", required=True)
    sync.add_argument("--expected-version", required=True, type=int)
    sync.add_argument("--expected-observed-main-sha", required=True)
    check = commands.add_parser("check")
    check.add_argument("--repository", required=True)
    check.add_argument("--current-main", required=True)
    queue = commands.add_parser("schedule")
    queue.add_argument("--repository", required=True)
    queue.add_argument("--current-main", required=True)
    queue.add_argument("--record", action="store_true")
    explain = commands.add_parser("explain")
    explain.add_argument("--repository", required=True)
    explain.add_argument("--current-main", required=True)
    explain.add_argument("--node", required=True)
    guard = commands.add_parser("guard-transition")
    guard.add_argument("--repository", required=True)
    guard.add_argument("--issue-number", type=int, required=True)
    guard.add_argument("--status", required=True)
    guard.add_argument("--allocation-class", required=True)
    guard.add_argument("--current-main")
    args = parser.parse_args()
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect(args.database)
        if args.command == "replace":
            plan = json.loads(args.file.read_text(encoding="utf-8"))
            result = replace_graph(connection, plan, now=utc_now())
        elif args.command == "sync-head":
            result = sync_head(
                connection,
                args.repository,
                args.sha,
                expected_version=args.expected_version,
                expected_observed_main_sha=args.expected_observed_main_sha,
                now=utc_now(),
            )
        elif args.command == "check":
            result = evaluate_graph(
                connection, args.repository, current_main=args.current_main
            )
        elif args.command == "schedule":
            result = schedule(
                connection,
                args.repository,
                current_main=args.current_main,
                record=args.record,
                now=utc_now(),
            )
        elif args.command == "explain":
            evaluation = evaluate_graph(
                connection, args.repository, current_main=args.current_main
            )
            matches = [
                node for node in evaluation["nodes"] if node["node_key"] == args.node
            ]
            if not matches:
                raise PortfolioGraphError("GRAPH_NODE_NOT_FOUND")
            result = {
                "repository": args.repository,
                "version": evaluation["version"],
                "health": evaluation["health"],
                "node": matches[0],
            }
        else:
            validate_portfolio_transition(
                connection,
                repository=args.repository,
                issue_number=args.issue_number,
                status=args.status,
                allocation_class=args.allocation_class,
                current_main=args.current_main,
            )
            result = {"allowed": True}
        print(canonical_json({"phase": "COMPLETE", "result": result}))
        return 0
    except (PortfolioGraphError, json.JSONDecodeError) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
