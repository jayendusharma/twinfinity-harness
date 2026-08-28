#!/usr/bin/env python3
"""Request bounded Planner preparation for structurally ready zero-WIP work."""

from __future__ import annotations

from typing import Any

from coordination_store import CoordinationStore, digest_json
from executor_registry import RegistryError, current_endpoint
from portfolio_graph import PortfolioGraphError, evaluate_graph


SCHEMA = "twinfinity-kanban-make-ready/v1"
MAX_CANDIDATES = 2
ZERO_WIP_STATUSES = {"PREPARED", "QUEUED"}


class KanbanMakeReadyError(ValueError):
    """Typed bounded make-ready validation error."""


def _hold(repository: str, reason: str) -> dict[str, Any]:
    return {
        "repository": repository,
        "state": "HOLD",
        "reason": reason,
        "planned": [],
        "skipped": [],
    }


def _skip(row: Any, reason: str, **evidence: Any) -> dict[str, Any]:
    return {
        "issue_number": int(row["issue_number"]),
        "node_key": str(row["node_key"]),
        "state": "SKIPPED",
        "reason": reason,
        **evidence,
    }


def _notice(binding: dict[str, Any], binding_sha256: str) -> dict[str, Any]:
    issue_number = int(binding["issue_number"])
    return {
        "source": {
            "repository": binding["repository"],
            "object_kind": "issue",
            "object_number": issue_number,
            "payload_sha256": binding["source_payload_sha256"],
        },
        "notice_kind": "planning_request",
        "mutation_authority": False,
        "subject": f"Issue {issue_number} Kanban make-ready request",
        "summary": (
            "This structurally ready zero-WIP issue lacks a current preparation "
            "packet or readiness plan. The request carries no writer allocation."
        ),
        "evidence": {
            **binding,
            "binding_sha256": binding_sha256,
        },
        "requested_evidence": [
            "One source-current prepared candidate and candidate-level readiness "
            "plan, or one typed Planner disposition."
        ],
        "next_observation": (
            "A later bounded pass may dispatch only an existing PENDING readiness "
            "campaign; this notice does not create READY or delivery authority."
        ),
    }


def sweep(
    store: CoordinationStore,
    repository: str,
    *,
    max_candidates: int,
    now: str,
    audit_invalid: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Enqueue at most the unused readiness slots as idempotent Planner notices."""

    if (
        type(max_candidates) is not int
        or max_candidates < 0
        or max_candidates > MAX_CANDIDATES
    ):
        raise KanbanMakeReadyError("MAKE_READY_LIMIT_INVALID")
    if max_candidates == 0:
        return {
            "repository": repository,
            "state": "COMPLETE",
            "max_candidates": 0,
            "planned": [],
            "skipped": [],
            "available_after": 0,
        }

    connection = store.connection
    with store.transaction():
        graph = connection.execute(
            """
            SELECT current.version, current.observed_main_sha, current.health,
                   revision.accepted_main_sha, revision.graph_sha256
            FROM portfolio_graph_current current
            JOIN portfolio_graph_revisions revision
              ON revision.repository=current.repository
             AND revision.version=current.version
            WHERE current.repository=?
            """,
            (repository,),
        ).fetchone()
        if graph is None:
            return _hold(repository, "GRAPH_BINDING_MISSING")
        if graph["health"] != "CURRENT":
            return _hold(repository, "GRAPH_STALE")
        if graph["observed_main_sha"] != graph["accepted_main_sha"]:
            return _hold(repository, "GRAPH_MAIN_DRIFT")

        try:
            evaluation = evaluate_graph(
                connection,
                repository,
                current_main=str(graph["observed_main_sha"]),
                _ensure_schema=False,
            )
        except PortfolioGraphError as exc:
            return _hold(repository, f"GRAPH_DRIFT:{exc}")
        if evaluation["health"] != "CURRENT":
            return _hold(
                repository,
                "GRAPH_DRIFT:" + ",".join(evaluation["stale_reasons"]),
            )

        policy = connection.execute(
            """
            SELECT policy.version
            FROM coordination_capacity_current current
            JOIN coordination_capacity_policies policy
              ON policy.repository=current.repository
             AND policy.version=current.version
            WHERE current.repository=?
            """,
            (repository,),
        ).fetchone()
        if policy is None:
            return _hold(repository, "CAPACITY_POLICY_MISSING")
        try:
            planner = current_endpoint(connection, "planner")
        except RegistryError:
            planner = None
        if planner is None:
            return _hold(repository, "CURRENT_PLANNER_ENDPOINT_REQUIRED")

        projections = {
            str(item["node_key"]): item for item in evaluation["nodes"]
        }
        rows = connection.execute(
            """
            SELECT node.*,
                   item.status AS item_status,
                   item.allocation_class,
                   item.generation AS item_generation,
                   item.version AS item_version,
                   item.source_payload_sha256 AS item_source_sha256,
                   source.payload_sha256 AS current_source_sha256,
                   pointer.candidate_id,
                   candidate.state AS candidate_state,
                   candidate.candidate_sha256,
                   candidate.generation AS candidate_generation,
                   candidate.item_version AS candidate_item_version,
                   candidate.source_payload_sha256 AS candidate_source_sha256,
                   candidate.accepted_main_sha AS candidate_main_sha,
                   candidate.graph_version AS candidate_graph_version,
                   candidate.capacity_policy_version AS candidate_policy_version,
                   readiness.campaign_id,
                   readiness.state AS campaign_state
            FROM portfolio_graph_nodes node
            LEFT JOIN coordination_items item
              ON item.repository=node.repository
             AND item.issue_number=node.issue_number
            LEFT JOIN github_current source
              ON source.repository=node.repository
             AND source.object_kind='issue'
             AND source.object_number=node.issue_number
            LEFT JOIN portfolio_pull_buffer_current pointer
              ON pointer.repository=node.repository
             AND pointer.issue_number=node.issue_number
            LEFT JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=pointer.candidate_id
            LEFT JOIN portfolio_readiness_current readiness
              ON readiness.repository=node.repository
             AND readiness.issue_number=node.issue_number
            WHERE node.repository=? AND node.graph_version=?
            ORDER BY node.priority_rank, node.lane_order, node.ready_at,
                     node.issue_number, node.node_key
            """,
            (repository, int(graph["version"])),
        ).fetchall()

        active_keys = {
            str(row["node_key"])
            for row in connection.execute(
                """
                SELECT node.node_key
                FROM portfolio_graph_nodes node
                JOIN coordination_items item
                  ON item.repository=node.repository
                 AND item.issue_number=node.issue_number
                WHERE node.repository=? AND node.graph_version=?
                  AND item.allocation_class IN ('ACTIVE','RETAINED')
                """,
                (repository, int(graph["version"])),
            )
        }
        collisions: dict[str, set[str]] = {}
        for relation in connection.execute(
            """
            SELECT left_node_key, right_node_key
            FROM portfolio_graph_relations
            WHERE repository=? AND graph_version=? AND relation_kind='COLLISION'
            """,
            (repository, int(graph["version"])),
        ):
            left = str(relation["left_node_key"])
            right = str(relation["right_node_key"])
            if right in active_keys:
                collisions.setdefault(left, set()).add(right)
            if left in active_keys:
                collisions.setdefault(right, set()).add(left)

        invalid_by_issue = {
            int(item["issue_number"]): list(item.get("reasons") or [])
            for item in (audit_invalid or [])
            if isinstance(item, dict) and type(item.get("issue_number")) is int
        }

        eligible: list[tuple[Any, dict[str, Any], str]] = []
        skipped: list[dict[str, Any]] = []
        for row in rows:
            projection = projections[str(row["node_key"])]
            if int(row["issue_number"]) in invalid_by_issue:
                skipped.append(
                    _skip(
                        row,
                        "PULL_BUFFER_INVALID",
                        reasons=invalid_by_issue[int(row["issue_number"])],
                    )
                )
                continue
            if projection["terminal"]:
                skipped.append(_skip(row, "TERMINAL"))
                continue
            if projection["blocked_by"]:
                skipped.append(
                    _skip(
                        row,
                        "HARD_PREDECESSOR_UNSATISFIED",
                        blocked_by=list(projection["blocked_by"]),
                    )
                )
                continue
            if not projection["structurally_ready"]:
                skipped.append(_skip(row, "NOT_DISPATCHABLE"))
                continue
            if row["item_status"] is None:
                skipped.append(_skip(row, "ITEM_MISSING"))
                continue
            if (
                row["allocation_class"] != "NONE"
                or row["item_status"] not in ZERO_WIP_STATUSES
            ):
                skipped.append(_skip(row, "NOT_ZERO_WIP"))
                continue
            if (
                row["item_source_sha256"] != row["source_payload_sha256"]
                or row["current_source_sha256"] != row["source_payload_sha256"]
            ):
                skipped.append(_skip(row, "SOURCE_DRIFT"))
                continue
            if str(row["node_key"]) in collisions:
                skipped.append(
                    _skip(
                        row,
                        "MUTABLE_COLLISION",
                        collides_with=sorted(collisions[str(row["node_key"])]),
                    )
                )
                continue
            if row["campaign_id"] is not None:
                skipped.append(
                    _skip(
                        row,
                        "EXISTING_READINESS_CAMPAIGN",
                        campaign_id=int(row["campaign_id"]),
                        campaign_state=str(row["campaign_state"]),
                    )
                )
                continue

            if row["candidate_id"] is None:
                candidate = {
                    "need": "PACKET_MISSING",
                    "candidate_id": None,
                    "candidate_sha256": None,
                    "candidate_state": "MISSING",
                }
            elif (
                row["candidate_state"] != "PREPARED_NOT_READY"
                or int(row["candidate_generation"]) != int(row["item_generation"])
                or int(row["candidate_item_version"]) != int(row["item_version"])
                or row["candidate_source_sha256"] != row["source_payload_sha256"]
                or row["candidate_main_sha"] != graph["observed_main_sha"]
                or int(row["candidate_graph_version"]) != int(graph["version"])
                or int(row["candidate_policy_version"]) != int(policy["version"])
            ):
                skipped.append(_skip(row, "CANDIDATE_DRIFT"))
                continue
            else:
                candidate = {
                    "need": "PLAN_MISSING",
                    "candidate_id": int(row["candidate_id"]),
                    "candidate_sha256": str(row["candidate_sha256"]),
                    "candidate_state": str(row["candidate_state"]),
                }

            binding = {
                "schema": SCHEMA,
                "repository": repository,
                "issue_number": int(row["issue_number"]),
                "node_key": str(row["node_key"]),
                "source_payload_sha256": str(row["source_payload_sha256"]),
                "accepted_main_sha": str(graph["observed_main_sha"]),
                "graph_version": int(graph["version"]),
                "graph_sha256": str(graph["graph_sha256"]),
                "capacity_policy_version": int(policy["version"]),
                "item_generation": int(row["item_generation"]),
                "item_version": int(row["item_version"]),
                "item_status": str(row["item_status"]),
                **candidate,
                "campaign_id": None,
                "campaign_state": "MISSING",
                "planner_endpoint_id": str(planner["endpoint_id"]),
                "planner_pointer_version": int(planner["pointer_version"]),
            }
            eligible.append((row, binding, digest_json(binding)))

        planned: list[dict[str, Any]] = []
        for row, binding, binding_sha256 in eligible[:max_candidates]:
            idempotency_key = f"kanban-make-ready:{binding_sha256}"
            prior = connection.execute(
                "SELECT id FROM coordination_messages WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            message_id = store.enqueue_message(
                idempotency_key=idempotency_key,
                recipient_session_id=str(planner["endpoint_id"]),
                topic="coordination.notice",
                payload=_notice(binding, binding_sha256),
                now=now,
                _transaction=False,
            )
            planned.append(
                {
                    "issue_number": int(row["issue_number"]),
                    "node_key": str(row["node_key"]),
                    "need": str(binding["need"]),
                    "message_id": message_id,
                    "binding_sha256": binding_sha256,
                    "state": "REUSED" if prior is not None else "PREPARED",
                }
            )

        return {
            "repository": repository,
            "state": "COMPLETE",
            "max_candidates": max_candidates,
            "graph_version": int(graph["version"]),
            "capacity_policy_version": int(policy["version"]),
            "accepted_main_sha": str(graph["observed_main_sha"]),
            "planned": planned,
            "skipped": skipped,
            "available_after": max_candidates - len(planned),
        }
