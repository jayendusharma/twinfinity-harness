"""Focused execution guard for effective SQLite approval decisions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from executor_registry import identities_role_equivalent, identity_role
from repository_delivery_policy import HARNESS_REPOSITORY, HARNESS_STANDING_AUTHORITY_SCHEMA


SHA256_LENGTH = 64
REVIEW_BATCH_SCHEMA = "twinfinity.approval-review-batch.v2"
BATCH_ANSWER_SCHEMA = "twinfinity.approval-batch-answer-map.v1"
LEGACY_PROPOSAL_SCHEMA = "twinfinity.approval-proposal.v1"
PROPOSAL_SCHEMA = "twinfinity.approval-proposal.v2"
LEGACY_AUTHORITY_HOLD = "APPROVAL_LEGACY_V1_AUTHORITY_QUARANTINED"
PROPOSAL_PACKET_KEYS = {
    "schema", "decision_key", "repository", "owning_issue",
    "source_snapshot_sha256", "execution_scope_sha256",
    "requester_session_id", "recipient_session_id", "workstream",
    "boundary", "priority", "urgency", "summary", "question",
    "requested_action", "target", "affected_issues", "blocked_mutation",
    "immediate_beneficiary", "evidence", "risk", "drift_guards",
    "prohibited_side_effects", "options", "recommendation", "expires_at",
}


class ApprovalGuardError(ValueError):
    """Typed fail-closed approval guard error."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID")
        result[key] = value
    return result


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _approval_contract_is_v2(connection: sqlite3.Connection) -> bool:
    if not _table_exists(connection, "approval_semantic_contract_current"):
        return False
    rows = connection.execute(
        "SELECT schema FROM approval_semantic_contract_current WHERE singleton=1"
    ).fetchall()
    if not rows:
        return False
    if len(rows) != 1 or rows[0]["schema"] not in {
        LEGACY_PROPOSAL_SCHEMA, PROPOSAL_SCHEMA
    }:
        raise ApprovalGuardError("APPROVAL_SEMANTIC_CONTRACT_POINTER_INVALID")
    return rows[0]["schema"] == PROPOSAL_SCHEMA


def _proposal_semantic_packet(packet: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "schema", "decision_key", "repository", "owning_issue",
        "source_snapshot_sha256", "execution_scope_sha256", "boundary",
        "summary", "question", "requested_action", "target",
        "affected_issues", "blocked_mutation", "immediate_beneficiary",
        "risk", "drift_guards", "prohibited_side_effects", "options",
        "recommendation", "expires_at",
    ]
    if packet.get("schema") == PROPOSAL_SCHEMA:
        keys.append("evidence")
    return {key: packet[key] for key in keys}


def _require_bound_proposal(row: sqlite3.Row, *, v2_active: bool) -> dict[str, Any]:
    try:
        packet = json.loads(
            row["packet_json"], object_pairs_hook=_strict_object
        )
    except (KeyError, TypeError, json.JSONDecodeError, ApprovalGuardError) as exc:
        raise ApprovalGuardError("APPROVAL_PROPOSAL_BINDING_INVALID") from exc
    if (
        not isinstance(packet, dict)
        or set(packet) != PROPOSAL_PACKET_KEYS
        or packet.get("schema") not in {LEGACY_PROPOSAL_SCHEMA, PROPOSAL_SCHEMA}
        or _canonical_json(packet) != row["packet_json"]
    ):
        raise ApprovalGuardError("APPROVAL_PROPOSAL_BINDING_INVALID")
    expected = _digest_json(_proposal_semantic_packet(packet))
    if (
        expected != row["proposal_sha256"]
        or expected != row["semantic_sha256"]
        or packet.get("repository") != row["repository"]
        or packet.get("owning_issue") != row["owning_issue"]
        or packet.get("source_snapshot_sha256") != row["proposal_source_sha256"]
        or packet.get("boundary") != row["boundary"]
    ):
        raise ApprovalGuardError("APPROVAL_PROPOSAL_BINDING_INVALID")
    if v2_active and packet["schema"] == LEGACY_PROPOSAL_SCHEMA:
        raise ApprovalGuardError(LEGACY_AUTHORITY_HOLD)
    return packet


def _require_frozen_batch_decision(row: sqlite3.Row) -> None:
    """Revalidate the immutable user batch at the execution boundary."""

    required = (
        "batch_sha256",
        "batch_answer_map_sha256",
        "option_map_sha256",
        "selected_option_machine_outcome",
        "batch_json",
        "batch_answer_map_json",
    )
    if any(not isinstance(row[key], str) or not row[key] for key in required):
        raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID")
    if (
        row["event_batch_sha256"] != row["batch_sha256"]
        or row["event_batch_answer_map_sha256"]
        != row["batch_answer_map_sha256"]
    ):
        raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID")
    try:
        batch = json.loads(
            row["batch_json"], object_pairs_hook=_strict_object
        )
        answer_map = json.loads(
            row["batch_answer_map_json"], object_pairs_hook=_strict_object
        )
    except (TypeError, json.JSONDecodeError, ApprovalGuardError) as exc:
        raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID") from exc
    if (
        not isinstance(batch, dict)
        or set(batch) != {"schema", "repository", "proposals"}
        or batch.get("schema") != REVIEW_BATCH_SCHEMA
        or batch.get("repository") != row["repository"]
        or _canonical_json(batch) != row["batch_json"]
        or _digest_json(batch) != row["batch_sha256"]
        or not isinstance(batch.get("proposals"), list)
    ):
        raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID")
    proposals = [
        proposal
        for proposal in batch["proposals"]
        if isinstance(proposal, dict)
        and proposal.get("proposal_sha256") == row["proposal_sha256"]
    ]
    if len(proposals) != 1:
        raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID")
    frozen = proposals[0]
    if set(frozen) != {
        "proposal_sha256",
        "source_snapshot_sha256",
        "execution_scope_sha256",
        "recipient_session_ids",
        "recipient_set_sha256",
        "option_map",
        "option_map_sha256",
    } or (
        frozen["source_snapshot_sha256"] != row["proposal_source_sha256"]
        or frozen["execution_scope_sha256"]
        != row["approved_execution_scope_sha256"]
        or frozen["recipient_set_sha256"] != row["recipient_set_sha256"]
        or frozen["option_map_sha256"] != row["option_map_sha256"]
        or not isinstance(frozen["recipient_session_ids"], list)
        or row["recipient_session_id"] not in frozen["recipient_session_ids"]
        or _digest_json(frozen["recipient_session_ids"])
        != frozen["recipient_set_sha256"]
        or not isinstance(frozen["option_map"], list)
        or _digest_json(frozen["option_map"]) != frozen["option_map_sha256"]
    ):
        raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID")
    selected = [
        option
        for option in frozen["option_map"]
        if isinstance(option, dict)
        and option.get("id") == row["selected_option_id"]
    ]
    if len(selected) != 1 or set(selected[0]) != {
        "id", "label", "effect", "machine_outcome"
    } or (
        selected[0]["machine_outcome"] != row["decision"]
        or row["selected_option_machine_outcome"] != row["decision"]
    ):
        raise ApprovalGuardError("APPROVAL_OPTION_OUTCOME_MISMATCH")
    if (
        not isinstance(answer_map, dict)
        or set(answer_map) != {"schema", "batch_sha256", "answers"}
        or answer_map.get("schema") != BATCH_ANSWER_SCHEMA
        or answer_map.get("batch_sha256") != row["batch_sha256"]
        or _canonical_json(answer_map) != row["batch_answer_map_json"]
        or _digest_json(answer_map) != row["batch_answer_map_sha256"]
        or not isinstance(answer_map.get("answers"), list)
    ):
        raise ApprovalGuardError("APPROVAL_BATCH_BINDING_INVALID")
    answers = [
        answer
        for answer in answer_map["answers"]
        if isinstance(answer, dict)
        and answer.get("proposal_sha256") == row["proposal_sha256"]
    ]
    if len(answers) != 1 or set(answers[0]) != {
        "proposal_sha256", "selected_option_id"
    } or answers[0]["selected_option_id"] != row["selected_option_id"]:
        raise ApprovalGuardError("APPROVAL_BATCH_ANSWER_MISMATCH")


def _stable_payload_sha256(payload_json: str | None) -> str | None:
    if payload_json is None:
        return None
    payload = json.loads(payload_json)
    stable = {
        key: value
        for key, value in payload.items()
        if key != "updated_at" and not key.startswith("_projection_")
    }
    canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def execution_scope_sha256(scope: dict[str, Any]) -> str:
    canonical = json.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def admission_execution_scope_sha256(payload: dict[str, Any]) -> str:
    scope = {
        "kind": "ADMISSION",
        "repository": payload["source"]["repository"],
        "issue_number": payload["issue_number"],
        "generation": payload["generation"],
        "item_version": payload["item_version"],
        "action": payload["action"],
        "base_sha": payload["base_sha"],
        "branch": payload["branch"],
        "worktree_path": payload["worktree_path"],
        "lease_manifest_sha256": payload["lease_manifest_sha256"],
        "capacity": payload["capacity"],
    }
    if payload["source"]["repository"] == HARNESS_REPOSITORY:
        standing = payload.get("standing_source_authority")
        standing_complete = (
            isinstance(standing, dict)
            and standing.get("schema") == HARNESS_STANDING_AUTHORITY_SCHEMA
            and all(
                key in standing
                for key in (
                    "stable_source_sha256",
                    "planner_goal_sha256",
                    "source_scope",
                    "exclusions",
                    "writer",
                    "reviewer_plan",
                    "collision_proof",
                    "environment_rule",
                    "routine_chain",
                    "hard_stops",
                )
            )
        )
        scope.update(
            {
                "source_identity": {
                    key: payload["source"].get(key)
                    for key in ("repository", "object_kind", "object_number")
                },
                "stable_source_sha256": (
                    standing.get("stable_source_sha256")
                    if standing_complete
                    else None
                ),
                "planner_goal_sha256": (
                    standing.get("planner_goal_sha256")
                    if standing_complete
                    else None
                ),
                "standing_source_authority_schema": (
                    standing.get("schema") if isinstance(standing, dict) else None
                ),
                "standing_source_authority_sha256": payload.get(
                    "standing_source_authority_sha256"
                ),
                "source_scope": (
                    standing.get("source_scope")
                    if standing_complete
                    else payload.get("source_scope")
                ),
                "source_exclusions": (
                    standing.get("exclusions")
                    if standing_complete
                    else payload.get("source_exclusions")
                ),
                "writer": (
                    standing.get("writer")
                    if standing_complete
                    else payload.get("writer")
                ),
                "reviewer_plan": (
                    standing.get("reviewer_plan")
                    if standing_complete
                    else payload.get("reviewer_plan")
                ),
                "collision_proof": (
                    standing.get("collision_proof")
                    if standing_complete
                    else payload.get("collision_proof")
                ),
                "environment_rule": (
                    standing.get("environment_rule")
                    if standing_complete
                    else payload.get("environment_rule")
                ),
                "routine_chain": (
                    standing.get("routine_chain")
                    if standing_complete
                    else payload.get("routine_chain")
                ),
                "hard_stops": (
                    standing.get("hard_stops")
                    if standing_complete
                    else payload.get("hard_stops")
                ),
            }
        )
    return execution_scope_sha256(scope)


def capacity_policy_execution_scope_sha256(
    *,
    repository: str,
    expected_prior_version: int,
    development_limit: int,
    shared_limit: int,
    sre_limit: int,
) -> str:
    """Digest the complete authority-bearing capacity-policy mutation."""

    return execution_scope_sha256(
        {
            "kind": "CAPACITY_POLICY",
            "repository": repository,
            "expected_prior_version": expected_prior_version,
            "development_limit": development_limit,
            "shared_limit": shared_limit,
            "sre_limit": sre_limit,
        }
    )


def readiness_execution_scope_sha256(
    *,
    repository: str,
    issue_number: int,
    source_payload_sha256: str,
    campaign_id: int,
    generation: int,
    item_version: int,
    accepted_main_sha: str,
    graph_version: int,
    capacity_policy_version: int,
    candidate_sha256: str,
    worker_role: str,
    worker_endpoint_id: str,
    worker_attempt_id: str,
    parent_plan_sha256: str,
    material_boundary: str,
) -> str:
    """Digest the complete authority-bearing readiness approval wait.

    The decision mapping is deliberately fixed in the digest contract rather
    than supplied by a worker: APPROVE resumes one deterministic successor;
    every other user outcome preserves the lineage on HOLD.
    """

    return execution_scope_sha256(
        {
            "kind": "READINESS_APPROVAL",
            "repository": repository,
            "issue_number": issue_number,
            "source_payload_sha256": source_payload_sha256,
            "campaign_id": campaign_id,
            "generation": generation,
            "item_version": item_version,
            "accepted_main_sha": accepted_main_sha,
            "graph_version": graph_version,
            "capacity_policy_version": capacity_policy_version,
            "candidate_sha256": candidate_sha256,
            "worker_role": worker_role,
            "worker_endpoint_id": worker_endpoint_id,
            "worker_attempt_id": worker_attempt_id,
            "parent_plan_sha256": parent_plan_sha256,
            "material_boundary": material_boundary,
            "decision_mapping": {
                "APPROVE": "APPROVAL_RESUME",
                "REJECT": "HOLD",
                "DEFER": "HOLD",
                "COURSE_CORRECT": "HOLD",
            },
        }
    )


def hosted_execution_scope_sha256(
    *,
    provider: str,
    target_kind: str,
    target_key: str,
    operation_kind: str,
    scope: dict[str, Any],
) -> str:
    return execution_scope_sha256(
        {
            "kind": "HOSTED_OPERATION",
            "provider": provider,
            "target_kind": target_kind,
            "target_key": target_key,
            "operation_kind": operation_kind,
            "scope": scope,
        }
    )


def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def require_effective_approval(
    connection: sqlite3.Connection,
    *,
    repository: str,
    issue_number: int,
    recipient_session_id: str,
    execution_scope_sha256: str | None = None,
    authority_sha256: str | None = None,
    authority_comment_id: int | None = None,
    required_proposal_sha256: str | None = None,
    required_workstream: str | None = None,
    required_boundary: str | None = None,
    required_current_recipient_role: str | None = None,
    actor_session_id: str | None = None,
    required: bool,
) -> dict[str, Any] | None:
    """Require one current APPROVE decision and its exact execution binding.

    Development admissions bind the decision digest as ``authority_sha256``.
    Hosted operations bind the published owning-issue comment ID.  When
    ``required`` is false, absence of any ledger proposal preserves standing
    autonomy and historical lineages; once a current proposal exists, however,
    execution cannot bypass its state with an unrelated authority hash.
    """

    tables = {
        "approval_current",
        "approval_proposals",
        "approval_submissions",
        "approval_interests",
        "approval_review_batches",
        "approval_user_events",
        "approval_decisions",
        "approval_deliveries",
        "approval_effectivity",
        "approval_revocations",
    }
    if not all(_table_exists(connection, name) for name in tables):
        if required:
            raise ApprovalGuardError("APPROVAL_LEDGER_REQUIRED")
        return None

    actor = actor_session_id or recipient_session_id
    if required_current_recipient_role is not None:
        current_recipient = connection.execute(
            """
            SELECT endpoint.endpoint_id
            FROM executor_role_endpoint_current current
            JOIN executor_role_endpoints endpoint
              ON endpoint.endpoint_id=current.endpoint_id
             AND endpoint.role=current.role
            WHERE current.role=?
            """,
            (required_current_recipient_role,),
        ).fetchone()
        if (
            current_recipient is None
            or current_recipient["endpoint_id"] != actor
        ):
            raise ApprovalGuardError("APPROVAL_CURRENT_RECIPIENT_REQUIRED")

    if required_proposal_sha256 is not None and (
        len(required_proposal_sha256) != SHA256_LENGTH
        or any(
            character not in "0123456789abcdef"
            for character in required_proposal_sha256
        )
    ):
        raise ApprovalGuardError("APPROVAL_PROPOSAL_BINDING_INVALID")
    if required_workstream is not None and (
        not isinstance(required_workstream, str) or not required_workstream.strip()
    ):
        raise ApprovalGuardError("APPROVAL_WORKSTREAM_BINDING_INVALID")

    proposals = connection.execute(
        """
        SELECT DISTINCT p.proposal_sha256, p.semantic_sha256, p.packet_json,
               p.repository, p.owning_issue, p.boundary,
               p.source_snapshot_sha256 AS proposal_source_sha256,
               i.recipient_session_id
        FROM approval_current c
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN approval_interests i USING(proposal_sha256)
        WHERE p.repository=? AND p.owning_issue=?
          AND (? IS NULL OR p.proposal_sha256=?)
          AND (? IS NULL OR EXISTS (
              SELECT 1 FROM approval_submissions submission
              WHERE submission.proposal_sha256=p.proposal_sha256
                AND submission.workstream=?
          ))
          AND (? IS NULL OR p.boundary=?)
        """,
        (
            repository,
            issue_number,
            required_proposal_sha256,
            required_proposal_sha256,
            required_workstream,
            required_workstream,
            required_boundary,
            required_boundary,
        ),
    ).fetchall()
    v2_active = _approval_contract_is_v2(connection)
    if required_proposal_sha256 is not None:
        for proposal in proposals:
            _require_bound_proposal(proposal, v2_active=v2_active)
    proposals = [
        row
        for row in proposals
        if identities_role_equivalent(
            connection, str(row["recipient_session_id"]), actor
        )
    ]
    for proposal in proposals:
        _require_bound_proposal(proposal, v2_active=v2_active)
    if not proposals:
        if required:
            raise ApprovalGuardError("APPROVAL_DECISION_REQUIRED")
        return None
    if (
        not isinstance(execution_scope_sha256, str)
        or len(execution_scope_sha256) != SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in execution_scope_sha256)
    ):
        raise ApprovalGuardError("APPROVAL_EXECUTION_SCOPE_MISSING")

    clauses: list[str] = []
    parameters: list[Any] = [
        repository,
        issue_number,
        required_proposal_sha256,
        required_proposal_sha256,
        required_workstream,
        required_workstream,
        required_boundary,
        required_boundary,
    ]
    if authority_sha256 is not None:
        clauses.append("d.decision_sha256=?")
        parameters.append(authority_sha256)
    if authority_comment_id is not None:
        clauses.append("o.remote_receipt=?")
        parameters.append(f"comment:{authority_comment_id}")
    if not clauses:
        raise ApprovalGuardError("APPROVAL_AUTHORITY_BINDING_MISSING")
    matches = connection.execute(
        f"""
        SELECT p.proposal_sha256, p.semantic_sha256, p.packet_json,
               p.repository, p.owning_issue, p.boundary,
               p.source_snapshot_sha256 AS proposal_source_sha256,
               x.recipient_session_id,
               d.decision_sha256, d.decision, d.selected_option_id,
               d.selected_option_machine_outcome, d.recipient_set_sha256,
               d.batch_sha256, d.batch_answer_map_sha256,
               d.option_map_sha256,
               x.state AS delivery_state, e.effective_source_sha256,
               e.remote_receipt, o.state AS outbox_state,
               o.remote_receipt AS outbox_receipt,
               current.payload_sha256 AS current_source_sha256,
               current_snapshot.payload_json AS current_source_json,
               d.execution_scope_sha256 AS approved_execution_scope_sha256,
               d.planner_session_id, batch.batch_json,
               user_event.batch_sha256 AS event_batch_sha256,
               user_event.batch_answer_map_sha256
                   AS event_batch_answer_map_sha256,
               user_event.batch_answer_map_json
        FROM approval_current c
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN approval_decisions d USING(proposal_sha256)
        JOIN approval_deliveries x USING(proposal_sha256, decision_sha256)
        JOIN approval_effectivity e USING(proposal_sha256, decision_sha256)
        JOIN github_outbox o ON o.id=d.owner_outbox_id
        LEFT JOIN approval_review_batches batch
          ON batch.batch_sha256=d.batch_sha256
        LEFT JOIN approval_user_events user_event
          ON user_event.user_event_source=d.user_event_source
         AND user_event.user_event_id=d.user_event_id
        LEFT JOIN approval_revocations r USING(proposal_sha256, decision_sha256)
        LEFT JOIN github_current current
          ON current.repository=p.repository
         AND current.object_kind='issue'
         AND current.object_number=p.owning_issue
        LEFT JOIN github_snapshots current_snapshot
          ON current_snapshot.repository=current.repository
         AND current_snapshot.object_kind=current.object_kind
         AND current_snapshot.object_number=current.object_number
         AND current_snapshot.payload_sha256=current.payload_sha256
        WHERE p.repository=? AND p.owning_issue=?
          AND (? IS NULL OR p.proposal_sha256=?)
          AND (? IS NULL OR EXISTS (
              SELECT 1 FROM approval_submissions submission
              WHERE submission.proposal_sha256=p.proposal_sha256
                AND submission.workstream=?
          ))
          AND (? IS NULL OR p.boundary=?)
          AND r.decision_sha256 IS NULL
          AND ({' OR '.join(clauses)})
        """,
        tuple(parameters),
    ).fetchall()
    role_matches = [
        row
        for row in matches
        if identities_role_equivalent(
            connection, str(row["recipient_session_id"]), actor
        )
    ]
    if len(role_matches) > 1:
        raise ApprovalGuardError("APPROVAL_AUTHORITY_AMBIGUOUS")
    match = None if not role_matches else role_matches[0]
    if match is None:
        raise ApprovalGuardError("APPROVAL_AUTHORITY_MISMATCH")
    _require_bound_proposal(match, v2_active=v2_active)
    if match["approved_execution_scope_sha256"] != execution_scope_sha256:
        raise ApprovalGuardError("APPROVAL_EXECUTION_SCOPE_MISMATCH")
    _require_frozen_batch_decision(match)
    if required_boundary is not None and match["boundary"] != required_boundary:
        raise ApprovalGuardError("APPROVAL_BOUNDARY_MISMATCH")
    if (
        required_current_recipient_role is not None
        and (
            identity_role(connection, str(match["planner_session_id"]))
            != required_current_recipient_role
            or not identities_role_equivalent(
                connection, str(match["planner_session_id"]), actor
            )
        )
    ):
        raise ApprovalGuardError("APPROVAL_PLANNER_IDENTITY_MISMATCH")
    if match["decision"] != "APPROVE":
        raise ApprovalGuardError("APPROVAL_DECISION_NOT_APPROVED")
    if match["delivery_state"] not in {"CLAIMED", "ACKNOWLEDGED"}:
        raise ApprovalGuardError("APPROVAL_DELIVERY_NOT_CLAIMED")
    if (
        match["outbox_state"] != "COMPLETE"
        or not match["outbox_receipt"]
        or match["outbox_receipt"] != match["remote_receipt"]
    ):
        raise ApprovalGuardError("APPROVAL_PUBLICATION_INCOMPLETE")
    if _stable_payload_sha256(match["current_source_json"]) != match["effective_source_sha256"]:
        raise ApprovalGuardError("APPROVAL_EFFECTIVE_SOURCE_DRIFT")
    result = dict(match)
    result.pop("current_source_json", None)
    return result
