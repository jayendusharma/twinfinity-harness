"""Focused execution guard for effective SQLite approval decisions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from executor_registry import identities_role_equivalent, identity_role


SHA256_LENGTH = 64


class ApprovalGuardError(ValueError):
    """Typed fail-closed approval guard error."""


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
    return execution_scope_sha256(
        {
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
    )


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
        SELECT DISTINCT p.proposal_sha256, i.recipient_session_id
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
    proposals = [
        row
        for row in proposals
        if identities_role_equivalent(
            connection, str(row["recipient_session_id"]), actor
        )
    ]
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
        SELECT p.proposal_sha256, p.boundary, x.recipient_session_id,
               d.decision_sha256, d.decision,
               x.state AS delivery_state, e.effective_source_sha256,
               e.remote_receipt, o.state AS outbox_state,
               o.remote_receipt AS outbox_receipt,
               current.payload_sha256 AS current_source_sha256,
               current_snapshot.payload_json AS current_source_json,
               d.execution_scope_sha256 AS approved_execution_scope_sha256,
               d.planner_session_id
        FROM approval_current c
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN approval_decisions d USING(proposal_sha256)
        JOIN approval_deliveries x USING(proposal_sha256, decision_sha256)
        JOIN approval_effectivity e USING(proposal_sha256, decision_sha256)
        JOIN github_outbox o ON o.id=d.owner_outbox_id
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
    if match["approved_execution_scope_sha256"] != execution_scope_sha256:
        raise ApprovalGuardError("APPROVAL_EXECUTION_SCOPE_MISMATCH")
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
