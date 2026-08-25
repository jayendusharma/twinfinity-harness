"""Focused execution guard for effective SQLite approval decisions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any


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

    proposals = connection.execute(
        """
        SELECT p.proposal_sha256
        FROM approval_current c
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN approval_interests i USING(proposal_sha256)
        WHERE p.repository=? AND p.owning_issue=? AND i.recipient_session_id=?
        """,
        (repository, issue_number, recipient_session_id),
    ).fetchall()
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
    parameters: list[Any] = [repository, issue_number, recipient_session_id]
    if authority_sha256 is not None:
        clauses.append("d.decision_sha256=?")
        parameters.append(authority_sha256)
    if authority_comment_id is not None:
        clauses.append("o.remote_receipt=?")
        parameters.append(f"comment:{authority_comment_id}")
    if not clauses:
        raise ApprovalGuardError("APPROVAL_AUTHORITY_BINDING_MISSING")
    match = connection.execute(
        f"""
        SELECT p.proposal_sha256, d.decision_sha256, d.decision,
               x.state AS delivery_state, e.effective_source_sha256,
               e.remote_receipt, o.state AS outbox_state,
               o.remote_receipt AS outbox_receipt,
               current.payload_sha256 AS current_source_sha256,
               current_snapshot.payload_json AS current_source_json,
               d.execution_scope_sha256 AS approved_execution_scope_sha256
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
        WHERE p.repository=? AND p.owning_issue=? AND x.recipient_session_id=?
          AND r.decision_sha256 IS NULL
          AND ({' OR '.join(clauses)})
        """,
        tuple(parameters),
    ).fetchone()
    if match is None:
        raise ApprovalGuardError("APPROVAL_AUTHORITY_MISMATCH")
    if match["approved_execution_scope_sha256"] != execution_scope_sha256:
        raise ApprovalGuardError("APPROVAL_EXECUTION_SCOPE_MISMATCH")
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
