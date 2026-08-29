"""Canonical delivery identity shared by readiness and writer-side guards."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping

from approval_guard import admission_execution_scope_sha256
from repository_delivery_policy import (
    APPLICATION_REPOSITORY,
    delivery_branch_issue_number,
    delivery_branch_matches_owning_issue,
    expected_worktree_identity,
    expected_worktree_parent,
    strict_delivery_branch_matches,
    worktree_identity_matches,
)


DELIVERY_IDENTITY_SCHEMA = "twinfinity-delivery-identity/v1"
DELIVERY_IDENTITY_KEYS = {
    "schema",
    "repository",
    "issue_number",
    "generation",
    "lease_manifest_sha256",
    "branch",
    "worktree_path",
    "opaque_worktree_id",
    "admission_execution_scope_sha256",
    "admission_transaction_sha256",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
WORKSPACE_ROOT = Path("/home/ubuntu/code")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def delivery_identity_sha256(identity: dict[str, Any]) -> str:
    """Return the canonical digest carried by plans and PASS receipts."""

    return _digest_json(identity)


def _transaction_with_normalized_self_digest(
    admission: dict[str, Any], identity: dict[str, Any]
) -> dict[str, Any]:
    """Canonicalize the one self-referential digest slot to JSON null.

    Every admission byte, including every other delivery-identity field, is
    covered.  Only the digest's own value is normalized so the complete
    activation transaction can carry its canonical identity without a
    recursive hash fixed point.
    """

    transaction = deepcopy(admission)
    message = transaction.get("message")
    payload = message.get("payload") if isinstance(message, dict) else None
    if not isinstance(payload, dict):
        raise ValueError("DELIVERY_IDENTITY_ADMISSION_INVALID")
    normalized_identity = deepcopy(identity)
    normalized_identity["admission_transaction_sha256"] = None
    payload["delivery_identity"] = normalized_identity
    return transaction


def admission_transaction_sha256(admission: dict[str, Any]) -> str:
    """Digest a complete identity-bearing admission transaction."""

    if not isinstance(admission, dict):
        raise ValueError("DELIVERY_IDENTITY_ADMISSION_INVALID")
    message = admission.get("message")
    payload = message.get("payload") if isinstance(message, dict) else None
    identity = payload.get("delivery_identity") if isinstance(payload, dict) else None
    if not isinstance(identity, dict):
        raise ValueError("DELIVERY_IDENTITY_MISSING")
    return _digest_json(_transaction_with_normalized_self_digest(admission, identity))


def build_delivery_identity(admission: dict[str, Any]) -> dict[str, Any]:
    """Construct the sole versioned identity before readiness dispatch."""

    if not isinstance(admission, dict):
        raise ValueError("DELIVERY_IDENTITY_ADMISSION_INVALID")
    item = admission.get("item")
    message = admission.get("message")
    payload = message.get("payload") if isinstance(message, dict) else None
    source = payload.get("source") if isinstance(payload, dict) else None
    if not all(isinstance(value, dict) for value in (item, message, payload, source)):
        raise ValueError("DELIVERY_IDENTITY_ADMISSION_INVALID")
    try:
        identity: dict[str, Any] = {
            "schema": DELIVERY_IDENTITY_SCHEMA,
            "repository": source["repository"],
            "issue_number": payload["issue_number"],
            "generation": payload["generation"],
            "lease_manifest_sha256": payload["lease_manifest_sha256"],
            "branch": payload["branch"],
            "worktree_path": payload["worktree_path"],
            "opaque_worktree_id": payload["opaque_worktree_id"],
            "admission_execution_scope_sha256": (
                admission_execution_scope_sha256(payload)
            ),
            "admission_transaction_sha256": "0" * 64,
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("DELIVERY_IDENTITY_ADMISSION_INVALID") from exc
    identity["admission_transaction_sha256"] = _digest_json(
        _transaction_with_normalized_self_digest(admission, identity)
    )
    return identity


def delivery_identity_error(
    identity: Any,
    *,
    admission: dict[str, Any] | None = None,
    expected_identity: dict[str, Any] | None = None,
    expected_sha256: str | None = None,
) -> str | None:
    """Validate shape, repository grammar, and optional transaction binding."""

    if (
        not isinstance(identity, dict)
        or set(identity) != DELIVERY_IDENTITY_KEYS
        or identity.get("schema") != DELIVERY_IDENTITY_SCHEMA
        or not isinstance(identity.get("repository"), str)
        or type(identity.get("issue_number")) is not int
        or int(identity["issue_number"]) <= 0
        or type(identity.get("generation")) is not int
        or int(identity["generation"]) < 0
        or any(
            not isinstance(identity.get(field), str) or not identity[field]
            for field in (
                "branch", "worktree_path", "opaque_worktree_id"
            )
        )
        or any(
            not isinstance(identity.get(field), str)
            or SHA256.fullmatch(identity[field]) is None
            for field in (
                "lease_manifest_sha256",
                "admission_execution_scope_sha256",
                "admission_transaction_sha256",
            )
        )
    ):
        return "DELIVERY_IDENTITY_INVALID"
    repository = identity["repository"]
    issue_number = int(identity["issue_number"])
    generation = int(identity["generation"])
    surface_issue_number = delivery_branch_issue_number(
        repository, identity["branch"]
    )
    worktree_path = Path(identity["worktree_path"])
    expected_parent = expected_worktree_parent(repository, WORKSPACE_ROOT)
    transfer_identity = False
    if (
        repository == APPLICATION_REPOSITORY
        and surface_issue_number is not None
        and surface_issue_number != issue_number
    ):
        expected_surface = expected_worktree_identity(
            repository, surface_issue_number
        )
        transfer_identity = bool(
            expected_surface is not None
            and identity["worktree_path"].rsplit("/", 1)[-1]
            == expected_surface
            and identity["opaque_worktree_id"] == expected_surface
        )
    same_issue_identity = worktree_identity_matches(
        repository,
        surface_issue_number=surface_issue_number,
        owning_issue_number=issue_number,
        generation=generation,
        worktree_path=identity["worktree_path"],
        opaque_worktree_id=identity["opaque_worktree_id"],
    )
    if (
        surface_issue_number is None
        or expected_parent is None
        or not worktree_path.is_absolute()
        or identity["worktree_path"] != str(worktree_path)
        or worktree_path.parent != expected_parent
        or not strict_delivery_branch_matches(repository, identity["branch"])
        or not delivery_branch_matches_owning_issue(
            repository, identity["branch"], issue_number
        )
        or not (same_issue_identity or transfer_identity)
    ):
        return "DELIVERY_IDENTITY_POLICY_INVALID"
    if expected_identity is not None and identity != expected_identity:
        return "DELIVERY_IDENTITY_BINDING_DRIFT"
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or not hmac.compare_digest(
            delivery_identity_sha256(identity), expected_sha256
        )
    ):
        return "DELIVERY_IDENTITY_DIGEST_DRIFT"
    if admission is not None:
        message = admission.get("message") if isinstance(admission, dict) else None
        payload = message.get("payload") if isinstance(message, dict) else None
        embedded_identity = (
            payload.get("delivery_identity") if isinstance(payload, dict) else None
        )
        if not isinstance(embedded_identity, dict):
            return "DELIVERY_IDENTITY_MISSING"
        if embedded_identity != identity:
            return "DELIVERY_IDENTITY_TRANSACTION_DRIFT"
        try:
            computed = build_delivery_identity(admission)
        except ValueError as exc:
            return str(exc)
        if computed != identity:
            return "DELIVERY_IDENTITY_TRANSACTION_DRIFT"
    return None


def immutable_admission_error(
    connection: sqlite3.Connection,
    *,
    message: Mapping[str, Any],
    payload: dict[str, Any],
) -> str | None:
    """Compare a live admission message with its immutable READY transaction.

    Writer-side consumers cannot safely validate the transaction digest from
    the message payload alone: the digest also covers the item and artifact
    set.  The v2 finalization therefore retains the exact reviewed transaction,
    and this check compares every immutable message byte with that attestation.
    Endpoint rotation may change the current item/watch route, but it never
    rewrites the admission message or its reviewed transaction.
    """

    identity = payload.get("delivery_identity")
    error = delivery_identity_error(identity)
    source = payload.get("source")
    if error is not None:
        return error
    if (
        not isinstance(source, dict)
        or not isinstance(source.get("repository"), str)
        or type(payload.get("issue_number")) is not int
        or type(payload.get("generation")) is not int
    ):
        return "DELIVERY_IDENTITY_ADMISSION_INVALID"
    try:
        row = connection.execute(
            """
            SELECT finalization.finalization_sha256,
                   finalization.payload_json,
                   current.state AS readiness_state,
                   candidate.state AS candidate_state
            FROM portfolio_ready_finalizations finalization
            JOIN portfolio_readiness_current current
              ON current.repository=finalization.repository
             AND current.issue_number=finalization.issue_number
             AND current.campaign_id=finalization.campaign_id
             AND current.finalized_candidate_id=finalization.ready_candidate_id
             AND current.finalized_event_id=finalization.dirty_event_id
            JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=finalization.ready_candidate_id
            WHERE finalization.repository=?
              AND finalization.issue_number=?
              AND finalization.generation=?
            """,
            (
                source["repository"],
                payload["issue_number"],
                payload["generation"],
            ),
        ).fetchall()
    except sqlite3.Error:
        return "DELIVERY_IDENTITY_ATTESTATION_MISSING"
    if len(row) != 1:
        return "DELIVERY_IDENTITY_ATTESTATION_MISSING"
    attestation = row[0]
    try:
        finalization = json.loads(attestation["payload_json"])
    except (TypeError, json.JSONDecodeError):
        return "DELIVERY_IDENTITY_ATTESTATION_DRIFT"
    admission = (
        finalization.get("admission_transaction")
        if isinstance(finalization, dict)
        else None
    )
    expected_message = (
        admission.get("message") if isinstance(admission, dict) else None
    )
    try:
        current_message = {
            "idempotency_key": message["idempotency_key"],
            "recipient_session_id": message["recipient_session_id"],
            "topic": message["topic"],
            "payload": payload,
        }
    except (KeyError, IndexError, TypeError):
        return "DELIVERY_IDENTITY_ADMISSION_INVALID"
    if (
        attestation["readiness_state"] != "FINALIZED"
        or attestation["candidate_state"] != "READY"
        or not isinstance(finalization, dict)
        or _digest_json(finalization) != attestation["finalization_sha256"]
        or finalization.get("schema")
        != "twinfinity-kanban-ready-finalization/v2"
        or finalization.get("repository") != source["repository"]
        or finalization.get("issue_number") != payload["issue_number"]
        or finalization.get("generation") != payload["generation"]
        or finalization.get("delivery_identity") != identity
        or finalization.get("delivery_identity_sha256")
        != delivery_identity_sha256(identity)
        or finalization.get("admission_transaction_sha256")
        != identity["admission_transaction_sha256"]
        or not isinstance(admission, dict)
        or expected_message != current_message
        or delivery_identity_error(
            identity,
            admission=admission,
            expected_sha256=finalization.get("delivery_identity_sha256"),
        )
        is not None
    ):
        return "DELIVERY_IDENTITY_ATTESTATION_DRIFT"
    return None


def bind_delivery_identity(admission: dict[str, Any]) -> dict[str, Any]:
    """Insert the canonical identity and return it after strict validation."""

    identity = build_delivery_identity(admission)
    admission["message"]["payload"]["delivery_identity"] = identity
    error = delivery_identity_error(identity, admission=admission)
    if error is not None:
        raise ValueError(error)
    return identity
