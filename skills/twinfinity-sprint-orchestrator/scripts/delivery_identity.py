"""Canonical delivery identity shared by readiness and writer-side guards."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
import re
from typing import Any

from approval_guard import admission_execution_scope_sha256
from repository_delivery_policy import (
    APPLICATION_REPOSITORY,
    delivery_branch_issue_number,
    delivery_branch_matches_owning_issue,
    expected_worktree_identity,
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
        surface_issue_number=issue_number,
        owning_issue_number=issue_number,
        generation=generation,
        worktree_path=identity["worktree_path"],
        opaque_worktree_id=identity["opaque_worktree_id"],
    )
    if (
        not strict_delivery_branch_matches(repository, identity["branch"])
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


def bind_delivery_identity(admission: dict[str, Any]) -> dict[str, Any]:
    """Insert the canonical identity and return it after strict validation."""

    identity = build_delivery_identity(admission)
    admission["message"]["payload"]["delivery_identity"] = identity
    error = delivery_identity_error(identity, admission=admission)
    if error is not None:
        raise ValueError(error)
    return identity
