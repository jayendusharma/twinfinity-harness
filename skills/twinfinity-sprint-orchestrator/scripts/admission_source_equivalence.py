"""Exact admission-lineage source equivalence helpers.

The receipt is deliberately narrower than general source compatibility: it
only permits a previously admitted issue snapshot and the current snapshot to
differ in volatile top-level projection fields.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdmissionSourceEquivalenceError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_issue_projection(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AdmissionSourceEquivalenceError("SOURCE_EQUIVALENCE_PAYLOAD_INVALID")
    return {
        key: value
        for key, value in payload.items()
        if key != "updated_at" and not key.startswith("_projection_")
    }


def stable_issue_digest(payload: Any) -> str:
    return digest_json(stable_issue_projection(payload))


def require_stable_issue_equivalence(bound: Any, current: Any) -> str:
    bound_digest = stable_issue_digest(bound)
    current_digest = stable_issue_digest(current)
    if bound_digest != current_digest:
        raise AdmissionSourceEquivalenceError("SOURCE_EQUIVALENCE_MATERIAL_DRIFT")
    return bound_digest


def active_admission_source_equivalence(
    connection: sqlite3.Connection,
    *,
    repository: str,
    issue_number: int,
    generation: int,
    message_id: int,
    watch_key: str,
    item_version: int,
    bound_source_sha256: str,
    current_source_sha256: str,
    endpoint_id: str,
    claimant: str,
    claim_attempt_id: str,
    lease_manifest_sha256: str,
) -> bool:
    """Return true only for one intact receipt bound to the active lineage."""

    if not all(
        isinstance(value, str) and value
        for value in (repository, watch_key, endpoint_id, claimant, claim_attempt_id, lease_manifest_sha256)
    ) or not all(SHA256.fullmatch(value) for value in (bound_source_sha256, current_source_sha256, lease_manifest_sha256)):
        return False
    try:
        row = connection.execute(
            """
            SELECT * FROM coordination_admission_source_equivalence
            WHERE repository=? AND issue_number=? AND generation=?
              AND message_id=? AND watch_key=? AND item_version=?
              AND bound_source_sha256=? AND current_source_sha256=?
              AND endpoint_id=? AND claimant=? AND claim_attempt_id=?
              AND lease_manifest_sha256=?
            """,
            (
                repository, issue_number, generation, message_id, watch_key,
                item_version, bound_source_sha256, current_source_sha256,
                endpoint_id, claimant, claim_attempt_id, lease_manifest_sha256,
            ),
        ).fetchone()
    except sqlite3.Error:
        return False
    if row is None:
        return False
    try:
        receipt = json.loads(row["receipt_json"])
    except (TypeError, json.JSONDecodeError):
        return False
    return bool(
        isinstance(receipt, dict)
        and canonical_json(receipt) == row["receipt_json"]
        and digest_json(receipt) == row["receipt_sha256"]
        and receipt.get("kind") == "TWINFINITY_ADMISSION_SOURCE_EQUIVALENCE_RECEIPT_V1"
        and receipt.get("receipt_key") == row["receipt_key"]
        and receipt.get("preview_sha256") == row["preview_sha256"]
    )


def admission_lineage_source_is_current(
    connection: sqlite3.Connection,
    *,
    item: sqlite3.Row,
    message: sqlite3.Row,
    watch: sqlite3.Row,
    current_source_sha256: str,
) -> bool:
    """Accept raw equality or the exact current receipt for this lineage."""

    bound = item["source_payload_sha256"]
    if current_source_sha256 == bound:
        return True
    if (message["state"] != "CLAIMED" or watch["state"] != "ACTIVE"
            or int(watch["admission_message_id"] or 0) != int(message["id"])
            or watch["admission_payload_sha256"] != message["payload_sha256"]
            or message["claimed_by"] != item["accountable_session_id"]
            or watch["accountable_session_id"] != item["accountable_session_id"]
            or watch["lease_manifest_sha256"] != item["lease_manifest_sha256"]
            or not isinstance(watch["claim_attempt_id"], str)):
        return False
    return active_admission_source_equivalence(
        connection,
        repository=str(item["repository"]),
        issue_number=int(item["issue_number"]),
        generation=int(item["generation"]),
        message_id=int(message["id"]),
        watch_key=str(watch["watch_key"]),
        item_version=int(item["version"]),
        bound_source_sha256=str(bound),
        current_source_sha256=current_source_sha256,
        endpoint_id=str(item["accountable_session_id"]),
        claimant=str(message["claimed_by"]),
        claim_attempt_id=str(watch["claim_attempt_id"]),
        lease_manifest_sha256=str(item["lease_manifest_sha256"]),
    )
