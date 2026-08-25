#!/usr/bin/env python3
"""Atomically release local issue leases while activating one successor admission."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
    digest_json,
    terminal_watch_key,
    utc_now,
)
from coordination_transfer_ledger import (
    activation_event_payload,
    create_schema as create_transfer_ledger_schema,
    intent_sha256 as transfer_intent_sha256,
    load_record as load_transfer_record,
    predecessor_snapshot_event_payload,
    record_sha256 as transfer_record_sha256,
    validate_comments,
    validate_existing_state,
    validate_predecessor_provenance,
    validate_record_shape,
)


ITEM_KEYS = {
    "repository",
    "issue_number",
    "status",
    "allocation_class",
    "generation",
    "accountable_session_id",
    "lease_manifest_sha256",
    "development_units",
    "shared_units",
    "sre_units",
    "expected_source_sha256",
    "expected_version",
}
MESSAGE_KEYS = {"idempotency_key", "recipient_session_id", "topic", "payload"}
BRANCH = re.compile(r"^codex/(?P<issue>[1-9][0-9]*)-[A-Za-z0-9._-]+$")
LINEAGE_KEYS = {
    "predecessor_issue_number",
    "predecessor_generation",
    "predecessor_item_version",
    "predecessor_admission_item_version",
    "predecessor_source_payload_sha256",
    "predecessor_admission_message_id",
    "predecessor_admission_payload_sha256",
    "predecessor_accountable_session_id",
    "predecessor_lease_manifest_sha256",
    "predecessor_development_units",
    "predecessor_shared_units",
    "predecessor_sre_units",
    "predecessor_pretransfer_status",
    "predecessor_pretransfer_allocation_class",
    "predecessor_comment_id",
    "predecessor_comment_body_sha256",
    "successor_comment_id",
    "successor_comment_body_sha256",
}


def _item_result(desired: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": desired["repository"],
        "issue_number": desired["issue_number"],
        "status": desired["status"],
        "allocation_class": desired["allocation_class"],
        "generation": desired["generation"],
        "version": desired["expected_version"] + 1,
        "source_payload_sha256": desired["expected_source_sha256"],
    }


def _exact_item(row: Any, desired: dict[str, Any]) -> bool:
    return bool(
        row
        and row["status"] == desired["status"]
        and row["allocation_class"] == desired["allocation_class"]
        and int(row["generation"]) == desired["generation"]
        and row["accountable_session_id"] == desired["accountable_session_id"]
        and row["lease_manifest_sha256"] == desired["lease_manifest_sha256"]
        and int(row["development_units"]) == desired["development_units"]
        and int(row["shared_units"]) == desired["shared_units"]
        and int(row["sre_units"]) == desired["sre_units"]
        and row["source_payload_sha256"] == desired["expected_source_sha256"]
        and int(row["version"]) == desired["expected_version"] + 1
    )


def activate_transfer(
    store: CoordinationStore, transaction: dict[str, Any], now: str
) -> dict[str, Any]:
    if not isinstance(transaction, dict) or set(transaction) != {
        "transfer_key",
        "releases",
        "activation",
        "lineage",
    }:
        raise CoordinationError("TRANSFER_TRANSACTION_INVALID")
    transfer_key = transaction["transfer_key"]
    releases = transaction["releases"]
    activation = transaction["activation"]
    lineage = transaction["lineage"]
    if (
        not isinstance(transfer_key, str)
        or not transfer_key
        or not isinstance(releases, list)
        or not releases
        or len(releases) > 20
        or not isinstance(activation, dict)
        or set(activation) != {"item", "message"}
        or not isinstance(lineage, dict)
        or set(lineage) != LINEAGE_KEYS
    ):
        raise CoordinationError("TRANSFER_TRANSACTION_INVALID")
    item = activation["item"]
    message = activation["message"]
    if (
        not isinstance(item, dict)
        or set(item) != ITEM_KEYS
        or not isinstance(message, dict)
        or set(message) != MESSAGE_KEYS
        or message["topic"] not in {"development.admission", "sre.admission"}
    ):
        raise CoordinationError("TRANSFER_TRANSACTION_INVALID")
    repository = item["repository"]
    activated_key = (repository, item["issue_number"])
    seen: set[tuple[str, int]] = set()
    for release in releases:
        if (
            not isinstance(release, dict)
            or set(release) != ITEM_KEYS
            or release["repository"] != repository
            or release["allocation_class"] != "NONE"
            or release["status"] not in {"MONITOR", "DONE"}
            or release["accountable_session_id"] is not None
            or release["lease_manifest_sha256"] is not None
            or any(
                release[key] != 0
                for key in ("development_units", "shared_units", "sre_units")
            )
        ):
            raise CoordinationError("TRANSFER_RELEASE_INVALID")
        key = (release["repository"], release["issue_number"])
        if key == activated_key or key in seen:
            raise CoordinationError("TRANSFER_ITEM_CONFLICT")
        seen.add(key)
    if item["allocation_class"] != "ACTIVE" or item["status"] not in {
        "ACTIVE",
        "ACTIVE_FENCED",
    }:
        raise CoordinationError("TRANSFER_ACTIVATION_INVALID")

    payload = message["payload"]
    if not isinstance(payload, dict) or payload.get("transfer_key") != transfer_key:
        raise CoordinationError("TRANSFER_KEY_BINDING_MISMATCH")
    branch = payload.get("branch")
    branch_match = BRANCH.fullmatch(branch) if isinstance(branch, str) else None
    if branch_match is None:
        raise CoordinationError("TRANSFER_SURFACE_INVALID")
    surface_issue_number = int(branch_match.group("issue"))
    predecessor_issue_number = lineage["predecessor_issue_number"]
    predecessor_release = next(
        (entry for entry in releases if entry["issue_number"] == predecessor_issue_number),
        None,
    )
    expected_surface_id = f"twinfinityapp-issue-{predecessor_issue_number}"
    if (
        surface_issue_number != predecessor_issue_number
        or predecessor_issue_number == item["issue_number"]
        or predecessor_release is None
        or predecessor_release["expected_version"] != lineage["predecessor_item_version"]
        or predecessor_release["expected_source_sha256"]
        != lineage["predecessor_source_payload_sha256"]
        or predecessor_release["generation"] != lineage["predecessor_generation"] + 1
        or payload.get("parent_issue_number") != predecessor_issue_number
        or payload.get("worktree_path") != f"/home/ubuntu/code/{expected_surface_id}"
        or payload.get("opaque_worktree_id") != expected_surface_id
        or payload.get("transfer_comment_ids")
        != [lineage["predecessor_comment_id"], lineage["successor_comment_id"]]
        or payload.get("transfer_comment_body_sha256")
        != [
            lineage["predecessor_comment_body_sha256"],
            lineage["successor_comment_body_sha256"],
        ]
        or payload.get("authority_sha256") is None
        or payload.get("transfer_authority_sha256") != payload.get("authority_sha256")
    ):
        raise CoordinationError("TRANSFER_SURFACE_INVALID")

    comment_record = {
        "transfer_key": transfer_key,
        "repository": repository,
        "predecessor_issue_number": predecessor_issue_number,
        "predecessor_generation": lineage["predecessor_generation"],
        "predecessor_item_version": lineage["predecessor_item_version"],
        "predecessor_admission_item_version": lineage[
            "predecessor_admission_item_version"
        ],
        "predecessor_source_payload_sha256": lineage["predecessor_source_payload_sha256"],
        "predecessor_admission_message_id": lineage["predecessor_admission_message_id"],
        "predecessor_admission_payload_sha256": lineage["predecessor_admission_payload_sha256"],
        "predecessor_accountable_session_id": lineage[
            "predecessor_accountable_session_id"
        ],
        "predecessor_lease_manifest_sha256": lineage[
            "predecessor_lease_manifest_sha256"
        ],
        "predecessor_development_units": lineage["predecessor_development_units"],
        "predecessor_shared_units": lineage["predecessor_shared_units"],
        "predecessor_sre_units": lineage["predecessor_sre_units"],
        "predecessor_pretransfer_status": lineage[
            "predecessor_pretransfer_status"
        ],
        "predecessor_pretransfer_allocation_class": lineage[
            "predecessor_pretransfer_allocation_class"
        ],
        "predecessor_release_status": predecessor_release["status"],
        "predecessor_release_allocation_class": predecessor_release[
            "allocation_class"
        ],
        "successor_issue_number": item["issue_number"],
        "successor_generation": item["generation"],
        "successor_item_version": item["expected_version"] + 1,
        "successor_source_payload_sha256": item["expected_source_sha256"],
        "successor_admission_message_id": 1,
        "successor_admission_payload_sha256": "0" * 64,
        "successor_accountable_session_id": item["accountable_session_id"],
        "successor_lease_manifest_sha256": item["lease_manifest_sha256"],
        "successor_development_units": item["development_units"],
        "successor_shared_units": item["shared_units"],
        "successor_sre_units": item["sre_units"],
        "released_items": [_item_result(entry) for entry in releases],
        "activated_item": _item_result(item),
        "activation_event_schema": "v2",
        "branch": branch,
        "worktree_path": payload["worktree_path"],
        "opaque_worktree_id": payload["opaque_worktree_id"],
        "transfer_authority_sha256": payload["authority_sha256"],
        "predecessor_comment_id": lineage["predecessor_comment_id"],
        "predecessor_comment_body_sha256": lineage["predecessor_comment_body_sha256"],
        "successor_comment_id": lineage["successor_comment_id"],
        "successor_comment_body_sha256": lineage["successor_comment_body_sha256"],
    }
    validate_record_shape(comment_record)
    expected_transfer_intent_sha256 = transfer_intent_sha256(comment_record)
    if payload.get("transfer_intent_sha256") != expected_transfer_intent_sha256:
        raise CoordinationError("TRANSFER_LEDGER_BINDING_MISMATCH")
    validate_comments(comment_record)

    with store.transaction():
        existing = store.connection.execute(
            "SELECT * FROM coordination_messages WHERE idempotency_key=?",
            (message["idempotency_key"],),
        ).fetchone()
        if existing is not None:
            if (
                existing["recipient_session_id"] != message["recipient_session_id"]
                or existing["topic"] != message["topic"]
                or existing["payload_sha256"] != digest_json(payload)
            ):
                raise CoordinationError("TRANSFER_IDEMPOTENCY_CONFLICT")
            if existing["state"] == "HOLD":
                raise CoordinationError("TRANSFER_REPLAY_ADMISSION_HELD")
            expected_record = {
                **comment_record,
                "successor_admission_message_id": int(existing["id"]),
                "successor_admission_payload_sha256": existing["payload_sha256"],
            }
            try:
                stored_record, stored_digest = load_transfer_record(store, transfer_key)
                if (
                    canonical_json(stored_record) != canonical_json(expected_record)
                    or stored_digest != transfer_record_sha256(expected_record)
                    or transfer_intent_sha256(stored_record)
                    != expected_transfer_intent_sha256
                ):
                    raise CoordinationError("TRANSFER_REPLAY_LEDGER_DRIFT")
                validate_existing_state(store, stored_record)
            except CoordinationError as exc:
                if str(exc) == "TRANSFER_LEDGER_SOURCE_DRIFT":
                    raise CoordinationError("TRANSFER_REPLAY_SOURCE_DRIFT") from exc
                if str(exc) == "TRANSFER_LEDGER_STATE_INVALID":
                    raise CoordinationError("TRANSFER_REPLAY_STATE_DRIFT") from exc
                raise
            watch = store.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (terminal_watch_key(repository, item["issue_number"], item["generation"]),),
            ).fetchone()
            if (
                watch is None
                or watch["state"] != "ACTIVE"
                or watch["accountable_session_id"] != item["accountable_session_id"]
                or watch["lease_manifest_sha256"] != item["lease_manifest_sha256"]
            ):
                raise CoordinationError("TRANSFER_REPLAY_WATCH_DRIFT")
            return {
                "transfer_key": transfer_key,
                "replayed": True,
                "message_id": int(existing["id"]),
                "activated_issue_number": item["issue_number"],
                "released_issue_numbers": [entry["issue_number"] for entry in releases],
            }
        validate_predecessor_provenance(
            store,
            comment_record,
            require_current=True,
            require_snapshot=False,
        )
        store._event(
            "TRANSFER_PREDECESSOR_BOUND",
            transfer_key,
            predecessor_snapshot_event_payload(comment_record),
            now,
        )
        released = [
            store.set_issue_status(**entry, now=now, _transaction=False)
            for entry in releases
        ]
        activated = store.set_issue_status(**item, now=now, _transaction=False)
        if (
            payload.get("item_version") != activated["version"]
            or payload.get("issue_number") != activated["issue_number"]
            or payload.get("generation") != activated["generation"]
        ):
            raise CoordinationError("TRANSFER_ADMISSION_BINDING_MISMATCH")
        message_id = store.enqueue_message(
            idempotency_key=message["idempotency_key"],
            recipient_session_id=message["recipient_session_id"],
            topic=message["topic"],
            payload=payload,
            now=now,
            _transaction=False,
        )
        transfer_record = {
            **comment_record,
            "successor_admission_message_id": message_id,
            "successor_admission_payload_sha256": digest_json(payload),
        }
        validate_record_shape(transfer_record)
        if transfer_intent_sha256(transfer_record) != expected_transfer_intent_sha256:
            raise CoordinationError("TRANSFER_LEDGER_BINDING_MISMATCH")
        transfer_record_json = canonical_json(transfer_record)
        transfer_record_sha256_value = transfer_record_sha256(transfer_record)
        create_transfer_ledger_schema(store)
        store.connection.execute(
            """
            INSERT INTO coordination_transfer_ledger(
                transfer_key, repository, predecessor_issue_number,
                successor_issue_number, intent_sha256, record_sha256,
                record_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transfer_key,
                repository,
                predecessor_issue_number,
                item["issue_number"],
                expected_transfer_intent_sha256,
                transfer_record_sha256_value,
                transfer_record_json,
                now,
            ),
        )
        store._event(
            "TRANSFER_ADMISSION_ACTIVATED",
            transfer_key,
            activation_event_payload(transfer_record),
            now,
        )
    return {
        "transfer_key": transfer_key,
        "replayed": False,
        "message_id": message_id,
        "activated_issue_number": activated["issue_number"],
        "released_issue_numbers": [entry["issue_number"] for entry in released],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transaction-file", type=Path, required=True)
    args = parser.parse_args()
    store = CoordinationStore(DEFAULT_DATABASE)
    try:
        transaction = json.loads(args.transaction_file.read_text(encoding="utf-8"))
        print(canonical_json(activate_transfer(store, transaction, utc_now())))
        return 0
    except (CoordinationError, json.JSONDecodeError, OSError) as exc:
        error = str(exc) if isinstance(exc, CoordinationError) else "TRANSFER_CONTROL_FAILED"
        print(canonical_json({"phase": "HOLD", "error": error}))
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
