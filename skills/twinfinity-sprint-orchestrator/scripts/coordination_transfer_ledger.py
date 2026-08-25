#!/usr/bin/env python3
"""Durable provenance for cross-issue branch and worktree transfers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from coordination_store import (
    DEFAULT_DATABASE,
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
    utc_now,
)


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COORDINATION_IDENTITY = re.compile(
    r"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|role\.(?:planner|development|sre)\.v[1-9][0-9]*)$"
)
BRANCH = re.compile(r"^codex/(?P<issue>[1-9][0-9]*)-[A-Za-z0-9._-]+$")
TRANSFER_KEY = re.compile(r"^[A-Za-z0-9._-]+$")
ITEM_RESULT_KEYS = {
    "repository",
    "issue_number",
    "status",
    "allocation_class",
    "generation",
    "version",
    "source_payload_sha256",
}
RECORD_KEYS = {
    "transfer_key",
    "repository",
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
    "predecessor_release_status",
    "predecessor_release_allocation_class",
    "successor_issue_number",
    "successor_generation",
    "successor_item_version",
    "successor_source_payload_sha256",
    "successor_admission_message_id",
    "successor_admission_payload_sha256",
    "successor_accountable_session_id",
    "successor_lease_manifest_sha256",
    "successor_development_units",
    "successor_shared_units",
    "successor_sre_units",
    "released_items",
    "activated_item",
    "activation_event_schema",
    "branch",
    "worktree_path",
    "opaque_worktree_id",
    "transfer_authority_sha256",
    "predecessor_comment_id",
    "predecessor_comment_body_sha256",
    "successor_comment_id",
    "successor_comment_body_sha256",
}
INTENT_HASH_EXCLUDED_KEYS = {
    "successor_admission_message_id",
    "successor_admission_payload_sha256",
}


def intent_sha256(record: dict[str, Any]) -> str:
    contract = {
        key: value for key, value in record.items() if key not in INTENT_HASH_EXCLUDED_KEYS
    }
    return hashlib.sha256(canonical_json(contract).encode("utf-8")).hexdigest()


def record_sha256(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()


def create_schema(store: CoordinationStore) -> None:
    store.connection.execute(
        """
        CREATE TABLE IF NOT EXISTS coordination_transfer_ledger (
            transfer_key TEXT PRIMARY KEY,
            repository TEXT NOT NULL,
            predecessor_issue_number INTEGER NOT NULL CHECK(predecessor_issue_number > 0),
            successor_issue_number INTEGER NOT NULL CHECK(successor_issue_number > 0),
            intent_sha256 TEXT NOT NULL UNIQUE,
            record_sha256 TEXT NOT NULL UNIQUE,
            record_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CHECK(predecessor_issue_number <> successor_issue_number)
        )
        """
    )
    columns = {
        row[1]
        for row in store.connection.execute(
            "PRAGMA table_info(coordination_transfer_ledger)"
        )
    }
    if "intent_sha256" not in columns:
        count = int(
            store.connection.execute(
                "SELECT COUNT(*) FROM coordination_transfer_ledger"
            ).fetchone()[0]
        )
        if count:
            raise CoordinationError("TRANSFER_LEDGER_SCHEMA_LEGACY")
        store.connection.execute(
            "ALTER TABLE coordination_transfer_ledger ADD COLUMN intent_sha256 TEXT"
        )
        store.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS coordination_transfer_intent_unique "
            "ON coordination_transfer_ledger(intent_sha256)"
        )


def fetch_comment(repository: str, comment_id: int) -> dict[str, Any]:
    completed = subprocess.run(
        ["gh", "api", f"repos/{repository}/issues/comments/{comment_id}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise CoordinationError("TRANSFER_COMMENT_UNAVAILABLE")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CoordinationError("TRANSFER_COMMENT_INVALID") from exc
    if not isinstance(result, dict):
        raise CoordinationError("TRANSFER_COMMENT_INVALID")
    return result


def validate_record_shape(record: dict[str, Any]) -> None:
    if not isinstance(record, dict) or set(record) != RECORD_KEYS:
        raise CoordinationError("TRANSFER_LEDGER_INVALID")
    integer_fields = (
        "predecessor_issue_number",
        "predecessor_generation",
        "predecessor_item_version",
        "predecessor_admission_item_version",
        "predecessor_admission_message_id",
        "successor_issue_number",
        "successor_generation",
        "successor_item_version",
        "successor_admission_message_id",
        "predecessor_development_units",
        "predecessor_shared_units",
        "predecessor_sre_units",
        "successor_development_units",
        "successor_shared_units",
        "successor_sre_units",
        "predecessor_comment_id",
        "successor_comment_id",
    )
    positive_integer_fields = {
        "predecessor_issue_number",
        "predecessor_item_version",
        "predecessor_admission_item_version",
        "predecessor_admission_message_id",
        "successor_issue_number",
        "successor_item_version",
        "successor_admission_message_id",
        "predecessor_comment_id",
        "successor_comment_id",
    }
    if any(
        type(record[field]) is not int
        or record[field] < 0
        or (field in positive_integer_fields and record[field] == 0)
        for field in integer_fields
    ):
        raise CoordinationError("TRANSFER_LEDGER_INVALID")
    if record["predecessor_issue_number"] == record["successor_issue_number"]:
        raise CoordinationError("TRANSFER_LEDGER_INVALID")
    sha_fields = (
        "predecessor_source_payload_sha256",
        "predecessor_admission_payload_sha256",
        "successor_source_payload_sha256",
        "successor_admission_payload_sha256",
        "predecessor_lease_manifest_sha256",
        "successor_lease_manifest_sha256",
        "transfer_authority_sha256",
        "predecessor_comment_body_sha256",
        "successor_comment_body_sha256",
    )
    if any(not isinstance(record[field], str) or not SHA256.fullmatch(record[field]) for field in sha_fields):
        raise CoordinationError("TRANSFER_LEDGER_INVALID")
    branch = record["branch"]
    branch_match = BRANCH.fullmatch(branch) if isinstance(branch, str) else None
    predecessor = record["predecessor_issue_number"]
    expected_surface = f"twinfinityapp-issue-{predecessor}"
    released_items = record["released_items"]
    activated_item = record["activated_item"]

    def valid_item_result(value: Any) -> bool:
        return bool(
            isinstance(value, dict)
            and set(value) == ITEM_RESULT_KEYS
            and value["repository"] == record["repository"]
            and type(value["issue_number"]) is int
            and value["issue_number"] > 0
            and type(value["generation"]) is int
            and value["generation"] >= 0
            and type(value["version"]) is int
            and value["version"] > 0
            and isinstance(value["source_payload_sha256"], str)
            and SHA256.fullmatch(value["source_payload_sha256"])
        )

    if (
        not isinstance(released_items, list)
        or not released_items
        or len(released_items) > 20
        or any(not valid_item_result(item) for item in released_items)
        or len({item["issue_number"] for item in released_items})
        != len(released_items)
        or not valid_item_result(activated_item)
        or activated_item["status"] not in {"ACTIVE", "ACTIVE_FENCED"}
        or activated_item["allocation_class"] != "ACTIVE"
        or any(
            item["status"] not in {"MONITOR", "DONE"}
            or item["allocation_class"] != "NONE"
            for item in released_items
        )
        or record["activation_event_schema"] != "v2"
    ):
        raise CoordinationError("TRANSFER_LEDGER_INVALID")
    predecessor_release = next(
        (
            item
            for item in released_items
            if item["issue_number"] == predecessor
        ),
        None,
    )
    if (
        not isinstance(record["repository"], str)
        or not TRANSFER_KEY.fullmatch(record["transfer_key"])
        or branch_match is None
        or int(branch_match.group("issue")) != predecessor
        or record["worktree_path"] != f"/home/ubuntu/code/{expected_surface}"
        or record["opaque_worktree_id"] != expected_surface
        or record["predecessor_comment_id"] == record["successor_comment_id"]
        or not isinstance(record["predecessor_accountable_session_id"], str)
        or not COORDINATION_IDENTITY.fullmatch(record["predecessor_accountable_session_id"])
        or not isinstance(record["successor_accountable_session_id"], str)
        or not COORDINATION_IDENTITY.fullmatch(record["successor_accountable_session_id"])
        or record["predecessor_release_status"] not in {"MONITOR", "DONE"}
        or record["predecessor_release_allocation_class"] != "NONE"
        or record["predecessor_pretransfer_status"]
        not in {"ACTIVE", "ACTIVE_FENCED", "MONITOR", "HOLD"}
        or record["predecessor_pretransfer_allocation_class"]
        not in {"ACTIVE", "RETAINED"}
        or record["predecessor_item_version"]
        not in {
            record["predecessor_admission_item_version"],
            record["predecessor_admission_item_version"] + 1,
        }
        or predecessor_release is None
        or predecessor_release["repository"] != record["repository"]
        or predecessor_release["status"] != record["predecessor_release_status"]
        or predecessor_release["allocation_class"]
        != record["predecessor_release_allocation_class"]
        or predecessor_release["generation"] != record["predecessor_generation"] + 1
        or predecessor_release["version"] != record["predecessor_item_version"] + 1
        or predecessor_release["source_payload_sha256"]
        != record["predecessor_source_payload_sha256"]
        or activated_item["repository"] != record["repository"]
        or activated_item["issue_number"] != record["successor_issue_number"]
        or activated_item["generation"] != record["successor_generation"]
        or activated_item["version"] != record["successor_item_version"]
        or activated_item["source_payload_sha256"]
        != record["successor_source_payload_sha256"]
    ):
        raise CoordinationError("TRANSFER_LEDGER_INVALID")


def validate_comments(
    record: dict[str, Any],
    comment_fetcher: Callable[[str, int], dict[str, Any]] | None = None,
) -> None:
    comment_fetcher = fetch_comment if comment_fetcher is None else comment_fetcher
    authority = record["transfer_authority_sha256"]
    for side in ("predecessor", "successor"):
        issue_number = record[f"{side}_issue_number"]
        comment_id = record[f"{side}_comment_id"]
        expected_body_sha256 = record[f"{side}_comment_body_sha256"]
        comment = comment_fetcher(record["repository"], comment_id)
        body = comment.get("body")
        issue_url = comment.get("issue_url")
        if (
            comment.get("id") != comment_id
            or not isinstance(body, str)
            or hashlib.sha256(body.encode("utf-8")).hexdigest() != expected_body_sha256
            or not isinstance(issue_url, str)
            or not issue_url.endswith(
                f"/repos/{record['repository']}/issues/{issue_number}"
            )
            or authority not in body
        ):
            raise CoordinationError("TRANSFER_COMMENT_INVALID")


def _message(store: CoordinationStore, message_id: int) -> Any:
    return store.connection.execute(
        "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
    ).fetchone()


def _validate_admission(
    store: CoordinationStore,
    *,
    message_id: int,
    payload_sha256: str,
    issue_number: int,
    generation: int,
    item_version: int,
    source_payload_sha256: str,
    accountable_session_id: str,
    lease_manifest_sha256: str,
    development_units: int,
    shared_units: int,
    sre_units: int,
    branch: str,
    worktree_path: str,
    opaque_worktree_id: str,
    allow_prepared: bool = False,
) -> Any:
    message = _message(store, message_id)
    valid_state = bool(
        message
        and (
            (
                allow_prepared
                and message["state"] == "PREPARED"
                and message["claimed_by"] is None
            )
            or (
                message["state"] in {"CLAIMED", "COMPLETE", "HOLD"}
                and message["claimed_by"]
                and message["claimed_by"] == message["recipient_session_id"]
            )
        )
    )
    if (
        message is None
        or message["topic"] not in {"development.admission", "sre.admission"}
        or message["payload_sha256"] != payload_sha256
        or not valid_state
        or message["recipient_session_id"] != accountable_session_id
    ):
        raise CoordinationError("TRANSFER_ADMISSION_PROVENANCE_INVALID")
    payload = json.loads(message["payload_json"])
    if (
        payload.get("issue_number") != issue_number
        or payload.get("generation") != generation
        or payload.get("item_version") != item_version
        or payload.get("source", {}).get("payload_sha256")
        != source_payload_sha256
        or payload.get("accountable_session_id") != accountable_session_id
        or payload.get("lease_manifest_sha256") != lease_manifest_sha256
        or payload.get("capacity")
        != {
            "development_units": development_units,
            "shared_units": shared_units,
            "sre_units": sre_units,
        }
        or payload.get("branch") != branch
        or payload.get("worktree_path") != worktree_path
        or payload.get("opaque_worktree_id") != opaque_worktree_id
    ):
        raise CoordinationError("TRANSFER_ADMISSION_PROVENANCE_INVALID")
    return message


def activation_event_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "activated": record["activated_item"],
        "released": record["released_items"],
        "message_id": record["successor_admission_message_id"],
        "transfer_record_sha256": record_sha256(record),
        "transfer_intent_sha256": intent_sha256(record),
    }


def validate_activation_event(
    store: CoordinationStore, record: dict[str, Any]
) -> None:
    expected_payload_sha256 = digest_json(activation_event_payload(record))
    rows = store.connection.execute(
        "SELECT payload_sha256 FROM coordination_events "
        "WHERE event_type='TRANSFER_ADMISSION_ACTIVATED' AND entity_key=?",
        (record["transfer_key"],),
    ).fetchall()
    if (
        len(rows) != 1
        or rows[0]["payload_sha256"] != expected_payload_sha256
    ):
        raise CoordinationError("TRANSFER_EVENT_PROVENANCE_INVALID")


def _validate_predecessor_continuity(
    store: CoordinationStore, record: dict[str, Any]
) -> None:
    if (
        record["predecessor_item_version"]
        == record["predecessor_admission_item_version"]
    ):
        return
    expected = {
        "repository": record["repository"],
        "issue_number": record["predecessor_issue_number"],
        "status": record["predecessor_pretransfer_status"],
        "allocation_class": record["predecessor_pretransfer_allocation_class"],
        "generation": record["predecessor_generation"],
        "version": record["predecessor_item_version"],
        "source_payload_sha256": record["predecessor_source_payload_sha256"],
    }
    count = store.connection.execute(
        "SELECT COUNT(*) FROM coordination_events "
        "WHERE event_type='ISSUE_STATUS_CHANGED' AND entity_key=? "
        "AND payload_sha256=?",
        (
            f"{record['repository']}:issue:{record['predecessor_issue_number']}",
            digest_json(expected),
        ),
    ).fetchone()[0]
    if int(count) != 1:
        raise CoordinationError("TRANSFER_PREDECESSOR_CONTINUITY_INVALID")


def predecessor_snapshot_event_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": record["repository"],
        "issue_number": record["predecessor_issue_number"],
        "status": record["predecessor_pretransfer_status"],
        "allocation_class": record["predecessor_pretransfer_allocation_class"],
        "generation": record["predecessor_generation"],
        "version": record["predecessor_item_version"],
        "source_payload_sha256": record["predecessor_source_payload_sha256"],
        "accountable_session_id": record["predecessor_accountable_session_id"],
        "lease_manifest_sha256": record["predecessor_lease_manifest_sha256"],
        "development_units": record["predecessor_development_units"],
        "shared_units": record["predecessor_shared_units"],
        "sre_units": record["predecessor_sre_units"],
        "admission_message_id": record["predecessor_admission_message_id"],
        "admission_payload_sha256": record[
            "predecessor_admission_payload_sha256"
        ],
        "transfer_intent_sha256": intent_sha256(record),
    }


def validate_predecessor_snapshot_event(
    store: CoordinationStore, record: dict[str, Any]
) -> None:
    expected = digest_json(predecessor_snapshot_event_payload(record))
    rows = store.connection.execute(
        "SELECT payload_sha256 FROM coordination_events "
        "WHERE event_type='TRANSFER_PREDECESSOR_BOUND' AND entity_key=?",
        (record["transfer_key"],),
    ).fetchall()
    if len(rows) != 1 or rows[0]["payload_sha256"] != expected:
        raise CoordinationError("TRANSFER_PREDECESSOR_SNAPSHOT_INVALID")


def validate_predecessor_provenance(
    store: CoordinationStore,
    record: dict[str, Any],
    *,
    require_current: bool,
    require_snapshot: bool = True,
) -> None:
    """Bind the transfer to the exact predecessor lease and its state history."""
    validate_record_shape(record)
    if require_current:
        predecessor = store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (record["repository"], record["predecessor_issue_number"]),
        ).fetchone()
        if (
            predecessor is None
            or predecessor["status"] != record["predecessor_pretransfer_status"]
            or predecessor["allocation_class"]
            != record["predecessor_pretransfer_allocation_class"]
            or int(predecessor["generation"]) != record["predecessor_generation"]
            or int(predecessor["version"]) != record["predecessor_item_version"]
            or predecessor["source_payload_sha256"]
            != record["predecessor_source_payload_sha256"]
            or predecessor["accountable_session_id"]
            != record["predecessor_accountable_session_id"]
            or predecessor["lease_manifest_sha256"]
            != record["predecessor_lease_manifest_sha256"]
            or int(predecessor["development_units"])
            != record["predecessor_development_units"]
            or int(predecessor["shared_units"])
            != record["predecessor_shared_units"]
            or int(predecessor["sre_units"])
            != record["predecessor_sre_units"]
        ):
            raise CoordinationError("TRANSFER_PREDECESSOR_OWNERSHIP_INVALID")
    try:
        _validate_admission(
            store,
            message_id=record["predecessor_admission_message_id"],
            payload_sha256=record["predecessor_admission_payload_sha256"],
            issue_number=record["predecessor_issue_number"],
            generation=record["predecessor_generation"],
            item_version=record["predecessor_admission_item_version"],
            source_payload_sha256=record["predecessor_source_payload_sha256"],
            accountable_session_id=record["predecessor_accountable_session_id"],
            lease_manifest_sha256=record["predecessor_lease_manifest_sha256"],
            development_units=record["predecessor_development_units"],
            shared_units=record["predecessor_shared_units"],
            sre_units=record["predecessor_sre_units"],
            branch=record["branch"],
            worktree_path=record["worktree_path"],
            opaque_worktree_id=record["opaque_worktree_id"],
        )
        _validate_predecessor_continuity(store, record)
        if require_snapshot:
            validate_predecessor_snapshot_event(store, record)
    except CoordinationError as exc:
        if str(exc) in {
            "TRANSFER_ADMISSION_PROVENANCE_INVALID",
            "TRANSFER_PREDECESSOR_CONTINUITY_INVALID",
            "TRANSFER_PREDECESSOR_SNAPSHOT_INVALID",
        }:
            raise CoordinationError("TRANSFER_PREDECESSOR_OWNERSHIP_INVALID") from exc
        raise


def validate_existing_state(store: CoordinationStore, record: dict[str, Any]) -> None:
    validate_record_shape(record)
    repository = record["repository"]
    predecessor = store.connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (repository, record["predecessor_issue_number"]),
    ).fetchone()
    successor = store.connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (repository, record["successor_issue_number"]),
    ).fetchone()
    if (
        predecessor is None
        or predecessor["status"] not in {"MONITOR", "DONE"}
        or predecessor["allocation_class"] != "NONE"
        or predecessor["accountable_session_id"] is not None
        or predecessor["lease_manifest_sha256"] is not None
        or any(int(predecessor[key]) != 0 for key in ("development_units", "shared_units", "sre_units"))
        or int(predecessor["generation"]) != record["predecessor_generation"] + 1
        or int(predecessor["version"]) != record["predecessor_item_version"] + 1
        or predecessor["source_payload_sha256"] != record["predecessor_source_payload_sha256"]
        or successor is None
        or int(successor["generation"]) < record["successor_generation"]
        or int(successor["version"]) < record["successor_item_version"]
        or successor["source_payload_sha256"] != record["successor_source_payload_sha256"]
        or successor["accountable_session_id"]
        != record["successor_accountable_session_id"]
        or successor["lease_manifest_sha256"]
        != record["successor_lease_manifest_sha256"]
        or int(successor["development_units"])
        != record["successor_development_units"]
        or int(successor["shared_units"])
        != record["successor_shared_units"]
        or int(successor["sre_units"])
        != record["successor_sre_units"]
    ):
        raise CoordinationError("TRANSFER_LEDGER_STATE_INVALID")
    for released in record["released_items"]:
        released_row = store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (released["repository"], released["issue_number"]),
        ).fetchone()
        if (
            released_row is None
            or released_row["status"] != released["status"]
            or released_row["allocation_class"] != released["allocation_class"]
            or int(released_row["generation"]) != released["generation"]
            or int(released_row["version"]) != released["version"]
            or released_row["source_payload_sha256"]
            != released["source_payload_sha256"]
            or released_row["accountable_session_id"] is not None
            or released_row["lease_manifest_sha256"] is not None
            or any(
                int(released_row[key]) != 0
                for key in ("development_units", "shared_units", "sre_units")
            )
        ):
            raise CoordinationError("TRANSFER_LEDGER_STATE_INVALID")
    for issue_field, source_field in (
        ("predecessor_issue_number", "predecessor_source_payload_sha256"),
        ("successor_issue_number", "successor_source_payload_sha256"),
    ):
        current = store.current_snapshot(repository, "issue", record[issue_field])
        if current is None or current.payload_sha256 != record[source_field]:
            raise CoordinationError("TRANSFER_LEDGER_SOURCE_DRIFT")
    validate_predecessor_provenance(store, record, require_current=False)
    successor_message = _validate_admission(
        store,
        message_id=record["successor_admission_message_id"],
        payload_sha256=record["successor_admission_payload_sha256"],
        issue_number=record["successor_issue_number"],
        generation=record["successor_generation"],
        item_version=record["successor_item_version"],
        source_payload_sha256=record["successor_source_payload_sha256"],
        accountable_session_id=record["successor_accountable_session_id"],
        lease_manifest_sha256=record["successor_lease_manifest_sha256"],
        development_units=record["successor_development_units"],
        shared_units=record["successor_shared_units"],
        sre_units=record["successor_sre_units"],
        branch=record["branch"],
        worktree_path=record["worktree_path"],
        opaque_worktree_id=record["opaque_worktree_id"],
        allow_prepared=True,
    )
    successor_payload = json.loads(successor_message["payload_json"])
    expected_binding = successor_payload.get("transfer_intent_sha256") == intent_sha256(
        record
    )
    if (
        successor_payload.get("parent_issue_number") != record["predecessor_issue_number"]
        or successor_payload.get("transfer_key") != record["transfer_key"]
        or successor_payload.get("transfer_comment_ids")
        != [record["predecessor_comment_id"], record["successor_comment_id"]]
        or successor_payload.get("authority_sha256") != record["transfer_authority_sha256"]
        or not expected_binding
    ):
        raise CoordinationError("TRANSFER_ADMISSION_PROVENANCE_INVALID")
    validate_activation_event(store, record)


def record_existing(
    store: CoordinationStore,
    record: dict[str, Any],
    now: str,
    *,
    comment_fetcher: Callable[[str, int], dict[str, Any]] | None = None,
) -> str:
    validate_record_shape(record)
    validate_comments(record, comment_fetcher)
    with store.transaction():
        create_schema(store)
        validate_existing_state(store, record)
        record_json = canonical_json(record)
        intent_sha256_value = intent_sha256(record)
        record_sha256_value = record_sha256(record)
        existing = store.connection.execute(
            "SELECT * FROM coordination_transfer_ledger WHERE transfer_key=?",
            (record["transfer_key"],),
        ).fetchone()
        if existing is not None:
            if (
                existing["record_sha256"] != record_sha256_value
                or existing["intent_sha256"] != intent_sha256_value
                or existing["record_json"] != record_json
            ):
                raise CoordinationError("TRANSFER_LEDGER_IDEMPOTENCY_CONFLICT")
            return record_sha256_value
        store.connection.execute(
            """
            INSERT INTO coordination_transfer_ledger(
                transfer_key, repository, predecessor_issue_number,
                successor_issue_number, intent_sha256, record_sha256,
                record_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["transfer_key"],
                record["repository"],
                record["predecessor_issue_number"],
                record["successor_issue_number"],
                intent_sha256_value,
                record_sha256_value,
                record_json,
                now,
            ),
        )
        store._event(
            "TRANSFER_LEDGER_RECORDED",
            record["transfer_key"],
            {
                "intent_sha256": intent_sha256_value,
                "record_sha256": record_sha256_value,
                "successor_admission_message_id": record[
                    "successor_admission_message_id"
                ],
                "successor_admission_payload_sha256": record[
                    "successor_admission_payload_sha256"
                ],
            },
            now,
        )
        return record_sha256_value


def load_record(store: CoordinationStore, transfer_key: str) -> tuple[dict[str, Any], str]:
    try:
        columns = {
            row[1]
            for row in store.connection.execute(
                "PRAGMA table_info(coordination_transfer_ledger)"
            )
        }
        if not columns:
            raise CoordinationError("TRANSFER_LEDGER_ABSENT")
        required_columns = {
            "transfer_key",
            "repository",
            "predecessor_issue_number",
            "successor_issue_number",
            "intent_sha256",
            "record_sha256",
            "record_json",
            "created_at",
        }
        if not required_columns.issubset(columns):
            raise CoordinationError("TRANSFER_LEDGER_SCHEMA_LEGACY")
        row = store.connection.execute(
            "SELECT * FROM coordination_transfer_ledger WHERE transfer_key=?",
            (transfer_key,),
        ).fetchone()
    except CoordinationError:
        raise
    except Exception as exc:
        raise CoordinationError("TRANSFER_LEDGER_ABSENT") from exc
    if row is None:
        raise CoordinationError("TRANSFER_LEDGER_ABSENT")
    record = json.loads(row["record_json"])
    validate_record_shape(record)
    if (
        record_sha256(record) != row["record_sha256"]
        or intent_sha256(record) != row["intent_sha256"]
        or canonical_json(record) != row["record_json"]
    ):
        raise CoordinationError("TRANSFER_LEDGER_CORRUPT")
    return record, row["record_sha256"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-file", type=Path, required=True)
    args = parser.parse_args()
    store = CoordinationStore(DEFAULT_DATABASE)
    try:
        record = json.loads(args.record_file.read_text(encoding="utf-8"))
        digest = record_existing(store, record, utc_now())
        print(canonical_json({"phase": "COMPLETE", "record_sha256": digest}))
        return 0
    except (CoordinationError, json.JSONDecodeError, OSError) as exc:
        error = str(exc) if isinstance(exc, CoordinationError) else "TRANSFER_LEDGER_FAILED"
        print(canonical_json({"phase": "HOLD", "error": error}))
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
