#!/usr/bin/env python3
"""Central same-host user approval ledger for Twinfinity workstreams.

Approval proposals and user decisions are immutable.  A small mutable current
pointer selects the newest proposal for a decision key, and a delivery row
tracks exact-recipient claim/acknowledgement.  GitHub is an external audit
destination: a decision cannot be claimed until its owning-issue outbox record
has been published and read back successfully.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any, Callable

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
    canonicalize_coordination_identity,
    coordination_identity_role,
    digest_json,
    utc_now,
)
from executor_registry import (
    ENDPOINT_ID,
    canonical_endpoint_id,
    configured_identity_role,
    current_endpoint,
    identities_role_equivalent,
    load_legacy_aliases,
    load_registry_config,
)
from sync_github_coordination import fetch_object


SCHEMA = "twinfinity.approval-proposal.v1"
DECISIONS = {"APPROVE", "REJECT", "COURSE_CORRECT", "DEFER"}
USER_EVENT_SOURCES = {
    "CODEX_DIRECT_USER_TURN",
    "GITHUB_USER_COMMENT",
    "EXTERNAL_CLIENT_RECORD",
}
PRIORITIES = {"P0", "P1", "P2"}
URGENCIES = {"ACTIVE_BLOCKER", "READY_BLOCKER", "FUTURE", "INFORMATIONAL"}
WORKSTREAMS = {"DEVELOPMENT", "SRE", "PLANNER", "PORTFOLIO", "CLIENT"}
WORKSTREAM_ROLES = {
    "DEVELOPMENT": "development",
    "SRE": "sre",
    "PLANNER": "planner",
    "PORTFOLIO": "planner",
    "CLIENT": "planner",
}
BOUNDARIES = {
    "PRODUCT_BEHAVIOR",
    "UX_FLOW",
    "PERSISTENT_DATA",
    "PUBLIC_CONTRACT",
    "SECURITY_PRIVACY",
    "HOSTED_PROVIDER",
    "DESTRUCTIVE",
    "EXTERNAL_COMMITMENT",
    "CAPACITY_POLICY",
    "OTHER_MATERIAL",
}
PACKET_KEYS = {
    "schema",
    "decision_key",
    "repository",
    "owning_issue",
    "source_snapshot_sha256",
    "execution_scope_sha256",
    "requester_session_id",
    "recipient_session_id",
    "workstream",
    "boundary",
    "priority",
    "urgency",
    "summary",
    "question",
    "requested_action",
    "target",
    "affected_issues",
    "blocked_mutation",
    "immediate_beneficiary",
    "evidence",
    "risk",
    "drift_guards",
    "prohibited_side_effects",
    "options",
    "recommendation",
    "expires_at",
}
SESSION = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DECISION_KEY = re.compile(r"^[a-z0-9][a-z0-9._:/-]{2,159}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPTION_ID = re.compile(r"^[A-Z][A-Z0-9_]{1,39}$")
USER_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$")
SENSITIVE_VALUE = re.compile(
    r"(?i)(?:\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"client[_ -]?secret|password|private[_ -]?key)\b\s*[:=]\s*\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{12,})"
)
URL_QUERY = re.compile(r"https?://\S+\?\S+")


def _identity_syntax(value: Any) -> bool:
    return isinstance(value, str) and bool(
        SESSION.fullmatch(value) or ENDPOINT_ID.fullmatch(value)
    )


def _reviewed_role_alias(role: str) -> str:
    return next(
        alias for alias, alias_role in load_legacy_aliases().aliases.items()
        if alias_role == role
    )


def _current_role_route(store: CoordinationStore, role: str) -> str:
    """Select the current endpoint or the configured migration target."""

    endpoint = current_endpoint(store.connection, role)
    return (
        str(endpoint["endpoint_id"])
        if endpoint is not None
        else load_registry_config().roles[role].endpoint_id
    )


def _historical_identity_current_route(
    store: CoordinationStore, identity: str
) -> str:
    """Resolve one immutable historical row to its role's current consumer."""

    return canonical_endpoint_id(store.connection, identity) or identity


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoordinationError("APPROVAL_PACKET_DUPLICATE_KEY")
        result[key] = value
    return result


def _validate_text(value: Any, field: str, *, maximum: int = 2000) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise CoordinationError(f"APPROVAL_{field.upper()}_INVALID")
    if SENSITIVE_VALUE.search(value) or URL_QUERY.search(value):
        raise CoordinationError("APPROVAL_SENSITIVE_CONTENT")
    return value.strip()


def _validate_string_list(
    value: Any, field: str, *, maximum_items: int = 20, maximum_text: int = 1000
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise CoordinationError(f"APPROVAL_{field.upper()}_INVALID")
    return [
        _validate_text(item, field, maximum=maximum_text)
        for item in value
    ]


def validate_packet(packet: Any) -> dict[str, Any]:
    if not isinstance(packet, dict) or set(packet) != PACKET_KEYS:
        raise CoordinationError("APPROVAL_PACKET_SCHEMA_INVALID")
    if packet["schema"] != SCHEMA:
        raise CoordinationError("APPROVAL_PACKET_SCHEMA_INVALID")
    if (
        not isinstance(packet["decision_key"], str)
        or not DECISION_KEY.fullmatch(packet["decision_key"])
        or not isinstance(packet["repository"], str)
        or not REPOSITORY.fullmatch(packet["repository"])
        or type(packet["owning_issue"]) is not int
        or packet["owning_issue"] <= 0
        or not isinstance(packet["source_snapshot_sha256"], str)
        or not SHA256.fullmatch(packet["source_snapshot_sha256"])
        or not isinstance(packet["execution_scope_sha256"], str)
        or not SHA256.fullmatch(packet["execution_scope_sha256"])
        or not isinstance(packet["requester_session_id"], str)
        or not _identity_syntax(packet["requester_session_id"])
        or not isinstance(packet["recipient_session_id"], str)
        or not _identity_syntax(packet["recipient_session_id"])
        or packet["workstream"] not in WORKSTREAMS
        or packet["boundary"] not in BOUNDARIES
        or packet["priority"] not in PRIORITIES
        or packet["urgency"] not in URGENCIES
    ):
        raise CoordinationError("APPROVAL_PACKET_FIELD_INVALID")
    expected_role = WORKSTREAM_ROLES[packet["workstream"]]
    if (
        configured_identity_role(packet["requester_session_id"]) != expected_role
        or configured_identity_role(packet["recipient_session_id"]) != expected_role
    ):
        raise CoordinationError("APPROVAL_CANONICAL_PARENT_REQUIRED")

    normalized = dict(packet)
    for field in (
        "summary",
        "question",
        "requested_action",
        "target",
        "blocked_mutation",
        "immediate_beneficiary",
        "risk",
    ):
        normalized[field] = _validate_text(packet[field], field)
    affected = packet["affected_issues"]
    if (
        not isinstance(affected, list)
        or not affected
        or len(affected) > 30
        or any(type(value) is not int or value <= 0 for value in affected)
        or len(set(affected)) != len(affected)
    ):
        raise CoordinationError("APPROVAL_AFFECTED_ISSUES_INVALID")
    normalized["affected_issues"] = affected
    normalized["evidence"] = _validate_string_list(packet["evidence"], "evidence")
    normalized["drift_guards"] = _validate_string_list(
        packet["drift_guards"], "drift_guards"
    )
    if not normalized["drift_guards"]:
        raise CoordinationError("APPROVAL_DRIFT_GUARDS_INVALID")
    normalized["prohibited_side_effects"] = _validate_string_list(
        packet["prohibited_side_effects"], "prohibited_side_effects"
    )
    if not normalized["prohibited_side_effects"]:
        raise CoordinationError("APPROVAL_PROHIBITED_SIDE_EFFECTS_INVALID")

    options = packet["options"]
    if not isinstance(options, list) or not 2 <= len(options) <= 5:
        raise CoordinationError("APPROVAL_OPTIONS_INVALID")
    normalized_options: list[dict[str, str]] = []
    option_ids: set[str] = set()
    for option in options:
        if not isinstance(option, dict) or set(option) != {"id", "label", "effect"}:
            raise CoordinationError("APPROVAL_OPTIONS_INVALID")
        option_id = option["id"]
        if (
            not isinstance(option_id, str)
            or not OPTION_ID.fullmatch(option_id)
            or option_id in option_ids
        ):
            raise CoordinationError("APPROVAL_OPTIONS_INVALID")
        option_ids.add(option_id)
        normalized_options.append(
            {
                "id": option_id,
                "label": _validate_text(option["label"], "option", maximum=120),
                "effect": _validate_text(option["effect"], "option", maximum=800),
            }
        )
    normalized["options"] = normalized_options
    if packet["recommendation"] not in option_ids:
        raise CoordinationError("APPROVAL_RECOMMENDATION_INVALID")
    if packet["expires_at"] is not None:
        normalized["expires_at"] = _validate_text(
            packet["expires_at"], "expires_at", maximum=40
        )
        try:
            datetime.fromisoformat(normalized["expires_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise CoordinationError("APPROVAL_EXPIRES_AT_INVALID") from exc
    return normalized


def _expired(packet: dict[str, Any], now: str) -> bool:
    expires_at = packet.get("expires_at")
    if expires_at is None:
        return False
    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    observed = datetime.fromisoformat(now.replace("Z", "+00:00"))
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    return observed >= expiry


def ensure_schema(connection: sqlite3.Connection) -> None:
    try:
        connection.executescript(
            """
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS approval_proposals (
            proposal_sha256 TEXT PRIMARY KEY,
            semantic_sha256 TEXT NOT NULL UNIQUE,
            decision_key TEXT NOT NULL,
            repository TEXT NOT NULL,
            owning_issue INTEGER NOT NULL CHECK(owning_issue > 0),
            source_snapshot_sha256 TEXT NOT NULL,
            source_updated_at TEXT NOT NULL,
            proposal_generation INTEGER NOT NULL CHECK(proposal_generation > 0),
            requester_session_id TEXT NOT NULL,
            recipient_session_id TEXT NOT NULL,
            workstream TEXT NOT NULL,
            boundary TEXT NOT NULL,
            priority TEXT NOT NULL,
            urgency TEXT NOT NULL,
            supersedes_sha256 TEXT,
            packet_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(supersedes_sha256) REFERENCES approval_proposals(proposal_sha256)
        );
        CREATE TABLE IF NOT EXISTS approval_current (
            repository TEXT NOT NULL,
            owning_issue INTEGER NOT NULL CHECK(owning_issue > 0),
            decision_key TEXT NOT NULL,
            proposal_sha256 TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(repository, owning_issue, decision_key),
            FOREIGN KEY(proposal_sha256) REFERENCES approval_proposals(proposal_sha256)
        );
        CREATE TABLE IF NOT EXISTS approval_submissions (
            submission_sha256 TEXT PRIMARY KEY,
            proposal_sha256 TEXT NOT NULL,
            requester_session_id TEXT NOT NULL,
            recipient_session_id TEXT NOT NULL,
            workstream TEXT NOT NULL,
            packet_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(proposal_sha256) REFERENCES approval_proposals(proposal_sha256)
        );
        CREATE TABLE IF NOT EXISTS approval_interests (
            proposal_sha256 TEXT NOT NULL,
            recipient_session_id TEXT NOT NULL,
            requester_session_id TEXT NOT NULL,
            workstream TEXT NOT NULL,
            priority TEXT NOT NULL,
            urgency TEXT NOT NULL,
            latest_submission_sha256 TEXT NOT NULL,
            submission_count INTEGER NOT NULL CHECK(submission_count > 0),
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            PRIMARY KEY(proposal_sha256, recipient_session_id),
            FOREIGN KEY(proposal_sha256) REFERENCES approval_proposals(proposal_sha256),
            FOREIGN KEY(latest_submission_sha256) REFERENCES approval_submissions(submission_sha256)
        );
        CREATE TABLE IF NOT EXISTS approval_user_events (
            user_event_source TEXT NOT NULL,
            user_event_id TEXT NOT NULL,
            user_input_sha256 TEXT NOT NULL,
            planner_session_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_event_source, user_event_id)
        );
        CREATE TABLE IF NOT EXISTS approval_decisions (
            proposal_sha256 TEXT PRIMARY KEY,
            decision_sha256 TEXT NOT NULL UNIQUE,
            decision TEXT NOT NULL CHECK(decision IN ('APPROVE','REJECT','COURSE_CORRECT','DEFER')),
            selected_option_id TEXT NOT NULL,
            revisit_trigger TEXT,
            recipient_set_sha256 TEXT NOT NULL,
            execution_scope_sha256 TEXT NOT NULL,
            decision_note TEXT NOT NULL,
            user_input_sha256 TEXT NOT NULL,
            user_event_source TEXT NOT NULL,
            user_event_id TEXT NOT NULL,
            planner_session_id TEXT NOT NULL,
            owner_outbox_id INTEGER NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            FOREIGN KEY(proposal_sha256) REFERENCES approval_proposals(proposal_sha256),
            FOREIGN KEY(owner_outbox_id) REFERENCES github_outbox(id),
            FOREIGN KEY(user_event_source, user_event_id)
                REFERENCES approval_user_events(user_event_source, user_event_id)
        );
        CREATE TABLE IF NOT EXISTS approval_revocations (
            decision_sha256 TEXT PRIMARY KEY,
            proposal_sha256 TEXT NOT NULL,
            reason TEXT NOT NULL,
            user_event_source TEXT NOT NULL,
            user_event_id TEXT NOT NULL,
            user_input_sha256 TEXT NOT NULL,
            planner_session_id TEXT NOT NULL,
            owner_outbox_id INTEGER NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            FOREIGN KEY(proposal_sha256) REFERENCES approval_decisions(proposal_sha256),
            FOREIGN KEY(decision_sha256) REFERENCES approval_decisions(decision_sha256),
            FOREIGN KEY(owner_outbox_id) REFERENCES github_outbox(id),
            FOREIGN KEY(user_event_source, user_event_id)
                REFERENCES approval_user_events(user_event_source, user_event_id)
        );
        CREATE TABLE IF NOT EXISTS approval_deliveries (
            proposal_sha256 TEXT NOT NULL,
            decision_sha256 TEXT NOT NULL,
            recipient_session_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('WAITING_PUBLICATION','CLAIMED','ACKNOWLEDGED','HOLD')),
            claimed_at TEXT,
            acknowledged_at TEXT,
            updated_at TEXT NOT NULL,
            last_error TEXT,
            PRIMARY KEY(proposal_sha256, recipient_session_id),
            FOREIGN KEY(proposal_sha256) REFERENCES approval_decisions(proposal_sha256),
            FOREIGN KEY(decision_sha256) REFERENCES approval_decisions(decision_sha256)
        );
        CREATE TABLE IF NOT EXISTS approval_proposal_notices (
            proposal_sha256 TEXT PRIMARY KEY,
            message_id INTEGER NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            FOREIGN KEY(proposal_sha256) REFERENCES approval_proposals(proposal_sha256),
            FOREIGN KEY(message_id) REFERENCES coordination_messages(id)
        );
        CREATE TABLE IF NOT EXISTS approval_effectivity (
            proposal_sha256 TEXT PRIMARY KEY,
            decision_sha256 TEXT NOT NULL UNIQUE,
            effective_source_sha256 TEXT NOT NULL,
            remote_receipt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(proposal_sha256) REFERENCES approval_decisions(proposal_sha256),
            FOREIGN KEY(decision_sha256) REFERENCES approval_decisions(decision_sha256)
        );
        CREATE TABLE IF NOT EXISTS approval_review_batches (
            batch_sha256 TEXT PRIMARY KEY,
            repository TEXT NOT NULL,
            proposal_sha256_json TEXT NOT NULL,
            proposal_count INTEGER NOT NULL CHECK(proposal_count >= 0),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS approval_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS approval_pending_order
            ON approval_proposals(repository, urgency, priority, created_at);
        CREATE TRIGGER IF NOT EXISTS approval_proposals_immutable_update
        BEFORE UPDATE ON approval_proposals
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_PROPOSAL_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_proposals_immutable_delete
        BEFORE DELETE ON approval_proposals
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_PROPOSAL_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_decisions_immutable_update
        BEFORE UPDATE ON approval_decisions
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_DECISION_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_decisions_immutable_delete
        BEFORE DELETE ON approval_decisions
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_DECISION_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_submissions_immutable_update
        BEFORE UPDATE ON approval_submissions
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_SUBMISSION_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_submissions_immutable_delete
        BEFORE DELETE ON approval_submissions
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_SUBMISSION_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_user_events_immutable_update
        BEFORE UPDATE ON approval_user_events
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_USER_EVENT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_user_events_immutable_delete
        BEFORE DELETE ON approval_user_events
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_USER_EVENT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_revocations_immutable_update
        BEFORE UPDATE ON approval_revocations
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_REVOCATION_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_revocations_immutable_delete
        BEFORE DELETE ON approval_revocations
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_REVOCATION_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_delivery_envelope_immutable
        BEFORE UPDATE ON approval_deliveries
        WHEN NEW.proposal_sha256 IS NOT OLD.proposal_sha256
          OR NEW.decision_sha256 IS NOT OLD.decision_sha256
          OR NEW.recipient_session_id IS NOT OLD.recipient_session_id
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_DELIVERY_ENVELOPE_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_effectivity_immutable_update
        BEFORE UPDATE ON approval_effectivity
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_EFFECTIVITY_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS approval_effectivity_immutable_delete
        BEFORE DELETE ON approval_effectivity
        BEGIN SELECT RAISE(ABORT, 'APPROVAL_EFFECTIVITY_IMMUTABLE'); END;
        COMMIT;
            """
        )
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _event(
    connection: sqlite3.Connection,
    event_type: str,
    entity_key: str,
    payload: Any,
    now: str,
) -> None:
    connection.execute(
        "INSERT INTO approval_events(event_type,entity_key,payload_sha256,created_at) "
        "VALUES (?,?,?,?)",
        (event_type, entity_key, digest_json(payload), now),
    )


def _source_is_current(store: CoordinationStore, packet: dict[str, Any]) -> bool:
    source = store.current_snapshot(
        packet["repository"], "issue", packet["owning_issue"]
    )
    return bool(
        source and source.payload_sha256 == packet["source_snapshot_sha256"]
    )


def _stable_source_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "updated_at" and not key.startswith("_projection_")
    }


def _semantic_packet(packet: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "schema",
        "decision_key",
        "repository",
        "owning_issue",
        "source_snapshot_sha256",
        "execution_scope_sha256",
        "boundary",
        "summary",
        "question",
        "requested_action",
        "target",
        "affected_issues",
        "blocked_mutation",
        "immediate_beneficiary",
        "risk",
        "drift_guards",
        "prohibited_side_effects",
        "options",
        "recommendation",
        "expires_at",
    )
    return {key: packet[key] for key in keys}


def _retire_planner_notice(
    store: CoordinationStore, proposal_sha256: str, now: str
) -> None:
    row = store.connection.execute(
        """
        SELECT m.id,m.state,m.claimed_by FROM approval_proposal_notices n
        JOIN coordination_messages m ON m.id=n.message_id
        WHERE n.proposal_sha256=?
        """,
        (proposal_sha256,),
    ).fetchone()
    if row is None or row["state"] in {"COMPLETE", "HOLD"}:
        return
    if (
        row["state"] == "CLAIMED"
        and coordination_identity_role(store.connection, row["claimed_by"])
        != "planner"
    ):
        raise CoordinationError("APPROVAL_NOTICE_RECIPIENT_MISMATCH")
    planner_endpoint = canonicalize_coordination_identity(
        store.connection, _current_role_route(store, "planner")
    )
    store.connection.execute(
        """
        UPDATE coordination_messages
        SET state='COMPLETE', claimed_by=?, updated_at=?, last_error=NULL
        WHERE id=? AND state IN ('PREPARED','CLAIMED')
        """,
        (planner_endpoint, now, int(row["id"])),
    )
    store._event(
        "MESSAGE_COMPLETED",
        f"message:{int(row['id'])}",
        {"session_id": planner_endpoint},
        now,
    )


def _record_interest(
    store: CoordinationStore,
    *,
    proposal_sha256: str,
    submission_sha256: str,
    packet: dict[str, Any],
    now: str,
) -> None:
    store.connection.execute(
        """
        INSERT INTO approval_submissions(
            submission_sha256, proposal_sha256, requester_session_id,
            recipient_session_id, workstream, packet_json, created_at
        ) VALUES (?,?,?,?,?,?,?)
        """,
        (
            submission_sha256,
            proposal_sha256,
            packet["requester_session_id"],
            packet["recipient_session_id"],
            packet["workstream"],
            canonical_json(packet),
            now,
        ),
    )
    existing = store.connection.execute(
        """
        SELECT * FROM approval_interests
        WHERE proposal_sha256=? AND recipient_session_id=?
        """,
        (proposal_sha256, packet["recipient_session_id"]),
    ).fetchone()
    priority_rank = {"P0": 0, "P1": 1, "P2": 2}
    urgency_rank = {
        "ACTIVE_BLOCKER": 0,
        "READY_BLOCKER": 1,
        "FUTURE": 2,
        "INFORMATIONAL": 3,
    }
    priority = packet["priority"]
    urgency = packet["urgency"]
    if existing is not None:
        if priority_rank[existing["priority"]] < priority_rank[priority]:
            priority = existing["priority"]
        if urgency_rank[existing["urgency"]] < urgency_rank[urgency]:
            urgency = existing["urgency"]
    store.connection.execute(
        """
        INSERT INTO approval_interests(
            proposal_sha256, recipient_session_id, requester_session_id,
            workstream, priority, urgency, latest_submission_sha256,
            submission_count, first_seen_at, last_seen_at
        ) VALUES (?,?,?,?,?,?,?,1,?,?)
        ON CONFLICT(proposal_sha256, recipient_session_id) DO UPDATE SET
            requester_session_id=excluded.requester_session_id,
            workstream=excluded.workstream,
            priority=excluded.priority,
            urgency=excluded.urgency,
            latest_submission_sha256=excluded.latest_submission_sha256,
            submission_count=approval_interests.submission_count+1,
            last_seen_at=excluded.last_seen_at
        """,
        (
            proposal_sha256,
            packet["recipient_session_id"],
            packet["requester_session_id"],
            packet["workstream"],
            priority,
            urgency,
            submission_sha256,
            now,
            now,
        ),
    )


def submit_proposal(
    store: CoordinationStore, packet: dict[str, Any], now: str
) -> dict[str, Any]:
    ensure_schema(store.connection)
    packet = validate_packet(packet)
    packet = dict(packet)
    packet["requester_session_id"] = canonicalize_coordination_identity(
        store.connection, packet["requester_session_id"]
    )
    packet["recipient_session_id"] = canonicalize_coordination_identity(
        store.connection, packet["recipient_session_id"]
    )
    submission_sha256 = digest_json(packet)
    semantic_sha256 = digest_json(_semantic_packet(packet))
    proposal_sha256 = semantic_sha256
    with store.transaction():
        if not _source_is_current(store, packet):
            raise CoordinationError("APPROVAL_SOURCE_SNAPSHOT_DRIFT")
        submission = store.connection.execute(
            "SELECT proposal_sha256 FROM approval_submissions WHERE submission_sha256=?",
            (submission_sha256,),
        ).fetchone()
        if submission is not None:
            return {
                "proposal_sha256": submission["proposal_sha256"],
                "submission_sha256": submission_sha256,
                "state": "PENDING",
                "idempotent": True,
            }
        current = store.connection.execute(
            """
            SELECT p.*, d.decision, d.decision_sha256,
                   r.decision_sha256 AS revoked_decision_sha256,
                   (SELECT COUNT(*) FROM approval_deliveries x
                    WHERE x.proposal_sha256=p.proposal_sha256
                      AND x.state NOT IN ('ACKNOWLEDGED','HOLD')) AS open_deliveries
            FROM approval_current c
            JOIN approval_proposals p USING(proposal_sha256)
            LEFT JOIN approval_decisions d USING(proposal_sha256)
            LEFT JOIN approval_revocations r USING(proposal_sha256)
            WHERE c.repository=? AND c.owning_issue=? AND c.decision_key=?
            """,
            (packet["repository"], packet["owning_issue"], packet["decision_key"]),
        ).fetchone()
        if current is not None and current["proposal_sha256"] == proposal_sha256:
            existing_interest = store.connection.execute(
                "SELECT 1 FROM approval_interests WHERE proposal_sha256=? "
                "AND recipient_session_id=?",
                (proposal_sha256, packet["recipient_session_id"]),
            ).fetchone()
            if current["decision_sha256"] is not None and existing_interest is None:
                raise CoordinationError("APPROVAL_RECIPIENT_SET_FROZEN")
            _record_interest(
                store,
                proposal_sha256=proposal_sha256,
                submission_sha256=submission_sha256,
                packet=packet,
                now=now,
            )
            return {
                "proposal_sha256": proposal_sha256,
                "submission_sha256": submission_sha256,
                "state": "DECIDED" if current["decision"] else "PENDING",
                "idempotent": False,
                "clustered": True,
            }
        historical = store.connection.execute(
            "SELECT 1 FROM approval_proposals WHERE proposal_sha256=?",
            (proposal_sha256,),
        ).fetchone()
        if historical is not None:
            raise CoordinationError("APPROVAL_SEMANTIC_REQUEST_SUPPRESSED")
        if current is not None and int(current["open_deliveries"]) > 0:
            raise CoordinationError("APPROVAL_DECISION_IN_FLIGHT")
        supersedes = current["proposal_sha256"] if current is not None else None
        proposal_generation = int(current["proposal_generation"]) + 1 if current else 1
        source = store.current_snapshot(packet["repository"], "issue", packet["owning_issue"])
        if source is None:
            raise CoordinationError("APPROVAL_SOURCE_SNAPSHOT_DRIFT")
        store.connection.execute(
            """
            INSERT INTO approval_proposals(
                proposal_sha256, semantic_sha256, decision_key, repository,
                owning_issue, source_snapshot_sha256, source_updated_at,
                proposal_generation, requester_session_id, recipient_session_id,
                workstream, boundary, priority, urgency, supersedes_sha256,
                packet_json, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                proposal_sha256, semantic_sha256, packet["decision_key"],
                packet["repository"], packet["owning_issue"],
                packet["source_snapshot_sha256"], source.source_updated_at,
                proposal_generation, packet["requester_session_id"],
                packet["recipient_session_id"], packet["workstream"],
                packet["boundary"], packet["priority"], packet["urgency"],
                supersedes, canonical_json(packet), now,
            ),
        )
        store.connection.execute(
            """
            INSERT INTO approval_current(
                repository, owning_issue, decision_key, proposal_sha256, updated_at
            ) VALUES (?,?,?,?,?)
            ON CONFLICT(repository, owning_issue, decision_key) DO UPDATE SET
                proposal_sha256=excluded.proposal_sha256,
                updated_at=excluded.updated_at
            """,
            (
                packet["repository"], packet["owning_issue"],
                packet["decision_key"], proposal_sha256, now,
            ),
        )
        _record_interest(
            store,
            proposal_sha256=proposal_sha256,
            submission_sha256=submission_sha256,
            packet=packet,
            now=now,
        )
        message_id = store.enqueue_message(
            idempotency_key=f"user-decision-review:{proposal_sha256}",
            recipient_session_id=canonicalize_coordination_identity(
                store.connection, _current_role_route(store, "planner")
            ),
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": packet["repository"], "object_kind": "issue",
                    "object_number": packet["owning_issue"],
                    "payload_sha256": packet["source_snapshot_sha256"],
                },
                "notice_kind": "planning_request", "mutation_authority": False,
                "subject": f"material-user-decision:{proposal_sha256}",
                "summary": "A source-current material user decision packet is pending Planner review.",
                "evidence": {
                    "proposal_sha256": proposal_sha256,
                    "decision_key": packet["decision_key"],
                    "boundary": packet["boundary"],
                    "priority": packet["priority"], "urgency": packet["urgency"],
                    "owning_issue": packet["owning_issue"],
                },
                "requested_evidence": ["Planner review-batch disposition."],
                "next_observation": "Planner review-batch status.",
            },
            now=now,
            _transaction=False,
        )
        store.connection.execute(
            "INSERT INTO approval_proposal_notices(proposal_sha256,message_id,created_at) VALUES (?,?,?)",
            (proposal_sha256, message_id, now),
        )
        if supersedes is not None:
            _retire_planner_notice(store, supersedes, now)
        _event(
            store.connection, "PROPOSAL_SUBMITTED", f"approval:{proposal_sha256}",
            {"supersedes_sha256": supersedes, "submission_sha256": submission_sha256}, now,
        )
    return {
        "proposal_sha256": proposal_sha256,
        "submission_sha256": submission_sha256,
        "state": "PENDING",
        "idempotent": False,
        "clustered": False,
    }


def _pending_rows(
    store: CoordinationStore, repository: str, *, now: str
) -> list[dict[str, Any]]:
    rows = store.connection.execute(
        """
        SELECT p.*,
               MIN(CASE i.urgency
                   WHEN 'ACTIVE_BLOCKER' THEN 0 WHEN 'READY_BLOCKER' THEN 1
                   WHEN 'FUTURE' THEN 2 ELSE 3 END) AS urgency_rank,
               MIN(CASE i.priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 ELSE 2 END)
                   AS priority_rank,
               COUNT(DISTINCT s.submission_sha256) AS submission_count,
               GROUP_CONCAT(DISTINCT i.recipient_session_id) AS recipient_sessions,
               GROUP_CONCAT(DISTINCT s.workstream) AS interested_workstreams
        FROM approval_current c
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN approval_interests i USING(proposal_sha256)
        JOIN approval_submissions s USING(proposal_sha256)
        LEFT JOIN approval_decisions d USING(proposal_sha256)
        WHERE p.repository=? AND d.proposal_sha256 IS NULL
        GROUP BY p.proposal_sha256
        """,
        (repository,),
    ).fetchall()
    item_rows = {
        int(row["issue_number"]): row["status"]
        for row in store.connection.execute(
            "SELECT issue_number,status FROM coordination_items WHERE repository=?",
            (repository,),
        )
    }
    graph_rows: dict[int, tuple[int, int]] = {}
    if store.connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='portfolio_graph_current'"
    ).fetchone():
        for graph_row in store.connection.execute(
            """
            SELECT n.issue_number, MIN(n.priority_rank) AS priority_rank,
                   COUNT(DISTINCT r.right_node_key) AS immediate_unlocks
            FROM portfolio_graph_current c
            JOIN portfolio_graph_nodes n
              ON n.repository=c.repository AND n.graph_version=c.version
            LEFT JOIN portfolio_graph_relations r
              ON r.repository=n.repository AND r.graph_version=n.graph_version
             AND r.left_node_key=n.node_key AND r.relation_kind='HARD_BLOCK'
            WHERE c.repository=? AND c.health='CURRENT'
            GROUP BY n.issue_number
            """,
            (repository,),
        ):
            graph_rows[int(graph_row["issue_number"])] = (
                int(graph_row["priority_rank"]), int(graph_row["immediate_unlocks"])
            )
    result = []
    for row in rows:
        packet = json.loads(row["packet_json"])
        affected = packet["affected_issues"]
        active_count = sum(
            item_rows.get(issue) in {"ACTIVE_FENCED", "ACTIVE", "RETAINED"}
            for issue in affected
        )
        ready_count = sum(item_rows.get(issue) == "READY" for issue in affected)
        graph_priority = min(
            (graph_rows[issue][0] for issue in affected if issue in graph_rows),
            default=10**9,
        )
        immediate_unlocks = sum(
            graph_rows[issue][1] for issue in affected if issue in graph_rows
        )
        packet["proposal_sha256"] = row["proposal_sha256"]
        packet["proposal_generation"] = int(row["proposal_generation"])
        packet["created_at"] = row["created_at"]
        packet["submission_count"] = int(row["submission_count"])
        packet["recipient_session_ids"] = sorted(
            value for value in (row["recipient_sessions"] or "").split(",") if value
        )
        packet["interested_workstreams"] = sorted(
            value for value in (row["interested_workstreams"] or "").split(",") if value
        )
        packet["portfolio_rank"] = {
            "active_or_retained": active_count,
            "ready": ready_count,
            "graph_priority": None if graph_priority == 10**9 else graph_priority,
            "immediate_unlocks": immediate_unlocks,
        }
        packet["source_current"] = _source_is_current(store, packet)
        packet["expired"] = _expired(packet, now)
        safety_rank = 0 if packet["boundary"] in {
            "SECURITY_PRIVACY", "HOSTED_PROVIDER", "DESTRUCTIVE", "PERSISTENT_DATA"
        } else 1
        packet["_sort_key"] = (
            safety_rank,
            packet["expires_at"] or "9999-12-31T23:59:59Z",
            -active_count,
            -ready_count,
            graph_priority,
            -immediate_unlocks,
            int(row["urgency_rank"]),
            int(row["priority_rank"]),
            row["created_at"],
            row["proposal_sha256"],
        )
        result.append(packet)
    result.sort(key=lambda item: item["_sort_key"])
    for item in result:
        del item["_sort_key"]
    return result


def create_review_batch(
    store: CoordinationStore, repository: str, now: str
) -> dict[str, Any]:
    if not REPOSITORY.fullmatch(repository):
        raise CoordinationError("INVALID_REPOSITORY")
    ensure_schema(store.connection)
    with store.transaction():
        proposals = _pending_rows(store, repository, now=now)
        digests = [
            entry["proposal_sha256"]
            for entry in proposals
            if entry["source_current"] and not entry["expired"]
        ]
        batch = {"repository": repository, "proposal_sha256": digests}
        batch_sha256 = digest_json(batch)
        cursor = store.connection.execute(
            """
            INSERT OR IGNORE INTO approval_review_batches(
                batch_sha256, repository, proposal_sha256_json,
                proposal_count, created_at
            ) VALUES (?,?,?,?,?)
            """,
            (batch_sha256, repository, canonical_json(digests), len(digests), now),
        )
        if cursor.rowcount == 1:
            _event(
                store.connection,
                "REVIEW_BATCH_CREATED",
                f"approval-batch:{batch_sha256}",
                batch,
                now,
            )
    return {
        "batch_sha256": batch_sha256,
        "pending_count": len(digests),
        "proposals": [
            entry for entry in proposals if entry["source_current"] and not entry["expired"]
        ],
        "held": [
            {
                "proposal_sha256": entry["proposal_sha256"],
                "reason": "SOURCE_DRIFT" if not entry["source_current"] else "EXPIRED",
            }
            for entry in proposals
            if not entry["source_current"] or entry["expired"]
        ],
    }


def _decision_comment(
    packet: dict[str, Any], proposal_sha256: str, decision: str, note: str,
    *, selected_option_id: str, revisit_trigger: str | None,
    recipients: list[str], recipient_set_sha256: str, user_input_sha256: str,
    user_event_source: str, user_event_id: str,
) -> str:
    prohibited = "\n".join(
        f"- {value}" for value in packet["prohibited_side_effects"]
    )
    return (
        "APPROVAL LEDGER DECISION\n\n"
        f"- Decision: `{decision}`\n"
        f"- Selected option: `{selected_option_id}`\n"
        f"- Proposal digest: `{proposal_sha256}`\n"
        f"- Decision key: `{packet['decision_key']}`\n"
        f"- Boundary: `{packet['boundary']}`\n"
        f"- Exact target: {packet['target']}\n"
        f"- Requested action: {packet['requested_action']}\n"
        f"- User decision note: {note}\n"
        f"- User event: `{user_event_source}:{user_event_id}`\n"
        f"- User input digest: `{user_input_sha256}`\n"
        f"- Source snapshot: `{packet['source_snapshot_sha256']}`\n"
        f"- Exact recipients: `{', '.join(recipients)}`\n"
        f"- Recipient-set digest: `{recipient_set_sha256}`\n"
        f"- Execution-scope digest: `{packet['execution_scope_sha256']}`\n"
        + (f"- Revisit trigger: {revisit_trigger}\n" if revisit_trigger else "")
        + "\n"
        "Prohibited side effects:\n"
        f"{prohibited}\n\n"
        "This owning-issue receipt is the external audit record. It conveys no "
        "authority beyond the exact proposal and decision above."
    )


def record_decision(
    store: CoordinationStore,
    *,
    proposal_sha256: str,
    decision: str,
    selected_option_id: str,
    revisit_trigger: str | None,
    decision_note: str,
    user_input_sha256: str,
    user_event_source: str,
    user_event_id: str,
    planner_session_id: str,
    now: str,
) -> dict[str, Any]:
    ensure_schema(store.connection)
    if coordination_identity_role(store.connection, planner_session_id) != "planner":
        raise CoordinationError("PLANNER_SESSION_REQUIRED")
    planner_session_id = canonicalize_coordination_identity(
        store.connection, planner_session_id
    )
    if decision not in DECISIONS:
        raise CoordinationError("APPROVAL_DECISION_INVALID")
    if not SHA256.fullmatch(proposal_sha256) or not SHA256.fullmatch(user_input_sha256):
        raise CoordinationError("APPROVAL_DIGEST_INVALID")
    if (
        user_event_source not in USER_EVENT_SOURCES
        or not isinstance(user_event_id, str)
        or not USER_EVENT_ID.fullmatch(user_event_id)
    ):
        raise CoordinationError("APPROVAL_USER_EVENT_INVALID")
    decision_note = _validate_text(decision_note, "decision_note")
    if decision == "DEFER":
        revisit_trigger = _validate_text(revisit_trigger, "revisit_trigger")
    elif revisit_trigger is not None:
        raise CoordinationError("APPROVAL_REVISIT_TRIGGER_UNEXPECTED")
    with store.transaction():
        row = store.connection.execute(
            """
            SELECT p.*, c.proposal_sha256 AS current_sha
            FROM approval_proposals p
            LEFT JOIN approval_current c
              ON c.repository=p.repository
             AND c.owning_issue=p.owning_issue
             AND c.decision_key=p.decision_key
            WHERE p.proposal_sha256=?
            """,
            (proposal_sha256,),
        ).fetchone()
        if row is None:
            raise CoordinationError("APPROVAL_PROPOSAL_NOT_FOUND")
        if row["current_sha"] != proposal_sha256:
            raise CoordinationError("APPROVAL_PROPOSAL_SUPERSEDED")
        packet = json.loads(row["packet_json"])
        if not _source_is_current(store, packet):
            raise CoordinationError("APPROVAL_SOURCE_SNAPSHOT_DRIFT")
        if _expired(packet, now):
            raise CoordinationError("APPROVAL_PROPOSAL_EXPIRED")
        if selected_option_id not in {option["id"] for option in packet["options"]}:
            raise CoordinationError("APPROVAL_SELECTED_OPTION_INVALID")
        recipients = sorted({
            canonicalize_coordination_identity(
                store.connection,
                _historical_identity_current_route(
                    store, str(interest["recipient_session_id"])
                ),
            )
            for interest in store.connection.execute(
                "SELECT recipient_session_id FROM approval_interests "
                "WHERE proposal_sha256=? ORDER BY recipient_session_id",
                (proposal_sha256,),
            )
        })
        if not recipients:
            raise CoordinationError("APPROVAL_RECIPIENT_MISSING")
        recipient_set_sha256 = digest_json(recipients)
        existing = store.connection.execute(
            "SELECT * FROM approval_decisions WHERE proposal_sha256=?",
            (proposal_sha256,),
        ).fetchone()
        decision_record = {
            "proposal_sha256": proposal_sha256,
            "decision": decision,
            "selected_option_id": selected_option_id,
            "revisit_trigger": revisit_trigger,
            "recipient_set_sha256": recipient_set_sha256,
            "execution_scope_sha256": packet["execution_scope_sha256"],
            "decision_note": decision_note,
            "user_input_sha256": user_input_sha256,
            "user_event_source": user_event_source,
            "user_event_id": user_event_id,
            "planner_session_id": planner_session_id,
        }
        decision_sha256 = digest_json(decision_record)
        if existing is not None:
            if existing["decision_sha256"] != decision_sha256:
                raise CoordinationError("APPROVAL_DECISION_CONFLICT")
            return {
                "proposal_sha256": proposal_sha256,
                "decision_sha256": decision_sha256,
                "owner_outbox_id": int(existing["owner_outbox_id"]),
                "delivery_states": {
                    delivery["recipient_session_id"]: delivery["state"]
                    for delivery in store.connection.execute(
                        "SELECT recipient_session_id,state FROM approval_deliveries "
                        "WHERE proposal_sha256=? ORDER BY recipient_session_id",
                        (proposal_sha256,),
                    )
                },
                "idempotent": True,
            }
        user_event = store.connection.execute(
            "SELECT * FROM approval_user_events WHERE user_event_source=? AND user_event_id=?",
            (user_event_source, user_event_id),
        ).fetchone()
        if user_event is not None and (
            user_event["user_input_sha256"] != user_input_sha256
            or user_event["planner_session_id"] != planner_session_id
        ):
            raise CoordinationError("APPROVAL_USER_EVENT_CONFLICT")
        if user_event is None:
            store.connection.execute(
                "INSERT INTO approval_user_events(user_event_source,user_event_id,"
                "user_input_sha256,planner_session_id,created_at) VALUES (?,?,?,?,?)",
                (user_event_source, user_event_id, user_input_sha256, planner_session_id, now),
            )
        body = _decision_comment(
            packet,
            proposal_sha256,
            decision,
            decision_note,
            selected_option_id=selected_option_id,
            revisit_trigger=revisit_trigger,
            recipients=recipients,
            recipient_set_sha256=recipient_set_sha256,
            user_input_sha256=user_input_sha256,
            user_event_source=user_event_source,
            user_event_id=user_event_id,
        )
        outbox_id = store.enqueue_comment(
            idempotency_key=f"approval-decision:{decision_sha256}",
            repository=packet["repository"],
            object_kind="issue",
            object_number=packet["owning_issue"],
            expected_source_sha256=packet["source_snapshot_sha256"],
            body=body,
            now=now,
            _transaction=False,
        )
        store.connection.execute(
            """
            INSERT INTO approval_decisions(
                proposal_sha256, decision_sha256, decision, selected_option_id,
                revisit_trigger, recipient_set_sha256, execution_scope_sha256,
                decision_note,
                user_input_sha256, user_event_source, user_event_id,
                planner_session_id, owner_outbox_id, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                proposal_sha256,
                decision_sha256,
                decision,
                selected_option_id,
                revisit_trigger,
                recipient_set_sha256,
                packet["execution_scope_sha256"],
                decision_note,
                user_input_sha256,
                user_event_source,
                user_event_id,
                planner_session_id,
                outbox_id,
                now,
            ),
        )
        delivery_state = "HOLD" if decision == "DEFER" else "WAITING_PUBLICATION"
        delivery_error = "APPROVAL_DEFERRED" if decision == "DEFER" else None
        store.connection.executemany(
            "INSERT INTO approval_deliveries(proposal_sha256,decision_sha256,"
            "recipient_session_id,state,updated_at,last_error) VALUES (?,?,?,?,?,?)",
            [
                (proposal_sha256, decision_sha256, recipient, delivery_state, now, delivery_error)
                for recipient in recipients
            ],
        )
        _retire_planner_notice(store, proposal_sha256, now)
        _event(
            store.connection,
            "DECISION_RECORDED",
            f"approval:{proposal_sha256}",
            {"decision_sha256": decision_sha256, "owner_outbox_id": outbox_id},
            now,
        )
    return {
        "proposal_sha256": proposal_sha256,
        "decision_sha256": decision_sha256,
        "owner_outbox_id": outbox_id,
        "delivery_states": {recipient: delivery_state for recipient in recipients},
        "idempotent": False,
    }


def revoke_decision(
    store: CoordinationStore,
    *,
    proposal_sha256: str,
    decision_sha256: str,
    reason: str,
    user_input_sha256: str,
    user_event_source: str,
    user_event_id: str,
    planner_session_id: str,
    now: str,
) -> dict[str, Any]:
    ensure_schema(store.connection)
    if coordination_identity_role(store.connection, planner_session_id) != "planner":
        raise CoordinationError("PLANNER_SESSION_REQUIRED")
    planner_session_id = canonicalize_coordination_identity(
        store.connection, planner_session_id
    )
    if (
        not SHA256.fullmatch(proposal_sha256)
        or not SHA256.fullmatch(decision_sha256)
        or not SHA256.fullmatch(user_input_sha256)
    ):
        raise CoordinationError("APPROVAL_DIGEST_INVALID")
    if (
        user_event_source not in USER_EVENT_SOURCES
        or not USER_EVENT_ID.fullmatch(user_event_id)
    ):
        raise CoordinationError("APPROVAL_USER_EVENT_INVALID")
    reason = _validate_text(reason, "revocation_reason")
    with store.transaction():
        row = store.connection.execute(
            """
            SELECT p.*, d.decision_sha256, c.proposal_sha256 AS current_sha
            FROM approval_proposals p
            JOIN approval_decisions d USING(proposal_sha256)
            JOIN approval_current c ON c.repository=p.repository
             AND c.owning_issue=p.owning_issue AND c.decision_key=p.decision_key
            WHERE p.proposal_sha256=? AND d.decision_sha256=?
            """,
            (proposal_sha256, decision_sha256),
        ).fetchone()
        if row is None:
            raise CoordinationError("APPROVAL_DECISION_NOT_FOUND")
        if row["current_sha"] != proposal_sha256:
            raise CoordinationError("APPROVAL_PROPOSAL_SUPERSEDED")
        existing = store.connection.execute(
            "SELECT * FROM approval_revocations WHERE decision_sha256=?",
            (decision_sha256,),
        ).fetchone()
        if existing is not None:
            if (
                existing["reason"] != reason
                or existing["user_input_sha256"] != user_input_sha256
            ):
                raise CoordinationError("APPROVAL_REVOCATION_CONFLICT")
            return {
                "proposal_sha256": proposal_sha256,
                "decision_sha256": decision_sha256,
                "owner_outbox_id": int(existing["owner_outbox_id"]),
                "state": "REVOKED",
                "idempotent": True,
            }
        user_event = store.connection.execute(
            "SELECT * FROM approval_user_events WHERE user_event_source=? AND user_event_id=?",
            (user_event_source, user_event_id),
        ).fetchone()
        if user_event is not None and (
            user_event["user_input_sha256"] != user_input_sha256
            or user_event["planner_session_id"] != planner_session_id
        ):
            raise CoordinationError("APPROVAL_USER_EVENT_CONFLICT")
        if user_event is None:
            store.connection.execute(
                "INSERT INTO approval_user_events(user_event_source,user_event_id,"
                "user_input_sha256,planner_session_id,created_at) VALUES (?,?,?,?,?)",
                (user_event_source, user_event_id, user_input_sha256, planner_session_id, now),
            )
        packet = json.loads(row["packet_json"])
        source = store.current_snapshot(packet["repository"], "issue", packet["owning_issue"])
        if source is None:
            raise CoordinationError("APPROVAL_SOURCE_SNAPSHOT_MISSING")
        body = (
            "APPROVAL LEDGER REVOCATION\n\n"
            f"- Proposal digest: `{proposal_sha256}`\n"
            f"- Decision digest: `{decision_sha256}`\n"
            f"- Reason: {reason}\n"
            f"- User event: `{user_event_source}:{user_event_id}`\n"
            f"- User input digest: `{user_input_sha256}`\n\n"
            "The prior decision is no longer valid for future execution."
        )
        outbox_id = store.enqueue_comment(
            idempotency_key=f"approval-revocation:{decision_sha256}",
            repository=packet["repository"],
            object_kind="issue",
            object_number=packet["owning_issue"],
            expected_source_sha256=source.payload_sha256,
            body=body,
            now=now,
            _transaction=False,
        )
        store.connection.execute(
            "INSERT INTO approval_revocations(decision_sha256,proposal_sha256,reason,"
            "user_event_source,user_event_id,user_input_sha256,planner_session_id,"
            "owner_outbox_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                decision_sha256, proposal_sha256, reason, user_event_source,
                user_event_id, user_input_sha256, planner_session_id, outbox_id, now,
            ),
        )
        store.connection.execute(
            "UPDATE approval_deliveries SET state='HOLD',updated_at=?,"
            "last_error='APPROVAL_USER_DECISION_SUPERSEDED' WHERE proposal_sha256=? "
            "AND state IN ('WAITING_PUBLICATION','CLAIMED')",
            (now, proposal_sha256),
        )
        _event(
            store.connection,
            "DECISION_REVOKED",
            f"approval:{proposal_sha256}",
            {"decision_sha256": decision_sha256, "owner_outbox_id": outbox_id},
            now,
        )
    return {
        "proposal_sha256": proposal_sha256,
        "decision_sha256": decision_sha256,
        "owner_outbox_id": outbox_id,
        "state": "REVOKED",
        "idempotent": False,
    }


def delivery_recipient_for_role(
    store: CoordinationStore, proposal_sha256: str, requested_identity: str
) -> str:
    """Resolve one immutable delivery row through the current role endpoint."""

    if coordination_identity_role(store.connection, requested_identity) is None:
        raise CoordinationError("INVALID_SESSION")
    requested_identity = canonicalize_coordination_identity(
        store.connection, requested_identity
    )
    rows = store.connection.execute(
        "SELECT recipient_session_id FROM approval_deliveries "
        "WHERE proposal_sha256=? ORDER BY recipient_session_id",
        (proposal_sha256,),
    ).fetchall()
    exact = [str(row["recipient_session_id"]) for row in rows if row["recipient_session_id"] == requested_identity]
    if exact:
        return exact[0]
    equivalent = [
        str(row["recipient_session_id"])
        for row in rows
        if identities_role_equivalent(
            store.connection, str(row["recipient_session_id"]), requested_identity
        )
    ]
    if len(equivalent) == 1:
        return equivalent[0]
    if rows:
        raise CoordinationError("APPROVAL_RECIPIENT_MISMATCH")
    raise CoordinationError("APPROVAL_DELIVERY_NOT_FOUND")


def claim_decision_in_transaction(
    store: CoordinationStore,
    *,
    proposal_sha256: str,
    recipient_session_id: str,
    refreshed_payload: dict[str, Any],
    refreshed_payload_sha256: str,
    now: str,
    allow_acknowledged_replay: bool = False,
) -> dict[str, Any]:
    """Claim a delivery and bind effectivity inside an existing transaction."""

    if not store.connection.in_transaction:
        raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
    if not SHA256.fullmatch(proposal_sha256):
        raise CoordinationError("APPROVAL_DIGEST_INVALID")
    recipient_session_id = delivery_recipient_for_role(
        store, proposal_sha256, recipient_session_id
    )
    if not isinstance(refreshed_payload, dict):
        raise CoordinationError("APPROVAL_SOURCE_REFRESH_INVALID")
    if digest_json(refreshed_payload) != refreshed_payload_sha256:
        raise CoordinationError("APPROVAL_SOURCE_REFRESH_DIGEST_DRIFT")
    row = store.connection.execute(
        """
        SELECT x.*, d.decision, d.selected_option_id, d.revisit_trigger,
               d.execution_scope_sha256, d.decision_note, d.owner_outbox_id,
               o.state AS outbox_state, o.remote_receipt,
               p.packet_json, p.source_snapshot_sha256,
               c.proposal_sha256 AS current_sha,
               r.decision_sha256 AS revoked_decision_sha256
        FROM approval_deliveries x
        JOIN approval_decisions d USING(proposal_sha256, decision_sha256)
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN approval_current c
          ON c.repository=p.repository
         AND c.owning_issue=p.owning_issue
         AND c.decision_key=p.decision_key
        JOIN github_outbox o ON o.id=d.owner_outbox_id
        LEFT JOIN approval_revocations r USING(proposal_sha256,decision_sha256)
        WHERE x.proposal_sha256=? AND x.recipient_session_id=?
        """,
        (proposal_sha256, recipient_session_id),
    ).fetchone()
    if row is None:
        if store.connection.execute(
            "SELECT 1 FROM approval_deliveries WHERE proposal_sha256=?",
            (proposal_sha256,),
        ).fetchone():
            raise CoordinationError("APPROVAL_RECIPIENT_MISMATCH")
        raise CoordinationError("APPROVAL_DELIVERY_NOT_FOUND")
    if row["current_sha"] != proposal_sha256:
        raise CoordinationError("APPROVAL_PROPOSAL_SUPERSEDED")
    if row["revoked_decision_sha256"] is not None:
        raise CoordinationError("APPROVAL_DECISION_REVOKED")
    if row["outbox_state"] != "COMPLETE" or not row["remote_receipt"]:
        raise CoordinationError("APPROVAL_PUBLICATION_INCOMPLETE")
    if row["state"] == "HOLD":
        raise CoordinationError("APPROVAL_DELIVERY_HELD")
    if row["state"] == "ACKNOWLEDGED" and not allow_acknowledged_replay:
        raise CoordinationError("APPROVAL_ALREADY_ACKNOWLEDGED")

    packet = json.loads(row["packet_json"])
    refreshed = store.ingest_snapshot_in_transaction(
        repository=packet["repository"],
        object_kind="issue",
        object_number=packet["owning_issue"],
        payload=refreshed_payload,
        source_updated_at=refreshed_payload.get(
            "_projection_updated_at", refreshed_payload.get("updated_at", "")
        ),
        fetched_at=now,
        expected_payload_sha256=refreshed_payload_sha256,
    )
    original_row = store.connection.execute(
        """
        SELECT payload_json FROM github_snapshots
        WHERE repository=? AND object_kind='issue' AND object_number=?
          AND payload_sha256=?
        """,
        (
            packet["repository"],
            packet["owning_issue"],
            row["source_snapshot_sha256"],
        ),
    ).fetchone()
    if original_row is None:
        raise CoordinationError("APPROVAL_SOURCE_SNAPSHOT_MISSING")
    original_payload = json.loads(original_row["payload_json"])
    if _stable_source_payload(original_payload) != _stable_source_payload(
        refreshed.payload
    ):
        raise CoordinationError("APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION")

    effective_source_sha256 = digest_json(_stable_source_payload(refreshed.payload))
    effectivity = store.connection.execute(
        "SELECT * FROM approval_effectivity WHERE proposal_sha256=?",
        (proposal_sha256,),
    ).fetchone()
    if effectivity is None:
        if row["state"] != "WAITING_PUBLICATION":
            raise CoordinationError("APPROVAL_EFFECTIVITY_CONFLICT")
        store.connection.execute(
            """
            INSERT INTO approval_effectivity(
                proposal_sha256, decision_sha256, effective_source_sha256,
                remote_receipt, created_at
            ) VALUES (?,?,?,?,?)
            """,
            (
                proposal_sha256,
                row["decision_sha256"],
                effective_source_sha256,
                row["remote_receipt"],
                now,
            ),
        )
    elif (
        effectivity["decision_sha256"] != row["decision_sha256"]
        or effectivity["effective_source_sha256"] != effective_source_sha256
        or effectivity["remote_receipt"] != row["remote_receipt"]
    ):
        raise CoordinationError("APPROVAL_EFFECTIVITY_CONFLICT")

    if row["state"] == "WAITING_PUBLICATION":
        changed = store.connection.execute(
            "UPDATE approval_deliveries SET state='CLAIMED', claimed_at=?, "
            "updated_at=? WHERE proposal_sha256=? AND recipient_session_id=? "
            "AND state='WAITING_PUBLICATION'",
            (now, now, proposal_sha256, recipient_session_id),
        ).rowcount
        if changed != 1:
            raise CoordinationError("APPROVAL_DELIVERY_STATE_CONFLICT")
        _event(
            store.connection,
            "DECISION_CLAIMED",
            f"approval:{proposal_sha256}",
            {"recipient_session_id": recipient_session_id},
            now,
        )
    elif row["state"] not in {"CLAIMED", "ACKNOWLEDGED"}:
        raise CoordinationError("APPROVAL_DELIVERY_STATE_CONFLICT")

    return {
        "proposal_sha256": proposal_sha256,
        "decision_sha256": row["decision_sha256"],
        "decision": row["decision"],
        "selected_option_id": row["selected_option_id"],
        "revisit_trigger": row["revisit_trigger"],
        "execution_scope_sha256": row["execution_scope_sha256"],
        "decision_note": row["decision_note"],
        "requested_action": packet["requested_action"],
        "target": packet["target"],
        "prohibited_side_effects": packet["prohibited_side_effects"],
        "owning_issue": packet["owning_issue"],
        "remote_receipt": row["remote_receipt"],
        "state": "CLAIMED" if row["state"] == "WAITING_PUBLICATION" else row["state"],
    }


def claim_decision(
    store: CoordinationStore,
    *,
    proposal_sha256: str,
    recipient_session_id: str,
    now: str,
    source_refresher: Callable[[str, str, int], dict[str, Any]] = fetch_object,
) -> dict[str, Any]:
    ensure_schema(store.connection)
    recipient_session_id = delivery_recipient_for_role(
        store, proposal_sha256, recipient_session_id
    )
    preflight = store.connection.execute(
        """
        SELECT x.recipient_session_id, x.state, d.owner_outbox_id,
               o.state AS outbox_state, o.remote_receipt, p.packet_json
        FROM approval_deliveries x
        JOIN approval_decisions d USING(proposal_sha256, decision_sha256)
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN github_outbox o ON o.id=d.owner_outbox_id
        WHERE x.proposal_sha256=? AND x.recipient_session_id=?
        """,
        (proposal_sha256, recipient_session_id),
    ).fetchone()
    if preflight is None:
        if store.connection.execute(
            "SELECT 1 FROM approval_deliveries WHERE proposal_sha256=?",
            (proposal_sha256,),
        ).fetchone():
            raise CoordinationError("APPROVAL_RECIPIENT_MISMATCH")
        raise CoordinationError("APPROVAL_DELIVERY_NOT_FOUND")
    if preflight["state"] == "HOLD":
        raise CoordinationError("APPROVAL_DELIVERY_HELD")
    if preflight["outbox_state"] != "COMPLETE" or not preflight["remote_receipt"]:
        raise CoordinationError("APPROVAL_PUBLICATION_INCOMPLETE")
    packet = json.loads(preflight["packet_json"])
    refreshed_payload = source_refresher(
        packet["repository"], "issue", packet["owning_issue"]
    )
    if not isinstance(refreshed_payload, dict):
        raise CoordinationError("APPROVAL_SOURCE_REFRESH_INVALID")
    refreshed = store.ingest_snapshot(
        repository=packet["repository"],
        object_kind="issue",
        object_number=packet["owning_issue"],
        payload=refreshed_payload,
        source_updated_at=refreshed_payload.get(
            "_projection_updated_at", refreshed_payload.get("updated_at", "")
        ),
        fetched_at=now,
    )
    held_error: str | None = None
    with store.transaction():
        row = store.connection.execute(
            """
            SELECT x.*, d.decision, d.selected_option_id, d.revisit_trigger,
                   d.execution_scope_sha256,
                   d.decision_note, d.owner_outbox_id,
                   o.state AS outbox_state, o.remote_receipt,
                   p.packet_json, p.source_snapshot_sha256,
                   c.proposal_sha256 AS current_sha,
                   r.decision_sha256 AS revoked_decision_sha256
            FROM approval_deliveries x
            JOIN approval_decisions d USING(proposal_sha256, decision_sha256)
            JOIN approval_proposals p USING(proposal_sha256)
            JOIN approval_current c
              ON c.repository=p.repository
             AND c.owning_issue=p.owning_issue
             AND c.decision_key=p.decision_key
            JOIN github_outbox o ON o.id=d.owner_outbox_id
            LEFT JOIN approval_revocations r USING(proposal_sha256,decision_sha256)
            WHERE x.proposal_sha256=? AND x.recipient_session_id=?
            """,
            (proposal_sha256, recipient_session_id),
        ).fetchone()
        if row is None:
            raise CoordinationError("APPROVAL_DELIVERY_NOT_FOUND")
        if row["current_sha"] != proposal_sha256:
            raise CoordinationError("APPROVAL_PROPOSAL_SUPERSEDED")
        if row["revoked_decision_sha256"] is not None:
            raise CoordinationError("APPROVAL_DECISION_REVOKED")
        if row["outbox_state"] != "COMPLETE" or not row["remote_receipt"]:
            raise CoordinationError("APPROVAL_PUBLICATION_INCOMPLETE")
        if row["state"] == "ACKNOWLEDGED":
            raise CoordinationError("APPROVAL_ALREADY_ACKNOWLEDGED")
        if row["state"] == "HOLD":
            raise CoordinationError("APPROVAL_DELIVERY_HELD")
        original_row = store.connection.execute(
            """
            SELECT payload_json FROM github_snapshots
            WHERE repository=? AND object_kind='issue' AND object_number=?
              AND payload_sha256=?
            """,
            (
                packet["repository"],
                packet["owning_issue"],
                row["source_snapshot_sha256"],
            ),
        ).fetchone()
        if original_row is None:
            raise CoordinationError("APPROVAL_SOURCE_SNAPSHOT_MISSING")
        original_payload = json.loads(original_row["payload_json"])
        if _stable_source_payload(original_payload) != _stable_source_payload(
            refreshed.payload
        ):
            held_error = "APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION"
            store.connection.execute(
                "UPDATE approval_deliveries SET state='HOLD', updated_at=?, "
                "last_error=? WHERE proposal_sha256=? AND state IN "
                "('WAITING_PUBLICATION','CLAIMED')",
                (now, held_error, proposal_sha256),
            )
            _event(
                store.connection,
                "DECISION_HELD",
                f"approval:{proposal_sha256}",
                {"error": held_error},
                now,
            )
        elif row["state"] == "WAITING_PUBLICATION":
            effective_source_sha256 = digest_json(
                _stable_source_payload(refreshed.payload)
            )
            effectivity = store.connection.execute(
                "SELECT * FROM approval_effectivity WHERE proposal_sha256=?",
                (proposal_sha256,),
            ).fetchone()
            if effectivity is None:
                store.connection.execute(
                    """
                    INSERT INTO approval_effectivity(
                        proposal_sha256, decision_sha256, effective_source_sha256,
                        remote_receipt, created_at
                    ) VALUES (?,?,?,?,?)
                    """,
                    (
                        proposal_sha256,
                        row["decision_sha256"],
                        effective_source_sha256,
                        row["remote_receipt"],
                        now,
                    ),
                )
            elif (
                effectivity["decision_sha256"] != row["decision_sha256"]
                or effectivity["effective_source_sha256"] != effective_source_sha256
                or effectivity["remote_receipt"] != row["remote_receipt"]
            ):
                raise CoordinationError("APPROVAL_EFFECTIVITY_CONFLICT")
            store.connection.execute(
                "UPDATE approval_deliveries SET state='CLAIMED', claimed_at=?, "
                "updated_at=? WHERE proposal_sha256=? AND recipient_session_id=? "
                "AND state='WAITING_PUBLICATION'",
                (now, now, proposal_sha256, recipient_session_id),
            )
            _event(
                store.connection,
                "DECISION_CLAIMED",
                f"approval:{proposal_sha256}",
                {"recipient_session_id": recipient_session_id},
                now,
            )
        packet = json.loads(row["packet_json"])
    if held_error is not None:
        raise CoordinationError(held_error)
    return {
        "proposal_sha256": proposal_sha256,
        "decision_sha256": row["decision_sha256"],
        "decision": row["decision"],
        "selected_option_id": row["selected_option_id"],
        "revisit_trigger": row["revisit_trigger"],
        "execution_scope_sha256": row["execution_scope_sha256"],
        "decision_note": row["decision_note"],
        "requested_action": packet["requested_action"],
        "target": packet["target"],
        "prohibited_side_effects": packet["prohibited_side_effects"],
        "owning_issue": packet["owning_issue"],
        "remote_receipt": row["remote_receipt"],
        "state": "CLAIMED",
    }


def acknowledge_decision_in_transaction(
    store: CoordinationStore,
    *,
    proposal_sha256: str,
    decision_sha256: str,
    recipient_session_id: str,
    now: str,
) -> dict[str, Any]:
    if not store.connection.in_transaction:
        raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
    if not SHA256.fullmatch(proposal_sha256) or not SHA256.fullmatch(decision_sha256):
        raise CoordinationError("APPROVAL_DIGEST_INVALID")
    recipient_session_id = delivery_recipient_for_role(
        store, proposal_sha256, recipient_session_id
    )
    row = store.connection.execute(
        "SELECT * FROM approval_deliveries WHERE proposal_sha256=? "
        "AND recipient_session_id=?",
        (proposal_sha256, recipient_session_id),
    ).fetchone()
    if row is None:
        raise CoordinationError("APPROVAL_DELIVERY_NOT_FOUND")
    if (
        row["decision_sha256"] != decision_sha256
        or row["recipient_session_id"] != recipient_session_id
    ):
        raise CoordinationError("APPROVAL_DELIVERY_BINDING_MISMATCH")
    if row["state"] == "ACKNOWLEDGED":
        return {"proposal_sha256": proposal_sha256, "state": "ACKNOWLEDGED"}
    if row["state"] != "CLAIMED":
        raise CoordinationError("APPROVAL_DELIVERY_STATE_CONFLICT")
    store.connection.execute(
        "UPDATE approval_deliveries SET state='ACKNOWLEDGED', "
        "acknowledged_at=?, updated_at=? WHERE proposal_sha256=? "
        "AND recipient_session_id=? AND state='CLAIMED'",
        (now, now, proposal_sha256, recipient_session_id),
    )
    _event(
        store.connection,
        "DECISION_ACKNOWLEDGED",
        f"approval:{proposal_sha256}",
        {"decision_sha256": decision_sha256},
        now,
    )
    return {"proposal_sha256": proposal_sha256, "state": "ACKNOWLEDGED"}


def acknowledge_decision(
    store: CoordinationStore,
    *,
    proposal_sha256: str,
    decision_sha256: str,
    recipient_session_id: str,
    now: str,
) -> dict[str, Any]:
    ensure_schema(store.connection)
    with store.transaction():
        return acknowledge_decision_in_transaction(
            store,
            proposal_sha256=proposal_sha256,
            decision_sha256=decision_sha256,
            recipient_session_id=recipient_session_id,
            now=now,
        )


def summary(store: CoordinationStore, repository: str, *, now: str | None = None) -> dict[str, Any]:
    ensure_schema(store.connection)
    observed_at = now or utc_now()
    pending = _pending_rows(store, repository, now=observed_at)
    counts = {
        row["state"]: int(row["count"])
        for row in store.connection.execute(
            """
            SELECT x.state, COUNT(*) AS count
            FROM approval_deliveries x
            JOIN approval_proposals p USING(proposal_sha256)
            WHERE p.repository=? GROUP BY x.state
            """,
            (repository,),
        )
    }
    deliverable = store.connection.execute(
        """
        SELECT COUNT(*) FROM approval_deliveries x
        JOIN approval_decisions d USING(proposal_sha256, decision_sha256)
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN github_outbox o ON o.id=d.owner_outbox_id
        WHERE p.repository=? AND x.state='WAITING_PUBLICATION'
          AND o.state='COMPLETE' AND o.remote_receipt IS NOT NULL
        """,
        (repository,),
    ).fetchone()[0]
    notices = store.connection.execute(
        """
        SELECT COUNT(*) FROM approval_proposal_notices n
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN coordination_messages m ON m.id=n.message_id
        WHERE p.repository=? AND m.state IN ('PREPARED','CLAIMED')
        """,
        (repository,),
    ).fetchone()[0]
    return {
        "repository": repository,
        "pending_current": sum(
            1 for item in pending
            if _source_is_current(store, item) and not item["expired"]
        ),
        "pending_stale": sum(1 for item in pending if not _source_is_current(store, item)),
        "pending_expired": sum(1 for item in pending if item["expired"]),
        "deliverable": int(deliverable),
        "deliveries": counts,
        "pending_planner_notices": int(notices),
    }


def load_packet(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size > 256 * 1024
        ):
            raise CoordinationError("APPROVAL_PACKET_FILE_UNSAFE")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            chunks.append(block)
        packet = json.loads(
            b"".join(chunks).decode("utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoordinationError("APPROVAL_PACKET_INVALID") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return validate_packet(packet)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    submit = subparsers.add_parser("submit")
    submit.add_argument("--packet", type=Path, required=True)

    batch = subparsers.add_parser("review-batch")
    batch.add_argument("--repository", required=True)

    decide = subparsers.add_parser("decide")
    decide.add_argument("--proposal-sha256", required=True)
    decide.add_argument("--decision", choices=sorted(DECISIONS), required=True)
    decide.add_argument("--selected-option-id", required=True)
    decide.add_argument("--revisit-trigger")
    decide.add_argument("--decision-note", required=True)
    decide.add_argument("--user-input-sha256", required=True)
    decide.add_argument("--user-event-source", choices=sorted(USER_EVENT_SOURCES), required=True)
    decide.add_argument("--user-event-id", required=True)
    decide.add_argument("--planner-session-id", required=True)

    revoke = subparsers.add_parser("revoke")
    revoke.add_argument("--proposal-sha256", required=True)
    revoke.add_argument("--decision-sha256", required=True)
    revoke.add_argument("--reason", required=True)
    revoke.add_argument("--user-input-sha256", required=True)
    revoke.add_argument("--user-event-source", choices=sorted(USER_EVENT_SOURCES), required=True)
    revoke.add_argument("--user-event-id", required=True)
    revoke.add_argument("--planner-session-id", required=True)

    claim = subparsers.add_parser("claim")
    claim.add_argument("--proposal-sha256", required=True)
    claim.add_argument("--recipient-session-id", required=True)

    acknowledge = subparsers.add_parser("ack")
    acknowledge.add_argument("--proposal-sha256", required=True)
    acknowledge.add_argument("--decision-sha256", required=True)
    acknowledge.add_argument("--recipient-session-id", required=True)

    report = subparsers.add_parser("summary")
    report.add_argument("--repository", required=True)

    args = parser.parse_args()
    store: CoordinationStore | None = None
    try:
        store = CoordinationStore(DEFAULT_DATABASE)
        if args.command == "submit":
            result = submit_proposal(store, load_packet(args.packet), utc_now())
        elif args.command == "review-batch":
            result = create_review_batch(store, args.repository, utc_now())
        elif args.command == "decide":
            result = record_decision(
                store,
                proposal_sha256=args.proposal_sha256,
                decision=args.decision,
                selected_option_id=args.selected_option_id,
                revisit_trigger=args.revisit_trigger,
                decision_note=args.decision_note,
                user_input_sha256=args.user_input_sha256,
                user_event_source=args.user_event_source,
                user_event_id=args.user_event_id,
                planner_session_id=args.planner_session_id,
                now=utc_now(),
            )
        elif args.command == "revoke":
            result = revoke_decision(
                store,
                proposal_sha256=args.proposal_sha256,
                decision_sha256=args.decision_sha256,
                reason=args.reason,
                user_input_sha256=args.user_input_sha256,
                user_event_source=args.user_event_source,
                user_event_id=args.user_event_id,
                planner_session_id=args.planner_session_id,
                now=utc_now(),
            )
        elif args.command == "claim":
            result = claim_decision(
                store,
                proposal_sha256=args.proposal_sha256,
                recipient_session_id=args.recipient_session_id,
                now=utc_now(),
            )
        elif args.command == "ack":
            result = acknowledge_decision(
                store,
                proposal_sha256=args.proposal_sha256,
                decision_sha256=args.decision_sha256,
                recipient_session_id=args.recipient_session_id,
                now=utc_now(),
            )
        else:
            result = summary(store, args.repository)
        print(canonical_json(result))
        return 0
    except CoordinationError as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
