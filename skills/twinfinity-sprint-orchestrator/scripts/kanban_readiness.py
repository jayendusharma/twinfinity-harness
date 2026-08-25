#!/usr/bin/env python3
"""One candidate-level PREPARED-to-READY Kanban phase."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Any, Callable

from approval_guard import (
    ApprovalGuardError,
    readiness_execution_scope_sha256,
    require_effective_approval,
)
from approval_ledger import (
    acknowledge_decision_in_transaction,
    claim_decision_in_transaction,
    delivery_recipient_for_role,
    ensure_schema as ensure_approval_schema,
    submit_readiness_proposal_in_transaction,
    validate_packet as validate_approval_packet,
)
from coordination_store import (
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
    timestamp_after,
)
from executor_registry import current_endpoint, identities_role_equivalent, identity_role
from portfolio_graph import PortfolioGraphError, evaluate_graph, replace_graph


PLAN_SCHEMA = "twinfinity-kanban-readiness-phase/v1"
SUCCESSOR_PLAN_SCHEMA = "twinfinity-kanban-readiness-phase/v2"
TRANSITION_EVIDENCE_SCHEMA = "twinfinity-kanban-readiness-transition-evidence/v1"
RECEIPT_SCHEMA = "twinfinity-kanban-readiness-receipt/v1"
RECEIPT_JSON_SCHEMA_ID = (
    "https://twinfinity.ai/schemas/twinfinity-kanban-readiness-receipt/v1"
)
RECEIPT_LOCATOR_SCHEMA = "twinfinity-kanban-readiness-receipt-locator/v1"
READINESS_APPROVAL_INPUT_SCHEMA = "twinfinity-kanban-readiness-approval-input/v1"
READINESS_RESOLUTION_CONTEXT_SCHEMA = (
    "twinfinity-kanban-readiness-resolution-context/v1"
)
READINESS_RESOLUTION_RESULT_SCHEMA = (
    "twinfinity-kanban-readiness-resolution-result/v1"
)
READINESS_RESOLUTION_FAILURE_SCHEMA = (
    "twinfinity-kanban-readiness-resolution-failure/v1"
)
READINESS_RESOLUTION_ACTION_RECEIPT_SCHEMA = (
    "twinfinity-kanban-readiness-resolution-action-receipt/v1"
)
READINESS_DECISION_MAPPING = {
    "APPROVE": "APPROVAL_RESUME",
    "REJECT": "HOLD",
    "DEFER": "HOLD",
    "COURSE_CORRECT": "HOLD",
}
MAX_PARALLEL_CANDIDATES = 2
MAX_RESOLUTION_CYCLES = 2
MAX_RECEIPT_PICKUP_ATTEMPTS = 3
RECEIPT_PICKUP_RETRY_SECONDS = 60
MAX_RECEIPT_PICKUPS_PER_SCAN = 8
WORKER_ROLES = {"development", "sre"}
RESOLUTION_ACTION_KEYS = {
    "kind",
    "target",
    "expected_digest",
    "desired_digest",
    "authority_class",
    "evidence_required",
}
PLANNER_ACTION_AUTHORITY = "PLANNER_OWNER_API"
MATERIAL_ACTION_AUTHORITY = "HUMAN_APPROVAL"
RESOLUTION_ACTION_REGISTRY = {
    "REFRESH_SOURCE_SNAPSHOT": {
        "owner_api": "CoordinationStore.ingest_snapshot/set_issue_status",
        "target_kind": "ISSUE",
        "evidence_required": [
            "github_current.payload_sha256",
            "coordination_items.source_payload_sha256",
        ],
        "order": 10,
    },
    "RECOMPUTE_DEPENDENCY_GRAPH": {
        "owner_api": "portfolio_graph.replace_graph",
        "target_kind": "REPOSITORY",
        "evidence_required": [
            "portfolio_graph_revisions.graph_sha256",
            "portfolio_graph_current.health",
        ],
        "order": 20,
    },
    "REBUILD_PREPARED_CANDIDATE": {
        "owner_api": "kanban_pull_buffer.register_candidate",
        "target_kind": "ISSUE",
        "evidence_required": [
            "portfolio_pull_buffer_current.candidate_id",
            "portfolio_pull_buffer_candidates.candidate_sha256",
        ],
        "order": 30,
    },
}
MATERIAL_ACTION_REGISTRY = {
    "REQUEST_MATERIAL_APPROVAL": {
        "evidence_required": ["approval_ledger.published_decision"],
    }
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
GATE_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ReadinessError(ValueError):
    """Typed fail-closed Kanban readiness error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadinessError("READINESS_DUPLICATE_KEY")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadinessError("READINESS_ARTIFACT_INVALID") from exc
    if not isinstance(value, dict):
        raise ReadinessError("READINESS_ARTIFACT_INVALID")
    return value


def _receipt_relative_path(plan_sha256: str) -> str:
    if not isinstance(plan_sha256, str) or SHA256.fullmatch(plan_sha256) is None:
        raise ReadinessError("READINESS_RECEIPT_LOCATOR_INVALID")
    return f"readiness-receipts/{plan_sha256}.json"


def _receipt_locator(campaign: Any) -> dict[str, Any]:
    return {
        "schema": RECEIPT_LOCATOR_SCHEMA,
        "campaign_id": int(campaign["id"]),
        "repository": str(campaign["repository"]),
        "issue_number": int(campaign["issue_number"]),
        "readiness_plan_sha256": str(campaign["plan_sha256"]),
        "candidate_sha256": str(campaign["candidate_sha256"]),
        "source_payload_sha256": str(campaign["source_payload_sha256"]),
        "relative_path": _receipt_relative_path(str(campaign["plan_sha256"])),
    }


def _receipt_locator_evidence(campaign: Any) -> dict[str, Any]:
    locator = _receipt_locator(campaign)
    return {**locator, "locator_sha256": digest_json(locator)}


def _safe_file_metadata(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _read_safe_draft(path: Path) -> dict[str, Any]:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError as exc:
        raise ReadinessError("READINESS_RECEIPT_DRAFT_UNSAFE") from exc
    try:
        before = os.fstat(descriptor)
        if not _safe_file_metadata(before):
            raise ReadinessError("READINESS_RECEIPT_DRAFT_UNSAFE")
        raw = _read_descriptor(descriptor)
        after = os.fstat(descriptor)
        try:
            path_metadata = path.lstat()
        except OSError as exc:
            raise ReadinessError("READINESS_RECEIPT_DRAFT_UNSAFE") from exc
        if (
            not _same_file_identity(before, after)
            or after.st_dev != path_metadata.st_dev
            or after.st_ino != path_metadata.st_ino
        ):
            raise ReadinessError("READINESS_RECEIPT_DRAFT_CHANGED")
        try:
            receipt = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ReadinessError("READINESS_RECEIPT_INVALID") from exc
        if not isinstance(receipt, dict):
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        _validate_receipt(receipt)
        return receipt
    finally:
        os.close(descriptor)


def _receipt_directory(database: Path, *, create: bool) -> Path:
    root = Path(database).parent / "readiness-receipts"
    if create:
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ReadinessError("READINESS_RECEIPT_DIRECTORY_UNSAFE") from exc
    try:
        metadata = root.lstat()
    except OSError as exc:
        code = (
            "READINESS_RECEIPT_ARTIFACT_MISSING"
            if not create and isinstance(exc, FileNotFoundError)
            else "READINESS_RECEIPT_DIRECTORY_UNSAFE"
        )
        raise ReadinessError(code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReadinessError("READINESS_RECEIPT_DIRECTORY_UNSAFE")
    return root


def _require_database_binding(
    connection: sqlite3.Connection, database: Path
) -> None:
    main = next(
        (
            row
            for row in connection.execute("PRAGMA database_list")
            if str(row[1]) == "main"
        ),
        None,
    )
    if (
        main is None
        or not str(main[2])
        or Path(str(main[2])).absolute() != Path(database).absolute()
    ):
        raise ReadinessError("READINESS_DATABASE_BINDING_INVALID")


def _open_staged_artifact(
    database: Path, relative_path: str
) -> dict[str, Any]:
    if (
        not isinstance(relative_path, str)
        or Path(relative_path).is_absolute()
        or Path(relative_path).parts != (
            "readiness-receipts", Path(relative_path).name
        )
        or not Path(relative_path).name.endswith(".json")
    ):
        raise ReadinessError("READINESS_RECEIPT_LOCATOR_INVALID")
    root = _receipt_directory(database, create=False)
    path = Path(database).parent / relative_path
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except FileNotFoundError as exc:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_MISSING") from exc
    except OSError as exc:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_UNSAFE") from exc
    try:
        before = os.fstat(descriptor)
        if not _safe_file_metadata(before):
            raise ReadinessError("READINESS_RECEIPT_ARTIFACT_UNSAFE")
        raw = _read_descriptor(descriptor)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
        root_metadata = root.lstat()
        if (
            not _same_file_identity(before, after)
            or after.st_dev != path_metadata.st_dev
            or after.st_ino != path_metadata.st_ino
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CHANGED")
        return {
            "descriptor": descriptor,
            "path": path,
            "relative_path": relative_path,
            "raw": raw,
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": int(after.st_size),
            "device_id": int(after.st_dev),
            "inode": int(after.st_ino),
            "mode": int(after.st_mode),
            "uid": int(after.st_uid),
            "nlink": int(after.st_nlink),
            "mtime_ns": int(after.st_mtime_ns),
            "ctime_ns": int(after.st_ctime_ns),
        }
    except Exception:
        os.close(descriptor)
        raise


def _assert_artifact_current(artifact: dict[str, Any]) -> None:
    try:
        metadata = os.fstat(int(artifact["descriptor"]))
        path_metadata = Path(artifact["path"]).lstat()
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CHANGED") from exc
    if (
        not _safe_file_metadata(metadata)
        or metadata.st_dev != int(artifact["device_id"])
        or metadata.st_ino != int(artifact["inode"])
        or metadata.st_size != int(artifact["size_bytes"])
        or metadata.st_mtime_ns != int(artifact["mtime_ns"])
        or metadata.st_ctime_ns != int(artifact["ctime_ns"])
        or path_metadata.st_dev != metadata.st_dev
        or path_metadata.st_ino != metadata.st_ino
    ):
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CHANGED")


def _close_artifact(artifact: dict[str, Any]) -> None:
    descriptor = artifact.get("descriptor")
    if type(descriptor) is int and descriptor >= 0:
        os.close(descriptor)
        artifact["descriptor"] = -1


def _artifact_matches_pickup(pickup: Any, artifact: dict[str, Any]) -> bool:
    expected = (
        ("artifact_sha256", "artifact_sha256"),
        ("artifact_size_bytes", "size_bytes"),
        ("artifact_device_id", "device_id"),
        ("artifact_inode", "inode"),
        ("artifact_mode", "mode"),
        ("artifact_uid", "uid"),
        ("artifact_nlink", "nlink"),
        ("artifact_mtime_ns", "mtime_ns"),
        ("artifact_ctime_ns", "ctime_ns"),
    )
    try:
        return all(
            pickup[column] is not None
            and str(pickup[column]) == str(artifact[key])
            for column, key in expected
        )
    except (KeyError, IndexError, TypeError):
        return False


def _migration_step(
    failpoint: Callable[[str], None] | None, step: str
) -> None:
    if failpoint is not None:
        failpoint(step)


def _create_receipt_pickup_table(
    connection: sqlite3.Connection, table_name: str
) -> None:
    if not re.fullmatch(r"portfolio_readiness_receipt_pickups(?:_legacy)?", table_name):
        raise ReadinessError("READINESS_SCHEMA_TABLE_INVALID")
    connection.execute(
        f"""
        CREATE TABLE {table_name} (
            campaign_id INTEGER PRIMARY KEY,
            message_id INTEGER NOT NULL UNIQUE,
            attempt_id TEXT,
            locator_sha256 TEXT NOT NULL UNIQUE,
            relative_path TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK(state IN ('PENDING','STAGED','RECORDED','HOLD')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            next_attempt_at TEXT,
            receipt_id INTEGER,
            attempt_token_sha256 TEXT,
            artifact_sha256 TEXT,
            artifact_size_bytes INTEGER,
            artifact_device_id INTEGER,
            artifact_inode INTEGER,
            artifact_mode INTEGER,
            artifact_uid INTEGER,
            artifact_nlink INTEGER,
            artifact_mtime_ns INTEGER,
            artifact_ctime_ns INTEGER,
            version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_error TEXT,
            FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
            FOREIGN KEY(message_id) REFERENCES coordination_messages(id),
            FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id),
            FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id)
        )
        """
    )


def ensure_schema(
    connection: sqlite3.Connection,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> None:
    """Atomically install or migrate the readiness and receipt-pickup ledgers."""

    if connection.in_transaction:
        raise ReadinessError("READINESS_SCHEMA_TRANSACTION_CONFLICT")
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                generation INTEGER NOT NULL CHECK(generation >= 0),
                item_version INTEGER NOT NULL CHECK(item_version > 0),
                source_payload_sha256 TEXT NOT NULL,
                accepted_main_sha TEXT NOT NULL,
                graph_version INTEGER NOT NULL CHECK(graph_version > 0),
                capacity_policy_version INTEGER NOT NULL CHECK(capacity_policy_version > 0),
                candidate_sha256 TEXT NOT NULL,
                worker_role TEXT NOT NULL CHECK(worker_role IN ('development','sre')),
                phase_summary TEXT NOT NULL,
                plan_sha256 TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL,
                parent_campaign_id INTEGER,
                transition_kind TEXT,
                resolution_ordinal INTEGER NOT NULL DEFAULT 0,
                changed_evidence_sha256 TEXT,
                resolution_action_set_sha256 TEXT,
                approval_proposal_sha256 TEXT,
                approval_decision_sha256 TEXT,
                approval_recipient_session_id TEXT,
                approval_execution_scope_sha256 TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_gates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                gate_key TEXT NOT NULL,
                description TEXT NOT NULL,
                requested_evidence_json TEXT NOT NULL,
                gate_sha256 TEXT NOT NULL,
                UNIQUE(campaign_id, gate_key),
                UNIQUE(campaign_id, gate_sha256),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                verdict TEXT NOT NULL CHECK(verdict IN (
                    'PASS','ACTIONABLE_HOLD','APPROVAL_REQUIRED','TERMINAL_HOLD'
                )),
                worker_role TEXT NOT NULL CHECK(worker_role IN ('development','sre')),
                message_id INTEGER NOT NULL,
                attempt_id TEXT NOT NULL,
                resolution_role TEXT,
                resolution_action_set_sha256 TEXT NOT NULL,
                approval_proposal_sha256 TEXT,
                receipt_sha256 TEXT NOT NULL UNIQUE,
                receipt_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_current (
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                campaign_id INTEGER NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN (
                    'PENDING','RUNNING','RESOLUTION_PENDING','APPROVAL_PENDING',
                    'READY_ELIGIBLE','FINALIZED','HOLD','STALE'
                )),
                message_id INTEGER,
                attempt_id TEXT,
                endpoint_id TEXT,
                receipt_id INTEGER,
                resolution_cycles INTEGER NOT NULL DEFAULT 0 CHECK(resolution_cycles >= 0),
                version INTEGER NOT NULL CHECK(version > 0),
                updated_at TEXT NOT NULL,
                last_error TEXT,
                finalized_candidate_id INTEGER,
                finalized_event_id INTEGER,
                finalized_at TEXT,
                PRIMARY KEY(repository, issue_number),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id),
                FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_resolution_notices (
                campaign_id INTEGER PRIMARY KEY,
                receipt_id INTEGER NOT NULL UNIQUE,
                action_set_sha256 TEXT NOT NULL,
                message_id INTEGER NOT NULL UNIQUE,
                routed_endpoint_id TEXT NOT NULL,
                expected_readiness_version INTEGER NOT NULL
                    CHECK(expected_readiness_version > 0),
                created_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_resolution_contexts (
                notice_message_id INTEGER PRIMARY KEY,
                campaign_id INTEGER NOT NULL UNIQUE,
                receipt_id INTEGER NOT NULL UNIQUE,
                action_set_sha256 TEXT NOT NULL,
                context_sha256 TEXT NOT NULL UNIQUE,
                context_json TEXT NOT NULL,
                acting_planner_session_id TEXT NOT NULL,
                claimed_at TEXT NOT NULL,
                FOREIGN KEY(notice_message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_resolution_cycles (
                parent_campaign_id INTEGER PRIMARY KEY,
                receipt_id INTEGER NOT NULL UNIQUE,
                notice_message_id INTEGER NOT NULL UNIQUE,
                action_set_sha256 TEXT NOT NULL,
                context_sha256 TEXT NOT NULL,
                changed_evidence_sha256 TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK(outcome IN ('SUCCESSOR','HOLD')),
                successor_campaign_id INTEGER UNIQUE,
                disposition_reason TEXT,
                acting_planner_session_id TEXT NOT NULL,
                result_sha256 TEXT NOT NULL UNIQUE,
                result_json TEXT NOT NULL,
                consumed_at TEXT NOT NULL,
                FOREIGN KEY(parent_campaign_id)
                    REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id),
                FOREIGN KEY(notice_message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(successor_campaign_id)
                    REFERENCES portfolio_readiness_campaigns(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_resolution_action_starts (
                notice_message_id INTEGER NOT NULL,
                action_sha256 TEXT NOT NULL,
                action_index INTEGER NOT NULL CHECK(action_index >= 0),
                campaign_id INTEGER NOT NULL,
                receipt_id INTEGER NOT NULL,
                context_sha256 TEXT NOT NULL,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                expected_digest TEXT NOT NULL,
                desired_digest TEXT NOT NULL,
                action_input_sha256 TEXT NOT NULL,
                before_binding_sha256 TEXT NOT NULL,
                before_binding_json TEXT NOT NULL,
                acting_planner_session_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(notice_message_id, action_sha256),
                UNIQUE(notice_message_id, action_index),
                FOREIGN KEY(notice_message_id)
                    REFERENCES coordination_messages(id),
                FOREIGN KEY(campaign_id)
                    REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(receipt_id)
                    REFERENCES portfolio_readiness_receipts(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_resolution_action_completions (
                notice_message_id INTEGER NOT NULL,
                action_sha256 TEXT NOT NULL,
                context_sha256 TEXT NOT NULL,
                after_binding_sha256 TEXT NOT NULL,
                after_binding_json TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                PRIMARY KEY(notice_message_id, action_sha256),
                FOREIGN KEY(notice_message_id, action_sha256)
                    REFERENCES portfolio_readiness_resolution_action_starts(
                        notice_message_id, action_sha256
                    )
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_approval_requests (
                campaign_id INTEGER PRIMARY KEY,
                receipt_id INTEGER NOT NULL UNIQUE,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                source_payload_sha256 TEXT NOT NULL,
                expected_approval_pending_version INTEGER NOT NULL
                    CHECK(expected_approval_pending_version > 0),
                proposal_sha256 TEXT NOT NULL UNIQUE,
                submission_sha256 TEXT NOT NULL UNIQUE,
                execution_scope_sha256 TEXT NOT NULL,
                boundary TEXT NOT NULL,
                requester_session_id TEXT NOT NULL,
                packet_recipient_session_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id),
                FOREIGN KEY(proposal_sha256) REFERENCES approval_proposals(proposal_sha256),
                FOREIGN KEY(submission_sha256)
                    REFERENCES approval_submissions(submission_sha256)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_approval_consumptions (
                request_campaign_id INTEGER PRIMARY KEY,
                receipt_id INTEGER NOT NULL UNIQUE,
                proposal_sha256 TEXT NOT NULL UNIQUE,
                decision_sha256 TEXT NOT NULL UNIQUE,
                delivery_recipient_session_id TEXT NOT NULL,
                notice_message_id INTEGER NOT NULL UNIQUE,
                disposition TEXT NOT NULL CHECK(disposition IN (
                    'RESUMED','HOLD','STALE','RESOLUTION_PENDING'
                )),
                successor_campaign_id INTEGER UNIQUE,
                effective_source_sha256 TEXT NOT NULL,
                remote_receipt TEXT NOT NULL,
                acting_planner_session_id TEXT NOT NULL,
                revisit_trigger_json TEXT,
                consumed_at TEXT NOT NULL,
                FOREIGN KEY(request_campaign_id)
                    REFERENCES portfolio_readiness_approval_requests(campaign_id),
                FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id),
                FOREIGN KEY(notice_message_id) REFERENCES coordination_messages(id),
                FOREIGN KEY(successor_campaign_id)
                    REFERENCES portfolio_readiness_campaigns(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_source_equivalence (
                request_campaign_id INTEGER NOT NULL,
                decision_sha256 TEXT NOT NULL,
                bound_source_sha256 TEXT NOT NULL,
                observed_source_sha256 TEXT NOT NULL,
                stable_source_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(request_campaign_id, observed_source_sha256),
                FOREIGN KEY(request_campaign_id)
                    REFERENCES portfolio_readiness_approval_requests(campaign_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_revisit_notices (
                request_campaign_id INTEGER PRIMARY KEY,
                proposal_sha256 TEXT NOT NULL UNIQUE,
                decision_sha256 TEXT NOT NULL UNIQUE,
                due_at TEXT NOT NULL,
                routed_endpoint_id TEXT NOT NULL,
                message_id INTEGER NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY(request_campaign_id)
                    REFERENCES portfolio_readiness_approval_requests(campaign_id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_readiness_revocation_notices (
                campaign_id INTEGER PRIMARY KEY,
                proposal_sha256 TEXT NOT NULL,
                decision_sha256 TEXT NOT NULL UNIQUE,
                prior_state TEXT NOT NULL,
                routed_endpoint_id TEXT NOT NULL,
                message_id INTEGER NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                FOREIGN KEY(message_id) REFERENCES coordination_messages(id)
            )
            """
        )
        _migration_step(failpoint, "after_base_tables")
        campaign_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(portfolio_readiness_campaigns)")
        }
        campaign_additions = {
            "parent_campaign_id": "INTEGER",
            "transition_kind": "TEXT",
            "resolution_ordinal": "INTEGER NOT NULL DEFAULT 0",
            "changed_evidence_sha256": "TEXT",
            "resolution_action_set_sha256": "TEXT",
            "approval_proposal_sha256": "TEXT",
            "approval_decision_sha256": "TEXT",
            "approval_recipient_session_id": "TEXT",
            "approval_execution_scope_sha256": "TEXT",
        }
        for column, declaration in campaign_additions.items():
            if column not in campaign_columns:
                connection.execute(
                    f"ALTER TABLE portfolio_readiness_campaigns ADD COLUMN {column} {declaration}"
                )
        _migration_step(failpoint, "after_campaign_columns")
        receipt_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(portfolio_readiness_receipts)")
        }
        for column, declaration in {
            "resolution_action_set_sha256": "TEXT",
            "approval_proposal_sha256": "TEXT",
        }.items():
            if column not in receipt_columns:
                connection.execute(
                    f"ALTER TABLE portfolio_readiness_receipts "
                    f"ADD COLUMN {column} {declaration}"
                )
        _migration_step(failpoint, "after_receipt_columns")
        current_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(portfolio_readiness_current)")
        }
        current_sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='portfolio_readiness_current'"
        ).fetchone()
        current_sql = "" if current_sql_row is None else str(current_sql_row[0])
        if "FINALIZED" not in current_sql:
            connection.execute(
                "ALTER TABLE portfolio_readiness_current "
                "RENAME TO portfolio_readiness_current_legacy"
            )
            connection.execute(
                """
                CREATE TABLE portfolio_readiness_current (
                    repository TEXT NOT NULL,
                    issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                    campaign_id INTEGER NOT NULL UNIQUE,
                    state TEXT NOT NULL CHECK(state IN (
                        'PENDING','RUNNING','RESOLUTION_PENDING','APPROVAL_PENDING',
                        'READY_ELIGIBLE','FINALIZED','HOLD','STALE'
                    )),
                    message_id INTEGER,
                    attempt_id TEXT,
                    endpoint_id TEXT,
                    receipt_id INTEGER,
                    resolution_cycles INTEGER NOT NULL DEFAULT 0
                        CHECK(resolution_cycles >= 0),
                    version INTEGER NOT NULL CHECK(version > 0),
                    updated_at TEXT NOT NULL,
                    last_error TEXT,
                    finalized_candidate_id INTEGER,
                    finalized_event_id INTEGER,
                    finalized_at TEXT,
                    PRIMARY KEY(repository, issue_number),
                    FOREIGN KEY(campaign_id) REFERENCES portfolio_readiness_campaigns(id),
                    FOREIGN KEY(message_id) REFERENCES coordination_messages(id),
                    FOREIGN KEY(attempt_id) REFERENCES executor_attempts(attempt_id),
                    FOREIGN KEY(receipt_id) REFERENCES portfolio_readiness_receipts(id)
                )
                """
            )
            connection.execute(
                """
                INSERT INTO portfolio_readiness_current(
                    repository, issue_number, campaign_id, state, message_id,
                    attempt_id, endpoint_id, receipt_id, resolution_cycles,
                    version, updated_at, last_error
                )
                SELECT repository, issue_number, campaign_id, state, message_id,
                       attempt_id, endpoint_id, receipt_id, resolution_cycles,
                       version, updated_at, last_error
                FROM portfolio_readiness_current_legacy
                """
            )
            connection.execute("DROP TABLE portfolio_readiness_current_legacy")
        else:
            for column, declaration in {
                "finalized_candidate_id": "INTEGER",
                "finalized_event_id": "INTEGER",
                "finalized_at": "TEXT",
            }.items():
                if column not in current_columns:
                    connection.execute(
                        f"ALTER TABLE portfolio_readiness_current ADD COLUMN {column} {declaration}"
                    )
        _migration_step(failpoint, "after_current_table")
        pickup_sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='portfolio_readiness_receipt_pickups'"
        ).fetchone()
        if pickup_sql_row is None:
            _create_receipt_pickup_table(
                connection, "portfolio_readiness_receipt_pickups"
            )
        else:
            pickup_sql = str(pickup_sql_row[0])
            pickup_columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(portfolio_readiness_receipt_pickups)"
                )
            }
            required_pickup_columns = {
                "attempt_token_sha256", "artifact_mode", "artifact_uid",
                "artifact_nlink", "artifact_ctime_ns",
            }
            if "STAGED" not in pickup_sql or not required_pickup_columns.issubset(
                pickup_columns
            ):
                connection.execute(
                    "ALTER TABLE portfolio_readiness_receipt_pickups "
                    "RENAME TO portfolio_readiness_receipt_pickups_legacy"
                )
                _create_receipt_pickup_table(
                    connection, "portfolio_readiness_receipt_pickups"
                )
                connection.execute(
                    """
                    INSERT INTO portfolio_readiness_receipt_pickups(
                        campaign_id, message_id, attempt_id, locator_sha256,
                        relative_path, state, attempts, next_attempt_at, receipt_id,
                        artifact_sha256, artifact_size_bytes, artifact_device_id,
                        artifact_inode, artifact_mtime_ns, version, created_at,
                        updated_at, last_error
                    )
                    SELECT campaign_id, message_id, attempt_id, locator_sha256,
                           relative_path, state, attempts, next_attempt_at, receipt_id,
                           artifact_sha256, artifact_size_bytes, artifact_device_id,
                           artifact_inode, artifact_mtime_ns, version, created_at,
                           updated_at, last_error
                    FROM portfolio_readiness_receipt_pickups_legacy
                    """
                )
                connection.execute(
                    "DROP TABLE portfolio_readiness_receipt_pickups_legacy"
                )
        _migration_step(failpoint, "after_pickup_table")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "portfolio_readiness_one_successor_per_parent "
            "ON portfolio_readiness_campaigns(parent_campaign_id) "
            "WHERE parent_campaign_id IS NOT NULL"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "portfolio_readiness_one_receipt_per_campaign "
            "ON portfolio_readiness_receipts(campaign_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS portfolio_readiness_pickup_due "
            "ON portfolio_readiness_receipt_pickups(state, next_attempt_at, campaign_id)"
        )
        _migration_step(failpoint, "after_indexes")
        trigger_statements = (
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_campaigns_immutable_update
               BEFORE UPDATE ON portfolio_readiness_campaigns
               BEGIN SELECT RAISE(ABORT, 'READINESS_CAMPAIGN_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_campaigns_immutable_delete
               BEFORE DELETE ON portfolio_readiness_campaigns
               BEGIN SELECT RAISE(ABORT, 'READINESS_CAMPAIGN_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_gates_immutable_update
               BEFORE UPDATE ON portfolio_readiness_gates
               BEGIN SELECT RAISE(ABORT, 'READINESS_GATE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_gates_immutable_delete
               BEFORE DELETE ON portfolio_readiness_gates
               BEGIN SELECT RAISE(ABORT, 'READINESS_GATE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_receipts_immutable_update
               BEFORE UPDATE ON portfolio_readiness_receipts
               BEGIN SELECT RAISE(ABORT, 'READINESS_RECEIPT_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_receipts_immutable_delete
               BEFORE DELETE ON portfolio_readiness_receipts
               BEGIN SELECT RAISE(ABORT, 'READINESS_RECEIPT_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_events_immutable_update
               BEFORE UPDATE ON portfolio_readiness_events
               BEGIN SELECT RAISE(ABORT, 'READINESS_EVENT_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_events_immutable_delete
               BEFORE DELETE ON portfolio_readiness_events
               BEGIN SELECT RAISE(ABORT, 'READINESS_EVENT_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_notices_immutable_update
               BEFORE UPDATE ON portfolio_readiness_resolution_notices
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_NOTICE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_notices_immutable_delete
               BEFORE DELETE ON portfolio_readiness_resolution_notices
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_NOTICE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_contexts_immutable_update
               BEFORE UPDATE ON portfolio_readiness_resolution_contexts
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_CONTEXT_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_contexts_immutable_delete
               BEFORE DELETE ON portfolio_readiness_resolution_contexts
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_CONTEXT_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_cycles_immutable_update
               BEFORE UPDATE ON portfolio_readiness_resolution_cycles
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_CYCLE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_cycles_immutable_delete
               BEFORE DELETE ON portfolio_readiness_resolution_cycles
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_CYCLE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_action_starts_immutable_update
               BEFORE UPDATE ON portfolio_readiness_resolution_action_starts
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_ACTION_START_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_action_starts_immutable_delete
               BEFORE DELETE ON portfolio_readiness_resolution_action_starts
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_ACTION_START_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_action_completions_immutable_update
               BEFORE UPDATE ON portfolio_readiness_resolution_action_completions
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_ACTION_COMPLETION_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_resolution_action_completions_immutable_delete
               BEFORE DELETE ON portfolio_readiness_resolution_action_completions
               BEGIN SELECT RAISE(ABORT, 'READINESS_RESOLUTION_ACTION_COMPLETION_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_approval_requests_immutable_update
               BEFORE UPDATE ON portfolio_readiness_approval_requests
               BEGIN SELECT RAISE(ABORT, 'READINESS_APPROVAL_REQUEST_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_approval_requests_immutable_delete
               BEFORE DELETE ON portfolio_readiness_approval_requests
               BEGIN SELECT RAISE(ABORT, 'READINESS_APPROVAL_REQUEST_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_approval_consumptions_immutable_update
               BEFORE UPDATE ON portfolio_readiness_approval_consumptions
               BEGIN SELECT RAISE(ABORT, 'READINESS_APPROVAL_CONSUMPTION_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_approval_consumptions_immutable_delete
               BEFORE DELETE ON portfolio_readiness_approval_consumptions
               BEGIN SELECT RAISE(ABORT, 'READINESS_APPROVAL_CONSUMPTION_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_source_equivalence_immutable_update
               BEFORE UPDATE ON portfolio_readiness_source_equivalence
               BEGIN SELECT RAISE(ABORT, 'READINESS_SOURCE_EQUIVALENCE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_source_equivalence_immutable_delete
               BEFORE DELETE ON portfolio_readiness_source_equivalence
               BEGIN SELECT RAISE(ABORT, 'READINESS_SOURCE_EQUIVALENCE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_revisit_notices_immutable_update
               BEFORE UPDATE ON portfolio_readiness_revisit_notices
               BEGIN SELECT RAISE(ABORT, 'READINESS_REVISIT_NOTICE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_revisit_notices_immutable_delete
               BEFORE DELETE ON portfolio_readiness_revisit_notices
               BEGIN SELECT RAISE(ABORT, 'READINESS_REVISIT_NOTICE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_revocation_notices_immutable_update
               BEFORE UPDATE ON portfolio_readiness_revocation_notices
               BEGIN SELECT RAISE(ABORT, 'READINESS_REVOCATION_NOTICE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_revocation_notices_immutable_delete
               BEFORE DELETE ON portfolio_readiness_revocation_notices
               BEGIN SELECT RAISE(ABORT, 'READINESS_REVOCATION_NOTICE_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_pickup_identity_immutable
               BEFORE UPDATE ON portfolio_readiness_receipt_pickups
               WHEN NEW.campaign_id IS NOT OLD.campaign_id
                 OR NEW.message_id IS NOT OLD.message_id
                 OR NEW.locator_sha256 IS NOT OLD.locator_sha256
                 OR NEW.relative_path IS NOT OLD.relative_path
                 OR NEW.created_at IS NOT OLD.created_at
                 OR (OLD.attempt_id IS NOT NULL AND NEW.attempt_id IS NOT OLD.attempt_id)
                 OR (OLD.attempt_token_sha256 IS NOT NULL AND (
                       NEW.attempt_token_sha256 IS NOT OLD.attempt_token_sha256
                    OR NEW.artifact_sha256 IS NOT OLD.artifact_sha256
                    OR NEW.artifact_size_bytes IS NOT OLD.artifact_size_bytes
                    OR NEW.artifact_device_id IS NOT OLD.artifact_device_id
                    OR NEW.artifact_inode IS NOT OLD.artifact_inode
                    OR NEW.artifact_mode IS NOT OLD.artifact_mode
                    OR NEW.artifact_uid IS NOT OLD.artifact_uid
                    OR NEW.artifact_nlink IS NOT OLD.artifact_nlink
                    OR NEW.artifact_mtime_ns IS NOT OLD.artifact_mtime_ns
                    OR NEW.artifact_ctime_ns IS NOT OLD.artifact_ctime_ns
                 ))
                 OR (OLD.state='STAGED' AND NEW.state NOT IN ('STAGED','RECORDED','HOLD'))
                 OR (OLD.state='RECORDED' AND NEW.state!='RECORDED')
               BEGIN SELECT RAISE(ABORT, 'READINESS_PICKUP_IDENTITY_IMMUTABLE'); END""",
            """CREATE TRIGGER IF NOT EXISTS portfolio_readiness_pickup_immutable_delete
               BEFORE DELETE ON portfolio_readiness_receipt_pickups
               BEGIN SELECT RAISE(ABORT, 'READINESS_PICKUP_IMMUTABLE'); END""",
        )
        for statement in trigger_statements:
            connection.execute(statement)
        _migration_step(failpoint, "after_triggers")

        legacy = connection.execute(
            """
            SELECT campaign.*, current.message_id, current.attempt_id,
                   current.receipt_id AS current_receipt_id,
                   current.state AS current_state,
                   current.updated_at AS current_updated_at
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
            LEFT JOIN portfolio_readiness_receipt_pickups pickup
              ON pickup.campaign_id=campaign.id
            WHERE current.message_id IS NOT NULL AND pickup.campaign_id IS NULL
            """
        ).fetchall()
        for campaign in legacy:
            locator = _receipt_locator(campaign)
            pickup_state = (
                "RECORDED"
                if campaign["current_receipt_id"] is not None
                else "PENDING"
                if campaign["current_state"] == "RUNNING"
                else "HOLD"
            )
            pickup_error = (
                None
                if pickup_state in {"RECORDED", "PENDING"}
                else "READINESS_RECEIPT_LEGACY_STATE_UNRECOVERABLE"
            )
            connection.execute(
                """
                INSERT INTO portfolio_readiness_receipt_pickups(
                    campaign_id, message_id, attempt_id, locator_sha256,
                    relative_path, state, attempts, next_attempt_at, receipt_id,
                    version, created_at, updated_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, 1, ?, ?, ?)
                """,
                (
                    int(campaign["id"]), int(campaign["message_id"]),
                    campaign["attempt_id"], digest_json(locator),
                    locator["relative_path"], pickup_state,
                    campaign["current_receipt_id"], campaign["current_updated_at"],
                    campaign["current_updated_at"], pickup_error,
                ),
            )
        _migration_step(failpoint, "before_commit")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _require_pull_buffer_schema(connection: sqlite3.Connection) -> None:
    required = {"portfolio_pull_buffer_candidates", "portfolio_pull_buffer_current"}
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'portfolio_pull_buffer_%'"
        )
    }
    if not required.issubset(present):
        raise ReadinessError("PULL_BUFFER_SCHEMA_MISSING")


def require_schema(connection: sqlite3.Connection) -> None:
    required = {
        "portfolio_readiness_campaigns", "portfolio_readiness_gates",
        "portfolio_readiness_receipts", "portfolio_readiness_current",
        "portfolio_readiness_events", "portfolio_readiness_receipt_pickups",
        "portfolio_readiness_resolution_notices",
        "portfolio_readiness_resolution_contexts",
        "portfolio_readiness_resolution_cycles",
        "portfolio_readiness_resolution_action_starts",
        "portfolio_readiness_resolution_action_completions",
    }
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'portfolio_readiness_%'"
        )
    }
    if not required.issubset(present):
        raise ReadinessError("READINESS_SCHEMA_MISSING")


def _event(
    connection: sqlite3.Connection,
    campaign_id: int,
    event_type: str,
    payload: dict[str, Any],
    now: str,
) -> None:
    connection.execute(
        """
        INSERT INTO portfolio_readiness_events(
            campaign_id, event_type, payload_sha256, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (campaign_id, event_type, digest_json(payload), canonical_json(payload), now),
    )


def _validate_plan(plan: dict[str, Any]) -> None:
    expected = {
        "schema", "repository", "issue_number", "generation", "item_version",
        "source_payload_sha256", "accepted_main_sha", "graph_version",
        "capacity_policy_version", "candidate_sha256", "worker_role",
        "phase_summary", "gates",
    }
    schema = plan.get("schema")
    if schema == SUCCESSOR_PLAN_SCHEMA:
        expected.add("transition")
    if set(plan) != expected or schema not in {PLAN_SCHEMA, SUCCESSOR_PLAN_SCHEMA}:
        raise ReadinessError("READINESS_PLAN_INVALID")
    if not isinstance(plan.get("repository"), str) or not REPOSITORY.fullmatch(plan["repository"]):
        raise ReadinessError("READINESS_PLAN_INVALID")
    for field in ("issue_number", "item_version", "graph_version", "capacity_policy_version"):
        if type(plan.get(field)) is not int or int(plan[field]) <= 0:
            raise ReadinessError("READINESS_PLAN_INVALID")
    if type(plan.get("generation")) is not int or int(plan["generation"]) < 0:
        raise ReadinessError("READINESS_PLAN_INVALID")
    for field in ("source_payload_sha256", "candidate_sha256"):
        if not isinstance(plan.get(field), str) or not SHA256.fullmatch(plan[field]):
            raise ReadinessError("READINESS_PLAN_INVALID")
    if not isinstance(plan.get("accepted_main_sha"), str) or not GIT_SHA.fullmatch(plan["accepted_main_sha"]):
        raise ReadinessError("READINESS_PLAN_INVALID")
    if plan.get("worker_role") not in WORKER_ROLES:
        raise ReadinessError("READINESS_WORKER_ROLE_INVALID")
    if not isinstance(plan.get("phase_summary"), str) or not plan["phase_summary"].strip():
        raise ReadinessError("READINESS_PLAN_INVALID")
    gates = plan.get("gates")
    if not isinstance(gates, list) or not gates:
        raise ReadinessError("READINESS_GATES_REQUIRED")
    seen: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) != {
            "gate_key", "description", "requested_evidence"
        }:
            raise ReadinessError("READINESS_GATE_INVALID")
        key = gate.get("gate_key")
        if not isinstance(key, str) or not GATE_KEY.fullmatch(key) or key in seen:
            raise ReadinessError("READINESS_GATE_INVALID")
        seen.add(key)
        if not isinstance(gate.get("description"), str) or not gate["description"].strip():
            raise ReadinessError("READINESS_GATE_INVALID")
        evidence = gate.get("requested_evidence")
        if not isinstance(evidence, list) or not evidence or any(
            not isinstance(value, str) or not value.strip() for value in evidence
        ):
            raise ReadinessError("READINESS_GATE_INVALID")
    if schema == SUCCESSOR_PLAN_SCHEMA:
        transition = plan.get("transition")
        if not isinstance(transition, dict) or set(transition) != {
            "kind", "parent_campaign_id", "expected_parent_version",
            "changed_evidence_sha256", "resolution_action_set_sha256",
            "approval",
        }:
            raise ReadinessError("READINESS_TRANSITION_INVALID")
        if transition.get("kind") not in {
            "RESOLUTION", "REFRESH", "APPROVAL_RESUME"
        }:
            raise ReadinessError("READINESS_TRANSITION_INVALID")
        for field in ("parent_campaign_id", "expected_parent_version"):
            if type(transition.get(field)) is not int or int(transition[field]) <= 0:
                raise ReadinessError("READINESS_TRANSITION_INVALID")
        changed = transition.get("changed_evidence_sha256")
        if not isinstance(changed, str) or not SHA256.fullmatch(changed):
            raise ReadinessError("READINESS_TRANSITION_INVALID")
        action_set_sha256 = transition.get("resolution_action_set_sha256")
        if transition["kind"] == "RESOLUTION":
            if (
                not isinstance(action_set_sha256, str)
                or SHA256.fullmatch(action_set_sha256) is None
            ):
                raise ReadinessError("READINESS_RESOLUTION_ACTION_BINDING_INVALID")
        elif action_set_sha256 is not None:
            raise ReadinessError("READINESS_TRANSITION_INVALID")
        approval = transition.get("approval")
        if transition["kind"] in {"APPROVAL_RESUME", "RESOLUTION"} and (
            transition["kind"] == "APPROVAL_RESUME" or approval is not None
        ):
            if not isinstance(approval, dict) or set(approval) != {
                "proposal_sha256", "decision_sha256", "recipient_session_id",
                "execution_scope_sha256",
            }:
                raise ReadinessError("READINESS_APPROVAL_BINDING_INVALID")
            for field in (
                "proposal_sha256", "decision_sha256", "execution_scope_sha256"
            ):
                if not isinstance(approval.get(field), str) or not SHA256.fullmatch(
                    approval[field]
                ):
                    raise ReadinessError("READINESS_APPROVAL_BINDING_INVALID")
            if not isinstance(approval.get("recipient_session_id"), str) or not approval[
                "recipient_session_id"
            ].strip():
                raise ReadinessError("READINESS_APPROVAL_BINDING_INVALID")
        elif approval is not None:
            raise ReadinessError("READINESS_TRANSITION_INVALID")


def transition_evidence_payload(
    parent_plan: dict[str, Any], successor_plan: dict[str, Any]
) -> dict[str, Any]:
    """Return the canonical, non-self-referential successor evidence delta."""

    transition = successor_plan.get("transition")
    if not isinstance(parent_plan, dict) or not isinstance(transition, dict):
        raise ReadinessError("READINESS_TRANSITION_INVALID")
    parent_core = {
        key: value
        for key, value in parent_plan.items()
        if key not in {"schema", "transition"}
    }
    successor_core = {
        key: value
        for key, value in successor_plan.items()
        if key not in {"schema", "transition"}
    }
    changed_fields = {
        key: {
            "before_sha256": digest_json(parent_core.get(key)),
            "after_sha256": digest_json(successor_core.get(key)),
        }
        for key in sorted(set(parent_core) | set(successor_core))
        if parent_core.get(key) != successor_core.get(key)
    }
    return {
        "schema": TRANSITION_EVIDENCE_SCHEMA,
        "kind": transition.get("kind"),
        "parent_campaign_id": transition.get("parent_campaign_id"),
        "parent_plan_sha256": digest_json(parent_plan),
        "changed_fields": changed_fields,
        "approval_sha256": (
            None
            if transition.get("approval") is None
            else digest_json(transition["approval"])
        ),
        "resolution_action_set_sha256": transition.get(
            "resolution_action_set_sha256"
        ),
    }


def transition_evidence_sha256(
    parent_plan: dict[str, Any], successor_plan: dict[str, Any]
) -> str:
    return digest_json(transition_evidence_payload(parent_plan, successor_plan))


def _campaign(
    connection: sqlite3.Connection, repository: str, issue_number: int
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT campaign.*, current.state, current.message_id, current.attempt_id,
               current.endpoint_id, current.receipt_id, current.resolution_cycles,
               current.version AS current_version, current.updated_at,
               current.last_error, current.finalized_candidate_id,
               current.finalized_event_id, current.finalized_at
        FROM portfolio_readiness_current current
        JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
        WHERE current.repository=? AND current.issue_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if row is None:
        raise ReadinessError("READINESS_CAMPAIGN_NOT_FOUND")
    return row


def _stable_source_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "updated_at" and not key.startswith("_projection_")
    }


def _approval_parent_campaign_id(campaign: Any) -> int | None:
    if isinstance(campaign, dict):
        transition = campaign.get("transition")
        if isinstance(transition, dict) and transition.get("kind") == "APPROVAL_RESUME":
            value = transition.get("parent_campaign_id")
            return value if type(value) is int else None
        value = campaign.get("parent_campaign_id")
        return int(value) if value is not None else None
    keys = set(campaign.keys())
    if "transition_kind" not in keys or campaign["transition_kind"] != "APPROVAL_RESUME":
        return None
    value = campaign["parent_campaign_id"]
    return int(value) if value is not None else None


def approval_source_equivalent(
    connection: sqlite3.Connection,
    campaign: Any,
    bound_source_sha256: str,
    observed_source_sha256: str,
) -> bool:
    """Prove one narrowly recorded comment/projection-only source change."""

    if bound_source_sha256 == observed_source_sha256:
        return True
    parent_campaign_id = _approval_parent_campaign_id(campaign)
    if parent_campaign_id is None:
        candidate_id = (
            campaign.get("id")
            if isinstance(campaign, dict)
            else campaign["id"] if "id" in campaign.keys() else None
        )
        if type(candidate_id) is int and candidate_id > 0 and connection.execute(
            "SELECT 1 FROM portfolio_readiness_approval_requests WHERE campaign_id=?",
            (candidate_id,),
        ).fetchone():
            parent_campaign_id = candidate_id
    if parent_campaign_id is None:
        return False
    row = connection.execute(
        """
        SELECT equivalence.*, request.proposal_sha256,
               bound.payload_json AS bound_payload_json,
               observed.payload_json AS observed_payload_json
        FROM portfolio_readiness_source_equivalence equivalence
        JOIN portfolio_readiness_approval_requests request
          ON request.campaign_id=equivalence.request_campaign_id
        JOIN github_snapshots bound
          ON bound.repository=request.repository
         AND bound.object_kind='issue'
         AND bound.object_number=request.issue_number
         AND bound.payload_sha256=equivalence.bound_source_sha256
        JOIN github_snapshots observed
          ON observed.repository=request.repository
         AND observed.object_kind='issue'
         AND observed.object_number=request.issue_number
         AND observed.payload_sha256=equivalence.observed_source_sha256
        WHERE equivalence.request_campaign_id=?
          AND equivalence.bound_source_sha256=?
          AND equivalence.observed_source_sha256=?
        """,
        (parent_campaign_id, bound_source_sha256, observed_source_sha256),
    ).fetchone()
    if row is None:
        return False
    try:
        bound = json.loads(row["bound_payload_json"], object_pairs_hook=_strict_object)
        observed = json.loads(
            row["observed_payload_json"], object_pairs_hook=_strict_object
        )
    except (TypeError, json.JSONDecodeError, ReadinessError):
        return False
    stable = digest_json(_stable_source_payload(bound))
    return bool(
        stable == row["stable_source_sha256"]
        and stable == digest_json(_stable_source_payload(observed))
    )


def _graph_stale_only_for_equivalent_source(
    connection: sqlite3.Connection, campaign: Any, graph: Any
) -> bool:
    if graph is None or graph["health"] != "STALE":
        return False
    if (
        int(graph["version"]) != int(campaign["graph_version"])
        or graph["observed_main_sha"] != campaign["accepted_main_sha"]
    ):
        return False
    mismatches = connection.execute(
        """
        SELECT node.issue_number, node.source_payload_sha256,
               current.payload_sha256 AS observed_source_sha256
        FROM portfolio_graph_nodes node
        LEFT JOIN github_current current
          ON current.repository=node.repository
         AND current.object_kind='issue'
         AND current.object_number=node.issue_number
        WHERE node.repository=? AND node.graph_version=?
          AND (current.payload_sha256 IS NULL
               OR current.payload_sha256<>node.source_payload_sha256)
        """,
        (campaign["repository"], int(campaign["graph_version"])),
    ).fetchall()
    return bool(
        mismatches
        and all(
            int(row["issue_number"]) == int(campaign["issue_number"])
            and row["observed_source_sha256"] is not None
            and approval_source_equivalent(
                connection,
                campaign,
                str(row["source_payload_sha256"]),
                str(row["observed_source_sha256"]),
            )
            for row in mismatches
        )
    )


def _binding_reasons(connection: sqlite3.Connection, campaign: Any) -> list[str]:
    repository = str(campaign["repository"])
    issue_number = int(campaign["issue_number"])
    reasons: list[str] = []
    state = (
        campaign.get("state")
        if isinstance(campaign, dict)
        else campaign["state"] if "state" in campaign.keys() else None
    )
    finalized = state == "FINALIZED"
    graph = connection.execute(
        "SELECT * FROM portfolio_graph_current WHERE repository=?", (repository,)
    ).fetchone()
    if not finalized:
        if graph is None or (
            graph["health"] != "CURRENT"
            and not _graph_stale_only_for_equivalent_source(
                connection, campaign, graph
            )
        ):
            reasons.append("GRAPH_STALE")
        else:
            if int(graph["version"]) != int(campaign["graph_version"]):
                reasons.append("GRAPH_VERSION_DRIFT")
            if graph["observed_main_sha"] != campaign["accepted_main_sha"]:
                reasons.append("MAIN_DRIFT")
    policy = connection.execute(
        "SELECT version FROM coordination_capacity_current WHERE repository=?", (repository,)
    ).fetchone()
    if not finalized and (
        policy is None or int(policy["version"]) != int(campaign["capacity_policy_version"])
    ):
        reasons.append("CAPACITY_POLICY_DRIFT")
    item = connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (repository, issue_number),
    ).fetchone()
    if item is None:
        reasons.append("ITEM_MISSING")
    else:
        if int(item["generation"]) != int(campaign["generation"]):
            reasons.append("ITEM_GENERATION_DRIFT")
        if item["source_payload_sha256"] != campaign["source_payload_sha256"]:
            reasons.append("ITEM_SOURCE_DRIFT")
        if finalized:
            if item["status"] == "READY":
                if (
                    int(item["version"]) != int(campaign["item_version"]) + 1
                    or item["allocation_class"] != "NONE"
                ):
                    reasons.append("ITEM_VERSION_DRIFT")
            elif item["status"] not in {
                "ACTIVE", "ACTIVE_FENCED", "MONITOR", "HOLD", "DONE"
            }:
                reasons.append("ITEM_FINALIZATION_STATE_DRIFT")
        elif int(item["version"]) != int(campaign["item_version"]):
            reasons.append("ITEM_VERSION_DRIFT")
        if not finalized and (
            item["status"] != "PREPARED" or item["allocation_class"] != "NONE"
        ):
            reasons.append("ITEM_NOT_ZERO_WIP_PREPARED")
    if not finalized:
        source = connection.execute(
            """
            SELECT payload_sha256 FROM github_current
            WHERE repository=? AND object_kind='issue' AND object_number=?
            """,
            (repository, issue_number),
        ).fetchone()
        if source is None or (
            source["payload_sha256"] != campaign["source_payload_sha256"]
            and not approval_source_equivalent(
                connection,
                campaign,
                str(campaign["source_payload_sha256"]),
                str(source["payload_sha256"]),
            )
        ):
            reasons.append("SOURCE_SNAPSHOT_DRIFT")
    if finalized:
        candidate = connection.execute(
            """
            SELECT candidate.*, finalization.campaign_id AS finalization_campaign_id,
                   finalization.receipt_id AS finalization_receipt_id,
                   finalization.dirty_event_id AS finalization_event_id
            FROM portfolio_pull_buffer_candidates candidate
            LEFT JOIN portfolio_ready_finalizations finalization
              ON finalization.ready_candidate_id=candidate.id
            WHERE candidate.id=?
            """,
            (int(campaign["finalized_candidate_id"] or -1),),
        ).fetchone()
    else:
        candidate = connection.execute(
            """
            SELECT candidate.* FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates candidate ON candidate.id=pointer.candidate_id
            WHERE pointer.repository=? AND pointer.issue_number=?
            """,
            (repository, issue_number),
        ).fetchone()
    if candidate is None:
        reasons.append("PULL_BUFFER_CANDIDATE_MISSING")
    else:
        if not finalized and candidate["candidate_sha256"] != campaign["candidate_sha256"]:
            reasons.append("PULL_BUFFER_CANDIDATE_DRIFT")
        expected_candidate_state = "READY" if finalized else "PREPARED_NOT_READY"
        if candidate["state"] != expected_candidate_state:
            reasons.append("PULL_BUFFER_CANDIDATE_STATE_DRIFT")
        if finalized and (
            int(candidate["readiness_campaign_id"] or -1) != int(campaign["id"])
            or int(candidate["finalization_campaign_id"] or -1) != int(campaign["id"])
            or int(candidate["finalization_event_id"] or -1)
            != int(campaign["finalized_event_id"] or -1)
        ):
            reasons.append("READINESS_FINALIZATION_DRIFT")
    if not finalized and graph is not None and graph["health"] == "CURRENT":
        try:
            evaluation = evaluate_graph(
                connection,
                repository,
                current_main=str(graph["observed_main_sha"]),
                _ensure_schema=False,
            )
        except PortfolioGraphError:
            reasons.append("GRAPH_EVALUATION_FAILED")
        else:
            projection = next(
                (node for node in evaluation["nodes"] if int(node["issue_number"]) == issue_number),
                None,
            )
            if projection is None or not projection["structurally_ready"]:
                reasons.append("DEPENDENCY_NOT_READY")
    endpoint_id = campaign.get("endpoint_id") if isinstance(campaign, dict) else campaign["endpoint_id"]
    if endpoint_id is not None:
        endpoint = current_endpoint(connection, str(campaign["worker_role"]))
        if endpoint is None or endpoint["endpoint_id"] != endpoint_id:
            reasons.append("ENDPOINT_DRIFT")
    approval: dict[str, Any] | None = None
    if isinstance(campaign, dict):
        transition = campaign.get("transition")
        if isinstance(transition, dict):
            candidate_approval = transition.get("approval")
            if isinstance(candidate_approval, dict):
                approval = candidate_approval
    elif (
        "transition_kind" in campaign.keys()
        and campaign["approval_proposal_sha256"] is not None
    ):
        approval = {
            "proposal_sha256": campaign["approval_proposal_sha256"],
            "decision_sha256": campaign["approval_decision_sha256"],
            "recipient_session_id": campaign["approval_recipient_session_id"],
            "execution_scope_sha256": campaign[
                "approval_execution_scope_sha256"
            ],
        }
    if approval is not None:
        planner = current_endpoint(connection, "planner")
        boundary = connection.execute(
            "SELECT boundary FROM approval_proposals WHERE proposal_sha256=?",
            (approval["proposal_sha256"],),
        ).fetchone()
        if planner is None or boundary is None:
            reasons.append("APPROVAL_AUTHORITY_MISSING")
        else:
            try:
                require_effective_approval(
                    connection,
                    repository=repository,
                    issue_number=issue_number,
                    recipient_session_id=str(approval["recipient_session_id"]),
                    actor_session_id=str(planner["endpoint_id"]),
                    execution_scope_sha256=str(
                        approval["execution_scope_sha256"]
                    ),
                    authority_sha256=str(approval["decision_sha256"]),
                    required_proposal_sha256=str(approval["proposal_sha256"]),
                    required_workstream="READINESS",
                    required_boundary=str(boundary["boundary"]),
                    required_current_recipient_role="planner",
                    required=True,
                )
            except ApprovalGuardError as exc:
                reasons.append("APPROVAL_AUTHORITY_" + str(exc))
    return sorted(set(reasons))


def discover(
    connection: sqlite3.Connection, repository: str, *, limit: int
) -> dict[str, Any]:
    """Rank zero-WIP DAG-ready candidates; parallelism is across candidates."""

    if limit <= 0:
        raise ReadinessError("READINESS_LIMIT_INVALID")
    require_schema(connection)
    _require_pull_buffer_schema(connection)
    graph = connection.execute(
        "SELECT * FROM portfolio_graph_current WHERE repository=?", (repository,)
    ).fetchone()
    if graph is None or graph["health"] != "CURRENT":
        raise ReadinessError("GRAPH_STALE")
    evaluation = evaluate_graph(
        connection,
        repository,
        current_main=str(graph["observed_main_sha"]),
        _ensure_schema=False,
    )
    nodes = {
        row["node_key"]: row
        for row in connection.execute(
            "SELECT * FROM portfolio_graph_nodes WHERE repository=? AND graph_version=?",
            (repository, int(graph["version"])),
        )
    }
    collisions = {
        frozenset((row["left_node_key"], row["right_node_key"]))
        for row in connection.execute(
            """
            SELECT * FROM portfolio_graph_relations
            WHERE repository=? AND graph_version=? AND relation_kind='COLLISION'
            """,
            (repository, int(graph["version"])),
        )
    }
    occupied = {
        row["node_key"]
        for row in connection.execute(
            """
            SELECT node.node_key FROM portfolio_graph_nodes node
            JOIN coordination_items item
              ON item.repository=node.repository AND item.issue_number=node.issue_number
            WHERE node.repository=? AND node.graph_version=?
              AND item.allocation_class IN ('ACTIVE','RETAINED')
            """,
            (repository, int(graph["version"])),
        )
    }
    projections = {
        item["node_key"]: item
        for item in evaluation["nodes"]
        if item["structurally_ready"] and item["item_status"] == "PREPARED"
    }
    ordered = sorted(
        projections,
        key=lambda key: (
            int(nodes[key]["priority_rank"]),
            str(nodes[key]["ready_at"]),
            int(nodes[key]["lane_order"]),
            -int(projections[key]["critical_path_units"]),
            -int(projections[key]["immediate_unlocks"]),
            -int(projections[key]["descendant_count"]),
            key,
        ),
    )
    selected: list[dict[str, Any]] = []
    selected_keys: set[str] = set()
    skipped: list[dict[str, Any]] = []
    for key in ordered:
        node = nodes[key]
        candidate = connection.execute(
            """
            SELECT candidate.* FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates candidate ON candidate.id=pointer.candidate_id
            WHERE pointer.repository=? AND pointer.issue_number=?
            """,
            (repository, int(node["issue_number"])),
        ).fetchone()
        reason = None
        if candidate is None or candidate["state"] != "PREPARED_NOT_READY":
            reason = "PREPARED_CANDIDATE_MISSING"
        elif any(frozenset((key, other)) in collisions for other in occupied | selected_keys):
            reason = "COLLISION"
        if reason is not None:
            skipped.append({"node_key": key, "reason": reason})
            continue
        current = connection.execute(
            """
            SELECT campaign.plan_sha256, pointer.state
            FROM portfolio_readiness_current pointer
            JOIN portfolio_readiness_campaigns campaign ON campaign.id=pointer.campaign_id
            WHERE pointer.repository=? AND pointer.issue_number=?
            """,
            (repository, int(node["issue_number"])),
        ).fetchone()
        selected.append(
            {
                "node_key": key,
                "issue_number": int(node["issue_number"]),
                "lane_key": node["lane_key"],
                "priority_rank": int(node["priority_rank"]),
                "item_status": projections[key]["item_status"],
                "candidate_sha256": candidate["candidate_sha256"],
                "campaign": None if current is None else dict(current),
            }
        )
        selected_keys.add(key)
        if len(selected) >= limit:
            break
    return {
        "repository": repository,
        "graph_version": int(graph["version"]),
        "accepted_main_sha": graph["observed_main_sha"],
        "selected": selected,
        "skipped": skipped,
    }


def _register_locked(
    connection: sqlite3.Connection,
    plan: dict[str, Any],
    *,
    now: str,
    approval_verified: bool,
    resolution_verified: bool = False,
) -> dict[str, Any]:
    """Register one initial or explicitly fenced successor while holding BEGIN IMMEDIATE."""

    if not connection.in_transaction:
        raise ReadinessError("READINESS_TRANSACTION_REQUIRED")
    plan_sha = digest_json(plan)
    prior = connection.execute(
        """
        SELECT current.*, campaign.plan_sha256 AS current_plan_sha256,
               campaign.generation AS current_generation,
               campaign.resolution_ordinal AS campaign_resolution_ordinal
        FROM portfolio_readiness_current current
        JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
        WHERE current.repository=? AND current.issue_number=?
        """,
        (plan["repository"], plan["issue_number"]),
    ).fetchone()
    existing = connection.execute(
        "SELECT * FROM portfolio_readiness_campaigns WHERE plan_sha256=?",
        (plan_sha,),
    ).fetchone()
    if existing is not None:
        if prior is not None and int(prior["campaign_id"]) == int(existing["id"]):
            return {
                "repository": plan["repository"],
                "issue_number": int(plan["issue_number"]),
                "campaign_id": int(existing["id"]),
                "plan_sha256": plan_sha,
                "state": str(prior["state"]),
                "replay": True,
            }
        raise ReadinessError("READINESS_PLAN_REPLAY_CONFLICT")

    transition = plan.get("transition")
    parent_campaign_id: int | None = None
    transition_kind = "INITIAL"
    resolution_ordinal = 0
    changed_evidence_sha256: str | None = None
    resolution_action_set_sha256: str | None = None
    approval: dict[str, Any] | None = None
    if prior is None:
        if plan["schema"] != PLAN_SCHEMA:
            raise ReadinessError("READINESS_INITIAL_PLAN_REQUIRED")
    else:
        if plan["schema"] != SUCCESSOR_PLAN_SCHEMA or not isinstance(transition, dict):
            raise ReadinessError("READINESS_SUCCESSOR_FENCE_REQUIRED")
        parent_campaign_id = int(transition["parent_campaign_id"])
        transition_kind = str(transition["kind"])
        changed_evidence_sha256 = str(transition["changed_evidence_sha256"])
        resolution_action_set_sha256 = transition.get(
            "resolution_action_set_sha256"
        )
        approval = transition.get("approval")
        if (
            parent_campaign_id != int(prior["campaign_id"])
            or int(transition["expected_parent_version"]) != int(prior["version"])
        ):
            raise ReadinessError("READINESS_SUCCESSOR_FENCE_LOST")
        expected_state = {
            "RESOLUTION": "RESOLUTION_PENDING",
            "REFRESH": "STALE",
            "APPROVAL_RESUME": "APPROVAL_PENDING",
        }[transition_kind]
        if prior["state"] != expected_state:
            raise ReadinessError("READINESS_SUCCESSOR_STATE_CONFLICT")
        if approval is not None and not approval_verified:
            raise ReadinessError("READINESS_EFFECTIVE_APPROVAL_REQUIRED")
        if approval is None and approval_verified:
            raise ReadinessError("READINESS_TRANSITION_INVALID")
        if transition_kind == "RESOLUTION" and not resolution_verified:
            raise ReadinessError("READINESS_RESOLUTION_HANDLER_REQUIRED")
        if transition_kind != "RESOLUTION" and resolution_verified:
            raise ReadinessError("READINESS_TRANSITION_INVALID")
        if transition_kind == "RESOLUTION":
            receipt_binding = connection.execute(
                "SELECT resolution_action_set_sha256 "
                "FROM portfolio_readiness_receipts WHERE id=? AND campaign_id=?",
                (prior["receipt_id"], parent_campaign_id),
            ).fetchone()
            if (
                receipt_binding is None
                or receipt_binding["resolution_action_set_sha256"]
                != resolution_action_set_sha256
            ):
                raise ReadinessError("READINESS_RESOLUTION_ACTION_BINDING_INVALID")
        try:
            parent_plan = json.loads(
                connection.execute(
                    "SELECT plan_json FROM portfolio_readiness_campaigns WHERE id=?",
                    (parent_campaign_id,),
                ).fetchone()["plan_json"],
                object_pairs_hook=_strict_object,
            )
        except (TypeError, json.JSONDecodeError, KeyError) as exc:
            raise ReadinessError("READINESS_PARENT_PLAN_INVALID") from exc
        evidence = transition_evidence_payload(parent_plan, plan)
        material_fields = set(evidence["changed_fields"]) - {"phase_summary"}
        if transition_kind in {"RESOLUTION", "REFRESH"} and not material_fields:
            raise ReadinessError("READINESS_RESOLUTION_NO_CHANGE")
        if changed_evidence_sha256 != digest_json(evidence):
            raise ReadinessError("READINESS_CHANGED_EVIDENCE_MISMATCH")
        prior_ordinal = int(
            prior["campaign_resolution_ordinal"]
            if prior["campaign_resolution_ordinal"] is not None
            else prior["resolution_cycles"]
        )
        if int(plan["generation"]) > int(prior["current_generation"]):
            if transition_kind != "REFRESH":
                raise ReadinessError("READINESS_NEW_GENERATION_REFRESH_REQUIRED")
            resolution_ordinal = 0
        else:
            if int(plan["generation"]) != int(prior["current_generation"]):
                raise ReadinessError("READINESS_GENERATION_REGRESSION")
            resolution_ordinal = prior_ordinal + (
                1 if transition_kind == "RESOLUTION" else 0
            )
        if resolution_ordinal > MAX_RESOLUTION_CYCLES:
            raise ReadinessError("READINESS_RESOLUTION_CYCLE_LIMIT")
        if plan_sha == prior["current_plan_sha256"]:
            raise ReadinessError("READINESS_RESOLUTION_NO_CHANGE")

    binding = {**plan, "id": -1, "endpoint_id": None}
    reasons = _binding_reasons(connection, binding)
    if reasons:
        raise ReadinessError("READINESS_BINDING_DRIFT:" + ",".join(reasons))
    connection.execute(
        """
        INSERT INTO portfolio_readiness_campaigns(
            repository, issue_number, generation, item_version,
            source_payload_sha256, accepted_main_sha, graph_version,
            capacity_policy_version, candidate_sha256, worker_role,
            phase_summary, plan_sha256, plan_json, parent_campaign_id,
            transition_kind, resolution_ordinal, changed_evidence_sha256,
            resolution_action_set_sha256,
            approval_proposal_sha256, approval_decision_sha256,
            approval_recipient_session_id, approval_execution_scope_sha256,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            plan["repository"], plan["issue_number"], plan["generation"],
            plan["item_version"], plan["source_payload_sha256"],
            plan["accepted_main_sha"], plan["graph_version"],
            plan["capacity_policy_version"], plan["candidate_sha256"],
            plan["worker_role"], plan["phase_summary"], plan_sha,
            canonical_json(plan), parent_campaign_id, transition_kind,
            resolution_ordinal, changed_evidence_sha256,
            resolution_action_set_sha256,
            None if approval is None else approval["proposal_sha256"],
            None if approval is None else approval["decision_sha256"],
            None if approval is None else approval["recipient_session_id"],
            None if approval is None else approval["execution_scope_sha256"], now,
        ),
    )
    campaign = connection.execute(
        "SELECT * FROM portfolio_readiness_campaigns WHERE plan_sha256=?", (plan_sha,)
    ).fetchone()
    connection.execute(
        """
        INSERT INTO portfolio_readiness_current(
            repository, issue_number, campaign_id, state, resolution_cycles,
            version, updated_at
        ) VALUES (?, ?, ?, 'PENDING', ?, 1, ?)
        ON CONFLICT(repository, issue_number) DO UPDATE SET
            campaign_id=excluded.campaign_id, state='PENDING', message_id=NULL,
            attempt_id=NULL, endpoint_id=NULL, receipt_id=NULL,
            resolution_cycles=excluded.resolution_cycles,
            version=portfolio_readiness_current.version+1,
            updated_at=excluded.updated_at, last_error=NULL,
            finalized_candidate_id=NULL, finalized_event_id=NULL, finalized_at=NULL
        """,
        (
            plan["repository"], plan["issue_number"], int(campaign["id"]),
            resolution_ordinal, now,
        ),
    )
    for gate in plan["gates"]:
        connection.execute(
            """
            INSERT INTO portfolio_readiness_gates(
                campaign_id, gate_key, description, requested_evidence_json, gate_sha256
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(campaign["id"]), gate["gate_key"], gate["description"],
                canonical_json(gate["requested_evidence"]), digest_json(gate),
            ),
        )
    _event(
        connection,
        int(campaign["id"]),
        "READINESS_PHASE_REGISTERED",
        {
            "plan_sha256": plan_sha,
            "gate_count": len(plan["gates"]),
            "parent_campaign_id": parent_campaign_id,
            "transition_kind": transition_kind,
            "resolution_ordinal": resolution_ordinal,
            "resolution_action_set_sha256": resolution_action_set_sha256,
        },
        now,
    )
    return {
        "repository": plan["repository"],
        "issue_number": int(plan["issue_number"]),
        "campaign_id": int(campaign["id"]),
        "plan_sha256": plan_sha,
        "state": "PENDING",
        "resolution_ordinal": resolution_ordinal,
        "replay": False,
    }


def register(
    connection: sqlite3.Connection, plan: dict[str, Any], *, now: str
) -> dict[str, Any]:
    _validate_plan(plan)
    transition_kind = plan.get("transition", {}).get("kind")
    if transition_kind == "APPROVAL_RESUME":
        raise ReadinessError("READINESS_EFFECTIVE_APPROVAL_REQUIRED")
    if transition_kind == "RESOLUTION":
        raise ReadinessError("READINESS_RESOLUTION_HANDLER_REQUIRED")
    ensure_schema(connection)
    _require_pull_buffer_schema(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        result = _register_locked(
            connection, plan, now=now, approval_verified=False
        )
        connection.execute("COMMIT")
        return result
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def resume_after_approval(
    store: CoordinationStore, plan: dict[str, Any], *, now: str
) -> dict[str, Any]:
    """Reject caller-authored resumes; the exact decision notice owns this edge."""

    raise ReadinessError("READINESS_DECISION_HANDLER_REQUIRED")


def _parse_bound_json(raw: Any, error: str) -> dict[str, Any]:
    try:
        value = json.loads(str(raw), object_pairs_hook=_strict_object)
    except (TypeError, json.JSONDecodeError, ReadinessError) as exc:
        raise ReadinessError(error) from exc
    if not isinstance(value, dict) or canonical_json(value) != str(raw):
        raise ReadinessError(error)
    return value


def _resolution_notice_row(
    connection: sqlite3.Connection, message_id: int
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT notice.campaign_id AS resolution_campaign_id,
               notice.receipt_id AS resolution_receipt_id,
               notice.action_set_sha256 AS notice_action_set_sha256,
               notice.message_id, notice.routed_endpoint_id,
               notice.expected_readiness_version,
               message.state AS message_state,
               message.recipient_session_id AS message_recipient_session_id,
               message.claimed_by AS message_claimed_by,
               message.payload_sha256 AS message_payload_sha256,
               message.payload_json AS message_payload_json,
               current.state AS readiness_state,
               current.version AS readiness_version,
               current.campaign_id AS current_campaign_id,
               current.receipt_id AS current_receipt_id,
               current.resolution_cycles,
               campaign.repository, campaign.issue_number, campaign.generation,
               campaign.item_version, campaign.source_payload_sha256,
               campaign.accepted_main_sha, campaign.graph_version,
               campaign.capacity_policy_version, campaign.candidate_sha256,
               campaign.worker_role, campaign.plan_sha256, campaign.plan_json,
               campaign.resolution_ordinal,
               campaign.approval_proposal_sha256,
               campaign.approval_decision_sha256,
               campaign.approval_recipient_session_id,
               campaign.approval_execution_scope_sha256,
               receipt.verdict, receipt.message_id AS worker_message_id,
               receipt.receipt_sha256, receipt.receipt_json,
               receipt.resolution_action_set_sha256 AS receipt_action_set_sha256,
               context.context_sha256, context.context_json,
               context.acting_planner_session_id AS context_planner_session_id,
               context.claimed_at AS context_claimed_at,
               cycle.outcome AS cycle_outcome,
               cycle.successor_campaign_id AS cycle_successor_campaign_id,
               cycle.result_sha256 AS cycle_result_sha256,
               cycle.result_json AS cycle_result_json
        FROM portfolio_readiness_resolution_notices notice
        JOIN coordination_messages message ON message.id=notice.message_id
        JOIN portfolio_readiness_campaigns campaign
          ON campaign.id=notice.campaign_id
        JOIN portfolio_readiness_current current
          ON current.repository=campaign.repository
         AND current.issue_number=campaign.issue_number
        JOIN portfolio_readiness_receipts receipt
          ON receipt.id=notice.receipt_id
         AND receipt.campaign_id=notice.campaign_id
        LEFT JOIN portfolio_readiness_resolution_contexts context
          ON context.notice_message_id=notice.message_id
         AND context.campaign_id=notice.campaign_id
         AND context.receipt_id=notice.receipt_id
        LEFT JOIN portfolio_readiness_resolution_cycles cycle
          ON cycle.notice_message_id=notice.message_id
         AND cycle.parent_campaign_id=notice.campaign_id
         AND cycle.receipt_id=notice.receipt_id
        WHERE notice.message_id=?
        """,
        (message_id,),
    ).fetchone()
    if row is None:
        raise ReadinessError("READINESS_RESOLUTION_NOTICE_NOT_FOUND")
    return row


def _validate_resolution_notice_binding(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    planner_session_id: str,
    require_pending: bool,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    planner = current_endpoint(connection, "planner")
    if planner is None or planner["endpoint_id"] != planner_session_id:
        raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
    if (
        not identities_role_equivalent(
            connection, str(row["routed_endpoint_id"]), planner_session_id
        )
        or not identities_role_equivalent(
            connection, str(row["message_recipient_session_id"]), planner_session_id
        )
        or row["verdict"] != "ACTIONABLE_HOLD"
        or row["notice_action_set_sha256"] != row["receipt_action_set_sha256"]
    ):
        raise ReadinessError("READINESS_RESOLUTION_BINDING_DRIFT")
    if require_pending:
        if (
            int(row["current_campaign_id"])
            != int(row["resolution_campaign_id"])
            or row["current_receipt_id"] is None
            or int(row["current_receipt_id"])
            != int(row["resolution_receipt_id"])
            or int(row["readiness_version"])
            != int(row["expected_readiness_version"])
        ):
            raise ReadinessError("READINESS_RESOLUTION_BINDING_DRIFT")
        if row["readiness_state"] != "RESOLUTION_PENDING":
            raise ReadinessError("READINESS_RESOLUTION_STATE_CONFLICT")
        if int(row["resolution_cycles"]) >= MAX_RESOLUTION_CYCLES:
            raise ReadinessError("READINESS_RESOLUTION_CYCLE_LIMIT")
    parent_plan = _parse_bound_json(
        row["plan_json"], "READINESS_PARENT_PLAN_INVALID"
    )
    receipt = _parse_bound_json(
        row["receipt_json"], "READINESS_RECEIPT_INVALID"
    )
    if (
        digest_json(parent_plan) != row["plan_sha256"]
        or digest_json(receipt) != row["receipt_sha256"]
        or receipt.get("readiness_plan_sha256") != row["plan_sha256"]
        or int(receipt.get("message_id", -1)) != int(row["worker_message_id"])
    ):
        raise ReadinessError("READINESS_RESOLUTION_BINDING_DRIFT")
    actions = _validate_resolution_actions(
        receipt.get("resolution", {}).get("actions"), "ACTIONABLE_HOLD"
    )
    if digest_json(actions) != row["notice_action_set_sha256"]:
        raise ReadinessError("READINESS_RESOLUTION_ACTION_BINDING_INVALID")
    message_payload = _parse_bound_json(
        row["message_payload_json"], "READINESS_RESOLUTION_NOTICE_INVALID"
    )
    evidence = message_payload.get("evidence")
    source = message_payload.get("source")
    if (
        digest_json(message_payload) != row["message_payload_sha256"]
        or not isinstance(evidence, dict)
        or not isinstance(source, dict)
        or source.get("repository") != row["repository"]
        or source.get("object_kind") != "issue"
        or source.get("object_number") != int(row["issue_number"])
        or source.get("payload_sha256") != row["source_payload_sha256"]
        or evidence.get("readiness_plan_sha256") != row["plan_sha256"]
        or evidence.get("readiness_receipt_sha256") != row["receipt_sha256"]
        or evidence.get("resolution_action_set_sha256")
        != row["notice_action_set_sha256"]
    ):
        raise ReadinessError("READINESS_RESOLUTION_NOTICE_INVALID")
    return parent_plan, receipt, actions


def _current_resolution_bindings(
    connection: sqlite3.Connection, row: sqlite3.Row
) -> tuple[dict[str, Any], dict[str, Any]]:
    repository = str(row["repository"])
    issue_number = int(row["issue_number"])
    source = connection.execute(
        "SELECT payload_sha256, source_updated_at, fetched_at FROM github_current "
        "WHERE repository=? AND object_kind='issue' AND object_number=?",
        (repository, issue_number),
    ).fetchone()
    item = connection.execute(
        "SELECT generation, version, source_payload_sha256, status, "
        "allocation_class, development_units, shared_units, sre_units "
        "FROM coordination_items WHERE repository=? AND issue_number=?",
        (repository, issue_number),
    ).fetchone()
    graph = connection.execute(
        """
        SELECT current.version, current.observed_main_sha, current.health,
               current.updated_at, current.last_error, revision.graph_sha256
        FROM portfolio_graph_current current
        LEFT JOIN portfolio_graph_revisions revision
          ON revision.repository=current.repository
         AND revision.version=current.version
        WHERE current.repository=?
        """,
        (repository,),
    ).fetchone()
    policy = connection.execute(
        "SELECT version FROM coordination_capacity_current WHERE repository=?",
        (repository,),
    ).fetchone()
    candidate = connection.execute(
        """
        SELECT candidate.* FROM portfolio_pull_buffer_current pointer
        JOIN portfolio_pull_buffer_candidates candidate
          ON candidate.id=pointer.candidate_id
        LEFT JOIN portfolio_pull_buffer_retirements retirement
          ON retirement.candidate_id=candidate.id
        WHERE pointer.repository=? AND pointer.issue_number=?
          AND retirement.candidate_id IS NULL
        """,
        (repository, issue_number),
    ).fetchone()
    if source is None or item is None or graph is None or policy is None or candidate is None:
        raise ReadinessError("READINESS_RESOLUTION_CONTEXT_BINDING_MISSING")
    prepared_candidate = {
        key: candidate[key]
        for key in (
            "id", "repository", "issue_number", "generation", "item_version",
            "source_payload_sha256", "accepted_main_sha", "graph_version",
            "capacity_policy_version", "lane_key", "state", "verticality",
            "development_units", "shared_units", "sre_units", "promotion_trigger",
            "artifact_relative_path", "artifact_content_sha256",
            "candidate_sha256", "registered_at",
        )
    }
    bindings = {
        "source": {
            "payload_sha256": source["payload_sha256"],
            "source_updated_at": source["source_updated_at"],
            "fetched_at": source["fetched_at"],
        },
        "item": {
            key: item[key]
            for key in (
                "generation", "version", "source_payload_sha256", "status",
                "allocation_class", "development_units", "shared_units",
                "sre_units",
            )
        },
        "graph": {
            "version": int(graph["version"]),
            "observed_main_sha": graph["observed_main_sha"],
            "health": graph["health"],
            "graph_sha256": graph["graph_sha256"],
            "updated_at": graph["updated_at"],
            "last_error": graph["last_error"],
        },
        "capacity_policy": {"version": int(policy["version"])},
        "candidate": {
            "id": int(candidate["id"]),
            "candidate_sha256": candidate["candidate_sha256"],
            "state": candidate["state"],
        },
    }
    return prepared_candidate, bindings


def _resolution_action_observation(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    action: dict[str, Any],
) -> dict[str, Any]:
    repository = str(row["repository"])
    issue_number = int(row["issue_number"])
    kind = str(action["kind"])
    if kind == "REFRESH_SOURCE_SNAPSHOT":
        source = connection.execute(
            "SELECT payload_sha256,source_updated_at,fetched_at FROM github_current "
            "WHERE repository=? AND object_kind='issue' AND object_number=?",
            (repository, issue_number),
        ).fetchone()
        item = connection.execute(
            "SELECT generation,version,source_payload_sha256,status,"
            "allocation_class,development_units,shared_units,sre_units "
            "FROM coordination_items WHERE repository=? AND issue_number=?",
            (repository, issue_number),
        ).fetchone()
        observed_digest = None if source is None else source["payload_sha256"]
        binding = {
            "source_payload_sha256": observed_digest,
            "source_updated_at": None if source is None else source["source_updated_at"],
            "source_fetched_at": None if source is None else source["fetched_at"],
            "item_source_payload_sha256": (
                None if item is None else item["source_payload_sha256"]
            ),
            "item_generation": None if item is None else int(item["generation"]),
            "item_version": None if item is None else int(item["version"]),
            "item_status": None if item is None else item["status"],
            "item_allocation_class": (
                None if item is None else item["allocation_class"]
            ),
            "development_units": (
                None if item is None else int(item["development_units"])
            ),
            "shared_units": None if item is None else int(item["shared_units"]),
            "sre_units": None if item is None else int(item["sre_units"]),
        }
    elif kind == "RECOMPUTE_DEPENDENCY_GRAPH":
        graph = connection.execute(
            """
            SELECT current.version, current.observed_main_sha, current.health,
                   revision.graph_sha256
            FROM portfolio_graph_current current
            LEFT JOIN portfolio_graph_revisions revision
              ON revision.repository=current.repository
             AND revision.version=current.version
            WHERE current.repository=?
            """,
            (repository,),
        ).fetchone()
        observed_digest = None if graph is None else graph["graph_sha256"]
        binding = {
            "graph_sha256": observed_digest,
            "graph_version": None if graph is None else int(graph["version"]),
            "accepted_main_sha": (
                None if graph is None else graph["observed_main_sha"]
            ),
            "health": None if graph is None else graph["health"],
        }
    elif kind == "REBUILD_PREPARED_CANDIDATE":
        candidate = connection.execute(
            """
            SELECT candidate.* FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=pointer.candidate_id
            LEFT JOIN portfolio_pull_buffer_retirements retirement
              ON retirement.candidate_id=candidate.id
            WHERE pointer.repository=? AND pointer.issue_number=?
              AND retirement.candidate_id IS NULL
            """,
            (repository, issue_number),
        ).fetchone()
        observed_digest = (
            None if candidate is None else candidate["candidate_sha256"]
        )
        binding = {
            "candidate_id": None if candidate is None else int(candidate["id"]),
            "candidate_sha256": observed_digest,
            "state": None if candidate is None else candidate["state"],
            "generation": (
                None if candidate is None else int(candidate["generation"])
            ),
            "item_version": (
                None if candidate is None else int(candidate["item_version"])
            ),
            "source_payload_sha256": (
                None if candidate is None else candidate["source_payload_sha256"]
            ),
            "accepted_main_sha": (
                None if candidate is None else candidate["accepted_main_sha"]
            ),
            "graph_version": (
                None if candidate is None else int(candidate["graph_version"])
            ),
            "capacity_policy_version": (
                None
                if candidate is None
                else int(candidate["capacity_policy_version"])
            ),
        }
    else:
        raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
    return {
        "kind": kind,
        "target": action["target"],
        "action_sha256": digest_json(action),
        "observed_digest": observed_digest,
        "binding": binding,
        "binding_sha256": digest_json(binding),
    }


def _resolution_observation_matches(
    observation: dict[str, Any], expected_digest: str
) -> bool:
    binding = observation["binding"]
    kind = observation["kind"]
    if observation["observed_digest"] != expected_digest:
        return False
    if kind == "REFRESH_SOURCE_SNAPSHOT":
        return bool(
            binding["item_source_payload_sha256"] == expected_digest
            and binding["item_status"] == "PREPARED"
            and binding["item_allocation_class"] == "NONE"
        )
    if kind == "RECOMPUTE_DEPENDENCY_GRAPH":
        return binding["health"] == "CURRENT"
    if kind == "REBUILD_PREPARED_CANDIDATE":
        return binding["state"] == "PREPARED_NOT_READY"
    return False


def _resolution_action_start_matches(
    observation: dict[str, Any], expected_digest: str
) -> bool:
    """Fence the frozen target while allowing an ordered prerequisite effect."""

    if observation["observed_digest"] != expected_digest:
        return False
    if observation["kind"] == "RECOMPUTE_DEPENDENCY_GRAPH":
        # A preceding source refresh deliberately makes the still-exact frozen
        # graph revision stale before the graph owner API replaces it.
        return True
    return _resolution_observation_matches(observation, expected_digest)


def _resolution_action_start_receipt(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    actions: list[dict[str, Any]],
    action_index: int,
) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
    action = actions[action_index]
    action_sha256 = digest_json(action)
    start = connection.execute(
        "SELECT * FROM portfolio_readiness_resolution_action_starts "
        "WHERE notice_message_id=? AND action_sha256=?",
        (int(row["message_id"]), action_sha256),
    ).fetchone()
    completion = connection.execute(
        "SELECT * FROM portfolio_readiness_resolution_action_completions "
        "WHERE notice_message_id=? AND action_sha256=?",
        (int(row["message_id"]), action_sha256),
    ).fetchone()
    if start is not None and (
        int(start["action_index"]) != action_index
        or int(start["campaign_id"]) != int(row["resolution_campaign_id"])
        or int(start["receipt_id"]) != int(row["resolution_receipt_id"])
        or start["context_sha256"] != row["context_sha256"]
        or start["kind"] != action["kind"]
        or start["target"] != action["target"]
        or start["expected_digest"] != action["expected_digest"]
        or start["desired_digest"] != action["desired_digest"]
    ):
        raise ReadinessError("READINESS_RESOLUTION_ACTION_RECEIPT_CONFLICT")
    if completion is not None and (
        start is None
        or completion["context_sha256"] != row["context_sha256"]
    ):
        raise ReadinessError("READINESS_RESOLUTION_ACTION_RECEIPT_CONFLICT")
    return start, completion


def _require_resolution_action_predecessors(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    actions: list[dict[str, Any]],
    action_index: int,
) -> None:
    """Require each frozen predecessor receipt and its durable owner effect."""

    current = actions[action_index]
    for predecessor_index, predecessor in enumerate(actions[:action_index]):
        start, completion = _resolution_action_start_receipt(
            connection, row, actions, predecessor_index
        )
        if start is None:
            raise ReadinessError("READINESS_RESOLUTION_ACTION_ORDER_REQUIRED")
        source_to_graph = (
            predecessor["kind"] == "REFRESH_SOURCE_SNAPSHOT"
            and current["kind"] == "RECOMPUTE_DEPENDENCY_GRAPH"
        )
        if not source_to_graph and completion is None:
            raise ReadinessError("READINESS_RESOLUTION_ACTION_ORDER_REQUIRED")
        observation = _resolution_action_observation(
            connection, row, predecessor
        )
        if source_to_graph:
            if observation["observed_digest"] != predecessor["desired_digest"]:
                raise ReadinessError(
                    "READINESS_RESOLUTION_ACTION_PREREQUISITE_EFFECT_MISSING"
                )
        elif not _resolution_observation_matches(
            observation, str(predecessor["desired_digest"])
        ):
            raise ReadinessError(
                "READINESS_RESOLUTION_ACTION_PREREQUISITE_DRIFT"
            )


def _source_graph_completion_required(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    actions: list[dict[str, Any]],
    source_index: int,
) -> bool:
    """Return whether a frozen downstream graph effect is still incomplete."""

    for graph_index in range(source_index + 1, len(actions)):
        graph = actions[graph_index]
        if graph["kind"] != "RECOMPUTE_DEPENDENCY_GRAPH":
            continue
        start, completion = _resolution_action_start_receipt(
            connection, row, actions, graph_index
        )
        if start is None or completion is None:
            return True
        observation = _resolution_action_observation(connection, row, graph)
        if not _resolution_observation_matches(
            observation, str(graph["desired_digest"])
        ):
            raise ReadinessError(
                "READINESS_RESOLUTION_ACTION_PREREQUISITE_DRIFT"
            )
        return False
    return False


def _resolution_context_payload(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    parent_plan: dict[str, Any],
    actions: list[dict[str, Any]],
    *,
    planner_session_id: str,
    claimed_at: str,
) -> dict[str, Any]:
    prepared_candidate, bindings = _current_resolution_bindings(connection, row)
    target_preconditions = [
        _resolution_action_observation(connection, row, action)
        for action in actions
    ]
    approval_values = {
        "proposal_sha256": row["approval_proposal_sha256"],
        "decision_sha256": row["approval_decision_sha256"],
        "recipient_session_id": row["approval_recipient_session_id"],
        "execution_scope_sha256": row["approval_execution_scope_sha256"],
    }
    frozen_approval = (
        None if all(value is None for value in approval_values.values()) else approval_values
    )
    return {
        "schema": READINESS_RESOLUTION_CONTEXT_SCHEMA,
        "repository": row["repository"],
        "issue_number": int(row["issue_number"]),
        "campaign": {
            "campaign_id": int(row["resolution_campaign_id"]),
            "current_version": int(row["readiness_version"]),
            "generation": int(row["generation"]),
            "item_version": int(row["item_version"]),
            "resolution_ordinal": int(row["resolution_ordinal"]),
            "resolution_cycles": int(row["resolution_cycles"]),
            "state": row["readiness_state"],
            "plan_sha256": row["plan_sha256"],
        },
        "parent_plan": parent_plan,
        "parent_plan_json": canonical_json(parent_plan),
        "prepared_candidate": prepared_candidate,
        "receipt": {
            "receipt_id": int(row["resolution_receipt_id"]),
            "receipt_sha256": row["receipt_sha256"],
        },
        "action_set": {
            "actions": actions,
            "actions_json": canonical_json(actions),
            "action_set_sha256": row["notice_action_set_sha256"],
        },
        "current_bindings": bindings,
        "target_preconditions": target_preconditions,
        "frozen_approval_reference": frozen_approval,
        "planner_notice": {
            "message_id": int(row["message_id"]),
            "payload_sha256": row["message_payload_sha256"],
            "routed_endpoint_id": row["routed_endpoint_id"],
            "expected_readiness_version": int(
                row["expected_readiness_version"]
            ),
        },
        "execution": {
            "mode": "BROKER_MEDIATED_PREREQUISITE",
            "direct_database_authority": False,
            "handlers": [
                {
                    "kind": action["kind"],
                    "owner_api": RESOLUTION_ACTION_REGISTRY[action["kind"]][
                        "owner_api"
                    ],
                }
                for action in actions
            ],
        },
        "planner_claim": {
            "acting_planner_session_id": planner_session_id,
            "claimed_at": claimed_at,
        },
        "claim_outcome": None,
    }


def claim_readiness_resolution_context(
    store: CoordinationStore,
    *,
    message_id: int,
    planner_session_id: str,
    now: str,
) -> dict[str, Any]:
    """Claim one exact Planner notice and return its complete cold context."""

    if type(message_id) is not int or message_id <= 0:
        raise ReadinessError("READINESS_RESOLUTION_NOTICE_INVALID")
    ensure_schema(store.connection)
    _require_pull_buffer_schema(store.connection)
    with store.transaction():
        row = _resolution_notice_row(store.connection, message_id)
        parent_plan, _receipt, actions = _validate_resolution_notice_binding(
            store.connection,
            row,
            planner_session_id=planner_session_id,
            require_pending=row["cycle_result_json"] is None,
        )
        if row["context_json"] is not None:
            context = _parse_bound_json(
                row["context_json"], "READINESS_RESOLUTION_CONTEXT_INVALID"
            )
            if digest_json(context) != row["context_sha256"]:
                raise ReadinessError("READINESS_RESOLUTION_CONTEXT_INVALID")
            if row["message_state"] not in {"CLAIMED", "COMPLETE"} or (
                row["message_claimed_by"] is None
                or not identities_role_equivalent(
                    store.connection,
                    str(row["message_claimed_by"]),
                    planner_session_id,
                )
            ):
                raise ReadinessError("READINESS_RESOLUTION_CONTEXT_CLAIM_INVALID")
            return {
                **context,
                "context_sha256": row["context_sha256"],
                "replay": True,
            }
        claimed = store.claim_readiness_resolution_message_in_transaction(
            message_id, planner_session_id, now
        )
        if claimed["state"] != "CLAIMED":
            raise ReadinessError("READINESS_RESOLUTION_MESSAGE_CLAIM_FAILED")
        context = _resolution_context_payload(
            store.connection,
            row,
            parent_plan,
            actions,
            planner_session_id=planner_session_id,
            claimed_at=now,
        )
        mismatched_targets = [
            action["kind"]
            for action, observation in zip(
                actions, context["target_preconditions"], strict=True
            )
            if not _resolution_observation_matches(
                observation, str(action["expected_digest"])
            )
        ]
        if mismatched_targets:
            context["claim_outcome"] = {
                "outcome": "HOLD",
                "disposition": "TERMINAL_HOLD",
                "reason": (
                    "READINESS_RESOLUTION_EVIDENCE_PRECLAIM_TARGET_DRIFT:"
                    + ",".join(mismatched_targets)
                ),
            }
        context_sha256 = digest_json(context)
        store.connection.execute(
            """
            INSERT INTO portfolio_readiness_resolution_contexts(
                notice_message_id, campaign_id, receipt_id,
                action_set_sha256, context_sha256, context_json,
                acting_planner_session_id, claimed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_id, int(row["resolution_campaign_id"]),
                int(row["resolution_receipt_id"]),
                row["notice_action_set_sha256"], context_sha256,
                canonical_json(context), planner_session_id, now,
            ),
        )
        _event(
            store.connection,
            int(row["resolution_campaign_id"]),
            "READINESS_RESOLUTION_CONTEXT_CLAIMED",
            {
                "message_id": message_id,
                "context_sha256": context_sha256,
                "action_set_sha256": row["notice_action_set_sha256"],
            },
            now,
        )
        if mismatched_targets:
            reason = str(context["claim_outcome"]["reason"])
            changed = store.connection.execute(
                "UPDATE portfolio_readiness_current SET state='HOLD', "
                "version=version+1, updated_at=?, last_error=? "
                "WHERE campaign_id=? AND receipt_id=? "
                "AND state='RESOLUTION_PENDING' AND version=?",
                (
                    now, reason, int(row["resolution_campaign_id"]),
                    int(row["resolution_receipt_id"]),
                    int(row["expected_readiness_version"]),
                ),
            ).rowcount
            if changed != 1:
                raise ReadinessError("READINESS_RESOLUTION_FENCE_LOST")
            failure = {
                "schema": READINESS_RESOLUTION_FAILURE_SCHEMA,
                "parent_campaign_id": int(row["resolution_campaign_id"]),
                "notice_message_id": message_id,
                "action_set_sha256": row["notice_action_set_sha256"],
                "context_sha256": context_sha256,
                "reason": reason,
            }
            changed_evidence_sha256 = digest_json(failure)
            result = {
                "schema": READINESS_RESOLUTION_RESULT_SCHEMA,
                "repository": row["repository"],
                "issue_number": int(row["issue_number"]),
                "parent_campaign_id": int(row["resolution_campaign_id"]),
                "successor_campaign_id": None,
                "outcome": "HOLD",
                "disposition": "TERMINAL_HOLD",
                "reason": reason,
                "action_set_sha256": row["notice_action_set_sha256"],
                "changed_evidence_sha256": changed_evidence_sha256,
                "context_sha256": context_sha256,
            }
            _insert_resolution_cycle(
                store.connection,
                row,
                context_sha256=context_sha256,
                changed_evidence_sha256=changed_evidence_sha256,
                outcome="HOLD",
                successor_campaign_id=None,
                disposition_reason=reason,
                acting_planner_session_id=planner_session_id,
                result=result,
                now=now,
            )
            store.complete_readiness_resolution_message_in_transaction(
                message_id, planner_session_id, now
            )
            _event(
                store.connection,
                int(row["resolution_campaign_id"]),
                "READINESS_RESOLUTION_PRECLAIM_HELD",
                result,
                now,
            )
    return {**context, "context_sha256": context_sha256, "replay": False}


def execute_readiness_resolution_action(
    store: CoordinationStore,
    *,
    message_id: int,
    planner_session_id: str,
    expected_context_sha256: str,
    action_sha256: str,
    expected_digest: str,
    action_input: dict[str, Any],
    now: str,
) -> dict[str, Any]:
    """Run one frozen action through its owner API and receipt both sides."""

    if (
        type(message_id) is not int
        or message_id <= 0
        or not isinstance(expected_context_sha256, str)
        or SHA256.fullmatch(expected_context_sha256) is None
        or not isinstance(action_sha256, str)
        or SHA256.fullmatch(action_sha256) is None
        or not isinstance(expected_digest, str)
        or SHA256.fullmatch(expected_digest) is None
        or not isinstance(action_input, dict)
    ):
        raise ReadinessError("READINESS_RESOLUTION_ACTION_CALL_INVALID")
    ensure_schema(store.connection)
    _require_pull_buffer_schema(store.connection)
    action_input_sha256 = digest_json(action_input)
    execute_owner = True
    source_effect_already_applied = False
    start_before_binding: dict[str, Any]
    start_binding_sha256: str
    with store.transaction():
        row = _resolution_notice_row(store.connection, message_id)
        _parent_plan, _receipt, actions = _validate_resolution_notice_binding(
            store.connection,
            row,
            planner_session_id=planner_session_id,
            require_pending=True,
        )
        if (
            row["context_sha256"] != expected_context_sha256
            or row["context_json"] is None
            or row["message_state"] != "CLAIMED"
            or row["message_claimed_by"] is None
            or not identities_role_equivalent(
                store.connection,
                str(row["message_claimed_by"]),
                planner_session_id,
            )
        ):
            raise ReadinessError("READINESS_RESOLUTION_CONTEXT_CLAIM_INVALID")
        matches = [
            (index, action)
            for index, action in enumerate(actions)
            if digest_json(action) == action_sha256
        ]
        if len(matches) != 1:
            raise ReadinessError("READINESS_RESOLUTION_ACTION_IDENTITY_INVALID")
        action_index, action = matches[0]
        if action["expected_digest"] != expected_digest:
            raise ReadinessError("READINESS_RESOLUTION_ACTION_EXPECTED_DRIFT")
        _require_resolution_action_predecessors(
            store.connection, row, actions, action_index
        )
        observation = _resolution_action_observation(
            store.connection, row, action
        )
        start, completion = _resolution_action_start_receipt(
            store.connection, row, actions, action_index
        )
        source_effect_already_applied = (
            action["kind"] == "REFRESH_SOURCE_SNAPSHOT"
            and observation["observed_digest"] == action["desired_digest"]
        )
        if start is None:
            if not _resolution_action_start_matches(
                observation, expected_digest
            ):
                raise ReadinessError(
                    "READINESS_RESOLUTION_ACTION_EXPECTED_DRIFT"
                )
            store.connection.execute(
                """
                INSERT INTO portfolio_readiness_resolution_action_starts(
                    notice_message_id, action_sha256, action_index,
                    campaign_id, receipt_id, context_sha256, kind, target,
                    expected_digest, desired_digest, action_input_sha256,
                    before_binding_sha256, before_binding_json,
                    acting_planner_session_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id, action_sha256, action_index,
                    int(row["resolution_campaign_id"]),
                    int(row["resolution_receipt_id"]), expected_context_sha256,
                    action["kind"], action["target"], action["expected_digest"],
                    action["desired_digest"], action_input_sha256,
                    observation["binding_sha256"],
                    canonical_json(observation["binding"]),
                    planner_session_id, now,
                ),
            )
            start_before_binding = observation["binding"]
            start_binding_sha256 = observation["binding_sha256"]
        else:
            if (
                int(start["action_index"]) != action_index
                or int(start["campaign_id"])
                != int(row["resolution_campaign_id"])
                or int(start["receipt_id"])
                != int(row["resolution_receipt_id"])
                or start["context_sha256"] != expected_context_sha256
                or start["kind"] != action["kind"]
                or start["target"] != action["target"]
                or start["expected_digest"] != expected_digest
                or start["desired_digest"] != action["desired_digest"]
                or start["action_input_sha256"] != action_input_sha256
            ):
                raise ReadinessError(
                    "READINESS_RESOLUTION_ACTION_RECEIPT_CONFLICT"
                )
            start_before_binding = _parse_bound_json(
                start["before_binding_json"],
                "READINESS_RESOLUTION_ACTION_RECEIPT_INVALID",
            )
            if digest_json(start_before_binding) != start["before_binding_sha256"]:
                raise ReadinessError(
                    "READINESS_RESOLUTION_ACTION_RECEIPT_INVALID"
                )
            start_binding_sha256 = str(start["before_binding_sha256"])
            if completion is not None:
                if not _resolution_observation_matches(
                    observation, str(action["desired_digest"])
                ):
                    raise ReadinessError(
                        "READINESS_RESOLUTION_ACTION_AFTER_DRIFT"
                    )
                return {
                    "schema": READINESS_RESOLUTION_ACTION_RECEIPT_SCHEMA,
                    "message_id": message_id,
                    "context_sha256": expected_context_sha256,
                    "action_sha256": action_sha256,
                    "before_binding_sha256": start["before_binding_sha256"],
                    "after_binding_sha256": completion[
                        "after_binding_sha256"
                    ],
                    "state": "COMPLETE",
                    "replay": True,
                }
            execute_owner = not _resolution_observation_matches(
                observation, str(action["desired_digest"])
            )

    kind = str(action["kind"])
    if execute_owner:
        if kind == "REFRESH_SOURCE_SNAPSHOT":
            if set(action_input) != {
                "payload", "source_updated_at", "fetched_at"
            } or not isinstance(action_input["payload"], dict):
                raise ReadinessError("READINESS_RESOLUTION_ACTION_INPUT_INVALID")
            if digest_json(action_input["payload"]) != action["desired_digest"]:
                raise ReadinessError("READINESS_RESOLUTION_ACTION_INPUT_DRIFT")
            if not source_effect_already_applied:
                with store.transaction():
                    store.ingest_snapshot_in_transaction(
                        repository=str(row["repository"]),
                        object_kind="issue",
                        object_number=int(row["issue_number"]),
                        payload=action_input["payload"],
                        source_updated_at=str(action_input["source_updated_at"]),
                        fetched_at=str(action_input["fetched_at"]),
                        expected_payload_sha256=str(action["desired_digest"]),
                    )
            if _source_graph_completion_required(
                store.connection, row, actions, action_index
            ):
                return {
                    "schema": READINESS_RESOLUTION_ACTION_RECEIPT_SCHEMA,
                    "message_id": message_id,
                    "context_sha256": expected_context_sha256,
                    "action_sha256": action_sha256,
                    "before_binding_sha256": start_binding_sha256,
                    "after_binding_sha256": None,
                    "state": "WAITING_DEPENDENCY",
                    "replay": source_effect_already_applied,
                }
            try:
                store.set_issue_status(
                    repository=str(row["repository"]),
                    issue_number=int(row["issue_number"]),
                    status="PREPARED",
                    allocation_class="NONE",
                    generation=int(start_before_binding["item_generation"]),
                    accountable_session_id=None,
                    lease_manifest_sha256=None,
                    development_units=int(
                        start_before_binding["development_units"]
                    ),
                    shared_units=int(start_before_binding["shared_units"]),
                    sre_units=int(start_before_binding["sre_units"]),
                    expected_source_sha256=str(action["desired_digest"]),
                    expected_version=int(start_before_binding["item_version"]),
                    now=now,
                )
            except CoordinationError as exc:
                if str(exc) != "GRAPH_STALE":
                    raise ReadinessError(str(exc)) from exc
                return {
                    "schema": READINESS_RESOLUTION_ACTION_RECEIPT_SCHEMA,
                    "message_id": message_id,
                    "context_sha256": expected_context_sha256,
                    "action_sha256": action_sha256,
                    "before_binding_sha256": start_binding_sha256,
                    "after_binding_sha256": None,
                    "state": "WAITING_DEPENDENCY",
                    "replay": False,
                }
        elif kind == "RECOMPUTE_DEPENDENCY_GRAPH":
            if set(action_input) != {"plan"} or not isinstance(
                action_input["plan"], dict
            ):
                raise ReadinessError("READINESS_RESOLUTION_ACTION_INPUT_INVALID")
            graph_payload = {
                key: action_input["plan"].get(key)
                for key in (
                    "repository", "scope_milestones", "excluded_issues",
                    "nodes", "relations",
                )
            }
            if digest_json(graph_payload) != action["desired_digest"]:
                raise ReadinessError("READINESS_RESOLUTION_ACTION_INPUT_DRIFT")
            try:
                replace_graph(store.connection, action_input["plan"], now=now)
            except PortfolioGraphError as exc:
                raise ReadinessError(str(exc)) from exc
        elif kind == "REBUILD_PREPARED_CANDIDATE":
            if set(action_input) != {"packet_path"} or not isinstance(
                action_input["packet_path"], str
            ):
                raise ReadinessError("READINESS_RESOLUTION_ACTION_INPUT_INVALID")
            from kanban_pull_buffer import PullBufferError, register_candidate

            try:
                candidate = register_candidate(
                    store.connection,
                    store.path,
                    Path(action_input["packet_path"]),
                    now=now,
                )
            except PullBufferError as exc:
                raise ReadinessError(str(exc)) from exc
            if candidate["candidate_sha256"] != action["desired_digest"]:
                raise ReadinessError("READINESS_RESOLUTION_ACTION_INPUT_DRIFT")
        else:
            raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")

    with store.transaction():
        latest = _resolution_notice_row(store.connection, message_id)
        _validate_resolution_notice_binding(
            store.connection,
            latest,
            planner_session_id=planner_session_id,
            require_pending=True,
        )
        if kind == "REFRESH_SOURCE_SNAPSHOT" and _source_graph_completion_required(
            store.connection, latest, actions, action_index
        ):
            raise ReadinessError("READINESS_RESOLUTION_ACTION_ORDER_REQUIRED")
        after = _resolution_action_observation(store.connection, latest, action)
        if not _resolution_observation_matches(
            after, str(action["desired_digest"])
        ):
            raise ReadinessError("READINESS_RESOLUTION_ACTION_AFTER_DRIFT")
        store.connection.execute(
            """
            INSERT INTO portfolio_readiness_resolution_action_completions(
                notice_message_id, action_sha256, context_sha256,
                after_binding_sha256, after_binding_json, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                message_id, action_sha256, expected_context_sha256,
                after["binding_sha256"], canonical_json(after["binding"]), now,
            ),
        )
        start = store.connection.execute(
            "SELECT before_binding_sha256 FROM "
            "portfolio_readiness_resolution_action_starts "
            "WHERE notice_message_id=? AND action_sha256=?",
            (message_id, action_sha256),
        ).fetchone()
    return {
        "schema": READINESS_RESOLUTION_ACTION_RECEIPT_SCHEMA,
        "message_id": message_id,
        "context_sha256": expected_context_sha256,
        "action_sha256": action_sha256,
        "before_binding_sha256": start_binding_sha256,
        "after_binding_sha256": after["binding_sha256"],
        "state": "COMPLETE",
        "replay": False,
    }


def _resolution_observations_and_successor(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    parent_plan: dict[str, Any],
    actions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    successor = {
        key: value
        for key, value in parent_plan.items()
        if key not in {"schema", "transition"}
    }
    observations: list[dict[str, Any]] = []
    repository = str(row["repository"])
    issue_number = int(row["issue_number"])
    for action_index, action in enumerate(actions):
        observation = _resolution_action_observation(connection, row, action)
        if not _resolution_observation_matches(
            observation, str(action["desired_digest"])
        ):
            raise ReadinessError(
                "READINESS_RESOLUTION_EVIDENCE_DRIFT:" + str(action["kind"])
            )
        action_sha256 = digest_json(action)
        receipt = connection.execute(
            """
            SELECT start.*, completion.context_sha256 AS completion_context_sha256,
                   completion.after_binding_sha256,
                   completion.after_binding_json, completion.completed_at
            FROM portfolio_readiness_resolution_action_starts start
            LEFT JOIN portfolio_readiness_resolution_action_completions completion
              USING(notice_message_id, action_sha256)
            WHERE start.notice_message_id=? AND start.action_sha256=?
            """,
            (int(row["message_id"]), action_sha256),
        ).fetchone()
        if receipt is None or receipt["after_binding_json"] is None:
            raise ReadinessError(
                "READINESS_RESOLUTION_EVIDENCE_ACTION_RECEIPT_INCOMPLETE"
            )
        try:
            before_binding = _parse_bound_json(
                receipt["before_binding_json"],
                "READINESS_RESOLUTION_EVIDENCE_ACTION_RECEIPT_INVALID",
            )
            after_binding = _parse_bound_json(
                receipt["after_binding_json"],
                "READINESS_RESOLUTION_EVIDENCE_ACTION_RECEIPT_INVALID",
            )
        except ReadinessError as exc:
            raise ReadinessError(
                "READINESS_RESOLUTION_EVIDENCE_ACTION_RECEIPT_INVALID"
            ) from exc
        if (
            int(receipt["action_index"]) != action_index
            or int(receipt["campaign_id"])
            != int(row["resolution_campaign_id"])
            or int(receipt["receipt_id"]) != int(row["resolution_receipt_id"])
            or receipt["context_sha256"] != row["context_sha256"]
            or receipt["completion_context_sha256"] != row["context_sha256"]
            or receipt["kind"] != action["kind"]
            or receipt["target"] != action["target"]
            or receipt["expected_digest"] != action["expected_digest"]
            or receipt["desired_digest"] != action["desired_digest"]
            or digest_json(before_binding) != receipt["before_binding_sha256"]
            or digest_json(after_binding) != receipt["after_binding_sha256"]
            or after_binding != observation["binding"]
        ):
            raise ReadinessError(
                "READINESS_RESOLUTION_EVIDENCE_ACTION_RECEIPT_INVALID"
            )
        binding = observation["binding"]
        kind = str(action["kind"])
        if kind == "REFRESH_SOURCE_SNAPSHOT":
            successor["source_payload_sha256"] = observation["observed_digest"]
            successor["generation"] = int(binding["item_generation"])
            successor["item_version"] = int(binding["item_version"])
        elif kind == "RECOMPUTE_DEPENDENCY_GRAPH":
            successor["accepted_main_sha"] = binding["accepted_main_sha"]
            successor["graph_version"] = int(binding["graph_version"])
        elif kind == "REBUILD_PREPARED_CANDIDATE":
            successor.update(
                {
                    "generation": int(binding["generation"]),
                    "item_version": int(binding["item_version"]),
                    "source_payload_sha256": binding["source_payload_sha256"],
                    "accepted_main_sha": binding["accepted_main_sha"],
                    "graph_version": int(binding["graph_version"]),
                    "capacity_policy_version": int(
                        binding["capacity_policy_version"]
                    ),
                    "candidate_sha256": observation["observed_digest"],
                }
            )
        observations.append(
            {
                **observation,
                "expected_digest": action["expected_digest"],
                "desired_digest": action["desired_digest"],
                "before_binding_sha256": receipt["before_binding_sha256"],
                "after_binding_sha256": receipt["after_binding_sha256"],
            }
        )
    counts = connection.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM portfolio_readiness_resolution_action_starts
           WHERE notice_message_id=?) AS starts,
          (SELECT COUNT(*) FROM portfolio_readiness_resolution_action_completions
           WHERE notice_message_id=?) AS completions
        """,
        (int(row["message_id"]), int(row["message_id"])),
    ).fetchone()
    if int(counts["starts"]) != len(actions) or int(counts["completions"]) != len(actions):
        raise ReadinessError(
            "READINESS_RESOLUTION_EVIDENCE_ACTION_RECEIPT_SET_INVALID"
        )
    frozen_approval_values = {
        "proposal_sha256": row["approval_proposal_sha256"],
        "decision_sha256": row["approval_decision_sha256"],
        "recipient_session_id": row["approval_recipient_session_id"],
        "execution_scope_sha256": row["approval_execution_scope_sha256"],
    }
    frozen_approval = (
        None
        if all(value is None for value in frozen_approval_values.values())
        else frozen_approval_values
    )
    if frozen_approval is not None and any(
        value is None for value in frozen_approval.values()
    ):
        raise ReadinessError("READINESS_RESOLUTION_EVIDENCE_APPROVAL_BINDING_DRIFT")
    successor.update(
        {
            "schema": SUCCESSOR_PLAN_SCHEMA,
            "transition": {
                "kind": "RESOLUTION",
                "parent_campaign_id": int(row["resolution_campaign_id"]),
                "expected_parent_version": int(row["expected_readiness_version"]),
                "changed_evidence_sha256": "0" * 64,
                "resolution_action_set_sha256": row[
                    "notice_action_set_sha256"
                ],
                "approval": frozen_approval,
            },
        }
    )
    successor["transition"]["changed_evidence_sha256"] = (
        transition_evidence_sha256(parent_plan, successor)
    )
    _validate_plan(successor)
    return observations, successor


def _insert_resolution_cycle(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    context_sha256: str,
    changed_evidence_sha256: str,
    outcome: str,
    successor_campaign_id: int | None,
    disposition_reason: str | None,
    acting_planner_session_id: str,
    result: dict[str, Any],
    now: str,
) -> None:
    connection.execute(
        """
        INSERT INTO portfolio_readiness_resolution_cycles(
            parent_campaign_id, receipt_id, notice_message_id,
            action_set_sha256, context_sha256, changed_evidence_sha256,
            outcome, successor_campaign_id, disposition_reason,
            acting_planner_session_id, result_sha256, result_json, consumed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(row["resolution_campaign_id"]),
            int(row["resolution_receipt_id"]), int(row["message_id"]),
            row["notice_action_set_sha256"], context_sha256,
            changed_evidence_sha256, outcome, successor_campaign_id,
            disposition_reason, acting_planner_session_id, digest_json(result),
            canonical_json(result), now,
        ),
    )


def apply_readiness_resolution(
    store: CoordinationStore,
    *,
    message_id: int,
    planner_session_id: str,
    expected_context_sha256: str,
    now: str,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Consume one claimed context after all broker-owned prerequisites read back."""

    if (
        type(message_id) is not int
        or message_id <= 0
        or not isinstance(expected_context_sha256, str)
        or SHA256.fullmatch(expected_context_sha256) is None
    ):
        raise ReadinessError("READINESS_RESOLUTION_CONTEXT_INVALID")
    ensure_schema(store.connection)
    _require_pull_buffer_schema(store.connection)
    with store.transaction():
        row = _resolution_notice_row(store.connection, message_id)
        if row["cycle_result_json"] is not None:
            if row["message_state"] != "COMPLETE":
                raise ReadinessError("READINESS_RESOLUTION_REPLAY_INCOMPLETE")
            result = _parse_bound_json(
                row["cycle_result_json"], "READINESS_RESOLUTION_RESULT_INVALID"
            )
            if digest_json(result) != row["cycle_result_sha256"]:
                raise ReadinessError("READINESS_RESOLUTION_RESULT_INVALID")
            return {**result, "replay": True}
        parent_plan, _receipt, actions = _validate_resolution_notice_binding(
            store.connection,
            row,
            planner_session_id=planner_session_id,
            require_pending=True,
        )
        if (
            row["context_json"] is None
            or row["context_sha256"] != expected_context_sha256
            or row["message_state"] != "CLAIMED"
            or row["message_claimed_by"] is None
            or not identities_role_equivalent(
                store.connection,
                str(row["message_claimed_by"]),
                planner_session_id,
            )
        ):
            raise ReadinessError("READINESS_RESOLUTION_CONTEXT_CLAIM_INVALID")
        context = _parse_bound_json(
            row["context_json"], "READINESS_RESOLUTION_CONTEXT_INVALID"
        )
        if (
            digest_json(context) != expected_context_sha256
            or context.get("action_set", {}).get("action_set_sha256")
            != row["notice_action_set_sha256"]
        ):
            raise ReadinessError("READINESS_RESOLUTION_CONTEXT_INVALID")
        try:
            observations, successor = _resolution_observations_and_successor(
                store.connection, row, parent_plan, actions
            )
            reasons = _binding_reasons(
                store.connection, {**successor, "id": -1, "endpoint_id": None}
            )
            if reasons:
                raise ReadinessError(
                    "READINESS_RESOLUTION_EVIDENCE_DRIFT:" + ",".join(reasons)
                )
        except ReadinessError as exc:
            reason = str(exc)
            if not reason.startswith("READINESS_RESOLUTION_EVIDENCE_"):
                raise
            failure = {
                "schema": READINESS_RESOLUTION_FAILURE_SCHEMA,
                "parent_campaign_id": int(row["resolution_campaign_id"]),
                "notice_message_id": message_id,
                "action_set_sha256": row["notice_action_set_sha256"],
                "context_sha256": expected_context_sha256,
                "reason": reason,
            }
            changed_evidence_sha256 = digest_json(failure)
            changed = store.connection.execute(
                "UPDATE portfolio_readiness_current SET state='HOLD', "
                "version=version+1, updated_at=?, last_error=? "
                "WHERE campaign_id=? AND receipt_id=? "
                "AND state='RESOLUTION_PENDING' AND version=?",
                (
                    now, reason, int(row["resolution_campaign_id"]),
                    int(row["resolution_receipt_id"]),
                    int(row["expected_readiness_version"]),
                ),
            ).rowcount
            if changed != 1:
                raise ReadinessError("READINESS_RESOLUTION_FENCE_LOST")
            result = {
                "schema": READINESS_RESOLUTION_RESULT_SCHEMA,
                "repository": row["repository"],
                "issue_number": int(row["issue_number"]),
                "parent_campaign_id": int(row["resolution_campaign_id"]),
                "successor_campaign_id": None,
                "outcome": "HOLD",
                "disposition": "TERMINAL_HOLD",
                "reason": reason,
                "action_set_sha256": row["notice_action_set_sha256"],
                "changed_evidence_sha256": changed_evidence_sha256,
                "context_sha256": expected_context_sha256,
            }
            _decision_failpoint(failpoint, "after_disposition")
            _insert_resolution_cycle(
                store.connection,
                row,
                context_sha256=expected_context_sha256,
                changed_evidence_sha256=changed_evidence_sha256,
                outcome="HOLD",
                successor_campaign_id=None,
                disposition_reason=reason,
                acting_planner_session_id=planner_session_id,
                result=result,
                now=now,
            )
            _decision_failpoint(failpoint, "after_consumption")
            store.complete_readiness_resolution_message_in_transaction(
                message_id, planner_session_id, now
            )
            _event(
                store.connection,
                int(row["resolution_campaign_id"]),
                "READINESS_RESOLUTION_HELD",
                result,
                now,
            )
            return {**result, "replay": False}
        _decision_failpoint(failpoint, "after_evidence_readback")
        registered = _register_locked(
            store.connection,
            successor,
            now=now,
            approval_verified=(
                successor["transition"].get("approval") is not None
            ),
            resolution_verified=True,
        )
        _decision_failpoint(failpoint, "after_successor_registered")
        changed_evidence_sha256 = successor["transition"][
            "changed_evidence_sha256"
        ]
        result = {
            "schema": READINESS_RESOLUTION_RESULT_SCHEMA,
            "repository": row["repository"],
            "issue_number": int(row["issue_number"]),
            "parent_campaign_id": int(row["resolution_campaign_id"]),
            "successor_campaign_id": int(registered["campaign_id"]),
            "outcome": "SUCCESSOR",
            "disposition": "RESUMED",
            "reason": None,
            "action_set_sha256": row["notice_action_set_sha256"],
            "changed_evidence_sha256": changed_evidence_sha256,
            "context_sha256": expected_context_sha256,
            "observation_set_sha256": digest_json(observations),
        }
        _insert_resolution_cycle(
            store.connection,
            row,
            context_sha256=expected_context_sha256,
            changed_evidence_sha256=changed_evidence_sha256,
            outcome="SUCCESSOR",
            successor_campaign_id=int(registered["campaign_id"]),
            disposition_reason=None,
            acting_planner_session_id=planner_session_id,
            result=result,
            now=now,
        )
        _decision_failpoint(failpoint, "after_consumption")
        store.complete_readiness_resolution_message_in_transaction(
            message_id, planner_session_id, now
        )
        _event(
            store.connection,
            int(row["resolution_campaign_id"]),
            "READINESS_RESOLUTION_COMPLETED",
            {**result, "observations": observations},
            now,
        )
    return {**result, "replay": False}


def _decision_failpoint(
    failpoint: Callable[[str], None] | None, step: str
) -> None:
    if failpoint is not None:
        failpoint(step)


def _insert_approval_consumption(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    disposition: str,
    successor_campaign_id: int | None,
    effective_source_sha256: str,
    acting_planner_session_id: str,
    revisit_trigger_json: str | None,
    now: str,
) -> None:
    connection.execute(
        """
        INSERT INTO portfolio_readiness_approval_consumptions(
            request_campaign_id, receipt_id, proposal_sha256,
            decision_sha256, delivery_recipient_session_id,
            notice_message_id, disposition, successor_campaign_id,
            effective_source_sha256, remote_receipt,
            acting_planner_session_id, revisit_trigger_json, consumed_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            int(row["readiness_campaign_id"]),
            int(row["readiness_receipt_id"]),
            row["proposal_sha256"], row["decision_sha256"],
            row["recipient_session_id"], int(row["message_id"]), disposition,
            successor_campaign_id, effective_source_sha256,
            row["remote_receipt"], acting_planner_session_id,
            revisit_trigger_json, now,
        ),
    )


def _deterministic_approval_successor(
    row: sqlite3.Row, *, recipient_session_id: str
) -> dict[str, Any]:
    try:
        parent = json.loads(row["plan_json"], object_pairs_hook=_strict_object)
    except (TypeError, json.JSONDecodeError, ReadinessError) as exc:
        raise ReadinessError("READINESS_PARENT_PLAN_INVALID") from exc
    successor = {
        **{
            key: value
            for key, value in parent.items()
            if key not in {"schema", "transition"}
        },
        "schema": SUCCESSOR_PLAN_SCHEMA,
        "transition": {
            "kind": "APPROVAL_RESUME",
            "parent_campaign_id": int(row["readiness_campaign_id"]),
            "expected_parent_version": int(row["expected_readiness_version"]),
            "changed_evidence_sha256": "0" * 64,
            "resolution_action_set_sha256": None,
            "approval": {
                "proposal_sha256": row["proposal_sha256"],
                "decision_sha256": row["decision_sha256"],
                "recipient_session_id": recipient_session_id,
                "execution_scope_sha256": row["execution_scope_sha256"],
            },
        },
    }
    successor["transition"]["changed_evidence_sha256"] = (
        transition_evidence_sha256(parent, successor)
    )
    _validate_plan(successor)
    return successor


def apply_readiness_decision(
    store: CoordinationStore,
    *,
    message_id: int,
    planner_session_id: str,
    refreshed_payload: dict[str, Any],
    refreshed_payload_sha256: str,
    now: str,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Consume one published readiness decision as one atomic Planner action."""

    if type(message_id) is not int or message_id <= 0:
        raise ReadinessError("READINESS_DECISION_NOTICE_INVALID")
    if not isinstance(refreshed_payload, dict) or (
        digest_json(refreshed_payload) != refreshed_payload_sha256
    ):
        raise ReadinessError("READINESS_DECISION_SOURCE_INVALID")
    ensure_approval_schema(store.connection)
    ensure_schema(store.connection)
    _require_pull_buffer_schema(store.connection)
    with store.transaction():
        planner = current_endpoint(store.connection, "planner")
        if planner is None or planner["endpoint_id"] != planner_session_id:
            raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
        row = store.connection.execute(
            """
            SELECT notice.message_id, notice.proposal_sha256,
                   notice.submission_sha256, notice.decision_sha256,
                   notice.recipient_session_id,
                   notice.readiness_campaign_id, notice.readiness_receipt_id,
                   notice.expected_readiness_version,
                   notice.source_payload_sha256 AS notice_source_sha256,
                   notice.routed_endpoint_id,
                   message.state AS message_state,
                   message.recipient_session_id AS message_recipient_session_id,
                   message.payload_json AS message_payload_json,
                   request.repository, request.issue_number,
                   request.source_payload_sha256,
                   request.execution_scope_sha256, request.boundary,
                   request.requester_session_id,
                   request.packet_recipient_session_id,
                   current.state AS readiness_state,
                   current.version AS readiness_version,
                   current.campaign_id AS current_campaign_id,
                   current.receipt_id AS current_receipt_id,
                   campaign.plan_json, campaign.plan_sha256,
                   campaign.worker_role,
                   receipt.verdict, receipt.approval_proposal_sha256,
                   submission.packet_json AS submission_packet_json,
                   delivery.state AS delivery_state,
                   decision.decision, decision.selected_option_id,
                   decision.revisit_trigger, decision.execution_scope_sha256
                       AS decision_execution_scope_sha256,
                   decision.owner_outbox_id,
                   outbox.state AS outbox_state, outbox.remote_receipt,
                   revocation.decision_sha256 AS revoked_decision_sha256,
                   source.payload_sha256 AS current_source_sha256,
                   source_snapshot.payload_json AS current_source_payload_json,
                   original.payload_json AS original_source_payload_json,
                   effectivity.effective_source_sha256,
                   consumption.disposition AS consumed_disposition,
                   consumption.successor_campaign_id AS consumed_successor_campaign_id
            FROM approval_delivery_notices notice
            JOIN coordination_messages message ON message.id=notice.message_id
            JOIN portfolio_readiness_approval_requests request
              ON request.campaign_id=notice.readiness_campaign_id
             AND request.receipt_id=notice.readiness_receipt_id
             AND request.proposal_sha256=notice.proposal_sha256
             AND request.submission_sha256=notice.submission_sha256
             AND request.expected_approval_pending_version=
                 notice.expected_readiness_version
            JOIN portfolio_readiness_current current
              ON current.campaign_id=request.campaign_id
             AND current.receipt_id=request.receipt_id
            JOIN portfolio_readiness_campaigns campaign
              ON campaign.id=request.campaign_id
            JOIN portfolio_readiness_receipts receipt
              ON receipt.id=request.receipt_id
            JOIN approval_submissions submission
              ON submission.submission_sha256=request.submission_sha256
             AND submission.proposal_sha256=request.proposal_sha256
            JOIN approval_decisions decision
              ON decision.proposal_sha256=request.proposal_sha256
             AND decision.decision_sha256=notice.decision_sha256
            JOIN approval_deliveries delivery
              ON delivery.proposal_sha256=request.proposal_sha256
             AND delivery.decision_sha256=notice.decision_sha256
             AND delivery.recipient_session_id=notice.recipient_session_id
            JOIN github_outbox outbox ON outbox.id=decision.owner_outbox_id
            JOIN github_current source
              ON source.repository=request.repository
             AND source.object_kind='issue'
             AND source.object_number=request.issue_number
            JOIN github_snapshots source_snapshot
              ON source_snapshot.repository=source.repository
             AND source_snapshot.object_kind=source.object_kind
             AND source_snapshot.object_number=source.object_number
             AND source_snapshot.payload_sha256=source.payload_sha256
            JOIN github_snapshots original
              ON original.repository=request.repository
             AND original.object_kind='issue'
             AND original.object_number=request.issue_number
             AND original.payload_sha256=request.source_payload_sha256
            LEFT JOIN approval_revocations revocation
              ON revocation.proposal_sha256=request.proposal_sha256
             AND revocation.decision_sha256=notice.decision_sha256
            LEFT JOIN approval_effectivity effectivity
              ON effectivity.proposal_sha256=request.proposal_sha256
             AND effectivity.decision_sha256=notice.decision_sha256
            LEFT JOIN portfolio_readiness_approval_consumptions consumption
              ON consumption.request_campaign_id=request.campaign_id
            WHERE notice.message_id=?
            """,
            (message_id,),
        ).fetchone()
        if row is None:
            raise ReadinessError("READINESS_DECISION_NOTICE_NOT_FOUND")
        if row["consumed_disposition"] is not None:
            if row["message_state"] != "COMPLETE":
                raise ReadinessError("READINESS_DECISION_REPLAY_INCOMPLETE")
            return {
                "repository": row["repository"],
                "issue_number": int(row["issue_number"]),
                "disposition": row["consumed_disposition"],
                "successor_campaign_id": row["consumed_successor_campaign_id"],
                "replay": True,
            }
        if (
            row["routed_endpoint_id"] != planner_session_id
            or row["message_recipient_session_id"] != planner_session_id
            or not identities_role_equivalent(
                store.connection,
                str(row["recipient_session_id"]),
                planner_session_id,
            )
            or row["readiness_state"] != "APPROVAL_PENDING"
            or int(row["readiness_version"])
                != int(row["expected_readiness_version"])
            or int(row["current_campaign_id"])
                != int(row["readiness_campaign_id"])
            or int(row["current_receipt_id"])
                != int(row["readiness_receipt_id"])
            or row["verdict"] != "APPROVAL_REQUIRED"
            or row["approval_proposal_sha256"] != row["proposal_sha256"]
            or row["decision_execution_scope_sha256"]
                != row["execution_scope_sha256"]
            or row["outbox_state"] != "COMPLETE"
            or not row["remote_receipt"]
        ):
            raise ReadinessError("READINESS_DECISION_BINDING_DRIFT")
        try:
            submission_packet = json.loads(
                row["submission_packet_json"], object_pairs_hook=_strict_object
            )
            message_payload = json.loads(
                row["message_payload_json"], object_pairs_hook=_strict_object
            )
            original_payload = json.loads(
                row["original_source_payload_json"], object_pairs_hook=_strict_object
            )
            current_payload = json.loads(
                row["current_source_payload_json"], object_pairs_hook=_strict_object
            )
        except (TypeError, json.JSONDecodeError, ReadinessError) as exc:
            raise ReadinessError("READINESS_DECISION_BINDING_DRIFT") from exc
        evidence = message_payload.get("evidence", {})
        if (
            submission_packet.get("workstream") != "READINESS"
            or submission_packet.get("requester_session_id")
                != row["requester_session_id"]
            or submission_packet.get("recipient_session_id")
                != row["packet_recipient_session_id"]
            or submission_packet.get("repository") != row["repository"]
            or submission_packet.get("owning_issue") != row["issue_number"]
            or submission_packet.get("source_snapshot_sha256")
                != row["source_payload_sha256"]
            or submission_packet.get("execution_scope_sha256")
                != row["execution_scope_sha256"]
            or submission_packet.get("boundary") != row["boundary"]
            or message_payload.get("source", {}).get("payload_sha256")
                != row["notice_source_sha256"]
            or evidence.get("proposal_sha256") != row["proposal_sha256"]
            or evidence.get("submission_sha256") != row["submission_sha256"]
            or evidence.get("decision_sha256") != row["decision_sha256"]
            or evidence.get("readiness_campaign_id")
                != int(row["readiness_campaign_id"])
            or evidence.get("readiness_receipt_id")
                != int(row["readiness_receipt_id"])
            or evidence.get("expected_readiness_version")
                != int(row["expected_readiness_version"])
        ):
            raise ReadinessError("READINESS_DECISION_BINDING_DRIFT")
        claimed_message = store.claim_readiness_decision_message_in_transaction(
            message_id, planner_session_id, now
        )
        if claimed_message["state"] != "CLAIMED":
            raise ReadinessError("READINESS_DECISION_MESSAGE_CLAIM_FAILED")
        _decision_failpoint(failpoint, "after_message_claim")

        stable_original = _stable_source_payload(original_payload)
        stable_refreshed = _stable_source_payload(refreshed_payload)
        stable_current = _stable_source_payload(current_payload)
        stable_sha256 = digest_json(stable_original)
        source_updated_at = refreshed_payload.get(
            "_projection_updated_at", refreshed_payload.get("updated_at")
        )
        if not isinstance(source_updated_at, str) or not source_updated_at:
            raise ReadinessError("READINESS_DECISION_SOURCE_INVALID")
        store.connection.execute(
            """
            INSERT OR IGNORE INTO github_snapshots(
                repository, object_kind, object_number, payload_sha256,
                source_updated_at, fetched_at, payload_json
            ) VALUES (?, 'issue', ?, ?, ?, ?, ?)
            """,
            (
                row["repository"], int(row["issue_number"]),
                refreshed_payload_sha256, source_updated_at, now,
                canonical_json(refreshed_payload),
            ),
        )
        material_drift = (
            stable_refreshed != stable_original
            or stable_current != stable_original
        )
        if material_drift or row["revoked_decision_sha256"] is not None:
            disposition = "STALE" if material_drift else "HOLD"
            error = (
                "APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION"
                if material_drift
                else "APPROVAL_DECISION_REVOKED"
            )
            changed = store.connection.execute(
                "UPDATE portfolio_readiness_current SET state=?, version=version+1, "
                "updated_at=?, last_error=? WHERE campaign_id=? "
                "AND state='APPROVAL_PENDING' AND version=?",
                (
                    disposition, now, error,
                    int(row["readiness_campaign_id"]),
                    int(row["expected_readiness_version"]),
                ),
            ).rowcount
            if changed != 1:
                raise ReadinessError("READINESS_DECISION_FENCE_LOST")
            store.connection.execute(
                "UPDATE approval_deliveries SET state='HOLD', updated_at=?, "
                "last_error=? WHERE proposal_sha256=? "
                "AND recipient_session_id=? AND state IN "
                "('WAITING_PUBLICATION','CLAIMED','HOLD')",
                (
                    now, error, row["proposal_sha256"],
                    row["recipient_session_id"],
                ),
            )
            _insert_approval_consumption(
                store.connection,
                row,
                disposition=disposition,
                successor_campaign_id=None,
                effective_source_sha256=stable_sha256,
                acting_planner_session_id=planner_session_id,
                revisit_trigger_json=None,
                now=now,
            )
            _decision_failpoint(failpoint, "after_consumption")
            store.complete_readiness_decision_message_in_transaction(
                message_id, planner_session_id, now
            )
            return {
                "repository": row["repository"],
                "issue_number": int(row["issue_number"]),
                "disposition": disposition,
                "successor_campaign_id": None,
                "replay": False,
            }

        for observed_sha256 in {
            refreshed_payload_sha256,
            str(row["current_source_sha256"]),
        }:
            if observed_sha256 != row["source_payload_sha256"]:
                store.connection.execute(
                    """
                    INSERT OR IGNORE INTO portfolio_readiness_source_equivalence(
                        request_campaign_id, decision_sha256,
                        bound_source_sha256, observed_source_sha256,
                        stable_source_sha256, created_at
                    ) VALUES (?,?,?,?,?,?)
                    """,
                    (
                        int(row["readiness_campaign_id"]),
                        row["decision_sha256"], row["source_payload_sha256"],
                        observed_sha256, stable_sha256, now,
                    ),
                )
        binding_campaign = _campaign(
            store.connection, str(row["repository"]), int(row["issue_number"])
        )
        binding_reasons = [
            reason
            for reason in _binding_reasons(store.connection, binding_campaign)
            # The worker's endpoint may rotate after its exact terminal receipt;
            # immutable request provenance, not current routing, owns this wait.
            if reason != "ENDPOINT_DRIFT"
        ]
        if binding_reasons:
            error = "READINESS_BINDING_DRIFT:" + ",".join(binding_reasons)
            changed = store.connection.execute(
                "UPDATE portfolio_readiness_current SET state='STALE', "
                "version=version+1, updated_at=?, last_error=? "
                "WHERE campaign_id=? AND state='APPROVAL_PENDING' AND version=?",
                (
                    now, error, int(row["readiness_campaign_id"]),
                    int(row["expected_readiness_version"]),
                ),
            ).rowcount
            if changed != 1:
                raise ReadinessError("READINESS_DECISION_FENCE_LOST")
            store.connection.execute(
                "UPDATE approval_deliveries SET state='HOLD', updated_at=?, "
                "last_error=? WHERE proposal_sha256=? AND recipient_session_id=? "
                "AND state IN ('WAITING_PUBLICATION','CLAIMED')",
                (
                    now, error, row["proposal_sha256"],
                    row["recipient_session_id"],
                ),
            )
            _insert_approval_consumption(
                store.connection,
                row,
                disposition="STALE",
                successor_campaign_id=None,
                effective_source_sha256=stable_sha256,
                acting_planner_session_id=planner_session_id,
                revisit_trigger_json=None,
                now=now,
            )
            store.complete_readiness_decision_message_in_transaction(
                message_id, planner_session_id, now
            )
            return {
                "repository": row["repository"],
                "issue_number": int(row["issue_number"]),
                "disposition": "STALE",
                "successor_campaign_id": None,
                "binding_reasons": binding_reasons,
                "replay": False,
            }
        try:
            claimed = claim_decision_in_transaction(
                store,
                proposal_sha256=str(row["proposal_sha256"]),
                recipient_session_id=planner_session_id,
                refreshed_payload=refreshed_payload,
                refreshed_payload_sha256=refreshed_payload_sha256,
                now=now,
                ingest_refreshed_source=False,
                expected_current_source_sha256=str(
                    row["current_source_sha256"]
                ),
            )
        except CoordinationError as exc:
            raise ReadinessError(str(exc)) from exc
        _decision_failpoint(failpoint, "after_delivery_claim")

        successor_campaign_id: int | None = None
        revisit_json: str | None = None
        if claimed["decision"] == "APPROVE":
            try:
                effective = require_effective_approval(
                    store.connection,
                    repository=str(row["repository"]),
                    issue_number=int(row["issue_number"]),
                    recipient_session_id=str(row["recipient_session_id"]),
                    actor_session_id=planner_session_id,
                    execution_scope_sha256=str(row["execution_scope_sha256"]),
                    authority_sha256=str(row["decision_sha256"]),
                    required_proposal_sha256=str(row["proposal_sha256"]),
                    required_workstream="READINESS",
                    required_boundary=str(row["boundary"]),
                    required_current_recipient_role="planner",
                    required=True,
                )
            except ApprovalGuardError as exc:
                raise ReadinessError(str(exc)) from exc
            if effective is None:
                raise ReadinessError("READINESS_EFFECTIVE_APPROVAL_REQUIRED")
            successor = _deterministic_approval_successor(
                row, recipient_session_id=str(row["recipient_session_id"])
            )
            registered = _register_locked(
                store.connection, successor, now=now, approval_verified=True
            )
            successor_campaign_id = int(registered["campaign_id"])
            disposition = "RESUMED"
        else:
            if claimed["decision"] == "REJECT":
                next_state = "HOLD"
                disposition = "HOLD"
                error = "APPROVAL_REJECTED"
            elif claimed["decision"] == "DEFER":
                try:
                    revisit_at = datetime.fromisoformat(
                        str(claimed["revisit_trigger"]).replace("Z", "+00:00")
                    )
                except ValueError as exc:
                    raise ReadinessError(
                        "APPROVAL_READINESS_REVISIT_TRIGGER_INVALID"
                    ) from exc
                if revisit_at.tzinfo is None or not str(claimed["revisit_trigger"]).endswith("Z"):
                    raise ReadinessError(
                        "APPROVAL_READINESS_REVISIT_TRIGGER_INVALID"
                    )
                revisit_json = canonical_json(
                    {"kind": "AT", "at": claimed["revisit_trigger"]}
                )
                next_state = "HOLD"
                disposition = "HOLD"
                error = "APPROVAL_DEFERRED"
            elif claimed["decision"] == "COURSE_CORRECT":
                next_state = "HOLD"
                disposition = "HOLD"
                error = "APPROVAL_COURSE_CORRECT"
            else:
                raise ReadinessError("APPROVAL_DECISION_INVALID")
            changed = store.connection.execute(
                "UPDATE portfolio_readiness_current SET state=?, version=version+1, "
                "updated_at=?, last_error=? WHERE campaign_id=? "
                "AND state='APPROVAL_PENDING' AND version=?",
                (
                    next_state, now, error,
                    int(row["readiness_campaign_id"]),
                    int(row["expected_readiness_version"]),
                ),
            ).rowcount
            if changed != 1:
                raise ReadinessError("READINESS_DECISION_FENCE_LOST")
            if claimed["decision"] == "COURSE_CORRECT":
                store.enqueue_message(
                    idempotency_key=(
                        "readiness-course-change:"
                        f"{int(row['readiness_campaign_id'])}:"
                        f"{row['decision_sha256']}"
                    ),
                    recipient_session_id=planner_session_id,
                    topic="coordination.notice",
                    payload={
                        "source": {
                            "repository": row["repository"],
                            "object_kind": "issue",
                            "object_number": int(row["issue_number"]),
                            "payload_sha256": row["current_source_sha256"],
                        },
                        "notice_kind": "planning_request",
                        "mutation_authority": False,
                        "subject": (
                            "readiness-course-change:"
                            f"{int(row['readiness_campaign_id'])}"
                        ),
                        "summary": (
                            "Published direction requires a fresh materially changed "
                            "proposal; the original lineage remains durably held."
                        ),
                        "evidence": {
                            "decision_sha256": row["decision_sha256"],
                            "selected_option_id": row["selected_option_id"],
                            "parent_plan_sha256": row["plan_sha256"],
                        },
                        "requested_evidence": [
                            "One fresh source-current proposal with a new scope digest."
                        ],
                        "next_observation": (
                            "A materially changed scope returns through a new decision."
                        ),
                    },
                    now=now,
                    _transaction=False,
                )
        _decision_failpoint(failpoint, "after_disposition")
        _insert_approval_consumption(
            store.connection,
            row,
            disposition=disposition,
            successor_campaign_id=successor_campaign_id,
            effective_source_sha256=stable_sha256,
            acting_planner_session_id=planner_session_id,
            revisit_trigger_json=revisit_json,
            now=now,
        )
        _decision_failpoint(failpoint, "after_consumption")
        try:
            acknowledge_decision_in_transaction(
                store,
                proposal_sha256=str(row["proposal_sha256"]),
                decision_sha256=str(row["decision_sha256"]),
                recipient_session_id=planner_session_id,
                now=now,
            )
        except CoordinationError as exc:
            raise ReadinessError(str(exc)) from exc
        _decision_failpoint(failpoint, "after_acknowledge")
        _decision_failpoint(failpoint, "before_message_complete")
        store.complete_readiness_decision_message_in_transaction(
            message_id, planner_session_id, now
        )
        _event(
            store.connection,
            int(row["readiness_campaign_id"]),
            "READINESS_DECISION_CONSUMED",
            {
                "proposal_sha256": row["proposal_sha256"],
                "decision_sha256": row["decision_sha256"],
                "disposition": disposition,
                "successor_campaign_id": successor_campaign_id,
            },
            now,
        )
    return {
        "repository": row["repository"],
        "issue_number": int(row["issue_number"]),
        "disposition": disposition,
        "successor_campaign_id": successor_campaign_id,
        "replay": False,
    }


def enqueue_due_readiness_revisits(
    store: CoordinationStore,
    *,
    now: str,
    limit: int = 8,
) -> dict[str, Any]:
    """Wake one current Planner when a typed DEFER AT trigger becomes due."""

    if type(limit) is not int or limit <= 0 or limit > 64:
        raise ReadinessError("READINESS_REVISIT_LIMIT_INVALID")
    try:
        observed = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReadinessError("READINESS_REVISIT_TIME_INVALID") from exc
    ensure_schema(store.connection)
    planner = current_endpoint(store.connection, "planner")
    if planner is None:
        raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
    planner_endpoint = str(planner["endpoint_id"])
    enqueued: list[dict[str, Any]] = []
    with store.transaction():
        rows = store.connection.execute(
            """
            SELECT consumption.request_campaign_id,
                   consumption.proposal_sha256, consumption.decision_sha256,
                   consumption.revisit_trigger_json,
                   request.repository, request.issue_number,
                   source.payload_sha256 AS current_source_sha256
            FROM portfolio_readiness_approval_consumptions consumption
            JOIN portfolio_readiness_approval_requests request
              ON request.campaign_id=consumption.request_campaign_id
            JOIN portfolio_readiness_current current
              ON current.campaign_id=request.campaign_id
             AND current.state='HOLD'
            JOIN approval_decisions decision
              ON decision.proposal_sha256=consumption.proposal_sha256
             AND decision.decision_sha256=consumption.decision_sha256
             AND decision.decision='DEFER'
            JOIN github_current source
              ON source.repository=request.repository
             AND source.object_kind='issue'
             AND source.object_number=request.issue_number
            LEFT JOIN portfolio_readiness_revisit_notices notice
              ON notice.request_campaign_id=request.campaign_id
            WHERE consumption.disposition='HOLD'
              AND consumption.revisit_trigger_json IS NOT NULL
              AND notice.request_campaign_id IS NULL
            ORDER BY consumption.consumed_at, request.campaign_id
            """
        ).fetchall()
        for row in rows:
            try:
                trigger = json.loads(
                    row["revisit_trigger_json"], object_pairs_hook=_strict_object
                )
                if set(trigger) != {"kind", "at"} or trigger["kind"] != "AT":
                    raise ValueError
                due = datetime.fromisoformat(str(trigger["at"]).replace("Z", "+00:00"))
            except (TypeError, ValueError, json.JSONDecodeError, ReadinessError) as exc:
                raise ReadinessError(
                    "APPROVAL_READINESS_REVISIT_TRIGGER_INVALID"
                ) from exc
            if observed < due:
                continue
            message_id = store.enqueue_message(
                idempotency_key=(
                    "readiness-revisit-due:"
                    f"{int(row['request_campaign_id'])}:"
                    f"{row['decision_sha256']}"
                ),
                recipient_session_id=planner_endpoint,
                topic="coordination.notice",
                payload={
                    "source": {
                        "repository": row["repository"],
                        "object_kind": "issue",
                        "object_number": int(row["issue_number"]),
                        "payload_sha256": row["current_source_sha256"],
                    },
                    "notice_kind": "planning_request",
                    "mutation_authority": False,
                    "subject": (
                        "readiness-revisit-due:"
                        f"{int(row['request_campaign_id'])}"
                    ),
                    "summary": (
                        "The recorded AT trigger is due; one fresh material "
                        "decision review is required before this hold can exit."
                    ),
                    "evidence": {
                        "prior_proposal_sha256": row["proposal_sha256"],
                        "prior_decision_sha256": row["decision_sha256"],
                        "trigger_kind": "AT",
                        "trigger_at": trigger["at"],
                    },
                    "requested_evidence": [
                        "A fresh source-current proposal or a continued typed hold."
                    ],
                    "next_observation": (
                        "No execution resumes without a new published decision."
                    ),
                },
                now=now,
                _transaction=False,
            )
            store.connection.execute(
                """
                INSERT INTO portfolio_readiness_revisit_notices(
                    request_campaign_id, proposal_sha256, decision_sha256,
                    due_at, routed_endpoint_id, message_id, created_at
                ) VALUES (?,?,?,?,?,?,?)
                """,
                (
                    int(row["request_campaign_id"]), row["proposal_sha256"],
                    row["decision_sha256"], trigger["at"], planner_endpoint,
                    message_id, now,
                ),
            )
            enqueued.append(
                {
                    "request_campaign_id": int(row["request_campaign_id"]),
                    "message_id": message_id,
                    "routed_endpoint_id": planner_endpoint,
                }
            )
            if len(enqueued) >= limit:
                break
    return {"limit": limit, "enqueued": enqueued}


def stop_revoked_readiness_successors(
    store: CoordinationStore,
    *,
    now: str,
    limit: int = 8,
) -> dict[str, Any]:
    """Mechanically stop and wake each revoked resumed lineage at most once."""

    if type(limit) is not int or limit <= 0 or limit > 64:
        raise ReadinessError("READINESS_REVOCATION_LIMIT_INVALID")
    ensure_schema(store.connection)
    planner = current_endpoint(store.connection, "planner")
    if planner is None:
        raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
    planner_endpoint = str(planner["endpoint_id"])
    stopped: list[dict[str, Any]] = []
    with store.transaction():
        rows = store.connection.execute(
            """
            SELECT campaign.id AS campaign_id, campaign.repository,
                   campaign.issue_number, campaign.approval_proposal_sha256,
                   campaign.approval_decision_sha256, current.state,
                   current.version, current.message_id,
                   source.payload_sha256 AS current_source_sha256
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign
              ON campaign.id=current.campaign_id
             AND campaign.transition_kind='APPROVAL_RESUME'
            JOIN approval_revocations revocation
              ON revocation.proposal_sha256=campaign.approval_proposal_sha256
             AND revocation.decision_sha256=campaign.approval_decision_sha256
            JOIN github_current source
              ON source.repository=campaign.repository
             AND source.object_kind='issue'
             AND source.object_number=campaign.issue_number
            LEFT JOIN portfolio_readiness_revocation_notices notice
              ON notice.campaign_id=campaign.id
            WHERE current.state IN (
                'PENDING','RUNNING','READY_ELIGIBLE','FINALIZED'
            )
              AND notice.campaign_id IS NULL
            ORDER BY campaign.id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        for row in rows:
            changed = store.connection.execute(
                "UPDATE portfolio_readiness_current SET state='HOLD', "
                "version=version+1, updated_at=?, "
                "last_error='APPROVAL_DECISION_REVOKED' "
                "WHERE campaign_id=? AND state=? AND version=?",
                (now, int(row["campaign_id"]), row["state"], int(row["version"])),
            ).rowcount
            if changed != 1:
                raise ReadinessError("READINESS_REVOCATION_FENCE_LOST")
            if row["message_id"] is not None:
                store.connection.execute(
                    "UPDATE coordination_messages SET state='HOLD', updated_at=?, "
                    "last_error='APPROVAL_DECISION_REVOKED' WHERE id=? "
                    "AND state IN ('PREPARED','CLAIMED')",
                    (now, int(row["message_id"])),
                )
            message_id = store.enqueue_message(
                idempotency_key=(
                    "readiness-revoked-disposition:"
                    f"{int(row['campaign_id'])}:"
                    f"{row['approval_decision_sha256']}"
                ),
                recipient_session_id=planner_endpoint,
                topic="coordination.notice",
                payload={
                    "source": {
                        "repository": row["repository"],
                        "object_kind": "issue",
                        "object_number": int(row["issue_number"]),
                        "payload_sha256": row["current_source_sha256"],
                    },
                    "notice_kind": "status",
                    "mutation_authority": False,
                    "subject": f"readiness-lineage-held:{int(row['campaign_id'])}",
                    "summary": (
                        "The prior material decision is no longer effective; "
                        "the resumed lineage is durably held."
                    ),
                    "evidence": {
                        "proposal_sha256": row["approval_proposal_sha256"],
                        "decision_sha256": row["approval_decision_sha256"],
                        "prior_state": row["state"],
                        "current_state": "HOLD",
                    },
                    "next_observation": (
                        "A fresh source-current material decision is required."
                    ),
                },
                now=now,
                _transaction=False,
            )
            store.connection.execute(
                """
                INSERT INTO portfolio_readiness_revocation_notices(
                    campaign_id, proposal_sha256, decision_sha256, prior_state,
                    routed_endpoint_id, message_id, created_at
                ) VALUES (?,?,?,?,?,?,?)
                """,
                (
                    int(row["campaign_id"]), row["approval_proposal_sha256"],
                    row["approval_decision_sha256"], row["state"],
                    planner_endpoint, message_id, now,
                ),
            )
            stopped.append(
                {
                    "campaign_id": int(row["campaign_id"]),
                    "prior_state": row["state"],
                    "state": "HOLD",
                    "message_id": message_id,
                }
            )
    return {"limit": limit, "stopped": stopped}


def _notice_payload(connection: sqlite3.Connection, campaign: sqlite3.Row) -> dict[str, Any]:
    gates = connection.execute(
        """
        SELECT gate_key, description, requested_evidence_json
        FROM portfolio_readiness_gates WHERE campaign_id=? ORDER BY id
        """,
        (int(campaign["id"]),),
    ).fetchall()
    requested = [
        f"{gate['gate_key']}: {gate['description']} Evidence: "
        + "; ".join(json.loads(gate["requested_evidence_json"]))
        for gate in gates
    ]
    return {
        "source": {
            "repository": campaign["repository"],
            "object_kind": "issue",
            "object_number": int(campaign["issue_number"]),
            "payload_sha256": campaign["source_payload_sha256"],
        },
        "notice_kind": "planning_request",
        "mutation_authority": False,
        "subject": f"Issue {int(campaign['issue_number'])} Kanban readiness phase",
        "summary": campaign["phase_summary"],
        "evidence": {
            "readiness_plan_sha256": campaign["plan_sha256"],
            "candidate_sha256": campaign["candidate_sha256"],
            "accepted_main_sha": campaign["accepted_main_sha"],
            "graph_version": int(campaign["graph_version"]),
            "capacity_policy_version": int(campaign["capacity_policy_version"]),
            "receipt_artifact": _receipt_locator_evidence(campaign),
        },
        "requested_evidence": requested,
        "next_observation": "One terminal evidence bundle covers every listed gate.",
    }


def dispatch(
    store: CoordinationStore,
    repository: str,
    *,
    max_parallel: int,
    now: str,
) -> dict[str, Any]:
    """Dispatch one fresh readiness attempt per candidate, never per gate."""

    if max_parallel <= 0 or max_parallel > MAX_PARALLEL_CANDIDATES:
        raise ReadinessError("READINESS_LIMIT_INVALID")
    connection = store.connection
    ensure_schema(connection)
    dispatched: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    with store.transaction():
        active = int(
            connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_current "
                "WHERE repository=? AND state='RUNNING'",
                (repository,),
            ).fetchone()[0]
        )
        slots = max(0, max_parallel - active)
        campaigns = connection.execute(
            """
            SELECT campaign.*, current.state, current.endpoint_id,
                   current.version AS current_version
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
            JOIN portfolio_graph_nodes node
              ON node.repository=campaign.repository
             AND node.graph_version=campaign.graph_version
             AND node.issue_number=campaign.issue_number
            WHERE campaign.repository=? AND current.state='PENDING'
            ORDER BY node.priority_rank, node.ready_at, node.lane_order, campaign.issue_number
            """,
            (repository,),
        ).fetchall()
        for campaign in campaigns:
            reasons = _binding_reasons(connection, campaign)
            if reasons:
                _mark_stale(connection, campaign, reasons, now)
                stale.append({"issue_number": int(campaign["issue_number"]), "reasons": reasons})
                continue
            if slots <= 0:
                break
            endpoint = current_endpoint(connection, str(campaign["worker_role"]))
            if endpoint is None:
                raise ReadinessError("CURRENT_ENDPOINT_REQUIRED")
            message_id = store.enqueue_message(
                idempotency_key=(
                    f"kanban-readiness:{campaign['plan_sha256']}:{endpoint['endpoint_id']}"
                ),
                recipient_session_id=str(endpoint["endpoint_id"]),
                topic="coordination.notice",
                payload=_notice_payload(connection, campaign),
                now=now,
                _transaction=False,
            )
            locator = _receipt_locator(campaign)
            connection.execute(
                """
                INSERT INTO portfolio_readiness_receipt_pickups(
                    campaign_id, message_id, attempt_id, locator_sha256,
                    relative_path, state, attempts, next_attempt_at, receipt_id,
                    version, created_at, updated_at, last_error
                ) VALUES (?, ?, NULL, ?, ?, 'PENDING', 0, NULL, NULL, 1, ?, ?, NULL)
                """,
                (
                    int(campaign["id"]), message_id, digest_json(locator),
                    locator["relative_path"], now, now,
                ),
            )
            cursor = connection.execute(
                """
                UPDATE portfolio_readiness_current
                SET state='RUNNING', message_id=?, endpoint_id=?,
                    version=version+1, updated_at=?, last_error=NULL
                WHERE campaign_id=? AND state='PENDING' AND version=?
                """,
                (
                    message_id, endpoint["endpoint_id"], now, int(campaign["id"]),
                    int(campaign["current_version"]),
                ),
            )
            if cursor.rowcount != 1:
                raise ReadinessError("READINESS_PHASE_FENCE_LOST")
            _event(
                connection,
                int(campaign["id"]),
                "READINESS_PHASE_DISPATCHED",
                {"message_id": message_id, "endpoint_id": endpoint["endpoint_id"]},
                now,
            )
            dispatched.append(
                {
                    "issue_number": int(campaign["issue_number"]),
                    "message_id": message_id,
                    "endpoint_id": endpoint["endpoint_id"],
                    "receipt_relative_path": locator["relative_path"],
                }
            )
            slots -= 1
    return {
        "repository": repository,
        "max_parallel_candidates": max_parallel,
        "active_before": active,
        "dispatched": dispatched,
        "stale": stale,
        "available_after": slots,
    }


def _validate_attempt(
    connection: sqlite3.Connection,
    campaign: sqlite3.Row,
    message_id: int,
    attempt_id: str,
    *,
    terminal: bool,
) -> tuple[sqlite3.Row, sqlite3.Row]:
    message = connection.execute(
        "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
    ).fetchone()
    attempt = connection.execute(
        "SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if message is None or attempt is None:
        raise ReadinessError("READINESS_ATTEMPT_MISSING")
    try:
        payload = json.loads(message["payload_json"])
    except json.JSONDecodeError as exc:
        raise ReadinessError("READINESS_MESSAGE_INVALID") from exc
    source = payload.get("source") if isinstance(payload, dict) else None
    evidence = payload.get("evidence") if isinstance(payload, dict) else None
    expected_locator = _receipt_locator_evidence(campaign)
    message_states = {"COMPLETE"} if terminal else {"PREPARED", "CLAIMED", "COMPLETE"}
    attempt_states = {"COMPLETE"} if terminal else {
        "RESERVED", "LAUNCHING", "RUNNING", "COMPLETE"
    }
    if (
        identity_role(connection, str(message["recipient_session_id"])) != campaign["worker_role"]
        or attempt["role"] != campaign["worker_role"]
        or attempt["endpoint_id"] != message["recipient_session_id"]
        or attempt["target_kind"] != "message"
        or attempt["target_key"] != str(message_id)
        or not isinstance(source, dict)
        or source.get("repository") != campaign["repository"]
        or source.get("object_kind") != "issue"
        or source.get("object_number") != int(campaign["issue_number"])
        or source.get("payload_sha256") != campaign["source_payload_sha256"]
        or not isinstance(evidence, dict)
        or evidence.get("readiness_plan_sha256") != campaign["plan_sha256"]
        or evidence.get("candidate_sha256") != campaign["candidate_sha256"]
        or evidence.get("accepted_main_sha") != campaign["accepted_main_sha"]
        or evidence.get("graph_version") != int(campaign["graph_version"])
        or evidence.get("capacity_policy_version")
        != int(campaign["capacity_policy_version"])
        or evidence.get("receipt_artifact") != expected_locator
        or message["state"] not in message_states
        or attempt["state"] not in attempt_states
    ):
        raise ReadinessError("READINESS_ATTEMPT_BINDING_INVALID")
    return message, attempt


def attach(
    connection: sqlite3.Connection,
    repository: str,
    issue_number: int,
    message_id: int,
    attempt_id: str,
    *,
    now: str,
) -> dict[str, Any]:
    """Adopt one existing candidate-level phase after exact validation."""

    ensure_schema(connection)
    connection.execute("BEGIN IMMEDIATE")
    try:
        campaign = _campaign(connection, repository, issue_number)
        if campaign["state"] not in {"PENDING", "RUNNING"}:
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if campaign["state"] == "RUNNING" and (
            int(campaign["message_id"]) != message_id
            or campaign["endpoint_id"] is None
            or (
                campaign["attempt_id"] is not None
                and campaign["attempt_id"] != attempt_id
            )
        ):
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if campaign["attempt_id"] == attempt_id:
            connection.execute("COMMIT")
            return {
                "repository": repository,
                "issue_number": issue_number,
                "message_id": message_id,
                "attempt_id": attempt_id,
                "state": "RUNNING",
            }
        reasons = _binding_reasons(connection, campaign)
        if reasons:
            _mark_stale(connection, campaign, reasons, now)
            connection.execute("COMMIT")
            return {
                "repository": repository,
                "issue_number": issue_number,
                "message_id": message_id,
                "attempt_id": attempt_id,
                "state": "STALE",
                "binding_reasons": reasons,
            }
        _message, attempt = _validate_attempt(
            connection, campaign, message_id, attempt_id, terminal=False
        )
        pickup = connection.execute(
            "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
            (int(campaign["id"]),),
        ).fetchone()
        locator = _receipt_locator(campaign)
        if (
            pickup is None
            or int(pickup["message_id"]) != message_id
            or pickup["locator_sha256"] != digest_json(locator)
            or pickup["relative_path"] != locator["relative_path"]
            or pickup["state"] != "PENDING"
            or (
                pickup["attempt_id"] is not None
                and pickup["attempt_id"] != attempt_id
            )
        ):
            raise ReadinessError("READINESS_RECEIPT_PICKUP_BINDING_INVALID")
        cursor = connection.execute(
            """
            UPDATE portfolio_readiness_current
            SET state='RUNNING', message_id=?, attempt_id=?, endpoint_id=?,
                version=version+1, updated_at=?, last_error=NULL
            WHERE campaign_id=? AND state IN ('PENDING','RUNNING') AND version=?
            """,
            (
                message_id, attempt_id, attempt["endpoint_id"], now,
                int(campaign["id"]), int(campaign["current_version"]),
            ),
        )
        if cursor.rowcount != 1:
            raise ReadinessError("READINESS_PHASE_FENCE_LOST")
        pickup_cursor = connection.execute(
            """
            UPDATE portfolio_readiness_receipt_pickups
            SET attempt_id=?, version=version+1, updated_at=?, last_error=NULL
            WHERE campaign_id=? AND message_id=? AND state='PENDING'
              AND (attempt_id IS NULL OR attempt_id=?)
            """,
            (
                attempt_id, now, int(campaign["id"]), message_id, attempt_id,
            ),
        )
        if pickup_cursor.rowcount != 1:
            raise ReadinessError("READINESS_RECEIPT_PICKUP_FENCE_LOST")
        _event(
            connection,
            int(campaign["id"]),
            "READINESS_PHASE_ATTACHED",
            {"message_id": message_id, "attempt_id": attempt_id},
            now,
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return {
        "repository": repository,
        "issue_number": issue_number,
        "message_id": message_id,
        "attempt_id": attempt_id,
        "state": "RUNNING",
    }


def _stage_binding(
    connection: sqlite3.Connection,
    receipt: dict[str, Any],
    message_id: int,
    attempt_id: str,
    token_sha256: str,
) -> tuple[sqlite3.Row, sqlite3.Row]:
    campaign = _campaign(
        connection, str(receipt["repository"]), int(receipt["issue_number"])
    )
    if (
        campaign["state"] != "RUNNING"
        or campaign["attempt_id"] != attempt_id
        or int(campaign["message_id"]) != message_id
        or receipt["attempt_id"] != attempt_id
        or int(receipt["message_id"]) != message_id
        or receipt["readiness_plan_sha256"] != campaign["plan_sha256"]
        or receipt["worker_role"] != campaign["worker_role"]
    ):
        raise ReadinessError("READINESS_RECEIPT_ATTEMPT_DRIFT")
    if _binding_reasons(connection, campaign):
        raise ReadinessError("READINESS_RECEIPT_CAMPAIGN_DRIFT")
    message, attempt = _validate_attempt(
        connection, campaign, message_id, attempt_id, terminal=False
    )
    stored_token_sha256 = attempt["token_sha256"]
    if (
        message["state"] != "CLAIMED"
        or attempt["state"] != "RUNNING"
        or not isinstance(stored_token_sha256, str)
        or not secrets.compare_digest(stored_token_sha256, token_sha256)
    ):
        raise ReadinessError("READINESS_RECEIPT_STAGE_NOT_CURRENT")
    pickup = connection.execute(
        "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
        (int(campaign["id"]),),
    ).fetchone()
    locator = _receipt_locator(campaign)
    if (
        pickup is None
        or pickup["state"] not in {"PENDING", "STAGED"}
        or pickup["attempt_id"] != attempt_id
        or int(pickup["message_id"]) != message_id
        or pickup["relative_path"] != locator["relative_path"]
        or pickup["locator_sha256"] != digest_json(locator)
    ):
        raise ReadinessError("READINESS_RECEIPT_PICKUP_BINDING_INVALID")
    expected_gates = {
        row["gate_key"]
        for row in connection.execute(
            "SELECT gate_key FROM portfolio_readiness_gates WHERE campaign_id=?",
            (int(campaign["id"]),),
        )
    }
    if expected_gates != {
        result["gate_key"] for result in receipt["gate_results"]
    }:
        raise ReadinessError("READINESS_RECEIPT_GATE_COVERAGE_INVALID")
    return campaign, pickup


def stage_receipt(
    connection: sqlite3.Connection,
    database: Path,
    receipt_path: Path,
    *,
    message_id: int,
    attempt_id: str,
    now: str,
) -> dict[str, Any]:
    """Authenticate and durably bind one current worker-observed artifact."""

    require_schema(connection)
    _require_database_binding(connection, database)
    executor_token = os.environ.get("TWINFINITY_EXECUTOR_TOKEN")
    if not executor_token:
        raise ReadinessError("READINESS_EXECUTOR_TOKEN_REQUIRED")
    token_sha256 = hashlib.sha256(executor_token.encode("utf-8")).hexdigest()
    receipt = _read_safe_draft(receipt_path)
    _campaign_row, pickup = _stage_binding(
        connection, receipt, message_id, attempt_id, token_sha256
    )

    canonical_bytes = canonical_json(receipt).encode("utf-8")
    root = _receipt_directory(database, create=True)
    path = Path(database).parent / str(pickup["relative_path"])
    created = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError:
        artifact = _open_staged_artifact(database, str(pickup["relative_path"]))
        if artifact["raw"] != canonical_bytes:
            _close_artifact(artifact)
            raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CONFLICT")
    except OSError as exc:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_UNSAFE") from exc
    else:
        try:
            created = True
            offset = 0
            while offset < len(canonical_bytes):
                offset += os.write(descriptor, canonical_bytes[offset:])
            os.fsync(descriptor)
        except Exception:
            os.close(descriptor)
            try:
                path.unlink()
            except OSError:
                pass
            raise
        else:
            os.close(descriptor)
        directory_descriptor = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        artifact = _open_staged_artifact(database, str(pickup["relative_path"]))
    try:
        if artifact["raw"] != canonical_bytes:
            raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CHANGED")
        _assert_artifact_current(artifact)
        connection.execute("BEGIN IMMEDIATE")
        try:
            campaign, current_pickup = _stage_binding(
                connection, receipt, message_id, attempt_id, token_sha256
            )
            if current_pickup["state"] == "STAGED":
                if (
                    not isinstance(current_pickup["attempt_token_sha256"], str)
                    or not secrets.compare_digest(
                        current_pickup["attempt_token_sha256"], token_sha256
                    )
                    or not _artifact_matches_pickup(current_pickup, artifact)
                ):
                    raise ReadinessError("READINESS_RECEIPT_PICKUP_REPLAY_INVALID")
                replay = True
            else:
                _assert_artifact_current(artifact)
                changed = connection.execute(
                    """
                    UPDATE portfolio_readiness_receipt_pickups
                    SET state='STAGED', attempt_token_sha256=?, artifact_sha256=?,
                        artifact_size_bytes=?, artifact_device_id=?, artifact_inode=?,
                        artifact_mode=?, artifact_uid=?, artifact_nlink=?,
                        artifact_mtime_ns=?, artifact_ctime_ns=?,
                        version=version+1, updated_at=?, last_error=NULL
                    WHERE campaign_id=? AND message_id=? AND attempt_id=?
                      AND state='PENDING' AND version=?
                    """,
                    (
                        token_sha256, artifact["artifact_sha256"],
                        artifact["size_bytes"], artifact["device_id"],
                        artifact["inode"], artifact["mode"], artifact["uid"],
                        artifact["nlink"], artifact["mtime_ns"],
                        artifact["ctime_ns"], now, int(campaign["id"]),
                        message_id, attempt_id, int(current_pickup["version"]),
                    ),
                ).rowcount
                if changed != 1:
                    raise ReadinessError("READINESS_RECEIPT_PICKUP_FENCE_LOST")
                replay = False
            _assert_artifact_current(artifact)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        return {
            "repository": receipt["repository"],
            "issue_number": receipt["issue_number"],
            "message_id": message_id,
            "attempt_id": attempt_id,
            "relative_path": pickup["relative_path"],
            "receipt_sha256": digest_json(receipt),
            "artifact_sha256": artifact["artifact_sha256"],
            "device_id": artifact["device_id"],
            "inode": artifact["inode"],
            "state": "STAGED",
            "replay": replay,
        }
    finally:
        _close_artifact(artifact)


def _issue_action_target(repository: str, issue_number: int) -> str:
    return f"{repository}:issue:{issue_number}"


def _validate_resolution_actions(actions: Any, verdict: str) -> list[dict[str, Any]]:
    if not isinstance(actions, list) or len(actions) > 8:
        raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    if verdict in {"PASS", "TERMINAL_HOLD"}:
        if actions:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
        return []
    if not actions:
        raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    normalized: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    last_order = -1
    for action in actions:
        if not isinstance(action, dict) or set(action) != RESOLUTION_ACTION_KEYS:
            raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
        kind = action.get("kind")
        target = action.get("target")
        expected_digest = action.get("expected_digest")
        desired_digest = action.get("desired_digest")
        authority_class = action.get("authority_class")
        evidence_required = action.get("evidence_required")
        if (
            not isinstance(kind, str)
            or not isinstance(target, str)
            or not target.strip()
            or not isinstance(expected_digest, str)
            or SHA256.fullmatch(expected_digest) is None
            or not isinstance(desired_digest, str)
            or SHA256.fullmatch(desired_digest) is None
            or expected_digest == desired_digest
        ):
            raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
        identity = (kind, target)
        if identity in identities:
            raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
        identities.add(identity)
        if kind in RESOLUTION_ACTION_REGISTRY:
            registry = RESOLUTION_ACTION_REGISTRY[kind]
            if verdict != "ACTIONABLE_HOLD":
                raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
            if authority_class != PLANNER_ACTION_AUTHORITY:
                raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
            if evidence_required != registry["evidence_required"]:
                raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
            order = int(registry["order"])
            if order <= last_order:
                raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
            last_order = order
        elif kind in MATERIAL_ACTION_REGISTRY:
            registry = MATERIAL_ACTION_REGISTRY[kind]
            if authority_class != MATERIAL_ACTION_AUTHORITY:
                raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
            if verdict != "APPROVAL_REQUIRED":
                raise ReadinessError("READINESS_ACTION_APPROVAL_REQUIRED")
            if evidence_required != registry["evidence_required"]:
                raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
        else:
            raise ReadinessError("READINESS_ACTION_TERMINAL_HOLD")
        normalized.append(action)
    return normalized


def _parent_graph_digest(
    connection: sqlite3.Connection, repository: str, graph_version: int
) -> str:
    row = connection.execute(
        "SELECT graph_sha256 FROM portfolio_graph_revisions "
        "WHERE repository=? AND version=?",
        (repository, graph_version),
    ).fetchone()
    if row is None or not isinstance(row["graph_sha256"], str):
        raise ReadinessError("READINESS_ACTION_BINDING_INVALID")
    return str(row["graph_sha256"])


def _validate_resolution_action_bindings(
    connection: sqlite3.Connection,
    campaign: sqlite3.Row,
    actions: list[dict[str, Any]],
    *,
    approval_scope_sha256: str | None,
) -> str:
    repository = str(campaign["repository"])
    issue_number = int(campaign["issue_number"])
    issue_target = _issue_action_target(repository, issue_number)
    expected_by_kind = {
        "REFRESH_SOURCE_SNAPSHOT": str(campaign["source_payload_sha256"]),
        "RECOMPUTE_DEPENDENCY_GRAPH": _parent_graph_digest(
            connection, repository, int(campaign["graph_version"])
        ),
        "REBUILD_PREPARED_CANDIDATE": str(campaign["candidate_sha256"]),
        "REQUEST_MATERIAL_APPROVAL": str(campaign["plan_sha256"]),
    }
    target_by_kind = {
        "REFRESH_SOURCE_SNAPSHOT": issue_target,
        "RECOMPUTE_DEPENDENCY_GRAPH": repository,
        "REBUILD_PREPARED_CANDIDATE": issue_target,
        "REQUEST_MATERIAL_APPROVAL": issue_target,
    }
    for action in actions:
        kind = str(action["kind"])
        if (
            action["target"] != target_by_kind[kind]
            or action["expected_digest"] != expected_by_kind[kind]
        ):
            raise ReadinessError("READINESS_ACTION_BINDING_INVALID")
        if kind == "REQUEST_MATERIAL_APPROVAL" and (
            approval_scope_sha256 is None
            or action["desired_digest"] != approval_scope_sha256
        ):
            raise ReadinessError("READINESS_ACTION_APPROVAL_BINDING_INVALID")
    return digest_json(actions)


def _validate_receipt(receipt: dict[str, Any]) -> None:
    expected = {
        "schema", "repository", "issue_number", "readiness_plan_sha256",
        "verdict", "worker_role", "message_id", "attempt_id", "gate_results",
        "resolution", "summary", "observed_at",
    }
    if set(receipt) != expected or receipt.get("schema") != RECEIPT_SCHEMA:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    verdict = receipt.get("verdict")
    if verdict not in {"PASS", "ACTIONABLE_HOLD", "APPROVAL_REQUIRED", "TERMINAL_HOLD"}:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if receipt.get("worker_role") not in WORKER_ROLES:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if (
        not isinstance(receipt.get("repository"), str)
        or not REPOSITORY.fullmatch(receipt["repository"])
    ):
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if type(receipt.get("issue_number")) is not int or receipt["issue_number"] <= 0:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if type(receipt.get("message_id")) is not int or not isinstance(receipt.get("attempt_id"), str):
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if not isinstance(receipt.get("readiness_plan_sha256"), str) or not SHA256.fullmatch(
        receipt["readiness_plan_sha256"]
    ):
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if not isinstance(receipt.get("summary"), str) or not receipt["summary"].strip():
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if not isinstance(receipt.get("observed_at"), str) or not receipt["observed_at"].strip():
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    results = receipt.get("gate_results")
    if not isinstance(results, list) or not results:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    seen: set[str] = set()
    for result in results:
        if not isinstance(result, dict) or set(result) != {
            "gate_key", "verdict", "evidence_sha256", "summary"
        }:
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        key = result.get("gate_key")
        if not isinstance(key, str) or not GATE_KEY.fullmatch(key) or key in seen:
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        seen.add(key)
        if result.get("verdict") not in {"PASS", "HOLD"}:
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        if not isinstance(result.get("evidence_sha256"), str) or not SHA256.fullmatch(
            result["evidence_sha256"]
        ):
            raise ReadinessError("READINESS_RECEIPT_INVALID")
        if not isinstance(result.get("summary"), str) or not result["summary"].strip():
            raise ReadinessError("READINESS_RECEIPT_INVALID")
    gate_verdicts = {result["verdict"] for result in results}
    if (verdict == "PASS" and gate_verdicts != {"PASS"}) or (
        verdict != "PASS" and "HOLD" not in gate_verdicts
    ):
        raise ReadinessError("READINESS_RECEIPT_VERDICT_MISMATCH")
    resolution = receipt.get("resolution")
    if not isinstance(resolution, dict):
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    if set(resolution) != {"role", "actions", "approval"}:
        raise ReadinessError("READINESS_RECEIPT_INVALID")
    role = resolution.get("role")
    actions = resolution.get("actions")
    approval = resolution.get("approval")
    if verdict == "PASS":
        if (
            role is not None
            or actions != []
            or approval is not None
        ):
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    elif verdict == "ACTIONABLE_HOLD":
        if role != "planner" or not isinstance(actions, list) or not actions:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
        if approval is not None:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    elif verdict == "APPROVAL_REQUIRED":
        if role != "planner" or not isinstance(actions, list) or not actions:
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
        if not isinstance(approval, dict) or set(approval) != {
            "schema", "packet", "material_boundary", "decision_mapping"
        }:
            raise ReadinessError("READINESS_APPROVAL_INPUT_REQUIRED")
        if (
            approval.get("schema") != READINESS_APPROVAL_INPUT_SCHEMA
            or not isinstance(approval.get("material_boundary"), str)
            or approval.get("decision_mapping") != READINESS_DECISION_MAPPING
        ):
            raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
        try:
            normalized_packet = validate_approval_packet(approval.get("packet"))
        except CoordinationError as exc:
            raise ReadinessError(str(exc)) from exc
        if (
            normalized_packet.get("workstream") != "READINESS"
            or normalized_packet.get("boundary")
            != approval["material_boundary"]
            or canonical_json(normalized_packet)
            != canonical_json(approval["packet"])
        ):
            raise ReadinessError("READINESS_APPROVAL_INPUT_INVALID")
    elif (
        role is not None
        or actions != []
        or approval is not None
    ):
        raise ReadinessError("READINESS_RECEIPT_RESOLUTION_INVALID")
    _validate_resolution_actions(actions, str(verdict))


def _approval_input_for_campaign(
    connection: sqlite3.Connection,
    campaign: sqlite3.Row,
    receipt: dict[str, Any],
    terminal_attempt: sqlite3.Row,
) -> tuple[dict[str, Any], str, str]:
    """Validate the worker's immutable input against exact terminal provenance."""

    approval = receipt["resolution"].get("approval")
    if not isinstance(approval, dict):
        raise ReadinessError("READINESS_APPROVAL_INPUT_REQUIRED")
    try:
        packet = validate_approval_packet(approval.get("packet"))
    except CoordinationError as exc:
        raise ReadinessError(str(exc)) from exc
    planner = current_endpoint(connection, "planner")
    if planner is None:
        raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
    planner_endpoint = str(planner["endpoint_id"])
    material_boundary = str(approval["material_boundary"])
    expected_scope = readiness_execution_scope_sha256(
        repository=str(campaign["repository"]),
        issue_number=int(campaign["issue_number"]),
        source_payload_sha256=str(campaign["source_payload_sha256"]),
        campaign_id=int(campaign["id"]),
        generation=int(campaign["generation"]),
        item_version=int(campaign["item_version"]),
        accepted_main_sha=str(campaign["accepted_main_sha"]),
        graph_version=int(campaign["graph_version"]),
        capacity_policy_version=int(campaign["capacity_policy_version"]),
        candidate_sha256=str(campaign["candidate_sha256"]),
        worker_role=str(campaign["worker_role"]),
        worker_endpoint_id=str(campaign["endpoint_id"]),
        worker_attempt_id=str(terminal_attempt["attempt_id"]),
        parent_plan_sha256=str(campaign["plan_sha256"]),
        material_boundary=material_boundary,
    )
    expected_decision_key = (
        f"issue-{int(campaign['issue_number'])}:readiness-campaign-"
        f"{int(campaign['id'])}:{material_boundary.casefold().replace('_', '-')}"
    )
    if (
        packet["decision_key"] != expected_decision_key
        or packet["repository"] != campaign["repository"]
        or int(packet["owning_issue"]) != int(campaign["issue_number"])
        or packet["source_snapshot_sha256"]
        != campaign["source_payload_sha256"]
        or packet["execution_scope_sha256"] != expected_scope
        or packet["requester_session_id"] != campaign["endpoint_id"]
        or packet["recipient_session_id"] != planner_endpoint
        or packet["workstream"] != "READINESS"
        or packet["boundary"] != material_boundary
        or packet["urgency"] != "READY_BLOCKER"
        or int(campaign["issue_number"]) not in packet["affected_issues"]
        or terminal_attempt["endpoint_id"] != campaign["endpoint_id"]
        or terminal_attempt["role"] != campaign["worker_role"]
    ):
        raise ReadinessError("READINESS_APPROVAL_INPUT_BINDING_INVALID")
    return packet, expected_scope, planner_endpoint


def _planner_notice(
    store: CoordinationStore,
    campaign: sqlite3.Row,
    receipt: dict[str, Any],
    receipt_sha: str,
    *,
    now: str,
) -> int:
    planner = current_endpoint(store.connection, "planner")
    if planner is None:
        raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
    verdict = str(receipt["verdict"])
    action_set_sha256 = digest_json(receipt["resolution"]["actions"])
    evidence = {
        "readiness_plan_sha256": campaign["plan_sha256"],
        "readiness_receipt_sha256": receipt_sha,
        "verdict": verdict,
        "resolution_role": receipt["resolution"]["role"],
        "resolution_item_count": len(receipt["resolution"]["actions"]),
        "resolution_action_set_sha256": action_set_sha256,
    }
    payload = {
        "source": {
            "repository": campaign["repository"],
            "object_kind": "issue",
            "object_number": int(campaign["issue_number"]),
            "payload_sha256": campaign["source_payload_sha256"],
        },
        "notice_kind": "status",
        "mutation_authority": False,
        "subject": f"Issue {int(campaign['issue_number'])} readiness phase result",
        "summary": "One bounded candidate-level readiness evidence bundle is complete.",
        "evidence": evidence,
        "next_observation": (
            "Planner guard review remains pending."
            if verdict == "PASS"
            else "One consolidated Planner review remains pending."
            if verdict == "ACTIONABLE_HOLD"
            else "The material-decision ledger entry remains pending."
            if verdict == "APPROVAL_REQUIRED"
            else "The terminal blocker remains preserved for portfolio disposition."
        ),
    }
    return store.enqueue_message(
        idempotency_key=f"kanban-readiness-planner:{receipt_sha}",
        recipient_session_id=str(planner["endpoint_id"]),
        topic="coordination.notice",
        payload=payload,
        now=now,
        _transaction=False,
    )


def _record_staged_receipt(
    store: CoordinationStore,
    receipt: dict[str, Any],
    artifact: dict[str, Any],
    *,
    now: str,
) -> dict[str, Any]:
    """Commit one authenticated STAGED artifact and one Planner continuation."""

    _validate_receipt(receipt)
    connection = store.connection
    ensure_schema(connection)
    if receipt["verdict"] == "APPROVAL_REQUIRED":
        ensure_approval_schema(connection)
    receipt_sha = digest_json(receipt)
    if (
        artifact.get("artifact_sha256") != receipt_sha
        or artifact.get("raw") != canonical_json(receipt).encode("utf-8")
    ):
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_DIGEST_INVALID")
    _assert_artifact_current(artifact)
    with store.transaction():
        campaign = _campaign(
            connection, str(receipt["repository"]), int(receipt["issue_number"])
        )
        if campaign["plan_sha256"] != receipt["readiness_plan_sha256"]:
            raise ReadinessError("READINESS_RECEIPT_CAMPAIGN_DRIFT")
        if campaign["state"] in {
            "READY_ELIGIBLE", "FINALIZED", "RESOLUTION_PENDING", "APPROVAL_PENDING", "HOLD"
        }:
            prior = connection.execute(
                "SELECT receipt_sha256 FROM portfolio_readiness_receipts WHERE id=?",
                (campaign["receipt_id"],),
            ).fetchone()
            if prior is not None and prior["receipt_sha256"] == receipt_sha:
                pickup = connection.execute(
                    "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
                    (int(campaign["id"]),),
                ).fetchone()
                if (
                    pickup is None
                    or pickup["state"] != "RECORDED"
                    or pickup["relative_path"] != artifact["relative_path"]
                    or not _artifact_matches_pickup(pickup, artifact)
                ):
                    raise ReadinessError("READINESS_RECEIPT_PICKUP_REPLAY_INVALID")
                _assert_artifact_current(artifact)
                return {
                    "repository": receipt["repository"],
                    "issue_number": receipt["issue_number"],
                    "verdict": receipt["verdict"],
                    "receipt_sha256": receipt_sha,
                    "state": campaign["state"],
                    "replay": True,
                }
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if campaign["state"] != "RUNNING":
            raise ReadinessError("READINESS_PHASE_STATE_CONFLICT")
        if (
            campaign["worker_role"] != receipt["worker_role"]
            or int(campaign["message_id"]) != int(receipt["message_id"])
            or campaign["attempt_id"] != receipt["attempt_id"]
        ):
            raise ReadinessError("READINESS_RECEIPT_ATTEMPT_DRIFT")
        pickup = connection.execute(
            "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
            (int(campaign["id"]),),
        ).fetchone()
        locator = _receipt_locator(campaign)
        if (
            pickup is None
            or pickup["state"] != "STAGED"
            or int(pickup["message_id"]) != int(receipt["message_id"])
            or pickup["attempt_id"] != receipt["attempt_id"]
            or pickup["locator_sha256"] != digest_json(locator)
            or pickup["relative_path"] != locator["relative_path"]
            or artifact["relative_path"] != pickup["relative_path"]
            or not _artifact_matches_pickup(pickup, artifact)
        ):
            raise ReadinessError("READINESS_RECEIPT_PICKUP_BINDING_INVALID")
        reasons = _binding_reasons(connection, campaign)
        if reasons:
            _mark_stale(connection, campaign, reasons, now)
            return {
                "repository": receipt["repository"],
                "issue_number": receipt["issue_number"],
                "verdict": None,
                "receipt_sha256": None,
                "state": "STALE",
                "binding_reasons": reasons,
            }
        _message, terminal_attempt = _validate_attempt(
            connection,
            campaign,
            int(receipt["message_id"]),
            str(receipt["attempt_id"]),
            terminal=True,
        )
        if (
            not isinstance(pickup["attempt_token_sha256"], str)
            or not isinstance(terminal_attempt["token_sha256"], str)
            or not secrets.compare_digest(
                pickup["attempt_token_sha256"], terminal_attempt["token_sha256"]
            )
        ):
            raise ReadinessError("READINESS_RECEIPT_PICKUP_TOKEN_INVALID")
        expected_gates = {
            row["gate_key"]
            for row in connection.execute(
                "SELECT gate_key FROM portfolio_readiness_gates WHERE campaign_id=?",
                (int(campaign["id"]),),
            )
        }
        received_gates = {result["gate_key"] for result in receipt["gate_results"]}
        if expected_gates != received_gates:
            raise ReadinessError("READINESS_RECEIPT_GATE_COVERAGE_INVALID")
        proposal: str | None = None
        approval_submission_sha256: str | None = None
        approval_packet: dict[str, Any] | None = None
        approval_scope: str | None = None
        approval_planner_endpoint: str | None = None
        planner_message_id: int | None = None
        if receipt["verdict"] == "APPROVAL_REQUIRED":
            packet, expected_scope, planner_endpoint = _approval_input_for_campaign(
                connection, campaign, receipt, terminal_attempt
            )
            try:
                submission = submit_readiness_proposal_in_transaction(
                    store,
                    packet,
                    expected_requester_session_id=str(campaign["endpoint_id"]),
                    expected_recipient_session_id=planner_endpoint,
                    expected_execution_scope_sha256=expected_scope,
                    now=now,
                )
            except CoordinationError as exc:
                raise ReadinessError(str(exc)) from exc
            proposal = str(submission["proposal_sha256"])
            approval_submission_sha256 = str(submission["submission_sha256"])
            approval_packet = packet
            approval_scope = expected_scope
            approval_planner_endpoint = planner_endpoint
            if submission.get("planner_message_id") is None:
                raise ReadinessError("READINESS_APPROVAL_NOTICE_MISSING")
            planner_message_id = int(submission["planner_message_id"])
        action_set_sha256 = _validate_resolution_action_bindings(
            connection,
            campaign,
            receipt["resolution"]["actions"],
            approval_scope_sha256=approval_scope,
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO portfolio_readiness_receipts(
                campaign_id, verdict, worker_role, message_id, attempt_id,
                resolution_role, resolution_action_set_sha256,
                approval_proposal_sha256, receipt_sha256,
                receipt_json, observed_at, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(campaign["id"]), receipt["verdict"], receipt["worker_role"],
                receipt["message_id"], receipt["attempt_id"],
                receipt["resolution"]["role"], action_set_sha256,
                proposal, receipt_sha,
                canonical_json(receipt), receipt["observed_at"], now,
            ),
        )
        receipt_row = connection.execute(
            "SELECT id FROM portfolio_readiness_receipts WHERE receipt_sha256=?",
            (receipt_sha,),
        ).fetchone()
        actionable_state = (
            "HOLD"
            if int(campaign["resolution_cycles"]) >= MAX_RESOLUTION_CYCLES
            else "RESOLUTION_PENDING"
        )
        state = {
            "PASS": "READY_ELIGIBLE",
            "ACTIONABLE_HOLD": actionable_state,
            "APPROVAL_REQUIRED": "APPROVAL_PENDING",
            "TERMINAL_HOLD": "HOLD",
        }[receipt["verdict"]]
        cursor = connection.execute(
            """
            UPDATE portfolio_readiness_current
            SET state=?, receipt_id=?, version=version+1, updated_at=?, last_error=?
            WHERE campaign_id=? AND state='RUNNING' AND version=?
            """,
            (
                state, int(receipt_row["id"]), now,
                None if state == "READY_ELIGIBLE" else receipt["summary"],
                int(campaign["id"]), int(campaign["current_version"]),
            ),
        )
        if cursor.rowcount != 1:
            raise ReadinessError("READINESS_PHASE_FENCE_LOST")
        if receipt["verdict"] == "APPROVAL_REQUIRED":
            if (
                approval_packet is None
                or approval_scope is None
                or approval_planner_endpoint is None
                or approval_submission_sha256 is None
                or proposal is None
            ):
                raise ReadinessError("READINESS_APPROVAL_BINDING_MISSING")
            connection.execute(
                """
                INSERT INTO portfolio_readiness_approval_requests(
                    campaign_id, receipt_id, repository, issue_number,
                    source_payload_sha256, expected_approval_pending_version,
                    proposal_sha256, submission_sha256, execution_scope_sha256,
                    boundary, requester_session_id,
                    packet_recipient_session_id, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    int(campaign["id"]), int(receipt_row["id"]),
                    str(campaign["repository"]), int(campaign["issue_number"]),
                    str(campaign["source_payload_sha256"]),
                    int(campaign["current_version"]) + 1,
                    proposal, approval_submission_sha256, approval_scope,
                    str(approval_packet["boundary"]),
                    str(campaign["endpoint_id"]), approval_planner_endpoint, now,
                ),
            )
        _assert_artifact_current(artifact)
        pickup_cursor = connection.execute(
            """
            UPDATE portfolio_readiness_receipt_pickups
            SET state='RECORDED', receipt_id=?, next_attempt_at=NULL,
                version=version+1, updated_at=?, last_error=NULL
            WHERE campaign_id=? AND state='STAGED' AND message_id=?
              AND attempt_id=? AND version=?
            """,
            (
                int(receipt_row["id"]), now, int(campaign["id"]),
                int(receipt["message_id"]),
                receipt["attempt_id"], int(pickup["version"]),
            ),
        )
        if pickup_cursor.rowcount != 1:
            raise ReadinessError("READINESS_RECEIPT_PICKUP_FENCE_LOST")
        if planner_message_id is None:
            planner_message_id = _planner_notice(
                store, campaign, receipt, receipt_sha, now=now
            )
        if receipt["verdict"] == "ACTIONABLE_HOLD" and state == "RESOLUTION_PENDING":
            planner = current_endpoint(connection, "planner")
            if planner is None:
                raise ReadinessError("CURRENT_PLANNER_ENDPOINT_REQUIRED")
            connection.execute(
                """
                INSERT INTO portfolio_readiness_resolution_notices(
                    campaign_id, receipt_id, action_set_sha256, message_id,
                    routed_endpoint_id, expected_readiness_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(campaign["id"]), int(receipt_row["id"]),
                    action_set_sha256, planner_message_id,
                    str(planner["endpoint_id"]),
                    int(campaign["current_version"]) + 1, now,
                ),
            )
        _event(
            connection,
            int(campaign["id"]),
            "READINESS_PHASE_COMPLETED",
            {
                "verdict": receipt["verdict"],
                "receipt_sha256": receipt_sha,
                "planner_message_id": planner_message_id,
                "artifact_relative_path": artifact["relative_path"],
                "artifact_sha256": artifact["artifact_sha256"],
            },
            now,
        )
        _assert_artifact_current(artifact)
    return {
        "repository": receipt["repository"],
        "issue_number": receipt["issue_number"],
        "verdict": receipt["verdict"],
        "receipt_sha256": receipt_sha,
        "state": state,
        "planner_message_id": planner_message_id,
        "replay": False,
    }


def _receipt_from_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    try:
        receipt = json.loads(
            bytes(artifact["raw"]).decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_INVALID") from exc
    if not isinstance(receipt, dict):
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_INVALID")
    _validate_receipt(receipt)
    if canonical_json(receipt).encode("utf-8") != artifact["raw"]:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_NONCANONICAL")
    if digest_json(receipt) != artifact["artifact_sha256"]:
        raise ReadinessError("READINESS_RECEIPT_ARTIFACT_DIGEST_INVALID")
    return receipt


def pickup_receipt(
    store: CoordinationStore, campaign_id: int, *, now: str
) -> dict[str, Any]:
    """Record one exact staged artifact only after its worker is terminal."""

    ensure_schema(store.connection)
    row = store.connection.execute(
        """
        SELECT campaign.*, current.state, current.message_id, current.attempt_id,
               current.endpoint_id, current.receipt_id,
               current.resolution_cycles, current.version AS current_version,
               current.updated_at, current.last_error,
               current.finalized_candidate_id, current.finalized_event_id,
               current.finalized_at, pickup.locator_sha256,
               pickup.relative_path AS pickup_relative_path,
               pickup.state AS pickup_state, pickup.version AS pickup_version
        FROM portfolio_readiness_campaigns campaign
        JOIN portfolio_readiness_current current ON current.campaign_id=campaign.id
        JOIN portfolio_readiness_receipt_pickups pickup
          ON pickup.campaign_id=campaign.id
        WHERE campaign.id=?
        """,
        (campaign_id,),
    ).fetchone()
    if row is None:
        raise ReadinessError("READINESS_RECEIPT_PICKUP_MISSING")
    if row["state"] != "RUNNING" or row["pickup_state"] != "STAGED":
        raise ReadinessError("READINESS_RECEIPT_PICKUP_STATE_CONFLICT")
    pickup = store.connection.execute(
        "SELECT * FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
        (campaign_id,),
    ).fetchone()
    if pickup is None:
        raise ReadinessError("READINESS_RECEIPT_PICKUP_MISSING")
    locator = _receipt_locator(row)
    if (
        row["locator_sha256"] != digest_json(locator)
        or row["pickup_relative_path"] != locator["relative_path"]
    ):
        raise ReadinessError("READINESS_RECEIPT_PICKUP_BINDING_INVALID")
    _message, attempt = _validate_attempt(
        store.connection,
        row,
        int(row["message_id"]),
        str(row["attempt_id"]),
        terminal=True,
    )
    if (
        not isinstance(pickup["attempt_token_sha256"], str)
        or not isinstance(attempt["token_sha256"], str)
        or not secrets.compare_digest(
            pickup["attempt_token_sha256"], attempt["token_sha256"]
        )
    ):
        raise ReadinessError("READINESS_RECEIPT_PICKUP_TOKEN_INVALID")
    artifact = _open_staged_artifact(store.path, str(row["pickup_relative_path"]))
    try:
        if not _artifact_matches_pickup(pickup, artifact):
            raise ReadinessError("READINESS_RECEIPT_ARTIFACT_CHANGED")
        receipt = _receipt_from_artifact(artifact)
        return _record_staged_receipt(store, receipt, artifact, now=now)
    finally:
        _close_artifact(artifact)


def _record_pickup_failure(
    store: CoordinationStore,
    campaign_id: int,
    error: str,
    *,
    now: str,
) -> dict[str, Any]:
    with store.transaction():
        row = store.connection.execute(
            """
            SELECT pickup.*, current.state AS campaign_state,
                   current.version AS current_version,
                   message.state AS message_state, attempt.state AS attempt_state
            FROM portfolio_readiness_receipt_pickups pickup
            JOIN portfolio_readiness_current current
              ON current.campaign_id=pickup.campaign_id
            JOIN coordination_messages message ON message.id=pickup.message_id
            JOIN executor_attempts attempt ON attempt.attempt_id=pickup.attempt_id
            WHERE pickup.campaign_id=?
            """,
            (campaign_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] not in {"PENDING", "STAGED"}
            or row["campaign_state"] != "RUNNING"
            or row["message_state"] != "COMPLETE"
            or row["attempt_state"] != "COMPLETE"
        ):
            return {"campaign_id": campaign_id, "state": "SKIPPED"}
        attempts = int(row["attempts"]) + 1
        exhausted = attempts >= MAX_RECEIPT_PICKUP_ATTEMPTS
        prior_pickup_state = str(row["state"])
        pickup_state = "HOLD" if exhausted else prior_pickup_state
        next_attempt_at = (
            None
            if exhausted
            else timestamp_after(
                now,
                RECEIPT_PICKUP_RETRY_SECONDS * (2 ** max(0, attempts - 1)),
            )
        )
        changed = store.connection.execute(
            """
            UPDATE portfolio_readiness_receipt_pickups
            SET state=?, attempts=?, next_attempt_at=?, version=version+1,
                updated_at=?, last_error=?
            WHERE campaign_id=? AND state=? AND version=?
            """,
            (
                pickup_state, attempts, next_attempt_at, now, error,
                campaign_id, prior_pickup_state, int(row["version"]),
            ),
        ).rowcount
        if changed != 1:
            raise ReadinessError("READINESS_RECEIPT_PICKUP_FENCE_LOST")
        current_state = "HOLD" if exhausted else "RUNNING"
        current_changed = store.connection.execute(
            """
            UPDATE portfolio_readiness_current
            SET state=?, version=version+1, updated_at=?, last_error=?
            WHERE campaign_id=? AND state='RUNNING' AND version=?
            """,
            (
                current_state, now, error, campaign_id,
                int(row["current_version"]),
            ),
        ).rowcount
        if current_changed != 1:
            raise ReadinessError("READINESS_PHASE_FENCE_LOST")
        _event(
            store.connection,
            campaign_id,
            "READINESS_RECEIPT_PICKUP_HELD" if exhausted
            else "READINESS_RECEIPT_PICKUP_RETRY",
            {"attempts": attempts, "error": error},
            now,
        )
    return {
        "campaign_id": campaign_id,
        "state": pickup_state,
        "attempts": attempts,
        "next_attempt_at": next_attempt_at,
        "error": error,
    }


def pickup_due_receipts(
    store: CoordinationStore,
    *,
    now: str,
    limit: int = MAX_RECEIPT_PICKUPS_PER_SCAN,
) -> dict[str, Any]:
    """Mechanically discover terminal readiness attempts and record artifacts."""

    if limit <= 0 or limit > MAX_RECEIPT_PICKUPS_PER_SCAN:
        raise ReadinessError("READINESS_RECEIPT_PICKUP_LIMIT_INVALID")
    ensure_schema(store.connection)
    rows = store.connection.execute(
        """
        SELECT pickup.campaign_id, pickup.state
        FROM portfolio_readiness_receipt_pickups pickup
        JOIN portfolio_readiness_current current
          ON current.campaign_id=pickup.campaign_id
        JOIN coordination_messages message ON message.id=pickup.message_id
        JOIN executor_attempts attempt ON attempt.attempt_id=pickup.attempt_id
        WHERE pickup.state IN ('PENDING','STAGED') AND current.state='RUNNING'
          AND message.state='COMPLETE' AND attempt.state='COMPLETE'
          AND (pickup.next_attempt_at IS NULL OR pickup.next_attempt_at<=?)
        ORDER BY pickup.campaign_id
        LIMIT ?
        """,
        (now, limit),
    ).fetchall()
    recorded: list[dict[str, Any]] = []
    retried: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []
    for row in rows:
        campaign_id = int(row["campaign_id"])
        try:
            if row["state"] == "PENDING":
                raise ReadinessError("READINESS_RECEIPT_NOT_STAGED")
            recorded.append(pickup_receipt(store, campaign_id, now=now))
        except (ReadinessError, OSError, sqlite3.Error) as exc:
            error = (
                str(exc)
                if isinstance(exc, ReadinessError)
                else "READINESS_RECEIPT_ARTIFACT_INVALID"
            )
            failure = _record_pickup_failure(
                store, campaign_id, error, now=now
            )
            if failure["state"] == "HOLD":
                held.append(failure)
            elif failure["state"] in {"PENDING", "STAGED"}:
                retried.append(failure)
    return {
        "limit": limit,
        "recorded": recorded,
        "retried": retried,
        "held": held,
    }


def _mark_stale(
    connection: sqlite3.Connection,
    campaign: sqlite3.Row,
    reasons: list[str],
    now: str,
) -> None:
    error = ",".join(sorted(set(reasons)))
    cursor = connection.execute(
        """
        UPDATE portfolio_readiness_current
        SET state='STALE', version=version+1, updated_at=?, last_error=?
        WHERE campaign_id=? AND state!='STALE'
        """,
        (now, error, int(campaign["id"])),
    )
    if cursor.rowcount:
        _event(
            connection,
            int(campaign["id"]),
            "READINESS_PHASE_STALE",
            {"reasons": sorted(set(reasons))},
            now,
        )


def evaluate(
    connection: sqlite3.Connection,
    repository: str,
    issue_number: int,
    *,
    now: str,
    record_state: bool,
) -> dict[str, Any]:
    if record_state:
        ensure_schema(connection)
    else:
        require_schema(connection)
    if record_state:
        connection.execute("BEGIN IMMEDIATE")
    try:
        campaign = _campaign(connection, repository, issue_number)
        reasons = _binding_reasons(connection, campaign)
        protected_state = campaign["state"] in {
            "APPROVAL_PENDING",
            "HOLD",
            "FINALIZED",
        }
        # Exact decision/disposition or finalized-recovery handlers own these
        # states. Generic observation reports drift but cannot rewrite them to
        # STALE and thereby open the ordinary STALE -> REFRESH successor edge
        # or strand an already finalized READY candidate.
        state = (
            campaign["state"]
            if protected_state
            else "STALE"
            if reasons
            else campaign["state"]
        )
        if record_state and reasons and not protected_state:
            _mark_stale(connection, campaign, reasons, now)
        if record_state:
            connection.execute("COMMIT")
    except Exception:
        if record_state and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    gates = [
        {
            "gate_key": row["gate_key"],
            "description": row["description"],
            "requested_evidence": json.loads(row["requested_evidence_json"]),
        }
        for row in connection.execute(
            """
            SELECT gate_key, description, requested_evidence_json
            FROM portfolio_readiness_gates WHERE campaign_id=? ORDER BY id
            """,
            (int(campaign["id"]),),
        )
    ]
    return {
        "repository": repository,
        "issue_number": issue_number,
        "plan_sha256": campaign["plan_sha256"],
        "state": state,
        "binding_reasons": reasons,
        "gates": gates,
        "promotion_allowed": state == "READY_ELIGIBLE",
        "finalized": state == "FINALIZED",
    }


def show(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    require_schema(connection)
    rows = connection.execute(
        """
        SELECT campaign.issue_number, campaign.generation, campaign.plan_sha256,
               campaign.candidate_sha256, campaign.worker_role, current.state,
               current.message_id, current.attempt_id, current.endpoint_id,
               current.resolution_cycles, current.version, current.updated_at,
               current.last_error, current.finalized_candidate_id,
               current.finalized_event_id, current.finalized_at,
               pickup.state AS receipt_pickup_state,
               pickup.attempts AS receipt_pickup_attempts,
               pickup.relative_path AS receipt_relative_path,
               pickup.artifact_sha256 AS receipt_artifact_sha256,
               pickup.last_error AS receipt_pickup_last_error
        FROM portfolio_readiness_current current
        JOIN portfolio_readiness_campaigns campaign ON campaign.id=current.campaign_id
        LEFT JOIN portfolio_readiness_receipt_pickups pickup
          ON pickup.campaign_id=campaign.id
        WHERE current.repository=? ORDER BY campaign.issue_number
        """,
        (repository,),
    ).fetchall()
    return {"repository": repository, "campaigns": [dict(row) for row in rows]}
