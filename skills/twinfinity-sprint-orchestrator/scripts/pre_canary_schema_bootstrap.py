#!/usr/bin/env python3
"""Fenced bootstrap for the exact pre-canary coordination schema.

This command intentionally has no database selector and no generic migration
surface.  It recognizes one source-bound 79-table predecessor, creates the two
missing accepted tables, installs one explicit v1 semantic pointer, and appends
one replay-binding event.  The retired broker schema is evidence only: it must
be complete, exact, and empty and is never projected as authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Mapping, Sequence

from approval_ledger import (
    LEGACY_SCHEMA,
    ensure_schema as ensure_approval_schema,
)
from coordination_store import (
    DEFAULT_DATABASE,
    _normalized_schema_sql,
    canonical_json,
    digest_json,
)
from coordination_truth_snapshot import (
    BROKER_QUARANTINE_SCHEMA_MANIFEST_SHA256,
    BROKER_QUARANTINE_TABLES,
    EXPECTED_DEFAULT_MANIFEST_SHA256,
    EXPECTED_SCHEMA_SHA256,
    SIDECAR_FREE_WAL_READ_BOUNDARY,
    SnapshotHold,
    _descriptor_file_identity,
    _file_identity,
    _filesystem_state,
    _journal_contract,
    _open_pinned_immutable_database_readonly,
    _regular_file_descriptor_identities,
    _require_sqlite_opened_pinned_identity,
    _schema_record,
    _stable_file_tuple,
    _validate_filesystem_effect,
)
from kanban_pull_buffer import ensure_pull_buffer_schema
from owner_safe_sqlite import UnsafeSQLitePathError, validate_owner_database


REQUEST_SCHEMA = "twinfinity.pre-canary-schema-bootstrap-request.v1"
PREVIEW_SCHEMA = "twinfinity.pre-canary-schema-bootstrap-preview.v1"
RECEIPT_SCHEMA = "twinfinity.pre-canary-schema-bootstrap-receipt.v1"
PREDECESSOR_SENTINEL_SCHEMA = (
    "twinfinity.pre-canary-schema-bootstrap-predecessor-sentinel.v1"
)
RESULT_SENTINEL_SCHEMA = (
    "twinfinity.pre-canary-schema-bootstrap-result-sentinel.v1"
)
HOLD_SCHEMA = "twinfinity.pre-canary-schema-bootstrap-hold.v1"
REPOSITORY = "jayendusharma/twinfinity-harness"
EVENT_TYPE = "PRE_CANARY_SCHEMA_BOOTSTRAP_APPLIED"
EVENT_ENTITY_PREFIX = "pre-canary-schema-bootstrap:"
MISSING_TABLES = (
    "approval_semantic_contract_current",
    "portfolio_ready_quarantines",
)
MISSING_SCHEMA_OBJECT_MANIFEST_SHA256 = (
    "ff41d7528e276913613e61216089d1736c6e5acba55f652664d3ddc3b0b8f94b"
)
PREDECESSOR_DEFAULT_MANIFEST_SHA256 = (
    "d277985296e8fa0997a46d252f0a07cf8c9f23210ded2a4db18525722c99e7af"
)
PREDECESSOR_SCHEMA_SENTINEL_SHA256 = (
    "f1d51c3f5ec50fdd439ebec01cbd3cec572c9b28bfea6b3cb4b61a5b6b77d5ae"
)
RESULT_SCHEMA_SENTINEL_SHA256 = (
    "a182a57c547e2a3692604fa84dc4daa9ffba45fc50e08a0b264415122a35291d"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
OPERATION_KEY = re.compile(r"^[a-z0-9][a-z0-9._:/-]{7,159}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DATABASE_IDENTITY_KEYS = {
    "device",
    "inode",
    "mode",
    "uid",
    "gid",
    "links",
    "size",
    "mtime_ns",
    "ctime_ns",
    "sha256",
}
REQUEST_KEYS = {
    "schema",
    "repository",
    "accepted_harness_main_sha",
    "database_identity",
    "stopped_state_evidence_sha256",
    "predecessor_schema_sentinel_sha256",
    "broker_schema_manifest_sha256",
    "broker_row_counts",
    "missing_tables",
    "v1_authority_sha256",
    "v1_activated_at",
    "operation_key",
    "rollback_evidence_sha256",
}
APPLY_FAILPOINTS = (
    "before_writable_open",
    "after_begin",
    "after_approval_semantic_contract_current",
    "after_approval_semantic_contract_triggers",
    "after_portfolio_ready_quarantines",
    "after_portfolio_ready_quarantine_triggers",
    "after_v1_pointer",
    "after_receipt_event",
    "before_commit",
)


class BootstrapHold(ValueError):
    """One stable, value-free, fail-closed bootstrap outcome."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
        result[key] = value
    return result


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _request_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != DATABASE_IDENTITY_KEYS:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
    integer_keys = DATABASE_IDENTITY_KEYS - {"sha256"}
    if any(type(value.get(key)) is not int for key in integer_keys):
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
    if (
        value["device"] < 0
        or value["inode"] <= 0
        or value["mode"] != 0o600
        or value["uid"] != os.getuid()
        or value["gid"] < 0
        or value["links"] != 1
        or value["size"] <= 0
        or value["mtime_ns"] < 0
        or value["ctime_ns"] < 0
        or not isinstance(value.get("sha256"), str)
        or SHA256.fullmatch(value["sha256"]) is None
    ):
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
    return {key: value[key] for key in sorted(value)}


def validate_request(value: Any) -> dict[str, Any]:
    """Validate the sole closed bootstrap request shape."""

    expected_counts = {table: 0 for table in BROKER_QUARANTINE_TABLES}
    if not isinstance(value, dict) or set(value) != REQUEST_KEYS:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
    counts = value.get("broker_row_counts")
    counts_exact = (
        isinstance(counts, dict)
        and set(counts) == set(expected_counts)
        and all(type(counts[table]) is int and counts[table] == 0 for table in counts)
    )
    if (
        value.get("schema") != REQUEST_SCHEMA
        or value.get("repository") != REPOSITORY
        or not isinstance(value.get("accepted_harness_main_sha"), str)
        or GIT_SHA1.fullmatch(value["accepted_harness_main_sha"]) is None
        or value.get("predecessor_schema_sentinel_sha256")
        != PREDECESSOR_SCHEMA_SENTINEL_SHA256
        or value.get("broker_schema_manifest_sha256")
        != BROKER_QUARANTINE_SCHEMA_MANIFEST_SHA256
        or not counts_exact
        or value.get("missing_tables") != list(MISSING_TABLES)
        or not isinstance(value.get("v1_authority_sha256"), str)
        or SHA256.fullmatch(value["v1_authority_sha256"]) is None
        or not _valid_timestamp(value.get("v1_activated_at"))
        or not isinstance(value.get("operation_key"), str)
        or OPERATION_KEY.fullmatch(value["operation_key"]) is None
    ):
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
    for key in (
        "stopped_state_evidence_sha256",
        "rollback_evidence_sha256",
    ):
        if not isinstance(value.get(key), str) or SHA256.fullmatch(value[key]) is None:
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
    normalized = {
        key: (
            _request_identity(value[key])
            if key == "database_identity"
            else dict(value[key])
            if key == "broker_row_counts"
            else list(value[key])
            if key == "missing_tables"
            else value[key]
        )
        for key in sorted(value)
    }
    return normalized


def load_request(path: Path) -> dict[str, Any]:
    """Load canonical request bytes from one owner-only regular file."""

    descriptor: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > 64 * 1024
        ):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_FILE_UNSAFE")
        raw = b""
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            raw += block
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        request = validate_request(value)
        if raw.decode("utf-8") != canonical_json(request):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID")
        return request
    except BootstrapHold:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_INVALID") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _expected_predecessor_tables() -> list[dict[str, str]]:
    return [
        {"table": table, "schema_sha256": EXPECTED_SCHEMA_SHA256[table]}
        for table in sorted(set(EXPECTED_SCHEMA_SHA256) - set(MISSING_TABLES))
    ]


def _predecessor_sentinel() -> dict[str, Any]:
    return {
        "schema": PREDECESSOR_SENTINEL_SCHEMA,
        "accepted_tables": _expected_predecessor_tables(),
        "defaults_sha256": PREDECESSOR_DEFAULT_MANIFEST_SHA256,
        "missing_tables": list(MISSING_TABLES),
        "broker_schema_manifest_sha256": (
            BROKER_QUARANTINE_SCHEMA_MANIFEST_SHA256
        ),
        "broker_row_counts": {
            table: 0 for table in BROKER_QUARANTINE_TABLES
        },
    }


def _result_sentinel() -> dict[str, Any]:
    return {
        "schema": RESULT_SENTINEL_SCHEMA,
        "accepted_tables": [
            {"table": table, "schema_sha256": EXPECTED_SCHEMA_SHA256[table]}
            for table in sorted(EXPECTED_SCHEMA_SHA256)
        ],
        "defaults_sha256": EXPECTED_DEFAULT_MANIFEST_SHA256,
        "broker_schema_manifest_sha256": (
            BROKER_QUARANTINE_SCHEMA_MANIFEST_SHA256
        ),
        "broker_row_counts": {
            table: 0 for table in BROKER_QUARANTINE_TABLES
        },
    }


def _require_source_sentinels() -> None:
    if (
        digest_json(_predecessor_sentinel())
        != PREDECESSOR_SCHEMA_SENTINEL_SHA256
        or digest_json(_result_sentinel()) != RESULT_SCHEMA_SENTINEL_SHA256
    ):
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_SOURCE_SENTINEL_DRIFT")


def _objects_owned_by_missing_tables(
    connection: sqlite3.Connection,
) -> list[dict[str, str]]:
    """Return the complete explicit schema-object family for both new tables."""

    placeholders = ",".join("?" for _ in MISSING_TABLES)
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        f"WHERE sql IS NOT NULL AND tbl_name IN ({placeholders}) "
        "AND type IN ('table','index','trigger') ORDER BY type,name",
        MISSING_TABLES,
    ).fetchall()
    return [
        {
            "type": str(row["type"]),
            "name": str(row["name"]),
            "table": str(row["tbl_name"]),
            "sql": str(row["sql"]),
        }
        for row in rows
    ]


def _schema_object_manifest(
    objects: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    return [
        {
            **{key: item[key] for key in ("type", "name", "table")},
            "sql": _normalized_schema_sql(item["sql"]),
        }
        for item in objects
    ]


def _canonical_missing_objects() -> list[dict[str, str]]:
    """Derive the complete six-object family from accepted source initializers."""

    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        ensure_approval_schema(connection)
        ensure_pull_buffer_schema(connection)
        objects = _objects_owned_by_missing_tables(connection)
        manifest = _schema_object_manifest(objects)
        if (
            len(objects) != 6
            or digest_json(manifest)
            != MISSING_SCHEMA_OBJECT_MANIFEST_SHA256
        ):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_SOURCE_SENTINEL_DRIFT")
        return objects
    finally:
        connection.close()


def _broker_state(connection: sqlite3.Connection) -> dict[str, int]:
    placeholders = ",".join("?" for _ in BROKER_QUARANTINE_TABLES)
    objects = [
        {
            "type": str(row[0]),
            "name": str(row[1]),
            "table": str(row[2]),
            "sql": _normalized_schema_sql(str(row[3])),
        }
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            f"WHERE sql IS NOT NULL AND tbl_name IN ({placeholders}) "
            "AND type IN ('table','index','trigger') ORDER BY type,name",
            BROKER_QUARANTINE_TABLES,
        )
    ]
    if digest_json(objects) != BROKER_QUARANTINE_SCHEMA_MANIFEST_SHA256:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_BROKER_SCHEMA_DRIFT")
    counts: dict[str, int] = {}
    for table in BROKER_QUARANTINE_TABLES:
        row = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()
        if row is None or type(row[0]) is not int:
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_BROKER_SCHEMA_DRIFT")
        counts[table] = int(row[0])
    if counts != {table: 0 for table in BROKER_QUARANTINE_TABLES}:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_BROKER_NONEMPTY")
    return counts


def _accepted_schema_state(
    connection: sqlite3.Connection,
) -> tuple[str, dict[str, int]]:
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        )
    }
    accepted = set(EXPECTED_SCHEMA_SHA256)
    broker = set(BROKER_QUARANTINE_TABLES)
    predecessor = accepted - set(MISSING_TABLES) | broker
    result = accepted | broker
    broker_present = present & broker
    if broker_present and broker_present != broker:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_BROKER_PARTIAL")
    if present == predecessor:
        state = "PREDECESSOR"
        expected_defaults = PREDECESSOR_DEFAULT_MANIFEST_SHA256
    elif present == result:
        state = "RESULT"
        expected_defaults = EXPECTED_DEFAULT_MANIFEST_SHA256
    else:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_SCHEMA_SET_DRIFT")
    for table in sorted(present & accepted):
        if digest_json(_schema_record(connection, table)) != (
            EXPECTED_SCHEMA_SHA256[table]
        ):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_ACCEPTED_SCHEMA_DRIFT")
    defaults = [
        {
            "table": table,
            "columns": [
                {"name": str(row[1]), "default": row[4]}
                for row in connection.execute(f'PRAGMA table_xinfo("{table}")')
            ],
        }
        for table in sorted(present & accepted)
    ]
    if digest_json(defaults) != expected_defaults:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_ACCEPTED_SCHEMA_DRIFT")
    if state == "RESULT":
        objects = _objects_owned_by_missing_tables(connection)
        if (
            len(objects) != 6
            or digest_json(_schema_object_manifest(objects))
            != MISSING_SCHEMA_OBJECT_MANIFEST_SHA256
        ):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_RESULT_SCHEMA_DRIFT")
    return state, _broker_state(connection)


def _bootstrap_events(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT event_type,entity_key,payload_sha256,created_at "
        "FROM approval_events WHERE event_type=? ORDER BY id",
        (EVENT_TYPE,),
    ).fetchall()


def _pointer(connection: sqlite3.Connection) -> dict[str, Any] | None:
    rows = connection.execute(
        "SELECT singleton,schema,authority_sha256,activated_at "
        "FROM approval_semantic_contract_current ORDER BY singleton"
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_POINTER_CONFLICT")
    return {
        "singleton": int(rows[0]["singleton"]),
        "schema": rows[0]["schema"],
        "authority_sha256": rows[0]["authority_sha256"],
        "activated_at": rows[0]["activated_at"],
    }


def _preview(request: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": PREVIEW_SCHEMA,
        "request": request,
        "request_sha256": digest_json(request),
        "predecessor_schema_sentinel_sha256": (
            PREDECESSOR_SCHEMA_SENTINEL_SHA256
        ),
        "missing_schema_object_manifest_sha256": (
            MISSING_SCHEMA_OBJECT_MANIFEST_SHA256
        ),
        "result_schema_sentinel_sha256": RESULT_SCHEMA_SENTINEL_SHA256,
        "target_pointer": {
            "singleton": 1,
            "schema": LEGACY_SCHEMA,
            "authority_sha256": request["v1_authority_sha256"],
            "activated_at": request["v1_activated_at"],
        },
        "state": "READY_OR_EXACT_REPLAY",
    }
    return {**body, "preview_sha256": digest_json(body)}


def _receipt(request: dict[str, Any], preview: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": RECEIPT_SCHEMA,
        "request": request,
        "request_sha256": preview["request_sha256"],
        "preview_sha256": preview["preview_sha256"],
        "predecessor_schema_sentinel_sha256": (
            PREDECESSOR_SCHEMA_SENTINEL_SHA256
        ),
        "missing_schema_object_manifest_sha256": (
            MISSING_SCHEMA_OBJECT_MANIFEST_SHA256
        ),
        "result_schema_sentinel_sha256": RESULT_SCHEMA_SENTINEL_SHA256,
        "created_tables": list(MISSING_TABLES),
        "result_table_count": 81,
        "result_pointer": preview["target_pointer"],
        "broker_schema_manifest_sha256": (
            BROKER_QUARANTINE_SCHEMA_MANIFEST_SHA256
        ),
        "broker_row_counts": {
            table: 0 for table in BROKER_QUARANTINE_TABLES
        },
        "state": "APPLIED",
    }
    return {**body, "receipt_sha256": digest_json(body)}


def _require_identity(
    expected: Mapping[str, Any], observed: Mapping[str, Any], *, replay: bool
) -> None:
    keys = (
        {"device", "inode", "mode", "uid", "gid", "links"}
        if replay
        else DATABASE_IDENTITY_KEYS
    )
    if any(expected[key] != observed[key] for key in keys):
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_DATABASE_IDENTITY_DRIFT")


def _require_result(
    connection: sqlite3.Connection,
    request: dict[str, Any],
    preview: dict[str, Any],
) -> dict[str, Any]:
    pointer = _pointer(connection)
    expected_pointer = preview["target_pointer"]
    events = _bootstrap_events(connection)
    if pointer != expected_pointer:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_POINTER_CONFLICT")
    if len(events) != 1:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_RECEIPT_INVALID")
    receipt = _receipt(request, preview)
    event = events[0]
    if (
        event["entity_key"] != EVENT_ENTITY_PREFIX + request["operation_key"]
        or event["created_at"] != request["v1_activated_at"]
        or event["payload_sha256"] != receipt["receipt_sha256"]
    ):
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_RECEIPT_INVALID")
    return receipt


def _read_state(
    connection: sqlite3.Connection,
    request: dict[str, Any],
    preview: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    state, counts = _accepted_schema_state(connection)
    if counts != request["broker_row_counts"]:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_BROKER_COUNT_DRIFT")
    if state == "PREDECESSOR":
        if _bootstrap_events(connection):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_RECEIPT_INVALID")
        return state, None
    return state, _require_result(connection, request, preview)


def _validated_database() -> tuple[Path, dict[str, Any], str]:
    try:
        database = validate_owner_database(DEFAULT_DATABASE)
        before = _filesystem_state(database)
        journal = _journal_contract(
            database, before, SIDECAR_FREE_WAL_READ_BOUNDARY
        )
    except SnapshotHold as exc:
        raise BootstrapHold(str(exc)) from exc
    except (OSError, UnsafeSQLitePathError) as exc:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_DATABASE_UNSAFE") from exc
    return database, before, journal


def preview_schema_bootstrap(value: Any) -> dict[str, Any]:
    """Preview the exact predecessor or exact replay with zero durable effect."""

    request = validate_request(value)
    _require_source_sentinels()
    _canonical_missing_objects()
    preview = _preview(request)
    database, before, journal = _validated_database()
    connection: sqlite3.Connection | None = None
    descriptor: int | None = None
    failure: BaseException | None = None
    try:
        connection, descriptor = _open_pinned_immutable_database_readonly(
            database, before["files"]["database"]
        )
        connection.execute("BEGIN")
        state, _receipt_value = _read_state(connection, request, preview)
        _require_identity(
            request["database_identity"],
            _descriptor_file_identity(descriptor),
            replay=state == "RESULT",
        )
        connection.execute("ROLLBACK")
    except BaseException as exc:
        failure = exc
    finally:
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()
            except BaseException as exc:
                failure = exc
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                failure = exc
        try:
            _validate_filesystem_effect(before, _filesystem_state(database), journal)
        except BaseException as exc:
            failure = exc
    if failure is not None:
        if isinstance(failure, BootstrapHold):
            raise failure
        if isinstance(failure, SnapshotHold):
            raise BootstrapHold(str(failure)) from failure
        if isinstance(failure, sqlite3.Error):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_SQLITE_INVALID") from failure
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_PREVIEW_FAILED") from failure
    return preview


def _apply_failpoint(step: str) -> None:
    """Private test seam; production has no caller-controlled failpoint."""

    if step not in APPLY_FAILPOINTS:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_INTERNAL_FAILPOINT_INVALID")


def _require_anchor(
    descriptor: int,
    database: Path,
    expected: Mapping[str, Any],
    *,
    replay: bool,
) -> None:
    try:
        observed = _descriptor_file_identity(descriptor)
        _require_identity(expected, observed, replay=replay)
        _require_identity(expected, _file_identity(database), replay=replay)
        if _stable_file_tuple(os.fstat(descriptor)) != _stable_file_tuple(
            database.lstat()
        ):
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_DATABASE_IDENTITY_DRIFT")
    except (OSError, SnapshotHold) as exc:
        if isinstance(exc, BootstrapHold):
            raise
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_DATABASE_IDENTITY_DRIFT") from exc


def apply_schema_bootstrap(
    value: Any,
    *,
    expected_request_sha256: str,
    expected_preview_sha256: str,
) -> dict[str, Any]:
    """Apply the one fixed bootstrap atomically, or return its exact replay."""

    request = validate_request(value)
    _require_source_sentinels()
    objects = _canonical_missing_objects()
    preview = _preview(request)
    if expected_request_sha256 != preview["request_sha256"]:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_REQUEST_DIGEST_DRIFT")
    if expected_preview_sha256 != preview["preview_sha256"]:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_PREVIEW_DIGEST_DRIFT")
    database, before, _journal = _validated_database()
    connection: sqlite3.Connection | None = None
    anchor: int | None = None
    try:
        readonly, anchor = _open_pinned_immutable_database_readonly(
            database, before["files"]["database"]
        )
        try:
            readonly.execute("BEGIN")
            state, replay_receipt = _read_state(readonly, request, preview)
            _require_identity(
                request["database_identity"],
                _descriptor_file_identity(anchor),
                replay=state == "RESULT",
            )
            readonly.execute("ROLLBACK")
        finally:
            if readonly.in_transaction:
                readonly.execute("ROLLBACK")
            readonly.close()
        _require_anchor(
            anchor,
            database,
            request["database_identity"],
            replay=state == "RESULT",
        )
        if state == "RESULT":
            assert replay_receipt is not None
            return replay_receipt

        _apply_failpoint("before_writable_open")
        before_open = _regular_file_descriptor_identities()
        try:
            connection = sqlite3.connect(
                f"{database.as_uri()}?mode=rw",
                uri=True,
                isolation_level=None,
                timeout=5,
            )
        except sqlite3.Error as exc:
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_DATABASE_UNSAFE") from exc
        connection.row_factory = sqlite3.Row
        anchor_metadata = os.fstat(anchor)
        expected_sqlite_identity = (
            int(anchor_metadata.st_dev),
            int(anchor_metadata.st_ino),
            int(anchor_metadata.st_mode),
            int(anchor_metadata.st_uid),
            int(anchor_metadata.st_nlink),
        )
        _require_sqlite_opened_pinned_identity(
            connection, before_open, expected_sqlite_identity
        )
        _require_anchor(
            anchor, database, request["database_identity"], replay=False
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        _apply_failpoint("after_begin")
        transaction_state, _ = _read_state(connection, request, preview)
        if transaction_state != "PREDECESSOR":
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_STATE_DRIFT")

        by_name = {item["name"]: item for item in objects}
        connection.execute(by_name["approval_semantic_contract_current"]["sql"])
        _apply_failpoint("after_approval_semantic_contract_current")
        for name in (
            "approval_semantic_contract_no_delete",
            "approval_semantic_contract_no_downgrade",
        ):
            connection.execute(by_name[name]["sql"])
        _apply_failpoint("after_approval_semantic_contract_triggers")
        connection.execute(by_name["portfolio_ready_quarantines"]["sql"])
        _apply_failpoint("after_portfolio_ready_quarantines")
        for name in (
            "portfolio_ready_quarantines_immutable_delete",
            "portfolio_ready_quarantines_immutable_update",
        ):
            connection.execute(by_name[name]["sql"])
        _apply_failpoint("after_portfolio_ready_quarantine_triggers")

        connection.execute(
            "INSERT INTO approval_semantic_contract_current("
            "singleton,schema,authority_sha256,activated_at) VALUES (1,?,?,?)",
            (
                LEGACY_SCHEMA,
                request["v1_authority_sha256"],
                request["v1_activated_at"],
            ),
        )
        _apply_failpoint("after_v1_pointer")
        receipt = _receipt(request, preview)
        connection.execute(
            "INSERT INTO approval_events("
            "event_type,entity_key,payload_sha256,created_at) VALUES (?,?,?,?)",
            (
                EVENT_TYPE,
                EVENT_ENTITY_PREFIX + request["operation_key"],
                receipt["receipt_sha256"],
                request["v1_activated_at"],
            ),
        )
        _apply_failpoint("after_receipt_event")
        final_state, stored_receipt = _read_state(connection, request, preview)
        if final_state != "RESULT" or stored_receipt != receipt:
            raise BootstrapHold("PRE_CANARY_BOOTSTRAP_RESULT_INVALID")
        _apply_failpoint("before_commit")
        _require_anchor(
            anchor, database, request["database_identity"], replay=True
        )
        connection.execute("COMMIT")
        return receipt
    except BootstrapHold:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except SnapshotHold as exc:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise BootstrapHold(str(exc)) from exc
    except sqlite3.Error as exc:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_OPERATION_CONFLICT") from exc
    finally:
        if connection is not None:
            connection.close()
        if anchor is not None:
            os.close(anchor)


def database_identity(path: Path) -> dict[str, Any]:
    """Return the request-safe identity for an already quiescent test target."""

    try:
        database = validate_owner_database(path)
        state = _filesystem_state(database)
        _journal_contract(database, state, SIDECAR_FREE_WAL_READ_BOUNDARY)
        identity = state["files"]["database"]
    except (OSError, UnsafeSQLitePathError, SnapshotHold) as exc:
        raise BootstrapHold("PRE_CANARY_BOOTSTRAP_DATABASE_UNSAFE") from exc
    return {key: identity[key] for key in sorted(DATABASE_IDENTITY_KEYS)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    preview_parser = subparsers.add_parser("preview")
    preview_parser.add_argument("--request", type=Path, required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--request", type=Path, required=True)
    apply_parser.add_argument("--expected-request-sha256", required=True)
    apply_parser.add_argument("--expected-preview-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        request = load_request(args.request)
        if args.command == "preview":
            result = preview_schema_bootstrap(request)
        else:
            result = apply_schema_bootstrap(
                request,
                expected_request_sha256=args.expected_request_sha256,
                expected_preview_sha256=args.expected_preview_sha256,
            )
    except BootstrapHold as exc:
        print(canonical_json({
            "schema": HOLD_SCHEMA,
            "state": "HOLD",
            "error": str(exc),
        }))
        return 1
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
