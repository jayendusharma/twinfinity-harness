#!/usr/bin/env python3
"""Fail-closed audit for retiring legacy canonical-session UUID routing."""

from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from typing import Any

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    digest_json,
    routing_endpoint_state_digest,
)

from executor_registry import (
    DEFAULT_DATABASE,
    DEFAULT_LEGACY_ALIASES,
    ROLES,
    RegistryError,
    UUID,
    attempt_lineage_for_target,
    attempt_schema_is_current,
    canonical_json,
    current_endpoint,
    identity_role,
    load_registry_config,
    open_registry_database,
    stable_systemd_unit,
)
from hosted_operation_control import (
    HostedOperationControl,
    hosted_execution_scope_sha256,
)
from legacy_ack_compat import inspect_legacy_ack_rows
from routing_deprecation_inventory import (
    InventoryError,
    PageReader,
    github_page_reader,
    load_alias_artifact,
    outbox_idempotency_key,
    published_receipt_body,
    receipt_body,
    stable_scan_repository,
)
from routing_inventory_contract import RoutingInventoryContractError, validate_inventory_record


EXECUTABLE_TOPICS = {
    "development.admission",
    "development.recovery_prepare",
    "development.recovery_commit",
    "development.terminal_closeout",
    "sre.admission",
}
SCRIPT_ROOT = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_ROOT.parent
CANONICAL_PLANNER_GOAL = Path(
    "/home/ubuntu/.codex/twinfinity-coordination/product-planner-goal.md"
)
CANONICAL_AGENTS = Path("/home/ubuntu/.codex/AGENTS.md")
CommentReader = Any

ACTIONABLE_MESSAGE_STATES = {"PREPARED", "CLAIMED"}
ACTIONABLE_HOSTED_OPERATION_STATES = {"PREPARED", "CLAIMED"}
SHA256 = re.compile(r"[0-9a-f]{64}")
SYSTEMD_INVOCATION_ID = re.compile(r"[0-9a-f]{32}")
LOCAL_DIGEST_TABLES = (
    "ack_turns",
    "approval_deliveries",
    "coordination_items",
    "coordination_messages",
    "coordination_terminal_watches",
    "executor_attempt_events",
    "executor_attempts",
    "executor_role_endpoint_aliases",
    "executor_role_endpoint_current",
    "executor_role_endpoints",
    "github_outbox",
    "hosted_operations",
    "portfolio_pull_buffer_candidates",
    "portfolio_pull_buffer_current",
    "routing_deprecation_inventories",
    "routing_deprecation_occurrences",
    "routing_deprecation_current",
    "routing_deprecation_promotions",
)


@contextmanager
def _stable_read_snapshot(connection: sqlite3.Connection):
    """Hold one local SQLite read snapshot and always release it locally."""

    if connection.in_transaction:
        raise CoordinationError("ARCHIVE_READINESS_TRANSACTION_ACTIVE")
    connection.execute("BEGIN")
    try:
        yield
    finally:
        if connection.in_transaction:
            connection.execute("ROLLBACK")


def _digest_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest()}
    return value


def _local_state_digest(connection: sqlite3.Connection) -> str:
    """Digest only local state that can change an archive-readiness decision."""

    table_names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    manifest: list[dict[str, Any]] = []
    for table in LOCAL_DIGEST_TABLES:
        if table not in table_names:
            manifest.append({"table": table, "present": False})
            continue
        quoted = '"' + table.replace('"', '""') + '"'
        schema = [
            {
                "type": str(row[0]),
                "name": str(row[1]),
                "sql": None if row[2] is None else str(row[2]),
            }
            for row in connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE tbl_name=? ORDER BY type, name",
                (table,),
            ).fetchall()
        ]
        columns = [
            str(row[1])
            for row in connection.execute(f"PRAGMA table_info({quoted})").fetchall()
        ]
        rows = [
            [_digest_value(value) for value in row]
            for row in connection.execute(f"SELECT * FROM {quoted}").fetchall()
        ]
        rows.sort(key=canonical_json)
        manifest.append({
            "table": table,
            "present": True,
            "schema": schema,
            "columns": columns,
            "rows": rows,
        })
    return digest_json(manifest)


def _operational_markdown() -> tuple[Path, ...]:
    return (
        SKILL_ROOT / "SKILL.md",
        SKILL_ROOT / "README.md",
        *sorted((SKILL_ROOT / "references").glob("*.md")),
        CANONICAL_PLANNER_GOAL,
        CANONICAL_AGENTS,
    )


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _contains_alias(value: Any, aliases: set[str]) -> bool:
    if isinstance(value, dict):
        return any(_contains_alias(child, aliases) for child in value.values())
    if isinstance(value, list):
        return any(_contains_alias(child, aliases) for child in value)
    return isinstance(value, str) and any(alias in value for alias in aliases)


def _legacy_source_commands(
    paths: tuple[Path, ...] | None = None,
) -> list[dict[str, Any]]:
    """Find installed executable vectors that still resume a legacy role constant."""

    findings: list[dict[str, Any]] = []
    source_paths = paths or tuple(sorted(SCRIPT_ROOT.glob("*.py")))
    for path in source_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            findings.append({
                "kind": "source_audit_error",
                "path": f"scripts/{path.name}",
                "error": "LEGACY_COMMAND_SOURCE_UNREADABLE",
            })
            continue
        exec_commands: set[str] = set()
        resume_commands: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
            elif isinstance(node, ast.AugAssign):
                targets = [node.target]
                value = node.value
            else:
                continue
            if value is None:
                continue
            names = {
                target.id for target in targets if isinstance(target, ast.Name)
            }
            constants = {
                child.value for child in ast.walk(value)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            }
            for name in names:
                if "exec" in constants:
                    exec_commands.add(name)
                if "resume" in constants:
                    resume_commands[name] = int(getattr(node, "lineno", 0))
        command_names = exec_commands & set(resume_commands)
        if command_names:
            name = sorted(command_names)[0]
            findings.append({
                "kind": "legacy_resume_command",
                "path": f"scripts/{path.name}",
                "line": resume_commands[name],
            })
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.List, ast.Tuple)):
                continue
            constants = {
                child.value for child in ast.walk(node)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            }
            names = {
                child.id for child in ast.walk(node) if isinstance(child, ast.Name)
            }
            if {"exec", "resume"}.issubset(constants) and "SRE_SESSION" in names:
                findings.append({
                    "kind": "legacy_resume_command",
                    "path": f"scripts/{path.name}",
                    "line": int(getattr(node, "lineno", 0)),
                })
                break
    return findings


def _legacy_markdown_vectors(
    paths: tuple[Path, ...] | None = None,
) -> list[dict[str, Any]]:
    """Find positive executable legacy ACK/session instructions in operator docs."""

    patterns = (
        re.compile(r"scripts/(?:run_ack_only_turn|run_ack_only_transaction|build_ack_transaction_contract)\.py"),
        re.compile(r"twinfinity-ack-only\.config\.toml"),
        re.compile(r"--session-id\s+<[^>]*(?:UUID|session)[^>]*>", re.IGNORECASE),
        re.compile(
            r"\b(?:run|invoke|execute|launch|use)\b[^\n]*\bcodex\s+exec\s+resume\b",
            re.IGNORECASE,
        ),
    )
    findings: list[dict[str, Any]] = []
    for path in paths or _operational_markdown():
        try:
            display_path = str(path.relative_to(SKILL_ROOT))
        except ValueError:
            display_path = str(path)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            findings.append({
                "kind": "documentation_audit_error",
                "path": display_path,
                "error": (
                    "CANONICAL_PLANNER_GOAL_MISSING"
                    if path == CANONICAL_PLANNER_GOAL and not path.exists()
                    else "OPERATIONAL_MARKDOWN_UNREADABLE"
                ),
            })
            continue
        for line_number, line in enumerate(lines, 1):
            if any(pattern.search(line) for pattern in patterns):
                findings.append({
                    "kind": "legacy_operational_instruction",
                    "path": display_path,
                    "line": line_number,
                })
    return findings


def _current_kanban_routing(
    connection: sqlite3.Connection, aliases: set[str]
) -> list[dict[str, Any]]:
    if not _table_exists(connection, "portfolio_pull_buffer_current"):
        return []
    database = connection.execute("PRAGMA database_list").fetchone()
    if database is None or not database[2] or database[2] == ":memory:":
        return [{"kind": "kanban_candidate", "error": "KANBAN_ARTIFACT_UNREADABLE"}]
    root = Path(str(database[2])).parent.resolve()
    findings: list[dict[str, Any]] = []
    rows = connection.execute(
        """
        SELECT c.id, c.repository, c.issue_number, c.state,
               c.artifact_relative_path, c.artifact_content_sha256
        FROM portfolio_pull_buffer_current current
        JOIN portfolio_pull_buffer_candidates c ON c.id=current.candidate_id
        WHERE c.state='READY' ORDER BY c.repository, c.issue_number
        """
    ).fetchall()
    for row in rows:
        relative = Path(str(row["artifact_relative_path"]))
        path = (root / relative).resolve()
        error: str | None = None
        value: Any = None
        descriptor = -1
        try:
            if relative.is_absolute() or root not in path.parents:
                raise OSError
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise OSError
            raw = b""
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                raw += chunk
            if hashlib.sha256(raw).hexdigest() != row["artifact_content_sha256"]:
                raise OSError
            value = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            error = "KANBAN_ARTIFACT_UNREADABLE"
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if error is not None or _contains_alias(value, aliases):
            finding = {
                "kind": "kanban_candidate",
                "candidate_id": int(row["id"]),
                "repository": row["repository"],
                "issue_number": int(row["issue_number"]),
            }
            if error is not None:
                finding["error"] = error
            findings.append(finding)
    return findings


def github_comment_reader(
    repository: str, issue_number: int, comment_id: int
) -> dict[str, Any]:
    completed = subprocess.run(
        ["gh", "api", f"repos/{repository}/issues/comments/{comment_id}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise InventoryError("ROUTING_DEPRECATION_RECEIPT_READ_FAILED")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise InventoryError("ROUTING_DEPRECATION_RECEIPT_INVALID") from exc
    if not isinstance(value, dict):
        raise InventoryError("ROUTING_DEPRECATION_RECEIPT_INVALID")
    return value


def _routing_inventory_local_gate(
    connection: sqlite3.Connection,
    *,
    alias_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    required = {
        "routing_deprecation_inventories",
        "routing_deprecation_occurrences",
        "routing_deprecation_current",
        "routing_deprecation_promotions",
        "github_outbox",
    }
    if not all(_table_exists(connection, table) for table in required):
        return [{"error": "ROUTING_DEPRECATION_INVENTORY_REQUIRED"}], None
    rows = connection.execute(
        "SELECT * FROM routing_deprecation_inventories ORDER BY repository,generation"
    ).fetchall()
    currents = connection.execute("SELECT * FROM routing_deprecation_current").fetchall()
    if not rows or len(currents) != 1:
        return [{"error": "ROUTING_DEPRECATION_INVENTORY_LINEAGE_INVALID"}], None
    current = currents[0]
    if type(current["generation"]) is not int or type(current["version"]) is not int or current["generation"] < 1 or current["version"] != current["generation"]:
        return [{"error": "ROUTING_DEPRECATION_INVENTORY_LINEAGE_INVALID"}], None
    matching = [item for item in rows if item["repository"] == current["repository"] and int(item["generation"]) == int(current["generation"]) and item["inventory_sha256"] == current["inventory_sha256"]]
    if len(matching) != 1 or int(current["generation"]) != len(rows):
        return [{"error": "ROUTING_DEPRECATION_INVENTORY_LINEAGE_INVALID"}], None
    expected_generation = 1
    predecessor = None
    for historic in rows:
        if int(historic["generation"]) != expected_generation or historic["predecessor_inventory_sha256"] != predecessor:
            return [{"error": "ROUTING_DEPRECATION_INVENTORY_LINEAGE_INVALID"}], None
        promotion = connection.execute("SELECT * FROM routing_deprecation_promotions WHERE repository=? AND generation=? AND inventory_sha256=?", (historic["repository"], historic["generation"], historic["inventory_sha256"])).fetchone()
        expected_prior = None if expected_generation == 1 else expected_generation - 1
        if promotion is None or promotion["prior_generation"] != expected_prior:
            return [{"error": "ROUTING_DEPRECATION_INVENTORY_LINEAGE_INVALID"}], None
        historic_occurrence_rows = connection.execute(
            "SELECT * FROM routing_deprecation_occurrences WHERE inventory_sha256=? ORDER BY ordinal",
            (historic["inventory_sha256"],),
        ).fetchall()
        try:
            historic_inventory, historic_occurrences = validate_inventory_record(historic, historic_occurrence_rows)
            historic_objects = historic_inventory["object_manifest"]
        except RoutingInventoryContractError:
            return [{"error": "ROUTING_DEPRECATION_HISTORY_CORRUPT"}], None
        if (digest_json(historic_objects) != historic["object_manifest_sha256"]
                or digest_json(historic_occurrences) != historic["occurrence_manifest_sha256"]
                or len(historic_occurrences) != int(historic["occurrence_count"])):
            return [{"error": "ROUTING_DEPRECATION_HISTORY_CORRUPT"}], None
        preview = {
            "repository": historic["repository"], "generation": int(historic["generation"]),
            "predecessor_inventory_sha256": historic["predecessor_inventory_sha256"],
            "inventory_sha256": historic["inventory_sha256"],
            "alias_source_sha256": historic["alias_source_sha256"],
            "endpoint_state_sha256": historic["endpoint_state_sha256"],
            "issue_179_source_sha256": historic["issue_179_source_sha256"],
            "object_manifest_sha256": historic["object_manifest_sha256"],
            "occurrence_manifest_sha256": historic["occurrence_manifest_sha256"],
        }
        preview_sha256 = digest_json(preview)
        outbox = connection.execute("SELECT * FROM github_outbox WHERE id=?", (historic["outbox_id"],)).fetchone()
        try:
            payload = None if outbox is None else json.loads(outbox["payload_json"])
        except (TypeError, json.JSONDecodeError):
            payload = None
        if (historic["preview_sha256"] != preview_sha256
                or promotion["preview_sha256"] != preview_sha256
                or outbox is None or outbox["state"] != "COMPLETE"
                or outbox["repository"] != historic["repository"] or outbox["object_kind"] != "issue"
                or int(outbox["object_number"]) != 179 or outbox["operation"] != "comment"
                or outbox["expected_source_sha256"] != historic["issue_179_source_sha256"]
                or outbox["idempotency_key"] != outbox_idempotency_key(historic_inventory)
                or payload != {"body": receipt_body(historic_inventory)}
                or outbox["payload_sha256"] != digest_json(payload)
                or re.fullmatch(r"comment:[1-9][0-9]*", str(outbox["remote_receipt"])) is None
                or promotion["remote_receipt"] != outbox["remote_receipt"]):
            return [{"error": "ROUTING_DEPRECATION_HISTORY_CORRUPT"}], None
        predecessor = historic["inventory_sha256"]
        expected_generation += 1
    row = matching[0]
    try:
        objects = json.loads(row["object_manifest_json"])
        classification_counts = json.loads(row["classification_counts_json"])
        semantic_tag_counts = json.loads(row["semantic_tag_counts_json"])
        occurrence_rows = connection.execute(
            "SELECT * FROM routing_deprecation_occurrences "
            "WHERE inventory_sha256=? ORDER BY ordinal",
            (row["inventory_sha256"],),
        ).fetchall()
        occurrences = [
            {
                "ordinal": int(item["ordinal"]),
                "object_kind": item["object_kind"],
                "object_number": int(item["object_number"]),
                "node_id": item["node_id"],
                "body_sha256": item["body_sha256"],
                "alias": item["alias"],
                "byte_start": int(item["byte_start"]),
                "byte_end": int(item["byte_end"]),
                "line_number": int(item["line_number"]),
                "byte_column": int(item["byte_column"]),
                "classification": item["classification"],
                "semantic_tags": json.loads(item["semantic_tags_json"]),
            }
            for item in occurrence_rows
        ]
    except (TypeError, ValueError, json.JSONDecodeError):
        return [{"error": "ROUTING_DEPRECATION_INVENTORY_INVALID"}], None
    inventory = {
        "kind": row["kind"],
        "repository": row["repository"],
        "alias_source_sha256": row["alias_source_sha256"],
        "endpoint_state_sha256": row["endpoint_state_sha256"],
        "issue_179_source_sha256": row["issue_179_source_sha256"],
        "object_manifest_sha256": row["object_manifest_sha256"],
        "occurrence_manifest_sha256": row["occurrence_manifest_sha256"],
        "object_manifest": objects,
        "object_count": int(row["object_count"]),
        "issue_count": int(row["issue_count"]),
        "pull_request_count": int(row["pull_request_count"]),
        "occurrence_count": int(row["occurrence_count"]),
        "classification_counts": classification_counts,
        "semantic_tag_counts": semantic_tag_counts,
    }
    inventory["inventory_sha256"] = row["inventory_sha256"]
    findings: list[dict[str, Any]] = []
    object_fields = {"object_kind", "object_number", "node_id", "body_sha256"}
    objects_valid = isinstance(objects, list) and all(
        isinstance(item, dict)
        and set(item) == object_fields
        and item["object_kind"] in {"issue", "pull_request"}
        and isinstance(item["object_number"], int)
        and item["object_number"] > 0
        and isinstance(item["node_id"], str)
        and bool(item["node_id"])
        and re.fullmatch(r"[0-9a-f]{64}", str(item["body_sha256"])) is not None
        for item in objects
    )
    expected_classifications = {
        name: sum(item["classification"] == name for item in occurrences)
        for name in (
            "EXECUTABLE_ROUTE",
            "ROUTING_REFERENCE",
            "HISTORICAL_PROVENANCE",
            "AMBIGUOUS_REFERENCE",
        )
    }
    expected_tags = {
        name: sum(name in item["semantic_tags"] for item in occurrences)
        for name in ("ACCEPTANCE", "APPROVAL", "DEPENDENCY", "HOLD", "SCOPE")
    }
    if (
        row["state"] != "COMPLETE"
        or row["kind"] != "TWINFINITY_ROUTING_DEPRECATION_INVENTORY_V1"
        or not objects_valid
        or [item["ordinal"] for item in occurrences] != list(range(len(occurrences)))
        or digest_json(objects) != row["object_manifest_sha256"]
        or digest_json(occurrences) != row["occurrence_manifest_sha256"]
        or digest_json({key: value for key, value in inventory.items() if key != "inventory_sha256"})
        != row["inventory_sha256"]
        or len(objects) != int(row["object_count"])
        or len(occurrences) != int(row["occurrence_count"])
        or sum(item["object_kind"] == "issue" for item in objects)
        != int(row["issue_count"])
        or sum(item["object_kind"] == "pull_request" for item in objects)
        != int(row["pull_request_count"])
        or classification_counts != expected_classifications
        or semantic_tag_counts != expected_tags
        or any(item["object_updated_at"] != row["created_at"] for item in occurrence_rows)
    ):
        findings.append({"error": "ROUTING_DEPRECATION_INVENTORY_INVALID"})
    try:
        aliases = load_alias_artifact(alias_path)
        if aliases.source_sha256 != row["alias_source_sha256"]:
            findings.append({"error": "ROUTING_DEPRECATION_ALIAS_DRIFT"})
        if routing_endpoint_state_digest(connection) != row["endpoint_state_sha256"]:
            findings.append({"error": "ROUTING_DEPRECATION_ENDPOINT_DRIFT"})
    except (CoordinationError, InventoryError):
        aliases = None
        findings.append({"error": "ROUTING_DEPRECATION_ALIAS_OR_ENDPOINT_INVALID"})
    outbox = connection.execute(
        "SELECT * FROM github_outbox WHERE id=?", (row["outbox_id"],)
    ).fetchone()
    if outbox is None:
        findings.append({"error": "ROUTING_DEPRECATION_OUTBOX_MISSING"})
    else:
        try:
            payload = json.loads(outbox["payload_json"])
        except (TypeError, json.JSONDecodeError):
            payload = None
        if (
            outbox["state"] != "COMPLETE"
            or outbox["repository"] != row["repository"]
            or outbox["object_kind"] != "issue"
            or int(outbox["object_number"]) != 179
            or outbox["expected_source_sha256"] != row["issue_179_source_sha256"]
            or outbox["idempotency_key"] != outbox_idempotency_key(inventory)
            or payload != {"body": receipt_body(inventory)}
            or outbox["payload_sha256"] != digest_json(payload)
            or not isinstance(outbox["remote_receipt"], str)
            or re.fullmatch(r"comment:[1-9][0-9]*", outbox["remote_receipt"]) is None
        ):
            findings.append({"error": "ROUTING_DEPRECATION_OUTBOX_INVALID"})
    context = {
        "repository": str(row["repository"]),
        "objects": objects,
        "occurrences": occurrences,
        "object_manifest_sha256": str(row["object_manifest_sha256"]),
        "occurrence_manifest_sha256": str(row["occurrence_manifest_sha256"]),
        "inventory": inventory,
        "aliases": None if aliases is None else dict(aliases.aliases),
        "remote_receipt": (
            None if outbox is None or not isinstance(outbox["remote_receipt"], str)
            else str(outbox["remote_receipt"])
        ),
    }
    return findings, context


def _routing_inventory_external_gate(
    context: dict[str, Any] | None,
    *,
    page_reader: PageReader | None,
    comment_reader: CommentReader | None,
) -> list[dict[str, Any]]:
    if context is None:
        return []
    findings: list[dict[str, Any]] = []
    if page_reader is None or comment_reader is None:
        findings.append({"error": "ROUTING_DEPRECATION_LIVE_READER_REQUIRED"})
        return findings
    aliases = context["aliases"]
    if aliases is not None:
        try:
            live = stable_scan_repository(
                context["repository"], aliases, page_reader
            )
            if (
                live["object_manifest"] != context["objects"]
                or live["occurrences"] != context["occurrences"]
                or live["object_manifest_sha256"]
                != context["object_manifest_sha256"]
                or live["occurrence_manifest_sha256"]
                != context["occurrence_manifest_sha256"]
            ):
                findings.append({"error": "ROUTING_DEPRECATION_OCCURRENCE_DRIFT"})
        except InventoryError:
            findings.append({"error": "ROUTING_DEPRECATION_LIVE_SCAN_INVALID"})
    remote_receipt = context["remote_receipt"]
    if remote_receipt is not None:
        match = re.fullmatch(r"comment:([1-9][0-9]*)", remote_receipt)
        if match is not None:
            try:
                comment = comment_reader(
                    context["repository"], 179, int(match.group(1))
                )
                expected_issue_url = (
                    f"https://api.github.com/repos/{context['repository']}/issues/179"
                )
                if (
                    not isinstance(comment, dict)
                    or comment.get("id") != int(match.group(1))
                    or comment.get("body")
                    != published_receipt_body(context["inventory"])
                    or comment.get("issue_url") != expected_issue_url
                ):
                    findings.append({"error": "ROUTING_DEPRECATION_RECEIPT_MISMATCH"})
            except InventoryError:
                findings.append({"error": "ROUTING_DEPRECATION_RECEIPT_MISSING"})
    return findings


def _attempt_event_integrity_error(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> str | None:
    """Validate the opaque attempt identity and its append-only event chain."""

    required_attempt_columns = {
        "attempt_id", "instance_id", "token_sha256", "role", "target_kind",
        "target_key", "state", "process_id", "systemd_unit",
        "systemd_invocation_id", "systemd_control_group", "heartbeat_at",
        "version", "created_at", "updated_at", "last_error",
    }
    required_event_columns = {
        "event_id", "attempt_id", "from_state", "to_state", "from_version",
        "to_version", "reason", "evidence_sha256", "evidence_json",
        "recorded_at",
    }
    if not required_attempt_columns.issubset(row.keys()) or not required_event_columns.issubset({
        str(item[1])
        for item in connection.execute(
            "PRAGMA table_info(executor_attempt_events)"
        ).fetchall()
    }):
        return "ACTIVE_ATTEMPT_IDENTITY_INVALID"
    try:
        version = int(row["version"])
    except (TypeError, ValueError):
        return "ACTIVE_ATTEMPT_IDENTITY_INVALID"
    if (
        UUID.fullmatch(str(row["attempt_id"])) is None
        or UUID.fullmatch(str(row["instance_id"])) is None
        or SHA256.fullmatch(str(row["token_sha256"])) is None
        or version <= 0
        or not isinstance(row["created_at"], str)
        or not row["created_at"]
        or not isinstance(row["heartbeat_at"], str)
        or not row["heartbeat_at"]
        or not isinstance(row["updated_at"], str)
        or not row["updated_at"]
    ):
        return "ACTIVE_ATTEMPT_IDENTITY_INVALID"

    state = str(row["state"])
    unit = row["systemd_unit"]
    invocation_id = row["systemd_invocation_id"]
    control_group = row["systemd_control_group"]
    process_id = row["process_id"]
    expected_unit = stable_systemd_unit(
        str(row["role"]), str(row["target_kind"]), str(row["target_key"])
    )
    if state == "RESERVED":
        if any(value is not None for value in (unit, invocation_id, control_group, process_id)):
            return "ACTIVE_ATTEMPT_RUNTIME_IDENTITY_INVALID"
    elif state == "LAUNCHING":
        if (
            unit != expected_unit
            or SYSTEMD_INVOCATION_ID.fullmatch(str(invocation_id)) is None
            or not isinstance(control_group, str)
            or not control_group.endswith(f"/{unit}")
            or process_id is not None
        ):
            return "ACTIVE_ATTEMPT_RUNTIME_IDENTITY_INVALID"
    elif state == "RUNNING":
        if (
            unit != expected_unit
            or SYSTEMD_INVOCATION_ID.fullmatch(str(invocation_id)) is None
            or not isinstance(control_group, str)
            or not control_group.endswith(f"/{unit}")
            or type(process_id) is not int
            or process_id <= 0
        ):
            return "ACTIVE_ATTEMPT_RUNTIME_IDENTITY_INVALID"
    else:
        return "ACTIVE_ATTEMPT_STATE_INVALID"

    events = connection.execute(
        "SELECT * FROM executor_attempt_events WHERE attempt_id=? "
        "ORDER BY to_version, event_id",
        (row["attempt_id"],),
    ).fetchall()
    if len(events) != version:
        return "ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID"
    allowed = {
        "RESERVED": {"LAUNCHING", "LAUNCH_FAILED", "HOLD"},
        "LAUNCHING": {"RUNNING", "LAUNCH_FAILED", "HOLD"},
        "RUNNING": {"RUNNING", "COMPLETE", "HOLD"},
    }
    previous_state: str | None = None
    for expected_version, event in enumerate(events, 1):
        evidence_json = event["evidence_json"]
        evidence_sha256 = event["evidence_sha256"]
        try:
            to_version = int(event["to_version"])
            from_version = (
                None
                if event["from_version"] is None
                else int(event["from_version"])
            )
        except (TypeError, ValueError):
            return "ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID"
        if (
            UUID.fullmatch(str(event["event_id"])) is None
            or to_version != expected_version
            or not isinstance(event["recorded_at"], str)
            or not event["recorded_at"]
        ):
            return "ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID"
        if expected_version == 1:
            if (
                event["from_state"] is not None
                or event["from_version"] is not None
                or event["to_state"] != "RESERVED"
                or event["reason"] != "ATTEMPT_RESERVED"
            ):
                return "ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID"
        else:
            if (
                event["from_state"] != previous_state
                or from_version != expected_version - 1
                or event["to_state"] not in allowed.get(str(previous_state), set())
            ):
                return "ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID"
        if (evidence_json is None) != (evidence_sha256 is None):
            return "ACTIVE_ATTEMPT_EVENT_EVIDENCE_INVALID"
        if evidence_json is not None:
            try:
                evidence = json.loads(evidence_json)
            except (TypeError, json.JSONDecodeError):
                return "ACTIVE_ATTEMPT_EVENT_EVIDENCE_INVALID"
            if (
                canonical_json(evidence) != evidence_json
                or hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
                != evidence_sha256
            ):
                return "ACTIVE_ATTEMPT_EVENT_EVIDENCE_INVALID"
            if event["to_state"] != "LAUNCHING" or evidence != {
                "systemd_control_group": control_group,
                "systemd_invocation_id": invocation_id,
                "systemd_unit": unit,
            }:
                return "ACTIVE_ATTEMPT_EVENT_EVIDENCE_INVALID"
        elif event["to_state"] == "LAUNCHING":
            return "ACTIVE_ATTEMPT_EVENT_EVIDENCE_INVALID"
        previous_state = str(event["to_state"])
    if previous_state != state:
        return "ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID"
    if version > 1 and events[-1]["reason"] != row["last_error"]:
        return "ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID"
    return None


def _message_target_error(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    role: str,
    endpoint_id: str,
    config: Any,
) -> str | None:
    try:
        target_id = int(row["target_key"])
    except ValueError:
        return "ACTIVE_ATTEMPT_TARGET_INVALID"
    target = connection.execute(
        "SELECT * FROM coordination_messages WHERE id=?", (target_id,)
    ).fetchone()
    if target is None:
        return "ACTIVE_ATTEMPT_TARGET_MISSING"
    if target["state"] not in ACTIONABLE_MESSAGE_STATES:
        return "ACTIVE_ATTEMPT_TARGET_NOT_ACTIONABLE"
    if (
        target["topic"] not in config.roles[role].allowed_topics
        or identity_role(connection, target["recipient_session_id"]) != role
    ):
        return "ACTIVE_ATTEMPT_TARGET_ROLE_OR_TOPIC_INVALID"
    if target["recipient_session_id"] != endpoint_id:
        return "ACTIVE_ATTEMPT_TARGET_RECIPIENT_NOT_CURRENT"
    if (
        (target["state"] == "PREPARED" and target["claimed_by"] is not None)
        or (
            target["state"] == "CLAIMED"
            and target["claimed_by"] != endpoint_id
        )
    ):
        return "ACTIVE_ATTEMPT_TARGET_CLAIM_INVALID"
    try:
        payload = json.loads(target["payload_json"])
        if digest_json(payload) != target["payload_sha256"]:
            raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
        store = object.__new__(CoordinationStore)
        store.connection = connection
        store._validate_message_source(payload)
        store._validate_message_contract(
            topic=target["topic"],
            recipient_session_id=target["recipient_session_id"],
            payload=payload,
            current_write=True,
        )
    except (CoordinationError, TypeError, json.JSONDecodeError):
        return "ACTIVE_ATTEMPT_TARGET_AUTHORITY_INVALID"
    return None


def _terminal_watch_target_error(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    role: str,
    endpoint_id: str,
) -> str | None:
    target = connection.execute(
        "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
        (row["target_key"],),
    ).fetchone()
    if target is None:
        return "ACTIVE_ATTEMPT_TARGET_MISSING"
    if target["state"] != "ACTIVE":
        return "ACTIVE_ATTEMPT_TARGET_NOT_ACTIONABLE"
    if (
        identity_role(connection, target["accountable_session_id"]) != role
        or target["accountable_session_id"] != endpoint_id
    ):
        return "ACTIVE_ATTEMPT_TARGET_RECIPIENT_NOT_CURRENT"
    item = connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (target["repository"], target["issue_number"]),
    ).fetchone()
    source = None if item is None else connection.execute(
        "SELECT payload_sha256 FROM github_current WHERE repository=? "
        "AND object_kind='issue' AND object_number=?",
        (target["repository"], target["issue_number"]),
    ).fetchone()
    if (
        item is None
        or source is None
        or item["allocation_class"] != "ACTIVE"
        or item["status"] not in {"ACTIVE", "ACTIVE_FENCED", "MONITOR"}
        or int(item["generation"]) != int(target["generation"])
        or item["accountable_session_id"] != endpoint_id
        or item["lease_manifest_sha256"] != target["lease_manifest_sha256"]
        or source["payload_sha256"] != item["source_payload_sha256"]
        or SHA256.fullmatch(str(target["lease_manifest_sha256"])) is None
    ):
        return "ACTIVE_ATTEMPT_TARGET_STALE"
    return None


def _hosted_operation_target_error(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    role: str,
    endpoint_id: str,
) -> str | None:
    if role != "sre":
        return "ACTIVE_ATTEMPT_TARGET_ROLE_OR_TOPIC_INVALID"
    try:
        target_id = int(row["target_key"])
    except ValueError:
        return "ACTIVE_ATTEMPT_TARGET_INVALID"
    target = connection.execute(
        "SELECT * FROM hosted_operations WHERE id=?", (target_id,)
    ).fetchone()
    if target is None:
        return "ACTIVE_ATTEMPT_TARGET_MISSING"
    required = {
        "id", "repository", "object_kind", "issue_number",
        "source_payload_sha256", "provider", "target_kind", "target_key",
        "operation_kind", "authority_comment_id", "authority_body_sha256",
        "scope_sha256", "scope_json", "recipient_session_id", "sre_units",
        "blocked_by_issue_number", "state", "claimed_by",
    }
    if not required.issubset(target.keys()):
        return "ACTIVE_ATTEMPT_TARGET_AUTHORITY_INVALID"
    if target["state"] not in ACTIONABLE_HOSTED_OPERATION_STATES:
        return "ACTIVE_ATTEMPT_TARGET_NOT_ACTIONABLE"
    if (
        identity_role(connection, target["recipient_session_id"]) != "sre"
        or target["recipient_session_id"] != endpoint_id
    ):
        return "ACTIVE_ATTEMPT_TARGET_RECIPIENT_NOT_CURRENT"
    if (
        (target["state"] == "PREPARED" and target["claimed_by"] is not None)
        or (
            target["state"] == "CLAIMED"
            and target["claimed_by"] != endpoint_id
        )
    ):
        return "ACTIVE_ATTEMPT_TARGET_CLAIM_INVALID"
    try:
        store = object.__new__(CoordinationStore)
        store.connection = connection
        control = object.__new__(HostedOperationControl)
        control.connection = connection
        control.store = store
        scope = control._validate_persisted_operation(target)
        control._validate_operation_evidence(
            repository=target["repository"],
            issue_number=int(target["issue_number"]),
            provider=target["provider"],
            target_kind=target["target_kind"],
            operation_kind=target["operation_kind"],
            scope=scope,
        )
        control._validate_source(
            target["repository"],
            int(target["issue_number"]),
            target["source_payload_sha256"],
        )
        if not control._blocker_terminal(
            target["repository"], target["blocked_by_issue_number"]
        ):
            raise CoordinationError("HOSTED_BLOCKER_NOT_TERMINAL")
        control._validate_approval_guard(
            repository=target["repository"],
            issue_number=int(target["issue_number"]),
            operation_kind=target["operation_kind"],
            execution_scope_sha256=hosted_execution_scope_sha256(
                provider=target["provider"],
                target_kind=target["target_kind"],
                target_key=target["target_key"],
                operation_kind=target["operation_kind"],
                scope=scope,
            ),
            authority_comment_id=int(target["authority_comment_id"]),
            required=False,
        )
    except (CoordinationError, RegistryError, TypeError, ValueError, json.JSONDecodeError):
        return "ACTIVE_ATTEMPT_TARGET_AUTHORITY_INVALID"
    return None


def _active_attempt_target_error(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    config: Any,
) -> str | None:
    role = str(row["role"])
    endpoint_id = str(row["endpoint_id"])
    target_kind = str(row["target_kind"])
    target_key = str(row["target_key"])
    if role not in ROLES:
        return "ACTIVE_ATTEMPT_ROLE_INVALID"
    endpoint = current_endpoint(connection, role)
    if endpoint is None or endpoint_id != endpoint["endpoint_id"]:
        return "ACTIVE_ATTEMPT_ROUTE_NOT_CURRENT"

    integrity_error = _attempt_event_integrity_error(connection, row)
    if integrity_error is not None:
        return integrity_error
    try:
        lineage = attempt_lineage_for_target(connection, target_kind, target_key)
    except RegistryError:
        return "ACTIVE_ATTEMPT_LINEAGE_INVALID"
    lineage_columns = {
        "lineage_repository", "lineage_issue_number", "lineage_generation",
        "lineage_lease_sha256", "lineage_sha256",
    }
    if not lineage_columns.issubset(row.keys()):
        return "ACTIVE_ATTEMPT_LINEAGE_INVALID"
    stored_lineage = (
        row["lineage_repository"],
        row["lineage_issue_number"],
        row["lineage_generation"],
        row["lineage_lease_sha256"],
        row["lineage_sha256"],
    )
    expected_lineage = (
        (None, None, None, None, None)
        if lineage is None
        else (
            lineage.repository,
            lineage.issue_number,
            lineage.generation,
            lineage.lease_manifest_sha256,
            lineage.sha256,
        )
    )
    if stored_lineage != expected_lineage:
        return "ACTIVE_ATTEMPT_LINEAGE_INVALID"

    if target_kind == "message":
        if not _table_exists(connection, "coordination_messages"):
            return "ACTIVE_ATTEMPT_TARGET_MISSING"
        return _message_target_error(
            connection, row, role=role, endpoint_id=endpoint_id, config=config
        )

    if target_kind == "terminal_watch":
        if (
            not _table_exists(connection, "coordination_terminal_watches")
            or not _table_exists(connection, "coordination_items")
        ):
            return "ACTIVE_ATTEMPT_TARGET_MISSING"
        return _terminal_watch_target_error(
            connection, row, role=role, endpoint_id=endpoint_id
        )

    if target_kind == "hosted_operation":
        if not _table_exists(connection, "hosted_operations"):
            return "ACTIVE_ATTEMPT_TARGET_MISSING"
        return _hosted_operation_target_error(
            connection, row, role=role, endpoint_id=endpoint_id
        )

    return "ACTIVE_ATTEMPT_TARGET_KIND_INVALID"


def archive_readiness(
    connection: sqlite3.Connection,
    *,
    operational_markdown_paths: tuple[Path, ...] | None = None,
    legacy_alias_path: Path | None = None,
    routing_page_reader: PageReader | None = None,
    routing_comment_reader: CommentReader | None = None,
    _local_snapshot: bool = False,
) -> dict[str, Any]:
    """Return the exact archive gates without changing local or remote state."""

    if not _local_snapshot:
        with _stable_read_snapshot(connection):
            result = archive_readiness(
                connection,
                operational_markdown_paths=operational_markdown_paths,
                legacy_alias_path=legacy_alias_path,
                _local_snapshot=True,
            )
            before_digest = _local_state_digest(connection)
        routing_context = result.pop("_routing_inventory_context")
        result["gates"]["routing_deprecation_inventory"].extend(
            _routing_inventory_external_gate(
                routing_context,
                page_reader=routing_page_reader,
                comment_reader=routing_comment_reader,
            )
        )
        with _stable_read_snapshot(connection):
            after_digest = _local_state_digest(connection)
        result["gates"]["local_state_consistency"] = (
            [] if before_digest == after_digest
            else [{"error": "ARCHIVE_READINESS_LOCAL_STATE_DRIFT"}]
        )
        blockers = [name for name, entries in result["gates"].items() if entries]
        result["blockers"] = blockers
        result["phase"] = "PASS" if not blockers else "HOLD"
        return result

    alias_path = legacy_alias_path or DEFAULT_LEGACY_ALIASES
    alias_set = load_alias_artifact(alias_path)
    aliases = set(alias_set.aliases)
    config = load_registry_config()

    required_registry_tables = {
        "executor_role_endpoints",
        "executor_role_endpoint_current",
        "executor_role_endpoint_aliases",
        "executor_attempts",
        "executor_attempt_events",
    }
    present_tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    missing_registry_tables = sorted(required_registry_tables - present_tables)
    registry_schema_findings: list[dict[str, Any]] = []
    if missing_registry_tables:
        registry_schema_findings.append({"missing_tables": missing_registry_tables})
    elif not attempt_schema_is_current(connection):
        registry_schema_findings.append({
            "table": "executor_attempts",
            "error": "EXECUTOR_ATTEMPT_TARGET_UNIQUENESS_REQUIRED",
        })
    executable_commands: list[dict[str, Any]] = []
    executable_commands.extend(_legacy_source_commands())
    executable_commands.extend(_legacy_markdown_vectors(operational_markdown_paths))
    if {
        "executor_role_endpoints",
        "executor_role_endpoint_current",
    }.issubset(present_tables):
        for row in connection.execute(
            """
            SELECT endpoint.endpoint_id, endpoint.role,
                   endpoint.command_json, endpoint.config_json
            FROM executor_role_endpoint_current current
            JOIN executor_role_endpoints endpoint
              ON endpoint.endpoint_id=current.endpoint_id
            ORDER BY endpoint.role, endpoint.version
            """
        ).fetchall():
            if _contains_alias(json.loads(row["command_json"]), aliases) or _contains_alias(
                json.loads(row["config_json"]), aliases
            ):
                executable_commands.append({
                    "kind": "endpoint_command",
                    "endpoint_id": row["endpoint_id"],
                    "role": row["role"],
                })
    if _table_exists(connection, "coordination_messages"):
        for row in connection.execute(
            """
            SELECT id, recipient_session_id, topic, state, payload_json
            FROM coordination_messages
            WHERE state IN ('PREPARED','CLAIMED')
            ORDER BY id
            """
        ).fetchall():
            if row["topic"] not in EXECUTABLE_TOPICS:
                continue
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                executable_commands.append({
                    "kind": "coordination_message",
                    "message_id": int(row["id"]),
                    "topic": row["topic"],
                    "state": row["state"],
                    "error": "ACTIONABLE_MESSAGE_PAYLOAD_INVALID",
                })
                continue
            if (
                row["recipient_session_id"] in aliases
                or _contains_alias(payload, aliases)
            ):
                executable_commands.append({
                    "kind": "coordination_message",
                    "message_id": int(row["id"]),
                    "topic": row["topic"],
                    "state": row["state"],
                })
    current_pointers: list[dict[str, Any]] = []
    if not missing_registry_tables:
        pointer_rows = connection.execute(
            """
            SELECT current.role, current.endpoint_id, endpoint.role AS endpoint_role,
                   endpoint.version, endpoint.config_sha256,
                   endpoint.executor_profile, endpoint.codex_profile,
                   endpoint.config_json, endpoint.command_json
            FROM executor_role_endpoint_current current
            LEFT JOIN executor_role_endpoints endpoint
              ON endpoint.endpoint_id=current.endpoint_id
            ORDER BY current.role
            """
        ).fetchall()
        by_role = {str(row["role"]): row for row in pointer_rows}
        for role in ROLES:
            row = by_role.get(role)
            expected = config.roles[role]
            if row is None:
                current_pointers.append({"role": role, "error": "CURRENT_POINTER_MISSING"})
                continue
            try:
                stored_config = json.loads(row["config_json"])
                stored_command = json.loads(row["command_json"])
                config_has_alias = _contains_alias(stored_config, aliases)
                command_has_alias = _contains_alias(stored_command, aliases)
            except (TypeError, json.JSONDecodeError):
                stored_config = None
                stored_command = None
                config_has_alias = True
                command_has_alias = True
            if (
                row["endpoint_role"] != role
                or row["endpoint_id"] != expected.endpoint_id
                or row["version"] != expected.version
                or row["config_sha256"] != expected.config_sha256
                or row["executor_profile"] != expected.executor_profile
                or row["codex_profile"] != expected.codex_profile
                or stored_config != expected.payload
                or stored_command != list(expected.command_prefix)
                or config_has_alias
                or command_has_alias
            ):
                current_pointers.append({
                    "role": role,
                    "endpoint_id": row["endpoint_id"],
                    "error": "CURRENT_POINTER_INVALID",
                })
        for unexpected_role in sorted(set(by_role) - set(ROLES)):
            current_pointers.append({
                "role": unexpected_role,
                "error": "CURRENT_POINTER_INVALID",
            })
    else:
        current_pointers.extend(
            {"role": role, "error": "CURRENT_POINTER_MISSING"} for role in ROLES
        )
    active_attempts: list[dict[str, Any]] = []
    if "executor_attempts" in present_tables:
        for row in connection.execute(
            """
            SELECT *
            FROM executor_attempts
            WHERE state IN ('RESERVED','LAUNCHING','RUNNING') ORDER BY created_at
            """
        ).fetchall():
            error = _active_attempt_target_error(connection, row, config=config)
            if error is not None:
                active_attempts.append({
                    "attempt_id": row["attempt_id"],
                    "role": row["role"],
                    "target_kind": row["target_kind"],
                    "target_key": row["target_key"],
                    "state": row["state"],
                    "error": error,
                })
    local_current_routing: list[dict[str, Any]] = []
    if _table_exists(connection, "coordination_items"):
        for row in connection.execute(
            """
            SELECT repository, issue_number, accountable_session_id, status, allocation_class
            FROM coordination_items
            WHERE accountable_session_id IS NOT NULL
            ORDER BY repository, issue_number
            """
        ).fetchall():
            actionable = (
                row["allocation_class"] in {"ACTIVE", "RETAINED"}
                or row["status"]
                in {"PREPARED", "QUEUED", "READY", "ACTIVE", "ACTIVE_FENCED", "MONITOR"}
            )
            if actionable and row["accountable_session_id"] in aliases:
                local_current_routing.append({
                    "kind": "coordination_item",
                    "repository": row["repository"],
                    "issue_number": int(row["issue_number"]),
                    "status": row["status"],
                    "allocation_class": row["allocation_class"],
                })
    if _table_exists(connection, "coordination_terminal_watches"):
        for row in connection.execute(
            """
            SELECT watch_key, accountable_session_id, state
            FROM coordination_terminal_watches
            WHERE state='ACTIVE' ORDER BY watch_key
            """
        ).fetchall():
            if row["accountable_session_id"] in aliases:
                local_current_routing.append({
                    "kind": "terminal_watch",
                    "watch_key": row["watch_key"],
                    "state": row["state"],
                })
    if _table_exists(connection, "hosted_operations"):
        for row in connection.execute(
            """
            SELECT id, recipient_session_id, state
            FROM hosted_operations
            WHERE state IN ('WAITING','PREPARED','CLAIMED') ORDER BY id
            """
        ).fetchall():
            if row["recipient_session_id"] in aliases:
                local_current_routing.append({
                    "kind": "hosted_operation",
                    "operation_id": int(row["id"]),
                    "state": row["state"],
                })
    if _table_exists(connection, "approval_deliveries"):
        for row in connection.execute(
            """
            SELECT proposal_sha256, recipient_session_id, state
            FROM approval_deliveries
            WHERE state IN ('WAITING_PUBLICATION','CLAIMED')
            ORDER BY proposal_sha256, recipient_session_id
            """
        ).fetchall():
            if row["recipient_session_id"] in aliases:
                local_current_routing.append({
                    "kind": "approval_delivery",
                    "proposal_sha256": row["proposal_sha256"],
                    "state": row["state"],
                })
    local_current_routing.extend(_current_kanban_routing(connection, aliases))
    legacy_ack = inspect_legacy_ack_rows(connection)
    legacy_ack_runtime: list[dict[str, Any]] = []
    if legacy_ack.get("error"):
        legacy_ack_runtime.append({"error": legacy_ack["error"]})
    legacy_ack_runtime.extend(legacy_ack.get("nonterminal", []))
    routing_inventory, routing_inventory_context = _routing_inventory_local_gate(
        connection,
        alias_path=alias_path,
    )
    gates = {
        "registry_schema": (
            registry_schema_findings
        ),
        "executable_commands": executable_commands,
        "current_pointers": current_pointers,
        "active_attempts": active_attempts,
        "routing_deprecation_inventory": routing_inventory,
        "local_current_routing": local_current_routing,
        "legacy_ack_runtime": legacy_ack_runtime,
    }
    blockers = [name for name, entries in gates.items() if entries]
    result = {
        "kind": "TWINFINITY_LEGACY_SESSION_ARCHIVE_READINESS_V1",
        "phase": "PASS" if not blockers else "HOLD",
        "legacy_alias_count": len(aliases),
        "legacy_alias_source_sha256": alias_set.source_sha256,
        "blockers": blockers,
        "gates": gates,
        "_routing_inventory_context": routing_inventory_context,
    }
    if registry_schema_findings or any(
        entry.get("error") == "CURRENT_POINTER_MISSING" for entry in current_pointers
    ):
        result["error"] = "REGISTRY_NOT_MIGRATED"
    elif current_pointers:
        result["error"] = "REGISTRY_POINTER_INVALID"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    args = parser.parse_args()
    connection: sqlite3.Connection | None = None
    try:
        connection = open_registry_database(DEFAULT_DATABASE, read_only=True)
        inventory = (
            connection.execute(
                "SELECT repository FROM routing_deprecation_inventories"
            ).fetchall()
            if _table_exists(connection, "routing_deprecation_inventories")
            else []
        )
        repository = str(inventory[0]["repository"]) if len(inventory) == 1 else ""
        result = archive_readiness(
            connection,
            routing_page_reader=(github_page_reader(repository) if repository else None),
            routing_comment_reader=github_comment_reader,
        )
        print(canonical_json(result))
        return 0 if result["phase"] == "PASS" else 1
    except (CoordinationError, InventoryError, OSError, RegistryError, sqlite3.Error):
        print(canonical_json({
            "kind": "TWINFINITY_LEGACY_SESSION_ARCHIVE_READINESS_V1",
            "phase": "HOLD",
            "error": "ARCHIVE_READINESS_AUDIT_FAILED",
        }))
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
