#!/usr/bin/env python3
"""Freeze a complete, digest-only inventory of legacy routing in GitHub bodies."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from typing import Any, Callable

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
    digest_json,
    routing_endpoint_state_digest,
    utc_now,
)
from executor_registry import DEFAULT_LEGACY_ALIASES, ROLES, UUID


INVENTORY_KIND = "TWINFINITY_ROUTING_DEPRECATION_INVENTORY_V1"
OBJECT_KINDS = ("issue", "pull_request")
CLASSIFICATIONS = (
    "EXECUTABLE_ROUTE",
    "ROUTING_REFERENCE",
    "HISTORICAL_PROVENANCE",
    "AMBIGUOUS_REFERENCE",
)
SEMANTIC_TAGS = ("ACCEPTANCE", "APPROVAL", "DEPENDENCY", "HOLD", "SCOPE")
PageReader = Callable[[str, str | None], dict[str, Any]]


class InventoryError(RuntimeError):
    pass


def _unicode_scalar_text(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


@dataclass(frozen=True)
class AliasArtifact:
    aliases: dict[str, str]
    source_sha256: str


def load_alias_artifact(path: Path) -> AliasArtifact:
    """Read and validate the exact alias bytes through an owner-safe descriptor."""

    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise InventoryError("LEGACY_ALIAS_ARTIFACT_UNSAFE")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise InventoryError("LEGACY_ALIAS_ARTIFACT_DRIFT")
        raw = b"".join(chunks)
    except OSError as exc:
        raise InventoryError("LEGACY_ALIAS_ARTIFACT_UNSAFE") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("LEGACY_ALIAS_FILE_INVALID_JSON") from exc
    if type(value) is not dict or set(value) != {"schema_version", "aliases"}:
        raise InventoryError("LEGACY_ALIAS_FILE_SCHEMA_INVALID")
    if value.get("schema_version") != 1 or type(value.get("aliases")) is not list:
        raise InventoryError("LEGACY_ALIAS_FILE_SCHEMA_INVALID")
    aliases: dict[str, str] = {}
    roles: set[str] = set()
    for item in value["aliases"]:
        if type(item) is not dict or set(item) != {"alias", "role"}:
            raise InventoryError("LEGACY_ALIAS_FILE_SCHEMA_INVALID")
        alias = item.get("alias")
        role = item.get("role")
        if (
            type(alias) is not str
            or UUID.fullmatch(alias) is None
            or type(role) is not str
            or role not in ROLES
            or alias in aliases
            or role in roles
        ):
            raise InventoryError("LEGACY_ALIAS_FILE_VALUE_INVALID")
        aliases[alias] = role
        roles.add(role)
    if roles != set(ROLES):
        raise InventoryError("LEGACY_ALIAS_FILE_ROLES_INVALID")
    return AliasArtifact(aliases, hashlib.sha256(raw).hexdigest())


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _graphql_query(kind: str) -> str:
    field = "issues" if kind == "issue" else "pullRequests"
    typename = "Issue" if kind == "issue" else "PullRequest"
    return f"""
query($owner:String!,$name:String!,$cursor:String) {{
  repository(owner:$owner,name:$name) {{
    {field}(first:100,after:$cursor,orderBy:{{field:CREATED_AT,direction:ASC}}) {{
      totalCount
      pageInfo {{ hasNextPage endCursor }}
      nodes {{ __typename id number body updatedAt }}
    }}
  }}
}}
""".strip()


def github_page_reader(repository: str) -> PageReader:
    try:
        owner, name = repository.split("/", 1)
    except ValueError as exc:
        raise InventoryError("REPOSITORY_INVALID") from exc

    def read(kind: str, cursor: str | None) -> dict[str, Any]:
        field = "issues" if kind == "issue" else "pullRequests"
        payload = {
            "query": _graphql_query(kind),
            "variables": {"owner": owner, "name": name, "cursor": cursor},
        }
        try:
            completed = subprocess.run(
                ["gh", "api", "graphql", "--input", "-"],
                input=canonical_json(payload), check=False, capture_output=True,
                text=True, timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise InventoryError("GITHUB_INVENTORY_READ_FAILED") from exc
        if completed.returncode != 0:
            raise InventoryError("GITHUB_INVENTORY_READ_FAILED")
        try:
            response = json.loads(completed.stdout)
            if type(response) is not dict or ("errors" in response and response["errors"] != []):
                raise InventoryError("GITHUB_INVENTORY_RESPONSE_INVALID")
            connection = response["data"]["repository"][field]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise InventoryError("GITHUB_INVENTORY_RESPONSE_INVALID") from exc
        if not isinstance(connection, dict):
            raise InventoryError("GITHUB_INVENTORY_RESPONSE_INVALID")
        return connection

    return read


def github_comment_reader(repository: str, issue_number: int, comment_id: int) -> dict[str, Any]:
    """Read one exact issue comment and fail closed on identity/shape drift."""
    if type(issue_number) is not int or issue_number != 179 or type(comment_id) is not int or comment_id <= 0:
        raise InventoryError("GITHUB_COMMENT_IDENTITY_INVALID")
    try:
        completed = subprocess.run(
            ["gh", "api", f"repos/{repository}/issues/comments/{comment_id}"],
            check=False, capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise InventoryError("GITHUB_COMMENT_READ_FAILED") from exc
    if completed.returncode != 0:
        raise InventoryError("GITHUB_COMMENT_READ_FAILED")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise InventoryError("GITHUB_COMMENT_RESPONSE_INVALID") from exc
    expected_issue_url = f"https://api.github.com/repos/{repository}/issues/{issue_number}"
    if (type(value) is not dict or value.get("id") != comment_id
            or type(value.get("body")) is not str or not _unicode_scalar_text(value["body"])
            or value.get("issue_url") != expected_issue_url):
        raise InventoryError("GITHUB_COMMENT_RESPONSE_INVALID")
    return value


def _scan_connection(kind: str, page_reader: PageReader) -> list[dict[str, Any]]:
    expected_typename = "Issue" if kind == "issue" else "PullRequest"
    cursor: str | None = None
    seen_cursors: set[str] = set()
    seen_numbers: set[int] = set()
    seen_node_ids: set[str] = set()
    total_count: int | None = None
    objects: list[dict[str, Any]] = []
    while True:
        try:
            connection = page_reader(kind, cursor)
        except InventoryError:
            raise
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            raise InventoryError("GITHUB_INVENTORY_PAGE_INVALID") from exc
        if type(connection) is not dict:
            raise InventoryError("GITHUB_INVENTORY_PAGE_INVALID")
        count = connection.get("totalCount")
        nodes = connection.get("nodes")
        page_info = connection.get("pageInfo")
        if (
            type(count) is not int
            or count < 0
            or not isinstance(nodes, list)
            or len(nodes) > 100
            or not isinstance(page_info, dict)
            or type(page_info.get("hasNextPage")) is not bool
        ):
            raise InventoryError("GITHUB_INVENTORY_PAGE_INVALID")
        if total_count is None:
            total_count = count
        elif total_count != count:
            raise InventoryError("GITHUB_INVENTORY_COUNT_DRIFT")
        for node in nodes:
            if not isinstance(node, dict):
                raise InventoryError("GITHUB_INVENTORY_OBJECT_INVALID")
            number = node.get("number")
            node_id = node.get("id")
            body = node.get("body")
            updated_at = node.get("updatedAt")
            if (
                node.get("__typename") != expected_typename
                or type(number) is not int
                or number <= 0
                or not isinstance(node_id, str)
                or not node_id
                or not _unicode_scalar_text(node_id)
                or not isinstance(body, str)
                or not _unicode_scalar_text(body)
                or not _valid_timestamp(updated_at)
            ):
                raise InventoryError("GITHUB_INVENTORY_OBJECT_INVALID")
            if number in seen_numbers or node_id in seen_node_ids:
                raise InventoryError("GITHUB_INVENTORY_DUPLICATE_OBJECT")
            seen_numbers.add(number)
            seen_node_ids.add(node_id)
            objects.append(
                {
                    "object_kind": kind,
                    "object_number": number,
                    "node_id": node_id,
                    "updated_at": updated_at,
                    "body": body,
                }
            )
        has_next = page_info["hasNextPage"]
        end_cursor = page_info.get("endCursor")
        if not has_next:
            if len(objects) != total_count:
                raise InventoryError("GITHUB_INVENTORY_COUNT_MISMATCH")
            break
        if not isinstance(end_cursor, str) or not end_cursor or end_cursor in seen_cursors:
            raise InventoryError("GITHUB_INVENTORY_CURSOR_INVALID")
        if not nodes:
            raise InventoryError("GITHUB_INVENTORY_PAGE_INVALID")
        seen_cursors.add(end_cursor)
        cursor = end_cursor
    return objects


def _paragraph(body: str, char_start: int) -> str:
    separator = body.rfind("\n\n", 0, char_start)
    start = 0 if separator < 0 else separator + 2
    end = body.find("\n\n", char_start)
    return body[start:] if end < 0 else body[start:end]


_EXECUTABLE_ROUTE = re.compile(
    r"\bcodex\s+exec\s+resume\b|"
    r"\b(?:recipient_session_id|accountable_session_id|session-id)\b\s*[:=]?|"
    r"\b(?:rout(?:e|ed|es|ing)|dispatch(?:ed|es|ing)?|send|sent|"
    r"resum(?:e|ed|es|ing)|invok(?:e|ed|es|ing)|launch(?:ed|es|ing)?|"
    r"execut(?:e|ed|es|ing)|run|ran|use(?:d|s|ing)?|assign(?:ed|s|ing)?|"
    r"handoff|hand[ -]?off|forward(?:ed|s|ing)?|deliver(?:ed|s|ing)?|"
    r"queue(?:d|s|ing)?|schedul(?:e|ed|es|ing)|wake|woke|notify|notified|"
    r"contact(?:ed|s|ing)?|continu(?:e|ed|es|ing)|proceed(?:ed|s|ing)?|"
    r"start(?:ed|s|ing)?)\b"
)
_ROUTE_NEGATION = re.compile(
    r"\b(?:do not|does not|don't|never|must not|may not|cannot|can't|"
    r"no longer|is not|are not|was not|were not)\b"
)
_POLARITY_BOUNDARY = re.compile(
    r"[.!?;\n]+|\b(?:but|however|instead|rather)\b"
)
_HISTORICAL_PROVENANCE = re.compile(
    r"\b(?:historical|provenance|retired|deprecated|superseded|archived|former|"
    r"previous|legacy-only|immutable history|immutable provenance)\b"
)
_ROUTING_LANGUAGE = re.compile(
    r"\b(?:route|routing|receiver|recipient|session|endpoint|owner|assignee|"
    r"worker|agent|thread|attempt|delivery|work|task|job|queue|lease)\b"
)
_ACTIVE_OR_DIRECTIVE = re.compile(
    r"\b(?:current|active|live|next|now|today|still|pending|ready|should|shall|"
    r"must|may|can|will|need(?:s)?\s+to|is\s+to|are\s+to|please)\b"
)
_NEGATED_DIRECTIVE = re.compile(
    r"\b(?:must\s+never|must\s+not|may\s+not|should\s+not|shall\s+not|"
    r"cannot|can't|do\s+not|does\s+not)\b"
)
_INERT_REFERENCE = re.compile(
    r"\b(?:literal|string|identifier|field|column|record|recorded|example|"
    r"sample|format|value|documentation|quoted|snapshot)\b"
)


def _route_polarities(context: str) -> tuple[bool, bool]:
    """Return whether a paragraph contains negative and positive route signals."""

    negative = False
    positive = False
    boundary_ends = [match.end() for match in _POLARITY_BOUNDARY.finditer(context)]
    for signal in _EXECUTABLE_ROUTE.finditer(context):
        clause_start = max(
            (end for end in boundary_ends if end <= signal.start()),
            default=0,
        )
        prefix = context[clause_start : signal.start()]
        if _ROUTE_NEGATION.search(prefix[-100:]):
            negative = True
        else:
            positive = True
    return negative, positive


def classify_occurrence(body: str, char_start: int) -> str:
    context = _paragraph(body, char_start)
    lowered = context.casefold()
    negative_route, positive_route = _route_polarities(lowered)
    historical = _HISTORICAL_PROVENANCE.search(lowered)
    routing = _ROUTING_LANGUAGE.search(lowered)

    # Historical is deliberately narrow: the same paragraph must establish
    # immutable provenance and explicit negative routing authority, with no
    # positive route signal. Everything mixed or semantically uncertain holds.
    if negative_route and positive_route:
        return "AMBIGUOUS_REFERENCE"
    nonnegative_directive_context = _NEGATED_DIRECTIVE.sub("", lowered)
    if (
        negative_route
        and historical
        and not _ACTIVE_OR_DIRECTIVE.search(nonnegative_directive_context)
    ):
        return "HISTORICAL_PROVENANCE"
    if negative_route:
        return "AMBIGUOUS_REFERENCE"
    if positive_route:
        return "EXECUTABLE_ROUTE"
    if historical:
        return "AMBIGUOUS_REFERENCE"
    if routing and _INERT_REFERENCE.search(lowered) and not _ACTIVE_OR_DIRECTIVE.search(lowered):
        return "ROUTING_REFERENCE"
    if routing:
        return "AMBIGUOUS_REFERENCE"
    return "AMBIGUOUS_REFERENCE"


_TAG_PATTERNS = {
    "SCOPE": re.compile(r"\b(?:scope|scoped|non-goal|boundary|bounded)\b", re.I),
    "HOLD": re.compile(r"\b(?:hold|blocked|blocker|stop|stopped)\b", re.I),
    "APPROVAL": re.compile(r"\b(?:approval|approve|approved|authorization|authorize)\b", re.I),
    "DEPENDENCY": re.compile(r"\b(?:dependency|depends|dependent|predecessor|prerequisite)\b", re.I),
    "ACCEPTANCE": re.compile(r"\b(?:acceptance|accepted|definition of done|gherkin)\b", re.I),
}


def semantic_tags(body: str, char_start: int) -> list[str]:
    context = _paragraph(body, char_start)
    return sorted(tag for tag, pattern in _TAG_PATTERNS.items() if pattern.search(context))


def scan_repository(
    repository: str, aliases: dict[str, str], page_reader: PageReader
) -> dict[str, Any]:
    raw_objects = [
        *_scan_connection("issue", page_reader),
        *_scan_connection("pull_request", page_reader),
    ]
    node_ids: set[str] = set()
    identities: set[tuple[str, int]] = set()
    object_manifest: list[dict[str, Any]] = []
    occurrences: list[dict[str, Any]] = []
    for obj in sorted(
        raw_objects,
        key=lambda item: (OBJECT_KINDS.index(item["object_kind"]), item["object_number"]),
    ):
        identity = (obj["object_kind"], obj["object_number"])
        if obj["node_id"] in node_ids or identity in identities:
            raise InventoryError("GITHUB_INVENTORY_DUPLICATE_OBJECT")
        node_ids.add(obj["node_id"])
        identities.add(identity)
        body = obj["body"]
        body_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
        object_manifest.append(
            {
                "object_kind": obj["object_kind"],
                "object_number": obj["object_number"],
                "node_id": obj["node_id"],
                "body_sha256": body_sha256,
            }
        )
        for alias in sorted(aliases):
            char_start = 0
            while True:
                char_start = body.find(alias, char_start)
                if char_start < 0:
                    break
                byte_start = len(body[:char_start].encode("utf-8"))
                line_start = body.rfind("\n", 0, char_start) + 1
                occurrences.append(
                    {
                        "object_kind": obj["object_kind"],
                        "object_number": obj["object_number"],
                        "node_id": obj["node_id"],
                        "body_sha256": body_sha256,
                        "alias": alias,
                        "byte_start": byte_start,
                        "byte_end": byte_start + len(alias.encode("utf-8")),
                        "line_number": body.count("\n", 0, char_start) + 1,
                        "byte_column": len(body[line_start:char_start].encode("utf-8")) + 1,
                        "classification": classify_occurrence(body, char_start),
                        "semantic_tags": semantic_tags(body, char_start),
                    }
                )
                char_start += len(alias)
    occurrences.sort(
        key=lambda item: (
            OBJECT_KINDS.index(item["object_kind"]),
            item["object_number"],
            item["byte_start"],
            item["alias"],
        )
    )
    occurrences = [{"ordinal": ordinal, **item} for ordinal, item in enumerate(occurrences)]
    return {
        "repository": repository,
        "object_manifest": object_manifest,
        "object_manifest_sha256": digest_json(object_manifest),
        "occurrences": occurrences,
        "occurrence_manifest_sha256": digest_json(occurrences),
    }


def stable_scan_repository(
    repository: str, aliases: dict[str, str], page_reader: PageReader
) -> dict[str, Any]:
    first = scan_repository(repository, aliases, page_reader)
    second = scan_repository(repository, aliases, page_reader)
    if canonical_json(first) != canonical_json(second):
        raise InventoryError("GITHUB_INVENTORY_SCAN_DRIFT")
    return first


def _current_issue_179_source(
    connection: sqlite3.Connection, repository: str
) -> str:
    row = connection.execute(
        """
        SELECT current.payload_sha256
        FROM github_current current
        JOIN github_snapshots snapshot
          ON snapshot.repository=current.repository
         AND snapshot.object_kind=current.object_kind
         AND snapshot.object_number=current.object_number
         AND snapshot.payload_sha256=current.payload_sha256
        WHERE current.repository=? AND current.object_kind='issue'
          AND current.object_number=179
        """,
        (repository,),
    ).fetchone()
    if row is None:
        raise InventoryError("ISSUE_179_SNAPSHOT_REQUIRED")
    return str(row["payload_sha256"])


def build_inventory_candidate(
    connection: sqlite3.Connection,
    *,
    repository: str,
    alias_artifact: AliasArtifact,
    page_reader: PageReader,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    scan = stable_scan_repository(repository, alias_artifact.aliases, page_reader)
    objects = scan["object_manifest"]
    if not any(
        item["object_kind"] == "issue" and item["object_number"] == 179
        for item in objects
    ):
        raise InventoryError("ISSUE_179_NOT_IN_COMPLETE_SCAN")
    classifications = Counter(item["classification"] for item in scan["occurrences"])
    tags = Counter(tag for item in scan["occurrences"] for tag in item["semantic_tags"])
    inventory = {
        "kind": INVENTORY_KIND,
        "repository": repository,
        "alias_source_sha256": alias_artifact.source_sha256,
        "endpoint_state_sha256": routing_endpoint_state_digest(connection),
        "issue_179_source_sha256": _current_issue_179_source(connection, repository),
        "object_manifest_sha256": scan["object_manifest_sha256"],
        "occurrence_manifest_sha256": scan["occurrence_manifest_sha256"],
        "object_manifest": objects,
        "object_count": len(objects),
        "issue_count": sum(item["object_kind"] == "issue" for item in objects),
        "pull_request_count": sum(
            item["object_kind"] == "pull_request" for item in objects
        ),
        "occurrence_count": len(scan["occurrences"]),
        "classification_counts": {
            name: classifications.get(name, 0) for name in CLASSIFICATIONS
        },
        "semantic_tag_counts": {name: tags.get(name, 0) for name in SEMANTIC_TAGS},
    }
    inventory["inventory_sha256"] = digest_json(inventory)
    return inventory, scan["occurrences"]


def receipt_body(inventory: dict[str, Any]) -> str:
    return "\n".join(
        (
            "## Legacy routing inventory frozen",
            "",
            f"- Repository: `{inventory['repository']}`",
            f"- Inventory SHA-256: `{inventory['inventory_sha256']}`",
            f"- Object manifest SHA-256: `{inventory['object_manifest_sha256']}`",
            f"- Occurrence manifest SHA-256: `{inventory['occurrence_manifest_sha256']}`",
            f"- Endpoint-state SHA-256: `{inventory['endpoint_state_sha256']}`",
            f"- Alias-source SHA-256: `{inventory['alias_source_sha256']}`",
            f"- Frozen objects: {inventory['object_count']}",
            f"- Exact occurrences: {inventory['occurrence_count']}",
            "",
            "Exact negative-routing overlay: every legacy alias occurrence in the bound "
            "object and occurrence manifests is superseded as executable routing and remains "
            "immutable provenance only. Comment-only timestamp changes are intentionally "
            "non-controlling; any object-body, node-identity, endpoint-state, alias-source, or "
            "receipt drift invalidates this overlay.",
            "",
            "Negative authority: this receipt does not route work, acknowledge a receiver, "
            "grant approval, change scope, satisfy a dependency or acceptance gate, rewrite "
            "any body, or alter any non-routing semantic.",
        )
    )


def outbox_idempotency_key(inventory: dict[str, Any]) -> str:
    return (
        f"routing-deprecation-inventory:{inventory['repository']}:"
        f"{inventory['inventory_sha256']}"
    )


def published_receipt_body(inventory: dict[str, Any]) -> str:
    key = outbox_idempotency_key(inventory)
    marker = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"{receipt_body(inventory)}\n\n<!-- twinfinity-outbox:{marker} -->"


def prepare_inventory(
    store: CoordinationStore,
    *,
    repository: str,
    alias_path: Path,
    page_reader: PageReader,
    expected_inventory_sha256: str,
    expected_endpoint_state_sha256: str,
    expected_issue_179_source_sha256: str,
    now: str,
    expected_preview_sha256: str,
    expected_prior_generation: int | None,
) -> tuple[dict[str, Any], int]:
    aliases = load_alias_artifact(alias_path)
    inventory, occurrences = build_inventory_candidate(
        store.connection,
        repository=repository,
        alias_artifact=aliases,
        page_reader=page_reader,
    )
    if inventory["inventory_sha256"] != expected_inventory_sha256:
        raise InventoryError("REVIEWED_INVENTORY_DIGEST_MISMATCH")
    if inventory["endpoint_state_sha256"] != expected_endpoint_state_sha256:
        raise InventoryError("REVIEWED_ENDPOINT_STATE_DIGEST_MISMATCH")
    if inventory["issue_179_source_sha256"] != expected_issue_179_source_sha256:
        raise InventoryError("REVIEWED_ISSUE_179_SNAPSHOT_MISMATCH")
    _, outbox_id = store.prepare_routing_deprecation_inventory(
        inventory=inventory,
        occurrences=occurrences,
        alias_source_path=alias_path,
        outbox_idempotency_key=outbox_idempotency_key(inventory),
        receipt_body=receipt_body(inventory),
        now=now,
        expected_preview_sha256=expected_preview_sha256,
        expected_prior_generation=expected_prior_generation,
    )
    return inventory, outbox_id


def preview_inventory(
    store: CoordinationStore, *, repository: str, alias_path: Path,
    page_reader: PageReader,
) -> dict[str, Any]:
    inventory, _ = build_inventory_candidate(
        store.connection, repository=repository,
        alias_artifact=load_alias_artifact(alias_path), page_reader=page_reader,
    )
    current = store.connection.execute(
        "SELECT generation,inventory_sha256,version FROM routing_deprecation_current WHERE repository=?",
        (repository,),
    ).fetchone()
    generation = 1 if current is None else int(current["generation"]) + 1
    value = {
        "repository": repository,
        "generation": generation,
        "predecessor_inventory_sha256": None if current is None else current["inventory_sha256"],
        "inventory_sha256": inventory["inventory_sha256"],
        "alias_source_sha256": inventory["alias_source_sha256"],
        "endpoint_state_sha256": inventory["endpoint_state_sha256"],
        "issue_179_source_sha256": inventory["issue_179_source_sha256"],
        "object_manifest_sha256": inventory["object_manifest_sha256"],
        "occurrence_manifest_sha256": inventory["occurrence_manifest_sha256"],
    }
    return {**value, "preview_sha256": digest_json(value)}


def _open_read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--legacy-alias-file", type=Path, default=DEFAULT_LEGACY_ALIASES
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("scan")
    subparsers.add_parser("preview")
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--expected-inventory-sha256", required=True)
    prepare.add_argument("--expected-endpoint-state-sha256", required=True)
    prepare.add_argument("--expected-issue-179-source-sha256", required=True)
    prepare.add_argument("--expected-preview-sha256", required=True)
    prepare.add_argument("--expected-prior-generation", type=int)
    promote = subparsers.add_parser("promote")
    promote.add_argument("--generation", required=True, type=int)
    promote.add_argument("--inventory-sha256", required=True)
    promote.add_argument("--expected-prior-generation", type=int)
    promote.add_argument("--expected-preview-sha256", required=True)
    migrate = subparsers.add_parser("migrate-legacy")
    migrate.add_argument("--expected-inventory-sha256", required=True)
    migrate.add_argument("--expected-occurrence-count", required=True, type=int)
    args = parser.parse_args()
    connection: sqlite3.Connection | None = None
    store: CoordinationStore | None = None
    try:
        if args.command == "migrate-legacy":
            store = CoordinationStore(args.database)
            result = store.migrate_legacy_routing_deprecation_inventory(
                expected_repository=args.repository,
                expected_inventory_sha256=args.expected_inventory_sha256,
                expected_occurrence_count=args.expected_occurrence_count,
                now=utc_now(),
            )
            print(canonical_json({"phase": "MIGRATED", "migration": result}))
            return 0
        aliases = load_alias_artifact(args.legacy_alias_file)
        reader = github_page_reader(args.repository)
        if args.command == "scan":
            connection = _open_read_only(args.database)
            inventory, occurrences = build_inventory_candidate(
                connection,
                repository=args.repository,
                alias_artifact=aliases,
                page_reader=reader,
            )
            print(
                canonical_json(
                    {
                        "phase": "COMPLETE",
                        "inventory": inventory,
                        "occurrences": occurrences,
                        "receipt_body": receipt_body(inventory),
                    }
                )
            )
        elif args.command == "preview":
            store = CoordinationStore(args.database)
            print(canonical_json({"phase": "PREVIEW", **preview_inventory(store, repository=args.repository, alias_path=args.legacy_alias_file, page_reader=reader)}))
        elif args.command == "prepare":
            store = CoordinationStore(args.database)
            inventory, outbox_id = prepare_inventory(
                store,
                repository=args.repository,
                alias_path=args.legacy_alias_file,
                page_reader=reader,
                expected_inventory_sha256=args.expected_inventory_sha256,
                expected_endpoint_state_sha256=args.expected_endpoint_state_sha256,
                expected_issue_179_source_sha256=args.expected_issue_179_source_sha256,
                now=utc_now(),
                expected_preview_sha256=args.expected_preview_sha256,
                expected_prior_generation=args.expected_prior_generation,
            )
            print(canonical_json({"phase": "PREPARED", "inventory_sha256": inventory["inventory_sha256"], "object_manifest_sha256": inventory["object_manifest_sha256"], "occurrence_manifest_sha256": inventory["occurrence_manifest_sha256"], "endpoint_state_sha256": inventory["endpoint_state_sha256"], "outbox_id": outbox_id}))
        else:
            store = CoordinationStore(args.database)
            row = store.connection.execute("SELECT outbox_id FROM routing_deprecation_inventories WHERE repository=? AND generation=? AND inventory_sha256=?", (args.repository, args.generation, args.inventory_sha256)).fetchone()
            if row is None:
                raise CoordinationError("ROUTING_DEPRECATION_SUCCESSOR_MISSING")
            outbox = store.connection.execute("SELECT remote_receipt FROM github_outbox WHERE id=?", (row["outbox_id"],)).fetchone()
            if outbox is None or not isinstance(outbox["remote_receipt"], str) or re.fullmatch(r"comment:[1-9][0-9]*", outbox["remote_receipt"]) is None:
                raise CoordinationError("ROUTING_DEPRECATION_RECEIPT_INCOMPLETE")
            comment = github_comment_reader(args.repository, 179, int(outbox["remote_receipt"].split(":", 1)[1]))
            current_inventory, current_occurrences = build_inventory_candidate(
                store.connection, repository=args.repository, alias_artifact=aliases,
                page_reader=reader,
            )
            result = store.promote_routing_deprecation_inventory(repository=args.repository, generation=args.generation, inventory_sha256=args.inventory_sha256, expected_prior_generation=args.expected_prior_generation, expected_preview_sha256=args.expected_preview_sha256, remote_receipt_body=comment["body"], current_inventory=current_inventory, current_occurrences=current_occurrences, alias_source_path=args.legacy_alias_file, now=utc_now())
            print(canonical_json({"phase": "PROMOTED", "promotion": result}))
        return 0
    except (CoordinationError, InventoryError, sqlite3.Error) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        if connection is not None:
            connection.close()
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
