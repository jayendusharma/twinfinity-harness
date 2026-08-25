#!/usr/bin/env python3
"""Cache the read-only five-body tracker reconciliation in SQLite.

The cache contains only deterministic projections, body digests, and validator
results. It never stores tracker body text and never performs a GitHub write.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, Sequence

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
)
from owner_safe_sqlite import prepare_owner_database
from validate_tracker_reconciliation import (
    Outcome,
    REQUIRED_ISSUES,
    parse_body_arg,
    parse_projection,
    validate_body_snapshots,
)


CACHE_SCHEMA = "twinfinity-tracker-reconciliation-cache/v2"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def body_snapshots(
    body_paths: dict[int, Path],
) -> tuple[dict[int, bytes], dict[str, str]]:
    actual = tuple(sorted(body_paths))
    if actual != REQUIRED_ISSUES:
        missing = sorted(set(REQUIRED_ISSUES) - set(actual))
        extra = sorted(set(actual) - set(REQUIRED_ISSUES))
        raise ValueError(f"body set mismatch; missing={missing}, extra={extra}")
    snapshots = {issue: body_paths[issue].read_bytes() for issue in REQUIRED_ISSUES}
    digests = {
        str(issue): hashlib.sha256(snapshots[issue]).hexdigest()
        for issue in REQUIRED_ISSUES
    }
    return snapshots, digests


def cache_key(
    *,
    repository: str,
    capacity_policy_version: int,
    development_limit: int,
    shared_limit: int,
    accepted_main: str,
    state: str,
    capacity: str,
    digests: dict[str, str],
) -> str:
    payload = {
        "schema": CACHE_SCHEMA,
        "repository": repository,
        "capacity_policy_version": capacity_policy_version,
        "development_limit": development_limit,
        "shared_limit": shared_limit,
        "accepted_main": accepted_main,
        "state": state,
        "capacity": capacity,
        "body_digests": digests,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _connect(path: Path) -> sqlite3.Connection:
    prepare_owner_database(path)
    for attempt in range(20):
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(path, timeout=30.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS tracker_reconciliation_cache (
                    cache_key TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    accepted_main TEXT NOT NULL,
                    state TEXT NOT NULL,
                    capacity TEXT NOT NULL,
                    body_digests_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            return connection
        except sqlite3.OperationalError as exc:
            if connection is not None:
                connection.close()
            if "locked" not in str(exc).lower() or attempt == 19:
                raise
            time.sleep(min(0.01 * (2**attempt), 0.25))
    raise sqlite3.OperationalError("database is locked")


def _capacity_policy(path: Path, repository: str) -> dict[str, Any]:
    for attempt in range(20):
        store: CoordinationStore | None = None
        try:
            store = CoordinationStore(path)
            return store.capacity_policy(repository)
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 19:
                raise
            time.sleep(min(0.01 * (2**attempt), 0.25))
        finally:
            if store is not None:
                store.close()
    raise sqlite3.OperationalError("database is locked")


def _assert_capacity_policy_current(
    connection: sqlite3.Connection,
    repository: str,
    expected: dict[str, Any],
) -> None:
    current = connection.execute(
        """
        SELECT p.* FROM coordination_capacity_current c
        JOIN coordination_capacity_policies p
          ON p.repository=c.repository AND p.version=c.version
        WHERE c.repository=?
        """,
        (repository,),
    ).fetchone()
    fields = (
        "version",
        "development_limit",
        "shared_limit",
        "sre_limit",
        "authority_sha256",
    )
    if current is None or any(current[field] != expected[field] for field in fields):
        raise ValueError("CAPACITY_POLICY_DRIFT")


def _validated_cached_payload(
    row: sqlite3.Row,
    *,
    projection: Any,
    digests: dict[str, str],
    body_paths: dict[int, Path],
) -> dict[str, Any]:
    if (
        row["schema_version"] != CACHE_SCHEMA
        or row["accepted_main"] != projection.accepted_main
        or row["state"] != projection.state
        or row["capacity"] != projection.capacity_text
        or json.loads(row["body_digests_json"]) != digests
    ):
        raise ValueError("CACHE_ROW_BINDING_INVALID")

    payload = json.loads(row["result_json"])
    if not isinstance(payload, dict) or set(payload) != {
        "outcome",
        "accepted_main",
        "state",
        "capacity",
        "stale_issues",
        "bodies",
    }:
        raise ValueError("CACHE_RESULT_SCHEMA_INVALID")
    if (
        payload["accepted_main"] != projection.accepted_main
        or payload["state"] != projection.state
        or payload["capacity"] != projection.capacity_text
        or payload["outcome"]
        not in {Outcome.COMPLETE.value, Outcome.TRACKER_BODY_PENDING.value}
        or not isinstance(payload["stale_issues"], list)
        or not isinstance(payload["bodies"], list)
    ):
        raise ValueError("CACHE_RESULT_BINDING_INVALID")

    normalized_bodies: list[dict[str, Any]] = []
    observed_issues: list[int] = []
    stale_issues: list[int] = []
    for body in payload["bodies"]:
        if not isinstance(body, dict) or set(body) != {
            "issue",
            "path",
            "sha256",
            "reasons",
        }:
            raise ValueError("CACHE_BODY_SCHEMA_INVALID")
        issue = body["issue"]
        reasons = body["reasons"]
        if (
            type(issue) is not int
            or issue not in REQUIRED_ISSUES
            or issue in observed_issues
            or not isinstance(body["path"], str)
            or body["sha256"] != digests[str(issue)]
            or not isinstance(reasons, list)
            or any(not isinstance(reason, str) or not reason for reason in reasons)
        ):
            raise ValueError("CACHE_BODY_BINDING_INVALID")
        observed_issues.append(issue)
        if reasons:
            stale_issues.append(issue)
        normalized_bodies.append(
            {
                "issue": issue,
                "path": str(body_paths[issue]),
                "sha256": body["sha256"],
                "reasons": reasons,
            }
        )

    if tuple(observed_issues) != REQUIRED_ISSUES:
        raise ValueError("CACHE_BODY_SET_INVALID")
    if payload["stale_issues"] != stale_issues:
        raise ValueError("CACHE_STALE_DERIVATION_INVALID")
    expected_outcome = (
        Outcome.TRACKER_BODY_PENDING.value if stale_issues else Outcome.COMPLETE.value
    )
    if payload["outcome"] != expected_outcome:
        raise ValueError("CACHE_OUTCOME_INVALID")
    payload["bodies"] = normalized_bodies
    return payload


def _render(payload: dict[str, Any], *, hit: bool, key: str) -> str:
    rendered = dict(payload)
    rendered["cache"] = "HIT" if hit else "MISS"
    rendered["cache_key"] = key
    return canonical_json(rendered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and cache the five canonical tracker body postconditions "
            "by main, state, capacity, and exact body digests"
        )
    )
    parser.add_argument(
        "--body",
        action="append",
        required=True,
        type=parse_body_arg,
        metavar="ISSUE=PATH",
    )
    parser.add_argument("--accepted-main", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--capacity", required=True)
    parser.add_argument(
        "--repository", default="twinfinityai/twinfinityapp"
    )
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    connection: sqlite3.Connection | None = None
    try:
        body_paths: dict[int, Path] = {}
        for issue, path in args.body:
            if issue in body_paths:
                raise ValueError(f"duplicate body for #{issue}")
            body_paths[issue] = path
        policy = _capacity_policy(args.database, args.repository)
        projection = parse_projection(
            args.accepted_main,
            args.state,
            args.capacity,
            development_limit=int(policy["development_limit"]),
            shared_limit=int(policy["shared_limit"]),
        )
        snapshots, digests = body_snapshots(body_paths)
        key = cache_key(
            repository=args.repository,
            capacity_policy_version=int(policy["version"]),
            development_limit=int(policy["development_limit"]),
            shared_limit=int(policy["shared_limit"]),
            accepted_main=projection.accepted_main,
            state=projection.state,
            capacity=projection.capacity_text,
            digests=digests,
        )
        connection = _connect(args.database)
        _assert_capacity_policy_current(connection, args.repository, policy)
        row = connection.execute(
            "SELECT * FROM tracker_reconciliation_cache WHERE cache_key=?",
            (key,),
        ).fetchone()
        if row is not None:
            payload = _validated_cached_payload(
                row,
                projection=projection,
                digests=digests,
                body_paths=body_paths,
            )
            _assert_capacity_policy_current(connection, args.repository, policy)
            print(_render(payload, hit=True, key=key))
            return 0 if payload["outcome"] == Outcome.COMPLETE.value else 3

        result = validate_body_snapshots(body_paths, snapshots, projection)
        if any(
            body.sha256 != digests[str(body.issue)] for body in result.bodies
        ):
            raise ValueError("BODY_DIGEST_VALIDATION_MISMATCH")
        payload = asdict(result)
        result_json = canonical_json(payload)
        _assert_capacity_policy_current(connection, args.repository, policy)
        with connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO tracker_reconciliation_cache (
                    cache_key, schema_version, accepted_main, state, capacity,
                    body_digests_json, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    CACHE_SCHEMA,
                    projection.accepted_main,
                    projection.state,
                    projection.capacity_text,
                    canonical_json(digests),
                    result_json,
                    utc_now(),
                ),
            )
        if cursor.rowcount == 0:
            row = connection.execute(
                "SELECT * FROM tracker_reconciliation_cache WHERE cache_key=?",
                (key,),
            ).fetchone()
            if row is None:
                raise ValueError("CACHE_CONCURRENT_INSERT_MISSING")
            payload = _validated_cached_payload(
                row,
                projection=projection,
                digests=digests,
                body_paths=body_paths,
            )
            _assert_capacity_policy_current(connection, args.repository, policy)
            print(_render(payload, hit=True, key=key))
            return 0 if payload["outcome"] == Outcome.COMPLETE.value else 3
        _assert_capacity_policy_current(connection, args.repository, policy)
        print(_render(payload, hit=False, key=key))
        return 0 if result.outcome is Outcome.COMPLETE else 3
    except (
        CoordinationError,
        OSError,
        UnicodeError,
        ValueError,
        sqlite3.Error,
        json.JSONDecodeError,
    ) as exc:
        print(canonical_json({"outcome": "INVALID_INPUT", "detail": str(exc)}))
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    sys.exit(main())
