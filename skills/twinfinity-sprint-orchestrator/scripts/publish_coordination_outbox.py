#!/usr/bin/env python3
"""Publish one preauthorized material GitHub comment from the SQLite outbox.

The publisher performs at most one external write. Recovery from an INFLIGHT
row is readback-only and never blindly resends.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from typing import Any

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
    utc_now,
)
from sync_github_coordination import fetch_object


CONFIRMATION = "PUBLISH_MATERIAL_RECEIPT"


def _gh_json(arguments: list[str], payload: dict[str, Any] | None = None) -> Any:
    completed = subprocess.run(
        ["gh", *arguments],
        input=None if payload is None else canonical_json(payload),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise CoordinationError("GITHUB_WRITE_AMBIGUOUS")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CoordinationError("GITHUB_RESPONSE_INVALID") from exc


def _all_comments(repository: str, object_number: int) -> list[dict[str, Any]]:
    raw = _gh_json(
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/issues/{object_number}/comments?per_page=100",
        ]
    )
    if not isinstance(raw, list):
        raise CoordinationError("GITHUB_RESPONSE_INVALID")
    comments: list[dict[str, Any]] = []
    for page in raw:
        if not isinstance(page, list):
            raise CoordinationError("GITHUB_RESPONSE_INVALID")
        comments.extend(item for item in page if isinstance(item, dict))
    return comments


def _published_body(body: str, idempotency_key: str) -> str:
    marker = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    return f"{body}\n\n<!-- twinfinity-outbox:{marker} -->"


def _matching_receipts(
    repository: str,
    object_number: int,
    body: str,
    *,
    publisher_login: str,
    not_before: str,
) -> list[str]:
    matches = []
    for comment in _all_comments(repository, object_number):
        author = comment.get("user") or {}
        if (
            comment.get("body") == body
            and author.get("login") == publisher_login
            and isinstance(comment.get("created_at"), str)
            and comment["created_at"] >= not_before
            and isinstance(comment.get("id"), int)
        ):
            matches.append(f"comment:{comment['id']}")
    return matches


def _complete_from_readback(
    store: CoordinationStore,
    row: dict[str, Any],
    body: str,
    *,
    publisher_login: str,
) -> dict[str, Any]:
    matches = _matching_receipts(
        row["repository"],
        row["object_number"],
        body,
        publisher_login=publisher_login,
        not_before=row["updated_at"],
    )
    if len(matches) == 1:
        store.complete_outbox(row["id"], matches[0], utc_now())
        return {"phase": "COMPLETE", "outbox_id": row["id"], "receipt": matches[0]}
    error = "GITHUB_READBACK_MISSING" if not matches else "GITHUB_READBACK_DUPLICATE"
    store.hold_outbox(row["id"], error, utc_now())
    raise CoordinationError(error)


def publish(store: CoordinationStore, outbox_id: int) -> dict[str, Any]:
    row_value = store.connection.execute(
        "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
    ).fetchone()
    if row_value is None:
        raise CoordinationError("OUTBOX_NOT_FOUND")
    row = dict(row_value)
    if row["state"] == "COMPLETE":
        return {
            "phase": "COMPLETE",
            "outbox_id": outbox_id,
            "receipt": row["remote_receipt"],
        }
    if row["state"] == "HOLD":
        raise CoordinationError("OUTBOX_STATE_CONFLICT")
    payload = json.loads(row["payload_json"])
    body = payload.get("body")
    if not isinstance(body, str) or not body:
        raise CoordinationError("INVALID_OUTBOX_ITEM")

    published_body = _published_body(body, row["idempotency_key"])
    user = _gh_json(["api", "user"])
    publisher_login = user.get("login") if isinstance(user, dict) else None
    if not isinstance(publisher_login, str) or not publisher_login:
        raise CoordinationError("GITHUB_IDENTITY_INVALID")

    if row["state"] == "INFLIGHT":
        return _complete_from_readback(
            store,
            row,
            published_body,
            publisher_login=publisher_login,
        )

    refreshed_payload = fetch_object(
        row["repository"], row["object_kind"], row["object_number"]
    )
    refreshed = store.ingest_snapshot(
        repository=row["repository"],
        object_kind=row["object_kind"],
        object_number=row["object_number"],
        payload=refreshed_payload,
        source_updated_at=refreshed_payload.get(
            "_projection_updated_at", refreshed_payload["updated_at"]
        ),
        fetched_at=utc_now(),
    )
    if refreshed.payload_sha256 != row["expected_source_sha256"]:
        store.hold_outbox(outbox_id, "SOURCE_SNAPSHOT_DRIFT", utc_now())
        raise CoordinationError("SOURCE_SNAPSHOT_DRIFT")

    reserved = store.reserve_outbox(outbox_id, utc_now())
    try:
        response = _gh_json(
            [
                "api",
                "--method",
                "POST",
                f"repos/{reserved['repository']}/issues/{reserved['object_number']}/comments",
                "--input",
                "-",
            ],
            {"body": published_body},
        )
        comment_id = response.get("id") if isinstance(response, dict) else None
        response_user = response.get("user") or {} if isinstance(response, dict) else {}
        if (
            not isinstance(comment_id, int)
            or response.get("body") != published_body
            or response_user.get("login") != publisher_login
        ):
            raise CoordinationError("GITHUB_WRITE_AMBIGUOUS")
    except CoordinationError:
        return _complete_from_readback(
            store,
            reserved,
            published_body,
            publisher_login=publisher_login,
        )

    readback = _gh_json(
        ["api", f"repos/{reserved['repository']}/issues/comments/{comment_id}"]
    )
    readback_user = readback.get("user") or {} if isinstance(readback, dict) else {}
    if (
        not isinstance(readback, dict)
        or readback.get("body") != published_body
        or readback_user.get("login") != publisher_login
    ):
        return _complete_from_readback(
            store,
            reserved,
            published_body,
            publisher_login=publisher_login,
        )
    receipt = f"comment:{comment_id}"
    store.complete_outbox(outbox_id, receipt, utc_now())
    return {"phase": "COMPLETE", "outbox_id": outbox_id, "receipt": receipt}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--outbox-id", type=int, required=True)
    parser.add_argument("--confirmation", required=True)
    args = parser.parse_args()
    if args.confirmation != CONFIRMATION:
        print(canonical_json({"phase": "HOLD", "error": "PUBLICATION_NOT_CONFIRMED"}))
        return 1
    try:
        store = CoordinationStore(DEFAULT_DATABASE)
        result = publish(store, args.outbox_id)
        store.close()
        print(canonical_json(result))
        return 0
    except CoordinationError as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
    except Exception:
        print(canonical_json({"phase": "HOLD", "error": "COORDINATION_FAILED"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
