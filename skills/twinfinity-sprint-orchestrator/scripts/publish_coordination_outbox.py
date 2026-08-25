#!/usr/bin/env python3
"""Publish one preauthorized material GitHub comment from the SQLite outbox.

The publisher performs at most one external write. Recovery from an INFLIGHT
row is readback-only and never blindly resends.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
    terminal_published_body,
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
    return terminal_published_body(body, idempotency_key)


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
    observed_publisher_login: str | None = None,
) -> dict[str, Any]:
    terminal_context = store.terminal_outbox_context(int(row["id"]))
    matches = _matching_receipts(
        row["repository"],
        row["object_number"],
        body,
        publisher_login=publisher_login,
        not_before=(
            str(terminal_context["created_at"])
            if terminal_context is not None
            else row["updated_at"]
        ),
    )
    if len(matches) == 1:
        if terminal_context is None:
            store.complete_outbox(row["id"], matches[0], utc_now())
        else:
            store.complete_terminal_outbox_from_readback(
                outbox_id=int(row["id"]),
                remote_receipt=matches[0],
                published_body=body,
                publisher_login=publisher_login,
                now=utc_now(),
            )
        return {"phase": "COMPLETE", "outbox_id": row["id"], "receipt": matches[0]}
    error = "GITHUB_READBACK_MISSING" if not matches else "GITHUB_READBACK_DUPLICATE"
    if terminal_context is None:
        store.hold_outbox(row["id"], error, utc_now())
    elif (
        observed_publisher_login is not None
        and observed_publisher_login != publisher_login
        and error == "GITHUB_READBACK_MISSING"
    ):
        identity_error = "TERMINAL_OUTBOX_PUBLISHER_IDENTITY_MISMATCH"
        store.hold_terminal_outbox_publisher_identity(
            outbox_id=int(row["id"]),
            observed_publisher_login=observed_publisher_login,
            error=identity_error,
            now=utc_now(),
        )
        raise CoordinationError(identity_error)
    else:
        store.record_terminal_outbox_readback_miss(
            outbox_id=int(row["id"]),
            error=error,
            publisher_login=publisher_login,
            now=utc_now(),
        )
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
    payload = json.loads(row["payload_json"])
    body = payload.get("body")
    if not isinstance(body, str) or not body:
        raise CoordinationError("INVALID_OUTBOX_ITEM")

    published_body = _published_body(body, row["idempotency_key"])
    user = _gh_json(["api", "user"])
    publisher_login = user.get("login") if isinstance(user, dict) else None
    if not isinstance(publisher_login, str) or not publisher_login:
        raise CoordinationError("GITHUB_IDENTITY_INVALID")

    terminal_context = store.terminal_outbox_context(outbox_id)
    if terminal_context is not None:
        original_publisher = terminal_context.get("publisher_login")
        if original_publisher is None:
            if row["state"] != "PREPARED":
                error = "TERMINAL_OUTBOX_PUBLISHER_UNBOUND"
                store.hold_terminal_outbox_publisher_identity(
                    outbox_id=outbox_id,
                    observed_publisher_login=publisher_login,
                    error=error,
                    now=utc_now(),
                )
                raise CoordinationError(error)
            try:
                bound = store.bind_terminal_outbox_publisher(
                    outbox_id=outbox_id,
                    publisher_login=publisher_login,
                    now=utc_now(),
                )
            except CoordinationError as exc:
                if str(exc) != "TERMINAL_OUTBOX_PUBLISHER_IDENTITY_MISMATCH":
                    raise
                rebound_context = store.terminal_outbox_context(outbox_id)
                original_publisher = (
                    None
                    if rebound_context is None
                    else rebound_context.get("publisher_login")
                )
                if not isinstance(original_publisher, str):
                    raise
            else:
                original_publisher = bound["publisher_login"]
        if original_publisher != publisher_login:
            # A rotated credential may prove the exact original actor's marker,
            # but it can neither assume that identity nor re-arm the envelope.
            return _complete_from_readback(
                store,
                row,
                published_body,
                publisher_login=str(original_publisher),
                observed_publisher_login=publisher_login,
            )
        publisher_login = str(original_publisher)
        if (
            row["state"] == "PREPARED"
            and terminal_context.get("recovery_state") == "RETRY_READY"
        ):
            # The bounded absence proof authorized a retry, but perform one
            # last original-actor marker scan immediately before POST so a
            # delayed GitHub read model cannot turn recovery into a duplicate.
            retry_matches = _matching_receipts(
                row["repository"],
                row["object_number"],
                published_body,
                publisher_login=publisher_login,
                not_before=str(terminal_context["created_at"]),
            )
            if len(retry_matches) == 1:
                store.complete_terminal_outbox_from_readback(
                    outbox_id=outbox_id,
                    remote_receipt=retry_matches[0],
                    published_body=published_body,
                    publisher_login=publisher_login,
                    now=utc_now(),
                )
                return {
                    "phase": "COMPLETE",
                    "outbox_id": outbox_id,
                    "receipt": retry_matches[0],
                }
            if len(retry_matches) > 1:
                store.record_terminal_outbox_readback_miss(
                    outbox_id=outbox_id,
                    error="GITHUB_READBACK_DUPLICATE",
                    publisher_login=publisher_login,
                    now=utc_now(),
                )
                raise CoordinationError("GITHUB_READBACK_DUPLICATE")

    if row["state"] in {"INFLIGHT", "HOLD"}:
        if row["state"] == "HOLD" and terminal_context is None:
            raise CoordinationError("OUTBOX_STATE_CONFLICT")
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
    if store.terminal_outbox_context(outbox_id) is None:
        store.complete_outbox(outbox_id, receipt, utc_now())
    else:
        store.complete_terminal_outbox_from_readback(
            outbox_id=outbox_id,
            remote_receipt=receipt,
            published_body=published_body,
            publisher_login=publisher_login,
            now=utc_now(),
        )
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
