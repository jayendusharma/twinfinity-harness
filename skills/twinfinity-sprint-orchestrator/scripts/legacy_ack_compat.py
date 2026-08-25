"""Read-only compatibility for immutable legacy ACK provenance.

This module deliberately has no command-line entry point, process launch,
network transport, SQLite write, or session-routing capability.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from typing import Any


TERMINAL_ACK_PHASES = {"COMPLETE", "HOLD"}
REQUIRED_ACK_TURN_COLUMNS = {"contract_key", "session_id", "turn_id", "phase"}
RECEIVER_DIGEST_FIELD = re.compile(r"(?i)receiver-body\s+stable\s+digest\s*:")
CANONICAL_RECEIVER_DIGEST_FIELD = re.compile(
    r"^Receiver-body stable digest: `([0-9a-f]{64})`$"
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def ack_transaction_sha256(receiver_body: str, echo_body: str) -> str:
    """Reproduce the historical immutable receiver/echo receipt digest."""

    return sha256_text(f"{receiver_body}\0{echo_body}")


def has_exact_rendezvous_token_binding(
    issue_number: int,
    rendezvous_token: str,
    authorization_body: str,
    receiver_body: str,
    echo_body: str,
) -> bool:
    """Parse the historical issue-bound v2 token without enabling transport."""

    match = re.fullmatch(
        r"issue #([1-9][0-9]*) generation ([1-9][0-9]*) deterministic ACK v2",
        rendezvous_token,
    )
    if match is None or int(match.group(1)) != issue_number:
        return False
    token_line = f"Authorized rendezvous token: {rendezvous_token}"
    this_comment_line = "Authorized rendezvous: `THIS COMMENT`"
    candidate = re.compile(r"(?i)\brendezvous\b[^:\n]*:")

    def fields(body: str) -> list[str]:
        return [
            line
            for line in body.splitlines()
            if candidate.search(re.sub(r"[*_`~]", "", line))
        ]

    return (
        fields(authorization_body) == [this_comment_line, token_line]
        and fields(receiver_body) == [token_line]
        and fields(echo_body) == [token_line]
    )


def has_exact_receiver_body_digest_binding(receiver_body: str, echo_body: str) -> bool:
    """Parse the historical echo field bound to exact receiver bytes."""

    fields = [
        line for line in echo_body.splitlines() if RECEIVER_DIGEST_FIELD.search(line)
    ]
    if len(fields) != 1:
        return False
    match = CANONICAL_RECEIVER_DIGEST_FIELD.fullmatch(fields[0])
    return match is not None and match.group(1) == sha256_text(receiver_body)


def inspect_legacy_ack_rows(connection: sqlite3.Connection) -> dict[str, Any]:
    """Inspect historical ACK rows without creating, updating, or deleting them."""

    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ack_turns'"
    ).fetchone()
    if table is None:
        return {"table_present": False, "row_count": 0, "nonterminal": []}
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(ack_turns)")
    }
    if not REQUIRED_ACK_TURN_COLUMNS <= columns:
        return {
            "table_present": True,
            "row_count": None,
            "nonterminal": [],
            "error": "LEGACY_ACK_SCHEMA_UNREADABLE",
        }
    rows = connection.execute(
        "SELECT contract_key, phase FROM ack_turns ORDER BY contract_key"
    ).fetchall()
    return {
        "table_present": True,
        "row_count": len(rows),
        "nonterminal": [
            {"contract_key": str(row[0]), "phase": str(row[1])}
            for row in rows
            if str(row[1]) not in TERMINAL_ACK_PHASES
        ],
    }
