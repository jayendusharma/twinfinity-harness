#!/usr/bin/env python3
"""Fail-closed GitHub issue-body compare-and-swap transaction.

The transport is intentionally injected.  This module never imports a GitHub
client or performs network access itself, which keeps the transaction testable
without mutating an issue.  A caller supplies canonical reads and the single
PATCH operation through ``IssueBodyTransport``.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from collections.abc import Callable
from typing import Protocol


class Outcome(StrEnum):
    """Typed terminal outcomes for an issue-body transaction."""

    APPLIED = "APPLIED"
    ALREADY_APPLIED = "ALREADY_APPLIED"
    CONFLICT = "CONFLICT"
    POSTCONDITION_FAILED = "POSTCONDITION_FAILED"


class AtomicWriteDisposition(StrEnum):
    APPLIED = "APPLIED"
    CONFLICT = "CONFLICT"


class AtomicCASUnsupported(RuntimeError):
    """Raised when a transport cannot make the precondition atomic with write."""


@dataclass(frozen=True, slots=True)
class IssueSnapshot:
    body: bytes
    updated_at: str


@dataclass(frozen=True, slots=True)
class IssueBodyMutation:
    repository: str
    issue_number: int
    expected_body: bytes
    expected_updated_at: str
    desired_body: bytes
    expected_body_sha256: str
    desired_body_sha256: str

    @classmethod
    def from_bodies(
        cls,
        *,
        repository: str,
        issue_number: int,
        expected_body: bytes,
        expected_updated_at: str,
        desired_body: bytes,
    ) -> "IssueBodyMutation":
        return cls(
            repository=repository,
            issue_number=issue_number,
            expected_body=expected_body,
            expected_updated_at=expected_updated_at,
            desired_body=desired_body,
            expected_body_sha256=sha256(expected_body),
            desired_body_sha256=sha256(desired_body),
        )

    def validate(self) -> None:
        if not self.repository or self.issue_number <= 0:
            raise ValueError("repository and a positive issue number are required")
        if not self.expected_updated_at:
            raise ValueError("expected_updated_at is required")
        if self.expected_body_sha256 != sha256(self.expected_body):
            raise ValueError("expected body digest does not match expected bytes")
        if self.desired_body_sha256 != sha256(self.desired_body):
            raise ValueError("desired body digest does not match desired bytes")


@dataclass(frozen=True, slots=True)
class TransactionResult:
    outcome: Outcome
    expected_body_sha256: str
    desired_body_sha256: str
    observed_body_sha256: str | None
    observed_updated_at: str | None
    patch_count: int
    canonical_read_count: int
    retry_suppressed: bool = False
    detail: str = ""


class IssueBodyTransport(Protocol):
    """Connector adapter contract.

    ``read_canonical`` must bypass local/connector caches and return the
    canonical rendered issue body as exact UTF-8 bytes plus ``updated_at``.
    """

    def read_canonical(
        self,
        repository: str,
        issue_number: int,
        *,
        no_cache: bool,
    ) -> IssueSnapshot:
        ...

    supports_atomic_compare_and_swap: bool

    def atomic_compare_and_swap_body(
        self,
        mutation: IssueBodyMutation,
    ) -> AtomicWriteDisposition:
        ...


class GitHubConnectorTransport:
    """Fail-closed adapter for the installed GitHub connector surface.

    The connector exposes canonical issue reads and an unconditional
    ``update_issue`` PATCH, but no server-enforced expected-body, digest,
    timestamp, ETag, or revision precondition.  GitHub documents that
    conditional requests for unsafe methods are unsupported unless an endpoint
    explicitly opts in; the issue-update endpoint does not.  Consequently this
    adapter deliberately never calls the supplied updater.
    """

    supports_atomic_compare_and_swap = False

    def __init__(
        self,
        *,
        canonical_reader: Callable[[str, int, bool], IssueSnapshot],
        unconditional_updater: Callable[[str, int, bytes], object],
    ) -> None:
        self._canonical_reader = canonical_reader
        self._unconditional_updater = unconditional_updater

    def read_canonical(
        self,
        repository: str,
        issue_number: int,
        *,
        no_cache: bool,
    ) -> IssueSnapshot:
        return self._canonical_reader(repository, issue_number, no_cache)

    def atomic_compare_and_swap_body(
        self,
        mutation: IssueBodyMutation,
    ) -> AtomicWriteDisposition:
        del mutation
        raise AtomicCASUnsupported(
            "installed GitHub connector has no atomic issue-body CAS primitive"
        )


class AttemptLedger(Protocol):
    """Atomically consumes the one allowed PATCH for a desired digest."""

    def reserve_patch(self, mutation: IssueBodyMutation) -> bool:
        ...


class InMemoryAttemptLedger:
    """Deterministic ledger for tests and single-process adapters."""

    def __init__(self) -> None:
        self._keys: set[str] = set()

    def reserve_patch(self, mutation: IssueBodyMutation) -> bool:
        key = attempt_key(mutation)
        if key in self._keys:
            return False
        self._keys.add(key)
        return True


class SQLiteAttemptLedger:
    """Durable, cross-process same-digest retry suppression.

    Reservation is recorded before PATCH.  Once reserved, the same repository,
    issue, and desired digest can never emit another PATCH from this ledger,
    including after a transport or postcondition failure.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS issue_body_patch_attempts (
                    attempt_key TEXT PRIMARY KEY,
                    repository TEXT NOT NULL,
                    issue_number INTEGER NOT NULL,
                    expected_body_sha256 TEXT NOT NULL,
                    expected_updated_at TEXT NOT NULL,
                    desired_body_sha256 TEXT NOT NULL,
                    reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30, isolation_level=None)

    def reserve_patch(self, mutation: IssueBodyMutation) -> bool:
        key = attempt_key(mutation)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO issue_body_patch_attempts (
                        attempt_key,
                        repository,
                        issue_number,
                        expected_body_sha256,
                        expected_updated_at,
                        desired_body_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        mutation.repository,
                        mutation.issue_number,
                        mutation.expected_body_sha256,
                        mutation.expected_updated_at,
                        mutation.desired_body_sha256,
                    ),
                )
            except sqlite3.IntegrityError:
                connection.execute("ROLLBACK")
                return False
            connection.execute("COMMIT")
            return True


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def attempt_key(mutation: IssueBodyMutation) -> str:
    """Stable suppression key scoped to repo, issue, and desired digest."""

    payload = (
        f"issue-body-cas-v1\0{mutation.repository}\0{mutation.issue_number}\0"
        f"{mutation.desired_body_sha256}"
    ).encode("utf-8")
    return sha256(payload)


def apply_issue_body_mutation(
    mutation: IssueBodyMutation,
    *,
    transport: IssueBodyTransport,
    ledger: AttemptLedger,
) -> TransactionResult:
    """Apply one fail-closed issue-body transaction.

    Invariants:
    - both initial and post-PATCH reads are canonical/no-cache transport reads;
    - exact desired bytes short-circuit to ``ALREADY_APPLIED``;
    - body digest *and* timestamp must match the expected snapshot before PATCH;
    - the transport must make the expected body/digest/timestamp precondition
      atomic with its PATCH; an unconditional connector is rejected;
    - the ledger is reserved before atomic PATCH and suppresses every
      same-digest retry;
    - at most one atomic PATCH is issued;
    - after an attempted atomic PATCH, exactly one canonical readback determines
      success.
    """

    mutation.validate()
    reads = 0

    if not transport.supports_atomic_compare_and_swap:
        return _result(
            mutation,
            outcome=Outcome.POSTCONDITION_FAILED,
            snapshot=None,
            patch_count=0,
            canonical_read_count=0,
            detail="transport_does_not_support_atomic_issue_body_cas",
        )

    reads += 1
    try:
        current = transport.read_canonical(
            mutation.repository,
            mutation.issue_number,
            no_cache=True,
        )
    except Exception as exc:  # transport boundary: fail closed with a typed result
        return _result(
            mutation,
            outcome=Outcome.POSTCONDITION_FAILED,
            snapshot=None,
            patch_count=0,
            canonical_read_count=reads,
            detail=f"initial_canonical_read_failed:{type(exc).__name__}",
        )

    current_digest = sha256(current.body)
    if current.body == mutation.desired_body:
        return _result(
            mutation,
            outcome=Outcome.ALREADY_APPLIED,
            snapshot=current,
            patch_count=0,
            canonical_read_count=reads,
            detail="desired_body_already_canonical",
        )

    if (
        current_digest != mutation.expected_body_sha256
        or current.body != mutation.expected_body
        or current.updated_at != mutation.expected_updated_at
    ):
        return _result(
            mutation,
            outcome=Outcome.CONFLICT,
            snapshot=current,
            patch_count=0,
            canonical_read_count=reads,
            detail="expected_body_or_timestamp_mismatch",
        )

    try:
        reserved = ledger.reserve_patch(mutation)
    except Exception as exc:
        return _result(
            mutation,
            outcome=Outcome.POSTCONDITION_FAILED,
            snapshot=current,
            patch_count=0,
            canonical_read_count=reads,
            detail=f"attempt_ledger_failed:{type(exc).__name__}",
        )

    if not reserved:
        return _result(
            mutation,
            outcome=Outcome.POSTCONDITION_FAILED,
            snapshot=current,
            patch_count=0,
            canonical_read_count=reads,
            retry_suppressed=True,
            detail="same_desired_digest_retry_suppressed",
        )

    patch_error: Exception | None = None
    write_disposition: AtomicWriteDisposition | None = None
    try:
        write_disposition = transport.atomic_compare_and_swap_body(mutation)
    except Exception as exc:  # a canonical readback is still required
        patch_error = exc

    reads += 1
    try:
        readback = transport.read_canonical(
            mutation.repository,
            mutation.issue_number,
            no_cache=True,
        )
    except Exception as exc:
        detail = f"canonical_readback_failed:{type(exc).__name__}"
        if patch_error is not None:
            detail = (
                f"patch_failed:{type(patch_error).__name__};"
                f"{detail}"
            )
        return _result(
            mutation,
            outcome=Outcome.POSTCONDITION_FAILED,
            snapshot=None,
            patch_count=1,
            canonical_read_count=reads,
            detail=detail,
        )

    if readback.body == mutation.desired_body:
        return _result(
            mutation,
            outcome=Outcome.APPLIED,
            snapshot=readback,
            patch_count=1,
            canonical_read_count=reads,
            detail="byte_exact_canonical_readback",
        )

    if write_disposition == AtomicWriteDisposition.CONFLICT:
        return _result(
            mutation,
            outcome=Outcome.CONFLICT,
            snapshot=readback,
            patch_count=1,
            canonical_read_count=reads,
            detail="atomic_write_precondition_conflict",
        )

    detail = "canonical_readback_body_mismatch"
    if patch_error is not None:
        detail = f"patch_failed:{type(patch_error).__name__};{detail}"
    return _result(
        mutation,
        outcome=Outcome.POSTCONDITION_FAILED,
        snapshot=readback,
        patch_count=1,
        canonical_read_count=reads,
        detail=detail,
    )


def _result(
    mutation: IssueBodyMutation,
    *,
    outcome: Outcome,
    snapshot: IssueSnapshot | None,
    patch_count: int,
    canonical_read_count: int,
    retry_suppressed: bool = False,
    detail: str,
) -> TransactionResult:
    return TransactionResult(
        outcome=outcome,
        expected_body_sha256=mutation.expected_body_sha256,
        desired_body_sha256=mutation.desired_body_sha256,
        observed_body_sha256=sha256(snapshot.body) if snapshot is not None else None,
        observed_updated_at=snapshot.updated_at if snapshot is not None else None,
        patch_count=patch_count,
        canonical_read_count=canonical_read_count,
        retry_suppressed=retry_suppressed,
        detail=detail,
    )


__all__ = [
    "AttemptLedger",
    "AtomicCASUnsupported",
    "AtomicWriteDisposition",
    "GitHubConnectorTransport",
    "InMemoryAttemptLedger",
    "IssueBodyMutation",
    "IssueBodyTransport",
    "IssueSnapshot",
    "Outcome",
    "SQLiteAttemptLedger",
    "TransactionResult",
    "apply_issue_body_mutation",
    "attempt_key",
    "sha256",
]
