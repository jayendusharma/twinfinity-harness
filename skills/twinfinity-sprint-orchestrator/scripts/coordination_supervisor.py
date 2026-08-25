#!/usr/bin/env python3
"""Owner-only same-host wake supervisor for the SQLite coordination plane."""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import subprocess
from dataclasses import dataclass
from typing import Callable

from coordination_store import (
    ACTIVE_EXECUTION_STATUSES,
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    MUTATING_MESSAGE_TOPICS,
    canonical_json,
    coordination_identity_role,
    digest_json,
    recipient_matches_topic,
    terminal_watch_key,
    timestamp_after,
    utc_now,
)
from executor_registry import (
    ENDPOINT_ID,
    RegistryError,
    active_attempt_for_lineage,
    active_attempt_for_target,
    active_planner_attempt_for_repository,
    attempt_lineage_for_target,
    current_endpoint,
    planner_repository_for_target,
    target_progress_digest,
)
from role_executor_transport import launch_role_executor, role_executor_command
from portfolio_convergence import (
    DEFAULT_CONVERGENCE_LIMIT,
    MAX_CONVERGENCE_LIMIT,
    PortfolioConvergence,
)
from approval_ledger import enqueue_published_readiness_decision_notices
from kanban_readiness import (
    ReadinessError,
    enqueue_due_readiness_revisits,
    pickup_due_receipts,
    stop_revoked_readiness_successors,
)


RETRY_SECONDS = 60
MAX_RETRY_SECONDS = 15 * 60
MAX_LAUNCH_ATTEMPTS_PER_RUN = 4
MAX_MESSAGE_LAUNCH_ATTEMPTS_PER_RUN = 3
MAX_TERMINAL_WATCH_LAUNCH_ATTEMPTS_PER_RUN = 1
MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS = 3
MAX_DUE_MESSAGE_RETRY_LAUNCH_ATTEMPTS_PER_RUN = 1
LOCK = DEFAULT_DATABASE.parent / "coordination-supervisor.lock"


@dataclass(frozen=True)
class SchedulerLaunchPolicy:
    """Per-pass transport budget; this does not consume role capacity."""

    total: int = MAX_LAUNCH_ATTEMPTS_PER_RUN
    messages: int = MAX_MESSAGE_LAUNCH_ATTEMPTS_PER_RUN
    terminal_watches: int = MAX_TERMINAL_WATCH_LAUNCH_ATTEMPTS_PER_RUN

    def __post_init__(self) -> None:
        values = (self.total, self.messages, self.terminal_watches)
        if (
            any(type(value) is not int for value in values)
            or self.total <= 0
            or self.messages < 0
            or self.terminal_watches <= 0
            or self.messages + self.terminal_watches > self.total
        ):
            raise CoordinationError("SCHEDULER_LAUNCH_POLICY_INVALID")

    def as_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "messages": self.messages,
            "terminal_watches": self.terminal_watches,
        }


DEFAULT_LAUNCH_POLICY = SchedulerLaunchPolicy()


def _epoch(timestamp: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


def _retry_seconds(attempts: int) -> int:
    return min(RETRY_SECONDS * (2 ** max(0, attempts - 1)), MAX_RETRY_SECONDS)


def canonical_session_running(
    identity: str, target_kind: str, target_key: str
) -> bool:
    """Use exact-target attempt state, never process-list resume inference."""

    try:
        store = CoordinationStore(DEFAULT_DATABASE)
    except CoordinationError:
        return False
    try:
        return (
            active_attempt_for_target(
                store.connection, identity, target_kind, target_key
            )
            is not None
        )
    finally:
        store.close()


def _canonical_session_command(
    identity: str,
    prompt: str,
    *,
    target_kind: str = "message",
    target_key: str = "0",
) -> list[str]:
    """Build a fresh endpoint executor command with no legacy resume path."""

    if not isinstance(identity, str) or ENDPOINT_ID.fullmatch(identity) is None:
        raise CoordinationError("NONCANONICAL_ROLE_ENDPOINT")
    role = identity.split(".")[1]
    return role_executor_command(
        role=role,
        endpoint_id=identity,
        target_kind=target_kind,
        target_key=target_key,
        prompt=prompt,
    )


def _launch_canonical_session(
    identity: str, prompt: str, *, target_kind: str, target_key: str
) -> int:
    if not isinstance(identity, str) or ENDPOINT_ID.fullmatch(identity) is None:
        raise CoordinationError("NONCANONICAL_ROLE_ENDPOINT")
    role = identity.split(".")[1]
    return_code = launch_role_executor(
        role=role,
        endpoint_id=identity,
        target_kind=target_kind,
        target_key=target_key,
        prompt=prompt,
        runner=subprocess.run,
    )
    if return_code != 0:
        raise OSError("ROLE_EXECUTOR_TRANSIENT_LAUNCH_FAILED")
    return 0


def launch_canonical_session(session_id: str, message_id: int) -> int:
    return _launch_canonical_session(
        session_id,
        (
            f"SQLite coordination wake for exact inbox row {message_id}. "
            "Read and validate that row from the owner-only canonical database before acting. "
            "This wake carries no authority beyond the typed row and its current source/item guards."
        ),
        target_kind="message",
        target_key=str(message_id),
    )


def launch_terminal_watch_session(session_id: str, watch_key: str) -> int:
    return _launch_canonical_session(
        session_id,
        (
            f"SQLite terminal-followup wake for exact watch {watch_key}. "
            "Read and validate the watch and its current coordination item before acting. "
            "The watch carries no new authority. Continue the existing bounded lineage through "
            "every immediately executable routine step toward merge, cleanup, and capacity "
            "release; do not stop merely because one material gate passed. Heartbeat only when "
            "a genuine external wait or hard stop prevents another immediate step, and close the "
            "watch only through the exact item transition."
        ),
        target_kind="terminal_watch",
        target_key=watch_key,
    )


class CoordinationSupervisor:
    def __init__(
        self,
        store: CoordinationStore,
        *,
        launcher: Callable[[str, int], int] = launch_canonical_session,
        terminal_watch_launcher: Callable[[str, str], int] = launch_terminal_watch_session,
        process_checker: Callable[[str, str, str], bool] = canonical_session_running,
        convergence: PortfolioConvergence | None = None,
        convergence_limit: int = DEFAULT_CONVERGENCE_LIMIT,
        launch_policy: SchedulerLaunchPolicy = DEFAULT_LAUNCH_POLICY,
    ) -> None:
        if convergence_limit <= 0 or convergence_limit > MAX_CONVERGENCE_LIMIT:
            raise CoordinationError("CONVERGENCE_LIMIT_INVALID")
        self.store = store
        self.launcher = launcher
        self.terminal_watch_launcher = terminal_watch_launcher
        self.process_checker = process_checker
        self.convergence = convergence or PortfolioConvergence(store)
        self.convergence_limit = convergence_limit
        if not isinstance(launch_policy, SchedulerLaunchPolicy):
            raise CoordinationError("SCHEDULER_LAUNCH_POLICY_INVALID")
        self.launch_policy = launch_policy

    def _ensure_terminal_watches(self, now: str) -> tuple[list[str], list[dict[str, object]]]:
        opened: list[str] = []
        held: list[dict[str, object]] = []
        with self.store.transaction():
            items = self.store.connection.execute(
                """
                SELECT * FROM coordination_items
                WHERE allocation_class='ACTIVE'
                  AND status IN ('ACTIVE', 'ACTIVE_FENCED', 'MONITOR')
                ORDER BY repository, issue_number
                """
            ).fetchall()
            for item in items:
                key = terminal_watch_key(
                    item["repository"], int(item["issue_number"]), int(item["generation"])
                )
                watch = self.store.connection.execute(
                    "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                    (key,),
                ).fetchone()
                if watch is not None:
                    continue
                session_id = item["accountable_session_id"]
                lease = item["lease_manifest_sha256"]
                role = coordination_identity_role(self.store.connection, session_id)
                endpoint = (
                    current_endpoint(self.store.connection, role)
                    if role in {"development", "sre"} else None
                )
                if endpoint is None or not lease:
                    error = "TERMINAL_WATCH_BACKFILL_INVALID_LINEAGE"
                    held.append(
                        {
                            "repository": item["repository"],
                            "issue_number": int(item["issue_number"]),
                            "error": error,
                        }
                    )
                    self.store._event(
                        "TERMINAL_WATCH_BACKFILL_HELD",
                        key,
                        {"error": error},
                        now,
                    )
                    continue
                self.store.connection.execute(
                    """
                    INSERT INTO coordination_terminal_watches(
                        watch_key, repository, issue_number, generation,
                        accountable_session_id, lease_manifest_sha256, state,
                        attempts, process_id, last_heartbeat_at, next_wake_at,
                        updated_at, last_error
                    ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 0, NULL, ?, ?, ?, NULL)
                    """,
                    (
                        key,
                        item["repository"],
                        item["issue_number"],
                        item["generation"],
                        str(endpoint["endpoint_id"]),
                        lease,
                        now,
                        now,
                        now,
                    ),
                )
                self.store._event(
                    "TERMINAL_WATCH_BACKFILLED",
                    key,
                    {"item_version": int(item["version"])},
                    now,
                )
                opened.append(key)
        return opened, held

    def _reserve_terminal_watch(self, watch_key: str, now: str) -> tuple[object | None, bool]:
        with self.store.transaction():
            watch = self.store.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            if watch is None or watch["state"] != "ACTIVE":
                return None, False
            role = coordination_identity_role(
                self.store.connection, str(watch["accountable_session_id"])
            )
            endpoint = (
                current_endpoint(self.store.connection, role)
                if role in {"development", "sre"}
                else None
            )
            if (
                endpoint is None
                or str(watch["accountable_session_id"])
                != str(endpoint["endpoint_id"])
            ):
                self.store.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='HOLD', process_id=NULL, updated_at=?,
                        last_error='TERMINAL_WATCH_ENDPOINT_NOT_CURRENT'
                    WHERE watch_key=? AND state='ACTIVE'
                    """,
                    (now, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_HELD",
                    watch_key,
                    {"error": "TERMINAL_WATCH_ENDPOINT_NOT_CURRENT"},
                    now,
                )
                return None, False
            item = self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (watch["repository"], watch["issue_number"]),
            ).fetchone()
            if item is None or item["allocation_class"] != "ACTIVE" or item["status"] not in ACTIVE_EXECUTION_STATUSES:
                self.store.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='COMPLETE', process_id=NULL, updated_at=?, last_error=NULL
                    WHERE watch_key=? AND state='ACTIVE'
                    """,
                    (now, watch_key),
                )
                self.store._event("TERMINAL_WATCH_COMPLETED", watch_key, {}, now)
                return None, False
            if (
                int(item["generation"]) != int(watch["generation"])
                or item["accountable_session_id"] != watch["accountable_session_id"]
                or item["lease_manifest_sha256"] != watch["lease_manifest_sha256"]
            ):
                self.store.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='HOLD', process_id=NULL, updated_at=?, last_error='TERMINAL_WATCH_LINEAGE_DRIFT'
                    WHERE watch_key=? AND state='ACTIVE'
                    """,
                    (now, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_HELD",
                    watch_key,
                    {"error": "TERMINAL_WATCH_LINEAGE_DRIFT"},
                    now,
                )
                return None, False
            if _epoch(now) < _epoch(watch["next_wake_at"]):
                return watch, False
            progress_sha256 = target_progress_digest(
                self.store.connection, "terminal_watch", watch_key
            )
            progress_changed = (
                watch["target_progress_sha256"] != progress_sha256
            )
            if (
                not progress_changed
                and int(watch["attempts"])
                >= MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS
            ):
                self.store.connection.execute(
                    """UPDATE coordination_terminal_watches
                    SET state='HOLD', process_id=NULL, updated_at=?,
                        last_error='TERMINAL_WATCH_RETRY_EXHAUSTED'
                    WHERE watch_key=? AND state='ACTIVE'""",
                    (now, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_HELD",
                    watch_key,
                    {"error": "TERMINAL_WATCH_RETRY_EXHAUSTED"},
                    now,
                )
                return None, False
            attempts = 1 if progress_changed else int(watch["attempts"]) + 1
            self.store.connection.execute(
                """
                UPDATE coordination_terminal_watches
                SET attempts=?, process_id=NULL, target_progress_sha256=?,
                    next_wake_at=?, updated_at=?, last_error=NULL
                WHERE watch_key=? AND state='ACTIVE'
                """,
                (
                    attempts,
                    progress_sha256,
                    timestamp_after(now, 300),
                    now,
                    watch_key,
                ),
            )
            return watch, True

    def _eligible_due_terminal_watch_lineages(self, now: str) -> set[str]:
        """Read due watch eligibility without consuming a wake or retry counter."""

        eligible: set[str] = set()
        watches = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE state='ACTIVE'"
        ).fetchall()
        for watch in watches:
            try:
                if _epoch(now) < _epoch(str(watch["next_wake_at"])):
                    continue
                role = coordination_identity_role(
                    self.store.connection, str(watch["accountable_session_id"])
                )
                endpoint = (
                    current_endpoint(self.store.connection, role)
                    if role in {"development", "sre"}
                    else None
                )
                item = self.store.connection.execute(
                    "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                    (watch["repository"], watch["issue_number"]),
                ).fetchone()
                if (
                    endpoint is None
                    or str(endpoint["endpoint_id"])
                    != str(watch["accountable_session_id"])
                    or item is None
                    or item["allocation_class"] != "ACTIVE"
                    or item["status"] not in ACTIVE_EXECUTION_STATUSES
                    or int(item["generation"]) != int(watch["generation"])
                    or item["accountable_session_id"]
                    != watch["accountable_session_id"]
                    or item["lease_manifest_sha256"]
                    != watch["lease_manifest_sha256"]
                    or self.process_checker(
                        str(endpoint["endpoint_id"]),
                        "terminal_watch",
                        str(watch["watch_key"]),
                    )
                ):
                    continue
                lineage = attempt_lineage_for_target(
                    self.store.connection,
                    "terminal_watch",
                    str(watch["watch_key"]),
                )
                if (
                    lineage is not None
                    and active_attempt_for_lineage(
                        self.store.connection, lineage.sha256
                    )
                    is None
                ):
                    eligible.add(lineage.sha256)
            except (CoordinationError, RegistryError, TypeError, ValueError):
                continue
        return eligible

    def _record_terminal_watch_launch(
        self, watch_key: str, process_id: int, now: str
    ) -> None:
        with self.store.transaction():
            self.store.connection.execute(
                """
                UPDATE coordination_terminal_watches
                SET process_id=?, updated_at=?
                WHERE watch_key=? AND state='ACTIVE'
                """,
                (process_id, now, watch_key),
            )
            self.store._event(
                "TERMINAL_WATCH_WAKE_STARTED",
                watch_key,
                {"process_id": process_id},
                now,
            )

    def _record_terminal_watch_launch_failure(self, watch_key: str, now: str) -> None:
        with self.store.transaction():
            watch = self.store.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            if watch is None or watch["state"] != "ACTIVE":
                return
            role = coordination_identity_role(
                self.store.connection, str(watch["accountable_session_id"])
            )
            endpoint = (
                current_endpoint(self.store.connection, role)
                if role in {"development", "sre"}
                else None
            )
            if (
                endpoint is None
                or str(endpoint["endpoint_id"])
                != str(watch["accountable_session_id"])
            ):
                error = "TERMINAL_WATCH_ENDPOINT_NOT_CURRENT"
                self.store.connection.execute(
                    """UPDATE coordination_terminal_watches
                    SET state='HOLD',process_id=NULL,updated_at=?,last_error=?
                    WHERE watch_key=? AND state='ACTIVE'""",
                    (now, error, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_HELD", watch_key, {"error": error}, now
                )
                return
            item = self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (watch["repository"], watch["issue_number"]),
            ).fetchone()
            if (
                item is None
                or item["allocation_class"] != "ACTIVE"
                or item["status"] not in ACTIVE_EXECUTION_STATUSES
            ):
                self.store.connection.execute(
                    """UPDATE coordination_terminal_watches
                    SET state='COMPLETE',process_id=NULL,updated_at=?,last_error=NULL
                    WHERE watch_key=? AND state='ACTIVE'""",
                    (now, watch_key),
                )
                self.store._event("TERMINAL_WATCH_COMPLETED", watch_key, {}, now)
                return
            if (
                int(item["generation"]) != int(watch["generation"])
                or item["accountable_session_id"] != watch["accountable_session_id"]
                or item["lease_manifest_sha256"] != watch["lease_manifest_sha256"]
            ):
                error = "TERMINAL_WATCH_LINEAGE_DRIFT"
                self.store.connection.execute(
                    """UPDATE coordination_terminal_watches
                    SET state='HOLD',process_id=NULL,updated_at=?,last_error=?
                    WHERE watch_key=? AND state='ACTIVE'""",
                    (now, error, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_HELD", watch_key, {"error": error}, now
                )
                return
            try:
                progress_sha256 = target_progress_digest(
                    self.store.connection, "terminal_watch", watch_key
                )
            except (RegistryError, TypeError, ValueError):
                error = "TERMINAL_WATCH_PROGRESS_READBACK_FAILED"
                self.store.connection.execute(
                    """UPDATE coordination_terminal_watches
                    SET state='HOLD',process_id=NULL,updated_at=?,last_error=?
                    WHERE watch_key=? AND state='ACTIVE'""",
                    (now, error, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_HELD", watch_key, {"error": error}, now
                )
                return
            if progress_sha256 != watch["target_progress_sha256"]:
                error = "TERMINAL_WATCH_WAKE_FAILED_AFTER_PROGRESS"
                self.store.connection.execute(
                    """UPDATE coordination_terminal_watches
                    SET attempts=0,process_id=NULL,target_progress_sha256=?,
                        updated_at=?,last_error=?
                    WHERE watch_key=? AND state='ACTIVE'""",
                    (progress_sha256, now, error, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_RETRY_BUDGET_RESET",
                    watch_key,
                    {"reason": "TARGET_PROGRESS_CHANGED"},
                    now,
                )
                return
            exhausted = (
                int(watch["attempts"]) >= MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS
            )
            error = (
                "TERMINAL_WATCH_RETRY_EXHAUSTED"
                if exhausted else "TERMINAL_WATCH_WAKE_FAILED"
            )
            self.store.connection.execute(
                """
                UPDATE coordination_terminal_watches
                SET state=?, process_id=NULL,
                    next_wake_at=?, updated_at=?, last_error=?
                WHERE watch_key=? AND state='ACTIVE'
                """,
                (
                    "HOLD" if exhausted else "ACTIVE",
                    timestamp_after(now, 60),
                    now,
                    error,
                    watch_key,
                ),
            )
            self.store._event(
                "TERMINAL_WATCH_HELD" if exhausted else "TERMINAL_WATCH_WAKE_FAILED",
                watch_key,
                {"error": error},
                now,
            )

    def _hold_terminal_watch(self, watch_key: str, error: str, now: str) -> None:
        with self.store.transaction():
            cursor = self.store.connection.execute(
                """UPDATE coordination_terminal_watches
                SET state='HOLD', process_id=NULL, updated_at=?, last_error=?
                WHERE watch_key=? AND state='ACTIVE'""",
                (now, error, watch_key),
            )
            if cursor.rowcount == 1:
                self.store._event(
                    "TERMINAL_WATCH_HELD", watch_key, {"error": error}, now
                )

    def _message_contract_error(self, row: object) -> str | None:
        if row["state"] not in {"PREPARED", "CLAIMED"}:
            return None
        try:
            payload = json.loads(row["payload_json"])
            if digest_json(payload) != row["payload_sha256"]:
                raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
            self.store._validate_message_source(payload)
            self.store._validate_message_contract(
                topic=row["topic"],
                recipient_session_id=row["recipient_session_id"],
                payload=payload,
            )
        except (CoordinationError, json.JSONDecodeError) as exc:
            return str(exc) if isinstance(exc, CoordinationError) else "INVALID_MESSAGE"
        return None

    def _hold_stale_message(self, row: object, error: str, now: str) -> None:
        with self.store.transaction():
            self._hold_stale_message_locked(row, error, now)

    def _hold_stale_message_locked(self, row: object, error: str, now: str) -> None:
        cursor = self.store.connection.execute(
            "UPDATE coordination_messages SET state='HOLD', updated_at=?, last_error=? WHERE id=? AND state IN ('PREPARED', 'CLAIMED')",
            (now, error, row["id"]),
        )
        if cursor.rowcount == 1:
            self.store._event(
                "MESSAGE_HELD", f"message:{row['id']}", {"error": error}, now
            )

    def _message_needs_worker(self, row: object) -> bool:
        if not recipient_matches_topic(
            self.store.connection,
            topic=row["topic"],
            recipient=row["recipient_session_id"],
        ):
            return False
        if row["state"] == "PREPARED":
            return self._message_contract_error(row) is None
        if row["state"] != "CLAIMED" or row["topic"] not in MUTATING_MESSAGE_TOPICS:
            return False
        return self._message_contract_error(row) is None

    def _order_message_rows(
        self, rows: list[object], now: str
    ) -> tuple[list[object], set[int], set[int]]:
        """Prioritize one oldest due retry without starving fresh targets."""

        wakes = {
            str(wake["wake_key"]): wake
            for wake in self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE state='INFLIGHT'"
            ).fetchall()
        }
        due: list[tuple[int, object]] = []
        fresh: list[object] = []
        cooling: list[object] = []
        retry_ids: set[int] = set()
        due_retry_ids: set[int] = set()
        for row in rows:
            message_id = int(row["id"])
            phase = "prepared" if row["state"] == "PREPARED" else "claimed"
            wake = wakes.get(f"message:{message_id}:{phase}")
            if wake is None:
                fresh.append(row)
                continue
            retry_ids.add(message_id)
            progress_changed = False
            try:
                progress_changed = (
                    wake["target_progress_sha256"]
                    != target_progress_digest(
                        self.store.connection, "message", str(message_id)
                    )
                )
                retry_due = progress_changed or (
                    _epoch(now) - _epoch(str(wake["last_attempt_at"]))
                    >= _retry_seconds(int(wake["attempts"]))
                )
            except (RegistryError, TypeError, ValueError):
                retry_due = True
            if retry_due:
                due_retry_ids.add(message_id)
                due.append((message_id, row))
            else:
                cooling.append(row)
        due.sort(key=lambda item: item[0])
        fresh.sort(key=lambda row: int(row["id"]))
        cooling.sort(key=lambda row: int(row["id"]))
        return (
            [item[1] for item in due] + fresh + cooling,
            retry_ids,
            due_retry_ids,
        )

    def _hold_rebound_existing_wake(self, row: object, now: str) -> bool:
        """Fence immutable wake payload drift even when this pass does not select it."""

        phase = "prepared" if row["state"] == "PREPARED" else "claimed"
        wake_key = f"message:{row['id']}:{phase}"
        wake = self.store.connection.execute(
            "SELECT message_payload_sha256,state FROM coordination_wakes WHERE wake_key=?",
            (wake_key,),
        ).fetchone()
        if (
            wake is None
            or wake["state"] != "INFLIGHT"
            or wake["message_payload_sha256"] == row["payload_sha256"]
        ):
            return False
        with self.store.transaction():
            current = self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (row["id"],)
            ).fetchone()
            current_wake = self.store.connection.execute(
                "SELECT message_payload_sha256,state FROM coordination_wakes WHERE wake_key=?",
                (wake_key,),
            ).fetchone()
            if (
                current is None
                or current_wake is None
                or current_wake["state"] != "INFLIGHT"
                or current_wake["message_payload_sha256"]
                == current["payload_sha256"]
            ):
                return False
            self._hold_stale_message_locked(current, "MESSAGE_PAYLOAD_MISMATCH", now)
            self.store.connection.execute(
                """UPDATE coordination_wakes
                SET state='COMPLETE', updated_at=?, last_error='MESSAGE_PAYLOAD_MISMATCH'
                WHERE wake_key=? AND state='INFLIGHT'""",
                (now, wake_key),
            )
            self.store._event(
                "WAKE_COMPLETED",
                wake_key,
                {"error": "MESSAGE_PAYLOAD_MISMATCH"},
                now,
            )
        return True

    def _reserve_wake(self, row: object, now: str) -> tuple[str | None, bool]:
        with self.store.transaction():
            # Re-read and validate at the reservation linearization point. The
            # earlier scan is advisory only; a source/item change between scan
            # and reservation must never leave a stale wake INFLIGHT.
            current_row = self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (row["id"],)
            ).fetchone()
            if current_row is None or current_row["state"] not in {
                "PREPARED",
                "CLAIMED",
            }:
                return None, False
            if not recipient_matches_topic(
                self.store.connection,
                topic=current_row["topic"],
                recipient=current_row["recipient_session_id"],
            ):
                self._hold_stale_message_locked(
                    current_row, "MESSAGE_ROLE_MISMATCH", now
                )
                return None, False
            contract_error = self._message_contract_error(current_row)
            if contract_error is not None:
                self._hold_stale_message_locked(current_row, contract_error, now)
                return None, False
            if not self._message_needs_worker(current_row):
                return None, False

            phase = (
                "prepared" if current_row["state"] == "PREPARED" else "claimed"
            )
            wake_key = f"message:{current_row['id']}:{phase}"
            progress_sha256 = target_progress_digest(
                self.store.connection, "message", str(current_row["id"])
            )
            current = self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE wake_key=?", (wake_key,)
            ).fetchone()
            if current is None:
                self.store.connection.execute(
                    """
                    INSERT INTO coordination_wakes(
                        wake_key, message_id, recipient_session_id, message_payload_sha256,
                        target_progress_sha256, state, attempts, process_id,
                        last_attempt_at, updated_at, last_error
                    ) VALUES (?, ?, ?, ?, ?, 'INFLIGHT', 1, NULL, ?, ?, NULL)
                    """,
                    (
                        wake_key,
                        current_row["id"],
                        current_row["recipient_session_id"],
                        current_row["payload_sha256"],
                        progress_sha256,
                        now,
                        now,
                    ),
                )
                return wake_key, True
            if current["message_payload_sha256"] != current_row["payload_sha256"]:
                self._hold_stale_message_locked(
                    current_row, "MESSAGE_PAYLOAD_MISMATCH", now
                )
                self.store.connection.execute(
                    "UPDATE coordination_wakes SET state='COMPLETE', updated_at=?, last_error='MESSAGE_PAYLOAD_MISMATCH' WHERE wake_key=? AND state='INFLIGHT'",
                    (now, wake_key),
                )
                self.store._event(
                    "WAKE_COMPLETED",
                    wake_key,
                    {"error": "MESSAGE_PAYLOAD_MISMATCH"},
                    now,
                )
                return wake_key, False
            if current["state"] != "INFLIGHT":
                return wake_key, False
            if current["target_progress_sha256"] != progress_sha256:
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET attempts=1, process_id=NULL, target_progress_sha256=?,
                        last_attempt_at=?, updated_at=?, last_error=NULL
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (progress_sha256, now, now, wake_key),
                )
                self.store._event(
                    "WAKE_RETRY_BUDGET_RESET",
                    wake_key,
                    {"reason": "TARGET_PROGRESS_CHANGED"},
                    now,
                )
                return wake_key, True
            if _epoch(now) - _epoch(current["last_attempt_at"]) < _retry_seconds(
                int(current["attempts"])
            ):
                return wake_key, False
            if int(current["attempts"]) >= MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS:
                self._hold_stale_message_locked(
                    current_row, "WAKE_RETRY_EXHAUSTED", now
                )
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET state='HOLD', process_id=NULL, updated_at=?,
                        last_error='WAKE_RETRY_EXHAUSTED'
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (now, wake_key),
                )
                self.store._event(
                    "WAKE_HELD",
                    wake_key,
                    {"error": "WAKE_RETRY_EXHAUSTED"},
                    now,
                )
                return wake_key, False
            self.store.connection.execute(
                "UPDATE coordination_wakes SET attempts=attempts+1, process_id=NULL, last_attempt_at=?, updated_at=?, last_error=NULL WHERE wake_key=?",
                (now, now, wake_key),
            )
            return wake_key, True

    def _record_launch(self, wake_key: str, process_id: int, now: str) -> None:
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_wakes SET process_id=?, updated_at=? WHERE wake_key=? AND state='INFLIGHT'",
                (process_id, now, wake_key),
            )
            self.store._event(
                "SESSION_WAKE_STARTED", wake_key, {"process_id": process_id}, now
            )

    def _record_launch_failure(self, wake_key: str, now: str) -> None:
        with self.store.transaction():
            wake = self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE wake_key=?",
                (wake_key,),
            ).fetchone()
            if wake is None or wake["state"] != "INFLIGHT":
                return
            message = self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (wake["message_id"],),
            ).fetchone()
            if message is None:
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET state='COMPLETE',process_id=NULL,updated_at=?,last_error=NULL
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (now, wake_key),
                )
                self.store._event("WAKE_COMPLETED", wake_key, {}, now)
                return
            if wake["message_payload_sha256"] != message["payload_sha256"]:
                self._hold_stale_message_locked(
                    message, "MESSAGE_PAYLOAD_MISMATCH", now
                )
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET state='COMPLETE',process_id=NULL,updated_at=?,
                        last_error='MESSAGE_PAYLOAD_MISMATCH'
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (now, wake_key),
                )
                self.store._event(
                    "WAKE_COMPLETED",
                    wake_key,
                    {"error": "MESSAGE_PAYLOAD_MISMATCH"},
                    now,
                )
                return
            contract_error = self._message_contract_error(message)
            if contract_error is not None:
                self._hold_stale_message_locked(message, contract_error, now)
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET state='COMPLETE',process_id=NULL,updated_at=?,last_error=?
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (now, contract_error, wake_key),
                )
                self.store._event(
                    "WAKE_COMPLETED", wake_key, {"error": contract_error}, now
                )
                return
            expected_phase = wake_key.rsplit(":", 1)[-1]
            current_phase = (
                "prepared" if message["state"] == "PREPARED" else "claimed"
            )
            if (
                message["state"] not in {"PREPARED", "CLAIMED"}
                or current_phase != expected_phase
                or not self._message_needs_worker(message)
            ):
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET state='COMPLETE',process_id=NULL,updated_at=?,last_error=NULL
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (now, wake_key),
                )
                self.store._event("WAKE_COMPLETED", wake_key, {}, now)
                return
            try:
                progress_sha256 = target_progress_digest(
                    self.store.connection, "message", str(wake["message_id"])
                )
            except (RegistryError, TypeError, ValueError):
                error = "WAKE_PROGRESS_READBACK_FAILED"
                self._hold_stale_message_locked(message, error, now)
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET state='HOLD',process_id=NULL,updated_at=?,last_error=?
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (now, error, wake_key),
                )
                self.store._event("WAKE_HELD", wake_key, {"error": error}, now)
                return
            if progress_sha256 != wake["target_progress_sha256"]:
                error = "WAKE_LAUNCH_FAILED_AFTER_PROGRESS"
                self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET attempts=1,process_id=NULL,target_progress_sha256=?,
                        last_attempt_at=?,updated_at=?,last_error=?
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (progress_sha256, now, now, error, wake_key),
                )
                self.store._event(
                    "WAKE_RETRY_BUDGET_RESET",
                    wake_key,
                    {"reason": "TARGET_PROGRESS_CHANGED"},
                    now,
                )
                return
            exhausted = (
                int(wake["attempts"]) >= MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS
            )
            error = "WAKE_RETRY_EXHAUSTED" if exhausted else "WAKE_LAUNCH_FAILED"
            self.store.connection.execute(
                "UPDATE coordination_wakes SET state=?, process_id=NULL, updated_at=?, "
                "last_error=? "
                "WHERE wake_key=? AND state='INFLIGHT'",
                ("HOLD" if exhausted else "INFLIGHT", now, error, wake_key),
            )
            if exhausted:
                self._hold_stale_message_locked(
                    message, "WAKE_RETRY_EXHAUSTED", now
                )
            self.store._event(
                "WAKE_HELD" if exhausted else "WAKE_LAUNCH_FAILED",
                wake_key,
                {"error": error},
                now,
            )

    def _complete_stale_wakes(self, now: str) -> None:
        with self.store.transaction():
            rows = self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE state='INFLIGHT'"
            ).fetchall()
            for wake in rows:
                message = self.store.connection.execute(
                    "SELECT * FROM coordination_messages WHERE id=?", (wake["message_id"],)
                ).fetchone()
                phase = wake["wake_key"].rsplit(":", 1)[-1]
                complete = message is None or message["state"] in {"COMPLETE", "HOLD"}
                if phase == "prepared" and message is not None and message["state"] != "PREPARED":
                    complete = True
                if phase == "claimed" and message is not None and not self._message_needs_worker(message):
                    complete = True
                if complete:
                    self.store.connection.execute(
                        "UPDATE coordination_wakes SET state='COMPLETE', updated_at=?, last_error=NULL WHERE wake_key=?",
                        (now, wake["wake_key"]),
                    )
                    self.store._event("WAKE_COMPLETED", wake["wake_key"], {}, now)

    def run_once(self, now: str | None = None) -> dict[str, object]:
        observed_at = now or utc_now()
        try:
            readiness_receipt_pickup: dict[str, object] = pickup_due_receipts(
                self.store, now=observed_at
            )
        except (ReadinessError, sqlite3.Error, OSError) as exc:
            readiness_receipt_pickup = {
                "mode": "HOLD",
                "error": (
                    str(exc)
                    if isinstance(exc, ReadinessError)
                    else "READINESS_RECEIPT_PICKUP_FAILED"
                ),
            }
        try:
            readiness_decision_notices: dict[str, object] = (
                enqueue_published_readiness_decision_notices(
                    self.store, now=observed_at
                )
            )
        except (CoordinationError, sqlite3.Error) as exc:
            readiness_decision_notices = {
                "mode": "HOLD",
                "error": (
                    str(exc)
                    if isinstance(exc, CoordinationError)
                    else "READINESS_DECISION_NOTICE_FAILED"
                ),
            }
        try:
            readiness_revisits: dict[str, object] = enqueue_due_readiness_revisits(
                self.store, now=observed_at
            )
        except (ReadinessError, CoordinationError, sqlite3.Error) as exc:
            readiness_revisits = {
                "mode": "HOLD",
                "error": (
                    str(exc)
                    if isinstance(exc, (ReadinessError, CoordinationError))
                    else "READINESS_REVISIT_NOTICE_FAILED"
                ),
            }
        try:
            readiness_revocations: dict[str, object] = (
                stop_revoked_readiness_successors(
                    self.store, now=observed_at
                )
            )
        except (ReadinessError, CoordinationError, sqlite3.Error) as exc:
            readiness_revocations = {
                "mode": "HOLD",
                "error": (
                    str(exc)
                    if isinstance(exc, (ReadinessError, CoordinationError))
                    else "READINESS_REVOCATION_STOP_FAILED"
                ),
            }
        # A revoked readiness authority must stop its resumed lineage before a
        # READY dirty event is allowed to select it. Activation repeats the
        # approval-effectivity guard inside its own transaction for the race
        # between this scan-level stop and admission.
        convergence_results = self.convergence.consume_due(
            limit=self.convergence_limit, now=observed_at
        )
        try:
            artifact_gc: dict[str, object] = self.store.collect_artifacts(
                now=observed_at, execute=True
            )
        except (CoordinationError, OSError) as exc:
            # Artifact housekeeping is fail-closed and orthogonal to session
            # wake delivery; a local trash defect must not stall active lanes.
            artifact_gc = {
                "mode": "HOLD",
                "error": str(exc) if isinstance(exc, CoordinationError) else "ARTIFACT_GC_FAILED",
            }
        opened_watches, held_watch_backfills = self._ensure_terminal_watches(observed_at)
        self._complete_stale_wakes(observed_at)
        due_terminal_lineages = self._eligible_due_terminal_watch_lineages(observed_at)
        terminal_watch_slot_reserved = bool(due_terminal_lineages)
        message_launch_limit = self.launch_policy.messages
        if not terminal_watch_slot_reserved:
            message_launch_limit = min(
                self.launch_policy.total,
                self.launch_policy.messages + self.launch_policy.terminal_watches,
            )
        launched: list[dict[str, object]] = []
        scanned_rows = self.store.connection.execute(
            """
            SELECT * FROM coordination_messages AS message
            WHERE state IN ('PREPARED', 'CLAIMED')
            ORDER BY id
            """
        ).fetchall()
        rows, retry_message_ids, due_retry_message_ids = self._order_message_rows(
            list(scanned_rows), observed_at
        )
        scheduled_targets: set[tuple[str, str, str]] = set()
        scheduled_lineages: set[str] = set()
        scheduled_planner_repositories: set[str] = set()
        launch_attempts = 0
        message_launch_attempts = 0
        due_message_retry_launch_attempts = 0
        for row in rows:
            if (
                launch_attempts >= self.launch_policy.total
                or message_launch_attempts >= message_launch_limit
            ):
                break
            message_id = int(row["id"])
            if (
                message_id in retry_message_ids
                and due_message_retry_launch_attempts
                >= MAX_DUE_MESSAGE_RETRY_LAUNCH_ATTEMPTS_PER_RUN
            ):
                continue
            recipient = row["recipient_session_id"]
            if not recipient_matches_topic(
                self.store.connection, topic=row["topic"], recipient=recipient
            ):
                self._hold_stale_message(row, "MESSAGE_ROLE_MISMATCH", observed_at)
                continue
            recipient_role = coordination_identity_role(
                self.store.connection, recipient
            )
            if recipient_role not in {"planner", "development", "sre"}:
                continue
            endpoint = current_endpoint(self.store.connection, recipient_role)
            if endpoint is None:
                continue
            current_identity = str(endpoint["endpoint_id"])
            contract_error = self._message_contract_error(row)
            if contract_error is not None:
                self._hold_stale_message(row, contract_error, observed_at)
                continue
            if not self._message_needs_worker(row):
                continue
            if self._hold_rebound_existing_wake(row, observed_at):
                continue
            try:
                planner_repository = (
                    planner_repository_for_target(
                        self.store.connection, "message", str(row["id"])
                    )
                    if recipient_role == "planner"
                    else None
                )
                planner_repository_busy = planner_repository is not None and (
                    planner_repository in scheduled_planner_repositories
                    or active_planner_attempt_for_repository(
                        self.store.connection, planner_repository
                    )
                    is not None
                )
                lineage = attempt_lineage_for_target(
                    self.store.connection, "message", str(row["id"])
                )
                lineage_busy = lineage is not None and (
                    lineage.sha256 in scheduled_lineages
                    or lineage.sha256 in due_terminal_lineages
                    or active_attempt_for_lineage(
                        self.store.connection, lineage.sha256
                    ) is not None
                )
            except RegistryError:
                self._hold_stale_message(
                    row, "EXECUTOR_LINEAGE_FENCE_UNAVAILABLE", observed_at
                )
                continue
            if planner_repository_busy or lineage_busy:
                continue
            target = (recipient_role, "message", str(row["id"]))
            if target in scheduled_targets:
                continue
            scheduled_targets.add(target)
            if self.process_checker(current_identity, "message", str(row["id"])):
                continue
            wake_key, should_launch = self._reserve_wake(row, observed_at)
            if not should_launch or wake_key is None:
                continue
            launch_attempts += 1
            message_launch_attempts += 1
            if message_id in retry_message_ids:
                due_message_retry_launch_attempts += 1
            if lineage is not None:
                scheduled_lineages.add(lineage.sha256)
            if planner_repository is not None:
                scheduled_planner_repositories.add(planner_repository)
            try:
                process_id = self.launcher(current_identity, int(row["id"]))
            except (OSError, subprocess.CalledProcessError):
                self._record_launch_failure(wake_key, observed_at)
                continue
            self._record_launch(wake_key, process_id, observed_at)
            launched.append(
                {"wake_key": wake_key, "message_id": int(row["id"]), "process_id": process_id}
            )
        terminal_watch_launches: list[dict[str, object]] = []
        watches = self.store.connection.execute(
            """
            SELECT * FROM coordination_terminal_watches
            WHERE state='ACTIVE'
            ORDER BY attempts, next_wake_at, repository, issue_number, generation
            """
        ).fetchall()
        terminal_watch_launch_attempts = 0
        for watch in watches:
            if (
                launch_attempts >= self.launch_policy.total
                or terminal_watch_launch_attempts
                >= self.launch_policy.terminal_watches
            ):
                break
            recipient = watch["accountable_session_id"]
            recipient_role = coordination_identity_role(
                self.store.connection, recipient
            )
            if recipient_role not in {"development", "sre"}:
                continue
            endpoint = current_endpoint(self.store.connection, recipient_role)
            if endpoint is None:
                continue
            current_identity = str(endpoint["endpoint_id"])
            try:
                lineage = attempt_lineage_for_target(
                    self.store.connection,
                    "terminal_watch",
                    str(watch["watch_key"]),
                )
                lineage_busy = (
                    lineage is None
                    or lineage.sha256 in scheduled_lineages
                    or active_attempt_for_lineage(
                        self.store.connection, lineage.sha256
                    ) is not None
                )
            except RegistryError:
                self._hold_terminal_watch(
                    str(watch["watch_key"]),
                    "EXECUTOR_LINEAGE_FENCE_UNAVAILABLE",
                    observed_at,
                )
                continue
            if lineage_busy:
                continue
            target = (recipient_role, "terminal_watch", str(watch["watch_key"]))
            if target in scheduled_targets:
                continue
            scheduled_targets.add(target)
            if self.process_checker(
                current_identity, "terminal_watch", str(watch["watch_key"])
            ):
                continue
            current, should_launch = self._reserve_terminal_watch(
                watch["watch_key"], observed_at
            )
            if not should_launch or current is None:
                continue
            launch_attempts += 1
            terminal_watch_launch_attempts += 1
            try:
                process_id = self.terminal_watch_launcher(
                    current_identity, watch["watch_key"]
                )
            except (OSError, subprocess.CalledProcessError):
                self._record_terminal_watch_launch_failure(watch["watch_key"], observed_at)
                continue
            self._record_terminal_watch_launch(watch["watch_key"], process_id, observed_at)
            scheduled_lineages.add(lineage.sha256)
            terminal_watch_launches.append(
                {
                    "watch_key": watch["watch_key"],
                    "recipient_session_id": recipient,
                    "process_id": process_id,
                }
            )
        return {
            "launch_policy": self.launch_policy.as_dict(),
            "launch_policy_decision": {
                "terminal_watch_slot_reserved": terminal_watch_slot_reserved,
                "message_limit": message_launch_limit,
                "due_message_retry_slot_reserved": bool(due_retry_message_ids),
                "due_message_retry_limit": (
                    MAX_DUE_MESSAGE_RETRY_LAUNCH_ATTEMPTS_PER_RUN
                ),
            },
            "launch_attempts": {
                "total": launch_attempts,
                "messages": message_launch_attempts,
                "terminal_watches": terminal_watch_launch_attempts,
            },
            "artifact_gc": artifact_gc,
            "readiness_receipt_pickup": readiness_receipt_pickup,
            "readiness_decision_notices": readiness_decision_notices,
            "readiness_revisits": readiness_revisits,
            "readiness_revocations": readiness_revocations,
            "portfolio_convergence": convergence_results,
            "opened_terminal_watches": opened_watches,
            "held_terminal_watch_backfills": held_watch_backfills,
            "launched": launched,
            "terminal_watch_launches": terminal_watch_launches,
        }


def main() -> int:
    LOCK.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return 0
    store = CoordinationStore(DEFAULT_DATABASE)
    try:
        result = CoordinationSupervisor(store).run_once()
        print(canonical_json(result))
    except CoordinationError as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        store.close()
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
