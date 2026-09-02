#!/usr/bin/env python3
"""Owner-only same-host wake supervisor for the SQLite coordination plane."""

from __future__ import annotations

import fcntl
import json
import math
import os
import sqlite3
import time
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Callable

from coordination_store import (
    ACTIVE_EXECUTION_STATUSES,
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    MUTATING_MESSAGE_TOPICS,
    canonical_json,
    coordination_envelope_error_is_zero_write,
    coordination_identity_role,
    digest_json,
    parse_coordination_envelope,
    recipient_matches_topic,
    terminal_watch_key,
    timestamp_after,
    utc_now,
)
from executor_registry import (
    ENDPOINT_ID,
    RegistryError,
    RoleExecutorChildAckFence,
    RoleExecutorChildAckExpectation,
    RoleExecutorChildAcknowledgement,
    SystemdUnitEvidence,
    applied_endpoint_rotation_chain,
    active_attempt_for_lineage,
    active_attempt_for_target,
    active_planner_attempt_for_repository,
    attempt_lineage_for_target,
    bind_role_executor_child_ack_expectation,
    current_endpoint,
    observe_role_executor_child_ack,
    planner_repository_for_target,
    recover_reserved_attempts,
    recover_role_executor_child_ack_expectation,
    recover_stale_active_attempts,
    snapshot_role_executor_child_ack_fence,
    target_progress_digest,
)
from role_executor_transport import (
    RoleExecutorManagerNotSubmitted,
    RoleExecutorManagerSubmission,
    RoleExecutorTransportPreflight,
    attest_role_executor_transport,
    build_role_executor_transport_preflight,
    enqueue_role_executor_transport_failure_notice,
    injected_role_executor_transport_attestation,
    revalidate_role_executor_transport_preflight,
    role_executor_command,
    role_executor_transport_failure_reason,
    submit_role_executor,
    validate_role_executor_transport_attestation,
)
from role_executor_broker import (
    consume_staged_broker_pickups,
    recover_stale_broker_runs,
)
from portfolio_convergence import (
    DEFAULT_CONVERGENCE_LIMIT,
    MAX_CONVERGENCE_LIMIT,
    PortfolioConvergence,
)
from approval_ledger import enqueue_published_readiness_decision_notices
from admission_source_equivalence import admission_lineage_source_is_current
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
ATTEMPT_STALE_SECONDS = 15 * 60
CONVERGENCE_PHASE_TIMEOUT_SECONDS = 5
CHILD_ACK_TIMEOUT_SECONDS = 5.0
CHILD_ACK_POLL_INTERVAL_SECONDS = 0.05
CHILD_ACK_LATE_RECONCILE_SECONDS = ATTEMPT_STALE_SECONDS
CHILD_ACK_SUBMITTING = "ROLE_EXECUTOR_MANAGER_SUBMISSION_INFLIGHT"
CHILD_ACK_PENDING = "ROLE_EXECUTOR_CHILD_ACK_PENDING"
CHILD_ACK_AMBIGUOUS = "ROLE_EXECUTOR_MANAGER_SUBMISSION_AMBIGUOUS"
CHILD_ACK_REJECTED = "ROLE_EXECUTOR_CHILD_ACK_REJECTED"
CHILD_ACK_EXPIRED = "ROLE_EXECUTOR_CHILD_ACK_EXPIRED"
CHILD_ACK_SUBMISSION_INTENT_EVENT_KEY_SCHEMA = (
    "twinfinity-role-executor-manager-submission-intent-event-key/v2"
)
CHILD_ACK_SUBMISSION_EVENT_KEY_SCHEMA = (
    "twinfinity-role-executor-manager-submission-event-key/v3"
)
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


def _before(timestamp: str, seconds: int) -> str:
    from datetime import datetime, timedelta, timezone

    value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (value - timedelta(seconds=seconds)).astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def _retry_seconds(attempts: int) -> int:
    return min(RETRY_SECONDS * (2 ** max(0, attempts - 1)), MAX_RETRY_SECONDS)


def canonical_session_running(
    connection: sqlite3.Connection,
    identity: str,
    target_kind: str,
    target_key: str,
) -> bool:
    """Use exact-target attempt state, never process-list resume inference."""

    return (
        active_attempt_for_target(connection, identity, target_kind, target_key)
        is not None
    )


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
) -> RoleExecutorManagerSubmission:
    if not isinstance(identity, str) or ENDPOINT_ID.fullmatch(identity) is None:
        raise CoordinationError("NONCANONICAL_ROLE_ENDPOINT")
    role = identity.split(".")[1]
    return submit_role_executor(
        role=role,
        endpoint_id=identity,
        target_kind=target_kind,
        target_key=target_key,
        prompt=prompt,
    )


def launch_canonical_session(
    session_id: str, message_id: int
) -> RoleExecutorManagerSubmission:
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


def launch_terminal_watch_session(
    session_id: str, watch_key: str
) -> RoleExecutorManagerSubmission:
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
        launcher: Callable[[str, int], object] = launch_canonical_session,
        terminal_watch_launcher: Callable[[str, str], object] = launch_terminal_watch_session,
        process_checker: Callable[[str, str, str], bool] | None = None,
        convergence: PortfolioConvergence | None = None,
        convergence_limit: int = DEFAULT_CONVERGENCE_LIMIT,
        launch_policy: SchedulerLaunchPolicy = DEFAULT_LAUNCH_POLICY,
        monotonic: Callable[[], float] = time.monotonic,
        stale_attempt_evidence_reader: Callable[[str], SystemdUnitEvidence]
        | None = None,
        transport_preflight: Callable[[RoleExecutorTransportPreflight], object]
        | None = None,
        child_ack_timeout_seconds: float = CHILD_ACK_TIMEOUT_SECONDS,
        child_ack_poll_interval_seconds: float = CHILD_ACK_POLL_INTERVAL_SECONDS,
        child_ack_monotonic: Callable[[], float] = time.monotonic,
        child_ack_sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if convergence_limit <= 0 or convergence_limit > MAX_CONVERGENCE_LIMIT:
            raise CoordinationError("CONVERGENCE_LIMIT_INVALID")
        self.store = store
        self.launcher = launcher
        self.terminal_watch_launcher = terminal_watch_launcher
        self.process_checker = (
            process_checker
            if process_checker is not None
            else lambda identity, target_kind, target_key: canonical_session_running(
                self.store.connection, identity, target_kind, target_key
            )
        )
        self.convergence = convergence
        self.convergence_limit = convergence_limit
        if not isinstance(launch_policy, SchedulerLaunchPolicy):
            raise CoordinationError("SCHEDULER_LAUNCH_POLICY_INVALID")
        self.launch_policy = launch_policy
        self.monotonic = monotonic
        self.stale_attempt_evidence_reader = stale_attempt_evidence_reader
        if (
            isinstance(child_ack_timeout_seconds, bool)
            or not isinstance(child_ack_timeout_seconds, (int, float))
            or not math.isfinite(float(child_ack_timeout_seconds))
            or float(child_ack_timeout_seconds) < 0
            or isinstance(child_ack_poll_interval_seconds, bool)
            or not isinstance(child_ack_poll_interval_seconds, (int, float))
            or not math.isfinite(float(child_ack_poll_interval_seconds))
            or float(child_ack_poll_interval_seconds) <= 0
        ):
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_WAIT_INVALID")
        self.child_ack_timeout_seconds = float(child_ack_timeout_seconds)
        self.child_ack_poll_interval_seconds = float(child_ack_poll_interval_seconds)
        self.child_ack_monotonic = child_ack_monotonic
        self.child_ack_sleeper = child_ack_sleeper
        self.transport_preflight = (
            transport_preflight
            if transport_preflight is not None
            else (
                attest_role_executor_transport
                if launcher is launch_canonical_session
                and terminal_watch_launcher is launch_terminal_watch_session
                else injected_role_executor_transport_attestation
            )
        )

    @staticmethod
    def _submission_event_types(target_kind: str) -> dict[str, str]:
        if target_kind == "message":
            prefix = "SESSION_WAKE"
        elif target_kind == "terminal_watch":
            prefix = "TERMINAL_WATCH"
        else:
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_TARGET_INVALID")
        return {
            "intent": f"{prefix}_MANAGER_SUBMISSION_INTENT",
            "submitted": f"{prefix}_MANAGER_SUBMITTED",
            "abandoned": f"{prefix}_MANAGER_SUBMISSION_ABANDONED",
            "ambiguous": f"{prefix}_MANAGER_SUBMISSION_AMBIGUOUS",
            "recovered": f"{prefix}_MANAGER_SUBMISSION_RECOVERED_FROM_EXACT_CHILD",
            "terminal_resolved": (
                f"{prefix}_MANAGER_SUBMISSION_RESOLVED_BY_TERMINAL_EVIDENCE"
            ),
            "accepted": f"{prefix}_CHILD_ACK_ACCEPTED",
            "rejected": f"{prefix}_CHILD_ACK_REJECTED",
            "expired": f"{prefix}_CHILD_ACK_EXPIRED",
        }

    @staticmethod
    def _target_entity_matches(
        target_kind: str, entity_key: str, target_key: str
    ) -> bool:
        if target_kind == "terminal_watch":
            return entity_key == target_key
        if target_kind == "message":
            return entity_key in {
                f"message:{target_key}:prepared",
                f"message:{target_key}:claimed",
            }
        return False

    @staticmethod
    def _target_table(target_kind: str) -> tuple[str, str]:
        if target_kind == "message":
            return "coordination_wakes", "wake_key"
        if target_kind == "terminal_watch":
            return "coordination_terminal_watches", "watch_key"
        raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_TARGET_INVALID")

    @staticmethod
    def _decode_fence(payload: object) -> RoleExecutorChildAckFence:
        if type(payload) is not dict:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_INTENT_INVALID"
            )
        values = dict(payload)
        preexisting = values.get("preexisting_attempt_ids")
        if type(preexisting) is not list or any(
            type(value) is not str for value in preexisting
        ):
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_INTENT_INVALID"
            )
        values["preexisting_attempt_ids"] = tuple(preexisting)
        try:
            return RoleExecutorChildAckFence(**values)
        except (TypeError, ValueError, RegistryError) as exc:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_INTENT_INVALID"
            ) from exc

    @staticmethod
    def _decode_expectation(payload: object) -> RoleExecutorChildAckExpectation:
        if type(payload) is not dict:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
            )
        values = dict(payload)
        preexisting = values.get("preexisting_attempt_ids")
        if type(preexisting) is not list or any(
            type(value) is not str for value in preexisting
        ):
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
            )
        values["preexisting_attempt_ids"] = tuple(preexisting)
        try:
            return RoleExecutorChildAckExpectation(**values)
        except (TypeError, ValueError, RegistryError) as exc:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
            ) from exc

    def _submission_intent_event_key(
        self,
        *,
        entity_key: str,
        target_kind: str,
        fence: RoleExecutorChildAckFence,
        reservation: dict[str, object],
        now: str,
    ) -> str:
        if (
            type(fence) is not RoleExecutorChildAckFence
            or type(reservation) is not dict
            or not self._target_entity_matches(
                target_kind, entity_key, fence.target_key
            )
        ):
            raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
        attempts = reservation.get("attempts")
        if (
            type(attempts) is not int
            or attempts <= 0
            or attempts > MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS
        ):
            raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
        planner_repository = (
            planner_repository_for_target(
                self.store.connection, target_kind, fence.target_key
            )
            if fence.role == "planner"
            else None
        )
        return canonical_json(
            {
                "schema": CHILD_ACK_SUBMISSION_INTENT_EVENT_KEY_SCHEMA,
                "target_kind": target_kind,
                "target_entity_key": entity_key,
                "submission_attempt": attempts,
                "observation_deadline_at": timestamp_after(
                    now, CHILD_ACK_LATE_RECONCILE_SECONDS
                ),
                "planner_repository": planner_repository,
                "reservation": reservation,
                "fence": fence.payload,
            }
        )

    def _intent_from_submission_event(
        self, event: sqlite3.Row
    ) -> dict[str, object]:
        try:
            envelope = json.loads(str(event["entity_key"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_INTENT_INVALID"
            ) from exc
        if (
            type(envelope) is not dict
            or canonical_json(envelope) != event["entity_key"]
            or envelope.get("schema")
            != CHILD_ACK_SUBMISSION_INTENT_EVENT_KEY_SCHEMA
            or envelope.get("target_kind") not in {"message", "terminal_watch"}
            or type(envelope.get("target_entity_key")) is not str
            or type(envelope.get("submission_attempt")) is not int
            or envelope.get("submission_attempt", 0) <= 0
            or envelope.get("submission_attempt", 0)
            > MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS
            or type(envelope.get("reservation")) is not dict
            or type(envelope.get("observation_deadline_at")) is not str
            or (
                envelope.get("planner_repository") is not None
                and type(envelope.get("planner_repository")) is not str
            )
            or digest_json(envelope) != event["payload_sha256"]
        ):
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_INTENT_INVALID"
            )
        fence = self._decode_fence(envelope.get("fence"))
        reservation = dict(envelope["reservation"])
        if (
            not self._target_entity_matches(
                str(envelope["target_kind"]),
                str(envelope["target_entity_key"]),
                fence.target_key,
            )
            or envelope["submission_attempt"] != reservation.get("attempts")
            or (
                fence.role != "planner"
                and envelope.get("planner_repository") is not None
            )
            or envelope["observation_deadline_at"]
            != timestamp_after(
                str(event["created_at"]), CHILD_ACK_LATE_RECONCILE_SECONDS
            )
        ):
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_INTENT_INVALID"
            )
        return {
            "fence": fence,
            "reservation": reservation,
            "intent_event_key": str(event["entity_key"]),
            "intent_recorded_at": str(event["created_at"]),
            "observation_deadline_at": str(
                envelope["observation_deadline_at"]
            ),
            "planner_repository": envelope.get("planner_repository"),
            "target_kind": str(envelope["target_kind"]),
            "target_entity_key": str(envelope["target_entity_key"]),
        }

    def _intent_event(
        self, *, target_kind: str, intent_event_key: str
    ) -> sqlite3.Row:
        event_type = self._submission_event_types(target_kind)["intent"]
        rows = self.store.connection.execute(
            "SELECT * FROM coordination_events WHERE event_type=? "
            "AND entity_key=? ORDER BY id",
            (event_type, intent_event_key),
        ).fetchall()
        if len(rows) != 1:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_INTENT_INVALID"
            )
        return rows[0]

    @staticmethod
    def _marker_target_snapshot(
        reservation: dict[str, object], *, marker: str, updated_at: str
    ) -> dict[str, object]:
        expected = dict(reservation)
        expected["process_id"] = None
        expected["last_error"] = marker
        expected["updated_at"] = updated_at
        return expected

    def _require_marker_target(
        self,
        *,
        decoded_intent: dict[str, object],
        marker: str,
        updated_at: str,
    ) -> sqlite3.Row:
        target_kind = str(decoded_intent["target_kind"])
        entity_key = str(decoded_intent["target_entity_key"])
        table, key_column = self._target_table(target_kind)
        target = self.store.connection.execute(
            f"SELECT * FROM {table} WHERE {key_column}=?", (entity_key,)
        ).fetchone()
        reservation = decoded_intent["reservation"]
        assert type(reservation) is dict
        expected = self._marker_target_snapshot(
            reservation, marker=marker, updated_at=updated_at
        )
        if target is None or dict(target) != expected:
            raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
        return target

    def _submitted_events_for_intent(
        self, *, target_kind: str, intent_event_key: str
    ) -> list[sqlite3.Row]:
        event_type = self._submission_event_types(target_kind)["submitted"]
        matches: list[sqlite3.Row] = []
        for row in self.store.connection.execute(
            "SELECT * FROM coordination_events WHERE event_type=? ORDER BY id",
            (event_type,),
        ).fetchall():
            try:
                envelope = json.loads(str(row["entity_key"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise CoordinationError(
                    "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
                ) from exc
            if (
                type(envelope) is not dict
                or canonical_json(envelope) != row["entity_key"]
                or digest_json(envelope) != row["payload_sha256"]
            ):
                raise CoordinationError(
                    "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
                )
            if envelope.get("intent_event_key") == intent_event_key:
                matches.append(row)
        return matches

    def _intent_first_disposition(
        self, *, target_kind: str, intent_event_key: str
    ) -> tuple[str | None, sqlite3.Row | None]:
        event_types = self._submission_event_types(target_kind)
        dispositions: list[tuple[str, sqlite3.Row]] = []
        submitted = self._submitted_events_for_intent(
            target_kind=target_kind, intent_event_key=intent_event_key
        )
        dispositions.extend(("submitted", row) for row in submitted)
        for kind in ("abandoned", "ambiguous"):
            rows = self.store.connection.execute(
                "SELECT * FROM coordination_events WHERE event_type=? "
                "AND entity_key=? ORDER BY id",
                (event_types[kind], intent_event_key),
            ).fetchall()
            dispositions.extend((kind, row) for row in rows)
        if not dispositions:
            return None, None
        if len(dispositions) != 1:
            raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT")
        return dispositions[0]

    def _ambiguous_resolution(
        self, *, target_kind: str, intent_event_key: str
    ) -> tuple[str | None, sqlite3.Row | None]:
        event_types = self._submission_event_types(target_kind)
        found: list[tuple[str, sqlite3.Row]] = []
        for kind in ("recovered", "terminal_resolved"):
            rows = self.store.connection.execute(
                "SELECT * FROM coordination_events WHERE event_type=? ORDER BY id",
                (event_types[kind],),
            ).fetchall()
            for row in rows:
                try:
                    envelope = json.loads(str(row["entity_key"]))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise CoordinationError(
                        "ROLE_EXECUTOR_CHILD_ACK_DISPOSITION_INVALID"
                    ) from exc
                if (
                    type(envelope) is not dict
                    or canonical_json(envelope) != row["entity_key"]
                    or digest_json(envelope) != row["payload_sha256"]
                    or envelope.get("schema")
                    != "twinfinity-manager-ambiguity-resolution/v1"
                    or envelope.get("resolution_kind") != kind
                ):
                    raise CoordinationError(
                        "ROLE_EXECUTOR_CHILD_ACK_DISPOSITION_INVALID"
                    )
                if envelope.get("intent_event_key") == intent_event_key:
                    found.append((kind, row))
        if not found:
            return None, None
        if len(found) != 1:
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_DISPOSITION_INVALID")
        return found[0]

    def _unresolved_submission_intents(self) -> list[dict[str, object]]:
        unresolved: list[dict[str, object]] = []
        for target_kind in ("message", "terminal_watch"):
            event_type = self._submission_event_types(target_kind)["intent"]
            for event in self.store.connection.execute(
                "SELECT * FROM coordination_events WHERE event_type=? ORDER BY id",
                (event_type,),
            ).fetchall():
                decoded = self._intent_from_submission_event(event)
                prior, prior_event = self._intent_first_disposition(
                    target_kind=target_kind,
                    intent_event_key=str(decoded["intent_event_key"]),
                )
                if prior is None:
                    unresolved.append(decoded)
                elif prior == "submitted" and prior_event is not None:
                    terminal, _terminal_event = self._terminal_disposition(
                        target_kind=target_kind,
                        receipt_event_key=str(prior_event["entity_key"]),
                    )
                    if terminal is None:
                        unresolved.append(decoded)
                elif prior == "ambiguous":
                    resolution, _resolution_event = self._ambiguous_resolution(
                        target_kind=target_kind,
                        intent_event_key=str(decoded["intent_event_key"]),
                    )
                    if resolution is None:
                        unresolved.append(decoded)
        return unresolved

    def _authoritative_terminal_evidence(
        self, decoded: dict[str, object]
    ) -> dict[str, object] | None:
        target_kind = str(decoded["target_kind"])
        fence = decoded["fence"]
        assert type(fence) is RoleExecutorChildAckFence
        if target_kind == "message":
            message = self.store.connection.execute(
                "SELECT id,state,payload_sha256,claimed_by,updated_at,last_error "
                "FROM coordination_messages WHERE id=?",
                (int(fence.target_key),),
            ).fetchone()
            if message is None or message["state"] not in {"COMPLETE", "HOLD"}:
                return None
            terminal_event_type = (
                "MESSAGE_COMPLETED"
                if message["state"] == "COMPLETE"
                else "MESSAGE_HELD"
            )
            terminal_events = self.store.connection.execute(
                "SELECT id,event_type,entity_key,payload_sha256,created_at "
                "FROM coordination_events WHERE event_type=? AND entity_key=? "
                "AND created_at=? ORDER BY id",
                (
                    terminal_event_type,
                    f"message:{fence.target_key}",
                    message["updated_at"],
                ),
            ).fetchall()
            if len(terminal_events) != 1:
                return None
            return {
                "schema": "twinfinity-manager-ambiguity-terminal-evidence/v1",
                "target_kind": target_kind,
                "target_key": fence.target_key,
                "message": dict(message),
                "terminal_event": dict(terminal_events[0]),
            }
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
            (fence.target_key,),
        ).fetchone()
        if watch is None:
            return None
        item = self.store.connection.execute(
            "SELECT status,allocation_class,generation,version "
            "FROM coordination_items WHERE repository=? AND issue_number=?",
            (watch["repository"], watch["issue_number"]),
        ).fetchone()
        closeout = self.store.connection.execute(
            "SELECT terminal_commit.closeout_key "
            "FROM coordination_terminal_closeout_packets packet "
            "JOIN coordination_terminal_closeout_commits terminal_commit "
            "USING(closeout_key) WHERE packet.terminal_watch_key=?",
            (fence.target_key,),
        ).fetchone()
        if (
            item is not None
            and item["allocation_class"] == "ACTIVE"
            and item["status"] in ACTIVE_EXECUTION_STATUSES
        ) or closeout is None:
            return None
        return {
            "schema": "twinfinity-manager-ambiguity-terminal-evidence/v1",
            "target_kind": target_kind,
            "target_key": fence.target_key,
            "item": None if item is None else dict(item),
            "closeout_key": str(closeout["closeout_key"]),
        }

    def _resolve_ambiguous_submission(
        self, *, decoded: dict[str, object], now: str
    ) -> dict[str, object]:
        target_kind = str(decoded["target_kind"])
        entity_key = str(decoded["target_entity_key"])
        intent_event_key = str(decoded["intent_event_key"])
        event_types = self._submission_event_types(target_kind)
        with self.store.transaction():
            intent = self._intent_event(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            current_decoded = self._intent_from_submission_event(intent)
            if current_decoded != decoded:
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            prior, prior_event = self._intent_first_disposition(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            if prior != "ambiguous" or prior_event is None:
                raise CoordinationError(
                    "ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT"
                )
            resolution, _resolution_event = self._ambiguous_resolution(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            if resolution is not None:
                return {"status": "RESOLVED", "acknowledgement": None}
            terminal_evidence = self._authoritative_terminal_evidence(decoded)
            if terminal_evidence is not None:
                resolution_payload = {
                    "schema": "twinfinity-manager-ambiguity-resolution/v1",
                    "resolution_kind": "terminal_resolved",
                    "intent_event_key": intent_event_key,
                    "target_kind": target_kind,
                    "target_entity_key": entity_key,
                    "evidence": terminal_evidence,
                }
                self.store._event(
                    event_types["terminal_resolved"],
                    canonical_json(resolution_payload),
                    resolution_payload,
                    now,
                )
                return {"status": "TERMINAL", "acknowledgement": None}
            table, key_column = self._target_table(target_kind)
            target = self.store.connection.execute(
                f"SELECT * FROM {table} WHERE {key_column}=?", (entity_key,)
            ).fetchone()
            reservation = decoded["reservation"]
            assert type(reservation) is dict
            expected = dict(reservation)
            expected["process_id"] = None
            expected["last_error"] = CHILD_ACK_AMBIGUOUS
            expected["updated_at"] = str(prior_event["created_at"])
            held_expected = dict(expected)
            held_expected["state"] = "HOLD"
            if target is None or (
                dict(target) != expected
                and not all(
                    target[key] == value
                    for key, value in held_expected.items()
                    if key != "updated_at"
                )
            ):
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            fence = decoded["fence"]
            assert type(fence) is RoleExecutorChildAckFence
            try:
                recovered = recover_role_executor_child_ack_expectation(
                    self.store.connection,
                    fence=fence,
                    intent_recorded_at=str(decoded["intent_recorded_at"]),
                    observation_deadline_at=str(
                        decoded["observation_deadline_at"]
                    ),
                    not_after=now,
                )
            except RegistryError:
                recovered = None
            if recovered is None:
                if target["state"] != "HOLD":
                    cursor = self.store.connection.execute(
                        f"UPDATE {table} SET state='HOLD',process_id=NULL,"
                        f"updated_at=?,last_error=? WHERE {key_column}=? "
                        "AND process_id IS NULL AND last_error=?",
                        (now, CHILD_ACK_AMBIGUOUS, entity_key, CHILD_ACK_AMBIGUOUS),
                    )
                    if cursor.rowcount != 1:
                        raise CoordinationError(
                            "ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT"
                        )
                    self.store._event(
                        "WAKE_HELD"
                        if target_kind == "message"
                        else "TERMINAL_WATCH_HELD",
                        entity_key,
                        {"error": CHILD_ACK_AMBIGUOUS},
                        now,
                    )
                return {"status": "UNRESOLVED", "acknowledgement": None}
            expectation, acknowledgement = recovered
            event_payload = {
                "child_ack_sha256": acknowledgement.sha256,
                "expectation_sha256": acknowledgement.expectation_sha256,
                "manager_identity_source": expectation.manager_identity_source,
                "manager_identity_sha256": expectation.manager_identity_sha256,
                "attempt_id": acknowledgement.attempt_id,
                "instance_id": acknowledgement.instance_id,
                "token_sha256": acknowledgement.token_sha256,
                "event_chain_sha256": acknowledgement.event_chain_sha256,
                "execution_class": acknowledgement.execution_class,
                "execution_ownership_sha256": (
                    acknowledgement.execution_ownership_sha256
                ),
                "process_id": acknowledgement.process_id,
            }
            cursor = self.store.connection.execute(
                f"UPDATE {table} SET state=?,process_id=?,updated_at=?,last_error=NULL "
                f"WHERE {key_column}=? AND process_id IS NULL AND last_error=?",
                (
                    reservation["state"],
                    acknowledgement.process_id,
                    now,
                    entity_key,
                    CHILD_ACK_AMBIGUOUS,
                ),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            self.store._event(
                "SESSION_WAKE_STARTED"
                if target_kind == "message"
                else "TERMINAL_WATCH_WAKE_STARTED",
                entity_key,
                event_payload,
                now,
            )
            resolution_payload = {
                "schema": "twinfinity-manager-ambiguity-resolution/v1",
                "resolution_kind": "recovered",
                "intent_event_key": intent_event_key,
                "target_kind": target_kind,
                "target_entity_key": entity_key,
                "evidence": event_payload,
            }
            self.store._event(
                event_types["recovered"],
                canonical_json(resolution_payload),
                resolution_payload,
                now,
            )
            return {
                "status": "RECOVERED",
                "acknowledgement": acknowledgement,
            }

    def _reconcile_ambiguous_submission_intents(
        self, now: str
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        messages: list[dict[str, object]] = []
        watches: list[dict[str, object]] = []
        for decoded in self._unresolved_submission_intents():
            target_kind = str(decoded["target_kind"])
            prior, _prior_event = self._intent_first_disposition(
                target_kind=target_kind,
                intent_event_key=str(decoded["intent_event_key"]),
            )
            if prior != "ambiguous":
                continue
            resolved = self._resolve_ambiguous_submission(
                decoded=decoded, now=now
            )
            acknowledgement = resolved["acknowledgement"]
            if (
                type(acknowledgement) is RoleExecutorChildAcknowledgement
                and resolved["status"] == "RECOVERED"
            ):
                result = {
                    "process_id": acknowledgement.process_id,
                    "child_ack_sha256": acknowledgement.sha256,
                    "manager_identity_source": "AUTHENTICATED_CHILD_RECOVERY",
                }
                if target_kind == "message":
                    messages.append(
                        {
                            **result,
                            "wake_key": str(decoded["target_entity_key"]),
                            "message_id": int(acknowledgement.target_key),
                        }
                    )
                else:
                    watches.append(
                        {
                            **result,
                            "watch_key": acknowledgement.target_key,
                            "recipient_session_id": acknowledgement.endpoint_id,
                        }
                    )
        return messages, watches

    def _record_submission_intent(
        self,
        *,
        entity_key: str,
        target_kind: str,
        fence: RoleExecutorChildAckFence,
        reservation: dict[str, object],
        now: str,
    ) -> str:
        """Commit an exact retry reservation and immutable child fence first."""

        intent_event_key = self._submission_intent_event_key(
            entity_key=entity_key,
            target_kind=target_kind,
            fence=fence,
            reservation=reservation,
            now=now,
        )
        event_type = self._submission_event_types(target_kind)["intent"]
        table, key_column = self._target_table(target_kind)
        with self.store.transaction():
            current_fence = snapshot_role_executor_child_ack_fence(
                self.store.connection,
                role=fence.role,
                endpoint_id=fence.endpoint_id,
                target_kind=fence.target_kind,
                target_key=fence.target_key,
            )
            target = self.store.connection.execute(
                f"SELECT * FROM {table} WHERE {key_column}=?", (entity_key,)
            ).fetchone()
            current_planner_repository = (
                planner_repository_for_target(
                    self.store.connection, target_kind, fence.target_key
                )
                if fence.role == "planner"
                else None
            )
            intent_envelope = json.loads(intent_event_key)
            if (
                current_fence != fence
                or current_planner_repository
                != intent_envelope.get("planner_repository")
                or target is None
                or dict(target) != reservation
                or reservation.get("process_id") is not None
                or reservation.get("last_error") is not None
                or reservation.get("target_progress_sha256")
                != fence.target_progress_sha256
                or (
                    target_kind == "message"
                    and (
                        reservation.get("state") != "INFLIGHT"
                        or reservation.get("recipient_session_id")
                        != fence.endpoint_id
                        or str(reservation.get("message_id")) != fence.target_key
                    )
                )
                or (
                    target_kind == "terminal_watch"
                    and (
                        reservation.get("state") != "ACTIVE"
                        or reservation.get("accountable_session_id")
                        != fence.endpoint_id
                        or reservation.get("watch_key") != fence.target_key
                    )
                )
            ):
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            cursor = self.store.connection.execute(
                f"UPDATE {table} SET updated_at=?,last_error=? "
                f"WHERE {key_column}=? AND process_id IS NULL AND last_error IS NULL",
                (now, CHILD_ACK_SUBMITTING, entity_key),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            self.store._event(event_type, intent_event_key, json.loads(intent_event_key), now)
        return intent_event_key

    def _submit_manager_after_atomic_revalidation(
        self,
        *,
        intent_event_key: str,
        target_kind: str,
        entity_key: str,
        submit: Callable[[], object],
        now: str,
    ) -> dict[str, object]:
        """Atomically revalidate, submit, and bind the manager outcome."""

        with self.store.transaction():
            intent = self._intent_event(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            decoded = self._intent_from_submission_event(intent)
            if (
                decoded["target_kind"] != target_kind
                or decoded["target_entity_key"] != entity_key
            ):
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            prior, _prior_event = self._intent_first_disposition(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            if prior is not None:
                raise CoordinationError(
                    "ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT"
                )
            self._require_marker_target(
                decoded_intent=decoded,
                marker=CHILD_ACK_SUBMITTING,
                updated_at=str(intent["created_at"]),
            )
            fence = decoded["fence"]
            assert type(fence) is RoleExecutorChildAckFence
            current_fence = snapshot_role_executor_child_ack_fence(
                self.store.connection,
                role=fence.role,
                endpoint_id=fence.endpoint_id,
                target_kind=fence.target_kind,
                target_key=fence.target_key,
            )
            current_planner_repository = (
                planner_repository_for_target(
                    self.store.connection, target_kind, fence.target_key
                )
                if fence.role == "planner"
                else None
            )
            message_contract_current = True
            if target_kind == "message":
                reservation = decoded["reservation"]
                assert type(reservation) is dict
                message = self.store.connection.execute(
                    "SELECT * FROM coordination_messages WHERE id=?",
                    (reservation.get("message_id"),),
                ).fetchone()
                message_contract_current = (
                    message is not None
                    and message["payload_sha256"]
                    == reservation.get("message_payload_sha256")
                    and self._message_contract_error(message) is None
                    and self._message_needs_worker(message)
                )
            if (
                current_fence != fence
                or current_planner_repository != decoded["planner_repository"]
                or not message_contract_current
            ):
                self._record_unbound_submission_not_submitted(
                    intent_event_key=intent_event_key,
                    target_kind=target_kind,
                    entity_key=entity_key,
                    now=now,
                    mark_launch_failure=False,
                )
                return {"status": "ABANDONED"}
        # The transaction above is the final pre-call fence.  Do not hold a
        # SQLite writer lock across the external manager invocation; bind its
        # outcome in a new transaction so target progress can be revalidated.
        try:
            result = submit()
        except RoleExecutorManagerNotSubmitted:
            self._record_unbound_submission_not_submitted(
                intent_event_key=intent_event_key,
                target_kind=target_kind,
                entity_key=entity_key,
                now=now,
            )
            return {"status": "ABANDONED"}
        except Exception:
            self._record_unbound_submission_hold(
                intent_event_key=intent_event_key,
                target_kind=target_kind,
                entity_key=entity_key,
                now=now,
            )
            return {"status": "AMBIGUOUS"}
        if type(result) is not RoleExecutorManagerSubmission:
            self._record_unbound_submission_hold(
                intent_event_key=intent_event_key,
                target_kind=target_kind,
                entity_key=entity_key,
                now=now,
            )
            return {"status": "AMBIGUOUS"}
        try:
            expectation = bind_role_executor_child_ack_expectation(
                fence,
                systemd_unit=result.systemd_unit,
                systemd_invocation_id=result.systemd_invocation_id,
                manager_receipt_sha256=result.receipt_sha256,
                intent_recorded_at=str(intent["created_at"]),
                observation_deadline_at=str(decoded["observation_deadline_at"]),
            )
        except RegistryError:
            self._record_unbound_submission_hold(
                intent_event_key=intent_event_key,
                target_kind=target_kind,
                entity_key=entity_key,
                now=now,
            )
            return {"status": "AMBIGUOUS"}
        receipt_event_key = self._record_manager_submission(
            entity_key=entity_key,
            target_kind=target_kind,
            intent_event_key=intent_event_key,
            expectation=expectation,
            now=now,
        )
        return {
            "status": "SUBMITTED",
            "submission": result,
            "expectation": expectation,
            "receipt_event_key": receipt_event_key,
        }

    def _record_unbound_submission_disposition(
        self,
        *,
        intent_event_key: str,
        target_kind: str,
        entity_key: str,
        disposition: str,
        now: str,
        mark_launch_failure: bool = True,
    ) -> bool:
        if disposition not in {"abandoned", "ambiguous"}:
            raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT")
        event_types = self._submission_event_types(target_kind)
        transaction = (
            self.store.transaction()
            if not self.store.connection.in_transaction
            else nullcontext()
        )
        with transaction:
            intent = self._intent_event(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            decoded = self._intent_from_submission_event(intent)
            if decoded["target_entity_key"] != entity_key:
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            prior, _prior_event = self._intent_first_disposition(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            if prior is not None:
                if prior == disposition:
                    return False
                raise CoordinationError(
                    "ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT"
                )
            table, key_column = self._target_table(target_kind)
            if disposition == "abandoned":
                reservation = decoded["reservation"]
                assert type(reservation) is dict
                current_progress_sha256 = target_progress_digest(
                    self.store.connection,
                    target_kind,
                    str(decoded["fence"].target_key),
                )
                if (
                    mark_launch_failure
                    and current_progress_sha256
                    != reservation["target_progress_sha256"]
                ):
                    if target_kind == "message":
                        self._require_marker_target(
                            decoded_intent=decoded,
                            marker=CHILD_ACK_SUBMITTING,
                            updated_at=str(intent["created_at"]),
                        )
                        cursor = self.store.connection.execute(
                            "UPDATE coordination_wakes SET attempts=1,process_id=NULL,"
                            "target_progress_sha256=?,last_attempt_at=?,updated_at=?,"
                            "last_error='WAKE_LAUNCH_FAILED_AFTER_PROGRESS' "
                            "WHERE wake_key=? AND process_id IS NULL AND last_error=?",
                            (
                                current_progress_sha256,
                                now,
                                now,
                                entity_key,
                                CHILD_ACK_SUBMITTING,
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise CoordinationError(
                                "ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT"
                            )
                        self.store._event(
                            "WAKE_RETRY_BUDGET_RESET",
                            entity_key,
                            {"reason": "TARGET_PROGRESS_CHANGED"},
                            now,
                        )
                    else:
                        # The watch itself advanced while the manager call was
                        # in flight.  Preserve that authoritative heartbeat and
                        # the unresolved intent; neither an abandonment nor a
                        # retry is safe until exact evidence resolves it.
                        return False
                    self.store._event(
                        event_types[disposition],
                        intent_event_key,
                        {"error": "ROLE_EXECUTOR_MANAGER_NOT_SUBMITTED"},
                        now,
                    )
                    return True
                self._require_marker_target(
                    decoded_intent=decoded,
                    marker=CHILD_ACK_SUBMITTING,
                    updated_at=str(intent["created_at"]),
                )
                if not mark_launch_failure:
                    cursor = self.store.connection.execute(
                        f"UPDATE {table} SET state=?,process_id=NULL,updated_at=?,"
                        f"last_error=NULL WHERE {key_column}=? AND process_id IS NULL "
                        "AND last_error=?",
                        (
                            reservation["state"],
                            now,
                            entity_key,
                            CHILD_ACK_SUBMITTING,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise CoordinationError(
                            "ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT"
                        )
                    self.store._event(
                        event_types[disposition],
                        intent_event_key,
                        {"error": "ROLE_EXECUTOR_PRECALL_VALIDATION_FAILED"},
                        now,
                    )
                    return True
                exhausted = (
                    int(reservation["attempts"])
                    >= MAX_IDENTICAL_TARGET_LAUNCH_ATTEMPTS
                )
                failure_error = (
                    "WAKE_RETRY_EXHAUSTED"
                    if target_kind == "message" and exhausted
                    else "TERMINAL_WATCH_RETRY_EXHAUSTED"
                    if exhausted
                    else "WAKE_LAUNCH_FAILED"
                    if target_kind == "message"
                    else "TERMINAL_WATCH_WAKE_FAILED"
                )
                if target_kind == "message" and exhausted:
                    message = self.store.connection.execute(
                        "SELECT * FROM coordination_messages WHERE id=?",
                        (int(decoded["fence"].target_key),),
                    ).fetchone()
                    if message is None:
                        raise CoordinationError(
                            "ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT"
                        )
                    self._hold_retry_exhausted_locked(message, reservation, now)
                    cursor = None
                else:
                    next_wake_sql = (
                        ",next_wake_at=?" if target_kind == "terminal_watch" else ""
                    )
                    parameters: tuple[object, ...] = (
                        (
                            "HOLD" if exhausted else reservation["state"],
                            now,
                            failure_error,
                            timestamp_after(now, 60),
                            entity_key,
                            CHILD_ACK_SUBMITTING,
                        )
                        if target_kind == "terminal_watch"
                        else (
                            reservation["state"],
                            now,
                            failure_error,
                            entity_key,
                            CHILD_ACK_SUBMITTING,
                        )
                    )
                    cursor = self.store.connection.execute(
                        f"UPDATE {table} SET state=?,updated_at=?,last_error=?"
                        f"{next_wake_sql} WHERE {key_column}=? AND process_id IS NULL "
                        "AND last_error=?",
                        parameters,
                    )
                error = "ROLE_EXECUTOR_MANAGER_NOT_SUBMITTED"
            else:
                self._require_marker_target(
                    decoded_intent=decoded,
                    marker=CHILD_ACK_SUBMITTING,
                    updated_at=str(intent["created_at"]),
                )
                cursor = self.store.connection.execute(
                    f"UPDATE {table} SET process_id=NULL,updated_at=?,last_error=? "
                    f"WHERE {key_column}=? "
                    "AND process_id IS NULL AND last_error=?",
                    (now, CHILD_ACK_AMBIGUOUS, entity_key, CHILD_ACK_SUBMITTING),
                )
                error = CHILD_ACK_AMBIGUOUS
            if cursor is not None and cursor.rowcount != 1:
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            if disposition == "abandoned" and not (
                target_kind == "message" and exhausted
            ):
                self.store._event(
                    (
                        "WAKE_HELD"
                        if target_kind == "message" and exhausted
                        else "TERMINAL_WATCH_HELD"
                        if exhausted
                        else "WAKE_LAUNCH_FAILED"
                        if target_kind == "message"
                        else "TERMINAL_WATCH_WAKE_FAILED"
                    ),
                    entity_key,
                    {"error": failure_error},
                    now,
                )
            self.store._event(
                event_types[disposition],
                intent_event_key,
                {"error": error},
                now,
            )
        return True

    def _record_unbound_submission_hold(
        self,
        *,
        intent_event_key: str,
        target_kind: str,
        entity_key: str,
        now: str,
    ) -> bool:
        return self._record_unbound_submission_disposition(
            intent_event_key=intent_event_key,
            target_kind=target_kind,
            entity_key=entity_key,
            disposition="ambiguous",
            now=now,
        )

    def _record_unbound_submission_not_submitted(
        self,
        *,
        intent_event_key: str,
        target_kind: str,
        entity_key: str,
        now: str,
        mark_launch_failure: bool = True,
    ) -> bool:
        return self._record_unbound_submission_disposition(
            intent_event_key=intent_event_key,
            target_kind=target_kind,
            entity_key=entity_key,
            disposition="abandoned",
            now=now,
            mark_launch_failure=mark_launch_failure,
        )

    def _manager_submission_event_key(
        self,
        *,
        entity_key: str,
        target_kind: str,
        intent_event_key: str,
        expectation: RoleExecutorChildAckExpectation,
        now: str,
    ) -> str:
        if (
            type(expectation) is not RoleExecutorChildAckExpectation
            or not self._target_entity_matches(
                target_kind, entity_key, expectation.target_key
            )
        ):
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")
        return canonical_json(
            {
                "schema": CHILD_ACK_SUBMISSION_EVENT_KEY_SCHEMA,
                "target_kind": target_kind,
                "target_entity_key": entity_key,
                "intent_event_key": intent_event_key,
                "late_reconcile_deadline_at": expectation.observation_deadline_at,
                "expectation": expectation.payload,
            }
        )

    def _expectation_from_submission_event(
        self, event: sqlite3.Row
    ) -> dict[str, object]:
        try:
            envelope = json.loads(str(event["entity_key"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
            ) from exc
        if (
            type(envelope) is not dict
            or canonical_json(envelope) != event["entity_key"]
            or digest_json(envelope) != event["payload_sha256"]
            or envelope.get("schema") != CHILD_ACK_SUBMISSION_EVENT_KEY_SCHEMA
            or envelope.get("target_kind") not in {"message", "terminal_watch"}
            or type(envelope.get("target_entity_key")) is not str
            or type(envelope.get("intent_event_key")) is not str
            or type(envelope.get("late_reconcile_deadline_at")) is not str
        ):
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
            )
        expectation = self._decode_expectation(envelope.get("expectation"))
        intent = self._intent_event(
            target_kind=str(envelope["target_kind"]),
            intent_event_key=str(envelope["intent_event_key"]),
        )
        decoded_intent = self._intent_from_submission_event(intent)
        try:
            expected = bind_role_executor_child_ack_expectation(
                decoded_intent["fence"],
                systemd_unit=expectation.systemd_unit,
                systemd_invocation_id=expectation.systemd_invocation_id,
                manager_receipt_sha256=expectation.manager_receipt_sha256,
                intent_recorded_at=str(intent["created_at"]),
                observation_deadline_at=expectation.observation_deadline_at,
            )
            deadline = str(envelope["late_reconcile_deadline_at"])
            if (
                deadline != expectation.observation_deadline_at
                or deadline
                != timestamp_after(
                    str(intent["created_at"]),
                    CHILD_ACK_LATE_RECONCILE_SECONDS,
                )
            ):
                raise ValueError
        except (TypeError, ValueError, RegistryError) as exc:
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
            ) from exc
        if (
            expected != expectation
            or expectation.fence_sha256 != decoded_intent["fence"].sha256
            or decoded_intent["target_kind"] != envelope["target_kind"]
            or decoded_intent["target_entity_key"]
            != envelope["target_entity_key"]
            or not self._target_entity_matches(
                str(envelope["target_kind"]),
                str(envelope["target_entity_key"]),
                expectation.target_key,
            )
        ):
            raise CoordinationError(
                "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
            )
        return {
            "expectation": expectation,
            "receipt_event_key": str(event["entity_key"]),
            "intent_event_key": str(envelope["intent_event_key"]),
            "target_kind": str(envelope["target_kind"]),
            "target_entity_key": str(envelope["target_entity_key"]),
            "submission_recorded_at": str(event["created_at"]),
            "late_reconcile_deadline_at": deadline,
            "decoded_intent": decoded_intent,
        }

    def _record_manager_submission(
        self,
        *,
        entity_key: str,
        target_kind: str,
        intent_event_key: str,
        expectation: RoleExecutorChildAckExpectation,
        now: str,
    ) -> str:
        """Bind one manager receipt to its committed intent by exact CAS."""

        if (
            type(expectation) is not RoleExecutorChildAckExpectation
            or digest_json(expectation.payload) != expectation.sha256
            or expectation.observation_deadline_at
            != timestamp_after(
                expectation.intent_recorded_at,
                CHILD_ACK_LATE_RECONCILE_SECONDS,
            )
        ):
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_EXPECTATION_INVALID")
        receipt_event_key = self._manager_submission_event_key(
            entity_key=entity_key,
            target_kind=target_kind,
            intent_event_key=intent_event_key,
            expectation=expectation,
            now=now,
        )
        event_types = self._submission_event_types(target_kind)
        transaction = (
            self.store.transaction()
            if not self.store.connection.in_transaction
            else nullcontext()
        )
        with transaction:
            intent = self._intent_event(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            decoded = self._intent_from_submission_event(intent)
            if (
                decoded["target_entity_key"] != entity_key
                or decoded["target_kind"] != target_kind
                or expectation.fence_sha256 != decoded["fence"].sha256
                or expectation.intent_recorded_at != intent["created_at"]
            ):
                raise CoordinationError(
                    "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
                )
            expected = bind_role_executor_child_ack_expectation(
                decoded["fence"],
                systemd_unit=expectation.systemd_unit,
                systemd_invocation_id=expectation.systemd_invocation_id,
                manager_receipt_sha256=expectation.manager_receipt_sha256,
                intent_recorded_at=str(intent["created_at"]),
                observation_deadline_at=expectation.observation_deadline_at,
            )
            if expected != expectation:
                raise CoordinationError(
                    "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
                )
            prior, prior_event = self._intent_first_disposition(
                target_kind=target_kind, intent_event_key=intent_event_key
            )
            if prior is not None:
                if prior == "submitted" and prior_event is not None:
                    if prior_event["entity_key"] == receipt_event_key:
                        return receipt_event_key
                raise CoordinationError(
                    "ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT"
                )
            self._require_marker_target(
                decoded_intent=decoded,
                marker=CHILD_ACK_SUBMITTING,
                updated_at=str(intent["created_at"]),
            )
            table, key_column = self._target_table(target_kind)
            cursor = self.store.connection.execute(
                f"UPDATE {table} SET updated_at=?,last_error=? "
                f"WHERE {key_column}=? AND process_id IS NULL AND last_error=?",
                (now, CHILD_ACK_PENDING, entity_key, CHILD_ACK_SUBMITTING),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            self.store._event(
                event_types["submitted"],
                receipt_event_key,
                json.loads(receipt_event_key),
                now,
            )
        return receipt_event_key

    @staticmethod
    def _child_ack_observation_ceiling(
        *,
        observed_at: str,
        observation_deadline_at: str,
        elapsed_seconds: float = 0.0,
    ) -> str:
        """Advance a caller-owned logical wall, capped by the fixed deadline."""

        try:
            if (
                isinstance(elapsed_seconds, bool)
                or not isinstance(elapsed_seconds, (int, float))
                or not math.isfinite(float(elapsed_seconds))
                or float(elapsed_seconds) < 0
            ):
                raise ValueError
            advanced = timestamp_after(observed_at, float(elapsed_seconds))
            if _epoch(advanced) <= _epoch(observation_deadline_at):
                return advanced
            return observation_deadline_at
        except (TypeError, ValueError, OverflowError) as exc:
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_WAIT_INVALID") from exc

    def _await_role_executor_child_ack(
        self,
        expectation: RoleExecutorChildAckExpectation,
        *,
        observed_at: str,
    ) -> tuple[RoleExecutorChildAcknowledgement | None, str]:
        """Bound the exact-child observation loop independently of its clock."""

        def sample(previous: float | None = None) -> float:
            raw = self.child_ack_monotonic()
            if (
                isinstance(raw, bool)
                or not isinstance(raw, (int, float))
                or not math.isfinite(float(raw))
                or float(raw) < 0
                or (previous is not None and float(raw) < previous)
            ):
                raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_WAIT_INVALID")
            return float(raw)

        try:
            wait_started_wall = utc_now()
            observation_started_at = (
                wait_started_wall
                if _epoch(wait_started_wall) >= _epoch(observed_at)
                else observed_at
            )
        except (TypeError, ValueError, OverflowError) as exc:
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_WAIT_INVALID") from exc
        started_at = sample()
        previous = started_at
        maximum_polls = (
            math.ceil(
                self.child_ack_timeout_seconds
                / self.child_ack_poll_interval_seconds
            )
            + 2
        )
        for _poll in range(maximum_polls):
            observation_not_after = self._child_ack_observation_ceiling(
                observed_at=observation_started_at,
                observation_deadline_at=expectation.observation_deadline_at,
                elapsed_seconds=previous - started_at,
            )
            acknowledgement = observe_role_executor_child_ack(
                self.store.connection,
                expectation=expectation,
                not_after=observation_not_after,
            )
            if acknowledgement is not None:
                return acknowledgement, observation_not_after
            sampled_at = sample(previous)
            previous = sampled_at
            remaining = self.child_ack_timeout_seconds - (
                sampled_at - started_at
            )
            if remaining <= 0:
                return None, self._child_ack_observation_ceiling(
                    observed_at=observation_started_at,
                    observation_deadline_at=expectation.observation_deadline_at,
                    elapsed_seconds=sampled_at - started_at,
                )
            self.child_ack_sleeper(
                min(self.child_ack_poll_interval_seconds, remaining)
            )
        raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_WAIT_INVALID")

    def _terminal_disposition(
        self, *, target_kind: str, receipt_event_key: str
    ) -> tuple[str | None, sqlite3.Row | None]:
        event_types = self._submission_event_types(target_kind)
        found: list[tuple[str, sqlite3.Row]] = []
        for kind in ("accepted", "rejected", "expired"):
            rows = self.store.connection.execute(
                "SELECT * FROM coordination_events WHERE event_type=? "
                "AND entity_key=? ORDER BY id",
                (event_types[kind], receipt_event_key),
            ).fetchall()
            found.extend((kind, row) for row in rows)
        if not found:
            return None, None
        if len(found) != 1:
            raise CoordinationError("ROLE_EXECUTOR_CHILD_ACK_DISPOSITION_INVALID")
        return found[0]

    def _finalize_manager_submission(
        self,
        *,
        entity_key: str,
        target_kind: str,
        receipt_event_key: str,
        expectation: RoleExecutorChildAckExpectation,
        now: str,
        observation_not_after: str,
        expire_if_pending: bool = False,
        forced_rejection: bool = False,
    ) -> dict[str, object]:
        """Observe and attach one authenticated exact child atomically."""

        event_types = self._submission_event_types(target_kind)
        with self.store.transaction():
            rows = self.store.connection.execute(
                "SELECT * FROM coordination_events WHERE event_type=? "
                "AND entity_key=? ORDER BY id",
                (event_types["submitted"], receipt_event_key),
            ).fetchall()
            if len(rows) != 1:
                raise CoordinationError(
                    "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
                )
            decoded = self._expectation_from_submission_event(rows[0])
            if (
                decoded["target_kind"] != target_kind
                or decoded["target_entity_key"] != entity_key
                or decoded["expectation"] != expectation
                or _epoch(observation_not_after)
                < _epoch(expectation.intent_recorded_at)
                or _epoch(observation_not_after)
                > _epoch(expectation.observation_deadline_at)
            ):
                raise CoordinationError(
                    "ROLE_EXECUTOR_MANAGER_SUBMISSION_EVENT_INVALID"
                )
            terminal, _terminal_event = self._terminal_disposition(
                target_kind=target_kind, receipt_event_key=receipt_event_key
            )
            if terminal is not None:
                return {
                    "resolved": True,
                    "started": False,
                    "acknowledgement": None,
                }

            acknowledgement: RoleExecutorChildAcknowledgement | None = None
            rejection: str | None = CHILD_ACK_REJECTED if forced_rejection else None
            if rejection is None:
                try:
                    acknowledgement = observe_role_executor_child_ack(
                        self.store.connection,
                        expectation=expectation,
                        not_after=observation_not_after,
                    )
                except RegistryError as exc:
                    rejection = (
                        CHILD_ACK_EXPIRED
                        if str(exc) == "EXECUTOR_CHILD_ACK_EXPIRED"
                        else CHILD_ACK_REJECTED
                    )
            if acknowledgement is None and rejection is None:
                if not expire_if_pending:
                    return {
                        "resolved": False,
                        "started": False,
                        "acknowledgement": None,
                    }
                rejection = CHILD_ACK_EXPIRED

            intent = self._intent_event(
                target_kind=target_kind,
                intent_event_key=str(decoded["intent_event_key"]),
            )
            decoded_intent = decoded["decoded_intent"]
            assert type(decoded_intent) is dict
            self._require_marker_target(
                decoded_intent=decoded_intent,
                marker=CHILD_ACK_PENDING,
                updated_at=str(rows[0]["created_at"]),
            )
            table, key_column = self._target_table(target_kind)
            if acknowledgement is not None:
                event_payload = {
                    "child_ack_sha256": acknowledgement.sha256,
                    "expectation_sha256": acknowledgement.expectation_sha256,
                    "manager_receipt_sha256": (
                        acknowledgement.manager_receipt_sha256
                    ),
                    "attempt_id": acknowledgement.attempt_id,
                    "instance_id": acknowledgement.instance_id,
                    "token_sha256": acknowledgement.token_sha256,
                    "event_chain_sha256": acknowledgement.event_chain_sha256,
                    "execution_class": acknowledgement.execution_class,
                    "execution_ownership_sha256": (
                        acknowledgement.execution_ownership_sha256
                    ),
                    "process_id": acknowledgement.process_id,
                }
                cursor = self.store.connection.execute(
                    f"UPDATE {table} SET process_id=?,updated_at=?,last_error=NULL "
                    f"WHERE {key_column}=? AND process_id IS NULL AND last_error=?",
                    (
                        acknowledgement.process_id,
                        now,
                        entity_key,
                        CHILD_ACK_PENDING,
                    ),
                )
                if cursor.rowcount != 1:
                    raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
                self.store._event(
                    "SESSION_WAKE_STARTED"
                    if target_kind == "message"
                    else "TERMINAL_WATCH_WAKE_STARTED",
                    entity_key,
                    event_payload,
                    now,
                )
                self.store._event(
                    event_types["accepted"], receipt_event_key, event_payload, now
                )
                return {
                    "resolved": True,
                    "started": True,
                    "acknowledgement": acknowledgement,
                }

            assert rejection is not None
            kind = "expired" if rejection == CHILD_ACK_EXPIRED else "rejected"
            cursor = self.store.connection.execute(
                f"UPDATE {table} SET state='HOLD',process_id=NULL,"
                f"updated_at=?,last_error=? WHERE {key_column}=? "
                "AND process_id IS NULL AND last_error=?",
                (now, rejection, entity_key, CHILD_ACK_PENDING),
            )
            if cursor.rowcount != 1:
                raise CoordinationError("ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT")
            self.store._event(
                event_types[kind],
                receipt_event_key,
                {
                    "error": rejection,
                    "expectation_sha256": expectation.sha256,
                    "manager_receipt_sha256": expectation.manager_receipt_sha256,
                },
                now,
            )
            return {
                "resolved": True,
                "started": False,
                "acknowledgement": None,
            }

    def _pending_manager_submission_rows(
        self, *, target_kind: str
    ) -> list[dict[str, object]]:
        event_types = self._submission_event_types(target_kind)
        pending: list[dict[str, object]] = []
        seen_intents: set[str] = set()
        seen_targets: set[str] = set()
        for event in self.store.connection.execute(
            "SELECT * FROM coordination_events WHERE event_type=? ORDER BY id",
            (event_types["submitted"],),
        ).fetchall():
            decoded = self._expectation_from_submission_event(event)
            intent_key = str(decoded["intent_event_key"])
            entity_key = str(decoded["target_entity_key"])
            terminal, _terminal_event = self._terminal_disposition(
                target_kind=target_kind,
                receipt_event_key=str(decoded["receipt_event_key"]),
            )
            if terminal is not None:
                continue
            if intent_key in seen_intents or entity_key in seen_targets:
                raise CoordinationError(
                    "ROLE_EXECUTOR_MANAGER_SUBMISSION_AMBIGUOUS"
                )
            seen_intents.add(intent_key)
            seen_targets.add(entity_key)
            pending.append(decoded)
        return pending

    def _reconcile_unbound_submission_intents(
        self, now: str
    ) -> set[tuple[str, str, str]]:
        """Fail closed on an intent whose manager outcome was never bound."""

        handled: set[tuple[str, str, str]] = set()
        for target_kind in ("message", "terminal_watch"):
            event_types = self._submission_event_types(target_kind)
            for event in self.store.connection.execute(
                "SELECT * FROM coordination_events WHERE event_type=? ORDER BY id",
                (event_types["intent"],),
            ).fetchall():
                decoded = self._intent_from_submission_event(event)
                fence = decoded["fence"]
                assert type(fence) is RoleExecutorChildAckFence
                prior, _prior_event = self._intent_first_disposition(
                    target_kind=target_kind,
                    intent_event_key=str(decoded["intent_event_key"]),
                )
                if prior == "abandoned":
                    continue
                if prior == "submitted" and _prior_event is not None:
                    terminal, _terminal_event = self._terminal_disposition(
                        target_kind=target_kind,
                        receipt_event_key=str(_prior_event["entity_key"]),
                    )
                    if terminal is not None:
                        continue
                if prior == "ambiguous":
                    resolution, _resolution_event = self._ambiguous_resolution(
                        target_kind=target_kind,
                        intent_event_key=str(decoded["intent_event_key"]),
                    )
                    if resolution is not None:
                        continue
                handled.add((fence.role, target_kind, fence.target_key))
                if prior is not None:
                    continue
                try:
                    self._record_unbound_submission_hold(
                        intent_event_key=str(decoded["intent_event_key"]),
                        target_kind=target_kind,
                        entity_key=str(decoded["target_entity_key"]),
                        now=now,
                    )
                except CoordinationError as exc:
                    if str(exc) != "ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT":
                        raise
        return handled

    def _reconcile_pending_manager_submissions(
        self, now: str
    ) -> tuple[
        list[dict[str, object]],
        list[dict[str, object]],
        set[tuple[str, str, str]],
    ]:
        messages: list[dict[str, object]] = []
        watches: list[dict[str, object]] = []
        handled: set[tuple[str, str, str]] = set()
        for target_kind in ("message", "terminal_watch"):
            for pending in self._pending_manager_submission_rows(
                target_kind=target_kind
            ):
                expectation = pending["expectation"]
                assert type(expectation) is RoleExecutorChildAckExpectation
                handled.add((expectation.role, target_kind, expectation.target_key))
                try:
                    observation_not_after = self._child_ack_observation_ceiling(
                        observed_at=now,
                        observation_deadline_at=str(
                            pending["late_reconcile_deadline_at"]
                        ),
                    )
                    finalized = self._finalize_manager_submission(
                        entity_key=str(pending["target_entity_key"]),
                        target_kind=target_kind,
                        receipt_event_key=str(pending["receipt_event_key"]),
                        expectation=expectation,
                        now=now,
                        observation_not_after=observation_not_after,
                        expire_if_pending=(
                            _epoch(now)
                            >= _epoch(str(pending["late_reconcile_deadline_at"]))
                        ),
                    )
                except CoordinationError as exc:
                    if str(exc) == "ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT":
                        continue
                    raise
                acknowledgement = finalized["acknowledgement"]
                if (
                    type(acknowledgement) is RoleExecutorChildAcknowledgement
                    and finalized["started"] is True
                ):
                    result = {
                        "process_id": acknowledgement.process_id,
                        "child_ack_sha256": acknowledgement.sha256,
                    }
                    if target_kind == "message":
                        messages.append(
                            {
                                **result,
                                "wake_key": str(pending["target_entity_key"]),
                                "message_id": int(expectation.target_key),
                            }
                        )
                    else:
                        watches.append(
                            {
                                **result,
                                "watch_key": expectation.target_key,
                                "recipient_session_id": expectation.endpoint_id,
                            }
                        )
        return messages, watches, handled

    def _transport_preflight_hold(self, now: str) -> dict[str, object] | None:
        request: RoleExecutorTransportPreflight | None = None
        try:
            request = build_role_executor_transport_preflight(
                self.store.connection
            )
            attestation = self.transport_preflight(request)
            validate_role_executor_transport_attestation(request, attestation)
            revalidate_role_executor_transport_preflight(
                self.store.connection, request
            )
            return None
        except Exception as exc:
            reason = role_executor_transport_failure_reason(exc)
            notice_message_id = (
                None
                if request is None
                else enqueue_role_executor_transport_failure_notice(
                    self.store, request, reason=reason, now=now
                )
            )
            return {
                "phase": "HOLD",
                "reason": reason,
                "notice_message_id": notice_message_id,
                "launched": [],
                "terminal_watch_launches": [],
                "transport_preflight": {
                    "status": "HOLD",
                    "reason": reason,
                },
            }

    def _terminal_watch_backfill_plan(self, item: object) -> dict[str, object]:
        item_snapshot = dict(item)
        session_id = item_snapshot["accountable_session_id"]
        lease = item_snapshot["lease_manifest_sha256"]
        role = coordination_identity_role(self.store.connection, session_id)
        endpoint = (
            current_endpoint(self.store.connection, role)
            if role in {"development", "sre"}
            else None
        )
        endpoint_id = None if endpoint is None else str(endpoint["endpoint_id"])
        messages: list[object] = []
        if endpoint_id is not None and lease:
            if role == "development":
                messages = self.store.connection.execute(
                    """
                    SELECT * FROM coordination_messages
                    WHERE recipient_session_id=?
                      AND topic IN (
                        'development.admission', 'development.recovery_commit'
                      )
                    ORDER BY id
                    """,
                    (endpoint_id,),
                ).fetchall()
            elif role == "sre":
                messages = self.store.connection.execute(
                    """
                    SELECT * FROM coordination_messages
                    WHERE recipient_session_id=? AND topic='sre.admission'
                    ORDER BY id
                    """,
                    (endpoint_id,),
                ).fetchall()
        candidates: list[dict[str, object]] = []
        for message in messages:
            try:
                payload = json.loads(message["payload_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            source = payload.get("source") if isinstance(payload, dict) else None
            if (
                isinstance(source, dict)
                and source.get("repository") == item_snapshot["repository"]
                and source.get("object_kind") == "issue"
                and source.get("object_number") == int(item_snapshot["issue_number"])
                and payload.get("issue_number") == int(item_snapshot["issue_number"])
                and payload.get("generation") == int(item_snapshot["generation"])
                and payload.get("lease_manifest_sha256") == lease
                and source.get("payload_sha256")
                == item_snapshot["source_payload_sha256"]
                and digest_json(payload) == message["payload_sha256"]
            ):
                candidates.append(dict(message))
        bound_message = candidates[0] if len(candidates) == 1 else None
        backfill_state = "HOLD"
        claim_attempt_id = None
        error = "TERMINAL_WATCH_BACKFILL_INVALID_LINEAGE"
        if bound_message is not None and bound_message["state"] == "PREPARED":
            backfill_state = "PENDING_CLAIM"
            error = None
        elif bound_message is not None and bound_message["state"] in {
            "CLAIMED",
            "COMPLETE",
        }:
            if bound_message["claimed_by"] != endpoint_id:
                error = "TERMINAL_WATCH_BACKFILL_CLAIM_BINDING_INVALID"
                attempts = []
            else:
                attempts = None
            if attempts is None:
                required_attempt_states = (
                    ("RUNNING", "COMPLETE")
                    if bound_message["state"] == "CLAIMED"
                    else ("COMPLETE",)
                )
                attempts = self.store.connection.execute(
                    """
                    SELECT * FROM executor_attempts
                    WHERE role=? AND endpoint_id=?
                      AND target_kind='message' AND target_key=?
                      AND state IN ({})
                      AND lineage_repository=? AND lineage_issue_number=?
                      AND lineage_generation=? AND lineage_lease_sha256=?
                    ORDER BY created_at DESC
                    """.format(
                        ",".join("?" for _ in required_attempt_states)
                    ),
                    (
                        role,
                        endpoint_id,
                        str(bound_message["id"]),
                        *required_attempt_states,
                        item_snapshot["repository"],
                        item_snapshot["issue_number"],
                        item_snapshot["generation"],
                        lease,
                    ),
                ).fetchall()
            if len(attempts) == 1:
                backfill_state = "ACTIVE"
                claim_attempt_id = attempts[0]["attempt_id"]
                error = None
            elif error != "TERMINAL_WATCH_BACKFILL_CLAIM_BINDING_INVALID":
                error = "TERMINAL_WATCH_BACKFILL_ATTEMPT_AMBIGUOUS"
        elif bound_message is not None:
            error = "TERMINAL_WATCH_BACKFILL_MESSAGE_NOT_EXECUTABLE"
        return {
            "item": item_snapshot,
            "watch_key": terminal_watch_key(
                str(item_snapshot["repository"]),
                int(item_snapshot["issue_number"]),
                int(item_snapshot["generation"]),
            ),
            "session_id": session_id,
            "lease": lease,
            "endpoint_id": endpoint_id,
            "bound_message": bound_message,
            "backfill_state": backfill_state,
            "claim_attempt_id": claim_attempt_id,
            "error": error,
        }

    def _ensure_terminal_watches(self, now: str) -> tuple[list[str], list[dict[str, object]]]:
        opened: list[str] = []
        held: list[dict[str, object]] = []
        items = self.store.connection.execute(
            """
            SELECT * FROM coordination_items
            WHERE allocation_class='ACTIVE'
              AND status IN (
                'ACTIVE', 'ACTIVE_FENCED', 'MONITOR', 'PUBLICATION_PENDING'
              )
            ORDER BY repository, issue_number
            """
        ).fetchall()
        plans: list[dict[str, object]] = []
        for item in items:
            key = terminal_watch_key(
                item["repository"], int(item["issue_number"]), int(item["generation"])
            )
            if self.store.connection.execute(
                "SELECT 1 FROM coordination_terminal_watches WHERE watch_key=?",
                (key,),
            ).fetchone() is None:
                plans.append(self._terminal_watch_backfill_plan(item))
        for plan in plans:
            item_snapshot = plan["item"]
            with self.store.transaction():
                item = self.store.connection.execute(
                    "SELECT * FROM coordination_items "
                    "WHERE repository=? AND issue_number=?",
                    (item_snapshot["repository"], item_snapshot["issue_number"]),
                ).fetchone()
                if item is None or dict(item) != item_snapshot:
                    continue
                key = str(plan["watch_key"])
                if self.store.connection.execute(
                    "SELECT 1 FROM coordination_terminal_watches WHERE watch_key=?",
                    (key,),
                ).fetchone() is not None:
                    continue
                if self._terminal_watch_backfill_plan(item) != plan:
                    continue
                bound_message = plan["bound_message"]
                error = plan["error"]
                if error is not None:
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
                    self.store.connection.execute(
                        """
                        INSERT INTO coordination_terminal_watches(
                            watch_key, repository, issue_number, generation,
                            accountable_session_id, lease_manifest_sha256, state,
                            admission_message_id, admission_payload_sha256,
                            claim_attempt_id,
                            attempts, process_id, last_heartbeat_at, next_wake_at,
                            updated_at, last_error
                        ) VALUES (?, ?, ?, ?, ?, ?, 'HOLD', ?, ?, ?, 0, NULL, ?, ?, ?, ?)
                        """,
                        (
                            key,
                            item["repository"],
                            item["issue_number"],
                            item["generation"],
                            plan["session_id"]
                            if isinstance(plan["session_id"], str) and plan["session_id"]
                            else "invalid",
                            plan["lease"]
                            if isinstance(plan["lease"], str) and plan["lease"]
                            else "0" * 64,
                            None if bound_message is None else bound_message["id"],
                            None
                            if bound_message is None
                            else bound_message["payload_sha256"],
                            plan["claim_attempt_id"],
                            now,
                            now,
                            now,
                            error,
                        ),
                    )
                    continue
                self.store.connection.execute(
                    """
                    INSERT INTO coordination_terminal_watches(
                        watch_key, repository, issue_number, generation,
                        accountable_session_id, lease_manifest_sha256, state,
                        admission_message_id, admission_payload_sha256,
                        claim_attempt_id,
                        attempts, process_id, last_heartbeat_at, next_wake_at,
                        updated_at, last_error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, NULL)
                    """,
                    (
                        key,
                        item["repository"],
                        item["issue_number"],
                        item["generation"],
                        plan["endpoint_id"],
                        plan["lease"],
                        plan["backfill_state"],
                        bound_message["id"],
                        bound_message["payload_sha256"],
                        plan["claim_attempt_id"],
                        now,
                        now,
                        now,
                    ),
                )
                self.store._event(
                    "TERMINAL_WATCH_BACKFILLED",
                    key,
                    {
                        "item_version": int(item["version"]),
                        "state": plan["backfill_state"],
                        "admission_message_id": int(bound_message["id"]),
                    },
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
            current_source = self.store.connection.execute(
                "SELECT payload_sha256 FROM github_current "
                "WHERE repository=? AND object_kind='issue' AND object_number=?",
                (watch["repository"], watch["issue_number"]),
            ).fetchone()
            if item is None or item["allocation_class"] != "ACTIVE" or item["status"] not in ACTIVE_EXECUTION_STATUSES:
                terminal_commit = self.store.connection.execute(
                    """
                    SELECT 1
                    FROM coordination_terminal_closeout_packets packet
                    JOIN coordination_terminal_closeout_commits terminal_commit
                      USING(closeout_key)
                    WHERE packet.terminal_watch_key=?
                    """,
                    (watch_key,),
                ).fetchone()
                state = "COMPLETE" if terminal_commit is not None else "HOLD"
                error = (
                    None
                    if terminal_commit is not None
                    else "TERMINAL_WATCH_ITEM_STATE_WITHOUT_CLOSEOUT_COMMIT"
                )
                self.store.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state=?, process_id=NULL, updated_at=?, last_error=?
                    WHERE watch_key=? AND state='ACTIVE'
                    """,
                    (state, now, error, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_COMPLETED"
                    if state == "COMPLETE"
                    else "TERMINAL_WATCH_HELD",
                    watch_key,
                    {} if error is None else {"error": error},
                    now,
                )
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
            admission = self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (watch["admission_message_id"],),
            ).fetchone()
            try:
                admission_payload = (
                    None
                    if admission is None
                    else json.loads(admission["payload_json"])
                )
            except (TypeError, json.JSONDecodeError):
                admission_payload = None
            admission_source = (
                admission_payload.get("source")
                if isinstance(admission_payload, dict)
                else None
            )
            admission_capacity = (
                admission_payload.get("capacity")
                if isinstance(admission_payload, dict)
                else None
            )
            expected_admission_topics = (
                {"development.admission", "development.recovery_commit"}
                if role == "development"
                else {"sre.admission"}
            )
            claim_attempt = self.store.connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (watch["claim_attempt_id"],),
            ).fetchone()
            packet = self.store.connection.execute(
                "SELECT 1 FROM coordination_terminal_closeout_packets "
                "WHERE terminal_watch_key=?",
                (watch_key,),
            ).fetchone()
            original_endpoint = (
                None if admission is None else admission["recipient_session_id"]
            )
            historical_before_version = (
                None
                if not isinstance(admission_payload, dict)
                or type(admission_payload.get("item_version")) is not int
                else int(admission_payload["item_version"])
                + (1 if admission["topic"] == "development.recovery_commit" else 0)
            )
            rotation_chain = None
            if (
                original_endpoint != watch["accountable_session_id"]
                and admission is not None
                and admission["topic"]
                in {"development.admission", "sre.admission"}
                and item is not None
                and isinstance(historical_before_version, int)
            ):
                try:
                    rotation_chain = applied_endpoint_rotation_chain(
                        self.store.connection,
                        repository=str(watch["repository"]),
                        issue_number=int(watch["issue_number"]),
                        before_identity=str(original_endpoint),
                        before_item_version=historical_before_version,
                        after_identity=str(watch["accountable_session_id"]),
                        after_item_version=int(item["version"]),
                        watch_key=watch_key,
                        expected_watch_state="ACTIVE",
                        not_before=str(claim_attempt["created_at"]),
                    )
                except RegistryError:
                    rotation_chain = None
            rotated_proven = rotation_chain is not None
            rotation_valid = bool(
                original_endpoint == watch["accountable_session_id"]
                or rotated_proven
            )
            if (
                admission is None
                or admission["topic"] not in expected_admission_topics
                or not isinstance(admission_payload, dict)
                or not isinstance(admission_source, dict)
                or not isinstance(admission_capacity, dict)
                or digest_json(admission_payload) != admission["payload_sha256"]
                or admission["payload_sha256"] != watch["admission_payload_sha256"]
                or admission["state"] not in {"CLAIMED", "COMPLETE"}
                or (rotated_proven and admission["state"] != "CLAIMED")
                or coordination_identity_role(
                    self.store.connection, str(original_endpoint)
                ) != role
                or admission["claimed_by"] != original_endpoint
                or not rotation_valid
                or admission_source.get("repository") != watch["repository"]
                or admission_source.get("object_kind") != "issue"
                or admission_source.get("object_number")
                != int(watch["issue_number"])
                or admission_payload.get("issue_number")
                != int(watch["issue_number"])
                or admission_payload.get("generation")
                != int(watch["generation"])
                or admission_payload.get("accountable_session_id")
                != original_endpoint
                or admission_payload.get("lease_manifest_sha256")
                != watch["lease_manifest_sha256"]
                or item["source_payload_sha256"]
                != admission_source.get("payload_sha256")
                or current_source is None
                or not admission_lineage_source_is_current(
                    self.store.connection, item=item, message=admission, watch=watch,
                    current_source_sha256=str(current_source["payload_sha256"]),
                )
                or int(item["development_units"])
                != admission_capacity.get("development_units")
                or int(item["shared_units"])
                != admission_capacity.get("shared_units")
                or int(item["sre_units"])
                != admission_capacity.get("sre_units")
                or claim_attempt is None
                or claim_attempt["role"] != role
                or claim_attempt["endpoint_id"] != original_endpoint
                or claim_attempt["state"] not in (
                    {"RUNNING", "COMPLETE", "HOLD"}
                    if packet is not None or rotated_proven
                    else {"RUNNING", "COMPLETE"}
                )
                or claim_attempt["target_kind"] != "message"
                or claim_attempt["target_key"] != str(watch["admission_message_id"])
                or claim_attempt["lineage_repository"] != watch["repository"]
                or int(claim_attempt["lineage_issue_number"] or -1)
                != int(watch["issue_number"])
                or int(
                    claim_attempt["lineage_generation"]
                    if claim_attempt["lineage_generation"] is not None
                    else -1
                )
                != int(watch["generation"])
                or claim_attempt["lineage_lease_sha256"]
                != watch["lease_manifest_sha256"]
            ):
                self.store.connection.execute(
                    """
                    UPDATE coordination_terminal_watches
                    SET state='HOLD', process_id=NULL, updated_at=?,
                        last_error='TERMINAL_WATCH_ADMISSION_BINDING_DRIFT'
                    WHERE watch_key=? AND state='ACTIVE'
                    """,
                    (now, watch_key),
                )
                self.store._event(
                    "TERMINAL_WATCH_HELD",
                    watch_key,
                    {"error": "TERMINAL_WATCH_ADMISSION_BINDING_DRIFT"},
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
            cursor = self.store.connection.execute(
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
            if cursor.rowcount != 1:
                return None, False
            reserved = self.store.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (watch_key,),
            ).fetchone()
            return reserved, reserved is not None

    def _eligible_due_terminal_watch_lineages(self, now: str) -> set[str]:
        """Read due watch eligibility without consuming a wake or retry counter."""

        eligible: set[str] = set()
        watches = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches "
            "WHERE state='ACTIVE' AND next_wake_at<=?",
            (now,),
        ).fetchall()
        for watch in watches:
            try:
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
                ):
                    continue
            except (CoordinationError, RegistryError, TypeError, ValueError):
                continue
            if self.process_checker(
                str(endpoint["endpoint_id"]),
                "terminal_watch",
                str(watch["watch_key"]),
            ):
                continue
            try:
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
            envelope = parse_coordination_envelope(row["payload_json"])
            payload = envelope.payload
            if envelope.payload_sha256 != row["payload_sha256"]:
                raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
            if envelope.reserved_handler != "claimed_no_delivery_park":
                self.store._validate_message_source(payload)
            self.store._validate_message_contract(
                topic=row["topic"],
                recipient_session_id=row["recipient_session_id"],
                payload=payload,
                message_id=int(row["id"]),
            )
            if row["state"] == "CLAIMED" and row["topic"] in {
                "development.admission",
                "development.recovery_commit",
                "sre.admission",
            }:
                source = payload.get("source") if isinstance(payload, dict) else None
                watch = (
                    None
                    if not isinstance(source, dict)
                    else self.store.connection.execute(
                        "SELECT admission_message_id,admission_payload_sha256 "
                        "FROM coordination_terminal_watches "
                        "WHERE repository=? AND issue_number=? AND generation=?",
                        (
                            source.get("repository"),
                            payload.get("issue_number"),
                            payload.get("generation"),
                        ),
                    ).fetchone()
                )
                if (
                    watch is not None
                    and int(watch["admission_message_id"] or 0) == int(row["id"])
                    and watch["admission_payload_sha256"] != row["payload_sha256"]
                ):
                    raise CoordinationError("MESSAGE_PAYLOAD_MISMATCH")
        except (CoordinationError, RegistryError) as exc:
            return str(exc) if isinstance(exc, CoordinationError) else "INVALID_MESSAGE"
        return None

    def _hold_stale_message(self, row: object, error: str, now: str) -> None:
        if coordination_envelope_error_is_zero_write(
            error, payload_json=row["payload_json"]
        ):
            return
        with self.store.transaction():
            self._hold_stale_message_locked(row, error, now)

    def _hold_stale_message_locked(self, row: object, error: str, now: str) -> None:
        if coordination_envelope_error_is_zero_write(
            error, payload_json=row["payload_json"]
        ):
            return
        cursor = self.store.connection.execute(
            "UPDATE coordination_messages SET state='HOLD', updated_at=?, last_error=? WHERE id=? AND state IN ('PREPARED', 'CLAIMED')",
            (now, error, row["id"]),
        )
        if cursor.rowcount == 1:
            self.store._event(
                "MESSAGE_HELD", f"message:{row['id']}", {"error": error}, now
            )

    def _hold_retry_exhausted_locked(
        self, message: object, wake: object, now: str
    ) -> None:
        """Retain exact pre-claim admissions; preserve generic wake behavior."""

        if (
            message["state"] == "PREPARED"
            and message["claimed_by"] is None
            and message["topic"] in {"development.admission", "sre.admission"}
            and isinstance(wake["target_progress_sha256"], str)
        ):
            self.store.hold_unclaimed_admission_retry_exhausted(
                message_id=int(message["id"]),
                wake_key=str(wake["wake_key"]),
                expected_target_progress_sha256=str(
                    wake["target_progress_sha256"]
                ),
                expected_wake_attempts=int(wake["attempts"]),
                now=now,
                _transaction=False,
            )
            return
        self._hold_stale_message_locked(message, "WAKE_RETRY_EXHAUSTED", now)
        self.store.connection.execute(
            """UPDATE coordination_wakes
            SET state='HOLD', process_id=NULL, updated_at=?,
                last_error='WAKE_RETRY_EXHAUSTED'
            WHERE wake_key=? AND state='INFLIGHT'""",
            (now, wake["wake_key"]),
        )
        self.store._event(
            "WAKE_HELD",
            str(wake["wake_key"]),
            {"error": "WAKE_RETRY_EXHAUSTED"},
            now,
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
        if self.store.connection.execute(
            "SELECT 1 FROM coordination_terminal_closeout_packets "
            "WHERE activation_message_id=?",
            (row["id"],),
        ).fetchone() is not None:
            # A durable terminal packet is the typed continuation target.  A
            # crashed original writer must not be relaunched against the
            # admission row and race a fresh terminal watcher.
            return False
        if row["topic"] in {
            "development.admission",
            "development.recovery_commit",
            "sre.admission",
        }:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            source = payload.get("source") if isinstance(payload, dict) else None
            watch = (
                None
                if not isinstance(source, dict)
                else self.store.connection.execute(
                    "SELECT * FROM coordination_terminal_watches "
                    "WHERE repository=? AND issue_number=? AND generation=?",
                    (
                        source.get("repository"),
                        payload.get("issue_number"),
                        payload.get("generation"),
                    ),
                ).fetchone()
            )
            if (
                watch is not None
                and digest_json(payload) == row["payload_sha256"]
                and watch["state"] == "ACTIVE"
                and int(watch["admission_message_id"] or 0) == int(row["id"])
                and watch["admission_payload_sha256"] == row["payload_sha256"]
                and watch["claim_attempt_id"] is not None
            ):
                # Recovery activation has transferred continuation to its
                # exact terminal watch.  The recovery message remains CLAIMED
                # until the atomic terminal commit and must not be relaunched.
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
        if coordination_envelope_error_is_zero_write(
            "MESSAGE_PAYLOAD_MISMATCH", payload_json=row["payload_json"]
        ):
            return True
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
            if coordination_envelope_error_is_zero_write(
                "MESSAGE_PAYLOAD_MISMATCH",
                payload_json=current["payload_json"],
            ):
                return True
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
        if row["state"] in {"PREPARED", "CLAIMED"}:
            if (
                not recipient_matches_topic(
                    self.store.connection,
                    topic=row["topic"],
                    recipient=row["recipient_session_id"],
                )
                and coordination_envelope_error_is_zero_write(
                    "MESSAGE_ROLE_MISMATCH", payload_json=row["payload_json"]
                )
            ):
                return None, False
            advisory_error = self._message_contract_error(row)
            if advisory_error is not None and coordination_envelope_error_is_zero_write(
                advisory_error, payload_json=row["payload_json"]
            ):
                return None, False
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
                if coordination_envelope_error_is_zero_write(
                    "MESSAGE_PAYLOAD_MISMATCH",
                    payload_json=current_row["payload_json"],
                ):
                    return wake_key, False
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
                cursor = self.store.connection.execute(
                    """UPDATE coordination_wakes
                    SET attempts=1, process_id=NULL, target_progress_sha256=?,
                        last_attempt_at=?, updated_at=?, last_error=NULL
                    WHERE wake_key=? AND state='INFLIGHT'""",
                    (progress_sha256, now, now, wake_key),
                )
                if cursor.rowcount != 1:
                    return wake_key, False
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
                self._hold_retry_exhausted_locked(current_row, current, now)
                return wake_key, False
            cursor = self.store.connection.execute(
                "UPDATE coordination_wakes SET attempts=attempts+1, process_id=NULL, last_attempt_at=?, updated_at=?, last_error=NULL WHERE wake_key=?",
                (now, now, wake_key),
            )
            if cursor.rowcount != 1:
                return wake_key, False
            return wake_key, True

    def _record_launch_failure(self, wake_key: str, now: str) -> None:
        preview_wake = self.store.connection.execute(
            "SELECT * FROM coordination_wakes WHERE wake_key=?",
            (wake_key,),
        ).fetchone()
        preview_message = (
            None
            if preview_wake is None
            else self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (preview_wake["message_id"],),
            ).fetchone()
        )
        if preview_wake is not None and preview_message is not None:
            preview_error = (
                "MESSAGE_PAYLOAD_MISMATCH"
                if preview_wake["message_payload_sha256"]
                != preview_message["payload_sha256"]
                else self._message_contract_error(preview_message)
            )
            if preview_error is not None and coordination_envelope_error_is_zero_write(
                preview_error, payload_json=preview_message["payload_json"]
            ):
                return
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
                if coordination_envelope_error_is_zero_write(
                    "MESSAGE_PAYLOAD_MISMATCH",
                    payload_json=message["payload_json"],
                ):
                    return
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
                if coordination_envelope_error_is_zero_write(
                    contract_error, payload_json=message["payload_json"]
                ):
                    return
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
            if exhausted:
                self._hold_retry_exhausted_locked(message, wake, now)
            else:
                self.store.connection.execute(
                    "UPDATE coordination_wakes SET state='INFLIGHT', "
                    "process_id=NULL, updated_at=?, last_error=? "
                    "WHERE wake_key=? AND state='INFLIGHT'",
                    (now, error, wake_key),
                )
                self.store._event(
                    "WAKE_LAUNCH_FAILED", wake_key, {"error": error}, now
                )

    def _complete_stale_wakes(self, now: str) -> None:
        pending_manager_wakes = {
            str(row["target_entity_key"])
            for row in self._unresolved_submission_intents()
            if row["target_kind"] == "message"
        }
        with self.store.transaction():
            rows = self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE state='INFLIGHT'"
            ).fetchall()
            for wake in rows:
                if str(wake["wake_key"]) in pending_manager_wakes:
                    continue
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
        pass_started_at = self.monotonic()
        observed_at = now or utc_now()
        transport_hold = self._transport_preflight_hold(observed_at)
        if transport_hold is not None:
            return transport_hold
        if self.convergence is None:
            self.convergence = PortfolioConvergence(self.store)
        assert self.convergence is not None
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
        broker_pickups = consume_staged_broker_pickups(
            self.store.connection, now=observed_at
        )
        broker_recovery = recover_stale_broker_runs(
            self.store.connection,
            before=_before(observed_at, 120),
            now=observed_at,
        )
        # Release events are committed by coordination_store with the item
        # transition. Consume them before housekeeping or ordinary inbox wakes;
        # a successful admission is durable before its canonical session launch.
        convergence_deadline = self.monotonic() + CONVERGENCE_PHASE_TIMEOUT_SECONDS
        convergence_results = self.convergence.consume_due(
            limit=self.convergence_limit,
            now=observed_at,
            deadline=convergence_deadline,
            monotonic=self.monotonic,
        )
        stale_before = timestamp_after(observed_at, -ATTEMPT_STALE_SECONDS)
        try:
            recovered_reserved = recover_reserved_attempts(
                self.store.connection, before=stale_before, now=observed_at
            )
            recovery_kwargs = {}
            if self.stale_attempt_evidence_reader is not None:
                recovery_kwargs["evidence_reader"] = self.stale_attempt_evidence_reader
            recovered_active = recover_stale_active_attempts(
                self.store.connection,
                before=stale_before,
                now=observed_at,
                **recovery_kwargs,
            )
        except RegistryError as exc:
            recovered_reserved = []
            recovered_active = [{"phase": "HOLD", "error": str(exc)}]
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
        self._reconcile_unbound_submission_intents(observed_at)
        (
            ambiguity_recovered_message_launches,
            ambiguity_recovered_terminal_watch_launches,
        ) = self._reconcile_ambiguous_submission_intents(observed_at)
        (
            reconciled_message_launches,
            reconciled_terminal_watch_launches,
            _pending_submission_targets,
        ) = self._reconcile_pending_manager_submissions(observed_at)
        unresolved_submission_intents = self._unresolved_submission_intents()
        manager_submission_targets = {
            (
                str(decoded["fence"].role),
                str(decoded["target_kind"]),
                str(decoded["fence"].target_key),
            )
            for decoded in unresolved_submission_intents
        }
        manager_submission_lineages = {
            str(decoded["fence"].lineage_sha256)
            for decoded in unresolved_submission_intents
            if decoded["fence"].lineage_sha256 is not None
        }
        manager_submission_planner_repositories = {
            str(decoded["planner_repository"])
            for decoded in unresolved_submission_intents
            if decoded["planner_repository"] is not None
        }
        self._complete_stale_wakes(observed_at)
        due_terminal_lineages = self._eligible_due_terminal_watch_lineages(observed_at)
        terminal_watch_slot_reserved = bool(due_terminal_lineages)
        message_launch_limit = self.launch_policy.messages
        if not terminal_watch_slot_reserved:
            message_launch_limit = min(
                self.launch_policy.total,
                self.launch_policy.messages + self.launch_policy.terminal_watches,
            )
        launched: list[dict[str, object]] = [
            *ambiguity_recovered_message_launches,
            *reconciled_message_launches,
        ]
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
        scheduled_lineages: set[str] = set(manager_submission_lineages)
        scheduled_planner_repositories: set[str] = set(
            manager_submission_planner_repositories
        )
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
            if row["state"] == "CLAIMED" and self.store.connection.execute(
                "SELECT 1 FROM coordination_terminal_closeout_packets "
                "WHERE activation_message_id=?",
                (row["id"],),
            ).fetchone() is not None:
                # The immutable packet is now the sole continuation target.
                # Do not revalidate or hold the historical admission against a
                # rotated mutable item before the current watcher runs.
                continue
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
            if target in scheduled_targets or target in manager_submission_targets:
                continue
            scheduled_targets.add(target)
            if self.process_checker(current_identity, "message", str(row["id"])):
                continue
            wake_key, should_launch = self._reserve_wake(row, observed_at)
            if not should_launch or wake_key is None:
                continue
            reservation_row = self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE wake_key=?", (wake_key,)
            ).fetchone()
            if reservation_row is None:
                continue
            reservation = dict(reservation_row)
            launch_attempts += 1
            message_launch_attempts += 1
            if message_id in retry_message_ids:
                due_message_retry_launch_attempts += 1
            if lineage is not None:
                scheduled_lineages.add(lineage.sha256)
            if planner_repository is not None:
                scheduled_planner_repositories.add(planner_repository)
            try:
                child_ack_fence = snapshot_role_executor_child_ack_fence(
                    self.store.connection,
                    role=recipient_role,
                    endpoint_id=current_identity,
                    target_kind="message",
                    target_key=str(row["id"]),
                )
                intent_event_key = self._record_submission_intent(
                    entity_key=wake_key,
                    target_kind="message",
                    fence=child_ack_fence,
                    reservation=reservation,
                    now=observed_at,
                )
            except (CoordinationError, RegistryError):
                continue
            try:
                launch_result = self._submit_manager_after_atomic_revalidation(
                    intent_event_key=intent_event_key,
                    target_kind="message",
                    entity_key=wake_key,
                    submit=lambda: self.launcher(
                        current_identity, int(row["id"])
                    ),
                    now=observed_at,
                )
            except Exception:
                try:
                    self._record_unbound_submission_hold(
                        intent_event_key=intent_event_key,
                        target_kind="message",
                        entity_key=wake_key,
                        now=observed_at,
                    )
                except CoordinationError:
                    pass
                continue
            if launch_result["status"] == "ABANDONED":
                continue
            if launch_result["status"] != "SUBMITTED":
                continue
            expectation = launch_result["expectation"]
            receipt_event_key = str(launch_result["receipt_event_key"])
            assert type(expectation) is RoleExecutorChildAckExpectation
            try:
                (
                    observed_ack,
                    observation_not_after,
                ) = self._await_role_executor_child_ack(
                    expectation, observed_at=observed_at
                )
            except (CoordinationError, RegistryError):
                try:
                    self._finalize_manager_submission(
                        entity_key=wake_key,
                        target_kind="message",
                        receipt_event_key=receipt_event_key,
                        expectation=expectation,
                        now=observed_at,
                        observation_not_after=self._child_ack_observation_ceiling(
                            observed_at=observed_at,
                            observation_deadline_at=(
                                expectation.observation_deadline_at
                            ),
                        ),
                        forced_rejection=True,
                    )
                except (CoordinationError, RegistryError):
                    pass
                continue
            if observed_ack is None:
                continue
            try:
                finalized = self._finalize_manager_submission(
                    entity_key=wake_key,
                    target_kind="message",
                    receipt_event_key=receipt_event_key,
                    expectation=expectation,
                    now=observed_at,
                    observation_not_after=observation_not_after,
                )
            except (CoordinationError, RegistryError):
                continue
            acknowledgement = finalized["acknowledgement"]
            if (
                type(acknowledgement) is RoleExecutorChildAcknowledgement
                and finalized["started"] is True
            ):
                launched.append(
                    {
                        "wake_key": wake_key,
                        "message_id": int(row["id"]),
                        "process_id": acknowledgement.process_id,
                        "child_ack_sha256": acknowledgement.sha256,
                    }
                )
        terminal_watch_launches: list[dict[str, object]] = [
            *ambiguity_recovered_terminal_watch_launches,
            *reconciled_terminal_watch_launches,
        ]
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
            if target in scheduled_targets or target in manager_submission_targets:
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
                child_ack_fence = snapshot_role_executor_child_ack_fence(
                    self.store.connection,
                    role=recipient_role,
                    endpoint_id=current_identity,
                    target_kind="terminal_watch",
                    target_key=str(watch["watch_key"]),
                )
                intent_event_key = self._record_submission_intent(
                    entity_key=str(watch["watch_key"]),
                    target_kind="terminal_watch",
                    fence=child_ack_fence,
                    reservation=dict(current),
                    now=observed_at,
                )
            except (CoordinationError, RegistryError):
                continue
            try:
                launch_result = self._submit_manager_after_atomic_revalidation(
                    intent_event_key=intent_event_key,
                    target_kind="terminal_watch",
                    entity_key=str(watch["watch_key"]),
                    submit=lambda: self.terminal_watch_launcher(
                        current_identity, watch["watch_key"]
                    ),
                    now=observed_at,
                )
            except Exception:
                try:
                    self._record_unbound_submission_hold(
                        intent_event_key=intent_event_key,
                        target_kind="terminal_watch",
                        entity_key=str(watch["watch_key"]),
                        now=observed_at,
                    )
                except CoordinationError:
                    pass
                continue
            if launch_result["status"] == "ABANDONED":
                continue
            if launch_result["status"] != "SUBMITTED":
                continue
            expectation = launch_result["expectation"]
            receipt_event_key = str(launch_result["receipt_event_key"])
            assert type(expectation) is RoleExecutorChildAckExpectation
            try:
                (
                    observed_ack,
                    observation_not_after,
                ) = self._await_role_executor_child_ack(
                    expectation, observed_at=observed_at
                )
            except (CoordinationError, RegistryError):
                try:
                    self._finalize_manager_submission(
                        entity_key=str(watch["watch_key"]),
                        target_kind="terminal_watch",
                        receipt_event_key=receipt_event_key,
                        expectation=expectation,
                        now=observed_at,
                        observation_not_after=self._child_ack_observation_ceiling(
                            observed_at=observed_at,
                            observation_deadline_at=(
                                expectation.observation_deadline_at
                            ),
                        ),
                        forced_rejection=True,
                    )
                except (CoordinationError, RegistryError):
                    pass
                continue
            if observed_ack is None:
                continue
            try:
                finalized = self._finalize_manager_submission(
                    entity_key=str(watch["watch_key"]),
                    target_kind="terminal_watch",
                    receipt_event_key=receipt_event_key,
                    expectation=expectation,
                    now=observed_at,
                    observation_not_after=observation_not_after,
                )
            except (CoordinationError, RegistryError):
                continue
            acknowledgement = finalized["acknowledgement"]
            if (
                type(acknowledgement) is RoleExecutorChildAcknowledgement
                and finalized["started"] is True
            ):
                scheduled_lineages.add(lineage.sha256)
                terminal_watch_launches.append(
                    {
                        "watch_key": watch["watch_key"],
                        "recipient_session_id": recipient,
                        "process_id": acknowledgement.process_id,
                        "child_ack_sha256": acknowledgement.sha256,
                    }
                )
        successful_launches = len(launched) + len(terminal_watch_launches)
        reconciled_launches = (
            len(ambiguity_recovered_message_launches)
            + len(ambiguity_recovered_terminal_watch_launches)
            + len(reconciled_message_launches)
            + len(reconciled_terminal_watch_launches)
        )
        newly_successful_launches = successful_launches - reconciled_launches
        return {
            "telemetry": {
                "duration_seconds": round(
                    max(0.0, self.monotonic() - pass_started_at), 6
                ),
                "selected": len(rows) + len(watches),
                "attempted": launch_attempts,
                "succeeded": newly_successful_launches,
                "failed": launch_attempts - newly_successful_launches,
            },
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
            "broker_pickups": broker_pickups,
            "broker_recovery": broker_recovery,
            "artifact_gc": artifact_gc,
            "readiness_receipt_pickup": readiness_receipt_pickup,
            "readiness_decision_notices": readiness_decision_notices,
            "readiness_revisits": readiness_revisits,
            "readiness_revocations": readiness_revocations,
            "portfolio_convergence": convergence_results,
            "recovered_reserved_attempts": recovered_reserved,
            "recovered_active_attempts": recovered_active,
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
        print(canonical_json({"phase": "SKIPPED", "reason": "LOCK_CONTENDED"}))
        return 0
    store = CoordinationStore(DEFAULT_DATABASE)
    try:
        result = CoordinationSupervisor(
            store, transport_preflight=attest_role_executor_transport
        ).run_once()
        print(canonical_json(result))
    except (CoordinationError, RegistryError) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        store.close()
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
