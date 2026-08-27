#!/usr/bin/env python3
"""Consume durable portfolio-release events and converge one safe successor."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Callable

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
    digest_json,
    utc_now,
)
from kanban_pull_buffer import (
    PullBufferError,
    _retire_pointer,
    admission_binding_error,
    audit_pull_buffer,
    close_candidate_observations,
    ensure_pull_buffer_schema,
    load_candidate_packets,
)
from portfolio_graph import (
    PortfolioGraphError,
    _schedule_decision,
)
from repository_delivery_policy import expected_canonical_checkout


GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_ATTEMPTS = 5
RETRY_BASE_SECONDS = 5
MAX_RETRY_SECONDS = 60
DEFAULT_CONVERGENCE_LIMIT = 32
MAX_CONVERGENCE_LIMIT = 100


class PortfolioConvergenceError(ValueError):
    """Typed fail-closed convergence error."""


ExternalReader = Callable[[dict[str, Any]], dict[str, Any]]
CanonicalMainReader = Callable[[str], str]
Failpoint = Callable[[str], None]


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _owner_directory_valid(metadata: os.stat_result) -> bool:
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _read_canonical_git_file(
    git_descriptor: int, relative_path: str, *, maximum_bytes: int
) -> bytes | None:
    """Read a ref through owner-safe no-follow openat traversal."""

    parts = Path(relative_path).parts
    if (
        not parts
        or Path(relative_path).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID")
    directory_descriptor = os.dup(git_descriptor)
    opened_directories: list[int] = [directory_descriptor]
    descriptor = -1
    try:
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        for component in parts[:-1]:
            try:
                child = os.open(component, directory_flags, dir_fd=directory_descriptor)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID") from exc
            descriptor_metadata = os.fstat(child)
            path_metadata = os.stat(
                component, dir_fd=directory_descriptor, follow_symlinks=False
            )
            if (
                not _owner_directory_valid(descriptor_metadata)
                or _metadata_identity(descriptor_metadata)
                != _metadata_identity(path_metadata)
            ):
                os.close(child)
                raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID")
            directory_descriptor = child
            opened_directories.append(child)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(parts[-1], flags, dir_fd=directory_descriptor)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID") from exc
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID")
        chunks = []
        remaining = int(before.st_size) + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        try:
            path_metadata = os.stat(
                parts[-1], dir_fd=directory_descriptor, follow_symlinks=False
            )
        except OSError as exc:
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID") from exc
        raw = b"".join(chunks)
        if (
            len(raw) != int(before.st_size)
            or _metadata_identity(after) != _metadata_identity(before)
            or _metadata_identity(path_metadata) != _metadata_identity(before)
        ):
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for opened in reversed(opened_directories):
            os.close(opened)


def read_canonical_local_main(repository: str) -> str:
    """Read the canonical checkout's remote-main ref without Git or network."""

    checkout = expected_canonical_checkout(repository, Path("/home/ubuntu/code"))
    if checkout is None:
        raise PortfolioConvergenceError("CANONICAL_REPOSITORY_UNSUPPORTED")
    git_marker = checkout / ".git"
    try:
        marker_metadata = git_marker.lstat()
    except FileNotFoundError as exc:
        raise PortfolioConvergenceError("CANONICAL_MAIN_REF_MISSING") from exc
    if stat.S_ISDIR(marker_metadata.st_mode) and not git_marker.is_symlink():
        pass
    elif stat.S_ISREG(marker_metadata.st_mode):
        # Canonical repositories must be full owner checkouts.  Worktree
        # indirection can escape the repository policy and its commondir.
        raise PortfolioConvergenceError("CANONICAL_CHECKOUT_WORKTREE_FORBIDDEN")
    else:
        raise PortfolioConvergenceError("CANONICAL_MAIN_REF_MISSING")
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    checkout_descriptor = -1
    git_descriptor = -1
    try:
        checkout_descriptor = os.open(checkout, directory_flags)
        checkout_metadata = os.fstat(checkout_descriptor)
        checkout_path_metadata = checkout.lstat()
        if (
            not _owner_directory_valid(checkout_metadata)
            or _metadata_identity(checkout_metadata)
            != _metadata_identity(checkout_path_metadata)
        ):
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID")
        git_descriptor = os.open(".git", directory_flags, dir_fd=checkout_descriptor)
        git_metadata = os.fstat(git_descriptor)
        git_path_metadata = os.stat(
            ".git", dir_fd=checkout_descriptor, follow_symlinks=False
        )
        if (
            not _owner_directory_valid(git_metadata)
            or _metadata_identity(git_metadata) != _metadata_identity(git_path_metadata)
        ):
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID")
        ref_name = "refs/remotes/origin/main"
        sha: str | None = None
        loose_raw = _read_canonical_git_file(
            git_descriptor, ref_name, maximum_bytes=256
        )
        if loose_raw is not None:
            try:
                sha = loose_raw.decode("ascii").strip()
            except UnicodeError as exc:
                raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID") from exc
        else:
            packed_raw = _read_canonical_git_file(
                git_descriptor, "packed-refs", maximum_bytes=8 * 1024 * 1024
            )
            if packed_raw is None:
                raise PortfolioConvergenceError("CANONICAL_MAIN_REF_MISSING")
            try:
                lines = packed_raw.decode("ascii").splitlines()
            except UnicodeError as exc:
                raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID") from exc
            for line in lines:
                if line and not line.startswith(("#", "^")):
                    value, _, name = line.partition(" ")
                    if name == ref_name:
                        sha = value
                        break
            if _read_canonical_git_file(
                git_descriptor, ref_name, maximum_bytes=256
            ) is not None:
                raise PortfolioConvergenceError("CANONICAL_MAIN_REF_CHANGED")
        if sha is None or not GIT_SHA.fullmatch(sha):
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID")
        if (
            _metadata_identity(os.fstat(git_descriptor))
            != _metadata_identity(
                os.stat(".git", dir_fd=checkout_descriptor, follow_symlinks=False)
            )
            or _metadata_identity(os.fstat(checkout_descriptor))
            != _metadata_identity(checkout.lstat())
        ):
            raise PortfolioConvergenceError("CANONICAL_MAIN_REF_CHANGED")
        return sha
    except FileNotFoundError as exc:
        raise PortfolioConvergenceError("CANONICAL_MAIN_REF_MISSING") from exc
    except OSError as exc:
        raise PortfolioConvergenceError("CANONICAL_MAIN_REF_INVALID") from exc
    finally:
        if git_descriptor >= 0:
            os.close(git_descriptor)
        if checkout_descriptor >= 0:
            os.close(checkout_descriptor)


def _retry_seconds(attempts: int) -> int:
    return min(
        RETRY_BASE_SECONDS * (2 ** max(0, attempts - 1)), MAX_RETRY_SECONDS
    )


def _timestamp_after(timestamp: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (parsed + timedelta(seconds=seconds)).astimezone(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


class PortfolioConvergence:
    """Linearize one release event with pointer audit, scheduling, and admission."""

    def __init__(
        self,
        store: CoordinationStore,
        *,
        external_reader: ExternalReader | None = None,
        canonical_main_reader: CanonicalMainReader | None = None,
        failpoint: Failpoint | None = None,
    ) -> None:
        self.store = store
        self.external_reader = external_reader or self._read_external_context
        self.canonical_main_reader = canonical_main_reader or read_canonical_local_main
        self.failpoint = failpoint
        ensure_pull_buffer_schema(self.store.connection)

    def _read_external_context(self, event: dict[str, Any]) -> dict[str, Any]:
        """Read cursor and immutable candidate bytes before BEGIN IMMEDIATE."""

        if self.store.connection.in_transaction:
            raise PortfolioConvergenceError("EXTERNAL_READ_UNDER_WRITE_LOCK")
        return {
            "candidate_observations": load_candidate_packets(
                self.store.connection,
                event["repository"],
                database=self.store.path,
                keep_descriptors=True,
            ),
        }

    def _next_event(
        self, now: str, repository: str | None = None
    ) -> dict[str, Any] | None:
        query = (
            "SELECT * FROM portfolio_dirty_events "
            "WHERE state IN ('PENDING','RETRY') AND next_attempt_at<=?"
        )
        parameters: list[Any] = [now]
        if repository is not None:
            query += " AND repository=?"
            parameters.append(repository)
        query += " ORDER BY id LIMIT 1"
        row = self.store.connection.execute(query, parameters).fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _validate_event(row: sqlite3.Row, expected: dict[str, Any]) -> dict[str, Any]:
        if int(row["id"]) != int(expected["id"]):
            raise PortfolioConvergenceError("PORTFOLIO_EVENT_FENCE_LOST")
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError as exc:
            raise PortfolioConvergenceError("PORTFOLIO_EVENT_PAYLOAD_INVALID") from exc
        if (
            digest_json(payload) != row["event_sha256"]
            or row["event_sha256"] != expected["event_sha256"]
            or row["payload_json"] != expected["payload_json"]
            or payload.get("repository") != row["repository"]
            or payload.get("issue_number") != int(row["issue_number"])
            or payload.get("release_item_version")
            != int(row["release_item_version"])
            or payload.get("release_source_sha256")
            != row["release_source_sha256"]
        ):
            raise PortfolioConvergenceError("PORTFOLIO_EVENT_PAYLOAD_MISMATCH")
        return payload

    def _complete_event(
        self,
        row: sqlite3.Row,
        result: dict[str, Any],
        *,
        now: str,
    ) -> None:
        result_json = canonical_json(result)
        result_sha256 = digest_json(result)
        cursor = self.store.connection.execute(
            """
            UPDATE portfolio_dirty_events
            SET state='COMPLETE', attempts=attempts+1, result_sha256=?,
                result_json=?, updated_at=?, last_error=NULL
            WHERE id=? AND event_sha256=? AND state IN ('PENDING','RETRY')
            """,
            (result_sha256, result_json, now, row["id"], row["event_sha256"]),
        )
        if cursor.rowcount != 1:
            raise PortfolioConvergenceError("PORTFOLIO_EVENT_FENCE_LOST")
        self.store._event(
            "PORTFOLIO_CONVERGED",
            row["event_key"],
            {"result_sha256": result_sha256, "outcome": result["outcome"]},
            now,
        )

    def _defer_event(
        self,
        row: sqlite3.Row,
        result: dict[str, Any],
        *,
        now: str,
    ) -> str:
        attempts = int(row["attempts"]) + 1
        state = "HOLD" if attempts >= MAX_ATTEMPTS else "RETRY"
        next_attempt = _timestamp_after(now, _retry_seconds(attempts))
        result_json = canonical_json(result)
        result_sha256 = digest_json(result)
        cursor = self.store.connection.execute(
            """
            UPDATE portfolio_dirty_events
            SET state=?, attempts=?, next_attempt_at=?, result_sha256=?,
                result_json=?, updated_at=?, last_error=?
            WHERE id=? AND event_sha256=? AND state IN ('PENDING','RETRY')
            """,
            (
                state,
                attempts,
                next_attempt,
                result_sha256,
                result_json,
                now,
                ",".join(result["blockers"]),
                row["id"],
                row["event_sha256"],
            ),
        )
        if cursor.rowcount != 1:
            raise PortfolioConvergenceError("PORTFOLIO_EVENT_FENCE_LOST")
        self.store._event(
            "PORTFOLIO_CONVERGENCE_DEFICIT"
            if state == "RETRY"
            else "PORTFOLIO_CONVERGENCE_HOLD",
            row["event_key"],
            {
                "attempts": attempts,
                "result_sha256": result_sha256,
                "blockers": result["blockers"],
            },
            now,
        )
        return state

    def _record_retry(self, expected: dict[str, Any], error: str, now: str) -> dict[str, Any]:
        with self.store.transaction():
            row = self.store.connection.execute(
                "SELECT * FROM portfolio_dirty_events WHERE id=?", (expected["id"],)
            ).fetchone()
            if row is None or row["state"] == "COMPLETE":
                return {"state": "ALREADY_COMPLETE", "event_id": int(expected["id"])}
            if row["event_sha256"] != expected["event_sha256"]:
                raise PortfolioConvergenceError("PORTFOLIO_EVENT_FENCE_LOST")
            attempts = int(row["attempts"]) + 1
            state = "HOLD" if attempts >= MAX_ATTEMPTS else "RETRY"
            next_attempt = _timestamp_after(now, _retry_seconds(attempts))
            self.store.connection.execute(
                """
                UPDATE portfolio_dirty_events
                SET state=?, attempts=?, next_attempt_at=?, updated_at=?, last_error=?
                WHERE id=? AND event_sha256=? AND state IN ('PENDING','RETRY','HOLD')
                """,
                (state, attempts, next_attempt, now, error, row["id"], row["event_sha256"]),
            )
            self.store._event(
                "PORTFOLIO_CONVERGENCE_RETRY" if state == "RETRY" else "PORTFOLIO_CONVERGENCE_HOLD",
                row["event_key"],
                {"attempts": attempts, "error": error},
                now,
            )
        return {
            "state": state,
            "event_id": int(expected["id"]),
            "attempts": attempts,
            "next_attempt_at": next_attempt,
            "error": error,
        }

    def _admission_blocker(
        self,
        admission: Any,
        *,
        candidate: dict[str, Any],
        observed_main_sha: str,
        observation: dict[str, Any] | None,
    ) -> str | None:
        return admission_binding_error(
            admission,
            candidate=candidate,
            observed_main_sha=observed_main_sha,
            observation=observation,
            connection=self.store.connection,
        )

    @staticmethod
    def _trigger_result_fields(
        row: sqlite3.Row, payload: dict[str, Any]
    ) -> dict[str, Any]:
        trigger_kind = payload.get("trigger_kind", "CAPACITY_RELEASE")
        is_release = trigger_kind == "CAPACITY_RELEASE"
        return {
            "trigger_kind": trigger_kind,
            "trigger_issue_number": (
                None
                if trigger_kind in {"MAIN_CURSOR_ADVANCED", "CAPACITY_POLICY_CHANGED"}
                else int(row["issue_number"])
            ),
            "released_issue_number": int(row["issue_number"]) if is_release else None,
            "released_item_version": (
                int(row["release_item_version"]) if is_release else None
            ),
        }

    def consume_one(
        self,
        now: str | None = None,
        *,
        repository: str | None = None,
    ) -> dict[str, Any]:
        observed_at = now or utc_now()
        expected = self._next_event(observed_at, repository)
        if expected is None:
            return {"state": "IDLE"}

        observations: dict[int, dict[str, Any]] = {}
        try:
            canonical_main_before = self.canonical_main_reader(expected["repository"])
            if not isinstance(canonical_main_before, str) or not GIT_SHA.fullmatch(
                canonical_main_before
            ):
                raise PortfolioConvergenceError("CANONICAL_MAIN_INVALID")
            external = self.external_reader(expected)
            if not isinstance(external, dict):
                raise PortfolioConvergenceError("EXTERNAL_CONTEXT_INVALID")
            observations = external.get("candidate_observations")
            if observations is None:
                observations = load_candidate_packets(
                    self.store.connection,
                    expected["repository"],
                    database=self.store.path,
                    keep_descriptors=True,
                )
            if not isinstance(observations, dict):
                raise PortfolioConvergenceError("CANDIDATE_OBSERVATIONS_INVALID")
            observed_main_sha = self.canonical_main_reader(expected["repository"])
            if observed_main_sha != canonical_main_before:
                raise PortfolioConvergenceError("CANONICAL_MAIN_CHANGED_DURING_READ")

            with self.store.transaction():
                row = self.store.connection.execute(
                    "SELECT * FROM portfolio_dirty_events WHERE id=?",
                    (expected["id"],),
                ).fetchone()
                if (
                    row is None
                    or row["state"] not in {"PENDING", "RETRY"}
                    or row["next_attempt_at"] > observed_at
                ):
                    return {"state": "FENCED", "event_id": int(expected["id"])}
                payload = self._validate_event(row, expected)
                trigger_kind = payload.get("trigger_kind", "CAPACITY_RELEASE")
                released = None
                if trigger_kind == "CAPACITY_RELEASE":
                    released = self.store.connection.execute(
                        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                        (row["repository"], row["issue_number"]),
                    ).fetchone()
                if trigger_kind == "CAPACITY_RELEASE" and (
                    released is None
                    or int(released["version"]) < int(row["release_item_version"])
                    or released["allocation_class"] != "NONE"
                    or released["status"] != "DONE"
                ):
                    result = {
                        "event_sha256": row["event_sha256"],
                        "outcome": "NO_ADMISSION",
                        "blockers": ["RELEASE_ITEM_DRIFT"],
                        **self._trigger_result_fields(row, payload),
                        "admitted_issue_number": None,
                        "message_id": None,
                        "wip_delta": {"development": 0, "shared": 0, "sre": 0},
                    }
                    self._complete_event(row, result, now=observed_at)
                    return {"state": "COMPLETE", "event_id": int(row["id"]), **result}

                release_source = (
                    self.store.current_snapshot(
                        row["repository"], "issue", int(row["issue_number"])
                    )
                    if trigger_kind == "CAPACITY_RELEASE"
                    else None
                )
                if trigger_kind == "CAPACITY_RELEASE" and (
                    release_source is None
                    or release_source.payload_sha256
                    != released["source_payload_sha256"]
                ):
                    result = {
                        "event_sha256": row["event_sha256"],
                        "outcome": "NO_ADMISSION",
                        "blockers": ["RELEASE_SOURCE_DRIFT"],
                        **self._trigger_result_fields(row, payload),
                        "admitted_issue_number": None,
                        "message_id": None,
                        "wip_delta": {"development": 0, "shared": 0, "sre": 0},
                    }
                    state = self._defer_event(row, result, now=observed_at)
                    return {"state": state, "event_id": int(row["id"]), **result}

                current = self.store.connection.execute(
                    "SELECT observed_main_sha FROM portfolio_graph_current WHERE repository=?",
                    (row["repository"],),
                ).fetchone()
                if current is None:
                    raise PortfolioConvergenceError("GRAPH_NOT_FOUND")
                if current["observed_main_sha"] != observed_main_sha:
                    raise PortfolioConvergenceError(
                        "CANONICAL_MAIN_PROVIDER_CURSOR_DRIFT"
                    )

                audit = audit_pull_buffer(
                    self.store.connection,
                    row["repository"],
                    record=True,
                    now=observed_at,
                    database=self.store.path,
                    artifact_observations=observations,
                    store=self.store,
                    _transaction=False,
                    _ensure_schema=False,
                )
                graph = self.store.connection.execute(
                    "SELECT health, last_error FROM portfolio_graph_current WHERE repository=?",
                    (row["repository"],),
                ).fetchone()
                decision: dict[str, Any] | None = None
                if graph["health"] == "CURRENT":
                    decision = _schedule_decision(
                        self.store.connection,
                        row["repository"],
                        current_main=observed_main_sha,
                        record=True,
                        now=observed_at,
                    )

                selected_node_keys = set((decision or {}).get("selected", []))
                candidates = self.store.connection.execute(
                    """
                    SELECT c.*, n.node_key
                    FROM portfolio_pull_buffer_current pointer
                    JOIN portfolio_pull_buffer_candidates c ON c.id=pointer.candidate_id
                    JOIN portfolio_graph_nodes n
                      ON n.repository=c.repository
                     AND n.graph_version=c.graph_version
                     AND n.issue_number=c.issue_number
                    WHERE pointer.repository=? AND c.state='READY'
                    ORDER BY n.priority_rank, n.lane_order, n.ready_at, c.issue_number
                    """,
                    (row["repository"],),
                ).fetchall()
                chosen: tuple[sqlite3.Row, dict[str, Any]] | None = None
                admission_blockers: list[str] = []
                for candidate_row in candidates:
                    if candidate_row["node_key"] not in selected_node_keys:
                        continue
                    observation = observations.get(int(candidate_row["id"]), {})
                    packet = observation.get("packet")
                    candidate = dict(candidate_row)
                    admission = (
                        packet.get("admission_transaction")
                        if isinstance(packet, dict)
                        else None
                    )
                    blocker = self._admission_blocker(
                        admission,
                        candidate=candidate,
                        observed_main_sha=observed_main_sha,
                        observation=observation,
                    )
                    if blocker is not None:
                        admission_blockers.append(
                            f"{blocker}:issue:{int(candidate_row['issue_number'])}"
                        )
                        continue
                    chosen = (candidate_row, admission)
                    break

                if chosen is None:
                    blockers: list[str] = []
                    if graph["health"] != "CURRENT":
                        blockers.append(str(graph["last_error"] or "GRAPH_STALE"))
                    blockers.extend(audit["deficit_reasons"])
                    blockers.extend(
                        f"{reason}:issue:{item['issue_number']}"
                        for item in audit["invalid"]
                        for reason in item["reasons"]
                    )
                    blockers.extend(admission_blockers)
                    if (
                        audit["executable_ready_depth"] > 0
                        and audit["dispatchable_now_depth"] == 0
                    ):
                        blockers.append("NO_DISPATCHABLE_READY")
                    if decision is not None:
                        blockers.extend(
                            f"{item['reason']}:{item['node_key']}"
                            for item in decision["skipped"]
                        )
                    if not blockers:
                        blockers.append("NO_SAFE_READY_CANDIDATE")
                    result = {
                        "event_sha256": row["event_sha256"],
                        "outcome": "NO_ADMISSION",
                        "blockers": sorted(set(blockers)),
                        **self._trigger_result_fields(row, payload),
                        "admitted_issue_number": None,
                        "message_id": None,
                        "wip_delta": {"development": 0, "shared": 0, "sre": 0},
                        "pull_buffer": {
                            key: audit[key]
                            for key in (
                                "reviewed_candidate_depth",
                                "prepared_or_queued_depth",
                                "executable_ready_depth",
                                "dispatchable_now_depth",
                            )
                        },
                    }
                    state = self._defer_event(row, result, now=observed_at)
                    return {"state": state, "event_id": int(row["id"]), **result}

                candidate_row, admission = chosen
                activated, message_id = self.store.activate_admission(
                    item=admission["item"],
                    message=admission["message"],
                    artifacts=admission.get("artifacts"),
                    artifact_observations=observations.get(
                        int(candidate_row["id"]), {}
                    ).get("admission_artifacts"),
                    now=observed_at,
                    _transaction=False,
                )
                if self.failpoint is not None:
                    self.failpoint("after_activation_before_main_fence")
                _retire_pointer(
                    self.store.connection,
                    repository=row["repository"],
                    issue_number=int(candidate_row["issue_number"]),
                    candidate_id=int(candidate_row["id"]),
                    reasons=["ADMITTED"],
                    now=observed_at,
                )
                if self.failpoint is not None:
                    self.failpoint("before_event_complete")
                result = {
                    "event_sha256": row["event_sha256"],
                    "outcome": "ADMITTED",
                    "blockers": [],
                    **self._trigger_result_fields(row, payload),
                    "admitted_issue_number": int(activated["issue_number"]),
                    "admitted_item_version": int(activated["version"]),
                    "message_id": int(message_id),
                    "wip_delta": {
                        "development": int(admission["item"]["development_units"]),
                        "shared": int(admission["item"]["shared_units"]),
                        "sre": int(admission["item"]["sre_units"]),
                    },
                }
                self._complete_event(row, result, now=observed_at)
                final_main = self.canonical_main_reader(row["repository"])
                if final_main != observed_main_sha:
                    raise PortfolioConvergenceError(
                        "CANONICAL_MAIN_CHANGED_BEFORE_ADMISSION_COMMIT"
                    )
            return {"state": "COMPLETE", "event_id": int(expected["id"]), **result}
        except (
            CoordinationError,
            PortfolioConvergenceError,
            PortfolioGraphError,
            PullBufferError,
            OSError,
            RuntimeError,
            sqlite3.Error,
            ValueError,
        ) as exc:
            error = str(exc) or type(exc).__name__
            return self._record_retry(expected, error, observed_at)
        finally:
            close_candidate_observations(observations)

    def consume_due(
        self,
        *,
        limit: int = 1,
        now: str | None = None,
        repository: str | None = None,
    ) -> list[dict[str, Any]]:
        if limit <= 0 or limit > MAX_CONVERGENCE_LIMIT:
            raise PortfolioConvergenceError("CONVERGENCE_LIMIT_INVALID")
        results: list[dict[str, Any]] = []
        observed_at = now or utc_now()
        for _ in range(limit):
            result = self.consume_one(observed_at, repository=repository)
            if result["state"] == "IDLE":
                break
            results.append(result)
        return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository")
    parser.add_argument("--limit", type=int, default=1)
    args = parser.parse_args()
    store = CoordinationStore(DEFAULT_DATABASE)
    try:
        results = PortfolioConvergence(store).consume_due(
            limit=args.limit, repository=args.repository
        )
        print(canonical_json({"phase": "COMPLETE", "results": results}))
        return 0
    except (PortfolioConvergenceError, CoordinationError, sqlite3.Error) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
