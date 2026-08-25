from __future__ import annotations

from pathlib import Path
import json
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
)
from coordination_supervisor import (  # noqa: E402
    CoordinationSupervisor,
    _canonical_session_command,
    launch_canonical_session,
    launch_terminal_watch_session,
)
from executor_registry import (  # noqa: E402
    AttemptLineage,
    load_registry_config,
    reserve_attempt,
    stable_systemd_unit,
)
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)


ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT_SESSION = "role.development.v4"
PLANNER_SESSION = "role.planner.v2"
SRE_SESSION = "role.sre.v4"


REPOSITORY = "twinfinityai/twinfinityapp"
LEASE = "5" * 64
NONCANONICAL_SESSION = "01a00000-0000-7000-8000-000000000001"


class CoordinationSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name) / "coordinator"
        directory.mkdir(mode=0o700)
        self.store = CoordinationStore(directory / "state.sqlite3")
        config = load_registry_config(
            ROOT / "references" / "twinfinity-executor-registry.toml"
        )
        aliases, alias_sha = load_legacy_alias_fixture(
            ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="coordination-supervisor-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-22T09:59:59Z",
        )
        self.launches: list[tuple[str, int]] = []
        self.terminal_watch_launches: list[tuple[str, str]] = []

        def launcher(session_id: str, message_id: int) -> int:
            self.launches.append((session_id, message_id))
            return 1000 + len(self.launches)

        def terminal_watch_launcher(session_id: str, watch_key: str) -> int:
            self.terminal_watch_launches.append((session_id, watch_key))
            return 2000 + len(self.terminal_watch_launches)

        self.supervisor = CoordinationSupervisor(
            self.store,
            launcher=launcher,
            terminal_watch_launcher=terminal_watch_launcher,
            process_checker=lambda *_: False,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def snapshot(self):
        return self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={"number": 92, "title": "Issue 92"},
            source_updated_at="2026-08-22T10:00:00Z",
            fetched_at="2026-08-22T10:00:01Z",
        )

    def claimed_admission(self) -> tuple[object, int]:
        source = self.snapshot()
        active = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE_FENCED",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        message_id = self.store.enqueue_message(
            idempotency_key="claimed-admission",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="development.admission",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "issue_number": 92,
                "generation": 1,
                "item_version": active["version"],
                "action": "CREATE_LOCAL_BRANCH_AND_WORKTREE_THEN_CONTINUE",
                "base_sha": "a" * 40,
                "branch": "codex/92-claimed-retry",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
                "opaque_worktree_id": "twinfinityapp-issue-92",
                "accountable_session_id": DEVELOPMENT_SESSION,
                "lease_manifest_sha256": LEASE,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 1,
                    "sre_units": 0,
                },
            },
            now="2026-08-22T10:00:03Z",
        )
        self.store.claim_message(
            message_id, DEVELOPMENT_SESSION, "2026-08-22T10:00:04Z"
        )
        return source, message_id

    def test_claimed_valid_message_retries_with_backoff(self) -> None:
        _source, message_id = self.claimed_admission()

        first = self.supervisor.run_once("2026-08-22T10:00:05Z")
        early = self.supervisor.run_once("2026-08-22T10:00:30Z")
        retry = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual(1, len(first["launched"]))
        self.assertEqual([], early["launched"])
        self.assertEqual(1, len(retry["launched"]))
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state, attempts FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("CLAIMED", None), tuple(observed))
        self.assertEqual(("INFLIGHT", 2), tuple(wake))

    def test_claimed_retry_backoff_does_not_block_a_different_target(self) -> None:
        source, message_id = self.claimed_admission()
        first = self.supervisor.run_once("2026-08-22T10:00:05Z")
        newer_id = self.store.enqueue_message(
            idempotency_key="newer-same-recipient",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Different target remains schedulable",
                "summary": "The claimed admission backoff applies only to its exact target.",
                "evidence": {"predecessor_message_id": message_id},
            },
            now="2026-08-22T10:00:06Z",
        )

        cooling_down = self.supervisor.run_once("2026-08-22T10:00:30Z")

        self.assertEqual(1, len(first["launched"]))
        self.assertEqual(1, len(cooling_down["launched"]))
        self.assertEqual(
            [(DEVELOPMENT_SESSION, message_id), (DEVELOPMENT_SESSION, newer_id)],
            self.launches,
        )
        newer_wakes = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?", (newer_id,)
        ).fetchone()[0]
        self.assertEqual(1, newer_wakes)

    def test_claimed_source_drift_holds_message_and_terminates_wake(self) -> None:
        _source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={"number": 92, "title": "Changed after claim"},
            source_updated_at="2026-08-22T10:01:00Z",
            fetched_at="2026-08-22T10:01:01Z",
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(observed))
        self.assertEqual("COMPLETE", wake["state"])

    def test_claimed_item_drift_holds_message_and_terminates_wake(self) -> None:
        source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        active = self.store.connection.execute(
            "SELECT version FROM coordination_items WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:01:00Z",
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "MESSAGE_ITEM_STATE_MISMATCH"), tuple(observed))
        self.assertEqual("COMPLETE", wake["state"])

    def test_claimed_schema_valid_payload_drift_holds_message_and_terminates_wake(self) -> None:
        _source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        self.store.connection.execute(
            "DROP TRIGGER coordination_message_envelope_immutable"
        )
        row = self.store.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["base_sha"] = "b" * 40
        self.store.connection.execute(
            "UPDATE coordination_messages SET payload_json=? WHERE id=?",
            (canonical_json(payload), message_id),
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "MESSAGE_PAYLOAD_MISMATCH"), tuple(observed))
        self.assertEqual("COMPLETE", wake["state"])

    def test_claimed_retry_rejects_payload_and_digest_rebinding(self) -> None:
        _source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        self.store.connection.execute(
            "DROP TRIGGER coordination_message_envelope_immutable"
        )
        row = self.store.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["base_sha"] = "b" * 40
        self.store.connection.execute(
            "UPDATE coordination_messages SET payload_json=?, payload_sha256=? WHERE id=?",
            (canonical_json(payload), digest_json(payload), message_id),
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "MESSAGE_PAYLOAD_MISMATCH"), tuple(observed))
        self.assertEqual(
            ("COMPLETE", "MESSAGE_PAYLOAD_MISMATCH"), tuple(wake)
        )

    def test_claimed_envelope_cannot_rebind_before_first_wake(self) -> None:
        _source, message_id = self.claimed_admission()
        row = self.store.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["base_sha"] = "b" * 40

        with self.assertRaisesRegex(sqlite3.IntegrityError, "MESSAGE_ENVELOPE_IMMUTABLE"):
            self.store.connection.execute(
                "UPDATE coordination_messages SET payload_json=?, payload_sha256=? WHERE id=?",
                (canonical_json(payload), digest_json(payload), message_id),
            )

        result = self.supervisor.run_once("2026-08-22T10:00:05Z")
        observed = self.store.connection.execute(
            "SELECT state, payload_json FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(1, len(result["launched"]))
        self.assertEqual("CLAIMED", observed["state"])
        self.assertEqual("a" * 40, json.loads(observed["payload_json"])["base_sha"])

    def test_prepared_message_wake_is_idempotent_with_bounded_retry(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="prepared-status",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A new local status is available.",
                "evidence": {"item_version": 1},
            },
            now="2026-08-22T10:00:02Z",
        )

        first = self.supervisor.run_once("2026-08-22T10:00:03Z")
        second = self.supervisor.run_once("2026-08-22T10:00:30Z")
        third = self.supervisor.run_once("2026-08-22T10:01:04Z")

        self.assertEqual([(DEVELOPMENT_SESSION, message_id)], self.launches[:1])
        self.assertEqual(1, len(first["launched"]))
        self.assertEqual([], second["launched"])
        self.assertEqual(1, len(third["launched"]))
        wake = self.store.connection.execute(
            "SELECT state, attempts FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:prepared",),
        ).fetchone()
        self.assertEqual(("INFLIGHT", 2), tuple(wake))

    def test_launch_failures_retry_with_capped_backoff_without_orphaning_inbox(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="prepared-launch-retry",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A valid local inbox row remains available.",
                "evidence": {"item_version": 1},
            },
            now="2026-08-22T10:00:02Z",
        )
        failures: list[tuple[str, int]] = []

        def failing_launcher(session_id: str, candidate_message_id: int) -> int:
            failures.append((session_id, candidate_message_id))
            raise OSError("launch failed")

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=failing_launcher,
            terminal_watch_launcher=lambda _session, _key: 1,
            process_checker=lambda *_: False,
        )
        for timestamp in (
            "2026-08-22T10:00:03Z",
            "2026-08-22T10:01:04Z",
            "2026-08-22T10:03:05Z",
            "2026-08-22T10:07:06Z",
            "2026-08-22T10:15:07Z",
            "2026-08-22T10:30:08Z",
        ):
            supervisor.run_once(timestamp)

        wake = self.store.connection.execute(
            "SELECT state, attempts, process_id, last_error "
            "FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:prepared",),
        ).fetchone()
        message = self.store.connection.execute(
            "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        self.assertEqual(6, len(failures))
        self.assertEqual(
            ("INFLIGHT", 6, None, "WAKE_LAUNCH_FAILED"), tuple(wake)
        )
        self.assertEqual("PREPARED", message["state"])

    def test_capacity_release_consumes_dirty_event_without_planner_notice(self) -> None:
        source = self.snapshot()
        active = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.supervisor.run_once("2026-08-22T10:00:03Z")
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:04Z",
        )

        result = self.supervisor.run_once("2026-08-22T10:00:05Z")
        repeated = self.supervisor.run_once("2026-08-22T10:00:06Z")

        self.assertEqual("RETRY", result["portfolio_convergence"][0]["state"])
        self.assertEqual([], self.launches)
        self.assertEqual([], repeated["portfolio_convergence"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages WHERE idempotency_key LIKE 'supervisor-capacity-release:%'"
            ).fetchone()[0],
        )

    def test_missing_active_terminal_watch_is_backfilled_and_wakes_owner(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.store.connection.execute("DELETE FROM coordination_terminal_watches")

        result = self.supervisor.run_once("2026-08-22T10:01:03Z")

        key = f"terminal:{REPOSITORY}:issue:92:generation:1"
        self.assertEqual([key], result["opened_terminal_watches"])
        self.assertEqual([(DEVELOPMENT_SESSION, key)], self.terminal_watch_launches)
        watch = self.store.connection.execute(
            "SELECT state, attempts, process_id FROM coordination_terminal_watches WHERE watch_key=?",
            (key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", 1, 2001), tuple(watch))

    def test_active_message_lineage_suppresses_duplicate_terminal_watch_launch(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key="already-running-lineage",
            now="2026-08-22T10:00:03Z",
            precondition=lambda _connection: AttemptLineage(
                REPOSITORY, 92, 1, LEASE
            ),
        )

        result = self.supervisor.run_once("2026-08-22T10:01:03Z")

        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:1"
        self.assertEqual([], result["opened_terminal_watches"])
        self.assertEqual([], result["terminal_watch_launches"])
        self.assertEqual([], self.terminal_watch_launches)
        watch = self.store.connection.execute(
            "SELECT state,attempts,process_id FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", 0, None), tuple(watch))

    def test_running_exact_target_suppresses_terminal_watch_wake(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        running = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
            terminal_watch_launcher=lambda session, key: self.terminal_watch_launches.append((session, key)) or 2,
            process_checker=lambda session, kind, key: (
                session == DEVELOPMENT_SESSION and kind == "terminal_watch"
            ),
        )

        result = running.run_once("2026-08-22T10:01:03Z")

        self.assertEqual([], result["terminal_watch_launches"])
        self.assertEqual([], self.terminal_watch_launches)

    def test_recovery_reopen_closes_message_wake_and_resumes_terminal_wake(self) -> None:
        source = self.snapshot()
        active = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=2,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:00Z",
        )
        held = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=2,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:01Z",
        )
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 2,
            "item_version": held["version"],
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": DEVELOPMENT_SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
        }
        prepare = self.store.enqueue_message(
            idempotency_key="supervisor-recovery-prepare",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:02Z",
        )
        self.store.claim_message(
            prepare, DEVELOPMENT_SESSION, "2026-08-22T10:00:03Z"
        )
        self.store.complete_message(
            prepare, DEVELOPMENT_SESSION, "2026-08-22T10:00:04Z"
        )
        commit = self.store.enqueue_message(
            idempotency_key="supervisor-recovery-commit",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:05Z",
        )
        self.store.claim_message(
            commit, DEVELOPMENT_SESSION, "2026-08-22T10:00:06Z"
        )
        message_launch = self.supervisor.run_once("2026-08-22T10:00:07Z")
        self.assertEqual(1, len(message_launch["launched"]))

        self.store.activate_recovery(
            message_id=commit,
            session_id=DEVELOPMENT_SESSION,
            now="2026-08-22T10:00:08Z",
        )
        running = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
            terminal_watch_launcher=lambda session, key: self.terminal_watch_launches.append((session, key)) or 2,
            process_checker=lambda session, kind, key: (
                session == DEVELOPMENT_SESSION and kind == "terminal_watch"
            ),
        )
        while_running = running.run_once("2026-08-22T10:01:09Z")
        self.assertEqual([], while_running["launched"])
        self.assertEqual([], while_running["terminal_watch_launches"])
        message_wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{commit}:claimed",),
        ).fetchone()
        self.assertEqual("COMPLETE", message_wake["state"])

        after_exit = self.supervisor.run_once("2026-08-22T10:01:10Z")
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:2"
        self.assertEqual(
            [
                {
                    "watch_key": watch_key,
                    "recipient_session_id": DEVELOPMENT_SESSION,
                    "process_id": 2001,
                }
            ],
            after_exit["terminal_watch_launches"],
        )
        self.assertEqual([(DEVELOPMENT_SESSION, watch_key)], self.terminal_watch_launches)

    def test_terminal_item_transition_completes_watch(self) -> None:
        source = self.snapshot()
        active = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:03Z",
        )

        watch = self.store.connection.execute(
            "SELECT state FROM coordination_terminal_watches"
        ).fetchone()
        self.assertEqual("COMPLETE", watch["state"])

    def test_stale_prepared_message_is_held_without_wake(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="stale-status",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A local status was observed.",
                "evidence": {},
            },
            now="2026-08-22T10:00:02Z",
        )
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={"number": 92, "title": "Changed"},
            source_updated_at="2026-08-22T10:01:00Z",
            fetched_at="2026-08-22T10:01:01Z",
        )

        result = self.supervisor.run_once("2026-08-22T10:01:02Z")

        self.assertEqual([], result["launched"])
        self.assertEqual([], self.launches)
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(observed))

    def test_source_advance_between_scan_and_reservation_holds_without_wake(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="reservation-race-status",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A local status was observed.",
                "evidence": {},
            },
            now="2026-08-22T10:00:02Z",
        )
        reserve = self.supervisor._reserve_wake
        advanced = False

        def advance_then_reserve(row, now):
            nonlocal advanced
            if not advanced:
                advanced = True
                self.store.ingest_snapshot(
                    repository=REPOSITORY,
                    object_kind="issue",
                    object_number=92,
                    payload={"number": 92, "title": "Changed during scan"},
                    source_updated_at="2026-08-22T10:01:00Z",
                    fetched_at="2026-08-22T10:01:01Z",
                )
            return reserve(row, now)

        self.supervisor._reserve_wake = advance_then_reserve
        result = self.supervisor.run_once("2026-08-22T10:01:02Z")

        self.assertEqual([], result["launched"])
        self.assertEqual([], self.launches)
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(observed))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?", (message_id,)
            ).fetchone()[0],
        )

    def test_different_targets_for_one_role_are_scheduled_in_one_scan(self) -> None:
        source = self.snapshot()
        message_ids = []
        for suffix in ("first", "second"):
            message_ids.append(
                self.store.enqueue_message(
                    idempotency_key=f"two-row-{suffix}",
                    recipient_session_id=DEVELOPMENT_SESSION,
                    topic="coordination.notice",
                    payload={
                        "source": {
                            "repository": REPOSITORY,
                            "object_kind": "issue",
                            "object_number": 92,
                            "payload_sha256": source.payload_sha256,
                        },
                        "notice_kind": "status",
                        "mutation_authority": False,
                        "subject": f"Observed status {suffix}",
                        "summary": "A local status was observed.",
                        "evidence": {},
                    },
                    now="2026-08-22T10:00:02Z",
                )
            )

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual(
            [(DEVELOPMENT_SESSION, message_id) for message_id in message_ids],
            self.launches,
        )
        self.assertEqual(2, len(result["launched"]))
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE recipient_session_id=?",
                (DEVELOPMENT_SESSION,),
            ).fetchone()[0],
        )

    def test_disjoint_mixed_role_notices_launch_in_one_scan(self) -> None:
        source = self.snapshot()
        expected = []
        for recipient, suffix in (
            (DEVELOPMENT_SESSION, "development"),
            (SRE_SESSION, "sre"),
        ):
            message_id = self.store.enqueue_message(
                idempotency_key=f"mixed-role-{suffix}",
                recipient_session_id=recipient,
                topic="coordination.notice",
                payload={
                    "source": {
                        "repository": REPOSITORY,
                        "object_kind": "issue",
                        "object_number": 92,
                        "payload_sha256": source.payload_sha256,
                    },
                    "notice_kind": "status",
                    "mutation_authority": False,
                    "subject": f"{suffix} status",
                    "summary": "A nonmutating role-local observation is ready.",
                    "evidence": {},
                },
                now="2026-08-22T10:00:02Z",
            )
            expected.append((recipient, message_id))

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual(expected, self.launches)
        self.assertEqual(2, len(result["launched"]))

    def test_systemd_wake_unit_is_deterministic_per_target(self) -> None:
        with patch("coordination_supervisor.subprocess.run") as run:
            run.return_value.returncode = 0
            launch_canonical_session(DEVELOPMENT_SESSION, 11)
            launch_canonical_session(DEVELOPMENT_SESSION, 12)

        units = [
            next(argument for argument in call.args[0] if argument.startswith("--unit="))
            for call in run.call_args_list
        ]
        self.assertEqual(
            [
                f"--unit={stable_systemd_unit('development', 'message', key)}"
                for key in ("11", "12")
            ],
            units,
        )
        self.assertEqual(2, len(set(units)))
        self.assertTrue(all(len(unit.removeprefix("--unit=")) < 100 for unit in units))
        self.assertEqual(
            units[0],
            f"--unit={stable_systemd_unit('development', 'message', '11')}",
        )
        for key, call in zip(("11", "12"), run.call_args_list, strict=True):
            command = call.args[0]
            self.assertNotIn("--collect", command)
            self.assertIn("run_role_executor.py", " ".join(command))
            self.assertEqual(
                "development", command[command.index("--role") + 1]
            )
            self.assertEqual(
                DEVELOPMENT_SESSION,
                command[command.index("--endpoint-id") + 1],
            )
            self.assertEqual(
                stable_systemd_unit("development", "message", key),
                command[command.index("--systemd-unit") + 1],
            )
            self.assertNotIn("resume", command)

    def test_closed_canonical_command_requires_native_capability(self) -> None:
        prompt = "exact typed row"
        development = _canonical_session_command(DEVELOPMENT_SESSION, prompt)
        self.assertEqual("/usr/bin/python3", development[0])
        self.assertIn("run_role_executor.py", development[1])
        self.assertEqual("development", development[development.index("--role") + 1])
        self.assertEqual(
            DEVELOPMENT_SESSION,
            development[development.index("--endpoint-id") + 1],
        )
        self.assertEqual(prompt, development[-1])
        self.assertNotIn("resume", development)
        with self.assertRaisesRegex(CoordinationError, "NONCANONICAL_ROLE_ENDPOINT"):
            _canonical_session_command(NONCANONICAL_SESSION, prompt)

        with patch("coordination_supervisor.subprocess.run") as run:
            with self.assertRaisesRegex(
                CoordinationError, "NONCANONICAL_ROLE_ENDPOINT"
            ):
                launch_canonical_session(NONCANONICAL_SESSION, 7)
        run.assert_not_called()

    def test_terminal_watch_wake_is_outcome_oriented_not_one_gate_bounded(self) -> None:
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:3"
        with patch("coordination_supervisor.subprocess.run") as run:
            run.return_value.returncode = 0
            launch_terminal_watch_session(DEVELOPMENT_SESSION, watch_key)

        command = run.call_args.args[0]
        prompt = command[-1]
        self.assertIn(watch_key, prompt)
        self.assertIn("every immediately executable routine step", prompt)
        self.assertIn("merge, cleanup, and capacity release", prompt)
        self.assertIn("do not stop merely because one material gate passed", prompt)
        self.assertIn("genuine external wait or hard stop", prompt)
        self.assertNotIn("next material or terminal gate", prompt)

    def test_role_executor_profile_is_selected_by_strict_registry_config(self) -> None:
        with patch("coordination_supervisor.subprocess.run") as run:
            run.return_value.returncode = 0
            launch_canonical_session(PLANNER_SESSION, 21)
            launch_canonical_session(SRE_SESSION, 22)

        planner_command = run.call_args_list[0].args[0]
        sre_command = run.call_args_list[1].args[0]
        self.assertEqual("planner", planner_command[planner_command.index("--role") + 1])
        self.assertEqual(
            PLANNER_SESSION,
            planner_command[planner_command.index("--endpoint-id") + 1],
        )
        self.assertEqual(
            "sre",
            sre_command[sre_command.index("--role") + 1],
        )
        self.assertEqual(
            SRE_SESSION,
            sre_command[sre_command.index("--endpoint-id") + 1],
        )
        self.assertNotIn("resume", planner_command)
        self.assertNotIn("resume", sre_command)

    def test_wrong_role_prepared_and_claimed_rows_are_held_without_wake(self) -> None:
        now = "2026-08-22T10:00:02Z"
        for recipient in (
            DEVELOPMENT_SESSION,
            PLANNER_SESSION,
            NONCANONICAL_SESSION,
        ):
            for state in ("PREPARED", "CLAIMED"):
                self.store.connection.execute(
                    """
                    INSERT INTO coordination_messages(
                        idempotency_key, recipient_session_id, topic, payload_sha256,
                        payload_json, state, claimed_by, created_at, updated_at
                    ) VALUES (?, ?, 'sre.admission', ?, '{}', ?, ?, ?, ?)
                    """,
                    (
                        f"wrong-role-{recipient}-{state.lower()}",
                        recipient,
                        "0" * 64,
                        state,
                        recipient if state == "CLAIMED" else None,
                        now,
                        now,
                    ),
                )

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual([], result["launched"])
        self.assertEqual([], self.launches)
        rows = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE idempotency_key LIKE 'wrong-role-%' ORDER BY id",
        ).fetchall()
        self.assertEqual(
            [("HOLD", "MESSAGE_ROLE_MISMATCH")] * 6,
            [tuple(row) for row in rows],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                """
                SELECT COUNT(*) FROM coordination_wakes AS wakes
                JOIN coordination_messages AS messages ON messages.id=wakes.message_id
                WHERE messages.idempotency_key LIKE 'wrong-role-%'
                """
            ).fetchone()[0],
        )

    def test_artifact_filesystem_failure_does_not_block_session_wake(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="wake-despite-artifact-failure",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A local status remains available.",
                "evidence": {"item_version": 1},
            },
            now="2026-08-22T10:00:02Z",
        )
        with patch.object(
            self.store, "collect_artifacts", side_effect=OSError("filesystem")
        ):
            result = self.supervisor.run_once("2026-08-22T10:00:03Z")
        self.assertEqual("HOLD", result["artifact_gc"]["mode"])
        self.assertEqual("ARTIFACT_GC_FAILED", result["artifact_gc"]["error"])
        self.assertEqual([(DEVELOPMENT_SESSION, message_id)], self.launches)


if __name__ == "__main__":
    unittest.main()
