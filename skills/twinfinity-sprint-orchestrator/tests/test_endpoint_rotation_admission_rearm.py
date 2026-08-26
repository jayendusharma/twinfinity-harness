from __future__ import annotations

from dataclasses import replace
from contextlib import redirect_stdout
from pathlib import Path
import io
import json
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationError, CoordinationStore, digest_json  # noqa: E402
import coordination_store as coordination_store_module  # noqa: E402
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from delivery_guard import (  # noqa: E402
    GuardError,
    _message_context,
    _terminal_watch_context,
)
from executor_registry import (  # noqa: E402
    AttemptLineage,
    RegistryError,
    attempt_lineage_for_target,
    load_registry_config,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from prepush_control import PrePushControl, PrePushError  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from run_role_executor import _validate_target  # noqa: E402


REPOSITORY = "twinfinityai/twinfinityapp"
ISSUE = 328
GENERATION = 7
LEASE = "5" * 64
V3 = "role.development.v3"
V6 = "role.development.v6"


class EndpointRotationAdmissionRearmTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        temporary = Path(self.temp.name)
        coordination_root = temporary / "coordination"
        coordination_root.mkdir(mode=0o700)
        self.database = coordination_root / "state.sqlite3"
        self.store = CoordinationStore(self.database)

        installed = temporary / "installed"
        installed.mkdir()
        references = ROOT / "references"
        for profile in references.glob("*-v*.config.toml"):
            shutil.copy2(profile, installed / profile.name)
        self.v6_config = load_registry_config(
            references / "twinfinity-executor-registry.toml",
            codex_home=installed,
            profile_template_root=references,
        )
        self.v3_config = replace(
            self.v6_config,
            roles={
                **self.v6_config.roles,
                "development": self.v6_config.endpoints[V3],
            },
        )
        aliases, alias_sha256 = load_legacy_alias_fixture(
            references / "twinfinity-legacy-role-aliases.json"
        )
        self.aliases = aliases
        self.alias_sha256 = alias_sha256
        initial_plan = build_plan(
            self.store.connection,
            self.v3_config,
            aliases,
            alias_fixture_sha256=alias_sha256,
        )
        apply_plan(
            self.store.connection,
            plan=initial_plan,
            operation_key="issue-24-v3-baseline",
            expected_plan_sha256=initial_plan["plan_sha256"],
            now="2026-08-26T10:00:00Z",
        )

        source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload={"number": ISSUE, "updated_at": "2026-08-26T10:00:01Z"},
            source_updated_at="2026-08-26T10:00:01Z",
            fetched_at="2026-08-26T10:00:02Z",
        )
        self.source_sha256 = source.payload_sha256
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=ISSUE,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=GENERATION,
            accountable_session_id=V3,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.source_sha256,
            expected_version=0,
            now="2026-08-26T10:00:03Z",
        )
        self.payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": ISSUE,
                "payload_sha256": self.source_sha256,
            },
            "issue_number": ISSUE,
            "generation": GENERATION,
            "item_version": 1,
            "base_sha": "a" * 40,
            "branch": "codex/328-endpoint-rotation-continuation",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-328",
            "opaque_worktree_id": "twinfinityapp-issue-328",
            "accountable_session_id": V3,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            "writer": "one accountable writer",
            "reviewer_plan": ["Independent exact-head review."],
            "collision_proof": ["The lease is collision-free."],
            "environment_rule": "Use only the issue-owned environment.",
            "routine_chain": ["Complete the admitted delivery chain."],
            "hard_stops": ["Stop on binding drift."],
        }
        self.message_id = self.store.enqueue_message(
            idempotency_key="issue-328-generation-7-admission",
            recipient_session_id=V3,
            topic="development.admission",
            payload=self.payload,
            now="2026-08-26T10:00:04Z",
        )
        message = self.store.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (self.message_id,),
        ).fetchone()
        self.watch_key = f"terminal:{REPOSITORY}:issue:{ISSUE}:generation:{GENERATION}"
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches "
            "SET state='PENDING_CLAIM', admission_message_id=?, "
            "admission_payload_sha256=? "
            "WHERE watch_key=?",
            (self.message_id, message["payload_sha256"], self.watch_key),
        )
        old_attempt, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=V3,
            target_kind="message",
            target_key=str(self.message_id),
            now="2026-08-26T10:00:05Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(self.message_id)
            ),
        )
        unit = stable_systemd_unit("development", "message", str(self.message_id))
        launching = transition_attempt(
            self.store.connection,
            attempt_id=old_attempt["attempt_id"],
            token=token,
            expected_version=old_attempt["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="c" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-26T10:00:05Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=old_attempt["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9328,
            now="2026-08-26T10:00:05Z",
        )
        self.store.claim_message(
            self.message_id,
            V3,
            "2026-08-26T10:00:06Z",
            attempt_id=running["attempt_id"],
            executor_token=token,
        )
        self.old_attempt_id = old_attempt["attempt_id"]
        transition_attempt(
            self.store.connection,
            attempt_id=old_attempt["attempt_id"],
            token=token,
            expected_version=running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-26T10:00:07Z",
        )

        migration = build_plan(
            self.store.connection,
            self.v6_config,
            aliases,
            alias_fixture_sha256=alias_sha256,
        )
        self.change = apply_plan(
            self.store.connection,
            plan=migration,
            operation_key="issue-24-v3-to-v6",
            expected_plan_sha256=migration["plan_sha256"],
            now="2026-08-26T10:00:08Z",
        )
        self.message_hold_at = "2026-08-26T10:00:09Z"
        self.watch_hold_at = "2026-08-26T10:00:10Z"
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='HOLD', updated_at=?, "
            "last_error='MESSAGE_ITEM_STATE_MISMATCH' WHERE id=?",
            (self.message_hold_at, self.message_id),
        )
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET state='HOLD', updated_at=?, "
            "last_error='TERMINAL_WATCH_ADMISSION_BINDING_DRIFT' WHERE watch_key=?",
            (self.watch_hold_at, self.watch_key),
        )
        self.request = {
            "change_id": self.change["change_id"],
            "change_version": int(self.change["version"]),
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "message_id": self.message_id,
            "expected_message_updated_at": self.message_hold_at,
            "watch_key": self.watch_key,
            "expected_watch_updated_at": self.watch_hold_at,
        }

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def preview(self) -> dict:
        return self.store.preview_endpoint_rotation_admission_rearm(**self.request)

    def apply(self) -> dict:
        preview = self.preview()
        return self.store.apply_endpoint_rotation_admission_rearm(
            **self.request,
            expected_preview_sha256=preview["preview_sha256"],
            now="2026-08-26T10:00:11Z",
        )

    def test_rearm_is_atomic_exact_replay_and_preserves_immutable_admission(self) -> None:
        before = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (self.message_id,),
            ).fetchone()
        )
        attempt_count = self.store.connection.execute(
            "SELECT COUNT(*) FROM executor_attempts"
        ).fetchone()[0]
        preview = self.preview()
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_PREVIEW_DRIFT"
        ):
            self.store.apply_endpoint_rotation_admission_rearm(
                **self.request,
                expected_preview_sha256="0" * 64,
                now="2026-08-26T10:00:11Z",
            )
        self.assertEqual(
            ("HOLD", "MESSAGE_ITEM_STATE_MISMATCH"),
            tuple(
                self.store.connection.execute(
                    "SELECT state,last_error FROM coordination_messages WHERE id=?",
                    (self.message_id,),
                ).fetchone()
            ),
        )
        receipt = self.store.apply_endpoint_rotation_admission_rearm(
            **self.request,
            expected_preview_sha256=preview["preview_sha256"],
            now="2026-08-26T10:00:11Z",
        )
        replay = self.store.apply_endpoint_rotation_admission_rearm(
            **self.request,
            expected_preview_sha256=preview["preview_sha256"],
            now="2026-08-26T10:00:12Z",
        )
        self.assertEqual(receipt, replay)
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET attempts=1, updated_at=? "
            "WHERE watch_key=?",
            ("2026-08-26T10:00:13Z", self.watch_key),
        )
        progressed_replay = self.store.apply_endpoint_rotation_admission_rearm(
            **self.request,
            expected_preview_sha256=preview["preview_sha256"],
            now="2026-08-26T10:00:14Z",
        )
        self.assertEqual(receipt, progressed_replay)
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET attempts=0, updated_at=? "
            "WHERE watch_key=?",
            ("2026-08-26T10:00:11Z", self.watch_key),
        )
        after = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (self.message_id,),
            ).fetchone()
        )
        for field in (
            "idempotency_key",
            "recipient_session_id",
            "topic",
            "payload_sha256",
            "payload_json",
            "claimed_by",
            "created_at",
        ):
            self.assertEqual(before[field], after[field])
        self.assertEqual(("CLAIMED", None), (after["state"], after["last_error"]))
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
            (self.watch_key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", 0, None), (watch["state"], watch["attempts"], watch["last_error"]))
        self.assertEqual(self.old_attempt_id, watch["claim_attempt_id"])
        self.assertEqual(attempt_count, self.store.connection.execute(
            "SELECT COUNT(*) FROM executor_attempts"
        ).fetchone()[0])
        self.assertEqual(
            "TWINFINITY_ENDPOINT_ROTATION_ADMISSION_REARM_RECEIPT_V1",
            receipt["kind"],
        )

    def test_rearmed_lineage_continues_through_all_runtime_consumers(self) -> None:
        self.apply()
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (self.message_id,),
        ).fetchone()
        supervisor = CoordinationSupervisor(self.store)
        self.assertIsNone(supervisor._message_contract_error(message))
        selected, due = supervisor._reserve_terminal_watch(
            self.watch_key, "2026-08-26T10:00:12Z"
        )
        self.assertTrue(due)
        self.assertIsNotNone(selected)
        with self.assertRaisesRegex(
            RegistryError, "EXECUTOR_TARGET_ENDPOINT_MISMATCH"
        ):
            _validate_target(
                self.store.connection,
                role="development",
                endpoint_id=V6,
                target_kind="message",
                target_key=str(self.message_id),
                allowed_topics={"development.admission"},
            )
        self.assertEqual(
            AttemptLineage(REPOSITORY, ISSUE, GENERATION, LEASE),
            _validate_target(
                self.store.connection,
                role="development",
                endpoint_id=V6,
                target_kind="terminal_watch",
                target_key=self.watch_key,
                allowed_topics={"development.admission"},
            ),
        )
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_TARGET_INVALID"):
            _validate_target(
                self.store.connection,
                role="development",
                endpoint_id=V6,
                target_kind="terminal_watch",
                target_key=self.watch_key,
                allowed_topics={"coordination.notice"},
            )
        lease_result = (
            Path(self.payload["worktree_path"]),
            frozenset({Path(self.payload["worktree_path"]) / "backend/example.py"}),
            Path("/home/ubuntu/code/twinfinityapp"),
            self.payload["branch"],
            self.payload["base_sha"],
        )
        with patch("delivery_guard._load_lease", return_value=lease_result):
            with self.assertRaisesRegex(GuardError, "DELIVERY_TARGET_INVALID"):
                _message_context(
                    self.store.connection,
                    self.database,
                    role="development",
                    endpoint_id=V6,
                    target_key=str(self.message_id),
                    worktree_root=Path("/home/ubuntu/code"),
                )
            self.assertTrue(
                _terminal_watch_context(
                    self.store.connection,
                    self.database,
                    role="development",
                    endpoint_id=V6,
                    target_key=self.watch_key,
                    worktree_root=Path("/home/ubuntu/code"),
                ).repository_writes
            )
        prepush = PrePushControl(self.database)
        try:
            lineage = prepush._lineage(REPOSITORY, ISSUE)
        finally:
            prepush.close()
        self.assertEqual(self.message_id, lineage.admission_message_id)
        self.assertEqual(V6, lineage.session_id)
        fresh, _token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=V6,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            now="2026-08-26T10:00:13Z",
            precondition=lambda connection: _validate_target(
                connection,
                role="development",
                endpoint_id=V6,
                target_kind="terminal_watch",
                target_key=self.watch_key,
                allowed_topics={"development.admission"},
            ),
        )
        self.assertEqual((V6, "RESERVED"), (fresh["endpoint_id"], fresh["state"]))

    def test_claimed_historical_admission_routes_only_through_terminal_watch(self) -> None:
        self.apply()
        before_attempt = self.store.connection.execute(
            "SELECT claim_attempt_id FROM coordination_terminal_watches "
            "WHERE watch_key=?",
            (self.watch_key,),
        ).fetchone()[0]
        with self.assertRaisesRegex(
            CoordinationError, "TERMINAL_WATCH_CONTINUATION_REQUIRED"
        ):
            self.store.claim_message(
                self.message_id, V6, "2026-08-26T10:00:12Z"
            )
        after = self.store.connection.execute(
            "SELECT state,claim_attempt_id FROM coordination_terminal_watches "
            "WHERE watch_key=?",
            (self.watch_key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", before_attempt), tuple(after))

    def test_supervisor_never_relaunches_bound_claimed_admission(self) -> None:
        self.apply()
        supervisor = CoordinationSupervisor(self.store)
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (self.message_id,)
        ).fetchone()
        self.assertFalse(supervisor._message_needs_worker(message))
        selected, due = supervisor._reserve_terminal_watch(
            self.watch_key, "2026-08-26T10:00:12Z"
        )
        self.assertTrue(due)
        self.assertIsNotNone(selected)
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET next_wake_at=? "
            "WHERE watch_key=?",
            ("2026-08-26T10:05:00Z", self.watch_key),
        )
        selected, due = supervisor._reserve_terminal_watch(
            self.watch_key, "2026-08-26T10:00:13Z"
        )
        self.assertFalse(due)
        self.assertIsNotNone(selected)
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (self.message_id,)
        ).fetchone()
        self.assertFalse(supervisor._message_needs_worker(message))
        self.assertEqual(
            self.old_attempt_id,
            self.store.connection.execute(
                "SELECT claim_attempt_id FROM coordination_terminal_watches "
                "WHERE watch_key=?",
                (self.watch_key,),
            ).fetchone()[0],
        )

    def test_rotated_consumers_reject_completed_admission(self) -> None:
        self.apply()
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE' WHERE id=?",
            (self.message_id,),
        )
        prepush = PrePushControl(self.database)
        try:
            with self.assertRaisesRegex(
                PrePushError, "PREPUSH_COMPLETED_ADMISSION_ABSENT"
            ):
                prepush._lineage(REPOSITORY, ISSUE)
        finally:
            prepush.close()
        selected, due = CoordinationSupervisor(self.store)._reserve_terminal_watch(
            self.watch_key, "2026-08-26T10:00:12Z"
        )
        self.assertIsNone(selected)
        self.assertFalse(due)

    def test_terminal_historical_claim_attempt_can_continue_after_rearm(self) -> None:
        self.store.connection.execute(
            "UPDATE executor_attempts SET state='HOLD', version=version+1, "
            "updated_at=?, last_error='OLD_ENDPOINT_TERMINAL' WHERE attempt_id=?",
            ("2026-08-26T10:00:10Z", self.old_attempt_id),
        )
        self.apply()
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (self.message_id,)
        ).fetchone()
        self.assertIsNone(CoordinationSupervisor(self.store)._message_contract_error(message))
        lineage = _validate_target(
            self.store.connection,
            role="development",
            endpoint_id=V6,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            allowed_topics={"development.admission"},
        )
        self.assertEqual(REPOSITORY, lineage.repository)

    def test_runtime_consumers_reject_watch_coordinate_drift(self) -> None:
        self.apply()
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches "
            "SET repository='other/repo', issue_number=999, generation=999 "
            "WHERE watch_key=?",
            (self.watch_key,),
        )
        lease_result = (
            Path(self.payload["worktree_path"]),
            frozenset({Path(self.payload["worktree_path"]) / "backend/example.py"}),
            Path("/home/ubuntu/code/twinfinityapp"),
            self.payload["branch"],
            self.payload["base_sha"],
        )
        with patch("delivery_guard._load_lease", return_value=lease_result):
            with self.assertRaisesRegex(GuardError, "DELIVERY_TARGET_INVALID"):
                _terminal_watch_context(
                    self.store.connection,
                    self.database,
                    role="development",
                    endpoint_id=V6,
                    target_key=self.watch_key,
                    worktree_root=Path("/home/ubuntu/code"),
                )
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_TARGET_INVALID"):
            _validate_target(
                self.store.connection,
                role="development",
                endpoint_id=V6,
                target_kind="terminal_watch",
                target_key=self.watch_key,
                allowed_topics={"development.admission"},
            )

    def test_guard_accepts_publication_pending_rotated_watch(self) -> None:
        self.apply()
        self.store.connection.execute(
            "UPDATE coordination_items SET status='PUBLICATION_PENDING' "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        )
        self.assertEqual(
            REPOSITORY,
            _validate_target(
                self.store.connection,
                role="development",
                endpoint_id=V6,
                target_kind="terminal_watch",
                target_key=self.watch_key,
                allowed_topics={"development.admission"},
            ).repository,
        )
        lease_result = (
            Path(self.payload["worktree_path"]),
            frozenset({Path(self.payload["worktree_path"]) / "backend/example.py"}),
            Path("/home/ubuntu/code/twinfinityapp"),
            self.payload["branch"],
            self.payload["base_sha"],
        )
        with patch("delivery_guard._load_lease", return_value=lease_result):
            self.assertTrue(
                _terminal_watch_context(
                    self.store.connection,
                    self.database,
                    role="development",
                    endpoint_id=V6,
                    target_key=self.watch_key,
                    worktree_root=Path("/home/ubuntu/code"),
                ).repository_writes
            )

    def _assert_supervisor_drift_rejected(
        self, sql: str, parameters: tuple[object, ...]
    ) -> None:
        self.apply()
        self.store.connection.execute(sql, parameters)
        selected, due = CoordinationSupervisor(self.store)._reserve_terminal_watch(
            self.watch_key, "2026-08-26T10:00:12Z"
        )
        self.assertIsNone(selected)
        self.assertFalse(due)
        watch = self.store.connection.execute(
            "SELECT state,last_error FROM coordination_terminal_watches "
            "WHERE watch_key=?",
            (self.watch_key,),
        ).fetchone()
        self.assertEqual(
            ("HOLD", "TERMINAL_WATCH_ADMISSION_BINDING_DRIFT"), tuple(watch)
        )

    def test_supervisor_rejects_capacity_drift_after_rearm(self) -> None:
        self._assert_supervisor_drift_rejected(
            "UPDATE coordination_items SET development_units=2 "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        )

    def test_supervisor_rejects_item_source_drift_after_rearm(self) -> None:
        self._assert_supervisor_drift_rejected(
            "UPDATE coordination_items SET source_payload_sha256=? "
            "WHERE repository=? AND issue_number=?",
            ("8" * 64, REPOSITORY, ISSUE),
        )

    def test_supervisor_rejects_current_source_drift_after_rearm(self) -> None:
        self.apply()
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload={"number": ISSUE, "updated_at": "2026-08-26T10:00:13Z"},
            source_updated_at="2026-08-26T10:00:13Z",
            fetched_at="2026-08-26T10:00:14Z",
        )
        selected, due = CoordinationSupervisor(self.store)._reserve_terminal_watch(
            self.watch_key, "2026-08-26T10:00:15Z"
        )
        self.assertIsNone(selected)
        self.assertFalse(due)

    def test_preview_rejects_ledger_version_state_and_unrelated_item_bump(self) -> None:
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_LEDGER_MISMATCH"
        ):
            self.store.preview_endpoint_rotation_admission_rearm(
                **{**self.request, "change_version": self.request["change_version"] + 1}
            )
        self.store.connection.execute("SAVEPOINT wrong_state")
        self.store.connection.execute(
            "UPDATE executor_registry_changes SET state='ROLLED_BACK' WHERE change_id=?",
            (self.change["change_id"],),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_LEDGER_MISMATCH"
        ):
            self.store._endpoint_rotation_rearm_preview_locked(**self.request)
        self.store.connection.execute("ROLLBACK TO wrong_state")
        self.store.connection.execute("RELEASE wrong_state")
        self.store.connection.execute("SAVEPOINT forged_change_id")
        forged_change_id = "f" * 64
        self.store.connection.execute(
            "UPDATE executor_registry_changes SET change_id=? WHERE change_id=?",
            (forged_change_id, self.change["change_id"]),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_LEDGER_MISMATCH"
        ):
            self.store._endpoint_rotation_rearm_preview_locked(
                **{**self.request, "change_id": forged_change_id}
            )
        self.store.connection.execute("ROLLBACK TO forged_change_id")
        self.store.connection.execute("RELEASE forged_change_id")
        self.store.connection.execute("SAVEPOINT forged_operation")
        self.store.connection.execute(
            "UPDATE executor_registry_changes SET operation_key='forged' "
            "WHERE change_id=?",
            (self.change["change_id"],),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_LEDGER_MISMATCH"
        ):
            self.store._endpoint_rotation_rearm_preview_locked(**self.request)
        self.store.connection.execute("ROLLBACK TO forged_operation")
        self.store.connection.execute("RELEASE forged_operation")
        self.store.connection.execute("SAVEPOINT applied_v2")
        self.store.connection.execute(
            "UPDATE executor_registry_changes SET version=2 WHERE change_id=?",
            (self.change["change_id"],),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_LEDGER_MISMATCH"
        ):
            self.store._endpoint_rotation_rearm_preview_locked(
                **{**self.request, "change_version": 2}
            )
        self.store.connection.execute("ROLLBACK TO applied_v2")
        self.store.connection.execute("RELEASE applied_v2")
        self.store.connection.execute("SAVEPOINT unrelated_bump")
        self.store.connection.execute(
            "UPDATE coordination_items SET version=version+1 WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_LEDGER_MISMATCH"
        ):
            self.store._endpoint_rotation_rearm_preview_locked(**self.request)
        self.store.connection.execute("ROLLBACK TO unrelated_bump")
        self.store.connection.execute("RELEASE unrelated_bump")

    def test_preview_rejects_lineage_binding_drift(self) -> None:
        mutations = (
            ("source", "UPDATE coordination_items SET source_payload_sha256=? WHERE repository=? AND issue_number=?", ("8" * 64, REPOSITORY, ISSUE)),
            ("generation", "UPDATE coordination_items SET generation=generation+1 WHERE repository=? AND issue_number=?", (REPOSITORY, ISSUE)),
            ("lease", "UPDATE coordination_items SET lease_manifest_sha256=? WHERE repository=? AND issue_number=?", ("9" * 64, REPOSITORY, ISSUE)),
            ("capacity", "UPDATE coordination_items SET development_units=2 WHERE repository=? AND issue_number=?", (REPOSITORY, ISSUE)),
            ("monitor", "UPDATE coordination_items SET status='MONITOR' WHERE repository=? AND issue_number=?", (REPOSITORY, ISSUE)),
            ("claim_attempt", "UPDATE coordination_terminal_watches SET claim_attempt_id=? WHERE watch_key=?", ("missing-attempt", self.watch_key)),
            ("process", "UPDATE coordination_terminal_watches SET process_id=123 WHERE watch_key=?", (self.watch_key,)),
        )
        for name, sql, parameters in mutations:
            with self.subTest(name=name):
                self.store.connection.execute(f"SAVEPOINT {name}")
                self.store.connection.execute(sql, parameters)
                with self.assertRaises(CoordinationError):
                    self.store._endpoint_rotation_rearm_preview_locked(**self.request)
                self.store.connection.execute(f"ROLLBACK TO {name}")
                self.store.connection.execute(f"RELEASE {name}")

    def test_preview_rejects_active_attempt_wrong_errors_and_timestamp_fences(self) -> None:
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_STATE_MISMATCH"
        ):
            self.store.preview_endpoint_rotation_admission_rearm(
                **{**self.request, "expected_message_updated_at": "2026-08-26T10:00:00Z"}
            )
        self.store.connection.execute("SAVEPOINT wrong_error")
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET last_error='OTHER' WHERE watch_key=?",
            (self.watch_key,),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_STATE_MISMATCH"
        ):
            self.store._endpoint_rotation_rearm_preview_locked(**self.request)
        self.store.connection.execute("ROLLBACK TO wrong_error")
        self.store.connection.execute("RELEASE wrong_error")
        active, _token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=V6,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            now="2026-08-26T10:00:10Z",
            precondition=lambda _connection: AttemptLineage(
                REPOSITORY, ISSUE, GENERATION, LEASE
            ),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_ACTIVE_ATTEMPT"
        ):
            self.preview()
        self.store.connection.execute(
            "UPDATE executor_attempts SET state='HOLD', version=version+1, "
            "updated_at=? WHERE attempt_id=?",
            ("2026-08-26T10:00:11Z", active["attempt_id"]),
        )

    def test_partial_replay_without_receipt_fails_closed(self) -> None:
        preview = self.preview()
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='CLAIMED', last_error=NULL WHERE id=?",
            (self.message_id,),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_STATE_MISMATCH"
        ):
            self.store.apply_endpoint_rotation_admission_rearm(
                **self.request,
                expected_preview_sha256=preview["preview_sha256"],
                now="2026-08-26T10:00:11Z",
            )
        watch = self.store.connection.execute(
            "SELECT state,last_error FROM coordination_terminal_watches WHERE watch_key=?",
            (self.watch_key,),
        ).fetchone()
        self.assertEqual(
            ("HOLD", "TERMINAL_WATCH_ADMISSION_BINDING_DRIFT"), tuple(watch)
        )

    def test_replay_rejects_self_consistent_receipt_column_drift(self) -> None:
        receipt = self.apply()
        stored = self.store.connection.execute(
            "SELECT * FROM coordination_endpoint_rotation_rearms WHERE rearm_key=?",
            (receipt["rearm_key"],),
        ).fetchone()
        drifted = json.loads(stored["receipt_json"])
        drifted["generation"] += 1
        self.store.connection.execute(
            "DROP TRIGGER coordination_endpoint_rotation_rearm_immutable_update"
        )
        self.store.connection.execute(
            "UPDATE coordination_endpoint_rotation_rearms "
            "SET receipt_json=?, receipt_sha256=? WHERE rearm_key=?",
            (
                coordination_store_module.canonical_json(drifted),
                digest_json(drifted),
                receipt["rearm_key"],
            ),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_REPLAY_CONFLICT"
        ):
            self.store.apply_endpoint_rotation_admission_rearm(
                **self.request,
                expected_preview_sha256=receipt["preview_sha256"],
                now="2026-08-26T10:00:12Z",
            )

    def test_preview_rejects_tampered_message_digest_and_closeout_packet(self) -> None:
        self.store.connection.execute("SAVEPOINT message_digest")
        self.store.connection.execute("DROP TRIGGER coordination_message_envelope_immutable")
        self.store.connection.execute(
            "UPDATE coordination_messages SET payload_sha256=? WHERE id=?",
            ("0" * 64, self.message_id),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_STATE_MISMATCH"
        ):
            self.store._endpoint_rotation_rearm_preview_locked(**self.request)
        self.store.connection.execute("ROLLBACK TO message_digest")
        self.store.connection.execute("RELEASE message_digest")

        self.store.connection.execute(
            """
            INSERT INTO coordination_terminal_closeout_packets(
                closeout_key,packet_sha256,repository,issue_number,generation,
                source_payload_sha256,lease_manifest_sha256,accountable_role,
                endpoint_id,preparer_attempt_id,preparer_attempt_version,
                terminal_watch_key,activation_message_id,
                activation_payload_sha256,expected_item_version,
                publication_pending_item_version,terminal_receipt_sha256,
                terminal_receipt_json,cleanup_evidence_sha256,
                cleanup_evidence_json,outbox_id,outbox_payload_sha256,
                graph_version,graph_sha256,graph_main_sha,graph_node_key,
                graph_binding_sha256,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "issue-328-closeout",
                "1" * 64,
                REPOSITORY,
                ISSUE,
                GENERATION,
                self.source_sha256,
                LEASE,
                "development",
                V3,
                self.old_attempt_id,
                2,
                self.watch_key,
                self.message_id,
                digest_json(self.payload),
                2,
                3,
                "2" * 64,
                "{}",
                "3" * 64,
                "{}",
                999,
                "4" * 64,
                1,
                "5" * 64,
                "a" * 40,
                "issue:328",
                "6" * 64,
                "2026-08-26T10:00:10Z",
            ),
        )
        with self.assertRaisesRegex(
            CoordinationError, "ENDPOINT_ROTATION_REARM_CLOSEOUT_CONFLICT"
        ):
            self.preview()

    def test_official_cli_previews_then_applies_the_exact_cas(self) -> None:
        common = [
            "--change-id",
            self.request["change_id"],
            "--change-version",
            str(self.request["change_version"]),
            "--repository",
            REPOSITORY,
            "--issue-number",
            str(ISSUE),
            "--message-id",
            str(self.message_id),
            "--expected-message-updated-at",
            self.message_hold_at,
            "--watch-key",
            self.watch_key,
            "--expected-watch-updated-at",
            self.watch_hold_at,
        ]
        output = io.StringIO()
        with (
            patch.object(coordination_store_module, "DEFAULT_DATABASE", self.database),
            patch.object(
                sys,
                "argv",
                [
                    "coordination_store.py",
                    "preview-endpoint-rotation-admission-rearm",
                    *common,
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(0, coordination_store_module.main())
        preview = json.loads(output.getvalue())
        self.assertEqual("PREVIEW", preview["phase"])
        output = io.StringIO()
        with (
            patch.object(coordination_store_module, "DEFAULT_DATABASE", self.database),
            patch.object(
                sys,
                "argv",
                [
                    "coordination_store.py",
                    "apply-endpoint-rotation-admission-rearm",
                    *common,
                    "--expected-preview-sha256",
                    preview["rearm"]["preview_sha256"],
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(0, coordination_store_module.main())
        applied = json.loads(output.getvalue())
        self.assertEqual("COMPLETE", applied["phase"])
        self.assertEqual(
            "TWINFINITY_ENDPOINT_ROTATION_ADMISSION_REARM_RECEIPT_V1",
            applied["rearm"]["kind"],
        )


if __name__ == "__main__":
    unittest.main()
