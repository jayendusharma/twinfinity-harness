from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    UNCLAIMED_ADMISSION_RETRY_REASON,
    canonical_json,
)
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from executor_registry import (  # noqa: E402
    attempt_lineage_for_target,
    current_endpoint,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
import kanban_pull_buffer as pull_buffer  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    LEGACY_329_DURABLE_FENCE,
    LEGACY_329_NORMALIZATION_EVENTS,
    LEGACY_329_RECOVERY_REASON,
    PullBufferError,
    UNCLAIMED_ADMISSION_RECOVERY_SCHEMA,
    _legacy_329_recovery_fence,
    _legacy_recovery_stable_source,
    recover_unclaimed_admission,
)
from portfolio_convergence import PortfolioConvergence  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)
from tests.canonical_ready_fixture import (  # noqa: E402
    finalize_canonical_ready_item,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
DEVELOPMENT = "role.development.v4"
SRE = "role.sre.v4"


class UnclaimedAdmissionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "coordinator"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="unclaimed-admission-recovery-tests",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _admitted(self, role: str = "development", issue: int = 273) -> dict:
        endpoint = SRE if role == "sre" else DEVELOPMENT
        payload = {
            "_projection_version": 3,
            "number": issue,
            "title": f"Issue {issue}",
            "state": "open",
            "body": "Operational projection: PREPARED / NOT AGENT-READY",
            "labels": [{"name": "delivery"}],
            "updated_at": "2026-08-26T10:00:00Z",
            "milestone": {"number": 1, "title": "Sprint", "state": "open"},
        }
        source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue,
            payload=payload,
            source_updated_at=payload["updated_at"],
            fetched_at="2026-08-26T10:00:01Z",
        )
        units = {
            "development_units": 0 if role == "sre" else 1,
            "shared_units": 0 if role == "sre" else 1,
            "sre_units": 1 if role == "sre" else 0,
        }
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=issue,
            status="PREPARED",
            allocation_class="NONE",
            generation=0,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            **units,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-26T10:00:02Z",
        )
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Sprint", "rank": 1}],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": f"issue:{issue}",
                        "issue_number": issue,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent recovery regression",
                        "lane_key": f"lane-{issue}",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": 1,
                        "estimate_units": 1,
                        **units,
                        "source_payload_sha256": source.payload_sha256,
                        "ready_at": "2026-08-26T10:00:00Z",
                    }
                ],
                "relations": [],
            },
            now="2026-08-26T10:00:03Z",
        )
        finalized = finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.root,
            repository=REPOSITORY,
            issue_number=issue,
            source_payload_sha256=source.payload_sha256,
            accepted_main_sha=MAIN,
            worker_role=role,
            worker_endpoint_id=endpoint,
            now="2026-08-26T10:00:04Z",
            suffix=f"recovery-{role}-{issue}",
        )
        admitted = PortfolioConvergence(
            self.store, canonical_main_reader=lambda _repository: MAIN
        ).consume_one("2026-08-26T10:00:05Z")
        self.assertEqual("ADMITTED", admitted["outcome"])
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (admitted["message_id"],),
        ).fetchone()
        return {
            "issue": issue,
            "role": role,
            "endpoint": endpoint,
            "source": source,
            "source_payload": payload,
            "finalized": finalized,
            "message_id": int(admitted["message_id"]),
            "message": dict(message),
        }

    def _reserve_running_attempt(self, lineage: dict) -> tuple[dict, str]:
        reserved, token = reserve_attempt(
            self.store.connection,
            role=lineage["role"],
            endpoint_id=lineage["endpoint"],
            target_kind="message",
            target_key=str(lineage["message_id"]),
            now="2026-08-26T10:00:06Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(lineage["message_id"])
            ),
        )
        unit = stable_systemd_unit(
            lineage["role"], "message", str(lineage["message_id"])
        )
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=hashlib.md5(unit.encode()).hexdigest(),
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-26T10:00:06Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9273,
            now="2026-08-26T10:00:06Z",
        )
        return running, token

    def _run_to_third_attempt(self, lineage: dict) -> CoordinationSupervisor:
        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 9273,
            terminal_watch_launcher=lambda _session, _watch: 9274,
            process_checker=lambda *_args: False,
        )
        for timestamp in (
            "2026-08-26T10:00:06Z",
            "2026-08-26T10:01:07Z",
            "2026-08-26T10:03:08Z",
        ):
            supervisor.run_once(timestamp)
        wake = self.store.connection.execute(
            "SELECT * FROM coordination_wakes WHERE message_id=?",
            (lineage["message_id"],),
        ).fetchone()
        self.assertEqual(("INFLIGHT", 3), (wake["state"], int(wake["attempts"])))
        return supervisor

    def _exhaust(self, lineage: dict) -> dict:
        supervisor = self._run_to_third_attempt(lineage)
        supervisor.run_once("2026-08-26T10:07:09Z")
        return self._recovery_request(lineage)

    def _recovery_request(self, lineage: dict) -> dict:
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (lineage["message_id"],),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT * FROM coordination_wakes WHERE message_id=?",
            (lineage["message_id"],),
        ).fetchone()
        payload = json.loads(message["payload_json"])
        watch_key = (
            f"terminal:{REPOSITORY}:issue:{lineage['issue']}:"
            f"generation:{payload['generation']}"
        )
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, lineage["issue"]),
        ).fetchone()
        planner = current_endpoint(self.store.connection, "planner")
        notices = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE topic='coordination.notice' "
            "AND recipient_session_id=? ORDER BY id",
            (planner["endpoint_id"],),
        ).fetchall()
        notice = next(
            row
            for row in notices
            if json.loads(row["payload_json"]).get("evidence", {}).get(
                "admission_message_id"
            )
            == lineage["message_id"]
        )
        return {
            "schema": UNCLAIMED_ADMISSION_RECOVERY_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": lineage["issue"],
            "planner_session_id": planner["endpoint_id"],
            "generation": payload["generation"],
            "retained_item_version": int(item["version"]),
            "source_payload_sha256": payload["source"]["payload_sha256"],
            "current_source_payload_sha256": payload["source"]["payload_sha256"],
            "accountable_session_id": item["accountable_session_id"],
            "lease_manifest_sha256": item["lease_manifest_sha256"],
            "admission_message_id": lineage["message_id"],
            "admission_payload_sha256": message["payload_sha256"],
            "wake_key": wake["wake_key"],
            "wake_attempts": int(wake["attempts"]),
            "target_progress_sha256": wake["target_progress_sha256"],
            "watch_key": watch_key,
            "recovery_notice_message_id": int(notice["id"]),
            "recovery_reason": UNCLAIMED_ADMISSION_RETRY_REASON,
        }

    def _fingerprint(self) -> str:
        tables = (
            "coordination_items",
            "coordination_messages",
            "coordination_wakes",
            "coordination_terminal_watches",
            "portfolio_readiness_current",
            "portfolio_dirty_events",
            "portfolio_pull_buffer_retirements",
            "portfolio_readiness_events",
            "coordination_events",
        )
        rows = {
            table: [dict(row) for row in self.store.connection.execute(
                f"SELECT * FROM {table} ORDER BY rowid"
            ).fetchall()]
            for table in tables
        }
        return hashlib.sha256(canonical_json(rows).encode()).hexdigest()

    def _assert_recovery_rejected_without_writes(
        self, request: dict, error: str
    ) -> None:
        baseline = self._fingerprint()
        with self.assertRaisesRegex(PullBufferError, error):
            recover_unclaimed_admission(
                self.store, request, now="2026-08-26T10:08:00Z"
            )
        self.assertEqual(baseline, self._fingerprint())

    def _legacy_329_request(self) -> dict:
        return {
            "schema": UNCLAIMED_ADMISSION_RECOVERY_SCHEMA,
            "repository": LEGACY_329_DURABLE_FENCE["repository"],
            "issue_number": LEGACY_329_DURABLE_FENCE["issue_number"],
            "planner_session_id": "role.planner.v4",
            "generation": LEGACY_329_DURABLE_FENCE["generation"],
            "retained_item_version": LEGACY_329_DURABLE_FENCE[
                "retained_item_version"
            ],
            "source_payload_sha256": LEGACY_329_DURABLE_FENCE[
                "source_payload_sha256"
            ],
            "current_source_payload_sha256": LEGACY_329_DURABLE_FENCE[
                "source_payload_sha256"
            ],
            "accountable_session_id": LEGACY_329_DURABLE_FENCE[
                "accountable_session_id"
            ],
            "lease_manifest_sha256": LEGACY_329_DURABLE_FENCE[
                "lease_manifest_sha256"
            ],
            "admission_message_id": LEGACY_329_DURABLE_FENCE[
                "admission_message_id"
            ],
            "admission_payload_sha256": LEGACY_329_DURABLE_FENCE[
                "admission_payload_sha256"
            ],
            "wake_key": LEGACY_329_DURABLE_FENCE["wake_key"],
            "wake_attempts": LEGACY_329_DURABLE_FENCE["wake_attempts"],
            "target_progress_sha256": LEGACY_329_DURABLE_FENCE[
                "target_progress_sha256"
            ],
            "watch_key": f"terminal:{REPOSITORY}:issue:329:generation:2",
            "recovery_notice_message_id": None,
            "recovery_reason": LEGACY_329_RECOVERY_REASON,
        }

    @staticmethod
    def _legacy_329_rows() -> dict:
        return {
            "message": {
                "recipient_session_id": LEGACY_329_DURABLE_FENCE[
                    "admission_recipient"
                ],
                "state": "HOLD",
                "last_error": "WAKE_RETRY_EXHAUSTED",
            },
            "wake": {
                "state": "HOLD",
                "last_error": "WAKE_RETRY_EXHAUSTED",
                "last_attempt_at": LEGACY_329_DURABLE_FENCE[
                    "wake_last_attempt_at"
                ],
            },
            "watch": {
                "state": "COMPLETE",
                "accountable_session_id": LEGACY_329_DURABLE_FENCE[
                    "admission_recipient"
                ],
                "process_id": None,
                "attempts": 0,
                "updated_at": LEGACY_329_DURABLE_FENCE["watch_updated_at"],
            },
            "item": {
                "updated_at": LEGACY_329_DURABLE_FENCE["item_updated_at"],
            },
            "candidate": {"id": LEGACY_329_DURABLE_FENCE["ready_candidate_id"]},
            "finalization": {
                "id": LEGACY_329_DURABLE_FENCE["ready_finalization_id"],
                "campaign_id": LEGACY_329_DURABLE_FENCE[
                    "readiness_campaign_id"
                ],
                "receipt_id": LEGACY_329_DURABLE_FENCE[
                    "readiness_receipt_id"
                ],
                "dirty_event_id": LEGACY_329_DURABLE_FENCE[
                    "finalization_dirty_event_id"
                ],
                "finalization_sha256": LEGACY_329_DURABLE_FENCE[
                    "ready_finalization_sha256"
                ],
            },
        }

    def test_exact_source_claim_ignores_absent_stale_ready_projection(self) -> None:
        lineage = self._admitted()
        self.assertNotIn("agent-ready", lineage["source_payload"]["labels"])
        running, token = self._reserve_running_attempt(lineage)
        claimed = self.store.claim_message(
            lineage["message_id"],
            DEVELOPMENT,
            "2026-08-26T10:00:07Z",
            attempt_id=running["attempt_id"],
            executor_token=token,
        )
        self.assertEqual("CLAIMED", claimed["state"])

    def test_material_source_drift_still_prevents_claim(self) -> None:
        lineage = self._admitted()
        changed = {**lineage["source_payload"], "title": "Materially changed"}
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=lineage["issue"],
            payload=changed,
            source_updated_at="2026-08-26T10:01:00Z",
            fetched_at="2026-08-26T10:01:01Z",
        )
        running, token = self._reserve_running_attempt(lineage)
        with self.assertRaisesRegex(CoordinationError, "SOURCE_SNAPSHOT_DRIFT"):
            self.store.claim_message(
                lineage["message_id"], DEVELOPMENT, "2026-08-26T10:01:02Z",
                attempt_id=running["attempt_id"], executor_token=token,
            )

    def test_development_and_sre_exhaustion_hold_every_bound_row(self) -> None:
        for role, issue in (("development", 273), ("sre", 274)):
            with self.subTest(role=role):
                if role == "sre":
                    self.tearDown()
                    self.setUp()
                lineage = self._admitted(role, issue)
                before = self.store.connection.execute(
                    "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                    (REPOSITORY, issue),
                ).fetchone()
                request = self._exhaust(lineage)
                message = self.store.connection.execute(
                    "SELECT state,last_error FROM coordination_messages WHERE id=?",
                    (lineage["message_id"],),
                ).fetchone()
                wake = self.store.connection.execute(
                    "SELECT state,last_error FROM coordination_wakes WHERE message_id=?",
                    (lineage["message_id"],),
                ).fetchone()
                watch = self.store.connection.execute(
                    "SELECT state,last_error FROM coordination_terminal_watches "
                    "WHERE watch_key=?", (request["watch_key"],),
                ).fetchone()
                item = self.store.connection.execute(
                    "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                    (REPOSITORY, issue),
                ).fetchone()
                self.assertEqual(
                    ("HOLD", UNCLAIMED_ADMISSION_RETRY_REASON), tuple(message)
                )
                self.assertEqual(tuple(message), tuple(wake))
                self.assertEqual(tuple(message), tuple(watch))
                self.assertEqual(("HOLD", "RETAINED"), (item["status"], item["allocation_class"]))
                self.assertEqual(before["lease_manifest_sha256"], item["lease_manifest_sha256"])
                self.assertEqual(int(before["version"]) + 1, int(item["version"]))
                notices = self.store.connection.execute(
                    "SELECT recipient_session_id,payload_json FROM coordination_messages "
                    "WHERE topic='coordination.notice'"
                ).fetchall()
                planner = current_endpoint(self.store.connection, "planner")
                matching = [
                    row for row in notices
                    if row["recipient_session_id"] == planner["endpoint_id"]
                    and json.loads(row["payload_json"]).get("evidence", {}).get(
                        "admission_message_id"
                    ) == lineage["message_id"]
                ]
                self.assertEqual(1, len(matching))

    def test_exhaustion_failpoints_roll_back_every_write(self) -> None:
        lineage = self._admitted()
        self._run_to_third_attempt(lineage)
        wake = self.store.connection.execute(
            "SELECT * FROM coordination_wakes WHERE message_id=?",
            (lineage["message_id"],),
        ).fetchone()
        baseline = self._fingerprint()
        for marker in (
            "exhaustion.after_message",
            "exhaustion.after_wake",
            "exhaustion.after_watch",
            "exhaustion.after_item",
            "exhaustion.after_notice",
            "exhaustion.after_event",
        ):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, marker):
                self.store.hold_unclaimed_admission_retry_exhausted(
                    message_id=lineage["message_id"],
                    wake_key=wake["wake_key"],
                    expected_target_progress_sha256=wake["target_progress_sha256"],
                    expected_wake_attempts=3,
                    now="2026-08-26T10:07:09Z",
                    _test_failpoint=lambda point, wanted=marker: (
                        (_ for _ in ()).throw(RuntimeError(point))
                        if point == wanted else None
                    ),
                )
            self.assertEqual(baseline, self._fingerprint())

    def test_planner_rebaseline_replays_and_reaches_genuine_claim(self) -> None:
        lineage = self._admitted()
        request = self._exhaust(lineage)
        units = self.store.connection.execute(
            "SELECT development_units,shared_units,sre_units FROM coordination_items "
            "WHERE repository=? AND issue_number=?", (REPOSITORY, lineage["issue"]),
        ).fetchone()
        result = recover_unclaimed_admission(
            self.store, request, now="2026-08-26T10:08:00Z"
        )
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, lineage["issue"]),
        ).fetchone()
        self.assertEqual(("PREPARED", "NONE", 1), (
            item["status"], item["allocation_class"], int(item["generation"])
        ))
        self.assertIsNone(item["accountable_session_id"])
        self.assertIsNone(item["lease_manifest_sha256"])
        self.assertEqual(tuple(units), (
            item["development_units"], item["shared_units"], item["sre_units"]
        ))
        before_replay = self._fingerprint()
        self.assertEqual(
            result,
            recover_unclaimed_admission(
                self.store, request, now="2026-08-26T10:08:01Z"
            ),
        )
        self.assertEqual(before_replay, self._fingerprint())

        finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.root,
            repository=REPOSITORY,
            issue_number=lineage["issue"],
            source_payload_sha256=request["current_source_payload_sha256"],
            accepted_main_sha=MAIN,
            worker_role="development",
            worker_endpoint_id=DEVELOPMENT,
            now="2026-08-26T10:09:00Z",
            suffix="recovered-successor",
            refresh=True,
        )
        admitted = PortfolioConvergence(
            self.store, canonical_main_reader=lambda _repository: MAIN
        ).consume_one("2026-08-26T10:09:01Z")
        self.assertEqual("ADMITTED", admitted["outcome"])
        successor = {
            **lineage,
            "message_id": int(admitted["message_id"]),
        }
        running, token = self._reserve_running_attempt(successor)
        claimed = self.store.claim_message(
            successor["message_id"], DEVELOPMENT, "2026-08-26T10:09:02Z",
            attempt_id=running["attempt_id"], executor_token=token,
        )
        self.assertEqual("CLAIMED", claimed["state"])
        downstream = self._fingerprint()
        self.assertEqual(
            result,
            recover_unclaimed_admission(
                self.store, request, now="2026-08-26T10:09:03Z"
            ),
        )
        self.assertEqual(downstream, self._fingerprint())

    def test_recovery_requires_the_current_planner_without_writes(self) -> None:
        request = self._exhaust(self._admitted())
        request["planner_session_id"] = DEVELOPMENT
        self._assert_recovery_rejected_without_writes(
            request, "CURRENT_PLANNER_ENDPOINT_REQUIRED"
        )

    def test_claim_evidence_blocks_recovery_without_writes(self) -> None:
        lineage = self._admitted()
        request = self._exhaust(lineage)
        self.store._event(
            "MESSAGE_CLAIMED",
            f"message:{lineage['message_id']}",
            {"adversarial_fixture": True},
            "2026-08-26T10:07:30Z",
        )
        self._assert_recovery_rejected_without_writes(
            request, "UNCLAIMED_ADMISSION_CLAIM_EVIDENCE_PRESENT"
        )

    def test_active_attempt_blocks_recovery_without_writes(self) -> None:
        lineage = self._admitted()
        request = self._exhaust(lineage)
        reserve_attempt(
            self.store.connection,
            role=lineage["role"],
            endpoint_id=lineage["endpoint"],
            target_kind="message",
            target_key=str(lineage["message_id"]),
            now="2026-08-26T10:07:30Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(lineage["message_id"])
            ),
        )
        self._assert_recovery_rejected_without_writes(
            request, "UNCLAIMED_ADMISSION_TERMINAL_LINEAGE_PRESENT"
        )

    def test_terminal_message_blocks_recovery_without_writes(self) -> None:
        lineage = self._admitted()
        request = self._exhaust(lineage)
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": lineage["issue"],
                "payload_sha256": request["source_payload_sha256"],
            },
            "issue_number": lineage["issue"],
            "generation": request["generation"],
        }
        self.store.connection.execute(
            "INSERT INTO coordination_messages("
            "idempotency_key,recipient_session_id,topic,payload_sha256,"
            "payload_json,state,created_at,updated_at,last_error) "
            "VALUES (?,?,?,?,?,'HOLD',?,?,?)",
            (
                f"adversarial-terminal:{lineage['issue']}",
                DEVELOPMENT,
                "development.terminal_closeout",
                hashlib.sha256(canonical_json(payload).encode()).hexdigest(),
                canonical_json(payload),
                "2026-08-26T10:07:30Z",
                "2026-08-26T10:07:30Z",
                "ADVERSARIAL_FIXTURE",
            ),
        )
        self._assert_recovery_rejected_without_writes(
            request, "UNCLAIMED_ADMISSION_TERMINAL_LINEAGE_PRESENT"
        )

    def test_changed_recovery_bindings_are_write_free(self) -> None:
        request = self._exhaust(self._admitted())
        cases = {
            "source": {"source_payload_sha256": "f" * 64},
            "item": {
                "retained_item_version": request["retained_item_version"] + 1
            },
            "message": {"admission_payload_sha256": "f" * 64},
            "lease": {"lease_manifest_sha256": "f" * 64},
            "generation": {
                "generation": request["generation"] + 1,
                "watch_key": (
                    f"terminal:{REPOSITORY}:issue:{request['issue_number']}:"
                    f"generation:{request['generation'] + 1}"
                ),
            },
        }
        for name, changed in cases.items():
            with self.subTest(binding=name):
                self._assert_recovery_rejected_without_writes(
                    {**request, **changed}, "UNCLAIMED_ADMISSION"
                )

        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET last_error=? "
            "WHERE watch_key=?",
            ("ADVERSARIAL_WATCH_DRIFT", request["watch_key"]),
        )
        self._assert_recovery_rejected_without_writes(
            request, "UNCLAIMED_ADMISSION_RECOVERY_FENCE_MISMATCH"
        )

    def test_recovery_failpoints_and_stale_fences_are_write_free(self) -> None:
        lineage = self._admitted()
        request = self._exhaust(lineage)
        baseline = self._fingerprint()
        for marker in (
            "recovery.after_item",
            "recovery.after_readiness",
            "recovery.after_refill_event",
            "recovery.after_notice_claim",
            "recovery.after_notice_complete",
            "recovery.after_readiness_event",
            "recovery.after_audit_event",
        ):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, marker):
                recover_unclaimed_admission(
                    self.store,
                    request,
                    now="2026-08-26T10:08:00Z",
                    failpoint=lambda point, wanted=marker: (
                        (_ for _ in ()).throw(RuntimeError(point))
                        if point == wanted else None
                    ),
                )
            self.assertEqual(baseline, self._fingerprint())
        wrong = {**request, "lease_manifest_sha256": "f" * 64}
        with self.assertRaises(PullBufferError):
            recover_unclaimed_admission(self.store, wrong, now="2026-08-26T10:08:00Z")
        self.assertEqual(baseline, self._fingerprint())

    def test_owner_cli_recovers_one_exact_transaction_file(self) -> None:
        request = self._exhaust(self._admitted())
        request_path = self.root / "recover-unclaimed-admission.json"
        request_path.write_text(canonical_json(request), encoding="utf-8")
        output = io.StringIO()
        with (
            patch.object(pull_buffer, "DEFAULT_DATABASE", self.database),
            patch.object(
                sys,
                "argv",
                [
                    "kanban_pull_buffer.py",
                    "recover-unclaimed-admission",
                    "--transaction-file",
                    str(request_path),
                ],
            ),
            patch.object(
                pull_buffer, "utc_now", return_value="2026-08-26T10:08:00Z"
            ),
            redirect_stdout(output),
        ):
            return_code = pull_buffer.main()
        receipt = json.loads(output.getvalue())
        self.assertEqual(0, return_code)
        self.assertEqual("COMPLETE", receipt["phase"])
        self.assertEqual("RECOVERED", receipt["result"]["state"])
        item = self.store.connection.execute(
            "SELECT status,allocation_class,generation FROM coordination_items "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, request["issue_number"]),
        ).fetchone()
        self.assertEqual(("PREPARED", "NONE", 1), tuple(item))

    def test_exact_legacy_329_fence_accepts_only_proven_lineage(self) -> None:
        request = self._legacy_329_request()
        rows = self._legacy_329_rows()
        expected_attempt = (
            LEGACY_329_DURABLE_FENCE["executor_attempt_id"],
            "development",
            LEGACY_329_DURABLE_FENCE["admission_recipient"],
            "message",
            "16",
            "HOLD",
            0,
            "EXECUTOR_TARGET_NO_PROGRESS",
        )

        class Result:
            def __init__(self, values: list) -> None:
                self.values = values

            def fetchall(self) -> list:
                return self.values

        class Connection:
            def __init__(self, events: list[dict]) -> None:
                self.events = events

            def execute(self, sql: str, _values: tuple = ()) -> Result:
                if "coordination_events" in sql:
                    return Result(self.events)
                if "executor_attempts" in sql:
                    return Result([expected_attempt])
                raise AssertionError(sql)

        connection = Connection(list(LEGACY_329_NORMALIZATION_EVENTS))
        with patch.object(
            pull_buffer,
            "applied_endpoint_rotation_chain",
            return_value={"state": "APPLIED"},
        ) as rotation:
            _legacy_329_recovery_fence(
                connection, rows, request, replay=False
            )
        rotation.assert_called_once_with(
            connection,
            repository=REPOSITORY,
            issue_number=329,
            before_identity=LEGACY_329_DURABLE_FENCE["admission_recipient"],
            before_item_version=6,
            after_identity=LEGACY_329_DURABLE_FENCE["accountable_session_id"],
            after_item_version=7,
            not_before=LEGACY_329_NORMALIZATION_EVENTS[1]["created_at"],
            change_id=LEGACY_329_DURABLE_FENCE["rotation_change_id"],
            change_version=LEGACY_329_DURABLE_FENCE["rotation_change_version"],
        )

        drifted = deepcopy(rows)
        drifted["item"]["updated_at"] = "2026-08-26T09:26:22Z"
        with self.assertRaisesRegex(
            PullBufferError, "LEGACY_329_RECOVERY_FENCE_MISMATCH"
        ):
            _legacy_329_recovery_fence(
                connection, drifted, request, replay=False
            )
        with (
            patch.object(
                pull_buffer, "applied_endpoint_rotation_chain", return_value=None
            ),
            self.assertRaisesRegex(
                PullBufferError, "LEGACY_329_RECOVERY_FENCE_MISMATCH"
            ),
        ):
            _legacy_329_recovery_fence(
                connection, rows, request, replay=False
            )

    def test_legacy_329_fences_and_projection_delta_are_exact(self) -> None:
        self.assertEqual(329, LEGACY_329_DURABLE_FENCE["issue_number"])
        self.assertEqual(16, LEGACY_329_DURABLE_FENCE["admission_message_id"])
        self.assertEqual([3003, 3004], [row["id"] for row in LEGACY_329_NORMALIZATION_EVENTS])
        self.assertEqual(
            LEGACY_329_NORMALIZATION_EVENTS[0]["payload_sha256"],
            hashlib.sha256(canonical_json({
                "allocation_class": "RETAINED", "item_version": 6, "status": "HOLD"
            }).encode()).hexdigest(),
        )
        bound = {"title": "Stable", "labels": ["delivery"], "updated_at": "one"}
        projected = {
            **bound,
            "labels": ["delivery", "agent-ready"],
            "updated_at": "two",
            "_projection_version": 3,
        }
        self.assertEqual(
            _legacy_recovery_stable_source(bound),
            _legacy_recovery_stable_source(projected),
        )
        self.assertNotEqual(
            _legacy_recovery_stable_source(bound),
            _legacy_recovery_stable_source({**projected, "title": "Drift"}),
        )


if __name__ == "__main__":
    unittest.main()
