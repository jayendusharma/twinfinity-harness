from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
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
    load_registry_config,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
import kanban_pull_buffer as pull_buffer  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA,
    CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON,
    LEGACY_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA,
    LEGACY_UNCLAIMED_ADMISSION_RECOVERY_REASON,
    PullBufferError,
    UNCLAIMED_ADMISSION_RECOVERY_SCHEMA,
    _legacy_recovery_stable_source,
    cutover_held_unclaimed_admission_recovery_notice_payload,
    digest_json,
    legacy_unclaimed_admission_recovery_notice_payload,
    recover_unclaimed_admission,
)
from portfolio_convergence import PortfolioConvergence  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)
from role_executor_transport import (  # noqa: E402
    RoleExecutorManagerNotSubmitted,
    RoleExecutorManagerSubmission,
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
        self.registry_config = apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="unclaimed-admission-recovery-tests",
        )
        source_config = load_registry_config(
            ROOT / "references" / "twinfinity-executor-registry.toml",
            codex_home=ROOT / "references",
            profile_template_root=ROOT / "references",
        )
        self.registry_config = replace(
            self.registry_config,
            endpoints={
                **self.registry_config.endpoints,
                **{
                    endpoint_id: source_config.endpoints[endpoint_id]
                    for endpoint_id in (
                        "role.development.v6",
                        "role.sre.v6",
                    )
                },
            },
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _admitted(self, role: str = "development", issue: int = 273) -> dict:
        endpoint = str(current_endpoint(self.store.connection, role)["endpoint_id"])
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

    def _claim_recovery_notice(
        self, request: dict, *, claim: bool = True
    ) -> tuple[dict, str]:
        notice_id = int(request["recovery_notice_message_id"])
        reserved, token = reserve_attempt(
            self.store.connection,
            role="planner",
            endpoint_id=request["planner_session_id"],
            target_kind="message",
            target_key=str(notice_id),
            now="2026-08-26T10:07:30Z",
            precondition=lambda _connection: None,
        )
        unit = stable_systemd_unit("planner", "message", str(notice_id))
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=hashlib.md5(unit.encode()).hexdigest(),
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-26T10:07:30Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9275,
            now="2026-08-26T10:07:31Z",
        )
        if claim:
            self.store.claim_message(
                notice_id,
                request["planner_session_id"],
                "2026-08-26T10:07:32Z",
            )
        return running, token

    def _launch_exact_child(
        self,
        *,
        endpoint_id: str,
        target_kind: str,
        target_key: str,
        process_id: int,
        terminal: bool,
    ) -> tuple[RoleExecutorManagerSubmission, dict, str]:
        event_type = (
            "SESSION_WAKE_MANAGER_SUBMISSION_INTENT"
            if target_kind == "message"
            else "TERMINAL_WATCH_MANAGER_SUBMISSION_INTENT"
        )
        intent = self.store.connection.execute(
            "SELECT created_at FROM coordination_events WHERE event_type=? "
            "ORDER BY id DESC LIMIT 1",
            (event_type,),
        ).fetchone()
        self.assertIsNotNone(intent)
        intent_recorded_at = str(intent["created_at"])
        role = endpoint_id.split(".")[1]
        ordinal = int(
            self.store.connection.execute(
                "SELECT COUNT(*) FROM executor_attempts "
                "WHERE target_kind=? AND target_key=?",
                (target_kind, target_key),
            ).fetchone()[0]
        )
        invocation_id = hashlib.sha256(
            (
                f"{endpoint_id}:{target_kind}:{target_key}:"
                f"{intent_recorded_at}:{ordinal}"
            ).encode()
        ).hexdigest()[:32]
        unit = stable_systemd_unit(role, target_kind, target_key)
        reserved, token = reserve_attempt(
            self.store.connection,
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            now=intent_recorded_at,
            precondition=lambda connection: attempt_lineage_for_target(
                connection, target_kind, target_key
            ),
        )
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=invocation_id,
            systemd_control_group=f"/user.slice/{unit}",
            now=intent_recorded_at,
        )
        child = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=process_id,
            now=intent_recorded_at,
        )
        if terminal:
            child = transition_attempt(
                self.store.connection,
                attempt_id=reserved["attempt_id"],
                token=token,
                expected_version=child["version"],
                new_state="COMPLETE",
                exit_code=0,
                now=intent_recorded_at,
            )
        return (
            RoleExecutorManagerSubmission(
                systemd_unit=unit,
                systemd_invocation_id=invocation_id,
            ),
            child,
            token,
        )

    def _run_to_third_attempt(self, lineage: dict) -> CoordinationSupervisor:
        launches = 0

        def launcher(session_id: str, message_id: int):
            nonlocal launches
            launches += 1
            receipt, _child, _token = self._launch_exact_child(
                endpoint_id=session_id,
                target_kind="message",
                target_key=str(message_id),
                process_id=9272 + launches,
                terminal=True,
            )
            return receipt

        def terminal_watch_launcher(session_id: str, watch_key: str):
            receipt, _child, _token = self._launch_exact_child(
                endpoint_id=session_id,
                target_kind="terminal_watch",
                target_key=watch_key,
                process_id=9274,
                terminal=True,
            )
            return receipt

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=launcher,
            terminal_watch_launcher=terminal_watch_launcher,
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
            "executor_attempts",
        )
        rows = {
            table: [dict(row) for row in self.store.connection.execute(
                f"SELECT * FROM {table} ORDER BY rowid"
            ).fetchall()]
            for table in tables
        }
        return hashlib.sha256(canonical_json(rows).encode()).hexdigest()

    def _assert_recovery_rejected_without_writes(
        self,
        request: dict,
        error: str,
        *,
        attempt_id: str | None = None,
        executor_token: str | None = None,
        compatibility_descriptor: dict | None = None,
    ) -> None:
        baseline = self._fingerprint()
        with self.assertRaisesRegex(PullBufferError, error):
            recover_unclaimed_admission(
                self.store,
                request,
                now="2026-08-26T10:08:00Z",
                attempt_id=attempt_id,
                executor_token=executor_token,
                compatibility_descriptor=compatibility_descriptor,
            )
        self.assertEqual(baseline, self._fingerprint())

    def _apply_development_endpoint(
        self, endpoint_id: str, *, operation_key: str, now: str
    ) -> dict:
        return self._apply_role_endpoint(
            "development", endpoint_id, operation_key=operation_key, now=now
        )

    def _apply_role_endpoint(
        self, role: str, endpoint_id: str, *, operation_key: str, now: str
    ) -> dict:
        config = replace(
            self.registry_config,
            roles={
                **self.registry_config.roles,
                role: self.registry_config.endpoints[endpoint_id],
            },
        )
        aliases, aliases_sha256 = load_legacy_alias_fixture(
            ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=aliases_sha256,
        )
        return apply_plan(
            self.store.connection,
            plan=plan,
            operation_key=operation_key,
            expected_plan_sha256=plan["plan_sha256"],
            now=now,
        )

    def _legacy_compatible_transaction(self) -> tuple[dict, dict]:
        """Build a full synthetic equivalent of the one-time legacy lineage."""

        historical_endpoint = "role.development.v3"
        current_endpoint_id = "role.development.v4"
        self._apply_development_endpoint(
            historical_endpoint,
            operation_key="legacy-compatible-historical-route",
            now="2026-08-26T09:00:00Z",
        )
        lineage = self._admitted(issue=812)
        self.assertEqual(historical_endpoint, lineage["endpoint"])

        def manager_not_submitted(*_args: object) -> RoleExecutorManagerSubmission:
            raise RoleExecutorManagerNotSubmitted()

        legacy_supervisor = CoordinationSupervisor(
            self.store,
            launcher=manager_not_submitted,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_args: False,
        )
        for timestamp in (
            "2026-08-26T10:00:06Z",
            "2026-08-26T10:01:07Z",
        ):
            legacy_supervisor.run_once(timestamp)
        legacy_message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (lineage["message_id"],),
        ).fetchone()
        legacy_wake_key, should_launch = legacy_supervisor._reserve_wake(
            legacy_message, "2026-08-26T10:03:08Z"
        )
        self.assertTrue(should_launch)
        self.assertIsNotNone(legacy_wake_key)
        legacy_wake = self.store.connection.execute(
            "SELECT state,attempts FROM coordination_wakes WHERE message_id=?",
            (lineage["message_id"],),
        ).fetchone()
        self.assertEqual(("INFLIGHT", 3), tuple(legacy_wake))

        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (lineage["message_id"],),
        ).fetchone()
        payload = json.loads(message["payload_json"])
        watch_key = (
            f"terminal:{REPOSITORY}:issue:{lineage['issue']}:"
            f"generation:{payload['generation']}"
        )
        normalized_at = "2026-08-26T10:04:00Z"
        hold_reason = "WAKE_RETRY_EXHAUSTED"
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, lineage["issue"]),
        ).fetchone()
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_messages SET state='HOLD', updated_at=?, "
                "last_error=? WHERE id=? AND state='PREPARED' AND claimed_by IS NULL",
                (normalized_at, hold_reason, lineage["message_id"]),
            )
            self.store.connection.execute(
                "UPDATE coordination_wakes SET state='HOLD', process_id=NULL, "
                "updated_at=?, last_error=? WHERE message_id=? AND attempts=3",
                (normalized_at, hold_reason, lineage["message_id"]),
            )
        normalized = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=lineage["issue"],
            status="HOLD",
            allocation_class="RETAINED",
            generation=int(item["generation"]),
            accountable_session_id=historical_endpoint,
            lease_manifest_sha256=item["lease_manifest_sha256"],
            development_units=int(item["development_units"]),
            shared_units=int(item["shared_units"]),
            sre_units=int(item["sre_units"]),
            expected_source_sha256=item["source_payload_sha256"],
            expected_version=int(item["version"]),
            now=normalized_at,
        )
        normalized_version = int(normalized["version"])

        historical_attempt, historical_token = self._reserve_running_attempt(lineage)
        transition_attempt(
            self.store.connection,
            attempt_id=historical_attempt["attempt_id"],
            token=historical_token,
            expected_version=historical_attempt["version"],
            new_state="HOLD",
            exit_code=0,
            last_error="EXECUTOR_TARGET_NO_PROGRESS",
            now="2026-08-26T10:04:30Z",
        )
        change = self._apply_development_endpoint(
            current_endpoint_id,
            operation_key="legacy-compatible-current-route",
            now="2026-08-26T10:05:00Z",
        )
        projected = {
            **lineage["source_payload"],
            "labels": [*lineage["source_payload"]["labels"], {"name": "agent-ready"}],
            "updated_at": "2026-08-26T10:05:01Z",
            "_projection_version": 4,
        }
        current_source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=lineage["issue"],
            payload=projected,
            source_updated_at=projected["updated_at"],
            fetched_at="2026-08-26T10:05:02Z",
        )

        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (lineage["message_id"],),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT * FROM coordination_wakes WHERE message_id=?",
            (lineage["message_id"],),
        ).fetchone()
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, lineage["issue"]),
        ).fetchone()
        finalization = self.store.connection.execute(
            "SELECT * FROM portfolio_ready_finalizations "
            "WHERE repository=? AND issue_number=? AND generation=?",
            (REPOSITORY, lineage["issue"], payload["generation"]),
        ).fetchone()
        events = self.store.connection.execute(
            "SELECT id,event_type,entity_key,payload_sha256,created_at "
            "FROM coordination_events WHERE entity_key=? AND created_at=? "
            "AND event_type IN ('TERMINAL_WATCH_COMPLETED','ISSUE_STATUS_CHANGED') "
            "ORDER BY id",
            (f"{REPOSITORY}:issue:{lineage['issue']}", normalized_at),
        ).fetchall()
        executor_attempt = self.store.connection.execute(
            "SELECT attempt_id,role,endpoint_id,target_kind,target_key,state,"
            "exit_code,last_error FROM executor_attempts WHERE attempt_id=?",
            (historical_attempt["attempt_id"],),
        ).fetchone()
        planner = current_endpoint(self.store.connection, "planner")
        request = {
            "schema": UNCLAIMED_ADMISSION_RECOVERY_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": lineage["issue"],
            "planner_session_id": planner["endpoint_id"],
            "generation": payload["generation"],
            "retained_item_version": int(item["version"]),
            "source_payload_sha256": payload["source"]["payload_sha256"],
            "current_source_payload_sha256": current_source.payload_sha256,
            "accountable_session_id": item["accountable_session_id"],
            "lease_manifest_sha256": item["lease_manifest_sha256"],
            "admission_message_id": lineage["message_id"],
            "admission_payload_sha256": message["payload_sha256"],
            "wake_key": wake["wake_key"],
            "wake_attempts": int(wake["attempts"]),
            "target_progress_sha256": wake["target_progress_sha256"],
            "watch_key": watch_key,
            "recovery_notice_message_id": 1,
            "recovery_reason": LEGACY_UNCLAIMED_ADMISSION_RECOVERY_REASON,
        }
        evidence = {
            **{key: request[key] for key in (
                "repository", "issue_number", "generation",
                "retained_item_version", "source_payload_sha256",
                "accountable_session_id", "lease_manifest_sha256",
                "admission_message_id", "admission_payload_sha256", "wake_key",
                "wake_attempts", "target_progress_sha256", "watch_key",
            )},
            "historical_recipient": historical_endpoint,
            "hold_reason": hold_reason,
            "wake_last_attempt_at": wake["last_attempt_at"],
            "watch_updated_at": watch["updated_at"],
            "item_updated_at": item["updated_at"],
            "ready_candidate_id": int(finalization["ready_candidate_id"]),
            "ready_finalization_id": int(finalization["id"]),
            "readiness_campaign_id": int(finalization["campaign_id"]),
            "readiness_receipt_id": int(finalization["receipt_id"]),
            "finalization_dirty_event_id": int(finalization["dirty_event_id"]),
            "ready_finalization_sha256": finalization["finalization_sha256"],
            "normalization_events": [dict(event) for event in events],
            "endpoint_rotation": {
                "change_id": change["change_id"],
                "change_version": int(change["version"]),
                "before_item_version": normalized_version,
                "not_before": normalized_at,
            },
            "executor_attempt": dict(executor_attempt),
        }
        descriptor = {
            "schema": LEGACY_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA,
            "evidence": evidence,
            "evidence_sha256": digest_json(evidence),
        }
        descriptor_sha256 = digest_json(descriptor)
        notice_id = self.store.enqueue_message(
            idempotency_key=(
                "legacy-unclaimed-admission-recovery:"
                f"{descriptor_sha256}"
            ),
            recipient_session_id=request["planner_session_id"],
            topic="coordination.notice",
            payload=legacy_unclaimed_admission_recovery_notice_payload(
                request, descriptor_sha256
            ),
            now="2026-08-26T10:05:03Z",
        )
        request["recovery_notice_message_id"] = notice_id
        return request, descriptor

    def _cutover_held_transaction(
        self, role: str = "sre", issue: int = 830
    ) -> tuple[dict, dict]:
        """Build one exact never-claimed lineage retained for role cutover."""

        historical_endpoint = f"role.{role}.v3"
        current_endpoint_id = f"role.{role}.v6"
        self._apply_role_endpoint(
            role,
            historical_endpoint,
            operation_key=f"cutover-held-{role}-historical-route",
            now="2026-08-26T09:00:00Z",
        )
        lineage = self._admitted(role=role, issue=issue)
        self.assertEqual(historical_endpoint, lineage["endpoint"])
        launched_child: dict[str, object] = {}

        def launcher(session_id: str, message_id: int):
            receipt, child, token = self._launch_exact_child(
                endpoint_id=session_id,
                target_kind="message",
                target_key=str(message_id),
                process_id=9273,
                terminal=False,
            )
            launched_child.update({"attempt": child, "token": token})
            return receipt

        def terminal_watch_launcher(session_id: str, watch_key: str):
            receipt, _child, _token = self._launch_exact_child(
                endpoint_id=session_id,
                target_kind="terminal_watch",
                target_key=watch_key,
                process_id=9274,
                terminal=True,
            )
            return receipt

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=launcher,
            terminal_watch_launcher=terminal_watch_launcher,
            process_checker=lambda *_args: False,
        )
        supervisor.run_once("2026-08-26T10:00:06Z")
        wake = self.store.connection.execute(
            "SELECT * FROM coordination_wakes WHERE message_id=?",
            (lineage["message_id"],),
        ).fetchone()
        self.assertEqual(("INFLIGHT", 1), (wake["state"], int(wake["attempts"])))
        self.assertEqual({"attempt", "token"}, set(launched_child))
        historical_attempt = dict(launched_child["attempt"])
        historical_token = str(launched_child["token"])
        historical_attempt = transition_attempt(
            self.store.connection,
            attempt_id=historical_attempt["attempt_id"],
            token=historical_token,
            expected_version=historical_attempt["version"],
            new_state="HOLD",
            exit_code=0,
            last_error="EXECUTOR_TARGET_NO_PROGRESS",
            terminal_progress_sha256=wake["target_progress_sha256"],
            now="2026-08-26T10:00:30Z",
        )
        supervisor._record_launch_failure(
            wake["wake_key"], "2026-08-26T10:00:31Z"
        )
        planner = current_endpoint(self.store.connection, "planner")
        self.store.hold_prepared_message(
            message_id=lineage["message_id"],
            expected_payload_sha256=lineage["message"]["payload_sha256"],
            reason="SUPERSEDED_BY_ROLE_ENDPOINT_CUTOVER",
            session_id=planner["endpoint_id"],
            now="2026-08-26T10:01:00Z",
        )
        supervisor._complete_stale_wakes("2026-08-26T10:01:01Z")
        held_item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, issue),
        ).fetchone()
        change = self._apply_role_endpoint(
            role,
            current_endpoint_id,
            operation_key=f"cutover-held-{role}-current-route",
            now="2026-08-26T10:02:00Z",
        )

        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (lineage["message_id"],),
        ).fetchone()
        payload = json.loads(message["payload_json"])
        watch_key = (
            f"terminal:{REPOSITORY}:issue:{issue}:"
            f"generation:{payload['generation']}"
        )
        wake = self.store.connection.execute(
            "SELECT * FROM coordination_wakes WHERE message_id=?",
            (lineage["message_id"],),
        ).fetchone()
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, issue),
        ).fetchone()
        finalization = self.store.connection.execute(
            "SELECT * FROM portfolio_ready_finalizations "
            "WHERE repository=? AND issue_number=? AND generation=?",
            (REPOSITORY, issue, payload["generation"]),
        ).fetchone()
        events = self.store.connection.execute(
            "SELECT id,event_type,entity_key,payload_sha256,created_at "
            "FROM coordination_events WHERE "
            "(event_type='MESSAGE_HELD' AND entity_key=?) OR "
            "(event_type='WAKE_COMPLETED' AND entity_key=?) ORDER BY id",
            (f"message:{lineage['message_id']}", wake["wake_key"]),
        ).fetchall()
        executor_attempt = self.store.connection.execute(
            "SELECT attempt_id,role,endpoint_id,target_kind,target_key,"
            "target_progress_sha256,terminal_progress_sha256,lineage_repository,"
            "lineage_issue_number,lineage_generation,lineage_lease_sha256,"
            "lineage_sha256,state,exit_code,updated_at,last_error "
            "FROM executor_attempts WHERE attempt_id=?",
            (historical_attempt["attempt_id"],),
        ).fetchone()
        request = {
            "schema": UNCLAIMED_ADMISSION_RECOVERY_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": issue,
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
            "recovery_notice_message_id": 1,
            "recovery_reason": CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_REASON,
        }
        evidence = {
            **{key: request[key] for key in (
                "repository", "issue_number", "generation",
                "retained_item_version", "source_payload_sha256",
                "current_source_payload_sha256", "accountable_session_id",
                "lease_manifest_sha256", "admission_message_id",
                "admission_payload_sha256", "wake_key", "wake_attempts",
                "target_progress_sha256", "watch_key",
            )},
            "role": role,
            "historical_recipient": historical_endpoint,
            "hold_reason": "SUPERSEDED_BY_ROLE_ENDPOINT_CUTOVER",
            "message_updated_at": message["updated_at"],
            "wake_last_attempt_at": wake["last_attempt_at"],
            "wake_updated_at": wake["updated_at"],
            "watch_updated_at": watch["updated_at"],
            "item_updated_at": item["updated_at"],
            "capacity": {
                key: int(item[key]) for key in (
                    "development_units", "shared_units", "sre_units"
                )
            },
            "ready_candidate_id": int(finalization["ready_candidate_id"]),
            "ready_finalization_id": int(finalization["id"]),
            "readiness_campaign_id": int(finalization["campaign_id"]),
            "readiness_receipt_id": int(finalization["receipt_id"]),
            "finalization_dirty_event_id": int(finalization["dirty_event_id"]),
            "ready_finalization_sha256": finalization["finalization_sha256"],
            "cutover_events": [dict(event) for event in events],
            "endpoint_rotation": {
                "change_id": change["change_id"],
                "change_version": int(change["version"]),
                "before_item_version": int(held_item["version"]),
                "not_before": message["updated_at"],
            },
            "executor_attempt": dict(executor_attempt),
        }
        descriptor = {
            "schema": CUTOVER_HELD_UNCLAIMED_ADMISSION_RECOVERY_DESCRIPTOR_SCHEMA,
            "evidence": evidence,
            "evidence_sha256": digest_json(evidence),
        }
        descriptor_sha256 = digest_json(descriptor)
        notice_id = self.store.enqueue_message(
            idempotency_key=(
                "cutover-held-unclaimed-admission-recovery:"
                f"{descriptor_sha256}"
            ),
            recipient_session_id=request["planner_session_id"],
            topic="coordination.notice",
            payload=cutover_held_unclaimed_admission_recovery_notice_payload(
                request, descriptor_sha256
            ),
            now="2026-08-26T10:02:01Z",
        )
        request["recovery_notice_message_id"] = notice_id
        return request, descriptor

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
        planner_attempt, planner_token = self._claim_recovery_notice(request)
        units = self.store.connection.execute(
            "SELECT development_units,shared_units,sre_units FROM coordination_items "
            "WHERE repository=? AND issue_number=?", (REPOSITORY, lineage["issue"]),
        ).fetchone()
        result = recover_unclaimed_admission(
            self.store,
            request,
            now="2026-08-26T10:08:00Z",
            attempt_id=planner_attempt["attempt_id"],
            executor_token=planner_token,
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
                self.store,
                request,
                now="2026-08-26T10:08:01Z",
                attempt_id=planner_attempt["attempt_id"],
                executor_token=planner_token,
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
                self.store,
                request,
                now="2026-08-26T10:09:03Z",
                attempt_id=planner_attempt["attempt_id"],
                executor_token=planner_token,
            ),
        )
        self.assertEqual(downstream, self._fingerprint())

    def test_recovery_requires_the_current_planner_without_writes(self) -> None:
        request = self._exhaust(self._admitted())
        attempt, token = self._claim_recovery_notice(request)
        request["planner_session_id"] = DEVELOPMENT
        self._assert_recovery_rejected_without_writes(
            request,
            "CURRENT_PLANNER_ENDPOINT_REQUIRED",
            attempt_id=attempt["attempt_id"],
            executor_token=token,
        )

    def test_recovery_authenticates_claimed_notice_attempt_and_token(self) -> None:
        request = self._exhaust(self._admitted())
        planner_attempt, planner_token = self._claim_recovery_notice(
            request, claim=False
        )
        self._assert_recovery_rejected_without_writes(
            request,
            "UNCLAIMED_ADMISSION_RECOVERY_NOTICE_NOT_CLAIMED",
            attempt_id=planner_attempt["attempt_id"],
            executor_token=planner_token,
        )
        self.store.claim_message(
            request["recovery_notice_message_id"],
            request["planner_session_id"],
            "2026-08-26T10:07:32Z",
        )
        for name, attempt_id, token, error in (
            (
                "missing-attempt",
                None,
                planner_token,
                "UNCLAIMED_ADMISSION_RECOVERY_ATTEMPT_REQUIRED",
            ),
            (
                "missing-token",
                planner_attempt["attempt_id"],
                None,
                "UNCLAIMED_ADMISSION_RECOVERY_ATTEMPT_REQUIRED",
            ),
            (
                "unknown-attempt",
                "00000000-0000-0000-0000-000000000000",
                planner_token,
                "UNCLAIMED_ADMISSION_RECOVERY_ATTEMPT_NOT_FOUND",
            ),
            (
                "wrong-token",
                planner_attempt["attempt_id"],
                "wrong-token",
                "UNCLAIMED_ADMISSION_RECOVERY_TOKEN_MISMATCH",
            ),
        ):
            with self.subTest(case=name):
                self._assert_recovery_rejected_without_writes(
                    request,
                    error,
                    attempt_id=attempt_id,
                    executor_token=token,
                )

        spoof, spoof_token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT,
            target_kind="message",
            target_key=str(request["recovery_notice_message_id"]),
            now="2026-08-26T10:07:33Z",
            precondition=lambda _connection: None,
        )
        unit = stable_systemd_unit(
            "development", "message", str(request["recovery_notice_message_id"])
        )
        launching = transition_attempt(
            self.store.connection,
            attempt_id=spoof["attempt_id"],
            token=spoof_token,
            expected_version=spoof["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=hashlib.md5(unit.encode()).hexdigest(),
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-26T10:07:33Z",
        )
        spoof = transition_attempt(
            self.store.connection,
            attempt_id=spoof["attempt_id"],
            token=spoof_token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9276,
            now="2026-08-26T10:07:34Z",
        )
        self._assert_recovery_rejected_without_writes(
            request,
            "UNCLAIMED_ADMISSION_RECOVERY_ATTEMPT_BINDING_MISMATCH",
            attempt_id=spoof["attempt_id"],
            executor_token=spoof_token,
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
        attempt, token = self._claim_recovery_notice(request)
        baseline = self._fingerprint()
        for marker in (
            "recovery.after_item",
            "recovery.after_readiness",
            "recovery.after_refill_event",
            "recovery.after_notice_complete",
            "recovery.after_readiness_event",
            "recovery.after_audit_event",
        ):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, marker):
                recover_unclaimed_admission(
                    self.store,
                    request,
                    now="2026-08-26T10:08:00Z",
                    attempt_id=attempt["attempt_id"],
                    executor_token=token,
                    failpoint=lambda point, wanted=marker: (
                        (_ for _ in ()).throw(RuntimeError(point))
                        if point == wanted else None
                    ),
                )
            self.assertEqual(baseline, self._fingerprint())
        wrong = {**request, "lease_manifest_sha256": "f" * 64}
        with self.assertRaises(PullBufferError):
            recover_unclaimed_admission(
                self.store,
                wrong,
                now="2026-08-26T10:08:00Z",
                attempt_id=attempt["attempt_id"],
                executor_token=token,
            )
        self.assertEqual(baseline, self._fingerprint())

    def test_owner_cli_recovers_one_exact_transaction_file(self) -> None:
        request = self._exhaust(self._admitted())
        attempt, token = self._claim_recovery_notice(request)
        request_path = self.root / "recover-unclaimed-admission.json"
        request_path.write_text(canonical_json(request), encoding="utf-8")
        argv = [
            "kanban_pull_buffer.py",
            "recover-unclaimed-admission",
            "--transaction-file",
            str(request_path),
        ]
        baseline = self._fingerprint()
        rejected_output = io.StringIO()
        with (
            patch.object(pull_buffer, "DEFAULT_DATABASE", self.database),
            patch.object(sys, "argv", argv),
            patch.object(
                pull_buffer, "utc_now", return_value="2026-08-26T10:08:00Z"
            ),
            patch.dict(
                "os.environ",
                {
                    "TWINFINITY_EXECUTOR_ATTEMPT_ID": "",
                    "TWINFINITY_EXECUTOR_TOKEN": "",
                },
                clear=False,
            ),
            redirect_stdout(rejected_output),
        ):
            rejected_code = pull_buffer.main()
        rejected = json.loads(rejected_output.getvalue())
        self.assertEqual(1, rejected_code)
        self.assertEqual("HOLD", rejected["phase"])
        self.assertIn("ATTEMPT_REQUIRED", rejected["error"])
        self.assertEqual(baseline, self._fingerprint())

        output = io.StringIO()
        with (
            patch.object(pull_buffer, "DEFAULT_DATABASE", self.database),
            patch.object(sys, "argv", argv),
            patch.object(
                pull_buffer, "utc_now", return_value="2026-08-26T10:08:00Z"
            ),
            patch.dict(
                "os.environ",
                {
                    "TWINFINITY_EXECUTOR_ATTEMPT_ID": attempt["attempt_id"],
                    "TWINFINITY_EXECUTOR_TOKEN": token,
                },
                clear=False,
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

    def test_cutover_held_development_and_sre_recover_and_replay(self) -> None:
        for role, issue in (("development", 829), ("sre", 830)):
            with self.subTest(role=role):
                if role == "sre":
                    self.tearDown()
                    self.setUp()
                request, descriptor = self._cutover_held_transaction(role, issue)
                preserved = {
                    "message": dict(self.store.connection.execute(
                        "SELECT * FROM coordination_messages WHERE id=?",
                        (request["admission_message_id"],),
                    ).fetchone()),
                    "wake": dict(self.store.connection.execute(
                        "SELECT * FROM coordination_wakes WHERE wake_key=?",
                        (request["wake_key"],),
                    ).fetchone()),
                    "watch": dict(self.store.connection.execute(
                        "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                        (request["watch_key"],),
                    ).fetchone()),
                    "attempt": dict(self.store.connection.execute(
                        "SELECT * FROM executor_attempts WHERE attempt_id=?",
                        (descriptor["evidence"]["executor_attempt"]["attempt_id"],),
                    ).fetchone()),
                }
                units = self.store.connection.execute(
                    "SELECT development_units,shared_units,sre_units "
                    "FROM coordination_items WHERE repository=? AND issue_number=?",
                    (REPOSITORY, issue),
                ).fetchone()
                planner_attempt, planner_token = self._claim_recovery_notice(request)
                result = recover_unclaimed_admission(
                    self.store,
                    request,
                    now="2026-08-26T10:03:00Z",
                    attempt_id=planner_attempt["attempt_id"],
                    executor_token=planner_token,
                    compatibility_descriptor=descriptor,
                )
                item = self.store.connection.execute(
                    "SELECT * FROM coordination_items "
                    "WHERE repository=? AND issue_number=?",
                    (REPOSITORY, issue),
                ).fetchone()
                readiness = self.store.connection.execute(
                    "SELECT state FROM portfolio_readiness_current "
                    "WHERE repository=? AND issue_number=?",
                    (REPOSITORY, issue),
                ).fetchone()
                self.assertEqual(
                    ("PREPARED", "NONE", request["generation"] + 1),
                    (item["status"], item["allocation_class"], int(item["generation"])),
                )
                self.assertIsNone(item["accountable_session_id"])
                self.assertIsNone(item["lease_manifest_sha256"])
                self.assertEqual(tuple(units), (
                    item["development_units"], item["shared_units"], item["sre_units"]
                ))
                self.assertEqual("STALE", readiness["state"])
                for table, key, value, name in (
                    (
                        "coordination_messages", "id",
                        request["admission_message_id"], "message",
                    ),
                    ("coordination_wakes", "wake_key", request["wake_key"], "wake"),
                    (
                        "coordination_terminal_watches", "watch_key",
                        request["watch_key"], "watch",
                    ),
                    (
                        "executor_attempts", "attempt_id",
                        descriptor["evidence"]["executor_attempt"]["attempt_id"],
                        "attempt",
                    ),
                ):
                    observed = dict(self.store.connection.execute(
                        f"SELECT * FROM {table} WHERE {key}=?", (value,)
                    ).fetchone())
                    self.assertEqual(preserved[name], observed)
                before_replay = self._fingerprint()
                self.assertEqual(
                    result,
                    recover_unclaimed_admission(
                        self.store,
                        request,
                        now="2026-08-26T10:03:01Z",
                        attempt_id=planner_attempt["attempt_id"],
                        executor_token=planner_token,
                        compatibility_descriptor=descriptor,
                    ),
                )
                self.assertEqual(before_replay, self._fingerprint())

    def test_cutover_held_drift_and_claim_evidence_are_write_free(self) -> None:
        request, descriptor = self._cutover_held_transaction()
        invalid = json.loads(canonical_json(descriptor))
        invalid["evidence"]["endpoint_rotation"]["change_id"] = "f" * 64
        invalid["evidence_sha256"] = digest_json(invalid["evidence"])
        self._assert_recovery_rejected_without_writes(
            request,
            "CUTOVER_HELD_RECOVERY_FENCE_MISMATCH",
            compatibility_descriptor=invalid,
        )
        mismatched = json.loads(canonical_json(descriptor))
        mismatched["evidence"]["role"] = "development"
        mismatched["evidence_sha256"] = digest_json(mismatched["evidence"])
        self._assert_recovery_rejected_without_writes(
            request,
            "CUTOVER_HELD_RECOVERY_DESCRIPTOR_INVALID",
            compatibility_descriptor=mismatched,
        )
        self.store._event(
            "MESSAGE_CLAIMED",
            f"message:{request['admission_message_id']}",
            {"adversarial_fixture": True},
            "2026-08-26T10:02:30Z",
        )
        self._assert_recovery_rejected_without_writes(
            request,
            "UNCLAIMED_ADMISSION_CLAIM_EVIDENCE_PRESENT",
            compatibility_descriptor=descriptor,
        )

    def test_cutover_held_recovery_rolls_back_and_cli_recovers(self) -> None:
        request, descriptor = self._cutover_held_transaction()
        planner_attempt, planner_token = self._claim_recovery_notice(request)
        baseline = self._fingerprint()
        with self.assertRaisesRegex(RuntimeError, "recovery.after_item"):
            recover_unclaimed_admission(
                self.store,
                request,
                now="2026-08-26T10:03:00Z",
                attempt_id=planner_attempt["attempt_id"],
                executor_token=planner_token,
                compatibility_descriptor=descriptor,
                failpoint=lambda point: (
                    (_ for _ in ()).throw(RuntimeError(point))
                    if point == "recovery.after_item" else None
                ),
            )
        self.assertEqual(baseline, self._fingerprint())

        request_path = self.root / "cutover-held-recovery.json"
        descriptor_path = self.root / "cutover-held-descriptor.json"
        request_path.write_text(canonical_json(request), encoding="utf-8")
        descriptor_path.write_text(canonical_json(descriptor), encoding="utf-8")
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
                    "--compatibility-descriptor-file",
                    str(descriptor_path),
                ],
            ),
            patch.object(
                pull_buffer, "utc_now", return_value="2026-08-26T10:03:00Z"
            ),
            patch.dict(
                "os.environ",
                {
                    "TWINFINITY_EXECUTOR_ATTEMPT_ID": planner_attempt["attempt_id"],
                    "TWINFINITY_EXECUTOR_TOKEN": planner_token,
                },
                clear=False,
            ),
            redirect_stdout(output),
        ):
            return_code = pull_buffer.main()
        receipt = json.loads(output.getvalue())
        self.assertEqual(0, return_code)
        self.assertEqual("COMPLETE", receipt["phase"])
        self.assertEqual("RECOVERED", receipt["result"]["state"])

    def test_synthetic_legacy_transaction_rejects_drift_and_recovers(self) -> None:
        request, descriptor = self._legacy_compatible_transaction()
        invalid = json.loads(canonical_json(descriptor))
        invalid["evidence_sha256"] = "0" * 64
        self._assert_recovery_rejected_without_writes(
            request,
            "LEGACY_RECOVERY_DESCRIPTOR_INVALID",
            compatibility_descriptor=invalid,
        )
        drifted = json.loads(canonical_json(descriptor))
        drifted["evidence"]["normalization_events"][0]["payload_sha256"] = "f" * 64
        drifted["evidence_sha256"] = digest_json(drifted["evidence"])
        self._assert_recovery_rejected_without_writes(
            request,
            "LEGACY_RECOVERY_FENCE_MISMATCH",
            compatibility_descriptor=drifted,
        )

        preserved = {
            "message": dict(self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (request["admission_message_id"],),
            ).fetchone()),
            "wake": dict(self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE wake_key=?",
                (request["wake_key"],),
            ).fetchone()),
            "watch": dict(self.store.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
                (request["watch_key"],),
            ).fetchone()),
            "attempt": dict(self.store.connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (descriptor["evidence"]["executor_attempt"]["attempt_id"],),
            ).fetchone()),
        }
        units = self.store.connection.execute(
            "SELECT development_units,shared_units,sre_units FROM coordination_items "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, request["issue_number"]),
        ).fetchone()
        attempt, token = self._claim_recovery_notice(request)
        request_path = self.root / "legacy-compatible-recovery.json"
        descriptor_path = self.root / "legacy-compatible-descriptor.json"
        request_path.write_text(canonical_json(request), encoding="utf-8")
        descriptor_path.write_text(canonical_json(descriptor), encoding="utf-8")
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
                    "--compatibility-descriptor-file",
                    str(descriptor_path),
                ],
            ),
            patch.object(
                pull_buffer, "utc_now", return_value="2026-08-26T10:06:00Z"
            ),
            patch.dict(
                "os.environ",
                {
                    "TWINFINITY_EXECUTOR_ATTEMPT_ID": attempt["attempt_id"],
                    "TWINFINITY_EXECUTOR_TOKEN": token,
                },
                clear=False,
            ),
            redirect_stdout(output),
        ):
            return_code = pull_buffer.main()
        receipt = json.loads(output.getvalue())
        self.assertEqual(0, return_code)
        self.assertEqual("COMPLETE", receipt["phase"])
        result = receipt["result"]
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, request["issue_number"]),
        ).fetchone()
        readiness = self.store.connection.execute(
            "SELECT state FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, request["issue_number"]),
        ).fetchone()
        self.assertEqual(
            ("PREPARED", "NONE", request["generation"] + 1),
            (item["status"], item["allocation_class"], int(item["generation"])),
        )
        self.assertIsNone(item["accountable_session_id"])
        self.assertIsNone(item["lease_manifest_sha256"])
        self.assertEqual(request["current_source_payload_sha256"], item["source_payload_sha256"])
        self.assertEqual(tuple(units), (
            item["development_units"], item["shared_units"], item["sre_units"]
        ))
        self.assertEqual("STALE", readiness["state"])
        for table, key, value in (
            ("coordination_messages", "id", request["admission_message_id"]),
            ("coordination_wakes", "wake_key", request["wake_key"]),
            ("coordination_terminal_watches", "watch_key", request["watch_key"]),
            (
                "executor_attempts",
                "attempt_id",
                descriptor["evidence"]["executor_attempt"]["attempt_id"],
            ),
        ):
            observed = dict(self.store.connection.execute(
                f"SELECT * FROM {table} WHERE {key}=?", (value,)
            ).fetchone())
            name = {
                "coordination_messages": "message",
                "coordination_wakes": "wake",
                "coordination_terminal_watches": "watch",
                "executor_attempts": "attempt",
            }[table]
            self.assertEqual(preserved[name], observed)
        before_replay = self._fingerprint()
        self.assertEqual(
            result,
            recover_unclaimed_admission(
                self.store,
                request,
                now="2026-08-26T10:06:01Z",
                attempt_id=attempt["attempt_id"],
                executor_token=token,
                compatibility_descriptor=descriptor,
            ),
        )
        self.assertEqual(before_replay, self._fingerprint())

    def test_legacy_projection_delta_is_narrow(self) -> None:
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
