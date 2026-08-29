from __future__ import annotations

from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from tests.delivery_identity_fixture import synthetic_delivery_identity  # noqa: E402
import kanban_pull_buffer  # noqa: E402
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
)
from executor_registry import ensure_executor_registry_schema  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    ensure_pull_buffer_schema,
    register_candidate,
)
from kanban_readiness import (  # noqa: E402
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    ReadinessError,
    _validate_receipt,
    apply_readiness_resolution,
    attach,
    claim_readiness_resolution_context,
    dispatch,
    ensure_schema as ensure_readiness_schema,
    execute_readiness_resolution_action,
    pickup_receipt,
    register,
    stage_receipt,
)
from portfolio_graph import replace_graph  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from tests.reviewed_endpoint_catalog_fixture import (  # noqa: E402
    reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
ISSUE = 7
MAIN = "a" * 40
NOW = "2026-08-25T05:00:00Z"
CLAIMED_AT = "2026-08-25T05:01:00Z"
APPLIED_AT = "2026-08-25T05:02:00Z"
PLANNER = "role.planner.v2"
SRE = "role.sre.v4"


class ResolutionHarness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.skill_root = Path(__file__).resolve().parents[1]
        self.catalog_context = reviewed_current_endpoint_catalog(
            self.skill_root, Path(self.temporary.name)
        )
        self.endpoint_config = self.catalog_context.__enter__()
        self.root = Path(self.temporary.name) / "coordination"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        ensure_executor_registry_schema(self.store.connection)
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        self._install_endpoints()
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload={
                "_projection_version": 3,
                "number": ISSUE,
                "title": "Typed readiness resolution",
                "state": "open",
                "updated_at": NOW,
                "milestone": {"number": 1, "title": "Sprint", "state": "open"},
            },
            source_updated_at=NOW,
            fetched_at=NOW,
        )
        self.source_sha256 = snapshot.payload_sha256
        self.item = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=ISSUE,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.source_sha256,
            expected_version=0,
            now=NOW,
        )
        self._install_graph()
        self.initial_packet = self._candidate_packet("initial")
        self.initial_candidate = self._register_candidate(
            self.initial_packet, "initial", NOW
        )
        self.desired_packet = self._candidate_packet("corrected")
        self.desired_candidate_sha256 = digest_json(self.desired_packet)
        self.plan = self._plan()
        self.registered = register(self.store.connection, self.plan, now=NOW)
        dispatched = dispatch(
            self.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]
        self.worker_message_id = int(dispatched["message_id"])
        self.worker_attempt_id = "77777777-7777-4777-8777-777777777777"
        self.worker_token = f"executor-token:{self.worker_attempt_id}"
        self._start_worker()

    def close(self) -> None:
        self.store.close()
        self.catalog_context.__exit__(None, None, None)
        self.temporary.cleanup()

    def _install_endpoints(self) -> None:
        aliases, alias_sha256 = load_legacy_alias_fixture(
            self.skill_root / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.store.connection,
            self.endpoint_config,
            aliases,
            alias_fixture_sha256=alias_sha256,
        )
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="readiness-resolution-flow-fixture",
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )

    def _install_graph(self) -> None:
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
                        "node_key": f"issue:{ISSUE}",
                        "issue_number": ISSUE,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent outcome",
                        "lane_key": "lane-resolution",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": 1,
                        "estimate_units": 1,
                        "development_units": 1,
                        "shared_units": 0,
                        "sre_units": 0,
                        "source_payload_sha256": self.source_sha256,
                        "ready_at": NOW,
                    }
                ],
                "relations": [],
            },
            now=NOW,
        )

    def _policy(self) -> dict:
        return dict(
            self.store.connection.execute(
                """
                SELECT policy.* FROM coordination_capacity_current current
                JOIN coordination_capacity_policies policy
                  ON policy.repository=current.repository
                 AND policy.version=current.version
                WHERE current.repository=?
                """,
                (REPOSITORY,),
            ).fetchone()
        )

    def _candidate_packet(self, suffix: str) -> dict:
        policy = self._policy()
        return {
            "schema": "twinfinity-kanban-pull-buffer/v2",
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": 1,
            "item_version_at_preparation": int(self.item["version"]),
            "source_payload_sha256": self.source_sha256,
            "accepted_main_at_preparation": MAIN,
            "portfolio_graph_version": 1,
            "capacity_policy": {
                "version": int(policy["version"]),
                "development_limit": int(policy["development_limit"]),
                "shared_limit": int(policy["shared_limit"]),
                "sre_limit": int(policy["sre_limit"]),
            },
            "state": "PREPARED_NOT_READY",
            "verticality": "END_TO_END",
            "owner_visible_outcome": "One bounded typed readiness resolution.",
            "capacity_on_activation": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "precomputed_collision_matrix": [
                {
                    "other_issue": 999,
                    "disposition": "DISJOINT",
                    "reason": "No shared mutable surface.",
                }
            ],
            "preparation_complete": ["The vertical packet is complete."],
            "promotion_checks_after_predecessor": ["Revalidate exact bindings."],
            "hard_stops": ["No writer before atomic admission."],
            "promotion_trigger": f"Planner resolution artifact {suffix}.",
        }

    def _candidate_path(self, packet: dict, suffix: str) -> Path:
        directory = self.root / "plans"
        directory.mkdir(exist_ok=True)
        path = directory / f"issue-{ISSUE}-{suffix}.json"
        path.write_text(canonical_json(packet), encoding="utf-8")
        self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": 1,
                    "path": str(path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now=NOW,
        )
        return path

    def _register_candidate(self, packet: dict, suffix: str, now: str) -> dict:
        return register_candidate(
            self.store.connection,
            self.database,
            self._candidate_path(packet, suffix),
            now=now,
        )

    def register_desired_candidate(self) -> dict:
        return self._register_candidate(
            self.desired_packet, "corrected", CLAIMED_AT
        )

    def execute_candidate_action(
        self, message_id: int, context: dict, *, suffix: str = "corrected"
    ) -> dict:
        path = self._candidate_path(self.desired_packet, suffix)
        return execute_readiness_resolution_action(
            self.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            action_sha256=digest_json(self.action()),
            expected_digest=self.action()["expected_digest"],
            action_input={"packet_path": str(path)},
            now=CLAIMED_AT,
        )

    def _plan(self) -> dict:
        policy = self._policy()
        identity, identity_sha256 = synthetic_delivery_identity(
            REPOSITORY, ISSUE, 1
        )
        return {
            "schema": PLAN_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": 1,
            "item_version": int(self.item["version"]),
            "source_payload_sha256": self.source_sha256,
            "accepted_main_sha": MAIN,
            "graph_version": 1,
            "capacity_policy_version": int(policy["version"]),
            "candidate_sha256": self.initial_candidate["candidate_sha256"],
            "worker_role": "sre",
            "phase_summary": "Evaluate the complete candidate in one read-only phase.",
            "delivery_identity": identity,
            "delivery_identity_sha256": identity_sha256,
            "gates": [
                {
                    "gate_key": "complete-review",
                    "description": "The prepared packet needs one owner-safe rebuild.",
                    "requested_evidence": ["One complete exact-binding verdict"],
                }
            ],
        }

    def _start_worker(self) -> None:
        token_sha256 = hashlib.sha256(self.worker_token.encode()).hexdigest()
        self.store.claim_message(self.worker_message_id, SRE, NOW)
        with self.store.transaction():
            self.store.connection.execute(
                """
                INSERT INTO executor_attempts(
                    attempt_id, role, endpoint_id, instance_id, token_sha256,
                    target_kind, target_key, state, process_id, exit_code,
                    heartbeat_at, version, created_at, updated_at
                ) VALUES (?, 'sre', ?, 'resolution-readiness-worker', ?,
                          'message', ?, 'RUNNING', 7007, NULL, ?, 1, ?, ?)
                """,
                (
                    self.worker_attempt_id,
                    SRE,
                    token_sha256,
                    str(self.worker_message_id),
                    NOW,
                    NOW,
                    NOW,
                ),
            )
        attach(
            self.store.connection,
            REPOSITORY,
            ISSUE,
            self.worker_message_id,
            self.worker_attempt_id,
            now=NOW,
        )

    def action(self) -> dict:
        return {
            "kind": "REBUILD_PREPARED_CANDIDATE",
            "target": f"{REPOSITORY}:issue:{ISSUE}",
            "expected_digest": self.initial_candidate["candidate_sha256"],
            "desired_digest": self.desired_candidate_sha256,
            "authority_class": "PLANNER_OWNER_API",
            "evidence_required": [
                "portfolio_pull_buffer_current.candidate_id",
                "portfolio_pull_buffer_candidates.candidate_sha256",
            ],
        }

    def receipt(self, actions: list[dict] | None = None) -> dict:
        return {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "readiness_plan_sha256": self.registered["plan_sha256"],
            "delivery_identity_sha256": synthetic_delivery_identity(
                REPOSITORY, ISSUE, 1
            )[1],
            "verdict": "ACTIONABLE_HOLD",
            "worker_role": "sre",
            "message_id": self.worker_message_id,
            "attempt_id": self.worker_attempt_id,
            "gate_results": [
                {
                    "gate_key": "complete-review",
                    "verdict": "HOLD",
                    "evidence_sha256": "e" * 64,
                    "summary": "The prepared packet needs one bounded rebuild.",
                }
            ],
            "resolution": {
                "role": "planner",
                "actions": [self.action()] if actions is None else actions,
                "approval": None,
            },
            "summary": "One consolidated Planner-owned resolution is sufficient.",
            "observed_at": NOW,
        }

    def finish_actionable(
        self, *, exhausted: bool = False, actions: list[dict] | None = None
    ) -> dict:
        receipt = self.receipt(actions)
        path = self.root / "actionable-receipt.json"
        path.write_text(canonical_json(receipt), encoding="utf-8")
        path.chmod(0o600)
        with patch.dict(
            os.environ, {"TWINFINITY_EXECUTOR_TOKEN": self.worker_token}
        ):
            stage_receipt(
                self.store.connection,
                self.database,
                path,
                message_id=self.worker_message_id,
                attempt_id=self.worker_attempt_id,
                now=NOW,
            )
        self.store.complete_message(self.worker_message_id, SRE, NOW)
        with self.store.transaction():
            if exhausted:
                self.store.connection.execute(
                    "UPDATE portfolio_readiness_current SET resolution_cycles=2 "
                    "WHERE campaign_id=? AND state='RUNNING'",
                    (int(self.registered["campaign_id"]),),
                )
            changed = self.store.connection.execute(
                "UPDATE executor_attempts SET state='COMPLETE', exit_code=0, "
                "version=version+1, updated_at=? WHERE attempt_id=? "
                "AND state='RUNNING'",
                (NOW, self.worker_attempt_id),
            ).rowcount
            if changed != 1:
                raise AssertionError("worker attempt did not terminate")
        return pickup_receipt(
            self.store, int(self.registered["campaign_id"]), now=NOW
        )

    def resolution_message_id(self) -> int:
        row = self.store.connection.execute(
            "SELECT message_id FROM portfolio_readiness_resolution_notices "
            "WHERE campaign_id=?",
            (int(self.registered["campaign_id"]),),
        ).fetchone()
        if row is None:
            raise AssertionError("resolution notice missing")
        return int(row["message_id"])


class ReadinessResolutionFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = ResolutionHarness()

    def tearDown(self) -> None:
        self.h.close()

    def assert_zero_writer_wip(self) -> None:
        connection = self.h.store.connection
        self.assertEqual(
            0,
            connection.execute(
                "SELECT COUNT(*) FROM coordination_items "
                "WHERE allocation_class!='NONE'"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            connection.execute(
                "SELECT COUNT(*) FROM executor_attempts "
                "WHERE role IN ('development','sre') "
                "AND state IN ('RESERVED','LAUNCHING','RUNNING')"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches "
                "WHERE state='ACTIVE'"
            ).fetchone()[0],
        )

    def _claim(self) -> tuple[int, dict]:
        self.h.finish_actionable()
        message_id = self.h.resolution_message_id()
        with self.assertRaisesRegex(
            CoordinationError, "READINESS_RESOLUTION_HANDLER_REQUIRED"
        ):
            self.h.store.claim_message(message_id, PLANNER, CLAIMED_AT)
        with self.assertRaisesRegex(
            ReadinessError, "CURRENT_PLANNER_ENDPOINT_REQUIRED"
        ):
            claim_readiness_resolution_context(
                self.h.store,
                message_id=message_id,
                planner_session_id=SRE,
                now=CLAIMED_AT,
            )
        context = claim_readiness_resolution_context(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            now=CLAIMED_AT,
        )
        return message_id, context

    def test_cold_context_owner_readback_successor_and_replay(self) -> None:
        message_id, context = self._claim()
        self.assertEqual(self.h.plan, context["parent_plan"])
        self.assertEqual(
            canonical_json(context["action_set"]["actions"]),
            context["action_set"]["actions_json"],
        )
        self.assertEqual(
            digest_json(context["action_set"]["actions"]),
            context["action_set"]["action_set_sha256"],
        )
        self.assertEqual(
            self.h.registered["campaign_id"], context["campaign"]["campaign_id"]
        )
        self.assertEqual(
            self.h.initial_candidate["candidate_sha256"],
            context["prepared_candidate"]["candidate_sha256"],
        )
        self.assertEqual(message_id, context["planner_notice"]["message_id"])
        self.assertIsNone(context["frozen_approval_reference"])
        self.assertEqual(
            "BROKER_MEDIATED_PREREQUISITE", context["execution"]["mode"]
        )
        self.assertFalse(context["execution"]["direct_database_authority"])
        self.assert_zero_writer_wip()

        action_receipt = self.h.execute_candidate_action(message_id, context)
        self.assertEqual("COMPLETE", action_receipt["state"])
        replayed_receipt = self.h.execute_candidate_action(message_id, context)
        self.assertTrue(replayed_receipt["replay"])
        result = apply_readiness_resolution(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            now=APPLIED_AT,
        )
        self.assertEqual("SUCCESSOR", result["outcome"])
        self.assertEqual("RESUMED", result["disposition"])
        successor = self.h.store.connection.execute(
            "SELECT * FROM portfolio_readiness_campaigns WHERE id=?",
            (result["successor_campaign_id"],),
        ).fetchone()
        self.assertEqual(self.h.desired_candidate_sha256, successor["candidate_sha256"])
        self.assertEqual(
            result["action_set_sha256"], successor["resolution_action_set_sha256"]
        )
        self.assertEqual(
            result["changed_evidence_sha256"], successor["changed_evidence_sha256"]
        )
        replay = apply_readiness_resolution(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            now=APPLIED_AT,
        )
        self.assertTrue(replay["replay"])
        self.assertEqual(result["successor_campaign_id"], replay["successor_campaign_id"])
        context_replay = claim_readiness_resolution_context(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            now=APPLIED_AT,
        )
        self.assertTrue(context_replay["replay"])
        self.assertEqual(context["context_sha256"], context_replay["context_sha256"])
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_resolution_cycles"
            ).fetchone()[0],
        )
        self.assert_zero_writer_wip()

    def test_context_and_apply_are_cold_process_safe(self) -> None:
        self.h.finish_actionable()
        message_id = self.h.resolution_message_id()
        self.h.store.close()
        self.h.store = CoordinationStore(self.h.database)
        context = claim_readiness_resolution_context(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            now=CLAIMED_AT,
        )
        self.h.execute_candidate_action(message_id, context)
        self.h.store.close()
        self.h.store = CoordinationStore(self.h.database)
        result = apply_readiness_resolution(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            now=APPLIED_AT,
        )
        self.assertEqual("SUCCESSOR", result["outcome"])
        self.assert_zero_writer_wip()

    def test_digest_drift_terminal_holds_once_and_replays(self) -> None:
        message_id, context = self._claim()
        result = apply_readiness_resolution(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            now=APPLIED_AT,
        )
        self.assertEqual("HOLD", result["outcome"])
        self.assertEqual("TERMINAL_HOLD", result["disposition"])
        self.assertIn("READINESS_RESOLUTION_EVIDENCE_DRIFT", result["reason"])
        current = self.h.store.connection.execute(
            "SELECT campaign_id,state,last_error FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        ).fetchone()
        self.assertEqual(self.h.registered["campaign_id"], current["campaign_id"])
        self.assertEqual("HOLD", current["state"])
        replay = apply_readiness_resolution(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            now=APPLIED_AT,
        )
        self.assertTrue(replay["replay"])
        self.assertEqual("HOLD", replay["outcome"])
        self.assert_zero_writer_wip()

    def test_target_mutation_before_claim_terminal_holds_without_successor(self) -> None:
        self.h.finish_actionable()
        message_id = self.h.resolution_message_id()
        self.h.register_desired_candidate()
        context = claim_readiness_resolution_context(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            now=CLAIMED_AT,
        )
        self.assertEqual("HOLD", context["claim_outcome"]["outcome"])
        self.assertEqual(
            "TERMINAL_HOLD", context["claim_outcome"]["disposition"]
        )
        self.assertIn(
            "READINESS_RESOLUTION_EVIDENCE_PRECLAIM_TARGET_DRIFT",
            context["claim_outcome"]["reason"],
        )
        current = self.h.store.connection.execute(
            "SELECT state FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        ).fetchone()
        self.assertEqual("HOLD", current["state"])
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_resolution_cycles "
                "WHERE outcome='HOLD' AND successor_campaign_id IS NULL"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_campaigns"
            ).fetchone()[0],
        )
        self.assertEqual(
            "COMPLETE",
            self.h.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()[0],
        )
        self.assert_zero_writer_wip()

    def test_partial_failure_rolls_back_and_retry_consumes_once(self) -> None:
        message_id, context = self._claim()
        self.h.execute_candidate_action(message_id, context)
        before_campaigns = self.h.store.connection.execute(
            "SELECT COUNT(*) FROM portfolio_readiness_campaigns"
        ).fetchone()[0]

        def failpoint(step: str) -> None:
            if step == "after_successor_registered":
                raise RuntimeError("resolution-failpoint")

        with self.assertRaisesRegex(RuntimeError, "resolution-failpoint"):
            apply_readiness_resolution(
                self.h.store,
                message_id=message_id,
                planner_session_id=PLANNER,
                expected_context_sha256=context["context_sha256"],
                now=APPLIED_AT,
                failpoint=failpoint,
            )
        self.assertEqual(
            before_campaigns,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_campaigns"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_resolution_cycles"
            ).fetchone()[0],
        )
        self.assertEqual(
            "CLAIMED",
            self.h.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()[0],
        )
        result = apply_readiness_resolution(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            now=APPLIED_AT,
        )
        self.assertEqual("SUCCESSOR", result["outcome"])
        self.assert_zero_writer_wip()

    def test_complete_safe_registry_set_reads_back_owner_apis_atomically(self) -> None:
        next_payload = {
            "_projection_version": 4,
            "number": ISSUE,
            "title": "Typed readiness resolution with refreshed evidence",
            "state": "open",
            "updated_at": CLAIMED_AT,
            "milestone": {"number": 1, "title": "Sprint", "state": "open"},
        }
        next_source_sha256 = digest_json(next_payload)
        graph_plan = {
            "repository": REPOSITORY,
            "accepted_main_sha": MAIN,
            "expected_current_version": 1,
            "scope_milestones": [{"title": "Sprint", "rank": 1}],
            "excluded_issues": [],
            "nodes": [
                {
                    "node_key": f"issue:{ISSUE}",
                    "issue_number": ISSUE,
                    "role": "DELIVERY",
                    "root_kind": "STANDALONE",
                    "root_reason": "Independent outcome",
                    "lane_key": "lane-resolution",
                    "lane_order": 0,
                    "dispatchable": True,
                    "priority_rank": 1,
                    "estimate_units": 1,
                    "development_units": 1,
                    "shared_units": 0,
                    "sre_units": 0,
                    "source_payload_sha256": next_source_sha256,
                    "ready_at": NOW,
                }
            ],
            "relations": [],
        }
        desired_graph_sha256 = digest_json(
            {
                key: graph_plan[key]
                for key in (
                    "repository", "scope_milestones", "excluded_issues",
                    "nodes", "relations",
                )
            }
        )
        prior_graph_sha256 = self.h.store.connection.execute(
            "SELECT graph_sha256 FROM portfolio_graph_revisions "
            "WHERE repository=? AND version=1",
            (REPOSITORY,),
        ).fetchone()[0]
        desired_packet = copy.deepcopy(self.h.desired_packet)
        desired_packet["source_payload_sha256"] = next_source_sha256
        desired_packet["item_version_at_preparation"] = int(self.h.item["version"]) + 1
        desired_packet["portfolio_graph_version"] = 2
        desired_candidate_sha256 = digest_json(desired_packet)
        actions = [
            {
                "kind": "REFRESH_SOURCE_SNAPSHOT",
                "target": f"{REPOSITORY}:issue:{ISSUE}",
                "expected_digest": self.h.source_sha256,
                "desired_digest": next_source_sha256,
                "authority_class": "PLANNER_OWNER_API",
                "evidence_required": [
                    "github_current.payload_sha256",
                    "coordination_items.source_payload_sha256",
                ],
            },
            {
                "kind": "RECOMPUTE_DEPENDENCY_GRAPH",
                "target": REPOSITORY,
                "expected_digest": prior_graph_sha256,
                "desired_digest": desired_graph_sha256,
                "authority_class": "PLANNER_OWNER_API",
                "evidence_required": [
                    "portfolio_graph_revisions.graph_sha256",
                    "portfolio_graph_current.health",
                ],
            },
            {
                "kind": "REBUILD_PREPARED_CANDIDATE",
                "target": f"{REPOSITORY}:issue:{ISSUE}",
                "expected_digest": self.h.initial_candidate["candidate_sha256"],
                "desired_digest": desired_candidate_sha256,
                "authority_class": "PLANNER_OWNER_API",
                "evidence_required": [
                    "portfolio_pull_buffer_current.candidate_id",
                    "portfolio_pull_buffer_candidates.candidate_sha256",
                ],
            },
        ]
        self.h.finish_actionable(actions=actions)
        message_id = self.h.resolution_message_id()
        context = claim_readiness_resolution_context(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            now=CLAIMED_AT,
        )

        def durable_counts() -> tuple[int, ...]:
            return tuple(
                self.h.store.connection.execute(
                    "SELECT "
                    "(SELECT COUNT(*) FROM portfolio_graph_revisions),"
                    "(SELECT COUNT(*) FROM portfolio_readiness_events),"
                    "(SELECT COUNT(*) FROM portfolio_readiness_resolution_action_starts),"
                    "(SELECT COUNT(*) FROM portfolio_readiness_resolution_action_completions),"
                    "(SELECT COUNT(*) FROM coordination_events)"
                ).fetchone()
            )

        before_out_of_order = durable_counts()
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_RESOLUTION_ACTION_ORDER_REQUIRED"
        ):
            execute_readiness_resolution_action(
                self.h.store,
                message_id=message_id,
                planner_session_id=PLANNER,
                expected_context_sha256=context["context_sha256"],
                action_sha256=digest_json(actions[1]),
                expected_digest=actions[1]["expected_digest"],
                action_input={"plan": graph_plan},
                now=CLAIMED_AT,
            )
        self.assertEqual(before_out_of_order, durable_counts())

        source_receipt = execute_readiness_resolution_action(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            action_sha256=digest_json(actions[0]),
            expected_digest=actions[0]["expected_digest"],
            action_input={
                "payload": next_payload,
                "source_updated_at": CLAIMED_AT,
                "fetched_at": CLAIMED_AT,
            },
            now=CLAIMED_AT,
        )
        self.assertEqual("WAITING_DEPENDENCY", source_receipt["state"])
        self.assertIsNone(source_receipt["after_binding_sha256"])
        source_events = self.h.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events "
            "WHERE event_type='SOURCE_REFRESHED'"
        ).fetchone()[0]
        waiting_replay = execute_readiness_resolution_action(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            action_sha256=digest_json(actions[0]),
            expected_digest=actions[0]["expected_digest"],
            action_input={
                "payload": next_payload,
                "source_updated_at": CLAIMED_AT,
                "fetched_at": CLAIMED_AT,
            },
            now=CLAIMED_AT,
        )
        self.assertEqual("WAITING_DEPENDENCY", waiting_replay["state"])
        self.assertTrue(waiting_replay["replay"])
        self.assertEqual(
            source_events,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events "
                "WHERE event_type='SOURCE_REFRESHED'"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_resolution_action_completions "
                "WHERE notice_message_id=? AND action_sha256=?",
                (message_id, digest_json(actions[0])),
            ).fetchone()[0],
        )

        premature_candidate_path = self.h._candidate_path(
            desired_packet, "premature-full-correction"
        )
        candidate_count = self.h.store.connection.execute(
            "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates"
        ).fetchone()[0]
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_RESOLUTION_ACTION_ORDER_REQUIRED"
        ):
            execute_readiness_resolution_action(
                self.h.store,
                message_id=message_id,
                planner_session_id=PLANNER,
                expected_context_sha256=context["context_sha256"],
                action_sha256=digest_json(actions[2]),
                expected_digest=actions[2]["expected_digest"],
                action_input={"packet_path": str(premature_candidate_path)},
                now=CLAIMED_AT,
            )
        self.assertEqual(
            candidate_count,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates"
            ).fetchone()[0],
        )
        graph_receipt = execute_readiness_resolution_action(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            action_sha256=digest_json(actions[1]),
            expected_digest=actions[1]["expected_digest"],
            action_input={"plan": graph_plan},
            now=CLAIMED_AT,
        )
        self.assertEqual("COMPLETE", graph_receipt["state"])
        source_receipt = execute_readiness_resolution_action(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            action_sha256=digest_json(actions[0]),
            expected_digest=actions[0]["expected_digest"],
            action_input={
                "payload": next_payload,
                "source_updated_at": CLAIMED_AT,
                "fetched_at": CLAIMED_AT,
            },
            now=CLAIMED_AT,
        )
        self.assertEqual("COMPLETE", source_receipt["state"])
        item = self.h.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        ).fetchone()
        self.assertEqual(int(self.h.item["version"]) + 1, item["version"])
        candidate_path = self.h._candidate_path(
            desired_packet, "full-correction"
        )
        candidate_receipt = execute_readiness_resolution_action(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            action_sha256=digest_json(actions[2]),
            expected_digest=actions[2]["expected_digest"],
            action_input={"packet_path": str(candidate_path)},
            now=CLAIMED_AT,
        )
        self.assertEqual("COMPLETE", candidate_receipt["state"])

        receipts_before_replay = durable_counts()
        for action, action_input in (
            (
                actions[0],
                {
                    "payload": next_payload,
                    "source_updated_at": CLAIMED_AT,
                    "fetched_at": CLAIMED_AT,
                },
            ),
            (actions[1], {"plan": graph_plan}),
            (actions[2], {"packet_path": str(candidate_path)}),
        ):
            replay = execute_readiness_resolution_action(
                self.h.store,
                message_id=message_id,
                planner_session_id=PLANNER,
                expected_context_sha256=context["context_sha256"],
                action_sha256=digest_json(action),
                expected_digest=action["expected_digest"],
                action_input=action_input,
                now=CLAIMED_AT,
            )
            self.assertEqual("COMPLETE", replay["state"])
            self.assertTrue(replay["replay"])
        self.assertEqual(receipts_before_replay, durable_counts())

        result = apply_readiness_resolution(
            self.h.store,
            message_id=message_id,
            planner_session_id=PLANNER,
            expected_context_sha256=context["context_sha256"],
            now=APPLIED_AT,
        )
        successor = self.h.store.connection.execute(
            "SELECT source_payload_sha256, graph_version, item_version, "
            "candidate_sha256 FROM portfolio_readiness_campaigns WHERE id=?",
            (result["successor_campaign_id"],),
        ).fetchone()
        self.assertEqual(next_source_sha256, successor["source_payload_sha256"])
        self.assertEqual(2, successor["graph_version"])
        self.assertEqual(item["version"], successor["item_version"])
        self.assertEqual(desired_candidate_sha256, successor["candidate_sha256"])
        self.assert_zero_writer_wip()

    def test_exhaustion_holds_without_an_executable_notice(self) -> None:
        result = self.h.finish_actionable(exhausted=True)
        self.assertEqual("HOLD", result["state"])
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_resolution_notices"
            ).fetchone()[0],
        )
        self.assert_zero_writer_wip()

    def test_unknown_nonplanner_and_material_actions_fail_closed(self) -> None:
        receipt = self.h.receipt()
        unknown = copy.deepcopy(receipt)
        unknown["resolution"]["actions"][0]["kind"] = "RUN_ARBITRARY_SQL"
        with self.assertRaisesRegex(ReadinessError, "READINESS_ACTION_TERMINAL_HOLD"):
            _validate_receipt(unknown)

        nonplanner = copy.deepcopy(receipt)
        nonplanner["resolution"]["actions"][0]["authority_class"] = "WORKER_DB"
        with self.assertRaisesRegex(ReadinessError, "READINESS_ACTION_TERMINAL_HOLD"):
            _validate_receipt(nonplanner)

        material = copy.deepcopy(receipt)
        material["resolution"]["actions"] = [
            {
                "kind": "REQUEST_MATERIAL_APPROVAL",
                "target": f"{REPOSITORY}:issue:{ISSUE}",
                "expected_digest": self.h.registered["plan_sha256"],
                "desired_digest": "f" * 64,
                "authority_class": "HUMAN_APPROVAL",
                "evidence_required": ["approval_ledger.published_decision"],
            }
        ]
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_ACTION_APPROVAL_REQUIRED"
        ):
            _validate_receipt(material)

    def test_cli_claims_exact_context_and_applies_same_notice(self) -> None:
        self.h.finish_actionable()
        message_id = self.h.resolution_message_id()
        output = io.StringIO()
        with patch.object(
            kanban_pull_buffer, "DEFAULT_DATABASE", self.h.database
        ), patch.object(
            sys,
            "argv",
            [
                "kanban_pull_buffer.py",
                "readiness-resolution-context",
                "--message-id",
                str(message_id),
                "--planner-session-id",
                PLANNER,
            ],
        ), redirect_stdout(output):
            self.assertEqual(0, kanban_pull_buffer.main())
        context_envelope = json.loads(output.getvalue())
        context = context_envelope["result"]
        self.assertEqual("COMPLETE", context_envelope["phase"])
        candidate_path = self.h._candidate_path(
            self.h.desired_packet, "cli-corrected"
        )
        action_input_path = self.h.root / "candidate-action-input.json"
        action_input_path.write_text(
            canonical_json({"packet_path": str(candidate_path)}),
            encoding="utf-8",
        )
        output = io.StringIO()
        with patch.object(
            kanban_pull_buffer, "DEFAULT_DATABASE", self.h.database
        ), patch.object(
            sys,
            "argv",
            [
                "kanban_pull_buffer.py",
                "readiness-execute-resolution-action",
                "--message-id",
                str(message_id),
                "--planner-session-id",
                PLANNER,
                "--expected-context-sha256",
                context["context_sha256"],
                "--action-sha256",
                digest_json(self.h.action()),
                "--expected-digest",
                self.h.action()["expected_digest"],
                "--action-input",
                str(action_input_path),
            ],
        ), redirect_stdout(output):
            self.assertEqual(0, kanban_pull_buffer.main())
        action_result = json.loads(output.getvalue())
        self.assertEqual("COMPLETE", action_result["result"]["state"])
        output = io.StringIO()
        with patch.object(
            kanban_pull_buffer, "DEFAULT_DATABASE", self.h.database
        ), patch.object(
            sys,
            "argv",
            [
                "kanban_pull_buffer.py",
                "readiness-apply-resolution",
                "--message-id",
                str(message_id),
                "--planner-session-id",
                PLANNER,
                "--expected-context-sha256",
                context["context_sha256"],
            ],
        ), redirect_stdout(output):
            self.assertEqual(0, kanban_pull_buffer.main())
        result = json.loads(output.getvalue())
        self.assertEqual("SUCCESSOR", result["result"]["outcome"])
        self.assert_zero_writer_wip()


if __name__ == "__main__":
    unittest.main()
