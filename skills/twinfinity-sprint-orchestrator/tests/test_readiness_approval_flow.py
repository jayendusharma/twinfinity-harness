from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


STAGED = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(STAGED))

from approval_guard import readiness_execution_scope_sha256  # noqa: E402
from approval_ledger import (  # noqa: E402
    enqueue_published_readiness_decision_notices,
    record_decision,
    revoke_decision,
)
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
)
from executor_registry import ensure_executor_registry_schema  # noqa: E402
from executor_registry import load_registry_config  # noqa: E402
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import (  # noqa: E402
    PLAN_SCHEMA,
    READINESS_APPROVAL_INPUT_SCHEMA,
    READINESS_DECISION_MAPPING,
    RECEIPT_SCHEMA,
    apply_readiness_decision,
    attach,
    claim_readiness_resolution_context,
    dispatch,
    enqueue_due_readiness_revisits,
    ensure_schema as ensure_readiness_schema,
    evaluate,
    pickup_receipt,
    register,
    stage_receipt,
    stop_revoked_readiness_successors,
    transition_evidence_sha256,
)
from portfolio_graph import replace_graph  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from tests.reviewed_endpoint_catalog_fixture import (  # noqa: E402
    reviewed_current_endpoint_catalog,
    reviewed_planner_rotation_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
ISSUE = 1
MAIN = "a" * 40
NOW = "2026-08-25T05:00:00Z"
PUBLISHED_AT = "2026-08-25T05:01:00Z"
CONSUMED_AT = "2026-08-25T05:02:00Z"
REVISIT_AT = "2026-08-26T05:00:00Z"
PLANNER_V1 = "role.planner.v2"
PLANNER_V2 = "role.planner.v3"
SRE = "role.sre.v4"


class ApprovalFlowHarness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        skill_root = Path(__file__).resolve().parents[1]
        self.current_catalog = reviewed_current_endpoint_catalog(
            skill_root, Path(self.temporary.name)
        )
        self.endpoint_config = self.current_catalog.__enter__()
        self.root = Path(self.temporary.name) / "coordination"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        ensure_executor_registry_schema(self.store.connection)
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        self._install_current_endpoints()
        self.issue_payload = {
            "_projection_version": 3,
            "number": ISSUE,
            "title": "Issue 1",
            "state": "open",
            "updated_at": NOW,
            "milestone": {"number": 1, "title": "Sprint", "state": "open"},
        }
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload=self.issue_payload,
            source_updated_at=NOW,
            fetched_at=NOW,
        )
        self.source_sha256 = snapshot.payload_sha256
        self.item = self.store._set_issue_status_for_test_fixture(
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
        self._install_graph_and_candidate()
        self.registered = register(
            self.store.connection, self._plan(), now=NOW
        )
        dispatched = dispatch(
            self.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]
        self.worker_message_id = int(dispatched["message_id"])
        self.worker_attempt_id = "11111111-1111-4111-8111-111111111111"
        self.worker_token = f"executor-token:{self.worker_attempt_id}"
        self._start_worker_attempt()
        self.approval_packet = self._approval_packet()
        self._stage_and_finish_approval_receipt()
        self.request = dict(
            self.store.connection.execute(
                "SELECT * FROM portfolio_readiness_approval_requests"
            ).fetchone()
        )

    def close(self) -> None:
        self.store.close()
        self.current_catalog.__exit__(None, None, None)
        self.temporary.cleanup()

    def _install_current_endpoints(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = self.endpoint_config
        aliases, alias_sha = load_legacy_alias_fixture(
            root / "tests" / "fixtures" / "legacy-role-aliases.json"
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
            operation_key="readiness-approval-flow-fixture",
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )

    def rotate_planner(self, config) -> None:
        root = Path(__file__).resolve().parents[1]
        aliases, alias_sha = load_legacy_alias_fixture(
            root / "tests" / "fixtures" / "legacy-role-aliases.json"
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
            operation_key="readiness-approval-flow-planner-v3",
            expected_plan_sha256=plan["plan_sha256"],
            now=PUBLISHED_AT,
        )

    def _install_graph_and_candidate(self) -> None:
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0,
                "scope_milestones": [
                    {"title": "Sprint", "rank": 1}
                ],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": f"issue:{ISSUE}",
                        "issue_number": ISSUE,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent outcome",
                        "lane_key": "lane-1",
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
        policy_version = int(
            self.store.connection.execute(
                "SELECT version FROM coordination_capacity_current "
                "WHERE repository=?",
                (REPOSITORY,),
            ).fetchone()[0]
        )
        self.candidate_sha256 = hashlib.sha256(b"candidate:1").hexdigest()
        with self.store.transaction():
            cursor = self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_candidates(
                    repository, issue_number, generation, item_version,
                    source_payload_sha256, accepted_main_sha, graph_version,
                    capacity_policy_version, lane_key, state, verticality,
                    development_units, shared_units, sre_units, promotion_trigger,
                    artifact_relative_path, artifact_content_sha256,
                    candidate_sha256, registered_at
                ) VALUES (?, ?, 1, ?, ?, ?, 1, ?, 'lane-1',
                          'PREPARED_NOT_READY', 'END_TO_END', 1, 0, 0,
                          'Close readiness phase', 'plans/issue-1.json', ?, ?, ?)
                """,
                (
                    REPOSITORY,
                    ISSUE,
                    int(self.item["version"]),
                    self.source_sha256,
                    MAIN,
                    policy_version,
                    "c" * 64,
                    self.candidate_sha256,
                    NOW,
                ),
            )
            self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_current(
                    repository, issue_number, candidate_id, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (REPOSITORY, ISSUE, int(cursor.lastrowid), NOW),
            )

    def _plan(self) -> dict:
        policy_version = int(
            self.store.connection.execute(
                "SELECT version FROM coordination_capacity_current "
                "WHERE repository=?",
                (REPOSITORY,),
            ).fetchone()[0]
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
            "capacity_policy_version": policy_version,
            "candidate_sha256": self.candidate_sha256,
            "worker_role": "sre",
            "phase_summary": (
                "Resolve the complete material readiness question without "
                "repository mutation."
            ),
            "gates": [
                {
                    "gate_key": "material-decision",
                    "description": "One exact product behavior decision is required.",
                    "requested_evidence": [
                        "A published user decision bound to this campaign"
                    ],
                }
            ],
        }

    def _start_worker_attempt(self) -> None:
        token_sha256 = hashlib.sha256(self.worker_token.encode()).hexdigest()
        self.store.claim_message(self.worker_message_id, SRE, NOW)
        with self.store.transaction():
            self.store.connection.execute(
                """
                INSERT INTO executor_attempts(
                    attempt_id, role, endpoint_id, instance_id, token_sha256,
                    target_kind, target_key, state, process_id, exit_code,
                    heartbeat_at, version, created_at, updated_at
                ) VALUES (?, 'sre', ?, ?, ?,
                          'message', ?, 'RUNNING', 9001, NULL, ?, 1, ?, ?)
                """,
                (
                    self.worker_attempt_id,
                    SRE,
                    f"approval-readiness-worker:{self.worker_attempt_id}",
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

    def _approval_packet(self) -> dict:
        campaign = self.store.connection.execute(
            """
            SELECT campaign.*, current.endpoint_id
            FROM portfolio_readiness_campaigns campaign
            JOIN portfolio_readiness_current current
              ON current.campaign_id=campaign.id
            WHERE campaign.id=?
            """,
            (int(self.registered["campaign_id"]),),
        ).fetchone()
        boundary = "PRODUCT_BEHAVIOR"
        scope = readiness_execution_scope_sha256(
            repository=REPOSITORY,
            issue_number=ISSUE,
            source_payload_sha256=str(campaign["source_payload_sha256"]),
            campaign_id=int(campaign["id"]),
            generation=int(campaign["generation"]),
            item_version=int(campaign["item_version"]),
            accepted_main_sha=str(campaign["accepted_main_sha"]),
            graph_version=int(campaign["graph_version"]),
            capacity_policy_version=int(campaign["capacity_policy_version"]),
            candidate_sha256=str(campaign["candidate_sha256"]),
            worker_role=str(campaign["worker_role"]),
            worker_endpoint_id=str(campaign["endpoint_id"]),
            worker_attempt_id=self.worker_attempt_id,
            parent_plan_sha256=str(campaign["plan_sha256"]),
            material_boundary=boundary,
        )
        return {
            "schema": "twinfinity.approval-proposal.v1",
            "decision_key": "issue-1:readiness-campaign-1:product-behavior",
            "repository": REPOSITORY,
            "owning_issue": ISSUE,
            "source_snapshot_sha256": self.source_sha256,
            "execution_scope_sha256": scope,
            "requester_session_id": SRE,
            "recipient_session_id": PLANNER_V1,
            "workstream": "READINESS",
            "boundary": boundary,
            "priority": "P1",
            "urgency": "READY_BLOCKER",
            "summary": "Issue 1 needs one material product behavior decision.",
            "question": "Should the bounded product behavior proceed?",
            "requested_action": "Select one exact disposition.",
            "target": "Issue 1 readiness campaign 1.",
            "affected_issues": [ISSUE],
            "blocked_mutation": "Register the deterministic readiness successor.",
            "immediate_beneficiary": "The issue 1 vertical delivery lineage.",
            "evidence": ["The terminal readiness gate requires this decision."],
            "risk": "An unbound decision could authorize the wrong successor.",
            "drift_guards": [
                "Require the exact campaign, source, scope, and published decision."
            ],
            "prohibited_side_effects": [
                "Do not allocate writer capacity during readiness disposition."
            ],
            "options": [
                {
                    "id": "APPROVE",
                    "label": "Approve",
                    "effect": "Register one deterministic approval-resume successor.",
                },
                {
                    "id": "REJECT",
                    "label": "Reject",
                    "effect": "Preserve the readiness lineage on HOLD.",
                },
                {
                    "id": "DEFER",
                    "label": "Defer",
                    "effect": "Hold the lineage and arm one typed revisit.",
                },
                {
                    "id": "COURSE_CORRECT",
                    "label": "Course correct",
                    "effect": "Hold pending a newly scoped proposal.",
                },
            ],
            "recommendation": "APPROVE",
            "expires_at": None,
        }

    def _stage_and_finish_approval_receipt(self) -> None:
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "readiness_plan_sha256": self.registered["plan_sha256"],
            "verdict": "APPROVAL_REQUIRED",
            "worker_role": "sre",
            "message_id": self.worker_message_id,
            "attempt_id": self.worker_attempt_id,
            "gate_results": [
                {
                    "gate_key": "material-decision",
                    "verdict": "HOLD",
                    "evidence_sha256": "e" * 64,
                    "summary": "The exact material decision is still required.",
                }
            ],
            "resolution": {
                "role": "planner",
                "actions": [
                    {
                        "kind": "REQUEST_MATERIAL_APPROVAL",
                        "target": f"{REPOSITORY}:issue:{ISSUE}",
                        "expected_digest": self.registered["plan_sha256"],
                        "desired_digest": self.approval_packet[
                            "execution_scope_sha256"
                        ],
                        "authority_class": "HUMAN_APPROVAL",
                        "evidence_required": [
                            "approval_ledger.published_decision"
                        ],
                    }
                ],
                "approval": {
                    "schema": READINESS_APPROVAL_INPUT_SCHEMA,
                    "packet": self.approval_packet,
                    "material_boundary": "PRODUCT_BEHAVIOR",
                    "decision_mapping": READINESS_DECISION_MAPPING,
                },
            },
            "summary": "The candidate is waiting on one material user decision.",
            "observed_at": NOW,
        }
        draft = self.root / "approval-required-receipt.json"
        draft.write_text(canonical_json(receipt), encoding="utf-8")
        draft.chmod(0o600)
        with patch.dict(
            os.environ, {"TWINFINITY_EXECUTOR_TOKEN": self.worker_token}
        ):
            stage_receipt(
                self.store.connection,
                self.database,
                draft,
                message_id=self.worker_message_id,
                attempt_id=self.worker_attempt_id,
                now=NOW,
            )
        self.store.complete_message(self.worker_message_id, SRE, NOW)
        with self.store.transaction():
            changed = self.store.connection.execute(
                """
                UPDATE executor_attempts
                SET state='COMPLETE', exit_code=0, version=version+1, updated_at=?
                WHERE attempt_id=? AND state='RUNNING'
                """,
                (NOW, self.worker_attempt_id),
            ).rowcount
            if changed != 1:
                raise AssertionError("worker attempt did not become terminal")
        result = pickup_receipt(
            self.store, int(self.registered["campaign_id"]), now=NOW
        )
        if result["state"] != "APPROVAL_PENDING":
            raise AssertionError(result)

    def decide(self, decision: str) -> dict:
        revisit = REVISIT_AT if decision == "DEFER" else None
        user_input = {
            "decision": decision,
            "selected_option_id": decision,
            "revisit_trigger": revisit,
        }
        return record_decision(
            self.store,
            proposal_sha256=str(self.request["proposal_sha256"]),
            decision=decision,
            selected_option_id=decision,
            revisit_trigger=revisit,
            decision_note=f"Hermetic {decision} decision.",
            user_input_sha256=digest_json(user_input),
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id=f"approval-flow-{decision.casefold()}",
            planner_session_id=PLANNER_V1,
            now=PUBLISHED_AT,
        )

    def publish(self, decision: dict) -> None:
        outbox_id = int(decision["owner_outbox_id"])
        self.store.reserve_outbox(outbox_id, PUBLISHED_AT)
        self.store.complete_outbox(
            outbox_id, f"github-comment:{outbox_id}", PUBLISHED_AT
        )

    def enqueue_decision_notice(self) -> int:
        result = enqueue_published_readiness_decision_notices(
            self.store, now=PUBLISHED_AT
        )
        if len(result["enqueued"]) != 1:
            raise AssertionError(result)
        return int(result["enqueued"][0]["message_id"])

    def apply(
        self,
        message_id: int,
        *,
        planner_session_id: str = PLANNER_V1,
        payload: dict | None = None,
        failpoint=None,
    ) -> dict:
        refreshed = self.issue_payload if payload is None else payload
        return apply_readiness_decision(
            self.store,
            message_id=message_id,
            planner_session_id=planner_session_id,
            refreshed_payload=refreshed,
            refreshed_payload_sha256=digest_json(refreshed),
            now=CONSUMED_AT,
            failpoint=failpoint,
        )


class ReadinessApprovalFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = ApprovalFlowHarness()

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

    def test_approve_waits_for_publication_replays_once_and_survives_rotation(self) -> None:
        decision = self.h.decide("APPROVE")
        before_publication = enqueue_published_readiness_decision_notices(
            self.h.store, now=PUBLISHED_AT
        )
        self.assertEqual([], before_publication["enqueued"])

        root = Path(__file__).resolve().parents[1]
        with reviewed_planner_rotation_catalog(
            root, Path(self.h.temporary.name)
        ) as config:
            self.h.rotate_planner(config)
            self.h.publish(decision)
            message_id = self.h.enqueue_decision_notice()
            replay = enqueue_published_readiness_decision_notices(
                self.h.store, now=PUBLISHED_AT
            )
            self.assertEqual([], replay["enqueued"])
            notice = self.h.store.connection.execute(
                "SELECT recipient_session_id,state FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()
            self.assertEqual((PLANNER_V2, "PREPARED"), tuple(notice))
            with self.assertRaisesRegex(
                CoordinationError, "READINESS_DECISION_HANDLER_REQUIRED"
            ):
                self.h.store.claim_message(message_id, PLANNER_V2, CONSUMED_AT)

            self.h.apply(message_id, planner_session_id=PLANNER_V2)
            connection = self.h.store.connection
            current = connection.execute(
                "SELECT campaign_id,state FROM portfolio_readiness_current "
                "WHERE repository=? AND issue_number=?",
                (REPOSITORY, ISSUE),
            ).fetchone()
            successor = connection.execute(
                "SELECT * FROM portfolio_readiness_campaigns WHERE id=?",
                (int(current["campaign_id"]),),
            ).fetchone()
            delivery = connection.execute(
                "SELECT recipient_session_id,state FROM approval_deliveries "
                "WHERE proposal_sha256=?",
                (decision["proposal_sha256"],),
            ).fetchone()
            consumption = connection.execute(
                "SELECT * FROM portfolio_readiness_approval_consumptions"
            ).fetchone()
            self.assertEqual("PENDING", current["state"])
            self.assertEqual("APPROVAL_RESUME", successor["transition_kind"])
            self.assertEqual(
                decision["decision_sha256"],
                successor["approval_decision_sha256"],
            )
            self.assertEqual((PLANNER_V1, "ACKNOWLEDGED"), tuple(delivery))
            self.assertEqual("RESUMED", consumption["disposition"])
            self.assertEqual(
                int(successor["id"]), int(consumption["successor_campaign_id"])
            )
            self.assertEqual(
                "COMPLETE",
                connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
                ).fetchone()[0],
            )
        self.assert_zero_writer_wip()

    def test_approved_successor_freezes_approval_in_cold_resolution_context(self) -> None:
        decision = self.h.decide("APPROVE")
        self.h.publish(decision)
        approval_message_id = self.h.enqueue_decision_notice()
        resumed = self.h.apply(approval_message_id)

        dispatched = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=CONSUMED_AT
        )["dispatched"][0]
        self.h.worker_message_id = int(dispatched["message_id"])
        self.h.worker_attempt_id = "22222222-2222-4222-8222-222222222222"
        self.h.worker_token = f"executor-token:{self.h.worker_attempt_id}"
        self.h._start_worker_attempt()

        campaign = self.h.store.connection.execute(
            "SELECT * FROM portfolio_readiness_campaigns WHERE id=?",
            (int(resumed["successor_campaign_id"]),),
        ).fetchone()
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "readiness_plan_sha256": campaign["plan_sha256"],
            "verdict": "ACTIONABLE_HOLD",
            "worker_role": "sre",
            "message_id": self.h.worker_message_id,
            "attempt_id": self.h.worker_attempt_id,
            "gate_results": [
                {
                    "gate_key": "material-decision",
                    "verdict": "HOLD",
                    "evidence_sha256": "f" * 64,
                    "summary": "One exact prepared-candidate rebuild is needed.",
                }
            ],
            "resolution": {
                "role": "planner",
                "actions": [
                    {
                        "kind": "REBUILD_PREPARED_CANDIDATE",
                        "target": f"{REPOSITORY}:issue:{ISSUE}",
                        "expected_digest": campaign["candidate_sha256"],
                        "desired_digest": "d" * 64,
                        "authority_class": "PLANNER_OWNER_API",
                        "evidence_required": [
                            "portfolio_pull_buffer_current.candidate_id",
                            "portfolio_pull_buffer_candidates.candidate_sha256",
                        ],
                    }
                ],
                "approval": None,
            },
            "summary": "One consolidated Planner-owned rebuild is sufficient.",
            "observed_at": CONSUMED_AT,
        }
        draft = self.h.root / "approved-actionable-receipt.json"
        draft.write_text(canonical_json(receipt), encoding="utf-8")
        draft.chmod(0o600)
        with patch.dict(
            os.environ, {"TWINFINITY_EXECUTOR_TOKEN": self.h.worker_token}
        ):
            stage_receipt(
                self.h.store.connection,
                self.h.database,
                draft,
                message_id=self.h.worker_message_id,
                attempt_id=self.h.worker_attempt_id,
                now=CONSUMED_AT,
            )
        self.h.store.complete_message(self.h.worker_message_id, SRE, CONSUMED_AT)
        with self.h.store.transaction():
            changed = self.h.store.connection.execute(
                "UPDATE executor_attempts SET state='COMPLETE', exit_code=0, "
                "version=version+1, updated_at=? WHERE attempt_id=? "
                "AND state='RUNNING'",
                (CONSUMED_AT, self.h.worker_attempt_id),
            ).rowcount
            self.assertEqual(1, changed)
        pickup = pickup_receipt(
            self.h.store, int(resumed["successor_campaign_id"]), now=CONSUMED_AT
        )
        self.assertEqual("RESOLUTION_PENDING", pickup["state"])
        resolution_message_id = int(
            self.h.store.connection.execute(
                "SELECT message_id FROM portfolio_readiness_resolution_notices "
                "WHERE campaign_id=?",
                (int(resumed["successor_campaign_id"]),),
            ).fetchone()[0]
        )
        context = claim_readiness_resolution_context(
            self.h.store,
            message_id=resolution_message_id,
            planner_session_id=PLANNER_V1,
            now=CONSUMED_AT,
        )
        self.assertEqual(
            {
                "proposal_sha256": decision["proposal_sha256"],
                "decision_sha256": decision["decision_sha256"],
                "recipient_session_id": PLANNER_V1,
                "execution_scope_sha256": self.h.approval_packet[
                    "execution_scope_sha256"
                ],
            },
            context["frozen_approval_reference"],
        )
        self.assert_zero_writer_wip()

    def test_defer_holds_and_arms_one_typed_revisit(self) -> None:
        decision = self.h.decide("DEFER")
        self.h.publish(decision)
        message_id = self.h.enqueue_decision_notice()
        self.h.apply(message_id)

        connection = self.h.store.connection
        self.assertEqual(
            "HOLD",
            connection.execute(
                "SELECT state FROM portfolio_readiness_current WHERE issue_number=?",
                (ISSUE,),
            ).fetchone()[0],
        )
        self.assertEqual(
            "ACKNOWLEDGED",
            connection.execute(
                "SELECT state FROM approval_deliveries WHERE proposal_sha256=?",
                (decision["proposal_sha256"],),
            ).fetchone()[0],
        )
        enqueue_due_readiness_revisits(
            self.h.store, now="2026-08-26T04:59:59Z"
        )
        self.assertEqual(
            0,
            connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_revisit_notices"
            ).fetchone()[0],
        )
        enqueue_due_readiness_revisits(self.h.store, now=REVISIT_AT)
        enqueue_due_readiness_revisits(
            self.h.store, now="2026-08-26T05:00:01Z"
        )
        revisit = connection.execute(
            """
            SELECT revisit.*, message.recipient_session_id, message.state
            FROM portfolio_readiness_revisit_notices revisit
            JOIN coordination_messages message ON message.id=revisit.message_id
            """
        ).fetchall()
        self.assertEqual(1, len(revisit))
        self.assertEqual(REVISIT_AT, revisit[0]["due_at"])
        self.assertEqual(PLANNER_V1, revisit[0]["recipient_session_id"])
        self.assertEqual("PREPARED", revisit[0]["state"])
        self.assert_zero_writer_wip()

    def test_material_drift_terminalizes_delivery_and_lineage(self) -> None:
        decision = self.h.decide("APPROVE")
        self.h.publish(decision)
        message_id = self.h.enqueue_decision_notice()
        drifted = {
            **self.h.issue_payload,
            "_projection_version": 4,
            "title": "Materially changed issue 1",
            "updated_at": "2026-08-25T05:02:00Z",
        }
        self.h.apply(message_id, payload=drifted)

        connection = self.h.store.connection
        delivery = connection.execute(
            "SELECT state,last_error FROM approval_deliveries "
            "WHERE proposal_sha256=?",
            (decision["proposal_sha256"],),
        ).fetchone()
        current = connection.execute(
            "SELECT state,last_error FROM portfolio_readiness_current "
            "WHERE issue_number=?",
            (ISSUE,),
        ).fetchone()
        consumption = connection.execute(
            "SELECT disposition,successor_campaign_id "
            "FROM portfolio_readiness_approval_consumptions"
        ).fetchone()
        self.assertEqual(
            ("HOLD", "APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION"), tuple(delivery)
        )
        self.assertEqual("STALE", current["state"])
        self.assertIn("APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION", current["last_error"])
        self.assertEqual(("STALE", None), tuple(consumption))
        self.assertEqual(
            "COMPLETE",
            connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()[0],
        )
        self.assert_zero_writer_wip()

    def test_every_failpoint_rolls_back_claim_disposition_consumption_and_completion(self) -> None:
        steps = (
            "after_message_claim",
            "after_delivery_claim",
            "after_disposition",
            "after_consumption",
            "after_acknowledge",
            "before_message_complete",
        )
        for step in steps:
            with self.subTest(step=step):
                harness = ApprovalFlowHarness()
                try:
                    decision = harness.decide("APPROVE")
                    harness.publish(decision)
                    message_id = harness.enqueue_decision_notice()

                    def failpoint(observed: str) -> None:
                        if observed == step:
                            raise RuntimeError(f"approval-flow-failpoint:{step}")

                    with self.assertRaisesRegex(
                        RuntimeError, f"approval-flow-failpoint:{step}"
                    ):
                        harness.apply(message_id, failpoint=failpoint)

                    connection = harness.store.connection
                    self.assertEqual(
                        "PREPARED",
                        connection.execute(
                            "SELECT state FROM coordination_messages WHERE id=?",
                            (message_id,),
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        "WAITING_PUBLICATION",
                        connection.execute(
                            "SELECT state FROM approval_deliveries "
                            "WHERE proposal_sha256=?",
                            (decision["proposal_sha256"],),
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        "APPROVAL_PENDING",
                        connection.execute(
                            "SELECT state FROM portfolio_readiness_current "
                            "WHERE issue_number=?",
                            (ISSUE,),
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        0,
                        connection.execute(
                            "SELECT COUNT(*) FROM approval_effectivity"
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        0,
                        connection.execute(
                            "SELECT COUNT(*) FROM "
                            "portfolio_readiness_approval_consumptions"
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        1,
                        connection.execute(
                            "SELECT COUNT(*) FROM portfolio_readiness_campaigns"
                        ).fetchone()[0],
                    )

                    harness.apply(message_id)
                    self.assertEqual(
                        "ACKNOWLEDGED",
                        connection.execute(
                            "SELECT state FROM approval_deliveries "
                            "WHERE proposal_sha256=?",
                            (decision["proposal_sha256"],),
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        1,
                        connection.execute(
                            "SELECT COUNT(*) FROM "
                            "portfolio_readiness_approval_consumptions"
                        ).fetchone()[0],
                    )
                finally:
                    harness.close()
        self.assert_zero_writer_wip()

    def test_comment_only_current_advance_records_equivalence_and_resumes(self) -> None:
        decision = self.h.decide("APPROVE")
        self.h.publish(decision)
        comment_only = {
            **self.h.issue_payload,
            "_projection_version": 4,
            "updated_at": "2026-08-25T05:01:30Z",
        }
        advanced = self.h.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload=comment_only,
            source_updated_at=comment_only["updated_at"],
            fetched_at=comment_only["updated_at"],
        )
        message_id = self.h.enqueue_decision_notice()
        result = self.h.apply(message_id, payload=comment_only)
        self.assertEqual("RESUMED", result["disposition"])
        equivalence = self.h.store.connection.execute(
            "SELECT bound_source_sha256,observed_source_sha256 "
            "FROM portfolio_readiness_source_equivalence"
        ).fetchone()
        self.assertEqual(
            (self.h.source_sha256, advanced.payload_sha256), tuple(equivalence)
        )
        self.assertEqual(
            "PENDING",
            self.h.store.connection.execute(
                "SELECT state FROM portfolio_readiness_current WHERE issue_number=?",
                (ISSUE,),
            ).fetchone()[0],
        )
        self.assert_zero_writer_wip()

    def _revoke(self, decision: dict, suffix: str) -> dict:
        return revoke_decision(
            self.h.store,
            proposal_sha256=decision["proposal_sha256"],
            decision_sha256=decision["decision_sha256"],
            reason="The exact readiness direction was withdrawn.",
            user_input_sha256=digest_json({"revoked": suffix}),
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id=f"approval-flow-revocation-{suffix}",
            planner_session_id=PLANNER_V1,
            now=CONSUMED_AT,
        )

    def test_revocation_before_consumption_holds_without_successor(self) -> None:
        decision = self.h.decide("APPROVE")
        self.h.publish(decision)
        self._revoke(decision, "before")
        message_id = self.h.enqueue_decision_notice()
        result = self.h.apply(message_id)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_campaigns"
            ).fetchone()[0],
        )
        self.assertEqual(
            "COMPLETE",
            self.h.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()[0],
        )
        self.assert_zero_writer_wip()

    def test_revocation_after_resume_stops_once_and_wakes_current_planner(self) -> None:
        decision = self.h.decide("APPROVE")
        self.h.publish(decision)
        message_id = self.h.enqueue_decision_notice()
        resumed = self.h.apply(message_id)
        self._revoke(decision, "after")
        first = stop_revoked_readiness_successors(
            self.h.store, now="2026-08-25T05:03:00Z"
        )
        replay = stop_revoked_readiness_successors(
            self.h.store, now="2026-08-25T05:04:00Z"
        )
        self.assertEqual(1, len(first["stopped"]))
        self.assertEqual([], replay["stopped"])
        self.assertEqual(
            "HOLD",
            self.h.store.connection.execute(
                "SELECT state FROM portfolio_readiness_current WHERE campaign_id=?",
                (resumed["successor_campaign_id"],),
            ).fetchone()[0],
        )
        wake = self.h.store.connection.execute(
            "SELECT message.recipient_session_id FROM "
            "portfolio_readiness_revocation_notices notice "
            "JOIN coordination_messages message ON message.id=notice.message_id"
        ).fetchone()
        self.assertEqual(PLANNER_V1, wake[0])
        self.assert_zero_writer_wip()

    def test_course_correct_is_hold_and_generic_resolution_cannot_exit(self) -> None:
        decision = self.h.decide("COURSE_CORRECT")
        self.h.publish(decision)
        message_id = self.h.enqueue_decision_notice()
        self.h.apply(message_id)
        current = self.h.store.connection.execute(
            "SELECT campaign_id,state,version FROM portfolio_readiness_current "
            "WHERE issue_number=?",
            (ISSUE,),
        ).fetchone()
        self.assertEqual("HOLD", current["state"])
        observed = evaluate(
            self.h.store.connection,
            REPOSITORY,
            ISSUE,
            now=CONSUMED_AT,
            record_state=True,
        )
        self.assertEqual("HOLD", observed["state"])
        self.assertEqual(
            "HOLD",
            self.h.store.connection.execute(
                "SELECT state FROM portfolio_readiness_current WHERE issue_number=?",
                (ISSUE,),
            ).fetchone()[0],
        )
        parent = self.h._plan()
        successor = {
            **parent,
            "schema": "twinfinity-kanban-readiness-phase/v2",
            "phase_summary": "Changed plan that must not bypass the held decision.",
            "transition": {
                "kind": "RESOLUTION",
                "parent_campaign_id": int(current["campaign_id"]),
                "expected_parent_version": int(current["version"]),
                "changed_evidence_sha256": "0" * 64,
                "resolution_action_set_sha256": "f" * 64,
                "approval": None,
            },
        }
        successor["transition"]["changed_evidence_sha256"] = (
            transition_evidence_sha256(parent, successor)
        )
        with self.assertRaisesRegex(
            Exception, "READINESS_RESOLUTION_HANDLER_REQUIRED"
        ):
            register(self.h.store.connection, successor, now=CONSUMED_AT)
        self.assert_zero_writer_wip()


if __name__ == "__main__":
    unittest.main()
