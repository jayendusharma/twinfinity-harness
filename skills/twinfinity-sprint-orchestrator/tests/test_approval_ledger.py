from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch


import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import approval_ledger as approval_ledger_module  # noqa: E402
from approval_ledger import (  # noqa: E402
    activate_semantic_contract_v2,
    acknowledge_decision,
    claim_decision,
    claim_decision_in_transaction,
    create_review_batch,
    enqueue_published_readiness_decision_notices,
    ensure_schema,
    load_packet,
    record_decision,
    revoke_decision,
    submit_proposal,
    submit_readiness_proposal_in_transaction,
    validate_packet,
)
from approval_guard import (  # noqa: E402
    ApprovalGuardError,
    require_effective_approval,
)
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    digest_json,
)
from executor_registry import load_registry_config  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
    reviewed_planner_rotation_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
DEVELOPMENT_SESSION = "role.development.v4"
PLANNER_SESSION = "role.planner.v2"
SRE_SESSION = "role.sre.v4"
REQUESTER = DEVELOPMENT_SESSION


class ApprovalLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.store = CoordinationStore(root / "state.sqlite3")
        self.endpoint_config = apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="approval-ledger-tests",
        )
        self.snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=58,
            payload={"number": 58, "updated_at": "2026-08-24T04:00:00Z"},
            source_updated_at="2026-08-24T04:00:00Z",
            fetched_at="2026-08-24T04:00:01Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def packet(self, *, key: str = "issue-58:material-choice", summary: str = "Choose behavior") -> dict:
        return {
            "schema": "twinfinity.approval-proposal.v2",
            "decision_key": key,
            "repository": REPOSITORY,
            "owning_issue": 58,
            "source_snapshot_sha256": self.snapshot.payload_sha256,
            "execution_scope_sha256": "9" * 64,
            "requester_session_id": REQUESTER,
            "recipient_session_id": REQUESTER,
            "workstream": "DEVELOPMENT",
            "boundary": "PRODUCT_BEHAVIOR",
            "priority": "P0",
            "urgency": "ACTIVE_BLOCKER",
            "summary": summary,
            "question": "Should the bounded behavior be enabled?",
            "requested_action": "Enable only the reviewed bounded behavior.",
            "target": "Issue #58 reviewed product slice",
            "affected_issues": [58, 115],
            "blocked_mutation": "The exact owner-visible behavior change is paused.",
            "immediate_beneficiary": "Twin Studio staff evaluator",
            "evidence": ["Current issue snapshot and exact review are available."],
            "risk": "The wrong choice could change owner-visible behavior.",
            "drift_guards": ["Owning issue source digest must remain current."],
            "prohibited_side_effects": ["No hosted or provider mutation."],
            "options": [
                {
                    "id": "ENABLE", "label": "Enable",
                    "effect": "Enable the bounded behavior.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "HOLD", "label": "Hold",
                    "effect": "Keep the behavior unchanged.",
                    "machine_outcome": "REJECT",
                },
                {
                    "id": "DEFER", "label": "Defer",
                    "effect": "Hold until the named revisit trigger.",
                    "machine_outcome": "DEFER",
                },
                {
                    "id": "REVISE", "label": "Revise",
                    "effect": "Return for a materially corrected proposal.",
                    "machine_outcome": "COURSE_CORRECT",
                },
            ],
            "recommendation": "ENABLE",
            "expires_at": None,
        }

    def readiness_packet(self) -> dict:
        packet = self.packet(key="issue-58:readiness-material-choice")
        packet.update(
            {
                "requester_session_id": DEVELOPMENT_SESSION,
                "recipient_session_id": PLANNER_SESSION,
                "workstream": "READINESS",
                "urgency": "READY_BLOCKER",
            }
        )
        return packet

    def submit_readiness(self, packet: dict | None = None) -> dict:
        packet = self.readiness_packet() if packet is None else packet
        ensure_schema(self.store.connection)
        with self.store.transaction():
            return submit_readiness_proposal_in_transaction(
                self.store,
                packet,
                expected_requester_session_id=DEVELOPMENT_SESSION,
                expected_recipient_session_id=PLANNER_SESSION,
                expected_execution_scope_sha256=packet[
                    "execution_scope_sha256"
                ],
                now="2026-08-24T04:00:02Z",
            )

    def batch_answer(
        self,
        proposal_sha256: str,
        selected_option_id: str,
        *,
        now: str = "2026-08-24T04:00:03Z",
    ) -> tuple[str, dict]:
        batch = create_review_batch(self.store, REPOSITORY, now)
        return batch["batch_sha256"], {
            "schema": "twinfinity.approval-batch-answer-map.v1",
            "batch_sha256": batch["batch_sha256"],
            "answers": [
                {
                    "proposal_sha256": proposal_sha256,
                    "selected_option_id": selected_option_id,
                }
            ],
        }

    def decide(self, proposal_sha256: str) -> dict:
        batch_sha256, answer_map = self.batch_answer(
            proposal_sha256, "ENABLE"
        )
        return record_decision(
            self.store,
            proposal_sha256=proposal_sha256,
            batch_sha256=batch_sha256,
            batch_answer_map=answer_map,
            decision="APPROVE",
            selected_option_id="ENABLE",
            revisit_trigger=None,
            decision_note="Approved only for the exact bounded issue contract.",
            user_input_sha256="a" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T04:00:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:00:03Z",
        )

    def publish(self, outbox_id: int) -> None:
        self.store.reserve_outbox(outbox_id, "2026-08-24T04:00:04Z")
        self.store.complete_outbox(
            outbox_id, "comment:1234", "2026-08-24T04:00:05Z"
        )

    @staticmethod
    def refreshed_source(*_args) -> dict:
        return {"number": 58, "updated_at": "2026-08-24T04:00:05Z"}

    def install_registry(self, operation_key: str) -> None:
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
            operation_key=operation_key,
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T04:00:06Z",
        )

    def rotate_planner_to_v3(self, config, operation_key: str) -> None:
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
            operation_key=operation_key,
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T04:00:07Z",
        )

    def test_submit_and_review_batch_are_prioritized_and_idempotent(self) -> None:
        submitted = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )
        duplicate = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:03Z"
        )
        batch = create_review_batch(
            self.store, REPOSITORY, "2026-08-24T04:00:04Z"
        )
        self.assertFalse(submitted["idempotent"])
        self.assertTrue(duplicate["idempotent"])
        self.assertEqual(1, batch["pending_count"])
        self.assertEqual(submitted["proposal_sha256"], batch["proposals"][0]["proposal_sha256"])
        notice = self.store.connection.execute(
            "SELECT recipient_session_id, topic, state FROM coordination_messages"
        ).fetchall()
        self.assertEqual(
            [(PLANNER_SESSION, "coordination.notice", "PREPARED")],
            [tuple(row) for row in notice],
        )

    def test_v2_proposal_identity_includes_exact_evidence(self) -> None:
        first_packet = self.packet()
        first = submit_proposal(
            self.store, first_packet, "2026-08-24T04:00:02Z"
        )
        replay = submit_proposal(
            self.store, first_packet, "2026-08-24T04:00:03Z"
        )
        changed_packet = self.packet()
        changed_packet["evidence"] = [
            "A distinct secret-safe review artifact is now current."
        ]
        changed = submit_proposal(
            self.store, changed_packet, "2026-08-24T04:00:04Z"
        )

        self.assertTrue(replay["idempotent"])
        self.assertEqual(first["proposal_sha256"], replay["proposal_sha256"])
        self.assertNotEqual(first["proposal_sha256"], changed["proposal_sha256"])
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM approval_proposals"
            ).fetchone()[0],
        )

    def test_v1_pending_is_quarantined_after_explicit_v2_cutover(self) -> None:
        legacy = self.packet()
        legacy["schema"] = "twinfinity.approval-proposal.v1"
        submitted = submit_proposal(
            self.store, legacy, "2026-08-24T04:00:02Z"
        )
        before = self.store.connection.execute(
            "SELECT proposal_sha256,semantic_sha256,packet_json "
            "FROM approval_proposals WHERE proposal_sha256=?",
            (submitted["proposal_sha256"],),
        ).fetchone()

        activate_semantic_contract_v2(
            self.store.connection,
            authority_sha256="7" * 64,
            now="2026-08-24T04:00:03Z",
        )
        batch = create_review_batch(
            self.store, REPOSITORY, "2026-08-24T04:00:04Z"
        )
        self.assertEqual(0, batch["pending_count"])
        self.assertEqual(
            "APPROVAL_LEGACY_V1_AUTHORITY_QUARANTINED",
            batch["held"][0]["reason"],
        )
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_LEGACY_V1_AUTHORITY_QUARANTINED"
        ):
            submit_proposal(
                self.store, legacy, "2026-08-24T04:00:05Z"
            )

        replacement = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:06Z"
        )
        self.assertNotEqual(
            submitted["proposal_sha256"], replacement["proposal_sha256"]
        )
        after = self.store.connection.execute(
            "SELECT proposal_sha256,semantic_sha256,packet_json "
            "FROM approval_proposals WHERE proposal_sha256=?",
            (submitted["proposal_sha256"],),
        ).fetchone()
        self.assertEqual(tuple(before), tuple(after))

    def test_v1_deliverable_claim_holds_before_refresh_or_any_write(self) -> None:
        legacy = self.packet()
        legacy["schema"] = "twinfinity.approval-proposal.v1"
        proposal = submit_proposal(
            self.store, legacy, "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        decision = self.decide(proposal)
        self.publish(decision["owner_outbox_id"])
        activate_semantic_contract_v2(
            self.store.connection,
            authority_sha256="b" * 64,
            now="2026-08-24T04:00:06Z",
        )
        refresher = Mock(side_effect=AssertionError("must not refresh"))
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_LEGACY_V1_AUTHORITY_QUARANTINED"
        ):
            claim_decision(
                self.store,
                proposal_sha256=proposal,
                recipient_session_id=DEVELOPMENT_SESSION,
                now="2026-08-24T04:00:07Z",
                source_refresher=refresher,
            )
        refresher.assert_not_called()
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_v1_claimed_delivery_cannot_be_acknowledged_after_cutover(self) -> None:
        legacy = self.packet()
        legacy["schema"] = "twinfinity.approval-proposal.v1"
        proposal = submit_proposal(
            self.store, legacy, "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        decision = self.decide(proposal)
        self.publish(decision["owner_outbox_id"])
        claim_decision(
            self.store,
            proposal_sha256=proposal,
            recipient_session_id=DEVELOPMENT_SESSION,
            now="2026-08-24T04:00:06Z",
            source_refresher=self.refreshed_source,
        )
        activate_semantic_contract_v2(
            self.store.connection,
            authority_sha256="c" * 64,
            now="2026-08-24T04:00:07Z",
        )
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_LEGACY_V1_AUTHORITY_QUARANTINED"
        ):
            acknowledge_decision(
                self.store,
                proposal_sha256=proposal,
                decision_sha256=decision["decision_sha256"],
                recipient_session_id=DEVELOPMENT_SESSION,
                now="2026-08-24T04:00:08Z",
            )
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_decision_requires_frozen_batch_and_matching_option_outcome(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_REVIEW_BATCH_REQUIRED"
        ):
            record_decision(
                self.store,
                proposal_sha256=proposal,
                decision="APPROVE",
                selected_option_id="ENABLE",
                revisit_trigger=None,
                decision_note="Must not decide without a frozen batch.",
                user_input_sha256="1" * 64,
                user_event_source="CODEX_DIRECT_USER_TURN",
                user_event_id="planner-turn:unbatched-2026-08-24",
                planner_session_id=PLANNER_SESSION,
                now="2026-08-24T04:00:03Z",
            )

        cases = (("APPROVE", "HOLD"), ("REJECT", "ENABLE"))
        for index, (decision, option_id) in enumerate(cases):
            batch_sha256, answer_map = self.batch_answer(proposal, option_id)
            with self.subTest(decision=decision, option_id=option_id), self.assertRaisesRegex(
                CoordinationError, "APPROVAL_OPTION_OUTCOME_MISMATCH"
            ):
                record_decision(
                    self.store,
                    proposal_sha256=proposal,
                    batch_sha256=batch_sha256,
                    batch_answer_map=answer_map,
                    decision=decision,
                    selected_option_id=option_id,
                    revisit_trigger=None,
                    decision_note="Caller outcome must match the frozen option.",
                    user_input_sha256=str(index + 2) * 64,
                    user_event_source="CODEX_DIRECT_USER_TURN",
                    user_event_id=f"planner-turn:mismatch-{index}-2026-08-24",
                    planner_session_id=PLANNER_SESSION,
                    now="2026-08-24T04:00:03Z",
                )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM approval_decisions"
            ).fetchone()[0],
        )

    def test_batch_rejects_late_recipient_and_cross_batch_event_reuse(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        batch_sha256, answer_map = self.batch_answer(proposal, "ENABLE")
        sre_packet = self.packet()
        sre_packet["requester_session_id"] = SRE_SESSION
        sre_packet["recipient_session_id"] = SRE_SESSION
        sre_packet["workstream"] = "SRE"
        submit_proposal(self.store, sre_packet, "2026-08-24T04:00:03Z")
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_BATCH_RECIPIENT_SET_DRIFT"
        ):
            record_decision(
                self.store,
                proposal_sha256=proposal,
                batch_sha256=batch_sha256,
                batch_answer_map=answer_map,
                decision="APPROVE",
                selected_option_id="ENABLE",
                revisit_trigger=None,
                decision_note="Late recipients require a fresh review batch.",
                user_input_sha256="4" * 64,
                user_event_source="CODEX_DIRECT_USER_TURN",
                user_event_id="planner-turn:late-recipient-2026-08-24",
                planner_session_id=PLANNER_SESSION,
                now="2026-08-24T04:00:04Z",
            )

        fresh_batch_sha256, fresh_answer_map = self.batch_answer(
            proposal, "ENABLE", now="2026-08-24T04:00:05Z"
        )
        first = record_decision(
            self.store,
            proposal_sha256=proposal,
            batch_sha256=fresh_batch_sha256,
            batch_answer_map=fresh_answer_map,
            decision="APPROVE",
            selected_option_id="ENABLE",
            revisit_trigger=None,
            decision_note="Approve the freshly frozen recipient set.",
            user_input_sha256="5" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:cross-batch-2026-08-24",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:00:05Z",
        )
        self.assertFalse(first["idempotent"])
        second_packet = self.packet(key="issue-58:second-material-choice")
        second = submit_proposal(
            self.store, second_packet, "2026-08-24T04:00:06Z"
        )["proposal_sha256"]
        second_batch_sha256, second_answer_map = self.batch_answer(
            second, "ENABLE", now="2026-08-24T04:00:07Z"
        )
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_USER_EVENT_CROSS_BATCH_REUSE"
        ):
            record_decision(
                self.store,
                proposal_sha256=second,
                batch_sha256=second_batch_sha256,
                batch_answer_map=second_answer_map,
                decision="APPROVE",
                selected_option_id="ENABLE",
                revisit_trigger=None,
                decision_note="A different batch needs a different user event.",
                user_input_sha256="5" * 64,
                user_event_source="CODEX_DIRECT_USER_TURN",
                user_event_id="planner-turn:cross-batch-2026-08-24",
                planner_session_id=PLANNER_SESSION,
                now="2026-08-24T04:00:07Z",
            )

    def test_readiness_packet_can_only_be_submitted_by_terminal_pickup_path(self) -> None:
        packet = self.readiness_packet()
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_READINESS_SUPERVISOR_REQUIRED"
        ):
            submit_proposal(self.store, packet, "2026-08-24T04:00:02Z")

        submitted = self.submit_readiness(packet)
        proposal = self.store.connection.execute(
            "SELECT requester_session_id,recipient_session_id,workstream "
            "FROM approval_proposals WHERE proposal_sha256=?",
            (submitted["proposal_sha256"],),
        ).fetchone()
        self.assertEqual(
            (DEVELOPMENT_SESSION, PLANNER_SESSION, "READINESS"),
            tuple(proposal),
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM approval_proposal_notices"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_items "
                "WHERE allocation_class IN ('ACTIVE','RETAINED')"
            ).fetchone()[0],
        )

    def test_readiness_submission_rejects_wrong_exact_route_and_scope(self) -> None:
        packet = self.readiness_packet()
        ensure_schema(self.store.connection)
        cases = (
            {
                "requester_session_id": SRE_SESSION,
                "recipient_session_id": PLANNER_SESSION,
                "execution_scope_sha256": packet["execution_scope_sha256"],
            },
            {
                "requester_session_id": DEVELOPMENT_SESSION,
                "recipient_session_id": "role.planner.v3",
                "execution_scope_sha256": packet["execution_scope_sha256"],
            },
            {
                "requester_session_id": DEVELOPMENT_SESSION,
                "recipient_session_id": PLANNER_SESSION,
                "execution_scope_sha256": "8" * 64,
            },
        )
        for binding in cases:
            with self.subTest(binding=binding), self.assertRaisesRegex(
                CoordinationError, "APPROVAL_READINESS_BINDING_MISMATCH"
            ):
                with self.store.transaction():
                    submit_readiness_proposal_in_transaction(
                        self.store,
                        packet,
                        expected_requester_session_id=binding[
                            "requester_session_id"
                        ],
                        expected_recipient_session_id=binding[
                            "recipient_session_id"
                        ],
                        expected_execution_scope_sha256=binding[
                            "execution_scope_sha256"
                        ],
                        now="2026-08-24T04:00:02Z",
                    )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM approval_proposals"
            ).fetchone()[0],
        )

    def test_readiness_decision_wake_requires_exact_campaign_request(self) -> None:
        proposal = self.submit_readiness()["proposal_sha256"]
        decision = self.decide(proposal)
        before = enqueue_published_readiness_decision_notices(
            self.store, now="2026-08-24T04:00:04Z"
        )
        self.assertEqual([], before["enqueued"])

        self.publish(decision["owner_outbox_id"])
        first = enqueue_published_readiness_decision_notices(
            self.store, now="2026-08-24T04:00:06Z"
        )
        replay = enqueue_published_readiness_decision_notices(
            self.store, now="2026-08-24T04:00:07Z"
        )
        self.assertEqual([], first["enqueued"])
        self.assertEqual([], replay["enqueued"])
        self.assertIsNone(
            self.store.connection.execute(
                "SELECT 1 FROM approval_delivery_notices"
            ).fetchone()
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_items "
                "WHERE allocation_class IN ('ACTIVE','RETAINED')"
            ).fetchone()[0],
        )

    def test_defer_remains_claimable_after_publication_and_gets_one_wake(self) -> None:
        proposal = self.submit_readiness()["proposal_sha256"]
        batch_sha256, answer_map = self.batch_answer(proposal, "DEFER")
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
            batch_sha256=batch_sha256,
            batch_answer_map=answer_map,
            decision="DEFER",
            selected_option_id="DEFER",
            revisit_trigger="2026-08-25T05:00:00Z",
            decision_note="Defer until the named portfolio trigger occurs.",
            user_input_sha256="c" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T04:02:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:02:03Z",
        )
        self.assertEqual(
            {PLANNER_SESSION: "WAITING_PUBLICATION"},
            decision["delivery_states"],
        )
        self.assertEqual(
            [],
            enqueue_published_readiness_decision_notices(
                self.store, now="2026-08-24T04:02:04Z"
            )["enqueued"],
        )
        self.publish(decision["owner_outbox_id"])
        self.assertEqual(
            [],
            enqueue_published_readiness_decision_notices(
                self.store, now="2026-08-24T04:02:06Z"
            )["enqueued"],
        )

    def test_effective_guard_requires_exact_readiness_bindings(self) -> None:
        packet = self.readiness_packet()
        proposal = self.submit_readiness(packet)["proposal_sha256"]
        decision = self.decide(proposal)
        self.publish(decision["owner_outbox_id"])
        claim_decision(
            self.store,
            proposal_sha256=proposal,
            recipient_session_id=PLANNER_SESSION,
            now="2026-08-24T04:00:06Z",
            source_refresher=self.refreshed_source,
        )
        effective = require_effective_approval(
            self.store.connection,
            repository=REPOSITORY,
            issue_number=58,
            recipient_session_id=PLANNER_SESSION,
            actor_session_id=PLANNER_SESSION,
            execution_scope_sha256=packet["execution_scope_sha256"],
            authority_sha256=decision["decision_sha256"],
            required_proposal_sha256=proposal,
            required_workstream="READINESS",
            required_boundary="PRODUCT_BEHAVIOR",
            required_current_recipient_role=None,
            required=True,
        )
        self.assertEqual(proposal, effective["proposal_sha256"])

        bad_cases = (
            ("proposal", {"required_proposal_sha256": "8" * 64}),
            ("workstream", {"required_workstream": "SRE"}),
            ("boundary", {"required_boundary": "HOSTED_PROVIDER"}),
            ("scope", {"execution_scope_sha256": "8" * 64}),
        )
        base = {
            "repository": REPOSITORY,
            "issue_number": 58,
            "recipient_session_id": PLANNER_SESSION,
            "actor_session_id": PLANNER_SESSION,
            "execution_scope_sha256": packet["execution_scope_sha256"],
            "authority_sha256": decision["decision_sha256"],
            "required_proposal_sha256": proposal,
            "required_workstream": "READINESS",
            "required_boundary": "PRODUCT_BEHAVIOR",
            "required_current_recipient_role": None,
            "required": True,
        }
        for name, changed in bad_cases:
            with self.subTest(name=name), self.assertRaises(ApprovalGuardError):
                require_effective_approval(
                    self.store.connection, **{**base, **changed}
                )

    def test_planner_rotation_before_decision_preserves_historical_packet(self) -> None:
        packet = self.readiness_packet()
        proposal = self.submit_readiness(packet)["proposal_sha256"]
        root = Path(__file__).resolve().parents[1]
        with reviewed_planner_rotation_catalog(
            root, Path(self.temp.name)
        ) as config:
            self.rotate_planner_to_v3(config, "approval-planner-rotation-before")
            batch_sha256, answer_map = self.batch_answer(proposal, "ENABLE")
            decision = record_decision(
                self.store,
                proposal_sha256=proposal,
                batch_sha256=batch_sha256,
                batch_answer_map=answer_map,
                decision="APPROVE",
                selected_option_id="ENABLE",
                revisit_trigger=None,
                decision_note="Approve the exact readiness boundary.",
                user_input_sha256="6" * 64,
                user_event_source="CODEX_DIRECT_USER_TURN",
                user_event_id="planner-turn:2026-08-24T04:10:03Z",
                planner_session_id="role.planner.v3",
                now="2026-08-24T04:10:03Z",
            )
            self.publish(decision["owner_outbox_id"])
            claim_decision(
                self.store,
                proposal_sha256=proposal,
                recipient_session_id="role.planner.v3",
                now="2026-08-24T04:10:06Z",
                source_refresher=self.refreshed_source,
            )
            effective = require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=58,
                recipient_session_id="role.planner.v3",
                actor_session_id="role.planner.v3",
                execution_scope_sha256=packet["execution_scope_sha256"],
                authority_sha256=decision["decision_sha256"],
                required_proposal_sha256=proposal,
                required_workstream="READINESS",
                required_boundary="PRODUCT_BEHAVIOR",
                required_current_recipient_role="planner",
                required=True,
            )
            self.assertEqual("role.planner.v2", self.store.connection.execute(
                "SELECT recipient_session_id FROM approval_proposals "
                "WHERE proposal_sha256=?", (proposal,)
            ).fetchone()[0])
            self.assertEqual(proposal, effective["proposal_sha256"])

    def test_planner_rotation_after_decision_consumes_historical_delivery(self) -> None:
        packet = self.readiness_packet()
        proposal = self.submit_readiness(packet)["proposal_sha256"]
        decision = self.decide(proposal)
        self.publish(decision["owner_outbox_id"])
        root = Path(__file__).resolve().parents[1]
        with reviewed_planner_rotation_catalog(
            root, Path(self.temp.name)
        ) as config:
            self.rotate_planner_to_v3(config, "approval-planner-rotation-after")
            claimed = claim_decision(
                self.store,
                proposal_sha256=proposal,
                recipient_session_id="role.planner.v3",
                now="2026-08-24T04:11:06Z",
                source_refresher=self.refreshed_source,
            )
            self.assertEqual("CLAIMED", claimed["state"])
            effective = require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=58,
                recipient_session_id="role.planner.v3",
                actor_session_id="role.planner.v3",
                execution_scope_sha256=packet["execution_scope_sha256"],
                authority_sha256=decision["decision_sha256"],
                required_proposal_sha256=proposal,
                required_workstream="READINESS",
                required_boundary="PRODUCT_BEHAVIOR",
                required_current_recipient_role="planner",
                required=True,
            )
            self.assertEqual(proposal, effective["proposal_sha256"])

    def test_stale_source_is_not_furnished(self) -> None:
        submitted = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=58,
            payload={"number": 58, "updated_at": "2026-08-24T04:01:00Z"},
            source_updated_at="2026-08-24T04:01:00Z",
            fetched_at="2026-08-24T04:01:01Z",
        )
        batch = create_review_batch(
            self.store, REPOSITORY, "2026-08-24T04:01:02Z"
        )
        self.assertEqual(0, batch["pending_count"])
        self.assertEqual(
            [{"proposal_sha256": submitted["proposal_sha256"], "reason": "SOURCE_DRIFT"}],
            batch["held"],
        )

    def test_only_planner_can_record_decision(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        batch_sha256, answer_map = self.batch_answer(proposal, "ENABLE")
        with self.assertRaisesRegex(CoordinationError, "PLANNER_SESSION_REQUIRED"):
            record_decision(
                self.store,
                proposal_sha256=proposal,
                batch_sha256=batch_sha256,
                batch_answer_map=answer_map,
                decision="APPROVE",
                selected_option_id="ENABLE",
                revisit_trigger=None,
                decision_note="Approved.",
                user_input_sha256="a" * 64,
                user_event_source="CODEX_DIRECT_USER_TURN",
                user_event_id="planner-turn:2026-08-24T04:00:03Z",
                planner_session_id=REQUESTER,
                now="2026-08-24T04:00:03Z",
            )

    def test_publication_is_required_before_exact_recipient_claim_and_ack(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        decision = self.decide(proposal)
        with self.assertRaisesRegex(CoordinationError, "APPROVAL_PUBLICATION_INCOMPLETE"):
            claim_decision(
                self.store,
                proposal_sha256=proposal,
                recipient_session_id=REQUESTER,
                now="2026-08-24T04:00:04Z",
                source_refresher=self.refreshed_source,
            )
        self.publish(decision["owner_outbox_id"])
        with self.assertRaisesRegex(CoordinationError, "APPROVAL_RECIPIENT_MISMATCH"):
            claim_decision(
                self.store,
                proposal_sha256=proposal,
                recipient_session_id=PLANNER_SESSION,
                now="2026-08-24T04:00:06Z",
                source_refresher=self.refreshed_source,
            )
        claimed = claim_decision(
            self.store,
            proposal_sha256=proposal,
            recipient_session_id=REQUESTER,
            now="2026-08-24T04:00:06Z",
            source_refresher=self.refreshed_source,
        )
        self.assertEqual("comment:1234", claimed["remote_receipt"])
        acknowledged = acknowledge_decision(
            self.store,
            proposal_sha256=proposal,
            decision_sha256=decision["decision_sha256"],
            recipient_session_id=REQUESTER,
            now="2026-08-24T04:00:07Z",
        )
        self.assertEqual("ACKNOWLEDGED", acknowledged["state"])

    def test_pending_successor_retires_pointer_but_preserves_history(self) -> None:
        first = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        second = submit_proposal(
            self.store,
            self.packet(summary="Choose the corrected behavior"),
            "2026-08-24T04:00:03Z",
        )["proposal_sha256"]
        self.assertNotEqual(first, second)
        count = self.store.connection.execute(
            "SELECT COUNT(*) FROM approval_proposals"
        ).fetchone()[0]
        current = self.store.connection.execute(
            "SELECT proposal_sha256 FROM approval_current"
        ).fetchone()[0]
        self.assertEqual(2, count)
        self.assertEqual(second, current)

    def test_approved_decision_cannot_be_superseded_before_ack(self) -> None:
        first = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        self.decide(first)
        with self.assertRaisesRegex(CoordinationError, "APPROVAL_DECISION_IN_FLIGHT"):
            submit_proposal(
                self.store,
                self.packet(summary="A conflicting successor"),
                "2026-08-24T04:00:04Z",
            )

    def test_proposal_and_decision_rows_are_immutable(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        self.decide(proposal)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                "UPDATE approval_proposals SET priority='P2' WHERE proposal_sha256=?",
                (proposal,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                "UPDATE approval_decisions SET decision='REJECT' WHERE proposal_sha256=?",
                (proposal,),
            )

    def test_secret_like_packet_is_rejected(self) -> None:
        packet = self.packet()
        packet["evidence"] = ["api_key=not-safe-to-store"]
        with self.assertRaisesRegex(CoordinationError, "APPROVAL_SENSITIVE_CONTENT"):
            submit_proposal(self.store, packet, "2026-08-24T04:00:02Z")

    def test_advisory_subagent_cannot_submit_as_canonical_parent(self) -> None:
        packet = self.packet()
        packet["requester_session_id"] = "01a02b12-efdb-72d2-95d6-754f203c7a8c"
        packet["recipient_session_id"] = packet["requester_session_id"]
        with self.assertRaisesRegex(CoordinationError, "APPROVAL_CANONICAL_PARENT_REQUIRED"):
            submit_proposal(self.store, packet, "2026-08-24T04:00:02Z")

    def test_current_endpoint_consumes_immutable_historical_delivery_by_role(self) -> None:
        endpoint_packet = self.packet(key="issue-58:endpoint-packet")
        endpoint_packet["requester_session_id"] = "role.development.v3"
        endpoint_packet["recipient_session_id"] = "role.development.v3"
        self.assertEqual(
            "role.development.v3",
            validate_packet(endpoint_packet)["recipient_session_id"],
        )

        submitted = submit_proposal(
            self.store, self.packet(key="issue-58:legacy-delivery"),
            "2026-08-24T04:00:02Z",
        )
        decision = self.decide(submitted["proposal_sha256"])
        self.publish(decision["owner_outbox_id"])
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
            operation_key="approval-role-equivalence",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T04:00:06Z",
        )
        legacy_development = next(
            entry["alias"] for entry in aliases if entry["role"] == "development"
        )
        self.store.connection.execute(
            "DROP TRIGGER approval_delivery_envelope_immutable"
        )
        self.store.connection.execute(
            "UPDATE approval_deliveries SET recipient_session_id=? "
            "WHERE proposal_sha256=?",
            (legacy_development, submitted["proposal_sha256"]),
        )
        ensure_schema(self.store.connection)
        claimed = claim_decision(
            self.store,
            proposal_sha256=submitted["proposal_sha256"],
            recipient_session_id=DEVELOPMENT_SESSION,
            now="2026-08-24T04:00:07Z",
            source_refresher=self.refreshed_source,
        )
        self.assertEqual("CLAIMED", claimed["state"])
        acknowledge_decision(
            self.store,
            proposal_sha256=submitted["proposal_sha256"],
            decision_sha256=decision["decision_sha256"],
            recipient_session_id=DEVELOPMENT_SESSION,
            now="2026-08-24T04:00:08Z",
        )
        immutable = self.store.connection.execute(
            "SELECT recipient_session_id FROM approval_deliveries WHERE proposal_sha256=?",
            (submitted["proposal_sha256"],),
        ).fetchone()
        self.assertEqual(legacy_development, immutable["recipient_session_id"])

    def test_post_migration_proposal_rejects_legacy_alias(self) -> None:
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
            operation_key="approval-reject-legacy-new-write",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T04:00:01Z",
        )
        legacy_development = next(
            entry["alias"] for entry in aliases if entry["role"] == "development"
        )
        packet = self.packet(key="issue-58:legacy-post-migration")
        packet["requester_session_id"] = legacy_development
        packet["recipient_session_id"] = legacy_development
        with self.assertRaisesRegex(
            CoordinationError,
            "(?:APPROVAL_CANONICAL_PARENT_REQUIRED|CURRENT_ROLE_ENDPOINT_REQUIRED)",
        ):
            submit_proposal(self.store, packet, "2026-08-24T04:00:02Z")
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM approval_proposals"
            ).fetchone()[0],
        )

    def test_expired_proposal_is_held_out_of_review_bundle(self) -> None:
        packet = self.packet()
        packet["expires_at"] = "2026-08-24T04:00:03Z"
        proposal = submit_proposal(
            self.store, packet, "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        batch = create_review_batch(
            self.store, REPOSITORY, "2026-08-24T04:00:04Z"
        )
        self.assertEqual(0, batch["pending_count"])
        self.assertEqual(
            [{"proposal_sha256": proposal, "reason": "EXPIRED"}],
            batch["held"],
        )

    def test_packet_loader_refuses_symlink(self) -> None:
        packet = self.packet()
        target = Path(self.temp.name) / "packet.json"
        target.write_text(json.dumps(packet), encoding="utf-8")
        link = Path(self.temp.name) / "packet-link.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(CoordinationError, "APPROVAL_PACKET_INVALID"):
            load_packet(link)

    def test_post_publication_source_drift_holds_delivery(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        decision = self.decide(proposal)
        self.publish(decision["owner_outbox_id"])
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION"
        ):
            claim_decision(
                self.store,
                proposal_sha256=proposal,
                recipient_session_id=REQUESTER,
                now="2026-08-24T04:00:06Z",
                source_refresher=lambda *_: {
                    "number": 58,
                    "title": "Materially changed contract",
                    "updated_at": "2026-08-24T04:00:06Z",
                },
            )
        delivery = self.store.connection.execute(
            "SELECT state,last_error FROM approval_deliveries WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()
        self.assertEqual(
            ("HOLD", "APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION"), tuple(delivery)
        )

    def test_transactional_claim_cannot_trust_stale_caller_bytes_over_current(self) -> None:
        original_payload = {
            "number": 58,
            "updated_at": "2026-08-24T04:00:00Z",
        }
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        decision = self.decide(proposal)
        self.publish(decision["owner_outbox_id"])
        materially_changed = {
            "number": 58,
            "title": "Materially changed contract",
            "updated_at": "2026-08-24T04:00:06Z",
        }
        current = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=58,
            payload=materially_changed,
            source_updated_at=materially_changed["updated_at"],
            fetched_at="2026-08-24T04:00:06Z",
        )

        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_CURRENT_SOURCE_DIGEST_DRIFT"
        ):
            with self.store.transaction():
                claim_decision_in_transaction(
                    self.store,
                    proposal_sha256=proposal,
                    recipient_session_id=REQUESTER,
                    refreshed_payload=materially_changed,
                    refreshed_payload_sha256=digest_json(materially_changed),
                    expected_current_source_sha256=self.snapshot.payload_sha256,
                    now="2026-08-24T04:00:07Z",
                    ingest_refreshed_source=False,
                )

        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_SOURCE_DRIFT_AFTER_PUBLICATION"
        ):
            with self.store.transaction():
                claim_decision_in_transaction(
                    self.store,
                    proposal_sha256=proposal,
                    recipient_session_id=REQUESTER,
                    refreshed_payload=original_payload,
                    refreshed_payload_sha256=digest_json(original_payload),
                    expected_current_source_sha256=current.payload_sha256,
                    now="2026-08-24T04:00:07Z",
                    ingest_refreshed_source=False,
                )

        delivery = self.store.connection.execute(
            "SELECT state,claimed_at FROM approval_deliveries "
            "WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()
        self.assertEqual(("WAITING_PUBLICATION", None), tuple(delivery))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM approval_effectivity"
            ).fetchone()[0],
        )
        self.assertEqual(
            current.payload_sha256,
            self.store.current_snapshot(REPOSITORY, "issue", 58).payload_sha256,
        )

    def test_semantic_request_clusters_across_workstreams_and_delivers_to_each(self) -> None:
        development = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )
        sre_packet = self.packet()
        sre_packet["requester_session_id"] = SRE_SESSION
        sre_packet["recipient_session_id"] = SRE_SESSION
        sre_packet["workstream"] = "SRE"
        sre = submit_proposal(self.store, sre_packet, "2026-08-24T04:00:03Z")
        self.assertEqual(development["proposal_sha256"], sre["proposal_sha256"])
        self.assertTrue(sre["clustered"])
        batch = create_review_batch(self.store, REPOSITORY, "2026-08-24T04:00:04Z")
        self.assertEqual(2, batch["proposals"][0]["submission_count"])
        self.assertEqual(
            sorted([DEVELOPMENT_SESSION, SRE_SESSION]),
            batch["proposals"][0]["recipient_session_ids"],
        )
        decision = self.decide(development["proposal_sha256"])
        self.assertEqual(
            {DEVELOPMENT_SESSION: "WAITING_PUBLICATION", SRE_SESSION: "WAITING_PUBLICATION"},
            decision["delivery_states"],
        )
        self.publish(decision["owner_outbox_id"])
        first = claim_decision(
            self.store,
            proposal_sha256=development["proposal_sha256"],
            recipient_session_id=DEVELOPMENT_SESSION,
            now="2026-08-24T04:00:06Z",
            source_refresher=lambda *_: {
                "number": 58, "updated_at": "2026-08-24T04:00:06Z"
            },
        )
        second = claim_decision(
            self.store,
            proposal_sha256=development["proposal_sha256"],
            recipient_session_id=SRE_SESSION,
            now="2026-08-24T04:00:07Z",
            source_refresher=lambda *_: {
                "number": 58, "updated_at": "2026-08-24T04:00:07Z"
            },
        )
        self.assertEqual("CLAIMED", first["state"])
        self.assertEqual("CLAIMED", second["state"])

    def test_defer_is_persistent_hold_with_revisit_trigger(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        batch_sha256, answer_map = self.batch_answer(proposal, "DEFER")
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
            batch_sha256=batch_sha256,
            batch_answer_map=answer_map,
            decision="DEFER",
            selected_option_id="DEFER",
            revisit_trigger="Revisit after issue #115 reaches READY.",
            decision_note="Defer until the named portfolio trigger occurs.",
            user_input_sha256="c" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T04:02:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:02:03Z",
        )
        self.assertEqual(
            {DEVELOPMENT_SESSION: "HOLD"},
            decision["delivery_states"],
        )
        stored = self.store.connection.execute(
            "SELECT revisit_trigger FROM approval_decisions WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()[0]
        self.assertEqual("Revisit after issue #115 reaches READY.", stored)
        notice_state = self.store.connection.execute(
            "SELECT m.state FROM approval_proposal_notices n JOIN coordination_messages m "
            "ON m.id=n.message_id WHERE n.proposal_sha256=?",
            (proposal,),
        ).fetchone()[0]
        self.assertEqual("COMPLETE", notice_state)

    def test_revocation_holds_old_delivery_and_allows_corrected_successor(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        decision = self.decide(proposal)
        revoked = revoke_decision(
            self.store,
            proposal_sha256=proposal,
            decision_sha256=decision["decision_sha256"],
            reason="The user corrected the material decision before execution.",
            user_input_sha256="d" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T04:03:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:03:03Z",
        )
        self.assertEqual("REVOKED", revoked["state"])
        delivery = self.store.connection.execute(
            "SELECT state,last_error FROM approval_deliveries WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()
        self.assertEqual(
            ("HOLD", "APPROVAL_USER_DECISION_SUPERSEDED"), tuple(delivery)
        )
        successor = submit_proposal(
            self.store,
            self.packet(summary="Choose the corrected post-revocation behavior"),
            "2026-08-24T04:03:04Z",
        )
        self.assertNotEqual(proposal, successor["proposal_sha256"])

    def test_review_batch_uses_safety_then_portfolio_order_not_submitter_only(self) -> None:
        product = self.packet(key="issue-58:product-choice")
        security = self.packet(key="issue-58:security-choice")
        security["boundary"] = "SECURITY_PRIVACY"
        submit_proposal(self.store, product, "2026-08-24T04:00:02Z")
        secured = submit_proposal(self.store, security, "2026-08-24T04:00:03Z")
        batch = create_review_batch(self.store, REPOSITORY, "2026-08-24T04:00:04Z")
        self.assertEqual(secured["proposal_sha256"], batch["proposals"][0]["proposal_sha256"])

    def test_same_recipient_preserves_all_submitting_workstreams(self) -> None:
        planner = self.packet()
        planner["requester_session_id"] = PLANNER_SESSION
        planner["recipient_session_id"] = PLANNER_SESSION
        planner["workstream"] = "PLANNER"
        portfolio = dict(planner)
        portfolio["workstream"] = "PORTFOLIO"
        first = submit_proposal(self.store, planner, "2026-08-24T04:00:02Z")
        second = submit_proposal(self.store, portfolio, "2026-08-24T04:00:03Z")
        self.assertEqual(first["proposal_sha256"], second["proposal_sha256"])
        batch = create_review_batch(self.store, REPOSITORY, "2026-08-24T04:00:04Z")
        self.assertEqual(
            ["PLANNER", "PORTFOLIO"],
            batch["proposals"][0]["interested_workstreams"],
        )
        interests = self.store.connection.execute(
            "SELECT COUNT(*) FROM approval_interests WHERE proposal_sha256=?",
            (first["proposal_sha256"],),
        ).fetchone()[0]
        self.assertEqual(1, interests)

    def test_claim_returns_nonrecommended_selected_option(self) -> None:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        batch_sha256, answer_map = self.batch_answer(proposal, "REVISE")
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
            batch_sha256=batch_sha256,
            batch_answer_map=answer_map,
            decision="COURSE_CORRECT",
            selected_option_id="REVISE",
            revisit_trigger=None,
            decision_note="Use the non-recommended hold option and revise the proposal.",
            user_input_sha256="e" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T04:04:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:04:03Z",
        )
        self.publish(decision["owner_outbox_id"])
        claimed = claim_decision(
            self.store,
            proposal_sha256=proposal,
            recipient_session_id=DEVELOPMENT_SESSION,
            now="2026-08-24T04:04:06Z",
            source_refresher=self.refreshed_source,
        )
        self.assertEqual("COURSE_CORRECT", claimed["decision"])
        self.assertEqual("REVISE", claimed["selected_option_id"])
        self.assertIsNone(claimed["revisit_trigger"])

    def test_decision_freezes_recipient_set_but_allows_same_recipient_evidence(self) -> None:
        planner = self.packet()
        planner["requester_session_id"] = PLANNER_SESSION
        planner["recipient_session_id"] = PLANNER_SESSION
        planner["workstream"] = "PLANNER"
        proposal = submit_proposal(
            self.store, planner, "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        batch_sha256, answer_map = self.batch_answer(proposal, "ENABLE")
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
            batch_sha256=batch_sha256,
            batch_answer_map=answer_map,
            decision="APPROVE",
            selected_option_id="ENABLE",
            revisit_trigger=None,
            decision_note="Approve the exact frozen recipient set.",
            user_input_sha256="f" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T04:05:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:05:03Z",
        )
        portfolio = dict(planner)
        portfolio["workstream"] = "PORTFOLIO"
        clustered = submit_proposal(
            self.store, portfolio, "2026-08-24T04:05:04Z"
        )
        self.assertTrue(clustered["clustered"])
        sre = self.packet()
        sre["requester_session_id"] = SRE_SESSION
        sre["recipient_session_id"] = SRE_SESSION
        sre["workstream"] = "SRE"
        with self.assertRaisesRegex(
            CoordinationError, "APPROVAL_RECIPIENT_SET_FROZEN"
        ):
            submit_proposal(self.store, sre, "2026-08-24T04:05:05Z")
        stored = self.store.connection.execute(
            "SELECT recipient_set_sha256 FROM approval_decisions WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()[0]
        self.assertEqual(decision["decision_sha256"], self.store.connection.execute(
            "SELECT decision_sha256 FROM approval_decisions WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()[0])
        self.assertEqual(64, len(stored))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM approval_deliveries WHERE proposal_sha256=?",
                (proposal,),
            ).fetchone()[0],
        )


class ApprovalSemanticContractV2ActivationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "coordination"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        store = CoordinationStore(self.database)
        ensure_schema(store.connection)
        with store.transaction():
            store.connection.execute(
                "INSERT INTO approval_semantic_contract_current("
                "singleton,schema,authority_sha256,activated_at) "
                "VALUES (1,?,?,?)",
                (
                    "twinfinity.approval-proposal.v1",
                    "1" * 64,
                    "2026-09-04T05:00:00Z",
                ),
            )
        store.close()
        self.request = self.root / "activation-request.json"
        self.request_payload = {
            "schema": (
                "twinfinity.approval-semantic-contract-v2-activation-request.v1"
            ),
            "repository": "jayendusharma/twinfinity-harness",
            "accepted_harness_main_sha": "2" * 40,
            "schema_sentinel_sha256": (
                approval_ledger_module
                .SEMANTIC_CONTRACT_V2_ACTIVATION_SCHEMA_SENTINEL_SHA256
            ),
            "expected_v1_pointer": {
                "singleton": 1,
                "schema": "twinfinity.approval-proposal.v1",
                "authority_sha256": "1" * 64,
                "activated_at": "2026-09-04T05:00:00Z",
            },
            "v2_authority_sha256": "3" * 64,
            "legacy_authority_inventory_sha256": "4" * 64,
            "stopped_state_evidence_sha256": "5" * 64,
            "operation_key": "issue-193-v2-activation",
        }
        self.write_request(self.request_payload)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_request(self, payload: dict) -> None:
        self.request.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    def run_cli(self, *arguments: str) -> tuple[int, dict]:
        output = io.StringIO()
        with (
            patch.object(approval_ledger_module, "DEFAULT_DATABASE", self.database),
            patch.object(
                sys,
                "argv",
                ["approval_ledger.py", *arguments],
            ),
            redirect_stdout(output),
        ):
            result = approval_ledger_module.main()
        return result, json.loads(output.getvalue())

    def preview(self) -> dict:
        code, result = self.run_cli(
            "semantic-contract-v2-preview", "--request", str(self.request)
        )
        self.assertEqual(0, code)
        return result

    def apply(self, preview: dict) -> tuple[int, dict]:
        return self.run_cli(
            "semantic-contract-v2-apply",
            "--request",
            str(self.request),
            "--expected-request-sha256",
            preview["request_sha256"],
            "--expected-preview-sha256",
            preview["preview_sha256"],
        )

    def database_dump(self) -> list[str]:
        connection = sqlite3.connect(
            f"{self.database.as_uri()}?mode=ro&immutable=1", uri=True
        )
        try:
            return list(connection.iterdump())
        finally:
            connection.close()

    def test_registered_preview_command_is_available_and_non_mutating(self) -> None:
        before = self.database.read_bytes()
        before_names = sorted(path.name for path in self.root.iterdir())
        result = self.preview()
        self.assertEqual(
            "twinfinity.approval-semantic-contract-v2-activation-preview.v1",
            result["schema"],
        )
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(
            before_names, sorted(path.name for path in self.root.iterdir())
        )

    def test_apply_commits_pointer_and_receipt_atomically_then_replays_exactly(
        self,
    ) -> None:
        preview = self.preview()
        code, first = self.apply(preview)
        self.assertEqual(0, code)
        self.assertEqual(
            "twinfinity.approval-semantic-contract-v2-activation-receipt.v1",
            first["schema"],
        )
        connection = sqlite3.connect(
            f"{self.database.as_uri()}?mode=ro&immutable=1", uri=True
        )
        try:
            pointer = connection.execute(
                "SELECT singleton,schema,authority_sha256,activated_at "
                "FROM approval_semantic_contract_current"
            ).fetchone()
            event = connection.execute(
                "SELECT event_type,entity_key,payload_sha256,created_at "
                "FROM approval_events WHERE event_type=?",
                (
                    approval_ledger_module
                    .SEMANTIC_CONTRACT_V2_ACTIVATION_EVENT,
                ),
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(
            (1, "twinfinity.approval-proposal.v2", "3" * 64),
            pointer[:3],
        )
        self.assertEqual(1, len(event))
        self.assertEqual(first["receipt_sha256"], event[0][2])
        self.assertEqual(pointer[3], event[0][3])

        before_dump = self.database_dump()
        before_bytes = self.database.read_bytes()
        code, replay = self.apply(preview)
        self.assertEqual(0, code)
        self.assertEqual(first, replay)
        self.assertEqual(before_dump, self.database_dump())
        self.assertEqual(before_bytes, self.database.read_bytes())
        self.assertEqual(preview, self.preview())

    def test_request_and_preview_digest_drift_fail_before_writable_open(self) -> None:
        preview = self.preview()
        before = self.database_dump()
        cases = (
            ("0" * 64, preview["preview_sha256"], "REQUEST_DIGEST_DRIFT"),
            (preview["request_sha256"], "0" * 64, "PREVIEW_DRIFT"),
        )
        for request_sha, preview_sha, error in cases:
            with self.subTest(error=error):
                code, result = self.run_cli(
                    "semantic-contract-v2-apply",
                    "--request",
                    str(self.request),
                    "--expected-request-sha256",
                    request_sha,
                    "--expected-preview-sha256",
                    preview_sha,
                )
                self.assertEqual(1, code)
                self.assertIn(error, result["error"])
                self.assertEqual(before, self.database_dump())

    def test_every_bound_request_field_substitution_is_zero_write(self) -> None:
        preview = self.preview()
        before = self.database_dump()
        substitutions = {
            "repository": "other/harness",
            "accepted_harness_main_sha": "6" * 40,
            "schema_sentinel_sha256": "6" * 64,
            "expected_v1_pointer": {
                **self.request_payload["expected_v1_pointer"],
                "authority_sha256": "6" * 64,
            },
            "v2_authority_sha256": "6" * 64,
            "legacy_authority_inventory_sha256": "6" * 64,
            "stopped_state_evidence_sha256": "6" * 64,
            "operation_key": "issue-193-v2-activation-substituted",
        }
        for field, value in substitutions.items():
            with self.subTest(field=field):
                changed = dict(self.request_payload)
                changed[field] = value
                self.write_request(changed)
                code, _result = self.run_cli(
                    "semantic-contract-v2-apply",
                    "--request",
                    str(self.request),
                    "--expected-request-sha256",
                    preview["request_sha256"],
                    "--expected-preview-sha256",
                    preview["preview_sha256"],
                )
                self.assertEqual(1, code)
                self.assertEqual(before, self.database_dump())
        self.write_request(self.request_payload)

    def test_pointer_singleton_rejects_boolean_json_alias(self) -> None:
        changed = dict(self.request_payload)
        changed["expected_v1_pointer"] = {
            **self.request_payload["expected_v1_pointer"],
            "singleton": True,
        }
        self.write_request(changed)
        before = self.database_dump()
        code, result = self.run_cli(
            "semantic-contract-v2-preview", "--request", str(self.request)
        )
        self.assertEqual(1, code)
        self.assertIn("ACTIVATION_REQUEST_INVALID", result["error"])
        self.assertEqual(before, self.database_dump())

    def test_missing_schema_and_explicit_v1_pointer_do_not_create_state(self) -> None:
        empty = self.root / "empty.sqlite3"
        sqlite3.connect(empty).close()
        empty.chmod(0o600)
        no_pointer = self.root / "no-pointer.sqlite3"
        store = CoordinationStore(no_pointer)
        ensure_schema(store.connection)
        store.close()
        preview = approval_ledger_module._semantic_contract_v2_activation_preview(
            self.request_payload
        )
        for database, expected_error in (
            (empty, "SCHEMA_SENTINEL_REQUIRED"),
            (no_pointer, "EXPLICIT_V1_POINTER_REQUIRED"),
        ):
            with self.subTest(database=database.name):
                original = self.database
                self.database = database
                before_bytes = database.read_bytes()
                before_names = sorted(path.name for path in self.root.iterdir())
                for command in ("preview", "apply"):
                    with self.subTest(command=command):
                        if command == "preview":
                            code, result = self.run_cli(
                                "semantic-contract-v2-preview",
                                "--request",
                                str(self.request),
                            )
                        else:
                            code, result = self.run_cli(
                                "semantic-contract-v2-apply",
                                "--request",
                                str(self.request),
                                "--expected-request-sha256",
                                preview["request_sha256"],
                                "--expected-preview-sha256",
                                preview["preview_sha256"],
                            )
                        self.assertEqual(1, code)
                        self.assertIn(expected_error, result["error"])
                        self.assertEqual(before_bytes, database.read_bytes())
                        self.assertEqual(
                            before_names,
                            sorted(path.name for path in self.root.iterdir()),
                        )
                self.database = original

    def test_drifted_schema_sentinel_is_rejected_without_further_effect(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "DROP TRIGGER approval_semantic_contract_no_downgrade"
        )
        connection.commit()
        connection.close()
        before = self.database.read_bytes()
        before_names = sorted(path.name for path in self.root.iterdir())
        code, result = self.run_cli(
            "semantic-contract-v2-preview", "--request", str(self.request)
        )
        self.assertEqual(1, code)
        self.assertIn("SCHEMA_SENTINEL_REQUIRED", result["error"])
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(
            before_names, sorted(path.name for path in self.root.iterdir())
        )

    def test_receipt_failure_rolls_back_pointer_and_event_together(self) -> None:
        preview = self.preview()
        before = self.database_dump()
        original_event = approval_ledger_module._event

        def fail_after_event(*args, **kwargs) -> None:
            original_event(*args, **kwargs)
            raise CoordinationError("INJECTED_RECEIPT_FAILURE")

        with patch.object(
            approval_ledger_module,
            "_event",
            side_effect=fail_after_event,
        ):
            code, result = self.apply(preview)
        self.assertEqual(1, code)
        self.assertEqual("INJECTED_RECEIPT_FAILURE", result["error"])
        self.assertEqual(before, self.database_dump())

    def test_non_activation_v1_rows_are_byte_preserved(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "INSERT INTO approval_events("
            "event_type,entity_key,payload_sha256,created_at) VALUES (?,?,?,?)",
            ("LEGACY_V1_EVIDENCE", "approval:legacy", "7" * 64,
             "2026-09-04T05:00:01Z"),
        )
        connection.commit()
        before = connection.execute(
            "SELECT event_type,entity_key,payload_sha256,created_at "
            "FROM approval_events WHERE event_type='LEGACY_V1_EVIDENCE'"
        ).fetchone()
        connection.close()
        preview = self.preview()
        code, _receipt = self.apply(preview)
        self.assertEqual(0, code)
        connection = sqlite3.connect(
            f"{self.database.as_uri()}?mode=ro&immutable=1", uri=True
        )
        try:
            after = connection.execute(
                "SELECT event_type,entity_key,payload_sha256,created_at "
                "FROM approval_events WHERE event_type='LEGACY_V1_EVIDENCE'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(before, after)

    def test_noncanonical_request_and_busy_sidecars_fail_with_zero_effect(self) -> None:
        self.request.write_text(
            json.dumps(self.request_payload, indent=2), encoding="utf-8"
        )
        before = self.database_dump()
        code, result = self.run_cli(
            "semantic-contract-v2-preview", "--request", str(self.request)
        )
        self.assertEqual(1, code)
        self.assertIn("REQUEST_INVALID", result["error"])
        self.assertEqual(before, self.database_dump())

        self.write_request(self.request_payload)
        wal = Path(f"{self.database}-wal")
        wal.write_bytes(b"synthetic-busy-sidecar")
        before_database = self.database.read_bytes()
        before_wal = wal.read_bytes()
        code, result = self.run_cli(
            "semantic-contract-v2-preview", "--request", str(self.request)
        )
        self.assertEqual(1, code)
        self.assertIn("ACTIVATION_NOT_QUIESCENT", result["error"])
        self.assertEqual(before_database, self.database.read_bytes())
        self.assertEqual(before_wal, wal.read_bytes())

    def test_dangling_sidecar_entry_is_not_treated_as_quiescent(self) -> None:
        wal = Path(f"{self.database}-wal")
        wal.symlink_to(self.root / "missing-wal-target")
        before = self.database.read_bytes()
        code, result = self.run_cli(
            "semantic-contract-v2-preview", "--request", str(self.request)
        )
        self.assertEqual(1, code)
        self.assertIn("ACTIVATION_NOT_QUIESCENT", result["error"])
        self.assertEqual(before, self.database.read_bytes())
        self.assertTrue(wal.is_symlink())

    def test_extra_activation_table_trigger_is_schema_drift(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "CREATE TRIGGER unexpected_activation_receipt_effect "
            "AFTER INSERT ON approval_events BEGIN SELECT 1; END"
        )
        connection.commit()
        connection.close()
        before = self.database.read_bytes()
        code, result = self.run_cli(
            "semantic-contract-v2-preview", "--request", str(self.request)
        )
        self.assertEqual(1, code)
        self.assertIn("SCHEMA_SENTINEL_INVALID", result["error"])
        self.assertEqual(before, self.database.read_bytes())

    def test_writable_open_cannot_follow_a_post_preflight_path_swap(self) -> None:
        preview = self.preview()
        victim = self.root / "replacement.sqlite3"
        victim.write_bytes(self.database.read_bytes())
        victim.chmod(0o600)
        victim_before = victim.read_bytes()
        original_validate = (
            approval_ledger_module._validated_quiescent_activation_database
        )
        validations = 0

        def swap_before_writable_open(path: Path) -> Path:
            nonlocal validations
            validated = original_validate(path)
            validations += 1
            if validations == 2:
                validated.unlink()
                validated.symlink_to(victim)
            return validated

        with patch.object(
            approval_ledger_module,
            "_validated_quiescent_activation_database",
            side_effect=swap_before_writable_open,
        ):
            code, result = self.apply(preview)
        self.assertEqual(1, code)
        self.assertIn("ACTIVATION_DATABASE_UNSAFE", result["error"])
        self.assertEqual(victim_before, victim.read_bytes())
        self.assertTrue(self.database.is_symlink())

    def test_pointer_drift_between_preflight_and_transaction_cannot_activate(
        self,
    ) -> None:
        preview = self.preview()
        original_validate = (
            approval_ledger_module._validated_quiescent_activation_database
        )
        validations = 0

        def drift_before_writable_open(path: Path) -> Path:
            nonlocal validations
            validated = original_validate(path)
            validations += 1
            if validations == 2:
                connection = sqlite3.connect(validated)
                connection.execute(
                    "UPDATE approval_semantic_contract_current "
                    "SET authority_sha256=? WHERE singleton=1",
                    ("6" * 64,),
                )
                connection.commit()
                connection.close()
            return validated

        with patch.object(
            approval_ledger_module,
            "_validated_quiescent_activation_database",
            side_effect=drift_before_writable_open,
        ):
            code, result = self.apply(preview)
        self.assertEqual(1, code)
        self.assertIn("ACTIVATION_POINTER_DRIFT", result["error"])
        connection = sqlite3.connect(
            f"{self.database.as_uri()}?mode=ro&immutable=1", uri=True
        )
        try:
            pointer = connection.execute(
                "SELECT schema,authority_sha256 "
                "FROM approval_semantic_contract_current WHERE singleton=1"
            ).fetchone()
            activation_events = connection.execute(
                "SELECT COUNT(*) FROM approval_events WHERE event_type=?",
                (
                    approval_ledger_module
                    .SEMANTIC_CONTRACT_V2_ACTIVATION_EVENT,
                ),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(
            ("twinfinity.approval-proposal.v1", "6" * 64), pointer
        )
        self.assertEqual(0, activation_events)

    def test_v2_without_exact_receipt_cannot_be_treated_as_replay(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE approval_semantic_contract_current "
            "SET schema=?,authority_sha256=?,activated_at=? WHERE singleton=1",
            (
                "twinfinity.approval-proposal.v2",
                self.request_payload["v2_authority_sha256"],
                "2026-09-04T05:00:02Z",
            ),
        )
        connection.commit()
        connection.close()
        preview = approval_ledger_module._semantic_contract_v2_activation_preview(
            self.request_payload
        )
        before = self.database_dump()
        code, result = self.apply(preview)
        self.assertEqual(1, code)
        self.assertIn("ACTIVATION_RECEIPT_INVALID", result["error"])
        self.assertEqual(before, self.database_dump())

    def test_changed_operation_cannot_replay_an_existing_activation(self) -> None:
        preview = self.preview()
        code, _receipt = self.apply(preview)
        self.assertEqual(0, code)
        before = self.database_dump()
        changed = dict(self.request_payload)
        changed["operation_key"] = "issue-193-v2-activation-other"
        self.write_request(changed)
        changed_preview = (
            approval_ledger_module._semantic_contract_v2_activation_preview(
                changed
            )
        )
        code, result = self.apply(changed_preview)
        self.assertEqual(1, code)
        self.assertIn("OPERATION_CONFLICT", result["error"])
        self.assertEqual(before, self.database_dump())

    def test_changed_authority_with_recomputed_digests_cannot_replay(self) -> None:
        preview = self.preview()
        code, _receipt = self.apply(preview)
        self.assertEqual(0, code)
        before = self.database_dump()
        changed = dict(self.request_payload)
        changed["v2_authority_sha256"] = "6" * 64
        self.write_request(changed)
        changed_preview = (
            approval_ledger_module._semantic_contract_v2_activation_preview(
                changed
            )
        )
        code, result = self.apply(changed_preview)
        self.assertEqual(1, code)
        self.assertIn("OPERATION_CONFLICT", result["error"])
        self.assertEqual(before, self.database_dump())


if __name__ == "__main__":
    unittest.main()
