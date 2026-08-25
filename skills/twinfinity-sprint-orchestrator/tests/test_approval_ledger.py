from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest


import sys

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from approval_ledger import (  # noqa: E402
    acknowledge_decision,
    claim_decision,
    create_review_batch,
    ensure_schema,
    load_packet,
    record_decision,
    revoke_decision,
    submit_proposal,
    validate_packet,
)
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
)
from executor_registry import load_registry_config  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)


REPOSITORY = "twinfinityai/twinfinityapp"
DEVELOPMENT_SESSION = "role.development.v3"
PLANNER_SESSION = "role.planner.v2"
SRE_SESSION = "role.sre.v3"
REQUESTER = DEVELOPMENT_SESSION


class ApprovalLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.store = CoordinationStore(root / "state.sqlite3")
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
            "schema": "twinfinity.approval-proposal.v1",
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
                {"id": "ENABLE", "label": "Enable", "effect": "Enable the bounded behavior."},
                {"id": "HOLD", "label": "Hold", "effect": "Keep the behavior unchanged."},
            ],
            "recommendation": "ENABLE",
            "expires_at": None,
        }

    def decide(self, proposal_sha256: str) -> dict:
        return record_decision(
            self.store,
            proposal_sha256=proposal_sha256,
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
        with self.assertRaisesRegex(CoordinationError, "PLANNER_SESSION_REQUIRED"):
            record_decision(
                self.store,
                proposal_sha256=proposal,
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
        endpoint_packet["requester_session_id"] = "role.development.v2"
        endpoint_packet["recipient_session_id"] = "role.development.v2"
        self.assertEqual(
            "role.development.v2",
            validate_packet(endpoint_packet)["recipient_session_id"],
        )

        submitted = submit_proposal(
            self.store, self.packet(key="issue-58:legacy-delivery"),
            "2026-08-24T04:00:02Z",
        )
        decision = self.decide(submitted["proposal_sha256"])
        self.publish(decision["owner_outbox_id"])
        root = Path(__file__).resolve().parents[1]
        config = load_registry_config(
            root / "references" / "twinfinity-executor-registry.toml"
        )
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
        config = load_registry_config(
            root / "references" / "twinfinity-executor-registry.toml"
        )
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
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
            decision="DEFER",
            selected_option_id="HOLD",
            revisit_trigger="Revisit after issue #115 reaches READY.",
            decision_note="Defer until the named portfolio trigger occurs.",
            user_input_sha256="c" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T04:02:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T04:02:03Z",
        )
        self.assertEqual({DEVELOPMENT_SESSION: "HOLD"}, decision["delivery_states"])
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
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
            decision="COURSE_CORRECT",
            selected_option_id="HOLD",
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
        self.assertEqual("HOLD", claimed["selected_option_id"])
        self.assertIsNone(claimed["revisit_trigger"])

    def test_decision_freezes_recipient_set_but_allows_same_recipient_evidence(self) -> None:
        planner = self.packet()
        planner["requester_session_id"] = PLANNER_SESSION
        planner["recipient_session_id"] = PLANNER_SESSION
        planner["workstream"] = "PLANNER"
        proposal = submit_proposal(
            self.store, planner, "2026-08-24T04:00:02Z"
        )["proposal_sha256"]
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
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


if __name__ == "__main__":
    unittest.main()
