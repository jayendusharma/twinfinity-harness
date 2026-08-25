from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from approval_guard import (  # noqa: E402
    ApprovalGuardError,
    admission_execution_scope_sha256,
    require_effective_approval,
)
from approval_ledger import (  # noqa: E402
    claim_decision,
    create_review_batch,
    record_decision,
    revoke_decision,
    submit_proposal,
)
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    digest_json,
)
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
PLANNER_SESSION = "role.planner.v2"
SRE_SESSION = "role.sre.v4"


class ApprovalGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.store = CoordinationStore(root / "state.sqlite3")
        apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="approval-guard-tests",
        )
        self.source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            payload={"number": 143, "title": "Staging", "updated_at": "2026-08-24T05:00:00Z"},
            source_updated_at="2026-08-24T05:00:00Z",
            fetched_at="2026-08-24T05:00:01Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def packet(self) -> dict:
        packet = {
            "schema": "twinfinity.approval-proposal.v1",
            "decision_key": "issue-143:ruleset-update",
            "repository": REPOSITORY,
            "owning_issue": 143,
            "source_snapshot_sha256": self.source.payload_sha256,
            "execution_scope_sha256": "0" * 64,
            "requester_session_id": SRE_SESSION,
            "recipient_session_id": SRE_SESSION,
            "workstream": "SRE",
            "boundary": "HOSTED_PROVIDER",
            "priority": "P0",
            "urgency": "READY_BLOCKER",
            "summary": "Apply the exact reviewed main ruleset change.",
            "question": "Should the exact reviewed ruleset update proceed?",
            "requested_action": "Update only the reviewed ruleset fields.",
            "target": "GitHub main ruleset for twinfinityapp",
            "affected_issues": [143],
            "blocked_mutation": "The ruleset update is paused.",
            "immediate_beneficiary": "Gate A release operators",
            "evidence": ["The current issue snapshot records the exact target."],
            "risk": "An adjacent settings change could alter repository policy.",
            "drift_guards": ["Issue and target must remain exact."],
            "prohibited_side_effects": ["No repository content or deployment mutation."],
            "options": [
                {
                    "id": "UPDATE",
                    "label": "Update",
                    "effect": "Apply only reviewed settings.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "HOLD",
                    "label": "Hold",
                    "effect": "Leave settings unchanged.",
                    "machine_outcome": "REJECT",
                },
            ],
            "recommendation": "UPDATE",
            "expires_at": None,
        }
        packet["execution_scope_sha256"] = admission_execution_scope_sha256(
            {
                "source": {"repository": REPOSITORY},
                "issue_number": 143,
                "generation": 1,
                "item_version": 1,
                "action": "CREATE_LOCAL_BRANCH_AND_WORKTREE_THEN_CONTINUE",
                "base_sha": "a" * 40,
                "branch": "codex/143-ruleset-update",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-143",
                "lease_manifest_sha256": "1" * 64,
                "capacity": {
                    "development_units": 0,
                    "shared_units": 0,
                    "sre_units": 1,
                },
            }
        )
        return packet

    def effective(self) -> tuple[str, int]:
        proposal = submit_proposal(
            self.store, self.packet(), "2026-08-24T05:00:02Z"
        )["proposal_sha256"]
        batch = create_review_batch(
            self.store, REPOSITORY, "2026-08-24T05:00:03Z"
        )
        answer_map = {
            "schema": "twinfinity.approval-batch-answer-map.v1",
            "batch_sha256": batch["batch_sha256"],
            "answers": [
                {
                    "proposal_sha256": proposal,
                    "selected_option_id": "UPDATE",
                }
            ],
        }
        decision = record_decision(
            self.store,
            proposal_sha256=proposal,
            batch_sha256=batch["batch_sha256"],
            batch_answer_map=answer_map,
            decision="APPROVE",
            selected_option_id="UPDATE",
            revisit_trigger=None,
            decision_note="Approved only for the exact reviewed settings update.",
            user_input_sha256=digest_json(answer_map),
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T05:00:03Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T05:00:03Z",
        )
        self.store.reserve_outbox(decision["owner_outbox_id"], "2026-08-24T05:00:04Z")
        self.store.complete_outbox(
            decision["owner_outbox_id"], "comment:4321", "2026-08-24T05:00:05Z"
        )
        claim_decision(
            self.store,
            proposal_sha256=proposal,
            recipient_session_id=SRE_SESSION,
            now="2026-08-24T05:00:06Z",
            source_refresher=lambda *_: {
                "number": 143,
                "title": "Staging",
                "updated_at": "2026-08-24T05:00:05Z",
            },
        )
        return decision["decision_sha256"], 4321

    def test_missing_ledger_is_optional_only_for_nonmaterial_legacy_path(self) -> None:
        self.assertIsNone(
            require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=143,
                recipient_session_id=SRE_SESSION,
                execution_scope_sha256=self.packet()["execution_scope_sha256"],
                authority_sha256="a" * 64,
                required=False,
            )
        )
        with self.assertRaisesRegex(ApprovalGuardError, "APPROVAL_LEDGER_REQUIRED"):
            require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=143,
                recipient_session_id=SRE_SESSION,
                execution_scope_sha256=self.packet()["execution_scope_sha256"],
                authority_comment_id=4321,
                required=True,
            )

    def test_effective_decision_binds_digest_and_published_comment(self) -> None:
        decision_sha256, comment_id = self.effective()
        by_digest = require_effective_approval(
            self.store.connection,
            repository=REPOSITORY,
            issue_number=143,
            recipient_session_id=SRE_SESSION,
            execution_scope_sha256=self.packet()["execution_scope_sha256"],
            authority_sha256=decision_sha256,
            required=True,
        )
        by_comment = require_effective_approval(
            self.store.connection,
            repository=REPOSITORY,
            issue_number=143,
            recipient_session_id=SRE_SESSION,
            execution_scope_sha256=self.packet()["execution_scope_sha256"],
            authority_comment_id=comment_id,
            required=True,
        )
        self.assertEqual(decision_sha256, by_digest["decision_sha256"])
        self.assertEqual(decision_sha256, by_comment["decision_sha256"])
        with self.assertRaisesRegex(ApprovalGuardError, "APPROVAL_AUTHORITY_MISMATCH"):
            require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=143,
                recipient_session_id=SRE_SESSION,
                execution_scope_sha256=self.packet()["execution_scope_sha256"],
                authority_sha256="f" * 64,
                required=False,
            )
        with self.assertRaisesRegex(
            ApprovalGuardError, "APPROVAL_EXECUTION_SCOPE_MISMATCH"
        ):
            require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=143,
                recipient_session_id=SRE_SESSION,
                execution_scope_sha256="f" * 64,
                authority_sha256=decision_sha256,
                required=True,
            )

    def test_effective_source_drift_blocks_execution(self) -> None:
        decision_sha256, _ = self.effective()
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            payload={"number": 143, "title": "Changed", "updated_at": "2026-08-24T05:01:00Z"},
            source_updated_at="2026-08-24T05:01:00Z",
            fetched_at="2026-08-24T05:01:01Z",
        )
        with self.assertRaisesRegex(ApprovalGuardError, "APPROVAL_EFFECTIVE_SOURCE_DRIFT"):
            require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=143,
                recipient_session_id=SRE_SESSION,
                execution_scope_sha256=self.packet()["execution_scope_sha256"],
                authority_sha256=decision_sha256,
                required=True,
            )

    def test_timestamp_only_source_refresh_does_not_invalidate_effectivity(self) -> None:
        decision_sha256, _ = self.effective()
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            payload={
                "number": 143,
                "title": "Staging",
                "updated_at": "2026-08-24T05:01:00Z",
                "_projection_updated_at": "2026-08-24T05:01:01Z",
            },
            source_updated_at="2026-08-24T05:01:01Z",
            fetched_at="2026-08-24T05:01:02Z",
        )
        guarded = require_effective_approval(
            self.store.connection,
            repository=REPOSITORY,
            issue_number=143,
            recipient_session_id=SRE_SESSION,
            execution_scope_sha256=self.packet()["execution_scope_sha256"],
            authority_sha256=decision_sha256,
            required=True,
        )
        self.assertEqual(decision_sha256, guarded["decision_sha256"])

    def test_sre_admission_consumes_exact_effective_decision_digest(self) -> None:
        decision_sha256, _ = self.effective()
        current = self.store.current_snapshot(REPOSITORY, "issue", 143)
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=143,
            status="ACTIVE_FENCED",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SRE_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=0,
            shared_units=0,
            sre_units=1,
            expected_source_sha256=current.payload_sha256,
            expected_version=0,
            now="2026-08-24T05:00:07Z",
        )

        def payload(authority: str) -> dict:
            return {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 143,
                    "payload_sha256": current.payload_sha256,
                },
                "issue_number": 143,
                "generation": 1,
                "item_version": 1,
                "action": "CREATE_LOCAL_BRANCH_AND_WORKTREE_THEN_CONTINUE",
                "base_sha": "a" * 40,
                "branch": "codex/143-ruleset-update",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-143",
                "opaque_worktree_id": "twinfinityapp-issue-143",
                "accountable_session_id": SRE_SESSION,
                "lease_manifest_sha256": "1" * 64,
                "authority_sha256": authority,
                "capacity": {
                    "development_units": 0,
                    "shared_units": 0,
                    "sre_units": 1,
                },
            }

        message_id = self.store.enqueue_message(
            idempotency_key="issue143-effective-sre-admission",
            recipient_session_id=SRE_SESSION,
            topic="sre.admission",
            payload=payload(decision_sha256),
            now="2026-08-24T05:00:08Z",
        )
        self.assertGreater(message_id, 0)
        with self.assertRaisesRegex(CoordinationError, "APPROVAL_AUTHORITY_MISMATCH"):
            self.store.enqueue_message(
                idempotency_key="issue143-wrong-sre-admission",
                recipient_session_id=SRE_SESSION,
                topic="sre.admission",
                payload=payload("f" * 64),
                now="2026-08-24T05:00:09Z",
            )

    def test_user_revocation_invalidates_previously_effective_authority(self) -> None:
        decision_sha256, _ = self.effective()
        proposal_sha256 = self.store.connection.execute(
            "SELECT proposal_sha256 FROM approval_decisions WHERE decision_sha256=?",
            (decision_sha256,),
        ).fetchone()[0]
        revoke_decision(
            self.store,
            proposal_sha256=proposal_sha256,
            decision_sha256=decision_sha256,
            reason="The user withdrew the hosted-operation authorization.",
            user_input_sha256="c" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:2026-08-24T05:02:00Z",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-24T05:02:00Z",
        )
        with self.assertRaisesRegex(ApprovalGuardError, "APPROVAL_AUTHORITY_MISMATCH"):
            require_effective_approval(
                self.store.connection,
                repository=REPOSITORY,
                issue_number=143,
                recipient_session_id=SRE_SESSION,
                execution_scope_sha256=self.packet()["execution_scope_sha256"],
                authority_sha256=decision_sha256,
                required=True,
            )


if __name__ == "__main__":
    unittest.main()
