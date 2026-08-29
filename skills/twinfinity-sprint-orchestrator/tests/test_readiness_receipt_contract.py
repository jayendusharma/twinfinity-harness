from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


SKILL_ROOT = Path(__file__).resolve().parents[1]
STAGED = SKILL_ROOT / "scripts"
sys.path.insert(0, str(STAGED))

from coordination_store import canonical_json  # noqa: E402
from kanban_readiness import (  # noqa: E402
    READINESS_APPROVAL_INPUT_SCHEMA,
    READINESS_DECISION_MAPPING,
    RECEIPT_SCHEMA,
    ReadinessError,
    _validate_receipt,
)


REPOSITORY = "twinfinityai/twinfinityapp"
SCHEMA_PATH = (
    SKILL_ROOT / "references" / "twinfinity-kanban-readiness-receipt-v2.schema.json"
)


class ReadinessReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema_bytes = SCHEMA_PATH.read_bytes()
        cls.schema = json.loads(cls.schema_bytes)
        Draft202012Validator.check_schema(cls.schema)
        cls.json_schema_validator = Draft202012Validator(cls.schema)

    @staticmethod
    def _gate(verdict: str) -> dict:
        return {
            "gate_key": "complete-review",
            "verdict": verdict,
            "evidence_sha256": "e" * 64,
            "summary": "The complete readiness gate was evaluated.",
        }

    @staticmethod
    def _planner_action() -> dict:
        return {
            "kind": "REBUILD_PREPARED_CANDIDATE",
            "target": f"{REPOSITORY}:issue:1",
            "expected_digest": "a" * 64,
            "desired_digest": "b" * 64,
            "authority_class": "PLANNER_OWNER_API",
            "evidence_required": [
                "portfolio_pull_buffer_current.candidate_id",
                "portfolio_pull_buffer_candidates.candidate_sha256",
            ],
        }

    @staticmethod
    def _approval_packet() -> dict:
        return {
            "schema": "twinfinity.approval-proposal.v1",
            "decision_key": "issue-1:readiness-campaign-1:product-behavior",
            "repository": REPOSITORY,
            "owning_issue": 1,
            "source_snapshot_sha256": "c" * 64,
            "execution_scope_sha256": "d" * 64,
            "requester_session_id": "role.sre.v5",
            "recipient_session_id": "role.planner.v2",
            "workstream": "READINESS",
            "boundary": "PRODUCT_BEHAVIOR",
            "priority": "P1",
            "urgency": "READY_BLOCKER",
            "summary": "Issue 1 needs one material product behavior decision.",
            "question": "Should the bounded product behavior proceed?",
            "requested_action": "Select one exact disposition.",
            "target": "Issue 1 readiness campaign 1.",
            "affected_issues": [1],
            "blocked_mutation": "Register the deterministic readiness successor.",
            "immediate_beneficiary": "The issue 1 delivery lineage.",
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
                    "effect": "Resume from the exact effective decision.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "REJECT",
                    "label": "Reject",
                    "effect": "Hold the lineage.",
                    "machine_outcome": "REJECT",
                },
                {
                    "id": "DEFER",
                    "label": "Defer",
                    "effect": "Hold and arm one typed revisit.",
                    "machine_outcome": "DEFER",
                },
                {
                    "id": "COURSE_CORRECT",
                    "label": "Course correct",
                    "effect": "Hold pending a newly scoped proposal.",
                    "machine_outcome": "COURSE_CORRECT",
                },
            ],
            "recommendation": "APPROVE",
            "expires_at": None,
        }

    @classmethod
    def _approval_action(cls) -> dict:
        return {
            "kind": "REQUEST_MATERIAL_APPROVAL",
            "target": f"{REPOSITORY}:issue:1",
            "expected_digest": "a" * 64,
            "desired_digest": "d" * 64,
            "authority_class": "HUMAN_APPROVAL",
            "evidence_required": ["approval_ledger.published_decision"],
        }

    @classmethod
    def _receipt(cls, verdict: str) -> dict:
        resolution: dict
        gate_verdict = "PASS" if verdict == "PASS" else "HOLD"
        if verdict == "ACTIONABLE_HOLD":
            resolution = {
                "role": "planner",
                "actions": [cls._planner_action()],
                "approval": None,
            }
        elif verdict == "APPROVAL_REQUIRED":
            resolution = {
                "role": "planner",
                "actions": [cls._approval_action()],
                "approval": {
                    "schema": READINESS_APPROVAL_INPUT_SCHEMA,
                    "packet": cls._approval_packet(),
                    "material_boundary": "PRODUCT_BEHAVIOR",
                    "decision_mapping": READINESS_DECISION_MAPPING,
                },
            }
        else:
            resolution = {"role": None, "actions": [], "approval": None}
        return {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": 1,
            "readiness_plan_sha256": "a" * 64,
            "delivery_identity_sha256": "b" * 64,
            "verdict": verdict,
            "worker_role": "sre",
            "message_id": 7,
            "attempt_id": "11111111-1111-4111-8111-111111111111",
            "gate_results": [cls._gate(gate_verdict)],
            "resolution": resolution,
            "summary": "The complete candidate phase reached one exact verdict.",
            "observed_at": "2026-08-25T05:00:00Z",
        }

    def _assert_accepted_by_both(self, receipt: dict) -> None:
        raw = canonical_json(receipt).encode("utf-8")
        self.json_schema_validator.validate(json.loads(raw))
        _validate_receipt(json.loads(raw))

    def _assert_rejected_by_both(self, receipt: dict) -> None:
        raw = canonical_json(receipt).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.json_schema_validator.validate(json.loads(raw))
        with self.assertRaises(ReadinessError):
            _validate_receipt(json.loads(raw))

    def test_same_canonical_bytes_pass_both_contracts_for_all_verdicts(self) -> None:
        for verdict in (
            "PASS",
            "ACTIONABLE_HOLD",
            "APPROVAL_REQUIRED",
            "TERMINAL_HOLD",
        ):
            with self.subTest(verdict=verdict):
                self._assert_accepted_by_both(self._receipt(verdict))

    def test_legacy_digest_only_extra_and_missing_forms_fail_both_contracts(self) -> None:
        approval = self._receipt("APPROVAL_REQUIRED")
        adversarial: dict[str, dict] = {}

        legacy = deepcopy(approval)
        legacy["resolution"] = {
            "role": "planner",
            "actions": legacy["resolution"]["actions"],
            "approval_proposal_sha256": "f" * 64,
        }
        adversarial["legacy-resolution"] = legacy

        digest_only = deepcopy(approval)
        digest_only["resolution"]["approval"] = "f" * 64
        adversarial["digest-only-approval"] = digest_only

        extra = deepcopy(approval)
        extra["resolution"]["approval"]["packet"]["unexpected"] = True
        adversarial["extra-packet-field"] = extra

        missing = deepcopy(approval)
        del missing["resolution"]["approval"]["packet"]["decision_key"]
        adversarial["missing-packet-field"] = missing

        historical = deepcopy(approval)
        historical["schema"] = "twinfinity-kanban-readiness-receipt/v1"
        del historical["delivery_identity_sha256"]
        adversarial["historical-v1-unbound"] = historical

        for form, receipt in adversarial.items():
            with self.subTest(form=form):
                self._assert_rejected_by_both(receipt)


if __name__ == "__main__":
    unittest.main()
