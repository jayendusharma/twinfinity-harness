from __future__ import annotations

import difflib
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_issue_state_overlay.py"
VALIDATOR = ROOT / "references" / "validate_issue_body.py"
SPEC = importlib.util.spec_from_file_location("overlay", SCRIPT)
assert SPEC and SPEC.loader
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)

MAIN = "d" * 40
MANIFEST = "a" * 64
BODY = """> [!IMPORTANT]
> PREPARED on old main.

## User story
As an owner, I want a capability, so that value is delivered.

## Product or operational outcome
Outcome.

## Parent and related issues
- Parent: #1

## Current evidence and assumptions
Accepted main is old-main.

## Dependencies and sequencing
Wait for old predecessor.

## In scope
Bounded.

## Out of scope and hard stops
No expansion.

## Delivery plan
1. Verify the bounded contract.

## Gherkin BDD specification
```gherkin
Feature: Capability
  Scenario: Success
    Given a bounded input
    When it is processed
    Then the outcome is visible

  Scenario: Failure is bounded
    Given a malformed input
    When it is processed
    Then no state is changed
```

## Scenario-to-evidence map
| Scenario | Evidence |
| --- | --- |
| `Success` | Unit evidence |
| `Failure is bounded` | Negative unit evidence |

## Risks, safety, and approval boundary
No material change.

## Definition of done
- [ ] Reviewed and merged.

## Ownership, readiness, and capacity
State: PREPARED
Capacity: old capacity.
Next deterministic action: verify.
"""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload(phase: str = "PREPARED") -> dict:
    ready = phase == "READY"
    data = {
        "schema": overlay.SCHEMA,
        "repository": "owner/repo",
        "issue": 88,
        "generation": 1,
        "predecessor_ledger_comment_id": None,
        "pending_tracker_issue_numbers": [],
        "body": {
            "bytes": len(BODY.encode()),
            "sha256": digest(BODY.encode()),
            "effective_bytes": 0,
            "effective_sha256": "",
            "contract_unchanged": True,
        },
        "supersedes_fields": ["accepted_main", "dependency_state", "capacity"],
        "stale_field_inventory": [
            {
                "fields": ["accepted_main"],
                "section": "Current evidence and assumptions",
                "claim": "Accepted main is old-main.",
                "replacement": f"Accepted main is {MAIN}.",
            },
            {
                "fields": ["dependency_state"],
                "section": "Dependencies and sequencing",
                "claim": "Wait for old predecessor.",
                "replacement": "Predecessor released its collision surface.",
            },
            {
                "fields": ["capacity"],
                "section": "Ownership, readiness, and capacity",
                "claim": "Capacity: old capacity.",
                "replacement": "Capacity: Development 2/5 and Shared 1/2.",
            },
        ],
        "authority": {
            "decision_packet_comment_id": 10,
            "approval_comment_id": 11,
            "lease_accept_comment_id": 12,
            "lease_manifest_sha256": MANIFEST,
            "overlay_review_comment_id": 13,
        },
        "state": {
            "accepted_main": MAIN,
            "phase": phase,
            "zero_wip": True,
            "agent_ready": ready,
            "product_accepted": False,
            "development_occupied": 2,
            "development_limit": 5,
            "shared_occupied": 1,
            "shared_limit": 2,
            "ready_depth": 1 if ready else 0,
            "development_required": 1,
            "shared_required": 1,
        },
        "lease": {
            "kind": "exact-paths",
            "path_count": 20,
            "no_additional_paths": True,
            "manifest_sha256": MANIFEST,
            "absent": 8,
            "existing": 12,
        },
        "guards": {
            "main_current": True,
            "dependencies_satisfied": True,
            "collision_free": True,
            "capacity_available": True,
            "tracker_consistent": True,
            "decision_register_consistent": True,
            "no_newer_hold": True,
            "body_contract_complete": True,
            "body_digest_current": True,
            "agent_ready_label_present": ready,
            "provider_atomic_body_cas_unavailable": True,
        },
        "recovery": {"post_hold": True, "barrier": "ACK_ONLY_THEN_LATER_COMMIT"},
        "next_action": "Publish receiver-first rendezvous after READY.",
        "hard_stops": ["No body replacement.", "No mutation in ACK-only turn."],
    }
    effective = BODY
    for item in data["stale_field_inventory"]:
        effective = effective.replace(item["claim"], item["replacement"], 1)
    data["body"]["effective_bytes"] = len(effective.encode())
    data["body"]["effective_sha256"] = digest(effective.encode())
    return data


def markdown(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return (
        f"{overlay.MARKER} — generation {data['generation']}\n\n"
        f"```json\n{json.dumps(data, sort_keys=True)}\n```\n\n"
        f"Stable digest: `{digest(canonical)}`\n"
    )


EXPECTED_EFFECTIVE = payload()["body"]["effective_sha256"]


class OverlayTest(unittest.TestCase):
    def bind_body(self, data: dict, body: str) -> None:
        effective = body
        for item in data["stale_field_inventory"]:
            effective = effective.replace(item["claim"], item["replacement"], 1)
        data["body"]["bytes"] = len(body.encode())
        data["body"]["sha256"] = digest(body.encode())
        data["body"]["effective_bytes"] = len(effective.encode())
        data["body"]["effective_sha256"] = digest(effective.encode())

    def validate(self, data: dict, body: str = BODY, ready_label: bool = False, expected_effective: str | None = None) -> None:
        overlay.validate_payload(
            data,
            body.encode(),
            "owner/repo",
            88,
            MAIN,
            ready_label,
            expected_effective or data["body"]["effective_sha256"],
        )
        self.assertEqual(overlay.parse_ledger(markdown(data))[0], data)

    def assert_rejected(self, data: dict, **kwargs: object) -> None:
        with self.assertRaises(overlay.ValidationError):
            self.validate(data, **kwargs)

    def authority_comments(self, data: dict) -> list[dict]:
        authority = data["authority"]
        return [
            {
                "id": authority["decision_packet_comment_id"],
                "repository": data["repository"],
                "issue": data["issue"],
                "body": "DECISION PACKET exact scope",
            },
            {
                "id": authority["approval_comment_id"],
                "repository": data["repository"],
                "issue": data["issue"],
                "body": (
                    "Decision: APPROVE\n"
                    f"Exact packet: {authority['decision_packet_comment_id']}"
                ),
            },
            {
                "id": authority["lease_accept_comment_id"],
                "repository": data["repository"],
                "issue": data["issue"],
                "body": f"LEASE REVIEW ACCEPT {data['lease']['manifest_sha256']}",
            },
            {
                "id": authority["overlay_review_comment_id"],
                "repository": data["repository"],
                "issue": data["issue"],
                "body": f"OVERLAY REVIEW ACCEPT {data['lease']['manifest_sha256']} {data['body']['effective_sha256']}",
            },
        ]

    def durable_validate(
        self,
        data: dict,
        issue_comments: list[dict],
        ledger_id: int,
        authorities: list[dict] | None = None,
        suffix: tuple[int, int, int] | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            issue_path = Path(directory) / "issue.json"
            authority_path = Path(directory) / "authority.json"
            issue_path.write_text(json.dumps(issue_comments))
            authority_path.write_text(json.dumps(authorities or self.authority_comments(data)))
            overlay.validate_comments(
                issue_path, authority_path, markdown(data), data, ledger_id, suffix
            )

    def post_ledger_comments(self, data: dict, ledger_id: int = 100) -> list[dict]:
        ledger_digest = overlay.parse_ledger(markdown(data))[1]
        effective_digest = data["body"]["effective_sha256"]
        receiver = f"DEVELOPMENT RECEIVER binds ledger {ledger_id} rendezvous 101"
        receiver_digest = digest(receiver.encode())
        return [
            {"id": ledger_id, "body": markdown(data)},
            {
                "id": 101,
                "body": (
                    "CROSS-SESSION RENDEZVOUS binds ledger "
                    f"{ledger_id} {ledger_digest} {effective_digest}"
                ),
            },
            {
                "id": 102,
                "body": receiver,
            },
            {
                "id": 103,
                "body": (
                    "ACCOUNTABLE WRITER ECHO binds rendezvous 101; ZERO MUTATION\n"
                    f"Receiver-body stable digest: `{receiver_digest}`"
                ),
            },
        ]

    def post_ledger_v2_comments(self, data: dict, ledger_id: int = 100) -> list[dict]:
        ledger_digest = overlay.parse_ledger(markdown(data))[1]
        effective_digest = data["body"]["effective_sha256"]
        token = f"issue #{data['issue']} generation {data['generation']} deterministic ACK v2"
        receiver = (
            f"DEVELOPMENT RECEIVER binds ledger {ledger_id}\n"
            f"Authorized rendezvous token: {token}"
        )
        receiver_digest = digest(receiver.encode())
        echo = (
            "ACCOUNTABLE WRITER ECHO; ZERO MUTATION\n"
            f"Authorized rendezvous token: {token}\n"
            f"Receiver-body stable digest: `{receiver_digest}`"
        )
        transaction_digest = overlay.ack_transaction_sha256(receiver, echo)
        return [
            {"id": ledger_id, "body": markdown(data)},
            {
                "id": 101,
                "body": (
                    "CROSS-SESSION RENDEZVOUS binds ledger "
                    f"{ledger_id} {ledger_digest} {effective_digest}\n"
                    "Authorized rendezvous: `THIS COMMENT`\n"
                    f"Authorized rendezvous token: {token}\n"
                    f"ACK transaction stable digest: `{transaction_digest}`"
                ),
            },
            {"id": 102, "body": receiver},
            {"id": 103, "body": echo},
        ]

    def cli(
        self,
        data: dict,
        *,
        draft: bool,
        ready_label: bool = False,
        post_ack: bool = False,
    ) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body_path, ledger_path = root / "body.md", root / "ledger.md"
            issue_path, authority_path = root / "issue.json", root / "authority.json"
            body_path.write_text(BODY)
            ledger_path.write_text(markdown(data))
            issue_comments = (
                self.post_ledger_comments(data)
                if post_ack
                else [{"id": 100, "body": markdown(data)}]
            )
            issue_path.write_text(json.dumps(issue_comments))
            authority_path.write_text(json.dumps(self.authority_comments(data)))
            args = [sys.executable, str(SCRIPT), "--body", str(body_path), "--ledger", str(ledger_path), "--repository", "owner/repo", "--issue", "88", "--main", MAIN, "--expected-effective-sha256", data["body"]["effective_sha256"]]
            if ready_label:
                args.append("--agent-ready-label")
            if draft:
                args.append("--draft-validation")
            else:
                args += ["--comments-json", str(issue_path), "--authority-comments-json", str(authority_path), "--ledger-comment-id", "100"]
                if post_ack:
                    args += [
                        "--rendezvous-comment-id",
                        "101",
                        "--development-receiver-comment-id",
                        "102",
                        "--writer-echo-comment-id",
                        "103",
                    ]
            return subprocess.run(args, text=True, capture_output=True, check=False)

    def test_prepared_and_ready_are_valid_zero_wip(self) -> None:
        self.validate(payload())
        self.validate(payload("READY"), ready_label=True)

    def test_ready_requires_live_label(self) -> None:
        self.assert_rejected(payload("READY"))

    def test_prepared_allows_full_active_capacity(self) -> None:
        data = payload()
        data["state"]["development_occupied"] = data["state"]["development_limit"]
        data["state"]["shared_occupied"] = data["state"]["shared_limit"]
        self.validate(data)

    def test_ready_rejects_insufficient_prospective_capacity(self) -> None:
        for occupied, limit in (("development_occupied", "development_limit"), ("shared_occupied", "shared_limit")):
            data = payload("READY")
            data["state"][occupied] = data["state"][limit]
            self.assert_rejected(data, ready_label=True)

    def test_ready_supports_and_bounds_sre_only_capacity(self) -> None:
        data = payload("READY")
        data["state"].update(
            {
                "development_required": 0,
                "shared_required": 0,
                "sre_occupied": 0,
                "sre_limit": 5,
                "sre_required": 1,
            }
        )
        self.validate(data, ready_label=True)

        data["state"]["sre_occupied"] = data["state"]["sre_limit"]
        self.assert_rejected(data, ready_label=True)

    def test_sre_capacity_fields_are_all_or_none(self) -> None:
        data = payload("READY")
        data["state"]["sre_required"] = 1
        self.assert_rejected(data, ready_label=True)

    def test_preamble_control_is_narrowly_allowed(self) -> None:
        data = payload()
        data["supersedes_fields"].append("readiness")
        data["stale_field_inventory"].append({"fields": ["readiness"], "section": "Preamble control", "claim": "> PREPARED on old main.", "replacement": "> PREPARED under the current control ledger."})
        effective = BODY
        for item in data["stale_field_inventory"]:
            effective = effective.replace(item["claim"], item["replacement"], 1)
        data["body"]["effective_bytes"] = len(effective.encode())
        data["body"]["effective_sha256"] = digest(effective.encode())
        self.validate(data)

    def test_material_or_bdd_overlay_is_rejected(self) -> None:
        data = payload()
        data["supersedes_fields"].append("application_behavior")
        self.assert_rejected(data)

    def test_claim_cannot_cross_section_boundary(self) -> None:
        data = payload()
        start = BODY.index("Accepted main is old-main.")
        end = BODY.index("Then no state is changed") + len("Then no state is changed")
        data["stale_field_inventory"][0]["claim"] = BODY[start:end]
        data["stale_field_inventory"][0]["replacement"] = BODY[start:end].replace(
            "old-main", MAIN
        ).replace("Then no state is changed", "Then the request is accepted")
        self.assert_rejected(data)

    def test_replacement_cannot_inject_level_two_heading(self) -> None:
        data = payload()
        data["stale_field_inventory"][0]["replacement"] = (
            f"Accepted main is {MAIN}.\n\n## Material behavior override\nOverride."
        )
        effective = BODY
        for item in data["stale_field_inventory"]:
            effective = effective.replace(item["claim"], item["replacement"], 1)
        data["body"]["effective_bytes"] = len(effective.encode())
        data["body"]["effective_sha256"] = digest(effective.encode())
        self.assert_rejected(data)
        data = payload()
        data["supersedes_fields"].append("readiness")
        data["stale_field_inventory"].append({"fields": ["readiness"], "section": "Gherkin BDD specification", "claim": "Then no state is changed", "replacement": "Then the request is accepted"})
        self.assert_rejected(data)

    def test_body_and_independent_effective_digests_are_fail_closed(self) -> None:
        self.assert_rejected(payload(), body=BODY + "\n")
        self.assert_rejected(payload(), expected_effective="b" * 64)

    def test_rendered_body_must_be_complete_before_overlay(self) -> None:
        broken = BODY.replace("## Definition of done", "## Missing")
        data = payload()
        data["body"]["bytes"] = len(broken.encode())
        data["body"]["sha256"] = digest(broken.encode())
        effective = broken
        for item in data["stale_field_inventory"]:
            effective = effective.replace(item["claim"], item["replacement"], 1)
        data["body"]["effective_bytes"] = len(effective.encode())
        data["body"]["effective_sha256"] = digest(effective.encode())
        self.assert_rejected(data, body=broken)

    def test_legacy_ownership_field_gaps_are_cured_only_by_same_section_inventory(self) -> None:
        cases = (
            (
                "State: PREPARED\n",
                "readiness",
                "Next deterministic action: verify.",
                "State: PREPARED\nNext deterministic action: verify.",
            ),
            (
                "Next deterministic action: verify.\n",
                "next_action",
                "State: PREPARED",
                "State: PREPARED\nNext deterministic action: verify.",
            ),
        )
        for removed, field, claim, replacement in cases:
            with self.subTest(field=field):
                broken = BODY.replace(removed, "", 1)
                data = payload()
                data["supersedes_fields"].append(field)
                data["stale_field_inventory"].append(
                    {
                        "fields": [field],
                        "section": overlay.OWNERSHIP_SECTION,
                        "claim": claim,
                        "replacement": replacement,
                    }
                )
                self.bind_body(data, broken)
                self.validate(data, body=broken)

        broken = BODY.replace("Capacity: old capacity.\n", "", 1)
        data = payload()
        data["stale_field_inventory"] = [
            item for item in data["stale_field_inventory"] if "capacity" not in item["fields"]
        ]
        data["stale_field_inventory"].append(
            {
                "fields": ["capacity"],
                "section": overlay.OWNERSHIP_SECTION,
                "claim": "State: PREPARED",
                "replacement": "State: PREPARED\nCapacity now: Development 2/5 and Shared 1/2.",
            }
        )
        self.bind_body(data, broken)
        self.validate(data, body=broken)

    def test_legacy_ownership_gap_rejects_missing_or_preamble_only_inventory(self) -> None:
        broken = BODY.replace("Next deterministic action: verify.\n", "", 1)
        missing = payload()
        self.bind_body(missing, broken)
        self.assert_rejected(missing, body=broken)

        preamble = payload()
        preamble["supersedes_fields"].append("next_action")
        preamble["stale_field_inventory"].append(
            {
                "fields": ["next_action"],
                "section": "Preamble control",
                "claim": "> PREPARED on old main.",
                "replacement": (
                    "> PREPARED on old main.\n"
                    "> Next deterministic action: verify."
                ),
            }
        )
        self.bind_body(preamble, broken)
        self.assert_rejected(preamble, body=broken)

    def test_legacy_error_must_be_cured_by_its_own_field_item(self) -> None:
        broken = BODY.replace("Next deterministic action: verify.\n", "", 1)
        data = payload()
        capacity_item = next(
            item for item in data["stale_field_inventory"] if item["fields"] == ["capacity"]
        )
        capacity_item["replacement"] = (
            "Capacity: Development 2/5 and Shared 1/2.\n"
            "Next deterministic action: supplied by the wrong field."
        )
        data["supersedes_fields"].append("next_action")
        data["stale_field_inventory"].append(
            {
                "fields": ["next_action"],
                "section": overlay.OWNERSHIP_SECTION,
                "claim": "State: PREPARED",
                "replacement": "State: PREPARED (reviewed)",
            }
        )
        self.bind_body(data, broken)
        self.assert_rejected(data, body=broken)

    def test_inventory_rejects_no_op_replacement(self) -> None:
        data = payload()
        data["stale_field_inventory"][0]["replacement"] = data[
            "stale_field_inventory"
        ][0]["claim"]
        self.bind_body(data, BODY)
        self.assert_rejected(data)

    def test_every_overlapping_field_item_must_independently_cure_legacy_error(self) -> None:
        broken = BODY.replace("Next deterministic action: verify.\n", "", 1)
        data = payload()
        capacity_item = next(
            item for item in data["stale_field_inventory"] if item["fields"] == ["capacity"]
        )
        capacity_item["fields"].append("next_action")
        capacity_item["replacement"] = (
            "Capacity: Development 2/5 and Shared 1/2.\n"
            "Next deterministic action: supplied by one matching item."
        )
        data["supersedes_fields"].append("next_action")
        data["stale_field_inventory"].append(
            {
                "fields": ["next_action"],
                "section": overlay.OWNERSHIP_SECTION,
                "claim": "State: PREPARED",
                "replacement": "State: PREPARED (reviewed)",
            }
        )
        self.bind_body(data, broken)
        self.assert_rejected(data, body=broken)

    def test_legacy_exception_never_cures_material_body_failures(self) -> None:
        for broken in (
            BODY.replace("## User story", "## Missing user story", 1),
            BODY.replace("## Gherkin BDD specification", "## Missing BDD", 1),
            BODY.replace("## Risks, safety, and approval boundary", "## Missing safety", 1),
            BODY.replace("- [ ] Reviewed and merged.", "Reviewed and merged.", 1),
            BODY.replace(
                "## Ownership, readiness, and capacity",
                "## Missing ownership contract",
                1,
            ),
        ):
            with self.subTest(fragment=broken[-120:]):
                data = payload()
                self.bind_body(data, broken)
                self.assert_rejected(data, body=broken)

    def test_guard_failures_and_stale_main_reject(self) -> None:
        for key in ("dependencies_satisfied", "capacity_available", "collision_free", "decision_register_consistent", "no_newer_hold"):
            data = payload()
            data["guards"][key] = False
            self.assert_rejected(data)
        data = payload()
        data["state"]["accepted_main"] = "e" * 40
        self.assert_rejected(data)

    def test_generation_one_direct_ready_with_tracker_bodies_pending_is_valid(self) -> None:
        data = payload("READY")
        data["guards"]["tracker_consistent"] = False
        data["pending_tracker_issue_numbers"] = overlay.PENDING_TRACKERS
        data["next_action"] = overlay.TRACKER_PENDING_READY_NEXT_ACTION
        self.validate(data, ready_label=True)
        self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100)
        draft = self.cli(data, draft=True, ready_label=True)
        self.assertEqual(draft.returncode, 0, draft.stderr)
        self.assertIn("direct READY", draft.stdout)

    def test_tracker_pending_direct_ready_is_narrowly_fail_closed(self) -> None:
        base = payload("READY")
        base["guards"]["tracker_consistent"] = False
        base["pending_tracker_issue_numbers"] = overlay.PENDING_TRACKERS
        base["next_action"] = overlay.TRACKER_PENDING_READY_NEXT_ACTION
        variants = []
        prepared = json.loads(json.dumps(base))
        prepared["state"]["phase"] = "PREPARED"
        prepared["state"]["agent_ready"] = False
        prepared["state"]["ready_depth"] = 0
        prepared["guards"]["agent_ready_label_present"] = False
        variants.append((prepared, {}))
        depth = json.loads(json.dumps(base))
        depth["state"]["ready_depth"] = 0
        variants.append((depth, {"ready_label": True}))
        product = json.loads(json.dumps(base))
        product["state"]["product_accepted"] = True
        variants.append((product, {"ready_label": True}))
        cas_available = json.loads(json.dumps(base))
        cas_available["guards"]["provider_atomic_body_cas_unavailable"] = False
        variants.append((cas_available, {"ready_label": True}))
        for changed, kwargs in variants:
            self.assert_rejected(changed, **kwargs)
        later = json.loads(json.dumps(base))
        later["generation"] = 2
        later["predecessor_ledger_comment_id"] = 100
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(later, [{"id": 104, "body": markdown(later)}], 104)
        for targets in ([44, 61, 120, 131], [44, 61, 120, 131, 179, 179], []):
            changed = json.loads(json.dumps(base))
            changed["pending_tracker_issue_numbers"] = targets
            self.assert_rejected(changed, ready_label=True)
        changed = json.loads(json.dumps(base))
        changed["next_action"] = "Reconcile trackers later."
        self.assert_rejected(changed, ready_label=True)
        for action in (
            "Publish five tracker pointers before READY.",
            "Use a #179 comment as READY authority.",
            "Reconcile #44/#61/#120/#131/#179 using this ledger's durable comment ID.",
        ):
            changed = json.loads(json.dumps(base))
            changed["next_action"] = action
            self.assert_rejected(changed, ready_label=True)
        changed = json.loads(json.dumps(base))
        changed["guards"]["decision_register_consistent"] = False
        self.assert_rejected(changed, ready_label=True)

    def test_tracker_consistent_ledgers_reject_pending_targets(self) -> None:
        data = payload()
        data["pending_tracker_issue_numbers"] = [44, 61, 120, 131, 179]
        self.assert_rejected(data)

    def test_generation_rules_and_durable_chain(self) -> None:
        first = payload()
        self.durable_validate(first, [{"id": 100, "body": markdown(first)}], 100)
        second = payload()
        second["generation"] = 2
        second["predecessor_ledger_comment_id"] = 100
        self.durable_validate(second, [{"id": 100, "body": markdown(first)}, {"id": 101, "body": markdown(second)}], 101)
        broken = payload()
        broken["generation"] = 2
        broken["predecessor_ledger_comment_id"] = 999
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(broken, [{"id": 100, "body": markdown(first)}, {"id": 101, "body": markdown(broken)}], 101)

    def test_duplicate_or_non_newest_ledger_rejects(self) -> None:
        data = payload()
        for comments in (
            [{"id": 100, "body": markdown(data)}, {"id": 101, "body": markdown(data)}],
            [{"id": 100, "body": markdown(data)}, {"id": 101, "body": "HOLD"}],
            [{"id": 101, "body": "HOLD"}, {"id": 100, "body": markdown(data)}],
            [{"id": 100, "body": "older"}, {"id": 100, "body": markdown(data)}],
        ):
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, comments, 100)

    def test_durable_ledger_accepts_one_terminal_outbox_marker_only(self) -> None:
        data = payload("READY")
        marker = "\n\n<!-- twinfinity-outbox:" + "a" * 64 + " -->"
        comments = self.post_ledger_comments(data)
        comments[0]["body"] += marker
        self.durable_validate(data, comments, 100, suffix=(101, 102, 103))

        comments[0]["body"] += marker
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, comments, 100, suffix=(101, 102, 103))

    def test_material_approval_packet_is_a_structured_decision_marker(self) -> None:
        data = payload()
        authorities = self.authority_comments(data)
        authorities[0]["body"] = "ROUND #5 MATERIAL APPROVAL PACKET — exact bounded scope"
        authorities[1]["body"] = "CONTROLLING USER APPROVAL\nDecision: APPROVE\nExact packet: 10"
        self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)
        authorities[1]["body"] = "DO NOT APPROVE packet 10"
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)
        for rejected in (
            "Decision: APPROVE\nExact packet: 10\nDENIED",
            "Decision: APPROVE\nExact packet: 10\nWITHDRAWN",
            "Please APPROVE packet 10",
            "APPROVED decision 10",
            "Decision: APPROVE\nDecision: DEFER\nExact packet: 10",
            "Decision: APPROVE\nExact packet: 10\nExact packet: 11",
        ):
            authorities[1]["body"] = rejected
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)

    def test_decision_packet_distinguishes_context_from_current_contradiction(self) -> None:
        data = payload()
        authorities = self.authority_comments(data)
        authorities[0]["body"] += "\nRetained issue bytes remain stopped and non-exclusive."
        self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)

        for contradiction in ("Status: HOLD", "This packet is withdrawn", "DO NOT ACTIVATE"):
            changed = json.loads(json.dumps(authorities))
            changed[0]["body"] += f"\n{contradiction}"
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, changed)

        authorities = self.authority_comments(data)
        authorities[0]["body"] = (
            "DECISION PACKET exact scope A\n"
            "DECISION PACKET different scope B"
        )
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(
                data,
                [{"id": 100, "body": markdown(data)}],
                100,
                authorities,
            )
        authorities[1]["body"] = "CONTROLLING USER APPROVAL\nDecision: APPROVE\nExact packet: 10"
        authorities[0]["body"] = "ROUND #5 APPROVAL PACKET — ambiguous scope"
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)
        for rejected in (
            "ROUND #5 MATERIAL APPROVAL PACKET — REJECTED",
            "NOT A MATERIAL APPROVAL PACKET",
            "This is NOT a MATERIAL APPROVAL PACKET — no authority",
        ):
            authorities[0]["body"] = rejected
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)

    def test_exact_post_ledger_ack_suffix_is_valid(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        self.durable_validate(data, comments, 100, suffix=(101, 102, 103))
        cli = self.cli(data, draft=False, ready_label=True, post_ack=True)
        self.assertEqual(cli.returncode, 0, cli.stderr)

    def test_tracker_pending_direct_ready_accepts_post_ledger_ack_suffix(self) -> None:
        data = payload("READY")
        data["guards"]["tracker_consistent"] = False
        data["pending_tracker_issue_numbers"] = overlay.PENDING_TRACKERS
        data["next_action"] = overlay.TRACKER_PENDING_READY_NEXT_ACTION
        comments = self.post_ledger_comments(data)
        self.durable_validate(data, comments, 100, suffix=(101, 102, 103))
        cli = self.cli(data, draft=False, ready_label=True, post_ack=True)
        self.assertEqual(cli.returncode, 0, cli.stderr)

    def test_tracker_pending_ready_accepts_corrective_successor_generation(self) -> None:
        first = payload("READY")
        first["guards"]["tracker_consistent"] = False
        first["pending_tracker_issue_numbers"] = overlay.PENDING_TRACKERS
        first["next_action"] = overlay.TRACKER_PENDING_READY_NEXT_ACTION
        second = json.loads(json.dumps(first))
        second["generation"] = 2
        second["predecessor_ledger_comment_id"] = 100
        comments = [
            {"id": 100, "body": markdown(first)},
            {"id": 104, "body": markdown(second)},
        ]
        self.durable_validate(second, comments, 104)

        changed = json.loads(json.dumps(second))
        changed["lease"]["manifest_sha256"] = "b" * 64
        changed["authority"]["lease_manifest_sha256"] = "b" * 64
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(
                changed,
                [{"id": 100, "body": markdown(first)}, {"id": 104, "body": markdown(changed)}],
                104,
            )

    def test_post_ledger_suffix_rejects_extra_or_misbound_comment(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        for changed in (
            comments + [{"id": 104, "body": "HOLD"}],
            [
                comment
                if comment["id"] != 103
                else {"id": 103, "body": "ACCOUNTABLE WRITER ECHO binds rendezvous 101; ZERO MUTATION"}
                for comment in comments
            ],
        ):
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_accepts_ack_v2_token_without_server_id_binding(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_v2_comments(data)
        self.durable_validate(data, comments, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_ack_v2_wrong_transaction_digest(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_v2_comments(data)
        changed = [dict(comment) for comment in comments]
        digest_match = overlay.ACK_TRANSACTION_STABLE_DIGEST.search(changed[1]["body"])
        self.assertIsNotNone(digest_match)
        changed[1]["body"] = changed[1]["body"].replace(digest_match.group(1), "b" * 64)
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_ack_v2_wrong_generation_when_fully_rebound(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_v2_comments(data)
        old_token = f"issue #{data['issue']} generation {data['generation']} deterministic ACK v2"
        new_token = f"issue #{data['issue']} generation 2 deterministic ACK v2"
        changed = [
            {"id": comment["id"], "body": comment["body"].replace(old_token, new_token)}
            for comment in comments
        ]
        receiver_digest_match = re.search(
            r"Receiver-body stable digest: `([0-9a-f]{64})`", changed[3]["body"]
        )
        self.assertIsNotNone(receiver_digest_match)
        changed[3]["body"] = changed[3]["body"].replace(
            receiver_digest_match.group(1), digest(changed[2]["body"].encode())
        )
        transaction_match = overlay.ACK_TRANSACTION_STABLE_DIGEST.search(changed[1]["body"])
        self.assertIsNotNone(transaction_match)
        changed[1]["body"] = changed[1]["body"].replace(
            transaction_match.group(1),
            overlay.ack_transaction_sha256(changed[2]["body"], changed[3]["body"]),
        )
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_hybrid_legacy_v2_fallback(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_v2_comments(data)
        changed = [dict(comment) for comment in comments]
        changed[2]["body"] += "\nlegacy rendezvous 101"
        changed[3]["body"] += "\nlegacy rendezvous 101"
        changed[1]["body"] = changed[1]["body"].replace(
            "ACK transaction stable digest:", "ACK transaction stable digest invalid:"
        )
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_legacy_binding_with_rendezvous_field_alias(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        changed = [dict(comment) for comment in comments]
        changed[2]["body"] += (
            f"\nRendezvous token: issue #{data['issue']} generation "
            f"{data['generation']} deterministic ACK v2"
        )
        old_receiver_digest = digest(comments[2]["body"].encode())
        changed[3]["body"] = changed[3]["body"].replace(
            old_receiver_digest, digest(changed[2]["body"].encode())
        )
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_ack_v2_digest_alias_in_any_body(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_v2_comments(data)
        for index in (1, 2, 3):
            changed = [dict(comment) for comment in comments]
            changed[index]["body"] += (
                f"\nack transaction stable digest: `{'b' * 64}`"
            )
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_ack_v2_missing_wrong_or_duplicate_token(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_v2_comments(data)
        token = f"issue #{data['issue']} generation {data['generation']} deterministic ACK v2"
        variants = []
        for index in (1, 2, 3):
            missing = [dict(comment) for comment in comments]
            missing[index]["body"] = missing[index]["body"].replace(
                f"Authorized rendezvous token: {token}", ""
            )
            variants.append(missing)

            wrong = [dict(comment) for comment in comments]
            wrong[index]["body"] = wrong[index]["body"].replace(
                token, f"issue #999 generation {data['generation']} deterministic ACK v2"
            )
            variants.append(wrong)

            duplicate = [dict(comment) for comment in comments]
            duplicate[index]["body"] += f"\nAuthorized rendezvous token: {token}"
            variants.append(duplicate)

        for changed in variants:
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_contradiction_in_each_comment(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        for suffix_id in (101, 102, 103):
            for phrase in ("HOLD", "STOP", "BLOCKED", "PAUSE", "DO NOT ACTIVATE", "permission WITHDRAWN", "REVOKED", "INVALID", "DENIED"):
                changed = [
                    comment
                    if comment["id"] != suffix_id
                    else {"id": suffix_id, "body": comment["body"] + " " + phrase}
                    for comment in comments
                ]
                with self.assertRaises(overlay.ValidationError):
                    self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_accepts_bounded_hard_stop_prose(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        comments[1]["body"] += (
            "\nThis is the mandatory post-HOLD PREPARE barrier."
            "\nAny changed ledger, exact head, lease, or comment ordering is a hard stop."
            "\n### Mandatory hard stops"
            "\n- STOP if the ledger, exact head, lease, or comment ordering drifts."
            "\n- Do not mutate outside the exact lease."
        )
        self.durable_validate(data, comments, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_accepts_bounded_non_goal_prose(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        comments[1]["body"] += (
            "\n### Non-goals"
            "\n- Do not execute hosted or provider operations."
            "\n- BLOCKED retained lineages remain outside this admission."
        )
        self.durable_validate(data, comments, 100, suffix=(101, 102, 103))

    def test_constraint_section_does_not_hide_structured_negative_authority(self) -> None:
        data = payload("READY")
        for contradiction in ("State: BLOCKED", "Authority: REVOKED"):
            comments = self.post_ledger_comments(data)
            comments[1]["body"] += (
                "\n### Mandatory hard stops\n- STOP if the lease drifts.\n"
                + contradiction
            )
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, comments, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_superstring_id_bindings(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        replacements = {
            101: [("ledger 100", "ledger 1000")],
            102: [("ledger 100", "ledger 1000"), ("rendezvous 101", "rendezvous 1010")],
            103: [("rendezvous 101", "rendezvous 1010")],
        }
        for suffix_id, edits in replacements.items():
            changed = []
            for comment in comments:
                body = comment["body"]
                if comment["id"] == suffix_id:
                    for old, new in edits:
                        body = body.replace(old, new)
                changed.append({"id": comment["id"], "body": body})
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_post_ledger_suffix_rejects_wrong_receiver_digest_binding(self) -> None:
        data = payload("READY")
        comments = self.post_ledger_comments(data)
        valid_receiver_digest = digest(comments[2]["body"].encode())
        for replacement in (
            "b" * 64,
            valid_receiver_digest[:-1],
            f"{valid_receiver_digest}0",
        ):
            changed = [dict(comment) for comment in comments]
            changed[3]["body"] = changed[3]["body"].replace(valid_receiver_digest, replacement)
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

        for extra in (valid_receiver_digest, "b" * 64):
            changed = [dict(comment) for comment in comments]
            changed[3]["body"] += f"\nReceiver-body stable digest: `{extra}`"
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

        for alias in (
            f"Receiver-body  stable digest: `{'b' * 64}`",
            f"- Receiver-body stable digest: `{'b' * 64}`",
        ):
            changed = [dict(comment) for comment in comments]
            changed[3]["body"] += f"\n{alias}"
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

        changed = [dict(comment) for comment in comments]
        changed[2]["body"] += " changed"
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, changed, 100, suffix=(101, 102, 103))

    def test_authority_ids_and_markers_are_structured(self) -> None:
        data = payload()
        data["authority"]["approval_comment_id"] = data["authority"]["decision_packet_comment_id"]
        with self.assertRaises(overlay.ValidationError):
            self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100)
        for replacement in ("OVERLAY REVIEW ACCEPT", "OVERLAY REVIEW REJECT"):
            data = payload()
            authorities = self.authority_comments(data)
            authorities[-1]["body"] = f"{replacement} {MANIFEST} {data['body']['effective_sha256']}"
            if "REJECT" in replacement:
                with self.assertRaises(overlay.ValidationError):
                    self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)
            else:
                self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)

    def test_comment_from_179_cannot_substitute_for_owning_issue_authority(self) -> None:
        data = payload("READY")
        data["guards"]["tracker_consistent"] = False
        data["pending_tracker_issue_numbers"] = overlay.PENDING_TRACKERS
        data["next_action"] = overlay.TRACKER_PENDING_READY_NEXT_ACTION
        authorities = self.authority_comments(data)
        authorities[0]["issue"] = 179
        with self.assertRaisesRegex(
            overlay.ValidationError, "owning repository/issue"
        ):
            self.durable_validate(
                data,
                [{"id": 100, "body": markdown(data)}],
                100,
                authorities,
            )

    def test_negated_approval_and_lease_accept_reject(self) -> None:
        data = payload()
        for index, body in ((1, "NOT APPROVED decision 10"), (2, f"NOT ACCEPTED {MANIFEST}")):
            authorities = self.authority_comments(data)
            authorities[index]["body"] = body
            with self.assertRaises(overlay.ValidationError):
                self.durable_validate(data, [{"id": 100, "body": markdown(data)}], 100, authorities)

    def test_cli_draft_prepared_and_ready(self) -> None:
        draft = self.cli(payload(), draft=True)
        self.assertEqual(draft.returncode, 0, draft.stderr)
        self.assertIn("not activation authority", draft.stdout)
        prepared = self.cli(payload(), draft=False)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        ready = self.cli(payload("READY"), draft=False, ready_label=True)
        self.assertEqual(ready.returncode, 0, ready.stderr)

    def test_cli_requires_durable_evidence_and_has_no_validator_override(self) -> None:
        data = payload()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body_path, ledger_path = root / "body.md", root / "ledger.md"
            body_path.write_text(BODY)
            ledger_path.write_text(markdown(data))
            common = [sys.executable, str(SCRIPT), "--body", str(body_path), "--ledger", str(ledger_path), "--repository", "owner/repo", "--issue", "88", "--main", MAIN, "--expected-effective-sha256", EXPECTED_EFFECTIVE]
            missing = subprocess.run(common, text=True, capture_output=True, check=False)
            bypass = subprocess.run(common + ["--issue-body-validator", "/tmp/weak.py"], text=True, capture_output=True, check=False)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("durable validation requires", missing.stderr)
        self.assertEqual(bypass.returncode, 2)
        self.assertIn("unrecognized arguments", bypass.stderr)

    def test_frozen_issue88_fixture_has_seven_control_replacements(self) -> None:
        fixture_path = ROOT / "tests" / "issue88_fixture.py"
        spec = importlib.util.spec_from_file_location("issue88_fixture", fixture_path)
        assert spec and spec.loader
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        current, desired = fixture.current_body(), fixture.desired_body()
        self.assertEqual(digest(current), fixture.CURRENT_SHA256)
        self.assertEqual(digest(desired), fixture.DESIRED_SHA256)
        for candidate in (current, desired):
            result = subprocess.run([sys.executable, str(VALIDATOR)], input=candidate.decode(), text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
        current_lines, desired_lines = current.decode().splitlines(keepends=True), desired.decode().splitlines(keepends=True)
        changed = [item for item in difflib.SequenceMatcher(None, current_lines, desired_lines).get_opcodes() if item[0] != "equal"]
        self.assertEqual(len(changed), 7)
        field_sets = [
            ["accepted_main", "dependency_state", "readiness", "capacity", "exact_lease", "controlling_receipt_ids", "next_action"],
            ["accepted_main", "capacity", "controlling_receipt_ids"],
            ["exact_lease", "controlling_receipt_ids"],
            ["dependency_state", "receiver_state"],
            ["readiness", "controlling_receipt_ids"],
            ["capacity", "exact_lease", "dependency_state", "receiver_state", "controlling_receipt_ids"],
            ["next_action"],
        ]
        inventory = []
        for opcode, fields in zip(changed, field_sets, strict=True):
            _, i1, i2, j1, j2 = opcode
            claim = "".join(current_lines[i1:i2])
            replacement = "".join(desired_lines[j1:j2])
            inventory.append(
                {
                    "fields": fields,
                    "section": overlay.actual_section(current.decode(), claim),
                    "claim": claim,
                    "replacement": replacement,
                }
            )
        overlay_data = {
            "supersedes_fields": sorted({field for fields in field_sets for field in fields}),
            "stale_field_inventory": inventory,
        }
        self.assertEqual(overlay.validate_inventory(current.decode(), overlay_data).encode(), desired)


if __name__ == "__main__":
    unittest.main()
