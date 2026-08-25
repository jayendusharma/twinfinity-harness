from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "references" / "validate_issue_body.py"
SPEC = importlib.util.spec_from_file_location("issue_body", SCRIPT)
assert SPEC and SPEC.loader
issue_body = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = issue_body
SPEC.loader.exec_module(issue_body)

VALID_BODY = """## User story
As an owner, I want a capability, so that value is delivered.

## Product or operational outcome
Outcome.

## Parent and related issues
- Parent: #1

## Current evidence and assumptions
Current evidence.

## Dependencies and sequencing
Dependency state.

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
Capacity: Development 2/5.
Next deterministic action: verify.
"""


class IssueBodyValidatorTest(unittest.TestCase):
    def test_valid_body_has_no_issues_and_preserves_text_cli(self) -> None:
        self.assertEqual(issue_body.validate(VALID_BODY), [])
        self.assertEqual(issue_body.validate_issues(VALID_BODY), [])
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=VALID_BODY,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "Issue body structure is valid.\n")

    def test_json_output_exposes_stable_ownership_error_codes(self) -> None:
        broken = (
            VALID_BODY.replace("State: PREPARED\n", "")
            .replace("Capacity: Development 2/5.\n", "")
            .replace("Next deterministic action: verify.\n", "")
        )
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--format", "json"],
            input=broken,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        report = json.loads(completed.stdout)
        self.assertEqual(report["schema"], "twinfinity-issue-body-validation/v1")
        self.assertFalse(report["valid"])
        self.assertEqual(
            {error["code"] for error in report["errors"]},
            {
                "ownership_missing_state",
                "ownership_missing_capacity",
                "ownership_missing_next_action",
            },
        )

    def test_text_errors_remain_human_readable(self) -> None:
        broken = VALID_BODY.replace("Next deterministic action: verify.\n", "")
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=broken,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            completed.stderr,
            "ERROR: ownership section is missing 'Next deterministic action:'\n",
        )

    def test_material_errors_have_non_waivable_codes(self) -> None:
        variants = {
            "heading_count_invalid": VALID_BODY.replace(
                "## Risks, safety, and approval boundary",
                "## Missing safety",
                1,
            ),
            "user_story_format_invalid": VALID_BODY.replace(
                "As an owner, I want a capability, so that value is delivered.",
                "Build a capability.",
                1,
            ),
            "definition_of_done_checkbox_missing": VALID_BODY.replace(
                "- [ ] Reviewed and merged.",
                "Reviewed and merged.",
                1,
            ),
        }
        for expected_code, body in variants.items():
            with self.subTest(expected_code=expected_code):
                codes = {item.code for item in issue_body.validate_issues(body)}
                self.assertIn(expected_code, codes)


if __name__ == "__main__":
    unittest.main()
