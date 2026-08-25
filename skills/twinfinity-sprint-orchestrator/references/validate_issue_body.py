#!/usr/bin/env python3
"""Validate the minimum visible structure of a Twinfinity GitHub issue body."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import re
import sys
from pathlib import Path


REQUIRED_HEADINGS = (
    "User story",
    "Product or operational outcome",
    "Parent and related issues",
    "Current evidence and assumptions",
    "Dependencies and sequencing",
    "In scope",
    "Out of scope and hard stops",
    "Delivery plan",
    "Gherkin BDD specification",
    "Scenario-to-evidence map",
    "Risks, safety, and approval boundary",
    "Definition of done",
    "Ownership, readiness, and capacity",
)

TEMPLATE_PLACEHOLDERS = (
    "<concrete beneficiary>",
    "<capability or control>",
    "<observable value or risk reduction>",
    "<One independently reviewable outcome",
    "#<issue>",
    "<live/repository fact",
    "<explicitly labeled inference>",
    "<bounded unknown",
    "<issues/approvals>",
    "<paths/contracts/operational targets>",
    "<receiver, decision, external event",
    "<deterministic next owner/action>",
    "<bounded behavior, path, contract",
    "<adjacent behavior, environment",
    "<Implement, evaluate, decide, or monitor",
    "<capability or control outcome>",
    "<primary observable success>",
    "<negative or fail-closed behavior>",
    "<unit/integration/BDD/UI/operational>",
    "<negative/security/recovery>",
    "<accountable session or activation trigger>",
    "<one specific event/action>",
)


@dataclass(frozen=True)
class ValidationIssue:
    """One stable machine-readable issue-body validation failure."""

    code: str
    message: str


def read_body(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8")
    return sys.stdin.read()


def section(body: str, heading: str) -> str:
    match = re.search(
        rf"(?ms)^##\s+{re.escape(heading)}\s*$\n(.*?)(?=^##\s+|\Z)", body
    )
    return match.group(1).strip() if match else ""


def validate_issues(body: str) -> list[ValidationIssue]:
    errors: list[ValidationIssue] = []
    headings = re.findall(r"(?m)^##\s+(.+?)\s*$", body)
    for required in REQUIRED_HEADINGS:
        count = sum(heading.casefold() == required.casefold() for heading in headings)
        if count != 1:
            errors.append(
                ValidationIssue(
                    "heading_count_invalid",
                    f"expected exactly one '## {required}' heading; found {count}",
                )
            )

    for placeholder in TEMPLATE_PLACEHOLDERS:
        if placeholder.casefold() in body.casefold():
            errors.append(
                ValidationIssue(
                    "template_placeholder_unreplaced",
                    f"unreplaced template placeholder: {placeholder}",
                )
            )

    user_story = section(body, "User story")
    if not re.search(r"(?im)^As an?\s+.+?,\s+I want\s+.+?,?\s+so that\s+.+", user_story):
        errors.append(
            ValidationIssue(
                "user_story_format_invalid",
                "user story must use 'As a/an ..., I want ..., so that ...'",
            )
        )

    gherkin_section = section(body, "Gherkin BDD specification")
    match = re.search(r"(?ms)^```gherkin\s*$\n(.*?)^```\s*$", gherkin_section)
    if not match:
        errors.append(
            ValidationIssue("gherkin_fence_missing", "missing fenced ```gherkin block")
        )
    else:
        gherkin = match.group(1)
        if len(re.findall(r"(?m)^Feature:\s+\S", gherkin)) != 1:
            errors.append(
                ValidationIssue(
                    "gherkin_feature_count_invalid",
                    "Gherkin block must contain exactly one non-empty Feature",
                )
            )
        scenarios = re.findall(r"(?m)^\s+Scenario(?: Outline)?:\s+(.+?)\s*$", gherkin)
        if len(scenarios) < 2:
            errors.append(
                ValidationIssue(
                    "gherkin_scenario_count_invalid",
                    "Gherkin block must contain at least two named Scenarios",
                )
            )
        scenario_blocks = re.split(r"(?m)^\s+Scenario(?: Outline)?:\s+", gherkin)[1:]
        for scenario_block in scenario_blocks:
            name, _, steps = scenario_block.partition("\n")
            for keyword in ("Given", "When", "Then"):
                if not re.search(rf"(?m)^\s+{keyword}\s+\S", steps):
                    errors.append(
                        ValidationIssue(
                            "gherkin_scenario_step_missing",
                            f"scenario '{name.strip()}' is missing a {keyword} step",
                        )
                    )

        evidence_map = section(body, "Scenario-to-evidence map")
        for scenario in scenarios:
            if not re.search(
                rf"(?m)^\|\s*`?{re.escape(scenario)}`?\s*\|", evidence_map
            ):
                errors.append(
                    ValidationIssue(
                        "evidence_map_scenario_missing",
                        f"scenario is not named in evidence map: {scenario}",
                    )
                )

    delivery_plan = section(body, "Delivery plan")
    if not re.search(r"(?m)^\s*1\.\s+\S", delivery_plan):
        errors.append(
            ValidationIssue(
                "delivery_plan_first_step_missing",
                "delivery plan must contain a numbered first step",
            )
        )

    definition_of_done = section(body, "Definition of done")
    if not re.search(r"(?m)^- \[[ xX]\]\s+\S", definition_of_done):
        errors.append(
            ValidationIssue(
                "definition_of_done_checkbox_missing",
                "definition of done must contain checkboxes",
            )
        )

    ownership = section(body, "Ownership, readiness, and capacity")
    for label, code in (
        ("State:", "ownership_missing_state"),
        ("Next deterministic action:", "ownership_missing_next_action"),
    ):
        if label.casefold() not in ownership.casefold():
            errors.append(
                ValidationIssue(code, f"ownership section is missing '{label}'")
            )
    if not re.search(r"(?i)\bCapacity(?:\s+now)?:", ownership):
        errors.append(
            ValidationIssue(
                "ownership_missing_capacity",
                "ownership section is missing 'Capacity:' or 'Capacity now:'",
            )
        )
    return errors


def validate(body: str) -> list[str]:
    """Backward-compatible text-only validation API."""
    return [issue.message for issue in validate_issues(body)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("body_file", nargs="?", help="issue body file; reads stdin when omitted")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="validation output format; text preserves the historical CLI contract",
    )
    args = parser.parse_args()
    issues = validate_issues(read_body(args.body_file))
    if args.format == "json":
        print(
            json.dumps(
                {
                    "schema": "twinfinity-issue-body-validation/v1",
                    "valid": not issues,
                    "errors": [asdict(issue) for issue in issues],
                },
                sort_keys=True,
            )
        )
    elif issues:
        for issue in issues:
            print(f"ERROR: {issue.message}", file=sys.stderr)
    if issues:
        return 1
    if args.format == "text":
        print("Issue body structure is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
