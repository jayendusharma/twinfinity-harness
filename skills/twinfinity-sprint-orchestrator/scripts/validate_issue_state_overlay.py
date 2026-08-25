#!/usr/bin/env python3
"""Validate a Twinfinity owning-issue state/lease overlay.

The rendered issue body remains the immutable product, BDD, safety, and DoD
contract.  This validator permits only a narrow, append-only overlay for
volatile delivery state when provider-atomic body replacement is unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from legacy_ack_compat import (
        ack_transaction_sha256,
        has_exact_receiver_body_digest_binding,
        has_exact_rendezvous_token_binding,
    )
except ModuleNotFoundError:
    from scripts.legacy_ack_compat import (
        ack_transaction_sha256,
        has_exact_receiver_body_digest_binding,
        has_exact_rendezvous_token_binding,
    )


SCHEMA = "twinfinity-owning-state-ledger/v1"
MARKER = "## OWNING STATE/LEASE LEDGER"
ALLOWED_FIELDS = {
    "accepted_main",
    "dependency_state",
    "readiness",
    "capacity",
    "exact_lease",
    "receiver_state",
    "controlling_receipt_ids",
    "next_action",
}
FIELD_SECTIONS = {
    "accepted_main": {"Current evidence and assumptions", "Ownership, readiness, and capacity"},
    "dependency_state": {
        "Current evidence and assumptions",
        "Dependencies and sequencing",
        "Ownership, readiness, and capacity",
    },
    "readiness": {"Ownership, readiness, and capacity"},
    "capacity": {"Current evidence and assumptions", "Ownership, readiness, and capacity"},
    "exact_lease": {
        "Current evidence and assumptions",
        "Dependencies and sequencing",
        "In scope",
        "Ownership, readiness, and capacity",
    },
    "receiver_state": {"Dependencies and sequencing", "Ownership, readiness, and capacity"},
    "controlling_receipt_ids": {
        "Current evidence and assumptions",
        "Dependencies and sequencing",
        "Ownership, readiness, and capacity",
    },
    "next_action": {"Delivery plan", "Ownership, readiness, and capacity"},
}
PREAMBLE_FIELDS = {
    "accepted_main",
    "dependency_state",
    "readiness",
    "capacity",
    "exact_lease",
    "controlling_receipt_ids",
    "next_action",
}
REQUIRED_TOP_LEVEL = {
    "schema",
    "repository",
    "issue",
    "generation",
    "predecessor_ledger_comment_id",
    "pending_tracker_issue_numbers",
    "body",
    "supersedes_fields",
    "stale_field_inventory",
    "authority",
    "state",
    "lease",
    "guards",
    "recovery",
    "next_action",
    "hard_stops",
}
REQUIRED_GUARDS = {
    "main_current",
    "dependencies_satisfied",
    "collision_free",
    "capacity_available",
    "tracker_consistent",
    "decision_register_consistent",
    "no_newer_hold",
    "body_contract_complete",
    "body_digest_current",
    "agent_ready_label_present",
    "provider_atomic_body_cas_unavailable",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
JSON_FENCE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
STABLE_DIGEST = re.compile(r"^Stable digest:\s*`([0-9a-f]{64})`\s*$", re.MULTILINE)
ACK_TRANSACTION_STABLE_DIGEST = re.compile(
    r"^ACK transaction stable digest:\s*`([0-9a-f]{64})`\s*$", re.MULTILINE
)
ACK_V2_RENDEZVOUS_TOKEN = re.compile(
    r"^Authorized rendezvous token:\s*"
    r"(issue #[1-9][0-9]* generation [1-9][0-9]* deterministic ACK v2)\s*$",
    re.MULTILINE,
)
ACK_V2_TOKEN_FIELD_CANDIDATE = re.compile(
    r"^authorized\s+rendezvous\s+token\s*:", re.IGNORECASE
)
ACK_V2_RENDEZVOUS_FIELD_CANDIDATE = re.compile(
    r"\brendezvous\b[^:\n]*:", re.IGNORECASE
)
ACK_TRANSACTION_DIGEST_FIELD_CANDIDATE = re.compile(
    r"^ack\s+transaction\s+stable\s+digest\s*:", re.IGNORECASE
)
OUTBOX_MARKER_SUFFIX = re.compile(
    r"\n\n<!-- twinfinity-outbox:[0-9a-f]{64} -->\Z"
)
CONTROL_CONTRADICTION = re.compile(
    r"\b(HOLD|STOP(?:PED)?|BLOCKED|PAUSE(?:D)?|CONTRADICT|SUPERSED(?:E|ED|ING)|"
    r"WITHDRAWN|REVOKED|INVALID|DENIED|ENFORCEMENT INCIDENT)\b|"
    r"\bDO\s+NOT\s+(?:ACTIVATE|CONTINUE|MUTATE|EXECUTE)\b",
    re.IGNORECASE,
)
POST_LEDGER_STRUCTURED_CONTRADICTION = re.compile(
    r"(?im)^\s*#{1,6}\s+[^\n]*\b(?:HOLD|STOPPED|BLOCKED|PAUSED|SUPERSEDED|"
    r"WITHDRAWN|REVOKED|INVALID|DENIED|ENFORCEMENT INCIDENT)\b|"
    r"^\s*(?:[-+*]\s+)?(?:STATE|STATUS|AUTHORITY|RENDEZVOUS|DECISION|CONTROL)\s*:\s*"
    r"`?[^\n]*\b(?:HOLD|STOPPED?|BLOCKED|PAUSED?|SUPERSEDED|WITHDRAWN|REVOKED|"
    r"INVALID|DENIED|ENFORCEMENT INCIDENT)\b",
)
POST_LEDGER_CONSTRAINT_HEADING = re.compile(
    r"(?i)^#{1,6}\s+(?:MANDATORY\s+)?(?:HARD\s+STOPS?|NON-GOALS?|"
    r"OUT\s+OF\s+SCOPE\s+AND\s+HARD\s+STOPS?)\s*$"
)
NEGATED_AUTHORITY = re.compile(
    r"\b(?:NOT|NO)\s+(?:APPROV(?:E|ED|AL)|ACCEPT(?:ED)?)\b|\bREJECT(?:ED|ION)?\b",
    re.IGNORECASE,
)
AUTHORITY_CONTRADICTION = re.compile(
    r"(?im)^\s*(?:HOLD|STOPPED?|BLOCKED|PAUSED?|WITHDRAWN|REVOKED|INVALID|DENIED)\s*$|"
    r"^\s*(?:[-+*]\s+)?(?:STATE|STATUS|AUTHORITY|DECISION|CONTROL)\s*:\s*[^\n]*"
    r"\b(?:HOLD|STOPPED?|BLOCKED|PAUSED?|WITHDRAWN|REVOKED|INVALID|DENIED)\b|"
    r"\b(?:THIS|THE)\s+(?:PACKET|DECISION|APPROVAL|AUTHORITY)\s+"
    r"(?:IS|REMAINS)\s+(?:ON\s+)?(?:HOLD|STOPPED|BLOCKED|PAUSED|WITHDRAWN|REVOKED|INVALID|DENIED)\b|"
    r"\bDO\s+NOT\s+(?:ACTIVATE|CONTINUE|MUTATE|EXECUTE)\b"
)


def has_post_ledger_control_contradiction(text: str) -> bool:
    """Reject negative authority without treating bounded constraints as revocation."""
    if POST_LEDGER_STRUCTURED_CONTRADICTION.search(text):
        return True
    in_constraint_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            in_constraint_section = bool(
                POST_LEDGER_CONSTRAINT_HEADING.fullmatch(stripped)
            )
        if in_constraint_section:
            continue
        ordinary = re.sub(r"(?i)\bHARD\s+STOPS?\b|\bPOST-HOLD\b", "", line)
        if CONTROL_CONTRADICTION.search(ordinary):
            return True
    return False
DECISION_PACKET_MARKER = re.compile(
    r"^(?:#{1,6}\s+)?(?:ROUND\s+#\d+\s+MATERIAL\s+APPROVAL\s+PACKET|DECISION\s+PACKET)\b[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)
NEGATED_DECISION_PACKET = re.compile(
    r"\b(?:NOT|NO)\s+(?:A\s+)?(?:DECISION|MATERIAL\s+APPROVAL)\s+PACKET\b",
    re.IGNORECASE,
)
APPROVAL_DECISION_FIELD = re.compile(
    r"^\s*\**Decision:\**\s*(.*?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
EXACT_PACKET_FIELD = re.compile(
    r"^\s*\**Exact\s+packet:\**\s*(.*?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
PENDING_TRACKERS = [44, 61, 120, 131, 179]
TRACKER_PENDING_READY_NEXT_ACTION = (
    "After byte-exact ledger readback, re-fetch every ordinary admission guard "
    "and publish one current-main CROSS-SESSION RENDEZVOUS; continue reporting "
    "TRACKER_BODY_PENDING: #44/#61/#120/#131/#179 without tracker writes."
)
DEFAULT_ISSUE_BODY_VALIDATOR = (
    Path(__file__).resolve().parents[1] / "references" / "validate_issue_body.py"
)
ISSUE_BODY_VALIDATION_SCHEMA = "twinfinity-issue-body-validation/v1"
OWNERSHIP_SECTION = "Ownership, readiness, and capacity"
LEGACY_RENDERED_ERROR_FIELDS = {
    "ownership_missing_state": "readiness",
    "ownership_missing_capacity": "capacity",
    "ownership_missing_next_action": "next_action",
}


class ValidationError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded)


def contains_exact_decimal_id(text: str, value: int) -> bool:
    return re.search(rf"(?<!\d){value}(?!\d)", text) is not None


def parse_ledger(markdown: str) -> tuple[dict[str, Any], str]:
    if markdown.count(MARKER) != 1:
        raise ValidationError("ledger marker must occur exactly once")
    fences = JSON_FENCE.findall(markdown)
    if len(fences) != 1:
        raise ValidationError("ledger must contain exactly one fenced JSON object")
    digests = STABLE_DIGEST.findall(markdown)
    if len(digests) != 1:
        raise ValidationError("ledger must contain exactly one Stable digest line")
    try:
        payload = json.loads(fences[0])
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid ledger JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValidationError("ledger JSON must be an object")
    if canonical_digest(payload) != digests[0]:
        raise ValidationError("Stable digest does not match canonical ledger JSON")
    return payload, digests[0]


def semantic_comment_body(text: str) -> str:
    """Remove only the deterministic SQLite-outbox transport envelope."""
    return OUTBOX_MARKER_SUFFIX.sub("", text, count=1)


def require_bool(mapping: dict[str, Any], key: str, expected: bool | None = None) -> None:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise ValidationError(f"{key} must be boolean")
    if expected is not None and value is not expected:
        raise ValidationError(f"{key} must be {str(expected).lower()}")


def is_tracker_pending_ready(payload: dict[str, Any]) -> bool:
    state = payload.get("state", {})
    guards = payload.get("guards", {})
    generation = payload.get("generation")
    predecessor = payload.get("predecessor_ledger_comment_id")
    return (
        isinstance(generation, int)
        and generation >= 1
        and (
            (generation == 1 and predecessor is None)
            or (generation > 1 and isinstance(predecessor, int) and predecessor > 0)
        )
        and payload.get("pending_tracker_issue_numbers") == PENDING_TRACKERS
        and state.get("phase") == "READY"
        and state.get("zero_wip") is True
        and state.get("agent_ready") is True
        and state.get("product_accepted") is False
        and isinstance(state.get("ready_depth"), int)
        and state.get("ready_depth", 0) >= 1
        and guards.get("tracker_consistent") is False
        and guards.get("agent_ready_label_present") is True
        and guards.get("provider_atomic_body_cas_unavailable") is True
        and payload.get("next_action") == TRACKER_PENDING_READY_NEXT_ACTION
    )


def run_issue_body_validator(body: str, validator_path: Path) -> list[dict[str, str]]:
    if not validator_path.is_file():
        raise ValidationError(f"issue-body validator is unavailable: {validator_path}")
    completed = subprocess.run(
        [sys.executable, str(validator_path), "--format", "json"],
        input=body,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationError("issue-body validator returned malformed JSON") from exc
    if (
        not isinstance(report, dict)
        or report.get("schema") != ISSUE_BODY_VALIDATION_SCHEMA
        or not isinstance(report.get("valid"), bool)
        or not isinstance(report.get("errors"), list)
    ):
        raise ValidationError("issue-body validator returned an invalid report schema")
    errors = report["errors"]
    for error in errors:
        if (
            not isinstance(error, dict)
            or set(error) != {"code", "message"}
            or not isinstance(error["code"], str)
            or not error["code"]
            or not isinstance(error["message"], str)
            or not error["message"]
        ):
            raise ValidationError("issue-body validator returned an invalid error record")
    if report["valid"] is not (not errors):
        raise ValidationError("issue-body validator validity flag contradicts its errors")
    expected_returncode = 0 if report["valid"] else 1
    if completed.returncode != expected_returncode:
        raise ValidationError("issue-body validator return code contradicts its report")
    return errors


def validate_legacy_rendered_errors(
    errors: list[dict[str, str]], payload: dict[str, Any], body: str
) -> None:
    """Allow only exact, inventoried Ownership-field gaps in a legacy body."""
    for error in errors:
        field = LEGACY_RENDERED_ERROR_FIELDS.get(error["code"])
        if field is None:
            raise ValidationError(
                f"rendered body fails canonical issue-body validator: {errors}"
            )
        matching_items = [
            item
            for item in payload["stale_field_inventory"]
            if item.get("section") == OWNERSHIP_SECTION
            and field in item.get("fields", [])
        ]
        if not matching_items:
            raise ValidationError(
                "legacy rendered Ownership error lacks an exact same-section "
                f"{field!r} inventory replacement: {error}"
            )
        for item in matching_items:
            candidate = body.replace(item["claim"], item["replacement"], 1)
            candidate_codes = {
                candidate_error["code"]
                for candidate_error in run_issue_body_validator(
                    candidate, DEFAULT_ISSUE_BODY_VALIDATOR
                )
            }
            if error["code"] in candidate_codes:
                raise ValidationError(
                    "legacy rendered Ownership error has a same-section "
                    f"{field!r} inventory replacement that does not independently cure it: "
                    f"{error}"
                )


def markdown_sections(body: str) -> list[tuple[str, int, int]]:
    matches = list(re.finditer(r"^##\s+(.+?)\s*$", body, re.MULTILINE))
    return [
        (match.group(1), match.end(), matches[index + 1].start() if index + 1 < len(matches) else len(body))
        for index, match in enumerate(matches)
    ]


def actual_section(body: str, claim: str) -> str:
    start = body.find(claim)
    if start < 0 or body.find(claim, start + 1) >= 0:
        raise ValidationError(f"stale claim must occur exactly once in body: {claim[:80]!r}")
    end = start + len(claim)
    heading_matches = list(re.finditer(r"^##\s+(.+?)\s*$", body, re.MULTILINE))
    sections = markdown_sections(body)
    if heading_matches and start < heading_matches[0].start():
        if end <= heading_matches[0].start():
            return "Preamble control"
        raise ValidationError("preamble stale claim crosses into a level-two section")
    for heading, section_start, section_end in sections:
        if section_start <= start < section_end:
            if end <= section_end:
                return heading
            raise ValidationError(f"stale claim crosses the end of section {heading!r}")
    raise ValidationError("stale claim is outside a level-two Markdown section")


def validate_inventory(body: str, payload: dict[str, Any]) -> str:
    supersedes = payload.get("supersedes_fields")
    if not isinstance(supersedes, list) or not supersedes:
        raise ValidationError("supersedes_fields must be a non-empty list")
    if any(not isinstance(field, str) for field in supersedes):
        raise ValidationError("supersedes_fields entries must be strings")
    if len(set(supersedes)) != len(supersedes):
        raise ValidationError("supersedes_fields contains duplicates")
    unknown = set(supersedes) - ALLOWED_FIELDS
    if unknown:
        raise ValidationError(f"material or unknown superseded fields: {sorted(unknown)}")

    inventory = payload.get("stale_field_inventory")
    if not isinstance(inventory, list) or not inventory:
        raise ValidationError("stale_field_inventory must be a non-empty list")
    inventoried: set[str] = set()
    seen_claims: set[str] = set()
    effective = body
    for index, item in enumerate(inventory):
        if not isinstance(item, dict):
            raise ValidationError(f"stale_field_inventory[{index}] must be an object")
        if set(item) != {"fields", "section", "claim", "replacement"}:
            raise ValidationError(f"stale_field_inventory[{index}] has unexpected keys")
        fields = item["fields"]
        section = item["section"]
        claim = item["claim"]
        replacement = item["replacement"]
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(fields) != len(set(fields))
        ):
            raise ValidationError(f"stale_field_inventory[{index}].fields must be unique strings")
        if any(field not in ALLOWED_FIELDS or field not in supersedes for field in fields):
            raise ValidationError(f"inventory fields are not allowlisted/superseded: {fields!r}")
        if not all(isinstance(value, str) and value.strip() for value in (section, claim, replacement)):
            raise ValidationError(f"stale_field_inventory[{index}] strings must be non-empty")
        if claim == replacement:
            raise ValidationError(f"stale_field_inventory[{index}] replacement is a no-op")
        if claim in seen_claims:
            raise ValidationError("stale claim is inventoried more than once")
        resolved_section = actual_section(body, claim)
        if section != resolved_section:
            raise ValidationError(
                f"stale claim section mismatch: declared={section!r}, actual={resolved_section!r}"
            )
        for field in fields:
            allowed_sections = {"Preamble control"} if field in PREAMBLE_FIELDS else set()
            allowed_sections |= FIELD_SECTIONS[field]
            if section not in allowed_sections:
                raise ValidationError(f"field {field!r} cannot overlay section {section!r}")
        seen_claims.add(claim)
        inventoried.update(fields)
        effective = effective.replace(claim, replacement, 1)
    if inventoried != set(supersedes):
        missing = sorted(set(supersedes) - inventoried)
        raise ValidationError(f"superseded fields lack stale-site inventory: {missing}")
    return effective


def validate_payload(
    payload: dict[str, Any],
    body_bytes: bytes,
    expected_repository: str,
    expected_issue: int,
    expected_main: str,
    agent_ready_label: bool,
    expected_effective_sha256: str,
) -> None:
    if set(payload) != REQUIRED_TOP_LEVEL:
        missing = sorted(REQUIRED_TOP_LEVEL - set(payload))
        extra = sorted(set(payload) - REQUIRED_TOP_LEVEL)
        raise ValidationError(f"ledger keys mismatch; missing={missing}, extra={extra}")
    if payload["schema"] != SCHEMA:
        raise ValidationError("unsupported ledger schema")
    if payload["repository"] != expected_repository or payload["issue"] != expected_issue:
        raise ValidationError("repository/issue binding mismatch")
    if not isinstance(payload["generation"], int) or payload["generation"] < 1:
        raise ValidationError("generation must be a positive integer")
    predecessor = payload["predecessor_ledger_comment_id"]
    if predecessor is not None and (not isinstance(predecessor, int) or predecessor < 1):
        raise ValidationError("predecessor_ledger_comment_id must be null or positive integer")
    if payload["generation"] == 1 and predecessor is not None:
        raise ValidationError("generation 1 must have a null predecessor")
    if payload["generation"] > 1 and predecessor is None:
        raise ValidationError("later generations require a predecessor comment id")

    pending_trackers = payload["pending_tracker_issue_numbers"]
    if (
        not isinstance(pending_trackers, list)
        or any(not isinstance(issue, int) or issue < 1 for issue in pending_trackers)
        or len(pending_trackers) != len(set(pending_trackers))
    ):
        raise ValidationError("pending_tracker_issue_numbers must be unique positive integers")

    body = payload["body"]
    required_body = {
        "bytes",
        "sha256",
        "effective_bytes",
        "effective_sha256",
        "contract_unchanged",
    }
    if not isinstance(body, dict) or set(body) != required_body:
        raise ValidationError("body binding keys are invalid")
    if body["bytes"] != len(body_bytes) or body["sha256"] != sha256(body_bytes):
        raise ValidationError("body byte/digest binding mismatch")
    require_bool(body, "contract_unchanged", True)
    body_text = body_bytes.decode("utf-8")
    effective_body = validate_inventory(body_text, payload)
    effective_bytes = effective_body.encode("utf-8")
    rendered_headings = [heading for heading, _, _ in markdown_sections(body_text)]
    effective_headings = [heading for heading, _, _ in markdown_sections(effective_body)]
    if effective_headings != rendered_headings:
        raise ValidationError("overlay changes the ordered level-two heading sequence")
    if body["effective_bytes"] != len(effective_bytes) or body["effective_sha256"] != sha256(
        effective_bytes
    ):
        raise ValidationError("virtual effective-body byte/digest binding mismatch")
    if not HEX64.fullmatch(expected_effective_sha256) or body["effective_sha256"] != expected_effective_sha256:
        raise ValidationError("effective body does not match independently reviewed digest")
    rendered_errors = run_issue_body_validator(body_text, DEFAULT_ISSUE_BODY_VALIDATOR)
    validate_legacy_rendered_errors(rendered_errors, payload, body_text)
    effective_errors = run_issue_body_validator(effective_body, DEFAULT_ISSUE_BODY_VALIDATOR)
    if effective_errors:
        raise ValidationError(f"virtual effective body fails issue-body validator: {effective_errors}")

    authority = payload["authority"]
    required_authority = {
        "decision_packet_comment_id",
        "approval_comment_id",
        "lease_accept_comment_id",
        "lease_manifest_sha256",
        "overlay_review_comment_id",
    }
    if not isinstance(authority, dict) or set(authority) != required_authority:
        raise ValidationError("authority binding keys are invalid")
    for key in (
        "decision_packet_comment_id",
        "approval_comment_id",
        "lease_accept_comment_id",
        "overlay_review_comment_id",
    ):
        if not isinstance(authority[key], int) or authority[key] < 1:
            raise ValidationError(f"{key} must be a positive integer")
    if not isinstance(authority["lease_manifest_sha256"], str) or not HEX64.fullmatch(
        authority["lease_manifest_sha256"]
    ):
        raise ValidationError("lease_manifest_sha256 must be lowercase 64-hex")

    state = payload["state"]
    required_state = {
        "accepted_main",
        "phase",
        "zero_wip",
        "agent_ready",
        "product_accepted",
        "development_occupied",
        "development_limit",
        "shared_occupied",
        "shared_limit",
        "ready_depth",
        "development_required",
        "shared_required",
    }
    optional_sre_state = {"sre_occupied", "sre_limit", "sre_required"}
    if not isinstance(state, dict) or set(state) not in {
        frozenset(required_state),
        frozenset(required_state | optional_sre_state),
    }:
        raise ValidationError("state keys are invalid")
    if state["accepted_main"] != expected_main or not HEX40.fullmatch(expected_main):
        raise ValidationError("accepted main binding mismatch")
    if state["phase"] not in {"PREPARED", "READY"}:
        raise ValidationError("phase must be PREPARED or READY")
    require_bool(state, "zero_wip", True)
    require_bool(state, "product_accepted", False)
    require_bool(state, "agent_ready", state["phase"] == "READY")
    for key in (
        "development_occupied",
        "development_limit",
        "shared_occupied",
        "shared_limit",
        "ready_depth",
        "development_required",
        "shared_required",
    ):
        if not isinstance(state[key], int) or state[key] < 0:
            raise ValidationError(f"{key} must be a non-negative integer")
    if optional_sre_state.issubset(state):
        for key in optional_sre_state:
            if not isinstance(state[key], int) or state[key] < 0:
                raise ValidationError(f"{key} must be a non-negative integer")
    if state["development_occupied"] > state["development_limit"]:
        raise ValidationError("Development capacity exceeds its limit")
    if state["shared_occupied"] > state["shared_limit"]:
        raise ValidationError("Shared capacity exceeds its limit")
    if optional_sre_state.issubset(state) and state["sre_occupied"] > state["sre_limit"]:
        raise ValidationError("SRE capacity exceeds its limit")
    if state["phase"] == "READY":
        if state["development_occupied"] + state["development_required"] > state["development_limit"]:
            raise ValidationError("prospective Development claim exceeds its limit")
        if state["shared_occupied"] + state["shared_required"] > state["shared_limit"]:
            raise ValidationError("prospective Shared claim exceeds its limit")
        if (
            optional_sre_state.issubset(state)
            and state["sre_occupied"] + state["sre_required"] > state["sre_limit"]
        ):
            raise ValidationError("prospective SRE claim exceeds its limit")

    lease = payload["lease"]
    required_lease = {"kind", "path_count", "no_additional_paths", "manifest_sha256", "absent", "existing"}
    if not isinstance(lease, dict) or set(lease) != required_lease:
        raise ValidationError("lease keys are invalid")
    if lease["kind"] != "exact-paths":
        raise ValidationError("lease kind must be exact-paths")
    require_bool(lease, "no_additional_paths", True)
    for key in ("path_count", "absent", "existing"):
        if not isinstance(lease[key], int) or lease[key] < 0:
            raise ValidationError(f"lease {key} must be a non-negative integer")
    if lease["absent"] + lease["existing"] != lease["path_count"]:
        raise ValidationError("lease absent/existing counts do not equal path_count")
    if lease["manifest_sha256"] != authority["lease_manifest_sha256"]:
        raise ValidationError("lease and authority manifest digests differ")

    guards = payload["guards"]
    if not isinstance(guards, dict) or set(guards) != REQUIRED_GUARDS:
        raise ValidationError("guard keys are invalid")
    for key in REQUIRED_GUARDS - {"agent_ready_label_present", "tracker_consistent"}:
        require_bool(guards, key, True)
    require_bool(guards, "tracker_consistent")
    require_bool(guards, "agent_ready_label_present", state["phase"] == "READY")
    if agent_ready_label is not (state["phase"] == "READY"):
        raise ValidationError("live agent-ready label does not match ledger phase")
    if guards["tracker_consistent"]:
        if pending_trackers:
            raise ValidationError("tracker-consistent ledger cannot retain pending tracker targets")
    else:
        if not is_tracker_pending_ready(payload) or agent_ready_label is not True:
            raise ValidationError(
                "tracker bodies may remain pending only on a direct READY overlay lineage "
                "with unavailable provider-atomic CAS"
            )

    recovery = payload["recovery"]
    if not isinstance(recovery, dict) or set(recovery) != {"post_hold", "barrier"}:
        raise ValidationError("recovery keys are invalid")
    require_bool(recovery, "post_hold", True)
    if recovery["barrier"] != "ACK_ONLY_THEN_LATER_COMMIT":
        raise ValidationError("post-HOLD recovery barrier is invalid")
    if not isinstance(payload["next_action"], str) or not payload["next_action"].strip():
        raise ValidationError("next_action must be non-empty")
    if not isinstance(payload["hard_stops"], list) or not payload["hard_stops"]:
        raise ValidationError("hard_stops must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in payload["hard_stops"]):
        raise ValidationError("hard_stops entries must be non-empty strings")


def validate_comments(
    comments_path: Path,
    authority_comments_path: Path,
    ledger_markdown: str,
    payload: dict[str, Any],
    ledger_comment_id: int,
    post_ledger_suffix: tuple[int, int, int] | None = None,
) -> None:
    raw = json.loads(comments_path.read_text(encoding="utf-8"))
    comments = raw.get("comments") if isinstance(raw, dict) else raw
    if not isinstance(comments, list):
        raise ValidationError("comments JSON must be a list or {comments: [...]} object")
    normalized: list[tuple[int, str]] = []
    for comment in comments:
        if not isinstance(comment, dict) or not isinstance(comment.get("id"), int):
            raise ValidationError("every comment must contain an integer id")
        text = comment.get("body", comment.get("comment", ""))
        if not isinstance(text, str):
            raise ValidationError("every comment body must be a string")
        normalized.append((comment["id"], text))
    comment_ids = [cid for cid, _ in normalized]
    if len(comment_ids) != len(set(comment_ids)):
        raise ValidationError("issue comments contain a duplicate id")
    matches = [semantic_comment_body(text) for cid, text in normalized if cid == ledger_comment_id]
    if matches != [ledger_markdown]:
        raise ValidationError("durable ledger comment is missing, duplicated, or not byte-exact")
    newer_comments = {cid: text for cid, text in normalized if cid > ledger_comment_id}
    if post_ledger_suffix is None:
        if not comment_ids or ledger_comment_id != max(comment_ids):
            raise ValidationError("selected readiness ledger must be the newest issue comment")
    else:
        if not (
            payload["state"]["phase"] == "READY"
            and (
                (
                    payload["guards"]["tracker_consistent"] is True
                    and payload["pending_tracker_issue_numbers"] == []
                )
                or is_tracker_pending_ready(payload)
            )
        ):
            raise ValidationError("post-ledger rendezvous/ACK suffix requires valid READY")
        rendezvous_id, receiver_id, echo_id = post_ledger_suffix
        if not (ledger_comment_id < rendezvous_id < receiver_id < echo_id):
            raise ValidationError("post-ledger suffix IDs are not strictly ordered")
        if set(newer_comments) != {rendezvous_id, receiver_id, echo_id}:
            raise ValidationError("post-ledger suffix is missing, duplicated, or contains another comment")
        _, ledger_digest = parse_ledger(ledger_markdown)
        effective_digest = payload["body"]["effective_sha256"]
        rendezvous_text = newer_comments[rendezvous_id]
        receiver_text = newer_comments[receiver_id]
        echo_text = newer_comments[echo_id]
        if (
            "CROSS-SESSION RENDEZVOUS" not in rendezvous_text.upper()
            or has_post_ledger_control_contradiction(rendezvous_text)
            or not contains_exact_decimal_id(rendezvous_text, ledger_comment_id)
            or ledger_digest not in rendezvous_text
            or effective_digest not in rendezvous_text
        ):
            raise ValidationError("post-ledger rendezvous lacks ledger and digest bindings")
        rendezvous_tokens = ACK_V2_RENDEZVOUS_TOKEN.findall(rendezvous_text)
        transaction_digests = ACK_TRANSACTION_STABLE_DIGEST.findall(rendezvous_text)
        expected_token = (
            f"issue #{payload['issue']} generation {payload['generation']} deterministic ACK v2"
        )

        def candidate_count(pattern: re.Pattern[str]) -> int:
            return sum(
                bool(
                    pattern.search(
                        re.sub(
                            r"\s+",
                            " ",
                            re.sub(
                                r"[*_`~]",
                                "",
                                re.sub(
                                    r"^(?:\s*>\s*)*(?:(?:[-+*]|[1-9][0-9]*[.)])\s+)*",
                                    "",
                                    line,
                                ),
                            ),
                        ).strip()
                    )
                )
                for body in (rendezvous_text, receiver_text, echo_text)
                for line in body.splitlines()
            )

        token_candidate_count = candidate_count(ACK_V2_TOKEN_FIELD_CANDIDATE)
        rendezvous_field_candidate_count = candidate_count(
            ACK_V2_RENDEZVOUS_FIELD_CANDIDATE
        )
        digest_candidate_count = candidate_count(ACK_TRANSACTION_DIGEST_FIELD_CANDIDATE)
        ack_v2_fields_present = (
            rendezvous_field_candidate_count > 0 or digest_candidate_count > 0
        )
        ack_v2_binding = (
            rendezvous_tokens == [expected_token]
            and token_candidate_count == 3
            and transaction_digests
            == [ack_transaction_sha256(receiver_text, echo_text)]
            and digest_candidate_count == 1
            and has_exact_rendezvous_token_binding(
                payload["issue"],
                expected_token,
                rendezvous_text,
                receiver_text,
                echo_text,
            )
        )
        ordered_rendezvous_binding = (
            ack_v2_binding
            if ack_v2_fields_present
            else (
                contains_exact_decimal_id(receiver_text, rendezvous_id)
                and contains_exact_decimal_id(echo_text, rendezvous_id)
            )
        )
        if (
            "DEVELOPMENT RECEIVER" not in receiver_text.upper()
            or has_post_ledger_control_contradiction(receiver_text)
            or not contains_exact_decimal_id(receiver_text, ledger_comment_id)
            or not ordered_rendezvous_binding
        ):
            raise ValidationError("post-ledger Development receiver lacks ordered bindings")
        if (
            "ACCOUNTABLE WRITER ECHO" not in echo_text.upper()
            or "ZERO MUTATION" not in echo_text.upper()
            or NEGATED_AUTHORITY.search(echo_text)
            or has_post_ledger_control_contradiction(echo_text)
            or not ordered_rendezvous_binding
            or not has_exact_receiver_body_digest_binding(receiver_text, echo_text)
        ):
            raise ValidationError("post-ledger writer echo lacks zero-mutation ordered bindings")

    generations: dict[int, tuple[int, dict[str, Any]]] = {}
    for cid, text in normalized:
        if MARKER not in text:
            continue
        other, _ = parse_ledger(text)
        generation = other.get("generation")
        if not isinstance(generation, int):
            raise ValidationError("durable ledger has invalid generation")
        if generation in generations:
            raise ValidationError("competing or duplicate ledger generation")
        if (
            other.get("repository") != payload["repository"]
            or other.get("issue") != payload["issue"]
            or not isinstance(other.get("body"), dict)
            or other["body"].get("sha256") != payload["body"]["sha256"]
            or (
                is_tracker_pending_ready(payload)
                and (
                    other["body"].get("effective_sha256")
                    != payload["body"]["effective_sha256"]
                    or other.get("pending_tracker_issue_numbers")
                    != payload["pending_tracker_issue_numbers"]
                    or not isinstance(other.get("lease"), dict)
                    or other["lease"].get("manifest_sha256")
                    != payload["lease"]["manifest_sha256"]
                )
            )
        ):
            raise ValidationError("ledger lineage repository/issue/body binding changed")
        generations[generation] = (cid, other)
    if generations.get(payload["generation"], (None,))[0] != ledger_comment_id:
        raise ValidationError("ledger generation/comment binding mismatch")
    if payload["generation"] != max(generations):
        raise ValidationError("selected ledger is not the unique maximum generation")
    expected_generations = set(range(1, payload["generation"] + 1))
    if set(generations) != expected_generations:
        raise ValidationError("ledger predecessor chain is incomplete")
    for generation in sorted(generations):
        cid, item = generations[generation]
        predecessor = item.get("predecessor_ledger_comment_id")
        if generation == 1:
            if predecessor is not None:
                raise ValidationError("generation 1 must have a null predecessor")
        elif predecessor != generations[generation - 1][0]:
            raise ValidationError("ledger predecessor is missing or non-monotonic")
        if generation < payload["generation"] and cid >= ledger_comment_id:
            raise ValidationError("ledger comment chronology is non-monotonic")

    authority_raw = json.loads(authority_comments_path.read_text(encoding="utf-8"))
    authority_comments = (
        authority_raw.get("comments") if isinstance(authority_raw, dict) else authority_raw
    )
    if not isinstance(authority_comments, list):
        raise ValidationError("authority comments JSON must be a list or {comments: [...]} object")
    authority_by_id: dict[int, str] = {}
    for comment in authority_comments:
        if not isinstance(comment, dict) or not isinstance(comment.get("id"), int):
            raise ValidationError("every authority comment must contain an integer id")
        if (
            comment.get("repository") != payload["repository"]
            or comment.get("issue") != payload["issue"]
        ):
            raise ValidationError("every authority comment must bind the owning repository/issue")
        body_text = comment.get("body", comment.get("comment", ""))
        if not isinstance(body_text, str):
            raise ValidationError("every authority comment body must be a string")
        if comment["id"] in authority_by_id:
            raise ValidationError("authority comments contain a duplicate id")
        authority_by_id[comment["id"]] = semantic_comment_body(body_text)

    authority = payload["authority"]
    authority_keys = (
        "decision_packet_comment_id",
        "approval_comment_id",
        "lease_accept_comment_id",
        "overlay_review_comment_id",
    )
    authority_ids = [authority[key] for key in authority_keys]
    if len(authority_ids) != len(set(authority_ids)):
        raise ValidationError("decision, approval, lease ACCEPT, and overlay review must be distinct")
    for key in authority_keys:
        if authority[key] not in authority_by_id or authority[key] >= ledger_comment_id:
            raise ValidationError(f"authority comment is absent or does not precede ledger: {key}")
    lease_digest = authority["lease_manifest_sha256"]
    effective_digest = payload["body"]["effective_sha256"]
    decision_text = authority_by_id[authority["decision_packet_comment_id"]]
    approval_text = authority_by_id[authority["approval_comment_id"]]
    lease_text = authority_by_id[authority["lease_accept_comment_id"]]
    overlay_review = authority_by_id[authority["overlay_review_comment_id"]]
    approval_decisions = APPROVAL_DECISION_FIELD.findall(approval_text)
    approval_packets = EXACT_PACKET_FIELD.findall(approval_text)
    decision_markers = list(DECISION_PACKET_MARKER.finditer(decision_text))
    decision_marker = decision_markers[0] if len(decision_markers) == 1 else None
    if (
        decision_marker is None
        or NEGATED_AUTHORITY.search(decision_marker.group(0))
        or AUTHORITY_CONTRADICTION.search(decision_text)
        or NEGATED_DECISION_PACKET.search(decision_text)
    ):
        raise ValidationError("decision comment lacks structured DECISION PACKET marker")
    if (
        NEGATED_AUTHORITY.search(approval_text)
        or CONTROL_CONTRADICTION.search(approval_text)
        or len(approval_decisions) != 1
        or approval_decisions[0].upper() != "APPROVE"
        or len(approval_packets) != 1
        or re.fullmatch(
            rf"`?{authority['decision_packet_comment_id']}`?",
            approval_packets[0],
        ) is None
    ):
        raise ValidationError("approval comment lacks approval marker or decision binding")
    if (
        NEGATED_AUTHORITY.search(lease_text)
        or not re.search(r"\bACCEPT(?:ED)?\b", lease_text, re.IGNORECASE)
        or lease_digest not in lease_text
    ):
        raise ValidationError("lease ACCEPT comment does not bind lease manifest digest")
    if (
        "OVERLAY REVIEW" not in overlay_review.upper()
        or NEGATED_AUTHORITY.search(overlay_review)
        or not re.search(r"\bACCEPT(?:ED)?\b", overlay_review, re.IGNORECASE)
        or lease_digest not in overlay_review
        or effective_digest not in overlay_review
    ):
        raise ValidationError("independent overlay review is not a structured digest-bound ACCEPT")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--issue", type=int, required=True)
    parser.add_argument("--main", required=True)
    parser.add_argument("--expected-effective-sha256", required=True)
    parser.add_argument("--agent-ready-label", action="store_true")
    parser.add_argument("--comments-json", type=Path)
    parser.add_argument("--authority-comments-json", type=Path)
    parser.add_argument("--ledger-comment-id", type=int)
    parser.add_argument("--rendezvous-comment-id", type=int)
    parser.add_argument("--development-receiver-comment-id", type=int)
    parser.add_argument("--writer-echo-comment-id", type=int)
    parser.add_argument("--draft-validation", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        body_bytes = args.body.read_bytes()
        body_bytes.decode("utf-8")
        ledger_markdown = args.ledger.read_text(encoding="utf-8")
        payload, _ = parse_ledger(ledger_markdown)
        validate_payload(
            payload,
            body_bytes,
            args.repository,
            args.issue,
            args.main,
            args.agent_ready_label,
            args.expected_effective_sha256,
        )
        if args.draft_validation and (
            args.comments_json is not None
            or args.authority_comments_json is not None
            or args.ledger_comment_id is not None
            or args.rendezvous_comment_id is not None
            or args.development_receiver_comment_id is not None
            or args.writer_echo_comment_id is not None
        ):
            raise ValidationError("draft-validation cannot be combined with durable comments evidence")
        if not args.draft_validation and (
            args.comments_json is None
            or args.authority_comments_json is None
            or args.ledger_comment_id is None
        ):
            raise ValidationError(
                "durable validation requires comments-json, authority-comments-json, and ledger-comment-id"
            )
        if (args.comments_json is None) != (args.ledger_comment_id is None):
            raise ValidationError("comments-json and ledger-comment-id must be supplied together")
        suffix_values = (
            args.rendezvous_comment_id,
            args.development_receiver_comment_id,
            args.writer_echo_comment_id,
        )
        if any(value is not None for value in suffix_values) and not all(
            value is not None for value in suffix_values
        ):
            raise ValidationError("post-ledger suffix requires rendezvous, receiver, and echo IDs together")
        if args.comments_json is not None:
            validate_comments(
                args.comments_json,
                args.authority_comments_json,
                ledger_markdown,
                payload,
                args.ledger_comment_id,
                suffix_values if all(value is not None for value in suffix_values) else None,
            )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        print(f"State overlay rejected: {exc}", file=sys.stderr)
        return 1
    if args.draft_validation:
        if payload["guards"]["tracker_consistent"]:
            print("State overlay draft is structurally valid; it is not activation authority.")
        else:
            print("State overlay draft is direct READY with TRACKER_BODY_PENDING; live admission checks still apply.")
    else:
        if payload["guards"]["tracker_consistent"]:
            print("Durable state overlay artifact is valid; live admission still requires fresh runtime checks.")
        else:
            print("Durable direct READY overlay is valid with TRACKER_BODY_PENDING; live admission checks still apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
