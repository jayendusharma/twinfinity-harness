#!/usr/bin/env python3
"""Fail closed when a GitHub control receipt exposes owner-local evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.:/-])(?:file://|/(?!/)[^\s`'\"<>]+|[A-Za-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+)"
)
SECRET_VALUE = re.compile(
    r"(?i)(?:authorization\s*:\s*bearer\s+\S+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"(?:token|password|passwd|secret|api[_-]?key|client[_-]?secret)\s*[:=]\s*[`'\"]?[A-Za-z0-9_./+\-=]{8,})"
)
HEX64 = re.compile(r"(?i)\b[0-9a-f]{64}\b")
PATHISH = re.compile(r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+|\b[A-Za-z0-9_-]+\.(?:py|json|ya?ml|toml|lock|txt|md|sh|ts|tsx|js|jsx)\b")
LEDGER_HASH_INVENTORY_PATH = re.compile(
    r"(?:\b[A-Za-z0-9_.-]+/){2,}[A-Za-z0-9_.-]+|"
    r"(?:\b[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.(?:py|json|ya?ml|toml|lock|txt|md|sh|ts|tsx|js|jsx)\b"
)
DIRECT_APPROVAL = re.compile(
    r"(?is)(?:please\s+(?:approve|authorize|consent|grant\s+permission)|"
    r"reply\s+(?:with\s+)?approved|do\s+you\s+(?:approve|authorize|consent)|"
    r"can\s+you\s+(?:approve|authorize|consent)|user,?\s+approve|"
    r"approval\s+needed\s+from\s+you|"
    r"please\s+reply\s*:\s*(?:i\s+)?(?:explicitly\s+)?(?:approve|authorize|consent|grant\s+permission)|"
    r"\b(?:i|we)\s+(?:need|require|await)\s+your\s+(?:approval|authorization|consent|permission))"
)
LEDGER_SCHEMA = "twinfinity-owning-state-ledger/v1"
HOSTED_RECEIPT_SCHEMA = "twinfinity.hosted-operation-receipt.v1"


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def structured_ledger_digest_lines(body: str) -> set[int]:
    """Return JSON-line numbers only when every ledger digest is allowlisted."""
    safe_lines: set[int] = set()
    for match in re.finditer(r"(?ms)^```json[ \t]*\n(.*?)\n```[ \t]*$", body):
        block = match.group(1)
        try:
            payload = json.loads(block, object_pairs_hook=reject_duplicate_json_keys)
            allowed = [
                payload["body"]["sha256"],
                payload["body"]["effective_sha256"],
                payload["authority"]["lease_manifest_sha256"],
                payload["lease"]["manifest_sha256"],
            ]
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(payload, dict) or payload.get("schema") != LEDGER_SCHEMA:
            continue
        if not all(isinstance(value, str) and HEX64.fullmatch(value) for value in allowed):
            continue
        if allowed[2] != allowed[3]:
            continue
        allowed_paths = {
            ("body", "sha256"),
            ("body", "effective_sha256"),
            ("authority", "lease_manifest_sha256"),
            ("lease", "manifest_sha256"),
        }
        seen_paths: set[tuple[object, ...]] = set()
        valid = True

        def visit(value: object, path: tuple[object, ...] = ()) -> None:
            nonlocal valid
            if isinstance(value, dict):
                for key, child in value.items():
                    visit(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, path + (index,))
            elif isinstance(value, str) and HEX64.search(value):
                if path in allowed_paths and HEX64.fullmatch(value):
                    seen_paths.add(path)
                    return
                if (
                    len(path) == 3
                    and path[0] == "stale_field_inventory"
                    and isinstance(path[1], int)
                    and path[2] in {"claim", "replacement"}
                ):
                    for line in value.splitlines():
                        hashes = HEX64.findall(line)
                        if not hashes:
                            continue
                        safe_fingerprint = bool(
                            re.search(r"(?i)\b(?:manifest|fingerprint)\b", line)
                            or re.search(r"(?i)\b(?:stable|decision packet)\s+digest\b", line)
                        ) and not LEDGER_HASH_INVENTORY_PATH.search(line)
                        if len(hashes) != 1 or not safe_fingerprint:
                            valid = False
                    return
                valid = False

        visit(payload)
        if not valid or seen_paths != allowed_paths:
            continue
        first_line = body[: match.start(1)].count("\n") + 1
        safe_lines.update(range(first_line, first_line + len(block.splitlines())))
    return safe_lines


def structured_hosted_receipt_digest_lines(body: str) -> set[int]:
    """Allow only the closed hosted-receipt marker's binding digest paths."""
    safe_lines: set[int] = set()
    marker = re.compile(
        r"(?m)^<!-- twinfinity-hosted-operation-receipt:(\{[^\r\n]*\}) -->$"
    )
    allowed_paths = {
        ("idempotency_key_sha256",),
        ("scope_sha256",),
        ("result", "alert_config_sha256"),
    }
    for match in marker.finditer(body):
        try:
            payload = json.loads(match.group(1), object_pairs_hook=reject_duplicate_json_keys)
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict) or payload.get("schema") != HOSTED_RECEIPT_SCHEMA:
            continue
        if not all(
            isinstance(payload.get(key), str) and HEX64.fullmatch(payload[key])
            for key in ("idempotency_key_sha256", "scope_sha256")
        ):
            continue
        valid = True

        def visit(value: object, path: tuple[object, ...] = ()) -> None:
            nonlocal valid
            if isinstance(value, dict):
                for key, child in value.items():
                    visit(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, path + (index,))
            elif isinstance(value, str) and HEX64.search(value):
                if path not in allowed_paths or not HEX64.fullmatch(value):
                    valid = False

        visit(payload)
        if valid:
            safe_lines.add(body[: match.start()].count("\n") + 1)
    return safe_lines


def validate(body: str, session_role: str) -> list[str]:
    errors: list[str] = []
    structured_digest_lines = (
        structured_ledger_digest_lines(body)
        | structured_hosted_receipt_digest_lines(body)
    )
    for number, line in enumerate(body.splitlines(), start=1):
        if ABSOLUTE_PATH.search(line):
            errors.append(f"line {number}: absolute or local path is not GitHub-safe")
        if SECRET_VALUE.search(line):
            errors.append(f"line {number}: secret-like value is not GitHub-safe")
        hashes = HEX64.findall(line)
        if hashes and number not in structured_digest_lines:
            safe_fingerprint = bool(
                re.search(r"(?i)\b(?:manifest|fingerprint)\b", line)
                or re.search(r"(?i)\b(?:stable|decision packet)\s+digest\b", line)
            ) and not PATHISH.search(line)
            if len(hashes) != 1 or not safe_fingerprint:
                errors.append(f"line {number}: publish one manifest fingerprint, not a per-file hash inventory")
    if session_role != "planner" and DIRECT_APPROVAL.search(body):
        errors.append("non-planner control artifact directly solicits user approval")
    return errors


def self_test() -> int:
    fingerprint = "a" * 64
    rendered = "b" * 64
    effective = "c" * 64
    ledger = {
        "schema": LEDGER_SCHEMA,
        "body": {"sha256": rendered, "effective_sha256": effective},
        "authority": {"lease_manifest_sha256": fingerprint},
        "lease": {"manifest_sha256": fingerprint},
        "stale_field_inventory": [
            {"replacement": f"DevOps/SRE manifest fingerprint: {fingerprint}"}
        ],
    }
    safe_ledger = "```json\n" + json.dumps(ledger, sort_keys=True) + "\n```\n"
    unsafe_ledger = json.loads(json.dumps(ledger))
    unsafe_ledger["files"] = [{"sha256": "d" * 64}]
    reused_digest_ledger = json.loads(json.dumps(ledger))
    reused_digest_ledger["files"] = [{"path": "backend/app.py", "sha256": rendered}]
    embedded_inventory_ledger = json.loads(json.dumps(ledger))
    embedded_inventory_ledger["stale_field_inventory"][0]["replacement"] = (
        f"Manifest fingerprint: {fingerprint} for backend/app.py"
    )
    duplicate_key_ledger = safe_ledger.replace(
        f'"sha256": "{rendered}"',
        f'"sha256": {json.dumps("e" * 64)}, "sha256": "{rendered}"',
    )
    hosted_receipt = {
        "schema": HOSTED_RECEIPT_SCHEMA,
        "outcome": "SUCCESS",
        "operation_id": 5,
        "idempotency_key_sha256": fingerprint,
        "provider": "github",
        "target_kind": "github_actions_rerun",
        "target_key": "owner/repo:run:1:attempt:1",
        "operation_kind": "RERUN_WORKFLOW",
        "scope_sha256": rendered,
        "verification": "PASS",
        "summary": "One bounded retry completed.",
        "result": {
            "workflow_run_id": 1,
            "run_attempt": 2,
            "check_suite_id": 2,
            "job_ids": [3],
        },
    }
    safe_hosted_receipt = (
        "<!-- twinfinity-hosted-operation-receipt:"
        + json.dumps(hosted_receipt, sort_keys=True, separators=(",", ":"))
        + " -->\n"
    )
    unsafe_hosted_receipt = json.loads(json.dumps(hosted_receipt))
    unsafe_hosted_receipt["summary"] = f"Unexpected embedded hash {effective}"
    safe = (
        "CLEANUP RECEIPT\nIssue: #87\nHead: 888ae3e\n"
        "Lease: backend/services/segmentation_identity.py\n"
        "Worktree ID: issue87-r4\nTargets: 4 run roots; 1 worktree\n"
        "Reclaimed bytes: 5538368779\nAbsence verdict: PASS\n"
        f"Manifest fingerprint: {fingerprint}\n"
    )
    fixtures = [
        ("safe projection", safe, "development", False),
        ("home path", safe + "Archive: /home/ubuntu/private/archive.tar\n", "planner", True),
        ("tmp path", safe + "Root: /tmp/twinfinity-issue87-a\n", "development", True),
        ("windows path", safe + "Root: C:\\work\\issue87\n", "sre", True),
        ("general unix path", safe + "Archive: /opt/twinfinity/private/receipt.tar\n", "planner", True),
        ("unc path", safe + "Archive: \\\\server\\private\\receipt.tar\n", "development", True),
        ("file inventory", safe + f"- backend/app.py {fingerprint}\n", "planner", True),
        ("secret value", safe + "Authorization: Bearer abcdefghijklmnop\n", "planner", True),
        ("worker prompt", safe + "Please approve this operation.\n", "development", True),
        (
            "multiline worker prompt",
            safe + "Please reply:\nI explicitly authorize canonical Development to publish.\n",
            "development",
            True,
        ),
        ("authorization ask", safe + "I need your authorization before I can publish.\n", "development", True),
        ("neutral blocker", safe + "Planner authorization absent; mutation remains stopped.\n", "development", False),
        ("planner prompt", safe + "Please approve this material operation.\n", "planner", False),
        ("stable decision digest", f"APPROVAL DECISION PACKET\nStable digest: {fingerprint}\n", "planner", False),
        ("structured owning ledger", safe_ledger, "planner", False),
        (
            "structured ledger per-file hash",
            "```json\n" + json.dumps(unsafe_ledger, sort_keys=True) + "\n```\n",
            "planner",
            True,
        ),
        (
            "structured ledger reused per-file hash",
            "```json\n" + json.dumps(reused_digest_ledger, sort_keys=True) + "\n```\n",
            "planner",
            True,
        ),
        (
            "structured ledger embedded path hash",
            "```json\n" + json.dumps(embedded_inventory_ledger, sort_keys=True) + "\n```\n",
            "planner",
            True,
        ),
        ("structured ledger duplicate digest key", duplicate_key_ledger, "planner", True),
        ("structured hosted receipt", safe_hosted_receipt, "sre", False),
        (
            "structured hosted receipt embedded hash",
            "<!-- twinfinity-hosted-operation-receipt:"
            + json.dumps(unsafe_hosted_receipt, sort_keys=True, separators=(",", ":"))
            + " -->\n",
            "sre",
            True,
        ),
        (
            "decision digest path inventory",
            f"APPROVAL DECISION PACKET\nDecision packet digest: {fingerprint} for backend/app.py\n",
            "planner",
            True,
        ),
    ]
    failures = []
    for name, body, role, should_fail in fixtures:
        failed = bool(validate(body, role))
        if failed != should_fail:
            failures.append(name)
    if failures:
        print("SELF-TEST FAILED: " + ", ".join(failures), file=sys.stderr)
        return 1
    print(f"SELF-TEST PASS: {len(fixtures)} fixtures")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", nargs="?", help="Receipt file; omit to read stdin")
    parser.add_argument("--session-role", choices=("planner", "development", "sre"), default="planner")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    body = Path(args.receipt).read_text(encoding="utf-8") if args.receipt else sys.stdin.read()
    errors = validate(body, args.session_role)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Control receipt is GitHub-safe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
