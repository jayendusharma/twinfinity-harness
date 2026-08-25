#!/usr/bin/env python3
"""Read-only postcondition for Twinfinity canonical tracker bodies.

The validator deliberately accepts body files only. Comments, labels, issue
timestamps, session claims, and network transports are outside its interface
and therefore cannot satisfy the postcondition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence


REQUIRED_ISSUES = (44, 61, 120, 131, 179)
BLOCK_START = "<!-- twinfinity-current-control:v1 -->"
BLOCK_END = "<!-- /twinfinity-current-control:v1 -->"
HISTORICAL_BOUNDARY = (
    "> **HISTORICAL REFERENCE BELOW.** All status, head, capacity, readiness, "
    "and next-action language below this marker is a preserved superseded "
    "snapshot, not a current instruction. Only the authoritative block above "
    "and newer durable owning comments control execution. Stable product "
    "definitions and dependency descriptions below remain descriptive."
)
HISTORICAL_BOUNDARY_RE = re.compile(
    rf"(?m)^{re.escape(HISTORICAL_BOUNDARY)}(?:\n|$)"
)
BLOCK_RE = re.compile(
    rf"(?ms)^{re.escape(BLOCK_START)}\n.*?^{re.escape(BLOCK_END)}(?:\n|$)"
)
MAIN_RE = re.compile(
    r"(?i)\b(?:accepted|current)\s+main(?:\s+is|\s*[:=])\s*`?([0-9a-f]{40})`?"
)
CAPACITY_RE = re.compile(
    r"active D(?P<active_d>\d+)/S(?P<active_s>\d+); "
    r"retained D(?P<retained_d>\d+)/S(?P<retained_s>\d+); "
    r"available D(?P<available_d>\d+)/S(?P<available_s>\d+); "
    r"READY (?P<ready>\d+)"
)
LEGACY_CAPACITY_RE = re.compile(
    r"(?i)\b(?:portfolio|capacity)[^\n]{0,120}?"
    r"development\s+(\d+)/(\d+)[^\n]{0,80}?shared\s+(\d+)/(\d+)"
)
STATUS_TOKENS = frozenset(
    {
        "ACTIVE",
        "BLOCKED",
        "CLEANED",
        "CLOSED",
        "DONE",
        "HOLD",
        "MERGED",
        "PREPARED",
        "QUEUED",
        "READY",
        "RELEASED",
    }
)
NEGATION_SUFFIX_RE = re.compile(
    r"(?i)(?:\bno\s+longer\s+|\bnot\s+|\bpreviously\s+|"
    r"\bformerly\s+|\bwas\s+)$"
)
FENCE_RE = re.compile(r"^(?P<indent> {0,3})(?P<marker>`{3,}|~{3,})")
MAX_BODY_BYTES = 4 * 1024 * 1024


class Outcome(StrEnum):
    COMPLETE = "COMPLETE"
    TRACKER_BODY_PENDING = "TRACKER_BODY_PENDING"


@dataclass(frozen=True, slots=True)
class Capacity:
    active_d: int
    active_s: int
    retained_d: int
    retained_s: int
    available_d: int
    available_s: int
    ready: int

    @property
    def total_d(self) -> int:
        return self.active_d + self.retained_d

    @property
    def total_s(self) -> int:
        return self.active_s + self.retained_s


@dataclass(frozen=True, slots=True)
class Projection:
    accepted_main: str
    state: str
    capacity_text: str
    capacity: Capacity
    development_limit: int
    shared_limit: int
    state_issue: int
    state_tokens: frozenset[str]


@dataclass(frozen=True, slots=True)
class BodyResult:
    issue: int
    path: str
    sha256: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationResult:
    outcome: Outcome
    accepted_main: str
    state: str
    capacity: str
    stale_issues: tuple[int, ...]
    bodies: tuple[BodyResult, ...]


def canonical_block(projection: Projection) -> str:
    return (
        f"{BLOCK_START}\n"
        f"Accepted main: {projection.accepted_main}\n"
        f"State: {projection.state}\n"
        f"Capacity: {projection.capacity_text}\n"
        f"{BLOCK_END}\n"
    )


def parse_projection(
    accepted_main: str,
    state: str,
    capacity_text: str,
    *,
    development_limit: int,
    shared_limit: int,
) -> Projection:
    accepted_main = accepted_main.strip().lower()
    if re.fullmatch(r"[0-9a-f]{40}", accepted_main) is None:
        raise ValueError("accepted-main must be an exact 40-character lowercase SHA")

    state = " ".join(state.split())
    state_match = re.match(r"^#(\d+)\s+(.+)$", state)
    if state_match is None:
        raise ValueError("state must start with an owning issue such as '#88 DONE'")
    state_upper = state.upper()
    state_tokens = frozenset(
        token for token in STATUS_TOKENS if re.search(rf"\b{token}\b", state_upper)
    )
    if not state_tokens:
        raise ValueError("state must contain at least one canonical status token")
    for token in state_tokens:
        for match in re.finditer(rf"\b{token}\b", state_upper):
            if NEGATION_SUFFIX_RE.search(state[: match.start()]):
                raise ValueError("state status tokens must be positive, not negated")
    terminal = {"DONE", "MERGED", "CLEANED", "CLOSED", "RELEASED"}
    held = {"HOLD", "BLOCKED"}
    if state_tokens & terminal and not state_tokens <= terminal:
        raise ValueError("terminal state tokens cannot be combined with non-terminal state")
    if "READY" in state_tokens and state_tokens != {"READY"}:
        raise ValueError("READY cannot be combined with another state token")
    if state_tokens & held and not state_tokens <= held | {"ACTIVE"}:
        raise ValueError("HOLD/BLOCKED cannot be combined with this state")
    if "ACTIVE" in state_tokens and not state_tokens <= held | {"ACTIVE"}:
        raise ValueError("ACTIVE cannot be combined with this state")
    if state_tokens & {"PREPARED", "QUEUED"} and not state_tokens <= {
        "PREPARED",
        "QUEUED",
    }:
        raise ValueError("PREPARED/QUEUED cannot be combined with this state")

    capacity_text = " ".join(capacity_text.split())
    capacity_match = CAPACITY_RE.fullmatch(capacity_text)
    if capacity_match is None:
        raise ValueError(
            "capacity must use 'active Dn/Sn; retained Dn/Sn; "
            "available Dn/Sn; READY n'"
        )
    values = {name: int(value) for name, value in capacity_match.groupdict().items()}
    capacity = Capacity(**values)
    if development_limit <= 0 or shared_limit < 0:
        raise ValueError("capacity limits must be non-negative and Development positive")
    if capacity.total_d + capacity.available_d != development_limit:
        raise ValueError(
            f"Development capacity must account exactly to {development_limit}"
        )
    if capacity.total_s + capacity.available_s != shared_limit:
        raise ValueError(f"Shared capacity must account exactly to {shared_limit}")

    return Projection(
        accepted_main=accepted_main,
        state=state,
        capacity_text=capacity_text,
        capacity=capacity,
        development_limit=development_limit,
        shared_limit=shared_limit,
        state_issue=int(state_match.group(1)),
        state_tokens=state_tokens,
    )


def parse_body_arg(value: str) -> tuple[int, Path]:
    issue_text, separator, path_text = value.partition("=")
    if not separator or not issue_text.isdigit() or not path_text:
        raise argparse.ArgumentTypeError("body must use ISSUE=/absolute/or/relative/path")
    return int(issue_text), Path(path_text)


def _decode_body(raw: bytes) -> str:
    if len(raw) > MAX_BODY_BYTES:
        raise ValueError(f"body exceeds {MAX_BODY_BYTES} bytes")
    text = raw.decode("utf-8", errors="strict").replace("\r\n", "\n").replace("\r", "\n")
    if not text.endswith("\n"):
        text += "\n"
    return text


def _read_body(path: Path) -> tuple[bytes, str]:
    raw = path.read_bytes()
    return raw, _decode_body(raw)


def _remove_fenced_code(text: str) -> str:
    """Blank Markdown fenced code while preserving line positions."""

    output: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    for line in text.splitlines(keepends=True):
        match = FENCE_RE.match(line)
        if fence_character is None:
            if match is None:
                output.append(line)
                continue
            marker = match.group("marker")
            fence_character = marker[0]
            fence_length = len(marker)
            output.append("\n" if line.endswith("\n") else "")
            continue

        closing = FENCE_RE.match(line)
        if closing is not None:
            marker = closing.group("marker")
            tail = line[closing.end() :].strip()
            if (
                marker[0] == fence_character
                and len(marker) >= fence_length
                and not tail
            ):
                fence_character = None
                fence_length = 0
        output.append("\n" if line.endswith("\n") else "")
    return "".join(output)


def _unexpected_state_claims(text: str, projection: Projection) -> list[str]:
    claims: list[str] = []
    anchor = f"#{projection.state_issue}"
    for line_number, line in enumerate(text.splitlines(), start=1):
        if anchor not in line:
            continue
        upper_line = line.upper()
        unexpected: set[str] = set()
        for token in STATUS_TOKENS - projection.state_tokens:
            for match in re.finditer(rf"\b{token}\b", upper_line):
                prefix = line[: match.start()]
                if NEGATION_SUFFIX_RE.search(prefix):
                    continue
                unexpected.add(token)
        if unexpected:
            claims.append(
                f"line {line_number} contradicts state with "
                f"{','.join(sorted(unexpected))}"
            )
    return claims


def inspect_body_bytes(
    issue: int, path: Path, raw: bytes, projection: Projection
) -> BodyResult:
    text = _decode_body(raw)
    reasons: list[str] = []
    effective_text = _remove_fenced_code(text)
    boundary_matches = list(HISTORICAL_BOUNDARY_RE.finditer(effective_text))
    boundary_count = len(boundary_matches)
    if boundary_count == 1:
        current_text = effective_text[: boundary_matches[0].start()]
    else:
        current_text = effective_text
        if boundary_count > 1:
            reasons.append(
                f"expected at most one historical boundary, found {boundary_count}"
            )

    blocks = BLOCK_RE.findall(current_text)
    expected = canonical_block(projection)
    if not blocks:
        reasons.append("missing canonical current-control block")
    elif len(blocks) != 1:
        reasons.append(f"expected one current-control block, found {len(blocks)}")
    elif blocks[0] != expected:
        reasons.append("current-control block does not equal the intended projection")

    outside = BLOCK_RE.sub("", current_text)
    for match in MAIN_RE.finditer(outside):
        observed = match.group(1).lower()
        if observed != projection.accepted_main:
            reasons.append(f"contradictory accepted main {observed}")

    reasons.extend(_unexpected_state_claims(outside, projection))

    for match in LEGACY_CAPACITY_RE.finditer(outside):
        observed_d, observed_d_limit, observed_s, observed_s_limit = (
            int(value) for value in match.groups()
        )
        if (observed_d, observed_d_limit, observed_s, observed_s_limit) != (
            projection.capacity.total_d,
            projection.development_limit,
            projection.capacity.total_s,
            projection.shared_limit,
        ):
            reasons.append(
                "contradictory accounted capacity "
                f"D{observed_d}/{observed_d_limit} "
                f"S{observed_s}/{observed_s_limit}"
            )

    for match in CAPACITY_RE.finditer(outside):
        observed = " ".join(match.group(0).split())
        if observed != projection.capacity_text:
            reasons.append(f"contradictory capacity tuple {observed}")

    return BodyResult(
        issue=issue,
        path=str(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        reasons=tuple(dict.fromkeys(reasons)),
    )


def inspect_body(issue: int, path: Path, projection: Projection) -> BodyResult:
    raw, _ = _read_body(path)
    return inspect_body_bytes(issue, path, raw, projection)


def validate_bodies(
    body_paths: dict[int, Path], projection: Projection
) -> ValidationResult:
    actual = tuple(sorted(body_paths))
    if actual != REQUIRED_ISSUES:
        missing = sorted(set(REQUIRED_ISSUES) - set(actual))
        extra = sorted(set(actual) - set(REQUIRED_ISSUES))
        raise ValueError(f"body set mismatch; missing={missing}, extra={extra}")

    bodies = tuple(
        inspect_body(issue, body_paths[issue], projection) for issue in REQUIRED_ISSUES
    )
    stale = tuple(body.issue for body in bodies if body.reasons)
    return ValidationResult(
        outcome=Outcome.TRACKER_BODY_PENDING if stale else Outcome.COMPLETE,
        accepted_main=projection.accepted_main,
        state=projection.state,
        capacity=projection.capacity_text,
        stale_issues=stale,
        bodies=bodies,
    )


def validate_body_snapshots(
    body_paths: dict[int, Path], body_bytes: dict[int, bytes], projection: Projection
) -> ValidationResult:
    actual_paths = tuple(sorted(body_paths))
    actual_bytes = tuple(sorted(body_bytes))
    if actual_paths != REQUIRED_ISSUES or actual_bytes != REQUIRED_ISSUES:
        missing = sorted(
            set(REQUIRED_ISSUES) - (set(actual_paths) & set(actual_bytes))
        )
        extra = sorted((set(actual_paths) | set(actual_bytes)) - set(REQUIRED_ISSUES))
        raise ValueError(f"body set mismatch; missing={missing}, extra={extra}")
    bodies = tuple(
        inspect_body_bytes(issue, body_paths[issue], body_bytes[issue], projection)
        for issue in REQUIRED_ISSUES
    )
    stale = tuple(body.issue for body in bodies if body.reasons)
    return ValidationResult(
        outcome=Outcome.TRACKER_BODY_PENDING if stale else Outcome.COMPLETE,
        accepted_main=projection.accepted_main,
        state=projection.state,
        capacity=projection.capacity_text,
        stale_issues=stale,
        bodies=bodies,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the five canonical tracker body postconditions without writes"
    )
    parser.add_argument(
        "--body",
        action="append",
        required=True,
        type=parse_body_arg,
        metavar="ISSUE=PATH",
        help="exact rendered body file; repeat for 44,61,120,131,179",
    )
    parser.add_argument("--accepted-main", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--capacity", required=True)
    parser.add_argument("--development-limit", type=int, required=True)
    parser.add_argument("--shared-limit", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        body_paths: dict[int, Path] = {}
        for issue, path in args.body:
            if issue in body_paths:
                raise ValueError(f"duplicate body for #{issue}")
            body_paths[issue] = path
        projection = parse_projection(
            args.accepted_main,
            args.state,
            args.capacity,
            development_limit=args.development_limit,
            shared_limit=args.shared_limit,
        )
        result = validate_bodies(body_paths, projection)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"outcome": "INVALID_INPUT", "detail": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.outcome is Outcome.COMPLETE else 3


if __name__ == "__main__":
    sys.exit(main())
