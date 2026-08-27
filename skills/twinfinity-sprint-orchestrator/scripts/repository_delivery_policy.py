#!/usr/bin/env python3
"""Fail-closed branch and worktree policy derived from repository identity."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat


APPLICATION_REPOSITORY = "twinfinityai/twinfinityapp"
HARNESS_REPOSITORY = "jayendusharma/twinfinity-harness"
HARNESS_STANDING_AUTHORITY_SCHEMA = "twinfinity-harness-standing-source-authority/v1"
HARNESS_SOURCE_SCOPE = (
    "Repository-local harness source, contracts, and hermetic tests for the owning issue.",
)
HARNESS_SOURCE_EXCLUSIONS = (
    "No installation or runtime activation.",
    "No live coordination database, hosted provider, or application-repository mutation.",
)
HARNESS_SOURCE_WRITER = "One Development source writer using Shared capacity 1."
HARNESS_SOURCE_REVIEWER_PLAN = (
    "Independent Governor review on the exact candidate head.",
)
HARNESS_SOURCE_COLLISION_PROOF = (
    "Exclusive repository-writer mutex and graph collision evidence remain exact.",
)
HARNESS_SOURCE_ENVIRONMENT_RULE = (
    "Use repository-local source and isolated temporary SQLite databases only."
)
HARNESS_SOURCE_ROUTINE_CHAIN = (
    "Run focused hermetic tests.",
    "Run every repository skill validator.",
    "Run the full hermetic suite.",
    "Use guarded push with the repository-derived harness gate profile.",
    "Open a source-only pull request against the exact accepted main.",
    "Require current-head CI, zero unresolved review threads, and independent exact-head Governor approval.",
    "Merge only the reviewed and checked exact head into the exact target main.",
    "Require post-merge accepted-main green evidence.",
    "Clean up the retired source lane and isolated test state.",
    "Commit the terminal receipt and release Shared capacity atomically.",
)
HARNESS_SOURCE_HARD_STOPS = (
    "Stop on repository, source, main, scope, capacity, collision, goal, gate, review, CI, or merge drift.",
)


@dataclass(frozen=True)
class RepositoryDeliveryPolicy:
    repository: str
    branch_namespace: str
    worktree_stem: str
    workspace_subdirectory: str | None
    prepush_gate_profile: str
    exclusive_repository_writer: bool


_POLICIES = {
    APPLICATION_REPOSITORY: RepositoryDeliveryPolicy(
        repository=APPLICATION_REPOSITORY,
        branch_namespace="codex",
        worktree_stem="twinfinityapp-issue-",
        workspace_subdirectory=None,
        prepush_gate_profile="application-compose-v1",
        exclusive_repository_writer=False,
    ),
    HARNESS_REPOSITORY: RepositoryDeliveryPolicy(
        repository=HARNESS_REPOSITORY,
        branch_namespace="change",
        worktree_stem="twinfinity-harness-issue",
        workspace_subdirectory="twinfinity",
        prepush_gate_profile="harness-source-v1",
        exclusive_repository_writer=True,
    ),
}


def policy_for_repository(repository: object) -> RepositoryDeliveryPolicy | None:
    """Return only a reviewed exact-identity policy; unknown identities fail closed."""

    return _POLICIES.get(repository) if isinstance(repository, str) else None


def stable_issue_source_sha256(payload: dict[str, object]) -> str:
    """Digest the material issue projection shared with approval effectivity."""

    stable = {
        key: value
        for key, value in payload.items()
        if key != "updated_at" and not key.startswith("_projection_")
    }
    canonical = json.dumps(
        stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def canonical_harness_standing_controls() -> dict[str, object]:
    """Return the closed reviewed controls for every harness source admission."""

    return {
        "source_scope": list(HARNESS_SOURCE_SCOPE),
        "exclusions": list(HARNESS_SOURCE_EXCLUSIONS),
        "writer": HARNESS_SOURCE_WRITER,
        "reviewer_plan": list(HARNESS_SOURCE_REVIEWER_PLAN),
        "collision_proof": list(HARNESS_SOURCE_COLLISION_PROOF),
        "environment_rule": HARNESS_SOURCE_ENVIRONMENT_RULE,
        "routine_chain": list(HARNESS_SOURCE_ROUTINE_CHAIN),
        "hard_stops": list(HARNESS_SOURCE_HARD_STOPS),
    }


def _current_planner_goal_sha256(connection: sqlite3.Connection) -> str | None:
    rows = connection.execute("PRAGMA database_list").fetchall()
    main_rows = [row for row in rows if row[1] == "main"]
    if len(main_rows) != 1 or not isinstance(main_rows[0][2], str):
        return None
    database = Path(main_rows[0][2])
    if not database.is_absolute():
        return None
    goal = database.parent / "product-planner-goal.md"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(goal, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or before.st_size <= 0
            or before.st_size > 1024 * 1024
        ):
            return None
        chunks = []
        remaining = int(before.st_size) + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        raw = b"".join(chunks)
        try:
            path_metadata = goal.lstat()
        except OSError:
            return None
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_size,
            before.st_nlink,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if (
            len(raw) != int(before.st_size)
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_size,
                after.st_nlink,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != stable
            or (
                path_metadata.st_dev,
                path_metadata.st_ino,
                path_metadata.st_mode,
                path_metadata.st_uid,
                path_metadata.st_size,
                path_metadata.st_nlink,
                path_metadata.st_mtime_ns,
                path_metadata.st_ctime_ns,
            )
            != stable
        ):
            return None
        return hashlib.sha256(raw).hexdigest()
    finally:
        os.close(descriptor)


def harness_standing_authority_error(payload: object) -> str | None:
    """Bind harness standing source authority to its exact admission envelope."""

    if not isinstance(payload, dict):
        return "HARNESS_STANDING_AUTHORITY_INVALID"
    source = payload.get("source")
    if not isinstance(source, dict) or source.get("repository") != HARNESS_REPOSITORY:
        return None
    binding = payload.get("standing_source_authority")
    required = {
        "schema",
        "repository",
        "issue_number",
        "source_payload_sha256",
        "stable_source_sha256",
        "planner_goal_sha256",
        "accepted_main_sha",
        "source_scope",
        "exclusions",
        "writer",
        "reviewer_plan",
        "collision_proof",
        "environment_rule",
        "routine_chain",
        "hard_stops",
    }
    if not isinstance(binding, dict) or set(binding) != required:
        return "HARNESS_STANDING_AUTHORITY_INVALID"
    strings = (
        "repository",
        "source_payload_sha256",
        "stable_source_sha256",
        "planner_goal_sha256",
        "accepted_main_sha",
    )
    nonempty_list_fields = (
        "source_scope",
        "reviewer_plan",
        "collision_proof",
        "routine_chain",
        "hard_stops",
    )
    list_fields = (*nonempty_list_fields, "exclusions")
    if (
        binding.get("schema") != HARNESS_STANDING_AUTHORITY_SCHEMA
        or binding.get("repository") != HARNESS_REPOSITORY
        or type(binding.get("issue_number")) is not int
        or binding["issue_number"] <= 0
        or any(not isinstance(binding.get(field), str) for field in strings)
        or not isinstance(binding.get("writer"), str)
        or not binding["writer"].strip()
        or not isinstance(binding.get("environment_rule"), str)
        or not binding["environment_rule"].strip()
        or not re.fullmatch(r"[0-9a-f]{64}", binding["source_payload_sha256"])
        or not re.fullmatch(r"[0-9a-f]{64}", binding["stable_source_sha256"])
        or not re.fullmatch(r"[0-9a-f]{64}", binding["planner_goal_sha256"])
        or not re.fullmatch(r"[0-9a-f]{40}", binding["accepted_main_sha"])
        or any(not isinstance(binding.get(field), list) for field in list_fields)
        or any(not binding[field] for field in nonempty_list_fields)
        or any(
            any(
                not isinstance(value, str) or not value.strip()
                for value in binding[field]
            )
            for field in list_fields
        )
    ):
        return "HARNESS_STANDING_AUTHORITY_INVALID"
    canonical = json.dumps(
        binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    controls = canonical_harness_standing_controls()
    if (
        binding["issue_number"] != payload.get("issue_number")
        or binding["source_payload_sha256"] != source.get("payload_sha256")
        or binding["accepted_main_sha"] != payload.get("base_sha")
        or binding["source_scope"] != payload.get("source_scope")
        or binding["exclusions"] != payload.get("source_exclusions")
        or binding["writer"] != payload.get("writer")
        or binding["reviewer_plan"] != payload.get("reviewer_plan")
        or binding["collision_proof"] != payload.get("collision_proof")
        or binding["environment_rule"] != payload.get("environment_rule")
        or binding["routine_chain"] != payload.get("routine_chain")
        or binding["hard_stops"] != payload.get("hard_stops")
        or any(binding[field] != value for field, value in controls.items())
        or hashlib.sha256(canonical).hexdigest()
        != payload.get("standing_source_authority_sha256")
    ):
        return "HARNESS_STANDING_AUTHORITY_DRIFT"
    return None


def harness_standing_authority_provenance_error(
    connection: sqlite3.Connection, payload: object
) -> str | None:
    """Require one immutable clean-bootstrap goal behind harness authority."""

    error = harness_standing_authority_error(payload)
    if error is not None:
        return error
    if not isinstance(payload, dict):
        return "HARNESS_STANDING_AUTHORITY_INVALID"
    source = payload.get("source")
    if not isinstance(source, dict) or source.get("repository") != HARNESS_REPOSITORY:
        return None
    try:
        rows = connection.execute(
            "SELECT source_harness_repository,approved_goal_sha256 "
            "FROM coordination_bootstrap_provenance"
        ).fetchall()
    except sqlite3.Error:
        return "HARNESS_STANDING_AUTHORITY_PROVENANCE_MISSING"
    if not rows:
        return "HARNESS_STANDING_AUTHORITY_PROVENANCE_MISSING"
    if len(rows) != 1:
        return "HARNESS_STANDING_AUTHORITY_PROVENANCE_AMBIGUOUS"
    binding = payload["standing_source_authority"]
    current_goal_sha256 = _current_planner_goal_sha256(connection)
    current = connection.execute(
        "SELECT snapshots.payload_sha256,snapshots.payload_json "
        "FROM github_current current JOIN github_snapshots snapshots "
        "ON snapshots.repository=current.repository "
        "AND snapshots.object_kind=current.object_kind "
        "AND snapshots.object_number=current.object_number "
        "AND snapshots.payload_sha256=current.payload_sha256 "
        "WHERE current.repository=? AND current.object_kind='issue' "
        "AND current.object_number=?",
        (HARNESS_REPOSITORY, binding["issue_number"]),
    ).fetchone()
    try:
        current_payload = None if current is None else json.loads(current["payload_json"])
    except (TypeError, json.JSONDecodeError):
        current_payload = None
    if (
        rows[0]["source_harness_repository"] != HARNESS_REPOSITORY
        or rows[0]["approved_goal_sha256"] != binding["planner_goal_sha256"]
        or current_goal_sha256 != binding["planner_goal_sha256"]
        or current is None
        or current["payload_sha256"] != binding["source_payload_sha256"]
        or not isinstance(current_payload, dict)
        or stable_issue_source_sha256(current_payload)
        != binding["stable_source_sha256"]
    ):
        return "HARNESS_STANDING_AUTHORITY_PROVENANCE_DRIFT"
    return None


def strict_delivery_branch_matches(
    repository: object, branch: object, *, issue_number: object | None = None
) -> bool:
    """Validate the lease/message branch grammar without caller-selected policy."""

    policy = policy_for_repository(repository)
    if policy is None or not isinstance(branch, str):
        return False
    match = re.fullmatch(
        rf"{re.escape(policy.branch_namespace)}/(?P<issue>[1-9][0-9]*)-"
        r"[a-z0-9][a-z0-9-]*",
        branch,
    )
    return bool(
        match is not None
        and (
            issue_number is None
            or (
                type(issue_number) is int
                and int(match.group("issue")) == issue_number
            )
        )
    )


def delivery_branch_issue_number(repository: object, branch: object) -> int | None:
    """Parse the lane owner while preserving the publication slug grammar."""

    policy = policy_for_repository(repository)
    if policy is None or not isinstance(branch, str):
        return None
    match = re.fullmatch(
        rf"{re.escape(policy.branch_namespace)}/(?P<issue>[1-9][0-9]*)-"
        r"[A-Za-z0-9._-]+",
        branch,
    )
    return int(match.group("issue")) if match is not None else None


def delivery_branch_matches_owning_issue(
    repository: object, branch: object, owning_issue_number: object
) -> bool:
    """Apply only the repository's reviewed issue-ownership branch fence."""

    policy = policy_for_repository(repository)
    if (
        policy is None
        or type(owning_issue_number) is not int
        or owning_issue_number <= 0
        or not strict_delivery_branch_matches(repository, branch)
    ):
        return False
    if policy.repository == HARNESS_REPOSITORY:
        return delivery_branch_issue_number(repository, branch) == owning_issue_number
    return policy.repository == APPLICATION_REPOSITORY


def expected_worktree_identity(repository: object, issue_number: int) -> str | None:
    """Derive the repository-owned worktree identity from repository and issue."""

    policy = policy_for_repository(repository)
    if policy is None or type(issue_number) is not int or issue_number <= 0:
        return None
    return f"{policy.worktree_stem}{issue_number}"


def expected_worktree_parent(
    repository: object, workspace_root: Path
) -> Path | None:
    """Derive the sibling-worktree parent from exact repository identity."""

    policy = policy_for_repository(repository)
    if policy is None or not workspace_root.is_absolute():
        return None
    if policy.workspace_subdirectory is None:
        return workspace_root
    return workspace_root / policy.workspace_subdirectory


def expected_canonical_checkout(
    repository: object, workspace_root: Path
) -> Path | None:
    """Derive the canonical checkout paired with the repository's worktrees."""

    parent = expected_worktree_parent(repository, workspace_root)
    if parent is None or not isinstance(repository, str):
        return None
    return parent / repository.split("/", 1)[1]


def worktree_path_matches_owning_issue(
    repository: object, worktree_path: object, owning_issue_number: object
) -> bool:
    """Apply the harness basename fence without changing application transfers."""

    policy = policy_for_repository(repository)
    if (
        policy is None
        or type(owning_issue_number) is not int
        or owning_issue_number <= 0
        or not isinstance(worktree_path, str)
    ):
        return False
    if policy.repository == APPLICATION_REPOSITORY:
        return True
    expected = expected_worktree_identity(repository, owning_issue_number)
    if expected is None:
        return False
    name = Path(worktree_path).name
    return bool(
        name == expected
        or re.fullmatch(rf"{re.escape(expected)}-[a-z0-9][a-z0-9-]*", name)
    )


def message_worktree_identity_matches(
    repository: object,
    worktree_path: object,
    opaque_worktree_id: object,
    owning_issue_number: object,
) -> bool:
    """Bind harness message identity to its exact issue-owned basename."""

    if not worktree_path_matches_owning_issue(
        repository, worktree_path, owning_issue_number
    ):
        return False
    if repository == HARNESS_REPOSITORY:
        return (
            isinstance(worktree_path, str)
            and isinstance(opaque_worktree_id, str)
            and opaque_worktree_id == Path(worktree_path).name
        )
    return repository == APPLICATION_REPOSITORY


def worktree_identity_matches(
    repository: object,
    *,
    surface_issue_number: int,
    owning_issue_number: int,
    generation: int,
    worktree_path: object,
    opaque_worktree_id: object,
) -> bool:
    """Validate a same-issue worktree without weakening the application contract."""

    policy = policy_for_repository(repository)
    expected = expected_worktree_identity(repository, surface_issue_number)
    if (
        policy is None
        or expected is None
        or surface_issue_number != owning_issue_number
        or type(owning_issue_number) is not int
        or owning_issue_number <= 0
        or type(generation) is not int
        or generation < 0
        or not isinstance(worktree_path, str)
        or not isinstance(opaque_worktree_id, str)
    ):
        return False
    name = Path(worktree_path).name
    if policy.repository == APPLICATION_REPOSITORY:
        canonical = name == expected and opaque_worktree_id == expected
        versioned = bool(
            re.fullmatch(rf"{re.escape(expected)}-v[1-9][0-9]*", name)
            and opaque_worktree_id
            == f"issue-{owning_issue_number}-generation-{generation}"
        )
        return canonical or versioned
    if policy.repository == HARNESS_REPOSITORY:
        harness_owned = bool(
            name == expected
            or re.fullmatch(rf"{re.escape(expected)}-[a-z0-9][a-z0-9-]*", name)
        )
        return harness_owned and opaque_worktree_id == name
    return False
