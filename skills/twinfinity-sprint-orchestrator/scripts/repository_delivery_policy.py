#!/usr/bin/env python3
"""Fail-closed branch and worktree policy derived from repository identity."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


APPLICATION_REPOSITORY = "twinfinityai/twinfinityapp"
HARNESS_REPOSITORY = "jayendusharma/twinfinity-harness"


@dataclass(frozen=True)
class RepositoryDeliveryPolicy:
    repository: str
    branch_namespace: str
    worktree_stem: str
    workspace_subdirectory: str | None


_POLICIES = {
    APPLICATION_REPOSITORY: RepositoryDeliveryPolicy(
        repository=APPLICATION_REPOSITORY,
        branch_namespace="codex",
        worktree_stem="twinfinityapp-issue-",
        workspace_subdirectory=None,
    ),
    HARNESS_REPOSITORY: RepositoryDeliveryPolicy(
        repository=HARNESS_REPOSITORY,
        branch_namespace="change",
        worktree_stem="twinfinity-harness-issue",
        workspace_subdirectory="twinfinity",
    ),
}


def policy_for_repository(repository: object) -> RepositoryDeliveryPolicy | None:
    """Return only a reviewed exact-identity policy; unknown identities fail closed."""

    return _POLICIES.get(repository) if isinstance(repository, str) else None


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
