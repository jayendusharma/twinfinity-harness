"""Deterministic shape-valid delivery identities for readiness unit tests."""

from __future__ import annotations

from pathlib import Path

from delivery_identity import DELIVERY_IDENTITY_SCHEMA, delivery_identity_sha256
from repository_delivery_policy import (
    expected_worktree_identity,
    expected_worktree_parent,
    policy_for_repository,
)


def synthetic_delivery_identity(
    repository: str, issue_number: int, generation: int
) -> tuple[dict, str]:
    policy = policy_for_repository(repository)
    identity_name = expected_worktree_identity(repository, issue_number)
    parent = expected_worktree_parent(repository, Path("/home/ubuntu/code"))
    if policy is None or identity_name is None or parent is None:
        raise AssertionError("synthetic delivery repository unsupported")
    identity = {
        "schema": DELIVERY_IDENTITY_SCHEMA,
        "repository": repository,
        "issue_number": issue_number,
        "generation": generation,
        "lease_manifest_sha256": "1" * 64,
        "branch": f"{policy.branch_namespace}/{issue_number}-synthetic-readiness",
        "worktree_path": str(parent / identity_name),
        "opaque_worktree_id": identity_name,
        "admission_execution_scope_sha256": "2" * 64,
        "admission_transaction_sha256": "3" * 64,
    }
    return identity, delivery_identity_sha256(identity)
