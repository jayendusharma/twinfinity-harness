"""Test-side construction of a canonical PASS-to-READY lineage.

This helper has no synthetic production gateway.  It exercises the same
prepared-candidate, readiness attempt, immutable receipt, Planner continuation,
and atomic finalizer APIs used by the owner control plane.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch
from typing import Any

from coordination_store import CoordinationStore, canonical_json
from executor_registry import (
    attempt_lineage_for_target,
    current_endpoint,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from kanban_pull_buffer import finalize_ready, register_candidate
from kanban_readiness import (
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    SUCCESSOR_PLAN_SCHEMA,
    attach,
    dispatch,
    pickup_receipt,
    register,
    stage_receipt,
    transition_evidence_sha256,
)


def finalize_canonical_ready_candidate(
    store: CoordinationStore,
    *,
    database: Path,
    artifact_root: Path,
    prepared_packet: dict[str, Any],
    admission_transaction: dict[str, Any],
    worker_role: str,
    worker_endpoint_id: str,
    now: str,
    suffix: str,
    refresh: bool = False,
) -> dict[str, Any]:
    """Create one real PASS receipt and atomically finalize its READY packet."""

    repository = str(prepared_packet["repository"])
    issue_number = int(prepared_packet["issue_number"])
    generation = int(prepared_packet["generation"])
    item_version = int(prepared_packet["item_version_at_preparation"])
    plans = artifact_root / "plans"
    plans.mkdir(exist_ok=True)
    prepared_path = plans / f"issue-{issue_number}-{suffix}-prepared.json"
    prepared_path.write_text(canonical_json(prepared_packet), encoding="utf-8")
    store.register_artifacts(
        [
            {
                "repository": repository,
                "issue_number": issue_number,
                "generation": generation,
                "path": str(prepared_path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }
        ],
        now=now,
    )
    register_candidate(store.connection, database, prepared_path, now=now)
    prepared = store.connection.execute(
        """
        SELECT candidate.* FROM portfolio_pull_buffer_current pointer
        JOIN portfolio_pull_buffer_candidates candidate
          ON candidate.id=pointer.candidate_id
        WHERE pointer.repository=? AND pointer.issue_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    if prepared is None or prepared["state"] != "PREPARED_NOT_READY":
        raise AssertionError("canonical prepared candidate missing")

    plan = {
        "schema": PLAN_SCHEMA,
        "repository": repository,
        "issue_number": issue_number,
        "generation": generation,
        "item_version": item_version,
        "source_payload_sha256": prepared_packet["source_payload_sha256"],
        "accepted_main_sha": prepared_packet["accepted_main_at_preparation"],
        "graph_version": int(prepared_packet["portfolio_graph_version"]),
        "capacity_policy_version": int(
            prepared_packet["capacity_policy"]["version"]
        ),
        "candidate_sha256": prepared["candidate_sha256"],
        "worker_role": worker_role,
        "phase_summary": "Complete one canonical all-gates test readiness phase.",
        "gates": [
            {
                "gate_key": "complete-review",
                "description": "All exact candidate bindings are current.",
                "requested_evidence": ["One immutable PASS receipt"],
            }
        ],
    }
    if refresh:
        parent = store.connection.execute(
            "SELECT current.campaign_id,current.version,campaign.plan_json "
            "FROM portfolio_readiness_current current "
            "JOIN portfolio_readiness_campaigns campaign "
            "ON campaign.id=current.campaign_id "
            "WHERE current.repository=? AND current.issue_number=? "
            "AND current.state='STALE'",
            (repository, issue_number),
        ).fetchone()
        if parent is None:
            raise AssertionError("canonical REFRESH fixture requires STALE readiness")
        parent_plan = json.loads(parent["plan_json"])
        plan["schema"] = SUCCESSOR_PLAN_SCHEMA
        plan["transition"] = {
            "kind": "REFRESH",
            "parent_campaign_id": int(parent["campaign_id"]),
            "expected_parent_version": int(parent["version"]),
            "changed_evidence_sha256": "0" * 64,
            "resolution_action_set_sha256": None,
            "approval": None,
        }
        plan["transition"]["changed_evidence_sha256"] = (
            transition_evidence_sha256(parent_plan, plan)
        )
    campaign = register(store.connection, plan, now=now)
    dispatched = dispatch(store, repository, max_parallel=1, now=now)[
        "dispatched"
    ]
    if len(dispatched) != 1 or int(dispatched[0]["issue_number"]) != issue_number:
        raise AssertionError("canonical readiness dispatch selected wrong candidate")
    message_id = int(dispatched[0]["message_id"])
    if dispatched[0]["endpoint_id"] != worker_endpoint_id:
        raise AssertionError("canonical readiness endpoint mismatch")

    reserved, executor_token = reserve_attempt(
        store.connection,
        role=worker_role,
        endpoint_id=worker_endpoint_id,
        target_kind="message",
        target_key=str(message_id),
        now=now,
        precondition=lambda connection: attempt_lineage_for_target(
            connection, "message", str(message_id)
        ),
    )
    unit = stable_systemd_unit(worker_role, "message", str(message_id))
    invocation = hashlib.md5(
        f"canonical-ready:{repository}:{issue_number}:{message_id}".encode()
    ).hexdigest()
    launching = transition_attempt(
        store.connection,
        attempt_id=str(reserved["attempt_id"]),
        token=executor_token,
        expected_version=int(reserved["version"]),
        new_state="LAUNCHING",
        systemd_unit=unit,
        systemd_invocation_id=invocation,
        systemd_control_group=f"/user.slice/{unit}",
        now=now,
    )
    running = transition_attempt(
        store.connection,
        attempt_id=str(reserved["attempt_id"]),
        token=executor_token,
        expected_version=int(launching["version"]),
        new_state="RUNNING",
        process_id=9000 + issue_number,
        now=now,
    )
    store.claim_message(message_id, worker_endpoint_id, now)
    attach(
        store.connection,
        repository,
        issue_number,
        message_id,
        str(running["attempt_id"]),
        now=now,
    )
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "repository": repository,
        "issue_number": issue_number,
        "readiness_plan_sha256": campaign["plan_sha256"],
        "verdict": "PASS",
        "worker_role": worker_role,
        "message_id": message_id,
        "attempt_id": str(running["attempt_id"]),
        "gate_results": [
            {
                "gate_key": "complete-review",
                "verdict": "PASS",
                "evidence_sha256": hashlib.sha256(
                    f"canonical-pass:{campaign['plan_sha256']}".encode()
                ).hexdigest(),
                "summary": "Every frozen readiness gate passed.",
            }
        ],
        "resolution": {"role": None, "actions": [], "approval": None},
        "summary": "Canonical test evidence permits atomic READY finalization.",
        "observed_at": now,
    }
    receipt_path = artifact_root / (
        f"issue-{issue_number}-{suffix}-readiness-receipt.json"
    )
    receipt_path.write_text(canonical_json(receipt), encoding="utf-8")
    receipt_path.chmod(0o600)
    with patch.dict(os.environ, {"TWINFINITY_EXECUTOR_TOKEN": executor_token}):
        stage_receipt(
            store.connection,
            database,
            receipt_path,
            message_id=message_id,
            attempt_id=str(running["attempt_id"]),
            now=now,
        )
    store.complete_message(message_id, worker_endpoint_id, now)
    transition_attempt(
        store.connection,
        attempt_id=str(running["attempt_id"]),
        token=executor_token,
        expected_version=int(running["version"]),
        new_state="COMPLETE",
        exit_code=0,
        now=now,
    )
    recorded = pickup_receipt(store, int(campaign["campaign_id"]), now=now)
    planner = current_endpoint(store.connection, "planner")
    if planner is None:
        raise AssertionError("current Planner endpoint missing")
    planner_message_id = int(recorded["planner_message_id"])
    store.claim_message(planner_message_id, str(planner["endpoint_id"]), now)
    store.complete_message(planner_message_id, str(planner["endpoint_id"]), now)

    phase = store.connection.execute(
        """
        SELECT current.*, receipt.receipt_sha256
        FROM portfolio_readiness_current current
        JOIN portfolio_readiness_receipts receipt ON receipt.id=current.receipt_id
        WHERE current.repository=? AND current.issue_number=?
        """,
        (repository, issue_number),
    ).fetchone()
    ready_packet = {
        **prepared_packet,
        "schema": "twinfinity-kanban-pull-buffer/v3",
        "state": "READY",
        "admission_transaction": admission_transaction,
        "prepared_candidate": {
            "candidate_id": int(prepared["id"]),
            "candidate_sha256": prepared["candidate_sha256"],
        },
        "readiness_binding": {
            "campaign_id": int(campaign["campaign_id"]),
            "current_version": int(phase["version"]),
            "plan_sha256": campaign["plan_sha256"],
            "receipt_id": int(phase["receipt_id"]),
            "receipt_sha256": phase["receipt_sha256"],
        },
    }
    ready_path = plans / f"issue-{issue_number}-{suffix}-ready.json"
    ready_path.write_text(canonical_json(ready_packet), encoding="utf-8")
    store.register_artifacts(
        [
            {
                "repository": repository,
                "issue_number": issue_number,
                "generation": generation,
                "path": str(ready_path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }
        ],
        now=now,
    )
    finalized = finalize_ready(store, ready_path, now=now)
    current_item = dict(
        store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (repository, issue_number),
        ).fetchone()
    )
    return {
        "prepared_path": prepared_path,
        "ready_path": ready_path,
        "prepared_candidate_id": int(prepared["id"]),
        "campaign_id": int(campaign["campaign_id"]),
        "message_id": message_id,
        "finalized": finalized,
        "item": current_item,
    }


def finalize_canonical_ready_item(
    store: CoordinationStore,
    *,
    database: Path,
    artifact_root: Path,
    repository: str,
    issue_number: int,
    source_payload_sha256: str,
    accepted_main_sha: str,
    worker_role: str,
    worker_endpoint_id: str,
    now: str,
    suffix: str,
    refresh: bool = False,
) -> dict[str, Any]:
    """Finalize one existing PREPARED/QUEUED item through the canonical path."""

    item_row = store.connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (repository, issue_number),
    ).fetchone()
    graph = store.connection.execute(
        "SELECT * FROM portfolio_graph_current WHERE repository=?",
        (repository,),
    ).fetchone()
    if item_row is None or item_row["status"] not in {"PREPARED", "QUEUED"}:
        raise AssertionError("canonical READY fixture requires PREPARED or QUEUED item")
    if graph is None or graph["health"] != "CURRENT":
        raise AssertionError("canonical READY fixture requires current portfolio graph")
    item = dict(item_row)
    policy = store.capacity_policy(repository, now=now)
    units = {
        "development_units": int(item["development_units"]),
        "shared_units": int(item["shared_units"]),
        "sre_units": int(item["sre_units"]),
    }
    topic = "sre.admission" if worker_role == "sre" else "development.admission"
    plans = artifact_root / "plans"
    plans.mkdir(exist_ok=True)
    branch = f"codex/{issue_number}-{suffix}"
    worktree = f"/home/ubuntu/code/twinfinityapp-issue-{issue_number}-{suffix}"
    lease_path = plans / f"issue-{issue_number}-{suffix}-lease.json"
    lease_payload = {
        "repository": repository,
        "issue_number": issue_number,
        "generation": int(item["generation"]),
        "base_sha": accepted_main_sha,
        "branch": branch,
        "worktree_path": worktree,
        "no_additional_paths": True,
        "paths": [
            {
                "path": f"canonical-ready/issue-{issue_number}-{suffix}.py",
                "mode": "100644",
                "type": "blob",
                "sha": hashlib.sha1(
                    f"{repository}:{issue_number}:{suffix}".encode()
                ).hexdigest(),
            }
        ],
    }
    lease_path.write_text(
        json.dumps(lease_payload, sort_keys=True) + "\n", encoding="utf-8"
    )
    lease_sha = hashlib.sha256(lease_path.read_bytes()).hexdigest()
    admission_payload = {
        "source": {
            "repository": repository,
            "object_kind": "issue",
            "object_number": issue_number,
            "payload_sha256": source_payload_sha256,
        },
        "issue_number": issue_number,
        "generation": int(item["generation"]),
        "item_version": int(item["version"]) + 2,
        "base_sha": accepted_main_sha,
        "branch": branch,
        "worktree_path": worktree,
        "opaque_worktree_id": f"canonical-ready-{issue_number}-{suffix}",
        "accountable_session_id": worker_endpoint_id,
        "lease_manifest_sha256": lease_sha,
        "authority_sha256": hashlib.sha256(
            f"authority:{repository}:{issue_number}:{suffix}".encode()
        ).hexdigest(),
        "capacity": units,
        "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
    }
    if topic == "development.admission":
        admission_payload.update(
            {
                "writer": f"issue-{issue_number}-canonical-ready-writer",
                "reviewer_plan": ["Independent exact-head review."],
                "collision_proof": ["The canonical fixture lease is disjoint."],
                "environment_rule": "Use only the issue-owned environment.",
                "routine_chain": ["Run bounded gates and routine closeout."],
                "hard_stops": ["Stop on source, lease, or capacity drift."],
            }
        )
    prepared_packet = {
        "schema": "twinfinity-kanban-pull-buffer/v2",
        "repository": repository,
        "issue_number": issue_number,
        "generation": int(item["generation"]),
        "item_version_at_preparation": int(item["version"]),
        "source_payload_sha256": source_payload_sha256,
        "accepted_main_at_preparation": accepted_main_sha,
        "portfolio_graph_version": int(graph["version"]),
        "state": "PREPARED_NOT_READY",
        "verticality": "END_TO_END",
        "owner_visible_outcome": f"Deliver canonical fixture issue {issue_number}.",
        "capacity_policy": {
            "version": int(policy["version"]),
            "development_limit": int(policy["development_limit"]),
            "shared_limit": int(policy["shared_limit"]),
            "sre_limit": int(policy["sre_limit"]),
        },
        "capacity_on_activation": units,
        "precomputed_collision_matrix": [
            {
                "other_issue": 999999,
                "disposition": "DISJOINT",
                "reason": "Canonical fixture paths are issue-specific.",
            }
        ],
        "preparation_complete": ["The canonical admission envelope is complete."],
        "promotion_checks_after_predecessor": ["Revalidate every local guard."],
        "hard_stops": ["Stop on any controlling-state drift."],
        "promotion_trigger": "All canonical readiness gates pass.",
    }
    admission_transaction = {
        "item": {
            "repository": repository,
            "issue_number": issue_number,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": int(item["generation"]),
            "accountable_session_id": worker_endpoint_id,
            "lease_manifest_sha256": lease_sha,
            **units,
            "expected_source_sha256": source_payload_sha256,
            "expected_version": int(item["version"]) + 1,
        },
        "message": {
            "idempotency_key": f"canonical-ready-{issue_number}-{suffix}",
            "recipient_session_id": worker_endpoint_id,
            "topic": topic,
            "payload": admission_payload,
        },
        "artifacts": [
            {
                "repository": repository,
                "issue_number": issue_number,
                "generation": int(item["generation"]),
                "path": str(lease_path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }
        ],
    }
    return finalize_canonical_ready_candidate(
        store,
        database=database,
        artifact_root=artifact_root,
        prepared_packet=prepared_packet,
        admission_transaction=admission_transaction,
        worker_role=worker_role,
        worker_endpoint_id=worker_endpoint_id,
        now=now,
        suffix=suffix,
        refresh=refresh,
    )
