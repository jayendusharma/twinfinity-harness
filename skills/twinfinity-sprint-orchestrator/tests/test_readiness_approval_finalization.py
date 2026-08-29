from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
)
from delivery_identity import (  # noqa: E402
    bind_delivery_identity,
    delivery_identity_sha256,
)
from approval_guard import readiness_execution_scope_sha256  # noqa: E402
from approval_ledger import (  # noqa: E402
    claim_decision,
    create_review_batch,
    ensure_schema as ensure_approval_schema,
    record_decision,
    revoke_decision,
    submit_readiness_proposal_in_transaction,
)
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    PullBufferError,
    READY_SCHEMA,
    admission_binding_error,
    audit_pull_buffer,
    close_candidate_observations,
    load_candidate_packets,
    finalize_ready,
    ensure_pull_buffer_schema,
    register_candidate,
)
from kanban_readiness import (  # noqa: E402
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    ReadinessError,
    attach as attach_readiness,
    discover as discover_readiness,
    dispatch as dispatch_readiness,
    ensure_schema as ensure_readiness_schema,
    evaluate as evaluate_readiness,
    pickup_receipt as pickup_readiness_receipt,
    register as register_readiness,
    stage_receipt as stage_readiness_receipt,
)
from portfolio_convergence import (  # noqa: E402
    PortfolioConvergence,
    PortfolioConvergenceError,
)
from portfolio_graph import (  # noqa: E402
    PortfolioGraphError,
    enqueue_convergence_dirty_event,
    replace_graph,
)
from executor_registry import load_registry_config  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from tests.reviewed_endpoint_catalog_fixture import (  # noqa: E402
    reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
DEVELOPMENT_SESSION = "role.development.v4"


class ReadinessApprovalFinalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "coordinator"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        skill_root = Path(__file__).resolve().parents[1]
        self.current_catalog = reviewed_current_endpoint_catalog(
            skill_root, Path(self.temp.name)
        )
        config = self.current_catalog.__enter__()
        aliases, alias_sha = load_legacy_alias_fixture(
            skill_root / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="portfolio-convergence-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T09:59:59Z",
        )
        self.sources = {number: self._snapshot(number) for number in (1, 2)}
        self.release_item = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=1,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.sources[1],
            expected_version=0,
            now="2026-08-24T10:00:01Z",
        )
        self.ready_item = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=2,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.sources[2],
            expected_version=0,
            now="2026-08-24T10:00:01Z",
        )
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Sprint", "rank": 1}],
                "excluded_issues": [],
                "nodes": [self._node(1, 1), self._node(2, 2)],
                "relations": [],
            },
            now="2026-08-24T10:00:02Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.current_catalog.__exit__(None, None, None)
        self.temp.cleanup()

    def _snapshot(self, number: int) -> str:
        return self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=number,
            payload={
                "_projection_version": 3,
                "number": number,
                "title": f"Issue {number}",
                "state": "open",
                "updated_at": "2026-08-24T10:00:00Z",
                "milestone": {"number": 1, "title": "Sprint", "state": "open"},
            },
            source_updated_at="2026-08-24T10:00:00Z",
            fetched_at="2026-08-24T10:00:00Z",
        ).payload_sha256

    def _node(self, number: int, priority: int) -> dict:
        return {
            "node_key": f"issue:{number}",
            "issue_number": number,
            "role": "DELIVERY",
            "root_kind": "STANDALONE",
            "root_reason": "Independent test outcome",
            "lane_key": f"lane-{number}",
            "lane_order": 0,
            "dispatchable": True,
            "priority_rank": priority,
            "estimate_units": 1,
            "development_units": 1,
            "shared_units": 0,
            "sre_units": 0,
            "source_payload_sha256": self.sources[number],
            "ready_at": "2026-08-24T10:00:00Z",
        }

    def _release_predecessor(self, now: str) -> None:
        self.release_item = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=1,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=0,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.sources[1],
            expected_version=int(self.release_item["version"]),
            now=now,
        )

    def _delivery_snapshot(self) -> tuple:
        tables = (
            "coordination_items",
            "coordination_messages",
            "coordination_terminal_watches",
            "coordination_events",
            "coordination_artifacts",
            "portfolio_readiness_current",
            "portfolio_ready_finalizations",
        )
        return (
            self.store.connection.total_changes,
            *(
                tuple(
                    tuple(row)
                    for row in self.store.connection.execute(
                        f"SELECT * FROM {table} ORDER BY rowid"
                    ).fetchall()
                )
                for table in tables
            ),
        )

    def _register_ready_candidate(
        self,
        *,
        existing_lease: bool = False,
        finalize: bool = True,
        failpoint=None,
        packet_mutator=None,
        receipt_mutator=None,
    ) -> Path:
        plans = self.root / "plans"
        plans.mkdir(exist_ok=True)
        prepared_packet = {
            "schema": "twinfinity-kanban-pull-buffer/v2",
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "item_version_at_preparation": self.ready_item["version"],
            "source_payload_sha256": self.sources[2],
            "accepted_main_at_preparation": MAIN,
            "portfolio_graph_version": 1,
            "state": "PREPARED_NOT_READY",
            "verticality": "END_TO_END",
            "owner_visible_outcome": "Deliver the next safe owner-visible slice.",
            "capacity_policy": {
                "version": 1,
                "development_limit": 5,
                "shared_limit": 2,
                "sre_limit": 5,
            },
            "capacity_on_activation": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "precomputed_collision_matrix": [
                {
                    "other_issue": 1,
                    "disposition": "DISJOINT",
                    "reason": "The predecessor lease is released.",
                }
            ],
            "preparation_complete": ["The bounded candidate is prepared."],
            "promotion_checks_after_predecessor": ["Run one readiness phase."],
            "hard_stops": ["Stop on any binding drift."],
            "promotion_trigger": "Pass one all-gates readiness phase.",
        }
        prepared_path = plans / "issue-2-prepared.json"
        prepared_path.write_text(
            json.dumps(prepared_packet, sort_keys=True), encoding="utf-8"
        )
        self.store.register_artifacts(
            [{
                "repository": REPOSITORY,
                "issue_number": 2,
                "generation": 1,
                "path": str(prepared_path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }],
            now="2026-08-24T10:00:02Z",
        )
        register_candidate(
            self.store.connection,
            self.database,
            prepared_path,
            now="2026-08-24T10:00:02Z",
        )
        prepared = self.store.connection.execute(
            """
            SELECT candidate.* FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=pointer.candidate_id
            WHERE pointer.repository=? AND pointer.issue_number=2
            """,
            (REPOSITORY,),
        ).fetchone()
        lease_path = plans / "issue-2-lease.json"
        lease_payload = {
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "base_sha": MAIN,
            "branch": "codex/2-ready-successor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-2",
            "no_additional_paths": True,
            "paths": [{
                "path": "backend/successor.py",
                "mode": "100644",
                "type": "blob",
                "sha": "b" * 40,
            }],
        }
        lease_path.write_text(
            json.dumps(lease_payload, sort_keys=True) + "\n", encoding="utf-8"
        )
        lease_sha = hashlib.sha256(lease_path.read_bytes()).hexdigest()
        lease_artifacts = [{
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "path": str(lease_path),
            "retention_class": "CLOSEOUT_EVIDENCE",
        }]
        item = {
            "repository": REPOSITORY,
            "issue_number": 2,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": 1,
            "accountable_session_id": DEVELOPMENT_SESSION,
            "lease_manifest_sha256": lease_sha,
            "development_units": 1,
            "shared_units": 0,
            "sre_units": 0,
            "expected_source_sha256": self.sources[2],
            "expected_version": self.ready_item["version"] + 1,
        }
        message = {
            "idempotency_key": "portfolio-convergence-issue-2",
            "recipient_session_id": DEVELOPMENT_SESSION,
            "topic": "development.admission",
            "payload": {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 2,
                    "payload_sha256": self.sources[2],
                },
                "issue_number": 2,
                "generation": 1,
                "item_version": self.ready_item["version"] + 2,
                "base_sha": MAIN,
                "branch": "codex/2-ready-successor",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-2",
                "opaque_worktree_id": "twinfinityapp-issue-2",
                "accountable_session_id": DEVELOPMENT_SESSION,
                "writer": "issue-2-accountable-writer",
                "reviewer_plan": ["Different-session exact-head review."],
                "collision_proof": ["The closed lease is disjoint from active work."],
                "environment_rule": "Use only an issue-owned environment.",
                "routine_chain": [
                    "Implement and run the issue-owned gates.",
                    "Publish only through the guarded closeout chain.",
                ],
                "hard_stops": [
                    "Stop on source, graph, lease, capacity, or authority drift."
                ],
                "lease_manifest_sha256": lease_sha,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 0,
                    "sre_units": 0,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
        }
        prospective_admission = {
            "item": item,
            "message": message,
            **({} if existing_lease else {"artifacts": lease_artifacts}),
        }
        delivery_identity = bind_delivery_identity(prospective_admission)
        delivery_identity_digest = delivery_identity_sha256(delivery_identity)
        readiness_plan = {
            "schema": PLAN_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "item_version": int(self.ready_item["version"]),
            "source_payload_sha256": self.sources[2],
            "accepted_main_sha": MAIN,
            "graph_version": 1,
            "capacity_policy_version": 1,
            "candidate_sha256": prepared["candidate_sha256"],
            "worker_role": "development",
            "phase_summary": "Complete one all-gates readiness phase.",
            "delivery_identity": delivery_identity,
            "delivery_identity_sha256": delivery_identity_digest,
            "gates": [{
                "gate_key": "complete-review",
                "description": "All readiness evidence is current.",
                "requested_evidence": ["One exact PASS receipt"],
            }],
        }
        campaign = register_readiness(
            self.store.connection, readiness_plan, now="2026-08-24T10:00:02Z"
        )
        dispatched = dispatch_readiness(
            self.store,
            REPOSITORY,
            max_parallel=1,
            now="2026-08-24T10:00:02Z",
        )["dispatched"][0]
        message_id = int(dispatched["message_id"])
        attempt_id = "22222222-2222-4222-8222-222222222222"
        executor_token = "portfolio-convergence-readiness-token"
        self.store.claim_message(
            message_id, DEVELOPMENT_SESSION, "2026-08-24T10:00:02Z"
        )
        with self.store.transaction():
            self.store.connection.execute(
                """
                INSERT INTO executor_attempts(
                    attempt_id, role, endpoint_id, instance_id, token_sha256,
                    target_kind, target_key, state, process_id, exit_code,
                    heartbeat_at, version, created_at, updated_at
                ) VALUES (?, 'development', ?, 'readiness-test', ?, 'message', ?,
                          'RUNNING', 8002, NULL, ?, 1, ?, ?)
                """,
                (
                    attempt_id, DEVELOPMENT_SESSION,
                    hashlib.sha256(executor_token.encode()).hexdigest(),
                    str(message_id),
                    "2026-08-24T10:00:02Z", "2026-08-24T10:00:02Z",
                    "2026-08-24T10:00:02Z",
                ),
            )
        attach_readiness(
            self.store.connection,
            REPOSITORY,
            2,
            message_id,
            attempt_id,
            now="2026-08-24T10:00:02Z",
        )
        receipt = {
                "schema": RECEIPT_SCHEMA,
                "repository": REPOSITORY,
                "issue_number": 2,
                "readiness_plan_sha256": campaign["plan_sha256"],
                "delivery_identity_sha256": delivery_identity_digest,
                "verdict": "PASS",
                "worker_role": "development",
                "message_id": message_id,
                "attempt_id": attempt_id,
                "gate_results": [{
                    "gate_key": "complete-review",
                    "verdict": "PASS",
                    "evidence_sha256": "e" * 64,
                    "summary": "Every gate passed.",
                }],
                "resolution": {
                    "role": None,
                    "actions": [],
                    "approval": None,
                },
                "summary": "The candidate is ready for atomic finalization.",
                "observed_at": "2026-08-24T10:00:02Z",
            }
        if receipt_mutator is not None:
            receipt_mutator(receipt)
        draft = self.root / "readiness-receipt-2.json"
        draft.write_text(canonical_json(receipt), encoding="utf-8")
        draft.chmod(0o600)
        with patch.dict(
            os.environ, {"TWINFINITY_EXECUTOR_TOKEN": executor_token}
        ):
            stage_readiness_receipt(
                self.store.connection, self.database, draft,
                message_id=message_id, attempt_id=attempt_id,
                now="2026-08-24T10:00:02Z",
            )
        self.store.complete_message(
            message_id, DEVELOPMENT_SESSION, "2026-08-24T10:00:02Z"
        )
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE executor_attempts SET state='COMPLETE', exit_code=0, "
                "version=version+1, updated_at=? WHERE attempt_id=?",
                ("2026-08-24T10:00:02Z", attempt_id),
            )
        recorded = pickup_readiness_receipt(
            self.store, int(campaign["campaign_id"]),
            now="2026-08-24T10:00:02Z",
        )
        planner_endpoint = self.store.connection.execute(
            "SELECT endpoint_id FROM executor_role_endpoint_current WHERE role='planner'"
        ).fetchone()[0]
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_messages SET state='COMPLETE', claimed_by=?, "
                "updated_at=? WHERE id=?",
                (
                    planner_endpoint, "2026-08-24T10:00:02Z",
                    int(recorded["planner_message_id"]),
                ),
            )
        phase = self.store.connection.execute(
            """
            SELECT current.*, receipt.receipt_sha256
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_receipts receipt ON receipt.id=current.receipt_id
            WHERE current.repository=? AND current.issue_number=2
            """,
            (REPOSITORY,),
        ).fetchone()
        lease_path = plans / "issue-2-lease.json"
        lease_payload = {
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "base_sha": MAIN,
            "branch": "codex/2-ready-successor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-2",
            "no_additional_paths": True,
            "paths": [
                {
                    "path": "backend/successor.py",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "b" * 40,
                }
            ],
        }
        lease_path.write_text(
            json.dumps(lease_payload, sort_keys=True) + "\n", encoding="utf-8"
        )
        lease_sha = hashlib.sha256(lease_path.read_bytes()).hexdigest()
        lease_artifacts = [
            {
                "repository": REPOSITORY,
                "issue_number": 2,
                "generation": 1,
                "path": str(lease_path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }
        ]
        if existing_lease:
            self.store.register_artifacts(
                lease_artifacts,
                now="2026-08-24T10:00:02Z",
            )
        item = {
            "repository": REPOSITORY,
            "issue_number": 2,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": 1,
            "accountable_session_id": DEVELOPMENT_SESSION,
            "lease_manifest_sha256": lease_sha,
            "development_units": 1,
            "shared_units": 0,
            "sre_units": 0,
            "expected_source_sha256": self.sources[2],
            "expected_version": self.ready_item["version"] + 1,
        }
        message = {
            "idempotency_key": "portfolio-convergence-issue-2",
            "recipient_session_id": DEVELOPMENT_SESSION,
            "topic": "development.admission",
            "payload": {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 2,
                    "payload_sha256": self.sources[2],
                },
                "issue_number": 2,
                "generation": 1,
                "item_version": self.ready_item["version"] + 2,
                "base_sha": MAIN,
                "branch": "codex/2-ready-successor",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-2",
                "opaque_worktree_id": "twinfinityapp-issue-2",
                "accountable_session_id": DEVELOPMENT_SESSION,
                "writer": "issue-2-accountable-writer",
                "reviewer_plan": ["Different-session exact-head review."],
                "collision_proof": ["The closed lease is disjoint from active work."],
                "environment_rule": "Use only an issue-owned environment.",
                "routine_chain": [
                    "Implement and run the issue-owned gates.",
                    "Publish only through the guarded closeout chain.",
                ],
                "hard_stops": [
                    "Stop on source, graph, lease, capacity, or authority drift."
                ],
                "lease_manifest_sha256": lease_sha,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 0,
                    "sre_units": 0,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
        }
        admission_transaction = {
            "item": item,
            "message": message,
            **({} if existing_lease else {"artifacts": lease_artifacts}),
        }
        if bind_delivery_identity(admission_transaction) != delivery_identity:
            raise AssertionError("prospective delivery identity drifted before READY")
        packet = {
            "schema": READY_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "item_version_at_preparation": self.ready_item["version"],
            "source_payload_sha256": self.sources[2],
            "accepted_main_at_preparation": MAIN,
            "portfolio_graph_version": 1,
            "state": "READY",
            "verticality": "END_TO_END",
            "owner_visible_outcome": "Deliver the next safe owner-visible slice.",
            "capacity_policy": {
                "version": 1,
                "development_limit": 5,
                "shared_limit": 2,
                "sre_limit": 5,
            },
            "capacity_on_activation": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "precomputed_collision_matrix": [
                {
                    "other_issue": 1,
                    "disposition": "DISJOINT",
                    "reason": "The predecessor lease is released.",
                }
            ],
            "preparation_complete": ["The reviewed admission packet is complete."],
            "promotion_checks_after_predecessor": ["Revalidate every local guard."],
            "hard_stops": ["Stop on any source, graph, lease, or capacity drift."],
            "promotion_trigger": "Issue 1 releases its capacity.",
            "admission_transaction": admission_transaction,
            "delivery_identity": delivery_identity,
            "delivery_identity_sha256": delivery_identity_digest,
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
        packet_path = plans / "issue-2-pull-buffer.json"
        if packet_mutator is not None:
            packet_mutator(packet)
        packet_path.write_text(
            json.dumps(packet, sort_keys=True), encoding="utf-8"
        )
        self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 2,
                    "generation": 1,
                    "path": str(packet_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-24T10:00:02Z",
        )
        if finalize:
            finalize_ready(
                self.store,
                packet_path,
                now="2026-08-24T10:00:02Z",
                failpoint=failpoint,
                canonical_main_reader=lambda _repository: MAIN,
            )
            self.ready_item = dict(
                self.store.connection.execute(
                    "SELECT * FROM coordination_items WHERE repository=? AND issue_number=2",
                    (REPOSITORY,),
                ).fetchone()
            )
        return packet_path

    def _bind_finalized_candidate_to_effective_readiness_approval(self) -> dict:
        """Install one exact effective authority on the synthetic final campaign.

        The normal end-to-end approval-resume path is covered by
        test_readiness_approval_flow.  This fixture narrowly changes the already
        finalized synthetic campaign so activation itself can be race-tested
        independently of the scan-level revocation stopper.
        """

        campaign = self.store.connection.execute(
            """
            SELECT campaign.*, current.endpoint_id, receipt.attempt_id
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign
              ON campaign.id=current.campaign_id
            JOIN portfolio_readiness_receipts receipt
              ON receipt.id=current.receipt_id
            WHERE current.repository=? AND current.issue_number=2
            """,
            (REPOSITORY,),
        ).fetchone()
        planner = self.store.connection.execute(
            "SELECT endpoint_id FROM executor_role_endpoint_current "
            "WHERE role='planner'"
        ).fetchone()[0]
        boundary = "PRODUCT_BEHAVIOR"
        scope = readiness_execution_scope_sha256(
            repository=REPOSITORY,
            issue_number=2,
            source_payload_sha256=str(campaign["source_payload_sha256"]),
            campaign_id=int(campaign["id"]),
            generation=int(campaign["generation"]),
            item_version=int(campaign["item_version"]),
            accepted_main_sha=str(campaign["accepted_main_sha"]),
            graph_version=int(campaign["graph_version"]),
            capacity_policy_version=int(campaign["capacity_policy_version"]),
            candidate_sha256=str(campaign["candidate_sha256"]),
            worker_role=str(campaign["worker_role"]),
            worker_endpoint_id=str(campaign["endpoint_id"]),
            worker_attempt_id=str(campaign["attempt_id"]),
            parent_plan_sha256=str(campaign["plan_sha256"]),
            material_boundary=boundary,
        )
        packet = {
            "schema": "twinfinity.approval-proposal.v1",
            "decision_key": "issue-2:activation-revocation-race",
            "repository": REPOSITORY,
            "owning_issue": 2,
            "source_snapshot_sha256": self.sources[2],
            "execution_scope_sha256": scope,
            "requester_session_id": DEVELOPMENT_SESSION,
            "recipient_session_id": planner,
            "workstream": "READINESS",
            "boundary": boundary,
            "priority": "P0",
            "urgency": "READY_BLOCKER",
            "summary": "Issue 2 requires exact approval before activation.",
            "question": "May this exact finalized readiness lineage activate?",
            "requested_action": "Select one fixed readiness disposition.",
            "target": "Issue 2 finalized candidate activation.",
            "affected_issues": [2],
            "blocked_mutation": "Atomically activate the exact READY candidate.",
            "immediate_beneficiary": "The next bounded owner-visible slice.",
            "evidence": ["The exact finalized candidate is locally attested."],
            "risk": "Revoked authority must never allocate writer capacity.",
            "drift_guards": ["Recheck effectivity inside activation."],
            "prohibited_side_effects": ["No admission after revocation."],
            "options": [
                {
                    "id": "APPROVE", "label": "Approve", "effect": "Resume.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "REJECT", "label": "Reject", "effect": "Hold.",
                    "machine_outcome": "REJECT",
                },
                {
                    "id": "DEFER", "label": "Defer",
                    "effect": "Hold and revisit.",
                    "machine_outcome": "DEFER",
                },
                {
                    "id": "COURSE_CORRECT",
                    "label": "Course correct",
                    "effect": "Hold for a new proposal.",
                    "machine_outcome": "COURSE_CORRECT",
                },
            ],
            "recommendation": "APPROVE",
            "expires_at": None,
        }
        ensure_approval_schema(self.store.connection)
        with self.store.transaction():
            proposal = submit_readiness_proposal_in_transaction(
                self.store,
                packet,
                expected_requester_session_id=DEVELOPMENT_SESSION,
                expected_recipient_session_id=planner,
                expected_execution_scope_sha256=scope,
                now="2026-08-24T10:00:03Z",
            )
        batch = create_review_batch(
            self.store, REPOSITORY, "2026-08-24T10:00:04Z"
        )
        answer_map = {
            "schema": "twinfinity.approval-batch-answer-map.v1",
            "batch_sha256": batch["batch_sha256"],
            "answers": [
                {
                    "proposal_sha256": proposal["proposal_sha256"],
                    "selected_option_id": "APPROVE",
                }
            ],
        }
        decision = record_decision(
            self.store,
            proposal_sha256=proposal["proposal_sha256"],
            batch_sha256=batch["batch_sha256"],
            batch_answer_map=answer_map,
            decision="APPROVE",
            selected_option_id="APPROVE",
            revisit_trigger=None,
            decision_note="Approved only for the exact finalized issue 2 lineage.",
            user_input_sha256="8" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="portfolio-activation-race-approval",
            planner_session_id=planner,
            now="2026-08-24T10:00:04Z",
        )
        self.store.reserve_outbox(
            int(decision["owner_outbox_id"]), "2026-08-24T10:00:04Z"
        )
        self.store.complete_outbox(
            int(decision["owner_outbox_id"]),
            "comment:portfolio-activation-race",
            "2026-08-24T10:00:04Z",
        )
        current_payload = self.store.current_snapshot(
            REPOSITORY, "issue", 2
        ).payload
        claim_decision(
            self.store,
            proposal_sha256=proposal["proposal_sha256"],
            recipient_session_id=planner,
            now="2026-08-24T10:00:05Z",
            source_refresher=lambda *_args: current_payload,
        )

        # Campaigns are immutable in production.  This synthetic test-only
        # rewrite creates the exact finalized APPROVAL_RESUME shape whose
        # activation guard is under test, then immediately restores the trigger.
        with self.store.transaction():
            self.store.connection.execute(
                "DROP TRIGGER portfolio_readiness_campaigns_immutable_update"
            )
            self.store.connection.execute(
                """
                UPDATE portfolio_readiness_campaigns
                SET transition_kind='APPROVAL_RESUME',
                    approval_proposal_sha256=?,
                    approval_decision_sha256=?,
                    approval_recipient_session_id=?,
                    approval_execution_scope_sha256=?
                WHERE id=?
                """,
                (
                    proposal["proposal_sha256"],
                    decision["decision_sha256"],
                    planner,
                    scope,
                    int(campaign["id"]),
                ),
            )
        ensure_readiness_schema(self.store.connection)
        return {
            "proposal_sha256": proposal["proposal_sha256"],
            "decision_sha256": decision["decision_sha256"],
            "planner_session_id": planner,
        }

    def test_every_post_pass_delivery_substitution_fails_before_ready_without_writes(
        self,
    ) -> None:
        def mutate_identity(field: str, value):
            def apply(packet: dict) -> None:
                packet["delivery_identity"][field] = value
                packet["admission_transaction"]["message"]["payload"][
                    "delivery_identity"
                ][field] = value

            return apply

        def mutate_payload(field: str, value):
            def apply(packet: dict) -> None:
                packet["admission_transaction"]["message"]["payload"][
                    field
                ] = value

            return apply

        def mutate_item(packet: dict) -> None:
            packet["admission_transaction"]["item"]["expected_version"] += 1

        def mutate_message(packet: dict) -> None:
            packet["admission_transaction"]["message"][
                "idempotency_key"
            ] += "-substituted"

        def mutate_artifacts(packet: dict) -> None:
            packet["admission_transaction"].setdefault("artifacts", []).append(
                {
                    "repository": REPOSITORY,
                    "issue_number": 2,
                    "generation": 1,
                    "path": str(self.root / "foreign-artifact.json"),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            )

        mutations = (
            ("lease", mutate_payload("lease_manifest_sha256", "f" * 64)),
            ("branch", mutate_payload("branch", "codex/2-substituted")),
            (
                "worktree",
                mutate_payload(
                    "worktree_path",
                    "/home/ubuntu/code/twinfinityapp-issue-2-g2",
                ),
            ),
            ("opaque", mutate_payload("opaque_worktree_id", "issue-2-generation-9")),
            ("generation", mutate_payload("generation", 2)),
            ("admission-payload", mutate_payload("authority_sha256", "8" * 64)),
            ("artifact-set", mutate_artifacts),
            ("item-binding", mutate_item),
            ("message-binding", mutate_message),
            (
                "execution-scope",
                mutate_identity("admission_execution_scope_sha256", "4" * 64),
            ),
            (
                "transaction-digest",
                mutate_identity("admission_transaction_sha256", "5" * 64),
            ),
        )
        for index, (field, mutator) in enumerate(mutations):
            if index:
                self.tearDown()
                self.setUp()
            with self.subTest(field=field):
                packet_path = self._register_ready_candidate(
                    finalize=False, packet_mutator=mutator
                )
                tables = (
                    "portfolio_pull_buffer_candidates",
                    "portfolio_ready_finalizations",
                    "portfolio_dirty_events",
                    "coordination_messages",
                    "coordination_terminal_watches",
                )
                before = {
                    table: self.store.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in tables
                }
                with self.assertRaisesRegex(
                    PullBufferError,
                    "DELIVERY_IDENTITY|PULL_BUFFER_READINESS_BINDING",
                ):
                    finalize_ready(
                        self.store,
                        packet_path,
                        now="2026-08-24T10:00:03Z",
                        canonical_main_reader=lambda _repository: MAIN,
                    )
                after = {
                    table: self.store.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in tables
                }
                item = self.store.connection.execute(
                    "SELECT status,allocation_class FROM coordination_items "
                    "WHERE repository=? AND issue_number=2",
                    (REPOSITORY,),
                ).fetchone()
                ready_count = self.store.connection.execute(
                    "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates "
                    "WHERE repository=? AND issue_number=2 AND state='READY'",
                    (REPOSITORY,),
                ).fetchone()[0]
                self.assertEqual(before, after)
                self.assertEqual(("PREPARED", "NONE"), tuple(item))
                self.assertEqual(0, ready_count)

    def test_historical_unbound_receipt_requires_a_fresh_campaign(self) -> None:
        def historical(receipt: dict) -> None:
            receipt["schema"] = "twinfinity-kanban-readiness-receipt/v1"
            del receipt["delivery_identity_sha256"]

        with self.assertRaisesRegex(ReadinessError, "READINESS_RECEIPT_INVALID"):
            self._register_ready_candidate(
                finalize=False, receipt_mutator=historical
            )
        item = self.store.connection.execute(
            "SELECT status,allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(("PREPARED", "NONE"), tuple(item))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates "
                "WHERE repository=? AND issue_number=2 AND state='READY'",
                (REPOSITORY,),
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_ready_finalizations"
            ).fetchone()[0],
        )

    def test_missing_git_registration_blocks_ready_finalization_before_state_write(
        self,
    ) -> None:
        packet_path = self._register_ready_candidate(finalize=False)
        before = {
            table: self.store.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "portfolio_pull_buffer_candidates",
                "portfolio_ready_finalizations",
                "portfolio_dirty_events",
                "coordination_messages",
                "coordination_terminal_watches",
            )
        }

        with self.assertRaisesRegex(
            PullBufferError, "PULL_BUFFER_MAIN_EVIDENCE_INVALID"
        ):
            finalize_ready(
                self.store,
                packet_path,
                now="2026-08-24T10:00:03Z",
            )

        after = {
            table: self.store.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in before
        }
        item = self.store.connection.execute(
            "SELECT status,allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        phase = self.store.connection.execute(
            "SELECT state FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(before, after)
        self.assertEqual(("PREPARED", "NONE"), tuple(item))
        self.assertEqual("READY_ELIGIBLE", phase["state"])

    def test_main_drift_during_and_before_finalization_commit_rolls_back(self) -> None:
        packet_path = self._register_ready_candidate(finalize=False)
        for values in ((MAIN, "d" * 40), (MAIN, MAIN, "d" * 40)):
            with self.subTest(reads=len(values)):
                sequence = iter(values)
                before = {
                    table: self.store.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "portfolio_pull_buffer_candidates",
                        "portfolio_ready_finalizations",
                        "portfolio_dirty_events",
                        "coordination_messages",
                        "coordination_terminal_watches",
                    )
                }
                with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_MAIN_DRIFT"):
                    finalize_ready(
                        self.store,
                        packet_path,
                        now="2026-08-24T10:00:03Z",
                        canonical_main_reader=lambda _repository: next(sequence),
                    )
                after = {
                    table: self.store.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in before
                }
                item = self.store.connection.execute(
                    "SELECT status,allocation_class FROM coordination_items "
                    "WHERE repository=? AND issue_number=2",
                    (REPOSITORY,),
                ).fetchone()
                self.assertEqual(before, after)
                self.assertEqual(("PREPARED", "NONE"), tuple(item))

    def test_ready_finalization_rolls_back_each_write_and_replays_exactly(self) -> None:
        packet_path = self._register_ready_candidate(finalize=False)
        initial_message_count = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_messages"
        ).fetchone()[0]
        initial_dirty_event_notice_count = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events "
            "WHERE event_type='PORTFOLIO_DIRTY_ENQUEUED'"
        ).fetchone()[0]
        failpoints = (
            "after_item_ready",
            "after_ready_candidate",
            "after_prepared_retirement",
            "after_ready_pointer",
            "after_dirty_event",
            "after_finalization",
            "before_commit",
        )

        for target in failpoints:
            with self.subTest(failpoint=target):
                def injected(name: str, expected: str = target) -> None:
                    if name == expected:
                        raise RuntimeError(f"INJECTED_{expected}")

                with self.assertRaisesRegex(RuntimeError, f"INJECTED_{target}"):
                    finalize_ready(
                        self.store,
                        packet_path,
                        now="2026-08-24T10:00:03Z",
                        failpoint=injected,
                        canonical_main_reader=lambda _repository: MAIN,
                    )
                item = self.store.connection.execute(
                    "SELECT status,allocation_class,version FROM coordination_items "
                    "WHERE repository=? AND issue_number=2",
                    (REPOSITORY,),
                ).fetchone()
                phase = self.store.connection.execute(
                    "SELECT state,finalized_candidate_id,finalized_event_id "
                    "FROM portfolio_readiness_current WHERE repository=? AND issue_number=2",
                    (REPOSITORY,),
                ).fetchone()
                pointer = self.store.connection.execute(
                    """
                    SELECT candidate.state FROM portfolio_pull_buffer_current pointer
                    JOIN portfolio_pull_buffer_candidates candidate
                      ON candidate.id=pointer.candidate_id
                    WHERE pointer.repository=? AND pointer.issue_number=2
                    """,
                    (REPOSITORY,),
                ).fetchone()
                self.assertEqual(("PREPARED", "NONE", 1), tuple(item))
                self.assertEqual(("READY_ELIGIBLE", None, None), tuple(phase))
                self.assertEqual("PREPARED_NOT_READY", pointer["state"])
                self.assertEqual(
                    0,
                    self.store.connection.execute(
                        "SELECT COUNT(*) FROM portfolio_ready_finalizations"
                    ).fetchone()[0],
                )
                promoted = [
                    json.loads(row[0]).get("trigger_kind")
                    for row in self.store.connection.execute(
                        "SELECT payload_json FROM portfolio_dirty_events"
                    ).fetchall()
                ]
                self.assertNotIn("CANDIDATE_PROMOTED", promoted)

        first = finalize_ready(
            self.store,
            packet_path,
            now="2026-08-24T10:00:04Z",
            canonical_main_reader=lambda _repository: MAIN,
        )
        replay = finalize_ready(
            self.store,
            packet_path,
            now="2026-08-24T10:00:05Z",
            canonical_main_reader=lambda _repository: MAIN,
        )
        self.assertFalse(first["replay"])
        self.assertTrue(replay["replay"])
        self.assertEqual(first["candidate_id"], replay["candidate_id"])
        self.assertEqual(
            first["portfolio_dirty_event_id"], replay["portfolio_dirty_event_id"]
        )
        self.assertEqual(first["finalization_sha256"], replay["finalization_sha256"])
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_ready_finalizations"
            ).fetchone()[0],
        )
        promoted = [
            json.loads(row[0]).get("trigger_kind")
            for row in self.store.connection.execute(
                "SELECT payload_json FROM portfolio_dirty_events"
            ).fetchall()
        ]
        self.assertEqual(1, promoted.count("CANDIDATE_PROMOTED"))
        self.assertEqual(
            initial_dirty_event_notice_count + 1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events "
                "WHERE event_type='PORTFOLIO_DIRTY_ENQUEUED'"
            ).fetchone()[0],
        )
        self.assertEqual(
            initial_message_count,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        evaluated = evaluate_readiness(
            self.store.connection,
            REPOSITORY,
            2,
            now="2026-08-24T10:00:06Z",
            record_state=False,
        )
        self.assertEqual("FINALIZED", evaluated["state"])
        self.assertEqual([], evaluated["binding_reasons"])

    def test_revocation_committed_before_activation_cannot_allocate_writer(self) -> None:
        packet_path = self._register_ready_candidate()
        authority = self._bind_finalized_candidate_to_effective_readiness_approval()
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        admission = packet["admission_transaction"]
        self.assertIsNone(
            self.store._ready_finalization_attestation_error(
                repository=REPOSITORY,
                issue_number=2,
                generation=1,
                ready_item_version=int(self.ready_item["version"]),
                source_payload_sha256=self.sources[2],
            )
        )

        revoke_decision(
            self.store,
            proposal_sha256=authority["proposal_sha256"],
            decision_sha256=authority["decision_sha256"],
            reason="Authority was withdrawn after scan and before activation.",
            user_input_sha256="6" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="portfolio-activation-race-revocation",
            planner_session_id=authority["planner_session_id"],
            now="2026-08-24T10:00:06Z",
        )
        messages_before = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_messages "
            "WHERE topic='development.admission'"
        ).fetchone()[0]

        with self.assertRaisesRegex(
            CoordinationError, "READY_APPROVAL_AUTHORITY_"
        ):
            self.store.activate_admission(
                item=admission["item"],
                message=admission["message"],
                artifacts=admission.get("artifacts"),
                now="2026-08-24T10:00:07Z",
            )

        item = self.store.connection.execute(
            "SELECT status,allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(("READY", "NONE"), tuple(item))
        self.assertEqual(
            messages_before,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic='development.admission'"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches "
                "WHERE issue_number=2 AND state IN ('PENDING_CLAIM','ACTIVE')"
            ).fetchone()[0],
        )

    def test_approval_bound_activation_exact_replay_is_idempotent_and_current(self) -> None:
        packet_path = self._register_ready_candidate()
        authority = self._bind_finalized_candidate_to_effective_readiness_approval()
        admission = json.loads(packet_path.read_text(encoding="utf-8"))[
            "admission_transaction"
        ]
        self._release_predecessor("2026-08-24T10:00:06Z")

        first = self.store.activate_admission(
            item=admission["item"],
            message=admission["message"],
            artifacts=admission.get("artifacts"),
            now="2026-08-24T10:00:07Z",
        )
        before_replay = self._delivery_snapshot()
        replay = self.store.activate_admission(
            item=admission["item"],
            message=admission["message"],
            artifacts=admission.get("artifacts"),
            now="2026-08-24T10:00:08Z",
        )
        self.assertEqual(first, replay)
        self.assertEqual(before_replay, self._delivery_snapshot())

        revoke_decision(
            self.store,
            proposal_sha256=authority["proposal_sha256"],
            decision_sha256=authority["decision_sha256"],
            reason="Authority was withdrawn after the exact successful replay.",
            user_input_sha256="9" * 64,
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="portfolio-activation-replay-revocation",
            planner_session_id=authority["planner_session_id"],
            now="2026-08-24T10:00:09Z",
        )
        revoked = self._delivery_snapshot()
        with self.assertRaisesRegex(
            CoordinationError, "READY_APPROVAL_AUTHORITY_"
        ):
            self.store.activate_admission(
                item=admission["item"],
                message=admission["message"],
                artifacts=admission.get("artifacts"),
                now="2026-08-24T10:00:10Z",
            )
        self.assertEqual(revoked, self._delivery_snapshot())

    def test_terminal_approval_activation_cannot_replay_or_write(self) -> None:
        packet_path = self._register_ready_candidate()
        self._bind_finalized_candidate_to_effective_readiness_approval()
        admission = json.loads(packet_path.read_text(encoding="utf-8"))[
            "admission_transaction"
        ]
        self._release_predecessor("2026-08-24T10:00:06Z")
        _item, message_id = self.store.activate_admission(
            item=admission["item"],
            message=admission["message"],
            artifacts=admission.get("artifacts"),
            now="2026-08-24T10:00:07Z",
        )
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_messages SET state='COMPLETE',updated_at=? "
                "WHERE id=? AND state='PREPARED'",
                ("2026-08-24T10:00:08Z", message_id),
            )
            self.store.connection.execute(
                "UPDATE coordination_terminal_watches SET state='COMPLETE',updated_at=? "
                "WHERE admission_message_id=? AND state='PENDING_CLAIM'",
                ("2026-08-24T10:00:08Z", message_id),
            )
        terminal = self._delivery_snapshot()
        with self.assertRaisesRegex(
            CoordinationError, "ADMISSION_READY_REQUIRED"
        ):
            self.store.activate_admission(
                item=admission["item"],
                message=admission["message"],
                artifacts=admission.get("artifacts"),
                now="2026-08-24T10:00:09Z",
            )
        self.assertEqual(terminal, self._delivery_snapshot())

    def test_generic_evaluation_cannot_stale_a_finalized_ready_lineage(self) -> None:
        self._register_ready_candidate()
        self.store.connection.execute(
            "UPDATE portfolio_readiness_current SET endpoint_id=? "
            "WHERE repository=? AND issue_number=2",
            ("role.development.v0", REPOSITORY),
        )

        evaluated = evaluate_readiness(
            self.store.connection,
            REPOSITORY,
            2,
            now="2026-08-24T10:00:06Z",
            record_state=True,
        )

        self.assertEqual("FINALIZED", evaluated["state"])
        self.assertIn("ENDPOINT_DRIFT", evaluated["binding_reasons"])
        persisted = self.store.connection.execute(
            "SELECT state FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        item = self.store.connection.execute(
            "SELECT status,allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        candidate = self.store.connection.execute(
            """
            SELECT candidate.state
            FROM portfolio_pull_buffer_current pointer
            JOIN portfolio_pull_buffer_candidates candidate
              ON candidate.id=pointer.candidate_id
            WHERE pointer.repository=? AND pointer.issue_number=2
            """,
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("FINALIZED", persisted["state"])
        self.assertEqual(("READY", "NONE"), tuple(item))
        self.assertEqual("READY", candidate["state"])
