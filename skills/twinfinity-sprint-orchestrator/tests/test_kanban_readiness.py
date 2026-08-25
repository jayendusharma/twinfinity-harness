from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


STAGED = Path(__file__).resolve().parents[1] / "scripts"
INSTALLED = Path("/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts")
sys.path.insert(0, str(INSTALLED))
sys.path.insert(0, str(STAGED))

from coordination_store import CoordinationStore  # noqa: E402
from executor_registry import ensure_executor_registry_schema  # noqa: E402
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import (  # noqa: E402
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    ReadinessError,
    attach,
    discover,
    dispatch,
    evaluate,
    record,
    register,
)
from portfolio_graph import replace_graph  # noqa: E402


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
NOW = "2026-08-25T05:00:00Z"


class Harness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "coordination"
        root.mkdir(mode=0o700)
        self.store = CoordinationStore(root / "state.sqlite3")
        ensure_executor_registry_schema(self.store.connection)
        ensure_pull_buffer_schema(self.store.connection)
        self.sources: dict[int, str] = {}
        self.items: dict[int, dict] = {}
        self.candidates: dict[int, str] = {}
        self._install_endpoints()

    def close(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _install_endpoints(self) -> None:
        with self.store.transaction():
            for role in ("planner", "development", "sre"):
                endpoint = f"role.{role}.v1"
                self.store.connection.execute(
                    """
                    INSERT INTO executor_role_endpoints(
                        endpoint_id, role, version, executor_profile, codex_profile,
                        config_sha256, config_json, command_json, created_at
                    ) VALUES (?, ?, 1, ?, ?, ?, '{}', '[]', ?)
                    """,
                    (endpoint, role, role, f"twinfinity-{role}", "b" * 64, NOW),
                )
                self.store.connection.execute(
                    """
                    INSERT INTO executor_role_endpoint_current(
                        role, endpoint_id, pointer_version, updated_at
                    ) VALUES (?, ?, 1, ?)
                    """,
                    (role, endpoint, NOW),
                )

    def add_issue(self, issue: int) -> None:
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue,
            payload={
                "_projection_version": 3,
                "number": issue,
                "title": f"Issue {issue}",
                "state": "open",
                "updated_at": NOW,
                "milestone": {"number": 1, "title": "Sprint", "state": "open"},
            },
            source_updated_at=NOW,
            fetched_at=NOW,
        )
        self.sources[issue] = snapshot.payload_sha256
        self.items[issue] = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=issue,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=snapshot.payload_sha256,
            expected_version=0,
            now=NOW,
        )

    def install_graph(self, issues: list[int]) -> None:
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Sprint", "rank": 1}],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": f"issue:{issue}",
                        "issue_number": issue,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent outcome",
                        "lane_key": f"lane-{issue}",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": issue,
                        "estimate_units": 1,
                        "development_units": 1,
                        "shared_units": 0,
                        "sre_units": 0,
                        "source_payload_sha256": self.sources[issue],
                        "ready_at": NOW,
                    }
                    for issue in issues
                ],
                "relations": [],
            },
            now=NOW,
        )

    def add_candidate(self, issue: int) -> None:
        policy_version = self.store.connection.execute(
            "SELECT version FROM coordination_capacity_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()[0]
        candidate_sha = hashlib.sha256(f"candidate:{issue}".encode()).hexdigest()
        self.candidates[issue] = candidate_sha
        with self.store.transaction():
            cursor = self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_candidates(
                    repository, issue_number, generation, item_version,
                    source_payload_sha256, accepted_main_sha, graph_version,
                    capacity_policy_version, lane_key, state, verticality,
                    development_units, shared_units, sre_units, promotion_trigger,
                    artifact_relative_path, artifact_content_sha256,
                    candidate_sha256, registered_at
                ) VALUES (?, ?, 1, ?, ?, ?, 1, ?, ?, 'PREPARED_NOT_READY',
                          'END_TO_END', 1, 0, 0, 'Close readiness phase', ?, ?, ?, ?)
                """,
                (
                    REPOSITORY, issue, int(self.items[issue]["version"]),
                    self.sources[issue], MAIN, int(policy_version), f"lane-{issue}",
                    f"plans/issue-{issue}.json", "c" * 64, candidate_sha, NOW,
                ),
            )
            self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_current(
                    repository, issue_number, candidate_id, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (REPOSITORY, issue, int(cursor.lastrowid), NOW),
            )

    def plan(self, issue: int, role: str = "sre") -> dict:
        policy_version = self.store.connection.execute(
            "SELECT version FROM coordination_capacity_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()[0]
        return {
            "schema": PLAN_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": issue,
            "generation": 1,
            "item_version": int(self.items[issue]["version"]),
            "source_payload_sha256": self.sources[issue],
            "accepted_main_sha": MAIN,
            "graph_version": 1,
            "capacity_policy_version": int(policy_version),
            "candidate_sha256": self.candidates[issue],
            "worker_role": role,
            "phase_summary": "Resolve and assess the complete readiness phase without repository mutation.",
            "gates": [
                {
                    "gate_key": "complete-review",
                    "description": "Current source, boundary, collision, and evidence are sufficient.",
                    "requested_evidence": ["One complete exact-binding verdict"],
                }
            ],
        }

    def seed(self, issues: list[int]) -> None:
        for issue in issues:
            self.add_issue(issue)
        self.install_graph(issues)
        for issue in issues:
            self.add_candidate(issue)

    def complete_attempt(self, issue: int, message_id: int, attempt_id: str) -> None:
        endpoint = "role.sre.v1"
        with self.store.transaction():
            self.store.connection.execute(
                """
                INSERT INTO executor_attempts(
                    attempt_id, role, endpoint_id, instance_id, token_sha256,
                    target_kind, target_key, state, process_id, exit_code,
                    heartbeat_at, version, created_at, updated_at
                ) VALUES (?, 'sre', ?, ?, ?, 'message', ?, 'COMPLETE', 9001, 0,
                          ?, 1, ?, ?)
                """,
                (
                    attempt_id, endpoint, f"instance-{issue}", "d" * 64,
                    str(message_id), NOW, NOW, NOW,
                ),
            )
            self.store.connection.execute(
                """
                UPDATE coordination_messages
                SET state='COMPLETE', claimed_by=?, updated_at=? WHERE id=?
                """,
                (endpoint, NOW, message_id),
            )


class KanbanReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.close()

    def test_discovery_returns_two_candidate_phases(self) -> None:
        self.h.seed([1, 2])
        result = discover(self.h.store.connection, REPOSITORY, limit=2)
        self.assertEqual([1, 2], [row["issue_number"] for row in result["selected"]])

    def test_discovery_does_not_promote_queued_work(self) -> None:
        self.h.seed([1])
        item = self.h.items[1]
        self.h.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=1,
            status="QUEUED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.h.sources[1],
            expected_version=int(item["version"]),
            now=NOW,
        )
        result = discover(self.h.store.connection, REPOSITORY, limit=1)
        self.assertEqual([], result["selected"])

    def test_dispatch_is_one_attempt_per_candidate_not_per_gate(self) -> None:
        self.h.seed([1, 2])
        for issue in (1, 2):
            plan = self.h.plan(issue)
            plan["gates"].append(
                {
                    "gate_key": "second-check",
                    "description": "Second internal checklist item.",
                    "requested_evidence": ["Second fact"],
                }
            )
            register(self.h.store.connection, plan, now=NOW)
        result = dispatch(self.h.store, REPOSITORY, max_parallel=2, now=NOW)
        self.assertEqual(2, len(result["dispatched"]))
        self.assertEqual(
            2,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages WHERE state='PREPARED'"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_items WHERE allocation_class!='NONE'"
            ).fetchone()[0],
        )

    def test_actionable_hold_creates_one_resolution_transition(self) -> None:
        self.h.seed([1])
        plan = self.h.plan(1)
        registered = register(self.h.store.connection, plan, now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.complete_attempt(1, message_id, attempt_id)
        attach(
            self.h.store.connection,
            REPOSITORY,
            1,
            message_id,
            attempt_id,
            now=NOW,
        )
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": 1,
            "readiness_plan_sha256": registered["plan_sha256"],
            "verdict": "ACTIONABLE_HOLD",
            "worker_role": "sre",
            "message_id": message_id,
            "attempt_id": attempt_id,
            "gate_results": [
                {
                    "gate_key": "complete-review",
                    "verdict": "HOLD",
                    "evidence_sha256": "e" * 64,
                    "summary": "One bounded control is missing.",
                }
            ],
            "resolution": {
                "role": "planner",
                "actions": ["Reconcile the bounded control and rebind the campaign."],
                "approval_proposal_sha256": None,
            },
            "summary": "One bounded Planner-owned resolution cycle is sufficient.",
            "observed_at": NOW,
        }
        result = record(self.h.store, receipt, now=NOW)
        self.assertEqual("RESOLUTION_PENDING", result["state"])
        planner_notices = self.h.store.connection.execute(
            """
            SELECT COUNT(*) FROM coordination_messages
            WHERE recipient_session_id='role.planner.v1' AND state='PREPARED'
            """
        ).fetchone()[0]
        self.assertEqual(1, planner_notices)
        with self.assertRaisesRegex(ReadinessError, "READINESS_RESOLUTION_NO_CHANGE"):
            register(self.h.store.connection, plan, now=NOW)

    def test_source_drift_invalidates_phase(self) -> None:
        self.h.seed([1])
        register(self.h.store.connection, self.h.plan(1), now=NOW)
        self.h.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=1,
            payload={
                "_projection_version": 3,
                "number": 1,
                "title": "Changed",
                "state": "open",
                "updated_at": "2026-08-25T05:01:00Z",
                "milestone": {"number": 1, "title": "Sprint", "state": "open"},
            },
            source_updated_at="2026-08-25T05:01:00Z",
            fetched_at="2026-08-25T05:01:00Z",
        )
        result = evaluate(
            self.h.store.connection,
            REPOSITORY,
            1,
            now=NOW,
            record_state=True,
        )
        self.assertEqual("STALE", result["state"])
        self.assertIn("SOURCE_SNAPSHOT_DRIFT", result["binding_reasons"])


if __name__ == "__main__":
    unittest.main()
