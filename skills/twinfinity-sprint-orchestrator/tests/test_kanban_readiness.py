from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


STAGED = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(STAGED))

from coordination_store import CoordinationStore, canonical_json  # noqa: E402
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
import kanban_pull_buffer  # noqa: E402
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import (  # noqa: E402
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    SUCCESSOR_PLAN_SCHEMA,
    TERMINAL_HOLD_REFRESH_GATES,
    TERMINAL_HOLD_REFRESH_PHASE_SUMMARY,
    ReadinessError,
    attach,
    discover,
    dispatch,
    evaluate,
    ensure_schema as ensure_readiness_schema,
    pickup_receipt,
    register,
    reopen_terminal_hold,
    show,
    stage_receipt,
    transition_evidence_sha256,
)
from portfolio_graph import replace_graph  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
NOW = "2026-08-25T05:00:00Z"


class Harness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "coordination"
        root.mkdir(mode=0o700)
        self.root = root
        self.database = root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        config = apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            Path(__file__).resolve().parents[1],
            operation_key="kanban-readiness-tests",
            now=NOW,
        )
        self.endpoints = {
            role: endpoint.endpoint_id for role, endpoint in config.roles.items()
        }
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        self.sources: dict[int, str] = {}
        self.items: dict[int, dict] = {}
        self.candidates: dict[int, str] = {}
        self.tokens: dict[str, str] = {}

    def close(self) -> None:
        self.store.close()
        self.temporary.cleanup()

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
        endpoint = self.endpoints["sre"]
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

    def start_attempt(self, issue: int, message_id: int, attempt_id: str) -> str:
        endpoint = self.endpoints["sre"]
        token = f"executor-token:{attempt_id}"
        self.tokens[attempt_id] = token
        self.store.claim_message(message_id, endpoint, NOW)
        with self.store.transaction():
            self.store.connection.execute(
                """
                INSERT INTO executor_attempts(
                    attempt_id, role, endpoint_id, instance_id, token_sha256,
                    target_kind, target_key, state, process_id, exit_code,
                    heartbeat_at, version, created_at, updated_at
                ) VALUES (?, 'sre', ?, ?, ?, 'message', ?, 'RUNNING', 9001, NULL,
                          ?, 1, ?, ?)
                """,
                (
                    attempt_id, endpoint, f"instance-{issue}",
                    hashlib.sha256(token.encode()).hexdigest(),
                    str(message_id), NOW, NOW, NOW,
                ),
            )
        attach(
            self.store.connection,
            REPOSITORY,
            issue,
            message_id,
            attempt_id,
            now=NOW,
        )
        return token

    def finish_attempt(self, message_id: int, attempt_id: str) -> None:
        endpoint = self.endpoints["sre"]
        self.store.complete_message(message_id, endpoint, NOW)
        with self.store.transaction():
            self.store.connection.execute(
                """
                UPDATE executor_attempts
                SET state='COMPLETE', exit_code=0, version=version+1, updated_at=?
                WHERE attempt_id=? AND state='RUNNING'
                """,
                (NOW, attempt_id),
            )

    def receipt(self, registered: dict, message_id: int, attempt_id: str) -> dict:
        return {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": 1,
            "readiness_plan_sha256": registered["plan_sha256"],
            "verdict": "PASS",
            "worker_role": "sre",
            "message_id": message_id,
            "attempt_id": attempt_id,
            "gate_results": [
                {
                    "gate_key": "complete-review",
                    "verdict": "PASS",
                    "evidence_sha256": "e" * 64,
                    "summary": "Every readiness gate passed.",
                }
            ],
            "resolution": {
                "role": None,
                "actions": [],
                "approval": None,
            },
            "summary": "The complete candidate-level phase passed.",
            "observed_at": NOW,
        }

    def draft(self, receipt: dict, name: str = "receipt-draft.json") -> Path:
        path = self.root / name
        path.write_text(canonical_json(receipt), encoding="utf-8")
        path.chmod(0o600)
        return path

    def stage(self, receipt: dict, message_id: int, attempt_id: str) -> dict:
        with patch.dict(
            os.environ,
            {"TWINFINITY_EXECUTOR_TOKEN": self.tokens[attempt_id]},
        ):
            return stage_receipt(
                self.store.connection,
                self.database,
                self.draft(receipt),
                message_id=message_id,
                attempt_id=attempt_id,
                now=NOW,
            )

    def pickup(self, issue: int = 1, *, now: str = NOW) -> dict:
        campaign_id = self.store.connection.execute(
            "SELECT campaign_id FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, issue),
        ).fetchone()[0]
        return pickup_receipt(self.store, int(campaign_id), now=now)

    def terminal_hold(self, plan: dict | None = None) -> dict:
        if plan is None:
            self.seed([1])
            plan = self.plan(1)
        registered = register(self.store.connection, plan, now=NOW)
        dispatched = dispatch(
            self.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]
        message_id = int(dispatched["message_id"])
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.start_attempt(1, message_id, attempt_id)
        receipt = self.receipt(registered, message_id, attempt_id)
        receipt["verdict"] = "TERMINAL_HOLD"
        receipt["gate_results"][0]["verdict"] = "HOLD"
        receipt["gate_results"][0]["summary"] = "The old generation is terminal."
        receipt["summary"] = "The old prepared generation cannot proceed."
        self.stage(receipt, message_id, attempt_id)
        self.finish_attempt(message_id, attempt_id)
        pickup = self.pickup()
        current = self.store.connection.execute(
            """
            SELECT current.campaign_id, current.version, current.receipt_id,
                   receipt.receipt_sha256, current.message_id
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_receipts receipt
              ON receipt.id=current.receipt_id
            WHERE current.repository=? AND current.issue_number=1
            """,
            (REPOSITORY,),
        ).fetchone()
        if pickup["state"] != "HOLD":
            raise AssertionError(f"expected terminal HOLD, got {pickup['state']}")
        return {**dict(current), "planner_message_id": pickup["planner_message_id"]}

    def complete_planner_notice(self, hold: dict) -> None:
        planner = self.endpoints["planner"]
        message_id = int(hold["planner_message_id"])
        self.store.claim_message(message_id, planner, "2026-08-25T05:01:30Z")
        self.store.complete_message(message_id, planner, "2026-08-25T05:01:31Z")

    def advance_generation(self, *, accepted_main: str = MAIN) -> dict:
        prior = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=1",
            (REPOSITORY,),
        ).fetchone()
        item = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=1,
            status="PREPARED",
            allocation_class="NONE",
            generation=int(prior["generation"]) + 1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=int(prior["development_units"]),
            shared_units=int(prior["shared_units"]),
            sre_units=int(prior["sre_units"]),
            expected_source_sha256=self.sources[1],
            expected_version=int(prior["version"]),
            now="2026-08-25T05:01:00Z",
        )
        candidate_sha = hashlib.sha256(
            f"candidate:1:generation:{item['generation']}:{accepted_main}".encode()
        ).hexdigest()
        policy_version = self.store.connection.execute(
            "SELECT version FROM coordination_capacity_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()[0]
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
                ) VALUES (?, 1, ?, ?, ?, ?, 1, ?, 'lane-1',
                          'PREPARED_NOT_READY', 'END_TO_END', ?, ?, ?,
                          'Close refreshed readiness phase', ?, ?, ?, ?)
                """,
                (
                    REPOSITORY, int(item["generation"]), int(item["version"]),
                    self.sources[1], accepted_main, int(policy_version),
                    int(prior["development_units"]), int(prior["shared_units"]),
                    int(prior["sre_units"]), "plans/issue-1-generation-2.json",
                    "f" * 64, candidate_sha, "2026-08-25T05:01:00Z",
                ),
            )
            self.store.connection.execute(
                """
                UPDATE portfolio_pull_buffer_current
                SET candidate_id=?, updated_at=?
                WHERE repository=? AND issue_number=1
                """,
                (
                    int(cursor.lastrowid), "2026-08-25T05:01:00Z", REPOSITORY,
                ),
            )
        self.items[1] = item
        self.candidates[1] = candidate_sha
        return item


class KanbanReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.close()

    def reopen(self, hold: dict) -> dict:
        return reopen_terminal_hold(
            self.h.store.connection,
            REPOSITORY,
            1,
            expected_campaign_id=int(hold["campaign_id"]),
            expected_current_version=int(hold["version"]),
            expected_terminal_receipt_id=int(hold["receipt_id"]),
            expected_terminal_receipt_sha256=str(hold["receipt_sha256"]),
            now="2026-08-25T05:02:00Z",
        )

    def test_terminal_hold_reopens_only_to_new_bound_prepared_generation(self) -> None:
        hold = self.h.terminal_hold()
        self.h.complete_planner_notice(hold)
        old_gates = [
            tuple(row)
            for row in self.h.store.connection.execute(
                """
                SELECT gate_key,description,requested_evidence_json
                FROM portfolio_readiness_gates WHERE campaign_id=? ORDER BY id
                """,
                (int(hold["campaign_id"]),),
            )
        ]
        item = self.h.advance_generation()

        result = self.reopen(hold)

        current = self.h.store.connection.execute(
            """
            SELECT current.state,current.campaign_id,current.version,
                   campaign.generation,campaign.item_version,
                   campaign.parent_campaign_id,campaign.transition_kind,
                   campaign.candidate_sha256
            FROM portfolio_readiness_current current
            JOIN portfolio_readiness_campaigns campaign
              ON campaign.id=current.campaign_id
            WHERE current.repository=? AND current.issue_number=1
            """,
            (REPOSITORY,),
        ).fetchone()
        new_gates = [
            tuple(row)
            for row in self.h.store.connection.execute(
                """
                SELECT gate_key,description,requested_evidence_json
                FROM portfolio_readiness_gates WHERE campaign_id=? ORDER BY id
                """,
                (int(current["campaign_id"]),),
            )
        ]
        self.assertEqual("PENDING", current["state"])
        self.assertEqual(int(item["generation"]), current["generation"])
        self.assertEqual(int(item["version"]), current["item_version"])
        self.assertEqual(int(hold["campaign_id"]), current["parent_campaign_id"])
        self.assertEqual("REFRESH", current["transition_kind"])
        self.assertEqual(self.h.candidates[1], current["candidate_sha256"])
        self.assertNotEqual(old_gates, new_gates)
        self.assertEqual(
            [
                (
                    gate["gate_key"],
                    gate["description"],
                    canonical_json(gate["requested_evidence"]),
                )
                for gate in TERMINAL_HOLD_REFRESH_GATES
            ],
            new_gates,
        )
        self.assertEqual(int(current["campaign_id"]), result["campaign_id"])
        self.assertEqual(int(hold["receipt_id"]), result["terminal_receipt_id"])
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_events "
                "WHERE campaign_id=? "
                "AND event_type='READINESS_TERMINAL_HOLD_REOPENED'",
                (int(hold["campaign_id"]),),
            ).fetchone()[0],
        )

    def test_terminal_hold_refresh_does_not_copy_stale_parent_instructions(self) -> None:
        self.h.seed([1])
        stale_plan = self.h.plan(1)
        stale_plan["phase_summary"] = (
            "Use graph v1, branch codex/1-v2, worktree /tmp/issue-1-v2, "
            "and exactly four paths."
        )
        stale_plan["gates"][0] = {
            "gate_key": "complete-review",
            "description": (
                "Require graph v1, branch codex/1-v2, worktree "
                "/tmp/issue-1-v2, and the old four-path lease."
            ),
            "requested_evidence": [
                "Prove graph v1 and exactly four old paths"
            ],
        }
        hold = self.h.terminal_hold(stale_plan)
        self.h.complete_planner_notice(hold)
        item = self.h.advance_generation()

        result = self.reopen(hold)
        successor = json.loads(
            self.h.store.connection.execute(
                "SELECT plan_json FROM portfolio_readiness_campaigns WHERE id=?",
                (int(result["campaign_id"]),),
            ).fetchone()[0]
        )

        self.assertEqual(TERMINAL_HOLD_REFRESH_PHASE_SUMMARY, successor["phase_summary"])
        self.assertEqual(list(TERMINAL_HOLD_REFRESH_GATES), successor["gates"])
        self.assertEqual(int(item["generation"]), successor["generation"])
        self.assertEqual(self.h.candidates[1], successor["candidate_sha256"])
        prose = canonical_json(
            {
                "phase_summary": successor["phase_summary"],
                "gates": successor["gates"],
            }
        )
        for stale_instruction in (
            "graph v1", "codex/1-v2", "/tmp/issue-1-v2", "four path"
        ):
            self.assertNotIn(stale_instruction, prose)

    def test_terminal_hold_reopen_rejects_same_generation_without_mutation(self) -> None:
        hold = self.h.terminal_hold()
        self.h.complete_planner_notice(hold)
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_TERMINAL_HOLD_NEW_GENERATION_REQUIRED"
        ):
            self.reopen(hold)
        current = self.h.store.connection.execute(
            "SELECT campaign_id,state,version FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=1",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(
            (int(hold["campaign_id"]), "HOLD", int(hold["version"])),
            tuple(current),
        )
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_campaigns"
            ).fetchone()[0],
        )

    def test_terminal_hold_reopen_requires_exact_receipt_and_current_fences(self) -> None:
        hold = self.h.terminal_hold()
        self.h.complete_planner_notice(hold)
        self.h.advance_generation()
        for field, value, error in (
            ("campaign_id", int(hold["campaign_id"]) + 1,
             "READINESS_TERMINAL_HOLD_REOPEN_FENCE_LOST"),
            ("version", int(hold["version"]) + 1,
             "READINESS_TERMINAL_HOLD_REOPEN_FENCE_LOST"),
            ("receipt_id", int(hold["receipt_id"]) + 1,
             "READINESS_TERMINAL_HOLD_RECEIPT_FENCE_LOST"),
            ("receipt_sha256", "0" * 64,
             "READINESS_TERMINAL_HOLD_RECEIPT_FENCE_LOST"),
        ):
            candidate = {**hold, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(
                ReadinessError, error
            ):
                self.reopen(candidate)
        self.assertEqual(
            (int(hold["campaign_id"]), "HOLD", int(hold["version"])),
            tuple(
                self.h.store.connection.execute(
                    "SELECT campaign_id,state,version "
                    "FROM portfolio_readiness_current WHERE issue_number=1"
                ).fetchone()
            ),
        )

    def test_terminal_hold_reopen_rejects_arbitrary_and_protected_holds(self) -> None:
        for protected_state in ("HOLD", "APPROVAL_PENDING", "FINALIZED"):
            harness = Harness()
            try:
                harness.seed([1])
                registered = register(
                    harness.store.connection, harness.plan(1), now=NOW
                )
                with harness.store.transaction():
                    harness.store.connection.execute(
                        "UPDATE portfolio_readiness_current SET state=? "
                        "WHERE campaign_id=?",
                        (protected_state, int(registered["campaign_id"])),
                    )
                before = tuple(
                    harness.store.connection.execute(
                        "SELECT campaign_id,state,version "
                        "FROM portfolio_readiness_current WHERE issue_number=1"
                    ).fetchone()
                )
                expected_error = (
                    "READINESS_TERMINAL_HOLD_RECEIPT_FENCE_LOST"
                    if protected_state == "HOLD"
                    else "READINESS_TERMINAL_HOLD_REOPEN_STATE_CONFLICT"
                )
                with self.subTest(state=protected_state), self.assertRaisesRegex(
                    ReadinessError, expected_error
                ):
                    reopen_terminal_hold(
                        harness.store.connection,
                        REPOSITORY,
                        1,
                        expected_campaign_id=int(registered["campaign_id"]),
                        expected_current_version=int(before[2]),
                        expected_terminal_receipt_id=1,
                        expected_terminal_receipt_sha256="a" * 64,
                        now="2026-08-25T05:02:00Z",
                    )
                self.assertEqual(
                    before,
                    tuple(
                        harness.store.connection.execute(
                            "SELECT campaign_id,state,version "
                            "FROM portfolio_readiness_current WHERE issue_number=1"
                        ).fetchone()
                    ),
                )
            finally:
                harness.close()

    def test_terminal_hold_reopen_rejects_active_attempt(self) -> None:
        hold = self.h.terminal_hold()
        self.h.complete_planner_notice(hold)
        self.h.advance_generation()
        with self.h.store.transaction():
            self.h.store.connection.execute(
                """
                INSERT INTO executor_attempts(
                    attempt_id, role, endpoint_id, instance_id, token_sha256,
                    target_kind, target_key, state, process_id, exit_code,
                    heartbeat_at, version, created_at, updated_at
                ) VALUES (?, 'sre', ?, ?, ?, 'message', ?, 'RUNNING', 9002,
                          NULL, ?, 1, ?, ?)
                """,
                (
                    "22222222-2222-4222-8222-222222222222",
                    self.h.endpoints["sre"], "active-retry-instance", "b" * 64,
                    str(hold["message_id"]), NOW, NOW, NOW,
                ),
            )
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_TERMINAL_HOLD_ATTEMPT_ACTIVE"
        ):
            self.reopen(hold)
        self.assertEqual(
            (int(hold["campaign_id"]), "HOLD", int(hold["version"])),
            tuple(
                self.h.store.connection.execute(
                    "SELECT campaign_id,state,version "
                    "FROM portfolio_readiness_current WHERE issue_number=1"
                ).fetchone()
            ),
        )

    def test_terminal_hold_reopen_rejects_nonterminal_old_message(self) -> None:
        hold = self.h.terminal_hold()
        self.h.advance_generation()
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_TERMINAL_HOLD_MESSAGE_NONTERMINAL"
        ):
            self.reopen(hold)

    def test_terminal_hold_reopen_rejects_binding_drift(self) -> None:
        hold = self.h.terminal_hold()
        self.h.complete_planner_notice(hold)
        self.h.advance_generation(accepted_main="b" * 40)
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_TERMINAL_HOLD_BINDING_DRIFT"
        ):
            self.reopen(hold)
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_campaigns"
            ).fetchone()[0],
        )

    def test_terminal_hold_reopen_cli_uses_exact_fences(self) -> None:
        hold = self.h.terminal_hold()
        self.h.complete_planner_notice(hold)
        self.h.advance_generation()
        argv = [
            "kanban_pull_buffer.py",
            "readiness-reopen-terminal-hold",
            "--repository", REPOSITORY,
            "--issue", "1",
            "--expected-campaign-id", str(hold["campaign_id"]),
            "--expected-current-version", str(hold["version"]),
            "--expected-terminal-receipt-id", str(hold["receipt_id"]),
            "--expected-terminal-receipt-sha256", str(hold["receipt_sha256"]),
        ]
        output = io.StringIO()
        with (
            patch.object(kanban_pull_buffer, "DEFAULT_DATABASE", self.h.database),
            patch.object(sys, "argv", argv),
            redirect_stdout(output),
        ):
            self.assertEqual(0, kanban_pull_buffer.main())
        payload = json.loads(output.getvalue())
        self.assertEqual("COMPLETE", payload["phase"])
        self.assertEqual("PENDING", payload["result"]["state"])
        self.assertEqual(2, payload["result"]["generation"])

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

    def test_dispatch_preserves_factual_docker_readiness_evidence(self) -> None:
        self.h.seed([1])
        plan = self.h.plan(1)
        plan["gates"].append(
            {
                "gate_key": "local-docker-boundary",
                "description": "Confirm the candidate-local Docker boundary.",
                "requested_evidence": [
                    "Local Docker identity and isolation evidence",
                    "Local Docker boundary ownership",
                    "Docker endpoint provenance",
                ],
            }
        )
        register(self.h.store.connection, plan, now=NOW)

        dispatched = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"]

        self.assertEqual(1, len(dispatched))
        message = self.h.store.connection.execute(
            "SELECT state,payload_json FROM coordination_messages WHERE id=?",
            (int(dispatched[0]["message_id"]),),
        ).fetchone()
        payload = json.loads(message["payload_json"])
        self.assertEqual("PREPARED", message["state"])
        self.assertTrue(
            any(
                "Docker endpoint provenance" in evidence
                for evidence in payload["requested_evidence"]
            )
        )

    def test_supervisor_picks_up_one_exact_staged_receipt_after_terminal(self) -> None:
        self.h.seed([1])
        plan = self.h.plan(1)
        plan["gates"].append(
            {
                "gate_key": "second-check",
                "description": "Second internal checklist item.",
                "requested_evidence": ["Second fact"],
            }
        )
        registered = register(self.h.store.connection, plan, now=NOW)
        dispatched = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]
        message_id = int(dispatched["message_id"])
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
        receipt = self.h.receipt(registered, message_id, attempt_id)
        receipt["gate_results"].append(
            {
                "gate_key": "second-check",
                "verdict": "PASS",
                "evidence_sha256": "f" * 64,
                "summary": "The second internal check passed.",
            }
        )
        draft = self.h.draft(receipt)

        with patch.dict(
            os.environ,
            {"TWINFINITY_EXECUTOR_TOKEN": self.h.tokens[attempt_id]},
        ):
            staged = stage_receipt(
                self.h.store.connection, self.h.database, draft,
                message_id=message_id, attempt_id=attempt_id, now=NOW,
            )
            replay = stage_receipt(
                self.h.store.connection, self.h.database, draft,
                message_id=message_id, attempt_id=attempt_id, now=NOW,
            )
        self.assertFalse(staged["replay"])
        self.assertTrue(replay["replay"])
        pickup_before_terminal = self.h.store.connection.execute(
            "SELECT state,attempt_token_sha256,artifact_device_id,artifact_inode "
            "FROM portfolio_readiness_receipt_pickups"
        ).fetchone()
        self.assertEqual("STAGED", pickup_before_terminal["state"])
        self.assertEqual(
            hashlib.sha256(self.h.tokens[attempt_id].encode()).hexdigest(),
            pickup_before_terminal["attempt_token_sha256"],
        )
        payload = json.loads(
            self.h.store.connection.execute(
                "SELECT payload_json FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()[0]
        )
        self.assertEqual(
            staged["relative_path"],
            payload["evidence"]["receipt_artifact"]["relative_path"],
        )

        supervisor = CoordinationSupervisor(
            self.h.store,
            launcher=lambda _session, _message: 7001,
            terminal_watch_launcher=lambda _session, _watch: 7002,
            process_checker=lambda *_target: False,
        )
        before_terminal = supervisor.run_once("2026-08-25T05:00:01Z")
        self.assertEqual([], before_terminal["readiness_receipt_pickup"]["recorded"])
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE recipient_session_id=?",
                (self.h.endpoints["planner"],),
            ).fetchone()[0],
        )

        self.h.finish_attempt(message_id, attempt_id)
        completed = supervisor.run_once("2026-08-25T05:00:02Z")
        exact_replay = supervisor.run_once("2026-08-25T05:00:03Z")
        self.assertEqual(1, len(completed["readiness_receipt_pickup"]["recorded"]))
        self.assertEqual([], exact_replay["readiness_receipt_pickup"]["recorded"])
        current = self.h.store.connection.execute(
            "SELECT state FROM portfolio_readiness_current WHERE issue_number=1"
        ).fetchone()
        pickup = self.h.store.connection.execute(
            "SELECT state, attempts, artifact_sha256 FROM portfolio_readiness_receipt_pickups"
        ).fetchone()
        self.assertEqual("READY_ELIGIBLE", current["state"])
        self.assertEqual(("RECORDED", 0, staged["artifact_sha256"]), tuple(pickup))
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE recipient_session_id=?",
                (self.h.endpoints["planner"],),
            ).fetchone()[0],
        )
        self.assertEqual(
            2,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_items WHERE allocation_class!='NONE'"
            ).fetchone()[0],
        )

    def test_worker_cannot_record_before_message_and_attempt_are_terminal(self) -> None:
        self.h.seed([1])
        registered = register(self.h.store.connection, self.h.plan(1), now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
        receipt = self.h.receipt(registered, message_id, attempt_id)
        self.h.stage(receipt, message_id, attempt_id)
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_ATTEMPT_BINDING_INVALID"
        ):
            self.h.pickup()
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE recipient_session_id=?",
                (self.h.endpoints["planner"],),
            ).fetchone()[0],
        )

    def test_stage_requires_exact_wrapper_token_and_rejects_other_attempts(self) -> None:
        self.h.seed([1])
        registered = register(self.h.store.connection, self.h.plan(1), now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        exact_token = self.h.start_attempt(1, message_id, attempt_id)
        receipt = self.h.receipt(registered, message_id, attempt_id)
        draft = self.h.draft(receipt)
        other_tokens = {
            "wrong": "not-issued-by-wrapper",
            "planner": "planner-attempt-token",
            "other-worker": "other-worker-attempt-token",
        }
        with self.h.store.transaction():
            for label, role, endpoint, token in (
                (
                    "planner", "planner", self.h.endpoints["planner"],
                    other_tokens["planner"],
                ),
                (
                    "worker", "sre", self.h.endpoints["sre"],
                    other_tokens["other-worker"],
                ),
            ):
                self.h.store.connection.execute(
                    """
                    INSERT INTO executor_attempts(
                        attempt_id, role, endpoint_id, instance_id, token_sha256,
                        target_kind, target_key, state, process_id, exit_code,
                        heartbeat_at, version, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'message', ?, 'RUNNING', ?, NULL,
                              ?, 1, ?, ?)
                    """,
                    (
                        f"other-{label}-attempt", role, endpoint, f"other-{label}",
                        hashlib.sha256(token.encode()).hexdigest(), "99999", 9100,
                        NOW, NOW, NOW,
                    ),
                )
        with patch.dict(os.environ, {"TWINFINITY_EXECUTOR_TOKEN": ""}):
            with self.assertRaisesRegex(
                ReadinessError, "READINESS_EXECUTOR_TOKEN_REQUIRED"
            ):
                stage_receipt(
                    self.h.store.connection, self.h.database, draft,
                    message_id=message_id, attempt_id=attempt_id, now=NOW,
                )
        for label, token in other_tokens.items():
            with self.subTest(token=label), patch.dict(
                os.environ, {"TWINFINITY_EXECUTOR_TOKEN": token}
            ):
                with self.assertRaisesRegex(
                    ReadinessError, "READINESS_RECEIPT_STAGE_NOT_CURRENT"
                ):
                    stage_receipt(
                        self.h.store.connection, self.h.database, draft,
                        message_id=message_id, attempt_id=attempt_id, now=NOW,
                    )
        self.assertEqual(
            "PENDING",
            self.h.store.connection.execute(
                "SELECT state FROM portfolio_readiness_receipt_pickups"
            ).fetchone()[0],
        )
        with patch.dict(os.environ, {"TWINFINITY_EXECUTOR_TOKEN": exact_token}):
            staged = stage_receipt(
                self.h.store.connection, self.h.database, draft,
                message_id=message_id, attempt_id=attempt_id, now=NOW,
            )
        self.assertEqual("STAGED", staged["state"])

    def test_staged_identity_is_immutable_and_substitution_holds(self) -> None:
        self.h.seed([1])
        registered = register(self.h.store.connection, self.h.plan(1), now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
        staged = self.h.stage(
            self.h.receipt(registered, message_id, attempt_id), message_id, attempt_id
        )
        before = self.h.store.connection.execute(
            "SELECT artifact_sha256,artifact_size_bytes,artifact_device_id,"
            "artifact_inode,artifact_mode,artifact_uid,artifact_nlink,"
            "artifact_mtime_ns,artifact_ctime_ns "
            "FROM portfolio_readiness_receipt_pickups"
        ).fetchone()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "READINESS_PICKUP_IDENTITY_IMMUTABLE"
        ):
            self.h.store.connection.execute(
                "UPDATE portfolio_readiness_receipt_pickups "
                "SET artifact_sha256=? WHERE state='STAGED'",
                ("0" * 64,),
            )
        self.h.store.connection.rollback()
        artifact = self.h.database.parent / staged["relative_path"]
        artifact.write_text("{}", encoding="utf-8")
        artifact.chmod(0o600)
        self.h.finish_attempt(message_id, attempt_id)
        supervisor = CoordinationSupervisor(
            self.h.store,
            launcher=lambda _session, _message: 7001,
            terminal_watch_launcher=lambda _session, _watch: 7002,
            process_checker=lambda *_target: False,
        )
        supervisor.run_once("2026-08-25T05:00:01Z")
        supervisor.run_once("2026-08-25T05:01:02Z")
        result = supervisor.run_once("2026-08-25T05:03:03Z")
        self.assertEqual(1, len(result["readiness_receipt_pickup"]["held"]))
        after = self.h.store.connection.execute(
            "SELECT artifact_sha256,artifact_size_bytes,artifact_device_id,"
            "artifact_inode,artifact_mode,artifact_uid,artifact_nlink,"
            "artifact_mtime_ns,artifact_ctime_ns "
            "FROM portfolio_readiness_receipt_pickups"
        ).fetchone()
        self.assertEqual(tuple(before), tuple(after))

    def test_terminal_pending_rejects_even_valid_file_at_locator(self) -> None:
        self.h.seed([1])
        registered = register(self.h.store.connection, self.h.plan(1), now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
        receipt = self.h.receipt(registered, message_id, attempt_id)
        relative_path = self.h.store.connection.execute(
            "SELECT relative_path FROM portfolio_readiness_receipt_pickups"
        ).fetchone()[0]
        directory = self.h.database.parent / "readiness-receipts"
        directory.mkdir(mode=0o700)
        artifact = self.h.database.parent / relative_path
        artifact.write_text(canonical_json(receipt), encoding="utf-8")
        artifact.chmod(0o600)
        self.h.finish_attempt(message_id, attempt_id)
        supervisor = CoordinationSupervisor(
            self.h.store,
            launcher=lambda _session, _message: 7001,
            terminal_watch_launcher=lambda _session, _watch: 7002,
            process_checker=lambda *_target: False,
        )
        result = supervisor.run_once("2026-08-25T05:00:01Z")
        self.assertEqual(
            "READINESS_RECEIPT_NOT_STAGED",
            result["readiness_receipt_pickup"]["retried"][0]["error"],
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_receipts"
            ).fetchone()[0],
        )

    def test_missing_terminal_receipt_retries_then_holds_without_planner_notice(self) -> None:
        self.h.seed([1])
        register(self.h.store.connection, self.h.plan(1), now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
        self.h.finish_attempt(message_id, attempt_id)
        supervisor = CoordinationSupervisor(
            self.h.store,
            launcher=lambda _session, _message: 7001,
            terminal_watch_launcher=lambda _session, _watch: 7002,
            process_checker=lambda *_target: False,
        )
        first = supervisor.run_once("2026-08-25T05:00:01Z")
        second = supervisor.run_once("2026-08-25T05:01:02Z")
        third = supervisor.run_once("2026-08-25T05:03:03Z")
        self.assertEqual(1, len(first["readiness_receipt_pickup"]["retried"]))
        self.assertEqual(1, len(second["readiness_receipt_pickup"]["retried"]))
        self.assertEqual(1, len(third["readiness_receipt_pickup"]["held"]))
        self.assertEqual(
            ("HOLD", 3, "READINESS_RECEIPT_NOT_STAGED"),
            tuple(
                self.h.store.connection.execute(
                    "SELECT state,attempts,last_error "
                    "FROM portfolio_readiness_receipt_pickups"
                ).fetchone()
            ),
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE recipient_session_id=?",
                (self.h.endpoints["planner"],),
            ).fetchone()[0],
        )

    def test_invalid_terminal_receipt_retries_then_holds(self) -> None:
        self.h.seed([1])
        registered = register(self.h.store.connection, self.h.plan(1), now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
        receipt = self.h.receipt(registered, message_id, attempt_id)
        staged = self.h.stage(receipt, message_id, attempt_id)
        artifact = self.h.database.parent / staged["relative_path"]
        artifact.write_text("{", encoding="utf-8")
        artifact.chmod(0o600)
        self.h.finish_attempt(message_id, attempt_id)
        supervisor = CoordinationSupervisor(
            self.h.store,
            launcher=lambda _session, _message: 7001,
            terminal_watch_launcher=lambda _session, _watch: 7002,
            process_checker=lambda *_target: False,
        )
        supervisor.run_once("2026-08-25T05:00:01Z")
        supervisor.run_once("2026-08-25T05:01:02Z")
        result = supervisor.run_once("2026-08-25T05:03:03Z")
        self.assertEqual(1, len(result["readiness_receipt_pickup"]["held"]))
        pickup = self.h.store.connection.execute(
            "SELECT state,attempts,last_error FROM portfolio_readiness_receipt_pickups"
        ).fetchone()
        self.assertEqual("HOLD", pickup["state"])
        self.assertEqual(3, pickup["attempts"])
        self.assertEqual("READINESS_RECEIPT_ARTIFACT_CHANGED", pickup["last_error"])

    def test_atomic_schema_migration_rolls_back_every_change(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE portfolio_readiness_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL, issue_number INTEGER NOT NULL,
                generation INTEGER NOT NULL, item_version INTEGER NOT NULL,
                source_payload_sha256 TEXT NOT NULL, accepted_main_sha TEXT NOT NULL,
                graph_version INTEGER NOT NULL, capacity_policy_version INTEGER NOT NULL,
                candidate_sha256 TEXT NOT NULL, worker_role TEXT NOT NULL,
                phase_summary TEXT NOT NULL, plan_sha256 TEXT NOT NULL UNIQUE,
                plan_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE portfolio_readiness_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL,
                verdict TEXT NOT NULL, worker_role TEXT NOT NULL, message_id INTEGER NOT NULL,
                attempt_id TEXT NOT NULL, resolution_role TEXT, receipt_sha256 TEXT NOT NULL UNIQUE,
                receipt_json TEXT NOT NULL, observed_at TEXT NOT NULL, recorded_at TEXT NOT NULL
            );
            CREATE TABLE portfolio_readiness_current (
                repository TEXT NOT NULL, issue_number INTEGER NOT NULL,
                campaign_id INTEGER NOT NULL UNIQUE, state TEXT NOT NULL CHECK(state IN (
                    'PENDING','RUNNING','RESOLUTION_PENDING','APPROVAL_PENDING',
                    'READY_ELIGIBLE','HOLD','STALE')),
                message_id INTEGER, attempt_id TEXT, endpoint_id TEXT, receipt_id INTEGER,
                resolution_cycles INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL,
                updated_at TEXT NOT NULL, last_error TEXT,
                PRIMARY KEY(repository, issue_number)
            );
            """
        )
        before_campaign = [
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(portfolio_readiness_campaigns)"
            )
        ]
        before_receipt = [
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(portfolio_readiness_receipts)"
            )
        ]

        def failpoint(step: str) -> None:
            if step == "before_commit":
                raise RuntimeError("migration-failpoint")

        with self.assertRaisesRegex(RuntimeError, "migration-failpoint"):
            ensure_readiness_schema(connection, failpoint=failpoint)

        self.assertFalse(connection.in_transaction)
        self.assertEqual(
            before_campaign,
            [
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(portfolio_readiness_campaigns)"
                )
            ],
        )
        self.assertEqual(
            before_receipt,
            [
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(portfolio_readiness_receipts)"
                )
            ],
        )
        self.assertIsNone(
            connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE name='portfolio_readiness_receipt_pickups'"
            ).fetchone()
        )
        current_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='portfolio_readiness_current'"
        ).fetchone()[0]
        self.assertNotIn("FINALIZED", current_sql)
        connection.close()

    def test_pickup_schema_rebuild_rolls_back_without_partial_cutover(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE portfolio_readiness_receipt_pickups (
                campaign_id INTEGER PRIMARY KEY,
                message_id INTEGER NOT NULL UNIQUE,
                attempt_id TEXT,
                locator_sha256 TEXT NOT NULL UNIQUE,
                relative_path TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('PENDING','RECORDED','HOLD')),
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                receipt_id INTEGER,
                artifact_sha256 TEXT,
                artifact_size_bytes INTEGER,
                artifact_device_id INTEGER,
                artifact_inode INTEGER,
                artifact_mtime_ns INTEGER,
                version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT
            );
            INSERT INTO portfolio_readiness_receipt_pickups(
                campaign_id,message_id,attempt_id,locator_sha256,relative_path,
                state,attempts,version,created_at,updated_at
            ) VALUES (7, 11, 'attempt-7', 'locator-7',
                      'readiness-receipts/legacy.json', 'PENDING', 2, 4,
                      '2026-08-25T04:00:00Z', '2026-08-25T04:01:00Z');
            """
        )
        before_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='portfolio_readiness_receipt_pickups'"
        ).fetchone()[0]

        def failpoint(step: str) -> None:
            if step == "after_pickup_table":
                raise RuntimeError("pickup-migration-failpoint")

        with self.assertRaisesRegex(RuntimeError, "pickup-migration-failpoint"):
            ensure_readiness_schema(connection, failpoint=failpoint)

        after_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='portfolio_readiness_receipt_pickups'"
        ).fetchone()[0]
        row = connection.execute(
            "SELECT campaign_id,state,attempts,version "
            "FROM portfolio_readiness_receipt_pickups"
        ).fetchone()
        columns = {
            item["name"] for item in connection.execute(
                "PRAGMA table_info(portfolio_readiness_receipt_pickups)"
            )
        }
        self.assertEqual(before_sql, after_sql)
        self.assertNotIn("attempt_token_sha256", columns)
        self.assertEqual((7, "PENDING", 2, 4), tuple(row))
        self.assertIsNone(
            connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE name='portfolio_readiness_receipt_pickups_legacy'"
            ).fetchone()
        )
        connection.close()

    def test_actionable_hold_creates_one_resolution_transition(self) -> None:
        self.h.seed([1])
        plan = self.h.plan(1)
        registered = register(self.h.store.connection, plan, now=NOW)
        message_id = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]["message_id"]
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
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
                "actions": [
                    {
                        "kind": "REBUILD_PREPARED_CANDIDATE",
                        "target": f"{REPOSITORY}:issue:1",
                        "expected_digest": self.h.candidates[1],
                        "desired_digest": "d" * 64,
                        "authority_class": "PLANNER_OWNER_API",
                        "evidence_required": [
                            "portfolio_pull_buffer_current.candidate_id",
                            "portfolio_pull_buffer_candidates.candidate_sha256",
                        ],
                    }
                ],
                "approval": None,
            },
            "summary": "One bounded Planner-owned resolution cycle is sufficient.",
            "observed_at": NOW,
        }
        self.h.stage(receipt, message_id, attempt_id)
        self.h.finish_attempt(message_id, attempt_id)
        result = self.h.pickup()
        self.assertEqual("RESOLUTION_PENDING", result["state"])
        planner_notices = self.h.store.connection.execute(
            """
            SELECT COUNT(*) FROM coordination_messages
            WHERE recipient_session_id=? AND state='PREPARED'
            """,
            (self.h.endpoints["planner"],),
        ).fetchone()[0]
        self.assertEqual(1, planner_notices)
        replay = register(self.h.store.connection, plan, now=NOW)
        self.assertTrue(replay["replay"])
        self.assertEqual("RESOLUTION_PENDING", replay["state"])
        current = self.h.store.connection.execute(
            "SELECT campaign_id,version FROM portfolio_readiness_current "
            "WHERE repository=? AND issue_number=1",
            (REPOSITORY,),
        ).fetchone()
        successor = self.h.plan(1)
        successor["schema"] = SUCCESSOR_PLAN_SCHEMA
        successor["gates"][0]["description"] = (
            "The missing bounded control is now reconciled and evidenced."
        )
        successor["transition"] = {
            "kind": "RESOLUTION",
            "parent_campaign_id": int(current["campaign_id"]),
            "expected_parent_version": int(current["version"]),
            "changed_evidence_sha256": "0" * 64,
            "resolution_action_set_sha256": hashlib.sha256(
                canonical_json(receipt["resolution"]["actions"]).encode("utf-8")
            ).hexdigest(),
            "approval": None,
        }
        successor["transition"]["changed_evidence_sha256"] = (
            transition_evidence_sha256(plan, successor)
        )
        with self.assertRaisesRegex(
            ReadinessError, "READINESS_RESOLUTION_HANDLER_REQUIRED"
        ):
            register(self.h.store.connection, successor, now=NOW)

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

    def test_observational_discovery_evaluation_and_show_are_query_only_safe(self) -> None:
        self.h.seed([1])
        register(self.h.store.connection, self.h.plan(1), now=NOW)
        before_changes = self.h.store.connection.total_changes
        self.h.store.connection.execute("PRAGMA query_only=ON")
        try:
            discovered = discover(self.h.store.connection, REPOSITORY, limit=1)
            evaluated = evaluate(
                self.h.store.connection,
                REPOSITORY,
                1,
                now=NOW,
                record_state=False,
            )
            shown = show(self.h.store.connection, REPOSITORY)
        finally:
            self.h.store.connection.execute("PRAGMA query_only=OFF")
        self.assertEqual(before_changes, self.h.store.connection.total_changes)
        self.assertEqual([1], [row["issue_number"] for row in discovered["selected"]])
        self.assertEqual("PENDING", evaluated["state"])
        self.assertEqual("PENDING", shown["campaigns"][0]["state"])

    def test_pending_running_and_ready_eligible_campaigns_cannot_be_superseded(self) -> None:
        self.h.seed([1, 2, 3])
        campaigns = {
            issue: register(self.h.store.connection, self.h.plan(issue), now=NOW)
            for issue in (1, 2, 3)
        }
        first_dispatch = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]
        self.assertEqual(1, first_dispatch["issue_number"])
        message_id = int(first_dispatch["message_id"])
        attempt_id = "11111111-1111-4111-8111-111111111111"
        self.h.start_attempt(1, message_id, attempt_id)
        ready_receipt = {
                "schema": RECEIPT_SCHEMA,
                "repository": REPOSITORY,
                "issue_number": 1,
                "readiness_plan_sha256": campaigns[1]["plan_sha256"],
                "verdict": "PASS",
                "worker_role": "sre",
                "message_id": message_id,
                "attempt_id": attempt_id,
                "gate_results": [
                    {
                        "gate_key": "complete-review",
                        "verdict": "PASS",
                        "evidence_sha256": "e" * 64,
                        "summary": "Every readiness gate passed.",
                    }
                ],
                "resolution": {
                    "role": None,
                    "actions": [],
                    "approval": None,
                },
                "summary": "The complete candidate-level phase passed.",
                "observed_at": NOW,
            }
        self.h.stage(ready_receipt, message_id, attempt_id)
        self.h.finish_attempt(message_id, attempt_id)
        self.h.pickup()
        second_dispatch = dispatch(
            self.h.store, REPOSITORY, max_parallel=1, now=NOW
        )["dispatched"][0]
        self.assertEqual(2, second_dispatch["issue_number"])

        states = {1: "READY_ELIGIBLE", 2: "RUNNING", 3: "PENDING"}
        for issue, expected_state in states.items():
            with self.subTest(issue=issue, state=expected_state):
                current = self.h.store.connection.execute(
                    "SELECT campaign_id,state,version FROM portfolio_readiness_current "
                    "WHERE repository=? AND issue_number=?",
                    (REPOSITORY, issue),
                ).fetchone()
                self.assertEqual(expected_state, current["state"])
                successor = self.h.plan(issue)
                successor["schema"] = SUCCESSOR_PLAN_SCHEMA
                successor["phase_summary"] = (
                    "Changed text must not replace an active or accepted phase."
                )
                successor["transition"] = {
                    "kind": "REFRESH",
                    "parent_campaign_id": int(current["campaign_id"]),
                    "expected_parent_version": int(current["version"]),
                    "changed_evidence_sha256": "f" * 64,
                    "resolution_action_set_sha256": None,
                    "approval": None,
                }
                with self.assertRaisesRegex(
                    ReadinessError, "READINESS_SUCCESSOR_STATE_CONFLICT"
                ):
                    register(self.h.store.connection, successor, now=NOW)


if __name__ == "__main__":
    unittest.main()
