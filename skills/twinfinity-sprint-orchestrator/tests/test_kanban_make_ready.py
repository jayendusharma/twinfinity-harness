from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationStore  # noqa: E402
from kanban_make_ready import sweep  # noqa: E402
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import ensure_schema as ensure_readiness_schema  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
NOW = "2026-08-27T20:00:00Z"


class MakeReadyHarness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "coordination"
        root.mkdir(mode=0o700)
        self.database = root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        config = apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            Path(__file__).resolve().parents[1],
            operation_key="kanban-make-ready-tests",
            now=NOW,
        )
        self.endpoints = {
            role: endpoint.endpoint_id for role, endpoint in config.roles.items()
        }
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        self.sources: dict[int, str] = {}
        self.items: dict[int, dict] = {}

    def close(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def add_issue(self, issue_number: int) -> None:
        source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue_number,
            payload={
                "_projection_version": 3,
                "number": issue_number,
                "title": f"Issue {issue_number}",
                "state": "open",
                "updated_at": NOW,
                "milestone": {
                    "number": 1,
                    "title": "Sprint",
                    "state": "open",
                },
            },
            source_updated_at=NOW,
            fetched_at=NOW,
        )
        self.sources[issue_number] = source.payload_sha256
        self.items[issue_number] = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=issue_number,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now=NOW,
        )

    def install_graph(
        self,
        nodes: list[dict],
        relations: list[dict] | None = None,
    ) -> None:
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
                        "node_key": node.get(
                            "node_key", f"issue:{node['issue_number']}"
                        ),
                        "issue_number": node["issue_number"],
                        "role": node.get("role", "DELIVERY"),
                        "root_kind": node.get("root_kind", "STANDALONE"),
                        "root_reason": (
                            None
                            if node.get("root_kind") == "NORMAL"
                            else "Focused make-ready fixture"
                        ),
                        "lane_key": node.get(
                            "lane_key", f"lane-{node['issue_number']}"
                        ),
                        "lane_order": node.get("lane_order", 0),
                        "dispatchable": node.get("dispatchable", True),
                        "priority_rank": node["priority_rank"],
                        "estimate_units": 1,
                        "development_units": 1,
                        "shared_units": 0,
                        "sre_units": 0,
                        "source_payload_sha256": self.sources[
                            node["issue_number"]
                        ],
                        "ready_at": node.get("ready_at", NOW),
                    }
                    for node in nodes
                ],
                "relations": relations or [],
            },
            now=NOW,
        )

    def add_prepared_candidate(self, issue_number: int) -> str:
        item = self.items[issue_number]
        graph = self.store.connection.execute(
            "SELECT version FROM portfolio_graph_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        policy = self.store.connection.execute(
            "SELECT version FROM coordination_capacity_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        candidate_sha256 = hashlib.sha256(
            f"candidate:{issue_number}".encode()
        ).hexdigest()
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED_NOT_READY',
                          'END_TO_END', 1, 0, 0, 'Complete readiness', ?, ?, ?, ?)
                """,
                (
                    REPOSITORY,
                    issue_number,
                    int(item["generation"]),
                    int(item["version"]),
                    self.sources[issue_number],
                    MAIN,
                    int(graph["version"]),
                    int(policy["version"]),
                    f"lane-{issue_number}",
                    f"plans/issue-{issue_number}.json",
                    "c" * 64,
                    candidate_sha256,
                    NOW,
                ),
            )
            self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_current(
                    repository, issue_number, candidate_id, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (REPOSITORY, issue_number, int(cursor.lastrowid), NOW),
            )
        return candidate_sha256


class KanbanMakeReadyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = MakeReadyHarness()

    def tearDown(self) -> None:
        self.h.close()

    def test_ranked_missing_packet_and_plan_notices_are_idempotent(self) -> None:
        for issue_number in (1, 2, 3):
            self.h.add_issue(issue_number)
        self.h.install_graph(
            [
                {"issue_number": 1, "priority_rank": 3},
                {"issue_number": 2, "priority_rank": 1},
                {"issue_number": 3, "priority_rank": 2},
            ]
        )
        self.h.add_prepared_candidate(3)

        first = sweep(
            self.h.store,
            REPOSITORY,
            max_candidates=2,
            now=NOW,
        )
        counts_after_first = tuple(
            self.h.store.connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM coordination_messages),
                  (SELECT COUNT(*) FROM coordination_events)
                """
            ).fetchone()
        )
        second = sweep(
            self.h.store,
            REPOSITORY,
            max_candidates=2,
            now="2026-08-27T20:01:00Z",
        )
        counts_after_second = tuple(
            self.h.store.connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM coordination_messages),
                  (SELECT COUNT(*) FROM coordination_events)
                """
            ).fetchone()
        )

        self.assertEqual([2, 3], [item["issue_number"] for item in first["planned"]])
        self.assertEqual(
            ["PACKET_MISSING", "PLAN_MISSING"],
            [item["need"] for item in first["planned"]],
        )
        self.assertEqual(
            [item["message_id"] for item in first["planned"]],
            [item["message_id"] for item in second["planned"]],
        )
        self.assertEqual(["REUSED", "REUSED"], [item["state"] for item in second["planned"]])
        self.assertEqual(counts_after_first, counts_after_second)

        payloads = [
            json.loads(row["payload_json"])
            for row in self.h.store.connection.execute(
                "SELECT payload_json FROM coordination_messages ORDER BY id"
            )
        ]
        self.assertEqual(
            ["PACKET_MISSING", "PLAN_MISSING"],
            [payload["evidence"]["need"] for payload in payloads],
        )
        self.assertTrue(
            all(
                payload["notice_kind"] == "planning_request"
                and payload["mutation_authority"] is False
                and payload["evidence"]["accepted_main_sha"] == MAIN
                and payload["evidence"]["campaign_state"] == "MISSING"
                and payload["evidence"]["planner_endpoint_id"]
                for payload in payloads
            )
        )

    def test_duplicate_issue_nodes_use_one_notice_and_one_slot(self) -> None:
        for issue_number in (1, 2):
            self.h.add_issue(issue_number)
        self.h.install_graph(
            [
                {
                    "issue_number": 1,
                    "node_key": "issue:1:first",
                    "priority_rank": 1,
                    "lane_key": "duplicate",
                    "lane_order": 0,
                },
                {
                    "issue_number": 1,
                    "node_key": "issue:1:second",
                    "priority_rank": 1,
                    "lane_key": "duplicate",
                    "lane_order": 1,
                },
                {"issue_number": 2, "priority_rank": 2},
            ]
        )

        result = sweep(
            self.h.store,
            REPOSITORY,
            max_candidates=2,
            now=NOW,
        )

        self.assertEqual([1, 2], [item["issue_number"] for item in result["planned"]])
        self.assertEqual(
            ["issue:1:first", "issue:2"],
            [item["node_key"] for item in result["planned"]],
        )
        self.assertEqual(
            2,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )

    def test_hard_predecessor_is_a_typed_no_write_skip(self) -> None:
        for issue_number in (10, 11):
            self.h.add_issue(issue_number)
        self.h.install_graph(
            [
                {
                    "issue_number": 10,
                    "priority_rank": 1,
                    "role": "MONITOR",
                    "root_kind": "INTENTIONAL",
                    "dispatchable": False,
                },
                {
                    "issue_number": 11,
                    "priority_rank": 2,
                    "root_kind": "NORMAL",
                },
            ],
            [
                {
                    "left_node_key": "issue:10",
                    "right_node_key": "issue:11",
                    "relation_kind": "HARD_BLOCK",
                    "reason": "Issue 10 must finish first",
                    "source_payload_sha256": self.h.sources[10],
                }
            ],
        )

        result = sweep(
            self.h.store,
            REPOSITORY,
            max_candidates=2,
            now=NOW,
        )

        self.assertEqual([], result["planned"])
        self.assertIn(
            (11, "HARD_PREDECESSOR_UNSATISFIED"),
            {
                (item["issue_number"], item["reason"])
                for item in result["skipped"]
            },
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )


if __name__ == "__main__":
    unittest.main()
