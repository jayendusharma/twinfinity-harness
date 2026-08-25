from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationError, CoordinationStore  # noqa: E402
import portfolio_graph  # noqa: E402
from portfolio_graph import (  # noqa: E402
    PortfolioGraphError,
    evaluate_graph,
    replace_graph,
    schedule,
    sync_head,
)
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "1" * 40
SESSION = "role.development.v4"


class PortfolioGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name) / "coordinator"
        directory.mkdir(mode=0o700)
        self.database = directory / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="portfolio-graph-tests",
        )
        self.sources: dict[int, str] = {}
        self._issue(58, "Sprint 1")
        self._issue(115, "Sprint 2")
        self._issue(320, "Sprint 2")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _issue(
        self,
        number: int,
        milestone: str,
        *,
        updated_at: str = "2026-08-22T10:00:00Z",
        state: str = "open",
    ) -> str:
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=number,
            payload={
                "_projection_version": 3,
                "number": number,
                "title": f"Issue {number}",
                "state": state,
                "updated_at": updated_at,
                "milestone": {"number": 1, "title": milestone, "state": "open"},
            },
            source_updated_at=updated_at,
            fetched_at=updated_at,
        )
        self.sources[number] = snapshot.payload_sha256
        return snapshot.payload_sha256

    def _node(
        self,
        number: int,
        *,
        role: str,
        root_kind: str,
        lane: str,
        order: int,
        priority: int = 1,
        development: int = 1,
        shared: int = 0,
        ready_at: str = "2026-08-22T10:00:00Z",
    ) -> dict:
        return {
            "node_key": f"issue:{number}",
            "issue_number": number,
            "role": role,
            "root_kind": root_kind,
            "root_reason": (
                f"Explicit {root_kind.lower()} portfolio root"
                if root_kind != "NORMAL"
                else None
            ),
            "lane_key": lane,
            "lane_order": order,
            "dispatchable": role not in {"MONITOR", "TRACKER", "EPIC"},
            "priority_rank": priority,
            "estimate_units": 1,
            "development_units": development,
            "shared_units": shared,
            "sre_units": 0,
            "source_payload_sha256": self.sources[number],
            "ready_at": ready_at,
        }

    def _plan(self) -> dict:
        return {
            "repository": REPOSITORY,
            "accepted_main_sha": MAIN,
            "expected_current_version": 0,
            "scope_milestones": [
                {"title": "Sprint 1", "rank": 1},
                {"title": "Sprint 2", "rank": 2},
            ],
            "excluded_issues": [],
            "nodes": [
                self._node(
                    58,
                    role="SERIAL_GATE",
                    root_kind="INTENTIONAL",
                    lane="studio",
                    order=0,
                    shared=1,
                ),
                self._node(
                    115,
                    role="DELIVERY",
                    root_kind="NORMAL",
                    lane="studio",
                    order=1,
                    shared=1,
                ),
                self._node(
                    320,
                    role="CONTROL",
                    root_kind="STANDALONE",
                    lane="sre",
                    order=0,
                    priority=2,
                ),
            ],
            "relations": [
                {
                    "left_node_key": "issue:58",
                    "right_node_key": "issue:115",
                    "relation_kind": "HARD_BLOCK",
                    "reason": "Serialized product outcome",
                    "source_payload_sha256": self.sources[58],
                },
                {
                    "left_node_key": "issue:320",
                    "right_node_key": "issue:58",
                    "relation_kind": "COLLISION",
                    "reason": "Shared semantic CI surface",
                    "source_payload_sha256": self.sources[320],
                },
            ],
        }

    def _status(
        self,
        number: int,
        status: str,
        allocation: str = "NONE",
        *,
        version: int = 0,
        generation: int = 1,
        development: int = 1,
        shared: int = 0,
    ) -> dict:
        setter = (
            self.store._set_issue_status_for_test_fixture
            if status == "READY"
            else self.store.set_issue_status
        )
        return setter(
            repository=REPOSITORY,
            issue_number=number,
            status=status,
            allocation_class=allocation,
            generation=generation,
            accountable_session_id=SESSION if allocation != "NONE" else None,
            lease_manifest_sha256=(
                hashlib.sha256(f"lease:{number}:{generation}".encode()).hexdigest()
                if allocation != "NONE"
                else None
            ),
            development_units=development,
            shared_units=shared,
            sre_units=0,
            expected_source_sha256=self.sources[number],
            expected_version=version,
            now="2026-08-22T10:01:00Z",
        )

    def test_replace_is_atomic_versioned_and_reports_cross_milestone_edges(self) -> None:
        result = replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self.assertEqual((1, 3, 2), (
            result["version"], result["node_count"], result["relation_count"]
        ))
        evaluated = evaluate_graph(
            self.store.connection, REPOSITORY, current_main=MAIN
        )
        self.assertEqual("CURRENT", evaluated["health"])
        self.assertEqual([], evaluated["milestone_inversions"])

        cycle = self._plan()
        cycle["expected_current_version"] = 1
        cycle["relations"].append(
            {
                "left_node_key": "issue:115",
                "right_node_key": "issue:58",
                "relation_kind": "HARD_BLOCK",
                "reason": "Invalid cycle",
                "source_payload_sha256": self.sources[115],
            }
        )
        with self.assertRaisesRegex(PortfolioGraphError, "GRAPH_CYCLE"):
            replace_graph(
                self.store.connection, cycle, now="2026-08-22T10:03:00Z"
            )
        current = self.store.connection.execute(
            "SELECT version FROM portfolio_graph_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(1, current["version"])

    def test_actionable_orphan_is_rejected(self) -> None:
        plan = self._plan()
        plan["nodes"][1]["root_kind"] = "NORMAL"
        plan["relations"] = [
            relation
            for relation in plan["relations"]
            if relation["relation_kind"] != "HARD_BLOCK"
        ]
        with self.assertRaisesRegex(PortfolioGraphError, "GRAPH_ACTIONABLE_ORPHAN"):
            replace_graph(
                self.store.connection, plan, now="2026-08-22T10:02:00Z"
            )

    def test_adjacent_unmilestoned_issue_can_be_represented(self) -> None:
        self._issue(298, "Adjacent", updated_at="2026-08-22T09:00:00Z")
        payload = json.loads(
            self.store.connection.execute(
                """
                SELECT s.payload_json FROM github_current c JOIN github_snapshots s
                ON s.repository=c.repository AND s.object_kind=c.object_kind
                AND s.object_number=c.object_number AND s.payload_sha256=c.payload_sha256
                WHERE c.repository=? AND c.object_kind='issue' AND c.object_number=298
                """,
                (REPOSITORY,),
            ).fetchone()["payload_json"]
        )
        payload["milestone"] = None
        self.sources[298] = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=298,
            payload=payload,
            source_updated_at="2026-08-22T09:01:00Z",
            fetched_at="2026-08-22T09:01:00Z",
        ).payload_sha256
        plan = self._plan()
        plan["nodes"].append(
            self._node(
                298,
                role="CONTROL",
                root_kind="STANDALONE",
                lane="adjacent",
                order=0,
            )
        )
        result = replace_graph(
            self.store.connection, plan, now="2026-08-22T10:02:00Z"
        )
        self.assertEqual(4, result["node_count"])

    def test_dependency_aware_fifo_skips_collision_without_head_of_line_blocking(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._status(58, "READY", shared=1)
        self._status(115, "QUEUED", shared=1)
        self._status(320, "READY")
        decision = schedule(
            self.store.connection,
            REPOSITORY,
            current_main=MAIN,
            record=True,
            now="2026-08-22T10:03:00Z",
        )
        self.assertEqual(["issue:58"], decision["selected"])
        self.assertEqual(
            [{"node_key": "issue:320", "reason": "COLLISION"}],
            decision["skipped"],
        )
        events = self.store.connection.execute(
            "SELECT COUNT(*) FROM portfolio_scheduler_events"
        ).fetchone()[0]
        self.assertGreaterEqual(events, 3)

    def test_recorded_schedule_reads_and_writes_under_one_immediate_transaction(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._status(58, "READY", shared=1)
        original = portfolio_graph._capacity_policy

        def assert_locked(connection, repository):
            self.assertTrue(connection.in_transaction)
            return original(connection, repository)

        with patch("portfolio_graph._capacity_policy", side_effect=assert_locked):
            decision = schedule(
                self.store.connection,
                REPOSITORY,
                current_main=MAIN,
                record=True,
                now="2026-08-22T10:03:00Z",
            )
        self.assertEqual(["issue:58"], decision["selected"])
        self.assertFalse(self.store.connection.in_transaction)

    def test_scheduler_reselects_against_revised_capacity_policy(self) -> None:
        plan = self._plan()
        plan["relations"] = [
            relation
            for relation in plan["relations"]
            if relation["relation_kind"] != "COLLISION"
        ]
        plan["nodes"][0]["development_units"] = 3
        plan["nodes"][0]["shared_units"] = 2
        plan["nodes"][2]["development_units"] = 3
        plan["nodes"][2]["shared_units"] = 1
        replace_graph(self.store.connection, plan, now="2026-08-22T10:02:00Z")
        self._status(58, "READY", development=3, shared=2)
        self._status(320, "READY", development=3, shared=1)
        default = schedule(
            self.store.connection,
            REPOSITORY,
            current_main=MAIN,
            record=False,
            now="2026-08-22T10:03:00Z",
        )
        self.assertEqual(["issue:58"], default["selected"])
        self.assertEqual(1, default["capacity_policy_version"])

        revised = self.store.set_capacity_policy(
            repository=REPOSITORY,
            development_limit=6,
            shared_limit=3,
            sre_limit=5,
            authority_sha256="d" * 64,
            expected_version=1,
            now="2026-08-22T10:04:00Z",
        )
        self.assertEqual(2, revised["version"])
        expanded = schedule(
            self.store.connection,
            REPOSITORY,
            current_main=MAIN,
            record=False,
            now="2026-08-22T10:05:00Z",
        )
        self.assertEqual(["issue:58", "issue:320"], expanded["selected"])
        self.assertEqual(2, expanded["capacity_policy_version"])

    def test_scheduler_counts_hosted_sre_reservations(self) -> None:
        plan = self._plan()
        plan["nodes"][2]["development_units"] = 0
        plan["nodes"][2]["sre_units"] = 1
        replace_graph(self.store.connection, plan, now="2026-08-22T10:02:00Z")
        self.store.connection.execute(
            "CREATE TABLE hosted_operations (repository TEXT, state TEXT, sre_units INTEGER)"
        )
        self.store.connection.execute(
            "INSERT INTO hosted_operations(repository, state, sre_units) VALUES (?, 'CLAIMED', 5)",
            (REPOSITORY,),
        )
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=320,
            status="READY",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=0,
            shared_units=0,
            sre_units=1,
            expected_source_sha256=self.sources[320],
            expected_version=0,
            now="2026-08-22T10:02:30Z",
        )
        decision = schedule(
            self.store.connection,
            REPOSITORY,
            current_main=MAIN,
            record=False,
            now="2026-08-22T10:03:00Z",
        )
        self.assertEqual([], decision["selected"])
        self.assertEqual(
            [{"node_key": "issue:320", "reason": "SRE_CAPACITY"}],
            decision["skipped"],
        )
        self.assertEqual(0, decision["remaining_capacity"]["sre"])

    def test_serial_gate_cannot_be_stably_parked_with_unfinished_descendants(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        with self.assertRaisesRegex(CoordinationError, "GRAPH_SERIAL_GATE_PARKED"):
            self._status(58, "QUEUED")

    def test_hard_successor_cannot_be_ready_before_gate_is_done(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._status(58, "HOLD", "RETAINED", shared=1)
        evaluated = evaluate_graph(
            self.store.connection, REPOSITORY, current_main=MAIN
        )
        self.assertEqual(["issue:58"], evaluated["critical_path_holds"])
        with self.assertRaisesRegex(
            CoordinationError, "GRAPH_HARD_PREDECESSOR_UNSATISFIED"
        ):
            self._status(115, "READY", shared=1)

    def test_active_collision_is_rejected_by_transition_guard(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._status(320, "HOLD", "RETAINED")
        with self.assertRaisesRegex(CoordinationError, "GRAPH_COLLISION_ACTIVE:320"):
            self._status(58, "ACTIVE", "ACTIVE", shared=1)

    def test_source_change_marks_graph_stale(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._issue(
            58,
            "Sprint 1",
            updated_at="2026-08-22T10:05:00Z",
        )
        evaluated = evaluate_graph(
            self.store.connection, REPOSITORY, current_main=MAIN
        )
        self.assertEqual("STALE", evaluated["health"])
        self.assertIn("GRAPH_SOURCE_DRIFT", evaluated["stale_reasons"])

    def test_stale_graph_does_not_retain_closed_wip_capacity(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        retained = self._status(58, "HOLD", "RETAINED", shared=1)
        self._issue(58, "Sprint 1", updated_at="2026-08-22T10:05:00Z", state="closed")

        released = self._status(
            58,
            "DONE",
            "NONE",
            version=retained["version"],
            generation=retained["generation"] + 1,
            development=0,
            shared=0,
        )

        self.assertEqual("DONE", released["status"])
        self.assertEqual("NONE", released["allocation_class"])

    def test_stale_graph_still_blocks_release_for_open_issue(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        retained = self._status(58, "HOLD", "RETAINED", shared=1)
        self._issue(58, "Sprint 1", updated_at="2026-08-22T10:05:00Z")

        with self.assertRaisesRegex(CoordinationError, "GRAPH_STALE"):
            self._status(
                58,
                "DONE",
                "NONE",
                version=retained["version"],
                generation=retained["generation"] + 1,
                development=0,
                shared=0,
            )

    def test_new_open_issue_in_scope_marks_graph_stale(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._issue(251, "Sprint 1", updated_at="2026-08-22T10:05:00Z")
        health = self.store.connection.execute(
            "SELECT health,last_error FROM portfolio_graph_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(
            ("STALE", "GRAPH_SCOPE_INVENTORY_DRIFT"),
            (health["health"], health["last_error"]),
        )

    def test_existing_issue_moved_into_scope_marks_graph_stale(self) -> None:
        self._issue(251, "Later", updated_at="2026-08-22T09:00:00Z")
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._issue(251, "Sprint 1", updated_at="2026-08-22T10:05:00Z")
        health = self.store.connection.execute(
            "SELECT health FROM portfolio_graph_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("STALE", health["health"])

    def test_sync_head_does_not_clear_existing_source_staleness(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        self._issue(251, "Sprint 1", updated_at="2026-08-22T10:05:00Z")

        result = sync_head(
            self.store.connection, REPOSITORY, MAIN, now="2026-08-22T10:06:00Z"
        )
        current = self.store.connection.execute(
            "SELECT health,last_error FROM portfolio_graph_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("STALE", result["health"])
        self.assertEqual(
            ("STALE", "GRAPH_SCOPE_INVENTORY_DRIFT"),
            (current["health"], current["last_error"]),
        )

    def test_main_only_cursor_advance_preserves_reviewed_topology(self) -> None:
        replace_graph(
            self.store.connection, self._plan(), now="2026-08-22T10:02:00Z"
        )
        advanced = "2" * 40

        result = sync_head(
            self.store.connection,
            REPOSITORY,
            advanced,
            now="2026-08-22T10:03:00Z",
        )
        evaluation = evaluate_graph(
            self.store.connection, REPOSITORY, current_main=advanced
        )
        current = self.store.connection.execute(
            """
            SELECT c.health, c.observed_main_sha, r.accepted_main_sha
            FROM portfolio_graph_current c
            JOIN portfolio_graph_revisions r
              ON r.repository=c.repository AND r.version=c.version
            WHERE c.repository=?
            """,
            (REPOSITORY,),
        ).fetchone()

        self.assertEqual("CURRENT", result["health"])
        self.assertEqual("CURRENT", evaluation["health"])
        self.assertEqual(("CURRENT", advanced, MAIN), tuple(current))
        dirty = self.store.connection.execute(
            "SELECT payload_json FROM portfolio_dirty_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(
            "MAIN_CURSOR_ADVANCED",
            json.loads(dirty["payload_json"])["trigger_kind"],
        )

    def test_topology_digest_excludes_accepted_main_but_keeps_provenance(self) -> None:
        first = replace_graph(
            self.store.connection,
            self._plan(),
            now="2026-08-22T10:02:00Z",
        )
        successor = self._plan()
        successor["accepted_main_sha"] = "3" * 40
        successor["expected_current_version"] = 1
        second = replace_graph(
            self.store.connection,
            successor,
            now="2026-08-22T10:03:00Z",
        )
        revisions = self.store.connection.execute(
            "SELECT accepted_main_sha, graph_sha256 FROM portfolio_graph_revisions "
            "WHERE repository=? ORDER BY version",
            (REPOSITORY,),
        ).fetchall()

        self.assertEqual(first["graph_sha256"], second["graph_sha256"])
        self.assertEqual(
            [MAIN, "3" * 40],
            [row["accepted_main_sha"] for row in revisions],
        )

    def test_closed_github_issue_with_nonterminal_item_does_not_release_successor(self) -> None:
        plan = self._plan()
        replace_graph(self.store.connection, plan, now="2026-08-22T10:00:01Z")
        self._status(58, "HOLD", "RETAINED", shared=1)
        closed = self._issue(
            58,
            "Sprint 1",
            updated_at="2026-08-22T10:00:03Z",
            state="closed",
        )
        plan["expected_current_version"] = 1
        plan["nodes"][0]["source_payload_sha256"] = closed
        replace_graph(self.store.connection, plan, now="2026-08-22T10:00:04Z")

        result = evaluate_graph(self.store.connection, REPOSITORY, current_main=MAIN)
        by_issue = {node["issue_number"]: node for node in result["nodes"]}
        self.assertFalse(by_issue[58]["terminal"])
        self.assertEqual(["issue:58"], by_issue[115]["blocked_by"])

    def test_closed_github_issue_without_item_is_terminal(self) -> None:
        closed = self._issue(
            58,
            "Sprint 1",
            updated_at="2026-08-22T10:00:03Z",
            state="closed",
        )
        plan = self._plan()
        plan["nodes"][0]["source_payload_sha256"] = closed
        replace_graph(self.store.connection, plan, now="2026-08-22T10:00:04Z")

        result = evaluate_graph(self.store.connection, REPOSITORY, current_main=MAIN)
        by_issue = {node["issue_number"]: node for node in result["nodes"]}
        self.assertTrue(by_issue[58]["terminal"])
        self.assertEqual([], by_issue[115]["blocked_by"])
        self.assertEqual(0, by_issue[58]["critical_path_units"])


if __name__ == "__main__":
    unittest.main()
