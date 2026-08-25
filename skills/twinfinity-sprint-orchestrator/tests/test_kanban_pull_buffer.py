from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationStore  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    PullBufferError,
    audit_pull_buffer,
    register_candidate,
)
from portfolio_graph import replace_graph, sync_head  # noqa: E402


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "1" * 40


class KanbanPullBufferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "coordinator"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        self.sources: dict[int, str] = {}
        self._issue(115, "Sprint 1")
        self._issue(251, "Sprint 2")
        self._issue(76, "Sprint 2")
        self._item(115, "QUEUED")
        self._item(251, "PREPARED")
        self._item(76, "HOLD")
        replace_graph(
            self.store.connection,
            self._plan(),
            now="2026-08-24T02:00:01Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _issue(self, number: int, milestone: str) -> None:
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=number,
            payload={
                "_projection_version": 3,
                "number": number,
                "title": f"Issue {number}",
                "state": "open",
                "updated_at": "2026-08-24T02:00:00Z",
                "milestone": {"number": 1, "title": milestone, "state": "open"},
            },
            source_updated_at="2026-08-24T02:00:00Z",
            fetched_at="2026-08-24T02:00:00Z",
        )
        self.sources[number] = snapshot.payload_sha256

    def _item(self, number: int, status: str) -> None:
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=number,
            status=status,
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=self.sources[number],
            expected_version=0,
            now="2026-08-24T02:00:01Z",
        )

    def _node(self, number: int, lane: str, order: int) -> dict:
        return {
            "node_key": f"issue:{number}",
            "issue_number": number,
            "role": "DELIVERY",
            "root_kind": "STANDALONE",
            "root_reason": "Independent test outcome",
            "lane_key": lane,
            "lane_order": order,
            "dispatchable": True,
            "priority_rank": order + 1,
            "estimate_units": 1,
            "development_units": 1,
            "shared_units": 1,
            "sre_units": 0,
            "source_payload_sha256": self.sources[number],
            "ready_at": "2026-08-24T02:00:00Z",
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
                self._node(115, "gate-a", 0),
                self._node(251, "studio-wave3a", 0),
                self._node(76, "durable-jobs", 0),
            ],
            "relations": [
                {
                    "left_node_key": "issue:251",
                    "right_node_key": "issue:76",
                    "relation_kind": "COLLISION",
                    "reason": "Shared migration family",
                    "source_payload_sha256": self.sources[251],
                }
            ],
        }

    def _packet(self, number: int, verticality: str, mutator=None) -> Path:
        item = self.store.connection.execute(
            "SELECT version FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, number),
        ).fetchone()
        packet = {
            "schema": "twinfinity-kanban-pull-buffer/v2",
            "repository": REPOSITORY,
            "issue_number": number,
            "generation": 1,
            "item_version_at_preparation": int(item["version"]),
            "source_payload_sha256": self.sources[number],
            "accepted_main_at_preparation": MAIN,
            "portfolio_graph_version": 1,
            "capacity_policy": {
                "version": 1,
                "development_limit": 5,
                "shared_limit": 2,
                "sre_limit": 5,
            },
            "state": "PREPARED_NOT_READY",
            "verticality": verticality,
            "owner_visible_outcome": f"Outcome {number}",
            "capacity_on_activation": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
            "precomputed_collision_matrix": [
                {
                    "other_issue": 76 if number != 76 else 251,
                    "disposition": "AUDIT",
                    "reason": "Exact path audit required",
                }
            ],
            "preparation_complete": ["Outcome and activation trigger are explicit."],
            "promotion_checks_after_predecessor": ["Refresh main and lease."],
            "hard_stops": ["No mutation before admission."],
            "promotion_trigger": "Promote after predecessor terminal release.",
        }
        if verticality == "BOUNDED_ENABLER":
            packet["immediate_product_consumer"] = "Issue #298"
        if mutator is not None:
            mutator(packet)
        plans = self.root / "plans"
        plans.mkdir(exist_ok=True)
        path = plans / f"issue-{number}-packet.json"
        path.write_text(json.dumps(packet, sort_keys=True), encoding="utf-8")
        self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": number,
                    "generation": 1,
                    "path": str(path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-24T02:00:02Z",
        )
        return path

    def test_two_distinct_registered_candidates_are_healthy_and_idempotent(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(251, "END_TO_END"),
            now="2026-08-24T02:00:04Z",
        )
        first = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:05Z",
        )
        second = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:06Z",
        )
        self.assertEqual("PULL_BUFFER_DEFICIT", first["state"])
        self.assertEqual([115, 251], [item["issue_number"] for item in first["selected"]])
        self.assertEqual(2, first["reviewed_candidate_depth"])
        self.assertEqual(2, first["prepared_or_queued_depth"])
        self.assertEqual(0, first["executable_ready_depth"])
        self.assertEqual(0, first["dispatchable_now_depth"])
        self.assertIn("READY_DEPTH_ZERO", first["deficit_reasons"])
        self.assertEqual(first["audit_sha256"], second["audit_sha256"])
        count = self.store.connection.execute(
            "SELECT COUNT(*) FROM portfolio_pull_buffer_audits"
        ).fetchone()[0]
        self.assertEqual(1, count)
        triggers = {
            json.loads(row[0])["trigger_kind"]
            for row in self.store.connection.execute(
                "SELECT payload_json FROM portfolio_dirty_events"
            )
        }
        self.assertEqual({"CANDIDATE_REGISTERED"}, triggers)

    def test_ready_registration_fails_closed_on_incomplete_admission(self) -> None:
        current = self.store.connection.execute(
            "SELECT version FROM coordination_items WHERE repository=? AND issue_number=251",
            (REPOSITORY,),
        ).fetchone()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=251,
            status="READY",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=self.sources[251],
            expected_version=int(current["version"]),
            now="2026-08-24T02:00:02Z",
        )
        packet = self._packet(
            251,
            "END_TO_END",
            lambda value: value.update(
                {
                    "state": "READY",
                    "admission_transaction": {"item": {}, "message": {}},
                }
            ),
        )

        with self.assertRaisesRegex(PullBufferError, "ADMISSION_PACKET_INVALID"):
            register_candidate(
                self.store.connection,
                self.database,
                packet,
                now="2026-08-24T02:00:03Z",
            )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current WHERE issue_number=251"
            ).fetchone()[0],
        )

    def test_missing_second_lane_records_typed_deficit(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:05Z",
        )
        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        self.assertEqual(
            ["PULL_BUFFER_DEPTH_1_OF_2", "READY_DEPTH_ZERO"],
            audit["deficit_reasons"],
        )

    def test_main_and_policy_drift_invalidate_registered_candidates(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(251, "END_TO_END"),
            now="2026-08-24T02:00:04Z",
        )
        self.store.set_capacity_policy(
            repository=REPOSITORY,
            development_limit=6,
            shared_limit=3,
            sre_limit=5,
            authority_sha256="a" * 64,
            expected_version=1,
            now="2026-08-24T02:00:05Z",
        )
        sync_head(
            self.store.connection,
            REPOSITORY,
            "2" * 40,
            now="2026-08-24T02:00:06Z",
        )
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=False,
            now="2026-08-24T02:00:07Z",
        )
        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        reasons = {reason for item in audit["invalid"] for reason in item["reasons"]}
        self.assertTrue({"MAIN_DRIFT", "CAPACITY_POLICY_DRIFT"} <= reasons)
        self.assertNotIn("GRAPH_STALE", reasons)
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_retirements"
            ).fetchone()[0],
        )

    def test_topology_review_staleness_retires_current_pointer(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        changed = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=115,
            payload={
                "_projection_version": 3,
                "number": 115,
                "title": "Issue 115 changed during topology review",
                "state": "open",
                "updated_at": "2026-08-24T02:00:04Z",
                "milestone": {"number": 1, "title": "Sprint 1", "state": "open"},
            },
            source_updated_at="2026-08-24T02:00:04Z",
            fetched_at="2026-08-24T02:00:04Z",
        )
        self.sources[115] = changed.payload_sha256
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:05Z",
        )

        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        self.assertIn("GRAPH_STALE", audit["invalid"][0]["reasons"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )

    def test_audit_reopens_artifact_and_retires_inode_replacement(self) -> None:
        packet_path = self._packet(115, "BOUNDED_ENABLER")
        register_candidate(
            self.store.connection,
            self.database,
            packet_path,
            now="2026-08-24T02:00:03Z",
        )
        original = packet_path.read_bytes()
        preserved = packet_path.with_suffix(".preserved")
        packet_path.rename(preserved)
        packet_path.write_bytes(original)

        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:04Z",
        )

        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        self.assertEqual(["ARTIFACT_DRIFT"], audit["invalid"][0]["reasons"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )
        retirement = self.store.connection.execute(
            "SELECT reasons_json FROM portfolio_pull_buffer_retirements"
        ).fetchone()[0]
        self.assertEqual('["ARTIFACT_DRIFT"]', retirement)

    def test_item_activation_retires_candidate_but_preserves_candidate_history(self) -> None:
        packet_path = self._packet(115, "BOUNDED_ENABLER")
        register_candidate(
            self.store.connection,
            self.database,
            packet_path,
            now="2026-08-24T02:00:03Z",
        )
        self.store.connection.execute(
            "UPDATE coordination_items SET status='ACTIVE', allocation_class='ACTIVE', "
            "version=version+1 WHERE repository=? AND issue_number=115",
            (REPOSITORY,),
        )
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=False,
            now="2026-08-24T02:00:04Z",
        )
        reasons = set(audit["invalid"][0]["reasons"])
        self.assertEqual({"ITEM_VERSION_DRIFT", "NOT_ZERO_WIP_PREP"}, reasons)
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )
        self.store.connection.execute(
            "UPDATE coordination_items SET status='QUEUED', allocation_class='NONE', "
            "version=1 WHERE repository=? AND issue_number=115",
            (REPOSITORY,),
        )
        with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_CANDIDATE_RETIRED"):
            register_candidate(
                self.store.connection,
                self.database,
                packet_path,
                now="2026-08-24T02:00:05Z",
            )

    def test_duplicate_packet_key_fails_before_registration(self) -> None:
        plans = self.root / "plans"
        plans.mkdir(exist_ok=True)
        path = plans / "duplicate.json"
        path.write_text(
            '{"schema":"twinfinity-kanban-pull-buffer/v2",'
            '"schema":"twinfinity-kanban-pull-buffer/v2"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_PACKET_DUPLICATE_KEY"):
            register_candidate(
                self.store.connection,
                self.database,
                path,
                now="2026-08-24T02:00:03Z",
            )
        self.assertFalse(self.store.connection.in_transaction)

    def test_unknown_top_level_and_nested_keys_fail_closed(self) -> None:
        top_level = self._packet(
            115,
            "BOUNDED_ENABLER",
            lambda packet: packet.update({"unexpected": "not allowed"}),
        )
        with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_PACKET_INVALID"):
            register_candidate(
                self.store.connection,
                self.database,
                top_level,
                now="2026-08-24T02:00:03Z",
            )

        nested = self._packet(
            251,
            "END_TO_END",
            lambda packet: packet["capacity_policy"].update({"unexpected": 1}),
        )
        with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_PACKET_INVALID"):
            register_candidate(
                self.store.connection,
                self.database,
                nested,
                now="2026-08-24T02:00:04Z",
            )

    def test_final_descriptor_link_count_drift_rolls_back_registration(self) -> None:
        packet_path = self._packet(115, "BOUNDED_ENABLER")
        real_fstat = __import__("os").fstat
        calls = 0

        def drifting_fstat(descriptor):
            nonlocal calls
            calls += 1
            observed = real_fstat(descriptor)
            if calls < 5:
                return observed
            return SimpleNamespace(
                st_mode=observed.st_mode,
                st_uid=observed.st_uid,
                st_nlink=2,
                st_size=observed.st_size,
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
            )

        with patch("kanban_pull_buffer.os.fstat", side_effect=drifting_fstat):
            with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_ARTIFACT_DRIFT"):
                register_candidate(
                    self.store.connection,
                    self.database,
                    packet_path,
                    now="2026-08-24T02:00:03Z",
                )
        self.assertFalse(self.store.connection.in_transaction)
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates"
            ).fetchone()[0],
        )


if __name__ == "__main__":
    unittest.main()
