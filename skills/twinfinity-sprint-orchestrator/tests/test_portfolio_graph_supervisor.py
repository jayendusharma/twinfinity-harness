from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationStore, DEFAULT_DATABASE  # noqa: E402
import portfolio_graph_supervisor  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402


REPOSITORY = "twinfinityai/twinfinityapp"
OLD_MAIN = "1" * 40
NEW_MAIN = "2" * 40


class PortfolioGraphSupervisorCliTests(unittest.TestCase):
    def _run_mocked_supervisor(self, *, fail_dispatch: bool = False):
        store = MagicMock()
        current = {
            "version": 1,
            "observed_main_sha": NEW_MAIN,
            "health": "CURRENT",
            "last_error": None,
        }
        store.connection.execute.return_value.fetchone.return_value = current
        decision = {
            "graph_version": 1,
            "capacity_policy_version": 1,
            "selected": [],
            "skipped": [],
            "remaining_capacity": {"development": 5, "shared": 2, "sre": 5},
        }
        pull_buffer = {"audit_sha256": "a" * 64}
        call_order = []

        def dispatch_side_effect(*args, **kwargs):
            call_order.append(("dispatch", kwargs["max_parallel"]))
            if fail_dispatch:
                raise RuntimeError("injected Phase B failure")
            return {
                "active_before": 0,
                "dispatched": [{"issue_number": 1, "message_id": 6}],
                "stale": [],
                "available_after": 1,
            }

        def sweep_side_effect(*args, **kwargs):
            call_order.append(("sweep", kwargs["max_candidates"]))
            return {
                "state": "COMPLETE",
                "planned": [{"issue_number": 2, "message_id": 7}],
                "skipped": [],
                "available_after": 0,
            }

        convergence = MagicMock()
        convergence.consume_due.return_value = []
        with patch.object(
            portfolio_graph_supervisor,
            "CoordinationStore",
            return_value=store,
        ), patch.object(
            portfolio_graph_supervisor,
            "PortfolioConvergence",
            return_value=convergence,
        ), patch.object(
            portfolio_graph_supervisor,
            "evaluate_graph",
            return_value={"health": "CURRENT", "stale_reasons": []},
        ), patch.object(
            portfolio_graph_supervisor,
            "schedule",
            return_value=decision,
        ), patch.object(
            portfolio_graph_supervisor,
            "audit_pull_buffer",
            return_value=pull_buffer,
        ), patch.object(
            portfolio_graph_supervisor,
            "dispatch_readiness",
            side_effect=dispatch_side_effect,
        ), patch.object(
            portfolio_graph_supervisor,
            "sweep_make_ready",
            side_effect=sweep_side_effect,
        ):
            result = portfolio_graph_supervisor.supervise(
                REPOSITORY,
                database=Path("/tmp/unused-mocked-state.sqlite3"),
                refresh=False,
            )
        return result, call_order

    def test_production_cli_rejects_database_override(self) -> None:
        with patch.object(
            sys,
            "argv",
            ["portfolio_graph_supervisor.py", "--database", "/tmp/alternate.sqlite3"],
        ):
            with self.assertRaises(SystemExit):
                portfolio_graph_supervisor.main()

    def test_production_cli_uses_default_database(self) -> None:
        result = {
            "graph_version": 1,
            "capacity_policy_version": 1,
            "state": "SCHEDULED",
            "selected": [],
            "skipped": [],
            "remaining_capacity": {},
            "pull_buffer": {},
            "refresh_count": 0,
        }
        with patch.object(sys, "argv", ["portfolio_graph_supervisor.py", "--no-refresh"]):
            with patch.object(
                portfolio_graph_supervisor, "supervise", return_value=result
            ) as mocked:
                self.assertEqual(0, portfolio_graph_supervisor.main())
        mocked.assert_called_once_with(
            "twinfinityai/twinfinityapp",
            database=DEFAULT_DATABASE,
            refresh=False,
        )

    def test_scheduler_reloads_graph_cursor_after_convergence_advances_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = CoordinationStore(database)
            try:
                source = store.ingest_snapshot(
                    repository=REPOSITORY,
                    object_kind="issue",
                    object_number=1,
                    payload={
                        "_projection_version": 3,
                        "number": 1,
                        "title": "Cursor reload",
                        "state": "open",
                        "updated_at": "2026-08-24T10:00:00Z",
                        "milestone": {"number": 1, "title": "Sprint", "state": "open"},
                    },
                    source_updated_at="2026-08-24T10:00:00Z",
                    fetched_at="2026-08-24T10:00:00Z",
                )
                replace_graph(
                    store.connection,
                    {
                        "repository": REPOSITORY,
                        "accepted_main_sha": OLD_MAIN,
                        "expected_current_version": 0,
                        "scope_milestones": [{"title": "Sprint", "rank": 1}],
                        "excluded_issues": [],
                        "nodes": [
                            {
                                "node_key": "issue:1",
                                "issue_number": 1,
                                "role": "DELIVERY",
                                "root_kind": "STANDALONE",
                                "root_reason": "Cursor regression",
                                "lane_key": "cursor",
                                "lane_order": 0,
                                "dispatchable": True,
                                "priority_rank": 1,
                                "estimate_units": 1,
                                "development_units": 1,
                                "shared_units": 0,
                                "sre_units": 0,
                                "source_payload_sha256": source.payload_sha256,
                                "ready_at": "2026-08-24T10:00:00Z",
                            }
                        ],
                        "relations": [],
                    },
                    now="2026-08-24T10:00:01Z",
                )
            finally:
                store.close()

            observed_cursors: list[tuple[str, str]] = []

            def convergence_advance(instance, *, limit, repository):
                instance.store.connection.execute(
                    "UPDATE portfolio_graph_current SET observed_main_sha=? WHERE repository=?",
                    (NEW_MAIN, repository),
                )
                return [{"state": "COMPLETE", "outcome": "NO_ADMISSION"}]

            def evaluated(connection, repository, *, current_main):
                database_cursor = connection.execute(
                    "SELECT observed_main_sha FROM portfolio_graph_current WHERE repository=?",
                    (repository,),
                ).fetchone()[0]
                observed_cursors.append(("evaluate", current_main))
                self.assertEqual(NEW_MAIN, database_cursor)
                return {"health": "CURRENT", "stale_reasons": []}

            def scheduled(connection, repository, *, current_main, record, now):
                database_cursor = connection.execute(
                    "SELECT observed_main_sha FROM portfolio_graph_current WHERE repository=?",
                    (repository,),
                ).fetchone()[0]
                observed_cursors.append(("schedule", current_main))
                self.assertEqual(NEW_MAIN, database_cursor)
                return {
                    "graph_version": 1,
                    "capacity_policy_version": 1,
                    "selected": [],
                    "skipped": [],
                    "remaining_capacity": {"development": 5, "shared": 2, "sre": 5},
                }

            with patch.object(
                portfolio_graph_supervisor.PortfolioConvergence,
                "consume_due",
                autospec=True,
                side_effect=convergence_advance,
            ), patch.object(
                portfolio_graph_supervisor,
                "evaluate_graph",
                side_effect=evaluated,
            ), patch.object(
                portfolio_graph_supervisor,
                "schedule",
                side_effect=scheduled,
            ), patch.object(
                portfolio_graph_supervisor,
                "audit_pull_buffer",
                return_value={},
            ):
                result = portfolio_graph_supervisor.supervise(
                    REPOSITORY,
                    database=database,
                    refresh=False,
                )

            self.assertEqual(
                [("evaluate", NEW_MAIN), ("schedule", NEW_MAIN)], observed_cursors
            )
            self.assertEqual("SCHEDULED", result["state"])

    def test_pending_readiness_consumes_slots_before_make_ready(self) -> None:
        result, call_order = self._run_mocked_supervisor()

        self.assertEqual([("dispatch", 2), ("sweep", 1)], call_order)
        self.assertEqual("SCHEDULED", result["state"])
        self.assertEqual("COMPLETE", result["kanban_phase_b"]["state"])
        self.assertEqual(
            1,
            result["kanban_phase_b"]["readiness_dispatch"]["available_after"],
        )

    def test_phase_b_failure_preserves_phase_a_result(self) -> None:
        result, call_order = self._run_mocked_supervisor(fail_dispatch=True)
        expected_phase_a = {
            "repository": REPOSITORY,
            "graph_version": 1,
            "capacity_policy_version": 1,
            "state": "SCHEDULED",
            "selected": [],
            "skipped": [],
            "remaining_capacity": {"development": 5, "shared": 2, "sre": 5},
            "pull_buffer": {"audit_sha256": "a" * 64},
            "portfolio_convergence": [],
            "refresh_count": 0,
        }

        self.assertEqual([("dispatch", 2)], call_order)
        self.assertEqual(
            expected_phase_a,
            {key: result[key] for key in expected_phase_a},
        )
        self.assertEqual(
            {"state": "HOLD", "error": "KANBAN_PHASE_B_FAILED"},
            result["kanban_phase_b"],
        )


if __name__ == "__main__":
    unittest.main()
