from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationStore  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
import sync_github_coordination as sync_module  # noqa: E402
from sync_github_coordination import normalize_issue, normalize_pull  # noqa: E402


HARNESS_REPOSITORY = "jayendusharma/twinfinity-harness"
APPLICATION_REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40


class SnapshotNormalizationTests(unittest.TestCase):
    def test_issue_projection_includes_body_and_sorts_labels(self) -> None:
        payload = normalize_issue(
            {
                "number": 92,
                "title": "Issue",
                "body": "Complete issue contract",
                "updated_at": "2026-08-22T10:00:00Z",
                "labels": [
                    {"name": "z", "color": "000000"},
                    {"name": "a", "color": "ffffff"},
                ],
            }
        )
        self.assertEqual(3, payload["_projection_version"])
        self.assertEqual("Complete issue contract", payload["body"])
        self.assertEqual(["a", "z"], [item["name"] for item in payload["labels"]])

    def test_pull_projection_binds_head_reviews_statuses_and_checks(self) -> None:
        payload = normalize_pull(
            {
                "number": 400,
                "title": "PR",
                "body": "Acceptance evidence",
                "updated_at": "2026-08-22T10:00:00Z",
                "head": {"ref": "feature", "sha": "a" * 40, "repo": {"full_name": "o/r"}},
                "base": {"ref": "main", "sha": "b" * 40, "repo": {"full_name": "o/r"}},
            },
            reviews=[
                {
                    "id": 9,
                    "state": "APPROVED",
                    "submitted_at": "2026-08-22T10:01:00Z",
                    "commit_id": "a" * 40,
                    "user": {"login": "reviewer", "id": 1},
                }
            ],
            combined_status={
                "sha": "a" * 40,
                "state": "success",
                "statuses": [{"context": "legacy", "state": "success"}],
            },
            check_runs=[
                {
                    "id": 10,
                    "name": "frontend",
                    "head_sha": "a" * 40,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": "2026-08-22T10:02:00Z",
                    "completed_at": "2026-08-22T10:03:00Z",
                }
            ],
        )
        self.assertEqual(3, payload["_projection_version"])
        self.assertEqual(
            "2026-08-22T10:03:00Z", payload["_projection_updated_at"]
        )
        self.assertEqual("Acceptance evidence", payload["body"])
        self.assertEqual("APPROVED", payload["reviews"][0]["state"])
        self.assertEqual("success", payload["combined_status"]["state"])
        self.assertEqual("frontend", payload["check_runs"][0]["name"])


class PortfolioGraphBootstrapSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "coordination"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def issue(number: int) -> dict:
        return normalize_issue(
            {
                "number": number,
                "title": f"Harness issue {number}",
                "state": "open",
                "updated_at": "2026-08-27T06:00:00Z",
                "milestone": None,
            }
        )

    def run_main(
        self,
        arguments: list[str],
        *,
        main_sha: str = MAIN,
        main_shas: list[str] | None = None,
    ):
        output = io.StringIO()
        observed_main_shas = iter(main_shas or [])

        def github_response(_arguments: list[str]):
            return {
                "object": {
                    "sha": next(observed_main_shas) if main_shas else main_sha
                }
            }

        with (
            patch.object(sync_module, "DEFAULT_DATABASE", self.database),
            patch.object(
                sync_module,
                "_run_gh",
                side_effect=github_response,
            ),
            patch.object(
                sync_module,
                "fetch_object",
                side_effect=lambda _repository, _kind, number: self.issue(number),
            ) as fetch,
            patch.object(sys, "argv", ["sync_github_coordination.py", *arguments]),
            patch("sys.stdout", output),
        ):
            status = sync_module.main()
        return status, json.loads(output.getvalue()), fetch

    def test_absent_graph_bootstrap_fetches_explicit_issue_and_valid_main(self) -> None:
        status, payload, fetch = self.run_main(
            [
                "--repository",
                HARNESS_REPOSITORY,
                "--portfolio-graph",
                "--issue",
                "36",
            ]
        )
        self.assertEqual(0, status)
        self.assertEqual("BOOTSTRAP_INPUTS_REFRESHED", payload["phase"])
        self.assertEqual(HARNESS_REPOSITORY, payload["repository"])
        self.assertEqual(MAIN, payload["observed_main_sha"])
        self.assertEqual(["issue"], [row["kind"] for row in payload["refreshed"]])
        fetch.assert_called_once_with(HARNESS_REPOSITORY, "issue", 36)
        store = CoordinationStore(self.database)
        try:
            self.assertIsNotNone(
                store.current_snapshot(HARNESS_REPOSITORY, "issue", 36)
            )
            self.assertIsNone(
                store.connection.execute(
                    "SELECT 1 FROM portfolio_graph_current WHERE repository=?",
                    (HARNESS_REPOSITORY,),
                ).fetchone()
            )
        finally:
            store.close()

    def test_absent_graph_rejects_malformed_main_before_issue_fetch(self) -> None:
        status, payload, fetch = self.run_main(
            [
                "--repository",
                HARNESS_REPOSITORY,
                "--portfolio-graph",
                "--issue",
                "36",
            ],
            main_sha="A" * 40,
        )
        self.assertEqual(1, status)
        self.assertEqual("GITHUB_RESPONSE_INVALID", payload["error"])
        fetch.assert_not_called()

    def test_absent_graph_main_move_during_fetch_rolls_back_all_snapshots(self) -> None:
        status, payload, fetch = self.run_main(
            [
                "--repository",
                HARNESS_REPOSITORY,
                "--portfolio-graph",
                "--issue",
                "36",
            ],
            main_shas=[MAIN, "b" * 40],
        )
        self.assertEqual(1, status)
        self.assertEqual("GITHUB_MAIN_CHANGED_DURING_REFRESH", payload["error"])
        fetch.assert_called_once_with(HARNESS_REPOSITORY, "issue", 36)
        store = CoordinationStore(self.database)
        try:
            self.assertIsNone(
                store.current_snapshot(HARNESS_REPOSITORY, "issue", 36)
            )
        finally:
            store.close()

    def test_application_absent_graph_remains_graph_not_found_without_fetch(self) -> None:
        status, payload, fetch = self.run_main(
            [
                "--repository",
                APPLICATION_REPOSITORY,
                "--portfolio-graph",
                "--issue",
                "36",
            ]
        )
        self.assertEqual(1, status)
        self.assertEqual({"phase": "HOLD", "error": "GRAPH_NOT_FOUND"}, payload)
        fetch.assert_not_called()
        store = CoordinationStore(self.database)
        try:
            self.assertIsNone(
                store.current_snapshot(APPLICATION_REPOSITORY, "issue", 36)
            )
        finally:
            store.close()

    def test_issue_set_graph_refreshes_nodes_and_digest_bound_exclusions(self) -> None:
        store = CoordinationStore(self.database)
        try:
            sources = {}
            for issue_number in (34, 35, 36):
                sources[issue_number] = store.ingest_snapshot(
                    repository=HARNESS_REPOSITORY,
                    object_kind="issue",
                    object_number=issue_number,
                    payload=self.issue(issue_number),
                    source_updated_at="2026-08-27T06:00:00Z",
                    fetched_at="2026-08-27T06:00:00Z",
                ).payload_sha256
            nodes = []
            for order, issue_number in enumerate((35, 36)):
                nodes.append(
                    {
                        "node_key": f"issue:{issue_number}",
                        "issue_number": issue_number,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent harness source work.",
                        "lane_key": "harness-source",
                        "lane_order": order,
                        "dispatchable": True,
                        "priority_rank": order + 1,
                        "estimate_units": 1,
                        "development_units": 0,
                        "shared_units": 1,
                        "sre_units": 0,
                        "source_payload_sha256": sources[issue_number],
                        "ready_at": "2026-08-27T06:00:00Z",
                    }
                )
            replace_graph(
                store.connection,
                {
                    "repository": HARNESS_REPOSITORY,
                    "accepted_main_sha": MAIN,
                    "expected_current_version": 0,
                    "scope": {
                        "kind": "ISSUE_SET",
                        "issue_numbers": [34, 35, 36],
                    },
                    "excluded_issues": [
                        {
                            "issue_number": 34,
                            "reason": "Outside this bounded slice.",
                            "source_payload_sha256": sources[34],
                        }
                    ],
                    "nodes": nodes,
                    "relations": [],
                },
                now="2026-08-27T06:00:00Z",
            )
        finally:
            store.close()

        status, payload, fetch = self.run_main(
            ["--repository", HARNESS_REPOSITORY, "--portfolio-graph"]
        )
        self.assertEqual(0, status, payload)
        self.assertEqual(
            [34, 35, 36],
            sorted(call.args[2] for call in fetch.call_args_list),
        )
        self.assertEqual(
            ["issue", "issue", "issue"],
            [row["kind"] for row in payload["refreshed"]],
        )


if __name__ == "__main__":
    unittest.main()
