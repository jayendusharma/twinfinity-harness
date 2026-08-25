from __future__ import annotations

from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from sync_github_coordination import normalize_issue, normalize_pull  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
