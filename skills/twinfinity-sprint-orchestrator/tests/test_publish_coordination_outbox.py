from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationError, CoordinationStore  # noqa: E402
import publish_coordination_outbox as publisher  # noqa: E402


REPOSITORY = "twinfinityai/twinfinityapp"


class PublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name) / "coordinator"
        directory.mkdir(mode=0o700)
        self.store = CoordinationStore(directory / "state.sqlite3")
        self.payload = {
            "number": 92,
            "state": "open",
            "title": "Issue",
            "updated_at": "2026-08-22T10:00:00Z",
        }
        source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload=self.payload,
            source_updated_at=self.payload["updated_at"],
            fetched_at="2026-08-22T10:00:01Z",
        )
        self.body = "Material terminal receipt"
        self.outbox = self.store.enqueue_comment(
            idempotency_key="issue-92-terminal",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            expected_source_sha256=source.payload_sha256,
            body=self.body,
            now="2026-08-22T10:00:02Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    @patch.object(publisher, "fetch_object")
    @patch.object(publisher, "_gh_json")
    def test_success_posts_once_and_requires_exact_readback(self, gh, fetch) -> None:
        fetch.return_value = self.payload
        published = publisher._published_body(self.body, "issue-92-terminal")
        gh.side_effect = [
            {"login": "twinfinity-bot"},
            {"id": 123, "body": published, "user": {"login": "twinfinity-bot"}},
            {"id": 123, "body": published, "user": {"login": "twinfinity-bot"}},
        ]
        result = publisher.publish(self.store, self.outbox)
        self.assertEqual("comment:123", result["receipt"])
        post_calls = [call for call in gh.call_args_list if "POST" in call.args[0]]
        self.assertEqual(1, len(post_calls))
        state = self.store.connection.execute(
            "SELECT state FROM github_outbox WHERE id=?", (self.outbox,)
        ).fetchone()[0]
        self.assertEqual("COMPLETE", state)

    @patch.object(publisher, "fetch_object")
    @patch.object(publisher, "_gh_json")
    def test_pull_request_uses_check_aware_projection_timestamp(self, gh, fetch) -> None:
        pull_payload = {
            "number": 310,
            "state": "open",
            "title": "Pull request",
            "updated_at": "2026-08-22T10:00:00Z",
            "_projection_updated_at": "2026-08-22T10:05:00Z",
        }
        source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="pull_request",
            object_number=310,
            payload=pull_payload,
            source_updated_at=pull_payload["_projection_updated_at"],
            fetched_at="2026-08-22T10:05:01Z",
        )
        outbox = self.store.enqueue_comment(
            idempotency_key="pr-310-evidence",
            repository=REPOSITORY,
            object_kind="pull_request",
            object_number=310,
            expected_source_sha256=source.payload_sha256,
            body=self.body,
            now="2026-08-22T10:05:02Z",
        )
        fetch.return_value = pull_payload
        published = publisher._published_body(self.body, "pr-310-evidence")
        gh.side_effect = [
            {"login": "twinfinity-bot"},
            {"id": 310, "body": published, "user": {"login": "twinfinity-bot"}},
            {"id": 310, "body": published, "user": {"login": "twinfinity-bot"}},
        ]

        result = publisher.publish(self.store, outbox)

        self.assertEqual("comment:310", result["receipt"])
        post_calls = [call for call in gh.call_args_list if "POST" in call.args[0]]
        self.assertEqual(1, len(post_calls))

    @patch.object(publisher, "_gh_json")
    def test_inflight_recovery_is_readback_only(self, gh) -> None:
        self.store.reserve_outbox(self.outbox, "2026-08-22T10:00:03Z")
        published = publisher._published_body(self.body, "issue-92-terminal")
        gh.side_effect = [
            {"login": "twinfinity-bot"},
            [[
                {
                    "id": 456,
                    "body": published,
                    "created_at": "2026-08-22T10:00:04Z",
                    "user": {"login": "twinfinity-bot"},
                }
            ]],
        ]
        result = publisher.publish(self.store, self.outbox)
        self.assertEqual("comment:456", result["receipt"])
        self.assertTrue(all("POST" not in call.args[0] for call in gh.call_args_list))

    @patch.object(publisher, "fetch_object")
    @patch.object(publisher, "_gh_json")
    def test_ambiguous_write_without_readback_holds(self, gh, fetch) -> None:
        fetch.return_value = self.payload
        gh.side_effect = [
            {"login": "twinfinity-bot"},
            CoordinationError("GITHUB_WRITE_AMBIGUOUS"),
            [[]],
        ]
        with self.assertRaisesRegex(CoordinationError, "GITHUB_READBACK_MISSING"):
            publisher.publish(self.store, self.outbox)
        row = self.store.connection.execute(
            "SELECT state, last_error FROM github_outbox WHERE id=?", (self.outbox,)
        ).fetchone()
        self.assertEqual(("HOLD", "GITHUB_READBACK_MISSING"), tuple(row))

    @patch.object(publisher, "_gh_json")
    def test_inflight_ignores_older_foreign_exact_body(self, gh) -> None:
        self.store.reserve_outbox(self.outbox, "2026-08-22T10:00:03Z")
        published = publisher._published_body(self.body, "issue-92-terminal")
        gh.side_effect = [
            {"login": "twinfinity-bot"},
            [[
                {
                    "id": 111,
                    "body": published,
                    "created_at": "2026-08-22T09:59:59Z",
                    "user": {"login": "somebody-else"},
                }
            ]],
        ]
        with self.assertRaisesRegex(CoordinationError, "GITHUB_READBACK_MISSING"):
            publisher.publish(self.store, self.outbox)


if __name__ == "__main__":
    unittest.main()
