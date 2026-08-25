from __future__ import annotations

from pathlib import Path
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    digest_json,
)
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

    def bind_terminal_packet(self) -> None:
        row = self.store.connection.execute(
            "SELECT * FROM github_outbox WHERE id=?", (self.outbox,)
        ).fetchone()
        closeout_key = row["idempotency_key"]
        graph_sha = digest_json({"issue": 92, "source": row["expected_source_sha256"]})
        graph_binding = {
            "repository": REPOSITORY,
            "issue_number": 92,
            "graph_version": 1,
            "graph_sha256": graph_sha,
            "graph_main_sha": "a" * 40,
            "graph_node_key": "issue-92",
            "source_payload_sha256": row["expected_source_sha256"],
        }
        graph_binding["graph_binding_sha256"] = digest_json(graph_binding)
        self.store.connection.execute(
            "INSERT INTO portfolio_graph_revisions VALUES (?,?,NULL,?,?,?,?,?)",
            (
                REPOSITORY, 1, "a" * 40, graph_sha,
                '{"milestones":[]}', "[]", "2026-08-22T10:00:01Z",
            ),
        )
        self.store.connection.execute(
            """
            INSERT INTO portfolio_graph_nodes VALUES (
                ?,1,'issue-92',92,'DELIVERY','STANDALONE',NULL,NULL,NULL,
                'issue-92',0,1,1,1,1,1,0,?,'2026-08-22T10:00:01Z'
            )
            """,
            (REPOSITORY, row["expected_source_sha256"]),
        )
        self.store.connection.execute(
            "INSERT INTO portfolio_graph_current VALUES (?,1,?,'CURRENT',?,NULL)",
            (REPOSITORY, "a" * 40, "2026-08-22T10:00:01Z"),
        )
        self.store.connection.execute(
            """
            INSERT INTO coordination_terminal_closeout_packets(
                closeout_key,packet_sha256,repository,issue_number,generation,
                source_payload_sha256,lease_manifest_sha256,accountable_role,
                endpoint_id,preparer_attempt_id,preparer_attempt_version,
                terminal_watch_key,activation_message_id,
                activation_payload_sha256,expected_item_version,
                publication_pending_item_version,terminal_receipt_sha256,
                terminal_receipt_json,cleanup_evidence_sha256,
                cleanup_evidence_json,outbox_id,outbox_payload_sha256,
                graph_version,graph_sha256,graph_main_sha,graph_node_key,
                graph_binding_sha256,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                closeout_key,
                hashlib.sha256(f"packet:{closeout_key}".encode()).hexdigest(),
                REPOSITORY,
                92,
                1,
                row["expected_source_sha256"],
                "5" * 64,
                "development",
                "role.development.v3",
                "00000000-0000-4000-8000-000000000001",
                1,
                f"terminal:{REPOSITORY}:issue:92:generation:1",
                1,
                "6" * 64,
                1,
                2,
                "7" * 64,
                "{}",
                "8" * 64,
                "{}",
                self.outbox,
                row["payload_sha256"],
                1,
                graph_binding["graph_sha256"],
                graph_binding["graph_main_sha"],
                graph_binding["graph_node_key"],
                graph_binding["graph_binding_sha256"],
                "2026-08-22T10:00:02Z",
            ),
        )
        self.store.connection.execute(
            """
            INSERT INTO coordination_terminal_outbox_recovery(
                outbox_id,readback_attempts,retry_rounds,next_retry_at,
                state,updated_at,last_error
            ) VALUES (?,0,0,'2026-08-22T10:00:02Z','PENDING',
                      '2026-08-22T10:00:02Z',NULL)
            """,
            (self.outbox,),
        )

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

    @patch.object(publisher, "_gh_json")
    def test_terminal_hold_reconciles_exact_marker_without_republish(self, gh) -> None:
        self.bind_terminal_packet()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "TERMINAL_OUTBOX_ENVELOPE_IMMUTABLE"
        ):
            self.store.connection.execute(
                "UPDATE github_outbox SET payload_json='{}' WHERE id=?",
                (self.outbox,),
            )
        self.store.reserve_outbox(self.outbox, "2026-08-22T10:00:03Z")
        self.store.hold_outbox(
            self.outbox, "GITHUB_WRITE_AMBIGUOUS", "2026-08-22T10:00:04Z"
        )
        published = publisher._published_body(self.body, "issue-92-terminal")
        gh.side_effect = [
            {"login": "twinfinity-bot"},
            [[{
                "id": 789,
                "body": published,
                "created_at": "2026-08-22T10:00:03Z",
                "user": {"login": "twinfinity-bot"},
            }]],
        ]

        result = publisher.publish(self.store, self.outbox)

        self.assertEqual("comment:789", result["receipt"])
        self.assertTrue(all("POST" not in call.args[0] for call in gh.call_args_list))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "TERMINAL_OUTBOX_COMPLETE_IMMUTABLE"):
            self.store.connection.execute(
                "UPDATE github_outbox SET remote_receipt='comment:999' WHERE id=?",
                (self.outbox,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "TERMINAL_OUTBOX_READBACK_IMMUTABLE"):
            self.store.connection.execute(
                "UPDATE coordination_terminal_outbox_readbacks "
                "SET publisher_login='somebody-else' WHERE outbox_id=?",
                (self.outbox,),
            )

    @patch.object(publisher, "utc_now")
    @patch.object(publisher, "_gh_json")
    def test_terminal_missing_readback_has_bounded_rebind_to_same_outbox(
        self, gh, now
    ) -> None:
        self.bind_terminal_packet()
        self.store.reserve_outbox(self.outbox, "2026-08-22T10:00:02Z")
        self.store.hold_outbox(
            self.outbox, "GITHUB_WRITE_AMBIGUOUS", "2026-08-22T10:00:02Z"
        )
        gh.side_effect = [
            {"login": "twinfinity-bot"}, [[]],
            {"login": "twinfinity-bot"}, [[]],
            {"login": "twinfinity-bot"}, [[]],
        ]
        now.side_effect = [
            "2026-08-22T10:00:03Z",
            "2026-08-22T10:01:04Z",
            "2026-08-22T10:03:05Z",
        ]

        for _ in range(3):
            with self.assertRaisesRegex(
                CoordinationError, "GITHUB_READBACK_MISSING"
            ):
                publisher.publish(self.store, self.outbox)

        outbox = self.store.connection.execute(
            "SELECT state FROM github_outbox WHERE id=?", (self.outbox,)
        ).fetchone()
        recovery = self.store.connection.execute(
            "SELECT state,retry_rounds,readback_attempts "
            "FROM coordination_terminal_outbox_recovery WHERE outbox_id=?",
            (self.outbox,),
        ).fetchone()
        self.assertEqual("PREPARED", outbox["state"])
        self.assertEqual(("RETRY_READY", 1, 0), tuple(recovery))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_closeout_packets"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM github_outbox"
            ).fetchone()[0],
        )


if __name__ == "__main__":
    unittest.main()
