from __future__ import annotations

import json
import hashlib
import fcntl
import os
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    artifact_registry_identity,
    digest_json,
    terminal_publication_body,
)
from prepush_control import PrePushControl  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
    reviewed_planner_rotation_catalog,
)
from tests.canonical_ready_fixture import (  # noqa: E402
    finalize_canonical_ready_item,
)


REPOSITORY = "twinfinityai/twinfinityapp"
SESSION = "role.development.v4"
SRE_SESSION = "role.sre.v4"
PLANNER_SESSION = "role.planner.v2"
LEASE = "5" * 64


class CoordinationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name) / "coordinator"
        directory.mkdir(mode=0o700)
        self.database = directory / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="coordination-store-tests",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def snapshot(self, updated: str = "2026-08-22T10:00:00Z", title: str = "Issue"):
        return self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={"number": 92, "title": title, "updated_at": updated},
            source_updated_at=updated,
            fetched_at="2026-08-22T10:00:01Z",
        )

    def issue_snapshot(self, issue_number: int):
        return self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue_number,
            payload={
                "number": issue_number,
                "title": f"Issue {issue_number}",
                "updated_at": "2026-08-22T10:00:00Z",
            },
            source_updated_at="2026-08-22T10:00:00Z",
            fetched_at="2026-08-22T10:00:01Z",
        )

    def install_all_current_endpoints(self) -> None:
        catalog = reviewed_current_endpoint_catalog(ROOT, Path(self.temp.name))
        config = catalog.__enter__()
        self.addCleanup(catalog.__exit__, None, None, None)
        aliases, alias_sha = load_legacy_alias_fixture(
            ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="terminal-closeout-reviewed-endpoints",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-22T10:00:01Z",
        )

    def running_message_attempt(
        self, message_id: int, *, process_id: int = 9200
    ) -> tuple[dict, str]:
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=SESSION,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-22T10:00:03Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(message_id)
            ),
        )
        unit = stable_systemd_unit("development", "message", str(message_id))
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="a" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-22T10:00:04Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=process_id,
            now="2026-08-22T10:00:05Z",
        )
        return running, token

    def running_terminal_watch_attempt(
        self, watch_key: str, *, process_id: int = 9201
    ) -> tuple[dict, str]:
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=SESSION,
            target_kind="terminal_watch",
            target_key=watch_key,
            now="2026-08-22T10:00:10Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "terminal_watch", watch_key
            ),
        )
        unit = stable_systemd_unit("development", "terminal_watch", watch_key)
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="b" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-22T10:00:10Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=process_id,
            now="2026-08-22T10:00:10Z",
        )
        return running, token

    def seed_committed_terminal_closeout_for_artifact_gc(
        self, *, source_sha256: str, generation: int
    ) -> None:
        closeout_key = (
            f"terminal-closeout:{REPOSITORY}:issue:92:generation:{generation}"
        )
        receipt = {
            "schema": "twinfinity-terminal-receipt/v1",
            "repository": REPOSITORY,
            "issue_number": 92,
            "generation": generation,
            "source_payload_sha256": source_sha256,
            "lease_manifest_sha256": LEASE,
            "outcome": "ACCEPTED",
            "accepted_head_sha": "c" * 40,
            "operational_state_sha256": None,
            "acceptance_evidence_sha256": "d" * 64,
            "residual_risks": [],
        }
        cleanup = {
            "schema": "twinfinity-terminal-cleanup/v1",
            "repository": REPOSITORY,
            "issue_number": 92,
            "generation": generation,
            "lease_manifest_sha256": LEASE,
            "owned_resources_absent": True,
            "temporary_resources_absent": True,
            "worktree_disposition": "ABSENT",
            "local_branch_disposition": "ABSENT",
            "remote_branch_disposition": "ABSENT",
            "residuals": [],
        }
        outbox_id = self.store.enqueue_comment(
            idempotency_key=closeout_key,
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            expected_source_sha256=source_sha256,
            body=terminal_publication_body(
                closeout_key=closeout_key,
                terminal_receipt=receipt,
                cleanup_evidence=cleanup,
            ),
            now="2026-08-22T10:00:04Z",
        )
        self.store.reserve_outbox(outbox_id, "2026-08-22T10:00:04Z")
        self.store.complete_outbox(
            outbox_id, "comment:123", "2026-08-22T10:00:04Z"
        )
        outbox = self.store.connection.execute(
            "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
        ).fetchone()
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        packet_sha256 = digest_json(
            {"test_fixture": closeout_key, "outbox_id": outbox_id}
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
                cleanup_evidence_json,outbox_id,outbox_payload_sha256,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                closeout_key,
                packet_sha256,
                REPOSITORY,
                92,
                generation,
                source_sha256,
                LEASE,
                "development",
                SESSION,
                "00000000-0000-4000-8000-000000000001",
                1,
                f"terminal:{REPOSITORY}:issue:92:generation:{generation}",
                1,
                "e" * 64,
                int(item["version"]) - 1,
                int(item["version"]),
                digest_json(receipt),
                canonical_json(receipt),
                digest_json(cleanup),
                canonical_json(cleanup),
                outbox_id,
                outbox["payload_sha256"],
                "2026-08-22T10:00:04Z",
            ),
        )
        remote_sha256 = hashlib.sha256(b"comment:123").hexdigest()
        self.store.connection.execute(
            """
            INSERT INTO coordination_terminal_closeout_commits(
                closeout_key,commit_sha256,finalizer_attempt_id,
                finalizer_attempt_version,remote_receipt,remote_receipt_sha256,
                prior_item_version,done_item_version,dirty_event_id,committed_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                closeout_key,
                digest_json({"test_fixture_commit": closeout_key}),
                "00000000-0000-4000-8000-000000000002",
                1,
                "comment:123",
                remote_sha256,
                int(item["version"]) - 1,
                int(item["version"]),
                100000 + generation,
                "2026-08-22T10:00:04Z",
            ),
        )

    def development_dispatch_bindings(self) -> dict:
        return {
            "writer": "accountable-writer",
            "reviewer_plan": ["Different-session exact-head review."],
            "collision_proof": ["The closed lease is collision-free."],
            "environment_rule": "Use only an issue-owned environment.",
            "routine_chain": ["Run the issue-owned delivery chain."],
            "hard_stops": ["Stop on any binding drift."],
        }

    def canonical_ready_item(
        self,
        source,
        *,
        issue_number: int = 92,
        generation: int = 1,
        development_units: int = 1,
        shared_units: int = 0,
        sre_units: int = 0,
        suffix: str,
    ) -> dict:
        endpoint = SRE_SESSION if sre_units else SESSION
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=issue_number,
            status="PREPARED",
            allocation_class="NONE",
            generation=generation,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=development_units,
            shared_units=shared_units,
            sre_units=sre_units,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": "a" * 40,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Fixture", "rank": 1}],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": f"issue:{issue_number}",
                        "issue_number": issue_number,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent canonical fixture outcome",
                        "lane_key": f"lane-{issue_number}",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": 1,
                        "estimate_units": 1,
                        "development_units": development_units,
                        "shared_units": shared_units,
                        "sre_units": sre_units,
                        "source_payload_sha256": source.payload_sha256,
                        "ready_at": "2026-08-22T10:00:00Z",
                    }
                ],
                "relations": [],
            },
            now="2026-08-22T10:00:03Z",
        )
        return finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.database.parent,
            repository=REPOSITORY,
            issue_number=issue_number,
            source_payload_sha256=source.payload_sha256,
            accepted_main_sha="a" * 40,
            worker_role="sre" if sre_units else "development",
            worker_endpoint_id=endpoint,
            now="2026-08-22T10:00:04Z",
            suffix=suffix,
        )["item"]

    def bind_admission_lease(
        self,
        item: dict,
        message: dict,
        slug: str,
    ) -> tuple[dict, dict, list[dict]]:
        payload = message["payload"]
        plans = self.database.parent / "plans"
        plans.mkdir(exist_ok=True)
        path = plans / f"{slug}.json"
        path.write_text(
            json.dumps(
                {
                    "repository": item["repository"],
                    "issue_number": item["issue_number"],
                    "generation": item["generation"],
                    "base_sha": payload["base_sha"],
                    "branch": payload["branch"],
                    "worktree_path": payload["worktree_path"],
                    "no_additional_paths": True,
                    "paths": [
                        {
                            "path": "backend/example.py",
                            "mode": "100644",
                            "type": "blob",
                            "sha": "b" * 40,
                        }
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        bound_item = {**item, "lease_manifest_sha256": digest}
        bound_message = {
            **message,
            "payload": {
                **(
                    self.development_dispatch_bindings()
                    if message["topic"] == "development.admission"
                    else {}
                ),
                **payload,
                "lease_manifest_sha256": digest,
            },
        }
        artifacts = [
            {
                "repository": item["repository"],
                "issue_number": item["issue_number"],
                "generation": item["generation"],
                "path": str(path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }
        ]
        return bound_item, bound_message, artifacts

    def prepare_development_admission(
        self, slug: str
    ) -> tuple[dict, dict, list[dict], dict]:
        source = self.snapshot()
        ready = self.canonical_ready_item(
            source,
            generation=3,
            shared_units=1,
            suffix=f"{slug}-ready",
        )
        item = {
            "repository": REPOSITORY,
            "issue_number": 92,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": 3,
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "development_units": 1,
            "shared_units": 1,
            "sre_units": 0,
            "expected_source_sha256": source.payload_sha256,
            "expected_version": ready["version"],
        }
        message = {
            "idempotency_key": f"{slug}-admission",
            "recipient_session_id": SESSION,
            "topic": "development.admission",
            "payload": {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "issue_number": 92,
                "generation": 3,
                "item_version": ready["version"] + 1,
                "base_sha": "a" * 40,
                "branch": "codex/92-transcript-review-editor",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
                "opaque_worktree_id": "twinfinityapp-issue-92",
                "accountable_session_id": SESSION,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 1,
                    "sre_units": 0,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
        }
        bound_item, bound_message, artifacts = self.bind_admission_lease(
            item, message, f"{slug}-lease"
        )
        return bound_item, bound_message, artifacts, ready

    def test_database_is_durable_and_coexists_with_ack_table(self) -> None:
        self.assertEqual("wal", self.store.connection.execute("PRAGMA journal_mode").fetchone()[0])
        self.assertEqual(2, self.store.connection.execute("PRAGMA synchronous").fetchone()[0])
        self.store.connection.execute("CREATE TABLE ack_transactions (contract_key TEXT PRIMARY KEY)")
        self.store._create_schema()
        tables = {
            row[0]
            for row in self.store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("ack_transactions", tables)
        self.assertIn("coordination_messages", tables)
        self.assertIn("coordination_artifacts", tables)
        self.assertIn("coordination_capacity_policies", tables)
        self.assertIn("coordination_capacity_current", tables)
        target_index = self.store.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' "
            "AND name='executor_one_active_attempt_per_target'"
        ).fetchone()
        role_index = self.store.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' "
            "AND name='executor_one_active_attempt_per_role'"
        ).fetchone()
        self.assertIsNotNone(target_index)
        self.assertIn(
            "role, target_kind, target_key", target_index[0]
        )
        self.assertIsNone(role_index)

    def test_test_fixture_ready_gateway_rejects_copied_live_database_without_writes(self) -> None:
        source = self.snapshot()
        seeded = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
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
            now="2026-08-22T10:00:02Z",
        )
        copied_path = self.database.parent / "live-shaped-copy.sqlite3"
        copied = CoordinationStore(copied_path)
        try:
            self.store.connection.backup(copied.connection)
            before_changes = copied.connection.total_changes
            before_item = tuple(
                copied.connection.execute(
                    "SELECT status, generation, version, source_payload_sha256 "
                    "FROM coordination_items WHERE repository=? AND issue_number=92",
                    (REPOSITORY,),
                ).fetchone()
            )
            before_coordination = tuple(
                copied.connection.execute(
                    "SELECT "
                    "(SELECT COUNT(*) FROM coordination_items),"
                    "(SELECT COUNT(*) FROM coordination_messages),"
                    "(SELECT COUNT(*) FROM github_outbox),"
                    "(SELECT COUNT(*) FROM coordination_artifacts),"
                    "(SELECT COUNT(*) FROM coordination_events)"
                ).fetchone()
            )
            for forbidden in ("READY", "READY_ELIGIBLE", "FINALIZED"):
                with self.subTest(forbidden=forbidden):
                    with self.assertRaisesRegex(
                        CoordinationError, "READY_FINALIZATION_REQUIRED"
                    ):
                        copied._set_issue_status_for_test_fixture(
                            repository=REPOSITORY,
                            issue_number=92,
                            status=forbidden,
                            allocation_class="NONE",
                            generation=1,
                            accountable_session_id=None,
                            lease_manifest_sha256=None,
                            development_units=1,
                            shared_units=0,
                            sre_units=0,
                            expected_source_sha256=source.payload_sha256,
                            expected_version=int(seeded["version"]),
                            now="2026-08-22T10:00:03Z",
                        )
                    self.assertFalse(copied.connection.in_transaction)
                    self.assertEqual(before_changes, copied.connection.total_changes)
                    self.assertEqual(
                        before_item,
                        tuple(
                            copied.connection.execute(
                                "SELECT status, generation, version, source_payload_sha256 "
                                "FROM coordination_items "
                                "WHERE repository=? AND issue_number=92",
                                (REPOSITORY,),
                            ).fetchone()
                        ),
                    )
                    self.assertEqual(
                        before_coordination,
                        tuple(
                            copied.connection.execute(
                                "SELECT "
                                "(SELECT COUNT(*) FROM coordination_items),"
                                "(SELECT COUNT(*) FROM coordination_messages),"
                                "(SELECT COUNT(*) FROM github_outbox),"
                                "(SELECT COUNT(*) FROM coordination_artifacts),"
                                "(SELECT COUNT(*) FROM coordination_events)"
                            ).fetchone()
                        ),
                    )
        finally:
            copied.close()

    def test_capacity_policy_is_persisted_versioned_and_drives_enforcement(self) -> None:
        source = self.snapshot()
        default = self.store.capacity_policy(REPOSITORY, now="2026-08-22T10:00:02Z")
        self.assertEqual(
            (1, 5, 2, 5),
            (
                default["version"],
                default["development_limit"],
                default["shared_limit"],
                default["sre_limit"],
            ),
        )
        expanded = self.store.set_capacity_policy(
            repository=REPOSITORY,
            development_limit=6,
            shared_limit=3,
            sre_limit=5,
            authority_sha256="a" * 64,
            expected_version=1,
            now="2026-08-22T10:00:03Z",
        )
        self.assertEqual(
            (2, 6, 3, 5),
            (
                expanded["version"],
                expanded["development_limit"],
                expanded["shared_limit"],
                expanded["sre_limit"],
            ),
        )
        with self.assertRaisesRegex(
            CoordinationError, "CAPACITY_POLICY_VERSION_CONFLICT"
        ):
            self.store.set_capacity_policy(
                repository=REPOSITORY,
                development_limit=7,
                shared_limit=4,
                sre_limit=5,
                authority_sha256="c" * 64,
                expected_version=1,
                now="2026-08-22T10:00:03Z",
            )
        item = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=6,
            shared_units=3,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:04Z",
        )
        self.assertEqual(1, item["version"])
        with self.assertRaisesRegex(
            CoordinationError, "CAPACITY_POLICY_BELOW_OCCUPANCY"
        ):
            self.store.set_capacity_policy(
                repository=REPOSITORY,
                development_limit=5,
                shared_limit=2,
                sre_limit=5,
                authority_sha256="b" * 64,
                expected_version=2,
                now="2026-08-22T10:00:05Z",
            )

    def test_existing_coordination_table_migrates_allocation_class(self) -> None:
        alternate = self.database.parent / "legacy.sqlite3"
        descriptor = sqlite3.connect(alternate)
        descriptor.execute(
            """
            CREATE TABLE coordination_items (
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                generation INTEGER NOT NULL,
                accountable_session_id TEXT,
                lease_manifest_sha256 TEXT,
                development_units INTEGER NOT NULL,
                shared_units INTEGER NOT NULL,
                source_payload_sha256 TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(repository, issue_number)
            )
            """
        )
        descriptor.close()
        alternate.chmod(0o600)
        migrated = CoordinationStore(alternate)
        try:
            columns = {
                row[1]
                for row in migrated.connection.execute("PRAGMA table_info(coordination_items)")
            }
            self.assertIn("allocation_class", columns)
            self.assertIn("sre_units", columns)
            default_value = migrated.connection.execute(
                "SELECT dflt_value FROM pragma_table_info('coordination_items') WHERE name='allocation_class'"
            ).fetchone()[0]
            self.assertIsNone(default_value)
            sre_default = migrated.connection.execute(
                "SELECT dflt_value FROM pragma_table_info('coordination_items') WHERE name='sre_units'"
            ).fetchone()[0]
            self.assertIsNone(sre_default)
        finally:
            migrated.close()

    def test_snapshot_rejects_stale_and_same_version_conflict(self) -> None:
        first = self.snapshot()
        same = self.snapshot()
        self.assertEqual(first.payload_sha256, same.payload_sha256)
        with self.assertRaisesRegex(CoordinationError, "SOURCE_VERSION_CONFLICT"):
            self.snapshot(title="Changed without timestamp")
        with self.assertRaisesRegex(CoordinationError, "STALE_SOURCE_SNAPSHOT"):
            self.snapshot(updated="2026-08-21T10:00:00Z")

    def test_snapshot_allows_monotonic_projection_upgrade(self) -> None:
        first = self.snapshot()
        upgraded = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={
                "_projection_version": 2,
                "number": 92,
                "title": "Issue",
                "body": "Complete contract",
                "updated_at": "2026-08-22T10:00:00Z",
            },
            source_updated_at="2026-08-22T10:00:00Z",
            fetched_at="2026-08-22T10:00:02Z",
        )
        self.assertNotEqual(first.payload_sha256, upgraded.payload_sha256)

    def test_issue_status_uses_source_digest_and_version_cas(self) -> None:
        source = self.snapshot()
        status = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.assertEqual(1, status["version"])
        with self.assertRaisesRegex(CoordinationError, "ITEM_VERSION_CONFLICT"):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="DONE",
                allocation_class="NONE",
                generation=3,
                accountable_session_id=SESSION,
                lease_manifest_sha256=LEASE,
                development_units=0,
                shared_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=0,
                now="2026-08-22T10:00:03Z",
            )

    def test_activation_and_admission_commit_atomically(self) -> None:
        source = self.snapshot()
        ready = self.canonical_ready_item(
            source,
            generation=3,
            shared_units=1,
            suffix="atomic-admission-ready",
        )
        item = {
            "repository": REPOSITORY,
            "issue_number": 92,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": 3,
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "development_units": 1,
            "shared_units": 1,
            "sre_units": 0,
            "expected_source_sha256": source.payload_sha256,
            "expected_version": ready["version"],
        }
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 3,
            "item_version": ready["version"] + 1,
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
        }
        message = {
            "idempotency_key": "atomic-issue-92-admission",
            "recipient_session_id": SESSION,
            "topic": "development.admission",
            "payload": payload,
        }
        item, message, artifacts = self.bind_admission_lease(
            item, message, "atomic-issue-92-admission-lease"
        )
        payload = message["payload"]
        before_messages = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_messages"
        ).fetchone()[0]
        before_watches = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_terminal_watches"
        ).fetchone()[0]
        with self.assertRaisesRegex(
            CoordinationError, "ADMISSION_ITEM_BINDING_MISMATCH"
        ):
            self.store.activate_admission(
                item=item,
                message={**message, "payload": {**payload, "item_version": 99}},
                artifacts=artifacts,
                now="2026-08-22T10:00:03Z",
            )
        rolled_back = self.store.connection.execute(
            "SELECT status, version FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, 92),
        ).fetchone()
        self.assertEqual(("READY", ready["version"]), tuple(rolled_back))
        self.assertEqual(
            before_messages,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        self.assertEqual(
            before_watches,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches"
            ).fetchone()[0],
        )
        activated, message_id = self.store.activate_admission(
            item=item,
            message=message,
            artifacts=artifacts,
            now="2026-08-22T10:00:04Z",
        )
        self.assertEqual(
            ("ACTIVE", ready["version"] + 1),
            (activated["status"], activated["version"]),
        )
        observed = self.store.connection.execute(
            "SELECT state, recipient_session_id FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("PREPARED", SESSION), tuple(observed))
        watch = self.store.connection.execute(
            """
            SELECT state, accountable_session_id, generation, attempts
            FROM coordination_terminal_watches
            WHERE repository=? AND issue_number=?
            """,
            (REPOSITORY, 92),
        ).fetchone()
        self.assertEqual(("PENDING_CLAIM", SESSION, 3, 0), tuple(watch))
        with self.assertRaisesRegex(
            CoordinationError, "TERMINAL_WATCH_FENCE_MISMATCH"
        ):
            self.store.heartbeat_terminal_watch(
                watch_key=f"terminal:{REPOSITORY}:issue:92:generation:3",
                session_id=SESSION,
                generation=3,
                delay_seconds=300,
                now="2026-08-22T10:00:05Z",
            )
        newer = self.snapshot(updated="2026-08-22T11:00:00Z", title="New")
        self.assertNotEqual(source.payload_sha256, newer.payload_sha256)
        with self.assertRaisesRegex(CoordinationError, "SOURCE_SNAPSHOT_DRIFT"):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="DONE",
                allocation_class="NONE",
                generation=3,
                accountable_session_id=SESSION,
                lease_manifest_sha256=LEASE,
                development_units=0,
                shared_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=1,
                now="2026-08-22T11:00:01Z",
            )

    def test_direct_activation_rejects_every_invalid_dispatch_binding_atomically(
        self,
    ) -> None:
        item, message, artifacts, ready = self.prepare_development_admission(
            "strict-dispatch"
        )
        wrong_types = {
            "writer": ["accountable-writer"],
            "reviewer_plan": ("Different-session exact-head review.",),
            "collision_proof": {"proof": "collision-free"},
            "environment_rule": ["Use an issue-owned environment."],
            "routine_chain": "Run the delivery chain.",
            "hard_stops": {"stop": "on drift"},
        }
        semantic_empties = {
            "writer": "   ",
            "reviewer_plan": ["   "],
            "collision_proof": ["\t"],
            "environment_rule": "\n",
            "routine_chain": [""],
            "hard_stops": ["   "],
        }
        before_events = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events"
        ).fetchone()[0]
        before_tables = {
            table: self.store.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "coordination_messages",
                "coordination_terminal_watches",
                "coordination_artifacts",
            )
        }

        for category, invalid_values in (
            ("wrong_type", wrong_types),
            ("semantic_empty", semantic_empties),
        ):
            for field, value in invalid_values.items():
                with self.subTest(category=category, field=field):
                    invalid_message = {
                        **message,
                        "idempotency_key": f"strict-dispatch-{category}-{field}",
                        "payload": {**message["payload"], field: value},
                    }
                    with self.assertRaisesRegex(
                        CoordinationError, "ADMISSION_DISPATCH_BINDING_INVALID"
                    ):
                        self.store.activate_admission(
                            item=item,
                            message=invalid_message,
                            artifacts=artifacts,
                            now="2026-08-22T10:00:03Z",
                        )

        observed_item = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, 92),
        ).fetchone()
        self.assertEqual(("READY", "NONE", ready["version"]), tuple(observed_item))
        for table in (
            "coordination_messages",
            "coordination_terminal_watches",
            "coordination_artifacts",
        ):
            self.assertEqual(
                before_tables[table],
                self.store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0],
            )
        self.assertEqual(
            before_events,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0],
        )

    def test_direct_activation_rejects_every_registry_identity_substitution(
        self,
    ) -> None:
        item, message, artifacts, ready = self.prepare_development_admission(
            "registry-lineage"
        )
        self.store.register_artifacts(
            artifacts,
            now="2026-08-22T10:00:03Z",
        )
        registered_row = self.store.connection.execute(
            "SELECT * FROM coordination_artifacts WHERE repository=? AND issue_number=?",
            (REPOSITORY, 92),
        ).fetchone()
        registered = artifact_registry_identity(registered_row)
        artifact_path = Path(artifacts[0]["path"])
        descriptor = os.open(artifact_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw = artifact_path.read_bytes()
            metadata = os.fstat(descriptor)
            observation = {
                "descriptor": descriptor,
                "raw": raw,
                "content_sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": int(metadata.st_size),
                "device_id": int(metadata.st_dev),
                "inode": int(metadata.st_ino),
                "mode": int(metadata.st_mode),
                "uid": int(metadata.st_uid),
                "nlink": int(metadata.st_nlink),
                "mtime_ns": int(metadata.st_mtime_ns),
                "ctime_ns": int(metadata.st_ctime_ns),
                "relative_path": registered["relative_path"],
                "existing_only": True,
                "entry": {
                    **artifacts[0],
                    "registered_artifact": registered,
                },
            }
            substitutions = {
                "artifact_key": "0" * 64,
                "repository": "twinfinityai/substituted",
                "issue_number": 999,
                "generation": 999,
                "relative_path": "plans/substituted.json",
                "content_sha256": "1" * 64,
                "size_bytes": registered["size_bytes"] + 1,
                "device_id": registered["device_id"] + 1,
                "inode": registered["inode"] + 1,
                "retention_class": "RETAINED",
                "registered_at": "2026-08-22T10:00:03.000001Z",
            }
            before_events = self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0]
            before_messages = self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0]
            before_watches = self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches"
            ).fetchone()[0]
            for field, value in substitutions.items():
                with self.subTest(field=field):
                    observation["entry"] = {
                        **artifacts[0],
                        "registered_artifact": {**registered, field: value},
                    }
                    with self.assertRaisesRegex(
                        CoordinationError, "ARTIFACT_REGISTRY_IDENTITY_DRIFT"
                    ):
                        self.store.activate_admission(
                            item=item,
                            message=message,
                            artifacts=None,
                            artifact_observations=[observation],
                            now="2026-08-22T10:00:04Z",
                        )
        finally:
            os.close(descriptor)

        observed_item = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, 92),
        ).fetchone()
        self.assertEqual(("READY", "NONE", ready["version"]), tuple(observed_item))
        self.assertEqual(
            before_messages,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        self.assertEqual(
            before_watches,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches"
            ).fetchone()[0],
        )
        current_row = self.store.connection.execute(
            "SELECT * FROM coordination_artifacts WHERE artifact_key=?",
            (registered["artifact_key"],),
        ).fetchone()
        self.assertEqual("REGISTERED", current_row["state"])
        self.assertEqual(registered, artifact_registry_identity(current_row))
        self.assertEqual(
            before_events,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0],
        )

    def test_new_active_generation_supersedes_prior_terminal_watch(self) -> None:
        source = self.snapshot()
        first = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=2,
            accountable_session_id=SESSION,
            lease_manifest_sha256="6" * 64,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=first["version"],
            now="2026-08-22T10:00:03Z",
        )
        watches = self.store.connection.execute(
            """
            SELECT generation, state, last_error
            FROM coordination_terminal_watches
            WHERE repository=? AND issue_number=? ORDER BY generation
            """,
            (REPOSITORY, 92),
        ).fetchall()
        self.assertEqual(
            [
                (1, "COMPLETE", "SUPERSEDED_BY_NEW_GENERATION"),
                (2, "ACTIVE", None),
            ],
            [tuple(row) for row in watches],
        )

    def test_generation_rollover_requires_matching_structured_lease_atomically(self) -> None:
        source = self.snapshot()
        held = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=2,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        plans = self.database.parent / "plans"
        plans.mkdir()

        def write_manifest(path: Path, generation: int) -> str:
            path.write_text(
                json.dumps(
                    {
                        "repository": REPOSITORY,
                        "issue_number": 92,
                        "generation": generation,
                        "base_sha": "a" * 40,
                        "branch": "codex/92-transcript-review-editor",
                        "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
                        "no_additional_paths": True,
                        "paths": [
                            {
                                "path": "backend/example.py",
                                "mode": "100644",
                                "type": "blob",
                                "sha": "b" * 40,
                            }
                        ],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return hashlib.sha256(path.read_bytes()).hexdigest()

        stale_path = plans / "stale-generation-2-lease.json"
        stale_digest = write_manifest(stale_path, 2)

        def transaction(lease_path: Path, lease_digest: str) -> dict:
            return {
                "item": {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "status": "ACTIVE_FENCED",
                    "allocation_class": "ACTIVE",
                    "generation": 3,
                    "accountable_session_id": SESSION,
                    "lease_manifest_sha256": lease_digest,
                    "development_units": 1,
                    "shared_units": 1,
                    "sre_units": 0,
                    "expected_source_sha256": source.payload_sha256,
                    "expected_version": held["version"],
                },
                "message": {
                    "idempotency_key": f"generation-3-{lease_digest}",
                    "recipient_session_id": SESSION,
                    "topic": "development.admission",
                    "payload": {
                        "source": {
                            "repository": REPOSITORY,
                            "object_kind": "issue",
                            "object_number": 92,
                            "payload_sha256": source.payload_sha256,
                        },
                        "issue_number": 92,
                        "generation": 3,
                        "item_version": held["version"] + 1,
                        "base_sha": "a" * 40,
                        "branch": "codex/92-transcript-review-editor",
                        "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
                        "opaque_worktree_id": "twinfinityapp-issue-92",
                        "accountable_session_id": SESSION,
                        **self.development_dispatch_bindings(),
                        "lease_manifest_sha256": lease_digest,
                        "authority_sha256": "7" * 64,
                        "capacity": {
                            "development_units": 1,
                            "shared_units": 1,
                            "sre_units": 0,
                        },
                        "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                    },
                },
                "artifacts": [
                    {
                        "repository": REPOSITORY,
                        "issue_number": 92,
                        "generation": 3,
                        "path": str(lease_path),
                        "retention_class": "CLOSEOUT_EVIDENCE",
                    }
                ],
            }

        stale = transaction(stale_path, stale_digest)
        before_events = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events"
        ).fetchone()[0]
        with self.assertRaisesRegex(
            CoordinationError, "ADMISSION_LEASE_LINEAGE_MISMATCH"
        ):
            self.store.activate_admission(
                **stale, now="2026-08-22T10:00:03Z"
            )
        unchanged = self.store.connection.execute(
            "SELECT status, allocation_class, generation, version FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, 92),
        ).fetchone()
        self.assertEqual(("HOLD", "RETAINED", 2, held["version"]), tuple(unchanged))
        self.assertEqual(
            before_events,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_artifacts"
            ).fetchone()[0],
        )

        current_path = plans / "current-generation-3-lease.json"
        current_digest = write_manifest(current_path, 3)
        current = transaction(current_path, current_digest)
        activated, message_id = self.store.activate_admission(
            **current, now="2026-08-22T10:00:04Z"
        )
        self.assertEqual((3, "ACTIVE_FENCED"), (activated["generation"], activated["status"]))
        self.assertGreater(message_id, 0)
        artifact = self.store.connection.execute(
            "SELECT generation, content_sha256, state FROM coordination_artifacts"
        ).fetchone()
        self.assertEqual((3, current_digest, "REGISTERED"), tuple(artifact))

    def test_ready_first_admission_requires_a_complete_lease_artifact(self) -> None:
        source = self.snapshot()
        ready = self.canonical_ready_item(
            source,
            generation=3,
            shared_units=1,
            suffix="ready-first-admission",
        )
        item = {
            "repository": REPOSITORY,
            "issue_number": 92,
            "status": "ACTIVE_FENCED",
            "allocation_class": "ACTIVE",
            "generation": 3,
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "development_units": 1,
            "shared_units": 1,
            "sre_units": 0,
            "expected_source_sha256": source.payload_sha256,
            "expected_version": ready["version"],
        }
        message = {
            "idempotency_key": "ready-first-generation-3",
            "recipient_session_id": SESSION,
            "topic": "development.admission",
            "payload": {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "issue_number": 92,
                "generation": 3,
                "item_version": ready["version"] + 1,
                "base_sha": "a" * 40,
                "branch": "codex/92-transcript-review-editor",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
                "opaque_worktree_id": "twinfinityapp-issue-92",
                "accountable_session_id": SESSION,
                "lease_manifest_sha256": LEASE,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 1,
                    "sre_units": 0,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
        }
        item, message, artifacts = self.bind_admission_lease(
            item, message, "ready-first-generation-3-lease"
        )
        with self.assertRaisesRegex(
            CoordinationError, "ADMISSION_LEASE_ARTIFACT_MISMATCH"
        ):
            self.store.activate_admission(
                item=item,
                message=message,
                now="2026-08-22T10:00:03Z",
            )

        malformed_path = Path(artifacts[0]["path"])
        malformed = {
            "repository": REPOSITORY,
            "issue_number": 92,
            "generation": 3,
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "no_additional_paths": True,
            "paths": [None],
        }
        malformed_path.write_text(
            json.dumps(malformed, sort_keys=True) + "\n", encoding="utf-8"
        )
        malformed_digest = hashlib.sha256(malformed_path.read_bytes()).hexdigest()
        malformed_item = {**item, "lease_manifest_sha256": malformed_digest}
        malformed_message = {
            **message,
            "payload": {
                **message["payload"],
                "lease_manifest_sha256": malformed_digest,
            },
        }
        before_events = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events"
        ).fetchone()[0]
        with self.assertRaisesRegex(CoordinationError, "LEASE_MANIFEST_INVALID"):
            self.store.activate_admission(
                item=malformed_item,
                message=malformed_message,
                artifacts=artifacts,
                now="2026-08-22T10:00:04Z",
            )
        unchanged = self.store.connection.execute(
            "SELECT status, generation, version FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, 92),
        ).fetchone()
        self.assertEqual(("READY", 3, ready["version"]), tuple(unchanged))
        self.assertEqual(
            before_events,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0],
        )

    def test_legacy_active_terminal_watch_migrates_to_bound_hold(self) -> None:
        legacy_path = Path(self.temp.name) / "legacy-terminal-watch.sqlite3"
        legacy = sqlite3.connect(legacy_path)
        legacy.executescript(
            """
            CREATE TABLE coordination_terminal_watches (
                watch_key TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                accountable_session_id TEXT NOT NULL,
                lease_manifest_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('ACTIVE','COMPLETE','HOLD')),
                attempts INTEGER NOT NULL DEFAULT 0,
                process_id INTEGER,
                last_heartbeat_at TEXT NOT NULL,
                next_wake_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_error TEXT,
                UNIQUE(repository, issue_number, generation)
            );
            INSERT INTO coordination_terminal_watches VALUES (
                'terminal:twinfinityai/twinfinityapp:issue:92:generation:4',
                'twinfinityai/twinfinityapp', 92, 4,
                'role.development.v3',
                '5555555555555555555555555555555555555555555555555555555555555555',
                'ACTIVE', 2, 9812,
                '2026-08-22T10:00:00Z', '2026-08-22T10:01:00Z',
                '2026-08-22T10:00:00Z', NULL
            );
            """
        )
        legacy.close()
        legacy_path.chmod(0o600)

        migrated = CoordinationStore(legacy_path)
        try:
            row = migrated.connection.execute(
                "SELECT state,admission_message_id,admission_payload_sha256,"
                "claim_attempt_id,process_id,last_error "
                "FROM coordination_terminal_watches"
            ).fetchone()
            self.assertEqual(
                (
                    "HOLD",
                    None,
                    None,
                    None,
                    None,
                    "TERMINAL_WATCH_ADMISSION_BINDING_MIGRATION_REQUIRED",
                ),
                tuple(row),
            )
        finally:
            migrated.close()

    def test_sre_admission_and_terminal_closeout_are_atomic_and_capacity_typed(self) -> None:
        self.install_all_current_endpoints()
        source = self.issue_snapshot(314)
        ready = self.canonical_ready_item(
            source,
            issue_number=314,
            development_units=0,
            sre_units=1,
            suffix="sre-atomic-admission",
        )
        item = {
            "repository": REPOSITORY,
            "issue_number": 314,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": 1,
            "accountable_session_id": SRE_SESSION,
            "lease_manifest_sha256": LEASE,
            "development_units": 0,
            "shared_units": 0,
            "sre_units": 1,
            "expected_source_sha256": source.payload_sha256,
            "expected_version": ready["version"],
        }
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 314,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 314,
            "generation": 1,
            "item_version": ready["version"] + 1,
            "base_sha": "a" * 40,
            "branch": "codex/314-ci-hardening",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-314",
            "opaque_worktree_id": "twinfinityapp-issue-314",
            "accountable_session_id": SRE_SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 0,
                "shared_units": 0,
                "sre_units": 1,
            },
            "action": "CREATE_LOCAL_BRANCH_AND_WORKTREE_THEN_CONTINUE",
        }
        message = {
            "idempotency_key": "atomic-issue-314-sre-admission",
            "recipient_session_id": SRE_SESSION,
            "topic": "sre.admission",
            "payload": payload,
        }
        item, message, artifacts = self.bind_admission_lease(
            item, message, "atomic-issue-314-sre-admission-lease"
        )
        payload = message["payload"]
        before_messages = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_messages"
        ).fetchone()[0]

        for wrong_recipient in (SESSION, PLANNER_SESSION):
            wrong_role_item = {
                **item,
                "accountable_session_id": wrong_recipient,
            }
            wrong_role_payload = {
                **payload,
                "accountable_session_id": wrong_recipient,
            }
            with self.assertRaisesRegex(
                CoordinationError, "MESSAGE_ROLE_MISMATCH"
            ):
                self.store.activate_admission(
                    item=wrong_role_item,
                    message={
                        **message,
                        "idempotency_key": f"wrong-sre-recipient-{wrong_recipient}",
                        "recipient_session_id": wrong_recipient,
                        "payload": wrong_role_payload,
                    },
                    artifacts=artifacts,
                    now="2026-08-22T10:00:03Z",
                )

        with self.assertRaisesRegex(CoordinationError, "MESSAGE_ROLE_MISMATCH"):
            self.store.activate_admission(
                item=item,
                message={**message, "topic": "development.admission"},
                artifacts=artifacts,
                now="2026-08-22T10:00:03Z",
            )

        wrong_capacity = {
            **payload,
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 1,
            },
        }
        with self.assertRaisesRegex(
            CoordinationError, "MESSAGE_CAPACITY_CLASS_MISMATCH"
        ):
            self.store.activate_admission(
                item=item,
                message={**message, "payload": wrong_capacity},
                artifacts=artifacts,
                now="2026-08-22T10:00:03Z",
            )
        rolled_back = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, 314),
        ).fetchone()
        self.assertEqual(
            ("READY", "NONE", ready["version"]), tuple(rolled_back)
        )
        self.assertEqual(
            before_messages,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )

        activated, message_id = self.store.activate_admission(
            item=item,
            message=message,
            artifacts=artifacts,
            now="2026-08-22T10:00:04Z",
        )
        self.assertEqual(
            ("ACTIVE", "ACTIVE", ready["version"] + 1),
            (activated["status"], activated["allocation_class"], activated["version"]),
        )
        observed = self.store.connection.execute(
            "SELECT state, recipient_session_id, topic FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("PREPARED", SRE_SESSION, "sre.admission"), tuple(observed))
        reserved, token = reserve_attempt(
            self.store.connection,
            role="sre",
            endpoint_id=SRE_SESSION,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-22T10:00:05Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(message_id)
            ),
        )
        unit = stable_systemd_unit("sre", "message", str(message_id))
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="c" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-22T10:00:05Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9314,
            now="2026-08-22T10:00:05Z",
        )
        claimed = self.store.claim_message(
            message_id,
            SRE_SESSION,
            "2026-08-22T10:00:06Z",
            attempt_id=running["attempt_id"],
            executor_token=token,
        )
        self.assertEqual("sre.admission", claimed["topic"])
        watch_key = f"terminal:{REPOSITORY}:issue:314:generation:1"
        receipt = {
            "schema": "twinfinity-terminal-receipt/v1",
            "repository": REPOSITORY,
            "issue_number": 314,
            "generation": 1,
            "source_payload_sha256": source.payload_sha256,
            "lease_manifest_sha256": item["lease_manifest_sha256"],
            "outcome": "ACCEPTED",
            "accepted_head_sha": None,
            "operational_state_sha256": "e" * 64,
            "acceptance_evidence_sha256": "d" * 64,
            "residual_risks": [],
        }
        cleanup = {
            "schema": "twinfinity-terminal-cleanup/v1",
            "repository": REPOSITORY,
            "issue_number": 314,
            "generation": 1,
            "lease_manifest_sha256": item["lease_manifest_sha256"],
            "owned_resources_absent": True,
            "temporary_resources_absent": True,
            "worktree_disposition": "NOT_APPLICABLE",
            "local_branch_disposition": "NOT_APPLICABLE",
            "remote_branch_disposition": "NOT_APPLICABLE",
            "residuals": [],
        }
        closeout_key = f"terminal-closeout:{REPOSITORY}:issue:314:generation:1"
        prepared = self.store.prepare_terminal_closeout(
            packet={
                "schema": "twinfinity-terminal-closeout-packet/v1",
                "repository": REPOSITORY,
                "issue_number": 314,
                "generation": 1,
                "expected_item_version": activated["version"],
                "source_payload_sha256": source.payload_sha256,
                "lease_manifest_sha256": item["lease_manifest_sha256"],
                "terminal_watch_key": watch_key,
                "activation_message_id": message_id,
                "terminal_receipt": receipt,
                "cleanup_evidence": cleanup,
                "outbox": {
                    "idempotency_key": closeout_key,
                    "body": terminal_publication_body(
                        closeout_key=closeout_key,
                        terminal_receipt=receipt,
                        cleanup_evidence=cleanup,
                    ),
                },
            },
            attempt_id=running["attempt_id"],
            executor_token=token,
            now="2026-08-22T10:00:07Z",
        )
        pending = self.store.connection.execute(
            "SELECT status,allocation_class,sre_units FROM coordination_items "
            "WHERE repository=? AND issue_number=314",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("COMPLETE", completed["state"])

    def test_terminal_closeout_binds_done_item_watch_lineage_and_outbox(self) -> None:
        source = self.snapshot()
        ready = self.canonical_ready_item(
            source,
            shared_units=1,
            suffix="terminal-closeout-ready",
        )
        committed = self.store.commit_terminal_closeout(
            closeout_key=closeout_key,
            attempt_id=running["attempt_id"],
            executor_token=token,
            now="2026-08-22T10:00:10Z",
        )
        done = self.store.connection.execute(
            "SELECT status,allocation_class,sre_units FROM coordination_items "
            "WHERE repository=? AND issue_number=314",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("COMPLETE", committed["state"])
        self.assertEqual(("DONE", "NONE", 0), tuple(done))

    def test_legacy_terminal_closeout_topic_is_retired_for_new_work(self) -> None:
        self.install_all_current_endpoints()
        source = self.snapshot()
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            }
        }
        with self.assertRaisesRegex(
            CoordinationError, "TERMINAL_CLOSEOUT_TOPIC_RETIRED"
        ):
            self.store.enqueue_message(
                idempotency_key="retired-terminal-closeout-enqueue",
                recipient_session_id=SESSION,
                topic="development.terminal_closeout",
                payload=payload,
                now="2026-08-22T10:00:02Z",
            )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        admission_payload = admission_message["payload"]
        active, admission_id = self.store.activate_admission(
            item=admission_item,
            message=admission_message,
            artifacts=admission_artifacts,
            now="2026-08-22T10:00:03Z",
        )
        self.store.claim_message(admission_id, SESSION, "2026-08-22T10:00:04Z")
        self.store.complete_message(admission_id, SESSION, "2026-08-22T10:00:05Z")
        done = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=0,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:06Z",
        )
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:1"
        outbox_id, closeout_id = self.store.prepare_terminal_closeout(
            outbox={
                "idempotency_key": "issue-92-terminal-receipt",
                "repository": REPOSITORY,
                "issue_number": 92,
                "expected_source_sha256": source.payload_sha256,
                "body": "Issue 92 terminal receipt",
            },
            message={
                "idempotency_key": "issue-92-terminal-closeout",
                "payload": {
                    "source": {
                        "repository": REPOSITORY,
                        "object_kind": "issue",
                        "object_number": 92,
                        "payload_sha256": source.payload_sha256,
                    },
                    "issue_number": 92,
                    "item_generation": done["generation"],
                    "item_version": done["version"],
                    "terminal_watch_key": watch_key,
                    "terminal_watch_generation": 1,
                    "original_message_id": admission_id,
                    "action": "PUBLISH_TERMINAL_OWNING_ISSUE_RECEIPT",
                },
            },
        }
        prepared = self.store.prepare_terminal_closeout(
            packet=packet,
            attempt_id=running["attempt_id"],
            executor_token=token,
            now="2026-08-22T10:00:07Z",
        )
        self.assertEqual("PUBLICATION_PENDING", prepared["state"])
        pending = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        pending_watch = self.store.connection.execute(
            "SELECT state FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        local_message = self.store.connection.execute(
            "SELECT state FROM coordination_messages WHERE id=?", (admission_id,)
        ).fetchone()
        self.assertEqual(
            (
                "PUBLICATION_PENDING",
                "ACTIVE",
                SESSION,
                item["lease_manifest_sha256"],
                1,
                1,
                0,
            ),
            (
                pending["status"],
                pending["allocation_class"],
                pending["accountable_session_id"],
                pending["lease_manifest_sha256"],
                pending["development_units"],
                pending["shared_units"],
                pending["sre_units"],
            ),
        )
        self.assertEqual("ACTIVE", pending_watch["state"])
        self.assertEqual("COMPLETE", local_message["state"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_dirty_events"
            ).fetchone()[0],
        )
        with self.assertRaisesRegex(CoordinationError, "TERMINAL_OUTBOX_NOT_COMPLETE"):
            self.store.commit_terminal_closeout(
                closeout_key=closeout_key,
                attempt_id=running["attempt_id"],
                executor_token=token,
                now="2026-08-22T10:00:08Z",
            )
        outbox_id = prepared["outbox_id"]
        self.store.reserve_outbox(outbox_id, "2026-08-22T10:00:09Z")
        self.store.complete_outbox(
            outbox_id, "comment:123", "2026-08-22T10:00:10Z"
        )
        transition_attempt(
            self.store.connection,
            attempt_id=running["attempt_id"],
            token=token,
            expected_version=running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-22T10:00:10Z",
        )
        watcher, watcher_token = self.running_terminal_watch_attempt(watch_key)
        committed = self.store.commit_terminal_closeout(
            closeout_key=closeout_key,
            attempt_id=watcher["attempt_id"],
            executor_token=watcher_token,
            now="2026-08-22T10:00:11Z",
        )
        self.assertEqual("COMPLETE", committed["state"])
        final_item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        final_watch = self.store.connection.execute(
            "SELECT state FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(
            ("DONE", "NONE", None, None, 0, 0, 0),
            (
                final_item["status"],
                final_item["allocation_class"],
                final_item["accountable_session_id"],
                final_item["lease_manifest_sha256"],
                final_item["development_units"],
                final_item["shared_units"],
                final_item["sre_units"],
            ),
        )
        self.assertEqual("COMPLETE", final_watch["state"])
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_dirty_events"
            ).fetchone()[0],
        )
        replay = self.store.commit_terminal_closeout(
            closeout_key=closeout_key,
            attempt_id=watcher["attempt_id"],
            executor_token=watcher_token,
            now="2026-08-22T10:00:12Z",
        )
        self.assertEqual(committed, replay)
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_closeout_commits"
            ).fetchone()[0],
        )

    def test_message_queue_is_idempotent_and_recipient_fenced(self) -> None:
        source = self.snapshot()
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "notice_kind": "status",
            "mutation_authority": False,
            "subject": "issue-92-implementation",
            "summary": "Implementation status observed",
            "evidence": {"issue": 92},
            "next_observation": "Observe the next exact-head state.",
        }
        first = self.store.enqueue_message(
            idempotency_key="issue-92-generation-3-implement",
            recipient_session_id=SESSION,
            topic="coordination.notice",
            payload=payload,
            now="2026-08-22T10:00:00Z",
        )
        second = self.store.enqueue_message(
            idempotency_key="issue-92-generation-3-implement",
            recipient_session_id=SESSION,
            topic="coordination.notice",
            payload=payload,
            now="2026-08-22T10:00:01Z",
        )
        self.assertEqual(first, second)
        with self.assertRaisesRegex(CoordinationError, "IDEMPOTENCY_CONFLICT"):
            self.store.enqueue_message(
                idempotency_key="issue-92-generation-3-implement",
                recipient_session_id=SESSION,
                topic="coordination.notice",
                payload={**payload, "evidence": {"issue": 94}},
                now="2026-08-22T10:00:02Z",
            )
        claimed = self.store.claim_message(first, SESSION, "2026-08-22T10:00:03Z")
        self.assertEqual("CLAIMED", claimed["state"])
        self.store.complete_message(first, SESSION, "2026-08-22T10:00:04Z")
        state = self.store.connection.execute(
            "SELECT state FROM coordination_messages WHERE id=?", (first,)
        ).fetchone()[0]
        self.assertEqual("COMPLETE", state)

    def test_message_claim_holds_when_github_source_drifted(self) -> None:
        source = self.snapshot()
        message = self.store.enqueue_message(
            idempotency_key="issue-92-source-fence",
            recipient_session_id=SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "source-fence",
                "summary": "Source fence observed",
                "evidence": {},
                "next_observation": "Observe the source snapshot digest.",
            },
            now="2026-08-22T10:00:00Z",
        )
        self.snapshot(updated="2026-08-22T11:00:00Z", title="Changed")
        with self.assertRaisesRegex(CoordinationError, "SOURCE_SNAPSHOT_DRIFT"):
            self.store.claim_message(message, SESSION, "2026-08-22T11:00:01Z")
        row = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?", (message,)
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(row))

    def test_message_completion_holds_when_source_drifted_after_claim(self) -> None:
        source = self.snapshot()
        message = self.store.enqueue_message(
            idempotency_key="issue-92-completion-fence",
            recipient_session_id=SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "completion-fence",
                "summary": "Completion fence observed",
                "evidence": {},
                "next_observation": "Observe completion state.",
            },
            now="2026-08-22T10:00:00Z",
        )
        self.store.claim_message(message, SESSION, "2026-08-22T10:00:01Z")
        self.snapshot(updated="2026-08-22T11:00:00Z", title="Changed")
        with self.assertRaisesRegex(CoordinationError, "SOURCE_SNAPSHOT_DRIFT"):
            self.store.complete_message(message, SESSION, "2026-08-22T11:00:01Z")
        row = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?", (message,)
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(row))

    def test_notice_rejects_mutation_shaped_fields(self) -> None:
        source = self.snapshot()
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "notice_kind": "status",
            "mutation_authority": False,
            "subject": "held-out-notice",
            "summary": "Held-out notice evidence",
            "evidence": {},
            "next_observation": "Observe the next state.",
        }
        unsafe_payloads = (
            {**base, "action": "PUSH_EXISTING_EXACT_COMMIT"},
            {**base, "command": "git push origin exact-head"},
            {**base, "already_authorized": True},
            {**base, "evidence": {"commands": ["gh api --method POST"]}},
            {**base, "Command": "git push origin exact-head"},
            {**base, "evidence": {"instruction": {"shell": "git push"}}},
            {**base, "next_action": "Run git push origin exact-head"},
            {**base, "summary": "Run git push origin exact-head"},
            {**base, "summary": "git -C /tmp/repo push origin exact-head"},
            {**base, "summary": "Please run git push origin exact-head"},
            {**base, "summary": "Execute gh api --method POST /repos/example"},
            {**base, "summary": "Use docker compose up --build"},
            {**base, "summary": "Proceed to run git push origin exact-head"},
            {**base, "summary": "Run: git push origin exact-head"},
            {**base, "summary": "Git push is authorized for exact-head."},
            {**base, "summary": "git status && git push origin exact-head"},
            {**base, "summary": "/usr/bin/git push origin exact-head"},
            {
                **base,
                "summary": "git --git-dir=/tmp/repo/.git push origin exact-head",
            },
            {**base, "summary": "sudo git push origin exact-head"},
            {**base, "summary": "env git push origin exact-head"},
            {**base, "summary": "bash -lc 'git push origin exact-head'"},
            {**base, "summary": "git status | git push origin exact-head"},
            {
                **base,
                "summary": "git -C /tmp/repo push is authorized for exact-head.",
            },
            {**base, "summary": "Git push is allowed for exact-head."},
            {
                **base,
                "summary": "git -C /tmp/repo -c color.ui=false --no-pager push origin exact-head",
            },
            {
                **base,
                "summary": "git -C /tmp/repo -c color.ui=false --no-pager push is authorized for exact-head.",
            },
            {
                **base,
                "summary": "git --git-dir /tmp/repo/metadata push origin exact-head",
            },
            {
                **base,
                "summary": "git --work-tree /tmp/repo push origin exact-head",
            },
            {
                **base,
                "summary": "git --git-dir /tmp/repo/metadata push is authorized for exact-head.",
            },
            {**base, "summary": "Run git add frontend/src/App.tsx"},
            {**base, "summary": "git rebase origin/main"},
            {**base, "summary": "git cherry-pick 0123456789abcdef"},
            {**base, "summary": "git stash push -m repair"},
            {**base, "summary": "git clean -fd"},
            {**base, "summary": "git tag release-candidate"},
            {**base, "summary": "git pull --rebase origin main"},
            {**base, "summary": "gh pr create --title repair --body bounded"},
            {**base, "summary": "gh issue comment 92 --body proceed"},
            {**base, "summary": "gh workflow run ci.yml"},
            {**base, "summary": "docker network rm issue92-network"},
            {**base, "summary": "docker rm removed"},
            {**base, "summary": "git push removed"},
            {**base, "summary": "git clean deleted"},
            {**base, "summary": "gh issue closed"},
            {**base, "summary": "rm removed"},
            {
                **base,
                "evidence": {"argv": ["git", "push", "origin", "exact-head"]},
            },
            {
                **base,
                "evidence": {
                    "program": "gh",
                    "arguments": ["pr", "create", "--title", "repair"],
                },
            },
            {
                **base,
                "evidence": {"tokens": ["docker", "compose", "up", "--build"]},
            },
            {
                **base,
                "evidence": {"parts": ["git", "push", "origin", "exact-head"]},
            },
            {**base, "summary": "Implementation is authorized to continue."},
            {
                **base,
                "summary": "Implementation is authorized while independent review remains pending.",
            },
            {**base, "summary": "Implementation is approved and not blocked."},
            {**base, "summary": "Clearance is granted for implementation."},
            {**base, "summary": "The repair has the go-ahead."},
            {**base, "summary": "Implementation may proceed."},
            {**base, "summary": "Repair can continue."},
            {**base, "summary": "Work should resume."},
            {**base, "summary": "The change is cleared to proceed."},
            {**base, "summary": "The repair is greenlit."},
            {**base, "summary": "Development may proceed."},
            {**base, "summary": "Repair can move forward."},
            {**base, "summary": "The repair has the green light."},
            {**base, "summary": "Consent has been given for implementation."},
            {**base, "summary": "Implementation is ready to proceed."},
            {**base, "summary": "Repair is unblocked."},
            {
                **base,
                "subject": "implementation",
                "summary": "may proceed",
            },
            {
                **base,
                "evidence": {
                    "scope": "implementation",
                    "disposition": "may proceed",
                },
            },
            {**base, "evidence": {"parts": ["merge", "should begin"]}},
            {**base, "evidence": {"implementation": "may proceed"}},
            {**base, "evidence": {"git": "push origin exact-head"}},
            {**base, "evidence": {"implementation_may_proceed": True}},
            {**base, "evidence": {"mutationAuthorityGranted": True}},
            {**base, "evidence": {"implementationMayProceed": True}},
            {**base, "evidence": {"gitPushOriginExactHead": True}},
            {**base, "evidence": {"parts": ("merge", "should begin")}},
            {**base, "evidence": {"parts": ("git", "push", "origin")}},
            {
                **base,
                "subject": "git",
                "summary": "push origin exact-head",
            },
            {
                **base,
                "summary": "The exact-head repair is approved; proceed with implementation.",
            },
            {
                **base,
                "evidence": {
                    "decision": "AUTHORIZED",
                    "scope": "continue implementation",
                },
            },
            {**base, "summary": "Proceed with the bounded repair work."},
        )
        for index, payload in enumerate(unsafe_payloads):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    CoordinationError, "NOTICE_MUTATION_FIELDS_FORBIDDEN"
                ):
                    self.store.enqueue_message(
                        idempotency_key=f"unsafe-notice-{index}",
                        recipient_session_id=SESSION,
                        topic="coordination.notice",
                        payload=payload,
                        now="2026-08-22T10:00:00Z",
                    )

    def test_notice_accepts_factual_command_evidence(self) -> None:
        source = self.snapshot()
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "notice_kind": "status",
            "mutation_authority": False,
            "subject": "factual-notice",
            "evidence": {},
            "next_observation": "Observe the next state.",
        }
        summaries = (
            "Docker Compose gate passed at the exact head.",
            "Git push was not performed.",
            "Git clients cannot push the exact head.",
            "Implementation is not authorized by this notice.",
            "The prior approval was revoked.",
            "Authorization remains pending.",
            "Permission was denied.",
            "Implementation cannot proceed while review is pending.",
            "Work should not resume until the source digest is current.",
        )
        for index, summary in enumerate(summaries):
            with self.subTest(index=index):
                self.store.enqueue_message(
                    idempotency_key=f"factual-notice-{index}",
                    recipient_session_id=SESSION,
                    topic="coordination.notice",
                    payload={**base, "summary": summary},
                    now="2026-08-22T10:00:00Z",
                )

    def test_terminal_notice_accepts_factual_resource_state_keys(self) -> None:
        source = self.snapshot()
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "notice_kind": "terminal_receipt",
            "mutation_authority": False,
            "subject": "issue-92-terminal-receipt",
            "summary": "Issue-owned cleanup and capacity release completed.",
            "evidence": {
                "cleanup": {
                    "docker_resources_absent": True,
                    "local_branch_absent": True,
                    "owned_container_resources": "were absent",
                    "remote_branch_deleted": True,
                    "worktree_removed": True,
                },
                "capacity_release": {
                    "development_units_released": 1,
                    "shared_units_released": 1,
                },
            },
        }
        message_id = self.store.enqueue_message(
            idempotency_key="terminal-factual-resource-state",
            recipient_session_id=SESSION,
            topic="coordination.notice",
            payload=payload,
            now="2026-08-22T10:00:00Z",
        )

        self.assertGreater(message_id, 0)

    def test_terminal_notice_rejects_untyped_cleanup_command_aliases(self) -> None:
        source = self.snapshot()
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "notice_kind": "terminal_receipt",
            "mutation_authority": False,
            "subject": "issue-92-terminal-receipt",
            "summary": "Cleanup evidence was recorded.",
        }
        unsafe_cleanup = (
            {"docker_rm_removed": True},
            {"git_push_removed": True},
            {"git_clean_deleted": True},
            {"gh_issue_closed": True},
            {"rm_removed": True},
            {"docker_resources_absent": "true"},
        )
        for index, cleanup in enumerate(unsafe_cleanup):
            with self.subTest(index=index):
                with self.assertRaisesRegex(CoordinationError, "NOTICE_SCHEMA_INVALID"):
                    self.store.enqueue_message(
                        idempotency_key=f"terminal-unsafe-cleanup-{index}",
                        recipient_session_id=SESSION,
                        topic="coordination.notice",
                        payload={**base, "evidence": {"cleanup": cleanup}},
                        now="2026-08-22T10:00:00Z",
                    )

    def test_notice_requires_closed_kind(self) -> None:
        source = self.snapshot()
        with self.assertRaisesRegex(CoordinationError, "NOTICE_KIND_INVALID"):
            self.store.enqueue_message(
                idempotency_key="notice-without-kind",
                recipient_session_id=SESSION,
                topic="coordination.notice",
                payload={
                    "source": {
                        "repository": REPOSITORY,
                        "object_kind": "issue",
                        "object_number": 92,
                        "payload_sha256": source.payload_sha256,
                    },
                    "mutation_authority": False,
                },
                now="2026-08-22T10:00:00Z",
            )

    def test_mutating_handoff_is_typed_and_recovery_commit_binds_prepare(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="ACTIVE",
            generation=4,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T09:59:59Z",
        )
        recovery_contract = {
            "commands": ["uv venv issue92", "uv pip install --link-mode copy"],
            "timeout_seconds": 900,
        }
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 4,
            "item_version": 1,
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "environment_root": "/home/ubuntu/.codex/twinfinity-issue92-prepush-venv",
            "recovery_contract": recovery_contract,
            "recovery_contract_sha256": digest_json(recovery_contract),
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
        }
        with self.assertRaisesRegex(CoordinationError, "MESSAGE_TOPIC_INVALID"):
            self.store.enqueue_message(
                idempotency_key="arbitrary",
                recipient_session_id=SESSION,
                topic="development.handoff",
                payload={**base, "action": "IMPLEMENT"},
                now="2026-08-22T10:00:00Z",
            )
        prepare = self.store.enqueue_message(
            idempotency_key="recovery-prepare",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:00Z",
        )
        self.store.claim_message(prepare, SESSION, "2026-08-22T10:00:01Z")
        self.store.complete_message(prepare, SESSION, "2026-08-22T10:00:02Z")
        with self.assertRaisesRegex(CoordinationError, "RECOVERY_CONTRACT_DRIFT"):
            self.store.enqueue_message(
                idempotency_key="recovery-commit-changed-worktree",
                recipient_session_id=SESSION,
                topic="development.recovery_commit",
                payload={
                    **base,
                    "opaque_worktree_id": "different-worktree-identity",
                    "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                    "prior_message_id": prepare,
                },
                now="2026-08-22T10:00:03Z",
            )
        changed_contract = {
            **recovery_contract,
            "timeout_seconds": 1800,
        }
        with self.assertRaisesRegex(CoordinationError, "RECOVERY_CONTRACT_DRIFT"):
            self.store.enqueue_message(
                idempotency_key="recovery-commit-changed-contract",
                recipient_session_id=SESSION,
                topic="development.recovery_commit",
                payload={
                    **base,
                    "recovery_contract": changed_contract,
                    "recovery_contract_sha256": digest_json(changed_contract),
                    "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                    "prior_message_id": prepare,
                },
                now="2026-08-22T10:00:03Z",
            )
        with self.assertRaisesRegex(
            CoordinationError, "RECOVERY_CONTRACT_DIGEST_MISMATCH"
        ):
            self.store.enqueue_message(
                idempotency_key="recovery-commit-invalid-contract-digest",
                recipient_session_id=SESSION,
                topic="development.recovery_commit",
                payload={
                    **base,
                    "recovery_contract_sha256": "8" * 64,
                    "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                    "prior_message_id": prepare,
                },
                now="2026-08-22T10:00:03Z",
            )
        with self.assertRaisesRegex(CoordinationError, "RECOVERY_CONTRACT_DRIFT"):
            self.store.enqueue_message(
                idempotency_key="recovery-commit-changed-environment",
                recipient_session_id=SESSION,
                topic="development.recovery_commit",
                payload={
                    **base,
                    "environment_root": "/home/ubuntu/.codex/twinfinity-issue92-other-venv",
                    "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                    "prior_message_id": prepare,
                },
                now="2026-08-22T10:00:03Z",
            )
        commit = self.store.enqueue_message(
            idempotency_key="recovery-commit",
            recipient_session_id=SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:03Z",
        )
        self.assertGreater(commit, prepare)

    def test_recovery_reused_environment_is_artifact_bound_and_drift_fenced(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=4,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        evidence = self.database.parent / "environment-rebuild.log"
        evidence.write_text("verified environment\n", encoding="utf-8")
        log_artifact = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 4,
                    "path": str(evidence),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )[0]
        receipt_path = self.database.parent / "environment-rebuild-receipt.json"
        receipt_path.write_text(
            json.dumps(
                {
                    "kind": "TWINFINITY_ENVIRONMENT_REBUILD_RECEIPT_V1",
                    "state": "PASS",
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 4,
                    "source_payload_sha256": source.payload_sha256,
                    "built_candidate_head_sha": "a" * 40,
                    "environment_root": "/home/ubuntu/.codex/twinfinity-issue92-prepush-venv-v3",
                    "requirements": [
                        {"path": "backend/requirements.txt", "sha256": "6" * 64}
                    ],
                    "freeze_sha256": "8" * 64,
                    "package_count": 42,
                    "gate_environment_provenance_sha256": "9" * 64,
                    "log_artifact_key": log_artifact["artifact_key"],
                    "log_artifact_content_sha256": log_artifact["content_sha256"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        artifact = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 4,
                    "path": str(receipt_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )[0]
        existing_environment = {
            "root": "/home/ubuntu/.codex/twinfinity-issue92-prepush-venv-v3",
            "rebuild_artifact_key": artifact["artifact_key"],
            "rebuild_artifact_content_sha256": artifact["content_sha256"],
            "freeze_sha256": "8" * 64,
            "package_count": 42,
            "gate_environment_provenance_sha256": "9" * 64,
        }
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 4,
            "item_version": 1,
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "existing_environment": existing_environment,
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
        }
        missing_provenance = dict(existing_environment)
        missing_provenance.pop("gate_environment_provenance_sha256")
        with self.assertRaisesRegex(
            CoordinationError, "MESSAGE_EXISTING_ENVIRONMENT_INVALID"
        ):
            self.store.enqueue_message(
                idempotency_key="missing-environment-provenance-prepare",
                recipient_session_id=SESSION,
                topic="development.recovery_prepare",
                payload={
                    **base,
                    "existing_environment": missing_provenance,
                    "action": "ACK_ZERO_MUTATION",
                },
                now="2026-08-22T10:00:03Z",
            )
        with self.assertRaisesRegex(
            CoordinationError, "MESSAGE_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
        ):
            self.store.enqueue_message(
                idempotency_key="unrelated-environment-artifact-prepare",
                recipient_session_id=SESSION,
                topic="development.recovery_prepare",
                payload={
                    **base,
                    "existing_environment": {
                        **existing_environment,
                        "rebuild_artifact_key": log_artifact["artifact_key"],
                        "rebuild_artifact_content_sha256": log_artifact[
                            "content_sha256"
                        ],
                    },
                    "action": "ACK_ZERO_MUTATION",
                },
                now="2026-08-22T10:00:03Z",
            )
        ephemeral_receipt_path = self.database.parent / "ephemeral-receipt.json"
        ephemeral_receipt_path.write_bytes(receipt_path.read_bytes())
        ephemeral_receipt = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 4,
                    "path": str(ephemeral_receipt_path),
                    "retention_class": "EPHEMERAL",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )[0]
        with self.assertRaisesRegex(CoordinationError, "ARTIFACT_LINEAGE_MISMATCH"):
            self.store.enqueue_message(
                idempotency_key="wrong-class-environment-artifact-prepare",
                recipient_session_id=SESSION,
                topic="development.recovery_prepare",
                payload={
                    **base,
                    "existing_environment": {
                        **existing_environment,
                        "rebuild_artifact_key": ephemeral_receipt["artifact_key"],
                        "rebuild_artifact_content_sha256": ephemeral_receipt[
                            "content_sha256"
                        ],
                    },
                    "action": "ACK_ZERO_MUTATION",
                },
                now="2026-08-22T10:00:03Z",
            )
        unsafe_receipt_path = self.database.parent / "unsafe-receipt.json"
        unsafe_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        unsafe_receipt["requirements"][0]["path"] = "../requirements.txt"
        unsafe_receipt_path.write_text(
            json.dumps(unsafe_receipt, sort_keys=True) + "\n", encoding="utf-8"
        )
        unsafe_receipt_artifact = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 4,
                    "path": str(unsafe_receipt_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )[0]
        with self.assertRaisesRegex(
            CoordinationError, "MESSAGE_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
        ):
            self.store.enqueue_message(
                idempotency_key="unsafe-environment-receipt-prepare",
                recipient_session_id=SESSION,
                topic="development.recovery_prepare",
                payload={
                    **base,
                    "existing_environment": {
                        **existing_environment,
                        "rebuild_artifact_key": unsafe_receipt_artifact[
                            "artifact_key"
                        ],
                        "rebuild_artifact_content_sha256": (
                            unsafe_receipt_artifact["content_sha256"]
                        ),
                    },
                    "action": "ACK_ZERO_MUTATION",
                },
                now="2026-08-22T10:00:03Z",
            )
        prepare = self.store.enqueue_message(
            idempotency_key="reused-environment-prepare",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:04Z",
        )
        self.store.claim_message(prepare, SESSION, "2026-08-22T10:00:05Z")
        self.store.complete_message(prepare, SESSION, "2026-08-22T10:00:06Z")
        drifted_receipt_path = (
            self.database.parent / "environment-rebuild-receipt-drifted.json"
        )
        drifted_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        drifted_receipt["package_count"] = 43
        drifted_receipt_path.write_text(
            json.dumps(drifted_receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        drifted_artifact = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 4,
                    "path": str(drifted_receipt_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-22T10:00:06Z",
        )[0]
        with self.assertRaisesRegex(CoordinationError, "RECOVERY_CONTRACT_DRIFT"):
            self.store.enqueue_message(
                idempotency_key="reused-environment-drifted-commit",
                recipient_session_id=SESSION,
                topic="development.recovery_commit",
                payload={
                    **base,
                    "existing_environment": {
                        **existing_environment,
                        "rebuild_artifact_key": drifted_artifact["artifact_key"],
                        "rebuild_artifact_content_sha256": drifted_artifact[
                            "content_sha256"
                        ],
                        "package_count": 43,
                    },
                    "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                    "prior_message_id": prepare,
                },
                now="2026-08-22T10:00:07Z",
            )
        commit = self.store.enqueue_message(
            idempotency_key="reused-environment-commit",
            recipient_session_id=SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:08Z",
        )
        self.assertGreater(commit, prepare)
        receipt_path.write_text("drifted environment\n", encoding="utf-8")
        with self.assertRaisesRegex(CoordinationError, "ARTIFACT_CONTENT_DRIFT"):
            self.store.verify_registered_artifact(
                artifact_key=artifact["artifact_key"],
                repository=REPOSITORY,
                issue_number=92,
                generation=4,
                expected_content_sha256=artifact["content_sha256"],
            )

    def test_planner_can_hold_only_exact_unclaimed_prepared_message(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 1,
            "item_version": 1,
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
            "action": "ACK_ZERO_MUTATION",
        }
        message_id = self.store.enqueue_message(
            idempotency_key="hold-exact-prepared-message",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload=payload,
            now="2026-08-22T10:00:03Z",
        )
        digest = self.store.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()[0]
        with self.assertRaisesRegex(CoordinationError, "PLANNER_SESSION_REQUIRED"):
            self.store.hold_prepared_message(
                message_id=message_id,
                expected_payload_sha256=digest,
                reason="SUPERSEDED_BY_ARTIFACT_REBIND",
                session_id=SESSION,
                now="2026-08-22T10:00:04Z",
            )
        with self.assertRaisesRegex(CoordinationError, "MESSAGE_PAYLOAD_MISMATCH"):
            self.store.hold_prepared_message(
                message_id=message_id,
                expected_payload_sha256="9" * 64,
                reason="SUPERSEDED_BY_ARTIFACT_REBIND",
                session_id=PLANNER_SESSION,
                now="2026-08-22T10:00:04Z",
            )
        held = self.store.hold_prepared_message(
            message_id=message_id,
            expected_payload_sha256=digest,
            reason="SUPERSEDED_BY_ARTIFACT_REBIND",
            session_id=PLANNER_SESSION,
            now="2026-08-22T10:00:05Z",
        )
        self.assertEqual(
            ("HOLD", "SUPERSEDED_BY_ARTIFACT_REBIND"),
            (held["state"], held["last_error"]),
        )
        repeated = self.store.hold_prepared_message(
            message_id=message_id,
            expected_payload_sha256=digest,
            reason="SUPERSEDED_BY_ARTIFACT_REBIND",
            session_id=PLANNER_SESSION,
            now="2026-08-22T10:00:06Z",
        )
        self.assertEqual("HOLD", repeated["state"])
        with self.assertRaisesRegex(CoordinationError, "MESSAGE_STATE_CONFLICT"):
            self.store.claim_message(message_id, SESSION, "2026-08-22T10:00:07Z")

        environment_message = self.store.enqueue_message(
            idempotency_key="hold-environment-rebind-prepared-message",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload=payload,
            now="2026-08-22T10:00:08Z",
        )
        environment_digest = self.store.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (environment_message,),
        ).fetchone()[0]
        environment_held = self.store.hold_prepared_message(
            message_id=environment_message,
            expected_payload_sha256=environment_digest,
            reason="SUPERSEDED_BY_ENVIRONMENT_REBIND",
            session_id=PLANNER_SESSION,
            now="2026-08-22T10:00:09Z",
        )
        self.assertEqual(
            ("HOLD", "SUPERSEDED_BY_ENVIRONMENT_REBIND"),
            (environment_held["state"], environment_held["last_error"]),
        )

    def test_legacy_planner_notice_cutover_is_one_exact_atomic_window(self) -> None:
        with reviewed_planner_rotation_catalog(
            ROOT, Path(self.temp.name)
        ) as config:
            aliases, alias_sha = load_legacy_alias_fixture(
                ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
            )
            plan = build_plan(
                self.store.connection,
                config,
                aliases,
                alias_fixture_sha256=alias_sha,
            )
            apply_plan(
                self.store.connection,
                plan=plan,
                operation_key="legacy-notice-cutover-test",
                expected_plan_sha256=plan["plan_sha256"],
                now="2026-08-22T10:00:00Z",
            )
            legacy = "role.planner.v2"
            current = "role.planner.v3"
            source = self.snapshot()
            payload = {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "subject": "Legacy cutover notice",
                "summary": "Non-authorizing historical notice.",
                "evidence": {"status": "historical"},
                "next_observation": "Read current SQLite and GitHub state.",
                "mutation_authority": False,
            }
            message_id = self.store.enqueue_message(
                idempotency_key="legacy-notice-cutover",
                recipient_session_id=current,
                topic="coordination.notice",
                payload=payload,
                now="2026-08-22T10:00:01Z",
            )
            self.store.connection.execute(
                "DROP TRIGGER coordination_message_envelope_immutable"
            )
            self.store.connection.execute(
                "UPDATE coordination_messages SET recipient_session_id=? WHERE id=?",
                (legacy, message_id),
            )
            manifest = self.store.prepared_legacy_notice_manifest(legacy)
            with self.assertRaisesRegex(CoordinationError, "MANIFEST_DRIFT"):
                self.store.retire_prepared_legacy_notices(
                    legacy_recipient=legacy,
                    current_planner_endpoint=current,
                    expected_manifest_sha256="9" * 64,
                    now="2026-08-22T10:00:02Z",
                )
            result = self.store.retire_prepared_legacy_notices(
                legacy_recipient=legacy,
                current_planner_endpoint=current,
                expected_manifest_sha256=manifest["manifest_sha256"],
                now="2026-08-22T10:00:03Z",
            )
            self.assertEqual((1, "HOLD"), (result["count"], result["state"]))
            row = self.store.connection.execute(
                "SELECT state,last_error FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()
            self.assertEqual(
                ("HOLD", "SUPERSEDED_BY_ROLE_ENDPOINT_CUTOVER"), tuple(row)
            )

    def test_claimed_recovery_activates_same_generation_atomically_and_idempotently(self) -> None:
        source = self.snapshot()
        held = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=4,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T09:59:59Z",
        )
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 4,
            "item_version": held["version"],
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
        }
        prepare = self.store.enqueue_message(
            idempotency_key="atomic-recovery-prepare",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:00Z",
        )
        self.store.claim_message(prepare, SESSION, "2026-08-22T10:00:01Z")
        self.store.complete_message(prepare, SESSION, "2026-08-22T10:00:02Z")
        commit = self.store.enqueue_message(
            idempotency_key="atomic-recovery-commit",
            recipient_session_id=SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:03Z",
        )
        with self.assertRaisesRegex(
            CoordinationError, "RECOVERY_COMMIT_NOT_CLAIMED"
        ):
            self.store.activate_recovery(
                message_id=commit,
                session_id=SESSION,
                now="2026-08-22T10:00:04Z",
            )
        self.store.claim_message(commit, SESSION, "2026-08-22T10:00:05Z")
        with self.assertRaisesRegex(CoordinationError, "WRONG_MESSAGE_RECIPIENT"):
            self.store.activate_recovery(
                message_id=commit,
                session_id=PLANNER_SESSION,
                now="2026-08-22T10:00:06Z",
            )

        activated, watch_key = self.store.activate_recovery(
            message_id=commit,
            session_id=SESSION,
            now="2026-08-22T10:00:07Z",
        )
        self.assertEqual(
            ("ACTIVE_FENCED", "ACTIVE", 4, 2),
            (
                activated["status"],
                activated["allocation_class"],
                activated["generation"],
                activated["version"],
            ),
        )
        observed = self.store.connection.execute(
            "SELECT state FROM coordination_messages WHERE id=?", (commit,)
        ).fetchone()
        self.assertEqual("COMPLETE", observed["state"])
        watch = self.store.connection.execute(
            "SELECT state, generation, accountable_session_id FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", 4, SESSION), tuple(watch))
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )

        repeated, repeated_watch = self.store.activate_recovery(
            message_id=commit,
            session_id=SESSION,
            now="2026-08-22T10:00:08Z",
        )
        self.assertEqual(activated, repeated)
        self.assertEqual(watch_key, repeated_watch)
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT version FROM coordination_items WHERE repository=? AND issue_number=92",
                (REPOSITORY,),
            ).fetchone()[0],
        )

        prepush = PrePushControl(self.database)
        try:
            lineage = prepush._lineage(REPOSITORY, 92)
            self.assertEqual(commit, lineage.admission_message_id)
            self.assertEqual(4, lineage.generation)
        finally:
            prepush.close()

    def test_recovery_activation_rolls_back_on_source_drift(self) -> None:
        source = self.snapshot()
        held = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=5,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T09:59:59Z",
        )
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 5,
            "item_version": held["version"],
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
        }
        prepare = self.store.enqueue_message(
            idempotency_key="drift-recovery-prepare",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:00Z",
        )
        self.store.claim_message(prepare, SESSION, "2026-08-22T10:00:01Z")
        self.store.complete_message(prepare, SESSION, "2026-08-22T10:00:02Z")
        commit = self.store.enqueue_message(
            idempotency_key="drift-recovery-commit",
            recipient_session_id=SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:03Z",
        )
        self.store.claim_message(commit, SESSION, "2026-08-22T10:00:04Z")
        self.snapshot(updated="2026-08-22T11:00:00Z", title="Changed")

        with self.assertRaisesRegex(CoordinationError, "SOURCE_SNAPSHOT_DRIFT"):
            self.store.activate_recovery(
                message_id=commit,
                session_id=SESSION,
                now="2026-08-22T11:00:01Z",
            )
        item = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(("HOLD", "RETAINED", 1), tuple(item))
        message = self.store.connection.execute(
            "SELECT state FROM coordination_messages WHERE id=?", (commit,)
        ).fetchone()
        self.assertEqual("CLAIMED", message["state"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches"
            ).fetchone()[0],
        )

    def test_recovery_reopens_completed_same_generation_watch(self) -> None:
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=6,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:00Z",
        )
        held = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=6,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:01Z",
        )
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:6"
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET attempts=3, process_id=123, last_error='OLD_FAILURE' WHERE watch_key=?",
            (watch_key,),
        )
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 6,
            "item_version": held["version"],
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
        }
        prepare = self.store.enqueue_message(
            idempotency_key="reopen-recovery-prepare",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:02Z",
        )
        self.store.claim_message(prepare, SESSION, "2026-08-22T10:00:03Z")
        self.store.complete_message(prepare, SESSION, "2026-08-22T10:00:04Z")
        commit = self.store.enqueue_message(
            idempotency_key="reopen-recovery-commit",
            recipient_session_id=SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:05Z",
        )
        self.store.claim_message(commit, SESSION, "2026-08-22T10:00:06Z")

        activated, observed_key = self.store.activate_recovery(
            message_id=commit,
            session_id=SESSION,
            now="2026-08-22T10:00:07Z",
        )

        self.assertEqual(watch_key, observed_key)
        self.assertEqual(("ACTIVE_FENCED", "ACTIVE", 6, 3), (
            activated["status"],
            activated["allocation_class"],
            activated["generation"],
            activated["version"],
        ))
        watch = self.store.connection.execute(
            "SELECT state, attempts, process_id, last_error FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", 0, None, None), tuple(watch))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches WHERE repository=? AND issue_number=92 AND generation=6",
                (REPOSITORY,),
            ).fetchone()[0],
        )
        self.assertEqual(
            "COMPLETE",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?", (commit,)
            ).fetchone()[0],
        )

    def test_recovery_watch_conflict_rolls_back_item_message_and_events(self) -> None:
        source = self.snapshot()
        held = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=7,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:00Z",
        )
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 7,
            "item_version": held["version"],
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
        }
        prepare = self.store.enqueue_message(
            idempotency_key="conflict-recovery-prepare",
            recipient_session_id=SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:01Z",
        )
        self.store.claim_message(prepare, SESSION, "2026-08-22T10:00:02Z")
        self.store.complete_message(prepare, SESSION, "2026-08-22T10:00:03Z")
        commit = self.store.enqueue_message(
            idempotency_key="conflict-recovery-commit",
            recipient_session_id=SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:04Z",
        )
        self.store.claim_message(commit, SESSION, "2026-08-22T10:00:05Z")
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:7"
        self.store.connection.execute(
            """
            INSERT INTO coordination_terminal_watches(
                watch_key, repository, issue_number, generation,
                accountable_session_id, lease_manifest_sha256, state,
                attempts, process_id, last_heartbeat_at, next_wake_at,
                updated_at, last_error
            ) VALUES (?, ?, 92, 7, ?, ?, 'COMPLETE', 4, 777, ?, ?, ?, 'CONFLICT')
            """,
            (
                watch_key,
                REPOSITORY,
                SESSION,
                "6" * 64,
                "2026-08-22T10:00:00Z",
                "2026-08-22T10:05:00Z",
                "2026-08-22T10:00:00Z",
            ),
        )
        before_events = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events"
        ).fetchone()[0]

        with self.assertRaisesRegex(
            CoordinationError, "RECOVERY_TERMINAL_WATCH_CONFLICT"
        ):
            self.store.activate_recovery(
                message_id=commit,
                session_id=SESSION,
                now="2026-08-22T10:00:06Z",
            )

        item = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(("HOLD", "RETAINED", 1), tuple(item))
        self.assertEqual(
            "CLAIMED",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?", (commit,)
            ).fetchone()[0],
        )
        watch = self.store.connection.execute(
            "SELECT state, attempts, process_id, lease_manifest_sha256, last_error FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(("COMPLETE", 4, 777, "6" * 64, "CONFLICT"), tuple(watch))
        self.assertEqual(
            before_events,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0],
        )

    def test_mutating_message_completion_holds_after_item_state_change(self) -> None:
        source = self.snapshot()
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:00Z",
        )
        message = self.store.enqueue_message(
            idempotency_key="admission-item-completion-fence",
            recipient_session_id=SESSION,
            topic="development.admission",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "issue_number": 92,
                "generation": 3,
                "item_version": 1,
                "base_sha": "a" * 40,
                "branch": "codex/92-transcript-review-editor",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
                "opaque_worktree_id": "twinfinityapp-issue-92",
                "accountable_session_id": SESSION,
                "lease_manifest_sha256": LEASE,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 1,
                    "sre_units": 0,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
            now="2026-08-22T10:00:01Z",
        )
        envelope = self.store.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (message,),
        ).fetchone()
        self.store.connection.execute(
            """
            UPDATE coordination_terminal_watches
            SET admission_message_id=?, admission_payload_sha256=?
            WHERE repository=? AND issue_number=92 AND generation=3
            """,
            (message, envelope["payload_sha256"], REPOSITORY),
        )
        self.store.claim_message(message, SESSION, "2026-08-22T10:00:02Z")
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=1,
            now="2026-08-22T10:00:03Z",
        )
        with self.assertRaisesRegex(CoordinationError, "MESSAGE_ITEM_STATE_MISMATCH"):
            self.store.complete_message(message, SESSION, "2026-08-22T10:00:04Z")
        state = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?", (message,)
        ).fetchone()
        self.assertEqual(("HOLD", "MESSAGE_ITEM_STATE_MISMATCH"), tuple(state))

    def test_outbox_is_idempotent_and_never_blindly_rereserved(self) -> None:
        source = self.snapshot()
        outbox = self.store.enqueue_comment(
            idempotency_key="issue-92-terminal-receipt",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            expected_source_sha256=source.payload_sha256,
            body="Terminal receipt",
            now="2026-08-22T10:00:02Z",
        )
        reserved = self.store.reserve_outbox(outbox, "2026-08-22T10:00:03Z")
        self.assertEqual("INFLIGHT", reserved["state"])
        with self.assertRaisesRegex(CoordinationError, "OUTBOX_STATE_CONFLICT"):
            self.store.reserve_outbox(outbox, "2026-08-22T10:00:04Z")
        self.store.complete_outbox(outbox, "comment:123", "2026-08-22T10:00:05Z")
        with self.assertRaisesRegex(CoordinationError, "OUTBOX_STATE_CONFLICT"):
            self.store.reserve_outbox(outbox, "2026-08-22T10:00:06Z")

    def test_second_connection_observes_atomic_commit(self) -> None:
        source = self.snapshot()
        peer = CoordinationStore(self.database)
        try:
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="ACTIVE",
                allocation_class="ACTIVE",
                generation=3,
                accountable_session_id=SESSION,
                lease_manifest_sha256=LEASE,
                development_units=1,
                shared_units=1,
                expected_source_sha256=source.payload_sha256,
                expected_version=0,
                now="2026-08-22T10:00:02Z",
            )
            observed = peer.connection.execute(
                "SELECT status, version FROM coordination_items WHERE repository=? AND issue_number=92",
                (REPOSITORY,),
            ).fetchone()
            self.assertEqual(("ACTIVE", 1), tuple(observed))
        finally:
            peer.close()

    def test_summary_marks_derived_status_stale_after_source_change(self) -> None:
        source = self.snapshot()
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.assertEqual(1, self.store.summary(REPOSITORY)["items"][0]["source_current"])
        self.snapshot(updated="2026-08-22T11:00:00Z", title="Changed")
        summary = self.store.summary(REPOSITORY)
        self.assertEqual(0, summary["items"][0]["source_current"])
        self.assertFalse(summary["capacity"]["source_current"])
        self.assertIsNone(summary["capacity"]["available_development"])

    def test_capacity_separates_active_and_retained_allocations(self) -> None:
        source = self.snapshot()
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        retained = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=115,
            payload={"number": 115, "updated_at": "2026-08-22T10:00:00Z"},
            source_updated_at="2026-08-22T10:00:00Z",
            fetched_at="2026-08-22T10:00:01Z",
        )
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=115,
            status="HOLD",
            allocation_class="RETAINED",
            generation=0,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=1,
            expected_source_sha256=retained.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        capacity = self.store.summary(REPOSITORY)["capacity"]
        self.assertEqual(1, capacity["active_development"])
        self.assertEqual(1, capacity["retained_development"])
        self.assertEqual(3, capacity["available_development"])
        self.assertEqual(0, capacity["available_shared"])

    def test_none_allocation_records_prospective_demand_without_reserving_capacity(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="PREPARED",
            allocation_class="NONE",
            generation=3,
            accountable_session_id=None,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        capacity = self.store.summary(REPOSITORY)["capacity"]
        self.assertEqual(1, capacity["prepared_development_demand"])
        self.assertEqual(5, capacity["available_development"])
        self.assertEqual(2, capacity["available_shared"])
        self.assertEqual(5, capacity["available_sre"])

    def test_repository_admission_and_summary_count_hosted_sre_reservations(self) -> None:
        self.store.set_capacity_policy(
            repository=REPOSITORY,
            development_limit=5,
            shared_limit=2,
            sre_limit=1,
            authority_sha256="c" * 64,
            expected_version=1,
            now="2026-08-22T10:00:01Z",
        )
        self.store.connection.execute(
            "CREATE TABLE hosted_operations (repository TEXT, state TEXT, sre_units INTEGER)"
        )
        self.store.connection.execute(
            "INSERT INTO hosted_operations(repository, state, sre_units) VALUES (?, 'PREPARED', 1)",
            (REPOSITORY,),
        )
        source = self.snapshot()
        capacity = self.store.summary(REPOSITORY)["capacity"]
        self.assertEqual(1, capacity["hosted_reserved_sre"])
        self.assertEqual(0, capacity["available_sre"])
        with self.assertRaisesRegex(CoordinationError, "CAPACITY_EXCEEDED"):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="ACTIVE",
                allocation_class="ACTIVE",
                generation=1,
                accountable_session_id=SRE_SESSION,
                lease_manifest_sha256=LEASE,
                development_units=0,
                shared_units=0,
                sre_units=1,
                expected_source_sha256=source.payload_sha256,
                expected_version=0,
                now="2026-08-22T10:00:02Z",
            )

    def test_issue_plan_applies_prospective_rows_atomically(self) -> None:
        first = self.issue_snapshot(87)
        second = self.issue_snapshot(95)
        entries = [
            {
                "repository": REPOSITORY,
                "issue_number": 87,
                "status": "PREPARED",
                "allocation_class": "NONE",
                "generation": 0,
                "accountable_session_id": None,
                "lease_manifest_sha256": None,
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
                "expected_source_sha256": first.payload_sha256,
                "expected_version": 0,
            },
            {
                "repository": REPOSITORY,
                "issue_number": 95,
                "status": "PREPARED",
                "allocation_class": "NONE",
                "generation": 0,
                "accountable_session_id": None,
                "lease_manifest_sha256": None,
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
                "expected_source_sha256": second.payload_sha256,
                "expected_version": 0,
            },
        ]
        rows = self.store.apply_issue_plan(entries, now="2026-08-22T10:00:02Z")
        self.assertEqual([87, 95], [row["issue_number"] for row in rows])
        capacity = self.store.summary(REPOSITORY)["capacity"]
        self.assertEqual(2, capacity["prepared_development_demand"])
        self.assertEqual(1, capacity["prepared_shared_demand"])
        event = self.store.connection.execute(
            "SELECT event_type FROM coordination_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual("ISSUE_PLAN_APPLIED", event["event_type"])

    def test_issue_plan_rolls_back_every_row_on_conflict(self) -> None:
        first = self.issue_snapshot(87)
        self.issue_snapshot(95)
        entries = [
            {
                "repository": REPOSITORY,
                "issue_number": 87,
                "status": "PREPARED",
                "allocation_class": "NONE",
                "generation": 0,
                "accountable_session_id": None,
                "lease_manifest_sha256": None,
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
                "expected_source_sha256": first.payload_sha256,
                "expected_version": 0,
            },
            {
                "repository": REPOSITORY,
                "issue_number": 95,
                "status": "PREPARED",
                "allocation_class": "NONE",
                "generation": 0,
                "accountable_session_id": None,
                "lease_manifest_sha256": None,
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
                "expected_source_sha256": "0" * 64,
                "expected_version": 0,
            },
        ]
        with self.assertRaisesRegex(CoordinationError, "SOURCE_SNAPSHOT_DRIFT"):
            self.store.apply_issue_plan(entries, now="2026-08-22T10:00:02Z")
        count = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_items WHERE issue_number IN (87, 95)"
        ).fetchone()[0]
        self.assertEqual(0, count)

    def test_capacity_ceiling_lease_collision_and_generation_are_enforced(self) -> None:
        source = self.snapshot()
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=4,
            shared_units=1,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        other = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=115,
            payload={"number": 115, "updated_at": "2026-08-22T10:00:00Z"},
            source_updated_at="2026-08-22T10:00:00Z",
            fetched_at="2026-08-22T10:00:01Z",
        )
        with self.assertRaisesRegex(CoordinationError, "LEASE_COLLISION"):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=115,
                status="ACTIVE",
                allocation_class="ACTIVE",
                generation=1,
                accountable_session_id=SESSION,
                lease_manifest_sha256=LEASE,
                development_units=1,
                shared_units=1,
                expected_source_sha256=other.payload_sha256,
                expected_version=0,
                now="2026-08-22T10:00:02Z",
            )
        with self.assertRaisesRegex(CoordinationError, "CAPACITY_EXCEEDED"):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=115,
                status="ACTIVE",
                allocation_class="ACTIVE",
                generation=1,
                accountable_session_id=SESSION,
                lease_manifest_sha256="6" * 64,
                development_units=2,
                shared_units=1,
                expected_source_sha256=other.payload_sha256,
                expected_version=0,
                now="2026-08-22T10:00:02Z",
            )
        with self.assertRaisesRegex(CoordinationError, "GENERATION_REGRESSION"):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="READY",
                allocation_class="NONE",
                generation=2,
                accountable_session_id=None,
                lease_manifest_sha256=LEASE,
                development_units=0,
                shared_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=1,
                now="2026-08-22T10:00:03Z",
            )

    def test_planner_can_hold_only_byte_identical_identity_drifted_artifact(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        plans = self.database.parent / "plans"
        plans.mkdir()
        artifact = plans / "issue-92-plan.json"
        artifact.write_text('{"issue":92}\n', encoding="utf-8")
        registered = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 1,
                    "path": str(artifact),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )[0]
        with self.assertRaisesRegex(CoordinationError, "PLANNER_SESSION_REQUIRED"):
            self.store.hold_drifted_artifact(
                artifact_key=registered["artifact_key"],
                expected_content_sha256=registered["content_sha256"],
                session_id=SESSION,
                now="2026-08-22T10:00:04Z",
            )
        with self.assertRaisesRegex(CoordinationError, "ARTIFACT_IDENTITY_CURRENT"):
            self.store.hold_drifted_artifact(
                artifact_key=registered["artifact_key"],
                expected_content_sha256=registered["content_sha256"],
                session_id=PLANNER_SESSION,
                now="2026-08-22T10:00:04Z",
            )
        replacement = plans / "replacement.tmp"
        replacement.write_bytes(artifact.read_bytes())
        os.replace(replacement, artifact)
        held = self.store.hold_drifted_artifact(
            artifact_key=registered["artifact_key"],
            expected_content_sha256=registered["content_sha256"],
            session_id=PLANNER_SESSION,
            now="2026-08-22T10:00:05Z",
        )
        self.assertEqual(
            ("HOLD", "ARTIFACT_IDENTITY_DRIFT"),
            (held["state"], held["last_error"]),
        )
        repeated = self.store.hold_drifted_artifact(
            artifact_key=registered["artifact_key"],
            expected_content_sha256=registered["content_sha256"],
            session_id=PLANNER_SESSION,
            now="2026-08-22T10:00:06Z",
        )
        self.assertEqual("HOLD", repeated["state"])

    def test_hold_drifted_artifact_rejects_changed_bytes(self) -> None:
        source = self.snapshot()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        plans = self.database.parent / "plans"
        plans.mkdir()
        artifact = plans / "issue-92-plan.json"
        artifact.write_text("before\n", encoding="utf-8")
        registered = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 1,
                    "path": str(artifact),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )[0]
        replacement = plans / "replacement.tmp"
        replacement.write_text("changed\n", encoding="utf-8")
        os.replace(replacement, artifact)
        with self.assertRaisesRegex(CoordinationError, "ARTIFACT_CONTENT_DRIFT"):
            self.store.hold_drifted_artifact(
                artifact_key=registered["artifact_key"],
                expected_content_sha256=registered["content_sha256"],
                session_id=PLANNER_SESSION,
                now="2026-08-22T10:00:04Z",
            )
        state = self.store.connection.execute(
            "SELECT state FROM coordination_artifacts WHERE artifact_key=?",
            (registered["artifact_key"],),
        ).fetchone()[0]
        self.assertEqual("REGISTERED", state)

    def test_registered_artifact_moves_only_after_exact_terminal_lineage_and_then_purges(self) -> None:
        self.install_all_current_endpoints()
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        plans = self.database.parent / "plans"
        plans.mkdir()
        artifact = plans / "issue-92-plan.json"
        artifact.write_text('{"issue":92}\n', encoding="utf-8")
        registered = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 1,
                    "path": str(artifact),
                    "retention_class": "EPHEMERAL",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )
        self.assertEqual(1, len(registered))
        active_gc = self.store.collect_artifacts(
            now="2026-08-22T10:00:04Z", execute=True
        )
        self.assertEqual([], active_gc["moved"])
        self.assertTrue(artifact.exists())

        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:05Z",
        )
        self.seed_committed_terminal_closeout_for_artifact_gc(
            source_sha256=source.payload_sha256, generation=1
        )
        collected = self.store.collect_artifacts(
            now="2026-08-22T10:00:06Z", execute=True
        )
        self.assertEqual([registered[0]["artifact_key"]], collected["moved"])
        self.assertFalse(artifact.exists())
        row = self.store.connection.execute(
            "SELECT state, trash_relative_path FROM coordination_artifacts"
        ).fetchone()
        self.assertEqual("TRASHED", row["state"])
        self.assertTrue((self.database.parent / row["trash_relative_path"]).exists())

        purged = self.store.collect_artifacts(
            now="2026-08-29T10:00:07Z", execute=True
        )
        self.assertEqual([registered[0]["artifact_key"]], purged["purged"])
        state = self.store.connection.execute(
            "SELECT state FROM coordination_artifacts"
        ).fetchone()[0]
        self.assertEqual("PURGED", state)

    def test_artifact_gc_ignores_unregistered_and_retained_files(self) -> None:
        self.install_all_current_endpoints()
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        retained = self.database.parent / "retained.md"
        unregistered = self.database.parent / "unregistered.md"
        retained.write_text("retain\n", encoding="utf-8")
        unregistered.write_text("user-owned\n", encoding="utf-8")
        self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 92,
                    "generation": 1,
                    "path": str(retained),
                    "retention_class": "RETAINED",
                }
            ],
            now="2026-08-22T10:00:03Z",
        )
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:04Z",
        )
        result = self.store.collect_artifacts(
            now="2026-09-30T10:00:00Z", execute=True
        )
        self.assertEqual([], result["moved"])
        self.assertTrue(retained.exists())
        self.assertTrue(unregistered.exists())

    def test_artifact_gc_lock_contention_is_nonblocking_noop(self) -> None:
        lock_path = self.database.parent / "artifact-gc.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.store.collect_artifacts(
                now="2026-08-22T10:00:00Z", execute=True
            )
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(
            {
                "mode": "EXECUTE",
                "contention": True,
                "moved": [],
                "purged": [],
                "held": [],
            },
            result,
        )

    def test_artifact_gc_waits_for_pending_controls_and_outbox(self) -> None:
        self.install_all_current_endpoints()
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        artifact = self.database.parent / "terminal-plan.json"
        artifact.write_text("{}\n", encoding="utf-8")
        self.store.register_artifacts(
            [{
                "repository": REPOSITORY,
                "issue_number": 92,
                "generation": 1,
                "path": str(artifact),
                "retention_class": "EPHEMERAL",
            }],
            now="2026-08-22T10:00:03Z",
        )
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:04Z",
        )
        self.seed_committed_terminal_closeout_for_artifact_gc(
            source_sha256=source.payload_sha256, generation=1
        )
        message_id = self.store.enqueue_message(
            idempotency_key="pending-terminal-control",
            recipient_session_id=PLANNER_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Terminal observation",
                "summary": "Terminal publication remains pending.",
                "evidence": {"item_version": 2},
            },
            now="2026-08-22T10:00:05Z",
        )
        self.assertEqual(
            [],
            self.store.collect_artifacts(
                now="2026-08-22T10:00:06Z", execute=True
            )["moved"],
        )
        self.assertTrue(artifact.exists())
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='HOLD' WHERE id=?",
            (message_id,),
        )
        self.store.enqueue_comment(
            idempotency_key="pending-terminal-outbox",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            expected_source_sha256=source.payload_sha256,
            body="Terminal receipt pending",
            now="2026-08-22T10:00:07Z",
        )
        self.assertEqual(
            [],
            self.store.collect_artifacts(
                now="2026-08-22T10:00:08Z", execute=True
            )["moved"],
        )
        self.assertTrue(artifact.exists())

    def test_artifact_move_reservation_fences_issue_transition(self) -> None:
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        artifact = self.database.parent / "reserved.json"
        artifact.write_text("{}\n", encoding="utf-8")
        self.store.register_artifacts(
            [{
                "repository": REPOSITORY,
                "issue_number": 92,
                "generation": 1,
                "path": str(artifact),
                "retention_class": "EPHEMERAL",
            }],
            now="2026-08-22T10:00:03Z",
        )
        terminal = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:04Z",
        )
        self.store.connection.execute(
            "UPDATE coordination_artifacts SET state='MOVE_RESERVED'"
        )
        with self.assertRaisesRegex(CoordinationError, "ARTIFACT_GC_INFLIGHT"):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="DONE",
                allocation_class="NONE",
                generation=2,
                accountable_session_id=SESSION,
                lease_manifest_sha256=LEASE,
                development_units=0,
                shared_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=terminal["version"],
                now="2026-08-22T10:00:05Z",
            )

    def test_artifact_gc_reconciles_crash_after_no_replace_link(self) -> None:
        self.install_all_current_endpoints()
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        artifact = self.database.parent / "crash.json"
        artifact.write_text("{}\n", encoding="utf-8")
        registered = self.store.register_artifacts(
            [{
                "repository": REPOSITORY,
                "issue_number": 92,
                "generation": 1,
                "path": str(artifact),
                "retention_class": "EPHEMERAL",
            }],
            now="2026-08-22T10:00:03Z",
        )[0]
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:04Z",
        )
        self.seed_committed_terminal_closeout_for_artifact_gc(
            source_sha256=source.payload_sha256, generation=1
        )
        trash = self.database.parent / ".artifact-trash"
        trash.mkdir(mode=0o700)
        trash_relative = (
            f".artifact-trash/{registered['artifact_key']}-{artifact.name}"
        )
        trash_file = self.database.parent / trash_relative
        trash_file.hardlink_to(artifact)
        self.store.connection.execute(
            "UPDATE coordination_artifacts SET state='MOVE_RESERVED', trash_relative_path=?",
            (trash_relative,),
        )
        result = self.store.collect_artifacts(
            now="2026-08-22T10:00:05Z", execute=True
        )
        self.assertEqual([registered["artifact_key"]], result["moved"])
        self.assertFalse(artifact.exists())
        self.assertTrue(trash_file.exists())
        self.assertEqual(
            "TRASHED",
            self.store.connection.execute(
                "SELECT state FROM coordination_artifacts"
            ).fetchone()[0],
        )

    def test_artifact_gc_holds_symlink_swap_without_touching_target(self) -> None:
        self.install_all_current_endpoints()
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        artifact = self.database.parent / "swap.json"
        target = self.database.parent / "user-owned.json"
        artifact.write_text("registered\n", encoding="utf-8")
        target.write_text("preserve\n", encoding="utf-8")
        self.store.register_artifacts(
            [{
                "repository": REPOSITORY,
                "issue_number": 92,
                "generation": 1,
                "path": str(artifact),
                "retention_class": "EPHEMERAL",
            }],
            now="2026-08-22T10:00:03Z",
        )
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:04Z",
        )
        self.seed_committed_terminal_closeout_for_artifact_gc(
            source_sha256=source.payload_sha256, generation=1
        )
        artifact.unlink()
        artifact.symlink_to(target)
        result = self.store.collect_artifacts(
            now="2026-08-22T10:00:05Z", execute=True
        )
        self.assertEqual([], result["moved"])
        self.assertEqual("preserve\n", target.read_text(encoding="utf-8"))
        self.assertEqual(
            "HOLD",
            self.store.connection.execute(
                "SELECT state FROM coordination_artifacts"
            ).fetchone()[0],
        )


if __name__ == "__main__":
    unittest.main()
