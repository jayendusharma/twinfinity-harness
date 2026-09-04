from __future__ import annotations

import unittest
import io
import json
import os
import sqlite3
import tempfile
from contextlib import redirect_stdout
from unittest.mock import patch

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import coordination_truth_snapshot as snapshot_module  # noqa: E402
from coordination_truth_snapshot import (  # noqa: E402
    SIDECAR_FREE_WAL_READ_BOUNDARY,
    SNAPSHOT_SCHEMA,
    SnapshotHold,
    snapshot_database,
)
from approval_ledger import (  # noqa: E402
    activate_semantic_contract_v2,
    ensure_schema as ensure_approval_schema,
    submit_proposal,
)
from hosted_operation_control import HostedOperationControl  # noqa: E402
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import ensure_schema as ensure_readiness_schema  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)
from coordination_store import canonical_json, digest_json  # noqa: E402
from routing_inventory_contract import (  # noqa: E402
    CLASSIFICATIONS,
    KIND as ROUTING_KIND,
    TAGS,
)


REPOSITORY = "twinfinityai/twinfinityapp"


class CoordinationTruthSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "state.sqlite3"
        self.control = HostedOperationControl(self.database)
        ensure_approval_schema(self.control.connection)
        ensure_readiness_schema(self.control.connection)
        ensure_pull_buffer_schema(self.control.connection)
        apply_reviewed_current_endpoint_catalog(
            self.control.connection,
            ROOT,
            operation_key="coordination-truth-snapshot-tests",
        )
        self.control.store.capacity_policy(
            REPOSITORY, now="2026-09-03T12:00:00Z"
        )

    def tearDown(self) -> None:
        if self.control is not None:
            self.control.close()
        self.temp.cleanup()

    def prime_wal_reader_mark(self) -> None:
        self.control.connection.execute(
            "SELECT COUNT(*) FROM sqlite_master"
        ).fetchone()

    def close_to_database_only_wal(self) -> list[str]:
        self.prime_wal_reader_mark()
        checkpoint = tuple(
            self.control.connection.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)"
            ).fetchone()
        )
        self.assertEqual((0, 0, 0), checkpoint)
        self.control.close()
        self.control = None
        self.database.chmod(0o600)
        self.assertEqual(b"\x02\x02", self.database.read_bytes()[18:20])
        namespace = sorted(
            entry.name for entry in self.database.parent.iterdir()
        )
        self.assertIn(self.database.name, namespace)
        self.assertFalse(Path(str(self.database) + "-wal").exists())
        self.assertFalse(Path(str(self.database) + "-shm").exists())
        self.assertFalse(Path(str(self.database) + "-journal").exists())
        return namespace

    @staticmethod
    def synthetic_wal_filesystem_state() -> dict:
        def identity(*, inode: int, digest: str) -> dict:
            return {
                "device": 2096,
                "inode": inode,
                "mode": 0o600,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "links": 1,
                "size": 4096,
                "mtime_ns": 100,
                "ctime_ns": 100,
                "atime_ns": 100,
                "sha256": digest,
            }

        parent = {
            "device": 2096,
            "inode": 10,
            "mode": 0o700,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "links": 2,
        }
        return {
            "parent_chain": [dict(parent)],
            "parent": dict(parent),
            "namespace": ["state.sqlite3", "state.sqlite3-shm", "state.sqlite3-wal"],
            "files": {
                "database": identity(inode=11, digest="a" * 64),
                "-wal": identity(inode=12, digest="b" * 64),
                "-shm": identity(inode=13, digest="c" * 64),
            },
        }

    def approval_packet(self, schema: str) -> dict:
        return {
            "schema": schema,
            "decision_key": "issue-338:snapshot-test",
            "repository": REPOSITORY,
            "owning_issue": 338,
            "source_snapshot_sha256": self.control.store.current_snapshot(
                REPOSITORY, "issue", 338
            ).payload_sha256,
            "execution_scope_sha256": "9" * 64,
            "requester_session_id": "role.development.v4",
            "recipient_session_id": "role.development.v4",
            "workstream": "DEVELOPMENT",
            "boundary": "PRODUCT_BEHAVIOR",
            "priority": "P0",
            "urgency": "ACTIVE_BLOCKER",
            "summary": "Synthetic snapshot approval",
            "question": "Proceed?",
            "requested_action": "Exercise only the disposable fixture.",
            "target": "Synthetic issue 338",
            "affected_issues": [338],
            "blocked_mutation": "Synthetic mutation remains blocked.",
            "immediate_beneficiary": "Snapshot test",
            "evidence": ["PRIVATE_APPROVAL_EVIDENCE_SENTINEL"],
            "risk": "Synthetic only.",
            "drift_guards": ["Source stays exact."],
            "prohibited_side_effects": ["No live effect."],
            "options": [
                {
                    "id": "APPROVE",
                    "label": "Approve",
                    "effect": "Exercise the fixture.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "HOLD",
                    "label": "Hold",
                    "effect": "Leave it blocked.",
                    "machine_outcome": "REJECT",
                },
            ],
            "recommendation": "APPROVE",
            "expires_at": None,
        }

    def install_routing_inventory(self, objects: list[dict]) -> str:
        source = self.control.store.current_snapshot(REPOSITORY, "issue", 179)
        if source is None:
            source = self.control.store.ingest_snapshot(
                repository=REPOSITORY,
                object_kind="issue",
                object_number=179,
                payload={
                    "number": 179,
                    "updated_at": "2026-09-03T12:04:00Z",
                },
                source_updated_at="2026-09-03T12:04:00Z",
                fetched_at="2026-09-03T12:04:01Z",
            )
        occurrence_manifest = digest_json([])
        payload = {
            "kind": ROUTING_KIND,
            "repository": REPOSITORY,
            "alias_source_sha256": "1" * 64,
            "endpoint_state_sha256": "2" * 64,
            "issue_179_source_sha256": source.payload_sha256,
            "object_manifest_sha256": digest_json(objects),
            "occurrence_manifest_sha256": occurrence_manifest,
            "object_manifest": objects,
            "object_count": len(objects),
            "issue_count": sum(
                item.get("object_kind") == "issue" for item in objects
            ),
            "pull_request_count": sum(
                item.get("object_kind") == "pull_request" for item in objects
            ),
            "occurrence_count": 0,
            "classification_counts": {name: 0 for name in CLASSIFICATIONS},
            "semantic_tag_counts": {name: 0 for name in TAGS},
        }
        inventory_sha256 = digest_json(payload)
        preview = {
            "repository": REPOSITORY,
            "generation": 1,
            "predecessor_inventory_sha256": None,
            "inventory_sha256": inventory_sha256,
            "alias_source_sha256": payload["alias_source_sha256"],
            "endpoint_state_sha256": payload["endpoint_state_sha256"],
            "issue_179_source_sha256": payload["issue_179_source_sha256"],
            "object_manifest_sha256": payload["object_manifest_sha256"],
            "occurrence_manifest_sha256": occurrence_manifest,
        }
        outbox_payload = {"body": "PRIVATE_ROUTING_RECEIPT_SENTINEL"}
        now = "2026-09-03T12:05:00Z"
        with self.control.store.transaction():
            outbox_id = self.control.connection.execute(
                "INSERT INTO github_outbox(idempotency_key,repository,object_kind,"
                "object_number,operation,expected_source_sha256,payload_sha256,"
                "payload_json,state,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    f"routing-test:{inventory_sha256}", REPOSITORY, "issue", 179,
                    "comment", payload["issue_179_source_sha256"],
                    digest_json(outbox_payload), canonical_json(outbox_payload),
                    "COMPLETE", now, now,
                ),
            ).lastrowid
            self.control.connection.execute(
                "INSERT INTO routing_deprecation_inventories VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    inventory_sha256, REPOSITORY, 1, None, digest_json(preview),
                    ROUTING_KIND, payload["alias_source_sha256"],
                    payload["endpoint_state_sha256"],
                    payload["issue_179_source_sha256"],
                    payload["object_manifest_sha256"], occurrence_manifest,
                    canonical_json(objects), len(objects), payload["issue_count"],
                    payload["pull_request_count"], 0,
                    canonical_json(payload["classification_counts"]),
                    canonical_json(payload["semantic_tag_counts"]),
                    outbox_id, "COMPLETE", now,
                ),
            )
            self.control.connection.execute(
                "INSERT INTO routing_deprecation_current VALUES (?,?,?,?,?)",
                (REPOSITORY, 1, inventory_sha256, 1, now),
            )
            self.control.connection.execute(
                "INSERT INTO routing_deprecation_promotions VALUES (?,?,?,?,?,?,?)",
                (REPOSITORY, 1, None, inventory_sha256, digest_json(preview),
                 "comment:1", now),
            )
        return inventory_sha256

    def test_public_snapshot_contract_is_versioned(self) -> None:
        self.assertEqual(
            "twinfinity-coordination-truth-snapshot/v1", SNAPSHOT_SCHEMA
        )

    def test_database_only_wal_requires_the_exact_explicit_boundary(self) -> None:
        self.prime_wal_reader_mark()
        triplet = snapshot_database(self.database, REPOSITORY)
        namespace = self.close_to_database_only_wal()

        with patch.object(
            snapshot_module, "open_owner_database_readonly"
        ) as default_opener, self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_WAL_SIDECAR_REQUIRED"
        ):
            snapshot_database(self.database, REPOSITORY)
        default_opener.assert_not_called()

        explicit = snapshot_database(
            self.database,
            REPOSITORY,
            read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
        )
        self.assertEqual(triplet, explicit)
        self.assertEqual(triplet["snapshot_sha256"], explicit["snapshot_sha256"])
        self.assertEqual(SNAPSHOT_SCHEMA, explicit["schema"])
        self.assertEqual(
            {
                "schema", "repository", "global_current", "schema_sentinels",
                "families", "read_effect_budget", "snapshot_sha256",
            },
            set(explicit),
        )
        self.assertNotIn(
            SIDECAR_FREE_WAL_READ_BOUNDARY,
            canonical_json(explicit),
        )
        self.assertEqual(
            namespace,
            sorted(entry.name for entry in self.database.parent.iterdir()),
        )

    def test_sidecar_free_boundary_uses_private_pinned_immutable_connection(
        self,
    ) -> None:
        self.close_to_database_only_wal()
        real_connect = snapshot_module.sqlite3.connect
        evidence: dict[str, object] = {"statements": []}

        class TracedConnection:
            def __init__(self, connection, descriptor: int):
                object.__setattr__(self, "connection", connection)
                object.__setattr__(self, "descriptor", descriptor)

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def __setattr__(self, name, value):
                if name in {"connection", "descriptor"}:
                    object.__setattr__(self, name, value)
                else:
                    setattr(self.connection, name, value)

            def execute(self, statement, *args):
                evidence["statements"].append(statement.strip().upper())
                return self.connection.execute(statement, *args)

            def close(self):
                os.fstat(self.descriptor)
                evidence["descriptor_alive_at_sqlite_close"] = True
                return self.connection.close()

        def traced_connect(database_uri, *args, **kwargs):
            prefix = "file:/proc/self/fd/"
            suffix = "?mode=ro&immutable=1&cache=private"
            self.assertTrue(database_uri.startswith(prefix))
            self.assertTrue(database_uri.endswith(suffix))
            descriptor = int(database_uri[len(prefix):-len(suffix)])
            os.fstat(descriptor)
            evidence["descriptor"] = descriptor
            evidence["uri"] = database_uri
            self.assertTrue(kwargs["uri"])
            self.assertIsNone(kwargs["isolation_level"])
            self.assertEqual(5, kwargs["timeout"])
            return TracedConnection(
                real_connect(database_uri, *args, **kwargs), descriptor
            )

        before = snapshot_module._filesystem_state(self.database)
        with patch.object(
            snapshot_module.sqlite3, "connect", side_effect=traced_connect
        ):
            result = snapshot_database(
                self.database,
                REPOSITORY,
                read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
            )
        after = snapshot_module._filesystem_state(self.database)

        self.assertEqual(SNAPSHOT_SCHEMA, result["schema"])
        self.assertTrue(evidence["descriptor_alive_at_sqlite_close"])
        descriptor = evidence["descriptor"]
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertEqual(
            ["BEGIN", "ROLLBACK"],
            [
                statement for statement in evidence["statements"]
                if statement in {"BEGIN", "ROLLBACK", "COMMIT"}
            ],
        )
        self.assertIn("PRAGMA QUERY_ONLY=ON", evidence["statements"])
        snapshot_module._validate_filesystem_effect(
            before, after, "WAL_SIDECAR_FREE_IMMUTABLE"
        )

    def test_sidecar_free_boundary_rejects_controlled_writer_before_open(
        self,
    ) -> None:
        self.close_to_database_only_wal()
        hook_calls: list[bool] = []

        with patch.object(
            snapshot_module, "_open_pinned_immutable_database_readonly"
        ) as opener, self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_READ_BOUNDARY_WRITER_FORBIDDEN"
        ):
            snapshot_database(
                self.database,
                REPOSITORY,
                read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
                after_begin=lambda: hook_calls.append(True),
            )
        opener.assert_not_called()
        self.assertEqual([], hook_calls)

    def test_sidecar_free_boundary_rejects_other_routes_and_values(self) -> None:
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_READ_BOUNDARY_INVALID"
        ):
            snapshot_database(
                self.database,
                REPOSITORY,
                read_boundary="immutable",
            )

        with patch.object(
            snapshot_module, "_open_pinned_immutable_database_readonly"
        ) as opener, self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_READ_BOUNDARY_MISMATCH"
        ):
            snapshot_database(
                self.database,
                REPOSITORY,
                read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
            )
        opener.assert_not_called()

        self.close_to_database_only_wal()
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(sidecar=suffix):
                sidecar = Path(str(self.database) + suffix)
                sidecar.write_bytes(b"")
                sidecar.chmod(0o600)
                with self.assertRaisesRegex(
                    SnapshotHold, "COORDINATION_TRUTH_READ_BOUNDARY_MISMATCH"
                ):
                    snapshot_database(
                        self.database,
                        REPOSITORY,
                        read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
                    )
                sidecar.unlink()

        connection = sqlite3.connect(self.database, isolation_level=None)
        self.assertEqual(
            "delete", connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        )
        connection.close()
        self.database.chmod(0o600)
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_READ_BOUNDARY_MISMATCH"
        ):
            snapshot_database(
                self.database,
                REPOSITORY,
                read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
            )

    def test_pinned_database_identity_matrix_is_exact_except_atime(self) -> None:
        self.close_to_database_only_wal()
        descriptor = snapshot_module._open_file_noatime(self.database)
        try:
            expected = snapshot_module._descriptor_file_identity(descriptor)
        finally:
            os.close(descriptor)

        for field in (
            "device", "inode", "mode", "uid", "gid", "links", "size",
            "mtime_ns", "ctime_ns", "sha256",
        ):
            with self.subTest(field=field):
                observed = dict(expected)
                if field == "sha256":
                    observed[field] = "0" * 64
                else:
                    observed[field] += 1
                with self.assertRaisesRegex(
                    SnapshotHold, "COORDINATION_TRUTH_FILESYSTEM_DRIFT"
                ):
                    snapshot_module._validate_pinned_database_identity(
                        expected, observed
                    )

        atime_only = dict(expected)
        atime_only["atime_ns"] += 1
        snapshot_module._validate_pinned_database_identity(expected, atime_only)

    def test_sidecar_free_boundary_rejects_pinned_descriptor_substitution(
        self,
    ) -> None:
        self.close_to_database_only_wal()
        expected = snapshot_module._file_identity(self.database)
        substitute = self.database.parent / "substitute.sqlite3"
        substitute.write_bytes(self.database.read_bytes())
        substitute.chmod(0o600)

        def open_substitute(_path):
            return os.open(substitute, os.O_RDONLY)

        with (
            patch.object(
                snapshot_module,
                "_open_file_noatime",
                side_effect=open_substitute,
            ),
            patch.object(snapshot_module.sqlite3, "connect") as sqlite_open,
            self.assertRaisesRegex(
                    SnapshotHold, "COORDINATION_TRUTH_FILESYSTEM_DRIFT"
            ),
        ):
            snapshot_module._open_pinned_immutable_database_readonly(
                self.database, expected
            )
        sqlite_open.assert_not_called()

    def test_sidecar_free_boundary_requires_sqlite_retained_file_identity(
        self,
    ) -> None:
        self.close_to_database_only_wal()
        expected = snapshot_module._file_identity(self.database)
        before = snapshot_module._filesystem_state(self.database)

        with patch.object(
            snapshot_module,
            "_regular_file_descriptor_identities",
            return_value={},
        ), self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_PINNED_SQLITE_IDENTITY_INVALID"
        ):
            snapshot_module._open_pinned_immutable_database_readonly(
                self.database, expected
            )

        after = snapshot_module._filesystem_state(self.database)
        snapshot_module._validate_filesystem_effect(
            before, after, "WAL_SIDECAR_FREE_IMMUTABLE"
        )

    def test_sidecar_free_terminal_path_replacement_discards_snapshot(
        self,
    ) -> None:
        self.close_to_database_only_wal()
        original_bytes = self.database.read_bytes()
        real_assemble = snapshot_module._assemble

        def replace_path(connection, repository):
            result = real_assemble(connection, repository)
            self.database.rename(self.database.parent / "retired.sqlite3")
            self.database.write_bytes(original_bytes)
            self.database.chmod(0o600)
            return result

        with patch.object(
            snapshot_module, "_assemble", side_effect=replace_path
        ), self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_FILESYSTEM_NAMESPACE_EFFECT"
        ):
            snapshot_database(
                self.database,
                REPOSITORY,
                read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
            )

    def test_sidecar_free_terminal_sidecar_appearance_discards_snapshot(
        self,
    ) -> None:
        self.close_to_database_only_wal()
        real_assemble = snapshot_module._assemble

        def add_sidecar(connection, repository):
            result = real_assemble(connection, repository)
            sidecar = Path(str(self.database) + "-wal")
            sidecar.write_bytes(b"injected")
            sidecar.chmod(0o600)
            return result

        with patch.object(
            snapshot_module, "_assemble", side_effect=add_sidecar
        ), self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_FILESYSTEM_NAMESPACE_EFFECT"
        ):
            snapshot_database(
                self.database,
                REPOSITORY,
                read_boundary=SIDECAR_FREE_WAL_READ_BOUNDARY,
            )

    def test_cli_accepts_only_the_explicit_sidecar_free_boundary(self) -> None:
        self.close_to_database_only_wal()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                0,
                snapshot_module.main(
                    [
                        "--repository", REPOSITORY,
                        "--database", str(self.database),
                        "--read-boundary", SIDECAR_FREE_WAL_READ_BOUNDARY,
                    ]
                ),
            )
        result = json.loads(output.getvalue())
        self.assertEqual(SNAPSHOT_SCHEMA, result["schema"])
        self.assertNotIn(
            SIDECAR_FREE_WAL_READ_BOUNDARY,
            canonical_json(result),
        )

    def test_complete_snapshot_is_deterministic_and_privacy_safe(self) -> None:
        sentinel = "PRIVATE_TOKEN_SENTINEL"
        source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=338,
            payload={
                "number": 338,
                "title": sentinel,
                "updated_at": "2026-09-03T12:00:01Z",
            },
            source_updated_at="2026-09-03T12:00:01Z",
            fetched_at="2026-09-03T12:00:02Z",
        )
        self.prime_wal_reader_mark()
        first = snapshot_database(self.database, REPOSITORY)
        second = snapshot_database(self.database, REPOSITORY)

        self.assertEqual(first, second)
        self.assertEqual(
            {
                "schema", "repository", "global_current", "schema_sentinels",
                "families", "read_effect_budget", "snapshot_sha256",
            },
            set(first),
        )
        self.assertEqual(
            {
                "capacity", "sources_graph", "items_allocations_leases",
                "messages_admissions", "attempts_watches", "readiness",
                "pull_buffer", "approvals", "outbox", "hosted_operations",
                "delivery_control", "routing_truth",
            },
            set(first["families"]),
        )
        self.assertEqual(
            {
                "database_opens": 1,
                "read_transactions": 1,
                "rollbacks": 1,
                "sql_writes": 0,
                "filesystem_namespace_writes": 0,
                "rollback_journal_metadata_changes": 0,
                "read_atime_changes_only": True,
                "wal_existing_shm_lock_bytes_and_timestamps_only": True,
            },
            first["read_effect_budget"],
        )
        encoded = json.dumps(first, sort_keys=True)
        self.assertNotIn(sentinel, encoded)
        self.assertIn(source.payload_sha256, encoded)

    def test_v1_authority_is_quarantined_and_fresh_v2_reissue_is_private(self) -> None:
        self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=338,
            payload={"number": 338, "updated_at": "2026-09-03T12:00:01Z"},
            source_updated_at="2026-09-03T12:00:01Z",
            fetched_at="2026-09-03T12:00:02Z",
        )
        legacy = submit_proposal(
            self.control.store,
            self.approval_packet("twinfinity.approval-proposal.v1"),
            "2026-09-03T12:00:03Z",
        )
        legacy_before = tuple(
            self.control.connection.execute(
                "SELECT * FROM approval_proposals WHERE proposal_sha256=?",
                (legacy["proposal_sha256"],),
            ).fetchone()
        )
        activate_semantic_contract_v2(
            self.control.connection,
            authority_sha256="8" * 64,
            now="2026-09-03T12:00:04Z",
        )
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_LEGACY_V1_AUTHORITY_QUARANTINED"
        ):
            snapshot_database(self.database, REPOSITORY)
        fresh = submit_proposal(
            self.control.store,
            self.approval_packet("twinfinity.approval-proposal.v2"),
            "2026-09-03T12:00:05Z",
        )
        result = snapshot_database(self.database, REPOSITORY)
        encoded = canonical_json(result)
        self.assertIn(fresh["proposal_sha256"], encoded)
        self.assertNotIn("PRIVATE_APPROVAL_EVIDENCE_SENTINEL", encoded)
        self.assertEqual(
            legacy_before,
            tuple(
                self.control.connection.execute(
                    "SELECT * FROM approval_proposals WHERE proposal_sha256=?",
                    (legacy["proposal_sha256"],),
                ).fetchone()
            ),
        )

    def test_routing_record_exact_shape_is_emitted(self) -> None:
        exact = {
            "object_kind": "issue",
            "object_number": 190,
            "node_id": "I_kwDOUDeaEM8AAAABPmRqEA",
            "body_sha256": "a" * 64,
        }
        inventory = self.install_routing_inventory([exact])
        self.prime_wal_reader_mark()
        result = snapshot_database(self.database, REPOSITORY)
        records = result["families"]["routing_truth"]["tables"][
            "routing_deprecation_inventories"
        ]
        self.assertEqual(inventory, records[0]["inventory_sha256"])
        self.assertEqual([exact], records[0]["objects"])
        self.assertNotIn("PRIVATE_ROUTING_RECEIPT_SENTINEL", canonical_json(result))

    def test_routing_extra_field_fails_with_recomputed_outer_digests(self) -> None:
        malformed = {
            "object_kind": "issue",
            "object_number": 190,
            "node_id": "I_kwDOUDeaEM8AAAABPmRqEA",
            "body_sha256": "a" * 64,
            "extra": "attacker-controlled",
        }
        self.install_routing_inventory([malformed])
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_ROUTING_INVALID"
        ):
            snapshot_database(self.database, REPOSITORY)

    def test_schema_inventory_rejects_missing_extra_column_and_default_drift(self) -> None:
        self.control.connection.execute(
            "ALTER TABLE approval_semantic_contract_current "
            "ADD COLUMN unreviewed_default INTEGER NOT NULL DEFAULT 7"
        )
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(SnapshotHold, "COORDINATION_TRUTH_SCHEMA_DRIFT"):
            snapshot_database(self.database, REPOSITORY)

        incomplete_dir = Path(self.temp.name) / "incomplete"
        incomplete_dir.mkdir(mode=0o700)
        incomplete = incomplete_dir / "state.sqlite3"
        connection = sqlite3.connect(incomplete)
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.close()
        incomplete.chmod(0o600)
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_SCHEMA_INCOMPLETE"
        ):
            snapshot_database(incomplete, REPOSITORY)

    def test_missing_capacity_and_endpoint_current_fail_closed(self) -> None:
        with self.control.store.transaction():
            self.control.connection.execute(
                "DELETE FROM coordination_capacity_current WHERE repository=?",
                (REPOSITORY,),
            )
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_CAPACITY_CURRENT_REQUIRED"
        ):
            snapshot_database(self.database, REPOSITORY)

    def test_endpoint_current_requires_exact_three_role_bindings(self) -> None:
        with self.control.store.transaction():
            self.control.connection.execute(
                "DROP TRIGGER executor_current_endpoint_monotonic_delete"
            )
            self.control.connection.execute(
                "DELETE FROM executor_role_endpoint_current WHERE role='sre'"
            )
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_REGISTRY_INVALID"
        ):
            snapshot_database(self.database, REPOSITORY)

    def test_wal_writer_commit_after_snapshot_acquisition_cannot_tear_read(self) -> None:
        old = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=339,
            payload={"number": 339, "updated_at": "2026-09-03T12:01:00Z"},
            source_updated_at="2026-09-03T12:01:00Z",
            fetched_at="2026-09-03T12:01:01Z",
        )
        successor: dict[str, object] = {}

        def commit_successor() -> None:
            successor["source"] = self.control.store.ingest_snapshot(
                repository=REPOSITORY,
                object_kind="issue",
                object_number=339,
                payload={
                    "number": 339,
                    "updated_at": "2026-09-03T12:02:00Z",
                },
                source_updated_at="2026-09-03T12:02:00Z",
                fetched_at="2026-09-03T12:02:01Z",
            )

        self.prime_wal_reader_mark()
        first = snapshot_database(
            self.database, REPOSITORY, after_begin=commit_successor
        )
        second = snapshot_database(self.database, REPOSITORY)
        successor_source = successor["source"]
        first_bytes = json.dumps(first, sort_keys=True)
        second_bytes = json.dumps(second, sort_keys=True)
        self.assertIn(old.payload_sha256, first_bytes)
        self.assertNotIn(successor_source.payload_sha256, first_bytes)
        self.assertNotIn(old.payload_sha256, second_bytes)
        self.assertIn(successor_source.payload_sha256, second_bytes)

    def test_success_and_failure_have_exact_begin_rollback_without_commit(self) -> None:
        real_open = snapshot_module.open_owner_database_readonly

        class TracedConnection:
            def __init__(self, connection, trace):
                self.connection = connection
                self.trace = trace

            def execute(self, statement, *args):
                self.trace.append(statement.strip().upper())
                return self.connection.execute(statement, *args)

            def __getattr__(self, name):
                return getattr(self.connection, name)

        self.prime_wal_reader_mark()
        success_trace: list[str] = []
        with patch.object(
            snapshot_module,
            "open_owner_database_readonly",
            side_effect=lambda path: TracedConnection(
                real_open(path), success_trace
            ),
        ):
            snapshot_database(self.database, REPOSITORY)
        self.assertEqual(
            ["BEGIN", "ROLLBACK"],
            [
                statement for statement in success_trace
                if statement in {"BEGIN", "ROLLBACK", "COMMIT"}
            ],
        )

        failure_trace: list[str] = []
        with patch.object(
            snapshot_module,
            "open_owner_database_readonly",
            side_effect=lambda path: TracedConnection(
                real_open(path), failure_trace
            ),
        ), patch.object(
            snapshot_module,
            "_assemble",
            side_effect=SnapshotHold("COORDINATION_TRUTH_INJECTED"),
        ):
            with self.assertRaisesRegex(
                SnapshotHold, "COORDINATION_TRUTH_INJECTED"
            ):
                snapshot_database(self.database, REPOSITORY)
        self.assertEqual(
            ["BEGIN", "ROLLBACK"],
            [
                statement for statement in failure_trace
                if statement in {"BEGIN", "ROLLBACK", "COMMIT"}
            ],
        )

    def test_quiescent_rollback_journal_snapshot_has_only_read_atime_effect(self) -> None:
        self.control.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.control.close()
        self.control = None
        connection = sqlite3.connect(self.database, isolation_level=None)
        self.assertEqual(
            "delete", connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        )
        connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        connection.close()
        before = snapshot_module._filesystem_state(self.database)
        snapshot_database(self.database, REPOSITORY)
        after = snapshot_module._filesystem_state(self.database)
        snapshot_module._validate_filesystem_effect(before, after, "ROLLBACK")
        self.assertEqual(
            before["files"]["database"]["sha256"],
            after["files"]["database"]["sha256"],
        )

    def test_synthetic_wal_reader_effects_accept_only_atime_and_bounded_shm(self) -> None:
        before = self.synthetic_wal_filesystem_state()
        for name in before["files"]:
            with self.subTest(effect="atime", name=name):
                after = json.loads(json.dumps(before))
                after["files"][name]["atime_ns"] += 1
                snapshot_module._validate_filesystem_effect(before, after, "WAL")

        after = json.loads(json.dumps(before))
        after["files"]["-shm"].update(
            {
                "mtime_ns": 101,
                "ctime_ns": 102,
                "sha256": "d" * 64,
            }
        )
        snapshot_module._validate_filesystem_effect(before, after, "WAL")

        for field in (
            "device", "inode", "mode", "uid", "gid", "links", "size"
        ):
            with self.subTest(effect="shm-invariant", field=field):
                after = json.loads(json.dumps(before))
                after["files"]["-shm"][field] += 1
                with self.assertRaisesRegex(
                    SnapshotHold, "COORDINATION_TRUTH_FILESYSTEM_EFFECT"
                ):
                    snapshot_module._validate_filesystem_effect(
                        before, after, "WAL"
                    )

    def test_synthetic_wal_mutations_and_namespace_effects_fail_closed(self) -> None:
        before = self.synthetic_wal_filesystem_state()
        for field in (
            "device", "inode", "mode", "uid", "gid", "links", "size",
            "mtime_ns", "ctime_ns", "sha256",
        ):
            with self.subTest(effect="wal", field=field):
                after = json.loads(json.dumps(before))
                if field == "sha256":
                    after["files"]["-wal"][field] = "e" * 64
                else:
                    after["files"]["-wal"][field] += 1
                with self.assertRaisesRegex(
                    SnapshotHold, "COORDINATION_TRUTH_FILESYSTEM_EFFECT"
                ):
                    snapshot_module._validate_filesystem_effect(
                        before, after, "WAL"
                    )

        structural_mutations = {
            "namespace": lambda after: after["namespace"].append("unexpected"),
            "parent": lambda after: after["parent"].update({"mode": 0o755}),
            "parent-chain": lambda after: after["parent_chain"][0].update(
                {"mode": 0o755}
            ),
        }
        for effect, mutate in structural_mutations.items():
            with self.subTest(effect=effect):
                after = json.loads(json.dumps(before))
                mutate(after)
                with self.assertRaisesRegex(
                    SnapshotHold,
                    "COORDINATION_TRUTH_FILESYSTEM_NAMESPACE_EFFECT",
                ):
                    snapshot_module._validate_filesystem_effect(
                        before, after, "WAL"
                    )

    def test_routing_object_consumer_oracle_is_exact_and_non_boolean(self) -> None:
        valid = {
            "object_kind": "issue",
            "object_number": 190,
            "node_id": "I_kwDOUDeaEM8AAAABPmRqEA",
            "body_sha256": "a" * 64,
        }
        self.assertEqual(
            [valid], snapshot_module._validated_routing_objects([valid])
        )
        invalid = []
        for key in valid:
            candidate = dict(valid)
            candidate.pop(key)
            invalid.append(candidate)
        invalid.extend(
            [
                {**valid, "extra": "field"},
                {**valid, "object_kind": "discussion"},
                {**valid, "object_number": True},
                {**valid, "object_number": 0},
                {**valid, "node_id": ""},
                {**valid, "body_sha256": "A" * 64},
            ]
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                SnapshotHold, "COORDINATION_TRUTH_ROUTING_INVALID"
            ):
                snapshot_module._validated_routing_objects([candidate])
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_ROUTING_INVALID"
        ):
            snapshot_module._validated_routing_objects([valid, dict(valid)])

    def test_routing_consumer_oracle_is_resource_bounded(self) -> None:
        valid = {
            "object_kind": "issue",
            "object_number": 190,
            "node_id": "I_kwDOUDeaEM8AAAABPmRqEA",
            "body_sha256": "a" * 64,
        }
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_ROUTING_INVALID"
        ):
            snapshot_module._validated_routing_objects(
                [valid] * (snapshot_module.MAX_ROUTING_OBJECTS + 1)
            )
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_ROUTING_INVALID"
        ):
            snapshot_module._validated_routing_objects(
                [{**valid, "node_id": "n" * 256}]
            )

    def test_every_declared_delivery_table_is_emitted(self) -> None:
        self.prime_wal_reader_mark()
        result = snapshot_database(self.database, REPOSITORY)
        self.assertEqual(
            set(snapshot_module.FAMILY_TABLES["delivery_control"]),
            set(result["families"]["delivery_control"]["tables"]),
        )

    def test_closeout_commit_query_keeps_closeout_key_filter(self) -> None:
        real_table_rows = snapshot_module._table_rows
        real_select = snapshot_module._select
        commit_queries: list[tuple[str, tuple[object, ...]]] = []

        def table_rows(connection, table, repository, **kwargs):
            if table == "coordination_terminal_closeout_packets":
                return [{"closeout_key": "packet-1", "outbox_id": 1}]
            return real_table_rows(connection, table, repository, **kwargs)

        def select(connection, table, columns, **kwargs):
            if table == "coordination_terminal_closeout_commits":
                commit_queries.append(
                    (kwargs.get("where", ""), tuple(kwargs.get("parameters", ())))
                )
            return real_select(connection, table, columns, **kwargs)

        with patch.object(
            snapshot_module, "_table_rows", side_effect=table_rows
        ), patch.object(snapshot_module, "_select", side_effect=select):
            snapshot_module._delivery_family(
                self.control.connection,
                REPOSITORY,
                outboxes={},
                message_ids=set(),
            )
        self.assertEqual(
            [
                ('"closeout_key" IN (?)', ("packet-1",)),
                ('"closeout_key" IN (?)', ("packet-1",)),
            ],
            commit_queries,
        )

    def test_outbox_payload_and_source_bindings_fail_closed(self) -> None:
        source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=340,
            payload={"number": 340, "updated_at": "2026-09-03T12:10:00Z"},
            source_updated_at="2026-09-03T12:10:00Z",
            fetched_at="2026-09-03T12:10:01Z",
        )
        outbox_id = self.control.store.enqueue_comment(
            idempotency_key="snapshot-outbox-integrity",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=340,
            expected_source_sha256=source.payload_sha256,
            body="Synthetic receipt",
            now="2026-09-03T12:10:02Z",
        )
        self.control.connection.execute(
            "UPDATE github_outbox SET payload_json=? WHERE id=?",
            (canonical_json({"body": "Substituted receipt"}), outbox_id),
        )
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_OUTBOX_DIGEST_INVALID"
        ):
            snapshot_database(self.database, REPOSITORY)

    def test_hosted_scope_digest_substitution_fails_closed(self) -> None:
        source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=341,
            payload={"number": 341, "updated_at": "2026-09-03T12:11:00Z"},
            source_updated_at="2026-09-03T12:11:00Z",
            fetched_at="2026-09-03T12:11:01Z",
        )
        endpoint = self.control.connection.execute(
            "SELECT endpoint_id FROM executor_role_endpoint_current WHERE role='sre'"
        ).fetchone()[0]
        now = "2026-09-03T12:11:02Z"
        self.control.connection.execute(
            "INSERT INTO hosted_operations("
            "idempotency_key,repository,object_kind,issue_number,"
            "source_payload_sha256,provider,target_kind,target_key,operation_kind,"
            "authority_comment_id,authority_body_sha256,scope_sha256,scope_json,"
            "recipient_session_id,sre_units,state,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "snapshot-hosted-integrity", REPOSITORY, "issue", 341,
                source.payload_sha256, "github", "repository", "synthetic",
                "READ_METADATA", 1, "a" * 64, "b" * 64,
                canonical_json({"kind": "synthetic"}), endpoint, 0,
                "PREPARED", now, now,
            ),
        )
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_HOSTED_SCOPE_INVALID"
        ):
            snapshot_database(self.database, REPOSITORY)

    def test_pre_push_gate_rejects_cross_repository_message_parent(self) -> None:
        source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=342,
            payload={"number": 342, "updated_at": "2026-09-03T12:13:00Z"},
            source_updated_at="2026-09-03T12:13:00Z",
            fetched_at="2026-09-03T12:13:01Z",
        )
        foreign_payload = {
            "source": {
                "repository": "jayendusharma/twinfinity-harness",
                "object_kind": "issue",
                "object_number": 190,
                "payload_sha256": "a" * 64,
            }
        }
        foreign_sha256 = digest_json(foreign_payload)
        now = "2026-09-03T12:13:02Z"
        message_id = self.control.connection.execute(
            "INSERT INTO coordination_messages("
            "idempotency_key,recipient_session_id,topic,payload_sha256,"
            "payload_json,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "foreign-pre-push-parent", "role.development.v6",
                "development.admission", foreign_sha256,
                canonical_json(foreign_payload), "COMPLETE", now, now,
            ),
        ).lastrowid
        self.control.connection.execute(
            "INSERT INTO coordination_pre_push_gates("
            "repository,issue_number,generation,accountable_session_id,"
            "source_payload_sha256,lease_manifest_sha256,admission_message_id,"
            "admission_payload_sha256,branch,worktree_path,base_sha,head_sha,"
            "changed_paths_sha256,changed_path_count,lower_gate,"
            "lower_gate_exit_code,compose_gate,compose_gate_exit_code,"
            "compose_run_id,head_unchanged,cleanup_proven,state,evidence_sha256,"
            "environment_provenance_sha256,started_at,completed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                REPOSITORY, 342, 1, "role.development.v6",
                source.payload_sha256, "b" * 64, message_id, foreign_sha256,
                "codex/342-synthetic", "/tmp/synthetic", "c" * 40,
                "d" * 40, "e" * 64, 1, "synthetic-lower", 0,
                "synthetic-compose", 0, "synthetic-run", 1, 1, "PASS",
                "f" * 64, "1" * 64, now, now,
            ),
        )
        self.prime_wal_reader_mark()
        with self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_PRE_PUSH_MESSAGE_INVALID"
        ):
            snapshot_database(self.database, REPOSITORY)

    def test_unrelated_repository_foreign_key_corruption_is_out_of_scope(self) -> None:
        self.control.connection.execute("PRAGMA foreign_keys=OFF")
        self.assertEqual(
            0, self.control.connection.execute("PRAGMA foreign_keys").fetchone()[0]
        )
        self.control.connection.execute(
            "INSERT INTO coordination_wakes("
            "wake_key,message_id,recipient_session_id,message_payload_sha256,"
            "state,attempts,last_attempt_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "foreign-repository-orphan", 999999, "role.planner.v3",
                "a" * 64, "COMPLETE", 1, "2026-09-03T12:12:00Z",
                "2026-09-03T12:12:00Z",
            ),
        )
        self.prime_wal_reader_mark()
        result = snapshot_database(self.database, REPOSITORY)
        self.assertEqual(REPOSITORY, result["repository"])

    def test_post_effect_inspection_error_is_typed(self) -> None:
        self.prime_wal_reader_mark()
        before = snapshot_module._filesystem_state(self.database)
        with patch.object(
            snapshot_module,
            "_filesystem_state",
            side_effect=[before, OSError("PRIVATE_PATH_SENTINEL")],
        ), self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_POST_EFFECT_INVALID"
        ) as raised:
            snapshot_database(self.database, REPOSITORY)
        self.assertNotIn("PRIVATE_PATH_SENTINEL", str(raised.exception))

    def test_symlink_sidecar_fails_before_sqlite_open(self) -> None:
        self.control.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.control.close()
        self.control = None
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        connection.close()
        Path(str(self.database) + "-journal").symlink_to(self.database.name)
        with patch.object(
            snapshot_module,
            "open_owner_database_readonly",
        ) as opener, self.assertRaisesRegex(
            SnapshotHold, "COORDINATION_TRUTH_FILESYSTEM_UNSAFE"
        ):
            snapshot_database(self.database, REPOSITORY)
        opener.assert_not_called()

    def test_cli_hold_is_value_free_and_has_no_traceback(self) -> None:
        output = io.StringIO()
        with patch.object(
            snapshot_module,
            "snapshot_database",
            side_effect=SnapshotHold("COORDINATION_TRUTH_SCHEMA_DRIFT"),
        ), redirect_stdout(output):
            self.assertEqual(
                1,
                snapshot_module.main(
                    ["--repository", REPOSITORY, "--database", str(self.database)]
                ),
            )
        self.assertEqual(
            {
                "schema": "twinfinity-coordination-truth-snapshot-hold/v1",
                "state": "HOLD",
                "error": "COORDINATION_TRUTH_SCHEMA_DRIFT",
            },
            json.loads(output.getvalue()),
        )
        self.assertNotIn(str(self.database), output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main()
