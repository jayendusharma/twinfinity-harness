from __future__ import annotations

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
)
from coordination_transfer import activate_transfer  # noqa: E402
from coordination_transfer_ledger import (  # noqa: E402
    create_schema,
    intent_sha256,
    load_record,
    record_existing,
    record_sha256,
)
from canonical_ready_fixture import finalize_canonical_ready_candidate  # noqa: E402
from delivery_guard import (  # noqa: E402
    GuardError,
    _message_context,
    _terminal_watch_context,
)
from delivery_identity import bind_delivery_identity  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
SRE_SESSION = "role.sre.v4"


class CoordinationTransferTests(unittest.TestCase):
    LEGACY_LEDGER_SCHEMA = """
        CREATE TABLE coordination_transfer_ledger (
            transfer_key TEXT PRIMARY KEY,
            repository TEXT NOT NULL,
            predecessor_issue_number INTEGER NOT NULL,
            successor_issue_number INTEGER NOT NULL,
            record_sha256 TEXT NOT NULL UNIQUE,
            record_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.root = root
        self.store = CoordinationStore(root / "state.sqlite3")
        apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="coordination-transfer-tests",
        )
        self.database = root / "state.sqlite3"
        self.sources = {}
        for issue in (314, 320):
            self.sources[issue] = self.store.ingest_snapshot(
                repository=REPOSITORY,
                object_kind="issue",
                object_number=issue,
                payload={"number": issue, "updated_at": "2026-08-23T17:00:00Z"},
                source_updated_at="2026-08-23T17:00:00Z",
                fetched_at="2026-08-23T17:00:01Z",
            )
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=314,
            status="ACTIVE_FENCED",
            allocation_class="ACTIVE",
            generation=8,
            accountable_session_id=SRE_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=0,
            shared_units=0,
            sre_units=1,
            expected_source_sha256=self.sources[314].payload_sha256,
            expected_version=0,
            now="2026-08-23T17:00:02Z",
        )
        parent_admission = {
            "item": {
                "repository": REPOSITORY,
                "issue_number": 314,
                "generation": 8,
                "expected_version": 0,
            },
            "message": {
                "idempotency_key": "issue314-generation8-parent-admission",
                "recipient_session_id": SRE_SESSION,
                "topic": "sre.admission",
                "payload": {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 314,
                    "payload_sha256": self.sources[314].payload_sha256,
                },
                "issue_number": 314,
                "generation": 8,
                "item_version": 1,
                "base_sha": "a" * 40,
                "branch": "codex/314-ci-hardening",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-314",
                "opaque_worktree_id": "twinfinityapp-issue-314",
                "accountable_session_id": SRE_SESSION,
                "lease_manifest_sha256": "1" * 64,
                "authority_sha256": "4" * 64,
                "capacity": {"development_units": 0, "shared_units": 0, "sre_units": 1},
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
            },
        }
        bind_delivery_identity(parent_admission)
        self.parent_message = self.store.enqueue_message(
            **parent_admission["message"],
            now="2026-08-23T17:00:03Z",
        )
        parent = self.store.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (self.parent_message,),
        ).fetchone()
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches "
            "SET admission_message_id=?,admission_payload_sha256=? "
            "WHERE watch_key=?",
            (
                self.parent_message,
                parent["payload_sha256"],
                f"terminal:{REPOSITORY}:issue:314:generation:8",
            ),
        )
        self.store.claim_message(
            self.parent_message, SRE_SESSION, "2026-08-23T17:00:04Z"
        )
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE',updated_at=? "
            "WHERE id=? AND state='CLAIMED' AND claimed_by=?",
            ("2026-08-23T17:00:05Z", self.parent_message, SRE_SESSION),
        )
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=314,
            status="HOLD",
            allocation_class="RETAINED",
            generation=8,
            accountable_session_id=SRE_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=0,
            shared_units=0,
            sre_units=1,
            expected_source_sha256=self.sources[314].payload_sha256,
            expected_version=1,
            now="2026-08-23T17:00:06Z",
        )
        authority = "3" * 64
        self.comment_bodies = {
            1001: f"parent transfer accepted {authority}",
            1002: f"successor transfer accepted {authority}",
        }
        self.comment_patch = patch(
            "coordination_transfer_ledger.fetch_comment",
            side_effect=lambda repository, comment_id: {
                "id": comment_id,
                "issue_url": (
                    f"https://api.github.com/repos/{repository}/issues/"
                    f"{314 if comment_id == 1001 else 320}"
                ),
                "body": self.comment_bodies[comment_id],
            },
        )
        self.comment_patch.start()

        successor = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=320,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=SRE_SESSION,
            lease_manifest_sha256=None,
            development_units=0,
            shared_units=0,
            sre_units=1,
            expected_source_sha256=self.sources[320].payload_sha256,
            expected_version=0,
            now="2026-08-23T17:00:07Z",
        )
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": "a" * 40,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Transfer", "rank": 1}],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": "issue:320",
                        "issue_number": 320,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Canonical transfer successor",
                        "lane_key": "transfer-successor",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": 1,
                        "estimate_units": 1,
                        "development_units": 0,
                        "shared_units": 0,
                        "sre_units": 1,
                        "source_payload_sha256": self.sources[320].payload_sha256,
                        "ready_at": "2026-08-23T17:00:07Z",
                    }
                ],
                "relations": [],
            },
            now="2026-08-23T17:00:07Z",
        )
        lease_dir = self.root / "leases"
        lease_dir.mkdir()
        lease_path = lease_dir / "issue-320-transfer-lease.json"
        lease_payload = {
            "repository": REPOSITORY,
            "issue_number": 320,
            "generation": 1,
            "base_sha": "a" * 40,
            "branch": "codex/314-ci-hardening",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-314",
            "no_additional_paths": True,
            "paths": [
                {
                    "path": "backend/example.py",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "5" * 40,
                }
            ],
        }
        lease_path.write_text(
            json.dumps(lease_payload, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.successor_lease_sha = hashlib.sha256(lease_path.read_bytes()).hexdigest()
        self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": 320,
                    "generation": 1,
                    "path": str(lease_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-23T17:00:07Z",
        )
        policy = self.store.capacity_policy(
            REPOSITORY, now="2026-08-23T17:00:07Z"
        )
        canonical_transaction = self._build_transaction()
        finalized = finalize_canonical_ready_candidate(
            self.store,
            database=self.database,
            artifact_root=self.root,
            prepared_packet={
                "schema": "twinfinity-kanban-pull-buffer/v2",
                "repository": REPOSITORY,
                "issue_number": 320,
                "generation": 1,
                "item_version_at_preparation": int(successor["version"]),
                "source_payload_sha256": self.sources[320].payload_sha256,
                "accepted_main_at_preparation": "a" * 40,
                "portfolio_graph_version": 1,
                "state": "PREPARED_NOT_READY",
                "verticality": "END_TO_END",
                "owner_visible_outcome": "Continue the canonical SRE transfer.",
                "capacity_policy": {
                    "version": int(policy["version"]),
                    "development_limit": int(policy["development_limit"]),
                    "shared_limit": int(policy["shared_limit"]),
                    "sre_limit": int(policy["sre_limit"]),
                },
                "capacity_on_activation": {
                    "development_units": 0,
                    "shared_units": 0,
                    "sre_units": 1,
                },
                "precomputed_collision_matrix": [
                    {
                        "other_issue": 314,
                        "disposition": "DISJOINT",
                        "reason": "The predecessor is released atomically.",
                    }
                ],
                "preparation_complete": ["The transfer admission is complete."],
                "promotion_checks_after_predecessor": [
                    "Revalidate predecessor provenance and comments."
                ],
                "hard_stops": ["Stop on any identity or transfer drift."],
                "promotion_trigger": "The canonical transfer readiness gates pass.",
            },
            admission_transaction=canonical_transaction["activation"],
            worker_role="sre",
            worker_endpoint_id=SRE_SESSION,
            now="2026-08-23T17:00:08Z",
            suffix="coordination-transfer",
        )
        self.assertEqual(
            ("READY", "NONE", 2),
            (
                finalized["item"]["status"],
                finalized["item"]["allocation_class"],
                finalized["item"]["version"],
            ),
        )
        self.ready_transaction = copy.deepcopy(canonical_transaction)

    def tearDown(self) -> None:
        self.comment_patch.stop()
        self.store.close()
        self.temp.cleanup()

    def _build_transaction(self, *, payload_version: int = 3):
        release = {
            "repository": REPOSITORY,
            "issue_number": 314,
            "status": "MONITOR",
            "allocation_class": "NONE",
            "generation": 9,
            "accountable_session_id": None,
            "lease_manifest_sha256": None,
            "development_units": 0,
            "shared_units": 0,
            "sre_units": 0,
            "expected_source_sha256": self.sources[314].payload_sha256,
            "expected_version": 2,
        }
        item = {
            "repository": REPOSITORY,
            "issue_number": 320,
            "status": "ACTIVE_FENCED",
            "allocation_class": "ACTIVE",
            "generation": 1,
            "accountable_session_id": SRE_SESSION,
            "lease_manifest_sha256": self.successor_lease_sha,
            "development_units": 0,
            "shared_units": 0,
            "sre_units": 1,
            "expected_source_sha256": self.sources[320].payload_sha256,
            "expected_version": 2,
        }
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 320,
                "payload_sha256": self.sources[320].payload_sha256,
            },
            "issue_number": 320,
            "generation": 1,
            "item_version": payload_version,
            "transfer_key": "issue314-to-320-v1",
            "parent_issue_number": 314,
            "transfer_comment_ids": [1001, 1002],
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            "base_sha": "a" * 40,
            "branch": "codex/314-ci-hardening",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-314",
            "opaque_worktree_id": "twinfinityapp-issue-314",
            "accountable_session_id": SRE_SESSION,
            "lease_manifest_sha256": self.successor_lease_sha,
            "authority_sha256": "3" * 64,
            "capacity": {"development_units": 0, "shared_units": 0, "sre_units": 1},
        }
        lineage = {
            "predecessor_issue_number": 314,
            "predecessor_generation": 8,
            "predecessor_item_version": 2,
            "predecessor_admission_item_version": 1,
            "predecessor_source_payload_sha256": self.sources[314].payload_sha256,
            "predecessor_admission_message_id": self.parent_message,
            "predecessor_admission_payload_sha256": self.store.connection.execute(
                "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
                (self.parent_message,),
            ).fetchone()[0],
            "predecessor_accountable_session_id": SRE_SESSION,
            "predecessor_lease_manifest_sha256": "1" * 64,
            "predecessor_development_units": 0,
            "predecessor_shared_units": 0,
            "predecessor_sre_units": 1,
            "predecessor_pretransfer_status": "HOLD",
            "predecessor_pretransfer_allocation_class": "RETAINED",
            "predecessor_comment_id": 1001,
            "predecessor_comment_body_sha256": hashlib.sha256(
                self.comment_bodies[1001].encode()
            ).hexdigest(),
            "successor_comment_id": 1002,
            "successor_comment_body_sha256": hashlib.sha256(
                self.comment_bodies[1002].encode()
            ).hexdigest(),
        }
        payload["transfer_comment_body_sha256"] = [
            lineage["predecessor_comment_body_sha256"],
            lineage["successor_comment_body_sha256"],
        ]
        payload["transfer_authority_sha256"] = "3" * 64
        transaction = {
            "transfer_key": "issue314-to-320-v1",
            "lineage": lineage,
            "releases": [release],
            "activation": {
                "item": item,
                "message": {
                    "idempotency_key": "issue320-admission-v1",
                    "recipient_session_id": SRE_SESSION,
                    "topic": "sre.admission",
                    "payload": payload,
                },
            },
        }
        self.refresh_transfer_intent_hash(transaction)
        bind_delivery_identity(transaction["activation"])
        return transaction

    def transaction(self, *, payload_version: int = 3):
        transaction = copy.deepcopy(self.ready_transaction)
        if payload_version != 3:
            transaction["activation"]["message"]["payload"][
                "item_version"
            ] = payload_version
            self.refresh_transfer_intent_hash(transaction)
            bind_delivery_identity(transaction["activation"])
        return transaction

    @staticmethod
    def intent_record(transaction: dict) -> dict:
        lineage = transaction["lineage"]
        item = transaction["activation"]["item"]
        payload = transaction["activation"]["message"]["payload"]
        releases = transaction["releases"]
        predecessor_release = next(
            release
            for release in releases
            if release["issue_number"] == lineage["predecessor_issue_number"]
        )
        item_result = lambda desired: {
            "repository": desired["repository"],
            "issue_number": desired["issue_number"],
            "status": desired["status"],
            "allocation_class": desired["allocation_class"],
            "generation": desired["generation"],
            "version": desired["expected_version"] + 1,
            "source_payload_sha256": desired["expected_source_sha256"],
        }
        return {
            "transfer_key": transaction["transfer_key"],
            "repository": item["repository"],
            **lineage,
            "predecessor_release_status": predecessor_release["status"],
            "predecessor_release_allocation_class": predecessor_release[
                "allocation_class"
            ],
            "successor_issue_number": item["issue_number"],
            "successor_generation": item["generation"],
            "successor_item_version": item["expected_version"] + 1,
            "successor_source_payload_sha256": item["expected_source_sha256"],
            "successor_admission_message_id": 1,
            "successor_admission_payload_sha256": "0" * 64,
            "successor_accountable_session_id": item["accountable_session_id"],
            "successor_lease_manifest_sha256": item["lease_manifest_sha256"],
            "successor_development_units": item["development_units"],
            "successor_shared_units": item["shared_units"],
            "successor_sre_units": item["sre_units"],
            "released_items": [item_result(release) for release in releases],
            "activated_item": item_result(item),
            "activation_event_schema": "v2",
            "branch": payload["branch"],
            "worktree_path": payload["worktree_path"],
            "opaque_worktree_id": payload["opaque_worktree_id"],
            "transfer_authority_sha256": payload["authority_sha256"],
        }

    @classmethod
    def refresh_transfer_intent_hash(cls, transaction: dict) -> None:
        transaction["activation"]["message"]["payload"][
            "transfer_intent_sha256"
        ] = intent_sha256(cls.intent_record(transaction))
        if "delivery_identity" in transaction["activation"]["message"]["payload"]:
            bind_delivery_identity(transaction["activation"])

    def test_atomic_transfer_and_idempotent_replay(self) -> None:
        transaction = self.transaction()
        first = activate_transfer(self.store, transaction, "2026-08-23T17:00:03Z")
        self.assertFalse(first["replayed"])
        second = activate_transfer(self.store, transaction, "2026-08-23T17:00:04Z")
        self.assertTrue(second["replayed"])
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET state='ACTIVE' "
            "WHERE repository=? AND issue_number=320 AND generation=1",
            (REPOSITORY,),
        )
        self.store.claim_message(
            first["message_id"], SRE_SESSION, "2026-08-23T17:00:05Z"
        )
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE',updated_at=? "
            "WHERE id=? AND state='CLAIMED' AND claimed_by=?",
            ("2026-08-23T17:00:06Z", first["message_id"], SRE_SESSION),
        )
        transfer_record, transfer_digest = load_record(
            self.store, transaction["transfer_key"]
        )
        self.assertEqual(
            transfer_digest,
            record_existing(
                self.store,
                transfer_record,
                "2026-08-23T17:00:07Z",
            ),
        )
        rows = {
            row["issue_number"]: row
            for row in self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=?", (REPOSITORY,)
            )
        }
        self.assertEqual(("MONITOR", "NONE"), (rows[314]["status"], rows[314]["allocation_class"]))
        self.assertEqual(
            ("ACTIVE_FENCED", "ACTIVE", 1),
            (rows[320]["status"], rows[320]["allocation_class"], rows[320]["sre_units"]),
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages WHERE idempotency_key='issue320-admission-v1'"
            ).fetchone()[0],
        )
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE repository=? AND issue_number=320 AND generation=1",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(
            ("ACTIVE", SRE_SESSION, self.successor_lease_sha),
            (
                watch["state"],
                watch["accountable_session_id"],
                watch["lease_manifest_sha256"],
            ),
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE event_type='TRANSFER_ADMISSION_ACTIVATED' AND entity_key='issue314-to-320-v1'"
            ).fetchone()[0],
        )

    def test_delivery_context_preserves_transferred_owning_issue(self) -> None:
        result = activate_transfer(
            self.store,
            self.transaction(),
            "2026-08-23T17:00:03Z",
        )
        watch = self.store.connection.execute(
            "SELECT watch_key FROM coordination_terminal_watches "
            "WHERE repository=? AND issue_number=320 AND generation=1",
            (REPOSITORY,),
        ).fetchone()
        self.assertIsNotNone(watch)
        lease_result = (
            Path("/home/ubuntu/code/twinfinityapp-issue-314"),
            frozenset(
                {
                    Path("/home/ubuntu/code/twinfinityapp-issue-314")
                    / "backend/example.py"
                }
            ),
            Path("/home/ubuntu/code/twinfinityapp"),
            "codex/314-ci-hardening",
            "a" * 40,
        )
        with patch("delivery_guard._load_lease", return_value=lease_result):
            message_context = _message_context(
                self.store.connection,
                self.database,
                role="sre",
                endpoint_id=SRE_SESSION,
                target_key=str(result["message_id"]),
                worktree_root=Path("/home/ubuntu/code"),
            )
            self.assertEqual(320, message_context.owning_issue_number)
            self.assertEqual("codex/314-ci-hardening", message_context.branch)

            self.store.connection.execute(
                "UPDATE coordination_terminal_watches SET state='ACTIVE' "
                "WHERE watch_key=?",
                (watch["watch_key"],),
            )
            watch_context = _terminal_watch_context(
                self.store.connection,
                self.database,
                role="sre",
                endpoint_id=SRE_SESSION,
                target_key=watch["watch_key"],
                worktree_root=Path("/home/ubuntu/code"),
            )
            self.assertEqual(320, watch_context.owning_issue_number)
            self.assertEqual("codex/314-ci-hardening", watch_context.branch)

            self.store.connection.execute(
                "UPDATE coordination_terminal_watches SET issue_number=314 "
                "WHERE watch_key=?",
                (watch["watch_key"],),
            )
            with self.assertRaisesRegex(GuardError, "DELIVERY_TARGET_INVALID"):
                _terminal_watch_context(
                    self.store.connection,
                    self.database,
                    role="sre",
                    endpoint_id=SRE_SESSION,
                    target_key=watch["watch_key"],
                    worktree_root=Path("/home/ubuntu/code"),
                )

    def test_binding_failure_rolls_back_release_and_activation(self) -> None:
        with self.assertRaisesRegex(
            CoordinationError, "READY_FINALIZATION_ATTESTATION_DRIFT"
        ):
            activate_transfer(
                self.store, self.transaction(payload_version=2), "2026-08-23T17:00:03Z"
            )
        parent = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=314",
            (REPOSITORY,),
        ).fetchone()
        child = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=320",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(("HOLD", "RETAINED", 1), (parent["status"], parent["allocation_class"], parent["sre_units"]))
        self.assertEqual(("READY", "NONE", 2), (
            child["status"], child["allocation_class"], child["version"]
        ))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches WHERE issue_number=320"
            ).fetchone()[0],
        )

    def test_identity_or_ready_attestation_drift_has_zero_transfer_writes(self) -> None:
        def writer_state() -> tuple:
            return (
                self.store.connection.total_changes,
                tuple(
                    self.store.connection.execute(
                        "SELECT status,allocation_class,generation,version "
                        "FROM coordination_items WHERE issue_number=314"
                    ).fetchone()
                ),
                tuple(
                    self.store.connection.execute(
                        "SELECT status,allocation_class,generation,version "
                        "FROM coordination_items WHERE issue_number=320"
                    ).fetchone()
                ),
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM coordination_messages "
                    "WHERE idempotency_key LIKE 'issue320-admission-v1%'"
                ).fetchone()[0],
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM coordination_terminal_watches "
                    "WHERE issue_number=320"
                ).fetchone()[0],
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM coordination_events "
                    "WHERE event_type LIKE 'TRANSFER_%'"
                ).fetchone()[0],
            )

        missing_identity = self.transaction()
        missing_identity["activation"]["message"]["payload"].pop(
            "delivery_identity"
        )
        before = writer_state()
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_DELIVERY_IDENTITY_INVALID"
        ):
            activate_transfer(
                self.store, missing_identity, "2026-08-23T17:00:09Z"
            )
        self.assertEqual(before, writer_state())

        substituted_message = self.transaction()
        substituted_message["activation"]["message"][
            "idempotency_key"
        ] = "issue320-admission-v1-substituted"
        bind_delivery_identity(substituted_message["activation"])
        before = writer_state()
        with self.assertRaisesRegex(
            CoordinationError, "READY_FINALIZATION_ATTESTATION_DRIFT"
        ):
            activate_transfer(
                self.store, substituted_message, "2026-08-23T17:00:10Z"
            )
        self.assertEqual(before, writer_state())

    def test_missing_ready_attestation_has_zero_transfer_writes(self) -> None:
        trigger_sql = self.store.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='portfolio_ready_finalizations_immutable_delete'"
        ).fetchone()[0]
        with self.store.transaction():
            self.store.connection.execute(
                "DROP TRIGGER portfolio_ready_finalizations_immutable_delete"
            )
            self.store.connection.execute(
                "DELETE FROM portfolio_ready_finalizations "
                "WHERE repository=? AND issue_number=320",
                (REPOSITORY,),
            )
            self.store.connection.execute(trigger_sql)
        before = (
            self.store.connection.total_changes,
            tuple(
                self.store.connection.execute(
                    "SELECT status,allocation_class,version FROM coordination_items "
                    "WHERE issue_number=314"
                ).fetchone()
            ),
            tuple(
                self.store.connection.execute(
                    "SELECT status,allocation_class,version FROM coordination_items "
                    "WHERE issue_number=320"
                ).fetchone()
            ),
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE idempotency_key='issue320-admission-v1'"
            ).fetchone()[0],
        )
        with self.assertRaisesRegex(
            CoordinationError, "READY_FINALIZATION_ATTESTATION_MISSING"
        ):
            activate_transfer(
                self.store, self.transaction(), "2026-08-23T17:00:09Z"
            )
        after = (
            self.store.connection.total_changes,
            tuple(
                self.store.connection.execute(
                    "SELECT status,allocation_class,version FROM coordination_items "
                    "WHERE issue_number=314"
                ).fetchone()
            ),
            tuple(
                self.store.connection.execute(
                    "SELECT status,allocation_class,version FROM coordination_items "
                    "WHERE issue_number=320"
                ).fetchone()
            ),
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE idempotency_key='issue320-admission-v1'"
            ).fetchone()[0],
        )
        self.assertEqual(before, after)

    def test_transferred_surface_requires_exact_parent_bindings(self) -> None:
        for mutate in (
            lambda payload: payload.pop("parent_issue_number"),
            lambda payload: payload.update(parent_issue_number=313),
            lambda payload: payload.update(worktree_path="/home/ubuntu/code/twinfinityapp-issue-320"),
            lambda payload: payload.update(opaque_worktree_id="twinfinityapp-issue-320"),
            lambda payload: payload.update(transfer_comment_ids=[1001]),
        ):
            with self.subTest(mutate=mutate):
                transaction = self.transaction()
                mutate(transaction["activation"]["message"]["payload"])
                with self.assertRaisesRegex(CoordinationError, "TRANSFER_SURFACE_INVALID"):
                    activate_transfer(
                        self.store, transaction, "2026-08-23T17:00:03Z"
                    )
                child = self.store.connection.execute(
                    "SELECT status,allocation_class,version FROM coordination_items "
                    "WHERE issue_number=320"
                ).fetchone()
                self.assertEqual(
                    ("READY", "NONE", 2),
                    tuple(child),
                )

    def test_transfer_rejects_missing_predecessor_ownership_and_nonterminal_release(self) -> None:
        missing_admission = self.transaction()
        missing_admission["lineage"]["predecessor_admission_message_id"] = 999999
        self.refresh_transfer_intent_hash(missing_admission)
        with self.assertRaisesRegex(
            CoordinationError, "READY_FINALIZATION_ATTESTATION_DRIFT"
        ):
            activate_transfer(
                self.store, missing_admission, "2026-08-23T17:00:07Z"
            )
        nonterminal = self.transaction()
        nonterminal["releases"][0]["status"] = "QUEUED"
        with self.assertRaisesRegex(CoordinationError, "TRANSFER_RELEASE_INVALID"):
            activate_transfer(self.store, nonterminal, "2026-08-23T17:00:08Z")
        parent = self.store.connection.execute(
            "SELECT status, allocation_class FROM coordination_items WHERE issue_number=314"
        ).fetchone()
        self.assertEqual(("HOLD", "RETAINED"), tuple(parent))
        child = self.store.connection.execute(
            "SELECT status,allocation_class,version FROM coordination_items "
            "WHERE issue_number=320"
        ).fetchone()
        self.assertEqual(
            ("READY", "NONE", 2),
            tuple(child),
        )

    def test_transfer_rejects_stale_or_unavailable_comment_receipts(self) -> None:
        stale = self.transaction()
        with (
            patch(
                "coordination_transfer_ledger.fetch_comment",
                side_effect=lambda repository, comment_id: {
                    "id": comment_id,
                    "issue_url": (
                        f"https://api.github.com/repos/{repository}/issues/"
                        f"{314 if comment_id == 1001 else 320}"
                    ),
                    "body": self.comment_bodies[comment_id] + " changed",
                },
            ),
            self.assertRaisesRegex(CoordinationError, "TRANSFER_COMMENT_INVALID"),
        ):
            activate_transfer(self.store, stale, "2026-08-23T17:00:07Z")
        unavailable = self.transaction()
        with (
            patch(
                "coordination_transfer_ledger.fetch_comment",
                side_effect=CoordinationError("TRANSFER_COMMENT_UNAVAILABLE"),
            ),
            self.assertRaisesRegex(CoordinationError, "TRANSFER_COMMENT_UNAVAILABLE"),
        ):
            activate_transfer(self.store, unavailable, "2026-08-23T17:00:08Z")
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages WHERE idempotency_key='issue320-admission-v1'"
            ).fetchone()[0],
        )

    def test_replay_rejects_watch_and_source_drift(self) -> None:
        transaction = self.transaction()
        activate_transfer(self.store, transaction, "2026-08-23T17:00:03Z")
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_terminal_watches SET state='HOLD' WHERE issue_number=320"
            )
        with self.assertRaisesRegex(CoordinationError, "TRANSFER_REPLAY_WATCH_DRIFT"):
            activate_transfer(self.store, transaction, "2026-08-23T17:00:04Z")
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_terminal_watches SET state='ACTIVE' WHERE issue_number=320"
            )
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=320,
            payload={"number": 320, "updated_at": "2026-08-23T17:01:00Z"},
            source_updated_at="2026-08-23T17:01:00Z",
            fetched_at="2026-08-23T17:01:01Z",
        )
        with self.assertRaisesRegex(CoordinationError, "TRANSFER_REPLAY_SOURCE_DRIFT"):
            activate_transfer(self.store, transaction, "2026-08-23T17:01:02Z")

    def test_concurrent_identical_call_replays_after_one_commit(self) -> None:
        transaction = self.transaction()

        def run(index: int):
            store = CoordinationStore(self.database)
            try:
                return activate_transfer(
                    store, transaction, f"2026-08-23T17:00:0{index + 3}Z"
                )
            finally:
                store.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(run, (0, 1)))
        self.assertEqual([False, True], sorted(result["replayed"] for result in results))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages WHERE idempotency_key='issue320-admission-v1'"
            ).fetchone()[0],
        )

    def test_replay_rejects_held_admission(self) -> None:
        transaction = self.transaction()
        activate_transfer(self.store, transaction, "2026-08-23T17:00:03Z")
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_messages SET state='HOLD', last_error='TEST_HOLD' WHERE idempotency_key='issue320-admission-v1'"
            )
        with self.assertRaisesRegex(CoordinationError, "TRANSFER_REPLAY_ADMISSION_HELD"):
            activate_transfer(self.store, transaction, "2026-08-23T17:00:04Z")

    def test_intent_is_non_circular_and_full_record_binds_successor_receipt(self) -> None:
        record = self.intent_record(self.transaction())
        changed = copy.deepcopy(record)
        changed["successor_admission_message_id"] = 999
        changed["successor_admission_payload_sha256"] = "9" * 64
        self.assertEqual(intent_sha256(record), intent_sha256(changed))
        self.assertNotEqual(record_sha256(record), record_sha256(changed))

    def test_predecessor_admission_and_lease_fields_are_all_bound(self) -> None:
        mutations = (
            ("predecessor_admission_item_version", 2),
            ("predecessor_source_payload_sha256", "8" * 64),
            (
                "predecessor_accountable_session_id",
                "role.development.v3",
            ),
            ("predecessor_lease_manifest_sha256", "7" * 64),
            ("predecessor_development_units", 1),
            ("predecessor_shared_units", 1),
            ("predecessor_sre_units", 0),
            ("predecessor_pretransfer_status", "ACTIVE_FENCED"),
            ("predecessor_pretransfer_allocation_class", "ACTIVE"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                transaction = self.transaction()
                transaction["lineage"][field] = value
                if field == "predecessor_source_payload_sha256":
                    transaction["releases"][0]["expected_source_sha256"] = value
                self.refresh_transfer_intent_hash(transaction)
                with self.assertRaisesRegex(
                    CoordinationError, "READY_FINALIZATION_ATTESTATION_DRIFT"
                ):
                    activate_transfer(
                        self.store, transaction, "2026-08-23T17:00:07Z"
                    )

    def test_predecessor_version_continuity_requires_exact_state_event(self) -> None:
        transaction = self.transaction()
        with self.store.transaction():
            self.store.connection.execute(
                "DELETE FROM coordination_events WHERE id=("
                "SELECT MAX(id) FROM coordination_events "
                "WHERE event_type='ISSUE_STATUS_CHANGED' "
                "AND entity_key=?"
                ")",
                (f"{REPOSITORY}:issue:314",),
            )
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_PREDECESSOR_OWNERSHIP_INVALID"
        ):
            activate_transfer(self.store, transaction, "2026-08-23T17:00:07Z")

    def test_replay_rejects_exact_event_or_ledger_corruption(self) -> None:
        transaction = self.transaction()
        activate_transfer(self.store, transaction, "2026-08-23T17:00:03Z")
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_events SET payload_sha256=? "
                "WHERE event_type='TRANSFER_ADMISSION_ACTIVATED' AND entity_key=?",
                ("f" * 64, transaction["transfer_key"]),
            )
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_EVENT_PROVENANCE_INVALID"
        ):
            activate_transfer(self.store, transaction, "2026-08-23T17:00:04Z")
        with self.store.transaction():
            self.store.connection.execute(
                "UPDATE coordination_transfer_ledger SET record_json='{}' "
                "WHERE transfer_key=?",
                (transaction["transfer_key"],),
            )
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_LEDGER_INVALID"
        ):
            activate_transfer(self.store, transaction, "2026-08-23T17:00:05Z")

    def test_replay_rejects_missing_exact_predecessor_snapshot(self) -> None:
        transaction = self.transaction()
        activate_transfer(self.store, transaction, "2026-08-23T17:00:03Z")
        with self.store.transaction():
            self.store.connection.execute(
                "DELETE FROM coordination_events "
                "WHERE event_type='TRANSFER_PREDECESSOR_BOUND' AND entity_key=?",
                (transaction["transfer_key"],),
            )
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_PREDECESSOR_OWNERSHIP_INVALID"
        ):
            activate_transfer(self.store, transaction, "2026-08-23T17:00:04Z")

    def test_empty_legacy_ledger_schema_migrates_before_first_record(self) -> None:
        self.store.connection.execute(self.LEGACY_LEDGER_SCHEMA)
        create_schema(self.store)
        columns = {
            row[1]
            for row in self.store.connection.execute(
                "PRAGMA table_info(coordination_transfer_ledger)"
            )
        }
        self.assertIn("intent_sha256", columns)

    def test_populated_legacy_ledger_and_legacy_read_fail_closed(self) -> None:
        self.store.connection.execute(self.LEGACY_LEDGER_SCHEMA)
        self.store.connection.execute(
            "INSERT INTO coordination_transfer_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-transfer",
                REPOSITORY,
                314,
                320,
                "a" * 64,
                "{}",
                "2026-08-23T17:00:00Z",
            ),
        )
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_LEDGER_SCHEMA_LEGACY"
        ):
            create_schema(self.store)
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_LEDGER_SCHEMA_LEGACY"
        ):
            load_record(self.store, "legacy-transfer")


if __name__ == "__main__":
    unittest.main()
