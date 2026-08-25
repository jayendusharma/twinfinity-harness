from __future__ import annotations

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
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
        self.store.set_issue_status(
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
        self.parent_message = self.store.enqueue_message(
            idempotency_key="issue314-generation8-parent-admission",
            recipient_session_id=SRE_SESSION,
            topic="sre.admission",
            payload={
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
            now="2026-08-23T17:00:03Z",
        )
        self.store.claim_message(
            self.parent_message, SRE_SESSION, "2026-08-23T17:00:04Z"
        )
        self.store.complete_message(
            self.parent_message, SRE_SESSION, "2026-08-23T17:00:05Z"
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

    def tearDown(self) -> None:
        self.comment_patch.stop()
        self.store.close()
        self.temp.cleanup()

    def transaction(self, *, payload_version: int = 1):
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
            "lease_manifest_sha256": "2" * 64,
            "development_units": 0,
            "shared_units": 0,
            "sre_units": 1,
            "expected_source_sha256": self.sources[320].payload_sha256,
            "expected_version": 0,
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
            "lease_manifest_sha256": "2" * 64,
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

    def test_atomic_transfer_and_idempotent_replay(self) -> None:
        transaction = self.transaction()
        first = activate_transfer(self.store, transaction, "2026-08-23T17:00:03Z")
        self.assertFalse(first["replayed"])
        second = activate_transfer(self.store, transaction, "2026-08-23T17:00:04Z")
        self.assertTrue(second["replayed"])
        self.store.claim_message(
            first["message_id"], SRE_SESSION, "2026-08-23T17:00:05Z"
        )
        self.store.complete_message(
            first["message_id"], SRE_SESSION, "2026-08-23T17:00:06Z"
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
        self.assertEqual(("ACTIVE", SRE_SESSION, "2" * 64), (watch["state"], watch["accountable_session_id"], watch["lease_manifest_sha256"]))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE event_type='TRANSFER_ADMISSION_ACTIVATED' AND entity_key='issue314-to-320-v1'"
            ).fetchone()[0],
        )

    def test_binding_failure_rolls_back_release_and_activation(self) -> None:
        with self.assertRaisesRegex(CoordinationError, "TRANSFER_ADMISSION_BINDING_MISMATCH"):
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
        self.assertIsNone(child)
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches WHERE issue_number=320"
            ).fetchone()[0],
        )

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
                self.assertIsNone(
                    self.store.connection.execute(
                        "SELECT 1 FROM coordination_items WHERE issue_number=320"
                    ).fetchone()
                )

    def test_transfer_rejects_missing_predecessor_ownership_and_nonterminal_release(self) -> None:
        missing_admission = self.transaction()
        missing_admission["lineage"]["predecessor_admission_message_id"] = 999999
        self.refresh_transfer_intent_hash(missing_admission)
        with self.assertRaisesRegex(
            CoordinationError, "TRANSFER_PREDECESSOR_OWNERSHIP_INVALID"
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
        self.assertIsNone(
            self.store.connection.execute(
                "SELECT 1 FROM coordination_items WHERE issue_number=320"
            ).fetchone()
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
                    CoordinationError, "TRANSFER_PREDECESSOR_OWNERSHIP_INVALID"
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
