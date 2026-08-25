from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from archive_readiness_audit import archive_readiness  # noqa: E402
from coordination_store import CoordinationStore  # noqa: E402
from executor_registry import (  # noqa: E402
    RegistryError,
    attempt_lineage_for_target,
    load_registry_config,
    reserve_attempt,
)
from hosted_operation_control import HostedOperationControl  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)


CONFIG = ROOT / "references" / "twinfinity-executor-registry.toml"
ALIASES = ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
REPOSITORY = "twinfinityai/twinfinityapp"
DEVELOPMENT_ENDPOINT = "role.development.v3"
SRE_ENDPOINT = "role.sre.v3"
LEASE = "7" * 64


class ArchiveReadinessAtomicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.store = CoordinationStore(root / "state.sqlite3")
        config = load_registry_config(CONFIG)
        aliases, alias_sha = load_legacy_alias_fixture(ALIASES)
        plan = build_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="archive-readiness-atomic-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:00Z",
        )
        self.notice_source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=900,
            payload={"number": 900, "title": "Audit notice", "body": "safe"},
            source_updated_at="2026-08-24T09:00:00Z",
            fetched_at="2026-08-24T09:00:01Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def readiness(self) -> dict:
        return archive_readiness(
            self.store.connection,
            legacy_alias_path=ALIASES,
        )

    def insert_message(
        self,
        *,
        recipient: str = DEVELOPMENT_ENDPOINT,
        topic: str = "coordination.notice",
        state: str = "PREPARED",
    ) -> int:
        value = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 900,
                "payload_sha256": self.notice_source.payload_sha256,
            },
            "notice_kind": "status",
            "mutation_authority": False,
            "subject": "archive audit",
            "summary": "read-only status",
            "evidence": {"phase": "prepared"},
        }
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        cursor = self.store.connection.execute(
            """
            INSERT INTO coordination_messages(
                idempotency_key,recipient_session_id,topic,payload_sha256,
                payload_json,state,created_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                f"atomic-message-{recipient}-{topic}-{state}",
                recipient,
                topic,
                digest,
                payload,
                state,
                "2026-08-24T10:00:01Z",
                "2026-08-24T10:00:01Z",
            ),
        )
        return int(cursor.lastrowid)

    def reserve(
        self,
        *,
        role: str,
        endpoint: str,
        target_kind: str,
        target_key: str,
    ) -> None:
        def lineage(connection):
            try:
                return attempt_lineage_for_target(connection, target_kind, target_key)
            except RegistryError:
                return None

        reserve_attempt(
            self.store.connection,
            role=role,
            endpoint_id=endpoint,
            target_kind=target_kind,
            target_key=target_key,
            now="2026-08-24T10:00:02Z",
            precondition=lineage,
        )

    def test_current_message_attempt_is_nonblocking(self) -> None:
        message_id = self.insert_message()
        self.reserve(
            role="development",
            endpoint=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
        )

        result = self.readiness()

        self.assertEqual([], result["gates"]["active_attempts"])

    def test_missing_terminal_wrong_role_and_wrong_recipient_messages_block(self) -> None:
        cases = (
            ("missing", None, "999999"),
            ("terminal", {"state": "COMPLETE"}, None),
            ("wrong-role", {"topic": "sre.admission"}, None),
            ("wrong-recipient", {"recipient": SRE_ENDPOINT}, None),
        )
        for name, values, explicit_key in cases:
            with self.subTest(name=name):
                if name != "missing":
                    message_id = self.insert_message(**(values or {}))
                    target_key = str(message_id)
                else:
                    target_key = str(explicit_key)
                self.reserve(
                    role="development",
                    endpoint=DEVELOPMENT_ENDPOINT,
                    target_kind="message",
                    target_key=target_key,
                )
                result = self.readiness()
                self.assertEqual(1, len(result["gates"]["active_attempts"]))
                self.store.connection.execute(
                    "UPDATE executor_attempts SET state='HOLD' "
                    "WHERE target_kind='message' AND target_key=?",
                    (target_key,),
                )

    def test_terminal_watch_must_match_the_current_active_item(self) -> None:
        source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={"number": 92, "title": "Atomic watch", "body": "safe"},
            source_updated_at="2026-08-24T09:00:00Z",
            fetched_at="2026-08-24T09:00:01Z",
        )
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_ENDPOINT,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-24T10:00:01Z",
        )
        watch = self.store.connection.execute(
            "SELECT watch_key FROM coordination_terminal_watches WHERE issue_number=92"
        ).fetchone()
        self.reserve(
            role="development",
            endpoint=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=str(watch["watch_key"]),
        )
        self.assertEqual([], self.readiness()["gates"]["active_attempts"])

        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET lease_manifest_sha256=?",
            ("8" * 64,),
        )
        held = self.readiness()
        self.assertEqual(
            "ACTIVE_ATTEMPT_LINEAGE_INVALID",
            held["gates"]["active_attempts"][0]["error"],
        )

    def test_hosted_operation_must_be_actionable_current_sre_target(self) -> None:
        control = object.__new__(HostedOperationControl)
        control.store = self.store
        control.connection = self.store.connection
        control._create_schema()
        source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=328,
            payload={"number": 328, "title": "Hosted audit", "body": "safe"},
            source_updated_at="2026-08-24T09:00:00Z",
            fetched_at="2026-08-24T09:00:01Z",
        )
        scope = {
            "target": {"project_ids": ["twinfinity-staging"]},
            "expected_state": {"authenticated_account_sha256": "9" * 64},
            "desired_state": {
                "metadata_categories": ["iam_bindings"],
                "read_only": True,
            },
            "exclusions": ["secret payloads"],
            "stop_conditions": ["source drift"],
        }
        scope_json = json.dumps(scope, sort_keys=True, separators=(",", ":"))
        self.store.connection.execute(
            """
            INSERT INTO hosted_operations(
                id,idempotency_key,repository,object_kind,issue_number,
                source_payload_sha256,provider,target_kind,target_key,
                operation_kind,authority_comment_id,authority_body_sha256,
                scope_sha256,scope_json,recipient_session_id,sre_units,
                blocked_by_issue_number,state,created_at,updated_at
            ) VALUES (328,'hosted-328',?,'issue',328,?,'google_cloud',
                      'gcp_project_inventory','twinfinity-staging','READ_METADATA',
                      1,?,?,?,?,0,NULL,'PREPARED',?,?)
            """,
            (
                REPOSITORY,
                source.payload_sha256,
                "8" * 64,
                hashlib.sha256(scope_json.encode("utf-8")).hexdigest(),
                scope_json,
                SRE_ENDPOINT,
                "2026-08-24T10:00:01Z",
                "2026-08-24T10:00:01Z",
            ),
        )
        self.reserve(
            role="sre",
            endpoint=SRE_ENDPOINT,
            target_kind="hosted_operation",
            target_key="328",
        )
        self.assertEqual([], self.readiness()["gates"]["active_attempts"])

        self.store.connection.execute(
            "UPDATE hosted_operations SET state='COMPLETE' WHERE id=328"
        )
        held = self.readiness()
        self.assertEqual(
            "ACTIVE_ATTEMPT_TARGET_NOT_ACTIONABLE",
            held["gates"]["active_attempts"][0]["error"],
        )

    def test_external_reads_hold_no_transaction_and_local_drift_fails_closed(self) -> None:
        message_id = self.insert_message()
        self.reserve(
            role="development",
            endpoint=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
        )

        def external_read(_context, *, page_reader, comment_reader):
            self.assertIsNone(page_reader)
            self.assertIsNone(comment_reader)
            self.assertFalse(self.store.connection.in_transaction)
            self.store.connection.execute(
                "UPDATE coordination_messages SET state='COMPLETE' WHERE id=?",
                (message_id,),
            )
            return []

        with patch(
            "archive_readiness_audit._routing_inventory_external_gate",
            side_effect=external_read,
        ):
            result = self.readiness()

        self.assertEqual("HOLD", result["phase"])
        self.assertEqual(
            [{"error": "ARCHIVE_READINESS_LOCAL_STATE_DRIFT"}],
            result["gates"]["local_state_consistency"],
        )
        self.assertEqual([], result["gates"]["active_attempts"])

    def test_concurrent_writer_cannot_mix_local_table_generations(self) -> None:
        message_id = self.insert_message()
        self.reserve(
            role="development",
            endpoint=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
        )
        writer = sqlite3.connect(self.store.path, isolation_level=None, timeout=5)
        mutated = False

        def interleave(statement: str) -> None:
            nonlocal mutated
            if not mutated and "SELECT endpoint.endpoint_id" in statement:
                writer.execute(
                    "UPDATE coordination_messages SET state='COMPLETE' WHERE id=?",
                    (message_id,),
                )
                mutated = True

        self.store.connection.set_trace_callback(interleave)
        try:
            result = self.readiness()
        finally:
            self.store.connection.set_trace_callback(None)
            writer.close()

        self.assertTrue(mutated)
        self.assertEqual([], result["gates"]["active_attempts"])
        self.assertEqual(
            [{"error": "ARCHIVE_READINESS_LOCAL_STATE_DRIFT"}],
            result["gates"]["local_state_consistency"],
        )


if __name__ == "__main__":
    unittest.main()
