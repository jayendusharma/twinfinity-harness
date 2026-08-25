from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


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
DEVELOPMENT_ENDPOINT = "role.development.v4"
SRE_ENDPOINT = "role.sre.v4"
LEASE = "7" * 64


class ArchiveReadinessAttemptAuditTests(unittest.TestCase):
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
            operation_key="archive-readiness-adversarial-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:00Z",
        )
        self.source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=501,
            payload={"number": 501, "title": "Audit", "body": "safe"},
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

    def notice_payload(self) -> dict:
        return {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 501,
                "payload_sha256": self.source.payload_sha256,
            },
            "notice_kind": "status",
            "mutation_authority": False,
            "subject": "audit",
            "summary": "read-only status",
            "evidence": {"phase": "prepared"},
        }

    def insert_notice(self, *, payload: dict | None = None) -> int:
        value = self.notice_payload() if payload is None else payload
        payload_json = json.dumps(value, sort_keys=True, separators=(",", ":"))
        cursor = self.store.connection.execute(
            """
            INSERT INTO coordination_messages(
                idempotency_key,recipient_session_id,topic,payload_sha256,
                payload_json,state,created_at,updated_at
            ) VALUES (?,?,?,?,?,'PREPARED',?,?)
            """,
            (
                f"audit-notice-{hashlib.sha256(payload_json.encode()).hexdigest()}",
                DEVELOPMENT_ENDPOINT,
                "coordination.notice",
                hashlib.sha256(payload_json.encode()).hexdigest(),
                payload_json,
                "2026-08-24T10:00:01Z",
                "2026-08-24T10:00:01Z",
            ),
        )
        return int(cursor.lastrowid)

    def reserve(self, target_kind: str, target_key: str, *, role="development") -> str:
        endpoint = DEVELOPMENT_ENDPOINT if role == "development" else SRE_ENDPOINT
        def lineage(connection):
            try:
                return attempt_lineage_for_target(connection, target_kind, target_key)
            except RegistryError:
                return None

        row, _token = reserve_attempt(
            self.store.connection,
            role=role,
            endpoint_id=endpoint,
            target_kind=target_kind,
            target_key=target_key,
            now="2026-08-24T10:00:02Z",
            precondition=lineage,
        )
        return str(row["attempt_id"])

    def active_error(self) -> str | None:
        entries = self.readiness()["gates"]["active_attempts"]
        return None if not entries else str(entries[0]["error"])

    def test_valid_message_attempt_includes_contract_and_event_integrity(self) -> None:
        message_id = self.insert_notice()
        self.reserve("message", str(message_id))
        self.assertIsNone(self.active_error())

    def test_message_payload_digest_and_source_drift_block(self) -> None:
        bad = self.notice_payload()
        bad.pop("summary")
        message_id = self.insert_notice(payload=bad)
        self.reserve("message", str(message_id))
        self.assertEqual("ACTIVE_ATTEMPT_TARGET_AUTHORITY_INVALID", self.active_error())

        self.store.connection.execute(
            "UPDATE executor_attempts SET state='HOLD' WHERE target_key=?",
            (str(message_id),),
        )
        valid_id = self.insert_notice()
        self.reserve("message", str(valid_id))
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=501,
            payload={"number": 501, "title": "Audit", "body": "drifted"},
            source_updated_at="2026-08-24T09:01:00Z",
            fetched_at="2026-08-24T09:01:01Z",
        )
        self.assertEqual("ACTIVE_ATTEMPT_TARGET_AUTHORITY_INVALID", self.active_error())

    def test_token_digest_and_event_chain_corruption_block(self) -> None:
        message_id = self.insert_notice()
        attempt_id = self.reserve("message", str(message_id))
        self.store.connection.execute("DROP TRIGGER executor_attempt_identity_immutable")
        self.store.connection.execute(
            "UPDATE executor_attempts SET token_sha256='not-a-digest' WHERE attempt_id=?",
            (attempt_id,),
        )
        self.assertEqual("ACTIVE_ATTEMPT_IDENTITY_INVALID", self.active_error())

        self.store.connection.execute(
            "UPDATE executor_attempts SET token_sha256=? WHERE attempt_id=?",
            ("a" * 64, attempt_id),
        )
        self.store.connection.execute("DROP TRIGGER executor_attempt_event_immutable_delete")
        self.store.connection.execute(
            "DELETE FROM executor_attempt_events WHERE attempt_id=?", (attempt_id,)
        )
        self.assertEqual("ACTIVE_ATTEMPT_EVENT_CHAIN_INVALID", self.active_error())

    def test_watch_requires_current_source_generation_and_lease(self) -> None:
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=501,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=DEVELOPMENT_ENDPOINT,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.source.payload_sha256,
            expected_version=0,
            now="2026-08-24T10:00:01Z",
        )
        watch = self.store.connection.execute(
            "SELECT watch_key FROM coordination_terminal_watches WHERE issue_number=501"
        ).fetchone()
        self.reserve("terminal_watch", str(watch["watch_key"]))
        self.assertIsNone(self.active_error())
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=501,
            payload={"number": 501, "title": "Audit", "body": "new source"},
            source_updated_at="2026-08-24T09:02:00Z",
            fetched_at="2026-08-24T09:02:01Z",
        )
        self.assertEqual("ACTIVE_ATTEMPT_TARGET_STALE", self.active_error())

    def test_hosted_scope_source_authority_and_claim_are_verified(self) -> None:
        control = object.__new__(HostedOperationControl)
        control.store = self.store
        control.connection = self.store.connection
        control._create_schema()
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
        cursor = self.store.connection.execute(
            """
            INSERT INTO hosted_operations(
                idempotency_key,repository,object_kind,issue_number,
                source_payload_sha256,provider,target_kind,target_key,
                operation_kind,authority_comment_id,authority_body_sha256,
                scope_sha256,scope_json,recipient_session_id,sre_units,
                blocked_by_issue_number,state,created_at,updated_at
            ) VALUES ('hosted-audit',?,'issue',501,?,'google_cloud',
                      'gcp_project_inventory','twinfinity-staging','READ_METADATA',
                      17,?,?,?,?,0,NULL,'PREPARED',?,?)
            """,
            (
                REPOSITORY,
                self.source.payload_sha256,
                "8" * 64,
                hashlib.sha256(scope_json.encode()).hexdigest(),
                scope_json,
                SRE_ENDPOINT,
                "2026-08-24T10:00:01Z",
                "2026-08-24T10:00:01Z",
            ),
        )
        operation_id = int(cursor.lastrowid)
        self.reserve("hosted_operation", str(operation_id), role="sre")
        self.assertIsNone(self.active_error())

        self.store.connection.execute(
            "UPDATE hosted_operations SET scope_sha256=? WHERE id=?",
            ("0" * 64, operation_id),
        )
        self.assertEqual("ACTIVE_ATTEMPT_TARGET_AUTHORITY_INVALID", self.active_error())


if __name__ == "__main__":
    unittest.main()
