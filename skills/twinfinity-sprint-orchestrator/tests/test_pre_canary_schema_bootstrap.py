from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path[:0] = [str(SCRIPTS), str(ROOT / "tests")]

import pre_canary_schema_bootstrap as bootstrap  # noqa: E402
from approval_ledger import (  # noqa: E402
    LEGACY_SCHEMA,
    SEMANTIC_CONTRACT_V2_ACTIVATION_EVENT,
    SEMANTIC_CONTRACT_V2_ACTIVATION_REQUEST_SCHEMA,
    SEMANTIC_CONTRACT_V2_ACTIVATION_SCHEMA_SENTINEL_SHA256,
    ensure_schema as ensure_approval_schema,
    preview_semantic_contract_v2_activation,
)
from coordination_store import canonical_json, digest_json  # noqa: E402
from hosted_operation_control import HostedOperationControl  # noqa: E402
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import ensure_schema as ensure_readiness_schema  # noqa: E402
from role_executor_broker import ensure_broker_schema  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"


def build_predecessor(
    root: Path,
    mutation: object | None = None,
) -> Path:
    database = root / "state.sqlite3"
    control = HostedOperationControl(database)
    try:
        ensure_approval_schema(control.connection)
        ensure_readiness_schema(control.connection)
        ensure_pull_buffer_schema(control.connection)
        apply_reviewed_current_endpoint_catalog(
            control.connection,
            ROOT,
            operation_key="pre-canary-schema-bootstrap-tests",
        )
        control.store.capacity_policy(
            REPOSITORY, now="2026-09-04T12:00:00Z"
        )
        ensure_broker_schema(control.connection)
        for table in bootstrap.MISSING_TABLES:
            control.connection.execute(f'DROP TABLE "{table}"')
        if mutation is not None:
            mutation(control.connection)
        control.connection.execute(
            "SELECT COUNT(*) FROM sqlite_master"
        ).fetchone()
        checkpoint = tuple(
            control.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        )
        if checkpoint != (0, 0, 0):
            raise AssertionError(checkpoint)
    finally:
        control.close()
    database.chmod(0o600)
    if database.read_bytes()[18:20] != b"\x02\x02":
        raise AssertionError("fixture is not WAL")
    for suffix in ("-wal", "-shm", "-journal"):
        if Path(str(database) + suffix).exists():
            raise AssertionError(f"fixture sidecar remains: {suffix}")
    return database


def request_for(database: Path) -> dict:
    return {
        "schema": bootstrap.REQUEST_SCHEMA,
        "repository": bootstrap.REPOSITORY,
        "accepted_harness_main_sha": "1" * 40,
        "database_identity": bootstrap.database_identity(database),
        "stopped_state_evidence_sha256": "2" * 64,
        "predecessor_schema_sentinel_sha256": (
            bootstrap.PREDECESSOR_SCHEMA_SENTINEL_SHA256
        ),
        "broker_schema_manifest_sha256": (
            bootstrap.BROKER_QUARANTINE_SCHEMA_MANIFEST_SHA256
        ),
        "broker_row_counts": {
            table: 0 for table in bootstrap.BROKER_QUARANTINE_TABLES
        },
        "missing_tables": list(bootstrap.MISSING_TABLES),
        "v1_authority_sha256": "3" * 64,
        "v1_activated_at": "2026-09-04T20:00:00Z",
        "operation_key": "issue-199-test-bootstrap",
        "rollback_evidence_sha256": "4" * 64,
    }


def immutable_connection(database: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{database.as_uri()}?mode=ro&immutable=1",
        uri=True,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


class PreCanarySchemaBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = build_predecessor(self.root)
        self.request = request_for(self.database)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def preview(self) -> dict:
        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database):
            return bootstrap.preview_schema_bootstrap(self.request)

    def apply(self, preview: dict | None = None) -> dict:
        if preview is None:
            preview = self.preview()
        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database):
            return bootstrap.apply_schema_bootstrap(
                self.request,
                expected_request_sha256=preview["request_sha256"],
                expected_preview_sha256=preview["preview_sha256"],
            )

    def test_preview_apply_and_exact_replay_are_closed_and_atomic(self) -> None:
        before_bytes = self.database.read_bytes()
        before_namespace = sorted(entry.name for entry in self.root.iterdir())
        first_preview = self.preview()
        second_preview = self.preview()
        self.assertEqual(first_preview, second_preview)
        self.assertEqual(before_bytes, self.database.read_bytes())
        self.assertEqual(
            before_namespace,
            sorted(entry.name for entry in self.root.iterdir()),
        )

        receipt = self.apply(first_preview)
        self.assertEqual("APPLIED", receipt["state"])
        self.assertEqual(list(bootstrap.MISSING_TABLES), receipt["created_tables"])
        self.assertEqual(81, receipt["result_table_count"])
        self.assertEqual(first_preview["target_pointer"], receipt["result_pointer"])
        connection = immutable_connection(self.database)
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(81, len(tables))
            self.assertEqual(
                first_preview["target_pointer"],
                dict(connection.execute(
                    "SELECT singleton,schema,authority_sha256,activated_at "
                    "FROM approval_semantic_contract_current"
                ).fetchone()),
            )
            events = connection.execute(
                "SELECT event_type,entity_key,payload_sha256,created_at "
                "FROM approval_events WHERE event_type=?",
                (bootstrap.EVENT_TYPE,),
            ).fetchall()
            self.assertEqual(1, len(events))
            self.assertEqual(receipt["receipt_sha256"], events[0]["payload_sha256"])
            for table in bootstrap.BROKER_QUARANTINE_TABLES:
                self.assertEqual(
                    0,
                    connection.execute(
                        f'SELECT COUNT(*) FROM "{table}"'
                    ).fetchone()[0],
                )
        finally:
            connection.close()

        applied_bytes = self.database.read_bytes()
        applied_namespace = sorted(entry.name for entry in self.root.iterdir())
        self.assertEqual(receipt, self.apply(first_preview))
        self.assertEqual(first_preview, self.preview())
        self.assertEqual(applied_bytes, self.database.read_bytes())
        self.assertEqual(
            applied_namespace,
            sorted(entry.name for entry in self.root.iterdir()),
        )

    def test_every_private_apply_failpoint_rolls_back_the_complete_effect(self) -> None:
        for failpoint in bootstrap.APPLY_FAILPOINTS:
            with self.subTest(failpoint=failpoint):
                with tempfile.TemporaryDirectory() as name:
                    database = build_predecessor(Path(name))
                    request = request_for(database)
                    before = database.read_bytes()
                    namespace = sorted(
                        entry.name for entry in database.parent.iterdir()
                    )
                    with patch.object(bootstrap, "DEFAULT_DATABASE", database):
                        preview = bootstrap.preview_schema_bootstrap(request)

                        def stop(step: str) -> None:
                            if step == failpoint:
                                raise bootstrap.BootstrapHold(
                                    "PRE_CANARY_BOOTSTRAP_SYNTHETIC_FAILPOINT"
                                )

                        with patch.object(
                            bootstrap, "_apply_failpoint", side_effect=stop
                        ):
                            with self.assertRaisesRegex(
                                bootstrap.BootstrapHold,
                                "PRE_CANARY_BOOTSTRAP_SYNTHETIC_FAILPOINT",
                            ):
                                bootstrap.apply_schema_bootstrap(
                                    request,
                                    expected_request_sha256=(
                                        preview["request_sha256"]
                                    ),
                                    expected_preview_sha256=(
                                        preview["preview_sha256"]
                                    ),
                                )
                    self.assertEqual(before, database.read_bytes())
                    self.assertEqual(
                        namespace,
                        sorted(entry.name for entry in database.parent.iterdir()),
                    )

    def test_schema_broker_and_pointer_negative_matrix_is_zero_write(self) -> None:
        def partial(connection: sqlite3.Connection) -> None:
            connection.execute("DROP TABLE role_executor_broker_events")

        def malformed(connection: sqlite3.Connection) -> None:
            connection.execute("DROP TRIGGER role_executor_broker_event_delete")

        def nonempty(connection: sqlite3.Connection) -> None:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "INSERT INTO role_executor_broker_events("
                "attempt_id,to_state,to_version,created_at) VALUES (?,?,?,?)",
                ("synthetic-attempt", "HOLD", 1, "2026-09-04T20:00:00Z"),
            )
            connection.execute("PRAGMA foreign_keys=ON")

        def unknown(connection: sqlite3.Connection) -> None:
            connection.execute("CREATE TABLE unknown_canary_state(id INTEGER)")

        def another_missing(connection: sqlite3.Connection) -> None:
            connection.execute("DROP TABLE approval_current")

        def conflicting_pointer(connection: sqlite3.Connection) -> None:
            for item in bootstrap._canonical_missing_objects():
                connection.execute(item["sql"])
            connection.execute(
                "INSERT INTO approval_semantic_contract_current "
                "VALUES (1,?,?,?)",
                (LEGACY_SCHEMA, "9" * 64, "2026-09-04T19:00:00Z"),
            )

        cases = (
            (partial, "PRE_CANARY_BOOTSTRAP_BROKER_PARTIAL"),
            (malformed, "PRE_CANARY_BOOTSTRAP_BROKER_SCHEMA_DRIFT"),
            (nonempty, "PRE_CANARY_BOOTSTRAP_BROKER_NONEMPTY"),
            (unknown, "PRE_CANARY_BOOTSTRAP_SCHEMA_SET_DRIFT"),
            (another_missing, "PRE_CANARY_BOOTSTRAP_SCHEMA_SET_DRIFT"),
            (conflicting_pointer, "PRE_CANARY_BOOTSTRAP_POINTER_CONFLICT"),
        )
        for mutation, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as name:
                database = build_predecessor(Path(name), mutation)
                request = request_for(database)
                before = database.read_bytes()
                namespace = sorted(entry.name for entry in database.parent.iterdir())
                with patch.object(bootstrap, "DEFAULT_DATABASE", database):
                    with self.assertRaisesRegex(bootstrap.BootstrapHold, error):
                        bootstrap.preview_schema_bootstrap(request)
                self.assertEqual(before, database.read_bytes())
                self.assertEqual(
                    namespace,
                    sorted(entry.name for entry in database.parent.iterdir()),
                )

    def test_request_preview_and_database_identity_drift_fail_before_write(self) -> None:
        before = self.database.read_bytes()
        request = json.loads(canonical_json(self.request))
        request["database_identity"]["sha256"] = "f" * 64
        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database):
            with self.assertRaisesRegex(
                bootstrap.BootstrapHold,
                "PRE_CANARY_BOOTSTRAP_DATABASE_IDENTITY_DRIFT",
            ):
                bootstrap.preview_schema_bootstrap(request)
        self.assertEqual(before, self.database.read_bytes())

        preview = self.preview()
        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database):
            with self.assertRaisesRegex(
                bootstrap.BootstrapHold,
                "PRE_CANARY_BOOTSTRAP_REQUEST_DIGEST_DRIFT",
            ):
                bootstrap.apply_schema_bootstrap(
                    self.request,
                    expected_request_sha256="0" * 64,
                    expected_preview_sha256=preview["preview_sha256"],
                )
            with self.assertRaisesRegex(
                bootstrap.BootstrapHold,
                "PRE_CANARY_BOOTSTRAP_PREVIEW_DIGEST_DRIFT",
            ):
                bootstrap.apply_schema_bootstrap(
                    self.request,
                    expected_request_sha256=preview["request_sha256"],
                    expected_preview_sha256="0" * 64,
                )
        self.assertEqual(before, self.database.read_bytes())

    def test_path_replacement_race_is_rejected_by_pinned_identity(self) -> None:
        preview = self.preview()
        original = self.root / "anchored-original.sqlite3"

        def replace_path(step: str) -> None:
            if step == "before_writable_open":
                self.database.rename(original)
                shutil.copy2(original, self.database)
                self.database.chmod(0o600)

        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database), patch.object(
            bootstrap, "_apply_failpoint", side_effect=replace_path
        ):
            with self.assertRaisesRegex(
                bootstrap.BootstrapHold,
                "(?:DATABASE_IDENTITY_DRIFT|PINNED_SQLITE_IDENTITY_INVALID)",
            ):
                bootstrap.apply_schema_bootstrap(
                    self.request,
                    expected_request_sha256=preview["request_sha256"],
                    expected_preview_sha256=preview["preview_sha256"],
                )
        connection = immutable_connection(self.database)
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(79, len(tables))
        finally:
            connection.close()

    def test_commit_boundary_anchor_failure_rolls_back_complete_effect(self) -> None:
        preview = self.preview()
        before = self.database.read_bytes()
        before_namespace = sorted(entry.name for entry in self.root.iterdir())
        require_anchor = bootstrap._require_anchor
        anchor_calls = 0

        def fail_final_anchor(*args: object, **kwargs: object) -> None:
            nonlocal anchor_calls
            anchor_calls += 1
            require_anchor(*args, **kwargs)
            if anchor_calls == 3:
                raise bootstrap.BootstrapHold(
                    "PRE_CANARY_BOOTSTRAP_DATABASE_IDENTITY_DRIFT"
                )

        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database), patch.object(
            bootstrap, "_require_anchor", side_effect=fail_final_anchor
        ):
            with self.assertRaisesRegex(
                bootstrap.BootstrapHold,
                "PRE_CANARY_BOOTSTRAP_DATABASE_IDENTITY_DRIFT",
            ):
                bootstrap.apply_schema_bootstrap(
                    self.request,
                    expected_request_sha256=preview["request_sha256"],
                    expected_preview_sha256=preview["preview_sha256"],
                )
        self.assertEqual(3, anchor_calls)
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(
            before_namespace,
            sorted(entry.name for entry in self.root.iterdir()),
        )

    def test_commit_boundary_path_replacement_is_rejected_before_commit(self) -> None:
        preview = self.preview()
        before = self.database.read_bytes()
        displaced = self.root / "commit-boundary-original.sqlite3"

        def replace_path(step: str) -> None:
            if step == "before_commit":
                self.database.rename(displaced)
                shutil.copy2(displaced, self.database)
                self.database.chmod(0o600)

        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database), patch.object(
            bootstrap, "_apply_failpoint", side_effect=replace_path
        ):
            with self.assertRaisesRegex(
                bootstrap.BootstrapHold,
                "PRE_CANARY_BOOTSTRAP_DATABASE_IDENTITY_DRIFT",
            ):
                bootstrap.apply_schema_bootstrap(
                    self.request,
                    expected_request_sha256=preview["request_sha256"],
                    expected_preview_sha256=preview["preview_sha256"],
                )
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before, displaced.read_bytes())
        for database in (self.database, displaced):
            connection = immutable_connection(database)
            try:
                table_count = connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                ).fetchone()[0]
                event_count = connection.execute(
                    "SELECT COUNT(*) FROM approval_events WHERE event_type=?",
                    (bootstrap.EVENT_TYPE,),
                ).fetchone()[0]
                self.assertEqual(79, table_count)
                self.assertEqual(0, event_count)
            finally:
                connection.close()

    def test_result_replay_rejects_complete_new_table_object_drift(self) -> None:
        cases = (
            (
                "extra-approval-index",
                ("CREATE INDEX synthetic_approval_index ON "
                 "approval_semantic_contract_current(authority_sha256)",),
            ),
            (
                "extra-quarantine-index",
                ("CREATE INDEX synthetic_quarantine_index ON "
                 "portfolio_ready_quarantines(repository)",),
            ),
            (
                "extra-approval-trigger",
                ("CREATE TRIGGER synthetic_approval_trigger AFTER INSERT ON "
                 "approval_semantic_contract_current BEGIN SELECT 1; END",),
            ),
            (
                "extra-quarantine-trigger",
                ("CREATE TRIGGER synthetic_quarantine_trigger AFTER INSERT ON "
                 "portfolio_ready_quarantines BEGIN SELECT 1; END",),
            ),
            (
                "accepted-trigger-schema-drift",
                (
                    "DROP TRIGGER approval_semantic_contract_no_delete",
                    "CREATE TRIGGER approval_semantic_contract_no_delete "
                    "BEFORE DELETE ON approval_semantic_contract_current "
                    "BEGIN SELECT RAISE(ABORT, 'SYNTHETIC_DRIFT'); END",
                ),
            ),
        )
        for name, statements in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                database = build_predecessor(Path(root))
                request = request_for(database)
                with patch.object(bootstrap, "DEFAULT_DATABASE", database):
                    preview = bootstrap.preview_schema_bootstrap(request)
                    bootstrap.apply_schema_bootstrap(
                        request,
                        expected_request_sha256=preview["request_sha256"],
                        expected_preview_sha256=preview["preview_sha256"],
                    )
                connection = sqlite3.connect(database, isolation_level=None)
                try:
                    for statement in statements:
                        connection.execute(statement)
                    checkpoint = tuple(
                        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    )
                    self.assertEqual((0, 0, 0), checkpoint)
                finally:
                    connection.close()
                database.chmod(0o600)
                before = database.read_bytes()
                before_namespace = sorted(
                    entry.name for entry in database.parent.iterdir()
                )
                with patch.object(bootstrap, "DEFAULT_DATABASE", database):
                    with self.assertRaisesRegex(
                        bootstrap.BootstrapHold,
                        "PRE_CANARY_BOOTSTRAP_RESULT_SCHEMA_DRIFT",
                    ):
                        bootstrap.preview_schema_bootstrap(request)
                self.assertEqual(before, database.read_bytes())
                self.assertEqual(
                    before_namespace,
                    sorted(entry.name for entry in database.parent.iterdir()),
                )

    def test_bootstrap_result_is_consumable_by_strict_v2_preview_only(self) -> None:
        receipt = self.apply()
        v2_request = {
            "schema": SEMANTIC_CONTRACT_V2_ACTIVATION_REQUEST_SCHEMA,
            "repository": bootstrap.REPOSITORY,
            "accepted_harness_main_sha": "5" * 40,
            "schema_sentinel_sha256": (
                SEMANTIC_CONTRACT_V2_ACTIVATION_SCHEMA_SENTINEL_SHA256
            ),
            "expected_v1_pointer": receipt["result_pointer"],
            "v2_authority_sha256": "6" * 64,
            "legacy_authority_inventory_sha256": "7" * 64,
            "stopped_state_evidence_sha256": "8" * 64,
            "operation_key": "issue-193-after-bootstrap",
        }
        preview = preview_semantic_contract_v2_activation(
            self.database, v2_request
        )
        self.assertEqual("READY_OR_EXACT_REPLAY", preview["state"])
        connection = immutable_connection(self.database)
        try:
            pointer = dict(connection.execute(
                "SELECT singleton,schema,authority_sha256,activated_at "
                "FROM approval_semantic_contract_current"
            ).fetchone())
            self.assertEqual(receipt["result_pointer"], pointer)
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM approval_events WHERE event_type=?",
                    (SEMANTIC_CONTRACT_V2_ACTIVATION_EVENT,),
                ).fetchone()[0],
            )
        finally:
            connection.close()

    def test_request_file_is_canonical_and_cli_has_no_database_selector(self) -> None:
        request_path = self.root / "request.json"
        request_path.write_text(canonical_json(self.request), encoding="utf-8")
        request_path.chmod(0o600)
        self.assertEqual(self.request, bootstrap.load_request(request_path))
        with patch.object(bootstrap, "DEFAULT_DATABASE", self.database):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    0,
                    bootstrap.main(["preview", "--request", str(request_path)]),
                )
            self.assertEqual(bootstrap.PREVIEW_SCHEMA, json.loads(output.getvalue())["schema"])
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                bootstrap.main([
                    "preview",
                    "--request",
                    str(request_path),
                    "--database",
                    str(self.database),
                ])
        request_path.write_text(
            canonical_json(self.request) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            bootstrap.BootstrapHold, "PRE_CANARY_BOOTSTRAP_REQUEST_INVALID"
        ):
            bootstrap.load_request(request_path)

    def test_source_sentinels_are_derived_from_accepted_definitions(self) -> None:
        bootstrap._require_source_sentinels()
        objects = bootstrap._canonical_missing_objects()
        manifest = [
            {
                "type": item["type"],
                "name": item["name"],
                "table": item["table"],
                "sql": bootstrap._normalized_schema_sql(item["sql"]),
            }
            for item in objects
        ]
        self.assertEqual(
            bootstrap.MISSING_SCHEMA_OBJECT_MANIFEST_SHA256,
            digest_json(manifest),
        )
        self.assertEqual(
            bootstrap.PREDECESSOR_SCHEMA_SENTINEL_SHA256,
            digest_json(bootstrap._predecessor_sentinel()),
        )
        self.assertEqual(
            bootstrap.RESULT_SCHEMA_SENTINEL_SHA256,
            digest_json(bootstrap._result_sentinel()),
        )


if __name__ == "__main__":
    unittest.main()
