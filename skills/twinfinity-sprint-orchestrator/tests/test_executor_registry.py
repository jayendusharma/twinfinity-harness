from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from archive_readiness_audit import archive_readiness  # noqa: E402
import run_role_executor  # noqa: E402
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    digest_json,
)
from executor_registry import (  # noqa: E402
    AttemptLineage,
    RegistryError,
    SystemdUnitEvidence,
    attempt_lineage_for_target,
    attempt_schema_is_current,
    attempts_support_hosted_operation,
    current_endpoint,
    ensure_executor_registry_schema,
    identity_role,
    load_legacy_aliases,
    load_registry_config,
    open_registry_database,
    probe_systemd_unit,
    reserve_attempt,
    recover_stale_active_attempts,
    require_current_endpoint_identity,
    stable_systemd_unit,
    transition_attempt,
)
from reconcile_routing_artifacts import (  # noqa: E402
    _legacy_occurrences,
    _verify_or_insert_endpoint,
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
    replay_applied_change,
    rollback_change,
)
from run_role_executor import build_fresh_command, execute_role  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    reviewed_current_endpoint_catalog,
    reviewed_planner_rotation_catalog,
)


CONFIG = ROOT / "tests" / "fixtures" / "twinfinity-executor-registry-v4.toml"
ALIASES = ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
REPOSITORY = "twinfinityai/twinfinityapp"
DEVELOPMENT_UUID = "22222222-2222-4222-8222-222222222222"
SRE_UUID = "33333333-3333-4333-8333-333333333333"
DEVELOPMENT_ENDPOINT = "role.development.v4"
SRE_ENDPOINT = "role.sre.v4"
PLANNER_ENDPOINT = "role.planner.v2"
LEASE = "5" * 64
INVOCATION_ID = "a" * 32
UNIT = stable_systemd_unit("development", "message", "11")
CONTROL_GROUP = f"/user.slice/user-1000.slice/user@1000.service/app.slice/{UNIT}"


def systemd_evidence(
    *,
    invocation_id: str = INVOCATION_ID,
    load_state: str = "loaded",
    active_state: str = "active",
    sub_state: str = "running",
    result: str = "success",
    role: str = "development",
    target_kind: str = "message",
    target_key: str = "11",
    unit: str | None = None,
    control_group: str | None = None,
) -> SystemdUnitEvidence:
    resolved_unit = unit or stable_systemd_unit(role, target_kind, target_key)
    resolved_control_group = control_group or (
        f"/user.slice/user-1000.slice/user@1000.service/app.slice/{resolved_unit}"
    )
    return SystemdUnitEvidence(
        unit=resolved_unit,
        load_state=load_state,
        active_state=active_state,
        sub_state=sub_state,
        invocation_id=invocation_id,
        control_group=resolved_control_group,
        result=result,
    )


class _ImmediateProcess:
    pid = 4321

    def poll(self):
        return 0


class _TerminableProcess:
    pid = 9876

    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return -15

    def kill(self):
        self.terminated = True


class ExecutorRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        fixture_root = Path(self.temp.name) / "canonical-operational-inputs"
        fixture_root.mkdir()
        planner_goal = fixture_root / "product-planner-goal.md"
        planner_goal.write_text(
            "Use only current role endpoints.\n",
            encoding="utf-8",
        )
        agents = fixture_root / "AGENTS.md"
        agents.write_text(
            "Current role endpoints are the only executable routing inputs.\n",
            encoding="utf-8",
        )
        self.enterContext(
            patch(
                "archive_readiness_audit.CANONICAL_PLANNER_GOAL",
                planner_goal,
            )
        )
        self.enterContext(
            patch("archive_readiness_audit.CANONICAL_AGENTS", agents)
        )
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.store = CoordinationStore(root / "state.sqlite3")
        self.codex_home = Path(self.temp.name) / "codex-home"
        self._install_role_profiles(self.codex_home)
        self.environment = patch.dict(os.environ, {"CODEX_HOME": str(self.codex_home)})
        self.environment.start()
        self.config = load_registry_config(CONFIG)
        self.registry_loader = patch(
            "executor_registry.load_registry_config", return_value=self.config
        )
        self.runner_registry_loader = patch(
            "run_role_executor.load_registry_config", return_value=self.config
        )
        self.readiness_registry_loader = patch(
            "archive_readiness_audit.load_registry_config", return_value=self.config
        )
        self.registry_loader.start()
        self.runner_registry_loader.start()
        self.readiness_registry_loader.start()
        self.aliases, self.alias_sha = load_legacy_alias_fixture(ALIASES)

    def tearDown(self) -> None:
        self.readiness_registry_loader.stop()
        self.runner_registry_loader.stop()
        self.registry_loader.stop()
        self.environment.stop()
        self.store.close()
        self.temp.cleanup()

    def test_systemd_probe_reads_exact_attempt_cgroup_limits(self) -> None:
        fields = {
            "Id": UNIT,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "InvocationID": INVOCATION_ID,
            "ControlGroup": CONTROL_GROUP,
            "Result": "success",
            "MemoryMax": "2147483648",
            "TasksMax": "64",
            "RuntimeMaxUSec": "11min",
            "CPUQuotaPerSecUSec": "1s",
        }

        def runner(_command, **_kwargs):
            return types.SimpleNamespace(
                returncode=0,
                stdout="".join(f"{key}={value}\n" for key, value in fields.items()),
            )

        evidence = probe_systemd_unit(UNIT, runner=runner)
        self.assertEqual(
            ("2147483648", "64", "11min", "1s"),
            (
                evidence.memory_max,
                evidence.tasks_max,
                evidence.runtime_max_usec,
                evidence.cpu_quota_per_sec_usec,
            ),
        )
        missing = dict(fields)
        missing.pop("MemoryMax")
        with self.assertRaisesRegex(RegistryError, "SYSTEMD_EVIDENCE_AMBIGUOUS"):
            probe_systemd_unit(
                UNIT,
                runner=lambda _command, **_kwargs: types.SimpleNamespace(
                    returncode=0,
                    stdout="".join(
                        f"{key}={value}\n" for key, value in missing.items()
                    ),
                ),
            )

    @staticmethod
    def no_lineage(_connection: sqlite3.Connection) -> None:
        return None

    def migrate(self, operation_key: str = "test-migration") -> dict:
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        return apply_plan(
            self.store.connection,
            plan=plan,
            operation_key=operation_key,
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:00Z",
        )

    def readiness(self, **kwargs) -> dict:
        return archive_readiness(
            self.store.connection,
            legacy_alias_path=ALIASES,
            **kwargs,
        )

    def snapshot(self, *, body: str = "No legacy route", comments=None):
        payload = {"number": 92, "title": "Endpoint routing", "body": body}
        if comments is not None:
            payload["comments"] = comments
        return self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload=payload,
            source_updated_at="2026-08-24T09:00:00Z",
            fetched_at="2026-08-24T09:00:01Z",
        )

    def planner_notice(
        self, *, repository: str, issue_number: int, idempotency_key: str
    ) -> int:
        source = self.store.ingest_snapshot(
            repository=repository,
            object_kind="issue",
            object_number=issue_number,
            payload={"number": issue_number, "title": idempotency_key},
            source_updated_at="2026-08-24T09:00:00Z",
            fetched_at="2026-08-24T09:00:01Z",
        )
        return self.store.enqueue_message(
            idempotency_key=idempotency_key,
            recipient_session_id=PLANNER_ENDPOINT,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": repository,
                    "object_kind": "issue",
                    "object_number": issue_number,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Planner repository fence",
                "summary": "Exercise one repository-scoped Planner attempt.",
                "evidence": {},
            },
            now="2026-08-24T10:00:00Z",
        )

    def launched_attempt(self, *, running: bool = True):
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="11",
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        attempt = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=UNIT,
            systemd_invocation_id=INVOCATION_ID,
            systemd_control_group=CONTROL_GROUP,
            now="2026-08-24T10:00:02Z",
        )
        if running:
            attempt = transition_attempt(
                self.store.connection,
                attempt_id=attempt["attempt_id"],
                token=token,
                expected_version=attempt["version"],
                new_state="RUNNING",
                process_id=4321,
                now="2026-08-24T10:00:03Z",
            )
        return attempt, token

    def test_strict_toml_rejects_unknown_keys_and_profile_aliasing(self) -> None:
        raw = CONFIG.read_text(encoding="utf-8")
        unknown = Path(self.temp.name) / "unknown.toml"
        unknown.write_text(raw + "\nunknown = true\n", encoding="utf-8")
        with self.assertRaisesRegex(RegistryError, "REGISTRY_CONFIG_.*SCHEMA_INVALID"):
            load_registry_config(unknown)

        aliased = Path(self.temp.name) / "aliased.toml"
        aliased.write_text(
            raw.replace('executor_profile = "sre"', 'executor_profile = "development"'),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            RegistryError, "REGISTRY_(?:CONFIG_ROLE_INVALID|PROFILE_NOT_EXCLUSIVE)"
        ):
            load_registry_config(aliased)

    def _install_role_profiles(self, codex_home: Path) -> None:
        codex_home.mkdir(exist_ok=True)
        for profile in (
            "twinfinity-planner-v2",
            "twinfinity-development-v3",
            "twinfinity-development-v4",
            "twinfinity-sre-v3",
            "twinfinity-sre-v4",
        ):
            source = ROOT / "references" / f"{profile}.config.toml"
            (codex_home / f"{profile}.config.toml").write_bytes(source.read_bytes())

    def test_registry_profile_validation_rejects_missing_and_mismatched_install(self) -> None:
        missing_home = Path(self.temp.name) / "missing-codex-home"
        missing_home.mkdir()
        with self.assertRaisesRegex(RegistryError, "REGISTRY_PROFILE_MISSING"):
            load_registry_config(CONFIG, codex_home=missing_home)

        mismatched_home = Path(self.temp.name) / "mismatched-codex-home"
        self._install_role_profiles(mismatched_home)
        development = mismatched_home / "twinfinity-development-v4.config.toml"
        development.write_bytes(development.read_bytes() + b"\n")
        with self.assertRaisesRegex(RegistryError, "REGISTRY_PROFILE_DIGEST_MISMATCH"):
            load_registry_config(CONFIG, codex_home=mismatched_home)

    def test_registry_rejects_command_profile_inconsistency_and_bypass_vectors(self) -> None:
        raw = CONFIG.read_text(encoding="utf-8")
        variants = {
            "wrong-profile": raw.replace(
                '  "twinfinity-development",', '  "twinfinity-sre",', 1
            ),
            "resume": raw.replace('  "--json",', '  "resume",\n  "--json",', 1),
            "uuid": raw.replace(
                '  "--json",',
                '  "22222222-2222-4222-8222-222222222222",\n  "--json",',
                1,
            ),
            "bypass": raw.replace(
                '  "--json",',
                '  "--dangerously-bypass-approvals-and-sandbox",\n  "--json",',
                1,
            ),
        }
        for name, contents in variants.items():
            candidate = Path(self.temp.name) / f"{name}.toml"
            candidate.write_text(contents, encoding="utf-8")
            with self.subTest(name=name), self.assertRaisesRegex(
                RegistryError,
                "REGISTRY_CONFIG_(?:COMMAND_INVALID|COMMAND_PROFILE_MISMATCH)",
            ):
                load_registry_config(candidate)

    def test_production_and_fixture_alias_schemas_are_independently_strict(self) -> None:
        production = load_legacy_aliases()
        fixture = load_legacy_aliases(ALIASES)
        self.assertEqual({"planner", "development", "sre"}, set(production.aliases.values()))
        self.assertEqual({"planner", "development", "sre"}, set(fixture.aliases.values()))
        self.assertEqual(3, len(production.aliases))
        self.assertEqual(3, len(fixture.aliases))
        self.assertTrue(set(production.aliases).isdisjoint(fixture.aliases))
        invalid = Path(self.temp.name) / "invalid-production-aliases.json"
        invalid_production = [
            {"alias": alias, "role": role}
            for alias, role in production.aliases.items()
        ]
        invalid_production[0]["extra"] = True
        invalid.write_text(
            json.dumps({"schema_version": 1, "aliases": invalid_production}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RegistryError, "LEGACY_ALIAS_FILE_SCHEMA_INVALID"):
            load_legacy_aliases(invalid)
        invalid_fixture = Path(self.temp.name) / "invalid-fixture-aliases.json"
        invalid_fixture.write_text(
            json.dumps({"schema_version": 2, "aliases": self.aliases}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RegistryError, "LEGACY_ALIAS_FILE_SCHEMA_INVALID"):
            load_legacy_aliases(invalid_fixture)

    def test_dry_run_plan_does_not_initialize_registry_schema(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            plan = build_plan(
                connection,
                self.config,
                self.aliases,
                alias_fixture_sha256=self.alias_sha,
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            connection.close()
        self.assertEqual(set(), tables)
        self.assertEqual(3, len(plan["pointer_changes"]))

    def test_endpoint_identity_never_fails_open_or_accepts_syntax_only_ids(self) -> None:
        ensure_executor_registry_schema(self.store.connection)
        self.assertIsNone(
            identity_role(self.store.connection, "role.development.v999")
        )
        self.store.connection.execute(
            """
            INSERT INTO executor_role_endpoints(
                endpoint_id, role, version, executor_profile, codex_profile,
                config_sha256, config_json, command_json, created_at
            ) VALUES (
                'role.development.v999', 'development', 999, 'development',
                'twinfinity-development', ?, '{}', '[]',
                '2026-08-24T08:59:59Z'
            )
            """,
            ("f" * 64,),
        )
        self.assertIsNone(
            identity_role(self.store.connection, "role.development.v999")
        )
        with self.assertRaisesRegex(
            RegistryError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
        ):
            require_current_endpoint_identity(
                self.store.connection,
                DEVELOPMENT_ENDPOINT,
                expected_role="development",
            )

        endpoint = self.config.roles["development"]
        _verify_or_insert_endpoint(
            self.store.connection, endpoint.payload, "2026-08-24T09:00:00Z"
        )
        self.store.connection.execute(
            """
            INSERT INTO executor_role_endpoint_current(
                role, endpoint_id, pointer_version, updated_at
            ) VALUES ('development', ?, 1, '2026-08-24T09:00:01Z')
            """,
            (DEVELOPMENT_ENDPOINT,),
        )
        with self.assertRaisesRegex(
            RegistryError, "REGISTRY_CURRENT_POINTER_SET_INCOMPLETE"
        ):
            current_endpoint(self.store.connection, "development")

    def test_temporary_reviewed_planner_rotation_catalog_is_complete(self) -> None:
        self.migrate("planner-rotation-fixture-base")
        root = Path(__file__).resolve().parents[1]
        with reviewed_planner_rotation_catalog(
            root, Path(self.temp.name)
        ) as rotated_config:
            self.assertEqual(
                "role.planner.v3", rotated_config.roles["planner"].endpoint_id
            )
            self.assertEqual(
                {
                    "role.planner.v1",
                    "role.planner.v2",
                    "role.planner.v3",
                    "role.development.v3",
                    "role.development.v4",
                    "role.development.v5",
                    "role.sre.v3",
                    "role.sre.v4",
                    "role.sre.v5",
                },
                set(rotated_config.endpoints),
            )
            rotation_only = replace(
                rotated_config,
                roles={
                    "planner": rotated_config.roles["planner"],
                    "development": self.config.roles["development"],
                    "sre": self.config.roles["sre"],
                },
            )
            plan = build_plan(
                self.store.connection,
                rotation_only,
                self.aliases,
                alias_fixture_sha256=self.alias_sha,
            )
            apply_plan(
                self.store.connection,
                plan=plan,
                operation_key="planner-rotation-fixture-v3",
                expected_plan_sha256=plan["plan_sha256"],
                now="2026-08-24T09:00:02Z",
            )
            self.assertEqual(
                "role.planner.v3",
                current_endpoint(self.store.connection, "planner")["endpoint_id"],
            )
            self.assertEqual(
                "planner", identity_role(self.store.connection, "role.planner.v2")
            )
            self.assertIsNone(
                identity_role(self.store.connection, "role.planner.v999")
            )

    def test_temporary_reviewed_current_catalog_is_complete(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with reviewed_current_endpoint_catalog(
            root, Path(self.temp.name)
        ) as current_config:
            self.assertEqual(
                {
                    "planner": "role.planner.v2",
                    "development": "role.development.v5",
                    "sre": "role.sre.v5",
                },
                {
                    role: endpoint.endpoint_id
                    for role, endpoint in current_config.roles.items()
                },
            )
            self.assertEqual(
                {
                    "role.planner.v2",
                    "role.development.v3",
                    "role.development.v4",
                    "role.development.v5",
                    "role.sre.v3",
                    "role.sre.v4",
                    "role.sre.v5",
                },
                set(current_config.endpoints),
            )
            for role in ("development", "sre"):
                endpoint = current_config.roles[role]
                self.assertEqual("readiness/v1", endpoint.execution_protocol)
                self.assertEqual(("coordination.notice",), endpoint.allowed_topics)

    def test_read_only_registry_open_cannot_write(self) -> None:
        connection = open_registry_database(self.store.path, read_only=True)
        try:
            self.assertEqual(1, connection.execute("PRAGMA query_only").fetchone()[0])
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("CREATE TABLE forbidden(value TEXT)")
        finally:
            connection.close()

    def test_first_cutover_is_monotonic_and_cannot_restore_legacy_routing(self) -> None:
        source = self.snapshot()
        with patch(
            "coordination_store.require_current_endpoint_identity",
            return_value=DEVELOPMENT_UUID,
        ):
            active = self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="ACTIVE",
                allocation_class="ACTIVE",
                generation=1,
                accountable_session_id=DEVELOPMENT_UUID,
                lease_manifest_sha256=LEASE,
                development_units=1,
                shared_units=1,
                sre_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=0,
                now="2026-08-24T09:00:02Z",
            )
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        applied = apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="migration-with-active-item",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:00Z",
        )
        repeated = apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="migration-with-active-item",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:01Z",
        )
        self.assertEqual(applied["change_id"], repeated["change_id"])
        replayed = replay_applied_change(
            self.store.connection,
            operation_key="migration-with-active-item",
            expected_plan_sha256=plan["plan_sha256"],
            config_sha256=self.config.source_sha256,
            alias_fixture_sha256=self.alias_sha,
        )
        self.assertEqual(applied["change_id"], replayed["change_id"])
        endpoint = current_endpoint(self.store.connection, "development")
        self.assertEqual(DEVELOPMENT_ENDPOINT, endpoint["endpoint_id"])
        item = self.store.connection.execute(
            "SELECT accountable_session_id, version FROM coordination_items WHERE issue_number=92"
        ).fetchone()
        self.assertEqual((DEVELOPMENT_ENDPOINT, active["version"] + 1), tuple(item))
        watch = self.store.connection.execute(
            "SELECT accountable_session_id FROM coordination_terminal_watches"
        ).fetchone()
        self.assertEqual(DEVELOPMENT_ENDPOINT, watch["accountable_session_id"])

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "REGISTRY_ROLLBACK_PRECUTOVER_FORBIDDEN"
        ):
            rollback_change(
                self.store.connection,
                change_id=applied["change_id"],
                expected_version=1,
                now="2026-08-24T10:00:02Z",
            )
        retained = self.store.connection.execute(
            "SELECT accountable_session_id, version FROM coordination_items WHERE issue_number=92"
        ).fetchone()
        self.assertEqual((DEVELOPMENT_ENDPOINT, active["version"] + 1), tuple(retained))
        self.assertEqual(
            DEVELOPMENT_ENDPOINT,
            current_endpoint(self.store.connection, "development")["endpoint_id"],
        )
        endpoint_count = self.store.connection.execute(
            "SELECT COUNT(*) FROM executor_role_endpoints"
        ).fetchone()[0]
        self.assertEqual(3, endpoint_count)

    def test_rollback_rejects_terminal_watch_timestamp_drift(self) -> None:
        source = self.snapshot()
        with patch(
            "coordination_store.require_current_endpoint_identity",
            return_value=DEVELOPMENT_UUID,
        ):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="ACTIVE",
                allocation_class="ACTIVE",
                generation=1,
                accountable_session_id=DEVELOPMENT_UUID,
                lease_manifest_sha256=LEASE,
                development_units=1,
                shared_units=1,
                sre_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=0,
                now="2026-08-24T09:00:02Z",
            )
        applied = self.migrate("watch-cas")
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET updated_at=?",
            ("2026-08-24T10:00:01Z",),
        )
        with self.assertRaisesRegex(RegistryError, "REGISTRY_ROLLBACK_WATCH_CONFLICT"):
            rollback_change(
                self.store.connection,
                change_id=applied["change_id"],
                expected_version=1,
                now="2026-08-24T10:00:02Z",
            )

    def test_post_migration_messages_target_current_endpoint(self) -> None:
        source = self.snapshot()
        self.migrate()
        with self.assertRaisesRegex(
            CoordinationError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
        ):
            self.store.enqueue_message(
                idempotency_key="legacy-alias-notice",
                recipient_session_id=DEVELOPMENT_UUID,
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
                    "subject": "Legacy alias",
                    "summary": "The legacy route must be rejected.",
                    "evidence": {},
                },
                now="2026-08-24T10:00:01Z",
            )
        message_id = self.store.enqueue_message(
            idempotency_key="endpoint-notice",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
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
                "subject": "Endpoint migration",
                "summary": "The role endpoint is current.",
                "evidence": {},
            },
            now="2026-08-24T10:00:01Z",
        )
        recipient = self.store.connection.execute(
            "SELECT recipient_session_id FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()[0]
        self.assertEqual(DEVELOPMENT_ENDPOINT, recipient)

    def test_current_claim_rejects_alias_but_consumes_historical_alias_row(self) -> None:
        source = self.snapshot()
        with patch(
            "coordination_store.require_current_endpoint_identity",
            return_value=DEVELOPMENT_UUID,
        ):
            message_id = self.store.enqueue_message(
                idempotency_key="historical-alias-notice",
                recipient_session_id=DEVELOPMENT_UUID,
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
                    "subject": "Historical route",
                    "summary": "This immutable row predates endpoint cutover.",
                    "evidence": {},
                },
                now="2026-08-24T09:00:01Z",
            )
        before = self.store.connection.execute(
            "SELECT recipient_session_id,payload_json FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.migrate()

        with self.assertRaisesRegex(
            CoordinationError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
        ):
            self.store.claim_message(
                message_id, DEVELOPMENT_UUID, "2026-08-24T10:00:01Z"
            )
        claimed = self.store.claim_message(
            message_id, DEVELOPMENT_ENDPOINT, "2026-08-24T10:00:02Z"
        )
        self.assertEqual(DEVELOPMENT_ENDPOINT, claimed["claimed_by"])
        self.store.complete_message(
            message_id, DEVELOPMENT_ENDPOINT, "2026-08-24T10:00:03Z"
        )
        after = self.store.connection.execute(
            "SELECT recipient_session_id,payload_json,state FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(tuple(before), tuple(after)[:2])
        self.assertEqual("COMPLETE", after["state"])

        with self.assertRaisesRegex(
            CoordinationError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
        ):
            self.store.set_issue_status(
                repository=REPOSITORY,
                issue_number=92,
                status="PREPARED",
                allocation_class="NONE",
                generation=1,
                accountable_session_id=DEVELOPMENT_UUID,
                lease_manifest_sha256=LEASE,
                development_units=1,
                shared_units=0,
                sre_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=0,
                now="2026-08-24T10:00:04Z",
            )
        active = self.store._set_issue_status_for_test_fixture(
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
            now="2026-08-24T10:00:05Z",
        )
        with self.assertRaisesRegex(
            CoordinationError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
        ):
            self.store.enqueue_message(
                idempotency_key="alias-payload-admission",
                recipient_session_id=DEVELOPMENT_ENDPOINT,
                topic="development.admission",
                payload={
                    "source": {
                        "repository": REPOSITORY,
                        "object_kind": "issue",
                        "object_number": 92,
                        "payload_sha256": source.payload_sha256,
                    },
                    "issue_number": 92,
                    "generation": 1,
                    "item_version": active["version"],
                    "base_sha": "a" * 40,
                    "branch": "codex/92-alias-rejection",
                    "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
                    "opaque_worktree_id": "issue-92-alias-rejection",
                    "accountable_session_id": DEVELOPMENT_UUID,
                    "lease_manifest_sha256": LEASE,
                    "authority_sha256": "7" * 64,
                    "capacity": {
                        "development_units": 1,
                        "shared_units": 0,
                        "sre_units": 0,
                    },
                    "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                    "writer": "accountable-writer",
                    "reviewer_plan": ["Different-session exact-head review."],
                    "collision_proof": ["Closed lease is collision-free."],
                    "environment_rule": "Use only an issue-owned environment.",
                    "routine_chain": ["Continue through routine closeout."],
                    "hard_stops": ["Stop on any binding drift."],
                },
                now="2026-08-24T10:00:06Z",
            )

    def test_attempts_are_token_bound_cas_records_and_never_store_raw_token(self) -> None:
        self.migrate()
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="11",
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        serialized = json.dumps(dict(self.store.connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?", (reserved["attempt_id"],)
        ).fetchone()))
        self.assertNotIn(token, serialized)
        different, _different_token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="12",
            now="2026-08-24T10:00:02Z",
            precondition=self.no_lineage,
        )
        self.assertEqual("RESERVED", different["state"])
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_TARGET_BUSY"):
            reserve_attempt(
                self.store.connection,
                role="development",
                endpoint_id=DEVELOPMENT_ENDPOINT,
                target_kind="message",
                target_key="11",
                now="2026-08-24T10:00:02Z",
                precondition=self.no_lineage,
            )
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=1,
            new_state="LAUNCHING",
            systemd_unit=UNIT,
            systemd_invocation_id=INVOCATION_ID,
            systemd_control_group=CONTROL_GROUP,
            now="2026-08-24T10:00:03Z",
        )
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_TARGET_BUSY"):
            reserve_attempt(
                self.store.connection,
                role="development",
                endpoint_id=DEVELOPMENT_ENDPOINT,
                target_kind="message",
                target_key="11",
                now="2026-08-24T10:00:03Z",
                precondition=self.no_lineage,
            )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=123,
            now="2026-08-24T10:00:04Z",
        )
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_ATTEMPT_VERSION_CONFLICT"):
            transition_attempt(
                self.store.connection,
                attempt_id=reserved["attempt_id"],
                token=token,
                expected_version=1,
                new_state="COMPLETE",
                exit_code=0,
                now="2026-08-24T10:00:05Z",
            )
        complete = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-24T10:00:06Z",
        )
        self.assertEqual("COMPLETE", complete["state"])
        self.assertEqual(123, complete["process_id"])
        events = self.store.connection.execute(
            "SELECT from_state,to_state FROM executor_attempt_events "
            "WHERE attempt_id=? ORDER BY rowid",
            (reserved["attempt_id"],),
        ).fetchall()
        self.assertEqual(
            [(None, "RESERVED"), ("RESERVED", "LAUNCHING"),
             ("LAUNCHING", "RUNNING"), ("RUNNING", "COMPLETE")],
            [tuple(row) for row in events],
        )

    def test_logical_lineage_fence_denies_cross_target_duplicate_and_keeps_disjoint_parallelism(self) -> None:
        self.migrate("logical-lineage-fence")
        issue_92 = AttemptLineage(REPOSITORY, 92, 7, LEASE)
        issue_93 = AttemptLineage(REPOSITORY, 93, 1, "6" * 64)
        issue_94 = AttemptLineage(REPOSITORY, 94, 2, "7" * 64)

        first, _token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="lineage-message-92",
            now="2026-08-24T10:00:01Z",
            precondition=lambda _connection: issue_92,
        )
        self.assertEqual(issue_92.sha256, first["lineage_sha256"])
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "EXECUTOR_ATTEMPT_IDENTITY_IMMUTABLE"
        ):
            self.store.connection.execute(
                "UPDATE executor_attempts SET lineage_generation=8 WHERE attempt_id=?",
                (first["attempt_id"],),
            )
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_LINEAGE_BUSY"):
            reserve_attempt(
                self.store.connection,
                role="development",
                endpoint_id=DEVELOPMENT_ENDPOINT,
                target_kind="terminal_watch",
                target_key="lineage-watch-92",
                now="2026-08-24T10:00:02Z",
                precondition=lambda _connection: issue_92,
            )

        same_role, _same_role_token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="lineage-message-93",
            now="2026-08-24T10:00:02Z",
            precondition=lambda _connection: issue_93,
        )
        mixed_role, _mixed_role_token = reserve_attempt(
            self.store.connection,
            role="sre",
            endpoint_id=SRE_ENDPOINT,
            target_kind="message",
            target_key="lineage-message-94",
            now="2026-08-24T10:00:02Z",
            precondition=lambda _connection: issue_94,
        )
        notice_a, _notice_a_token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="notice-a",
            now="2026-08-24T10:00:02Z",
            precondition=self.no_lineage,
        )
        notice_b, _notice_b_token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="notice-b",
            now="2026-08-24T10:00:02Z",
            precondition=self.no_lineage,
        )
        self.assertEqual(
            ["RESERVED"] * 4,
            [same_role["state"], mixed_role["state"], notice_a["state"], notice_b["state"]],
        )
        self.assertIsNone(notice_a["lineage_sha256"])
        self.assertIsNone(notice_b["lineage_sha256"])

    def test_planner_repository_fence_is_immutable_and_keeps_distinct_repositories_parallel(self) -> None:
        self.migrate("planner-repository-fence")
        first_message = self.planner_notice(
            repository=REPOSITORY,
            issue_number=92,
            idempotency_key="planner-repository-first",
        )
        second_message = self.planner_notice(
            repository=REPOSITORY,
            issue_number=93,
            idempotency_key="planner-repository-second",
        )
        other_repository = "twinfinityai/twinfinity-companion"
        other_message = self.planner_notice(
            repository=other_repository,
            issue_number=1,
            idempotency_key="planner-repository-other",
        )

        first, _token = reserve_attempt(
            self.store.connection,
            role="planner",
            endpoint_id=PLANNER_ENDPOINT,
            target_kind="message",
            target_key=str(first_message),
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        self.assertEqual(REPOSITORY, first["repository_scope"])
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "EXECUTOR_ATTEMPT_IDENTITY_IMMUTABLE"
        ):
            self.store.connection.execute(
                "UPDATE executor_attempts SET repository_scope=? WHERE attempt_id=?",
                (other_repository, first["attempt_id"]),
            )
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_REPOSITORY_BUSY"):
            reserve_attempt(
                self.store.connection,
                role="planner",
                endpoint_id=PLANNER_ENDPOINT,
                target_kind="message",
                target_key=str(second_message),
                now="2026-08-24T10:00:02Z",
                precondition=self.no_lineage,
            )
        other, _other_token = reserve_attempt(
            self.store.connection,
            role="planner",
            endpoint_id=PLANNER_ENDPOINT,
            target_kind="message",
            target_key=str(other_message),
            now="2026-08-24T10:00:02Z",
            precondition=self.no_lineage,
        )
        self.assertEqual(other_repository, other["repository_scope"])

    def test_planner_repository_fence_serializes_two_connection_race(self) -> None:
        self.migrate("planner-repository-race")
        message_ids = [
            self.planner_notice(
                repository=REPOSITORY,
                issue_number=issue_number,
                idempotency_key=f"planner-race-{issue_number}",
            )
            for issue_number in (92, 93)
        ]
        barrier = threading.Barrier(2)

        def compete(message_id: int) -> str:
            contender = CoordinationStore(self.store.path)
            try:
                barrier.wait(timeout=5)
                reserve_attempt(
                    contender.connection,
                    role="planner",
                    endpoint_id=PLANNER_ENDPOINT,
                    target_kind="message",
                    target_key=str(message_id),
                    now="2026-08-24T10:00:01Z",
                    precondition=self.no_lineage,
                )
                return "RESERVED"
            except RegistryError as exc:
                return str(exc)
            finally:
                contender.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(compete, message_ids))
        self.assertCountEqual(
            ["RESERVED", "EXECUTOR_REPOSITORY_BUSY"], outcomes
        )
        active = self.store.connection.execute(
            "SELECT repository_scope FROM executor_attempts "
            "WHERE role='planner' AND state IN ('RESERVED','LAUNCHING','RUNNING')"
        ).fetchall()
        self.assertEqual([REPOSITORY], [row["repository_scope"] for row in active])

    def test_role_executor_reserves_before_launch_and_never_resumes(self) -> None:
        source = self.snapshot()
        self.migrate()
        message_id = self.store.enqueue_message(
            idempotency_key="executor-target",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
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
                "subject": "Launch target",
                "summary": "A fresh executor should inspect this row.",
                "evidence": {},
            },
            now="2026-08-24T10:00:01Z",
        )
        observed: dict = {}

        def fail_after_reservation(command, **kwargs):
            observed["command"] = command
            observed["states"] = [
                tuple(row)
                for row in self.store.connection.execute(
                    "SELECT state,systemd_unit,systemd_invocation_id,process_id "
                    "FROM executor_attempts"
                ).fetchall()
            ]
            raise OSError("synthetic")

        failed = execute_role(
            self.store.connection,
            config_path=CONFIG,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            prompt="Inspect the exact endpoint row.",
            systemd_invocation_id=INVOCATION_ID,
            systemd_evidence=systemd_evidence(target_key=str(message_id)),
            popen=fail_after_reservation,
        )
        self.assertEqual(
            [(
                "LAUNCHING",
                stable_systemd_unit("development", "message", str(message_id)),
                INVOCATION_ID,
                None,
            )],
            observed["states"],
        )
        self.assertNotIn("resume", observed["command"])
        self.assertEqual("LAUNCH_FAILED", failed["state"])

        environments = []

        def succeed(command, **kwargs):
            environments.append(kwargs["env"])
            self.assertNotIn("resume", command)
            self.store.claim_message(
                message_id, DEVELOPMENT_ENDPOINT, "2026-08-24T10:00:02Z"
            )
            self.store.complete_message(
                message_id, DEVELOPMENT_ENDPOINT, "2026-08-24T10:00:03Z"
            )
            return _ImmediateProcess()

        complete = execute_role(
            self.store.connection,
            config_path=CONFIG,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            prompt="Inspect the exact endpoint row.",
            systemd_invocation_id=INVOCATION_ID,
            systemd_evidence=systemd_evidence(target_key=str(message_id)),
            popen=succeed,
        )
        self.assertEqual("COMPLETE", complete["state"])
        self.assertTrue(environments[0]["TWINFINITY_EXECUTOR_TOKEN"])
        self.assertFalse(complete["token_persisted"])

    def test_exit_zero_without_target_progress_holds_with_digest_readback(self) -> None:
        source = self.snapshot()
        self.migrate("zero-exit-no-progress")
        message_id = self.store.enqueue_message(
            idempotency_key="zero-exit-no-progress",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
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
                "subject": "No-op readback",
                "summary": "An exit-zero child must still advance its target.",
                "evidence": {},
            },
            now="2026-08-24T10:00:01Z",
        )

        result = execute_role(
            self.store.connection,
            config_path=CONFIG,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            prompt="Return without changing the target.",
            systemd_invocation_id=INVOCATION_ID,
            systemd_evidence=systemd_evidence(target_key=str(message_id)),
            popen=lambda *_args, **_kwargs: _ImmediateProcess(),
        )

        self.assertEqual("HOLD", result["state"])
        self.assertEqual("EXECUTOR_TARGET_NO_PROGRESS", result["error"])
        self.assertEqual(
            result["target_progress_sha256"], result["terminal_progress_sha256"]
        )
        self.assertEqual(
            "PREPARED",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()[0],
        )

    def test_nonmutating_notice_ignores_referenced_item_version_drift(self) -> None:
        source = self.snapshot()
        self.migrate("notice-item-drift")
        item = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="PREPARED",
            allocation_class="NONE",
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
        message_id = self.store.enqueue_message(
            idempotency_key="notice-external-item-drift",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
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
                "subject": "External item drift",
                "summary": "Only the exact notice lifecycle counts as notice progress.",
                "evidence": {},
            },
            now="2026-08-24T10:00:02Z",
        )

        def drift_referenced_item(*_args, **_kwargs):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="PREPARED",
                allocation_class="NONE",
                generation=1,
                accountable_session_id=DEVELOPMENT_ENDPOINT,
                lease_manifest_sha256=LEASE,
                development_units=1,
                shared_units=0,
                sre_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=int(item["version"]),
                now="2026-08-24T10:00:03Z",
            )
            return _ImmediateProcess()

        result = execute_role(
            self.store.connection,
            config_path=CONFIG,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            prompt="Do not confuse referenced-item drift with notice progress.",
            systemd_invocation_id=INVOCATION_ID,
            systemd_evidence=systemd_evidence(target_key=str(message_id)),
            popen=drift_referenced_item,
        )

        self.assertEqual("HOLD", result["state"])
        self.assertEqual("EXECUTOR_TARGET_NO_PROGRESS", result["error"])
        self.assertEqual(
            result["target_progress_sha256"], result["terminal_progress_sha256"]
        )
        self.assertEqual(
            int(item["version"]) + 1,
            self.store.connection.execute(
                "SELECT version FROM coordination_items "
                "WHERE repository=? AND issue_number=92",
                (REPOSITORY,),
            ).fetchone()[0],
        )

    def test_v3_launch_v4_cutover_launch_rollback_and_v3_launch(self) -> None:
        source = self.snapshot()
        now = "2026-08-24T09:00:00Z"
        for endpoint in self.config.endpoints.values():
            _verify_or_insert_endpoint(self.store.connection, endpoint.payload, now)
        initial = {
            "planner": PLANNER_ENDPOINT,
            "development": "role.development.v3",
            "sre": "role.sre.v3",
        }
        for role, endpoint_id in initial.items():
            self.store.connection.execute(
                """
                INSERT INTO executor_role_endpoint_current(
                    role, endpoint_id, pointer_version, updated_at
                ) VALUES (?, ?, 1, ?)
                """,
                (role, endpoint_id, now),
            )

        observed_profiles: list[str] = []

        def launch(endpoint_id: str, suffix: str) -> None:
            message_id = self.store.enqueue_message(
                idempotency_key=f"endpoint-rollback-{suffix}",
                recipient_session_id=endpoint_id,
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
                    "subject": "Endpoint rollback probe",
                    "summary": "Validate an immutable endpoint runtime profile.",
                    "evidence": {},
                },
                now=f"2026-08-24T10:00:0{suffix}Z",
            )

            def succeed(command, **_kwargs):
                observed_profiles.append(command[command.index("--profile") + 1])
                self.store.claim_message(
                    message_id, endpoint_id, f"2026-08-24T10:00:1{suffix}Z"
                )
                self.store.complete_message(
                    message_id, endpoint_id, f"2026-08-24T10:00:2{suffix}Z"
                )
                return _ImmediateProcess()

            result = execute_role(
                self.store.connection,
                config_path=CONFIG,
                role="development",
                endpoint_id=endpoint_id,
                target_kind="message",
                target_key=str(message_id),
                prompt="Inspect the exact endpoint rollback probe.",
                systemd_invocation_id=INVOCATION_ID,
                systemd_evidence=systemd_evidence(target_key=str(message_id)),
                popen=succeed,
            )
            self.assertEqual("COMPLETE", result["state"])

        launch("role.development.v3", "1")
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        applied = apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="versioned-runtime-cutover",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:02Z",
        )
        launch(DEVELOPMENT_ENDPOINT, "3")
        rolled_back = rollback_change(
            self.store.connection,
            change_id=applied["change_id"],
            expected_version=1,
            now="2026-08-24T10:00:04Z",
        )
        self.assertEqual("ROLLED_BACK", rolled_back["state"])
        launch("role.development.v3", "5")
        self.assertEqual(
            [
                "twinfinity-development-v3",
                "twinfinity-development-v4",
                "twinfinity-development-v3",
            ],
            observed_profiles,
        )

    def test_launching_transition_failure_never_creates_child(self) -> None:
        source = self.snapshot()
        self.migrate()
        message_id = self.store.enqueue_message(
            idempotency_key="launching-transition-failure",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
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
                "subject": "Launch target",
                "summary": "A fresh executor should inspect this row.",
                "evidence": {},
            },
            now="2026-08-24T10:00:01Z",
        )
        popen_called = False

        def forbidden_popen(*_args, **_kwargs):
            nonlocal popen_called
            popen_called = True
            return _ImmediateProcess()

        def fail_launching(*args, **kwargs):
            if kwargs["new_state"] == "LAUNCHING":
                raise RegistryError("SYNTHETIC_LAUNCHING_CAS_FAILURE")
            return transition_attempt(*args, **kwargs)

        with self.assertRaisesRegex(
            RegistryError, "EXECUTOR_LAUNCHING_TRANSITION_FAILED"
        ):
            execute_role(
                self.store.connection,
                config_path=CONFIG,
                role="development",
                endpoint_id=DEVELOPMENT_ENDPOINT,
                target_kind="message",
                target_key=str(message_id),
                prompt="Do not launch.",
                systemd_invocation_id=INVOCATION_ID,
                systemd_evidence=systemd_evidence(target_key=str(message_id)),
                popen=forbidden_popen,
                transitioner=fail_launching,
            )
        self.assertFalse(popen_called)
        state = self.store.connection.execute(
            "SELECT state FROM executor_attempts"
        ).fetchone()[0]
        self.assertEqual("LAUNCH_FAILED", state)

    def test_post_popen_running_transition_failure_terminates_child(self) -> None:
        source = self.snapshot()
        self.migrate()
        message_id = self.store.enqueue_message(
            idempotency_key="post-popen-transition-failure",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
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
                "subject": "Launch target",
                "summary": "A fresh executor should inspect this row.",
                "evidence": {},
            },
            now="2026-08-24T10:00:01Z",
        )
        process = _TerminableProcess()

        def fail_running(*args, **kwargs):
            if kwargs["new_state"] == "RUNNING":
                raise RegistryError("SYNTHETIC_RUNNING_CAS_FAILURE")
            return transition_attempt(*args, **kwargs)

        with self.assertRaisesRegex(
            RegistryError, "EXECUTOR_POST_LAUNCH_TRANSITION_FAILED"
        ):
            execute_role(
                self.store.connection,
                config_path=CONFIG,
                role="development",
                endpoint_id=DEVELOPMENT_ENDPOINT,
                target_kind="message",
                target_key=str(message_id),
                prompt="Terminate if RUNNING cannot persist.",
                systemd_invocation_id=INVOCATION_ID,
                systemd_evidence=systemd_evidence(target_key=str(message_id)),
                popen=lambda *_args, **_kwargs: process,
                transitioner=fail_running,
            )
        self.assertTrue(process.terminated)
        row = self.store.connection.execute(
            "SELECT state,process_id,last_error FROM executor_attempts"
        ).fetchone()
        self.assertEqual(
            ("HOLD", None, "EXECUTOR_POST_LAUNCH_TRANSITION_FAILED"), tuple(row)
        )

    def test_stale_active_recovery_requires_exact_positive_systemd_evidence(self) -> None:
        self.migrate()
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="11",
            now="2026-08-24T10:00:00Z",
            precondition=self.no_lineage,
        )
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=UNIT,
            systemd_invocation_id=INVOCATION_ID,
            systemd_control_group=CONTROL_GROUP,
            now="2026-08-24T10:00:01Z",
        )
        before = "2026-08-24T10:01:00Z"
        now = "2026-08-24T10:02:00Z"

        active = recover_stale_active_attempts(
            self.store.connection,
            before=before,
            now=now,
            evidence_reader=lambda _unit: systemd_evidence(),
        )
        self.assertEqual("STALE_RECOVERY_SYSTEMD_NOT_PROVEN_INACTIVE", active[0]["error"])
        mismatched = recover_stale_active_attempts(
            self.store.connection,
            before=before,
            now=now,
            evidence_reader=lambda _unit: systemd_evidence(invocation_id="b" * 32),
        )
        self.assertEqual("STALE_RECOVERY_SYSTEMD_IDENTITY_MISMATCH", mismatched[0]["error"])

        def missing(_unit):
            raise RegistryError("SYSTEMD_EVIDENCE_QUERY_FAILED")

        absent = recover_stale_active_attempts(
            self.store.connection,
            before=before,
            now=now,
            evidence_reader=missing,
        )
        self.assertEqual("STALE_RECOVERY_SYSTEMD_EVIDENCE_FAILED", absent[0]["error"])
        unchanged = self.store.connection.execute(
            "SELECT state,version FROM executor_attempts WHERE attempt_id=?",
            (reserved["attempt_id"],),
        ).fetchone()
        self.assertEqual(("LAUNCHING", launching["version"]), tuple(unchanged))

        inactive = systemd_evidence(active_state="inactive", sub_state="dead")
        recovered = recover_stale_active_attempts(
            self.store.connection,
            before=before,
            now=now,
            evidence_reader=lambda _unit: inactive,
        )
        self.assertEqual("RECOVERED", recovered[0]["phase"])
        terminal = self.store.connection.execute(
            "SELECT state,version,last_error FROM executor_attempts WHERE attempt_id=?",
            (reserved["attempt_id"],),
        ).fetchone()
        self.assertEqual(
            ("HOLD", launching["version"] + 1,
             "RECOVERED_STALE_ACTIVE_SYSTEMD_INACTIVE"),
            tuple(terminal),
        )
        event = self.store.connection.execute(
            "SELECT evidence_sha256,evidence_json FROM executor_attempt_events "
            "WHERE attempt_id=? AND reason='RECOVERED_STALE_ACTIVE_SYSTEMD_INACTIVE'",
            (reserved["attempt_id"],),
        ).fetchone()
        self.assertIsNotNone(event["evidence_sha256"])
        self.assertEqual(inactive.payload, json.loads(event["evidence_json"]))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE"):
            self.store.connection.execute(
                "UPDATE executor_attempt_events SET reason='changed' "
                "WHERE attempt_id=?",
                (reserved["attempt_id"],),
            )

        reserved_running, token_running = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="12",
            now="2026-08-24T10:00:10Z",
            precondition=self.no_lineage,
        )
        launching_running = transition_attempt(
            self.store.connection,
            attempt_id=reserved_running["attempt_id"],
            token=token_running,
            expected_version=reserved_running["version"],
            new_state="LAUNCHING",
            systemd_unit=stable_systemd_unit("development", "message", "12"),
            systemd_invocation_id=INVOCATION_ID,
            systemd_control_group=(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/"
                + stable_systemd_unit("development", "message", "12")
            ),
            now="2026-08-24T10:00:11Z",
        )
        transition_attempt(
            self.store.connection,
            attempt_id=reserved_running["attempt_id"],
            token=token_running,
            expected_version=launching_running["version"],
            new_state="RUNNING",
            process_id=2222,
            now="2026-08-24T10:00:12Z",
        )
        inactive_running = systemd_evidence(
            target_key="12", active_state="inactive", sub_state="dead"
        )
        recovered_running = recover_stale_active_attempts(
            self.store.connection,
            before=before,
            now=now,
            evidence_reader=lambda _unit: inactive_running,
        )
        self.assertEqual("RECOVERED", recovered_running[0]["phase"])
        running_terminal = self.store.connection.execute(
            "SELECT state,process_id FROM executor_attempts WHERE attempt_id=?",
            (reserved_running["attempt_id"],),
        ).fetchone()
        self.assertEqual(("HOLD", 2222), tuple(running_terminal))

    def test_runner_terminal_watch_reservation_repeats_item_endpoint_and_lineage(self) -> None:
        source = self.snapshot()
        self.migrate("runner-terminal-watch-contract")
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE_FENCED",
            allocation_class="ACTIVE",
            generation=3,
            accountable_session_id=DEVELOPMENT_ENDPOINT,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-24T10:00:01Z",
        )
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:3"
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(
            ("ACTIVE", DEVELOPMENT_ENDPOINT, LEASE),
            (
                watch["state"],
                watch["accountable_session_id"],
                watch["lease_manifest_sha256"],
            ),
        )

        with self.assertRaisesRegex(RegistryError, "EXECUTOR_TARGET_INVALID"):
            execute_role(
                self.store.connection,
                config_path=CONFIG,
                role="development",
                endpoint_id=DEVELOPMENT_ENDPOINT,
                target_kind="terminal_watch",
                target_key=watch_key,
                prompt="Do not launch an unbound terminal watch.",
                systemd_invocation_id=INVOCATION_ID,
                systemd_evidence=systemd_evidence(
                    role="development",
                    target_kind="terminal_watch",
                    target_key=watch_key,
                ),
                popen=lambda *_args, **_kwargs: self.fail("child must not launch"),
            )
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 3,
            "item_version": 1,
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            "base_sha": "a" * 40,
            "branch": "codex/92-runner-terminal-binding",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "issue-92-runner-terminal-binding",
            "accountable_session_id": DEVELOPMENT_ENDPOINT,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "writer": "accountable-writer",
            "reviewer_plan": ["Different-session exact-head review."],
            "collision_proof": ["Closed lease is collision-free."],
            "environment_rule": "Use only an issue-owned environment.",
            "routine_chain": ["Continue through routine closeout."],
            "hard_stops": ["Stop on any binding drift."],
        }
        message_id = self.store.enqueue_message(
            idempotency_key="runner-terminal-watch-binding",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
            topic="development.admission",
            payload=payload,
            now="2026-08-24T10:00:02Z",
        )
        self.store.connection.execute(
            """
            UPDATE coordination_terminal_watches
            SET state='PENDING_CLAIM', admission_message_id=?,
                admission_payload_sha256=?
            WHERE watch_key=?
            """,
            (message_id, digest_json(payload), watch_key),
        )
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-24T10:00:03Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(message_id)
            ),
        )
        message_unit = stable_systemd_unit(
            "development", "message", str(message_id)
        )
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=message_unit,
            systemd_invocation_id="b" * 32,
            systemd_control_group=f"/user.slice/{message_unit}",
            now="2026-08-24T10:00:04Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9200,
            now="2026-08-24T10:00:05Z",
        )
        self.store.claim_message(
            message_id,
            DEVELOPMENT_ENDPOINT,
            "2026-08-24T10:00:06Z",
            attempt_id=running["attempt_id"],
            executor_token=token,
        )
        transition_attempt(
            self.store.connection,
            attempt_id=running["attempt_id"],
            token=token,
            expected_version=running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-24T10:00:08Z",
        )
        self.assertEqual(
            "CLAIMED",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()[0],
        )

        def advance_terminal_watch(*_args, **_kwargs):
            self.store.connection.execute(
                "UPDATE coordination_terminal_watches SET last_heartbeat_at=? "
                "WHERE watch_key=?",
                ("2026-08-24T10:00:09Z", watch_key),
            )
            return _ImmediateProcess()

        launched = execute_role(
            self.store.connection,
            config_path=CONFIG,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=watch_key,
            prompt="Inspect the exact bound terminal watch.",
            systemd_invocation_id=INVOCATION_ID,
            systemd_evidence=systemd_evidence(
                role="development",
                target_kind="terminal_watch",
                target_key=watch_key,
            ),
            popen=advance_terminal_watch,
        )
        self.assertEqual("COMPLETE", launched["state"])
        before_drift_attempts = self.store.connection.execute(
            "SELECT COUNT(*) FROM executor_attempts"
        ).fetchone()[0]

        self.store.connection.execute(
            "UPDATE coordination_items SET lease_manifest_sha256=? "
            "WHERE repository=? AND issue_number=92",
            ("6" * 64, REPOSITORY),
        )
        with self.assertRaisesRegex(
            RegistryError, "EXECUTOR_TERMINAL_WATCH_CONTRACT_INVALID"
        ):
            execute_role(
                self.store.connection,
                config_path=CONFIG,
                role="development",
                endpoint_id=DEVELOPMENT_ENDPOINT,
                target_kind="terminal_watch",
                target_key=watch_key,
                prompt="Do not launch a drifted terminal watch.",
                systemd_invocation_id=INVOCATION_ID,
                systemd_evidence=systemd_evidence(
                    role="development",
                    target_kind="terminal_watch",
                    target_key=watch_key,
                ),
                popen=lambda *_args, **_kwargs: self.fail("child must not launch"),
            )
        self.assertEqual(
            before_drift_attempts,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM executor_attempts"
            ).fetchone()[0],
        )
        self.store.connection.execute(
            "UPDATE coordination_items SET lease_manifest_sha256=? "
            "WHERE repository=? AND issue_number=92",
            (LEASE, REPOSITORY),
        )
        rotated_endpoint = "role.development.v3"
        _verify_or_insert_endpoint(
            self.store.connection,
            self.config.endpoints[rotated_endpoint].payload,
            "2026-08-24T10:00:20Z",
        )
        self.store.connection.execute(
            "UPDATE executor_role_endpoint_current SET endpoint_id=?,"
            "pointer_version=pointer_version+1,updated_at=? "
            "WHERE role='development'",
            (rotated_endpoint, "2026-08-24T10:00:20Z"),
        )
        self.store.connection.execute(
            "UPDATE coordination_items SET accountable_session_id=?,"
            "version=version+1,updated_at=? WHERE repository=? AND issue_number=92",
            (rotated_endpoint, "2026-08-24T10:00:20Z", REPOSITORY),
        )
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET accountable_session_id=?,"
            "updated_at=? WHERE watch_key=?",
            (rotated_endpoint, "2026-08-24T10:00:20Z", watch_key),
        )
        lineage = run_role_executor._validate_target(
            self.store.connection,
            role="development",
            endpoint_id=rotated_endpoint,
            target_kind="terminal_watch",
            target_key=watch_key,
            allowed_topics={"development.admission"},
        )
        self.assertEqual(REPOSITORY, lineage.repository)

    def test_hosted_executor_revalidates_exact_sre_row_before_reservation(self) -> None:
        self.migrate()
        self.store.connection.execute(
            "CREATE TABLE hosted_operations(id INTEGER PRIMARY KEY, "
            "recipient_session_id TEXT NOT NULL, state TEXT NOT NULL)"
        )
        self.store.connection.execute(
            "INSERT INTO hosted_operations VALUES (328, ?, 'PREPARED')",
            (SRE_ENDPOINT,),
        )
        def complete_hosted(*_args, **_kwargs):
            self.store.connection.execute(
                "UPDATE hosted_operations SET state='COMPLETE' WHERE id=328"
            )
            return _ImmediateProcess()

        complete = execute_role(
            self.store.connection,
            config_path=CONFIG,
            role="sre",
            endpoint_id=SRE_ENDPOINT,
            target_kind="hosted_operation",
            target_key="328",
            prompt="Revalidate exact hosted operation 328 before claim.",
            systemd_invocation_id="b" * 32,
            systemd_evidence=systemd_evidence(
                role="sre",
                target_kind="hosted_operation",
                target_key="328",
                invocation_id="b" * 32,
            ),
            popen=complete_hosted,
        )
        self.assertEqual("COMPLETE", complete["state"])
        self.assertEqual("hosted_operation", complete["target_kind"])
        with self.assertRaisesRegex(RegistryError, "EXECUTOR_TARGET_INVALID"):
            execute_role(
                self.store.connection,
                config_path=CONFIG,
                role="sre",
                endpoint_id=SRE_ENDPOINT,
                target_kind="hosted_operation",
                target_key="329",
                prompt="Missing row must fail before reserve.",
                systemd_invocation_id="b" * 32,
                systemd_evidence=systemd_evidence(
                    role="sre",
                    target_kind="hosted_operation",
                    target_key="329",
                    invocation_id="b" * 32,
                ),
                popen=lambda *_args, **_kwargs: _ImmediateProcess(),
            )

    def test_stale_recovery_rejects_active_missing_mismatch_and_failed_probe(self) -> None:
        self.migrate()
        evidence_cases = {
            "active": lambda _unit: systemd_evidence(),
            "missing": lambda _unit: systemd_evidence(
                load_state="not-found", active_state="inactive", sub_state="dead"
            ),
            "mismatch": lambda _unit: systemd_evidence(
                invocation_id="b" * 32, active_state="inactive", sub_state="dead"
            ),
            "command_failed": lambda _unit: (_ for _ in ()).throw(
                RegistryError("SYSTEMD_EVIDENCE_QUERY_FAILED")
            ),
        }
        for name, reader in evidence_cases.items():
            with self.subTest(name=name):
                attempt, token = self.launched_attempt()
                result = recover_stale_active_attempts(
                    self.store.connection,
                    before="2026-08-24T10:01:00Z",
                    now="2026-08-24T10:02:00Z",
                    evidence_reader=reader,
                )
                self.assertEqual("HOLD", result[0]["phase"])
                current = self.store.connection.execute(
                    "SELECT * FROM executor_attempts WHERE attempt_id=?",
                    (attempt["attempt_id"],),
                ).fetchone()
                self.assertEqual("RUNNING", current["state"])
                transition_attempt(
                    self.store.connection,
                    attempt_id=attempt["attempt_id"],
                    token=token,
                    expected_version=current["version"],
                    new_state="HOLD",
                    now="2026-08-24T10:02:01Z",
                    last_error="TEST_CLEANUP",
                )

    def test_stale_launching_and_running_recover_only_with_exact_inactive_evidence(self) -> None:
        self.migrate()
        for running in (False, True):
            with self.subTest(state="RUNNING" if running else "LAUNCHING"):
                attempt, _token = self.launched_attempt(running=running)
                result = recover_stale_active_attempts(
                    self.store.connection,
                    before="2026-08-24T10:01:00Z",
                    now="2026-08-24T10:02:00Z",
                    evidence_reader=lambda _unit: systemd_evidence(
                        active_state="inactive",
                        sub_state="dead",
                        result="exit-code",
                    ),
                )
                self.assertEqual(
                    [{
                        "attempt_id": attempt["attempt_id"],
                        "phase": "RECOVERED",
                        "state": "HOLD",
                    }],
                    result,
                )
                row = self.store.connection.execute(
                    "SELECT state,last_error FROM executor_attempts WHERE attempt_id=?",
                    (attempt["attempt_id"],),
                ).fetchone()
                self.assertEqual(
                    ("HOLD", "RECOVERED_STALE_ACTIVE_SYSTEMD_INACTIVE"), tuple(row)
                )
                event = self.store.connection.execute(
                    "SELECT to_state,evidence_json FROM executor_attempt_events "
                    "WHERE attempt_id=? ORDER BY rowid DESC LIMIT 1",
                    (attempt["attempt_id"],),
                ).fetchone()
                self.assertEqual("HOLD", event["to_state"])
                self.assertIn('"active_state":"inactive"', event["evidence_json"])

    def test_reviewed_migration_expands_legacy_attempt_target_schema(self) -> None:
        self.migrate("endpoint-bootstrap")
        self.store.connection.executescript(
            "DROP TRIGGER executor_attempt_event_immutable_update; "
            "DROP TRIGGER executor_attempt_event_immutable_delete; "
            "DROP TABLE executor_attempt_events; "
            "DROP TRIGGER executor_attempt_identity_immutable; "
            "DROP INDEX executor_one_active_attempt_per_target; "
            "DROP TABLE executor_attempts; "
            "CREATE TABLE executor_attempts("
            "attempt_id TEXT PRIMARY KEY, role TEXT NOT NULL, endpoint_id TEXT NOT NULL, "
            "instance_id TEXT NOT NULL UNIQUE, token_sha256 TEXT NOT NULL, "
            "target_kind TEXT NOT NULL CHECK(target_kind IN ('message','terminal_watch')), "
            "target_key TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN "
            "('RESERVED','RUNNING','COMPLETE','HOLD','LAUNCH_FAILED')), "
            "process_id INTEGER, exit_code INTEGER, heartbeat_at TEXT NOT NULL, "
            "version INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "last_error TEXT); "
            "CREATE UNIQUE INDEX executor_one_active_attempt_per_role "
            "ON executor_attempts(role) WHERE state IN ('RESERVED','RUNNING'); "
            "CREATE TRIGGER executor_attempt_identity_immutable BEFORE UPDATE ON "
            "executor_attempts WHEN NEW.attempt_id IS NOT OLD.attempt_id "
            "BEGIN SELECT RAISE(ABORT, 'EXECUTOR_ATTEMPT_IDENTITY_IMMUTABLE'); END;"
        )
        self.store.connection.execute(
            "INSERT INTO executor_attempts VALUES ("
            f"'historical-attempt','development','{DEVELOPMENT_ENDPOINT}',"
            "'historical-instance',?, 'message','11','COMPLETE',4321,0,"
            "'2026-08-23T10:00:00Z',4,'2026-08-23T09:00:00Z',"
            "'2026-08-23T10:00:00Z',NULL)",
            ("f" * 64,),
        )
        self.assertFalse(attempts_support_hosted_operation(self.store.connection))
        self.assertFalse(attempt_schema_is_current(self.store.connection))
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        self.assertTrue(plan["attempt_schema_upgrade"])
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="attempt-target-schema-upgrade",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:00Z",
        )
        self.assertTrue(attempts_support_hosted_operation(self.store.connection))
        self.assertTrue(attempt_schema_is_current(self.store.connection))
        indexes = {
            row[0]
            for row in self.store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
        self.assertIn("executor_one_active_attempt_per_target", indexes)
        self.assertIn("executor_one_active_attempt_per_lineage", indexes)
        self.assertNotIn("executor_one_active_attempt_per_role", indexes)
        historical = self.store.connection.execute(
            "SELECT state,process_id,exit_code,version,systemd_unit,lineage_sha256 "
            "FROM executor_attempts WHERE attempt_id='historical-attempt'"
        ).fetchone()
        self.assertEqual(("COMPLETE", 4321, 0, 4, None, None), tuple(historical))

    def test_role_index_migration_preserves_attempt_and_event_history(self) -> None:
        self.migrate("initial-target-schema")
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="history-target",
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        unit = stable_systemd_unit("development", "message", "history-target")
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=INVOCATION_ID,
            systemd_control_group=f"/user.slice/app.slice/{unit}",
            now="2026-08-24T10:00:02Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=4321,
            now="2026-08-24T10:00:03Z",
        )
        transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-24T10:00:04Z",
        )
        self.store.connection.executescript(
            "DROP INDEX executor_one_active_attempt_per_target; "
            "CREATE UNIQUE INDEX executor_one_active_attempt_per_role "
            "ON executor_attempts(role) "
            "WHERE state IN ('RESERVED','LAUNCHING','RUNNING');"
        )

        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        self.assertEqual("ROLE_LEGACY", plan["attempt_active_uniqueness"])
        self.assertTrue(plan["attempt_schema_upgrade"])
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="role-to-target-index",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:05Z",
        )

        self.assertTrue(attempt_schema_is_current(self.store.connection))
        self.assertEqual(
            4,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM executor_attempt_events WHERE attempt_id=?",
                (reserved["attempt_id"],),
            ).fetchone()[0],
        )
        self.assertEqual(
            ("COMPLETE", 4321, 0),
            tuple(self.store.connection.execute(
                "SELECT state,process_id,exit_code FROM executor_attempts "
                "WHERE attempt_id=?",
                (reserved["attempt_id"],),
            ).fetchone()),
        )

    def test_role_index_migration_requires_zero_active_attempts(self) -> None:
        self.migrate("initial-active-target-schema")
        reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="active-target",
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        self.store.connection.executescript(
            "DROP INDEX executor_one_active_attempt_per_target; "
            "CREATE UNIQUE INDEX executor_one_active_attempt_per_role "
            "ON executor_attempts(role) "
            "WHERE state IN ('RESERVED','LAUNCHING','RUNNING');"
        )
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        readiness = self.readiness()
        self.assertIn("registry_schema", readiness["blockers"])
        self.assertEqual(
            "EXECUTOR_ATTEMPT_TARGET_UNIQUENESS_REQUIRED",
            readiness["gates"]["registry_schema"][0]["error"],
        )

        with self.assertRaisesRegex(
            RegistryError, "EXECUTOR_ATTEMPT_SCHEMA_ACTIVE_CONFLICT"
        ):
            apply_plan(
                self.store.connection,
                plan=plan,
                operation_key="active-role-to-target-index",
                expected_plan_sha256=plan["plan_sha256"],
                now="2026-08-24T10:00:02Z",
            )
        self.assertIsNotNone(self.store.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' "
            "AND name='executor_one_active_attempt_per_role'"
        ).fetchone())
        self.assertIsNone(self.store.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' "
            "AND name='executor_one_active_attempt_per_target'"
        ).fetchone())

    def test_planner_repository_schema_upgrade_is_atomic_and_preserves_progress(self) -> None:
        self.migrate("planner-fence-upgrade-base")
        message_id = self.planner_notice(
            repository=REPOSITORY,
            issue_number=92,
            idempotency_key="planner-fence-upgrade-history",
        )
        reserved, token = reserve_attempt(
            self.store.connection,
            role="planner",
            endpoint_id=PLANNER_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="HOLD",
            now="2026-08-24T10:00:02Z",
            last_error="TEST_TERMINAL",
        )
        self.store.connection.execute(
            "DROP INDEX executor_one_active_planner_per_repository"
        )
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        self.assertTrue(plan["attempt_schema_upgrade"])
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="planner-fence-upgrade",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:03Z",
        )

        historical = self.store.connection.execute(
            "SELECT repository_scope,target_progress_sha256,state "
            "FROM executor_attempts WHERE attempt_id=?",
            (reserved["attempt_id"],),
        ).fetchone()
        self.assertEqual(REPOSITORY, historical["repository_scope"])
        self.assertEqual(reserved["target_progress_sha256"], historical["target_progress_sha256"])
        self.assertEqual("HOLD", historical["state"])
        self.assertTrue(attempt_schema_is_current(self.store.connection))
        self.assertEqual(
            [],
            self.store.connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE '%_legacy_schema'"
            ).fetchall(),
        )

    def test_planner_repository_schema_upgrade_active_conflict_rolls_back_cleanly(self) -> None:
        self.migrate("planner-fence-active-base")
        message_id = self.planner_notice(
            repository=REPOSITORY,
            issue_number=92,
            idempotency_key="planner-fence-active-conflict",
        )
        reserved, _token = reserve_attempt(
            self.store.connection,
            role="planner",
            endpoint_id=PLANNER_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        self.store.connection.execute(
            "DROP INDEX executor_one_active_planner_per_repository"
        )
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        with self.assertRaisesRegex(
            RegistryError, "EXECUTOR_ATTEMPT_SCHEMA_ACTIVE_CONFLICT"
        ):
            apply_plan(
                self.store.connection,
                plan=plan,
                operation_key="planner-fence-active-upgrade",
                expected_plan_sha256=plan["plan_sha256"],
                now="2026-08-24T10:00:02Z",
            )
        current = self.store.connection.execute(
            "SELECT state,repository_scope FROM executor_attempts WHERE attempt_id=?",
            (reserved["attempt_id"],),
        ).fetchone()
        self.assertEqual(("RESERVED", REPOSITORY), tuple(current))
        self.assertEqual(
            [],
            self.store.connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE '%_legacy_schema'"
            ).fetchall(),
        )

    def test_github_routing_hint_is_digest_only_and_comments_are_history(self) -> None:
        self.migrate()
        source = self.snapshot(
            body=f"Current owner: {DEVELOPMENT_UUID}",
            comments=[{"body": f"Historical receiver {DEVELOPMENT_UUID}"}],
        )
        plan = build_plan(
            self.store.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )
        self.assertEqual(1, len(plan["github_routing_inventory_hints"]))
        hint = plan["github_routing_inventory_hints"][0]
        self.assertEqual(source.payload_sha256, hint["source_payload_sha256"])
        self.assertEqual(1, hint["occurrence_count"])
        self.assertNotIn("desired_body", json.dumps(plan))
        self.assertEqual(
            "IMMUTABLE_PROVENANCE_NO_REWRITE",
            plan["github_comment_history"][0]["disposition"],
        )
        current = self.store.current_snapshot(REPOSITORY, "issue", 92)
        self.assertEqual(source.payload_sha256, current.payload_sha256)
        readiness = self.readiness()
        self.assertEqual("HOLD", readiness["phase"])
        self.assertTrue(readiness["gates"]["routing_deprecation_inventory"])

    def test_legacy_occurrence_order_is_independent_of_set_iteration(self) -> None:
        body = f"route {SRE_UUID} then {DEVELOPMENT_UUID}"
        occurrences = _legacy_occurrences(
            body,
            {SRE_UUID, DEVELOPMENT_UUID},
            "$.body",
        )
        self.assertEqual(
            [DEVELOPMENT_UUID, SRE_UUID],
            [item["alias"] for item in occurrences],
        )

    def test_archive_readiness_requires_frozen_inventory_without_ack_vector(self) -> None:
        self.snapshot()
        self.migrate()
        result = self.readiness()
        self.assertEqual("HOLD", result["phase"])
        self.assertEqual(["routing_deprecation_inventory"], result["blockers"])

    def test_archive_readiness_blocks_nonterminal_legacy_ack_but_allows_current_attempt(self) -> None:
        self.snapshot()
        self.migrate()
        current = self.store.connection.execute(
            "SELECT * FROM executor_role_endpoints "
            "WHERE endpoint_id=?",
            (DEVELOPMENT_ENDPOINT,),
        ).fetchone()
        self.store.connection.execute(
            "INSERT INTO executor_role_endpoints("
            "endpoint_id,role,version,executor_profile,codex_profile,config_sha256,"
            "config_json,command_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "role.development.v2",
                "development",
                2,
                "historical-development-profile",
                "historical-development-codex-profile",
                current["config_sha256"],
                current["config_json"],
                json.dumps(["codex", "exec", DEVELOPMENT_UUID]),
                "2026-08-24T10:00:00Z",
            ),
        )
        self.store.connection.execute(
            "CREATE TABLE ack_turns(contract_key TEXT PRIMARY KEY, session_id TEXT, "
            "turn_id TEXT, phase TEXT)"
        )
        self.store.connection.execute(
            "INSERT INTO ack_turns VALUES ('historic', ?, 'turn', 'COMPLETE')",
            (DEVELOPMENT_UUID,),
        )
        initial = self.readiness()
        self.assertEqual("HOLD", initial["phase"])
        self.assertEqual(["routing_deprecation_inventory"], initial["blockers"])
        self.store.connection.execute(
            "INSERT INTO ack_turns VALUES ('stale', ?, 'turn', 'RECEIVER_INFLIGHT')",
            (DEVELOPMENT_UUID,),
        )
        held = self.readiness()
        self.assertIn("legacy_ack_runtime", held["blockers"])
        source = self.store.current_snapshot(REPOSITORY, "issue", 92)
        message_id = self.store.enqueue_message(
            idempotency_key="healthy-current-attempt-target",
            recipient_session_id=DEVELOPMENT_ENDPOINT,
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
                "subject": "Healthy current attempt",
                "summary": "A current endpoint owns this fresh target.",
                "evidence": {},
            },
            now="2026-08-24T10:00:00Z",
        )
        reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-24T10:00:01Z",
            precondition=self.no_lineage,
        )
        active = self.readiness()
        self.assertNotIn("active_attempts", active["blockers"])
        self.assertIn("legacy_ack_runtime", active["blockers"])

    def test_archive_readiness_fails_closed_before_migration_and_finds_item(self) -> None:
        source = self.snapshot()
        with patch(
            "coordination_store.require_current_endpoint_identity",
            return_value=DEVELOPMENT_UUID,
        ):
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=92,
                status="ACTIVE",
                allocation_class="RETAINED",
                generation=1,
                accountable_session_id=DEVELOPMENT_UUID,
                lease_manifest_sha256=LEASE,
                development_units=1,
                shared_units=1,
                sre_units=0,
                expected_source_sha256=source.payload_sha256,
                expected_version=0,
                now="2026-08-24T09:00:02Z",
            )
        self.store.connection.executescript(
            """
            CREATE TABLE hosted_operations(
                id INTEGER PRIMARY KEY, recipient_session_id TEXT, state TEXT
            );
            CREATE TABLE approval_deliveries(
                proposal_sha256 TEXT, recipient_session_id TEXT, state TEXT
            );
            """
        )
        self.store.connection.execute(
            "INSERT INTO hosted_operations VALUES (328, ?, 'PREPARED')",
            (SRE_UUID,),
        )
        self.store.connection.execute(
            "INSERT INTO approval_deliveries VALUES (?, ?, 'WAITING_PUBLICATION')",
            ("8" * 64, DEVELOPMENT_UUID),
        )
        result = self.readiness()
        self.assertEqual("HOLD", result["phase"])
        self.assertEqual("REGISTRY_NOT_MIGRATED", result["error"])
        self.assertEqual(3, result["legacy_alias_count"])
        self.assertTrue(result["gates"]["current_pointers"])
        kinds = {entry["kind"] for entry in result["gates"]["local_current_routing"]}
        self.assertTrue(
            {"coordination_item", "hosted_operation", "approval_delivery"}.issubset(kinds)
        )

    def test_archive_readiness_blocks_incomplete_current_profile_contract(self) -> None:
        self.snapshot()
        self.migrate()
        self.store.connection.execute(
            "DROP TRIGGER executor_role_endpoint_immutable_update"
        )
        self.store.connection.execute(
            "UPDATE executor_role_endpoints SET codex_profile='' "
            f"WHERE endpoint_id='{DEVELOPMENT_ENDPOINT}'"
        )
        result = self.readiness()
        self.assertEqual("HOLD", result["phase"])
        self.assertEqual("REGISTRY_POINTER_INVALID", result["error"])
        self.assertEqual(
            ["development"],
            [entry["role"] for entry in result["gates"]["current_pointers"]],
        )

    def test_archive_readiness_preserves_terminal_history_and_blocks_actionable_history(self) -> None:
        self.snapshot()
        self.migrate()
        historical = {
            "accountable_session_id": DEVELOPMENT_UUID,
            "note": "immutable historical route",
        }
        historical_json = json.dumps(historical, sort_keys=True, separators=(",", ":"))
        historical_sha = hashlib.sha256(historical_json.encode("utf-8")).hexdigest()
        self.store.connection.executemany(
            "INSERT INTO coordination_messages("
            "idempotency_key,recipient_session_id,topic,payload_sha256,payload_json,"
            "state,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            [
                (
                    "terminal-historical-alias",
                    DEVELOPMENT_UUID,
                    "development.admission",
                    historical_sha,
                    historical_json,
                    "COMPLETE",
                    "2026-08-24T09:00:00Z",
                    "2026-08-24T09:00:00Z",
                ),
                (
                    "actionable-historical-alias",
                    DEVELOPMENT_UUID,
                    "development.admission",
                    historical_sha,
                    historical_json,
                    "PREPARED",
                    "2026-08-24T09:00:00Z",
                    "2026-08-24T09:00:00Z",
                ),
            ],
        )
        result = self.readiness()
        messages = result["gates"]["executable_commands"]
        self.assertEqual("HOLD", result["phase"])
        self.assertEqual(
            {"actionable-historical-alias"},
            {
                self.store.connection.execute(
                    "SELECT idempotency_key FROM coordination_messages WHERE id=?",
                    (entry["message_id"],),
                ).fetchone()[0]
                for entry in messages
                if entry["kind"] == "coordination_message"
            },
        )

    def test_archive_readiness_blocks_only_legacy_dependent_actionable_route(self) -> None:
        source = self.snapshot()
        self.migrate()
        self.store._set_issue_status_for_test_fixture(
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
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:1"
        with self.assertRaisesRegex(
            CoordinationError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
        ):
            self.store.heartbeat_terminal_watch(
                watch_key=watch_key,
                session_id=DEVELOPMENT_UUID,
                generation=1,
                delay_seconds=60,
                now="2026-08-24T10:00:02Z",
            )
        self.store.connection.execute(
            "UPDATE coordination_items SET accountable_session_id=? WHERE issue_number=92",
            (DEVELOPMENT_UUID,),
        )
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET accountable_session_id=?",
            (DEVELOPMENT_UUID,),
        )
        result = self.readiness()
        self.assertEqual("HOLD", result["phase"])
        self.assertEqual(
            {"coordination_item", "terminal_watch"},
            {entry["kind"] for entry in result["gates"]["local_current_routing"]},
        )

    def test_canonical_goal_and_agents_are_fail_closed_instruction_inputs(self) -> None:
        self.snapshot()
        self.migrate()
        temp = Path(self.temp.name)
        missing_goal = temp / "missing-product-planner-goal.md"
        with patch(
            "archive_readiness_audit.CANONICAL_PLANNER_GOAL", missing_goal
        ):
            missing = self.readiness()
        self.assertEqual("HOLD", missing["phase"])
        self.assertIn(
            "CANONICAL_PLANNER_GOAL_MISSING",
            {
                entry.get("error")
                for entry in missing["gates"]["executable_commands"]
            },
        )

        legacy_goal = temp / "product-planner-goal.md"
        legacy_goal.write_text(
            "Run codex exec resume 22222222-2222-4222-8222-222222222222\n",
            encoding="utf-8",
        )
        with patch(
            "archive_readiness_audit.CANONICAL_PLANNER_GOAL", legacy_goal
        ):
            legacy = self.readiness()
        self.assertEqual("HOLD", legacy["phase"])
        self.assertTrue(any(
            entry.get("path") == str(legacy_goal)
            for entry in legacy["gates"]["executable_commands"]
        ))

        safe_goal = temp / "safe-product-planner-goal.md"
        safe_goal.write_text("Use only current role endpoints.\n", encoding="utf-8")
        legacy_agents = temp / "AGENTS.md"
        legacy_agents.write_text(
            "Launch codex exec resume 33333333-3333-4333-8333-333333333333\n",
            encoding="utf-8",
        )
        with (
            patch("archive_readiness_audit.CANONICAL_PLANNER_GOAL", safe_goal),
            patch("archive_readiness_audit.CANONICAL_AGENTS", legacy_agents),
        ):
            agents = self.readiness()
        self.assertEqual("HOLD", agents["phase"])
        self.assertTrue(any(
            entry.get("path") == str(legacy_agents)
            for entry in agents["gates"]["executable_commands"]
        ))

    def test_fresh_command_builder_rejects_resume_uuid_and_bypass(self) -> None:
        command = build_fresh_command(
            ["/home/ubuntu/.local/bin/codex", "exec", "--json"], "work"
        )
        self.assertEqual("work", command[-1])
        invalid_suffixes = (
            ["resume"],
            ["22222222-2222-4222-8222-222222222222"],
            ["--dangerously-bypass-approvals-and-sandbox"],
            ["--dangerously-bypass-hook-trust"],
        )
        for suffix in invalid_suffixes:
            with self.subTest(suffix=suffix), self.assertRaisesRegex(
                RegistryError, "EXECUTOR_COMMAND_INVALID"
            ):
                build_fresh_command(
                    ["/home/ubuntu/.local/bin/codex", "exec", *suffix], "work"
                )


if __name__ == "__main__":
    unittest.main()
