from __future__ import annotations

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
sys.path.insert(0, str(SCRIPTS))

from executor_registry import (  # noqa: E402
    ROLES,
    RegistryError,
    ensure_executor_registry_schema,
    load_registry_config,
    require_current_endpoint_identity,
)
from reconcile_routing_artifacts import (  # noqa: E402
    _verify_or_insert_endpoint,
    build_plan,
    load_legacy_alias_fixture,
    migrate_plan,
    rollback_change,
)


CONFIG = ROOT / "references" / "twinfinity-executor-registry.toml"
ALIASES = ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"


class RoutingMigrationAtomicityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.connection = sqlite3.connect(
            Path(self.temp.name) / "routing.sqlite3",
            isolation_level=None,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript(
            """
            CREATE TABLE coordination_items (
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL,
                accountable_session_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(repository, issue_number)
            );
            CREATE TABLE coordination_terminal_watches (
                watch_key TEXT PRIMARY KEY,
                accountable_session_id TEXT NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        (
            self.config,
            self.aliases,
            self.alias_sha,
            _config_path,
            _alias_path,
            _template_root,
            _codex_home,
        ) = self._copied_review_inputs()
        self.alias_by_role = {
            entry["role"]: entry["alias"] for entry in self.aliases
        }

    def tearDown(self) -> None:
        self.connection.close()
        self.temp.cleanup()

    def _insert_legacy_item_and_watch(self, suffix: str) -> None:
        identity = self.alias_by_role["development"]
        self.connection.execute(
            """
            INSERT INTO coordination_items(
                repository, issue_number, accountable_session_id, version, updated_at
            ) VALUES (?, ?, ?, 1, ?)
            """,
            ("twinfinityai/twinfinityapp", int(suffix), identity, "2026-08-24T09:00:00Z"),
        )
        self.connection.execute(
            """
            INSERT INTO coordination_terminal_watches(
                watch_key, accountable_session_id, state, updated_at
            ) VALUES (?, ?, 'ACTIVE', ?)
            """,
            (f"watch-{suffix}", identity, "2026-08-24T09:00:01Z"),
        )

    def _routing_state_bytes(self) -> bytes:
        schema = [
            tuple(row)
            for row in self.connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            ).fetchall()
        ]
        rows: dict[str, list[tuple[object, ...]]] = {}
        for table in (
            "coordination_items",
            "coordination_terminal_watches",
            "executor_role_endpoint_current",
            "executor_registry_changes",
        ):
            exists = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if exists is not None:
                rows[table] = [
                    tuple(row)
                    for row in self.connection.execute(
                        f"SELECT * FROM {table} ORDER BY rowid"
                    ).fetchall()
                ]
        return json.dumps(
            {"schema": schema, "rows": rows},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _dry_run_plan(self) -> dict:
        return build_plan(
            self.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )

    def _copied_review_inputs(self):
        root = Path(tempfile.mkdtemp(prefix="review-inputs-", dir=self.temp.name))
        template_root = root / "templates"
        codex_home = root / "installed"
        template_root.mkdir(parents=True)
        codex_home.mkdir()
        config_path = root / "registry.toml"
        alias_path = root / "aliases.json"
        shutil.copy2(CONFIG, config_path)
        shutil.copy2(ALIASES, alias_path)
        for profile in (
            "twinfinity-planner-v2",
            "twinfinity-development-v3",
            "twinfinity-development-v4",
            "twinfinity-development-v5",
            "twinfinity-sre-v3",
            "twinfinity-sre-v4",
            "twinfinity-sre-v5",
        ):
            source = ROOT / "references" / f"{profile}.config.toml"
            shutil.copy2(source, template_root / source.name)
            shutil.copy2(source, codex_home / source.name)
        config = load_registry_config(
            config_path,
            codex_home=codex_home,
            profile_template_root=template_root,
        )
        aliases, alias_sha = load_legacy_alias_fixture(alias_path)
        return config, aliases, alias_sha, config_path, alias_path, template_root, codex_home

    @staticmethod
    def _replace_with_same_bytes(path: Path) -> None:
        replacement = path.with_name(f"{path.name}.replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(path.stat().st_mode & 0o777)
        os.replace(replacement, path)

    def _migrate(self, plan: dict, operation_key: str) -> dict:
        return migrate_plan(
            self.connection,
            config=self.config,
            aliases=self.aliases,
            alias_fixture_sha256=self.alias_sha,
            operation_key=operation_key,
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:00Z",
        )

    def test_wrong_reviewed_digest_changes_no_schema_or_routing_bytes(self) -> None:
        self._insert_legacy_item_and_watch("101")
        before = self._routing_state_bytes()

        with self.assertRaisesRegex(
            RegistryError, "REGISTRY_MIGRATION_PLAN_MISMATCH"
        ):
            migrate_plan(
                self.connection,
                config=self.config,
                aliases=self.aliases,
                alias_fixture_sha256=self.alias_sha,
                operation_key="wrong-reviewed-digest",
                expected_plan_sha256="0" * 64,
                now="2026-08-24T10:00:00Z",
            )

        self.assertEqual(before, self._routing_state_bytes())

    def test_phantom_after_external_dry_run_has_zero_migration_effects(self) -> None:
        reviewed = self._dry_run_plan()
        self._insert_legacy_item_and_watch("102")
        before = self._routing_state_bytes()

        with self.assertRaisesRegex(
            RegistryError, "REGISTRY_MIGRATION_PLAN_MISMATCH"
        ):
            self._migrate(reviewed, "phantom-after-dry-run")

        self.assertEqual(before, self._routing_state_bytes())
        self.assertIsNone(
            self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='executor_registry_changes'"
            ).fetchone()
        )

    def test_registry_rename_swap_after_review_has_zero_sqlite_effects(self) -> None:
        (
            config,
            aliases,
            alias_sha,
            config_path,
            _alias_path,
            _template_root,
            _codex_home,
        ) = self._copied_review_inputs()
        reviewed = build_plan(
            self.connection, config, aliases, alias_fixture_sha256=alias_sha
        )
        before = self._routing_state_bytes()
        self._replace_with_same_bytes(config_path)

        with self.assertRaisesRegex(RegistryError, "REGISTRY_CONFIG_DRIFT"):
            migrate_plan(
                self.connection,
                config=config,
                aliases=aliases,
                alias_fixture_sha256=alias_sha,
                operation_key="registry-rename-swap",
                expected_plan_sha256=reviewed["plan_sha256"],
                now="2026-08-24T10:00:00Z",
            )

        self.assertEqual(before, self._routing_state_bytes())

    def test_alias_truncate_after_review_has_zero_sqlite_effects(self) -> None:
        (
            config,
            aliases,
            alias_sha,
            _config_path,
            alias_path,
            _template_root,
            _codex_home,
        ) = self._copied_review_inputs()
        reviewed = build_plan(
            self.connection, config, aliases, alias_fixture_sha256=alias_sha
        )
        before = self._routing_state_bytes()
        alias_path.write_bytes(alias_path.read_bytes()[:-1])

        with self.assertRaisesRegex(RegistryError, "LEGACY_ALIAS_FILE_DRIFT"):
            migrate_plan(
                self.connection,
                config=config,
                aliases=aliases,
                alias_fixture_sha256=alias_sha,
                operation_key="alias-truncate",
                expected_plan_sha256=reviewed["plan_sha256"],
                now="2026-08-24T10:00:00Z",
            )

        self.assertEqual(before, self._routing_state_bytes())

    def test_template_and_installed_profile_swaps_have_zero_sqlite_effects(self) -> None:
        for source_kind in ("template", "installed"):
            with self.subTest(source_kind=source_kind):
                (
                    config,
                    aliases,
                    alias_sha,
                    _config_path,
                    _alias_path,
                    template_root,
                    codex_home,
                ) = self._copied_review_inputs()
                reviewed = build_plan(
                    self.connection, config, aliases, alias_fixture_sha256=alias_sha
                )
                before = self._routing_state_bytes()
                root = template_root if source_kind == "template" else codex_home
                self._replace_with_same_bytes(
                    root / "twinfinity-development-v5.config.toml"
                )

                with self.assertRaisesRegex(RegistryError, "REGISTRY_PROFILE_DRIFT"):
                    migrate_plan(
                        self.connection,
                        config=config,
                        aliases=aliases,
                        alias_fixture_sha256=alias_sha,
                        operation_key=f"{source_kind}-profile-swap",
                        expected_plan_sha256=reviewed["plan_sha256"],
                        now="2026-08-24T10:00:00Z",
                    )

                self.assertEqual(before, self._routing_state_bytes())

    def test_apply_is_atomic_and_first_cutover_rollback_is_forbidden(self) -> None:
        self._insert_legacy_item_and_watch("103")
        reviewed = self._dry_run_plan()
        statements: list[str] = []
        self.connection.set_trace_callback(statements.append)
        try:
            applied = self._migrate(reviewed, "atomic-apply-replay-rollback")
        finally:
            self.connection.set_trace_callback(None)

        controls = [statement.strip().upper() for statement in statements]
        self.assertEqual(1, controls.count("BEGIN IMMEDIATE"))
        self.assertEqual(1, controls.count("COMMIT"))
        self.assertEqual("BEGIN IMMEDIATE", controls[0])
        self.assertEqual("COMMIT", controls[-1])

        replayed = self._migrate(reviewed, "atomic-apply-replay-rollback")
        self.assertEqual(applied["change_id"], replayed["change_id"])

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "REGISTRY_ROLLBACK_PRECUTOVER_FORBIDDEN"
        ):
            rollback_change(
                self.connection,
                change_id=applied["change_id"],
                expected_version=1,
                now="2026-08-24T10:00:01Z",
            )
        item = self.connection.execute(
            "SELECT accountable_session_id, version FROM coordination_items"
        ).fetchone()
        watch = self.connection.execute(
            "SELECT accountable_session_id FROM coordination_terminal_watches"
        ).fetchone()
        self.assertEqual((self.config.roles["development"].endpoint_id, 2), tuple(item))
        self.assertEqual(self.config.roles["development"].endpoint_id, watch[0])
        self.assertEqual(
            3,
            self.connection.execute(
                "SELECT COUNT(*) FROM executor_role_endpoint_current"
            ).fetchone()[0],
        )

    def test_versioned_cutover_preserves_immutable_legacy_alias_provenance(self) -> None:
        ensure_executor_registry_schema(self.connection)
        now = "2026-08-24T09:00:00Z"
        for role in ROLES:
            _verify_or_insert_endpoint(
                self.connection, self.config.roles[role].payload, now
            )

        prior_endpoints = {
            "development": "role.development.v3",
            "sre": "role.sre.v3",
        }
        for role, endpoint_id in prior_endpoints.items():
            self.connection.execute(
                """
                INSERT INTO executor_role_endpoints(
                    endpoint_id, role, version, executor_profile, codex_profile,
                    config_sha256, config_json, command_json, created_at
                ) VALUES (?, ?, 3, ?, ?, ?, '{}', '[]', ?)
                """,
                (
                    endpoint_id,
                    role,
                    role,
                    f"twinfinity-{role}",
                    {"development": "d", "sre": "e"}[role] * 64,
                    now,
                ),
            )

        current_by_role = {
            "planner": self.config.roles["planner"].endpoint_id,
            **prior_endpoints,
        }
        for role, endpoint_id in current_by_role.items():
            self.connection.execute(
                """
                INSERT INTO executor_role_endpoint_current(
                    role, endpoint_id, pointer_version, updated_at
                ) VALUES (?, ?, 1, ?)
                """,
                (role, endpoint_id, now),
            )
        for entry in self.aliases:
            self.connection.execute(
                """
                INSERT INTO executor_role_endpoint_aliases(
                    alias, role, endpoint_id, source, created_at
                ) VALUES (?, ?, ?, 'legacy-fixture', ?)
                """,
                (entry["alias"], entry["role"], current_by_role[entry["role"]], now),
            )

        reviewed = self._dry_run_plan()
        self._migrate(reviewed, "versioned-endpoint-cutover")

        pointers = {
            row["role"]: (row["endpoint_id"], row["pointer_version"])
            for row in self.connection.execute(
                "SELECT role, endpoint_id, pointer_version "
                "FROM executor_role_endpoint_current"
            )
        }
        self.assertEqual(
            (self.config.roles["development"].endpoint_id, 2),
            pointers["development"],
        )
        self.assertEqual(
            (self.config.roles["sre"].endpoint_id, 2), pointers["sre"]
        )
        self.assertEqual(
            (self.config.roles["planner"].endpoint_id, 1), pointers["planner"]
        )
        preserved = {
            row["endpoint_id"]: (row["role"], row["version"])
            for row in self.connection.execute(
                "SELECT endpoint_id, role, version FROM executor_role_endpoints "
                "WHERE endpoint_id IN (?, ?)",
                (prior_endpoints["development"], prior_endpoints["sre"]),
            )
        }
        self.assertEqual(
            {
                "role.development.v3": ("development", 3),
                "role.sre.v3": ("sre", 3),
            },
            preserved,
        )
        for entry in self.aliases:
            stored = self.connection.execute(
                "SELECT endpoint_id FROM executor_role_endpoint_aliases WHERE alias=?",
                (entry["alias"],),
            ).fetchone()
            self.assertEqual(current_by_role[entry["role"]], stored["endpoint_id"])
            with patch(
                "executor_registry.load_registry_config", return_value=self.config
            ), self.assertRaisesRegex(
                RegistryError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
            ):
                require_current_endpoint_identity(
                    self.connection,
                    entry["alias"],
                    expected_role=entry["role"],
                )

    def test_versioned_cutover_rejects_alias_bound_to_wrong_role_endpoint(self) -> None:
        ensure_executor_registry_schema(self.connection)
        now = "2026-08-24T09:00:00Z"
        for role in ROLES:
            _verify_or_insert_endpoint(
                self.connection, self.config.roles[role].payload, now
            )
        development_alias = self.alias_by_role["development"]
        self.connection.execute(
            """
            INSERT INTO executor_role_endpoint_aliases(
                alias, role, endpoint_id, source, created_at
            ) VALUES (?, 'development', ?, 'legacy-fixture', ?)
            """,
            (development_alias, self.config.roles["sre"].endpoint_id, now),
        )
        reviewed = self._dry_run_plan()
        before = self._routing_state_bytes()

        with self.assertRaisesRegex(
            RegistryError, "EXECUTOR_ALIAS_IMMUTABLE_CONFLICT"
        ):
            self._migrate(reviewed, "wrong-role-alias-endpoint")

        self.assertEqual(before, self._routing_state_bytes())


if __name__ == "__main__":
    unittest.main()
