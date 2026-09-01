from __future__ import annotations

import copy
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from executor_registry import (  # noqa: E402
    RegistryError,
    ensure_executor_registry_schema,
    load_registry_config,
)
from reconcile_routing_artifacts import (  # noqa: E402
    _verify_or_insert_endpoint,
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
    migrate_plan,
    rollback_change,
)


CONFIG = ROOT / "references" / "twinfinity-executor-registry.toml"
ALIASES = ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
REPOSITORY = "twinfinityai/twinfinityapp"
DEVELOPMENT_V3 = "role.development.v3"
DEVELOPMENT_V6 = "role.development.v6"
SRE_V3 = "role.sre.v3"
SRE_V6 = "role.sre.v6"
NOW = "2026-08-26T08:45:00Z"
APPLY_NOW = "2026-08-26T08:46:00Z"
ROLLBACK_NOW = "2026-08-26T08:47:00Z"


class CurrentEndpointOwnerRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.connection = sqlite3.connect(
            Path(self.temp.name) / "routing.sqlite3", isolation_level=None
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript(
            """
            CREATE TABLE coordination_items (
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                allocation_class TEXT NOT NULL,
                generation INTEGER NOT NULL,
                accountable_session_id TEXT,
                lease_manifest_sha256 TEXT,
                development_units INTEGER NOT NULL,
                shared_units INTEGER NOT NULL,
                sre_units INTEGER NOT NULL,
                source_payload_sha256 TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(repository, issue_number)
            );
            CREATE TABLE coordination_terminal_watches (
                watch_key TEXT PRIMARY KEY,
                accountable_session_id TEXT NOT NULL,
                lease_manifest_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                admission_message_id INTEGER,
                admission_payload_sha256 TEXT,
                claim_attempt_id TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE coordination_messages (
                id INTEGER PRIMARY KEY,
                recipient_session_id TEXT NOT NULL,
                topic TEXT NOT NULL,
                state TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            );
            """
        )
        self.config = load_registry_config(
            CONFIG,
            codex_home=ROOT / "references",
            profile_template_root=ROOT / "references",
            profile_validation_scope="catalog",
        )
        self.aliases, self.alias_sha = load_legacy_alias_fixture(ALIASES)
        ensure_executor_registry_schema(self.connection)
        for endpoint in self.config.endpoints.values():
            _verify_or_insert_endpoint(self.connection, endpoint.payload, NOW)
        for role, endpoint_id in (
            ("planner", self.config.roles["planner"].endpoint_id),
            ("development", DEVELOPMENT_V3),
            ("sre", SRE_V3),
        ):
            self.connection.execute(
                "INSERT INTO executor_role_endpoint_current"
                "(role,endpoint_id,pointer_version,updated_at) VALUES (?,?,1,?)",
                (role, endpoint_id, NOW),
            )
        self._seed_routing()

    def tearDown(self) -> None:
        self.connection.close()
        self.temp.cleanup()

    def _seed_routing(self) -> None:
        items = (
            (328, "ACTIVE", "ACTIVE", 6, DEVELOPMENT_V3, "a" * 64, 1, 0, 0, "1" * 64, 9),
            (329, "HOLD", "RETAINED", 2, DEVELOPMENT_V3, "b" * 64, 1, 1, 0, "2" * 64, 6),
            (330, "DONE", "NONE", 3, DEVELOPMENT_V3, None, 0, 0, 0, "3" * 64, 4),
            (320, "HOLD", "RETAINED", 4, SRE_V3, "c" * 64, 0, 0, 1, "4" * 64, 7),
        )
        self.connection.executemany(
            """
            INSERT INTO coordination_items(
                repository,issue_number,status,allocation_class,generation,
                accountable_session_id,lease_manifest_sha256,development_units,
                shared_units,sre_units,source_payload_sha256,version,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            [(REPOSITORY, *item, NOW) for item in items],
        )
        watches = (
            ("watch-328", DEVELOPMENT_V3, "a" * 64, "ACTIVE", 17, "5" * 64, "attempt-328"),
            ("watch-329", DEVELOPMENT_V3, "b" * 64, "HOLD", 16, "6" * 64, "attempt-329"),
            ("watch-330", DEVELOPMENT_V3, "d" * 64, "COMPLETE", 15, "7" * 64, "attempt-330"),
            ("watch-320", SRE_V3, "c" * 64, "HOLD", 14, "8" * 64, "attempt-320"),
        )
        self.connection.executemany(
            """
            INSERT INTO coordination_terminal_watches(
                watch_key,accountable_session_id,lease_manifest_sha256,state,
                admission_message_id,admission_payload_sha256,claim_attempt_id,
                updated_at
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            [(*watch, NOW) for watch in watches],
        )
        self.connection.execute(
            "INSERT INTO coordination_messages VALUES"
            "(17,?,'development.admission','CLAIMED',?)",
            (DEVELOPMENT_V3, "5" * 64),
        )

    def _plan(self) -> dict:
        return build_plan(
            self.connection,
            self.config,
            self.aliases,
            alias_fixture_sha256=self.alias_sha,
        )

    def _migrate(self, plan: dict, key: str) -> dict:
        return migrate_plan(
            self.connection,
            config=self.config,
            aliases=self.aliases,
            alias_fixture_sha256=self.alias_sha,
            operation_key=key,
            expected_plan_sha256=plan["plan_sha256"],
            now=APPLY_NOW,
        )

    def test_v3_to_v6_apply_replay_and_rollback_preserve_lineage(self) -> None:
        before_items = {
            row["issue_number"]: dict(row)
            for row in self.connection.execute("SELECT * FROM coordination_items")
        }
        before_watches = {
            row["watch_key"]: dict(row)
            for row in self.connection.execute(
                "SELECT * FROM coordination_terminal_watches"
            )
        }
        before_message = dict(
            self.connection.execute("SELECT * FROM coordination_messages").fetchone()
        )
        plan = self._plan()
        self.assertEqual(
            [
                ("development", DEVELOPMENT_V3, DEVELOPMENT_V6),
                ("sre", SRE_V3, SRE_V6),
            ],
            [
                (change["role"], change["before_endpoint_id"], change["after_endpoint_id"])
                for change in plan["pointer_changes"]
                if change["before_endpoint_id"] != change["after_endpoint_id"]
            ],
        )
        self.assertEqual(
            {320, 328, 329},
            {row["issue_number"] for row in plan["item_changes"]},
        )
        self.assertEqual(
            {"watch-320", "watch-328", "watch-329"},
            {row["watch_key"] for row in plan["watch_changes"]},
        )

        applied = self._migrate(plan, "execution-v6-owner-rotation")
        self.assertEqual(applied["change_id"], self._migrate(
            plan, "execution-v6-owner-rotation"
        )["change_id"])
        for issue in (328, 329):
            after = dict(self.connection.execute(
                "SELECT * FROM coordination_items WHERE issue_number=?", (issue,)
            ).fetchone())
            self.assertEqual(DEVELOPMENT_V6, after["accountable_session_id"])
            self.assertEqual(before_items[issue]["version"] + 1, after["version"])
            for field in (
                "status", "allocation_class", "generation", "lease_manifest_sha256",
                "development_units", "shared_units", "sre_units", "source_payload_sha256",
            ):
                self.assertEqual(before_items[issue][field], after[field])
        for key in ("watch-328", "watch-329"):
            after = dict(self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?", (key,)
            ).fetchone())
            self.assertEqual(DEVELOPMENT_V6, after["accountable_session_id"])
            for field in (
                "lease_manifest_sha256", "state", "admission_message_id",
                "admission_payload_sha256", "claim_attempt_id",
            ):
                self.assertEqual(before_watches[key][field], after[field])
        after_320 = dict(self.connection.execute(
            "SELECT * FROM coordination_items WHERE issue_number=320"
        ).fetchone())
        self.assertEqual(SRE_V6, after_320["accountable_session_id"])
        self.assertEqual(before_items[320]["version"] + 1, after_320["version"])
        for field in (
            "status", "allocation_class", "generation", "lease_manifest_sha256",
            "development_units", "shared_units", "sre_units", "source_payload_sha256",
        ):
            self.assertEqual(before_items[320][field], after_320[field])
        after_watch_320 = dict(self.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key='watch-320'"
        ).fetchone())
        self.assertEqual(SRE_V6, after_watch_320["accountable_session_id"])
        for field in (
            "lease_manifest_sha256", "state", "admission_message_id",
            "admission_payload_sha256", "claim_attempt_id",
        ):
            self.assertEqual(before_watches["watch-320"][field], after_watch_320[field])
        for issue in (330,):
            self.assertEqual(before_items[issue], dict(self.connection.execute(
                "SELECT * FROM coordination_items WHERE issue_number=?", (issue,)
            ).fetchone()))
        for key in ("watch-330",):
            self.assertEqual(before_watches[key], dict(self.connection.execute(
                "SELECT * FROM coordination_terminal_watches WHERE watch_key=?", (key,)
            ).fetchone()))
        self.assertEqual(before_message, dict(
            self.connection.execute("SELECT * FROM coordination_messages").fetchone()
        ))

        rolled_back = rollback_change(
            self.connection,
            change_id=applied["change_id"],
            expected_version=1,
            now=ROLLBACK_NOW,
        )
        self.assertEqual("ROLLED_BACK", rolled_back["state"])
        self.assertEqual(rolled_back["version"], rollback_change(
            self.connection,
            change_id=applied["change_id"],
            expected_version=1,
            now=ROLLBACK_NOW,
        )["version"])
        self.assertEqual(
            (DEVELOPMENT_V3, 3),
            tuple(self.connection.execute(
                "SELECT endpoint_id,pointer_version FROM executor_role_endpoint_current "
                "WHERE role='development'"
            ).fetchone()),
        )
        self.assertEqual(
            (SRE_V3, 3),
            tuple(self.connection.execute(
                "SELECT endpoint_id,pointer_version FROM executor_role_endpoint_current "
                "WHERE role='sre'"
            ).fetchone()),
        )
        self.assertEqual(
            {DEVELOPMENT_V3},
            {row[0] for row in self.connection.execute(
                "SELECT accountable_session_id FROM coordination_items "
                "WHERE issue_number IN (328,329)"
            )},
        )
        self.assertEqual(
            SRE_V3,
            self.connection.execute(
                "SELECT accountable_session_id FROM coordination_items "
                "WHERE issue_number=320"
            ).fetchone()[0],
        )

    def test_plan_digest_and_forward_cas_fail_closed(self) -> None:
        plan = self._plan()
        before = "\n".join(self.connection.iterdump())
        tampered = copy.deepcopy(plan)
        tampered["item_changes"][0]["after_identity"] = SRE_V3
        with self.assertRaisesRegex(RegistryError, "REGISTRY_MIGRATION_PLAN_MISMATCH"):
            apply_plan(
                self.connection,
                plan=tampered,
                operation_key="tampered",
                expected_plan_sha256=plan["plan_sha256"],
                now=APPLY_NOW,
            )
        self.assertEqual(before, "\n".join(self.connection.iterdump()))

        self.connection.execute(
            "UPDATE coordination_items SET version=version+1 WHERE issue_number=328"
        )
        with self.assertRaisesRegex(RegistryError, "REGISTRY_MIGRATION_PLAN_MISMATCH"):
            self._migrate(plan, "stale-forward-cas")
        self.assertEqual(
            (DEVELOPMENT_V3, 1),
            tuple(self.connection.execute(
                "SELECT endpoint_id,pointer_version FROM executor_role_endpoint_current "
                "WHERE role='development'"
            ).fetchone()),
        )

    def test_rollback_item_cas_conflict_is_atomic(self) -> None:
        applied = self._migrate(self._plan(), "rollback-item-cas")
        self.connection.execute(
            "UPDATE coordination_items SET version=version+1 WHERE issue_number=329"
        )
        with self.assertRaisesRegex(RegistryError, "REGISTRY_ROLLBACK_ITEM_CONFLICT"):
            rollback_change(
                self.connection,
                change_id=applied["change_id"],
                expected_version=1,
                now=ROLLBACK_NOW,
            )
        self.assertEqual(
            (DEVELOPMENT_V6, 2),
            tuple(self.connection.execute(
                "SELECT endpoint_id,pointer_version FROM executor_role_endpoint_current "
                "WHERE role='development'"
            ).fetchone()),
        )
        self.assertEqual(
            (SRE_V6, 2),
            tuple(self.connection.execute(
                "SELECT endpoint_id,pointer_version FROM executor_role_endpoint_current "
                "WHERE role='sre'"
            ).fetchone()),
        )
        self.assertEqual(
            {DEVELOPMENT_V6},
            {row[0] for row in self.connection.execute(
                "SELECT accountable_session_id FROM coordination_terminal_watches "
                "WHERE watch_key IN ('watch-328','watch-329')"
            )},
        )
        self.assertEqual("APPLIED", self.connection.execute(
            "SELECT state FROM executor_registry_changes WHERE change_id=?",
            (applied["change_id"],),
        ).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
