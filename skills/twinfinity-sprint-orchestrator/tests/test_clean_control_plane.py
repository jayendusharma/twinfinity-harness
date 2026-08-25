from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

import clean_control_plane as clean


SOURCE_ROOT = SKILL_ROOT.parents[1]
HARNESS_MAIN = subprocess.run(
    ["git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
APPLICATION_MAIN = "a" * 40
NOW = "2026-08-25T20:00:00Z"
AUTHORITATIVE_STRANDED_IDENTITIES = (
    (328, 2, "c448fd19-40a6-4511-bdf7-9ca7bbbb2788"),
    (329, 1, "d7f69b5a-dc4c-4d1e-b434-da4ab6cdb2d5"),
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CleanControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="clean-control-plane-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.archive = self.root / "old-archive.sqlite3"
        connection = sqlite3.connect(self.archive)
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE portfolio_readiness_campaigns(
                id INTEGER PRIMARY KEY, repository TEXT, issue_number INTEGER,
                generation INTEGER, item_version INTEGER,
                source_payload_sha256 TEXT, accepted_main_sha TEXT,
                graph_version INTEGER, capacity_policy_version INTEGER,
                candidate_sha256 TEXT, worker_role TEXT, phase_summary TEXT,
                plan_sha256 TEXT, plan_json TEXT, parent_campaign_id INTEGER,
                transition_kind TEXT, resolution_ordinal INTEGER,
                changed_evidence_sha256 TEXT,
                resolution_action_set_sha256 TEXT,
                approval_proposal_sha256 TEXT,
                approval_decision_sha256 TEXT,
                approval_recipient_session_id TEXT,
                approval_execution_scope_sha256 TEXT,
                created_at TEXT
            );
            CREATE TABLE portfolio_readiness_current(
                repository TEXT, issue_number INTEGER, campaign_id INTEGER,
                state TEXT, message_id INTEGER, attempt_id TEXT,
                endpoint_id TEXT, version INTEGER
            );
            CREATE TABLE portfolio_pull_buffer_candidates(
                repository TEXT, issue_number INTEGER, candidate_sha256 TEXT,
                state TEXT
            );
            CREATE TABLE coordination_messages(
                id INTEGER PRIMARY KEY, state TEXT, payload_sha256 TEXT
            );
            CREATE TABLE executor_attempts(
                attempt_id TEXT PRIMARY KEY, state TEXT, target_kind TEXT,
                target_key TEXT, endpoint_id TEXT
            );
            CREATE TABLE portfolio_readiness_receipts(campaign_id INTEGER);
            """
        )
        self.archive_lineages: list[dict[str, object]] = []
        for ordinal, (issue_number, campaign_id, attempt_id) in enumerate(
            AUTHORITATIVE_STRANDED_IDENTITIES, start=1
        ):
            message_id = 3_000 + issue_number
            source_sha = f"{ordinal}" * 64
            candidate_sha = f"{ordinal + 2}" * 64
            message_sha = f"{ordinal + 4}" * 64
            plan = {"campaign_id": campaign_id, "issue_number": issue_number}
            plan_json = clean.canonical_json(plan)
            plan_sha = clean.digest_json(plan)
            endpoint_id = (
                "role.development.v5" if issue_number == 328 else "role.sre.v5"
            )
            projection = {
                "campaign_id": campaign_id,
                "repository": "twinfinityai/twinfinityapp",
                "issue_number": issue_number,
                "generation": 1,
                "item_version": 1,
                "source_payload_sha256": source_sha,
                "accepted_main_sha": APPLICATION_MAIN,
                "graph_version": 1,
                "capacity_policy_version": 1,
                "candidate_sha256": candidate_sha,
                "worker_role": "development" if issue_number == 328 else "sre",
                "phase_summary": "stranded malformed readiness",
                "plan_sha256": plan_sha,
                "plan_json": plan_json,
                "parent_campaign_id": None,
                "transition_kind": None,
                "resolution_ordinal": 0,
                "campaign_state": "RUNNING",
                "message_id": message_id,
                "attempt_id": attempt_id,
                "endpoint_id": endpoint_id,
                "current_version": 2,
            }
            connection.execute(
                """
                INSERT INTO portfolio_readiness_campaigns(
                    id,repository,issue_number,generation,item_version,
                    source_payload_sha256,accepted_main_sha,graph_version,
                    capacity_policy_version,candidate_sha256,worker_role,
                    phase_summary,plan_sha256,plan_json,parent_campaign_id,
                    transition_kind,resolution_ordinal,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    campaign_id,
                    projection["repository"],
                    issue_number,
                    projection["generation"],
                    projection["item_version"],
                    source_sha,
                    APPLICATION_MAIN,
                    projection["graph_version"],
                    projection["capacity_policy_version"],
                    candidate_sha,
                    projection["worker_role"],
                    projection["phase_summary"],
                    plan_sha,
                    plan_json,
                    None,
                    None,
                    0,
                    NOW,
                ),
            )
            connection.execute(
                "INSERT INTO portfolio_readiness_current VALUES(?,?,?,?,?,?,?,?)",
                (
                    projection["repository"],
                    issue_number,
                    campaign_id,
                    projection["campaign_state"],
                    message_id,
                    attempt_id,
                    endpoint_id,
                    projection["current_version"],
                ),
            )
            connection.execute(
                "INSERT INTO portfolio_pull_buffer_candidates VALUES(?,?,?,?)",
                (
                    projection["repository"],
                    issue_number,
                    candidate_sha,
                    "PREPARED_NOT_READY",
                ),
            )
            connection.execute(
                "INSERT INTO coordination_messages VALUES(?,?,?)",
                (message_id, "CLAIMED", message_sha),
            )
            connection.execute(
                "INSERT INTO executor_attempts VALUES(?,?,?,?,?)",
                (attempt_id, "COMPLETE", "message", str(message_id), endpoint_id),
            )
            self.archive_lineages.append(
                {
                    "repository": projection["repository"],
                    "issue_number": issue_number,
                    "campaign_id": campaign_id,
                    "attempt_id": attempt_id,
                    "source_payload_sha256": source_sha,
                    "campaign_sha256": clean.digest_json(projection),
                    "candidate_sha256": candidate_sha,
                    "plan_sha256": plan_sha,
                    "message_payload_sha256": message_sha,
                    "campaign_state": "RUNNING",
                    "candidate_state": "PREPARED_NOT_READY",
                    "message_id": message_id,
                    "message_state": "CLAIMED",
                    "attempt_state": "COMPLETE",
                    "disposition": "SUPERSEDED_WITHOUT_REPLAY",
                    "receipt_fabricated": False,
                }
            )
        connection.commit()
        connection.close()
        self.archive.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def legacy_archive(self) -> tuple[Path, list[dict[str, object]]]:
        legacy = self.root / "legacy-archive.sqlite3"
        source = sqlite3.connect(self.archive)
        source.row_factory = sqlite3.Row
        target = sqlite3.connect(legacy)
        target.executescript(
            """
            CREATE TABLE portfolio_readiness_campaigns(
                id INTEGER PRIMARY KEY, repository TEXT, issue_number INTEGER,
                generation INTEGER, item_version INTEGER,
                source_payload_sha256 TEXT, accepted_main_sha TEXT,
                graph_version INTEGER, capacity_policy_version INTEGER,
                candidate_sha256 TEXT, worker_role TEXT, phase_summary TEXT,
                plan_sha256 TEXT, plan_json TEXT, created_at TEXT
            );
            CREATE TABLE portfolio_readiness_current(
                repository TEXT, issue_number INTEGER, campaign_id INTEGER,
                state TEXT, message_id INTEGER, attempt_id TEXT,
                endpoint_id TEXT, version INTEGER
            );
            CREATE TABLE portfolio_pull_buffer_candidates(
                repository TEXT, issue_number INTEGER, candidate_sha256 TEXT,
                state TEXT
            );
            CREATE TABLE coordination_messages(
                id INTEGER PRIMARY KEY, state TEXT, payload_sha256 TEXT
            );
            CREATE TABLE executor_attempts(
                attempt_id TEXT PRIMARY KEY, state TEXT, target_kind TEXT,
                target_key TEXT, endpoint_id TEXT
            );
            CREATE TABLE portfolio_readiness_receipts(campaign_id INTEGER);
            """
        )
        campaign_columns = ",".join(clean.ARCHIVE_CAMPAIGN_BASE_COLUMNS) + ",created_at"
        campaign_placeholders = ",".join("?" for _ in range(15))
        for row in source.execute(
            f"SELECT {campaign_columns} FROM portfolio_readiness_campaigns"
        ):
            target.execute(
                f"INSERT INTO portfolio_readiness_campaigns({campaign_columns}) "
                f"VALUES({campaign_placeholders})",
                tuple(row),
            )
        table_columns = {
            "portfolio_readiness_current": (
                "repository,issue_number,campaign_id,state,message_id,attempt_id,endpoint_id,version"
            ),
            "portfolio_pull_buffer_candidates": (
                "repository,issue_number,candidate_sha256,state"
            ),
            "coordination_messages": "id,state,payload_sha256",
            "executor_attempts": (
                "attempt_id,state,target_kind,target_key,endpoint_id"
            ),
        }
        for table, columns in table_columns.items():
            rows = source.execute(f"SELECT {columns} FROM {table}").fetchall()
            placeholders = ",".join("?" for _ in columns.split(","))
            target.executemany(
                f"INSERT INTO {table}({columns}) VALUES({placeholders})", rows
            )
        target.commit()
        target.close()

        legacy_lineages = copy.deepcopy(self.archive_lineages)
        for lineage in legacy_lineages:
            row = source.execute(
                """
                SELECT campaign.repository,campaign.issue_number,
                       campaign.generation,campaign.id AS campaign_id,
                       campaign.item_version,campaign.source_payload_sha256,
                       campaign.accepted_main_sha,campaign.graph_version,
                       campaign.capacity_policy_version,
                       campaign.candidate_sha256,campaign.worker_role,
                       campaign.phase_summary,campaign.plan_sha256,
                       campaign.plan_json,current.state AS campaign_state,
                       current.message_id,current.attempt_id,current.endpoint_id,
                       current.version AS current_version
                FROM portfolio_readiness_campaigns AS campaign
                JOIN portfolio_readiness_current AS current
                  ON current.campaign_id=campaign.id
                WHERE campaign.issue_number=?
                """,
                (lineage["issue_number"],),
            ).fetchone()
            assert row is not None
            projection = dict(row)
            projection.update(clean.ARCHIVE_LEGACY_TRANSITION_SENTINELS)
            lineage["campaign_sha256"] = clean.digest_json(projection)
        source.close()
        legacy.chmod(0o600)
        return legacy, legacy_lineages

    def bind_archive(
        self,
        manifest: dict[str, object],
        archive: Path,
        lineages: list[dict[str, object]],
    ) -> None:
        old = manifest["old_control_plane"]
        assert isinstance(old, dict)
        old["archive_path"] = str(archive)
        old["archive_sha256"] = sha(archive)
        old["excluded_lineages"] = copy.deepcopy(lineages)
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)

    def manifest(self, *, retained: bool = False) -> dict[str, object]:
        references = SKILL_ROOT / "references"
        snapshots: list[dict[str, object]] = []
        retained_item: dict[str, object] | None = None
        if retained:
            payload = {"number": 320, "state": "open", "title": "retained SRE lane"}
            payload_sha = clean.digest_json(payload)
            snapshots.append(
                {
                    "object_kind": "issue",
                    "object_number": 320,
                    "payload": payload,
                    "payload_sha256": payload_sha,
                    "source_updated_at": NOW,
                    "fetched_at": NOW,
                }
            )
            retained_root = self.root / "retained"
            retained_root.mkdir(mode=0o700, exist_ok=True)
            lease = {
                "repository": "twinfinityai/twinfinityapp",
                "issue_number": 320,
                "generation": 4,
                "base_sha": APPLICATION_MAIN,
                "branch": "codex/320-retained-sre",
                "worktree_path": "/tmp/twinfinity-issue320-retained",
                "no_additional_paths": True,
                "paths": [
                    {
                        "path": "infra/retained.txt",
                        "mode": "100644",
                        "type": "blob",
                        "sha": None,
                    }
                ],
            }
            lease_path = retained_root / "lease.json"
            lease_path.write_text(clean.canonical_json(lease), encoding="utf-8")
            lease_path.chmod(0o600)
            evidence_path = retained_root / "evidence.json"
            evidence_path.write_text('{"state":"retained"}', encoding="utf-8")
            evidence_path.chmod(0o600)
            retained_item = {
                "issue_number": 320,
                "generation": 4,
                "accountable_endpoint_id": "role.sre.v3",
                "source_payload_sha256": payload_sha,
                "lease_manifest_path": "retained/lease.json",
                "lease_manifest_sha256": sha(lease_path),
                "lease_bindings": copy.deepcopy(lease["paths"]),
                "development_units": 0,
                "shared_units": 0,
                "sre_units": 1,
                "artifacts": [
                    {
                        "path": "retained/lease.json",
                        "sha256": sha(lease_path),
                        "retention_class": "RETAINED",
                    },
                    {
                        "path": "retained/evidence.json",
                        "sha256": sha(evidence_path),
                        "retention_class": "RETAINED",
                    },
                ],
            }
        value: dict[str, object] = {
            "schema": clean.SCHEMA,
            "manifest_sha256": "0" * 64,
            "bootstrap_id": "clean-v3-test",
            "created_at": NOW,
            "source_harness": {
                "repository": "jayendusharma/twinfinity-harness",
                "main_sha": HARNESS_MAIN,
                "registry_path": "skills/twinfinity-sprint-orchestrator/references/twinfinity-executor-registry.toml",
                "registry_sha256": sha(references / "twinfinity-executor-registry.toml"),
                "profiles": [
                    {
                        "role": role,
                        "endpoint_id": endpoint,
                        "path": f"skills/twinfinity-sprint-orchestrator/references/twinfinity-{role if role == 'planner' else role}-v{2 if role == 'planner' else 3}.config.toml",
                        "sha256": sha(
                            references
                            / f"twinfinity-{role if role == 'planner' else role}-v{2 if role == 'planner' else 3}.config.toml"
                        ),
                    }
                    for role, endpoint in clean.EXPECTED_ENDPOINTS.items()
                ],
            },
            "approved_goal": {
                "path": "coordination/product-planner-goal.md",
                "sha256": sha(SOURCE_ROOT / "coordination" / "product-planner-goal.md"),
            },
            "application": {
                "repository": "twinfinityai/twinfinityapp",
                "main_sha": APPLICATION_MAIN,
                "snapshots": snapshots,
            },
            "capacity_policy": {
                "repository": "twinfinityai/twinfinityapp",
                "version": 1,
                "development_limit": 6,
                "shared_limit": 3,
                "sre_limit": 5,
                "authority_sha256": "c" * 64,
            },
            "current_endpoints": copy.deepcopy(clean.EXPECTED_ENDPOINTS),
            "retained_item": retained_item,
            "old_control_plane": {
                "archive_path": str(self.archive),
                "archive_sha256": sha(self.archive),
                "archive_integrity": "ok",
                "disposition": "IMMUTABLE_ARCHIVE_SUPERSEDED",
                "excluded_lineages": copy.deepcopy(self.archive_lineages),
            },
        }
        value["manifest_sha256"] = clean.manifest_digest(value)
        return value

    def rewrite_retained_lease(
        self, manifest: dict[str, object], **updates: object
    ) -> None:
        retained = manifest["retained_item"]
        assert isinstance(retained, dict)
        lease_path = self.root / str(retained["lease_manifest_path"])
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        lease.update(updates)
        lease_path.write_text(clean.canonical_json(lease), encoding="utf-8")
        lease_path.chmod(0o600)
        lease_sha = sha(lease_path)
        retained["lease_manifest_sha256"] = lease_sha
        artifacts = retained["artifacts"]
        assert isinstance(artifacts, list)
        for artifact in artifacts:
            if artifact["path"] == retained["lease_manifest_path"]:
                artifact["sha256"] = lease_sha
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)

    def source_fixture(self, manifest: dict[str, object]) -> tuple[Path, str]:
        source_root = self.root / "source-fixture"
        source_root.mkdir(mode=0o700)
        source = manifest["source_harness"]
        assert isinstance(source, dict)
        goal = manifest["approved_goal"]
        assert isinstance(goal, dict)
        relative_paths = [
            str(source["registry_path"]),
            *(str(profile["path"]) for profile in source["profiles"]),
            str(goal["path"]),
        ]
        for relative in relative_paths:
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE_ROOT / relative, destination)
        subprocess.run(["git", "init", "-q", str(source_root)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(source_root),
                "remote",
                "add",
                "origin",
                "https://github.com/jayendusharma/twinfinity-harness.git",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(source_root), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(source_root),
                "-c",
                "user.name=Twinfinity Test",
                "-c",
                "user.email=test@twinfinity.invalid",
                "commit",
                "-q",
                "-m",
                "source fixture",
            ],
            check=True,
        )
        commit = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return source_root, commit

    def test_creates_and_validates_clean_database_without_retained_work(self) -> None:
        database = self.root / "clean.sqlite3"
        manifest = self.manifest()
        result = clean.bootstrap_database(
            database=database,
            manifest=manifest,
            source_root=SOURCE_ROOT,
            harness_main_sha=HARNESS_MAIN,
        )
        self.assertEqual("PASS", result["state"])
        self.assertFalse(result["retained_issue_320"])
        self.assertEqual(0o600, database.stat().st_mode & 0o777)
        self.assertFalse(Path(f"{database}-wal").exists())
        self.assertFalse(Path(f"{database}-shm").exists())
        connection = sqlite3.connect(database)
        try:
            pointers = dict(connection.execute("SELECT role, endpoint_id FROM executor_role_endpoint_current"))
            self.assertEqual(clean.EXPECTED_ENDPOINTS, pointers)
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM portfolio_readiness_campaigns").fetchone()[0])
            stored = json.loads(connection.execute("SELECT manifest_json FROM coordination_bootstrap_provenance").fetchone()[0])
            self.assertEqual(
                self.archive_lineages,
                stored["old_control_plane"]["excluded_lineages"],
            )
        finally:
            connection.close()

    def test_exact_retained_320_seed_binds_lease_and_artifacts(self) -> None:
        database = self.root / "clean-retained.sqlite3"
        manifest = self.manifest(retained=True)
        result = clean.bootstrap_database(
            database=database,
            manifest=manifest,
            source_root=SOURCE_ROOT,
            harness_main_sha=HARNESS_MAIN,
        )
        self.assertTrue(result["retained_issue_320"])
        connection = sqlite3.connect(database)
        try:
            item = connection.execute(
                "SELECT issue_number,status,allocation_class,sre_units,accountable_session_id FROM coordination_items"
            ).fetchone()
            self.assertEqual((320, "HOLD", "RETAINED", 1, "role.sre.v3"), item)
            self.assertEqual(2, connection.execute("SELECT COUNT(*) FROM coordination_artifacts").fetchone()[0])
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM coordination_terminal_watches").fetchone()[0])
        finally:
            connection.close()

    def test_rejects_existing_canonical_symlink_and_unsafe_paths(self) -> None:
        existing = self.root / "existing.sqlite3"
        existing.touch(mode=0o600)
        with self.assertRaisesRegex(clean.CleanControlPlaneError, "BOOTSTRAP_DATABASE_EXISTS"):
            clean._validate_target(existing)
        with self.assertRaisesRegex(clean.CleanControlPlaneError, "BOOTSTRAP_CANONICAL_DATABASE_FORBIDDEN"):
            clean._validate_target(clean.DEFAULT_CANONICAL_DATABASE)
        symlink = self.root / "link"
        symlink.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(clean.CleanControlPlaneError, "BOOTSTRAP_DATABASE_PARENT_UNSAFE"):
            clean._validate_target(symlink / "candidate.sqlite3")
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        with self.assertRaisesRegex(clean.CleanControlPlaneError, "BOOTSTRAP_DATABASE_PARENT_UNSAFE"):
            clean._validate_target(unsafe / "candidate.sqlite3")

    def test_closed_manifest_tamper_and_archive_digest_fail_closed(self) -> None:
        manifest = self.manifest()
        manifest["unexpected"] = True
        with self.assertRaisesRegex(clean.CleanControlPlaneError, "BOOTSTRAP_MANIFEST_SCHEMA_INVALID"):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )
        manifest = self.manifest()
        manifest["capacity_policy"]["shared_limit"] = 4  # type: ignore[index]
        with self.assertRaisesRegex(clean.CleanControlPlaneError, "BOOTSTRAP_MANIFEST_DIGEST_MISMATCH"):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )
        manifest = self.manifest()
        manifest["old_control_plane"]["archive_sha256"] = "d" * 64  # type: ignore[index]
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)
        with self.assertRaisesRegex(clean.CleanControlPlaneError, "BOOTSTRAP_ARCHIVE_DIGEST_MISMATCH"):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )

    def test_archive_must_contain_exact_authenticated_stranded_lineages(self) -> None:
        manifest = self.manifest()
        connection = sqlite3.connect(self.archive)
        connection.execute(
            "UPDATE portfolio_readiness_current SET state='HOLD' WHERE issue_number=328"
        )
        connection.commit()
        connection.close()
        manifest["old_control_plane"]["archive_sha256"] = sha(self.archive)  # type: ignore[index]
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError, "BOOTSTRAP_ARCHIVE_LINEAGE_MISMATCH"
        ):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )

    def test_real_archive_lineage_identities_cannot_swap(self) -> None:
        expected = {
            328: (2, "c448fd19-40a6-4511-bdf7-9ca7bbbb2788"),
            329: (1, "d7f69b5a-dc4c-4d1e-b434-da4ab6cdb2d5"),
        }
        self.assertEqual(expected, clean.STRANDED_IDENTITIES)
        self.assertEqual(
            expected,
            {
                int(lineage["issue_number"]): (
                    int(lineage["campaign_id"]),
                    str(lineage["attempt_id"]),
                )
                for lineage in self.archive_lineages
            },
        )

        manifest = self.manifest()
        lineages = manifest["old_control_plane"]["excluded_lineages"]  # type: ignore[index]
        lineages[0]["campaign_id"], lineages[1]["campaign_id"] = (  # type: ignore[index]
            lineages[1]["campaign_id"],  # type: ignore[index]
            lineages[0]["campaign_id"],  # type: ignore[index]
        )
        lineages[0]["attempt_id"], lineages[1]["attempt_id"] = (  # type: ignore[index]
            lineages[1]["attempt_id"],  # type: ignore[index]
            lineages[0]["attempt_id"],  # type: ignore[index]
        )
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError,
            "BOOTSTRAP_ARCHIVE_LINEAGE_SCHEMA_INVALID",
        ):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )

    def test_current_and_legacy_campaign_schemas_have_exact_digests(self) -> None:
        self.assertEqual(
            {
                328: "232b3fea182452ec467e497643feab6f9d34d49862ecc57fc5f286adcc196d2a",
                329: "f255e616e66e29ab6708957df78f7f18998bc1a90c2044386e1a1c4f18f023c5",
            },
            {
                int(lineage["issue_number"]): lineage["campaign_sha256"]
                for lineage in self.archive_lineages
            },
        )
        current_manifest = self.manifest()
        clean._validate_manifest(
            current_manifest,
            source_root=SOURCE_ROOT,
            database=self.root / "current-candidate.sqlite3",
            harness_main_sha=HARNESS_MAIN,
        )

        legacy, legacy_lineages = self.legacy_archive()
        self.assertEqual(
            {
                328: "a6d9a4ef4aeef8110d64559e2860609f4fdc9c48323220016cd91588ae311ad9",
                329: "2c38b355df0cb913d81c41b3d653d324c7dfeb51eb95b4a7cef9836a4649256f",
            },
            {
                int(lineage["issue_number"]): lineage["campaign_sha256"]
                for lineage in legacy_lineages
            },
        )
        legacy_manifest = self.manifest()
        self.bind_archive(legacy_manifest, legacy, legacy_lineages)
        clean._validate_manifest(
            legacy_manifest,
            source_root=SOURCE_ROOT,
            database=self.root / "legacy-candidate.sqlite3",
            harness_main_sha=HARNESS_MAIN,
        )

    def test_partial_or_unknown_campaign_schema_fails_closed(self) -> None:
        legacy, legacy_lineages = self.legacy_archive()
        connection = sqlite3.connect(legacy)
        connection.execute(
            "ALTER TABLE portfolio_readiness_campaigns "
            "ADD COLUMN parent_campaign_id INTEGER"
        )
        connection.commit()
        connection.close()
        legacy.chmod(0o600)
        manifest = self.manifest()
        self.bind_archive(manifest, legacy, legacy_lineages)
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError,
            "BOOTSTRAP_ARCHIVE_CAMPAIGN_SCHEMA_INVALID",
        ):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "partial-candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )

    def test_archive_rejects_canonical_path_and_descriptor_replacement_race(self) -> None:
        manifest = self.manifest()
        manifest["old_control_plane"]["archive_path"] = str(  # type: ignore[index]
            clean.DEFAULT_CANONICAL_DATABASE
        )
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError, "BOOTSTRAP_ARCHIVE_PATH_INVALID"
        ):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )

        manifest = self.manifest()
        real_digest = clean._descriptor_sha256
        calls = 0

        def replace_after_digest(descriptor: int) -> str:
            nonlocal calls
            result = real_digest(descriptor)
            calls += 1
            if calls == 1:
                replacement = self.root / "archive-replacement.sqlite3"
                shutil.copy2(self.archive, replacement)
                replacement.chmod(0o600)
                os.replace(replacement, self.archive)
            return result

        with patch.object(
            clean, "_descriptor_sha256", side_effect=replace_after_digest
        ), self.assertRaisesRegex(
            clean.CleanControlPlaneError, "BOOTSTRAP_ARCHIVE_DRIFT"
        ):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )

        unrelated = self.root / "unrelated.sqlite3"
        connection = sqlite3.connect(unrelated)
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.commit()
        connection.close()
        unrelated.chmod(0o600)
        manifest = self.manifest()
        manifest["old_control_plane"]["archive_path"] = str(unrelated)  # type: ignore[index]
        manifest["old_control_plane"]["archive_sha256"] = sha(unrelated)  # type: ignore[index]
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError,
            "BOOTSTRAP_ARCHIVE_CAMPAIGN_SCHEMA_INVALID",
        ):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=HARNESS_MAIN,
            )

    def test_retained_lease_identity_base_and_paths_are_exactly_bound(self) -> None:
        cases = (
            {"issue_number": 999},
            {"base_sha": "f" * 40},
            {
                "paths": [
                    {
                        "path": "infra/different.txt",
                        "mode": "100644",
                        "type": "blob",
                        "sha": None,
                    }
                ]
            },
        )
        for updates in cases:
            with self.subTest(updates=updates):
                manifest = self.manifest(retained=True)
                self.rewrite_retained_lease(manifest, **updates)
                with self.assertRaisesRegex(
                    clean.CleanControlPlaneError,
                    "BOOTSTRAP_LEASE_BINDING_MISMATCH",
                ):
                    clean._validate_manifest(
                        manifest,
                        source_root=SOURCE_ROOT,
                        database=self.root / "candidate.sqlite3",
                        harness_main_sha=HARNESS_MAIN,
                    )

    def test_source_git_attestation_rejects_sha_repository_root_and_dirty_binding(self) -> None:
        manifest = self.manifest()
        manifest["source_harness"]["main_sha"] = "f" * 40  # type: ignore[index]
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError, "BOOTSTRAP_SOURCE_GIT_MISMATCH"
        ):
            clean._validate_manifest(
                manifest,
                source_root=SOURCE_ROOT,
                database=self.root / "candidate.sqlite3",
                harness_main_sha="f" * 40,
            )

        with self.assertRaisesRegex(
            clean.CleanControlPlaneError, "BOOTSTRAP_SOURCE_GIT_MISMATCH"
        ):
            clean._validate_source_git(
                SOURCE_ROOT / "skills",
                repository=clean.SOURCE_HARNESS_REPOSITORY,
                commit=HARNESS_MAIN,
                bound_paths=[],
            )
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError, "BOOTSTRAP_SOURCE_GIT_MISMATCH"
        ):
            clean._validate_source_git(
                SOURCE_ROOT,
                repository="unrelated/repository",
                commit=HARNESS_MAIN,
                bound_paths=[],
            )

        manifest = self.manifest()
        source_root, commit = self.source_fixture(manifest)
        source = manifest["source_harness"]
        assert isinstance(source, dict)
        source["main_sha"] = commit
        registry = source_root / str(source["registry_path"])
        registry.write_bytes(registry.read_bytes() + b"\n")
        source["registry_sha256"] = sha(registry)
        manifest["manifest_sha256"] = clean.manifest_digest(manifest)
        with self.assertRaisesRegex(
            clean.CleanControlPlaneError, "BOOTSTRAP_SOURCE_GIT_MISMATCH"
        ):
            clean._validate_manifest(
                manifest,
                source_root=source_root,
                database=self.root / "candidate.sqlite3",
                harness_main_sha=commit,
            )


if __name__ == "__main__":
    unittest.main()
