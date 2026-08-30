from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationError, CoordinationStore  # noqa: E402
from repository_delivery_policy import (  # noqa: E402
    APPLICATION_REPOSITORY,
    HARNESS_REPOSITORY,
)


HARNESS_MAIN = "a" * 40
APPLICATION_MAIN = "b" * 40
NOW = "2026-08-28T21:00:00Z"


class RepositoryGitRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "registry"
        self.root.mkdir(mode=0o700)
        self.store = CoordinationStore(self.root / "state.sqlite3")
        self.bootstrap_manifest = {"kind": "repository-git-registry-test-bootstrap"}
        self.bootstrap_sha256 = hashlib.sha256(
            json.dumps(
                self.bootstrap_manifest, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        with self.store.transaction():
            self.store.record_bootstrap_provenance(
                bootstrap_id="repository-git-registry-tests",
                manifest_sha256=self.bootstrap_sha256,
                manifest=self.bootstrap_manifest,
                source_harness_repository=HARNESS_REPOSITORY,
                source_harness_main_sha=HARNESS_MAIN,
                source_registry_sha256="1" * 64,
                approved_goal_sha256="2" * 64,
                application_repository=APPLICATION_REPOSITORY,
                application_main_sha=APPLICATION_MAIN,
                archived_database_sha256="3" * 64,
                now=NOW,
            )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _git_dir(
        self,
        name: str,
        repository: str,
        main_sha: str,
        *,
        full_checkout: bool = False,
    ) -> Path:
        root = self.root / name
        git_dir = root / ".git" if full_checkout else root
        git_dir.mkdir(parents=True)
        (git_dir / "config").write_text(
            "[core]\n"
            f"\tbare = {'false' if full_checkout else 'true'}\n"
            '[remote "origin"]\n'
            f"\turl = https://github.com/{repository}.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8",
        )
        ref = git_dir / "refs" / "remotes" / "origin" / "main"
        ref.parent.mkdir(parents=True)
        ref.write_text(main_sha + "\n", encoding="ascii")
        return git_dir

    def _register(self, repository: str, git_dir: Path, source_main: str) -> dict:
        with self.store.transaction():
            return self.store.record_repository_git_registration(
                repository=repository,
                git_dir=git_dir,
                source_main_sha=source_main,
                bootstrap_id="repository-git-registry-tests",
                bootstrap_manifest_sha256=self.bootstrap_sha256,
                now=NOW,
            )

    def test_hidden_common_git_dir_and_full_checkout_resolve_exact_main(self) -> None:
        harness_git = self._git_dir(
            ".harness-common-git", HARNESS_REPOSITORY, HARNESS_MAIN
        )
        application_git = self._git_dir(
            "application", APPLICATION_REPOSITORY, APPLICATION_MAIN, full_checkout=True
        )
        self.assertFalse((self.root / "twinfinity-harness").exists())

        harness = self._register(HARNESS_REPOSITORY, harness_git, HARNESS_MAIN)
        application = self._register(
            APPLICATION_REPOSITORY, application_git, APPLICATION_MAIN
        )

        self.assertFalse(harness["replay"])
        self.assertFalse(application["replay"])
        self.assertEqual(
            HARNESS_MAIN,
            self.store.read_registered_repository_main(HARNESS_REPOSITORY),
        )
        self.assertEqual(
            APPLICATION_MAIN,
            self.store.read_registered_repository_main(APPLICATION_REPOSITORY),
        )

    def test_exact_replay_is_idempotent_and_changed_path_conflicts(self) -> None:
        git_dir = self._git_dir("common", HARNESS_REPOSITORY, HARNESS_MAIN)
        first = self._register(HARNESS_REPOSITORY, git_dir, HARNESS_MAIN)
        replay = self._register(HARNESS_REPOSITORY, git_dir, HARNESS_MAIN)
        replacement = self._git_dir("replacement", HARNESS_REPOSITORY, HARNESS_MAIN)

        self.assertTrue(replay["replay"])
        self.assertEqual(first["registration_sha256"], replay["registration_sha256"])
        with self.assertRaisesRegex(
            CoordinationError, "REPOSITORY_GIT_REGISTRATION_CONFLICT"
        ):
            self._register(HARNESS_REPOSITORY, replacement, HARNESS_MAIN)
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_repository_git_registrations"
            ).fetchone()[0],
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "REPOSITORY_GIT_REGISTRATION_IMMUTABLE"
        ):
            self.store.connection.execute(
                "UPDATE coordination_repository_git_registrations SET origin_url=origin_url"
            )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "REPOSITORY_GIT_REGISTRATION_IMMUTABLE"
        ):
            self.store.connection.execute(
                "DELETE FROM coordination_repository_git_registrations"
            )

    def test_packed_remote_main_is_read_without_git_or_network(self) -> None:
        git_dir = self._git_dir("packed", HARNESS_REPOSITORY, HARNESS_MAIN)
        loose = git_dir / "refs" / "remotes" / "origin" / "main"
        loose.unlink()
        (git_dir / "packed-refs").write_text(
            "# pack-refs with: peeled fully-peeled sorted\n"
            f"{HARNESS_MAIN} refs/remotes/origin/main\n",
            encoding="ascii",
        )

        self._register(HARNESS_REPOSITORY, git_dir, HARNESS_MAIN)

        self.assertEqual(
            HARNESS_MAIN,
            self.store.read_registered_repository_main(HARNESS_REPOSITORY),
        )

    def test_missing_wrong_origin_symlink_owner_and_mode_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            CoordinationError, "REPOSITORY_GIT_REGISTRATION_MISSING"
        ):
            self.store.read_registered_repository_main(HARNESS_REPOSITORY)

        wrong_origin = self._git_dir("wrong-origin", APPLICATION_REPOSITORY, HARNESS_MAIN)
        with self.assertRaisesRegex(CoordinationError, "REPOSITORY_GIT_ORIGIN_MISMATCH"):
            self._register(HARNESS_REPOSITORY, wrong_origin, HARNESS_MAIN)

        real = self._git_dir("real", HARNESS_REPOSITORY, HARNESS_MAIN)
        symlink = self.root / "symlink"
        symlink.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(CoordinationError, "REPOSITORY_GIT_DIRECTORY_INVALID"):
            self._register(HARNESS_REPOSITORY, symlink, HARNESS_MAIN)

        with patch("repository_git_registry.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(
                CoordinationError, "REPOSITORY_GIT_DIRECTORY_UNSAFE"
            ):
                self._register(HARNESS_REPOSITORY, real, HARNESS_MAIN)

        unsafe = self._git_dir("unsafe", HARNESS_REPOSITORY, HARNESS_MAIN)
        unsafe.chmod(0o770)
        with self.assertRaisesRegex(
            CoordinationError, "REPOSITORY_GIT_DIRECTORY_UNSAFE"
        ):
            self._register(HARNESS_REPOSITORY, unsafe, HARNESS_MAIN)

    def test_substitution_origin_ref_and_provenance_drift_are_rejected(self) -> None:
        git_dir = self._git_dir("common", HARNESS_REPOSITORY, HARNESS_MAIN)
        self._register(HARNESS_REPOSITORY, git_dir, HARNESS_MAIN)

        preserved = self.root / "preserved-common"
        git_dir.rename(preserved)
        self._git_dir("common", HARNESS_REPOSITORY, HARNESS_MAIN)
        with self.assertRaisesRegex(
            CoordinationError, "REPOSITORY_GIT_DIRECTORY_SUBSTITUTED"
        ):
            self.store.read_registered_repository_main(HARNESS_REPOSITORY)

        replacement = self.root / "common"
        for child in sorted(replacement.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            else:
                child.rmdir()
        replacement.rmdir()
        preserved.rename(git_dir)

        config = git_dir / "config"
        config.write_text(
            "[core]\n\tbare = true\n"
            '[remote "origin"]\n'
            f"\turl = git@github.com:{HARNESS_REPOSITORY}.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            CoordinationError, "REPOSITORY_GIT_REGISTRATION_DRIFT"
        ):
            self.store.read_registered_repository_main(HARNESS_REPOSITORY)

        config.write_text(
            "[core]\n\tbare = true\n"
            '[remote "origin"]\n'
            f"\turl = https://github.com/{HARNESS_REPOSITORY}.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8",
        )
        ref = git_dir / "refs" / "remotes" / "origin" / "main"
        ref.write_text("A" * 40 + "\n", encoding="ascii")
        with self.assertRaisesRegex(CoordinationError, "REPOSITORY_GIT_MAIN_INVALID"):
            self.store.read_registered_repository_main(HARNESS_REPOSITORY)

        ref.write_text(HARNESS_MAIN + "\n", encoding="ascii")
        self.store.connection.execute(
            "DROP TRIGGER coordination_bootstrap_provenance_immutable_update"
        )
        self.store.connection.execute(
            "UPDATE coordination_bootstrap_provenance "
            "SET source_harness_main_sha=? WHERE bootstrap_id=?",
            ("c" * 40, "repository-git-registry-tests"),
        )
        with self.assertRaisesRegex(
            CoordinationError, "REPOSITORY_GIT_PROVENANCE_DRIFT"
        ):
            self.store.read_registered_repository_main(HARNESS_REPOSITORY)

    def test_derived_git_state_is_rejected_before_any_git_child(self) -> None:
        git_dir = self._git_dir("common", HARNESS_REPOSITORY, HARNESS_MAIN)
        (git_dir / "commondir").write_text("../common\n", encoding="utf-8")

        with patch("repository_git_registry.subprocess.run") as run:
            with self.assertRaisesRegex(
                CoordinationError, "REPOSITORY_GIT_DERIVED_STATE_PRESENT"
            ):
                self._register(HARNESS_REPOSITORY, git_dir, HARNESS_MAIN)

        run.assert_not_called()

    def test_insert_or_replace_cannot_replace_bootstrap_or_legacy_unique_keys(
        self,
    ) -> None:
        git_dir = self._git_dir("common", HARNESS_REPOSITORY, HARNESS_MAIN)
        self._register(HARNESS_REPOSITORY, git_dir, HARNESS_MAIN)
        connection = self.store.connection
        connection.execute("PRAGMA recursive_triggers=OFF")
        bootstrap_before = tuple(
            connection.execute(
                "SELECT * FROM coordination_bootstrap_provenance"
            ).fetchone()
        )
        registration_before = tuple(
            connection.execute(
                "SELECT * FROM coordination_repository_git_registrations"
            ).fetchone()
        )

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "BOOTSTRAP_PROVENANCE_IMMUTABLE"
        ):
            connection.execute(
                "INSERT OR REPLACE INTO coordination_bootstrap_provenance "
                "SELECT * FROM coordination_bootstrap_provenance"
            )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "BOOTSTRAP_PROVENANCE_IMMUTABLE"
        ):
            connection.execute(
                """
                INSERT OR REPLACE INTO coordination_bootstrap_provenance(
                    bootstrap_id, manifest_sha256, manifest_json,
                    source_harness_repository, source_harness_main_sha,
                    source_registry_sha256, approved_goal_sha256,
                    application_repository, application_main_sha,
                    archived_database_sha256, created_at
                )
                SELECT 'other-bootstrap', manifest_sha256, manifest_json,
                       source_harness_repository, source_harness_main_sha,
                       source_registry_sha256, approved_goal_sha256,
                       application_repository, application_main_sha,
                       archived_database_sha256, created_at
                FROM coordination_bootstrap_provenance
                """
            )

        for label in ("primary", "digest", "inode", "repository", "path"):
            with self.subTest(label=label):
                select = {
                    "id": "id + 100",
                    "repository": "'other/other'",
                    "git_dir": "git_dir || '-other'",
                    "source_main_sha": "source_main_sha",
                    "origin_url": "origin_url",
                    "bootstrap_id": "bootstrap_id",
                    "bootstrap_manifest_sha256": "bootstrap_manifest_sha256",
                    "device_id": "device_id + 100",
                    "inode": "inode + 100",
                    "owner_uid": "owner_uid",
                    "owner_gid": "owner_gid",
                    "mode": "mode",
                    "registration_sha256": "printf('%064x', 7)",
                    "registration_json": "registration_json",
                    "created_at": "created_at",
                }
                if label == "primary":
                    select["id"] = "id"
                elif label == "digest":
                    select["registration_sha256"] = "registration_sha256"
                elif label == "inode":
                    select["device_id"] = "device_id"
                    select["inode"] = "inode"
                elif label == "repository":
                    select["repository"] = "repository"
                else:
                    select["git_dir"] = "git_dir"
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "REPOSITORY_GIT_REGISTRATION_(?:IMMUTABLE|DUPLICATE)",
                ):
                    connection.execute(
                        "INSERT OR REPLACE INTO "
                        "coordination_repository_git_registrations "
                        "SELECT " + ", ".join(select.values()) + " "
                        "FROM coordination_repository_git_registrations"
                    )

        self.assertEqual(
            bootstrap_before,
            tuple(
                connection.execute(
                    "SELECT * FROM coordination_bootstrap_provenance"
                ).fetchone()
            ),
        )
        self.assertEqual(
            registration_before,
            tuple(
                connection.execute(
                    "SELECT * FROM coordination_repository_git_registrations"
                ).fetchone()
            ),
        )


if __name__ == "__main__":
    unittest.main()
