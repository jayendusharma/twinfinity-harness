from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = SKILL_ROOT / "scripts" / "cached_tracker_reconciliation.py"
sys.path.insert(0, str(SKILL_ROOT / "scripts"))
import cached_tracker_reconciliation as cache  # noqa: E402
MAIN = "e38d05da9e0be9d450bb22d752c35154e733a50e"
STATE = "#88 DONE/MERGED/CLEANED/RELEASED"
CAPACITY = "active D0/S0; retained D2/S1; available D3/S1; READY 0"
BLOCK_START = "<!-- twinfinity-current-control:v1 -->"
BLOCK_END = "<!-- /twinfinity-current-control:v1 -->"


class CachedTrackerReconciliationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = self.root / "coordination.sqlite3"
        self.paths: dict[int, Path] = {}
        block = (
            f"{BLOCK_START}\nAccepted main: {MAIN}\nState: {STATE}\n"
            f"Capacity: {CAPACITY}\n{BLOCK_END}\n"
        )
        for issue in (44, 61, 120, 131, 179):
            path = self.root / f"{issue}.md"
            path.write_text(f"# Tracker {issue}\n\n{block}", encoding="utf-8")
            self.paths[issue] = path

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def command(
        self,
        *,
        capacity: str = CAPACITY,
        accepted_main: str = MAIN,
        state: str = STATE,
        database: Path | None = None,
    ) -> list[str]:
        command = [sys.executable, str(SCRIPT)]
        for issue, path in self.paths.items():
            command.extend(["--body", f"{issue}={path}"])
        command.extend(
            [
                "--accepted-main",
                accepted_main,
                "--state",
                state,
                "--capacity",
                capacity,
                "--database",
                str(database or self.database),
            ]
        )
        return command

    def run_cache(
        self,
        *,
        capacity: str = CAPACITY,
        accepted_main: str = MAIN,
        state: str = STATE,
        database: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(
                capacity=capacity,
                accepted_main=accepted_main,
                state=state,
                database=database,
            ),
            text=True,
            capture_output=True,
            check=False,
        )

    def test_identical_projection_and_body_digests_hit_cache(self) -> None:
        first = self.run_cache()
        second = self.run_cache()
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(json.loads(first.stdout)["cache"], "MISS")
        self.assertEqual(json.loads(second.stdout)["cache"], "HIT")
        self.assertEqual(
            json.loads(first.stdout)["cache_key"], json.loads(second.stdout)["cache_key"]
        )

    def test_body_digest_change_invalidates_cache(self) -> None:
        first = self.run_cache()
        self.paths[44].write_text(
            self.paths[44].read_text(encoding="utf-8") + "\nNon-control note.\n",
            encoding="utf-8",
        )
        second = self.run_cache()
        self.assertEqual(json.loads(first.stdout)["cache"], "MISS")
        self.assertEqual(json.loads(second.stdout)["cache"], "MISS")
        self.assertNotEqual(
            json.loads(first.stdout)["cache_key"], json.loads(second.stdout)["cache_key"]
        )

    def test_capacity_change_invalidates_and_revalidates(self) -> None:
        first = self.run_cache()
        changed = "active D1/S1; retained D1/S0; available D3/S1; READY 0"
        second = self.run_cache(capacity=changed)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 3)
        self.assertEqual(json.loads(second.stdout)["cache"], "MISS")

    def test_cache_reads_revised_capacity_policy_from_sqlite(self) -> None:
        self.assertEqual(self.run_cache().returncode, 0)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """
                INSERT INTO coordination_capacity_policies(
                    repository, version, development_limit, shared_limit,
                    sre_limit, authority_sha256, created_at
                ) VALUES (?, 2, 6, 3, 5, ?, ?)
                """,
                (
                    "twinfinityai/twinfinityapp",
                    "a" * 64,
                    "2026-08-24T00:00:00Z",
                ),
            )
            connection.execute(
                """
                UPDATE coordination_capacity_current
                SET version=2, updated_at=?
                WHERE repository=? AND version=1
                """,
                ("2026-08-24T00:00:00Z", "twinfinityai/twinfinityapp"),
            )
        revised = "active D1/S1; retained D0/S0; available D5/S2; READY 0"
        block = (
            f"{BLOCK_START}\nAccepted main: {MAIN}\nState: {STATE}\n"
            f"Capacity: {revised}\n{BLOCK_END}\n"
        )
        for issue, path in self.paths.items():
            path.write_text(f"# Tracker {issue}\n\n{block}", encoding="utf-8")
        completed = self.run_cache(capacity=revised)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["cache"], "MISS")

    def test_policy_pointer_drift_fails_closed(self) -> None:
        self.assertEqual(self.run_cache().returncode, 0)
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            expected = dict(
                connection.execute(
                    """
                    SELECT p.* FROM coordination_capacity_current c
                    JOIN coordination_capacity_policies p
                      ON p.repository=c.repository AND p.version=c.version
                    WHERE c.repository=?
                    """,
                    ("twinfinityai/twinfinityapp",),
                ).fetchone()
            )
            connection.execute(
                """
                INSERT INTO coordination_capacity_policies(
                    repository, version, development_limit, shared_limit,
                    sre_limit, authority_sha256, created_at
                ) VALUES (?, 2, 6, 3, 5, ?, ?)
                """,
                (
                    "twinfinityai/twinfinityapp",
                    "b" * 64,
                    "2026-08-24T00:00:00Z",
                ),
            )
            connection.execute(
                "UPDATE coordination_capacity_current SET version=2 WHERE repository=?",
                ("twinfinityai/twinfinityapp",),
            )
            with self.assertRaisesRegex(ValueError, "CAPACITY_POLICY_DRIFT"):
                cache._assert_capacity_policy_current(
                    connection, "twinfinityai/twinfinityapp", expected
                )

    def test_main_and_state_changes_invalidate_cache(self) -> None:
        first = self.run_cache()
        changed_main = self.run_cache(accepted_main="f" * 40)
        changed_state = self.run_cache(state="#91 READY")
        self.assertEqual(json.loads(first.stdout)["cache"], "MISS")
        self.assertEqual(json.loads(changed_main.stdout)["cache"], "MISS")
        self.assertEqual(json.loads(changed_state.stdout)["cache"], "MISS")
        self.assertEqual(
            len(
                {
                    json.loads(first.stdout)["cache_key"],
                    json.loads(changed_main.stdout)["cache_key"],
                    json.loads(changed_state.stdout)["cache_key"],
                }
            ),
            3,
        )

    def test_each_body_digest_invalidates_cache(self) -> None:
        first = self.run_cache()
        first_key = json.loads(first.stdout)["cache_key"]
        for issue in (44, 61, 120, 131, 179):
            original = self.paths[issue].read_text(encoding="utf-8")
            self.paths[issue].write_text(
                original + f"\nDigest change for {issue}.\n", encoding="utf-8"
            )
            changed = self.run_cache(database=self.root / f"cache-{issue}.sqlite3")
            self.assertEqual(json.loads(changed.stdout)["cache"], "MISS")
            self.assertNotEqual(json.loads(changed.stdout)["cache_key"], first_key)
            self.paths[issue].write_text(original, encoding="utf-8")

    def test_pending_result_hits_cache_with_exit_three(self) -> None:
        self.paths[44].write_text("# stale\n", encoding="utf-8")
        first = self.run_cache()
        second = self.run_cache()
        self.assertEqual(first.returncode, 3)
        self.assertEqual(second.returncode, 3)
        self.assertEqual(json.loads(first.stdout)["cache"], "MISS")
        self.assertEqual(json.loads(second.stdout)["cache"], "HIT")

    def test_corrupt_cached_result_fails_closed(self) -> None:
        first = self.run_cache()
        key = json.loads(first.stdout)["cache_key"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tracker_reconciliation_cache SET result_json='{}' "
                "WHERE cache_key=?",
                (key,),
            )
        second = self.run_cache()
        self.assertEqual(second.returncode, 2)
        self.assertEqual(json.loads(second.stdout)["outcome"], "INVALID_INPUT")

    def test_cache_stores_no_body_text(self) -> None:
        secret_marker = "UNIQUE-BODY-TEXT-MUST-NOT-ENTER-SQLITE"
        self.paths[44].write_text(
            self.paths[44].read_text(encoding="utf-8") + f"\n{secret_marker}\n",
            encoding="utf-8",
        )
        self.assertEqual(self.run_cache().returncode, 0)
        self.assertNotIn(secret_marker.encode("utf-8"), self.database.read_bytes())

    def test_unsafe_parent_and_symlink_database_fail_closed(self) -> None:
        unsafe_parent = self.root / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o755)
        os.chmod(unsafe_parent, 0o755)
        unsafe = self.run_cache(database=unsafe_parent / "cache.sqlite3")
        self.assertEqual(unsafe.returncode, 2)
        self.assertFalse((unsafe_parent / "cache.sqlite3").exists())

        target = self.root / "target.sqlite3"
        self.assertEqual(self.run_cache(database=target).returncode, 0)
        link = self.root / "linked.sqlite3"
        link.symlink_to(target)
        linked = self.run_cache(database=link)
        self.assertEqual(linked.returncode, 2)

    def test_intermediate_parent_symlink_creates_nothing_in_target(self) -> None:
        target = self.root / "redirect-target"
        target.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        redirected = self.run_cache(database=alias / "nested" / "cache.sqlite3")
        self.assertEqual(redirected.returncode, 2)
        self.assertFalse((target / "nested").exists())

    def test_concurrent_identical_insert_has_one_miss_and_one_hit(self) -> None:
        first = subprocess.Popen(
            self.command(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        second = subprocess.Popen(
            self.command(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        first_stdout, first_stderr = first.communicate(timeout=30)
        second_stdout, second_stderr = second.communicate(timeout=30)
        self.assertEqual(first.returncode, 0, first_stdout + first_stderr)
        self.assertEqual(second.returncode, 0, second_stdout + second_stderr)
        self.assertEqual(
            sorted(
                [json.loads(first_stdout)["cache"], json.loads(second_stdout)["cache"]]
            ),
            ["HIT", "MISS"],
        )


if __name__ == "__main__":
    unittest.main()
