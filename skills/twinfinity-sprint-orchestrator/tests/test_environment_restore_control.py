from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import environment_restore_control as restore_module  # noqa: E402
from environment_restore_control import (  # noqa: E402
    EnvironmentRestoreError,
    control_restore,
    probe_active_systemd_units,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EnvironmentRestoreControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "coordination"
        self.backups = self.root / "backups"
        self.forensics = self.root / "forensics"
        self.root.mkdir(mode=0o700)
        self.backups.mkdir(mode=0o700)
        self.database = self.root / "ack-transactions.sqlite3"
        self.backup = self.backups / "backup.sqlite3"
        self.stage = self.root / "restore-stage.unique.sqlite3"
        self.forensic_dir = self.forensics / "restore-unique"
        self._create_database(self.database, marker="current")
        self._create_database(self.backup, marker="backup")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _create_database(
        path: Path,
        *,
        marker: str,
        attempt_state: str = "COMPLETE",
        watch_state: str = "COMPLETE",
        hosted_state: str = "COMPLETE",
    ) -> None:
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            CREATE TABLE restore_marker(value TEXT NOT NULL);
            CREATE TABLE executor_attempts(state TEXT NOT NULL);
            CREATE TABLE coordination_terminal_watches(state TEXT NOT NULL);
            CREATE TABLE hosted_operations(state TEXT NOT NULL);
            """
        )
        connection.execute("INSERT INTO restore_marker VALUES (?)", (marker,))
        connection.execute("INSERT INTO executor_attempts VALUES (?)", (attempt_state,))
        connection.execute(
            "INSERT INTO coordination_terminal_watches VALUES (?)", (watch_state,)
        )
        connection.execute("INSERT INTO hosted_operations VALUES (?)", (hosted_state,))
        connection.commit()
        connection.close()
        os.chmod(path, 0o600)

    def _control(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "database": self.database,
            "backup": self.backup,
            "stage": self.stage,
            "forensic_dir": self.forensic_dir,
            "systemd_probe": lambda: [],
        }
        arguments.update(overrides)
        return control_restore(**arguments)  # type: ignore[arg-type]

    def _mocked_user_bus_context(
        self, *metadata: os.stat_result
    ) -> restore_module.SystemdUserBusContext:
        runtime_root = Path(self.temporary.name) / "run" / "user"
        with mock.patch.object(
            restore_module, "_reject_symlink_components"
        ), mock.patch.object(
            restore_module.Path,
            "lstat",
            side_effect=list(metadata),
        ):
            return restore_module._systemd_user_bus_context(
                runtime_root=runtime_root
            )

    @staticmethod
    def _metadata(
        kind: int,
        mode: int,
        *,
        uid: int | None = None,
        nlink: int = 1,
        inode: int = 11,
    ) -> os.stat_result:
        return os.stat_result(
            (
                kind | mode,
                inode,
                12,
                nlink,
                os.getuid() if uid is None else uid,
                os.getgid(),
                0,
                0,
                0,
                0,
            )
        )

    def test_dry_run_is_default_and_does_not_create_destinations(self) -> None:
        current_sha256 = _sha256(self.database)
        result = self._control()
        self.assertEqual("DRY_RUN", result["mode"])
        self.assertEqual("READY", result["state"])
        self.assertEqual(current_sha256, _sha256(self.database))
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.forensic_dir.exists())
        self.assertFalse(self.forensics.exists())

    def test_apply_requires_exact_database_confirmation(self) -> None:
        for confirmation in (None, "RESTORE:/wrong/database"):
            with self.subTest(confirmation=confirmation):
                with self.assertRaisesRegex(
                    EnvironmentRestoreError, "RESTORE_CONFIRMATION_REQUIRED"
                ):
                    self._control(apply=True, confirmation=confirmation)
                self.assertFalse(self.stage.exists())
                self.assertFalse(self.forensic_dir.exists())

    def test_apply_stages_preserves_current_and_atomically_places_backup(self) -> None:
        current_sha256 = _sha256(self.database)
        result = self._control(
            apply=True,
            confirmation=f"RESTORE:{self.database}",
        )
        self.assertEqual("COMPLETE", result["state"])
        self.assertEqual(result["restored_sha256"], _sha256(self.database))
        self.assertEqual(current_sha256, _sha256(self.forensic_dir / self.database.name))
        self.assertFalse(self.stage.exists())
        self.assertEqual(0o600, stat_mode(self.database))
        self.assertEqual(0o700, stat_mode(self.forensic_dir))
        connection = sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)
        try:
            marker = connection.execute("SELECT value FROM restore_marker").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual("backup", marker)

    def test_existing_stage_or_forensic_destination_fails_before_placement(self) -> None:
        current_sha256 = _sha256(self.database)
        self.stage.write_bytes(b"occupied")
        os.chmod(self.stage, 0o600)
        with self.assertRaisesRegex(EnvironmentRestoreError, "DESTINATION_EXISTS"):
            self._control()
        self.stage.unlink()
        self.forensics.mkdir(mode=0o700)
        self.forensic_dir.mkdir(mode=0o700)
        with self.assertRaisesRegex(EnvironmentRestoreError, "DESTINATION_EXISTS"):
            self._control()
        self.assertEqual(current_sha256, _sha256(self.database))

    def test_symlink_wrong_mode_hardlink_and_wrong_type_fail_closed(self) -> None:
        real_backup = self.backups / "real.sqlite3"
        self.backup.rename(real_backup)
        self.backup.symlink_to(real_backup)
        with self.assertRaisesRegex(EnvironmentRestoreError, "PATH_SYMLINK"):
            self._control()
        self.backup.unlink()
        real_backup.rename(self.backup)

        os.chmod(self.backup, 0o640)
        with self.assertRaisesRegex(EnvironmentRestoreError, "FILE_UNSAFE"):
            self._control()
        os.chmod(self.backup, 0o600)

        hardlink = self.backups / "backup-hardlink.sqlite3"
        os.link(self.backup, hardlink)
        with self.assertRaisesRegex(EnvironmentRestoreError, "FILE_UNSAFE"):
            self._control()
        hardlink.unlink()

        self.backup.unlink()
        self.backup.mkdir(mode=0o700)
        with self.assertRaisesRegex(EnvironmentRestoreError, "FILE_UNSAFE"):
            self._control()

    def test_active_systemd_or_sqlite_work_fails_closed(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_ACTIVITY_ACTIVE"):
            self._control(systemd_probe=lambda: ["twinfinity-role-executor-active.service"])

        cases = (
            ("RUNNING", "COMPLETE", "COMPLETE"),
            ("COMPLETE", "ACTIVE", "COMPLETE"),
            ("COMPLETE", "COMPLETE", "CLAIMED"),
        )
        for attempt, watch, hosted in cases:
            with self.subTest(attempt=attempt, watch=watch, hosted=hosted):
                self.database.unlink()
                self._create_database(
                    self.database,
                    marker="current",
                    attempt_state=attempt,
                    watch_state=watch,
                    hosted_state=hosted,
                )
                with self.assertRaisesRegex(
                    EnvironmentRestoreError, "SQLITE_ACTIVITY_ACTIVE"
                ):
                    self._control()

    def test_systemd_probe_detects_managed_and_transient_active_units(self) -> None:
        show_blocks = []
        for index, unit in enumerate(restore_module.MANAGED_UNITS):
            state = "active" if index == 0 else "inactive"
            show_blocks.append(f"Id={unit}\nActiveState={state}")
        role_units = (
            "twinfinity-role-executor-active.service loaded running running description\n"
            "twinfinity-role-executor-old.service loaded failed failed description\n"
        )
        user_bus = restore_module.SystemdUserBusContext(
            environment={"XDG_RUNTIME_DIR": "/run/user/1234"},
            runtime_identity=(1, 2, stat.S_IFDIR | 0o700, 1234),
            bus_identity=(1, 4, stat.S_IFSOCK | 0o666, 1234, 1),
        )
        with mock.patch.object(
            restore_module,
            "_systemd_user_bus_context",
            return_value=user_bus,
        ), mock.patch.object(
            restore_module,
            "_systemctl_run",
            side_effect=["\n\n".join(show_blocks), role_units],
        ) as systemctl_run:
            active = probe_active_systemd_units()
        self.assertEqual(
            [
                restore_module.MANAGED_UNITS[0],
                "twinfinity-role-executor-active.service",
            ],
            active,
        )
        self.assertEqual(
            [user_bus, user_bus],
            [call.kwargs["user_bus"] for call in systemctl_run.call_args_list],
        )

    def test_systemd_probe_rejects_user_bus_drift_between_successful_calls(
        self,
    ) -> None:
        before = restore_module.SystemdUserBusContext(
            environment={
                "HOME": "/safe/home",
                "PATH": "/usr/bin:/bin",
                "XDG_RUNTIME_DIR": "/run/user/1234",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1234/bus",
            },
            runtime_identity=(1, 2, stat.S_IFDIR | 0o700, 1234),
            bus_identity=(1, 4, stat.S_IFSOCK | 0o666, 1234, 1),
        )
        after = restore_module.SystemdUserBusContext(
            environment=before.environment,
            runtime_identity=before.runtime_identity,
            bus_identity=(1, 5, stat.S_IFSOCK | 0o666, 1234, 1),
        )
        show = "\n\n".join(
            f"Id={unit}\nActiveState=inactive" for unit in restore_module.MANAGED_UNITS
        )
        responses = [
            mock.Mock(returncode=0, stdout=show, stderr=""),
            mock.Mock(returncode=0, stdout="", stderr=""),
        ]
        with mock.patch.object(
            restore_module,
            "_systemd_user_bus_context",
            side_effect=[before, before, after],
        ), mock.patch.object(
            restore_module.subprocess,
            "run",
            side_effect=responses,
        ) as run:
            with self.assertRaisesRegex(
                EnvironmentRestoreError, "RESTORE_SYSTEMD_BUS_DRIFT"
            ):
                probe_active_systemd_units()
        self.assertEqual(2, run.call_count)

    def test_systemctl_run_passes_only_derived_user_bus_environment(self) -> None:
        context = restore_module.SystemdUserBusContext(
            environment={
                "HOME": "/safe/home",
                "PATH": "/usr/bin:/bin",
                "XDG_RUNTIME_DIR": "/run/user/1234",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1234/bus",
            },
            runtime_identity=(1, 2, 3, 1234),
            bus_identity=(1, 4, 5, 1234, 1),
        )
        completed = mock.Mock(returncode=0, stdout="running\n", stderr="")
        with mock.patch.dict(
            os.environ,
            {
                "HOME": "/hostile/home",
                "PATH": "/hostile/bin",
                "XDG_RUNTIME_DIR": "/hostile/runtime",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/hostile/bus",
                "LD_PRELOAD": "/hostile/library.so",
            },
        ), mock.patch.object(
            restore_module,
            "_systemd_user_bus_context",
            side_effect=[context, context],
        ), mock.patch.object(
            restore_module.subprocess,
            "run",
            return_value=completed,
        ) as run:
            output = restore_module._systemctl_run(["/usr/bin/systemctl", "--user"])

        self.assertEqual("running\n", output)
        self.assertEqual(context.environment, run.call_args.kwargs["env"])
        self.assertNotIn("LD_PRELOAD", run.call_args.kwargs["env"])

    def test_systemctl_run_rejects_user_bus_identity_drift(self) -> None:
        before = restore_module.SystemdUserBusContext(
            environment={
                "HOME": "/safe/home",
                "PATH": "/usr/bin:/bin",
                "XDG_RUNTIME_DIR": "/run/user/1234",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1234/bus",
            },
            runtime_identity=(1, 2, stat.S_IFDIR | 0o700, 1234),
            bus_identity=(1, 4, stat.S_IFSOCK | 0o666, 1234, 1),
        )
        after = restore_module.SystemdUserBusContext(
            environment=before.environment,
            runtime_identity=before.runtime_identity,
            bus_identity=(1, 5, stat.S_IFSOCK | 0o666, 1234, 1),
        )
        completed = mock.Mock(returncode=0, stdout="running\n", stderr="")
        with mock.patch.object(
            restore_module,
            "_systemd_user_bus_context",
            side_effect=[before, after],
        ), mock.patch.object(
            restore_module.subprocess,
            "run",
            return_value=completed,
        ):
            with self.assertRaisesRegex(
                EnvironmentRestoreError, "RESTORE_SYSTEMD_BUS_DRIFT"
            ):
                restore_module._systemctl_run(["/usr/bin/systemctl", "--user"])

    def test_systemd_user_bus_context_validates_runtime_and_socket(self) -> None:
        runtime_root = Path(self.temporary.name) / "run" / "user"
        runtime_dir = runtime_root / str(os.getuid())
        bus = runtime_dir / "bus"
        context = self._mocked_user_bus_context(
            self._metadata(stat.S_IFDIR, 0o700, nlink=2),
            self._metadata(stat.S_IFSOCK, 0o666, inode=13),
        )
        self.assertEqual(str(runtime_dir), context.environment["XDG_RUNTIME_DIR"])
        self.assertEqual(
            f"unix:path={bus}", context.environment["DBUS_SESSION_BUS_ADDRESS"]
        )

    def test_systemd_user_bus_context_rejects_missing_runtime(self) -> None:
        runtime_root = Path(self.temporary.name) / "run" / "user"
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            restore_module._systemd_user_bus_context(runtime_root=runtime_root)

    def test_systemd_user_bus_context_accepts_nonwritable_runtime_mode_0755(
        self,
    ) -> None:
        runtime_root = Path(self.temporary.name) / "run" / "user"
        runtime_dir = runtime_root / str(os.getuid())
        context = self._mocked_user_bus_context(
            self._metadata(stat.S_IFDIR, 0o755, nlink=2),
            self._metadata(stat.S_IFSOCK, 0o666, inode=13),
        )
        self.assertEqual(str(runtime_dir), context.environment["XDG_RUNTIME_DIR"])

    def test_systemd_user_bus_context_rejects_group_writable_runtime(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            self._mocked_user_bus_context(self._metadata(stat.S_IFDIR, 0o775))

    def test_systemd_user_bus_context_rejects_incomplete_owner_access(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            self._mocked_user_bus_context(self._metadata(stat.S_IFDIR, 0o655))

    def test_systemd_user_bus_context_rejects_world_writable_runtime(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            self._mocked_user_bus_context(self._metadata(stat.S_IFDIR, 0o757))

    def test_systemd_user_bus_context_rejects_symlink_runtime_component(self) -> None:
        actual_root = Path(self.temporary.name) / "actual-user"
        actual_root.mkdir(mode=0o700)
        linked_root = Path(self.temporary.name) / "linked-user"
        linked_root.symlink_to(actual_root, target_is_directory=True)
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            restore_module._systemd_user_bus_context(runtime_root=linked_root)

    def test_systemd_user_bus_context_rejects_symlink_runtime_directory(self) -> None:
        runtime_root = Path(self.temporary.name) / "run" / "user"
        runtime_root.mkdir(parents=True)
        actual_runtime = Path(self.temporary.name) / "actual-runtime"
        actual_runtime.mkdir(mode=0o700)
        (runtime_root / str(os.getuid())).symlink_to(
            actual_runtime, target_is_directory=True
        )
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            restore_module._systemd_user_bus_context(runtime_root=runtime_root)

    def test_systemd_user_bus_context_rejects_runtime_wrong_owner(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            self._mocked_user_bus_context(
                self._metadata(stat.S_IFDIR, 0o700, uid=os.getuid() + 1)
            )

    def test_systemd_user_bus_context_rejects_runtime_wrong_type(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_RUNTIME_UNSAFE"):
            self._mocked_user_bus_context(self._metadata(stat.S_IFREG, 0o700))

    def test_systemd_user_bus_context_rejects_missing_bus(self) -> None:
        runtime_root = Path(self.temporary.name) / "run" / "user"
        runtime_dir = runtime_root / str(os.getuid())
        runtime_dir.mkdir(parents=True, mode=0o700)
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_BUS_UNSAFE"):
            restore_module._systemd_user_bus_context(runtime_root=runtime_root)

    def test_systemd_user_bus_context_rejects_symlink_bus(self) -> None:
        runtime_root = Path(self.temporary.name) / "run" / "user"
        runtime_dir = runtime_root / str(os.getuid())
        runtime_dir.mkdir(parents=True, mode=0o700)
        target = Path(self.temporary.name) / "other-bus"
        target.write_text("not a socket", encoding="utf-8")
        (runtime_dir / "bus").symlink_to(target)
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_BUS_UNSAFE"):
            restore_module._systemd_user_bus_context(runtime_root=runtime_root)

    def test_systemd_user_bus_context_rejects_bus_wrong_owner(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_BUS_UNSAFE"):
            self._mocked_user_bus_context(
                self._metadata(stat.S_IFDIR, 0o700, nlink=2),
                self._metadata(
                    stat.S_IFSOCK, 0o666, uid=os.getuid() + 1, inode=13
                ),
            )

    def test_systemd_user_bus_context_rejects_bus_wrong_type(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_BUS_UNSAFE"):
            self._mocked_user_bus_context(
                self._metadata(stat.S_IFDIR, 0o700, nlink=2),
                self._metadata(stat.S_IFREG, 0o600, inode=13),
            )

    def test_systemd_user_bus_context_rejects_bus_link_count(self) -> None:
        with self.assertRaisesRegex(EnvironmentRestoreError, "SYSTEMD_BUS_UNSAFE"):
            self._mocked_user_bus_context(
                self._metadata(stat.S_IFDIR, 0o700, nlink=2),
                self._metadata(stat.S_IFSOCK, 0o666, nlink=2, inode=13),
            )

    def test_active_state_in_backup_is_not_revived(self) -> None:
        self.backup.unlink()
        self._create_database(
            self.backup,
            marker="backup",
            hosted_state="PREPARED",
        )
        with self.assertRaisesRegex(EnvironmentRestoreError, "SQLITE_ACTIVITY_ACTIVE"):
            self._control()

    def test_invalid_backup_integrity_fails_without_source_placement(self) -> None:
        current_sha256 = _sha256(self.database)
        self.backup.write_bytes(b"not a sqlite database")
        os.chmod(self.backup, 0o600)
        with self.assertRaisesRegex(EnvironmentRestoreError, "BACKUP_INTEGRITY_INVALID"):
            self._control()
        self.assertEqual(current_sha256, _sha256(self.database))
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.forensic_dir.exists())

    def test_ambiguous_database_and_backup_sidecars_fail_closed(self) -> None:
        current_wal = Path(f"{self.database}-wal")
        current_wal.write_bytes(b"ambiguous")
        os.chmod(current_wal, 0o600)
        with self.assertRaisesRegex(EnvironmentRestoreError, "DATABASE_SIDECAR_AMBIGUOUS"):
            self._control()
        current_wal.unlink()

        backup_wal = Path(f"{self.backup}-wal")
        backup_wal.write_bytes(b"ambiguous")
        os.chmod(backup_wal, 0o600)
        with self.assertRaisesRegex(EnvironmentRestoreError, "BACKUP_SIDECAR_AMBIGUOUS"):
            self._control()

    def test_complete_sidecar_pair_is_preserved_with_current_database(self) -> None:
        wal = Path(f"{self.database}-wal")
        shm = Path(f"{self.database}-shm")
        writer = sqlite3.connect(self.database)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE wal_marker(value TEXT)")
        writer.execute("INSERT INTO wal_marker VALUES ('preserve')")
        writer.commit()
        self.assertTrue(wal.exists())
        self.assertTrue(shm.exists())
        wal_bytes = wal.read_bytes()
        shm_bytes = shm.read_bytes()
        writer.close()
        wal.write_bytes(wal_bytes)
        shm.write_bytes(shm_bytes)
        os.chmod(wal, 0o600)
        os.chmod(shm, 0o600)
        result = self._control(
            apply=True,
            confirmation=f"RESTORE:{self.database}",
        )
        self.assertEqual(
            [self.database.name, wal.name, shm.name], result["forensic_files"]
        )
        self.assertTrue((self.forensic_dir / wal.name).is_file())
        self.assertTrue((self.forensic_dir / shm.name).is_file())

    def test_exclusive_restore_lock_rejects_concurrent_attempt(self) -> None:
        with restore_module._exclusive_restore_lock(self.root):
            with self.assertRaisesRegex(EnvironmentRestoreError, "RESTORE_LOCK_BUSY"):
                self._control()
        self.assertTrue(self.database.is_file())
        self.assertEqual("current", self._marker(self.database))

    def test_every_placement_transition_failure_restores_valid_canonical_database(self) -> None:
        wal, shm = restore_module._sidecars(self.database)
        real_rename = os.rename
        real_replace = os.replace
        for name in ("database_move", "wal_move", "shm_move", "stage_install"):
            with self.subTest(transition=name):
                if self.forensic_dir.exists():
                    self.forensic_dir.rmdir()
                if self.stage.exists():
                    self.stage.unlink()
                for path in (wal, shm, self.database):
                    if path.exists():
                        path.unlink()
                self._create_database(self.database, marker="current")
                writer = sqlite3.connect(self.database)
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE transition_marker(value TEXT)")
                writer.execute("INSERT INTO transition_marker VALUES ('preserve')")
                writer.commit()
                wal_bytes = wal.read_bytes()
                shm_bytes = shm.read_bytes()
                writer.close()
                wal.write_bytes(wal_bytes)
                shm.write_bytes(shm_bytes)
                os.chmod(wal, 0o600)
                os.chmod(shm, 0o600)
                expected_database = self.database.read_bytes()
                expected_wal = wal.read_bytes()
                expected_shm_size = shm.stat().st_size
                targets = {
                    "database_move": (
                        self.database,
                        self.forensic_dir / self.database.name,
                    ),
                    "wal_move": (wal, self.forensic_dir / wal.name),
                    "shm_move": (shm, self.forensic_dir / shm.name),
                    "stage_install": (self.stage, self.database),
                }
                target = targets[name]

                def failing_rename(source: object, destination: object) -> None:
                    if (Path(source), Path(destination)) == target:
                        real_rename(source, destination)
                        raise OSError(f"injected {name}")
                    real_rename(source, destination)

                def failing_replace(source: object, destination: object) -> None:
                    if (Path(source), Path(destination)) == target:
                        real_replace(source, destination)
                        raise OSError(f"injected {name}")
                    real_replace(source, destination)

                with mock.patch.object(os, "rename", side_effect=failing_rename), mock.patch.object(
                    os, "replace", side_effect=failing_replace
                ):
                    with self.assertRaisesRegex(
                        EnvironmentRestoreError, "RESTORE_PLACEMENT_FAILED"
                    ):
                        self._control(
                            apply=True,
                            confirmation=f"RESTORE:{self.database}",
                        )

                self.assertTrue(self.database.is_file())
                self.assertEqual(expected_database, self.database.read_bytes())
                self.assertTrue(wal.is_file())
                self.assertEqual(expected_wal, wal.read_bytes())
                self.assertTrue(shm.is_file())
                self.assertEqual(expected_shm_size, shm.stat().st_size)
                self.assertEqual("current", self._marker(self.database))
                integrity = sqlite3.connect(self.database).execute(
                    "PRAGMA integrity_check"
                ).fetchone()[0]
                self.assertEqual("ok", integrity)

    @staticmethod
    def _marker(path: Path) -> str:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return str(
                connection.execute("SELECT value FROM restore_marker").fetchone()[0]
            )
        finally:
            connection.close()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
