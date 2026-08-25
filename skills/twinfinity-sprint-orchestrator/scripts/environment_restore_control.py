#!/usr/bin/env python3
"""Owner-safe, fail-closed disaster restore for the coordination database."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import subprocess
import sys
from typing import Any
from urllib.parse import quote


DEFAULT_DATABASE = (
    Path(pwd.getpwuid(os.getuid()).pw_dir)
    / ".codex"
    / "twinfinity-coordination"
    / "ack-transactions.sqlite3"
)
MANAGED_UNITS = (
    "twinfinity-coordination-supervisor.timer",
    "twinfinity-hosted-operation-supervisor.timer",
    "twinfinity-portfolio-graph-supervisor.timer",
    "twinfinity-coordination-supervisor.service",
    "twinfinity-hosted-operation-supervisor.service",
    "twinfinity-portfolio-graph-supervisor.service",
)


class EnvironmentRestoreError(RuntimeError):
    """Raised before unsafe or ambiguous restore work can continue."""


@dataclass(frozen=True)
class RestorePaths:
    database: Path
    backup: Path
    stage: Path
    forensic_dir: Path

    @property
    def root(self) -> Path:
        return self.database.parent


SystemdProbe = Callable[[], Sequence[str]]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _sidecars(path: Path) -> tuple[Path, Path]:
    return (Path(f"{path}-wal"), Path(f"{path}-shm"))


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _reject_symlink_components(path: Path, *, allow_missing_tail: bool = False) -> None:
    if not path.is_absolute():
        raise EnvironmentRestoreError("RESTORE_PATH_NOT_ABSOLUTE")
    current = Path(path.anchor)
    missing = False
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            missing = True
            if allow_missing_tail:
                continue
            raise EnvironmentRestoreError("RESTORE_PATH_MISSING")
        if missing:
            raise EnvironmentRestoreError("RESTORE_PATH_AMBIGUOUS")
        if stat.S_ISLNK(metadata.st_mode):
            raise EnvironmentRestoreError("RESTORE_PATH_SYMLINK")


def _require_private_directory(path: Path) -> None:
    _reject_symlink_components(path)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise EnvironmentRestoreError("RESTORE_DIRECTORY_UNSAFE")


def _file_snapshot(path: Path) -> dict[str, Any]:
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EnvironmentRestoreError("RESTORE_FILE_UNSAFE") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise EnvironmentRestoreError("RESTORE_FILE_UNSAFE")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _metadata_identity(before) != _metadata_identity(after):
            raise EnvironmentRestoreError("RESTORE_FILE_DRIFT")
        return {
            "device": before.st_dev,
            "inode": before.st_ino,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def _readonly_connection(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(str(path), safe='/')}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=0)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=0")
    return connection


def _inspect_database(path: Path, *, require_integrity: bool) -> dict[str, int | str]:
    try:
        connection = _readonly_connection(path)
        try:
            if require_integrity:
                integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
                if integrity != ["ok"]:
                    raise EnvironmentRestoreError("BACKUP_INTEGRITY_INVALID")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                    "('executor_attempts','coordination_terminal_watches','hosted_operations')"
                )
            }
            required = {
                "executor_attempts",
                "coordination_terminal_watches",
                "hosted_operations",
            }
            if tables != required:
                raise EnvironmentRestoreError("RESTORE_CONTROL_SCHEMA_INCOMPLETE")
            active_attempts = int(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_attempts "
                    "WHERE state IN ('RESERVED','LAUNCHING','RUNNING')"
                ).fetchone()[0]
            )
            active_watches = int(
                connection.execute(
                    "SELECT COUNT(*) FROM coordination_terminal_watches WHERE state='ACTIVE'"
                ).fetchone()[0]
            )
            active_hosted = int(
                connection.execute(
                    "SELECT COUNT(*) FROM hosted_operations "
                    "WHERE state IN ('WAITING','PREPARED','CLAIMED')"
                ).fetchone()[0]
            )
        finally:
            connection.close()
    except EnvironmentRestoreError:
        raise
    except sqlite3.Error as exc:
        if require_integrity:
            raise EnvironmentRestoreError("BACKUP_INTEGRITY_INVALID") from exc
        raise EnvironmentRestoreError("RESTORE_DATABASE_UNREADABLE") from exc
    if active_attempts or active_watches or active_hosted:
        raise EnvironmentRestoreError("RESTORE_SQLITE_ACTIVITY_ACTIVE")
    return {
        "active_attempts": active_attempts,
        "active_hosted_operations": active_hosted,
        "active_terminal_watches": active_watches,
        "integrity": "ok" if require_integrity else "not_requested",
    }


def _systemctl_run(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
            env={
                "HOME": str(Path(pwd.getpwuid(os.getuid()).pw_dir)),
                "PATH": "/usr/bin:/bin",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentRestoreError("RESTORE_SYSTEMD_PROBE_FAILED") from exc
    if result.returncode != 0:
        raise EnvironmentRestoreError("RESTORE_SYSTEMD_PROBE_FAILED")
    return result.stdout


def probe_active_systemd_units() -> list[str]:
    show = _systemctl_run(
        [
            "/usr/bin/systemctl",
            "--user",
            "show",
            "--no-pager",
            "--property=Id",
            "--property=ActiveState",
            *MANAGED_UNITS,
        ]
    )
    active: list[str] = []
    blocks = [block for block in show.strip().split("\n\n") if block.strip()]
    if len(blocks) != len(MANAGED_UNITS):
        raise EnvironmentRestoreError("RESTORE_SYSTEMD_PROBE_AMBIGUOUS")
    for block in blocks:
        properties = dict(
            line.split("=", 1) for line in block.splitlines() if "=" in line
        )
        unit = properties.get("Id")
        state = properties.get("ActiveState")
        if not unit or not state:
            raise EnvironmentRestoreError("RESTORE_SYSTEMD_PROBE_AMBIGUOUS")
        if state not in {"inactive", "failed"}:
            active.append(unit)

    role_output = _systemctl_run(
        [
            "/usr/bin/systemctl",
            "--user",
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "twinfinity-role-executor-*",
        ]
    )
    for line in role_output.splitlines():
        fields = line.split(None, 4)
        if len(fields) < 4:
            raise EnvironmentRestoreError("RESTORE_SYSTEMD_PROBE_AMBIGUOUS")
        unit, _load, state, _substate = fields[:4]
        if state not in {"inactive", "failed"}:
            active.append(unit)
    return sorted(set(active))


def _validate_layout(paths: RestorePaths) -> None:
    values = (paths.database, paths.backup, paths.stage, paths.forensic_dir)
    if any(not path.is_absolute() for path in values) or len(set(values)) != len(values):
        raise EnvironmentRestoreError("RESTORE_PATH_LAYOUT_INVALID")
    if (
        paths.backup.parent != paths.root / "backups"
        or paths.stage.parent != paths.root
        or paths.forensic_dir.parent != paths.root / "forensics"
    ):
        raise EnvironmentRestoreError("RESTORE_PATH_LAYOUT_INVALID")
    _require_private_directory(paths.root)
    _require_private_directory(paths.backup.parent)
    if _lexists(paths.root / "forensics"):
        _require_private_directory(paths.root / "forensics")
    else:
        _reject_symlink_components(paths.root / "forensics", allow_missing_tail=True)


def _require_new_destinations(paths: RestorePaths) -> None:
    candidates = (
        paths.stage,
        *_sidecars(paths.stage),
        paths.forensic_dir,
    )
    if any(_lexists(path) for path in candidates):
        raise EnvironmentRestoreError("RESTORE_DESTINATION_EXISTS")
    _reject_symlink_components(paths.stage, allow_missing_tail=True)
    _reject_symlink_components(paths.forensic_dir, allow_missing_tail=True)


def _sidecar_snapshots(path: Path, *, backup: bool) -> dict[str, dict[str, Any]]:
    wal, shm = _sidecars(path)
    present = (_lexists(wal), _lexists(shm))
    if backup and any(present):
        raise EnvironmentRestoreError("RESTORE_BACKUP_SIDECAR_AMBIGUOUS")
    if not backup and present[0] != present[1]:
        raise EnvironmentRestoreError("RESTORE_DATABASE_SIDECAR_AMBIGUOUS")
    snapshots: dict[str, dict[str, Any]] = {}
    for sidecar, exists in zip((wal, shm), present, strict=True):
        if exists:
            snapshots[sidecar.name] = _file_snapshot(sidecar)
    return snapshots


def _sidecars_unchanged(
    expected: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> bool:
    if set(expected) != set(current):
        return False
    for name, before in expected.items():
        after = current[name]
        fields = ("device", "inode", "size") if name.endswith("-shm") else tuple(before)
        if any(before[field] != after[field] for field in fields):
            return False
    return True


def _preflight(paths: RestorePaths, systemd_probe: SystemdProbe) -> dict[str, Any]:
    _validate_layout(paths)
    _require_new_destinations(paths)
    active_units = list(systemd_probe())
    if active_units:
        raise EnvironmentRestoreError("RESTORE_SYSTEMD_ACTIVITY_ACTIVE")
    database_snapshot = _file_snapshot(paths.database)
    backup_snapshot = _file_snapshot(paths.backup)
    database_sidecars = _sidecar_snapshots(paths.database, backup=False)
    _sidecar_snapshots(paths.backup, backup=True)
    current_state = _inspect_database(paths.database, require_integrity=False)
    backup_state = _inspect_database(paths.backup, require_integrity=True)
    return {
        "backup": backup_snapshot,
        "backup_state": backup_state,
        "current": database_snapshot,
        "current_sidecars": database_sidecars,
        "current_state": current_state,
    }


def _restore_stage(paths: RestorePaths) -> dict[str, Any]:
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    old_umask = os.umask(0o077)
    try:
        descriptor = os.open(paths.stage, flags, 0o600)
    except OSError as exc:
        raise EnvironmentRestoreError("RESTORE_STAGE_CREATE_FAILED") from exc
    finally:
        os.umask(old_umask)
    os.close(descriptor)
    try:
        source = _readonly_connection(paths.backup)
        destination = sqlite3.connect(paths.stage, isolation_level=None, timeout=0)
        try:
            source.backup(destination)
            destination.execute("PRAGMA journal_mode=DELETE")
        finally:
            destination.close()
            source.close()
    except sqlite3.Error as exc:
        raise EnvironmentRestoreError("RESTORE_STAGE_FAILED") from exc
    os.chmod(paths.stage, 0o600, follow_symlinks=False)
    if any(_lexists(path) for path in _sidecars(paths.stage)):
        raise EnvironmentRestoreError("RESTORE_STAGE_SIDECAR_AMBIGUOUS")
    snapshot = _file_snapshot(paths.stage)
    state = _inspect_database(paths.stage, require_integrity=True)
    return {"snapshot": snapshot, "state": state}


def _revalidate(
    paths: RestorePaths,
    expected: dict[str, Any],
    stage: dict[str, Any],
    systemd_probe: SystemdProbe,
) -> None:
    if list(systemd_probe()):
        raise EnvironmentRestoreError("RESTORE_SYSTEMD_ACTIVITY_ACTIVE")
    if _lexists(paths.forensic_dir):
        raise EnvironmentRestoreError("RESTORE_DESTINATION_EXISTS")
    if _file_snapshot(paths.database) != expected["current"]:
        raise EnvironmentRestoreError("RESTORE_FILE_DRIFT")
    if _file_snapshot(paths.backup) != expected["backup"]:
        raise EnvironmentRestoreError("RESTORE_FILE_DRIFT")
    current_sidecars = _sidecar_snapshots(paths.database, backup=False)
    if not _sidecars_unchanged(expected["current_sidecars"], current_sidecars):
        raise EnvironmentRestoreError("RESTORE_FILE_DRIFT")
    _sidecar_snapshots(paths.backup, backup=True)
    _inspect_database(paths.database, require_integrity=False)
    _inspect_database(paths.backup, require_integrity=True)
    if _file_snapshot(paths.stage) != stage["snapshot"]:
        raise EnvironmentRestoreError("RESTORE_FILE_DRIFT")
    _inspect_database(paths.stage, require_integrity=True)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_restore_lock(root: Path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise EnvironmentRestoreError("RESTORE_LOCK_OPEN_FAILED") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise EnvironmentRestoreError("RESTORE_LOCK_UNSAFE")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise EnvironmentRestoreError("RESTORE_LOCK_BUSY") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _same_snapshot(path: Path, expected: dict[str, Any]) -> bool:
    try:
        current = _file_snapshot(path)
    except EnvironmentRestoreError:
        return False
    stable_fields = ("device", "inode", "size", "mtime_ns", "sha256")
    return all(current[field] == expected[field] for field in stable_fields)


def _sidecars_restored(
    expected: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> bool:
    if set(expected) != set(current):
        return False
    for name, before in expected.items():
        after = current[name]
        fields = ("device", "inode", "size")
        if not name.endswith("-shm"):
            fields += ("mtime_ns", "sha256")
        if any(before[field] != after[field] for field in fields):
            return False
    return True


def _rollback_placement(
    paths: RestorePaths,
    transitions: Sequence[tuple[Path, Path]],
    expected: dict[str, Any],
    stage_snapshot: dict[str, Any],
) -> None:
    errors: list[str] = []

    # os.replace() is atomic, but an injected or unusual post-syscall exception can
    # be observed after the staged database reached the canonical path. Preserve it
    # back at the stage path before restoring the former canonical database.
    if _lexists(paths.database) and not _same_snapshot(
        paths.database, expected["current"]
    ):
        if not _same_snapshot(paths.database, stage_snapshot):
            errors.append("RESTORE_ROLLBACK_CANONICAL_AMBIGUOUS")
        elif _lexists(paths.stage):
            errors.append("RESTORE_ROLLBACK_STAGE_COLLISION")
        else:
            try:
                os.rename(paths.database, paths.stage)
            except OSError:
                errors.append("RESTORE_ROLLBACK_STAGE_PRESERVE_FAILED")

    # Determine what actually moved from filesystem state rather than trusting
    # which Python call returned. This also covers a syscall that succeeds and is
    # followed by an injected exception.
    for source, forensic in reversed(tuple(transitions)):
        source_exists = _lexists(source)
        forensic_exists = _lexists(forensic)
        if source_exists:
            continue
        if not forensic_exists:
            errors.append(f"RESTORE_ROLLBACK_SOURCE_MISSING:{source.name}")
            continue
        try:
            os.rename(forensic, source)
        except OSError:
            errors.append(f"RESTORE_ROLLBACK_MOVE_FAILED:{source.name}")

    try:
        _fsync_directory(paths.root)
        if _lexists(paths.forensic_dir):
            _fsync_directory(paths.forensic_dir)
    except OSError:
        errors.append("RESTORE_ROLLBACK_FSYNC_FAILED")

    if not _same_snapshot(paths.database, expected["current"]):
        errors.append("RESTORE_ROLLBACK_DATABASE_INVALID")
    try:
        restored_sidecars = _sidecar_snapshots(paths.database, backup=False)
    except EnvironmentRestoreError:
        errors.append("RESTORE_ROLLBACK_SIDECARS_INVALID")
    else:
        if not _sidecars_restored(expected["current_sidecars"], restored_sidecars):
            errors.append("RESTORE_ROLLBACK_SIDECARS_INVALID")
    try:
        _inspect_database(paths.database, require_integrity=True)
    except EnvironmentRestoreError:
        errors.append("RESTORE_ROLLBACK_DATABASE_INVALID")

    if errors:
        raise EnvironmentRestoreError(
            "RESTORE_ROLLBACK_FAILED:" + ",".join(sorted(set(errors)))
        )


def _place_restore(
    paths: RestorePaths,
    sidecar_names: Sequence[str],
    expected: dict[str, Any],
    stage_snapshot: dict[str, Any],
) -> dict[str, Any]:
    forensics_parent = paths.forensic_dir.parent
    if not _lexists(forensics_parent):
        old_umask = os.umask(0o077)
        try:
            forensics_parent.mkdir(mode=0o700)
        except (FileExistsError, OSError) as exc:
            raise EnvironmentRestoreError("RESTORE_FORENSIC_PARENT_CREATE_FAILED") from exc
        finally:
            os.umask(old_umask)
    _require_private_directory(forensics_parent)
    old_umask = os.umask(0o077)
    try:
        paths.forensic_dir.mkdir(mode=0o700)
    except (FileExistsError, OSError) as exc:
        raise EnvironmentRestoreError("RESTORE_FORENSIC_CREATE_FAILED") from exc
    finally:
        os.umask(old_umask)
    _require_private_directory(paths.forensic_dir)

    sources = [paths.database, *(paths.root / name for name in sidecar_names)]
    transitions = tuple(
        (source, paths.forensic_dir / source.name) for source in sources
    )
    try:
        for source, forensic in transitions:
            os.rename(source, forensic)
        _fsync_directory(paths.forensic_dir)
        os.replace(paths.stage, paths.database)
        _fsync_directory(paths.root)

        placed = _file_snapshot(paths.database)
        placed_state = _inspect_database(paths.database, require_integrity=True)
        immutable_stage_fields = ("device", "inode", "size", "sha256")
        if (
            any(
                placed[field] != stage_snapshot[field]
                for field in immutable_stage_fields
            )
            or placed_state["integrity"] != "ok"
        ):
            raise EnvironmentRestoreError("RESTORE_POSTCONDITION_FAILED")
        for name in (paths.database.name, *sidecar_names):
            _file_snapshot(paths.forensic_dir / name)
        return placed
    except BaseException as exc:
        mutation_started = any(
            _lexists(forensic) or not _lexists(source)
            for source, forensic in transitions
        )
        if mutation_started:
            try:
                _rollback_placement(paths, transitions, expected, stage_snapshot)
            except EnvironmentRestoreError as rollback_exc:
                raise rollback_exc from exc
        if isinstance(exc, EnvironmentRestoreError):
            raise
        raise EnvironmentRestoreError("RESTORE_PLACEMENT_FAILED") from exc


def control_restore(
    *,
    database: Path,
    backup: Path,
    stage: Path,
    forensic_dir: Path,
    apply: bool = False,
    confirmation: str | None = None,
    systemd_probe: SystemdProbe = probe_active_systemd_units,
) -> dict[str, Any]:
    paths = RestorePaths(
        database=Path(database),
        backup=Path(backup),
        stage=Path(stage),
        forensic_dir=Path(forensic_dir),
    )
    expected_confirmation = f"RESTORE:{paths.database}"
    if apply and confirmation != expected_confirmation:
        raise EnvironmentRestoreError("RESTORE_CONFIRMATION_REQUIRED")
    if not apply and confirmation is not None:
        raise EnvironmentRestoreError("RESTORE_CONFIRMATION_WITHOUT_APPLY")

    with _exclusive_restore_lock(paths.root):
        preflight = _preflight(paths, systemd_probe)
        result: dict[str, Any] = {
            "backup": str(paths.backup),
            "backup_sha256": preflight["backup"]["sha256"],
            "database": str(paths.database),
            "forensic_dir": str(paths.forensic_dir),
            "kind": "TWINFINITY_ENVIRONMENT_RESTORE_CONTROL_V1",
            "stage": str(paths.stage),
        }
        if not apply:
            result.update(
                {
                    "confirmation_required": expected_confirmation,
                    "mode": "DRY_RUN",
                    "state": "READY",
                }
            )
            return result

        stage_result = _restore_stage(paths)
        _revalidate(paths, preflight, stage_result, systemd_probe)
        sidecar_names = tuple(preflight["current_sidecars"])
        placed = _place_restore(
            paths,
            sidecar_names,
            preflight,
            stage_result["snapshot"],
        )
        result.update(
            {
                "forensic_files": [paths.database.name, *sidecar_names],
                "mode": "APPLY",
                "restored_sha256": placed["sha256"],
                "state": "COMPLETE",
            }
        )
        return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dry-run or apply one owner-safe coordination SQLite disaster restore."
    )
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--forensic-dir", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", help="Exact RESTORE:<absolute-database-path> confirmation")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = control_restore(
            database=args.database,
            backup=args.backup,
            stage=args.stage,
            forensic_dir=args.forensic_dir,
            apply=args.apply,
            confirmation=args.confirm,
        )
    except EnvironmentRestoreError as exc:
        print(_canonical_json({"error": str(exc), "state": "HOLD"}), file=sys.stderr)
        return 1
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
