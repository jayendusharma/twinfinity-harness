"""Owner-only SQLite path preparation shared by coordination helpers."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote


class UnsafeSQLitePathError(ValueError):
    """Raised before SQLite opens an unsafe database path."""


def validate_owner_database(path: Path) -> Path:
    """Validate an existing owner-only database without creating or changing it."""

    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    path = Path(os.path.abspath(path))

    chain = [*reversed(path.parent.parents), path.parent]
    for directory in chain:
        try:
            metadata = directory.lstat()
        except FileNotFoundError as exc:
            raise UnsafeSQLitePathError("DATABASE_PARENT_UNSAFE") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafeSQLitePathError("DATABASE_PARENT_UNSAFE")

    parent = path.parent.lstat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise UnsafeSQLitePathError("DATABASE_PARENT_UNSAFE")

    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise UnsafeSQLitePathError("DATABASE_UNSAFE") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise UnsafeSQLitePathError("DATABASE_UNSAFE")
    return path


def open_owner_database_readonly(path: Path) -> sqlite3.Connection:
    """Open one validated existing database with an enforced no-write contract."""

    validated = validate_owner_database(path)
    uri = f"file:{quote(validated.as_posix(), safe='/')}?mode=ro&immutable=0"
    connection = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def prepare_owner_database(path: Path) -> None:
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path

    chain = [*reversed(path.parent.parents), path.parent]
    for directory in chain:
        try:
            directory_metadata = directory.lstat()
        except FileNotFoundError:
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            directory_metadata = directory.lstat()
        if stat.S_ISLNK(directory_metadata.st_mode):
            raise UnsafeSQLitePathError("DATABASE_PARENT_UNSAFE")
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise UnsafeSQLitePathError("DATABASE_PARENT_UNSAFE")

    parent = path.parent.lstat()
    if (
        parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise UnsafeSQLitePathError("DATABASE_PARENT_UNSAFE")

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        metadata = path.lstat()

    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise UnsafeSQLitePathError("DATABASE_UNSAFE")
