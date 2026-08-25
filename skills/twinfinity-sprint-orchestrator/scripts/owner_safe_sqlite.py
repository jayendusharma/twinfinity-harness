"""Owner-only SQLite path preparation shared by coordination helpers."""

from __future__ import annotations

import os
from pathlib import Path
import stat


class UnsafeSQLitePathError(ValueError):
    """Raised before SQLite opens an unsafe database path."""


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
