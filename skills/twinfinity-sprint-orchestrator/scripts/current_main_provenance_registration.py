#!/usr/bin/env python3
"""Atomic accepted-main provenance and v2 read-only Git registration."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import sys
from typing import Any, Callable
from urllib.parse import quote

from owner_safe_sqlite import UnsafeSQLitePathError, validate_owner_database
from repository_git_registry import (
    RepositoryGitRegistryError,
    _metadata_identity,
    _open_absolute_directory,
    load_repository_git_registration,
    prove_repository_git_current_main,
)


REQUEST_SCHEMA = "twinfinity-current-main-provenance-registration/v1"
PROVENANCE_SCHEMA = "twinfinity-current-main-provenance/v1"
REGISTRATION_SCHEMA = "twinfinity-repository-git-registration/v2"
PRIVATE_PREVIEW_SCHEMA = "twinfinity-current-main-registration-private-preview/v1"
PUBLIC_PREVIEW_SCHEMA = "twinfinity-current-main-registration-preview/v1"
CONFIRMATION_SCHEMA = "twinfinity-current-main-registration-confirmation/v1"
RECEIPT_SCHEMA = "twinfinity-current-main-registration-receipt/v1"

REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
OPERATION_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_SECONDS = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)

IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000
_PARENT_MASK = IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT | IN_IGNORED
_CONTAINER_MASK = IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE
_EVENT = struct.Struct("iIII")
_MAX_EVENT_BYTES = 1024 * 1024


class CurrentMainRegistrationError(ValueError):
    """Typed value-free fail-closed current-main registration error."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_nlink),
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
        value[key] = item
    return value


def _require_keys(value: Any, expected: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    return value


def _require_string(value: Any, pattern: re.Pattern[str] | None = None) -> str:
    if type(value) is not str or not value or (pattern is not None and pattern.fullmatch(value) is None):
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    return value


def validate_request(request: Any) -> dict[str, Any]:
    request = _require_keys(
        request,
        {
            "schema",
            "operation_key",
            "repository",
            "bootstrap",
            "accepted_source",
            "recorded_at",
        },
    )
    if request["schema"] != REQUEST_SCHEMA:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    _require_string(request["operation_key"], OPERATION_KEY)
    _require_string(request["repository"], REPOSITORY)
    _require_string(request["recorded_at"], RFC3339_SECONDS)
    bootstrap = _require_keys(
        request["bootstrap"], {"bootstrap_id", "manifest_sha256"}
    )
    bootstrap_id = _require_string(bootstrap["bootstrap_id"])
    if len(bootstrap_id) > 256:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    _require_string(bootstrap["manifest_sha256"], SHA256)
    accepted = _require_keys(
        request["accepted_source"],
        {
            "merge_sha",
            "main_sha",
            "tree_sha",
            "source_receipt_sha256",
            "independent_review",
            "ci",
            "stopped_state_receipt_sha256",
            "approval_execution_scope_sha256",
        },
    )
    for key in ("merge_sha", "main_sha", "tree_sha"):
        _require_string(accepted[key], GIT_SHA)
    if accepted["merge_sha"] != accepted["main_sha"]:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    for key in (
        "source_receipt_sha256",
        "stopped_state_receipt_sha256",
        "approval_execution_scope_sha256",
    ):
        _require_string(accepted[key], SHA256)
    review = _require_keys(
        accepted["independent_review"], {"receipt_id", "receipt_sha256"}
    )
    review_id = _require_string(review["receipt_id"])
    if len(review_id) > 256:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    _require_string(review["receipt_sha256"], SHA256)
    ci = _require_keys(accepted["ci"], {"run_id", "job_id", "receipt_sha256"})
    if type(ci["run_id"]) is not int or ci["run_id"] < 1:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    if type(ci["job_id"]) is not int or ci["job_id"] < 1:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
    _require_string(ci["receipt_sha256"], SHA256)
    return request


def load_request(path: Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
        if not raw or len(raw) > 1024 * 1024:
            raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID")
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except CurrentMainRegistrationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REQUEST_INVALID") from exc
    return validate_request(value)


_LIBC = ctypes.CDLL(None, use_errno=True)
_INOTIFY_INIT1 = getattr(_LIBC, "inotify_init1", None)
_INOTIFY_ADD_WATCH = getattr(_LIBC, "inotify_add_watch", None)
if _INOTIFY_INIT1 is not None:
    _INOTIFY_INIT1.argtypes = [ctypes.c_int]
    _INOTIFY_INIT1.restype = ctypes.c_int
if _INOTIFY_ADD_WATCH is not None:
    _INOTIFY_ADD_WATCH.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    _INOTIFY_ADD_WATCH.restype = ctypes.c_int


def _inotify_init() -> int:
    if _INOTIFY_INIT1 is None:
        raise OSError(errno.ENOSYS, "inotify unavailable")
    descriptor = int(_INOTIFY_INIT1(os.O_NONBLOCK | os.O_CLOEXEC))
    if descriptor < 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    return descriptor


def _inotify_add_watch(descriptor: int, path: bytes, mask: int) -> int:
    if _INOTIFY_ADD_WATCH is None:
        raise OSError(errno.ENOSYS, "inotify unavailable")
    watch = int(_INOTIFY_ADD_WATCH(descriptor, path, mask))
    if watch < 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    return watch


def _read_inotify(descriptor: int) -> bytes:
    return os.read(descriptor, 65536)


def _test_failpoint(_name: str) -> None:
    """Private deterministic test seam; never accepts production caller input."""


class NamespaceEventGuard:
    """Monotonic descriptor-bound database-parent namespace evidence."""

    def __init__(
        self, parent_descriptor: int, container_descriptor: int, parent_name: str
    ) -> None:
        if (
            type(parent_descriptor) is not int
            or type(container_descriptor) is not int
            or type(parent_name) is not str
            or not parent_name
            or parent_name in {".", ".."}
            or "/" in parent_name
            or "\x00" in parent_name
        ):
            raise CurrentMainRegistrationError(
                "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE"
            )
        self._descriptor = -1
        self._parent_watch = -1
        self._container_watch = -1
        self._parent_name = parent_name.encode("utf-8", "strict")
        self._dirty = False
        self._closed = False
        try:
            if not Path("/proc/self/fd").is_dir():
                raise OSError(errno.ENOENT, "procfs unavailable")
            descriptor = _inotify_init()
            self._descriptor = descriptor
            self._parent_watch = _inotify_add_watch(
                descriptor,
                os.fsencode(f"/proc/self/fd/{parent_descriptor}"),
                _PARENT_MASK,
            )
            self._container_watch = _inotify_add_watch(
                descriptor,
                os.fsencode(f"/proc/self/fd/{container_descriptor}"),
                _CONTAINER_MASK,
            )
            if (
                self._parent_watch < 0
                or self._container_watch < 0
                or self._parent_watch == self._container_watch
            ):
                raise OSError(errno.EINVAL, "watch identity invalid")
            self.check()
        except CurrentMainRegistrationError:
            self.close()
            raise
        except (OSError, UnicodeError) as exc:
            self.close()
            raise CurrentMainRegistrationError(
                "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE"
            ) from exc

    def _consume(self, raw: bytes) -> None:
        if not raw or len(raw) > _MAX_EVENT_BYTES:
            self._dirty = True
            return
        offset = 0
        while offset < len(raw):
            if len(raw) - offset < _EVENT.size:
                self._dirty = True
                return
            watch, mask, _cookie, name_length = _EVENT.unpack_from(raw, offset)
            offset += _EVENT.size
            if name_length > _MAX_EVENT_BYTES or offset + name_length > len(raw):
                self._dirty = True
                return
            name_field = raw[offset : offset + name_length]
            offset += name_length
            if name_length:
                nul = name_field.find(b"\x00")
                if nul < 0 or any(name_field[nul:]):
                    self._dirty = True
                    return
                name = name_field[:nul]
            else:
                name = b""
            if watch == -1 and mask & IN_Q_OVERFLOW:
                self._dirty = True
                continue
            if watch == self._parent_watch:
                if name or not mask & (
                    IN_MOVE_SELF | IN_DELETE_SELF | IN_UNMOUNT | IN_IGNORED
                ):
                    self._dirty = True
                    continue
                self._dirty = True
                continue
            if watch == self._container_watch:
                if mask & (IN_IGNORED | IN_UNMOUNT):
                    self._dirty = True
                    continue
                if mask & _CONTAINER_MASK:
                    if not name or mask & ~(_CONTAINER_MASK | IN_ISDIR):
                        self._dirty = True
                    elif name == self._parent_name:
                        self._dirty = True
                    continue
                self._dirty = True
                continue
            self._dirty = True

    def check(self) -> None:
        if self._closed or self._descriptor < 0:
            raise CurrentMainRegistrationError(
                "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE"
            )
        while True:
            try:
                raw = _read_inotify(self._descriptor)
            except BlockingIOError:
                break
            except OSError as exc:
                raise CurrentMainRegistrationError(
                    "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE"
                ) from exc
            self._consume(raw)
            if not raw:
                raise CurrentMainRegistrationError(
                    "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE"
                )
        if self._dirty:
            raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_SUBSTITUTED")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._descriptor >= 0:
                os.close(self._descriptor)
            self._descriptor = -1


class GuardedDatabase:
    """Retain namespace, database flock, and SQLite identities in close order."""

    def __init__(self, database: Path, *, readonly: bool) -> None:
        self.database = Path(database)
        self.container_descriptor = -1
        self.parent_descriptor = -1
        self.database_descriptor = -1
        self.guard: NamespaceEventGuard | None = None
        self.connection: sqlite3.Connection | None = None
        self.parent_identity: tuple[int, ...] | None = None
        self.container_identity: tuple[int, ...] | None = None
        self.database_identity: tuple[int, ...] | None = None
        try:
            validated = validate_owner_database(self.database)
            self.database = validated
            self.container_descriptor = _open_absolute_directory(validated.parent.parent)
            self.parent_descriptor = _open_absolute_directory(validated.parent)
            container = os.fstat(self.container_descriptor)
            parent = os.fstat(self.parent_descriptor)
            if (
                _metadata_identity(container)
                != _metadata_identity(validated.parent.parent.lstat())
                or _metadata_identity(parent)
                != _metadata_identity(validated.parent.lstat())
            ):
                raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_SUBSTITUTED")
            self.container_identity = _stable_identity(container)
            self.parent_identity = _stable_identity(parent)
            self.guard = NamespaceEventGuard(
                self.parent_descriptor,
                self.container_descriptor,
                validated.parent.name,
            )
            flags = os.O_RDONLY if readonly else os.O_RDWR
            flags |= os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            self.database_descriptor = os.open(
                validated.name, flags, dir_fd=self.parent_descriptor
            )
            database_metadata = os.fstat(self.database_descriptor)
            named_database = os.stat(
                validated.name,
                dir_fd=self.parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(database_metadata.st_mode)
                or database_metadata.st_uid != os.getuid()
                or database_metadata.st_nlink != 1
                or stat.S_IMODE(database_metadata.st_mode) != 0o600
                or _metadata_identity(database_metadata)
                != _metadata_identity(named_database)
            ):
                raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_SUBSTITUTED")
            self.database_identity = _stable_identity(database_metadata)
            fcntl.flock(
                self.database_descriptor,
                (fcntl.LOCK_SH if readonly else fcntl.LOCK_EX) | fcntl.LOCK_NB,
            )
            self.boundary()
            uri_path = f"/proc/self/fd/{self.parent_descriptor}/{validated.name}"
            mode = "ro" if readonly else "rw"
            uri = f"file:{quote(uri_path, safe='/')}?mode={mode}&immutable=0"
            connection = sqlite3.connect(
                uri, uri=True, isolation_level=None, timeout=5
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA recursive_triggers=OFF")
            if readonly:
                connection.execute("PRAGMA query_only=ON")
            self.connection = connection
            self.boundary()
        except CurrentMainRegistrationError:
            self.close()
            raise
        except RepositoryGitRegistryError as exc:
            self.close()
            raise CurrentMainRegistrationError(
                "CURRENT_MAIN_DATABASE_SUBSTITUTED"
            ) from exc
        except (OSError, sqlite3.Error, UnsafeSQLitePathError) as exc:
            self.close()
            raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_UNSAFE") from exc

    def boundary(self) -> None:
        if self.guard is None:
            raise CurrentMainRegistrationError(
                "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE"
            )
        self.guard.check()
        try:
            if (
                self.parent_identity
                != _stable_identity(os.fstat(self.parent_descriptor))
                or self.parent_identity
                != _stable_identity(self.database.parent.lstat())
                or self.container_identity
                != _stable_identity(os.fstat(self.container_descriptor))
                or self.container_identity
                != _stable_identity(self.database.parent.parent.lstat())
                or self.database_identity is not None
                and self.database_identity
                != _stable_identity(os.fstat(self.database_descriptor))
                or self.database_identity is not None
                and self.database_identity
                != _stable_identity(
                    os.stat(
                        self.database.name,
                        dir_fd=self.parent_descriptor,
                        follow_symlinks=False,
                    )
                )
            ):
                raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_SUBSTITUTED")
        except CurrentMainRegistrationError:
            raise
        except OSError as exc:
            raise CurrentMainRegistrationError(
                "CURRENT_MAIN_DATABASE_SUBSTITUTED"
            ) from exc
        self.guard.check()

    def close_connection(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def close(self) -> None:
        self.close_connection()
        if self.database_descriptor >= 0:
            try:
                fcntl.flock(self.database_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(self.database_descriptor)
            self.database_descriptor = -1
        if self.guard is not None:
            self.guard.close()
            self.guard = None
        if self.parent_descriptor >= 0:
            os.close(self.parent_descriptor)
            self.parent_descriptor = -1
        if self.container_descriptor >= 0:
            os.close(self.container_descriptor)
            self.container_descriptor = -1


def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?", (name,)
        ).fetchone()
        is not None
    )


def _snapshot(connection: sqlite3.Connection, table: str) -> str:
    if table not in {
        "coordination_bootstrap_provenance",
        "coordination_repository_git_registrations",
    }:
        raise CurrentMainRegistrationError("CURRENT_MAIN_SCHEMA_INVALID")
    if not _table_exists(connection, table):
        raise CurrentMainRegistrationError("CURRENT_MAIN_SCHEMA_INVALID")
    ordering = "bootstrap_id" if table == "coordination_bootstrap_provenance" else "id"
    rows = [
        dict(row)
        for row in connection.execute(f"SELECT * FROM {table} ORDER BY {ordering}")
    ]
    return _digest(rows)


def _bootstrap(
    connection: sqlite3.Connection, request: dict[str, Any]
) -> tuple[sqlite3.Row, str]:
    rows = connection.execute(
        "SELECT * FROM coordination_bootstrap_provenance WHERE bootstrap_id=?",
        (request["bootstrap"]["bootstrap_id"],),
    ).fetchall()
    if len(rows) != 1:
        raise CurrentMainRegistrationError("CURRENT_MAIN_BOOTSTRAP_INVALID")
    row = rows[0]
    try:
        manifest = json.loads(row["manifest_json"], object_pairs_hook=_strict_object)
    except (TypeError, json.JSONDecodeError) as exc:
        raise CurrentMainRegistrationError("CURRENT_MAIN_BOOTSTRAP_INVALID") from exc
    if (
        type(manifest) is not dict
        or row["manifest_sha256"] != request["bootstrap"]["manifest_sha256"]
        or _canonical_json(manifest) != row["manifest_json"]
        or hashlib.sha256(row["manifest_json"].encode("utf-8")).hexdigest()
        != row["manifest_sha256"]
    ):
        raise CurrentMainRegistrationError("CURRENT_MAIN_BOOTSTRAP_INVALID")
    repository = request["repository"]
    if repository == row["source_harness_repository"]:
        prior_main = str(row["source_harness_main_sha"])
    elif repository == row["application_repository"]:
        prior_main = str(row["application_main_sha"])
    else:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REPOSITORY_UNSUPPORTED")
    if GIT_SHA.fullmatch(prior_main) is None:
        raise CurrentMainRegistrationError("CURRENT_MAIN_BOOTSTRAP_INVALID")
    return row, prior_main


def _legacy_compatible(
    connection: sqlite3.Connection,
    request: dict[str, Any],
    git_dir: Path,
    prior_main: str,
    git_proof: dict[str, Any],
) -> None:
    rows = connection.execute(
        "SELECT 1 FROM coordination_repository_git_registrations WHERE repository=?",
        (request["repository"],),
    ).fetchall()
    if len(rows) > 1:
        raise CurrentMainRegistrationError("CURRENT_MAIN_LEGACY_CONFLICT")
    if not rows:
        return
    try:
        legacy = load_repository_git_registration(connection, request["repository"])
    except RepositoryGitRegistryError as exc:
        raise CurrentMainRegistrationError("CURRENT_MAIN_LEGACY_CONFLICT") from exc
    if (
        legacy["git_dir"] != os.fspath(git_dir)
        or legacy["source_main_sha"] != prior_main
        or legacy["provenance"]["bootstrap_id"]
        != request["bootstrap"]["bootstrap_id"]
        or legacy["provenance"]["bootstrap_manifest_sha256"]
        != request["bootstrap"]["manifest_sha256"]
        or legacy["git_dir_identity"] != git_proof["git_dir_identity"]
        or legacy["origin_url"] != git_proof["origin_url"]
    ):
        raise CurrentMainRegistrationError("CURRENT_MAIN_LEGACY_CONFLICT")


def _candidate(
    guarded: GuardedDatabase,
    request: dict[str, Any],
    git_dir: Path,
) -> dict[str, Any]:
    if guarded.connection is None or guarded.database_identity is None:
        raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_UNSAFE")
    connection = guarded.connection
    guarded.boundary()
    bootstrap_snapshot = _snapshot(connection, "coordination_bootstrap_provenance")
    legacy_snapshot = _snapshot(
        connection, "coordination_repository_git_registrations"
    )
    _bootstrap_row, prior_main = _bootstrap(connection, request)
    _test_failpoint("before_git_proof")
    guarded.boundary()
    try:
        proof = prove_repository_git_current_main(
            Path(git_dir),
            request["repository"],
            prior_main_sha=prior_main,
            accepted_main_sha=request["accepted_source"]["main_sha"],
            accepted_tree_sha=request["accepted_source"]["tree_sha"],
        )
    except RepositoryGitRegistryError as exc:
        raise CurrentMainRegistrationError(str(exc)) from exc
    guarded.boundary()
    _legacy_compatible(connection, request, Path(git_dir), prior_main, proof)
    normalized_origin = f"https://github.com/{request['repository']}.git"
    provenance_id = (
        f"current-main:{request['repository']}:{request['accepted_source']['main_sha']}"
    )
    provenance_manifest = {
        "schema": PROVENANCE_SCHEMA,
        "operation_key": request["operation_key"],
        "repository": request["repository"],
        "normalized_origin": normalized_origin,
        "prior_provenance": {
            "kind": "BOOTSTRAP",
            "bootstrap_id": request["bootstrap"]["bootstrap_id"],
            "manifest_sha256": request["bootstrap"]["manifest_sha256"],
            "main_sha": prior_main,
        },
        "accepted_source": request["accepted_source"],
        "recorded_at": request["recorded_at"],
    }
    provenance_sha256 = _digest(provenance_manifest)
    registration_id = f"read-only-git-v2:{request['repository']}"
    registration_manifest = {
        "schema": REGISTRATION_SCHEMA,
        "registration_id": registration_id,
        "repository": request["repository"],
        "git_dir": proof["git_dir"],
        "normalized_origin": normalized_origin,
        "accepted_main_sha": request["accepted_source"]["main_sha"],
        "accepted_tree_sha": request["accepted_source"]["tree_sha"],
        "provenance": {
            "provenance_id": provenance_id,
            "provenance_sha256": provenance_sha256,
        },
        "git_dir_identity": proof["git_dir_identity"],
    }
    registration_sha256 = _digest(registration_manifest)
    database_identity = {
        "device": int(guarded.database_identity[0]),
        "inode": int(guarded.database_identity[1]),
        "mode": int(guarded.database_identity[2]),
        "uid": int(guarded.database_identity[3]),
        "gid": int(guarded.database_identity[4]),
        "link_count": int(guarded.database_identity[5]),
    }
    private_preview = {
        "schema": PRIVATE_PREVIEW_SCHEMA,
        "operation_key": request["operation_key"],
        "request_sha256": _digest(request),
        "repository": request["repository"],
        "accepted_main_sha": request["accepted_source"]["main_sha"],
        "accepted_tree_sha": request["accepted_source"]["tree_sha"],
        "bootstrap_snapshot_sha256": bootstrap_snapshot,
        "legacy_snapshot_sha256": legacy_snapshot,
        "database_identity": database_identity,
        "git_dir_identity": proof["git_dir_identity"],
        "provenance_sha256": provenance_sha256,
        "registration_sha256": registration_sha256,
    }
    transaction_sha256 = _digest(private_preview)
    confirmation_sha256 = _digest(
        {
            "schema": CONFIRMATION_SCHEMA,
            "transaction_sha256": transaction_sha256,
        }
    )
    public_preview = {
        "schema": PUBLIC_PREVIEW_SCHEMA,
        "operation_key": request["operation_key"],
        "repository": request["repository"],
        "accepted_main_sha": request["accepted_source"]["main_sha"],
        "accepted_tree_sha": request["accepted_source"]["tree_sha"],
        "provenance_sha256": provenance_sha256,
        "registration_sha256": registration_sha256,
        "transaction_sha256": transaction_sha256,
        "confirmation_sha256": confirmation_sha256,
    }
    return {
        "prior_main": prior_main,
        "proof": proof,
        "provenance_id": provenance_id,
        "provenance_manifest": provenance_manifest,
        "provenance_sha256": provenance_sha256,
        "registration_id": registration_id,
        "registration_manifest": registration_manifest,
        "registration_sha256": registration_sha256,
        "bootstrap_snapshot_sha256": bootstrap_snapshot,
        "legacy_snapshot_sha256": legacy_snapshot,
        "transaction_sha256": transaction_sha256,
        "confirmation_sha256": confirmation_sha256,
        "public_preview": public_preview,
    }


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS coordination_current_main_provenance (
        provenance_id TEXT PRIMARY KEY,
        repository TEXT NOT NULL,
        prior_bootstrap_id TEXT NOT NULL,
        prior_manifest_sha256 TEXT NOT NULL,
        prior_main_sha TEXT NOT NULL,
        accepted_merge_sha TEXT NOT NULL,
        accepted_main_sha TEXT NOT NULL,
        accepted_tree_sha TEXT NOT NULL,
        normalized_origin TEXT NOT NULL,
        source_receipt_sha256 TEXT NOT NULL,
        review_receipt_id TEXT NOT NULL,
        review_receipt_sha256 TEXT NOT NULL,
        ci_run_id INTEGER NOT NULL,
        ci_job_id INTEGER NOT NULL,
        ci_receipt_sha256 TEXT NOT NULL,
        stopped_state_receipt_sha256 TEXT NOT NULL,
        approval_execution_scope_sha256 TEXT NOT NULL,
        transaction_sha256 TEXT NOT NULL UNIQUE,
        provenance_sha256 TEXT NOT NULL UNIQUE,
        provenance_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(prior_bootstrap_id)
            REFERENCES coordination_bootstrap_provenance(bootstrap_id),
        UNIQUE(repository, accepted_main_sha)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS coordination_repository_git_registrations_v2 (
        registration_id TEXT PRIMARY KEY,
        repository TEXT NOT NULL UNIQUE,
        git_dir TEXT NOT NULL UNIQUE,
        accepted_main_sha TEXT NOT NULL,
        accepted_tree_sha TEXT NOT NULL,
        provenance_id TEXT NOT NULL UNIQUE,
        device_id INTEGER NOT NULL,
        inode INTEGER NOT NULL,
        owner_uid INTEGER NOT NULL,
        owner_gid INTEGER NOT NULL,
        mode INTEGER NOT NULL,
        link_count INTEGER NOT NULL,
        normalized_origin TEXT NOT NULL,
        transaction_sha256 TEXT NOT NULL UNIQUE,
        registration_sha256 TEXT NOT NULL UNIQUE,
        registration_json TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL UNIQUE,
        receipt_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(provenance_id)
            REFERENCES coordination_current_main_provenance(provenance_id),
        UNIQUE(device_id, inode)
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_bootstrap_provenance_immutable_insert_collision
    BEFORE INSERT ON coordination_bootstrap_provenance
    WHEN EXISTS(
        SELECT 1 FROM coordination_bootstrap_provenance
        WHERE bootstrap_id=NEW.bootstrap_id
           OR manifest_sha256=NEW.manifest_sha256
    )
    BEGIN
        SELECT RAISE(ABORT, 'BOOTSTRAP_PROVENANCE_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_repository_git_registration_immutable_insert_collision
    BEFORE INSERT ON coordination_repository_git_registrations
    WHEN EXISTS(
        SELECT 1 FROM coordination_repository_git_registrations
        WHERE id=NEW.id
           OR registration_sha256=NEW.registration_sha256
           OR (device_id=NEW.device_id AND inode=NEW.inode)
           OR repository=NEW.repository
           OR git_dir=NEW.git_dir
    )
    BEGIN
        SELECT RAISE(ABORT, 'REPOSITORY_GIT_REGISTRATION_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_current_main_provenance_insert_collision
    BEFORE INSERT ON coordination_current_main_provenance
    WHEN EXISTS(
        SELECT 1 FROM coordination_current_main_provenance
        WHERE provenance_id=NEW.provenance_id
           OR provenance_sha256=NEW.provenance_sha256
           OR transaction_sha256=NEW.transaction_sha256
           OR (repository=NEW.repository AND accepted_main_sha=NEW.accepted_main_sha)
    )
    BEGIN
        SELECT RAISE(ABORT, 'CURRENT_MAIN_PROVENANCE_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_current_main_provenance_immutable_update
    BEFORE UPDATE ON coordination_current_main_provenance
    BEGIN
        SELECT RAISE(ABORT, 'CURRENT_MAIN_PROVENANCE_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_current_main_provenance_immutable_delete
    BEFORE DELETE ON coordination_current_main_provenance
    BEGIN
        SELECT RAISE(ABORT, 'CURRENT_MAIN_PROVENANCE_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_repository_git_registration_v2_insert_collision
    BEFORE INSERT ON coordination_repository_git_registrations_v2
    WHEN EXISTS(
        SELECT 1 FROM coordination_repository_git_registrations_v2
        WHERE registration_id=NEW.registration_id
           OR repository=NEW.repository
           OR git_dir=NEW.git_dir
           OR provenance_id=NEW.provenance_id
           OR (device_id=NEW.device_id AND inode=NEW.inode)
           OR transaction_sha256=NEW.transaction_sha256
           OR registration_sha256=NEW.registration_sha256
           OR receipt_sha256=NEW.receipt_sha256
    )
    BEGIN
        SELECT RAISE(ABORT, 'REPOSITORY_GIT_REGISTRATION_V2_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_repository_git_registration_v2_immutable_update
    BEFORE UPDATE ON coordination_repository_git_registrations_v2
    BEGIN
        SELECT RAISE(ABORT, 'REPOSITORY_GIT_REGISTRATION_V2_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS coordination_repository_git_registration_v2_immutable_delete
    BEFORE DELETE ON coordination_repository_git_registrations_v2
    BEGIN
        SELECT RAISE(ABORT, 'REPOSITORY_GIT_REGISTRATION_V2_IMMUTABLE');
    END
    """,
)


def ensure_current_main_registration_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise CurrentMainRegistrationError("CURRENT_MAIN_TRANSACTION_REQUIRED")
    for statement in _SCHEMA_STATEMENTS:
        connection.execute(statement)
    _require_current_schema(connection)


def _unique_column_sets(connection: sqlite3.Connection, table: str) -> set[tuple[str, ...]]:
    result: set[tuple[str, ...]] = set()
    for index in connection.execute(f"PRAGMA index_list({table})"):
        if int(index[2]) != 1:
            continue
        columns = tuple(
            str(row[2])
            for row in connection.execute(f"PRAGMA index_info({index[1]})")
        )
        result.add(columns)
    return result


def _require_current_schema(connection: sqlite3.Connection) -> None:
    expected_columns = {
        "coordination_current_main_provenance": (
            "provenance_id",
            "repository",
            "prior_bootstrap_id",
            "prior_manifest_sha256",
            "prior_main_sha",
            "accepted_merge_sha",
            "accepted_main_sha",
            "accepted_tree_sha",
            "normalized_origin",
            "source_receipt_sha256",
            "review_receipt_id",
            "review_receipt_sha256",
            "ci_run_id",
            "ci_job_id",
            "ci_receipt_sha256",
            "stopped_state_receipt_sha256",
            "approval_execution_scope_sha256",
            "transaction_sha256",
            "provenance_sha256",
            "provenance_json",
            "created_at",
        ),
        "coordination_repository_git_registrations_v2": (
            "registration_id",
            "repository",
            "git_dir",
            "accepted_main_sha",
            "accepted_tree_sha",
            "provenance_id",
            "device_id",
            "inode",
            "owner_uid",
            "owner_gid",
            "mode",
            "link_count",
            "normalized_origin",
            "transaction_sha256",
            "registration_sha256",
            "registration_json",
            "receipt_sha256",
            "receipt_json",
            "created_at",
        ),
    }
    expected_unique = {
        "coordination_current_main_provenance": {
            ("provenance_id",),
            ("transaction_sha256",),
            ("provenance_sha256",),
            ("repository", "accepted_main_sha"),
        },
        "coordination_repository_git_registrations_v2": {
            ("registration_id",),
            ("repository",),
            ("git_dir",),
            ("provenance_id",),
            ("device_id", "inode"),
            ("transaction_sha256",),
            ("registration_sha256",),
            ("receipt_sha256",),
        },
    }
    expected_triggers = {
        "coordination_current_main_provenance": {
            "coordination_current_main_provenance_insert_collision",
            "coordination_current_main_provenance_immutable_update",
            "coordination_current_main_provenance_immutable_delete",
        },
        "coordination_repository_git_registrations_v2": {
            "coordination_repository_git_registration_v2_insert_collision",
            "coordination_repository_git_registration_v2_immutable_update",
            "coordination_repository_git_registration_v2_immutable_delete",
        },
    }
    expected_foreign = {
        "coordination_current_main_provenance": {
            (
                "coordination_bootstrap_provenance",
                "prior_bootstrap_id",
                "bootstrap_id",
            )
        },
        "coordination_repository_git_registrations_v2": {
            (
                "coordination_current_main_provenance",
                "provenance_id",
                "provenance_id",
            )
        },
    }
    for table, columns in expected_columns.items():
        actual_columns = tuple(
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
        )
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name=?",
                (table,),
            )
        }
        foreign = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute(f"PRAGMA foreign_key_list({table})")
        }
        if (
            actual_columns != columns
            or _unique_column_sets(connection, table) != expected_unique[table]
            or triggers != expected_triggers[table]
            or foreign != expected_foreign[table]
        ):
            raise CurrentMainRegistrationError("CURRENT_MAIN_SCHEMA_INVALID")


def _receipt(candidate: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": RECEIPT_SCHEMA,
        "result": "COMMITTED",
        "operation_key": request["operation_key"],
        "repository": request["repository"],
        "accepted_main_sha": request["accepted_source"]["main_sha"],
        "accepted_tree_sha": request["accepted_source"]["tree_sha"],
        "provenance_sha256": candidate["provenance_sha256"],
        "registration_sha256": candidate["registration_sha256"],
        "transaction_sha256": candidate["transaction_sha256"],
        "committed_at": request["recorded_at"],
    }
    return {**body, "receipt_sha256": _digest(body)}


def _insert_pair(
    connection: sqlite3.Connection,
    request: dict[str, Any],
    candidate: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    accepted = request["accepted_source"]
    proof = candidate["proof"]
    identity = proof["git_dir_identity"]
    connection.execute(
        """
        INSERT INTO coordination_current_main_provenance(
            provenance_id, repository, prior_bootstrap_id,
            prior_manifest_sha256, prior_main_sha, accepted_merge_sha,
            accepted_main_sha, accepted_tree_sha, normalized_origin,
            source_receipt_sha256, review_receipt_id,
            review_receipt_sha256, ci_run_id, ci_job_id, ci_receipt_sha256,
            stopped_state_receipt_sha256, approval_execution_scope_sha256,
            transaction_sha256, provenance_sha256, provenance_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            candidate["provenance_id"],
            request["repository"],
            request["bootstrap"]["bootstrap_id"],
            request["bootstrap"]["manifest_sha256"],
            candidate["prior_main"],
            accepted["merge_sha"],
            accepted["main_sha"],
            accepted["tree_sha"],
            candidate["provenance_manifest"]["normalized_origin"],
            accepted["source_receipt_sha256"],
            accepted["independent_review"]["receipt_id"],
            accepted["independent_review"]["receipt_sha256"],
            accepted["ci"]["run_id"],
            accepted["ci"]["job_id"],
            accepted["ci"]["receipt_sha256"],
            accepted["stopped_state_receipt_sha256"],
            accepted["approval_execution_scope_sha256"],
            candidate["transaction_sha256"],
            candidate["provenance_sha256"],
            _canonical_json(candidate["provenance_manifest"]),
            request["recorded_at"],
        ),
    )
    connection.execute(
        """
        INSERT INTO coordination_repository_git_registrations_v2(
            registration_id, repository, git_dir, accepted_main_sha,
            accepted_tree_sha, provenance_id, device_id, inode, owner_uid,
            owner_gid, mode, link_count, normalized_origin, transaction_sha256,
            registration_sha256, registration_json, receipt_sha256,
            receipt_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            candidate["registration_id"],
            request["repository"],
            proof["git_dir"],
            accepted["main_sha"],
            accepted["tree_sha"],
            candidate["provenance_id"],
            identity["device"],
            identity["inode"],
            identity["uid"],
            identity["gid"],
            identity["mode"],
            identity["link_count"],
            candidate["provenance_manifest"]["normalized_origin"],
            candidate["transaction_sha256"],
            candidate["registration_sha256"],
            _canonical_json(candidate["registration_manifest"]),
            receipt["receipt_sha256"],
            _canonical_json(receipt),
            request["recorded_at"],
        ),
    )


def _load_stored_receipt(
    connection: sqlite3.Connection,
    request: dict[str, Any],
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    provenance_exists = _table_exists(
        connection, "coordination_current_main_provenance"
    )
    registration_exists = _table_exists(
        connection, "coordination_repository_git_registrations_v2"
    )
    if provenance_exists != registration_exists:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_PARTIAL")
    if not provenance_exists:
        return None
    _require_current_schema(connection)
    provenance_rows = connection.execute(
        "SELECT * FROM coordination_current_main_provenance WHERE repository=?",
        (request["repository"],),
    ).fetchall()
    registration_rows = connection.execute(
        "SELECT * FROM coordination_repository_git_registrations_v2 WHERE repository=?",
        (request["repository"],),
    ).fetchall()
    if not provenance_rows and not registration_rows:
        return None
    if len(provenance_rows) != 1 or len(registration_rows) != 1:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_PARTIAL")
    provenance = provenance_rows[0]
    registration = registration_rows[0]
    try:
        provenance_manifest = json.loads(
            provenance["provenance_json"], object_pairs_hook=_strict_object
        )
        registration_manifest = json.loads(
            registration["registration_json"], object_pairs_hook=_strict_object
        )
        receipt = json.loads(
            registration["receipt_json"], object_pairs_hook=_strict_object
        )
    except (TypeError, json.JSONDecodeError) as exc:
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_INVALID") from exc
    if (
        type(provenance_manifest) is not dict
        or type(registration_manifest) is not dict
        or type(receipt) is not dict
        or _canonical_json(provenance_manifest) != provenance["provenance_json"]
        or _digest(provenance_manifest) != provenance["provenance_sha256"]
        or _canonical_json(registration_manifest) != registration["registration_json"]
        or _digest(registration_manifest) != registration["registration_sha256"]
        or _canonical_json(receipt) != registration["receipt_json"]
        or set(receipt)
        != {
            "schema",
            "result",
            "operation_key",
            "repository",
            "accepted_main_sha",
            "accepted_tree_sha",
            "provenance_sha256",
            "registration_sha256",
            "transaction_sha256",
            "committed_at",
            "receipt_sha256",
        }
    ):
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_INVALID")
    receipt_body = dict(receipt)
    receipt_sha256 = receipt_body.pop("receipt_sha256", None)
    accepted = request["accepted_source"]
    normalized_origin = f"https://github.com/{request['repository']}.git"
    expected_provenance_keys = {
        "schema",
        "operation_key",
        "repository",
        "normalized_origin",
        "prior_provenance",
        "accepted_source",
        "recorded_at",
    }
    expected_registration_keys = {
        "schema",
        "registration_id",
        "repository",
        "git_dir",
        "normalized_origin",
        "accepted_main_sha",
        "accepted_tree_sha",
        "provenance",
        "git_dir_identity",
    }
    prior = provenance_manifest.get("prior_provenance")
    manifest_provenance = registration_manifest.get("provenance")
    identity = registration_manifest.get("git_dir_identity")
    if (
        receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("result") != "COMMITTED"
        or receipt_sha256 != _digest(receipt_body)
        or receipt_sha256 != registration["receipt_sha256"]
        or provenance["provenance_id"] != registration["provenance_id"]
        or provenance["transaction_sha256"] != registration["transaction_sha256"]
        or provenance["provenance_sha256"] != receipt["provenance_sha256"]
        or registration["registration_sha256"]
        != receipt["registration_sha256"]
        or registration["transaction_sha256"] != receipt["transaction_sha256"]
        or set(provenance_manifest) != expected_provenance_keys
        or provenance_manifest.get("schema") != PROVENANCE_SCHEMA
        or provenance_manifest.get("operation_key") != request["operation_key"]
        or provenance_manifest.get("repository") != request["repository"]
        or provenance_manifest.get("normalized_origin") != normalized_origin
        or provenance_manifest.get("accepted_source") != accepted
        or provenance_manifest.get("recorded_at") != request["recorded_at"]
        or type(prior) is not dict
        or set(prior) != {"kind", "bootstrap_id", "manifest_sha256", "main_sha"}
        or prior.get("kind") != "BOOTSTRAP"
        or prior.get("bootstrap_id") != request["bootstrap"]["bootstrap_id"]
        or prior.get("manifest_sha256")
        != request["bootstrap"]["manifest_sha256"]
        or GIT_SHA.fullmatch(str(prior.get("main_sha"))) is None
        or set(registration_manifest) != expected_registration_keys
        or registration_manifest.get("schema") != REGISTRATION_SCHEMA
        or registration_manifest.get("repository") != request["repository"]
        or registration_manifest.get("normalized_origin") != normalized_origin
        or registration_manifest.get("accepted_main_sha") != accepted["main_sha"]
        or registration_manifest.get("accepted_tree_sha") != accepted["tree_sha"]
        or type(registration_manifest.get("git_dir")) is not str
        or not Path(registration_manifest["git_dir"]).is_absolute()
        or type(manifest_provenance) is not dict
        or set(manifest_provenance) != {"provenance_id", "provenance_sha256"}
        or type(identity) is not dict
        or set(identity) != {"device", "inode", "mode", "uid", "gid", "link_count"}
        or any(type(value) is not int or value < 0 for value in identity.values())
        or provenance["repository"] != request["repository"]
        or provenance["prior_bootstrap_id"]
        != request["bootstrap"]["bootstrap_id"]
        or provenance["prior_manifest_sha256"]
        != request["bootstrap"]["manifest_sha256"]
        or provenance["prior_main_sha"] != prior["main_sha"]
        or provenance["accepted_merge_sha"] != accepted["merge_sha"]
        or provenance["accepted_main_sha"] != accepted["main_sha"]
        or provenance["accepted_tree_sha"] != accepted["tree_sha"]
        or provenance["normalized_origin"] != normalized_origin
        or provenance["source_receipt_sha256"]
        != accepted["source_receipt_sha256"]
        or provenance["review_receipt_id"]
        != accepted["independent_review"]["receipt_id"]
        or provenance["review_receipt_sha256"]
        != accepted["independent_review"]["receipt_sha256"]
        or provenance["ci_run_id"] != accepted["ci"]["run_id"]
        or provenance["ci_job_id"] != accepted["ci"]["job_id"]
        or provenance["ci_receipt_sha256"] != accepted["ci"]["receipt_sha256"]
        or provenance["stopped_state_receipt_sha256"]
        != accepted["stopped_state_receipt_sha256"]
        or provenance["approval_execution_scope_sha256"]
        != accepted["approval_execution_scope_sha256"]
        or provenance["created_at"] != request["recorded_at"]
        or registration["registration_id"]
        != registration_manifest["registration_id"]
        or registration["repository"] != request["repository"]
        or registration["git_dir"] != registration_manifest["git_dir"]
        or registration["accepted_main_sha"] != accepted["main_sha"]
        or registration["accepted_tree_sha"] != accepted["tree_sha"]
        or registration["provenance_id"] != manifest_provenance["provenance_id"]
        or manifest_provenance["provenance_id"] != provenance["provenance_id"]
        or manifest_provenance["provenance_sha256"]
        != provenance["provenance_sha256"]
        or registration["device_id"] != identity["device"]
        or registration["inode"] != identity["inode"]
        or registration["owner_uid"] != identity["uid"]
        or registration["owner_gid"] != identity["gid"]
        or registration["mode"] != identity["mode"]
        or registration["link_count"] != identity["link_count"]
        or registration["normalized_origin"] != normalized_origin
        or registration["created_at"] != request["recorded_at"]
        or receipt.get("operation_key") != request["operation_key"]
        or receipt.get("repository") != request["repository"]
        or receipt.get("accepted_main_sha") != accepted["main_sha"]
        or receipt.get("accepted_tree_sha") != accepted["tree_sha"]
        or receipt.get("committed_at") != request["recorded_at"]
    ):
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_INVALID")
    if candidate is not None and (
        provenance["provenance_id"] != candidate["provenance_id"]
        or provenance["provenance_sha256"] != candidate["provenance_sha256"]
        or registration["registration_id"] != candidate["registration_id"]
        or registration["registration_sha256"] != candidate["registration_sha256"]
        or registration["transaction_sha256"] != candidate["transaction_sha256"]
        or receipt != _receipt(candidate, request)
    ):
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_CONFLICT")
    return receipt


def _finish_guarded(
    guarded: GuardedDatabase, result: dict[str, Any], *, failpoint: bool = True
) -> dict[str, Any]:
    guarded.close_connection()
    guarded.boundary()
    if failpoint:
        _test_failpoint("before_public_output")
    guarded.boundary()
    return result


def preview_registration(
    database: Path, git_dir: Path, request: dict[str, Any]
) -> dict[str, Any]:
    request = validate_request(request)
    guarded = GuardedDatabase(Path(database), readonly=True)
    try:
        if guarded.connection is None:
            raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_UNSAFE")
        guarded.connection.execute("BEGIN")
        candidate = _candidate(guarded, request, Path(git_dir))
        guarded.connection.execute("ROLLBACK")
        return _finish_guarded(guarded, candidate["public_preview"])
    except CurrentMainRegistrationError:
        if guarded.connection is not None and guarded.connection.in_transaction:
            guarded.connection.execute("ROLLBACK")
        raise
    except (OSError, sqlite3.Error) as exc:
        if guarded.connection is not None and guarded.connection.in_transaction:
            guarded.connection.execute("ROLLBACK")
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_HOLD") from exc
    finally:
        guarded.close()


def apply_registration(
    database: Path,
    git_dir: Path,
    request: dict[str, Any],
    *,
    expected_confirmation_sha256: str,
) -> dict[str, Any]:
    request = validate_request(request)
    if SHA256.fullmatch(expected_confirmation_sha256) is None:
        raise CurrentMainRegistrationError("CURRENT_MAIN_CONFIRMATION_INVALID")
    guarded = GuardedDatabase(Path(database), readonly=False)
    committed = False
    try:
        if guarded.connection is None:
            raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_UNSAFE")
        connection = guarded.connection
        connection.execute("BEGIN IMMEDIATE")
        candidate = _candidate(guarded, request, Path(git_dir))
        if candidate["confirmation_sha256"] != expected_confirmation_sha256:
            raise CurrentMainRegistrationError("CURRENT_MAIN_CONFIRMATION_DRIFT")
        stored = _load_stored_receipt(connection, request, candidate)
        if stored is not None:
            connection.execute("ROLLBACK")
            return _finish_guarded(guarded, stored)
        ensure_current_main_registration_schema(connection)
        _test_failpoint("before_insert")
        guarded.boundary()
        refreshed = _candidate(guarded, request, Path(git_dir))
        if refreshed["transaction_sha256"] != candidate["transaction_sha256"]:
            raise CurrentMainRegistrationError("CURRENT_MAIN_PREVIEW_DRIFT")
        receipt = _receipt(candidate, request)
        _insert_pair(connection, request, candidate, receipt)
        _test_failpoint("before_commit")
        guarded.boundary()
        if (
            _snapshot(connection, "coordination_bootstrap_provenance")
            != candidate["bootstrap_snapshot_sha256"]
            or _snapshot(connection, "coordination_repository_git_registrations")
            != candidate["legacy_snapshot_sha256"]
        ):
            raise CurrentMainRegistrationError("CURRENT_MAIN_LEGACY_CONFLICT")
        guarded.boundary()
        connection.execute("COMMIT")
        committed = True
        _test_failpoint("after_commit")
        guarded.boundary()
        stored = _load_stored_receipt(connection, request, candidate)
        if stored != receipt:
            raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_INVALID")
        return _finish_guarded(guarded, stored)
    except CurrentMainRegistrationError:
        if (
            not committed
            and guarded.connection is not None
            and guarded.connection.in_transaction
        ):
            guarded.connection.execute("ROLLBACK")
        raise
    except (OSError, sqlite3.Error) as exc:
        if (
            not committed
            and guarded.connection is not None
            and guarded.connection.in_transaction
        ):
            guarded.connection.execute("ROLLBACK")
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_HOLD") from exc
    finally:
        guarded.close()


def readback_registration(
    database: Path, git_dir: Path, request: dict[str, Any]
) -> dict[str, Any]:
    request = validate_request(request)
    guarded = GuardedDatabase(Path(database), readonly=True)
    try:
        if guarded.connection is None:
            raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_UNSAFE")
        connection = guarded.connection
        connection.execute("BEGIN")
        candidate = _candidate(guarded, request, Path(git_dir))
        stored = _load_stored_receipt(connection, request, candidate)
        if stored is None:
            raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_MISSING")
        connection.execute("ROLLBACK")
        return _finish_guarded(guarded, stored)
    except CurrentMainRegistrationError:
        if guarded.connection is not None and guarded.connection.in_transaction:
            guarded.connection.execute("ROLLBACK")
        raise
    except (OSError, sqlite3.Error) as exc:
        if guarded.connection is not None and guarded.connection.in_transaction:
            guarded.connection.execute("ROLLBACK")
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_HOLD") from exc
    finally:
        guarded.close()


def recover_registration(
    database: Path, git_dir: Path, request: dict[str, Any]
) -> dict[str, Any]:
    """Resolve durable outcome stored-first, then revalidate every live fence."""

    request = validate_request(request)
    guarded = GuardedDatabase(Path(database), readonly=True)
    try:
        if guarded.connection is None:
            raise CurrentMainRegistrationError("CURRENT_MAIN_DATABASE_UNSAFE")
        connection = guarded.connection
        connection.execute("BEGIN")
        stored_first = _load_stored_receipt(connection, request)
        if stored_first is None:
            raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_MISSING")
        guarded.boundary()
        candidate = _candidate(guarded, request, Path(git_dir))
        stored = _load_stored_receipt(connection, request, candidate)
        if stored != stored_first:
            raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_INVALID")
        connection.execute("ROLLBACK")
        return _finish_guarded(guarded, stored)
    except CurrentMainRegistrationError:
        if guarded.connection is not None and guarded.connection.in_transaction:
            guarded.connection.execute("ROLLBACK")
        raise
    except (OSError, sqlite3.Error) as exc:
        if guarded.connection is not None and guarded.connection.in_transaction:
            guarded.connection.execute("ROLLBACK")
        raise CurrentMainRegistrationError("CURRENT_MAIN_REGISTRATION_HOLD") from exc
    finally:
        guarded.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preview, apply, read back, or recover current-main registration."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("preview", "readback", "recover"):
        command = subparsers.add_parser(name)
        command.add_argument("--database", type=Path, required=True)
        command.add_argument("--git-dir", type=Path, required=True)
        command.add_argument("--request", type=Path, required=True)
    apply = subparsers.add_parser("apply")
    apply.add_argument("--database", type=Path, required=True)
    apply.add_argument("--git-dir", type=Path, required=True)
    apply.add_argument("--request", type=Path, required=True)
    apply.add_argument("--expected-confirmation-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        request = load_request(args.request)
        operations: dict[str, Callable[..., dict[str, Any]]] = {
            "preview": preview_registration,
            "readback": readback_registration,
            "recover": recover_registration,
        }
        if args.command == "apply":
            result = apply_registration(
                args.database,
                args.git_dir,
                request,
                expected_confirmation_sha256=args.expected_confirmation_sha256,
            )
        else:
            result = operations[args.command](args.database, args.git_dir, request)
    except CurrentMainRegistrationError as exc:
        print(_canonical_json({"status": "HOLD", "code": str(exc)}))
        return 2
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
