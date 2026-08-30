#!/usr/bin/env python3
"""Immutable owner-safe repository Git-directory registrations."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from typing import Any


REGISTRATION_SCHEMA = "twinfinity-repository-git-registration/v1"
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CANONICAL_ORIGIN_FETCH = "+refs/heads/*:refs/remotes/origin/*"
FIXED_GIT = "/usr/bin/git"
_GIT_ENVIRONMENT_SUBSTITUTION = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    }
)
GITHUB_ORIGINS = (
    re.compile(
        r"^https://github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
    ),
    re.compile(
        r"^git@github\.com:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
    ),
    re.compile(
        r"^ssh://git@github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
    ),
)


class RepositoryGitRegistryError(ValueError):
    """Typed fail-closed repository Git registry error."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_INVALID")
        value[key] = item
    return value


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_directory_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "mode": int(metadata.st_mode),
        "uid": int(metadata.st_uid),
        "gid": int(metadata.st_gid),
        "link_count": int(metadata.st_nlink),
    }


def _owner_directory_valid(metadata: os.stat_result) -> bool:
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _open_absolute_directory(path: Path) -> int:
    raw = os.fspath(path)
    if (
        not path.is_absolute()
        or not raw
        or "\x00" in raw
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if _metadata_identity(opened) != _metadata_identity(named):
                    raise RepositoryGitRegistryError(
                        "REPOSITORY_GIT_DIRECTORY_SUBSTITUTED"
                    )
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_git_file(
    git_descriptor: int, relative_path: str, *, maximum_bytes: int
) -> bytes | None:
    parts = Path(relative_path).parts
    if (
        not parts
        or Path(relative_path).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_FILE_INVALID")
    directory_descriptor = os.dup(git_descriptor)
    opened_directories = [directory_descriptor]
    descriptor = -1
    try:
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        for component in parts[:-1]:
            try:
                child = os.open(component, directory_flags, dir_fd=directory_descriptor)
            except FileNotFoundError:
                return None
            opened = os.fstat(child)
            named = os.stat(
                component, dir_fd=directory_descriptor, follow_symlinks=False
            )
            if (
                not _owner_directory_valid(opened)
                or _metadata_identity(opened) != _metadata_identity(named)
            ):
                os.close(child)
                raise RepositoryGitRegistryError("REPOSITORY_GIT_FILE_INVALID")
            directory_descriptor = child
            opened_directories.append(child)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(parts[-1], flags, dir_fd=directory_descriptor)
        except FileNotFoundError:
            return None
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_FILE_INVALID")
        chunks: list[bytes] = []
        remaining = int(before.st_size) + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        named = os.stat(parts[-1], dir_fd=directory_descriptor, follow_symlinks=False)
        raw = b"".join(chunks)
        if (
            len(raw) != int(before.st_size)
            or _metadata_identity(after) != _metadata_identity(before)
            or _metadata_identity(named) != _metadata_identity(before)
        ):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_FILE_CHANGED")
        return raw
    except OSError as exc:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_FILE_INVALID") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for opened in reversed(opened_directories):
            os.close(opened)


def _git_entry_exists(git_descriptor: int, relative_path: str) -> bool:
    """Observe one fixed Git-relative entry without following symlinks."""

    parts = Path(relative_path).parts
    if (
        not parts
        or Path(relative_path).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_DERIVED_STATE_PRESENT")
    descriptor = os.dup(git_descriptor)
    try:
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        for component in parts[:-1]:
            try:
                child = os.open(component, directory_flags, dir_fd=descriptor)
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise RepositoryGitRegistryError(
                    "REPOSITORY_GIT_DERIVED_STATE_PRESENT"
                ) from exc
            os.close(descriptor)
            descriptor = child
        try:
            os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise RepositoryGitRegistryError(
                "REPOSITORY_GIT_DERIVED_STATE_PRESENT"
            ) from exc
        return True
    finally:
        os.close(descriptor)


def _reject_derived_git_state(git_descriptor: int) -> None:
    """Reject every supported source of derived or replacement Git history."""

    for relative_path in (
        "commondir",
        "info/grafts",
        "shallow",
        "objects/info/alternates",
        "refs/replace",
    ):
        if _git_entry_exists(git_descriptor, relative_path):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DERIVED_STATE_PRESENT")
    packed = _read_git_file(
        git_descriptor, "packed-refs", maximum_bytes=8 * 1024 * 1024
    )
    if packed is not None:
        try:
            lines = packed.decode("ascii").splitlines()
        except UnicodeError as exc:
            raise RepositoryGitRegistryError(
                "REPOSITORY_GIT_DERIVED_STATE_PRESENT"
            ) from exc
        if any(
            line
            and not line.startswith(("#", "^"))
            and line.partition(" ")[2].startswith("refs/replace/")
            for line in lines
        ):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DERIVED_STATE_PRESENT")


def _closed_git_environment() -> dict[str, str]:
    if any(name in os.environ for name in _GIT_ENVIRONMENT_SUBSTITUTION):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_ENVIRONMENT_SUBSTITUTED")
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _fixed_git(git_descriptor: int, arguments: tuple[str, ...]) -> bytes:
    """Run one internally selected, read-only Git proof command."""

    try:
        result = subprocess.run(
            [
                FIXED_GIT,
                "--no-replace-objects",
                f"--git-dir=/proc/self/fd/{git_descriptor}",
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_closed_git_environment(),
            pass_fds=(git_descriptor,),
            close_fds=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROOF_FAILED") from exc
    if result.returncode != 0 or len(result.stdout) > 4096 or len(result.stderr) > 4096:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROOF_FAILED")
    return result.stdout


def _repository_from_origin(origin_url: str) -> str | None:
    for pattern in GITHUB_ORIGINS:
        match = pattern.fullmatch(origin_url)
        if match is not None:
            return match.group("repository")
    return None


def _origin_url(git_descriptor: int) -> str:
    raw = _read_git_file(git_descriptor, "config", maximum_bytes=1024 * 1024)
    if raw is None:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_ORIGIN_MISSING")
    try:
        text = raw.decode("utf-8")
        parser = configparser.RawConfigParser(interpolation=None, strict=True)
        parser.read_string(text)
        sections = [
            section
            for section in parser.sections()
            if section.lower() == 'remote "origin"'
        ]
        if len(sections) != 1:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_ORIGIN_INVALID")
        origin = parser.get(sections[0], "url").strip()
        fetch = parser.get(sections[0], "fetch").strip()
    except (UnicodeError, configparser.Error, KeyError) as exc:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_ORIGIN_INVALID") from exc
    if (
        not origin
        or "\n" in origin
        or "\r" in origin
        or fetch != CANONICAL_ORIGIN_FETCH
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_ORIGIN_INVALID")
    return origin


def _remote_main(git_descriptor: int) -> str:
    ref_name = "refs/remotes/origin/main"
    loose = _read_git_file(git_descriptor, ref_name, maximum_bytes=256)
    sha: str | None = None
    if loose is not None:
        try:
            sha = loose.decode("ascii").strip()
        except UnicodeError as exc:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_MAIN_INVALID") from exc
    else:
        packed = _read_git_file(
            git_descriptor, "packed-refs", maximum_bytes=8 * 1024 * 1024
        )
        if packed is None:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_MAIN_MISSING")
        try:
            lines = packed.decode("ascii").splitlines()
        except UnicodeError as exc:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_MAIN_INVALID") from exc
        for line in lines:
            if line and not line.startswith(("#", "^")):
                value, separator, name = line.partition(" ")
                if separator and name == ref_name:
                    sha = value
                    break
        if _read_git_file(git_descriptor, ref_name, maximum_bytes=256) is not None:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_MAIN_CHANGED")
    if sha is None:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_MAIN_MISSING")
    if GIT_SHA.fullmatch(sha) is None:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_MAIN_INVALID")
    return sha


def _observe_git_directory(
    git_dir: Path,
    repository: str,
    *,
    expected_identity: dict[str, int] | None = None,
) -> tuple[dict[str, int], str, str]:
    descriptor = -1
    try:
        descriptor = _open_absolute_directory(git_dir)
        initial = os.fstat(descriptor)
        if not _owner_directory_valid(initial):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_UNSAFE")
        identity = _stable_directory_identity(initial)
        if expected_identity is not None and identity != expected_identity:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_SUBSTITUTED")
        _reject_derived_git_state(descriptor)
        origin_url = _origin_url(descriptor)
        if _repository_from_origin(origin_url) != repository:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_ORIGIN_MISMATCH")
        main_sha = _remote_main(descriptor)
        final = os.fstat(descriptor)
        try:
            named = git_dir.lstat()
        except OSError as exc:
            raise RepositoryGitRegistryError(
                "REPOSITORY_GIT_DIRECTORY_SUBSTITUTED"
            ) from exc
        if (
            _metadata_identity(initial) != _metadata_identity(final)
            or _metadata_identity(final) != _metadata_identity(named)
        ):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_SUBSTITUTED")
        return identity, origin_url, main_sha
    except RepositoryGitRegistryError:
        raise
    except OSError as exc:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_INVALID") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def prove_repository_git_current_main(
    git_dir: Path,
    repository: str,
    *,
    prior_main_sha: str,
    accepted_main_sha: str,
    accepted_tree_sha: str,
    expected_identity: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Prove a fixed accepted-main DAG through one retained Git descriptor."""

    if (
        not isinstance(repository, str)
        or REPOSITORY.fullmatch(repository) is None
        or any(
            not isinstance(value, str) or GIT_SHA.fullmatch(value) is None
            for value in (prior_main_sha, accepted_main_sha, accepted_tree_sha)
        )
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROOF_INVALID")
    path = Path(git_dir)
    descriptor = -1
    try:
        descriptor = _open_absolute_directory(path)
        initial = os.fstat(descriptor)
        if not _owner_directory_valid(initial):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_UNSAFE")
        identity = _stable_directory_identity(initial)
        if expected_identity is not None and identity != expected_identity:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_SUBSTITUTED")
        # This fence deliberately precedes the first Git child.
        _reject_derived_git_state(descriptor)
        origin_url = _origin_url(descriptor)
        if _repository_from_origin(origin_url) != repository:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_ORIGIN_MISMATCH")
        remote_main = _remote_main(descriptor)
        if remote_main != accepted_main_sha:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_SOURCE_MAIN_DRIFT")

        try:
            proved_remote = _fixed_git(
                descriptor,
                ("rev-parse", "--verify", "refs/remotes/origin/main^{commit}"),
            ).decode("ascii").strip()
            proved_tree = _fixed_git(
                descriptor,
                ("rev-parse", "--verify", f"{accepted_main_sha}^{{tree}}"),
            ).decode("ascii").strip()
        except UnicodeError as exc:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_PROOF_FAILED") from exc
        if proved_remote != accepted_main_sha or proved_tree != accepted_tree_sha:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_PROOF_MISMATCH")
        try:
            ancestry = subprocess.run(
                [
                    FIXED_GIT,
                    "--no-replace-objects",
                    f"--git-dir=/proc/self/fd/{descriptor}",
                    "merge-base",
                    "--is-ancestor",
                    prior_main_sha,
                    accepted_main_sha,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_closed_git_environment(),
                pass_fds=(descriptor,),
                close_fds=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_PROOF_FAILED") from exc
        if ancestry.returncode == 1:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_MAIN_NOT_DESCENDANT")
        if ancestry.returncode != 0 or ancestry.stdout or len(ancestry.stderr) > 4096:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_PROOF_FAILED")

        _reject_derived_git_state(descriptor)
        if _remote_main(descriptor) != accepted_main_sha:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_SOURCE_MAIN_DRIFT")
        final = os.fstat(descriptor)
        try:
            named = path.lstat()
        except OSError as exc:
            raise RepositoryGitRegistryError(
                "REPOSITORY_GIT_DIRECTORY_SUBSTITUTED"
            ) from exc
        if (
            _metadata_identity(initial) != _metadata_identity(final)
            or _metadata_identity(final) != _metadata_identity(named)
        ):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_SUBSTITUTED")
        return {
            "repository": repository,
            "origin_url": origin_url,
            "main_sha": accepted_main_sha,
            "tree_sha": accepted_tree_sha,
            "prior_main_sha": prior_main_sha,
            "git_dir": os.fspath(path),
            "git_dir_identity": identity,
        }
    except RepositoryGitRegistryError:
        raise
    except OSError as exc:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_DIRECTORY_INVALID") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def ensure_repository_git_registry_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS coordination_repository_git_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            git_dir TEXT NOT NULL,
            source_main_sha TEXT NOT NULL,
            origin_url TEXT NOT NULL,
            bootstrap_id TEXT NOT NULL,
            bootstrap_manifest_sha256 TEXT NOT NULL,
            device_id INTEGER NOT NULL,
            inode INTEGER NOT NULL,
            owner_uid INTEGER NOT NULL,
            owner_gid INTEGER NOT NULL,
            mode INTEGER NOT NULL,
            registration_sha256 TEXT NOT NULL UNIQUE,
            registration_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(bootstrap_id)
                REFERENCES coordination_bootstrap_provenance(bootstrap_id),
            UNIQUE(device_id, inode)
        );
        CREATE INDEX IF NOT EXISTS coordination_repository_git_registration_repository
            ON coordination_repository_git_registrations(repository);
        CREATE TRIGGER IF NOT EXISTS coordination_bootstrap_provenance_immutable_insert_collision
        BEFORE INSERT ON coordination_bootstrap_provenance
        WHEN EXISTS(
            SELECT 1 FROM coordination_bootstrap_provenance
            WHERE bootstrap_id=NEW.bootstrap_id
               OR manifest_sha256=NEW.manifest_sha256
        )
        BEGIN
            SELECT RAISE(ABORT, 'BOOTSTRAP_PROVENANCE_IMMUTABLE');
        END;
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
        END;
        CREATE TRIGGER IF NOT EXISTS coordination_repository_git_registration_unique
        BEFORE INSERT ON coordination_repository_git_registrations
        WHEN EXISTS(
            SELECT 1 FROM coordination_repository_git_registrations
            WHERE repository=NEW.repository OR git_dir=NEW.git_dir
        )
        BEGIN
            SELECT RAISE(ABORT, 'REPOSITORY_GIT_REGISTRATION_DUPLICATE');
        END;
        CREATE TRIGGER IF NOT EXISTS coordination_repository_git_registration_immutable_update
        BEFORE UPDATE ON coordination_repository_git_registrations
        BEGIN
            SELECT RAISE(ABORT, 'REPOSITORY_GIT_REGISTRATION_IMMUTABLE');
        END;
        CREATE TRIGGER IF NOT EXISTS coordination_repository_git_registration_immutable_delete
        BEFORE DELETE ON coordination_repository_git_registrations
        BEGIN
            SELECT RAISE(ABORT, 'REPOSITORY_GIT_REGISTRATION_IMMUTABLE');
        END;
        """
    )


def _bootstrap_binding(
    connection: sqlite3.Connection,
    *,
    repository: str,
    bootstrap_id: str,
    bootstrap_manifest_sha256: str,
) -> str:
    rows = connection.execute(
        "SELECT * FROM coordination_bootstrap_provenance WHERE bootstrap_id=?",
        (bootstrap_id,),
    ).fetchall()
    if len(rows) != 1:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROVENANCE_MISSING")
    row = rows[0]
    try:
        manifest = json.loads(row["manifest_json"], object_pairs_hook=_strict_object)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROVENANCE_DRIFT") from exc
    if (
        row["manifest_sha256"] != bootstrap_manifest_sha256
        or not isinstance(manifest, dict)
        or _canonical_json(manifest) != row["manifest_json"]
        or hashlib.sha256(row["manifest_json"].encode("utf-8")).hexdigest()
        != row["manifest_sha256"]
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROVENANCE_DRIFT")
    if repository == row["source_harness_repository"]:
        return str(row["source_harness_main_sha"])
    if repository == row["application_repository"]:
        return str(row["application_main_sha"])
    raise RepositoryGitRegistryError("REPOSITORY_GIT_REPOSITORY_UNSUPPORTED")


def _registration_manifest(
    *,
    repository: str,
    git_dir: Path,
    source_main_sha: str,
    origin_url: str,
    bootstrap_id: str,
    bootstrap_manifest_sha256: str,
    identity: dict[str, int],
) -> dict[str, Any]:
    return {
        "schema": REGISTRATION_SCHEMA,
        "repository": repository,
        "git_dir": os.fspath(git_dir),
        "source_main_sha": source_main_sha,
        "origin_url": origin_url,
        "provenance": {
            "bootstrap_id": bootstrap_id,
            "bootstrap_manifest_sha256": bootstrap_manifest_sha256,
        },
        "git_dir_identity": identity,
    }


def load_repository_git_registration(
    connection: sqlite3.Connection, repository: str
) -> dict[str, Any]:
    if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REPOSITORY_INVALID")
    rows = connection.execute(
        "SELECT * FROM coordination_repository_git_registrations WHERE repository=?",
        (repository,),
    ).fetchall()
    if not rows:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_MISSING")
    if len(rows) != 1:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_DUPLICATE")
    row = rows[0]
    try:
        manifest = json.loads(row["registration_json"], object_pairs_hook=_strict_object)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_INVALID") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema",
            "repository",
            "git_dir",
            "source_main_sha",
            "origin_url",
            "provenance",
            "git_dir_identity",
        }
        or manifest.get("schema") != REGISTRATION_SCHEMA
        or manifest.get("repository") != repository
        or not isinstance(manifest.get("git_dir"), str)
        or not Path(manifest["git_dir"]).is_absolute()
        or not isinstance(manifest.get("origin_url"), str)
        or not isinstance(manifest.get("source_main_sha"), str)
        or GIT_SHA.fullmatch(manifest["source_main_sha"]) is None
        or not isinstance(manifest.get("provenance"), dict)
        or set(manifest["provenance"])
        != {"bootstrap_id", "bootstrap_manifest_sha256"}
        or not isinstance(manifest.get("git_dir_identity"), dict)
        or set(manifest["git_dir_identity"])
        != {"device", "inode", "mode", "uid", "gid", "link_count"}
        or any(
            type(value) is not int or value < 0
            for value in manifest["git_dir_identity"].values()
        )
        or manifest["repository"] != row["repository"]
        or manifest["git_dir"] != row["git_dir"]
        or manifest["source_main_sha"] != row["source_main_sha"]
        or manifest["origin_url"] != row["origin_url"]
        or manifest["provenance"]["bootstrap_id"] != row["bootstrap_id"]
        or manifest["provenance"]["bootstrap_manifest_sha256"]
        != row["bootstrap_manifest_sha256"]
        or manifest["git_dir_identity"]["device"] != row["device_id"]
        or manifest["git_dir_identity"]["inode"] != row["inode"]
        or manifest["git_dir_identity"]["uid"] != row["owner_uid"]
        or manifest["git_dir_identity"]["gid"] != row["owner_gid"]
        or manifest["git_dir_identity"]["mode"] != row["mode"]
        or not isinstance(row["registration_sha256"], str)
        or SHA256.fullmatch(row["registration_sha256"]) is None
        or _canonical_json(manifest) != row["registration_json"]
        or _digest(manifest) != row["registration_sha256"]
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_INVALID")
    expected_main = _bootstrap_binding(
        connection,
        repository=repository,
        bootstrap_id=manifest["provenance"]["bootstrap_id"],
        bootstrap_manifest_sha256=manifest["provenance"][
            "bootstrap_manifest_sha256"
        ],
    )
    if expected_main != manifest["source_main_sha"]:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROVENANCE_DRIFT")
    return {
        **manifest,
        "registration_sha256": str(row["registration_sha256"]),
        "created_at": str(row["created_at"]),
    }


def record_repository_git_registration(
    connection: sqlite3.Connection,
    *,
    repository: str,
    git_dir: Path,
    source_main_sha: str,
    bootstrap_id: str,
    bootstrap_manifest_sha256: str,
    now: str,
) -> dict[str, Any]:
    if not connection.in_transaction:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_TRANSACTION_REQUIRED")
    if (
        not isinstance(repository, str)
        or REPOSITORY.fullmatch(repository) is None
        or not isinstance(source_main_sha, str)
        or GIT_SHA.fullmatch(source_main_sha) is None
        or not isinstance(bootstrap_id, str)
        or not bootstrap_id
        or not isinstance(bootstrap_manifest_sha256, str)
        or SHA256.fullmatch(bootstrap_manifest_sha256) is None
        or not isinstance(now, str)
        or not now
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_INVALID")
    path = Path(git_dir)
    expected_main = _bootstrap_binding(
        connection,
        repository=repository,
        bootstrap_id=bootstrap_id,
        bootstrap_manifest_sha256=bootstrap_manifest_sha256,
    )
    if expected_main != source_main_sha:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_PROVENANCE_DRIFT")
    existing_rows = connection.execute(
        "SELECT * FROM coordination_repository_git_registrations WHERE repository=?",
        (repository,),
    ).fetchall()
    if len(existing_rows) > 1:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_DUPLICATE")
    if existing_rows:
        existing = load_repository_git_registration(connection, repository)
        if (
            existing["git_dir"] != os.fspath(path)
            or existing["source_main_sha"] != source_main_sha
            or existing["provenance"]["bootstrap_id"] != bootstrap_id
            or existing["provenance"]["bootstrap_manifest_sha256"]
            != bootstrap_manifest_sha256
        ):
            raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_CONFLICT")
        identity, origin_url, _current_main = _observe_git_directory(
            path,
            repository,
            expected_identity=existing["git_dir_identity"],
        )
        replay_manifest = _registration_manifest(
            repository=repository,
            git_dir=path,
            source_main_sha=source_main_sha,
            origin_url=origin_url,
            bootstrap_id=bootstrap_id,
            bootstrap_manifest_sha256=bootstrap_manifest_sha256,
            identity=identity,
        )
        if _digest(replay_manifest) != existing["registration_sha256"]:
            raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_CONFLICT")
        return {**existing, "replay": True}
    identity, origin_url, current_main = _observe_git_directory(path, repository)
    if current_main != source_main_sha:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_SOURCE_MAIN_DRIFT")
    manifest = _registration_manifest(
        repository=repository,
        git_dir=path,
        source_main_sha=source_main_sha,
        origin_url=origin_url,
        bootstrap_id=bootstrap_id,
        bootstrap_manifest_sha256=bootstrap_manifest_sha256,
        identity=identity,
    )
    registration_sha256 = _digest(manifest)
    try:
        connection.execute(
            """
            INSERT INTO coordination_repository_git_registrations(
                repository, git_dir, source_main_sha, origin_url, bootstrap_id,
                bootstrap_manifest_sha256, device_id, inode, owner_uid,
                owner_gid, mode, registration_sha256, registration_json,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                repository,
                os.fspath(path),
                source_main_sha,
                origin_url,
                bootstrap_id,
                bootstrap_manifest_sha256,
                identity["device"],
                identity["inode"],
                identity["uid"],
                identity["gid"],
                identity["mode"],
                registration_sha256,
                _canonical_json(manifest),
                now,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise RepositoryGitRegistryError(
            "REPOSITORY_GIT_REGISTRATION_DUPLICATE"
        ) from exc
    return {**load_repository_git_registration(connection, repository), "replay": False}


def read_registered_repository_main(
    connection: sqlite3.Connection, repository: str
) -> str:
    registration = load_repository_git_registration(connection, repository)
    identity, origin_url, main_sha = _observe_git_directory(
        Path(registration["git_dir"]),
        repository,
        expected_identity=registration["git_dir_identity"],
    )
    if (
        identity != registration["git_dir_identity"]
        or origin_url != registration["origin_url"]
    ):
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_DRIFT")
    final = load_repository_git_registration(connection, repository)
    if final["registration_sha256"] != registration["registration_sha256"]:
        raise RepositoryGitRegistryError("REPOSITORY_GIT_REGISTRATION_DRIFT")
    return main_sha
