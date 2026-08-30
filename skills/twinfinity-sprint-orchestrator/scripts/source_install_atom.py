#!/usr/bin/env python3
"""Stage, validate, install, or recover one reviewed journaled file set."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Iterator


SCHEMA = "twinfinity-source-install-atom/v2"
DESTINATION_ROOT_IDENTITY_SCHEMA = "twinfinity-destination-root-identity/v1"
STAGE_RECEIPT = ".twinfinity-source-install-stage.json"
ROLLBACK_RECEIPT = "rollback.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class SourceInstallAtomError(RuntimeError):
    """A source-install atom invariant failed."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def manifest_digest(manifest: dict[str, Any]) -> str:
    return digest_json({key: value for key, value in manifest.items() if key != "manifest_sha256"})


def receipt_digest(receipt: dict[str, Any]) -> str:
    return digest_json(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, error: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceInstallAtomError(error) from exc
    if not isinstance(value, dict):
        raise SourceInstallAtomError(error)
    return value


def _relative(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SourceInstallAtomError("INSTALL_ATOM_PATH_INVALID")
    path = Path(value)
    if path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise SourceInstallAtomError("INSTALL_ATOM_PATH_INVALID")
    return path


def _canonical_root_path(path: Path) -> Path:
    if not path.is_absolute() or "\x00" in os.fspath(path):
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_INVALID")
    canonical = Path(os.path.abspath(path))
    if os.fspath(path) != os.fspath(canonical):
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_NONCANONICAL")
    return canonical


def _safe_root(path: Path) -> Path:
    path = _canonical_root_path(path)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise SourceInstallAtomError("INSTALL_ATOM_ROOT_INVALID") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SourceInstallAtomError("INSTALL_ATOM_ROOT_INVALID")
    metadata = path.lstat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_UNSAFE")
    return path


def _safe_file(root: Path, relative: Path, *, required: bool = True) -> Path | None:
    candidate = Path(os.path.abspath(root / relative))
    try:
        candidate.relative_to(root)
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except FileNotFoundError:
        if not required:
            return None
        raise SourceInstallAtomError("INSTALL_ATOM_FILE_MISSING")
    except (ValueError, RuntimeError) as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_FILE_UNSAFE") from exc
    if (
        candidate != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_FILE_UNSAFE")
    return candidate


DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _validate_directory_descriptor(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_DIRECTORY_UNSAFE")


def _directory_identity(
    descriptor: int,
) -> tuple[int, int, int, int, int, int]:
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _directory_identity_payload(descriptor: int) -> dict[str, int]:
    identity = _directory_identity(descriptor)
    return {
        "device": identity[0],
        "inode": identity[1],
        "mode": identity[2],
        "uid": identity[3],
        "gid": identity[4],
    }


def _destination_root_identity_from_descriptor(
    root: Path, descriptor: int
) -> dict[str, str]:
    canonical = _canonical_root_path(root)
    _validate_directory_descriptor(descriptor)
    canonical_path_sha256 = hashlib.sha256(
        os.fsencode(os.fspath(canonical))
    ).hexdigest()
    filesystem_identity_sha256 = digest_json(
        _directory_identity_payload(descriptor)
    )
    identity = {
        "schema": DESTINATION_ROOT_IDENTITY_SCHEMA,
        "canonical_path_sha256": canonical_path_sha256,
        "filesystem_identity_sha256": filesystem_identity_sha256,
    }
    identity["identity_sha256"] = digest_json(identity)
    return identity


def destination_root_identity(root: Path) -> dict[str, str]:
    """Return privacy-safe evidence for one exact canonical destination root."""

    with _root_descriptor(root) as descriptor:
        return _destination_root_identity_from_descriptor(root, descriptor)


def _validate_destination_root_identity(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "canonical_path_sha256",
        "filesystem_identity_sha256",
        "identity_sha256",
    }:
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_IDENTITY_SCHEMA_INVALID")
    if (
        value["schema"] != DESTINATION_ROOT_IDENTITY_SCHEMA
        or any(
            not isinstance(value[key], str) or SHA256.fullmatch(value[key]) is None
            for key in (
                "canonical_path_sha256",
                "filesystem_identity_sha256",
                "identity_sha256",
            )
        )
        or digest_json(
            {
                "schema": value["schema"],
                "canonical_path_sha256": value["canonical_path_sha256"],
                "filesystem_identity_sha256": value[
                    "filesystem_identity_sha256"
                ],
            }
        )
        != value["identity_sha256"]
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_IDENTITY_INVALID")
    return value


def _require_destination_root_identity(
    manifest: dict[str, Any],
    destination_root: Path,
    *,
    root_descriptor: int | None = None,
    require_current_path: bool = True,
) -> dict[str, str]:
    expected = _validate_destination_root_identity(
        manifest.get("destination_root_identity")
    )
    if root_descriptor is None:
        observed = destination_root_identity(destination_root)
    else:
        observed = _destination_root_identity_from_descriptor(
            destination_root, root_descriptor
        )
        if require_current_path:
            with _root_descriptor(destination_root) as reopened:
                if _directory_identity(reopened) != _directory_identity(
                    root_descriptor
                ):
                    raise SourceInstallAtomError(
                        "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
                    )
                reopened_identity = _destination_root_identity_from_descriptor(
                    destination_root, reopened
                )
                if reopened_identity != observed:
                    raise SourceInstallAtomError(
                        "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
                    )
    if observed != expected:
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_IDENTITY_MISMATCH")
    return expected


def seal_manifest(
    manifest: dict[str, Any], destination_root: Path
) -> dict[str, Any]:
    """Bind one reviewed schema-v2 template to an exact destination root."""

    if set(manifest) != {
        "schema",
        "atom_id",
        "source_commit",
        "entries",
    } or manifest.get("schema") != SCHEMA:
        raise SourceInstallAtomError("INSTALL_ATOM_MANIFEST_SCHEMA_INVALID")
    sealed = dict(manifest)
    sealed["destination_root_identity"] = destination_root_identity(
        destination_root
    )
    sealed["manifest_sha256"] = manifest_digest(sealed)
    _validate_manifest(sealed)
    return sealed


def _seal_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(receipt)
    sealed["receipt_sha256"] = receipt_digest(sealed)
    return sealed


def _validate_receipt_digest(
    receipt: dict[str, Any], error: str
) -> None:
    value = receipt.get("receipt_sha256")
    if (
        not isinstance(value, str)
        or SHA256.fullmatch(value) is None
        or receipt_digest(receipt) != value
    ):
        raise SourceInstallAtomError(error)


@dataclass(frozen=True)
class DestinationParentBinding:
    relative: Path
    leaf: str
    descriptor: int
    component_identities: tuple[tuple[int, int, int, int, int, int], ...]


def _binding_key(entry: dict[str, Any]) -> str:
    return _relative(entry["destination_path"]).as_posix()


def _open_destination_parent_binding(
    root_descriptor: int, relative: Path
) -> DestinationParentBinding:
    descriptor = os.dup(root_descriptor)
    identities = [_directory_identity(descriptor)]
    try:
        for part in relative.parts[:-1]:
            try:
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise SourceInstallAtomError(
                    "INSTALL_ATOM_DIRECTORY_UNSAFE"
                ) from exc
            try:
                _validate_directory_descriptor(child)
                identities.append(_directory_identity(child))
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return DestinationParentBinding(
            relative=relative,
            leaf=relative.name,
            descriptor=descriptor,
            component_identities=tuple(identities),
        )
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _destination_parent_bindings(
    root_descriptor: int, entries: list[dict[str, Any]]
) -> Iterator[dict[str, DestinationParentBinding]]:
    bindings: dict[str, DestinationParentBinding] = {}
    try:
        for entry in entries:
            relative = _relative(entry["destination_path"])
            binding = _open_destination_parent_binding(root_descriptor, relative)
            bindings[relative.as_posix()] = binding
        yield bindings
    finally:
        for binding in bindings.values():
            os.close(binding.descriptor)


def _verify_destination_parent_binding(
    root_descriptor: int, binding: DestinationParentBinding
) -> None:
    descriptor = os.dup(root_descriptor)
    try:
        if _directory_identity(descriptor) != binding.component_identities[0]:
            raise SourceInstallAtomError("INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT")
        for index, part in enumerate(binding.relative.parts[:-1], start=1):
            try:
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise SourceInstallAtomError(
                    "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT"
                ) from exc
            os.close(descriptor)
            descriptor = child
            try:
                _validate_directory_descriptor(descriptor)
            except SourceInstallAtomError as exc:
                raise SourceInstallAtomError(
                    "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT"
                ) from exc
            if _directory_identity(descriptor) != binding.component_identities[index]:
                raise SourceInstallAtomError(
                    "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT"
                )
        if _directory_identity(descriptor) != _directory_identity(
            binding.descriptor
        ):
            raise SourceInstallAtomError("INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT")
    finally:
        os.close(descriptor)


def _verify_destination_bindings(
    destination_root: Path,
    root_descriptor: int,
    bindings: dict[str, DestinationParentBinding],
) -> None:
    try:
        with _root_descriptor(destination_root) as reopened_root:
            if _directory_identity(reopened_root) != _directory_identity(
                root_descriptor
            ):
                raise SourceInstallAtomError(
                    "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT"
                )
            for binding in bindings.values():
                _verify_destination_parent_binding(reopened_root, binding)
    except SourceInstallAtomError as exc:
        if str(exc) == "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT":
            raise
        raise SourceInstallAtomError(
            "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT"
        ) from exc


@contextmanager
def _root_descriptor(root: Path) -> Iterator[int]:
    root = _canonical_root_path(root)
    try:
        descriptor = os.open(root.anchor, DIRECTORY_FLAGS)
    except OSError as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_INVALID") from exc
    try:
        for part in root.parts[1:]:
            try:
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise SourceInstallAtomError("INSTALL_ATOM_ROOT_INVALID") from exc
            try:
                if not stat.S_ISDIR(os.fstat(child).st_mode):
                    raise SourceInstallAtomError("INSTALL_ATOM_ROOT_INVALID")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        _validate_directory_descriptor(descriptor)
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _parent_descriptor(
    root_descriptor: int, relative: Path, *, create: bool = False
) -> Iterator[tuple[int, str]]:
    """Open every parent without following a path component symlink."""

    descriptor = os.dup(root_descriptor)
    try:
        for part in relative.parts[:-1]:
            try:
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise SourceInstallAtomError(
                        "INSTALL_ATOM_DESTINATION_PARENT_MISSING"
                    )
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError as exc:
                    raise SourceInstallAtomError(
                        "INSTALL_ATOM_DIRECTORY_CREATE_FAILED"
                    ) from exc
            except OSError as exc:
                raise SourceInstallAtomError("INSTALL_ATOM_DIRECTORY_UNSAFE") from exc
            try:
                _validate_directory_descriptor(child)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        yield descriptor, relative.name
    finally:
        os.close(descriptor)


def _read_regular_at(
    root_descriptor: int,
    relative: Path,
    *,
    required: bool = True,
) -> tuple[bytes, os.stat_result] | None:
    with _parent_descriptor(root_descriptor, relative) as (parent, leaf):
        return _read_regular_leaf_at(parent, leaf, required=required)


def _read_regular_leaf_at(
    parent_descriptor: int,
    leaf: str,
    *,
    required: bool = True,
) -> tuple[bytes, os.stat_result] | None:
    try:
        descriptor = os.open(leaf, FILE_FLAGS, dir_fd=parent_descriptor)
    except FileNotFoundError:
        if not required:
            return None
        raise SourceInstallAtomError("INSTALL_ATOM_FILE_MISSING")
    except OSError as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_FILE_UNSAFE") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise SourceInstallAtomError("INSTALL_ATOM_FILE_UNSAFE")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _write_exclusive_at(
    root_descriptor: int,
    relative: Path,
    contents: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    create_parents: bool = False,
) -> None:
    with _parent_descriptor(
        root_descriptor, relative, create=create_parents
    ) as (parent, leaf):
        _write_leaf_exclusive(
            parent, leaf, contents, mode=mode, uid=uid, gid=gid
        )
        os.fsync(parent)


def _write_leaf_exclusive(
    parent_descriptor: int,
    leaf: str,
    contents: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(leaf, flags, mode, dir_fd=parent_descriptor)
    except OSError as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_FILE_CREATE_FAILED") from exc
    try:
        view = memoryview(contents)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise SourceInstallAtomError("INSTALL_ATOM_OWNER_MODE_INVALID")
    finally:
        os.close(descriptor)


def _verify_source_commit(
    source_root: Path, manifest: dict[str, Any], entries: list[dict[str, Any]]
) -> None:
    """Bind selected source bytes to an independently observed Git commit."""

    environment = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}

    def git(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                ["git", "-C", str(source_root), *arguments],
                check=True,
                capture_output=True,
                env=environment,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise SourceInstallAtomError("INSTALL_ATOM_SOURCE_COMMIT_INVALID") from exc

    top = Path(git("rev-parse", "--show-toplevel").stdout.decode().strip())
    if top.resolve(strict=True) != source_root.resolve(strict=True):
        raise SourceInstallAtomError("INSTALL_ATOM_SOURCE_COMMIT_INVALID")
    observed_commit = git("rev-parse", "--verify", "HEAD").stdout.decode().strip()
    if observed_commit != manifest["source_commit"]:
        raise SourceInstallAtomError("INSTALL_ATOM_SOURCE_COMMIT_MISMATCH")
    with _root_descriptor(source_root) as source_descriptor:
        for entry in entries:
            relative = _relative(entry["source_path"])
            actual = _read_regular_at(source_descriptor, relative)
            if actual is None:
                raise SourceInstallAtomError("INSTALL_ATOM_SOURCE_HASH_MISMATCH")
            committed = git(
                "show", f"{manifest['source_commit']}:{relative.as_posix()}"
            ).stdout
            if actual[0] != committed:
                raise SourceInstallAtomError("INSTALL_ATOM_SOURCE_COMMIT_MISMATCH")


def _validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if set(manifest) != {
        "schema",
        "manifest_sha256",
        "atom_id",
        "source_commit",
        "destination_root_identity",
        "entries",
    }:
        raise SourceInstallAtomError("INSTALL_ATOM_MANIFEST_SCHEMA_INVALID")
    _validate_destination_root_identity(manifest["destination_root_identity"])
    if (
        manifest["schema"] != SCHEMA
        or not isinstance(manifest["atom_id"], str)
        or not manifest["atom_id"]
        or not isinstance(manifest["source_commit"], str)
        or GIT_SHA.fullmatch(manifest["source_commit"]) is None
        or not isinstance(manifest["manifest_sha256"], str)
        or SHA256.fullmatch(manifest["manifest_sha256"]) is None
        or manifest_digest(manifest) != manifest["manifest_sha256"]
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_MANIFEST_INVALID")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise SourceInstallAtomError("INSTALL_ATOM_MANIFEST_SCHEMA_INVALID")
    seen_sources: set[str] = set()
    seen_destinations: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "source_path", "destination_path", "source_sha256", "source_mode",
            "destination_mode", "destination_uid", "destination_gid", "destination_prior",
        }:
            raise SourceInstallAtomError("INSTALL_ATOM_ENTRY_SCHEMA_INVALID")
        source = _relative(entry["source_path"])
        destination = _relative(entry["destination_path"])
        prior = entry["destination_prior"]
        if (
            source.as_posix() in seen_sources
            or destination.as_posix() in seen_destinations
            or not isinstance(entry["source_sha256"], str)
            or SHA256.fullmatch(entry["source_sha256"]) is None
            or entry["source_mode"] not in (0o600, 0o644, 0o700, 0o755)
            or entry["destination_mode"] not in (0o600, 0o644, 0o700, 0o755)
            or entry["destination_uid"] != os.getuid()
            or entry["destination_gid"] != os.getgid()
            or not isinstance(prior, dict)
            or set(prior) not in (
                {"state"},
                {"state", "sha256", "mode", "uid", "gid"},
            )
            or prior.get("state") not in ("ABSENT", "PRESENT")
            or (prior["state"] == "ABSENT" and set(prior) != {"state"})
            or (
                prior["state"] == "PRESENT"
                and (
                    set(prior) != {"state", "sha256", "mode", "uid", "gid"}
                    or not isinstance(prior["sha256"], str)
                    or SHA256.fullmatch(prior["sha256"]) is None
                    or prior["mode"] not in (0o600, 0o644, 0o700, 0o755)
                    or prior["uid"] != os.getuid()
                    or prior["gid"] != os.getgid()
                )
            )
        ):
            raise SourceInstallAtomError("INSTALL_ATOM_ENTRY_SCHEMA_INVALID")
        seen_sources.add(source.as_posix())
        seen_destinations.add(destination.as_posix())
    return entries


def _validate_prior_at(destination_descriptor: int, entry: dict[str, Any]) -> None:
    relative = _relative(entry["destination_path"])
    actual = _read_regular_at(destination_descriptor, relative, required=False)
    prior = entry["destination_prior"]
    if prior["state"] == "ABSENT":
        if actual is not None:
            raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")
        return
    if actual is None:
        raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")
    contents, metadata = actual
    if (
        _sha256_bytes(contents) != prior["sha256"]
        or stat.S_IMODE(metadata.st_mode) != prior["mode"]
        or metadata.st_uid != prior["uid"]
        or metadata.st_gid != prior["gid"]
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")


def _validate_prior_binding(
    binding: DestinationParentBinding, entry: dict[str, Any]
) -> None:
    actual = _read_regular_leaf_at(
        binding.descriptor, binding.leaf, required=False
    )
    prior = entry["destination_prior"]
    if prior["state"] == "ABSENT":
        if actual is not None:
            raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")
        return
    if actual is None:
        raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")
    contents, metadata = actual
    if (
        _sha256_bytes(contents) != prior["sha256"]
        or stat.S_IMODE(metadata.st_mode) != prior["mode"]
        or metadata.st_uid != prior["uid"]
        or metadata.st_gid != prior["gid"]
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")


def _validate_prior(destination_root: Path, entry: dict[str, Any]) -> None:
    with _root_descriptor(destination_root) as descriptor:
        _validate_prior_at(descriptor, entry)


def _write_file_exclusive(path: Path, contents: bytes, mode: int) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        view = memoryview(contents)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _write_sealed_manifest(path: Path, manifest: dict[str, Any]) -> None:
    canonical = Path(os.path.abspath(path))
    if (
        not path.is_absolute()
        or path != canonical
        or path.exists()
        or path.is_symlink()
        or path.name in {"", ".", ".."}
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_SEAL_OUTPUT_INVALID")
    parent = _safe_root(path.parent)
    contents = canonical_json(manifest).encode("utf-8")
    try:
        _write_file_exclusive(parent / path.name, contents, 0o600)
    except OSError as exc:
        raise SourceInstallAtomError(
            "INSTALL_ATOM_SEAL_OUTPUT_INVALID"
        ) from exc


def _make_private_directory(path: Path) -> None:
    old_umask = os.umask(0o077)
    try:
        path.mkdir(mode=0o700)
    except (FileExistsError, OSError) as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_DESTINATION_EXISTS") from exc
    finally:
        os.umask(old_umask)


def stage_atom(*, manifest: dict[str, Any], source_root: Path, destination_root: Path, stage_root: Path) -> dict[str, Any]:
    entries = _validate_manifest(manifest)
    source_root = _safe_root(source_root)
    destination_root = _safe_root(destination_root)
    root_identity = _require_destination_root_identity(
        manifest, destination_root
    )
    _verify_source_commit(source_root, manifest, entries)
    if not stage_root.is_absolute() or stage_root.exists() or stage_root.is_symlink():
        raise SourceInstallAtomError("INSTALL_ATOM_STAGE_PATH_INVALID")
    _safe_root(stage_root.parent)
    _require_destination_root_identity(manifest, destination_root)
    _make_private_directory(stage_root)
    staged: list[dict[str, Any]] = []
    try:
        for entry in entries:
            _validate_prior(destination_root, entry)
            source = _safe_file(source_root, _relative(entry["source_path"]))
            if source is None or _file_sha256(source) != entry["source_sha256"] or stat.S_IMODE(source.lstat().st_mode) != entry["source_mode"]:
                raise SourceInstallAtomError("INSTALL_ATOM_SOURCE_HASH_MISMATCH")
            relative = _relative(entry["destination_path"])
            target = stage_root / relative
            _require_destination_root_identity(manifest, destination_root)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _require_destination_root_identity(manifest, destination_root)
            _write_file_exclusive(target, source.read_bytes(), entry["destination_mode"])
            staged.append({"destination_path": relative.as_posix(), "sha256": _file_sha256(target), "mode": entry["destination_mode"]})
        receipt = _seal_receipt({
            "schema": SCHEMA,
            "manifest_sha256": manifest["manifest_sha256"],
            "destination_root_identity": root_identity,
            "entries": staged,
            "state": "STAGED",
        })
        _require_destination_root_identity(manifest, destination_root)
        _write_file_exclusive(stage_root / STAGE_RECEIPT, canonical_json(receipt).encode("utf-8"), 0o600)
        _require_destination_root_identity(manifest, destination_root)
        return receipt
    except Exception:
        shutil.rmtree(stage_root)
        raise


def validate_stage(
    *,
    manifest: dict[str, Any],
    source_root: Path,
    destination_root: Path,
    stage_root: Path,
    destination_bindings: dict[str, DestinationParentBinding] | None = None,
) -> dict[str, Any]:
    entries = _validate_manifest(manifest)
    source_root = _safe_root(source_root)
    destination_root = _safe_root(destination_root)
    root_identity = _require_destination_root_identity(
        manifest, destination_root
    )
    _verify_source_commit(source_root, manifest, entries)
    stage_root = _safe_root(stage_root)
    receipt = _read_json(stage_root / STAGE_RECEIPT, "INSTALL_ATOM_STAGE_RECEIPT_INVALID")
    if set(receipt) != {
        "schema",
        "manifest_sha256",
        "destination_root_identity",
        "entries",
        "state",
        "receipt_sha256",
    }:
        raise SourceInstallAtomError("INSTALL_ATOM_STAGE_RECEIPT_INVALID")
    _validate_receipt_digest(receipt, "INSTALL_ATOM_STAGE_RECEIPT_INVALID")
    if (
        receipt.get("schema") != SCHEMA
        or receipt.get("manifest_sha256") != manifest["manifest_sha256"]
        or receipt.get("destination_root_identity") != root_identity
        or receipt.get("state") != "STAGED"
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_STAGE_RECEIPT_INVALID")
    observed: list[dict[str, Any]] = []
    for entry in entries:
        if destination_bindings is None:
            _validate_prior(destination_root, entry)
        else:
            _validate_prior_binding(
                destination_bindings[_binding_key(entry)], entry
            )
        source = _safe_file(source_root, _relative(entry["source_path"]))
        staged = _safe_file(stage_root, _relative(entry["destination_path"]))
        if (
            source is None
            or staged is None
            or _file_sha256(source) != entry["source_sha256"]
            or stat.S_IMODE(source.lstat().st_mode) != entry["source_mode"]
            or _file_sha256(staged) != entry["source_sha256"]
            or stat.S_IMODE(staged.lstat().st_mode) != entry["destination_mode"]
        ):
            raise SourceInstallAtomError("INSTALL_ATOM_STAGE_VALIDATION_FAILED")
        observed.append({"destination_path": entry["destination_path"], "sha256": entry["source_sha256"], "mode": entry["destination_mode"]})
    if receipt.get("entries") != observed:
        raise SourceInstallAtomError("INSTALL_ATOM_STAGE_RECEIPT_INVALID")
    _require_destination_root_identity(manifest, destination_root)
    return _seal_receipt({
        "schema": SCHEMA,
        "manifest_sha256": manifest["manifest_sha256"],
        "destination_root_identity": root_identity,
        "rollback_data": [
            {"destination_path": entry["destination_path"], "prior": entry["destination_prior"], "installed_sha256": entry["source_sha256"]}
            for entry in entries
        ],
        "state": "PASS",
    })


@contextmanager
def _destination_lock(root: Path) -> Iterator[int]:
    with _root_descriptor(root) as descriptor:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield descriptor
        except BlockingIOError as exc:
            raise SourceInstallAtomError("INSTALL_ATOM_LOCK_BUSY") from exc
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)


def _atomic_replace_at(
    root_descriptor: int,
    relative: Path,
    contents: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    """Replace one leaf relative to an already validated directory chain."""

    with _parent_descriptor(root_descriptor, relative) as (parent, leaf):
        _atomic_replace_leaf_at(
            parent, leaf, contents, mode=mode, uid=uid, gid=gid
        )


def _atomic_replace_leaf_at(
    parent_descriptor: int,
    leaf: str,
    contents: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    temporary = f".{leaf}.twinfinity-install-{os.getpid()}"
    try:
        try:
            os.stat(temporary, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SourceInstallAtomError("INSTALL_ATOM_TEMP_CONFLICT")
        _write_leaf_exclusive(
            parent_descriptor,
            temporary,
            contents,
            mode=mode,
            uid=uid,
            gid=gid,
        )
        os.replace(
            temporary,
            leaf,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    finally:
        try:
            metadata = os.stat(
                temporary,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid():
                os.unlink(temporary, dir_fd=parent_descriptor)


def _unlink_regular_leaf_at(parent_descriptor: int, leaf: str) -> None:
    current = _read_regular_leaf_at(parent_descriptor, leaf)
    if current is None:
        raise SourceInstallAtomError("INSTALL_ATOM_INSTALLED_HASH_MISMATCH")
    try:
        os.unlink(leaf, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_FAILED") from exc


def _binding_identity_evidence(
    binding: DestinationParentBinding,
) -> list[dict[str, int]]:
    return [
        {
            "device": identity[0],
            "inode": identity[1],
            "mode": identity[2],
            "uid": identity[3],
            "gid": identity[4],
            "links": identity[5],
        }
        for identity in binding.component_identities
    ]


def _receipt(
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    state: str,
    bindings: dict[str, DestinationParentBinding],
) -> dict[str, Any]:
    return _seal_receipt({
        "schema": SCHEMA,
        "manifest_sha256": manifest["manifest_sha256"],
        "destination_root_identity": manifest["destination_root_identity"],
        "entries": [
            {
                "destination_path": entry["destination_path"],
                "destination_prior": entry["destination_prior"],
                "installed_sha256": entry["source_sha256"],
                "installed_mode": entry["destination_mode"],
                "installed_uid": entry["destination_uid"],
                "installed_gid": entry["destination_gid"],
                "destination_parent_identity": _binding_identity_evidence(
                    bindings[_binding_key(entry)]
                ),
            }
            for entry in entries
        ],
        "state": state,
    })


def _read_receipt_at(rollback_descriptor: int) -> dict[str, Any]:
    observed = _read_regular_at(rollback_descriptor, Path(ROLLBACK_RECEIPT))
    if observed is None:
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
    try:
        receipt = json.loads(observed[0].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID") from exc
    if not isinstance(receipt, dict):
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
    return receipt


def _replace_receipt_at(rollback_descriptor: int, receipt: dict[str, Any]) -> None:
    _atomic_replace_at(
        rollback_descriptor,
        Path(ROLLBACK_RECEIPT),
        canonical_json(receipt).encode("utf-8"),
        mode=0o600,
        uid=os.getuid(),
        gid=os.getgid(),
    )


def _validate_receipt(
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    receipt: dict[str, Any],
    bindings: dict[str, DestinationParentBinding],
) -> None:
    if set(receipt) != {
        "schema",
        "manifest_sha256",
        "destination_root_identity",
        "entries",
        "state",
        "receipt_sha256",
    }:
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
    _validate_receipt_digest(receipt, "INSTALL_ATOM_ROLLBACK_DATA_INVALID")
    expected = _receipt(manifest, entries, "PREPARED", bindings)
    if (
        receipt["schema"] != SCHEMA
        or receipt["manifest_sha256"] != manifest["manifest_sha256"]
        or receipt["destination_root_identity"]
        != manifest["destination_root_identity"]
        or receipt["state"] not in ("PREPARED", "INSTALLED", "ROLLED_BACK")
        or not isinstance(receipt["entries"], list)
        or len(receipt["entries"]) != len(expected["entries"])
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
    for observed, current in zip(
        receipt["entries"], expected["entries"], strict=True
    ):
        if not isinstance(observed, dict) or set(observed) != set(current):
            raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
        observed_without_identity = {
            key: value
            for key, value in observed.items()
            if key != "destination_parent_identity"
        }
        current_without_identity = {
            key: value
            for key, value in current.items()
            if key != "destination_parent_identity"
        }
        if observed_without_identity != current_without_identity:
            raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
        if (
            observed["destination_parent_identity"]
            != current["destination_parent_identity"]
        ):
            raise SourceInstallAtomError(
                "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT"
            )


def _entry_state_binding(
    binding: DestinationParentBinding, entry: dict[str, Any]
) -> str:
    current = _read_regular_leaf_at(
        binding.descriptor, binding.leaf, required=False
    )
    prior = entry["destination_prior"]
    if current is not None:
        contents, metadata = current
        if (
            _sha256_bytes(contents) == entry["source_sha256"]
            and stat.S_IMODE(metadata.st_mode) == entry["destination_mode"]
            and metadata.st_uid == entry["destination_uid"]
            and metadata.st_gid == entry["destination_gid"]
        ):
            return "INSTALLED"
        if (
            prior["state"] == "PRESENT"
            and _sha256_bytes(contents) == prior["sha256"]
            and stat.S_IMODE(metadata.st_mode) == prior["mode"]
            and metadata.st_uid == prior["uid"]
            and metadata.st_gid == prior["gid"]
        ):
            return "PRIOR"
    elif prior["state"] == "ABSENT":
        return "PRIOR"
    raise SourceInstallAtomError("INSTALL_ATOM_FILESYSTEM_STATE_INVALID")


def _recover_entries(
    *,
    destination_root: Path,
    destination_descriptor: int,
    destination_bindings: dict[str, DestinationParentBinding],
    rollback_descriptor: int,
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    """Derive a partial transition from bytes and restore the exact prior set."""

    _require_destination_root_identity(
        manifest,
        destination_root,
        root_descriptor=destination_descriptor,
        require_current_path=False,
    )
    _validate_receipt(manifest, entries, receipt, destination_bindings)
    states = [
        _entry_state_binding(destination_bindings[_binding_key(entry)], entry)
        for entry in entries
    ]
    backups: dict[str, bytes] = {}
    for entry in entries:
        prior = entry["destination_prior"]
        if prior["state"] != "PRESENT":
            continue
        relative = Path("files") / _relative(entry["destination_path"])
        observed = _read_regular_at(rollback_descriptor, relative)
        if observed is None:
            raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
        contents, metadata = observed
        if (
            _sha256_bytes(contents) != prior["sha256"]
            or stat.S_IMODE(metadata.st_mode) != prior["mode"]
            or metadata.st_uid != prior["uid"]
            or metadata.st_gid != prior["gid"]
        ):
            raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
        backups[entry["destination_path"]] = contents
    if receipt["state"] == "ROLLED_BACK":
        if any(state != "PRIOR" for state in states):
            raise SourceInstallAtomError("INSTALL_ATOM_FILESYSTEM_STATE_INVALID")
        _require_destination_root_identity(
            manifest,
            destination_root,
            root_descriptor=destination_descriptor,
            require_current_path=False,
        )
        return receipt
    for entry, state in reversed(list(zip(entries, states, strict=True))):
        if state == "PRIOR":
            continue
        binding = destination_bindings[_binding_key(entry)]
        prior = entry["destination_prior"]
        _require_destination_root_identity(
            manifest,
            destination_root,
            root_descriptor=destination_descriptor,
            require_current_path=False,
        )
        if prior["state"] == "ABSENT":
            _unlink_regular_leaf_at(binding.descriptor, binding.leaf)
        else:
            _atomic_replace_leaf_at(
                binding.descriptor,
                binding.leaf,
                backups[entry["destination_path"]],
                mode=prior["mode"],
                uid=prior["uid"],
                gid=prior["gid"],
            )
    if any(
        _entry_state_binding(destination_bindings[_binding_key(entry)], entry)
        != "PRIOR"
        for entry in entries
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_POSTCONDITION_FAILED")
    rolled_back = _receipt(
        manifest, entries, "ROLLED_BACK", destination_bindings
    )
    _require_destination_root_identity(
        manifest,
        destination_root,
        root_descriptor=destination_descriptor,
        require_current_path=False,
    )
    _replace_receipt_at(rollback_descriptor, rolled_back)
    return rolled_back


def apply_atom(*, manifest: dict[str, Any], source_root: Path, destination_root: Path, stage_root: Path, rollback_root: Path, confirmation: str) -> dict[str, Any]:
    if confirmation != f"INSTALL:{manifest.get('manifest_sha256', '')}":
        raise SourceInstallAtomError("INSTALL_ATOM_CONFIRMATION_REQUIRED")
    entries = _validate_manifest(manifest)
    source_root = _safe_root(source_root)
    destination_root = _safe_root(destination_root)
    _require_destination_root_identity(manifest, destination_root)
    if not rollback_root.is_absolute() or rollback_root.exists() or rollback_root.is_symlink():
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_PATH_INVALID")
    _safe_root(rollback_root.parent)
    with _destination_lock(destination_root) as destination_descriptor:
        _require_destination_root_identity(
            manifest,
            destination_root,
            root_descriptor=destination_descriptor,
        )
        with _destination_parent_bindings(
            destination_descriptor, entries
        ) as destination_bindings:
            validate_stage(
                manifest=manifest,
                source_root=source_root,
                destination_root=destination_root,
                stage_root=stage_root,
                destination_bindings=destination_bindings,
            )
            _verify_destination_bindings(
                destination_root, destination_descriptor, destination_bindings
            )
            _require_destination_root_identity(
                manifest,
                destination_root,
                root_descriptor=destination_descriptor,
            )
            _make_private_directory(rollback_root)
            with _root_descriptor(rollback_root) as rollback_descriptor:
                for entry in entries:
                    prior = entry["destination_prior"]
                    if prior["state"] == "PRESENT":
                        binding = destination_bindings[_binding_key(entry)]
                        current = _read_regular_leaf_at(
                            binding.descriptor, binding.leaf
                        )
                        if current is None:
                            raise SourceInstallAtomError(
                                "INSTALL_ATOM_PRIOR_HASH_MISMATCH"
                            )
                        _require_destination_root_identity(
                            manifest,
                            destination_root,
                            root_descriptor=destination_descriptor,
                        )
                        _write_exclusive_at(
                            rollback_descriptor,
                            Path("files") / _relative(entry["destination_path"]),
                            current[0],
                            mode=prior["mode"],
                            uid=prior["uid"],
                            gid=prior["gid"],
                            create_parents=True,
                        )
                prepared = _receipt(
                    manifest, entries, "PREPARED", destination_bindings
                )
                _require_destination_root_identity(
                    manifest,
                    destination_root,
                    root_descriptor=destination_descriptor,
                )
                _write_exclusive_at(
                    rollback_descriptor,
                    Path(ROLLBACK_RECEIPT),
                    canonical_json(prepared).encode("utf-8"),
                    mode=0o600,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
                try:
                    with _root_descriptor(stage_root) as stage_descriptor:
                        for entry in entries:
                            staged = _read_regular_at(
                                stage_descriptor,
                                _relative(entry["destination_path"]),
                            )
                            if staged is None:
                                raise SourceInstallAtomError(
                                    "INSTALL_ATOM_STAGE_VALIDATION_FAILED"
                                )
                            binding = destination_bindings[_binding_key(entry)]
                            _require_destination_root_identity(
                                manifest,
                                destination_root,
                                root_descriptor=destination_descriptor,
                            )
                            _atomic_replace_leaf_at(
                                binding.descriptor,
                                binding.leaf,
                                staged[0],
                                mode=entry["destination_mode"],
                                uid=entry["destination_uid"],
                                gid=entry["destination_gid"],
                            )
                            if (
                                _entry_state_binding(binding, entry)
                                != "INSTALLED"
                            ):
                                raise SourceInstallAtomError(
                                    "INSTALL_ATOM_POSTCONDITION_FAILED"
                                )
                    _verify_destination_bindings(
                        destination_root,
                        destination_descriptor,
                        destination_bindings,
                    )
                    installed = _receipt(
                        manifest, entries, "INSTALLED", destination_bindings
                    )
                    _require_destination_root_identity(
                        manifest,
                        destination_root,
                        root_descriptor=destination_descriptor,
                    )
                    _replace_receipt_at(rollback_descriptor, installed)
                    _verify_destination_bindings(
                        destination_root,
                        destination_descriptor,
                        destination_bindings,
                    )
                    _require_destination_root_identity(
                        manifest,
                        destination_root,
                        root_descriptor=destination_descriptor,
                    )
                    return installed
                except BaseException as failure:
                    try:
                        observed_receipt = _read_receipt_at(rollback_descriptor)
                        _recover_entries(
                            destination_root=destination_root,
                            destination_descriptor=destination_descriptor,
                            destination_bindings=destination_bindings,
                            rollback_descriptor=rollback_descriptor,
                            manifest=manifest,
                            entries=entries,
                            receipt=observed_receipt,
                        )
                    except BaseException as recovery_failure:
                        raise SourceInstallAtomError(
                            "INSTALL_ATOM_RECOVERY_REQUIRED"
                        ) from recovery_failure
                    _verify_destination_bindings(
                        destination_root,
                        destination_descriptor,
                        destination_bindings,
                    )
                    raise failure


def rollback_atom(*, manifest: dict[str, Any], destination_root: Path, rollback_root: Path, confirmation: str) -> dict[str, Any]:
    if confirmation != f"ROLLBACK:{manifest.get('manifest_sha256', '')}":
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_CONFIRMATION_REQUIRED")
    entries = _validate_manifest(manifest)
    destination_root = _safe_root(destination_root)
    _require_destination_root_identity(manifest, destination_root)
    rollback_root = _safe_root(rollback_root)
    with _destination_lock(destination_root) as destination_descriptor:
        _require_destination_root_identity(
            manifest,
            destination_root,
            root_descriptor=destination_descriptor,
        )
        with _destination_parent_bindings(
            destination_descriptor, entries
        ) as destination_bindings:
            with _root_descriptor(rollback_root) as rollback_descriptor:
                _require_destination_root_identity(
                    manifest,
                    destination_root,
                    root_descriptor=destination_descriptor,
                )
                receipt = _read_receipt_at(rollback_descriptor)
                result = _recover_entries(
                    destination_root=destination_root,
                    destination_descriptor=destination_descriptor,
                    destination_bindings=destination_bindings,
                    rollback_descriptor=rollback_descriptor,
                    manifest=manifest,
                    entries=entries,
                    receipt=receipt,
                )
                _verify_destination_bindings(
                    destination_root,
                    destination_descriptor,
                    destination_bindings,
                )
    terminal = {
        "schema": SCHEMA,
        "manifest_sha256": manifest["manifest_sha256"],
        "destination_root_identity": manifest["destination_root_identity"],
        "state": result["state"],
    }
    terminal["receipt_sha256"] = receipt_digest(terminal)
    return terminal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest = subparsers.add_parser("digest")
    digest.add_argument("--manifest", type=Path, required=True)
    digest.add_argument("--destination-root", type=Path, required=True)
    seal = subparsers.add_parser("seal-manifest")
    seal.add_argument("--manifest", type=Path, required=True)
    seal.add_argument("--destination-root", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    for command in ("stage", "validate", "apply"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--manifest", type=Path, required=True)
        subparser.add_argument("--source-root", type=Path, required=True)
        subparser.add_argument("--destination-root", type=Path, required=True)
        subparser.add_argument("--stage-root", type=Path, required=True)
        if command == "apply":
            subparser.add_argument("--rollback-root", type=Path, required=True)
            subparser.add_argument("--confirm", required=True)
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--manifest", type=Path, required=True)
    rollback.add_argument("--destination-root", type=Path, required=True)
    rollback.add_argument("--rollback-root", type=Path, required=True)
    rollback.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = _read_json(args.manifest, "INSTALL_ATOM_MANIFEST_UNREADABLE")
        if args.command == "digest":
            identity = destination_root_identity(args.destination_root)
            candidate = dict(manifest)
            candidate["destination_root_identity"] = identity
            candidate["manifest_sha256"] = manifest_digest(candidate)
            _validate_manifest(candidate)
            result = {
                "schema": SCHEMA,
                "destination_root_identity": identity,
                "manifest_sha256": candidate["manifest_sha256"],
                "state": "PASS",
            }
        elif args.command == "seal-manifest":
            candidate = seal_manifest(manifest, args.destination_root)
            _write_sealed_manifest(args.output, candidate)
            result = _seal_receipt(
                {
                    "schema": SCHEMA,
                    "destination_root_identity": candidate[
                        "destination_root_identity"
                    ],
                    "manifest_sha256": candidate["manifest_sha256"],
                    "state": "SEALED",
                }
            )
        elif args.command == "stage":
            result = stage_atom(manifest=manifest, source_root=args.source_root, destination_root=args.destination_root, stage_root=args.stage_root)
        elif args.command == "validate":
            result = validate_stage(manifest=manifest, source_root=args.source_root, destination_root=args.destination_root, stage_root=args.stage_root)
        elif args.command == "apply":
            result = apply_atom(manifest=manifest, source_root=args.source_root, destination_root=args.destination_root, stage_root=args.stage_root, rollback_root=args.rollback_root, confirmation=args.confirm)
        else:
            result = rollback_atom(manifest=manifest, destination_root=args.destination_root, rollback_root=args.rollback_root, confirmation=args.confirm)
        print(canonical_json(result))
        return 0
    except (SourceInstallAtomError, OSError) as exc:
        error = str(exc) if isinstance(exc, SourceInstallAtomError) else "INSTALL_ATOM_IO_ERROR"
        print(canonical_json({"error": error, "state": "HOLD"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
