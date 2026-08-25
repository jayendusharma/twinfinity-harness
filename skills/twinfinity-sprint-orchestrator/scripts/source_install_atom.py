#!/usr/bin/env python3
"""Stage, validate, install, or roll back one reviewed source file atom."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any, Iterator


SCHEMA = "twinfinity-source-install-atom/v1"
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
    if not isinstance(value, str) or not value or "\\" in value:
        raise SourceInstallAtomError("INSTALL_ATOM_PATH_INVALID")
    path = Path(value)
    if path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise SourceInstallAtomError("INSTALL_ATOM_PATH_INVALID")
    return path


def _safe_root(path: Path) -> Path:
    if not path.is_absolute():
        raise SourceInstallAtomError("INSTALL_ATOM_ROOT_INVALID")
    path = Path(os.path.abspath(path))
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


def _validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if set(manifest) != {"schema", "manifest_sha256", "atom_id", "source_commit", "entries"}:
        raise SourceInstallAtomError("INSTALL_ATOM_MANIFEST_SCHEMA_INVALID")
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
            or entry["source_mode"] not in {0o600, 0o644, 0o700, 0o755}
            or entry["destination_mode"] not in {0o600, 0o644, 0o700, 0o755}
            or type(entry["destination_uid"]) is not int
            or type(entry["destination_gid"]) is not int
            or not isinstance(prior, dict)
            or set(prior) not in (
                {"state"},
                {"state", "sha256", "mode", "uid", "gid"},
            )
            or prior.get("state") not in {"ABSENT", "PRESENT"}
            or (prior["state"] == "ABSENT" and set(prior) != {"state"})
            or (
                prior["state"] == "PRESENT"
                and (
                    set(prior) != {"state", "sha256", "mode", "uid", "gid"}
                    or not isinstance(prior["sha256"], str)
                    or SHA256.fullmatch(prior["sha256"]) is None
                    or prior["mode"] not in {0o600, 0o644, 0o700, 0o755}
                    or type(prior["uid"]) is not int
                    or type(prior["gid"]) is not int
                )
            )
        ):
            raise SourceInstallAtomError("INSTALL_ATOM_ENTRY_SCHEMA_INVALID")
        seen_sources.add(source.as_posix())
        seen_destinations.add(destination.as_posix())
    return entries


def _validate_prior(destination_root: Path, entry: dict[str, Any]) -> None:
    relative = _relative(entry["destination_path"])
    actual = _safe_file(destination_root, relative, required=False)
    prior = entry["destination_prior"]
    if prior["state"] == "ABSENT":
        if actual is not None:
            raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")
        return
    if actual is None:
        raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")
    metadata = actual.lstat()
    if (
        _file_sha256(actual) != prior["sha256"]
        or stat.S_IMODE(metadata.st_mode) != prior["mode"]
        or metadata.st_uid != prior["uid"]
        or metadata.st_gid != prior["gid"]
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")


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
    if not stage_root.is_absolute() or stage_root.exists() or stage_root.is_symlink():
        raise SourceInstallAtomError("INSTALL_ATOM_STAGE_PATH_INVALID")
    _safe_root(stage_root.parent)
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
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_file_exclusive(target, source.read_bytes(), entry["destination_mode"])
            staged.append({"destination_path": relative.as_posix(), "sha256": _file_sha256(target), "mode": entry["destination_mode"]})
        receipt = {
            "schema": SCHEMA,
            "manifest_sha256": manifest["manifest_sha256"],
            "entries": staged,
            "state": "STAGED",
        }
        _write_file_exclusive(stage_root / STAGE_RECEIPT, canonical_json(receipt).encode("utf-8"), 0o600)
        return receipt
    except Exception:
        shutil.rmtree(stage_root)
        raise


def validate_stage(*, manifest: dict[str, Any], source_root: Path, destination_root: Path, stage_root: Path) -> dict[str, Any]:
    entries = _validate_manifest(manifest)
    source_root = _safe_root(source_root)
    destination_root = _safe_root(destination_root)
    stage_root = _safe_root(stage_root)
    receipt = _read_json(stage_root / STAGE_RECEIPT, "INSTALL_ATOM_STAGE_RECEIPT_INVALID")
    if receipt.get("schema") != SCHEMA or receipt.get("manifest_sha256") != manifest["manifest_sha256"] or receipt.get("state") != "STAGED":
        raise SourceInstallAtomError("INSTALL_ATOM_STAGE_RECEIPT_INVALID")
    observed: list[dict[str, Any]] = []
    for entry in entries:
        _validate_prior(destination_root, entry)
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
    return {
        "manifest_sha256": manifest["manifest_sha256"],
        "rollback_data": [
            {"destination_path": entry["destination_path"], "prior": entry["destination_prior"], "installed_sha256": entry["source_sha256"]}
            for entry in entries
        ],
        "state": "PASS",
    }


@contextmanager
def _destination_lock(root: Path) -> Iterator[None]:
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError as exc:
        raise SourceInstallAtomError("INSTALL_ATOM_LOCK_BUSY") from exc
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _atomic_replace_from(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=False, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.twinfinity-install-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise SourceInstallAtomError("INSTALL_ATOM_TEMP_CONFLICT")
    try:
        _write_file_exclusive(temporary, source.read_bytes(), mode)
        os.replace(temporary, destination)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def _replace_receipt(path: Path, receipt: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        _write_file_exclusive(
            temporary, canonical_json(receipt).encode("utf-8"), 0o600
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def _restore_entries(destination_root: Path, rollback_root: Path, entries: list[dict[str, Any]]) -> None:
    for entry in reversed(entries):
        destination = destination_root / _relative(entry["destination_path"])
        prior = entry["destination_prior"]
        if prior["state"] == "ABSENT":
            if destination.exists() and not destination.is_symlink():
                destination.unlink()
            continue
        backup = _safe_file(rollback_root / "files", _relative(entry["destination_path"]))
        if backup is None or _file_sha256(backup) != prior["sha256"]:
            raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
        _atomic_replace_from(backup, destination, prior["mode"])


def apply_atom(*, manifest: dict[str, Any], source_root: Path, destination_root: Path, stage_root: Path, rollback_root: Path, confirmation: str) -> dict[str, Any]:
    if confirmation != f"INSTALL:{manifest.get('manifest_sha256', '')}":
        raise SourceInstallAtomError("INSTALL_ATOM_CONFIRMATION_REQUIRED")
    entries = _validate_manifest(manifest)
    source_root = _safe_root(source_root)
    destination_root = _safe_root(destination_root)
    validate_stage(manifest=manifest, source_root=source_root, destination_root=destination_root, stage_root=stage_root)
    if not rollback_root.is_absolute() or rollback_root.exists() or rollback_root.is_symlink():
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_PATH_INVALID")
    _safe_root(rollback_root.parent)
    with _destination_lock(destination_root):
        validate_stage(manifest=manifest, source_root=source_root, destination_root=destination_root, stage_root=stage_root)
        _make_private_directory(rollback_root)
        (rollback_root / "files").mkdir(mode=0o700)
        applied: list[dict[str, Any]] = []
        try:
            for entry in entries:
                prior = entry["destination_prior"]
                if prior["state"] == "PRESENT":
                    current = _safe_file(destination_root, _relative(entry["destination_path"]))
                    if current is None:
                        raise SourceInstallAtomError("INSTALL_ATOM_PRIOR_HASH_MISMATCH")
                    backup = rollback_root / "files" / _relative(entry["destination_path"])
                    backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    _write_file_exclusive(backup, current.read_bytes(), prior["mode"])
            receipt = {
                "schema": SCHEMA,
                "manifest_sha256": manifest["manifest_sha256"],
                "entries": [
                    {
                        "destination_path": entry["destination_path"],
                        "destination_prior": entry["destination_prior"],
                        "installed_sha256": entry["source_sha256"],
                        "installed_mode": entry["destination_mode"],
                    }
                    for entry in entries
                ],
                "state": "PREPARED",
            }
            _write_file_exclusive(
                rollback_root / ROLLBACK_RECEIPT,
                canonical_json(receipt).encode("utf-8"),
                0o600,
            )
            for entry in entries:
                staged = _safe_file(stage_root, _relative(entry["destination_path"]))
                if staged is None:
                    raise SourceInstallAtomError("INSTALL_ATOM_STAGE_VALIDATION_FAILED")
                destination = destination_root / _relative(entry["destination_path"])
                if not destination.parent.exists():
                    raise SourceInstallAtomError("INSTALL_ATOM_DESTINATION_PARENT_MISSING")
                _atomic_replace_from(staged, destination, entry["destination_mode"])
                applied.append(entry)
                metadata = destination.lstat()
                if (
                    metadata.st_uid != entry["destination_uid"]
                    or metadata.st_gid != entry["destination_gid"]
                    or stat.S_IMODE(metadata.st_mode) != entry["destination_mode"]
                    or _file_sha256(destination) != entry["source_sha256"]
                ):
                    raise SourceInstallAtomError("INSTALL_ATOM_POSTCONDITION_FAILED")
            receipt["state"] = "INSTALLED"
            _replace_receipt(rollback_root / ROLLBACK_RECEIPT, receipt)
            return receipt
        except Exception:
            _restore_entries(destination_root, rollback_root, applied)
            raise


def rollback_atom(*, manifest: dict[str, Any], destination_root: Path, rollback_root: Path, confirmation: str) -> dict[str, Any]:
    if confirmation != f"ROLLBACK:{manifest.get('manifest_sha256', '')}":
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_CONFIRMATION_REQUIRED")
    entries = _validate_manifest(manifest)
    destination_root = _safe_root(destination_root)
    rollback_root = _safe_root(rollback_root)
    receipt = _read_json(rollback_root / ROLLBACK_RECEIPT, "INSTALL_ATOM_ROLLBACK_DATA_INVALID")
    expected_entries = [
        {
            "destination_path": entry["destination_path"],
            "destination_prior": entry["destination_prior"],
            "installed_sha256": entry["source_sha256"],
            "installed_mode": entry["destination_mode"],
        }
        for entry in entries
    ]
    if (
        receipt.get("schema") != SCHEMA
        or receipt.get("manifest_sha256") != manifest["manifest_sha256"]
        or receipt.get("entries") != expected_entries
        or receipt.get("state") not in {"PREPARED", "INSTALLED"}
    ):
        raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
    with _destination_lock(destination_root):
        for entry in entries:
            relative = _relative(entry["destination_path"])
            current = _safe_file(destination_root, relative, required=False)
            prior = entry["destination_prior"]
            installed = (
                current is not None
                and _file_sha256(current) == entry["source_sha256"]
                and stat.S_IMODE(current.lstat().st_mode)
                == entry["destination_mode"]
            )
            still_prior = prior["state"] == "ABSENT" and current is None
            if prior["state"] == "PRESENT" and current is not None:
                metadata = current.lstat()
                still_prior = (
                    _file_sha256(current) == prior["sha256"]
                    and stat.S_IMODE(metadata.st_mode) == prior["mode"]
                    and metadata.st_uid == prior["uid"]
                    and metadata.st_gid == prior["gid"]
                )
            if not installed and not still_prior:
                raise SourceInstallAtomError("INSTALL_ATOM_INSTALLED_HASH_MISMATCH")
            if prior["state"] == "PRESENT":
                backup = _safe_file(
                    rollback_root / "files", _relative(entry["destination_path"])
                )
                if backup is None or _file_sha256(backup) != prior["sha256"]:
                    raise SourceInstallAtomError("INSTALL_ATOM_ROLLBACK_DATA_INVALID")
        _restore_entries(destination_root, rollback_root, entries)
    return {"manifest_sha256": manifest["manifest_sha256"], "state": "ROLLED_BACK"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest = subparsers.add_parser("digest")
    digest.add_argument("--manifest", type=Path, required=True)
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
            result = {"manifest_sha256": manifest_digest(manifest), "state": "PASS"}
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
