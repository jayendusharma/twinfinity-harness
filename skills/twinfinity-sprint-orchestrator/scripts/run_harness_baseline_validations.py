#!/usr/bin/env python3
"""Run and attest the fixed Twinfinity harness validation baseline."""

from __future__ import annotations

import argparse
import ast
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RUNNER_RELATIVE_PATH = (
    "skills/twinfinity-sprint-orchestrator/scripts/"
    "run_harness_baseline_validations.py"
)
CATALOG_RELATIVE_PATH = (
    "skills/twinfinity-sprint-orchestrator/references/"
    "twinfinity-harness-baseline-catalog-v1.json"
)
CATALOG_SCHEMA = "twinfinity-harness-baseline-catalog/v1"
ROOT_RECEIPT_SCHEMA = "twinfinity-harness-baseline-root-receipt/v1"
PAIR_RECEIPT_SCHEMA = "twinfinity-harness-baseline-pair-receipt/v1"
INSTALL_MANIFEST_SCHEMA = "twinfinity-source-install-atom/v2"
DESTINATION_ROOT_IDENTITY_SCHEMA = "twinfinity-destination-root-identity/v1"
INSTALL_STAGE_RECEIPT = ".twinfinity-source-install-stage.json"
TRUSTED_BASE_REF = "refs/remotes/origin/main"
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ROOT_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
CATALOG_KEYS = {
    "schema",
    "catalog_version",
    "entry_timeout_seconds",
    "maximum_output_bytes",
    "output_completeness_required",
    "entries",
    "baseline_triggers",
    "gate_control_paths",
}
ENTRY_KEYS = {
    "id",
    "kind",
    "executable",
    "working_directory",
    "arguments",
}
TRIGGER_KEYS = {"kind", "value"}
QUICK_VALIDATOR = "skills/.system/skill-creator/scripts/quick_validate.py"
REGISTRY_ARGUMENTS = (
    "skills/twinfinity-sprint-orchestrator/scripts/executor_registry.py",
    "--config",
    "skills/twinfinity-sprint-orchestrator/references/"
    "twinfinity-executor-registry.toml",
    "--profile-root",
    "skills/twinfinity-sprint-orchestrator/references",
    "audit-config",
)
REQUIRED_SELF_TRIGGERS = {
    ("prefix", ".github/workflows/"),
    ("prefix", "skills/.system/skill-creator/"),
    ("prefix", "skills/twinfinity-skill-governor/"),
    ("path", CATALOG_RELATIVE_PATH),
    ("path", RUNNER_RELATIVE_PATH),
    (
        "path",
        "skills/twinfinity-sprint-orchestrator/scripts/prepush_control.py",
    ),
    (
        "path",
        "skills/twinfinity-sprint-orchestrator/scripts/executor_registry.py",
    ),
    (
        "path",
        "skills/twinfinity-sprint-orchestrator/references/"
        "twinfinity-executor-registry.toml",
    ),
}
REQUIRED_CONTROL_PATHS = {
    CATALOG_RELATIVE_PATH,
    RUNNER_RELATIVE_PATH,
    QUICK_VALIDATOR,
    "skills/twinfinity-sprint-orchestrator/scripts/prepush_control.py",
    "skills/twinfinity-sprint-orchestrator/scripts/executor_registry.py",
    "skills/twinfinity-sprint-orchestrator/references/"
    "twinfinity-executor-registry.toml",
    ".github/workflows/validate-skills.yml",
}
SOURCE_ROOT_KINDS = {"accepted-base", "source-candidate"}
INSTALL_ROOT_KINDS = {"staged-install-atom", "installed-runtime"}
INSTALL_MANIFEST_KEYS = {
    "schema",
    "manifest_sha256",
    "atom_id",
    "source_commit",
    "destination_root_identity",
    "entries",
}
INSTALL_ENTRY_KEYS = {
    "source_path",
    "destination_path",
    "source_sha256",
    "source_mode",
    "destination_mode",
    "destination_uid",
    "destination_gid",
    "destination_prior",
}
ROOT_RECEIPT_KEYS = {
    "schema",
    "verdict",
    "target_root",
    "tool_root",
    "runner",
    "catalog",
    "result_count",
    "results",
}
TARGET_ROOT_KEYS = {
    "kind",
    "identity",
    "byte_manifest_scope",
    "byte_manifest_sha256",
    "install_manifest_sha256",
    "install_manifest_raw_sha256",
    "filesystem_identity_sha256",
    "installer_state_evidence_sha256",
}
TOOL_ROOT_KEYS = {
    "kind",
    "identity",
    "byte_manifest_scope",
    "byte_manifest_sha256",
}
RUNNER_RECEIPT_KEYS = {
    "relative_path",
    "target_runner_sha256",
    "tool_runner_sha256",
    "engine_runner_sha256",
    "engine_authority",
}
CATALOG_RECEIPT_KEYS = {
    "schema",
    "version",
    "raw_sha256",
    "canonical_sha256",
    "command_manifest_sha256",
    "target_raw_sha256",
}
RESULT_RECEIPT_KEYS = {
    "id",
    "kind",
    "working_directory",
    "argv",
    "argv_root_roles",
    "return_code",
    "timeout_seconds",
    "timed_out",
    "output_complete",
    "stdout_bytes",
    "stdout_sha256",
    "stderr_bytes",
    "stderr_sha256",
}
RECEIPT_OBSERVATION_KEYS = {
    "label",
    "return_code",
    "timeout_seconds",
    "timed_out",
    "output_complete",
    "stdout_bytes",
    "stdout_sha256",
    "stderr_bytes",
    "stderr_sha256",
    "runner_sha256",
    "protocol",
    "root_receipt_sha256",
}
LEGACY_OBSERVATION_KEYS = RECEIPT_OBSERVATION_KEYS - {"root_receipt_sha256"}
PROCESS_READ_CHUNK = 64 * 1024
ROOT_GATE_OVERHEAD_SECONDS = 360
LEGACY_BASE_TIMEOUT_SECONDS = 600
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37


class BaselineError(RuntimeError):
    """A closed baseline invariant failed."""


class _BoundedProcessError(RuntimeError):
    def __init__(self, kind: str, stdout: bytes, stderr: bytes) -> None:
        super().__init__(kind)
        self.kind = kind
        self.stdout = stdout
        self.stderr = stderr


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _git_object_sha1(value: bytes) -> str:
    header = f"blob {len(value)}\0".encode("ascii")
    return hashlib.sha1(header + value, usedforsecurity=False).hexdigest()


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BaselineError("BASELINE_CATALOG_DUPLICATE_KEY")
        result[key] = value
    return result


def _relative_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise BaselineError(f"BASELINE_CATALOG_{field}_INVALID")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or "." in candidate.parts
        or candidate.as_posix() != value
    ):
        raise BaselineError(f"BASELINE_CATALOG_{field}_INVALID")
    return candidate.as_posix()


def _validated_root(root: Path) -> Path:
    lexical = Path(os.path.abspath(root))
    try:
        resolved = lexical.resolve(strict=True)
        status = lexical.lstat()
    except OSError as exc:
        raise BaselineError("BASELINE_ROOT_UNSAFE") from exc
    if lexical != resolved or not stat.S_ISDIR(status.st_mode):
        raise BaselineError("BASELINE_ROOT_UNSAFE")
    return resolved


DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _read_relative_regular(
    root: Path,
    relative: str,
    *,
    error: str,
    maximum_bytes: int | None = None,
) -> tuple[bytes, os.stat_result]:
    """Read one root-relative file without following any path component."""

    normalized = _relative_path(relative, field="FILE")
    descriptor: int | None = None
    try:
        descriptor = os.open(root, DIRECTORY_FLAGS)
        root_status = os.fstat(descriptor)
        if not stat.S_ISDIR(root_status.st_mode):
            raise OSError(errno.ENOTDIR, "root is not a directory")
        parts = PurePosixPath(normalized).parts
        for part in parts[:-1]:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.ENOTDIR, "component is not a directory")
        leaf = os.open(parts[-1], FILE_FLAGS, dir_fd=descriptor)
    except (OSError, BaselineError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise BaselineError(error) from exc
    os.close(descriptor)
    try:
        metadata = os.fstat(leaf)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BaselineError(error)
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(leaf, PROCESS_READ_CHUNK)
            if not chunk:
                break
            observed += len(chunk)
            if maximum_bytes is not None and observed > maximum_bytes:
                raise BaselineError(error)
            chunks.append(chunk)
        return b"".join(chunks), metadata
    except OSError as exc:
        raise BaselineError(error) from exc
    finally:
        os.close(leaf)


def _read_external_regular(
    path: Path, *, error: str, maximum_bytes: int
) -> tuple[bytes, os.stat_result]:
    lexical = Path(os.path.abspath(path))
    try:
        parent = lexical.parent.resolve(strict=True)
    except OSError as exc:
        raise BaselineError(error) from exc
    if parent != lexical.parent:
        raise BaselineError(error)
    return _read_relative_regular(
        parent, lexical.name, error=error, maximum_bytes=maximum_bytes
    )


@dataclass(frozen=True)
class CatalogEntry:
    entry_id: str
    kind: str
    executable: str
    working_directory: str
    arguments: tuple[str, ...]

    def declared_argv(self) -> tuple[str, ...]:
        return (self.executable, *self.arguments)

    def argv_root_roles(self) -> tuple[str, ...]:
        if self.kind == "skill-validator":
            return ("runtime", "tool", "target")
        if self.kind == "executor-registry-audit":
            return (
                "runtime",
                "tool",
                "literal",
                "target",
                "literal",
                "target",
                "literal",
            )
        raise BaselineError("BASELINE_CATALOG_ENTRY_KIND_INVALID")


@dataclass(frozen=True)
class BaselineCatalog:
    version: int
    entry_timeout_seconds: int
    maximum_output_bytes: int
    entries: tuple[CatalogEntry, ...]
    triggers: tuple[tuple[str, str], ...]
    gate_control_paths: tuple[str, ...]
    raw_sha256: str
    canonical_sha256: str

    @property
    def skill_roots(self) -> tuple[str, ...]:
        return tuple(entry.arguments[1] for entry in self.entries[:-1])

    @property
    def command_manifest_sha256(self) -> str:
        return digest_json(
            [
                {
                    "id": entry.entry_id,
                    "kind": entry.kind,
                    "working_directory": entry.working_directory,
                    "argv": list(entry.declared_argv()),
                    "argv_root_roles": list(entry.argv_root_roles()),
                }
                for entry in self.entries
            ]
        )

    @property
    def root_execution_budget_seconds(self) -> int:
        return (
            len(self.entries) * self.entry_timeout_seconds
            + ROOT_GATE_OVERHEAD_SECONDS
        )

    @property
    def pair_execution_budget_seconds(self) -> int:
        return (
            LEGACY_BASE_TIMEOUT_SECONDS
            + 3 * self.root_execution_budget_seconds
        )


def load_catalog(
    root: Path, *, relative_path: str = CATALOG_RELATIVE_PATH
) -> BaselineCatalog:
    root = _validated_root(root)
    raw, _status = _read_relative_regular(
        root,
        relative_path,
        error="BASELINE_CATALOG_MISSING",
        maximum_bytes=1024 * 1024,
    )
    try:
        payload = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BaselineError("BASELINE_CATALOG_INVALID_JSON") from exc
    if not isinstance(payload, dict) or set(payload) != CATALOG_KEYS:
        raise BaselineError("BASELINE_CATALOG_SCHEMA_INVALID")
    if (
        payload["schema"] != CATALOG_SCHEMA
        or type(payload["catalog_version"]) is not int
        or payload["catalog_version"] != 1
    ):
        raise BaselineError("BASELINE_CATALOG_VERSION_UNSUPPORTED")
    timeout = payload["entry_timeout_seconds"]
    output_limit = payload["maximum_output_bytes"]
    if (
        type(timeout) is not int
        or timeout < 1
        or timeout > 600
        or type(output_limit) is not int
        or output_limit < 1024
        or output_limit > 16 * 1024 * 1024
        or payload["output_completeness_required"] is not True
    ):
        raise BaselineError("BASELINE_CATALOG_LIMIT_INVALID")

    raw_entries = payload["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) != 12:
        raise BaselineError("BASELINE_CATALOG_MEMBERSHIP_INVALID")
    entries: list[CatalogEntry] = []
    seen_ids: set[str] = set()
    seen_skill_roots: set[str] = set()
    for position, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, dict) or set(raw_entry) != ENTRY_KEYS:
            raise BaselineError("BASELINE_CATALOG_ENTRY_SCHEMA_INVALID")
        entry_id = raw_entry["id"]
        kind = raw_entry["kind"]
        executable = raw_entry["executable"]
        working_directory = raw_entry["working_directory"]
        arguments = raw_entry["arguments"]
        if (
            type(entry_id) is not str
            or not entry_id
            or entry_id in seen_ids
            or executable != "{python}"
            or working_directory != "."
            or type(arguments) is not list
            or not all(type(value) is str and value for value in arguments)
        ):
            raise BaselineError("BASELINE_CATALOG_ENTRY_INVALID")
        seen_ids.add(entry_id)
        normalized_arguments = tuple(
            _relative_path(value, field="ARGUMENT")
            if not value.startswith("--") and value != "audit-config"
            else value
            for value in arguments
        )
        if position < 11:
            if (
                kind != "skill-validator"
                or len(normalized_arguments) != 2
                or normalized_arguments[0] != QUICK_VALIDATOR
                or not entry_id.startswith("skill:")
                or entry_id != f"skill:{PurePosixPath(normalized_arguments[1]).name}"
                or normalized_arguments[1] in seen_skill_roots
            ):
                raise BaselineError("BASELINE_CATALOG_SKILL_ENTRY_INVALID")
            seen_skill_roots.add(normalized_arguments[1])
        elif (
            kind != "executor-registry-audit"
            or entry_id != "registry:audit-config"
            or normalized_arguments != REGISTRY_ARGUMENTS
        ):
            raise BaselineError("BASELINE_CATALOG_REGISTRY_ENTRY_INVALID")
        entries.append(
            CatalogEntry(
                entry_id=entry_id,
                kind=kind,
                executable=executable,
                working_directory=working_directory,
                arguments=normalized_arguments,
            )
        )

    raw_triggers = payload["baseline_triggers"]
    if type(raw_triggers) is not list or not raw_triggers:
        raise BaselineError("BASELINE_CATALOG_TRIGGER_INVALID")
    triggers: list[tuple[str, str]] = []
    for raw_trigger in raw_triggers:
        if not isinstance(raw_trigger, dict) or set(raw_trigger) != TRIGGER_KEYS:
            raise BaselineError("BASELINE_CATALOG_TRIGGER_INVALID")
        kind = raw_trigger["kind"]
        raw_value = raw_trigger["value"]
        if kind == "prefix" and type(raw_value) is str and raw_value.endswith("/"):
            value = _relative_path(raw_value[:-1], field="TRIGGER") + "/"
        else:
            value = _relative_path(raw_value, field="TRIGGER")
        if kind not in {"path", "prefix"} or (kind, value) in triggers:
            raise BaselineError("BASELINE_CATALOG_TRIGGER_INVALID")
        if kind == "prefix" and not value.endswith("/"):
            raise BaselineError("BASELINE_CATALOG_TRIGGER_INVALID")
        triggers.append((kind, value))
    if not REQUIRED_SELF_TRIGGERS.issubset(set(triggers)):
        raise BaselineError("BASELINE_CATALOG_SELF_TRIGGER_INCOMPLETE")

    raw_control_paths = payload["gate_control_paths"]
    if (
        type(raw_control_paths) is not list
        or not raw_control_paths
        or not all(type(value) is str for value in raw_control_paths)
    ):
        raise BaselineError("BASELINE_CATALOG_CONTROL_PATH_INVALID")
    control_paths = tuple(
        _relative_path(value, field="CONTROL_PATH") for value in raw_control_paths
    )
    if len(control_paths) != len(set(control_paths)) or not REQUIRED_CONTROL_PATHS.issubset(
        set(control_paths)
    ):
        raise BaselineError("BASELINE_CATALOG_CONTROL_PATH_INVALID")

    return BaselineCatalog(
        version=1,
        entry_timeout_seconds=timeout,
        maximum_output_bytes=output_limit,
        entries=tuple(entries),
        triggers=tuple(triggers),
        gate_control_paths=control_paths,
        raw_sha256=sha256_bytes(raw),
        canonical_sha256=digest_json(payload),
    )


def catalog_matches_path(catalog: BaselineCatalog, relative_path: str) -> bool:
    return any(
        relative_path == value if kind == "path" else relative_path.startswith(value)
        for kind, value in catalog.triggers
    )


def catalog_command(
    entry: CatalogEntry,
    python_executable: str,
    *,
    root: Path | None = None,
) -> tuple[str, ...]:
    arguments = tuple(
        os.fspath(root / value)
        if root is not None and value.startswith(("skills/", ".github/"))
        else value
        for value in entry.arguments
    )
    return (python_executable, *arguments)


def catalog_execution_command(
    entry: CatalogEntry,
    python_executable: str,
    *,
    tool_root: Path,
    target_root: Path,
    target_paths: dict[str, str] | None = None,
) -> tuple[str, ...]:
    roles = entry.argv_root_roles()[1:]
    arguments: list[str] = []
    for value, role in zip(entry.arguments, roles, strict=True):
        if role == "tool":
            arguments.append(os.fspath(tool_root / value))
        elif role == "target":
            target_relative = value if target_paths is None else target_paths.get(value)
            if target_relative is None:
                raise BaselineError("BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE")
            arguments.append(os.fspath(target_root / target_relative))
        elif role == "literal":
            arguments.append(value)
        else:
            raise BaselineError("BASELINE_CATALOG_ARGUMENT_ROLE_INVALID")
    return (python_executable, *arguments)


@dataclass(frozen=True)
class InstallManifest:
    atom_id: str
    source_commit: str
    manifest_sha256: str
    raw_sha256: str
    entries: tuple[dict[str, Any], ...]
    destination_root_identity: dict[str, str] | None = None


def _install_manifest_digest(payload: dict[str, Any]) -> str:
    without_digest = {
        key: value for key, value in payload.items() if key != "manifest_sha256"
    }
    serialized = json.dumps(
        without_digest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256_bytes(serialized.encode("utf-8"))


def _install_receipt_digest(payload: dict[str, Any]) -> str:
    without_digest = {
        key: value for key, value in payload.items() if key != "receipt_sha256"
    }
    return digest_json(without_digest)


def _validate_destination_root_identity(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "canonical_path_sha256",
        "filesystem_identity_sha256",
        "identity_sha256",
    }:
        raise BaselineError("BASELINE_INSTALL_ROOT_IDENTITY_INVALID")
    identity = dict(value)
    if (
        identity["schema"] != DESTINATION_ROOT_IDENTITY_SCHEMA
        or any(
            type(identity[key]) is not str or not SHA256.fullmatch(identity[key])
            for key in (
                "canonical_path_sha256",
                "filesystem_identity_sha256",
                "identity_sha256",
            )
        )
        or digest_json(
            {
                "schema": identity["schema"],
                "canonical_path_sha256": identity["canonical_path_sha256"],
                "filesystem_identity_sha256": identity[
                    "filesystem_identity_sha256"
                ],
            }
        )
        != identity["identity_sha256"]
    ):
        raise BaselineError("BASELINE_INSTALL_ROOT_IDENTITY_INVALID")
    return identity


def load_install_manifest(path: Path) -> InstallManifest:
    raw, _metadata = _read_external_regular(
        path, error="BASELINE_INSTALL_MANIFEST_UNSAFE", maximum_bytes=16 * 1024 * 1024
    )
    try:
        payload = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, BaselineError) as exc:
        raise BaselineError("BASELINE_INSTALL_MANIFEST_INVALID") from exc
    if not isinstance(payload, dict) or set(payload) != INSTALL_MANIFEST_KEYS:
        raise BaselineError("BASELINE_INSTALL_MANIFEST_INVALID")
    atom_id = payload["atom_id"]
    source_commit = payload["source_commit"]
    manifest_sha256 = payload["manifest_sha256"]
    destination_root_identity = _validate_destination_root_identity(
        payload["destination_root_identity"]
    )
    entries = payload["entries"]
    if (
        payload["schema"] != INSTALL_MANIFEST_SCHEMA
        or type(atom_id) is not str
        or not ROOT_IDENTITY.fullmatch(atom_id)
        or type(source_commit) is not str
        or not GIT_SHA.fullmatch(source_commit)
        or type(manifest_sha256) is not str
        or not SHA256.fullmatch(manifest_sha256)
        or _install_manifest_digest(payload) != manifest_sha256
        or type(entries) is not list
        or not entries
    ):
        raise BaselineError("BASELINE_INSTALL_MANIFEST_INVALID")
    normalized: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    seen_destinations: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != INSTALL_ENTRY_KEYS:
            raise BaselineError("BASELINE_INSTALL_MANIFEST_ENTRY_INVALID")
        source_path = _relative_path(
            entry.get("source_path"), field="INSTALL_SOURCE_PATH"
        )
        destination_path = _relative_path(
            entry.get("destination_path"), field="INSTALL_DESTINATION_PATH"
        )
        prior = entry.get("destination_prior")
        if (
            source_path in seen_sources
            or destination_path in seen_destinations
            or type(entry.get("source_sha256")) is not str
            or not SHA256.fullmatch(entry["source_sha256"])
            or type(entry.get("source_mode")) is not int
            or entry["source_mode"] not in {0o600, 0o644, 0o700, 0o755}
            or type(entry.get("destination_mode")) is not int
            or entry["destination_mode"] not in {0o600, 0o644, 0o700, 0o755}
            or type(entry.get("destination_uid")) is not int
            or type(entry.get("destination_gid")) is not int
            or entry["destination_uid"] != os.getuid()
            or entry["destination_gid"] != os.getgid()
            or not isinstance(prior, dict)
            or prior.get("state") not in {"ABSENT", "PRESENT"}
        ):
            raise BaselineError("BASELINE_INSTALL_MANIFEST_ENTRY_INVALID")
        if prior["state"] == "ABSENT":
            if set(prior) != {"state"}:
                raise BaselineError("BASELINE_INSTALL_MANIFEST_ENTRY_INVALID")
        elif (
            set(prior) != {"state", "sha256", "mode", "uid", "gid"}
            or type(prior.get("sha256")) is not str
            or not SHA256.fullmatch(prior["sha256"])
            or type(prior.get("mode")) is not int
            or type(prior.get("uid")) is not int
            or type(prior.get("gid")) is not int
            or prior["mode"] not in {0o600, 0o644, 0o700, 0o755}
            or prior["uid"] != os.getuid()
            or prior["gid"] != os.getgid()
        ):
            raise BaselineError("BASELINE_INSTALL_MANIFEST_ENTRY_INVALID")
        seen_sources.add(source_path)
        seen_destinations.add(destination_path)
        normalized.append(
            {
                **entry,
                "source_path": source_path,
                "destination_path": destination_path,
            }
        )
    return InstallManifest(
        atom_id=atom_id,
        source_commit=source_commit,
        manifest_sha256=manifest_sha256,
        raw_sha256=sha256_bytes(raw),
        entries=tuple(normalized),
        destination_root_identity=destination_root_identity,
    )


def _directory_identity(path: Path) -> dict[str, int]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BaselineError("BASELINE_INSTALL_TARGET_IDENTITY_INVALID") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise BaselineError("BASELINE_INSTALL_TARGET_IDENTITY_INVALID")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "links": metadata.st_nlink,
    }


def _destination_root_identity(root: Path) -> dict[str, str]:
    root = _validated_root(root)
    metadata = _directory_identity(root)
    identity = {
        "schema": DESTINATION_ROOT_IDENTITY_SCHEMA,
        "canonical_path_sha256": sha256_bytes(os.fsencode(os.fspath(root))),
        "filesystem_identity_sha256": digest_json(
            {
                "device": metadata["device"],
                "inode": metadata["inode"],
                "mode": metadata["mode"],
                "uid": metadata["uid"],
                "gid": metadata["gid"],
            }
        ),
    }
    identity["identity_sha256"] = digest_json(identity)
    return identity


def _require_manifest_destination_root_identity(
    manifest: InstallManifest, target_root: Path
) -> dict[str, str]:
    expected = _validate_destination_root_identity(
        manifest.destination_root_identity
    )
    if _destination_root_identity(target_root) != expected:
        raise BaselineError("BASELINE_INSTALL_ROOT_IDENTITY_MISMATCH")
    return expected


def _target_filesystem_identity_sha256(root: Path) -> str:
    return digest_json(
        {
            "resolved_path_sha256": sha256_bytes(os.fsencode(os.fspath(root))),
            "root": _directory_identity(root),
        }
    )


def _destination_parent_identity(
    target_root: Path, destination_path: str
) -> list[dict[str, int]]:
    relative = PurePosixPath(
        _relative_path(destination_path, field="INSTALL_DESTINATION_PATH")
    )
    current = target_root
    identities = [_directory_identity(current)]
    for component in relative.parts[:-1]:
        current /= component
        try:
            if current.resolve(strict=True) != Path(os.path.abspath(current)):
                raise OSError(errno.ELOOP, "directory identity escaped target")
        except OSError as exc:
            raise BaselineError(
                "BASELINE_INSTALL_TARGET_IDENTITY_INVALID"
            ) from exc
        identities.append(_directory_identity(current))
    return identities


def _verify_installer_state_evidence(
    target_root: Path,
    root_kind: str,
    manifest: InstallManifest,
    evidence_path: Path,
) -> tuple[str, str]:
    target_root = _validated_root(target_root)
    destination_root_identity = _require_manifest_destination_root_identity(
        manifest, target_root
    )
    evidence_lexical = Path(os.path.abspath(evidence_path))
    if root_kind == "staged-install-atom":
        expected_evidence = target_root / INSTALL_STAGE_RECEIPT
        if evidence_lexical != expected_evidence:
            raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH")
    elif root_kind == "installed-runtime":
        try:
            (target_root / INSTALL_STAGE_RECEIPT).lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise BaselineError(
                "BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH"
            ) from exc
        else:
            raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH")
        try:
            evidence_lexical.relative_to(target_root)
        except ValueError:
            pass
        else:
            raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH")
    else:
        raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_UNEXPECTED")
    raw, metadata = _read_external_regular(
        evidence_lexical,
        error="BASELINE_INSTALL_STATE_EVIDENCE_INVALID",
        maximum_bytes=16 * 1024 * 1024,
    )
    if (
        metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_INVALID")
    try:
        payload = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, BaselineError) as exc:
        raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_INVALID") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "manifest_sha256",
        "destination_root_identity",
        "entries",
        "state",
        "receipt_sha256",
    }:
        raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_INVALID")
    if (
        type(payload["receipt_sha256"]) is not str
        or not SHA256.fullmatch(payload["receipt_sha256"])
        or _install_receipt_digest(payload) != payload["receipt_sha256"]
    ):
        raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_INVALID")
    if root_kind == "staged-install-atom":
        expected_entries = [
            {
                "destination_path": entry["destination_path"],
                "sha256": entry["source_sha256"],
                "mode": entry["destination_mode"],
            }
            for entry in manifest.entries
        ]
        expected_state = "STAGED"
    else:
        expected_entries = [
            {
                "destination_path": entry["destination_path"],
                "destination_prior": entry["destination_prior"],
                "installed_sha256": entry["source_sha256"],
                "installed_mode": entry["destination_mode"],
                "installed_uid": entry["destination_uid"],
                "installed_gid": entry["destination_gid"],
                "destination_parent_identity": _destination_parent_identity(
                    target_root, entry["destination_path"]
                ),
            }
            for entry in manifest.entries
        ]
        expected_state = "INSTALLED"
    if payload != {
        "schema": INSTALL_MANIFEST_SCHEMA,
        "manifest_sha256": manifest.manifest_sha256,
        "destination_root_identity": destination_root_identity,
        "entries": expected_entries,
        "state": expected_state,
        "receipt_sha256": payload["receipt_sha256"],
    }:
        raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH")
    return sha256_bytes(raw), _target_filesystem_identity_sha256(target_root)


def _environment(temp_root: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(temp_root),
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": os.fspath(temp_root / "pycache"),
        "TMPDIR": os.fspath(temp_root),
    }


def _git_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git(root: Path, *arguments: str, binary: bool = False) -> str | bytes:
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-C",
            os.fspath(root),
            *arguments,
        ],
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if result.returncode != 0:
        raise BaselineError("BASELINE_GIT_PRECONDITION_FAILED")
    if binary:
        return result.stdout
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise BaselineError("BASELINE_GIT_OUTPUT_INVALID") from exc


def _candidate_head(root: Path, base_sha: str) -> str:
    head = _git(root, "rev-parse", "HEAD")
    if not isinstance(head, str) or not GIT_SHA.fullmatch(head):
        raise BaselineError("BASELINE_CANDIDATE_HEAD_INVALID")
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            os.fspath(root),
            "merge-base",
            "--is-ancestor",
            base_sha,
            head,
        ],
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if result.returncode != 0:
        raise BaselineError("BASELINE_BASE_NOT_ANCESTOR")
    return head


def _derived_pair_git_identity(
    repository_root: Path,
    expected_base_sha: str,
    expected_candidate_head: str,
) -> dict[str, str]:
    repository_root = _validated_root(repository_root)
    trusted_base = _git(
        repository_root, "rev-parse", f"{TRUSTED_BASE_REF}^{{commit}}"
    )
    candidate_head = _git(repository_root, "rev-parse", "HEAD^{commit}")
    if (
        not isinstance(trusted_base, str)
        or not isinstance(candidate_head, str)
        or trusted_base != expected_base_sha
        or candidate_head != expected_candidate_head
        or trusted_base == candidate_head
    ):
        raise BaselineError("BASELINE_GIT_IDENTITY_MISMATCH")
    ancestry = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            os.fspath(repository_root),
            "merge-base",
            "--is-ancestor",
            trusted_base,
            candidate_head,
        ],
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if ancestry.returncode != 0:
        raise BaselineError("BASELINE_GIT_IDENTITY_MISMATCH")
    base_runner = _git(
        repository_root,
        "show",
        f"{trusted_base}:{RUNNER_RELATIVE_PATH}",
        binary=True,
    )
    candidate_runner = _git(
        repository_root,
        "show",
        f"{candidate_head}:{RUNNER_RELATIVE_PATH}",
        binary=True,
    )
    assert isinstance(base_runner, bytes) and isinstance(candidate_runner, bytes)
    identity = {
        "trusted_base_ref": TRUSTED_BASE_REF,
        "trusted_base_sha": trusted_base,
        "trusted_base_tree": str(
            _git(repository_root, "rev-parse", f"{trusted_base}^{{tree}}")
        ),
        "trusted_base_runner_blob": str(
            _git(repository_root, "rev-parse", f"{trusted_base}:{RUNNER_RELATIVE_PATH}")
        ),
        "trusted_base_runner_sha256": sha256_bytes(base_runner),
        "candidate_head_sha": candidate_head,
        "candidate_tree": str(
            _git(repository_root, "rev-parse", f"{candidate_head}^{{tree}}")
        ),
        "candidate_runner_blob": str(
            _git(
                repository_root,
                "rev-parse",
                f"{candidate_head}:{RUNNER_RELATIVE_PATH}",
            )
        ),
        "candidate_runner_sha256": sha256_bytes(candidate_runner),
    }
    for field, value in identity.items():
        if field == "trusted_base_ref":
            if value != TRUSTED_BASE_REF:
                raise BaselineError("BASELINE_GIT_IDENTITY_MISMATCH")
        elif field.endswith("sha256"):
            if not SHA256.fullmatch(value):
                raise BaselineError("BASELINE_GIT_IDENTITY_MISMATCH")
        elif not GIT_SHA.fullmatch(value):
            raise BaselineError("BASELINE_GIT_IDENTITY_MISMATCH")
    return identity


def _extract_commit_tree(commit_sha: str, temp_root: Path, label: str) -> Path:
    if not GIT_SHA.fullmatch(commit_sha) or not re.fullmatch(r"[a-z][a-z0-9-]*", label):
        raise BaselineError("BASELINE_BASE_SHA_INVALID")
    extracted = temp_root / label
    prior_umask = os.umask(0o022)
    try:
        _git(
            temp_root,
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--no-checkout",
            os.fspath(REPOSITORY_ROOT),
            os.fspath(extracted),
        )
        _git(extracted, "checkout", "--quiet", "--detach", commit_sha)
    except BaselineError as exc:
        raise BaselineError("BASELINE_ARCHIVE_INVALID") from exc
    finally:
        os.umask(prior_umask)
    return extracted


def _extract_base_tree(base_sha: str, temp_root: Path) -> Path:
    return _extract_commit_tree(base_sha, temp_root, "accepted-base")


def _iter_root_files(root: Path) -> Iterable[tuple[str, Path]]:
    root = _validated_root(root)
    paths = sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix())
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise BaselineError("BASELINE_ROOT_SYMLINK")
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise BaselineError("BASELINE_ROOT_FILE_UNSAFE")
        yield relative, path


def root_byte_manifest_sha256(root: Path) -> str:
    entries: list[dict[str, Any]] = []
    for relative, _path in _iter_root_files(root):
        contents, metadata = _read_relative_regular(
            root, relative, error="BASELINE_ROOT_FILE_UNSAFE"
        )
        entries.append(
            {
                "path": relative,
                "mode": stat.S_IMODE(metadata.st_mode),
                "sha256": sha256_bytes(contents),
            }
        )
    return digest_json(entries)


def _git_commit_byte_manifest_sha256(
    repository_root: Path, commit_sha: str
) -> str:
    raw = _git(
        repository_root,
        "ls-tree",
        "-rz",
        "--full-tree",
        "-r",
        commit_sha,
        binary=True,
    )
    assert isinstance(raw, bytes)
    entries: list[dict[str, Any]] = []
    try:
        for record in (value for value in raw.split(b"\0") if value):
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8")
            _relative_path(relative, field="GIT_TREE_PATH")
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise ValueError
            contents = _git(
                repository_root, "cat-file", "blob", object_id, binary=True
            )
            assert isinstance(contents, bytes)
            entries.append(
                {
                    "path": relative,
                    "mode": int(mode[-3:], 8),
                    "sha256": sha256_bytes(contents),
                }
            )
    except (UnicodeDecodeError, ValueError, BaselineError) as exc:
        raise BaselineError("BASELINE_GIT_TREE_UNSUPPORTED") from exc
    return digest_json(entries)


def _assert_exact_commit_root(
    root: Path,
    commit_sha: str,
    *,
    repository_root: Path | None = None,
) -> None:
    if not GIT_SHA.fullmatch(commit_sha):
        raise BaselineError("BASELINE_SOURCE_IDENTITY_INVALID")
    git_root = root if repository_root is None else repository_root
    raw = _git(
        git_root, "ls-tree", "-rz", "--full-tree", commit_sha, binary=True
    )
    assert isinstance(raw, bytes)
    expected: dict[str, tuple[str, str]] = {}
    try:
        for record in (record for record in raw.split(b"\0") if record):
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8")
            _relative_path(relative, field="GIT_TREE_PATH")
            if (
                kind != "blob"
                or mode not in {"100644", "100755"}
                or not GIT_SHA.fullmatch(object_id)
                or relative in expected
            ):
                raise ValueError
            expected[relative] = (mode, object_id)
    except (UnicodeDecodeError, ValueError, BaselineError) as exc:
        raise BaselineError("BASELINE_GIT_TREE_UNSUPPORTED") from exc

    observed: set[str] = set()
    for relative, _path in _iter_root_files(root):
        observed.add(relative)
        expected_value = expected.get(relative)
        if expected_value is None:
            raise BaselineError("BASELINE_CANDIDATE_NOT_CLEAN")
        contents, metadata = _read_relative_regular(
            root, relative, error="BASELINE_ROOT_FILE_UNSAFE"
        )
        expected_mode, expected_object = expected_value
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            mode != int(expected_mode[-3:], 8)
            or _git_object_sha1(contents) != expected_object
        ):
            raise BaselineError("BASELINE_CANDIDATE_NOT_CLEAN")
    if observed != set(expected):
        raise BaselineError("BASELINE_CANDIDATE_NOT_CLEAN")


def _required_target_paths(catalog: BaselineCatalog) -> set[str]:
    paths = {RUNNER_RELATIVE_PATH, CATALOG_RELATIVE_PATH, QUICK_VALIDATOR}
    for entry in catalog.entries:
        for value in entry.arguments:
            if value.startswith(("skills/", ".github/")):
                paths.add(value)
    return paths


def _required_target_files(root: Path, catalog: BaselineCatalog) -> set[str]:
    required: set[str] = set()
    for relative in sorted(_required_target_paths(catalog)):
        path = root / relative
        try:
            resolved = path.resolve(strict=True)
            status = path.lstat()
        except OSError as exc:
            raise BaselineError("BASELINE_ENTRY_INPUT_MISSING") from exc
        if resolved != Path(os.path.abspath(path)) or stat.S_ISLNK(status.st_mode):
            raise BaselineError("BASELINE_ENTRY_INPUT_UNSAFE")
        if stat.S_ISREG(status.st_mode):
            required.add(relative)
            continue
        if not stat.S_ISDIR(status.st_mode):
            raise BaselineError("BASELINE_ENTRY_INPUT_UNSAFE")
        for child in sorted(
            path.rglob("*"), key=lambda value: value.relative_to(root).as_posix()
        ):
            child_relative = child.relative_to(root).as_posix()
            child_status = child.lstat()
            if stat.S_ISLNK(child_status.st_mode):
                raise BaselineError("BASELINE_ENTRY_INPUT_UNSAFE")
            if stat.S_ISDIR(child_status.st_mode):
                continue
            if "__pycache__" in child.relative_to(path).parts:
                continue
            if not stat.S_ISREG(child_status.st_mode) or child_status.st_nlink != 1:
                raise BaselineError("BASELINE_ENTRY_INPUT_UNSAFE")
            required.add(child_relative)
    return required


def _install_manifest_byte_manifest(
    tool_root: Path,
    target_root: Path,
    catalog: BaselineCatalog,
    manifest: InstallManifest,
) -> str:
    _install_manifest_target_paths(tool_root, catalog, manifest)
    observed: list[dict[str, Any]] = []
    for entry in sorted(manifest.entries, key=lambda value: value["destination_path"]):
        source, source_status = _read_relative_regular(
            tool_root,
            entry["source_path"],
            error="BASELINE_INSTALL_SOURCE_INVALID",
        )
        destination, destination_status = _read_relative_regular(
            target_root,
            entry["destination_path"],
            error="BASELINE_INSTALL_DESTINATION_INVALID",
        )
        if (
            sha256_bytes(source) != entry["source_sha256"]
            or stat.S_IMODE(source_status.st_mode) != entry["source_mode"]
            or destination != source
            or sha256_bytes(destination) != entry["source_sha256"]
            or stat.S_IMODE(destination_status.st_mode) != entry["destination_mode"]
            or destination_status.st_uid != entry["destination_uid"]
            or destination_status.st_gid != entry["destination_gid"]
        ):
            raise BaselineError("BASELINE_INSTALL_MANIFEST_BYTE_MISMATCH")
        observed.append(
            {
                "path": entry["destination_path"],
                "mode": stat.S_IMODE(destination_status.st_mode),
                "uid": destination_status.st_uid,
                "gid": destination_status.st_gid,
                "sha256": sha256_bytes(destination),
            }
        )
    return digest_json(observed)


def _install_manifest_target_paths(
    tool_root: Path,
    catalog: BaselineCatalog,
    manifest: InstallManifest,
) -> dict[str, str]:
    source_entries: dict[str, dict[str, Any]] = {}
    destination_paths: set[str] = set()
    for entry in manifest.entries:
        source_path = entry["source_path"]
        destination_path = entry["destination_path"]
        if source_path in source_entries or destination_path in destination_paths:
            raise BaselineError("BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE")
        source_entries[source_path] = entry
        destination_paths.add(destination_path)
    required = _required_target_files(tool_root, catalog)
    if not required.issubset(source_entries):
        raise BaselineError("BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE")
    target_paths = {
        relative: source_entries[relative]["destination_path"]
        for relative in required
    }
    for relative in sorted(_required_target_paths(catalog)):
        if relative in target_paths:
            continue
        source_root = PurePosixPath(relative)
        descendants = sorted(
            value
            for value in required
            if PurePosixPath(value).is_relative_to(source_root)
        )
        destination_roots: set[str] = set()
        for descendant in descendants:
            suffix = PurePosixPath(descendant).relative_to(source_root).parts
            destination = PurePosixPath(target_paths[descendant])
            if not suffix or destination.parts[-len(suffix) :] != suffix:
                raise BaselineError(
                    "BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE"
                )
            destination_root = destination.parts[: -len(suffix)]
            if not destination_root:
                raise BaselineError(
                    "BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE"
                )
            destination_roots.add(PurePosixPath(*destination_root).as_posix())
        if len(destination_roots) != 1:
            raise BaselineError("BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE")
        target_paths[relative] = destination_roots.pop()
    return target_paths


def _require_relative_node(root: Path, relative: str) -> None:
    path = root / relative
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BaselineError("BASELINE_ENTRY_INPUT_MISSING") from exc
    if resolved != Path(os.path.abspath(path)) or stat.S_ISLNK(status.st_mode):
        raise BaselineError("BASELINE_ENTRY_INPUT_UNSAFE")
    if not (stat.S_ISREG(status.st_mode) or stat.S_ISDIR(status.st_mode)):
        raise BaselineError("BASELINE_ENTRY_INPUT_UNSAFE")


def _require_entry_inputs(
    tool_root: Path,
    target_root: Path,
    entry: CatalogEntry,
    *,
    target_paths: dict[str, str] | None = None,
) -> None:
    for value, role in zip(
        entry.arguments, entry.argv_root_roles()[1:], strict=True
    ):
        if role == "literal":
            continue
        if role == "tool":
            _require_relative_node(tool_root, value)
        else:
            target_relative = value if target_paths is None else target_paths.get(value)
            if target_relative is None:
                raise BaselineError("BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE")
            _require_relative_node(target_root, target_relative)


_INOTIFY_MUTATION_MASK = (
    0x00000002  # IN_MODIFY
    | 0x00000004  # IN_ATTRIB
    | 0x00000008  # IN_CLOSE_WRITE
    | 0x00000040  # IN_MOVED_FROM
    | 0x00000080  # IN_MOVED_TO
    | 0x00000100  # IN_CREATE
    | 0x00000200  # IN_DELETE
    | 0x00000400  # IN_DELETE_SELF
    | 0x00000800  # IN_MOVE_SELF
    | 0x00002000  # IN_UNMOUNT
    | 0x00004000  # IN_Q_OVERFLOW
    | 0x00008000  # IN_IGNORED
)
_INOTIFY_EVENT = struct.Struct("iIII")


class _RootMutationGuard:
    """Fail closed on persistent or transient mutation of private inputs."""

    def __init__(self, roots: Iterable[Path]) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        self._descriptor = init(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if self._descriptor < 0:
            raise BaselineError("BASELINE_ROOT_GUARD_UNAVAILABLE")
        add = libc.inotify_add_watch
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int
        self._add = add
        self._roots = tuple(dict.fromkeys(Path(root).resolve() for root in roots))
        self._snapshots = {
            root: root_byte_manifest_sha256(root) for root in self._roots
        }
        try:
            for root in self._roots:
                self._arm(root)
            self.check()
        except BaseException:
            self.close()
            raise

    def _arm(self, root: Path) -> None:
        paths = [root, *(path for path in root.rglob("*") if path.is_dir())]
        paths.extend(path for path in root.rglob("*") if path.is_file())
        for path in paths:
            if self._add(
                self._descriptor,
                os.fsencode(path),
                _INOTIFY_MUTATION_MASK,
            ) < 0:
                raise BaselineError("BASELINE_ROOT_GUARD_UNAVAILABLE")

    def check(self) -> None:
        while True:
            try:
                payload = os.read(self._descriptor, 1024 * 1024)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            except OSError as exc:
                raise BaselineError("BASELINE_ROOT_GUARD_UNAVAILABLE") from exc
            if not payload:
                raise BaselineError("BASELINE_ROOT_GUARD_UNAVAILABLE")
            offset = 0
            while offset < len(payload):
                if len(payload) - offset < _INOTIFY_EVENT.size:
                    raise BaselineError("BASELINE_ROOT_CHANGED_DURING_VALIDATION")
                _, _, _, name_length = _INOTIFY_EVENT.unpack_from(payload, offset)
                offset += _INOTIFY_EVENT.size + name_length
                if offset > len(payload):
                    raise BaselineError("BASELINE_ROOT_CHANGED_DURING_VALIDATION")
            raise BaselineError("BASELINE_ROOT_CHANGED_DURING_VALIDATION")
        if any(
            root_byte_manifest_sha256(root) != expected
            for root, expected in self._snapshots.items()
        ):
            raise BaselineError("BASELINE_ROOT_CHANGED_DURING_VALIDATION")

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self) -> _RootMutationGuard:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            if exception_type is None:
                self.check()
        finally:
            self.close()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _subreaper_state() -> int:
    current = ctypes.c_int()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_GET_CHILD_SUBREAPER)")
    return current.value


def _set_subreaper(enabled: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, int(bool(enabled)), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER)")


def _process_snapshot() -> dict[int, tuple[int, int]]:
    """Return pid -> (ppid, start-time ticks) for the current procfs view."""

    observed: dict[int, tuple[int, int]] = {}
    try:
        entries = os.scandir("/proc")
    except OSError as exc:
        raise _BoundedProcessError("containment", b"", b"") from exc
    with entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                raw = Path(entry.path, "stat").read_bytes()
                closing = raw.rfind(b")")
                fields = raw[closing + 2 :].split()
                if closing < 2 or len(fields) < 20:
                    continue
                observed[int(entry.name)] = (int(fields[1]), int(fields[19]))
            except (OSError, ValueError):
                continue
    return observed


def _direct_child_tokens(snapshot: dict[int, tuple[int, int]]) -> set[tuple[int, int]]:
    owner = os.getpid()
    return {
        (pid, identity[1])
        for pid, identity in snapshot.items()
        if identity[0] == owner
    }


def _owned_process_tokens(
    root_pid: int,
    baseline_children: set[tuple[int, int]],
) -> set[tuple[int, int]]:
    snapshot = _process_snapshot()
    owned_pids: set[int] = set()
    if root_pid in snapshot:
        owned_pids.add(root_pid)
    owner = os.getpid()
    owned_pids.update(
        pid
        for pid, (parent, started) in snapshot.items()
        if parent == owner and (pid, started) not in baseline_children
    )
    while True:
        descendants = {
            pid for pid, (parent, _started) in snapshot.items() if parent in owned_pids
        }
        expanded = owned_pids | descendants
        if expanded == owned_pids:
            break
        owned_pids = expanded
    return {(pid, snapshot[pid][1]) for pid in owned_pids if pid in snapshot}


def _token_alive(token: tuple[int, int]) -> bool:
    pid, started = token
    return _process_snapshot().get(pid, (-1, -1))[1] == started


def _reap_owned(tokens: set[tuple[int, int]], root_pid: int) -> None:
    for pid, _started in sorted(tokens):
        if pid == root_pid:
            continue
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, ProcessLookupError):
            pass


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    baseline_children: set[tuple[int, int]],
) -> bool:
    known = _owned_process_tokens(process.pid, baseline_children)
    for requested_signal in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, requested_signal)
        except ProcessLookupError:
            pass
        for pid, started in sorted(known, reverse=True):
            if _token_alive((pid, started)):
                try:
                    os.kill(pid, requested_signal)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                process.wait(timeout=0.01)
            except subprocess.TimeoutExpired:
                pass
            current = _owned_process_tokens(process.pid, baseline_children)
            known.update(current)
            _reap_owned(known, process.pid)
            if not any(_token_alive(token) for token in known):
                return True
            time.sleep(0.01)
    _reap_owned(known, process.pid)
    return not any(_token_alive(token) for token in known)


def _wait_for_process_group_exit(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def _terminate_process_group(process: subprocess.Popen[bytes]) -> bool:
    for requested_signal in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, requested_signal)
        except ProcessLookupError:
            return True
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        if _wait_for_process_group_exit(process.pid, 1):
            return True
    return not _process_group_exists(process.pid)


def _run_bounded_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
    output_limit: int,
) -> subprocess.CompletedProcess[bytes]:
    try:
        prior_subreaper = _subreaper_state()
        _set_subreaper(1)
        baseline_children = _direct_child_tokens(_process_snapshot())
    except (OSError, _BoundedProcessError) as exc:
        raise _BoundedProcessError("containment", b"", b"") from exc
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        _set_subreaper(prior_subreaper)
        raise _BoundedProcessError("spawn", b"", b"") from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    for name, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout_seconds
    failure: str | None = None
    process_group_closed = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                break
            events = selector.select(min(0.1, remaining))
            for key, _mask in events:
                name = key.data
                remaining_capacity = output_limit + 1 - len(buffers[name])
                try:
                    chunk = os.read(
                        key.fileobj.fileno(),
                        max(1, min(PROCESS_READ_CHUNK, remaining_capacity)),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > output_limit:
                    failure = "output"
                    break
            if failure is not None:
                break
            if process.poll() is not None and _owned_process_tokens(
                process.pid, baseline_children
            ):
                failure = "descendant"
                break
        if failure is not None:
            process_group_closed = _terminate_process_tree(
                process, baseline_children
            )
            raise _BoundedProcessError(
                failure if process_group_closed else "process-tree",
                bytes(buffers["stdout"]),
                bytes(buffers["stderr"]),
            )
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if _owned_process_tokens(process.pid, baseline_children):
            process_group_closed = _terminate_process_tree(
                process, baseline_children
            )
            raise _BoundedProcessError(
                "descendant" if process_group_closed else "process-tree",
                bytes(buffers["stdout"]),
                bytes(buffers["stderr"]),
            )
        process_group_closed = True
        return subprocess.CompletedProcess(
            list(argv),
            return_code,
            bytes(buffers["stdout"]),
            bytes(buffers["stderr"]),
        )
    except subprocess.TimeoutExpired as exc:
        process_group_closed = _terminate_process_tree(process, baseline_children)
        raise _BoundedProcessError(
            "timeout" if process_group_closed else "process-tree",
            bytes(buffers["stdout"]),
            bytes(buffers["stderr"]),
        ) from exc
    finally:
        if not process_group_closed:
            _terminate_process_tree(process, baseline_children)
        selector.close()
        process.stdout.close()
        process.stderr.close()
        _set_subreaper(prior_subreaper)


def _run_entry(
    target_root: Path,
    entry: CatalogEntry,
    catalog: BaselineCatalog,
    environment: dict[str, str],
    *,
    tool_root: Path | None = None,
    target_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    tool_root = target_root if tool_root is None else tool_root
    _require_entry_inputs(
        tool_root, target_root, entry, target_paths=target_paths
    )
    argv = catalog_execution_command(
        entry,
        sys.executable,
        tool_root=tool_root,
        target_root=target_root,
        target_paths=target_paths,
    )
    try:
        result = _run_bounded_process(
            argv,
            cwd=target_root,
            environment=environment,
            timeout_seconds=catalog.entry_timeout_seconds,
            output_limit=catalog.maximum_output_bytes,
        )
    except _BoundedProcessError as exc:
        if exc.kind == "output":
            raise BaselineError(
                f"BASELINE_ENTRY_OUTPUT_INCOMPLETE:{entry.entry_id}"
            ) from exc
        if exc.kind == "spawn":
            raise BaselineError(f"BASELINE_ENTRY_FAILED:{entry.entry_id}") from exc
        if exc.kind in {"containment", "descendant", "process-tree"}:
            raise BaselineError(
                f"BASELINE_ENTRY_PROCESS_TREE_NOT_EMPTY:{entry.entry_id}"
            ) from exc
        raise BaselineError(
            "BASELINE_ENTRY_TIMEOUT:"
            f"{entry.entry_id}:{sha256_bytes(exc.stdout)}:{sha256_bytes(exc.stderr)}"
        ) from exc
    stdout = result.stdout
    stderr = result.stderr
    receipt = {
        "id": entry.entry_id,
        "kind": entry.kind,
        "working_directory": entry.working_directory,
        "argv": list(entry.declared_argv()),
        "argv_root_roles": list(entry.argv_root_roles()),
        "return_code": result.returncode,
        "timeout_seconds": catalog.entry_timeout_seconds,
        "timed_out": False,
        "output_complete": True,
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_bytes": len(stderr),
        "stderr_sha256": sha256_bytes(stderr),
    }
    if result.returncode != 0:
        raise BaselineError(f"BASELINE_ENTRY_FAILED:{entry.entry_id}")
    return receipt


def _root_runner_sha256(
    root: Path, *, relative_path: str = RUNNER_RELATIVE_PATH
) -> str:
    value, _status = _read_relative_regular(
        root,
        relative_path,
        error="BASELINE_ROOT_RUNNER_UNSAFE",
        maximum_bytes=4 * 1024 * 1024,
    )
    return sha256_bytes(value)


def _catalog_equal(left: BaselineCatalog, right: BaselineCatalog) -> bool:
    return (
        left.raw_sha256 == right.raw_sha256
        and left.canonical_sha256 == right.canonical_sha256
        and left.command_manifest_sha256 == right.command_manifest_sha256
    )


def _run_root(
    target_root: Path,
    catalog: BaselineCatalog,
    *,
    root_kind: str,
    root_identity: str,
    install_manifest: InstallManifest | None,
    installer_evidence: Path | None = None,
    tool_root: Path | None = None,
    tool_identity: str | None = None,
    engine_authority: str = "tool-root",
    target_catalog_required: bool = True,
    git_repository_root: Path | None = None,
) -> dict[str, Any]:
    target_root = _validated_root(target_root)
    tool_root = target_root if tool_root is None else _validated_root(tool_root)
    tool_identity = root_identity if tool_identity is None else tool_identity
    if root_kind not in SOURCE_ROOT_KINDS | INSTALL_ROOT_KINDS:
        raise BaselineError("BASELINE_ROOT_KIND_INVALID")
    if (
        not ROOT_IDENTITY.fullmatch(root_identity)
        or not ROOT_IDENTITY.fullmatch(tool_identity)
    ):
        raise BaselineError("BASELINE_ROOT_IDENTITY_INVALID")
    tool_prefix, tool_separator, tool_sha = tool_identity.partition(":")
    if tool_separator != ":" or tool_prefix != "git" or not GIT_SHA.fullmatch(tool_sha):
        raise BaselineError("BASELINE_TOOL_IDENTITY_INVALID")
    if engine_authority not in {"tool-root", "bootstrap-candidate"}:
        raise BaselineError("BASELINE_ENGINE_AUTHORITY_INVALID")
    if root_kind in SOURCE_ROOT_KINDS:
        _prefix, separator, source_sha = root_identity.partition(":")
        if separator != ":" or _prefix != "git" or not GIT_SHA.fullmatch(source_sha):
            raise BaselineError("BASELINE_SOURCE_IDENTITY_INVALID")
        identity_repository = (
            target_root if git_repository_root is None else git_repository_root
        )
        observed_head = _git(identity_repository, "rev-parse", source_sha)
        if observed_head != source_sha:
            raise BaselineError("BASELINE_CANDIDATE_NOT_CLEAN")
        _assert_exact_commit_root(
            target_root,
            source_sha,
            repository_root=identity_repository,
        )
    if root_kind in INSTALL_ROOT_KINDS:
        if install_manifest is None:
            raise BaselineError("BASELINE_INSTALL_MANIFEST_REQUIRED")
        if installer_evidence is None:
            raise BaselineError("BASELINE_INSTALL_STATE_EVIDENCE_REQUIRED")
        if (
            root_identity != f"install:{install_manifest.atom_id}"
            or tool_sha != install_manifest.source_commit
        ):
            raise BaselineError("BASELINE_INSTALL_MANIFEST_IDENTITY_MISMATCH")
        if _git(tool_root, "rev-parse", "HEAD") != tool_sha:
            raise BaselineError("BASELINE_INSTALL_SOURCE_IDENTITY_MISMATCH")
        _assert_exact_commit_root(tool_root, tool_sha)
        (
            installer_state_evidence_sha256,
            filesystem_identity_sha256,
        ) = _verify_installer_state_evidence(
            target_root, root_kind, install_manifest, installer_evidence
        )
    elif install_manifest is not None or installer_evidence is not None:
        raise BaselineError("BASELINE_INSTALL_MANIFEST_UNEXPECTED")
    else:
        installer_state_evidence_sha256 = None
        filesystem_identity_sha256 = None

    target_paths: dict[str, str] | None = None
    if install_manifest is not None:
        target_paths = _install_manifest_target_paths(
            tool_root, catalog, install_manifest
        )
        target_manifest_sha256 = _install_manifest_byte_manifest(
            tool_root, target_root, catalog, install_manifest
        )

    target_catalog: BaselineCatalog | None = None
    try:
        target_catalog = load_catalog(
            target_root,
            relative_path=(
                CATALOG_RELATIVE_PATH
                if target_paths is None
                else target_paths[CATALOG_RELATIVE_PATH]
            ),
        )
    except BaselineError:
        if target_catalog_required:
            raise
    if target_catalog is not None and not _catalog_equal(target_catalog, catalog):
        raise BaselineError("BASELINE_TARGET_CATALOG_MISMATCH")
    if target_catalog_required and target_catalog is None:
        raise BaselineError("BASELINE_TARGET_CATALOG_MISSING")

    if install_manifest is None:
        target_manifest_sha256 = root_byte_manifest_sha256(target_root)
        target_manifest_scope = "complete-source-tree"
    else:
        target_manifest_scope = "install-manifest-destinations"
    if tool_root == target_root and install_manifest is None:
        tool_manifest_sha256 = target_manifest_sha256
    else:
        tool_manifest_sha256 = root_byte_manifest_sha256(tool_root)

    target_runner_sha256 = _root_runner_sha256(
        target_root,
        relative_path=(
            RUNNER_RELATIVE_PATH
            if target_paths is None
            else target_paths[RUNNER_RELATIVE_PATH]
        ),
    )
    tool_runner_sha256 = _root_runner_sha256(tool_root)
    engine_runner_bytes, _engine_status = _read_external_regular(
        Path(__file__), error="BASELINE_ENGINE_RUNNER_UNSAFE", maximum_bytes=4 * 1024 * 1024
    )
    engine_runner_sha256 = sha256_bytes(engine_runner_bytes)
    if engine_authority == "tool-root" and engine_runner_sha256 != tool_runner_sha256:
        raise BaselineError("BASELINE_ENGINE_TOOL_MISMATCH")

    with (
        tempfile.TemporaryDirectory(prefix="twinfinity-harness-root-gate-") as name,
        _RootMutationGuard((target_root, tool_root)) as mutation_guard,
    ):
        environment = _environment(Path(name))
        results = []
        for entry in catalog.entries:
            mutation_guard.check()
            results.append(
                _run_entry(
                    target_root,
                    entry,
                    catalog,
                    environment,
                    tool_root=tool_root,
                    target_paths=target_paths,
                )
            )
            mutation_guard.check()
    if install_manifest is None:
        final_target_manifest = root_byte_manifest_sha256(target_root)
    else:
        final_target_manifest = _install_manifest_byte_manifest(
            tool_root, target_root, catalog, install_manifest
        )
        final_target_paths = _install_manifest_target_paths(
            tool_root, catalog, install_manifest
        )
        if final_target_paths != target_paths:
            raise BaselineError("BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE")
    final_tool_manifest = (
        final_target_manifest
        if tool_root == target_root and install_manifest is None
        else root_byte_manifest_sha256(tool_root)
    )
    if final_target_manifest != target_manifest_sha256:
        raise BaselineError("BASELINE_ROOT_CHANGED_DURING_VALIDATION")
    if final_tool_manifest != tool_manifest_sha256:
        raise BaselineError("BASELINE_TOOL_ROOT_CHANGED_DURING_VALIDATION")
    if root_kind in SOURCE_ROOT_KINDS:
        source_sha = root_identity.removeprefix("git:")
        identity_repository = (
            target_root if git_repository_root is None else git_repository_root
        )
        if _git(identity_repository, "rev-parse", source_sha) != source_sha:
            raise BaselineError("BASELINE_CANDIDATE_CHANGED_DURING_VALIDATION")
        _assert_exact_commit_root(
            target_root,
            source_sha,
            repository_root=identity_repository,
        )
    if (
        _root_runner_sha256(
            target_root,
            relative_path=(
                RUNNER_RELATIVE_PATH
                if target_paths is None
                else target_paths[RUNNER_RELATIVE_PATH]
            ),
        )
        != target_runner_sha256
        or _root_runner_sha256(tool_root) != tool_runner_sha256
    ):
        raise BaselineError("BASELINE_RUNNER_CHANGED_DURING_VALIDATION")
    if install_manifest is not None:
        assert installer_evidence is not None
        final_installer_state, final_filesystem_identity = (
            _verify_installer_state_evidence(
                target_root, root_kind, install_manifest, installer_evidence
            )
        )
        if (
            final_installer_state != installer_state_evidence_sha256
            or final_filesystem_identity != filesystem_identity_sha256
        ):
            raise BaselineError("BASELINE_INSTALL_STATE_CHANGED_DURING_VALIDATION")

    install_manifest_sha256 = (
        None if install_manifest is None else install_manifest.manifest_sha256
    )
    install_manifest_raw_sha256 = (
        None if install_manifest is None else install_manifest.raw_sha256
    )
    receipt = {
        "schema": ROOT_RECEIPT_SCHEMA,
        "verdict": "PASS",
        "target_root": {
            "kind": root_kind,
            "identity": root_identity,
            "byte_manifest_scope": target_manifest_scope,
            "byte_manifest_sha256": target_manifest_sha256,
            "install_manifest_sha256": install_manifest_sha256,
            "install_manifest_raw_sha256": install_manifest_raw_sha256,
            "filesystem_identity_sha256": filesystem_identity_sha256,
            "installer_state_evidence_sha256": (
                installer_state_evidence_sha256
            ),
        },
        "tool_root": {
            "kind": "source-tool",
            "identity": tool_identity,
            "byte_manifest_scope": "complete-source-tree",
            "byte_manifest_sha256": tool_manifest_sha256,
        },
        "runner": {
            "relative_path": RUNNER_RELATIVE_PATH,
            "target_runner_sha256": target_runner_sha256,
            "tool_runner_sha256": tool_runner_sha256,
            "engine_runner_sha256": engine_runner_sha256,
            "engine_authority": engine_authority,
        },
        "catalog": {
            "schema": CATALOG_SCHEMA,
            "version": catalog.version,
            "raw_sha256": catalog.raw_sha256,
            "canonical_sha256": catalog.canonical_sha256,
            "command_manifest_sha256": catalog.command_manifest_sha256,
            "target_raw_sha256": (
                None if target_catalog is None else target_catalog.raw_sha256
            ),
        },
        "result_count": len(results),
        "results": results,
    }
    _verify_root_receipt(
        receipt,
        catalog,
        expected_kind=root_kind,
        expected_identity=root_identity,
        expected_target_manifest_sha256=target_manifest_sha256,
        expected_target_manifest_scope=target_manifest_scope,
        expected_install_manifest_sha256=install_manifest_sha256,
        expected_install_manifest_raw_sha256=install_manifest_raw_sha256,
        expected_filesystem_identity_sha256=filesystem_identity_sha256,
        expected_installer_state_evidence_sha256=(
            installer_state_evidence_sha256
        ),
        expected_tool_identity=tool_identity,
        expected_tool_manifest_sha256=tool_manifest_sha256,
        expected_target_runner_sha256=target_runner_sha256,
        expected_tool_runner_sha256=tool_runner_sha256,
        expected_engine_runner_sha256=engine_runner_sha256,
        expected_engine_authority=engine_authority,
        expected_target_catalog_raw_sha256=(
            None if target_catalog is None else target_catalog.raw_sha256
        ),
    )
    return receipt


def _verify_root_receipt(
    receipt: Any,
    catalog: BaselineCatalog,
    *,
    expected_kind: str,
    expected_identity: str,
    expected_target_manifest_sha256: str,
    expected_target_manifest_scope: str,
    expected_install_manifest_sha256: str | None,
    expected_install_manifest_raw_sha256: str | None,
    expected_filesystem_identity_sha256: str | None,
    expected_installer_state_evidence_sha256: str | None,
    expected_tool_identity: str,
    expected_tool_manifest_sha256: str,
    expected_target_runner_sha256: str,
    expected_tool_runner_sha256: str,
    expected_engine_runner_sha256: str,
    expected_engine_authority: str,
    expected_target_catalog_raw_sha256: str | None,
) -> None:
    if type(receipt) is not dict or set(receipt) != ROOT_RECEIPT_KEYS:
        raise BaselineError("BASELINE_RECEIPT_SCHEMA_INVALID")
    if (
        type(receipt["schema"]) is not str
        or receipt["schema"] != ROOT_RECEIPT_SCHEMA
        or type(receipt["verdict"]) is not str
        or receipt["verdict"] != "PASS"
    ):
        raise BaselineError("BASELINE_RECEIPT_VERDICT_INVALID")
    target_root = receipt["target_root"]
    if (
        type(target_root) is not dict
        or set(target_root) != TARGET_ROOT_KEYS
        or any(
            type(target_root[field]) is not str
            for field in (
                "kind",
                "identity",
                "byte_manifest_scope",
                "byte_manifest_sha256",
            )
        )
        or not SHA256.fullmatch(target_root["byte_manifest_sha256"])
        or any(
            value is not None
            and (type(value) is not str or not SHA256.fullmatch(value))
            for value in (
                target_root["install_manifest_sha256"],
                target_root["install_manifest_raw_sha256"],
                target_root["filesystem_identity_sha256"],
                target_root["installer_state_evidence_sha256"],
            )
        )
    ):
        raise BaselineError("BASELINE_RECEIPT_ROOT_SCHEMA_INVALID")
    install_evidence_values = (
        target_root["install_manifest_sha256"],
        target_root["install_manifest_raw_sha256"],
        target_root["filesystem_identity_sha256"],
        target_root["installer_state_evidence_sha256"],
    )
    if (
        target_root["kind"] in INSTALL_ROOT_KINDS
        and any(value is None for value in install_evidence_values)
    ) or (
        target_root["kind"] in SOURCE_ROOT_KINDS
        and any(value is not None for value in install_evidence_values)
    ):
        raise BaselineError("BASELINE_RECEIPT_ROOT_SCHEMA_INVALID")
    if target_root != {
        "kind": expected_kind,
        "identity": expected_identity,
        "byte_manifest_scope": expected_target_manifest_scope,
        "byte_manifest_sha256": expected_target_manifest_sha256,
        "install_manifest_sha256": expected_install_manifest_sha256,
        "install_manifest_raw_sha256": expected_install_manifest_raw_sha256,
        "filesystem_identity_sha256": expected_filesystem_identity_sha256,
        "installer_state_evidence_sha256": (
            expected_installer_state_evidence_sha256
        ),
    }:
        raise BaselineError("BASELINE_RECEIPT_ROOT_MISMATCH")
    tool_root = receipt["tool_root"]
    if (
        type(tool_root) is not dict
        or set(tool_root) != TOOL_ROOT_KEYS
        or any(type(value) is not str for value in tool_root.values())
        or not SHA256.fullmatch(tool_root["byte_manifest_sha256"])
    ):
        raise BaselineError("BASELINE_RECEIPT_TOOL_ROOT_SCHEMA_INVALID")
    if tool_root != {
        "kind": "source-tool",
        "identity": expected_tool_identity,
        "byte_manifest_scope": "complete-source-tree",
        "byte_manifest_sha256": expected_tool_manifest_sha256,
    }:
        raise BaselineError("BASELINE_RECEIPT_TOOL_ROOT_MISMATCH")
    runner = receipt["runner"]
    if (
        type(runner) is not dict
        or set(runner) != RUNNER_RECEIPT_KEYS
        or any(type(value) is not str for value in runner.values())
        or any(
            not SHA256.fullmatch(runner[field])
            for field in (
                "target_runner_sha256",
                "tool_runner_sha256",
                "engine_runner_sha256",
            )
        )
        or runner["relative_path"] != RUNNER_RELATIVE_PATH
        or runner["target_runner_sha256"] != expected_target_runner_sha256
        or runner["tool_runner_sha256"] != expected_tool_runner_sha256
        or runner["engine_runner_sha256"] != expected_engine_runner_sha256
        or runner["engine_authority"] != expected_engine_authority
    ):
        raise BaselineError("BASELINE_RECEIPT_RUNNER_INVALID")
    receipt_catalog = receipt["catalog"]
    if (
        type(receipt_catalog) is not dict
        or set(receipt_catalog) != CATALOG_RECEIPT_KEYS
        or type(receipt_catalog["schema"]) is not str
        or type(receipt_catalog["version"]) is not int
        or any(
            type(receipt_catalog[field]) is not str
            or not SHA256.fullmatch(receipt_catalog[field])
            for field in (
                "raw_sha256",
                "canonical_sha256",
                "command_manifest_sha256",
            )
        )
        or (
            receipt_catalog["target_raw_sha256"] is not None
            and (
                type(receipt_catalog["target_raw_sha256"]) is not str
                or not SHA256.fullmatch(receipt_catalog["target_raw_sha256"])
            )
        )
    ):
        raise BaselineError("BASELINE_RECEIPT_CATALOG_SCHEMA_INVALID")
    if receipt_catalog != {
        "schema": CATALOG_SCHEMA,
        "version": catalog.version,
        "raw_sha256": catalog.raw_sha256,
        "canonical_sha256": catalog.canonical_sha256,
        "command_manifest_sha256": catalog.command_manifest_sha256,
        "target_raw_sha256": expected_target_catalog_raw_sha256,
    }:
        raise BaselineError("BASELINE_RECEIPT_CATALOG_MISMATCH")
    results = receipt["results"]
    if (
        type(results) is not list
        or type(receipt["result_count"]) is not int
        or receipt["result_count"] != len(catalog.entries)
    ):
        raise BaselineError("BASELINE_RECEIPT_RESULT_COUNT_INVALID")
    if len(results) != len(catalog.entries):
        raise BaselineError("BASELINE_RECEIPT_RESULT_COUNT_INVALID")
    for result, entry in zip(results, catalog.entries, strict=True):
        if type(result) is not dict or set(result) != RESULT_RECEIPT_KEYS:
            raise BaselineError("BASELINE_RECEIPT_RESULT_SCHEMA_INVALID")
        if (
            type(result["id"]) is not str
            or result["id"] != entry.entry_id
            or type(result["kind"]) is not str
            or result["kind"] != entry.kind
            or type(result["working_directory"]) is not str
            or result["working_directory"] != entry.working_directory
            or type(result["argv"]) is not list
            or not all(type(value) is str for value in result["argv"])
            or result["argv"] != list(entry.declared_argv())
            or type(result["argv_root_roles"]) is not list
            or not all(
                type(value) is str for value in result["argv_root_roles"]
            )
            or result["argv_root_roles"] != list(entry.argv_root_roles())
            or type(result["return_code"]) is not int
            or result["return_code"] != 0
            or type(result["timeout_seconds"]) is not int
            or result["timeout_seconds"] != catalog.entry_timeout_seconds
            or type(result["timed_out"]) is not bool
            or result["timed_out"] is not False
            or type(result["output_complete"]) is not bool
            or result["output_complete"] is not True
            or type(result["stdout_bytes"]) is not int
            or result["stdout_bytes"] < 0
            or result["stdout_bytes"] > catalog.maximum_output_bytes
            or type(result["stderr_bytes"]) is not int
            or result["stderr_bytes"] < 0
            or result["stderr_bytes"] > catalog.maximum_output_bytes
            or type(result["stdout_sha256"]) is not str
            or not SHA256.fullmatch(result["stdout_sha256"])
            or type(result["stderr_sha256"]) is not str
            or not SHA256.fullmatch(result["stderr_sha256"])
        ):
            raise BaselineError("BASELINE_RECEIPT_RESULT_INVALID")


def _legacy_skill_roots(base_runner: Path) -> tuple[str, ...]:
    try:
        raw, _metadata = _read_external_regular(
            base_runner,
            error="BASELINE_LEGACY_RUNNER_INVALID",
            maximum_bytes=4 * 1024 * 1024,
        )
        source = raw.decode("utf-8")
        tree = ast.parse(source)
    except (BaselineError, UnicodeDecodeError, SyntaxError) as exc:
        raise BaselineError("BASELINE_LEGACY_RUNNER_INVALID") from exc
    roots: tuple[str, ...] | None = None
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(target, ast.Name) and target.id == "VALIDATOR_SKILL_ROOTS"
                for target in targets
            ):
                value = ast.literal_eval(node.value)
                if type(value) is not tuple or not all(
                    type(item) is str for item in value
                ):
                    raise BaselineError("BASELINE_LEGACY_CATALOG_INVALID")
                roots = value
                break
    if roots is None:
        raise BaselineError("BASELINE_LEGACY_CATALOG_MISSING")
    for marker in (
        "executor_registry.py",
        "twinfinity-executor-registry.toml",
        "--config",
        "--profile-root",
        "audit-config",
    ):
        if marker not in source:
            raise BaselineError("BASELINE_LEGACY_REGISTRY_AUDIT_MISSING")
    return roots


def _catalog_compatibility(
    base_root: Path, candidate_catalog: BaselineCatalog
) -> tuple[str, BaselineCatalog | None]:
    base_catalog_path = base_root / CATALOG_RELATIVE_PATH
    try:
        base_catalog_path.lstat()
        has_catalog = True
    except FileNotFoundError:
        has_catalog = False
    except OSError as exc:
        raise BaselineError("BASELINE_CATALOG_UNSAFE") from exc
    if has_catalog:
        base_catalog = load_catalog(base_root)
        if not _catalog_equal(base_catalog, candidate_catalog):
            raise BaselineError("BASELINE_CATALOG_MUTATION")
        return "exact-v1", base_catalog
    base_runner = base_root / RUNNER_RELATIVE_PATH
    if _legacy_skill_roots(base_runner) != candidate_catalog.skill_roots:
        raise BaselineError("BASELINE_BOOTSTRAP_CATALOG_MUTATION")
    return "legacy-bootstrap", None


def _subprocess_observation(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
    output_limit: int,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    try:
        result = _run_bounded_process(
            argv,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
        )
    except _BoundedProcessError as exc:
        if exc.kind == "timeout":
            raise BaselineError(f"BASELINE_{label}_TIMEOUT") from exc
        if exc.kind == "output":
            raise BaselineError(f"BASELINE_{label}_OUTPUT_INCOMPLETE") from exc
        raise BaselineError(f"BASELINE_{label}_FAILED") from exc
    observation = {
        "label": label,
        "return_code": result.returncode,
        "timeout_seconds": timeout_seconds,
        "timed_out": False,
        "output_complete": True,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": sha256_bytes(result.stderr),
    }
    if result.returncode != 0:
        raise BaselineError(f"BASELINE_{label}_FAILED")
    return observation, result.stdout


def _parse_receipt_output(output: bytes) -> dict[str, Any]:
    try:
        text = output.decode("utf-8")
        lines = [line for line in text.splitlines() if line]
        if len(lines) != 1:
            raise ValueError
        value = json.loads(lines[0], object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, BaselineError, ValueError) as exc:
        raise BaselineError("BASELINE_RECEIPT_OUTPUT_INCOMPLETE") from exc
    if not isinstance(value, dict):
        raise BaselineError("BASELINE_RECEIPT_OUTPUT_INCOMPLETE")
    return value


def _legacy_base_observation(
    base_root: Path,
    base_sha: str,
    temp_root: Path,
    catalog: BaselineCatalog,
) -> dict[str, Any]:
    temp_root.mkdir(mode=0o700, parents=True)
    wrapper = (
        "import pathlib,runpy,sys;"
        "ns=runpy.run_path(sys.argv[1],run_name='twinfinity_legacy_baseline');"
        "ns['_extract_base_tree'].__globals__['REPOSITORY_ROOT']=pathlib.Path(sys.argv[2]);"
        "sys.argv=[sys.argv[1],'--base-sha',sys.argv[3]];"
        "raise SystemExit(ns['main']())"
    )
    observation, _output = _subprocess_observation(
        [
            sys.executable,
            "-B",
            "-c",
            wrapper,
            os.fspath(base_root / RUNNER_RELATIVE_PATH),
            os.fspath(REPOSITORY_ROOT),
            base_sha,
        ],
        cwd=REPOSITORY_ROOT,
        environment=_environment(temp_root),
        timeout_seconds=LEGACY_BASE_TIMEOUT_SECONDS,
        output_limit=catalog.maximum_output_bytes,
        label="ACCEPTED_BASE_RUNNER",
    )
    observation["runner_sha256"] = _root_runner_sha256(base_root)
    observation["protocol"] = "legacy-base-sha"
    return observation


def _single_root_subprocess(
    runner: Path,
    target_root: Path,
    *,
    root_kind: str,
    root_identity: str,
    tool_identity: str,
    catalog: BaselineCatalog,
    temp_root: Path,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    temp_root.mkdir(mode=0o700, parents=True)
    tool_root = runner.resolve(strict=True).parents[3]
    environment = _environment(temp_root)
    environment["TWINFINITY_BASELINE_GIT_REPOSITORY_ROOT"] = os.fspath(target_root)
    observation, output = _subprocess_observation(
        [
            sys.executable,
            "-B",
            os.fspath(runner),
            "--single-root",
            os.fspath(target_root),
            "--root-kind",
            root_kind,
            "--root-identity",
            root_identity,
            "--tool-root-identity",
            tool_identity,
        ],
        cwd=target_root,
        environment=environment,
        timeout_seconds=catalog.root_execution_budget_seconds,
        output_limit=catalog.maximum_output_bytes,
        label=label,
    )
    receipt = _parse_receipt_output(output)
    expected_target_manifest = root_byte_manifest_sha256(target_root)
    expected_tool_manifest = root_byte_manifest_sha256(tool_root)
    expected_target_runner_sha256 = _root_runner_sha256(target_root)
    expected_tool_runner_sha256 = _root_runner_sha256(tool_root)
    runner_bytes, _runner_status = _read_external_regular(
        runner, error="BASELINE_ENGINE_RUNNER_UNSAFE", maximum_bytes=4 * 1024 * 1024
    )
    expected_engine_runner_sha256 = sha256_bytes(runner_bytes)
    _verify_root_receipt(
        receipt,
        catalog,
        expected_kind=root_kind,
        expected_identity=root_identity,
        expected_target_manifest_sha256=expected_target_manifest,
        expected_target_manifest_scope="complete-source-tree",
        expected_install_manifest_sha256=None,
        expected_install_manifest_raw_sha256=None,
        expected_filesystem_identity_sha256=None,
        expected_installer_state_evidence_sha256=None,
        expected_tool_identity=tool_identity,
        expected_tool_manifest_sha256=expected_tool_manifest,
        expected_target_runner_sha256=expected_target_runner_sha256,
        expected_tool_runner_sha256=expected_tool_runner_sha256,
        expected_engine_runner_sha256=expected_engine_runner_sha256,
        expected_engine_authority="tool-root",
        expected_target_catalog_raw_sha256=catalog.raw_sha256,
    )
    observation["runner_sha256"] = expected_engine_runner_sha256
    observation["protocol"] = "root-receipt-v1"
    observation["root_receipt_sha256"] = digest_json(receipt)
    return observation, receipt


def _direct_root_observation(
    label: str,
    receipt: dict[str, Any],
    *,
    protocol: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    output = (canonical_json(receipt) + "\n").encode("utf-8")
    return {
        "label": label,
        "return_code": 0,
        "timeout_seconds": timeout_seconds,
        "timed_out": False,
        "output_complete": True,
        "stdout_bytes": len(output),
        "stdout_sha256": sha256_bytes(output),
        "stderr_bytes": 0,
        "stderr_sha256": sha256_bytes(b""),
        "runner_sha256": receipt["runner"]["engine_runner_sha256"],
        "protocol": protocol,
        "root_receipt_sha256": digest_json(receipt),
    }


def _verify_receipt_observation(
    observation: Any,
    receipt: dict[str, Any],
    *,
    expected_label: str,
    expected_protocol: str,
    maximum_output_bytes: int,
    expected_timeout_seconds: int,
) -> None:
    output = (canonical_json(receipt) + "\n").encode("utf-8")
    if (
        type(observation) is not dict
        or set(observation) != RECEIPT_OBSERVATION_KEYS
        or type(observation["label"]) is not str
        or observation["label"] != expected_label
        or type(observation["return_code"]) is not int
        or observation["return_code"] != 0
        or type(observation["timeout_seconds"]) is not int
        or observation["timeout_seconds"] != expected_timeout_seconds
        or type(observation["timed_out"]) is not bool
        or observation["timed_out"] is not False
        or type(observation["output_complete"]) is not bool
        or observation["output_complete"] is not True
        or type(observation["stdout_bytes"]) is not int
        or observation["stdout_bytes"] != len(output)
        or observation["stdout_bytes"] > maximum_output_bytes
        or type(observation["stdout_sha256"]) is not str
        or observation["stdout_sha256"] != sha256_bytes(output)
        or type(observation["stderr_bytes"]) is not int
        or observation["stderr_bytes"] != 0
        or observation["stderr_bytes"] > maximum_output_bytes
        or type(observation["stderr_sha256"]) is not str
        or observation["stderr_sha256"] != sha256_bytes(b"")
        or type(observation["runner_sha256"]) is not str
        or observation["runner_sha256"]
        != receipt["runner"]["engine_runner_sha256"]
        or type(observation["protocol"]) is not str
        or observation["protocol"] != expected_protocol
        or type(observation["root_receipt_sha256"]) is not str
        or observation["root_receipt_sha256"] != digest_json(receipt)
    ):
        raise BaselineError("BASELINE_PAIR_OBSERVATION_INVALID")


def _verify_legacy_observation(
    observation: Any,
    accepted_receipt: dict[str, Any],
    *,
    maximum_output_bytes: int,
) -> None:
    if (
        type(observation) is not dict
        or set(observation) != LEGACY_OBSERVATION_KEYS
        or type(observation["label"]) is not str
        or observation["label"] != "ACCEPTED_BASE_RUNNER"
        or type(observation["return_code"]) is not int
        or observation["return_code"] != 0
        or type(observation["timeout_seconds"]) is not int
        or observation["timeout_seconds"] != LEGACY_BASE_TIMEOUT_SECONDS
        or type(observation["timed_out"]) is not bool
        or observation["timed_out"] is not False
        or type(observation["output_complete"]) is not bool
        or observation["output_complete"] is not True
        or type(observation["stdout_bytes"]) is not int
        or observation["stdout_bytes"] < 0
        or observation["stdout_bytes"] > maximum_output_bytes
        or type(observation["stdout_sha256"]) is not str
        or not SHA256.fullmatch(observation["stdout_sha256"])
        or type(observation["stderr_bytes"]) is not int
        or observation["stderr_bytes"] < 0
        or observation["stderr_bytes"] > maximum_output_bytes
        or type(observation["stderr_sha256"]) is not str
        or not SHA256.fullmatch(observation["stderr_sha256"])
        or type(observation["runner_sha256"]) is not str
        or observation["runner_sha256"]
        != accepted_receipt["runner"]["target_runner_sha256"]
        or type(observation["protocol"]) is not str
        or observation["protocol"] != "legacy-base-sha"
    ):
        raise BaselineError("BASELINE_PAIR_LEGACY_OBSERVATION_INVALID")


def _verify_embedded_source_receipt(
    receipt: Any,
    catalog: BaselineCatalog,
    *,
    target_kind: str,
    target_identity: str,
    tool_identity: str,
    engine_authority: str,
    target_catalog_raw_sha256: str | None,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise BaselineError("BASELINE_PAIR_RECEIPT_INVALID")
    try:
        target = receipt["target_root"]
        tool = receipt["tool_root"]
        runner = receipt["runner"]
        target_manifest = target["byte_manifest_sha256"]
        tool_manifest = tool["byte_manifest_sha256"]
        target_runner = runner["target_runner_sha256"]
        tool_runner = runner["tool_runner_sha256"]
        engine_runner = runner["engine_runner_sha256"]
    except (KeyError, TypeError) as exc:
        raise BaselineError("BASELINE_PAIR_RECEIPT_INVALID") from exc
    for value in (
        target_manifest,
        tool_manifest,
        target_runner,
        tool_runner,
        engine_runner,
    ):
        if type(value) is not str or not SHA256.fullmatch(value):
            raise BaselineError("BASELINE_PAIR_RECEIPT_INVALID")
    _verify_root_receipt(
        receipt,
        catalog,
        expected_kind=target_kind,
        expected_identity=target_identity,
        expected_target_manifest_sha256=target_manifest,
        expected_target_manifest_scope="complete-source-tree",
        expected_install_manifest_sha256=None,
        expected_install_manifest_raw_sha256=None,
        expected_filesystem_identity_sha256=None,
        expected_installer_state_evidence_sha256=None,
        expected_tool_identity=tool_identity,
        expected_tool_manifest_sha256=tool_manifest,
        expected_target_runner_sha256=target_runner,
        expected_tool_runner_sha256=tool_runner,
        expected_engine_runner_sha256=engine_runner,
        expected_engine_authority=engine_authority,
        expected_target_catalog_raw_sha256=target_catalog_raw_sha256,
    )
    if engine_authority == "tool-root" and engine_runner != tool_runner:
        raise BaselineError("BASELINE_PAIR_ENGINE_TOOL_MISMATCH")
    return receipt


def verify_pair_receipt(
    receipt: Any,
    *,
    expected_base_sha: str,
    expected_candidate_head: str,
    catalog: BaselineCatalog,
    repository_root: Path,
) -> None:
    keys = {
        "schema",
        "verdict",
        "base_sha",
        "candidate_head_sha",
        "catalog_compatibility",
        "catalog_raw_sha256",
        "catalog_canonical_sha256",
        "command_manifest_sha256",
        "git_identity",
        "git_identity_sha256",
        "legacy_base_runner_observation",
        "accepted_base_receipt_observation",
        "trusted_candidate_runner_observation",
        "candidate_runner_observation",
        "accepted_base_receipt_sha256",
        "trusted_candidate_receipt_sha256",
        "candidate_receipt_sha256",
        "pair_manifest_sha256",
        "accepted_base_receipt",
        "trusted_candidate_receipt",
        "candidate_receipt",
    }
    if (
        type(receipt) is not dict
        or set(receipt) != keys
        or type(receipt["schema"]) is not str
        or receipt["schema"] != PAIR_RECEIPT_SCHEMA
        or type(receipt["verdict"]) is not str
        or receipt["verdict"] != "PASS"
        or type(receipt["base_sha"]) is not str
        or receipt["base_sha"] != expected_base_sha
        or type(receipt["candidate_head_sha"]) is not str
        or receipt["candidate_head_sha"] != expected_candidate_head
        or type(receipt["catalog_compatibility"]) is not str
        or receipt["catalog_compatibility"] not in {"legacy-bootstrap", "exact-v1"}
        or any(
            type(receipt[field]) is not str
            or not SHA256.fullmatch(receipt[field])
            for field in (
                "catalog_raw_sha256",
                "catalog_canonical_sha256",
                "command_manifest_sha256",
                "git_identity_sha256",
                "accepted_base_receipt_sha256",
                "trusted_candidate_receipt_sha256",
                "candidate_receipt_sha256",
                "pair_manifest_sha256",
            )
        )
        or receipt["catalog_raw_sha256"] != catalog.raw_sha256
        or receipt["catalog_canonical_sha256"] != catalog.canonical_sha256
        or receipt["command_manifest_sha256"] != catalog.command_manifest_sha256
    ):
        raise BaselineError("BASELINE_PAIR_RECEIPT_INVALID")
    git_identity = _derived_pair_git_identity(
        repository_root, expected_base_sha, expected_candidate_head
    )
    if (
        type(receipt["git_identity"]) is not dict
        or receipt["git_identity"] != git_identity
        or receipt["git_identity_sha256"] != digest_json(git_identity)
    ):
        raise BaselineError("BASELINE_PAIR_GIT_IDENTITY_INVALID")
    compatibility = receipt["catalog_compatibility"]
    base_engine_authority = (
        "bootstrap-candidate" if compatibility == "legacy-bootstrap" else "tool-root"
    )
    accepted = _verify_embedded_source_receipt(
        receipt["accepted_base_receipt"],
        catalog,
        target_kind="accepted-base",
        target_identity=f"git:{expected_base_sha}",
        tool_identity=f"git:{expected_base_sha}",
        engine_authority=base_engine_authority,
        target_catalog_raw_sha256=(
            None if compatibility == "legacy-bootstrap" else catalog.raw_sha256
        ),
    )
    trusted = _verify_embedded_source_receipt(
        receipt["trusted_candidate_receipt"],
        catalog,
        target_kind="source-candidate",
        target_identity=f"git:{expected_candidate_head}",
        tool_identity=f"git:{expected_base_sha}",
        engine_authority=base_engine_authority,
        target_catalog_raw_sha256=catalog.raw_sha256,
    )
    candidate = _verify_embedded_source_receipt(
        receipt["candidate_receipt"],
        catalog,
        target_kind="source-candidate",
        target_identity=f"git:{expected_candidate_head}",
        tool_identity=f"git:{expected_candidate_head}",
        engine_authority="tool-root",
        target_catalog_raw_sha256=catalog.raw_sha256,
    )
    base_tree_manifest_sha256 = _git_commit_byte_manifest_sha256(
        repository_root, expected_base_sha
    )
    candidate_tree_manifest_sha256 = _git_commit_byte_manifest_sha256(
        repository_root, expected_candidate_head
    )
    if (
        accepted["target_root"]["byte_manifest_sha256"]
        != base_tree_manifest_sha256
        or accepted["tool_root"]["byte_manifest_sha256"]
        != base_tree_manifest_sha256
        or trusted["tool_root"]["byte_manifest_sha256"]
        != base_tree_manifest_sha256
        or trusted["target_root"]["byte_manifest_sha256"]
        != candidate_tree_manifest_sha256
        or candidate["target_root"]["byte_manifest_sha256"]
        != candidate_tree_manifest_sha256
        or candidate["tool_root"]["byte_manifest_sha256"]
        != candidate_tree_manifest_sha256
        or accepted["target_root"]["byte_manifest_sha256"]
        != accepted["tool_root"]["byte_manifest_sha256"]
        or trusted["tool_root"]["byte_manifest_sha256"]
        != accepted["tool_root"]["byte_manifest_sha256"]
        or trusted["target_root"]["byte_manifest_sha256"]
        != candidate["target_root"]["byte_manifest_sha256"]
        or candidate["target_root"]["byte_manifest_sha256"]
        != candidate["tool_root"]["byte_manifest_sha256"]
        or accepted["runner"]["target_runner_sha256"]
        != accepted["runner"]["tool_runner_sha256"]
        or trusted["runner"]["tool_runner_sha256"]
        != accepted["runner"]["tool_runner_sha256"]
        or trusted["runner"]["target_runner_sha256"]
        != candidate["runner"]["target_runner_sha256"]
        or candidate["runner"]["target_runner_sha256"]
        != candidate["runner"]["tool_runner_sha256"]
        or accepted["runner"]["target_runner_sha256"]
        != git_identity["trusted_base_runner_sha256"]
        or trusted["runner"]["tool_runner_sha256"]
        != git_identity["trusted_base_runner_sha256"]
        or trusted["runner"]["target_runner_sha256"]
        != git_identity["candidate_runner_sha256"]
        or candidate["runner"]["target_runner_sha256"]
        != git_identity["candidate_runner_sha256"]
        or candidate["runner"]["engine_runner_sha256"]
        != git_identity["candidate_runner_sha256"]
        or (
            compatibility == "legacy-bootstrap"
            and (
                accepted["runner"]["engine_runner_sha256"]
                != git_identity["candidate_runner_sha256"]
                or trusted["runner"]["engine_runner_sha256"]
                != git_identity["candidate_runner_sha256"]
            )
        )
        or (
            compatibility == "exact-v1"
            and (
                accepted["runner"]["engine_runner_sha256"]
                != git_identity["trusted_base_runner_sha256"]
                or trusted["runner"]["engine_runner_sha256"]
                != git_identity["trusted_base_runner_sha256"]
            )
        )
    ):
        raise BaselineError("BASELINE_PAIR_CROSS_BINDING_INVALID")
    _verify_receipt_observation(
        receipt["accepted_base_receipt_observation"],
        accepted,
        expected_label="ACCEPTED_BASE_RECEIPT",
        expected_protocol=(
            "bootstrap-candidate-engine-base-tools"
            if compatibility == "legacy-bootstrap"
            else "root-receipt-v1"
        ),
        maximum_output_bytes=catalog.maximum_output_bytes,
        expected_timeout_seconds=catalog.root_execution_budget_seconds,
    )
    _verify_receipt_observation(
        receipt["trusted_candidate_runner_observation"],
        trusted,
        expected_label="TRUSTED_CANDIDATE_RUNNER",
        expected_protocol=(
            "bootstrap-candidate-engine-base-tools"
            if compatibility == "legacy-bootstrap"
            else "root-receipt-v1"
        ),
        maximum_output_bytes=catalog.maximum_output_bytes,
        expected_timeout_seconds=catalog.root_execution_budget_seconds,
    )
    _verify_receipt_observation(
        receipt["candidate_runner_observation"],
        candidate,
        expected_label="CANDIDATE_RUNNER",
        expected_protocol="root-receipt-v1",
        maximum_output_bytes=catalog.maximum_output_bytes,
        expected_timeout_seconds=catalog.root_execution_budget_seconds,
    )
    legacy = receipt["legacy_base_runner_observation"]
    if compatibility == "legacy-bootstrap":
        _verify_legacy_observation(
            legacy,
            accepted,
            maximum_output_bytes=catalog.maximum_output_bytes,
        )
    elif legacy is not None:
        raise BaselineError("BASELINE_PAIR_LEGACY_OBSERVATION_UNEXPECTED")
    for field, value in (
        ("accepted_base_receipt_sha256", accepted),
        ("trusted_candidate_receipt_sha256", trusted),
        ("candidate_receipt_sha256", candidate),
    ):
        if receipt[field] != digest_json(value):
            raise BaselineError("BASELINE_PAIR_RECEIPT_DIGEST_INVALID")
    pair_manifest = {
        "base_sha": expected_base_sha,
        "candidate_head_sha": expected_candidate_head,
        "catalog_compatibility": compatibility,
        "catalog_raw_sha256": catalog.raw_sha256,
        "catalog_canonical_sha256": catalog.canonical_sha256,
        "git_identity_sha256": receipt["git_identity_sha256"],
        "accepted_base_receipt_sha256": receipt["accepted_base_receipt_sha256"],
        "trusted_candidate_receipt_sha256": receipt[
            "trusted_candidate_receipt_sha256"
        ],
        "candidate_receipt_sha256": receipt["candidate_receipt_sha256"],
    }
    if receipt["pair_manifest_sha256"] != digest_json(pair_manifest):
        raise BaselineError("BASELINE_PAIR_MANIFEST_INVALID")


def _pair_receipt(base_sha: str) -> dict[str, Any]:
    if not GIT_SHA.fullmatch(base_sha):
        raise BaselineError("BASELINE_BASE_SHA_INVALID")
    candidate_head = _candidate_head(REPOSITORY_ROOT, base_sha)
    git_identity = _derived_pair_git_identity(
        REPOSITORY_ROOT, base_sha, candidate_head
    )
    candidate_catalog = load_catalog(REPOSITORY_ROOT)
    with (
        tempfile.TemporaryDirectory(prefix="twinfinity-harness-baseline-pair-") as name,
        tempfile.TemporaryDirectory(prefix="twinfinity-harness-baseline-evidence-") as evidence_name,
    ):
        temp_root = Path(name)
        evidence_root = Path(evidence_name)
        base_root = _extract_base_tree(base_sha, temp_root)
        candidate_root = _extract_commit_tree(
            candidate_head, temp_root, "exact-candidate"
        )
        compatibility, base_catalog = _catalog_compatibility(
            base_root, candidate_catalog
        )
        execution_catalog = (
            candidate_catalog if base_catalog is None else base_catalog
        )
        if base_catalog is None:
            with _RootMutationGuard((temp_root, base_root, candidate_root)):
                legacy_observation = _legacy_base_observation(
                    base_root, base_sha, evidence_root / "legacy", candidate_catalog
                )
        else:
            legacy_observation = None
        if compatibility == "exact-v1":
            with _RootMutationGuard(
                (temp_root, base_root, candidate_root)
            ) as pair_guard:
                base_observation, base_receipt = _single_root_subprocess(
                    base_root / RUNNER_RELATIVE_PATH,
                    base_root,
                    root_kind="accepted-base",
                    root_identity=f"git:{base_sha}",
                    tool_identity=f"git:{base_sha}",
                    catalog=execution_catalog,
                    temp_root=evidence_root / "accepted-base-evidence",
                    label="ACCEPTED_BASE_RECEIPT",
                )
                pair_guard.check()
                trusted_observation, trusted_receipt = _single_root_subprocess(
                    base_root / RUNNER_RELATIVE_PATH,
                    candidate_root,
                    root_kind="source-candidate",
                    root_identity=f"git:{candidate_head}",
                    tool_identity=f"git:{base_sha}",
                    catalog=execution_catalog,
                    temp_root=evidence_root / "trusted-candidate-evidence",
                    label="TRUSTED_CANDIDATE_RUNNER",
                )
                pair_guard.check()
                candidate_observation, candidate_receipt = _single_root_subprocess(
                    candidate_root / RUNNER_RELATIVE_PATH,
                    candidate_root,
                    root_kind="source-candidate",
                    root_identity=f"git:{candidate_head}",
                    tool_identity=f"git:{candidate_head}",
                    catalog=candidate_catalog,
                    temp_root=evidence_root / "candidate-evidence",
                    label="CANDIDATE_RUNNER",
                )
                pair_guard.check()
        else:
            with _RootMutationGuard(
                (temp_root, base_root, candidate_root)
            ) as pair_guard:
                base_receipt = _run_root(
                    base_root, execution_catalog,
                    root_kind="accepted-base", root_identity=f"git:{base_sha}",
                    install_manifest=None, tool_root=base_root,
                    tool_identity=f"git:{base_sha}", engine_authority="bootstrap-candidate",
                    target_catalog_required=False, git_repository_root=REPOSITORY_ROOT,
                )
                pair_guard.check()
                trusted_receipt = _run_root(
                    candidate_root, execution_catalog,
                    root_kind="source-candidate", root_identity=f"git:{candidate_head}",
                    install_manifest=None, tool_root=base_root,
                    tool_identity=f"git:{base_sha}", engine_authority="bootstrap-candidate",
                    git_repository_root=REPOSITORY_ROOT,
                )
                pair_guard.check()
                candidate_receipt = _run_root(
                    candidate_root, candidate_catalog,
                    root_kind="source-candidate", root_identity=f"git:{candidate_head}",
                    install_manifest=None, tool_root=candidate_root,
                    tool_identity=f"git:{candidate_head}", engine_authority="tool-root",
                    git_repository_root=REPOSITORY_ROOT,
                )
                pair_guard.check()
            base_observation = _direct_root_observation(
                "ACCEPTED_BASE_RECEIPT", base_receipt,
                protocol="bootstrap-candidate-engine-base-tools",
                timeout_seconds=execution_catalog.root_execution_budget_seconds,
            )
            trusted_observation = _direct_root_observation(
                "TRUSTED_CANDIDATE_RUNNER", trusted_receipt,
                protocol="bootstrap-candidate-engine-base-tools",
                timeout_seconds=execution_catalog.root_execution_budget_seconds,
            )
            candidate_observation = _direct_root_observation(
                "CANDIDATE_RUNNER", candidate_receipt, protocol="root-receipt-v1",
                timeout_seconds=candidate_catalog.root_execution_budget_seconds,
            )
    base_receipt_sha256 = digest_json(base_receipt)
    trusted_receipt_sha256 = digest_json(trusted_receipt)
    candidate_receipt_sha256 = digest_json(candidate_receipt)
    pair_manifest = {
        "base_sha": base_sha,
        "candidate_head_sha": candidate_head,
        "catalog_compatibility": compatibility,
        "catalog_raw_sha256": candidate_catalog.raw_sha256,
        "catalog_canonical_sha256": candidate_catalog.canonical_sha256,
        "git_identity_sha256": digest_json(git_identity),
        "accepted_base_receipt_sha256": base_receipt_sha256,
        "trusted_candidate_receipt_sha256": trusted_receipt_sha256,
        "candidate_receipt_sha256": candidate_receipt_sha256,
    }
    receipt = {
        "schema": PAIR_RECEIPT_SCHEMA,
        "verdict": "PASS",
        "base_sha": base_sha,
        "candidate_head_sha": candidate_head,
        "catalog_compatibility": compatibility,
        "catalog_raw_sha256": candidate_catalog.raw_sha256,
        "catalog_canonical_sha256": candidate_catalog.canonical_sha256,
        "command_manifest_sha256": candidate_catalog.command_manifest_sha256,
        "git_identity": git_identity,
        "git_identity_sha256": digest_json(git_identity),
        "legacy_base_runner_observation": legacy_observation,
        "accepted_base_receipt_observation": base_observation,
        "trusted_candidate_runner_observation": trusted_observation,
        "candidate_runner_observation": candidate_observation,
        "accepted_base_receipt_sha256": base_receipt_sha256,
        "trusted_candidate_receipt_sha256": trusted_receipt_sha256,
        "candidate_receipt_sha256": candidate_receipt_sha256,
        "pair_manifest_sha256": digest_json(pair_manifest),
        "accepted_base_receipt": base_receipt,
        "trusted_candidate_receipt": trusted_receipt,
        "candidate_receipt": candidate_receipt,
    }
    verify_pair_receipt(
        receipt,
        expected_base_sha=base_sha,
        expected_candidate_head=candidate_head,
        catalog=candidate_catalog,
        repository_root=REPOSITORY_ROOT,
    )
    return receipt


def _rename_noreplace(
    parent_descriptor: int, source_name: str, destination_name: str
) -> None:
    """Atomically publish one same-directory name without replacement."""

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename_noreplace = libc.renameat2
    except AttributeError as exc:
        raise OSError(errno.ENOSYS, "renameat2 unavailable") from exc
    rename_noreplace.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename_noreplace.restype = ctypes.c_int
    if (
        rename_noreplace(
            parent_descriptor,
            os.fsencode(source_name),
            parent_descriptor,
            os.fsencode(destination_name),
            1,  # RENAME_NOREPLACE
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def _read_existing_receipt(
    parent_descriptor: int, name: str, maximum_bytes: int
) -> bytes:
    """Read a stable, private, singly linked receipt through a pinned dirfd."""

    descriptor: int | None = None
    try:
        descriptor = os.open(name, FILE_FLAGS, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
        ):
            raise BaselineError("BASELINE_RECEIPT_CONFLICT")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, PROCESS_READ_CHUNK)
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes:
                raise BaselineError("BASELINE_RECEIPT_CONFLICT")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size")
        if any(
            getattr(before, field) != getattr(after, field)
            or getattr(after, field) != getattr(current, field)
            for field in stable_fields
        ):
            raise BaselineError("BASELINE_RECEIPT_CONFLICT")
        return b"".join(chunks)
    except BaselineError:
        raise
    except OSError as exc:
        raise BaselineError("BASELINE_RECEIPT_CONFLICT") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _assert_receipt_parent_identity(
    parent: Path, parent_descriptor: int, expected: os.stat_result
) -> None:
    """Require the pinned and lexical parent to remain the same private dir."""

    try:
        pinned = os.fstat(parent_descriptor)
        lexical = parent.lstat()
    except OSError as exc:
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE") from exc
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    if (
        not stat.S_ISDIR(pinned.st_mode)
        or not stat.S_ISDIR(lexical.st_mode)
        or any(
            getattr(pinned, field) != getattr(expected, field)
            or getattr(lexical, field) != getattr(expected, field)
            for field in fields
        )
    ):
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE")


def _atomic_receipt_write(path: Path, payload: bytes) -> None:
    lexical_parent = Path(os.path.abspath(path.parent))
    parent = lexical_parent.resolve(strict=True)
    if parent != lexical_parent:
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE")
    try:
        parent_status = parent.lstat()
    except OSError as exc:
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE") from exc
    if (
        not stat.S_ISDIR(parent_status.st_mode)
        or parent_status.st_uid != os.getuid()
        or stat.S_IMODE(parent_status.st_mode) & 0o077
    ):
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE")
    destination = parent / path.name
    if not path.name or path.name in {".", ".."}:
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE")
    descriptor: int | None = None
    directory_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        directory_descriptor = os.open(parent, DIRECTORY_FLAGS)
        _assert_receipt_parent_identity(
            parent, directory_descriptor, parent_status
        )
        for _attempt in range(128):
            candidate_name = f".{path.name}.tmp.{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    candidate_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                continue
            temporary_name = candidate_name
            break
        if descriptor is None or temporary_name is None:
            raise BaselineError("BASELINE_RECEIPT_WRITE_FAILED")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            _rename_noreplace(
                directory_descriptor, temporary_name, destination.name
            )
        except FileExistsError:
            _assert_receipt_parent_identity(
                parent, directory_descriptor, parent_status
            )
            existing = _read_existing_receipt(
                directory_descriptor, destination.name, max(len(payload), 1) + 1
            )
            if existing != payload:
                raise BaselineError("BASELINE_RECEIPT_CONFLICT")
            # An identical replay may be observing a publication whose
            # publisher failed before syncing the containing directory.  Sync
            # the pinned parent before reporting success so the replay itself
            # establishes directory-entry durability.
            os.fsync(directory_descriptor)
            _assert_receipt_parent_identity(
                parent, directory_descriptor, parent_status
            )
            return
        # renameat2(RENAME_NOREPLACE) moves the sole temporary directory entry
        # atomically.  The published receipt therefore never has the transient
        # two-link state produced by link(2)+unlink(2), so interruption after
        # publication remains strictly readable and safely replayable.
        temporary_name = None
        os.fsync(directory_descriptor)
        _assert_receipt_parent_identity(
            parent, directory_descriptor, parent_status
        )
    except BaselineError:
        raise
    except OSError as exc:
        raise BaselineError("BASELINE_RECEIPT_WRITE_FAILED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None and directory_descriptor is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _emit(receipt: dict[str, Any], receipt_path: Path | None) -> None:
    payload = (canonical_json(receipt) + "\n").encode("utf-8")
    if receipt_path is not None:
        _atomic_receipt_write(receipt_path, payload)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _require_receipt_outside_roots(path: Path | None, roots: Sequence[Path]) -> None:
    if path is None:
        return
    lexical = Path(os.path.abspath(path))
    try:
        parent = lexical.parent.resolve(strict=True)
    except OSError as exc:
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE") from exc
    if parent != lexical.parent:
        raise BaselineError("BASELINE_RECEIPT_ROOT_UNSAFE")
    for root in roots:
        validated = _validated_root(root)
        if lexical == validated or validated in lexical.parents:
            raise BaselineError("BASELINE_RECEIPT_INSIDE_ATTESTED_ROOT")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--base-sha")
    mode.add_argument("--single-root", type=Path)
    parser.add_argument(
        "--root-kind",
        choices=tuple(sorted(SOURCE_ROOT_KINDS | INSTALL_ROOT_KINDS)),
    )
    parser.add_argument("--root-identity")
    parser.add_argument("--tool-root-identity")
    parser.add_argument("--install-manifest", type=Path)
    parser.add_argument("--installer-evidence", type=Path)
    parser.add_argument("--receipt", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.base_sha is not None:
            if (
                args.root_kind is not None
                or args.root_identity is not None
                or args.tool_root_identity is not None
                or args.install_manifest is not None
                or args.installer_evidence is not None
            ):
                raise BaselineError("BASELINE_PAIR_ARGUMENT_INVALID")
            _require_receipt_outside_roots(args.receipt, (REPOSITORY_ROOT,))
            receipt = _pair_receipt(args.base_sha)
        else:
            if (
                args.root_kind is None
                or args.root_identity is None
                or args.tool_root_identity is None
            ):
                raise BaselineError("BASELINE_ROOT_ARGUMENT_MISSING")
            assert args.single_root is not None
            target_root = _validated_root(args.single_root)
            tool_root = _validated_root(REPOSITORY_ROOT)
            _require_receipt_outside_roots(
                args.receipt, (target_root, tool_root)
            )
            catalog = load_catalog(tool_root)
            install_manifest = (
                None
                if args.install_manifest is None
                else load_install_manifest(args.install_manifest)
            )
            receipt = _run_root(
                target_root,
                catalog,
                root_kind=args.root_kind,
                root_identity=args.root_identity,
                install_manifest=install_manifest,
                installer_evidence=args.installer_evidence,
                tool_root=tool_root,
                tool_identity=args.tool_root_identity,
                git_repository_root=(
                    None
                    if "TWINFINITY_BASELINE_GIT_REPOSITORY_ROOT" not in os.environ
                    else _validated_root(
                        Path(os.environ["TWINFINITY_BASELINE_GIT_REPOSITORY_ROOT"])
                    )
                ),
            )
        _emit(receipt, args.receipt)
        return 0
    except (BaselineError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
