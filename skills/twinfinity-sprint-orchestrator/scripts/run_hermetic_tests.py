#!/usr/bin/env python3
"""Run orchestrator tests against a private source-bound Codex home."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Sequence
import venv

from executor_registry import RegistryError, load_registry_config


SKILL_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_ROOT = SKILL_ROOT / "references"
REGISTRY_PATH = REFERENCE_ROOT / "twinfinity-executor-registry.toml"
TEST_ROOT = SKILL_ROOT / "tests"
PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class HermeticTestError(RuntimeError):
    """A source catalog or private test-home invariant failed."""


def _catalog_endpoints(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    if parsed.get("schema_version") != 2:
        raise HermeticTestError("HERMETIC_REGISTRY_SCHEMA_INVALID")
    roles = parsed.get("roles")
    history = parsed.get("historical_endpoints")
    staged = parsed.get("staged_endpoints")
    if (
        not isinstance(roles, dict)
        or not isinstance(history, list)
        or not isinstance(staged, list)
    ):
        raise HermeticTestError("HERMETIC_REGISTRY_CATALOG_INVALID")
    endpoints = list(roles.values()) + history + staged
    if not endpoints or any(not isinstance(item, dict) for item in endpoints):
        raise HermeticTestError("HERMETIC_REGISTRY_CATALOG_INVALID")
    return endpoints


def _metadata_tuple(metadata: os.stat_result) -> tuple[int, ...]:
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


def _read_source_file(
    path: Path,
    *,
    error_prefix: str,
    expected_sha256: str | None = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HermeticTestError(f"{error_prefix}_MISSING") from exc
    try:
        before = os.fstat(descriptor)
        try:
            path_metadata = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise HermeticTestError(f"{error_prefix}_DRIFT") from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or _metadata_tuple(path_metadata) != _metadata_tuple(before)
        ):
            raise HermeticTestError(f"{error_prefix}_UNSAFE")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        contents = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            final_path_metadata = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise HermeticTestError(f"{error_prefix}_DRIFT") from exc
        if (
            _metadata_tuple(before) != _metadata_tuple(after)
            or _metadata_tuple(after) != _metadata_tuple(final_path_metadata)
            or len(contents) != after.st_size
        ):
            raise HermeticTestError(f"{error_prefix}_DRIFT")
        if (
            expected_sha256 is not None
            and hashlib.sha256(contents).hexdigest() != expected_sha256
        ):
            raise HermeticTestError(f"{error_prefix}_DIGEST_MISMATCH")
        return contents
    finally:
        os.close(descriptor)


def _write_private_file(path: Path, contents: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise HermeticTestError("HERMETIC_PROFILE_INSTALL_FAILED") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(contents)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != 0o600:
        raise HermeticTestError("HERMETIC_PROFILE_INSTALL_MODE_INVALID")


def install_reviewed_profiles(codex_home: Path) -> None:
    """Install exactly the schema-v2 catalog's reviewed profile templates."""

    try:
        registry_bytes = _read_source_file(
            REGISTRY_PATH,
            error_prefix="HERMETIC_REGISTRY_SOURCE",
        )
        parsed = tomllib.loads(registry_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise HermeticTestError("HERMETIC_REGISTRY_SOURCE_INVALID") from exc
    endpoints = _catalog_endpoints(parsed)
    declared: dict[str, str] = {}
    for endpoint in endpoints:
        profile = endpoint.get("codex_profile")
        version = endpoint.get("version")
        digest = endpoint.get("profile_sha256")
        if (
            type(profile) is not str
            or PROFILE_NAME.fullmatch(profile) is None
            or type(version) is not int
            or version <= 0
            or type(digest) is not str
            or SHA256.fullmatch(digest) is None
        ):
            raise HermeticTestError("HERMETIC_REGISTRY_PROFILE_INVALID")
        filename = f"{profile}-v{version}.config.toml"
        if filename in declared and declared[filename] != digest:
            raise HermeticTestError("HERMETIC_REGISTRY_PROFILE_CONFLICT")
        declared[filename] = digest

    source_profiles = {
        path.name for path in REFERENCE_ROOT.glob("*-v*.config.toml")
    }
    if set(declared) != source_profiles:
        raise HermeticTestError("HERMETIC_REGISTRY_PROFILE_SET_MISMATCH")
    for filename, digest in sorted(declared.items()):
        contents = _read_source_file(
            REFERENCE_ROOT / filename,
            error_prefix="HERMETIC_PROFILE_SOURCE",
            expected_sha256=digest,
        )
        _write_private_file(codex_home / filename, contents)


def validate_test_registry(codex_home: Path) -> None:
    """Bind the temporary install to the checked-in production loader."""

    try:
        config = load_registry_config(
            REGISTRY_PATH,
            codex_home=codex_home,
            profile_template_root=REFERENCE_ROOT,
            profile_validation_scope="catalog",
        )
    except RegistryError as exc:
        raise HermeticTestError(str(exc)) from exc
    if (
        config.schema_version != 2
        or Path(config.source_evidence.path) != REGISTRY_PATH
        or Path(config.profile_template_root) != REFERENCE_ROOT
        or Path(config.codex_home) != codex_home
    ):
        raise HermeticTestError("HERMETIC_REGISTRY_BINDING_INVALID")


def _test_command(
    selectors: Sequence[str], verbose: bool, *, interpreter: Path
) -> list[str]:
    command = [os.fspath(interpreter), "-B", "-m", "unittest"]
    if verbose:
        command.append("-v")
    if selectors:
        command.extend(selectors)
    else:
        command.extend(("discover", "-s", "tests", "-p", "test_*.py"))
    return command


def run_tests(selectors: Sequence[str], *, verbose: bool = False) -> int:
    previous_umask = os.umask(0o077)
    try:
        # Keep the private root deliberately short. Several tests create an
        # additional TemporaryDirectory, coordination directory, PARK
        # capability directory, and AF_UNIX socket below TMPDIR. Linux limits
        # pathname-based AF_UNIX addresses to 107 bytes, so descriptive names
        # at this outer layer can make an otherwise valid issue-owned run fail.
        with tempfile.TemporaryDirectory(prefix="h-", dir="/tmp") as root:
            temporary_root = Path(root)
            temporary_root.chmod(0o700)
            codex_home = temporary_root / "c"
            test_environment = temporary_root / "v"
            test_tmp = temporary_root
            codex_home.mkdir(mode=0o700)
            venv.EnvBuilder(with_pip=False, symlinks=True).create(test_environment)
            test_python = test_environment / "bin" / "python"
            install_reviewed_profiles(codex_home)
            validate_test_registry(codex_home)

            environment = {
                "HOME": os.fspath(temporary_root),
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "CODEX_HOME": os.fspath(codex_home),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.fspath(TEST_ROOT),
                "TMPDIR": os.fspath(test_tmp),
                "VIRTUAL_ENV": os.fspath(test_environment),
            }
            completed = subprocess.run(
                _test_command(selectors, verbose, interpreter=test_python),
                cwd=SKILL_ROOT,
                env=environment,
                check=False,
            )
            return completed.returncode
    finally:
        os.umask(previous_umask)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "selectors",
        nargs="*",
        help=(
            "optional unittest modules, classes, or methods; "
            "default is full discovery"
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        return run_tests(arguments.selectors, verbose=arguments.verbose)
    except HermeticTestError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
