#!/usr/bin/env python3
"""Fail-closed, receipt-producing execution-environment rebuilds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from typing import Any, BinaryIO

from coordination_store import (
    DEFAULT_DATABASE,
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
    utc_now,
)


class EnvironmentRebuildError(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_root(value: Any, expected_name: str, *, must_be_absent: bool) -> Path:
    if not isinstance(value, str):
        raise EnvironmentRebuildError("ENVIRONMENT_CONTRACT_INVALID")
    path = Path(value)
    if (
        not path.is_absolute()
        or path.parent != Path("/home/ubuntu/.codex")
        or path.name != expected_name
        or path.is_symlink()
        or (must_be_absent and path.exists())
    ):
        raise EnvironmentRebuildError("ENVIRONMENT_ROOT_NOT_CLEAN")
    return path


def validate_packet(packet_path: Path, expected_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = packet_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or _sha256_file(packet_path) != expected_sha256
    ):
        raise EnvironmentRebuildError("PACKET_PROVENANCE_INVALID")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    contract = packet.get("recovery_contract")
    contract_sha256 = packet.get("recovery_contract_sha256")
    if (
        not isinstance(contract, dict)
        or not contract
        or not isinstance(contract_sha256, str)
        or digest_json(contract) != contract_sha256
    ):
        raise EnvironmentRebuildError("RECOVERY_CONTRACT_DIGEST_MISMATCH")
    return packet, contract


def _validate_active_lineage(store: CoordinationStore, packet: dict[str, Any]) -> None:
    source = packet["source"]
    item = store.connection.execute(
        "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
        (source["repository"], packet["issue_number"]),
    ).fetchone()
    if (
        item is None
        or item["status"] != "ACTIVE_FENCED"
        or item["allocation_class"] != "ACTIVE"
        or int(item["generation"]) != packet["generation"]
        or item["accountable_session_id"] != packet["accountable_session_id"]
        or item["lease_manifest_sha256"] != packet["lease_manifest_sha256"]
        or item["source_payload_sha256"] != source["payload_sha256"]
        or int(item["version"]) != packet["item_version"] + 1
        or int(item["development_units"]) != packet["capacity"]["development_units"]
        or int(item["shared_units"]) != packet["capacity"]["shared_units"]
        or int(item["sre_units"]) != packet["capacity"]["sre_units"]
    ):
        raise EnvironmentRebuildError("ACTIVE_LINEAGE_DRIFT")
    expected_payload = digest_json(packet)
    message = store.connection.execute(
        """
        SELECT state, claimed_by FROM coordination_messages
        WHERE topic='development.recovery_commit' AND payload_sha256=?
        """,
        (expected_payload,),
    ).fetchone()
    if (
        message is None
        or message["state"] != "COMPLETE"
        or message["claimed_by"] != packet["accountable_session_id"]
    ):
        raise EnvironmentRebuildError("RECOVERY_ACTIVATION_MISSING")


def _git_output(worktree: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["/usr/bin/git", "-C", str(worktree), *arguments],
            stdin=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            env={"HOME": "/home/ubuntu", "PATH": "/usr/bin:/bin"},
            text=True,
            timeout=30,
        ).strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentRebuildError("GIT_LINEAGE_INVALID") from exc


def _validate_git_lineage(packet: dict[str, Any]) -> None:
    worktree = Path(packet["worktree_path"])
    if (
        not worktree.is_dir()
        or worktree.parent != Path("/home/ubuntu/code")
        or worktree.name != packet["opaque_worktree_id"]
        or _git_output(worktree, "rev-parse", "HEAD") != packet["candidate_head_sha"]
        or _git_output(worktree, "branch", "--show-current") != packet["branch"]
        or _git_output(worktree, "status", "--porcelain")
    ):
        raise EnvironmentRebuildError("GIT_LINEAGE_INVALID")
    try:
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(worktree),
                "merge-base",
                "--is-ancestor",
                packet["base_sha"],
                packet["candidate_head_sha"],
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"HOME": "/home/ubuntu", "PATH": "/usr/bin:/bin"},
            timeout=30,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentRebuildError("GIT_LINEAGE_INVALID") from exc


def _validate_controller_contract(packet: dict[str, Any]) -> None:
    contract = packet.get("controller_contract")
    if not isinstance(contract, dict):
        raise EnvironmentRebuildError("CONTROLLER_CONTRACT_INVALID")
    scripts = Path(__file__).resolve().parent
    expected_paths = {
        "coordination_store_sha256": scripts / "coordination_store.py",
        "coordination_supervisor_sha256": scripts / "coordination_supervisor.py",
        "environment_rebuild_control_sha256": Path(__file__).resolve(),
        "prepush_control_sha256": scripts / "prepush_control.py",
    }
    for field, path in expected_paths.items():
        expected = contract.get(field)
        metadata = path.lstat()
        if (
            not isinstance(expected, str)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or _sha256_file(path) != expected
        ):
            raise EnvironmentRebuildError("CONTROLLER_CONTRACT_DRIFT")


def _exact_environment(contract: dict[str, Any]) -> dict[str, str]:
    declared = contract.get("sanitized_environment")
    if not isinstance(declared, dict):
        raise EnvironmentRebuildError("ENVIRONMENT_CONTRACT_INVALID")
    expected_keys = {"HOME", "PATH", "UV_CACHE_DIR", "UV_HTTP_TIMEOUT"}
    if set(declared) - (expected_keys | {"launcher", "ambient_uv_pip_python_index_constraint_state"}):
        raise EnvironmentRebuildError("ENVIRONMENT_CONTRACT_INVALID")
    environment = {key: declared[key] for key in expected_keys if key in declared}
    if set(environment) != expected_keys or any(not isinstance(value, str) for value in environment.values()):
        raise EnvironmentRebuildError("ENVIRONMENT_CONTRACT_INVALID")
    return environment


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=30)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _run(argv: list[str], *, environment: dict[str, str], timeout_seconds: int, log: BinaryIO) -> int:
    if not argv or any(not isinstance(value, str) or not value for value in argv):
        raise EnvironmentRebuildError("ENVIRONMENT_COMMAND_INVALID")
    log.write((canonical_json({"argv": argv, "timeout_seconds": timeout_seconds}) + "\n").encode())
    log.flush()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        env=environment,
        start_new_session=True,
    )
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        _terminate(process)
        raise EnvironmentRebuildError("ENVIRONMENT_COMMAND_TIMEOUT") from exc
    except BaseException:
        _terminate(process)
        raise


def _capture(argv: list[str], *, environment: dict[str, str], timeout_seconds: int, log: BinaryIO) -> bytes:
    if not argv or any(not isinstance(value, str) or not value for value in argv):
        raise EnvironmentRebuildError("ENVIRONMENT_COMMAND_INVALID")
    log.write((canonical_json({"argv": argv, "timeout_seconds": timeout_seconds}) + "\n").encode())
    log.flush()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    try:
        output, error_output = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        _terminate(process)
        raise EnvironmentRebuildError("ENVIRONMENT_COMMAND_TIMEOUT") from exc
    except BaseException:
        _terminate(process)
        raise
    log.write(output)
    if error_output:
        log.write((canonical_json({"stderr_bytes": len(error_output)}) + "\n").encode())
        log.write(error_output)
    log.write((canonical_json({"exit_code": process.returncode}) + "\n").encode())
    if process.returncode != 0:
        raise EnvironmentRebuildError("ENVIRONMENT_VERIFICATION_FAILED")
    return output


def _audit_tree(environment_root: Path) -> dict[str, int]:
    root_metadata = environment_root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise EnvironmentRebuildError("ENVIRONMENT_ROOT_MODE_INVALID")
    regular_files = 0
    directories = 0
    python_symlinks = 0
    allowed_python_names = {"python", "python3", "python3.12"}
    for root, directory_names, file_names in os.walk(environment_root, followlinks=False):
        root_path = Path(root)
        for name in directory_names + file_names:
            path = root_path / name
            metadata = path.lstat()
            if metadata.st_uid != os.getuid():
                raise EnvironmentRebuildError("ENVIRONMENT_TREE_OWNER_INVALID")
            if stat.S_ISLNK(metadata.st_mode):
                relative = path.relative_to(environment_root)
                if relative == Path("lib64"):
                    if os.readlink(path) != "lib" or path.resolve(strict=True) != (environment_root / "lib").resolve(strict=True):
                        raise EnvironmentRebuildError("ENVIRONMENT_FOREIGN_SYMLINK")
                else:
                    if relative.parent != Path("bin") or relative.name not in allowed_python_names:
                        raise EnvironmentRebuildError("ENVIRONMENT_FOREIGN_SYMLINK")
                    resolved = path.resolve(strict=True)
                    if resolved != Path("/usr/bin/python3.12").resolve(strict=True):
                        raise EnvironmentRebuildError("ENVIRONMENT_FOREIGN_SYMLINK")
                    python_symlinks += 1
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise EnvironmentRebuildError("ENVIRONMENT_HARDLINK_INVALID")
                regular_files += 1
            elif stat.S_ISDIR(metadata.st_mode):
                directories += 1
            else:
                raise EnvironmentRebuildError("ENVIRONMENT_TREE_TYPE_INVALID")
    return {
        "directories": directories,
        "python_symlinks": python_symlinks,
        "regular_files": regular_files,
    }


def _register_log(store: CoordinationStore, packet: dict[str, Any], log_path: Path) -> dict[str, Any]:
    return store.register_artifacts(
        [
            {
                "repository": packet["source"]["repository"],
                "issue_number": packet["issue_number"],
                "generation": packet["generation"],
                "path": str(log_path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }
        ],
        now=utc_now(),
    )[0]


def execute(packet_path: Path, expected_sha256: str, database: Path = DEFAULT_DATABASE) -> dict[str, Any]:
    packet, contract = validate_packet(packet_path, expected_sha256)
    environment_root = _private_root(
        contract.get("environment_root"),
        f"twinfinity-issue{packet['issue_number']}-prepush-venv-v3",
        must_be_absent=False,
    )
    cache_root = _private_root(
        contract.get("cache_root"),
        f"twinfinity-issue{packet['issue_number']}-prepush-uv-cache-v3",
        must_be_absent=False,
    )
    evidence = contract.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("mode") != "0600":
        raise EnvironmentRebuildError("ENVIRONMENT_EVIDENCE_INVALID")
    log_path = Path(str(evidence.get("path")))
    if log_path.parent != database.parent / "evidence" or log_path.is_symlink():
        raise EnvironmentRebuildError("ENVIRONMENT_EVIDENCE_INVALID")
    commands = contract.get("commands")
    if not isinstance(commands, list) or len(commands) != 2:
        raise EnvironmentRebuildError("ENVIRONMENT_COMMAND_INVALID")
    for requirement in contract.get("requirements", []):
        path = Path(requirement["path"])
        if _sha256_file(path) != requirement["sha256"]:
            raise EnvironmentRebuildError("ENVIRONMENT_INPUT_DRIFT")
    environment = _exact_environment(contract)
    if environment["UV_CACHE_DIR"] != str(cache_root):
        raise EnvironmentRebuildError("ENVIRONMENT_CONTRACT_INVALID")

    store = CoordinationStore(database)
    artifact: dict[str, Any] | None = None
    outcome = "FAIL"
    error: str | None = None
    old_umask = os.umask(0o077)
    try:
        _validate_active_lineage(store, packet)
        _validate_git_lineage(packet)
        _validate_controller_contract(packet)
        log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if log_path.exists():
            metadata = log_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise EnvironmentRebuildError("INTERRUPTED_EVIDENCE_UNSAFE")
            artifact = _register_log(store, packet, log_path)
            raise EnvironmentRebuildError(
                canonical_json(
                    {
                        "artifact": artifact,
                        "phase": "HOLD",
                        "reason": "RECOVERED_INTERRUPTED_ENVIRONMENT_EXECUTION",
                    }
                )
            )
        _private_root(
            str(environment_root),
            environment_root.name,
            must_be_absent=True,
        )
        _private_root(str(cache_root), cache_root.name, must_be_absent=True)
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", buffering=0) as log:
            try:
                cache_root.mkdir(mode=0o700)
                for command in commands:
                    argv = command.get("argv")
                    timeout_seconds = command.get("timeout_seconds")
                    if not isinstance(argv, list) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
                        raise EnvironmentRebuildError("ENVIRONMENT_COMMAND_INVALID")
                    exit_code = _run(argv, environment=environment, timeout_seconds=timeout_seconds, log=log)
                    log.write((canonical_json({"exit_code": exit_code}) + "\n").encode())
                    if exit_code != 0:
                        raise EnvironmentRebuildError("ENVIRONMENT_COMMAND_FAILED")
                os.chmod(environment_root, 0o700)
                checks = contract.get("verification_commands")
                if not isinstance(checks, list) or not checks:
                    raise EnvironmentRebuildError("ENVIRONMENT_VERIFICATION_INVALID")
                for argv in checks:
                    exit_code = _run(argv, environment=environment, timeout_seconds=120, log=log)
                    log.write((canonical_json({"exit_code": exit_code}) + "\n").encode())
                    if exit_code != 0:
                        raise EnvironmentRebuildError("ENVIRONMENT_VERIFICATION_FAILED")
                freeze_argv = contract.get("freeze_command")
                if not isinstance(freeze_argv, list):
                    raise EnvironmentRebuildError("ENVIRONMENT_VERIFICATION_INVALID")
                freeze_output = _capture(
                    freeze_argv,
                    environment=environment,
                    timeout_seconds=120,
                    log=log,
                )
                freeze_lines = sorted(
                    line.strip()
                    for line in freeze_output.decode("utf-8").splitlines()
                    if line.strip()
                )
                freeze_sha256 = hashlib.sha256(
                    ("\n".join(freeze_lines) + "\n").encode("utf-8")
                ).hexdigest()
                tree_audit = _audit_tree(environment_root)
                cache_metadata = cache_root.lstat()
                if (
                    not stat.S_ISDIR(cache_metadata.st_mode)
                    or cache_metadata.st_uid != os.getuid()
                    or stat.S_IMODE(cache_metadata.st_mode) != 0o700
                ):
                    raise EnvironmentRebuildError("ENVIRONMENT_CACHE_MODE_INVALID")
                log.write(
                    (
                        canonical_json(
                            {
                                "freeze_package_count": len(freeze_lines),
                                "freeze_sha256": freeze_sha256,
                                "tree_audit": tree_audit,
                            }
                        )
                        + "\n"
                    ).encode()
                )
                ruff = environment_root / "bin" / "ruff"
                ruff_metadata = ruff.lstat()
                if not stat.S_ISREG(ruff_metadata.st_mode) or ruff_metadata.st_uid != os.getuid() or ruff_metadata.st_nlink != 1:
                    raise EnvironmentRebuildError("ENVIRONMENT_TOOL_PROVENANCE_INVALID")
                _validate_active_lineage(store, packet)
                _validate_git_lineage(packet)
                _validate_controller_contract(packet)
                outcome = "PASS"
            except BaseException as exc:
                error = str(exc) or exc.__class__.__name__
                log.write((canonical_json({"error": error, "outcome": "FAIL"}) + "\n").encode())
            finally:
                log.flush()
                os.fsync(log.fileno())
        artifact = _register_log(store, packet, log_path)
    finally:
        os.umask(old_umask)
        store.close()
    result = {"phase": outcome, "artifact": artifact, "error": error}
    if outcome != "PASS":
        raise EnvironmentRebuildError(canonical_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--expected-packet-sha256", required=True)
    args = parser.parse_args()
    try:
        print(canonical_json(execute(args.packet, args.expected_packet_sha256)))
        return 0
    except (EnvironmentRebuildError, CoordinationError, OSError, ValueError, KeyError) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
