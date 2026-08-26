from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from executor_registry import (  # noqa: E402
    RegistryError,
    _validate_profile_directory,
    load_registry_config,
)


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
CODEX_HOME = Path(os.environ["CODEX_HOME"])
EXPECTED_ENDPOINTS = {
    "planner": ("role.planner.v2", 2),
    "development": ("role.development.v3", 3),
    "sre": ("role.sre.v3", 3),
}
class RuntimeProfileCutoverTests(unittest.TestCase):
    def audit_command(self, *extra: str) -> list[str]:
        return [
            sys.executable,
            str(ROOT / "scripts" / "executor_registry.py"),
            "--config",
            str(ROOT / "references" / "twinfinity-executor-registry.toml"),
            *extra,
            "audit-config",
        ]

    def test_source_profile_audit_does_not_read_or_write_live_codex_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            absent_codex_home = Path(temporary) / "must-remain-absent"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "executor_registry.py"),
                    "--config",
                    str(ROOT / "references" / "twinfinity-executor-registry.toml"),
                    "--profile-root",
                    str(ROOT / "references"),
                    "audit-config",
                ],
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, "CODEX_HOME": str(absent_codex_home)},
            )
            result = json.loads(completed.stdout)
            self.assertEqual("PASS", result["phase"])
            self.assertEqual(
                {
                    "planner": "role.planner.v2",
                    "development": "role.development.v3",
                    "sre": "role.sre.v3",
                },
                result["endpoints"],
            )
            self.assertEqual(
                [
                    "role.development.v4",
                    "role.development.v5",
                    "role.sre.v4",
                    "role.sre.v5",
                ],
                result["staged_endpoints"],
            )
            self.assertFalse(absent_codex_home.exists())

    def test_profile_root_rejects_symlink_and_world_writable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            symlink_root = temporary_root / "profile-link"
            symlink_root.symlink_to(ROOT / "references", target_is_directory=True)
            completed = subprocess.run(
                self.audit_command("--profile-root", str(symlink_root)),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, completed.returncode)
            self.assertEqual(
                "REGISTRY_CODEX_HOME_UNSAFE",
                json.loads(completed.stdout)["error"],
            )
            self.assertNotIn("Traceback", completed.stderr)

            writable_root = temporary_root / "world-writable"
            shutil.copytree(ROOT / "references", writable_root)
            writable_root.chmod(0o777)
            completed = subprocess.run(
                self.audit_command("--profile-root", str(writable_root)),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, completed.returncode)
            self.assertEqual(
                "REGISTRY_CODEX_HOME_UNSAFE",
                json.loads(completed.stdout)["error"],
            )
            self.assertNotIn("Traceback", completed.stderr)

    def test_profile_root_rejects_arbitrary_foreign_owned_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ancestor = Path(temporary) / "immutable-ancestor"
            profile_root = ancestor / "profile-root"
            profile_root.mkdir(parents=True, mode=0o700)
            original_lstat = Path.lstat

            def real_shaped_lstat(path: Path):
                metadata = original_lstat(path)
                if path == ancestor:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_uid=os.getuid() + 1,
                    )
                return metadata

            with mock.patch.object(Path, "lstat", real_shaped_lstat):
                with self.assertRaisesRegex(
                    RegistryError, "REGISTRY_CODEX_HOME_UNSAFE"
                ):
                    _validate_profile_directory(
                        profile_root, "REGISTRY_CODEX_HOME"
                    )

            def final_owned_elsewhere_lstat(path: Path):
                metadata = original_lstat(path)
                if path == profile_root:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_uid=os.getuid() + 1,
                    )
                return metadata

            with mock.patch.object(Path, "lstat", final_owned_elsewhere_lstat):
                with self.assertRaisesRegex(
                    RegistryError, "REGISTRY_CODEX_HOME_UNSAFE"
                ):
                    _validate_profile_directory(
                        profile_root, "REGISTRY_CODEX_HOME"
                    )

    def test_profile_root_accepts_only_mapped_namespace_ancestors(self) -> None:
        profile_root = Path("/home/ubuntu/.codex")
        metadata_by_path = {
            Path("/"): SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=65534),
            Path("/home"): SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755, st_uid=65534
            ),
            Path("/home/ubuntu"): SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o750, st_uid=os.getuid()
            ),
            profile_root: SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755, st_uid=os.getuid()
            ),
        }

        with mock.patch.object(Path, "lstat", lambda path: metadata_by_path[path]):
            self.assertEqual(
                profile_root,
                _validate_profile_directory(profile_root, "REGISTRY_CODEX_HOME"),
            )

    def test_profile_root_rejects_writable_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ancestor = Path(temporary) / "writable-ancestor"
            profile_root = ancestor / "profile-root"
            profile_root.mkdir(parents=True, mode=0o700)
            ancestor.chmod(0o777)
            try:
                with self.assertRaisesRegex(
                    RegistryError, "REGISTRY_CODEX_HOME_UNSAFE"
                ):
                    _validate_profile_directory(
                        profile_root, "REGISTRY_CODEX_HOME"
                    )
            finally:
                ancestor.chmod(0o700)

    def test_audit_config_omitted_profile_root_uses_safe_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home = Path(temporary) / "codex-home"
            codex_home.mkdir(mode=0o700)
            for profile in (ROOT / "references").glob("*.config.toml"):
                shutil.copy2(profile, codex_home / profile.name)
            completed = subprocess.run(
                self.audit_command(),
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, "CODEX_HOME": str(codex_home)},
            )
            self.assertEqual("PASS", json.loads(completed.stdout)["phase"])

    def test_invalid_profile_root_type_is_a_closed_registry_error(self) -> None:
        with self.assertRaisesRegex(RegistryError, "REGISTRY_CODEX_HOME_INVALID"):
            load_registry_config(
                ROOT / "references" / "twinfinity-executor-registry.toml",
                codex_home=object(),  # type: ignore[arg-type]
                profile_template_root=ROOT / "references",
            )

    def test_current_only_install_is_runtime_valid_but_not_catalog_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home = Path(temporary) / "current-only"
            codex_home.mkdir(mode=0o700)
            for profile in (
                "twinfinity-planner-v2.config.toml",
                "twinfinity-development-v3.config.toml",
                "twinfinity-sre-v3.config.toml",
            ):
                shutil.copy2(ROOT / "references" / profile, codex_home / profile)
            config = load_registry_config(
                ROOT / "references" / "twinfinity-executor-registry.toml",
                codex_home=codex_home,
            )
            self.assertEqual(
                {
                    "role.planner.v2",
                    "role.development.v3",
                    "role.sre.v3",
                },
                {
                    endpoint.endpoint_id for endpoint in config.roles.values()
                },
            )
            with self.assertRaisesRegex(RegistryError, "REGISTRY_PROFILE_MISSING"):
                load_registry_config(
                    ROOT / "references" / "twinfinity-executor-registry.toml",
                    codex_home=codex_home,
                    profile_validation_scope="catalog",
                )

    def test_readme_source_audit_command_executes_verbatim(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        marked = readme.split("<!-- source-profile-audit:start -->", 1)[1].split(
            "<!-- source-profile-audit:end -->", 1
        )[0]
        command = marked.split("```bash", 1)[1].split("```", 1)[0].strip()
        with tempfile.TemporaryDirectory() as temporary:
            absent_codex_home = Path(temporary) / "must-remain-absent"
            completed = subprocess.run(
                ["/bin/bash", "-eu", "-o", "pipefail", "-c", command],
                cwd=REPOSITORY_ROOT,
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, "CODEX_HOME": str(absent_codex_home)},
            )
            self.assertEqual("PASS", json.loads(completed.stdout)["phase"])
            self.assertFalse(absent_codex_home.exists())

    def test_current_direct_profiles_and_staged_profiles_are_digest_bound(self) -> None:
        registry = tomllib.loads(
            (ROOT / "references" / "twinfinity-executor-registry.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(2, registry["schema_version"])
        for role in ("planner", "development", "sre"):
            endpoint = registry["roles"][role]
            profile_name = endpoint["codex_profile"]
            template = (
                ROOT
                / "references"
                / f"{profile_name}-v{endpoint['version']}.config.toml"
            )
            expected_digest = endpoint["profile_sha256"]
            with self.subTest(role=role):
                self.assertEqual(
                    expected_digest,
                    hashlib.sha256(template.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    EXPECTED_ENDPOINTS[role],
                    (endpoint["endpoint_id"], endpoint["version"]),
                )
                profile = tomllib.loads(template.read_text(encoding="utf-8"))
                self.assertEqual("workspace-write", profile["sandbox_mode"])
                self.assertFalse(profile["sandbox_workspace_write"]["network_access"])
                self.assertFalse(profile["features"]["multi_agent"])
                role_label = {
                    "planner": "Product Planner",
                    "development": "Development",
                    "sre": "SRE",
                }[role]
                self.assertIn(f"Twinfinity {role_label}", profile["developer_instructions"])
                if role == "planner":
                    self.assertEqual("on-request", profile["approval_policy"])
                    self.assertNotIn("hooks", profile)
                    self.assertEqual(
                        ["/home/ubuntu/.codex/twinfinity-coordination"],
                        profile["sandbox_workspace_write"]["writable_roots"],
                    )
                else:
                    self.assertEqual("legacy", endpoint.get("execution_protocol", "legacy"))
                    self.assertEqual("on-request", profile["approval_policy"])
                    self.assertTrue(profile["features"]["hooks"])
                    self.assertEqual(
                        [
                            "/home/ubuntu/code",
                            "/home/ubuntu/.codex/twinfinity-coordination",
                        ],
                        profile["sandbox_workspace_write"]["writable_roots"],
                    )
                    instructions = profile["developer_instructions"]
                    self.assertIn("fresh bounded Twinfinity", instructions)
                    if role == "development":
                        self.assertIn("SQLite coordination rows", instructions)
                    else:
                        self.assertIn("hosted authority", instructions)
                command = endpoint["command_prefix"]
                self.assertEqual(profile_name, command[command.index("--profile") + 1])

        self.assertEqual([], registry["historical_endpoints"])
        staged = {
            endpoint["endpoint_id"]: endpoint
            for endpoint in registry["staged_endpoints"]
        }
        self.assertEqual(
            {
                "role.development.v4",
                "role.development.v5",
                "role.sre.v4",
                "role.sre.v5",
            },
            set(staged),
        )
        for endpoint in staged.values():
            versioned = (
                ROOT
                / "references"
                / f"{endpoint['codex_profile']}-v{endpoint['version']}.config.toml"
            )
            self.assertEqual(
                endpoint["profile_sha256"],
                hashlib.sha256(versioned.read_bytes()).hexdigest(),
            )
            staged_profile = tomllib.loads(versioned.read_text(encoding="utf-8"))
            if endpoint["version"] == 5:
                self.assertEqual("readiness/v1", endpoint["execution_protocol"])
                self.assertEqual("never", staged_profile["approval_policy"])
                self.assertFalse(staged_profile["features"]["hooks"])
                self.assertIn("brokered readiness/v1 boundary", staged_profile["developer_instructions"])
            else:
                self.assertEqual("on-request", staged_profile["approval_policy"])
                self.assertIn("hooks", staged_profile)

    def test_obsolete_runtime_artifacts_are_absent_and_uncalled(self) -> None:
        obsolete = (
            "twinfinity-" + "delivery.config.toml",
            "twinfinity-" + "ack-only.config.toml",
            "twinfinity-" + "sandbox-worker.config.toml",
            "run_" + "sandbox_worker.py",
            "sandbox_" + "worker_guard.py",
        )
        removed_paths = (
            CODEX_HOME / obsolete[0],
            CODEX_HOME / obsolete[1],
            ROOT / "references" / obsolete[0],
            ROOT / "references" / obsolete[2],
            ROOT / "scripts" / obsolete[3],
            ROOT / "scripts" / obsolete[4],
        )
        self.assertTrue((ROOT / "scripts" / "delivery_guard.py").is_file())
        for path in removed_paths:
            with self.subTest(path=path):
                self.assertFalse(path.exists())

        callers: list[str] = []
        for path in ROOT.rglob("*"):
            if (
                not path.is_file()
                or path == Path(__file__)
                or "__pycache__" in path.parts
                or ".mypy_cache" in path.parts
                or path.suffix not in {".py", ".md", ".toml", ".yaml"}
            ):
                continue
            contents = path.read_text(encoding="utf-8")
            for token in obsolete:
                if token in contents:
                    callers.append(f"{path.relative_to(ROOT)}:{token}")
        self.assertEqual([], callers)


if __name__ == "__main__":
    unittest.main()
