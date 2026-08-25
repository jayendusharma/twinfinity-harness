from __future__ import annotations

import hashlib
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
CODEX_HOME = Path("/home/ubuntu/.codex")


class RuntimeProfileCutoverTests(unittest.TestCase):
    def test_role_profile_templates_match_installed_official_profile_files(self) -> None:
        registry = tomllib.loads(
            (ROOT / "references" / "twinfinity-executor-registry.toml").read_text(
                encoding="utf-8"
            )
        )
        for role in ("planner", "development", "sre"):
            endpoint = registry["roles"][role]
            profile_name = endpoint["codex_profile"]
            template = ROOT / "references" / f"{profile_name}.config.toml"
            installed = CODEX_HOME / f"{profile_name}.config.toml"
            expected_digest = endpoint["profile_sha256"]
            with self.subTest(role=role):
                self.assertEqual(template.read_bytes(), installed.read_bytes())
                self.assertEqual(
                    expected_digest,
                    hashlib.sha256(installed.read_bytes()).hexdigest(),
                )
                profile = tomllib.loads(installed.read_text(encoding="utf-8"))
                self.assertEqual("on-request", profile["approval_policy"])
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
                    self.assertNotIn("hooks", profile)
                    self.assertEqual(
                        ["/home/ubuntu/.codex/twinfinity-coordination"],
                        profile["sandbox_workspace_write"]["writable_roots"],
                    )
                else:
                    hooks = profile["hooks"]["PreToolUse"]
                    self.assertEqual(1, len(hooks))
                    self.assertTrue(
                        hooks[0]["hooks"][0]["command"].endswith(
                            "/scripts/delivery_guard.py"
                        )
                    )
                command = endpoint["command_prefix"]
                self.assertEqual(profile_name, command[command.index("--profile") + 1])

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
