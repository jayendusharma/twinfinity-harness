from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
CODEX_HOME = Path(os.environ["CODEX_HOME"])
EXPECTED_ENDPOINTS = {
    "planner": ("role.planner.v2", 2),
    "development": ("role.development.v4", 4),
    "sre": ("role.sre.v4", 4),
}
class RuntimeProfileCutoverTests(unittest.TestCase):
    def test_staged_role_profiles_are_digest_bound_v4_cutover_inputs(self) -> None:
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
                    instructions = profile["developer_instructions"]
                    self.assertIn("current-endpoint target", instructions)
                    self.assertIn("non-authorizing coordination.notice", instructions)
                    self.assertIn("read-only", instructions)
                    self.assertIn("writer WIP", instructions)
                    self.assertIn("Every mutation requires", instructions)
                    self.assertIn("resume a legacy Codex thread", instructions)
                    if role == "development":
                        self.assertIn(
                            "zero Development and Shared writer WIP", instructions
                        )
                    else:
                        self.assertIn("zero SRE writer WIP", instructions)
                        self.assertIn("authorized read-only operational-audit", instructions)
                command = endpoint["command_prefix"]
                self.assertEqual(profile_name, command[command.index("--profile") + 1])

        history = {
            endpoint["endpoint_id"]: endpoint
            for endpoint in registry["historical_endpoints"]
        }
        self.assertEqual(
            {"role.development.v3", "role.sre.v3"}, set(history)
        )
        for endpoint in history.values():
            versioned = (
                ROOT
                / "references"
                / f"{endpoint['codex_profile']}-v{endpoint['version']}.config.toml"
            )
            self.assertEqual(
                endpoint["profile_sha256"],
                hashlib.sha256(versioned.read_bytes()).hexdigest(),
            )

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
