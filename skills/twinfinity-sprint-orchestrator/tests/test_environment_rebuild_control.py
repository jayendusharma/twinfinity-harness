from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from environment_rebuild_control import (  # noqa: E402
    EnvironmentRebuildError,
    _audit_tree,
    _capture,
    _exact_environment,
    _private_root,
    _validate_controller_contract,
    _validate_git_lineage,
    validate_packet,
)
from coordination_store import digest_json  # noqa: E402


class EnvironmentRebuildControlTests(unittest.TestCase):
    def test_controller_contract_binds_repository_delivery_policy(self) -> None:
        paths = {
            "coordination_store_sha256": SCRIPTS / "coordination_store.py",
            "coordination_supervisor_sha256": SCRIPTS / "coordination_supervisor.py",
            "environment_rebuild_control_sha256": (
                SCRIPTS / "environment_rebuild_control.py"
            ),
            "prepush_control_sha256": SCRIPTS / "prepush_control.py",
            "repository_delivery_policy_sha256": (
                SCRIPTS / "repository_delivery_policy.py"
            ),
        }
        contract = {
            field: hashlib.sha256(path.read_bytes()).hexdigest()
            for field, path in paths.items()
        }
        _validate_controller_contract({"controller_contract": contract})

        with self.assertRaisesRegex(
            EnvironmentRebuildError, "CONTROLLER_CONTRACT_DRIFT"
        ):
            _validate_controller_contract(
                {
                    "controller_contract": {
                        **contract,
                        "repository_delivery_policy_sha256": "0" * 64,
                    }
                }
            )

    def test_packet_digest_and_installer_environment_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract = {
                "sanitized_environment": {
                    "launcher": "/usr/bin/env -i",
                    "HOME": "/home/ubuntu",
                    "PATH": "/usr/bin:/bin",
                    "UV_CACHE_DIR": "/home/ubuntu/.codex/twinfinity-issue58-prepush-uv-cache-v3",
                    "UV_HTTP_TIMEOUT": "300",
                    "ambient_uv_pip_python_index_constraint_state": "ABSENT",
                }
            }
            packet = {
                "recovery_contract": contract,
                "recovery_contract_sha256": digest_json(contract),
            }
            path = Path(directory) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            observed, observed_contract = validate_packet(path, expected)
            self.assertEqual(packet, observed)
            self.assertEqual(contract, observed_contract)
            self.assertEqual(
                {
                    "HOME": "/home/ubuntu",
                    "PATH": "/usr/bin:/bin",
                    "UV_CACHE_DIR": "/home/ubuntu/.codex/twinfinity-issue58-prepush-uv-cache-v3",
                    "UV_HTTP_TIMEOUT": "300",
                },
                _exact_environment(contract),
            )

    def test_packet_and_environment_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            path.write_text(
                json.dumps(
                    {
                        "recovery_contract": {"mode": "test"},
                        "recovery_contract_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(EnvironmentRebuildError, "DIGEST_MISMATCH"):
                validate_packet(path, expected)
            with self.assertRaisesRegex(EnvironmentRebuildError, "CONTRACT_INVALID"):
                _exact_environment({"sanitized_environment": {**os.environ}})

    def test_tree_audit_rejects_hardlinks_and_foreign_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            first.write_text("value", encoding="utf-8")
            second = root / "second"
            os.link(first, second)
            with self.assertRaisesRegex(EnvironmentRebuildError, "HARDLINK_INVALID"):
                _audit_tree(root)
            second.unlink()
            link = root / "foreign"
            link.symlink_to("/usr/bin/env")
            with self.assertRaisesRegex(EnvironmentRebuildError, "FOREIGN_SYMLINK"):
                _audit_tree(root)

    def test_tree_audit_accepts_standard_internal_lib64_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            (root / "lib").mkdir()
            (root / "lib64").symlink_to("lib", target_is_directory=True)
            observed = _audit_tree(root)
            self.assertEqual(1, observed["directories"])

    def test_private_root_distinguishes_new_execution_from_reconciliation(self) -> None:
        with self.assertRaisesRegex(EnvironmentRebuildError, "ROOT_NOT_CLEAN"):
            _private_root(
                "/home/ubuntu/.codex/not-the-bound-root",
                "twinfinity-issue58-prepush-venv-v3",
                must_be_absent=False,
            )

    def test_git_lineage_rejects_unbound_worktree_identity(self) -> None:
        with self.assertRaisesRegex(EnvironmentRebuildError, "GIT_LINEAGE_INVALID"):
            _validate_git_lineage(
                {
                    "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-58",
                    "opaque_worktree_id": "different-worktree",
                    "candidate_head_sha": "0" * 40,
                    "branch": "codex/58-example",
                    "base_sha": "1" * 40,
                }
            )

    def test_capture_hash_input_excludes_stderr_diagnostics(self) -> None:
        log = io.BytesIO()
        output = _capture(
            [
                "/usr/bin/python3",
                "-c",
                "import sys; print('package==1'); print('diagnostic', file=sys.stderr)",
            ],
            environment={"PATH": "/usr/bin:/bin"},
            timeout_seconds=30,
            log=log,
        )
        self.assertEqual(b"package==1\n", output)
        self.assertIn(b"diagnostic", log.getvalue())


if __name__ == "__main__":
    unittest.main()
