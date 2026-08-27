from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import run_hermetic_tests


class HermeticTestRunnerTests(unittest.TestCase):
    def test_runner_uses_private_environment(self) -> None:
        observed: dict[str, str] = {}

        def capture_run(_argv, **kwargs):
            observed.update(kwargs["env"])
            return subprocess.CompletedProcess(_argv, 0)

        with (
            patch("run_hermetic_tests.install_reviewed_profiles"),
            patch("run_hermetic_tests.validate_test_registry"),
            patch("run_hermetic_tests.subprocess.run", side_effect=capture_run),
            patch.dict(
                os.environ,
                {
                    "HOME": "/home/ambient",
                    "PATH": "/usr/local/bin:/usr/bin",
                    "PYTHONHOME": "/unsafe/pythonhome",
                    "PYTHONPATH": "/unsafe/pythonpath",
                },
                clear=True,
            ),
        ):
            self.assertEqual(
                0, run_hermetic_tests.run_tests(("tests.test_repository_delivery_policy",))
            )

        self.assertEqual(
            {"HOME", "PATH", "CODEX_HOME", "PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "TMPDIR"},
            set(observed),
        )
        self.assertTrue(observed["CODEX_HOME"].startswith(observed["HOME"]))
        self.assertTrue(observed["TMPDIR"].startswith(observed["HOME"]))
        self.assertEqual("1", observed["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual("/usr/local/bin:/usr/bin", observed["PATH"])
        self.assertEqual(
            os.fspath(run_hermetic_tests.TEST_ROOT), observed["PYTHONPATH"]
        )


if __name__ == "__main__":
    unittest.main()
