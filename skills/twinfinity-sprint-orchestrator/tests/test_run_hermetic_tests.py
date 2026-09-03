from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import run_hermetic_tests


class HermeticTestRunnerTests(unittest.TestCase):
    def test_runner_uses_private_environment(self) -> None:
        observed: dict[str, str] = {}
        observed_argv: list[str] = []

        def capture_run(_argv, **kwargs):
            observed_argv.extend(_argv)
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
            {
                "HOME",
                "PATH",
                "CODEX_HOME",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONPATH",
                "TMPDIR",
                "VIRTUAL_ENV",
            },
            set(observed),
        )
        self.assertTrue(observed["CODEX_HOME"].startswith(observed["HOME"]))
        self.assertTrue(observed["TMPDIR"].startswith(observed["HOME"]))
        self.assertTrue(observed["VIRTUAL_ENV"].startswith(observed["HOME"]))
        self.assertEqual(
            os.fspath(Path(observed["VIRTUAL_ENV"]) / "bin" / "python"),
            observed_argv[0],
        )
        self.assertEqual("1", observed["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual("/usr/local/bin:/usr/bin", observed["PATH"])
        self.assertEqual(
            os.fspath(run_hermetic_tests.TEST_ROOT), observed["PYTHONPATH"]
        )

    def test_runner_bounds_issue_owned_park_socket_path(self) -> None:
        observed: dict[str, str] = {}
        observed_root: dict[str, int] = {}

        def capture_run(_argv, **kwargs):
            observed.update(kwargs["env"])
            metadata = Path(kwargs["env"]["HOME"]).stat()
            observed_root.update(
                {"mode": metadata.st_mode & 0o777, "uid": metadata.st_uid}
            )
            return subprocess.CompletedProcess(_argv, 0)

        with tempfile.TemporaryDirectory(
            prefix="twinfinity-issue177-", dir="/tmp"
        ) as root:
            issue_root = Path(root)
            outer_tmp = issue_root / "tmp"
            outer_tmp.mkdir(mode=0o700)
            with (
                patch("run_hermetic_tests.install_reviewed_profiles"),
                patch("run_hermetic_tests.validate_test_registry"),
                patch("run_hermetic_tests.subprocess.run", side_effect=capture_run),
                patch.object(run_hermetic_tests.tempfile, "tempdir", None),
                patch.dict(os.environ, {"TMPDIR": os.fspath(outer_tmp)}),
            ):
                self.assertEqual(0, run_hermetic_tests.run_tests(()))

            private_root = Path(observed["HOME"])
            test_tmp = Path(observed["TMPDIR"])
            maximum_park_socket = (
                test_tmp
                / "tmpabcdefgh"
                / "coordination"
                / "park-cap-abcdefgh"
                / "gate.sock"
            )
            self.assertEqual(Path("/tmp"), private_root.parent)
            self.assertFalse(private_root.is_relative_to(issue_root))
            self.assertEqual({"mode": 0o700, "uid": os.getuid()}, observed_root)
            self.assertTrue(Path(observed["CODEX_HOME"]).is_relative_to(private_root))
            self.assertTrue(Path(observed["VIRTUAL_ENV"]).is_relative_to(private_root))
            self.assertTrue(test_tmp.is_relative_to(private_root))
            self.assertLessEqual(len(os.fsencode(maximum_park_socket)), 107)


if __name__ == "__main__":
    unittest.main()
