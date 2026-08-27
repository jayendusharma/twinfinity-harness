from __future__ import annotations

from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import run_harness_baseline_validations as baseline_runner


class HarnessBaselineValidationRunnerTests(unittest.TestCase):
    def test_environment_is_private_and_minimal(self) -> None:
        temp_root = Path("/tmp/twinfinity-harness-baseline-test")
        with patch.dict(
            os.environ,
            {
                "HOME": "/home/ambient",
                "PATH": "/usr/local/bin:/usr/bin",
                "PYTHONHOME": "/unsafe/pythonhome",
            },
            clear=True,
        ):
            environment = baseline_runner._environment(temp_root)

        self.assertEqual(str(temp_root), environment["HOME"])
        self.assertEqual(str(temp_root), environment["TMPDIR"])
        self.assertEqual("1", environment["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual("/usr/local/bin:/usr/bin", environment["PATH"])
        self.assertNotIn("PYTHONHOME", environment)


if __name__ == "__main__":
    unittest.main()
