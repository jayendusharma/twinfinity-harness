from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = SKILL_ROOT / "scripts" / "validate_tracker_reconciliation.py"
SPEC = importlib.util.spec_from_file_location("validate_tracker_reconciliation", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

MAIN = "e38d05da9e0be9d450bb22d752c35154e733a50e"
OLD_MAIN = "de457a0000000000000000000000000000000000"
STATE = "#88 DONE/MERGED/CLEANED/RELEASED"
CAPACITY = "active D0/S0; retained D2/S1; available D3/S1; READY 0"


class TrackerReconciliationValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.projection = validator.parse_projection(
            MAIN, STATE, CAPACITY, development_limit=5, shared_limit=2
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_bodies(self, overrides: dict[int, str] | None = None):
        overrides = overrides or {}
        paths: dict[int, Path] = {}
        for issue in validator.REQUIRED_ISSUES:
            body = (
                f"# Tracker #{issue}\n\n"
                f"{validator.canonical_block(self.projection)}"
                "## Current portfolio\n\nCurrent projection verified.\n\n"
                f"{validator.HISTORICAL_BOUNDARY}\n\n"
                f"Accepted main: `{OLD_MAIN}`\n"
                "State: #88 PREPARED / HOLD\n"
                "Capacity: active D0/S0; retained D4/S2; available D1/S0; READY 0\n"
            )
            path = self.root / f"{issue}.md"
            path.write_text(overrides.get(issue, body), encoding="utf-8")
            paths[issue] = path
        return paths

    def test_five_exact_rendered_bodies_are_complete(self) -> None:
        result = validator.validate_bodies(self.write_bodies(), self.projection)
        self.assertEqual(result.outcome, validator.Outcome.COMPLETE)
        self.assertEqual(result.stale_issues, ())

    def test_comment_only_terminal_receipts_do_not_satisfy_bodies(self) -> None:
        stale = (
            "# Stale tracker\n\n"
            f"Verified: accepted main is `{OLD_MAIN}`.\n"
            "Verified: #88 is PREPARED / HOLD.\n"
            "Portfolio is Development 4/5, Shared 2/2.\n"
        )
        paths = self.write_bodies(
            {issue: stale for issue in validator.REQUIRED_ISSUES}
        )
        result = validator.validate_bodies(paths, self.projection)
        self.assertEqual(result.outcome, validator.Outcome.TRACKER_BODY_PENDING)
        self.assertEqual(result.stale_issues, validator.REQUIRED_ISSUES)

    def test_one_stale_body_lists_only_179(self) -> None:
        stale = (
            "# Decision dashboard\n\n"
            f"Accepted main: `{OLD_MAIN}`\n"
            "State: #88 PREPARED / HOLD\n"
            "Capacity: active D0/S0; retained D4/S2; available D1/S0; READY 0\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({179: stale}), self.projection
        )
        self.assertEqual(result.outcome, validator.Outcome.TRACKER_BODY_PENDING)
        self.assertEqual(result.stale_issues, (179,))
        body = next(item for item in result.bodies if item.issue == 179)
        self.assertIn("missing canonical current-control block", body.reasons)

    def test_exact_block_plus_old_current_main_is_pending(self) -> None:
        body = (
            f"{validator.canonical_block(self.projection)}"
            f"Current main: `{OLD_MAIN}`\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({44: body}), self.projection
        )
        self.assertEqual(result.stale_issues, (44,))
        self.assertTrue(
            any("contradictory accepted main" in reason for reason in result.bodies[0].reasons)
        )

    def test_contradiction_before_historical_boundary_is_pending(self) -> None:
        body = (
            f"{validator.canonical_block(self.projection)}"
            f"Current main: `{OLD_MAIN}`\n"
            f"{validator.HISTORICAL_BOUNDARY}\n"
            "Historical archive.\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({44: body}), self.projection
        )
        self.assertEqual(result.stale_issues, (44,))

    def test_duplicate_historical_boundary_is_pending(self) -> None:
        body = (
            f"{validator.canonical_block(self.projection)}"
            f"{validator.HISTORICAL_BOUNDARY}\n"
            f"{validator.HISTORICAL_BOUNDARY}\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({61: body}), self.projection
        )
        self.assertEqual(result.stale_issues, (61,))
        selected = next(item for item in result.bodies if item.issue == 61)
        self.assertIn(
            "expected at most one historical boundary, found 2", selected.reasons
        )

    def test_mid_line_historical_marker_cannot_hide_contradictions(self) -> None:
        body = (
            f"{validator.canonical_block(self.projection)}"
            f"Quoted marker: {validator.HISTORICAL_BOUNDARY}\n"
            f"Current main: `{OLD_MAIN}`\n"
            "#88 is HOLD.\n"
            "Capacity: active D0/S0; retained D4/S2; available D1/S0; READY 0\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({120: body}), self.projection
        )
        self.assertEqual(result.stale_issues, (120,))

    def test_duplicate_current_control_blocks_are_pending(self) -> None:
        duplicated = validator.canonical_block(self.projection) * 2
        result = validator.validate_bodies(
            self.write_bodies({61: duplicated}), self.projection
        )
        self.assertEqual(result.stale_issues, (61,))

    def test_invalid_capacity_accounting_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "account exactly to 5"):
            validator.parse_projection(
                MAIN,
                STATE,
                "active D1/S0; retained D2/S1; available D3/S1; READY 0",
                development_limit=5,
                shared_limit=2,
            )

    def test_capacity_accounting_uses_active_policy_limits(self) -> None:
        projection = validator.parse_projection(
            MAIN,
            STATE,
            "active D1/S1; retained D0/S0; available D5/S2; READY 0",
            development_limit=6,
            shared_limit=3,
        )
        self.assertEqual(projection.development_limit, 6)
        self.assertEqual(projection.shared_limit, 3)

    def test_terminal_and_hold_projection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "terminal state tokens"):
            validator.parse_projection(
                MAIN,
                "#88 DONE / HOLD",
                CAPACITY,
                development_limit=5,
                shared_limit=2,
            )

    def test_negated_projection_state_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive, not negated"):
            validator.parse_projection(
                MAIN,
                "#88 not DONE",
                CAPACITY,
                development_limit=5,
                shared_limit=2,
            )

    def test_past_prepared_does_not_hide_current_hold(self) -> None:
        body = (
            f"{validator.canonical_block(self.projection)}"
            "#88 was PREPARED, now HOLD.\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({44: body}), self.projection
        )
        self.assertEqual(result.stale_issues, (44,))
        self.assertTrue(
            any("HOLD" in reason for reason in result.bodies[0].reasons)
        )

    def test_fenced_example_block_does_not_satisfy_body(self) -> None:
        fenced = (
            "# Tracker documentation\n\n"
            "```markdown\n"
            f"{validator.canonical_block(self.projection)}"
            "```\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({131: fenced}), self.projection
        )
        self.assertEqual(result.stale_issues, (131,))
        body = next(item for item in result.bodies if item.issue == 131)
        self.assertIn("missing canonical current-control block", body.reasons)

    def test_four_space_backticks_do_not_close_commonmark_fence(self) -> None:
        fenced = (
            "```text\n"
            "    ```\n"
            f"{validator.canonical_block(self.projection)}"
            "```\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({44: fenced}), self.projection
        )
        self.assertEqual(result.stale_issues, (44,))
        self.assertIn(
            "missing canonical current-control block", result.bodies[0].reasons
        )

    def test_explicit_negation_of_old_state_is_not_a_contradiction(self) -> None:
        body = (
            f"{validator.canonical_block(self.projection)}"
            "#88 is no longer PREPARED.\n"
        )
        result = validator.validate_bodies(
            self.write_bodies({120: body}), self.projection
        )
        self.assertEqual(result.outcome, validator.Outcome.COMPLETE)

    def test_body_set_must_be_exact(self) -> None:
        paths = self.write_bodies()
        paths.pop(179)
        with self.assertRaisesRegex(ValueError, r"missing=\[179\]"):
            validator.validate_bodies(paths, self.projection)

    def test_snapshot_validation_is_bound_to_the_captured_bytes(self) -> None:
        paths = self.write_bodies()
        snapshots = {issue: path.read_bytes() for issue, path in paths.items()}
        paths[44].write_text("# changed after snapshot\n", encoding="utf-8")
        result = validator.validate_body_snapshots(paths, snapshots, self.projection)
        self.assertEqual(result.outcome, validator.Outcome.COMPLETE)
        body = next(item for item in result.bodies if item.issue == 44)
        self.assertEqual(
            body.sha256,
            __import__("hashlib").sha256(snapshots[44]).hexdigest(),
        )

    def test_cli_pending_exit_and_json_are_deterministic(self) -> None:
        paths = self.write_bodies({179: "# stale\n"})
        command = [sys.executable, str(MODULE_PATH)]
        for issue in validator.REQUIRED_ISSUES:
            command.extend(["--body", f"{issue}={paths[issue]}"])
        command.extend(
            [
                "--accepted-main",
                MAIN,
                "--state",
                STATE,
                "--capacity",
                CAPACITY,
                "--development-limit",
                "5",
                "--shared-limit",
                "2",
            ]
        )
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 3)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["outcome"], "TRACKER_BODY_PENDING")
        self.assertEqual(payload["stale_issues"], [179])


if __name__ == "__main__":
    unittest.main()
