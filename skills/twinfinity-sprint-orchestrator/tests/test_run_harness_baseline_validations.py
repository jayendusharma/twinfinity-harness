from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import run_harness_baseline_validations as baseline_runner


class HarnessBaselineValidationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository_root = Path(__file__).resolve().parents[3]
        self.catalog_path = self.repository_root / baseline_runner.CATALOG_RELATIVE_PATH
        self.runner_path = self.repository_root / baseline_runner.RUNNER_RELATIVE_PATH
        self.catalog = baseline_runner.load_catalog(self.repository_root)

    def test_environment_is_private_minimal_and_git_is_scrubbed(self) -> None:
        temp_root = Path("/tmp/twinfinity-harness-baseline-test")
        with patch.dict(
            os.environ,
            {
                "HOME": "/home/ambient",
                "PATH": "/malicious/bin:/usr/bin",
                "PYTHONHOME": "/unsafe/pythonhome",
                "GIT_DIR": "/tmp/redirected",
            },
            clear=True,
        ):
            environment = baseline_runner._environment(temp_root)
            git_environment = baseline_runner._git_environment()
        self.assertEqual(str(temp_root), environment["HOME"])
        self.assertEqual(str(temp_root), environment["TMPDIR"])
        self.assertEqual("1", environment["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual(str(temp_root / "pycache"), environment["PYTHONPYCACHEPREFIX"])
        self.assertEqual("/usr/bin:/bin", environment["PATH"])
        self.assertNotIn("PYTHONHOME", environment)
        self.assertNotIn("GIT_DIR", git_environment)
        self.assertEqual("1", git_environment["GIT_NO_REPLACE_OBJECTS"])

    def test_catalog_is_exact_ordered_eleven_skills_plus_registry(self) -> None:
        self.assertEqual(1, self.catalog.version)
        self.assertEqual(12, len(self.catalog.entries))
        self.assertEqual(
            ("skill-validator",) * 11 + ("executor-registry-audit",),
            tuple(entry.kind for entry in self.catalog.entries),
        )
        self.assertEqual(11, len(set(self.catalog.skill_roots)))
        self.assertEqual("registry:audit-config", self.catalog.entries[-1].entry_id)
        self.assertEqual(
            ("runtime", "tool", "target"),
            self.catalog.entries[0].argv_root_roles(),
        )
        self.assertEqual(
            (
                "runtime",
                "tool",
                "literal",
                "target",
                "literal",
                "target",
                "literal",
            ),
            self.catalog.entries[-1].argv_root_roles(),
        )
        for relative in (
            baseline_runner.CATALOG_RELATIVE_PATH,
            baseline_runner.RUNNER_RELATIVE_PATH,
            ".github/workflows/validate-skills.yml",
        ):
            self.assertTrue(baseline_runner.catalog_matches_path(self.catalog, relative))

    def _write_catalog_root(
        self, payload: dict | None = None
    ) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        destination = root / baseline_runner.CATALOG_RELATIVE_PATH
        destination.parent.mkdir(parents=True)
        if payload is None:
            destination.write_bytes(self.catalog_path.read_bytes())
        else:
            destination.write_text(json.dumps(payload), encoding="utf-8")
        return temporary

    def test_catalog_schema_membership_and_numeric_types_fail_closed(self) -> None:
        original = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        mutations: dict[str, dict] = {}
        missing = copy.deepcopy(original)
        missing["entries"].pop(0)
        mutations["missing"] = missing
        duplicate = copy.deepcopy(original)
        duplicate["entries"][1] = copy.deepcopy(duplicate["entries"][0])
        mutations["duplicate"] = duplicate
        registry_not_last = copy.deepcopy(original)
        registry_not_last["entries"][0], registry_not_last["entries"][-1] = (
            registry_not_last["entries"][-1],
            registry_not_last["entries"][0],
        )
        mutations["registry-not-last"] = registry_not_last
        unknown_field = copy.deepcopy(original)
        unknown_field["unexpected"] = True
        mutations["unknown-field"] = unknown_field
        boolean_version = copy.deepcopy(original)
        boolean_version["catalog_version"] = True
        mutations["boolean-version"] = boolean_version
        floating_timeout = copy.deepcopy(original)
        floating_timeout["entry_timeout_seconds"] = 1.0
        mutations["floating-timeout"] = floating_timeout
        parent_path = copy.deepcopy(original)
        parent_path["entries"][0]["arguments"][1] = "../escape"
        parent_path["entries"][0]["id"] = "skill:escape"
        mutations["parent-path"] = parent_path
        for name, payload in mutations.items():
            with self.subTest(name=name), self._write_catalog_root(payload) as root:
                with self.assertRaises(baseline_runner.BaselineError):
                    baseline_runner.load_catalog(Path(root))

    def test_exact_base_catalog_rejects_substitution_and_reordering(self) -> None:
        original = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        substituted = copy.deepcopy(original)
        substituted["entries"][0]["id"] = "skill:replacement"
        substituted["entries"][0]["arguments"][1] = "skills/replacement"
        reordered = copy.deepcopy(original)
        reordered["entries"][0], reordered["entries"][1] = (
            reordered["entries"][1],
            reordered["entries"][0],
        )
        with self._write_catalog_root() as base_root:
            for payload in (substituted, reordered):
                with self.subTest(first=payload["entries"][0]["id"]):
                    with self._write_catalog_root(payload) as candidate_root:
                        candidate = baseline_runner.load_catalog(Path(candidate_root))
                        with self.assertRaisesRegex(
                            baseline_runner.BaselineError,
                            "BASELINE_CATALOG_MUTATION",
                        ):
                            baseline_runner._catalog_compatibility(
                                Path(base_root), candidate
                            )

    def test_execution_command_separates_trusted_tools_from_targets(self) -> None:
        tool = Path("/trusted/base")
        target = Path("/candidate/head")
        skill = baseline_runner.catalog_execution_command(
            self.catalog.entries[0], "python", tool_root=tool, target_root=target
        )
        self.assertEqual(str(tool / baseline_runner.QUICK_VALIDATOR), skill[1])
        self.assertEqual(str(target / self.catalog.entries[0].arguments[1]), skill[2])
        registry = baseline_runner.catalog_execution_command(
            self.catalog.entries[-1], "python", tool_root=tool, target_root=target
        )
        self.assertEqual(str(tool / self.catalog.entries[-1].arguments[0]), registry[1])
        self.assertEqual(str(target / self.catalog.entries[-1].arguments[2]), registry[3])
        self.assertEqual(str(target / self.catalog.entries[-1].arguments[4]), registry[5])

    def test_nonzero_timeout_and_output_cap_fail_closed_without_unbounded_capture(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            tool = root / "tool.py"
            target = root / "target"
            target.mkdir()
            entry = baseline_runner.CatalogEntry(
                entry_id="skill:target",
                kind="skill-validator",
                executable="{python}",
                working_directory=".",
                arguments=("tool.py", "target"),
            )
            environment = baseline_runner._environment(root)
            tool.write_text("raise SystemExit(3)\n", encoding="utf-8")
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_ENTRY_FAILED"
            ):
                baseline_runner._run_entry(root, entry, self.catalog, environment)
            limited = replace(self.catalog, maximum_output_bytes=1024)
            tool.write_text(
                "import os\nwhile True: os.write(1, b'x' * 65536)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_ENTRY_OUTPUT_INCOMPLETE"
            ):
                baseline_runner._run_entry(root, entry, limited, environment)
            timed = replace(self.catalog, entry_timeout_seconds=1)
            tool.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_ENTRY_TIMEOUT"
            ):
                baseline_runner._run_entry(root, entry, timed, environment)

    def test_every_terminal_path_reaps_redirected_background_descendants(self) -> None:
        source = (
            "import os\n"
            "from pathlib import Path\n"
            "import subprocess\n"
            "import sys\n"
            "import time\n"
            "mode, pid_path = sys.argv[1:]\n"
            "with open(os.devnull, 'wb') as sink:\n"
            " child = subprocess.Popen(\n"
            "  [sys.executable, '-c', 'import time; time.sleep(60)'],\n"
            "  stdin=subprocess.DEVNULL, stdout=sink, stderr=sink,\n"
            " )\n"
            "Path(pid_path).write_text(str(child.pid), encoding='utf-8')\n"
            "if mode == 'timeout': time.sleep(30)\n"
            "if mode == 'output':\n"
            " while True: os.write(1, b'x' * 65536)\n"
            "raise SystemExit(0 if mode == 'zero' else 7)\n"
        )
        expected_kinds = {
            "zero": "descendant",
            "nonzero": "descendant",
            "timeout": "timeout",
            "output": "output",
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            environment_root = root / "environment"
            environment_root.mkdir()
            tool = root / "tool.py"
            tool.write_text(source, encoding="utf-8")
            for mode, expected_kind in expected_kinds.items():
                with self.subTest(mode=mode):
                    pid_path = root / f"{mode}.pid"
                    with self.assertRaises(
                        baseline_runner._BoundedProcessError
                    ) as raised:
                        baseline_runner._run_bounded_process(
                            [sys.executable, "-B", str(tool), mode, str(pid_path)],
                            cwd=root,
                            environment=baseline_runner._environment(environment_root),
                            timeout_seconds=1,
                            output_limit=1024,
                        )
                    self.assertEqual(expected_kind, raised.exception.kind)
                    descendant_pid = int(pid_path.read_text(encoding="utf-8"))
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        try:
                            os.kill(descendant_pid, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(0.01)
                    else:
                        self.fail(
                            f"background descendant {descendant_pid} survived {mode}"
                        )

    def test_session_process_group_and_sigterm_escapes_are_reaped(self) -> None:
        source = (
            "import os\n"
            "from pathlib import Path\n"
            "import subprocess\n"
            "import sys\n"
            "import time\n"
            "mode, escape, pid_path = sys.argv[1:]\n"
            "setup = {\n"
            " 'setsid': 'os.setsid()',\n"
            " 'setpgid': 'os.setpgid(0, 0)',\n"
            " 'start-new-session': 'pass',\n"
            "}[escape]\n"
            "child_source = (\n"
            " 'import os, signal, time\\n'\n"
            " 'signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n'\n"
            " + setup + '\\n'\n"
            " + 'time.sleep(60)\\n'\n"
            ")\n"
            "with open(os.devnull, 'wb') as sink:\n"
            " child = subprocess.Popen(\n"
            "  [sys.executable, '-c', child_source],\n"
            "  stdin=subprocess.DEVNULL, stdout=sink, stderr=sink,\n"
            "  start_new_session=(escape == 'start-new-session'),\n"
            " )\n"
            "Path(pid_path).write_text(str(child.pid), encoding='utf-8')\n"
            "if mode == 'timeout': time.sleep(30)\n"
            "if mode == 'output':\n"
            " while True: os.write(1, b'x' * 65536)\n"
            "raise SystemExit(0 if mode == 'zero' else 7)\n"
        )
        expected_kinds = {
            "zero": "descendant",
            "nonzero": "descendant",
            "timeout": "timeout",
            "output": "output",
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            environment_root = root / "environment"
            environment_root.mkdir()
            tool = root / "tool.py"
            tool.write_text(source, encoding="utf-8")
            for mode, expected_kind in expected_kinds.items():
                for escape in ("setsid", "start-new-session", "setpgid"):
                    with self.subTest(mode=mode, escape=escape):
                        pid_path = root / f"{mode}-{escape}.pid"
                        with self.assertRaises(
                            baseline_runner._BoundedProcessError
                        ) as raised:
                            baseline_runner._run_bounded_process(
                                [
                                    sys.executable,
                                    "-B",
                                    str(tool),
                                    mode,
                                    escape,
                                    str(pid_path),
                                ],
                                cwd=root,
                                environment=baseline_runner._environment(
                                    environment_root
                                ),
                                timeout_seconds=1,
                                output_limit=1024,
                            )
                        self.assertEqual(expected_kind, raised.exception.kind)
                        descendant_pid = int(pid_path.read_text(encoding="utf-8"))
                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline:
                            try:
                                os.kill(descendant_pid, 0)
                            except ProcessLookupError:
                                break
                            time.sleep(0.01)
                        else:
                            self.fail(
                                f"escaped descendant {descendant_pid} survived "
                                f"{mode}/{escape}"
                            )

    def _valid_root_receipt(
        self,
        *,
        kind: str = "source-candidate",
        identity: str = "git:" + "a" * 40,
        tool_identity: str = "git:" + "a" * 40,
        target_manifest: str = "b" * 64,
        tool_manifest: str = "b" * 64,
        target_runner: str = "c" * 64,
        tool_runner: str = "c" * 64,
        engine_runner: str = "c" * 64,
        engine_authority: str = "tool-root",
        target_catalog_raw: str | None = None,
        filesystem_identity: str | None = None,
        installer_state_evidence: str | None = None,
    ) -> dict:
        empty = baseline_runner.sha256_bytes(b"")
        results = [
            {
                "id": entry.entry_id,
                "kind": entry.kind,
                "working_directory": entry.working_directory,
                "argv": list(entry.declared_argv()),
                "argv_root_roles": list(entry.argv_root_roles()),
                "return_code": 0,
                "timeout_seconds": self.catalog.entry_timeout_seconds,
                "timed_out": False,
                "output_complete": True,
                "stdout_bytes": 0,
                "stdout_sha256": empty,
                "stderr_bytes": 0,
                "stderr_sha256": empty,
            }
            for entry in self.catalog.entries
        ]
        return {
            "schema": baseline_runner.ROOT_RECEIPT_SCHEMA,
            "verdict": "PASS",
            "target_root": {
                "kind": kind,
                "identity": identity,
                "byte_manifest_scope": "complete-source-tree",
                "byte_manifest_sha256": target_manifest,
                "install_manifest_sha256": None,
                "install_manifest_raw_sha256": None,
                "filesystem_identity_sha256": filesystem_identity,
                "installer_state_evidence_sha256": installer_state_evidence,
            },
            "tool_root": {
                "kind": "source-tool",
                "identity": tool_identity,
                "byte_manifest_scope": "complete-source-tree",
                "byte_manifest_sha256": tool_manifest,
            },
            "runner": {
                "relative_path": baseline_runner.RUNNER_RELATIVE_PATH,
                "target_runner_sha256": target_runner,
                "tool_runner_sha256": tool_runner,
                "engine_runner_sha256": engine_runner,
                "engine_authority": engine_authority,
            },
            "catalog": {
                "schema": baseline_runner.CATALOG_SCHEMA,
                "version": self.catalog.version,
                "raw_sha256": self.catalog.raw_sha256,
                "canonical_sha256": self.catalog.canonical_sha256,
                "command_manifest_sha256": self.catalog.command_manifest_sha256,
                "target_raw_sha256": (
                    self.catalog.raw_sha256
                    if target_catalog_raw is None
                    else target_catalog_raw
                ),
            },
            "result_count": len(results),
            "results": results,
        }

    def _verify_valid_root_receipt(
        self, receipt: dict, expected: dict | None = None
    ) -> None:
        expected = receipt if expected is None else expected
        baseline_runner._verify_root_receipt(
            receipt,
            self.catalog,
            expected_kind=expected["target_root"]["kind"],
            expected_identity=expected["target_root"]["identity"],
            expected_target_manifest_sha256=expected["target_root"]["byte_manifest_sha256"],
            expected_target_manifest_scope=expected["target_root"]["byte_manifest_scope"],
            expected_install_manifest_sha256=expected["target_root"]["install_manifest_sha256"],
            expected_install_manifest_raw_sha256=expected["target_root"]["install_manifest_raw_sha256"],
            expected_filesystem_identity_sha256=expected["target_root"]["filesystem_identity_sha256"],
            expected_installer_state_evidence_sha256=expected["target_root"]["installer_state_evidence_sha256"],
            expected_tool_identity=expected["tool_root"]["identity"],
            expected_tool_manifest_sha256=expected["tool_root"]["byte_manifest_sha256"],
            expected_target_runner_sha256=expected["runner"]["target_runner_sha256"],
            expected_tool_runner_sha256=expected["runner"]["tool_runner_sha256"],
            expected_engine_runner_sha256=expected["runner"]["engine_runner_sha256"],
            expected_engine_authority=expected["runner"]["engine_authority"],
            expected_target_catalog_raw_sha256=expected["catalog"]["target_raw_sha256"],
        )

    def test_receipt_rejects_root_order_output_role_and_runner_tampering(self) -> None:
        valid = self._valid_root_receipt()
        self._verify_valid_root_receipt(valid)
        variants: list[dict] = []
        wrong_root = copy.deepcopy(valid)
        wrong_root["target_root"]["kind"] = "installed-runtime"
        variants.append(wrong_root)
        reordered = copy.deepcopy(valid)
        reordered["results"][0], reordered["results"][1] = (
            reordered["results"][1], reordered["results"][0]
        )
        variants.append(reordered)
        incomplete = copy.deepcopy(valid)
        incomplete["results"][0]["output_complete"] = False
        variants.append(incomplete)
        wrong_role = copy.deepcopy(valid)
        wrong_role["results"][0]["argv_root_roles"][1] = "target"
        variants.append(wrong_role)
        wrong_runner = copy.deepcopy(valid)
        wrong_runner["runner"]["engine_runner_sha256"] = "e" * 64
        variants.append(wrong_runner)
        for receipt in variants:
            with self.subTest(receipt=receipt):
                with self.assertRaises(baseline_runner.BaselineError):
                    self._verify_valid_root_receipt(receipt, valid)

    def _receipt_observation(self, label: str, receipt: dict) -> dict:
        return baseline_runner._direct_root_observation(
            label,
            receipt,
            protocol="root-receipt-v1",
            timeout_seconds=self.catalog.root_execution_budget_seconds,
        )

    def _valid_pair_receipt(self) -> dict:
        base_sha = self._git(
            self.repository_root,
            "rev-parse",
            f"{baseline_runner.TRUSTED_BASE_REF}^{{commit}}",
        )
        head_sha = self._git(self.repository_root, "rev-parse", "HEAD^{commit}")
        git_identity = baseline_runner._derived_pair_git_identity(
            self.repository_root, base_sha, head_sha
        )
        base_runner_sha256 = git_identity["trusted_base_runner_sha256"]
        candidate_runner_sha256 = git_identity["candidate_runner_sha256"]
        base = self._valid_root_receipt(
            kind="accepted-base",
            identity=f"git:{base_sha}",
            tool_identity=f"git:{base_sha}",
            target_manifest="a" * 64,
            tool_manifest="a" * 64,
            target_runner=base_runner_sha256,
            tool_runner=base_runner_sha256,
            engine_runner=base_runner_sha256,
        )
        trusted = self._valid_root_receipt(
            identity=f"git:{head_sha}",
            tool_identity=f"git:{base_sha}",
            target_manifest="c" * 64,
            tool_manifest="a" * 64,
            target_runner=candidate_runner_sha256,
            tool_runner=base_runner_sha256,
            engine_runner=base_runner_sha256,
        )
        candidate = self._valid_root_receipt(
            identity=f"git:{head_sha}",
            tool_identity=f"git:{head_sha}",
            target_manifest="c" * 64,
            tool_manifest="c" * 64,
            target_runner=candidate_runner_sha256,
            tool_runner=candidate_runner_sha256,
            engine_runner=candidate_runner_sha256,
        )
        pair_manifest = {
            "base_sha": base_sha,
            "candidate_head_sha": head_sha,
            "catalog_compatibility": "exact-v1",
            "catalog_raw_sha256": self.catalog.raw_sha256,
            "catalog_canonical_sha256": self.catalog.canonical_sha256,
            "git_identity_sha256": baseline_runner.digest_json(git_identity),
            "accepted_base_receipt_sha256": baseline_runner.digest_json(base),
            "trusted_candidate_receipt_sha256": baseline_runner.digest_json(trusted),
            "candidate_receipt_sha256": baseline_runner.digest_json(candidate),
        }
        return {
            "schema": baseline_runner.PAIR_RECEIPT_SCHEMA,
            "verdict": "PASS",
            "base_sha": base_sha,
            "candidate_head_sha": head_sha,
            "catalog_compatibility": "exact-v1",
            "catalog_raw_sha256": self.catalog.raw_sha256,
            "catalog_canonical_sha256": self.catalog.canonical_sha256,
            "command_manifest_sha256": self.catalog.command_manifest_sha256,
            "git_identity": git_identity,
            "git_identity_sha256": baseline_runner.digest_json(git_identity),
            "legacy_base_runner_observation": None,
            "accepted_base_receipt_observation": self._receipt_observation("ACCEPTED_BASE_RECEIPT", base),
            "trusted_candidate_runner_observation": self._receipt_observation("TRUSTED_CANDIDATE_RUNNER", trusted),
            "candidate_runner_observation": self._receipt_observation("CANDIDATE_RUNNER", candidate),
            "accepted_base_receipt_sha256": baseline_runner.digest_json(base),
            "trusted_candidate_receipt_sha256": baseline_runner.digest_json(trusted),
            "candidate_receipt_sha256": baseline_runner.digest_json(candidate),
            "pair_manifest_sha256": baseline_runner.digest_json(pair_manifest),
            "accepted_base_receipt": base,
            "trusted_candidate_receipt": trusted,
            "candidate_receipt": candidate,
        }

    def _rebind_pair_receipt(self, receipt: dict) -> None:
        compatibility = receipt["catalog_compatibility"]
        base_protocol = (
            "bootstrap-candidate-engine-base-tools"
            if compatibility == "legacy-bootstrap"
            else "root-receipt-v1"
        )
        receipt["accepted_base_receipt_observation"] = (
            baseline_runner._direct_root_observation(
                "ACCEPTED_BASE_RECEIPT",
                receipt["accepted_base_receipt"],
                protocol=base_protocol,
                timeout_seconds=self.catalog.root_execution_budget_seconds,
            )
        )
        receipt["trusted_candidate_runner_observation"] = (
            baseline_runner._direct_root_observation(
                "TRUSTED_CANDIDATE_RUNNER",
                receipt["trusted_candidate_receipt"],
                protocol=base_protocol,
                timeout_seconds=self.catalog.root_execution_budget_seconds,
            )
        )
        receipt["candidate_runner_observation"] = (
            baseline_runner._direct_root_observation(
                "CANDIDATE_RUNNER",
                receipt["candidate_receipt"],
                protocol="root-receipt-v1",
                timeout_seconds=self.catalog.root_execution_budget_seconds,
            )
        )
        for digest_field, component_field in (
            ("accepted_base_receipt_sha256", "accepted_base_receipt"),
            ("trusted_candidate_receipt_sha256", "trusted_candidate_receipt"),
            ("candidate_receipt_sha256", "candidate_receipt"),
        ):
            receipt[digest_field] = baseline_runner.digest_json(
                receipt[component_field]
            )
        pair_manifest = {
            "base_sha": receipt["base_sha"],
            "candidate_head_sha": receipt["candidate_head_sha"],
            "catalog_compatibility": compatibility,
            "catalog_raw_sha256": receipt["catalog_raw_sha256"],
            "catalog_canonical_sha256": receipt["catalog_canonical_sha256"],
            "git_identity_sha256": receipt["git_identity_sha256"],
            "accepted_base_receipt_sha256": receipt[
                "accepted_base_receipt_sha256"
            ],
            "trusted_candidate_receipt_sha256": receipt[
                "trusted_candidate_receipt_sha256"
            ],
            "candidate_receipt_sha256": receipt["candidate_receipt_sha256"],
        }
        receipt["pair_manifest_sha256"] = baseline_runner.digest_json(pair_manifest)

    def _valid_legacy_pair_receipt(self) -> dict:
        receipt = self._valid_pair_receipt()
        receipt["catalog_compatibility"] = "legacy-bootstrap"
        accepted = receipt["accepted_base_receipt"]
        trusted = receipt["trusted_candidate_receipt"]
        accepted["catalog"]["target_raw_sha256"] = None
        accepted["runner"]["engine_authority"] = "bootstrap-candidate"
        trusted["runner"]["engine_authority"] = "bootstrap-candidate"
        accepted["runner"]["engine_runner_sha256"] = receipt["git_identity"][
            "candidate_runner_sha256"
        ]
        trusted["runner"]["engine_runner_sha256"] = receipt["git_identity"][
            "candidate_runner_sha256"
        ]
        empty = baseline_runner.sha256_bytes(b"")
        receipt["legacy_base_runner_observation"] = {
            "label": "ACCEPTED_BASE_RUNNER",
            "return_code": 0,
            "timeout_seconds": 600,
            "timed_out": False,
            "output_complete": True,
            "stdout_bytes": 0,
            "stdout_sha256": empty,
            "stderr_bytes": 0,
            "stderr_sha256": empty,
            "runner_sha256": accepted["runner"]["target_runner_sha256"],
            "protocol": "legacy-base-sha",
        }
        self._rebind_pair_receipt(receipt)
        return receipt

    def test_pair_receipt_requires_trusted_cross_proof_and_exact_cross_bindings(self) -> None:
        receipt = self._valid_pair_receipt()
        baseline_runner.verify_pair_receipt(
            receipt,
            expected_base_sha=receipt["base_sha"],
            expected_candidate_head=receipt["candidate_head_sha"],
            catalog=self.catalog,
            repository_root=self.repository_root,
        )
        missing = copy.deepcopy(receipt)
        missing.pop("trusted_candidate_receipt")
        forged = copy.deepcopy(receipt)
        forged["trusted_candidate_receipt"]["runner"]["tool_runner_sha256"] = "f" * 64
        for candidate in (missing, forged):
            with self.assertRaises(baseline_runner.BaselineError):
                baseline_runner.verify_pair_receipt(
                    candidate,
                    expected_base_sha=receipt["base_sha"],
                    expected_candidate_head=receipt["candidate_head_sha"],
                    catalog=self.catalog,
                    repository_root=self.repository_root,
                )

    def test_pair_receipt_rejects_equal_base_and_forged_git_tool_identity(self) -> None:
        receipt = self._valid_pair_receipt()
        equal_base = copy.deepcopy(receipt)
        equal_base["base_sha"] = equal_base["candidate_head_sha"]
        with self.assertRaisesRegex(
            baseline_runner.BaselineError, "BASELINE_GIT_IDENTITY_MISMATCH"
        ):
            baseline_runner.verify_pair_receipt(
                equal_base,
                expected_base_sha=equal_base["candidate_head_sha"],
                expected_candidate_head=equal_base["candidate_head_sha"],
                catalog=self.catalog,
                repository_root=self.repository_root,
            )

        forged_git = copy.deepcopy(receipt)
        forged_git["git_identity"]["trusted_base_sha"] = "f" * 40
        forged_git["git_identity_sha256"] = baseline_runner.digest_json(
            forged_git["git_identity"]
        )
        self._rebind_pair_receipt(forged_git)
        with self.assertRaisesRegex(
            baseline_runner.BaselineError, "BASELINE_PAIR_GIT_IDENTITY_INVALID"
        ):
            baseline_runner.verify_pair_receipt(
                forged_git,
                expected_base_sha=receipt["base_sha"],
                expected_candidate_head=receipt["candidate_head_sha"],
                catalog=self.catalog,
                repository_root=self.repository_root,
            )

        forged_tool = copy.deepcopy(receipt)
        forged_tool["accepted_base_receipt"]["tool_root"][
            "identity"
        ] = "git:" + "f" * 40
        self._rebind_pair_receipt(forged_tool)
        with self.assertRaises(baseline_runner.BaselineError):
            baseline_runner.verify_pair_receipt(
                forged_tool,
                expected_base_sha=receipt["base_sha"],
                expected_candidate_head=receipt["candidate_head_sha"],
                catalog=self.catalog,
                repository_root=self.repository_root,
            )

    def test_pair_receipt_rejects_rebound_unknown_and_scalar_substitutions(self) -> None:
        receipt = self._valid_pair_receipt()
        baseline_runner.verify_pair_receipt(
            receipt,
            expected_base_sha=receipt["base_sha"],
            expected_candidate_head=receipt["candidate_head_sha"],
            catalog=self.catalog,
            repository_root=self.repository_root,
        )
        component_mutations: dict[str, dict] = {}
        extra_runner = copy.deepcopy(receipt)
        extra_runner["candidate_receipt"]["runner"]["unexpected"] = True
        component_mutations["candidate-extra-runner-field"] = extra_runner
        extra_target = copy.deepcopy(receipt)
        extra_target["candidate_receipt"]["target_root"]["unexpected"] = True
        component_mutations["candidate-extra-root-field"] = extra_target
        extra_tool = copy.deepcopy(receipt)
        extra_tool["candidate_receipt"]["tool_root"]["unexpected"] = True
        component_mutations["candidate-extra-tool-field"] = extra_tool
        extra_catalog = copy.deepcopy(receipt)
        extra_catalog["candidate_receipt"]["catalog"]["unexpected"] = True
        component_mutations["candidate-extra-catalog-field"] = extra_catalog
        extra_result = copy.deepcopy(receipt)
        extra_result["candidate_receipt"]["results"][0]["unexpected"] = True
        component_mutations["candidate-extra-result-field"] = extra_result
        extra_component = copy.deepcopy(receipt)
        extra_component["candidate_receipt"]["unexpected"] = True
        component_mutations["candidate-extra-receipt-field"] = extra_component
        boolean_return = copy.deepcopy(receipt)
        boolean_return["candidate_receipt"]["results"][0]["return_code"] = False
        component_mutations["candidate-boolean-return-code"] = boolean_return
        floating_timeout = copy.deepcopy(receipt)
        floating_timeout["candidate_receipt"]["results"][0][
            "timeout_seconds"
        ] = float(self.catalog.entry_timeout_seconds)
        component_mutations["candidate-floating-timeout"] = floating_timeout
        boolean_catalog_version = copy.deepcopy(receipt)
        boolean_catalog_version["candidate_receipt"]["catalog"]["version"] = True
        component_mutations["candidate-boolean-catalog-version"] = (
            boolean_catalog_version
        )
        floating_result_count = copy.deepcopy(receipt)
        floating_result_count["candidate_receipt"]["result_count"] = float(
            len(self.catalog.entries)
        )
        component_mutations["candidate-floating-result-count"] = (
            floating_result_count
        )
        over_cap_stdout = copy.deepcopy(receipt)
        over_cap_stdout["candidate_receipt"]["results"][0][
            "stdout_bytes"
        ] = (self.catalog.maximum_output_bytes + 1)
        component_mutations["candidate-over-cap-stdout"] = over_cap_stdout
        over_cap_stderr = copy.deepcopy(receipt)
        over_cap_stderr["accepted_base_receipt"]["results"][0][
            "stderr_bytes"
        ] = (self.catalog.maximum_output_bytes + 1)
        component_mutations["accepted-over-cap-stderr"] = over_cap_stderr
        for name, candidate in component_mutations.items():
            with self.subTest(name=name):
                self._rebind_pair_receipt(candidate)
                with self.assertRaises(baseline_runner.BaselineError):
                    baseline_runner.verify_pair_receipt(
                        candidate,
                        expected_base_sha=receipt["base_sha"],
                        expected_candidate_head=receipt["candidate_head_sha"],
                        catalog=self.catalog,
                        repository_root=self.repository_root,
                    )

        observation_mutations: dict[str, dict] = {}
        boolean_return = copy.deepcopy(receipt)
        boolean_return["candidate_runner_observation"]["return_code"] = False
        observation_mutations["observation-boolean-return-code"] = boolean_return
        floating_bytes = copy.deepcopy(receipt)
        floating_bytes["candidate_runner_observation"]["stdout_bytes"] = float(
            floating_bytes["candidate_runner_observation"]["stdout_bytes"]
        )
        observation_mutations["observation-floating-byte-count"] = floating_bytes
        boolean_protocol = copy.deepcopy(receipt)
        boolean_protocol["candidate_runner_observation"]["protocol"] = True
        observation_mutations["observation-boolean-protocol"] = boolean_protocol
        extra_observation = copy.deepcopy(receipt)
        extra_observation["candidate_runner_observation"]["unexpected"] = True
        observation_mutations["observation-extra-field"] = extra_observation
        for name, candidate in observation_mutations.items():
            with self.subTest(name=name), self.assertRaises(
                baseline_runner.BaselineError
            ):
                baseline_runner.verify_pair_receipt(
                    candidate,
                    expected_base_sha=receipt["base_sha"],
                    expected_candidate_head=receipt["candidate_head_sha"],
                    catalog=self.catalog,
                    repository_root=self.repository_root,
                )

        legacy = self._valid_legacy_pair_receipt()
        baseline_runner.verify_pair_receipt(
            legacy,
            expected_base_sha=legacy["base_sha"],
            expected_candidate_head=legacy["candidate_head_sha"],
            catalog=self.catalog,
            repository_root=self.repository_root,
        )
        for name, field, value in (
            ("legacy-extra-field", "unexpected", True),
            ("legacy-boolean-return-code", "return_code", False),
            ("legacy-floating-timeout", "timeout_seconds", 600.0),
            ("legacy-boolean-protocol", "protocol", True),
            (
                "legacy-over-cap-stdout",
                "stdout_bytes",
                self.catalog.maximum_output_bytes + 1,
            ),
            (
                "legacy-over-cap-stderr",
                "stderr_bytes",
                self.catalog.maximum_output_bytes + 1,
            ),
        ):
            candidate = copy.deepcopy(legacy)
            candidate["legacy_base_runner_observation"][field] = value
            with self.subTest(name=name), self.assertRaises(
                baseline_runner.BaselineError
            ):
                baseline_runner.verify_pair_receipt(
                    candidate,
                    expected_base_sha=legacy["base_sha"],
                    expected_candidate_head=legacy["candidate_head_sha"],
                    catalog=self.catalog,
                    repository_root=self.repository_root,
                )

    def test_receipt_write_is_atomic_idempotent_and_concurrent_conflict_safe(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o700)
            receipt = root / "receipt.json"
            baseline_runner._atomic_receipt_write(receipt, b"one\n")
            fsync_kinds: list[str] = []
            real_fsync = os.fsync

            def record_fsync(descriptor: int) -> None:
                fsync_kinds.append(
                    "DIR" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "FILE"
                )
                real_fsync(descriptor)

            with patch.object(
                baseline_runner.os, "fsync", side_effect=record_fsync
            ):
                baseline_runner._atomic_receipt_write(receipt, b"one\n")
            self.assertIn("DIR", fsync_kinds)
            self.assertEqual(b"one\n", receipt.read_bytes())

            def fail_replay_directory_fsync(descriptor: int) -> None:
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise OSError("replay directory fsync failed")
                real_fsync(descriptor)

            with (
                patch.object(
                    baseline_runner.os,
                    "fsync",
                    side_effect=fail_replay_directory_fsync,
                ),
                self.assertRaisesRegex(
                    baseline_runner.BaselineError,
                    "BASELINE_RECEIPT_WRITE_FAILED",
                ),
            ):
                baseline_runner._atomic_receipt_write(receipt, b"one\n")
            baseline_runner._atomic_receipt_write(receipt, b"one\n")
            self.assertEqual(b"one\n", receipt.read_bytes())
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_RECEIPT_CONFLICT"
            ):
                baseline_runner._atomic_receipt_write(receipt, b"two\n")
            self.assertEqual(1, receipt.stat().st_nlink)

            def fail_directory_fsync(descriptor: int) -> None:
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise OSError("interrupted after publication")
                real_fsync(descriptor)

            interrupted = root / "interrupted.json"
            with (
                patch.object(
                    baseline_runner.os,
                    "fsync",
                    side_effect=fail_directory_fsync,
                ),
                self.assertRaisesRegex(
                    baseline_runner.BaselineError,
                    "BASELINE_RECEIPT_WRITE_FAILED",
                ),
            ):
                baseline_runner._atomic_receipt_write(interrupted, b"stable\n")
            self.assertEqual(1, interrupted.stat().st_nlink)
            baseline_runner._atomic_receipt_write(interrupted, b"stable\n")
            self.assertEqual(b"stable\n", interrupted.read_bytes())
            failed = root / "failed.json"
            with (
                patch.object(
                    baseline_runner,
                    "_rename_noreplace",
                    side_effect=OSError("pre-publication failure"),
                ),
                self.assertRaisesRegex(
                    baseline_runner.BaselineError,
                    "BASELINE_RECEIPT_WRITE_FAILED",
                ),
            ):
                baseline_runner._atomic_receipt_write(failed, b"absent\n")
            self.assertFalse(failed.exists())
            self.assertEqual([], list(root.glob(".failed.json.tmp.*")))

            residue = root / ".residue.json.tmp.crashed"
            residue.write_bytes(b"inert\n")
            residue.chmod(0o600)
            baseline_runner._atomic_receipt_write(root / "residue.json", b"new\n")
            self.assertEqual(b"new\n", (root / "residue.json").read_bytes())
            self.assertEqual(b"inert\n", residue.read_bytes())

            unsafe = root / "unsafe.json"
            unsafe.write_bytes(b"same\n")
            unsafe.chmod(0o644)
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_RECEIPT_CONFLICT"
            ):
                baseline_runner._atomic_receipt_write(unsafe, b"same\n")
            hardlink_source = root / "hardlink-source"
            hardlink_source.write_bytes(b"same\n")
            hardlink_source.chmod(0o600)
            os.link(hardlink_source, root / "hardlink.json")
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_RECEIPT_CONFLICT"
            ):
                baseline_runner._atomic_receipt_write(
                    root / "hardlink.json", b"same\n"
                )
        for name, raised in (
            ("identical-replay", FileExistsError()),
            ("failed-publication", OSError("publication failed")),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as container_name:
                container = Path(container_name)
                active = container / "active"
                old = container / "old"
                active.mkdir(mode=0o700)
                receipt = active / "receipt.json"
                if isinstance(raised, FileExistsError):
                    receipt.write_bytes(b"same\n")
                    receipt.chmod(0o600)
                replacement_decoys: list[Path] = []

                def replace_parent(_parent_fd, source_name, _destination_name):
                    active.rename(old)
                    active.mkdir(mode=0o700)
                    decoy = active / source_name
                    decoy.write_bytes(b"replacement-parent decoy\n")
                    decoy.chmod(0o600)
                    replacement_decoys.append(decoy)
                    raise raised

                with (
                    patch.object(
                        baseline_runner,
                        "_rename_noreplace",
                        side_effect=replace_parent,
                    ),
                    self.assertRaisesRegex(
                        baseline_runner.BaselineError,
                        (
                            "BASELINE_RECEIPT_ROOT_UNSAFE"
                            if isinstance(raised, FileExistsError)
                            else "BASELINE_RECEIPT_WRITE_FAILED"
                        ),
                    ),
                ):
                    baseline_runner._atomic_receipt_write(
                        active / "receipt.json", b"same\n"
                    )
                self.assertFalse((active / "receipt.json").exists())
                self.assertEqual([], list(old.glob(".receipt.json.tmp.*")))
                self.assertEqual(1, len(replacement_decoys))
                self.assertEqual(
                    b"replacement-parent decoy\n",
                    replacement_decoys[0].read_bytes(),
                )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o700)
            receipt = root / "receipt.json"
            barrier = threading.Barrier(2)
            real_rename_noreplace = baseline_runner._rename_noreplace
            outcomes: list[str] = []

            def synchronized_rename_noreplace(*args):
                barrier.wait(timeout=5)
                return real_rename_noreplace(*args)

            def writer(payload: bytes) -> None:
                try:
                    baseline_runner._atomic_receipt_write(receipt, payload)
                    outcomes.append("PASS")
                except baseline_runner.BaselineError as exc:
                    outcomes.append(str(exc))

            with patch.object(
                baseline_runner,
                "_rename_noreplace",
                side_effect=synchronized_rename_noreplace,
            ):
                first = threading.Thread(target=writer, args=(b"same\n",))
                second = threading.Thread(target=writer, args=(b"same\n",))
                first.start()
                second.start()
                first.join(timeout=10)
                second.join(timeout=10)
            self.assertEqual(["PASS", "PASS"], sorted(outcomes))
            self.assertEqual(b"same\n", receipt.read_bytes())
            self.assertEqual(1, receipt.stat().st_nlink)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o700)
            receipt = root / "receipt.json"
            barrier = threading.Barrier(2)
            real_rename_noreplace = baseline_runner._rename_noreplace
            outcomes: list[str] = []

            def synchronized_rename_noreplace(*args):
                barrier.wait(timeout=5)
                return real_rename_noreplace(*args)

            def writer(payload: bytes) -> None:
                try:
                    baseline_runner._atomic_receipt_write(receipt, payload)
                    outcomes.append("PASS")
                except baseline_runner.BaselineError as exc:
                    outcomes.append(str(exc))

            with patch.object(
                baseline_runner,
                "_rename_noreplace",
                side_effect=synchronized_rename_noreplace,
            ):
                first = threading.Thread(target=writer, args=(b"first\n",))
                second = threading.Thread(target=writer, args=(b"second\n",))
                first.start()
                second.start()
                first.join(timeout=10)
                second.join(timeout=10)
            self.assertEqual(1, outcomes.count("PASS"))
            self.assertEqual(1, outcomes.count("BASELINE_RECEIPT_CONFLICT"))
            self.assertIn(receipt.read_bytes(), {b"first\n", b"second\n"})
            self.assertEqual(1, receipt.stat().st_nlink)

    def test_symlink_fifo_and_receipt_inside_attested_root_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            target = parent / "target"
            target.mkdir()
            link = parent / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_ROOT_UNSAFE"
            ):
                baseline_runner._validated_root(link)
            fifo = target / "catalog.json"
            os.mkfifo(fifo)
            with self.assertRaises(baseline_runner.BaselineError):
                baseline_runner._read_relative_regular(
                    target, "catalog.json", error="UNSAFE", maximum_bytes=10
                )
            with self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_RECEIPT_INSIDE_ATTESTED_ROOT",
            ):
                baseline_runner._require_receipt_outside_roots(
                    target / "receipt.json", (target,)
                )

    @staticmethod
    def _git(root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            env={
                "HOME": "/nonexistent",
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
        )
        return result.stdout.strip()

    @staticmethod
    def _normalize_fixture_modes(root: Path) -> None:
        for path in root.rglob("*"):
            relative = path.relative_to(root)
            if ".git" in relative.parts:
                continue
            if path.is_file() and not path.is_symlink():
                path.chmod(0o644)

    def test_exact_commit_root_rejects_ignored_overlay_and_ambient_git_redirect(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self._git(root, "init", "-q")
            (root / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
            (root / "tracked.py").write_text("value = 1\n", encoding="utf-8")
            self._normalize_fixture_modes(root)
            self._git(root, "add", ".")
            self._git(root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "base")
            head = self._git(root, "rev-parse", "HEAD")
            with patch.dict(
                os.environ,
                {"GIT_DIR": "/tmp/not-this-repository", "GIT_WORK_TREE": "/tmp"},
                clear=False,
            ):
                self.assertEqual(head, baseline_runner._git(root, "rev-parse", "HEAD"))
            baseline_runner._assert_exact_commit_root(root, head)
            (root / "ignored.py").write_text("malicious = True\n", encoding="utf-8")
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_CANDIDATE_NOT_CLEAN"
            ):
                baseline_runner._assert_exact_commit_root(root, head)

    def _install_manifest(
        self, tool_root: Path, target_root: Path, paths: tuple[str, ...]
    ) -> baseline_runner.InstallManifest:
        entries: list[dict] = []
        for relative in paths:
            source = tool_root / relative
            destination = target_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o644)
            entries.append(
                {
                    "source_path": relative,
                    "destination_path": relative,
                    "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "source_mode": 0o644,
                    "destination_mode": 0o644,
                    "destination_uid": os.getuid(),
                    "destination_gid": os.getgid(),
                    "destination_prior": {"state": "ABSENT"},
                }
            )
        return baseline_runner.InstallManifest(
            atom_id="fixture",
            source_commit="1" * 40,
            manifest_sha256="2" * 64,
            raw_sha256="3" * 64,
            entries=tuple(entries),
        )

    def test_install_manifest_scopes_mutable_root_and_rejects_wrong_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tool_name, tempfile.TemporaryDirectory() as target_name:
            tool_root = Path(tool_name)
            target_root = Path(target_name)
            relative = "skills/tool.py"
            source = tool_root / relative
            source.parent.mkdir(parents=True)
            source.write_text("value = 1\n", encoding="utf-8")
            source.chmod(0o644)
            manifest = self._install_manifest(tool_root, target_root, (relative,))
            mutable = target_root / "unrelated.pipe"
            os.mkfifo(mutable)
            try:
                with patch.object(baseline_runner, "_required_target_files", return_value={relative}):
                    digest = baseline_runner._install_manifest_byte_manifest(
                        tool_root, target_root, self.catalog, manifest
                    )
                    self.assertRegex(digest, r"^[0-9a-f]{64}$")
                    (target_root / relative).write_text("substituted\n", encoding="utf-8")
                    with self.assertRaisesRegex(
                        baseline_runner.BaselineError,
                        "BASELINE_INSTALL_MANIFEST_BYTE_MISMATCH",
                    ):
                        baseline_runner._install_manifest_byte_manifest(
                            tool_root, target_root, self.catalog, manifest
                        )
            finally:
                mutable.unlink()

    def test_install_closure_is_source_derived_and_rejects_coordination_store_omission(self) -> None:
        with tempfile.TemporaryDirectory() as tool_name, tempfile.TemporaryDirectory() as target_name:
            tool_root = Path(tool_name)
            target_root = Path(target_name)
            included = "skills/twinfinity-sprint-orchestrator/scripts/runner.py"
            omitted = (
                "skills/twinfinity-sprint-orchestrator/scripts/"
                "coordination_store.py"
            )
            source = tool_root / included
            source.parent.mkdir(parents=True)
            source.write_text("value = 1\n", encoding="utf-8")
            source.chmod(0o644)
            manifest = self._install_manifest(
                tool_root, target_root, (included,)
            )
            with patch.object(
                baseline_runner,
                "_required_target_files",
                return_value={included, omitted},
            ) as required:
                with self.assertRaisesRegex(
                    baseline_runner.BaselineError,
                    "BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE",
                ):
                    baseline_runner._install_manifest_byte_manifest(
                        tool_root, target_root, self.catalog, manifest
                    )
            required.assert_called_once_with(tool_root, self.catalog)

    def test_install_closure_rejects_required_path_permutation(self) -> None:
        with tempfile.TemporaryDirectory() as tool_name, tempfile.TemporaryDirectory() as target_name:
            tool_root = Path(tool_name)
            target_root = Path(target_name)
            first = "skills/twinfinity-sprint-orchestrator/scripts/coordination_store.py"
            second = "skills/twinfinity-sprint-orchestrator/scripts/coordination_transfer.py"
            for relative, contents in ((first, "first\n"), (second, "second\n")):
                source = tool_root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(contents, encoding="utf-8")
                source.chmod(0o644)
            identity = self._install_manifest(tool_root, target_root, (first, second))
            with patch.object(
                baseline_runner,
                "_required_target_files",
                return_value={first, second},
            ):
                self.assertRegex(
                    baseline_runner._install_manifest_byte_manifest(
                        tool_root, target_root, self.catalog, identity
                    ),
                    r"^[0-9a-f]{64}$",
                )

                first_entry, second_entry = identity.entries
                permutation = replace(
                    identity,
                    entries=(
                        {
                            **first_entry,
                            "destination_path": second,
                        },
                        {
                            **second_entry,
                            "destination_path": first,
                        },
                    ),
                )
                (target_root / first).write_bytes((tool_root / second).read_bytes())
                (target_root / second).write_bytes((tool_root / first).read_bytes())
                with self.assertRaisesRegex(
                    baseline_runner.BaselineError,
                    "BASELINE_INSTALL_MANIFEST_COVERAGE_INCOMPLETE",
                ):
                    baseline_runner._install_manifest_byte_manifest(
                        tool_root, target_root, self.catalog, permutation
                    )

    def test_install_manifest_file_digest_is_semantically_verified(self) -> None:
        payload = {
            "schema": baseline_runner.INSTALL_MANIFEST_SCHEMA,
            "manifest_sha256": "0" * 64,
            "atom_id": "fixture",
            "source_commit": "1" * 40,
            "entries": [
                {
                    "source_path": "source.py",
                    "destination_path": "installed.py",
                    "source_sha256": "2" * 64,
                    "source_mode": 0o644,
                    "destination_mode": 0o644,
                    "destination_uid": os.getuid(),
                    "destination_gid": os.getgid(),
                    "destination_prior": {"state": "ABSENT"},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o700)
            path = root / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                baseline_runner.BaselineError, "BASELINE_INSTALL_MANIFEST_INVALID"
            ):
                baseline_runner.load_install_manifest(path)
            payload["manifest_sha256"] = baseline_runner._install_manifest_digest(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            manifest = baseline_runner.load_install_manifest(path)
            self.assertEqual(payload["manifest_sha256"], manifest.manifest_sha256)

            payload["entries"][0]["destination_uid"] = os.getuid() + 1
            payload["manifest_sha256"] = baseline_runner._install_manifest_digest(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_INSTALL_MANIFEST_ENTRY_INVALID",
            ):
                baseline_runner.load_install_manifest(path)

            payload["entries"][0]["destination_uid"] = os.getuid()
            payload["entries"][0]["destination_prior"] = {
                "state": "PRESENT",
                "sha256": "3" * 64,
                "mode": 0o644,
                "uid": os.getuid() + 1,
                "gid": os.getgid(),
            }
            payload["manifest_sha256"] = baseline_runner._install_manifest_digest(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_INSTALL_MANIFEST_ENTRY_INVALID",
            ):
                baseline_runner.load_install_manifest(path)

    def test_source_and_install_identities_are_not_interchangeable(self) -> None:
        with self.assertRaisesRegex(
            baseline_runner.BaselineError, "BASELINE_INSTALL_MANIFEST_REQUIRED"
        ):
            baseline_runner._run_root(
                self.repository_root,
                self.catalog,
                root_kind="installed-runtime",
                root_identity="install:fixture",
                install_manifest=None,
                tool_identity="git:" + "a" * 40,
            )

    def test_staged_and_installed_require_disjoint_verified_installer_state(self) -> None:
        with tempfile.TemporaryDirectory() as tool_name, tempfile.TemporaryDirectory() as target_name:
            tool_root = Path(tool_name)
            target_root = Path(target_name)
            relative = "skills/tool.py"
            source = tool_root / relative
            source.parent.mkdir(parents=True)
            source.write_text("value = 1\n", encoding="utf-8")
            source.chmod(0o644)
            manifest = self._install_manifest(
                tool_root, target_root, (relative,)
            )
            entry = manifest.entries[0]
            staged_payload = {
                "schema": baseline_runner.INSTALL_MANIFEST_SCHEMA,
                "manifest_sha256": manifest.manifest_sha256,
                "entries": [
                    {
                        "destination_path": relative,
                        "sha256": entry["source_sha256"],
                        "mode": entry["destination_mode"],
                    }
                ],
                "state": "STAGED",
            }
            staged_path = target_root / baseline_runner.INSTALL_STAGE_RECEIPT
            staged_path.write_text(
                baseline_runner.canonical_json(staged_payload), encoding="utf-8"
            )
            staged_path.chmod(0o600)
            staged_digest, staged_identity = (
                baseline_runner._verify_installer_state_evidence(
                    target_root,
                    "staged-install-atom",
                    manifest,
                    staged_path,
                )
            )
            self.assertRegex(staged_digest, r"^[0-9a-f]{64}$")
            self.assertRegex(staged_identity, r"^[0-9a-f]{64}$")

            original_target = tool_root / "original-target"
            target_root.rename(original_target)
            target_root.mkdir()
            recreated_destination = target_root / relative
            recreated_destination.parent.mkdir(parents=True)
            recreated_destination.write_bytes(
                (original_target / relative).read_bytes()
            )
            recreated_destination.chmod(0o644)
            staged_path = target_root / baseline_runner.INSTALL_STAGE_RECEIPT
            staged_path.write_text(
                baseline_runner.canonical_json(staged_payload), encoding="utf-8"
            )
            staged_path.chmod(0o600)
            replaced_digest, replaced_identity = (
                baseline_runner._verify_installer_state_evidence(
                    target_root,
                    "staged-install-atom",
                    manifest,
                    staged_path,
                )
            )
            self.assertEqual(staged_digest, replaced_digest)
            self.assertNotEqual(staged_identity, replaced_identity)

            installed_payload = {
                "schema": baseline_runner.INSTALL_MANIFEST_SCHEMA,
                "manifest_sha256": manifest.manifest_sha256,
                "entries": [
                    {
                        "destination_path": relative,
                        "destination_prior": entry["destination_prior"],
                        "installed_sha256": entry["source_sha256"],
                        "installed_mode": entry["destination_mode"],
                        "installed_uid": entry["destination_uid"],
                        "installed_gid": entry["destination_gid"],
                        "destination_parent_identity": (
                            baseline_runner._destination_parent_identity(
                                target_root, relative
                            )
                        ),
                    }
                ],
                "state": "INSTALLED",
            }
            installed_path = tool_root / "rollback.json"
            installed_path.write_text(
                baseline_runner.canonical_json(installed_payload),
                encoding="utf-8",
            )
            installed_path.chmod(0o600)
            with self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH",
            ):
                baseline_runner._verify_installer_state_evidence(
                    target_root,
                    "installed-runtime",
                    manifest,
                    installed_path,
                )
            staged_path.unlink()
            installed_digest, installed_identity = (
                baseline_runner._verify_installer_state_evidence(
                    target_root,
                    "installed-runtime",
                    manifest,
                    installed_path,
                )
            )
            self.assertNotEqual(staged_digest, installed_digest)
            self.assertEqual(replaced_identity, installed_identity)
            installed_parent = target_root / "skills"
            old_parent = target_root / "skills-old"
            installed_parent.rename(old_parent)
            installed_parent.mkdir()
            replacement = installed_parent / "tool.py"
            replacement.write_bytes((old_parent / "tool.py").read_bytes())
            replacement.chmod(0o644)
            with self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH",
            ):
                baseline_runner._verify_installer_state_evidence(
                    target_root,
                    "installed-runtime",
                    manifest,
                    installed_path,
                )
            with self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_INSTALL_STATE_EVIDENCE_MISMATCH",
            ):
                baseline_runner._verify_installer_state_evidence(
                    target_root,
                    "staged-install-atom",
                    manifest,
                    installed_path,
                )

    def test_staged_and_installed_receipt_evidence_is_not_interchangeable(self) -> None:
        def install_receipt(
            kind: str,
            atom_id: str,
            target_manifest: str,
            manifest_sha256: str,
            manifest_raw_sha256: str,
        ) -> dict:
            receipt = self._valid_root_receipt(
                kind=kind,
                identity=f"install:{atom_id}",
                target_manifest=target_manifest,
                filesystem_identity=target_manifest,
                installer_state_evidence=manifest_raw_sha256,
            )
            receipt["target_root"].update(
                {
                    "byte_manifest_scope": "install-manifest-destinations",
                    "install_manifest_sha256": manifest_sha256,
                    "install_manifest_raw_sha256": manifest_raw_sha256,
                }
            )
            return receipt

        staged = install_receipt(
            "staged-install-atom",
            "staged-fixture",
            "1" * 64,
            "2" * 64,
            "3" * 64,
        )
        installed = install_receipt(
            "installed-runtime",
            "installed-fixture",
            "4" * 64,
            "5" * 64,
            "6" * 64,
        )
        self._verify_valid_root_receipt(staged)
        self._verify_valid_root_receipt(installed)
        target_fields = (
            "kind",
            "identity",
            "byte_manifest_sha256",
            "install_manifest_sha256",
            "install_manifest_raw_sha256",
            "filesystem_identity_sha256",
            "installer_state_evidence_sha256",
        )
        for direction, source, substituted in (
            ("staged-as-installed", staged, installed),
            ("installed-as-staged", installed, staged),
        ):
            with self.subTest(direction=direction, field="complete-receipt"):
                with self.assertRaises(baseline_runner.BaselineError):
                    self._verify_valid_root_receipt(source, substituted)
            for field in target_fields:
                candidate = copy.deepcopy(source)
                candidate["target_root"][field] = substituted["target_root"][field]
                with self.subTest(direction=direction, field=field):
                    with self.assertRaises(baseline_runner.BaselineError):
                        self._verify_valid_root_receipt(candidate, source)

    def test_root_change_during_validation_fails_before_receipt(self) -> None:
        runner_digest = hashlib.sha256(self.runner_path.read_bytes()).hexdigest()
        with patch.object(
            baseline_runner,
            "root_byte_manifest_sha256",
            side_effect=("a" * 64, "b" * 64),
        ), patch.object(
            baseline_runner, "_run_entry", return_value={}
        ), patch.object(
            baseline_runner,
            "_root_runner_sha256",
            return_value=runner_digest,
        ):
            with self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_ROOT_CHANGED_DURING_VALIDATION",
            ):
                baseline_runner._run_root(
                    self.repository_root,
                    self.catalog,
                    root_kind="accepted-base",
                    root_identity="git:" + "a" * 40,
                    install_manifest=None,
                    tool_identity="git:" + "a" * 40,
                )
        manifest = baseline_runner.InstallManifest(
            atom_id="fixture",
            source_commit="a" * 40,
            manifest_sha256="b" * 64,
            raw_sha256="c" * 64,
            entries=(),
        )
        with self.assertRaisesRegex(
            baseline_runner.BaselineError, "BASELINE_INSTALL_MANIFEST_UNEXPECTED"
        ):
            baseline_runner._run_root(
                self.repository_root,
                self.catalog,
                root_kind="accepted-base",
                root_identity="git:" + "a" * 40,
                install_manifest=manifest,
                tool_identity="git:" + "a" * 40,
            )

    def test_install_state_and_filesystem_identity_are_revalidated_after_commands(self) -> None:
        manifest = baseline_runner.InstallManifest(
            atom_id="fixture",
            source_commit="a" * 40,
            manifest_sha256="b" * 64,
            raw_sha256="c" * 64,
            entries=(),
        )
        runner_digest = hashlib.sha256(self.runner_path.read_bytes()).hexdigest()
        for name, final_state in (
            ("evidence-mutated", ("d" * 64, "2" * 64)),
            ("filesystem-replaced", ("1" * 64, "e" * 64)),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as target_name:
                target_root = Path(target_name)
                evidence = target_root.parent / f"{name}.json"
                evidence.write_text("fixture\n", encoding="utf-8")
                evidence.chmod(0o600)
                with (
                    patch.object(
                        baseline_runner,
                        "_verify_installer_state_evidence",
                        side_effect=(("1" * 64, "2" * 64), final_state),
                    ) as verifier,
                    patch.object(baseline_runner, "_git", return_value="a" * 40),
                    patch.object(baseline_runner, "_assert_exact_commit_root"),
                    patch.object(baseline_runner, "load_catalog", return_value=self.catalog),
                    patch.object(
                        baseline_runner,
                        "_install_manifest_byte_manifest",
                        return_value="3" * 64,
                    ),
                    patch.object(
                        baseline_runner,
                        "root_byte_manifest_sha256",
                        return_value="4" * 64,
                    ),
                    patch.object(
                        baseline_runner,
                        "_root_runner_sha256",
                        return_value=runner_digest,
                    ),
                    patch.object(
                        baseline_runner,
                        "_read_external_regular",
                        return_value=(self.runner_path.read_bytes(), self.runner_path.stat()),
                    ),
                    patch.object(baseline_runner, "_run_entry", return_value={}),
                    self.assertRaisesRegex(
                        baseline_runner.BaselineError,
                        "BASELINE_INSTALL_STATE_CHANGED_DURING_VALIDATION",
                    ),
                ):
                    baseline_runner._run_root(
                        target_root,
                        self.catalog,
                        root_kind="installed-runtime",
                        root_identity="install:fixture",
                        install_manifest=manifest,
                        installer_evidence=evidence,
                        tool_root=self.repository_root,
                        tool_identity="git:" + "a" * 40,
                        engine_authority="bootstrap-candidate",
                    )
                self.assertEqual(2, verifier.call_count)

    def _make_fixture_repository(self, root: Path) -> tuple[str, str]:
        self._git(root, "init", "-q")
        skill_roots = self.catalog.skill_roots
        for skill_root in skill_roots:
            skill = root / skill_root
            skill.mkdir(parents=True, exist_ok=True)
            (skill / "SKILL.md").write_text("valid\n", encoding="utf-8")
        quick = root / baseline_runner.QUICK_VALIDATOR
        quick.parent.mkdir(parents=True, exist_ok=True)
        quick.write_text(
            "from pathlib import Path\nimport sys\n"
            "raise SystemExit(0 if (Path(sys.argv[1]) / 'SKILL.md').read_text() == 'valid\\n' else 7)\n",
            encoding="utf-8",
        )
        registry = root / baseline_runner.REGISTRY_ARGUMENTS[0]
        registry.parent.mkdir(parents=True, exist_ok=True)
        registry.write_text("raise SystemExit(0)\n", encoding="utf-8")
        config = root / baseline_runner.REGISTRY_ARGUMENTS[2]
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("fixture = true\n", encoding="utf-8")
        legacy_runner = root / baseline_runner.RUNNER_RELATIVE_PATH
        legacy_runner.parent.mkdir(parents=True, exist_ok=True)
        legacy_runner.write_text(
            "import argparse\nfrom pathlib import Path\nREPOSITORY_ROOT=Path('.')\n"
            f"VALIDATOR_SKILL_ROOTS={skill_roots!r}\n"
            "# executor_registry.py twinfinity-executor-registry.toml --config --profile-root audit-config\n"
            "def _extract_base_tree(*args): return None\n"
            "def main():\n"
            " p=argparse.ArgumentParser(); p.add_argument('--base-sha'); p.parse_args(); return 0\n"
            "if __name__ == '__main__': raise SystemExit(main())\n",
            encoding="utf-8",
        )
        self._normalize_fixture_modes(root)
        self._git(root, "add", ".")
        self._git(root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "legacy-base")
        legacy_sha = self._git(root, "rev-parse", "HEAD")
        self._git(root, "update-ref", baseline_runner.TRUSTED_BASE_REF, legacy_sha)
        legacy_runner.write_bytes(self.runner_path.read_bytes())
        catalog = root / baseline_runner.CATALOG_RELATIVE_PATH
        catalog.parent.mkdir(parents=True, exist_ok=True)
        catalog.write_bytes(self.catalog_path.read_bytes())
        self._normalize_fixture_modes(root)
        self._git(root, "add", ".")
        self._git(root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "catalog-bootstrap")
        catalog_sha = self._git(root, "rev-parse", "HEAD")
        return legacy_sha, catalog_sha

    def test_pair_orchestration_covers_bootstrap_exact_v1_and_trusted_tool_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            legacy_sha, catalog_sha = self._make_fixture_repository(root)
            with patch.object(baseline_runner, "REPOSITORY_ROOT", root):
                bootstrap = baseline_runner._pair_receipt(legacy_sha)
                self.assertEqual("legacy-bootstrap", bootstrap["catalog_compatibility"])
                self.assertIn("trusted_candidate_receipt", bootstrap)
                replay = baseline_runner._pair_receipt(legacy_sha)
                self.assertEqual(
                    baseline_runner.canonical_json(bootstrap),
                    baseline_runner.canonical_json(replay),
                )
            marker = root / self.catalog.skill_roots[0] / "marker.txt"
            marker.write_text("valid\n", encoding="utf-8")
            self._normalize_fixture_modes(root)
            self._git(root, "add", ".")
            self._git(root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "exact-candidate")
            self._git(
                root,
                "update-ref",
                baseline_runner.TRUSTED_BASE_REF,
                catalog_sha,
            )
            with patch.object(baseline_runner, "REPOSITORY_ROOT", root):
                exact = baseline_runner._pair_receipt(catalog_sha)
                self.assertEqual("exact-v1", exact["catalog_compatibility"])
            (root / self.catalog.skill_roots[0] / "SKILL.md").write_text("invalid\n", encoding="utf-8")
            (root / baseline_runner.QUICK_VALIDATOR).write_text("raise SystemExit(0)\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "lying-candidate-tool")
            exact_base = exact["candidate_head_sha"]
            self._git(
                root,
                "update-ref",
                baseline_runner.TRUSTED_BASE_REF,
                exact_base,
            )
            with patch.object(baseline_runner, "REPOSITORY_ROOT", root):
                with self.assertRaisesRegex(
                    baseline_runner.BaselineError,
                    "BASELINE_TRUSTED_CANDIDATE_RUNNER_FAILED",
                ):
                    baseline_runner._pair_receipt(exact_base)

    def test_receipt_parser_requires_one_complete_object(self) -> None:
        for value in (b"{}\n{}\n", b'{"a":'):
            with self.subTest(value=value), self.assertRaisesRegex(
                baseline_runner.BaselineError,
                "BASELINE_RECEIPT_OUTPUT_INCOMPLETE",
            ):
                baseline_runner._parse_receipt_output(value)


if __name__ == "__main__":
    unittest.main()
