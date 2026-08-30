from __future__ import annotations

from contextlib import redirect_stdout
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import current_main_provenance_registration as registration  # noqa: E402
from coordination_store import CoordinationStore  # noqa: E402
import repository_git_registry  # noqa: E402
from repository_delivery_policy import HARNESS_REPOSITORY  # noqa: E402


NOW = "2026-08-30T20:00:00Z"


class SimulatedAcknowledgementLoss(BaseException):
    pass


class CurrentMainProvenanceRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tfh128.")
        self.root = Path(self.temporary.name) / "case"
        self.root.mkdir(mode=0o700)
        self.database_parent = self.root / "coordination"
        self.database_parent.mkdir(mode=0o700)
        self.database = self.database_parent / "state.sqlite3"
        self.git_dir = self.root / "synthetic.git"
        self.prior_main, self.accepted_main, self.accepted_tree = (
            self._synthetic_git(self.git_dir)
        )
        self.bootstrap_manifest = {"kind": "current-main-registration-test"}
        self.bootstrap_sha256 = hashlib.sha256(
            json.dumps(
                self.bootstrap_manifest, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        store = CoordinationStore(self.database)
        with store.transaction():
            store.record_bootstrap_provenance(
                bootstrap_id="current-main-registration-tests",
                manifest_sha256=self.bootstrap_sha256,
                manifest=self.bootstrap_manifest,
                source_harness_repository=HARNESS_REPOSITORY,
                source_harness_main_sha=self.prior_main,
                source_registry_sha256="1" * 64,
                approved_goal_sha256="2" * 64,
                application_repository="twinfinityai/twinfinityapp",
                application_main_sha="3" * 40,
                archived_database_sha256="4" * 64,
                now=NOW,
            )
        self._git("update-ref", "refs/remotes/origin/main", self.prior_main)
        with store.transaction():
            store.record_repository_git_registration(
                repository=HARNESS_REPOSITORY,
                git_dir=self.git_dir,
                source_main_sha=self.prior_main,
                bootstrap_id="current-main-registration-tests",
                bootstrap_manifest_sha256=self.bootstrap_sha256,
                now=NOW,
            )
        store.close()
        self._git("update-ref", "refs/remotes/origin/main", self.accepted_main)
        self.request = {
            "schema": registration.REQUEST_SCHEMA,
            "operation_key": "issue-128-test-operation",
            "repository": HARNESS_REPOSITORY,
            "bootstrap": {
                "bootstrap_id": "current-main-registration-tests",
                "manifest_sha256": self.bootstrap_sha256,
            },
            "accepted_source": {
                "merge_sha": self.accepted_main,
                "main_sha": self.accepted_main,
                "tree_sha": self.accepted_tree,
                "source_receipt_sha256": "5" * 64,
                "independent_review": {
                    "receipt_id": "governor-test-receipt",
                    "receipt_sha256": "6" * 64,
                },
                "ci": {
                    "run_id": 123,
                    "job_id": 456,
                    "receipt_sha256": "7" * 64,
                },
                "stopped_state_receipt_sha256": "8" * 64,
                "approval_execution_scope_sha256": "9" * 64,
            },
            "recorded_at": NOW,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _git_environment() -> dict[str, str]:
        return {
            "GIT_AUTHOR_NAME": "Twinfinity Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_AUTHOR_DATE": "2026-08-30T00:00:00Z",
            "GIT_COMMITTER_NAME": "Twinfinity Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_DATE": "2026-08-30T00:00:00Z",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }

    def _run(self, arguments: list[str], *, input_bytes: bytes = b"") -> bytes:
        result = subprocess.run(
            arguments,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._git_environment(),
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stderr.decode("utf-8", "replace"))
        return result.stdout.strip()

    def _git(self, *arguments: str, input_bytes: bytes = b"") -> str:
        return self._run(
            ["/usr/bin/git", f"--git-dir={self.git_dir}", *arguments],
            input_bytes=input_bytes,
        ).decode("ascii")

    def _synthetic_git(self, path: Path) -> tuple[str, str, str]:
        self._run(["/usr/bin/git", "init", "--bare", os.fspath(path)])
        self._run(
            [
                "/usr/bin/git",
                f"--git-dir={path}",
                "config",
                "remote.origin.url",
                f"https://github.com/{HARNESS_REPOSITORY}.git",
            ]
        )
        self._run(
            [
                "/usr/bin/git",
                f"--git-dir={path}",
                "config",
                "remote.origin.fetch",
                "+refs/heads/*:refs/remotes/origin/*",
            ]
        )
        tree = self._run(
            ["/usr/bin/git", f"--git-dir={path}", "mktree"], input_bytes=b""
        ).decode("ascii")
        prior = self._run(
            ["/usr/bin/git", f"--git-dir={path}", "commit-tree", tree],
            input_bytes=b"prior\n",
        ).decode("ascii")
        accepted = self._run(
            [
                "/usr/bin/git",
                f"--git-dir={path}",
                "commit-tree",
                tree,
                "-p",
                prior,
            ],
            input_bytes=b"accepted\n",
        ).decode("ascii")
        return prior, accepted, tree

    def _counts(self) -> tuple[int, int]:
        connection = sqlite3.connect(self.database)
        try:
            provenance = (
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_schema "
                    "WHERE type='table' "
                    "AND name='coordination_current_main_provenance'"
                ).fetchone()[0]
                and connection.execute(
                    "SELECT COUNT(*) FROM coordination_current_main_provenance"
                ).fetchone()[0]
            )
            registrations = (
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_schema "
                    "WHERE type='table' "
                    "AND name='coordination_repository_git_registrations_v2'"
                ).fetchone()[0]
                and connection.execute(
                    "SELECT COUNT(*) FROM coordination_repository_git_registrations_v2"
                ).fetchone()[0]
            )
            return int(provenance), int(registrations)
        finally:
            connection.close()

    def _history(self) -> tuple[list[tuple], list[tuple]]:
        connection = sqlite3.connect(self.database)
        try:
            return (
                connection.execute(
                    "SELECT * FROM coordination_bootstrap_provenance"
                ).fetchall(),
                connection.execute(
                    "SELECT * FROM coordination_repository_git_registrations"
                ).fetchall(),
            )
        finally:
            connection.close()

    def _apply(self) -> dict:
        preview = registration.preview_registration(
            self.database, self.git_dir, self.request
        )
        return registration.apply_registration(
            self.database,
            self.git_dir,
            self.request,
            expected_confirmation_sha256=preview["confirmation_sha256"],
        )

    def _aba(self) -> None:
        original = self.database_parent
        preserved = self.root / "preserved-coordination"
        original.rename(preserved)
        original.mkdir(mode=0o700)
        original.rmdir()
        preserved.rename(original)

    def _substituted_directory_open(self, target_call: int):
        real_open = registration._open_absolute_directory
        real_identity = repository_git_registry._metadata_identity
        open_calls = 0

        def opened(path: Path) -> int:
            nonlocal open_calls
            open_calls += 1
            if open_calls != target_call:
                return real_open(path)
            identity_calls = 0
            final_named_identity_call = 2 * len(Path(path).parts[1:])

            def identity(metadata: os.stat_result) -> tuple[int, ...]:
                nonlocal identity_calls
                identity_calls += 1
                value = real_identity(metadata)
                if identity_calls == final_named_identity_call:
                    return (value[0], value[1] + 1, *value[2:])
                return value

            with patch.object(
                repository_git_registry, "_metadata_identity", side_effect=identity
            ):
                return real_open(path)

        return opened

    def _assert_database_resources_released(self, descriptors_before: int) -> None:
        descriptors_after = len(list(Path("/proc/self/fd").iterdir()))
        self.assertLessEqual(descriptors_after, descriptors_before + 1)
        descriptor = os.open(self.database, os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def test_preview_apply_readback_recover_and_replay_are_exact_and_redacted(
        self,
    ) -> None:
        history = self._history()
        preview = registration.preview_registration(
            self.database, self.git_dir, self.request
        )

        self.assertEqual(registration.PUBLIC_PREVIEW_SCHEMA, preview["schema"])
        self.assertEqual((0, 0), self._counts())
        self.assertEqual(history, self._history())
        receipt = registration.apply_registration(
            self.database,
            self.git_dir,
            self.request,
            expected_confirmation_sha256=preview["confirmation_sha256"],
        )

        self.assertEqual(registration.RECEIPT_SCHEMA, receipt["schema"])
        self.assertEqual((1, 1), self._counts())
        self.assertEqual(history, self._history())
        self.assertEqual(
            receipt,
            registration.readback_registration(
                self.database, self.git_dir, self.request
            ),
        )
        self.assertEqual(
            receipt,
            registration.recover_registration(
                self.database, self.git_dir, self.request
            ),
        )
        self.assertEqual(
            receipt,
            registration.apply_registration(
                self.database,
                self.git_dir,
                self.request,
                expected_confirmation_sha256=preview["confirmation_sha256"],
            ),
        )
        public = json.dumps({"preview": preview, "receipt": receipt})
        self.assertNotIn(os.fspath(self.root), public)
        self.assertNotIn("git_dir", public)
        self.assertNotIn("device", public)
        self.assertNotIn("inode", public)

    def test_fixed_request_schema_matches_controller_closed_contract(self) -> None:
        schema_path = (
            ROOT
            / "references"
            / "twinfinity-current-main-provenance-registration-v1.schema.json"
        )
        schema = json.loads(schema_path.read_bytes())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(self.request)
        changed = json.loads(json.dumps(self.request))
        changed["watcher_path"] = "/caller/selected"
        with self.assertRaises(ValidationError):
            validator.validate(changed)
        with self.assertRaisesRegex(
            registration.CurrentMainRegistrationError,
            "CURRENT_MAIN_REQUEST_INVALID",
        ):
            registration.validate_request(changed)

    def test_ten_complete_parent_namespace_aba_repetitions_fail_closed(self) -> None:
        for repetition in range(10):
            fired = False

            def failpoint(name: str) -> None:
                nonlocal fired
                if name == "before_git_proof" and not fired:
                    fired = True
                    self._aba()

            with self.subTest(repetition=repetition), patch.object(
                registration, "_test_failpoint", side_effect=failpoint
            ):
                with self.assertRaisesRegex(
                    registration.CurrentMainRegistrationError,
                    "CURRENT_MAIN_DATABASE_SUBSTITUTED",
                ):
                    registration.preview_registration(
                        self.database, self.git_dir, self.request
                    )
            self.assertTrue(fired)
            self.assertEqual((0, 0), self._counts())

    def test_parent_rename_and_replacement_reject_before_git_proof(self) -> None:
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                preserved = self.root / "preserved-coordination"
                fired = False

                def failpoint(name: str) -> None:
                    nonlocal fired
                    if name == "before_git_proof" and not fired:
                        fired = True
                        self.database_parent.rename(preserved)
                        if replacement:
                            self.database_parent.mkdir(mode=0o700)

                try:
                    with patch.object(
                        registration, "_test_failpoint", side_effect=failpoint
                    ), patch.object(
                        registration, "prove_repository_git_current_main"
                    ) as git_proof:
                        with self.assertRaisesRegex(
                            registration.CurrentMainRegistrationError,
                            "CURRENT_MAIN_DATABASE_SUBSTITUTED",
                        ):
                            registration.preview_registration(
                                self.database, self.git_dir, self.request
                            )
                    git_proof.assert_not_called()
                finally:
                    if replacement and self.database_parent.exists():
                        self.database_parent.rmdir()
                    if preserved.exists():
                        preserved.rename(self.database_parent)
                self.assertTrue(fired)
                self.assertEqual((0, 0), self._counts())

    def test_pre_guard_container_and_parent_substitution_is_typed_everywhere(
        self,
    ) -> None:
        request_path = self.root / "request.json"
        request_path.write_text(
            json.dumps(self.request, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        operations = {
            "preview": lambda: registration.preview_registration(
                self.database, self.git_dir, self.request
            ),
            "apply": lambda: registration.apply_registration(
                self.database,
                self.git_dir,
                self.request,
                expected_confirmation_sha256="0" * 64,
            ),
            "readback": lambda: registration.readback_registration(
                self.database, self.git_dir, self.request
            ),
            "recover": lambda: registration.recover_registration(
                self.database, self.git_dir, self.request
            ),
        }
        cli_arguments = {
            "preview": [],
            "apply": ["--expected-confirmation-sha256", "0" * 64],
            "readback": [],
            "recover": [],
        }
        expected_output = (
            '{"code":"CURRENT_MAIN_DATABASE_SUBSTITUTED","status":"HOLD"}\n'
        )

        for target, target_call in (("container", 1), ("parent", 2)):
            for operation, invoke in operations.items():
                with self.subTest(target=target, boundary="public", operation=operation):
                    descriptors_before = len(list(Path("/proc/self/fd").iterdir()))
                    with patch.object(
                        registration,
                        "_open_absolute_directory",
                        side_effect=self._substituted_directory_open(target_call),
                    ), patch.object(
                        registration, "NamespaceEventGuard"
                    ) as namespace_guard, patch.object(
                        repository_git_registry.subprocess, "run"
                    ) as git_child:
                        with self.assertRaisesRegex(
                            registration.CurrentMainRegistrationError,
                            "^CURRENT_MAIN_DATABASE_SUBSTITUTED$",
                        ):
                            invoke()
                    namespace_guard.assert_not_called()
                    git_child.assert_not_called()
                    self.assertEqual((0, 0), self._counts())
                    self._assert_database_resources_released(descriptors_before)

            for operation, extra_arguments in cli_arguments.items():
                with self.subTest(target=target, boundary="cli", operation=operation):
                    descriptors_before = len(list(Path("/proc/self/fd").iterdir()))
                    output = io.StringIO()
                    arguments = [
                        operation,
                        "--database",
                        os.fspath(self.database),
                        "--git-dir",
                        os.fspath(self.git_dir),
                        "--request",
                        os.fspath(request_path),
                        *extra_arguments,
                    ]
                    with patch.object(
                        registration,
                        "_open_absolute_directory",
                        side_effect=self._substituted_directory_open(target_call),
                    ), patch.object(
                        registration, "NamespaceEventGuard"
                    ) as namespace_guard, patch.object(
                        repository_git_registry.subprocess, "run"
                    ) as git_child, redirect_stdout(output):
                        self.assertEqual(2, registration.main(arguments))
                    self.assertEqual(expected_output, output.getvalue())
                    namespace_guard.assert_not_called()
                    git_child.assert_not_called()
                    self.assertEqual((0, 0), self._counts())
                    self._assert_database_resources_released(descriptors_before)

    def test_commit_window_events_leave_zero_rows_or_one_recoverable_pair(self) -> None:
        for failpoint_name, committed in (
            ("before_insert", False),
            ("before_commit", False),
            ("after_commit", True),
            ("before_public_output", True),
        ):
            with self.subTest(failpoint=failpoint_name):
                if self._counts() != (0, 0):
                    self.tearDown()
                    self.setUp()
                preview = registration.preview_registration(
                    self.database, self.git_dir, self.request
                )
                fired = False

                def failpoint(name: str) -> None:
                    nonlocal fired
                    if name == failpoint_name and not fired:
                        fired = True
                        self._aba()

                with patch.object(
                    registration, "_test_failpoint", side_effect=failpoint
                ):
                    with self.assertRaisesRegex(
                        registration.CurrentMainRegistrationError,
                        "CURRENT_MAIN_DATABASE_SUBSTITUTED",
                    ):
                        registration.apply_registration(
                            self.database,
                            self.git_dir,
                            self.request,
                            expected_confirmation_sha256=preview[
                                "confirmation_sha256"
                            ],
                        )
                self.assertTrue(fired)
                self.assertEqual((1, 1) if committed else (0, 0), self._counts())
                if committed:
                    receipt = registration.recover_registration(
                        self.database, self.git_dir, self.request
                    )
                    self.assertEqual("COMMITTED", receipt["result"])

    def test_acknowledgement_loss_recovers_exact_stored_receipt(self) -> None:
        preview = registration.preview_registration(
            self.database, self.git_dir, self.request
        )

        def failpoint(name: str) -> None:
            if name == "after_commit":
                raise SimulatedAcknowledgementLoss()

        with patch.object(registration, "_test_failpoint", side_effect=failpoint):
            with self.assertRaises(SimulatedAcknowledgementLoss):
                registration.apply_registration(
                    self.database,
                    self.git_dir,
                    self.request,
                    expected_confirmation_sha256=preview["confirmation_sha256"],
                )

        self.assertEqual((1, 1), self._counts())
        recovered = registration.recover_registration(
            self.database, self.git_dir, self.request
        )
        self.assertEqual(
            recovered,
            registration.readback_registration(
                self.database, self.git_dir, self.request
            ),
        )

    def test_git_derived_state_matrix_rejects_before_any_git_child(self) -> None:
        entries = {
            "commondir": (self.git_dir / "commondir", b"../synthetic.git\n"),
            "grafts": (self.git_dir / "info" / "grafts", b"0" * 81),
            "shallow": (self.git_dir / "shallow", (self.prior_main + "\n").encode()),
            "alternates": (
                self.git_dir / "objects" / "info" / "alternates",
                b"/untrusted/objects\n",
            ),
            "replace": (
                self.git_dir / "refs" / "replace" / self.prior_main,
                (self.accepted_main + "\n").encode(),
            ),
            "packed-replace": (
                self.git_dir / "packed-refs",
                (
                    self.accepted_main + " refs/replace/" + self.prior_main + "\n"
                ).encode(),
            ),
        }
        for label, (path, contents) in entries.items():
            with self.subTest(label=label):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
                try:
                    with patch.object(
                        repository_git_registry.subprocess, "run"
                    ) as child:
                        with self.assertRaisesRegex(
                            registration.CurrentMainRegistrationError,
                            "REPOSITORY_GIT_DERIVED_STATE_PRESENT",
                        ):
                            registration.preview_registration(
                                self.database, self.git_dir, self.request
                            )
                    child.assert_not_called()
                finally:
                    path.unlink()
                    if label == "replace":
                        path.parent.rmdir()
                self.assertEqual((0, 0), self._counts())

    def test_git_environment_tree_ref_and_ancestry_substitution_fail_closed(
        self,
    ) -> None:
        with patch.dict(os.environ, {"GIT_DIR": os.fspath(self.git_dir)}):
            with self.assertRaisesRegex(
                registration.CurrentMainRegistrationError,
                "REPOSITORY_GIT_ENVIRONMENT_SUBSTITUTED",
            ):
                registration.preview_registration(
                    self.database, self.git_dir, self.request
                )

        wrong_tree = json.loads(json.dumps(self.request))
        wrong_tree["accepted_source"]["tree_sha"] = "f" * 40
        with self.assertRaisesRegex(
            registration.CurrentMainRegistrationError,
            "REPOSITORY_GIT_PROOF_MISMATCH",
        ):
            registration.preview_registration(
                self.database, self.git_dir, wrong_tree
            )

        orphan = self._git(
            "commit-tree", self.accepted_tree, input_bytes=b"orphan\n"
        )
        self._git("update-ref", "refs/remotes/origin/main", orphan)
        nonancestor = json.loads(json.dumps(self.request))
        nonancestor["accepted_source"]["merge_sha"] = orphan
        nonancestor["accepted_source"]["main_sha"] = orphan
        try:
            with self.assertRaisesRegex(
                registration.CurrentMainRegistrationError,
                "REPOSITORY_GIT_MAIN_NOT_DESCENDANT",
            ):
                registration.preview_registration(
                    self.database, self.git_dir, nonancestor
                )
        finally:
            self._git("update-ref", "refs/remotes/origin/main", self.accepted_main)

        caller_selected = json.loads(json.dumps(self.request))
        caller_selected["git_ref"] = "refs/heads/other"
        with self.assertRaisesRegex(
            registration.CurrentMainRegistrationError,
            "CURRENT_MAIN_REQUEST_INVALID",
        ):
            registration.preview_registration(
                self.database, self.git_dir, caller_selected
            )
        self.assertEqual((0, 0), self._counts())

    def test_v2_primary_and_unique_replace_collisions_preserve_exact_pair(self) -> None:
        self._apply()
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA recursive_triggers=OFF")
        try:
            provenance = dict(
                connection.execute(
                    "SELECT * FROM coordination_current_main_provenance"
                ).fetchone()
            )
            v2 = dict(
                connection.execute(
                    "SELECT * FROM coordination_repository_git_registrations_v2"
                ).fetchone()
            )
            provenance_before = tuple(provenance.values())
            v2_before = tuple(v2.values())

            for target in (
                "provenance_id",
                "provenance_sha256",
                "transaction_sha256",
                "repository_main",
            ):
                with self.subTest(table="provenance", target=target):
                    candidate = dict(provenance)
                    candidate["provenance_id"] = "other-provenance"
                    candidate["provenance_sha256"] = "a" * 64
                    candidate["transaction_sha256"] = "b" * 64
                    candidate["repository"] = "other/other"
                    candidate["accepted_main_sha"] = "c" * 40
                    if target == "provenance_id":
                        candidate["provenance_id"] = provenance["provenance_id"]
                    elif target == "provenance_sha256":
                        candidate["provenance_sha256"] = provenance[
                            "provenance_sha256"
                        ]
                    elif target == "transaction_sha256":
                        candidate["transaction_sha256"] = provenance[
                            "transaction_sha256"
                        ]
                    else:
                        candidate["repository"] = provenance["repository"]
                        candidate["accepted_main_sha"] = provenance[
                            "accepted_main_sha"
                        ]
                    with self.assertRaisesRegex(
                        sqlite3.IntegrityError,
                        "CURRENT_MAIN_PROVENANCE_IMMUTABLE",
                    ):
                        connection.execute(
                            "INSERT OR REPLACE INTO "
                            "coordination_current_main_provenance VALUES ("
                            + ",".join("?" for _ in candidate)
                            + ")",
                            tuple(candidate.values()),
                        )

            for target in (
                "registration_id",
                "repository",
                "git_dir",
                "provenance_id",
                "device_inode",
                "transaction_sha256",
                "registration_sha256",
                "receipt_sha256",
            ):
                with self.subTest(table="v2", target=target):
                    candidate = dict(v2)
                    candidate.update(
                        {
                            "registration_id": "other-registration",
                            "repository": "other/other",
                            "git_dir": "/private/other.git",
                            "provenance_id": "other-provenance",
                            "device_id": int(v2["device_id"]) + 100,
                            "inode": int(v2["inode"]) + 100,
                            "transaction_sha256": "c" * 64,
                            "registration_sha256": "d" * 64,
                            "receipt_sha256": "e" * 64,
                        }
                    )
                    if target == "device_inode":
                        candidate["device_id"] = v2["device_id"]
                        candidate["inode"] = v2["inode"]
                    else:
                        candidate[target] = v2[target]
                    with self.assertRaisesRegex(
                        sqlite3.IntegrityError,
                        "REPOSITORY_GIT_REGISTRATION_V2_IMMUTABLE",
                    ):
                        connection.execute(
                            "INSERT OR REPLACE INTO "
                            "coordination_repository_git_registrations_v2 VALUES ("
                            + ",".join("?" for _ in candidate)
                            + ")",
                            tuple(candidate.values()),
                        )

            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "CURRENT_MAIN_PROVENANCE_IMMUTABLE"
            ):
                connection.execute(
                    "UPDATE coordination_current_main_provenance "
                    "SET repository=repository"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "REPOSITORY_GIT_REGISTRATION_V2_IMMUTABLE",
            ):
                connection.execute(
                    "DELETE FROM coordination_repository_git_registrations_v2"
                )
            self.assertEqual(
                provenance_before,
                tuple(
                    connection.execute(
                        "SELECT * FROM coordination_current_main_provenance"
                    ).fetchone()
                ),
            )
            self.assertEqual(
                v2_before,
                tuple(
                    connection.execute(
                        "SELECT * FROM coordination_repository_git_registrations_v2"
                    ).fetchone()
                ),
            )
        finally:
            connection.close()

    def test_missing_immutable_schema_guard_fails_readback_closed(self) -> None:
        self._apply()
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "DROP TRIGGER "
                "coordination_repository_git_registration_v2_immutable_update"
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(
            registration.CurrentMainRegistrationError,
            "CURRENT_MAIN_SCHEMA_INVALID",
        ):
            registration.readback_registration(
                self.database, self.git_dir, self.request
            )

    def test_guard_failure_event_matrix_and_unrelated_sibling(self) -> None:
        parent_descriptor = os.open(
            self.database_parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        container_descriptor = os.open(
            self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        guard = registration.NamespaceEventGuard(
            parent_descriptor, container_descriptor, self.database_parent.name
        )
        try:
            (self.root / "unrelated-sibling").mkdir()
            guard.check()
            (self.root / "unrelated-sibling").rmdir()
            guard.check()
            cases = {
                "overflow": struct.pack(
                    "iIII", -1, registration.IN_Q_OVERFLOW, 0, 0
                ),
                "ignored": struct.pack(
                    "iIII", guard._parent_watch, registration.IN_IGNORED, 0, 0
                ),
                "unmount": struct.pack(
                    "iIII", guard._parent_watch, registration.IN_UNMOUNT, 0, 0
                ),
                "wrong-watch": struct.pack("iIII", 999999, 0x1, 0, 0),
                "missing-name": struct.pack(
                    "iIII", guard._container_watch, registration.IN_CREATE, 0, 0
                ),
                "truncated": b"\x00\x01",
                "malformed-name": struct.pack(
                    "iIII", guard._container_watch, registration.IN_CREATE, 0, 4
                )
                + b"name",
            }
            for label, raw in cases.items():
                with self.subTest(label=label):
                    guard._dirty = False
                    reads = iter((raw, BlockingIOError()))

                    def read(_descriptor: int) -> bytes:
                        value = next(reads)
                        if isinstance(value, BaseException):
                            raise value
                        return value

                    with patch.object(registration, "_read_inotify", side_effect=read):
                        with self.assertRaisesRegex(
                            registration.CurrentMainRegistrationError,
                            "CURRENT_MAIN_DATABASE_SUBSTITUTED",
                        ):
                            guard.check()
                    with self.assertRaisesRegex(
                        registration.CurrentMainRegistrationError,
                        "CURRENT_MAIN_DATABASE_SUBSTITUTED",
                    ):
                        guard.check()
            guard._dirty = False
            os.close(guard._descriptor)
            guard._descriptor = -1
            with self.assertRaisesRegex(
                registration.CurrentMainRegistrationError,
                "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE",
            ):
                guard.check()
        finally:
            guard.close()
            os.close(parent_descriptor)
            os.close(container_descriptor)

    def test_watcher_init_and_add_watch_fail_without_rows(self) -> None:
        for target in ("_inotify_init", "_inotify_add_watch"):
            with self.subTest(target=target), patch.object(
                registration, target, side_effect=OSError(24, "unavailable")
            ):
                with self.assertRaisesRegex(
                    registration.CurrentMainRegistrationError,
                    "CURRENT_MAIN_NAMESPACE_GUARD_UNAVAILABLE",
                ):
                    registration.preview_registration(
                        self.database, self.git_dir, self.request
                    )
            self.assertEqual((0, 0), self._counts())

    def test_database_flock_and_descriptors_are_released(self) -> None:
        before = len(list(Path("/proc/self/fd").iterdir()))
        registration.preview_registration(self.database, self.git_dir, self.request)
        after = len(list(Path("/proc/self/fd").iterdir()))
        descriptor = os.open(self.database, os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        self.assertLessEqual(after, before + 1)


if __name__ == "__main__":
    unittest.main()
