from __future__ import annotations

import copy
import errno
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, os.fspath(SCRIPTS))

import verify_harness_baseline_receipt as verifier


ISSUE_NUMBER = 92
ISSUE92_ACCEPTED_BASE_COMMIT = "948e94e608b70d7b3a0a576079c1f648c4acbc40"
ISSUE92_ACCEPTED_BASE_TREE = "99caef65a4d0db450186e16035c2c6cff667e746"


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": os.fspath(root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    completed = subprocess.run(
        [verifier.GIT, "-C", os.fspath(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return completed.stdout.strip()


def _git_blob(root: Path, object_id: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": os.fspath(root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    completed = subprocess.run(
        [verifier.GIT, "-C", os.fspath(root), "cat-file", "blob", object_id],
        check=True,
        capture_output=True,
        env=environment,
    )
    return completed.stdout


def _write(path: Path, contents: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(contents, bytes):
        path.write_bytes(contents)
    else:
        path.write_text(contents, encoding="utf-8")


class BootstrapVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="bootstrap-verifier-tests-")
        cls.root = Path(cls.temporary.name)
        cls.root.chmod(0o700)
        cls.repository = cls.root / "twinfinity-harness-issue92"
        cls.repository.mkdir(mode=0o700)
        _git(cls.repository, "init", "-b", "main")
        _git(cls.repository, "config", "user.name", "Bootstrap Test")
        _git(cls.repository, "config", "user.email", "bootstrap@example.invalid")
        _git(cls.repository, "remote", "add", "origin", verifier.ORIGIN_URL)

        _write(
            cls.repository / verifier.VERIFIER_PATH,
            Path(verifier.__file__).read_bytes(),
        )
        _write(
            cls.repository / verifier.SCHEMA_PATH,
            (SKILL_ROOT / "references" / Path(verifier.SCHEMA_PATH).name).read_bytes(),
        )
        _write(
            cls.repository / verifier.CANDIDATE_RUNNER_PATH,
            "#!/usr/bin/env python3\nraise SystemExit(0)\n",
        )
        _write(
            cls.repository / verifier.VALIDATOR_PATH,
            "#!/usr/bin/env python3\n"
            "import pathlib,sys\n"
            "root=pathlib.Path(sys.argv[1]).resolve()\n"
            "cwd=pathlib.Path.cwd().resolve()\n"
            "marker=(cwd/'ROOT_MARKER').read_text().strip()\n"
            "if marker not in {'BASE','HEAD'} or cwd not in root.parents:\n"
            " raise SystemExit(41)\n"
            "if not (root/'SKILL.md').is_file(): raise SystemExit(42)\n"
            "print(f'ACCEPTED:{marker}:{root.relative_to(cwd).as_posix()}')\n",
        )
        _write(
            cls.repository / verifier.REGISTRY_AUDIT_PATH,
            "#!/usr/bin/env python3\n"
            "import pathlib,sys\n"
            "cwd=pathlib.Path.cwd().resolve()\n"
            "marker=(cwd/'ROOT_MARKER').read_text().strip()\n"
            "args=sys.argv[1:]\n"
            "config=pathlib.Path(args[args.index('--config')+1]).resolve()\n"
            "profiles=pathlib.Path(args[args.index('--profile-root')+1]).resolve()\n"
            "if marker not in {'BASE','HEAD'} or cwd not in config.parents or cwd not in profiles.parents:\n"
            " raise SystemExit(43)\n"
            "print(f'ACCEPTED-REGISTRY:{marker}')\n",
        )
        (cls.repository / verifier.REGISTRY_AUDIT_PATH).chmod(0o755)
        _write(
            cls.repository / verifier.OWNER_SAFE_SQLITE_PATH,
            "class UnsafeSQLitePathError(RuntimeError): pass\n"
            "def prepare_owner_database(*args,**kwargs): return None\n",
        )
        _write(cls.repository / verifier.REGISTRY_CONFIG_PATH, "schema_version = 2\n")
        for skill in verifier.SKILL_ROOTS:
            marker = cls.repository / skill / "SKILL.md"
            if not marker.exists():
                _write(marker, f"# {skill}\n")
        _write(cls.repository / "README.md", "base\n")
        _write(cls.repository / "ROOT_MARKER", "BASE\n")
        _git(cls.repository, "add", ".")
        _git(cls.repository, "commit", "-m", "base")
        cls.base_sha = _git(cls.repository, "rev-parse", "HEAD")
        cls.base_tree = _git(cls.repository, "rev-parse", "HEAD^{tree}")
        _git(
            cls.repository,
            "update-ref",
            "refs/remotes/origin/main",
            cls.base_sha,
        )
        cls.branch = "change/92-bootstrap-test"
        _git(cls.repository, "checkout", "-b", cls.branch)
        _write(cls.repository / "README.md", "candidate\n")
        _write(cls.repository / "ROOT_MARKER", "HEAD\n")
        forged = (
            "#!/usr/bin/env python3\n"
            "import os,pathlib\n"
            "marker=os.environ.get('FORGED_TOOL_SENTINEL')\n"
            "if marker: pathlib.Path(marker).write_text('FORGED\\n')\n"
            "raise SystemExit(0)\n"
        )
        _write(cls.repository / verifier.VALIDATOR_PATH, forged)
        _write(cls.repository / verifier.REGISTRY_AUDIT_PATH, forged)
        _write(cls.repository / verifier.CANDIDATE_RUNNER_PATH, forged)
        _git(cls.repository, "add", ".")
        _git(cls.repository, "commit", "-m", "candidate")
        cls.head_sha = _git(cls.repository, "rev-parse", "HEAD")
        cls.head_tree = _git(cls.repository, "rev-parse", "HEAD^{tree}")
        _git(cls.repository, "branch", "-D", "main")

        mutable_order = sorted(
            [
                "README.md",
                "ROOT_MARKER",
                verifier.CANDIDATE_RUNNER_PATH,
                verifier.VALIDATOR_PATH,
                verifier.REGISTRY_AUDIT_PATH,
            ]
        )
        mutable_paths = []
        for relative in mutable_order:
            blob, digest, _ = verifier._blob_identity(
                cls.repository, cls.base_tree, relative
            )
            mutable_paths.append(
                {
                    "path": relative,
                    "starting_sha256": digest,
                    "starting_git_blob": blob,
                }
            )
        cls.packet = {
            "recorded_at": "2026-08-29T00:00:00Z",
            "schema": "twinfinity-direct-harness-source-maintenance/v1",
            "repository": verifier.REPOSITORY,
            "owning_issue": ISSUE_NUMBER,
            "issue_body_sha256": "1" * 64,
            "issue_observed_at": "2026-08-29T00:00:00Z",
            "issue_observed_state": "open",
            "issue_url": (
                "https://github.com/jayendusharma/twinfinity-harness/issues/92"
            ),
            "trigger": {
                "kind": "OBSERVED_HARNESS_TRUST_DEFECT",
                "invariant": "CANDIDATE_BYTES_CANNOT_SELECT_ACCEPTED_TOOLS",
                "measurable_effect": "SYNTHETIC_VALIDATION_IS_BLOCKED",
                "blocked_consumer_issue": ISSUE_NUMBER,
                "blocked_consumer_hold_comment_id": 1,
            },
            "starting_main_ref": "refs/heads/main",
            "starting_main_sha": cls.base_sha,
            "starting_main_tree": cls.base_tree,
            "starting_main_contract_sha256": "2" * 64,
            "branch": cls.branch,
            "worktree_path": os.fspath(cls.repository.resolve()),
            "opaque_worktree_id": cls.repository.name,
            "accountable_writer": "/root/bootstrap-verifier-test-writer",
            "authority": {
                "kind": "DIRECT_OWNER_INSTRUCTION",
                "direct_owner_instructions": [
                    "test-only direct harness source authority"
                ],
                "sqlite_harness_loop": (
                    "PROHIBITED_FOR_HARNESS_SOURCE_MAINTENANCE"
                ),
                "temporary_six_writer_authority_sha256": "3" * 64,
                "standing_routine_delivery_authority_sha256": "4" * 64,
            },
            "direct_capacity": {
                "class": "HARNESS_SOURCE_WRITER",
                "units": 1,
                "temporary_limit": 6,
                "occupancy_after_reservation_including_active_and_retained": 1,
                "occupancy_components": ["SYNTHETIC_ACTIVE_WRITER"],
                "sqlite_allocation_units": 0,
            },
            "repository_fence": {
                "observed_at": "2026-08-29T00:00:00Z",
                "live_main": cls.base_sha,
                "open_pull_requests": 0,
                "remote_branches": [{"name": "main", "sha": cls.base_sha}],
                "candidate_remote_branch_present": False,
                "planned_local_branch_present": False,
                "planned_worktree_present": False,
                "local_branch_inventory_sha256": "5" * 64,
                "local_worktree_porcelain_sha256": "6" * 64,
            },
            "dependencies": {
                "predecessor_issue": 98,
                "predecessor_source_complete": True,
                "predecessor_accepted_head": cls.base_sha,
                "predecessor_merge_result_main": cls.base_sha,
                "predecessor_terminal_receipt_body_sha256": "7" * 64,
                "unmet_dependencies": [],
            },
            "mutable_paths": mutable_paths,
            "mutable_path_order": mutable_order,
            "mutable_paths_digest_serialization": (
                "SHA256_OF_UTF8_COMPACT_JSON_MUTABLE_PATH_ORDER_WITH_NO_TRAILING_LF"
            ),
            "mutable_paths_sha256": verifier._sha256(
                json.dumps(mutable_order, separators=(",", ":")).encode()
            ),
            "collision_fence": {
                "issue_98_intersection_with_92": [],
                "issue_98_intersection_with_93": [],
                "issue_98_intersection_with_94": [],
                "issue_98_intersection_with_96": [],
                "issue_92_state": "SYNTHETIC_RETAINED",
                "issue_92_worktree": os.fspath(cls.repository.resolve()),
                "issue_92_mutable_paths_sha256": "8" * 64,
                "issue_93_state": "SYNTHETIC_DISJOINT",
                "issue_93_mutable_paths_sha256": "9" * 64,
                "issue_94_state": "SYNTHETIC_DISJOINT",
                "issue_94_mutable_paths_sha256": "a" * 64,
                "issue_96_state": "SYNTHETIC_DISJOINT",
                "issue_96_mutable_paths_sha256": "b" * 64,
                "historical_and_retired_worktree_mutation": "PROHIBITED",
                "branch_collision": False,
                "worktree_collision": False,
                "path_collision": False,
                "semantic_relation_with_92": "SYNTHETIC_BOOTSTRAP_PREDECESSOR",
                "unknown_overlap_action": "HOLD",
            },
            "semantic_scope": [
                "IMMUTABLE_ACCEPTED_BASE_VALIDATION",
                "INDEPENDENT_BASE_AND_HEAD_EXECUTION",
            ],
            "safety_invariants": [
                "CANDIDATE_CANNOT_SELECT_ACCEPTED_TOOL",
                "NO_DESCENDANT_SURVIVES",
                "PASS_IS_SOURCE_ONLY",
            ],
            "authorized_stages": [
                "READ_AND_VALIDATE_PACKET",
                "EDIT_ONLY_THE_FROZEN_PATH_SET",
                "RUN_FOCUSED_ADVERSARIAL_TESTS",
                "RUN_FULL_HERMETIC_SUITE",
                "CREATE_ONE_LOCAL_COMMIT",
                "RETURN_PACKET_BOUND_VALIDATION_MANIFEST",
            ],
            "stages_requiring_planner_continuation": [
                "FRESH_GOVERNOR_REVIEW",
                "REMOTE_PUBLICATION",
                "PULL_REQUEST_CREATION",
                "MATCH_HEAD_MERGE",
                "CLEANUP_AND_TERMINAL_RECEIPT",
            ],
            "repair_budget": 1,
            "hard_stops": [
                "ANY_SECOND_PATH",
                "ANY_SQLITE_MUTATION",
                "ANY_REMOTE_PUBLICATION",
                "ANY_INSTALLATION_OR_RUNTIME_EFFECT",
                "ANY_APPLICATION_EFFECT",
                "ANY_SELF_APPROVAL",
            ],
            "excluded_effects": [
                "SQLITE_MUTATION",
                "REMOTE_PUBLICATION",
                "MERGE",
                "INSTALLATION_OR_RUNTIME_ACTIVATION",
                "APPLICATION_OR_PROVIDER_OPERATION",
            ],
            "bootstrap_validation_contract": {
                "self_verification_for_issue_92": "PROHIBITED",
                "issue_92_source_acceptance": [
                    "CURRENT_MAIN_RAW_FIXED_ELEVEN_SKILL_VALIDATORS",
                    "CURRENT_MAIN_RAW_EXECUTOR_REGISTRY_AUDIT",
                    "FOCUSED_ADVERSARIAL_BOOTSTRAP_VERIFIER_TESTS",
                    "FULL_HERMETIC_SUITE",
                    "FRESH_INDEPENDENT_EXACT_HEAD_GOVERNOR",
                    "NATURAL_EXACT_HEAD_CI",
                ],
            },
            "current_stage": "LOCAL_VALIDATION_READY",
        }
        cls.packet_path = cls.root / "direct-packet.json"
        cls.packet_path.write_bytes(verifier._canonical_bytes(cls.packet))
        cls.packet_sha256 = verifier._sha256(cls.packet_path.read_bytes())

        cls.evidence = verifier._prepare_evidence(
            cls.packet_path, cls.packet_sha256
        )
        cls.observations = verifier._execute_observations(
            cls.repository,
            cls.evidence["base"]["tree"],
            cls.evidence["head"]["tree"],
            cls.evidence["command_manifest"],
        )
        cls.candidate = cls._candidate(cls.observations)
        cls.candidate_path = cls.root / "candidate.json"
        cls.candidate_path.write_bytes(verifier._canonical_bytes(cls.candidate))
        schema = json.loads((cls.repository / verifier.SCHEMA_PATH).read_text())
        Draft202012Validator.check_schema(schema)
        cls.schema_validator = Draft202012Validator(schema)
        cls.schema = schema

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _candidate(cls, observations: list[dict[str, object]]) -> dict[str, object]:
        return {
            "schema": "twinfinity-harness-baseline-candidate-receipt/v1",
            "repository": verifier.REPOSITORY,
            "issue_number": str(ISSUE_NUMBER),
            "packet_sha256": cls.packet_sha256,
            "base": cls.evidence["base"],
            "head": cls.evidence["head"],
            "tool_identities": cls.evidence["tool_identities"],
            "external_tools": cls.evidence["external_tools"],
            "command_manifest": cls.evidence["command_manifest"],
            "command_manifest_sha256": cls.evidence["command_manifest_sha256"],
            "observations": observations,
            "verdict": "PASS",
            "evidence_scope": verifier.EVIDENCE_SCOPE,
        }

    def _candidate_file(self, value: object, name: str = "candidate-mutated.json") -> Path:
        path = self.root / name
        path.unlink(missing_ok=True)
        path.write_bytes(verifier._canonical_bytes(value))
        return path

    def _post_merge_issue92_fixture(
        self,
        *,
        contaminate_outer_candidate: bool = False,
    ) -> tuple[tempfile.TemporaryDirectory[str], dict[str, object]]:
        temporary = tempfile.TemporaryDirectory(
            prefix="post-merge-issue92-successor-"
        )
        root = Path(temporary.name)
        root.chmod(0o700)
        repository = root / "twinfinity-harness-issue92"
        repository.mkdir(mode=0o700)
        _git(repository, "init", "-b", "main")
        _git(repository, "config", "user.name", "Post Merge Test")
        _git(repository, "config", "user.email", "post-merge@example.invalid")
        _git(repository, "remote", "add", "origin", verifier.ORIGIN_URL)
        _git(repository, "commit", "--allow-empty", "-m", "old accepted base")
        old_base = _git(repository, "rev-parse", "HEAD")
        old_base_tree = _git(repository, "rev-parse", "HEAD^{tree}")

        source_root = SKILL_ROOT.parents[1]
        required_base_paths = {
            verifier.VERIFIER_PATH,
            verifier.SCHEMA_PATH,
            verifier.CANDIDATE_RUNNER_PATH,
            verifier.VALIDATOR_PATH,
            verifier.REGISTRY_AUDIT_PATH,
            verifier.OWNER_SAFE_SQLITE_PATH,
            verifier.REGISTRY_CONFIG_PATH,
            *(
                path
                for path, starting_sha256, _ in (
                    verifier.ISSUE92_POST_MERGE_MUTABLE_PATHS
                )
                if starting_sha256 != "ABSENT"
            ),
        }
        for relative in sorted(required_base_paths):
            _write(repository / relative, (source_root / relative).read_bytes())
        contaminated_outer_paths = {}
        if contaminate_outer_candidate:
            for relative, starting_sha256, _ in (
                verifier.ISSUE92_POST_MERGE_MUTABLE_PATHS
            ):
                if starting_sha256 == "ABSENT":
                    continue
                target = repository / relative
                target.write_bytes(
                    target.read_bytes() + b"\n# contaminated outer candidate\n"
                )
                contaminated_outer_paths[relative] = verifier._sha256(
                    target.read_bytes()
                )

        trusted_repository = Path(verifier.__file__).resolve().parents[3]
        self.assertEqual(
            ISSUE92_ACCEPTED_BASE_COMMIT,
            _git(trusted_repository, "rev-parse", f"{ISSUE92_ACCEPTED_BASE_COMMIT}^{{commit}}"),
        )
        self.assertEqual(
            ISSUE92_ACCEPTED_BASE_TREE,
            _git(trusted_repository, "rev-parse", f"{ISSUE92_ACCEPTED_BASE_COMMIT}^{{tree}}"),
        )
        for relative, starting_sha256, starting_git_blob in (
            verifier.ISSUE92_POST_MERGE_MUTABLE_PATHS
        ):
            trusted_entry = _git(
                trusted_repository,
                "ls-tree",
                ISSUE92_ACCEPTED_BASE_COMMIT,
                "--",
                relative,
            )
            if starting_sha256 == "ABSENT":
                self.assertEqual("ABSENT", starting_git_blob)
                self.assertEqual("", trusted_entry)
                (repository / relative).unlink(missing_ok=True)
                continue
            self.assertEqual(
                f"100644 blob {starting_git_blob}\t{relative}", trusted_entry
            )
            trusted_bytes = _git_blob(trusted_repository, starting_git_blob)
            self.assertEqual(starting_sha256, verifier._sha256(trusted_bytes))
            _write(repository / relative, trusted_bytes)
        _write(
            repository / verifier.VALIDATOR_PATH,
            "#!/usr/bin/env python3\n"
            "import pathlib,sys\n"
            "root=pathlib.Path(sys.argv[1]).resolve()\n"
            "cwd=pathlib.Path.cwd().resolve()\n"
            "if cwd not in root.parents or not (root/'SKILL.md').is_file():\n"
            " raise SystemExit(42)\n"
            "print(f'POST-MERGE:{root.relative_to(cwd).as_posix()}')\n",
        )
        _write(
            repository / verifier.REGISTRY_AUDIT_PATH,
            "#!/usr/bin/env python3\n"
            "import pathlib,sys\n"
            "cwd=pathlib.Path.cwd().resolve()\n"
            "args=sys.argv[1:]\n"
            "config=pathlib.Path(args[args.index('--config')+1]).resolve()\n"
            "profiles=pathlib.Path(args[args.index('--profile-root')+1]).resolve()\n"
            "if cwd not in config.parents or cwd not in profiles.parents:\n"
            " raise SystemExit(43)\n"
            "print('POST-MERGE-REGISTRY')\n",
        )
        _write(
            repository / verifier.OWNER_SAFE_SQLITE_PATH,
            "class UnsafeSQLitePathError(RuntimeError): pass\n"
            "def prepare_owner_database(*args,**kwargs): return None\n",
        )
        _write(repository / verifier.REGISTRY_CONFIG_PATH, "schema_version = 2\n")
        for skill in verifier.SKILL_ROOTS:
            marker = repository / skill / "SKILL.md"
            if not marker.exists():
                _write(marker, f"# {skill}\n")
        _git(repository, "add", ".")
        _git(repository, "commit", "-m", "accepted base contains verifier")
        base_sha = _git(repository, "rev-parse", "HEAD")
        base_tree = _git(repository, "rev-parse", "HEAD^{tree}")
        _git(repository, "update-ref", "refs/remotes/origin/main", base_sha)

        accepted_base_mutable_paths = []
        for relative, starting_sha256, _ in (
            verifier.ISSUE92_POST_MERGE_MUTABLE_PATHS
        ):
            if starting_sha256 == "ABSENT":
                accepted_base_mutable_paths.append(
                    (relative, "ABSENT", "ABSENT")
                )
                continue
            starting_git_blob, base_sha256, _ = verifier._blob_identity(
                repository, base_tree, relative
            )
            accepted_base_mutable_paths.append(
                (relative, base_sha256, starting_git_blob)
            )
        accepted_base_mutable_paths = tuple(accepted_base_mutable_paths)

        _git(repository, "checkout", "-b", verifier.ISSUE92_POST_MERGE_BRANCH)
        for relative, starting_sha256, _ in accepted_base_mutable_paths:
            target = repository / relative
            if starting_sha256 == "ABSENT":
                _write(target, '{"synthetic":true}\n')
            else:
                target.write_bytes(target.read_bytes() + b"\n# synthetic candidate\n")
        _git(repository, "add", ".")
        _git(repository, "commit", "-m", "rebased synthetic issue92 candidate")
        candidate_head = _git(repository, "rev-parse", "HEAD")
        candidate_tree = _git(repository, "rev-parse", "HEAD^{tree}")
        prior_retained_head = _git(
            repository,
            "commit-tree",
            candidate_tree,
            "-p",
            old_base,
            "-m",
            "prior retained issue92 head",
        )
        _git(repository, "branch", "-D", "main")
        return temporary, {
            "repository": repository,
            "old_base": old_base,
            "old_base_tree": old_base_tree,
            "base_sha": base_sha,
            "base_tree": base_tree,
            "candidate_head": candidate_head,
            "candidate_tree": candidate_tree,
            "accepted_base_mutable_paths": accepted_base_mutable_paths,
            "contaminated_outer_paths": contaminated_outer_paths,
            "prior_retained_head": prior_retained_head,
            "prior_retained_tree": candidate_tree,
            "prior_retained_parent": old_base,
        }

    def _post_merge_issue92_constant_patch(self, fixture: dict[str, object]):
        return patch.multiple(
            verifier,
            ISSUE92_POST_MERGE_WORKTREE=os.fspath(fixture["repository"]),
            ISSUE92_POST_MERGE_PRIOR_RETAINED_HEAD=fixture[
                "prior_retained_head"
            ],
            ISSUE92_POST_MERGE_PRIOR_RETAINED_TREE=fixture[
                "prior_retained_tree"
            ],
            ISSUE92_POST_MERGE_PRIOR_RETAINED_PARENT=fixture[
                "prior_retained_parent"
            ],
        )

    def _verify(self, candidate_path: Path | None = None) -> dict[str, object]:
        return verifier.verify(
            direct_packet=self.packet_path,
            expected_packet_sha256=self.packet_sha256,
            candidate_receipt=candidate_path or self.candidate_path,
        )

    def _synthetic_v4_lineage(
        self, prefix: str
    ) -> tuple[Path, str, dict[str, object]]:
        def write_packet(value: object, name: str) -> tuple[Path, str]:
            path = self.root / f"{prefix}-{name}.json"
            path.write_bytes(verifier._canonical_bytes(value))
            return path, verifier._sha256(path.read_bytes())

        changed_paths = []
        historical_paths = []
        for relative in self.packet["mutable_path_order"]:
            blob, digest, contents = verifier._blob_identity(
                self.repository, self.head_tree, relative
            )
            mode = _git(
                self.repository, "ls-tree", self.head_tree, "--", relative
            ).split()[0]
            changed_paths.append(
                {
                    "path": relative,
                    "sha256": digest,
                    "git_blob": blob,
                    "bytes": len(contents),
                    "git_mode": mode,
                }
            )
            historical_paths.append(
                {
                    "path": relative,
                    "sha256": digest,
                    "git_blob": blob,
                    "bytes": len(contents),
                    "mode": "0755" if mode == "100755" else "0644",
                }
            )

        v1 = copy.deepcopy(self.packet)
        v1_path, v1_digest = write_packet(v1, "v1")

        v2 = copy.deepcopy(v1)
        v2["attempt_generation"] = 2
        v2["supersedes_packet_sha256"] = v1_digest
        v2["incorporated_packet"] = {
            "path": os.fspath(v1_path),
            "sha256": v1_digest,
        }
        v2.update(
            {
                "accountable_writer": "/root/synthetic-v2-writer",
                "writer_transfer": "FRESH_WRITER_INHERITS_THE_DIRECT_UNIT",
                "prior_writer": v1["accountable_writer"],
                "prior_writer_terminal_state": "INTERRUPTED_NO_REMOTE_EFFECT",
                "fresh_planner_disposition_reason": "SAME_SCOPE_RETRY",
                "repair_starting_head": self.base_sha,
                "repair_starting_tree": self.base_tree,
                "repository_fence": {
                    "observed_at": "2026-08-29T00:00:01Z",
                    "live_main": self.base_sha,
                    "open_pull_requests": 0,
                    "remote_branches": ["main"],
                    "candidate_remote_branch_present": False,
                    "local_branch_exact": True,
                    "local_worktree_exact": True,
                },
                "adopted_uncommitted_state": {
                    "changed_paths": self.packet["mutable_path_order"][:1],
                    "schema_sha256": "c" * 64,
                    "schema_json_valid": True,
                    "script_path_state": "ABSENT",
                    "test_path_state": "ABSENT",
                    "tracked_changes": 0,
                    "untracked_authorized_paths": 1,
                    "commit_created": False,
                    "validation_run": False,
                },
            }
        )
        v2_path, v2_digest = write_packet(v2, "v2")

        v3 = copy.deepcopy(v2)
        v3.pop("incorporated_packet")
        v3["attempt_generation"] = 3
        v3["supersedes_packet_sha256"] = v2_digest
        v3["incorporated_packets"] = [
            {"path": os.fspath(v1_path), "sha256": v1_digest},
            {"path": os.fspath(v2_path), "sha256": v2_digest},
        ]
        v3.update(
            {
                "accountable_writer": "/root/synthetic-v3-writer",
                "writer_transfer": "FRESH_WRITER_INHERITS_THE_DIRECT_UNIT",
                "prior_writer": v2["accountable_writer"],
                "prior_writer_terminal_state": "ACTIONABLE_HOLD_NO_REMOTE_EFFECT",
                "fresh_planner_disposition_reason": "SAME_SCOPE_REPAIR",
                "repair_starting_head": self.base_sha,
                "repair_starting_tree": self.base_tree,
                "incorporation": (
                    "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_EXCEPT_EXPLICIT_"
                    "WRITER_AND_REPAIR_FIELDS"
                ),
                "repository_fence": {
                    "observed_at": "2026-08-29T00:00:02Z",
                    "live_main": self.base_sha,
                    "live_main_tree": self.base_tree,
                    "open_pull_requests": 0,
                    "remote_branches": ["main"],
                    "candidate_remote_branch_present": False,
                    "local_branch_exact": True,
                    "local_worktree_exact": True,
                },
                "adopted_uncommitted_state": {
                    "status": (
                        "EXACTLY_FIVE_AUTHORIZED_UNTRACKED_PATHS_NO_TRACKED_DIFF"
                    ),
                    "head": self.base_sha,
                    "tree": self.base_tree,
                    "canonical_diff_sha256": "d" * 64,
                    "canonical_diff_bytes": 1,
                    "canonical_diff_algorithm": "SYNTHETIC_PACKET_ORDER_DIFF",
                    "paths": historical_paths,
                    "commit_created": False,
                    "remote_effect": False,
                },
                "inherited_validation_evidence": {
                    "focused_adversarial": "PASS_PRE_CHANGED_DIAGNOSIS",
                    "raw_fixed_skill_validators": "PASS_PRE_CHANGED_DIAGNOSIS",
                    "executor_registry_audit": "PASS_PRE_CHANGED_DIAGNOSIS",
                    "full_hermetic": "INVALID_GATE_SYNTHETIC",
                    "acceptance_effect": (
                        "NO_INHERITED_RESULT_AUTHORIZES_FINAL_HEAD_ACCEPTANCE"
                    ),
                },
                "changed_diagnosis": [
                    {
                        "code": "SYNTHETIC_PRIOR_FINDING",
                        "required_correction": "CLOSE_THE_PRIOR_PACKET",
                        "required_regression": "PRIOR_SUBSTITUTION_FAILS",
                    }
                ],
            }
        )
        v3_path, v3_digest = write_packet(v3, "v3")

        diff_digest = "a" * 64
        diff_bytes = 123
        manifest_paths = [
            {
                **item,
                "lines": len(
                    (self.repository / item["path"]).read_bytes().splitlines()
                ),
                "filesystem_mode": (
                    "0755" if item["git_mode"] == "100755" else "0644"
                ),
                "status": "M",
            }
            for item in changed_paths
        ]
        manifest = {
            "schema": "twinfinity-harness-source-validation-manifest/v1",
            "recorded_at": "2026-08-29T00:00:03Z",
            "repository": verifier.REPOSITORY,
            "owning_issue": ISSUE_NUMBER,
            "issue_body_sha256": self.packet["issue_body_sha256"],
            "terminal_state": "LOCAL_COMMIT_VALIDATED_AWAITING_PLANNER_CONTINUATION",
            "direct_packet": {
                "attempt_generation": 3,
                "incorporated_packet_sha256": [v1_digest, v2_digest],
                "mutable_paths_sha256": self.packet["mutable_paths_sha256"],
                "schema": "twinfinity-direct-harness-source-maintenance/v1",
                "sha256": v3_digest,
                "starting_main_contract_sha256": self.packet[
                    "starting_main_contract_sha256"
                ],
            },
            "base": {
                "ref": "refs/heads/main",
                "commit": self.base_sha,
                "tree": self.base_tree,
            },
            "head": {
                "ref": f"refs/heads/{self.branch}",
                "commit": self.head_sha,
                "tree": self.head_tree,
                "parents": [self.base_sha],
                "commits_from_base": 1,
                "subject": "candidate",
            },
            "canonical_diff": {
                "algorithm": (
                    "SHA256_OF_GIT_DIFF_BINARY_NO_EXT_DIFF_PARENT_HEAD_"
                    "PACKET_PATH_ORDER"
                ),
                "bytes": diff_bytes,
                "command": (
                    f"git diff --binary --no-ext-diff {self.base_sha} "
                    f"{self.head_sha} -- <packet-order-paths>"
                ),
                "packet_order_no_index_crosscheck_sha256": diff_digest,
                "sha256": diff_digest,
            },
            "changed_paths": manifest_paths,
            "validation_tool_provenance": {
                "accepted_base_materialization": {
                    "commit": self.base_sha,
                    "file_count": 226,
                    "symlink_count": 0,
                    "tree": self.base_tree,
                },
                "git": {"logical_path": "/usr/bin/git", "version": "2.43.0"},
                "hermetic_runner_sha256": "1" * 64,
                "jsonschema_version": "4.10.3",
                "python": {
                    "logical_path": "/usr/bin/python3",
                    "resolved_path": "/usr/bin/python3.12",
                    "version": "3.12.3",
                },
                "raw_executor_registry": {
                    "git_blob": "fde2137b37af0b46e99270f85acf06f0a3e4a102",
                    "sha256": (
                        "02b473448b3ce2f13db1b04491f6c6c4cf4ada114e2085b752cfcb91c6f38467"
                    ),
                },
                "raw_quick_validator": {
                    "git_blob": "877c9b384a56622098a4f863ac9e0a31242a3b2d",
                    "sha256": (
                        "1fd66498c219616fd9249eacdf16c458412ea9065a9d887fd716aeef03907762"
                    ),
                },
                "requirements_ci_sha256": "2" * 64,
            },
            "validations": [
                {
                    "command": "schema-check",
                    "gate": "draft_2020_12_schema",
                    "result": "PASS",
                },
                {"command": "compile", "gate": "py_compile", "result": "PASS"},
                {
                    "command": "focused",
                    "elapsed_seconds": 1.0,
                    "gate": "focused_adversarial",
                    "result": "PASS",
                    "tests_failed": 0,
                    "tests_passed": 24,
                },
                {
                    "command": "skills",
                    "failed": 0,
                    "gate": "immutable_current_main_fixed_skill_validators",
                    "ordered_skill_roots": list(verifier.SKILL_ROOTS),
                    "passed": len(verifier.SKILL_ROOTS),
                    "result": "PASS",
                },
                {
                    "command": "registry",
                    "config_sha256": (
                        "b8fc76a28fc4938449a970d65819eaadf0134fe642956a956e28eaf0bd5a4e31"
                    ),
                    "endpoints": {
                        "development": "role.development.v6",
                        "planner": "role.planner.v2",
                        "sre": "role.sre.v6",
                    },
                    "gate": "immutable_current_main_executor_registry_audit",
                    "result": "PASS",
                },
                {
                    "command": "full",
                    "elapsed_seconds": 1.0,
                    "environment": "clean",
                    "gate": "full_hermetic",
                    "result": "PASS",
                    "tests_failed": 0,
                    "tests_passed": 935,
                },
            ],
            "invalidated_invocations": [
                {
                    "invocation": "bad-command",
                    "reason": "no tests",
                    "result": "INVALID_COMMAND",
                },
                {
                    "invocation": "bad-environment",
                    "observed": "contaminated",
                    "reason": "caller state",
                    "resolution_evidence": "clean rerun",
                    "result": "INVALID_ENVIRONMENT",
                },
            ],
            "findings_closed": [
                "PASS_SCHEMA_NUMERIC_CONST_TYPE_MALLEABILITY",
                "PASS_SCHEMA_TERMINAL_STATE_NOT_CONST_BOUND",
                "RAW_COMMIT_PARENT_BLOCK_GRAMMAR_TOO_PERMISSIVE",
            ],
            "numeric_schema_note": "canonical raw JSON rejects float forms",
            "live_precommit_fence": {
                "candidate_remote_branch_present": False,
                "collision_drift": False,
                "direct_capacity_limit": 6,
                "direct_capacity_occupancy": 1,
                "main_commit": self.base_sha,
                "main_tree": self.base_tree,
                "observed_at": "2026-08-29T00:00:03Z",
                "open_pull_requests": 0,
                "remote_branches": ["main"],
                "sqlite_allocation_units": 0,
                "verdict": "PASS",
            },
            "cleanliness": {
                "diff_check": "PASS",
                "exact_changed_path_count": len(manifest_paths),
                "generated_worktree_artifacts": 0,
                "ignored_paths": 0,
                "lane_cleanup_performed": False,
                "owner_local_validation_run_root_retained": os.fspath(self.root),
                "tracked_or_untracked_fourth_paths": 0,
                "worktree_status": "CLEAN",
            },
            "excluded_effects": [
                "NO_REMOTE_PUSH",
                "NO_PULL_REQUEST_CREATION_OR_MUTATION",
                "NO_MERGE",
                "NO_GOVERNOR_SELF_APPROVAL",
                "NO_SQLITE_READ_OR_MUTATION_AS_AUTHORITY",
                "NO_SKILL_INSTALLATION_OR_RUNTIME_ACTIVATION",
                "NO_ENDPOINT_PROFILE_SYSTEMD_TIMER_OR_SERVICE_EFFECT",
                "NO_PROVIDER_HOSTED_DEPLOYMENT_TRAFFIC_PRODUCTION_OR_APPLICATION_EFFECT",
                "NO_MUTATION_OF_ISSUES_92_93_94_OR_96",
                "NO_BRANCH_WORKTREE_CAPACITY_OR_TERMINAL_CLEANUP",
            ],
        }
        manifest_path, manifest_digest = write_packet(manifest, "manifest")
        attempt = "twinfinity-skill-governor/synthetic-v4"
        report_digest = "b" * 64
        diagnosis = {
            "code": "SYNTHETIC_GOVERNOR_FINDING",
            "required_behavior": "CLOSE_THE_SYNTHETIC_PACKET_ENVELOPE",
            "required_regression": "SYNTHETIC_PACKET_MUTATIONS_FAIL",
        }
        rejection_receipt = {
            "schema": "twinfinity-harness-governor-rejection-receipt/v1",
            "recorded_at": "2026-08-29T00:00:04Z",
            "repository": verifier.REPOSITORY,
            "owning_issue": ISSUE_NUMBER,
            "issue_body_sha256": self.packet["issue_body_sha256"],
            "starting_main_contract_sha256": self.packet[
                "starting_main_contract_sha256"
            ],
            "base_sha": self.base_sha,
            "base_tree": self.base_tree,
            "head_sha": self.head_sha,
            "head_tree": self.head_tree,
            "canonical_diff_sha256": diff_digest,
            "canonical_diff_bytes": diff_bytes,
            "validation_manifest_bytes": len(manifest_path.read_bytes()),
            "validation_manifest_sha256": manifest_digest,
            "validation_manifest_correction_sha256": "3" * 64,
            "packet_sha256": v3_digest,
            "governor_contract_sha256": "4" * 64,
            "evaluation_rubric_sha256": "5" * 64,
            "governor_attempt_identity": attempt,
            "governor_report_sha256": report_digest,
            "terminal_verb": "REJECT_SOURCE_HEAD",
            "publication_authorized": False,
            "repair_authorized": False,
            "installation_or_runtime_authorized": False,
            "independent_focused_validation": "24_OF_24_PASS_BUT_INSUFFICIENT",
            "planner_next_action": (
                "FRESH_CHANGED_DIAGNOSIS_DISPOSITION_AND_PACKET_REQUIRED"
            ),
            "findings": [
                {
                    "code": diagnosis["code"],
                    "severity": "CRITICAL",
                    "required_change": "CLOSE_THE_SYNTHETIC_PACKET_ENVELOPE",
                }
            ],
        }
        rejection_path, rejection_digest = write_packet(
            rejection_receipt, "rejection"
        )

        v4 = copy.deepcopy(v3)
        v4.pop("adopted_uncommitted_state")
        v4.pop("inherited_validation_evidence")
        v4["attempt_generation"] = 4
        v4["supersedes_packet_sha256"] = v3_digest
        v4["incorporated_packets"] = [
            {"path": os.fspath(v1_path), "sha256": v1_digest},
            {"path": os.fspath(v2_path), "sha256": v2_digest},
            {"path": os.fspath(v3_path), "sha256": v3_digest},
        ]
        v4.update(
            {
                "incorporation": "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_EXCEPT_EXPLICIT_REPAIR_FIELDS",
                "issue_updated_at": "2026-08-29T00:01:00Z",
                "accountable_writer": "/root/synthetic-v4-writer",
                "writer_transfer": "FRESH_WRITER_INHERITS_THE_EXISTING_UNIT",
                "prior_writer": v3["accountable_writer"],
                "prior_writer_terminal_state": "GOVERNOR_REJECTED_NO_REMOTE_EFFECT",
                "fresh_planner_disposition_reason": "SAME_SCOPE_GOVERNOR_REPAIR",
                "repair_starting_head": self.head_sha,
                "repair_starting_tree": self.head_tree,
                "repair_starting_parent": self.base_sha,
                "governor_rejection": {
                    "terminal_verb": "REJECT_SOURCE_HEAD",
                    "attempt_identity": attempt,
                    "report_sha256": report_digest,
                    "receipt_path": os.fspath(rejection_path),
                    "receipt_sha256": rejection_digest,
                    "github_comment_id": 1,
                    "github_comment_url": (
                        "https://github.com/jayendusharma/twinfinity-harness/"
                        "issues/92#issuecomment-1"
                    ),
                    "publication_authorized": False,
                },
                "adopted_committed_state": {
                    "status": "CLEAN_EXACT_FIVE_PATH_SINGLE_COMMIT_FROM_STARTING_MAIN",
                    "head": self.head_sha,
                    "tree": self.head_tree,
                    "parent": self.base_sha,
                    "canonical_diff_sha256": diff_digest,
                    "canonical_diff_bytes": diff_bytes,
                    "validation_manifest_path": os.fspath(manifest_path),
                    "validation_manifest_sha256": manifest_digest,
                    "paths": changed_paths,
                    "worktree_clean": True,
                    "ignored_paths": 0,
                    "remote_effect": False,
                },
                "changed_diagnosis": [diagnosis],
            }
        )
        v4_path, v4_digest = write_packet(v4, "v4")
        return v4_path, v4_digest, v4

    def test_valid_receipt_is_independently_reexecuted_and_schema_valid(self) -> None:
        result = self._verify()
        self.schema_validator.validate(result)
        self.assertEqual("PASS", result["verdict"])
        self.assertEqual(self.base_sha, result["base"]["commit"])
        self.assertEqual(self.head_sha, result["head"]["commit"])
        self.assertEqual(24, len(result["observations"]))
        self.assertEqual(
            verifier._sha256(self.candidate_path.read_bytes()),
            result["candidate_receipt_sha256"],
        )
        replay = self._verify()
        self.assertEqual(verifier._canonical_bytes(result), verifier._canonical_bytes(replay))

    def test_forged_pass_observation_is_rejected(self) -> None:
        forged = copy.deepcopy(self.candidate)
        forged["observations"][0]["stdout_sha256"] = "f" * 64
        path = self._candidate_file(forged, "forged.json")
        with patch.object(
            verifier, "_execute_observations", return_value=self.observations
        ):
            with self.assertRaisesRegex(
                verifier.VerificationError, "BOOTSTRAP_CANDIDATE_OBSERVATION_MISMATCH"
            ):
                self._verify(path)

    def test_unknown_fields_and_boolean_numeric_substitution_are_rejected(self) -> None:
        unknown = copy.deepcopy(self.candidate)
        unknown["unexpected"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "CANDIDATE_SCHEMA"):
            self._verify(self._candidate_file(unknown, "unknown.json"))

        boolean = copy.deepcopy(self.candidate)
        boolean["observations"][0]["stdout_bytes"] = False
        with self.assertRaisesRegex(verifier.VerificationError, "OBSERVATION_TYPE"):
            self._verify(self._candidate_file(boolean, "boolean.json"))

        floating = copy.deepcopy(self.candidate)
        floating["command_manifest"]["commands"][0]["timeout_seconds"] = 60.0
        with self.assertRaisesRegex(verifier.VerificationError, "IDENTITY_OR_MANIFEST"):
            self._verify(self._candidate_file(floating, "floating.json"))

        external_float = copy.deepcopy(self.candidate)
        external_float["external_tools"][0]["size"] = float(
            external_float["external_tools"][0]["size"]
        )
        with self.assertRaisesRegex(verifier.VerificationError, "IDENTITY_OR_MANIFEST"):
            self._verify(self._candidate_file(external_float, "external-float.json"))

    def test_digest_rebound_float_equivalent_limits_are_rejected(self) -> None:
        cases = (
            ("manifest-timeout", "command_manifest", "timeout_seconds", 60.0),
            ("manifest-output", "command_manifest", "output_limit_bytes", 1048576.0),
            ("observation-timeout", "observations", "timeout_seconds", 60.0),
            ("observation-output", "observations", "output_limit_bytes", 1048576.0),
        )
        original_digest = verifier._sha256(self.candidate_path.read_bytes())
        for name, container, key, value in cases:
            with self.subTest(name=name):
                mutated = copy.deepcopy(self.candidate)
                if container == "command_manifest":
                    manifest = mutated[container]
                    manifest["commands"][0][key] = value
                    mutated["command_manifest_sha256"] = verifier._sha256(
                        verifier._canonical_bytes(manifest)
                    )
                    error = "IDENTITY_OR_MANIFEST"
                else:
                    mutated[container][0][key] = value
                    error = "OBSERVATION_TYPE"
                path = self._candidate_file(mutated, f"{name}.json")
                self.assertNotEqual(
                    original_digest,
                    verifier._sha256(path.read_bytes()),
                )
                with patch.object(
                    verifier,
                    "_execute_observations",
                    side_effect=AssertionError("must fail before execution"),
                ):
                    with self.assertRaisesRegex(verifier.VerificationError, error):
                        self._verify(path)

    def test_command_membership_order_and_arguments_are_frozen_before_execution(self) -> None:
        variants = []
        removed = copy.deepcopy(self.candidate)
        removed["command_manifest"]["commands"].pop()
        variants.append(removed)
        reordered = copy.deepcopy(self.candidate)
        reordered["command_manifest"]["commands"][0:2] = reversed(
            reordered["command_manifest"]["commands"][0:2]
        )
        variants.append(reordered)
        substituted = copy.deepcopy(self.candidate)
        substituted["command_manifest"]["commands"][0]["argv"][-1] = "HEAD/other"
        variants.append(substituted)
        duplicated = copy.deepcopy(self.candidate)
        duplicated["command_manifest"]["commands"][1] = copy.deepcopy(
            duplicated["command_manifest"]["commands"][0]
        )
        variants.append(duplicated)
        for index, candidate in enumerate(variants):
            with self.subTest(index=index), patch.object(
                verifier,
                "_execute_observations",
                side_effect=AssertionError("must fail before execution"),
            ):
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "BOOTSTRAP_CANDIDATE_IDENTITY_OR_MANIFEST_MISMATCH",
                ):
                    self._verify(self._candidate_file(candidate, f"manifest-{index}.json"))

    def test_false_tool_identity_and_replaced_running_verifier_are_rejected(self) -> None:
        false_identity = copy.deepcopy(self.candidate)
        false_identity["tool_identities"][0]["base_blob"] = "0" * 40
        with self.assertRaisesRegex(verifier.VerificationError, "IDENTITY_OR_MANIFEST"):
            self._verify(self._candidate_file(false_identity, "identity.json"))

        replacement = self.root / "replacement-verifier.py"
        replacement.write_text("# candidate replacement\n", encoding="utf-8")
        with patch.object(verifier, "__file__", os.fspath(replacement)):
            with self.assertRaisesRegex(
                verifier.VerificationError, "RUNNING_VERIFIER_NOT_ACCEPTED_BASE"
            ):
                verifier._prepare_evidence(
                    self.packet_path, self.packet_sha256
                )

    def test_equal_base_nonancestor_and_different_repository_fail(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "BASE_EQUALS_HEAD"):
            verifier._require_proper_ancestry(
                self.repository, self.base_sha, self.base_sha
            )

        with self.assertRaisesRegex(
            verifier.VerificationError, "BASE_NOT_ACCEPTED_ORIGIN_MAIN"
        ):
            false_packet = copy.deepcopy(self.packet)
            false_packet["starting_main_sha"] = self.head_sha
            false_packet["starting_main_tree"] = self.head_tree
            false_packet["repository_fence"]["live_main"] = self.head_sha
            false_packet["repository_fence"]["remote_branches"] = [
                {"name": "main", "sha": self.head_sha}
            ]
            false_packet["dependencies"]["predecessor_merge_result_main"] = (
                self.head_sha
            )
            false_path = self._candidate_file(false_packet, "false-packet.json")
            verifier._prepare_evidence(
                false_path, verifier._sha256(false_path.read_bytes())
            )

        side_branch = self.root / "side"
        _git(self.repository, "branch", "side", self.base_sha)
        _git(self.repository, "checkout", "side")
        _write(self.repository / "SIDE", "side\n")
        _git(self.repository, "add", "SIDE")
        _git(self.repository, "commit", "-m", "side")
        side_sha = _git(self.repository, "rev-parse", "HEAD")
        _git(self.repository, "checkout", self.branch)
        with self.assertRaisesRegex(verifier.VerificationError, "BASE_NOT_ANCESTOR"):
            verifier._require_proper_ancestry(
                self.repository, self.head_sha, side_sha
            )

        different = self.root / "different"
        different.mkdir(mode=0o700)
        _git(different, "init", "-b", "main")
        _git(different, "remote", "add", "origin", "https://example.invalid/other.git")
        with self.assertRaisesRegex(verifier.VerificationError, "ORIGIN_SUBSTITUTED"):
            verifier._resolve_repository(different)

    def test_raw_commit_parent_block_is_contiguous_and_strict(self) -> None:
        tree = "1" * 40
        other_parent = "2" * 40
        valid = (
            f"tree {tree}\n"
            f"parent {self.base_sha}\n"
            f"parent {other_parent}\n"
            "author Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
            "committer Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
            "\nmessage\n"
        ).encode("ascii")
        with patch.object(verifier, "_git_object_bytes", return_value=valid):
            self.assertEqual(
                (tree, (self.base_sha, other_parent)),
                verifier._raw_commit(self.repository, self.head_sha, "TEST"),
            )

        misplaced = (
            f"tree {tree}\n"
            "author Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
            f"parent {self.base_sha}\n"
            "committer Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
            "\nmessage\n"
        ).encode("ascii")
        with patch.object(verifier, "_git_object_bytes", return_value=misplaced):
            with self.assertRaisesRegex(
                verifier.VerificationError, "BOOTSTRAP_ANCESTRY_PARENT_INVALID"
            ):
                verifier._require_proper_ancestry(
                    self.repository, self.base_sha, self.head_sha
                )

        malformed_headers = (
            (valid.replace(b"\n\nmessage\n", b"\nmessage\n"), "COMMIT_INVALID"),
            (valid.replace(b"\n", b"\r\n"), "COMMIT_INVALID"),
        )
        for contents, error in malformed_headers:
            with self.subTest(error=error), patch.object(
                verifier, "_git_object_bytes", return_value=contents
            ):
                with self.assertRaisesRegex(
                    verifier.VerificationError, f"BOOTSTRAP_TEST_{error}"
                ):
                    verifier._raw_commit(self.repository, self.head_sha, "TEST")

    def test_noncanonical_and_symlink_candidate_receipts_fail(self) -> None:
        noncanonical = self.root / "noncanonical.json"
        noncanonical.write_text(json.dumps(self.candidate), encoding="utf-8")
        with self.assertRaisesRegex(verifier.VerificationError, "NOT_CANONICAL"):
            self._verify(noncanonical)
        symlink = self.root / "candidate-link.json"
        symlink.unlink(missing_ok=True)
        symlink.symlink_to(self.candidate_path)
        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_UNSAFE"):
            self._verify(symlink)

    @staticmethod
    def _synthetic_command() -> dict[str, object]:
        return {
            "command_id": "base:skill:skills/synthetic",
            "root": "BASE",
            "kind": "SKILL_VALIDATOR",
            "argv": [verifier.PYTHON, "ACCEPTED_BASE/synthetic.py", "BASE/skill"],
            "timeout_seconds": verifier.COMMAND_TIMEOUT,
            "output_limit_bytes": verifier.OUTPUT_LIMIT,
        }

    def _run_bounded_after_pid_marker_ready(
        self,
        actual_argv: list[str],
        *,
        pid_marker: Path,
        timeout_seconds: float,
        readiness_timeout_seconds: float = 2.0,
    ) -> dict[str, object]:
        real_popen = verifier.subprocess.Popen
        marker_ready = False

        def spawn_and_wait_for_marker(
            *arguments: object, **keywords: object
        ) -> subprocess.Popen[bytes]:
            nonlocal marker_ready
            process = real_popen(*arguments, **keywords)
            readiness_deadline = time.monotonic() + readiness_timeout_seconds
            while (
                not pid_marker.is_file()
                and process.poll() is None
                and time.monotonic() < readiness_deadline
            ):
                time.sleep(0.01)
            marker_ready = pid_marker.is_file()
            return process

        with patch.object(
            verifier.subprocess, "Popen", side_effect=spawn_and_wait_for_marker
        ):
            observation = verifier._run_bounded(
                actual_argv,
                canonical_command=self._synthetic_command(),
                cwd=self.root,
                environment=verifier._validation_environment(self.root),
                timeout_seconds=timeout_seconds,
            )
        self.assertTrue(
            marker_ready,
            "terminal descendant PID marker was not ready before timeout start",
        )
        return observation

    def test_timeout_and_output_limit_are_bounded_and_clean(self) -> None:
        environment = verifier._validation_environment(self.root)
        timeout = verifier._run_bounded(
            [verifier.PYTHON, "-c", "import time; time.sleep(30)"],
            canonical_command=self._synthetic_command(),
            cwd=self.root,
            environment=environment,
            timeout_seconds=0.1,
        )
        self.assertTrue(timeout["timed_out"])
        self.assertTrue(timeout["cleanup_verified"])
        self.assertNotEqual(0, timeout["exit_code"])

        output = verifier._run_bounded(
            [verifier.PYTHON, "-c", "import sys; sys.stdout.write('x'*100000)"],
            canonical_command=self._synthetic_command(),
            cwd=self.root,
            environment=environment,
            output_limit_bytes=128,
        )
        self.assertTrue(output["output_limited"])
        self.assertTrue(output["cleanup_verified"])
        self.assertLessEqual(int(output["stdout_bytes"]), 128)

    def test_setsid_sigterm_ignoring_descendant_cannot_survive(self) -> None:
        pid_file = self.root / "escaped.pid"
        pid_file.unlink(missing_ok=True)
        descendant = (
            "import os,signal,time,pathlib;"
            "os.setsid();signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            f"pathlib.Path({os.fspath(pid_file)!r}).write_text(str(os.getpid()));"
            "time.sleep(30)"
        )
        parent = (
            "import subprocess,time;"
            f"subprocess.Popen([{verifier.PYTHON!r},'-c',{descendant!r}],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL,close_fds=True);"
            "time.sleep(.15)"
        )
        observation = verifier._run_bounded(
            [verifier.PYTHON, "-c", parent],
            canonical_command=self._synthetic_command(),
            cwd=self.root,
            environment=verifier._validation_environment(self.root),
        )
        self.assertEqual("0", observation["exit_code"])
        self.assertTrue(observation["descendants_detected"])
        self.assertTrue(observation["cleanup_verified"])
        escaped_pid = int(pid_file.read_text(encoding="utf-8"))
        self.assertFalse(Path(f"/proc/{escaped_pid}").exists())

    def test_atomic_receipt_is_idempotent_concurrent_and_conflict_safe(self) -> None:
        target = self.root / "atomic-receipt.json"
        contents = verifier._canonical_bytes({"value": 1})
        for round_number in range(25):
            target.unlink(missing_ok=True)
            failures: list[BaseException] = []

            def writer() -> None:
                try:
                    verifier._write_atomic_receipt(target, contents)
                except BaseException as exc:  # pragma: no cover - diagnostic capture
                    failures.append(exc)

            threads = [threading.Thread(target=writer) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2)
            with self.subTest(concurrent_round=round_number):
                self.assertTrue(all(not thread.is_alive() for thread in threads))
                self.assertEqual([], failures)
                self.assertEqual(contents, target.read_bytes())
        verifier._write_atomic_receipt(target, contents)
        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_CONFLICT"):
            verifier._write_atomic_receipt(
                target, verifier._canonical_bytes({"value": 2})
            )
        self.assertEqual(contents, target.read_bytes())
        self.assertEqual([], list(self.root.glob(".atomic-receipt.json.tmp.*")))

        window_target = self.root / "window-receipt.json"
        window_target.unlink(missing_ok=True)
        linked_window = threading.Event()
        release_winner = threading.Event()
        guard_lock = threading.Lock()
        guard_calls = 0
        window_failures: list[BaseException] = []

        def pause_after_link() -> None:
            nonlocal guard_calls
            with guard_lock:
                guard_calls += 1
                current_call = guard_calls
            if current_call == 3:
                linked_window.set()
                if not release_winner.wait(2):
                    raise RuntimeError("publication-window timeout")

        def window_writer(*, pause: bool) -> None:
            try:
                verifier._write_atomic_receipt(
                    window_target,
                    contents,
                    publication_guard=pause_after_link if pause else None,
                )
            except BaseException as exc:  # pragma: no cover - diagnostic capture
                window_failures.append(exc)

        winner = threading.Thread(target=window_writer, kwargs={"pause": True})
        winner.start()
        self.assertTrue(linked_window.wait(2))
        loser = threading.Thread(target=window_writer, kwargs={"pause": False})
        loser.start()
        time.sleep(0.05)
        release_winner.set()
        winner.join(2)
        loser.join(2)
        self.assertFalse(winner.is_alive())
        self.assertFalse(loser.is_alive())
        self.assertEqual([], window_failures)
        self.assertEqual(contents, window_target.read_bytes())
        self.assertEqual(1, window_target.stat().st_nlink)
        self.assertEqual([], list(self.root.glob(".window-receipt.json.tmp.*")))

        contested = self.root / "contested-receipt.json"
        contested.unlink(missing_ok=True)
        left = verifier._canonical_bytes({"writer": "left"})
        right = verifier._canonical_bytes({"writer": "right"})
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def conflicting_writer(payload: bytes) -> None:
            barrier.wait()
            try:
                verifier._write_atomic_receipt(contested, payload)
                outcomes.append("PASS")
            except verifier.VerificationError as exc:
                outcomes.append(str(exc))

        contenders = [
            threading.Thread(target=conflicting_writer, args=(payload,))
            for payload in (left, right)
        ]
        for contender in contenders:
            contender.start()
        for contender in contenders:
            contender.join()
        self.assertEqual(1, outcomes.count("PASS"))
        self.assertEqual(1, outcomes.count("BOOTSTRAP_RECEIPT_CONFLICT"))
        self.assertIn(contested.read_bytes(), {left, right})
        self.assertEqual(1, contested.stat().st_nlink)
        self.assertEqual([], list(self.root.glob(".contested-receipt.json.tmp.*")))

    def test_manifest_is_exact_fixed_eleven_plus_registry_for_both_roots(self) -> None:
        manifest = verifier._command_manifest()
        commands = manifest["commands"]
        self.assertEqual(24, len(commands))
        self.assertEqual(22, sum(item["kind"] == "SKILL_VALIDATOR" for item in commands))
        self.assertEqual(
            2, sum(item["kind"] == "EXECUTOR_REGISTRY_AUDIT" for item in commands)
        )
        self.assertEqual(
            [f"base:skill:{root}" for root in verifier.SKILL_ROOTS],
            [item["command_id"] for item in commands[:11]],
        )
        self.assertEqual(
            [f"head:skill:{root}" for root in verifier.SKILL_ROOTS],
            [item["command_id"] for item in commands[12:23]],
        )
        self.assertEqual(
            {verifier.PYTHON_MANIFEST_TOKEN},
            {item["argv"][0] for item in commands},
        )

    def test_executing_python_is_kernel_derived_and_exactly_attested(self) -> None:
        self.assertEqual(verifier.PYTHON, verifier._derive_executing_interpreter_path())
        identity = verifier._external_tools()[0]
        executable_stat = os.fstat(verifier.PYTHON_SOURCE_FD)
        self.assertEqual("python", identity["name"])
        self.assertEqual(verifier.PYTHON, identity["logical_path"])
        self.assertEqual(verifier.PYTHON, identity["resolved_path"])
        self.assertEqual(str(executable_stat.st_dev), identity["device"])
        self.assertEqual(str(executable_stat.st_ino), identity["inode"])
        self.assertEqual(str(executable_stat.st_mode), identity["mode"])
        self.assertEqual(str(executable_stat.st_uid), identity["uid"])
        self.assertEqual(str(executable_stat.st_gid), identity["gid"])
        self.assertEqual(str(executable_stat.st_nlink), identity["link_count"])
        self.assertEqual(str(executable_stat.st_mtime_ns), identity["mtime_ns"])
        self.assertEqual(str(executable_stat.st_ctime_ns), identity["ctime_ns"])
        self.assertEqual(
            verifier.PINNED_PYTHON_EXECUTION_SOURCE,
            identity["execution_source"],
        )
        self.assertEqual(identity["sha256"], identity["execution_sha256"])
        execution = verifier._attest_python_execution()
        self.assertEqual(executable_stat.st_dev, execution["device"])
        self.assertEqual(executable_stat.st_ino, execution["inode"])
        with self.assertRaises(OSError) as denied:
            os.open(verifier.PYTHON_EXECUTABLE, os.O_WRONLY)
        self.assertIn(denied.exception.errno, {errno.EACCES, errno.ETXTBSY})

    def test_alternate_absolute_executing_python_path_is_accepted(self) -> None:
        alternate = self.root / "alternate-executing-python"
        alternate.write_bytes(Path(verifier.PYTHON).read_bytes())
        alternate.chmod(0o700)
        proc_alias = self.root / "alternate-proc-self-exe"
        proc_alias.symlink_to(alternate)
        with (
            patch.object(verifier, "PYTHON_PROC_SELF_EXE", os.fspath(proc_alias)),
            patch.object(verifier.sys, "executable", os.fspath(alternate)),
        ):
            path, descriptor, identity, execution = (
                verifier._bind_executing_interpreter()
            )
        try:
            self.assertEqual(os.fspath(alternate), path)
            command = [
                f"/proc/self/fd/{descriptor}",
                "-B",
                "-I",
                "-c",
                "import sys;print(sys.version_info[0])",
            ]
            completed = subprocess.run(
                command,
                executable=command[0],
                pass_fds=(descriptor,),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("3", completed.stdout.strip())
            attested = verifier._attest_python_execution(execution)
            self.assertEqual(execution["sha256"], attested["sha256"])
            self.assertEqual(execution["inode"], attested["inode"])
        finally:
            os.close(descriptor)
        self.assertEqual(os.fspath(alternate), identity["logical_path"])
        self.assertEqual(os.fspath(alternate), identity["resolved_path"])

    def test_python_path_swap_and_transient_bytes_substitution_cannot_win(self) -> None:
        original = self.root / "pinned-python-original"
        replacement = self.root / "pinned-python-replacement"
        original.write_bytes(Path(verifier.PYTHON).read_bytes())
        replacement.write_bytes(Path(verifier.GIT).read_bytes())
        original.chmod(0o700)
        replacement.chmod(0o700)
        proc_alias = self.root / "pinned-python-proc-alias"
        proc_alias.symlink_to(original)
        with (
            patch.object(verifier, "PYTHON_PROC_SELF_EXE", os.fspath(proc_alias)),
            patch.object(verifier.sys, "executable", os.fspath(original)),
        ):
            _, descriptor, _, execution = verifier._bind_executing_interpreter()
        try:
            proc_alias.unlink()
            proc_alias.symlink_to(replacement)
            marker = self.root / "pinned-python-running"
            command = [
                f"/proc/self/fd/{descriptor}",
                "-B",
                "-I",
                "-c",
                (
                    "import pathlib,time;"
                    f"pathlib.Path({os.fspath(marker)!r}).write_text('ready');"
                    "time.sleep(0.25);print('ORIGINAL')"
                ),
            ]
            process = subprocess.Popen(
                command,
                executable=command[0],
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertTrue(marker.exists())
            with self.assertRaises(OSError) as denied:
                os.open(original, os.O_WRONLY)
            self.assertEqual(errno.ETXTBSY, denied.exception.errno)
            stdout, stderr = process.communicate(timeout=2)
            self.assertEqual(0, process.returncode, stderr)
            self.assertEqual("ORIGINAL", stdout.strip())
            attested = verifier._attest_python_execution(execution)
            self.assertEqual(execution["sha256"], attested["sha256"])
            self.assertEqual(execution["inode"], attested["inode"])
        finally:
            os.close(descriptor)

    def test_python_caller_or_bound_identity_override_is_rejected(self) -> None:
        with patch.object(verifier.sys, "executable", verifier.GIT):
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED",
            ):
                verifier._derive_executing_interpreter_path()
        with patch.object(verifier, "PYTHON", verifier.GIT):
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED",
            ):
                verifier._external_tools()

    def test_external_tool_resolved_path_and_bytes_drift_are_detected(self) -> None:
        first = self.root / "external-python-first"
        second = self.root / "external-python-second"
        first.write_bytes(b"first external tool\n")
        second.write_bytes(b"other external tool\n")
        first.chmod(0o700)
        second.chmod(0o700)
        logical = self.root / "external-python"
        logical.symlink_to(first)
        real_read = verifier._read_regular_with_identity

        def read_then_substitute(*args: object, **kwargs: object) -> object:
            result = real_read(*args, **kwargs)
            logical.unlink()
            logical.symlink_to(second)
            return result

        with patch.object(
            verifier,
            "_read_regular_with_identity",
            side_effect=read_then_substitute,
        ):
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "BOOTSTRAP_EXTERNAL_TOOL_DRIFT",
            ):
                verifier._external_identity("python", os.fspath(logical))

        before = verifier._external_identity("python", os.fspath(second))
        second.write_bytes(b"drift external tool\n")
        second.chmod(0o700)
        after = verifier._external_identity("python", os.fspath(second))
        self.assertNotEqual(before, after)
        self.assertNotEqual(before["sha256"], after["sha256"])

    def test_schema_uses_portable_noncapturing_command_pattern(self) -> None:
        pattern = self.schema["$defs"]["command"]["properties"]["command_id"][
            "pattern"
        ]
        self.assertNotIn("(?>", pattern)
        self.assertIn("(?:skill:", pattern)

    def test_git_replacements_are_disabled_and_reads_are_bounded(self) -> None:
        base_tree = _git(self.repository, "show", "-s", "--format=%T", self.base_sha)
        _git(
            self.repository,
            "update-ref",
            f"refs/replace/{self.base_sha}",
            self.head_sha,
        )
        try:
            resolved = verifier._resolve_commit(
                self.repository, self.base_sha, "BASE"
            )
            self.assertEqual(base_tree, resolved["tree"])
        finally:
            _git(
                self.repository,
                "update-ref",
                "-d",
                f"refs/replace/{self.base_sha}",
            )
        blob = _git(self.repository, "rev-parse", f"{self.head_sha}:README.md")
        with self.assertRaisesRegex(verifier.VerificationError, "GIT_OUTPUT_LIMIT"):
            verifier._git(
                self.repository,
                ("cat-file", "blob", blob),
                output_limit=2,
            )

    def test_exact_tree_materialization_ignores_archive_attributes(self) -> None:
        _git(self.repository, "checkout", "-b", "attributes", self.head_sha)
        try:
            _write(
                self.repository / ".gitattributes",
                "README.md export-ignore export-subst\n",
            )
            _git(self.repository, "add", ".gitattributes")
            _git(self.repository, "commit", "-m", "attributes")
            attributes_sha = _git(self.repository, "rev-parse", "HEAD")
            attributes_tree, _ = verifier._raw_commit(
                self.repository, attributes_sha, "ATTRIBUTES"
            )
            extracted = self.root / "attribute-extraction"
            if extracted.exists():
                self.fail("test extraction root unexpectedly exists")
            verifier._extract_tree(self.repository, attributes_tree, extracted)
            self.assertEqual("candidate\n", (extracted / "README.md").read_text())
            self.assertEqual(
                0o700,
                stat.S_IMODE(
                    (extracted / verifier.REGISTRY_AUDIT_PATH).stat().st_mode
                ),
            )
        finally:
            _git(self.repository, "checkout", self.branch)

    def test_atomic_receipt_rejects_symlinked_output_parent(self) -> None:
        real_parent = self.root / "real-output-parent"
        real_parent.mkdir(mode=0o700, exist_ok=True)
        linked_parent = self.root / "linked-output-parent"
        linked_parent.unlink(missing_ok=True)
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(verifier.VerificationError, "PARENT_UNSAFE"):
            verifier._write_atomic_receipt(
                linked_parent / "receipt.json",
                verifier._canonical_bytes({"value": 1}),
            )

    def test_schema_closes_every_ordered_identity_and_command_slot(self) -> None:
        result = {
            "schema": "twinfinity-harness-bootstrap-verifier/v1",
            "repository": verifier.REPOSITORY,
            "issue_number": str(ISSUE_NUMBER),
            "packet_sha256": self.packet_sha256,
            "base": self.evidence["base"],
            "head": self.evidence["head"],
            "candidate_receipt_sha256": verifier._sha256(
                self.candidate_path.read_bytes()
            ),
            "tool_identities": self.evidence["tool_identities"],
            "external_tools": self.evidence["external_tools"],
            "command_manifest": self.evidence["command_manifest"],
            "command_manifest_sha256": self.evidence["command_manifest_sha256"],
            "observations": self.observations,
            "verdict": "PASS",
            "evidence_scope": verifier.EVIDENCE_SCOPE,
        }
        self.schema_validator.validate(result)
        for definition in ("command", "observation"):
            properties = self.schema["$defs"][definition]["properties"]
            self.assertEqual(
                {"const": "60"},
                properties["timeout_seconds"],
            )
            self.assertEqual(
                {"const": "1048576"},
                properties["output_limit_bytes"],
            )
        mutations: list[dict[str, object]] = []
        for key in ("tool_identities", "external_tools"):
            mutated = copy.deepcopy(result)
            mutated[key][0], mutated[key][1] = mutated[key][1], mutated[key][0]
            mutations.append(mutated)
        command_swap = copy.deepcopy(result)
        commands = command_swap["command_manifest"]["commands"]
        commands[0], commands[1] = commands[1], commands[0]
        mutations.append(command_swap)
        command_argv = copy.deepcopy(result)
        command_argv["command_manifest"]["commands"][0]["argv"][-1] = "BASE/other"
        mutations.append(command_argv)
        observation_swap = copy.deepcopy(result)
        observations = observation_swap["observations"]
        observations[0], observations[1] = observations[1], observations[0]
        mutations.append(observation_swap)
        observation_root = copy.deepcopy(result)
        observation_root["observations"][0]["root"] = "HEAD"
        mutations.append(observation_root)
        for key, value in (
            ("exit_code", 1),
            ("timed_out", True),
            ("output_limited", True),
            ("cleanup_verified", False),
        ):
            terminal = copy.deepcopy(result)
            terminal["observations"][0][key] = value
            rebound_candidate = copy.deepcopy(self.candidate)
            rebound_candidate["observations"] = terminal["observations"]
            terminal["candidate_receipt_sha256"] = verifier._sha256(
                verifier._canonical_bytes(rebound_candidate)
            )
            mutations.append(terminal)
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                self.assertFalse(self.schema_validator.is_valid(mutated))

    def test_packet_worktree_branch_and_remote_main_are_exactly_bound(self) -> None:
        linked = self.root / "twinfinity-harness-issue92-link"
        linked.unlink(missing_ok=True)
        linked.symlink_to(self.repository, target_is_directory=True)
        linked_packet = copy.deepcopy(self.packet)
        linked_packet["worktree_path"] = os.fspath(linked)
        linked_packet["opaque_worktree_id"] = linked.name
        linked_path = self._candidate_file(linked_packet, "linked-packet.json")
        with self.assertRaisesRegex(verifier.VerificationError, "REPOSITORY_INVALID"):
            verifier._prepare_evidence(
                linked_path, verifier._sha256(linked_path.read_bytes())
            )

        wrong_branch = copy.deepcopy(self.packet)
        wrong_branch["branch"] = "change/93-bootstrap-test"
        wrong_path = self._candidate_file(wrong_branch, "wrong-branch-packet.json")
        with self.assertRaisesRegex(verifier.VerificationError, "PACKET_BINDING"):
            verifier._load_direct_packet(
                wrong_path, verifier._sha256(wrong_path.read_bytes())
            )

        local_main = subprocess.run(
            [
                verifier.GIT,
                "-C",
                os.fspath(self.repository),
                "show-ref",
                "--verify",
                "--hash",
                "refs/heads/main",
            ],
            capture_output=True,
            env=verifier._git_environment(),
            check=False,
        )
        self.assertNotEqual(0, local_main.returncode)
        _git(
            self.repository,
            "update-ref",
            "refs/remotes/origin/main",
            self.head_sha,
        )
        try:
            with self.assertRaisesRegex(
                verifier.VerificationError, "BASE_NOT_ACCEPTED_ORIGIN_MAIN"
            ):
                verifier._prepare_evidence(self.packet_path, self.packet_sha256)
        finally:
            _git(
                self.repository,
                "update-ref",
                "refs/remotes/origin/main",
                self.base_sha,
            )

    def test_raw_objects_are_digest_checked_and_empty_trees_preserved(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 0, b"blob\n", b""),
            subprocess.CompletedProcess([], 0, b"3\n", b""),
            subprocess.CompletedProcess([], 0, b"abc", b""),
        ]
        with patch.object(verifier, "_git", side_effect=responses):
            with self.assertRaisesRegex(
                verifier.VerificationError, "OBJECT_DIGEST_MISMATCH"
            ):
                verifier._git_object_bytes(
                    self.repository,
                    "0" * 40,
                    "blob",
                    maximum=3,
                    label="TEST",
                )

        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": os.fspath(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }

        def write_object(object_type: str, contents: bytes) -> str:
            completed = subprocess.run(
                [
                    verifier.GIT,
                    "-C",
                    os.fspath(self.repository),
                    "hash-object",
                    "-w",
                    "-t",
                    object_type,
                    "--stdin",
                ],
                input=contents,
                capture_output=True,
                check=True,
                env=environment,
            )
            return completed.stdout.decode("ascii").strip()

        empty = write_object("tree", b"")
        root_tree = write_object(
            "tree", b"40000 empty\0" + bytes.fromhex(empty)
        )
        destination = self.root / "empty-tree-extraction"
        verifier._extract_tree(self.repository, root_tree, destination)
        self.assertTrue((destination / "empty").is_dir())
        self.assertEqual([], list((destination / "empty").iterdir()))

        blob = write_object("blob", b"target")
        unsafe_tree = write_object(
            "tree", b"120000 link\0" + bytes.fromhex(blob)
        )
        with self.assertRaisesRegex(verifier.VerificationError, "TREE_ENTRY_UNSAFE"):
            verifier._extract_tree(
                self.repository, unsafe_tree, self.root / "unsafe-tree-extraction"
            )

    def test_atomic_receipt_recovers_crash_and_rejects_unexplained_links(self) -> None:
        contents = verifier._canonical_bytes({"crash": True})
        target = self.root / "crash-receipt.json"
        process_identity = verifier._proc_stat(os.getpid())
        self.assertIsNotNone(process_identity)
        assert process_identity is not None
        temporary = self.root / (
            f".crash-receipt.json.tmp.{os.getpid()}.{process_identity[2] + 1}."
            f"{threading.get_native_id()}.0.0"
        )
        temporary.write_bytes(contents)
        temporary.chmod(0o600)
        os.link(temporary, target)
        self.assertEqual(2, target.stat().st_nlink)
        verifier._write_atomic_receipt(target, contents)
        self.assertEqual(contents, target.read_bytes())
        self.assertEqual(1, target.stat().st_nlink)
        self.assertFalse(temporary.exists())

        foreign = self.root / "foreign-hardlink"
        foreign.write_bytes(contents)
        foreign.chmod(0o600)
        unexplained = self.root / "unexplained-receipt.json"
        os.link(foreign, unexplained)
        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_CONFLICT"):
            verifier._write_atomic_receipt(unexplained, contents)
        self.assertEqual(2, foreign.stat().st_nlink)

        fifo = self.root / "receipt-fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_CONFLICT"):
            verifier._write_atomic_receipt(fifo, contents)

        backing = self.root / "receipt-backing"
        backing.write_bytes(contents)
        link = self.root / "receipt-target-link"
        link.symlink_to(backing)
        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_CONFLICT"):
            verifier._write_atomic_receipt(link, contents)

    def test_atomic_receipt_rejects_renamed_or_rebound_lexical_parent(self) -> None:
        parent = self.root / "pinned-parent"
        parent.mkdir(mode=0o700)
        moved = self.root / "pinned-parent-moved"
        target = parent / "receipt.json"
        contents = verifier._canonical_bytes({"pinned": True})
        real_open = verifier._open_output_directory

        def swap_after_open(path: Path) -> tuple[int, str]:
            descriptor, name = real_open(path)
            parent.rename(moved)
            parent.mkdir(mode=0o700)
            return descriptor, name

        calls = 0

        def swap_once(path: Path) -> tuple[int, str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return swap_after_open(path)
            return real_open(path)

        with patch.object(verifier, "_open_output_directory", side_effect=swap_once):
            with self.assertRaisesRegex(verifier.VerificationError, "PARENT_UNSAFE"):
                verifier._write_atomic_receipt(target, contents)
        self.assertFalse((parent / "receipt.json").exists())
        self.assertFalse((moved / "receipt.json").exists())
        self.assertEqual([], list(moved.glob(".receipt.json.tmp.*")))

    def test_git_and_exception_paths_reap_escaped_descendants(self) -> None:
        git_pid = self.root / "git-helper.pid"
        fake_git = self.root / "fake-git"
        child = (
            "import os,signal,time,pathlib;os.setsid();"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            f"pathlib.Path({os.fspath(git_pid)!r}).write_text(str(os.getpid()));"
            "time.sleep(30)"
        )
        fake_git.write_text(
            "#!/usr/bin/python3\n"
            "import pathlib,subprocess,time\n"
            f"p=subprocess.Popen(['/usr/bin/python3','-c',{child!r}],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL,close_fds=True)\n"
            f"path=pathlib.Path({os.fspath(git_pid)!r})\n"
            "deadline=time.monotonic()+2\n"
            "while not path.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
            "print('ok')\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o700)
        with patch.object(verifier, "GIT", os.fspath(fake_git)):
            completed = verifier._git(self.repository, ("ignored",))
        self.assertEqual(b"ok\n", completed.stdout)
        helper_pid = int(git_pid.read_text(encoding="utf-8"))
        self.assertFalse(Path(f"/proc/{helper_pid}").exists())

        escaped_pid = self.root / "exception-helper.pid"
        escaped_child = (
            "import os,signal,time,pathlib;os.setsid();"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            f"pathlib.Path({os.fspath(escaped_pid)!r}).write_text(str(os.getpid()));"
            "time.sleep(30)"
        )
        parent_code = (
            "import subprocess,time;"
            f"subprocess.Popen([{verifier.PYTHON!r},'-c',{escaped_child!r}],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL,close_fds=True);time.sleep(30)"
        )
        real_remember = verifier._remember_processes
        raised = False

        def fail_after_discovery(*arguments: object) -> None:
            nonlocal raised
            real_remember(*arguments)
            if not raised:
                deadline = time.monotonic() + 2
                while not escaped_pid.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raised = True
                raise verifier.VerificationError("SYNTHETIC_POST_SPAWN_FAILURE")

        with patch.object(verifier, "_remember_processes", side_effect=fail_after_discovery):
            with self.assertRaisesRegex(
                verifier.VerificationError, "SYNTHETIC_POST_SPAWN_FAILURE"
            ):
                verifier._run_bounded(
                    [verifier.PYTHON, "-c", parent_code],
                    canonical_command=self._synthetic_command(),
                    cwd=self.root,
                    environment=verifier._validation_environment(self.root),
                )
        exception_pid = int(escaped_pid.read_text(encoding="utf-8"))
        self.assertFalse(Path(f"/proc/{exception_pid}").exists())

    def test_late_and_all_terminal_descendants_cannot_survive(self) -> None:
        environment = verifier._validation_environment(self.root)
        scenarios = (
            ("nonzero", "raise SystemExit(7)", {}),
            ("timeout", "time.sleep(30)", {"timeout_seconds": 0.1}),
            (
                "output",
                "import sys;sys.stdout.write('x'*100000)",
                {"output_limit_bytes": 128},
            ),
        )
        for name, terminal, overrides in scenarios:
            pid_file = self.root / f"{name}-terminal.pid"
            pid_file.unlink(missing_ok=True)
            startup_delay = "time.sleep(.2);" if name == "timeout" else ""
            child = (
                "import os,signal,time,pathlib;os.setsid();"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                f"pathlib.Path({os.fspath(pid_file)!r}).write_text(str(os.getpid()));"
                "time.sleep(30)"
            )
            parent = (
                "import pathlib,subprocess,time;"
                f"{startup_delay}"
                f"subprocess.Popen([{verifier.PYTHON!r},'-c',{child!r}],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL,close_fds=True);"
                f"p=pathlib.Path({os.fspath(pid_file)!r});"
                "deadline=time.monotonic()+2;"
                "exec(\"while not p.exists() and time.monotonic()<deadline: time.sleep(.01)\");"
                f"exec({terminal!r})"
            )
            if name == "timeout":
                observation = self._run_bounded_after_pid_marker_ready(
                    [verifier.PYTHON, "-c", parent],
                    pid_marker=pid_file,
                    timeout_seconds=overrides["timeout_seconds"],
                )
            else:
                observation = verifier._run_bounded(
                    [verifier.PYTHON, "-c", parent],
                    canonical_command=self._synthetic_command(),
                    cwd=self.root,
                    environment=environment,
                    **overrides,
                )
            self.assertTrue(
                pid_file.is_file(), f"{name} descendant PID marker was not created"
            )
            self.assertTrue(observation["descendants_detected"], name)
            self.assertTrue(observation["cleanup_verified"], name)
            pid = int(pid_file.read_text(encoding="utf-8"))
            self.assertFalse(Path(f"/proc/{pid}").exists(), name)

        late_pid = self.root / "late-descendant.pid"
        late_child = (
            "import os,signal,time;os.setsid();"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)"
        )
        handler = (
            "import os,pathlib,signal,subprocess,time\n"
            f"path=pathlib.Path({os.fspath(late_pid)!r})\n"
            "def handler(signum,frame):\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            f" p=subprocess.Popen([{verifier.PYTHON!r},'-c',{late_child!r}],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL,close_fds=True)\n"
            " path.write_text(str(p.pid))\n"
            "signal.signal(signal.SIGTERM,handler)\n"
            "time.sleep(30)\n"
        )
        late = verifier._run_bounded(
            [verifier.PYTHON, "-c", handler],
            canonical_command=self._synthetic_command(),
            cwd=self.root,
            environment=environment,
            timeout_seconds=0.1,
        )
        self.assertTrue(late["timed_out"])
        self.assertTrue(late["descendants_detected"])
        self.assertTrue(late["cleanup_verified"])
        pid = int(late_pid.read_text(encoding="utf-8"))
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_terminal_pid_marker_readiness_failure_is_deterministic(self) -> None:
        missing_marker = self.root / "missing-terminal.pid"
        missing_marker.unlink(missing_ok=True)
        with self.assertRaisesRegex(
            AssertionError,
            "terminal descendant PID marker was not ready before timeout start",
        ):
            self._run_bounded_after_pid_marker_ready(
                [verifier.PYTHON, "-c", "import time; time.sleep(30)"],
                pid_marker=missing_marker,
                timeout_seconds=0.1,
                readiness_timeout_seconds=0.05,
            )
        self.assertFalse(missing_marker.exists())

    def test_extracted_tool_substitution_is_rejected_before_sealed_execution(self) -> None:
        sentinel = self.root / "same-uid-substitution-sentinel"
        sentinel.unlink(missing_ok=True)
        real_extract = verifier._extract_tree
        extracted_base: Path | None = None

        def extract_then_substitute(
            repository: Path, tree: str, destination: Path
        ) -> dict[str, tuple[str, int, int, str]]:
            nonlocal extracted_base
            expected = real_extract(repository, tree, destination)
            if destination.name == "base":
                extracted_base = destination
            elif destination.name == "head":
                self.assertIsNotNone(extracted_base)
                forged = (
                    "import pathlib\n"
                    f"pathlib.Path({os.fspath(sentinel)!r}).write_text('FORGED\\n')\n"
                    "raise SystemExit(73)\n"
                )
                for relative in (
                    verifier.VALIDATOR_PATH,
                    verifier.REGISTRY_AUDIT_PATH,
                    verifier.OWNER_SAFE_SQLITE_PATH,
                ):
                    target = extracted_base / relative
                    self.assertEqual(os.getuid(), target.stat().st_uid)
                    target.write_text(forged, encoding="utf-8")
            return expected

        with patch.object(
            verifier, "_extract_tree", side_effect=extract_then_substitute
        ):
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "BOOTSTRAP_VALIDATION_ROOT_DRIFT",
            ):
                verifier._execute_observations(
                    self.repository,
                    self.base_tree,
                    self.head_tree,
                    self.evidence["command_manifest"],
                )
        self.assertFalse(sentinel.exists())

    def test_validation_roots_reject_every_transient_mutation_class(self) -> None:
        def exercise(
            mutate,
        ) -> None:
            with tempfile.TemporaryDirectory(prefix="root-guard-mutation-") as raw:
                private = Path(raw)
                private.chmod(0o700)
                scratch = private / "scratch"
                scratch.mkdir(mode=0o700)
                base = private / "base"
                head = private / "head"
                base_expected = verifier._extract_tree(
                    self.repository, self.base_tree, base
                )
                head_expected = verifier._extract_tree(
                    self.repository, self.head_tree, head
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "BOOTSTRAP_VALIDATION_ROOT_DRIFT",
                ):
                    with verifier._ValidationRootGuard(
                        private,
                        ((base, base_expected), (head, head_expected)),
                    ) as guard:
                        mutate(base, head, scratch)
                        guard.revalidate()

        def rewrite_restore(base: Path, _: Path, __: Path) -> None:
            target = base / "README.md"
            original = target.read_bytes()
            target.write_bytes(b"transient base mutation\n")
            target.write_bytes(original)

        def head_rewrite_restore(_: Path, head: Path, __: Path) -> None:
            target = head / "README.md"
            original = target.read_bytes()
            target.write_bytes(b"transient head mutation\n")
            target.write_bytes(original)

        def chmod_restore(base: Path, _: Path, __: Path) -> None:
            target = base / "README.md"
            target.chmod(0o400)
            target.chmod(0o600)

        def symlink_create_delete(base: Path, _: Path, __: Path) -> None:
            linked = base / "transient-link"
            linked.symlink_to("README.md")
            linked.unlink()

        def new_file_create_delete(_: Path, head: Path, __: Path) -> None:
            added = head / "transient-new-file"
            added.write_bytes(b"transient\n")
            added.unlink()

        def pycache_create_delete(base: Path, _: Path, __: Path) -> None:
            cache = base / "__pycache__"
            cache.mkdir()
            bytecode = cache / "forged.cpython-312.pyc"
            bytecode.write_bytes(b"forged")
            bytecode.unlink()
            cache.rmdir()

        def root_rename_replace(base: Path, _: Path, scratch: Path) -> None:
            moved = scratch / "moved-base"
            replacement = scratch / "replacement-base"
            replacement.mkdir(mode=0o700)
            base.rename(moved)
            replacement.rename(base)
            base.rename(replacement)
            moved.rename(base)
            replacement.rmdir()

        def external_hardlink_mutation(base: Path, _: Path, scratch: Path) -> None:
            target = base / "README.md"
            original = target.read_bytes()
            external = scratch / "external-hardlink"
            os.link(target, external)
            external.write_bytes(b"transient hardlink mutation\n")
            external.write_bytes(original)
            external.unlink()

        for mutate in (
            rewrite_restore,
            head_rewrite_restore,
            chmod_restore,
            symlink_create_delete,
            new_file_create_delete,
            pycache_create_delete,
            root_rename_replace,
            external_hardlink_mutation,
        ):
            with self.subTest(mutation=mutate.__name__):
                exercise(mutate)

    def test_validation_loop_rejects_base_and_head_mutate_restore_races(self) -> None:
        for root_name, tree in (("base", self.base_tree), ("head", self.head_tree)):
            with self.subTest(root=root_name):
                with tempfile.TemporaryDirectory(
                    prefix=f"root-guard-race-{root_name}-"
                ) as raw:
                    private = Path(raw)
                    private.chmod(0o700)
                    scratch = private / "scratch"
                    scratch.mkdir(mode=0o700)
                    base = private / "base"
                    head = private / "head"
                    base_expected = verifier._extract_tree(
                        self.repository, self.base_tree, base
                    )
                    head_expected = verifier._extract_tree(
                        self.repository, self.head_tree, head
                    )
                    target_root = base if root_name == "base" else head
                    target = target_root / "README.md"
                    ready = scratch / "ready"
                    original = target.read_bytes()

                    def mutate_during_child() -> None:
                        deadline = time.monotonic() + 2
                        while not ready.exists() and time.monotonic() < deadline:
                            time.sleep(0.001)
                        if ready.exists():
                            target.write_bytes(b"transient validator race\n")
                            target.write_bytes(original)

                    worker = threading.Thread(target=mutate_during_child)
                    with self.assertRaisesRegex(
                        verifier.VerificationError,
                        "BOOTSTRAP_VALIDATION_ROOT_DRIFT",
                    ):
                        with verifier._ValidationRootGuard(
                            private,
                            ((base, base_expected), (head, head_expected)),
                        ) as guard:
                            worker.start()
                            code = (
                                "import pathlib,time;"
                                f"pathlib.Path({os.fspath(ready)!r}).write_text('ready');"
                                "time.sleep(.5)"
                            )
                            command = [
                                verifier.PYTHON_EXECUTABLE,
                                "-B",
                                "-I",
                                "-c",
                                code,
                            ]
                            verifier._run_bounded(
                                command,
                                canonical_command=self._synthetic_command(),
                                cwd=target_root,
                                environment=verifier._validation_environment(scratch),
                                pass_fds=(verifier.PYTHON_EXECUTION["fd"],),
                                python_execution=verifier.PYTHON_EXECUTION,
                                input_guard=guard.check_events,
                            )
                    worker.join(timeout=2)
                    self.assertFalse(worker.is_alive())

    def test_behavioral_routing_uses_accepted_tools_correct_roots_and_never_candidate_runner(
        self,
    ) -> None:
        for command, observation in zip(
            self.evidence["command_manifest"]["commands"],
            self.observations,
            strict=True,
        ):
            marker = command["root"]
            if command["kind"] == "SKILL_VALIDATOR":
                relative = command["argv"][-1].split("/", 1)[1]
                expected = f"ACCEPTED:{marker}:{relative}\n".encode()
                expected_dependency = verifier.EMPTY_SHA256
            else:
                expected = f"ACCEPTED-REGISTRY:{marker}\n".encode()
                dependency = next(
                    item
                    for item in self.evidence["tool_identities"]
                    if item["name"] == "executor_registry_dependency"
                )
                expected_dependency = dependency["base_sha256"]
            self.assertEqual(len(expected), int(observation["stdout_bytes"]))
            self.assertEqual(
                verifier._sha256(expected), observation["stdout_sha256"]
            )
            self.assertEqual(expected_dependency, observation["executed_dependency_sha256"])

        candidate_runner = next(
            item
            for item in self.evidence["tool_identities"]
            if item["name"] == "candidate_runner"
        )
        self.assertEqual("NOT_EXECUTED", candidate_runner["execution_source"])
        forged_sentinel = self.root / "active-forged-runner"
        forged_sentinel.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="forged-runner-") as temporary:
            head_root = Path(temporary) / "head"
            verifier._extract_tree(self.repository, self.head_tree, head_root)
            environment = verifier._validation_environment(Path(temporary))
            environment["FORGED_TOOL_SENTINEL"] = os.fspath(forged_sentinel)
            completed = subprocess.run(
                [verifier.PYTHON, os.fspath(head_root / verifier.CANDIDATE_RUNNER_PATH)],
                cwd=head_root,
                env=environment,
                check=False,
            )
            self.assertEqual(0, completed.returncode)
        self.assertEqual("FORGED\n", forged_sentinel.read_text(encoding="utf-8"))
        forged_sentinel.unlink()

        sealed = verifier._seal_accepted_tools(self.repository, self.base_tree)
        try:
            with tempfile.TemporaryDirectory(prefix="swapped-root-") as temporary:
                private = Path(temporary)
                base_root = private / "base"
                head_root = private / "head"
                verifier._extract_tree(self.repository, self.base_tree, base_root)
                verifier._extract_tree(self.repository, self.head_tree, head_root)
                command = self.evidence["command_manifest"]["commands"][0]
                actual, descriptors, bundle = verifier._sealed_command(
                    command, base_root, head_root, sealed
                )
                swapped = verifier._run_bounded(
                    actual,
                    canonical_command=command,
                    cwd=head_root,
                    environment=verifier._validation_environment(private),
                    pass_fds=descriptors,
                    sealed_bundle=bundle,
                )
                self.assertNotEqual("0", swapped["exit_code"])
        finally:
            verifier._close_sealed_tools(sealed)

        self.assertEqual(
            verifier.APPLICATION_ROUTE,
            verifier._classify_packet_route(
                {
                    "schema": "twinfinity-development-admission/v1",
                    "repository": "jayendusharma/twinfinityapp",
                }
            ),
        )

    def test_generic_issue92_v4_lineage_cannot_bypass_successor_route(self) -> None:
        path, digest, _ = self._synthetic_v4_lineage("complete-lineage")
        with patch.object(
            verifier,
            "_resolve_repository",
            side_effect=AssertionError("packet loading must not resolve a repository"),
        ), patch.object(
            verifier,
            "_validate_packet_document_shape",
            side_effect=AssertionError("generic generation-4 fallback"),
        ), self.assertRaisesRegex(
            verifier.VerificationError, "LINEAGE_INVALID"
        ):
            verifier._load_direct_packet(path, digest)

    def test_exact_current_issue92_packet_v5_routes_and_rebound_mutations_fail(
        self,
    ) -> None:
        configured = os.environ.get("TWINFINITY_HARNESS_ACTUAL_ISSUE92_PACKET")
        if configured is None:
            self.skipTest("exact current issue-92 packet was not supplied")
        packet_path = Path(configured)
        raw = packet_path.read_bytes()
        self.assertEqual(
            verifier.CONSOLIDATED_ISSUE92_PACKET_V5_SHA256,
            verifier._sha256(raw),
        )
        with patch.object(
            verifier,
            "_resolve_repository",
            side_effect=AssertionError("packet loading must not resolve a repository"),
        ), patch.object(
            verifier,
            "_execute_observations",
            side_effect=AssertionError("packet loading must not execute observations"),
        ):
            packet = verifier._load_direct_packet(
                packet_path, verifier.CONSOLIDATED_ISSUE92_PACKET_V5_SHA256
            )
        self.assertEqual(verifier.DIRECT_ROUTE, packet["route"])
        self.assertEqual(92, packet["issue_number"])
        self.assertEqual(6, len(packet["mutable_path_order"]))
        self.assertEqual(4, len(packet["incorporated_packet_sha256"]))

        document = json.loads(raw)
        topology = os.environ.get("TWINFINITY_HARNESS_REAL_TOPOLOGY_ROOT")
        if topology is not None:
            verifier._require_packet_git_scope(
                Path(topology),
                packet["base_tree"],
                packet["base_sha"],
                document["repair_starting_head"],
                packet,
            )
        mutations: list[tuple[str, dict[str, object]]] = []
        for key in document:
            value = copy.deepcopy(document)
            value.pop(key)
            mutations.append((f"missing-{key}", value))
        for name, mutate in (
            (
                "writer",
                lambda value: value.__setitem__(
                    "accountable_writer", "/root/substituted-writer"
                ),
            ),
            (
                "issue-body",
                lambda value: value.__setitem__("issue_body_sha256", "f" * 64),
            ),
            (
                "disposition",
                lambda value: value.__setitem__(
                    "current_stage", "REMOTE_PUBLICATION_READY"
                ),
            ),
            (
                "chain",
                lambda value: value["complete_packet_chain"][0].__setitem__(
                    "sha256", "f" * 64
                ),
            ),
            (
                "budget",
                lambda value: value.__setitem__(
                    "repair_budget_for_attempt_generation_3", 2
                ),
            ),
            ("unknown", lambda value: value.__setitem__("unknown", True)),
        ):
            value = copy.deepcopy(document)
            mutate(value)
            mutations.append((name, value))
        for name, value in mutations:
            with self.subTest(name=name):
                path = self._candidate_file(
                    value, f"issue92-v5-rebound-{name}.json"
                )
                with patch.object(
                    verifier,
                    "_resolve_repository",
                    side_effect=AssertionError(
                        "rebound packet must fail before repository resolution"
                    ),
                ), patch.object(
                    verifier,
                    "_execute_observations",
                    side_effect=AssertionError(
                        "rebound packet must fail before execution"
                    ),
                ), self.assertRaises(verifier.VerificationError):
                    verifier._load_direct_packet(
                        path, verifier._sha256(path.read_bytes())
                    )

    def test_post_merge_issue92_outer_candidate_bytes_cannot_become_base_evidence(
        self,
    ) -> None:
        temporary, fixture = self._post_merge_issue92_fixture(
            contaminate_outer_candidate=True
        )
        try:
            self.assertEqual(
                verifier.ISSUE92_POST_MERGE_MUTABLE_PATHS,
                fixture["accepted_base_mutable_paths"],
            )
            self.assertEqual(5, len(fixture["contaminated_outer_paths"]))
            for relative, starting_sha256, starting_git_blob in (
                verifier.ISSUE92_POST_MERGE_MUTABLE_PATHS
            ):
                if starting_sha256 == "ABSENT":
                    continue
                self.assertNotEqual(
                    starting_sha256,
                    fixture["contaminated_outer_paths"][relative],
                )
                base_blob, base_sha256, _ = verifier._blob_identity(
                    fixture["repository"], fixture["base_tree"], relative
                )
                self.assertEqual(
                    (starting_sha256, starting_git_blob),
                    (base_sha256, base_blob),
                )

            with self._post_merge_issue92_constant_patch(fixture):
                document = verifier._issue92_post_merge_expected_document(
                    {
                        "starting_main_sha": fixture["base_sha"],
                        "starting_main_tree": fixture["base_tree"],
                        "candidate_head": fixture["candidate_head"],
                        "candidate_tree": fixture["candidate_tree"],
                        "candidate_parent": fixture["base_sha"],
                    }
                )
            document_preimages = tuple(
                (
                    item["path"],
                    item["starting_sha256"],
                    item["starting_git_blob"],
                )
                for item in document["mutable_paths"]
            )
            self.assertEqual(
                verifier.ISSUE92_POST_MERGE_MUTABLE_PATHS,
                document_preimages,
            )
        finally:
            temporary.cleanup()

    def test_post_merge_issue92_successor_passes_rebased_synthetic_topology(
        self,
    ) -> None:
        temporary, fixture = self._post_merge_issue92_fixture()
        try:
            with self._post_merge_issue92_constant_patch(fixture):
                seed = {
                    "starting_main_sha": fixture["base_sha"],
                    "starting_main_tree": fixture["base_tree"],
                    "candidate_head": fixture["candidate_head"],
                    "candidate_tree": fixture["candidate_tree"],
                    "candidate_parent": fixture["base_sha"],
                }
                document = verifier._issue92_post_merge_expected_document(seed)
                document_preimages = tuple(
                    (
                        item["path"],
                        item["starting_sha256"],
                        item["starting_git_blob"],
                    )
                    for item in document["mutable_paths"]
                )
                self.assertEqual(
                    fixture["accepted_base_mutable_paths"],
                    document_preimages,
                )
                for relative, starting_sha256, starting_git_blob in (
                    document_preimages
                ):
                    if starting_sha256 == "ABSENT":
                        self.assertEqual("ABSENT", starting_git_blob)
                        self.assertEqual(
                            "",
                            _git(
                                fixture["repository"],
                                "ls-tree",
                                fixture["base_tree"],
                                "--",
                                relative,
                            ),
                        )
                    else:
                        base_blob, base_sha256, _ = verifier._blob_identity(
                            fixture["repository"],
                            fixture["base_tree"],
                            relative,
                        )
                        self.assertEqual(
                            (starting_sha256, starting_git_blob),
                            (base_sha256, base_blob),
                        )
                    head_blob, head_sha256, _ = verifier._blob_identity(
                        fixture["repository"],
                        fixture["candidate_tree"],
                        relative,
                    )
                    self.assertNotEqual(
                        (starting_sha256, starting_git_blob),
                        (head_sha256, head_blob),
                    )
                packet_path = Path(temporary.name) / "generation4-successor.json"
                packet_path.write_bytes(verifier._canonical_bytes(document))
                packet_sha256 = verifier._sha256(packet_path.read_bytes())

                loaded = verifier._load_direct_packet(
                    packet_path, packet_sha256
                )
                self.assertEqual(verifier.DIRECT_ROUTE, loaded["route"])
                self.assertEqual(92, loaded["issue_number"])
                self.assertEqual(5, len(loaded["incorporated_packet_sha256"]))
                self.assertEqual(6, len(loaded["mutable_path_order"]))
                self.assertNotIn("recorded_at", document)
                self.assertNotIn("issue_observed_at", document)

                evidence = verifier._prepare_evidence(
                    packet_path, packet_sha256
                )
                self.assertEqual(fixture["base_sha"], evidence["base"]["commit"])
                self.assertEqual(
                    fixture["candidate_head"], evidence["head"]["commit"]
                )
                accepted_verifier = next(
                    item
                    for item in evidence["tool_identities"]
                    if item["name"] == "accepted_base_verifier"
                )
                self.assertEqual(
                    verifier._sha256(Path(verifier.__file__).read_bytes()),
                    accepted_verifier["base_sha256"],
                )

                observations = verifier._execute_observations(
                    fixture["repository"],
                    fixture["base_tree"],
                    fixture["candidate_tree"],
                    evidence["command_manifest"],
                )
                candidate = {
                    "schema": (
                        "twinfinity-harness-baseline-candidate-receipt/v1"
                    ),
                    "repository": verifier.REPOSITORY,
                    "issue_number": "92",
                    "packet_sha256": packet_sha256,
                    "base": evidence["base"],
                    "head": evidence["head"],
                    "tool_identities": evidence["tool_identities"],
                    "external_tools": evidence["external_tools"],
                    "command_manifest": evidence["command_manifest"],
                    "command_manifest_sha256": evidence[
                        "command_manifest_sha256"
                    ],
                    "observations": observations,
                    "verdict": "PASS",
                    "evidence_scope": verifier.EVIDENCE_SCOPE,
                }
                candidate_path = Path(temporary.name) / "candidate.json"
                candidate_path.write_bytes(verifier._canonical_bytes(candidate))
                result = verifier.verify(
                    direct_packet=packet_path,
                    expected_packet_sha256=packet_sha256,
                    candidate_receipt=candidate_path,
                )
                self.schema_validator.validate(result)
                self.assertEqual("PASS", result["verdict"])
                self.assertEqual(24, len(result["observations"]))
        finally:
            temporary.cleanup()

    def test_post_merge_issue92_successor_complete_negative_matrix(
        self,
    ) -> None:
        temporary, fixture = self._post_merge_issue92_fixture()
        root = Path(temporary.name)
        try:
            with self._post_merge_issue92_constant_patch(fixture):
                seed = {
                    "starting_main_sha": fixture["base_sha"],
                    "starting_main_tree": fixture["base_tree"],
                    "candidate_head": fixture["candidate_head"],
                    "candidate_tree": fixture["candidate_tree"],
                    "candidate_parent": fixture["base_sha"],
                }
                valid = verifier._issue92_post_merge_expected_document(seed)

                def packet_file(value: object, name: str) -> Path:
                    path = root / f"negative-{name}.json"
                    path.write_bytes(verifier._canonical_bytes(value))
                    return path

                def reject_before_repository(name: str, value: object) -> None:
                    path = packet_file(value, name)
                    with patch.object(
                        verifier,
                        "_resolve_repository",
                        side_effect=AssertionError(
                            f"{name} reached repository resolution"
                        ),
                    ), patch.object(
                        verifier,
                        "_execute_observations",
                        side_effect=AssertionError(f"{name} executed tools"),
                    ), self.assertRaises(verifier.VerificationError):
                        verifier._load_direct_packet(
                            path, verifier._sha256(path.read_bytes())
                        )

                mutations: list[tuple[str, dict[str, object]]] = []

                def mutated(name: str, change) -> None:
                    value = copy.deepcopy(valid)
                    change(value)
                    mutations.append((name, value))

                mutated(
                    "caller-generation5",
                    lambda value: value.__setitem__("attempt_generation", 5),
                )
                mutated(
                    "chain-omission",
                    lambda value: value["complete_packet_chain"].pop(0),
                )
                mutated(
                    "chain-swap",
                    lambda value: value["complete_packet_chain"].__setitem__(
                        slice(0, 2),
                        list(reversed(value["complete_packet_chain"][:2])),
                    ),
                )
                mutated(
                    "chain-duplicate",
                    lambda value: value["complete_packet_chain"].__setitem__(
                        1, copy.deepcopy(value["complete_packet_chain"][0])
                    ),
                )
                mutated(
                    "chain-extra",
                    lambda value: value["complete_packet_chain"].append(
                        {"version": 6, "sha256": "f" * 64}
                    ),
                )
                mutated(
                    "chain-wrong-version",
                    lambda value: value["complete_packet_chain"][0].__setitem__(
                        "version", 0
                    ),
                )
                mutated(
                    "wrong-v5-predecessor",
                    lambda value: value.__setitem__(
                        "supersedes_packet_sha256", "f" * 64
                    ),
                )
                mutated(
                    "writer",
                    lambda value: value.__setitem__(
                        "accountable_writer", "/root/caller-writer"
                    ),
                )
                mutated(
                    "prior-writer",
                    lambda value: value.__setitem__(
                        "prior_writer", "/root/caller-prior-writer"
                    ),
                )
                mutated(
                    "prior-current-writer-equality",
                    lambda value: value.__setitem__(
                        "prior_writer", value["accountable_writer"]
                    ),
                )
                mutated(
                    "writer-transfer",
                    lambda value: value.__setitem__(
                        "writer_transfer", "CALLER_SELECTED_TRANSFER"
                    ),
                )
                mutated(
                    "authority",
                    lambda value: value["authority"].__setitem__(
                        "kind", "CALLER_AUTHORITY"
                    ),
                )
                mutated(
                    "human-authority",
                    lambda value: value["human_path_authority"].__setitem__(
                        "issue_body_states_direct_user_authority_effective", False
                    ),
                )
                mutated(
                    "scope-path",
                    lambda value: value["mutable_paths"][0].__setitem__(
                        "path", "substituted/path"
                    ),
                )
                mutated(
                    "scope-order",
                    lambda value: value["mutable_path_order"].reverse(),
                )
                mutated(
                    "scope-preimage",
                    lambda value: value["mutable_paths"][1].__setitem__(
                        "starting_sha256", "f" * 64
                    ),
                )
                mutated(
                    "capacity",
                    lambda value: value["direct_capacity"].__setitem__(
                        "capacity_effect", "CALLER_SELECTED_CAPACITY"
                    ),
                )
                mutated(
                    "exclusions",
                    lambda value: value["excluded_effects"].__setitem__(
                        0, "ALLOW_SQLITE"
                    ),
                )
                mutated(
                    "stage",
                    lambda value: value["authorized_stages"].append(
                        "REMOTE_PUBLICATION"
                    ),
                )
                mutated(
                    "hard-stop",
                    lambda value: value["hard_stops"].pop(),
                )
                mutated(
                    "issue-body",
                    lambda value: value.__setitem__("issue_body_sha256", "f" * 64),
                )
                mutated(
                    "branch",
                    lambda value: value.__setitem__(
                        "branch", "change/92-caller-branch"
                    ),
                )
                mutated(
                    "worktree",
                    lambda value: value.__setitem__(
                        "worktree_path", os.fspath(root / "replacement")
                    ),
                )
                mutated(
                    "retained-object",
                    lambda value: value.__setitem__("prior_retained_tree", "f" * 40),
                )
                mutated(
                    "repository",
                    lambda value: value.__setitem__("repository", "caller/repo"),
                )
                mutated(
                    "issue",
                    lambda value: value.__setitem__("owning_issue", 93),
                )
                mutated(
                    "local-main-substitution",
                    lambda value: value.__setitem__(
                        "starting_main_ref", "refs/heads/main"
                    ),
                )
                mutated(
                    "timestamp-top-level",
                    lambda value: value.__setitem__(
                        "recorded_at", "2026-08-29T00:00:00Z"
                    ),
                )
                mutated(
                    "timestamp-invalid-calendar",
                    lambda value: value.__setitem__(
                        "recorded_at", "2026-02-30T00:00:00Z"
                    ),
                )
                mutated(
                    "timestamp-offset-fraction",
                    lambda value: value.__setitem__(
                        "recorded_at", "2026-08-29T00:00:00.1+00:00"
                    ),
                )
                mutated(
                    "timestamp-nested-authority",
                    lambda value: value["authority"].__setitem__(
                        "observed_at", "2026-08-29T00:00:00Z"
                    ),
                )
                mutated(
                    "base-equals-head",
                    lambda value: (
                        value.__setitem__("starting_main_sha", value["candidate_head"]),
                        value.__setitem__("candidate_parent", value["candidate_head"]),
                    ),
                )
                for name, value in mutations:
                    with self.subTest(name=name):
                        reject_before_repository(name, value)

                missing_chain = copy.deepcopy(valid)
                missing_chain.pop("complete_packet_chain")
                missing_path = packet_file(missing_chain, "missing-chain")
                with patch.object(
                    verifier,
                    "_validate_packet_document_shape",
                    side_effect=AssertionError("generic generation-4 fallback"),
                ), patch.object(
                    verifier,
                    "_resolve_repository",
                    side_effect=AssertionError("missing chain reached repository"),
                ), self.assertRaisesRegex(
                    verifier.VerificationError, "LINEAGE_INVALID"
                ):
                    verifier._load_direct_packet(
                        missing_path,
                        verifier._sha256(missing_path.read_bytes()),
                    )

                noncanonical_path = root / "negative-noncanonical.json"
                noncanonical_path.write_text(
                    json.dumps(valid, indent=2) + "\n", encoding="utf-8"
                )
                with patch.object(
                    verifier,
                    "_resolve_repository",
                    side_effect=AssertionError("noncanonical reached repository"),
                ), self.assertRaises(verifier.VerificationError):
                    verifier._load_direct_packet(
                        noncanonical_path,
                        verifier._sha256(noncanonical_path.read_bytes()),
                    )

                def prepare_rejected(name: str, value: dict[str, object]) -> None:
                    path = packet_file(value, f"git-{name}")
                    with patch.object(
                        verifier,
                        "_execute_observations",
                        side_effect=AssertionError(f"{name} executed tools"),
                    ), self.assertRaises(verifier.VerificationError):
                        verifier._prepare_evidence(
                            path, verifier._sha256(path.read_bytes())
                        )

                fake_base = copy.deepcopy(valid)
                fake_base["starting_main_sha"] = fixture["prior_retained_head"]
                fake_base["starting_main_tree"] = fixture["prior_retained_tree"]
                fake_base["candidate_parent"] = fixture["prior_retained_head"]
                fake_base["repository_fence"]["accepted_main_sha"] = fixture[
                    "prior_retained_head"
                ]
                fake_base["repository_fence"]["accepted_main_tree"] = fixture[
                    "prior_retained_tree"
                ]
                fake_base["repository_fence"]["candidate_parent"] = fixture[
                    "prior_retained_head"
                ]
                prepare_rejected("fake-self-consistent-base", fake_base)

                false_tree = copy.deepcopy(valid)
                false_tree["starting_main_tree"] = fixture["candidate_tree"]
                false_tree["repository_fence"]["accepted_main_tree"] = fixture[
                    "candidate_tree"
                ]
                prepare_rejected("false-base-tree", false_tree)

                wrong_head = copy.deepcopy(valid)
                wrong_head["candidate_head"] = fixture["old_base"]
                wrong_head["candidate_tree"] = fixture["old_base_tree"]
                wrong_head["repository_fence"]["candidate_head"] = fixture[
                    "old_base"
                ]
                wrong_head["repository_fence"]["candidate_tree"] = fixture[
                    "old_base_tree"
                ]
                prepare_rejected("arbitrary-packet-git-object", wrong_head)

                with patch.object(
                    verifier,
                    "ISSUE92_POST_MERGE_PRIOR_RETAINED_TREE",
                    "f" * 40,
                ):
                    retained_mismatch = verifier._issue92_post_merge_expected_document(
                        seed
                    )
                    prepare_rejected(
                        "retained-object-mismatch", retained_mismatch
                    )

                repository = fixture["repository"]
                branch_ref = f"refs/heads/{verifier.ISSUE92_POST_MERGE_BRANCH}"
                old_parent_head = _git(
                    repository,
                    "commit-tree",
                    fixture["candidate_tree"],
                    "-p",
                    fixture["old_base"],
                    "-m",
                    "old parent candidate",
                )
                merge_head = _git(
                    repository,
                    "commit-tree",
                    fixture["candidate_tree"],
                    "-p",
                    fixture["base_sha"],
                    "-p",
                    fixture["old_base"],
                    "-m",
                    "merge candidate",
                )
                try:
                    for name, replacement in (
                        ("old-parent-head", old_parent_head),
                        ("merge-head", merge_head),
                    ):
                        _git(repository, "update-ref", branch_ref, replacement)
                        value = copy.deepcopy(valid)
                        value["candidate_head"] = replacement
                        value["repository_fence"]["candidate_head"] = replacement
                        with self.subTest(name=name):
                            prepare_rejected(name, value)
                finally:
                    _git(
                        repository,
                        "update-ref",
                        branch_ref,
                        fixture["candidate_head"],
                    )

                alternate_prior = _git(
                    repository,
                    "commit-tree",
                    fixture["candidate_tree"],
                    "-p",
                    fixture["base_sha"],
                    "-m",
                    "alternate retained head",
                )
                no_verifier_head = _git(
                    repository,
                    "commit-tree",
                    fixture["old_base_tree"],
                    "-p",
                    fixture["old_base"],
                    "-m",
                    "candidate without verifier",
                )
                try:
                    _git(
                        repository,
                        "update-ref",
                        "refs/remotes/origin/main",
                        fixture["old_base"],
                    )
                    _git(repository, "update-ref", branch_ref, no_verifier_head)
                    with patch.multiple(
                        verifier,
                        ISSUE92_POST_MERGE_PRIOR_RETAINED_HEAD=alternate_prior,
                        ISSUE92_POST_MERGE_PRIOR_RETAINED_TREE=fixture[
                            "candidate_tree"
                        ],
                        ISSUE92_POST_MERGE_PRIOR_RETAINED_PARENT=fixture[
                            "base_sha"
                        ],
                    ):
                        no_verifier_seed = {
                            "starting_main_sha": fixture["old_base"],
                            "starting_main_tree": fixture["old_base_tree"],
                            "candidate_head": no_verifier_head,
                            "candidate_tree": fixture["old_base_tree"],
                            "candidate_parent": fixture["old_base"],
                        }
                        no_verifier = (
                            verifier._issue92_post_merge_expected_document(
                                no_verifier_seed
                            )
                        )
                        prepare_rejected(
                            "accepted-base-lacks-verifier", no_verifier
                        )
                finally:
                    _git(
                        repository,
                        "update-ref",
                        "refs/remotes/origin/main",
                        fixture["base_sha"],
                    )
                    _git(
                        repository,
                        "update-ref",
                        branch_ref,
                        fixture["candidate_head"],
                    )
        finally:
            temporary.cleanup()

    def test_exact_current_issue98_packet_v5_binds_current_consumer(self) -> None:
        configured = os.environ.get("TWINFINITY_HARNESS_ACTUAL_ISSUE98_PACKET")
        if configured is None:
            self.skipTest("exact current issue-98 packet was not supplied")
        packet_path = Path(configured)
        document = json.loads(packet_path.read_bytes())
        expected = "a8cd6dda6bce2860e4a9865cd867ff246979d978d4b1ac2d7189fd230e1d5735"
        self.assertEqual(expected, verifier._sha256(packet_path.read_bytes()))
        with patch.object(
            verifier,
            "_resolve_repository",
            side_effect=AssertionError("packet loading must not resolve a repository"),
        ), patch.object(
            verifier,
            "_execute_observations",
            side_effect=AssertionError("packet loading must not execute observations"),
        ):
            packet = verifier._load_direct_packet(packet_path, expected)
        self.assertEqual(verifier.DIRECT_ROUTE, packet["route"])
        self.assertEqual(98, packet["issue_number"])
        self.assertEqual(4, len(packet["incorporated_packet_sha256"]))
        self.assertEqual(
            "1b8b614f630e1c6204cb8a3cae4798bab32dab475aa5fd6fce817b71ebde21ed",
            packet["governor_rejection_receipt_sha256"],
        )

        receipt_source = Path(document["governor_rejection"]["receipt_path"])
        manifest_source = Path(
            document["adopted_committed_state"]["validation_manifest_path"]
        )

        def rebound_rejected(
            name: str,
            *,
            mutate_packet: object | None = None,
            mutate_receipt: object | None = None,
            mutate_manifest: object | None = None,
        ) -> None:
            rebound = copy.deepcopy(document)
            receipt = json.loads(receipt_source.read_bytes())
            manifest = json.loads(manifest_source.read_bytes())
            if callable(mutate_manifest):
                mutate_manifest(manifest)
                manifest_path = self._candidate_file(
                    manifest, f"issue98-v5-{name}-manifest.json"
                )
                manifest_raw = manifest_path.read_bytes()
                manifest_sha = verifier._sha256(manifest_raw)
                rebound["adopted_committed_state"][
                    "validation_manifest_path"
                ] = os.fspath(manifest_path)
                rebound["adopted_committed_state"][
                    "validation_manifest_sha256"
                ] = manifest_sha
                receipt["validation_manifest_sha256"] = manifest_sha
                receipt["validation_manifest_bytes"] = len(manifest_raw)
            if callable(mutate_receipt):
                mutate_receipt(receipt)
            if callable(mutate_manifest) or callable(mutate_receipt):
                receipt_path = self._candidate_file(
                    receipt, f"issue98-v5-{name}-rejection.json"
                )
                rebound["governor_rejection"]["receipt_path"] = os.fspath(
                    receipt_path
                )
                rebound["governor_rejection"]["receipt_sha256"] = (
                    verifier._sha256(receipt_path.read_bytes())
                )
            if callable(mutate_packet):
                mutate_packet(rebound)
            rebound_path = self._candidate_file(
                rebound, f"issue98-v5-{name}-packet.json"
            )
            with patch.object(
                verifier,
                "_resolve_repository",
                side_effect=AssertionError(
                    "rebound packet must fail before repository resolution"
                ),
            ), patch.object(
                verifier,
                "_execute_observations",
                side_effect=AssertionError("rebound packet must not execute"),
            ), self.assertRaises(verifier.VerificationError):
                verifier._load_direct_packet(
                    rebound_path, verifier._sha256(rebound_path.read_bytes())
                )

        mutations = (
            (
                "receipt-contract",
                {
                    "mutate_receipt": lambda value: value.__setitem__(
                        "starting_main_contract_sha256", "f" * 64
                    )
                },
            ),
            (
                "receipt-manifest-bytes",
                {
                    "mutate_receipt": lambda value: value.__setitem__(
                        "validation_manifest_bytes",
                        value["validation_manifest_bytes"] + 1,
                    )
                },
            ),
            (
                "receipt-next-action",
                {
                    "mutate_receipt": lambda value: value.__setitem__(
                        "planner_next_action", "ALLOW_REMOTE_PUBLICATION"
                    )
                },
            ),
            (
                "manifest-gate-argv",
                {
                    "mutate_manifest": lambda value: value["validations"][
                        0
                    ].__setitem__("argv", ["/bin/true"])
                },
            ),
            (
                "manifest-gate-unknown-field",
                {
                    "mutate_manifest": lambda value: value["validations"][
                        0
                    ].__setitem__("unknown", True)
                },
            ),
            (
                "manifest-source-labels",
                {
                    "mutate_manifest": lambda value: value[
                        "validation_tool_provenance"
                    ]["final_source_sha256"].update(
                        {
                            "schema": value["validation_tool_provenance"][
                                "final_source_sha256"
                            ]["tests"],
                            "tests": value["validation_tool_provenance"][
                                "final_source_sha256"
                            ]["schema"],
                        }
                    )
                },
            ),
            (
                "manifest-audit-identity",
                {
                    "mutate_manifest": lambda value: value[
                        "independent_exact_hash_audits"
                    ][0].__setitem__("audit", "substituted-audit")
                },
            ),
            (
                "excluded-effect-removed",
                {
                    "mutate_packet": lambda value: value.__setitem__(
                        "excluded_effects", value["excluded_effects"][1:]
                    )
                },
            ),
            (
                "excluded-effect-authorizing",
                {
                    "mutate_packet": lambda value: value[
                        "excluded_effects"
                    ].__setitem__(0, "ALLOW_REMOTE_PUBLICATION")
                },
            ),
            (
                "excluded-effect-duplicate",
                {
                    "mutate_packet": lambda value: value[
                        "excluded_effects"
                    ].__setitem__(1, value["excluded_effects"][0])
                },
            ),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                rebound_rejected(name, **mutation)

    def test_incomplete_or_substituted_packet_envelope_fails_before_execution(
        self,
    ) -> None:
        _, _, complete = self._synthetic_v4_lineage("invalid-envelope-source")
        variants: list[tuple[str, dict[str, object]]] = []
        for key in (
            "issue_updated_at",
            "writer_transfer",
            "repair_starting_head",
            "governor_rejection",
            "changed_diagnosis",
        ):
            value = copy.deepcopy(complete)
            value.pop(key)
            variants.append((f"missing-{key}", value))

        mutations = {
            "route-schema": ("schema", "twinfinity-development-admission/v1"),
            "route-repository": ("repository", "jayendusharma/twinfinityapp"),
            "authorized-remote": ("authorized_stages", ["REMOTE_PUBLICATION"]),
            "weak-hard-stop": (
                "hard_stops",
                [
                    "ANY_ALLOW_PATH_SQLITE_REMOTE_PUBLICATION_INSTALLATION_"
                    "RUNTIME_APPLICATION_SELF_APPROVAL"
                ],
            ),
            "unknown-runtime-authority": ("runtime_authorized", True),
            "unknown-sqlite-authority": ("sqlite_authority", True),
        }
        for name, (key, replacement) in mutations.items():
            value = copy.deepcopy(complete)
            value[key] = replacement
            variants.append((name, value))

        nested_mutations = []
        value = copy.deepcopy(complete)
        value["repository_fence"]["observed_at"] = None
        nested_mutations.append(("fence-observation", value))
        value = copy.deepcopy(complete)
        value["repository_fence"]["local_branch_exact"] = False
        nested_mutations.append(("fence-local-branch", value))
        value = copy.deepcopy(complete)
        value["authority"]["kind"] = "INDIRECT_OWNER_INSTRUCTION"
        nested_mutations.append(("authority", value))
        value = copy.deepcopy(complete)
        value["authority"]["runtime_authorized"] = True
        nested_mutations.append(("authority-unknown-field", value))
        value = copy.deepcopy(complete)
        value["direct_capacity"]["sqlite_allocation_units"] = 1
        nested_mutations.append(("capacity", value))
        value = copy.deepcopy(complete)
        value["direct_capacity"]["sqlite_mutation_authorized"] = True
        nested_mutations.append(("capacity-unknown-field", value))
        value = copy.deepcopy(complete)
        value["dependencies"] = {"unmet_dependencies": []}
        nested_mutations.append(("dependency", value))
        value = copy.deepcopy(complete)
        value["collision_fence"]["path_collision"] = True
        nested_mutations.append(("collision", value))
        value = copy.deepcopy(complete)
        value["collision_fence"]["runtime_collision_ignored"] = True
        nested_mutations.append(("collision-unknown-field", value))
        value = copy.deepcopy(complete)
        value["repository_fence"]["remote_mutation_authorized"] = True
        nested_mutations.append(("fence-unknown-field", value))
        value = copy.deepcopy(complete)
        value["bootstrap_validation_contract"]["self_approval"] = "ALLOWED"
        nested_mutations.append(("validation-unknown-field", value))
        value = copy.deepcopy(complete)
        value["governor_rejection"]["attempt_identity"] = "substituted"
        nested_mutations.append(("governor-attempt", value))
        value = copy.deepcopy(complete)
        value["governor_rejection"]["report_sha256"] = "c" * 64
        nested_mutations.append(("governor-report", value))
        value = copy.deepcopy(complete)
        value["governor_rejection"]["github_comment_url"] = (
            "https://github.com/jayendusharma/twinfinity-harness/"
            "issues/92#issuecomment-2"
        )
        nested_mutations.append(("governor-comment-binding", value))
        value = copy.deepcopy(complete)
        value["changed_diagnosis"][0].pop("required_behavior")
        nested_mutations.append(("diagnosis", value))
        value = copy.deepcopy(complete)
        value["repair_starting_head"] = self.base_sha
        nested_mutations.append(("repair-head", value))
        value = copy.deepcopy(complete)
        value["writer_transfer"] = None
        nested_mutations.append(("writer-transfer-type", value))
        value = copy.deepcopy(complete)
        value["prior_writer"] = 7
        nested_mutations.append(("prior-writer-type", value))
        value = copy.deepcopy(complete)
        value["prior_writer"] = "/root/substituted-prior-writer"
        nested_mutations.append(("prior-writer-chain", value))
        value = copy.deepcopy(complete)
        value["fresh_planner_disposition_reason"] = False
        nested_mutations.append(("disposition-type", value))
        value = copy.deepcopy(complete)
        value["repair_starting_head"] = "not-a-sha"
        nested_mutations.append(("repair-head-form", value))
        value = copy.deepcopy(complete)
        value["incorporation"] = True
        nested_mutations.append(("incorporation-type", value))
        value = copy.deepcopy(complete)
        value["writer_transfer"] = "WRONG_TRANSFER"
        nested_mutations.append(("writer-transfer-value", value))
        value = copy.deepcopy(complete)
        value["prior_writer_terminal_state"] = (
            "WRITER_STILL_ACTIVE_REMOTE_EFFECT_UNKNOWN"
        )
        nested_mutations.append(("prior-terminal-value", value))
        value = copy.deepcopy(complete)
        value["fresh_planner_disposition_reason"] = (
            "CHANGED_SCOPE_WITHOUT_AUTHORITY"
        )
        nested_mutations.append(("disposition-value", value))
        value = copy.deepcopy(complete)
        value["incorporation"] = (
            "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_AND_RUNTIME_IS_NOW_AUTHORIZED"
        )
        nested_mutations.append(("incorporation-value", value))
        value = copy.deepcopy(complete)
        value["direct_capacity"]["temporary_limit"] = 64
        nested_mutations.append(("capacity-limit", value))
        value = copy.deepcopy(complete)
        value["direct_capacity"]["occupancy_components"] = []
        nested_mutations.append(("capacity-components", value))
        value = copy.deepcopy(complete)
        value["dependencies"]["predecessor_merge_result_main"] = "f" * 40
        nested_mutations.append(("dependency-main-binding", value))
        value = copy.deepcopy(complete)
        value["bootstrap_validation_contract"]["future_issue_92_use"] = (
            "BEFORE_THE_VERIFIER_BYTES_ARE_ACCEPTED"
        )
        nested_mutations.append(("future-use-timing", value))
        value = copy.deepcopy(complete)
        value["authorized_stages"].append("REMOTE_PUBLICATION")
        nested_mutations.append(("remote-publication-stage", value))
        value = copy.deepcopy(complete)
        value["collision_fence"]["issue_92_state"] = 7
        nested_mutations.append(("collision-state-type", value))
        value = copy.deepcopy(complete)
        value["collision_fence"]["issue_92_mutable_paths_sha256"] = "bad"
        nested_mutations.append(("collision-digest", value))
        variants.extend(nested_mutations)

        for name, value in variants:
            with self.subTest(name=name):
                path = self._candidate_file(value, f"invalid-envelope-{name}.json")
                with patch.object(
                    verifier,
                    "_resolve_repository",
                    side_effect=AssertionError("must fail before repository resolution"),
                ), patch.object(
                    verifier,
                    "_execute_observations",
                    side_effect=AssertionError("must fail before execution"),
                ):
                    with self.assertRaises(verifier.VerificationError):
                        verifier._load_direct_packet(
                            path, verifier._sha256(path.read_bytes())
                        )

        incomplete_v1 = copy.deepcopy(self.packet)
        incomplete_v1.pop("bootstrap_validation_contract")
        path = self._candidate_file(incomplete_v1, "incomplete-v1.json")
        with self.assertRaisesRegex(verifier.VerificationError, "PACKET_SCHEMA"):
            verifier._load_direct_packet(path, verifier._sha256(path.read_bytes()))

        for name, key, replacement in (
            ("bool-generation", "attempt_generation", True),
            ("bool-capacity", "direct_capacity", None),
        ):
            value = copy.deepcopy(self.packet)
            if key == "direct_capacity":
                value[key]["units"] = True
            else:
                value[key] = replacement
            path = self._candidate_file(value, f"invalid-{name}.json")
            with self.subTest(name=name), self.assertRaises(
                verifier.VerificationError
            ):
                verifier._load_direct_packet(
                    path, verifier._sha256(path.read_bytes())
                )

        wrong_predecessor = copy.deepcopy(self.packet)
        wrong_predecessor["dependencies"]["predecessor_issue"] = 97
        path = self._candidate_file(
            wrong_predecessor, "invalid-issue92-predecessor.json"
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID",
        ):
            verifier._load_direct_packet(path, verifier._sha256(path.read_bytes()))

    def test_packet_git_scope_accepts_exact_path_set_in_git_tree_order(self) -> None:
        reordered = copy.deepcopy(self.packet)
        reordered["mutable_path_order"] = list(
            reversed(reordered["mutable_path_order"])
        )
        indexed = {item["path"]: item for item in reordered["mutable_paths"]}
        reordered["mutable_paths"] = [
            indexed[path] for path in reordered["mutable_path_order"]
        ]
        reordered["mutable_paths_sha256"] = verifier._sha256(
            json.dumps(
                reordered["mutable_path_order"], separators=(",", ":")
            ).encode()
        )
        verifier._require_packet_git_scope(
            self.repository,
            self.base_tree,
            self.base_sha,
            self.head_sha,
            reordered,
        )

        variants: list[tuple[str, list[str]]] = []
        variants.append(("missing", reordered["mutable_path_order"][:-1]))
        substituted = list(reordered["mutable_path_order"])
        substituted[-1] = "substituted-path"
        variants.append(("substituted", substituted))
        duplicate = list(reordered["mutable_path_order"])
        duplicate[-1] = duplicate[0]
        variants.append(("duplicate", duplicate))
        for name, expected_paths in variants:
            packet = copy.deepcopy(reordered)
            packet["mutable_path_order"] = expected_paths
            with self.subTest(name=name), self.assertRaisesRegex(
                verifier.VerificationError, "CHANGED_PATH_SET_MISMATCH"
            ):
                verifier._require_packet_git_scope(
                    self.repository,
                    self.base_tree,
                    self.base_sha,
                    self.head_sha,
                    packet,
                )

    def test_packet_git_scope_tree_preimages_and_single_parent_are_enforced(
        self,
    ) -> None:
        missing_path = copy.deepcopy(self.packet)
        missing_path["mutable_paths"].pop()
        missing_path["mutable_path_order"].pop()
        missing_path["mutable_paths_sha256"] = verifier._sha256(
            json.dumps(
                missing_path["mutable_path_order"], separators=(",", ":")
            ).encode()
        )
        missing_path_file = self._candidate_file(
            missing_path, "packet-missing-real-change.json"
        )
        with patch.object(
            verifier,
            "_execute_observations",
            side_effect=AssertionError("must fail before execution"),
        ):
            with self.assertRaisesRegex(
                verifier.VerificationError, "CHANGED_PATH_SET_MISMATCH"
            ):
                verifier._prepare_evidence(
                    missing_path_file,
                    verifier._sha256(missing_path_file.read_bytes()),
                )

        rebound = copy.deepcopy(self.packet)
        rebound["mutable_paths"][0]["starting_sha256"] = "f" * 64
        rebound_file = self._candidate_file(rebound, "packet-rebound-preimage.json")
        with self.assertRaisesRegex(
            verifier.VerificationError, "MUTABLE_PATH_PREIMAGE_MISMATCH"
        ):
            verifier._prepare_evidence(
                rebound_file, verifier._sha256(rebound_file.read_bytes())
            )

        false_tree = copy.deepcopy(self.packet)
        false_tree["starting_main_tree"] = self.head_tree
        false_tree_file = self._candidate_file(false_tree, "packet-false-base-tree.json")
        with self.assertRaisesRegex(
            verifier.VerificationError, "BASE_TREE_PACKET_MISMATCH"
        ):
            verifier._prepare_evidence(
                false_tree_file, verifier._sha256(false_tree_file.read_bytes())
            )

        merge_contents = (
            f"tree {self.head_tree}\n"
            f"parent {self.base_sha}\n"
            f"parent {self.base_sha}\n"
            "author Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
            "committer Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
            "\nsynthetic duplicate-parent merge\n"
        ).encode("ascii")
        completed = subprocess.run(
            [
                verifier.GIT,
                "-C",
                os.fspath(self.repository),
                "hash-object",
                "--literally",
                "-w",
                "-t",
                "commit",
                "--stdin",
            ],
            input=merge_contents,
            capture_output=True,
            env=verifier._git_environment(),
            check=True,
        )
        merge_head = completed.stdout.decode("ascii").strip()
        branch_ref = f"refs/heads/{self.branch}"
        _git(self.repository, "update-ref", branch_ref, merge_head)
        try:
            with self.assertRaisesRegex(
                verifier.VerificationError, "HEAD_PARENT_SET_INVALID"
            ):
                verifier._prepare_evidence(self.packet_path, self.packet_sha256)
        finally:
            _git(self.repository, "update-ref", branch_ref, self.head_sha)

    def test_v4_rejects_authorizing_or_dirty_bound_artifacts(self) -> None:
        _, _, source = self._synthetic_v4_lineage("artifact-substitution")
        source_receipt = Path(source["governor_rejection"]["receipt_path"])
        source_manifest = Path(
            source["adopted_committed_state"]["validation_manifest_path"]
        )

        authorizing = copy.deepcopy(source)
        receipt = json.loads(source_receipt.read_text(encoding="utf-8"))
        receipt["publication_authorized"] = True
        receipt["repair_authorized"] = True
        receipt["installation_or_runtime_authorized"] = True
        receipt_path = self._candidate_file(
            receipt, "authorizing-rejection-receipt.json"
        )
        authorizing["governor_rejection"]["receipt_path"] = os.fspath(
            receipt_path
        )
        authorizing["governor_rejection"]["receipt_sha256"] = verifier._sha256(
            receipt_path.read_bytes()
        )

        dirty = copy.deepcopy(source)
        manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
        manifest["cleanliness"] = {"ignored_paths": 1}
        manifest_path = self._candidate_file(manifest, "dirty-v3-manifest.json")
        manifest_sha = verifier._sha256(manifest_path.read_bytes())
        dirty_receipt = json.loads(source_receipt.read_text(encoding="utf-8"))
        dirty_receipt["validation_manifest_sha256"] = manifest_sha
        dirty_receipt_path = self._candidate_file(
            dirty_receipt, "dirty-v3-rejection-receipt.json"
        )
        dirty["adopted_committed_state"]["validation_manifest_path"] = os.fspath(
            manifest_path
        )
        dirty["adopted_committed_state"]["validation_manifest_sha256"] = manifest_sha
        dirty["governor_rejection"]["receipt_path"] = os.fspath(
            dirty_receipt_path
        )
        dirty["governor_rejection"]["receipt_sha256"] = verifier._sha256(
            dirty_receipt_path.read_bytes()
        )

        bool_count = copy.deepcopy(source)
        bool_count["adopted_committed_state"]["ignored_paths"] = False

        minimal_pair = copy.deepcopy(source)
        full_manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
        minimal_manifest = {
            "repository": full_manifest["repository"],
            "owning_issue": full_manifest["owning_issue"],
            "base": {
                "commit": full_manifest["base"]["commit"],
                "tree": full_manifest["base"]["tree"],
            },
            "head": {
                "commit": full_manifest["head"]["commit"],
                "tree": full_manifest["head"]["tree"],
            },
            "canonical_diff": {
                "sha256": full_manifest["canonical_diff"]["sha256"],
                "bytes": full_manifest["canonical_diff"]["bytes"],
            },
            "direct_packet": {
                "sha256": full_manifest["direct_packet"]["sha256"]
            },
            "changed_paths": [
                {
                    key: item[key]
                    for key in ("path", "sha256", "git_blob", "bytes", "git_mode")
                }
                for item in full_manifest["changed_paths"]
            ],
        }
        minimal_manifest_path = self._candidate_file(
            minimal_manifest, "minimal-v3-manifest.json"
        )
        minimal_manifest_sha = verifier._sha256(minimal_manifest_path.read_bytes())
        full_receipt = json.loads(source_receipt.read_text(encoding="utf-8"))
        minimal_receipt = {
            key: full_receipt[key]
            for key in (
                "repository",
                "owning_issue",
                "issue_body_sha256",
                "base_sha",
                "base_tree",
                "head_sha",
                "head_tree",
                "canonical_diff_sha256",
                "canonical_diff_bytes",
                "packet_sha256",
                "governor_attempt_identity",
                "governor_report_sha256",
                "terminal_verb",
                "publication_authorized",
            )
        }
        minimal_receipt["validation_manifest_sha256"] = minimal_manifest_sha
        minimal_receipt["findings"] = [
            {"code": item["code"]} for item in full_receipt["findings"]
        ]
        minimal_receipt_path = self._candidate_file(
            minimal_receipt, "minimal-v3-rejection-receipt.json"
        )
        minimal_pair["adopted_committed_state"]["validation_manifest_path"] = (
            os.fspath(minimal_manifest_path)
        )
        minimal_pair["adopted_committed_state"]["validation_manifest_sha256"] = (
            minimal_manifest_sha
        )
        minimal_pair["governor_rejection"]["receipt_path"] = os.fspath(
            minimal_receipt_path
        )
        minimal_pair["governor_rejection"]["receipt_sha256"] = verifier._sha256(
            minimal_receipt_path.read_bytes()
        )
        for name, packet in (
            ("authorizing-rejection", authorizing),
            ("dirty-manifest", dirty),
            ("boolean-ignored-count", bool_count),
            ("minimal-receipt-manifest-pair", minimal_pair),
        ):
            with self.subTest(name=name):
                path = self._candidate_file(packet, f"{name}-packet.json")
                with patch.object(
                    verifier,
                    "_resolve_repository",
                    side_effect=AssertionError("must fail before repository resolution"),
                ), self.assertRaises(verifier.VerificationError):
                    verifier._load_direct_packet(
                        path, verifier._sha256(path.read_bytes())
                    )

    def test_real_issue92_remote_tracking_topology_passes_without_local_main(
        self,
    ) -> None:
        configured = os.environ.get("TWINFINITY_HARNESS_REAL_TOPOLOGY_ROOT")
        root = Path(configured) if configured else self.repository
        resolved = verifier._resolve_repository(root)
        before = _git(resolved, "for-each-ref", "--format=%(refname) %(objectname)")
        remote_main = _git(
            resolved, "show-ref", "--verify", "--hash", "refs/remotes/origin/main"
        )
        branch_ref = _git(resolved, "symbolic-ref", "--quiet", "HEAD")
        self.assertTrue(branch_ref.startswith("refs/heads/change/"))
        branch = branch_ref.removeprefix("refs/heads/")
        head = _git(resolved, "show-ref", "--verify", "--hash", branch_ref)
        local_main = subprocess.run(
            [
                verifier.GIT,
                "-C",
                os.fspath(resolved),
                "show-ref",
                "--verify",
                "--hash",
                "refs/heads/main",
            ],
            capture_output=True,
            env=verifier._git_environment(),
            check=False,
        )
        self.assertNotEqual(0, local_main.returncode)
        verifier._require_frozen_refs(resolved, remote_main, head, branch)
        self.assertEqual(
            before,
            _git(resolved, "for-each-ref", "--format=%(refname) %(objectname)"),
        )

    def test_real_malformed_commit_objects_fail_before_ancestry(self) -> None:
        def write_commit(contents: bytes) -> str:
            completed = subprocess.run(
                [
                    verifier.GIT,
                    "-C",
                    os.fspath(self.repository),
                    "hash-object",
                    "--literally",
                    "-w",
                    "-t",
                    "commit",
                    "--stdin",
                ],
                input=contents,
                capture_output=True,
                env=verifier._git_environment(),
                check=True,
            )
            return completed.stdout.decode("ascii").strip()

        prefix = (
            f"tree {self.head_tree}\n"
            f"parent {self.base_sha}\n"
            "author Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
            "committer Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
        )
        malformed = (
            (prefix + "unknown forbidden\n\nmessage\n", "COMMIT_INVALID"),
            (
                f"tree {self.head_tree}\n"
                "author Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
                f"parent {self.base_sha}\n"
                "committer Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
                "\nmessage\n",
                "PARENT_INVALID",
            ),
        )
        branch_ref = f"refs/heads/{self.branch}"
        try:
            for index, (contents, error) in enumerate(malformed):
                with self.subTest(index=index, error=error):
                    object_id = write_commit(contents.encode("ascii"))
                    _git(self.repository, "update-ref", branch_ref, object_id)
                    with patch.object(
                        verifier,
                        "_require_proper_ancestry",
                        side_effect=AssertionError("must reject before ancestry"),
                    ):
                        with self.assertRaisesRegex(
                            verifier.VerificationError, error
                        ):
                            verifier._prepare_evidence(
                                self.packet_path, self.packet_sha256
                            )
        finally:
            _git(self.repository, "update-ref", branch_ref, self.head_sha)

    def test_schema_and_verifier_reject_exact_form_mutations(self) -> None:
        result = self._verify()
        schema_mutations: list[tuple[str, dict[str, object]]] = []
        for name, mutate in (
            (
                "issue-float-string",
                lambda value: value.__setitem__("issue_number", "92.0"),
            ),
            (
                "issue-newline",
                lambda value: value.__setitem__("issue_number", "92\n"),
            ),
            (
                "digest-newline",
                lambda value: value.__setitem__(
                    "packet_sha256", value["packet_sha256"] + "\n"
                ),
            ),
            (
                "digest-short",
                lambda value: value.__setitem__("packet_sha256", "a" * 63),
            ),
            (
                "digest-uppercase",
                lambda value: value.__setitem__("packet_sha256", "A" * 64),
            ),
            (
                "external-leading-zero",
                lambda value: value["external_tools"][0].__setitem__("size", "01"),
            ),
            (
                "external-newline",
                lambda value: value["external_tools"][0].__setitem__(
                    "size", value["external_tools"][0]["size"] + "\n"
                ),
            ),
            (
                "external-float",
                lambda value: value["external_tools"][0].__setitem__("size", 1.0),
            ),
            (
                "count-leading-zero",
                lambda value: value["observations"][0].__setitem__(
                    "stdout_bytes", "00"
                ),
            ),
            (
                "count-newline",
                lambda value: value["observations"][0].__setitem__(
                    "stdout_bytes", value["observations"][0]["stdout_bytes"] + "\n"
                ),
            ),
            (
                "count-overflow",
                lambda value: value["observations"][0].__setitem__(
                    "stdout_bytes", "1048577"
                ),
            ),
            (
                "timeout-float",
                lambda value: value["observations"][0].__setitem__(
                    "timeout_seconds", 60.0
                ),
            ),
            (
                "exit-integer",
                lambda value: value["observations"][0].__setitem__("exit_code", 0),
            ),
        ):
            mutated = copy.deepcopy(result)
            mutate(mutated)
            schema_mutations.append((name, mutated))
        for name, mutated in schema_mutations:
            with self.subTest(schema=name):
                self.assertFalse(self.schema_validator.is_valid(mutated))

        candidate_mutations = []
        value = copy.deepcopy(self.candidate)
        value["packet_sha256"] += "\n"
        candidate_mutations.append(("packet-digest-newline", value))
        value = copy.deepcopy(self.candidate)
        value["observations"][0]["stdout_sha256"] += "\n"
        candidate_mutations.append(("observation-digest-newline", value))
        value = copy.deepcopy(self.candidate)
        value["observations"][0]["stdout_bytes"] = "00"
        candidate_mutations.append(("count-leading-zero", value))
        value = copy.deepcopy(self.candidate)
        value["external_tools"][0]["size"] = 1.0
        candidate_mutations.append(("external-float", value))
        value = copy.deepcopy(self.candidate)
        value["command_manifest"]["commands"][0]["timeout_seconds"] = 60.0
        value["command_manifest_sha256"] = verifier._sha256(
            verifier._canonical_bytes(value["command_manifest"])
        )
        candidate_mutations.append(("timeout-float", value))
        for name, mutated in candidate_mutations:
            with self.subTest(verifier=name), patch.object(
                verifier,
                "_execute_observations",
                side_effect=AssertionError("must fail before execution"),
            ):
                with self.assertRaises(verifier.VerificationError):
                    self._verify(
                        self._candidate_file(mutated, f"exact-form-{name}.json")
                    )

    def test_recycled_pid_process_group_fixture_is_not_signaled(self) -> None:
        class FakeProcess:
            pid = 424242
            returncode = None

        with patch.object(
            verifier, "_proc_stat", return_value=(1, FakeProcess.pid, 999)
        ), patch.object(verifier.os, "killpg") as killpg:
            verifier._signal_process_group(FakeProcess(), 111, signal.SIGKILL)
        killpg.assert_not_called()

        with patch.object(verifier, "_pidfd_alive", return_value=True), patch.object(
            verifier.signal, "pidfd_send_signal"
        ) as pidfd_signal, patch.object(
            verifier, "_same_process", return_value=False
        ):
            verifier._signal_known({424242: (111, 77)}, signal.SIGTERM)
        pidfd_signal.assert_called_once_with(77, signal.SIGTERM)

    def test_recycled_root_pid_descendant_is_neither_captured_nor_signaled(
        self,
    ) -> None:
        def snapshot_processes(
            snapshot: dict[int, tuple[int, int]] | None = None,
        ) -> dict[int, list[int]]:
            if snapshot is not None:
                snapshot.update({100: (1, 111), 200: (100, 222)})
            return {100: [200]}

        for name, root_identity in (
            ("recycled-before-snapshot", [False]),
            ("recycled-during-snapshot", [True, False]),
        ):
            with self.subTest(name=name):
                known = {100: (111, 10)}
                with patch.object(
                    verifier, "_same_process", side_effect=root_identity
                ) as same_process, patch.object(
                    verifier, "_children_map", side_effect=snapshot_processes
                ), patch.object(
                    verifier, "_capture_pidfd", return_value=20
                ) as capture, patch.object(
                    verifier, "_pidfd_alive", return_value=False
                ), patch.object(
                    verifier.signal, "pidfd_send_signal"
                ) as pidfd_signal:
                    verifier._remember_processes(100, 111, {}, known)
                    verifier._signal_known(known, signal.SIGTERM)
                self.assertEqual({100: (111, 10)}, known)
                self.assertEqual(len(root_identity), same_process.call_count)
                capture.assert_not_called()
                pidfd_signal.assert_not_called()

        known = {100: (111, 10)}
        with patch.object(
            verifier, "_same_process", side_effect=[True, True, True]
        ), patch.object(
            verifier, "_children_map", side_effect=snapshot_processes
        ), patch.object(
            verifier.os, "pidfd_open", return_value=20
        ) as pidfd_open, patch.object(
            verifier, "_proc_stat", return_value=(100, 200, 999)
        ), patch.object(verifier.os, "close") as close, patch.object(
            verifier, "_pidfd_alive", return_value=False
        ), patch.object(
            verifier.signal, "pidfd_send_signal"
        ) as pidfd_signal:
            verifier._remember_processes(100, 111, {}, known)
            verifier._signal_known(known, signal.SIGTERM)
        self.assertEqual({100: (111, 10)}, known)
        pidfd_open.assert_called_once_with(200, 0)
        close.assert_called_once_with(20)
        pidfd_signal.assert_not_called()

        known = {}
        with patch.object(
            verifier, "_same_process", side_effect=[True, True, False]
        ), patch.object(
            verifier, "_children_map", side_effect=snapshot_processes
        ), patch.object(
            verifier.os, "pidfd_open", return_value=20
        ) as pidfd_open, patch.object(
            verifier, "_proc_stat", return_value=(1, 100, 999)
        ), patch.object(verifier.os, "close") as close:
            verifier._remember_processes(100, 111, {}, known)
        self.assertEqual({}, known)
        pidfd_open.assert_called_once_with(100, 0)
        close.assert_called_once_with(20)

        def adopted_snapshot(
            snapshot: dict[int, tuple[int, int]] | None = None,
        ) -> dict[int, list[int]]:
            if snapshot is not None:
                snapshot[200] = (os.getpid(), 999)
            return {os.getpid(): [200]}

        known = {200: (222, 20)}
        with patch.object(
            verifier, "_same_process", return_value=False
        ), patch.object(
            verifier, "_children_map", side_effect=adopted_snapshot
        ), patch.object(
            verifier, "_pidfd_alive", side_effect=[False, True]
        ), patch.object(
            verifier, "_capture_pidfd", return_value=30
        ) as capture, patch.object(
            verifier.os, "close"
        ) as close, patch.object(
            verifier.signal, "pidfd_send_signal"
        ) as pidfd_signal:
            verifier._remember_processes(100, 111, {}, known)
            verifier._signal_known(known, signal.SIGTERM)
        self.assertEqual({200: (999, 30)}, known)
        close.assert_called_once_with(20)
        capture.assert_called_once_with(200, 999)
        pidfd_signal.assert_called_once_with(30, signal.SIGTERM)

        with patch.object(verifier.os, "waitpid") as waitpid:
            verifier._reap_adopted(100, 111, {100: (999, 30)})
        waitpid.assert_called_once_with(100, os.WNOHANG)

    def test_post_link_parent_rebind_rolls_back_every_receipt_link(self) -> None:
        parent = self.root / "post-link-parent"
        parent.mkdir(mode=0o700)
        moved = self.root / "post-link-parent-moved"
        target = parent / "receipt.json"
        contents = verifier._canonical_bytes({"post-link": True})
        callbacks = 0

        def rebind_on_post_link_guard() -> None:
            nonlocal callbacks
            callbacks += 1
            if callbacks == 3:
                parent.rename(moved)
                parent.mkdir(mode=0o700)

        with self.assertRaisesRegex(verifier.VerificationError, "PARENT_UNSAFE"):
            verifier._write_atomic_receipt(
                target, contents, publication_guard=rebind_on_post_link_guard
            )
        self.assertGreaterEqual(callbacks, 3)
        self.assertFalse((parent / "receipt.json").exists())
        self.assertFalse((moved / "receipt.json").exists())
        self.assertEqual([], list(parent.glob(".receipt.json.tmp.*")))
        self.assertEqual([], list(moved.glob(".receipt.json.tmp.*")))

        late_parent = self.root / "late-read-parent"
        late_parent.mkdir(mode=0o700)
        late_moved = self.root / "late-read-parent-moved"
        late_target = late_parent / "receipt.json"
        real_read = verifier._read_receipt_at

        def rename_after_final_read(
            directory_fd: int,
            name: str,
            *,
            allowed_links: set[int],
        ) -> tuple[bytes, os.stat_result]:
            result = real_read(
                directory_fd, name, allowed_links=allowed_links
            )
            if allowed_links == {1} and late_parent.exists():
                late_parent.rename(late_moved)
                late_parent.mkdir(mode=0o700)
            return result

        with patch.object(
            verifier, "_read_receipt_at", side_effect=rename_after_final_read
        ):
            with self.assertRaisesRegex(verifier.VerificationError, "PARENT_UNSAFE"):
                verifier._write_atomic_receipt(late_target, contents)
        self.assertFalse((late_parent / "receipt.json").exists())
        self.assertFalse((late_moved / "receipt.json").exists())
        self.assertEqual([], list(late_parent.glob(".receipt.json.tmp.*")))
        self.assertEqual([], list(late_moved.glob(".receipt.json.tmp.*")))

    def test_post_link_target_substitution_preserves_foreign_target_and_cleans_temp(
        self,
    ) -> None:
        parent = self.root / "post-link-target-substitution"
        parent.mkdir(mode=0o700)
        target = parent / "receipt.json"
        callbacks = 0

        def substitute_on_post_link_guard() -> None:
            nonlocal callbacks
            callbacks += 1
            if callbacks == 3:
                target.unlink()
                target.write_bytes(b"attacker")
                target.chmod(0o600)
                raise verifier.VerificationError("SYNTHETIC_POST_LINK_FAILURE")

        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_CONFLICT"):
            verifier._write_atomic_receipt(
                target,
                verifier._canonical_bytes({"verdict": "PASS"}),
                publication_guard=substitute_on_post_link_guard,
            )
        self.assertEqual(b"attacker", target.read_bytes())
        self.assertEqual([], list(parent.glob(".receipt.json.tmp.*")))

        late_parent = self.root / "post-final-guard-target-substitution"
        late_parent.mkdir(mode=0o700)
        late_target = late_parent / "receipt.json"
        late_callbacks = 0

        def substitute_after_final_guard() -> None:
            nonlocal late_callbacks
            late_callbacks += 1
            if late_callbacks == 4:
                late_target.unlink()
                late_target.write_bytes(b"late-attacker")
                late_target.chmod(0o600)

        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_CONFLICT"):
            verifier._write_atomic_receipt(
                late_target,
                verifier._canonical_bytes({"verdict": "PASS"}),
                publication_guard=substitute_after_final_guard,
            )
        self.assertEqual(b"late-attacker", late_target.read_bytes())
        self.assertEqual([], list(late_parent.glob(".receipt.json.tmp.*")))

        existing_parent = self.root / "existing-final-guard-target-substitution"
        existing_parent.mkdir(mode=0o700)
        existing_target = existing_parent / "receipt.json"
        expected = verifier._canonical_bytes({"verdict": "PASS"})
        existing_target.write_bytes(expected)
        existing_target.chmod(0o600)
        existing_callbacks = 0

        def substitute_existing_after_guard() -> None:
            nonlocal existing_callbacks
            existing_callbacks += 1
            if existing_callbacks == 2:
                existing_target.unlink()
                existing_target.write_bytes(b"existing-attacker")
                existing_target.chmod(0o600)

        with self.assertRaisesRegex(verifier.VerificationError, "RECEIPT_CONFLICT"):
            verifier._write_atomic_receipt(
                existing_target,
                expected,
                publication_guard=substitute_existing_after_guard,
            )
        self.assertEqual(b"existing-attacker", existing_target.read_bytes())
        self.assertEqual([], list(existing_parent.glob(".receipt.json.tmp.*")))

    def test_final_repository_ref_cas_rejects_drift_without_pass(self) -> None:
        def publication_guard() -> None:
            verifier._final_publication_guard(
                direct_packet=self.packet_path,
                expected_packet_sha256=self.packet_sha256,
                evidence=self.evidence,
                packet=self.evidence["packet"],
            )

        remote_main = "refs/remotes/origin/main"
        candidate_remote = f"refs/remotes/origin/{self.branch}"
        scenarios = (
            ("main", remote_main, self.head_sha, self.base_sha),
            ("candidate-remote", candidate_remote, self.head_sha, None),
            (
                "unexpected-remote",
                "refs/remotes/origin/unexpected-after-prepare",
                self.head_sha,
                None,
            ),
            (
                "secondary-remote",
                "refs/remotes/secondary/unexpected-after-prepare",
                self.head_sha,
                None,
            ),
        )
        for name, reference, drift, restore in scenarios:
            with self.subTest(name=name):
                target = self.root / f"cas-{name}.json"
                _git(self.repository, "update-ref", reference, drift)
                try:
                    with self.assertRaises(verifier.VerificationError):
                        verifier._write_atomic_receipt(
                            target,
                            verifier._canonical_bytes({"verdict": "PASS"}),
                            publication_guard=publication_guard,
                        )
                finally:
                    if restore is None:
                        _git(self.repository, "update-ref", "-d", reference)
                    else:
                        _git(self.repository, "update-ref", reference, restore)
                self.assertFalse(target.exists())
                self.assertEqual([], list(self.root.glob(f".{target.name}.tmp.*")))

    def test_ancestry_budgets_and_deep_json_fail_deterministically(self) -> None:
        head = "a" * 40
        base = "b" * 40
        parent_one = "c" * 40
        parent_two = "d" * 40

        def commit(parents: tuple[str, ...]) -> bytes:
            return (
                f"tree {'e' * 40}\n"
                + "".join(f"parent {parent}\n" for parent in parents)
                + "author Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
                + "committer Bootstrap Test <bootstrap@example.invalid> 1 +0000\n"
                + "\nmessage\n"
            ).encode("ascii")

        with patch.object(
            verifier,
            "_git_object_bytes",
            return_value=commit((parent_one, parent_two)),
        ), patch.object(verifier, "ANCESTRY_EDGE_LIMIT", 1):
            with self.assertRaisesRegex(verifier.VerificationError, "ANCESTRY_LIMIT"):
                verifier._require_proper_ancestry(self.repository, base, head)

        with patch.object(
            verifier, "_git_object_bytes", return_value=commit((parent_one,))
        ), patch.object(verifier, "ANCESTRY_BYTE_LIMIT", 1):
            with self.assertRaisesRegex(verifier.VerificationError, "ANCESTRY_LIMIT"):
                verifier._require_proper_ancestry(self.repository, base, head)

        with patch.object(verifier, "ANCESTRY_SECONDS_LIMIT", -1), patch.object(
            verifier, "_git_object_bytes"
        ) as object_read:
            with self.assertRaisesRegex(verifier.VerificationError, "ANCESTRY_LIMIT"):
                verifier._require_proper_ancestry(self.repository, base, head)
        object_read.assert_not_called()

        raw_tree = b"".join(
            b"100644 entry-" + str(index).encode("ascii") + b"\0" + bytes([index]) * 20
            for index in range(1, 5)
        )
        with self.assertRaisesRegex(verifier.VerificationError, "TREE_ENTRY_LIMIT"):
            verifier._raw_tree_entries(raw_tree, remaining=3)

        oversized_header = commit(())
        with patch.object(
            verifier, "_git_object_bytes", return_value=oversized_header
        ), patch.object(verifier, "COMMIT_HEADER_LINE_LIMIT", 2):
            with self.assertRaisesRegex(
                verifier.VerificationError, "COMMIT_HEADER_LIMIT"
            ):
                verifier._raw_commit(self.repository, head, "SYNTHETIC")

        deep = b'{"nested":' + (b"[" * 1000) + b"0" + (b"]" * 1000) + b"}"
        deep_packet = self.root / "deep-packet.json"
        deep_packet.write_bytes(deep)
        with self.assertRaisesRegex(verifier.VerificationError, "INVALID_JSON"):
            verifier._load_direct_packet(
                deep_packet, verifier._sha256(deep_packet.read_bytes())
            )
        deep_candidate = self.root / "deep-candidate.json"
        deep_candidate.write_bytes(deep)
        with self.assertRaisesRegex(verifier.VerificationError, "INVALID_JSON"):
            verifier._load_candidate(deep_candidate)
        brackets_in_string = verifier._load_json_object(
            verifier._canonical_bytes({"value": "[" * 1000}),
            "SYNTHETIC_INVALID_JSON",
        )
        self.assertEqual("[" * 1000, brackets_in_string["value"])

    def test_early_receipt_failures_leave_zero_temporary_artifacts(self) -> None:
        contents = verifier._canonical_bytes({"early": "failure"})

        partial_target = self.root / "partial-write.json"

        def fail_partial(descriptor: int, payload: bytes) -> None:
            os.write(descriptor, payload[:1])
            raise verifier.VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED")

        with patch.object(verifier, "_write_all", side_effect=fail_partial):
            with self.assertRaisesRegex(verifier.VerificationError, "WRITE_FAILED"):
                verifier._write_atomic_receipt(partial_target, contents)
        self.assertFalse(partial_target.exists())
        self.assertEqual([], list(self.root.glob(".partial-write.json.tmp.*")))

        fstat_target = self.root / "early-fstat.json"
        real_fstat = verifier.os.fstat
        failed = False

        def fail_created_temporary(descriptor: int) -> os.stat_result:
            nonlocal failed
            try:
                linked = os.readlink(f"/proc/self/fd/{descriptor}")
            except OSError:
                linked = ""
            if not failed and ".early-fstat.json.tmp." in linked:
                failed = True
                raise OSError("synthetic fstat failure")
            return real_fstat(descriptor)

        with patch.object(verifier.os, "fstat", side_effect=fail_created_temporary):
            with self.assertRaisesRegex(verifier.VerificationError, "WRITE_FAILED"):
                verifier._write_atomic_receipt(fstat_target, contents)
        self.assertTrue(failed)
        self.assertFalse(fstat_target.exists())
        self.assertEqual([], list(self.root.glob(".early-fstat.json.tmp.*")))

        scan_parent = self.root / "bounded-crash-scan"
        scan_parent.mkdir(mode=0o700)
        scan_target = scan_parent / "receipt.json"
        scan_target.write_bytes(contents)
        scan_target.chmod(0o600)
        os.link(scan_target, scan_parent / ".receipt.json.tmp.synthetic")
        (scan_parent / "unrelated-one").write_bytes(b"1")
        (scan_parent / "unrelated-two").write_bytes(b"2")
        directory_fd = os.open(scan_parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(verifier, "RECEIPT_DIRECTORY_ENTRY_LIMIT", 1):
                with self.assertRaisesRegex(
                    verifier.VerificationError, "DIRECTORY_SCAN_LIMIT"
                ):
                    verifier._matching_crash_temporary(
                        directory_fd, scan_target.name, scan_target.stat()
                    )
        finally:
            os.close(directory_fd)


if __name__ == "__main__":
    unittest.main()
