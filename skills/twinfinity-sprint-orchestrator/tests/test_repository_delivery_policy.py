from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    canonical_json,
    parse_structured_lease_manifest,
)
from delivery_guard import GuardError, _parse_lease  # noqa: E402
from delivery_identity import (  # noqa: E402
    DELIVERY_IDENTITY_SCHEMA,
    delivery_identity_error,
)
from approval_guard import (  # noqa: E402
    admission_execution_scope_sha256,
    execution_scope_sha256,
)
from repository_delivery_policy import (  # noqa: E402
    APPLICATION_REPOSITORY,
    HARNESS_REPOSITORY,
    HARNESS_STANDING_AUTHORITY_SCHEMA,
    canonical_harness_standing_controls,
    delivery_branch_matches_owning_issue,
    delivery_branch_issue_number,
    expected_canonical_checkout,
    expected_worktree_parent,
    harness_standing_authority_error,
    message_worktree_identity_matches,
    policy_for_repository,
    strict_delivery_branch_matches,
    worktree_identity_matches,
    worktree_path_matches_owning_issue,
)


class RepositoryDeliveryPolicyTests(unittest.TestCase):
    def lease(
        self,
        repository: str,
        branch: str,
        *,
        issue_number: int = 36,
        worktree_path: str = (
            "/home/ubuntu/code/twinfinity/"
            "twinfinity-harness-issue36-authorized"
        ),
    ) -> bytes:
        return canonical_json(
            {
                "repository": repository,
                "issue_number": issue_number,
                "generation": 1,
                "base_sha": "a" * 40,
                "branch": branch,
                "worktree_path": worktree_path,
                "no_additional_paths": True,
                "paths": [
                    {
                        "path": "README.md",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "b" * 40,
                    }
                ],
            }
        ).encode("utf-8")

    def test_repository_derived_branch_matrix(self) -> None:
        accepted = (
            (APPLICATION_REPOSITORY, "codex/36-policy"),
            (HARNESS_REPOSITORY, "change/36-policy"),
        )
        rejected = (
            (APPLICATION_REPOSITORY, "change/36-policy"),
            (HARNESS_REPOSITORY, "codex/36-policy"),
            (HARNESS_REPOSITORY, "change/0-policy"),
            ("other/example", "codex/36-policy"),
            (HARNESS_REPOSITORY.upper(), "change/36-policy"),
        )
        for repository, branch in accepted:
            with self.subTest(repository=repository, branch=branch):
                self.assertTrue(strict_delivery_branch_matches(repository, branch))
                self.assertTrue(
                    strict_delivery_branch_matches(
                        repository, branch, issue_number=36
                    )
                )
                self.assertEqual(
                    36, delivery_branch_issue_number(repository, branch)
                )
        for repository, branch in rejected:
            with self.subTest(repository=repository, branch=branch):
                self.assertFalse(strict_delivery_branch_matches(repository, branch))
                self.assertIsNone(delivery_branch_issue_number(repository, branch))
        self.assertFalse(
            strict_delivery_branch_matches(
                HARNESS_REPOSITORY, "change/36-policy", issue_number=37
            )
        )
        self.assertTrue(
            delivery_branch_matches_owning_issue(
                APPLICATION_REPOSITORY, "codex/36-policy", 37
            )
        )
        self.assertTrue(
            delivery_branch_matches_owning_issue(
                HARNESS_REPOSITORY, "change/36-policy", 36
            )
        )
        self.assertFalse(
            delivery_branch_matches_owning_issue(
                HARNESS_REPOSITORY, "change/36-policy", 37
            )
        )

    def test_application_worktree_behavior_is_preserved(self) -> None:
        workspace_root = Path("/home/ubuntu/code")
        self.assertEqual(
            workspace_root,
            expected_worktree_parent(APPLICATION_REPOSITORY, workspace_root),
        )
        self.assertEqual(
            workspace_root / "twinfinityapp",
            expected_canonical_checkout(APPLICATION_REPOSITORY, workspace_root),
        )
        self.assertTrue(
            worktree_identity_matches(
                APPLICATION_REPOSITORY,
                surface_issue_number=36,
                owning_issue_number=36,
                generation=2,
                worktree_path="/home/ubuntu/code/twinfinityapp-issue-36",
                opaque_worktree_id="twinfinityapp-issue-36",
            )
        )
        self.assertTrue(
            worktree_path_matches_owning_issue(
                HARNESS_REPOSITORY,
                "/home/ubuntu/code/twinfinity/"
                "twinfinity-harness-issue36-authorized",
                36,
            )
        )
        self.assertTrue(
            message_worktree_identity_matches(
                HARNESS_REPOSITORY,
                "/home/ubuntu/code/twinfinity/"
                "twinfinity-harness-issue36-authorized",
                "twinfinity-harness-issue36-authorized",
                36,
            )
        )
        self.assertFalse(
            message_worktree_identity_matches(
                HARNESS_REPOSITORY,
                "/home/ubuntu/code/twinfinity/"
                "twinfinity-harness-issue36-authorized",
                "caller-selected-identity",
                36,
            )
        )
        for path in (
            "/home/ubuntu/code/twinfinity/twinfinity-harness",
            "/home/ubuntu/code/twinfinity/twinfinity-harness-issue37",
        ):
            with self.subTest(path=path):
                self.assertFalse(
                    worktree_path_matches_owning_issue(
                        HARNESS_REPOSITORY, path, 36
                    )
                )
        self.assertFalse(
            worktree_identity_matches(
                HARNESS_REPOSITORY,
                surface_issue_number=36,
                owning_issue_number=37,
                generation=1,
                worktree_path=(
                    "/home/ubuntu/code/twinfinity/"
                    "twinfinity-harness-issue36-authorized"
                ),
                opaque_worktree_id="twinfinity-harness-issue36-authorized",
            )
        )
        self.assertTrue(
            worktree_identity_matches(
                APPLICATION_REPOSITORY,
                surface_issue_number=36,
                owning_issue_number=36,
                generation=2,
                worktree_path="/home/ubuntu/code/twinfinityapp-issue-36-v2",
                opaque_worktree_id="issue-36-generation-2",
            )
        )
        self.assertFalse(
            worktree_identity_matches(
                APPLICATION_REPOSITORY,
                surface_issue_number=303,
                owning_issue_number=303,
                generation=2,
                worktree_path="/home/ubuntu/code/twinfinityapp-issue-303-g2",
                opaque_worktree_id="issue-303-generation-2",
            )
        )
        self.assertFalse(
            worktree_identity_matches(
                APPLICATION_REPOSITORY,
                surface_issue_number=36,
                owning_issue_number=36,
                generation=2,
                worktree_path=(
                    "/home/ubuntu/code/twinfinity-harness-issue36-authorized"
                ),
                opaque_worktree_id="twinfinity-harness-issue36-authorized",
            )
        )

    def test_harness_worktree_is_exactly_harness_owned(self) -> None:
        workspace_root = Path("/home/ubuntu/code")
        self.assertEqual(
            workspace_root / "twinfinity",
            expected_worktree_parent(HARNESS_REPOSITORY, workspace_root),
        )
        self.assertEqual(
            workspace_root / "twinfinity" / "twinfinity-harness",
            expected_canonical_checkout(HARNESS_REPOSITORY, workspace_root),
        )
        self.assertTrue(
            worktree_identity_matches(
                HARNESS_REPOSITORY,
                surface_issue_number=36,
                owning_issue_number=36,
                generation=1,
                worktree_path=(
                    "/home/ubuntu/code/twinfinity/"
                    "twinfinity-harness-issue36-authorized"
                ),
                opaque_worktree_id="twinfinity-harness-issue36-authorized",
            )
        )
        for path, opaque in (
            (
                "/home/ubuntu/code/twinfinityapp-issue-36",
                "twinfinityapp-issue-36",
            ),
            (
                "/home/ubuntu/code/twinfinity-harness-issue37-authorized",
                "twinfinity-harness-issue37-authorized",
            ),
            (
                "/home/ubuntu/code/twinfinity-harness-issue36-authorized",
                "caller-selected-identity",
            ),
        ):
            with self.subTest(path=path, opaque=opaque):
                self.assertFalse(
                    worktree_identity_matches(
                        HARNESS_REPOSITORY,
                        surface_issue_number=36,
                        owning_issue_number=36,
                        generation=1,
                        worktree_path=path,
                        opaque_worktree_id=opaque,
                    )
                )

    def test_delivery_identity_policy_rejects_the_issue_303_g2_regression(self) -> None:
        def identity(
            repository: str,
            issue_number: int,
            generation: int,
            branch: str,
            worktree_path: str,
            opaque_worktree_id: str,
        ) -> dict:
            return {
                "schema": DELIVERY_IDENTITY_SCHEMA,
                "repository": repository,
                "issue_number": issue_number,
                "generation": generation,
                "lease_manifest_sha256": "1" * 64,
                "branch": branch,
                "worktree_path": worktree_path,
                "opaque_worktree_id": opaque_worktree_id,
                "admission_execution_scope_sha256": "2" * 64,
                "admission_transaction_sha256": "3" * 64,
            }

        accepted = (
            identity(
                APPLICATION_REPOSITORY,
                303,
                2,
                "codex/303-delivery-identity",
                "/home/ubuntu/code/twinfinityapp-issue-303",
                "twinfinityapp-issue-303",
            ),
            identity(
                APPLICATION_REPOSITORY,
                303,
                2,
                "codex/303-delivery-identity",
                "/home/ubuntu/code/twinfinityapp-issue-303-v2",
                "issue-303-generation-2",
            ),
            identity(
                HARNESS_REPOSITORY,
                68,
                1,
                "change/68-delivery-identity",
                "/home/ubuntu/code/twinfinity/twinfinity-harness-issue68-recovery",
                "twinfinity-harness-issue68-recovery",
            ),
        )
        for candidate in accepted:
            with self.subTest(candidate=candidate["worktree_path"]):
                self.assertIsNone(delivery_identity_error(candidate))

        rejected = (
            identity(
                APPLICATION_REPOSITORY,
                303,
                2,
                "codex/303-delivery-identity",
                "/home/ubuntu/code/twinfinityapp-issue-303-g2",
                "issue-303-generation-2",
            ),
            identity(
                APPLICATION_REPOSITORY,
                303,
                2,
                "change/303-delivery-identity",
                "/home/ubuntu/code/twinfinityapp-issue-303",
                "twinfinityapp-issue-303",
            ),
            identity(
                HARNESS_REPOSITORY,
                68,
                1,
                "codex/68-delivery-identity",
                "/home/ubuntu/code/twinfinity/twinfinity-harness-issue68-recovery",
                "twinfinity-harness-issue68-recovery",
            ),
            identity(
                HARNESS_REPOSITORY,
                68,
                1,
                "change/67-delivery-identity",
                "/home/ubuntu/code/twinfinity/twinfinity-harness-issue68-recovery",
                "twinfinity-harness-issue68-recovery",
            ),
        )
        for candidate in rejected:
            with self.subTest(candidate=candidate):
                self.assertEqual(
                    "DELIVERY_IDENTITY_POLICY_INVALID",
                    delivery_identity_error(candidate),
                )

    def test_store_and_delivery_guard_share_the_harness_lease_policy(self) -> None:
        raw = self.lease(HARNESS_REPOSITORY, "change/36-policy")
        self.assertEqual(
            "change/36-policy", parse_structured_lease_manifest(raw)["branch"]
        )
        self.assertEqual("change/36-policy", _parse_lease(raw)["branch"])

        for repository, branch in (
            (HARNESS_REPOSITORY, "codex/36-policy"),
            (APPLICATION_REPOSITORY, "change/36-policy"),
            ("other/example", "change/36-policy"),
        ):
            with self.subTest(repository=repository, branch=branch):
                invalid = self.lease(repository, branch)
                with self.assertRaisesRegex(
                    CoordinationError, "LEASE_MANIFEST_INVALID"
                ):
                    parse_structured_lease_manifest(invalid)
                with self.assertRaisesRegex(
                    GuardError, "DELIVERY_LEASE_INVALID"
                ):
                    _parse_lease(invalid)

        transferred_application = self.lease(
            APPLICATION_REPOSITORY,
            "codex/36-policy",
            issue_number=37,
            worktree_path="/home/ubuntu/code/twinfinityapp-issue-36",
        )
        self.assertEqual(
            37,
            parse_structured_lease_manifest(transferred_application)[
                "issue_number"
            ],
        )
        self.assertEqual(37, _parse_lease(transferred_application)["issue_number"])

        foreign_harness = self.lease(
            HARNESS_REPOSITORY,
            "change/36-policy",
            issue_number=37,
        )
        with self.assertRaisesRegex(CoordinationError, "LEASE_MANIFEST_INVALID"):
            parse_structured_lease_manifest(foreign_harness)
        with self.assertRaisesRegex(GuardError, "DELIVERY_LEASE_INVALID"):
            _parse_lease(foreign_harness)

        for worktree_path in (
            "/home/ubuntu/code/twinfinity/twinfinity-harness",
            "/home/ubuntu/code/twinfinity/twinfinity-harness-issue37",
        ):
            with self.subTest(worktree_path=worktree_path):
                invalid_worktree = self.lease(
                    HARNESS_REPOSITORY,
                    "change/36-policy",
                    worktree_path=worktree_path,
                )
                with self.assertRaisesRegex(
                    CoordinationError, "LEASE_MANIFEST_INVALID"
                ):
                    parse_structured_lease_manifest(invalid_worktree)
                with self.assertRaisesRegex(
                    GuardError, "DELIVERY_LEASE_INVALID"
                ):
                    _parse_lease(invalid_worktree)

    def test_lease_parser_rejects_duplicate_keys(self) -> None:
        payload = json.loads(self.lease(HARNESS_REPOSITORY, "change/36-policy"))
        raw = canonical_json(payload)[:-1] + ',"repository":"other/example"}'
        with self.assertRaisesRegex(
            CoordinationError, "LEASE_MANIFEST_INVALID"
        ):
            parse_structured_lease_manifest(raw.encode("utf-8"))

    def test_gate_profile_and_writer_mutex_are_derived_only_from_repository(self) -> None:
        application = policy_for_repository(APPLICATION_REPOSITORY)
        harness = policy_for_repository(HARNESS_REPOSITORY)
        self.assertEqual("application-compose-v1", application.prepush_gate_profile)
        self.assertFalse(application.exclusive_repository_writer)
        self.assertEqual("harness-source-v1", harness.prepush_gate_profile)
        self.assertTrue(harness.exclusive_repository_writer)
        self.assertIsNone(policy_for_repository(HARNESS_REPOSITORY.upper()))

    def test_harness_standing_authority_binds_complete_source_envelope(self) -> None:
        controls = canonical_harness_standing_controls()
        binding = {
            "schema": HARNESS_STANDING_AUTHORITY_SCHEMA,
            "repository": HARNESS_REPOSITORY,
            "issue_number": 36,
            "source_payload_sha256": "1" * 64,
            "stable_source_sha256": "7" * 64,
            "planner_goal_sha256": "2" * 64,
            "accepted_main_sha": "3" * 40,
            **controls,
        }
        payload = {
            "source": {
                "repository": HARNESS_REPOSITORY,
                "object_kind": "issue",
                "object_number": 36,
                "payload_sha256": "1" * 64,
            },
            "issue_number": 36,
            "base_sha": "3" * 40,
            "standing_source_authority": binding,
            "standing_source_authority_sha256": hashlib.sha256(
                canonical_json(binding).encode("utf-8")
            ).hexdigest(),
            "source_scope": binding["source_scope"],
            "source_exclusions": binding["exclusions"],
            "writer": binding["writer"],
            "reviewer_plan": binding["reviewer_plan"],
            "collision_proof": binding["collision_proof"],
            "environment_rule": binding["environment_rule"],
            "routine_chain": binding["routine_chain"],
            "hard_stops": binding["hard_stops"],
            "authority_sha256": "8" * 64,
        }
        self.assertIsNone(harness_standing_authority_error(payload))
        for field, replacement in (
            ("source_payload_sha256", "4" * 64),
            ("stable_source_sha256", "6" * 64),
            ("planner_goal_sha256", "5" * 64),
            ("accepted_main_sha", "6" * 40),
            ("source_scope", ["Different scope."]),
            ("exclusions", ["Different exclusion."]),
            ("writer", "Different writer."),
            ("reviewer_plan", ["Different reviewer."]),
            ("collision_proof", ["Different collision proof."]),
            ("environment_rule", "Different environment."),
            ("routine_chain", ["Different routine."]),
            ("hard_stops", ["Different stop."]),
        ):
            with self.subTest(field=field):
                drifted = copy.deepcopy(payload)
                drifted["standing_source_authority"][field] = replacement
                self.assertEqual(
                    "HARNESS_STANDING_AUTHORITY_DRIFT",
                    harness_standing_authority_error(drifted),
                )

    def test_application_approval_scope_is_unchanged_and_harness_scope_is_complete(self) -> None:
        application = {
            "source": {
                "repository": APPLICATION_REPOSITORY,
                "object_kind": "issue",
                "object_number": 36,
                "payload_sha256": "1" * 64,
            },
            "issue_number": 36,
            "generation": 1,
            "item_version": 2,
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            "base_sha": "3" * 40,
            "branch": "codex/36-example",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-36",
            "lease_manifest_sha256": "4" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
        }
        legacy_scope = {
            "kind": "ADMISSION",
            "repository": APPLICATION_REPOSITORY,
            "issue_number": 36,
            "generation": 1,
            "item_version": 2,
            "action": application["action"],
            "base_sha": application["base_sha"],
            "branch": application["branch"],
            "worktree_path": application["worktree_path"],
            "lease_manifest_sha256": application["lease_manifest_sha256"],
            "capacity": application["capacity"],
        }
        self.assertEqual(
            execution_scope_sha256(legacy_scope),
            admission_execution_scope_sha256(application),
        )
        harness = copy.deepcopy(application)
        harness["source"]["repository"] = HARNESS_REPOSITORY
        harness.update(
            {
                "source_scope": ["source"],
                "source_exclusions": ["runtime"],
                "writer": "writer",
                "reviewer_plan": ["review"],
                "collision_proof": ["collision"],
                "environment_rule": "environment",
                "routine_chain": ["validate"],
                "hard_stops": ["stop"],
                "standing_source_authority": {"schema": "bound"},
            }
        )
        original = admission_execution_scope_sha256(harness)
        harness["source_scope"] = ["drifted"]
        self.assertNotEqual(original, admission_execution_scope_sha256(harness))

    def test_harness_approval_scope_ignores_caller_mirrors_when_standing_authority_is_stable(self) -> None:
        controls = canonical_harness_standing_controls()
        standing = {
            "schema": HARNESS_STANDING_AUTHORITY_SCHEMA,
            "repository": HARNESS_REPOSITORY,
            "issue_number": 36,
            "source_payload_sha256": "1" * 64,
            "stable_source_sha256": "2" * 64,
            "planner_goal_sha256": "3" * 64,
            "accepted_main_sha": "4" * 40,
            **controls,
        }
        payload = {
            "source": {
                "repository": HARNESS_REPOSITORY,
                "object_kind": "issue",
                "object_number": 36,
                "payload_sha256": "1" * 64,
            },
            "issue_number": 36,
            "generation": 1,
            "item_version": 2,
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            "base_sha": "4" * 40,
            "branch": "change/36-complete-harness-source-lane",
            "worktree_path": (
                "/home/ubuntu/code/twinfinity/"
                "twinfinity-harness-issue36-authorized"
            ),
            "lease_manifest_sha256": "5" * 64,
            "capacity": {
                "development_units": 0,
                "shared_units": 1,
                "sre_units": 0,
            },
            "standing_source_authority": standing,
            "standing_source_authority_sha256": hashlib.sha256(
                canonical_json(standing).encode("utf-8")
            ).hexdigest(),
            "source_scope": ["caller-supplied drift"],
            "source_exclusions": [],
            "writer": "caller drift",
            "reviewer_plan": ["caller drift"],
            "collision_proof": ["caller drift"],
            "environment_rule": "caller drift",
            "routine_chain": ["caller drift"],
            "hard_stops": ["caller drift"],
        }
        original = admission_execution_scope_sha256(payload)
        payload.update(
            {
                "source_scope": ["different caller scope"],
                "source_exclusions": ["different caller exclusion"],
                "writer": "different caller writer",
                "reviewer_plan": ["different caller reviewer"],
                "collision_proof": ["different caller collision"],
                "environment_rule": "different caller environment",
                "routine_chain": ["different caller routine"],
                "hard_stops": ["different caller stop"],
            }
        )
        self.assertEqual(original, admission_execution_scope_sha256(payload))


if __name__ == "__main__":
    unittest.main()
    harness_standing_authority_error,
    policy_for_repository,
