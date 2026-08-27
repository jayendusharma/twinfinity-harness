from __future__ import annotations

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
from repository_delivery_policy import (  # noqa: E402
    APPLICATION_REPOSITORY,
    HARNESS_REPOSITORY,
    delivery_branch_matches_owning_issue,
    delivery_branch_issue_number,
    expected_canonical_checkout,
    expected_worktree_parent,
    message_worktree_identity_matches,
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


if __name__ == "__main__":
    unittest.main()
