from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from delivery_identity import (  # noqa: E402
    admission_transaction_sha256,
    bind_delivery_identity,
    delivery_identity_error,
    delivery_identity_sha256,
)
from repository_delivery_policy import (  # noqa: E402
    APPLICATION_REPOSITORY,
    HARNESS_REPOSITORY,
)


class DeliveryIdentityTests(unittest.TestCase):
    @staticmethod
    def admission(
        *,
        repository: str = APPLICATION_REPOSITORY,
        issue_number: int = 303,
        generation: int = 2,
        branch: str = "codex/303-delivery-identity",
        worktree_path: str = "/home/ubuntu/code/twinfinityapp-issue-303",
        opaque_worktree_id: str = "twinfinityapp-issue-303",
    ) -> dict:
        payload = {
            "source": {
                "repository": repository,
                "object_kind": "issue",
                "object_number": issue_number,
                "payload_sha256": "a" * 64,
            },
            "issue_number": issue_number,
            "generation": generation,
            "item_version": 8,
            "base_sha": "b" * 40,
            "branch": branch,
            "worktree_path": worktree_path,
            "opaque_worktree_id": opaque_worktree_id,
            "lease_manifest_sha256": "c" * 64,
            "authority_sha256": "d" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
        }
        return {
            "item": {
                "repository": repository,
                "issue_number": issue_number,
                "generation": generation,
                "expected_version": 7,
            },
            "message": {
                "idempotency_key": f"issue-{issue_number}-delivery-identity",
                "recipient_session_id": "role.development.v1",
                "topic": "development.admission",
                "payload": payload,
            },
            "artifacts": [],
        }

    def test_bind_covers_the_complete_admission_transaction(self) -> None:
        admission = self.admission()
        identity = bind_delivery_identity(admission)

        self.assertIsNone(delivery_identity_error(identity, admission=admission))
        self.assertEqual(
            identity["admission_transaction_sha256"],
            admission_transaction_sha256(admission),
        )
        self.assertEqual(64, len(delivery_identity_sha256(identity)))

        changed = deepcopy(admission)
        changed["item"]["expected_version"] += 1
        self.assertEqual(
            "DELIVERY_IDENTITY_TRANSACTION_DRIFT",
            delivery_identity_error(identity, admission=changed),
        )
        unbound = deepcopy(admission)
        del unbound["message"]["payload"]["delivery_identity"]
        self.assertEqual(
            "DELIVERY_IDENTITY_MISSING",
            delivery_identity_error(identity, admission=unbound),
        )

    def test_transaction_digest_normalizes_only_its_own_slot(self) -> None:
        admission = self.admission()
        identity = bind_delivery_identity(admission)
        expected = admission_transaction_sha256(admission)

        self_digest_only = deepcopy(admission)
        self_digest_only["message"]["payload"]["delivery_identity"][
            "admission_transaction_sha256"
        ] = "e" * 64
        self.assertEqual(expected, admission_transaction_sha256(self_digest_only))

        another_identity_field = deepcopy(admission)
        another_identity_field["message"]["payload"]["delivery_identity"][
            "lease_manifest_sha256"
        ] = "f" * 64
        self.assertNotEqual(
            identity["admission_transaction_sha256"],
            admission_transaction_sha256(another_identity_field),
        )

    def test_every_delivery_coordinate_is_transaction_bound(self) -> None:
        admission = self.admission()
        identity = bind_delivery_identity(admission)
        substitutions = {
            "lease_manifest_sha256": "1" * 64,
            "branch": "codex/303-substituted",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-303-v2",
            "opaque_worktree_id": "issue-303-generation-2",
            "generation": 3,
            "authority_sha256": "2" * 64,
        }
        for field, value in substitutions.items():
            with self.subTest(field=field):
                changed = deepcopy(admission)
                changed["message"]["payload"][field] = value
                self.assertEqual(
                    "DELIVERY_IDENTITY_TRANSACTION_DRIFT",
                    delivery_identity_error(identity, admission=changed),
                )

    def test_repository_specific_identity_policy_is_preserved(self) -> None:
        accepted = (
            self.admission(),
            self.admission(
                worktree_path="/home/ubuntu/code/twinfinityapp-issue-303-v2",
                opaque_worktree_id="issue-303-generation-2",
            ),
            self.admission(
                repository=HARNESS_REPOSITORY,
                issue_number=68,
                generation=1,
                branch="change/68-delivery-identity",
                worktree_path=(
                    "/home/ubuntu/code/twinfinity/"
                    "twinfinity-harness-issue68-delivery"
                ),
                opaque_worktree_id="twinfinity-harness-issue68-delivery",
            ),
        )
        for admission in accepted:
            with self.subTest(
                repository=admission["message"]["payload"]["source"]["repository"],
                worktree=admission["message"]["payload"]["worktree_path"],
            ):
                identity = bind_delivery_identity(admission)
                self.assertIsNone(
                    delivery_identity_error(identity, admission=admission)
                )

        rejected = self.admission(
            worktree_path="/home/ubuntu/code/twinfinityapp-issue-303-g2",
            opaque_worktree_id="issue-303-generation-2",
        )
        with self.assertRaisesRegex(ValueError, "DELIVERY_IDENTITY_POLICY_INVALID"):
            bind_delivery_identity(rejected)
        policy_substitutions = (
            self.admission(
                branch="codex/304-wrong-surface",
                worktree_path="/home/ubuntu/code/twinfinityapp-issue-303",
                opaque_worktree_id="twinfinityapp-issue-303",
            ),
            self.admission(
                worktree_path=(
                    "/home/ubuntu/code/./twinfinityapp-issue-303"
                ),
            ),
            self.admission(
                worktree_path=(
                    "/home/ubuntu//code/twinfinityapp-issue-303"
                ),
            ),
            self.admission(
                repository=HARNESS_REPOSITORY,
                issue_number=68,
                generation=1,
                branch="change/68-delivery-identity",
                worktree_path=(
                    "/home/ubuntu/code/twinfinity/harness/"
                    "twinfinity-harness-issue68-delivery"
                ),
                opaque_worktree_id="twinfinity-harness-issue68-delivery",
            ),
            self.admission(
                repository=HARNESS_REPOSITORY,
                issue_number=68,
                generation=1,
                branch="change/69-wrong-owner",
                worktree_path=(
                    "/home/ubuntu/code/twinfinity/"
                    "twinfinity-harness-issue69-wrong-owner"
                ),
                opaque_worktree_id="twinfinity-harness-issue69-wrong-owner",
            ),
        )
        for substituted in policy_substitutions:
            with self.subTest(
                branch=substituted["message"]["payload"]["branch"],
                worktree=substituted["message"]["payload"]["worktree_path"],
            ), self.assertRaisesRegex(
                ValueError, "DELIVERY_IDENTITY_POLICY_INVALID"
            ):
                bind_delivery_identity(substituted)


if __name__ == "__main__":
    unittest.main()
