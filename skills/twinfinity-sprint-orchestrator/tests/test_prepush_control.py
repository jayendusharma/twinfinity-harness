from __future__ import annotations

from pathlib import Path
from dataclasses import replace
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import canonical_json, digest_json  # noqa: E402
from coordination_transfer import activate_transfer  # noqa: E402
from coordination_transfer_ledger import intent_sha256  # noqa: E402
from prepush_control import (  # noqa: E402
    ExistingEnvironment,
    LeaseManifest,
    PrePushControl,
    PrePushError,
    build_parser,
)
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
ISSUE = 314
SESSION = "role.sre.v4"
LEASE = "5" * 64
HEAD = "b" * 40


class PrePushControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.control = PrePushControl(root / "state.sqlite3")
        apply_reviewed_current_endpoint_catalog(
            self.control.connection,
            ROOT,
            operation_key="prepush-control-tests",
        )
        source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload={"number": ISSUE, "updated_at": "2026-08-23T00:00:00Z"},
            source_updated_at="2026-08-23T00:00:00Z",
            fetched_at="2026-08-23T00:00:01Z",
        )
        self.source_sha = source.payload_sha256
        self.control.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=ISSUE,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=2,
            accountable_session_id=SESSION,
            lease_manifest_sha256=LEASE,
            development_units=0,
            shared_units=0,
            sre_units=1,
            expected_source_sha256=self.source_sha,
            expected_version=0,
            now="2026-08-23T00:00:02Z",
        )
        self.message = self.control.store.enqueue_message(
            idempotency_key="issue-314-generation-2-sre",
            recipient_session_id=SESSION,
            topic="sre.admission",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": ISSUE,
                    "payload_sha256": self.source_sha,
                },
                "issue_number": ISSUE,
                "generation": 2,
                "item_version": 1,
                "base_sha": "a" * 40,
                "branch": "codex/314-ci-hardening",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-314",
                "opaque_worktree_id": "twinfinityapp-issue-314",
                "accountable_session_id": SESSION,
                "lease_manifest_sha256": LEASE,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 0,
                    "shared_units": 0,
                    "sre_units": 1,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
            now="2026-08-23T00:00:03Z",
        )
        message = self.control.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (self.message,),
        ).fetchone()
        self.control.connection.execute(
            "UPDATE coordination_terminal_watches "
            "SET admission_message_id=?,admission_payload_sha256=? "
            "WHERE watch_key=?",
            (
                self.message,
                message["payload_sha256"],
                f"terminal:{REPOSITORY}:issue:{ISSUE}:generation:2",
            ),
        )
        self.control.store.claim_message(
            self.message, SESSION, "2026-08-23T00:00:04Z"
        )
        self.control.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE',updated_at=? "
            "WHERE id=? AND state='CLAIMED' AND claimed_by=?",
            ("2026-08-23T00:00:05Z", self.message, SESSION),
        )
        row = self.control.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?",
            (self.message,),
        ).fetchone()
        self.admission_payload = json.loads(row["payload_json"])

    def tearDown(self) -> None:
        self.control.close()
        self.temp.cleanup()

    def rewrite_admission_payload(self, **updates: object) -> None:
        payload = json.loads(canonical_json(self.admission_payload))
        payload.update(updates)
        payload_sha256 = digest_json(payload)
        self.control.connection.execute(
            "DROP TRIGGER IF EXISTS coordination_message_envelope_immutable"
        )
        self.control.connection.execute(
            "UPDATE coordination_messages SET payload_json=?,payload_sha256=? "
            "WHERE id=?",
            (canonical_json(payload), payload_sha256, self.message),
        )
        self.control.connection.execute(
            "UPDATE coordination_terminal_watches "
            "SET admission_payload_sha256=? WHERE admission_message_id=?",
            (payload_sha256, self.message),
        )

    def seed_issue_328_versioned_lineage(self) -> int:
        issue_number = 328
        generation = 6
        session_id = "role.development.v4"
        lease_sha256 = "6" * 64
        source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue_number,
            payload={
                "number": issue_number,
                "updated_at": "2026-08-26T10:59:00Z",
            },
            source_updated_at="2026-08-26T10:59:00Z",
            fetched_at="2026-08-26T10:59:01Z",
        )
        self.control.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=issue_number,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=generation,
            accountable_session_id=session_id,
            lease_manifest_sha256=lease_sha256,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-26T10:59:02Z",
        )
        message_id = self.control.store.enqueue_message(
            idempotency_key="issue-328-generation-6-development-versioned",
            recipient_session_id=session_id,
            topic="development.admission",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": issue_number,
                    "payload_sha256": source.payload_sha256,
                },
                "issue_number": issue_number,
                "generation": generation,
                "item_version": 1,
                "base_sha": "c" * 40,
                "branch": "codex/328-evaluation-client-validation-v3",
                "worktree_path": (
                    "/home/ubuntu/code/twinfinityapp-issue-328-v3"
                ),
                "opaque_worktree_id": "issue-328-generation-6",
                "accountable_session_id": session_id,
                "lease_manifest_sha256": lease_sha256,
                "authority_sha256": "8" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 0,
                    "sre_units": 0,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
            now="2026-08-26T10:59:03Z",
        )
        message = self.control.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.control.connection.execute(
            "UPDATE coordination_terminal_watches "
            "SET admission_message_id=?,admission_payload_sha256=? "
            "WHERE watch_key=?",
            (
                message_id,
                message["payload_sha256"],
                f"terminal:{REPOSITORY}:issue:{issue_number}:generation:{generation}",
            ),
        )
        self.control.store.claim_message(
            message_id, session_id, "2026-08-26T10:59:04Z"
        )
        self.control.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE',updated_at=? "
            "WHERE id=? AND state='CLAIMED' AND claimed_by=?",
            ("2026-08-26T10:59:05Z", message_id, session_id),
        )
        return message_id

    def record(self, *, state: str = "PASS") -> dict:
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        passed = state == "PASS"
        return self.control._record(
            lineage=lineage,
            head_sha=HEAD,
            manifest=LeaseManifest(
                content_sha256=LEASE,
                changed_paths_sha256=digest_json(["backend/example.py"]),
                paths=("backend/example.py",),
            ),
            lower_gate='[{"argv":["./check.sh"],"cwd":"backend","name":"backend/check.sh"}]',
            compose_gate="python3 backend/scripts/browser_e2e.py",
            lower_exit=0 if passed else 1,
            compose_exit=0 if passed else None,
            run_id="p314-g2-bbbbbbbbbbbb",
            head_unchanged=True,
            cleanup_proven=passed,
            started_at="2026-08-23T00:00:06Z",
            completed_at=(
                "2026-08-23T00:00:07Z"
                if passed
                else "2026-08-23T00:00:08Z"
            ),
            error=None if passed else "PREPUSH_LOWER_GATE_FAILED",
            environment_provenance={
                "python": "/home/ubuntu/.codex/twinfinity-issue314-prepush-venv/bin/python"
            },
        )

    def test_claimed_recipient_fenced_admission_is_active_lineage(self) -> None:
        self.control.connection.execute(
            "UPDATE coordination_messages SET state='CLAIMED', claimed_by=? WHERE id=?",
            (SESSION, self.message),
        )
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        self.assertEqual(self.message, lineage.admission_message_id)

        self.control.connection.execute(
            "UPDATE coordination_messages SET claimed_by=? WHERE id=?",
            ("role.development.v4", self.message),
        )
        with self.assertRaisesRegex(
            PrePushError, "PREPUSH_COMPLETED_ADMISSION_ABSENT"
        ):
            self.control._lineage(REPOSITORY, ISSUE)

    def test_exact_issue_328_versioned_identity_reaches_ordinary_lineage(self) -> None:
        message_id = self.seed_issue_328_versioned_lineage()

        lineage = self.control._lineage(REPOSITORY, 328)

        self.assertEqual(message_id, lineage.admission_message_id)
        self.assertEqual(328, lineage.issue_number)
        self.assertEqual(328, lineage.surface_issue_number)
        self.assertEqual(6, lineage.generation)
        self.assertEqual(
            "codex/328-evaluation-client-validation-v3", lineage.branch
        )
        self.assertEqual(
            "/home/ubuntu/code/twinfinityapp-issue-328-v3",
            lineage.worktree_path,
        )

    def test_non_transfer_worktree_identity_positive_and_negative_matrix(self) -> None:
        accepted = (
            (
                "/home/ubuntu/code/twinfinityapp-issue-314",
                "twinfinityapp-issue-314",
            ),
            (
                "/home/ubuntu/code/twinfinityapp-issue-314-v7",
                "issue-314-generation-2",
            ),
        )
        for worktree_path, opaque_worktree_id in accepted:
            with self.subTest(
                accepted=True,
                worktree_path=worktree_path,
                opaque_worktree_id=opaque_worktree_id,
            ):
                self.rewrite_admission_payload(
                    worktree_path=worktree_path,
                    opaque_worktree_id=opaque_worktree_id,
                )
                lineage = self.control._lineage(REPOSITORY, ISSUE)
                self.assertEqual(worktree_path, lineage.worktree_path)

        rejected = (
            (
                "mixed-canonical-path",
                "/home/ubuntu/code/twinfinityapp-issue-314",
                "issue-314-generation-2",
            ),
            (
                "mixed-versioned-path",
                "/home/ubuntu/code/twinfinityapp-issue-314-v3",
                "twinfinityapp-issue-314",
            ),
            (
                "wrong-path-issue",
                "/home/ubuntu/code/twinfinityapp-issue-315-v3",
                "issue-314-generation-2",
            ),
            (
                "wrong-opaque-issue",
                "/home/ubuntu/code/twinfinityapp-issue-314-v3",
                "issue-315-generation-2",
            ),
            (
                "wrong-generation",
                "/home/ubuntu/code/twinfinityapp-issue-314-v3",
                "issue-314-generation-3",
            ),
            (
                "missing-version",
                "/home/ubuntu/code/twinfinityapp-issue-314-v",
                "issue-314-generation-2",
            ),
            (
                "zero-version",
                "/home/ubuntu/code/twinfinityapp-issue-314-v0",
                "issue-314-generation-2",
            ),
            (
                "negative-version",
                "/home/ubuntu/code/twinfinityapp-issue-314-v-1",
                "issue-314-generation-2",
            ),
            (
                "non-decimal-version",
                "/home/ubuntu/code/twinfinityapp-issue-314-vthree",
                "issue-314-generation-2",
            ),
            (
                "leading-zero-version",
                "/home/ubuntu/code/twinfinityapp-issue-314-v03",
                "issue-314-generation-2",
            ),
            (
                "extra-suffix",
                "/home/ubuntu/code/twinfinityapp-issue-314-v3-extra",
                "issue-314-generation-2",
            ),
            (
                "opaque-extra-suffix",
                "/home/ubuntu/code/twinfinityapp-issue-314-v3",
                "issue-314-generation-2-extra",
            ),
            (
                "wrong-parent",
                "/home/ubuntu/twinfinityapp-issue-314-v3",
                "issue-314-generation-2",
            ),
            (
                "relative-path",
                "twinfinityapp-issue-314-v3",
                "issue-314-generation-2",
            ),
            (
                "traversal",
                "/home/ubuntu/code/../code/twinfinityapp-issue-314-v3",
                "issue-314-generation-2",
            ),
            (
                "arbitrary-basename",
                "/home/ubuntu/code/planner-issued-v3",
                "issue-314-generation-2",
            ),
        )
        for name, worktree_path, opaque_worktree_id in rejected:
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    PrePushError, "PREPUSH_ADMISSION_INVALID"
                ),
            ):
                self.rewrite_admission_payload(
                    worktree_path=worktree_path,
                    opaque_worktree_id=opaque_worktree_id,
                )
                self.control._lineage(REPOSITORY, ISSUE)

    def test_versioned_identity_does_not_enable_transfer_fields(self) -> None:
        transfer_fields = {
            "parent_issue_number": ISSUE,
            "transfer_key": "ordinary-lineage-must-not-carry-transfer",
            "transfer_comment_ids": [1, 2],
            "transfer_comment_body_sha256": ["1" * 64, "2" * 64],
            "transfer_authority_sha256": "3" * 64,
            "transfer_intent_sha256": "4" * 64,
            "transfer_ledger_sha256": "5" * 64,
        }
        for field, value in transfer_fields.items():
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    PrePushError, "PREPUSH_ADMISSION_INVALID"
                ),
            ):
                self.rewrite_admission_payload(
                    worktree_path=(
                        "/home/ubuntu/code/twinfinityapp-issue-314-v3"
                    ),
                    opaque_worktree_id="issue-314-generation-2",
                    **{field: value},
                )
                self.control._lineage(REPOSITORY, ISSUE)

    def test_reviewed_transfer_preserves_parent_branch_and_environment_ownership(self) -> None:
        child_issue = 320
        child_lease = "6" * 64
        child_source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=child_issue,
            payload={"number": child_issue, "updated_at": "2026-08-23T00:01:00Z"},
            source_updated_at="2026-08-23T00:01:00Z",
            fetched_at="2026-08-23T00:01:01Z",
        )
        transfer_key = "issue314-to-320-v1"
        authority = "8" * 64
        comment_bodies = {
            1001: f"parent accepted {authority}",
            1002: f"successor accepted {authority}",
        }
        parent_payload_sha256 = self.control.connection.execute(
            "SELECT payload_sha256 FROM coordination_messages WHERE id=?",
            (self.message,),
        ).fetchone()[0]
        lineage_record = {
            "transfer_key": transfer_key,
            "repository": REPOSITORY,
            "predecessor_issue_number": ISSUE,
            "predecessor_generation": 2,
            "predecessor_item_version": 1,
            "predecessor_admission_item_version": 1,
            "predecessor_source_payload_sha256": self.source_sha,
            "predecessor_admission_message_id": self.message,
            "predecessor_admission_payload_sha256": parent_payload_sha256,
            "predecessor_accountable_session_id": SESSION,
            "predecessor_lease_manifest_sha256": LEASE,
            "predecessor_development_units": 0,
            "predecessor_shared_units": 0,
            "predecessor_sre_units": 1,
            "predecessor_pretransfer_status": "ACTIVE",
            "predecessor_pretransfer_allocation_class": "ACTIVE",
            "predecessor_release_status": "MONITOR",
            "predecessor_release_allocation_class": "NONE",
            "successor_issue_number": child_issue,
            "successor_generation": 1,
            "successor_item_version": 1,
            "successor_source_payload_sha256": child_source.payload_sha256,
            "successor_admission_message_id": 1,
            "successor_admission_payload_sha256": "0" * 64,
            "successor_accountable_session_id": SESSION,
            "successor_lease_manifest_sha256": child_lease,
            "successor_development_units": 0,
            "successor_shared_units": 0,
            "successor_sre_units": 1,
            "released_items": [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "status": "MONITOR",
                    "allocation_class": "NONE",
                    "generation": 3,
                    "version": 2,
                    "source_payload_sha256": self.source_sha,
                }
            ],
            "activated_item": {
                "repository": REPOSITORY,
                "issue_number": child_issue,
                "status": "ACTIVE_FENCED",
                "allocation_class": "ACTIVE",
                "generation": 1,
                "version": 1,
                "source_payload_sha256": child_source.payload_sha256,
            },
            "activation_event_schema": "v2",
            "branch": "codex/314-ci-hardening",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-314",
            "opaque_worktree_id": "twinfinityapp-issue-314",
            "transfer_authority_sha256": authority,
            "predecessor_comment_id": 1001,
            "predecessor_comment_body_sha256": hashlib.sha256(
                comment_bodies[1001].encode()
            ).hexdigest(),
            "successor_comment_id": 1002,
            "successor_comment_body_sha256": hashlib.sha256(
                comment_bodies[1002].encode()
            ).hexdigest(),
        }
        transfer_intent_sha256 = intent_sha256(lineage_record)
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": child_issue,
                "payload_sha256": child_source.payload_sha256,
            },
            "issue_number": child_issue,
            "generation": 1,
            "item_version": 1,
            "base_sha": "a" * 40,
            "branch": "codex/314-ci-hardening",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-314",
            "opaque_worktree_id": "twinfinityapp-issue-314",
            "accountable_session_id": SESSION,
            "lease_manifest_sha256": child_lease,
            "authority_sha256": authority,
            "capacity": {
                "development_units": 0,
                "shared_units": 0,
                "sre_units": 1,
            },
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            "transfer_key": transfer_key,
            "parent_issue_number": ISSUE,
            "transfer_comment_ids": [1001, 1002],
            "transfer_comment_body_sha256": [
                lineage_record["predecessor_comment_body_sha256"],
                lineage_record["successor_comment_body_sha256"],
            ],
            "transfer_authority_sha256": authority,
            "transfer_intent_sha256": transfer_intent_sha256,
        }
        transaction = {
            "transfer_key": transfer_key,
            "lineage": {
                key: lineage_record[key]
                for key in (
                    "predecessor_issue_number",
                    "predecessor_generation",
                    "predecessor_item_version",
                    "predecessor_admission_item_version",
                    "predecessor_source_payload_sha256",
                    "predecessor_admission_message_id",
                    "predecessor_admission_payload_sha256",
                    "predecessor_accountable_session_id",
                    "predecessor_lease_manifest_sha256",
                    "predecessor_development_units",
                    "predecessor_shared_units",
                    "predecessor_sre_units",
                    "predecessor_pretransfer_status",
                    "predecessor_pretransfer_allocation_class",
                    "predecessor_comment_id",
                    "predecessor_comment_body_sha256",
                    "successor_comment_id",
                    "successor_comment_body_sha256",
                )
            },
            "releases": [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "status": "MONITOR",
                    "allocation_class": "NONE",
                    "generation": 3,
                    "accountable_session_id": None,
                    "lease_manifest_sha256": None,
                    "development_units": 0,
                    "shared_units": 0,
                    "sre_units": 0,
                    "expected_source_sha256": self.source_sha,
                    "expected_version": 1,
                }
            ],
            "activation": {
                "item": {
                    "repository": REPOSITORY,
                    "issue_number": child_issue,
                    "status": "ACTIVE_FENCED",
                    "allocation_class": "ACTIVE",
                    "generation": 1,
                    "accountable_session_id": SESSION,
                    "lease_manifest_sha256": child_lease,
                    "development_units": 0,
                    "shared_units": 0,
                    "sre_units": 1,
                    "expected_source_sha256": child_source.payload_sha256,
                    "expected_version": 0,
                },
                "message": {
                    "idempotency_key": "issue-320-generation-1-sre",
                    "recipient_session_id": SESSION,
                    "topic": "sre.admission",
                    "payload": payload,
                },
            },
        }
        def fetch_comment(repository: str, comment_id: int) -> dict:
            return {
                "id": comment_id,
                "issue_url": (
                    f"https://api.github.com/repos/{repository}/issues/"
                    f"{ISSUE if comment_id == 1001 else child_issue}"
                ),
                "body": comment_bodies[comment_id],
            }

        with patch(
            "coordination_transfer_ledger.fetch_comment", side_effect=fetch_comment
        ):
            result = activate_transfer(
                self.control.store, transaction, "2026-08-23T00:01:02Z"
            )
        child_message = result["message_id"]
        self.control.connection.execute(
            "UPDATE coordination_terminal_watches SET state='ACTIVE' "
            "WHERE repository=? AND issue_number=? AND generation=1",
            (REPOSITORY, child_issue),
        )
        self.control.store.claim_message(
            child_message, SESSION, "2026-08-23T00:01:03Z"
        )
        self.control.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE',updated_at=? "
            "WHERE id=? AND state='CLAIMED' AND claimed_by=?",
            ("2026-08-23T00:01:04Z", child_message, SESSION),
        )
        with patch(
            "coordination_transfer_ledger.fetch_comment", side_effect=fetch_comment
        ):
            lineage = self.control._lineage(REPOSITORY, child_issue)
        self.assertEqual(child_issue, lineage.issue_number)
        self.assertEqual(ISSUE, lineage.surface_issue_number)
        self.assertEqual("codex/314-ci-hardening", lineage.branch)

        commands = (("backend/check.sh", "backend", ("./check.sh",)),)
        parent_bin = self._make_backend_environment(
            Path(self.temp.name) / "twinfinityapp-issue-314-env"
        )
        accepted = self.control._validate_gate_environment(
            lineage, commands, {"PATH": str(parent_bin)}
        )
        self.assertIn("twinfinityapp-issue-314", accepted["python"])
        child_bin = self._make_backend_environment(
            Path(self.temp.name) / "twinfinityapp-issue-320-env"
        )
        with self.assertRaisesRegex(PrePushError, "PREPUSH_FOREIGN_ENVIRONMENT"):
            self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(child_bin)}
            )

        def stale_comment(repository: str, comment_id: int) -> dict:
            result = fetch_comment(repository, comment_id)
            result["body"] = result["body"] + " changed"
            return result

        with (
            patch(
                "coordination_transfer_ledger.fetch_comment",
                side_effect=stale_comment,
            ),
            self.assertRaisesRegex(PrePushError, "TRANSFER_COMMENT_INVALID"),
        ):
            self.control._lineage(REPOSITORY, child_issue)

        with self.control.store.transaction():
            self.control.store._event(
                "TRANSFER_ADMISSION_ACTIVATED",
                transfer_key,
                {"duplicate": True},
                "2026-08-23T00:01:05Z",
            )
            duplicate_event_id = self.control.connection.execute(
                "SELECT MAX(id) FROM coordination_events"
            ).fetchone()[0]
        with (
            patch(
                "coordination_transfer_ledger.fetch_comment",
                side_effect=fetch_comment,
            ),
            self.assertRaisesRegex(
                PrePushError, "TRANSFER_EVENT_PROVENANCE_INVALID"
            ),
        ):
            self.control._lineage(REPOSITORY, child_issue)
        with self.control.store.transaction():
            self.control.connection.execute(
                "DELETE FROM coordination_events WHERE id=?", (duplicate_event_id,)
            )

        self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload={"number": ISSUE, "updated_at": "2026-08-23T00:02:00Z"},
            source_updated_at="2026-08-23T00:02:00Z",
            fetched_at="2026-08-23T00:02:01Z",
        )
        with (
            patch(
                "coordination_transfer_ledger.fetch_comment",
                side_effect=fetch_comment,
            ),
            self.assertRaisesRegex(PrePushError, "TRANSFER_LEDGER_SOURCE_DRIFT"),
        ):
            self.control._lineage(REPOSITORY, child_issue)

    def test_successor_branch_cannot_alias_predecessor_worktree(self) -> None:
        # Simulate a legacy/corrupted store. Current stores reject this write at
        # the immutable message-envelope trigger before pre-push is reached.
        self.control.connection.execute(
            "DROP TRIGGER coordination_message_envelope_immutable"
        )
        row = self.control.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?", (self.message,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["branch"] = "codex/314-ci-hardening"
        payload["worktree_path"] = "/home/ubuntu/code/twinfinityapp-issue-315"
        payload["opaque_worktree_id"] = "twinfinityapp-issue-315"
        self.control.connection.execute(
            "UPDATE coordination_messages SET payload_json=? WHERE id=?",
            (json.dumps(payload), self.message),
        )
        with self.assertRaisesRegex(PrePushError, "PREPUSH_ADMISSION_INVALID"):
            self.control._lineage(REPOSITORY, ISSUE)

    def test_production_cli_has_no_database_or_remote_override(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--database", "/tmp/alternate.sqlite3", "show"])
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "guarded-push",
                    "--repository",
                    REPOSITORY,
                    "--issue",
                    str(ISSUE),
                    "--remote",
                    "elsewhere",
                ]
            )
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "run",
                    "--repository",
                    REPOSITORY,
                    "--issue",
                    str(ISSUE),
                    "--lease-manifest",
                    "/tmp/lease.json",
                    "--pull-request",
                    "322",
                ]
            )

    def test_remote_must_be_canonical_github_repository(self) -> None:
        accepted = (
            "https://github.com/twinfinityai/twinfinityapp.git",
            "git@github.com:twinfinityai/twinfinityapp.git",
            "ssh://git@github.com/twinfinityai/twinfinityapp.git",
        )
        for remote in accepted:
            with self.subTest(remote=remote):
                self.assertEqual(
                    REPOSITORY,
                    self.control._normalized_remote_repository(remote),
                )
        for remote in (
            "https://github.com/other/twinfinityapp.git",
            "https://token@github.com/twinfinityai/twinfinityapp.git",
            "/tmp/twinfinityapp.git",
        ):
            with self.subTest(remote=remote):
                if remote.startswith("https://github.com/other/"):
                    self.assertNotEqual(
                        REPOSITORY,
                        self.control._normalized_remote_repository(remote),
                    )
                else:
                    with self.assertRaises(PrePushError):
                        self.control._normalized_remote_repository(remote)

    def test_lower_gate_matrix_covers_backend_frontend_and_workflow(self) -> None:
        commands = self.control._lower_gate_commands(
            ("backend/service.py", "frontend/src/App.tsx", ".github/workflows/ci.yml")
        )
        self.assertEqual(
            ("backend/check.sh", "frontend/npm-check", "frontend/npm-build"),
            tuple(command[0] for command in commands),
        )

    @staticmethod
    def _make_backend_environment(root: Path, *, python_symlink: bool = True) -> Path:
        bin_path = root / "bin"
        bin_path.mkdir(parents=True)
        (root / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
        python = bin_path / "python"
        if python_symlink:
            python.symlink_to(sys.executable)
        else:
            python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python.chmod(0o700)
        ruff = bin_path / "ruff"
        ruff.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        ruff.chmod(0o700)
        return bin_path

    def test_gate_environment_rejects_foreign_issue_and_unowned_backend_tools(self) -> None:
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        commands = (("backend/check.sh", "backend", ("./check.sh",)),)
        foreign_bin = self._make_backend_environment(
            Path(self.temp.name) / "twinfinityapp-issue-315-env"
        )
        unowned_bin = self._make_backend_environment(
            Path(self.temp.name) / "unowned-env"
        )
        owned_bin = self._make_backend_environment(
            Path(self.temp.name) / "twinfinityapp-issue-314-env"
        )
        with self.assertRaisesRegex(PrePushError, "PREPUSH_FOREIGN_ENVIRONMENT"):
            self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(foreign_bin)}
            )
        with self.assertRaisesRegex(PrePushError, "PREPUSH_ENVIRONMENT_UNOWNED"):
            self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(unowned_bin)}
            )
        accepted = self.control._validate_gate_environment(
            lineage, commands, {"PATH": str(owned_bin)}
        )
        self.assertIn("twinfinityapp-issue-314", accepted["python"])
        self.assertIn("twinfinityapp-issue-314", accepted["ruff"])

    def test_frontend_gate_environment_requires_node_20_before_lower_gates(self) -> None:
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        commands = (("frontend/npm-check", "frontend", ("npm", "run", "check")),)
        node_bin = Path(self.temp.name) / "node-v20" / "bin"
        node_bin.mkdir(parents=True)
        for tool in ("node", "npm"):
            executable = node_bin / tool
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
        resolved = {tool: str(node_bin / tool) for tool in ("node", "npm")}
        with patch(
            "prepush_control.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [resolved["node"], "--version"], 0, "v20.20.2\n", ""
            ),
        ) as version_check:
            accepted = self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(node_bin)}
            )
        self.assertEqual(resolved, {key: accepted[key] for key in ("node", "npm")})
        self.assertEqual(10, version_check.call_args.kwargs["timeout"])

        with (
            patch(
                "prepush_control.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [resolved["node"], "--version"], 0, "v18.20.8\n", ""
                ),
            ),
            self.assertRaisesRegex(PrePushError, "PREPUSH_NODE_VERSION_MISMATCH"),
        ):
            self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(node_bin)}
            )

        (node_bin / "npm").unlink()
        with self.assertRaisesRegex(PrePushError, "PREPUSH_GATE_TOOL_MISSING"):
            self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(node_bin)}
            )

    def test_gate_environment_prepares_lane_venv_and_installed_node_20(self) -> None:
        worktree = Path(self.temp.name) / "twinfinityapp-issue-314"
        lane_bin = self._make_backend_environment(worktree / ".venv")
        node_bin = Path(self.temp.name) / ".nvm" / "versions" / "node" / "v20.20.2" / "bin"
        node_bin.mkdir(parents=True)
        for tool in ("node", "npm"):
            executable = node_bin / tool
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(worktree),
        )
        commands = (
            ("backend/check.sh", "backend", ("./check.sh",)),
            ("frontend/npm-check", "frontend", ("npm", "run", "check")),
        )
        with patch("prepush_control.Path.home", return_value=Path(self.temp.name)):
            prepared = self.control._prepared_gate_environment(
                lineage, commands, {"PATH": "/usr/bin:/bin"}
            )
        self.assertEqual(
            (str(node_bin), str(lane_bin), "/usr/bin", "/bin"),
            tuple(prepared["PATH"].split(":")),
        )
        self.assertEqual(str(worktree / ".venv"), prepared["VIRTUAL_ENV"])

    def test_gate_environment_discovers_canonical_external_issue_venv(self) -> None:
        home = Path(self.temp.name) / "home"
        worktree = Path(self.temp.name) / "twinfinityapp-issue-314"
        worktree.mkdir()
        external_root = home / ".codex" / "twinfinity-issue314-prepush-venv"
        external_bin = self._make_backend_environment(external_root)
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(worktree),
        )
        commands = (("backend/check.sh", "backend", ("./check.sh",)),)

        with patch("prepush_control.Path.home", return_value=home):
            prepared = self.control._prepared_gate_environment(
                lineage, commands, {"PATH": "/usr/bin:/bin"}
            )
        provenance = self.control._validate_gate_environment(
            lineage, commands, prepared
        )

        self.assertEqual(str(external_root), prepared["VIRTUAL_ENV"])
        self.assertEqual(str(external_bin / "python"), provenance["python"])
        self.assertEqual(str(external_bin / "ruff"), provenance["ruff"])
        self.assertEqual(str(external_root), provenance["virtual_environment"])

    def test_packet_bound_backend_environment_is_preferred_and_fail_closed(self) -> None:
        worktree = Path(self.temp.name) / "twinfinityapp-issue-314"
        worktree.mkdir()
        self._make_backend_environment(worktree / ".venv")
        bound_root = Path(self.temp.name) / "twinfinity-issue314-bound-venv"
        bound_bin = self._make_backend_environment(bound_root)
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(worktree),
            environment_root=str(bound_root),
        )
        commands = (("backend/check.sh", "backend", ("./check.sh",)),)

        prepared = self.control._prepared_gate_environment(
            lineage, commands, {"PATH": "/usr/bin:/bin"}
        )
        self.assertEqual(str(bound_root), prepared["VIRTUAL_ENV"])
        self.assertEqual(str(bound_bin), prepared["PATH"].split(":")[0])

        (bound_bin / "ruff").unlink()
        with self.assertRaisesRegex(
            PrePushError, "PREPUSH_ADMISSION_ENVIRONMENT_INVALID"
        ):
            self.control._prepared_gate_environment(
                lineage, commands, {"PATH": "/usr/bin:/bin"}
            )

    def test_reused_environment_revalidates_receipt_provenance_and_freeze(self) -> None:
        evidence = self.control.store.path.parent / "environment-rebuild.log"
        evidence.write_text("verified environment\n", encoding="utf-8")
        artifact = self.control.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": 2,
                    "path": str(evidence),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-23T00:00:06Z",
        )[0]
        root = Path(self.temp.name) / "twinfinity-issue314-bound-venv"
        self._make_backend_environment(root)
        provenance = {
            "python": str(root / "bin" / "python"),
            "ruff": str(root / "bin" / "ruff"),
            "virtual_environment": str(root),
        }
        freeze = "alpha==1\nbeta==2\n"
        binding = ExistingEnvironment(
            root=str(root),
            rebuild_artifact_key=artifact["artifact_key"],
            rebuild_artifact_content_sha256=artifact["content_sha256"],
            freeze_sha256=hashlib.sha256(freeze.encode("utf-8")).hexdigest(),
            package_count=2,
            gate_environment_provenance_sha256=digest_json(provenance),
        )
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(Path(self.temp.name) / "twinfinityapp-issue-314"),
            environment_root=str(root),
            existing_environment=binding,
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="beta==2\nalpha==1\n", stderr=""
        )
        uv = Path("/home/ubuntu/.local/bin/uv")
        verifier_metadata = (root / "bin" / "ruff").lstat()
        path_lstat = Path.lstat
        path_is_symlink = Path.is_symlink

        def fixture_lstat(path: Path):
            if path == uv:
                return verifier_metadata
            return path_lstat(path)

        def fixture_is_symlink(path: Path) -> bool:
            if path == uv:
                return False
            return path_is_symlink(path)

        with (
            patch(
                "prepush_control.Path.lstat",
                autospec=True,
                side_effect=fixture_lstat,
            ),
            patch(
                "prepush_control.Path.is_symlink",
                autospec=True,
                side_effect=fixture_is_symlink,
            ),
            patch("prepush_control.subprocess.run", return_value=completed),
            patch.object(
                self.control,
                "_verify_existing_environment_receipt",
                return_value={"state": "PASS"},
            ),
        ):
            validated = self.control._validate_existing_environment(
                lineage, provenance
            )
        self.assertEqual(binding.freeze_sha256, validated["environment_freeze_sha256"])
        self.assertEqual("2", validated["environment_package_count"])

        drifted = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="alpha==9\nbeta==2\n", stderr=""
        )
        with (
            patch(
                "prepush_control.Path.lstat",
                autospec=True,
                side_effect=fixture_lstat,
            ),
            patch(
                "prepush_control.Path.is_symlink",
                autospec=True,
                side_effect=fixture_is_symlink,
            ),
            patch("prepush_control.subprocess.run", return_value=drifted),
            patch.object(
                self.control,
                "_verify_existing_environment_receipt",
                return_value={"state": "PASS"},
            ),
        ):
            with self.assertRaisesRegex(
                PrePushError, "PREPUSH_EXISTING_ENVIRONMENT_PACKAGE_DRIFT"
            ):
                self.control._validate_existing_environment(lineage, provenance)

    def test_reused_environment_rejects_malformed_persisted_receipts(self) -> None:
        base_lineage = self.control._lineage(REPOSITORY, ISSUE)
        log_path = self.control.store.path.parent / "persisted-rebuild.log"
        log_path.write_text("verified\n", encoding="utf-8")
        log_artifact = self.control.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": 2,
                    "path": str(log_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-23T00:00:06Z",
        )[0]
        template = {
            "kind": "TWINFINITY_ENVIRONMENT_REBUILD_RECEIPT_V1",
            "state": "PASS",
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": 2,
            "source_payload_sha256": base_lineage.source_payload_sha256,
            "built_candidate_head_sha": HEAD,
            "environment_root": "/home/ubuntu/.codex/twinfinity-issue314-prepush-venv-v3",
            "requirements": [
                {"path": "backend/requirements.txt", "sha256": "5" * 64}
            ],
            "freeze_sha256": "7" * 64,
            "package_count": 2,
            "gate_environment_provenance_sha256": "6" * 64,
            "log_artifact_key": log_artifact["artifact_key"],
            "log_artifact_content_sha256": log_artifact["content_sha256"],
        }
        malformed = []
        missing_provenance = dict(template)
        missing_provenance.pop("gate_environment_provenance_sha256")
        malformed.append(missing_provenance)
        unsafe_path = json.loads(json.dumps(template))
        unsafe_path["requirements"][0]["path"] = "../requirements.txt"
        malformed.append(unsafe_path)
        for index, receipt in enumerate(malformed):
            with self.subTest(index=index):
                receipt_path = (
                    self.control.store.path.parent
                    / f"persisted-rebuild-receipt-{index}.json"
                )
                receipt_path.write_text(
                    json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8"
                )
                receipt_artifact = self.control.store.register_artifacts(
                    [
                        {
                            "repository": REPOSITORY,
                            "issue_number": ISSUE,
                            "generation": 2,
                            "path": str(receipt_path),
                            "retention_class": "CLOSEOUT_EVIDENCE",
                        }
                    ],
                    now="2026-08-23T00:00:07Z",
                )[0]
                binding = ExistingEnvironment(
                    root=template["environment_root"],
                    rebuild_artifact_key=receipt_artifact["artifact_key"],
                    rebuild_artifact_content_sha256=receipt_artifact[
                        "content_sha256"
                    ],
                    freeze_sha256=template["freeze_sha256"],
                    package_count=template["package_count"],
                    gate_environment_provenance_sha256=template[
                        "gate_environment_provenance_sha256"
                    ],
                )
                lineage = replace(
                    base_lineage,
                    worktree_path=str(Path(self.temp.name) / "worktree"),
                    environment_root=binding.root,
                    existing_environment=binding,
                )
                with self.assertRaisesRegex(
                    PrePushError, "PREPUSH_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
                ):
                    self.control._verify_existing_environment_receipt(lineage)

    def test_backend_environment_rejects_hardlinked_executable(self) -> None:
        worktree = Path(self.temp.name) / "twinfinityapp-issue-314"
        worktree.mkdir()
        owned_root = Path(self.temp.name) / "twinfinity-issue314-owned-venv"
        owned_bin = self._make_backend_environment(owned_root)
        external = Path(self.temp.name) / "external-ruff"
        external.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        external.chmod(0o700)
        (owned_bin / "ruff").unlink()
        (owned_bin / "ruff").hardlink_to(external)
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(worktree),
            environment_root=str(owned_root),
        )
        commands = (("backend/check.sh", "backend", ("./check.sh",)),)

        with self.assertRaisesRegex(
            PrePushError, "PREPUSH_ADMISSION_ENVIRONMENT_INVALID"
        ):
            self.control._prepared_gate_environment(
                lineage, commands, {"PATH": "/usr/bin:/bin"}
            )

    def test_gate_environment_rejects_symlinked_roots_and_foreign_tool_targets(self) -> None:
        worktree = Path(self.temp.name) / "twinfinityapp-issue-314"
        foreign_root = Path(self.temp.name) / "twinfinityapp-issue-315-env"
        foreign_bin = self._make_backend_environment(foreign_root)
        worktree.mkdir()
        (worktree / ".venv").symlink_to(foreign_root)
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(worktree),
        )
        commands = (("backend/check.sh", "backend", ("./check.sh",)),)
        prepared = self.control._prepared_gate_environment(
            lineage, commands, {"PATH": "/usr/bin:/bin"}
        )
        self.assertNotIn(str(worktree / ".venv" / "bin"), prepared["PATH"])
        with self.assertRaisesRegex(
            PrePushError, "PREPUSH_(FOREIGN_ENVIRONMENT|ENVIRONMENT_UNOWNED)"
        ):
            self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(worktree / ".venv" / "bin")}
            )

        owned_root = Path(self.temp.name) / "twinfinityapp-issue-314-env"
        owned_bin = self._make_backend_environment(owned_root)
        (owned_bin / "ruff").unlink()
        (owned_bin / "ruff").symlink_to(foreign_bin / "ruff")
        with self.assertRaisesRegex(PrePushError, "PREPUSH_FOREIGN_ENVIRONMENT"):
            self.control._validate_gate_environment(
                lineage, commands, {"PATH": str(owned_bin)}
            )

    def test_prepared_environment_skips_symlinked_nvm_version(self) -> None:
        home = Path(self.temp.name) / "home"
        versions = home / ".nvm" / "versions" / "node"
        real_version = Path(self.temp.name) / "real-node" / "v20.20.2"
        real_bin = real_version / "bin"
        real_bin.mkdir(parents=True)
        versions.mkdir(parents=True)
        for tool in ("node", "npm"):
            executable = real_bin / tool
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
        (versions / "v20.20.2").symlink_to(real_version)
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        commands = (("frontend/npm-check", "frontend", ("npm", "run", "check")),)
        with patch("prepush_control.Path.home", return_value=home):
            prepared = self.control._prepared_gate_environment(
                lineage, commands, {"PATH": "/usr/bin:/bin"}
            )
        self.assertEqual("/usr/bin:/bin", prepared["PATH"])

    def test_controlled_gate_environment_removes_shell_injection_inputs(self) -> None:
        controlled = self.control._controlled_gate_environment(
            {
                "PATH": "/usr/bin:/bin",
                "BASH_ENV": "/tmp/injected.sh",
                "ENV": "/tmp/sh-injected.sh",
                "BASHOPTS": "extdebug",
                "SHELLOPTS": "xtrace",
                "CDPATH": "/tmp",
                "BASH_FUNC_ruff%%": "() { false; }",
                "SAFE_VALUE": "preserved",
            }
        )
        self.assertEqual("/usr/bin:/bin", controlled["PATH"])
        self.assertEqual("preserved", controlled["SAFE_VALUE"])
        self.assertEqual("1", controlled["PYTHONDONTWRITEBYTECODE"])
        for key in (
            "BASH_ENV",
            "ENV",
            "BASHOPTS",
            "SHELLOPTS",
            "CDPATH",
            "BASH_FUNC_ruff%%",
        ):
            self.assertNotIn(key, controlled)

    def test_manifest_binds_exact_diff_and_rejects_fifth_path(self) -> None:
        repository = Path(self.temp.name) / "repo"
        repository.mkdir()

        def git(*args: str) -> str:
            return subprocess.run(
                ["git", "-C", str(repository), *args],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        git("init", "-b", "codex/314-ci-hardening")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "Test")
        (repository / "one.txt").write_text("one\n", encoding="utf-8")
        (repository / "two.txt").write_text("two\n", encoding="utf-8")
        git("add", "one.txt", "two.txt")
        git("commit", "-m", "base")
        base = git("rev-parse", "HEAD")
        base_blobs = {
            path: git("rev-parse", f"{base}:{path}") for path in ("one.txt", "two.txt")
        }
        (repository / "one.txt").write_text("changed one\n", encoding="utf-8")
        (repository / "two.txt").write_text("changed two\n", encoding="utf-8")
        git("add", "one.txt", "two.txt")
        git("commit", "-m", "exact two")
        head = git("rev-parse", "HEAD")
        manifest_data = {
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": 2,
            "base_sha": base,
            "branch": "codex/314-ci-hardening",
            "worktree_path": str(repository),
            "no_additional_paths": True,
            "paths": [
                {
                    "path": path,
                    "mode": "100644",
                    "type": "blob",
                    "sha": base_blobs[path],
                }
                for path in ("one.txt", "two.txt")
            ],
        }
        raw = (json.dumps(manifest_data, indent=2) + "\n").encode()
        manifest_path = self.control.store.path.parent / "lease.json"
        manifest_path.write_bytes(raw)
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(repository),
            base_sha=base,
            lease_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        )
        validated = self.control._validate_manifest_file(
            lineage, repository, head, manifest_path
        )
        self.assertEqual(("one.txt", "two.txt"), validated.paths)

        reordered = json.loads(json.dumps(manifest_data))
        reordered["paths"].reverse()
        reordered_raw = (json.dumps(reordered, indent=2) + "\n").encode()
        manifest_path.write_bytes(reordered_raw)
        reordered_lineage = replace(
            lineage,
            lease_manifest_sha256=hashlib.sha256(reordered_raw).hexdigest(),
        )
        reordered_validated = self.control._validate_manifest_file(
            reordered_lineage, repository, head, manifest_path
        )
        self.assertEqual(("one.txt", "two.txt"), reordered_validated.paths)

        aliased = json.loads(json.dumps(manifest_data))
        aliased["paths"][0]["path"] = "./one.txt"
        aliased_raw = (json.dumps(aliased, indent=2) + "\n").encode()
        manifest_path.write_bytes(aliased_raw)
        with self.assertRaisesRegex(PrePushError, "PREPUSH_MANIFEST_INVALID"):
            self.control._validate_manifest_file(
                replace(
                    lineage,
                    lease_manifest_sha256=hashlib.sha256(aliased_raw).hexdigest(),
                ),
                repository,
                head,
                manifest_path,
            )
        manifest_path.write_bytes(raw)

        (repository / "three.txt").write_text("third\n", encoding="utf-8")
        git("add", "three.txt")
        git("commit", "-m", "third path")
        with self.assertRaisesRegex(PrePushError, "PREPUSH_EXACT_DIFF_MISMATCH"):
            self.control._validate_manifest_file(
                lineage, repository, git("rev-parse", "HEAD"), manifest_path
            )

    def test_exhaustive_absent_path_manifest_preserves_frozen_inputs(self) -> None:
        repository = Path(self.temp.name) / "exhaustive-repo"
        repository.mkdir()

        def git(*args: str) -> str:
            return subprocess.run(
                ["git", "-C", str(repository), *args],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        git("init", "-b", "codex/314-ci-hardening")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "Test")
        frozen = repository / "frozen.txt"
        frozen.write_text("frozen input\n", encoding="utf-8")
        git("add", "frozen.txt")
        git("commit", "-m", "base")
        base = git("rev-parse", "HEAD")
        base_tree = git("rev-parse", f"{base}^{{tree}}")
        frozen_blob = git("rev-parse", f"{base}:frozen.txt")
        frozen_digest = hashlib.sha256(b"frozen input\n").hexdigest()
        for path in ("new-one.txt", "new-two.txt"):
            (repository / path).write_text(f"{path}\n", encoding="utf-8")
        git("add", "new-one.txt", "new-two.txt")
        git("commit", "-m", "exact new paths")
        head = git("rev-parse", "HEAD")
        manifest_data = {
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": 2,
            "base_sha": base,
            "base_tree": base_tree,
            "branch": "codex/314-ci-hardening",
            "worktree_path": str(repository),
            "no_additional_paths": True,
            "paths": [
                {"path": "new-two.txt", "state": "ABSENT"},
                {"path": "new-one.txt", "state": "ABSENT"},
            ],
            "frozen_inputs": [
                {
                    "path": "frozen.txt",
                    "git_blob_sha1": frozen_blob,
                    "content_sha256": frozen_digest,
                }
            ],
            "capacity": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "collision_evidence": {
                "observed_at": "2026-08-23T00:00:00Z",
                "source_snapshot_sha256": "8" * 64,
                "open_pr_count": 1,
                "open_prs": {
                    "316": {"head_sha": "9" * 40, "paths": ["other.txt"]}
                },
                "retained_or_active_issues_checked": [115, 303],
                "exact_path_intersection": [],
            },
            "historical_remote_evidence": {
                "closed_unmerged_pr": 305,
                "preserved_branch": "codex/87-old",
                "prohibited_from_reuse": True,
            },
        }

        def validate(data: dict) -> LeaseManifest:
            raw = (json.dumps(data, indent=2) + "\n").encode()
            manifest_path = self.control.store.path.parent / "exhaustive-lease.json"
            manifest_path.write_bytes(raw)
            lineage = replace(
                self.control._lineage(REPOSITORY, ISSUE),
                worktree_path=str(repository),
                base_sha=base,
                lease_manifest_sha256=hashlib.sha256(raw).hexdigest(),
            )
            return self.control._validate_manifest_file(
                lineage, repository, head, manifest_path
            )

        self.assertEqual(("new-one.txt", "new-two.txt"), validate(manifest_data).paths)

        corruptions = []
        for mutate in (
            lambda data: data["paths"][0].update(state="PRESENT"),
            lambda data: data["paths"][0].update(path="./new-two.txt"),
            lambda data: data.update(base_tree="0" * 40),
            lambda data: data.update(generation=True),
            lambda data: data.update(issue_number=float(ISSUE)),
            lambda data: data["frozen_inputs"][0].update(content_sha256="0" * 64),
            lambda data: data["frozen_inputs"][0].update(path="./frozen.txt"),
            lambda data: data["collision_evidence"]["open_prs"]["316"].update(
                paths=["new-one.txt"]
            ),
            lambda data: data["collision_evidence"].update(
                source_snapshot_sha256=int("1" * 64)
            ),
            lambda data: data["collision_evidence"]["open_prs"]["316"].update(
                head_sha=int("1" * 40)
            ),
            lambda data: data["collision_evidence"].update(
                exact_path_intersection=["new-one.txt"]
            ),
            lambda data: data["historical_remote_evidence"].update(
                preserved_branch="codex/314-ci-hardening"
            ),
            lambda data: data.update(unreviewed_extra=True),
        ):
            changed = json.loads(json.dumps(manifest_data))
            mutate(changed)
            corruptions.append(changed)
        for changed in corruptions:
            with self.assertRaises(PrePushError):
                validate(changed)

        duplicate_raw = (
            json.dumps(manifest_data, indent=2)
            .replace('  "generation": 2,', '  "generation": 2,\n  "generation": 2,', 1)
            .encode()
            + b"\n"
        )
        duplicate_path = self.control.store.path.parent / "duplicate-lease.json"
        duplicate_path.write_bytes(duplicate_raw)
        with self.assertRaisesRegex(PrePushError, "PREPUSH_MANIFEST_INVALID"):
            self.control._validate_manifest_file(
                replace(
                    self.control._lineage(REPOSITORY, ISSUE),
                    worktree_path=str(repository),
                    base_sha=base,
                    lease_manifest_sha256=hashlib.sha256(duplicate_raw).hexdigest(),
                ),
                repository,
                head,
                duplicate_path,
            )

    def test_legacy_canonical_text_manifest_is_digest_bound_and_exact(self) -> None:
        repository = Path(self.temp.name) / "legacy-repo"
        repository.mkdir()

        def git(*args: str) -> str:
            return subprocess.run(
                ["git", "-C", str(repository), *args],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        git("init", "-b", "codex/314-ci-hardening")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "Test")
        (repository / "existing.txt").write_text("base\n", encoding="utf-8")
        git("add", "existing.txt")
        git("commit", "-m", "base")
        base = git("rev-parse", "HEAD")
        existing_blob = git("rev-parse", f"{base}:existing.txt")
        (repository / "existing.txt").write_text("changed\n", encoding="utf-8")
        (repository / "new.txt").write_text("new\n", encoding="utf-8")
        git("add", "existing.txt", "new.txt")
        git("commit", "-m", "exact two")
        head = git("rev-parse", "HEAD")

        raw = f"existing.txt\t{existing_blob}\nnew.txt\tNEW\n".encode()
        manifest_path = self.control.store.path.parent / "legacy-lease.txt"
        manifest_path.write_bytes(raw)
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            worktree_path=str(repository),
            base_sha=base,
            lease_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        )
        validated = self.control._validate_manifest_file(
            lineage, repository, head, manifest_path
        )
        self.assertEqual(("existing.txt", "new.txt"), validated.paths)

        noncanonical = f"new.txt\tNEW\nexisting.txt\t{existing_blob}\n".encode()
        manifest_path.write_bytes(noncanonical)
        with self.assertRaisesRegex(PrePushError, "PREPUSH_MANIFEST_INVALID"):
            self.control._validate_manifest_file(
                replace(
                    lineage,
                    lease_manifest_sha256=hashlib.sha256(noncanonical).hexdigest(),
                ),
                repository,
                head,
                manifest_path,
            )

        aliased = f"./existing.txt\t{existing_blob}\nnew.txt\tNEW\n".encode()
        manifest_path.write_bytes(aliased)
        with self.assertRaisesRegex(PrePushError, "PREPUSH_MANIFEST_INVALID"):
            self.control._validate_manifest_file(
                replace(
                    lineage,
                    lease_manifest_sha256=hashlib.sha256(aliased).hexdigest(),
                ),
                repository,
                head,
                manifest_path,
            )

    def test_run_timeout_records_hold_before_any_push(self) -> None:
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        worktree = Path(self.temp.name) / "worktree"
        (worktree / "backend").mkdir(parents=True)
        manifest = LeaseManifest(
            content_sha256=LEASE,
            changed_paths_sha256=digest_json(["backend/example.py"]),
            paths=("backend/example.py",),
        )
        held = {"state": "HOLD", "last_error": "PREPUSH_GATE_TIMEOUT"}

        def git_after_gate(_worktree: Path, *args: str) -> str:
            return HEAD if args[-1] == "HEAD" else ""

        with (
            patch.object(self.control, "_lineage", return_value=lineage),
            patch.object(self.control, "_validate_worktree", return_value=(worktree, HEAD)),
            patch.object(self.control, "_validate_manifest_file", return_value=manifest),
            patch.object(
                self.control,
                "_lower_gate_commands",
                return_value=(("backend/check.sh", "backend", ("./check.sh",)),),
            ),
            patch.object(self.control, "_validate_gate_environment", return_value={}),
            patch.object(self.control, "_git", side_effect=git_after_gate),
            patch.object(self.control, "_record", return_value=held) as record,
            patch(
                "prepush_control.subprocess.run",
                side_effect=subprocess.TimeoutExpired("./check.sh", 1),
            ) as subprocess_run,
        ):
            with self.assertRaisesRegex(PrePushError, "PREPUSH_GATE_TIMEOUT"):
                self.control.run(
                    REPOSITORY,
                    ISSUE,
                    1,
                    self.control.store.path.parent / "lease.json",
                )
        self.assertEqual(
            "1", subprocess_run.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"]
        )
        self.assertEqual("PREPUSH_GATE_TIMEOUT", record.call_args.kwargs["error"])
        self.assertFalse(record.call_args.kwargs["cleanup_proven"])

    def test_run_post_gate_environment_drift_records_hold(self) -> None:
        binding = ExistingEnvironment(
            root="/home/ubuntu/.codex/twinfinity-issue314-prepush-venv-v3",
            rebuild_artifact_key="8" * 64,
            rebuild_artifact_content_sha256="9" * 64,
            freeze_sha256="7" * 64,
            package_count=2,
            gate_environment_provenance_sha256="6" * 64,
        )
        lineage = replace(
            self.control._lineage(REPOSITORY, ISSUE),
            existing_environment=binding,
            environment_root=binding.root,
        )
        worktree = Path(self.temp.name) / "worktree"
        (worktree / "backend").mkdir(parents=True)
        manifest = LeaseManifest(
            content_sha256=LEASE,
            changed_paths_sha256=digest_json(["backend/example.py"]),
            paths=("backend/example.py",),
        )
        held = {
            "state": "HOLD",
            "last_error": "PREPUSH_EXISTING_ENVIRONMENT_PACKAGE_DRIFT",
        }

        def git_after_gate(_worktree: Path, *args: str) -> str:
            return HEAD if args[-1] == "HEAD" else ""

        with (
            patch.object(self.control, "_lineage", return_value=lineage),
            patch.object(
                self.control, "_validate_worktree", return_value=(worktree, HEAD)
            ),
            patch.object(
                self.control, "_validate_manifest_file", return_value=manifest
            ),
            patch.object(
                self.control,
                "_lower_gate_commands",
                return_value=(("backend/check.sh", "backend", ("./check.sh",)),),
            ),
            patch.object(
                self.control,
                "_prepared_gate_environment",
                return_value={"PATH": "/usr/bin:/bin"},
            ),
            patch.object(
                self.control,
                "_validate_gate_environment",
                return_value={"python": f"{binding.root}/bin/python"},
            ),
            patch.object(
                self.control,
                "_validate_existing_environment",
                side_effect=[
                    {"environment_freeze_sha256": binding.freeze_sha256},
                    PrePushError("PREPUSH_EXISTING_ENVIRONMENT_PACKAGE_DRIFT"),
                ],
            ) as validate_existing,
            patch.object(self.control, "_git", side_effect=git_after_gate),
            patch.object(self.control, "_record", return_value=held) as record,
            patch(
                "prepush_control.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0),
            ),
        ):
            with self.assertRaisesRegex(
                PrePushError, "PREPUSH_EXISTING_ENVIRONMENT_PACKAGE_DRIFT"
            ):
                self.control.run(
                    REPOSITORY,
                    ISSUE,
                    30,
                    self.control.store.path.parent / "lease.json",
                )
        self.assertEqual(2, validate_existing.call_count)
        self.assertEqual(
            "PREPUSH_EXISTING_ENVIRONMENT_PACKAGE_DRIFT",
            record.call_args.kwargs["error"],
        )

    def test_record_downgrades_pass_when_final_receipt_revalidation_drifts(self) -> None:
        base_lineage = self.control._lineage(REPOSITORY, ISSUE)
        log_path = self.control.store.path.parent / "final-environment-rebuild.log"
        log_path.write_text("verified\n", encoding="utf-8")
        log_artifact = self.control.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": 2,
                    "path": str(log_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-23T00:00:06Z",
        )[0]
        receipt_path = self.control.store.path.parent / "final-environment-receipt.json"
        receipt_path.write_text(
            json.dumps(
                {
                    "kind": "TWINFINITY_ENVIRONMENT_REBUILD_RECEIPT_V1",
                    "state": "PASS",
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": 2,
                    "source_payload_sha256": base_lineage.source_payload_sha256,
                    "built_candidate_head_sha": HEAD,
                    "environment_root": "/home/ubuntu/.codex/twinfinity-issue314-prepush-venv-v3",
                    "requirements": [
                        {"path": "backend/requirements.txt", "sha256": "5" * 64}
                    ],
                    "freeze_sha256": "7" * 64,
                    "package_count": 2,
                    "gate_environment_provenance_sha256": "6" * 64,
                    "log_artifact_key": log_artifact["artifact_key"],
                    "log_artifact_content_sha256": log_artifact["content_sha256"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        receipt_artifact = self.control.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": 2,
                    "path": str(receipt_path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-23T00:00:06Z",
        )[0]
        binding = ExistingEnvironment(
            root="/home/ubuntu/.codex/twinfinity-issue314-prepush-venv-v3",
            rebuild_artifact_key=receipt_artifact["artifact_key"],
            rebuild_artifact_content_sha256=receipt_artifact["content_sha256"],
            freeze_sha256="7" * 64,
            package_count=2,
            gate_environment_provenance_sha256="6" * 64,
        )
        lineage = replace(
            base_lineage,
            existing_environment=binding,
            environment_root=binding.root,
        )
        receipt_path.write_text("drifted\n", encoding="utf-8")
        with patch.object(self.control, "_lineage", return_value=lineage):
            receipt = self.control._record(
                lineage=lineage,
                head_sha=HEAD,
                manifest=LeaseManifest(
                    content_sha256=LEASE,
                    changed_paths_sha256=digest_json(["backend/example.py"]),
                    paths=("backend/example.py",),
                ),
                lower_gate="[]",
                compose_gate="compose",
                lower_exit=0,
                compose_exit=0,
                run_id="p314-g2-final-drift",
                head_unchanged=True,
                cleanup_proven=True,
                started_at="2026-08-23T00:00:06Z",
                completed_at="2026-08-23T00:00:07Z",
                error=None,
                environment_provenance={"environment_freeze_sha256": "7" * 64},
            )
        self.assertEqual("HOLD", receipt["state"])
        self.assertEqual(
            "PREPUSH_EXISTING_ENVIRONMENT_FINAL_RECEIPT_DRIFT",
            receipt["last_error"],
        )

    def test_ui_evidence_lease_runs_ordinary_compose_without_pull_request(self) -> None:
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        worktree = Path(self.temp.name) / "worktree"
        (worktree / "backend" / "scripts").mkdir(parents=True)
        manifest = LeaseManifest(
            content_sha256=LEASE,
            changed_paths_sha256=digest_json(
                ["frontend/e2e/ui-evidence/example.spec.ts"]
            ),
            paths=("frontend/e2e/ui-evidence/example.spec.ts",),
        )
        passed = {"state": "PASS"}
        compose_calls: list[tuple[list[str], dict[str, str]]] = []

        def git_after_gate(_worktree: Path, *args: str) -> str:
            return HEAD if args[-1] == "HEAD" else ""

        def run_gate(argv, **kwargs):
            compose_calls.append((list(argv), kwargs["env"]))
            return subprocess.CompletedProcess(argv, 0)

        with (
            patch.object(self.control, "_lineage", return_value=lineage),
            patch.object(self.control, "_validate_worktree", return_value=(worktree, HEAD)),
            patch.object(self.control, "_validate_manifest_file", return_value=manifest),
            patch.object(self.control, "_lower_gate_commands", return_value=()),
            patch.object(self.control, "_validate_gate_environment", return_value={}),
            patch.object(self.control, "_git", side_effect=git_after_gate),
            patch.object(self.control, "_record", return_value=passed) as record,
            patch("prepush_control.subprocess.run", side_effect=run_gate),
        ):
            receipt = self.control.run(
                REPOSITORY,
                ISSUE,
                30,
                self.control.store.path.parent / "lease.json",
            )
        self.assertEqual(passed, receipt)
        self.assertEqual(1, len(compose_calls))
        self.assertEqual(
            [
                sys.executable,
                "backend/scripts/browser_e2e.py",
                "--run-id",
                f"p{ISSUE}-g{lineage.generation}-{HEAD[:12]}",
            ],
            compose_calls[0][0],
        )
        self.assertNotIn("--candidate-output", compose_calls[0][0])
        self.assertFalse(
            {
                "TWINFINITY_UI_EVIDENCE_REPOSITORY",
                "TWINFINITY_UI_EVIDENCE_PULL_REQUEST",
                "TWINFINITY_UI_EVIDENCE_LEAF_ISSUE",
                "TWINFINITY_UI_EVIDENCE_EVENT_BASE_SHA",
                "TWINFINITY_UI_EVIDENCE_EVENT_HEAD_SHA",
            }
            & compose_calls[0][1].keys()
        )
        self.assertEqual(
            "python3 backend/scripts/browser_e2e.py",
            record.call_args.kwargs["compose_gate"],
        )
        self.assertTrue(record.call_args.kwargs["cleanup_proven"])

    def test_ui_evidence_lease_failed_ordinary_compose_holds(self) -> None:
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        worktree = Path(self.temp.name) / "worktree"
        worktree.mkdir()
        manifest = LeaseManifest(
            content_sha256=LEASE,
            changed_paths_sha256=digest_json(
                ["frontend/e2e/ui-evidence/example.spec.ts"]
            ),
            paths=("frontend/e2e/ui-evidence/example.spec.ts",),
        )
        held = {"state": "HOLD", "last_error": "PREPUSH_COMPOSE_GATE_FAILED"}

        def git_after_gate(_worktree: Path, *args: str) -> str:
            return HEAD if args[-1] == "HEAD" else ""

        with (
            patch.object(self.control, "_lineage", return_value=lineage),
            patch.object(self.control, "_validate_worktree", return_value=(worktree, HEAD)),
            patch.object(self.control, "_validate_manifest_file", return_value=manifest),
            patch.object(self.control, "_lower_gate_commands", return_value=()),
            patch.object(self.control, "_validate_gate_environment", return_value={}),
            patch.object(self.control, "_git", side_effect=git_after_gate),
            patch.object(self.control, "_record", return_value=held) as record,
            patch(
                "prepush_control.subprocess.run",
                return_value=subprocess.CompletedProcess([], 1),
            ) as subprocess_run,
        ):
            with self.assertRaisesRegex(
                PrePushError, "PREPUSH_COMPOSE_GATE_FAILED"
            ):
                self.control.run(
                    REPOSITORY,
                    ISSUE,
                    30,
                    self.control.store.path.parent / "lease.json",
                )
        self.assertNotIn("--candidate-output", subprocess_run.call_args.args[0])
        self.assertEqual(
            "PREPUSH_COMPOSE_GATE_FAILED", record.call_args.kwargs["error"]
        )
        self.assertFalse(record.call_args.kwargs["cleanup_proven"])

    def test_environment_discovery_error_records_hold_before_any_gate(self) -> None:
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        worktree = Path(self.temp.name) / "worktree"
        (worktree / "backend").mkdir(parents=True)
        manifest = LeaseManifest(
            content_sha256=LEASE,
            changed_paths_sha256=digest_json(["backend/example.py"]),
            paths=("backend/example.py",),
        )
        held = {"state": "HOLD", "last_error": "PREPUSH_GATE_EXEC_FAILED"}

        def git_after_gate(_worktree: Path, *args: str) -> str:
            return HEAD if args[-1] == "HEAD" else ""

        with (
            patch.object(self.control, "_lineage", return_value=lineage),
            patch.object(self.control, "_validate_worktree", return_value=(worktree, HEAD)),
            patch.object(self.control, "_validate_manifest_file", return_value=manifest),
            patch.object(
                self.control,
                "_lower_gate_commands",
                return_value=(("backend/check.sh", "backend", ("./check.sh",)),),
            ),
            patch.object(
                self.control,
                "_prepared_gate_environment",
                side_effect=OSError("filesystem race"),
            ),
            patch.object(self.control, "_git", side_effect=git_after_gate),
            patch.object(self.control, "_record", return_value=held) as record,
            patch("prepush_control.subprocess.run") as subprocess_run,
        ):
            with self.assertRaisesRegex(PrePushError, "PREPUSH_GATE_EXEC_FAILED"):
                self.control.run(
                    REPOSITORY,
                    ISSUE,
                    1,
                    self.control.store.path.parent / "lease.json",
                )
        subprocess_run.assert_not_called()
        self.assertEqual(
            "PREPUSH_GATE_EXEC_FAILED", record.call_args.kwargs["error"]
        )

    def test_reserved_publication_fences_lineage_until_finalization(self) -> None:
        receipt = self.record()
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        original = self.control.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?",
            (self.message,),
        ).fetchone()
        pending_admission = self.control.store.enqueue_message(
            idempotency_key="issue-314-generation-2-sre-race",
            recipient_session_id=SESSION,
            topic="sre.admission",
            payload=json.loads(original["payload_json"]),
            now="2026-08-23T00:00:08Z",
        )
        publication, created = self.control._reserve_publication(
            lineage, receipt, "8" * 64
        )
        self.assertTrue(created)
        self.assertEqual("RESERVED", publication["state"])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "PREPUSH_PUBLICATION_RESERVED"):
            self.control.connection.execute(
                "UPDATE coordination_items SET updated_at=? WHERE repository=? AND issue_number=?",
                ("2026-08-23T00:01:00Z", REPOSITORY, ISSUE),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "PREPUSH_PUBLICATION_RESERVED"):
            self.control.connection.execute(
                "UPDATE coordination_messages SET state='CLAIMED',claimed_by=?,updated_at=? "
                "WHERE id=? AND state='PREPARED'",
                (SESSION, "2026-08-23T00:01:00Z", pending_admission),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "PREPUSH_PUBLICATION_RESERVED"):
            self.control.store.enqueue_message(
                idempotency_key="issue-314-generation-2-sre-race-after-reserve",
                recipient_session_id=SESSION,
                topic="sre.admission",
                payload=json.loads(original["payload_json"]),
                now="2026-08-23T00:01:00Z",
            )
        completed = self.control._finish_publication(
            int(publication["id"]), lineage, "COMPLETE", None
        )
        self.assertEqual("COMPLETE", completed["state"])
        self.control.connection.execute(
            "UPDATE coordination_items SET updated_at=? WHERE repository=? AND issue_number=?",
            ("2026-08-23T00:01:01Z", REPOSITORY, ISSUE),
        )

    def test_bound_remote_url_is_used_after_origin_alias_changes(self) -> None:
        receipt = self.record()
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        worktree = Path(self.temp.name) / "worktree"
        canonical_url = "https://github.com/twinfinityai/twinfinityapp.git"
        calls: list[list[str]] = []

        def run_git(argv: list[str], **kwargs):
            calls.append(argv)
            if "ls-remote" in argv:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    stdout=f"{HEAD}\trefs/heads/{lineage.branch}\n",
                    stderr="",
                )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with (
            patch.object(self.control, "_lineage", return_value=lineage),
            patch.object(self.control, "_validate_worktree", return_value=(worktree, HEAD)),
            patch.object(self.control, "_canonical_remote_url", return_value=canonical_url),
            patch.object(self.control, "assert_push_eligible", return_value=receipt),
            patch("prepush_control.subprocess.run", side_effect=run_git),
        ):
            result = self.control.guarded_push(REPOSITORY, ISSUE)

        self.assertEqual("PUSHED", result["state"])
        publication_calls = [
            call for call in calls if "push" in call or "ls-remote" in call
        ]
        self.assertEqual(2, len(publication_calls))
        for call in publication_calls:
            self.assertIn(canonical_url, call)
            self.assertNotIn("origin", call)

    def test_repository_hook_requires_exact_reserved_publication(self) -> None:
        receipt = self.record()
        lineage = self.control._lineage(REPOSITORY, ISSUE)
        remote_url = "https://github.com/twinfinityai/twinfinityapp.git"
        publication, created = self.control._reserve_publication(
            lineage,
            receipt,
            hashlib.sha256(remote_url.encode()).hexdigest(),
        )
        self.assertTrue(created)
        environment = {
            "TWINFINITY_PUBLICATION_ID": str(publication["id"]),
            "TWINFINITY_PUBLICATION_ISSUE": str(ISSUE),
            "TWINFINITY_PUBLICATION_GENERATION": "2",
            "TWINFINITY_PUBLICATION_HEAD": HEAD,
        }
        result = self.control.validate_git_hook(
            remote_url,
            f"refs/heads/codex/314-ci-hardening {HEAD} refs/heads/codex/314-ci-hardening {'0' * 40}\n",
            environment,
        )
        self.assertEqual("HOOK_ACCEPTED", result["state"])

        with self.assertRaisesRegex(PrePushError, "PREPUSH_HOOK_RESERVATION_ABSENT"):
            self.control.validate_git_hook(remote_url, "", {})
        with self.assertRaisesRegex(PrePushError, "PREPUSH_HOOK_UPDATE_DRIFT"):
            self.control.validate_git_hook(
                remote_url,
                f"refs/heads/codex/314-ci-hardening {'c' * 40} refs/heads/codex/314-ci-hardening {'0' * 40}\n",
                environment,
            )

    def test_exact_head_pass_is_push_eligible(self) -> None:
        receipt = self.record()
        eligible = self.control.assert_push_eligible(
            REPOSITORY, ISSUE, "codex/314-ci-hardening", HEAD
        )
        self.assertEqual(receipt["id"], eligible["id"])
        self.assertEqual(
            digest_json(
                {
                    "python": "/home/ubuntu/.codex/twinfinity-issue314-prepush-venv/bin/python"
                }
            ),
            eligible["environment_provenance_sha256"],
        )

    def test_item_version_and_capacity_drift_invalidate_existing_pass(self) -> None:
        self.record()
        self.control.connection.execute(
            "UPDATE coordination_items SET version=version+1 WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        )
        with self.assertRaisesRegex(
            PrePushError, "PREPUSH_COMPLETED_ADMISSION_ABSENT"
        ):
            self.control.assert_push_eligible(
                REPOSITORY, ISSUE, "codex/314-ci-hardening", HEAD
            )
        self.control.connection.execute(
            "UPDATE coordination_items SET version=version-1, sre_units=sre_units+1 WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        )
        with self.assertRaisesRegex(
            PrePushError, "PREPUSH_COMPLETED_ADMISSION_ABSENT"
        ):
            self.control.assert_push_eligible(
                REPOSITORY, ISSUE, "codex/314-ci-hardening", HEAD
            )

    def test_missing_wrong_head_and_newer_hold_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrePushError, "PREPUSH_EXACT_HEAD_GATE_ABSENT"):
            self.control.assert_push_eligible(
                REPOSITORY, ISSUE, "codex/314-ci-hardening", HEAD
            )
        self.record()
        with self.assertRaisesRegex(PrePushError, "PREPUSH_EXACT_HEAD_GATE_ABSENT"):
            self.control.assert_push_eligible(
                REPOSITORY, ISSUE, "codex/314-ci-hardening", "c" * 40
            )
        self.record(state="HOLD")
        with self.assertRaisesRegex(PrePushError, "PREPUSH_EXACT_HEAD_GATE_ABSENT"):
            self.control.assert_push_eligible(
                REPOSITORY, ISSUE, "codex/314-ci-hardening", HEAD
            )

    def test_source_drift_invalidates_existing_pass(self) -> None:
        self.record()
        self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload={"number": ISSUE, "updated_at": "2026-08-23T01:00:00Z"},
            source_updated_at="2026-08-23T01:00:00Z",
            fetched_at="2026-08-23T01:00:01Z",
        )
        with self.assertRaisesRegex(PrePushError, "PREPUSH_SOURCE_DRIFT"):
            self.control.assert_push_eligible(
                REPOSITORY, ISSUE, "codex/314-ci-hardening", HEAD
            )


if __name__ == "__main__":
    unittest.main()
