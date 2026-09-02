from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
import sys

sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationError, digest_json  # noqa: E402
from approval_guard import (  # noqa: E402
    ApprovalGuardError,
    hosted_execution_scope_sha256,
    require_effective_approval,
)
from approval_ledger import (  # noqa: E402
    claim_decision,
    create_review_batch,
    record_decision,
    revoke_decision,
    submit_proposal,
)
from hosted_operation_control import (  # noqa: E402
    HostedOperationControl,
    RUNNER_NOT_ACQUIRED_ANNOTATION,
    run_supervisor,
)
from actions_rerun_scope import build_scope  # noqa: E402
from hosted_operation_clearance import clear_actions_rerun  # noqa: E402
from coordination_store import CoordinationStore  # noqa: E402
from executor_registry import load_registry_config  # noqa: E402
from executor_registry import RegistryError  # noqa: E402
from role_executor_transport import (  # noqa: E402
    ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE,
    RoleExecutorTransportAttestation,
)
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
SRE_SESSION = "role.sre.v4"
PLANNER_SESSION = "role.planner.v2"
AUTHORITY_BODY = "Exact bounded settings authority"
AUTHORITY_SHA = hashlib.sha256(AUTHORITY_BODY.encode()).hexdigest()


class HostedOperationControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name) / "coordinator"
        directory.mkdir(mode=0o700)
        self.database = directory / "state.sqlite3"
        self.control = HostedOperationControl(self.database)
        apply_reviewed_current_endpoint_catalog(
            self.control.connection,
            ROOT,
            operation_key="hosted-operation-control-tests",
        )
        self.approval_guard = patch.object(
            HostedOperationControl, "_validate_approval_guard", return_value=None
        )
        self.approval_guard_mock = self.approval_guard.start()
        self.source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            payload={"number": 143, "title": "Staging", "updated_at": "2026-08-23T10:00:00Z"},
            source_updated_at="2026-08-23T10:00:00Z",
            fetched_at="2026-08-23T10:00:01Z",
        )

    def tearDown(self) -> None:
        self.approval_guard.stop()
        self.control.close()
        self.temp.cleanup()

    @staticmethod
    def successful_transport(preflight):
        return RoleExecutorTransportAttestation.pass_for(
            preflight, user_manager_identity_sha256="a" * 64
        )

    @staticmethod
    def non_notice_database_state(connection) -> dict[str, object]:
        excluded = {"coordination_events", "coordination_messages", "sqlite_sequence"}
        tables = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            if str(row[0]) not in excluded
        ]
        return {
            table: sorted(
                (tuple(row) for row in connection.execute(f'SELECT * FROM "{table}"')),
                key=repr,
            )
            for table in tables
        }

    def seed_transport_notice_source(self, body: str) -> object:
        return self.control.store.ingest_snapshot(
            repository="jayendusharma/twinfinity-harness",
            object_kind="issue",
            object_number=149,
            payload={
                "number": 149,
                "state": "open",
                "title": "Transport preflight",
                "body": body,
                "updated_at": "2026-09-02T04:23:51Z",
                "html_url": "https://github.com/jayendusharma/twinfinity-harness/issues/149",
            },
            source_updated_at="2026-09-02T04:23:51Z",
            fetched_at="2026-09-02T04:24:00Z",
        )

    def migrate_registry(self, operation_key: str) -> list[dict[str, str]]:
        root = Path(__file__).resolve().parents[1]
        config = load_registry_config(
            root / "tests" / "fixtures" / "twinfinity-executor-registry-v4.toml"
        )
        aliases, alias_sha = load_legacy_alias_fixture(
            root / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.control.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_plan(
            self.control.connection,
            plan=plan,
            operation_key=operation_key,
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T10:00:00Z",
        )
        return aliases

    def seed_current_sre_endpoint(self) -> None:
        """Assert the shared fixture installed the reviewed current SRE endpoint."""

        row = self.control.connection.execute(
            "SELECT endpoint_id FROM executor_role_endpoint_current WHERE role='sre'"
        ).fetchone()
        self.assertEqual(SRE_SESSION, row["endpoint_id"])

    def seed_active_sre_attempt(self, target_kind: str, target_key: str) -> None:
        with self.control.store.transaction():
            self.control.connection.execute(
                """
                INSERT INTO executor_attempts(
                    attempt_id, role, endpoint_id, instance_id, token_sha256,
                    target_kind, target_key, state, process_id, exit_code,
                    heartbeat_at, version, created_at, updated_at, last_error
                ) VALUES (?, 'sre', ?, ?, ?, ?, ?, 'RUNNING',
                          1234, NULL, ?, 1, ?, ?, NULL)
                """,
                (
                    f"attempt-{target_kind}-{target_key}",
                    SRE_SESSION,
                    f"instance-{target_kind}-{target_key}",
                    "b" * 64,
                    target_kind,
                    target_key,
                    "2026-08-23T10:00:03Z",
                    "2026-08-23T10:00:03Z",
                    "2026-08-23T10:00:03Z",
                ),
            )

    @staticmethod
    def authority_comment(repository: str, issue_number: int, comment_id: int):
        return {
            "id": comment_id,
            "issue_url": f"https://api.github.com/repos/{repository}/issues/{issue_number}",
            "body": AUTHORITY_BODY,
        }

    def transaction(self, *, blocked_by: int | None = None) -> dict[str, object]:
        return {
            "idempotency_key": "issue143-ruleset-20717667-v1",
            "repository": REPOSITORY,
            "issue_number": 143,
            "source_payload_sha256": self.source.payload_sha256,
            "provider": "github",
            "target_kind": "github_ruleset",
            "target_key": "20717667",
            "operation_kind": "UPDATE_SETTINGS",
            "authority_comment_id": 1234,
            "authority_body_sha256": AUTHORITY_SHA,
            "recipient_session_id": SRE_SESSION,
            "sre_units": 1,
            "blocked_by_issue_number": blocked_by,
            "scope": {
                "target": {"repository": REPOSITORY, "ruleset_id": 20717667},
                "expected_state": {
                    "enforcement": "evaluate",
                    "include": [],
                    "required_status_check": None,
                },
                "desired_state": {
                    "enforcement": "active",
                    "include": ["refs/heads/main"],
                    "required_status_check": "ci-gate",
                    "required_approving_review_count": 1,
                },
                "exclusions": ["No repository content change"],
                "stop_conditions": ["Source or target drift"],
            },
        }

    def gcp_inventory_transaction(
        self, idempotency_key: str, projects: list[str]
    ) -> dict[str, object]:
        return {
            "idempotency_key": idempotency_key,
            "repository": REPOSITORY,
            "issue_number": 143,
            "source_payload_sha256": self.source.payload_sha256,
            "provider": "google_cloud",
            "target_kind": "gcp_project_inventory",
            "target_key": ",".join(projects),
            "operation_kind": "READ_METADATA",
            "authority_comment_id": 1234,
            "authority_body_sha256": AUTHORITY_SHA,
            "recipient_session_id": SRE_SESSION,
            "sre_units": 0,
            "blocked_by_issue_number": None,
            "scope": {
                "target": {"project_ids": projects},
                "expected_state": {"authenticated_account_sha256": "b" * 64},
                "desired_state": {
                    "metadata_categories": ["cloud_run", "iam_bindings"],
                    "read_only": True,
                },
                "exclusions": ["No payloads, logs, or mutations"],
                "stop_conditions": ["Identity or project inventory drift"],
            },
        }

    def test_post_migration_hosted_prepare_clearance_and_claim_reject_alias(self) -> None:
        aliases = self.migrate_registry("hosted-alias-rejection")
        legacy_sre = next(
            entry["alias"] for entry in aliases if entry["role"] == "sre"
        )
        transaction = self.transaction()
        transaction["recipient_session_id"] = legacy_sre
        with (
            patch.object(
                HostedOperationControl,
                "_fetch_authority_comment",
                side_effect=self.authority_comment,
            ),
            self.assertRaisesRegex(
                CoordinationError, "CURRENT_ROLE_ENDPOINT_REQUIRED"
            ),
        ):
            self.control.prepare(transaction, "2026-08-24T10:00:01Z")
        with self.assertRaisesRegex(
            CoordinationError, "HOSTED_RECIPIENT_MISMATCH"
        ):
            self.control.claim(1, legacy_sre, "2026-08-24T10:00:02Z")
        with self.assertRaisesRegex(
            CoordinationError, "HOSTED_CLEARANCE_RECIPIENT_INVALID"
        ):
            clear_actions_rerun(
                self.control,
                request={},
                proposal_sha256="0" * 64,
                decision_sha256="1" * 64,
                authority_comment_id=1,
                idempotency_key="legacy-clearance",
                recipient_session_id=legacy_sre,
                github=object(),
            )

    def actions_rerun_transaction(self) -> dict[str, object]:
        return {
            "idempotency_key": "issue58-pr322-run32733505535-attempt1-rerun-v1",
            "repository": REPOSITORY,
            "issue_number": 143,
            "source_payload_sha256": self.source.payload_sha256,
            "provider": "github",
            "target_kind": "github_actions_rerun",
            "target_key": f"{REPOSITORY}:pr:322:run:32733505535:attempt:1",
            "operation_kind": "RERUN_WORKFLOW",
            "authority_comment_id": 1234,
            "authority_body_sha256": AUTHORITY_SHA,
            "recipient_session_id": SRE_SESSION,
            "sre_units": 1,
            "blocked_by_issue_number": None,
            "scope": {
                "target": {
                    "repository": REPOSITORY,
                    "pull_request_number": 322,
                    "workflow_path": ".github/workflows/ci.yml",
                    "workflow_run_id": 32733505535,
                    "run_attempt": 1,
                    "check_suite_id": 99112233,
                    "head_sha": "8" * 40,
                    "base_sha": "6" * 40,
                    "workflow_sha": "7" * 40,
                },
                "expected_state": {
                    "pull_request_state": "OPEN",
                    "draft": False,
                    "ready_generation": 1,
                    "classifier_conclusion": "cancelled",
                    "classifier_runner_id": 0,
                    "classifier_runner_name_present": False,
                    "classifier_step_count": 0,
                    "log_count": 0,
                    "annotation_count": 0,
                    "artifact_count": 0,
                    "substantive_jobs": {
                        "backend-check": "skipped",
                        "browser-e2e": "skipped",
                        "frontend-check": "skipped",
                    },
                    "cancellation_reason": "HOSTED_RUNNER_NOT_ACQUIRED",
                    "cancellation_ambiguous": False,
                    "local_gate_id": 1,
                    "local_gate_evidence_sha256": "a" * 64,
                    "local_gate_receipt_sha256": "b" * 64,
                    "guarded_publication_id": 1,
                    "guarded_publication_receipt_sha256": "c" * 64,
                    "provider_restoration_operation_id": 1,
                    "provider_restoration_target_key": (
                        "twinfinityai:c1976a50-4e93-47bd-9a2a-e8c4802255de"
                    ),
                    "provider_restoration_receipt_sha256": "d" * 64,
                    "failed_run_completed_at": "2026-08-23T09:12:30Z",
                    "provider_restoration_minimum_amount": 40,
                },
                "desired_state": {
                    "endpoint": "RERUN_SAME_WORKFLOW_RUN",
                    "next_run_attempt": 2,
                    "preserve_workflow_run_id": True,
                    "preserve_check_suite_id": True,
                    "rerun_once": True,
                    "repeat_local_gate": False,
                },
                "exclusions": [
                    "No workflow dispatch, Ready toggle, commit, push, PR edit, or check recreation"
                ],
                "stop_conditions": [
                    "Any source, workflow, PR, evidence, provider, or run-lineage drift"
                ],
            },
        }

    def actions_rerun_request(self) -> dict[str, object]:
        return {
            "repository": REPOSITORY,
            "issue_number": 143,
            "pull_request_number": 322,
            "workflow_run_id": 32733505535,
            "ready_generation": 1,
            "local_gate_id": 1,
            "guarded_publication_id": 1,
            "provider_restoration_operation_id": 1,
            "provider_restoration_minimum_amount": 40,
            "exclusions": ["No unrelated mutation"],
            "stop_conditions": ["Any lineage drift"],
        }

    @staticmethod
    def actions_rerun_github(annotations=None):
        class FakeGitHub:
            def __init__(self, supplied_annotations):
                self.annotations = supplied_annotations

            def json(self, endpoint):
                if endpoint.endswith("/pulls/322"):
                    return {
                        "number": 322,
                        "state": "open",
                        "draft": False,
                        "head": {"sha": "8" * 40},
                        "base": {"sha": "6" * 40},
                    }
                if endpoint.endswith("/actions/runs/32733505535"):
                    return {
                        "id": 32733505535,
                        "run_attempt": 1,
                        "status": "completed",
                        "conclusion": "failure",
                        "event": "pull_request",
                        "head_sha": "8" * 40,
                        "path": ".github/workflows/ci.yml",
                        "check_suite_id": 99112233,
                        "pull_requests": [{"number": 322}],
                        "updated_at": "2026-08-23T09:12:30Z",
                    }
                if "/jobs?" in endpoint:
                    return {
                        "jobs": [
                            {
                                "id": 7000,
                                "name": "classify-ci",
                                "conclusion": "cancelled",
                                "runner_id": 0,
                                "runner_name": "",
                                "steps": [],
                            },
                            {"name": "backend-check", "conclusion": "skipped"},
                            {"name": "browser-e2e", "conclusion": "skipped"},
                            {"name": "frontend-check", "conclusion": "skipped"},
                            {"name": "ci-gate", "conclusion": "failure"},
                        ]
                    }
                if "/annotations?" in endpoint:
                    return self.annotations
                if "/artifacts?" in endpoint:
                    return {"total_count": 0, "artifacts": []}
                if "/contents/" in endpoint:
                    return {"sha": "7" * 40}
                raise AssertionError(endpoint)

            def log_count(self, repository, job_id):
                return 0

        return FakeGitHub(
            [RUNNER_NOT_ACQUIRED_ANNOTATION] if annotations is None else annotations
        )

    def seed_actions_rerun_evidence(
        self, *, capacity_restored: bool = True
    ) -> dict[str, object]:
        with self.control.store.transaction():
            admission_message_id = self.control.connection.execute(
                """
                INSERT INTO coordination_messages(
                    idempotency_key, recipient_session_id, topic, payload_sha256,
                    payload_json, state, claimed_by, created_at, updated_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "issue143-test-admission", "role.development.v3",
                    "development.admission", "2" * 64, "{}", "COMPLETE",
                    "role.development.v3",
                    "2026-08-23T08:59:00Z", "2026-08-23T08:59:30Z", None,
                ),
            ).lastrowid
            gate_id = self.control.connection.execute(
                """
                INSERT INTO coordination_pre_push_gates(
                    repository, issue_number, generation, accountable_session_id,
                    source_payload_sha256, lease_manifest_sha256,
                    admission_message_id, admission_payload_sha256, branch,
                    worktree_path, base_sha, head_sha, changed_paths_sha256,
                    changed_path_count, lower_gate, lower_gate_exit_code,
                    compose_gate, compose_gate_exit_code, compose_run_id,
                    head_unchanged, cleanup_proven, state, evidence_sha256,
                    environment_provenance_sha256, started_at, completed_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    REPOSITORY, 143, 1, "role.development.v3",
                    self.source.payload_sha256, "1" * 64, admission_message_id, "2" * 64,
                    "codex/143-test", "/tmp/issue-143", "6" * 40, "8" * 40,
                    "3" * 64, 1, "focused", 0, "compose", 0, "owned-run", 1, 1,
                    "PASS", "4" * 64, "5" * 64,
                    "2026-08-23T09:00:00Z", "2026-08-23T09:10:00Z", None,
                ),
            ).lastrowid
            gate = self.control.connection.execute(
                "SELECT * FROM coordination_pre_push_gates WHERE id=?", (gate_id,)
            ).fetchone()
            publication_id = self.control.connection.execute(
                """
                INSERT INTO coordination_pre_push_publications(
                    gate_id, repository, issue_number, generation,
                    accountable_session_id, source_payload_sha256,
                    lease_manifest_sha256, admission_message_id, branch, head_sha,
                    remote_name, remote_url_sha256, state, created_at, updated_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    gate_id, REPOSITORY, 143, 1,
                    "role.development.v3",
                    self.source.payload_sha256, "1" * 64, admission_message_id,
                    "codex/143-test",
                    "8" * 40, "origin", "6" * 64, "COMPLETE",
                    "2026-08-23T09:11:00Z", "2026-08-23T09:12:00Z", None,
                ),
            ).lastrowid
            publication = self.control.connection.execute(
                "SELECT * FROM coordination_pre_push_publications WHERE id=?",
                (publication_id,),
            ).fetchone()

        budget = self.transaction()
        budget.update(
            {
                "idempotency_key": "issue143-actions-budget-restoration-v1",
                "target_kind": "github_billing_budget",
                "target_key": "twinfinityai:c1976a50-4e93-47bd-9a2a-e8c4802255de",
                "scope": {
                    "target": {
                        "organization": "twinfinityai",
                        "budget_id": "c1976a50-4e93-47bd-9a2a-e8c4802255de",
                    },
                    "expected_state": {
                        "amount": 30,
                        "prevent_further_usage": True,
                        "alert_config_sha256": "7" * 64,
                    },
                    "desired_state": {
                        "amount": 40,
                        "prevent_further_usage": True,
                        "preserve_alerting": True,
                    },
                    "exclusions": ["No other billing or repository mutation"],
                    "stop_conditions": ["Budget or alerting drift"],
                },
            }
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            restoration = self.control.prepare(budget, "2026-08-23T09:13:00Z")
            restoration = self.control.claim(
                restoration["id"], SRE_SESSION, "2026-08-23T09:14:00Z"
            )
        outbox_id = self.control.store.enqueue_comment(
            idempotency_key="issue143-actions-budget-restoration-receipt-v1",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            expected_source_sha256=self.source.payload_sha256,
            body=self.receipt_body(
                restoration,
                overrides={
                    "result": {
                        "amount": 40,
                        "prevent_further_usage": True,
                        "alert_config_sha256": "7" * 64,
                        "capacity_restored": capacity_restored,
                    }
                },
            ),
            now="2026-08-23T09:15:00Z",
        )
        self.control.store.reserve_outbox(outbox_id, "2026-08-23T09:16:00Z")
        self.control.store.complete_outbox(
            outbox_id, "comment:1900", "2026-08-23T09:17:00Z"
        )
        restoration = self.control.complete(
            restoration["id"], SRE_SESSION, outbox_id, "2026-08-23T09:18:00Z"
        )
        return {
            "local_gate_id": gate_id,
            "local_gate_evidence_sha256": gate["evidence_sha256"],
            "local_gate_receipt_sha256": digest_json(dict(gate)),
            "guarded_publication_id": publication_id,
            "guarded_publication_receipt_sha256": digest_json(dict(publication)),
            "provider_restoration_operation_id": restoration["id"],
            "provider_restoration_target_key": restoration["target_key"],
            "provider_restoration_receipt_sha256": restoration["receipt_payload_sha256"],
            "failed_run_completed_at": "2026-08-23T09:12:30Z",
            "provider_restoration_minimum_amount": 40,
        }

    @staticmethod
    def receipt_body(
        row: dict[str, object],
        outcome: str = "SUCCESS",
        overrides: dict[str, object] | None = None,
    ) -> str:
        verification = {"SUCCESS": "PASS", "FAILURE": "FAIL", "PARTIAL": "PARTIAL"}[outcome]
        receipt = {
            "schema": "twinfinity.hosted-operation-receipt.v1",
            "outcome": outcome,
            "operation_id": row["id"],
            "idempotency_key_sha256": hashlib.sha256(
                str(row["idempotency_key"]).encode()
            ).hexdigest(),
            "provider": row["provider"],
            "target_kind": row["target_kind"],
            "target_key": row["target_key"],
            "operation_kind": row["operation_kind"],
            "scope_sha256": row["scope_sha256"],
            "verification": verification,
            "summary": f"Hosted operation ended with {outcome.lower()}.",
        }
        if overrides:
            receipt.update(overrides)
        payload = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        return f"Settings receipt\n\n<!-- twinfinity-hosted-operation-receipt:{payload} -->"

    def seed_clearance_approval(self):
        evidence = self.seed_actions_rerun_evidence()
        request = self.actions_rerun_request()
        request.update(
            {
                "local_gate_id": evidence["local_gate_id"],
                "guarded_publication_id": evidence["guarded_publication_id"],
                "provider_restoration_operation_id": evidence[
                    "provider_restoration_operation_id"
                ],
            }
        )
        github = self.actions_rerun_github()
        built = build_scope(self.control, request, github)
        packet = {
            "schema": "twinfinity.approval-proposal.v1",
            "decision_key": "issue-143:ruleset-update",
            "repository": REPOSITORY,
            "owning_issue": 143,
            "source_snapshot_sha256": self.source.payload_sha256,
            "execution_scope_sha256": built["hosted_execution_scope_sha256"],
            "requester_session_id": SRE_SESSION,
            "recipient_session_id": SRE_SESSION,
            "workstream": "SRE",
            "boundary": "HOSTED_PROVIDER",
            "priority": "P0",
            "urgency": "ACTIVE_BLOCKER",
            "summary": "Retry one infrastructure-only workflow run.",
            "question": "Should the exact same-run retry proceed?",
            "requested_action": "Retry only the exact run once.",
            "target": "PR 322 workflow run 32733505535",
            "affected_issues": [143],
            "blocked_mutation": "Natural CI is blocked.",
            "immediate_beneficiary": "Twin Studio operators",
            "evidence": ["The canonical builder validated the exact scope."],
            "risk": "A repeated or drifted retry wastes CI capacity.",
            "drift_guards": ["All scope evidence must remain exact."],
            "prohibited_side_effects": ["No source or workflow mutation."],
            "options": [
                {
                    "id": "RETRY",
                    "label": "Retry",
                    "effect": "Retry once.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "HOLD",
                    "label": "Hold",
                    "effect": "Do not retry.",
                    "machine_outcome": "REJECT",
                },
            ],
            "recommendation": "RETRY",
            "expires_at": None,
        }
        proposal = submit_proposal(
            self.control.store, packet, "2026-08-23T10:00:02Z"
        )["proposal_sha256"]
        batch = create_review_batch(
            self.control.store, REPOSITORY, "2026-08-23T10:00:03Z"
        )
        answer_map = {
            "schema": "twinfinity.approval-batch-answer-map.v1",
            "batch_sha256": batch["batch_sha256"],
            "answers": [
                {
                    "proposal_sha256": proposal,
                    "selected_option_id": "RETRY",
                }
            ],
        }
        decision = record_decision(
            self.control.store,
            proposal_sha256=proposal,
            batch_sha256=batch["batch_sha256"],
            batch_answer_map=answer_map,
            decision="APPROVE",
            selected_option_id="RETRY",
            revisit_trigger=None,
            decision_note="Approved for one exact retry.",
            user_input_sha256=digest_json(answer_map),
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:atomic-clearance-approve",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-23T10:00:03Z",
        )
        self.control.store.reserve_outbox(
            decision["owner_outbox_id"], "2026-08-23T10:00:04Z"
        )
        self.control.store.complete_outbox(
            decision["owner_outbox_id"], "comment:1234", "2026-08-23T10:00:05Z"
        )
        return request, github, built, proposal, decision

    def rerun_transaction_from_scope(self, built, idempotency_key):
        return {
            "idempotency_key": idempotency_key,
            "repository": built["repository"],
            "issue_number": built["issue_number"],
            "source_payload_sha256": built["source_payload_sha256"],
            "provider": built["provider"],
            "target_kind": built["target_kind"],
            "target_key": built["target_key"],
            "operation_kind": built["operation_kind"],
            "authority_comment_id": 1234,
            "authority_body_sha256": AUTHORITY_SHA,
            "recipient_session_id": SRE_SESSION,
            "sre_units": 1,
            "blocked_by_issue_number": None,
            "scope": built["scope"],
        }

    def test_waiting_promotes_claims_and_requires_bound_receipt(self) -> None:
        blocker_source = self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=314,
            payload={"number": 314, "title": "CI", "updated_at": "2026-08-23T10:00:00Z"},
            source_updated_at="2026-08-23T10:00:00Z",
            fetched_at="2026-08-23T10:00:01Z",
        )
        self.control.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=314,
            status="ACTIVE_FENCED",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=SRE_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=0,
            shared_units=0,
            sre_units=1,
            expected_source_sha256=blocker_source.payload_sha256,
            expected_version=0,
            now="2026-08-23T10:00:02Z",
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            transaction = self.transaction(blocked_by=314)
            row = self.control.prepare(transaction, "2026-08-23T10:00:03Z")
            self.approval_guard_mock.assert_called_with(
                repository=REPOSITORY,
                issue_number=143,
                operation_kind="UPDATE_SETTINGS",
                execution_scope_sha256=hosted_execution_scope_sha256(
                    provider="github",
                    target_kind="github_ruleset",
                    target_key="20717667",
                    operation_kind="UPDATE_SETTINGS",
                    scope=transaction["scope"],
                ),
                authority_comment_id=1234,
                required=True,
            )
            self.assertEqual("WAITING", row["state"])
            self.control.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=314,
                status="DONE",
                allocation_class="NONE",
                generation=1,
                accountable_session_id=None,
                lease_manifest_sha256=None,
                development_units=0,
                shared_units=0,
                sre_units=0,
                expected_source_sha256=blocker_source.payload_sha256,
                expected_version=1,
                now="2026-08-23T10:00:04Z",
            )
            self.assertEqual([row["id"]], self.control.refresh_waiting("2026-08-23T10:00:05Z"))
            claimed = self.control.claim(row["id"], SRE_SESSION, "2026-08-23T10:00:06Z")
            self.assertEqual("CLAIMED", claimed["state"])

        outbox_id = self.control.store.enqueue_comment(
            idempotency_key="issue143-ruleset-receipt-v1",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            expected_source_sha256=self.source.payload_sha256,
            body=self.receipt_body(claimed),
            now="2026-08-23T10:00:07Z",
        )
        self.control.store.reserve_outbox(outbox_id, "2026-08-23T10:00:08Z")
        self.control.store.complete_outbox(outbox_id, "comment:999", "2026-08-23T10:00:09Z")
        completed = self.control.complete(
            row["id"], SRE_SESSION, outbox_id, "2026-08-23T10:00:10Z"
        )
        self.assertEqual("COMPLETE", completed["state"])
        self.assertEqual("comment:999", completed["remote_receipt"])

    def test_prepare_is_idempotent_and_source_bound(self) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
            second = self.control.prepare(self.transaction(), "2026-08-23T10:00:03Z")
            self.assertEqual(first["id"], second["id"])
            changed = self.transaction()
            changed["target_key"] = "20717668"
            changed["scope"]["target"]["ruleset_id"] = 20717668
            with self.assertRaisesRegex(CoordinationError, "HOSTED_IDEMPOTENCY_CONFLICT"):
                self.control.prepare(changed, "2026-08-23T10:00:04Z")

        self.control.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            payload={"number": 143, "title": "Changed", "updated_at": "2026-08-23T10:01:00Z"},
            source_updated_at="2026-08-23T10:01:00Z",
            fetched_at="2026-08-23T10:01:01Z",
        )
        with self.assertRaisesRegex(CoordinationError, "HOSTED_SOURCE_DRIFT"):
            self.control.claim(first["id"], SRE_SESSION, "2026-08-23T10:01:02Z")
        self.assertEqual("HOLD", self.control.show()[0]["state"])

    def test_github_billing_budget_is_an_explicit_approval_bound_class(self) -> None:
        transaction = self.transaction()
        transaction.update(
            {
                "idempotency_key": "issue143-actions-budget-c1976a50-v1",
                "target_kind": "github_billing_budget",
                "target_key": "twinfinityai:c1976a50-4e93-47bd-9a2a-e8c4802255de",
                "scope": {
                    "target": {
                        "organization": "twinfinityai",
                        "budget_id": "c1976a50-4e93-47bd-9a2a-e8c4802255de",
                    },
                    "expected_state": {
                        "amount": 30,
                        "prevent_further_usage": True,
                        "alert_config_sha256": "a" * 64,
                    },
                    "desired_state": {
                        "amount": 40,
                        "prevent_further_usage": True,
                        "preserve_alerting": True,
                    },
                    "exclusions": [
                        "No other budget, billing, repository, workflow, or organization setting change"
                    ],
                    "stop_conditions": [
                        "Budget identity, amount, enforcement state, or alerting configuration drift"
                    ],
                },
            }
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(transaction, "2026-08-23T10:00:02Z")

        self.assertEqual("PREPARED", row["state"])
        self.assertEqual("github_billing_budget", row["target_kind"])
        self.assertEqual(1, row["sre_units"])
        self.approval_guard_mock.assert_called_with(
            repository=REPOSITORY,
            issue_number=143,
            operation_kind="UPDATE_SETTINGS",
            execution_scope_sha256=hosted_execution_scope_sha256(
                provider="github",
                target_kind="github_billing_budget",
                target_key="twinfinityai:c1976a50-4e93-47bd-9a2a-e8c4802255de",
                operation_kind="UPDATE_SETTINGS",
                scope=transaction["scope"],
            ),
            authority_comment_id=1234,
            required=True,
        )

    def test_github_actions_rerun_is_single_attempt_infrastructure_only(self) -> None:
        transaction = self.actions_rerun_transaction()
        transaction["scope"]["expected_state"].update(
            self.seed_actions_rerun_evidence()
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(transaction, "2026-08-23T10:00:02Z")
            claimed = self.control.claim(row["id"], SRE_SESSION, "2026-08-23T10:00:03Z")

        self.assertEqual("CLAIMED", claimed["state"])
        self.assertEqual(1, claimed["sre_units"])
        result = {
            "workflow_run_id": 32733505535,
            "run_attempt": 2,
            "check_suite_id": 99112233,
            "job_ids": [7001, 7002, 7003],
        }
        outbox_id = self.control.store.enqueue_comment(
            idempotency_key="issue58-pr322-rerun-receipt-v1",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            expected_source_sha256=self.source.payload_sha256,
            body=self.receipt_body(claimed, overrides={"result": result}),
            now="2026-08-23T10:00:04Z",
        )
        self.control.store.reserve_outbox(outbox_id, "2026-08-23T10:00:05Z")
        self.control.store.complete_outbox(
            outbox_id, "comment:2001", "2026-08-23T10:00:06Z"
        )
        completed = self.control.complete(
            row["id"], SRE_SESSION, outbox_id, "2026-08-23T10:00:07Z"
        )
        self.assertEqual("COMPLETE", completed["state"])

    def test_github_actions_rerun_accepts_only_exact_known_annotation(self) -> None:
        transaction = self.actions_rerun_transaction()
        transaction["scope"]["expected_state"].update(
            self.seed_actions_rerun_evidence()
        )
        transaction["scope"]["expected_state"].update(
            {
                "annotation_count": 1,
                "infrastructure_annotations": [RUNNER_NOT_ACQUIRED_ANNOTATION],
            }
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(transaction, "2026-08-23T10:00:02Z")
        self.assertEqual("PREPARED", row["state"])

        unknown = self.actions_rerun_transaction()
        unknown["scope"]["expected_state"].update(
            {
                "annotation_count": 1,
                "infrastructure_annotations": [
                    {**RUNNER_NOT_ACQUIRED_ANNOTATION, "message": "test failed"}
                ],
            }
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(CoordinationError, "HOSTED_SCOPE_CLASS_INVALID"):
                self.control.prepare(unknown, "2026-08-23T10:00:03Z")

        mismatch = self.actions_rerun_transaction()
        mismatch["scope"]["expected_state"].update(
            {
                "annotation_count": 0,
                "infrastructure_annotations": [RUNNER_NOT_ACQUIRED_ANNOTATION],
            }
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(CoordinationError, "HOSTED_SCOPE_CLASS_INVALID"):
                self.control.prepare(mismatch, "2026-08-23T10:00:04Z")

    def test_unclaimed_receiptless_rerun_hold_allows_one_successor(self) -> None:
        evidence = self.seed_actions_rerun_evidence()
        transaction = self.actions_rerun_transaction()
        transaction["scope"]["expected_state"].update(evidence)
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(transaction, "2026-08-23T10:00:02Z")
            self.control.hold(first["id"], "HOSTED_RERUN_ANNOTATION_DRIFT", "2026-08-23T10:00:03Z")
            successor = self.actions_rerun_transaction()
            successor["idempotency_key"] = (
                "issue58-pr322-run32733505535-attempt1-rerun-v2"
            )
            successor["scope"]["expected_state"].update(evidence)
            second = self.control.prepare(successor, "2026-08-23T10:00:04Z")
        self.assertEqual("PREPARED", second["state"])

        with self.control.store.transaction():
            self.control.connection.execute(
                "UPDATE hosted_operations SET state='HOLD' WHERE id=?", (second["id"],)
            )
            self.control.connection.execute(
                "UPDATE hosted_operations SET claimed_by=? WHERE id=?",
                (SRE_SESSION, second["id"]),
            )
        fenced = self.actions_rerun_transaction()
        fenced["idempotency_key"] = "issue58-pr322-run32733505535-attempt1-rerun-v3"
        fenced["scope"]["expected_state"].update(evidence)
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_RERUN_TARGET_ALREADY_RESERVED"
            ):
                self.control.prepare(fenced, "2026-08-23T10:00:05Z")

    def test_actions_rerun_scope_builder_uses_native_sqlite_row_hashes(self) -> None:
        evidence = self.seed_actions_rerun_evidence()
        request = self.actions_rerun_request()
        request.update(
            {
                "local_gate_id": evidence["local_gate_id"],
                "guarded_publication_id": evidence["guarded_publication_id"],
                "provider_restoration_operation_id": evidence[
                    "provider_restoration_operation_id"
                ],
            }
        )
        result = build_scope(self.control, request, self.actions_rerun_github())
        expected = result["scope"]["expected_state"]
        gate = self.control.connection.execute(
            "SELECT * FROM coordination_pre_push_gates WHERE id=?",
            (evidence["local_gate_id"],),
        ).fetchone()
        publication = self.control.connection.execute(
            "SELECT * FROM coordination_pre_push_publications WHERE id=?",
            (evidence["guarded_publication_id"],),
        ).fetchone()
        self.assertEqual(digest_json(dict(gate)), expected["local_gate_receipt_sha256"])
        self.assertEqual(
            digest_json(dict(publication)),
            expected["guarded_publication_receipt_sha256"],
        )
        self.assertEqual(1, expected["annotation_count"])
        self.assertEqual(
            [RUNNER_NOT_ACQUIRED_ANNOTATION], expected["infrastructure_annotations"]
        )

    def test_hosted_clearance_collapses_claim_ack_build_and_prepare(self) -> None:
        evidence = self.seed_actions_rerun_evidence()
        request = self.actions_rerun_request()
        request.update(
            {
                "local_gate_id": evidence["local_gate_id"],
                "guarded_publication_id": evidence["guarded_publication_id"],
                "provider_restoration_operation_id": evidence[
                    "provider_restoration_operation_id"
                ],
            }
        )
        github = self.actions_rerun_github()
        built = build_scope(self.control, request, github)
        packet = {
            "schema": "twinfinity.approval-proposal.v1",
            "decision_key": "issue-143:ruleset-update",
            "repository": REPOSITORY,
            "owning_issue": 143,
            "source_snapshot_sha256": self.source.payload_sha256,
            "execution_scope_sha256": built["hosted_execution_scope_sha256"],
            "requester_session_id": SRE_SESSION,
            "recipient_session_id": SRE_SESSION,
            "workstream": "SRE",
            "boundary": "HOSTED_PROVIDER",
            "priority": "P0",
            "urgency": "ACTIVE_BLOCKER",
            "summary": "Retry one infrastructure-only workflow run.",
            "question": "Should the exact same-run retry proceed?",
            "requested_action": "Retry only the exact run once.",
            "target": "PR 322 workflow run 32733505535",
            "affected_issues": [143],
            "blocked_mutation": "Natural CI is blocked.",
            "immediate_beneficiary": "Twin Studio operators",
            "evidence": ["The canonical builder validated the exact scope."],
            "risk": "A repeated or drifted retry wastes CI capacity.",
            "drift_guards": ["All scope evidence must remain exact."],
            "prohibited_side_effects": ["No source or workflow mutation."],
            "options": [
                {
                    "id": "RETRY",
                    "label": "Retry",
                    "effect": "Retry once.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "HOLD",
                    "label": "Hold",
                    "effect": "Do not retry.",
                    "machine_outcome": "REJECT",
                },
            ],
            "recommendation": "RETRY",
            "expires_at": None,
        }
        proposal = submit_proposal(
            self.control.store, packet, "2026-08-23T10:00:02Z"
        )["proposal_sha256"]
        batch = create_review_batch(
            self.control.store, REPOSITORY, "2026-08-23T10:00:03Z"
        )
        answer_map = {
            "schema": "twinfinity.approval-batch-answer-map.v1",
            "batch_sha256": batch["batch_sha256"],
            "answers": [
                {
                    "proposal_sha256": proposal,
                    "selected_option_id": "RETRY",
                }
            ],
        }
        decision = record_decision(
            self.control.store,
            proposal_sha256=proposal,
            batch_sha256=batch["batch_sha256"],
            batch_answer_map=answer_map,
            decision="APPROVE",
            selected_option_id="RETRY",
            revisit_trigger=None,
            decision_note="Approved for one exact retry.",
            user_input_sha256=digest_json(answer_map),
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:clearance-approve",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-23T10:00:03Z",
        )
        self.control.store.reserve_outbox(
            decision["owner_outbox_id"], "2026-08-23T10:00:04Z"
        )
        self.control.store.complete_outbox(
            decision["owner_outbox_id"], "comment:1234", "2026-08-23T10:00:05Z"
        )
        moments = iter(
            [
                "2026-08-23T10:00:06Z",
                "2026-08-23T10:00:07Z",
                "2026-08-23T10:00:08Z",
            ]
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            result = clear_actions_rerun(
                self.control,
                request=request,
                proposal_sha256=proposal,
                decision_sha256=decision["decision_sha256"],
                authority_comment_id=1234,
                idempotency_key="issue143-pr322-rerun-clearance-v1",
                recipient_session_id=SRE_SESSION,
                github=github,
                source_refresher=lambda *_: {
                    "number": 143,
                    "title": "Staging",
                    "updated_at": "2026-08-23T10:00:00Z",
                },
                now=lambda: next(moments),
            )
        self.assertEqual("CLEARED", result["phase"])
        self.assertEqual("PREPARED", result["operation_state"])
        delivery = self.control.connection.execute(
            "SELECT state FROM approval_deliveries WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()
        self.assertEqual("ACKNOWLEDGED", delivery["state"])

    def test_hosted_clearance_uses_one_write_transaction_after_external_reads(self) -> None:
        request, github, _, proposal, decision = self.seed_clearance_approval()
        statements = []

        def source_refresher(*_):
            self.assertFalse(self.control.connection.in_transaction)
            return dict(self.source.payload)

        def authority(*args):
            self.assertFalse(self.control.connection.in_transaction)
            return self.authority_comment(*args)

        self.control.connection.set_trace_callback(statements.append)
        try:
            with patch.object(
                HostedOperationControl,
                "_fetch_authority_comment",
                side_effect=authority,
            ):
                result = clear_actions_rerun(
                    self.control,
                    request=request,
                    proposal_sha256=proposal,
                    decision_sha256=decision["decision_sha256"],
                    authority_comment_id=1234,
                    idempotency_key="issue143-pr322-rerun-atomic-v1",
                    recipient_session_id=SRE_SESSION,
                    github=github,
                    source_refresher=source_refresher,
                    now=lambda: "2026-08-23T10:00:06Z",
                )
        finally:
            self.control.connection.set_trace_callback(None)

        self.assertEqual("PREPARED", result["operation_state"])
        normalized = [statement.strip().upper() for statement in statements]
        self.assertEqual(1, normalized.count("BEGIN IMMEDIATE"))
        self.assertEqual(1, normalized.count("COMMIT"))
        self.assertEqual(0, normalized.count("ROLLBACK"))
        count = self.control.connection.execute(
            "SELECT COUNT(*) FROM hosted_operations WHERE target_kind='github_actions_rerun'"
        ).fetchone()[0]
        self.assertEqual(1, count)

    def test_hosted_clearance_late_failure_rolls_back_every_local_effect(self) -> None:
        request, github, built, proposal, decision = self.seed_clearance_approval()
        predecessor_key = "issue143-pr322-rerun-stale-predecessor"
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            predecessor = self.control.prepare(
                self.rerun_transaction_from_scope(built, predecessor_key),
                "2026-08-23T10:00:06Z",
            )
            self.control.hold(
                predecessor["id"], "STALE_PREDECESSOR", "2026-08-23T10:00:07Z"
            )
        original_event = self.control.store._event

        def fail_after_insert(event_type, entity_key, payload, observed_at):
            if event_type == "HOSTED_OPERATION_PREPARED":
                raise CoordinationError("INJECTED_LATE_FAILURE")
            original_event(event_type, entity_key, payload, observed_at)

        refreshed_payload = dict(self.source.payload)
        refreshed_payload["updated_at"] = "2026-08-23T10:00:08Z"
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ), patch.object(self.control.store, "_event", side_effect=fail_after_insert):
            with self.assertRaisesRegex(CoordinationError, "INJECTED_LATE_FAILURE"):
                clear_actions_rerun(
                    self.control,
                    request=request,
                    proposal_sha256=proposal,
                    decision_sha256=decision["decision_sha256"],
                    authority_comment_id=1234,
                    idempotency_key="issue143-pr322-rerun-atomic-fails",
                    recipient_session_id=SRE_SESSION,
                    github=github,
                    source_refresher=lambda *_: refreshed_payload,
                    now=lambda: "2026-08-23T10:00:08Z",
                )

        delivery = self.control.connection.execute(
            "SELECT state FROM approval_deliveries WHERE proposal_sha256=?",
            (proposal,),
        ).fetchone()
        self.assertEqual("WAITING_PUBLICATION", delivery["state"])
        self.assertIsNone(
            self.control.connection.execute(
                "SELECT 1 FROM approval_effectivity WHERE proposal_sha256=?", (proposal,)
            ).fetchone()
        )
        predecessor_after = self.control.connection.execute(
            "SELECT * FROM hosted_operations WHERE id=?", (predecessor["id"],)
        ).fetchone()
        self.assertIsNone(predecessor_after["retired_by_idempotency_key"])
        self.assertIsNone(predecessor_after["retired_at"])
        self.assertIsNone(
            self.control.connection.execute(
                "SELECT 1 FROM hosted_operations WHERE idempotency_key=?",
                ("issue143-pr322-rerun-atomic-fails",),
            ).fetchone()
        )
        current = self.control.store.current_snapshot(REPOSITORY, "issue", 143)
        self.assertEqual(self.source.payload_sha256, current.payload_sha256)

    def test_hosted_clearance_retires_only_eligible_stale_predecessor(self) -> None:
        request, github, built, proposal, decision = self.seed_clearance_approval()
        predecessor_key = "issue143-pr322-rerun-eligible-predecessor"
        successor_key = "issue143-pr322-rerun-eligible-successor"
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            predecessor = self.control.prepare(
                self.rerun_transaction_from_scope(built, predecessor_key),
                "2026-08-23T10:00:06Z",
            )
            self.control.hold(
                predecessor["id"], "STALE_PREDECESSOR", "2026-08-23T10:00:07Z"
            )
            result = clear_actions_rerun(
                self.control,
                request=request,
                proposal_sha256=proposal,
                decision_sha256=decision["decision_sha256"],
                authority_comment_id=1234,
                idempotency_key=successor_key,
                recipient_session_id=SRE_SESSION,
                github=github,
                source_refresher=lambda *_: dict(self.source.payload),
                now=lambda: "2026-08-23T10:00:08Z",
            )

        predecessor_after = self.control.connection.execute(
            "SELECT * FROM hosted_operations WHERE id=?", (predecessor["id"],)
        ).fetchone()
        self.assertEqual(successor_key, predecessor_after["retired_by_idempotency_key"])
        self.assertEqual("2026-08-23T10:00:08Z", predecessor_after["retired_at"])
        self.assertEqual("PREPARED", result["operation_state"])

    def test_hosted_clearance_preserves_every_protected_predecessor_collision(self) -> None:
        request, github, built, proposal, decision = self.seed_clearance_approval()
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            predecessor = self.control.prepare(
                self.rerun_transaction_from_scope(
                    built, "issue143-pr322-rerun-protected-predecessor"
                ),
                "2026-08-23T10:00:06Z",
            )
            self.control.hold(
                predecessor["id"], "STALE_PREDECESSOR", "2026-08-23T10:00:07Z"
            )

        protected_values = (
            ("claimed", "claimed_by", SRE_SESSION),
            ("local-receipt", "receipt_outbox_id", 999),
            ("remote-receipt", "remote_receipt", "comment:999"),
            ("not-hold", "state", "PREPARED"),
        )
        for label, column, value in protected_values:
            with self.subTest(predecessor=label):
                with self.control.store.transaction():
                    self.control.connection.execute(
                        f"UPDATE hosted_operations SET {column}=? WHERE id=?",
                        (value, predecessor["id"]),
                    )
                with patch.object(
                    HostedOperationControl,
                    "_fetch_authority_comment",
                    side_effect=self.authority_comment,
                ):
                    with self.assertRaisesRegex(
                        CoordinationError, "HOSTED_RERUN_TARGET_ALREADY_RESERVED"
                    ):
                        clear_actions_rerun(
                            self.control,
                            request=request,
                            proposal_sha256=proposal,
                            decision_sha256=decision["decision_sha256"],
                            authority_comment_id=1234,
                            idempotency_key=f"issue143-pr322-rerun-protected-{label}",
                            recipient_session_id=SRE_SESSION,
                            github=github,
                            source_refresher=lambda *_: dict(self.source.payload),
                            now=lambda: "2026-08-23T10:00:08Z",
                        )
                protected = self.control.connection.execute(
                    "SELECT * FROM hosted_operations WHERE id=?", (predecessor["id"],)
                ).fetchone()
                self.assertIsNone(protected["retired_by_idempotency_key"])
                with self.control.store.transaction():
                    self.control.connection.execute(
                        f"UPDATE hosted_operations SET {column}=? WHERE id=?",
                        ("HOLD" if column == "state" else None, predecessor["id"]),
                    )

    def test_hosted_clearance_rejects_prelock_source_digest_drift_atomically(self) -> None:
        request, github, _, proposal, decision = self.seed_clearance_approval()
        refreshed_payload = dict(self.source.payload)

        def mutating_authority(*args):
            refreshed_payload["title"] = "Changed after the external read digest"
            return self.authority_comment(*args)

        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=mutating_authority,
        ):
            with self.assertRaisesRegex(
                CoordinationError, "APPROVAL_SOURCE_REFRESH_DIGEST_DRIFT"
            ):
                clear_actions_rerun(
                    self.control,
                    request=request,
                    proposal_sha256=proposal,
                    decision_sha256=decision["decision_sha256"],
                    authority_comment_id=1234,
                    idempotency_key="issue143-pr322-rerun-source-drift",
                    recipient_session_id=SRE_SESSION,
                    github=github,
                    source_refresher=lambda *_: refreshed_payload,
                    now=lambda: "2026-08-23T10:00:06Z",
                )
        delivery = self.control.connection.execute(
            "SELECT state FROM approval_deliveries WHERE proposal_sha256=?", (proposal,)
        ).fetchone()
        self.assertEqual("WAITING_PUBLICATION", delivery["state"])
        self.assertIsNone(
            self.control.connection.execute(
                "SELECT 1 FROM hosted_operations WHERE idempotency_key=?",
                ("issue143-pr322-rerun-source-drift",),
            ).fetchone()
        )

    def test_hosted_clearance_exact_replay_returns_same_row_and_changed_bytes_conflict(self) -> None:
        request, github, _, proposal, decision = self.seed_clearance_approval()

        def clear(request_value):
            with patch.object(
                HostedOperationControl,
                "_fetch_authority_comment",
                side_effect=self.authority_comment,
            ):
                return clear_actions_rerun(
                    self.control,
                    request=request_value,
                    proposal_sha256=proposal,
                    decision_sha256=decision["decision_sha256"],
                    authority_comment_id=1234,
                    idempotency_key="issue143-pr322-rerun-replay",
                    recipient_session_id=SRE_SESSION,
                    github=github,
                    source_refresher=lambda *_: dict(self.source.payload),
                    now=lambda: "2026-08-23T10:00:06Z",
                )

        first = clear(request)
        replayed = clear(dict(request))
        self.assertEqual(first["operation_id"], replayed["operation_id"])
        self.assertEqual(1, self.control.connection.execute(
            "SELECT COUNT(*) FROM hosted_operations WHERE idempotency_key=?",
            ("issue143-pr322-rerun-replay",),
        ).fetchone()[0])

        changed = dict(request)
        changed["exclusions"] = ["Changed request bytes"]
        with self.assertRaisesRegex(CoordinationError, "HOSTED_IDEMPOTENCY_CONFLICT"):
            clear(changed)

    def test_github_actions_rerun_rejects_executed_or_second_attempt(self) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            executed = self.actions_rerun_transaction()
            executed["scope"]["expected_state"]["substantive_jobs"]["backend-check"] = "failure"
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_SCOPE_CLASS_INVALID"
            ):
                self.control.prepare(executed, "2026-08-23T10:00:02Z")

            second_attempt = self.actions_rerun_transaction()
            second_attempt["idempotency_key"] = "issue58-pr322-run32733505535-attempt2-rerun-v1"
            second_attempt["target_key"] = f"{REPOSITORY}:pr:322:run:32733505535:attempt:2"
            second_attempt["scope"]["target"]["run_attempt"] = 2
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_SCOPE_CLASS_INVALID"
            ):
                self.control.prepare(second_attempt, "2026-08-23T10:00:03Z")

    def test_github_actions_rerun_revalidates_receipts_and_fences_target(self) -> None:
        evidence = self.seed_actions_rerun_evidence()
        transaction = self.actions_rerun_transaction()
        transaction["scope"]["expected_state"].update(evidence)
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(transaction, "2026-08-23T10:00:02Z")

            duplicate = self.actions_rerun_transaction()
            duplicate["idempotency_key"] = (
                "issue58-pr322-run32733505535-attempt1-rerun-different-key"
            )
            duplicate["scope"]["expected_state"].update(evidence)
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_RERUN_TARGET_ALREADY_RESERVED"
            ):
                self.control.prepare(duplicate, "2026-08-23T10:00:03Z")

            with self.control.store.transaction():
                self.control.connection.execute(
                    "UPDATE hosted_operations SET receipt_outcome='FAILURE' WHERE id=?",
                    (evidence["provider_restoration_operation_id"],),
                )
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_RERUN_PROVIDER_RESTORATION_INVALID"
            ):
                self.control.claim(row["id"], SRE_SESSION, "2026-08-23T10:00:04Z")

        held = self.control.connection.execute(
            "SELECT state,last_error FROM hosted_operations WHERE id=?", (row["id"],)
        ).fetchone()
        self.assertEqual("HOLD", held["state"])
        self.assertEqual(
            "HOSTED_RERUN_PROVIDER_RESTORATION_INVALID", held["last_error"]
        )

    def test_github_actions_rerun_rejects_unregistered_receipt_hashes(self) -> None:
        evidence = self.seed_actions_rerun_evidence()
        transaction = self.actions_rerun_transaction()
        transaction["scope"]["expected_state"].update(evidence)
        transaction["scope"]["expected_state"]["local_gate_receipt_sha256"] = "f" * 64
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_RERUN_LOCAL_GATE_EVIDENCE_INVALID"
            ):
                self.control.prepare(transaction, "2026-08-23T10:00:02Z")

    def test_github_actions_rerun_rejects_stale_restoration(self) -> None:
        stale = self.actions_rerun_transaction()
        stale["scope"]["expected_state"].update(self.seed_actions_rerun_evidence())
        stale["scope"]["expected_state"]["failed_run_completed_at"] = (
            "2026-08-23T09:19:00Z"
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_RERUN_PROVIDER_RESTORATION_STALE"
            ):
                self.control.prepare(stale, "2026-08-23T10:00:02Z")

    def test_github_actions_rerun_rejects_non_restoring_capacity(self) -> None:
        not_restored = self.actions_rerun_transaction()
        not_restored["scope"]["expected_state"].update(
            self.seed_actions_rerun_evidence(capacity_restored=False)
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_RERUN_PROVIDER_CAPACITY_NOT_RESTORED"
            ):
                self.control.prepare(not_restored, "2026-08-23T10:00:02Z")

    def test_github_actions_rerun_rejects_completed_outbox_payload_drift(self) -> None:
        evidence = self.seed_actions_rerun_evidence(capacity_restored=False)
        restoration = self.control.connection.execute(
            "SELECT * FROM hosted_operations WHERE id=?",
            (evidence["provider_restoration_operation_id"],),
        ).fetchone()
        outbox = self.control.connection.execute(
            "SELECT * FROM github_outbox WHERE id=?",
            (restoration["receipt_outbox_id"],),
        ).fetchone()
        payload = json.loads(outbox["payload_json"])
        marker = "<!-- twinfinity-hosted-operation-receipt:"
        prefix, remainder = payload["body"].split(marker, 1)
        receipt_json, suffix = remainder.split(" -->", 1)
        receipt = json.loads(receipt_json)
        receipt["result"]["capacity_restored"] = True
        payload["body"] = (
            prefix
            + marker
            + json.dumps(receipt, sort_keys=True, separators=(",", ":"))
            + " -->"
            + suffix
        )
        with self.control.store.transaction():
            self.control.connection.execute(
                "UPDATE github_outbox SET payload_json=? WHERE id=?",
                (
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    outbox["id"],
                ),
            )
        transaction = self.actions_rerun_transaction()
        transaction["scope"]["expected_state"].update(evidence)
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(
                CoordinationError,
                "HOSTED_RERUN_PROVIDER_RESTORATION_RECEIPT_DRIFT",
            ):
                self.control.prepare(transaction, "2026-08-23T10:00:02Z")

    def test_revocation_between_preflight_and_claim_is_rechecked_atomically(self) -> None:
        transaction = self.transaction()
        execution_scope = hosted_execution_scope_sha256(
            provider=transaction["provider"],
            target_kind=transaction["target_kind"],
            target_key=transaction["target_key"],
            operation_kind=transaction["operation_kind"],
            scope=transaction["scope"],
        )
        packet = {
            "schema": "twinfinity.approval-proposal.v1",
            "decision_key": "issue-143:ruleset-update",
            "repository": REPOSITORY,
            "owning_issue": 143,
            "source_snapshot_sha256": self.source.payload_sha256,
            "execution_scope_sha256": execution_scope,
            "requester_session_id": SRE_SESSION,
            "recipient_session_id": SRE_SESSION,
            "workstream": "SRE",
            "boundary": "HOSTED_PROVIDER",
            "priority": "P0",
            "urgency": "READY_BLOCKER",
            "summary": "Apply the exact reviewed main ruleset change.",
            "question": "Should the exact reviewed ruleset update proceed?",
            "requested_action": "Update only the reviewed ruleset fields.",
            "target": "GitHub main ruleset for twinfinityapp",
            "affected_issues": [143],
            "blocked_mutation": "The ruleset update is paused.",
            "immediate_beneficiary": "Gate A release operators",
            "evidence": ["The current issue snapshot records the exact target."],
            "risk": "An adjacent settings change could alter repository policy.",
            "drift_guards": ["Issue and target must remain exact."],
            "prohibited_side_effects": ["No repository content or deployment mutation."],
            "options": [
                {
                    "id": "UPDATE",
                    "label": "Update",
                    "effect": "Apply only reviewed settings.",
                    "machine_outcome": "APPROVE",
                },
                {
                    "id": "HOLD",
                    "label": "Hold",
                    "effect": "Leave settings unchanged.",
                    "machine_outcome": "REJECT",
                },
            ],
            "recommendation": "UPDATE",
            "expires_at": None,
        }
        proposal = submit_proposal(
            self.control.store, packet, "2026-08-23T10:00:02Z"
        )["proposal_sha256"]
        batch = create_review_batch(
            self.control.store, REPOSITORY, "2026-08-23T10:00:03Z"
        )
        answer_map = {
            "schema": "twinfinity.approval-batch-answer-map.v1",
            "batch_sha256": batch["batch_sha256"],
            "answers": [
                {
                    "proposal_sha256": proposal,
                    "selected_option_id": "UPDATE",
                }
            ],
        }
        decision = record_decision(
            self.control.store,
            proposal_sha256=proposal,
            batch_sha256=batch["batch_sha256"],
            batch_answer_map=answer_map,
            decision="APPROVE",
            selected_option_id="UPDATE",
            revisit_trigger=None,
            decision_note="Approved only for the exact reviewed settings update.",
            user_input_sha256=digest_json(answer_map),
            user_event_source="CODEX_DIRECT_USER_TURN",
            user_event_id="planner-turn:hosted-race-approve",
            planner_session_id=PLANNER_SESSION,
            now="2026-08-23T10:00:03Z",
        )
        self.control.store.reserve_outbox(
            decision["owner_outbox_id"], "2026-08-23T10:00:04Z"
        )
        self.control.store.complete_outbox(
            decision["owner_outbox_id"], "comment:1234", "2026-08-23T10:00:05Z"
        )
        claim_decision(
            self.control.store,
            proposal_sha256=proposal,
            recipient_session_id=SRE_SESSION,
            now="2026-08-23T10:00:06Z",
            source_refresher=lambda *_: {
                "number": 143,
                "title": "Staging",
                "updated_at": "2026-08-23T10:00:05Z",
            },
        )
        transaction["source_payload_sha256"] = self.control.store.current_snapshot(
            REPOSITORY, "issue", 143
        ).payload_sha256
        def enforce_real_guard(**kwargs):
            kwargs.pop("operation_kind")
            try:
                return require_effective_approval(
                    self.control.connection,
                    recipient_session_id=SRE_SESSION,
                    **kwargs,
                )
            except ApprovalGuardError as exc:
                raise CoordinationError(str(exc)) from exc

        self.approval_guard_mock.side_effect = enforce_real_guard
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            operation = self.control.prepare(transaction, "2026-08-23T10:00:07Z")

            calls = 0

            def revoke_after_preflight(*_args) -> bool:
                nonlocal calls
                calls += 1
                if calls == 1:
                    concurrent = CoordinationStore(self.database)
                    try:
                        revoke_decision(
                            concurrent,
                            proposal_sha256=proposal,
                            decision_sha256=decision["decision_sha256"],
                            reason="The user revoked authority before hosted claim.",
                            user_input_sha256="c" * 64,
                            user_event_source="CODEX_DIRECT_USER_TURN",
                            user_event_id="planner-turn:hosted-race-revoke",
                            planner_session_id=PLANNER_SESSION,
                            now="2026-08-23T10:00:08Z",
                        )
                    finally:
                        concurrent.close()
                return True

            with patch.object(
                self.control, "_blocker_terminal", side_effect=revoke_after_preflight
            ):
                with self.assertRaisesRegex(
                    CoordinationError, "APPROVAL_AUTHORITY_MISMATCH"
                ):
                    self.control.claim(
                        operation["id"], SRE_SESSION, "2026-08-23T10:00:09Z"
                    )

        held = self.control.show()[0]
        self.assertEqual("HOLD", held["state"])
        self.assertEqual("APPROVAL_AUTHORITY_MISMATCH", held["last_error"])

    def test_rejects_secret_fields_and_wrong_capacity_class(self) -> None:
        secret = self.transaction()
        secret["scope"]["desired_state"]["secret_value"] = "forbidden"
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            with self.assertRaisesRegex(CoordinationError, "HOSTED_SCOPE_SECRET_FIELD"):
                self.control.prepare(secret, "2026-08-23T10:00:02Z")
            zero_capacity = self.transaction()
            zero_capacity["sre_units"] = 0
            with self.assertRaisesRegex(CoordinationError, "HOSTED_TRANSACTION_INVALID"):
                self.control.prepare(zero_capacity, "2026-08-23T10:00:03Z")
            mismatched_provider = self.transaction()
            mismatched_provider["provider"] = "supabase"
            with self.assertRaisesRegex(CoordinationError, "HOSTED_TRANSACTION_INVALID"):
                self.control.prepare(mismatched_provider, "2026-08-23T10:00:04Z")

    def test_each_supported_tuple_has_a_specific_scope_contract(self) -> None:
        environment = self.transaction()
        environment.update(
            {
                "idempotency_key": "issue143-environment-staging-v1",
                "target_kind": "github_environment",
                "target_key": f"{REPOSITORY}:staging",
                "operation_kind": "CREATE_SETTINGS",
                "scope": {
                    "target": {"repository": REPOSITORY, "environment": "staging"},
                    "expected_state": {"exists": False},
                    "desired_state": {
                        "deployment_branch": "refs/heads/main",
                        "required_reviewer": "jayendusharma",
                        "environment_values_configured": False,
                    },
                    "exclusions": ["No secrets or deployments"],
                    "stop_conditions": ["Environment already exists or plan support differs"],
                },
            }
        )
        gcp = self.transaction()
        gcp.update(
            {
                "idempotency_key": "issue143-gcp-inventory-v1",
                "provider": "google_cloud",
                "target_kind": "gcp_project_inventory",
                "target_key": "project-a,project-b",
                "operation_kind": "READ_METADATA",
                "sre_units": 0,
                "scope": {
                    "target": {"project_ids": ["project-a", "project-b"]},
                    "expected_state": {"authenticated_account_sha256": "b" * 64},
                    "desired_state": {
                        "metadata_categories": ["cloud_run", "iam_bindings", "secret_metadata"],
                        "read_only": True,
                    },
                    "exclusions": ["No payloads, logs, or mutations"],
                    "stop_conditions": ["Authenticated account or project set drifts"],
                },
            }
        )
        supabase = self.transaction()
        supabase.update(
            {
                "idempotency_key": "issue143-supabase-inventory-v1",
                "provider": "supabase",
                "target_kind": "supabase_project_inventory",
                "target_key": "twinfinity-staging",
                "operation_kind": "READ_METADATA",
                "sre_units": 0,
                "scope": {
                    "target": {"project_id": "twinfinity-staging", "region": "us-west-2"},
                    "expected_state": {
                        "status": "ACTIVE",
                        "project_fingerprint": "safe-project-fingerprint",
                    },
                    "desired_state": {
                        "metadata_categories": [
                            "grants", "performance_advisors", "rls", "schemas",
                            "security_advisors",
                        ],
                        "read_only": True,
                    },
                    "exclusions": ["No rows, identities, objects, logs, keys, or mutations"],
                    "stop_conditions": ["Project identity, status, or region drifts"],
                },
            }
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            for index, transaction in enumerate((environment, gcp, supabase), start=2):
                with self.subTest(target_kind=transaction["target_kind"]):
                    row = self.control.prepare(
                        transaction, f"2026-08-23T10:00:0{index}Z"
                    )
                    self.assertEqual("PREPARED", row["state"])

            invalid = environment.copy()
            invalid["idempotency_key"] = "issue143-environment-invalid-v1"
            invalid["scope"] = dict(environment["scope"])
            invalid["scope"]["desired_state"] = {
                "deployment_branch": "refs/heads/main",
                "environment_values_configured": False,
            }
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_SCOPE_CLASS_INVALID"
            ):
                self.control.prepare(invalid, "2026-08-23T10:00:06Z")

            unsafe_inventory = gcp.copy()
            unsafe_inventory["idempotency_key"] = "issue143-gcp-unsafe-inventory-v1"
            unsafe_inventory["scope"] = dict(gcp["scope"])
            unsafe_inventory["scope"]["desired_state"] = {
                "metadata_categories": ["secret_payloads"],
                "read_only": True,
            }
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_SCOPE_CLASS_INVALID"
            ):
                self.control.prepare(unsafe_inventory, "2026-08-23T10:00:07Z")

    def test_claim_revalidates_persisted_tuple_and_capacity_class(self) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
            with self.control.store.transaction():
                self.control.connection.execute(
                    "UPDATE hosted_operations SET sre_units=0 WHERE id=?", (row["id"],)
                )
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_PERSISTED_TRANSACTION_INVALID"
            ):
                self.control.claim(row["id"], SRE_SESSION, "2026-08-23T10:00:03Z")
        held = self.control.show()[0]
        self.assertEqual("HOLD", held["state"])
        self.assertEqual("HOSTED_PERSISTED_TRANSACTION_INVALID", held["last_error"])

        second = self.transaction()
        second["idempotency_key"] = "issue143-ruleset-persisted-tuple-corruption-v1"
        second["target_key"] = "20717668"
        second["scope"]["target"]["ruleset_id"] = 20717668
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(second, "2026-08-23T10:00:04Z")
            with self.control.store.transaction():
                self.control.connection.execute(
                    "UPDATE hosted_operations SET provider='supabase' WHERE id=?", (row["id"],)
                )
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_PERSISTED_TRANSACTION_INVALID"
            ):
                self.control.claim(row["id"], SRE_SESSION, "2026-08-23T10:00:05Z")
        corrupted = self.control.show()[1]
        self.assertEqual("HOLD", corrupted["state"])
        self.assertEqual("HOSTED_PERSISTED_TRANSACTION_INVALID", corrupted["last_error"])

    def test_claimed_operation_requires_structured_terminal_receipt(self) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
            claimed = self.control.claim(row["id"], SRE_SESSION, "2026-08-23T10:00:03Z")

        with self.assertRaisesRegex(CoordinationError, "HOSTED_STATE_CONFLICT"):
            self.control.hold(row["id"], "PROVIDER_TIMEOUT", "2026-08-23T10:00:04Z")

        invalid_outbox = self.control.store.enqueue_comment(
            idempotency_key="issue143-invalid-hosted-receipt-v1",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            expected_source_sha256=self.source.payload_sha256,
            body="Unstructured receipt",
            now="2026-08-23T10:00:05Z",
        )
        self.control.store.reserve_outbox(invalid_outbox, "2026-08-23T10:00:06Z")
        self.control.store.complete_outbox(
            invalid_outbox, "comment:1000", "2026-08-23T10:00:07Z"
        )
        with self.assertRaisesRegex(CoordinationError, "HOSTED_RECEIPT_INVALID"):
            self.control.complete(
                row["id"], SRE_SESSION, invalid_outbox, "2026-08-23T10:00:08Z"
            )
        self.assertEqual("CLAIMED", self.control.show()[0]["state"])

        partial_outbox = self.control.store.enqueue_comment(
            idempotency_key="issue143-partial-hosted-receipt-v1",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            expected_source_sha256=self.source.payload_sha256,
            body=self.receipt_body(claimed, "PARTIAL"),
            now="2026-08-23T10:00:09Z",
        )
        self.control.store.reserve_outbox(partial_outbox, "2026-08-23T10:00:10Z")
        self.control.store.complete_outbox(
            partial_outbox, "comment:1001", "2026-08-23T10:00:11Z"
        )
        held = self.control.complete(
            row["id"], SRE_SESSION, partial_outbox, "2026-08-23T10:00:12Z"
        )
        self.assertEqual("HOLD", held["state"])
        self.assertEqual("PARTIAL", held["receipt_outcome"])
        self.assertEqual("HOSTED_OPERATION_PARTIAL", held["last_error"])
        self.assertIsNotNone(held["receipt_payload_sha256"])

    def test_structured_failure_receipt_must_match_the_claimed_scope(self) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
            claimed = self.control.claim(row["id"], SRE_SESSION, "2026-08-23T10:00:03Z")

        mismatched_outbox = self.control.store.enqueue_comment(
            idempotency_key="issue143-mismatched-hosted-receipt-v1",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            expected_source_sha256=self.source.payload_sha256,
            body=self.receipt_body(claimed, "FAILURE", {"scope_sha256": "f" * 64}),
            now="2026-08-23T10:00:04Z",
        )
        self.control.store.reserve_outbox(mismatched_outbox, "2026-08-23T10:00:05Z")
        self.control.store.complete_outbox(
            mismatched_outbox, "comment:1002", "2026-08-23T10:00:06Z"
        )
        with self.assertRaisesRegex(CoordinationError, "HOSTED_RECEIPT_INVALID"):
            self.control.complete(
                row["id"], SRE_SESSION, mismatched_outbox, "2026-08-23T10:00:07Z"
            )
        self.assertEqual("CLAIMED", self.control.show()[0]["state"])

        failure_outbox = self.control.store.enqueue_comment(
            idempotency_key="issue143-failure-hosted-receipt-v1",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=143,
            expected_source_sha256=self.source.payload_sha256,
            body=self.receipt_body(claimed, "FAILURE"),
            now="2026-08-23T10:00:08Z",
        )
        self.control.store.reserve_outbox(failure_outbox, "2026-08-23T10:00:09Z")
        self.control.store.complete_outbox(
            failure_outbox, "comment:1003", "2026-08-23T10:00:10Z"
        )
        held = self.control.complete(
            row["id"], SRE_SESSION, failure_outbox, "2026-08-23T10:00:11Z"
        )
        self.assertEqual("HOLD", held["state"])
        self.assertEqual("FAILURE", held["receipt_outcome"])
        self.assertEqual("HOSTED_OPERATION_FAILED", held["last_error"])

    def test_hosted_capacity_reads_dynamic_sre_policy(self) -> None:
        self.control.store.set_capacity_policy(
            repository=REPOSITORY,
            development_limit=5,
            shared_limit=2,
            sre_limit=1,
            authority_sha256="c" * 64,
            expected_version=1,
            now="2026-08-23T10:00:01Z",
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
            self.assertEqual("PREPARED", first["state"])
            second = self.transaction()
            second["idempotency_key"] = "issue143-ruleset-20717667-v2"
            second["target_key"] = "20717668"
            second["scope"]["target"]["ruleset_id"] = 20717668
            with self.assertRaisesRegex(
                CoordinationError, "HOSTED_SRE_CAPACITY_EXCEEDED"
            ):
                self.control.prepare(second, "2026-08-23T10:00:03Z")

            with self.assertRaisesRegex(
                CoordinationError, "CAPACITY_POLICY_BELOW_OCCUPANCY"
            ):
                self.control.store.set_capacity_policy(
                    repository=REPOSITORY,
                    development_limit=5,
                    shared_limit=2,
                    sre_limit=0,
                    authority_sha256="d" * 64,
                    expected_version=2,
                    now="2026-08-23T10:00:04Z",
                )
            self.control.store.set_capacity_policy(
                repository=REPOSITORY,
                development_limit=5,
                shared_limit=2,
                sre_limit=2,
                authority_sha256="e" * 64,
                expected_version=2,
                now="2026-08-23T10:00:05Z",
            )
            prepared = self.control.prepare(second, "2026-08-23T10:00:06Z")
            self.assertEqual("PREPARED", prepared["state"])

    def test_supervisor_launches_fresh_hosted_role_attempt(self) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
        self.seed_current_sre_endpoint()
        launched: dict[str, object] = {}

        def launcher(**kwargs):
            launched.update(kwargs)
            return 0

        result = run_supervisor(
            self.control, "2026-08-23T10:01:03Z", launcher=launcher
        )

        self.assertEqual([row["id"]], result["launched"])
        self.assertEqual("sre", launched["role"])
        self.assertEqual(SRE_SESSION, launched["endpoint_id"])
        self.assertEqual("hosted_operation", launched["target_kind"])
        self.assertEqual(str(row["id"]), launched["target_key"])
        self.assertNotIn("resume", str(launched))

    def test_supervisor_preflight_failure_precedes_refresh_and_preserves_hosted_target(
        self,
    ) -> None:
        source_body = "synthetic hosted harness issue 149 body"
        source_body_sha256 = hashlib.sha256(source_body.encode()).hexdigest()
        self.seed_transport_notice_source(source_body)
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
        before = self.non_notice_database_state(self.control.connection)
        calls = 0

        def unavailable(_preflight):
            nonlocal calls
            calls += 1
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE)

        with patch(
            "role_executor_transport.TRANSPORT_PREFLIGHT_SOURCE_BODY_SHA256",
            source_body_sha256,
        ), patch.object(
            self.control,
            "refresh_waiting",
            side_effect=AssertionError("refresh must follow successful preflight"),
        ):
            result = run_supervisor(
                self.control,
                "2026-09-02T05:00:00Z",
                launcher=lambda **_kwargs: self.fail("launcher must not run"),
                transport_preflight=unavailable,
            )

        self.assertEqual(1, calls)
        self.assertEqual(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE, result["reason"])
        self.assertEqual([], result["promoted"])
        self.assertEqual([], result["launched"])
        self.assertEqual(before, self.non_notice_database_state(self.control.connection))
        self.assertEqual(
            ("PREPARED", None),
            tuple(
                self.control.connection.execute(
                    "SELECT state,last_wake_at FROM hosted_operations WHERE id=?",
                    (row["id"],),
                ).fetchone()
            ),
        )
        notice = self.control.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (result["notice_message_id"],),
        ).fetchone()
        self.assertEqual("coordination.notice", notice["topic"])
        self.assertEqual(
            ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE,
            json.loads(notice["payload_json"])["evidence"]["reason"],
        )

        replay_before = list(self.control.connection.iterdump())
        with patch(
            "role_executor_transport.TRANSPORT_PREFLIGHT_SOURCE_BODY_SHA256",
            source_body_sha256,
        ):
            replay = run_supervisor(
                self.control,
                "2026-09-02T06:00:00Z",
                launcher=lambda **_kwargs: self.fail("launcher must not run"),
                transport_preflight=unavailable,
            )
        self.assertEqual(result["notice_message_id"], replay["notice_message_id"])
        self.assertEqual(replay_before, list(self.control.connection.iterdump()))

    def test_supervisor_successful_preflight_preserves_dispatch_but_not_launch_success(
        self,
    ) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
        order: list[str] = []
        original_refresh = self.control.refresh_waiting

        def preflight(request):
            order.append("preflight")
            return self.successful_transport(request)

        def refresh(now):
            order.append("refresh")
            return original_refresh(now)

        def rejected(**_kwargs):
            order.append("launch")
            return 1

        with patch.object(self.control, "refresh_waiting", side_effect=refresh):
            result = run_supervisor(
                self.control,
                "2026-09-02T05:15:00Z",
                launcher=rejected,
                transport_preflight=preflight,
            )

        self.assertEqual(["preflight", "refresh", "launch"], order)
        self.assertEqual([], result["launched"])
        self.assertEqual([row["id"]], result["rejected"])
        self.assertEqual("LAUNCH_REJECTED", result["reason"])
        self.assertEqual(
            0,
            self.control.connection.execute(
                "SELECT COUNT(*) FROM executor_attempts WHERE target_kind='hosted_operation'"
            ).fetchone()[0],
        )

    def test_supervisor_ignores_a_different_active_sre_target(self) -> None:
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            row = self.control.prepare(self.transaction(), "2026-08-23T10:00:02Z")
        self.seed_current_sre_endpoint()
        self.seed_active_sre_attempt("message", "unrelated-sre-message")
        launched: dict[str, object] = {}

        result = run_supervisor(
            self.control,
            "2026-08-23T10:01:04Z",
            launcher=lambda **kwargs: launched.update(kwargs) or 0,
        )

        self.assertEqual([row["id"]], result["launched"])
        self.assertEqual("hosted_operation", launched["target_kind"])
        self.assertEqual(str(row["id"]), launched["target_key"])

    def test_supervisor_skips_active_first_row_and_launches_later_disjoint_row(
        self,
    ) -> None:
        first_transaction = self.transaction()
        second_transaction = self.transaction()
        second_transaction["idempotency_key"] = "issue143-ruleset-20717668-v1"
        second_transaction["target_key"] = "20717668"
        second_transaction["scope"]["target"]["ruleset_id"] = 20717668
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(
                first_transaction, "2026-08-23T10:00:01Z"
            )
            second = self.control.prepare(
                second_transaction, "2026-08-23T10:00:02Z"
            )
        self.seed_current_sre_endpoint()
        self.seed_active_sre_attempt("hosted_operation", str(first["id"]))
        launched: list[str] = []

        result = run_supervisor(
            self.control,
            "2026-08-23T10:01:03Z",
            launcher=lambda **kwargs: launched.append(kwargs["target_key"]) or 0,
        )

        self.assertEqual([second["id"]], result["launched"])
        self.assertEqual([str(second["id"])], launched)
        self.assertIn(
            {"operation_id": first["id"], "reason": "EXECUTOR_TARGET_ACTIVE"},
            result["skipped"],
        )

    def test_supervisor_launches_multiple_disjoint_rows_in_one_scan(self) -> None:
        first_transaction = self.transaction()
        second_transaction = self.transaction()
        second_transaction["idempotency_key"] = "issue143-ruleset-20717668-v1"
        second_transaction["target_key"] = "20717668"
        second_transaction["scope"]["target"]["ruleset_id"] = 20717668
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(
                first_transaction, "2026-08-23T10:00:01Z"
            )
            second = self.control.prepare(
                second_transaction, "2026-08-23T10:00:02Z"
            )
        self.seed_current_sre_endpoint()
        launches: list[dict[str, object]] = []

        result = run_supervisor(
            self.control,
            "2026-08-23T10:01:03Z",
            launcher=lambda **kwargs: launches.append(kwargs) or 0,
        )

        self.assertEqual([first["id"], second["id"]], result["launched"])
        self.assertEqual(
            [str(first["id"]), str(second["id"])],
            [launch["target_key"] for launch in launches],
        )
        self.assertEqual(2, result["capacity"]["reserved"])
        self.assertEqual([], result["rejected"])
        self.assertEqual([], result["skipped"])
        wake_times = {
            row["id"]: row["last_wake_at"] for row in self.control.show()
        }
        self.assertEqual("2026-08-23T10:01:03Z", wake_times[first["id"]])
        self.assertEqual("2026-08-23T10:01:03Z", wake_times[second["id"]])

    def test_supervisor_skips_cooling_first_row_and_launches_later_disjoint_row(
        self,
    ) -> None:
        first_transaction = self.transaction()
        second_transaction = self.transaction()
        second_transaction["idempotency_key"] = "issue143-ruleset-20717668-v1"
        second_transaction["target_key"] = "20717668"
        second_transaction["scope"]["target"]["ruleset_id"] = 20717668
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(
                first_transaction, "2026-08-23T10:00:01Z"
            )
            second = self.control.prepare(
                second_transaction, "2026-08-23T10:00:02Z"
            )
        self.seed_current_sre_endpoint()
        with self.control.store.transaction():
            self.control.connection.execute(
                "UPDATE hosted_operations SET last_wake_at=? WHERE id=?",
                ("2026-08-23T10:01:03Z", first["id"]),
            )
        launched: list[str] = []

        result = run_supervisor(
            self.control,
            "2026-08-23T10:01:03Z",
            launcher=lambda **kwargs: launched.append(kwargs["target_key"]) or 0,
        )

        self.assertEqual([second["id"]], result["launched"])
        self.assertEqual([str(second["id"])], launched)
        self.assertIn(
            {"operation_id": first["id"], "reason": "WAKE_NOT_DUE"},
            result["skipped"],
        )

    def test_supervisor_does_not_overcommit_zero_unit_metadata_workers(self) -> None:
        self.control.store.set_capacity_policy(
            repository=REPOSITORY,
            development_limit=5,
            shared_limit=2,
            sre_limit=1,
            authority_sha256="c" * 64,
            expected_version=1,
            now="2026-08-23T10:00:01Z",
        )
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(
                self.gcp_inventory_transaction(
                    "issue143-gcp-project-a-inventory-v1", ["project-a"]
                ),
                "2026-08-23T10:00:02Z",
            )
            second = self.control.prepare(
                self.gcp_inventory_transaction(
                    "issue143-gcp-project-b-inventory-v1", ["project-b"]
                ),
                "2026-08-23T10:00:03Z",
            )
        self.seed_current_sre_endpoint()
        launched: list[str] = []

        result = run_supervisor(
            self.control,
            "2026-08-23T10:01:03Z",
            launcher=lambda **kwargs: launched.append(kwargs["target_key"]) or 0,
        )

        self.assertEqual([first["id"]], result["launched"])
        self.assertEqual([str(first["id"])], launched)
        self.assertIn(
            {"operation_id": second["id"], "reason": "SRE_DISPATCH_CAPACITY_FULL"},
            result["skipped"],
        )
        self.assertEqual(1, result["capacity"]["limit"])
        self.assertEqual(1, result["capacity"]["reserved"])

    def test_supervisor_does_not_dispatch_colliding_external_targets(self) -> None:
        first_transaction = self.transaction()
        second_transaction = self.transaction()
        second_transaction["idempotency_key"] = "issue143-ruleset-20717667-v2"
        with patch.object(
            HostedOperationControl,
            "_fetch_authority_comment",
            side_effect=self.authority_comment,
        ):
            first = self.control.prepare(
                first_transaction, "2026-08-23T10:00:01Z"
            )
            second = self.control.prepare(
                second_transaction, "2026-08-23T10:00:02Z"
            )
        self.seed_current_sre_endpoint()

        result = run_supervisor(
            self.control,
            "2026-08-23T10:01:03Z",
            launcher=lambda **_kwargs: 0,
        )

        self.assertEqual([first["id"]], result["launched"])
        self.assertIn(
            {"operation_id": second["id"], "reason": "HOSTED_TARGET_COLLISION"},
            result["skipped"],
        )


if __name__ == "__main__":
    unittest.main()
