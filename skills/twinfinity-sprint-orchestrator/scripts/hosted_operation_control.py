#!/usr/bin/env python3
"""ACID control for same-host SRE operations that do not own a Git worktree."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
    canonicalize_coordination_identity,
    coordination_identity_role,
    digest_json,
    utc_now,
)
from executor_registry import (
    RegistryError,
    configured_identity_role,
    current_endpoint,
    identities_role_equivalent,
    load_legacy_aliases,
    require_current_endpoint_identity,
    select_role_equivalent_identity,
)
from role_executor_transport import (
    RoleExecutorTransportPreflight,
    attest_role_executor_transport,
    build_role_executor_transport_preflight,
    enqueue_role_executor_transport_failure_notice,
    injected_role_executor_transport_attestation,
    launch_role_executor,
    revalidate_role_executor_transport_preflight,
    role_executor_transport_failure_reason,
    validate_role_executor_transport_attestation,
)
from approval_guard import (
    ApprovalGuardError,
    hosted_execution_scope_sha256,
    require_effective_approval,
)


REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
PROVIDERS = {"github", "google_cloud", "supabase"}
TARGET_KINDS = {
    "github_ruleset",
    "github_environment",
    "github_billing_budget",
    "github_actions_rerun",
    "gcp_project_inventory",
    "supabase_project_inventory",
}
OPERATION_KINDS = {
    "READ_METADATA",
    "UPDATE_SETTINGS",
    "CREATE_SETTINGS",
    "RERUN_WORKFLOW",
}
MUTATING_OPERATIONS = {"UPDATE_SETTINGS", "CREATE_SETTINGS", "RERUN_WORKFLOW"}
ALLOWED_OPERATION_TARGETS = {
    ("github", "github_ruleset", "UPDATE_SETTINGS"),
    ("github", "github_environment", "CREATE_SETTINGS"),
    ("github", "github_billing_budget", "UPDATE_SETTINGS"),
    ("github", "github_actions_rerun", "RERUN_WORKFLOW"),
    ("google_cloud", "gcp_project_inventory", "READ_METADATA"),
    ("supabase", "supabase_project_inventory", "READ_METADATA"),
}
STATES = {"WAITING", "PREPARED", "CLAIMED", "COMPLETE", "HOLD"}
RECEIPT_OUTCOMES = {"SUCCESS", "FAILURE", "PARTIAL"}
GCP_METADATA_CATEGORIES = {
    "artifact_registry",
    "cloud_run",
    "iam_bindings",
    "secret_metadata",
    "service_accounts",
}
SUPABASE_METADATA_CATEGORIES = {
    "extensions",
    "functions",
    "grants",
    "migrations",
    "performance_advisors",
    "project_identity",
    "rls",
    "schemas",
    "security_advisors",
    "triggers",
}
FORBIDDEN_SCOPE_KEYS = re.compile(
    r"(?i)(?:secret|password|credential|access[_-]?token|refresh[_-]?token|private[_-]?key|row[_-]?data|payload)"
)
RUNNER_NOT_ACQUIRED_ANNOTATION = {
    "annotation_level": "failure",
    "end_line": 1,
    "message": "The job was not acquired by Runner of type hosted even after multiple attempts",
    "path": ".github",
    "raw_details": "",
    "start_line": 1,
    "title": "",
}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_sha(value: object) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise CoordinationError("HOSTED_SHA256_INVALID")
    return value


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CoordinationError("HOSTED_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CoordinationError("HOSTED_TIMESTAMP_INVALID") from exc
    if parsed.utcoffset() is None:
        raise CoordinationError("HOSTED_TIMESTAMP_INVALID")
    return parsed


def _require_shape(
    value: object,
    *,
    required: set[str],
    allowed: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(allowed):
        raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")
    return value


def _validate_rerun_annotations(expected: dict[str, Any]) -> None:
    annotations = expected.get("infrastructure_annotations", [])
    if (
        not isinstance(annotations, list)
        or annotations not in ([], [RUNNER_NOT_ACQUIRED_ANNOTATION])
        or expected.get("annotation_count") != len(annotations)
    ):
        raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")


def _validate_scope(
    value: object,
    *,
    provider: str,
    target_kind: str,
    operation_kind: str,
    target_key: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "target",
        "expected_state",
        "desired_state",
        "exclusions",
        "stop_conditions",
    }:
        raise CoordinationError("HOSTED_SCOPE_INVALID")
    if not isinstance(value["target"], dict) or not value["target"]:
        raise CoordinationError("HOSTED_SCOPE_INVALID")
    if not isinstance(value["expected_state"], dict) or not value["expected_state"]:
        raise CoordinationError("HOSTED_SCOPE_INVALID")
    if not isinstance(value["desired_state"], dict) or not value["desired_state"]:
        raise CoordinationError("HOSTED_SCOPE_INVALID")
    for key in ("exclusions", "stop_conditions"):
        if (
            not isinstance(value[key], list)
            or not value[key]
            or any(not isinstance(item, str) or not item for item in value[key])
        ):
            raise CoordinationError("HOSTED_SCOPE_INVALID")

    def walk(item: object) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or FORBIDDEN_SCOPE_KEYS.search(key):
                    raise CoordinationError("HOSTED_SCOPE_SECRET_FIELD")
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif item is not None and not isinstance(item, (str, int, bool)):
            raise CoordinationError("HOSTED_SCOPE_INVALID")

    walk(value)

    operation_tuple = (provider, target_kind, operation_kind)
    if operation_tuple == ("github", "github_ruleset", "UPDATE_SETTINGS"):
        target = _require_shape(
            value["target"],
            required={"repository", "ruleset_id"},
            allowed={"repository", "ruleset_id", "ruleset_name", "ruleset_target"},
        )
        expected = _require_shape(
            value["expected_state"],
            required={"enforcement", "include", "required_status_check"},
            allowed={
                "enforcement", "include", "exclude", "required_status_check",
                "required_approving_review_count", "dismiss_stale_reviews_on_push",
                "required_review_thread_resolution", "independent_approval", "retain_rules",
            },
        )
        desired = _require_shape(
            value["desired_state"],
            required={
                "enforcement", "include", "required_status_check",
                "required_approving_review_count",
            },
            allowed={
                "enforcement", "include", "exclude", "required_status_check",
                "required_approving_review_count", "dismiss_stale_reviews_on_push",
                "required_review_thread_resolution", "independent_approval", "retain_rules",
            },
        )
        if (
            not isinstance(target["repository"], str)
            or not REPOSITORY.fullmatch(target["repository"])
            or type(target["ruleset_id"]) is not int
            or target["ruleset_id"] <= 0
            or target_key != str(target["ruleset_id"])
            or not isinstance(expected["include"], list)
            or not isinstance(desired["include"], list)
            or not isinstance(desired["required_status_check"], str)
            or type(desired["required_approving_review_count"]) is not int
        ):
            raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")
    elif operation_tuple == ("github", "github_environment", "CREATE_SETTINGS"):
        target = _require_shape(
            value["target"],
            required={"repository", "environment"},
            allowed={"repository", "environment"},
        )
        expected = _require_shape(
            value["expected_state"], required={"exists"}, allowed={"exists"}
        )
        desired = _require_shape(
            value["desired_state"],
            required={"deployment_branch", "required_reviewer", "environment_values_configured"},
            allowed={"deployment_branch", "required_reviewer", "environment_values_configured"},
        )
        if (
            not isinstance(target["repository"], str)
            or not REPOSITORY.fullmatch(target["repository"])
            or not isinstance(target["environment"], str)
            or not target["environment"]
            or target_key != f"{target['repository']}:{target['environment']}"
            or type(expected["exists"]) is not bool
            or not isinstance(desired["deployment_branch"], str)
            or not isinstance(desired["required_reviewer"], str)
            or type(desired["environment_values_configured"]) is not bool
        ):
            raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")
    elif operation_tuple == ("github", "github_billing_budget", "UPDATE_SETTINGS"):
        target = _require_shape(
            value["target"],
            required={"organization", "budget_id"},
            allowed={"organization", "budget_id"},
        )
        expected = _require_shape(
            value["expected_state"],
            required={"amount", "prevent_further_usage", "alert_config_sha256"},
            allowed={"amount", "prevent_further_usage", "alert_config_sha256"},
        )
        desired = _require_shape(
            value["desired_state"],
            required={"amount", "prevent_further_usage", "preserve_alerting"},
            allowed={"amount", "prevent_further_usage", "preserve_alerting"},
        )
        if (
            not isinstance(target["organization"], str)
            or not target["organization"]
            or not isinstance(target["budget_id"], str)
            or not target["budget_id"]
            or target_key != f"{target['organization']}:{target['budget_id']}"
            or type(expected["amount"]) is not int
            or expected["amount"] <= 0
            or type(expected["prevent_further_usage"]) is not bool
            or not isinstance(expected["alert_config_sha256"], str)
            or not SHA256.fullmatch(expected["alert_config_sha256"])
            or type(desired["amount"]) is not int
            or desired["amount"] <= 0
            or type(desired["prevent_further_usage"]) is not bool
            or desired["preserve_alerting"] is not True
        ):
            raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")
    elif operation_tuple == ("github", "github_actions_rerun", "RERUN_WORKFLOW"):
        target = _require_shape(
            value["target"],
            required={
                "repository", "pull_request_number", "workflow_path", "workflow_run_id",
                "run_attempt", "check_suite_id", "head_sha", "base_sha", "workflow_sha",
            },
            allowed={
                "repository", "pull_request_number", "workflow_path", "workflow_run_id",
                "run_attempt", "check_suite_id", "head_sha", "base_sha", "workflow_sha",
            },
        )
        expected = _require_shape(
            value["expected_state"],
            required={
                "pull_request_state", "draft", "ready_generation",
                "classifier_conclusion", "classifier_runner_id",
                "classifier_runner_name_present", "classifier_step_count",
                "log_count", "annotation_count", "artifact_count",
                "substantive_jobs", "cancellation_reason", "cancellation_ambiguous",
                "local_gate_id", "local_gate_evidence_sha256",
                "local_gate_receipt_sha256", "guarded_publication_id",
                "guarded_publication_receipt_sha256",
                "provider_restoration_operation_id", "provider_restoration_target_key",
                "provider_restoration_receipt_sha256", "failed_run_completed_at",
                "provider_restoration_minimum_amount",
            },
            allowed={
                "pull_request_state", "draft", "ready_generation",
                "classifier_conclusion", "classifier_runner_id",
                "classifier_runner_name_present", "classifier_step_count",
                "log_count", "annotation_count", "artifact_count",
                "substantive_jobs", "cancellation_reason", "cancellation_ambiguous",
                "local_gate_id", "local_gate_evidence_sha256",
                "local_gate_receipt_sha256", "guarded_publication_id",
                "guarded_publication_receipt_sha256",
                "provider_restoration_operation_id", "provider_restoration_target_key",
                "provider_restoration_receipt_sha256", "failed_run_completed_at",
                "provider_restoration_minimum_amount", "infrastructure_annotations",
            },
        )
        desired = _require_shape(
            value["desired_state"],
            required={
                "endpoint", "next_run_attempt", "preserve_workflow_run_id",
                "preserve_check_suite_id", "rerun_once", "repeat_local_gate",
            },
            allowed={
                "endpoint", "next_run_attempt", "preserve_workflow_run_id",
                "preserve_check_suite_id", "rerun_once", "repeat_local_gate",
            },
        )
        substantive_jobs = expected["substantive_jobs"]
        if (
            not isinstance(target["repository"], str)
            or not REPOSITORY.fullmatch(target["repository"])
            or type(target["pull_request_number"]) is not int
            or target["pull_request_number"] <= 0
            or not isinstance(target["workflow_path"], str)
            or not target["workflow_path"].startswith(".github/workflows/")
            or type(target["workflow_run_id"]) is not int
            or target["workflow_run_id"] <= 0
            or target["run_attempt"] != 1
            or type(target["check_suite_id"]) is not int
            or target["check_suite_id"] <= 0
            or any(
                not isinstance(target[key], str) or not GIT_SHA.fullmatch(target[key])
                for key in ("head_sha", "base_sha", "workflow_sha")
            )
            or target_key
            != (
                f"{target['repository']}:pr:{target['pull_request_number']}:"
                f"run:{target['workflow_run_id']}:attempt:1"
            )
            or expected["pull_request_state"] != "OPEN"
            or expected["draft"] is not False
            or type(expected["ready_generation"]) is not int
            or expected["ready_generation"] <= 0
            or expected["classifier_conclusion"] != "cancelled"
            or expected["classifier_runner_id"] != 0
            or expected["classifier_runner_name_present"] is not False
            or any(
                expected[key] != 0
                for key in (
                    "classifier_step_count", "log_count", "artifact_count"
                )
            )
            or not isinstance(substantive_jobs, dict)
            or not substantive_jobs
            or any(
                not isinstance(name, str) or not name or conclusion != "skipped"
                for name, conclusion in substantive_jobs.items()
            )
            or list(substantive_jobs) != sorted(substantive_jobs)
            or expected["cancellation_reason"] != "HOSTED_RUNNER_NOT_ACQUIRED"
            or expected["cancellation_ambiguous"] is not False
            or type(expected["local_gate_id"]) is not int
            or expected["local_gate_id"] <= 0
            or type(expected["guarded_publication_id"]) is not int
            or expected["guarded_publication_id"] <= 0
            or type(expected["provider_restoration_operation_id"]) is not int
            or expected["provider_restoration_operation_id"] <= 0
            or not isinstance(expected["provider_restoration_target_key"], str)
            or not expected["provider_restoration_target_key"].startswith(
                f"{target['repository'].split('/', 1)[0]}:"
            )
            or type(expected["provider_restoration_minimum_amount"]) is not int
            or expected["provider_restoration_minimum_amount"] <= 0
            or any(
                not isinstance(expected[key], str) or not SHA256.fullmatch(expected[key])
                for key in (
                    "local_gate_evidence_sha256",
                    "local_gate_receipt_sha256",
                    "guarded_publication_receipt_sha256",
                    "provider_restoration_receipt_sha256",
                )
            )
            or desired["endpoint"] != "RERUN_SAME_WORKFLOW_RUN"
            or desired["next_run_attempt"] != 2
            or desired["preserve_workflow_run_id"] is not True
            or desired["preserve_check_suite_id"] is not True
            or desired["rerun_once"] is not True
            or desired["repeat_local_gate"] is not False
        ):
            raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")
        _validate_rerun_annotations(expected)
        _parse_timestamp(expected["failed_run_completed_at"])
    elif operation_tuple == ("google_cloud", "gcp_project_inventory", "READ_METADATA"):
        target = _require_shape(
            value["target"], required={"project_ids"}, allowed={"project_ids"}
        )
        expected = _require_shape(
            value["expected_state"],
            required={"authenticated_account_sha256"},
            allowed={"authenticated_account_sha256"},
        )
        desired = _require_shape(
            value["desired_state"],
            required={"metadata_categories", "read_only"},
            allowed={"metadata_categories", "read_only"},
        )
        projects = target["project_ids"]
        if (
            not isinstance(projects, list)
            or not projects
            or any(not isinstance(item, str) or not item for item in projects)
            or projects != sorted(set(projects))
            or target_key != ",".join(projects)
            or not isinstance(expected["authenticated_account_sha256"], str)
            or not SHA256.fullmatch(expected["authenticated_account_sha256"])
            or not isinstance(desired["metadata_categories"], list)
            or not desired["metadata_categories"]
            or any(not isinstance(item, str) for item in desired["metadata_categories"])
            or desired["metadata_categories"] != sorted(set(desired["metadata_categories"]))
            or not set(desired["metadata_categories"]).issubset(GCP_METADATA_CATEGORIES)
            or desired["read_only"] is not True
        ):
            raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")
    elif operation_tuple == ("supabase", "supabase_project_inventory", "READ_METADATA"):
        target = _require_shape(
            value["target"],
            required={"project_id", "region"},
            allowed={"project_id", "region"},
        )
        expected = _require_shape(
            value["expected_state"],
            required={"status", "project_fingerprint"},
            allowed={"status", "project_fingerprint"},
        )
        desired = _require_shape(
            value["desired_state"],
            required={"metadata_categories", "read_only"},
            allowed={"metadata_categories", "read_only"},
        )
        if (
            not isinstance(target["project_id"], str)
            or not target["project_id"]
            or target_key != target["project_id"]
            or not isinstance(target["region"], str)
            or not target["region"]
            or not isinstance(expected["status"], str)
            or not expected["status"]
            or not isinstance(expected["project_fingerprint"], str)
            or not expected["project_fingerprint"]
            or not isinstance(desired["metadata_categories"], list)
            or not desired["metadata_categories"]
            or any(not isinstance(item, str) for item in desired["metadata_categories"])
            or desired["metadata_categories"] != sorted(set(desired["metadata_categories"]))
            or not set(desired["metadata_categories"]).issubset(SUPABASE_METADATA_CATEGORIES)
            or desired["read_only"] is not True
        ):
            raise CoordinationError("HOSTED_SCOPE_CLASS_INVALID")
    else:
        raise CoordinationError("HOSTED_TRANSACTION_INVALID")
    return value


class HostedOperationControl:
    def __init__(self, database: Path = DEFAULT_DATABASE) -> None:
        self.store = CoordinationStore(database)
        self.connection = self.store.connection
        self._create_schema()

    def close(self) -> None:
        self.store.close()

    def _create_schema(self) -> None:
        with self.store.transaction():
            columns = {
                row[1]
                for row in self.connection.execute(
                    "PRAGMA table_info(hosted_operations)"
                ).fetchall()
            }
            if columns and "object_kind" not in columns:
                count = self.connection.execute(
                    "SELECT COUNT(*) FROM hosted_operations"
                ).fetchone()[0]
                if count:
                    raise CoordinationError("HOSTED_SCHEMA_MIGRATION_REQUIRED")
                self.connection.execute("DROP TABLE hosted_operations")
            self.connection.execute(
                """
                CREATE TABLE IF NOT EXISTS hosted_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    repository TEXT NOT NULL,
                    object_kind TEXT NOT NULL CHECK(object_kind = 'issue'),
                    issue_number INTEGER NOT NULL CHECK(issue_number > 0),
                    source_payload_sha256 TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    operation_kind TEXT NOT NULL,
                    authority_comment_id INTEGER NOT NULL CHECK(authority_comment_id > 0),
                    authority_body_sha256 TEXT NOT NULL,
                    scope_sha256 TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    recipient_session_id TEXT NOT NULL,
                    sre_units INTEGER NOT NULL CHECK(sre_units IN (0, 1)),
                    blocked_by_issue_number INTEGER,
                    state TEXT NOT NULL CHECK(state IN ('WAITING','PREPARED','CLAIMED','COMPLETE','HOLD')),
                    claimed_by TEXT,
                    receipt_outbox_id INTEGER,
                    remote_receipt TEXT,
                    receipt_outcome TEXT,
                    receipt_payload_sha256 TEXT,
                    retired_by_idempotency_key TEXT,
                    retired_at TEXT,
                    last_wake_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT,
                    FOREIGN KEY(repository, object_kind, issue_number, source_payload_sha256)
                        REFERENCES github_snapshots(repository, object_kind, object_number, payload_sha256)
                )
                """
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS hosted_operations_state_idx ON hosted_operations(state, id)"
            )
            columns = {
                row[1]
                for row in self.connection.execute(
                    "PRAGMA table_info(hosted_operations)"
                ).fetchall()
            }
            if "receipt_outcome" not in columns:
                self.connection.execute(
                    "ALTER TABLE hosted_operations ADD COLUMN receipt_outcome TEXT"
                )
            if "receipt_payload_sha256" not in columns:
                self.connection.execute(
                    "ALTER TABLE hosted_operations ADD COLUMN receipt_payload_sha256 TEXT"
                )
            if "retired_by_idempotency_key" not in columns:
                self.connection.execute(
                    "ALTER TABLE hosted_operations ADD COLUMN retired_by_idempotency_key TEXT"
                )
            if "retired_at" not in columns:
                self.connection.execute(
                    "ALTER TABLE hosted_operations ADD COLUMN retired_at TEXT"
                )
            self.connection.execute(
                "DROP INDEX IF EXISTS hosted_operations_actions_rerun_target_uq"
            )
            self.connection.execute(
                """
                CREATE UNIQUE INDEX hosted_operations_actions_rerun_target_uq
                ON hosted_operations(repository, target_kind, target_key, operation_kind)
                WHERE target_kind='github_actions_rerun'
                  AND NOT (
                    state='HOLD' AND claimed_by IS NULL
                    AND receipt_outbox_id IS NULL AND remote_receipt IS NULL
                    AND receipt_outcome IS NULL AND receipt_payload_sha256 IS NULL
                  )
                """
            )

    def _validate_source(self, repository: str, issue_number: int, digest: str) -> None:
        if not REPOSITORY.fullmatch(repository) or issue_number <= 0:
            raise CoordinationError("HOSTED_SOURCE_INVALID")
        _validate_sha(digest)
        current = self.store.current_snapshot(repository, "issue", issue_number)
        if current is None or current.payload_sha256 != digest:
            raise CoordinationError("HOSTED_SOURCE_DRIFT")

    @staticmethod
    def _fetch_authority_comment(
        repository: str, issue_number: int, comment_id: int
    ) -> dict[str, Any]:
        completed = subprocess.run(
            ["gh", "api", f"repos/{repository}/issues/comments/{comment_id}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise CoordinationError("HOSTED_AUTHORITY_UNAVAILABLE")
        try:
            comment = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise CoordinationError("HOSTED_AUTHORITY_INVALID") from exc
        issue_url = comment.get("issue_url") if isinstance(comment, dict) else None
        if (
            not isinstance(comment, dict)
            or not isinstance(comment.get("body"), str)
            or not isinstance(issue_url, str)
            or not issue_url.endswith(f"/repos/{repository}/issues/{issue_number}")
        ):
            raise CoordinationError("HOSTED_AUTHORITY_INVALID")
        return comment

    def _validate_authority(
        self,
        repository: str,
        issue_number: int,
        comment_id: int,
        body_sha256: str,
    ) -> None:
        _validate_sha(body_sha256)
        comment = self._fetch_authority_comment(repository, issue_number, comment_id)
        if _sha256_text(comment["body"]) != body_sha256:
            raise CoordinationError("HOSTED_AUTHORITY_DRIFT")

    def _validate_approval_guard(
        self,
        *,
        repository: str,
        issue_number: int,
        operation_kind: str,
        execution_scope_sha256: str,
        authority_comment_id: int,
        required: bool,
    ) -> None:
        if operation_kind not in MUTATING_OPERATIONS:
            return
        endpoint = current_endpoint(self.connection, "sre")
        requested = (
            str(endpoint["endpoint_id"])
            if endpoint is not None
            else next(
                alias for alias, role in load_legacy_aliases().aliases.items()
                if role == "sre"
            )
        )
        candidates: list[str] = []
        if self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='approval_interests'"
        ).fetchone():
            candidates = [
                str(row[0])
                for row in self.connection.execute(
                    """
                    SELECT DISTINCT i.recipient_session_id
                    FROM approval_current c
                    JOIN approval_proposals p USING(proposal_sha256)
                    JOIN approval_interests i USING(proposal_sha256)
                    WHERE p.repository=? AND p.owning_issue=?
                    """,
                    (repository, issue_number),
                ).fetchall()
            ]
        recipient = select_role_equivalent_identity(
            self.connection, requested, candidates
        )
        try:
            require_effective_approval(
                self.connection,
                repository=repository,
                issue_number=issue_number,
                recipient_session_id=recipient,
                execution_scope_sha256=execution_scope_sha256,
                authority_comment_id=authority_comment_id,
                required=required,
            )
        except ApprovalGuardError as exc:
            raise CoordinationError(str(exc)) from exc

    def _blocker_terminal(self, repository: str, issue_number: int | None) -> bool:
        if issue_number is None:
            return True
        row = self.connection.execute(
            "SELECT status, allocation_class FROM coordination_items WHERE repository=? AND issue_number=?",
            (repository, issue_number),
        ).fetchone()
        return bool(row and row["status"] == "DONE" and row["allocation_class"] == "NONE")

    def _validate_claim_local_state(self, row: Any) -> None:
        """Revalidate every SQLite-owned claim guard under one write transaction."""
        scope = self._validate_persisted_operation(row)
        self._validate_operation_evidence(
            repository=row["repository"],
            issue_number=int(row["issue_number"]),
            provider=row["provider"],
            target_kind=row["target_kind"],
            operation_kind=row["operation_kind"],
            scope=scope,
        )
        self._validate_source(
            row["repository"], row["issue_number"], row["source_payload_sha256"]
        )
        if not self._blocker_terminal(
            row["repository"], row["blocked_by_issue_number"]
        ):
            raise CoordinationError("HOSTED_BLOCKER_NOT_TERMINAL")
        if self._reserved_sre(row["repository"]) > self._sre_limit(row["repository"]):
            raise CoordinationError("HOSTED_SRE_CAPACITY_EXCEEDED")
        self._validate_approval_guard(
            repository=row["repository"],
            issue_number=row["issue_number"],
            operation_kind=row["operation_kind"],
            execution_scope_sha256=hosted_execution_scope_sha256(
                provider=row["provider"],
                target_kind=row["target_kind"],
                target_key=row["target_key"],
                operation_kind=row["operation_kind"],
                scope=scope,
            ),
            authority_comment_id=row["authority_comment_id"],
            required=False,
        )

    def _validate_persisted_operation(self, row: Any) -> dict[str, Any]:
        operation_tuple = (row["provider"], row["target_kind"], row["operation_kind"])
        try:
            require_current_endpoint_identity(
                self.connection,
                str(row["recipient_session_id"]),
                expected_role="sre",
            )
            recipient_is_current = True
        except RegistryError:
            recipient_is_current = False
        if (
            not recipient_is_current
            or not isinstance(row["repository"], str)
            or not REPOSITORY.fullmatch(row["repository"])
            or operation_tuple not in ALLOWED_OPERATION_TARGETS
            or not isinstance(row["target_key"], str)
            or not row["target_key"]
            or type(row["sre_units"]) is not int
            or row["sre_units"] not in {0, 1}
            or (row["operation_kind"] in MUTATING_OPERATIONS and row["sre_units"] != 1)
            or (row["operation_kind"] == "READ_METADATA" and row["sre_units"] != 0)
        ):
            raise CoordinationError("HOSTED_PERSISTED_TRANSACTION_INVALID")
        _validate_sha(row["source_payload_sha256"])
        _validate_sha(row["authority_body_sha256"])
        _validate_sha(row["scope_sha256"])
        try:
            scope = _validate_scope(
                json.loads(row["scope_json"]),
                provider=row["provider"],
                target_kind=row["target_kind"],
                operation_kind=row["operation_kind"],
                target_key=row["target_key"],
            )
        except (json.JSONDecodeError, TypeError) as exc:
            raise CoordinationError("HOSTED_SCOPE_INVALID") from exc
        if digest_json(scope) != row["scope_sha256"]:
            raise CoordinationError("HOSTED_SCOPE_DRIFT")
        return scope

    def _validate_operation_evidence(
        self,
        *,
        repository: str,
        issue_number: int,
        provider: str,
        target_kind: str,
        operation_kind: str,
        scope: dict[str, Any],
    ) -> None:
        if (provider, target_kind, operation_kind) != (
            "github",
            "github_actions_rerun",
            "RERUN_WORKFLOW",
        ):
            return
        target = scope["target"]
        expected = scope["expected_state"]
        gate = self.connection.execute(
            "SELECT * FROM coordination_pre_push_gates WHERE id=?",
            (expected["local_gate_id"],),
        ).fetchone()
        if (
            gate is None
            or gate["repository"] != repository
            or int(gate["issue_number"]) != issue_number
            or gate["base_sha"] != target["base_sha"]
            or gate["head_sha"] != target["head_sha"]
            or gate["state"] != "PASS"
            or gate["lower_gate_exit_code"] != 0
            or gate["compose_gate_exit_code"] != 0
            or int(gate["head_unchanged"]) != 1
            or int(gate["cleanup_proven"]) != 1
            or gate["evidence_sha256"] != expected["local_gate_evidence_sha256"]
            or digest_json(dict(gate)) != expected["local_gate_receipt_sha256"]
        ):
            raise CoordinationError("HOSTED_RERUN_LOCAL_GATE_EVIDENCE_INVALID")
        publication = self.connection.execute(
            "SELECT * FROM coordination_pre_push_publications WHERE id=?",
            (expected["guarded_publication_id"],),
        ).fetchone()
        if (
            publication is None
            or int(publication["gate_id"]) != int(gate["id"])
            or publication["repository"] != repository
            or int(publication["issue_number"]) != issue_number
            or publication["head_sha"] != target["head_sha"]
            or publication["state"] != "COMPLETE"
            or digest_json(dict(publication))
            != expected["guarded_publication_receipt_sha256"]
        ):
            raise CoordinationError("HOSTED_RERUN_PUBLICATION_EVIDENCE_INVALID")
        restoration = self.connection.execute(
            "SELECT * FROM hosted_operations WHERE id=?",
            (expected["provider_restoration_operation_id"],),
        ).fetchone()
        if (
            restoration is None
            or restoration["repository"] != repository
            or int(restoration["issue_number"]) != issue_number
            or restoration["provider"] != "github"
            or restoration["target_kind"] != "github_billing_budget"
            or restoration["target_key"] != expected["provider_restoration_target_key"]
            or restoration["operation_kind"] != "UPDATE_SETTINGS"
            or restoration["state"] != "COMPLETE"
            or restoration["receipt_outcome"] != "SUCCESS"
            or restoration["receipt_payload_sha256"]
            != expected["provider_restoration_receipt_sha256"]
        ):
            raise CoordinationError("HOSTED_RERUN_PROVIDER_RESTORATION_INVALID")
        restoration_scope = self._validate_persisted_operation(restoration)
        if _parse_timestamp(restoration["updated_at"]) <= _parse_timestamp(
            expected["failed_run_completed_at"]
        ):
            raise CoordinationError("HOSTED_RERUN_PROVIDER_RESTORATION_STALE")
        outbox = self.connection.execute(
            "SELECT * FROM github_outbox WHERE id=?",
            (restoration["receipt_outbox_id"],),
        ).fetchone()
        if outbox is None or outbox["state"] != "COMPLETE":
            raise CoordinationError("HOSTED_RERUN_PROVIDER_RESTORATION_INVALID")
        try:
            body = json.loads(outbox["payload_json"]).get("body")
        except (json.JSONDecodeError, AttributeError) as exc:
            raise CoordinationError("HOSTED_RERUN_PROVIDER_RESTORATION_INVALID") from exc
        restoration_receipt = self._validate_receipt(body, restoration)
        if (
            digest_json(restoration_receipt) != restoration["receipt_payload_sha256"]
            or digest_json(restoration_receipt)
            != expected["provider_restoration_receipt_sha256"]
        ):
            raise CoordinationError("HOSTED_RERUN_PROVIDER_RESTORATION_RECEIPT_DRIFT")
        result = restoration_receipt["result"]
        if (
            result["capacity_restored"] is not True
            or result["amount"] < expected["provider_restoration_minimum_amount"]
            or result["prevent_further_usage"] is not True
            or result["alert_config_sha256"]
            != restoration_scope["expected_state"]["alert_config_sha256"]
        ):
            raise CoordinationError("HOSTED_RERUN_PROVIDER_CAPACITY_NOT_RESTORED")

    def _reserved_sre(self, repository: str) -> int:
        issue_units = self.connection.execute(
            """
            SELECT COALESCE(SUM(sre_units), 0)
            FROM coordination_items
            WHERE repository=? AND allocation_class IN ('ACTIVE','RETAINED')
            """,
            (repository,),
        ).fetchone()[0]
        hosted_units = self.connection.execute(
            """
            SELECT COALESCE(SUM(sre_units), 0)
            FROM hosted_operations
            WHERE repository=? AND state IN ('PREPARED','CLAIMED')
            """,
            (repository,),
        ).fetchone()[0]
        return int(issue_units) + int(hosted_units)

    def _sre_limit(self, repository: str) -> int:
        return int(self.store.capacity_policy(repository)["sre_limit"])

    @staticmethod
    def _validate_transaction_shape(transaction: dict[str, Any]) -> None:
        required = {
            "idempotency_key",
            "repository",
            "issue_number",
            "source_payload_sha256",
            "provider",
            "target_kind",
            "target_key",
            "operation_kind",
            "authority_comment_id",
            "authority_body_sha256",
            "recipient_session_id",
            "sre_units",
            "blocked_by_issue_number",
            "scope",
        }
        if not isinstance(transaction, dict) or set(transaction) != required:
            raise CoordinationError("HOSTED_TRANSACTION_INVALID")
        issue_number = transaction["issue_number"]
        if (
            not isinstance(transaction["idempotency_key"], str)
            or not transaction["idempotency_key"]
            or not isinstance(issue_number, int)
            or transaction["provider"] not in PROVIDERS
            or transaction["target_kind"] not in TARGET_KINDS
            or not isinstance(transaction["target_key"], str)
            or not transaction["target_key"]
            or transaction["operation_kind"] not in OPERATION_KINDS
            or (
                transaction["provider"],
                transaction["target_kind"],
                transaction["operation_kind"],
            )
            not in ALLOWED_OPERATION_TARGETS
            or configured_identity_role(transaction["recipient_session_id"]) != "sre"
            or type(transaction["sre_units"]) is not int
            or transaction["sre_units"] not in {0, 1}
            or (
                transaction["operation_kind"] in MUTATING_OPERATIONS
                and transaction["sre_units"] != 1
            )
            or (
                transaction["operation_kind"] == "READ_METADATA"
                and transaction["sre_units"] != 0
            )
            or (
                transaction["blocked_by_issue_number"] is not None
                and (
                    type(transaction["blocked_by_issue_number"]) is not int
                    or transaction["blocked_by_issue_number"] <= 0
                )
            )
        ):
            raise CoordinationError("HOSTED_TRANSACTION_INVALID")

    @staticmethod
    def _validate_authority_snapshot(
        transaction: dict[str, Any],
        authority_comment: object,
        authority_comment_sha256: str,
    ) -> None:
        _validate_sha(authority_comment_sha256)
        if (
            not isinstance(authority_comment, dict)
            or digest_json(authority_comment) != authority_comment_sha256
        ):
            raise CoordinationError("HOSTED_AUTHORITY_INPUT_DRIFT")
        issue_url = authority_comment.get("issue_url")
        if (
            authority_comment.get("id") != transaction["authority_comment_id"]
            or not isinstance(authority_comment.get("body"), str)
            or not isinstance(issue_url, str)
            or not issue_url.endswith(
                f"/repos/{transaction['repository']}/issues/{transaction['issue_number']}"
            )
            or _sha256_text(authority_comment["body"])
            != transaction["authority_body_sha256"]
        ):
            raise CoordinationError("HOSTED_AUTHORITY_DRIFT")

    @staticmethod
    def _eligible_rerun_predecessor(row: Any) -> bool:
        return bool(
            row["state"] == "HOLD"
            and row["claimed_by"] is None
            and row["receipt_outbox_id"] is None
            and row["remote_receipt"] is None
            and row["receipt_outcome"] is None
            and row["receipt_payload_sha256"] is None
        )

    def prepare_in_transaction(
        self,
        transaction: dict[str, Any],
        now: str,
        *,
        authority_comment: object,
        authority_comment_sha256: str,
        retire_eligible_predecessors: bool = False,
        require_prepared: bool = False,
        before_apply: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Validate and prepare one hosted operation in the caller's transaction."""

        if not self.connection.in_transaction:
            raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
        transaction = dict(transaction)
        transaction["recipient_session_id"] = canonicalize_coordination_identity(
            self.connection, transaction.get("recipient_session_id", "")
        )
        self._validate_transaction_shape(transaction)
        repository = transaction["repository"]
        issue_number = transaction["issue_number"]
        self._validate_source(repository, issue_number, transaction["source_payload_sha256"])
        self._validate_authority_snapshot(
            transaction, authority_comment, authority_comment_sha256
        )
        scope = _validate_scope(
            transaction["scope"],
            provider=transaction["provider"],
            target_kind=transaction["target_kind"],
            operation_kind=transaction["operation_kind"],
            target_key=transaction["target_key"],
        )
        scope_json = canonical_json(scope)
        scope_sha256 = digest_json(scope)
        approval_scope_sha256 = hosted_execution_scope_sha256(
            provider=transaction["provider"],
            target_kind=transaction["target_kind"],
            target_key=transaction["target_key"],
            operation_kind=transaction["operation_kind"],
            scope=scope,
        )
        current = self.connection.execute(
            "SELECT * FROM hosted_operations WHERE idempotency_key=?",
            (transaction["idempotency_key"],),
        ).fetchone()
        self._validate_approval_guard(
            repository=repository,
            issue_number=issue_number,
            operation_kind=transaction["operation_kind"],
            execution_scope_sha256=approval_scope_sha256,
            authority_comment_id=transaction["authority_comment_id"],
            required=current is None,
        )
        state = (
            "PREPARED"
            if self._blocker_terminal(repository, transaction["blocked_by_issue_number"])
            else "WAITING"
        )
        if require_prepared and state != "PREPARED":
            raise CoordinationError("HOSTED_CLEARANCE_NOT_PREPARED")
        self._validate_operation_evidence(
            repository=repository,
            issue_number=issue_number,
            provider=transaction["provider"],
            target_kind=transaction["target_kind"],
            operation_kind=transaction["operation_kind"],
            scope=scope,
        )
        exact_keys = (
            "repository",
            "issue_number",
            "source_payload_sha256",
            "provider",
            "target_kind",
            "target_key",
            "operation_kind",
            "authority_comment_id",
            "authority_body_sha256",
            "scope_sha256",
            "sre_units",
            "blocked_by_issue_number",
        )
        exact = (
            repository,
            issue_number,
            transaction["source_payload_sha256"],
            transaction["provider"],
            transaction["target_kind"],
            transaction["target_key"],
            transaction["operation_kind"],
            transaction["authority_comment_id"],
            transaction["authority_body_sha256"],
            scope_sha256,
            transaction["sre_units"],
            transaction["blocked_by_issue_number"],
        )
        if current is not None:
            observed = tuple(current[key] for key in exact_keys)
            if observed != exact or not identities_role_equivalent(
                self.connection,
                current["recipient_session_id"],
                transaction["recipient_session_id"],
            ):
                raise CoordinationError("HOSTED_IDEMPOTENCY_CONFLICT")
            if before_apply is not None:
                before_apply()
            return dict(current)

        eligible_predecessors: list[Any] = []
        if transaction["target_kind"] == "github_actions_rerun":
            predecessors = self.connection.execute(
                """
                SELECT * FROM hosted_operations
                WHERE repository=? AND target_kind=? AND target_key=? AND operation_kind=?
                ORDER BY id
                """,
                (
                    repository,
                    transaction["target_kind"],
                    transaction["target_key"],
                    transaction["operation_kind"],
                ),
            ).fetchall()
            eligible_predecessors = [
                row for row in predecessors if self._eligible_rerun_predecessor(row)
            ]
            if len(eligible_predecessors) != len(predecessors):
                raise CoordinationError("HOSTED_RERUN_TARGET_ALREADY_RESERVED")

        if (
            state == "PREPARED"
            and self._reserved_sre(repository) + transaction["sre_units"]
            > self._sre_limit(repository)
        ):
            raise CoordinationError("HOSTED_SRE_CAPACITY_EXCEEDED")

        if before_apply is not None:
            before_apply()

        if retire_eligible_predecessors:
            for predecessor in eligible_predecessors:
                if predecessor["retired_by_idempotency_key"] is not None:
                    continue
                changed = self.connection.execute(
                    """
                    UPDATE hosted_operations
                    SET retired_by_idempotency_key=?, retired_at=?, updated_at=?
                    WHERE id=? AND state='HOLD' AND claimed_by IS NULL
                      AND receipt_outbox_id IS NULL AND remote_receipt IS NULL
                      AND receipt_outcome IS NULL AND receipt_payload_sha256 IS NULL
                      AND retired_by_idempotency_key IS NULL
                    """,
                    (
                        transaction["idempotency_key"],
                        now,
                        now,
                        predecessor["id"],
                    ),
                ).rowcount
                if changed != 1:
                    raise CoordinationError("HOSTED_RERUN_TARGET_ALREADY_RESERVED")
                self.store._event(
                    "HOSTED_RERUN_PREDECESSOR_RETIRED",
                    f"hosted-operation:{predecessor['id']}",
                    {"retired_by_idempotency_key": transaction["idempotency_key"]},
                    now,
                )

        cursor = self.connection.execute(
            """
            INSERT INTO hosted_operations(
                idempotency_key, repository, object_kind, issue_number, source_payload_sha256,
                provider, target_kind, target_key, operation_kind,
                authority_comment_id, authority_body_sha256, scope_sha256,
                scope_json, recipient_session_id, sre_units,
                blocked_by_issue_number, state, created_at, updated_at
            ) VALUES (?, ?, 'issue', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transaction["idempotency_key"], repository, issue_number,
                transaction["source_payload_sha256"], transaction["provider"],
                transaction["target_kind"], transaction["target_key"],
                transaction["operation_kind"], transaction["authority_comment_id"],
                transaction["authority_body_sha256"], scope_sha256, scope_json,
                transaction["recipient_session_id"], transaction["sre_units"],
                transaction["blocked_by_issue_number"], state, now, now,
            )
        )
        self.store._event(
            "HOSTED_OPERATION_PREPARED",
            f"hosted-operation:{cursor.lastrowid}",
            {
                "operation_id": cursor.lastrowid,
                "state": state,
                "scope_sha256": scope_sha256,
                "source_payload_sha256": transaction["source_payload_sha256"],
            },
            now,
        )
        return dict(
            self.connection.execute(
                "SELECT * FROM hosted_operations WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        )

    def prepare(self, transaction: dict[str, Any], now: str) -> dict[str, Any]:
        transaction = dict(transaction)
        transaction["recipient_session_id"] = canonicalize_coordination_identity(
            self.connection, transaction.get("recipient_session_id", "")
        )
        self._validate_transaction_shape(transaction)
        self._validate_source(
            transaction["repository"],
            transaction["issue_number"],
            transaction["source_payload_sha256"],
        )
        authority_comment = self._fetch_authority_comment(
            transaction["repository"],
            transaction["issue_number"],
            transaction["authority_comment_id"],
        )
        authority_comment_sha256 = digest_json(authority_comment)
        with self.store.transaction():
            return self.prepare_in_transaction(
                transaction,
                now,
                authority_comment=authority_comment,
                authority_comment_sha256=authority_comment_sha256,
            )

    def refresh_waiting(self, now: str) -> list[int]:
        promoted: list[int] = []
        rows = self.connection.execute(
            "SELECT * FROM hosted_operations WHERE state='WAITING' ORDER BY id"
        ).fetchall()
        for row in rows:
            if not self._blocker_terminal(row["repository"], row["blocked_by_issue_number"]):
                continue
            try:
                scope = self._validate_persisted_operation(row)
                self._validate_operation_evidence(
                    repository=row["repository"],
                    issue_number=int(row["issue_number"]),
                    provider=row["provider"],
                    target_kind=row["target_kind"],
                    operation_kind=row["operation_kind"],
                    scope=scope,
                )
                self._validate_source(
                    row["repository"], row["issue_number"], row["source_payload_sha256"]
                )
                self._validate_authority(
                    row["repository"], row["issue_number"], row["authority_comment_id"],
                    row["authority_body_sha256"],
                )
                self._validate_approval_guard(
                    repository=row["repository"],
                    issue_number=row["issue_number"],
                    operation_kind=row["operation_kind"],
                    execution_scope_sha256=hosted_execution_scope_sha256(
                        provider=row["provider"],
                        target_kind=row["target_kind"],
                        target_key=row["target_key"],
                        operation_kind=row["operation_kind"],
                        scope=scope,
                    ),
                    authority_comment_id=row["authority_comment_id"],
                    required=False,
                )
            except CoordinationError as exc:
                self.hold(row["id"], str(exc), now)
                continue
            with self.store.transaction():
                current = self.connection.execute(
                    "SELECT * FROM hosted_operations WHERE id=?", (row["id"],)
                ).fetchone()
                if current is None or current["state"] != "WAITING":
                    continue
                try:
                    current_scope = self._validate_persisted_operation(current)
                    self._validate_operation_evidence(
                        repository=current["repository"],
                        issue_number=int(current["issue_number"]),
                        provider=current["provider"],
                        target_kind=current["target_kind"],
                        operation_kind=current["operation_kind"],
                        scope=current_scope,
                    )
                except CoordinationError as exc:
                    normalized = (
                        str(exc)
                        if re.fullmatch(r"[A-Z][A-Z0-9_]*", str(exc))
                        else "HOSTED_OPERATION_HELD"
                    )
                    self.connection.execute(
                        """
                        UPDATE hosted_operations
                        SET state='HOLD', updated_at=?, last_error=?
                        WHERE id=? AND state='WAITING'
                        """,
                        (now, normalized, row["id"]),
                    )
                    self.store._event(
                        "HOSTED_OPERATION_HELD",
                        f"hosted-operation:{row['id']}",
                        {"operation_id": row["id"], "error": normalized},
                        now,
                    )
                    continue
                if (
                    self._reserved_sre(row["repository"]) + int(row["sre_units"])
                    > self._sre_limit(row["repository"])
                ):
                    continue
                changed = self.connection.execute(
                    "UPDATE hosted_operations SET state='PREPARED', updated_at=? WHERE id=? AND state='WAITING'",
                    (now, row["id"]),
                ).rowcount
                if changed:
                    self.store._event(
                        "HOSTED_OPERATION_PROMOTED",
                        f"hosted-operation:{row['id']}",
                        {"operation_id": row["id"], "state": "PREPARED"},
                        now,
                    )
                    promoted.append(int(row["id"]))
        return promoted

    def claim(self, operation_id: int, session_id: str, now: str) -> dict[str, Any]:
        if coordination_identity_role(self.connection, session_id) != "sre":
            raise CoordinationError("HOSTED_RECIPIENT_MISMATCH")
        session_id = canonicalize_coordination_identity(self.connection, session_id)
        row = self.connection.execute(
            "SELECT * FROM hosted_operations WHERE id=?", (operation_id,)
        ).fetchone()
        if (
            row is None
            or row["state"] != "PREPARED"
            or not identities_role_equivalent(
                self.connection, row["recipient_session_id"], session_id
            )
        ):
            raise CoordinationError("HOSTED_STATE_CONFLICT")
        try:
            scope = self._validate_persisted_operation(row)
            self._validate_source(
                row["repository"], row["issue_number"], row["source_payload_sha256"]
            )
            self._validate_authority(
                row["repository"], row["issue_number"], row["authority_comment_id"],
                row["authority_body_sha256"],
            )
            self._validate_approval_guard(
                repository=row["repository"],
                issue_number=row["issue_number"],
                operation_kind=row["operation_kind"],
                execution_scope_sha256=hosted_execution_scope_sha256(
                    provider=row["provider"],
                    target_kind=row["target_kind"],
                    target_key=row["target_key"],
                    operation_kind=row["operation_kind"],
                    scope=scope,
                ),
                authority_comment_id=row["authority_comment_id"],
                required=False,
            )
            if not self._blocker_terminal(
                row["repository"], row["blocked_by_issue_number"]
            ):
                raise CoordinationError("HOSTED_BLOCKER_NOT_TERMINAL")
        except CoordinationError as exc:
            self.hold(operation_id, str(exc), now)
            raise

        local_error: str | None = None
        with self.store.transaction():
            current = self.connection.execute(
                "SELECT * FROM hosted_operations WHERE id=?", (operation_id,)
            ).fetchone()
            if current is None or current["state"] != "PREPARED":
                raise CoordinationError("HOSTED_STATE_CONFLICT")
            try:
                self._validate_claim_local_state(current)
            except CoordinationError as exc:
                local_error = str(exc)
                changed = self.connection.execute(
                    """
                    UPDATE hosted_operations
                    SET state='HOLD', updated_at=?, last_error=?
                    WHERE id=? AND state='PREPARED'
                    """,
                    (now, local_error, operation_id),
                ).rowcount
                if changed != 1:
                    raise CoordinationError("HOSTED_STATE_CONFLICT")
                self.store._event(
                    "HOSTED_OPERATION_HELD",
                    f"hosted-operation:{operation_id}",
                    {"operation_id": operation_id, "error": local_error},
                    now,
                )
            else:
                changed = self.connection.execute(
                    "UPDATE hosted_operations SET state='CLAIMED', claimed_by=?, updated_at=? WHERE id=? AND state='PREPARED'",
                    (session_id, now, operation_id),
                ).rowcount
                if changed != 1:
                    raise CoordinationError("HOSTED_STATE_CONFLICT")
                self.store._event(
                    "HOSTED_OPERATION_CLAIMED",
                    f"hosted-operation:{operation_id}",
                    {"operation_id": operation_id, "session_id": session_id},
                    now,
                )
                claimed = dict(
                    self.connection.execute(
                        "SELECT * FROM hosted_operations WHERE id=?", (operation_id,)
                    ).fetchone()
                )
        if local_error is not None:
            raise CoordinationError(local_error)
        return claimed

    @staticmethod
    def _validate_receipt(body: object, row: Any) -> dict[str, Any]:
        if not isinstance(body, str):
            raise CoordinationError("HOSTED_RECEIPT_INVALID")
        matches = re.findall(
            r"<!-- twinfinity-hosted-operation-receipt:(\{[^\r\n]*\}) -->",
            body,
        )
        if len(matches) != 1:
            raise CoordinationError("HOSTED_RECEIPT_INVALID")
        try:
            receipt = json.loads(matches[0])
        except json.JSONDecodeError as exc:
            raise CoordinationError("HOSTED_RECEIPT_INVALID") from exc
        required = {
            "schema", "outcome", "operation_id", "idempotency_key_sha256",
            "provider", "target_kind", "target_key", "operation_kind",
            "scope_sha256", "verification", "summary",
        }
        if row["target_kind"] in {"github_actions_rerun", "github_billing_budget"}:
            required.add("result")
        expected_verification = {
            "SUCCESS": "PASS", "FAILURE": "FAIL", "PARTIAL": "PARTIAL"
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != required
            or receipt.get("schema") != "twinfinity.hosted-operation-receipt.v1"
            or receipt.get("outcome") not in RECEIPT_OUTCOMES
            or receipt.get("operation_id") != int(row["id"])
            or receipt.get("idempotency_key_sha256") != _sha256_text(row["idempotency_key"])
            or receipt.get("provider") != row["provider"]
            or receipt.get("target_kind") != row["target_kind"]
            or receipt.get("target_key") != row["target_key"]
            or receipt.get("operation_kind") != row["operation_kind"]
            or receipt.get("scope_sha256") != row["scope_sha256"]
            or receipt.get("verification") != expected_verification.get(receipt.get("outcome"))
            or not isinstance(receipt.get("summary"), str)
            or not receipt["summary"].strip()
        ):
            raise CoordinationError("HOSTED_RECEIPT_INVALID")
        if row["target_kind"] == "github_actions_rerun":
            result = receipt.get("result")
            if (
                not isinstance(result, dict)
                or set(result) != {
                    "workflow_run_id", "run_attempt", "check_suite_id", "job_ids"
                }
                or type(result["workflow_run_id"]) is not int
                or type(result["run_attempt"]) is not int
                or type(result["check_suite_id"]) is not int
                or not isinstance(result["job_ids"], list)
                or any(type(job_id) is not int or job_id <= 0 for job_id in result["job_ids"])
                or result["job_ids"] != sorted(set(result["job_ids"]))
            ):
                raise CoordinationError("HOSTED_RECEIPT_INVALID")
            scope = json.loads(row["scope_json"])
            if (
                result["workflow_run_id"] != scope["target"]["workflow_run_id"]
                or result["check_suite_id"] != scope["target"]["check_suite_id"]
            ):
                raise CoordinationError("HOSTED_RECEIPT_INVALID")
            if receipt["outcome"] == "SUCCESS" and (
                result["run_attempt"] != 2 or not result["job_ids"]
            ):
                raise CoordinationError("HOSTED_RECEIPT_INVALID")
            if receipt["outcome"] != "SUCCESS" and result["run_attempt"] not in {1, 2}:
                raise CoordinationError("HOSTED_RECEIPT_INVALID")
        elif row["target_kind"] == "github_billing_budget":
            result = receipt.get("result")
            if (
                not isinstance(result, dict)
                or set(result) != {
                    "amount", "prevent_further_usage", "alert_config_sha256",
                    "capacity_restored",
                }
                or type(result["amount"]) is not int
                or result["amount"] <= 0
                or type(result["prevent_further_usage"]) is not bool
                or not isinstance(result["alert_config_sha256"], str)
                or not SHA256.fullmatch(result["alert_config_sha256"])
                or type(result["capacity_restored"]) is not bool
            ):
                raise CoordinationError("HOSTED_RECEIPT_INVALID")
            scope = json.loads(row["scope_json"])
            if receipt["outcome"] == "SUCCESS" and (
                result["amount"] != scope["desired_state"]["amount"]
                or result["prevent_further_usage"]
                is not scope["desired_state"]["prevent_further_usage"]
                or result["alert_config_sha256"]
                != scope["expected_state"]["alert_config_sha256"]
            ):
                raise CoordinationError("HOSTED_RECEIPT_INVALID")
        return receipt

    def complete(self, operation_id: int, session_id: str, outbox_id: int, now: str) -> dict[str, Any]:
        if coordination_identity_role(self.connection, session_id) != "sre" or outbox_id <= 0:
            raise CoordinationError("HOSTED_RECIPIENT_MISMATCH")
        session_id = canonicalize_coordination_identity(self.connection, session_id)
        with self.store.transaction():
            row = self.connection.execute(
                "SELECT * FROM hosted_operations WHERE id=?", (operation_id,)
            ).fetchone()
            if (
                row is None
                or row["state"] != "CLAIMED"
                or not identities_role_equivalent(
                    self.connection, row["recipient_session_id"], session_id
                )
                or not identities_role_equivalent(
                    self.connection, row["claimed_by"], session_id
                )
            ):
                raise CoordinationError("HOSTED_STATE_CONFLICT")
            outbox = self.connection.execute(
                "SELECT * FROM github_outbox WHERE id=?", (outbox_id,)
            ).fetchone()
            body = None
            if outbox is not None:
                try:
                    body = json.loads(outbox["payload_json"]).get("body")
                except (json.JSONDecodeError, AttributeError):
                    body = None
            if (
                outbox is None
                or outbox["repository"] != row["repository"]
                or outbox["object_kind"] != "issue"
                or int(outbox["object_number"]) != int(row["issue_number"])
                or outbox["state"] != "COMPLETE"
                or not isinstance(outbox["remote_receipt"], str)
            ):
                raise CoordinationError("HOSTED_RECEIPT_INVALID")
            receipt = self._validate_receipt(body, row)
            target_state = "COMPLETE" if receipt["outcome"] == "SUCCESS" else "HOLD"
            last_error = {
                "SUCCESS": None,
                "FAILURE": "HOSTED_OPERATION_FAILED",
                "PARTIAL": "HOSTED_OPERATION_PARTIAL",
            }[receipt["outcome"]]
            changed = self.connection.execute(
                """
                UPDATE hosted_operations
                SET state=?, receipt_outbox_id=?, remote_receipt=?, receipt_outcome=?,
                    receipt_payload_sha256=?, updated_at=?, last_error=?
                WHERE id=? AND state='CLAIMED' AND claimed_by=?
                """,
                (
                    target_state, outbox_id, outbox["remote_receipt"], receipt["outcome"],
                    digest_json(receipt), now, last_error, operation_id, row["claimed_by"],
                ),
            ).rowcount
            if changed != 1:
                raise CoordinationError("HOSTED_STATE_CONFLICT")
            self.store._event(
                "HOSTED_OPERATION_COMPLETED" if target_state == "COMPLETE" else "HOSTED_OPERATION_TERMINATED",
                f"hosted-operation:{operation_id}",
                {
                    "operation_id": operation_id,
                    "receipt_outbox_id": outbox_id,
                    "outcome": receipt["outcome"],
                    "scope_sha256": row["scope_sha256"],
                },
                now,
            )
            return dict(
                self.connection.execute(
                    "SELECT * FROM hosted_operations WHERE id=?", (operation_id,)
                ).fetchone()
            )

    def hold(self, operation_id: int, error: str, now: str) -> dict[str, Any]:
        normalized = error if re.fullmatch(r"[A-Z][A-Z0-9_]*", error) else "HOSTED_OPERATION_HELD"
        with self.store.transaction():
            changed = self.connection.execute(
                """
                UPDATE hosted_operations
                SET state='HOLD', updated_at=?, last_error=?
                WHERE id=? AND state IN ('WAITING','PREPARED')
                """,
                (now, normalized, operation_id),
            ).rowcount
            if changed != 1:
                raise CoordinationError("HOSTED_STATE_CONFLICT")
            self.store._event(
                "HOSTED_OPERATION_HELD",
                f"hosted-operation:{operation_id}",
                {"operation_id": operation_id, "error": normalized},
                now,
            )
            return dict(
                self.connection.execute(
                    "SELECT * FROM hosted_operations WHERE id=?", (operation_id,)
                ).fetchone()
            )

    def show(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM hosted_operations ORDER BY id"
            ).fetchall()
        ]


def run_supervisor(
    control: HostedOperationControl,
    now: str,
    *,
    launcher: Callable[..., int] = launch_role_executor,
    transport_preflight: Callable[[RoleExecutorTransportPreflight], object]
    | None = None,
) -> dict[str, Any]:
    request: RoleExecutorTransportPreflight | None = None
    attestor = (
        transport_preflight
        if transport_preflight is not None
        else (
            attest_role_executor_transport
            if launcher is launch_role_executor
            else injected_role_executor_transport_attestation
        )
    )
    try:
        request = build_role_executor_transport_preflight(control.connection)
        attestation = attestor(request)
        validate_role_executor_transport_attestation(request, attestation)
        revalidate_role_executor_transport_preflight(
            control.connection, request
        )
    except Exception as exc:
        reason = role_executor_transport_failure_reason(exc)
        notice_message_id = (
            None
            if request is None
            else enqueue_role_executor_transport_failure_notice(
                control.store, request, reason=reason, now=now
            )
        )
        return {
            "phase": "HOLD",
            "promoted": [],
            "launched": [],
            "rejected": [],
            "skipped": [],
            "capacity": {
                "limit": 0,
                "active": 0,
                "pending": 0,
                "reserved": 0,
            },
            "reason": reason,
            "notice_message_id": notice_message_id,
            "transport_preflight": {
                "status": "HOLD",
                "reason": reason,
            },
        }
    promoted = control.refresh_waiting(now)
    endpoint = current_endpoint(control.connection, "sre")
    if endpoint is None:
        return {
            "promoted": promoted,
            "launched": [],
            "rejected": [],
            "skipped": [],
            "reason": "REGISTRY_NOT_MIGRATED",
        }
    endpoint_id = str(endpoint["endpoint_id"])
    reserved: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    capacity_limit = 0
    active_count = 0
    pending_count = 0

    # Reserve every eligible wake in one write transaction. last_wake_at is the
    # durable, cooldown-bound reservation that fences overlapping timer runs
    # until the target-bound executor attempt records its own reservation.
    with control.store.transaction():
        current = current_endpoint(control.connection, "sre")
        if current is None or str(current["endpoint_id"]) != endpoint_id:
            return {
                "promoted": promoted,
                "launched": [],
                "rejected": [],
                "skipped": [],
                "reason": "REGISTRY_ENDPOINT_CHANGED",
            }
        rows = control.connection.execute(
            """
            SELECT h.*,
                   CASE
                     WHEN h.last_wake_at IS NULL THEN 1
                     WHEN julianday(h.last_wake_at) IS NULL THEN -1
                     WHEN julianday(?) - julianday(h.last_wake_at) >= 60.0 / 86400.0 THEN 1
                     ELSE 0
                   END AS wake_due
            FROM hosted_operations h
            WHERE h.state IN ('PREPARED','CLAIMED')
            ORDER BY h.id
            """,
            (now,),
        ).fetchall()
        if not rows:
            return {
                "promoted": promoted,
                "launched": [],
                "rejected": [],
                "skipped": [],
                "reason": "NO_READY_OPERATION",
            }

        active_attempts = control.connection.execute(
            """
            SELECT target_kind, target_key
            FROM executor_attempts
            WHERE role='sre' AND state IN ('RESERVED','LAUNCHING','RUNNING')
            """
        ).fetchall()
        active_count = len(active_attempts)
        active_operation_ids = {
            str(attempt["target_key"])
            for attempt in active_attempts
            if attempt["target_kind"] == "hosted_operation"
        }
        rows_by_id = {str(row["id"]): row for row in rows}
        repositories = sorted({str(row["repository"]) for row in rows})
        repository_limits = {
            repository: control._sre_limit(repository) for repository in repositories
        }
        capacity_limit = sum(repository_limits.values())

        pending_rows = [
            row
            for row in rows
            if int(row["wake_due"]) != 1
            and str(row["id"]) not in active_operation_ids
        ]
        pending_count = len(pending_rows)
        remaining = max(0, capacity_limit - active_count - pending_count)
        active_hosted_by_repository = {repository: 0 for repository in repositories}
        for operation_id in active_operation_ids:
            active_row = rows_by_id.get(operation_id)
            if active_row is not None:
                repository = str(active_row["repository"])
                active_hosted_by_repository[repository] += 1
        pending_by_repository = {repository: 0 for repository in repositories}
        for pending in pending_rows:
            pending_by_repository[str(pending["repository"])] += 1
        repository_remaining = {
            repository: max(
                0,
                repository_limits[repository]
                - active_hosted_by_repository[repository]
                - pending_by_repository[repository],
            )
            for repository in repositories
        }

        occupied_targets: set[tuple[str, str, str, str]] = set()
        for row in rows:
            if int(row["wake_due"]) != 1 or str(row["id"]) in active_operation_ids:
                occupied_targets.add(
                    (
                        str(row["repository"]),
                        str(row["provider"]),
                        str(row["target_kind"]),
                        str(row["target_key"]),
                    )
                )

        for row in rows:
            operation_id = int(row["id"])
            operation_key = str(operation_id)
            target = (
                str(row["repository"]),
                str(row["provider"]),
                str(row["target_kind"]),
                str(row["target_key"]),
            )
            if int(row["wake_due"]) == -1:
                skipped.append(
                    {"operation_id": operation_id, "reason": "WAKE_TIMESTAMP_INVALID"}
                )
                continue
            if int(row["wake_due"]) == 0:
                skipped.append({"operation_id": operation_id, "reason": "WAKE_NOT_DUE"})
                continue
            if operation_key in active_operation_ids:
                skipped.append(
                    {"operation_id": operation_id, "reason": "EXECUTOR_TARGET_ACTIVE"}
                )
                continue
            if target in occupied_targets:
                skipped.append(
                    {"operation_id": operation_id, "reason": "HOSTED_TARGET_COLLISION"}
                )
                continue
            try:
                control._validate_claim_local_state(row)
            except CoordinationError as exc:
                occupied_targets.add(target)
                skipped.append({"operation_id": operation_id, "reason": str(exc)})
                continue
            repository = str(row["repository"])
            if remaining <= 0 or repository_remaining[repository] <= 0:
                skipped.append(
                    {"operation_id": operation_id, "reason": "SRE_DISPATCH_CAPACITY_FULL"}
                )
                continue
            changed = control.connection.execute(
                """
                UPDATE hosted_operations
                SET last_wake_at=?, updated_at=?
                WHERE id=? AND state=?
                  AND (last_wake_at IS NULL OR (
                    julianday(last_wake_at) IS NOT NULL
                    AND julianday(?) - julianday(last_wake_at) >= 60.0 / 86400.0
                  ))
                """,
                (now, now, operation_id, row["state"], now),
            ).rowcount
            if changed != 1:
                skipped.append(
                    {"operation_id": operation_id, "reason": "WAKE_RESERVATION_RACE"}
                )
                continue
            control.store._event(
                "HOSTED_OPERATION_WAKE_RESERVED",
                f"hosted-operation:{operation_id}",
                {"operation_id": operation_id, "recipient_session_id": endpoint_id},
                now,
            )
            reserved.append(dict(row))
            occupied_targets.add(target)
            remaining -= 1
            repository_remaining[repository] -= 1

    launched: list[int] = []
    rejected: list[int] = []
    for row in reserved:
        operation_id = int(row["id"])
        prompt = (
            f"SQLite hosted-operation wake for exact row {operation_id}. Read it through "
            "hosted_operation_control.py, re-fetch its owning issue authority, and claim it before "
            "any hosted mutation. The wake itself carries no authority."
        )
        return_code = launcher(
            role="sre",
            endpoint_id=endpoint_id,
            target_kind="hosted_operation",
            target_key=str(operation_id),
            prompt=prompt,
        )
        event_kind = (
            "HOSTED_OPERATION_WAKE_STARTED"
            if return_code == 0
            else "HOSTED_OPERATION_WAKE_REJECTED"
        )
        with control.store.transaction():
            control.store._event(
                event_kind,
                f"hosted-operation:{operation_id}",
                {"operation_id": operation_id, "recipient_session_id": endpoint_id},
                now,
            )
        if return_code == 0:
            launched.append(operation_id)
        else:
            rejected.append(operation_id)

    reason = None
    if not launched:
        if rejected:
            reason = "LAUNCH_REJECTED"
        elif any(item["reason"] == "SRE_DISPATCH_CAPACITY_FULL" for item in skipped):
            reason = "SRE_DISPATCH_CAPACITY_FULL"
        else:
            reason = "NO_ELIGIBLE_OPERATION"
    return {
        "promoted": promoted,
        "launched": launched,
        "rejected": rejected,
        "skipped": skipped,
        "capacity": {
            "limit": capacity_limit,
            "active": active_count,
            "pending": pending_count,
            "reserved": len(reserved),
        },
        "reason": reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--transaction-file", type=Path, required=True)
    claim = sub.add_parser("claim")
    claim.add_argument("--operation-id", type=int, required=True)
    claim.add_argument("--session-id", required=True)
    complete = sub.add_parser("complete")
    complete.add_argument("--operation-id", type=int, required=True)
    complete.add_argument("--session-id", required=True)
    complete.add_argument("--outbox-id", type=int, required=True)
    hold = sub.add_parser("hold")
    hold.add_argument("--operation-id", type=int, required=True)
    hold.add_argument("--error", required=True)
    sub.add_parser("show")
    sub.add_parser("supervise")
    args = parser.parse_args()
    control = HostedOperationControl()
    try:
        if args.command == "prepare":
            transaction = json.loads(args.transaction_file.read_text(encoding="utf-8"))
            result = control.prepare(transaction, utc_now())
        elif args.command == "claim":
            result = control.claim(args.operation_id, args.session_id, utc_now())
        elif args.command == "complete":
            result = control.complete(args.operation_id, args.session_id, args.outbox_id, utc_now())
        elif args.command == "hold":
            result = control.hold(args.operation_id, args.error, utc_now())
        elif args.command == "show":
            result = control.show()
        else:
            result = run_supervisor(
                control,
                utc_now(),
                transport_preflight=attest_role_executor_transport,
            )
        print(canonical_json(result))
        return 0
    except (CoordinationError, json.JSONDecodeError, OSError) as exc:
        error = str(exc) if isinstance(exc, CoordinationError) else "HOSTED_CONTROL_FAILED"
        print(canonical_json({"phase": "HOLD", "error": error}))
        return 1
    finally:
        control.close()


if __name__ == "__main__":
    raise SystemExit(main())
