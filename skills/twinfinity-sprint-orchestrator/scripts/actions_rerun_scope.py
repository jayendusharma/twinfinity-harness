#!/usr/bin/env python3
"""Build one fail-closed GitHub Actions rerun scope from live and SQLite truth."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from typing import Any
from urllib.parse import quote

from approval_guard import hosted_execution_scope_sha256
from coordination_store import CoordinationError, canonical_json, digest_json
from hosted_operation_control import (
    HostedOperationControl,
    RUNNER_NOT_ACQUIRED_ANNOTATION,
    _validate_scope,
)


REQUEST_KEYS = {
    "repository",
    "issue_number",
    "pull_request_number",
    "workflow_run_id",
    "ready_generation",
    "local_gate_id",
    "guarded_publication_id",
    "provider_restoration_operation_id",
    "provider_restoration_minimum_amount",
    "exclusions",
    "stop_conditions",
}
CLASSIFIER_JOB = "classify-ci"
AGGREGATE_JOBS = {"ci-gate"}
ANNOTATION_KEYS = tuple(RUNNER_NOT_ACQUIRED_ANNOTATION)


class GitHubReader:
    """Small read-only gh transport with typed, non-secret failure output."""

    @staticmethod
    def _run(endpoint: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["gh", "api", "--method", "GET", endpoint],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def json(self, endpoint: str) -> Any:
        completed = self._run(endpoint)
        if completed.returncode != 0:
            raise CoordinationError("ACTIONS_RERUN_GITHUB_READ_FAILED")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise CoordinationError("ACTIONS_RERUN_GITHUB_JSON_INVALID") from exc

    def log_count(self, repository: str, job_id: int) -> int:
        completed = self._run(f"repos/{repository}/actions/jobs/{job_id}/logs")
        if completed.returncode == 0:
            return 1
        if b"HTTP 404" in completed.stderr:
            return 0
        raise CoordinationError("ACTIONS_RERUN_LOG_PROBE_FAILED")


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _validate_request(request: object) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise CoordinationError("ACTIONS_RERUN_REQUEST_INVALID")
    if (
        not isinstance(request["repository"], str)
        or "/" not in request["repository"]
        or any(
            not _positive_int(request[key])
            for key in (
                "issue_number",
                "pull_request_number",
                "workflow_run_id",
                "ready_generation",
                "local_gate_id",
                "guarded_publication_id",
                "provider_restoration_operation_id",
                "provider_restoration_minimum_amount",
            )
        )
        or any(
            not isinstance(request[key], list)
            or not request[key]
            or any(not isinstance(item, str) or not item for item in request[key])
            for key in ("exclusions", "stop_conditions")
        )
    ):
        raise CoordinationError("ACTIONS_RERUN_REQUEST_INVALID")
    return request


def _normalized_annotations(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CoordinationError("ACTIONS_RERUN_ANNOTATIONS_INVALID")
    normalized: list[dict[str, Any]] = []
    for annotation in value:
        if not isinstance(annotation, dict):
            raise CoordinationError("ACTIONS_RERUN_ANNOTATIONS_INVALID")
        normalized.append({key: annotation.get(key) for key in ANNOTATION_KEYS})
    return sorted(normalized, key=canonical_json)


def read_scope_inputs(request_value: object, github: GitHubReader) -> dict[str, Any]:
    """Finish every GitHub read and freeze its canonical digest before locking."""

    request = _validate_request(request_value)
    repository = request["repository"]
    pr_number = request["pull_request_number"]
    run_id = request["workflow_run_id"]
    prefix = f"repos/{repository}"

    pull = github.json(f"{prefix}/pulls/{pr_number}")
    run = github.json(f"{prefix}/actions/runs/{run_id}")
    jobs_payload = github.json(f"{prefix}/actions/runs/{run_id}/jobs?per_page=100")
    artifacts = github.json(f"{prefix}/actions/runs/{run_id}/artifacts?per_page=100")
    jobs = jobs_payload.get("jobs") if isinstance(jobs_payload, dict) else None
    classifiers = (
        [job for job in jobs if isinstance(job, dict) and job.get("name") == CLASSIFIER_JOB]
        if isinstance(jobs, list)
        else []
    )
    classifier_id = classifiers[0].get("id") if len(classifiers) == 1 else None
    if not _positive_int(classifier_id):
        raise CoordinationError("ACTIONS_RERUN_CLASSIFIER_INVALID")
    annotations = github.json(
        f"{prefix}/check-runs/{classifier_id}/annotations?per_page=100"
    )
    workflow_path = run.get("path")
    head_sha = pull.get("head", {}).get("sha")
    if not isinstance(workflow_path, str) or not isinstance(head_sha, str):
        raise CoordinationError("ACTIONS_RERUN_LINEAGE_INVALID")
    workflow = github.json(
        f"{prefix}/contents/{quote(workflow_path, safe='/')}?ref={quote(head_sha, safe='')}"
    )
    inputs = {
        "request": request,
        "pull": pull,
        "run": run,
        "jobs": jobs_payload,
        "artifacts": artifacts,
        "annotations": annotations,
        "workflow": workflow,
        "classifier_log_count": github.log_count(repository, classifier_id),
    }
    return {"payload": inputs, "payload_sha256": digest_json(inputs)}


def build_scope_in_transaction(
    control: HostedOperationControl,
    request_value: object,
    inputs_value: object,
    inputs_sha256: str,
) -> dict[str, Any]:
    """Build and validate the scope from digest-bound reads under the write lock."""

    if not control.connection.in_transaction:
        raise CoordinationError("COORDINATOR_TRANSACTION_REQUIRED")
    request = _validate_request(request_value)
    if (
        not isinstance(inputs_value, dict)
        or digest_json(inputs_value) != inputs_sha256
        or inputs_value.get("request") != request
    ):
        raise CoordinationError("ACTIONS_RERUN_GITHUB_INPUT_DRIFT")
    pull = inputs_value.get("pull")
    run = inputs_value.get("run")
    jobs_payload = inputs_value.get("jobs")
    artifacts = inputs_value.get("artifacts")
    workflow = inputs_value.get("workflow")
    if (
        not isinstance(pull, dict)
        or not isinstance(run, dict)
        or not isinstance(jobs_payload, dict)
        or not isinstance(jobs_payload.get("jobs"), list)
        or not isinstance(artifacts, dict)
    ):
        raise CoordinationError("ACTIONS_RERUN_GITHUB_INPUT_INVALID")
    jobs = jobs_payload["jobs"]
    if any(not isinstance(job, dict) for job in jobs):
        raise CoordinationError("ACTIONS_RERUN_JOBS_INVALID")
    classifiers = [job for job in jobs if job.get("name") == CLASSIFIER_JOB]
    if len(classifiers) != 1:
        raise CoordinationError("ACTIONS_RERUN_CLASSIFIER_INVALID")
    classifier = classifiers[0]
    classifier_id = classifier.get("id")
    if not _positive_int(classifier_id):
        raise CoordinationError("ACTIONS_RERUN_CLASSIFIER_INVALID")
    annotations = _normalized_annotations(inputs_value.get("annotations"))
    log_count = inputs_value.get("classifier_log_count")
    if type(log_count) is not int or log_count < 0:
        raise CoordinationError("ACTIONS_RERUN_LOG_PROBE_FAILED")
    repository = request["repository"]
    issue_number = request["issue_number"]
    pr_number = request["pull_request_number"]
    run_id = request["workflow_run_id"]
    workflow_path = run.get("path")
    head_sha = pull.get("head", {}).get("sha")
    if not isinstance(workflow_path, str) or not isinstance(head_sha, str):
        raise CoordinationError("ACTIONS_RERUN_LINEAGE_INVALID")
    substantive_jobs = {
        job["name"]: job.get("conclusion")
        for job in jobs
        if isinstance(job.get("name"), str)
        and job.get("name") not in {CLASSIFIER_JOB, *AGGREGATE_JOBS}
    }
    substantive_jobs = dict(sorted(substantive_jobs.items()))
    run_prs = run.get("pull_requests", [])
    if (
        pull.get("number") != pr_number
        or run.get("id") != run_id
        or run.get("run_attempt") != 1
        or run.get("status") != "completed"
        or run.get("conclusion") != "failure"
        or run.get("event") != "pull_request"
        or run.get("head_sha") != head_sha
        or not isinstance(run_prs, list)
        or [item.get("number") for item in run_prs] != [pr_number]
        or not isinstance(artifacts.get("artifacts"), list)
        or artifacts.get("total_count") != len(artifacts["artifacts"])
        or not isinstance(workflow, dict)
    ):
        raise CoordinationError("ACTIONS_RERUN_LINEAGE_INVALID")

    source = control.store.current_snapshot(repository, "issue", issue_number)
    gate = control.connection.execute(
        "SELECT * FROM coordination_pre_push_gates WHERE id=?",
        (request["local_gate_id"],),
    ).fetchone()
    publication = control.connection.execute(
        "SELECT * FROM coordination_pre_push_publications WHERE id=?",
        (request["guarded_publication_id"],),
    ).fetchone()
    restoration = control.connection.execute(
        "SELECT * FROM hosted_operations WHERE id=?",
        (request["provider_restoration_operation_id"],),
    ).fetchone()
    if source is None or gate is None or publication is None or restoration is None:
        raise CoordinationError("ACTIONS_RERUN_SQLITE_EVIDENCE_MISSING")
    target_key = f"{repository}:pr:{pr_number}:run:{run_id}:attempt:1"
    scope = {
            "target": {
                "repository": repository,
                "pull_request_number": pr_number,
                "workflow_path": workflow_path,
                "workflow_run_id": run_id,
                "run_attempt": 1,
                "check_suite_id": run.get("check_suite_id"),
                "head_sha": head_sha,
                "base_sha": pull.get("base", {}).get("sha"),
                "workflow_sha": workflow.get("sha"),
            },
            "expected_state": {
                "pull_request_state": str(pull.get("state", "")).upper(),
                "draft": pull.get("draft"),
                "ready_generation": request["ready_generation"],
                "classifier_conclusion": classifier.get("conclusion"),
                "classifier_runner_id": classifier.get("runner_id"),
                "classifier_runner_name_present": bool(classifier.get("runner_name")),
                "classifier_step_count": len(classifier.get("steps", [])),
                "log_count": log_count,
                "annotation_count": len(annotations),
                "infrastructure_annotations": annotations,
                "artifact_count": artifacts.get("total_count"),
                "substantive_jobs": substantive_jobs,
                "cancellation_reason": "HOSTED_RUNNER_NOT_ACQUIRED",
                "cancellation_ambiguous": False,
                "local_gate_id": gate["id"],
                "local_gate_evidence_sha256": gate["evidence_sha256"],
                "local_gate_receipt_sha256": digest_json(dict(gate)),
                "guarded_publication_id": publication["id"],
                "guarded_publication_receipt_sha256": digest_json(dict(publication)),
                "provider_restoration_operation_id": restoration["id"],
                "provider_restoration_target_key": restoration["target_key"],
                "provider_restoration_receipt_sha256": restoration["receipt_payload_sha256"],
                "failed_run_completed_at": run.get("updated_at"),
                "provider_restoration_minimum_amount": request[
                    "provider_restoration_minimum_amount"
                ],
            },
            "desired_state": {
                "endpoint": "RERUN_SAME_WORKFLOW_RUN",
                "next_run_attempt": 2,
                "preserve_workflow_run_id": True,
                "preserve_check_suite_id": True,
                "rerun_once": True,
                "repeat_local_gate": False,
            },
            "exclusions": request["exclusions"],
            "stop_conditions": request["stop_conditions"],
        }
    _validate_scope(
        scope,
        provider="github",
        target_kind="github_actions_rerun",
        operation_kind="RERUN_WORKFLOW",
        target_key=target_key,
    )
    control._validate_operation_evidence(
        repository=repository,
        issue_number=issue_number,
        provider="github",
        target_kind="github_actions_rerun",
        operation_kind="RERUN_WORKFLOW",
        scope=scope,
    )
    return {
        "repository": repository,
        "issue_number": issue_number,
        "source_payload_sha256": source.payload_sha256,
        "provider": "github",
        "target_kind": "github_actions_rerun",
        "target_key": target_key,
        "operation_kind": "RERUN_WORKFLOW",
        "scope": scope,
        "scope_sha256": digest_json(scope),
        "hosted_execution_scope_sha256": hosted_execution_scope_sha256(
            provider="github",
            target_kind="github_actions_rerun",
            target_key=target_key,
            operation_kind="RERUN_WORKFLOW",
            scope=scope,
        ),
    }


def build_scope(
    control: HostedOperationControl,
    request_value: object,
    github: GitHubReader,
) -> dict[str, Any]:
    external = read_scope_inputs(request_value, github)
    with control.store.transaction():
        return build_scope_in_transaction(
            control,
            request_value,
            external["payload"],
            external["payload_sha256"],
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-file", type=Path, required=True)
    args = parser.parse_args()
    control = HostedOperationControl()
    try:
        request = json.loads(args.request_file.read_text(encoding="utf-8"))
        print(canonical_json(build_scope(control, request, GitHubReader())))
        return 0
    except (CoordinationError, json.JSONDecodeError, OSError) as exc:
        error = str(exc) if isinstance(exc, CoordinationError) else "ACTIONS_RERUN_SCOPE_FAILED"
        print(canonical_json({"phase": "HOLD", "error": error}))
        return 1
    finally:
        control.close()


if __name__ == "__main__":
    raise SystemExit(main())
