#!/usr/bin/env python3
"""Refresh exact issue and pull-request facts into the local coordination store."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
import subprocess
from typing import Any

from coordination_store import (
    CoordinationError,
    CoordinationStore,
    DEFAULT_DATABASE,
    canonical_json,
)
from portfolio_graph import PortfolioGraphError, issue_set_scope_numbers, sync_head
from repository_delivery_policy import HARNESS_REPOSITORY


PROJECTION_VERSION = 3

ISSUE_FIELDS = (
    "number",
    "state",
    "state_reason",
    "title",
    "body",
    "updated_at",
    "closed_at",
    "html_url",
    "labels",
    "milestone",
    "assignees",
)
PULL_FIELDS = (
    "number",
    "state",
    "title",
    "body",
    "updated_at",
    "closed_at",
    "merged_at",
    "draft",
    "html_url",
    "base",
    "head",
    "mergeable_state",
    "requested_reviewers",
    "labels",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_gh(arguments: list[str]) -> Any:
    completed = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise CoordinationError("GITHUB_REFRESH_FAILED")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CoordinationError("GITHUB_RESPONSE_INVALID") from exc


def _person(value: dict[str, Any]) -> dict[str, Any]:
    return {"login": value.get("login"), "id": value.get("id")}


def _labels(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return sorted(
        (
            {"name": item.get("name"), "color": item.get("color")}
            for item in value
            if isinstance(item, dict)
        ),
        key=lambda item: str(item["name"]),
    )


def normalize_issue(raw: dict[str, Any]) -> dict[str, Any]:
    if "pull_request" in raw:
        raise CoordinationError("SOURCE_KIND_MISMATCH")
    payload = {key: raw.get(key) for key in ISSUE_FIELDS}
    payload["_projection_version"] = PROJECTION_VERSION
    payload["labels"] = _labels(raw.get("labels"))
    payload["assignees"] = sorted(
        (_person(item) for item in raw.get("assignees", []) if isinstance(item, dict)),
        key=lambda item: str(item["login"]),
    )
    milestone = raw.get("milestone")
    payload["milestone"] = (
        None
        if not isinstance(milestone, dict)
        else {
            "number": milestone.get("number"),
            "title": milestone.get("title"),
            "state": milestone.get("state"),
        }
    )
    return payload


def normalize_pull(
    raw: dict[str, Any],
    *,
    reviews: list[dict[str, Any]] | None = None,
    combined_status: dict[str, Any] | None = None,
    check_runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = {key: raw.get(key) for key in PULL_FIELDS}
    payload["_projection_version"] = PROJECTION_VERSION
    payload["labels"] = _labels(raw.get("labels"))
    payload["requested_reviewers"] = sorted(
        (
            _person(item)
            for item in raw.get("requested_reviewers", [])
            if isinstance(item, dict)
        ),
        key=lambda item: str(item["login"]),
    )
    for side in ("base", "head"):
        value = raw.get(side)
        payload[side] = (
            None
            if not isinstance(value, dict)
            else {
                "ref": value.get("ref"),
                "sha": value.get("sha"),
                "repo": (value.get("repo") or {}).get("full_name"),
            }
        )
    payload["reviews"] = sorted(
        (
            {
                "id": item.get("id"),
                "state": item.get("state"),
                "submitted_at": item.get("submitted_at"),
                "commit_id": item.get("commit_id"),
                "user": _person(item.get("user") or {}),
            }
            for item in (reviews or [])
            if isinstance(item, dict)
        ),
        key=lambda item: (str(item["submitted_at"]), int(item["id"] or 0)),
    )
    status_value = combined_status or {}
    payload["combined_status"] = {
        "sha": status_value.get("sha"),
        "state": status_value.get("state"),
        "statuses": sorted(
            (
                {
                    "context": item.get("context"),
                    "state": item.get("state"),
                    "target_url": item.get("target_url"),
                    "updated_at": item.get("updated_at"),
                }
                for item in status_value.get("statuses", [])
                if isinstance(item, dict)
            ),
            key=lambda item: str(item["context"]),
        ),
    }
    payload["check_runs"] = sorted(
        (
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "head_sha": item.get("head_sha"),
                "status": item.get("status"),
                "conclusion": item.get("conclusion"),
                "started_at": item.get("started_at"),
                "completed_at": item.get("completed_at"),
                "details_url": item.get("details_url"),
            }
            for item in (check_runs or [])
            if isinstance(item, dict)
        ),
        key=lambda item: (str(item["name"]), int(item["id"] or 0)),
    )
    observation_timestamps = [payload.get("updated_at")]
    observation_timestamps.extend(
        item.get("submitted_at") for item in payload["reviews"]
    )
    observation_timestamps.extend(
        item.get("updated_at")
        for item in payload["combined_status"]["statuses"]
    )
    for item in payload["check_runs"]:
        observation_timestamps.extend(
            (item.get("started_at"), item.get("completed_at"))
        )
    payload["_projection_updated_at"] = max(
        value
        for value in observation_timestamps
        if isinstance(value, str) and value
    )
    return payload


def _flatten_pages(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise CoordinationError("GITHUB_RESPONSE_INVALID")
    if raw and all(isinstance(item, list) for item in raw):
        return [entry for page in raw for entry in page if isinstance(entry, dict)]
    return [entry for entry in raw if isinstance(entry, dict)]


def fetch_object(repository: str, kind: str, number: int) -> dict[str, Any]:
    endpoint = "issues" if kind == "issue" else "pulls"
    raw = _run_gh(["api", f"repos/{repository}/{endpoint}/{number}"])
    if not isinstance(raw, dict) or raw.get("number") != number:
        raise CoordinationError("GITHUB_RESPONSE_INVALID")
    if kind == "issue":
        return normalize_issue(raw)
    head = raw.get("head") or {}
    head_sha = head.get("sha")
    if not isinstance(head_sha, str) or not head_sha:
        raise CoordinationError("GITHUB_RESPONSE_INVALID")
    reviews = _flatten_pages(
        _run_gh(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/pulls/{number}/reviews?per_page=100",
            ]
        )
    )
    combined_status = _run_gh(["api", f"repos/{repository}/commits/{head_sha}/status"])
    check_response = _run_gh(
        ["api", f"repos/{repository}/commits/{head_sha}/check-runs?per_page=100"]
    )
    if not isinstance(combined_status, dict) or not isinstance(check_response, dict):
        raise CoordinationError("GITHUB_RESPONSE_INVALID")
    return normalize_pull(
        raw,
        reviews=reviews,
        combined_status=combined_status,
        check_runs=_flatten_pages(check_response.get("check_runs", [])),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--issue", type=int, action="append", default=[])
    parser.add_argument("--pull-request", type=int, action="append", default=[])
    parser.add_argument("--milestone-number", type=int, action="append", default=[])
    parser.add_argument("--portfolio-graph", action="store_true")
    args = parser.parse_args()
    if (
        not args.issue
        and not args.pull_request
        and not args.milestone_number
        and not args.portfolio_graph
    ):
        parser.error(
            "at least one --issue, --pull-request, --milestone-number, "
            "or --portfolio-graph is required"
        )

    try:
        store = CoordinationStore(DEFAULT_DATABASE)
        results: list[dict[str, Any]] = []
        issue_numbers = set(args.issue)
        prefetched_issues: dict[int, dict[str, Any]] = {}
        milestone_numbers = set(args.milestone_number)
        bootstrap_main_sha: str | None = None
        graph_expected_version: int | None = None
        graph_expected_main: str | None = None
        graph_main_sha: str | None = None
        if args.portfolio_graph:
            current = store.connection.execute(
                """
                SELECT c.version, c.observed_main_sha, r.scope_json
                FROM portfolio_graph_current c
                JOIN portfolio_graph_revisions r
                  ON r.repository=c.repository AND r.version=c.version
                WHERE c.repository=?
                """,
                (args.repository,),
            ).fetchone()
            if current is None and (
                args.repository != HARNESS_REPOSITORY or not issue_numbers
            ):
                raise PortfolioGraphError("GRAPH_NOT_FOUND")
            if current is not None:
                graph_expected_version = int(current["version"])
                graph_expected_main = str(current["observed_main_sha"])
                scope = json.loads(current["scope_json"])
                scoped_titles = set(scope.get("milestones", []))
                if scope.get("kind") == "ISSUE_SET":
                    issue_numbers.update(
                        issue_set_scope_numbers(args.repository, scope)
                    )
                graph_nodes = list(
                    store.connection.execute(
                        """
                        SELECT DISTINCT n.issue_number, s.payload_json
                        FROM portfolio_graph_nodes n
                        JOIN github_current c
                          ON c.repository=n.repository
                         AND c.object_kind='issue'
                         AND c.object_number=n.issue_number
                        JOIN github_snapshots s
                          ON s.repository=c.repository
                         AND s.object_kind=c.object_kind
                         AND s.object_number=n.issue_number
                         AND s.payload_sha256=c.payload_sha256
                        WHERE n.repository=? AND n.graph_version=?
                        """,
                        (args.repository, current["version"]),
                    )
                )
                issue_numbers.update(int(row["issue_number"]) for row in graph_nodes)
                for row in graph_nodes:
                    milestone = json.loads(row["payload_json"]).get("milestone")
                    if isinstance(milestone, dict) and isinstance(
                        milestone.get("number"), int
                    ) and milestone.get("title") in scoped_titles:
                        milestone_numbers.add(int(milestone["number"]))
            main_ref = _run_gh(
                ["api", f"repos/{args.repository}/git/ref/heads/main"]
            )
            main_sha = (main_ref.get("object") or {}).get("sha")
            if not isinstance(main_sha, str) or re.fullmatch(
                r"[0-9a-f]{40}", main_sha
            ) is None:
                raise CoordinationError("GITHUB_RESPONSE_INVALID")
            if current is not None:
                graph_main_sha = main_sha
            else:
                bootstrap_main_sha = main_sha

        for milestone_number in sorted(milestone_numbers):
            milestone_issues = _flatten_pages(
                _run_gh(
                    [
                        "api",
                        "--paginate",
                        "--slurp",
                        f"repos/{args.repository}/issues"
                        f"?state=open&milestone={milestone_number}&per_page=100",
                    ]
                )
            )
            for raw in milestone_issues:
                number = raw.get("number")
                if "pull_request" in raw or not isinstance(number, int):
                    continue
                issue_numbers.add(number)
                prefetched_issues[number] = normalize_issue(raw)

        pending_snapshots: list[dict[str, Any]] = []
        for kind, numbers in (
            ("issue", sorted(issue_numbers)),
            ("pull_request", args.pull_request),
        ):
            for number in sorted(set(numbers)):
                payload = (
                    prefetched_issues[number]
                    if kind == "issue" and number in prefetched_issues
                    else fetch_object(args.repository, kind, number)
                )
                source_updated_at = payload.get(
                    "_projection_updated_at", payload.get("updated_at")
                )
                if not isinstance(source_updated_at, str) or not source_updated_at:
                    raise CoordinationError("GITHUB_RESPONSE_INVALID")
                pending_snapshots.append(
                    {
                        "kind": kind,
                        "number": number,
                        "payload": payload,
                        "source_updated_at": source_updated_at,
                        "fetched_at": utc_now(),
                    }
                )
        bracketed_main_sha = graph_main_sha or bootstrap_main_sha
        if bracketed_main_sha is not None:
            final_main_ref = _run_gh(
                ["api", f"repos/{args.repository}/git/ref/heads/main"]
            )
            final_main_sha = (final_main_ref.get("object") or {}).get("sha")
            if final_main_sha != bracketed_main_sha:
                raise CoordinationError("GITHUB_MAIN_CHANGED_DURING_REFRESH")
        with store.transaction():
            for pending in pending_snapshots:
                snapshot = store.ingest_snapshot_in_transaction(
                    repository=args.repository,
                    object_kind=pending["kind"],
                    object_number=pending["number"],
                    payload=pending["payload"],
                    source_updated_at=pending["source_updated_at"],
                    fetched_at=pending["fetched_at"],
                )
                results.append(
                    {
                        "kind": pending["kind"],
                        "number": pending["number"],
                        "payload_sha256": snapshot.payload_sha256,
                        "source_updated_at": pending["source_updated_at"],
                    }
                )
            if graph_main_sha is not None:
                if graph_expected_version is None or graph_expected_main is None:
                    raise PortfolioGraphError("GRAPH_MAIN_CAS_DRIFT")
                sync_head(
                    store.connection,
                    args.repository,
                    graph_main_sha,
                    expected_version=graph_expected_version,
                    expected_observed_main_sha=graph_expected_main,
                    now=utc_now(),
                    _ensure_schema=False,
                    _transaction=False,
                )
        store.close()
        output = {"phase": "COMPLETE", "refreshed": results}
        if bootstrap_main_sha is not None:
            output.update(
                {
                    "phase": "BOOTSTRAP_INPUTS_REFRESHED",
                    "repository": args.repository,
                    "observed_main_sha": bootstrap_main_sha,
                }
            )
        print(canonical_json(output))
        return 0
    except (CoordinationError, PortfolioGraphError) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
    except Exception:
        print(canonical_json({"phase": "HOLD", "error": "COORDINATION_FAILED"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
