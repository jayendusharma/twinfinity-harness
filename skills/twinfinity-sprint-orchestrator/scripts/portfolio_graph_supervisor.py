#!/usr/bin/env python3
"""Refresh the live portfolio graph projection and record one scheduling decision."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import Any

from coordination_store import CoordinationStore, DEFAULT_DATABASE, canonical_json
from kanban_pull_buffer import PullBufferError, audit_pull_buffer
from portfolio_convergence import (
    DEFAULT_CONVERGENCE_LIMIT,
    MAX_CONVERGENCE_LIMIT,
    PortfolioConvergence,
    PortfolioConvergenceError,
)
from portfolio_graph import PortfolioGraphError, evaluate_graph, schedule, utc_now


DEFAULT_REPOSITORY = "twinfinityai/twinfinityapp"


def _run_refresh(repository: str) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).with_name("sync_github_coordination.py")),
        "--repository",
        repository,
        "--portfolio-graph",
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    try:
        result = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise PortfolioGraphError("GRAPH_REFRESH_INVALID") from exc
    if completed.returncode != 0 or result.get("phase") != "COMPLETE":
        raise PortfolioGraphError(str(result.get("error") or "GRAPH_REFRESH_FAILED"))
    return result


def supervise(
    repository: str,
    *,
    database: Path,
    refresh: bool = True,
    convergence_limit: int = DEFAULT_CONVERGENCE_LIMIT,
) -> dict[str, Any]:
    if convergence_limit <= 0 or convergence_limit > MAX_CONVERGENCE_LIMIT:
        raise PortfolioConvergenceError("CONVERGENCE_LIMIT_INVALID")
    refresh_result = _run_refresh(repository) if refresh else None
    store = CoordinationStore(database)
    connection = store.connection
    try:
        current = connection.execute(
            """
            SELECT version, observed_main_sha, health, last_error
            FROM portfolio_graph_current WHERE repository=?
            """,
            (repository,),
        ).fetchone()
        if current is None:
            raise PortfolioGraphError("GRAPH_NOT_FOUND")
        convergence = PortfolioConvergence(store).consume_due(
            limit=convergence_limit, repository=repository
        )
        current = connection.execute(
            """
            SELECT version, observed_main_sha, health, last_error
            FROM portfolio_graph_current WHERE repository=?
            """,
            (repository,),
        ).fetchone()
        if current is None:
            raise PortfolioGraphError("GRAPH_NOT_FOUND")
        evaluation = evaluate_graph(
            connection,
            repository,
            current_main=str(current["observed_main_sha"]),
        )
        if evaluation["health"] != "CURRENT":
            return {
                "repository": repository,
                "graph_version": int(current["version"]),
                "state": "GRAPH_STALE",
                "reasons": evaluation["stale_reasons"],
                "portfolio_convergence": convergence,
                "refresh_count": len((refresh_result or {}).get("refreshed", [])),
            }
        decision = schedule(
            connection,
            repository,
            current_main=str(current["observed_main_sha"]),
            record=True,
            now=utc_now(),
        )
        pull_buffer = audit_pull_buffer(
            connection,
            repository,
            record=True,
            now=utc_now(),
            database=database,
        )
        return {
            "repository": repository,
            "graph_version": decision["graph_version"],
            "capacity_policy_version": decision["capacity_policy_version"],
            "state": "SCHEDULED",
            "selected": decision["selected"],
            "skipped": decision["skipped"],
            "remaining_capacity": decision["remaining_capacity"],
            "pull_buffer": pull_buffer,
            "portfolio_convergence": convergence,
            "refresh_count": len((refresh_result or {}).get("refreshed", [])),
        }
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--no-refresh", action="store_true")
    args = parser.parse_args()
    try:
        result = supervise(
            args.repository,
            database=DEFAULT_DATABASE,
            refresh=not args.no_refresh,
        )
        print(canonical_json({"phase": "COMPLETE", "result": result}))
        return 0
    except (
        PortfolioGraphError,
        PullBufferError,
        PortfolioConvergenceError,
        OSError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as exc:
        print(canonical_json({"phase": "HOLD", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
