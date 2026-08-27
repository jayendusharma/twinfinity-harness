from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationStore,
    terminal_published_body,
    terminal_publication_body,
)
import coordination_store as coordination_store_module  # noqa: E402
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from executor_registry import (  # noqa: E402
    RegistryError,
    attempt_lineage_for_target,
    load_registry_config,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from hosted_operation_control import (  # noqa: E402
    HostedOperationControl,
    run_supervisor as run_hosted_supervisor,
)
from portfolio_convergence import PortfolioConvergence  # noqa: E402
from portfolio_graph import replace_graph, schedule  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from role_executor_transport import (  # noqa: E402
    SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS,
    launch_role_executor,
)
from tests.canonical_ready_fixture import (  # noqa: E402
    finalize_canonical_ready_candidate,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
DEVELOPMENT_ENDPOINT = "role.development.v4"
SRE_ENDPOINT = "role.sre.v4"
AUTHORITY_BODY = "Exact bounded throughput simulation authority"
AUTHORITY_SHA256 = hashlib.sha256(AUTHORITY_BODY.encode()).hexdigest()


class _FlowHarness:
    """Small isolated control-plane fixture; no live services or network."""

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "coordination"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        self.sources: dict[int, str] = {}
        self.remote_issues: dict[int, dict[str, object]] = {}
        self.remote_comments: dict[int, dict[str, object]] = {}
        self.remote_timelines: dict[int, list[dict[str, object]]] = {}
        self.items: dict[int, dict[str, object]] = {}
        self.attempts_by_message: dict[int, tuple[dict[str, object], str]] = {}
        self.message_by_issue: dict[int, int] = {}
        self.next_process_id = 4000
        self.live_observation_patcher = patch.object(
            coordination_store_module,
            "_fetch_terminal_live_observation",
            side_effect=self._terminal_live_observation,
        )
        self.live_observation_patcher.start()
        self._migrate_registry()

    def close(self) -> None:
        self.live_observation_patcher.stop()
        self.store.close()
        self.temporary.cleanup()

    def _terminal_live_observation(
        self, repository: str, issue_number: int, remote_receipt: str
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
        list[dict[str, object]],
    ]:
        self.assert_repository(repository)
        comment_id = int(remote_receipt.split(":", 1)[1])
        return (
            dict(self.remote_issues[issue_number]),
            {
                "ref": "refs/heads/main",
                "object": {"sha": MAIN},
            },
            dict(self.remote_comments[comment_id]),
            [dict(event) for event in self.remote_timelines[issue_number]],
        )

    @staticmethod
    def assert_repository(repository: str) -> None:
        if repository != REPOSITORY:
            raise AssertionError(f"unexpected repository: {repository}")

    def _migrate_registry(self) -> None:
        skill_root = Path(__file__).resolve().parents[1]
        config = load_registry_config(
            skill_root / "tests" / "fixtures" / "twinfinity-executor-registry-v4.toml"
        )
        aliases, alias_sha = load_legacy_alias_fixture(
            skill_root / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="capacity-dispatch-flow-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T09:59:00Z",
        )

    def set_capacity(self, development: int, shared: int, sre: int) -> dict:
        current = self.store.capacity_policy(
            REPOSITORY, now="2026-08-24T09:59:01Z"
        )
        return self.store.set_capacity_policy(
            repository=REPOSITORY,
            development_limit=development,
            shared_limit=shared,
            sre_limit=sre,
            authority_sha256="c" * 64,
            expected_version=int(current["version"]),
            now="2026-08-24T09:59:02Z",
        )

    def snapshot(self, issue_number: int) -> str:
        payload = {
            "_projection_version": 3,
            "number": issue_number,
            "title": f"Vertical slice {issue_number}",
            "state": "open",
            "updated_at": "2026-08-24T10:00:00Z",
            "milestone": {
                "number": 1,
                "title": "Throughput simulation",
                "state": "open",
            },
        }
        self.remote_issues[issue_number] = dict(payload)
        observed = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue_number,
            payload=payload,
            source_updated_at="2026-08-24T10:00:00Z",
            fetched_at="2026-08-24T10:00:00Z",
        )
        self.sources[issue_number] = observed.payload_sha256
        return observed.payload_sha256

    @staticmethod
    def _endpoint_for(units: dict[str, int]) -> str:
        return SRE_ENDPOINT if units["sre"] else DEVELOPMENT_ENDPOINT

    def install_portfolio(
        self,
        specs: list[dict[str, object]],
        relations: list[tuple[int, int, str]] | None = None,
    ) -> None:
        hard_left = {
            left for left, _right, kind in relations or [] if kind == "HARD_BLOCK"
        }
        hard_right = {
            right for _left, right, kind in relations or [] if kind == "HARD_BLOCK"
        }
        for spec in specs:
            issue = int(spec["issue"])
            self.snapshot(issue)
            units = dict(spec["units"])
            requested_status = str(spec.get("status", "READY"))
            status = "PREPARED" if requested_status == "READY" else requested_status
            allocation = "ACTIVE" if status == "ACTIVE" else "NONE"
            endpoint = self._endpoint_for(units)
            lease = (
                hashlib.sha256(f"active:{issue}".encode()).hexdigest()
                if allocation == "ACTIVE"
                else None
            )
            self.items[issue] = self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=issue,
                status=status,
                allocation_class=allocation,
                generation=1,
                accountable_session_id=endpoint,
                lease_manifest_sha256=lease,
                development_units=int(units["development"]),
                shared_units=int(units["shared"]),
                sre_units=int(units["sre"]),
                expected_source_sha256=self.sources[issue],
                expected_version=0,
                now="2026-08-24T10:00:01Z",
            )

        graph_relations = []
        for left, right, kind in relations or []:
            graph_relations.append(
                {
                    "left_node_key": f"issue:{left}",
                    "right_node_key": f"issue:{right}",
                    "relation_kind": kind,
                    "reason": f"Deterministic {kind.lower()} simulation",
                    "source_payload_sha256": self.sources[left],
                }
            )
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0,
                "scope_milestones": [
                    {"title": "Throughput simulation", "rank": 1}
                ],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": f"issue:{int(spec['issue'])}",
                        "issue_number": int(spec["issue"]),
                        "role": str(spec.get("role", "DELIVERY")),
                        "root_kind": (
                            "NORMAL"
                            if int(spec["issue"]) in hard_right
                            else "INTENTIONAL"
                            if int(spec["issue"]) in hard_left
                            else "STANDALONE"
                        ),
                        "root_reason": (
                            None
                            if int(spec["issue"]) in hard_right
                            else "Explicit simulated portfolio root"
                        ),
                        "lane_key": str(spec.get("lane", f"lane-{spec['issue']}")),
                        "lane_order": int(spec.get("order", 0)),
                        "dispatchable": True,
                        "priority_rank": int(spec.get("priority", 1)),
                        "estimate_units": 1,
                        "development_units": int(dict(spec["units"])["development"]),
                        "shared_units": int(dict(spec["units"])["shared"]),
                        "sre_units": int(dict(spec["units"])["sre"]),
                        "source_payload_sha256": self.sources[int(spec["issue"])],
                        "ready_at": str(
                            spec.get("ready_at", "2026-08-24T10:00:00Z")
                        ),
                    }
                    for spec in specs
                ],
                "relations": graph_relations,
            },
            now="2026-08-24T10:00:02Z",
        )

    def register_ready_candidate(self, issue_number: int, now: str) -> dict:
        item = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (REPOSITORY, issue_number),
            ).fetchone()
        )
        units = {
            "development_units": int(item["development_units"]),
            "shared_units": int(item["shared_units"]),
            "sre_units": int(item["sre_units"]),
        }
        endpoint = SRE_ENDPOINT if units["sre_units"] else DEVELOPMENT_ENDPOINT
        topic = "sre.admission" if units["sre_units"] else "development.admission"
        plans = self.root / "plans"
        plans.mkdir(exist_ok=True)
        branch = f"codex/{issue_number}-capacity-flow"
        worktree = f"/home/ubuntu/code/twinfinityapp-issue-{issue_number}"
        lease_path = plans / f"issue-{issue_number}-lease.json"
        lease_payload = {
            "repository": REPOSITORY,
            "issue_number": issue_number,
            "generation": int(item["generation"]),
            "base_sha": MAIN,
            "branch": branch,
            "worktree_path": worktree,
            "no_additional_paths": True,
            "paths": [
                {
                    "path": f"flow/issue_{issue_number}.py",
                    "mode": "100644",
                    "type": "blob",
                    "sha": hashlib.sha1(str(issue_number).encode()).hexdigest(),
                }
            ],
        }
        lease_path.write_text(
            json.dumps(lease_payload, sort_keys=True) + "\n", encoding="utf-8"
        )
        lease_sha = hashlib.sha256(lease_path.read_bytes()).hexdigest()
        artifact = {
            "repository": REPOSITORY,
            "issue_number": issue_number,
            "generation": int(item["generation"]),
            "path": str(lease_path),
            "retention_class": "CLOSEOUT_EVIDENCE",
        }
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": issue_number,
                "payload_sha256": self.sources[issue_number],
            },
            "issue_number": issue_number,
            "generation": int(item["generation"]),
            "item_version": int(item["version"]) + 2,
            "base_sha": MAIN,
            "branch": branch,
            "worktree_path": worktree,
            "opaque_worktree_id": f"flow-{issue_number}",
            "accountable_session_id": endpoint,
            "lease_manifest_sha256": lease_sha,
            "authority_sha256": "7" * 64,
            "capacity": units,
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
        }
        if topic == "development.admission":
            payload.update(
                {
                    "writer": f"issue-{issue_number}-writer",
                    "reviewer_plan": ["Independent exact-head review."],
                    "collision_proof": ["The selected lease is disjoint."],
                    "environment_rule": "Use only the issue-owned environment.",
                    "routine_chain": ["Run bounded gates and routine closeout."],
                    "hard_stops": ["Stop on source, lease, or capacity drift."],
                }
            )
        policy = self.store.capacity_policy(REPOSITORY, now=now)
        packet = {
            "schema": "twinfinity-kanban-pull-buffer/v2",
            "repository": REPOSITORY,
            "issue_number": issue_number,
            "generation": int(item["generation"]),
            "item_version_at_preparation": int(item["version"]),
            "source_payload_sha256": self.sources[issue_number],
            "accepted_main_at_preparation": MAIN,
            "portfolio_graph_version": 1,
            "state": "PREPARED_NOT_READY",
            "verticality": "END_TO_END",
            "owner_visible_outcome": f"Deliver vertical slice {issue_number}.",
            "capacity_policy": {
                "version": int(policy["version"]),
                "development_limit": int(policy["development_limit"]),
                "shared_limit": int(policy["shared_limit"]),
                "sre_limit": int(policy["sre_limit"]),
            },
            "capacity_on_activation": units,
            "precomputed_collision_matrix": [
                {
                    "other_issue": 999,
                    "disposition": "DISJOINT",
                    "reason": "Synthetic lease paths are issue-unique.",
                }
            ],
            "preparation_complete": ["Admission envelope is complete."],
            "promotion_checks_after_predecessor": [
                "Re-evaluate dependencies, collisions, and capacity."
            ],
            "hard_stops": ["Stop on any controlling-state drift."],
            "promotion_trigger": "Capacity and hard dependencies are satisfied.",
        }
        admission_transaction = {
            "item": {
                "repository": REPOSITORY,
                "issue_number": issue_number,
                "status": "ACTIVE",
                "allocation_class": "ACTIVE",
                "generation": int(item["generation"]),
                "accountable_session_id": endpoint,
                "lease_manifest_sha256": lease_sha,
                **units,
                "expected_source_sha256": self.sources[issue_number],
                "expected_version": int(item["version"]) + 1,
            },
            "message": {
                "idempotency_key": f"capacity-flow-issue-{issue_number}",
                "recipient_session_id": endpoint,
                "topic": topic,
                "payload": payload,
            },
            "artifacts": [artifact],
        }
        result = finalize_canonical_ready_candidate(
            self.store,
            database=self.database,
            artifact_root=self.root,
            prepared_packet=packet,
            admission_transaction=admission_transaction,
            worker_role="sre" if units["sre_units"] else "development",
            worker_endpoint_id=endpoint,
            now=now,
            suffix="capacity-flow",
        )
        self.items[issue_number] = result["item"]
        return result["finalized"]

    def _reserve_running(
        self, role: str, endpoint: str, target_kind: str, target_key: str
    ) -> int:
        reserved, token = reserve_attempt(
            self.store.connection,
            role=role,
            endpoint_id=endpoint,
            target_kind=target_kind,
            target_key=target_key,
            now="2026-08-24T10:01:00Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, target_kind, target_key
            ),
        )
        unit = stable_systemd_unit(role, target_kind, target_key)
        invocation = hashlib.md5(f"{role}:{target_kind}:{target_key}".encode()).hexdigest()
        launching = transition_attempt(
            self.store.connection,
            attempt_id=str(reserved["attempt_id"]),
            token=token,
            expected_version=int(reserved["version"]),
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=invocation,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-24T10:01:00Z",
        )
        self.next_process_id += 1
        running = transition_attempt(
            self.store.connection,
            attempt_id=str(reserved["attempt_id"]),
            token=token,
            expected_version=int(launching["version"]),
            new_state="RUNNING",
            process_id=self.next_process_id,
            now="2026-08-24T10:01:00Z",
        )
        if target_kind == "message":
            message_id = int(target_key)
            self.attempts_by_message[message_id] = (running, token)
            message = self.store.connection.execute(
                "SELECT payload_json FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()
            issue_number = int(json.loads(message["payload_json"])["issue_number"])
            self.message_by_issue[issue_number] = message_id
        return self.next_process_id

    def message_launcher(self, endpoint: str, message_id: int) -> int:
        role = "sre" if endpoint == SRE_ENDPOINT else "development"
        return self._reserve_running(role, endpoint, "message", str(message_id))

    def hosted_launcher(self, **kwargs: object) -> int:
        return_code = self._reserve_running(
            str(kwargs["role"]),
            str(kwargs["endpoint_id"]),
            str(kwargs["target_kind"]),
            str(kwargs["target_key"]),
        )
        return 0 if return_code > 0 else 1

    def supervisor(self) -> CoordinationSupervisor:
        return CoordinationSupervisor(
            self.store,
            convergence=PortfolioConvergence(
                self.store, canonical_main_reader=lambda _repository: MAIN
            ),
            launcher=self.message_launcher,
            terminal_watch_launcher=lambda _endpoint, _watch: 9999,
            process_checker=lambda _endpoint, _kind, _key: False,
        )

    def complete_issue(self, issue_number: int, now: str) -> None:
        message_id = self.message_by_issue[issue_number]
        running, token = self.attempts_by_message[message_id]
        endpoint = str(running["endpoint_id"])
        self.store.claim_message(
            message_id,
            endpoint,
            now,
            attempt_id=str(running["attempt_id"]),
            executor_token=token,
        )
        item = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (REPOSITORY, issue_number),
            ).fetchone()
        )
        lease = str(item["lease_manifest_sha256"])
        generation = int(item["generation"])
        watch_key = (
            f"terminal:{REPOSITORY}:issue:{issue_number}:generation:{generation}"
        )
        receipt = {
            "schema": "twinfinity-terminal-receipt/v1",
            "repository": REPOSITORY,
            "issue_number": issue_number,
            "generation": generation,
            "source_payload_sha256": self.sources[issue_number],
            "lease_manifest_sha256": lease,
            "outcome": "ACCEPTED",
            "accepted_head_sha": MAIN if endpoint == DEVELOPMENT_ENDPOINT else None,
            "operational_state_sha256": (
                None if endpoint == DEVELOPMENT_ENDPOINT else "e" * 64
            ),
            "acceptance_evidence_sha256": "d" * 64,
            "residual_risks": [],
        }
        cleanup = {
            "schema": "twinfinity-terminal-cleanup/v1",
            "repository": REPOSITORY,
            "issue_number": issue_number,
            "generation": generation,
            "lease_manifest_sha256": lease,
            "owned_resources_absent": True,
            "temporary_resources_absent": True,
            "worktree_disposition": (
                "ABSENT" if endpoint == DEVELOPMENT_ENDPOINT else "NOT_APPLICABLE"
            ),
            "local_branch_disposition": (
                "ABSENT" if endpoint == DEVELOPMENT_ENDPOINT else "NOT_APPLICABLE"
            ),
            "remote_branch_disposition": (
                "ABSENT" if endpoint == DEVELOPMENT_ENDPOINT else "NOT_APPLICABLE"
            ),
            "residuals": [],
        }
        closeout_key = (
            f"terminal-closeout:{REPOSITORY}:issue:{issue_number}:generation:{generation}"
        )
        prepared = self.store.prepare_terminal_closeout(
            packet={
                "schema": "twinfinity-terminal-closeout-packet/v1",
                "repository": REPOSITORY,
                "issue_number": issue_number,
                "generation": generation,
                "expected_item_version": int(item["version"]),
                "source_payload_sha256": self.sources[issue_number],
                "lease_manifest_sha256": lease,
                "terminal_watch_key": watch_key,
                "activation_message_id": message_id,
                "terminal_receipt": receipt,
                "cleanup_evidence": cleanup,
                "outbox": {
                    "idempotency_key": closeout_key,
                    "body": terminal_publication_body(
                        closeout_key=closeout_key,
                        terminal_receipt=receipt,
                        cleanup_evidence=cleanup,
                    ),
                },
            },
            attempt_id=str(running["attempt_id"]),
            executor_token=token,
            now=now,
        )
        self.store.bind_terminal_outbox_publisher(
            outbox_id=int(prepared["outbox_id"]),
            publisher_login="twinfinity-bot",
            now=now,
        )
        self.store.reserve_outbox(int(prepared["outbox_id"]), now)
        outbox = self.store.connection.execute(
            "SELECT idempotency_key,payload_json FROM github_outbox WHERE id=?",
            (prepared["outbox_id"],),
        ).fetchone()
        body = json.loads(outbox["payload_json"])["body"]
        published_body = terminal_published_body(
            body, str(outbox["idempotency_key"])
        )
        comment = {
            "id": issue_number,
            "event": "commented",
            "body": published_body,
            "created_at": now,
            "updated_at": now,
            "issue_url": (
                f"https://api.github.com/repos/{REPOSITORY}/issues/{issue_number}"
            ),
            "user": {"login": "twinfinity-bot"},
        }
        self.remote_comments[issue_number] = dict(comment)
        self.remote_timelines[issue_number] = [dict(comment)]
        self.store.complete_terminal_outbox_from_readback(
            outbox_id=int(prepared["outbox_id"]),
            remote_receipt=f"comment:{issue_number}",
            published_body=published_body,
            publisher_login="twinfinity-bot",
            now=now,
        )
        self.remote_issues[issue_number] = {
            **self.remote_issues[issue_number],
            "updated_at": now,
        }
        self.store.commit_terminal_closeout(
            closeout_key=closeout_key,
            attempt_id=str(running["attempt_id"]),
            executor_token=token,
        )
        transition_attempt(
            self.store.connection,
            attempt_id=str(running["attempt_id"]),
            token=token,
            expected_version=int(running["version"]),
            new_state="COMPLETE",
            exit_code=0,
            now=now,
        )
        item = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
                (REPOSITORY, issue_number),
            ).fetchone()
        )
        self.items[issue_number] = item


class CapacityDispatchFlowTests(unittest.TestCase):
    def test_transport_submission_timeout_uses_the_existing_nonzero_contract(self) -> None:
        observed_timeout = None

        def timed_out(command, **kwargs):
            nonlocal observed_timeout
            observed_timeout = kwargs["timeout"]
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        timed_out_result = launch_role_executor(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="37",
            prompt="Execute exact synthetic target 37",
            runner=timed_out,
        )
        numeric_result = launch_role_executor(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key="38",
            prompt="Execute exact synthetic target 38",
            runner=lambda _command, **_kwargs: types.SimpleNamespace(returncode=17),
        )

        self.assertEqual(SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS, observed_timeout)
        self.assertEqual(5, observed_timeout)
        self.assertEqual(1, timed_out_result)
        self.assertEqual(17, numeric_result)

    def test_real_transport_spins_all_target_specific_writers_without_role_lock(self) -> None:
        targets = [
            *(('development', DEVELOPMENT_ENDPOINT, str(index)) for index in range(1, 7)),
            *(('sre', SRE_ENDPOINT, str(index)) for index in range(7, 10)),
        ]
        barrier = threading.Barrier(len(targets))
        lock = threading.Lock()
        commands: list[list[str]] = []
        active = 0
        peak = 0

        def runner(command, **_kwargs):
            nonlocal active, peak
            with lock:
                commands.append(command)
                active += 1
                peak = max(peak, active)
            barrier.wait(timeout=5)
            with lock:
                active -= 1
            return types.SimpleNamespace(returncode=0)

        def launch(target):
            role, endpoint, key = target
            return launch_role_executor(
                role=role,
                endpoint_id=endpoint,
                target_kind="message",
                target_key=key,
                prompt=f"Execute exact synthetic target {key}",
                runner=runner,
            )

        with ThreadPoolExecutor(max_workers=len(targets)) as executor:
            results = list(executor.map(launch, targets))

        self.assertEqual([0] * len(targets), results)
        self.assertEqual(len(targets), peak, "transport serialized disjoint writers")
        self.assertEqual(len(targets), len(commands))
        units = [next(token for token in command if token.startswith("--unit=")) for command in commands]
        self.assertEqual(len(targets), len(set(units)))
        self.assertTrue(all(command[0:3] == ["/usr/bin/systemd-run", "--user", "--quiet"] for command in commands))
        expected_working_directory = f"--working-directory={Path.cwd().resolve()}"
        self.assertTrue(all(expected_working_directory in command for command in commands))
        self.assertEqual(6, sum(DEVELOPMENT_ENDPOINT in command for command in commands))
        self.assertEqual(3, sum(SRE_ENDPOINT in command for command in commands))

    def test_real_transport_rejects_a_missing_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaisesRegex(
                RegistryError,
                "ROLE_EXECUTOR_WORKING_DIRECTORY_INVALID",
            ):
                launch_role_executor(
                    role="sre",
                    endpoint_id=SRE_ENDPOINT,
                    target_kind="message",
                    target_key="178",
                    prompt="Execute exact synthetic target 178",
                    working_directory=missing,
                )

    def test_capacity_policy_change_enqueues_a_convergence_wake(self) -> None:
        harness = _FlowHarness()
        try:
            prior = harness.store.capacity_policy(
                REPOSITORY, now="2026-08-24T09:59:01Z"
            )
            self.assertEqual(
                (5, 2),
                (prior["development_limit"], prior["shared_limit"]),
            )
            dirty_before = harness.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_dirty_events"
            ).fetchone()[0]
            policy = harness.set_capacity(6, 3, 3)
            dirty_after = harness.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_dirty_events"
            ).fetchone()[0]

            self.assertEqual(
                (6, 3, 3),
                (
                    policy["development_limit"],
                    policy["shared_limit"],
                    policy["sre_limit"],
                ),
            )
            self.assertEqual(
                dirty_before + 1,
                dirty_after,
                "capacity policy change did not enqueue convergence work",
            )
            wake = harness.store.connection.execute(
                "SELECT event_key,event_sha256,payload_json,state "
                "FROM portfolio_dirty_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            payload = json.loads(wake["payload_json"])
            self.assertEqual("PENDING", wake["state"])
            self.assertEqual("CAPACITY_POLICY_CHANGED", payload["trigger_kind"])
            self.assertEqual(2, payload["capacity_policy_version"])
            self.assertEqual((6, 3, 3), (
                payload["development_limit"],
                payload["shared_limit"],
                payload["sre_limit"],
            ))
            self.assertIn(wake["event_sha256"], wake["event_key"])
        finally:
            harness.close()

    def test_dependency_collision_and_fifo_head_do_not_starve_disjoint_work(self) -> None:
        harness = _FlowHarness()
        try:
            harness.install_portfolio(
                [
                    {"issue": 100, "status": "ACTIVE", "priority": 9,
                     "units": {"development": 1, "shared": 1, "sre": 0}},
                    {"issue": 101, "priority": 1,
                     "units": {"development": 1, "shared": 1, "sre": 0}},
                    {"issue": 102, "priority": 2,
                     "units": {"development": 1, "shared": 1, "sre": 0}},
                    {"issue": 103, "status": "QUEUED", "priority": 3,
                     "units": {"development": 0, "shared": 0, "sre": 0}},
                    {"issue": 104, "priority": 4,
                     "units": {"development": 1, "shared": 0, "sre": 0}},
                ],
                relations=[(100, 101, "COLLISION"), (103, 104, "HARD_BLOCK")],
            )
            harness.register_ready_candidate(102, "2026-08-24T10:00:03Z")
            decision = schedule(
                harness.store.connection,
                REPOSITORY,
                current_main=MAIN,
                record=True,
                now="2026-08-24T10:00:03Z",
            )

            self.assertEqual(["issue:102"], decision["selected"])
            self.assertEqual([], decision["skipped"])
            self.assertEqual(
                "PREPARED",
                harness.store.connection.execute(
                    "SELECT status FROM coordination_items WHERE repository=? "
                    "AND issue_number=101",
                    (REPOSITORY,),
                ).fetchone()[0],
            )
            self.assertNotIn("issue:104", decision["ordered_ready"])
            self.assertGreaterEqual(decision["remaining_capacity"]["development"], 0)
            self.assertGreaterEqual(decision["remaining_capacity"]["shared"], 0)
            self.assertGreaterEqual(decision["remaining_capacity"]["sre"], 0)
        finally:
            harness.close()

    def test_six_development_three_sre_flow_to_distinct_writers_and_refills(self) -> None:
        harness = _FlowHarness()
        try:
            policy = harness.set_capacity(6, 3, 3)
            self.assertEqual((6, 3, 3), (
                policy["development_limit"], policy["shared_limit"], policy["sre_limit"]
            ))

            development = [201, 202, 203, 204, 205, 206]
            sre = [207, 208, 209]
            refill = 210
            specs = [
                {
                    "issue": issue,
                    "priority": index,
                    "units": {
                        "development": 1,
                        "shared": 1 if index <= 3 else 0,
                        "sre": 0,
                    },
                }
                for index, issue in enumerate(development, 1)
            ] + [
                {
                    "issue": issue,
                    "priority": index,
                    "units": {"development": 0, "shared": 0, "sre": 1},
                }
                for index, issue in enumerate(sre, 7)
            ] + [
                {
                    "issue": refill,
                    "status": "PREPARED",
                    "priority": 10,
                    "units": {"development": 1, "shared": 1, "sre": 0},
                }
            ]
            harness.install_portfolio(specs)
            expected_issues = development + sre
            expected_nodes = [f"issue:{issue}" for issue in expected_issues]
            for offset, issue in enumerate(expected_issues, 4):
                harness.register_ready_candidate(
                    issue, f"2026-08-24T10:00:{offset:02d}Z"
                )
            selected = schedule(
                harness.store.connection,
                REPOSITORY,
                current_main=MAIN,
                record=True,
                now="2026-08-24T10:00:03Z",
            )
            self.assertEqual(expected_nodes, selected["selected"])
            self.assertEqual(
                {"development": 0, "shared": 0, "sre": 0},
                selected["remaining_capacity"],
            )
            supervisor = harness.supervisor()
            results = [
                supervisor.run_once("2026-08-24T10:01:00Z"),
                supervisor.run_once("2026-08-24T10:01:01Z"),
                supervisor.run_once("2026-08-24T10:01:02Z"),
            ]
            result = results[0]
            admitted = [
                entry["admitted_issue_number"]
                for entry in result["portfolio_convergence"]
                if entry.get("outcome") == "ADMITTED"
            ]
            launched_messages = [
                entry["message_id"]
                for pass_result in results
                for entry in pass_result["launched"]
            ]
            launched_issues = [
                int(json.loads(harness.store.connection.execute(
                    "SELECT payload_json FROM coordination_messages WHERE id=?", (message_id,)
                ).fetchone()["payload_json"])["issue_number"])
                for message_id in launched_messages
            ]
            self.assertEqual(9, len(selected["selected"]), selected)
            self.assertEqual(9, len(admitted), result["portfolio_convergence"])
            self.assertEqual(9, len(launched_issues), launched_messages)
            self.assertEqual(
                (len(selected["selected"]), len(admitted), len(launched_issues)),
                (9, 9, 9),
                "selected -> admitted -> launched flow lost capacity",
            )
            self.assertEqual(expected_issues, admitted, result["portfolio_convergence"])
            self.assertEqual(expected_issues, launched_issues)
            self.assertTrue(
                all(
                    pass_result["launch_attempts"]["total"] <= 4
                    for pass_result in results
                )
            )
            self.assertTrue(
                all(not pass_result["terminal_watch_launches"] for pass_result in results)
            )

            active = harness.store.connection.execute(
                "SELECT role,target_kind,target_key,lineage_sha256,systemd_unit,"
                "systemd_invocation_id,systemd_control_group,state "
                "FROM executor_attempts WHERE state='RUNNING' ORDER BY rowid"
            ).fetchall()
            self.assertEqual(9, len(active), "selected work did not reach exact writers")
            self.assertEqual(6, sum(row["role"] == "development" for row in active))
            self.assertEqual(3, sum(row["role"] == "sre" for row in active))
            self.assertEqual(9, len({row["lineage_sha256"] for row in active}))
            self.assertTrue(all(row["target_kind"] == "message" for row in active))
            self.assertTrue(all(row["systemd_unit"] for row in active))
            self.assertTrue(all(row["systemd_invocation_id"] for row in active))
            self.assertTrue(all(row["systemd_control_group"] for row in active))
            occupancy = harness.store.connection.execute(
                "SELECT SUM(development_units),SUM(shared_units),SUM(sre_units) "
                "FROM coordination_items WHERE allocation_class IN ('ACTIVE','RETAINED')"
            ).fetchone()
            self.assertEqual((6, 3, 3), tuple(occupancy))

            first_message = harness.message_by_issue[development[0]]
            first_lineage = attempt_lineage_for_target(
                harness.store.connection, "message", str(first_message)
            )
            watch_key = harness.store.connection.execute(
                "SELECT watch_key FROM coordination_terminal_watches "
                "WHERE repository=? AND issue_number=?",
                (REPOSITORY, development[0]),
            ).fetchone()["watch_key"]
            with self.assertRaisesRegex(RegistryError, "EXECUTOR_LINEAGE_BUSY"):
                reserve_attempt(
                    harness.store.connection,
                    role="development",
                    endpoint_id=DEVELOPMENT_ENDPOINT,
                    target_kind="terminal_watch",
                    target_key=str(watch_key),
                    now="2026-08-24T10:01:01Z",
                    precondition=lambda _connection: first_lineage,
                )

            harness.complete_issue(development[0], "2026-08-24T10:02:00Z")
            harness.register_ready_candidate(refill, "2026-08-24T10:02:03Z")
            refill_decision = schedule(
                harness.store.connection,
                REPOSITORY,
                current_main=MAIN,
                record=True,
                now="2026-08-24T10:02:02Z",
            )
            self.assertEqual([f"issue:{refill}"], refill_decision["selected"])
            refill_result = harness.supervisor().run_once("2026-08-24T10:02:04Z")
            refill_launches = [
                int(json.loads(harness.store.connection.execute(
                    "SELECT payload_json FROM coordination_messages WHERE id=?",
                    (entry["message_id"],),
                ).fetchone()["payload_json"])["issue_number"])
                for entry in refill_result["launched"]
            ]
            self.assertEqual([refill], refill_launches)
            final_occupancy = harness.store.connection.execute(
                "SELECT SUM(development_units),SUM(shared_units),SUM(sre_units) "
                "FROM coordination_items WHERE allocation_class IN ('ACTIVE','RETAINED')"
            ).fetchone()
            self.assertEqual((6, 3, 3), tuple(final_occupancy))
        finally:
            harness.close()

    def test_hosted_sre_skips_blocked_fifo_head_and_launches_all_disjoint_rows(self) -> None:
        harness = _FlowHarness()
        control = None
        try:
            harness.set_capacity(6, 3, 3)
            source_sha = harness.snapshot(143)
            control = HostedOperationControl(harness.database)

            def transaction(index: int) -> dict[str, object]:
                target = str(20717667 + index)
                return {
                    "idempotency_key": f"throughput-hosted-{index}",
                    "repository": REPOSITORY,
                    "issue_number": 143,
                    "source_payload_sha256": source_sha,
                    "provider": "github",
                    "target_kind": "github_ruleset",
                    "target_key": target,
                    "operation_kind": "UPDATE_SETTINGS",
                    "authority_comment_id": 1234,
                    "authority_body_sha256": AUTHORITY_SHA256,
                    "recipient_session_id": SRE_ENDPOINT,
                    "sre_units": 1,
                    "blocked_by_issue_number": None,
                    "scope": {
                        "target": {"repository": REPOSITORY, "ruleset_id": int(target)},
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

            with patch.object(
                HostedOperationControl, "_validate_approval_guard", return_value=None
            ), patch.object(
                HostedOperationControl,
                "_fetch_authority_comment",
                return_value={
                    "id": 1234,
                    "issue_url": f"https://api.github.com/repos/{REPOSITORY}/issues/143",
                    "body": AUTHORITY_BODY,
                },
            ):
                rows = [
                    control.prepare(transaction(index), f"2026-08-24T10:00:0{index}Z")
                    for index in range(1, 4)
                ]

            harness._reserve_running(
                "sre", SRE_ENDPOINT, "hosted_operation", str(rows[0]["id"])
            )
            result = run_hosted_supervisor(
                control,
                "2026-08-24T10:01:03Z",
                launcher=harness.hosted_launcher,
            )
            self.assertEqual([rows[1]["id"], rows[2]["id"]], result["launched"])
            self.assertIn(
                {"operation_id": rows[0]["id"], "reason": "EXECUTOR_TARGET_ACTIVE"},
                result["skipped"],
            )
            self.assertEqual(2, result["capacity"]["reserved"])
            running = harness.store.connection.execute(
                "SELECT target_key FROM executor_attempts "
                "WHERE role='sre' AND target_kind='hosted_operation' AND state='RUNNING' "
                "ORDER BY CAST(target_key AS INTEGER)"
            ).fetchall()
            self.assertEqual(
                [str(row["id"]) for row in rows],
                [row["target_key"] for row in running],
            )
        finally:
            if control is not None:
                control.close()
            harness.close()


if __name__ == "__main__":
    unittest.main()
