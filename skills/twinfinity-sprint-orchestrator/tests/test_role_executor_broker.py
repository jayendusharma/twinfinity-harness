from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationStore, canonical_json  # noqa: E402
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from executor_registry import (  # noqa: E402
    RegistryError,
    SystemdUnitEvidence,
    ensure_executor_registry_schema,
    load_registry_config,
    recover_reserved_attempts,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import PLAN_SCHEMA, RECEIPT_SCHEMA, dispatch, register  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
from reconcile_routing_artifacts import _verify_or_insert_endpoint  # noqa: E402
import role_executor_broker as broker  # noqa: E402
from role_executor_broker import (  # noqa: E402
    BROKER_PROTOCOL,
    CONTRACT_SCHEMA,
    INPUT_SCHEMA,
    RESULT_MAX_BYTES,
    RESULT_PATH,
    BrokerError,
    BrokerEvaluatorInactivity,
    BrokerRuntimePaths,
    _build_input_projection,
    _execute_brokered_readiness_mechanics,
    attest_broker_systemd_limits,
    attest_bwrap_command,
    broker_terminal_readback,
    build_bwrap_command,
    claim_attach_and_start,
    complete_broker_receipt,
    consume_broker_pickup,
    hold_broker_run,
    mark_broker_launching,
    prepare_broker_run,
    prepare_spool,
    read_receipt_file,
    replay_broker_receipt,
    recover_stale_broker_runs,
)
from role_executor_transport import (  # noqa: E402
    BROKER_SYSTEMD_CPU_QUOTA_PERCENT,
    BROKER_SYSTEMD_MEMORY_MAX_BYTES,
    BROKER_SYSTEMD_RUNTIME_MAX_SECONDS,
    BROKER_SYSTEMD_TASKS_MAX,
    launch_role_executor,
)
from run_role_executor import execute_role  # noqa: E402


CONFIG = ROOT / "references" / "twinfinity-executor-registry.toml"
REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
NOW = "2026-08-25T05:00:00Z"


def systemd_evidence(
    role: str,
    target_kind: str,
    target_key: str,
) -> SystemdUnitEvidence:
    unit = stable_systemd_unit(role, target_kind, target_key)
    return SystemdUnitEvidence(
        unit=unit,
        load_state="loaded",
        active_state="active",
        sub_state="running",
        invocation_id="b" * 32,
        control_group=(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit
        ),
        result="success",
        memory_max=str(BROKER_SYSTEMD_MEMORY_MAX_BYTES),
        tasks_max=str(BROKER_SYSTEMD_TASKS_MAX),
        runtime_max_usec=f"{BROKER_SYSTEMD_RUNTIME_MAX_SECONDS}s",
        cpu_quota_per_sec_usec=(
            f"{BROKER_SYSTEMD_CPU_QUOTA_PERCENT / 100:g}s"
        ),
    )


def process_exit(
    process_id: int = 9001, exit_code: int = 0
) -> BrokerEvaluatorInactivity:
    return BrokerEvaluatorInactivity(
        kind="PROCESS_EXIT", process_id=process_id, exit_code=exit_code
    )


class _ReceiptProcess:
    pid = 43210

    def __init__(self, gate_fd: int, on_poll):
        self._gate_fd = os.dup(gate_fd)
        self._on_poll = on_poll
        self._finished = False
        self.terminated = False
        self.wait_timeouts = []

    def poll(self):
        if not self._finished:
            self._on_poll()
            os.close(self._gate_fd)
            self._gate_fd = -1
            self._finished = True
        return 0

    def terminate(self):
        self.terminated = True
        if self._gate_fd >= 0:
            os.close(self._gate_fd)
            self._gate_fd = -1

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        return self.poll()

    def kill(self):
        self.terminate()


class _NeverProcess:
    pid = 43211

    def __init__(self, gate_fd: int):
        self._gate_fd = os.dup(gate_fd)
        self.terminated = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True
        if self._gate_fd >= 0:
            os.close(self._gate_fd)
            self._gate_fd = -1

    def wait(self, timeout=None):
        if self.terminated:
            return -15
        raise subprocess.TimeoutExpired("synthetic", timeout)

    def kill(self):
        self.terminate()


class _DelayedKillProcess:
    pid = 43212

    def __init__(self, gate_fd: int, *, never_exit: bool):
        self._gate_fd = os.dup(gate_fd)
        self.never_exit = never_exit
        self.terminate_calls = 0
        self.kill_calls = 0
        self.killed = False

    def poll(self):
        return -9 if self.killed and not self.never_exit else None

    def terminate(self):
        self.terminate_calls += 1

    def wait(self, timeout=None):
        result = self.poll()
        if result is None:
            raise subprocess.TimeoutExpired("synthetic-stubborn", timeout)
        return result

    def kill(self):
        self.kill_calls += 1
        if self._gate_fd >= 0:
            os.close(self._gate_fd)
            self._gate_fd = -1
        if not self.never_exit:
            self.killed = True


class BrokerHarness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        for source in sorted((ROOT / "references").glob("*-v*.config.toml")):
            shutil.copy2(source, self.codex_home / source.name)
        self.environment = patch.dict(
            os.environ, {"CODEX_HOME": str(self.codex_home)}
        )
        self.environment.start()
        coordination_root = self.root / "coordination"
        coordination_root.mkdir(mode=0o700)
        self.store = CoordinationStore(coordination_root / "state.sqlite3")
        self.config = load_registry_config(CONFIG)
        ensure_executor_registry_schema(self.store.connection)
        ensure_pull_buffer_schema(self.store.connection)
        self._install_endpoints()
        self.runtime = self._runtime()
        self.source_sha256 = ""
        self.item: dict = {}
        self.candidate_sha256 = ""
        self.message_id = 0
        self.issue_number = 88
        self.seeded_candidates: list[dict[str, object]] = []

    def close(self) -> None:
        self.store.close()
        self.environment.stop()
        self.temporary.cleanup()

    def _install_endpoints(self) -> None:
        with self.store.transaction():
            for endpoint in self.config.endpoints.values():
                _verify_or_insert_endpoint(
                    self.store.connection, endpoint.payload, NOW
                )
            for role, endpoint in self.config.roles.items():
                self.store.connection.execute(
                    """
                    INSERT INTO executor_role_endpoint_current(
                        role, endpoint_id, pointer_version, updated_at
                    ) VALUES (?, ?, 1, ?)
                    """,
                    (role, endpoint.endpoint_id, NOW),
                )

    def _runtime(self) -> BrokerRuntimePaths:
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        files: dict[str, Path] = {}
        for name in ("bwrap", "setpriv", "codex"):
            path = runtime / name
            path.write_bytes(b"test-runtime\n")
            path.chmod(0o700)
            files[name] = path
        return BrokerRuntimePaths(
            spool_root=self.root / "spool",
            bwrap_path=files["bwrap"],
            setpriv_path=files["setpriv"],
            codex_binary_path=files["codex"],
        )

    def seed(self, *, role: str = "development", issue_number: int = 88) -> int:
        if any(
            int(candidate["issue_number"]) == issue_number
            for candidate in self.seeded_candidates
        ):
            raise AssertionError("candidate already seeded")
        self.issue_number = issue_number
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue_number,
            payload={
                "_projection_version": 3,
                "number": issue_number,
                "title": f"Brokered readiness {issue_number}",
                "state": "open",
                "updated_at": NOW,
                "milestone": {"number": 1, "title": "Sprint", "state": "open"},
            },
            source_updated_at=NOW,
            fetched_at=NOW,
        )
        self.source_sha256 = snapshot.payload_sha256
        self.item = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=issue_number,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1 if role == "development" else 0,
            shared_units=0,
            sre_units=1 if role == "sre" else 0,
            expected_source_sha256=snapshot.payload_sha256,
            expected_version=0,
            now=NOW,
        )
        self.seeded_candidates.append(
            {
                "issue_number": issue_number,
                "role": role,
                "source_payload_sha256": snapshot.payload_sha256,
            }
        )
        graph = self.store.connection.execute(
            "SELECT version FROM portfolio_graph_current WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0 if graph is None else int(graph["version"]),
                "scope_milestones": [{"title": "Sprint", "rank": 1}],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": f"issue:{int(candidate['issue_number'])}",
                        "issue_number": int(candidate["issue_number"]),
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent outcome",
                        "lane_key": f"lane-{int(candidate['issue_number'])}",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": index,
                        "estimate_units": 1,
                        "development_units": (
                            1 if candidate["role"] == "development" else 0
                        ),
                        "shared_units": 0,
                        "sre_units": 1 if candidate["role"] == "sre" else 0,
                        "source_payload_sha256": candidate["source_payload_sha256"],
                        "ready_at": NOW,
                    }
                    for index, candidate in enumerate(
                        self.seeded_candidates, start=1
                    )
                ],
                "relations": [],
            },
            now=NOW,
        )
        graph_version = int(
            self.store.connection.execute(
                "SELECT version FROM portfolio_graph_current WHERE repository=?",
                (REPOSITORY,),
            ).fetchone()[0]
        )
        policy_version = int(
            self.store.connection.execute(
                """
                SELECT version FROM coordination_capacity_current
                WHERE repository=?
                """,
                (REPOSITORY,),
            ).fetchone()[0]
        )
        self.candidate_sha256 = hashlib.sha256(
            f"candidate:{issue_number}".encode()
        ).hexdigest()
        with self.store.transaction():
            cursor = self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_candidates(
                    repository, issue_number, generation, item_version,
                    source_payload_sha256, accepted_main_sha, graph_version,
                    capacity_policy_version, lane_key, state, verticality,
                    development_units, shared_units, sre_units, promotion_trigger,
                    artifact_relative_path, artifact_content_sha256,
                    candidate_sha256, registered_at
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?,
                          'PREPARED_NOT_READY', 'END_TO_END', ?, 0, ?,
                          'Close readiness phase', ?, ?,
                          ?, ?)
                """,
                (
                    REPOSITORY,
                    issue_number,
                    int(self.item["version"]),
                    snapshot.payload_sha256,
                    MAIN,
                    graph_version,
                    policy_version,
                    f"lane-{issue_number}",
                    1 if role == "development" else 0,
                    1 if role == "sre" else 0,
                    f"plans/issue-{issue_number}.json",
                    "c" * 64,
                    self.candidate_sha256,
                    NOW,
                ),
            )
            self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_current(
                    repository, issue_number, candidate_id, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (REPOSITORY, issue_number, int(cursor.lastrowid), NOW),
            )
        plan = {
            "schema": PLAN_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": issue_number,
            "generation": 1,
            "item_version": int(self.item["version"]),
            "source_payload_sha256": snapshot.payload_sha256,
            "accepted_main_sha": MAIN,
            "graph_version": graph_version,
            "capacity_policy_version": policy_version,
            "candidate_sha256": self.candidate_sha256,
            "worker_role": role,
            "phase_summary": "Evaluate every readiness gate without mutation.",
            "gates": [
                {
                    "gate_key": "complete-review",
                    "description": "Current source and evidence are sufficient.",
                    "requested_evidence": ["One exact-binding verdict"],
                }
            ],
        }
        register(self.store.connection, plan, now=NOW)
        result = dispatch(self.store, REPOSITORY, max_parallel=1, now=NOW)
        dispatched = next(
            candidate
            for candidate in result["dispatched"]
            if int(candidate["issue_number"]) == issue_number
        )
        self.message_id = int(dispatched["message_id"])
        return self.message_id

    def receipt(self, attempt_id: str, *, verdict: str = "PASS") -> dict:
        return {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": self.issue_number,
            "readiness_plan_sha256": self.store.connection.execute(
                """
                SELECT campaign.plan_sha256
                FROM portfolio_readiness_current current
                JOIN portfolio_readiness_campaigns campaign
                  ON campaign.id=current.campaign_id
                WHERE current.repository=? AND current.issue_number=?
                """,
                (REPOSITORY, self.issue_number),
            ).fetchone()[0],
            "verdict": verdict,
            "worker_role": self.store.connection.execute(
                """
                SELECT campaign.worker_role
                FROM portfolio_readiness_current current
                JOIN portfolio_readiness_campaigns campaign
                  ON campaign.id=current.campaign_id
                WHERE current.repository=? AND current.issue_number=?
                """,
                (REPOSITORY, self.issue_number),
            ).fetchone()[0],
            "message_id": self.message_id,
            "attempt_id": attempt_id,
            "gate_results": [
                {
                    "gate_key": "complete-review",
                    "verdict": "PASS",
                    "evidence_sha256": "e" * 64,
                    "summary": "The complete canonical projection was reviewed.",
                }
            ],
            "resolution": {
                "role": None,
                "actions": [],
                "approval": None,
            },
            "summary": "All requested readiness evidence is sufficient.",
            "observed_at": NOW,
        }

    def reserve_and_launch(self, *, role: str = "development"):
        endpoint = self.config.roles[role]
        reserved, token = reserve_attempt(
            self.store.connection,
            role=role,
            endpoint_id=endpoint.endpoint_id,
            target_kind="message",
            target_key=str(self.message_id),
            now=NOW,
            precondition=lambda _connection: None,
        )
        run = prepare_broker_run(
            self.store.connection,
            configured=endpoint,
            attempt_id=str(reserved["attempt_id"]),
            profile_path=ROOT
            / "references"
            / f"{endpoint.runtime_codex_profile}.config.toml",
            now=NOW,
        )
        spool = prepare_spool(self.runtime, run)
        command = build_bwrap_command(
            configured=endpoint,
            runtime=self.runtime,
            spool=spool,
            start_gate_fd=3,
        )
        mark_broker_launching(
            self.store.connection,
            attempt_id=str(reserved["attempt_id"]),
            token=token,
            evidence=systemd_evidence(role, "message", str(self.message_id)),
            command_attestation=attest_bwrap_command(command),
            now=NOW,
        )
        return endpoint, reserved, token, spool


class RoleExecutorBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = BrokerHarness()

    def tearDown(self) -> None:
        self.h.close()

    def test_v5_catalog_preserves_direct_v3_v4_rollback_bundles(self) -> None:
        self.assertEqual(
            {
                "planner": ("role.planner.v2", None),
                "development": ("role.development.v5", BROKER_PROTOCOL),
                "sre": ("role.sre.v5", BROKER_PROTOCOL),
            },
            {
                role: (endpoint.endpoint_id, endpoint.execution_protocol)
                for role, endpoint in self.h.config.roles.items()
            },
        )
        for endpoint_id in (
            "role.development.v3",
            "role.development.v4",
            "role.sre.v3",
            "role.sre.v4",
        ):
            self.assertIsNone(self.h.config.endpoints[endpoint_id].execution_protocol)
        for role in ("development", "sre"):
            endpoint = self.h.config.roles[role]
            profile_path = (
                ROOT
                / "references"
                / f"{endpoint.runtime_codex_profile}.config.toml"
            )
            self.assertEqual(
                endpoint.profile_sha256,
                hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            )
            profile = tomllib.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual("never", profile["approval_policy"])
            self.assertEqual(
                ["/run/twinfinity-attempt/out"],
                profile["sandbox_workspace_write"]["writable_roots"],
            )
            self.assertNotIn("hooks", profile)
            self.assertNotIn(
                "/home/ubuntu/.codex/twinfinity-coordination",
                profile_path.read_text(encoding="utf-8"),
            )
            self.assertNotIn(
                "TWINFINITY_EXECUTOR_TOKEN",
                profile_path.read_text(encoding="utf-8"),
            )
            provider = profile["model_providers"]["twinfinity-attempt-proxy"]
            self.assertEqual("responses", provider["wire_api"])
            self.assertFalse(provider["requires_openai_auth"])
            self.assertNotIn("env_key", provider)
            self.assertNotIn("auth.json", profile_path.read_text(encoding="utf-8"))

    def test_v5_catalog_rejects_protocol_or_topic_authority_expansion(self) -> None:
        raw = CONFIG.read_text(encoding="utf-8")
        development_start = raw.index("[roles.development]")
        sre_start = raw.index("[roles.sre]")
        development = raw[development_start:sre_start]
        variants = {
            "unknown-protocol": raw.replace(
                'execution_protocol = "readiness/v1"',
                'execution_protocol = "writer/v1"',
                1,
            ),
            "mutating-topic": (
                raw[:development_start]
                + development.replace(
                    'allowed_topics = ["coordination.notice"]',
                    'allowed_topics = ["coordination.notice", "development.admission"]',
                    1,
                )
                + raw[sre_start:]
            ),
            "planner-broker": raw.replace(
                'profile_sha256 = "38d39166c7573d676206a0f70efd4ebbc68c2d74cd743bab85f48de56b5128cf"',
                'profile_sha256 = "38d39166c7573d676206a0f70efd4ebbc68c2d74cd743bab85f48de56b5128cf"\nexecution_protocol = "readiness/v1"',
                1,
            ),
        }
        for name, contents in variants.items():
            candidate = self.h.root / f"{name}.toml"
            candidate.write_text(contents, encoding="utf-8")
            with self.subTest(name=name), self.assertRaises(RegistryError):
                load_registry_config(candidate, codex_home=self.h.codex_home)

    def test_contract_projection_and_bwrap_are_exact_and_authority_free(self) -> None:
        self.h.seed()
        observed: dict = {}

        def launch(command, **kwargs):
            run = self.h.store.connection.execute(
                """
                SELECT * FROM role_executor_broker_runs
                WHERE state='LAUNCHING'
                """
            ).fetchone()
            message = self.h.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (self.h.message_id,),
            ).fetchone()
            current = self.h.store.connection.execute(
                """
                SELECT * FROM portfolio_readiness_current
                WHERE repository=? AND issue_number=88
                """,
                (REPOSITORY,),
            ).fetchone()
            self.assertEqual("PREPARED", message["state"])
            self.assertIsNone(current["attempt_id"])
            observed["command"] = command
            observed["environment"] = kwargs["env"]
            observed["run"] = dict(run)

            def write_receipt():
                attached = self.h.store.connection.execute(
                    """
                    SELECT attempt_id FROM portfolio_readiness_current
                    WHERE repository=? AND issue_number=88
                    """,
                    (REPOSITORY,),
                ).fetchone()[0]
                path = (
                    self.h.runtime.spool_root
                    / str(attached)
                    / "out"
                    / "receipt.json"
                )
                path.write_text(
                    canonical_json(self.h.receipt(str(attached))),
                    encoding="utf-8",
                )

            return _ReceiptProcess(kwargs["pass_fds"][0], write_receipt)

        endpoint = self.h.config.roles["development"]
        result = _execute_brokered_readiness_mechanics(
            self.h.store.connection,
            configured=endpoint,
            profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
            target_kind="message",
            target_key=str(self.h.message_id),
            systemd_evidence=systemd_evidence(
                "development", "message", str(self.h.message_id)
            ),
            target_precondition=lambda _connection: None,
            popen=launch,
            runtime=self.h.runtime,
            heartbeat_seconds=1,
        )
        self.assertEqual(("PASS", "STAGED"), (result["phase"], result["pickup_state"]))
        run = self.h.store.connection.execute(
            "SELECT * FROM role_executor_broker_runs WHERE attempt_id=?",
            (result["attempt_id"],),
        ).fetchone()
        contract = json.loads(run["contract_json"])
        projection = json.loads(run["input_projection_json"])
        self.assertEqual(CONTRACT_SCHEMA, contract["schema"])
        self.assertEqual(BROKER_PROTOCOL, contract["protocol"])
        self.assertEqual(INPUT_SCHEMA, projection["schema"])
        self.assertEqual(RESULT_PATH, contract["result_path"])
        self.assertEqual(RESULT_MAX_BYTES, contract["result_max_bytes"])
        bundle = projection["instruction_bundle"]
        self.assertEqual(
            contract["instruction_closure_sha256"],
            hashlib.sha256(canonical_json(bundle).encode()).hexdigest(),
        )
        self.assertEqual(
            bundle["instruction"]["sha256"],
            hashlib.sha256(
                (self.h.runtime.spool_root / result["attempt_id"] / "instructions" / "SKILL.md").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(
            bundle["receipt_schema"]["sha256"],
            hashlib.sha256(
                (self.h.runtime.spool_root / result["attempt_id"] / "receipt.schema.json").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual("NOT_IMPLEMENTED", contract["model_transport"]["state"])
        self.assertFalse(contract["model_transport"]["requires_openai_auth"])
        self.assertEqual(
            run["input_projection_sha256"],
            hashlib.sha256(run["input_projection_json"].encode()).hexdigest(),
        )
        self.assertEqual(self.h.candidate_sha256, contract["candidate_sha256"])
        self.assertEqual(self.h.source_sha256, contract["source_payload_sha256"])
        self.assertEqual(MAIN, contract["accepted_main_sha"])
        self.assertEqual(
            {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            observed["environment"],
        )
        command = observed["command"]
        self.assertEqual(str(self.h.runtime.setpriv_path), command[0])
        self.assertIn("--no-new-privs", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("--disable-userns", command)
        self.assertIn("--block-fd", command)
        self.assertNotIn("--unshare-net", command)
        self.assertEqual(1, command.count("--bind"))
        bind_index = command.index("--bind")
        self.assertEqual(RESULT_PATH, command[bind_index + 2])
        self.assertIn(
            [
                "--ro-bind",
                str(self.h.runtime.spool_root / result["attempt_id"]),
                "/run/twinfinity-attempt",
            ],
            [command[index : index + 3] for index in range(len(command) - 2)],
        )
        self.assertIn(
            [
                "--ro-bind",
                str(
                    self.h.runtime.spool_root
                    / result["attempt_id"]
                    / "masked-coordination"
                ),
                "/home/ubuntu/.codex/twinfinity-coordination",
            ],
            [command[index : index + 3] for index in range(len(command) - 2)],
        )
        joined = "\n".join(command)
        self.assertNotIn(str(self.h.store.path), joined)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", joined)
        self.assertNotIn("TWINFINITY_EXECUTOR_TOKEN", joined)
        self.assertNotIn("auth.json", joined)
        self.assertIn(
            "/home/ubuntu/.codex/twinfinity-coordination", joined
        )
        for name, invalid in (
            ("missing-cgroup", [part for part in command if part != "--unshare-cgroup"]),
            ("best-effort-cgroup", [
                "--unshare-cgroup-try" if part == "--unshare-cgroup" else part
                for part in command
            ]),
            ("credential-mount", [*command, "auth.json"]),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                BrokerError, "BROKER_NAMESPACE_POLICY_INVALID"
            ):
                attest_bwrap_command(invalid)
        self.assertEqual("COMPLETE", run["state"])
        self.assertEqual(
            "COMPLETE",
            self.h.store.connection.execute(
                "SELECT state FROM executor_attempts WHERE attempt_id=?",
                (result["attempt_id"],),
            ).fetchone()[0],
        )
        self.assertEqual(
            "COMPLETE",
            self.h.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?",
                (self.h.message_id,),
            ).fetchone()[0],
        )
        self.assertEqual(
            "READY_ELIGIBLE",
            self.h.store.connection.execute(
                """
                SELECT state FROM portfolio_readiness_current
                WHERE repository=? AND issue_number=88
                """,
                (REPOSITORY,),
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_receipts"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
            ).fetchone()[0],
        )

    def test_writer_and_hosted_targets_fail_before_attempt_reservation(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        payload = {"not": "readiness"}
        with self.h.store.transaction():
            cursor = self.h.store.connection.execute(
                """
                INSERT INTO coordination_messages(
                    idempotency_key, recipient_session_id, topic,
                    payload_sha256, payload_json, state, claimed_by,
                    created_at, updated_at, last_error
                ) VALUES ('writer-rpc', ?, 'development.admission', ?, ?,
                          'PREPARED', NULL, ?, ?, NULL)
                """,
                (
                    endpoint.endpoint_id,
                    hashlib.sha256(canonical_json(payload).encode()).hexdigest(),
                    canonical_json(payload),
                    NOW,
                    NOW,
                ),
            )
            writer_message = int(cursor.lastrowid)
        for target_kind, target_key in (
            ("message", str(writer_message)),
            ("hosted_operation", "328"),
        ):
            with self.subTest(target_kind=target_kind):
                with self.assertRaisesRegex(
                    BrokerError, "BROKER_RPC_NOT_IMPLEMENTED"
                ):
                    execute_role(
                        self.h.store.connection,
                        config_path=CONFIG,
                        role="development",
                        endpoint_id=endpoint.endpoint_id,
                        target_kind=target_kind,
                        target_key=target_key,
                        prompt="not implemented",
                        systemd_invocation_id="b" * 32,
                        systemd_evidence=systemd_evidence(
                            "development", target_kind, target_key
                        ),
                        broker_runtime=self.h.runtime,
                    )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM executor_attempts"
            ).fetchone()[0],
        )

    def test_exact_bwrap_command_runs_with_mandatory_namespaces_and_start_gate(self) -> None:
        if not Path("/usr/bin/bwrap").exists() or not Path("/usr/bin/setpriv").exists():
            self.skipTest("bubblewrap runtime unavailable")
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        reserved, _token = reserve_attempt(
            self.h.store.connection,
            role="development",
            endpoint_id=endpoint.endpoint_id,
            target_kind="message",
            target_key=str(self.h.message_id),
            now=NOW,
            precondition=lambda _connection: None,
        )
        run = prepare_broker_run(
            self.h.store.connection,
            configured=endpoint,
            attempt_id=str(reserved["attempt_id"]),
            profile_path=ROOT
            / "references"
            / "twinfinity-development-v5.config.toml",
            now=NOW,
        )
        runtime = replace(
            self.h.runtime,
            bwrap_path=Path("/usr/bin/bwrap"),
            setpriv_path=Path("/usr/bin/setpriv"),
            codex_binary_path=Path("/usr/bin/true"),
        )
        spool = prepare_spool(runtime, run)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        try:
            command = build_bwrap_command(
                configured=endpoint,
                runtime=runtime,
                spool=spool,
                start_gate_fd=gate_read,
            )
            attest_bwrap_command(command)
            process = subprocess.Popen(
                command,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                pass_fds=(gate_read,),
                preexec_fn=broker._apply_child_resource_limits,
            )
            os.close(gate_read)
            gate_read = -1
            os.write(gate_write, b"1")
            os.close(gate_write)
            gate_write = -1
            self.assertEqual(0, process.wait(timeout=10))
        finally:
            for descriptor in (gate_read, gate_write):
                if descriptor >= 0:
                    os.close(descriptor)

    def test_runtime_profile_is_snapshotted_before_source_path_drift(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        source = ROOT / "references" / "twinfinity-development-v5.config.toml"
        copied = self.h.root / "reviewed-profile.config.toml"
        copied.write_bytes(source.read_bytes())
        copied.chmod(0o600)
        reserved, _token = reserve_attempt(
            self.h.store.connection,
            role="development",
            endpoint_id=endpoint.endpoint_id,
            target_kind="message",
            target_key=str(self.h.message_id),
            now=NOW,
            precondition=lambda _connection: None,
        )
        run = prepare_broker_run(
            self.h.store.connection,
            configured=endpoint,
            attempt_id=str(reserved["attempt_id"]),
            profile_path=copied,
            now=NOW,
        )
        copied.write_text("tampered after snapshot\n", encoding="utf-8")
        spool = prepare_spool(self.h.runtime, run)
        self.assertEqual(source.read_bytes(), spool.runtime_profile_path.read_bytes())
        command = build_bwrap_command(
            configured=endpoint,
            runtime=self.h.runtime,
            spool=spool,
            start_gate_fd=3,
        )
        self.assertIn(str(spool.runtime_profile_path), command)
        self.assertNotIn(str(copied), command)

    def test_supported_readiness_holds_before_reservation_without_credentials(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        with self.assertRaisesRegex(
            BrokerError, "BROKER_CREDENTIAL_TRANSPORT_NOT_IMPLEMENTED"
        ):
            execute_role(
                self.h.store.connection,
                config_path=CONFIG,
                role="development",
                endpoint_id=endpoint.endpoint_id,
                target_kind="message",
                target_key=str(self.h.message_id),
                prompt="ignored",
                systemd_invocation_id="b" * 32,
                systemd_evidence=systemd_evidence(
                    "development", "message", str(self.h.message_id)
                ),
                broker_runtime=self.h.runtime,
            )
        self.assertEqual(
            (0, "PREPARED", None),
            (
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM executor_attempts"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?",
                    (self.h.message_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT attempt_id FROM portfolio_readiness_current"
                ).fetchone()[0],
            ),
        )

    def test_preclaimed_and_preattached_inputs_never_reserve_a_fresh_attempt(self) -> None:
        endpoint = self.h.config.roles["development"]
        with self.subTest(state="preclaimed"):
            self.h.seed()
            with self.h.store.transaction():
                self.h.store.connection.execute(
                    """
                    UPDATE coordination_messages
                    SET state='CLAIMED', claimed_by=?, updated_at=? WHERE id=?
                    """,
                    (endpoint.endpoint_id, NOW, self.h.message_id),
                )
            with self.assertRaisesRegex(BrokerError, "BROKER_MESSAGE_NOT_PREPARED"):
                _build_input_projection(
                    self.h.store.connection,
                    role="development",
                    endpoint_id=endpoint.endpoint_id,
                    target_kind="message",
                    target_key=str(self.h.message_id),
                )
            self.assertEqual(
                0,
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM executor_attempts"
                ).fetchone()[0],
            )

        self.h.close()
        self.h = BrokerHarness()
        self.h.seed()
        reserved, token = reserve_attempt(
            self.h.store.connection,
            role="development",
            endpoint_id=endpoint.endpoint_id,
            target_kind="message",
            target_key=str(self.h.message_id),
            now=NOW,
            precondition=lambda _connection: None,
        )
        transition_attempt(
            self.h.store.connection,
            attempt_id=str(reserved["attempt_id"]),
            token=token,
            expected_version=int(reserved["version"]),
            new_state="LAUNCH_FAILED",
            now=NOW,
            last_error="synthetic prior",
        )
        with self.h.store.transaction():
            self.h.store.connection.execute(
                "UPDATE portfolio_readiness_current SET attempt_id=?",
                (reserved["attempt_id"],),
            )
        with self.assertRaisesRegex(BrokerError, "BROKER_READINESS_ALREADY_ATTACHED"):
            _build_input_projection(
                self.h.store.connection,
                role="development",
                endpoint_id=endpoint.endpoint_id,
                target_kind="message",
                target_key=str(self.h.message_id),
            )
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM executor_attempts"
            ).fetchone()[0],
        )

    def test_claim_race_reports_authoritative_terminal_readback(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]

        def launch(_command, **kwargs):
            with self.h.store.transaction():
                self.h.store.connection.execute(
                    """
                    UPDATE coordination_messages SET state='CLAIMED', claimed_by=?,
                        updated_at=? WHERE id=? AND state='PREPARED'
                    """,
                    (endpoint.endpoint_id, NOW, self.h.message_id),
                )
            return _ReceiptProcess(kwargs["pass_fds"][0], lambda: None)

        result = _execute_brokered_readiness_mechanics(
            self.h.store.connection,
            configured=endpoint,
            profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
            target_kind="message",
            target_key=str(self.h.message_id),
            systemd_evidence=systemd_evidence(
                "development", "message", str(self.h.message_id)
            ),
            target_precondition=lambda _connection: None,
            popen=launch,
            runtime=self.h.runtime,
            heartbeat_seconds=1,
        )
        self.assertEqual(
            ("HOLD", "LAUNCH_FAILED", "HOLD", "CLAIMED", "RUNNING", None),
            (
                result["phase"],
                result["state"],
                result["broker_state"],
                result["message_state"],
                result["readiness_state"],
                result["readiness_attempt_id"],
            ),
        )

    def test_cleanup_failure_never_fabricates_terminal_state(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]

        def fail(_command, **_kwargs):
            self.h.store.connection.execute(
                """
                CREATE TRIGGER synthetic_broker_hold_abort
                BEFORE UPDATE OF state ON role_executor_broker_runs
                WHEN NEW.state='HOLD'
                BEGIN SELECT RAISE(ABORT, 'synthetic hold abort'); END
                """
            )
            raise OSError("synthetic launch failure")

        result = _execute_brokered_readiness_mechanics(
            self.h.store.connection,
            configured=endpoint,
            profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
            target_kind="message",
            target_key=str(self.h.message_id),
            systemd_evidence=systemd_evidence(
                "development", "message", str(self.h.message_id)
            ),
            target_precondition=lambda _connection: None,
            popen=fail,
            runtime=self.h.runtime,
            heartbeat_seconds=1,
        )
        self.assertEqual("BROKER_CLEANUP_FAILED", result["error"])
        self.assertEqual(("LAUNCHING", "LAUNCHING", "PREPARED"), (
            result["state"], result["broker_state"], result["message_state"]
        ))

    def test_sre_readiness_uses_the_sre_v5_boundary(self) -> None:
        self.h.seed(role="sre")
        observed: dict[str, object] = {}

        def launch(command, **kwargs):
            observed["command"] = command

            def write_receipt():
                attempt_id = self.h.store.connection.execute(
                    "SELECT attempt_id FROM role_executor_broker_runs"
                ).fetchone()[0]
                receipt_path = (
                    self.h.runtime.spool_root
                    / str(attempt_id)
                    / "out"
                    / "receipt.json"
                )
                receipt_path.write_text(
                    canonical_json(self.h.receipt(str(attempt_id))),
                    encoding="utf-8",
                )

            return _ReceiptProcess(kwargs["pass_fds"][0], write_receipt)

        endpoint = self.h.config.roles["sre"]
        result = _execute_brokered_readiness_mechanics(
            self.h.store.connection,
            configured=endpoint,
            profile_path=ROOT / "references" / "twinfinity-sre-v5.config.toml",
            target_kind="message",
            target_key=str(self.h.message_id),
            systemd_evidence=systemd_evidence(
                "sre", "message", str(self.h.message_id)
            ),
            target_precondition=lambda _connection: None,
            popen=launch,
            runtime=self.h.runtime,
            heartbeat_seconds=1,
        )
        self.assertEqual(("PASS", "COMPLETE"), (result["phase"], result["state"]))
        command = observed["command"]
        self.assertIn("twinfinity-sre-v5", command)
        self.assertIn("/run/twinfinity-attempt/instructions/SKILL.md", "\n".join(command))
        run = self.h.store.connection.execute(
            "SELECT role, endpoint_id, state FROM role_executor_broker_runs"
        ).fetchone()
        self.assertEqual(("sre", endpoint.endpoint_id, "COMPLETE"), tuple(run))

    def test_launch_failure_leaves_message_prepared_and_attempt_launch_failed(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]

        def fail(_command, **_kwargs):
            raise OSError("synthetic")

        result = _execute_brokered_readiness_mechanics(
            self.h.store.connection,
            configured=endpoint,
            profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
            target_kind="message",
            target_key=str(self.h.message_id),
            systemd_evidence=systemd_evidence(
                "development", "message", str(self.h.message_id)
            ),
            target_precondition=lambda _connection: None,
            popen=fail,
            runtime=self.h.runtime,
            heartbeat_seconds=1,
        )
        self.assertEqual("HOLD", result["phase"])
        self.assertEqual(
            ("LAUNCH_FAILED", "PREPARED", "HOLD"),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM executor_attempts"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?",
                    (self.h.message_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM role_executor_broker_runs"
                ).fetchone()[0],
            ),
        )

    def test_invalid_receipt_after_attach_holds_every_authoritative_row(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]

        def launch(_command, **kwargs):
            def write_invalid():
                run = self.h.store.connection.execute(
                    "SELECT attempt_id FROM role_executor_broker_runs"
                ).fetchone()[0]
                path = self.h.runtime.spool_root / run / "out" / "receipt.json"
                path.write_text("{}", encoding="utf-8")

            return _ReceiptProcess(kwargs["pass_fds"][0], write_invalid)

        result = _execute_brokered_readiness_mechanics(
            self.h.store.connection,
            configured=endpoint,
            profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
            target_kind="message",
            target_key=str(self.h.message_id),
            systemd_evidence=systemd_evidence(
                "development", "message", str(self.h.message_id)
            ),
            target_precondition=lambda _connection: None,
            popen=launch,
            runtime=self.h.runtime,
            heartbeat_seconds=1,
        )
        self.assertEqual("HOLD", result["phase"])
        self.assertEqual(
            ("HOLD", "HOLD", "HOLD", "HOLD"),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM executor_attempts"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?",
                    (self.h.message_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM portfolio_readiness_current"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM role_executor_broker_runs"
                ).fetchone()[0],
            ),
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM role_executor_broker_receipt_pickups"
            ).fetchone()[0],
        )

    def test_receipt_reader_rejects_duplicate_keys_and_oversize_bytes(self) -> None:
        receipt_path = self.h.root / "receipt.json"
        receipt_path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
        with self.assertRaisesRegex(BrokerError, "BROKER_RECEIPT_DUPLICATE_KEY"):
            read_receipt_file(receipt_path, observed_at=NOW)
        receipt_path.write_bytes(b"x" * (RESULT_MAX_BYTES + 1))
        with self.assertRaisesRegex(BrokerError, "BROKER_RECEIPT_FILE_INVALID"):
            read_receipt_file(receipt_path, observed_at=NOW)

    def test_kernel_file_and_open_file_limits_are_enforced_in_real_children(self) -> None:
        oversized = self.h.root / "rlimit-output.bin"
        file_result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    f"Path({str(oversized)!r}).write_bytes(b'x'*{RESULT_MAX_BYTES + 1})"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=broker._apply_child_resource_limits,
            check=False,
        )
        self.assertNotEqual(0, file_result.returncode)
        self.assertLessEqual(oversized.stat().st_size, RESULT_MAX_BYTES)

        nofile_result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os,sys; opened=[]; "
                    "\ntry:\n"
                    "  [opened.append(open('/dev/null','rb')) for _ in range(128)]\n"
                    "except OSError:\n  sys.exit(23)\n"
                    "sys.exit(0)"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=broker._apply_child_resource_limits,
            check=False,
        )
        self.assertEqual(23, nofile_result.returncode)
        self.assertIsNone(nofile_result.stdout)
        self.assertIsNone(nofile_result.stderr)

    def test_outer_systemd_cgroup_limits_are_built_and_exactly_attested(self) -> None:
        endpoint = self.h.config.roles["development"]
        captured: dict[str, list[str]] = {}

        def runner(command, **_kwargs):
            captured["command"] = command
            return type("Completed", (), {"returncode": 0})()

        self.assertEqual(
            0,
            launch_role_executor(
                role="development",
                endpoint_id=endpoint.endpoint_id,
                target_kind="message",
                target_key="88",
                prompt="credential transport remains disabled",
                working_directory=self.h.root,
                runner=runner,
            ),
        )
        command = captured["command"]
        self.assertIn(
            f"--property=MemoryMax={BROKER_SYSTEMD_MEMORY_MAX_BYTES}", command
        )
        self.assertIn(f"--property=TasksMax={BROKER_SYSTEMD_TASKS_MAX}", command)
        self.assertIn(
            f"--property=RuntimeMaxSec={BROKER_SYSTEMD_RUNTIME_MAX_SECONDS}s",
            command,
        )
        self.assertIn(
            f"--property=CPUQuota={BROKER_SYSTEMD_CPU_QUOTA_PERCENT}%", command
        )
        evidence = systemd_evidence("development", "message", "88")
        self.assertEqual(
            {
                "MemoryMax": BROKER_SYSTEMD_MEMORY_MAX_BYTES,
                "TasksMax": BROKER_SYSTEMD_TASKS_MAX,
                "RuntimeMaxUSec": BROKER_SYSTEMD_RUNTIME_MAX_SECONDS * 1_000_000,
                "CPUQuotaPerSecUSec": BROKER_SYSTEMD_CPU_QUOTA_PERCENT * 10_000,
            },
            attest_broker_systemd_limits(evidence),
        )
        for field in (
            "memory_max",
            "tasks_max",
            "runtime_max_usec",
            "cpu_quota_per_sec_usec",
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                BrokerError, "BROKER_SYSTEMD_LIMITS_INVALID"
            ):
                attest_broker_systemd_limits(replace(evidence, **{field: "infinity"}))

    def test_heartbeat_wait_is_capped_by_remaining_wall_deadline(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        observed: dict[str, _ReceiptProcess] = {}

        def launch(_command, **kwargs):
            def write_receipt():
                attempt_id = self.h.store.connection.execute(
                    "SELECT attempt_id FROM role_executor_broker_runs"
                ).fetchone()[0]
                path = self.h.runtime.spool_root / attempt_id / "out" / "receipt.json"
                path.write_text(
                    canonical_json(self.h.receipt(str(attempt_id))),
                    encoding="utf-8",
                )

            process = _ReceiptProcess(kwargs["pass_fds"][0], write_receipt)
            observed["process"] = process
            return process

        with patch.object(broker, "BROKER_WALL_SECONDS", 7):
            result = _execute_brokered_readiness_mechanics(
                self.h.store.connection,
                configured=endpoint,
                profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
                target_kind="message",
                target_key=str(self.h.message_id),
                systemd_evidence=systemd_evidence(
                    "development", "message", str(self.h.message_id)
                ),
                target_precondition=lambda _connection: None,
                popen=launch,
                runtime=self.h.runtime,
                heartbeat_seconds=30,
            )
        self.assertEqual("PASS", result["phase"])
        self.assertEqual(1, len(observed["process"].wait_timeouts))
        self.assertGreater(observed["process"].wait_timeouts[0], 0)
        self.assertLessEqual(observed["process"].wait_timeouts[0], 7)

    def test_wall_deadline_terminates_child_and_holds_attached_truth(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        observed: dict[str, object] = {}

        def launch(_command, **kwargs):
            observed.update(kwargs)
            process = _NeverProcess(kwargs["pass_fds"][0])
            observed["process"] = process
            return process

        with patch.object(broker, "BROKER_WALL_SECONDS", 0):
            result = _execute_brokered_readiness_mechanics(
                self.h.store.connection,
                configured=endpoint,
                profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
                target_kind="message",
                target_key=str(self.h.message_id),
                systemd_evidence=systemd_evidence(
                    "development", "message", str(self.h.message_id)
                ),
                target_precondition=lambda _connection: None,
                popen=launch,
                runtime=self.h.runtime,
                heartbeat_seconds=1,
            )
        self.assertEqual("BROKER_CHILD_DEADLINE_EXCEEDED", result["boundary_error"])
        self.assertEqual(("HOLD", "HOLD", "HOLD", "HOLD"), (
            result["phase"], result["state"], result["broker_state"],
            result["readiness_state"],
        ))
        self.assertTrue(observed["process"].terminated)
        self.assertIs(subprocess.DEVNULL, observed["stdout"])
        self.assertIs(subprocess.DEVNULL, observed["stderr"])
        self.assertIs(broker._apply_child_resource_limits, observed["preexec_fn"])

    def test_delayed_kill_must_observe_exit_before_terminal_hold(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        observed: dict[str, _DelayedKillProcess] = {}

        def launch(_command, **kwargs):
            process = _DelayedKillProcess(kwargs["pass_fds"][0], never_exit=False)
            observed["process"] = process
            return process

        with patch.object(broker, "BROKER_WALL_SECONDS", 0):
            result = _execute_brokered_readiness_mechanics(
                self.h.store.connection,
                configured=endpoint,
                profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
                target_kind="message",
                target_key=str(self.h.message_id),
                systemd_evidence=systemd_evidence(
                    "development", "message", str(self.h.message_id)
                ),
                target_precondition=lambda _connection: None,
                popen=launch,
                runtime=self.h.runtime,
                heartbeat_seconds=30,
            )
        self.assertEqual(("HOLD", "HOLD", "HOLD"), (
            result["phase"], result["state"], result["broker_state"]
        ))
        self.assertEqual((1, 1), (
            observed["process"].terminate_calls, observed["process"].kill_calls
        ))

    def test_stubborn_child_preserves_active_truth_until_recovery_proves_exit(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        observed: dict[str, _DelayedKillProcess] = {}

        def launch(_command, **kwargs):
            process = _DelayedKillProcess(kwargs["pass_fds"][0], never_exit=True)
            observed["process"] = process
            return process

        with patch.object(broker, "BROKER_WALL_SECONDS", 0):
            result = _execute_brokered_readiness_mechanics(
                self.h.store.connection,
                configured=endpoint,
                profile_path=ROOT / "references" / "twinfinity-development-v5.config.toml",
                target_kind="message",
                target_key=str(self.h.message_id),
                systemd_evidence=systemd_evidence(
                    "development", "message", str(self.h.message_id)
                ),
                target_precondition=lambda _connection: None,
                popen=launch,
                runtime=self.h.runtime,
                heartbeat_seconds=30,
                evidence_reader=lambda _unit: systemd_evidence(
                    "development", "message", str(self.h.message_id)
                ),
            )
        self.assertEqual(
            (
                "RECOVERY_REQUIRED",
                "RUNNING",
                "RUNNING",
                "CLAIMED",
                "RUNNING",
            ),
            (
                result["phase"],
                result["state"],
                result["broker_state"],
                result["message_state"],
                result["readiness_state"],
            ),
        )
        self.assertEqual("BROKER_CHILD_TERMINATION_UNCONFIRMED", result["error"])
        self.assertEqual((1, 1), (
            observed["process"].terminate_calls, observed["process"].kill_calls
        ))

    def test_claim_attach_is_atomic_and_replayable(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, _spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        self.h.store.connection.execute(
            """
            CREATE TRIGGER synthetic_attach_abort
            BEFORE UPDATE OF state ON role_executor_broker_runs
            WHEN NEW.state='RUNNING'
            BEGIN SELECT RAISE(ABORT, 'synthetic attach abort'); END
            """
        )
        with self.assertRaises(sqlite3.IntegrityError):
            claim_attach_and_start(
                self.h.store.connection,
                attempt_id=attempt_id,
                token=token,
                process_id=9001,
                now=NOW,
            )
        self.assertEqual(
            ("PREPARED", None, "LAUNCHING", "LAUNCHING"),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?",
                    (self.h.message_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT attempt_id FROM portfolio_readiness_current"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM executor_attempts WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM role_executor_broker_runs WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()[0],
            ),
        )
        self.h.store.connection.execute("DROP TRIGGER synthetic_attach_abort")
        started = claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        self.assertEqual("RUNNING", started["state"])

    def test_terminal_staging_is_atomic_then_crash_replays_without_token(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        receipt = self.h.receipt(attempt_id)
        spool.receipt_path.write_text(canonical_json(receipt), encoding="utf-8")
        parsed, receipt_json, observation = read_receipt_file(
            spool.receipt_path, observed_at=NOW
        )
        self.h.store.connection.execute(
            """
            CREATE TRIGGER synthetic_terminal_abort
            BEFORE UPDATE OF state ON role_executor_broker_runs
            WHEN NEW.state='COMPLETE'
            BEGIN SELECT RAISE(ABORT, 'synthetic terminal abort'); END
            """
        )
        with self.assertRaises(sqlite3.IntegrityError):
            complete_broker_receipt(
                self.h.store.connection,
                attempt_id=attempt_id,
                receipt=parsed,
                receipt_json=receipt_json,
                observation=observation,
                now=NOW,
                evaluator_inactivity=process_exit(),
            )
        self.assertEqual(
            ("CLAIMED", "RUNNING", "RUNNING", 0),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?",
                    (self.h.message_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM executor_attempts WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM role_executor_broker_runs WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_receipt_pickups"
                ).fetchone()[0],
            ),
        )
        self.h.store.connection.execute("DROP TRIGGER synthetic_terminal_abort")
        replayed = replay_broker_receipt(
            self.h.store.connection,
            attempt_id=attempt_id,
            runtime=self.h.runtime,
            now=NOW,
            evaluator_inactivity=process_exit(),
        )
        self.assertEqual(("COMPLETE", "STAGED"), (
            replayed["state"], replayed["pickup_state"]
        ))
        staged = self.h.store.connection.execute(
            "SELECT * FROM role_executor_broker_receipt_pickups"
        ).fetchone()
        self.assertEqual(canonical_json(receipt), staged["receipt_json"])
        self.assertEqual(
            hashlib.sha256(canonical_json(receipt).encode()).hexdigest(),
            staged["receipt_sha256"],
        )
        # The host file is a derived archive after commit and cannot change truth.
        spool.receipt_path.write_text("{}", encoding="utf-8")
        repeated = replay_broker_receipt(
            self.h.store.connection,
            attempt_id=attempt_id,
            runtime=self.h.runtime,
            now=NOW,
        )
        self.assertEqual(staged["receipt_sha256"], repeated["receipt_sha256"])
        consumed = consume_broker_pickup(
            self.h.store.connection, attempt_id=attempt_id, now=NOW
        )
        repeated_consumption = consume_broker_pickup(
            self.h.store.connection, attempt_id=attempt_id, now=NOW
        )
        self.assertEqual(consumed, repeated_consumption)
        self.assertEqual("READY_ELIGIBLE", consumed["readiness_state"])
        self.assertEqual(
            canonical_json(receipt),
            self.h.store.connection.execute(
                "SELECT receipt_json FROM portfolio_readiness_receipts"
            ).fetchone()[0],
        )

    def test_terminal_staging_requires_positive_evaluator_inactivity(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        receipt = self.h.receipt(attempt_id)
        spool.receipt_path.write_text(canonical_json(receipt), encoding="utf-8")
        parsed, receipt_json, observation = read_receipt_file(
            spool.receipt_path, observed_at=NOW
        )
        with self.assertRaisesRegex(
            BrokerError, "BROKER_EVALUATOR_INACTIVITY_REQUIRED"
        ):
            complete_broker_receipt(
                self.h.store.connection,
                attempt_id=attempt_id,
                receipt=parsed,
                receipt_json=receipt_json,
                observation=observation,
                now=NOW,
            )
        self.assertEqual(
            ("RUNNING", "RUNNING", "CLAIMED", "RUNNING"),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM executor_attempts WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM role_executor_broker_runs WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?",
                    (self.h.message_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM portfolio_readiness_current"
                ).fetchone()[0],
            ),
        )

    def test_generic_recovery_skips_broker_and_broker_recovers_preparing(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]
        reserved, _token = reserve_attempt(
            self.h.store.connection,
            role="development",
            endpoint_id=endpoint.endpoint_id,
            target_kind="message",
            target_key=str(self.h.message_id),
            now=NOW,
            precondition=lambda _connection: None,
        )
        prepare_broker_run(
            self.h.store.connection,
            configured=endpoint,
            attempt_id=str(reserved["attempt_id"]),
            profile_path=ROOT
            / "references"
            / "twinfinity-development-v5.config.toml",
            now=NOW,
        )
        self.assertEqual(
            [],
            recover_reserved_attempts(
                self.h.store.connection,
                before="2026-08-25T05:01:00Z",
                now="2026-08-25T05:02:00Z",
            ),
        )
        recovered = recover_stale_broker_runs(
            self.h.store.connection,
            before="2026-08-25T05:01:00Z",
            now="2026-08-25T05:02:00Z",
            runtime=self.h.runtime,
        )
        self.assertEqual("RECOVERED", recovered[0]["phase"])
        self.assertEqual(
            ("LAUNCH_FAILED", "HOLD", "PREPARED", None),
            (
                recovered[0]["state"],
                recovered[0]["broker_state"],
                recovered[0]["message_state"],
                recovered[0]["readiness_attempt_id"],
            ),
        )

    def test_supervisor_consumes_a_crash_left_immutable_pickup(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        receipt = self.h.receipt(attempt_id)
        spool.receipt_path.write_text(canonical_json(receipt), encoding="utf-8")
        replay_broker_receipt(
            self.h.store.connection,
            attempt_id=attempt_id,
            runtime=self.h.runtime,
            now=NOW,
            evaluator_inactivity=process_exit(),
        )
        supervisor = CoordinationSupervisor(
            self.h.store,
            launcher=lambda _identity, _message_id: 1,
            terminal_watch_launcher=lambda _identity, _watch_key: 1,
            process_checker=lambda _identity, _kind, _key: True,
        )
        result = supervisor.run_once("2026-08-25T05:00:30Z")
        self.assertEqual(1, len(result["broker_pickups"]))
        self.assertEqual("READY_ELIGIBLE", result["broker_pickups"][0]["readiness_state"])
        self.assertEqual(
            ("READY_ELIGIBLE", 1),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM portfolio_readiness_current"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
                ).fetchone()[0],
            ),
        )

    def test_poison_pickup_is_terminal_then_later_good_pickup_and_wake_continue(self) -> None:
        self.h.seed(issue_number=88)
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        poison_attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=poison_attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        spool.receipt_path.write_text(
            canonical_json(self.h.receipt(poison_attempt_id)), encoding="utf-8"
        )
        replay_broker_receipt(
            self.h.store.connection,
            attempt_id=poison_attempt_id,
            runtime=self.h.runtime,
            now=NOW,
            evaluator_inactivity=process_exit(),
        )
        with self.h.store.transaction():
            self.h.store.connection.execute(
                """
                UPDATE portfolio_graph_current
                SET health='STALE', last_error='synthetic poison drift'
                WHERE repository=?
                """,
                (REPOSITORY,),
            )
        launches: list[tuple[str, int]] = []
        supervisor = CoordinationSupervisor(
            self.h.store,
            launcher=lambda identity, message_id: (
                launches.append((identity, message_id)) or 8000 + len(launches)
            ),
            terminal_watch_launcher=lambda _identity, _watch_key: 1,
            process_checker=lambda _identity, _kind, _key: False,
        )
        first = supervisor.run_once("2026-08-25T05:00:30Z")
        self.assertEqual(
            (1, "STALE", "STALE", 1, []),
            (
                len(first["broker_pickups"]),
                first["broker_pickups"][0]["disposition"],
                self.h.store.connection.execute(
                    """
                    SELECT state FROM portfolio_readiness_current
                    WHERE repository=? AND issue_number=88
                    """,
                    (REPOSITORY,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
                ).fetchone()[0],
                launches,
            ),
        )

        self.h.seed(issue_number=89)
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        good_attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=good_attempt_id,
            token=token,
            process_id=9002,
            now="2026-08-25T05:00:31Z",
        )
        spool.receipt_path.write_text(
            canonical_json(self.h.receipt(good_attempt_id)), encoding="utf-8"
        )
        replay_broker_receipt(
            self.h.store.connection,
            attempt_id=good_attempt_id,
            runtime=self.h.runtime,
            now="2026-08-25T05:00:31Z",
            evaluator_inactivity=process_exit(9002),
        )
        second = supervisor.run_once("2026-08-25T05:00:32Z")
        self.assertEqual(1, len(second["broker_pickups"]))
        self.assertEqual(
            (good_attempt_id, "READY_ELIGIBLE"),
            (
                second["broker_pickups"][0]["attempt_id"],
                second["broker_pickups"][0]["readiness_state"],
            ),
        )
        self.assertEqual(2, self.h.store.connection.execute(
            "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
        ).fetchone()[0])
        self.assertTrue(second["launched"])
        self.assertTrue(any(identity == self.h.config.roles["planner"].endpoint_id for identity, _ in launches))

    def test_endpoint_drift_pickup_is_durably_retired_as_stale(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        spool.receipt_path.write_text(
            canonical_json(self.h.receipt(attempt_id)), encoding="utf-8"
        )
        replay_broker_receipt(
            self.h.store.connection,
            attempt_id=attempt_id,
            runtime=self.h.runtime,
            now=NOW,
            evaluator_inactivity=process_exit(),
        )
        with self.h.store.transaction():
            self.h.store.connection.execute(
                """
                UPDATE executor_role_endpoint_current
                SET endpoint_id='role.development.v4', pointer_version=pointer_version+1,
                    updated_at=? WHERE role='development'
                """,
                (NOW,),
            )
        outcome = consume_broker_pickup(
            self.h.store.connection, attempt_id=attempt_id, now=NOW
        )
        self.assertEqual(
            ("STALE", "STALE", "READINESS_BINDING_DRIFT:ENDPOINT_DRIFT"),
            (
                outcome["disposition"],
                outcome["readiness_state"],
                outcome["error"],
            ),
        )
        self.assertEqual(
            1,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
            ).fetchone()[0],
        )

    def test_pickup_consumption_crash_replays_without_duplicate_planner_notice(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        spool.receipt_path.write_text(
            canonical_json(self.h.receipt(attempt_id)), encoding="utf-8"
        )
        replay_broker_receipt(
            self.h.store.connection,
            attempt_id=attempt_id,
            runtime=self.h.runtime,
            now=NOW,
            evaluator_inactivity=process_exit(),
        )
        self.h.store.connection.execute(
            """
            CREATE TRIGGER synthetic_consumption_abort
            BEFORE INSERT ON role_executor_broker_pickup_consumptions
            BEGIN SELECT RAISE(ABORT, 'synthetic consumption abort'); END
            """
        )
        with self.assertRaises(sqlite3.IntegrityError):
            consume_broker_pickup(
                self.h.store.connection, attempt_id=attempt_id, now=NOW
            )
        self.assertEqual(
            ("READY_ELIGIBLE", 0, 1),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM portfolio_readiness_current"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    """
                    SELECT COUNT(*) FROM coordination_messages
                    WHERE idempotency_key LIKE 'kanban-readiness-planner:%'
                    """
                ).fetchone()[0],
            ),
        )
        self.h.store.connection.execute("DROP TRIGGER synthetic_consumption_abort")
        replayed = consume_broker_pickup(
            self.h.store.connection, attempt_id=attempt_id, now=NOW
        )
        self.assertEqual("READY_ELIGIBLE", replayed["readiness_state"])
        self.assertEqual(
            (1, 1),
            (
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    """
                    SELECT COUNT(*) FROM coordination_messages
                    WHERE idempotency_key LIKE 'kanban-readiness-planner:%'
                    """
                ).fetchone()[0],
            ),
        )

    def test_stale_running_recovery_replays_once_across_terminal_race(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        spool.receipt_path.write_text(
            canonical_json(self.h.receipt(attempt_id)), encoding="utf-8"
        )
        raced = False

        def inactive(unit: str) -> SystemdUnitEvidence:
            nonlocal raced
            if not raced:
                raced = True
                replay_broker_receipt(
                    self.h.store.connection,
                    attempt_id=attempt_id,
                    runtime=self.h.runtime,
                    now="2026-08-25T05:02:00Z",
                    evaluator_inactivity=process_exit(),
                )
                consume_broker_pickup(
                    self.h.store.connection,
                    attempt_id=attempt_id,
                    now="2026-08-25T05:02:00Z",
                )
            active = systemd_evidence(
                "development", "message", str(self.h.message_id)
            )
            self.assertEqual(active.unit, unit)
            return SystemdUnitEvidence(
                unit=active.unit,
                load_state="loaded",
                active_state="inactive",
                sub_state="dead",
                invocation_id=active.invocation_id,
                control_group=active.control_group,
                result="success",
                memory_max=active.memory_max,
                tasks_max=active.tasks_max,
                runtime_max_usec=active.runtime_max_usec,
                cpu_quota_per_sec_usec=active.cpu_quota_per_sec_usec,
            )

        recovered = recover_stale_broker_runs(
            self.h.store.connection,
            before="2026-08-25T05:01:00Z",
            now="2026-08-25T05:02:00Z",
            runtime=self.h.runtime,
            evidence_reader=inactive,
        )
        self.assertEqual(1, len(recovered))
        self.assertEqual(("RECOVERED", "COMPLETE", "COMPLETE", "READY_ELIGIBLE"), (
            recovered[0]["phase"],
            recovered[0]["state"],
            recovered[0]["broker_state"],
            recovered[0]["readiness_state"],
        ))
        self.assertEqual(
            (1, 1),
            (
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_receipt_pickups"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_pickup_consumptions"
                ).fetchone()[0],
            ),
        )

    def test_binding_drift_never_stages_or_completes(self) -> None:
        self.h.seed()
        _endpoint, reserved, token, spool = self.h.reserve_and_launch()
        attempt_id = str(reserved["attempt_id"])
        claim_attach_and_start(
            self.h.store.connection,
            attempt_id=attempt_id,
            token=token,
            process_id=9001,
            now=NOW,
        )
        spool.receipt_path.write_text(
            canonical_json(self.h.receipt(attempt_id)), encoding="utf-8"
        )
        self.h.store.connection.execute(
            """
            UPDATE portfolio_graph_current
            SET health='STALE', last_error='synthetic drift'
            WHERE repository=?
            """,
            (REPOSITORY,),
        )
        with self.assertRaisesRegex(BrokerError, "BROKER_READINESS_BINDING_DRIFT"):
            replay_broker_receipt(
                self.h.store.connection,
                attempt_id=attempt_id,
                runtime=self.h.runtime,
                now=NOW,
                evaluator_inactivity=process_exit(),
            )
        hold_broker_run(
            self.h.store.connection,
            attempt_id=attempt_id,
            error="BROKER_READINESS_BINDING_DRIFT:GRAPH_STALE",
            now=NOW,
            exit_code=None,
            evaluator_inactivity=process_exit(),
        )
        self.assertEqual(
            ("HOLD", "HOLD", 0),
            (
                self.h.store.connection.execute(
                    "SELECT state FROM executor_attempts WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT state FROM portfolio_readiness_current"
                ).fetchone()[0],
                self.h.store.connection.execute(
                    "SELECT COUNT(*) FROM role_executor_broker_receipt_pickups"
                ).fetchone()[0],
            ),
        )


if __name__ == "__main__":
    unittest.main()
