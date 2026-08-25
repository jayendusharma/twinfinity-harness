from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import CoordinationStore, canonical_json  # noqa: E402
from executor_registry import (  # noqa: E402
    RegistryError,
    SystemdUnitEvidence,
    ensure_executor_registry_schema,
    load_registry_config,
    reserve_attempt,
    stable_systemd_unit,
)
from kanban_pull_buffer import ensure_pull_buffer_schema  # noqa: E402
from kanban_readiness import PLAN_SCHEMA, RECEIPT_SCHEMA, dispatch, register  # noqa: E402
from portfolio_graph import replace_graph  # noqa: E402
from reconcile_routing_artifacts import _verify_or_insert_endpoint  # noqa: E402
from role_executor_broker import (  # noqa: E402
    BROKER_PROTOCOL,
    CONTRACT_SCHEMA,
    INPUT_SCHEMA,
    RESULT_MAX_BYTES,
    RESULT_PATH,
    BrokerError,
    BrokerRuntimePaths,
    claim_attach_and_start,
    complete_broker_receipt,
    hold_broker_run,
    mark_broker_launching,
    prepare_broker_run,
    prepare_spool,
    read_receipt_file,
    replay_broker_receipt,
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
    )


class _ReceiptProcess:
    pid = 43210

    def __init__(self, gate_fd: int, on_poll):
        self._gate_fd = os.dup(gate_fd)
        self._on_poll = on_poll
        self._finished = False
        self.terminated = False

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
        return -15

    def kill(self):
        self.terminate()


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
        for name in ("bwrap", "setpriv", "codex", "auth.json"):
            path = runtime / name
            path.write_bytes(b"test-runtime\n")
            path.chmod(0o700 if name != "auth.json" else 0o600)
            files[name] = path
        development = runtime / "development-skill"
        sre = runtime / "sre-skill"
        development.mkdir()
        sre.mkdir()
        (development / "SKILL.md").write_text("development\n", encoding="utf-8")
        (sre / "SKILL.md").write_text("sre\n", encoding="utf-8")
        return BrokerRuntimePaths(
            spool_root=self.root / "spool",
            bwrap_path=files["bwrap"],
            setpriv_path=files["setpriv"],
            codex_binary_path=files["codex"],
            codex_auth_path=files["auth.json"],
            development_skill_root=development,
            sre_skill_root=sre,
        )

    def seed(self, *, role: str = "development") -> int:
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=88,
            payload={
                "_projection_version": 3,
                "number": 88,
                "title": "Brokered readiness",
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
            issue_number=88,
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
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Sprint", "rank": 1}],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": "issue:88",
                        "issue_number": 88,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Independent outcome",
                        "lane_key": "lane-88",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": 1,
                        "estimate_units": 1,
                        "development_units": 1 if role == "development" else 0,
                        "shared_units": 0,
                        "sre_units": 1 if role == "sre" else 0,
                        "source_payload_sha256": snapshot.payload_sha256,
                        "ready_at": NOW,
                    }
                ],
                "relations": [],
            },
            now=NOW,
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
        self.candidate_sha256 = hashlib.sha256(b"candidate:88").hexdigest()
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
                ) VALUES (?, 88, 1, ?, ?, ?, 1, ?, 'lane-88',
                          'PREPARED_NOT_READY', 'END_TO_END', ?, 0, ?,
                          'Close readiness phase', 'plans/issue-88.json', ?,
                          ?, ?)
                """,
                (
                    REPOSITORY,
                    int(self.item["version"]),
                    snapshot.payload_sha256,
                    MAIN,
                    policy_version,
                    1 if role == "development" else 0,
                    1 if role == "sre" else 0,
                    "c" * 64,
                    self.candidate_sha256,
                    NOW,
                ),
            )
            self.store.connection.execute(
                """
                INSERT INTO portfolio_pull_buffer_current(
                    repository, issue_number, candidate_id, updated_at
                ) VALUES (?, 88, ?, ?)
                """,
                (REPOSITORY, int(cursor.lastrowid), NOW),
            )
        plan = {
            "schema": PLAN_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": 88,
            "generation": 1,
            "item_version": int(self.item["version"]),
            "source_payload_sha256": snapshot.payload_sha256,
            "accepted_main_sha": MAIN,
            "graph_version": 1,
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
        self.message_id = int(result["dispatched"][0]["message_id"])
        return self.message_id

    def receipt(self, attempt_id: str, *, verdict: str = "PASS") -> dict:
        return {
            "schema": RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": 88,
            "readiness_plan_sha256": self.store.connection.execute(
                """
                SELECT campaign.plan_sha256
                FROM portfolio_readiness_current current
                JOIN portfolio_readiness_campaigns campaign
                  ON campaign.id=current.campaign_id
                WHERE current.repository=? AND current.issue_number=88
                """,
                (REPOSITORY,),
            ).fetchone()[0],
            "verdict": verdict,
            "worker_role": self.store.connection.execute(
                """
                SELECT campaign.worker_role
                FROM portfolio_readiness_current current
                JOIN portfolio_readiness_campaigns campaign
                  ON campaign.id=current.campaign_id
                WHERE current.repository=? AND current.issue_number=88
                """,
                (REPOSITORY,),
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
                "approval_proposal_sha256": None,
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
            now=NOW,
        )
        spool = prepare_spool(self.runtime, run)
        mark_broker_launching(
            self.store.connection,
            attempt_id=str(reserved["attempt_id"]),
            token=token,
            evidence=systemd_evidence(role, "message", str(self.message_id)),
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
        result = execute_role(
            self.h.store.connection,
            config_path=CONFIG,
            role="development",
            endpoint_id=endpoint.endpoint_id,
            target_kind="message",
            target_key=str(self.h.message_id),
            prompt="This caller prompt must not become authority.",
            systemd_invocation_id="b" * 32,
            systemd_evidence=systemd_evidence(
                "development", "message", str(self.h.message_id)
            ),
            popen=launch,
            broker_runtime=self.h.runtime,
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
        self.assertIn(
            "/home/ubuntu/.codex/twinfinity-coordination", joined
        )
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
            "RUNNING",
            self.h.store.connection.execute(
                """
                SELECT state FROM portfolio_readiness_current
                WHERE repository=? AND issue_number=88
                """,
                (REPOSITORY,),
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.h.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_readiness_receipts"
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
        result = execute_role(
            self.h.store.connection,
            config_path=CONFIG,
            role="sre",
            endpoint_id=endpoint.endpoint_id,
            target_kind="message",
            target_key=str(self.h.message_id),
            prompt="ignored",
            systemd_invocation_id="b" * 32,
            systemd_evidence=systemd_evidence(
                "sre", "message", str(self.h.message_id)
            ),
            popen=launch,
            broker_runtime=self.h.runtime,
        )
        self.assertEqual(("PASS", "COMPLETE"), (result["phase"], result["state"]))
        command = observed["command"]
        self.assertIn("twinfinity-sre-v5", command)
        self.assertIn(str(self.h.runtime.sre_skill_root), command)
        run = self.h.store.connection.execute(
            "SELECT role, endpoint_id, state FROM role_executor_broker_runs"
        ).fetchone()
        self.assertEqual(("sre", endpoint.endpoint_id, "COMPLETE"), tuple(run))

    def test_launch_failure_leaves_message_prepared_and_attempt_launch_failed(self) -> None:
        self.h.seed()
        endpoint = self.h.config.roles["development"]

        def fail(_command, **_kwargs):
            raise OSError("synthetic")

        result = execute_role(
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
            popen=fail,
            broker_runtime=self.h.runtime,
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

        result = execute_role(
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
            popen=launch,
            broker_runtime=self.h.runtime,
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
            )
        hold_broker_run(
            self.h.store.connection,
            attempt_id=attempt_id,
            error="BROKER_READINESS_BINDING_DRIFT:GRAPH_STALE",
            now=NOW,
            exit_code=None,
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
