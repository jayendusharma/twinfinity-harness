from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from approval_ledger import ensure_schema as ensure_approval_schema  # noqa: E402
from coordination_store import (  # noqa: E402
    CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA,
    CLAIMED_NO_DELIVERY_PRESERVATION_SCHEMA,
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
)
from executor_registry import (  # noqa: E402
    AttemptLineage,
    SystemdUnitEvidence,
    attempt_lineage_for_target,
    load_registry_config,
    registry_config_scope,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from portfolio_graph import replace_graph  # noqa: E402
import kanban_pull_buffer as pull_buffer  # noqa: E402
import coordination_store as coordination  # noqa: E402
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from kanban_pull_buffer import _park_issue_material_projection  # noqa: E402
from owner_safe_sqlite import open_owner_database_readonly  # noqa: E402
from run_role_executor import (  # noqa: E402
    PARK_CAPABILITY_SCHEMA,
    PARK_CAPABILITY_SOCKET_ENV,
    PARK_CODEX_SHA256,
    PARK_CODEX_VERSION,
    PARK_POST_CONSUMPTION_ADOPTION_SECONDS,
    PARK_PRE_CONSUMPTION_WAIT_SECONDS,
    ParkCapabilityBroker,
    _owned_process_group,
    _process_argv,
    _process_control_group,
    _process_cwd,
    _process_executable,
    _process_group_exists,
    _process_identity,
    _park_controller_command,
    _prepare_park_prompt_release,
    _terminate_untracked_child,
    consume_park_controller_capability,
    execute_role,
    adopt_park_controller_capability,
)
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from tests.canonical_ready_fixture import finalize_canonical_ready_item  # noqa: E402


REPOSITORY = "twinfinityai/twinfinityapp"
ISSUE = 272
GENERATION = 0
DEVELOPMENT_ENDPOINT = "role.development.v6"
PLANNER_ENDPOINT = "role.planner.v3"
OWNER = "jayendusharma"
MAIN_SHA = "b" * 40
ACTUAL_CODEX_TEST_ENV = "TWINFINITY_RUN_ACTUAL_CODEX_PARK_TEST"
ACTUAL_CODEX_IN_NAMESPACE_ENV = "TWINFINITY_ACTUAL_CODEX_PARK_NAMESPACE"
ACTUAL_CODEX_FIXTURE_ROOT_ENV = "TWINFINITY_ACTUAL_CODEX_PARK_FIXTURE_ROOT"
ACTUAL_CODEX_GH_LOG_ENV = "TWINFINITY_ACTUAL_CODEX_PARK_GH_LOG"
FIXTURE_HOOK_INTERPRETER = Path("/usr/bin/python3")
FIXTURE_HOOK_EXECUTABLE = FIXTURE_HOOK_INTERPRETER.resolve(strict=True)


class ClaimedNoDeliveryParkTests(unittest.TestCase):
    """Exercise the exact live #272 shape on a disposable coordination store."""

    def setUp(self) -> None:
        external_root = os.environ.get(ACTUAL_CODEX_FIXTURE_ROOT_ENV)
        self.temp = tempfile.TemporaryDirectory(dir=external_root)
        root = Path(external_root) if external_root else Path(self.temp.name)
        coordination = root / "coordination"
        coordination.mkdir(mode=0o700, exist_ok=bool(external_root))
        database_name = (
            "ack-transactions.sqlite3"
            if os.environ.get(ACTUAL_CODEX_IN_NAMESPACE_ENV) == "1"
            else "state.sqlite3"
        )
        self.store = CoordinationStore(coordination / database_name)
        installed = root / "installed"
        installed.mkdir(exist_ok=bool(external_root))
        for profile in (ROOT / "references").glob("*-v*.config.toml"):
            shutil.copy2(profile, installed / profile.name)
        config = load_registry_config(
            ROOT / "references" / "twinfinity-executor-registry.toml",
            codex_home=installed,
            profile_template_root=ROOT / "references",
        )
        self.registry_scope = registry_config_scope(config)
        self.registry_scope.__enter__()
        self.addCleanup(self.registry_scope.__exit__, None, None, None)
        aliases, alias_sha = load_legacy_alias_fixture(
            ROOT / "references" / "twinfinity-legacy-role-aliases.json"
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
            operation_key="claimed-no-delivery-park-fixture",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-26T20:00:00Z",
        )
        ensure_approval_schema(self.store.connection)

        self.bound_payload = {
            "number": ISSUE,
            "title": "Bound scope",
            "body": "Exact body",
            "state": "open",
            "labels": ["bug"],
            "milestone": None,
            "assignees": [],
            "updated_at": "2026-08-26T20:00:01Z",
            "_projection_version": 1,
        }
        bound = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload=self.bound_payload,
            source_updated_at=self.bound_payload["updated_at"],
            fetched_at="2026-08-26T20:00:02Z",
        )
        self.bound_sha = bound.payload_sha256
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=ISSUE,
            status="PREPARED",
            allocation_class="NONE",
            generation=GENERATION,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=self.bound_sha,
            expected_version=0,
            now="2026-08-26T20:00:03Z",
        )
        self._replace_graph(self.bound_sha, expected_version=0, now="2026-08-26T20:00:03Z")
        ready_arguments = {
            "database": self.store.path,
            "artifact_root": self.store.path.parent,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "source_payload_sha256": self.bound_sha,
            "accepted_main_sha": MAIN_SHA,
            "worker_role": "development",
            "worker_endpoint_id": DEVELOPMENT_ENDPOINT,
            "now": "2026-08-26T20:00:04Z",
            "suffix": "claimed-no-delivery",
        }
        ready = finalize_canonical_ready_item(self.store, **ready_arguments)
        transaction = ready["admission_transaction"]
        self.delivery_branch = transaction["message"]["payload"]["branch"]
        self.delivery_worktree = transaction["message"]["payload"]["worktree_path"]
        self.lease = transaction["message"]["payload"]["lease_manifest_sha256"]
        _active, self.admission_message_id = self.store.activate_admission(
            item=transaction["item"],
            message=transaction["message"],
            artifacts=transaction.get("artifacts"),
            now="2026-08-26T20:00:05Z",
        )
        self.watch_key = (
            f"terminal:{REPOSITORY}:issue:{ISSUE}:generation:{GENERATION}"
        )
        claim_attempt, claim_token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(self.admission_message_id),
            start="2026-08-26T20:00:05Z",
            process_id=272,
            complete=False,
        )
        self.store.claim_message(
            self.admission_message_id,
            DEVELOPMENT_ENDPOINT,
            "2026-08-26T20:00:07Z",
            attempt_id=claim_attempt["attempt_id"],
            executor_token=claim_token,
        )
        claim_running = self.store.connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?",
            (claim_attempt["attempt_id"],),
        ).fetchone()
        transition_attempt(
            self.store.connection,
            attempt_id=claim_attempt["attempt_id"],
            token=claim_token,
            expected_version=claim_running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-26T20:00:08Z",
        )
        self.claim_attempt_id = claim_attempt["attempt_id"]
        self.store.connection.commit()

        control_body = {"kind": "OWNER_CONTROL_COMMENT", "body": "receipt"}
        cursor = self.store.connection.execute(
            "INSERT INTO github_outbox(idempotency_key,repository,object_kind,"
            "object_number,operation,expected_source_sha256,payload_sha256,"
            "payload_json,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "issue-272-owner-control-comment",
                REPOSITORY,
                "issue",
                ISSUE,
                "comment",
                self.bound_sha,
                digest_json(control_body),
                canonical_json(control_body),
                "PREPARED",
                "2026-08-26T20:00:09Z",
                "2026-08-26T20:00:09Z",
            ),
        )
        self.control_outbox_id = int(cursor.lastrowid)
        self.store.connection.commit()
        self.store.reserve_outbox(
            self.control_outbox_id, "2026-08-26T20:00:10Z"
        )
        self.store.complete_outbox(
            self.control_outbox_id,
            "comment:5430908495",
            "2026-08-26T20:00:11Z",
        )
        self._link_control_outbox_to_approval_decision()

        current_at = "2026-08-26T20:00:12Z"
        current_payload = {
            **self.bound_payload,
            "updated_at": current_at,
            "_projection_version": 2,
            "_projection_dashboard": "changed",
        }
        current = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            payload=current_payload,
            source_updated_at=current_at,
            fetched_at="2026-08-26T20:00:13Z",
        )
        self.current_sha = current.payload_sha256
        message_hold_at = "2026-08-26T20:00:14Z"
        watch_hold_at = "2026-08-26T20:00:15Z"
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='HOLD',updated_at=?,"
            "last_error='SOURCE_SNAPSHOT_DRIFT' WHERE id=?",
            (message_hold_at, self.admission_message_id),
        )
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET state='HOLD',process_id=NULL,"
            "updated_at=?,last_error='TERMINAL_WATCH_ADMISSION_BINDING_DRIFT' "
            "WHERE watch_key=?",
            (watch_hold_at, self.watch_key),
        )
        self.store.connection.commit()
        request = {
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "message_id": self.admission_message_id,
            "expected_message_updated_at": message_hold_at,
            "watch_key": self.watch_key,
            "expected_watch_updated_at": watch_hold_at,
            "outbox_id": self.control_outbox_id,
            "timeline": [
                {
                    "event": "commented",
                    "id": 5430908495,
                    "created_at": current_at,
                    "actor": {"login": OWNER},
                }
            ],
            "expected_owner_login": OWNER,
        }
        preview = self.store.preview_source_equivalent_admission_rearm(**request)
        self.equivalence = self.store.apply_source_equivalent_admission_rearm(
            **request,
            expected_preview_sha256=preview["preview_sha256"],
            now="2026-08-26T20:00:16Z",
        )
        self._replace_graph(
            self.current_sha,
            expected_version=1,
            now="2026-08-26T20:00:17Z",
        )

        preservation_attempt, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            start="2026-08-26T20:00:18Z",
            process_id=273,
            complete=True,
        )
        self.preservation_attempt_id = preservation_attempt["attempt_id"]
        self.cleanup_receipt_sha256 = digest_json(
            {
                "schema": "twinfinity-accountable-cleanup/v1",
                "branch": transaction["message"]["payload"]["branch"],
                "worktree": transaction["message"]["payload"]["worktree_path"],
                "state": "ABSENT",
            }
        )
        self.artifact = self._register_preservation_artifact(
            dirty_bytes=(
                b"diff --git a/frontend/src/issue-272.ts "
                b"b/frontend/src/issue-272.ts\n+preserved\n"
            )
        )
        self.repository_observation_sha256 = digest_json(
            {
                "schema": "twinfinity-claimed-no-delivery-repository-observation/v1",
                "repository": REPOSITORY,
                "issue_number": ISSUE,
                "generation": GENERATION,
                "state": "ABSENT_AFTER_ACCOUNTABLE_CLEANUP",
                "cleanup_receipt_sha256": self.cleanup_receipt_sha256,
            }
        )
        self.payload = self._park_payload(self.artifact)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _capability_manifest(self, *, command: str = "/usr/bin/true") -> dict:
        pid = os.getpid()
        _parent, start_time = _process_identity(pid)
        source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        guard = SCRIPTS / "delivery_guard.py"
        return {
            "schema": PARK_CAPABILITY_SCHEMA,
            "attempt_id": "1" * 8 + "-1111-1111-1111-" + "1" * 12,
            "instance_id": "2" * 8 + "-2222-2222-2222-" + "2" * 12,
            "endpoint_id": PLANNER_ENDPOINT,
            "target_kind": "message",
            "target_key": "1",
            "request_payload_sha256": "3" * 64,
            "repository_observation_sha256": "4" * 64,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": GENERATION,
            "lease_manifest_sha256": "5" * 64,
            "source_payload_sha256": "6" * 64,
            "branch": "change/272-fixture",
            "worktree": "/tmp/issue-272-fixture",
            "command": command,
            "controller_argv": _process_argv(pid),
            "controller_cwd": _process_cwd(pid),
            "runner_pid": pid,
            "runner_start_time": start_time,
            "runner_argv": _process_argv(pid),
            "codex_pid": pid,
            "codex_start_time": start_time,
            "codex_argv": _process_argv(pid),
            "codex_cwd": _process_cwd(pid),
            "codex_version": PARK_CODEX_VERSION,
            "codex_binary_sha256": PARK_CODEX_SHA256,
            "codex_home": os.fspath(Path(__file__).parent),
            "child_environment_sha256": "9" * 64,
            "immutable_files": [
                {
                    "kind": kind,
                    "path": os.fspath(
                        guard
                        if kind == "guard"
                        else FIXTURE_HOOK_EXECUTABLE
                        if kind == "python"
                        else Path(__file__)
                    ),
                    "sha256": source_sha256,
                }
                for kind in (
                    "codex",
                    "runner",
                    "controller",
                    "guard",
                    "profile",
                    "requirements",
                    "config",
                    "python",
                )
            ],
            "python_source_closure": [],
            "python_source_closure_sha256": digest_json([]),
            "hook_config_sha256": "7" * 64,
            "runner_control_group": _process_control_group(pid),
            "codex_control_group": _process_control_group(pid),
            "systemd_invocation_id": "8" * 32,
            "systemd_control_group": "/user.slice/fixture.service",
            "expires_monotonic": (
                time.monotonic() + PARK_PRE_CONSUMPTION_WAIT_SECONDS
            ),
            "post_consumption_adoption_seconds": (
                PARK_POST_CONSUMPTION_ADOPTION_SECONDS
            ),
            "one_use": True,
        }

    def _new_capability_broker(
        self,
        *,
        command: str = "/usr/bin/true",
        credential: str = "secret",
        manifest_updates: dict | None = None,
    ):
        patcher = mock.patch.object(
            ParkCapabilityBroker, "_immutable_manifest_matches", return_value=True
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        def fixture_controller_peer_matches(
            candidate: ParkCapabilityBroker,
            peer_pid: int,
            manifest: dict,
        ) -> bool:
            try:
                _parent, peer_start = _process_identity(peer_pid)
                return bool(
                    peer_pid == manifest["runner_pid"]
                    and peer_start == manifest["runner_start_time"]
                    and _process_argv(peer_pid) == manifest["controller_argv"]
                    and _process_cwd(peer_pid) == manifest["controller_cwd"]
                    and _process_control_group(peer_pid)
                    == manifest["codex_control_group"]
                    and candidate._hook_process_identity is not None
                    and (peer_pid, peer_start)
                    != candidate._hook_process_identity
                )
            except Exception:
                return False

        controller_patcher = mock.patch.object(
            ParkCapabilityBroker,
            "_controller_peer_matches",
            new=fixture_controller_peer_matches,
        )
        controller_patcher.start()
        self.addCleanup(controller_patcher.stop)
        broker = ParkCapabilityBroker(self.store.path.parent, credential=credential)
        broker.arm(
            {
                **self._capability_manifest(command=command),
                **(manifest_updates or {}),
            }
        )
        broker.release_prompt(io.BytesIO(), b"fixture prompt\n")
        self.addCleanup(broker.close)
        return broker, {PARK_CAPABILITY_SOCKET_ENV: os.fspath(broker.path)}

    def _assert_controller_payload_denied_before_writable(
        self,
        payload: dict,
        *,
        suffix: str,
        expected_error: str,
        process_id: int,
    ) -> None:
        payload_json = canonical_json(payload)
        request_sha256 = digest_json(payload)
        cursor = self.store.connection.execute(
            "INSERT INTO coordination_messages(idempotency_key,"
            "recipient_session_id,topic,payload_sha256,payload_json,state,"
            "created_at,updated_at) VALUES (?,?,'coordination.notice',?,?,"
            "'PREPARED',?,?)",
            (
                f"issue-272-stale-controller-{suffix}",
                PLANNER_ENDPOINT,
                request_sha256,
                payload_json,
                "2026-08-26T20:00:24Z",
                "2026-08-26T20:00:24Z",
            ),
        )
        message_id = int(cursor.lastrowid)
        self.store.connection.commit()
        attempt, token = self._running_planner_attempt(message_id, process_id)
        try:
            evidence = payload["evidence"]
            command = _park_controller_command()
            broker, environment = self._new_capability_broker(
                command=command,
                credential=token,
                manifest_updates={
                    "attempt_id": attempt["attempt_id"],
                    "instance_id": attempt["instance_id"],
                    "endpoint_id": PLANNER_ENDPOINT,
                    "target_key": str(message_id),
                    "request_payload_sha256": request_sha256,
                    "repository_observation_sha256": (
                        self.repository_observation_sha256
                    ),
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": GENERATION,
                    "lease_manifest_sha256": evidence["lease_manifest_sha256"],
                    "source_payload_sha256": self.bound_sha,
                },
            )
            environment.update(
                {
                    "TWINFINITY_EXECUTOR_ROLE": "planner",
                    "TWINFINITY_ROLE_ENDPOINT": PLANNER_ENDPOINT,
                    "TWINFINITY_EXECUTOR_TARGET_KIND": "message",
                    "TWINFINITY_EXECUTOR_TARGET_KEY": str(message_id),
                    "TWINFINITY_PARK_REQUEST_SHA256": request_sha256,
                    "TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256": (
                        self.repository_observation_sha256
                    ),
                }
            )
            hook = self._run_candidate_guard(
                self._park_hook_event(command=command), environment
            )
            self.assertEqual({}, json.loads(hook.stdout))
            before = self._durable_coordination_snapshot()
            with (
                mock.patch.object(
                    pull_buffer,
                    "acquire_claimed_no_delivery_repository_observation",
                    side_effect=AssertionError("provider observation must not run"),
                ),
                mock.patch.object(
                    pull_buffer,
                    "adopt_park_controller_capability",
                    side_effect=AssertionError("capability adoption must not run"),
                ),
                mock.patch.object(
                    pull_buffer,
                    "CoordinationStore",
                    side_effect=AssertionError(
                        "writable store must not be constructed"
                    ),
                ),
                self.assertRaisesRegex(pull_buffer.PullBufferError, expected_error),
            ):
                pull_buffer.park_claimed_no_delivery_controller(
                    database=self.store.path,
                    message_id=message_id,
                    planner_session_id=PLANNER_ENDPOINT,
                    request_sha256=request_sha256,
                    repository_observation_sha256=(
                        self.repository_observation_sha256
                    ),
                    environ=environment,
                )
            self.assertEqual("CONSUMED", broker.snapshot()["state"])
            self.assertEqual(before, self._durable_coordination_snapshot())
        finally:
            current = self.store.connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (attempt["attempt_id"],),
            ).fetchone()
            if current is not None and current["state"] in {
                "RESERVED",
                "LAUNCHING",
                "RUNNING",
            }:
                transition_attempt(
                    self.store.connection,
                    attempt_id=attempt["attempt_id"],
                    token=token,
                    expected_version=int(current["version"]),
                    new_state="HOLD",
                    last_error=expected_error,
                    now="2026-08-26T20:00:25Z",
                )

    def _park_hook_event(
        self, *, command: str = "/usr/bin/true", tool_name: str = "Bash"
    ) -> bytes:
        return canonical_json(
            {
                "cwd": _process_cwd(os.getpid()),
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.6-sol",
                "permission_mode": "default",
                "session_id": "session-fixture",
                "tool_input": {"command": command},
                "tool_name": tool_name,
                "tool_use_id": "tool-fixture",
                "transcript_path": None,
                "turn_id": "turn-fixture",
            }
        ).encode("utf-8")

    def _run_candidate_guard(self, raw: bytes, environment: dict[str, str]):
        return subprocess.run(
            [os.fspath(FIXTURE_HOOK_INTERPRETER), os.fspath(SCRIPTS / "delivery_guard.py")],
            input=raw,
            capture_output=True,
            env={**os.environ, **environment},
            check=False,
        )

    def test_missing_nested_hook_cannot_consume_capability_or_mutate_sqlite(self) -> None:
        before = list(self.store.connection.iterdump())
        broker, environment = self._new_capability_broker()
        self.assertNotIn("TWINFINITY_EXECUTOR_TOKEN", environment)
        with self.assertRaisesRegex(Exception, "PARK_CAPABILITY_DENIED"):
            consume_park_controller_capability(environ=environment)
        self.assertEqual("FAILED", broker.snapshot()["state"])
        self.assertEqual(before, list(self.store.connection.iterdump()))
        broker.close()

    def test_process_group_cleanup_kills_a_stubborn_descendant(self) -> None:
        leader_code = "\n".join(
            (
                "import signal, subprocess, sys, time",
                "child = subprocess.Popen([",
                "    sys.executable, '-c',",
                "    'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)',",
                "])",
                "print(child.pid, flush=True)",
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))",
                "time.sleep(60)",
            )
        )
        process = subprocess.Popen(
            [sys.executable, "-c", leader_code],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.addCleanup(
            _terminate_untracked_child,
            process,
            process_group_id=process.pid,
        )
        self.assertIsNotNone(process.stdout)
        child_pid = int(process.stdout.readline())
        process_group_id = _owned_process_group(process)
        self.assertEqual(process.pid, process_group_id)
        self.assertTrue(_process_group_exists(process_group_id))

        self.assertTrue(
            _terminate_untracked_child(
                process, process_group_id=process_group_id
            )
        )
        process.stdout.close()
        self.assertFalse(_process_group_exists(process_group_id))
        self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_zero_wal_barrier_excludes_every_other_writer_until_release(self) -> None:
        message_id = self._enqueue_park("wal-barrier")
        attempt, token = self._running_planner_attempt(message_id, os.getpid())
        attempt = dict(
            self.store.connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (attempt["attempt_id"],),
            ).fetchone()
        )
        heartbeat = _prepare_park_prompt_release(
            self.store.connection,
            token=token,
            attempt=attempt,
            process_id=os.getpid(),
            transitioner=transition_attempt,
        )
        self.assertEqual("RUNNING", heartbeat["state"])
        self.assertTrue(self.store.connection.in_transaction)
        wal = Path(os.fspath(self.store.path) + "-wal")
        self.assertTrue(not wal.exists() or wal.stat().st_size == 0)

        contender = sqlite3.connect(self.store.path, timeout=0.05)
        self.addCleanup(contender.close)
        with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
            contender.execute("BEGIN IMMEDIATE")
        self.store.connection.execute("ROLLBACK")
        contender.execute("BEGIN IMMEDIATE")
        contender.execute("ROLLBACK")

    def test_exact_nested_hook_allows_one_controller_consume_and_adopt(self) -> None:
        broker, environment = self._new_capability_broker()
        hook = self._run_candidate_guard(self._park_hook_event(), environment)
        self.assertEqual(0, hook.returncode, hook.stderr.decode())
        self.assertEqual({}, json.loads(hook.stdout))
        nested = next(
            event
            for event in broker.snapshot()["events"]
            if event["kind"] == "NESTED_BASH_PRETOOLUSE"
        )
        self.assertEqual(os.fspath(FIXTURE_HOOK_EXECUTABLE), nested["executable"])
        consumed = consume_park_controller_capability(environ=environment)
        self.assertEqual("secret", consumed["credential"])
        self.assertEqual("CONSUMED", broker.snapshot()["state"])
        self.assertEqual(
            "ADOPTED", adopt_park_controller_capability(environ=environment)["state"]
        )
        self.assertEqual("ADOPTED", broker.snapshot()["state"])
        with self.assertRaisesRegex(Exception, "PARK_CAPABILITY_DENIED"):
            adopt_park_controller_capability(environ=environment)
        replayed = broker.snapshot()
        self.assertEqual("FAILED", replayed["state"])
        self.assertEqual("PARK_CONTROLLER_ADOPTION_FAILED", replayed["error"])

    def test_consumption_starts_bounded_observation_deadline_and_late_adoption_fails(self) -> None:
        broker, environment = self._new_capability_broker()
        armed = broker.snapshot()
        arm_event = next(
            event for event in armed["events"] if event["kind"] == "CAPABILITY_ARMED"
        )
        self.assertEqual("PRE_CONSUMPTION", armed["deadline_phase"])
        self.assertGreater(armed["deadline_monotonic"], arm_event["monotonic"])
        self.assertLessEqual(
            armed["deadline_monotonic"] - arm_event["monotonic"],
            PARK_PRE_CONSUMPTION_WAIT_SECONDS,
        )
        hook = self._run_candidate_guard(self._park_hook_event(), environment)
        self.assertEqual({}, json.loads(hook.stdout))
        consume_park_controller_capability(environ=environment)
        consumed = broker.snapshot()
        consumed_event = next(
            event
            for event in consumed["events"]
            if event["kind"] == "CONTROLLER_CONSUMED"
        )
        observation_budget = (
            pull_buffer.PARK_REPOSITORY_OBSERVATION_PASSES_BEFORE_ADOPTION
            * pull_buffer.PARK_REPOSITORY_OBSERVATION_CALLS_PER_PASS
            * pull_buffer.PARK_REPOSITORY_OBSERVER_CALL_TIMEOUT_SECONDS
        )
        self.assertEqual(150, observation_budget)
        self.assertEqual("POST_CONSUMPTION", consumed["deadline_phase"])
        self.assertAlmostEqual(
            PARK_POST_CONSUMPTION_ADOPTION_SECONDS,
            consumed["deadline_monotonic"] - consumed_event["monotonic"],
        )
        self.assertGreaterEqual(
            PARK_POST_CONSUMPTION_ADOPTION_SECONDS,
            observation_budget
            + pull_buffer.PARK_REPOSITORY_OBSERVATION_ADOPTION_MARGIN_SECONDS,
        )
        with mock.patch(
            "run_role_executor.time.monotonic",
            return_value=consumed_event["monotonic"] + observation_budget,
        ):
            adopted = adopt_park_controller_capability(environ=environment)
        self.assertEqual("ADOPTED", adopted["state"])

        late_broker, late_environment = self._new_capability_broker(
            credential="late-secret"
        )
        late_hook = self._run_candidate_guard(
            self._park_hook_event(), late_environment
        )
        self.assertEqual({}, json.loads(late_hook.stdout))
        consume_park_controller_capability(environ=late_environment)
        late_deadline = late_broker.snapshot()["deadline_monotonic"]
        with mock.patch(
            "run_role_executor.time.monotonic", return_value=late_deadline
        ):
            with self.assertRaisesRegex(Exception, "PARK_CAPABILITY_DENIED"):
                adopt_park_controller_capability(environ=late_environment)
        late = late_broker.snapshot()
        self.assertEqual("FAILED", late["state"])
        self.assertEqual("PARK_CAPABILITY_ADOPTION_TIMEOUT", late["error"])

    def test_controller_adoption_peer_mismatch_fails_closed(self) -> None:
        broker, environment = self._new_capability_broker(
            credential="mismatch-secret"
        )
        hook = self._run_candidate_guard(self._park_hook_event(), environment)
        self.assertEqual({}, json.loads(hook.stdout))
        consume_park_controller_capability(environ=environment)
        source = (
            "from run_role_executor import adopt_park_controller_capability\n"
            "try:\n"
            "    adopt_park_controller_capability(environ=dict(__import__('os').environ))\n"
            "except Exception as exc:\n"
            "    print(str(exc))\n"
        )
        mismatched = subprocess.run(
            [os.fspath(FIXTURE_HOOK_INTERPRETER), "-c", source],
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                **environment,
                "PYTHONPATH": os.fspath(SCRIPTS),
            },
        )
        self.assertEqual(0, mismatched.returncode, mismatched.stderr)
        self.assertIn("PARK_CAPABILITY_DENIED", mismatched.stdout)
        mismatch = broker.snapshot()
        self.assertEqual("FAILED", mismatch["state"])
        self.assertEqual("PARK_CONTROLLER_ADOPTION_FAILED", mismatch["error"])

    def test_controller_consumes_before_readonly_and_adopts_before_writable_open(self) -> None:
        message_id = self._enqueue_park("brokered-controller")
        attempt, token = self._running_planner_attempt(message_id, os.getpid())
        request_sha256 = digest_json(self.payload)
        command = _park_controller_command()
        broker, environment = self._new_capability_broker(
            command=command,
            credential=token,
            manifest_updates={
                "attempt_id": attempt["attempt_id"],
                "instance_id": attempt["instance_id"],
                "endpoint_id": PLANNER_ENDPOINT,
                "target_key": str(message_id),
                "request_payload_sha256": request_sha256,
                "repository_observation_sha256": self.repository_observation_sha256,
                "repository": REPOSITORY,
                "issue_number": ISSUE,
                "generation": GENERATION,
                "lease_manifest_sha256": self.lease,
                "source_payload_sha256": self.bound_sha,
            },
        )
        environment.update(
            {
                "TWINFINITY_EXECUTOR_ROLE": "planner",
                "TWINFINITY_ROLE_ENDPOINT": PLANNER_ENDPOINT,
                "TWINFINITY_EXECUTOR_TARGET_KIND": "message",
                "TWINFINITY_EXECUTOR_TARGET_KEY": str(message_id),
                "TWINFINITY_PARK_REQUEST_SHA256": request_sha256,
                "TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256": (
                    self.repository_observation_sha256
                ),
            }
        )
        hook = self._run_candidate_guard(
            self._park_hook_event(command=command), environment
        )
        self.assertEqual({}, json.loads(hook.stdout))
        phases: list[tuple[str, str]] = []
        real_readonly = pull_buffer.open_owner_database_readonly
        real_store = pull_buffer.CoordinationStore

        def open_readonly(path):
            phases.append(("readonly", broker.snapshot()["state"]))
            return real_readonly(path)

        def open_writable(path):
            phases.append(("writable", broker.snapshot()["state"]))
            return real_store(path)

        with (
            mock.patch.object(
                pull_buffer, "open_owner_database_readonly", side_effect=open_readonly
            ),
            mock.patch.object(pull_buffer, "CoordinationStore", side_effect=open_writable),
            mock.patch.object(
                pull_buffer,
                "acquire_claimed_no_delivery_repository_observation",
                return_value={
                    "observation_sha256": self.repository_observation_sha256
                },
            ),
        ):
            receipt = pull_buffer.park_claimed_no_delivery_controller(
                database=self.store.path,
                message_id=message_id,
                planner_session_id=PLANNER_ENDPOINT,
                request_sha256=request_sha256,
                repository_observation_sha256=self.repository_observation_sha256,
                environ=environment,
            )
        self.assertEqual(
            [("readonly", "CONSUMED"), ("writable", "ADOPTED")], phases
        )
        self.assertEqual("ADOPTED", broker.snapshot()["state"])
        self.assertEqual("PARKED_NO_DELIVERY", receipt["disposition"])
        self.assertNotIn("TWINFINITY_EXECUTOR_TOKEN", environment)

    def test_authoritative_stale_snapshot_denies_before_adoption_and_writable_open(self) -> None:
        message_id = self._enqueue_park("stale-before-adoption")
        attempt, token = self._running_planner_attempt(message_id, os.getpid())
        request_sha256 = digest_json(self.payload)
        command = _park_controller_command()
        broker, environment = self._new_capability_broker(
            command=command,
            credential=token,
            manifest_updates={
                "attempt_id": attempt["attempt_id"],
                "instance_id": attempt["instance_id"],
                "endpoint_id": PLANNER_ENDPOINT,
                "target_key": str(message_id),
                "request_payload_sha256": request_sha256,
                "repository_observation_sha256": self.repository_observation_sha256,
                "repository": REPOSITORY,
                "issue_number": ISSUE,
                "generation": GENERATION,
                "lease_manifest_sha256": self.lease,
                "source_payload_sha256": self.bound_sha,
            },
        )
        environment.update(
            {
                "TWINFINITY_EXECUTOR_ROLE": "planner",
                "TWINFINITY_ROLE_ENDPOINT": PLANNER_ENDPOINT,
                "TWINFINITY_EXECUTOR_TARGET_KIND": "message",
                "TWINFINITY_EXECUTOR_TARGET_KEY": str(message_id),
                "TWINFINITY_PARK_REQUEST_SHA256": request_sha256,
                "TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256": (
                    self.repository_observation_sha256
                ),
            }
        )
        hook = self._run_candidate_guard(
            self._park_hook_event(command=command), environment
        )
        self.assertEqual({}, json.loads(hook.stdout))

        self.store.connection.execute(
            "UPDATE coordination_items SET version=version+1 "
            "WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        )
        self.store.connection.commit()
        before = self._durable_coordination_snapshot()
        with (
            mock.patch.object(
                pull_buffer,
                "acquire_claimed_no_delivery_repository_observation",
                side_effect=AssertionError("provider observation must not run"),
            ),
            mock.patch.object(
                pull_buffer,
                "adopt_park_controller_capability",
                side_effect=AssertionError("capability adoption must not run"),
            ),
            mock.patch.object(
                pull_buffer,
                "CoordinationStore",
                side_effect=AssertionError("writable store must not be constructed"),
            ),
            self.assertRaisesRegex(pull_buffer.PullBufferError, "PARK_LINEAGE_DRIFT"),
        ):
            pull_buffer.park_claimed_no_delivery_controller(
                database=self.store.path,
                message_id=message_id,
                planner_session_id=PLANNER_ENDPOINT,
                request_sha256=request_sha256,
                repository_observation_sha256=self.repository_observation_sha256,
                environ=environment,
            )
        self.assertEqual("CONSUMED", broker.snapshot()["state"])
        self.assertEqual(before, self._durable_coordination_snapshot())

    def test_controller_stale_matrix_rejects_every_fence_before_writable_construction(self) -> None:
        cases = {
            "item": (
                lambda value: value.__setitem__(
                    "item_version", value["item_version"] + 1
                ),
                "PARK_LINEAGE_DRIFT",
            ),
            "admission": (
                lambda value: value.__setitem__(
                    "admission_updated_at", "2026-08-26T20:00:99Z"
                ),
                "PARK_LINEAGE_DRIFT",
            ),
            "watch": (
                lambda value: value.__setitem__(
                    "watch_updated_at", "2026-08-26T20:00:99Z"
                ),
                "PARK_LINEAGE_DRIFT",
            ),
            "lease": (
                lambda value: value.__setitem__("lease_manifest_sha256", "0" * 64),
                "PARK_LINEAGE_DRIFT",
            ),
            "source-equivalence": (
                lambda value: value.__setitem__(
                    "source_equivalence_receipt_sha256", "0" * 64
                ),
                "PARK_SOURCE_EQUIVALENCE_DRIFT",
            ),
            "graph": (
                lambda value: value.__setitem__(
                    "graph_version", value["graph_version"] + 1
                ),
                "PARK_GRAPH_DRIFT",
            ),
            "policy": (
                lambda value: value.__setitem__(
                    "capacity_policy_version",
                    value["capacity_policy_version"] + 1,
                ),
                "PARK_CAPACITY_POLICY_DRIFT",
            ),
            "artifact": (
                lambda value: value.__setitem__("retained_artifact_key", "0" * 64),
                "ARTIFACT_NOT_FOUND",
            ),
            "preservation": (
                lambda value: value.__setitem__("cleanup_receipt_sha256", "0" * 64),
                "PARK_PRESERVATION_INVALID",
            ),
        }
        for index, (name, (mutate, expected_error)) in enumerate(cases.items()):
            with self.subTest(name=name):
                stale = copy.deepcopy(self.payload)
                mutate(stale["evidence"])
                self._assert_controller_payload_denied_before_writable(
                    stale,
                    suffix=name,
                    expected_error=expected_error,
                    process_id=290 + index,
                )

    def test_fixture_assertion_failure_terminalizes_planner_attempt(self) -> None:
        stale = copy.deepcopy(self.payload)
        stale["evidence"]["item_version"] += 1
        malformed_hook = subprocess.CompletedProcess(
            [os.fspath(FIXTURE_HOOK_INTERPRETER)],
            0,
            b'{"unexpected":"hook-output"}',
            b"",
        )
        with (
            mock.patch.object(
                self, "_run_candidate_guard", return_value=malformed_hook
            ),
            self.assertRaises(AssertionError),
        ):
            self._assert_controller_payload_denied_before_writable(
                stale,
                suffix="terminalized-assertion",
                expected_error="PARK_LINEAGE_DRIFT",
                process_id=399,
            )
        active = self.store.connection.execute(
            "SELECT COUNT(*) FROM executor_attempts WHERE role='planner' "
            "AND state IN ('RESERVED','LAUNCHING','RUNNING')"
        ).fetchone()[0]
        self.assertEqual(0, active)

        probe_message_id = self._enqueue_park("terminalization-probe")
        probe_attempt, probe_token = self._running_planner_attempt(
            probe_message_id, 400
        )
        try:
            current = self.store.connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (probe_attempt["attempt_id"],),
            ).fetchone()
            self.assertEqual("RUNNING", current["state"])
        finally:
            current = self.store.connection.execute(
                "SELECT * FROM executor_attempts WHERE attempt_id=?",
                (probe_attempt["attempt_id"],),
            ).fetchone()
            if current is not None and current["state"] in {
                "RESERVED",
                "LAUNCHING",
                "RUNNING",
            }:
                transition_attempt(
                    self.store.connection,
                    attempt_id=probe_attempt["attempt_id"],
                    token=probe_token,
                    expected_version=int(current["version"]),
                    new_state="HOLD",
                    last_error="FIXTURE_TERMINALIZATION_PROBE",
                    now="2026-08-26T20:00:26Z",
                )

    def test_shared_readonly_snapshot_rejects_delivery_evidence_without_mutation(self) -> None:
        self.store.enqueue_comment(
            idempotency_key="issue-272-readonly-delivery-publication",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            expected_source_sha256=self.current_sha,
            body="Delivery receipt",
            now="2026-08-26T20:00:25Z",
        )
        before = list(self.store.connection.iterdump())
        readonly = open_owner_database_readonly(self.store.path)
        try:
            readonly.execute("BEGIN")
            with self.assertRaisesRegex(
                CoordinationError, "PARK_DELIVERY_OUTBOX_PRESENT"
            ):
                coordination.validate_claimed_no_delivery_park_snapshot(
                    readonly,
                    artifact_root=self.store.path.parent,
                    evidence=coordination.claimed_no_delivery_park_evidence(
                        self.payload
                    ),
                )
            readonly.execute("ROLLBACK")
        finally:
            readonly.close()
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_controller_no_delivery_fence_denies_before_writable_construction(self) -> None:
        self.store.enqueue_comment(
            idempotency_key="issue-272-controller-delivery-publication",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            expected_source_sha256=self.current_sha,
            body="Delivery receipt",
            now="2026-08-26T20:00:25Z",
        )
        self._assert_controller_payload_denied_before_writable(
            copy.deepcopy(self.payload),
            suffix="no-delivery",
            expected_error="PARK_DELIVERY_OUTBOX_PRESENT",
            process_id=299,
        )

    def test_controller_invalid_and_source_mismatched_park_deny_before_writable(self) -> None:
        invalid_envelope = copy.deepcopy(self.payload)
        invalid_envelope["evidence"].pop("prepared_at")
        source_mismatch = copy.deepcopy(self.payload)
        source_mismatch["source"]["repository"] = "twinfinityai/substitute"
        cases = (
            (
                "invalid-envelope",
                invalid_envelope,
                "PARK_CONTROLLER_REQUEST_INVALID",
                300,
            ),
            (
                "source-binding",
                source_mismatch,
                "PARK_CONTROLLER_REQUEST_INVALID",
                301,
            ),
        )
        for suffix, payload, expected_error, process_id in cases:
            with self.subTest(suffix=suffix):
                self._assert_controller_payload_denied_before_writable(
                    payload,
                    suffix=suffix,
                    expected_error=expected_error,
                    process_id=process_id,
                )

    def test_atomic_writable_revalidation_rolls_back_race_after_readonly_snapshot(self) -> None:
        message_id = self._enqueue_park("race-after-readonly")
        attempt, token = self._running_planner_attempt(message_id, os.getpid())
        request_sha256 = digest_json(self.payload)
        command = _park_controller_command()
        broker, environment = self._new_capability_broker(
            command=command,
            credential=token,
            manifest_updates={
                "attempt_id": attempt["attempt_id"],
                "instance_id": attempt["instance_id"],
                "endpoint_id": PLANNER_ENDPOINT,
                "target_key": str(message_id),
                "request_payload_sha256": request_sha256,
                "repository_observation_sha256": self.repository_observation_sha256,
                "repository": REPOSITORY,
                "issue_number": ISSUE,
                "generation": GENERATION,
                "lease_manifest_sha256": self.lease,
                "source_payload_sha256": self.bound_sha,
            },
        )
        environment.update(
            {
                "TWINFINITY_EXECUTOR_ROLE": "planner",
                "TWINFINITY_ROLE_ENDPOINT": PLANNER_ENDPOINT,
                "TWINFINITY_EXECUTOR_TARGET_KIND": "message",
                "TWINFINITY_EXECUTOR_TARGET_KEY": str(message_id),
                "TWINFINITY_PARK_REQUEST_SHA256": request_sha256,
                "TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256": (
                    self.repository_observation_sha256
                ),
            }
        )
        hook = self._run_candidate_guard(
            self._park_hook_event(command=command), environment
        )
        self.assertEqual({}, json.loads(hook.stdout))
        raced_snapshot: list[list[str]] = []
        real_adopt = pull_buffer.adopt_park_controller_capability

        def adopt_then_race(*, environ):
            result = real_adopt(environ=environ)
            self.store.connection.execute(
                "UPDATE coordination_items SET version=version+1 "
                "WHERE repository=? AND issue_number=?",
                (REPOSITORY, ISSUE),
            )
            self.store.connection.commit()
            raced_snapshot.append(list(self.store.connection.iterdump()))
            return result

        with (
            mock.patch.object(
                pull_buffer,
                "acquire_claimed_no_delivery_repository_observation",
                return_value={
                    "observation_sha256": self.repository_observation_sha256
                },
            ),
            mock.patch.object(
                pull_buffer,
                "adopt_park_controller_capability",
                side_effect=adopt_then_race,
            ),
            self.assertRaisesRegex(CoordinationError, "PARK_LINEAGE_DRIFT"),
        ):
            pull_buffer.park_claimed_no_delivery_controller(
                database=self.store.path,
                message_id=message_id,
                planner_session_id=PLANNER_ENDPOINT,
                request_sha256=request_sha256,
                repository_observation_sha256=self.repository_observation_sha256,
                environ=environment,
            )
        self.assertEqual("ADOPTED", broker.snapshot()["state"])
        self.assertEqual(1, len(raced_snapshot))
        self.assertEqual(raced_snapshot[0], list(self.store.connection.iterdump()))

    def test_official_controller_replay_performs_zero_repository_observations(self) -> None:
        first_message_id = self._enqueue_park("official-first")
        first_attempt, first_token = self._running_planner_attempt(
            first_message_id, os.getpid()
        )
        receipt = self.store.commit_claimed_no_delivery_park(
            message_id=first_message_id,
            session_id=PLANNER_ENDPOINT,
            attempt_id=first_attempt["attempt_id"],
            executor_token=first_token,
            expected_repository_observation_sha256=self.repository_observation_sha256,
            repository_observer=lambda: self.repository_observation_sha256,
            now="2026-08-26T20:00:26Z",
        )
        first_running = self.store.connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?",
            (first_attempt["attempt_id"],),
        ).fetchone()
        transition_attempt(
            self.store.connection,
            attempt_id=first_attempt["attempt_id"],
            token=first_token,
            expected_version=first_running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-26T20:00:27Z",
        )

        replay_message_id = self._enqueue_park("official-replay")
        replay_attempt, replay_token = self._running_planner_attempt(
            replay_message_id, os.getpid()
        )
        request_sha256 = digest_json(self.payload)
        command = _park_controller_command()
        broker, environment = self._new_capability_broker(
            command=command,
            credential=replay_token,
            manifest_updates={
                "attempt_id": replay_attempt["attempt_id"],
                "instance_id": replay_attempt["instance_id"],
                "endpoint_id": PLANNER_ENDPOINT,
                "target_key": str(replay_message_id),
                "request_payload_sha256": request_sha256,
                "repository_observation_sha256": self.repository_observation_sha256,
                "repository": REPOSITORY,
                "issue_number": ISSUE,
                "generation": GENERATION,
                "lease_manifest_sha256": self.lease,
                "source_payload_sha256": self.bound_sha,
            },
        )
        environment.update(
            {
                "TWINFINITY_EXECUTOR_ROLE": "planner",
                "TWINFINITY_ROLE_ENDPOINT": PLANNER_ENDPOINT,
                "TWINFINITY_EXECUTOR_TARGET_KIND": "message",
                "TWINFINITY_EXECUTOR_TARGET_KEY": str(replay_message_id),
                "TWINFINITY_PARK_REQUEST_SHA256": request_sha256,
                "TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256": (
                    self.repository_observation_sha256
                ),
            }
        )
        hook = self._run_candidate_guard(
            self._park_hook_event(command=command), environment
        )
        self.assertEqual({}, json.loads(hook.stdout))
        observations: list[list[str]] = []

        def forbidden_observer(argv, **_kwargs):
            observations.append(list(argv))
            self.fail("official replay must not execute Git or GitHub observation")

        replay = pull_buffer.park_claimed_no_delivery_controller(
            database=self.store.path,
            message_id=replay_message_id,
            planner_session_id=PLANNER_ENDPOINT,
            request_sha256=request_sha256,
            repository_observation_sha256=self.repository_observation_sha256,
            environ=environment,
            runner=forbidden_observer,
        )
        self.assertEqual(receipt, replay)
        self.assertEqual([], observations)
        self.assertEqual("ADOPTED", broker.snapshot()["state"])

    def test_second_repository_observation_drift_denies_before_adoption(self) -> None:
        message_id = self._enqueue_park("second-observation-drift")
        attempt, token = self._running_planner_attempt(message_id, os.getpid())
        request_sha256 = digest_json(self.payload)
        command = _park_controller_command()
        broker, environment = self._new_capability_broker(
            command=command,
            credential=token,
            manifest_updates={
                "attempt_id": attempt["attempt_id"],
                "instance_id": attempt["instance_id"],
                "endpoint_id": PLANNER_ENDPOINT,
                "target_key": str(message_id),
                "request_payload_sha256": request_sha256,
                "repository_observation_sha256": self.repository_observation_sha256,
                "repository": REPOSITORY,
                "issue_number": ISSUE,
                "generation": GENERATION,
                "lease_manifest_sha256": self.lease,
                "source_payload_sha256": self.bound_sha,
            },
        )
        environment.update(
            {
                "TWINFINITY_EXECUTOR_ROLE": "planner",
                "TWINFINITY_ROLE_ENDPOINT": PLANNER_ENDPOINT,
                "TWINFINITY_EXECUTOR_TARGET_KIND": "message",
                "TWINFINITY_EXECUTOR_TARGET_KEY": str(message_id),
                "TWINFINITY_PARK_REQUEST_SHA256": request_sha256,
                "TWINFINITY_PARK_REPOSITORY_OBSERVATION_SHA256": (
                    self.repository_observation_sha256
                ),
            }
        )
        hook = self._run_candidate_guard(
            self._park_hook_event(command=command), environment
        )
        self.assertEqual({}, json.loads(hook.stdout))
        before = list(self.store.connection.iterdump())
        with (
            mock.patch.object(
                pull_buffer,
                "acquire_claimed_no_delivery_repository_observation",
                side_effect=(
                    {
                        "observation_sha256": self.repository_observation_sha256
                    },
                    {"observation_sha256": "0" * 64},
                ),
            ),
            self.assertRaisesRegex(
                pull_buffer.PullBufferError,
                "PARK_REPOSITORY_OBSERVATION_DRIFT",
            ),
        ):
            pull_buffer.park_claimed_no_delivery_controller(
                database=self.store.path,
                message_id=message_id,
                planner_session_id=PLANNER_ENDPOINT,
                request_sha256=request_sha256,
                repository_observation_sha256=self.repository_observation_sha256,
                environ=environment,
            )
        self.assertEqual("CONSUMED", broker.snapshot()["state"])
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_live_issue_material_drift_is_a_zero_write_denial(self) -> None:
        with mock.patch.dict(
            os.environ,
            {ACTUAL_CODEX_FIXTURE_ROOT_ENV: self.temp.name},
        ):
            self._register_actual_repository_observation()
        before = list(self.store.connection.iterdump())
        invocations: list[list[str]] = []

        def drifted_provider(argv, **_kwargs):
            invocations.append(list(argv))
            target = next(
                (item for item in argv if item.startswith("repos/")), ""
            )
            if argv[0] == "/usr/bin/git":
                return subprocess.CompletedProcess(argv, 1, "", "")
            if target.endswith("/git/matching-refs/heads/main"):
                stdout = canonical_json(
                    [
                        {
                            "ref": "refs/heads/main",
                            "object": {"sha": MAIN_SHA},
                        }
                    ]
                )
            elif target.endswith(f"/issues/{ISSUE}"):
                stdout = canonical_json(
                    {
                        "number": ISSUE,
                        "state": "open",
                        "title": "Bound scope",
                        "body": "materially drifted body",
                        "labels": [{"name": "bug"}],
                        "milestone": None,
                        "assignees": [],
                    }
                )
            else:
                stdout = "[]"
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with self.assertRaisesRegex(
            pull_buffer.PullBufferError, "PARK_PROVIDER_ISSUE_DRIFT"
        ):
            pull_buffer.acquire_claimed_no_delivery_repository_observation(
                self.store.connection,
                self.payload["evidence"],
                runner=drifted_provider,
            )
        self.assertEqual(5, len(invocations))
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_repository_observation_blocks_only_same_repository_exact_branch_pr(self) -> None:
        with mock.patch.dict(
            os.environ,
            {ACTUAL_CODEX_FIXTURE_ROOT_ENV: self.temp.name},
        ):
            self._register_actual_repository_observation()
        before = list(self.store.connection.iterdump())
        live_issue = self.store.current_snapshot(
            REPOSITORY, "issue", ISSUE
        ).payload

        def runner_for(pull_rows):
            def run(argv, **_kwargs):
                if argv[0] == "/usr/bin/git":
                    return subprocess.CompletedProcess(argv, 1, "", "")
                target = next(
                    (value for value in argv if value.startswith("repos/")), ""
                )
                if target.endswith("/git/matching-refs/heads/main"):
                    payload = [
                        {
                            "ref": "refs/heads/main",
                            "object": {"sha": MAIN_SHA},
                        }
                    ]
                elif target.endswith("/pulls"):
                    payload = pull_rows
                elif target.endswith(f"/issues/{ISSUE}"):
                    payload = live_issue
                else:
                    payload = []
                return subprocess.CompletedProcess(
                    argv, 0, canonical_json(payload), ""
                )

            return run

        def observe(pull_rows):
            with mock.patch.object(
                pull_buffer.os,
                "lstat",
                side_effect=FileNotFoundError,
            ):
                return pull_buffer.acquire_claimed_no_delivery_repository_observation(
                    self.store.connection,
                    self.payload["evidence"],
                    runner=runner_for(pull_rows),
                )

        ignored = [
            {
                "number": 144,
                "head": {
                    "ref": self.delivery_branch,
                    "repo": {"full_name": "fork-owner/twinfinityapp"},
                },
            },
            {
                "number": 145,
                "head": {"ref": self.delivery_branch, "repo": None},
            },
        ]
        observed = observe(ignored)
        self.assertEqual([], observed["matching_open_pull_requests"])
        self.assertEqual(self.repository_observation_sha256, observed["observation_sha256"])
        self.assertEqual(before, list(self.store.connection.iterdump()))

        same_repository = [
            {
                "number": 146,
                "head": {
                    "ref": self.delivery_branch,
                    "repo": {"full_name": REPOSITORY.upper()},
                },
            }
        ]
        with self.assertRaisesRegex(
            pull_buffer.PullBufferError, "PARK_CANDIDATE_STILL_PRESENT"
        ):
            observe(same_repository)
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_nested_hook_replay_fails_closed_before_controller(self) -> None:
        before = list(self.store.connection.iterdump())
        broker, environment = self._new_capability_broker()
        first = self._run_candidate_guard(self._park_hook_event(), environment)
        second = self._run_candidate_guard(self._park_hook_event(), environment)
        self.assertEqual({}, json.loads(first.stdout))
        self.assertEqual(
            "deny",
            json.loads(second.stdout)["hookSpecificOutput"]["permissionDecision"],
        )
        self.assertEqual("FAILED", broker.snapshot()["state"])
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_command_drift_and_specialized_bypass_fail_closed(self) -> None:
        for raw in (
            self._park_hook_event(command="/usr/bin/false"),
            self._park_hook_event(tool_name="apply_patch"),
        ):
            with self.subTest(raw=raw):
                before = list(self.store.connection.iterdump())
                broker, environment = self._new_capability_broker()
                result = self._run_candidate_guard(raw, environment)
                self.assertEqual(
                    "deny",
                    json.loads(result.stdout)["hookSpecificOutput"][
                        "permissionDecision"
                    ],
                )
                self.assertEqual("FAILED", broker.snapshot()["state"])
                self.assertEqual(before, list(self.store.connection.iterdump()))
                broker.close()

    def _run_actual_codex_test_in_namespace(
        self,
        *,
        test_method: str,
        expected_gh_invocations: int,
        writable_canonical_skill: bool = False,
    ) -> None:
        fixture_root = Path(self.temp.name) / "actual-codex-fixture"
        coordination = fixture_root / "coordination"
        coordination.mkdir(parents=True, mode=0o700)
        requirements = fixture_root / "requirements.toml"
        requirements.write_text(
            """allow_managed_hooks_only = true
allow_login_shell = false
check_for_update_on_startup = false
allowed_sandbox_modes = ["read-only"]
allowed_approval_policies = ["on-request"]
allowed_approvals_reviewers = ["auto_review"]
allowed_web_search_modes = []

[features]
hooks = true
apps = false
computer_use = false
goals = false
memories = false
multi_agent = false
plugins = false
remote_plugin = false
shell_snapshot = false
skill_mcp_dependency_install = false
workspace_dependencies = false

[mcp_servers]

[plugins]

[hooks]
managed_dir = "/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts"

[[hooks.PreToolUse]]
matcher = "*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/bin/python3 /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/delivery_guard.py"
timeout = 10
statusMessage = "Checking Planner SQLite delivery evidence"
""",
            encoding="utf-8",
        )
        gh_stub = fixture_root / "gh"
        gh_stub.write_text(
            """#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

log = (
    Path(os.environ["TWINFINITY_EXECUTOR_PROFILE_PATH"]).parent.parent
    / "gh.jsonl"
)
with log.open("a", encoding="utf-8") as output:
    output.write(json.dumps(sys.argv[1:], separators=(",", ":")) + "\\n")
target = next((item for item in sys.argv if item.startswith("repos/")), "")
if target.endswith("/git/matching-refs/heads/main"):
    print('[{"ref":"refs/heads/main","object":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]')
elif target.endswith("/issues/272"):
    print('{"number":272,"state":"open","title":"Bound scope","body":"Exact body","labels":[{"name":"bug"}],"milestone":null,"assignees":[]}')
else:
    print("[]")
""",
            encoding="utf-8",
        )
        gh_stub.chmod(0o700)
        gh_log = fixture_root / "gh.jsonl"
        candidate_repository = fixture_root / "candidate-repository"
        clone = subprocess.run(
            [
                "/usr/bin/git",
                "clone",
                "--no-local",
                "--single-branch",
                "--branch",
                "change/144-planner-v3-real-boundary-v2",
                os.fspath(ROOT.parents[1]),
                os.fspath(candidate_repository),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, clone.returncode, clone.stderr)
        candidate_skill = (
            candidate_repository / "skills" / "twinfinity-sprint-orchestrator"
        )
        shutil.copytree(ROOT, candidate_skill, dirs_exist_ok=True, symlinks=True)
        canonical_skill = Path(
            "/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator"
        )
        canonical_coordination = Path(
            "/home/ubuntu/.codex/twinfinity-coordination"
        )
        test_name = (
            "tests.test_claimed_no_delivery_park.ClaimedNoDeliveryParkTests."
            f"{test_method}"
        )
        command = [
            "/usr/bin/bwrap",
            "--die-with-parent",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--dev-bind",
            "/dev",
            "/dev",
            "--proc",
            "/proc",
            "--ro-bind",
            "/tmp",
            "/tmp",
            "--bind",
            os.fspath(fixture_root),
            os.fspath(fixture_root),
            "--tmpfs",
            "/home/ubuntu/code",
            "--dir",
            "/home/ubuntu/code/twinfinity",
            "--ro-bind",
            os.fspath(candidate_repository),
            os.fspath(ROOT.parents[1]),
            "--bind" if writable_canonical_skill else "--ro-bind",
            os.fspath(candidate_skill),
            os.fspath(canonical_skill),
            "--bind",
            os.fspath(coordination),
            os.fspath(canonical_coordination),
            "--tmpfs",
            "/etc",
            "--ro-bind",
            "/etc/passwd",
            "/etc/passwd",
            "--ro-bind",
            "/etc/group",
            "/etc/group",
            "--ro-bind",
            "/etc/ssl",
            "/etc/ssl",
            "--ro-bind",
            "/etc/hosts",
            "/etc/hosts",
            "--ro-bind",
            "/etc/resolv.conf",
            "/etc/resolv.conf",
            "--ro-bind",
            "/etc/nsswitch.conf",
            "/etc/nsswitch.conf",
            "--dir",
            "/etc/codex",
            "--ro-bind",
            os.fspath(requirements),
            "/etc/codex/requirements.toml",
            "--ro-bind",
            os.fspath(gh_stub),
            "/usr/bin/gh",
            "--setenv",
            ACTUAL_CODEX_IN_NAMESPACE_ENV,
            "1",
            "--setenv",
            ACTUAL_CODEX_FIXTURE_ROOT_ENV,
            os.fspath(fixture_root),
            "--setenv",
            ACTUAL_CODEX_GH_LOG_ENV,
            os.fspath(gh_log),
            "--setenv",
            "PYTHONPATH",
            os.fspath(ROOT),
            "--chdir",
            os.fspath(ROOT),
            "/usr/bin/python3",
            "-m",
            "unittest",
            test_name,
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "NO_PROXY": "127.0.0.1,localhost"},
            check=False,
        )
        self.assertEqual(
            0,
            result.returncode,
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        invocations = (
            gh_log.read_text(encoding="utf-8").splitlines()
            if gh_log.exists()
            else []
        )
        self.assertEqual(expected_gh_invocations, len(invocations))

    def _register_actual_repository_observation(self) -> None:
        fixture_root = Path(os.environ[ACTUAL_CODEX_FIXTURE_ROOT_ENV])
        bootstrap_manifest = {"kind": "actual-codex-park-bootstrap"}
        bootstrap_sha256 = digest_json(bootstrap_manifest)
        git_dir = fixture_root / "registered-application.git"
        initialized = subprocess.run(
            ["/usr/bin/git", "init", "--bare", os.fspath(git_dir)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, initialized.returncode, initialized.stderr)
        git_dir.chmod(0o700)
        (git_dir / "config").write_text(
            "[core]\n"
            "\tbare = true\n"
            '[remote "origin"]\n'
            f"\turl = https://github.com/{REPOSITORY}.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8",
        )
        main_ref = git_dir / "refs" / "remotes" / "origin" / "main"
        main_ref.parent.mkdir(parents=True)
        main_ref.write_text(MAIN_SHA + "\n", encoding="ascii")
        with self.store.transaction():
            self.store.record_bootstrap_provenance(
                bootstrap_id="actual-codex-park-bootstrap",
                manifest_sha256=bootstrap_sha256,
                manifest=bootstrap_manifest,
                source_harness_repository="jayendusharma/twinfinity-harness",
                source_harness_main_sha="a" * 40,
                source_registry_sha256="1" * 64,
                approved_goal_sha256="2" * 64,
                application_repository=REPOSITORY,
                application_main_sha=MAIN_SHA,
                archived_database_sha256="3" * 64,
                now="2026-08-26T20:00:23Z",
            )
            registration = self.store.record_repository_git_registration(
                repository=REPOSITORY,
                git_dir=git_dir,
                source_main_sha=MAIN_SHA,
                bootstrap_id="actual-codex-park-bootstrap",
                bootstrap_manifest_sha256=bootstrap_sha256,
                now="2026-08-26T20:00:23Z",
            )
        observation = {
            "schema": "twinfinity-claimed-no-delivery-repository-observation/v1",
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": GENERATION,
            "registration_sha256": registration["registration_sha256"],
            "origin_url_sha256": hashlib.sha256(
                f"https://github.com/{REPOSITORY}.git".encode("utf-8")
            ).hexdigest(),
            "remote_main_sha": MAIN_SHA,
            "current_source_sha256": self.current_sha,
            "issue_material_sha256": digest_json(
                _park_issue_material_projection(
                    self.store.current_snapshot(REPOSITORY, "issue", ISSUE).payload
                )
            ),
            "candidate_branch": self.delivery_branch,
            "remote_candidate_refs": [],
            "matching_open_pull_requests": [],
            "local_branch_absent": True,
            "worktree_absent": True,
            "cleanup_receipt_sha256": self.cleanup_receipt_sha256,
        }
        self.repository_observation_sha256 = digest_json(observation)
        self.payload["evidence"]["repository_observation_sha256"] = (
            self.repository_observation_sha256
        )

    def _actual_codex_responses_server(
        self,
        command: str,
        *,
        mode: str = "exec",
        specialized_marker: Path | None = None,
        guardian_outcome: str = "allow",
        guardian_delay: float = 1.2,
        completion_delay: float = 0.35,
    ) -> tuple[ThreadingHTTPServer, threading.Thread, list[dict]]:
        requests: list[dict] = []
        requests_lock = threading.Lock()
        nested_exec = (
            "tools.exec_command({"
            f"cmd: {json.dumps(command)}, "
            'workdir: "/home/ubuntu", '
            'sandbox_permissions: "require_escalated", '
            'justification: "Allow the exact owner-safe PARK controller to acquire current GitHub and local Git evidence."'
            "})"
        )
        if mode == "replay":
            call_input = (
                f"const first = await {nested_exec}; "
                f"const second = await {nested_exec}; "
                "text(JSON.stringify({first:first.output,second:second.output}));"
            )
        elif mode == "specialized":
            if specialized_marker is None:
                raise AssertionError("specialized marker is required")
            patch = (
                "*** Begin Patch\n*** Add File: "
                f"{specialized_marker}\n+specialized bypass must not execute\n"
                "*** End Patch"
            )
            call_input = (
                "const r = await tools.apply_patch("
                f"{json.dumps(patch)}); text(JSON.stringify(r));"
            )
        else:
            call_input = f"const r = await {nested_exec}; text(r.output);"

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format, *_args):
                return

            def do_POST(self):  # noqa: N802
                raw = self.rfile.read(int(self.headers.get("content-length", "0")))
                request = json.loads(raw)
                with requests_lock:
                    request_number = len(requests)
                    record = {
                        "raw": raw,
                        "guardian": bool(request.get("tools")),
                        "custom_output": any(
                            isinstance(item, dict)
                            and item.get("type") == "custom_tool_call_output"
                            for item in request.get("input", [])
                        ),
                        "received_monotonic": time.monotonic(),
                    }
                    requests.append(record)
                response_id = f"resp_park_{request_number}"
                usage = {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
                if record["guardian"]:
                    time.sleep(guardian_delay)
                    text = json.dumps(
                        {"outcome": guardian_outcome}, separators=(",", ":")
                    )
                    item = {
                        "type": "message",
                        "id": f"msg_guardian_{request_number}",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": text,
                                "annotations": [],
                            }
                        ],
                        "status": "completed",
                    }
                    events = [
                        {"type": "response.created", "response": {"id": response_id}},
                        {
                            "type": "response.output_item.added",
                            "output_index": 0,
                            "item": {**item, "content": [], "status": "in_progress"},
                        },
                        {
                            "type": "response.content_part.added",
                            "output_index": 0,
                            "item_id": item["id"],
                            "content_index": 0,
                            "part": {
                                "type": "output_text",
                                "text": "",
                                "annotations": [],
                            },
                        },
                        {
                            "type": "response.output_text.delta",
                            "output_index": 0,
                            "item_id": item["id"],
                            "content_index": 0,
                            "delta": text,
                        },
                        {
                            "type": "response.output_text.done",
                            "output_index": 0,
                            "item_id": item["id"],
                            "content_index": 0,
                            "text": text,
                        },
                        {
                            "type": "response.content_part.done",
                            "output_index": 0,
                            "item_id": item["id"],
                            "content_index": 0,
                            "part": item["content"][0],
                        },
                        {
                            "type": "response.output_item.done",
                            "output_index": 0,
                            "item": item,
                        },
                        {
                            "type": "response.completed",
                            "response": {
                                "id": response_id,
                                "output": [item],
                                "usage": usage,
                            },
                        },
                    ]
                elif record["custom_output"]:
                    time.sleep(completion_delay)
                    events = [
                        {"type": "response.created", "response": {"id": response_id}},
                        {
                            "type": "response.completed",
                            "response": {
                                "id": response_id,
                                "output": [],
                                "usage": usage,
                            },
                        },
                    ]
                else:
                    if mode == "crash":
                        self.close_connection = True
                        return
                    if mode == "timeout":
                        time.sleep(12.0)
                    if mode == "absence":
                        events = [
                            {"type": "response.created", "response": {"id": response_id}},
                            {
                                "type": "response.completed",
                                "response": {
                                    "id": response_id,
                                    "output": [],
                                    "usage": usage,
                                },
                            },
                        ]
                    else:
                        item = {
                            "type": "custom_tool_call",
                            "id": f"ctc_park_{request_number}",
                            "call_id": f"call_park_{request_number}",
                            "name": "exec",
                            "namespace": "functions",
                            "input": call_input,
                            "status": "completed",
                        }
                        events = [
                            {"type": "response.created", "response": {"id": response_id}},
                            {
                                "type": "response.output_item.added",
                                "output_index": 0,
                                "item": {**item, "input": "", "status": "in_progress"},
                            },
                            {
                                "type": "response.custom_tool_call_input.delta",
                                "output_index": 0,
                                "item_id": item["id"],
                                "delta": item["input"],
                            },
                            {
                                "type": "response.custom_tool_call_input.done",
                                "output_index": 0,
                                "item_id": item["id"],
                                "input": item["input"],
                            },
                            {
                                "type": "response.output_item.done",
                                "output_index": 0,
                                "item": item,
                            },
                            {
                                "type": "response.completed",
                                "response": {
                                    "id": response_id,
                                    "output": [item],
                                    "usage": usage,
                                },
                            },
                        ]
                body = b"".join(
                    f"data: {json.dumps(event, separators=(',', ':'))}\n\n".encode()
                    for event in events
                ) + b"data: [DONE]\n\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, requests

    def _actual_controller_state_snapshot(self, message_id: int) -> dict:
        del message_id
        excluded = {"executor_attempts", "executor_attempt_events"}
        tables = [
            str(candidate[0])
            for candidate in self.store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            if candidate[0] not in excluded
        ]
        snapshot: dict[str, list[dict]] = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            snapshot[table] = [
                dict(candidate)
                for candidate in self.store.connection.execute(
                    f"SELECT * FROM {quoted} ORDER BY rowid"
                )
            ]
        return snapshot

    def _actual_codex_systemd_evidence(
        self, message_id: int
    ) -> tuple[str, SystemdUnitEvidence]:
        unit = stable_systemd_unit("planner", "message", str(message_id))
        invocation_id = hashlib.md5(
            f"actual-park:{message_id}".encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        return invocation_id, SystemdUnitEvidence(
            unit=unit,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            invocation_id=invocation_id,
            control_group=(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit
            ),
            result="success",
        )

    def _execute_actual_codex_case(
        self,
        *,
        suffix: str,
        mode: str,
        provider_command: str | None = None,
        guardian_outcome: str = "allow",
        specialized_marker: Path | None = None,
        release_interference: str | None = None,
        pin_wal_reader: bool = False,
    ) -> dict:
        fixture_root = Path(os.environ[ACTUAL_CODEX_FIXTURE_ROOT_ENV])
        installed = fixture_root / "installed"
        profile = ROOT / "references" / "twinfinity-planner-v3.config.toml"
        installed_profile = installed / profile.name
        installed_profile.write_bytes(profile.read_bytes())
        expected_command = _park_controller_command()
        server, server_thread, requests = self._actual_codex_responses_server(
            provider_command or expected_command,
            mode=mode,
            specialized_marker=specialized_marker,
            guardian_outcome=guardian_outcome,
        )
        port = server.server_address[1]
        config_path = installed / "config.toml"
        config_path.write_text(
            f'''model = "gpt-5.6-sol"
model_provider = "local-park"
check_for_update_on_startup = false

[model_providers.local-park]
name = "Issue 144 local PARK proof"
base_url = "http://127.0.0.1:{port}/v1"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
stream_idle_timeout_ms = 5000
''',
            encoding="utf-8",
        )
        message_id = self._enqueue_park(suffix)
        before = self._actual_controller_state_snapshot(message_id)
        invocation_id, evidence = self._actual_codex_systemd_evidence(message_id)
        transitions: list[dict] = []
        captured_environment: dict[str, str] = {}
        wrong_process_outputs: list[subprocess.CompletedProcess] = []
        reader_connection: sqlite3.Connection | None = None
        real_popen = subprocess.Popen
        real_release_prompt = ParkCapabilityBroker.release_prompt
        mutated_path: Path | None = None
        original_bytes: bytes | None = None
        if release_interference == "profile_drift":
            mutated_path = installed_profile
        elif release_interference == "config_drift":
            mutated_path = config_path
        elif release_interference == "import_drift":
            mutated_path = Path(
                "/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/"
                "scripts/coordination_store.py"
            )
        if mutated_path is not None:
            original_bytes = mutated_path.read_bytes()

        def inspecting_popen(*args, **kwargs):
            captured_environment.update(kwargs.get("env", {}))
            return real_popen(*args, **kwargs)

        def traced_transition(connection, **kwargs):
            nonlocal reader_connection
            transitioned = transition_attempt(connection, **kwargs)
            transitions.append(
                {
                    "state": kwargs["new_state"],
                    "monotonic": time.monotonic(),
                    "version": transitioned["version"],
                }
            )
            if (
                pin_wal_reader
                and kwargs["new_state"] == "RUNNING"
                and reader_connection is None
            ):
                reader_connection = sqlite3.connect(self.store.path, timeout=2)
                reader_connection.execute("BEGIN")
                reader_connection.execute(
                    "SELECT state FROM coordination_messages WHERE id=?",
                    (message_id,),
                ).fetchone()
            return transitioned

        def interfered_release(broker, stream, prompt):
            if mutated_path is not None and original_bytes is not None:
                mutated_path.write_bytes(original_bytes + b"\n# issue-144 drift\n")
                real_release_prompt(broker, stream, prompt)
                return
            if release_interference == "socket_unavailable":
                broker.path.unlink()
                real_release_prompt(broker, stream, prompt)
                return
            real_release_prompt(broker, stream, prompt)
            if release_interference == "wrong_process":
                wrong_process_outputs.append(
                    self._run_candidate_guard(
                        self._park_hook_event(command=expected_command),
                        {PARK_CAPABILITY_SOCKET_ENV: os.fspath(broker.path)},
                    )
                )

        release_context = (
            mock.patch.object(
                ParkCapabilityBroker,
                "release_prompt",
                new=interfered_release,
            )
            if release_interference is not None
            else contextlib.nullcontext()
        )
        token_sentinel = f"PARK_SENTINEL_{suffix.upper()}_SECRET"
        gh_log = Path(os.environ[ACTUAL_CODEX_GH_LOG_ENV])
        gh_before = (
            len(gh_log.read_text(encoding="utf-8").splitlines())
            if gh_log.exists()
            else 0
        )
        try:
            with (
                release_context,
                mock.patch(
                    "executor_registry.secrets.token_urlsafe",
                    return_value=token_sentinel,
                ),
                mock.patch.dict(
                    os.environ,
                    {
                        "CODEX_HOME": os.fspath(installed),
                        "NO_PROXY": "127.0.0.1,localhost",
                    },
                ),
            ):
                result = execute_role(
                    self.store.connection,
                    config_path=(
                        ROOT / "references" / "twinfinity-executor-registry.toml"
                    ),
                    role="planner",
                    endpoint_id=PLANNER_ENDPOINT,
                    target_kind="message",
                    target_key=str(message_id),
                    prompt="Execute only the exact bound PARK controller.",
                    systemd_invocation_id=invocation_id,
                    systemd_evidence=evidence,
                    popen=inspecting_popen,
                    transitioner=traced_transition,
                    heartbeat_seconds=1,
                )
        finally:
            if reader_connection is not None:
                reader_connection.rollback()
                reader_connection.close()
            if mutated_path is not None and original_bytes is not None:
                mutated_path.write_bytes(original_bytes)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=8)
        gh_after = (
            len(gh_log.read_text(encoding="utf-8").splitlines())
            if gh_log.exists()
            else 0
        )
        self.assertNotIn("TWINFINITY_EXECUTOR_TOKEN", captured_environment)
        self.assertNotIn("TWINFINITY_COORDINATION_DATABASE", captured_environment)
        self.assertIn(PARK_CAPABILITY_SOCKET_ENV, captured_environment)
        self.assertTrue(
            all(token_sentinel.encode("utf-8") not in request["raw"] for request in requests)
        )
        runtime_files = {
            candidate
            for runtime_root in (installed, self.store.path.parent)
            for candidate in runtime_root.rglob("*")
            if candidate.is_file()
        }
        runtime_files.update(
            candidate
            for candidate in (gh_log, fixture_root / "requirements.toml")
            if candidate.is_file()
        )
        self.assertEqual(
            [],
            [
                os.fspath(candidate)
                for candidate in sorted(runtime_files)
                if token_sentinel.encode("utf-8") in candidate.read_bytes()
            ],
            "raw executor capability leaked into an issue-owned runtime surface",
        )
        self.assertEqual(
            [], list(self.store.path.parent.glob("park-cap-*")), suffix
        )
        return {
            "message_id": message_id,
            "before": before,
            "after": self._actual_controller_state_snapshot(message_id),
            "result": result,
            "requests": requests,
            "transitions": transitions,
            "wrong_process_outputs": wrong_process_outputs,
            "gh_invocations": gh_after - gh_before,
            "token_sentinel": token_sentinel,
        }

    def test_actual_codex_denial_bypass_drift_and_replay_matrix(self) -> None:
        if os.environ.get(ACTUAL_CODEX_TEST_ENV) != "1":
            self.skipTest(f"set {ACTUAL_CODEX_TEST_ENV}=1 for the native Codex gate")
        if os.environ.get(ACTUAL_CODEX_IN_NAMESPACE_ENV) != "1":
            self._run_actual_codex_test_in_namespace(
                test_method=self._testMethodName,
                expected_gh_invocations=8,
                writable_canonical_skill=True,
            )
            return

        self._register_actual_repository_observation()
        fixture_root = Path(os.environ[ACTUAL_CODEX_FIXTURE_ROOT_ENV])
        specialized_marker = fixture_root / "specialized-bypass-marker"
        cases = (
            {"suffix": "guardian-denial", "mode": "exec", "guardian_outcome": "deny"},
            {"suffix": "hook-absence", "mode": "absence"},
            {"suffix": "provider-crash", "mode": "crash"},
            {"suffix": "provider-timeout", "mode": "timeout"},
            {
                "suffix": "wrong-command",
                "mode": "exec",
                "provider_command": "/usr/bin/false",
            },
            {
                "suffix": "specialized-bypass",
                "mode": "specialized",
                "specialized_marker": specialized_marker,
            },
            {
                "suffix": "wrong-process",
                "mode": "absence",
                "release_interference": "wrong_process",
            },
            {
                "suffix": "hook-transport-failure",
                "mode": "exec",
                "release_interference": "socket_unavailable",
            },
            {
                "suffix": "profile-drift",
                "mode": "exec",
                "release_interference": "profile_drift",
            },
            {
                "suffix": "config-drift",
                "mode": "exec",
                "release_interference": "config_drift",
            },
            {
                "suffix": "import-drift",
                "mode": "exec",
                "release_interference": "import_drift",
            },
        )
        for case in cases:
            with self.subTest(case=case["suffix"]):
                database = self.store.path
                self.store.close()
                self.store = CoordinationStore(database)
                outcome = self._execute_actual_codex_case(**case)
                result = outcome["result"]
                self.assertEqual("HOLD", result["phase"], result)
                self.assertEqual("HOLD", result["state"], result)
                self.assertEqual(outcome["before"], outcome["after"], result)
                self.assertEqual(0, outcome["gh_invocations"], outcome)
                kinds = [
                    event["kind"]
                    for event in result["park_adoption"]["events"]
                ]
                self.assertNotIn("CONTROLLER_CONSUMED", kinds)
                self.assertNotIn("CONTROLLER_ADOPTED", kinds)
                if case["suffix"] == "provider-timeout":
                    self.assertEqual(
                        "PARK_CAPABILITY_ADOPTION_TIMEOUT", result["error"]
                    )
                if case["suffix"] == "wrong-process":
                    self.assertEqual(1, len(outcome["wrong_process_outputs"]))
                    denied = json.loads(
                        outcome["wrong_process_outputs"][0].stdout
                    )
                    self.assertEqual(
                        "deny",
                        denied["hookSpecificOutput"]["permissionDecision"],
                    )
        self.assertFalse(specialized_marker.exists())

        database = self.store.path
        self.store.close()
        self.store = CoordinationStore(database)
        replay = self._execute_actual_codex_case(
            suffix="nested-replay", mode="replay"
        )
        result = replay["result"]
        self.assertEqual("HOLD", result["phase"], result)
        kinds = [event["kind"] for event in result["park_adoption"]["events"]]
        self.assertEqual(1, kinds.count("CONTROLLER_CONSUMED"), kinds)
        self.assertEqual(1, kinds.count("CONTROLLER_ADOPTED"), kinds)
        self.assertEqual(1, kinds.count("CAPABILITY_FAILED"), kinds)
        self.assertEqual(8, replay["gh_invocations"], replay)
        self.assertEqual(
            "COMPLETE",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?",
                (replay["message_id"],),
            ).fetchone()[0],
        )

    def test_actual_codex_fresh_official_replay_has_no_second_observation_or_release(
        self,
    ) -> None:
        if os.environ.get(ACTUAL_CODEX_TEST_ENV) != "1":
            self.skipTest(f"set {ACTUAL_CODEX_TEST_ENV}=1 for the native Codex gate")
        if os.environ.get(ACTUAL_CODEX_IN_NAMESPACE_ENV) != "1":
            self._run_actual_codex_test_in_namespace(
                test_method=self._testMethodName,
                expected_gh_invocations=8,
            )
            return

        self._register_actual_repository_observation()
        first = self._execute_actual_codex_case(
            suffix="official-primary", mode="exec"
        )
        self.assertEqual("PASS", first["result"]["phase"], first)
        self.assertEqual(8, first["gh_invocations"], first)
        payload_sha256 = digest_json(self.payload)
        evidence = coordination.claimed_no_delivery_park_evidence(self.payload)
        receipt_before = coordination.committed_claimed_no_delivery_park_receipt(
            self.store.connection,
            payload_sha256=payload_sha256,
            evidence=evidence,
        )
        self.assertIsNotNone(receipt_before)
        database = self.store.path
        self.store.close()
        self.store = CoordinationStore(database)

        replay = self._execute_actual_codex_case(
            suffix="official-fresh-replay", mode="exec"
        )
        self.assertEqual("PASS", replay["result"]["phase"], replay)
        self.assertEqual(0, replay["gh_invocations"], replay)
        receipt_after = coordination.committed_claimed_no_delivery_park_receipt(
            self.store.connection,
            payload_sha256=payload_sha256,
            evidence=evidence,
        )
        self.assertEqual(
            canonical_json(receipt_before), canonical_json(receipt_after)
        )
        before = copy.deepcopy(replay["before"])
        after = copy.deepcopy(replay["after"])
        for snapshot in (before, after):
            snapshot["coordination_messages"] = [
                row
                for row in snapshot["coordination_messages"]
                if int(row["id"]) != replay["message_id"]
            ]
            snapshot["coordination_events"] = [
                row
                for row in snapshot["coordination_events"]
                if row["entity_key"] != f"message:{replay['message_id']}"
            ]
        self.assertEqual(before, after)
        self.assertEqual(
            "COMPLETE",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?",
                (replay["message_id"],),
            ).fetchone()[0],
        )

    def test_actual_codex_nonzero_wal_barrier_denies_before_prompt(self) -> None:
        if os.environ.get(ACTUAL_CODEX_TEST_ENV) != "1":
            self.skipTest(f"set {ACTUAL_CODEX_TEST_ENV}=1 for the native Codex gate")
        if os.environ.get(ACTUAL_CODEX_IN_NAMESPACE_ENV) != "1":
            self._run_actual_codex_test_in_namespace(
                test_method=self._testMethodName,
                expected_gh_invocations=0,
            )
            return

        self._register_actual_repository_observation()
        outcome = self._execute_actual_codex_case(
            suffix="nonzero-wal-barrier",
            mode="absence",
            pin_wal_reader=True,
        )
        result = outcome["result"]
        self.assertEqual("HOLD", result["phase"], result)
        self.assertEqual("PARK_ADOPTION_CHECKPOINT_NOT_ZERO", result["error"])
        self.assertEqual([], outcome["requests"])
        self.assertEqual(0, outcome["gh_invocations"])
        self.assertEqual(outcome["before"], outcome["after"])
        self.assertEqual([], result["park_adoption"]["events"])

    def test_actual_codex_runner_profile_nested_hook_controller_chain(self) -> None:
        if os.environ.get(ACTUAL_CODEX_TEST_ENV) != "1":
            self.skipTest(f"set {ACTUAL_CODEX_TEST_ENV}=1 for the native Codex gate")
        if os.environ.get(ACTUAL_CODEX_IN_NAMESPACE_ENV) != "1":
            self._run_actual_codex_test_in_namespace(
                test_method=self._testMethodName,
                expected_gh_invocations=8,
            )
            return

        self._register_actual_repository_observation()
        self.assertFalse(Path(self.delivery_worktree).exists())
        message_id = self._enqueue_park("actual-codex")
        request_sha256 = digest_json(self.payload)
        installed = Path(os.environ[ACTUAL_CODEX_FIXTURE_ROOT_ENV]) / "installed"
        profile = ROOT / "references" / "twinfinity-planner-v3.config.toml"
        (installed / profile.name).write_bytes(profile.read_bytes())
        command = _park_controller_command()
        server, server_thread, requests = self._actual_codex_responses_server(command)
        port = server.server_address[1]
        (installed / "config.toml").write_text(
            f'''model = "gpt-5.6-sol"
model_provider = "local-park"
check_for_update_on_startup = false

[model_providers.local-park]
name = "Issue 144 local PARK proof"
base_url = "http://127.0.0.1:{port}/v1"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
stream_idle_timeout_ms = 5000
''',
            encoding="utf-8",
        )
        unit = stable_systemd_unit("planner", "message", str(message_id))
        invocation_id = "9" * 32
        evidence = SystemdUnitEvidence(
            unit=unit,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            invocation_id=invocation_id,
            control_group=(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit
            ),
            result="success",
        )
        transitions: list[dict] = []
        contender: dict[str, float] = {}
        contender_errors: list[str] = []
        contender_attempting = threading.Event()
        contender_thread: threading.Thread | None = None
        real_release_prompt = ParkCapabilityBroker.release_prompt

        def traced_transition(connection, **kwargs):
            transitioned = transition_attempt(connection, **kwargs)
            transitions.append(
                {
                    "state": kwargs["new_state"],
                    "monotonic": time.monotonic(),
                    "version": transitioned["version"],
                }
            )
            return transitioned

        def contend_for_writer() -> None:
            connection = sqlite3.connect(self.store.path, timeout=15)
            try:
                contender_attempting.set()
                connection.execute("BEGIN IMMEDIATE")
                contender["acquired"] = time.monotonic()
                connection.execute("ROLLBACK")
            except sqlite3.Error as exc:
                contender_errors.append(str(exc))
            finally:
                connection.close()

        def release_with_contender(broker, stream, prompt):
            nonlocal contender_thread
            real_release_prompt(broker, stream, prompt)
            contender["started"] = time.monotonic()
            contender_thread = threading.Thread(
                target=contend_for_writer,
                name="issue-144-park-writer-contender",
                daemon=True,
            )
            contender_thread.start()
            if not contender_attempting.wait(1):
                raise AssertionError("writer contender did not start")

        try:
            with (
                mock.patch.object(
                    ParkCapabilityBroker,
                    "release_prompt",
                    new=release_with_contender,
                ),
                mock.patch.dict(
                    os.environ,
                    {
                        "CODEX_HOME": os.fspath(installed),
                        "NO_PROXY": "127.0.0.1,localhost",
                    },
                ),
            ):
                result = execute_role(
                    self.store.connection,
                    config_path=(
                        ROOT / "references" / "twinfinity-executor-registry.toml"
                    ),
                    role="planner",
                    endpoint_id=PLANNER_ENDPOINT,
                    target_kind="message",
                    target_key=str(message_id),
                    prompt="Execute only the exact bound PARK controller.",
                    systemd_invocation_id=invocation_id,
                    systemd_evidence=evidence,
                    transitioner=traced_transition,
                    heartbeat_seconds=1,
                )
        finally:
            if contender_thread is not None:
                contender_thread.join(timeout=16)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

        self.assertEqual("PASS", result["phase"], result)
        self.assertEqual("COMPLETE", result["state"])
        self.assertEqual("ADOPTED", result["park_adoption"]["state"])
        self.assertEqual(
            [
                "CAPABILITY_ARMED",
                "PROMPT_RELEASED",
                "NESTED_BASH_PRETOOLUSE",
                "CONTROLLER_CONSUMED",
                "CONTROLLER_ADOPTED",
            ],
            [event["kind"] for event in result["park_adoption"]["events"]],
        )
        self.assertEqual(3, len(requests), requests)
        self.assertEqual(1, sum(record["guardian"] for record in requests))
        self.assertEqual(1, sum(record["custom_output"] for record in requests))
        self.assertTrue(all(b"TWINFINITY_EXECUTOR_TOKEN" not in record["raw"] for record in requests))
        adopted_at = next(
            event["monotonic"]
            for event in result["park_adoption"]["events"]
            if event["kind"] == "CONTROLLER_ADOPTED"
        )
        prompt_released_at = next(
            event["monotonic"]
            for event in result["park_adoption"]["events"]
            if event["kind"] == "PROMPT_RELEASED"
        )
        running = [row for row in transitions if row["state"] == "RUNNING"]
        self.assertEqual(3, len(running), transitions)
        self.assertEqual(
            [],
            [
                row
                for row in running
                if prompt_released_at < row["monotonic"] < adopted_at
            ],
            transitions,
        )
        self.assertGreaterEqual(running[-1]["monotonic"], adopted_at)
        self.assertEqual([], contender_errors)
        self.assertLessEqual(contender["started"], adopted_at)
        self.assertGreaterEqual(contender["acquired"], adopted_at)
        self.assertEqual(
            "COMPLETE",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()[0],
        )

    def _replace_graph(self, source_sha256: str, *, expected_version: int, now: str) -> None:
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN_SHA,
                "expected_current_version": expected_version,
                "scope_milestones": [{"title": "Fixture", "rank": 1}],
                "excluded_issues": [],
                "nodes": [
                    {
                        "node_key": f"issue:{ISSUE}",
                        "issue_number": ISSUE,
                        "role": "DELIVERY",
                        "root_kind": "STANDALONE",
                        "root_reason": "Bounded no-delivery PARK fixture",
                        "lane_key": "development",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": 1,
                        "estimate_units": 1,
                        "development_units": 1,
                        "shared_units": 1,
                        "sre_units": 0,
                        "source_payload_sha256": source_sha256,
                        "ready_at": now,
                    }
                ],
                "relations": [],
            },
            now=now,
        )

    def _run_attempt(
        self,
        *,
        role: str,
        endpoint_id: str,
        target_kind: str,
        target_key: str,
        start: str,
        process_id: int,
        complete: bool,
        lineage: AttemptLineage | None = None,
    ) -> tuple[dict, str]:
        reserved, token = reserve_attempt(
            self.store.connection,
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            now=start,
            precondition=(
                (lambda _connection: lineage)
                if lineage is not None
                else lambda connection: attempt_lineage_for_target(
                    connection, target_kind, target_key
                )
            ),
        )
        unit = stable_systemd_unit(role, target_kind, target_key)
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=hashlib.md5(
                reserved["attempt_id"].encode("utf-8"), usedforsecurity=False
            ).hexdigest(),
            systemd_control_group=f"/user.slice/{unit}",
            now=start,
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=process_id,
            now=start,
        )
        if complete:
            transition_attempt(
                self.store.connection,
                attempt_id=reserved["attempt_id"],
                token=token,
                expected_version=running["version"],
                new_state="COMPLETE",
                exit_code=0,
                now=start,
            )
        return dict(reserved), token

    def _link_control_outbox_to_approval_decision(self) -> None:
        proposal = "1" * 64
        self.store.connection.execute(
            "INSERT INTO approval_proposals(proposal_sha256,semantic_sha256,"
            "decision_key,repository,owning_issue,source_snapshot_sha256,"
            "source_updated_at,proposal_generation,requester_session_id,"
            "recipient_session_id,workstream,boundary,priority,urgency,"
            "supersedes_sha256,packet_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                proposal,
                "2" * 64,
                "issue-272-control",
                REPOSITORY,
                ISSUE,
                self.bound_sha,
                "2026-08-26T20:00:01Z",
                1,
                DEVELOPMENT_ENDPOINT,
                PLANNER_ENDPOINT,
                "RECOVERY_CONTROL",
                "SOURCE_EQUIVALENCE",
                "HIGH",
                "NOW",
                None,
                "{}",
                "2026-08-26T20:00:09Z",
            ),
        )
        self.store.connection.execute(
            "INSERT INTO approval_user_events(user_event_source,user_event_id,"
            "user_input_sha256,planner_session_id,created_at) VALUES (?,?,?,?,?)",
            (
                "CODEX_DIRECT_USER_TURN",
                "planner-turn:272",
                "3" * 64,
                PLANNER_ENDPOINT,
                "2026-08-26T20:00:09Z",
            ),
        )
        self.store.connection.execute(
            "INSERT INTO approval_decisions(proposal_sha256,decision_sha256,"
            "decision,selected_option_id,recipient_set_sha256,execution_scope_sha256,"
            "decision_note,user_input_sha256,user_event_source,user_event_id,"
            "planner_session_id,owner_outbox_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                proposal,
                "4" * 64,
                "APPROVE",
                "APPROVE",
                "5" * 64,
                "6" * 64,
                "Exact control decision",
                "3" * 64,
                "CODEX_DIRECT_USER_TURN",
                "planner-turn:272",
                PLANNER_ENDPOINT,
                self.control_outbox_id,
                "2026-08-26T20:00:09Z",
            ),
        )
        self.store.connection.commit()

    def _register_preservation_artifact(
        self,
        *,
        dirty_bytes: bytes,
        preservation_attempt_id: str | None = None,
    ) -> dict:
        preservation_attempt_id = (
            self.preservation_attempt_id
            if preservation_attempt_id is None
            else preservation_attempt_id
        )
        manifest = {
            "schema": CLAIMED_NO_DELIVERY_PRESERVATION_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": GENERATION,
            "lease_manifest_sha256": self.lease,
            "dirty_paths": ["frontend/src/issue-272.ts"],
            "dirty_bytes_base64": base64.b64encode(dirty_bytes).decode("ascii"),
            "dirty_bytes_sha256": hashlib.sha256(dirty_bytes).hexdigest(),
            "preserved_by_endpoint_id": DEVELOPMENT_ENDPOINT,
            "preservation_attempt_id": preservation_attempt_id,
            "cleanup_receipt_sha256": self.cleanup_receipt_sha256,
            "preserved_at": "2026-08-26T20:00:22Z",
        }
        path = self.store.path.parent / f"preservation-{digest_json(manifest)[:12]}.json"
        path.write_text(canonical_json(manifest), encoding="utf-8")
        return self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": GENERATION,
                    "path": str(path),
                    "retention_class": "RETAINED",
                }
            ],
            now="2026-08-26T20:00:22Z",
        )[0]

    def _park_payload(
        self,
        artifact: dict,
        *,
        preservation_attempt_id: str | None = None,
    ) -> dict:
        preservation_attempt_id = (
            self.preservation_attempt_id
            if preservation_attempt_id is None
            else preservation_attempt_id
        )
        admission = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?",
            (self.admission_message_id,),
        ).fetchone()
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE watch_key=?",
            (self.watch_key,),
        ).fetchone()
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        ).fetchone()
        graph = self.store.connection.execute(
            "SELECT c.version,c.observed_main_sha,r.graph_sha256 "
            "FROM portfolio_graph_current c JOIN portfolio_graph_revisions r "
            "ON r.repository=c.repository AND r.version=c.version "
            "WHERE c.repository=?",
            (REPOSITORY,),
        ).fetchone()
        policy = self.store.connection.execute(
            "SELECT p.* FROM coordination_capacity_current c "
            "JOIN coordination_capacity_policies p "
            "ON p.repository=c.repository AND p.version=c.version "
            "WHERE c.repository=?",
            (REPOSITORY,),
        ).fetchone()
        evidence = {
            "schema": CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA,
            "disposition": "PARK",
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": GENERATION,
            "item_version": int(item["version"]),
            "admission_message_id": self.admission_message_id,
            "admission_payload_sha256": admission["payload_sha256"],
            "admission_updated_at": admission["updated_at"],
            "watch_key": self.watch_key,
            "watch_updated_at": watch["updated_at"],
            "claim_attempt_id": self.claim_attempt_id,
            "preservation_attempt_id": preservation_attempt_id,
            "endpoint_id": DEVELOPMENT_ENDPOINT,
            "lease_manifest_sha256": self.lease,
            "bound_source_sha256": self.bound_sha,
            "current_source_sha256": self.current_sha,
            "source_equivalence_receipt_sha256": self.equivalence["receipt_sha256"],
            "stable_source_sha256": self.equivalence["stable_source_sha256"],
            "capacity": {
                "development_units": int(item["development_units"]),
                "shared_units": int(item["shared_units"]),
                "sre_units": int(item["sre_units"]),
            },
            "retained_artifact_key": artifact["artifact_key"],
            "retained_artifact_sha256": artifact["content_sha256"],
            "cleanup_receipt_sha256": self.cleanup_receipt_sha256,
            "repository_observation_sha256": self.repository_observation_sha256,
            "graph_version": int(graph["version"]),
            "graph_sha256": graph["graph_sha256"],
            "graph_main_sha": graph["observed_main_sha"],
            "capacity_policy_version": int(policy["version"]),
            "capacity_policy_sha256": digest_json(dict(policy)),
            "prepared_at": "2026-08-26T20:00:23Z",
        }
        return {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": ISSUE,
                "payload_sha256": self.bound_sha,
            },
            "notice_kind": "planning_request",
            "mutation_authority": False,
            "subject": "Issue 272 claimed-no-delivery PARK",
            "summary": "Preserve exact dirty bytes, observe accountable cleanup, and reprepare.",
            "evidence": evidence,
            "requested_evidence": ["Exact atomic PARK receipt"],
            "next_observation": "Observe the fresh PREPARED generation.",
        }

    def _enqueue_park(self, suffix: str = "first") -> int:
        return self.store.enqueue_claimed_no_delivery_park_message(
            idempotency_key=f"issue-272-park-{suffix}",
            recipient_session_id=PLANNER_ENDPOINT,
            payload=copy.deepcopy(self.payload),
            now="2026-08-26T20:00:24Z",
        )

    def _running_planner_attempt(self, message_id: int, process_id: int) -> tuple[dict, str]:
        return self._run_attempt(
            role="planner",
            endpoint_id=PLANNER_ENDPOINT,
            target_kind="message",
            target_key=str(message_id),
            start="2026-08-26T20:00:25Z",
            process_id=process_id,
            complete=False,
        )

    def _assert_preservation_attempt_denied(
        self, attempt_id: str, *, suffix: str
    ) -> None:
        artifact = self._register_preservation_artifact(
            dirty_bytes=(
                b"diff --git a/frontend/src/issue-272.ts "
                b"b/frontend/src/issue-272.ts\n+substituted preservation attempt "
                + suffix.encode("utf-8")
                + b"\n"
            ),
            preservation_attempt_id=attempt_id,
        )
        payload = self._park_payload(
            artifact,
            preservation_attempt_id=attempt_id,
        )
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(
            CoordinationError, "PARK_ATTEMPT_LIVENESS_CONFLICT"
        ):
            self.store.enqueue_claimed_no_delivery_park_message(
                idempotency_key=f"issue-272-park-preservation-{suffix}",
                recipient_session_id=PLANNER_ENDPOINT,
                payload=payload,
                now="2026-08-26T20:00:24Z",
            )
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def _durable_coordination_snapshot(self) -> dict[str, object]:
        database = list(self.store.connection.iterdump())
        files: dict[str, tuple[int, int, int, str]] = {}
        for path in sorted(self.store.path.parent.iterdir()):
            if not path.is_file():
                continue
            metadata = path.stat()
            files[path.name] = (
                metadata.st_mode & 0o777,
                metadata.st_size,
                metadata.st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        return {
            "database": database,
            "files": files,
        }

    def test_dedicated_reserved_enqueue_uses_exact_source_equivalence(self) -> None:
        with self.assertRaisesRegex(
            CoordinationError, "CLAIMED_NO_DELIVERY_PARK_HANDLER_REQUIRED"
        ):
            self.store.enqueue_message(
                idempotency_key="generic-park-is-forbidden",
                recipient_session_id=PLANNER_ENDPOINT,
                topic="coordination.notice",
                payload=copy.deepcopy(self.payload),
                now="2026-08-26T20:00:24Z",
            )
        message_id = self._enqueue_park()
        self.assertGreater(message_id, self.admission_message_id)
        row = self.store.connection.execute(
            "SELECT state,payload_sha256 FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual("PREPARED", row["state"])
        self.assertEqual(digest_json(self.payload), row["payload_sha256"])
        self.assertNotEqual(self.bound_sha, self.current_sha)

    def test_generic_enqueue_rejects_reserved_park_before_message_or_event_write(self) -> None:
        generic_payload = copy.deepcopy(self.payload)
        generic_payload["source"]["payload_sha256"] = self.current_sha
        generic_payload["evidence"]["bound_source_sha256"] = self.current_sha
        before = list(self.store.connection.iterdump())

        with self.assertRaisesRegex(
            CoordinationError, "^CLAIMED_NO_DELIVERY_PARK_HANDLER_REQUIRED$"
        ):
            self.store.enqueue_message(
                idempotency_key="generic-park-reserved-handler-denied",
                recipient_session_id=PLANNER_ENDPOINT,
                topic="coordination.notice",
                payload=generic_payload,
                now="2026-08-26T20:00:24Z",
            )

        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_preservation_attempt_target_substitution_is_denied_without_mutation(self) -> None:
        substituted, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="message",
            target_key=str(self.admission_message_id),
            start="2026-08-26T20:00:23Z",
            process_id=274,
            complete=True,
            lineage=AttemptLineage(REPOSITORY, ISSUE, GENERATION, self.lease),
        )
        self._assert_preservation_attempt_denied(
            substituted["attempt_id"], suffix="target-kind"
        )

    def test_preservation_attempt_wrong_target_key_is_denied_without_mutation(self) -> None:
        substituted, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=f"{self.watch_key}:substitute",
            start="2026-08-26T20:00:23Z",
            process_id=275,
            complete=True,
            lineage=AttemptLineage(REPOSITORY, ISSUE, GENERATION, self.lease),
        )
        self._assert_preservation_attempt_denied(
            substituted["attempt_id"], suffix="target-key"
        )

    def test_preservation_attempt_wrong_issue_is_denied_without_mutation(self) -> None:
        substituted, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            start="2026-08-26T20:00:23Z",
            process_id=276,
            complete=True,
            lineage=AttemptLineage(REPOSITORY, ISSUE + 1, GENERATION, self.lease),
        )
        self._assert_preservation_attempt_denied(
            substituted["attempt_id"], suffix="issue"
        )

    def test_preservation_attempt_wrong_generation_is_denied_without_mutation(self) -> None:
        substituted, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            start="2026-08-26T20:00:23Z",
            process_id=277,
            complete=True,
            lineage=AttemptLineage(REPOSITORY, ISSUE, GENERATION + 1, self.lease),
        )
        self._assert_preservation_attempt_denied(
            substituted["attempt_id"], suffix="generation"
        )

    def test_preservation_attempt_wrong_lease_is_denied_without_mutation(self) -> None:
        substituted, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            start="2026-08-26T20:00:23Z",
            process_id=278,
            complete=True,
            lineage=AttemptLineage(REPOSITORY, ISSUE, GENERATION, "0" * 64),
        )
        self._assert_preservation_attempt_denied(
            substituted["attempt_id"], suffix="lease"
        )

    def test_preservation_attempt_nonterminal_state_is_denied_without_mutation(self) -> None:
        substituted, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            start="2026-08-26T20:00:23Z",
            process_id=279,
            complete=False,
            lineage=AttemptLineage(REPOSITORY, ISSUE, GENERATION, self.lease),
        )
        self._assert_preservation_attempt_denied(
            substituted["attempt_id"], suffix="nonterminal"
        )

    def test_preservation_attempt_noncurrent_endpoint_is_denied_without_mutation(self) -> None:
        substituted, _token = self._run_attempt(
            role="development",
            endpoint_id=DEVELOPMENT_ENDPOINT,
            target_kind="terminal_watch",
            target_key=self.watch_key,
            start="2026-08-26T20:00:23Z",
            process_id=280,
            complete=True,
            lineage=AttemptLineage(REPOSITORY, ISSUE, GENERATION, self.lease),
        )
        self.store.connection.execute(
            "INSERT INTO executor_role_endpoints(endpoint_id,role,version,"
            "executor_profile,codex_profile,config_sha256,config_json,"
            "command_json,created_at) SELECT ?,role,5,executor_profile,"
            "codex_profile,config_sha256,config_json,command_json,created_at "
            "FROM executor_role_endpoints WHERE endpoint_id=?",
            ("role.development.v5", DEVELOPMENT_ENDPOINT),
        )
        self.store.connection.execute(
            "UPDATE executor_role_endpoint_current SET endpoint_id=?,"
            "pointer_version=pointer_version+1,updated_at=? WHERE role='development'",
            ("role.development.v5", "2026-08-26T20:00:23Z"),
        )
        self.store.connection.commit()
        self._assert_preservation_attempt_denied(
            substituted["attempt_id"], suffix="endpoint"
        )

    def test_supervisor_reserved_park_validation_denials_open_no_write_transaction(self) -> None:
        invalid_envelope = copy.deepcopy(self.payload)
        invalid_envelope["evidence"].pop("prepared_at")
        source_mismatch = copy.deepcopy(self.payload)
        source_mismatch["source"]["repository"] = "twinfinityai/substitute"
        invalid_repository = copy.deepcopy(self.payload)
        invalid_repository["source"]["repository"] = "invalid repository"
        invalid_repository["evidence"]["repository"] = "invalid repository"
        notice_schema = copy.deepcopy(self.payload)
        notice_schema["subject"] = ""
        mutating_notice = copy.deepcopy(self.payload)
        mutating_notice["mutation_authority"] = True
        forbidden_notice = copy.deepcopy(self.payload)
        forbidden_notice["action"] = "forbidden"
        reserved_resource = copy.deepcopy(self.payload)
        reserved_resource["subject"] = "x" * (513 * 1024)
        cases = (
            (
                "park-envelope",
                canonical_json(invalid_envelope),
                digest_json(invalid_envelope),
                "PARK_ENVELOPE_INVALID",
            ),
            (
                "source-binding",
                canonical_json(source_mismatch),
                digest_json(source_mismatch),
                "PARK_SOURCE_BINDING_INVALID",
            ),
            (
                "invalid-repository",
                canonical_json(invalid_repository),
                digest_json(invalid_repository),
                "INVALID_REPOSITORY",
            ),
            (
                "notice-schema",
                canonical_json(notice_schema),
                digest_json(notice_schema),
                "NOTICE_SCHEMA_INVALID",
            ),
            (
                "notice-mutation-authority",
                canonical_json(mutating_notice),
                digest_json(mutating_notice),
                "NOTICE_MUST_BE_NON_MUTATING",
            ),
            (
                "notice-forbidden-field",
                canonical_json(forbidden_notice),
                digest_json(forbidden_notice),
                "NOTICE_MUTATION_FIELDS_FORBIDDEN",
            ),
            (
                "payload-binding",
                canonical_json(self.payload),
                "0" * 64,
                "MESSAGE_PAYLOAD_MISMATCH",
            ),
            (
                "reserved-malformed",
                '{"evidence":{"schema":"'
                + CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
                + '","disposition":"PARK"}',
                "0" * 64,
                "COORDINATION_ENVELOPE_MALFORMED",
            ),
            (
                "reserved-parser",
                '{"evidence":{"schema":"'
                + CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
                + '","schema":"'
                + CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
                + '","disposition":"PARK"}}',
                "0" * 64,
                "COORDINATION_ENVELOPE_DUPLICATE_KEY",
            ),
            (
                "reserved-resource",
                canonical_json(reserved_resource),
                "0" * 64,
                "COORDINATION_ENVELOPE_RESOURCE_LIMIT",
            ),
        )
        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda *_arguments: self.fail("launch must not run"),
            terminal_watch_launcher=lambda *_arguments: self.fail(
                "terminal-watch launch must not run"
            ),
            process_checker=lambda *_arguments: False,
        )
        for index, (name, raw, payload_sha256, expected_error) in enumerate(cases):
            with self.subTest(name=name):
                cursor = self.store.connection.execute(
                    "INSERT INTO coordination_messages(idempotency_key,"
                    "recipient_session_id,topic,payload_sha256,payload_json,state,"
                    "created_at,updated_at) VALUES (?,?,'coordination.notice',?,?,"
                    "'PREPARED',?,?)",
                    (
                        f"reserved-supervisor-{index}",
                        PLANNER_ENDPOINT,
                        payload_sha256,
                        raw,
                        "2026-08-26T20:00:24Z",
                        "2026-08-26T20:00:24Z",
                    ),
                )
                message_id = int(cursor.lastrowid)
                self.store.connection.commit()
                row = self.store.connection.execute(
                    "SELECT * FROM coordination_messages WHERE id=?",
                    (message_id,),
                ).fetchone()
                wake_key = f"message:{message_id}:prepared"
                self.store.connection.execute(
                    "INSERT INTO coordination_wakes(wake_key,message_id,"
                    "recipient_session_id,message_payload_sha256,"
                    "target_progress_sha256,state,attempts,process_id,"
                    "last_attempt_at,updated_at,last_error) VALUES (?,?,?,?,?,"
                    "'INFLIGHT',1,NULL,?,?,NULL)",
                    (
                        wake_key,
                        message_id,
                        PLANNER_ENDPOINT,
                        payload_sha256,
                        "1" * 64,
                        "2026-08-26T20:00:24Z",
                        "2026-08-26T20:00:24Z",
                    ),
                )
                self.store.connection.commit()
                error = supervisor._message_contract_error(row)
                self.assertEqual(expected_error, error)
                before = self._durable_coordination_snapshot()
                with (
                    mock.patch.object(
                        self.store,
                        "transaction",
                        side_effect=AssertionError("write transaction must not open"),
                    ),
                    mock.patch.object(
                        self.store,
                        "_event",
                        side_effect=AssertionError("event write must not run"),
                    ),
                ):
                    supervisor._hold_stale_message(
                        row, error, "2026-08-26T20:00:25Z"
                    )
                    self.assertEqual(
                        (None, False),
                        supervisor._reserve_wake(
                            row, "2026-08-26T20:00:25Z"
                        ),
                    )
                    supervisor._record_launch_failure(
                        wake_key, "2026-08-26T20:00:25Z"
                    )
                self.assertEqual(before, self._durable_coordination_snapshot())

    def test_strict_envelope_matrix_denies_before_every_claim_side_effect(self) -> None:
        escaped_payload = {
            "evidence": {
                "schema": CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA,
                "disposition": "PARK",
            }
        }
        cases = {
            "duplicate": (
                '{"x":1,"x":2}',
                "COORDINATION_ENVELOPE_DUPLICATE_KEY",
                "0" * 64,
            ),
            "escaped_reserved": (
                '{"evidence":{"sch\\u0065ma":"'
                + CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
                + '","disposition":"PARK"}}',
                "CLAIMED_NO_DELIVERY_PARK_HANDLER_REQUIRED",
                digest_json(escaped_payload),
            ),
            "literal_escaped_conflict": (
                '{"evidence":{"schema":"'
                + CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
                + '","sch\\u0065ma":"other"}}',
                "COORDINATION_ENVELOPE_DUPLICATE_KEY",
                "0" * 64,
            ),
            "nonfinite": (
                '{"value":NaN}',
                "COORDINATION_ENVELOPE_NONFINITE",
                "0" * 64,
            ),
            "conflicting_marker": (
                '{"evidence":{"schema":"'
                + CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
                + '","disposition":"COMPLETE"}}',
                "COORDINATION_ENVELOPE_AMBIGUOUS_RESERVED_INTENT",
                "0" * 64,
            ),
            "malformed": (
                '{"value":',
                "COORDINATION_ENVELOPE_MALFORMED",
                "0" * 64,
            ),
            "invalid_utf8": (
                b'{"value":"\xff"}',
                "COORDINATION_ENVELOPE_MALFORMED",
                "0" * 64,
            ),
            "non_object": (
                "[]",
                "COORDINATION_ENVELOPE_NON_OBJECT",
                "0" * 64,
            ),
            "depth": (
                '{"value":' + "[" * 50 + "0" + "]" * 50 + "}",
                "COORDINATION_ENVELOPE_DEPTH_EXCEEDED",
                "0" * 64,
            ),
            "node_budget": (
                '{"value":[' + ",".join("0" for _ in range(8200)) + "]}",
                "COORDINATION_ENVELOPE_RESOURCE_LIMIT",
                "0" * 64,
            ),
            "byte_budget": (
                '{"value":"' + "a" * (1024 * 1024) + '"}',
                "COORDINATION_ENVELOPE_RESOURCE_LIMIT",
                "0" * 64,
            ),
        }
        for index, (name, (raw, error, payload_sha256)) in enumerate(
            cases.items(), start=1
        ):
            with self.subTest(name=name):
                cursor = self.store.connection.execute(
                    "INSERT INTO coordination_messages(idempotency_key,"
                    "recipient_session_id,topic,payload_sha256,payload_json,state,"
                    "created_at,updated_at) VALUES (?,?, 'coordination.notice',?,?,"
                    "'PREPARED',?,?)",
                    (
                        f"strict-envelope-{index}",
                        PLANNER_ENDPOINT,
                        payload_sha256,
                        raw,
                        "2026-08-26T20:00:24Z",
                        "2026-08-26T20:00:24Z",
                    ),
                )
                message_id = int(cursor.lastrowid)
                self.store.connection.commit()
                before = list(self.store.connection.iterdump())
                with self.assertRaisesRegex(CoordinationError, error):
                    self.store.claim_message(
                        message_id,
                        PLANNER_ENDPOINT,
                        "2026-08-26T20:00:25Z",
                    )
                self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_planner_v3_keeps_the_ordinary_non_park_notice_path(self) -> None:
        message_id = self.store.enqueue_message(
            idempotency_key="planner-v3-ordinary-notice",
            recipient_session_id=PLANNER_ENDPOINT,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": ISSUE,
                    "payload_sha256": self.current_sha,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Ordinary Planner v3 notice",
                "summary": "Preserve the direct non-PARK execution path.",
                "evidence": {},
            },
            now="2026-08-26T20:00:24Z",
        )
        launch: dict[str, object] = {}

        class CompletingProcess:
            pid = 4321

            def poll(process_self):
                if not launch.get("completed"):
                    environment = launch["environment"]
                    self.store.claim_message(
                        message_id,
                        PLANNER_ENDPOINT,
                        "2026-08-26T20:00:25Z",
                        attempt_id=environment["TWINFINITY_EXECUTOR_ATTEMPT_ID"],
                        executor_token=environment["TWINFINITY_EXECUTOR_TOKEN"],
                    )
                    self.store.complete_message(
                        message_id,
                        PLANNER_ENDPOINT,
                        "2026-08-26T20:00:26Z",
                    )
                    launch["completed"] = True
                return 0

        def popen(command, **kwargs):
            launch["command"] = command
            launch["environment"] = kwargs["env"]
            launch["cwd"] = kwargs["cwd"]
            launch["stdin"] = kwargs["stdin"]
            return CompletingProcess()

        unit = stable_systemd_unit("planner", "message", str(message_id))
        invocation_id = "7" * 32
        with mock.patch.dict(
            os.environ,
            {"CODEX_HOME": os.fspath(Path(self.temp.name) / "installed")},
        ):
            result = execute_role(
                self.store.connection,
                config_path=(
                    ROOT / "references" / "twinfinity-executor-registry.toml"
                ),
                role="planner",
                endpoint_id=PLANNER_ENDPOINT,
                target_kind="message",
                target_key=str(message_id),
                prompt="Read the exact ordinary Planner notice.",
                systemd_invocation_id=invocation_id,
                systemd_evidence=SystemdUnitEvidence(
                    unit=unit,
                    load_state="loaded",
                    active_state="active",
                    sub_state="running",
                    invocation_id=invocation_id,
                    control_group=f"/user.slice/{unit}",
                    result="success",
                ),
                popen=popen,
            )
        self.assertEqual("PASS", result["phase"])
        self.assertEqual("COMPLETE", result["state"])
        self.assertIn("TWINFINITY_EXECUTOR_TOKEN", launch["environment"])
        self.assertNotIn(PARK_CAPABILITY_SOCKET_ENV, launch["environment"])
        self.assertIsNone(launch["cwd"])
        self.assertNotEqual("-", launch["command"][-1])

    def test_control_decision_comment_is_not_delivery_but_real_outbox_is(self) -> None:
        self.assertGreater(self._enqueue_park("control-only"), 0)
        self.store.enqueue_comment(
            idempotency_key="issue-272-real-delivery-publication",
            repository=REPOSITORY,
            object_kind="issue",
            object_number=ISSUE,
            expected_source_sha256=self.current_sha,
            body="Delivery receipt",
            now="2026-08-26T20:00:25Z",
        )
        with self.assertRaisesRegex(CoordinationError, "PARK_DELIVERY_OUTBOX_PRESENT"):
            self._enqueue_park("delivery-present")

    def test_retained_artifact_must_contain_actual_dirty_bytes(self) -> None:
        invalid_manifest = {
            "schema": CLAIMED_NO_DELIVERY_PRESERVATION_SCHEMA,
            "repository": REPOSITORY,
            "issue_number": ISSUE,
            "generation": GENERATION,
            "lease_manifest_sha256": self.lease,
            "dirty_paths": ["frontend/src/issue-272.ts"],
            "dirty_bytes_base64": base64.b64encode(b"lease manifest only").decode("ascii"),
            "dirty_bytes_sha256": hashlib.sha256(
                b"lease manifest only"
            ).hexdigest(),
            "preserved_by_endpoint_id": DEVELOPMENT_ENDPOINT,
            "preservation_attempt_id": self.preservation_attempt_id,
            "cleanup_receipt_sha256": self.cleanup_receipt_sha256,
            "preserved_at": "2026-08-26T20:00:22Z",
        }
        path = self.store.path.parent / "invalid-preservation.json"
        path.write_text(canonical_json(invalid_manifest), encoding="utf-8")
        invalid_artifact = self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": ISSUE,
                    "generation": GENERATION,
                    "path": str(path),
                    "retention_class": "RETAINED",
                }
            ],
            now="2026-08-26T20:00:23Z",
        )[0]
        invalid_payload = copy.deepcopy(self.payload)
        invalid_payload["evidence"]["retained_artifact_key"] = invalid_artifact[
            "artifact_key"
        ]
        invalid_payload["evidence"]["retained_artifact_sha256"] = invalid_artifact[
            "content_sha256"
        ]
        with self.assertRaisesRegex(
            CoordinationError, "PARK_PRESERVATION_CONTENT_INVALID"
        ):
            self.store.enqueue_claimed_no_delivery_park_message(
                idempotency_key="issue-272-invalid-preservation",
                recipient_session_id=PLANNER_ENDPOINT,
                payload=invalid_payload,
                now="2026-08-26T20:00:24Z",
            )

    def test_atomic_park_commit_fresh_replay_and_single_release_event(self) -> None:
        message_id = self._enqueue_park()
        attempt, token = self._running_planner_attempt(message_id, 274)
        receipt = self.store.commit_claimed_no_delivery_park(
            message_id=message_id,
            session_id=PLANNER_ENDPOINT,
            attempt_id=attempt["attempt_id"],
            executor_token=token,
            expected_repository_observation_sha256=self.repository_observation_sha256,
            repository_observer=lambda: self.repository_observation_sha256,
            now="2026-08-26T20:00:26Z",
        )
        self.assertEqual("PARKED_NO_DELIVERY", receipt["disposition"])
        first_running = self.store.connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?",
            (attempt["attempt_id"],),
        ).fetchone()
        transition_attempt(
            self.store.connection,
            attempt_id=attempt["attempt_id"],
            token=token,
            expected_version=first_running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-26T20:00:27Z",
        )
        replay_message_id = self._enqueue_park("replay")
        replay_attempt, replay_token = self._running_planner_attempt(
            replay_message_id, 275
        )
        replay = self.store.commit_claimed_no_delivery_park(
            message_id=replay_message_id,
            session_id=PLANNER_ENDPOINT,
            attempt_id=replay_attempt["attempt_id"],
            executor_token=replay_token,
            expected_repository_observation_sha256=self.repository_observation_sha256,
            repository_observer=lambda: self.fail("replay must not reacquire provider state"),
            now="2026-08-26T20:00:28Z",
        )
        self.assertEqual(receipt, replay)
        item = self.store.connection.execute(
            "SELECT status,allocation_class,generation,version,"
            "accountable_session_id,lease_manifest_sha256,source_payload_sha256 "
            "FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, ISSUE),
        ).fetchone()
        self.assertEqual(
            ("PREPARED", "NONE", 1, 4, None, None, self.current_sha), tuple(item)
        )
        self.assertEqual(
            ("COMPLETE", "PARKED_NO_DELIVERY"),
            tuple(
                self.store.connection.execute(
                    "SELECT state,last_error FROM coordination_terminal_watches "
                    "WHERE watch_key=?",
                    (self.watch_key,),
                ).fetchone()
            ),
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_dirty_events WHERE repository=? "
                "AND issue_number=? AND release_source_sha256=?",
                (REPOSITORY, ISSUE, self.current_sha),
            ).fetchone()[0],
        )

    def test_park_commit_hands_one_parsed_envelope_object_to_claim(self) -> None:
        message_id = self._enqueue_park("single-parse")
        attempt, token = self._running_planner_attempt(message_id, 276)
        request_sha256 = digest_json(self.payload)
        parsed_requests = []
        claimed_envelopes = []
        real_parse = coordination.parse_coordination_envelope
        real_claim = self.store.claim_claimed_no_delivery_park_message_in_transaction

        def traced_parse(raw):
            parsed = real_parse(raw)
            if parsed.payload_sha256 == request_sha256:
                parsed_requests.append(parsed)
            return parsed

        def traced_claim(*args, **kwargs):
            claimed_envelopes.append(kwargs.get("_parsed_envelope"))
            self.assertEqual(1, len(parsed_requests))
            self.assertIs(parsed_requests[0], kwargs.get("_parsed_envelope"))
            return real_claim(*args, **kwargs)

        with (
            mock.patch.object(
                coordination,
                "parse_coordination_envelope",
                side_effect=traced_parse,
            ),
            mock.patch.object(
                self.store,
                "claim_claimed_no_delivery_park_message_in_transaction",
                side_effect=traced_claim,
            ),
        ):
            self.store.commit_claimed_no_delivery_park(
                message_id=message_id,
                session_id=PLANNER_ENDPOINT,
                attempt_id=attempt["attempt_id"],
                executor_token=token,
                expected_repository_observation_sha256=(
                    self.repository_observation_sha256
                ),
                repository_observer=lambda: self.repository_observation_sha256,
                now="2026-08-26T20:00:26Z",
            )
        self.assertEqual(1, len(claimed_envelopes))

    def test_failpoint_rolls_back_claim_item_watch_and_events(self) -> None:
        message_id = self._enqueue_park()
        attempt, token = self._running_planner_attempt(message_id, 276)
        before = list(self.store.connection.iterdump())

        def failpoint(name: str) -> None:
            if name == "park.after_item":
                raise RuntimeError("synthetic crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic crash"):
            self.store.commit_claimed_no_delivery_park(
                message_id=message_id,
                session_id=PLANNER_ENDPOINT,
                attempt_id=attempt["attempt_id"],
                executor_token=token,
                expected_repository_observation_sha256=self.repository_observation_sha256,
                repository_observer=lambda: self.repository_observation_sha256,
                now="2026-08-26T20:00:26Z",
                _test_failpoint=failpoint,
            )
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def _run_prepare_cli(
        self,
        *,
        idempotency_key: str,
        recipient: str,
        raw_payload: bytes,
        expected_payload_sha256: str,
        suffix: str,
    ) -> tuple[int, dict[str, object]]:
        payload_file = self.store.path.parent / f"park-prepare-{suffix}.json"
        payload_file.write_bytes(raw_payload)
        output = io.StringIO()
        with (
            mock.patch.object(coordination, "DEFAULT_DATABASE", self.store.path),
            mock.patch.object(
                sys,
                "argv",
                [
                    "coordination_store.py",
                    "prepare-claimed-no-delivery-park",
                    "--idempotency-key",
                    idempotency_key,
                    "--planner-session-id",
                    recipient,
                    "--payload-file",
                    str(payload_file),
                    "--expected-payload-sha256",
                    expected_payload_sha256,
                ],
            ),
            contextlib.redirect_stdout(output),
        ):
            result = coordination.main()
        return result, json.loads(output.getvalue())

    def _logical_tables_except_park_receipt(self) -> dict[str, list[tuple]]:
        excluded = {
            "coordination_events",
            "coordination_messages",
            "sqlite_sequence",
        }
        names = self.store.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {
            str(row[0]): [
                tuple(value)
                for value in self.store.connection.execute(
                    f'SELECT * FROM "{row[0]}"'
                ).fetchall()
            ]
            for row in names
            if row[0] not in excluded
        }

    def test_prepare_cli_is_strict_single_parse_dedicated_and_idempotent(self) -> None:
        request_sha256 = digest_json(self.payload)
        raw_payload = json.dumps(self.payload, indent=2).encode("utf-8")
        before_protected = self._logical_tables_except_park_receipt()
        before_messages = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_messages"
        ).fetchone()[0]
        before_events = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events"
        ).fetchone()[0]
        parsed_requests = []
        dispatched_envelopes = []
        real_parse = coordination.parse_coordination_envelope
        real_enqueue = CoordinationStore.enqueue_claimed_no_delivery_park_message

        def traced_parse(raw):
            parsed = real_parse(raw)
            if parsed.payload_sha256 == request_sha256:
                parsed_requests.append(parsed)
            return parsed

        def traced_enqueue(store, *args, **kwargs):
            envelope = kwargs.get("_parsed_envelope")
            dispatched_envelopes.append(envelope)
            self.assertIs(kwargs.get("payload"), envelope.payload)
            return real_enqueue(store, *args, **kwargs)

        with (
            mock.patch.object(
                coordination,
                "parse_coordination_envelope",
                side_effect=traced_parse,
            ),
            mock.patch.object(
                CoordinationStore,
                "enqueue_claimed_no_delivery_park_message",
                autospec=True,
                side_effect=traced_enqueue,
            ),
            mock.patch.object(
                CoordinationStore,
                "enqueue_message",
                side_effect=AssertionError("generic enqueue must not run"),
            ),
        ):
            result, prepared = self._run_prepare_cli(
                idempotency_key="issue-272-park-cli",
                recipient=PLANNER_ENDPOINT,
                raw_payload=raw_payload,
                expected_payload_sha256=request_sha256,
                suffix="first",
            )
            self.assertEqual(0, result)
            self.assertEqual(
                {
                    "phase": "PREPARED",
                    "message_id": prepared["message_id"],
                    "payload_sha256": request_sha256,
                    "recipient_session_id": PLANNER_ENDPOINT,
                    "idempotency_key": "issue-272-park-cli",
                },
                prepared,
            )
            result, replay = self._run_prepare_cli(
                idempotency_key="issue-272-park-cli",
                recipient=PLANNER_ENDPOINT,
                raw_payload=raw_payload,
                expected_payload_sha256=request_sha256,
                suffix="replay",
            )
            self.assertEqual(0, result)
            self.assertEqual(prepared, replay)

        self.assertEqual(2, len(parsed_requests))
        self.assertEqual(2, len(dispatched_envelopes))
        self.assertIs(parsed_requests[0], dispatched_envelopes[0])
        self.assertIs(parsed_requests[1], dispatched_envelopes[1])
        self.assertEqual(before_protected, self._logical_tables_except_park_receipt())
        self.assertEqual(
            before_messages + 1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        self.assertEqual(
            before_events + 1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0],
        )
        event = self.store.connection.execute(
            "SELECT event_type,entity_key,payload_sha256 FROM coordination_events "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(
            (
                "CLAIMED_NO_DELIVERY_PARK_PREPARED",
                f'message:{prepared["message_id"]}',
                digest_json(
                    {
                        "request_sha256": request_sha256,
                        "repository": REPOSITORY,
                        "issue_number": ISSUE,
                    }
                ),
            ),
            tuple(event),
        )
        row = self.store.connection.execute(
            "SELECT recipient_session_id,topic,payload_sha256,payload_json,state "
            "FROM coordination_messages WHERE id=?",
            (prepared["message_id"],),
        ).fetchone()
        self.assertEqual(
            (
                PLANNER_ENDPOINT,
                "coordination.notice",
                request_sha256,
                canonical_json(self.payload),
                "PREPARED",
            ),
            tuple(row),
        )

        changed = copy.deepcopy(self.payload)
        changed["summary"] += " changed"
        before_conflict = list(self.store.connection.iterdump())
        with mock.patch.object(
            coordination,
            "CoordinationStore",
            side_effect=AssertionError("writable database must not open"),
        ):
            result, conflict = self._run_prepare_cli(
                idempotency_key="issue-272-park-cli",
                recipient=PLANNER_ENDPOINT,
                raw_payload=canonical_json(changed).encode("utf-8"),
                expected_payload_sha256=digest_json(changed),
                suffix="conflict",
            )
        self.assertEqual(1, result)
        self.assertEqual(
            {"phase": "HOLD", "error": "IDEMPOTENCY_CONFLICT"}, conflict
        )
        self.assertEqual(before_conflict, list(self.store.connection.iterdump()))

        before_recipient_conflict = list(self.store.connection.iterdump())
        with mock.patch.object(
            coordination,
            "CoordinationStore",
            side_effect=AssertionError("writable database must not open"),
        ):
            result, conflict = self._run_prepare_cli(
                idempotency_key="issue-272-park-cli",
                recipient=DEVELOPMENT_ENDPOINT,
                raw_payload=raw_payload,
                expected_payload_sha256=request_sha256,
                suffix="recipient-conflict",
            )
        self.assertEqual(1, result)
        self.assertEqual(
            {"phase": "HOLD", "error": "IDEMPOTENCY_CONFLICT"}, conflict
        )
        self.assertEqual(
            before_recipient_conflict, list(self.store.connection.iterdump())
        )

        for suffix, recipient, error in (
            ("historical", "role.planner.v2", "CURRENT_ROLE_ENDPOINT_REQUIRED"),
            (
                "alias",
                "01a017f9-4ce5-7110-9a1f-73b1c10f5625",
                "CURRENT_ROLE_ENDPOINT_REQUIRED",
            ),
            ("wrong-role", DEVELOPMENT_ENDPOINT, "PARK_PREPARER_INVALID"),
            ("substituted", "role.planner.v999", "CURRENT_ROLE_ENDPOINT_REQUIRED"),
        ):
            with self.subTest(recipient=recipient):
                before_identity = list(self.store.connection.iterdump())
                result, denial = self._run_prepare_cli(
                    idempotency_key=f"issue-272-park-cli-{suffix}",
                    recipient=recipient,
                    raw_payload=raw_payload,
                    expected_payload_sha256=request_sha256,
                    suffix=suffix,
                )
                self.assertEqual(1, result)
                self.assertEqual({"phase": "HOLD", "error": error}, denial)
                self.assertEqual(
                    before_identity, list(self.store.connection.iterdump())
                )


class ClaimedNoDeliveryParkPreparationPreDatabaseTests(unittest.TestCase):
    @staticmethod
    def _inventory(root: Path) -> dict[str, tuple[int, int, str | None]]:
        inventory = {}
        for path in root.rglob("*"):
            metadata = path.lstat()
            content_sha256 = None
            if stat.S_ISREG(metadata.st_mode):
                content_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            inventory[str(path.relative_to(root))] = (
                metadata.st_mode,
                metadata.st_size,
                content_sha256,
            )
        return inventory

    @staticmethod
    def _argv(
        payload_file: Path, expected_payload_sha256: str
    ) -> list[str]:
        return [
            "coordination_store.py",
            "prepare-claimed-no-delivery-park",
            "--idempotency-key",
            "pre-database-denial",
            "--planner-session-id",
            PLANNER_ENDPOINT,
            "--payload-file",
            str(payload_file),
            "--expected-payload-sha256",
            expected_payload_sha256,
        ]

    def _run_without_database(
        self,
        raw_payload: bytes,
        expected_payload_sha256: str,
        *,
        existing_database: bool = False,
    ) -> tuple[int, dict[str, object], dict[str, tuple[int, int, str | None]]]:
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-prepare-") as temp:
            root = Path(temp)
            payload_file = root / "payload.json"
            payload_file.write_bytes(raw_payload)
            database = root / "coordination" / "state.sqlite3"
            if existing_database:
                database.parent.mkdir(mode=0o700)
                for path, content in (
                    (database, b"synthetic-database"),
                    (Path(f"{database}-wal"), b"synthetic-wal"),
                    (Path(f"{database}-shm"), b"synthetic-shm"),
                    (database.parent / "state.lock", b"synthetic-lock"),
                ):
                    path.write_bytes(content)

            before = self._inventory(root)
            output = io.StringIO()
            with (
                mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                mock.patch.object(
                    coordination,
                    "CoordinationStore",
                    side_effect=AssertionError("database must not open"),
                ),
                mock.patch.object(sys, "argv", self._argv(payload_file, expected_payload_sha256)),
                contextlib.redirect_stdout(output),
            ):
                result = coordination.main()
            self.assertEqual(before, self._inventory(root))
            return result, json.loads(output.getvalue()), self._inventory(root)

    def test_malformed_ambiguous_and_digest_inputs_fail_before_database_open(self) -> None:
        reserved_schema = CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
        cases = (
            ("malformed", b'{"evidence":', "0" * 64, "COORDINATION_ENVELOPE_MALFORMED"),
            ("non-object", b"[]", "0" * 64, "COORDINATION_ENVELOPE_NON_OBJECT"),
            ("nonfinite", b'{"value":NaN}', "0" * 64, "COORDINATION_ENVELOPE_NONFINITE"),
            ("duplicate", b'{"x":1,"x":2}', "0" * 64, "COORDINATION_ENVELOPE_DUPLICATE_KEY"),
            (
                "ambiguous",
                (
                    '{"evidence":{"schema":"'
                    + reserved_schema
                    + '","disposition":"COMPLETE"}}'
                ).encode("utf-8"),
                "0" * 64,
                "COORDINATION_ENVELOPE_AMBIGUOUS_RESERVED_INTENT",
            ),
            (
                "ordinary",
                b'{"value":1}',
                digest_json({"value": 1}),
                "CLAIMED_NO_DELIVERY_PARK_HANDLER_REQUIRED",
            ),
            (
                "oversized",
                b'{"value":"' + b"a" * (1024 * 1024) + b'"}',
                "0" * 64,
                "COORDINATION_ENVELOPE_RESOURCE_LIMIT",
            ),
            (
                "digest",
                (
                    '{"evidence":{"schema":"'
                    + reserved_schema
                    + '","disposition":"PARK"}}'
                ).encode("utf-8"),
                "0" * 64,
                "MESSAGE_PAYLOAD_MISMATCH",
            ),
        )
        for name, raw_payload, expected_sha256, error in cases:
            with self.subTest(name=name):
                result, output, _inventory = self._run_without_database(
                    raw_payload, expected_sha256
                )
                self.assertEqual(1, result)
                self.assertEqual({"phase": "HOLD", "error": error}, output)

    def test_invalid_input_preserves_existing_database_and_sidecar_bytes(self) -> None:
        result, output, _inventory = self._run_without_database(
            b'{"evidence":',
            "0" * 64,
            existing_database=True,
        )
        self.assertEqual(1, result)
        self.assertEqual(
            {"phase": "HOLD", "error": "COORDINATION_ENVELOPE_MALFORMED"},
            output,
        )

    def test_exponent_overflow_is_nonfinite_before_digest_or_database(self) -> None:
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-overflow-") as temp:
            root = Path(temp)
            payload_file = root / "payload.json"
            payload_file.write_bytes(
                (
                    '{"evidence":{"schema":"'
                    + CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA
                    + '","disposition":"PARK"},"overflow":1e400}'
                ).encode("utf-8")
            )
            database = root / "coordination" / "state.sqlite3"
            before = self._inventory(root)
            output = io.StringIO()
            with (
                mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                mock.patch.object(
                    coordination,
                    "CoordinationStore",
                    side_effect=AssertionError("database must not open"),
                ),
                mock.patch.object(
                    coordination,
                    "digest_json",
                    side_effect=AssertionError("digest must not run"),
                ),
                mock.patch.object(sys, "argv", self._argv(payload_file, "0" * 64)),
                contextlib.redirect_stdout(output),
            ):
                result = coordination.main()
            self.assertEqual(1, result)
            self.assertEqual(
                {"phase": "HOLD", "error": "COORDINATION_ENVELOPE_NONFINITE"},
                json.loads(output.getvalue()),
            )
            self.assertEqual(before, self._inventory(root))
            self.assertFalse(database.parent.exists())

    def test_required_acquisition_flags_fail_closed_before_open_or_parse(self) -> None:
        for flag_name in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
            with self.subTest(flag_name=flag_name):
                with tempfile.TemporaryDirectory(
                    prefix=f"twinfinity-park-required-{flag_name.lower()}-"
                ) as temp:
                    root = Path(temp)
                    payload_file = root / "payload.json"
                    payload_file.write_bytes(b"{}")
                    database = root / "coordination" / "state.sqlite3"
                    before = self._inventory(root)
                    output = io.StringIO()
                    with (
                        mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                        mock.patch.object(coordination.os, flag_name, 0),
                        mock.patch.object(
                            coordination.os,
                            "open",
                            side_effect=AssertionError("payload must not open"),
                        ),
                        mock.patch.object(
                            coordination,
                            "parse_coordination_envelope",
                            side_effect=AssertionError("parser must not run"),
                        ),
                        mock.patch.object(
                            coordination,
                            "digest_json",
                            side_effect=AssertionError("digest must not run"),
                        ),
                        mock.patch.object(
                            coordination,
                            "CoordinationStore",
                            side_effect=AssertionError("database must not open"),
                        ),
                        mock.patch.object(
                            sys, "argv", self._argv(payload_file, "0" * 64)
                        ),
                        contextlib.redirect_stdout(output),
                    ):
                        result = coordination.main()

                    self.assertEqual(1, result)
                    self.assertEqual(
                        {"phase": "HOLD", "error": "PARK_PAYLOAD_READ_FAILED"},
                        json.loads(output.getvalue()),
                    )
                    self.assertEqual(before, self._inventory(root))
                    self.assertFalse(database.parent.exists())

    def test_short_read_valid_prefix_fails_before_parse_digest_or_database(self) -> None:
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-short-read-") as temp:
            root = Path(temp)
            valid_prefix = b'{"value":1}'
            payload_file = root / "payload.json"
            payload_file.write_bytes(valid_prefix + b"unread-suffix")
            database = root / "coordination" / "state.sqlite3"
            before = self._inventory(root)
            observed_reads = []

            def short_read(_descriptor, size):
                observed_reads.append(size)
                return valid_prefix

            output = io.StringIO()
            with (
                mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                mock.patch.object(coordination.os, "read", side_effect=short_read),
                mock.patch.object(
                    coordination,
                    "parse_coordination_envelope",
                    side_effect=AssertionError("parser must not run"),
                ),
                mock.patch.object(
                    coordination,
                    "digest_json",
                    side_effect=AssertionError("digest must not run"),
                ),
                mock.patch.object(
                    coordination,
                    "CoordinationStore",
                    side_effect=AssertionError("database must not open"),
                ),
                mock.patch.object(sys, "argv", self._argv(payload_file, "0" * 64)),
                contextlib.redirect_stdout(output),
            ):
                result = coordination.main()

            self.assertEqual(1, result)
            self.assertEqual(
                {"phase": "HOLD", "error": "PARK_PAYLOAD_READ_FAILED"},
                json.loads(output.getvalue()),
            )
            self.assertEqual(
                [coordination.COORDINATION_ENVELOPE_MAX_BYTES + 1], observed_reads
            )
            self.assertEqual(before, self._inventory(root))
            self.assertFalse(database.parent.exists())

    def test_identity_denials_use_readonly_lookup_before_writable_store(self) -> None:
        raw_payload = canonical_json(
            {
                "evidence": {
                    "schema": CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA,
                    "disposition": "PARK",
                }
            }
        ).encode("utf-8")
        payload_sha256 = digest_json(json.loads(raw_payload))
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-identity-") as temp:
            root = Path(temp)
            coordination_root = root / "coordination"
            coordination_root.mkdir(mode=0o700)
            database = coordination_root / "state.sqlite3"
            installed = root / "installed"
            installed.mkdir()
            for profile in (ROOT / "references").glob("*-v*.config.toml"):
                shutil.copy2(profile, installed / profile.name)
            config = load_registry_config(
                ROOT / "references" / "twinfinity-executor-registry.toml",
                codex_home=installed,
                profile_template_root=ROOT / "references",
            )
            store = CoordinationStore(database)
            aliases, alias_sha = load_legacy_alias_fixture(
                ROOT / "references" / "twinfinity-legacy-role-aliases.json"
            )
            plan = build_plan(
                store.connection,
                config,
                aliases,
                alias_fixture_sha256=alias_sha,
            )
            apply_plan(
                store.connection,
                plan=plan,
                operation_key="claimed-no-delivery-park-readonly-identity-fixture",
                expected_plan_sha256=plan["plan_sha256"],
                now="2026-08-26T20:00:00Z",
            )
            store.close()
            payload_file = root / "payload.json"
            payload_file.write_bytes(raw_payload)

            cases = (
                ("wrong-role", DEVELOPMENT_ENDPOINT, "PARK_PREPARER_INVALID"),
                ("historical", "role.planner.v2", "CURRENT_ROLE_ENDPOINT_REQUIRED"),
                (
                    "alias",
                    "01a017f9-4ce5-7110-9a1f-73b1c10f5625",
                    "CURRENT_ROLE_ENDPOINT_REQUIRED",
                ),
                ("substituted", "role.planner.v999", "CURRENT_ROLE_ENDPOINT_REQUIRED"),
            )
            with registry_config_scope(config):
                for suffix, recipient, expected_error in cases:
                    with self.subTest(suffix=suffix):
                        before = self._inventory(root)
                        output = io.StringIO()
                        with (
                            mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                            mock.patch.object(
                                coordination,
                                "CoordinationStore",
                                side_effect=AssertionError(
                                    "writable database must not open"
                                ),
                            ),
                            mock.patch.object(
                                sys,
                                "argv",
                                [
                                    "coordination_store.py",
                                    "prepare-claimed-no-delivery-park",
                                    "--idempotency-key",
                                    f"readonly-identity-{suffix}",
                                    "--planner-session-id",
                                    recipient,
                                    "--payload-file",
                                    str(payload_file),
                                    "--expected-payload-sha256",
                                    payload_sha256,
                                ],
                            ),
                            contextlib.redirect_stdout(output),
                        ):
                            result = coordination.main()
                        self.assertEqual(1, result)
                        self.assertEqual(
                            {"phase": "HOLD", "error": expected_error},
                            json.loads(output.getvalue()),
                        )
                        self.assertEqual(before, self._inventory(root))

    def test_missing_registry_and_absent_database_deny_without_artifacts(self) -> None:
        raw_payload = canonical_json(
            {
                "evidence": {
                    "schema": CLAIMED_NO_DELIVERY_PARK_NOTICE_SCHEMA,
                    "disposition": "PARK",
                }
            }
        ).encode("utf-8")
        payload_sha256 = digest_json(json.loads(raw_payload))
        for suffix, create_database, expected_error in (
            ("missing-registry", True, "REGISTRY_PROFILE_MISSING"),
            ("absent-database", False, "DATABASE_PARENT_UNSAFE"),
        ):
            with self.subTest(suffix=suffix):
                with tempfile.TemporaryDirectory(
                    prefix=f"twinfinity-park-{suffix}-"
                ) as temp:
                    root = Path(temp)
                    database = root / "coordination" / "state.sqlite3"
                    if create_database:
                        database.parent.mkdir(mode=0o700)
                        store = CoordinationStore(database)
                        store.close()
                    codex_home = root / "codex-home"
                    if suffix == "missing-registry":
                        codex_home.mkdir(mode=0o700)
                    environment = (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(codex_home)},
                        )
                        if suffix == "missing-registry"
                        else contextlib.nullcontext()
                    )
                    payload_file = root / "payload.json"
                    payload_file.write_bytes(raw_payload)
                    before = self._inventory(root)
                    output = io.StringIO()
                    with (
                        environment,
                        mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                        mock.patch.object(
                            coordination,
                            "CoordinationStore",
                            side_effect=AssertionError("writable database must not open"),
                        ),
                        mock.patch.object(
                            sys,
                            "argv",
                            [
                                "coordination_store.py",
                                "prepare-claimed-no-delivery-park",
                                "--idempotency-key",
                                f"readonly-identity-{suffix}",
                                "--planner-session-id",
                                PLANNER_ENDPOINT,
                                "--payload-file",
                                str(payload_file),
                                "--expected-payload-sha256",
                                payload_sha256,
                            ],
                        ),
                        contextlib.redirect_stdout(output),
                    ):
                        result = coordination.main()
                    self.assertEqual(1, result)
                    self.assertEqual(
                        {"phase": "HOLD", "error": expected_error},
                        json.loads(output.getvalue()),
                    )
                    self.assertEqual(before, self._inventory(root))
                    if not create_database:
                        self.assertFalse(database.parent.exists())

    def test_fifo_returns_within_explicit_timeout_and_creates_no_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-fifo-timeout-") as temp:
            root = Path(temp)
            payload_file = root / "payload.fifo"
            os.mkfifo(payload_file, mode=0o600)
            database = root / "coordination" / "state.sqlite3"
            before = self._inventory(root)
            child = (
                "import sys\n"
                "from pathlib import Path\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "import coordination_store as coordination\n"
                "coordination.DEFAULT_DATABASE = Path(sys.argv[2])\n"
                "sys.argv = ['coordination_store.py', "
                "'prepare-claimed-no-delivery-park', '--idempotency-key', "
                "'fifo-timeout', '--planner-session-id', 'role.planner.v3', "
                "'--payload-file', sys.argv[3], '--expected-payload-sha256', '0' * 64]\n"
                "raise SystemExit(coordination.main())\n"
            )
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment.pop("PYTHONPYCACHEPREFIX", None)
            started = time.monotonic()
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    child,
                    str(SCRIPTS),
                    str(database),
                    str(payload_file),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                timeout=2.0,
                check=False,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(1, completed.returncode, completed.stderr)
            self.assertLess(elapsed, 2.0)
            self.assertEqual(
                {"phase": "HOLD", "error": "PARK_PAYLOAD_READ_FAILED"},
                json.loads(completed.stdout),
            )
            self.assertEqual(before, self._inventory(root))
            self.assertFalse(database.parent.exists())

    def test_fifo_fails_before_parse_digest_store_or_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-fifo-") as temp:
            root = Path(temp)
            payload_file = root / "payload.fifo"
            os.mkfifo(payload_file, mode=0o600)
            database = root / "coordination" / "state.sqlite3"
            before = self._inventory(root)
            observed_open_flags = []
            real_os_open = os.open

            def traced_os_open(path, flags, *arguments, **keywords):
                if os.fspath(path) == os.fspath(payload_file):
                    observed_open_flags.append(flags)
                return real_os_open(path, flags, *arguments, **keywords)

            output = io.StringIO()
            with (
                mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                mock.patch.object(
                    coordination,
                    "CoordinationStore",
                    side_effect=AssertionError("database must not open"),
                ),
                mock.patch.object(
                    coordination,
                    "parse_coordination_envelope",
                    side_effect=AssertionError("parser must not run"),
                ),
                mock.patch.object(
                    coordination,
                    "digest_json",
                    side_effect=AssertionError("digest must not run"),
                ),
                mock.patch.object(coordination.os, "open", side_effect=traced_os_open),
                mock.patch.object(sys, "argv", self._argv(payload_file, "0" * 64)),
                contextlib.redirect_stdout(output),
            ):
                result = coordination.main()

            self.assertEqual(1, result)
            self.assertEqual(
                {"phase": "HOLD", "error": "PARK_PAYLOAD_READ_FAILED"},
                json.loads(output.getvalue()),
            )
            self.assertEqual(1, len(observed_open_flags))
            flags = observed_open_flags[0]
            self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
            self.assertEqual(os.O_NONBLOCK, flags & os.O_NONBLOCK)
            self.assertEqual(os.O_NOFOLLOW, flags & os.O_NOFOLLOW)
            self.assertEqual(os.O_CLOEXEC, flags & os.O_CLOEXEC)
            self.assertEqual(before, self._inventory(root))
            self.assertFalse(database.parent.exists())

    def test_symlink_directory_and_character_device_fail_before_parse_or_store(self) -> None:
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-nonregular-") as temp:
            root = Path(temp)
            regular = root / "regular.json"
            regular.write_text("{}", encoding="utf-8")
            symlink = root / "payload-link.json"
            symlink.symlink_to(regular)
            directory = root / "payload-directory"
            directory.mkdir()
            for name, payload_file in (
                ("symlink", symlink),
                ("directory", directory),
                ("character-device", Path("/dev/null")),
            ):
                with self.subTest(name=name):
                    database = root / f"coordination-{name}" / "state.sqlite3"
                    before = self._inventory(root)
                    output = io.StringIO()
                    with (
                        mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                        mock.patch.object(
                            coordination,
                            "CoordinationStore",
                            side_effect=AssertionError("database must not open"),
                        ),
                        mock.patch.object(
                            coordination,
                            "parse_coordination_envelope",
                            side_effect=AssertionError("parser must not run"),
                        ),
                        mock.patch.object(sys, "argv", self._argv(payload_file, "0" * 64)),
                        contextlib.redirect_stdout(output),
                    ):
                        result = coordination.main()
                    self.assertEqual(1, result)
                    self.assertEqual(
                        {"phase": "HOLD", "error": "PARK_PAYLOAD_READ_FAILED"},
                        json.loads(output.getvalue()),
                    )
                    self.assertEqual(before, self._inventory(root))
                    self.assertFalse(database.parent.exists())

    def test_socket_fails_before_parse_or_store(self) -> None:
        import socket

        with tempfile.TemporaryDirectory(prefix="tf-park-socket-") as temp:
            root = Path(temp)
            payload_file = root / "payload.sock"
            database = root / "coordination" / "state.sqlite3"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(os.fspath(payload_file))
                before = self._inventory(root)
                output = io.StringIO()
                with (
                    mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                    mock.patch.object(
                        coordination,
                        "CoordinationStore",
                        side_effect=AssertionError("database must not open"),
                    ),
                    mock.patch.object(
                        coordination,
                        "parse_coordination_envelope",
                        side_effect=AssertionError("parser must not run"),
                    ),
                    mock.patch.object(sys, "argv", self._argv(payload_file, "0" * 64)),
                    contextlib.redirect_stdout(output),
                ):
                    result = coordination.main()
                self.assertEqual(1, result)
                self.assertEqual(
                    {"phase": "HOLD", "error": "PARK_PAYLOAD_READ_FAILED"},
                    json.loads(output.getvalue()),
                )
                self.assertEqual(before, self._inventory(root))
                self.assertFalse(database.parent.exists())

    def test_oversized_regular_payload_uses_one_limit_plus_one_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="twinfinity-park-bounded-") as temp:
            root = Path(temp)
            payload_file = root / "payload.json"
            with payload_file.open("wb") as descriptor:
                descriptor.write(b"{")
                descriptor.seek(coordination.COORDINATION_ENVELOPE_MAX_BYTES * 4)
                descriptor.write(b"}")
            database = root / "coordination" / "state.sqlite3"
            before = self._inventory(root)
            observed_reads = []
            real_os_read = os.read

            def traced_os_read(descriptor, size):
                content = real_os_read(descriptor, size)
                observed_reads.append((size, len(content)))
                return content

            output = io.StringIO()
            with (
                mock.patch.object(coordination, "DEFAULT_DATABASE", database),
                mock.patch.object(
                    coordination,
                    "CoordinationStore",
                    side_effect=AssertionError("database must not open"),
                ),
                mock.patch.object(coordination.os, "read", side_effect=traced_os_read),
                mock.patch.object(sys, "argv", self._argv(payload_file, "0" * 64)),
                contextlib.redirect_stdout(output),
            ):
                result = coordination.main()
            bounded_size = coordination.COORDINATION_ENVELOPE_MAX_BYTES + 1
            self.assertEqual(1, result)
            self.assertEqual(
                {"phase": "HOLD", "error": "COORDINATION_ENVELOPE_RESOURCE_LIMIT"},
                json.loads(output.getvalue()),
            )
            self.assertEqual([(bounded_size, bounded_size)], observed_reads)
            self.assertEqual(before, self._inventory(root))
            self.assertFalse(database.parent.exists())


if __name__ == "__main__":
    unittest.main()
