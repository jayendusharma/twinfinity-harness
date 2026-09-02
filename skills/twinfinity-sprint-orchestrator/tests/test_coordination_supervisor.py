from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from dataclasses import replace
import fcntl
import hashlib
import io
from pathlib import Path
import json
import os
import pwd
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
    terminal_published_body,
    terminal_publication_body,
)
import coordination_store as coordination_store_module  # noqa: E402
import coordination_supervisor as coordination_supervisor_module  # noqa: E402
import executor_registry as executor_registry_module  # noqa: E402
import role_executor_transport as role_executor_transport_module  # noqa: E402
from coordination_supervisor import (  # noqa: E402
    CoordinationSupervisor,
    SchedulerLaunchPolicy,
    _canonical_session_command,
    launch_canonical_session,
    launch_terminal_watch_session,
)
from executor_registry import (  # noqa: E402
    AttemptLineage,
    RegistryError,
    SystemdUnitEvidence,
    attempt_lineage_for_target,
    current_endpoint,
    load_registry_config,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from hosted_operation_control import (  # noqa: E402
    HostedOperationControl,
    run_supervisor as run_hosted_supervisor,
)
from role_executor_transport import (  # noqa: E402
    ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS,
    ROLE_EXECUTOR_TRANSPORT_MALFORMED,
    ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED,
    ROLE_EXECUTOR_TRANSPORT_TIMED_OUT,
    ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE,
    RoleExecutorTransportAttestation,
    RoleExecutorUserBusContext,
    attest_role_executor_transport,
    build_role_executor_transport_preflight,
    launch_role_executor,
    role_executor_user_bus_context,
    validate_role_executor_transport_attestation,
)
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from tests.reviewed_endpoint_catalog_fixture import (  # noqa: E402
    reviewed_current_endpoint_catalog,
)
from tests.canonical_ready_fixture import (  # noqa: E402
    finalize_canonical_ready_item,
)


ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT_SESSION = "role.development.v4"
PLANNER_SESSION = "role.planner.v2"
SRE_SESSION = "role.sre.v4"


REPOSITORY = "twinfinityai/twinfinityapp"
LEASE = "5" * 64
NONCANONICAL_SESSION = "01a00000-0000-7000-8000-000000000001"


class CoordinationSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        catalog = reviewed_current_endpoint_catalog(ROOT, Path(self.temp.name))
        config = catalog.__enter__()
        self.addCleanup(catalog.__exit__, None, None, None)
        directory = Path(self.temp.name) / "coordinator"
        directory.mkdir(mode=0o700)
        self.store = CoordinationStore(directory / "state.sqlite3")
        aliases, alias_sha = load_legacy_alias_fixture(
            ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
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
            operation_key="coordination-supervisor-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-22T09:59:59Z",
        )
        self.launches: list[tuple[str, int]] = []
        self.terminal_watch_launches: list[tuple[str, str]] = []

        def launcher(session_id: str, message_id: int):
            self.launches.append((session_id, message_id))
            return self.synthetic_manager_submission(
                session_id,
                "message",
                str(message_id),
                1000 + len(self.launches),
            )

        def terminal_watch_launcher(session_id: str, watch_key: str):
            self.terminal_watch_launches.append((session_id, watch_key))
            return self.synthetic_manager_submission(
                session_id,
                "terminal_watch",
                watch_key,
                2000 + len(self.terminal_watch_launches),
            )

        self.supervisor = CoordinationSupervisor(
            self.store,
            launcher=launcher,
            terminal_watch_launcher=terminal_watch_launcher,
            process_checker=lambda *_: False,
        )

    @staticmethod
    def successful_transport(preflight):
        return RoleExecutorTransportAttestation.pass_for(
            preflight, user_manager_identity_sha256="a" * 64
        )

    @staticmethod
    def user_bus_context(effective_uid: int, generation: int = 1):
        return RoleExecutorUserBusContext(
            effective_uid=effective_uid,
            home=pwd.getpwuid(effective_uid).pw_dir,
            runtime_directory=f"/run/user/{effective_uid}",
            runtime_identity=(1, 2 + generation, 0o40700, effective_uid, 1),
            bus_identity=(1, 3 + generation, 0o140600, effective_uid, 1),
        )

    def manager_intent_event(
        self, *, target_kind: str, target_key: str
    ) -> tuple[sqlite3.Row, dict[str, object]]:
        event_type = (
            "SESSION_WAKE_MANAGER_SUBMISSION_INTENT"
            if target_kind == "message"
            else "TERMINAL_WATCH_MANAGER_SUBMISSION_INTENT"
        )
        for row in self.store.connection.execute(
            "SELECT * FROM coordination_events WHERE event_type=? ORDER BY id DESC",
            (event_type,),
        ).fetchall():
            try:
                envelope = json.loads(str(row["entity_key"]))
            except (TypeError, json.JSONDecodeError):
                continue
            fence = envelope.get("fence") if isinstance(envelope, dict) else None
            if (
                isinstance(fence, dict)
                and envelope.get("target_kind") == target_kind
                and fence.get("target_key") == target_key
            ):
                return row, envelope
        self.fail(f"manager intent missing for {target_kind}:{target_key}")

    def manager_submission_events_for_intent(
        self, *, target_kind: str, intent_event_key: str
    ) -> list[tuple[sqlite3.Row, dict[str, object]]]:
        event_type = (
            "SESSION_WAKE_MANAGER_SUBMITTED"
            if target_kind == "message"
            else "TERMINAL_WATCH_MANAGER_SUBMITTED"
        )
        matches: list[tuple[sqlite3.Row, dict[str, object]]] = []
        for row in self.store.connection.execute(
            "SELECT * FROM coordination_events WHERE event_type=? ORDER BY id",
            (event_type,),
        ).fetchall():
            try:
                envelope = json.loads(str(row["entity_key"]))
            except (TypeError, json.JSONDecodeError):
                continue
            if (
                isinstance(envelope, dict)
                and envelope.get("intent_event_key") == intent_event_key
            ):
                matches.append((row, envelope))
        return matches

    def seed_role_executor_child(
        self,
        *,
        role: str,
        endpoint_id: str,
        target_kind: str,
        target_key: str,
        invocation_id: str,
        process_id: int,
        reserved_at: str | None = None,
        launching_at: str | None = None,
        running_at: str | None = None,
        terminal_state: str | None = "COMPLETE",
        terminal_at: str | None = None,
    ) -> tuple[dict[str, object], str]:
        missing_timestamp = any(
            value is None for value in (reserved_at, launching_at, running_at)
        ) or (terminal_state is not None and terminal_at is None)
        intent_at = None
        if missing_timestamp:
            intent, _envelope = self.manager_intent_event(
                target_kind=target_kind, target_key=target_key
            )
            intent_at = str(intent["created_at"])
        reserved_at = reserved_at or intent_at
        launching_at = launching_at or intent_at
        running_at = running_at or intent_at
        if terminal_state is not None:
            terminal_at = terminal_at or intent_at
        reserved, token = reserve_attempt(
            self.store.connection,
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            now=reserved_at,
            precondition=lambda connection: attempt_lineage_for_target(
                connection, target_kind, target_key
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
            systemd_invocation_id=invocation_id,
            systemd_control_group=f"/user.slice/{unit}",
            now=launching_at,
        )
        current = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=process_id,
            now=running_at,
        )
        if terminal_state is not None:
            current = transition_attempt(
                self.store.connection,
                attempt_id=reserved["attempt_id"],
                token=token,
                expected_version=current["version"],
                new_state=terminal_state,
                exit_code=0 if terminal_state == "COMPLETE" else None,
                now=terminal_at,
            )
        return current, token

    def synthetic_manager_submission(
        self,
        endpoint_id: str,
        target_kind: str,
        target_key: str,
        process_id: int,
    ):
        ordinal = self.store.connection.execute(
            "SELECT COUNT(*) FROM executor_attempts "
            "WHERE target_kind=? AND target_key=?",
            (target_kind, target_key),
        ).fetchone()[0]
        invocation_id = hashlib.sha256(
            f"{target_kind}:{target_key}:{process_id}:{ordinal}".encode()
        ).hexdigest()[:32]
        role = endpoint_id.split(".")[1]
        self.seed_role_executor_child(
            role=role,
            endpoint_id=endpoint_id,
            target_kind=target_kind,
            target_key=target_key,
            invocation_id=invocation_id,
            process_id=process_id,
        )
        return role_executor_transport_module.RoleExecutorManagerSubmission(
            systemd_unit=stable_systemd_unit(role, target_kind, target_key),
            systemd_invocation_id=invocation_id,
        )

    @staticmethod
    def non_notice_database_state(connection: sqlite3.Connection) -> dict[str, object]:
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
        return self.store.ingest_snapshot(
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

    def transport_config_loader(self, preflight):
        rows = {
            role: dict(current_endpoint(self.store.connection, role))
            for role in ("planner", "development", "sre")
        }

        def load(_path, *, selected_current_endpoint_id):
            row = next(
                item
                for item in rows.values()
                if item["endpoint_id"] == selected_current_endpoint_id
            )
            payload = json.loads(row["config_json"])
            configured = SimpleNamespace(
                endpoint_id=row["endpoint_id"],
                role=row["role"],
                config_sha256=row["config_sha256"],
                payload=payload,
                profile_sha256=payload["profile_sha256"],
                command_prefix=tuple(json.loads(row["command_json"])),
            )
            return SimpleNamespace(
                source_sha256=preflight.registry_source_sha256,
                roles={row["role"]: configured},
            )

        return load

    def test_transport_preflight_runs_once_before_first_dispatch_write(self) -> None:
        message_id = self.notice(idempotency_key="preflight-before-write", issue_number=149)
        order: list[str] = []

        def attestor(preflight):
            order.append("preflight")
            return self.successful_transport(preflight)

        def trace(statement: str) -> None:
            verb = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else ""
            if verb in {"CREATE", "DELETE", "INSERT", "REPLACE", "UPDATE"}:
                order.append("write")

        self.store.connection.set_trace_callback(trace)
        try:
            def launcher(endpoint: str, candidate: int):
                self.launches.append((endpoint, candidate))
                return self.synthetic_manager_submission(
                    endpoint, "message", str(candidate), 1490
                )

            supervisor = CoordinationSupervisor(
                self.store,
                launcher=launcher,
                terminal_watch_launcher=lambda *_args: self.fail(
                    "terminal watcher must not launch"
                ),
                process_checker=lambda *_: False,
                transport_preflight=attestor,
            )
            result = supervisor.run_once("2026-09-02T05:00:00Z")
        finally:
            self.store.connection.set_trace_callback(None)

        self.assertEqual("preflight", order[0])
        self.assertEqual(1, order.count("preflight"))
        self.assertIn("write", order)
        self.assertEqual([message_id], [row["message_id"] for row in result["launched"]])

    def test_transport_attestor_is_strict_read_only_identity_bound_and_uncached(self) -> None:
        effective_uid = os.geteuid()
        preflight = build_role_executor_transport_preflight(
            self.store.connection, effective_uid=effective_uid
        )
        load = self.transport_config_loader(preflight)
        observed: list[tuple[list[str], dict[str, object]]] = []
        response = (
            "Architecture=x86-64\n"
            f"ControlGroup=/user.slice/user-{effective_uid}.slice/"
            f"user@{effective_uid}.service\n"
            "SystemState=running\n"
            "UserspaceTimestampMonotonic=123456\n"
            "Version=257.7\n"
        ).encode()
        user_bus = self.user_bus_context(effective_uid)

        def runner(command, **kwargs):
            observed.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout=response, stderr=b"")

        first = attest_role_executor_transport(
            preflight,
            runner=runner,
            config_loader=load,
            euid_reader=lambda: effective_uid,
            user_bus_reader=lambda _uid: user_bus,
        )
        second = attest_role_executor_transport(
            preflight,
            runner=runner,
            config_loader=load,
            euid_reader=lambda: effective_uid,
            user_bus_reader=lambda _uid: user_bus,
        )

        self.assertEqual(first, second)
        self.assertEqual(2, len(observed))
        command, kwargs = observed[0]
        self.assertEqual(
            [
                "/usr/bin/systemctl",
                "--user",
                "show",
                "--no-pager",
                "--property=Architecture",
                "--property=ControlGroup",
                "--property=SystemState",
                "--property=UserspaceTimestampMonotonic",
                "--property=Version",
            ],
            command,
        )
        self.assertEqual(observed[0], observed[1])
        self.assertIs(kwargs["check"], False)
        self.assertIs(kwargs["capture_output"], True)
        self.assertEqual(subprocess.DEVNULL, kwargs["stdin"])
        self.assertEqual(5, kwargs["timeout"])
        self.assertEqual(
            {"DBUS_SESSION_BUS_ADDRESS", "HOME", "LC_ALL", "PATH", "XDG_RUNTIME_DIR"},
            set(kwargs["env"]),
        )
        self.assertTrue(first.user_manager_identity_sha256)

        launch_call: dict[str, object] = {}

        def launch_runner(_command, **launch_kwargs):
            launch_call.update(launch_kwargs)
            return SimpleNamespace(returncode=0)

        with patch.dict(
            os.environ,
            {
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/hostile/bus",
                "XDG_RUNTIME_DIR": "/hostile/runtime",
            },
        ):
            self.assertEqual(
                0,
                launch_role_executor(
                    role="development",
                    endpoint_id=DEVELOPMENT_SESSION,
                    target_kind="message",
                    target_key="149",
                    prompt="Synthetic transport environment check",
                    runner=launch_runner,
                ),
            )
        self.assertEqual(kwargs["env"], launch_call["env"])

    def test_manager_submission_is_exact_and_combined_output_is_bounded(self) -> None:
        role = "development"
        target_kind = "message"
        target_key = "155"
        unit = stable_systemd_unit(role, target_kind, target_key)
        invocation_id = "a" * 32
        response = (
            f"Running as unit: {unit}; invocation ID: {invocation_id}\n"
        ).encode()

        def completed(
            stdout: object, stderr: object = b"", returncode: int = 0
        ) -> subprocess.CompletedProcess[object]:
            return subprocess.CompletedProcess(
                ["/usr/bin/systemd-run"],
                returncode,
                stdout=stdout,
                stderr=stderr,
            )

        with patch.object(
            role_executor_transport_module,
            "_bounded_manager_submission_run",
            return_value=completed(response),
        ) as bounded, patch.object(
            role_executor_transport_module.subprocess,
            "run",
            side_effect=AssertionError("subprocess.run must not submit"),
        ):
            receipt = role_executor_transport_module.submit_role_executor(
                role=role,
                endpoint_id=DEVELOPMENT_SESSION,
                target_kind=target_kind,
                target_key=target_key,
                prompt="Synthetic exact manager receipt",
            )
        self.assertEqual(unit, receipt.systemd_unit)
        self.assertEqual(invocation_id, receipt.systemd_invocation_id)
        self.assertRegex(receipt.receipt_sha256, r"^[0-9a-f]{64}$")
        command = bounded.call_args.args[0]
        kwargs = bounded.call_args.kwargs
        self.assertNotIn("--quiet", command)
        self.assertNotIn("TWINFINITY_EXECUTOR_TOKEN", " ".join(command))
        self.assertEqual(
            role_executor_transport_module.SYSTEMD_RUN_SUBMISSION_TIMEOUT_SECONDS,
            kwargs["timeout"],
        )
        self.assertEqual(
            role_executor_transport_module._manager_environment(os.geteuid()),
            kwargs["env"],
        )

        with patch.object(
            role_executor_transport_module,
            "_bounded_manager_submission_run",
            return_value=completed(b"", response),
        ):
            stderr_receipt = role_executor_transport_module.submit_role_executor(
                role=role,
                endpoint_id=DEVELOPMENT_SESSION,
                target_kind=target_kind,
                target_key=target_key,
                prompt="Synthetic exact manager receipt on stderr",
            )
        self.assertEqual(receipt, stderr_receipt)

        malformed = (
            (b"", b"", ROLE_EXECUTOR_TRANSPORT_MALFORMED),
            (response.decode(), b"", ROLE_EXECUTOR_TRANSPORT_MALFORMED),
            (response, response.decode(), ROLE_EXECUTOR_TRANSPORT_MALFORMED),
            (b"\xff\n", b"", ROLE_EXECUTOR_TRANSPORT_MALFORMED),
            (
                response.replace(b"\n", b"\0\n"),
                b"",
                ROLE_EXECUTOR_TRANSPORT_MALFORMED,
            ),
            (response[:-1], b"", ROLE_EXECUTOR_TRANSPORT_MALFORMED),
            (response + response, b"", ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS),
            (response, response, ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS),
            (
                response.replace(
                    unit.encode(),
                    stable_systemd_unit(role, target_kind, "156").encode(),
                ),
                b"",
                ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED,
            ),
            (b"x" * 513, b"", ROLE_EXECUTOR_TRANSPORT_MALFORMED),
            (b"x" * 300, b"y" * 213, ROLE_EXECUTOR_TRANSPORT_MALFORMED),
        )
        for stdout, stderr, expected in malformed:
            with self.subTest(expected=expected), self.assertRaisesRegex(
                RegistryError, f"^{expected}$"
            ), patch.object(
                role_executor_transport_module,
                "_bounded_manager_submission_run",
                return_value=completed(stdout, stderr),
            ):
                role_executor_transport_module.submit_role_executor(
                    role=role,
                    endpoint_id=DEVELOPMENT_SESSION,
                    target_kind=target_kind,
                    target_key=target_key,
                    prompt="Synthetic invalid manager receipt",
                )

        failures = (
            (
                "nonzero",
                completed(response, returncode=1),
                None,
                ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS,
            ),
            (
                "timeout",
                None,
                subprocess.TimeoutExpired(["/usr/bin/systemd-run"], 5),
                ROLE_EXECUTOR_TRANSPORT_TIMED_OUT,
            ),
            (
                "unavailable",
                None,
                OSError("synthetic post-start manager read failure"),
                ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE,
            ),
        )
        for label, returned, raised, expected in failures:
            patch_kwargs = (
                {"return_value": returned}
                if raised is None
                else {"side_effect": raised}
            )
            with self.subTest(label=label), self.assertRaisesRegex(
                RegistryError, f"^{expected}$"
            ), patch.object(
                role_executor_transport_module,
                "_bounded_manager_submission_run",
                **patch_kwargs,
            ):
                role_executor_transport_module.submit_role_executor(
                    role=role,
                    endpoint_id=DEVELOPMENT_SESSION,
                    target_kind=target_kind,
                    target_key=target_key,
                    prompt="Synthetic manager transport failure",
                )

        def unavailable_popen(*_args, **_kwargs):
            raise OSError("synthetic process creation failure")

        with self.assertRaises(
            role_executor_transport_module.RoleExecutorManagerNotSubmitted
        ) as unavailable:
            role_executor_transport_module._bounded_manager_submission_run(
                [sys.executable, "-c", "pass"],
                timeout=2,
                env=os.environ.copy(),
                popen=unavailable_popen,
            )
        self.assertEqual(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE, str(unavailable.exception))

        half = (
            role_executor_transport_module.
            ROLE_EXECUTOR_MANAGER_SUBMISSION_MAXIMUM_RESPONSE_BYTES
            // 2
            + 1
        )
        spawned: dict[str, subprocess.Popen[bytes]] = {}

        def capturing_popen(command, **popen_kwargs):
            process = subprocess.Popen(command, **popen_kwargs)
            spawned["process"] = process
            return process

        with self.assertRaises(
            role_executor_transport_module._ManagerSubmissionOutputOverflow
        ):
            role_executor_transport_module._bounded_manager_submission_run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os;"
                        f"os.write(1,b'x'*{half});"
                        f"os.write(2,b'y'*{half})"
                    ),
                ],
                timeout=2,
                env=os.environ.copy(),
                popen=capturing_popen,
            )
        process = spawned["process"]
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

        for invalid_clock in (float("nan"), float("inf")):
            blocked_spawn = Mock(
                side_effect=AssertionError(
                    "invalid initial clock must prevent spawn"
                )
            )
            with self.subTest(invalid_clock=invalid_clock), self.assertRaisesRegex(
                subprocess.SubprocessError, "manager submission clock invalid"
            ):
                role_executor_transport_module._bounded_manager_submission_run(
                    [sys.executable, "-c", "pass"],
                    timeout=2,
                    env=os.environ.copy(),
                    popen=blocked_spawn,
                    monotonic=lambda: invalid_clock,
                )
            blocked_spawn.assert_not_called()

        regressing_spawned: dict[str, subprocess.Popen[bytes]] = {}

        def capture_regressing_popen(command, **popen_kwargs):
            process = subprocess.Popen(command, **popen_kwargs)
            regressing_spawned["process"] = process
            return process

        clock_samples = iter((1.0, 0.5))
        with self.assertRaisesRegex(
            subprocess.SubprocessError, "manager submission clock invalid"
        ):
            role_executor_transport_module._bounded_manager_submission_run(
                [
                    sys.executable,
                    "-c",
                    "import time;time.sleep(30)",
                ],
                timeout=2,
                env=os.environ.copy(),
                popen=capture_regressing_popen,
                monotonic=lambda: next(clock_samples),
            )
        regressing_process = regressing_spawned["process"]
        self.assertIsNotNone(regressing_process.poll())
        self.assertTrue(regressing_process.stdout.closed)
        self.assertTrue(regressing_process.stderr.closed)

    def test_potentially_post_effect_error_never_resubmits(self) -> None:
        failures = (
            (
                "unavailable",
                lambda: RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE),
            ),
            (
                "timed-out",
                lambda: RegistryError(ROLE_EXECUTOR_TRANSPORT_TIMED_OUT),
            ),
            (
                "malformed",
                lambda: RegistryError(ROLE_EXECUTOR_TRANSPORT_MALFORMED),
            ),
            (
                "ambiguous",
                lambda: RegistryError(ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS),
            ),
            (
                "substituted",
                lambda: RegistryError(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED),
            ),
            ("oserror", lambda: OSError("synthetic post-effect read failure")),
            (
                "called-process-error",
                lambda: subprocess.CalledProcessError(
                    1, ["/usr/bin/systemd-run"]
                ),
            ),
        )
        for offset, (label, failure) in enumerate(failures):
            with self.subTest(label=label):
                message_id = self.notice(
                    idempotency_key=f"post-effect-{label}",
                    issue_number=1550 + offset,
                )
                calls = 0

                def launcher(_session: str, _message: int):
                    nonlocal calls
                    calls += 1
                    raise failure()

                supervisor = CoordinationSupervisor(
                    self.store,
                    launcher=launcher,
                    terminal_watch_launcher=lambda *_args: self.fail(
                        "terminal watcher must not launch"
                    ),
                    process_checker=lambda *_args: False,
                )
                minute = offset * 2
                supervisor.run_once(f"2026-09-02T21:{minute:02d}:00Z")
                supervisor.run_once(f"2026-09-02T21:{minute + 1:02d}:00Z")

                self.assertEqual(1, calls)
                wake = self.store.connection.execute(
                    "SELECT wake_key,state,process_id,last_error "
                    "FROM coordination_wakes WHERE message_id=?",
                    (message_id,),
                ).fetchone()
                self.assertEqual(
                    (
                        "HOLD",
                        None,
                        coordination_supervisor_module.CHILD_ACK_AMBIGUOUS,
                    ),
                    tuple(wake)[1:],
                )
                intent, envelope = self.manager_intent_event(
                    target_kind="message", target_key=str(message_id)
                )
                self.assertEqual(wake["wake_key"], envelope["target_entity_key"])
                self.assertEqual(
                    0,
                    self.store.connection.execute(
                        "SELECT COUNT(*) FROM coordination_events WHERE "
                        "event_type='SESSION_WAKE_MANAGER_SUBMISSION_ABANDONED' "
                        "AND entity_key=?",
                        (intent["entity_key"],),
                    ).fetchone()[0],
                )
                self.assertEqual(
                    [],
                    self.manager_submission_events_for_intent(
                        target_kind="message",
                        intent_event_key=str(intent["entity_key"]),
                    ),
                )
                self.assertEqual(
                    0,
                    self.store.connection.execute(
                        "SELECT COUNT(*) FROM coordination_events WHERE "
                        "event_type='SESSION_WAKE_STARTED' AND entity_key=?",
                        (wake["wake_key"],),
                    ).fetchone()[0],
                )

    def test_presubmit_intent_revalidates_exact_reserved_progress(self) -> None:
        message_id = self.notice(
            idempotency_key="stale-pre-submit-reservation", issue_number=155
        )
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        wake_key, should_launch = self.supervisor._reserve_wake(
            message, "2026-09-02T22:00:00Z"
        )
        self.assertTrue(should_launch)
        reservation = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE wake_key=?", (wake_key,)
            ).fetchone()
        )
        self.store.connection.execute(
            "UPDATE coordination_messages SET state='HOLD',last_error=? "
            "WHERE id=?",
            ("FOREIGN_PROGRESS", message_id),
        )
        fence = executor_registry_module.snapshot_role_executor_child_ack_fence(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=str(message_id),
        )
        self.assertNotEqual(
            reservation["target_progress_sha256"], fence.target_progress_sha256
        )
        self.store.connection.execute(
            "UPDATE coordination_wakes SET attempts=attempts+1,updated_at=? "
            "WHERE wake_key=?",
            ("2026-09-02T22:00:01Z", wake_key),
        )
        with self.assertRaisesRegex(
            CoordinationError, "^ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT$"
        ):
            self.supervisor._record_submission_intent(
                entity_key=wake_key,
                target_kind="message",
                fence=fence,
                reservation=reservation,
                now="2026-09-02T22:00:02Z",
            )
        current = self.store.connection.execute(
            "SELECT attempts,target_progress_sha256,last_error "
            "FROM coordination_wakes WHERE wake_key=?",
            (wake_key,),
        ).fetchone()
        self.assertEqual(reservation["attempts"] + 1, current["attempts"])
        self.assertEqual(
            reservation["target_progress_sha256"],
            current["target_progress_sha256"],
        )
        self.assertIsNone(current["last_error"])
        self.assertEqual(
            ("HOLD", "FOREIGN_PROGRESS"),
            tuple(
                self.store.connection.execute(
                    "SELECT state,last_error FROM coordination_messages WHERE id=?",
                    (message_id,),
                ).fetchone()
            ),
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events "
                "WHERE event_type='SESSION_WAKE_MANAGER_SUBMISSION_INTENT'"
            ).fetchone()[0],
        )

    def test_atomic_submit_revalidation_rejects_post_intent_message_drift(
        self,
    ) -> None:
        message_id = self.notice(
            idempotency_key="post-intent-message-drift", issue_number=1551
        )
        target_key = str(message_id)
        message = self.store.connection.execute(
            "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        wake_key, should_launch = self.supervisor._reserve_wake(
            message, "2026-09-02T22:01:00Z"
        )
        self.assertTrue(should_launch)
        reservation = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE wake_key=?", (wake_key,)
            ).fetchone()
        )
        fence = executor_registry_module.snapshot_role_executor_child_ack_fence(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=target_key,
        )
        intent_key = self.supervisor._record_submission_intent(
            entity_key=wake_key,
            target_kind="message",
            fence=fence,
            reservation=reservation,
            now="2026-09-02T22:01:01Z",
        )
        foreign = sqlite3.connect(self.store.path)
        try:
            foreign.execute(
                "UPDATE coordination_messages SET state='HOLD',last_error=?,"
                "updated_at=? WHERE id=?",
                (
                    "FOREIGN_PROGRESS",
                    "2026-09-02T22:01:02Z",
                    message_id,
                ),
            )
            foreign.commit()
        finally:
            foreign.close()
        calls = 0

        def forbidden_submit():
            nonlocal calls
            calls += 1
            return self.synthetic_manager_submission(
                DEVELOPMENT_SESSION, "message", target_key, 81551
            )

        result = self.supervisor._submit_manager_after_atomic_revalidation(
            intent_event_key=intent_key,
            target_kind="message",
            entity_key=wake_key,
            submit=forbidden_submit,
            now="2026-09-02T22:01:03Z",
        )

        self.assertEqual({"status": "ABANDONED"}, result)
        self.assertEqual(0, calls)
        current_message = self.store.connection.execute(
            "SELECT state,payload_sha256,updated_at,last_error "
            "FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(
            (
                "HOLD",
                message["payload_sha256"],
                "2026-09-02T22:01:02Z",
                "FOREIGN_PROGRESS",
            ),
            tuple(current_message),
        )
        self.assertEqual(
            ("INFLIGHT", reservation["attempts"], None, None),
            tuple(
                self.store.connection.execute(
                    "SELECT state,attempts,process_id,last_error "
                    "FROM coordination_wakes WHERE wake_key=?",
                    (wake_key,),
                ).fetchone()
            ),
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='SESSION_WAKE_MANAGER_SUBMISSION_ABANDONED' "
                "AND entity_key=?",
                (intent_key,),
            ).fetchone()[0],
        )

    def test_atomic_submit_revalidation_rejects_post_intent_watch_drift(
        self,
    ) -> None:
        _source, _message_id, watch_key, _attempt, _token = (
            self.bound_development_admission(complete=True)
        )
        reserved_watch, should_launch = self.supervisor._reserve_terminal_watch(
            watch_key, "2026-08-22T10:01:10Z"
        )
        self.assertTrue(should_launch)
        reservation = dict(reserved_watch)
        fence = executor_registry_module.snapshot_role_executor_child_ack_fence(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="terminal_watch",
            target_key=watch_key,
        )
        intent_key = self.supervisor._record_submission_intent(
            entity_key=watch_key,
            target_kind="terminal_watch",
            fence=fence,
            reservation=reservation,
            now="2026-08-22T10:01:11Z",
        )
        replacement_source_sha256 = "9" * 64
        foreign = sqlite3.connect(self.store.path)
        try:
            foreign.execute(
                "UPDATE coordination_items SET source_payload_sha256=?,"
                "version=version+1,updated_at=? WHERE repository=? "
                "AND issue_number=92",
                (
                    replacement_source_sha256,
                    "2026-08-22T10:01:12Z",
                    REPOSITORY,
                ),
            )
            foreign.commit()
        finally:
            foreign.close()
        calls = 0

        def forbidden_submit():
            nonlocal calls
            calls += 1
            return self.synthetic_manager_submission(
                DEVELOPMENT_SESSION, "terminal_watch", watch_key, 81552
            )

        result = self.supervisor._submit_manager_after_atomic_revalidation(
            intent_event_key=intent_key,
            target_kind="terminal_watch",
            entity_key=watch_key,
            submit=forbidden_submit,
            now="2026-08-22T10:01:13Z",
        )

        self.assertEqual({"status": "ABANDONED"}, result)
        self.assertEqual(0, calls)
        item = self.store.connection.execute(
            "SELECT source_payload_sha256,updated_at FROM coordination_items "
            "WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(
            (replacement_source_sha256, "2026-08-22T10:01:12Z"), tuple(item)
        )
        watch = self.store.connection.execute(
            "SELECT state,attempts,process_id,last_error "
            "FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(
            ("ACTIVE", reservation["attempts"], None, None), tuple(watch)
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='TERMINAL_WATCH_MANAGER_SUBMISSION_ABANDONED' "
                "AND entity_key=?",
                (intent_key,),
            ).fetchone()[0],
        )

    def test_manager_receipt_accepts_only_token_authenticated_exact_child(self) -> None:
        message_id = self.notice(
            idempotency_key="exact-manager-child", issue_number=155
        )
        target_key = str(message_id)
        invocation_id = "b" * 32

        def launcher(session_id: str, _message: int):
            self.seed_role_executor_child(
                role="development",
                endpoint_id=session_id,
                target_kind="message",
                target_key=target_key,
                invocation_id=invocation_id,
                process_id=8155,
            )
            return role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(
                    "development", "message", target_key
                ),
                systemd_invocation_id=invocation_id,
            )

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_args: False,
        )
        result = supervisor.run_once("2026-09-02T22:10:00Z")
        self.assertEqual(1, len(result["launched"]))
        self.assertEqual(8155, result["launched"][0]["process_id"])
        self.assertRegex(
            result["launched"][0]["child_ack_sha256"], r"^[0-9a-f]{64}$"
        )
        intent, _intent_envelope = self.manager_intent_event(
            target_kind="message", target_key=target_key
        )
        submissions = self.manager_submission_events_for_intent(
            target_kind="message", intent_event_key=str(intent["entity_key"])
        )
        self.assertEqual(1, len(submissions))
        receipt_event, receipt_envelope = submissions[0]
        expectation = receipt_envelope["expectation"]
        self.assertIsInstance(expectation, dict)
        expected_receipt = role_executor_transport_module.RoleExecutorManagerSubmission(
            systemd_unit=stable_systemd_unit(
                "development", "message", target_key
            ),
            systemd_invocation_id=invocation_id,
        )
        self.assertEqual(
            expected_receipt.receipt_sha256,
            expectation["manager_receipt_sha256"],
        )
        self.assertEqual(intent["created_at"], expectation["intent_recorded_at"])
        self.assertNotEqual(
            expectation["manager_receipt_sha256"], digest_json(expectation)
        )
        attempt = self.store.connection.execute(
            "SELECT * FROM executor_attempts WHERE target_kind='message' "
            "AND target_key=? AND process_id=?",
            (target_key, 8155),
        ).fetchone()
        accepted = self.store.connection.execute(
            "SELECT * FROM coordination_events WHERE "
            "event_type='SESSION_WAKE_CHILD_ACK_ACCEPTED' AND entity_key=?",
            (receipt_event["entity_key"],),
        ).fetchone()
        self.assertIsNotNone(accepted)
        expectation_object = self.supervisor._decode_expectation(expectation)
        acknowledgement = executor_registry_module.observe_role_executor_child_ack(
            self.store.connection,
            expectation=expectation_object,
            not_after="2026-09-02T22:10:00Z",
        )
        self.assertIsNotNone(acknowledgement)
        accepted_payload = {
            "child_ack_sha256": acknowledgement.sha256,
            "expectation_sha256": acknowledgement.expectation_sha256,
            "manager_receipt_sha256": acknowledgement.manager_receipt_sha256,
            "attempt_id": acknowledgement.attempt_id,
            "instance_id": acknowledgement.instance_id,
            "token_sha256": acknowledgement.token_sha256,
            "event_chain_sha256": acknowledgement.event_chain_sha256,
            "execution_class": acknowledgement.execution_class,
            "execution_ownership_sha256": (
                acknowledgement.execution_ownership_sha256
            ),
            "process_id": acknowledgement.process_id,
        }
        self.assertEqual(digest_json(accepted_payload), accepted["payload_sha256"])
        self.assertEqual(
            {
                "attempt_id": attempt["attempt_id"],
                "instance_id": attempt["instance_id"],
                "token_sha256": attempt["token_sha256"],
                "process_id": 8155,
                "manager_receipt_sha256": expected_receipt.receipt_sha256,
                "expectation_sha256": digest_json(expectation),
                "child_ack_sha256": result["launched"][0]["child_ack_sha256"],
            },
            {
                key: accepted_payload[key]
                for key in (
                    "attempt_id",
                    "instance_id",
                    "token_sha256",
                    "process_id",
                    "manager_receipt_sha256",
                    "expectation_sha256",
                    "child_ack_sha256",
                )
            },
        )

        competing_id = self.notice(
            idempotency_key="competing-manager-child", issue_number=156
        )
        competing_key = str(competing_id)

        def competing_launcher(session_id: str, _message: int):
            for ordinal, identity in enumerate(("c" * 32, "d" * 32), start=1):
                self.seed_role_executor_child(
                    role="development",
                    endpoint_id=session_id,
                    target_kind="message",
                    target_key=competing_key,
                    invocation_id=identity,
                    process_id=8255 + ordinal,
                )
            return role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(
                    "development", "message", competing_key
                ),
                systemd_invocation_id="c" * 32,
            )

        rejected = CoordinationSupervisor(
            self.store,
            launcher=competing_launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_args: False,
        ).run_once("2026-09-02T22:20:00Z")
        self.assertEqual([], rejected["launched"])
        self.assertEqual(
            ("HOLD", None),
            tuple(
                self.store.connection.execute(
                    "SELECT state,process_id FROM coordination_wakes "
                    "WHERE message_id=?",
                    (competing_id,),
                ).fetchone()
            ),
        )

        wrong_role_id = self.notice(
            idempotency_key="wrong-role-competing-manager-child",
            issue_number=157,
        )
        wrong_role_key = str(wrong_role_id)
        shared_invocation_id = "e" * 32

        def wrong_role_launcher(session_id: str, _message: int):
            self.seed_role_executor_child(
                role="sre",
                endpoint_id=SRE_SESSION,
                target_kind="message",
                target_key=wrong_role_key,
                invocation_id=shared_invocation_id,
                process_id=8355,
            )
            self.seed_role_executor_child(
                role="development",
                endpoint_id=session_id,
                target_kind="message",
                target_key=wrong_role_key,
                invocation_id=shared_invocation_id,
                process_id=8356,
            )
            return role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(
                    "development", "message", wrong_role_key
                ),
                systemd_invocation_id=shared_invocation_id,
            )

        wrong_role_result = CoordinationSupervisor(
            self.store,
            launcher=wrong_role_launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_args: False,
        ).run_once("2026-09-02T22:25:00Z")
        self.assertEqual([], wrong_role_result["launched"])
        self.assertEqual(
            ("HOLD", None),
            tuple(
                self.store.connection.execute(
                    "SELECT state,process_id FROM coordination_wakes "
                    "WHERE message_id=?",
                    (wrong_role_id,),
                ).fetchone()
            ),
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='SESSION_WAKE_STARTED' AND "
                "entity_key LIKE ?",
                (f"message:{wrong_role_key}:%",),
            ).fetchone()[0],
        )

    def test_manager_child_running_before_receipt_uses_wait_start_wall_time(
        self,
    ) -> None:
        observed_at = "2026-09-02T22:29:00Z"
        wait_started_at = coordination_store_module.timestamp_after(observed_at, 2)
        message_id = self.notice(
            idempotency_key="manager-child-running-before-receipt",
            issue_number=1570,
        )
        target_key = str(message_id)
        invocation_id = "5" * 32
        calls = 0

        def launcher(session_id: str, _message: int):
            nonlocal calls
            calls += 1
            child_at = coordination_store_module.timestamp_after(observed_at, 1)
            self.seed_role_executor_child(
                role="development",
                endpoint_id=session_id,
                target_kind="message",
                target_key=target_key,
                invocation_id=invocation_id,
                process_id=8450,
                reserved_at=child_at,
                launching_at=child_at,
                running_at=child_at,
                terminal_state=None,
            )
            return role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(
                    "development", "message", target_key
                ),
                systemd_invocation_id=invocation_id,
            )

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_args: False,
            child_ack_timeout_seconds=0,
        )
        with patch.object(
            coordination_supervisor_module,
            "utc_now",
            return_value=wait_started_at,
        ):
            result = supervisor.run_once(observed_at)

        self.assertEqual(1, calls)
        self.assertEqual(1, len(result["launched"]))
        self.assertEqual(8450, result["launched"][0]["process_id"])
        wake = self.store.connection.execute(
            "SELECT state,attempts,process_id,last_error FROM coordination_wakes "
            "WHERE message_id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("INFLIGHT", 1, 8450, None), tuple(wake))
        intent, _envelope = self.manager_intent_event(
            target_kind="message", target_key=target_key
        )
        submissions = self.manager_submission_events_for_intent(
            target_kind="message", intent_event_key=str(intent["entity_key"])
        )
        self.assertEqual(1, len(submissions))
        receipt = submissions[0][0]
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='SESSION_WAKE_CHILD_ACK_ACCEPTED' AND entity_key=?",
                (receipt["entity_key"],),
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type IN "
                "('SESSION_WAKE_CHILD_ACK_REJECTED', "
                "'SESSION_WAKE_CHILD_ACK_EXPIRED') AND entity_key=?",
                (receipt["entity_key"],),
            ).fetchone()[0],
        )

    def test_reserved_child_stays_pending_then_same_attempt_acknowledges(
        self,
    ) -> None:
        message_id = self.notice(
            idempotency_key="reserved-child-pending", issue_number=1571
        )
        target_key = str(message_id)
        intent_at = "2026-09-02T22:30:00Z"
        invocation_id = "6" * 32
        fence = executor_registry_module.snapshot_role_executor_child_ack_fence(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=target_key,
        )
        expectation = (
            executor_registry_module.bind_role_executor_child_ack_expectation(
                fence,
                systemd_unit=stable_systemd_unit(
                    "development", "message", target_key
                ),
                systemd_invocation_id=invocation_id,
                intent_recorded_at=intent_at,
                manager_receipt_sha256=(
                    role_executor_transport_module.RoleExecutorManagerSubmission(
                        systemd_unit=stable_systemd_unit(
                            "development", "message", target_key
                        ),
                        systemd_invocation_id=invocation_id,
                    ).receipt_sha256
                ),
                observation_deadline_at=(
                    coordination_store_module.timestamp_after(intent_at, 10)
                ),
            )
        )
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=target_key,
            now=intent_at,
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", target_key
            ),
        )

        self.assertIsNone(
            executor_registry_module.observe_role_executor_child_ack(
                self.store.connection,
                expectation=expectation,
                not_after=intent_at,
            )
        )
        unit = stable_systemd_unit("development", "message", target_key)
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=invocation_id,
            systemd_control_group=f"/user.slice/{unit}",
            now=intent_at,
        )
        self.assertIsNone(
            executor_registry_module.observe_role_executor_child_ack(
                self.store.connection,
                expectation=expectation,
                not_after=intent_at,
            )
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=8571,
            now=intent_at,
        )
        acknowledgement = (
            executor_registry_module.observe_role_executor_child_ack(
                self.store.connection,
                expectation=expectation,
                not_after=intent_at,
            )
        )

        self.assertIsNotNone(acknowledgement)
        self.assertEqual(running["attempt_id"], acknowledgement.attempt_id)
        self.assertEqual(running["instance_id"], acknowledgement.instance_id)
        self.assertEqual(running["token_sha256"], acknowledgement.token_sha256)
        self.assertEqual(8571, acknowledgement.process_id)
        self.assertEqual(
            digest_json(
                {
                    "schema": (
                        "twinfinity-role-executor-execution-ownership/v1"
                    ),
                    "attempt_id": running["attempt_id"],
                    "broker_table_present": False,
                    "broker_ownership_rows": [],
                }
            ),
            acknowledgement.execution_ownership_sha256,
        )

    def test_child_ack_enforces_bound_deadline_and_observation_instant(
        self,
    ) -> None:
        cases = (
            (
                "post-deadline",
                "2026-09-02T22:31:00Z",
                2,
                (0, 1, 3),
                3,
                "EXECUTOR_CHILD_ACK_EXPIRED",
            ),
            (
                "future-at-observation",
                "2026-09-02T22:32:00Z",
                10,
                (1, 1, 1),
                0,
                "EXECUTOR_CHILD_ACK_SUBSTITUTED",
            ),
        )
        for ordinal, (
            label,
            intent_at,
            deadline_seconds,
            child_seconds,
            observed_seconds,
            expected_error,
        ) in enumerate(cases, 1):
            with self.subTest(label=label):
                message_id = self.notice(
                    idempotency_key=f"child-window-{label}",
                    issue_number=1571 + ordinal,
                )
                target_key = str(message_id)
                invocation_id = str(6 + ordinal) * 32
                fence = (
                    executor_registry_module.snapshot_role_executor_child_ack_fence(
                        self.store.connection,
                        role="development",
                        endpoint_id=DEVELOPMENT_SESSION,
                        target_kind="message",
                        target_key=target_key,
                    )
                )
                expectation = (
                    executor_registry_module.bind_role_executor_child_ack_expectation(
                        fence,
                        systemd_unit=stable_systemd_unit(
                            "development", "message", target_key
                        ),
                        systemd_invocation_id=invocation_id,
                        intent_recorded_at=intent_at,
                        manager_receipt_sha256=(
                            role_executor_transport_module.RoleExecutorManagerSubmission(
                                systemd_unit=stable_systemd_unit(
                                    "development", "message", target_key
                                ),
                                systemd_invocation_id=invocation_id,
                            ).receipt_sha256
                        ),
                        observation_deadline_at=(
                            coordination_store_module.timestamp_after(
                                intent_at, deadline_seconds
                            )
                        ),
                    )
                )
                self.seed_role_executor_child(
                    role="development",
                    endpoint_id=DEVELOPMENT_SESSION,
                    target_kind="message",
                    target_key=target_key,
                    invocation_id=invocation_id,
                    process_id=8580 + ordinal,
                    reserved_at=coordination_store_module.timestamp_after(
                        intent_at, child_seconds[0]
                    ),
                    launching_at=coordination_store_module.timestamp_after(
                        intent_at, child_seconds[1]
                    ),
                    running_at=coordination_store_module.timestamp_after(
                        intent_at, child_seconds[2]
                    ),
                    terminal_state=None,
                )
                with self.assertRaisesRegex(
                    RegistryError, f"^{expected_error}$"
                ):
                    executor_registry_module.observe_role_executor_child_ack(
                        self.store.connection,
                        expectation=expectation,
                        not_after=coordination_store_module.timestamp_after(
                            intent_at, observed_seconds
                        ),
                    )

    def test_direct_child_with_broker_ownership_is_never_launch_evidence(
        self,
    ) -> None:
        message_id = self.notice(
            idempotency_key="broker-owned-direct-child", issue_number=1574
        )
        target_key = str(message_id)
        invocation_id = "9" * 32

        def broker_owned_launcher(session_id: str, _message: int):
            child, _token = self.seed_role_executor_child(
                role="development",
                endpoint_id=session_id,
                target_kind="message",
                target_key=target_key,
                invocation_id=invocation_id,
                process_id=8590,
            )
            self.store.connection.execute(
                "CREATE TABLE role_executor_broker_runs(attempt_id TEXT PRIMARY KEY)"
            )
            self.store.connection.execute(
                "INSERT INTO role_executor_broker_runs(attempt_id) VALUES (?)",
                (child["attempt_id"],),
            )
            return role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(
                    "development", "message", target_key
                ),
                systemd_invocation_id=invocation_id,
            )

        result = CoordinationSupervisor(
            self.store,
            launcher=broker_owned_launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_args: False,
            child_ack_timeout_seconds=0,
        ).run_once("2026-09-02T22:34:00Z")

        self.assertEqual([], result["launched"])
        wake = self.store.connection.execute(
            "SELECT wake_key,state,process_id,last_error FROM coordination_wakes "
            "WHERE message_id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(
            ("HOLD", None, coordination_supervisor_module.CHILD_ACK_REJECTED),
            tuple(wake)[1:],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='SESSION_WAKE_STARTED' AND entity_key=?",
                (wake["wake_key"],),
            ).fetchone()[0],
        )
        intent, _envelope = self.manager_intent_event(
            target_kind="message", target_key=target_key
        )
        receipt = self.manager_submission_events_for_intent(
            target_kind="message", intent_event_key=str(intent["entity_key"])
        )[0][0]
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='SESSION_WAKE_CHILD_ACK_REJECTED' AND entity_key=?",
                (receipt["entity_key"],),
            ).fetchone()[0],
        )

    def test_child_ack_rejects_preintent_and_regressing_event_timestamps(
        self,
    ) -> None:
        cases = (
            (
                "pre-intent",
                "2026-09-02T22:50:00Z",
                (
                    "2026-09-02T22:49:57Z",
                    "2026-09-02T22:49:58Z",
                    "2026-09-02T22:49:59Z",
                ),
            ),
            (
                "regressing",
                "2026-09-02T22:51:00Z",
                (
                    "2026-09-02T22:51:03Z",
                    "2026-09-02T22:51:02Z",
                    "2026-09-02T22:51:01Z",
                ),
            ),
        )
        for ordinal, (label, observed_at, event_times) in enumerate(cases, 1):
            with self.subTest(label=label):
                message_id = self.notice(
                    idempotency_key=f"child-time-{label}",
                    issue_number=1570 + ordinal,
                )
                target_key = str(message_id)
                invocation_id = (str(ordinal + 4) * 32)[:32]

                calls = 0

                def invalid_time_launcher(session_id: str, _message: int):
                    nonlocal calls
                    calls += 1
                    self.seed_role_executor_child(
                        role="development",
                        endpoint_id=session_id,
                        target_kind="message",
                        target_key=target_key,
                        invocation_id=invocation_id,
                        process_id=8455 + ordinal,
                        reserved_at=event_times[0],
                        launching_at=event_times[1],
                        running_at=event_times[2],
                        terminal_state=None,
                    )
                    return role_executor_transport_module.RoleExecutorManagerSubmission(
                        systemd_unit=stable_systemd_unit(
                            "development", "message", target_key
                        ),
                        systemd_invocation_id=invocation_id,
                    )

                supervisor = CoordinationSupervisor(
                    self.store,
                    launcher=invalid_time_launcher,
                    terminal_watch_launcher=lambda *_args: self.fail(
                        "terminal watcher must not launch"
                    ),
                    process_checker=lambda *_args: False,
                    child_ack_timeout_seconds=0,
                )
                result = supervisor.run_once(observed_at)
                supervisor.run_once(
                    coordination_store_module.timestamp_after(observed_at, 1)
                )

                self.assertEqual([], result["launched"])
                self.assertEqual(1, calls)
                wake = self.store.connection.execute(
                    "SELECT wake_key,state,process_id FROM coordination_wakes "
                    "WHERE message_id=?",
                    (message_id,),
                ).fetchone()
                self.assertEqual("HOLD", wake["state"])
                self.assertIsNone(wake["process_id"])
                intent, envelope = self.manager_intent_event(
                    target_kind="message", target_key=target_key
                )
                self.assertEqual(observed_at, intent["created_at"])
                self.assertEqual(wake["wake_key"], envelope["target_entity_key"])
                self.assertEqual(
                    0,
                    self.store.connection.execute(
                        "SELECT COUNT(*) FROM coordination_events WHERE "
                        "event_type='SESSION_WAKE_STARTED' AND entity_key=?",
                        (wake["wake_key"],),
                    ).fetchone()[0],
                )
                for receipt, _receipt_envelope in (
                    self.manager_submission_events_for_intent(
                        target_kind="message",
                        intent_event_key=str(intent["entity_key"]),
                    )
                ):
                    self.assertEqual(
                        0,
                        self.store.connection.execute(
                            "SELECT COUNT(*) FROM coordination_events WHERE "
                            "event_type='SESSION_WAKE_CHILD_ACK_ACCEPTED' "
                            "AND entity_key=?",
                            (receipt["entity_key"],),
                        ).fetchone()[0],
                    )

    def test_integer_result_and_raw_token_never_become_launch_evidence(self) -> None:
        message_id = self.notice(
            idempotency_key="integer-launch-evidence", issue_number=157
        )
        calls = 0

        def integer_launcher(_session: str, _message: int) -> int:
            nonlocal calls
            calls += 1
            return 8157

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=integer_launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_args: False,
        )
        supervisor.run_once("2026-09-02T22:30:00Z")
        supervisor.run_once("2026-09-02T22:31:00Z")
        self.assertEqual(1, calls)
        self.assertEqual(
            ("HOLD", None),
            tuple(
                self.store.connection.execute(
                    "SELECT state,process_id FROM coordination_wakes "
                    "WHERE message_id=?",
                    (message_id,),
                ).fetchone()
            ),
        )

        protected_id = self.notice(
            idempotency_key="raw-token-redaction", issue_number=158
        )
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=str(protected_id),
            now="2026-09-02T22:40:00Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(protected_id)
            ),
        )
        held = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="HOLD",
            last_error=f"private:{token}:value",
            now="2026-09-02T22:40:01Z",
        )
        self.assertEqual(
            executor_registry_module.EXECUTOR_PRIVATE_ERROR_REDACTED,
            held["last_error"],
        )
        self.assertNotIn(token, "\n".join(self.store.connection.iterdump()))

    def test_integer_terminal_watch_result_is_never_launch_evidence(self) -> None:
        _source, _message_id, watch_key, _attempt, _token = (
            self.bound_development_admission(complete=True)
        )
        calls = 0

        def integer_launcher(_session: str, _watch_key: str) -> int:
            nonlocal calls
            calls += 1
            return 8255

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda *_args: self.fail("message launcher must not run"),
            terminal_watch_launcher=integer_launcher,
            process_checker=lambda *_args: False,
        )
        first = supervisor.run_once("2026-08-22T10:01:10Z")
        second = supervisor.run_once("2026-08-22T10:20:10Z")

        self.assertEqual([], first["terminal_watch_launches"])
        self.assertEqual([], second["terminal_watch_launches"])
        self.assertEqual(1, calls)
        watch = self.store.connection.execute(
            "SELECT state,process_id,last_error FROM "
            "coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(
            ("HOLD", None, coordination_supervisor_module.CHILD_ACK_AMBIGUOUS),
            tuple(watch),
        )
        intent, envelope = self.manager_intent_event(
            target_kind="terminal_watch", target_key=watch_key
        )
        self.assertEqual(watch_key, envelope["target_entity_key"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='TERMINAL_WATCH_MANAGER_SUBMISSION_ABANDONED' "
                "AND entity_key=?",
                (intent["entity_key"],),
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='TERMINAL_WATCH_WAKE_STARTED' AND entity_key=?",
                (watch_key,),
            ).fetchone()[0],
        )

    def test_submission_dispositions_are_exclusive_and_zero_cas_is_nonretiring(
        self,
    ) -> None:
        def prepared_target(issue_number: int, suffix: str):
            message_id = self.notice(
                idempotency_key=f"intent-disposition-{suffix}",
                issue_number=issue_number,
            )
            message = self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()
            wake_key, should_launch = self.supervisor._reserve_wake(
                message, f"2026-09-02T23:0{suffix}:00Z"
            )
            self.assertTrue(should_launch)
            reservation = dict(
                self.store.connection.execute(
                    "SELECT * FROM coordination_wakes WHERE wake_key=?",
                    (wake_key,),
                ).fetchone()
            )
            fence = executor_registry_module.snapshot_role_executor_child_ack_fence(
                self.store.connection,
                role="development",
                endpoint_id=DEVELOPMENT_SESSION,
                target_kind="message",
                target_key=str(message_id),
            )
            now = f"2026-09-02T23:0{suffix}:01Z"
            intent_key = self.supervisor._record_submission_intent(
                entity_key=wake_key,
                target_kind="message",
                fence=fence,
                reservation=reservation,
                now=now,
            )
            expectation = executor_registry_module.bind_role_executor_child_ack_expectation(
                fence,
                systemd_unit=stable_systemd_unit(
                    "development", "message", str(message_id)
                ),
                systemd_invocation_id=(suffix * 32)[:32],
                intent_recorded_at=now,
                manager_receipt_sha256=(
                    role_executor_transport_module.RoleExecutorManagerSubmission(
                        systemd_unit=stable_systemd_unit(
                            "development", "message", str(message_id)
                        ),
                        systemd_invocation_id=(suffix * 32)[:32],
                    ).receipt_sha256
                ),
            )
            return message_id, wake_key, intent_key, expectation

        _message, wake_key, intent_key, expectation = prepared_target(159, "1")
        receipt_key = self.supervisor._record_manager_submission(
            entity_key=wake_key,
            target_kind="message",
            intent_event_key=intent_key,
            expectation=expectation,
            now="2026-09-02T23:01:02Z",
        )
        with self.assertRaisesRegex(
            CoordinationError, "^ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT$"
        ):
            self.supervisor._record_unbound_submission_not_submitted(
                intent_event_key=intent_key,
                target_kind="message",
                entity_key=wake_key,
                now="2026-09-02T23:01:03Z",
            )
        submitted = self.manager_submission_events_for_intent(
            target_kind="message", intent_event_key=intent_key
        )
        self.assertEqual(1, len(submitted))
        self.assertEqual(receipt_key, submitted[0][0]["entity_key"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='SESSION_WAKE_MANAGER_SUBMISSION_ABANDONED' "
                "AND entity_key=?",
                (intent_key,),
            ).fetchone()[0],
        )

        _message, wake_key, intent_key, expectation = prepared_target(160, "2")
        self.supervisor._record_unbound_submission_not_submitted(
            intent_event_key=intent_key,
            target_kind="message",
            entity_key=wake_key,
            now="2026-09-02T23:02:02Z",
        )
        with self.assertRaisesRegex(
            CoordinationError, "^ROLE_EXECUTOR_SUBMISSION_DISPOSITION_CONFLICT$"
        ):
            self.supervisor._record_manager_submission(
                entity_key=wake_key,
                target_kind="message",
                intent_event_key=intent_key,
                expectation=expectation,
                now="2026-09-02T23:02:03Z",
            )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='SESSION_WAKE_MANAGER_SUBMISSION_ABANDONED' "
                "AND entity_key=?",
                (intent_key,),
            ).fetchone()[0],
        )
        self.assertEqual(
            [],
            self.manager_submission_events_for_intent(
                target_kind="message", intent_event_key=intent_key
            ),
        )

        _message, wake_key, intent_key, expectation = prepared_target(161, "3")
        self.store.connection.execute(
            "UPDATE coordination_wakes SET state='HOLD',last_error='NEWER_STATE' "
            "WHERE wake_key=?",
            (wake_key,),
        )
        with self.assertRaisesRegex(
            CoordinationError, "^ROLE_EXECUTOR_SUBMISSION_TARGET_DRIFT$"
        ):
            self.supervisor._record_manager_submission(
                entity_key=wake_key,
                target_kind="message",
                intent_event_key=intent_key,
                expectation=expectation,
                now="2026-09-02T23:03:02Z",
            )
        self.assertEqual(
            [],
            self.manager_submission_events_for_intent(
                target_kind="message", intent_event_key=intent_key
            ),
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE event_type IN "
                "('SESSION_WAKE_MANAGER_SUBMISSION_ABANDONED',"
                "'SESSION_WAKE_MANAGER_SUBMISSION_AMBIGUOUS') "
                "AND entity_key=?",
                (intent_key,),
            ).fetchone()[0],
        )

    def test_user_bus_identity_rejects_a_mocked_unsafe_runtime_directory(self) -> None:
        effective_uid = os.geteuid()
        runtime_root = Path("/synthetic/run/user")

        def metadata(path: Path, *, unsafe: bool = False):
            is_bus = path.name == "bus"
            mode = (
                stat.S_IFSOCK | 0o600
                if is_bus
                else stat.S_IFDIR
                | (0o770 if unsafe and path.name == str(effective_uid) else 0o700)
            )
            return SimpleNamespace(
                st_dev=1,
                st_ino=3 if is_bus else 2,
                st_mode=mode,
                st_uid=effective_uid,
                st_nlink=1,
            )

        with patch.object(Path, "lstat", new=lambda path: metadata(path)):
            context = role_executor_user_bus_context(
                effective_uid, runtime_root=runtime_root
            )
        self.assertEqual(effective_uid, context.effective_uid)
        self.assertEqual(5, len(context.bus_identity))
        with patch.object(
            Path,
            "lstat",
            new=lambda path: metadata(path, unsafe=True),
        ):
            with self.assertRaisesRegex(
                RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED}$"
            ):
                context = role_executor_user_bus_context(
                    effective_uid, runtime_root=runtime_root
                )

    def test_source_current_registry_identity_attests_with_mocked_manager(self) -> None:
        directory = Path(self.temp.name) / "source-current-coordinator"
        directory.mkdir(mode=0o700)
        store = CoordinationStore(directory / "state.sqlite3")
        self.addCleanup(store.close)
        config = load_registry_config(
            ROOT / "references" / "twinfinity-executor-registry.toml"
        )
        aliases, alias_sha = load_legacy_alias_fixture(
            ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
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
            operation_key="transport-source-current-test",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-09-02T04:59:59Z",
        )
        effective_uid = os.geteuid()
        preflight = build_role_executor_transport_preflight(
            store.connection, effective_uid=effective_uid
        )
        response = (
            "Architecture=x86-64\n"
            f"ControlGroup=/user.slice/user-{effective_uid}.slice/"
            f"user@{effective_uid}.service\n"
            "SystemState=running\n"
            "UserspaceTimestampMonotonic=123456\n"
            "Version=257.7\n"
        ).encode()
        attestation = attest_role_executor_transport(
            preflight,
            runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 0, stdout=response, stderr=b""
            ),
            euid_reader=lambda: effective_uid,
            user_bus_reader=lambda _uid: self.user_bus_context(effective_uid),
        )

        self.assertEqual("PASS", attestation.status)
        self.assertEqual(
            ("role.development.v6", "role.planner.v3", "role.sre.v6"),
            tuple(identity.endpoint_id for identity in preflight.endpoint_identities),
        )

    def test_transport_attestor_rejects_outage_timeout_ambiguity_malformed_and_substitution(
        self,
    ) -> None:
        effective_uid = os.geteuid()
        preflight = build_role_executor_transport_preflight(
            self.store.connection, effective_uid=effective_uid
        )
        load = self.transport_config_loader(preflight)
        valid = (
            "Architecture=x86-64\n"
            f"ControlGroup=/user.slice/user-{effective_uid}.slice/"
            f"user@{effective_uid}.service\n"
            "SystemState=running\n"
            "UserspaceTimestampMonotonic=123456\n"
            "Version=257.7\n"
        ).encode()
        user_bus = self.user_bus_context(effective_uid)

        def completed(stdout: object, *, returncode: int = 0, stderr: object = b""):
            return lambda command, **_kwargs: subprocess.CompletedProcess(
                command, returncode, stdout=stdout, stderr=stderr
            )

        def timeout(command, **_kwargs):
            raise subprocess.TimeoutExpired(command, 5)

        def unavailable(_command, **_kwargs):
            raise OSError("private host detail")

        cases = (
            (ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE, unavailable, load),
            (ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE, completed(valid, returncode=1), load),
            (ROLE_EXECUTOR_TRANSPORT_TIMED_OUT, timeout, load),
            (
                ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS,
                completed(valid + b"Version=257.7\n"),
                load,
            ),
            (
                ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS,
                completed(valid + b"Unexpected=value\n"),
                load,
            ),
            (
                ROLE_EXECUTOR_TRANSPORT_MALFORMED,
                completed(valid.replace(b"Version=257.7\n", b"")),
                load,
            ),
            (ROLE_EXECUTOR_TRANSPORT_MALFORMED, completed("not-bytes"), load),
            (
                ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED,
                completed(
                    valid.replace(
                        f"user-{effective_uid}.slice/user@{effective_uid}.service".encode(),
                        f"user-{effective_uid + 1}.slice/user@{effective_uid + 1}.service".encode(),
                    )
                ),
                load,
            ),
        )
        for expected, runner, loader in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(
                RegistryError, f"^{expected}$"
            ):
                attest_role_executor_transport(
                    preflight,
                    runner=runner,
                    config_loader=loader,
                    euid_reader=lambda: effective_uid,
                    user_bus_reader=lambda _uid: user_bus,
                )

        transport_calls: list[str] = []

        def must_not_probe(_command, **_kwargs):
            transport_calls.append("called")
            return subprocess.CompletedProcess(_command, 0, stdout=valid, stderr=b"")

        with self.assertRaisesRegex(
            RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED}$"
        ):
            attest_role_executor_transport(
                preflight,
                runner=must_not_probe,
                config_loader=load,
                euid_reader=lambda: effective_uid + 1,
                user_bus_reader=lambda _uid: user_bus,
            )
        with self.assertRaisesRegex(
            RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE}$"
        ):
            attest_role_executor_transport(
                preflight,
                runner=must_not_probe,
                config_loader=load,
                euid_reader=lambda: effective_uid,
                user_bus_reader=lambda _uid: (_ for _ in ()).throw(
                    RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE)
                ),
            )
        self.assertEqual([], transport_calls)

        original = load(None, selected_current_endpoint_id=PLANNER_SESSION)
        configured = original.roles["planner"]
        substituted = SimpleNamespace(
            source_sha256=original.source_sha256,
            roles={
                "planner": SimpleNamespace(
                    **{
                        **configured.__dict__,
                        "profile_sha256": "f" * 64,
                    }
                )
            },
        )

        def substituted_loader(path, *, selected_current_endpoint_id):
            if selected_current_endpoint_id == PLANNER_SESSION:
                return substituted
            return load(path, selected_current_endpoint_id=selected_current_endpoint_id)

        with self.assertRaisesRegex(
            RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED}$"
        ):
            attest_role_executor_transport(
                preflight,
                runner=completed(valid),
                config_loader=substituted_loader,
                euid_reader=lambda: effective_uid,
                user_bus_reader=lambda _uid: user_bus,
            )

        user_buses = iter(
            (user_bus, self.user_bus_context(effective_uid, generation=2))
        )
        with self.assertRaisesRegex(
            RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED}$"
        ):
            attest_role_executor_transport(
                preflight,
                runner=completed(valid),
                config_loader=load,
                euid_reader=lambda: effective_uid,
                user_bus_reader=lambda _uid: next(user_buses),
            )

        identity = preflight.endpoint_identities[0]
        substituted_requests = (
            replace(preflight, source_body_sha256="f" * 64),
            replace(
                preflight,
                endpoint_identities=(
                    replace(identity, endpoint_config_sha256="f" * 64),
                    *preflight.endpoint_identities[1:],
                ),
            ),
            replace(
                preflight,
                endpoint_identities=(
                    replace(identity, registered_launch_sha256="f" * 64),
                    *preflight.endpoint_identities[1:],
                ),
            ),
        )
        for substituted_request in substituted_requests:
            with self.subTest(
                request=substituted_request.request_sha256
            ), self.assertRaisesRegex(
                RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED}$"
            ):
                attest_role_executor_transport(
                    substituted_request,
                    runner=completed(valid),
                    config_loader=load,
                    euid_reader=lambda: effective_uid,
                    user_bus_reader=lambda _uid: user_bus,
                )

        stale_request = replace(preflight, source_body_sha256="e" * 64)
        stale_attestation = RoleExecutorTransportAttestation.pass_for(
            stale_request, user_manager_identity_sha256="b" * 64
        )
        with self.assertRaisesRegex(
            RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED}$"
        ):
            validate_role_executor_transport_attestation(
                preflight, stale_attestation
            )
        malformed_attestation = replace(
            self.successful_transport(preflight),
            user_manager_identity_sha256=None,
        )
        with self.assertRaisesRegex(
            RegistryError, f"^{ROLE_EXECUTOR_TRANSPORT_MALFORMED}$"
        ):
            validate_role_executor_transport_attestation(
                preflight, malformed_attestation
            )

    def test_transport_failures_preserve_targets_and_notice_is_private_stable_replay(
        self,
    ) -> None:
        source_body = "synthetic exact harness issue 149 body"
        source_body_sha256 = hashlib.sha256(source_body.encode()).hexdigest()
        source = self.seed_transport_notice_source(source_body)
        message_id = self.notice(idempotency_key="preflight-failure-target", issue_number=150)
        original_message = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()
        )
        failure_codes = (
            ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE,
            ROLE_EXECUTOR_TRANSPORT_TIMED_OUT,
            ROLE_EXECUTOR_TRANSPORT_AMBIGUOUS,
            ROLE_EXECUTOR_TRANSPORT_MALFORMED,
            ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED,
        )

        with patch(
            "role_executor_transport.TRANSPORT_PREFLIGHT_SOURCE_BODY_SHA256",
            source_body_sha256,
        ):
            for index, code in enumerate(failure_codes):
                with self.subTest(code=code):
                    before = self.non_notice_database_state(self.store.connection)
                    message_count = self.store.connection.execute(
                        "SELECT COUNT(*) FROM coordination_messages"
                    ).fetchone()[0]
                    event_count = self.store.connection.execute(
                        "SELECT COUNT(*) FROM coordination_events"
                    ).fetchone()[0]

                    def fail(_preflight, reason=code):
                        raise RegistryError(reason)

                    supervisor = CoordinationSupervisor(
                        self.store,
                        launcher=lambda *_args: self.fail("launcher must not run"),
                        terminal_watch_launcher=lambda *_args: self.fail(
                            "terminal-watch launcher must not run"
                        ),
                        process_checker=lambda *_: False,
                        transport_preflight=fail,
                    )
                    result = supervisor.run_once(f"2026-09-02T05:0{index}:00Z")
                    after = self.non_notice_database_state(self.store.connection)

                    self.assertEqual(code, result["reason"])
                    self.assertEqual(before, after)
                    self.assertEqual(
                        original_message,
                        dict(
                            self.store.connection.execute(
                                "SELECT * FROM coordination_messages WHERE id=?",
                                (message_id,),
                            ).fetchone()
                        ),
                    )
                    notice = self.store.connection.execute(
                        "SELECT * FROM coordination_messages WHERE id=?",
                        (result["notice_message_id"],),
                    ).fetchone()
                    payload = json.loads(notice["payload_json"])
                    self.assertEqual(
                        {
                            "source",
                            "notice_kind",
                            "mutation_authority",
                            "subject",
                            "summary",
                            "evidence",
                            "next_observation",
                        },
                        set(payload),
                    )
                    self.assertEqual(
                        {"repository", "object_kind", "object_number", "payload_sha256"},
                        set(payload["source"]),
                    )
                    self.assertEqual(
                        {
                            "schema",
                            "reason",
                            "source_body_sha256",
                            "endpoint_identity_sha256",
                            "profile_identity_sha256",
                            "registry_config_sha256",
                            "transport_runner_sha256",
                            "registered_launch_sha256",
                            "transport_configuration_sha256",
                            "transport_probe_sha256",
                        },
                        set(payload["evidence"]),
                    )
                    self.assertEqual(PLANNER_SESSION, notice["recipient_session_id"])
                    self.assertEqual("coordination.notice", notice["topic"])
                    self.assertIs(payload["mutation_authority"], False)
                    self.assertEqual(source.payload_sha256, payload["source"]["payload_sha256"])
                    self.assertEqual(code, payload["evidence"]["reason"])
                    self.assertEqual(
                        message_count + 1,
                        self.store.connection.execute(
                            "SELECT COUNT(*) FROM coordination_messages"
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        event_count + 1,
                        self.store.connection.execute(
                            "SELECT COUNT(*) FROM coordination_events"
                        ).fetchone()[0],
                    )
                    rendered = notice["payload_json"]
                    for forbidden in (
                        "private host detail",
                        "2026-09-02T05:",
                        '"message_id"',
                        '"object_number":150',
                        str(self.store.path),
                        "DBUS_SESSION_BUS_ADDRESS",
                        "credential",
                    ):
                        self.assertNotIn(forbidden, rendered)

                    replay_before = list(self.store.connection.iterdump())
                    replay = supervisor.run_once(f"2026-09-02T06:0{index}:00Z")
                    self.assertEqual(result["notice_message_id"], replay["notice_message_id"])
                    self.assertEqual(replay_before, list(self.store.connection.iterdump()))

    def test_endpoint_rotation_after_pass_is_substitution_before_target_write(self) -> None:
        message_id = self.notice(
            idempotency_key="preflight-endpoint-rebound", issue_number=153
        )
        original_message = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()
        )
        calls = 0

        def rotate_after_pass(preflight):
            nonlocal calls
            calls += 1
            with self.store.transaction():
                self.store.connection.execute(
                    """
                    UPDATE executor_role_endpoint_current
                    SET pointer_version=pointer_version+1, updated_at=?
                    WHERE role='development'
                    """,
                    ("2026-09-02T05:20:01Z",),
                )
            return self.successful_transport(preflight)

        result = CoordinationSupervisor(
            self.store,
            launcher=lambda *_args: self.fail("launcher must not run"),
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal-watch launcher must not run"
            ),
            process_checker=lambda *_: False,
            transport_preflight=rotate_after_pass,
        ).run_once("2026-09-02T05:20:00Z")

        self.assertEqual(1, calls)
        self.assertEqual(ROLE_EXECUTOR_TRANSPORT_SUBSTITUTED, result["reason"])
        self.assertIsNone(result["notice_message_id"])
        self.assertEqual(
            original_message,
            dict(
                self.store.connection.execute(
                    "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
                ).fetchone()
            ),
        )
        self.assertIsNone(
            self.store.connection.execute(
                "SELECT * FROM coordination_wakes WHERE message_id=?", (message_id,)
            ).fetchone()
        )

    def test_concurrent_supervisors_share_one_notice_and_preserve_both_targets(self) -> None:
        source_body = "synthetic concurrent harness issue 149 body"
        source_body_sha256 = hashlib.sha256(source_body.encode()).hexdigest()
        source = self.seed_transport_notice_source(source_body)
        message_id = self.notice(idempotency_key="preflight-concurrent-target", issue_number=151)
        hosted = HostedOperationControl(self.store.path)
        hosted.close()
        with self.store.transaction():
            hosted_id = self.store.connection.execute(
                """
                INSERT INTO hosted_operations(
                    idempotency_key,repository,object_kind,issue_number,
                    source_payload_sha256,provider,target_kind,target_key,
                    operation_kind,authority_comment_id,authority_body_sha256,
                    scope_sha256,scope_json,recipient_session_id,sre_units,
                    state,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "preflight-concurrent-hosted-target",
                    "jayendusharma/twinfinity-harness",
                    "issue",
                    149,
                    source.payload_sha256,
                    "github",
                    "github_ruleset",
                    "synthetic-ruleset",
                    "UPDATE_SETTINGS",
                    1490,
                    "a" * 64,
                    "b" * 64,
                    "{}",
                    SRE_SESSION,
                    1,
                    "PREPARED",
                    "2026-09-02T05:00:00Z",
                    "2026-09-02T05:00:00Z",
                ),
            ).lastrowid
        original_message = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
            ).fetchone()
        )
        message_count = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_messages"
        ).fetchone()[0]
        event_count = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_events"
        ).fetchone()[0]
        original_hosted = dict(
            self.store.connection.execute(
                "SELECT * FROM hosted_operations WHERE id=?", (hosted_id,)
            ).fetchone()
        )
        barrier = threading.Barrier(2)
        initialized = threading.Barrier(3)
        start = threading.Event()

        def fail(_preflight):
            barrier.wait(timeout=5)
            raise RegistryError(ROLE_EXECUTOR_TRANSPORT_UNAVAILABLE)

        def run_failure(ordinal: int) -> dict[str, object]:
            if ordinal == 0:
                store = CoordinationStore(self.store.path)
                supervisor = CoordinationSupervisor(
                    store,
                    launcher=lambda *_args: 1,
                    terminal_watch_launcher=lambda *_args: 1,
                    process_checker=lambda *_: False,
                    transport_preflight=fail,
                )
                initialized.wait(timeout=5)
                start.wait(timeout=5)
                try:
                    return supervisor.run_once("2026-09-02T05:30:00Z")
                finally:
                    store.close()
            control = HostedOperationControl(self.store.path)
            initialized.wait(timeout=5)
            start.wait(timeout=5)
            try:
                return run_hosted_supervisor(
                    control,
                    "2026-09-02T05:30:00Z",
                    launcher=lambda **_kwargs: 1,
                    transport_preflight=fail,
                )
            finally:
                control.close()

        with patch(
            "role_executor_transport.TRANSPORT_PREFLIGHT_SOURCE_BODY_SHA256",
            source_body_sha256,
        ), ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run_failure, ordinal) for ordinal in range(2)]
            initialized.wait(timeout=5)
            before = self.non_notice_database_state(self.store.connection)
            start.set()
            results = [future.result(timeout=10) for future in futures]

        self.assertEqual(before, self.non_notice_database_state(self.store.connection))
        self.assertEqual(
            original_message,
            dict(
                self.store.connection.execute(
                    "SELECT * FROM coordination_messages WHERE id=?", (message_id,)
                ).fetchone()
            ),
        )
        self.assertEqual(
            original_hosted,
            dict(
                self.store.connection.execute(
                    "SELECT * FROM hosted_operations WHERE id=?", (hosted_id,)
                ).fetchone()
            ),
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE id<>? AND topic='coordination.notice' AND "
                "json_extract(payload_json,'$.subject')='Role transport preflight unavailable'",
                (message_id,),
            ).fetchone()[0],
        )
        self.assertEqual(1, len({result["notice_message_id"] for result in results}))
        self.assertEqual(
            message_count + 1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages"
            ).fetchone()[0],
        )
        self.assertEqual(
            event_count + 1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events"
            ).fetchone()[0],
        )

    def test_successful_preflight_is_not_child_launch_success(self) -> None:
        message_id = self.notice(idempotency_key="preflight-not-child-success", issue_number=152)

        def fail_launch(_endpoint: str, _message_id: int) -> int:
            raise role_executor_transport_module.RoleExecutorManagerNotSubmitted()

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=fail_launch,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_: False,
            transport_preflight=self.successful_transport,
        )
        result = supervisor.run_once("2026-09-02T05:45:00Z")

        self.assertEqual([], result["launched"])
        self.assertEqual(
            ("INFLIGHT", 1, "WAKE_LAUNCH_FAILED"),
            tuple(
                self.store.connection.execute(
                    "SELECT state,attempts,last_error FROM coordination_wakes "
                    "WHERE message_id=?",
                    (message_id,),
                ).fetchone()
            ),
        )
        self.assertEqual(
            0,
            self.store.connection.execute("SELECT COUNT(*) FROM executor_attempts").fetchone()[0],
        )

    def seed_current_graph(self, source_sha256: str) -> None:
        main_sha = "a" * 40
        current = self.store.connection.execute(
            "SELECT observed_main_sha,health FROM portfolio_graph_current "
            "WHERE repository=?",
            (REPOSITORY,),
        ).fetchone()
        if current is not None:
            self.assertEqual((main_sha, "CURRENT"), tuple(current))
            node = self.store.connection.execute(
                "SELECT source_payload_sha256 FROM portfolio_graph_nodes "
                "WHERE repository=? AND issue_number=92",
                (REPOSITORY,),
            ).fetchone()
            self.assertIsNotNone(node)
            self.assertEqual(source_sha256, node["source_payload_sha256"])
            return
        graph_sha = digest_json({"issue": 92, "source": source_sha256})
        self.store.connection.execute(
            "INSERT INTO portfolio_graph_revisions VALUES (?,?,NULL,?,?,?,?,?)",
            (
                REPOSITORY, 1, main_sha, graph_sha,
                '{"milestones":[]}', "[]", "2026-08-22T10:00:01Z",
            ),
        )
        self.store.connection.execute(
            """
            INSERT INTO portfolio_graph_nodes VALUES (
                ?,1,'issue-92',92,'DELIVERY','STANDALONE',NULL,NULL,NULL,
                'issue-92',0,1,1,1,1,1,0,?,'2026-08-22T10:00:01Z'
            )
            """,
            (REPOSITORY, source_sha256),
        )
        self.store.connection.execute(
            "INSERT INTO portfolio_graph_current VALUES (?,1,?,'CURRENT',?,NULL)",
            (REPOSITORY, main_sha, "2026-08-22T10:00:01Z"),
        )

    def activate_canonical_development_admission(
        self, source: object, *, suffix: str
    ) -> tuple[dict, int]:
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.seed_current_graph(source.payload_sha256)
        ready = finalize_canonical_ready_item(
            self.store,
            database=self.store.path,
            artifact_root=self.store.path.parent,
            repository=REPOSITORY,
            issue_number=92,
            source_payload_sha256=source.payload_sha256,
            accepted_main_sha="a" * 40,
            worker_role="development",
            worker_endpoint_id=DEVELOPMENT_SESSION,
            now="2026-08-22T10:00:03Z",
            suffix=suffix,
        )
        transaction = ready["admission_transaction"]
        _active, message_id = self.store.activate_admission(
            item=transaction["item"],
            message=transaction["message"],
            artifacts=transaction.get("artifacts"),
            now="2026-08-22T10:00:04Z",
        )
        return transaction["message"]["payload"], message_id

    def bound_development_admission(
        self, *, complete: bool
    ) -> tuple[object, int, str, object, str]:
        source = self.snapshot()
        _payload, message_id = self.activate_canonical_development_admission(
            source, suffix="supervisor-terminal-binding"
        )
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:1"
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-22T10:00:04Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(message_id)
            ),
        )
        unit = stable_systemd_unit("development", "message", str(message_id))
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="a" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-22T10:00:05Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9200,
            now="2026-08-22T10:00:06Z",
        )
        if complete:
            self.store.claim_message(
                message_id,
                DEVELOPMENT_SESSION,
                "2026-08-22T10:00:07Z",
                attempt_id=running["attempt_id"],
                executor_token=token,
            )
            # Historical pre-atomic-closeout rows can still be observed by the
            # supervisor.  Construct that legacy state directly; the public
            # completion API is intentionally fenced for current admissions.
            self.store.connection.execute(
                "UPDATE coordination_messages SET state='COMPLETE',updated_at=? "
                "WHERE id=? AND state='CLAIMED'",
                ("2026-08-22T10:00:08Z", message_id),
            )
            running = transition_attempt(
                self.store.connection,
                attempt_id=running["attempt_id"],
                token=token,
                expected_version=running["version"],
                new_state="COMPLETE",
                exit_code=0,
                now="2026-08-22T10:00:09Z",
            )
        return source, message_id, watch_key, running, token

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def snapshot(self):
        return self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={
                "number": 92,
                "title": "Issue 92",
                "updated_at": "2026-08-22T10:00:00Z",
            },
            source_updated_at="2026-08-22T10:00:00Z",
            fetched_at="2026-08-22T10:00:01Z",
        )

    def notice(
        self,
        *,
        idempotency_key: str,
        issue_number: int,
        recipient: str = DEVELOPMENT_SESSION,
        repository: str = REPOSITORY,
    ) -> int:
        source = self.store.ingest_snapshot(
            repository=repository,
            object_kind="issue",
            object_number=issue_number,
            payload={"number": issue_number, "title": idempotency_key},
            source_updated_at="2026-08-22T10:00:00Z",
            fetched_at="2026-08-22T10:00:01Z",
        )
        return self.store.enqueue_message(
            idempotency_key=idempotency_key,
            recipient_session_id=recipient,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": repository,
                    "object_kind": "issue",
                    "object_number": issue_number,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Supervisor launch policy",
                "summary": "Exercise a bounded transport selection.",
                "evidence": {},
            },
            now="2026-08-22T10:00:02Z",
        )

    def test_depth_and_resource_denials_create_no_target_wake_attempt_or_event(self) -> None:
        cases = (
            (
                '{"value":' + "[" * 50 + "0" + "]" * 50 + "}",
                "COORDINATION_ENVELOPE_DEPTH_EXCEEDED",
            ),
            (
                '{"value":[' + ",".join("0" for _ in range(8200)) + "]}",
                "COORDINATION_ENVELOPE_RESOURCE_LIMIT",
            ),
        )
        for index, (raw, expected_error) in enumerate(cases, start=1):
            with self.subTest(expected_error=expected_error):
                cursor = self.store.connection.execute(
                    "INSERT INTO coordination_messages(idempotency_key,"
                    "recipient_session_id,topic,payload_sha256,payload_json,state,"
                    "created_at,updated_at) VALUES (?,?,'coordination.notice',?,?,"
                    "'PREPARED',?,?)",
                    (
                        f"strict-supervisor-{index}",
                        PLANNER_SESSION,
                        "0" * 64,
                        raw,
                        "2026-08-22T10:00:02Z",
                        "2026-08-22T10:00:02Z",
                    ),
                )
                message_id = int(cursor.lastrowid)
                self.store.connection.commit()
                row = self.store.connection.execute(
                    "SELECT * FROM coordination_messages WHERE id=?",
                    (message_id,),
                ).fetchone()
                self.assertEqual(
                    expected_error, self.supervisor._message_contract_error(row)
                )
                before = list(self.store.connection.iterdump())
                with patch(
                    "coordination_supervisor.target_progress_digest",
                    side_effect=AssertionError("target progress must not run"),
                ):
                    self.assertEqual(
                        (None, False),
                        self.supervisor._reserve_wake(
                            row, "2026-08-22T10:00:03Z"
                        ),
                    )
                self.assertEqual(before, list(self.store.connection.iterdump()))
                self.assertEqual([], self.launches)
                self.assertEqual([], self.terminal_watch_launches)

    def test_default_liveness_query_reuses_store_and_aborts_before_reservation(self) -> None:
        message_id = self.notice(idempotency_key="liveness-query", issue_number=37)
        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
            terminal_watch_launcher=lambda _session, _watch: 1,
        )
        with patch(
            "coordination_supervisor.active_attempt_for_target", return_value=None
        ) as active_attempt:
            self.assertFalse(
                supervisor.process_checker(DEVELOPMENT_SESSION, "message", str(message_id))
            )
            self.assertFalse(
                supervisor.process_checker(DEVELOPMENT_SESSION, "message", str(message_id))
            )
        self.assertEqual(2, active_attempt.call_count)
        self.assertTrue(
            all(
                call.args[0] is self.store.connection
                for call in active_attempt.call_args_list
            )
        )

        with patch(
            "coordination_supervisor.active_attempt_for_target",
            side_effect=sqlite3.OperationalError("synthetic liveness failure"),
        ), self.assertRaises(sqlite3.OperationalError):
            supervisor.run_once("2026-08-22T10:00:03Z")
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?",
                (message_id,),
            ).fetchone()[0],
        )

    def test_convergence_deadline_and_pass_telemetry_are_output_only(self) -> None:
        calls: list[dict[str, object]] = []

        class EmptyConvergence:
            def consume_due(inner_self, **kwargs):
                calls.append(kwargs)
                return []

        ticks = iter((10.0, 12.0, 13.0))
        monotonic = lambda: next(ticks)
        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
            terminal_watch_launcher=lambda _session, _watch: 1,
            process_checker=lambda *_: False,
            convergence=EmptyConvergence(),
            monotonic=monotonic,
        )
        changes_before = self.store.connection.total_changes

        result = supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual(changes_before, self.store.connection.total_changes)
        self.assertEqual(17.0, calls[0]["deadline"])
        self.assertIs(monotonic, calls[0]["monotonic"])
        self.assertEqual(
            {
                "duration_seconds": 3.0,
                "selected": 0,
                "attempted": 0,
                "succeeded": 0,
                "failed": 0,
            },
            result["telemetry"],
        )

    def claimed_admission(self) -> tuple[object, int]:
        source = self.snapshot()
        _payload, message_id = self.activate_canonical_development_admission(
            source, suffix="claimed-retry"
        )
        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-22T10:00:03Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(message_id)
            ),
        )
        unit = stable_systemd_unit("development", "message", str(message_id))
        launching = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="b" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-22T10:00:03Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching["version"],
            new_state="RUNNING",
            process_id=9100,
            now="2026-08-22T10:00:03Z",
        )
        self.store.claim_message(
            message_id,
            DEVELOPMENT_SESSION,
            "2026-08-22T10:00:04Z",
            attempt_id=running["attempt_id"],
            executor_token=token,
        )
        transition_attempt(
            self.store.connection,
            attempt_id=running["attempt_id"],
            token=token,
            expected_version=running["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-22T10:00:04Z",
        )
        return source, message_id

    def test_due_terminal_watch_preempts_same_lineage_message_retry(self) -> None:
        _source, message_id = self.claimed_admission()

        first = self.supervisor.run_once("2026-08-22T10:00:05Z")
        early = self.supervisor.run_once("2026-08-22T10:00:30Z")
        retry = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], first["launched"])
        self.assertEqual([], early["launched"])
        self.assertEqual([], retry["launched"])
        self.assertEqual(1, len(retry["terminal_watch_launches"]))
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state, attempts FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("CLAIMED", None), tuple(observed))
        self.assertIsNone(wake)

    def test_claimed_retry_backoff_does_not_block_a_different_target(self) -> None:
        source, message_id = self.claimed_admission()
        first = self.supervisor.run_once("2026-08-22T10:00:05Z")
        newer_id = self.store.enqueue_message(
            idempotency_key="newer-same-recipient",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Different target remains schedulable",
                "summary": "The claimed admission backoff applies only to its exact target.",
                "evidence": {"predecessor_message_id": message_id},
            },
            now="2026-08-22T10:00:06Z",
        )

        cooling_down = self.supervisor.run_once("2026-08-22T10:00:30Z")

        self.assertEqual([], first["launched"])
        self.assertEqual(1, len(cooling_down["launched"]))
        self.assertEqual(
            [(DEVELOPMENT_SESSION, newer_id)],
            self.launches,
        )
        newer_wakes = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?", (newer_id,)
        ).fetchone()[0]
        self.assertEqual(1, newer_wakes)

    def test_claimed_source_drift_holds_message_and_terminates_wake(self) -> None:
        _source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={"number": 92, "title": "Changed after claim"},
            source_updated_at="2026-08-22T10:01:00Z",
            fetched_at="2026-08-22T10:01:01Z",
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(observed))
        self.assertIsNone(wake)

    def test_claimed_item_drift_holds_message_and_terminates_wake(self) -> None:
        source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        active = self.store.connection.execute(
            "SELECT version,lease_manifest_sha256 FROM coordination_items "
            "WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=active["lease_manifest_sha256"],
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:01:00Z",
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "MESSAGE_ITEM_STATE_MISMATCH"), tuple(observed))
        self.assertIsNone(wake)

    def test_claimed_schema_valid_payload_drift_holds_message_and_terminates_wake(self) -> None:
        _source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        self.store.connection.execute(
            "DROP TRIGGER coordination_message_envelope_immutable"
        )
        row = self.store.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["base_sha"] = "b" * 40
        self.store.connection.execute(
            "UPDATE coordination_messages SET payload_json=? WHERE id=?",
            (canonical_json(payload), message_id),
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "MESSAGE_PAYLOAD_MISMATCH"), tuple(observed))
        self.assertIsNone(wake)

    def test_claimed_retry_rejects_payload_and_digest_rebinding(self) -> None:
        _source, message_id = self.claimed_admission()
        self.supervisor.run_once("2026-08-22T10:00:05Z")
        self.store.connection.execute(
            "DROP TRIGGER coordination_message_envelope_immutable"
        )
        row = self.store.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["base_sha"] = "b" * 40
        self.store.connection.execute(
            "UPDATE coordination_messages SET payload_json=?, payload_sha256=? WHERE id=?",
            (canonical_json(payload), digest_json(payload), message_id),
        )

        result = self.supervisor.run_once("2026-08-22T10:01:06Z")

        self.assertEqual([], result["launched"])
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        wake = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:claimed",),
        ).fetchone()
        self.assertEqual(("HOLD", "MESSAGE_PAYLOAD_MISMATCH"), tuple(observed))
        self.assertIsNone(wake)

    def test_claimed_envelope_cannot_rebind_before_first_wake(self) -> None:
        _source, message_id = self.claimed_admission()
        row = self.store.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["base_sha"] = "b" * 40

        with self.assertRaisesRegex(sqlite3.IntegrityError, "MESSAGE_ENVELOPE_IMMUTABLE"):
            self.store.connection.execute(
                "UPDATE coordination_messages SET payload_json=?, payload_sha256=? WHERE id=?",
                (canonical_json(payload), digest_json(payload), message_id),
            )

        result = self.supervisor.run_once("2026-08-22T10:00:05Z")
        observed = self.store.connection.execute(
            "SELECT state, payload_json FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual([], result["launched"])
        self.assertEqual("CLAIMED", observed["state"])
        self.assertEqual("a" * 40, json.loads(observed["payload_json"])["base_sha"])

    def test_accepted_noop_wakes_exhaust_identical_progress_budget(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="prepared-status",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A new local status is available.",
                "evidence": {"item_version": 1},
            },
            now="2026-08-22T10:00:02Z",
        )

        first = self.supervisor.run_once("2026-08-22T10:00:03Z")
        second = self.supervisor.run_once("2026-08-22T10:00:30Z")
        third = self.supervisor.run_once("2026-08-22T10:01:04Z")
        fourth = self.supervisor.run_once("2026-08-22T10:03:05Z")
        exhausted = self.supervisor.run_once("2026-08-22T10:07:06Z")

        self.assertEqual([(DEVELOPMENT_SESSION, message_id)], self.launches[:1])
        self.assertEqual(1, len(first["launched"]))
        self.assertEqual([], second["launched"])
        self.assertEqual(1, len(third["launched"]))
        self.assertEqual(1, len(fourth["launched"]))
        self.assertEqual([], exhausted["launched"])
        wake = self.store.connection.execute(
            "SELECT state, attempts, last_error FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:prepared",),
        ).fetchone()
        self.assertEqual(("HOLD", 3, "WAKE_RETRY_EXHAUSTED"), tuple(wake))
        message = self.store.connection.execute(
            "SELECT state,last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("HOLD", "WAKE_RETRY_EXHAUSTED"), tuple(message))

    def test_due_retry_is_starvation_free_under_sustained_fresh_arrivals(self) -> None:
        retry_message_id = self.notice(
            idempotency_key="starvation-free-retry",
            issue_number=400,
        )
        first = self.supervisor.run_once("2026-08-22T10:00:03Z")
        self.assertEqual(
            [retry_message_id], [row["message_id"] for row in first["launched"]]
        )

        results = []
        for batch, timestamp in (
            (410, "2026-08-22T10:01:04Z"),
            (420, "2026-08-22T10:03:05Z"),
            (430, "2026-08-22T10:07:06Z"),
        ):
            for issue_number in range(batch, batch + 4):
                self.notice(
                    idempotency_key=f"sustained-fresh-{issue_number}",
                    issue_number=issue_number,
                )
            results.append(self.supervisor.run_once(timestamp))

        self.assertEqual(
            [retry_message_id],
            [row["message_id"] for row in results[0]["launched"][:1]],
        )
        self.assertEqual(
            [retry_message_id],
            [row["message_id"] for row in results[1]["launched"][:1]],
        )
        self.assertTrue(
            all(
                result["launch_policy_decision"][
                    "due_message_retry_slot_reserved"
                ]
                for result in results
            )
        )
        self.assertEqual(
            3,
            sum(
                candidate_message_id == retry_message_id
                for _session_id, candidate_message_id in self.launches
            ),
        )
        wake = self.store.connection.execute(
            "SELECT state,attempts,last_error FROM coordination_wakes "
            "WHERE message_id=?",
            (retry_message_id,),
        ).fetchone()
        self.assertEqual(("HOLD", 3, "WAKE_RETRY_EXHAUSTED"), tuple(wake))

    def test_launch_failures_exhaust_identical_progress_into_typed_hold(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="prepared-launch-retry",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A valid local inbox row remains available.",
                "evidence": {"item_version": 1},
            },
            now="2026-08-22T10:00:02Z",
        )
        failures: list[tuple[str, int]] = []

        def failing_launcher(session_id: str, candidate_message_id: int) -> int:
            failures.append((session_id, candidate_message_id))
            raise role_executor_transport_module.RoleExecutorManagerNotSubmitted()

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=failing_launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_: False,
        )
        for timestamp in (
            "2026-08-22T10:00:03Z",
            "2026-08-22T10:01:04Z",
            "2026-08-22T10:03:05Z",
            "2026-08-22T10:07:06Z",
            "2026-08-22T10:15:07Z",
            "2026-08-22T10:30:08Z",
        ):
            supervisor.run_once(timestamp)

        wake = self.store.connection.execute(
            "SELECT state, attempts, process_id, last_error "
            "FROM coordination_wakes WHERE wake_key=?",
            (f"message:{message_id}:prepared",),
        ).fetchone()
        message = self.store.connection.execute(
            "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        self.assertEqual(3, len(failures))
        self.assertEqual(
            ("HOLD", 3, None, "WAKE_RETRY_EXHAUSTED"), tuple(wake)
        )
        self.assertEqual("HOLD", message["state"])

    def test_third_message_launch_failure_rereads_progress_before_exhaustion(self) -> None:
        _source, message_id = self.claimed_admission()
        watch = self.store.connection.execute(
            "SELECT watch_key FROM coordination_terminal_watches"
        ).fetchone()
        watch_key = str(watch["watch_key"])
        self.store.connection.execute(
            "UPDATE coordination_terminal_watches SET claim_attempt_id=NULL "
            "WHERE watch_key=?",
            (watch_key,),
        )
        self.store.heartbeat_terminal_watch(
            watch_key=watch_key,
            session_id=DEVELOPMENT_SESSION,
            generation=1,
            delay_seconds=1800,
            now="2026-08-22T10:00:04Z",
        )
        failures: list[int] = []

        def failing_launcher(_session_id: str, candidate_message_id: int) -> int:
            failures.append(candidate_message_id)
            if len(failures) == 3:
                self.store.heartbeat_terminal_watch(
                    watch_key=watch_key,
                    session_id=DEVELOPMENT_SESSION,
                    generation=1,
                    delay_seconds=1800,
                    now="2026-08-22T10:03:07Z",
                )
            raise role_executor_transport_module.RoleExecutorManagerNotSubmitted()

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=failing_launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda *_: False,
        )
        supervisor.run_once("2026-08-22T10:00:05Z")
        supervisor.run_once("2026-08-22T10:01:06Z")
        supervisor.run_once("2026-08-22T10:03:07Z")

        after = self.store.connection.execute(
            "SELECT state,attempts,target_progress_sha256,last_error "
            "FROM coordination_wakes WHERE message_id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual("INFLIGHT", after["state"])
        self.assertEqual(1, after["attempts"])
        self.assertEqual("WAKE_LAUNCH_FAILED_AFTER_PROGRESS", after["last_error"])
        self.assertEqual(3, len(failures))

        retry = supervisor.run_once("2026-08-22T10:04:08Z")
        self.assertEqual(1, retry["launch_attempts"]["messages"])
        self.assertEqual(4, len(failures))
        self.assertEqual(
            ("INFLIGHT", 2, "WAKE_LAUNCH_FAILED"),
            tuple(self.store.connection.execute(
                "SELECT state,attempts,last_error FROM coordination_wakes "
                "WHERE message_id=?",
                (message_id,),
            ).fetchone()),
        )

    def test_terminal_watch_launch_failures_exhaust_into_typed_hold(self) -> None:
        self.bound_development_admission(complete=True)
        failures: list[str] = []

        def fail_watch(_session_id: str, watch_key: str) -> int:
            failures.append(watch_key)
            raise role_executor_transport_module.RoleExecutorManagerNotSubmitted()

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda *_args: self.fail("message launcher must not run"),
            terminal_watch_launcher=fail_watch,
            process_checker=lambda *_: False,
        )
        results = [
            supervisor.run_once(timestamp)
            for timestamp in (
                "2026-08-22T10:01:08Z",
                "2026-08-22T10:02:09Z",
                "2026-08-22T10:03:10Z",
            )
        ]

        self.assertEqual(3, len(failures))
        self.assertTrue(
            all(result["launch_attempts"]["terminal_watches"] == 1 for result in results)
        )
        watch = self.store.connection.execute(
            "SELECT state,attempts,last_error FROM coordination_terminal_watches"
        ).fetchone()
        self.assertEqual(
            ("HOLD", 3, "TERMINAL_WATCH_RETRY_EXHAUSTED"), tuple(watch)
        )

    def test_third_terminal_watch_failure_rereads_progress_before_exhaustion(self) -> None:
        _source, _message_id, watch_key, _attempt, _token = (
            self.bound_development_admission(complete=True)
        )
        failures: list[str] = []

        def fail_after_progress(_session_id: str, candidate_watch_key: str) -> int:
            failures.append(candidate_watch_key)
            if len(failures) == 3:
                self.store.heartbeat_terminal_watch(
                    watch_key=watch_key,
                    session_id=DEVELOPMENT_SESSION,
                    generation=1,
                    delay_seconds=600,
                    now="2026-08-22T10:03:10Z",
                )
            raise role_executor_transport_module.RoleExecutorManagerNotSubmitted()

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda *_args: self.fail("message launcher must not run"),
            terminal_watch_launcher=fail_after_progress,
            process_checker=lambda *_: False,
        )
        for timestamp in (
            "2026-08-22T10:01:08Z",
            "2026-08-22T10:02:09Z",
            "2026-08-22T10:03:10Z",
        ):
            supervisor.run_once(timestamp)

        watch = self.store.connection.execute(
            "SELECT state,attempts,next_wake_at,last_error "
            "FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual("ACTIVE", watch["state"])
        self.assertEqual(0, watch["attempts"])
        self.assertEqual("2026-08-22T10:13:10Z", watch["next_wake_at"])
        self.assertIsNone(watch["last_error"])
        self.assertEqual(3, len(failures))

        retry = supervisor.run_once("2026-08-22T10:13:11Z")
        self.assertEqual(0, retry["launch_attempts"]["terminal_watches"])
        self.assertEqual(3, len(failures))
        intent, envelope = self.manager_intent_event(
            target_kind="terminal_watch", target_key=watch_key
        )
        self.assertEqual(watch_key, envelope["target_entity_key"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events WHERE "
                "event_type='TERMINAL_WATCH_MANAGER_SUBMISSION_ABANDONED' "
                "AND entity_key=?",
                (intent["entity_key"],),
            ).fetchone()[0],
        )

    def test_capacity_release_consumes_dirty_event_without_planner_notice(self) -> None:
        source, message_id, watch_key, running, token = (
            self.bound_development_admission(complete=False)
        )
        self.store.claim_message(
            message_id,
            DEVELOPMENT_SESSION,
            "2026-08-22T10:00:07Z",
            attempt_id=running["attempt_id"],
            executor_token=token,
        )
        self.seed_current_graph(source.payload_sha256)
        active_item = self.store.connection.execute(
            "SELECT version,lease_manifest_sha256 FROM coordination_items "
            "WHERE repository=? AND issue_number=92",
            (REPOSITORY,),
        ).fetchone()
        lease = active_item["lease_manifest_sha256"]
        receipt = {
            "schema": "twinfinity-terminal-receipt/v1",
            "repository": REPOSITORY,
            "issue_number": 92,
            "generation": 1,
            "source_payload_sha256": source.payload_sha256,
            "lease_manifest_sha256": lease,
            "outcome": "ACCEPTED",
            "accepted_head_sha": "c" * 40,
            "operational_state_sha256": None,
            "acceptance_evidence_sha256": "d" * 64,
            "residual_risks": [],
        }
        cleanup = {
            "schema": "twinfinity-terminal-cleanup/v1",
            "repository": REPOSITORY,
            "issue_number": 92,
            "generation": 1,
            "lease_manifest_sha256": lease,
            "owned_resources_absent": True,
            "temporary_resources_absent": True,
            "worktree_disposition": "ABSENT",
            "local_branch_disposition": "ABSENT",
            "remote_branch_disposition": "ABSENT",
            "residuals": [],
        }
        closeout_key = f"terminal-closeout:{REPOSITORY}:issue:92:generation:1"
        prepared = self.store.prepare_terminal_closeout(
            packet={
                "schema": "twinfinity-terminal-closeout-packet/v1",
                "repository": REPOSITORY,
                "issue_number": 92,
                "generation": 1,
                "expected_item_version": active_item["version"],
                "source_payload_sha256": source.payload_sha256,
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
            attempt_id=running["attempt_id"],
            executor_token=token,
            now="2026-08-22T10:00:08Z",
        )
        original_attempt = self.store.connection.execute(
            "SELECT * FROM executor_attempts WHERE attempt_id=?",
            (running["attempt_id"],),
        ).fetchone()
        inactive = SystemdUnitEvidence(
            unit=original_attempt["systemd_unit"],
            load_state="loaded",
            active_state="inactive",
            sub_state="dead",
            invocation_id=original_attempt["systemd_invocation_id"],
            control_group=original_attempt["systemd_control_group"],
            result="exit-code",
        )
        watch_child: dict[str, object] = {}

        def launch_recovery_watch(session_id: str, candidate_watch_key: str):
            self.terminal_watch_launches.append(
                (session_id, candidate_watch_key)
            )
            invocation_id = "f" * 32
            attempt, child_token = self.seed_role_executor_child(
                role="development",
                endpoint_id=session_id,
                target_kind="terminal_watch",
                target_key=candidate_watch_key,
                invocation_id=invocation_id,
                process_id=2999,
                terminal_state=None,
            )
            watch_child.update(attempt=attempt, token=child_token)
            return role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(
                    "development", "terminal_watch", candidate_watch_key
                ),
                systemd_invocation_id=invocation_id,
            )

        recovery_supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: self.fail(
                "packet-aware recovery must not relaunch the admission"
            ),
            terminal_watch_launcher=launch_recovery_watch,
            process_checker=lambda *_: False,
            stale_attempt_evidence_reader=lambda _unit: inactive,
        )
        recovered = recovery_supervisor.run_once("2026-08-22T10:20:00Z")
        self.assertEqual("RECOVERED", recovered["recovered_active_attempts"][0]["phase"])
        self.assertEqual([(DEVELOPMENT_SESSION, watch_key)], self.terminal_watch_launches)
        self.assertEqual(
            "CLAIMED",
            self.store.connection.execute(
                "SELECT state FROM coordination_messages WHERE id=?",
                (message_id,),
            ).fetchone()[0],
        )
        self.store.bind_terminal_outbox_publisher(
            outbox_id=prepared["outbox_id"],
            publisher_login="twinfinity-bot",
            now="2026-08-22T10:20:01Z",
        )
        self.store.reserve_outbox(prepared["outbox_id"], "2026-08-22T10:20:01Z")
        outbox = self.store.connection.execute(
            "SELECT idempotency_key,payload_json FROM github_outbox WHERE id=?",
            (prepared["outbox_id"],),
        ).fetchone()
        published_body = terminal_published_body(
            json.loads(outbox["payload_json"])["body"],
            outbox["idempotency_key"],
        )
        self.store.complete_terminal_outbox_from_readback(
            outbox_id=prepared["outbox_id"],
            remote_receipt="comment:123",
            published_body=published_body,
            publisher_login="twinfinity-bot",
            now="2026-08-22T10:20:02Z",
        )
        fresh_running = watch_child["attempt"]
        fresh_token = watch_child["token"]
        with (
            patch.object(
                coordination_store_module,
                "_fetch_terminal_live_observation",
                return_value=(
                    {**source.payload, "updated_at": "2026-08-22T10:20:02Z"},
                    {
                        "ref": "refs/heads/main",
                        "object": {"sha": "a" * 40},
                    },
                    {
                        "id": 123,
                        "body": published_body,
                        "created_at": "2026-08-22T10:20:02Z",
                        "updated_at": "2026-08-22T10:20:02Z",
                        "issue_url": (
                            f"https://api.github.com/repos/{REPOSITORY}/issues/92"
                        ),
                        "user": {"login": "twinfinity-bot"},
                    },
                    [
                        {
                            "id": 123,
                            "event": "commented",
                            "body": published_body,
                            "created_at": "2026-08-22T10:20:02Z",
                            "updated_at": "2026-08-22T10:20:02Z",
                            "issue_url": (
                                f"https://api.github.com/repos/{REPOSITORY}"
                                "/issues/92"
                            ),
                            "user": {"login": "twinfinity-bot"},
                        }
                    ],
                ),
            ) as live_observation,
            patch.object(
                coordination_store_module,
                "utc_now",
                return_value="2026-08-22T10:20:05Z",
            ),
        ):
            self.store.commit_terminal_closeout(
                closeout_key=closeout_key,
                attempt_id=fresh_running["attempt_id"],
                executor_token=fresh_token,
            )
        live_observation.assert_called_once_with(REPOSITORY, 92, "comment:123")

        result = self.supervisor.run_once("2026-08-22T10:20:06Z")
        repeated = self.supervisor.run_once("2026-08-22T10:20:07Z")

        self.assertEqual("HOLD", result["portfolio_convergence"][0]["state"])
        self.assertEqual(
            "REPOSITORY_GIT_REGISTRATION_MISSING",
            result["portfolio_convergence"][0]["error"],
        )
        self.assertEqual([], self.launches)
        self.assertEqual([], repeated["portfolio_convergence"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages WHERE idempotency_key LIKE 'supervisor-capacity-release:%'"
            ).fetchone()[0],
        )

    def test_missing_active_terminal_watch_is_backfilled_and_wakes_owner(self) -> None:
        _source, _message_id, key, _attempt, _token = (
            self.bound_development_admission(complete=True)
        )
        self.store.connection.execute("DELETE FROM coordination_terminal_watches")

        result = self.supervisor.run_once("2026-08-22T10:06:10Z")

        self.assertEqual([key], result["opened_terminal_watches"])
        self.assertEqual([(DEVELOPMENT_SESSION, key)], self.terminal_watch_launches)
        watch = self.store.connection.execute(
            "SELECT state, attempts, process_id FROM coordination_terminal_watches WHERE watch_key=?",
            (key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", 1, 2001), tuple(watch))

    def test_missing_watch_two_connection_race_inserts_once_without_overwrite(self) -> None:
        _source, message_id, key, _attempt, _token = (
            self.bound_development_admission(complete=True)
        )
        self.store.connection.execute("DELETE FROM coordination_terminal_watches")
        barrier = threading.Barrier(2)

        class RacingSupervisor(CoordinationSupervisor):
            def _terminal_watch_backfill_plan(inner_self, item):
                plan = super()._terminal_watch_backfill_plan(item)
                if not inner_self.store.connection.in_transaction:
                    barrier.wait(timeout=5)
                return plan

        def backfill():
            store = CoordinationStore(self.store.path)
            try:
                return RacingSupervisor(
                    store,
                    launcher=lambda _session, _message: 1,
                    terminal_watch_launcher=lambda _session, _watch: 1,
                    process_checker=lambda *_: False,
                )._ensure_terminal_watches("2026-08-22T10:06:10Z")
            finally:
                store.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: backfill(), range(2)))

        self.assertEqual(1, sum(key in opened for opened, _held in results))
        watch = self.store.connection.execute(
            "SELECT state, admission_message_id FROM coordination_terminal_watches "
            "WHERE watch_key=?",
            (key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", message_id), tuple(watch))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_events "
                "WHERE event_type='TERMINAL_WATCH_BACKFILLED' AND entity_key=?",
                (key,),
            ).fetchone()[0],
        )

    def test_missing_watch_without_exact_admission_is_held_and_never_wakes(self) -> None:
        source = self.snapshot()
        self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:02Z",
        )
        self.store.connection.execute("DELETE FROM coordination_terminal_watches")

        result = self.supervisor.run_once("2026-08-22T10:06:10Z")

        key = f"terminal:{REPOSITORY}:issue:92:generation:1"
        self.assertEqual([], result["opened_terminal_watches"])
        self.assertEqual([], result["terminal_watch_launches"])
        watch = self.store.connection.execute(
            "SELECT state,attempts,process_id,last_error "
            "FROM coordination_terminal_watches WHERE watch_key=?",
            (key,),
        ).fetchone()
        self.assertEqual(
            ("HOLD", 0, None, "TERMINAL_WATCH_BACKFILL_INVALID_LINEAGE"),
            tuple(watch),
        )

    def test_prepared_admission_keeps_terminal_watch_pending_and_unwoken(self) -> None:
        _source, _message_id, watch_key, _attempt, _token = (
            self.bound_development_admission(complete=False)
        )

        result = self.supervisor.run_once("2026-08-22T10:06:10Z")

        self.assertEqual([], result["terminal_watch_launches"])
        self.assertEqual([], self.terminal_watch_launches)
        watch = self.store.connection.execute(
            "SELECT state,attempts,process_id,claim_attempt_id "
            "FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(("PENDING_CLAIM", 0, None, None), tuple(watch))

    def test_active_message_lineage_suppresses_duplicate_terminal_watch_launch(self) -> None:
        _source, message_id, watch_key, running, token = (
            self.bound_development_admission(complete=False)
        )
        self.store.claim_message(
            message_id,
            DEVELOPMENT_SESSION,
            "2026-08-22T10:00:07Z",
            attempt_id=running["attempt_id"],
            executor_token=token,
        )

        result = self.supervisor.run_once("2026-08-22T10:06:10Z")

        self.assertEqual([], result["opened_terminal_watches"])
        self.assertEqual([], result["terminal_watch_launches"])
        self.assertEqual([], self.terminal_watch_launches)
        watch = self.store.connection.execute(
            "SELECT state,attempts,process_id FROM coordination_terminal_watches WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual(("ACTIVE", 0, None), tuple(watch))

    def test_running_exact_target_suppresses_terminal_watch_wake(self) -> None:
        _source, _message_id, _watch_key, _attempt, _token = (
            self.bound_development_admission(complete=True)
        )
        running = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
            terminal_watch_launcher=lambda session, key: self.terminal_watch_launches.append((session, key)) or 2,
            process_checker=lambda session, kind, key: (
                session == DEVELOPMENT_SESSION and kind == "terminal_watch"
            ),
        )

        result = running.run_once("2026-08-22T10:06:10Z")

        self.assertEqual([], result["terminal_watch_launches"])
        self.assertEqual([], self.terminal_watch_launches)

    def test_recovery_reopen_closes_message_wake_and_resumes_terminal_wake(self) -> None:
        source = self.snapshot()
        active = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=2,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=0,
            now="2026-08-22T10:00:00Z",
        )
        held = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=92,
            status="HOLD",
            allocation_class="RETAINED",
            generation=2,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=LEASE,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=source.payload_sha256,
            expected_version=active["version"],
            now="2026-08-22T10:00:01Z",
        )
        base = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 92,
                "payload_sha256": source.payload_sha256,
            },
            "issue_number": 92,
            "generation": 2,
            "item_version": held["version"],
            "base_sha": "a" * 40,
            "branch": "codex/92-transcript-review-editor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-92",
            "opaque_worktree_id": "twinfinityapp-issue-92",
            "accountable_session_id": DEVELOPMENT_SESSION,
            "lease_manifest_sha256": LEASE,
            "authority_sha256": "7" * 64,
            "capacity": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
        }
        prepare = self.store.enqueue_message(
            idempotency_key="supervisor-recovery-prepare",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="development.recovery_prepare",
            payload={**base, "action": "ACK_ZERO_MUTATION"},
            now="2026-08-22T10:00:02Z",
        )
        self.store.claim_message(
            prepare, DEVELOPMENT_SESSION, "2026-08-22T10:00:03Z"
        )
        self.store.complete_message(
            prepare, DEVELOPMENT_SESSION, "2026-08-22T10:00:04Z"
        )
        commit = self.store.enqueue_message(
            idempotency_key="supervisor-recovery-commit",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="development.recovery_commit",
            payload={
                **base,
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
                "prior_message_id": prepare,
            },
            now="2026-08-22T10:00:05Z",
        )
        self.store.claim_message(
            commit, DEVELOPMENT_SESSION, "2026-08-22T10:00:06Z"
        )
        message_launch = self.supervisor.run_once("2026-08-22T10:00:07Z")
        self.assertEqual(1, len(message_launch["launched"]))

        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="message",
            target_key=str(commit),
            now="2026-08-22T10:00:07Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(commit)
            ),
        )
        unit = stable_systemd_unit("development", "message", str(commit))
        launching_attempt = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=reserved["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="c" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-22T10:00:07Z",
        )
        running_attempt = transition_attempt(
            self.store.connection,
            attempt_id=reserved["attempt_id"],
            token=token,
            expected_version=launching_attempt["version"],
            new_state="RUNNING",
            process_id=9202,
            now="2026-08-22T10:00:07Z",
        )

        self.store.activate_recovery(
            message_id=commit,
            session_id=DEVELOPMENT_SESSION,
            now="2026-08-22T10:00:08Z",
            attempt_id=running_attempt["attempt_id"],
            executor_token=token,
        )
        running = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
            terminal_watch_launcher=lambda session, key: self.terminal_watch_launches.append((session, key)) or 2,
            process_checker=lambda session, kind, key: (
                session == DEVELOPMENT_SESSION and kind == "terminal_watch"
            ),
        )
        while_running = running.run_once("2026-08-22T10:01:09Z")
        self.assertEqual([], while_running["launched"])
        self.assertEqual([], while_running["terminal_watch_launches"])
        message_wake = self.store.connection.execute(
            "SELECT state FROM coordination_wakes WHERE wake_key=?",
            (f"message:{commit}:claimed",),
        ).fetchone()
        self.assertEqual("COMPLETE", message_wake["state"])

        transition_attempt(
            self.store.connection,
            attempt_id=running_attempt["attempt_id"],
            token=token,
            expected_version=running_attempt["version"],
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-22T10:01:09Z",
        )

        after_exit = self.supervisor.run_once("2026-08-22T10:01:10Z")
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:2"
        self.assertEqual(1, len(after_exit["terminal_watch_launches"]))
        terminal_launch = after_exit["terminal_watch_launches"][0]
        self.assertEqual(
            {
                "watch_key": watch_key,
                "recipient_session_id": DEVELOPMENT_SESSION,
                "process_id": 2001,
            },
            {
                key: terminal_launch[key]
                for key in (
                    "watch_key",
                    "recipient_session_id",
                    "process_id",
                )
            },
        )
        self.assertRegex(terminal_launch["child_ack_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual([(DEVELOPMENT_SESSION, watch_key)], self.terminal_watch_launches)

    def test_done_item_without_terminal_commit_holds_watch(self) -> None:
        _source, _message_id, watch_key, _attempt, _token = (
            self.bound_development_admission(complete=True)
        )
        self.store.connection.execute(
            """
            UPDATE coordination_items
            SET status='DONE', allocation_class='NONE',
                accountable_session_id=NULL, lease_manifest_sha256=NULL,
                development_units=0, shared_units=0, sre_units=0,
                version=version+1, updated_at='2026-08-22T10:06:00Z'
            WHERE repository=? AND issue_number=92
            """,
            (REPOSITORY,),
        )

        result = self.supervisor.run_once("2026-08-22T10:06:10Z")

        watch = self.store.connection.execute(
            "SELECT state,last_error FROM coordination_terminal_watches "
            "WHERE watch_key=?",
            (watch_key,),
        ).fetchone()
        self.assertEqual([], result["terminal_watch_launches"])
        self.assertEqual(
            ("HOLD", "TERMINAL_WATCH_ITEM_STATE_WITHOUT_CLOSEOUT_COMMIT"),
            tuple(watch),
        )

    def test_stale_prepared_message_is_held_without_wake(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="stale-status",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A local status was observed.",
                "evidence": {},
            },
            now="2026-08-22T10:00:02Z",
        )
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=92,
            payload={"number": 92, "title": "Changed"},
            source_updated_at="2026-08-22T10:01:00Z",
            fetched_at="2026-08-22T10:01:01Z",
        )

        result = self.supervisor.run_once("2026-08-22T10:01:02Z")

        self.assertEqual([], result["launched"])
        self.assertEqual([], self.launches)
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(observed))

    def test_source_advance_between_scan_and_reservation_holds_without_wake(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="reservation-race-status",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A local status was observed.",
                "evidence": {},
            },
            now="2026-08-22T10:00:02Z",
        )
        reserve = self.supervisor._reserve_wake
        advanced = False

        def advance_then_reserve(row, now):
            nonlocal advanced
            if not advanced:
                advanced = True
                self.store.ingest_snapshot(
                    repository=REPOSITORY,
                    object_kind="issue",
                    object_number=92,
                    payload={"number": 92, "title": "Changed during scan"},
                    source_updated_at="2026-08-22T10:01:00Z",
                    fetched_at="2026-08-22T10:01:01Z",
                )
            return reserve(row, now)

        self.supervisor._reserve_wake = advance_then_reserve
        result = self.supervisor.run_once("2026-08-22T10:01:02Z")

        self.assertEqual([], result["launched"])
        self.assertEqual([], self.launches)
        observed = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE id=?",
            (message_id,),
        ).fetchone()
        self.assertEqual(("HOLD", "SOURCE_SNAPSHOT_DRIFT"), tuple(observed))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?", (message_id,)
            ).fetchone()[0],
        )

    def test_different_targets_for_one_role_are_scheduled_in_one_scan(self) -> None:
        source = self.snapshot()
        message_ids = []
        for suffix in ("first", "second"):
            message_ids.append(
                self.store.enqueue_message(
                    idempotency_key=f"two-row-{suffix}",
                    recipient_session_id=DEVELOPMENT_SESSION,
                    topic="coordination.notice",
                    payload={
                        "source": {
                            "repository": REPOSITORY,
                            "object_kind": "issue",
                            "object_number": 92,
                            "payload_sha256": source.payload_sha256,
                        },
                        "notice_kind": "status",
                        "mutation_authority": False,
                        "subject": f"Observed status {suffix}",
                        "summary": "A local status was observed.",
                        "evidence": {},
                    },
                    now="2026-08-22T10:00:02Z",
                )
            )

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual(
            [(DEVELOPMENT_SESSION, message_id) for message_id in message_ids],
            self.launches,
        )
        self.assertEqual(2, len(result["launched"]))
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE recipient_session_id=?",
                (DEVELOPMENT_SESSION,),
            ).fetchone()[0],
        )

    def test_launch_policy_reserves_terminal_watch_and_leaves_overflow_untouched(self) -> None:
        self.bound_development_admission(complete=True)
        message_ids = [
            self.notice(
                idempotency_key=f"launch-budget-{issue_number}",
                issue_number=issue_number,
            )
            for issue_number in (101, 102, 103, 104)
        ]

        first = self.supervisor.run_once("2026-08-22T10:01:08Z")

        self.assertEqual(
            {"total": 4, "messages": 3, "terminal_watches": 1},
            first["launch_policy"],
        )
        self.assertEqual(
            {
                "terminal_watch_slot_reserved": True,
                "message_limit": 3,
                "due_message_retry_slot_reserved": False,
                "due_message_retry_limit": 1,
            },
            first["launch_policy_decision"],
        )
        self.assertEqual(first["launch_policy"], first["launch_attempts"])
        self.assertEqual(message_ids[:3], [row["message_id"] for row in first["launched"]])
        self.assertEqual(1, len(first["terminal_watch_launches"]))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?",
                (message_ids[3],),
            ).fetchone()[0],
        )

        second = self.supervisor.run_once("2026-08-22T10:01:09Z")
        self.assertEqual([message_ids[3]], [row["message_id"] for row in second["launched"]])
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT attempts FROM coordination_wakes WHERE message_id=?",
                (message_ids[3],),
            ).fetchone()[0],
        )

    def test_launch_policy_lends_watch_reserve_to_fourth_message_when_no_watch_is_due(self) -> None:
        message_ids = [
            self.notice(
                idempotency_key=f"borrowed-watch-slot-{issue_number}",
                issue_number=issue_number,
            )
            for issue_number in (301, 302, 303, 304, 305)
        ]

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual(
            {
                "terminal_watch_slot_reserved": False,
                "message_limit": 4,
                "due_message_retry_slot_reserved": False,
                "due_message_retry_limit": 1,
            },
            result["launch_policy_decision"],
        )
        self.assertEqual(
            {"total": 4, "messages": 4, "terminal_watches": 0},
            result["launch_attempts"],
        )
        self.assertEqual(
            message_ids[:4], [row["message_id"] for row in result["launched"]]
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?",
                (message_ids[4],),
            ).fetchone()[0],
        )

    def test_planner_launches_one_target_per_repository_and_distinct_repositories(self) -> None:
        same_repository = [
            self.notice(
                idempotency_key=f"planner-same-repository-{issue_number}",
                issue_number=issue_number,
                recipient=PLANNER_SESSION,
            )
            for issue_number in (201, 202)
        ]
        other_repository_message = self.notice(
            idempotency_key="planner-other-repository",
            issue_number=1,
            recipient=PLANNER_SESSION,
            repository="twinfinityai/twinfinity-companion",
        )

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual(
            [same_repository[0], other_repository_message],
            [row["message_id"] for row in result["launched"]],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_wakes WHERE message_id=?",
                (same_repository[1],),
            ).fetchone()[0],
        )

    def test_launch_policy_validation_fails_closed(self) -> None:
        for values in ((0, 0, 0), (4, 4, 1), (4, 3, 0), (4, True, 1)):
            with self.subTest(values=values), self.assertRaisesRegex(
                CoordinationError, "SCHEDULER_LAUNCH_POLICY_INVALID"
            ):
                SchedulerLaunchPolicy(*values)

    def test_disjoint_mixed_role_notices_launch_in_one_scan(self) -> None:
        source = self.snapshot()
        expected = []
        for recipient, suffix in (
            (DEVELOPMENT_SESSION, "development"),
            (SRE_SESSION, "sre"),
        ):
            message_id = self.store.enqueue_message(
                idempotency_key=f"mixed-role-{suffix}",
                recipient_session_id=recipient,
                topic="coordination.notice",
                payload={
                    "source": {
                        "repository": REPOSITORY,
                        "object_kind": "issue",
                        "object_number": 92,
                        "payload_sha256": source.payload_sha256,
                    },
                    "notice_kind": "status",
                    "mutation_authority": False,
                    "subject": f"{suffix} status",
                    "summary": "A nonmutating role-local observation is ready.",
                    "evidence": {},
                },
                now="2026-08-22T10:00:02Z",
            )
            expected.append((recipient, message_id))

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual(expected, self.launches)
        self.assertEqual(2, len(result["launched"]))

    def test_systemd_wake_unit_is_deterministic_per_target(self) -> None:
        receipts = [
            role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(
                    "development", "message", target_key
                ),
                systemd_invocation_id=identity * 32,
            )
            for target_key, identity in (("11", "1"), ("12", "2"))
        ]
        with patch(
            "coordination_supervisor.submit_role_executor", side_effect=receipts
        ) as submit, patch(
            "role_executor_transport.subprocess.run",
            side_effect=AssertionError("direct manager path must not use run"),
        ) as run:
            observed = (
                launch_canonical_session(DEVELOPMENT_SESSION, 11),
                launch_canonical_session(DEVELOPMENT_SESSION, 12),
            )

        self.assertEqual(tuple(receipts), observed)
        run.assert_not_called()
        units = [call.kwargs["target_key"] for call in submit.call_args_list]
        self.assertEqual(
            ["11", "12"],
            units,
        )
        self.assertEqual(2, len(set(units)))
        self.assertEqual(
            [receipt.systemd_unit for receipt in receipts],
            [
                stable_systemd_unit("development", "message", key)
                for key in units
            ],
        )
        for key, call in zip(("11", "12"), submit.call_args_list, strict=True):
            self.assertEqual("development", call.kwargs["role"])
            self.assertEqual(
                DEVELOPMENT_SESSION,
                call.kwargs["endpoint_id"],
            )
            self.assertEqual("message", call.kwargs["target_kind"])
            self.assertEqual(key, call.kwargs["target_key"])
            self.assertIn(f"exact inbox row {key}", call.kwargs["prompt"])

    def test_lock_contention_emits_one_bounded_skip_without_opening_store(self) -> None:
        lock_path = Path(self.temp.name) / "coordination-supervisor.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        output = io.StringIO()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(
                coordination_supervisor_module, "LOCK", lock_path
            ), patch.object(
                coordination_supervisor_module, "CoordinationStore"
            ) as store, redirect_stdout(output):
                result = coordination_supervisor_module.main()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertEqual(0, result)
        self.assertEqual(
            '{"phase":"SKIPPED","reason":"LOCK_CONTENDED"}\n',
            output.getvalue(),
        )
        store.assert_not_called()

    def test_closed_canonical_command_requires_native_capability(self) -> None:
        prompt = "exact typed row"
        development = _canonical_session_command(DEVELOPMENT_SESSION, prompt)
        self.assertEqual("/usr/bin/python3", development[0])
        self.assertIn("run_role_executor.py", development[1])
        self.assertEqual("development", development[development.index("--role") + 1])
        self.assertEqual(
            DEVELOPMENT_SESSION,
            development[development.index("--endpoint-id") + 1],
        )
        self.assertEqual(prompt, development[-1])
        self.assertNotIn("resume", development)
        with self.assertRaisesRegex(CoordinationError, "NONCANONICAL_ROLE_ENDPOINT"):
            _canonical_session_command(NONCANONICAL_SESSION, prompt)

        with patch("coordination_supervisor.submit_role_executor") as submit:
            with self.assertRaisesRegex(
                CoordinationError, "NONCANONICAL_ROLE_ENDPOINT"
            ):
                launch_canonical_session(NONCANONICAL_SESSION, 7)
        submit.assert_not_called()

    def test_terminal_watch_wake_is_outcome_oriented_not_one_gate_bounded(self) -> None:
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:3"
        receipt = role_executor_transport_module.RoleExecutorManagerSubmission(
            systemd_unit=stable_systemd_unit(
                "development", "terminal_watch", watch_key
            ),
            systemd_invocation_id="3" * 32,
        )
        with patch(
            "coordination_supervisor.submit_role_executor", return_value=receipt
        ) as submit, patch(
            "role_executor_transport.subprocess.run",
            side_effect=AssertionError("direct manager path must not use run"),
        ) as run:
            observed = launch_terminal_watch_session(
                DEVELOPMENT_SESSION, watch_key
            )

        self.assertEqual(receipt, observed)
        run.assert_not_called()
        prompt = submit.call_args.kwargs["prompt"]
        self.assertEqual("development", submit.call_args.kwargs["role"])
        self.assertEqual(DEVELOPMENT_SESSION, submit.call_args.kwargs["endpoint_id"])
        self.assertEqual("terminal_watch", submit.call_args.kwargs["target_kind"])
        self.assertEqual(watch_key, submit.call_args.kwargs["target_key"])
        self.assertIn(watch_key, prompt)
        self.assertIn("every immediately executable routine step", prompt)
        self.assertIn("merge, cleanup, and capacity release", prompt)
        self.assertIn("do not stop merely because one material gate passed", prompt)
        self.assertIn("genuine external wait or hard stop", prompt)
        self.assertNotIn("next material or terminal gate", prompt)

    def test_role_executor_profile_is_selected_by_strict_registry_config(self) -> None:
        receipts = [
            role_executor_transport_module.RoleExecutorManagerSubmission(
                systemd_unit=stable_systemd_unit(role, "message", target_key),
                systemd_invocation_id=identity * 32,
            )
            for role, target_key, identity in (
                ("planner", "21", "4"),
                ("sre", "22", "5"),
            )
        ]
        with patch(
            "coordination_supervisor.submit_role_executor", side_effect=receipts
        ) as submit:
            launch_canonical_session(PLANNER_SESSION, 21)
            launch_canonical_session(SRE_SESSION, 22)

        planner_call, sre_call = submit.call_args_list
        self.assertEqual("planner", planner_call.kwargs["role"])
        self.assertEqual(
            PLANNER_SESSION,
            planner_call.kwargs["endpoint_id"],
        )
        self.assertEqual("sre", sre_call.kwargs["role"])
        self.assertEqual(
            SRE_SESSION,
            sre_call.kwargs["endpoint_id"],
        )

    def test_wrong_role_prepared_and_claimed_rows_are_held_without_wake(self) -> None:
        now = "2026-08-22T10:00:02Z"
        for recipient in (
            DEVELOPMENT_SESSION,
            PLANNER_SESSION,
            NONCANONICAL_SESSION,
        ):
            for state in ("PREPARED", "CLAIMED"):
                self.store.connection.execute(
                    """
                    INSERT INTO coordination_messages(
                        idempotency_key, recipient_session_id, topic, payload_sha256,
                        payload_json, state, claimed_by, created_at, updated_at
                    ) VALUES (?, ?, 'sre.admission', ?, '{}', ?, ?, ?, ?)
                    """,
                    (
                        f"wrong-role-{recipient}-{state.lower()}",
                        recipient,
                        "0" * 64,
                        state,
                        recipient if state == "CLAIMED" else None,
                        now,
                        now,
                    ),
                )

        result = self.supervisor.run_once("2026-08-22T10:00:03Z")

        self.assertEqual([], result["launched"])
        self.assertEqual([], self.launches)
        rows = self.store.connection.execute(
            "SELECT state, last_error FROM coordination_messages WHERE idempotency_key LIKE 'wrong-role-%' ORDER BY id",
        ).fetchall()
        self.assertEqual(
            [("HOLD", "MESSAGE_ROLE_MISMATCH")] * 6,
            [tuple(row) for row in rows],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                """
                SELECT COUNT(*) FROM coordination_wakes AS wakes
                JOIN coordination_messages AS messages ON messages.id=wakes.message_id
                WHERE messages.idempotency_key LIKE 'wrong-role-%'
                """
            ).fetchone()[0],
        )

    def test_artifact_filesystem_failure_does_not_block_session_wake(self) -> None:
        source = self.snapshot()
        message_id = self.store.enqueue_message(
            idempotency_key="wake-despite-artifact-failure",
            recipient_session_id=DEVELOPMENT_SESSION,
            topic="coordination.notice",
            payload={
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 92,
                    "payload_sha256": source.payload_sha256,
                },
                "notice_kind": "status",
                "mutation_authority": False,
                "subject": "Observed status",
                "summary": "A local status remains available.",
                "evidence": {"item_version": 1},
            },
            now="2026-08-22T10:00:02Z",
        )
        with patch.object(
            self.store, "collect_artifacts", side_effect=OSError("filesystem")
        ):
            result = self.supervisor.run_once("2026-08-22T10:00:03Z")
        self.assertEqual("HOLD", result["artifact_gc"]["mode"])
        self.assertEqual("ARTIFACT_GC_FAILED", result["artifact_gc"]["error"])
        self.assertEqual([(DEVELOPMENT_SESSION, message_id)], self.launches)


if __name__ == "__main__":
    unittest.main()
