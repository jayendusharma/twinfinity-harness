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
from unittest.mock import patch


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

        def launcher(session_id: str, message_id: int) -> int:
            self.launches.append((session_id, message_id))
            return 1000 + len(self.launches)

        def terminal_watch_launcher(session_id: str, watch_key: str) -> int:
            self.terminal_watch_launches.append((session_id, watch_key))
            return 2000 + len(self.terminal_watch_launches)

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
            supervisor = CoordinationSupervisor(
                self.store,
                launcher=lambda endpoint, candidate: (
                    self.launches.append((endpoint, candidate)) or 1490
                ),
                terminal_watch_launcher=lambda _endpoint, _watch: 1,
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
            raise OSError("later launch race")

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=fail_launch,
            terminal_watch_launcher=lambda *_args: 1,
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
            raise OSError("launch failed")

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=failing_launcher,
            terminal_watch_launcher=lambda _session, _key: 1,
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
            raise OSError("launch failed")

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=failing_launcher,
            terminal_watch_launcher=lambda _session, _key: 1,
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
            raise OSError("watch launch failed")

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
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
            raise OSError("watch launch failed")

        supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: 1,
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
        self.assertEqual(
            "TERMINAL_WATCH_WAKE_FAILED_AFTER_PROGRESS", watch["last_error"]
        )
        self.assertEqual(3, len(failures))

        retry = supervisor.run_once("2026-08-22T10:13:11Z")
        self.assertEqual(1, retry["launch_attempts"]["terminal_watches"])
        self.assertEqual(4, len(failures))

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
        recovery_supervisor = CoordinationSupervisor(
            self.store,
            launcher=lambda _session, _message: self.fail(
                "packet-aware recovery must not relaunch the admission"
            ),
            terminal_watch_launcher=lambda session, key: (
                self.terminal_watch_launches.append((session, key)) or 2999
            ),
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
        fresh, fresh_token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=DEVELOPMENT_SESSION,
            target_kind="terminal_watch",
            target_key=watch_key,
            now="2026-08-22T10:20:03Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "terminal_watch", watch_key
            ),
        )
        unit = stable_systemd_unit("development", "terminal_watch", watch_key)
        fresh_launching = transition_attempt(
            self.store.connection,
            attempt_id=fresh["attempt_id"],
            token=fresh_token,
            expected_version=fresh["version"],
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id="f" * 32,
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-22T10:20:03Z",
        )
        fresh_running = transition_attempt(
            self.store.connection,
            attempt_id=fresh["attempt_id"],
            token=fresh_token,
            expected_version=fresh_launching["version"],
            new_state="RUNNING",
            process_id=2999,
            now="2026-08-22T10:20:04Z",
        )
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
        self.assertEqual(
            [
                {
                    "watch_key": watch_key,
                    "recipient_session_id": DEVELOPMENT_SESSION,
                    "process_id": 2001,
                }
            ],
            after_exit["terminal_watch_launches"],
        )
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
        with patch("coordination_supervisor.subprocess.run") as run:
            run.return_value.returncode = 0
            launch_canonical_session(DEVELOPMENT_SESSION, 11)
            launch_canonical_session(DEVELOPMENT_SESSION, 12)

        units = [
            next(argument for argument in call.args[0] if argument.startswith("--unit="))
            for call in run.call_args_list
        ]
        self.assertEqual(
            [
                f"--unit={stable_systemd_unit('development', 'message', key)}"
                for key in ("11", "12")
            ],
            units,
        )
        self.assertEqual(2, len(set(units)))
        self.assertTrue(all(len(unit.removeprefix("--unit=")) < 100 for unit in units))
        self.assertEqual(
            units[0],
            f"--unit={stable_systemd_unit('development', 'message', '11')}",
        )
        for key, call in zip(("11", "12"), run.call_args_list, strict=True):
            command = call.args[0]
            self.assertNotIn("--collect", command)
            self.assertIn("run_role_executor.py", " ".join(command))
            self.assertEqual(
                "development", command[command.index("--role") + 1]
            )
            self.assertEqual(
                DEVELOPMENT_SESSION,
                command[command.index("--endpoint-id") + 1],
            )
            self.assertEqual(
                stable_systemd_unit("development", "message", key),
                command[command.index("--systemd-unit") + 1],
            )
            self.assertNotIn("resume", command)

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

        with patch("coordination_supervisor.subprocess.run") as run:
            with self.assertRaisesRegex(
                CoordinationError, "NONCANONICAL_ROLE_ENDPOINT"
            ):
                launch_canonical_session(NONCANONICAL_SESSION, 7)
        run.assert_not_called()

    def test_terminal_watch_wake_is_outcome_oriented_not_one_gate_bounded(self) -> None:
        watch_key = f"terminal:{REPOSITORY}:issue:92:generation:3"
        with patch("coordination_supervisor.subprocess.run") as run:
            run.return_value.returncode = 0
            launch_terminal_watch_session(DEVELOPMENT_SESSION, watch_key)

        command = run.call_args.args[0]
        prompt = command[-1]
        self.assertIn(watch_key, prompt)
        self.assertIn("every immediately executable routine step", prompt)
        self.assertIn("merge, cleanup, and capacity release", prompt)
        self.assertIn("do not stop merely because one material gate passed", prompt)
        self.assertIn("genuine external wait or hard stop", prompt)
        self.assertNotIn("next material or terminal gate", prompt)

    def test_role_executor_profile_is_selected_by_strict_registry_config(self) -> None:
        with patch("coordination_supervisor.subprocess.run") as run:
            run.return_value.returncode = 0
            launch_canonical_session(PLANNER_SESSION, 21)
            launch_canonical_session(SRE_SESSION, 22)

        planner_command = run.call_args_list[0].args[0]
        sre_command = run.call_args_list[1].args[0]
        self.assertEqual("planner", planner_command[planner_command.index("--role") + 1])
        self.assertEqual(
            PLANNER_SESSION,
            planner_command[planner_command.index("--endpoint-id") + 1],
        )
        self.assertEqual(
            "sre",
            sre_command[sre_command.index("--role") + 1],
        )
        self.assertEqual(
            SRE_SESSION,
            sre_command[sre_command.index("--endpoint-id") + 1],
        )
        self.assertNotIn("resume", planner_command)
        self.assertNotIn("resume", sre_command)

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
