from __future__ import annotations

from dataclasses import replace
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import threading
import time
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from attempt_responses_proxy import (  # noqa: E402
    ApprovedCredentialReference,
    AttemptBoundResponsesProxy,
    AttemptMountPolicy,
    AttemptProxyContract,
    AttemptProxyLedger,
    Frame,
    FrameKind,
    HOLD_PROXY_DISABLED,
    HOLD_UPSTREAM_AMBIGUOUS,
    HOLD_UPSTREAM_AUTH_UNSUPPORTED,
    IODeadline,
    ProxyActivation,
    ProxyError,
    ProxyHold,
    ProxyIOTimeout,
    ProxyPermit,
    ProxyPolicyError,
    ProxyProtocolError,
    ProxyProcessTerminalReceipt,
    RelayBinding,
    SupplementalMount,
    UpstreamOpenResult,
    UpstreamSendEvidence,
    build_uncredentialed_child_environment,
    canonical_json,
    channel_hello,
    create_attempt_socketpair,
    preflight_before_reservation,
    preflight_then_reserve,
    read_one_loopback_request,
    receive_frame,
    relay_framed_http_request,
    relay_one_loopback_connection,
    required_namespace_masks,
    render_machine_local_provider_config,
    send_frame,
    serve_framed_proxy_exchange,
    sha256_text,
    validate_supplemental_mounts,
    write_machine_local_provider_config,
)


ATTEMPT_ID = "11111111-1111-4111-8111-111111111111"
CONTRACT_SHA256 = "a" * 64
APPROVAL_SHA256 = "b" * 64
MODEL = "gpt-test-exact"
RESPONSE_ID = "resp_attempt_one"


def response_stream(
    response_id: str = RESPONSE_ID,
    *,
    input_tokens: int = 20,
    output_tokens: int = 10,
    fragments: bool = False,
) -> list[bytes]:
    created = canonical_json(
        {
            "type": "response.created",
            "response": {"id": response_id},
        }
    )
    completed = canonical_json(
        {
            "type": "response.completed",
            "response": {
                "id": response_id,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                },
            },
        }
    )
    encoded = (
        f"data: {created}\n\ndata: {completed}\n\ndata: [DONE]\n\n".encode(
            "utf-8"
        )
    )
    if not fragments:
        return [encoded]
    return [encoded[:7], encoded[7:31], encoded[31:79], encoded[79:]]


def event_wire(event: dict | str) -> bytes:
    encoded = event if isinstance(event, str) else canonical_json(event)
    return f"data: {encoded}\n\n".encode("utf-8")


def created_event(response_id: str = RESPONSE_ID) -> dict:
    return {"type": "response.created", "response": {"id": response_id}}


def completed_event(
    response_id: str = RESPONSE_ID,
    *,
    input_tokens: int = 20,
    output_tokens: int = 10,
) -> dict:
    return {
        "type": "response.completed",
        "response": {
            "id": response_id,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
        },
    }


class FakeStream:
    def __init__(
        self,
        chunks: list[bytes] | None = None,
        *,
        status: int = 200,
        content_type: str = "text/event-stream",
        before_receive=None,
    ) -> None:
        self.status = status
        self.headers = {
            "content-type": content_type,
            "set-cookie": "must-not-reach-child=1",
        }
        self.chunks = list(chunks or [])
        self.before_receive = before_receive
        self._closed = multiprocessing.get_context("spawn").Value("b", False)

    @property
    def closed(self) -> bool:
        return bool(self._closed.value)

    def receive(self, timeout_seconds: float) -> bytes | None:
        if self.before_receive is not None:
            self.before_receive(timeout_seconds)
        if not self.chunks:
            return None
        return self.chunks.pop(0)

    def close(self) -> None:
        self._closed.value = True


class FakeTransport:
    def __init__(self, outcomes) -> None:
        self.outcomes = list(outcomes)
        context = multiprocessing.get_context("spawn")
        self._next_outcome = context.Value("i", 0)
        self._call_receiver, self._call_sender = context.Pipe(duplex=False)
        self._calls = []

    @property
    def calls(self):
        while self._call_receiver.poll():
            self._calls.append(self._call_receiver.recv())
        return self._calls

    def open(self, request, *, credential_reference, timeout_seconds):
        self._call_sender.send((request, credential_reference, timeout_seconds))
        with self._next_outcome.get_lock():
            index = self._next_outcome.value
            self._next_outcome.value += 1
        outcome = self.outcomes[index]
        if isinstance(outcome, Exception):
            raise outcome
        if outcome == "ZERO_NOT_SENT":
            return UpstreamOpenResult(
                None,
                UpstreamSendEvidence(
                    request.attempt_id,
                    request.permit_binding_sha256,
                    request.request_sha256,
                    request.operation_id,
                    0,
                    True,
                    "BROKER_PROXY_UPSTREAM_NOT_SENT",
                ),
            )
        if isinstance(outcome, UpstreamOpenResult):
            return outcome
        return UpstreamOpenResult(
            outcome,
            UpstreamSendEvidence(
                request.attempt_id,
                request.permit_binding_sha256,
                request.request_sha256,
                request.operation_id,
                len(request.body),
                False,
            ),
        )

    def cancel_open(self, operation_id) -> None:
        self.cancelled_operation_id = operation_id


class BlockingOpenTransport:
    def __init__(self) -> None:
        context = multiprocessing.get_context("spawn")
        self.release = context.Event()
        self.cancelled = context.Value("i", 0)

    def open(self, request, *, credential_reference, timeout_seconds):
        self.release.wait(5)
        raise RuntimeError("cancelled open")

    def cancel_open(self, operation_id) -> None:
        with self.cancelled.get_lock():
            self.cancelled.value += 1


class LateSendAfterCancelTransport:
    """A broken transport whose cancel acknowledgement terminalizes nothing."""

    def __init__(self) -> None:
        context = multiprocessing.get_context("spawn")
        self.started = context.RawValue("b", 0)
        self.release = context.RawValue("b", 0)
        self.cancel_calls = context.RawValue("i", 0)
        self.send_count = context.RawValue("i", 0)
        self.resource_count = context.RawValue("i", 0)

    def open(self, request, *, credential_reference, timeout_seconds):
        self.started.value = 1
        expires_at = time.monotonic() + 5
        while not self.release.value and time.monotonic() < expires_at:
            time.sleep(0.005)
        self.send_count.value += 1
        self.resource_count.value += 1
        return UpstreamOpenResult(
            FakeStream(response_stream()),
            UpstreamSendEvidence(
                request.attempt_id,
                request.permit_binding_sha256,
                request.request_sha256,
                request.operation_id,
                len(request.body),
                False,
            ),
        )

    def cancel_open(self, operation_id) -> None:
        self.cancel_calls.value += 1


def acknowledge_cancel_without_terminalizing(
    transport: LateSendAfterCancelTransport,
) -> None:
    expires_at = time.monotonic() + 1
    while not transport.started.value and time.monotonic() < expires_at:
        time.sleep(0.005)
    if transport.started.value:
        transport.cancel_open("no-op-cancel")


class BlockingStream(FakeStream):
    def __init__(self) -> None:
        super().__init__([])
        self.release = multiprocessing.get_context("spawn").Event()

    def receive(self, timeout_seconds: float) -> bytes | None:
        self.release.wait(5)
        return None

    def close(self) -> None:
        self._closed.value = True
        self.release.set()


class SlowReturningStream(FakeStream):
    def receive(self, timeout_seconds: float) -> bytes | None:
        time.sleep(timeout_seconds + 1)
        return super().receive(timeout_seconds)


class ForgedSendEvidenceTransport:
    def open(self, request, *, credential_reference, timeout_seconds):
        return UpstreamOpenResult(
            None,
            UpstreamSendEvidence(
                request.attempt_id,
                "f" * 64,
                request.request_sha256,
                request.operation_id,
                0,
                True,
                "BROKER_PROXY_UPSTREAM_NOT_SENT",
            ),
        )


class ScriptedSlowClient:
    def __init__(self, request: bytes) -> None:
        self.request = bytearray(request)
        self.release = threading.Event()
        self.closed = False

    def recv(self, size: int) -> bytes:
        if not self.request:
            return b""
        value = bytes(self.request[:size])
        del self.request[:size]
        return value

    def send(self, _value) -> int:
        self.release.wait(5)
        if self.closed:
            raise OSError("closed")
        return 0

    def shutdown(self, _how) -> None:
        self.closed = True
        self.release.set()

    def close(self) -> None:
        self.shutdown(socket.SHUT_RDWR)


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class MemoryEndpoint:
    """A blocking byte-stream double for sandbox-denied local socket I/O."""

    def __init__(self) -> None:
        self.peer = None
        self.buffer = bytearray()
        self.condition = threading.Condition()
        self.incoming_closed = False
        self.closed = False

    def send(self, value) -> int:
        encoded = bytes(value)
        if self.peer is None or self.closed:
            raise OSError("closed")
        with self.peer.condition:
            self.peer.buffer.extend(encoded)
            self.peer.condition.notify_all()
        return len(encoded)

    def sendall(self, value) -> None:
        self.send(value)

    def recv(self, size: int) -> bytes:
        deadline = time.monotonic() + 5
        with self.condition:
            while not self.buffer and not self.incoming_closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("memory endpoint stalled")
                self.condition.wait(remaining)
            if not self.buffer:
                return b""
            result = bytes(self.buffer[:size])
            del self.buffer[:size]
            return result

    def shutdown(self, _how) -> None:
        if self.peer is not None:
            with self.peer.condition:
                self.peer.incoming_closed = True
                self.peer.condition.notify_all()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.shutdown(socket.SHUT_WR)


def memory_pair() -> tuple[MemoryEndpoint, MemoryEndpoint]:
    left = MemoryEndpoint()
    right = MemoryEndpoint()
    left.peer = right
    right.peer = left
    return left, right


def raw_request(
    payload: dict | None = None,
    *,
    method: str = "POST",
    path: str = "/v1/responses",
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    document = payload or {
        "model": MODEL,
        "stream": True,
        "input": "synthetic evaluator input",
        "max_output_tokens": 100,
    }
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    return raw_request_body(
        body,
        method=method,
        path=path,
        extra_headers=extra_headers,
    )


def raw_request_body(
    body: bytes,
    *,
    method: str = "POST",
    path: str = "/v1/responses",
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: 127.0.0.1:43121",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        *[f"{name}: {value}" for name, value in extra_headers],
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body


class AttemptResponsesProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "coordination"
        root.mkdir(mode=0o700)
        self.ledger = AttemptProxyLedger(root / "proxy.sqlite3")

    def tearDown(self) -> None:
        self.ledger.close()
        self.temp.cleanup()

    def contract(self, **changes) -> AttemptProxyContract:
        values = {
            "attempt_id": ATTEMPT_ID,
            "contract_sha256": CONTRACT_SHA256,
            "endpoint_id": "role.development.v5",
            "model": MODEL,
            "max_requests": 4,
            "max_body_bytes": 16_384,
            "max_input_tokens": 16_384,
            "max_output_tokens": 1_000,
            "max_total_tokens": 17_384,
            "max_wall_seconds": 60.0,
            "sse_idle_seconds": 5.0,
        }
        values.update(changes)
        return AttemptProxyContract(**values)

    @staticmethod
    def credential() -> ApprovedCredentialReference:
        return ApprovedCredentialReference(
            "provider://synthetic-project/evaluator",
            "platform_api_project",
            APPROVAL_SHA256,
        )

    def permit(self, contract=None):
        resolved = contract or self.contract()
        return preflight_before_reservation(
            resolved,
            ProxyActivation(True, self.credential()),
        )

    def proxy(self, outcomes, *, contract=None, clock=None):
        resolved = contract or self.contract()
        transport = FakeTransport(outcomes)
        proxy = AttemptBoundResponsesProxy(
            self.permit(resolved),
            self.ledger,
            transport,
            monotonic=clock or FakeClock(),
        )
        proxy.start(now="2026-08-25T10:00:00Z")
        return proxy, transport

    def test_disabled_default_and_missing_credential_hold_before_reservation(self) -> None:
        contract = self.contract()
        called = False

        def reserve(_permit):
            nonlocal called
            called = True

        with self.assertRaisesRegex(ProxyHold, HOLD_UPSTREAM_AUTH_UNSUPPORTED):
            preflight_then_reserve(contract, ProxyActivation(), reserve)
        self.assertFalse(called)
        with self.assertRaisesRegex(ProxyHold, HOLD_PROXY_DISABLED):
            preflight_then_reserve(
                contract,
                ProxyActivation(False, self.credential()),
                reserve,
            )
        self.assertFalse(called)

    def test_credential_reference_rejects_secret_shaped_values(self) -> None:
        for reference in (
            "sk-synthetic-not-a-real-key",
            "Bearer-synthetic",
            "provider://refresh_token",
        ):
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(
                    ProxyError, "CREDENTIAL_REFERENCE_NOT_OPAQUE"
                ):
                    ApprovedCredentialReference(
                        reference, "platform_api_project", APPROVAL_SHA256
                    )
        with self.assertRaisesRegex(ProxyError, "PERMIT_BINDING_INVALID"):
            ProxyPermit(self.contract(), self.credential(), "f" * 64)
    def test_machine_local_provider_is_exact_and_uncredentialed(self) -> None:
        contract = self.contract()
        rendered = render_machine_local_provider_config(contract, loopback_port=43121)
        parsed = tomllib.loads(rendered)
        self.assertEqual(MODEL, parsed["model"])
        self.assertEqual("twinfinity-attempt-responses", parsed["model_provider"])
        provider = parsed["model_providers"]["twinfinity-attempt-responses"]
        self.assertEqual(
            {
                "name",
                "base_url",
                "wire_api",
                "requires_openai_auth",
                "request_max_retries",
                "stream_max_retries",
                "stream_idle_timeout_ms",
            },
            set(provider),
        )
        self.assertEqual("http://127.0.0.1:43121/v1", provider["base_url"])
        self.assertEqual("responses", provider["wire_api"])
        self.assertFalse(provider["requires_openai_auth"])
        self.assertEqual(0, provider["request_max_retries"])
        self.assertEqual(0, provider["stream_max_retries"])
        for forbidden in ("env_key", "http_headers", "Authorization", "OPENAI_API_KEY"):
            self.assertNotIn(forbidden, rendered)

        machine_home = Path(self.temp.name) / "attempt-codex-home"
        machine_home.mkdir(mode=0o700)
        path = write_machine_local_provider_config(
            machine_home, contract, loopback_port=43121
        )
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        with self.assertRaisesRegex(ProxyError, "MACHINE_CONFIG_WRITE_FAILED"):
            write_machine_local_provider_config(
                machine_home, contract, loopback_port=43121
            )

    def test_environment_and_mount_contract_expose_no_reusable_authority(self) -> None:
        base = {
            "HOME": "/home/ubuntu",
            "PATH": "/usr/bin",
            "LANG": "C.UTF-8",
            "OPENAI_API_KEY": "synthetic-forbidden",
            "CODEX_API_KEY": "synthetic-forbidden",
            "TWINFINITY_EXECUTOR_TOKEN": "synthetic-forbidden",
            "SSH_AUTH_SOCK": "/run/agent",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
            "HTTPS_PROXY": "http://proxy.invalid",
        }
        environment = build_uncredentialed_child_environment(
            base,
            contract=self.contract(),
            machine_codex_home="/run/twinfinity-attempt/codex-home",
            loopback_port=43121,
        )
        self.assertEqual("/usr/bin", environment["PATH"])
        self.assertEqual("/run/twinfinity-attempt/home", environment["HOME"])
        with self.assertRaisesRegex(ProxyError, "CHILD_ENVIRONMENT_INVALID"):
            build_uncredentialed_child_environment(
                base,
                contract=self.contract(),
                machine_codex_home="/workspace",
                loopback_port=43121,
            )
        for forbidden in (
            "OPENAI_API_KEY",
            "CODEX_API_KEY",
            "TWINFINITY_EXECUTOR_TOKEN",
            "SSH_AUTH_SOCK",
            "DBUS_SESSION_BUS_ADDRESS",
            "HTTPS_PROXY",
        ):
            self.assertNotIn(forbidden, environment)
        fixture = Path(self.temp.name) / "mount-fixture"
        repository_parent = fixture / "repositories"
        repository = repository_parent / "exact-repository"
        attempt_parent = fixture / "attempts"
        attempt_root = attempt_parent / ATTEMPT_ID
        for directory in (
            repository_parent,
            repository,
            attempt_parent,
            attempt_root,
            attempt_root / "codex-home",
            attempt_root / "out",
            attempt_root / "runtime",
            attempt_root / "home",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (attempt_root / "out", attempt_root / "runtime", attempt_root / "home"):
            directory.chmod(0o700)
        (attempt_root / "contract.json").write_text("{}", encoding="utf-8")
        (attempt_root / "codex-home" / "config.toml").write_text("", encoding="utf-8")
        (attempt_root / "contract.json").chmod(0o600)
        (attempt_root / "codex-home" / "config.toml").chmod(0o600)
        policy = AttemptMountPolicy(
            os.fspath(repository_parent),
            os.fspath(repository),
            os.fspath(attempt_parent),
            os.fspath(attempt_root),
        )
        valid = (
            SupplementalMount("repository", os.fspath(repository), "/workspace", False),
            SupplementalMount(
                "attempt_contract",
                os.fspath(attempt_root / "contract.json"),
                "/run/twinfinity-attempt/contract.json",
                False,
            ),
            SupplementalMount(
                "provider_config",
                os.fspath(attempt_root / "codex-home" / "config.toml"),
                "/run/twinfinity-attempt/codex-home/config.toml",
                False,
            ),
            SupplementalMount(
                "receipt_output",
                os.fspath(attempt_root / "out"),
                "/run/twinfinity-attempt/out",
                True,
            ),
            SupplementalMount(
                "runtime",
                os.fspath(attempt_root / "runtime"),
                "/run/twinfinity-attempt/runtime",
                True,
            ),
            SupplementalMount(
                "private_home",
                os.fspath(attempt_root / "home"),
                "/run/twinfinity-attempt/home",
                True,
            ),
        )
        validate_supplemental_mounts(valid, policy=policy)
        self.assertEqual(
            ("/home/ubuntu", "/run/user/1000"), required_namespace_masks()
        )

        symlink = fixture / "repository-alias"
        symlink.symlink_to(repository, target_is_directory=True)
        attacks = (
            SupplementalMount("repository", "/home/ubuntu", "/workspace", False),
            SupplementalMount("repository", "/etc", "/workspace", False),
            SupplementalMount("repository", "/proc/1/root/etc", "/workspace", False),
            SupplementalMount(
                "repository", os.fspath(repository / ".." / repository.name), "/workspace", False
            ),
            SupplementalMount("repository", os.fspath(symlink), "/workspace", False),
            SupplementalMount("repository", os.fspath(repository), "/workspace", True),
            SupplementalMount("repository", os.fspath(repository), "/etc", False),
            SupplementalMount(
                "receipt_output",
                os.fspath(repository),
                "/run/twinfinity-attempt/out",
                True,
            ),
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                mutated = tuple(attack if mount.role == attack.role else mount for mount in valid)
                with self.assertRaises(ProxyError):
                    validate_supplemental_mounts(mutated, policy=policy)

    def test_success_streams_sse_and_records_only_hashed_lineage(self) -> None:
        stream = FakeStream(response_stream(fragments=True))
        proxy, transport = self.proxy([stream])
        emitted: list[bytes] = []
        result = proxy.handle_raw_request(raw_request(), emitted.append)
        self.assertEqual((200, "COMPLETE", 1), (
            result.http_status,
            result.request_state,
            result.sequence,
        ))
        response = b"".join(emitted)
        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"response.completed", response)
        self.assertNotIn(b"set-cookie", response.lower())
        self.assertTrue(stream.closed)
        self.assertEqual((0,), proxy.upstream_worker_exitcodes)
        self.assertEqual(1, len(transport.calls))
        upstream_request, credential, _timeout = transport.calls[0]
        self.assertEqual(self.credential(), credential)
        self.assertEqual(
            (("accept", "text/event-stream"), ("content-type", "application/json")),
            upstream_request.headers,
        )
        forwarded = json.loads(upstream_request.body)
        self.assertEqual(MODEL, forwarded["model"])
        self.assertFalse(forwarded["store"])

        request_row = self.ledger.request_rows(ATTEMPT_ID)[0]
        self.assertEqual("COMPLETE", request_row["state"])
        self.assertEqual(sha256_text(RESPONSE_ID), request_row["response_id_sha256"])
        stored_values = tuple(request_row)
        self.assertNotIn(RESPONSE_ID, stored_values)
        events = self.ledger.request_events(ATTEMPT_ID, 1)
        self.assertEqual(
            ["CREATED", "UPSTREAM_STARTED", "STREAMING", "COMPLETE"],
            [event["to_state"] for event in events],
        )
        proxy.complete(now="2026-08-25T10:01:00Z")
        self.assertEqual("COMPLETE", self.ledger.proxy_row(ATTEMPT_ID)["state"])

    def test_child_auth_and_routing_headers_are_rejected_before_upstream(self) -> None:
        headers = (
            ("Authorization", "Bearer child"),
            ("Cookie", "session=child"),
            ("OpenAI-Project", "child-project"),
            ("X-OpenAI-Account", "child-account"),
        )
        for index, header in enumerate(headers):
            with self.subTest(header=header[0]):
                root = Path(self.temp.name) / f"header-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"66666666-6666-4666-8666-66666666666{index}"
                    )
                    transport = FakeTransport([FakeStream(response_stream())])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    emitted: list[bytes] = []
                    result = proxy.handle_raw_request(
                        raw_request(extra_headers=(header,)), emitted.append
                    )
                    self.assertEqual(
                        (403, "FAILED"),
                        (result.http_status, result.request_state),
                    )
                    self.assertEqual([], transport.calls)
                    self.assertIn(
                        b"BROKER_PROXY_CHILD_AUTH_HEADER_REJECTED",
                        b"".join(emitted),
                    )

    def test_method_path_model_and_hosted_tools_are_closed(self) -> None:
        cases = (
            (raw_request(method="GET"), "BROKER_PROXY_METHOD_REJECTED"),
            (raw_request(path="/v1/models"), "BROKER_PROXY_PATH_REJECTED"),
            (
                raw_request(
                    {"model": "wrong", "stream": True, "input": "x"}
                ),
                "BROKER_PROXY_MODEL_MISMATCH",
            ),
            (
                raw_request(
                    {
                        "model": MODEL,
                        "stream": True,
                        "input": "x",
                        "tools": [{"type": "web_search_preview"}],
                    }
                ),
                "BROKER_PROXY_TOOLS_REJECTED",
            ),
        )
        for index, (request, code) in enumerate(cases):
            with self.subTest(code=code):
                separate_root = Path(self.temp.name) / f"case-{index}"
                separate_root.mkdir(mode=0o700)
                with AttemptProxyLedger(separate_root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"11111111-1111-4111-8111-11111111111{index}"
                    )
                    transport = FakeTransport([FakeStream(response_stream())])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    emitted: list[bytes] = []
                    result = proxy.handle_raw_request(request, emitted.append)
                    self.assertEqual("FAILED", result.request_state)
                    self.assertIn(code.encode("ascii"), b"".join(emitted))
                    self.assertEqual([], transport.calls)

    def test_http_smuggling_forms_fail_and_hop_headers_are_not_forwarded(self) -> None:
        malformed_requests = (
            raw_request(extra_headers=(("Transfer-Encoding", "chunked"),)),
            raw_request().replace(b"Content-Length: ", b"Content-Length: +", 1),
        )
        for index, malformed in enumerate(malformed_requests):
            with self.subTest(index=index):
                root = Path(self.temp.name) / f"smuggling-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"13131313-1313-4313-8313-13131313131{index}"
                    )
                    transport = FakeTransport([FakeStream(response_stream())])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    result = proxy.handle_raw_request(malformed, lambda _value: None)
                    self.assertEqual("FAILED", result.request_state)
                    self.assertEqual([], transport.calls)

        separate_root = Path(self.temp.name) / "hop-header"
        separate_root.mkdir(mode=0o700)
        with AttemptProxyLedger(separate_root / "proxy.sqlite3") as ledger:
            contract = self.contract(
                attempt_id="44444444-4444-4444-8444-444444444444"
            )
            hop_transport = FakeTransport([FakeStream(response_stream())])
            hop_proxy = AttemptBoundResponsesProxy(
                self.permit(contract), ledger, hop_transport, monotonic=FakeClock()
            )
            hop_proxy.start()
            accepted = hop_proxy.handle_raw_request(
                raw_request(extra_headers=(("Connection", "keep-alive"),)),
                lambda _value: None,
            )
            self.assertEqual("COMPLETE", accepted.request_state)
            forwarded_headers = dict(hop_transport.calls[0][0].headers)
            self.assertNotIn("connection", forwarded_headers)

    def test_request_count_and_concurrency_are_hard_limits(self) -> None:
        contract = self.contract(max_requests=2)
        proxy, transport = self.proxy(
            [FakeStream(response_stream())], contract=contract
        )
        first_sequence = self.ledger.begin_request(ATTEMPT_ID, "d" * 64)
        with self.assertRaisesRegex(ProxyPolicyError, "CONCURRENCY_LIMIT"):
            self.ledger.begin_request(ATTEMPT_ID, "e" * 64)
        self.ledger.transition_request(
            ATTEMPT_ID,
            first_sequence,
            expected_states={"CREATED"},
            new_state="FAILED",
            error_code="SYNTHETIC_LOCAL_FAILURE",
        )
        second_sequence = self.ledger.begin_request(ATTEMPT_ID, "e" * 64)
        self.ledger.transition_request(
            ATTEMPT_ID,
            second_sequence,
            expected_states={"CREATED"},
            new_state="FAILED",
            error_code="SYNTHETIC_LOCAL_FAILURE",
        )
        emitted: list[bytes] = []
        limited = proxy.handle_raw_request(raw_request(), emitted.append)
        self.assertEqual((429, "FAILED", 0), (
            limited.http_status, limited.request_state, limited.sequence
        ))
        self.assertIn(b"BROKER_PROXY_REQUEST_LIMIT", b"".join(emitted))
        self.assertEqual([], transport.calls)

    def test_body_and_token_limits_fail_before_upstream(self) -> None:
        cases = (
            (
                self.contract(
                    attempt_id="55555555-5555-4555-8555-555555555550",
                    max_body_bytes=1024,
                ),
                raw_request(
                    {
                        "model": MODEL,
                        "stream": True,
                        "input": "x" * 1500,
                        "max_output_tokens": 10,
                    }
                ),
                "BROKER_PROXY_BODY_LIMIT",
            ),
            (
                self.contract(
                    attempt_id="55555555-5555-4555-8555-555555555551",
                    max_input_tokens=64,
                    max_output_tokens=100,
                    max_total_tokens=100,
                ),
                raw_request(
                    {
                        "model": MODEL,
                        "stream": True,
                        "input": "input exceeds conservative token budget",
                        "max_output_tokens": 10,
                    }
                ),
                "BROKER_PROXY_TOKEN_LIMIT",
            ),
            (
                self.contract(
                    attempt_id="55555555-5555-4555-8555-555555555552",
                    max_output_tokens=50,
                    max_total_tokens=16_434,
                ),
                raw_request(
                    {
                        "model": MODEL,
                        "stream": True,
                        "input": "x",
                        "max_output_tokens": 51,
                    }
                ),
                "BROKER_PROXY_OUTPUT_TOKEN_LIMIT",
            ),
        )
        for index, (contract, request, code) in enumerate(cases):
            with self.subTest(code=code):
                root = Path(self.temp.name) / f"limit-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    transport = FakeTransport([FakeStream(response_stream())])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    emitted: list[bytes] = []
                    result = proxy.handle_raw_request(request, emitted.append)
                    self.assertEqual("FAILED", result.request_state)
                    self.assertIn(code.encode("ascii"), b"".join(emitted))
                    self.assertEqual([], transport.calls)

    def test_reported_usage_overrun_holds_after_stream_without_replay(self) -> None:
        contract = self.contract(
            max_output_tokens=100,
            max_total_tokens=16_484,
        )
        proxy, transport = self.proxy(
            [FakeStream(response_stream(output_tokens=101))], contract=contract
        )
        emitted: list[bytes] = []
        result = proxy.handle_raw_request(raw_request(), emitted.append)
        self.assertEqual("FAILED", result.request_state)
        self.assertNotIn(b"response.completed", b"".join(emitted))
        self.assertEqual(
            0,
            self.ledger.request_rows(ATTEMPT_ID)[0]["completion_prepared"],
        )
        row = self.ledger.proxy_row(ATTEMPT_ID)
        self.assertEqual(("HOLD", "BROKER_PROXY_BUDGET_OVERRUN"), (
            row["state"], row["hold_code"]
        ))
        self.assertEqual(1, len(transport.calls))
        limited = proxy.handle_raw_request(raw_request(), lambda _value: None)
        self.assertEqual((409, 0), (limited.http_status, limited.sequence))
        self.assertEqual(1, len(transport.calls))

    def test_upstream_credential_rejection_holds_without_retry(self) -> None:
        proxy, transport = self.proxy(
            [FakeStream([], status=401, content_type="application/json")]
        )
        emitted: list[bytes] = []
        result = proxy.handle_raw_request(raw_request(), emitted.append)
        self.assertEqual((502, "FAILED"), (result.http_status, result.request_state))
        row = self.ledger.proxy_row(ATTEMPT_ID)
        self.assertEqual(
            ("HOLD", "BROKER_UPSTREAM_CREDENTIAL_REJECTED"),
            (row["state"], row["hold_code"]),
        )
        self.assertEqual(1, len(transport.calls))

    def test_wall_deadline_fails_before_upstream_start(self) -> None:
        clock = FakeClock()
        proxy, transport = self.proxy(
            [FakeStream(response_stream())], clock=clock
        )
        clock.advance(61)
        emitted: list[bytes] = []
        result = proxy.handle_raw_request(raw_request(), emitted.append)
        self.assertEqual((504, "FAILED"), (result.http_status, result.request_state))
        self.assertEqual([], transport.calls)
        self.assertIn(b"BROKER_PROXY_WALL_TIMEOUT", b"".join(emitted))

    def test_response_id_lineage_is_host_authored_and_attempt_local(self) -> None:
        second_response = "resp_attempt_two"
        proxy, transport = self.proxy(
            [
                FakeStream(response_stream(RESPONSE_ID)),
                FakeStream(response_stream(second_response)),
            ]
        )
        first = proxy.handle_raw_request(raw_request(), lambda _value: None)
        self.assertEqual("COMPLETE", first.request_state)
        chained = raw_request(
            {
                "model": MODEL,
                "stream": True,
                "input": "follow-up",
                "max_output_tokens": 100,
            }
        )
        second = proxy.handle_raw_request(chained, lambda _value: None)
        self.assertEqual("COMPLETE", second.request_state)
        self.assertEqual(2, len(transport.calls))
        first_body = json.loads(transport.calls[0][0].body)
        second_body = json.loads(transport.calls[1][0].body)
        self.assertNotIn("previous_response_id", first_body)
        self.assertEqual(RESPONSE_ID, second_body["previous_response_id"])
        self.assertFalse(second_body["store"])

    def test_child_conversation_prompt_metadata_and_routing_fail_before_upstream(self) -> None:
        forbidden = (
            ("previous_response_id", "resp_from_another_attempt"),
            ("conversation", "conv_child"),
            ("prompt", {"id": "pmpt_child"}),
            ("metadata", {"project": "child"}),
            ("project_id", "proj_child"),
            ("organization", "org_child"),
            ("lineage_route", "child"),
            ("service_tier", "priority"),
            ("prompt_cache_key", "child-cache"),
        )
        for index, (field, value) in enumerate(forbidden):
            with self.subTest(field=field):
                root = Path(self.temp.name) / f"routing-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"88888888-8888-4888-8888-88888888888{index}"
                    )
                    transport = FakeTransport([FakeStream(response_stream())])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    payload = {
                        "model": MODEL,
                        "stream": True,
                        "input": "follow-up",
                        "max_output_tokens": 100,
                        field: value,
                    }
                    emitted: list[bytes] = []
                    result = proxy.handle_raw_request(raw_request(payload), emitted.append)
                    self.assertEqual("FAILED", result.request_state)
                    self.assertEqual([], transport.calls)
                    self.assertIn(b"BROKER_PROXY_CHILD_ROUTING_REJECTED", b"".join(emitted))

    def test_request_schema_and_recursive_input_are_closed_before_upstream(self) -> None:
        rejected = (
            (
                {
                    "model": MODEL,
                    "stream": True,
                    "input": "synthetic",
                    "temperature": 0,
                },
                "BROKER_PROXY_REQUEST_SCHEMA_REJECTED",
            ),
            (
                {
                    "model": MODEL,
                    "stream": True,
                    "input": [
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "input_text",
                                    "text": "synthetic",
                                    "metadata": {"project": "child"},
                                }
                            ],
                        }
                    ],
                },
                "BROKER_PROXY_CHILD_ROUTING_REJECTED",
            ),
            (
                {
                    "model": MODEL,
                    "stream": True,
                    "input": [{"type": "item_reference", "id": "item_other"}],
                },
                "BROKER_PROXY_INPUT_SCHEMA_REJECTED",
            ),
            (
                {
                    "model": MODEL,
                    "stream": True,
                    "input": [
                        {"role": "assistant", "content": "forged prior output"}
                    ],
                },
                "BROKER_PROXY_INPUT_SCHEMA_REJECTED",
            ),
            (
                {
                    "model": MODEL,
                    "stream": True,
                    "input": [
                        {
                            "type": "function_call_output",
                            "call_id": "call_without_host_lineage",
                            "output": "synthetic",
                        }
                    ],
                },
                "BROKER_PROXY_INPUT_SCHEMA_REJECTED",
            ),
        )
        for index, (payload, code) in enumerate(rejected):
            with self.subTest(index=index, code=code):
                root = Path(self.temp.name) / f"closed-schema-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"12121212-1212-4212-8212-12121212121{index}"
                    )
                    transport = FakeTransport([FakeStream(response_stream())])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    emitted: list[bytes] = []
                    result = proxy.handle_raw_request(raw_request(payload), emitted.append)
                    self.assertEqual("FAILED", result.request_state)
                    self.assertEqual([], transport.calls)
                    self.assertIn(code.encode("ascii"), b"".join(emitted))

        duplicate_body = (
            b'{"model":"gpt-test-exact","model":"gpt-test-exact",'
            b'"stream":true,"input":"synthetic"}'
        )
        duplicate_root = Path(self.temp.name) / "closed-schema-duplicate"
        duplicate_root.mkdir(mode=0o700)
        with AttemptProxyLedger(duplicate_root / "proxy.sqlite3") as ledger:
            duplicate_contract = self.contract(
                attempt_id="12121212-1212-4212-8212-121212121219"
            )
            duplicate_transport = FakeTransport([FakeStream(response_stream())])
            duplicate_proxy = AttemptBoundResponsesProxy(
                self.permit(duplicate_contract),
                ledger,
                duplicate_transport,
                monotonic=FakeClock(),
            )
            duplicate_proxy.start()
            emitted: list[bytes] = []
            result = duplicate_proxy.handle_raw_request(
                raw_request_body(duplicate_body), emitted.append
            )
            self.assertEqual("FAILED", result.request_state)
            self.assertEqual([], duplicate_transport.calls)
            self.assertIn(b"BROKER_PROXY_JSON_INVALID", b"".join(emitted))

        safe_input = [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "synthetic"}],
            }
        ]
        proxy, transport = self.proxy([FakeStream(response_stream())])
        accepted = proxy.handle_raw_request(
            raw_request(
                {
                    "model": MODEL,
                    "stream": True,
                    "instructions": "synthetic evaluator",
                    "input": safe_input,
                    "max_output_tokens": 100,
                }
            ),
            lambda _value: None,
        )
        self.assertEqual("COMPLETE", accepted.request_state)
        self.assertEqual(safe_input, json.loads(transport.calls[0][0].body)["input"])

    def test_json_numbers_are_finite_before_digest_or_transport(self) -> None:
        for value in (
            float("inf"),
            float("-inf"),
            float("nan"),
            {"nested": [float("inf")]},
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    canonical_json({"value": value})

        invalid_bodies = (
            b'{"model":"gpt-test-exact","stream":true,"input":"x","value":1e400}',
            b'{"model":"gpt-test-exact","stream":true,"input":"x","value":-1e400}',
            b'{"model":"gpt-test-exact","stream":true,"input":{"nested":[1e400]}}',
            b'{"model":"gpt-test-exact","stream":true,"input":"x","value":NaN}',
            b'{"model":"gpt-test-exact","stream":true,"input":"x","value":Infinity}',
        )
        for index, body in enumerate(invalid_bodies):
            with self.subTest(index=index):
                root = Path(self.temp.name) / f"finite-json-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"14141414-1414-4414-8414-14141414141{index}"
                    )
                    transport = FakeTransport([FakeStream(response_stream())])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    emitted: list[bytes] = []
                    result = proxy.handle_raw_request(
                        raw_request_body(body), emitted.append
                    )
                    self.assertEqual("FAILED", result.request_state)
                    self.assertEqual([], transport.calls)
                    self.assertIn(b"BROKER_PROXY_JSON_INVALID", b"".join(emitted))

        tools = [
            {
                "type": "function",
                "name": "synthetic_lookup",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "number", "maximum": 1e308}
                    },
                },
            }
        ]
        finite_contract = self.contract(
            allowed_tools_sha256=sha256_text(canonical_json(tools))
        )
        proxy, transport = self.proxy(
            [FakeStream(response_stream())], contract=finite_contract
        )
        result = proxy.handle_raw_request(
            raw_request(
                {
                    "model": MODEL,
                    "stream": True,
                    "input": "synthetic",
                    "tools": tools,
                    "max_output_tokens": 100,
                }
            ),
            lambda _value: None,
        )
        self.assertEqual("COMPLETE", result.request_state)
        forwarded_tools = json.loads(transport.calls[0][0].body)["tools"]
        self.assertEqual(tools, forwarded_tools)

    def test_safe_not_sent_and_ambiguous_are_distinct_and_never_replayed(self) -> None:
        proxy, transport = self.proxy(["ZERO_NOT_SENT"])
        safe = proxy.handle_raw_request(raw_request(), lambda _value: None)
        self.assertEqual("SAFE_NOT_SENT", safe.request_state)
        self.assertEqual("RUNNING", self.ledger.proxy_row(ATTEMPT_ID)["state"])
        self.assertEqual(1, len(transport.calls))
        safe_row = self.ledger.request_rows(ATTEMPT_ID)[0]
        self.assertEqual(0, safe_row["upstream_bytes_sent"])
        self.assertRegex(safe_row["send_evidence_sha256"], r"^[0-9a-f]{64}$")

        separate_root = Path(self.temp.name) / "ambiguous"
        separate_root.mkdir(mode=0o700)
        with AttemptProxyLedger(separate_root / "proxy.sqlite3") as ledger:
            contract = self.contract(
                attempt_id="22222222-2222-4222-8222-222222222222"
            )
            ambiguous_transport = FakeTransport([RuntimeError("connection lost")])
            ambiguous_proxy = AttemptBoundResponsesProxy(
                self.permit(contract),
                ledger,
                ambiguous_transport,
                monotonic=FakeClock(),
            )
            ambiguous_proxy.start()
            result = ambiguous_proxy.handle_raw_request(
                raw_request(), lambda _value: None
            )
            self.assertEqual("AMBIGUOUS", result.request_state)
            row = ledger.proxy_row(contract.attempt_id)
            self.assertEqual(("HOLD", HOLD_UPSTREAM_AMBIGUOUS), (
                row["state"], row["hold_code"]
            ))
            with self.assertRaisesRegex(ProxyHold, "BROKER_PROXY_NOT_RUNNING"):
                ledger.begin_request(contract.attempt_id, "c" * 64)
            self.assertEqual(1, len(ambiguous_transport.calls))

    def test_confirmed_process_loss_recovery_is_conservative_and_idempotent(self) -> None:
        process_identity_sha256 = "9" * 64
        cases = (
            ("CREATED", "SAFE_NOT_SENT", "BROKER_PROXY_PROCESS_LOST"),
            ("UPSTREAM_STARTED", "AMBIGUOUS", HOLD_UPSTREAM_AMBIGUOUS),
        )
        for index, (initial, recovered_state, hold_code) in enumerate(cases):
            with self.subTest(initial=initial):
                root = Path(self.temp.name) / f"recovery-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"77777777-7777-4777-8777-77777777777{index}"
                    )
                    permit = self.permit(contract)
                    ledger.register(permit)
                    ledger.activate(contract.attempt_id)
                    ledger.bind_process_identity(
                        contract.attempt_id,
                        permit_binding_sha256=permit.binding_sha256,
                        process_identity_sha256=process_identity_sha256,
                    )
                    sequence = ledger.begin_request(contract.attempt_id, "8" * 64)
                    if initial == "UPSTREAM_STARTED":
                        ledger.transition_request(
                            contract.attempt_id,
                            sequence,
                            expected_states={"CREATED"},
                            new_state="UPSTREAM_STARTED",
                        )
                    receipt = ProxyProcessTerminalReceipt(
                        contract.attempt_id,
                        permit.binding_sha256,
                        process_identity_sha256,
                        "EXITED",
                        "2026-08-25T10:02:00Z",
                    )
                    recovered = ledger.recover_after_confirmed_process_loss(
                        contract.attempt_id,
                        receipt=receipt,
                    )
                    self.assertEqual("HOLD", recovered["proxy_state"])
                    self.assertEqual(hold_code, recovered["hold_code"])
                    self.assertEqual(
                        recovered_state,
                        ledger.request_rows(contract.attempt_id)[0]["state"],
                    )
                    repeated = ledger.recover_after_confirmed_process_loss(
                        contract.attempt_id,
                        receipt=receipt,
                    )
                    self.assertEqual([], repeated["recovered_requests"])
                    events = ledger.request_events(contract.attempt_id, sequence)
                    self.assertEqual(
                        recovered_state,
                        events[-1]["to_state"],
                    )
                    if recovered_state == "SAFE_NOT_SENT":
                        row = ledger.request_rows(contract.attempt_id)[0]
                        self.assertEqual(0, row["upstream_bytes_sent"])
                        self.assertRegex(row["send_evidence_sha256"], r"^[0-9a-f]{64}$")
                    wrong_receipt = ProxyProcessTerminalReceipt(
                        contract.attempt_id,
                        "e" * 64,
                        process_identity_sha256,
                        "EXITED",
                        "2026-08-25T10:02:00Z",
                    )
                    with self.assertRaisesRegex(
                        ProxyError, "RECOVERY_RECEIPT_BINDING_INVALID"
                    ):
                        ledger.recover_after_confirmed_process_loss(
                            contract.attempt_id,
                            receipt=wrong_receipt,
                        )

    def test_sse_idle_and_truncation_become_ambiguous(self) -> None:
        for index, (stream, clock) in enumerate(
            (
                (FakeStream([b"data: {\"type\":\"response.created\"}\n\n"]), FakeClock()),
                (None, FakeClock()),
            )
        ):
            with self.subTest(index=index):
                separate_root = Path(self.temp.name) / f"sse-{index}"
                separate_root.mkdir(mode=0o700)
                with AttemptProxyLedger(separate_root / "proxy.sqlite3") as ledger:
                    changes = {
                        "attempt_id": f"33333333-3333-4333-8333-33333333333{index}"
                    }
                    if stream is None:
                        changes.update(
                            io_timeout_seconds=0.2,
                            sse_idle_seconds=0.2,
                        )
                        stream = SlowReturningStream(response_stream())
                    contract = self.contract(**changes)
                    transport = FakeTransport([stream])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=clock
                    )
                    proxy.start()
                    result = proxy.handle_raw_request(
                        raw_request(), lambda _value: None
                    )
                    self.assertEqual("AMBIGUOUS", result.request_state)
                    self.assertEqual("HOLD", ledger.proxy_row(contract.attempt_id)["state"])

    def test_sse_order_duplicates_and_post_completion_events_never_escape(self) -> None:
        delta = {"type": "response.output_text.delta", "delta": "late"}
        cases = (
            event_wire(completed_event()),
            event_wire(created_event()) + event_wire(created_event()),
            event_wire(created_event()) + event_wire(completed_event()) + event_wire(delta),
            event_wire(created_event())
            + event_wire(completed_event())
            + event_wire(completed_event()),
            event_wire(created_event())
            + event_wire(completed_event())
            + event_wire("[DONE]")
            + event_wire(delta),
            event_wire(created_event())
            + event_wire(completed_event())
            + b": forbidden heartbeat after completion\n\n",
            b": forbidden heartbeat before creation\n\n"
            + event_wire(created_event())
            + event_wire(completed_event()),
            event_wire(created_event())
            + b'data: {"type":"response.completed","type":"response.output_text.delta"}\n\n',
        )
        for index, encoded in enumerate(cases):
            with self.subTest(index=index):
                root = Path(self.temp.name) / f"sse-order-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    contract = self.contract(
                        attempt_id=f"99999999-9999-4999-8999-99999999999{index}"
                    )
                    transport = FakeTransport([FakeStream([encoded])])
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract), ledger, transport, monotonic=FakeClock()
                    )
                    proxy.start()
                    emitted: list[bytes] = []
                    result = proxy.handle_raw_request(raw_request(), emitted.append)
                    self.assertEqual("AMBIGUOUS", result.request_state)
                    self.assertEqual("HOLD", ledger.proxy_row(contract.attempt_id)["state"])
                    self.assertNotIn(b"response.completed", b"".join(emitted))

    def test_upstream_chunk_event_and_total_response_bounds_are_hard(self) -> None:
        cases = (
            (
                self.contract(
                    attempt_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
                    max_stream_chunk_bytes=1024,
                    max_response_bytes=4096,
                ),
                [b"x" * 1025],
                "BROKER_PROXY_SSE_CHUNK_LIMIT",
            ),
            (
                self.contract(
                    attempt_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
                    max_stream_chunk_bytes=1024,
                    max_response_bytes=1024,
                ),
                [event_wire(created_event()), b": " + b"x" * 980 + b"\n\n"],
                "BROKER_PROXY_RESPONSE_LIMIT",
            ),
            (
                self.contract(
                    attempt_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3",
                    max_stream_chunk_bytes=1024,
                    max_response_bytes=4096,
                    max_sse_event_bytes=1024,
                ),
                [b"data: " + b"x" * 700, b"y" * 400],
                "BROKER_PROXY_SSE_EVENT_TOO_LARGE",
            ),
        )
        for index, (contract, chunks, code) in enumerate(cases):
            with self.subTest(code=code):
                root = Path(self.temp.name) / f"response-bound-{index}"
                root.mkdir(mode=0o700)
                with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
                    proxy = AttemptBoundResponsesProxy(
                        self.permit(contract),
                        ledger,
                        FakeTransport([FakeStream(chunks)]),
                        monotonic=FakeClock(),
                    )
                    proxy.start()
                    result = proxy.handle_raw_request(raw_request(), lambda _value: None)
                    self.assertEqual("AMBIGUOUS", result.request_state)
                    self.assertEqual(code, ledger.request_rows(contract.attempt_id)[0]["error_code"])

    def test_real_open_read_uds_and_loopback_deadlines_terminalize(self) -> None:
        contract = self.contract(io_timeout_seconds=0.2, sse_idle_seconds=0.2)
        transport = BlockingOpenTransport()
        proxy = AttemptBoundResponsesProxy(
            self.permit(contract),
            self.ledger,
            transport,
            monotonic=FakeClock(),
        )
        proxy.start()
        started = time.monotonic()
        result = proxy.handle_raw_request(raw_request(), lambda _value: None)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual("AMBIGUOUS", result.request_state)
        self.assertEqual("HOLD", self.ledger.proxy_row(ATTEMPT_ID)["state"])
        self.assertEqual((-signal.SIGKILL,), proxy.upstream_worker_exitcodes)
        self.assertFalse(transport.release.is_set())
        self.assertEqual(0, transport.cancelled.value)

        root = Path(self.temp.name) / "blocking-read"
        root.mkdir(mode=0o700)
        with AttemptProxyLedger(root / "proxy.sqlite3") as ledger:
            read_contract = self.contract(
                attempt_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                io_timeout_seconds=0.2,
                sse_idle_seconds=0.2,
            )
            stream = BlockingStream()
            read_proxy = AttemptBoundResponsesProxy(
                self.permit(read_contract),
                ledger,
                FakeTransport([stream]),
                monotonic=FakeClock(),
            )
            read_proxy.start()
            started = time.monotonic()
            result = read_proxy.handle_raw_request(raw_request(), lambda _value: None)
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertEqual("AMBIGUOUS", result.request_state)
            self.assertEqual("HOLD", ledger.proxy_row(read_contract.attempt_id)["state"])
            self.assertEqual(
                (-signal.SIGKILL,), read_proxy.upstream_worker_exitcodes
            )
            self.assertFalse(stream.release.is_set())

        host, relay = memory_pair()
        started = time.monotonic()
        with self.assertRaises(ProxyIOTimeout):
            receive_frame(host, deadline=IODeadline.after(0.05))
        self.assertLess(time.monotonic() - started, 0.5)
        host.close()
        relay.close()

        loopback_host, loopback_peer = memory_pair()
        started = time.monotonic()
        with self.assertRaises(ProxyIOTimeout):
            read_one_loopback_request(
                loopback_host,
                max_header_bytes=4096,
                max_body_bytes=4096,
                deadline=IODeadline.after(0.05),
            )
        self.assertLess(time.monotonic() - started, 0.5)
        loopback_host.close()
        loopback_peer.close()

    def test_open_timeout_kills_noop_cancel_worker_before_return(self) -> None:
        contract = self.contract(
            io_timeout_seconds=0.2,
            sse_idle_seconds=0.2,
        )
        transport = LateSendAfterCancelTransport()
        proxy = AttemptBoundResponsesProxy(
            self.permit(contract),
            self.ledger,
            transport,
            monotonic=FakeClock(),
        )
        proxy.start()
        context = multiprocessing.get_context("spawn")
        cancel_process = context.Process(
            target=acknowledge_cancel_without_terminalizing,
            args=(transport,),
        )
        cancel_process.start()
        started = time.monotonic()
        result = proxy.handle_raw_request(raw_request(), lambda _value: None)
        elapsed = time.monotonic() - started
        cancel_process.join(1.0)
        self.assertFalse(cancel_process.is_alive())
        self.assertEqual(0, cancel_process.exitcode)
        cancel_process.close()
        self.assertLess(elapsed, 1.0)
        self.assertEqual("AMBIGUOUS", result.request_state)
        self.assertEqual(1, transport.cancel_calls.value)
        self.assertEqual((-signal.SIGKILL,), proxy.upstream_worker_exitcodes)
        transport.release.value = 1
        time.sleep(0.1)
        self.assertEqual(0, transport.send_count.value)
        self.assertEqual(0, transport.resource_count.value)

    def test_slow_loopback_reader_is_backpressured_and_bounded(self) -> None:
        contract = self.contract(io_timeout_seconds=0.05, sse_idle_seconds=0.1)
        binding = self.permit(contract)
        host, relay = memory_pair()
        send_frame(host, Frame(FrameKind.RESPONSE_DATA, 1, b"bounded response"))
        send_frame(
            host,
            Frame(
                FrameKind.RESPONSE_END,
                1,
                canonical_json(
                    {
                        "http_status": 200,
                        "request_state": "COMPLETE",
                        "response_id_sha256": "d" * 64,
                        "sequence": 1,
                    }
                ).encode("ascii"),
            ),
        )
        client = ScriptedSlowClient(raw_request())
        started = time.monotonic()
        with self.assertRaises(ProxyIOTimeout):
            relay_one_loopback_connection(
                client,
                relay,
                contract,
                RelayBinding.from_permit(binding),
            )
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(client.closed)
        host.close()
        relay.close()

    def test_hello_binding_covers_every_contract_and_permit_field_before_ledger(self) -> None:
        proxy, _transport = self.proxy([FakeStream(response_stream())])
        exact = proxy.relay_binding
        mismatches = (
            replace(exact, attempt_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            replace(exact, contract_sha256="c" * 64),
            replace(exact, endpoint_sha256="c" * 64),
            replace(exact, policy_sha256="c" * 64),
            replace(exact, permit_binding_sha256="c" * 64),
        )
        for mismatch in mismatches:
            with self.subTest(field=mismatch):
                host, relay = memory_pair()
                send_frame(relay, Frame(FrameKind.HELLO, 0, channel_hello(mismatch)))
                with self.assertRaisesRegex(
                    ProxyProtocolError, "CHANNEL_BINDING_MISMATCH"
                ):
                    serve_framed_proxy_exchange(host, exact, proxy)
                self.assertEqual([], self.ledger.request_rows(ATTEMPT_ID))
                host.close()
                relay.close()

                host, relay = memory_pair()
                with self.assertRaisesRegex(
                    ProxyProtocolError, "CHANNEL_BINDING_MISMATCH"
                ):
                    serve_framed_proxy_exchange(host, mismatch, proxy)
                self.assertEqual([], self.ledger.request_rows(ATTEMPT_ID))
                host.close()
                relay.close()

    def test_forged_send_evidence_is_ambiguous_not_safe_not_sent(self) -> None:
        proxy = AttemptBoundResponsesProxy(
            self.permit(),
            self.ledger,
            ForgedSendEvidenceTransport(),
            monotonic=FakeClock(),
        )
        proxy.start()
        result = proxy.handle_raw_request(raw_request(), lambda _value: None)
        self.assertEqual("AMBIGUOUS", result.request_state)
        row = self.ledger.request_rows(ATTEMPT_ID)[0]
        self.assertIsNone(row["send_evidence_sha256"])
        self.assertIsNone(row["upstream_bytes_sent"])
        self.assertEqual("HOLD", self.ledger.proxy_row(ATTEMPT_ID)["state"])

    def test_request_state_graph_refuses_terminal_reopening(self) -> None:
        proxy, _transport = self.proxy([FakeStream(response_stream())])
        result = proxy.handle_raw_request(raw_request(), lambda _value: None)
        self.assertEqual("COMPLETE", result.request_state)
        with self.assertRaisesRegex(ProxyError, "REQUEST_TRANSITION_INVALID"):
            self.ledger.transition_request(
                ATTEMPT_ID,
                1,
                expected_states={"COMPLETE"},
                new_state="FAILED",
                error_code="SYNTHETIC_REOPEN",
            )
        self.assertEqual("COMPLETE", self.ledger.request_rows(ATTEMPT_ID)[0]["state"])

    def test_socketpair_framing_binds_exact_contract_and_streams(self) -> None:
        proxy, _transport = self.proxy([FakeStream(response_stream(fragments=True))])
        real_host, real_relay = create_attempt_socketpair()
        self.assertFalse(real_host.get_inheritable())
        self.assertFalse(real_relay.get_inheritable())
        real_host.close()
        real_relay.close()
        host, relay = memory_pair()
        outcome = {}

        def host_worker():
            try:
                outcome["result"] = serve_framed_proxy_exchange(
                    host, proxy.relay_binding, proxy
                )
            except Exception as exc:  # pragma: no cover - surfaced below
                outcome["error"] = exc

        thread = threading.Thread(target=host_worker)
        thread.start()
        response, terminal = relay_framed_http_request(
            relay, self.contract(), proxy.relay_binding, raw_request()
        )
        thread.join(timeout=5)
        host.close()
        relay.close()
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", outcome)
        self.assertEqual("COMPLETE", terminal["request_state"])
        self.assertIn(b"HTTP/1.1 200 OK", response)

    def test_channel_binding_mismatch_fails_before_request_ledger(self) -> None:
        proxy, _transport = self.proxy([FakeStream(response_stream())])
        host, relay = memory_pair()
        send_frame(relay, Frame(FrameKind.HELLO, 0, b"{}"))
        with self.assertRaisesRegex(ProxyProtocolError, "CHANNEL_BINDING_MISMATCH"):
            serve_framed_proxy_exchange(host, proxy.relay_binding, proxy)
        self.assertEqual([], self.ledger.request_rows(ATTEMPT_ID))
        host.close()
        relay.close()

    def test_loopback_connection_relay_never_receives_provider_credential(self) -> None:
        proxy, _transport = self.proxy([FakeStream(response_stream())])
        host_channel, relay_channel = memory_pair()
        client, loopback_side = memory_pair()
        outcomes = {}

        def host_worker():
            outcomes["host"] = serve_framed_proxy_exchange(
                host_channel, proxy.relay_binding, proxy
            )

        def relay_worker():
            outcomes["relay"] = relay_one_loopback_connection(
                loopback_side, relay_channel, self.contract(), proxy.relay_binding
            )
            loopback_side.close()

        host_thread = threading.Thread(target=host_worker)
        relay_thread = threading.Thread(target=relay_worker)
        host_thread.start()
        relay_thread.start()
        client.sendall(raw_request())
        client.shutdown(socket.SHUT_WR)
        response_parts = []
        while True:
            part = client.recv(8192)
            if not part:
                break
            response_parts.append(part)
        host_thread.join(timeout=5)
        relay_thread.join(timeout=5)
        client.close()
        host_channel.close()
        relay_channel.close()
        self.assertFalse(host_thread.is_alive())
        self.assertFalse(relay_thread.is_alive())
        self.assertEqual("COMPLETE", outcomes["host"].request_state)
        self.assertEqual("COMPLETE", outcomes["relay"]["request_state"])
        self.assertIn(b"response.completed", b"".join(response_parts))

    def test_ledger_schema_contains_hashes_not_payload_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.ledger.connection.execute(
                "PRAGMA table_info(executor_attempt_response_requests)"
            )
        }
        self.assertIn("request_sha256", columns)
        self.assertIn("response_id_sha256", columns)
        for forbidden in (
            "body",
            "headers",
            "prompt",
            "response_id",
            "credential",
            "authorization",
        ):
            self.assertNotIn(forbidden, columns)

    def test_static_source_has_no_chat_session_cache_or_secret_reader(self) -> None:
        source = (SCRIPTS / "attempt_responses_proxy.py").read_text(encoding="utf-8")
        forbidden_literals = (
            "import keyring",
            "Path.home(",
            "chatgpt.com",
            "refresh" + "_token",
            "auth" + ".json",
            ".codex/" + "auth",
        )
        for forbidden in forbidden_literals:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_foundation_is_dormant_and_not_in_current_endpoint_commands(self) -> None:
        launcher = (SCRIPTS / "run_role_executor.py").read_text(encoding="utf-8")
        registry = (
            ROOT / "references" / "twinfinity-executor-registry.toml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("attempt_responses_proxy", launcher)
        self.assertNotIn("attempt_responses_proxy", registry)
        self.assertNotIn("role.development.v5", registry)
        self.assertNotIn("role.sre.v5", registry)


if __name__ == "__main__":
    unittest.main()
