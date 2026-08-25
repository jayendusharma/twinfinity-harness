#!/usr/bin/env python3
"""Credential-free, attempt-bound Responses proxy foundation.

This module is intentionally not wired into the current role endpoints.  The
future native role broker may construct it only after an approved host
credential reference passes preflight.  Sandbox children receive a loopback
Responses endpoint, never a provider credential or coordination capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct
import threading
import time
from typing import Any, Callable, Mapping, Protocol, Sequence, TypeVar
import uuid

from owner_safe_sqlite import prepare_owner_database


PROXY_PROTOCOL_VERSION = 1
PROXY_PROVIDER_NAME = "twinfinity-attempt-responses"
RESPONSES_PATH = "/v1/responses"
HOLD_UPSTREAM_AUTH_UNSUPPORTED = "BROKER_UPSTREAM_AUTH_UNSUPPORTED"
HOLD_PROXY_DISABLED = "BROKER_RESPONSES_PROXY_DISABLED"
HOLD_UPSTREAM_AMBIGUOUS = "BROKER_UPSTREAM_AMBIGUOUS"
HOLD_UPSTREAM_CREDENTIAL_REJECTED = "BROKER_UPSTREAM_CREDENTIAL_REJECTED"
HOLD_PROXY_BUDGET_OVERRUN = "BROKER_PROXY_BUDGET_OVERRUN"

REQUEST_STATES = frozenset(
    {
        "CREATED",
        "UPSTREAM_STARTED",
        "STREAMING",
        "COMPLETE",
        "SAFE_NOT_SENT",
        "AMBIGUOUS",
        "FAILED",
    }
)
TERMINAL_REQUEST_STATES = frozenset(
    {"COMPLETE", "SAFE_NOT_SENT", "AMBIGUOUS", "FAILED"}
)
PROXY_STATES = frozenset({"READY", "RUNNING", "COMPLETE", "HOLD"})

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")
HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
RESPONSE_ID = re.compile(r"^resp_[A-Za-z0-9_-]{1,240}$")

SENSITIVE_REQUEST_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "openai-organization",
        "openai-project",
    }
)
SAFE_CHILD_ENVIRONMENT_KEYS = frozenset(
    {
        "COLORTERM",
        "LANG",
        "LC_ALL",
        "LOGNAME",
        "NO_COLOR",
        "PATH",
        "SHELL",
        "TERM",
        "TMPDIR",
        "TZ",
        "USER",
    }
)

_FRAME_MAGIC = b"TFPX"
_FRAME_HEADER = struct.Struct("!4sBBII")
_MAX_FRAME_PAYLOAD = 64 * 1024
_MAX_HELLO_BYTES = 4096


class ProxyError(RuntimeError):
    """Base error for the attempt proxy foundation."""


class ProxyHold(ProxyError):
    """A fail-closed hold that is safe to project into broker state."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def receipt(self) -> dict[str, str]:
        return {"verdict": "ACTIONABLE_HOLD", "hold_code": self.code}


class ProxyPolicyError(ProxyError):
    """The sandbox request does not match its immutable contract."""

    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class ProxyProtocolError(ProxyError):
    """The inherited framed channel is malformed or cross-bound."""


class UpstreamNotSent(ProxyError):
    """The transport proves that zero request bytes reached upstream."""


class UpstreamAmbiguous(ProxyError):
    """The request may have reached upstream and must not be replayed."""


class UpstreamRejected(ProxyError):
    """Upstream returned a terminal, non-streaming response."""

    def __init__(self, status: int) -> None:
        super().__init__(f"UPSTREAM_STATUS_{status}")
        self.status = status


class UpstreamTerminalFailure(ProxyError):
    """A valid SSE stream reported response.failed or response.incomplete."""


class FrameKind(IntEnum):
    HELLO = 1
    REQUEST_START = 2
    REQUEST_DATA = 3
    REQUEST_END = 4
    RESPONSE_DATA = 5
    RESPONSE_END = 6
    ERROR = 7


@dataclass(frozen=True)
class Frame:
    kind: FrameKind
    stream_id: int
    payload: bytes = b""

    def __post_init__(self) -> None:
        if self.stream_id < 0 or self.stream_id > 0xFFFFFFFF:
            raise ProxyProtocolError("PROXY_FRAME_STREAM_INVALID")
        if len(self.payload) > _MAX_FRAME_PAYLOAD:
            raise ProxyProtocolError("PROXY_FRAME_TOO_LARGE")
        if self.kind is FrameKind.HELLO and self.stream_id != 0:
            raise ProxyProtocolError("PROXY_FRAME_HELLO_INVALID")
        if self.kind is not FrameKind.HELLO and self.stream_id == 0:
            raise ProxyProtocolError("PROXY_FRAME_STREAM_INVALID")


@dataclass(frozen=True)
class ApprovedCredentialReference:
    """Opaque host-side reference; never a bearer token or secret value."""

    reference_id: str
    kind: str
    approval_sha256: str

    def __post_init__(self) -> None:
        if (
            SAFE_IDENTIFIER.fullmatch(self.reference_id) is None
            or self.kind
            not in {
                "platform_api_project",
                "workload_identity",
                "documented_access_token",
            }
            or SHA256.fullmatch(self.approval_sha256) is None
        ):
            raise ProxyError("BROKER_CREDENTIAL_REFERENCE_INVALID")
        lowered = self.reference_id.casefold()
        if (
            lowered.startswith("sk-")
            or lowered.startswith("bearer")
            or "password" in lowered
            or "refresh" + "_token" in lowered
        ):
            raise ProxyError("BROKER_CREDENTIAL_REFERENCE_NOT_OPAQUE")

    @property
    def digest(self) -> str:
        return sha256_text(
            canonical_json(
                {
                    "approval_sha256": self.approval_sha256,
                    "kind": self.kind,
                    "reference_id": self.reference_id,
                }
            )
        )


@dataclass(frozen=True)
class ProxyActivation:
    enabled: bool = False
    credential_reference: ApprovedCredentialReference | None = None


@dataclass(frozen=True)
class AttemptProxyContract:
    attempt_id: str
    contract_sha256: str
    endpoint_id: str
    model: str
    max_requests: int
    max_body_bytes: int
    max_input_tokens: int
    max_output_tokens: int
    max_total_tokens: int
    max_wall_seconds: float
    sse_idle_seconds: float
    max_concurrency: int = 1
    max_header_bytes: int = 16 * 1024
    max_sse_event_bytes: int = 1024 * 1024
    allowed_tools_sha256: str | None = None

    def __post_init__(self) -> None:
        try:
            parsed_attempt = uuid.UUID(self.attempt_id)
        except (ValueError, AttributeError) as exc:
            raise ProxyError("BROKER_PROXY_ATTEMPT_INVALID") from exc
        if str(parsed_attempt) != self.attempt_id:
            raise ProxyError("BROKER_PROXY_ATTEMPT_INVALID")
        if (
            SHA256.fullmatch(self.contract_sha256) is None
            or SAFE_IDENTIFIER.fullmatch(self.endpoint_id) is None
            or SAFE_IDENTIFIER.fullmatch(self.model) is None
            or self.max_concurrency != 1
            or not 1 <= self.max_requests <= 64
            or not 1024 <= self.max_body_bytes <= 32 * 1024 * 1024
            or not 1 <= self.max_input_tokens <= 10_000_000
            or not 1 <= self.max_output_tokens <= 1_000_000
            or not 1 <= self.max_total_tokens <= 10_000_000
            or not 1.0 <= self.max_wall_seconds <= 24 * 60 * 60
            or not 0.1 <= self.sse_idle_seconds <= self.max_wall_seconds
            or not 1024 <= self.max_header_bytes <= 256 * 1024
            or not 1024 <= self.max_sse_event_bytes <= 8 * 1024 * 1024
            or (
                self.allowed_tools_sha256 is not None
                and SHA256.fullmatch(self.allowed_tools_sha256) is None
            )
        ):
            raise ProxyError("BROKER_PROXY_CONTRACT_INVALID")

    @property
    def policy_sha256(self) -> str:
        return sha256_text(
            canonical_json(
                {
                    "allowed_tools_sha256": self.allowed_tools_sha256,
                    "attempt_id": self.attempt_id,
                    "contract_sha256": self.contract_sha256,
                    "endpoint_id": self.endpoint_id,
                    "max_body_bytes": self.max_body_bytes,
                    "max_concurrency": self.max_concurrency,
                    "max_header_bytes": self.max_header_bytes,
                    "max_input_tokens": self.max_input_tokens,
                    "max_output_tokens": self.max_output_tokens,
                    "max_requests": self.max_requests,
                    "max_sse_event_bytes": self.max_sse_event_bytes,
                    "max_total_tokens": self.max_total_tokens,
                    "max_wall_seconds": self.max_wall_seconds,
                    "model": self.model,
                    "sse_idle_seconds": self.sse_idle_seconds,
                }
            )
        )


@dataclass(frozen=True)
class ProxyPermit:
    contract: AttemptProxyContract
    credential_reference: ApprovedCredentialReference
    binding_sha256: str

    def __post_init__(self) -> None:
        expected = sha256_text(
            canonical_json(
                {
                    "attempt_id": self.contract.attempt_id,
                    "contract_sha256": self.contract.contract_sha256,
                    "credential_ref_sha256": self.credential_reference.digest,
                    "endpoint_id": self.contract.endpoint_id,
                    "policy_sha256": self.contract.policy_sha256,
                }
            )
        )
        if self.binding_sha256 != expected:
            raise ProxyError("BROKER_PROXY_PERMIT_BINDING_INVALID")


@dataclass(frozen=True)
class SupplementalMount:
    source: str
    destination: str
    writable: bool


@dataclass(frozen=True)
class UpstreamRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    request_sha256: str
    deadline_seconds: float


class UpstreamStream(Protocol):
    status: int
    headers: Mapping[str, str]

    def receive(self, timeout_seconds: float) -> bytes | None:
        """Return one SSE chunk or None at EOF within the supplied timeout."""

    def close(self) -> None:
        """Release the host-side upstream connection."""


class UpstreamTransport(Protocol):
    def open(
        self,
        request: UpstreamRequest,
        *,
        credential_reference: ApprovedCredentialReference,
        timeout_seconds: float,
    ) -> UpstreamStream:
        """Open one authenticated host-side request without exposing auth."""


@dataclass(frozen=True)
class ParsedRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class PreparedRequest:
    upstream: UpstreamRequest
    estimated_input_tokens: int
    reserved_output_tokens: int


@dataclass(frozen=True)
class ProxyResult:
    http_status: int
    request_state: str
    sequence: int
    response_id_sha256: str | None = None


T = TypeVar("T")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def preflight_before_reservation(
    contract: AttemptProxyContract,
    activation: ProxyActivation = ProxyActivation(),
) -> ProxyPermit:
    """Fail before capacity/attempt reservation when host auth is unsupported."""

    credential = activation.credential_reference
    if credential is None:
        raise ProxyHold(HOLD_UPSTREAM_AUTH_UNSUPPORTED)
    if not activation.enabled:
        raise ProxyHold(HOLD_PROXY_DISABLED)
    binding_sha256 = sha256_text(
        canonical_json(
            {
                "attempt_id": contract.attempt_id,
                "contract_sha256": contract.contract_sha256,
                "credential_ref_sha256": credential.digest,
                "endpoint_id": contract.endpoint_id,
                "policy_sha256": contract.policy_sha256,
            }
        )
    )
    return ProxyPermit(contract, credential, binding_sha256)


def preflight_then_reserve(
    contract: AttemptProxyContract,
    activation: ProxyActivation,
    reserve: Callable[[ProxyPermit], T],
) -> T:
    """Closed broker seam that makes preflight ordering mechanically testable."""

    permit = preflight_before_reservation(contract, activation)
    return reserve(permit)


def build_uncredentialed_child_environment(
    base: Mapping[str, str],
    *,
    contract: AttemptProxyContract,
    machine_codex_home: str,
    loopback_port: int,
) -> dict[str, str]:
    """Build an allowlisted child environment containing no reusable authority."""

    if not machine_codex_home.startswith("/") or not 1 <= loopback_port <= 65535:
        raise ProxyError("BROKER_PROXY_CHILD_ENVIRONMENT_INVALID")
    environment = {
        key: value
        for key, value in base.items()
        if key in SAFE_CHILD_ENVIRONMENT_KEYS and type(value) is str
    }
    environment.update(
        {
            "CODEX_HOME": machine_codex_home,
            "HOME": "/run/twinfinity-attempt/home",
            "XDG_CACHE_HOME": "/run/twinfinity-attempt/runtime/cache",
            "XDG_CONFIG_HOME": "/run/twinfinity-attempt/home/.config",
            "XDG_DATA_HOME": "/run/twinfinity-attempt/home/.local/share",
            "TWINFINITY_EXECUTOR_ATTEMPT_ID": contract.attempt_id,
            "TWINFINITY_EXECUTOR_CONTRACT_SHA256": contract.contract_sha256,
            "TWINFINITY_ROLE_ENDPOINT": contract.endpoint_id,
            "TWINFINITY_RESPONSES_PROXY_PORT": str(loopback_port),
        }
    )
    return environment


def validate_supplemental_mounts(mounts: Sequence[SupplementalMount]) -> None:
    """Validate the only mounts added to the otherwise read-only sandbox root."""

    allowed_read_only = {
        "/workspace",
        "/run/twinfinity-attempt/contract.json",
        "/run/twinfinity-attempt/codex-home/config.toml",
    }
    allowed_writable = {
        "/run/twinfinity-attempt/home",
        "/run/twinfinity-attempt/out",
        "/run/twinfinity-attempt/runtime",
    }
    seen: set[str] = set()
    forbidden_fragments = (
        "/.ssh",
        "/.gnupg",
        "/.codex",
        "/keyring",
        "/secrets",
        "/twinfinity-coordination",
        "/run/user/",
        "/" + "auth" + ".json",
    )
    for mount in mounts:
        source = os.path.normpath(mount.source)
        destination = os.path.normpath(mount.destination)
        lowered = f"{source}\n{destination}".casefold()
        allowed = allowed_writable if mount.writable else allowed_read_only
        if (
            not source.startswith("/")
            or destination not in allowed
            or destination in seen
            or any(fragment in lowered for fragment in forbidden_fragments)
        ):
            raise ProxyError("BROKER_PROXY_MOUNT_CONTRACT_INVALID")
        seen.add(destination)


def required_namespace_masks() -> tuple[str, str]:
    """Return host paths that the future bwrap initializer must tmpfs-mask."""

    return ("/home/ubuntu", "/run/user/1000")


def render_machine_local_provider_config(
    contract: AttemptProxyContract,
    *,
    loopback_port: int,
) -> str:
    """Render the complete secret-free provider config for a private CODEX_HOME."""

    if not 1 <= loopback_port <= 65535:
        raise ProxyError("BROKER_PROXY_LOOPBACK_PORT_INVALID")
    idle_ms = max(100, int(contract.sse_idle_seconds * 1000))
    return (
        f'model = "{contract.model}"\n'
        f'model_provider = "{PROXY_PROVIDER_NAME}"\n\n'
        f'[model_providers.{PROXY_PROVIDER_NAME}]\n'
        'name = "Twinfinity attempt-bound Responses proxy"\n'
        f'base_url = "http://127.0.0.1:{loopback_port}/v1"\n'
        'wire_api = "responses"\n'
        'requires_openai_auth = false\n'
        'request_max_retries = 0\n'
        'stream_max_retries = 0\n'
        f'stream_idle_timeout_ms = {idle_ms}\n'
    )


def write_machine_local_provider_config(
    machine_codex_home: Path,
    contract: AttemptProxyContract,
    *,
    loopback_port: int,
) -> Path:
    """Write one owner-private, immutable-per-attempt machine config."""

    root = Path(machine_codex_home)
    try:
        metadata = root.lstat()
    except FileNotFoundError as exc:
        raise ProxyError("BROKER_PROXY_MACHINE_CONFIG_ROOT_MISSING") from exc
    if (
        not root.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProxyError("BROKER_PROXY_MACHINE_CONFIG_ROOT_UNSAFE")
    path = root / "config.toml"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    contents = render_machine_local_provider_config(
        contract, loopback_port=loopback_port
    ).encode("utf-8")
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ProxyError("BROKER_PROXY_MACHINE_CONFIG_WRITE_FAILED") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(contents)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)
    return path


def create_attempt_socketpair() -> tuple[socket.socket, socket.socket]:
    """Return non-inheritable host/relay FDs for explicit pass_fds transfer."""

    host_socket, relay_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    host_socket.set_inheritable(False)
    relay_socket.set_inheritable(False)
    return host_socket, relay_socket


def _send_all(sock: socket.socket, value: bytes) -> None:
    view = memoryview(value)
    while view:
        sent = sock.send(view)
        if sent <= 0:
            raise ProxyProtocolError("PROXY_CHANNEL_CLOSED")
        view = view[sent:]


def _receive_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProxyProtocolError("PROXY_CHANNEL_CLOSED")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock: socket.socket, frame: Frame) -> None:
    header = _FRAME_HEADER.pack(
        _FRAME_MAGIC,
        PROXY_PROTOCOL_VERSION,
        int(frame.kind),
        frame.stream_id,
        len(frame.payload),
    )
    _send_all(sock, header + frame.payload)


def receive_frame(sock: socket.socket) -> Frame:
    encoded = _receive_exact(sock, _FRAME_HEADER.size)
    magic, version, raw_kind, stream_id, payload_size = _FRAME_HEADER.unpack(encoded)
    if magic != _FRAME_MAGIC or version != PROXY_PROTOCOL_VERSION:
        raise ProxyProtocolError("PROXY_FRAME_VERSION_INVALID")
    if payload_size > _MAX_FRAME_PAYLOAD:
        raise ProxyProtocolError("PROXY_FRAME_TOO_LARGE")
    try:
        kind = FrameKind(raw_kind)
    except ValueError as exc:
        raise ProxyProtocolError("PROXY_FRAME_KIND_INVALID") from exc
    return Frame(kind, stream_id, _receive_exact(sock, payload_size))


def channel_hello(contract: AttemptProxyContract) -> bytes:
    return canonical_json(
        {
            "attempt_id": contract.attempt_id,
            "contract_sha256": contract.contract_sha256,
            "endpoint_sha256": sha256_text(contract.endpoint_id),
            "policy_sha256": contract.policy_sha256,
            "protocol_version": PROXY_PROTOCOL_VERSION,
        }
    ).encode("ascii")


class AttemptProxyLedger:
    """Owner-only SQLite ledger containing hashes and counters, never content."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        prepare_owner_database(self.path)
        self.connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            timeout=5.0,
            check_same_thread=False,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.RLock()
        self._ensure_schema()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "AttemptProxyLedger":
        return self

    def __exit__(self, *_arguments: object) -> None:
        self.close()

    def _ensure_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS executor_attempt_response_proxies (
                attempt_id TEXT PRIMARY KEY,
                contract_sha256 TEXT NOT NULL,
                policy_sha256 TEXT NOT NULL,
                binding_sha256 TEXT NOT NULL,
                endpoint_sha256 TEXT NOT NULL,
                model_sha256 TEXT NOT NULL,
                credential_ref_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('READY','RUNNING','COMPLETE','HOLD')),
                max_requests INTEGER NOT NULL CHECK (max_requests > 0),
                request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
                max_input_tokens INTEGER NOT NULL CHECK (max_input_tokens > 0),
                input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
                max_output_tokens INTEGER NOT NULL CHECK (max_output_tokens > 0),
                output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
                max_total_tokens INTEGER NOT NULL CHECK (max_total_tokens > 0),
                hold_code TEXT,
                terminal_evidence_sha256 TEXT,
                version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                terminal_at TEXT
            );

            CREATE TABLE IF NOT EXISTS executor_attempt_response_requests (
                attempt_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                request_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('CREATED','UPSTREAM_STARTED','STREAMING','COMPLETE',
                              'SAFE_NOT_SENT','AMBIGUOUS','FAILED')
                ),
                estimated_input_tokens INTEGER,
                reserved_output_tokens INTEGER,
                input_tokens INTEGER,
                output_tokens INTEGER,
                response_id_sha256 TEXT,
                error_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                terminal_at TEXT,
                PRIMARY KEY (attempt_id, sequence),
                FOREIGN KEY (attempt_id)
                    REFERENCES executor_attempt_response_proxies(attempt_id)
                    ON DELETE RESTRICT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS
                executor_attempt_response_requests_one_active
            ON executor_attempt_response_requests(attempt_id)
            WHERE state IN ('CREATED','UPSTREAM_STARTED','STREAMING');

            CREATE TABLE IF NOT EXISTS executor_attempt_response_request_events (
                attempt_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal > 0),
                from_state TEXT,
                to_state TEXT NOT NULL,
                metadata_sha256 TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                PRIMARY KEY (attempt_id, sequence, ordinal),
                FOREIGN KEY (attempt_id, sequence)
                    REFERENCES executor_attempt_response_requests(attempt_id, sequence)
                    ON DELETE RESTRICT
            );
            """
        )
        expected = {
            "attempt_id",
            "sequence",
            "request_sha256",
            "state",
            "estimated_input_tokens",
            "reserved_output_tokens",
            "input_tokens",
            "output_tokens",
            "response_id_sha256",
            "error_code",
            "created_at",
            "updated_at",
            "terminal_at",
        }
        expected_tables = {
            "executor_attempt_response_proxies": {
                "attempt_id",
                "contract_sha256",
                "policy_sha256",
                "binding_sha256",
                "endpoint_sha256",
                "model_sha256",
                "credential_ref_sha256",
                "state",
                "max_requests",
                "request_count",
                "max_input_tokens",
                "input_tokens",
                "max_output_tokens",
                "output_tokens",
                "max_total_tokens",
                "hold_code",
                "terminal_evidence_sha256",
                "version",
                "created_at",
                "updated_at",
                "terminal_at",
            },
            "executor_attempt_response_requests": expected,
            "executor_attempt_response_request_events": {
                "attempt_id",
                "sequence",
                "ordinal",
                "from_state",
                "to_state",
                "metadata_sha256",
                "occurred_at",
            },
        }
        actual_tables = {
            table: {
                row["name"]
                for row in self.connection.execute(f"PRAGMA table_info({table})")
            }
            for table in expected_tables
        }
        if actual_tables != expected_tables:
            raise ProxyError("BROKER_PROXY_LEDGER_SCHEMA_DRIFT")

    def _begin(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        self.connection.commit()

    def _rollback(self) -> None:
        self.connection.rollback()

    def register(self, permit: ProxyPermit, *, now: str | None = None) -> None:
        timestamp = now or utc_now()
        contract = permit.contract
        with self._lock:
            self._begin()
            try:
                self.connection.execute(
                    """
                    INSERT INTO executor_attempt_response_proxies (
                        attempt_id, contract_sha256, policy_sha256,
                        binding_sha256, endpoint_sha256, model_sha256,
                        credential_ref_sha256,
                        state, max_requests, max_input_tokens,
                        max_output_tokens, max_total_tokens, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'READY', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        contract.attempt_id,
                        contract.contract_sha256,
                        contract.policy_sha256,
                        permit.binding_sha256,
                        sha256_text(contract.endpoint_id),
                        sha256_text(contract.model),
                        permit.credential_reference.digest,
                        contract.max_requests,
                        contract.max_input_tokens,
                        contract.max_output_tokens,
                        contract.max_total_tokens,
                        timestamp,
                        timestamp,
                    ),
                )
                self._commit()
            except Exception:
                self._rollback()
                raise

    def activate(self, attempt_id: str, *, now: str | None = None) -> None:
        timestamp = now or utc_now()
        with self._lock:
            self._begin()
            try:
                updated = self.connection.execute(
                    """
                    UPDATE executor_attempt_response_proxies
                    SET state='RUNNING', version=version+1, updated_at=?
                    WHERE attempt_id=? AND state='READY'
                    """,
                    (timestamp, attempt_id),
                ).rowcount
                if updated != 1:
                    raise ProxyError("BROKER_PROXY_ACTIVATION_CONFLICT")
                self._commit()
            except Exception:
                self._rollback()
                raise

    def begin_request(
        self,
        attempt_id: str,
        request_sha256: str,
        *,
        now: str | None = None,
    ) -> int:
        if SHA256.fullmatch(request_sha256) is None:
            raise ProxyError("BROKER_PROXY_REQUEST_DIGEST_INVALID")
        timestamp = now or utc_now()
        with self._lock:
            self._begin()
            try:
                proxy = self.connection.execute(
                    """
                    SELECT state, request_count, max_requests
                    FROM executor_attempt_response_proxies
                    WHERE attempt_id=?
                    """,
                    (attempt_id,),
                ).fetchone()
                if proxy is None or proxy["state"] != "RUNNING":
                    raise ProxyHold("BROKER_PROXY_NOT_RUNNING")
                if proxy["request_count"] >= proxy["max_requests"]:
                    raise ProxyPolicyError("BROKER_PROXY_REQUEST_LIMIT", 429)
                active = self.connection.execute(
                    """
                    SELECT 1 FROM executor_attempt_response_requests
                    WHERE attempt_id=?
                      AND state IN ('CREATED','UPSTREAM_STARTED','STREAMING')
                    """,
                    (attempt_id,),
                ).fetchone()
                if active is not None:
                    raise ProxyPolicyError("BROKER_PROXY_CONCURRENCY_LIMIT", 429)
                sequence = proxy["request_count"] + 1
                self.connection.execute(
                    """
                    INSERT INTO executor_attempt_response_requests (
                        attempt_id, sequence, request_sha256, state,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'CREATED', ?, ?)
                    """,
                    (attempt_id, sequence, request_sha256, timestamp, timestamp),
                )
                self.connection.execute(
                    """
                    UPDATE executor_attempt_response_proxies
                    SET request_count=?, version=version+1, updated_at=?
                    WHERE attempt_id=?
                    """,
                    (sequence, timestamp, attempt_id),
                )
                self._append_event(
                    attempt_id,
                    sequence,
                    None,
                    "CREATED",
                    request_sha256,
                    timestamp,
                )
                self._commit()
                return sequence
            except Exception:
                self._rollback()
                raise

    def reserve_budget(
        self,
        attempt_id: str,
        sequence: int,
        *,
        estimated_input_tokens: int,
        reserved_output_tokens: int,
        now: str | None = None,
    ) -> None:
        timestamp = now or utc_now()
        if estimated_input_tokens <= 0 or reserved_output_tokens <= 0:
            raise ProxyPolicyError("BROKER_PROXY_TOKEN_BUDGET_INVALID")
        with self._lock:
            self._begin()
            try:
                proxy = self.connection.execute(
                    """
                    SELECT max_input_tokens, input_tokens, max_output_tokens,
                           output_tokens, max_total_tokens
                    FROM executor_attempt_response_proxies
                    WHERE attempt_id=? AND state='RUNNING'
                    """,
                    (attempt_id,),
                ).fetchone()
                request = self.connection.execute(
                    """
                    SELECT state, estimated_input_tokens, reserved_output_tokens
                    FROM executor_attempt_response_requests
                    WHERE attempt_id=? AND sequence=?
                    """,
                    (attempt_id, sequence),
                ).fetchone()
                if proxy is None or request is None or request["state"] != "CREATED":
                    raise ProxyError("BROKER_PROXY_REQUEST_STATE_CONFLICT")
                if (
                    request["estimated_input_tokens"] is not None
                    or request["reserved_output_tokens"] is not None
                ):
                    raise ProxyError("BROKER_PROXY_BUDGET_ALREADY_RESERVED")
                projected_input = proxy["input_tokens"] + estimated_input_tokens
                projected_output = proxy["output_tokens"] + reserved_output_tokens
                if (
                    projected_input > proxy["max_input_tokens"]
                    or projected_output > proxy["max_output_tokens"]
                    or projected_input + projected_output > proxy["max_total_tokens"]
                ):
                    raise ProxyPolicyError("BROKER_PROXY_TOKEN_LIMIT", 429)
                self.connection.execute(
                    """
                    UPDATE executor_attempt_response_requests
                    SET estimated_input_tokens=?, reserved_output_tokens=?,
                        updated_at=?
                    WHERE attempt_id=? AND sequence=? AND state='CREATED'
                    """,
                    (
                        estimated_input_tokens,
                        reserved_output_tokens,
                        timestamp,
                        attempt_id,
                        sequence,
                    ),
                )
                self._commit()
            except Exception:
                self._rollback()
                raise

    def _append_event(
        self,
        attempt_id: str,
        sequence: int,
        from_state: str | None,
        to_state: str,
        metadata: str,
        timestamp: str,
    ) -> None:
        ordinal = self.connection.execute(
            """
            SELECT COALESCE(MAX(ordinal), 0) + 1
            FROM executor_attempt_response_request_events
            WHERE attempt_id=? AND sequence=?
            """,
            (attempt_id, sequence),
        ).fetchone()[0]
        metadata_sha256 = (
            metadata if SHA256.fullmatch(metadata) else sha256_text(metadata)
        )
        self.connection.execute(
            """
            INSERT INTO executor_attempt_response_request_events (
                attempt_id, sequence, ordinal, from_state, to_state,
                metadata_sha256, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                sequence,
                ordinal,
                from_state,
                to_state,
                metadata_sha256,
                timestamp,
            ),
        )

    def transition_request(
        self,
        attempt_id: str,
        sequence: int,
        *,
        expected_states: set[str],
        new_state: str,
        error_code: str | None = None,
        response_id: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        now: str | None = None,
    ) -> None:
        if new_state not in REQUEST_STATES or not expected_states <= REQUEST_STATES:
            raise ProxyError("BROKER_PROXY_REQUEST_TRANSITION_INVALID")
        timestamp = now or utc_now()
        with self._lock:
            self._begin()
            try:
                row = self.connection.execute(
                    """
                    SELECT state, estimated_input_tokens, reserved_output_tokens
                    FROM executor_attempt_response_requests
                    WHERE attempt_id=? AND sequence=?
                    """,
                    (attempt_id, sequence),
                ).fetchone()
                if row is None or row["state"] not in expected_states:
                    raise ProxyError("BROKER_PROXY_REQUEST_STATE_CONFLICT")
                response_digest = (
                    sha256_text(response_id) if response_id is not None else None
                )
                terminal_at = timestamp if new_state in TERMINAL_REQUEST_STATES else None
                if new_state == "COMPLETE":
                    if (
                        response_id is None
                        or RESPONSE_ID.fullmatch(response_id) is None
                        or type(input_tokens) is not int
                        or type(output_tokens) is not int
                        or input_tokens < 0
                        or output_tokens < 0
                    ):
                        raise ProxyError("BROKER_PROXY_COMPLETION_INVALID")
                    proxy = self.connection.execute(
                        """
                        SELECT input_tokens, output_tokens, max_input_tokens,
                               max_output_tokens, max_total_tokens
                        FROM executor_attempt_response_proxies
                        WHERE attempt_id=? AND state='RUNNING'
                        """,
                        (attempt_id,),
                    ).fetchone()
                    if proxy is None:
                        raise ProxyError("BROKER_PROXY_NOT_RUNNING")
                    next_input = proxy["input_tokens"] + input_tokens
                    next_output = proxy["output_tokens"] + output_tokens
                    if (
                        input_tokens > row["estimated_input_tokens"]
                        or output_tokens > row["reserved_output_tokens"]
                        or next_input > proxy["max_input_tokens"]
                        or next_output > proxy["max_output_tokens"]
                        or next_input + next_output > proxy["max_total_tokens"]
                    ):
                        raise ProxyHold(HOLD_PROXY_BUDGET_OVERRUN)
                    self.connection.execute(
                        """
                        UPDATE executor_attempt_response_proxies
                        SET input_tokens=?, output_tokens=?, version=version+1,
                            updated_at=?
                        WHERE attempt_id=?
                        """,
                        (next_input, next_output, timestamp, attempt_id),
                    )
                self.connection.execute(
                    """
                    UPDATE executor_attempt_response_requests
                    SET state=?, error_code=?, response_id_sha256=?,
                        input_tokens=?, output_tokens=?, updated_at=?, terminal_at=?
                    WHERE attempt_id=? AND sequence=?
                    """,
                    (
                        new_state,
                        error_code,
                        response_digest,
                        input_tokens,
                        output_tokens,
                        timestamp,
                        terminal_at,
                        attempt_id,
                        sequence,
                    ),
                )
                metadata = canonical_json(
                    {
                        "error_code": error_code,
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "response_id_sha256": response_digest,
                    }
                )
                self._append_event(
                    attempt_id,
                    sequence,
                    row["state"],
                    new_state,
                    metadata,
                    timestamp,
                )
                if new_state == "AMBIGUOUS":
                    self.connection.execute(
                        """
                        UPDATE executor_attempt_response_proxies
                        SET state='HOLD', hold_code=?, version=version+1,
                            updated_at=?, terminal_at=?
                        WHERE attempt_id=? AND state='RUNNING'
                        """,
                        (
                            HOLD_UPSTREAM_AMBIGUOUS,
                            timestamp,
                            timestamp,
                            attempt_id,
                        ),
                    )
                self._commit()
            except Exception:
                self._rollback()
                raise

    def hold_proxy(
        self,
        attempt_id: str,
        hold_code: str,
        *,
        now: str | None = None,
    ) -> None:
        timestamp = now or utc_now()
        with self._lock:
            self._begin()
            try:
                updated = self.connection.execute(
                    """
                    UPDATE executor_attempt_response_proxies
                    SET state='HOLD', hold_code=?, version=version+1,
                        updated_at=?, terminal_at=?
                    WHERE attempt_id=? AND state IN ('READY','RUNNING')
                    """,
                    (hold_code, timestamp, timestamp, attempt_id),
                ).rowcount
                if updated != 1:
                    raise ProxyError("BROKER_PROXY_HOLD_CONFLICT")
                self._commit()
            except Exception:
                self._rollback()
                raise

    def complete_proxy(self, attempt_id: str, *, now: str | None = None) -> None:
        timestamp = now or utc_now()
        with self._lock:
            self._begin()
            try:
                active = self.connection.execute(
                    """
                    SELECT 1 FROM executor_attempt_response_requests
                    WHERE attempt_id=?
                      AND state IN ('CREATED','UPSTREAM_STARTED','STREAMING','AMBIGUOUS')
                    """,
                    (attempt_id,),
                ).fetchone()
                if active is not None:
                    raise ProxyHold("BROKER_PROXY_REQUEST_UNRESOLVED")
                updated = self.connection.execute(
                    """
                    UPDATE executor_attempt_response_proxies
                    SET state='COMPLETE', version=version+1,
                        updated_at=?, terminal_at=?
                    WHERE attempt_id=? AND state='RUNNING'
                    """,
                    (timestamp, timestamp, attempt_id),
                ).rowcount
                if updated != 1:
                    raise ProxyError("BROKER_PROXY_COMPLETION_CONFLICT")
                self._commit()
            except Exception:
                self._rollback()
                raise

    def recover_after_confirmed_process_loss(
        self,
        attempt_id: str,
        *,
        process_evidence_sha256: str,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Terminally hold a dead proxy; never infer death or replay a request."""

        if SHA256.fullmatch(process_evidence_sha256) is None:
            raise ProxyError("BROKER_PROXY_RECOVERY_EVIDENCE_INVALID")
        timestamp = now or utc_now()
        with self._lock:
            self._begin()
            try:
                proxy = self.connection.execute(
                    """
                    SELECT state, hold_code
                    FROM executor_attempt_response_proxies
                    WHERE attempt_id=?
                    """,
                    (attempt_id,),
                ).fetchone()
                if proxy is None:
                    raise ProxyError("BROKER_PROXY_NOT_FOUND")
                if proxy["state"] in {"COMPLETE", "HOLD"}:
                    self._commit()
                    return {
                        "attempt_id": attempt_id,
                        "proxy_state": proxy["state"],
                        "hold_code": proxy["hold_code"],
                        "recovered_requests": [],
                    }
                active = list(
                    self.connection.execute(
                        """
                        SELECT sequence, state
                        FROM executor_attempt_response_requests
                        WHERE attempt_id=?
                          AND state IN ('CREATED','UPSTREAM_STARTED','STREAMING')
                        ORDER BY sequence
                        """,
                        (attempt_id,),
                    )
                )
                recovered: list[dict[str, Any]] = []
                ambiguous = False
                for request in active:
                    old_state = request["state"]
                    new_state = (
                        "SAFE_NOT_SENT" if old_state == "CREATED" else "AMBIGUOUS"
                    )
                    error_code = (
                        "BROKER_PROXY_PROCESS_LOST_BEFORE_FORWARD"
                        if new_state == "SAFE_NOT_SENT"
                        else "BROKER_PROXY_PROCESS_LOST_AFTER_FORWARD"
                    )
                    ambiguous = ambiguous or new_state == "AMBIGUOUS"
                    self.connection.execute(
                        """
                        UPDATE executor_attempt_response_requests
                        SET state=?, error_code=?, updated_at=?, terminal_at=?
                        WHERE attempt_id=? AND sequence=? AND state=?
                        """,
                        (
                            new_state,
                            error_code,
                            timestamp,
                            timestamp,
                            attempt_id,
                            request["sequence"],
                            old_state,
                        ),
                    )
                    self._append_event(
                        attempt_id,
                        request["sequence"],
                        old_state,
                        new_state,
                        canonical_json(
                            {
                                "error_code": error_code,
                                "process_evidence_sha256": process_evidence_sha256,
                            }
                        ),
                        timestamp,
                    )
                    recovered.append(
                        {
                            "sequence": request["sequence"],
                            "state": new_state,
                        }
                    )
                hold_code = (
                    HOLD_UPSTREAM_AMBIGUOUS
                    if ambiguous
                    else "BROKER_PROXY_PROCESS_LOST"
                )
                self.connection.execute(
                    """
                    UPDATE executor_attempt_response_proxies
                    SET state='HOLD', hold_code=?, version=version+1,
                        terminal_evidence_sha256=?, updated_at=?, terminal_at=?
                    WHERE attempt_id=? AND state IN ('READY','RUNNING')
                    """,
                    (
                        hold_code,
                        process_evidence_sha256,
                        timestamp,
                        timestamp,
                        attempt_id,
                    ),
                )
                self._commit()
                return {
                    "attempt_id": attempt_id,
                    "proxy_state": "HOLD",
                    "hold_code": hold_code,
                    "recovered_requests": recovered,
                }
            except Exception:
                self._rollback()
                raise

    def owns_response_id(self, attempt_id: str, response_id: str) -> bool:
        digest = sha256_text(response_id)
        row = self.connection.execute(
            """
            SELECT 1 FROM executor_attempt_response_requests
            WHERE attempt_id=? AND state='COMPLETE' AND response_id_sha256=?
            """,
            (attempt_id, digest),
        ).fetchone()
        return row is not None

    def proxy_row(self, attempt_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM executor_attempt_response_proxies WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()

    def request_rows(self, attempt_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                """
                SELECT * FROM executor_attempt_response_requests
                WHERE attempt_id=? ORDER BY sequence
                """,
                (attempt_id,),
            )
        )

    def request_events(self, attempt_id: str, sequence: int) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                """
                SELECT * FROM executor_attempt_response_request_events
                WHERE attempt_id=? AND sequence=? ORDER BY ordinal
                """,
                (attempt_id, sequence),
            )
        )


def parse_http_request(
    raw_request: bytes,
    *,
    max_header_bytes: int,
    max_body_bytes: int,
) -> ParsedRequest:
    """Parse one closed HTTP/1.1 request without accepting smuggling forms."""

    boundary = raw_request.find(b"\r\n\r\n")
    if boundary < 0 or boundary + 4 > max_header_bytes:
        raise ProxyPolicyError("BROKER_PROXY_HTTP_HEADERS_INVALID")
    header_block = raw_request[:boundary]
    body = raw_request[boundary + 4 :]
    if b"\x00" in header_block or b"\n " in header_block or b"\n\t" in header_block:
        raise ProxyPolicyError("BROKER_PROXY_HTTP_HEADERS_INVALID")
    lines = header_block.split(b"\r\n")
    if not lines or len(lines[0]) > 4096:
        raise ProxyPolicyError("BROKER_PROXY_HTTP_REQUEST_LINE_INVALID")
    try:
        method_bytes, path_bytes, version_bytes = lines[0].split(b" ")
        method = method_bytes.decode("ascii")
        path = path_bytes.decode("ascii")
        version = version_bytes.decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProxyPolicyError("BROKER_PROXY_HTTP_REQUEST_LINE_INVALID") from exc
    if version != "HTTP/1.1":
        raise ProxyPolicyError("BROKER_PROXY_HTTP_VERSION_INVALID")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise ProxyPolicyError("BROKER_PROXY_HTTP_HEADERS_INVALID")
        raw_name, raw_value = line.split(b":", 1)
        if HEADER_NAME.fullmatch(raw_name) is None:
            raise ProxyPolicyError("BROKER_PROXY_HTTP_HEADERS_INVALID")
        try:
            name = raw_name.decode("ascii").casefold()
            value = raw_value.strip(b" \t").decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProxyPolicyError("BROKER_PROXY_HTTP_HEADERS_INVALID") from exc
        if name in headers or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ProxyPolicyError("BROKER_PROXY_HTTP_HEADERS_INVALID")
        headers[name] = value
    if any(
        name in SENSITIVE_REQUEST_HEADERS
        or name.startswith("x-openai-")
        or name.startswith("openai-")
        for name in headers
    ):
        raise ProxyPolicyError("BROKER_PROXY_CHILD_AUTH_HEADER_REJECTED", 403)
    if "transfer-encoding" in headers or "content-length" not in headers:
        raise ProxyPolicyError("BROKER_PROXY_HTTP_LENGTH_INVALID")
    try:
        content_length = int(headers["content-length"])
    except ValueError as exc:
        raise ProxyPolicyError("BROKER_PROXY_HTTP_LENGTH_INVALID") from exc
    if content_length < 0 or content_length != len(body) or len(body) > max_body_bytes:
        raise ProxyPolicyError("BROKER_PROXY_BODY_LIMIT", 413)
    if method != "POST":
        raise ProxyPolicyError("BROKER_PROXY_METHOD_REJECTED", 405)
    if path != RESPONSES_PATH:
        raise ProxyPolicyError("BROKER_PROXY_PATH_REJECTED", 404)
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if content_type != "application/json":
        raise ProxyPolicyError("BROKER_PROXY_CONTENT_TYPE_REJECTED", 415)
    return ParsedRequest(method, path, headers, body)


def _prepare_upstream_request(
    parsed: ParsedRequest,
    *,
    contract: AttemptProxyContract,
    ledger: AttemptProxyLedger,
    sequence: int,
    remaining_wall_seconds: float,
) -> PreparedRequest:
    try:
        payload = json.loads(parsed.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProxyPolicyError("BROKER_PROXY_JSON_INVALID") from exc
    if type(payload) is not dict:
        raise ProxyPolicyError("BROKER_PROXY_JSON_INVALID")
    if payload.get("model") != contract.model:
        raise ProxyPolicyError("BROKER_PROXY_MODEL_MISMATCH", 403)
    if payload.get("stream") is not True:
        raise ProxyPolicyError("BROKER_PROXY_STREAM_REQUIRED")
    if payload.get("background", False) is not False:
        raise ProxyPolicyError("BROKER_PROXY_BACKGROUND_REJECTED", 403)
    if payload.get("store", False) is not False:
        raise ProxyPolicyError("BROKER_PROXY_STORE_REJECTED", 403)
    if "include" in payload:
        raise ProxyPolicyError("BROKER_PROXY_INCLUDE_REJECTED", 403)

    previous_response_id = payload.get("previous_response_id")
    if previous_response_id is not None:
        if (
            type(previous_response_id) is not str
            or RESPONSE_ID.fullmatch(previous_response_id) is None
            or not ledger.owns_response_id(contract.attempt_id, previous_response_id)
        ):
            raise ProxyPolicyError("BROKER_PROXY_RESPONSE_LINEAGE_REJECTED", 403)

    tools = payload.get("tools", [])
    if type(tools) is not list:
        raise ProxyPolicyError("BROKER_PROXY_TOOLS_INVALID")
    if tools:
        if (
            contract.allowed_tools_sha256 is None
            or any(type(tool) is not dict or tool.get("type") != "function" for tool in tools)
            or sha256_text(canonical_json(tools)) != contract.allowed_tools_sha256
        ):
            raise ProxyPolicyError("BROKER_PROXY_TOOLS_REJECTED", 403)

    requested_output = payload.get("max_output_tokens")
    if requested_output is None:
        requested_output = contract.max_output_tokens
        payload["max_output_tokens"] = requested_output
    if (
        type(requested_output) is not int
        or requested_output <= 0
        or requested_output > contract.max_output_tokens
    ):
        raise ProxyPolicyError("BROKER_PROXY_OUTPUT_TOKEN_LIMIT", 429)
    payload["store"] = False
    sanitized_body = canonical_json(payload).encode("utf-8")
    if len(sanitized_body) > contract.max_body_bytes:
        raise ProxyPolicyError("BROKER_PROXY_BODY_LIMIT", 413)

    # One UTF-8 byte per token is deliberately conservative.  A future broker
    # may replace this with a pinned tokenizer only if that cannot reduce the
    # estimate for an already admitted request.
    estimated_input_tokens = len(sanitized_body)
    ledger.reserve_budget(
        contract.attempt_id,
        sequence,
        estimated_input_tokens=estimated_input_tokens,
        reserved_output_tokens=requested_output,
    )
    digest = sha256_bytes(
        canonical_json(
            {
                "attempt_id": contract.attempt_id,
                "contract_sha256": contract.contract_sha256,
                "method": parsed.method,
                "path": parsed.path,
                "policy_sha256": contract.policy_sha256,
                "body_sha256": sha256_bytes(sanitized_body),
            }
        ).encode("ascii")
    )
    upstream = UpstreamRequest(
        method="POST",
        path=RESPONSES_PATH,
        headers=(
            ("accept", "text/event-stream"),
            ("content-type", "application/json"),
        ),
        body=sanitized_body,
        request_sha256=digest,
        deadline_seconds=remaining_wall_seconds,
    )
    return PreparedRequest(upstream, estimated_input_tokens, requested_output)


class SSECompletionTracker:
    """Incrementally extract one terminal response ID and usage from SSE."""

    def __init__(self, max_event_bytes: int) -> None:
        self.max_event_bytes = max_event_bytes
        self.buffer = bytearray()
        self.response_id: str | None = None
        self.input_tokens: int | None = None
        self.output_tokens: int | None = None
        self.completed = False
        self.done = False

    @staticmethod
    def _response_from_event(event: Mapping[str, Any]) -> Mapping[str, Any] | None:
        response = event.get("response")
        return response if isinstance(response, dict) else None

    def _consume_event(self, encoded_event: bytes) -> None:
        data_lines: list[bytes] = []
        for raw_line in encoded_event.replace(b"\r\n", b"\n").split(b"\n"):
            if raw_line.startswith(b"data:"):
                data_lines.append(raw_line[5:].lstrip(b" "))
        if not data_lines:
            return
        encoded_data = b"\n".join(data_lines)
        if encoded_data == b"[DONE]":
            if not self.completed:
                raise UpstreamAmbiguous("BROKER_PROXY_SSE_DONE_BEFORE_COMPLETE")
            self.done = True
            return
        try:
            event = json.loads(encoded_data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpstreamAmbiguous("BROKER_PROXY_SSE_JSON_INVALID") from exc
        if not isinstance(event, dict) or type(event.get("type")) is not str:
            raise UpstreamAmbiguous("BROKER_PROXY_SSE_EVENT_INVALID")
        event_type = event["type"]
        response = self._response_from_event(event)
        if response is not None and response.get("id") is not None:
            response_id = response.get("id")
            if (
                type(response_id) is not str
                or RESPONSE_ID.fullmatch(response_id) is None
                or self.response_id not in {None, response_id}
            ):
                raise UpstreamAmbiguous("BROKER_PROXY_RESPONSE_ID_INVALID")
            self.response_id = response_id
        if event_type in {"response.failed", "response.incomplete"}:
            raise UpstreamTerminalFailure("BROKER_PROXY_UPSTREAM_TERMINAL_FAILURE")
        if event_type == "response.completed":
            if response is None or self.completed:
                raise UpstreamAmbiguous("BROKER_PROXY_SSE_COMPLETION_INVALID")
            usage = response.get("usage")
            if not isinstance(usage, dict):
                raise UpstreamAmbiguous("BROKER_PROXY_SSE_USAGE_MISSING")
            input_tokens = usage.get("input_tokens")
            output_tokens = usage.get("output_tokens")
            if (
                type(input_tokens) is not int
                or type(output_tokens) is not int
                or input_tokens < 0
                or output_tokens < 0
            ):
                raise UpstreamAmbiguous("BROKER_PROXY_SSE_USAGE_INVALID")
            self.input_tokens = input_tokens
            self.output_tokens = output_tokens
            self.completed = True

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.buffer.extend(chunk)
        if len(self.buffer) > self.max_event_bytes and b"\n\n" not in self.buffer:
            raise UpstreamAmbiguous("BROKER_PROXY_SSE_EVENT_TOO_LARGE")
        while True:
            lf_boundary = self.buffer.find(b"\n\n")
            crlf_boundary = self.buffer.find(b"\r\n\r\n")
            candidates = [value for value in (lf_boundary, crlf_boundary) if value >= 0]
            if not candidates:
                break
            boundary = min(candidates)
            delimiter_size = 4 if self.buffer[boundary : boundary + 4] == b"\r\n\r\n" else 2
            event = bytes(self.buffer[:boundary])
            del self.buffer[: boundary + delimiter_size]
            if len(event) > self.max_event_bytes:
                raise UpstreamAmbiguous("BROKER_PROXY_SSE_EVENT_TOO_LARGE")
            self._consume_event(event)

    def finish(self) -> tuple[str, int, int]:
        if self.buffer.strip():
            raise UpstreamAmbiguous("BROKER_PROXY_SSE_TRUNCATED")
        if (
            not self.completed
            or self.response_id is None
            or self.input_tokens is None
            or self.output_tokens is None
        ):
            raise UpstreamAmbiguous("BROKER_PROXY_SSE_COMPLETION_MISSING")
        return self.response_id, self.input_tokens, self.output_tokens


def _http_response_head(status: int, content_type: str, body_length: int | None) -> bytes:
    reasons = {
        200: "OK",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        413: "Content Too Large",
        415: "Unsupported Media Type",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
    }
    reason = reasons.get(status, "Error")
    lines = [
        f"HTTP/1.1 {status} {reason}",
        f"Content-Type: {content_type}",
        "Connection: close",
        "Cache-Control: no-store",
    ]
    if body_length is not None:
        lines.append(f"Content-Length: {body_length}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _local_error_bytes(status: int, code: str) -> bytes:
    body = canonical_json({"error": {"code": code}}).encode("ascii")
    return _http_response_head(status, "application/json", len(body)) + body


class AttemptBoundResponsesProxy:
    """One contract-bound host proxy with no production credential resolver."""

    def __init__(
        self,
        permit: ProxyPermit,
        ledger: AttemptProxyLedger,
        upstream: UpstreamTransport,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.permit = permit
        self.contract = permit.contract
        self.ledger = ledger
        self.upstream = upstream
        self.monotonic = monotonic
        self.started_monotonic: float | None = None

    def start(self, *, now: str | None = None) -> None:
        """Register and activate only after the external attempt reservation."""

        self.ledger.register(self.permit, now=now)
        self.ledger.activate(self.contract.attempt_id, now=now)
        self.started_monotonic = self.monotonic()

    def complete(self, *, now: str | None = None) -> None:
        self.ledger.complete_proxy(self.contract.attempt_id, now=now)

    def _remaining_wall(self) -> float:
        if self.started_monotonic is None:
            raise ProxyHold("BROKER_PROXY_NOT_STARTED")
        remaining = self.contract.max_wall_seconds - (
            self.monotonic() - self.started_monotonic
        )
        if remaining <= 0:
            raise ProxyPolicyError("BROKER_PROXY_WALL_TIMEOUT", 504)
        return remaining

    def _transition_failure(
        self,
        sequence: int,
        *,
        expected_states: set[str],
        state: str,
        code: str,
    ) -> None:
        self.ledger.transition_request(
            self.contract.attempt_id,
            sequence,
            expected_states=expected_states,
            new_state=state,
            error_code=code,
        )

    def handle_raw_request(
        self,
        raw_request: bytes,
        emit: Callable[[bytes], None],
    ) -> ProxyResult:
        """Validate, forward once, and stream a sanitized response to ``emit``."""

        raw_limit = self.contract.max_header_bytes + self.contract.max_body_bytes + 4
        bounded_raw = raw_request[: raw_limit + 1]
        try:
            sequence = self.ledger.begin_request(
                self.contract.attempt_id, sha256_bytes(bounded_raw)
            )
        except ProxyPolicyError as exc:
            emit(_local_error_bytes(exc.status, exc.code))
            return ProxyResult(exc.status, "FAILED", 0)
        except ProxyHold as exc:
            emit(_local_error_bytes(409, exc.code))
            return ProxyResult(409, "FAILED", 0)
        emitted_response = False
        upstream_stream: UpstreamStream | None = None
        request_state = "CREATED"
        try:
            if len(raw_request) > raw_limit:
                raise ProxyPolicyError("BROKER_PROXY_BODY_LIMIT", 413)
            parsed = parse_http_request(
                raw_request,
                max_header_bytes=self.contract.max_header_bytes,
                max_body_bytes=self.contract.max_body_bytes,
            )
            prepared = _prepare_upstream_request(
                parsed,
                contract=self.contract,
                ledger=self.ledger,
                sequence=sequence,
                remaining_wall_seconds=self._remaining_wall(),
            )
            upstream_timeout = self._remaining_wall()
            self.ledger.transition_request(
                self.contract.attempt_id,
                sequence,
                expected_states={"CREATED"},
                new_state="UPSTREAM_STARTED",
            )
            request_state = "UPSTREAM_STARTED"
            try:
                upstream_stream = self.upstream.open(
                    prepared.upstream,
                    credential_reference=self.permit.credential_reference,
                    timeout_seconds=upstream_timeout,
                )
            except UpstreamNotSent:
                self._transition_failure(
                    sequence,
                    expected_states={"UPSTREAM_STARTED"},
                    state="SAFE_NOT_SENT",
                    code="BROKER_PROXY_UPSTREAM_NOT_SENT",
                )
                emit(_local_error_bytes(503, "BROKER_PROXY_UPSTREAM_NOT_SENT"))
                return ProxyResult(503, "SAFE_NOT_SENT", sequence)
            except Exception as exc:
                self._transition_failure(
                    sequence,
                    expected_states={"UPSTREAM_STARTED"},
                    state="AMBIGUOUS",
                    code="BROKER_PROXY_UPSTREAM_OPEN_AMBIGUOUS",
                )
                raise UpstreamAmbiguous(
                    "BROKER_PROXY_UPSTREAM_OPEN_AMBIGUOUS"
                ) from exc

            if type(upstream_stream.status) is not int or not 100 <= upstream_stream.status <= 599:
                raise UpstreamAmbiguous("BROKER_PROXY_UPSTREAM_STATUS_INVALID")
            if upstream_stream.status != 200:
                raise UpstreamRejected(upstream_stream.status)
            content_type = ""
            for name, value in upstream_stream.headers.items():
                if name.casefold() == "content-type":
                    content_type = value.split(";", 1)[0].strip().casefold()
            if content_type != "text/event-stream":
                raise UpstreamAmbiguous("BROKER_PROXY_UPSTREAM_CONTENT_TYPE_INVALID")

            emit(_http_response_head(200, "text/event-stream", None))
            emitted_response = True
            tracker = SSECompletionTracker(self.contract.max_sse_event_bytes)
            streamed = False
            while True:
                if self.started_monotonic is None:
                    raise UpstreamAmbiguous("BROKER_PROXY_NOT_STARTED")
                remaining = self.contract.max_wall_seconds - (
                    self.monotonic() - self.started_monotonic
                )
                if remaining <= 0:
                    raise UpstreamAmbiguous("BROKER_PROXY_WALL_TIMEOUT")
                timeout = min(self.contract.sse_idle_seconds, remaining)
                before = self.monotonic()
                chunk = upstream_stream.receive(timeout)
                elapsed = self.monotonic() - before
                if elapsed > timeout:
                    raise UpstreamAmbiguous("BROKER_PROXY_SSE_IDLE_TIMEOUT")
                if chunk is None:
                    break
                if type(chunk) is not bytes:
                    raise UpstreamAmbiguous("BROKER_PROXY_SSE_CHUNK_INVALID")
                if not chunk:
                    continue
                if not streamed:
                    self.ledger.transition_request(
                        self.contract.attempt_id,
                        sequence,
                        expected_states={"UPSTREAM_STARTED"},
                        new_state="STREAMING",
                    )
                    request_state = "STREAMING"
                    streamed = True
                tracker.feed(chunk)
                emit(chunk)
            response_id, input_tokens, output_tokens = tracker.finish()
            try:
                self.ledger.transition_request(
                    self.contract.attempt_id,
                    sequence,
                    expected_states={"STREAMING"},
                    new_state="COMPLETE",
                    response_id=response_id,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                )
            except ProxyHold as exc:
                self._transition_failure(
                    sequence,
                    expected_states={"STREAMING"},
                    state="FAILED",
                    code=exc.code,
                )
                self.ledger.hold_proxy(self.contract.attempt_id, exc.code)
                return ProxyResult(200, "FAILED", sequence)
            return ProxyResult(
                200,
                "COMPLETE",
                sequence,
                response_id_sha256=sha256_text(response_id),
            )
        except ProxyPolicyError as exc:
            self._transition_failure(
                sequence,
                expected_states={request_state},
                state="FAILED",
                code=exc.code,
            )
            if not emitted_response:
                emit(_local_error_bytes(exc.status, exc.code))
            return ProxyResult(exc.status, "FAILED", sequence)
        except UpstreamRejected as exc:
            self._transition_failure(
                sequence,
                expected_states={request_state},
                state="FAILED",
                code=f"BROKER_PROXY_UPSTREAM_STATUS_{exc.status}",
            )
            hold_code = (
                HOLD_UPSTREAM_CREDENTIAL_REJECTED
                if exc.status in {401, 403}
                else f"BROKER_PROXY_UPSTREAM_STATUS_{exc.status}"
            )
            self.ledger.hold_proxy(self.contract.attempt_id, hold_code)
            if not emitted_response:
                emit(_local_error_bytes(502, hold_code))
            return ProxyResult(502, "FAILED", sequence)
        except UpstreamTerminalFailure as exc:
            code = str(exc)
            self._transition_failure(
                sequence,
                expected_states={request_state},
                state="FAILED",
                code=code,
            )
            self.ledger.hold_proxy(self.contract.attempt_id, code)
            if not emitted_response:
                emit(_local_error_bytes(502, code))
            return ProxyResult(502, "FAILED", sequence)
        except (UpstreamAmbiguous, ProxyHold) as exc:
            code = exc.code if isinstance(exc, ProxyHold) else str(exc)
            row = self.ledger.request_rows(self.contract.attempt_id)[-1]
            if row["state"] not in TERMINAL_REQUEST_STATES:
                self._transition_failure(
                    sequence,
                    expected_states={row["state"]},
                    state="AMBIGUOUS",
                    code=code,
                )
            if not emitted_response:
                emit(_local_error_bytes(502, code))
            return ProxyResult(502, "AMBIGUOUS", sequence)
        except Exception:
            row = self.ledger.request_rows(self.contract.attempt_id)[-1]
            terminal_state = row["state"]
            if row["state"] not in TERMINAL_REQUEST_STATES:
                terminal_state = (
                    "FAILED" if row["state"] == "CREATED" else "AMBIGUOUS"
                )
                self._transition_failure(
                    sequence,
                    expected_states={row["state"]},
                    state=terminal_state,
                    code="BROKER_PROXY_INTERNAL_FAILURE",
                )
            if not emitted_response:
                emit(_local_error_bytes(500, "BROKER_PROXY_INTERNAL_FAILURE"))
            return ProxyResult(500, terminal_state, sequence)
        finally:
            if upstream_stream is not None:
                try:
                    upstream_stream.close()
                except Exception:
                    pass


def _send_chunked_frames(
    sock: socket.socket,
    *,
    kind: FrameKind,
    stream_id: int,
    payload: bytes,
) -> None:
    if not payload:
        return
    for offset in range(0, len(payload), _MAX_FRAME_PAYLOAD):
        send_frame(sock, Frame(kind, stream_id, payload[offset : offset + _MAX_FRAME_PAYLOAD]))


def serve_framed_proxy_exchange(
    channel: socket.socket,
    contract: AttemptProxyContract,
    proxy: AttemptBoundResponsesProxy,
) -> ProxyResult:
    """Serve one request over the relay-only inherited UDS channel."""

    hello = receive_frame(channel)
    if (
        hello.kind is not FrameKind.HELLO
        or len(hello.payload) > _MAX_HELLO_BYTES
        or hello.payload != channel_hello(contract)
    ):
        raise ProxyProtocolError("PROXY_CHANNEL_BINDING_MISMATCH")
    start = receive_frame(channel)
    if start.kind is not FrameKind.REQUEST_START or start.payload:
        raise ProxyProtocolError("PROXY_REQUEST_START_INVALID")
    stream_id = start.stream_id
    raw = bytearray()
    raw_limit = contract.max_header_bytes + contract.max_body_bytes + 4
    while True:
        frame = receive_frame(channel)
        if frame.stream_id != stream_id:
            raise ProxyProtocolError("PROXY_FRAME_STREAM_MISMATCH")
        if frame.kind is FrameKind.REQUEST_END:
            if frame.payload:
                raise ProxyProtocolError("PROXY_REQUEST_END_INVALID")
            break
        if frame.kind is not FrameKind.REQUEST_DATA:
            raise ProxyProtocolError("PROXY_REQUEST_FRAME_INVALID")
        raw.extend(frame.payload)
        if len(raw) > raw_limit:
            raise ProxyProtocolError("PROXY_REQUEST_FRAME_LIMIT")

    def emit(value: bytes) -> None:
        _send_chunked_frames(
            channel,
            kind=FrameKind.RESPONSE_DATA,
            stream_id=stream_id,
            payload=value,
        )

    result = proxy.handle_raw_request(bytes(raw), emit)
    terminal_payload = canonical_json(
        {
            "http_status": result.http_status,
            "request_state": result.request_state,
            "response_id_sha256": result.response_id_sha256,
            "sequence": result.sequence,
        }
    ).encode("ascii")
    send_frame(channel, Frame(FrameKind.RESPONSE_END, stream_id, terminal_payload))
    return result


def relay_framed_http_request(
    channel: socket.socket,
    contract: AttemptProxyContract,
    raw_request: bytes,
    *,
    stream_id: int = 1,
) -> tuple[bytes, Mapping[str, Any]]:
    """Trusted relay side of one loopback-to-UDS exchange."""

    send_frame(channel, Frame(FrameKind.HELLO, 0, channel_hello(contract)))
    send_frame(channel, Frame(FrameKind.REQUEST_START, stream_id))
    _send_chunked_frames(
        channel,
        kind=FrameKind.REQUEST_DATA,
        stream_id=stream_id,
        payload=raw_request,
    )
    send_frame(channel, Frame(FrameKind.REQUEST_END, stream_id))
    response = bytearray()
    while True:
        frame = receive_frame(channel)
        if frame.stream_id != stream_id:
            raise ProxyProtocolError("PROXY_FRAME_STREAM_MISMATCH")
        if frame.kind is FrameKind.RESPONSE_DATA:
            response.extend(frame.payload)
            continue
        if frame.kind is FrameKind.RESPONSE_END:
            try:
                terminal = json.loads(frame.payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProxyProtocolError("PROXY_RESPONSE_END_INVALID") from exc
            if type(terminal) is not dict:
                raise ProxyProtocolError("PROXY_RESPONSE_END_INVALID")
            return bytes(response), terminal
        raise ProxyProtocolError("PROXY_RESPONSE_FRAME_INVALID")


def read_one_loopback_request(
    client: socket.socket,
    *,
    max_header_bytes: int,
    max_body_bytes: int,
) -> bytes:
    """Read one bounded HTTP request from an already accepted loopback socket."""

    buffer = bytearray()
    boundary = -1
    while boundary < 0:
        chunk = client.recv(min(8192, max_header_bytes + 4 - len(buffer)))
        if not chunk:
            raise ProxyProtocolError("PROXY_LOOPBACK_REQUEST_TRUNCATED")
        buffer.extend(chunk)
        boundary = buffer.find(b"\r\n\r\n")
        if boundary < 0 and len(buffer) >= max_header_bytes:
            raise ProxyProtocolError("PROXY_LOOPBACK_HEADERS_LIMIT")
    header_block = bytes(buffer[:boundary])
    content_length = 0
    for line in header_block.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                content_length = 0
            break
    if content_length < 0 or content_length > max_body_bytes:
        raise ProxyProtocolError("PROXY_LOOPBACK_BODY_LIMIT")
    expected = boundary + 4 + content_length
    while len(buffer) < expected:
        chunk = client.recv(min(8192, expected - len(buffer)))
        if not chunk:
            raise ProxyProtocolError("PROXY_LOOPBACK_REQUEST_TRUNCATED")
        buffer.extend(chunk)
    if len(buffer) != expected:
        raise ProxyProtocolError("PROXY_LOOPBACK_PIPELINE_REJECTED")
    return bytes(buffer)


def relay_one_loopback_connection(
    client: socket.socket,
    channel: socket.socket,
    contract: AttemptProxyContract,
    *,
    stream_id: int = 1,
) -> Mapping[str, Any]:
    """Relay one accepted in-namespace loopback connection without auth data."""

    raw_request = read_one_loopback_request(
        client,
        max_header_bytes=contract.max_header_bytes,
        max_body_bytes=contract.max_body_bytes,
    )
    response, terminal = relay_framed_http_request(
        channel, contract, raw_request, stream_id=stream_id
    )
    _send_all(client, response)
    try:
        client.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    return terminal


def open_loopback_listener(port: int = 0) -> socket.socket:
    """Open only 127.0.0.1 inside the caller's already-isolated net namespace."""

    if not 0 <= port <= 65535:
        raise ProxyError("BROKER_PROXY_LOOPBACK_PORT_INVALID")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.set_inheritable(False)
        return listener
    except Exception:
        listener.close()
        raise
