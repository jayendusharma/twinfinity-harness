#!/usr/bin/env python3
"""Native Codex hook: fence Twinfinity delivery tools to one live role lease."""

from __future__ import annotations

from dataclasses import dataclass
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import stat
import sys
from typing import Any, Iterable, Mapping


DEFAULT_DATABASE = Path.home() / ".codex/twinfinity-coordination/ack-transactions.sqlite3"
DEFAULT_WORKTREE_ROOT = Path("/home/ubuntu/code")
CANONICAL_PREPUSH_CONTROL = Path(
    "/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/"
    "scripts/prepush_control.py"
)
SHELL_TOOL = re.compile(r"(?i)(?:exec|shell|bash|command)")
SHELL_SEGMENT = re.compile(r"&&|\|\||[;|\n]")
TOKEN = re.compile(r"[A-Za-z0-9_./-]+")
READ_ONLY_SEARCH = re.compile(r"^\s*(?:/usr/bin/)?(?:rg|grep)\b", re.IGNORECASE)
JS_DOUBLE_CMD = re.compile(r'\bcmd\s*:\s*("(?:\\.|[^"\\])*")', re.DOTALL)
JS_BACKTICK_CMD = re.compile(r"\bcmd\s*:\s*`([^`]*)`", re.DOTALL)
TOOLS_REFERENCE = re.compile(r"\btools\b")
READ_ONLY_NESTED_TOOL = re.compile(
    r"(?i)(?:^|__)(?:get|list|read|view|search|find|open|screenshot|status|wait|time|weather|finance|sports)(?:_|$)"
)
MUTATING_NESTED_TOOL = re.compile(
    r"(?i)(?:^|_)(?:apply|approve|archive|close|create|delete|deploy|disable|edit|enable|execute|install|merge|move|mutate|publish|push|remove|rename|restore|restart|run|send|set|start|stop|terminate|update|write)(?:_|$)"
)
DOUBLE_LITERAL_CONCAT = re.compile(r'"([^"\\]*)"\s*\+\s*"([^"\\]*)"')
SINGLE_LITERAL_CONCAT = re.compile(r"'([^'\\]*)'\s*\+\s*'([^'\\]*)'")
GIT_CONFIG_PUSH_ALIAS = re.compile(r"(?i)\bGIT_CONFIG_(?:VALUE|KEY)_\d+\s*=\s*['\"]?[^\s;&|]*push")
GIT_METADATA_ENV = re.compile(
    r"(?i)(?:^|[;&|\s])GIT_(?:DIR|WORK_TREE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES)\s*="
)
GIT_EXTERNAL_HELPER_ENV = re.compile(
    r"(?i)(?:^|[;&|\s'\"])GIT_(?:EXTERNAL_DIFF|ASKPASS|SSH|SSH_COMMAND|EDITOR|SEQUENCE_EDITOR|PAGER)\s*="
)
PASSIVE_POLL_LOOP = re.compile(r"(?is)\b(?:while|until)\b.*?\bdo\b.*?\b(?:sleep|usleep)\b.*?\bdone\b")
SHELL_CONDITION_LOOP = re.compile(r"(?is)\b(?:while|until)\b.*?\bdo\b.*?\bdone\b")
FINITE_WHILE_READ = re.compile(r"(?is)^\s*while\s+(?:IFS=\S*\s+)?read\b.*?\bdo\b.*?\bdone\b\s*(?:<\s*\S+)?\s*$")
INFINITE_FOR_LOOP = re.compile(r"(?is)\bfor\s*\(\(\s*;\s*;\s*\)\)\s*;?\s*do\b.*?\bdone\b")
CONSTANT_LOOP = re.compile(r"(?is)\bwhile\s+(?:true|:)\s*;?\s*do\b.*?\bdone\b")
LONG_RUNNING_WAIT = re.compile(
    r"(?ix)(?:^|\s)(?:/[A-Za-z0-9_./-]+/)?gh\b[^;&|\n]*\brun\s+watch\b"
    r"|(?:^|[;&|\n]\s*)(?:/[A-Za-z0-9_./-]+/)?watch\b"
    r"|(?:^|[;&|\n]\s*)(?:/[A-Za-z0-9_./-]+/)?tail\b[^;&|\n]*(?:\s-f\b|\s--follow(?:=\S+)?\b)"
    r"|(?:^|[;&|\n]\s*)(?:/[A-Za-z0-9_./-]+/)?journalctl\b[^;&|\n]*(?:\s-f\b|\s--follow\b)"
    r"|(?:^|[;&|\n]\s*)(?:/[A-Za-z0-9_./-]+/)?inotifywait\b[^;&|\n]*(?:\s-m\b|\s--monitor\b)"
)
INTERPRETER_POLL_LOOP = re.compile(r"(?is)\bwhile\s+[^:\n]+:\s*.*?\b(?:time\.)?sleep\s*\(")
SLEEP = re.compile(r"(?i)(?:^|[;&|\n]\s*)sleep\s+(\S+)")
DURATION = re.compile(r"(?i)(\d+(?:\.\d+)?)([smhd]?)")
REDIRECTION = re.compile(r"(?<!<)(?:\d*)(?:>\||>>?)\s*([^\s;&|]+)")
PATCH_PATH = re.compile(r"^\*\*\* (?:Update|Add|Delete) File: (.+)$", re.MULTILINE)
PATCH_MOVE_PATH = re.compile(r"^\*\*\* Move to: (.+)$", re.MULTILINE)
FILESYSTEM_WRITE_TOOL = re.compile(r"(?i)(?:apply_patch|(?:write|edit|create|delete|remove|rename|move|copy)_file)")
PROVIDER_TOOL = re.compile(r"(?i)(?:boto3|cloudflare|supabase|google[._-]?cloud|gcp|aws|azure|kubectl|terraform|pulumi|vercel|heroku|flyio|provider|iam|secret|billing|production|deploy|traffic)")
PROVIDER_COMMANDS = {"aws", "az", "gcloud", "kubectl", "pulumi", "supabase", "terraform", "tofu", "vercel", "wrangler", "flyctl", "heroku"}
SHELL_WRAPPERS = {"bash", "dash", "sh", "zsh"}
PREFIX_WRAPPERS = {"command", "env", "nice", "nohup", "setsid", "stdbuf", "sudo"}
INTERPRETER_WRAPPERS = {"node", "nodejs", "perl", "php", "python", "python3", "ruby"}
PROCESS_EXECUTION = re.compile(
    r"(?i)(?:\bsubprocess\b|\bos\.system\s*\(|\bos\.popen\s*\(|"
    r"\bchild_process\b|\bexec(?:File|Sync)?\s*\(|\bspawn(?:Sync)?\s*\()"
)
INTERPRETER_WRITE = re.compile(
    r"(?i)(?:\bFile\.(?:write|delete|rename)\s*\(|\bfs\.(?:write|append|unlink|rename|mkdir|rm)"
    r"(?:File|Sync)?\s*\(|\bDeno\.(?:write|remove|rename|mkdir)\w*\s*\()"
)
SCRIPT_WRITE = re.compile(r"(?i)(?:write_text|write_bytes|\.unlink\s*\(|\.mkdir\s*\(|os\.(?:remove|unlink|rename|replace|mkdir|makedirs)\s*\(|open\s*\([^)]*,\s*['\"][wax+])")
FORMAT_WRITE = re.compile(r"(?i)(?:^|\s)(?:--write|--fix|-w|-i)(?:\s|$)")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
BRANCH = re.compile(r"^codex/[0-9]+-[a-z0-9][a-z0-9-]*$")
MAX_PASSIVE_WAIT_SECONDS = 60.0
MAX_ARTIFACT_BYTES = 1024 * 1024
LEASE_REQUIRED_KEYS = {"repository", "issue_number", "generation", "base_sha", "branch", "worktree_path", "no_additional_paths", "paths"}
GIT_READ_ONLY_SUBCOMMANDS = frozenset(
    {
        "cat-file",
        "count-objects",
        "describe",
        "diff",
        "for-each-ref",
        "grep",
        "log",
        "ls-files",
        "ls-remote",
        "ls-tree",
        "merge-base",
        "name-rev",
        "range-diff",
        "rev-parse",
        "shortlog",
        "show",
        "status",
    }
)
GH_READ_ONLY_COMMANDS = frozenset(
    {
        ("auth", "status"),
        ("issue", "list"),
        ("issue", "status"),
        ("issue", "view"),
        ("pr", "checks"),
        ("pr", "diff"),
        ("pr", "list"),
        ("pr", "status"),
        ("pr", "view"),
        ("release", "list"),
        ("release", "view"),
        ("repo", "view"),
        ("run", "list"),
        ("run", "view"),
        ("run", "watch"),
        ("workflow", "list"),
        ("workflow", "view"),
    }
)


@dataclass(frozen=True)
class DeliveryContext:
    role: str
    endpoint_id: str
    target_kind: str
    target_key: str
    topic: str | None
    worktree: Path | None
    lease_paths: frozenset[Path]
    repository_writes: bool
    canonical_checkout: Path | None = None
    branch: str | None = None
    base_sha: str | None = None
    repository: str | None = None


@dataclass(frozen=True)
class ShellWrite:
    writes: bool = False
    paths: tuple[str, ...] = ()
    worktree_only: bool = False
    ambiguous: bool = False
    allow_parent: bool = False


@dataclass(frozen=True)
class CommandLeaf:
    command: str
    bounded_wait: bool = False
    interpreter: str | None = None


class GuardError(RuntimeError):
    """Value-free fail-closed guard error."""


def _deny(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}


def _commands(tool_input: dict[str, Any]) -> Iterable[str]:
    for key in ("cmd", "command", "shell_command"):
        value = tool_input.get(key)
        if isinstance(value, str):
            yield value
    source = tool_input.get("source")
    if not isinstance(source, str):
        source = tool_input.get("input")
    if isinstance(source, str):
        for match in JS_DOUBLE_CMD.finditer(source):
            try:
                value = json.loads(match.group(1))
            except json.JSONDecodeError:
                continue
            if isinstance(value, str):
                yield value
        yield from (match.group(1) for match in JS_BACKTICK_CMD.finditer(source))


def _shell_tokens(command: str) -> tuple[str, ...] | None:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return tuple(lexer)
    except ValueError:
        return None


def _command_segments(command: str) -> tuple[str, ...] | None:
    tokens = _shell_tokens(command)
    if tokens is None:
        return None
    segments: list[str] = []
    current: list[str] = []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&"}:
            if current:
                segments.append(
                    " ".join(
                        item
                        if item in {
                            ">", ">>", ">|", "&>", "&>>",
                            "1>", "1>>", "1>|", "2>", "2>>", "2>|",
                        }
                        else shlex.quote(item)
                        for item in current
                    )
                )
                current = []
        else:
            current.append(token)
    if current:
        segments.append(
            " ".join(
                item
                if item in {
                    ">", ">>", ">|", "&>", "&>>",
                    "1>", "1>>", "1>|", "2>", "2>>", "2>|",
                }
                else shlex.quote(item)
                for item in current
            )
        )
    return tuple(segments)


def _duration_seconds(value: str) -> float | None:
    match = DURATION.fullmatch(value)
    if match is None:
        return None
    multiplier = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}[match.group(2).lower()]
    return float(match.group(1)) * multiplier


def _is_single_read_only_search(command: str) -> bool:
    tokens = _shell_tokens(command)
    return bool(tokens and tokens[0].rstrip("/").rsplit("/", 1)[-1].lower() in {"rg", "grep"} and not any(token in {";", "&&", "||", "|", "&"} for token in tokens) and "$(" not in command and "`" not in command and "--pre" not in command)


def _has_bounded_top_level_timeout(command: str) -> bool:
    tokens = _shell_tokens(command)
    if not tokens or tokens[0].rstrip("/").rsplit("/", 1)[-1].lower() != "timeout" or any(token in {";", "&&", "||", "|", "&"} for token in tokens):
        return False
    index = 1
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        index += 1
        if option in {"-k", "--kill-after", "-s", "--signal"}:
            index += 1
        elif option == "--":
            break
    if index >= len(tokens):
        return False
    seconds = _duration_seconds(tokens[index])
    return seconds is not None and seconds <= MAX_PASSIVE_WAIT_SECONDS and index + 1 < len(tokens)


def _contains_open_ended_wait(command: str) -> bool:
    if _is_single_read_only_search(command):
        return False
    shell_condition_loop = bool(SHELL_CONDITION_LOOP.search(command))
    if FINITE_WHILE_READ.fullmatch(command) and not PASSIVE_POLL_LOOP.search(command):
        shell_condition_loop = False
    passive_wait = bool(shell_condition_loop or PASSIVE_POLL_LOOP.search(command) or INFINITE_FOR_LOOP.search(command) or CONSTANT_LOOP.search(command) or LONG_RUNNING_WAIT.search(command) or INTERPRETER_POLL_LOOP.search(command))
    for match in SLEEP.finditer(command):
        seconds = _duration_seconds(match.group(1))
        if seconds is None or seconds > MAX_PASSIVE_WAIT_SECONDS:
            passive_wait = True
    return passive_wait and not _has_bounded_top_level_timeout(command)


def _contains_raw_push(command: str) -> bool:
    while True:
        collapsed = DOUBLE_LITERAL_CONCAT.sub(lambda match: f'"{match.group(1)}{match.group(2)}"', command)
        collapsed = SINGLE_LITERAL_CONCAT.sub(lambda match: f"'{match.group(1)}{match.group(2)}'", collapsed)
        if collapsed == command:
            break
        command = collapsed
    for segment in SHELL_SEGMENT.split(command):
        if READ_ONLY_SEARCH.match(segment) and "$(" not in segment and "`" not in segment and "--pre" not in segment:
            continue
        tokens = TOKEN.findall(segment.lower())
        git_indexes = [index for index, token in enumerate(tokens) if token.rstrip("/").rsplit("/", 1)[-1] == "git"]
        if git_indexes and GIT_CONFIG_PUSH_ALIAS.search(segment):
            return True
        for index in git_indexes:
            if "push" in tokens[index + 1:]:
                return True
    return False


def _safe_database(path: Path) -> sqlite3.Connection:
    metadata = path.lstat()
    parent = path.parent.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise GuardError("DELIVERY_CONTEXT_INVALID")
    connection = sqlite3.connect(f"{path.resolve(strict=True).as_uri()}?mode=ro", uri=True, isolation_level=None, timeout=2)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=2000")
    return connection


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("DELIVERY_LEASE_INVALID")
        result[key] = value
    return result


def _read_artifact(database: Path, row: sqlite3.Row) -> bytes:
    relative = Path(str(row["relative_path"]))
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise GuardError("DELIVERY_LEASE_INVALID")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptors = [os.open(database.parent, flags | os.O_DIRECTORY)]
    try:
        for component in relative.parts[:-1]:
            descriptors.append(os.open(component, flags | os.O_DIRECTORY, dir_fd=descriptors[-1]))
        descriptor = os.open(relative.parts[-1], flags, dir_fd=descriptors[-1])
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or metadata.st_size > MAX_ARTIFACT_BYTES or metadata.st_size != int(row["size_bytes"]) or metadata.st_dev != int(row["device_id"]) or metadata.st_ino != int(row["inode"]):
            raise GuardError("DELIVERY_LEASE_INVALID")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size",
            "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(metadata, field) != getattr(after, field) for field in stable_fields):
            raise GuardError("DELIVERY_LEASE_INVALID")
        return b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _parse_lease(raw: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuardError("DELIVERY_LEASE_INVALID") from exc
    if not isinstance(manifest, dict) or set(manifest) != LEASE_REQUIRED_KEYS:
        raise GuardError("DELIVERY_LEASE_INVALID")
    worktree = Path(manifest.get("worktree_path", ""))
    if not isinstance(manifest.get("repository"), str) or type(manifest.get("issue_number")) is not int or manifest["issue_number"] <= 0 or type(manifest.get("generation")) is not int or manifest["generation"] < 0 or not isinstance(manifest.get("base_sha"), str) or GIT_SHA.fullmatch(manifest["base_sha"]) is None or not isinstance(manifest.get("branch"), str) or BRANCH.fullmatch(manifest["branch"]) is None or not worktree.is_absolute() or manifest.get("no_additional_paths") is not True or not isinstance(manifest.get("paths"), list) or not manifest["paths"]:
        raise GuardError("DELIVERY_LEASE_INVALID")
    observed: set[str] = set()
    for entry in manifest["paths"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "mode", "type", "sha"}:
            raise GuardError("DELIVERY_LEASE_INVALID")
        value = entry.get("path")
        relative = Path(value) if isinstance(value, str) else Path()
        if not isinstance(value, str) or not value or "\\" in value or relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts) or relative.as_posix() != value or value in observed or entry["mode"] not in {"100644", "100755", "120000"} or entry["type"] != "blob" or (entry["sha"] is not None and (not isinstance(entry["sha"], str) or GIT_SHA.fullmatch(entry["sha"]) is None)):
            raise GuardError("DELIVERY_LEASE_INVALID")
        observed.add(value)
    return manifest


def _source_is_current(connection: sqlite3.Connection, payload: dict[str, Any]) -> bool:
    source = payload.get("source")
    if not isinstance(source, dict):
        return False
    row = connection.execute("SELECT payload_sha256 FROM github_current WHERE repository=? AND object_kind=? AND object_number=?", (source.get("repository"), source.get("object_kind"), source.get("object_number"))).fetchone()
    return bool(row is not None and isinstance(source.get("payload_sha256"), str) and secrets.compare_digest(str(row["payload_sha256"]), source["payload_sha256"]))


def _load_lease(
    connection: sqlite3.Connection,
    database: Path,
    payload: dict[str, Any],
    worktree_root: Path,
) -> tuple[Path, frozenset[Path], Path, str, str]:
    source = payload.get("source")
    if not isinstance(source, dict):
        raise GuardError("DELIVERY_TARGET_INVALID")
    repository, issue_number, generation = source.get("repository"), payload.get("issue_number"), payload.get("generation")
    digest, worktree_value = payload.get("lease_manifest_sha256"), payload.get("worktree_path")
    repository_parts = repository.split("/", 1) if isinstance(repository, str) else []
    if not isinstance(repository, str) or len(repository_parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in repository_parts) or type(issue_number) is not int or issue_number <= 0 or type(generation) is not int or generation < 0 or not isinstance(digest, str) or SHA256.fullmatch(digest) is None or not isinstance(worktree_value, str):
        raise GuardError("DELIVERY_TARGET_INVALID")
    worktree = Path(worktree_value)
    if not worktree.is_absolute() or worktree.parent != worktree_root:
        raise GuardError("DELIVERY_TARGET_INVALID")
    rows = connection.execute("SELECT relative_path,content_sha256,size_bytes,device_id,inode FROM coordination_artifacts WHERE repository=? AND issue_number=? AND generation=? AND content_sha256=? AND state='REGISTERED'", (repository, issue_number, generation, digest)).fetchall()
    if len(rows) != 1:
        raise GuardError("DELIVERY_LEASE_INVALID")
    raw = _read_artifact(database, rows[0])
    if not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), digest):
        raise GuardError("DELIVERY_LEASE_INVALID")
    manifest = _parse_lease(raw)
    if manifest["repository"] != repository or manifest["issue_number"] != issue_number or manifest["generation"] != generation or manifest["base_sha"] != payload.get("base_sha") or manifest["branch"] != payload.get("branch") or manifest["worktree_path"] != worktree_value:
        raise GuardError("DELIVERY_LEASE_INVALID")
    return (
        worktree,
        frozenset(worktree / entry["path"] for entry in manifest["paths"]),
        worktree_root / repository_parts[1],
        str(manifest["branch"]),
        str(manifest["base_sha"]),
    )


def _item_matches(connection: sqlite3.Connection, payload: dict[str, Any], endpoint_id: str, *, exact_version: bool) -> bool:
    source = payload.get("source")
    if not isinstance(source, dict):
        return False
    row = connection.execute("SELECT * FROM coordination_items WHERE repository=? AND issue_number=?", (source.get("repository"), payload.get("issue_number"))).fetchone()
    return bool(row is not None and row["status"] in {"ACTIVE", "ACTIVE_FENCED", "MONITOR", "HOLD"} and row["allocation_class"] in {"ACTIVE", "RETAINED"} and int(row["generation"]) == payload.get("generation") and row["accountable_session_id"] == endpoint_id and row["lease_manifest_sha256"] == payload.get("lease_manifest_sha256") and row["source_payload_sha256"] == source.get("payload_sha256") and (not exact_version or int(row["version"]) == payload.get("item_version")))


def _message_context(connection: sqlite3.Connection, database: Path, *, role: str, endpoint_id: str, target_key: str, worktree_root: Path) -> DeliveryContext:
    try:
        message_id = int(target_key)
    except ValueError as exc:
        raise GuardError("DELIVERY_TARGET_INVALID") from exc
    row = connection.execute("SELECT recipient_session_id,topic,payload_json,state FROM coordination_messages WHERE id=?", (message_id,)).fetchone()
    if row is None or row["state"] not in {"PREPARED", "CLAIMED"} or row["recipient_session_id"] != endpoint_id:
        raise GuardError("DELIVERY_TARGET_INVALID")
    topic = str(row["topic"])
    if topic != "coordination.notice" and not topic.startswith(f"{role}."):
        raise GuardError("DELIVERY_ROLE_TARGET_MISMATCH")
    try:
        payload = json.loads(row["payload_json"])
    except json.JSONDecodeError as exc:
        raise GuardError("DELIVERY_TARGET_INVALID") from exc
    if not isinstance(payload, dict) or not _source_is_current(connection, payload):
        raise GuardError("DELIVERY_TARGET_INVALID")
    if topic == "coordination.notice":
        if payload.get("mutation_authority") is not False:
            raise GuardError("DELIVERY_TARGET_INVALID")
        return DeliveryContext(role, endpoint_id, "message", target_key, topic, None, frozenset(), False)
    if topic in {"development.recovery_prepare", "development.terminal_closeout"}:
        return DeliveryContext(role, endpoint_id, "message", target_key, topic, None, frozenset(), False)
    if topic not in {"development.admission", "development.recovery_commit", "sre.admission"} or not _item_matches(connection, payload, endpoint_id, exact_version=True):
        raise GuardError("DELIVERY_TARGET_INVALID")
    worktree, paths, canonical_checkout, branch, base_sha = _load_lease(
        connection, database, payload, worktree_root
    )
    return DeliveryContext(
        role,
        endpoint_id,
        "message",
        target_key,
        topic,
        worktree,
        paths,
        True,
        canonical_checkout,
        branch,
        base_sha,
        str(payload["source"]["repository"]),
    )


def _terminal_watch_context(connection: sqlite3.Connection, database: Path, *, role: str, endpoint_id: str, target_key: str, worktree_root: Path) -> DeliveryContext:
    watch = connection.execute("SELECT * FROM coordination_terminal_watches WHERE watch_key=?", (target_key,)).fetchone()
    if watch is None or watch["state"] != "ACTIVE" or watch["accountable_session_id"] != endpoint_id:
        raise GuardError("DELIVERY_TARGET_INVALID")
    topics = {"development.admission", "development.recovery_commit"} if role == "development" else {"sre.admission"}
    payload: dict[str, Any] | None = None
    for candidate in connection.execute("SELECT topic,payload_json FROM coordination_messages WHERE recipient_session_id=? ORDER BY id DESC", (endpoint_id,)).fetchall():
        if candidate["topic"] not in topics:
            continue
        try:
            value = json.loads(candidate["payload_json"])
        except json.JSONDecodeError:
            continue
        source = value.get("source") if isinstance(value, dict) else None
        if isinstance(source, dict) and source.get("repository") == watch["repository"] and value.get("issue_number") == int(watch["issue_number"]) and value.get("generation") == int(watch["generation"]) and value.get("lease_manifest_sha256") == watch["lease_manifest_sha256"]:
            payload = value
            break
    if payload is None or not _source_is_current(connection, payload) or not _item_matches(connection, payload, endpoint_id, exact_version=False):
        raise GuardError("DELIVERY_TARGET_INVALID")
    worktree, paths, canonical_checkout, branch, base_sha = _load_lease(
        connection, database, payload, worktree_root
    )
    return DeliveryContext(
        role,
        endpoint_id,
        "terminal_watch",
        target_key,
        None,
        worktree,
        paths,
        True,
        canonical_checkout,
        branch,
        base_sha,
        str(payload["source"]["repository"]),
    )


def _hosted_context(connection: sqlite3.Connection, *, role: str, endpoint_id: str, target_key: str) -> DeliveryContext:
    if role != "sre":
        raise GuardError("DELIVERY_ROLE_TARGET_MISMATCH")
    try:
        operation_id = int(target_key)
    except ValueError as exc:
        raise GuardError("DELIVERY_TARGET_INVALID") from exc
    row = connection.execute("SELECT recipient_session_id,state FROM hosted_operations WHERE id=?", (operation_id,)).fetchone()
    if row is None or row["state"] not in {"PREPARED", "CLAIMED"} or row["recipient_session_id"] != endpoint_id:
        raise GuardError("DELIVERY_TARGET_INVALID")
    return DeliveryContext(role, endpoint_id, "hosted_operation", target_key, None, frozenset(), False)


def _load_context(environ: Mapping[str, str], database: Path, worktree_root: Path) -> DeliveryContext:
    names = ("TWINFINITY_EXECUTOR_ATTEMPT_ID", "TWINFINITY_EXECUTOR_INSTANCE_ID", "TWINFINITY_EXECUTOR_ROLE", "TWINFINITY_ROLE_ENDPOINT", "TWINFINITY_EXECUTOR_TOKEN", "TWINFINITY_EXECUTOR_TARGET_KIND", "TWINFINITY_EXECUTOR_TARGET_KEY")
    values = {name: environ.get(name, "") for name in names}
    if any(not value for value in values.values()):
        raise GuardError("DELIVERY_CONTEXT_INVALID")
    attempt_id, instance_id = values[names[0]], values[names[1]]
    role, endpoint_id, token = values[names[2]], values[names[3]], values[names[4]]
    target_kind, target_key = values[names[5]], values[names[6]]
    if UUID.fullmatch(attempt_id) is None or UUID.fullmatch(instance_id) is None or role not in {"development", "sre"} or target_kind not in {"message", "terminal_watch", "hosted_operation"}:
        raise GuardError("DELIVERY_CONTEXT_INVALID")
    connection = _safe_database(database)
    try:
        connection.execute("BEGIN")
        endpoint = connection.execute("SELECT current.endpoint_id,definitions.role FROM executor_role_endpoint_current current JOIN executor_role_endpoints definitions ON definitions.endpoint_id=current.endpoint_id WHERE current.role=?", (role,)).fetchone()
        if endpoint is None or endpoint["endpoint_id"] != endpoint_id or endpoint["role"] != role:
            raise GuardError("DELIVERY_ENDPOINT_STALE")
        attempt = connection.execute("SELECT * FROM executor_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if attempt is None or attempt["instance_id"] != instance_id or attempt["role"] != role or attempt["endpoint_id"] != endpoint_id or attempt["target_kind"] != target_kind or attempt["target_key"] != target_key or attempt["state"] not in {"LAUNCHING", "RUNNING"} or not secrets.compare_digest(str(attempt["token_sha256"]), token_sha256):
            raise GuardError("DELIVERY_ATTEMPT_INVALID")
        if target_kind == "message":
            context = _message_context(connection, database, role=role, endpoint_id=endpoint_id, target_key=target_key, worktree_root=worktree_root)
        elif target_kind == "terminal_watch":
            context = _terminal_watch_context(connection, database, role=role, endpoint_id=endpoint_id, target_key=target_key, worktree_root=worktree_root)
        else:
            context = _hosted_context(connection, role=role, endpoint_id=endpoint_id, target_key=target_key)
        connection.execute("COMMIT")
        return context
    except Exception:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        connection.close()


def _provider_command(command: str) -> bool:
    tokens = _shell_tokens(command)
    return bool(
        tokens
        and tokens[0].rstrip("/").rsplit("/", 1)[-1].casefold()
        in PROVIDER_COMMANDS
    )


def _cwd(event: dict[str, Any], tool_input: dict[str, Any]) -> Path:
    value = tool_input.get("workdir", event.get("cwd", os.getcwd()))
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise GuardError("DELIVERY_WRITE_PATH_INVALID")
    return Path(os.path.abspath(value))


def _path_value(value: str, cwd: Path) -> Path:
    try:
        token = shlex.split(value)[0]
    except (ValueError, IndexError) as exc:
        raise GuardError("DELIVERY_WRITE_PATH_INVALID") from exc
    path = Path(token)
    return Path(os.path.abspath(path if path.is_absolute() else cwd / path))


def _descriptor_unchanged(descriptor: int, before: os.stat_result) -> bool:
    after = os.fstat(descriptor)
    return all(
        getattr(before, field) == getattr(after, field)
        for field in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink",
            "st_size", "st_mtime_ns", "st_ctime_ns",
        )
    )


def _namespace_chain_unchanged(
    worktree: Path,
    relative: Path,
    snapshots: list[os.stat_result],
    *,
    missing_leaf: bool,
) -> bool:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    reopened: list[int] = []
    try:
        reopened.append(os.open(worktree, flags | os.O_DIRECTORY))
        components = () if relative == Path(".") else relative.parts
        existing_components = len(snapshots) - 1
        for index, component in enumerate(components[:existing_components]):
            final_existing = index == existing_components - 1 and not missing_leaf
            reopened.append(
                os.open(
                    component,
                    flags | (0 if final_existing else os.O_DIRECTORY),
                    dir_fd=reopened[-1],
                )
            )
        if len(reopened) != len(snapshots):
            return False
        if any(
            os.fstat(descriptor).st_dev != before.st_dev
            or os.fstat(descriptor).st_ino != before.st_ino
            or os.fstat(descriptor).st_mode != before.st_mode
            for descriptor, before in zip(reopened, snapshots, strict=True)
        ):
            return False
        if missing_leaf:
            try:
                os.stat(components[-1], dir_fd=reopened[-1], follow_symlinks=False)
            except FileNotFoundError:
                return True
            return False
        return True
    except OSError:
        return False
    finally:
        for descriptor in reversed(reopened):
            os.close(descriptor)


def _stable_descriptor_path(path: Path, worktree: Path, *, allow_missing_leaf: bool) -> bool:
    """Reject symlink/rename traversal while validating one worktree-relative path."""
    try:
        relative = path.relative_to(worktree)
    except ValueError:
        return False
    if not relative.parts:
        relative = Path(".")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptors: list[int] = []
    snapshots: list[os.stat_result] = []
    missing_leaf = False
    try:
        root_descriptor = os.open(worktree, flags | os.O_DIRECTORY)
        descriptors.append(root_descriptor)
        root_metadata = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
            or root_metadata.st_nlink < 1
        ):
            return False
        snapshots.append(root_metadata)
        for index, component in enumerate(() if relative == Path(".") else relative.parts):
            final = index == len(relative.parts) - 1
            try:
                descriptor = os.open(
                    component,
                    flags | (0 if final else os.O_DIRECTORY),
                    dir_fd=descriptors[-1],
                )
            except FileNotFoundError:
                if not (final and allow_missing_leaf):
                    return False
                missing_leaf = True
                break
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if final:
                if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                    return False
            elif not stat.S_ISDIR(metadata.st_mode):
                return False
            if metadata.st_uid != os.getuid() or metadata.st_nlink < 1:
                return False
            snapshots.append(metadata)
        return all(
            _descriptor_unchanged(descriptor, before)
            for descriptor, before in zip(descriptors, snapshots, strict=True)
        ) and _namespace_chain_unchanged(
            worktree, relative, snapshots, missing_leaf=missing_leaf
        )
    except OSError:
        return False
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _worktree_relative_path_allowed(path: Path, context: DeliveryContext) -> bool:
    if context.worktree is None:
        return False
    if path not in context.lease_paths:
        return False
    return _stable_descriptor_path(
        path, context.worktree, allow_missing_leaf=True
    )


def _path_allowed(path: Path, context: DeliveryContext, *, allow_parent: bool = False) -> bool:
    if path == Path("/dev/null"):
        return True
    if _worktree_relative_path_allowed(path, context):
        return True
    if not allow_parent or context.worktree is None:
        return False
    if not any(path in candidate.parents for candidate in context.lease_paths):
        return False
    return _stable_descriptor_path(path, context.worktree, allow_missing_leaf=False)


def _file_tool_paths(tool_input: dict[str, Any]) -> tuple[str, ...]:
    patch = tool_input.get("patch")
    if not isinstance(patch, str):
        patch = tool_input.get("input")
    if isinstance(patch, str):
        values = [*PATCH_PATH.findall(patch), *PATCH_MOVE_PATH.findall(patch)]
        if values:
            return tuple(values)
    return tuple(value for key in ("path", "file_path", "target_path", "destination", "destination_path") if isinstance((value := tool_input.get(key)), str))


def _operands(tokens: tuple[str, ...], start: int = 1) -> tuple[str, ...]:
    return tuple(token for token in tokens[start:] if not token.startswith("-"))


def _git_write(tokens: tuple[str, ...]) -> ShellWrite:
    index = 1
    alternate_worktree = False
    while index < len(tokens) and tokens[index].startswith("-"):
        if tokens[index] == "-C":
            alternate_worktree = True
            index += 2
        else:
            index += 1
    if index >= len(tokens):
        return ShellWrite()
    subcommand = tokens[index].casefold()
    arguments = tokens[index + 1:]
    if subcommand in {"status", "diff", "show", "log", "rev-parse", "ls-files", "ls-tree", "grep", "cat-file", "merge-base"}:
        return ShellWrite()
    if subcommand == "worktree" and arguments[:1] == ("list",):
        return ShellWrite()
    if subcommand == "branch" and (
        not arguments or arguments == ("--show-current",) or arguments[:1] == ("--list",)
    ):
        return ShellWrite()
    if subcommand == "remote" and (
        not arguments or arguments in {("-v",), ("--verbose",)} or arguments[:1] == ("get-url",)
    ):
        return ShellWrite()
    if subcommand == "config" and arguments and (
        arguments[0].startswith("--get") or arguments[0] in {"--list", "-l"}
    ):
        return ShellWrite()
    if subcommand in {"add", "rm"}:
        paths = _operands(tokens, index + 1)
        return ShellWrite(True, paths=paths, ambiguous=alternate_worktree or not paths or any(path in {".", "-A", "--all"} for path in paths))
    if subcommand == "mv":
        paths = _operands(tokens, index + 1)
        return ShellWrite(True, paths=paths, ambiguous=alternate_worktree or len(paths) != 2)
    if subcommand == "commit":
        return ShellWrite(
            True,
            worktree_only=True,
            ambiguous=alternate_worktree or any(
                argument in {"-a", "--all"} for argument in arguments
            ),
        )
    if subcommand == "push":
        return ShellWrite()
    return ShellWrite(True, ambiguous=True)


def _enforce_exact_worktree_command(
    command: str,
    context: DeliveryContext,
    cwd: Path,
) -> dict[str, Any] | None:
    """Default-deny Git mutation and permit only exact admitted metadata forms."""

    tokens = _shell_tokens(command)
    if not tokens or tokens[0].rstrip("/").rsplit("/", 1)[-1].casefold() != "git":
        return None
    if GIT_METADATA_ENV.search(command):
        return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
    index = 1
    repository_cwd = cwd
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        if option == "-C":
            if index + 1 >= len(tokens):
                return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
            repository_cwd = _path_value(tokens[index + 1], repository_cwd)
            index += 2
            continue
        if option == "--":
            index += 1
            break
        if option in {"--literal-pathspecs", "--no-pager", "--no-replace-objects"}:
            index += 1
            continue
        # Includes --git-dir, --work-tree, -c, --config-env, and aliases.
        return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
    if index >= len(tokens):
        return _deny("DELIVERY_GIT_COMMAND_NOT_APPROVED")
    subcommand = tokens[index].casefold()
    arguments = tokens[index + 1:]
    if any(
        argument in {"--git-dir", "--work-tree"}
        or argument.startswith(("--git-dir=", "--work-tree="))
        for argument in arguments
    ):
        return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")

    if subcommand in GIT_READ_ONLY_SUBCOMMANDS:
        if any(
            argument in {"--ext-diff", "--textconv", "--output"}
            or argument.startswith("--output=")
            for argument in arguments
        ):
            return _deny("DELIVERY_GIT_COMMAND_NOT_APPROVED")
        return {}
    if subcommand == "worktree" and arguments[:1] == ("list",):
        return {}
    if subcommand == "branch" and (
        not arguments
        or arguments == ("--show-current",)
        or arguments[:1] == ("--list",)
    ):
        return {}
    if subcommand == "remote" and (
        not arguments
        or arguments in {("-v",), ("--verbose",)}
        or arguments[:1] == ("get-url",)
    ):
        return {}
    if subcommand == "config" and arguments and (
        arguments[0].startswith("--get") or arguments[0] in {"--list", "-l"}
    ):
        return {}

    if subcommand == "fetch":
        fetch_operands = tuple(
            argument for argument in arguments if argument not in {"--no-tags", "--quiet", "-q"}
        )
        admitted_roots = {context.canonical_checkout, context.worktree}
        if (
            context.repository_writes
            and context.base_sha is not None
            and repository_cwd in admitted_roots
            and fetch_operands
            in {
                ("origin", "main"),
                ("origin", "refs/heads/main"),
                ("origin", context.base_sha),
            }
            and _stable_descriptor_path(
                repository_cwd, repository_cwd, allow_missing_leaf=False
            )
        ):
            return {}
        return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")

    if (
        not context.repository_writes
        or context.canonical_checkout is None
        or context.worktree is None
        or context.branch is None
        or context.base_sha is None
    ):
        return _deny("DELIVERY_TARGET_HAS_NO_REPOSITORY_WRITE_AUTHORITY")

    if subcommand == "branch" and arguments in {
        ("-d", context.branch),
        ("--delete", context.branch),
    }:
        if (
            repository_cwd != context.canonical_checkout
            or os.path.lexists(context.worktree)
            or not _stable_descriptor_path(
                context.canonical_checkout,
                context.canonical_checkout,
                allow_missing_leaf=False,
            )
        ):
            return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
        return {}

    if subcommand in {"add", "rm", "mv", "commit"}:
        if repository_cwd != context.worktree:
            return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
        if subcommand == "commit":
            position = 0
            while position < len(arguments):
                argument = arguments[position]
                if argument in {"-m", "--message"}:
                    position += 2
                    continue
                if argument in {"--no-gpg-sign", "--quiet", "-q", "--signoff", "-s"}:
                    position += 1
                    continue
                return _deny("DELIVERY_GIT_COMMAND_NOT_APPROVED")
            if not arguments:
                return _deny("DELIVERY_GIT_COMMAND_NOT_APPROVED")
        assessment = _git_write(("git", subcommand, *arguments))
        return _enforce_repository_write(assessment, context, repository_cwd)

    if subcommand != "worktree":
        return _deny("DELIVERY_GIT_COMMAND_NOT_APPROVED")
    if (
        repository_cwd != context.canonical_checkout
        or context.canonical_checkout.parent != context.worktree.parent
        or not _stable_descriptor_path(
            context.canonical_checkout,
            context.canonical_checkout,
            allow_missing_leaf=False,
        )
    ):
        return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
    if arguments == (
        "add",
        "-b",
        context.branch,
        str(context.worktree),
        context.base_sha,
    ):
        if os.path.lexists(context.worktree) or not _stable_descriptor_path(
            context.worktree.parent,
            context.worktree.parent,
            allow_missing_leaf=False,
        ):
            return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
        return {}
    if arguments == ("remove", str(context.worktree)):
        return (
            {}
            if _stable_descriptor_path(
                context.worktree,
                context.worktree,
                allow_missing_leaf=False,
            )
            else _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
        )
    return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")


def _option_values(
    arguments: tuple[str, ...], long_name: str, short_name: str
) -> tuple[str, ...]:
    values: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {long_name, short_name}:
            values.append(arguments[index + 1] if index + 1 < len(arguments) else "")
            index += 2
            continue
        if argument.startswith(f"{long_name}="):
            values.append(argument.split("=", 1)[1])
        elif argument.startswith(short_name) and argument != short_name:
            values.append(argument[len(short_name):].removeprefix("="))
        index += 1
    return tuple(values)


def _enforce_gh_command(
    tokens: tuple[str, ...], context: DeliveryContext, cwd: Path
) -> dict[str, Any]:
    index = 1
    selected_repository: str | None = None
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        if option in {"--repo", "-R", "--hostname"}:
            if index + 1 >= len(tokens):
                return _deny("DELIVERY_GH_COMMAND_NOT_APPROVED")
            if option in {"--repo", "-R"}:
                selected_repository = tokens[index + 1]
            index += 2
            continue
        if option.startswith("--repo="):
            selected_repository = option.split("=", 1)[1]
            index += 1
            continue
        if option.startswith("-R") and option != "-R":
            selected_repository = option[2:].removeprefix("=")
            if not selected_repository:
                return _deny("DELIVERY_GH_COMMAND_NOT_APPROVED")
            index += 1
            continue
        if option == "--":
            index += 1
            break
        return _deny("DELIVERY_GH_COMMAND_NOT_APPROVED")
    if index >= len(tokens):
        return _deny("DELIVERY_GH_COMMAND_NOT_APPROVED")
    group = tokens[index].casefold()
    arguments = tokens[index + 1:]
    if group == "api":
        method = "GET"
        position = 0
        while position < len(arguments):
            argument = arguments[position]
            if argument in {"-X", "--method"}:
                if position + 1 >= len(arguments):
                    return _deny("DELIVERY_GH_API_MUTATION_FORBIDDEN")
                method = arguments[position + 1].upper()
                position += 2
                continue
            if argument.startswith("-X") and argument != "-X":
                method = argument[2:].upper()
            if argument.startswith("--method="):
                method = argument.split("=", 1)[1].upper()
            if (
                argument in {"-f", "-F", "--field", "--raw-field", "--input"}
                or argument.startswith(
                    ("-f", "-F", "--field=", "--raw-field=", "--input=")
                )
                or argument.casefold() == "graphql"
            ):
                return _deny("DELIVERY_GH_API_MUTATION_FORBIDDEN")
            position += 1
        return (
            {}
            if method in {"GET", "HEAD"}
            else _deny("DELIVERY_GH_API_MUTATION_FORBIDDEN")
        )
    if group == "status":
        return {}
    if not arguments:
        return _deny("DELIVERY_GH_COMMAND_NOT_APPROVED")
    action = arguments[0].casefold()
    if (group, action) in GH_READ_ONLY_COMMANDS:
        return {}
    if group == "pr" and action == "create":
        pr_arguments = arguments[1:]
        heads = _option_values(pr_arguments, "--head", "-H")
        bases = _option_values(pr_arguments, "--base", "-B")
        repositories = _option_values(pr_arguments, "--repo", "-R")
        if selected_repository is not None:
            repositories = (*repositories, selected_repository)
        if (
            "--draft" not in pr_arguments
            or not context.repository_writes
            or context.worktree is None
            or context.branch is None
            or cwd != context.worktree
            or len(heads) > 1
            or any(head != context.branch for head in heads)
            or len(bases) > 1
            or any(base != "main" for base in bases)
            or len(repositories) > 1
            or any(
                not repository
                or (
                    context.repository is not None
                    and repository != context.repository
                )
                for repository in repositories
            )
            or any(argument in {"--web", "--recover"} for argument in pr_arguments)
            or not _stable_descriptor_path(cwd, context.worktree, allow_missing_leaf=False)
        ):
            return _deny("DELIVERY_GH_PR_FLOW_OUTSIDE_EXACT_ADMISSION")
        return {}
    return _deny("DELIVERY_GH_COMMAND_NOT_APPROVED")


def _enforce_curl_command(tokens: tuple[str, ...]) -> dict[str, Any]:
    method = "GET"
    position = 1
    while position < len(tokens):
        argument = tokens[position]
        if argument in {"-X", "--request"}:
            if position + 1 >= len(tokens):
                return _deny("DELIVERY_CURL_MUTATION_FORBIDDEN")
            method = tokens[position + 1].upper()
            position += 2
            continue
        if argument.startswith("--request="):
            method = argument.split("=", 1)[1].upper()
        elif argument.startswith("-X") and argument != "-X":
            method = argument[2:].upper()
        if argument in {"-I", "--head"}:
            method = "HEAD"
        if (
            argument in {
                "-d",
                "--data",
                "--data-ascii",
                "--data-binary",
                "--data-raw",
                "--data-urlencode",
                "-F",
                "--form",
                "--form-string",
                "-T",
                "--upload-file",
                "--json",
                "-K",
                "--config",
                "-o",
                "--output",
                "-O",
                "--remote-name",
                "--remote-header-name",
                "--output-dir",
            }
            or argument.startswith(
                (
                    "-d",
                    "--data=",
                    "--data-ascii=",
                    "--data-binary=",
                    "--data-raw=",
                    "--data-urlencode=",
                    "-F",
                    "--form=",
                    "--form-string=",
                    "-T",
                    "--upload-file=",
                    "--json=",
                    "-K",
                    "--config=",
                    "-o",
                    "--output=",
                    "--output-dir=",
                )
            )
        ):
            return _deny("DELIVERY_CURL_MUTATION_FORBIDDEN")
        position += 1
    return (
        {}
        if method in {"GET", "HEAD"}
        else _deny("DELIVERY_CURL_MUTATION_FORBIDDEN")
    )


def _enforce_outbound_command(
    command: str, context: DeliveryContext, cwd: Path
) -> dict[str, Any] | None:
    tokens = _shell_tokens(command)
    if not tokens:
        return _deny("DELIVERY_OUTBOUND_COMMAND_UNDETERMINED")
    executable = tokens[0].rstrip("/").rsplit("/", 1)[-1].casefold()
    if executable in {"prepush_control", "prepush_control.py"}:
        if (
            Path(tokens[0]) == CANONICAL_PREPUSH_CONTROL
            and len(tokens) >= 2
            and tokens[1] == "guarded-push"
            and context.repository_writes
            and context.worktree is not None
            and cwd == context.worktree
            and _stable_descriptor_path(cwd, context.worktree, allow_missing_leaf=False)
        ):
            return {}
        return _deny("DELIVERY_PREPUSH_CONTROLLER_NOT_APPROVED")
    if executable == "gh":
        return _enforce_gh_command(tokens, context, cwd)
    if executable == "curl":
        return _enforce_curl_command(tokens)
    if executable in {
        "ssh",
        "scp",
        "sftp",
        "git-push",
        "git-send-pack",
        "git-receive-pack",
        "git-shell",
    }:
        return _deny("DELIVERY_RAW_REMOTE_MUTATION_FORBIDDEN")
    return None


def _shell_write(command: str) -> ShellWrite:
    redirection = _redirection_write(command)
    if redirection.writes:
        return redirection
    tokens = _shell_tokens(command)
    if not tokens:
        return ShellWrite(True, ambiguous=True)
    meaningful = tuple(token for token in tokens if token not in {";", "&&", "||", "|", "&"})
    if not meaningful:
        return ShellWrite()
    executable = meaningful[0].rstrip("/").rsplit("/", 1)[-1].casefold()
    if executable == "git":
        return _git_write(meaningful)
    if executable in {"touch", "truncate", "rm", "rmdir", "unlink"}:
        paths = _operands(meaningful)
        return ShellWrite(True, paths=paths, ambiguous=not paths)
    if executable == "mkdir":
        paths = _operands(meaningful)
        return ShellWrite(True, paths=paths, ambiguous=not paths, allow_parent=True)
    if executable == "tee":
        paths = _operands(meaningful)
        return ShellWrite(True, paths=paths, ambiguous=not paths)
    if executable == "cp":
        paths = _operands(meaningful)
        return ShellWrite(True, paths=paths[-1:] if len(paths) >= 2 else (), ambiguous=len(paths) < 2)
    if executable in {"install", "ln", "rsync"}:
        paths = _operands(meaningful)
        return ShellWrite(True, paths=paths[-1:] if len(paths) >= 2 else (), ambiguous=len(paths) < 2)
    if executable == "mv":
        paths = _operands(meaningful)
        return ShellWrite(True, paths=paths, ambiguous=len(paths) != 2)
    if executable in {"chmod", "chown", "chgrp"}:
        paths = _operands(meaningful)
        return ShellWrite(True, paths=paths[1:] if len(paths) > 1 else (), ambiguous=len(paths) <= 1)
    if executable in {"sed", "perl"} and FORMAT_WRITE.search(command):
        paths = tuple(token for token in meaningful[1:] if not token.startswith("-") and not token.startswith("s/"))
        return ShellWrite(True, paths=paths, ambiguous=not paths)
    if executable == "dd":
        outputs = tuple(token[3:] for token in meaningful[1:] if token.startswith("of="))
        return ShellWrite(True, paths=outputs, ambiguous=len(outputs) != 1)
    if executable in {"tar", "unzip"} and any(
        token in {"-x", "--extract"} or (token.startswith("-") and "x" in token[1:])
        for token in meaningful[1:]
    ):
        return ShellWrite(True, ambiguous=True)
    if executable == "find" and "-delete" in meaningful:
        return ShellWrite(True, ambiguous=True)
    if executable in {".", "eval", "exec", "source", "xargs"}:
        return ShellWrite(True, ambiguous=True)
    if executable in {"apply_patch", "patch"} or SCRIPT_WRITE.search(command) or FORMAT_WRITE.search(command):
        return ShellWrite(True, ambiguous=True)
    if executable in {"npm", "npx", "pnpm", "yarn", "pip", "pip3", "pytest", "ruff", "mypy", "tox", "make", "cargo", "go", "docker", "python", "python3"}:
        return ShellWrite(True, worktree_only=True)
    return ShellWrite()


def _redirection_write(command: str) -> ShellWrite:
    redirects = tuple(match.group(1) for match in REDIRECTION.finditer(command))
    return ShellWrite(bool(redirects), paths=redirects)


def _enforce_repository_write(assessment: ShellWrite, context: DeliveryContext, cwd: Path) -> dict[str, Any]:
    if not assessment.writes:
        return {}
    if not context.repository_writes or context.worktree is None:
        return _deny("DELIVERY_TARGET_HAS_NO_REPOSITORY_WRITE_AUTHORITY")
    if assessment.ambiguous:
        return _deny("DELIVERY_WRITE_PATH_UNDETERMINED")
    if assessment.worktree_only:
        if context.worktree is None:
            return _deny("DELIVERY_WORKTREE_MISMATCH")
        if not (cwd == context.worktree or context.worktree in cwd.parents):
            return _deny("DELIVERY_WORKTREE_MISMATCH")
        return (
            {}
            if _stable_descriptor_path(cwd, context.worktree, allow_missing_leaf=False)
            else _deny("DELIVERY_WORKTREE_MISMATCH")
        )
    for value in assessment.paths:
        if not _path_allowed(_path_value(value, cwd), context, allow_parent=assessment.allow_parent):
            return _deny("DELIVERY_WRITE_OUTSIDE_EXACT_LEASE")
    return {}


def _mask_js_noncode(source: str) -> str:
    characters = list(source)
    index = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    while index < len(source):
        character = source[index]
        next_character = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
            else:
                characters[index] = " "
            index += 1
            continue
        if block_comment:
            characters[index] = " "
            if character == "*" and next_character == "/":
                characters[index + 1] = " "
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            characters[index] = " "
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character == "/" and next_character == "/":
            characters[index] = characters[index + 1] = " "
            line_comment = True
            index += 2
            continue
        if character == "/" and next_character == "*":
            characters[index] = characters[index + 1] = " "
            block_comment = True
            index += 2
            continue
        if character in {'"', "'", "`"}:
            characters[index] = " "
            quote = character
        index += 1
    if quote is not None or block_comment:
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    return "".join(characters)


def _matching_js_parenthesis(masked_source: str, opening: int) -> int:
    depth = 0
    index = opening
    while index < len(masked_source):
        character = masked_source[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
        index += 1
    raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")


def _direct_nested_calls(source: str) -> tuple[tuple[str, str], ...]:
    masked = _mask_js_noncode(source)
    calls: list[tuple[str, str]] = []
    for reference in TOOLS_REFERENCE.finditer(masked):
        prefix = masked[:reference.start()].rstrip()
        if prefix and prefix[-1] in {".", "]"}:
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        index = reference.end()
        while index < len(masked) and masked[index].isspace():
            index += 1
        if index >= len(masked) or masked[index] != ".":
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        index += 1
        name_match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", masked[index:])
        if name_match is None:
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        name = name_match.group(0)
        index += len(name)
        while index < len(masked) and masked[index].isspace():
            index += 1
        if index >= len(masked) or masked[index] != "(":
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        closing = _matching_js_parenthesis(masked, index)
        calls.append((name, source[index + 1:closing]))
    return tuple(calls)


def _js_literal(value: str) -> str:
    value = value.strip()
    if len(value) < 2 or value[0] not in {'"', "'", "`"} or value[-1] != value[0]:
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    if value[0] == '"':
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED") from exc
    elif value[0] == "'":
        try:
            decoded = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED") from exc
    else:
        if "${" in value or "\\`" in value:
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        decoded = value[1:-1]
    if not isinstance(decoded, str):
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    return decoded


def _js_object_literal_property(argument: str, name: str, *, required: bool) -> str | None:
    stripped = argument.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    masked = _mask_js_noncode(stripped)
    matches = tuple(re.finditer(rf"\b{re.escape(name)}\s*:", masked))
    if not matches:
        if required:
            raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        return None
    if len(matches) != 1:
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    start = matches[0].end()
    while start < len(stripped) and stripped[start].isspace():
        start += 1
    if start >= len(stripped) or stripped[start] not in {'"', "'", "`"}:
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    quote = stripped[start]
    escaped = False
    end = start + 1
    while end < len(stripped):
        character = stripped[end]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == quote:
            break
        end += 1
    if end >= len(stripped):
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    trailing = stripped[end + 1:].lstrip()
    if not trailing or trailing[0] not in {",", "}"}:
        raise GuardError("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    return _js_literal(stripped[start:end + 1])


def _wrapper_child(tokens: tuple[str, ...], executable: str) -> tuple[str, bool] | None:
    if executable in SHELL_WRAPPERS:
        command_index: int | None = None
        for index, token in enumerate(tokens[1:], start=1):
            if token == "--":
                continue
            if token.startswith("-") and "c" in token[1:]:
                command_index = index + 1
                break
            if not token.startswith("-"):
                return None
        if command_index is None or command_index >= len(tokens):
            return None
        if command_index + 1 < len(tokens):
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        return tokens[command_index], False
    if executable == "timeout":
        index = 1
        while index < len(tokens) and tokens[index].startswith("-"):
            option = tokens[index]
            index += 1
            if option in {"-k", "--kill-after", "-s", "--signal"}:
                index += 1
            elif option == "--":
                break
        if index + 1 >= len(tokens):
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        seconds = _duration_seconds(tokens[index])
        if seconds is None:
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        return shlex.join(tokens[index + 1:]), seconds <= MAX_PASSIVE_WAIT_SECONDS
    if executable in PREFIX_WRAPPERS:
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if executable == "env" and "=" in token and not token.startswith("="):
                index += 1
                continue
            if token == "--":
                index += 1
                break
            if token.startswith("-"):
                index += 1
                if token in {"-C", "-D", "-g", "-h", "-n", "-o", "-p", "-r", "-t", "-u"}:
                    index += 1
                continue
            break
        if index >= len(tokens):
            return None
        return shlex.join(tokens[index:]), False
    return None


def _command_leaves(command: str, *, bounded_wait: bool = False, depth: int = 0) -> tuple[CommandLeaf, ...]:
    if depth > 12:
        raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
    segments = _command_segments(command)
    if segments is None:
        raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
    leaves: list[CommandLeaf] = []
    segment_executables: list[str] = []
    for segment in segments:
        segment_tokens = _shell_tokens(segment)
        if segment_tokens:
            segment_executables.append(
                segment_tokens[0].rstrip("/").rsplit("/", 1)[-1].casefold()
            )
    if len(segments) > 1 and any(
        executable in {"cd", "popd", "pushd"} or executable.startswith("(")
        for executable in segment_executables
    ):
        raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
    for segment in segments:
        if ("$(" in segment or "`" in segment) and not _is_single_read_only_search(segment):
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        tokens = _shell_tokens(segment)
        if not tokens:
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        assignment_count = 0
        while assignment_count < len(tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[assignment_count]
        ):
            assignment_count += 1
        if assignment_count:
            if assignment_count == len(tokens):
                leaves.append(CommandLeaf(segment, bounded_wait))
                continue
            leaves.extend(
                _command_leaves(
                    shlex.join(tokens[assignment_count:]),
                    bounded_wait=bounded_wait,
                    depth=depth + 1,
                )
            )
            continue
        while tokens and tokens[0].casefold() in {"do", "else", "then"}:
            tokens = tokens[1:]
        if not tokens or tokens[0].casefold() in {"done", "fi", "esac"}:
            continue
        executable = tokens[0].rstrip("/").rsplit("/", 1)[-1].casefold()
        if len(segments) > 1 and executable in {"cd", "popd", "pushd"}:
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        if executable in {"case", "coproc", "function", "select"} or any(
            character in executable for character in ("$", "`", "\\", "(", ")", "{", "}")
        ):
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        child = _wrapper_child(tokens, executable)
        if child is not None:
            child_command, child_bounded = child
            leaves.extend(
                _command_leaves(
                    child_command,
                    bounded_wait=bounded_wait or child_bounded,
                    depth=depth + 1,
                )
            )
            continue
        if executable in SHELL_WRAPPERS:
            if any(token in {"-n", "--noprofile", "--norc"} for token in tokens[1:]) and "-n" in tokens[1:]:
                leaves.append(CommandLeaf(segment, bounded_wait))
                continue
            raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        if executable in INTERPRETER_WRAPPERS:
            code_flag = "-c" if executable in {"python", "python3"} else "-e"
            if code_flag in tokens:
                index = tokens.index(code_flag)
                if index + 1 >= len(tokens) or index + 2 != len(tokens):
                    raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
                leaves.append(CommandLeaf(tokens[index + 1], bounded_wait, executable))
                continue
            if executable in {"python", "python3"} and len(tokens) >= 3 and tokens[1] == "-m" and tokens[2] in {"pytest", "unittest"}:
                leaves.append(CommandLeaf(segment, bounded_wait))
                continue
            if (
                len(tokens) >= 3
                and tokens[1] == str(CANONICAL_PREPUSH_CONTROL)
                and tokens[2] == "guarded-push"
            ):
                leaves.append(CommandLeaf(segment, bounded_wait))
                continue
            if len(tokens) > 1 and not all(token.startswith("-") for token in tokens[1:]):
                raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
        leaves.append(CommandLeaf(segment, bounded_wait))
    return tuple(leaves)


def _python_interpreter_write(source: str) -> ShellWrite:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise GuardError("DELIVERY_WRAPPED_COMMAND_UNDETERMINED") from exc
    paths: list[str] = []
    writes = False
    ambiguous = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_writes = False
        function = node.func
        function_name = function.id if isinstance(function, ast.Name) else function.attr if isinstance(function, ast.Attribute) else ""
        path_nodes: list[ast.AST] = []
        if function_name == "open":
            mode_node = node.args[1] if len(node.args) > 1 else next((keyword.value for keyword in node.keywords if keyword.arg == "mode"), None)
            mode = mode_node.value if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str) else "r"
            if any(flag in mode for flag in "wax+"):
                writes = call_writes = True
                if node.args:
                    path_nodes.append(node.args[0])
        elif function_name in {"write_text", "write_bytes", "unlink", "mkdir", "touch", "chmod", "rename", "replace"}:
            writes = call_writes = True
            if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Call) and function.value.args:
                path_nodes.append(function.value.args[0])
            if function_name in {"rename", "replace"} and node.args:
                path_nodes.append(node.args[0])
        elif function_name in {"remove", "unlink", "rename", "replace", "mkdir", "makedirs", "chmod", "chown", "copy", "copy2", "copyfile", "move", "rmtree"} and isinstance(function, ast.Attribute):
            writes = call_writes = True
            path_nodes.extend(node.args[:2] if function_name in {"rename", "replace", "copy", "copy2", "copyfile", "move"} else node.args[:1])
        if call_writes:
            if not path_nodes:
                ambiguous = True
            for path_node in path_nodes:
                if isinstance(path_node, ast.Constant) and isinstance(path_node.value, str):
                    paths.append(path_node.value)
                else:
                    ambiguous = True
    return ShellWrite(writes, tuple(paths), ambiguous=ambiguous or (writes and not paths))


def _enforce_command(command: str, context: DeliveryContext, cwd: Path) -> dict[str, Any]:
    if GIT_METADATA_ENV.search(command):
        return _deny("DELIVERY_GIT_METADATA_OUTSIDE_EXACT_ADMISSION")
    if GIT_EXTERNAL_HELPER_ENV.search(command):
        return _deny("DELIVERY_GIT_EXTERNAL_HELPER_FORBIDDEN")
    if _contains_raw_push(command):
        return _deny("RAW_GIT_PUSH_FORBIDDEN_USE_SQLITE_EXACT_HEAD_GUARDED_PUSH")
    if _contains_open_ended_wait(command):
        return _deny("OPEN_ENDED_WAIT_FORBIDDEN_USE_SESSION_WAIT_OR_MAX_60S_POLL")
    try:
        leaves = _command_leaves(command)
    except GuardError:
        return _deny("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
    for leaf in leaves:
        if GIT_EXTERNAL_HELPER_ENV.search(leaf.command):
            return _deny("DELIVERY_GIT_EXTERNAL_HELPER_FORBIDDEN")
        if _contains_raw_push(leaf.command):
            return _deny("RAW_GIT_PUSH_FORBIDDEN_USE_SQLITE_EXACT_HEAD_GUARDED_PUSH")
        if _contains_open_ended_wait(leaf.command) and not leaf.bounded_wait:
            return _deny("OPEN_ENDED_WAIT_FORBIDDEN_USE_SESSION_WAIT_OR_MAX_60S_POLL")
        redirection_decision = _enforce_repository_write(
            _redirection_write(leaf.command), context, cwd
        )
        if redirection_decision:
            return redirection_decision
        outbound_decision = _enforce_outbound_command(leaf.command, context, cwd)
        if outbound_decision is not None:
            if outbound_decision:
                return outbound_decision
            continue
        worktree_decision = _enforce_exact_worktree_command(
            leaf.command, context, cwd
        )
        if worktree_decision is not None:
            if worktree_decision:
                return worktree_decision
            continue
        if _provider_command(leaf.command):
            if context.role == "development":
                return _deny("DEVELOPMENT_HOSTED_PROVIDER_OPERATION_FORBIDDEN")
            if context.target_kind != "hosted_operation":
                return _deny("HOSTED_PROVIDER_TARGET_REQUIRED")
        if leaf.interpreter is not None:
            if PROVIDER_TOOL.search(leaf.command):
                if context.role == "development":
                    return _deny("DEVELOPMENT_HOSTED_PROVIDER_OPERATION_FORBIDDEN")
                if context.target_kind != "hosted_operation":
                    return _deny("HOSTED_PROVIDER_TARGET_REQUIRED")
            if PROCESS_EXECUTION.search(leaf.command):
                return _deny("DELIVERY_WRAPPED_COMMAND_UNDETERMINED")
            assessment = (
                _python_interpreter_write(leaf.command)
                if leaf.interpreter in {"python", "python3"}
                else ShellWrite(
                    bool(SCRIPT_WRITE.search(leaf.command) or INTERPRETER_WRITE.search(leaf.command)),
                    ambiguous=True,
                )
            )
        else:
            assessment = _shell_write(leaf.command)
        decision = _enforce_repository_write(assessment, context, cwd)
        if decision:
            return decision
    return {}


def _enforce_nested_tools(
    source: str,
    context: DeliveryContext,
    cwd: Path,
) -> dict[str, Any]:
    try:
        calls = _direct_nested_calls(source)
    except GuardError:
        return _deny("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    if not calls:
        return _deny("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
    for name, argument in calls:
        if name == "apply_patch":
            try:
                patch = _js_literal(argument)
            except GuardError:
                return _deny("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
            paths = tuple([*PATCH_PATH.findall(patch), *PATCH_MOVE_PATH.findall(patch)])
            if not paths:
                return _deny("DELIVERY_WRITE_PATH_UNDETERMINED")
            decision = _enforce_repository_write(ShellWrite(True, paths=paths), context, cwd)
            if decision:
                return decision
            continue
        if name == "exec_command":
            try:
                command = _js_object_literal_property(argument, "cmd", required=True)
                workdir = _js_object_literal_property(argument, "workdir", required=False)
                nested_cwd = cwd if workdir is None else _path_value(workdir, cwd)
            except GuardError:
                return _deny("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
            decision = _enforce_command(command or "", context, nested_cwd)
            if decision:
                return decision
            continue
        if name == "write_stdin":
            if not argument.strip().startswith("{") or not argument.strip().endswith("}"):
                return _deny("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
            continue
        provider = bool(PROVIDER_TOOL.search(name))
        if provider and context.role == "development":
            return _deny("DEVELOPMENT_HOSTED_PROVIDER_OPERATION_FORBIDDEN")
        if provider and context.target_kind != "hosted_operation":
            return _deny("HOSTED_PROVIDER_TARGET_REQUIRED")
        if MUTATING_NESTED_TOOL.search(name) or not READ_ONLY_NESTED_TOOL.search(name):
            return _deny("DELIVERY_NESTED_MUTATION_TOOL_FORBIDDEN")
    return {}


def pre_tool(event: dict[str, Any], *, environ: Mapping[str, str] | None = None, database_path: Path = DEFAULT_DATABASE, worktree_root: Path = DEFAULT_WORKTREE_ROOT) -> dict[str, Any]:
    tool, tool_input = event.get("tool_name"), event.get("tool_input")
    if not isinstance(tool, str) or not isinstance(tool_input, dict):
        return _deny("DELIVERY_HOOK_EVENT_INVALID")
    try:
        context = _load_context(environ or os.environ, database_path, worktree_root)
        cwd = _cwd(event, tool_input)
        source = tool_input.get("source")
        if not isinstance(source, str):
            source = tool_input.get("input")
        if isinstance(source, str) and (
            "${" in source
            or re.search(
                r"(?:\b(?:eval|Function|globalThis|Proxy|Reflect)\b|\.constructor\b|\bthis\s*\[)",
                source,
            )
        ):
            return _deny("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        if isinstance(source, str):
            try:
                nested_source = bool(TOOLS_REFERENCE.search(_mask_js_noncode(source)))
            except GuardError:
                return _deny("DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED")
        else:
            nested_source = False
        if nested_source:
            decision = _enforce_nested_tools(source, context, cwd)
            if decision:
                return decision
        commands = () if nested_source else tuple(_commands(tool_input)) if SHELL_TOOL.search(tool) else ()
        provider_operation = bool(PROVIDER_TOOL.search(tool))
        if provider_operation and context.role == "development":
            return _deny("DEVELOPMENT_HOSTED_PROVIDER_OPERATION_FORBIDDEN")
        if provider_operation and context.target_kind != "hosted_operation":
            return _deny("HOSTED_PROVIDER_TARGET_REQUIRED")
        if FILESYSTEM_WRITE_TOOL.search(tool):
            paths = _file_tool_paths(tool_input)
            if not paths:
                return _deny("DELIVERY_WRITE_PATH_UNDETERMINED")
            return _enforce_repository_write(ShellWrite(True, paths=paths), context, cwd)
        for command in commands:
            decision = _enforce_command(command, context, cwd)
            if decision:
                return decision
        return {}
    except (GuardError, OSError, sqlite3.Error, TypeError, ValueError):
        return _deny("DELIVERY_CONTEXT_INVALID")


def main() -> int:
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError
        output = pre_tool(event) if event.get("hook_event_name") == "PreToolUse" else {}
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (json.JSONDecodeError, ValueError):
        print(json.dumps(_deny("DELIVERY_HOOK_EVENT_INVALID"), separators=(",", ":")))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
