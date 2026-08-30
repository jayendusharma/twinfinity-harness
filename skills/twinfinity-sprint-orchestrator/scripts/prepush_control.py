#!/usr/bin/env python3
"""Exact-head local-gate receipts and push eligibility for Twinfinity lanes."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Sequence

from coordination_store import (
    DEFAULT_DATABASE,
    CoordinationError,
    CoordinationStore,
    canonical_json,
    digest_json,
    parse_structured_lease_manifest,
    utc_now,
)
from delivery_identity import immutable_admission_error
from coordination_transfer_ledger import (
    intent_sha256 as transfer_intent_sha256,
    load_record as load_transfer_record,
    validate_comments as validate_transfer_comments,
    validate_existing_state as validate_transfer_state,
)
from executor_registry import RegistryError, applied_endpoint_rotation_chain, identity_role
from repository_delivery_policy import (
    HARNESS_REPOSITORY,
    delivery_branch_issue_number,
    expected_worktree_identity,
    expected_worktree_parent,
    harness_standing_authority_error,
    harness_standing_authority_provenance_error,
    policy_for_repository,
    worktree_identity_matches,
)
from admission_source_equivalence import admission_lineage_source_is_current
from run_harness_baseline_validations import (
    BaselineCatalog,
    BaselineError,
    PAIR_RECEIPT_SCHEMA,
    REQUIRED_SELF_TRIGGERS,
    catalog_command,
    catalog_matches_path,
    load_catalog,
    verify_pair_receipt,
)


GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
ACTIVE_STATUSES = {"ACTIVE", "ACTIVE_FENCED"}
REQUIRED_NODE_MAJOR = 20
CANONICAL_REMOTE = "origin"
ADMISSION_TOPICS = {
    "development.admission",
    "development.recovery_commit",
    "sre.admission",
}
GITHUB_HTTPS_REMOTE = re.compile(
    r"^https://github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
)
GITHUB_SCP_REMOTE = re.compile(
    r"^git@github\.com:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
)
GITHUB_SSH_REMOTE = re.compile(
    r"^ssh://git@github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
)
ISSUE_OWNED_PATH = re.compile(
    r"(?:twinfinityapp-issue-|twinfinity-issue)(?P<issue>[1-9][0-9]*)(?:[^0-9]|$)"
)
GATE_ENVIRONMENT_KEYS = {
    "PATH",
    "VIRTUAL_ENV",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONPYCACHEPREFIX",
    "NODE_PATH",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "npm_config_cache",
    "npm_config_prefix",
    "NPM_CONFIG_CACHE",
    "NPM_CONFIG_PREFIX",
}
SHELL_INJECTION_ENVIRONMENT_KEYS = {
    "BASH_ENV",
    "BASHOPTS",
    "CDPATH",
    "ENV",
    "SHELLOPTS",
}
PREPUSH_BASELINE_BINDING_SCHEMA = "twinfinity-prepush-baseline-binding/v1"
class PrePushError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExistingEnvironment:
    root: str
    rebuild_artifact_key: str
    rebuild_artifact_content_sha256: str
    freeze_sha256: str
    package_count: int
    gate_environment_provenance_sha256: str


@dataclass(frozen=True)
class Lineage:
    repository: str
    issue_number: int
    surface_issue_number: int
    generation: int
    session_id: str
    source_payload_sha256: str
    lease_manifest_sha256: str
    admission_message_id: int
    admission_payload_sha256: str
    branch: str
    worktree_path: str
    base_sha: str
    item_version: int
    allocation_class: str
    development_units: int
    shared_units: int
    sre_units: int
    admission_topic: str
    environment_root: str | None = None
    existing_environment: ExistingEnvironment | None = None


@dataclass(frozen=True)
class LeaseManifest:
    content_sha256: str
    changed_paths_sha256: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class GatePlan:
    """Closed, repository-derived local validation plan."""

    profile: str
    lower_commands: tuple[tuple[str, str, tuple[str, ...]], ...]
    final_name: str
    final_cwd: str
    final_argv: tuple[str, ...]
    final_receipt: str
    final_failure: str
    metadata: dict[str, Any]


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class PrePushControl:
    """A separate policy module over the shared ACID coordination database."""

    def __init__(self, database: Path = DEFAULT_DATABASE) -> None:
        self.store = CoordinationStore(database)
        self.connection = self.store.connection

    def close(self) -> None:
        self.store.close()

    def _lineage(self, repository: str, issue_number: int) -> Lineage:
        item = self.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=?",
            (repository, issue_number),
        ).fetchone()
        if (
            item is None
            or item["status"] not in ACTIVE_STATUSES
            or item["allocation_class"] != "ACTIVE"
        ):
            raise PrePushError("PREPUSH_ITEM_NOT_ACTIVE")
        if not item["accountable_session_id"] or not item["lease_manifest_sha256"]:
            raise PrePushError("PREPUSH_ITEM_LINEAGE_INCOMPLETE")
        current = self.connection.execute(
            """
            SELECT payload_sha256 FROM github_current
            WHERE repository=? AND object_kind='issue' AND object_number=?
            """,
            (repository, issue_number),
        ).fetchone()
        if current is None:
            raise PrePushError("PREPUSH_SOURCE_DRIFT")

        watch = self.connection.execute(
            "SELECT * FROM coordination_terminal_watches "
            "WHERE repository=? AND issue_number=? AND generation=?",
            (repository, issue_number, item["generation"]),
        ).fetchone()
        admission = (
            None
            if watch is None
            else self.connection.execute(
                "SELECT * FROM coordination_messages WHERE id=?",
                (watch["admission_message_id"],),
            ).fetchone()
        )
        try:
            admission_payload = (
                None
                if admission is None
                else json.loads(admission["payload_json"])
            )
        except (TypeError, json.JSONDecodeError):
            admission_payload = None
        if admission is not None and isinstance(admission_payload, dict):
            if digest_json(admission_payload) != admission["payload_sha256"]:
                raise PrePushError("PREPUSH_ADMISSION_INVALID")
            standing_error = harness_standing_authority_error(admission_payload)
            if standing_error is not None:
                raise PrePushError(standing_error)
            provenance_error = harness_standing_authority_provenance_error(
                self.connection, admission_payload
            )
            if provenance_error is not None:
                raise PrePushError(provenance_error)
            capacity = admission_payload.get("capacity")
            payload_item_version = admission_payload.get("item_version")
            historical_before_version = (
                payload_item_version + 1
                if isinstance(payload_item_version, int)
                and admission["topic"] == "development.recovery_commit"
                else payload_item_version
            )
            exact_version = historical_before_version == int(item["version"])
            claim_attempt = (
                None
                if watch is None
                else self.connection.execute(
                    "SELECT * FROM executor_attempts WHERE attempt_id=?",
                    (watch["claim_attempt_id"],),
                ).fetchone()
            )
            rotation_chain = None
            if (
                isinstance(historical_before_version, int)
                and admission["topic"]
                in {"development.admission", "sre.admission"}
                and watch is not None
            ):
                try:
                    rotation_chain = applied_endpoint_rotation_chain(
                        self.connection,
                        repository=repository,
                        issue_number=issue_number,
                        before_identity=str(admission["recipient_session_id"]),
                        before_item_version=historical_before_version,
                        after_identity=str(item["accountable_session_id"]),
                        after_item_version=int(item["version"]),
                        watch_key=str(watch["watch_key"]),
                        expected_watch_state="ACTIVE",
                        not_before=(
                            str(claim_attempt["created_at"])
                            if claim_attempt is not None
                            else str(admission["created_at"])
                        ),
                    )
                except RegistryError as exc:
                    raise PrePushError("PREPUSH_ADMISSION_INVALID") from exc
            rotated_version = rotation_chain is not None
            exact_route = bool(
                admission["recipient_session_id"]
                == item["accountable_session_id"]
                and exact_version
            )
            try:
                admission_role = identity_role(
                    self.connection, str(admission["recipient_session_id"])
                )
                item_role = identity_role(
                    self.connection, str(item["accountable_session_id"])
                )
            except RegistryError as exc:
                raise PrePushError("PREPUSH_ADMISSION_INVALID") from exc
            rotated_route = bool(
                rotated_version
                and admission["state"] == "CLAIMED"
                and claim_attempt is not None
                and claim_attempt["role"] == admission_role
                and claim_attempt["endpoint_id"]
                == admission["recipient_session_id"]
                and claim_attempt["state"] in {"COMPLETE", "HOLD"}
                and claim_attempt["target_kind"] == "message"
                and claim_attempt["target_key"] == str(admission["id"])
                and claim_attempt["lineage_repository"] == repository
                and int(claim_attempt["lineage_issue_number"] or -1)
                == issue_number
                and int(
                    claim_attempt["lineage_generation"]
                    if claim_attempt["lineage_generation"] is not None
                    else -1
                )
                == int(item["generation"])
                and claim_attempt["lineage_lease_sha256"]
                == item["lease_manifest_sha256"]
            )
            source_current = bool(
                watch is not None
                and admission_lineage_source_is_current(
                    self.connection, item=item, message=admission, watch=watch,
                    current_source_sha256=str(current["payload_sha256"]),
                )
            )
            if not source_current:
                raise PrePushError("PREPUSH_SOURCE_DRIFT")
            valid = bool(
                admission["topic"] in ADMISSION_TOPICS
                and admission["state"] in {"CLAIMED", "COMPLETE"}
                and admission["claimed_by"] == admission["recipient_session_id"]
                and admission_role == item_role
                and digest_json(admission_payload) == admission["payload_sha256"]
                and admission_payload.get("issue_number") == issue_number
                and admission_payload.get("generation") == int(item["generation"])
                and admission_payload.get("accountable_session_id")
                == admission["recipient_session_id"]
                and admission_payload.get("lease_manifest_sha256")
                == item["lease_manifest_sha256"]
                and admission_payload.get("source", {}).get("payload_sha256")
                == item["source_payload_sha256"]
                and (exact_route or rotated_route)
                and isinstance(capacity, dict)
                and capacity.get("development_units")
                == int(item["development_units"])
                and capacity.get("shared_units") == int(item["shared_units"])
                and capacity.get("sre_units") == int(item["sre_units"])
                and watch is not None
                and watch["state"] == "ACTIVE"
                and watch["accountable_session_id"]
                == item["accountable_session_id"]
                and watch["lease_manifest_sha256"]
                == item["lease_manifest_sha256"]
                and int(watch["admission_message_id"] or 0) == int(admission["id"])
                and watch["admission_payload_sha256"]
                == admission["payload_sha256"]
                and source_current
            )
            if not valid:
                admission = None
                admission_payload = None
        if admission is None or admission_payload is None:
            raise PrePushError("PREPUSH_COMPLETED_ADMISSION_ABSENT")
        if (
            admission["topic"] in {"development.admission", "sre.admission"}
            and immutable_admission_error(
                self.connection,
                message=admission,
                payload=admission_payload,
            )
            is not None
        ):
            raise PrePushError("PREPUSH_ADMISSION_INVALID")
        branch = admission_payload.get("branch")
        worktree_path = admission_payload.get("worktree_path")
        opaque_worktree_id = admission_payload.get("opaque_worktree_id")
        base_sha = admission_payload.get("base_sha")
        surface_issue_number = delivery_branch_issue_number(repository, branch)
        expected_parent = expected_worktree_parent(
            repository, Path("/home/ubuntu/code")
        )
        if (
            surface_issue_number is None
            or expected_parent is None
            or not isinstance(worktree_path, str)
            or not Path(worktree_path).is_absolute()
            or Path(worktree_path).parent != expected_parent
            or not isinstance(base_sha, str)
            or not GIT_SHA.fullmatch(base_sha)
        ):
            raise PrePushError("PREPUSH_ADMISSION_INVALID")
        expected_surface_id = expected_worktree_identity(
            repository, surface_issue_number
        )
        if expected_surface_id is None:
            raise PrePushError("PREPUSH_ADMISSION_INVALID")
        if (
            repository == HARNESS_REPOSITORY
            and surface_issue_number != issue_number
        ):
            raise PrePushError("PREPUSH_ADMISSION_INVALID")
        environment_root = admission_payload.get("environment_root")
        existing_environment_payload = admission_payload.get("existing_environment")
        existing_environment: ExistingEnvironment | None = None
        if existing_environment_payload is not None:
            required_environment_fields = {
                "root",
                "rebuild_artifact_key",
                "rebuild_artifact_content_sha256",
                "freeze_sha256",
                "package_count",
                "gate_environment_provenance_sha256",
            }
            if (
                not isinstance(existing_environment_payload, dict)
                or not required_environment_fields.issubset(
                    existing_environment_payload
                )
                or set(existing_environment_payload) != required_environment_fields
                or environment_root is not None
            ):
                raise PrePushError("PREPUSH_ADMISSION_ENVIRONMENT_INVALID")
            try:
                existing_environment = ExistingEnvironment(
                    **existing_environment_payload
                )
            except TypeError as exc:
                raise PrePushError(
                    "PREPUSH_ADMISSION_ENVIRONMENT_INVALID"
                ) from exc
            environment_root = existing_environment.root
        if environment_root is not None and (
            not isinstance(environment_root, str)
            or not Path(environment_root).is_absolute()
        ):
            raise PrePushError("PREPUSH_ADMISSION_ENVIRONMENT_INVALID")
        if environment_root is not None:
            environment_path = Path(environment_root)
            worktree_path_object = Path(worktree_path)
            tagged_for_lane = any(
                int(match.group("issue")) == surface_issue_number
                for match in ISSUE_OWNED_PATH.finditer(environment_root)
            )
            within_worktree = (
                environment_path == worktree_path_object
                or worktree_path_object in environment_path.parents
            )
            if not tagged_for_lane and not within_worktree:
                raise PrePushError("PREPUSH_ADMISSION_ENVIRONMENT_INVALID")
        valid_worktree_identity = worktree_identity_matches(
            repository,
            surface_issue_number=surface_issue_number,
            owning_issue_number=issue_number,
            generation=int(item["generation"]),
            worktree_path=worktree_path,
            opaque_worktree_id=opaque_worktree_id,
        )
        if surface_issue_number != issue_number:
            parent_issue_number = admission_payload.get("parent_issue_number")
            transfer_key = admission_payload.get("transfer_key")
            transfer_comment_ids = admission_payload.get("transfer_comment_ids")
            try:
                transfer_record, _transfer_record_sha256 = load_transfer_record(
                    self.store, transfer_key
                )
                validate_transfer_state(self.store, transfer_record)
                validate_transfer_comments(transfer_record)
            except CoordinationError as exc:
                raise PrePushError(str(exc)) from exc
            if (
                type(parent_issue_number) is not int
                or parent_issue_number != surface_issue_number
                or Path(worktree_path).name != expected_surface_id
                or opaque_worktree_id != expected_surface_id
                or transfer_record["repository"] != repository
                or transfer_record["predecessor_issue_number"] != surface_issue_number
                or transfer_record["successor_issue_number"] != issue_number
                or transfer_record["branch"] != branch
                or transfer_record["worktree_path"] != worktree_path
                or transfer_record["opaque_worktree_id"] != opaque_worktree_id
                or transfer_comment_ids
                != [
                    transfer_record["predecessor_comment_id"],
                    transfer_record["successor_comment_id"],
                ]
                or admission_payload.get("transfer_comment_body_sha256")
                != [
                    transfer_record["predecessor_comment_body_sha256"],
                    transfer_record["successor_comment_body_sha256"],
                ]
                or admission_payload.get("transfer_authority_sha256")
                != transfer_record["transfer_authority_sha256"]
                or admission_payload.get("transfer_intent_sha256")
                != transfer_intent_sha256(transfer_record)
                or "transfer_ledger_sha256" in admission_payload
                or transfer_record["successor_admission_message_id"]
                != int(admission["id"])
                or transfer_record["successor_admission_payload_sha256"]
                != admission["payload_sha256"]
            ):
                raise PrePushError("PREPUSH_TRANSFER_INVALID")
        elif (
            not valid_worktree_identity
            or any(
                key in admission_payload
                for key in (
                    "parent_issue_number",
                    "transfer_key",
                    "transfer_comment_ids",
                    "transfer_comment_body_sha256",
                    "transfer_authority_sha256",
                    "transfer_intent_sha256",
                    "transfer_ledger_sha256",
                )
            )
        ):
            raise PrePushError("PREPUSH_ADMISSION_INVALID")
        return Lineage(
            repository=repository,
            issue_number=issue_number,
            surface_issue_number=surface_issue_number,
            generation=int(item["generation"]),
            session_id=item["accountable_session_id"],
            source_payload_sha256=item["source_payload_sha256"],
            lease_manifest_sha256=item["lease_manifest_sha256"],
            admission_message_id=int(admission["id"]),
            admission_payload_sha256=admission["payload_sha256"],
            branch=branch,
            worktree_path=worktree_path,
            base_sha=base_sha,
            item_version=int(item["version"]),
            allocation_class=item["allocation_class"],
            development_units=int(item["development_units"]),
            shared_units=int(item["shared_units"]),
            sre_units=int(item["sre_units"]),
            admission_topic=admission["topic"],
            environment_root=environment_root,
            existing_environment=existing_environment,
        )

    @staticmethod
    def _git(worktree: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(worktree), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise PrePushError("PREPUSH_GIT_READ_FAILED")
        return result.stdout.strip()

    @staticmethod
    def _git_optional(worktree: Path, *args: str) -> tuple[int, str]:
        result = subprocess.run(
            ["git", "-C", str(worktree), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        return result.returncode, result.stdout.strip()

    @staticmethod
    def _git_bytes(worktree: Path, *args: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(worktree), *args],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise PrePushError("PREPUSH_GIT_READ_FAILED")
        return result.stdout

    @staticmethod
    def _safe_relative_path(value: Any) -> str:
        if not isinstance(value, str) or not value or "\\" in value:
            raise PrePushError("PREPUSH_MANIFEST_INVALID")
        path = Path(value)
        canonical = path.as_posix()
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or value != canonical
        ):
            raise PrePushError("PREPUSH_MANIFEST_INVALID")
        return canonical

    def _validate_manifest_file(
        self,
        lineage: Lineage,
        worktree: Path,
        head_sha: str,
        manifest_path: Path,
    ) -> LeaseManifest:
        try:
            root = self.store.path.parent.resolve(strict=True)
            resolved = manifest_path.resolve(strict=True)
            metadata = os.lstat(resolved)
        except (FileNotFoundError, OSError):
            raise PrePushError("PREPUSH_MANIFEST_UNSAFE") from None
        if (
            resolved.parent != root
            and root not in resolved.parents
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise PrePushError("PREPUSH_MANIFEST_UNSAFE")
        raw = resolved.read_bytes()
        content_sha256 = hashlib.sha256(raw).hexdigest()
        if content_sha256 != lineage.lease_manifest_sha256:
            raise PrePushError("PREPUSH_MANIFEST_DIGEST_MISMATCH")

        entries: list[dict[str, Any]]
        try:
            manifest = parse_structured_lease_manifest(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            try:
                text_manifest = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise PrePushError("PREPUSH_MANIFEST_INVALID") from None
            if not raw.endswith(b"\n") or b"\r" in raw:
                raise PrePushError("PREPUSH_MANIFEST_INVALID")
            lines = text_manifest.removesuffix("\n").split("\n")
            if not lines or any(not line or line.count("\t") != 1 for line in lines):
                raise PrePushError("PREPUSH_MANIFEST_INVALID")
            entries = []
            for line in lines:
                path_value, blob_value = line.split("\t")
                path = self._safe_relative_path(path_value)
                if blob_value != "NEW" and not GIT_SHA.fullmatch(blob_value):
                    raise PrePushError("PREPUSH_MANIFEST_INVALID")
                entries.append(
                    {
                        "path": path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": None if blob_value == "NEW" else blob_value,
                    }
                )
            legacy_paths = [entry["path"] for entry in entries]
            if legacy_paths != sorted(legacy_paths) or len(set(legacy_paths)) != len(
                legacy_paths
            ):
                raise PrePushError("PREPUSH_MANIFEST_INVALID")
        except CoordinationError as exc:
            raise PrePushError("PREPUSH_MANIFEST_INVALID") from exc
        else:
            if (
                not isinstance(manifest["repository"], str)
                or type(manifest["issue_number"]) is not int
                or type(manifest["generation"]) is not int
                or not isinstance(manifest["base_sha"], str)
                or not isinstance(manifest["branch"], str)
                or not isinstance(manifest["worktree_path"], str)
                or type(manifest["no_additional_paths"]) is not bool
                or manifest["repository"] != lineage.repository
                or manifest["issue_number"] != lineage.issue_number
                or manifest["generation"] != lineage.generation
                or manifest["base_sha"] != lineage.base_sha
                or manifest["branch"] != lineage.branch
                or manifest["worktree_path"] != lineage.worktree_path
                or manifest["no_additional_paths"] is not True
                or not isinstance(manifest["paths"], list)
                or not manifest["paths"]
            ):
                raise PrePushError("PREPUSH_MANIFEST_LINEAGE_MISMATCH")
            if set(manifest) == {
                "repository",
                "issue_number",
                "generation",
                "base_sha",
                "branch",
                "worktree_path",
                "no_additional_paths",
                "paths",
            }:
                entries = manifest["paths"]
            else:
                if (
                    not GIT_SHA.fullmatch(str(manifest["base_tree"]))
                    or self._git(worktree, "rev-parse", f"{lineage.base_sha}^{{tree}}")
                    != manifest["base_tree"]
                ):
                    raise PrePushError("PREPUSH_MANIFEST_BASE_DRIFT")
                capacity = manifest["capacity"]
                if (
                    not isinstance(capacity, dict)
                    or set(capacity)
                    != {"development_units", "shared_units", "sre_units"}
                    or any(type(value) is not int or value < 0 for value in capacity.values())
                    or not any(capacity.values())
                ):
                    raise PrePushError("PREPUSH_MANIFEST_INVALID")

                entries = []
                for item in manifest["paths"]:
                    if (
                        not isinstance(item, dict)
                        or set(item) != {"path", "state"}
                        or item["state"] != "ABSENT"
                    ):
                        raise PrePushError("PREPUSH_MANIFEST_INVALID")
                    entries.append(
                        {
                            "path": self._safe_relative_path(item["path"]),
                            "mode": "100644",
                            "type": "blob",
                            "sha": None,
                        }
                    )
                leased_paths = {entry["path"] for entry in entries}
                if len(leased_paths) != len(entries):
                    raise PrePushError("PREPUSH_MANIFEST_INVALID")

                collision = manifest["collision_evidence"]
                collision_keys = {
                    "observed_at",
                    "source_snapshot_sha256",
                    "open_pr_count",
                    "open_prs",
                    "retained_or_active_issues_checked",
                    "exact_path_intersection",
                }
                if (
                    not isinstance(collision, dict)
                    or set(collision) != collision_keys
                    or not isinstance(collision["observed_at"], str)
                    or not collision["observed_at"]
                    or not isinstance(collision["source_snapshot_sha256"], str)
                    or not re.fullmatch(
                        r"[0-9a-f]{64}", collision["source_snapshot_sha256"]
                    )
                    or type(collision["open_pr_count"]) is not int
                    or collision["open_pr_count"] < 0
                    or not isinstance(collision["open_prs"], dict)
                    or collision["open_pr_count"] != len(collision["open_prs"])
                    or collision["exact_path_intersection"] != []
                    or not isinstance(
                        collision["retained_or_active_issues_checked"], list
                    )
                    or any(
                        type(issue) is not int or issue <= 0
                        for issue in collision["retained_or_active_issues_checked"]
                    )
                    or len(set(collision["retained_or_active_issues_checked"]))
                    != len(collision["retained_or_active_issues_checked"])
                ):
                    raise PrePushError("PREPUSH_MANIFEST_INVALID")
                observed_collision_paths: set[str] = set()
                for number, pull in collision["open_prs"].items():
                    if (
                        not re.fullmatch(r"[1-9][0-9]*", str(number))
                        or not isinstance(pull, dict)
                        or set(pull) != {"head_sha", "paths"}
                        or not isinstance(pull["head_sha"], str)
                        or not GIT_SHA.fullmatch(pull["head_sha"])
                        or not isinstance(pull["paths"], list)
                        or not pull["paths"]
                    ):
                        raise PrePushError("PREPUSH_MANIFEST_INVALID")
                    pull_paths = [self._safe_relative_path(path) for path in pull["paths"]]
                    if len(set(pull_paths)) != len(pull_paths):
                        raise PrePushError("PREPUSH_MANIFEST_INVALID")
                    observed_collision_paths.update(leased_paths.intersection(pull_paths))
                if sorted(observed_collision_paths) != collision["exact_path_intersection"]:
                    raise PrePushError("PREPUSH_MANIFEST_INVALID")
                historical = manifest["historical_remote_evidence"]
                if (
                    not isinstance(historical, dict)
                    or set(historical)
                    != {"closed_unmerged_pr", "preserved_branch", "prohibited_from_reuse"}
                    or type(historical["closed_unmerged_pr"]) is not int
                    or historical["closed_unmerged_pr"] <= 0
                    or not isinstance(historical["preserved_branch"], str)
                    or not historical["preserved_branch"]
                    or historical["preserved_branch"] == manifest["branch"]
                    or historical["prohibited_from_reuse"] is not True
                ):
                    raise PrePushError("PREPUSH_MANIFEST_INVALID")

                frozen_inputs = manifest["frozen_inputs"]
                if not isinstance(frozen_inputs, list) or not frozen_inputs:
                    raise PrePushError("PREPUSH_MANIFEST_INVALID")
                frozen_paths: set[str] = set()
                for item in frozen_inputs:
                    if (
                        not isinstance(item, dict)
                        or set(item) != {"path", "git_blob_sha1", "content_sha256"}
                    ):
                        raise PrePushError("PREPUSH_MANIFEST_INVALID")
                    path = self._safe_relative_path(item["path"])
                    if (
                        path in leased_paths
                        or path in frozen_paths
                        or not GIT_SHA.fullmatch(str(item["git_blob_sha1"]))
                        or not re.fullmatch(r"[0-9a-f]{64}", str(item["content_sha256"]))
                        or self._git(worktree, "rev-parse", f"{lineage.base_sha}:{path}")
                        != item["git_blob_sha1"]
                        or hashlib.sha256(
                            self._git_bytes(worktree, "show", f"{lineage.base_sha}:{path}")
                        ).hexdigest()
                        != item["content_sha256"]
                    ):
                        raise PrePushError("PREPUSH_MANIFEST_BASE_DRIFT")
                    frozen_paths.add(path)
                entries.sort(key=lambda entry: entry["path"])

        paths: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"path", "mode", "type", "sha"}:
                raise PrePushError("PREPUSH_MANIFEST_INVALID")
            path = self._safe_relative_path(entry["path"])
            if path in paths:
                raise PrePushError("PREPUSH_MANIFEST_INVALID")
            if entry["mode"] != "100644" or entry["type"] != "blob":
                raise PrePushError("PREPUSH_MANIFEST_INVALID")
            blob_sha = entry["sha"]
            return_code, observed_blob = self._git_optional(
                worktree, "rev-parse", f"{lineage.base_sha}:{path}"
            )
            if blob_sha is None:
                if return_code == 0:
                    raise PrePushError("PREPUSH_MANIFEST_BASE_DRIFT")
            elif (
                not isinstance(blob_sha, str)
                or not GIT_SHA.fullmatch(blob_sha)
                or return_code != 0
                or observed_blob != blob_sha
            ):
                raise PrePushError("PREPUSH_MANIFEST_BASE_DRIFT")
            paths.append(path)

        self._git(worktree, "merge-base", "--is-ancestor", lineage.base_sha, head_sha)
        changed = tuple(
            line
            for line in self._git(
                worktree,
                "diff",
                "--name-only",
                "--diff-filter=ACDMRTUXB",
                f"{lineage.base_sha}...{head_sha}",
                "--",
            ).splitlines()
            if line
        )
        # Lease manifests bind the exact path set; list order is serialization,
        # not authority. Git tree order differs from Unicode/JSON ordering for
        # names such as `App.tsx` and `api/`, so compare the closed set and use
        # Git's deterministic diff tuple for the receipt and lower gates.
        if len(paths) != len(changed) or frozenset(paths) != frozenset(changed):
            raise PrePushError("PREPUSH_EXACT_DIFF_MISMATCH")
        return LeaseManifest(
            content_sha256=content_sha256,
            changed_paths_sha256=digest_json(list(changed)),
            paths=changed,
        )

    @staticmethod
    def _lower_gate_commands(paths: tuple[str, ...]) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
        commands: list[tuple[str, str, tuple[str, ...]]] = []
        if any(not path.startswith("frontend/") for path in paths):
            commands.append(("backend/check.sh", "backend", ("./check.sh",)))
        if any(path.startswith("frontend/") for path in paths):
            commands.extend(
                (
                    ("frontend/npm-check", "frontend", ("npm", "run", "check")),
                    ("frontend/npm-build", "frontend", ("npm", "run", "build")),
                )
            )
        if not commands:
            raise PrePushError("PREPUSH_LOWER_GATE_UNCLASSIFIED")
        return tuple(commands)

    @staticmethod
    def _source_digest(relative_path: str) -> str:
        path = REPOSITORY_ROOT / relative_path
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise PrePushError("PREPUSH_GATE_PROFILE_UNSUPPORTED") from exc

    @staticmethod
    def _require_harness_validator_catalog() -> BaselineCatalog:
        try:
            catalog = load_catalog(REPOSITORY_ROOT)
        except BaselineError as exc:
            raise PrePushError(
                "PREPUSH_HARNESS_VALIDATOR_CATALOG_INCOMPLETE"
            ) from exc
        for skill_root in catalog.skill_roots:
            root = REPOSITORY_ROOT / skill_root
            skill = root / "SKILL.md"
            if (
                not root.is_dir()
                or root.is_symlink()
                or not skill.is_file()
                or skill.is_symlink()
            ):
                raise PrePushError("PREPUSH_HARNESS_VALIDATOR_CATALOG_INCOMPLETE")
        return catalog

    @staticmethod
    def _require_harness_focused_selectors(paths: tuple[str, ...]) -> tuple[str, ...]:
        orchestrator_prefix = "skills/twinfinity-sprint-orchestrator/"
        selectors: set[str] = set()
        for path in paths:
            relative = path.removeprefix(orchestrator_prefix)
            if relative.startswith("tests/test_") and relative.endswith(".py"):
                selectors.add("tests." + Path(relative).stem)
            elif relative.startswith("scripts/") and relative.endswith(".py"):
                selector = "tests.test_" + Path(relative).stem
                test_path = (
                    REPOSITORY_ROOT
                    / "skills"
                    / "twinfinity-sprint-orchestrator"
                    / "tests"
                    / f"test_{Path(relative).stem}.py"
                )
                if not test_path.is_file() or test_path.is_symlink():
                    raise PrePushError("PREPUSH_HARNESS_FOCUSED_SELECTOR_MISSING")
                selectors.add(selector)
        return tuple(sorted(selectors))

    @staticmethod
    def _harness_baseline_required(
        paths: tuple[str, ...], catalog: BaselineCatalog
    ) -> bool:
        def trusted_match(path: str) -> bool:
            return any(
                path == value if kind == "path" else path.startswith(value)
                for kind, value in REQUIRED_SELF_TRIGGERS
            )

        return any(
            trusted_match(path) or catalog_matches_path(catalog, path)
            for path in paths
        )

    @staticmethod
    def _serialize_lower_gate(
        gate_plan: GatePlan,
        baseline_evidence: dict[str, Any] | None = None,
    ) -> str:
        return canonical_json(
            {
                "profile": gate_plan.profile,
                "metadata": gate_plan.metadata,
                "commands": [
                    {"name": name, "cwd": cwd, "argv": list(argv)}
                    for name, cwd, argv in gate_plan.lower_commands
                ],
                "baseline_evidence": baseline_evidence,
            }
        )

    @staticmethod
    def _load_baseline_evidence(
        path: Path,
        *,
        base_sha: str,
        head_sha: str,
        catalog: BaselineCatalog,
        repository_root: Path,
    ) -> dict[str, Any]:
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or path.is_symlink()
                or metadata.st_size > 4 * 1024 * 1024
            ):
                raise OSError
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            try:
                observed = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or observed.st_nlink != 1
                    or observed.st_uid != os.getuid()
                ):
                    raise OSError
                chunks: list[bytes] = []
                size = 0
                while True:
                    chunk = os.read(descriptor, 64 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 4 * 1024 * 1024:
                        raise OSError
                    chunks.append(chunk)
                raw = b"".join(chunks)
            finally:
                os.close(descriptor)
            receipt = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrePushError("PREPUSH_BASELINE_RECEIPT_INVALID") from exc
        if (
            not isinstance(receipt, dict)
            or receipt.get("schema") != PAIR_RECEIPT_SCHEMA
            or raw != (canonical_json(receipt) + "\n").encode("utf-8")
        ):
            raise PrePushError("PREPUSH_BASELINE_RECEIPT_INVALID")
        try:
            verify_pair_receipt(
                receipt,
                expected_base_sha=base_sha,
                expected_candidate_head=head_sha,
                catalog=catalog,
                repository_root=repository_root,
            )
        except BaselineError as exc:
            raise PrePushError("PREPUSH_BASELINE_RECEIPT_INVALID") from exc
        return {
            "schema": PREPUSH_BASELINE_BINDING_SCHEMA,
            "receipt_sha256": hashlib.sha256(raw).hexdigest(),
            "base_sha": base_sha,
            "candidate_head_sha": head_sha,
            "catalog_raw_sha256": catalog.raw_sha256,
            "accepted_base_receipt_sha256": receipt[
                "accepted_base_receipt_sha256"
            ],
            "trusted_candidate_receipt_sha256": receipt[
                "trusted_candidate_receipt_sha256"
            ],
            "candidate_receipt_sha256": receipt["candidate_receipt_sha256"],
            "pair_manifest_sha256": receipt["pair_manifest_sha256"],
            "receipt": receipt,
        }

    @staticmethod
    def _verify_serialized_lower_gate(
        serialized: str,
        gate_plan: GatePlan,
        *,
        base_sha: str,
        head_sha: str,
        repository_root: Path,
    ) -> None:
        try:
            payload = json.loads(serialized)
        except (TypeError, json.JSONDecodeError) as exc:
            raise PrePushError("PREPUSH_RECEIPT_DRIFT") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "profile",
            "metadata",
            "commands",
            "baseline_evidence",
        }:
            raise PrePushError("PREPUSH_RECEIPT_DRIFT")
        evidence = payload["baseline_evidence"]
        catalog = None
        if gate_plan.metadata.get("baseline_required") is True:
            catalog = PrePushControl._require_harness_validator_catalog()
            if not isinstance(evidence, dict) or set(evidence) != {
                "schema",
                "receipt_sha256",
                "base_sha",
                "candidate_head_sha",
                "catalog_raw_sha256",
                "accepted_base_receipt_sha256",
                "trusted_candidate_receipt_sha256",
                "candidate_receipt_sha256",
                "pair_manifest_sha256",
                "receipt",
            }:
                raise PrePushError("PREPUSH_RECEIPT_DRIFT")
            receipt = evidence["receipt"]
            raw = (canonical_json(receipt) + "\n").encode("utf-8")
            if (
                evidence["schema"] != PREPUSH_BASELINE_BINDING_SCHEMA
                or evidence["receipt_sha256"] != hashlib.sha256(raw).hexdigest()
                or evidence["base_sha"] != base_sha
                or evidence["candidate_head_sha"] != head_sha
                or evidence["catalog_raw_sha256"] != catalog.raw_sha256
            ):
                raise PrePushError("PREPUSH_RECEIPT_DRIFT")
            try:
                verify_pair_receipt(
                    receipt,
                    expected_base_sha=base_sha,
                    expected_candidate_head=head_sha,
                    catalog=catalog,
                    repository_root=repository_root,
                )
            except BaselineError as exc:
                raise PrePushError("PREPUSH_RECEIPT_DRIFT") from exc
            for field in (
                "accepted_base_receipt_sha256",
                "trusted_candidate_receipt_sha256",
                "candidate_receipt_sha256",
                "pair_manifest_sha256",
            ):
                if evidence[field] != receipt[field]:
                    raise PrePushError("PREPUSH_RECEIPT_DRIFT")
        elif evidence is not None:
            raise PrePushError("PREPUSH_RECEIPT_DRIFT")
        if serialized != PrePushControl._serialize_lower_gate(gate_plan, evidence):
            raise PrePushError("PREPUSH_RECEIPT_DRIFT")

    @staticmethod
    def _serialize_final_gate(gate_plan: GatePlan) -> str:
        return canonical_json(
            {
                "profile": gate_plan.profile,
                "metadata": gate_plan.metadata,
                "final_name": gate_plan.final_name,
                "final_cwd": gate_plan.final_cwd,
                "final_argv": list(gate_plan.final_argv),
            }
        )

    @staticmethod
    def _current_changed_paths(
        worktree: Path, base_sha: str, head_sha: str
    ) -> tuple[str, ...]:
        if not GIT_SHA.fullmatch(base_sha) or not GIT_SHA.fullmatch(head_sha):
            raise PrePushError("PREPUSH_HEAD_INVALID")
        changed = tuple(
            line
            for line in PrePushControl._git(
                worktree,
                "diff",
                "--name-only",
                "--diff-filter=ACDMRTUXB",
                f"{base_sha}...{head_sha}",
                "--",
            ).splitlines()
            if line
        )
        if not changed:
            raise PrePushError("PREPUSH_EXACT_HEAD_GATE_ABSENT")
        return changed

    def _gate_plan(
        self,
        repository: str,
        paths: tuple[str, ...],
        *,
        run_id: str,
        base_sha: str,
    ) -> GatePlan:
        """Select the complete gate plan from exact repository identity only."""

        policy = policy_for_repository(repository)
        if policy is None:
            raise PrePushError("PREPUSH_REPOSITORY_UNSUPPORTED")
        if policy.prepush_gate_profile == "application-compose-v1":
            metadata = {
                "profile": policy.prepush_gate_profile,
                "controller_sha256": self._source_digest(
                    "skills/twinfinity-sprint-orchestrator/scripts/prepush_control.py"
                ),
            }
            return GatePlan(
                profile=policy.prepush_gate_profile,
                lower_commands=self._lower_gate_commands(paths),
                final_name="application/browser-e2e",
                final_cwd=".",
                final_argv=(
                    sys.executable,
                    "backend/scripts/browser_e2e.py",
                    "--run-id",
                    run_id,
                ),
                final_receipt=canonical_json(
                    {
                        "profile": policy.prepush_gate_profile,
                        "metadata": metadata,
                        "final_argv": [
                            sys.executable,
                            "backend/scripts/browser_e2e.py",
                            "--run-id",
                            run_id,
                        ],
                    }
                ),
                final_failure="PREPUSH_COMPOSE_GATE_FAILED",
                metadata=metadata,
            )
        if policy.prepush_gate_profile == "harness-source-v1":
            baseline_catalog = self._require_harness_validator_catalog()
            validator_catalog = baseline_catalog.skill_roots
            selectors = self._require_harness_focused_selectors(paths)
            baseline_required = self._harness_baseline_required(
                paths, baseline_catalog
            )
            metadata = {
                "profile": policy.prepush_gate_profile,
                "base_sha": base_sha,
                "baseline_required": baseline_required,
                "baseline_execution_budget_seconds": (
                    baseline_catalog.pair_execution_budget_seconds
                    if baseline_required
                    else None
                ),
                "validator_catalog": list(validator_catalog),
                "baseline_catalog": {
                    "version": baseline_catalog.version,
                    "raw_sha256": baseline_catalog.raw_sha256,
                    "canonical_sha256": baseline_catalog.canonical_sha256,
                    "command_manifest_sha256": (
                        baseline_catalog.command_manifest_sha256
                    ),
                    "entry_timeout_seconds": (
                        baseline_catalog.entry_timeout_seconds
                    ),
                    "root_execution_budget_seconds": (
                        baseline_catalog.root_execution_budget_seconds
                    ),
                    "pair_execution_budget_seconds": (
                        baseline_catalog.pair_execution_budget_seconds
                    ),
                    "ordered_entry_ids": [
                        entry.entry_id for entry in baseline_catalog.entries
                    ],
                },
                "control_sha256": {
                    relative: self._source_digest(relative)
                    for relative in baseline_catalog.gate_control_paths
                },
            }
            baseline_commands: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
            if baseline_required:
                baseline_commands = (
                    (
                        "harness/baseline-source-controls",
                        ".",
                        (
                            sys.executable,
                            "-B",
                            "skills/twinfinity-sprint-orchestrator/scripts/run_harness_baseline_validations.py",
                            "--base-sha",
                            base_sha,
                        ),
                    ),
                )
            focused_commands: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
            if selectors:
                focused_commands = (
                    (
                        "harness/hermetic-focused",
                        ".",
                        (
                            sys.executable,
                            "-B",
                            "skills/twinfinity-sprint-orchestrator/scripts/run_hermetic_tests.py",
                            *selectors,
                        ),
                    ),
                )
            validation_commands = tuple(
                (
                    (
                        f"harness/quick-validate/{Path(entry.arguments[1]).name}"
                        if entry.kind == "skill-validator"
                        else "harness/executor-registry-audit"
                    ),
                    entry.working_directory,
                    catalog_command(entry, sys.executable),
                )
                for entry in baseline_catalog.entries
            )
            lower_commands = baseline_commands + focused_commands + validation_commands
            final_argv = (
                sys.executable,
                "-B",
                "skills/twinfinity-sprint-orchestrator/scripts/run_hermetic_tests.py",
            )
            return GatePlan(
                profile=policy.prepush_gate_profile,
                lower_commands=lower_commands,
                final_name="harness/hermetic-full-suite",
                final_cwd=".",
                final_argv=final_argv,
                final_receipt=self._serialize_final_gate(
                    GatePlan(
                        profile=policy.prepush_gate_profile,
                        lower_commands=lower_commands,
                        final_name="harness/hermetic-full-suite",
                        final_cwd=".",
                        final_argv=final_argv,
                        final_receipt="",
                        final_failure="PREPUSH_HARNESS_HERMETIC_GATE_FAILED",
                        metadata=metadata,
                    )
                ),
                final_failure="PREPUSH_HARNESS_HERMETIC_GATE_FAILED",
                metadata=metadata,
            )
        raise PrePushError("PREPUSH_GATE_PROFILE_UNSUPPORTED")

    @staticmethod
    def _normalized_remote_repository(remote_url: str) -> str:
        for pattern in (GITHUB_HTTPS_REMOTE, GITHUB_SCP_REMOTE, GITHUB_SSH_REMOTE):
            match = pattern.fullmatch(remote_url)
            if match:
                return match.group("repository").removesuffix(".git").lower()
        raise PrePushError("PREPUSH_REMOTE_UNSAFE")

    def _canonical_remote_url(self, worktree: Path, repository: str) -> str:
        remote_url = self._git(worktree, "remote", "get-url", CANONICAL_REMOTE)
        if self._normalized_remote_repository(remote_url) != repository.lower():
            raise PrePushError("PREPUSH_REMOTE_REPOSITORY_MISMATCH")
        return remote_url

    def _validate_worktree(self, lineage: Lineage) -> tuple[Path, str]:
        worktree = Path(lineage.worktree_path)
        if not worktree.is_dir() or worktree.is_symlink():
            raise PrePushError("PREPUSH_WORKTREE_UNSAFE")
        if self._git(worktree, "rev-parse", "--show-toplevel") != str(worktree):
            raise PrePushError("PREPUSH_WORKTREE_MISMATCH")
        if self._git(worktree, "branch", "--show-current") != lineage.branch:
            raise PrePushError("PREPUSH_BRANCH_MISMATCH")
        head_sha = self._git(worktree, "rev-parse", "HEAD")
        if not GIT_SHA.fullmatch(head_sha):
            raise PrePushError("PREPUSH_HEAD_INVALID")
        if self._git(worktree, "status", "--porcelain=v1", "--untracked-files=all"):
            raise PrePushError("PREPUSH_WORKTREE_NOT_CLEAN")
        return worktree, head_sha

    @staticmethod
    def _plain_directory(path: Path) -> bool:
        """Return true only for a directory with no symlinked path component."""

        return (
            path.is_dir()
            and not path.is_symlink()
            and path.resolve(strict=True) == path.absolute()
        )

    @staticmethod
    def _resolved_within(path: Path, root: Path) -> bool:
        resolved = path.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        return resolved == resolved_root or resolved_root in resolved.parents

    @staticmethod
    def _backend_environment_bin(root: Path, lineage: Lineage) -> Path | None:
        """Return a complete, issue-owned installed backend environment."""

        if not root.is_absolute():
            return None
        worktree = Path(lineage.worktree_path)
        tagged_for_lane = any(
            int(match.group("issue")) == lineage.surface_issue_number
            for match in ISSUE_OWNED_PATH.finditer(str(root))
        )
        within_worktree = root == worktree or worktree in root.parents
        if not tagged_for_lane and not within_worktree:
            return None
        for match in ISSUE_OWNED_PATH.finditer(str(root)):
            if int(match.group("issue")) != lineage.surface_issue_number:
                return None
        lane_bin = root / "bin"
        pyvenv = root / "pyvenv.cfg"
        try:
            root_status = root.lstat()
            bin_status = lane_bin.lstat()
            pyvenv_status = pyvenv.lstat()
            if (
                not PrePushControl._plain_directory(root)
                or not PrePushControl._plain_directory(lane_bin)
                or not stat.S_ISDIR(root_status.st_mode)
                or not stat.S_ISDIR(bin_status.st_mode)
                or root_status.st_uid != os.getuid()
                or bin_status.st_uid != os.getuid()
                or not stat.S_ISREG(pyvenv_status.st_mode)
                or pyvenv_status.st_uid != os.getuid()
                or pyvenv_status.st_nlink != 1
            ):
                return None
            for tool in ("python", "ruff"):
                executable = lane_bin / tool
                if not executable.exists():
                    return None
                executable_status = executable.lstat()
                if (
                    executable_status.st_uid != os.getuid()
                    or executable_status.st_nlink != 1
                    or (
                        tool == "python"
                        and not (
                            stat.S_ISREG(executable_status.st_mode)
                            or stat.S_ISLNK(executable_status.st_mode)
                        )
                    )
                    or (
                        tool != "python"
                        and not stat.S_ISREG(executable_status.st_mode)
                    )
                ):
                    return None
                resolved = executable.resolve(strict=True)
                for match in ISSUE_OWNED_PATH.finditer(str(resolved)):
                    if int(match.group("issue")) != lineage.surface_issue_number:
                        return None
                # A venv's Python commonly resolves to its generic base
                # interpreter. Every other executable must remain in the venv.
                if tool != "python" and not PrePushControl._resolved_within(
                    executable, root
                ):
                    return None
        except OSError:
            return None
        return lane_bin

    @staticmethod
    def _prepared_gate_environment(
        lineage: Lineage,
        lower_commands: tuple[tuple[str, str, tuple[str, ...]], ...],
        environment: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Build a deterministic gate PATH from already-installed trusted tools."""

        prepared = PrePushControl._controlled_gate_environment(environment)
        path_parts = [part for part in prepared.get("PATH", "").split(os.pathsep) if part]
        worktree = Path(lineage.worktree_path)

        if any(name == "backend/check.sh" for name, _cwd, _argv in lower_commands):
            roots: list[Path] = []
            if lineage.environment_root is not None:
                roots.append(Path(lineage.environment_root))
            roots.extend(
                (
                    worktree / ".venv",
                    Path.home()
                    / ".codex"
                    / f"twinfinity-issue{lineage.surface_issue_number}-prepush-venv",
                )
            )
            selected_root: Path | None = None
            for root in dict.fromkeys(roots):
                lane_bin = PrePushControl._backend_environment_bin(root, lineage)
                if lane_bin is not None:
                    selected_root = root
                    path_parts.insert(0, str(lane_bin))
                    break
                if lineage.environment_root is not None and root == Path(
                    lineage.environment_root
                ):
                    raise PrePushError("PREPUSH_ADMISSION_ENVIRONMENT_INVALID")
            if selected_root is not None:
                prepared["VIRTUAL_ENV"] = str(selected_root)

        if any(name.startswith("frontend/") for name, _cwd, _argv in lower_commands):
            versions_root = Path.home() / ".nvm" / "versions" / "node"
            candidates: list[tuple[tuple[int, int], Path]] = []
            if PrePushControl._plain_directory(versions_root):
                for version_dir in versions_root.iterdir():
                    match = re.fullmatch(
                        rf"v{REQUIRED_NODE_MAJOR}\.([0-9]+)\.([0-9]+)",
                        version_dir.name,
                    )
                    node_bin = version_dir / "bin"
                    if (
                        match
                        and PrePushControl._plain_directory(version_dir)
                        and PrePushControl._plain_directory(node_bin)
                        and PrePushControl._resolved_within(node_bin, versions_root)
                        and (node_bin / "node").exists()
                        and (node_bin / "npm").exists()
                        and PrePushControl._resolved_within(
                            node_bin / "node", version_dir
                        )
                        and PrePushControl._resolved_within(
                            node_bin / "npm", version_dir
                        )
                    ):
                        candidates.append(
                            ((int(match.group(1)), int(match.group(2))), node_bin)
                        )
            if candidates:
                _version, node_bin = max(candidates)
                path_parts.insert(0, str(node_bin))

        prepared["PATH"] = os.pathsep.join(dict.fromkeys(path_parts))
        return prepared

    @staticmethod
    def _validate_gate_environment(
        lineage: Lineage,
        lower_commands: tuple[tuple[str, str, tuple[str, ...]], ...],
        environment: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Reject another issue's toolchain and prove backend tools are lane-owned."""

        current = dict(os.environ if environment is None else environment)
        inspected = {
            key: value
            for key, value in current.items()
            if key in GATE_ENVIRONMENT_KEYS and isinstance(value, str) and value
        }
        inspected["PREPUSH_CONTROL_PYTHON"] = sys.executable
        for value in inspected.values():
            for match in ISSUE_OWNED_PATH.finditer(value):
                if int(match.group("issue")) != lineage.surface_issue_number:
                    raise PrePushError("PREPUSH_FOREIGN_ENVIRONMENT")

        provenance: dict[str, str] = {}
        if any(name.startswith("harness/") for name, _cwd, _argv in lower_commands):
            try:
                interpreter = Path(sys.executable).resolve(strict=True)
            except OSError as exc:
                raise PrePushError("PREPUSH_GATE_TOOL_MISSING") from exc
            for match in ISSUE_OWNED_PATH.finditer(str(interpreter)):
                if int(match.group("issue")) != lineage.surface_issue_number:
                    raise PrePushError("PREPUSH_FOREIGN_ENVIRONMENT")
            provenance["python"] = str(interpreter)
        if any(name == "backend/check.sh" for name, _cwd, _argv in lower_commands):
            search_path = current.get("PATH")
            worktree = Path(lineage.worktree_path)
            backend_roots: set[Path] = set()
            for tool in ("python", "ruff"):
                executable = shutil.which(tool, path=search_path)
                if executable is None:
                    raise PrePushError("PREPUSH_GATE_TOOL_MISSING")
                lexical = Path(executable).absolute()
                try:
                    resolved = lexical.resolve(strict=True)
                except OSError as exc:
                    raise PrePushError("PREPUSH_GATE_TOOL_MISSING") from exc
                tagged_for_lane = any(
                    int(match.group("issue")) == lineage.surface_issue_number
                    for match in ISSUE_OWNED_PATH.finditer(str(lexical))
                )
                within_worktree = lexical == worktree or worktree in lexical.parents
                if not tagged_for_lane and not within_worktree:
                    raise PrePushError("PREPUSH_ENVIRONMENT_UNOWNED")
                for match in ISSUE_OWNED_PATH.finditer(str(resolved)):
                    if int(match.group("issue")) != lineage.surface_issue_number:
                        raise PrePushError("PREPUSH_FOREIGN_ENVIRONMENT")
                environment_root = lexical.parent.parent
                pyvenv = environment_root / "pyvenv.cfg"
                if (
                    lexical.parent.name != "bin"
                    or not PrePushControl._plain_directory(environment_root)
                    or not PrePushControl._plain_directory(lexical.parent)
                    or not pyvenv.is_file()
                    or pyvenv.is_symlink()
                ):
                    raise PrePushError("PREPUSH_ENVIRONMENT_UNOWNED")
                if tool != "python" and not PrePushControl._resolved_within(
                    lexical, environment_root
                ):
                    raise PrePushError("PREPUSH_ENVIRONMENT_UNOWNED")
                backend_roots.add(environment_root)
                provenance[tool] = str(lexical)
            if len(backend_roots) != 1:
                raise PrePushError("PREPUSH_ENVIRONMENT_UNOWNED")
            selected_root = next(iter(backend_roots))
            if PrePushControl._backend_environment_bin(
                selected_root, lineage
            ) != selected_root / "bin":
                raise PrePushError("PREPUSH_ENVIRONMENT_UNOWNED")
            virtual_environment = current.get("VIRTUAL_ENV")
            if virtual_environment is not None and Path(
                virtual_environment
            ).absolute() != selected_root:
                raise PrePushError("PREPUSH_ENVIRONMENT_UNOWNED")
            provenance["virtual_environment"] = str(selected_root)
        if any(name.startswith("frontend/") for name, _cwd, _argv in lower_commands):
            search_path = current.get("PATH")
            for tool in ("node", "npm"):
                executable = shutil.which(tool, path=search_path)
                if executable is None:
                    raise PrePushError("PREPUSH_GATE_TOOL_MISSING")
                lexical = Path(executable).absolute()
                try:
                    resolved = lexical.resolve(strict=True)
                except OSError as exc:
                    raise PrePushError("PREPUSH_GATE_TOOL_MISSING") from exc
                for match in ISSUE_OWNED_PATH.finditer(str(resolved)):
                    if int(match.group("issue")) != lineage.surface_issue_number:
                        raise PrePushError("PREPUSH_FOREIGN_ENVIRONMENT")
                provenance[tool] = str(lexical)
            version = subprocess.run(
                [provenance["node"], "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=PrePushControl._controlled_gate_environment(current),
            )
            if (
                version.returncode != 0
                or not re.fullmatch(
                    rf"v{REQUIRED_NODE_MAJOR}\.[0-9]+\.[0-9]+",
                    version.stdout.strip(),
                )
            ):
                raise PrePushError("PREPUSH_NODE_VERSION_MISMATCH")
        return provenance

    def _validate_existing_environment(
        self,
        lineage: Lineage,
        environment_provenance: dict[str, str],
    ) -> dict[str, str]:
        """Bind a reused environment to its immutable receipt and package set."""

        binding = lineage.existing_environment
        if binding is None:
            return environment_provenance
        self._verify_existing_environment_receipt(lineage)
        if (
            digest_json(environment_provenance)
            != binding.gate_environment_provenance_sha256
        ):
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_PROVENANCE_DRIFT")

        root = Path(binding.root)
        python = root / "bin" / "python"
        if environment_provenance.get("python") != str(python):
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_PROVENANCE_DRIFT")
        uv = Path("/home/ubuntu/.local/bin/uv")
        try:
            uv_metadata = uv.lstat()
        except OSError as exc:
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_VERIFIER_MISSING") from exc
        if (
            not stat.S_ISREG(uv_metadata.st_mode)
            or uv_metadata.st_uid != os.getuid()
            or uv_metadata.st_nlink != 1
            or uv.is_symlink()
        ):
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_VERIFIER_INVALID")
        try:
            result = subprocess.run(
                [str(uv), "pip", "freeze", "--python", str(python)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
                env={
                    "HOME": "/home/ubuntu",
                    "PATH": "/home/ubuntu/.local/bin:/usr/bin:/bin",
                    "UV_NO_PROGRESS": "1",
                },
            )
        except subprocess.TimeoutExpired as exc:
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_VERIFY_TIMEOUT") from exc
        if result.returncode != 0:
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_VERIFY_FAILED")
        freeze_lines = sorted(
            line.strip() for line in result.stdout.splitlines() if line.strip()
        )
        freeze_sha256 = hashlib.sha256(
            ("\n".join(freeze_lines) + "\n").encode("utf-8")
        ).hexdigest()
        if (
            len(freeze_lines) != binding.package_count
            or freeze_sha256 != binding.freeze_sha256
        ):
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_PACKAGE_DRIFT")
        return {
            **environment_provenance,
            "environment_rebuild_artifact_key": binding.rebuild_artifact_key,
            "environment_rebuild_artifact_content_sha256": (
                binding.rebuild_artifact_content_sha256
            ),
            "environment_freeze_sha256": freeze_sha256,
            "environment_package_count": str(len(freeze_lines)),
        }

    def _verify_existing_environment_receipt(
        self, lineage: Lineage, *, _transaction: bool = True
    ) -> dict[str, Any]:
        """Verify the semantic rebuild receipt, its log, and immutable inputs."""

        binding = lineage.existing_environment
        if binding is None:
            return {}
        try:
            _artifact, receipt_bytes = self.store.read_registered_artifact(
                artifact_key=binding.rebuild_artifact_key,
                repository=lineage.repository,
                issue_number=lineage.issue_number,
                generation=lineage.generation,
                expected_content_sha256=binding.rebuild_artifact_content_sha256,
                expected_retention_class="CLOSEOUT_EVIDENCE",
                maximum_size_bytes=64 * 1024,
                _transaction=_transaction,
            )
        except CoordinationError as exc:
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_RECEIPT_INVALID") from exc
        try:
            receipt = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_RECEIPT_INVALID") from exc
        expected = {
            "kind": "TWINFINITY_ENVIRONMENT_REBUILD_RECEIPT_V1",
            "state": "PASS",
            "repository": lineage.repository,
            "issue_number": lineage.issue_number,
            "generation": lineage.generation,
            "source_payload_sha256": lineage.source_payload_sha256,
            "environment_root": binding.root,
            "freeze_sha256": binding.freeze_sha256,
            "package_count": binding.package_count,
            "gate_environment_provenance_sha256": (
                binding.gate_environment_provenance_sha256
            ),
        }
        receipt_fields = {
            *expected,
            "built_candidate_head_sha",
            "requirements",
            "log_artifact_key",
            "log_artifact_content_sha256",
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != receipt_fields
            or any(receipt.get(key) != value for key, value in expected.items())
            or not isinstance(receipt.get("requirements"), list)
            or not receipt["requirements"]
        ):
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_RECEIPT_INVALID")
        try:
            self.store.verify_registered_artifact(
                artifact_key=receipt["log_artifact_key"],
                repository=lineage.repository,
                issue_number=lineage.issue_number,
                generation=lineage.generation,
                expected_content_sha256=receipt[
                    "log_artifact_content_sha256"
                ],
                expected_retention_class="CLOSEOUT_EVIDENCE",
                _transaction=_transaction,
            )
        except (CoordinationError, KeyError, TypeError) as exc:
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_RECEIPT_INVALID") from exc
        worktree = Path(lineage.worktree_path)
        for requirement in receipt["requirements"]:
            if (
                not isinstance(requirement, dict)
                or set(requirement) != {"path", "sha256"}
                or not isinstance(requirement.get("path"), str)
                or not requirement["path"]
                or Path(requirement["path"]).is_absolute()
                or any(
                    part in {"", ".", ".."}
                    for part in Path(requirement["path"]).parts
                )
                or not isinstance(requirement.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", requirement["sha256"])
            ):
                raise PrePushError(
                    "PREPUSH_EXISTING_ENVIRONMENT_RECEIPT_INVALID"
                )
            try:
                path = worktree / requirement["path"]
                metadata = path.lstat()
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except (KeyError, TypeError, OSError) as exc:
                raise PrePushError(
                    "PREPUSH_EXISTING_ENVIRONMENT_INPUT_DRIFT"
                ) from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or path.is_symlink()
                or digest != requirement.get("sha256")
            ):
                raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_INPUT_DRIFT")
        try:
            self._git(
                worktree,
                "merge-base",
                "--is-ancestor",
                receipt["built_candidate_head_sha"],
                "HEAD",
            )
        except (KeyError, TypeError, PrePushError) as exc:
            raise PrePushError("PREPUSH_EXISTING_ENVIRONMENT_LINEAGE_DRIFT") from exc
        return receipt

    @staticmethod
    def _controlled_gate_environment(
        environment: dict[str, str] | None = None,
    ) -> dict[str, str]:
        controlled = dict(os.environ if environment is None else environment)
        for key in tuple(controlled):
            if key in SHELL_INJECTION_ENVIRONMENT_KEYS or key.startswith(
                "BASH_FUNC_"
            ):
                controlled.pop(key)
            elif key in GATE_ENVIRONMENT_KEYS - {"PATH", "TMPDIR"}:
                controlled.pop(key)
        controlled["PYTHONDONTWRITEBYTECODE"] = "1"
        return controlled

    def _record(
        self,
        *,
        lineage: Lineage,
        head_sha: str,
        manifest: LeaseManifest,
        lower_gate: str,
        compose_gate: str,
        lower_exit: int | None,
        compose_exit: int | None,
        run_id: str,
        head_unchanged: bool,
        cleanup_proven: bool,
        started_at: str,
        completed_at: str,
        error: str | None,
        environment_provenance: dict[str, str],
    ) -> dict[str, Any]:
        state = (
            "PASS"
            if lower_exit == 0
            and compose_exit == 0
            and head_unchanged
            and cleanup_proven
            and error is None
            else "HOLD"
        )
        with self.store.transaction():
            current = self._lineage(lineage.repository, lineage.issue_number)
            if current != lineage:
                raise PrePushError("PREPUSH_LINEAGE_DRIFT")
            if state == "PASS" and lineage.existing_environment is not None:
                try:
                    self._verify_existing_environment_receipt(
                        lineage, _transaction=False
                    )
                except PrePushError:
                    state = "HOLD"
                    error = "PREPUSH_EXISTING_ENVIRONMENT_FINAL_RECEIPT_DRIFT"
            environment_provenance_sha256 = digest_json(environment_provenance)
            evidence = {
                "lineage": asdict(lineage),
                "head_sha": head_sha,
                "changed_paths_sha256": manifest.changed_paths_sha256,
                "changed_path_count": len(manifest.paths),
                "lower_gate": lower_gate,
                "lower_gate_exit_code": lower_exit,
                "compose_gate": compose_gate,
                "compose_gate_exit_code": compose_exit,
                "compose_run_id": run_id,
                "head_unchanged": head_unchanged,
                "cleanup_proven": cleanup_proven,
                "state": state,
                "started_at": started_at,
                "completed_at": completed_at,
                "last_error": error,
                "environment_provenance": environment_provenance,
                "environment_provenance_sha256": environment_provenance_sha256,
            }
            evidence_sha256 = digest_json(evidence)
            cursor = self.connection.execute(
                """
                INSERT INTO coordination_pre_push_gates(
                    repository, issue_number, generation, accountable_session_id,
                    source_payload_sha256, lease_manifest_sha256,
                    admission_message_id, admission_payload_sha256, branch,
                    worktree_path, base_sha, head_sha, changed_paths_sha256,
                    changed_path_count, lower_gate,
                    lower_gate_exit_code, compose_gate, compose_gate_exit_code,
                    compose_run_id, head_unchanged, cleanup_proven, state,
                    evidence_sha256, environment_provenance_sha256,
                    started_at, completed_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lineage.repository,
                    lineage.issue_number,
                    lineage.generation,
                    lineage.session_id,
                    lineage.source_payload_sha256,
                    lineage.lease_manifest_sha256,
                    lineage.admission_message_id,
                    lineage.admission_payload_sha256,
                    lineage.branch,
                    lineage.worktree_path,
                    lineage.base_sha,
                    head_sha,
                    manifest.changed_paths_sha256,
                    len(manifest.paths),
                    evidence["lower_gate"],
                    lower_exit,
                    evidence["compose_gate"],
                    compose_exit,
                    run_id,
                    int(head_unchanged),
                    int(cleanup_proven),
                    state,
                    evidence_sha256,
                    environment_provenance_sha256,
                    started_at,
                    completed_at,
                    error,
                ),
            )
            self.store._event(
                "PREPUSH_GATE_RECORDED",
                f"{lineage.repository}:issue:{lineage.issue_number}:generation:{lineage.generation}:head:{head_sha}",
                {
                    "receipt_id": int(cursor.lastrowid),
                    "state": state,
                    "evidence_sha256": evidence_sha256,
                },
                completed_at,
            )
        return dict(
            self.connection.execute(
                "SELECT * FROM coordination_pre_push_gates WHERE id=?",
                (cursor.lastrowid,),
            ).fetchone()
        )

    def run(
        self,
        repository: str,
        issue_number: int,
        timeout_seconds: int,
        manifest_path: Path,
    ) -> dict[str, Any]:
        lineage = self._lineage(repository, issue_number)
        worktree, head_sha = self._validate_worktree(lineage)
        manifest = self._validate_manifest_file(
            lineage, worktree, head_sha, manifest_path
        )
        run_id = f"p{issue_number}-g{lineage.generation}-{head_sha[:12]}"
        gate_plan = self._gate_plan(
            lineage.repository, manifest.paths, run_id=run_id, base_sha=lineage.base_sha
        )
        lower_commands = gate_plan.lower_commands
        baseline_evidence: dict[str, Any] | None = None
        evidence_directory = tempfile.TemporaryDirectory(
            prefix="tf-prepush-baseline-"
        )
        evidence_root = Path(evidence_directory.name)
        evidence_root.chmod(0o700)
        if worktree == evidence_root or worktree in evidence_root.parents:
            evidence_directory.cleanup()
            raise PrePushError("PREPUSH_BASELINE_RECEIPT_ROOT_UNSAFE")
        baseline_receipt_path = evidence_root / "pair-receipt.json"
        lower_gate = self._serialize_lower_gate(gate_plan, baseline_evidence)
        compose_gate = gate_plan.final_receipt
        started_at = utc_now()
        lower_exit: int | None = None
        compose_exit: int | None = None
        error: str | None = None
        gate_environment: dict[str, str] = {}
        environment_provenance: dict[str, str] = {}
        try:
            gate_environment = self._prepared_gate_environment(
                lineage, lower_commands
            )
            environment_provenance = self._validate_gate_environment(
                lineage, lower_commands, gate_environment
            )
            environment_provenance = self._validate_existing_environment(
                lineage, environment_provenance
            )
            print(
                canonical_json(
                    {"prepush_gate_environment": environment_provenance}
                ),
                flush=True,
            )
            lower_exit = 0
            for name, cwd, argv in lower_commands:
                run_argv = argv
                command_timeout = timeout_seconds
                if name == "harness/baseline-source-controls":
                    run_argv = (*argv, "--receipt", str(baseline_receipt_path))
                    command_timeout = max(
                        timeout_seconds,
                        int(
                            gate_plan.metadata[
                                "baseline_execution_budget_seconds"
                            ]
                        ),
                    )
                lower = subprocess.run(
                    list(run_argv),
                    cwd=worktree / cwd,
                    timeout=command_timeout,
                    check=False,
                    env=gate_environment,
                )
                lower_exit = lower.returncode
                if lower_exit != 0:
                    break
                if name == "harness/baseline-source-controls":
                    if baseline_evidence is not None:
                        raise PrePushError(
                            "PREPUSH_BASELINE_RECEIPT_DUPLICATE"
                        )
                    baseline_evidence = self._load_baseline_evidence(
                        baseline_receipt_path,
                        base_sha=lineage.base_sha,
                        head_sha=head_sha,
                        catalog=self._require_harness_validator_catalog(),
                        repository_root=worktree,
                    )
            if (
                lower_exit == 0
                and gate_plan.metadata.get("baseline_required") is True
                and baseline_evidence is None
            ):
                raise PrePushError("PREPUSH_BASELINE_RECEIPT_MISSING")
            if lower_exit == 0:
                compose = subprocess.run(
                    list(gate_plan.final_argv),
                    cwd=worktree / gate_plan.final_cwd,
                    timeout=timeout_seconds,
                    check=False,
                    env=gate_environment,
                )
                compose_exit = compose.returncode
        except subprocess.TimeoutExpired:
            error = "PREPUSH_GATE_TIMEOUT"
        except OSError:
            error = "PREPUSH_GATE_EXEC_FAILED"
        except PrePushError as exc:
            error = str(exc)
        finally:
            evidence_directory.cleanup()
        lower_gate = self._serialize_lower_gate(gate_plan, baseline_evidence)
        try:
            final_head = self._git(worktree, "rev-parse", "HEAD")
            clean = not self._git(
                worktree, "status", "--porcelain=v1", "--untracked-files=all"
            )
        except PrePushError:
            final_head = ""
            clean = False
        head_unchanged = final_head == head_sha and clean
        cleanup_proven = compose_exit == 0
        if error is None and lower_exit != 0:
            error = "PREPUSH_LOWER_GATE_FAILED"
        if error is None and compose_exit != 0:
            error = gate_plan.final_failure
        if error is None and not head_unchanged:
            error = "PREPUSH_HEAD_OR_WORKTREE_CHANGED"
        if error is None and lineage.existing_environment is not None:
            try:
                post_gate_provenance = self._validate_gate_environment(
                    lineage, lower_commands, gate_environment
                )
                post_gate_provenance = self._validate_existing_environment(
                    lineage, post_gate_provenance
                )
                if post_gate_provenance != environment_provenance:
                    raise PrePushError(
                        "PREPUSH_EXISTING_ENVIRONMENT_POST_GATE_DRIFT"
                    )
                environment_provenance = post_gate_provenance
            except PrePushError as exc:
                error = str(exc)
        receipt = self._record(
            lineage=lineage,
            head_sha=head_sha,
            manifest=manifest,
            lower_gate=lower_gate,
            compose_gate=compose_gate,
            lower_exit=lower_exit,
            compose_exit=compose_exit,
            run_id=run_id,
            head_unchanged=head_unchanged,
            cleanup_proven=cleanup_proven,
            started_at=started_at,
            completed_at=utc_now(),
            error=error,
            environment_provenance=environment_provenance,
        )
        if receipt["state"] != "PASS":
            raise PrePushError(receipt["last_error"] or "PREPUSH_GATE_HELD")
        return receipt

    def assert_push_eligible(
        self, repository: str, issue_number: int, branch: str, head_sha: str
    ) -> dict[str, Any]:
        if not GIT_SHA.fullmatch(head_sha):
            raise PrePushError("PREPUSH_HEAD_INVALID")
        lineage = self._lineage(repository, issue_number)
        if branch != lineage.branch:
            raise PrePushError("PREPUSH_BRANCH_MISMATCH")
        worktree, observed_head = self._validate_worktree(lineage)
        if observed_head != head_sha:
            raise PrePushError("PREPUSH_HEAD_INVALID")
        changed_paths = self._current_changed_paths(
            worktree, lineage.base_sha, observed_head
        )
        run_id = f"p{issue_number}-g{lineage.generation}-{head_sha[:12]}"
        gate_plan = self._gate_plan(
            lineage.repository,
            changed_paths,
            run_id=run_id,
            base_sha=lineage.base_sha,
        )
        receipt = self.connection.execute(
            """
            SELECT * FROM coordination_pre_push_gates
            WHERE repository=? AND issue_number=? AND generation=?
              AND branch=? AND head_sha=?
            ORDER BY id DESC LIMIT 1
            """,
            (repository, issue_number, lineage.generation, branch, head_sha),
        ).fetchone()
        if receipt is None or receipt["state"] != "PASS":
            raise PrePushError("PREPUSH_EXACT_HEAD_GATE_ABSENT")
        if (
            receipt["accountable_session_id"] != lineage.session_id
            or receipt["source_payload_sha256"] != lineage.source_payload_sha256
            or receipt["lease_manifest_sha256"] != lineage.lease_manifest_sha256
            or int(receipt["admission_message_id"]) != lineage.admission_message_id
            or receipt["admission_payload_sha256"] != lineage.admission_payload_sha256
            or receipt["worktree_path"] != lineage.worktree_path
            or receipt["base_sha"] != lineage.base_sha
            or receipt["changed_paths_sha256"] != digest_json(list(changed_paths))
            or int(receipt["changed_path_count"]) != len(changed_paths)
            or receipt["compose_gate"] != gate_plan.final_receipt
            or not isinstance(receipt["environment_provenance_sha256"], str)
            or len(receipt["environment_provenance_sha256"]) != 64
            or int(receipt["lower_gate_exit_code"]) != 0
            or int(receipt["compose_gate_exit_code"]) != 0
            or not bool(receipt["head_unchanged"])
            or not bool(receipt["cleanup_proven"])
        ):
            raise PrePushError("PREPUSH_RECEIPT_DRIFT")
        self._verify_serialized_lower_gate(
            receipt["lower_gate"],
            gate_plan,
            base_sha=lineage.base_sha,
            head_sha=head_sha,
            repository_root=worktree,
        )
        return dict(receipt)

    def _reserve_publication(
        self,
        lineage: Lineage,
        receipt: dict[str, Any],
        remote_url_sha256: str,
    ) -> tuple[dict[str, Any], bool]:
        now = utc_now()
        with self.store.transaction():
            if self._lineage(lineage.repository, lineage.issue_number) != lineage:
                raise PrePushError("PREPUSH_LINEAGE_DRIFT")
            existing = self.connection.execute(
                """
                SELECT * FROM coordination_pre_push_publications
                WHERE repository=? AND issue_number=? AND generation=?
                  AND branch=? AND head_sha=?
                """,
                (
                    lineage.repository,
                    lineage.issue_number,
                    lineage.generation,
                    lineage.branch,
                    receipt["head_sha"],
                ),
            ).fetchone()
            if existing is not None:
                if existing["remote_url_sha256"] != remote_url_sha256:
                    raise PrePushError("PREPUSH_REMOTE_DRIFT")
                return dict(existing), False
            cursor = self.connection.execute(
                """
                INSERT INTO coordination_pre_push_publications(
                    gate_id, repository, issue_number, generation,
                    accountable_session_id, source_payload_sha256,
                    lease_manifest_sha256, admission_message_id, branch,
                    head_sha, remote_name, remote_url_sha256, state,
                    created_at, updated_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'origin', ?, 'RESERVED', ?, ?, NULL)
                """,
                (
                    receipt["id"],
                    lineage.repository,
                    lineage.issue_number,
                    lineage.generation,
                    lineage.session_id,
                    lineage.source_payload_sha256,
                    lineage.lease_manifest_sha256,
                    lineage.admission_message_id,
                    lineage.branch,
                    receipt["head_sha"],
                    remote_url_sha256,
                    now,
                    now,
                ),
            )
            publication_id = int(cursor.lastrowid)
            self.store._event(
                "PREPUSH_PUBLICATION_RESERVED",
                f"{lineage.repository}:issue:{lineage.issue_number}:generation:{lineage.generation}:head:{receipt['head_sha']}",
                {"publication_id": publication_id, "gate_id": int(receipt["id"])},
                now,
            )
        row = self.connection.execute(
            "SELECT * FROM coordination_pre_push_publications WHERE id=?",
            (publication_id,),
        ).fetchone()
        return dict(row), True

    def _remote_head(
        self, worktree: Path, remote_url: str, branch: str
    ) -> str | None:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(worktree),
                "ls-remote",
                "--heads",
                remote_url,
                f"refs/heads/{branch}",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise PrePushError("PREPUSH_REMOTE_READBACK_FAILED")
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return None
        if len(lines) != 1:
            raise PrePushError("PREPUSH_REMOTE_READBACK_AMBIGUOUS")
        fields = lines[0].split()
        if len(fields) != 2 or fields[1] != f"refs/heads/{branch}" or not GIT_SHA.fullmatch(fields[0]):
            raise PrePushError("PREPUSH_REMOTE_READBACK_AMBIGUOUS")
        return fields[0]

    def _finish_publication(
        self,
        publication_id: int,
        lineage: Lineage,
        state: str,
        error: str | None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.store.transaction():
            row = self.connection.execute(
                "SELECT * FROM coordination_pre_push_publications WHERE id=?",
                (publication_id,),
            ).fetchone()
            if row is None or row["state"] != "RESERVED":
                raise PrePushError("PREPUSH_PUBLICATION_STATE_DRIFT")
            if self._lineage(lineage.repository, lineage.issue_number) != lineage:
                raise PrePushError("PREPUSH_LINEAGE_DRIFT")
            self.connection.execute(
                """
                UPDATE coordination_pre_push_publications
                SET state=?, updated_at=?, last_error=?
                WHERE id=? AND state='RESERVED'
                """,
                (state, now, error, publication_id),
            )
            self.store._event(
                f"PREPUSH_PUBLICATION_{state}",
                f"{lineage.repository}:issue:{lineage.issue_number}:generation:{lineage.generation}:head:{row['head_sha']}",
                {"publication_id": publication_id, "error": error},
                now,
            )
        return dict(
            self.connection.execute(
                "SELECT * FROM coordination_pre_push_publications WHERE id=?",
                (publication_id,),
            ).fetchone()
        )

    def guarded_push(self, repository: str, issue_number: int) -> dict[str, Any]:
        lineage = self._lineage(repository, issue_number)
        worktree, head_sha = self._validate_worktree(lineage)
        remote_url = self._canonical_remote_url(worktree, repository)
        receipt = self.assert_push_eligible(
            repository, issue_number, lineage.branch, head_sha
        )
        publication, created = self._reserve_publication(
            lineage,
            receipt,
            hashlib.sha256(remote_url.encode("utf-8")).hexdigest(),
        )
        if publication["state"] == "COMPLETE":
            return {**publication, "result": "ALREADY_PUSHED"}
        if publication["state"] == "HOLD":
            raise PrePushError(publication["last_error"] or "PREPUSH_PUBLICATION_HELD")

        push_exit: int | None = None
        if created:
            try:
                push_environment = os.environ.copy()
                push_environment.update(
                    {
                        "TWINFINITY_PUBLICATION_ID": str(publication["id"]),
                        "TWINFINITY_PUBLICATION_ISSUE": str(issue_number),
                        "TWINFINITY_PUBLICATION_GENERATION": str(lineage.generation),
                        "TWINFINITY_PUBLICATION_HEAD": head_sha,
                    }
                )
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(worktree),
                        "push",
                        remote_url,
                        f"{head_sha}:refs/heads/{lineage.branch}",
                    ],
                    check=False,
                    env=push_environment,
                )
                push_exit = result.returncode
            except OSError:
                push_exit = None
        try:
            remote_head = self._remote_head(worktree, remote_url, lineage.branch)
        except PrePushError as exc:
            held = self._finish_publication(
                int(publication["id"]), lineage, "HOLD", str(exc)
            )
            raise PrePushError(held["last_error"]) from None
        if remote_head != head_sha:
            error = (
                "PREPUSH_REMOTE_PUSH_FAILED"
                if created and push_exit not in {0, None}
                else "PREPUSH_REMOTE_READBACK_MISMATCH"
            )
            self._finish_publication(int(publication["id"]), lineage, "HOLD", error)
            raise PrePushError(error)
        completed = self._finish_publication(
            int(publication["id"]), lineage, "COMPLETE", None
        )
        return {
            "repository": repository,
            "issue_number": issue_number,
            "generation": lineage.generation,
            "branch": lineage.branch,
            "head_sha": head_sha,
            "gate_receipt_id": int(receipt["id"]),
            "publication_id": int(completed["id"]),
            "remote": CANONICAL_REMOTE,
            "state": "PUSHED",
        }

    def validate_git_hook(
        self,
        remote_url: str,
        updates: str,
        environment: dict[str, str],
    ) -> dict[str, Any]:
        try:
            publication_id = int(environment["TWINFINITY_PUBLICATION_ID"])
            issue_number = int(environment["TWINFINITY_PUBLICATION_ISSUE"])
            generation = int(environment["TWINFINITY_PUBLICATION_GENERATION"])
            head_sha = environment["TWINFINITY_PUBLICATION_HEAD"]
        except (KeyError, TypeError, ValueError):
            raise PrePushError("PREPUSH_HOOK_RESERVATION_ABSENT") from None
        if publication_id <= 0 or issue_number <= 0 or generation < 0:
            raise PrePushError("PREPUSH_HOOK_RESERVATION_INVALID")
        if not GIT_SHA.fullmatch(head_sha):
            raise PrePushError("PREPUSH_HOOK_HEAD_INVALID")
        row = self.connection.execute(
            "SELECT * FROM coordination_pre_push_publications WHERE id=?",
            (publication_id,),
        ).fetchone()
        if (
            row is None
            or row["state"] != "RESERVED"
            or int(row["issue_number"]) != issue_number
            or int(row["generation"]) != generation
            or row["head_sha"] != head_sha
            or row["remote_url_sha256"]
            != hashlib.sha256(remote_url.encode("utf-8")).hexdigest()
        ):
            raise PrePushError("PREPUSH_HOOK_RESERVATION_DRIFT")
        gate = self.connection.execute(
            "SELECT state, head_sha FROM coordination_pre_push_gates WHERE id=?",
            (row["gate_id"],),
        ).fetchone()
        if gate is None or gate["state"] != "PASS" or gate["head_sha"] != head_sha:
            raise PrePushError("PREPUSH_HOOK_GATE_INVALID")

        lines = [line for line in updates.splitlines() if line.strip()]
        if len(lines) != 1:
            raise PrePushError("PREPUSH_HOOK_UPDATE_INVALID")
        fields = lines[0].split()
        expected_ref = f"refs/heads/{row['branch']}"
        if (
            len(fields) != 4
            or not fields[0]
            or fields[1] != head_sha
            or fields[2] != expected_ref
            or not re.fullmatch(r"[0-9a-f]{40}", fields[3])
        ):
            raise PrePushError("PREPUSH_HOOK_UPDATE_DRIFT")
        return {
            "publication_id": publication_id,
            "issue_number": issue_number,
            "generation": generation,
            "branch": row["branch"],
            "head_sha": head_sha,
            "state": "HOOK_ACCEPTED",
        }

    def show(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM coordination_pre_push_gates ORDER BY id"
            )
        ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--repository", required=True)
    run.add_argument("--issue", type=int, required=True)
    run.add_argument("--lease-manifest", type=Path, required=True)
    run.add_argument("--timeout-seconds", type=int, default=3600)
    check = commands.add_parser("assert-push")
    check.add_argument("--repository", required=True)
    check.add_argument("--issue", type=int, required=True)
    check.add_argument("--branch", required=True)
    check.add_argument("--head-sha", required=True)
    push = commands.add_parser("guarded-push")
    push.add_argument("--repository", required=True)
    push.add_argument("--issue", type=int, required=True)
    hook = commands.add_parser("validate-hook")
    hook.add_argument("--remote-url", required=True)
    commands.add_parser("show")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    control = PrePushControl(DEFAULT_DATABASE)
    try:
        if args.command == "run":
            result = control.run(
                args.repository,
                args.issue,
                args.timeout_seconds,
                args.lease_manifest,
            )
        elif args.command == "assert-push":
            result = control.assert_push_eligible(
                args.repository, args.issue, args.branch, args.head_sha
            )
        elif args.command == "guarded-push":
            result = control.guarded_push(args.repository, args.issue)
        elif args.command == "validate-hook":
            result = control.validate_git_hook(
                args.remote_url,
                sys.stdin.read(),
                dict(os.environ),
            )
        else:
            result = control.show()
        print(canonical_json(result))
        return 0
    except (CoordinationError, PrePushError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        control.close()


if __name__ == "__main__":
    raise SystemExit(main())
