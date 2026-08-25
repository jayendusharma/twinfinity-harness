"""Test-only complete reviewed endpoint catalogs for role-rotation scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import shutil
import sqlite3
from typing import Iterator
from unittest.mock import patch

import executor_registry
from executor_registry import (
    RegistryConfig,
    immediate_transaction,
    load_registry_config,
)
from reconcile_routing_artifacts import (
    _verify_or_insert_endpoint,
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)


_PLANNER_V2 = """[roles.planner]
endpoint_id = "role.planner.v2"
version = 2
executor_profile = "planner"
codex_profile = "twinfinity-planner"
profile_sha256 = "38d39166c7573d676206a0f70efd4ebbc68c2d74cd743bab85f48de56b5128cf"
command_prefix = [
  "/home/ubuntu/.local/bin/codex",
  "exec",
  "--profile",
  "twinfinity-planner",
  "--strict-config",
  "--json",
]
allowed_topics = ["coordination.notice"]
"""

_PLANNER_V3 = _PLANNER_V2.replace(
    'endpoint_id = "role.planner.v2"',
    'endpoint_id = "role.planner.v3"',
).replace("version = 2", "version = 3", 1)

_PLANNER_HISTORY = """

[[historical_endpoints]]
role = "planner"
endpoint_id = "role.planner.v1"
version = 1
executor_profile = "planner"
codex_profile = "twinfinity-planner"
profile_sha256 = "38d39166c7573d676206a0f70efd4ebbc68c2d74cd743bab85f48de56b5128cf"
command_prefix = [
  "/home/ubuntu/.local/bin/codex",
  "exec",
  "--profile",
  "twinfinity-planner",
  "--strict-config",
  "--json",
]
allowed_topics = ["coordination.notice"]

[[historical_endpoints]]
role = "planner"
endpoint_id = "role.planner.v2"
version = 2
executor_profile = "planner"
codex_profile = "twinfinity-planner"
profile_sha256 = "38d39166c7573d676206a0f70efd4ebbc68c2d74cd743bab85f48de56b5128cf"
command_prefix = [
  "/home/ubuntu/.local/bin/codex",
  "exec",
  "--profile",
  "twinfinity-planner",
  "--strict-config",
  "--json",
]
allowed_topics = ["coordination.notice"]
"""


def apply_reviewed_current_endpoint_catalog(
    connection: sqlite3.Connection,
    skill_root: Path,
    *,
    operation_key: str,
    now: str = "2026-08-24T09:59:59Z",
) -> RegistryConfig:
    """Apply and verify the complete production-current pointer set in a test DB."""

    config = load_registry_config(
        skill_root / "references" / "twinfinity-executor-registry.toml"
    )
    aliases, alias_sha256 = load_legacy_alias_fixture(
        skill_root / "tests" / "fixtures" / "legacy-role-aliases.json"
    )
    plan = build_plan(
        connection,
        config,
        aliases,
        alias_fixture_sha256=alias_sha256,
    )
    apply_plan(
        connection,
        plan=plan,
        operation_key=operation_key,
        expected_plan_sha256=plan["plan_sha256"],
        now=now,
    )
    with immediate_transaction(connection):
        for endpoint_id in sorted(config.endpoints):
            _verify_or_insert_endpoint(
                connection,
                config.endpoints[endpoint_id].payload,
                now,
            )
    expected = {
        role: endpoint.endpoint_id for role, endpoint in config.roles.items()
    }
    current = {
        str(row["role"]): str(row["endpoint_id"])
        for row in connection.execute(
            "SELECT role, endpoint_id FROM executor_role_endpoint_current ORDER BY role"
        ).fetchall()
    }
    if current != expected:
        raise AssertionError("temporary reviewed endpoint current set drifted")
    return config


@contextmanager
def reviewed_current_endpoint_catalog(
    skill_root: Path,
    temporary_root: Path,
) -> Iterator[RegistryConfig]:
    """Yield the complete reviewed production-current catalog from temp files."""

    source_references = skill_root / "references"
    fixture_root = temporary_root / "reviewed-current-endpoint-catalog"
    template_root = fixture_root / "templates"
    codex_home = fixture_root / "installed"
    template_root.mkdir(parents=True)
    codex_home.mkdir()

    for source in sorted(source_references.glob("*-v*.config.toml")):
        shutil.copy2(source, template_root / source.name)
        shutil.copy2(source, codex_home / source.name)
    catalog_path = template_root / "twinfinity-executor-registry.toml"
    shutil.copy2(
        source_references / "twinfinity-executor-registry.toml",
        catalog_path,
    )
    config = load_registry_config(
        catalog_path,
        codex_home=codex_home,
        profile_template_root=template_root,
    )
    expected = {
        "role.planner.v2",
        "role.development.v3",
        "role.development.v4",
        "role.development.v5",
        "role.sre.v3",
        "role.sre.v4",
        "role.sre.v5",
    }
    if set(config.endpoints) != expected:
        raise AssertionError("temporary reviewed endpoint catalog is incomplete")
    if {
        role: endpoint.endpoint_id for role, endpoint in config.roles.items()
    } != {
        "planner": "role.planner.v2",
        "development": "role.development.v5",
        "sre": "role.sre.v5",
    }:
        raise AssertionError("temporary reviewed endpoint current set drifted")
    with patch.object(executor_registry, "load_registry_config", return_value=config):
        yield config


@contextmanager
def reviewed_planner_rotation_catalog(
    skill_root: Path,
    temporary_root: Path,
) -> Iterator[RegistryConfig]:
    """Yield a real reviewed Planner-v3 catalog and scope identity lookup to it.

    The production catalog remains untouched.  The temporary catalog carries
    Planner v1/v2 as immutable history, Planner v3 as the reviewed current
    target, and the production Development/SRE current-and-rollback manifests.
    """

    source_references = skill_root / "references"
    fixture_root = temporary_root / "reviewed-planner-rotation-catalog"
    template_root = fixture_root / "templates"
    codex_home = fixture_root / "installed"
    template_root.mkdir(parents=True)
    codex_home.mkdir()

    for source in sorted(source_references.glob("*-v*.config.toml")):
        shutil.copy2(source, template_root / source.name)
        shutil.copy2(source, codex_home / source.name)
    planner_v2 = source_references / "twinfinity-planner-v2.config.toml"
    for version in (1, 3):
        filename = f"twinfinity-planner-v{version}.config.toml"
        shutil.copy2(planner_v2, template_root / filename)
        shutil.copy2(planner_v2, codex_home / filename)

    production_text = (
        source_references / "twinfinity-executor-registry.toml"
    ).read_text(encoding="utf-8")
    if production_text.count(_PLANNER_V2) != 1:
        raise AssertionError("production Planner-v2 registry stanza drifted")
    catalog_path = fixture_root / "executor-registry.toml"
    catalog_path.write_text(
        production_text.replace(_PLANNER_V2, _PLANNER_V3, 1)
        + _PLANNER_HISTORY,
        encoding="utf-8",
    )
    config = load_registry_config(
        catalog_path,
        codex_home=codex_home,
        profile_template_root=template_root,
    )
    expected = {
        "role.planner.v1",
        "role.planner.v2",
        "role.planner.v3",
        "role.development.v3",
        "role.development.v4",
        "role.development.v5",
        "role.sre.v3",
        "role.sre.v4",
        "role.sre.v5",
    }
    if set(config.endpoints) != expected:
        raise AssertionError("temporary reviewed endpoint catalog is incomplete")
    with patch.object(executor_registry, "load_registry_config", return_value=config):
        yield config
