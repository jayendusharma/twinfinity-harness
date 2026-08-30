from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SKILL_ROOT = REPOSITORY_ROOT / "skills/twinfinity-sprint-orchestrator"
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

import source_install_atom as atom


UNIT_NAMES = (
    "twinfinity-coordination-supervisor.service",
    "twinfinity-coordination-supervisor.timer",
    "twinfinity-hosted-operation-supervisor.service",
    "twinfinity-hosted-operation-supervisor.timer",
    "twinfinity-portfolio-graph-supervisor.service",
    "twinfinity-portfolio-graph-supervisor.timer",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OperatorLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="operator-lifecycle-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.source.mkdir(mode=0o700)
        self.destination.mkdir(mode=0o700)
        self._prepare_source()
        self._prepare_destination()
        self.manifest = self.root / "manifest.json"
        self._write_manifest()
        self.systemctl_log = self.root / "systemctl.log"
        self.systemctl = self.root / "fake-systemctl"
        self.systemctl.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -u
                printf '%s\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
                if [[ " $* " == *" is-enabled "* ]]; then
                  unit=${!#}
                  if [[ "${FAKE_ENABLED_TIMER:-}" == "$unit" ]]; then
                    echo enabled
                    exit 0
                  fi
                  echo disabled
                  exit 1
                fi
                if [[ " $* " == *" list-units "* ]]; then
                  if [[ "${FAKE_ACTIVE_EXECUTOR:-0}" == 1 ]]; then
                    echo 'twinfinity-role-executor-development-message-19.service loaded active running'
                  elif [[ "${FAKE_DEACTIVATING_EXECUTOR:-0}" == 1 && " $* " == *" --state=activating,active,reloading,deactivating "* ]]; then
                    echo 'twinfinity-role-executor-development-message-19.service loaded deactivating stop-sigterm'
                  fi
                fi
                exit 0
                """
            ),
            encoding="utf-8",
        )
        self.systemctl.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _prepare_source(self) -> None:
        scripts = self.source / "skills/twinfinity-sprint-orchestrator/scripts"
        references = self.source / "skills/twinfinity-sprint-orchestrator/references"
        units = self.source / "systemd/user"
        scripts.mkdir(parents=True)
        references.mkdir(parents=True)
        units.mkdir(parents=True)
        shutil.copy2(SKILL_ROOT / "scripts/source_install_atom.py", scripts)
        for entrypoint in (
            "coordination_supervisor.py",
            "hosted_operation_control.py",
            "portfolio_graph_supervisor.py",
        ):
            shutil.copy2(SKILL_ROOT / "scripts" / entrypoint, scripts / entrypoint)

        role_versions = {"planner": 12, "development": 17, "sre": 23}
        registry_lines = ["schema_version = 2", "staged_endpoints = []", ""]
        self.profile_names: list[str] = []
        for role, version in role_versions.items():
            profile = f"twinfinity-{role}-v{version}.config.toml"
            profile_path = references / profile
            profile_path.write_text(f'model = "fixture-{role}"\n', encoding="utf-8")
            self.profile_names.append(profile)
            registry_lines.extend(
                [
                    f"[roles.{role}]",
                    f'endpoint_id = "role.{role}.v{version}"',
                    f"version = {version}",
                    f'codex_profile = "twinfinity-{role}"',
                    f'profile_sha256 = "{sha256(profile_path)}"',
                    "",
                ]
            )
        (references / "twinfinity-executor-registry.toml").write_text(
            "\n".join(registry_lines), encoding="utf-8"
        )
        for unit in UNIT_NAMES:
            shutil.copy2(REPOSITORY_ROOT / "systemd/user" / unit, units / unit)

        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "-c",
                "user.name=Twinfinity Test",
                "-c",
                "user.email=test@twinfinity.invalid",
                "commit",
                "-q",
                "-m",
                "operator fixture",
            ],
            check=True,
        )
        self.source_commit = subprocess.run(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _prepare_destination(self) -> None:
        for relative in (
            ".codex/skills/twinfinity-sprint-orchestrator/scripts",
            ".codex/skills/twinfinity-sprint-orchestrator/references",
            ".config/systemd/user",
        ):
            (self.destination / relative).mkdir(parents=True)
        for profile in self.profile_names:
            source = (
                self.source
                / "skills/twinfinity-sprint-orchestrator/references"
                / profile
            )
            shutil.copy2(source, self.destination / ".codex" / profile)

    def _write_manifest(self) -> None:
        mappings = [
            (
                "skills/twinfinity-sprint-orchestrator/scripts/source_install_atom.py",
                ".codex/skills/twinfinity-sprint-orchestrator/scripts/source_install_atom.py",
            ),
            (
                "skills/twinfinity-sprint-orchestrator/references/twinfinity-executor-registry.toml",
                ".codex/skills/twinfinity-sprint-orchestrator/references/twinfinity-executor-registry.toml",
            ),
        ]
        mappings.extend(
            (
                f"skills/twinfinity-sprint-orchestrator/scripts/{entrypoint}",
                f".codex/skills/twinfinity-sprint-orchestrator/scripts/{entrypoint}",
            )
            for entrypoint in (
                "coordination_supervisor.py",
                "hosted_operation_control.py",
                "portfolio_graph_supervisor.py",
            )
        )
        mappings.extend(
            (
                f"skills/twinfinity-sprint-orchestrator/references/{profile}",
                f".codex/skills/twinfinity-sprint-orchestrator/references/{profile}",
            )
            for profile in self.profile_names
        )
        mappings.extend(
            (f"systemd/user/{unit}", f".config/systemd/user/{unit}")
            for unit in UNIT_NAMES
        )
        entries = []
        for source_relative, destination_relative in mappings:
            source = self.source / source_relative
            entries.append(
                {
                    "source_path": source_relative,
                    "destination_path": destination_relative,
                    "source_sha256": sha256(source),
                    "source_mode": stat.S_IMODE(source.stat().st_mode),
                    "destination_mode": stat.S_IMODE(source.stat().st_mode),
                    "destination_uid": os.getuid(),
                    "destination_gid": os.getgid(),
                    "destination_prior": {"state": "ABSENT"},
                }
            )
        value: dict[str, object] = {
            "schema": atom.SCHEMA,
            "manifest_sha256": "0" * 64,
            "atom_id": "operator-lifecycle-test",
            "source_commit": self.source_commit,
            "destination_root_identity": atom.destination_root_identity(
                self.destination
            ),
            "entries": entries,
        }
        value["manifest_sha256"] = atom.manifest_digest(value)
        self.manifest.write_text(atom.canonical_json(value), encoding="utf-8")
        self.manifest.chmod(0o600)

    def _install(self) -> None:
        stage = self.root / "stage"
        base = [
            str(REPOSITORY_ROOT / "scripts/install.sh"),
            "--manifest",
            str(self.manifest),
            "--source-root",
            str(self.source),
            "--destination-root",
            str(self.destination),
            "--stage-root",
            str(stage),
        ]
        dry_run = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(0, dry_run.returncode, dry_run.stderr)
        self.assertIn('"state":"DRY_RUN_VALIDATED"', dry_run.stdout)
        self.assertFalse(
            (self.destination / ".config/systemd/user" / UNIT_NAMES[0]).exists()
        )
        applied = subprocess.run(
            [
                base[0],
                "--apply",
                *base[1:],
                "--rollback-root",
                str(self.root / "rollback"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, applied.returncode, applied.stderr)
        self.assertIn('"state":"INSTALLED"', applied.stdout)

    def _systemctl_environment(self, **values: str) -> dict[str, str]:
        return {
            **os.environ,
            "FAKE_SYSTEMCTL_LOG": str(self.systemctl_log),
            **values,
        }

    def _start(
        self,
        *,
        destination_root: Path | None = None,
        **environment: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(REPOSITORY_ROOT / "scripts/start.sh"),
                "--manifest",
                str(self.manifest),
                "--source-root",
                str(self.source),
                "--destination-root",
                str(destination_root or self.destination),
                "--systemctl",
                str(self.systemctl),
            ],
            env=self._systemctl_environment(**environment),
            capture_output=True,
            text=True,
        )

    def _stop(self, **environment: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(REPOSITORY_ROOT / "scripts/stop.sh"),
                "--wait-seconds",
                "0",
                "--systemctl",
                str(self.systemctl),
            ],
            env=self._systemctl_environment(**environment),
            capture_output=True,
            text=True,
        )

    def test_install_is_dry_run_until_explicit_apply_and_does_not_activate(self) -> None:
        self._install()
        self.assertEqual(
            set(UNIT_NAMES),
            {
                path.name
                for path in (self.destination / ".config/systemd/user").iterdir()
            },
        )
        self.assertFalse(self.systemctl_log.exists())

    def test_start_derives_current_endpoints_and_starts_three_disabled_timers(self) -> None:
        self._install()
        result = self._start()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('"development": "role.development.v17"', result.stdout)
        lines = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(3, sum(" is-enabled " in f" {line} " for line in lines))
        self.assertEqual(1, sum(" daemon-reload" in line for line in lines))
        starts = [line for line in lines if " start " in f" {line} "]
        self.assertEqual(1, len(starts))
        self.assertEqual(3, sum(timer in starts[0] for timer in UNIT_NAMES if timer.endswith(".timer")))
        self.assertFalse(any(" enable " in f" {line} " for line in lines))

    def test_start_rejects_enabled_timer_before_reload_or_start(self) -> None:
        self._install()
        result = self._start(
            FAKE_ENABLED_TIMER="twinfinity-coordination-supervisor.timer"
        )
        self.assertNotEqual(0, result.returncode)
        lines = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any("daemon-reload" in line or " start " in f" {line} " for line in lines))

    def test_start_rejects_byte_identical_shadow_root_before_systemd(self) -> None:
        self._install()
        shadow = self.root / "shadow-destination"
        shutil.copytree(self.destination, shadow)

        result = self._start(destination_root=shadow)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("INSTALL_ATOM_ROOT_IDENTITY_MISMATCH", result.stderr)
        self.assertFalse(self.systemctl_log.exists())

    def test_start_rechecks_replaced_root_before_systemd_effects(self) -> None:
        self._install()
        displaced = self.root / "displaced-destination"
        marker = self.root / "destination-replaced"
        bash_env = self.root / "replace-after-installed-validation"
        bash_env.write_text(
            textwrap.dedent(
                """\
                trap '
                  if [[ ${BASH_COMMAND:-} == timers=* && ! -e "${FAKE_REPLACEMENT_MARKER:?}" ]]; then
                    trap - DEBUG
                    : > "$FAKE_REPLACEMENT_MARKER"
                    mv -- "$FAKE_DESTINATION_ROOT" "$FAKE_DISPLACED_DESTINATION_ROOT"
                    cp -a -- "$FAKE_DISPLACED_DESTINATION_ROOT" "$FAKE_DESTINATION_ROOT"
                  fi
                ' DEBUG
                """
            ),
            encoding="utf-8",
        )

        result = self._start(
            BASH_ENV=str(bash_env),
            FAKE_REPLACEMENT_MARKER=str(marker),
            FAKE_DESTINATION_ROOT=str(self.destination),
            FAKE_DISPLACED_DESTINATION_ROOT=str(displaced),
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("INSTALL_ATOM_ROOT_IDENTITY_MISMATCH", result.stderr)
        self.assertTrue(marker.is_file())
        self.assertTrue(displaced.is_dir())
        self.assertFalse(self.systemctl_log.exists())

    def test_start_rejects_manifest_missing_supervisor_entrypoint(self) -> None:
        self._install()
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        missing = (
            ".codex/skills/twinfinity-sprint-orchestrator/scripts/"
            "coordination_supervisor.py"
        )
        manifest["entries"] = [
            entry
            for entry in manifest["entries"]
            if entry["destination_path"] != missing
        ]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)
        self.manifest.write_text(atom.canonical_json(manifest), encoding="utf-8")

        result = self._start()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("START_ENTRYPOINT_INVENTORY_DRIFT", result.stderr)
        self.assertFalse(self.systemctl_log.exists())

    def test_stop_quiesces_before_observation_and_never_kills_live_executor(self) -> None:
        result = self._stop(FAKE_ACTIVE_EXECUTOR="1")
        self.assertNotEqual(0, result.returncode)
        self.assertIn('"executors_active":true', result.stderr)
        lines = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertIn(".timer", lines[0])
        self.assertIn(".service", lines[1])
        self.assertIn("list-units", lines[2])
        self.assertFalse(any("kill" in line for line in lines))

    def test_stop_treats_deactivating_executor_as_still_draining(self) -> None:
        result = self._stop(FAKE_DEACTIVATING_EXECUTOR="1")
        self.assertNotEqual(0, result.returncode)
        self.assertIn('"executors_active":true', result.stderr)
        lines = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertIn(
            "--state=activating,active,reloading,deactivating", lines[-1]
        )
        self.assertFalse(any("kill" in line for line in lines))

    def test_repeated_stop_is_idempotent_when_no_executor_is_active(self) -> None:
        first = self._stop()
        second = self._stop()
        self.assertEqual((0, 0), (first.returncode, second.returncode))
        self.assertIn('"state":"QUIESCED"', first.stdout)
        self.assertIn('"state":"QUIESCED"', second.stdout)

    def test_exact_unit_contract_and_guide_links(self) -> None:
        unit_root = REPOSITORY_ROOT / "systemd/user"
        self.assertEqual(set(UNIT_NAMES), {path.name for path in unit_root.iterdir()})
        contracts = {
            "twinfinity-coordination-supervisor.service": (
                "coordination_supervisor.py",
                "TimeoutStartSec=30",
            ),
            "twinfinity-hosted-operation-supervisor.service": (
                "hosted_operation_control.py supervise",
                "TimeoutStartSec=45",
            ),
            "twinfinity-portfolio-graph-supervisor.service": (
                "portfolio_graph_supervisor.py",
                "TimeoutStartSec=240",
            ),
            "twinfinity-coordination-supervisor.timer": (
                "OnBootSec=20s",
                "OnUnitActiveSec=30s",
            ),
            "twinfinity-hosted-operation-supervisor.timer": (
                "OnBootSec=25s",
                "OnUnitActiveSec=30s",
            ),
            "twinfinity-portfolio-graph-supervisor.timer": (
                "OnBootSec=90s",
                "OnUnitActiveSec=5min",
            ),
        }
        for name, expected in contracts.items():
            contents = (unit_root / name).read_text(encoding="utf-8")
            for value in expected:
                self.assertIn(value, contents)
        root_readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        operator_readme = (SKILL_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/installation.md", root_readme)
        self.assertIn("docs/architecture.md", root_readme)
        self.assertIn("../../docs/installation.md", operator_readme)
        self.assertNotIn("enable --now", operator_readme)


if __name__ == "__main__":
    unittest.main()
