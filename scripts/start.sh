#!/usr/bin/env bash
set -euo pipefail

script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
source_root=$script_root
destination_root=/home/ubuntu
manifest=
systemctl_command=/usr/bin/systemctl

usage() {
  echo "usage: $0 --manifest PATH [--source-root PATH] [--destination-root PATH] [--systemctl PATH]" >&2
}

while (($#)); do
  case "$1" in
    --manifest|--source-root|--destination-root|--systemctl)
      (($# >= 2)) || { usage; exit 2; }
      option=$1
      value=$2
      shift 2
      case "$option" in
        --manifest) manifest=$value ;;
        --source-root) source_root=$value ;;
        --destination-root) destination_root=$value ;;
        --systemctl) systemctl_command=$value ;;
      esac
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n "$manifest" ]] || { usage; exit 2; }

/usr/bin/python3 - "$source_root" "$destination_root" "$manifest" <<'PY'
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tomllib

source_root = Path(sys.argv[1])
destination_root = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])
atom_path = source_root / "skills/twinfinity-sprint-orchestrator/scripts/source_install_atom.py"
spec = importlib.util.spec_from_file_location("twinfinity_source_install_atom", atom_path)
if spec is None or spec.loader is None:
    raise SystemExit("START_SOURCE_ATOM_UNAVAILABLE")
atom = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = atom
spec.loader.exec_module(atom)

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
entries = atom._validate_manifest(manifest)
source_root = atom._safe_root(source_root)
destination_root = atom._safe_root(destination_root)
atom._verify_source_commit(source_root, manifest, entries)

unit_names = {
    "twinfinity-coordination-supervisor.service",
    "twinfinity-coordination-supervisor.timer",
    "twinfinity-hosted-operation-supervisor.service",
    "twinfinity-hosted-operation-supervisor.timer",
    "twinfinity-portfolio-graph-supervisor.service",
    "twinfinity-portfolio-graph-supervisor.timer",
}
unit_prefix = ".config/systemd/user/"
observed_units: set[str] = set()
required_entrypoints = {
    ".codex/skills/twinfinity-sprint-orchestrator/scripts/coordination_supervisor.py",
    ".codex/skills/twinfinity-sprint-orchestrator/scripts/hosted_operation_control.py",
    ".codex/skills/twinfinity-sprint-orchestrator/scripts/portfolio_graph_supervisor.py",
}
observed_destinations: set[str] = set()
for entry in entries:
    source = atom._safe_file(source_root, atom._relative(entry["source_path"]))
    installed = atom._safe_file(destination_root, atom._relative(entry["destination_path"]))
    metadata = installed.lstat()
    if (
        atom._file_sha256(source) != entry["source_sha256"]
        or atom._file_sha256(installed) != entry["source_sha256"]
        or stat.S_IMODE(metadata.st_mode) != entry["destination_mode"]
        or metadata.st_uid != entry["destination_uid"]
        or metadata.st_gid != entry["destination_gid"]
    ):
        raise SystemExit("START_INSTALLED_SOURCE_DRIFT")
    destination = entry["destination_path"]
    observed_destinations.add(destination)
    if destination.startswith(unit_prefix):
        observed_units.add(destination.removeprefix(unit_prefix))
if observed_units != unit_names:
    raise SystemExit("START_UNIT_INVENTORY_DRIFT")
if not required_entrypoints.issubset(observed_destinations):
    raise SystemExit("START_ENTRYPOINT_INVENTORY_DRIFT")

skill_root = destination_root / ".codex/skills/twinfinity-sprint-orchestrator"
registry_path = skill_root / "references/twinfinity-executor-registry.toml"
registry = tomllib.loads(registry_path.read_text(encoding="utf-8"))
roles = registry.get("roles")
if not isinstance(roles, dict) or set(roles) != {"planner", "development", "sre"}:
    raise SystemExit("START_REGISTRY_ROLES_INVALID")
endpoints: dict[str, str] = {}
for role in sorted(roles):
    value = roles[role]
    endpoint_id = value.get("endpoint_id")
    version = value.get("version")
    codex_profile = value.get("codex_profile")
    expected_sha = value.get("profile_sha256")
    if (
        endpoint_id != f"role.{role}.v{version}"
        or not isinstance(codex_profile, str)
        or not isinstance(expected_sha, str)
    ):
        raise SystemExit("START_REGISTRY_ENDPOINT_INVALID")
    profile_name = f"{codex_profile}-v{version}.config.toml"
    template = (skill_root / "references" / profile_name).read_bytes()
    installed = (destination_root / ".codex" / profile_name).read_bytes()
    if template != installed or hashlib.sha256(installed).hexdigest() != expected_sha:
        raise SystemExit("START_REGISTRY_PROFILE_DRIFT")
    endpoints[role] = endpoint_id
print(json.dumps({"endpoints": endpoints, "state": "SOURCE_VALIDATED"}, sort_keys=True))
PY

timers=(
  twinfinity-coordination-supervisor.timer
  twinfinity-hosted-operation-supervisor.timer
  twinfinity-portfolio-graph-supervisor.timer
)

for timer in "${timers[@]}"; do
  enabled_state=
  if enabled_state=$("$systemctl_command" --user is-enabled "$timer" 2>/dev/null); then
    :
  fi
  if [[ "$enabled_state" != disabled ]]; then
    echo "START_TIMER_ENABLED_DRIFT:$timer:${enabled_state:-unknown}" >&2
    exit 1
  fi
done

"$systemctl_command" --user daemon-reload
"$systemctl_command" --user start "${timers[@]}"
echo '{"state":"TIMERS_STARTED","enabled":false,"timer_count":3}'
