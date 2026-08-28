#!/usr/bin/env bash
set -euo pipefail

script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
source_root=$script_root
destination_root=/home/ubuntu
manifest=
stage_root=
rollback_root=
apply=false

usage() {
  echo "usage: $0 [--apply] --manifest PATH --stage-root PATH [--rollback-root PATH] [--source-root PATH] [--destination-root PATH]" >&2
}

while (($#)); do
  case "$1" in
    --apply)
      apply=true
      shift
      ;;
    --manifest|--stage-root|--rollback-root|--source-root|--destination-root)
      (($# >= 2)) || { usage; exit 2; }
      option=$1
      value=$2
      shift 2
      case "$option" in
        --manifest) manifest=$value ;;
        --stage-root) stage_root=$value ;;
        --rollback-root) rollback_root=$value ;;
        --source-root) source_root=$value ;;
        --destination-root) destination_root=$value ;;
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

[[ -n "$manifest" && -n "$stage_root" ]] || { usage; exit 2; }
if [[ "$apply" == true && -z "$rollback_root" ]]; then
  echo "--rollback-root is required with --apply" >&2
  exit 2
fi
if [[ "$apply" == false && -n "$rollback_root" ]]; then
  echo "--rollback-root is valid only with --apply" >&2
  exit 2
fi

atom="$source_root/skills/twinfinity-sprint-orchestrator/scripts/source_install_atom.py"
[[ -f "$atom" ]] || { echo "source_install_atom.py is missing from the source root" >&2; exit 1; }

if [[ ! -e "$stage_root" ]]; then
  /usr/bin/python3 "$atom" stage \
    --manifest "$manifest" \
    --source-root "$source_root" \
    --destination-root "$destination_root" \
    --stage-root "$stage_root"
fi

/usr/bin/python3 "$atom" validate \
  --manifest "$manifest" \
  --source-root "$source_root" \
  --destination-root "$destination_root" \
  --stage-root "$stage_root"

if [[ "$apply" == false ]]; then
  echo '{"state":"DRY_RUN_VALIDATED"}'
  exit 0
fi

manifest_sha=$(
  /usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["manifest_sha256"])' "$manifest"
)
/usr/bin/python3 "$atom" apply \
  --manifest "$manifest" \
  --source-root "$source_root" \
  --destination-root "$destination_root" \
  --stage-root "$stage_root" \
  --rollback-root "$rollback_root" \
  --confirm "INSTALL:$manifest_sha"
