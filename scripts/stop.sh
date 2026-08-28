#!/usr/bin/env bash
set -euo pipefail

systemctl_command=/usr/bin/systemctl
wait_seconds=30
poll_seconds=1

usage() {
  echo "usage: $0 [--wait-seconds N] [--poll-seconds N] [--systemctl PATH]" >&2
}

while (($#)); do
  case "$1" in
    --wait-seconds|--poll-seconds|--systemctl)
      (($# >= 2)) || { usage; exit 2; }
      option=$1
      value=$2
      shift 2
      case "$option" in
        --wait-seconds) wait_seconds=$value ;;
        --poll-seconds) poll_seconds=$value ;;
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

[[ "$wait_seconds" =~ ^[0-9]+$ && "$poll_seconds" =~ ^[1-9][0-9]*$ ]] || { usage; exit 2; }

timers=(
  twinfinity-coordination-supervisor.timer
  twinfinity-hosted-operation-supervisor.timer
  twinfinity-portfolio-graph-supervisor.timer
)
services=(
  twinfinity-coordination-supervisor.service
  twinfinity-hosted-operation-supervisor.service
  twinfinity-portfolio-graph-supervisor.service
)

"$systemctl_command" --user stop "${timers[@]}"
"$systemctl_command" --user stop "${services[@]}"

deadline=$((SECONDS + wait_seconds))
while true; do
  if ! active_units=$("$systemctl_command" --user list-units \
    --type=service \
    --state=activating,active,reloading \
    --plain \
    --no-legend \
    --no-pager \
    'twinfinity-role-executor-*'); then
    echo 'STOP_EXECUTOR_OBSERVATION_FAILED' >&2
    exit 1
  fi
  if [[ -z "${active_units//[[:space:]]/}" ]]; then
    echo '{"state":"QUIESCED","executors_active":false}'
    exit 0
  fi
  if ((SECONDS >= deadline)); then
    echo '{"state":"HOLD","executors_active":true}' >&2
    exit 1
  fi
  sleep "$poll_seconds"
done
