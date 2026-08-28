# Harness architecture

Twinfinity's harness separates durable control from fresh execution. The
Product Planner owns portfolio state, readiness, leases, capacity, and terminal
closeout. Fresh Development and SRE attempts own only their admitted delivery
or operational scope. The checked-in registry selects the current role
endpoints and profile hashes; scripts derive those identities from the registry
instead of embedding endpoint versions.

The delivery path is issue and graph readiness, atomic admission, one bounded
writer, exact-head validation and independent review, merge, post-main checks,
and terminal cleanup. GitHub is the external audit surface, while the owner-only
SQLite control plane holds local queue and state-machine truth.

This repository contains reviewed source, not active runtime state.
`scripts/install.sh` defaults to manifest-bound dry-run validation and requires
`--apply` for installation. `scripts/start.sh` validates installed source,
current registry-derived profiles, and all six unit bytes before reloading the
user manager and starting three disabled timers. `scripts/stop.sh` quiesces the
timers and supervisor services, then boundedly observes transient executors
without killing them or inventing completion.

| Supervisor | Installed command and working directory | Timeout | Timer cadence |
| --- | --- | --- | --- |
| Coordination | `coordination_supervisor.py` from `/home/ubuntu/code/twinfinityapp` | 30s | 20s, then every 30s |
| Hosted operation | `hosted_operation_control.py supervise` from `/home/ubuntu/code/twinfinityapp` | 45s | 25s, then every 30s |
| Portfolio graph | `portfolio_graph_supervisor.py` with no working-directory override | 240s | 90s, then every 5min |

Installation, activation, endpoint cutover, database mutation, and hosted
operations remain separate, explicitly authorized effects.
