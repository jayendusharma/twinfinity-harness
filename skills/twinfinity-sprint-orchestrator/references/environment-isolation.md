# Issue-owned environment isolation

Use this contract for every Twinfinity implementation or review lane that executes repository tooling.

## Establish ownership before execution

1. Bind the lane to one issue number, exact worktree, branch, HEAD, and dependency-manifest hashes.
2. Create an issue-named run root such as `/tmp/twinfinity-issue<NUMBER>-<NONCE>` owned by the invoking UID/GID with mode `0700`.
   - Create every writable package-manager cache inside that root as an empty directory and record that it was empty before installation.
   - Do not seed it by copying, reflinking, hardlinking, symlinking, bind-mounting, or cloning any generic cache or another issue's cache.
3. Record, without exposing secrets:
   - absolute and resolved paths for Python, Node, npm, uv, pip, Ruff, pytest, and other invoked tools;
   - tool versions, `sys.executable`, `sys.prefix`, `sys.base_prefix`, `VIRTUAL_ENV`, `NODE_PATH`, and npm prefix variables;
   - hashes of the exact requirements, lockfiles, and package manifests;
   - the environment owner, mode, installed-package count, canonical package-inventory digest, and dependency compatibility result.
4. Refuse the gate if any executable, virtual environment, `node_modules`, prefix, symlink target, copied dependency tree, or writable cache belongs to another issue/worktree or escapes the issue-owned root.

Generic machine interpreters and package-manager binaries may be reused. A generic content-addressed download cache may be consumed only through a package-manager mode that is provably read-only and creates no link from the issue root into that cache. Never copy or link generic `archive`, `wheels`, `sdists`, `builds`, `simple`, or interpreter-cache trees into an issue cache. If the sandbox or package manager cannot prove that boundary, use a planner-authorized network install with caching disabled. Another issue's installed environment or cache may not be reused.

## Python procedure

1. Create a fresh virtual environment inside the issue-owned run root using the repository-supported Python version.
2. Install the exact production and development requirement manifests. Offline installation from a generic machine cache is allowed only when the cache remains provably read-only and the installed artifacts are copied rather than linked. Otherwise use the separately authorized network path with a fresh empty issue cache; for uv, prefer `uv pip install --no-cache --link-mode copy`.
3. Run the dependency compatibility check and create a canonical sorted installed-package manifest plus SHA-256 digest.
4. Redirect `PYTHONPYCACHEPREFIX`, pytest cache, coverage output, Ruff cache, and general temporary output into the issue-owned root.
5. Invoke every Python gate through the absolute issue-owned interpreter or binaries. Do not rely on ambient activation alone.
6. Before accepting evidence, audit the run root for cache size and inventory, symlink targets, multiply linked files, tool shebangs, `pyvenv.cfg`, direct-URL metadata, and foreign issue/worktree strings. Any unexplained cache tree or link invalidates the environment.

## Frontend procedure

1. Prefer `npm ci` in the exact issue worktree using its exact lockfile.
2. If the worktree cannot host `node_modules`, create a fresh issue-owned frontend root from byte-identical copies of that worktree's `package.json` and lockfile. Install with `npm ci` into that root. A generic npm download cache may be consumed read-only, but it must not be copied, linked, or mounted into the issue root.
3. Invoke package binaries from that issue-owned tree. If configuration must be copied to the run root for sandbox writeability, prove byte identity and record the copy's hash; keep the repository source/root explicit.
4. Never borrow, copy, or link another issue's `node_modules`, even when lockfile hashes match.
5. Redirect npm logs, Vite/Vitest caches, coverage, build output, and temporary reports into the issue-owned root unless the repository gate explicitly requires an in-worktree output that is cleaned and audited afterward.

## Evidence validity and recovery

- Report environment provenance with every gate boundary. A passing count without provenance is incomplete evidence.
- Independent review must verify the provenance before relying on writer-reported gates.
- If foreign, copied-cache, linked-cache, or ambiguous provenance is discovered, invalidate all affected results. Do not repair the contaminated run root in place and do not change source merely to recover evidence. Freeze it for a read-only audit, create a new nonce root, rerun the affected focused and full gates, prove no generated worktree drift, refreeze hashes, and commission a new review.
- Delete an invalid or abandoned issue-owned run root only after confirming that no live process, working directory, open file descriptor, or active lane still references it and the planner or user has authorized the exact cleanup. Never delete or mutate the generic machine cache as part of issue cleanup.
- Environment isolation does not authorize dependency changes, package downloads, Docker, Git publication, workflow dispatch, deployment, cloud/provider access, or private-data use; apply the lane's existing authority boundary.
- Run Docker, Buildx, Compose, container-backed tests, cleanup, remote Git and `gh`, dependency downloads, package-registry access, artifact materialization, and provider/API operations only from the accountable fresh Development or SRE endpoint under its exact admission and controlled escalation. Evidence from an unaccountable process is not acceptance evidence, and its DNS, authentication, or connectivity failure does not diagnose the native role endpoint.
- Connector and web tools are separate controlled channels. Their availability may support read-only discovery or an explicitly authorized connector mutation, but it does not grant shell-network access and must not be used to circumvent a denied native-host boundary.

## Terminal workspace reclamation

Run this protocol after every merged PR and whenever a development task is durably concluded, parked, transferred, superseded, or abandoned. Cleanup is part of closeout and lease release; do not defer it to an undifferentiated machine-wide purge.

1. Establish the terminal boundary before deleting anything.
   - Re-fetch the owning issue, PR, accepted or preserved head, tracker state, branch, worktree, and environment record.
   - Require the worktree to be clean at the exact expected head. For a parked or rejected lane, first push an explicit blocked preservation snapshot; do not open or imply an accepted PR.
   - Confirm no active writer, reviewer, shell working directory, process, open file descriptor, stacked child, or pending evidence review still references the target. A stacked child must use its own worktree and run root before the parent workspace is reclaimed.
   - Run the reference check from the accountable native Ubuntu endpoint. Treat process, current-working-directory, open-file, and exact mount checks as executable assertions: a positive match must make the preflight exit nonzero. Merely printing matches is not a guard.
   - Separate native preflight from deletion. Do not put deletion in the same shell packet unless every ownership/reference check is an asserted hard stop with no permissive `|| true`. If an exact owned orphan is found, terminate that process tree separately, re-run the complete preflight, and only then reclaim files.
   - Confirm required manifests, hashes, logs, screenshots, and review evidence are durably stored or intentionally disposable. Do not retain a large local archive merely because it once supported a completed gate.
2. Inventory only exact issue-owned targets.
   - List every `/tmp/twinfinity-issue<NUMBER>-<NONCE>` root, including failed and superseded nonces.
   - List the exact sibling worktree, local branch, repository-local ignored outputs, Python virtual environments and bytecode, uv/pip/pytest/Ruff caches, npm caches and prefixes, `node_modules`, Vite/Vitest/build/coverage output, Playwright browsers/reports/test results, downloaded artifact ZIPs and extracted galleries, and temporary Docker/Compose evidence.
   - List Docker containers, networks, volumes, and images only by the lane's exact ownership label, project name, or run ID. Never use a broad prune as issue cleanup.
   - Record `du` or filesystem usage before cleanup when material space will be reclaimed.
3. Stop on ambiguity.
   - Do not remove a dirty worktree, unresolved symlink target, foreign owner, generic/shared cache, another issue's root, active process, mounted path, or resource whose ownership cannot be proven.
   - Do not use force deletion to bypass a dirty-state or ownership check. Resolve or preserve the state first.
4. Reclaim in bounded order.
   - Have the accountable fresh Development or SRE endpoint attempt stop and remove exact owned Docker/Compose resources from native Ubuntu, then prove their absence.
   - Remove exact issue run roots. This reclaims their virtual environments, package trees, caches, bytecode, coverage, reports, browser binaries, screenshots, ZIPs, and failed nonce roots together.
   - Remove any remaining allowlisted generated output from the exact worktree only after inventory. Then remove the worktree with `git worktree remove <exact-path>` without `--force`, prune stale worktree metadata, and delete the local branch with non-force `git branch -d` only when Git proves it safe. A preserved remote branch may remain when it is a blocked parent or accepted audit record.
   - Never delete a remote branch, generic interpreter, generic package cache, Docker resource, or workspace outside the exact terminal record merely to increase free space.
5. Verify and publish a cleanup receipt.
   - Prove every targeted run root, worktree entry, repository-local generated path, process, and owned Docker resource is absent; prove canonical and other active worktrees are unchanged.
   - Store exact target paths, per-file hashes, archive locations, and the exhaustive before/after inventory in the owner-local manifest. Its fingerprint binds the detailed verification without exposing local topology on GitHub.
   - In the GitHub-safe receipt, record the owning issue and exact public head, target categories and counts, reclaimed bytes or aggregate before/after usage, absence verdict, preserved remote branch/evidence, deliberate residual categories, and one redacted manifest fingerprint. Do not publish absolute local paths, per-file inventories, or archive locations unless the exact disclosure is materially necessary and separately approved.
   - Validate the projected receipt with `python3 references/validate_control_receipt.py --session-role development <receipt-file>` and add it once to the leaf closeout. Send the verified capacity-release delta to the Planner; only the Planner reconciles the tracker. Do not mark the owning lease terminal until verification and receipt publication both pass.

If a user performs machine cleanup while lanes are active, invalidate only the removed environments and evidence. Preserve source changes, create fresh nonce roots, rerun the affected final gates, and clearly identify the active roots that must remain until closeout.
