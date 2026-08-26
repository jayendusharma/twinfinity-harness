# Twinfinity exact-head UI evidence

Use this contract for every leaf and pull request that intentionally changes rendered layout, copy, state, interaction, typography, theme, or responsive behavior. A frontend label alone does not trigger it when the change is provably non-visual.

## Keep design intent separate from delivery evidence

- Use issue #131 as the canonical library for directional product mockups. A focused leaf links the exact applicable #131 assets or records `existing UI / no new design`.
- Mockups describe information architecture, state, and interaction direction. They do not prove implementation, accessibility, authorization, privacy, staging readiness, or release acceptance.
- Do not add exact-head implementation screenshots to #131. Let #131 aggregate links to accepted child evidence when useful.

## Define the issue visual contract before activation

Record `UI impact: required` or `UI impact: N/A - <specific reason>` in the leaf body or a controlling comment. When required, include a compact matrix with:

- route or surface;
- synthetic actor, role, and capability;
- materially changed state and matching Gherkin scenario;
- viewport;
- canonical mockup/reference or `existing UI` decision.

When this policy is introduced after work is already active, post the controlling visual-contract comment before the next UI-affecting edit or ready-for-review transition; do not retroactively treat an unlabeled active branch as exempt.

The default viewports are desktop `1400x900` and mobile `430x900`. Add tablet `768x900` when navigation, responsive reflow, breakpoints, long-value handling, a shared shell, or a tablet reference is in scope. Capture the changed success state and each materially affected loading, empty, denied, partial, unsupported, error, focus, and persisted mutation state. A mutation form before submission is not proof; show the persisted/refetched result. For a visual bug, place a safe before image on the issue and the exact-head after image on the PR.

## Separate local publication from PR evidence

Before publication, the exact source, lease, worktree, branch, base, and head must pass the local lower gates, ordinary final-head browser Compose, and cleanup. The resulting exact-head `PASS` makes that head eligible only for the existing guarded-push path under the current admission; it is not standalone mutation authority. Local pre-push does not require a pull request, inject pull-request identity, request candidate output, or produce review evidence.

After guarded publication, create or update the draft pull request. Natural exact-head pull-request CI is the sole producer of the durable PR-bound UI candidate. Missing, invalid, or stale candidate evidence blocks independent acceptance and merge, not the guarded publication needed to create or update the pull request for that head, including a repair head.

## Publish one exact-head PR gallery

After the last UI-affecting change and before ready-for-review, add an `Exact-head UI evidence` PR comment that links the exact successful workflow run and candidate artifact. For each image record:

- full base and head commit SHA;
- route/surface, state, synthetic actor/capability, viewport, and device-pixel ratio;
- Gherkin scenario and Playwright/test identifier;
- synthetic fixture/configuration version or digest;
- PNG dimensions and SHA-256;
- privacy-cleanliness attestation;
- link to the issue visual contract.

During the approved PoC, the exact-head CI workflow publishes one short-lived private candidate artifact. An independent fresh reviewer attempt must download the ZIP through the supported GitHub Actions artifact API or connector, validate its closed inventory, PNG bytes, dimensions, digests, privacy attestations, and exact-head identity, and record the result in one PR conversation comment. The leaf closeout and any parent or tracker link that exact comment and workflow artifact rather than duplicating binaries. Native PR attachments are optional presentation copies only and must never require an end user or other human participant. Do not place screenshot binaries on the product/default branch.

Any head move invalidates the gallery's exact-head binding. A UI-affecting move requires a fresh candidate artifact. For a proven non-UI-only move, rerun the same deterministic scenarios at the new head, compare the new PNG bytes, hashes, and dimensions to the prior images, and only when all are byte-identical publish a replacement manifest that explicitly supersedes the old evidence. A reviewer binds acceptance to the current head.

## Publish and verify through the private Actions artifact during the PoC

- Emit a distinct versioned success-only candidate containing only declared PNGs, an exact manifest, and a PNG-specific cleanliness attestation. Failure, skip, cancellation, cleanup-only, incomplete viewport coverage, unsafe evidence, or missing pull-request identity must create no final candidate; keep diagnostics separate and expiring.
- After the last UI-affecting change, natural exact-head CI publishes only the final declared candidate ZIP with short retention. Do not require a repository participant or end user to download, extract, or re-upload its PNGs.
- The independent reviewer attempt must use the supported `github_download_workflow_artifact` connector or authenticated GitHub Actions artifact API. A sandbox failure in `gh` is not proof that the artifact is inaccessible; inspect connector capabilities before escalating or requesting human help.
- Record full base/head SHA, workflow run and artifact ID/digest/expiry, route/surface/state, synthetic actor/capability, viewport/DPR, Gherkin/test ID, fixture digest, PNG dimensions/bytes/SHA-256, privacy attestation, and the issue visual-contract link in one PR comment.
- Before acceptance, an independent fresh reviewer attempt must re-read the live PR head, download and safely extract the ZIP, reject path traversal/symlinks/unexpected files, recompute hashes and dimensions, verify matrix completeness and privacy cleanliness, and separately verify Playwright, BDD, accessibility, authorization, tenant-isolation, and CI evidence.
- Link the exact PR evidence comment and workflow run/artifact from the leaf, #120/#131 when applicable, and parent closeout. Native attachments may be added automatically through a documented supported API when available, but are never a release prerequisite and must not require human intervention.
- A head move invalidates the gallery. A UI-affecting move requires a fresh exact-head artifact. A proven non-UI-only move may be accepted only after deterministic recapture at the new head proves every PNG byte-identical and a superseding manifest records the new head.
- Actions artifacts expire and identities with sufficient workflow authority may delete them. During the PoC, complete authenticated verification before expiry and preserve the verified hashes/metadata in the PR comment; missing or unverified evidence suspends acceptance until a new natural exact-head artifact is produced and verified.
- Treat the PoC artifact and evidence comment as review evidence, not an append-only audit ledger or exclusive-publisher guarantee. Preserve stronger protected append-only storage and a dedicated publisher as separately tracked post-PoC hardening when an assurance requirement, supported protection capability, artifact incident, or scale/retention trigger warrants it.

## Keep evidence synthetic and safe

- Use unmistakably synthetic, domain-neutral tenants, principals, configured Twin content, sources, citations, media, organization selectors, and identifiers.
- Never retain private/client data, credentials, tokens, request headers, real tenant or provider-account identifiers, hidden system prompts or enforcement rules, signed URLs, browser storage, console payloads, local paths, sensitive endpoints, or browser/DevTools chrome. When an authorized configuration UI intentionally exposes tenant-configurable instructions or guardrails, show only benign synthetic values permitted by that surface; end-user evidence must still prove those restricted fields are absent.
- Prefer fixed viewport-only PNGs with descriptive safe alt text, bounded size, valid PNG structure, digest binding, and a cleanliness attestation.
- Scan the rendered DOM, browser network/evidence, and retained artifacts. A screenshot cannot prove that hidden or protected data never reached the browser.

## Preserve independent acceptance layers

Screenshots prove rendered pixels and layout only. They supplement rather than replace:

- Playwright browser-to-API journeys;
- backend BDD and API integration tests;
- component tests;
- authorization, tenant-isolation, and restricted-field assertions;
- semantic HTML, accessible names, keyboard/focus order, screen-reader, contrast, reduced-motion, and responsive evidence.

A focus-state image may supplement executable accessibility evidence but never replaces it.

## Accept N/A narrowly

`UI evidence: N/A` is valid only when no rendered pixel changes, such as generated/type-only changes or an internal refactor with demonstrated identical output. A semantics-only accessibility change may use N/A only with separate executable accessibility evidence. The reviewer or orchestrator must accept the rationale.

The following are not valid N/A reasons: screenshots are inconvenient, the feature is configuration-gated, the page normally contains sensitive data, a mockup is absent, only desktop was tested, or the PR is mostly backend.
