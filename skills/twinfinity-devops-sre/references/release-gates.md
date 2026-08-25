# Twinfinity Operational Release Gates

Use this checklist for staging readiness, production promotion, deployment, rollback, or release audit. Scale the evidence to the change risk, but do not bypass a critical control silently.

## Gate 0: identify the release

Require:

- release owner and approver;
- exact source SHA, pull request, and immutable artifact digest;
- target environment, service, region, database, and provider configuration resolved live;
- user outcome, acceptance criteria, risk class, expected duration, and change window;
- dependency and shared-surface assessment from the sprint orchestrator;
- rollback owner, rollback artifact, abort signals, and communication path.

Block when the artifact is mutable, target is ambiguous, authority is missing, or rollback cannot restore a safe compatible state.

## Gate 1: code and artifact integrity

Verify:

- required exact-head checks and independent review pass;
- behavior-driven acceptance evidence covers the intended outcome;
- image was built by the approved pipeline from the candidate SHA;
- runtime versions and lockfile installation match supported CI policy;
- artifact contains required application, schema, and migration material;
- dependency, container, and secret scanning results are reviewed;
- provenance, software bill of materials, and signing are present when supported;
- no credential or private-data leak is present in the change or build output.

Prefer one build promoted by digest. Do not rebuild independently for production.

## Gate 2: environment and configuration isolation

Verify staging and production separately:

- workload identity and least-privilege IAM;
- environment-specific database, storage, credentials, webhooks, callback URLs, and provider accounts or safe vendor modes;
- configuration diff against the last known-good deployment;
- ingress, authentication, authorization, CORS, domain, certificate, and webhook verification;
- scaling bounds, concurrency, timeout, CPU, memory, and quota posture;
- no unintended public or search-indexable stealth surface;
- secret references resolve without exposing payloads and have an accountable rotation posture.

Shared production data, credentials, or vendor side effects in staging are a NO-GO unless a specifically reviewed isolation mechanism makes the path safe.

## Gate 3: data and migration safety

Require for any data-affecting change:

- isolated migration validation and schema drift check;
- backward- and forward-compatibility across the rollout window;
- expand-and-contract sequencing for breaking schema evolution;
- backup or recovery point appropriate to the change;
- demonstrated restore or reversal path;
- tenant-isolation, row-level authorization, and storage-policy negative tests;
- idempotency and concurrency tests for first-write, retry, webhook, job, and ingestion paths;
- retention, deletion, and provenance behavior preserved.

Never test against a shared, staging, or production database. Never apply a production migration without explicit authorization and the exact reviewed plan.

## Gate 4: staging acceptance

Deploy the immutable candidate to an isolated staging environment and verify:

- startup, readiness, and liveness reflect real dependency health;
- authenticated and unauthenticated paths behave as designed;
- a representative synthetic tenant can complete critical user journeys;
- cross-tenant and privilege-escalation attempts fail safely;
- database, storage, background, webhook, AI, avatar, voice, and media flows used by the change behave correctly;
- provider timeouts, malformed inputs, rate limits, and partial failures produce safe responses;
- logs, metrics, traces, correlation IDs, dashboards, and alerts observe the release without sensitive data;
- latency, errors, saturation, cold starts, and vendor cost are within the explicitly accepted envelope;
- a soak period proportional to risk shows no unexplained regression.

A process that returns HTTP 200 is not sufficient evidence. Verify real dependency and user-path semantics.

## Gate 5: production approval

Before changing production, capture:

- product acceptance or named risk acceptance;
- operational GO from this role;
- exact digest and configuration difference;
- current known-good revision and traffic split;
- recent recovery point and verified rollback compatibility;
- rollout stages, observation interval, abort thresholds, and observer;
- incident channel or communication route appropriate to the risk.

Use `CONDITIONAL GO` only for a noncritical, bounded exception with owner, expiration or activation event, explicit residual risk, and rollback protection.

## Gate 6: progressive rollout

When the platform supports it:

1. Deploy the new revision with no production traffic.
2. Run direct revision and internal smoke checks.
3. Shift a small traffic fraction or bounded cohort.
4. Observe user journeys, errors, latency, saturation, dependency behavior, and spend.
5. Advance in controlled steps only while abort thresholds remain clear.
6. Roll back traffic immediately on material user harm, security or privacy uncertainty, data-integrity risk, or unexplained critical signal.

For changes that cannot be canaried, reduce blast radius through feature flags, cohort controls, backward compatibility, tested rollback, and an attended window.

## Gate 7: post-release verification

Confirm from outside and inside the service:

- production domain and critical authenticated journeys;
- tenant boundaries and relevant negative cases;
- revision, digest, configuration, migration, and traffic state;
- alerting and dashboards receive current telemetry;
- error, latency, saturation, cold-start, provider, and cost signals remain healthy;
- release annotation and durable evidence are recorded;
- rollback remains possible until confidence is established.

Close the release only after direct verification. Record follow-up reliability debt separately rather than hiding it in the release result.

## Evidence template

```text
Release: <candidate SHA / artifact digest / target>
Decision: GO | CONDITIONAL GO | NO-GO
Freshness: <when and how live state was checked>
Passed: <gate evidence>
Blocked: <gate, evidence, owner, next action>
Authorized change: <exact target and operation>
Rollout: <stages and observations>
Rollback: <known-good state, trigger, owner>
Verification: <external and internal results>
Residual risk: <accepted or unresolved>
```
