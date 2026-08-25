# Twinfinity Production Support and Reliability

Use this guide for production symptoms, incidents, operational improvements, dependency degradation, security or privacy events, capacity, and cost work.

## Triage without increasing harm

1. Record the reported symptom, affected users or tenants, start time, current impact, and reporter confidence.
2. Confirm active identity and environment before querying systems.
3. Check recent releases, traffic changes, migrations, configuration changes, provider status, quotas, and spend anomalies.
4. Correlate edge, application, database, storage, job, and provider evidence using timestamps and request identifiers.
5. Use metadata and aggregate telemetry first. Avoid retrieving customer payloads, prompts, media, transcripts, tokens, or secret values.
6. State the leading hypothesis, confirming evidence, disconfirming evidence, and next safe test.

Do not mutate production merely to test a theory. Prefer reproducible staging or synthetic-tenant checks.

## Assign severity from impact

- **SEV-0:** confirmed or credible active security, privacy, tenant-isolation, destructive data-integrity, or secret-exposure event. Stop harm, preserve evidence, restrict access, and engage authorized security and leadership owners immediately.
- **SEV-1:** broad outage, critical journey unavailable, widespread corrupt output, or uncontrolled provider or cloud spend. Establish incident command and mitigate urgently.
- **SEV-2:** material degradation, bounded tenant impact, failing noncritical dependency, or broken operational control with a viable workaround.
- **SEV-3:** low-impact defect, alert-quality issue, reliability debt, or hygiene finding suitable for normal prioritization.

Use the highest credible severity until evidence safely narrows it. Do not publish customer or public communications without the accountable owner.

## Run the incident

Assign or identify:

- incident commander;
- operations lead;
- communications owner;
- scribe or timeline owner;
- subject-matter owners for application, data, cloud, and affected providers.

Then:

1. Stabilize and stop additional harm.
2. Prefer rollback, traffic isolation, feature disablement, quota cap, or dependency bypass when they are safer and faster than a forward fix.
3. Preserve relevant logs, audit evidence, revision metadata, and timestamps with strict access and redaction.
4. Publish concise internal updates: impact, known facts, actions, result, risk, and next update trigger.
5. Verify recovery through user journeys and telemetry; do not rely on absence of alerts.
6. Monitor for recurrence before standing down.
7. Create bounded follow-ups with owners and evidence, then run a blameless review proportional to impact.

Never allow urgency to erase authorization, tenant isolation, evidence handling, or recovery safety.

## Handle common operational domains

### Cloud Run and delivery

- Correlate errors with revision, digest, configuration, traffic, scaling, concurrency, memory, CPU, timeout, cold-start, and request logs.
- Verify startup, readiness, and liveness independently.
- Keep a known-good compatible revision available during rollout.
- Reconcile manual console drift back into reviewed automation.

### Supabase and data

- Check service status, connection pressure, query latency, locks, storage, auth, migration state, backups, and policy behavior.
- Use isolated data for diagnosis whenever possible.
- Treat cross-tenant access, missing row-level controls, or unexpected public storage as a security incident.
- Separate availability recovery from destructive data repair; require explicit approval for repair.

### AI, avatar, voice, media, and ingestion providers

- Check provider health, latency, error classes, quota, rate limits, authentication metadata, model or API changes, callback delivery, and spend.
- Bound retries and prevent retry storms or duplicate billable work.
- Verify webhook signatures, idempotency, replay handling, and tenant association.
- Preserve a safe degraded experience where the product permits; fail closed for authorization, privacy, or provenance uncertainty.
- Never paste vendor payloads or user content into tickets or chat.

### Security and secret exposure

- Stop propagation and restrict affected access.
- Preserve minimal audit evidence without repeating the secret or private content.
- Identify scope from metadata, logs, and access history.
- Rotate or revoke through an explicitly authorized plan, then redeploy and verify consumers.
- Search for secondary exposure and close the root control gap.

## Maintain a minimum viable reliability program

Keep these controls current and owned:

- service and dependency catalog with criticality and owner;
- user-centered SLIs, initial SLOs, and an error-budget decision practice;
- one useful service dashboard and actionable paging alerts;
- release annotations and revision-to-source provenance;
- runbooks for deploy, rollback, restore, secret rotation, provider outage, and tenant-isolation response;
- backup policy plus recurring restore evidence;
- workload identity, least privilege, public-surface review, and access review;
- cloud and vendor budgets, quotas, spend anomaly signals, and scaling caps;
- dependency timeout, retry, circuit-breaking or fallback strategy;
- periodic resilience exercises and post-incident follow-through.

Automate repetitive, high-risk steps first: exact artifact promotion, environment checks, smoke tests, migration validation, rollout observation, rollback, and evidence capture. Avoid an elaborate platform that costs more to maintain than the risk it removes.

## Review capacity and cost

For cloud and vendor spend:

1. Attribute cost by environment, service, provider, and major workload where practical.
2. Compare spend and usage trends with releases and traffic.
3. Set budgets, alerts, quotas, autoscaling ceilings, and request-level safeguards.
4. Find idle compute, disks, snapshots, images, secrets, IPs, and unused provider subscriptions.
5. Confirm ownership and recovery value before deleting or downsizing anything.
6. Treat runaway provider calls, retries, and media generation as reliability incidents when spend is uncontrolled.

Optimize after measuring. Do not trade away tenant isolation, recovery, security, or critical observability for minor savings.

## Close production support work

Record:

- severity and user impact;
- verified timeline and affected components;
- root cause or current hypothesis confidence;
- mitigation and direct recovery evidence;
- security, privacy, data-integrity, and spend assessment;
- follow-up issues with owners and priority inputs;
- monitoring period and recurrence trigger;
- any inaccessible evidence or unresolved unknowns.

Use sanitized operational metadata. Keep sensitive incident artifacts in the narrow approved system, not general GitHub or chat.
