# Twinfinity product vision and roadmap

## Source authority

Use this reference for durable product framing. Use live GitHub for current scope, delivery, acceptance, and authority facts. Historical plans and customer artifacts are inputs, not current control records.

## Product definition

Twinfinity is an AI-twin platform. It enables a person, expert, team, or organization to create and operate an AI representation of their expertise that people can engage through conversation and guided workflows.

An AI twin combines:

- owner-defined identity, voice, background, boundaries, and conversation starters;
- grounded knowledge from approved content and structured sources;
- conversational access to expertise when the human is unavailable;
- personalization and context appropriate to the user and purpose;
- reusable skills and workflows that move beyond question answering;
- citations, provenance, visibility, and honest unsupported behavior;
- publishing, lifecycle, operations, evaluation, and continuous improvement controls.

### Product vision

> Twinfinity enables people and organizations to create trusted AI twins that make human expertise continuously available through natural conversation, grounded knowledge, personalized guidance, and reusable workflows.

### Product promise

- **For twin users:** relevant access to expertise, guidance, and task support when they need it.
- **For experts and organizations:** a faithful, configurable, scalable extension of their knowledge and ways of helping people.
- **For twin operators:** practical tools to curate sources, configure behavior, manage visibility, inspect quality, and improve the twin over time.

Trust controls support this promise. They are not the product headline and must not replace the AI-twin value proposition.

## Platform capability map

### Twin Studio configuration plane

Treat the owner/admin UI as the primary product surface for creating and operating any domain's AI twins. Use one generic information architecture:

1. **Agents/Twins:** create, clone, archive, assign owners, select audience, and inspect lifecycle.
2. **Identity and behavior:** name, description, persona, tone, goals, instructions, boundaries, conversation starters, and model/runtime settings.
3. **Knowledge:** ingest, classify, review, approve, version, refresh, and retire sources; configure retrieval and citation behavior.
4. **Skills and actions:** select reusable skills/tools, configure typed parameters, compose bounded workflow templates, and require human approval where appropriate.
5. **Guardrails and access:** configure allowed topics, response constraints, roles/capabilities, visibility, consent/purpose, retention, and escalation within platform-owned safety bounds.
6. **Test and evaluate:** preview conversations, inspect evidence and traces, run saved evaluation sets, compare versions, and record acceptance.
7. **Publish and operate:** submit, approve, publish, hide, roll back, monitor usage/quality/cost, review feedback, and improve versions.

Education, coaching, corporate training, customer support, and other industry solutions are tenant-owned configurations or templates across these same screens. They must not create customer-specific runtime code, schema, services, routes, components, adapters, or authorization paths.

### 1. Twin studio and lifecycle

- Create and configure a twin's name, identity, description, imagery, greeting, voice, background, prompt policy, allowed topics, blocked topics, and conversation starters.
- Review, approve, publish, hide, version, transfer, and retire a twin.
- Support organization-owned and individual expert twins without hard-coding a customer domain.

### 2. Knowledge and source platform

- Ingest documents, web pages, video, audio, transcripts, structured records, and approved external sources.
- Generate and review transcripts, metadata, versions, source lineage, timestamps, passages, and consent/approval state.
- Retrieve grounded evidence with resolvable citations and clear unsupported behavior.

### 3. Conversational twin runtime

- Deliver private or public conversational experiences across desktop and mobile.
- Support streaming, history, source transparency, structured answers, and appropriate context.
- Configure distinct modes or policies where a tenant needs them without creating competing product authority planes.
- Keep model and agent providers replaceable behind Twinfinity-owned contracts.

### 4. Personalization, relationships, and recommendations

- Use authorized user context to tailor guidance.
- Filter and rank structured entities or resources for a stated goal.
- Explain recommendations and preserve feedback, eligibility, and provenance.
- Treat specialized customer data fields as typed tenant configuration over generic profile and metadata capabilities; never implement customer-specific runtime models.

### 5. Skills, workflows, and actions

- Turn repeated user goals into versioned, owner-controlled workflows.
- Combine twin knowledge, user context, structured data, external research, review, and human approval.
- Extract customer-neutral workflow primitives from validated configured journeys before building a generalized marketplace or designer.

### 6. Operations and intelligence

- Give owners source inventory, health, review, correction, reprocessing, refresh, usage, cost, quality, and feedback controls.
- Support evaluation sets, pilot evidence, observability, safe failure, and operational handoff.
- Minimize routine developer dependency for standard twin maintenance.

### 7. Trust foundation

- Preserve tenant and user isolation, consent, authorization, field visibility, auditability, retention, deletion, provenance, and source freshness.
- Make private, proprietary, structured, and public-web information distinguishable.
- Keep final policy and protected actions under server and human authority.

## Introships as the first customer configuration

Introships is the first production customer and validates a configured **Career Twin**. It is not the Twinfinity domain model.

The customer configuration combines:

- a proprietary learning corpus based initially on the selected top 100 videos, transcripts, presenter guidance, documents, and website content;
- structured context from Airtable/CRM exports covering alumni, experts, cohorts, companies, students, and placements;
- Expert Mode for grounded Introships knowledge;
- Assistant Mode for approved public-web career and internship research;
- permission-filtered alumni and industry-contact recommendations with explanations;
- private student career and application-support workflows;
- staff content, metadata, approval, correction, refresh, feedback, and evaluation operations;
- a controlled pilot with privacy, security, quality, mobile, accessibility, and acceptance evidence.

### Reuse versus configure

Promote these into reusable platform capabilities:

- configurable twin identity and publication;
- multimodal ingestion, transcript review, metadata, versions, and citations;
- structured-data mapping and explainable recommendations;
- policy-separated conversational modes;
- private user workspaces and context-aware guidance;
- reusable versioned skills/workflows;
- staff operations, evaluation, telemetry, and lifecycle management.

Keep these as tenant configuration or out of product until a reusable capability exists:

- the Introships name, brand voice, prompt, source corpus, top-100 manifest, cohorts, and acceptance thresholds;
- its alumni/contact visibility matrix, student labels and field definitions, ranking weights, consent values, and advisor-access policy, all stored as tenant configuration;
- Kajabi, Airtable/CRM, Zite, and Fillout connection settings and mappings, only when served by reusable customer-neutral connector capabilities;
- its summer-content refresh cadence, operational roles, and pilot procedures.

## Preserve #131 and #120

- **#131 is the complete Twin Studio platform.** It owns the customer-neutral owner/operator experience across twin creation, identity and behavior, knowledge, skills and actions, guardrails and access, test and evaluation, publication, and operations. Directional mockups and child leaves are evidence toward that complete outcome; no subset, sprint, or customer pilot replaces it.
- **#120 is the bounded Introships pilot subset.** It selects only the reusable Twinfinity capabilities and tenant configuration required to validate the first production customer. It does not define the platform, expand #131 acceptance, authorize Introships-specific runtime code, or imply that every Twin Studio capability belongs in the pilot.
- Classify every requirement against both issues. A reusable capability may advance #131 and be exercised by #120; an Introships value remains tenant configuration; a request with no accepted reusable expression stays out of product.
- Keep product acceptance separate. #131 acceptance requires evidence for the complete owner-operated platform outcome. #120 acceptance requires the approved bounded pilot journeys, operational gates, and customer evidence. A merged child, complete mockup pack, or accepted pilot does not automatically accept the other issue.

## Roadmap horizons

Treat the six-horizon sequence as first-customer learning within the complete #131 roadmap, not as the full platform definition:

1. **Foundation:** identity, roles, core data contracts, trust boundaries, CI, and evaluation.
2. **Twin and knowledge:** Twin onboarding, representative corpus, ingestion, transcripts, approvals, and citations.
3. **Personalization and recommendations:** structured data, profiles, networking recommendations, rationale, and feedback.
4. **User experience and workflows:** conversational modes, public research, source transparency, and private application support.
5. **Owner operations and reusable skills:** content administration, refresh, workflow operations, and evidence-based skill extraction.
6. **Pilot and acceptance:** evaluation, security, quality, mobile/accessibility, runbooks, and customer acceptance.

Post-MVP candidates include automated structured-data synchronization, selected production integrations, advisor collaboration, learned recommendation improvements, broader corpora, avatar/live-video experiences, billing and commercial plan management, public discovery/marketplace capabilities, and a broader skill catalog. Prioritize them through cross-customer evidence rather than assuming every deferred item belongs in the core roadmap.

## Product-strategy decision test

For each proposed capability, answer:

1. Which twin user or owner problem does it solve?
2. Is the value an Introships configuration value or a reusable customer-neutral Twinfinity capability?
3. Which platform layer owns it?
4. What customer vocabulary, policy, schema, content, connector settings, or mappings must remain tenant configuration rather than code?
5. What measurable user or owner outcome will prove it works?
6. What is the smallest vertical slice that teaches Twinfinity something reusable?
7. What must be deferred to avoid turning the first-customer roadmap into an unbounded platform rebuild?
