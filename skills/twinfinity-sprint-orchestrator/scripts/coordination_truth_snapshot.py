#!/usr/bin/env python3
"""Stable, privacy-safe, owner-read-only Twinfinity coordination truth.

The command deliberately has no write-capable store dependency.  It opens one
already-existing owner database through the shared read-only opener, holds one
SQLite read transaction, validates a closed schema/relationship contract, and
emits only decision-relevant typed identities and digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Callable, Iterable, Mapping, Sequence

from coordination_store import (
    CoordinationError,
    DEFAULT_DATABASE,
    canonical_json,
    digest_json,
    parse_coordination_envelope,
)
from owner_safe_sqlite import (
    UnsafeSQLitePathError,
    open_owner_database_readonly,
    validate_owner_database,
)
from routing_inventory_contract import (
    RoutingInventoryContractError,
    validate_inventory_record,
)


SNAPSHOT_SCHEMA = "twinfinity-coordination-truth-snapshot/v1"
HOLD_SCHEMA = "twinfinity-coordination-truth-snapshot-hold/v1"
ALLOWED_REPOSITORIES = {
    "twinfinityai/twinfinityapp",
    "jayendusharma/twinfinity-harness",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
ROLE_ORDER = ("planner", "development", "sre")
APPROVAL_V1 = "twinfinity.approval-proposal.v1"
APPROVAL_V2 = "twinfinity.approval-proposal.v2"
MAX_TABLE_ROWS = 20_000
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_ROUTING_OBJECTS = 10_000


class SnapshotHold(ValueError):
    """A stable, value-free, fail-closed snapshot outcome."""


# These digests cover the complete table_xinfo shape and every declared
# foreign-key tuple.  They are derived from the accepted source schemas, not
# from caller-supplied state.  Optional state rows may be empty; schema shape
# itself is never optional for a complete snapshot.
EXPECTED_SCHEMA_SHA256 = {
    "approval_current": "c9d9c3ca161078e6a477622a162fe20fe18e55854f7522abe83cc7a25ff7cc73",
    "approval_decisions": "fcbc0d8ffec5360aec9dd2cb02b9b6fadee3b57490eb8e58f6c7af1ff89fe97a",
    "approval_deliveries": "cc6fc4cfcd12d1e91076c67e4bf55a9b4528acd379db62a15cc08feff1f651cc",
    "approval_delivery_notices": "2eabd2f75d9700c497c65690297f894b8db8fa8ef3c91af5d90cd48ea032b149",
    "approval_effectivity": "118006a9f8f7a338f674897cc082e77756573a1bf502dbe1a6415ef6b8703daf",
    "approval_events": "463c886101c422e4cc875b156db69c526ab2d267d37690c5dbd5fa25c79310cf",
    "approval_interests": "9fdd8c06e6715f246dbc2c1ed623e88a54a112ded9c2eb3d5d430aef5a9a4c5c",
    "approval_proposal_notices": "7cb90892a40b878460341ec243ad4497cc1fcb67dfd3d8907b7abdf234ea6115",
    "approval_proposals": "90961c6fa8ede95a66b91aa6f956374bce67b2d93526dcc18fbe834afb6358e3",
    "approval_review_batches": "b37e33913fd66649216039d78cf7f4d2f10b9f46af0550c15a9df0a8da944249",
    "approval_revocations": "7304731d46b1a17f03b1e168b54de928882f37fc85deff89e7e49132ef4f5a59",
    "approval_semantic_contract_current": "d86372ac6c81ff4f30eb3fe5ce39496ee06afb1d56be25439ec1d201275c2f54",
    "approval_submissions": "d9cf9f7500451cbb842c2ac268e17bed05e502c3350b8a5769f1a064651303f9",
    "approval_user_events": "e90a3187779441dce1e51efba7ce6052fff0cbaf23192a78d3ee47bf00c45918",
    "coordination_admission_source_equivalence": "c545ab934d7fe1b55c495d2b24597cf151d5dc36fa98c0cf3b64099c0efa913e",
    "coordination_artifacts": "d6c140e8cd2657c63223e473da9c4d089062eaf36adee1eefd63365042277aec",
    "coordination_bootstrap_provenance": "1ff72d22efaa3657f60474d35b0dc37c1db2b281032a15b4e9cb721d52ab49fd",
    "coordination_capacity_current": "308699c69742121574d9d2c31242840cb41401d28b4a198f51b3d66000cff0b7",
    "coordination_capacity_policies": "3fa8000647f64ad36537a19849d49de6a4d759f326490f6c7e89dc57974a6466",
    "coordination_endpoint_rotation_rearms": "866ee22f124174a130b7fc7ba3f351024ee9719aa546506b072438b806389c2b",
    "coordination_events": "463c886101c422e4cc875b156db69c526ab2d267d37690c5dbd5fa25c79310cf",
    "coordination_items": "9c55081ac0ad800b9ba884fb8db4b76eef42ec117f30a25b8b85e75af26faf84",
    "coordination_messages": "46013307478e5d73d1651ff79a2fd97dccb22a470a251b88c055a0286e90159b",
    "coordination_pre_push_gates": "a8a72c5c8597f104cd1f603ecb3f11fcebaf2ac10ebe68d1fc9b272bb78078ea",
    "coordination_pre_push_publications": "406fd7da22dd64fc77b4011b91a6fd6ffa84debde0cf7871e0389604bedc23a7",
    "coordination_repository_git_registrations": "4b2e771ab1126f2cff5a8e3b55b4ebb5b2728cefbe1d8a45fa8bbdcc47232e4b",
    "coordination_supervisor_items": "743f562af5635c451daf98e10324e7a04fd8b47d2e2897935770dfe6f12f2fd8",
    "coordination_terminal_closeout_commits": "c5b573ce4cebe6098b3c0553b3457c3120ca1131b01f91b43116e0dcbffdcc57",
    "coordination_terminal_closeout_packets": "25ce7b6184f6c640a791256684f47f51b52ca92dd5c0413c3b19d5eaeffb9831",
    "coordination_terminal_outbox_publishers": "8d6ac961d150e7ee24be1a4775666b126a1811a40c66c0dd70b6de882f72dc5d",
    "coordination_terminal_outbox_readbacks": "f88fa6fcf11a2d17c33ffc1328021d43673e44bb8392cb69507baf2d061eefab",
    "coordination_terminal_outbox_recovery": "472595fa6eae65afbd95d518796969fe7428f61816e06350987df8b306f32bc4",
    "coordination_terminal_watches": "9303a60a40c4b1499fe3080f264e39ca89ebb4e05cfd4413640676966984e2ea",
    "coordination_wakes": "ef9554221a77cca724dffdbdbe711ba4e894e471ccd75b3b4f3db27f0f7f94cc",
    "executor_attempt_events": "a63261ac0d1eeb729753bb8a68d7280185513455e7e1e87fa28fb0542a424322",
    "executor_attempts": "f5a575fc8ba7be68de1057b3047f5fc031bf282300f541cbca640c7cd75d6d4a",
    "executor_registry_changes": "d82c388c700e58938ec4a237e2b451f7e77f81696a8f9e36af9e3a9214586588",
    "executor_registry_state": "426c448dbc322b2f175f51c4db5e9b6b28d33558430f369ef10a0be448084a9a",
    "executor_role_endpoint_aliases": "0659dbf44666448b5e34f0612bb2addcef84307e08299596208750c368b1c627",
    "executor_role_endpoint_current": "69b064520a250f549b9ee1ff5988606edc5599f0448d86c5f63fede755fc4309",
    "executor_role_endpoints": "9a2c12d5673d7bbffe509e2d58a0009090e4c9cefa003a0bb63bd003aab63f63",
    "github_current": "603db5aeeeaf564ea04a7e60cf1fbfb7d3f030663cb86c1bef81e8c82d23bb15",
    "github_outbox": "7dcc98532806d066d60d594edf0dd093e260c1ae1274809e90534ac3c57bbf44",
    "github_snapshots": "16a99c1850282aca3b532a19e0ed8fb71997e5a53683f0b8341a69778d2b4767",
    "hosted_operations": "0e6c91cbb11b414bed3b238cc82a6f613a7aebe0967a74f8ea5d5b873f3e9df7",
    "portfolio_dirty_events": "948b72bdef5afdd6f506506446d895808a571c161c718f3e39c2685e81f8540d",
    "portfolio_graph_current": "9d46f2be62ac9e329cba3591174ff8239ebf3f99642e10a66f8e10c1d5d29916",
    "portfolio_graph_nodes": "5c608f97c08976f63204052efeccc86e0b93591c90982b241e72027b470bfaaa",
    "portfolio_graph_relations": "9180c4ff8d5d232471761292efac5f24d71fde7ae4e610aaec683df4b7f9963c",
    "portfolio_graph_revisions": "9758f9a526e453e9e7caa64c8d9b18a3ccc6778f3becaea7282c468e96cf477f",
    "portfolio_pull_buffer_audits": "ca0a73f1021af2ef98eb5ddaf6a3f1e2d7fd66be7a66b403bad578bc5dca803c",
    "portfolio_pull_buffer_candidates": "7fd53caee9e4734470f997f6503403467bed73412e18ce107cc4bc647616d45e",
    "portfolio_pull_buffer_current": "9089065b68b38cb0aec366931f004779c506cae9863a4aee0242d2799291e15f",
    "portfolio_pull_buffer_retirements": "8ba3590f2fc9a4f20f32d7718d596d4076bedcae2ef373865665dbb5804cca8d",
    "portfolio_readiness_approval_consumptions": "9772309d36c29a023ad9f23d9ec47df441de8c3369d3c1619968b340e1a051b4",
    "portfolio_readiness_approval_requests": "5337a7092989292bd2e66f74172b50fe3fde657a4848aad48e4e367f0c96dc24",
    "portfolio_readiness_campaigns": "8e8dba2a610aad0693dca09a3e7d6362e85959c36e2d0245fbc77ff4398f0398",
    "portfolio_readiness_current": "5a15ef1492242c6593b7247387ba81986c5a9ac221a84e59e6f720ab24da587d",
    "portfolio_readiness_events": "22c43b49f9d0f175f278413e9884fcf99da78de003a239fbed1a4689f62179b9",
    "portfolio_readiness_gates": "10ec5e4636292fc4a937b74913e5d177176ce524280b9fcc3b425e57d5ca442a",
    "portfolio_readiness_receipt_pickups": "d4455c368cf3143fdf91279a7dee42751dcbd1d7fdc0d67a154134dadf993303",
    "portfolio_readiness_receipts": "544636170181a4edc947fd9bab3782635084057ea1ad2a6a440058471d5c55e7",
    "portfolio_readiness_resolution_action_completions": "d6dba9576623d418e6b356885346e98cce2e7bf79e86e47808a27a0d9b98989c",
    "portfolio_readiness_resolution_action_starts": "dc56379ed80ecac373696684bfeaacf29024e09487a7b1ed2f322949b59034de",
    "portfolio_readiness_resolution_contexts": "b0a7eae911dab0f94affd4d476255579852a470111fe6dc017d4fe6252b44cc3",
    "portfolio_readiness_resolution_cycles": "067b067fd067ca72f37e98b646cab829aa8e58b6d26845e4608860d0e8f5a270",
    "portfolio_readiness_resolution_notices": "697918ba8357a61aca773cbb86bb688b7345be62665d7df5d183e7120548fc46",
    "portfolio_readiness_revisit_notices": "e3544a13ef0473105890d4589e71227b6e2eb89d08218498b8564a6961089d79",
    "portfolio_readiness_revocation_notices": "760c2714759934aaf9d85f468f8d1d469a0af68b64025a1b3f6c9117fe30f2cd",
    "portfolio_readiness_source_equivalence": "ad4a38bdf13398f9100c30957f06bc0dacf164e08b21b3a34e45ca17126b9b69",
    "portfolio_ready_finalizations": "8793b99f6de4394082c0512931e278eff2218994f8e75c6ba42002b29c047037",
    "portfolio_ready_quarantines": "b961334eb685e1f44411c576f0bbe1347b93d9dabafdf95b4d5457c76610ed5f",
    "portfolio_scheduler_events": "a63d9202920cdf156b99d9fff09d1f509b6e5faeb6e0fc61d7960e3a8eebb3ab",
    "routing_deprecation_current": "dab0c9b37381bdc667578150dc15b44fec56968adae35f3081067c3f4aab38f7",
    "routing_deprecation_inventories": "e543f2bf1b1a0cda68c0b1d74393115423dfb83a9d155db25ef606f96ba8fc1e",
    "routing_deprecation_occurrences": "aeed41527c41d5c3857e5bfee9fbc6acd509b61e391ec41c0e9734385be13a3e",
    "routing_deprecation_promotions": "4d2fc062f111c981c63bcea2c6a3823c47b2f1851ea145ab46641361e1cf9f8e",
}
EXPECTED_DEFAULT_MANIFEST_SHA256 = (
    "c6289d383af6dc49bc15d88d48db9c9f351430551fba2ffd2dbea019e40cbdc6"
)


FAMILY_TABLES = {
    "capacity": (
        "coordination_capacity_policies", "coordination_capacity_current",
    ),
    "sources_graph": (
        "github_current", "portfolio_graph_revisions", "portfolio_graph_current",
        "portfolio_graph_nodes", "portfolio_graph_relations",
        "portfolio_scheduler_events",
        "coordination_bootstrap_provenance",
        "coordination_repository_git_registrations",
    ),
    "items_allocations_leases": (
        "coordination_items", "coordination_artifacts",
    ),
    "messages_admissions": (
        "coordination_messages", "coordination_supervisor_items",
    ),
    "attempts_watches": (
        "executor_attempts", "executor_attempt_events",
        "coordination_terminal_watches", "coordination_wakes",
    ),
    "readiness": (
        "portfolio_readiness_campaigns", "portfolio_readiness_current",
        "portfolio_readiness_receipts", "portfolio_readiness_gates",
        "portfolio_readiness_approval_requests",
        "portfolio_readiness_approval_consumptions",
        "portfolio_readiness_resolution_cycles",
        "portfolio_readiness_source_equivalence",
        "portfolio_readiness_events", "portfolio_readiness_receipt_pickups",
        "portfolio_readiness_resolution_notices",
        "portfolio_readiness_resolution_contexts",
        "portfolio_readiness_resolution_action_starts",
        "portfolio_readiness_resolution_action_completions",
        "portfolio_readiness_revisit_notices",
        "portfolio_readiness_revocation_notices",
    ),
    "pull_buffer": (
        "portfolio_pull_buffer_candidates", "portfolio_pull_buffer_current",
        "portfolio_pull_buffer_audits", "portfolio_pull_buffer_retirements",
        "portfolio_ready_finalizations", "portfolio_ready_quarantines",
    ),
    "approvals": (
        "approval_proposals", "approval_current", "approval_submissions",
        "approval_interests", "approval_decisions", "approval_deliveries",
        "approval_effectivity", "approval_revocations",
        "approval_semantic_contract_current",
        "approval_review_batches", "approval_user_events",
        "approval_proposal_notices", "approval_delivery_notices",
        "approval_events",
    ),
    "outbox": ("github_outbox",),
    "hosted_operations": ("hosted_operations",),
    "delivery_control": (
        "coordination_pre_push_gates", "coordination_pre_push_publications",
        "coordination_terminal_closeout_packets",
        "coordination_terminal_closeout_commits",
        "coordination_terminal_outbox_readbacks", "portfolio_dirty_events",
        "coordination_terminal_outbox_publishers",
        "coordination_terminal_outbox_recovery",
        "coordination_admission_source_equivalence",
        "coordination_endpoint_rotation_rearms",
    ),
    "routing_truth": (
        "routing_deprecation_current", "routing_deprecation_inventories",
        "routing_deprecation_promotions",
    ),
}


# Closed privacy-safe projections.  The reader may consume additional columns
# internally for validation, but no unlisted value is ever emitted.
SAFE_COLUMNS = {
    "coordination_capacity_policies": ("repository", "version", "development_limit", "shared_limit", "sre_limit", "authority_sha256"),
    "coordination_capacity_current": ("repository", "version"),
    "github_current": ("repository", "object_kind", "object_number", "payload_sha256"),
    "portfolio_graph_revisions": ("repository", "version", "parent_version", "accepted_main_sha", "graph_sha256"),
    "portfolio_graph_current": ("repository", "version", "observed_main_sha", "health"),
    "portfolio_graph_nodes": ("repository", "graph_version", "node_key", "issue_number", "role", "root_kind", "milestone_rank", "lane_key", "lane_order", "dispatchable", "priority_rank", "estimate_units", "development_units", "shared_units", "sre_units", "source_payload_sha256"),
    "portfolio_graph_relations": ("repository", "graph_version", "left_node_key", "right_node_key", "relation_kind", "source_payload_sha256"),
    "portfolio_scheduler_events": ("id", "repository", "graph_version", "decision_sha256", "node_key", "event_type", "reason_code"),
    "coordination_bootstrap_provenance": ("bootstrap_id", "manifest_sha256", "source_harness_repository", "source_harness_main_sha", "source_registry_sha256", "approved_goal_sha256", "application_repository", "application_main_sha", "archived_database_sha256"),
    "coordination_repository_git_registrations": ("id", "repository", "source_main_sha", "bootstrap_id", "bootstrap_manifest_sha256", "registration_sha256"),
    "executor_registry_changes": ("change_id", "config_sha256", "before_state_sha256", "after_state_sha256", "state", "version"),
    "executor_role_endpoint_aliases": ("alias", "role", "endpoint_id", "source"),
    "coordination_items": ("repository", "issue_number", "status", "allocation_class", "generation", "lease_manifest_sha256", "development_units", "shared_units", "sre_units", "source_payload_sha256", "version"),
    "coordination_artifacts": ("artifact_key", "repository", "issue_number", "generation", "content_sha256", "size_bytes", "retention_class", "state"),
    "coordination_messages": ("id", "recipient_session_id", "topic", "payload_sha256", "state"),
    "coordination_supervisor_items": ("repository", "issue_number", "status", "allocation_class", "version"),
    "executor_attempts": ("attempt_id", "role", "endpoint_id", "target_kind", "repository_scope", "target_progress_sha256", "terminal_progress_sha256", "lineage_repository", "lineage_issue_number", "lineage_generation", "lineage_lease_sha256", "lineage_sha256", "state", "exit_code", "version"),
    "executor_attempt_events": ("event_id", "attempt_id", "from_state", "to_state", "from_version", "to_version", "evidence_sha256"),
    "coordination_terminal_watches": ("watch_key", "repository", "issue_number", "generation", "lease_manifest_sha256", "state", "admission_message_id", "admission_payload_sha256", "claim_attempt_id", "attempts", "target_progress_sha256"),
    "coordination_wakes": ("wake_key", "message_id", "recipient_session_id", "message_payload_sha256", "target_progress_sha256", "state", "attempts"),
    "portfolio_readiness_campaigns": ("id", "repository", "issue_number", "generation", "item_version", "source_payload_sha256", "accepted_main_sha", "graph_version", "capacity_policy_version", "candidate_sha256", "worker_role", "plan_sha256", "parent_campaign_id", "transition_kind", "resolution_ordinal", "changed_evidence_sha256", "resolution_action_set_sha256", "approval_proposal_sha256", "approval_decision_sha256", "approval_execution_scope_sha256"),
    "portfolio_readiness_current": ("repository", "issue_number", "campaign_id", "state", "message_id", "attempt_id", "endpoint_id", "receipt_id", "resolution_cycles", "version", "finalized_candidate_id", "finalized_event_id"),
    "portfolio_readiness_receipts": ("id", "campaign_id", "verdict", "worker_role", "message_id", "attempt_id", "resolution_role", "resolution_action_set_sha256", "approval_proposal_sha256", "receipt_sha256"),
    "portfolio_readiness_gates": ("id", "campaign_id", "gate_key", "gate_sha256"),
    "portfolio_readiness_approval_requests": ("campaign_id", "receipt_id", "repository", "issue_number", "source_payload_sha256", "expected_approval_pending_version", "proposal_sha256", "submission_sha256", "execution_scope_sha256", "boundary"),
    "portfolio_readiness_approval_consumptions": ("request_campaign_id", "receipt_id", "proposal_sha256", "decision_sha256", "notice_message_id", "disposition", "successor_campaign_id", "effective_source_sha256"),
    "portfolio_readiness_resolution_cycles": ("parent_campaign_id", "receipt_id", "notice_message_id", "action_set_sha256", "context_sha256", "changed_evidence_sha256", "outcome", "successor_campaign_id", "result_sha256"),
    "portfolio_readiness_source_equivalence": ("request_campaign_id", "decision_sha256", "bound_source_sha256", "observed_source_sha256", "stable_source_sha256"),
    "portfolio_readiness_events": ("id", "campaign_id", "event_type", "payload_sha256"),
    "portfolio_readiness_receipt_pickups": ("campaign_id", "message_id", "attempt_id", "locator_sha256", "state", "attempts", "receipt_id", "attempt_token_sha256", "artifact_sha256", "artifact_size_bytes", "version"),
    "portfolio_readiness_resolution_notices": ("campaign_id", "receipt_id", "action_set_sha256", "message_id", "routed_endpoint_id", "expected_readiness_version"),
    "portfolio_readiness_resolution_contexts": ("notice_message_id", "campaign_id", "receipt_id", "action_set_sha256", "context_sha256"),
    "portfolio_readiness_resolution_action_starts": ("notice_message_id", "action_sha256", "action_index", "campaign_id", "receipt_id", "context_sha256", "kind", "expected_digest", "desired_digest", "action_input_sha256", "before_binding_sha256"),
    "portfolio_readiness_resolution_action_completions": ("notice_message_id", "action_sha256", "context_sha256", "after_binding_sha256"),
    "portfolio_readiness_revisit_notices": ("request_campaign_id", "proposal_sha256", "decision_sha256", "routed_endpoint_id", "message_id"),
    "portfolio_readiness_revocation_notices": ("campaign_id", "proposal_sha256", "decision_sha256", "prior_state", "routed_endpoint_id", "message_id"),
    "portfolio_pull_buffer_candidates": ("id", "repository", "issue_number", "generation", "item_version", "source_payload_sha256", "accepted_main_sha", "graph_version", "capacity_policy_version", "lane_key", "state", "verticality", "development_units", "shared_units", "sre_units", "artifact_content_sha256", "candidate_sha256", "readiness_campaign_id", "readiness_current_version", "readiness_plan_sha256", "readiness_receipt_id", "readiness_receipt_sha256"),
    "portfolio_pull_buffer_current": ("repository", "issue_number", "candidate_id"),
    "portfolio_pull_buffer_audits": ("id", "repository", "graph_version", "capacity_policy_version", "accepted_main_sha", "target_depth", "healthy_depth", "state", "audit_sha256"),
    "portfolio_pull_buffer_retirements": ("id", "repository", "issue_number", "candidate_id", "reason_sha256"),
    "portfolio_ready_finalizations": ("id", "repository", "issue_number", "generation", "prepared_candidate_id", "ready_candidate_id", "campaign_id", "receipt_id", "dirty_event_id", "finalization_sha256"),
    "portfolio_ready_quarantines": ("id", "repository", "request_sha256", "source_harness_repository", "source_harness_main_sha", "cutover_authority_sha256", "before_ready_inventory_sha256", "after_ready_inventory_sha256", "inspected_count", "preserved_count", "quarantined_count", "receipt_sha256"),
    "approval_proposals": ("proposal_sha256", "semantic_sha256", "decision_key", "repository", "owning_issue", "source_snapshot_sha256", "proposal_generation", "workstream", "boundary", "priority", "urgency", "supersedes_sha256"),
    "approval_current": ("repository", "owning_issue", "decision_key", "proposal_sha256"),
    "approval_submissions": ("submission_sha256", "proposal_sha256", "workstream"),
    "approval_interests": ("proposal_sha256", "workstream", "priority", "urgency", "latest_submission_sha256", "submission_count"),
    "approval_decisions": ("proposal_sha256", "decision_sha256", "decision", "selected_option_id", "selected_option_machine_outcome", "recipient_set_sha256", "execution_scope_sha256", "batch_sha256", "batch_answer_map_sha256", "option_map_sha256", "user_input_sha256", "owner_outbox_id"),
    "approval_deliveries": ("proposal_sha256", "decision_sha256", "state"),
    "approval_effectivity": ("proposal_sha256", "decision_sha256", "effective_source_sha256"),
    "approval_revocations": ("decision_sha256", "proposal_sha256", "user_input_sha256", "owner_outbox_id"),
    "approval_semantic_contract_current": ("singleton", "schema", "authority_sha256"),
    "approval_review_batches": ("batch_sha256", "repository", "proposal_count"),
    "approval_user_events": ("user_input_sha256", "batch_sha256", "batch_answer_map_sha256"),
    "approval_proposal_notices": ("proposal_sha256", "message_id"),
    "approval_delivery_notices": ("id", "proposal_sha256", "submission_sha256", "decision_sha256", "recipient_session_id", "readiness_campaign_id", "readiness_receipt_id", "expected_readiness_version", "source_payload_sha256", "routed_endpoint_id", "message_id"),
    "approval_events": ("id", "event_type", "payload_sha256"),
    "github_outbox": ("id", "repository", "object_kind", "object_number", "operation", "expected_source_sha256", "payload_sha256", "state"),
    "hosted_operations": ("id", "repository", "object_kind", "issue_number", "source_payload_sha256", "operation_kind", "authority_comment_id", "authority_body_sha256", "scope_sha256", "sre_units", "blocked_by_issue_number", "state", "receipt_outbox_id", "receipt_outcome", "receipt_payload_sha256"),
    "coordination_pre_push_gates": ("id", "repository", "issue_number", "generation", "source_payload_sha256", "lease_manifest_sha256", "admission_message_id", "admission_payload_sha256", "base_sha", "head_sha", "changed_paths_sha256", "changed_path_count", "lower_gate_exit_code", "compose_gate_exit_code", "head_unchanged", "cleanup_proven", "state", "evidence_sha256", "environment_provenance_sha256"),
    "coordination_pre_push_publications": ("id", "gate_id", "repository", "issue_number", "generation", "source_payload_sha256", "lease_manifest_sha256", "admission_message_id", "head_sha", "state"),
    "coordination_terminal_closeout_packets": ("closeout_key", "packet_sha256", "repository", "issue_number", "generation", "source_payload_sha256", "lease_manifest_sha256", "accountable_role", "endpoint_id", "terminal_watch_key", "activation_message_id", "activation_payload_sha256", "expected_item_version", "publication_pending_item_version", "terminal_receipt_sha256", "cleanup_evidence_sha256", "outbox_id", "outbox_payload_sha256", "graph_version", "graph_sha256", "graph_main_sha", "graph_node_key", "graph_binding_sha256"),
    "coordination_terminal_closeout_commits": ("closeout_key", "commit_sha256", "finalizer_attempt_id", "finalizer_attempt_version", "live_evidence_sha256", "remote_receipt_sha256", "prior_item_version", "done_item_version", "dirty_event_id"),
    "coordination_terminal_outbox_readbacks": ("outbox_id", "closeout_key", "remote_receipt_sha256", "published_body_sha256"),
    "coordination_terminal_outbox_publishers": ("outbox_id", "closeout_key", "binding_sha256"),
    "coordination_terminal_outbox_recovery": ("outbox_id", "readback_attempts", "retry_rounds", "state"),
    "portfolio_dirty_events": ("id", "repository", "issue_number", "release_item_version", "release_source_sha256", "event_sha256", "state", "attempts", "result_sha256"),
    "coordination_admission_source_equivalence": ("receipt_key", "preview_sha256", "repository", "issue_number", "generation", "message_id", "watch_key", "item_version", "bound_source_sha256", "current_source_sha256", "stable_source_sha256", "endpoint_id", "claim_attempt_id", "lease_manifest_sha256", "capacity_sha256", "outbox_id", "comment_id", "timeline_evidence_sha256", "receipt_sha256"),
    "coordination_endpoint_rotation_rearms": ("rearm_key", "preview_sha256", "change_id", "change_version", "repository", "issue_number", "generation", "message_id", "watch_key", "receipt_sha256"),
    "routing_deprecation_current": ("repository", "generation", "inventory_sha256", "version"),
    "routing_deprecation_inventories": ("inventory_sha256", "repository", "generation", "predecessor_inventory_sha256", "preview_sha256", "kind", "alias_source_sha256", "endpoint_state_sha256", "issue_179_source_sha256", "object_manifest_sha256", "occurrence_manifest_sha256", "object_count", "issue_count", "pull_request_count", "occurrence_count", "outbox_id", "state"),
    "routing_deprecation_promotions": ("repository", "generation", "prior_generation", "inventory_sha256", "preview_sha256"),
}


DIRECT_REPOSITORY_TABLES = {
    table
    for table, columns in SAFE_COLUMNS.items()
    if "repository" in columns
}


def _schema_record(connection: sqlite3.Connection, table: str) -> dict[str, Any]:
    columns = [
        {
            "name": str(row[1]), "type": str(row[2]),
            "notnull": int(row[3]), "pk": int(row[5]), "hidden": int(row[6]),
        }
        for row in connection.execute(f'PRAGMA table_xinfo("{table}")')
    ]
    foreign_keys = [
        {
            "id": int(row[0]), "seq": int(row[1]), "table": str(row[2]),
            "from": str(row[3]), "to": str(row[4]),
            "on_update": str(row[5]), "on_delete": str(row[6]),
            "match": str(row[7]),
        }
        for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')
    ]
    foreign_keys.sort(key=lambda value: (value["id"], value["seq"]))
    return {"columns": columns, "foreign_keys": foreign_keys}


def _validate_schema(connection: sqlite3.Connection) -> dict[str, Any]:
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        )
    }
    if present != set(EXPECTED_SCHEMA_SHA256):
        raise SnapshotHold("COORDINATION_TRUTH_SCHEMA_INCOMPLETE")
    tables = []
    for table in sorted(EXPECTED_SCHEMA_SHA256):
        actual = digest_json(_schema_record(connection, table))
        if actual != EXPECTED_SCHEMA_SHA256[table]:
            raise SnapshotHold("COORDINATION_TRUTH_SCHEMA_DRIFT")
        tables.append({"table": table, "schema_sha256": actual})
    defaults = [
        {
            "table": table,
            "columns": [
                {"name": str(row[1]), "default": row[4]}
                for row in connection.execute(f'PRAGMA table_xinfo("{table}")')
            ],
        }
        for table in sorted(EXPECTED_SCHEMA_SHA256)
    ]
    defaults_sha256 = digest_json(defaults)
    if defaults_sha256 != EXPECTED_DEFAULT_MANIFEST_SHA256:
        raise SnapshotHold("COORDINATION_TRUTH_SCHEMA_DRIFT")
    result = {
        "tables": tables,
        "defaults_sha256": defaults_sha256,
    }
    result["manifest_sha256"] = digest_json(result["tables"])
    return result


def _select(
    connection: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
    *,
    where: str = "",
    parameters: Sequence[Any] = (),
) -> list[dict[str, Any]]:
    if table not in EXPECTED_SCHEMA_SHA256:
        raise SnapshotHold("COORDINATION_TRUTH_SCHEMA_INTERNAL")
    known = {item["name"] for item in _schema_record(connection, table)["columns"]}
    if not set(columns).issubset(known):
        raise SnapshotHold("COORDINATION_TRUTH_SCHEMA_DRIFT")
    projection = ",".join(f'"{column}"' for column in columns)
    sql = f'SELECT {projection} FROM "{table}"'
    if where:
        sql += " WHERE " + where
    rows = connection.execute(sql, tuple(parameters)).fetchmany(MAX_TABLE_ROWS + 1)
    if len(rows) > MAX_TABLE_ROWS:
        raise SnapshotHold("COORDINATION_TRUTH_RESOURCE_LIMIT")
    return [dict(row) for row in rows]


def _select_all(
    connection: sqlite3.Connection,
    table: str,
    *,
    where: str = "",
    parameters: Sequence[Any] = (),
) -> list[dict[str, Any]]:
    columns = tuple(
        item["name"] for item in _schema_record(connection, table)["columns"]
    )
    return _select(
        connection, table, columns, where=where, parameters=parameters
    )


def _validate_safe_value(name: str, value: Any) -> None:
    if value is None:
        return
    integer_name = (
        name in {
            "id", "message_id", "admission_message_id", "owner_outbox_id",
            "receipt_outbox_id", "outbox_id", "gate_id", "campaign_id",
            "parent_campaign_id", "successor_campaign_id", "receipt_id",
            "notice_message_id", "candidate_id", "prepared_candidate_id",
            "ready_candidate_id", "finalized_candidate_id", "finalized_event_id",
            "dirty_event_id", "event_id", "authority_comment_id", "comment_id",
            "readiness_campaign_id", "readiness_receipt_id",
            "request_campaign_id", "owning_issue",
            "blocked_by_issue_number",
        }
        or name.endswith("_number")
        or name.endswith("_generation")
        or name.endswith("_version") or name.endswith("_units")
        or name.endswith("_count") or name.endswith("_limit")
        or name in {
            "version", "generation", "singleton", "ordinal", "attempts",
            "exit_code", "milestone_rank", "lane_order", "dispatchable",
            "priority_rank", "estimate_units", "resolution_cycles",
            "resolution_ordinal", "target_depth", "healthy_depth",
            "size_bytes", "lower_gate_exit_code", "compose_gate_exit_code",
            "changed_path_count", "head_unchanged", "cleanup_proven",
            "action_index", "artifact_size_bytes", "readback_attempts",
            "retry_rounds",
        }
    )
    if integer_name:
        if type(value) is not int:
            raise SnapshotHold("COORDINATION_TRUTH_RUNTIME_TYPE_INVALID")
        return
    if name.endswith("sha256") or name in {"expected_digest", "desired_digest"}:
        if type(value) is not str or SHA256.fullmatch(value) is None:
            raise SnapshotHold("COORDINATION_TRUTH_DIGEST_INVALID")
        return
    if name.endswith("_main_sha") or name in {
        "accepted_main_sha", "observed_main_sha", "base_sha", "head_sha",
        "graph_main_sha", "source_harness_main_sha",
    }:
        if type(value) is not str or GIT_SHA.fullmatch(value) is None:
            raise SnapshotHold("COORDINATION_TRUTH_GIT_IDENTITY_INVALID")
        return
    if type(value) is not str or SAFE_TOKEN.fullmatch(value) is None:
        raise SnapshotHold("COORDINATION_TRUTH_IDENTITY_INVALID")


def _project_rows(rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for row in rows:
        item = {column: row[column] for column in columns}
        for name, value in item.items():
            _validate_safe_value(name, value)
        projected.append(item)
    projected.sort(key=canonical_json)
    return projected


def _table_rows(
    connection: sqlite3.Connection,
    table: str,
    repository: str,
    *,
    where: str | None = None,
    parameters: Sequence[Any] = (),
) -> list[dict[str, Any]]:
    columns = SAFE_COLUMNS[table]
    if where is None and table in DIRECT_REPOSITORY_TABLES:
        where, parameters = "repository=?", (repository,)
    return _project_rows(
        _select(connection, table, columns, where=where or "", parameters=parameters),
        columns,
    )


def _in_where(column: str, values: Sequence[Any]) -> tuple[str, tuple[Any, ...]]:
    if not values:
        return "0", ()
    return f'"{column}" IN ({",".join("?" for _ in values)})', tuple(values)


def _family(tables: Mapping[str, list[dict[str, Any]]]) -> dict[str, Any]:
    normalized = {name: tables[name] for name in sorted(tables)}
    return {"tables": normalized, "manifest_sha256": digest_json(normalized)}


def _approval_contract_rows(
    connection: sqlite3.Connection,
) -> list[dict[str, Any]]:
    rows = _select(
        connection, "approval_semantic_contract_current",
        ("singleton", "schema", "authority_sha256"),
    )
    if not rows:
        return [{
            "singleton": 1,
            "schema": APPROVAL_V1,
            "authority_sha256": "0" * 64,
        }]
    return rows


def _global_current(connection: sqlite3.Connection) -> dict[str, Any]:
    states = _select(connection, "executor_registry_state", ("singleton", "cutover_state", "version"))
    if len(states) != 1 or states[0]["singleton"] != 1:
        raise SnapshotHold("COORDINATION_TRUTH_REGISTRY_INVALID")
    pointers = _select(
        connection, "executor_role_endpoint_current",
        ("role", "endpoint_id", "pointer_version"),
    )
    endpoints = {
        row["endpoint_id"]: row
        for row in _select(
            connection, "executor_role_endpoints",
            ("endpoint_id", "role", "version", "config_sha256"),
        )
    }
    if sorted(row["role"] for row in pointers) != sorted(ROLE_ORDER):
        raise SnapshotHold("COORDINATION_TRUTH_REGISTRY_INVALID")
    bindings = []
    for pointer in pointers:
        endpoint = endpoints.get(pointer["endpoint_id"])
        if endpoint is None or endpoint["role"] != pointer["role"]:
            raise SnapshotHold("COORDINATION_TRUTH_REGISTRY_INVALID")
        bindings.append({
            "role": pointer["role"], "endpoint_id": pointer["endpoint_id"],
            "endpoint_version": endpoint["version"],
            "pointer_version": pointer["pointer_version"],
            "config_sha256": endpoint["config_sha256"],
        })
    bindings.sort(key=lambda item: ROLE_ORDER.index(item["role"]))
    contract = _approval_contract_rows(connection)
    if (
        len(contract) != 1 or contract[0]["singleton"] != 1
        or contract[0]["schema"] not in {APPROVAL_V1, APPROVAL_V2}
        or not SHA256.fullmatch(contract[0]["authority_sha256"])
    ):
        raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_CONTRACT_INVALID")
    aliases = _table_rows(
        connection, "executor_role_endpoint_aliases", ""
    )
    if any(
        row["endpoint_id"] not in endpoints
        or endpoints[row["endpoint_id"]]["role"] != row["role"]
        for row in aliases
    ):
        raise SnapshotHold("COORDINATION_TRUTH_REGISTRY_ALIAS_INVALID")
    changes = _table_rows(connection, "executor_registry_changes", "")
    result = {
        "registry": {
            "cutover_state": states[0]["cutover_state"],
            "version": states[0]["version"],
        },
        "role_endpoints": bindings,
        "role_endpoint_aliases": aliases,
        "registry_changes": changes,
        "approval_semantic_contract": contract[0],
    }
    for item in [result["registry"], *bindings, *aliases, *changes, contract[0]]:
        for name, value in item.items():
            _validate_safe_value(name, value)
    return result


def _capacity_family(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    policies = _table_rows(connection, "coordination_capacity_policies", repository)
    current = _table_rows(connection, "coordination_capacity_current", repository)
    if len(current) != 1:
        raise SnapshotHold("COORDINATION_TRUTH_CAPACITY_CURRENT_REQUIRED")
    matches = [row for row in policies if row["version"] == current[0]["version"]]
    if len(matches) != 1:
        raise SnapshotHold("COORDINATION_TRUTH_CAPACITY_CURRENT_INVALID")
    items = _table_rows(connection, "coordination_items", repository)
    occupancy_rows = []
    for allocation_class in ("ACTIVE", "RETAINED"):
        occupancy_rows.append({
            "allocation_class": allocation_class,
            **{
                name: sum(
                    int(item[name]) for item in items
                    if item["allocation_class"] == allocation_class
                )
                for name in ("development_units", "shared_units", "sre_units")
            },
        })
    occupancy = {
        name: sum(row[name] for row in occupancy_rows)
        for name in ("development_units", "shared_units", "sre_units")
    }
    limits = {
        "development_units": matches[0]["development_limit"],
        "shared_units": matches[0]["shared_limit"],
        "sre_units": matches[0]["sre_limit"],
    }
    if any(occupancy[name] > limits[name] for name in occupancy):
        raise SnapshotHold("COORDINATION_TRUTH_CAPACITY_EXCEEDED")
    available = {
        name.replace("_units", "_available"): limits[name] - occupancy[name]
        for name in occupancy
    }
    return _family({
        "coordination_capacity_current": current,
        "coordination_capacity_policies": policies,
        "occupancy": [
            *occupancy_rows,
            {"allocation_class": "AVAILABLE", **available},
        ],
    })


def _sources_graph_family(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    current = _table_rows(connection, "github_current", repository)
    for pointer in current:
        matches = connection.execute(
            "SELECT payload_json FROM github_snapshots WHERE repository=? "
            "AND object_kind=? AND object_number=? AND payload_sha256=?",
            (repository, pointer["object_kind"], pointer["object_number"], pointer["payload_sha256"]),
        ).fetchall()
        if len(matches) != 1:
            raise SnapshotHold("COORDINATION_TRUTH_SOURCE_POINTER_INVALID")
        payload = _strict_json(
            matches[0]["payload_json"], "COORDINATION_TRUTH_SOURCE_INVALID"
        )
        if (
            digest_json(payload) != pointer["payload_sha256"]
            or ("number" in payload and payload["number"] != pointer["object_number"])
        ):
            raise SnapshotHold("COORDINATION_TRUTH_SOURCE_INVALID")
    revisions = _table_rows(connection, "portfolio_graph_revisions", repository)
    graph_current = _table_rows(connection, "portfolio_graph_current", repository)
    nodes = _table_rows(connection, "portfolio_graph_nodes", repository)
    relations = _table_rows(connection, "portfolio_graph_relations", repository)
    scheduler = _table_rows(connection, "portfolio_scheduler_events", repository)
    registrations = _table_rows(
        connection, "coordination_repository_git_registrations", repository
    )
    bootstrap_raw = _select(
        connection, "coordination_bootstrap_provenance",
        SAFE_COLUMNS["coordination_bootstrap_provenance"],
        where="source_harness_repository=? OR application_repository=?",
        parameters=(repository, repository),
    )
    bootstraps = _project_rows(
        bootstrap_raw, SAFE_COLUMNS["coordination_bootstrap_provenance"]
    )
    if (revisions or nodes or relations) and len(graph_current) != 1:
        raise SnapshotHold("COORDINATION_TRUTH_GRAPH_CURRENT_REQUIRED")
    revision_versions = {row["version"] for row in revisions}
    if graph_current and graph_current[0]["version"] not in revision_versions:
        raise SnapshotHold("COORDINATION_TRUTH_GRAPH_CURRENT_INVALID")
    if any(row["graph_version"] not in revision_versions for row in nodes + relations + scheduler):
        raise SnapshotHold("COORDINATION_TRUTH_GRAPH_RELATION_INVALID")
    node_ids = {(row["graph_version"], row["node_key"]) for row in nodes}
    for relation in relations:
        if (
            (relation["graph_version"], relation["left_node_key"]) not in node_ids
            or (relation["graph_version"], relation["right_node_key"]) not in node_ids
        ):
            raise SnapshotHold("COORDINATION_TRUTH_GRAPH_RELATION_INVALID")
    bootstrap_by_id = {row["bootstrap_id"]: row for row in bootstraps}
    for registration in registrations:
        bootstrap = bootstrap_by_id.get(registration["bootstrap_id"])
        if (
            bootstrap is None
            or bootstrap["manifest_sha256"]
            != registration["bootstrap_manifest_sha256"]
            or (
                repository == bootstrap["application_repository"]
                and registration["source_main_sha"]
                != bootstrap["application_main_sha"]
            )
            or (
                repository == bootstrap["source_harness_repository"]
                and registration["source_main_sha"]
                != bootstrap["source_harness_main_sha"]
            )
            or repository not in {
                bootstrap["application_repository"],
                bootstrap["source_harness_repository"],
            }
        ):
            raise SnapshotHold("COORDINATION_TRUTH_GIT_REGISTRATION_INVALID")
    return _family({
        "coordination_bootstrap_provenance": bootstraps,
        "coordination_repository_git_registrations": registrations,
        "github_current": current,
        "portfolio_graph_current": graph_current,
        "portfolio_graph_nodes": nodes,
        "portfolio_graph_relations": relations,
        "portfolio_graph_revisions": revisions,
        "portfolio_scheduler_events": scheduler,
    })


def _items_family(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    items = _table_rows(connection, "coordination_items", repository)
    artifacts = _table_rows(connection, "coordination_artifacts", repository)
    sources = {
        row["payload_sha256"]
        for row in _select(
            connection, "github_snapshots", ("payload_sha256",),
            where="repository=?", parameters=(repository,),
        )
    }
    current_sources = {
        int(row["object_number"]): str(row["payload_sha256"])
        for row in _select(
            connection, "github_current", ("object_number", "payload_sha256"),
            where="repository=? AND object_kind='issue'",
            parameters=(repository,),
        )
    }
    if any(item["source_payload_sha256"] not in sources for item in items):
        raise SnapshotHold("COORDINATION_TRUTH_ITEM_SOURCE_INVALID")
    if any(
        item["allocation_class"] in {"ACTIVE", "RETAINED"}
        and current_sources.get(item["issue_number"])
        != item["source_payload_sha256"]
        for item in items
    ):
        raise SnapshotHold("COORDINATION_TRUTH_ITEM_CURRENT_SOURCE_INVALID")
    item_keys = {(row["issue_number"], row["generation"]) for row in items}
    if any((row["issue_number"], row["generation"]) not in item_keys for row in artifacts):
        raise SnapshotHold("COORDINATION_TRUTH_ARTIFACT_OWNER_INVALID")
    return _family({"coordination_items": items, "coordination_artifacts": artifacts})


def _messages_family(connection: sqlite3.Connection, repository: str) -> tuple[dict[str, Any], set[int]]:
    raw = _select(
        connection, "coordination_messages",
        (*SAFE_COLUMNS["coordination_messages"], "payload_json"),
        where="json_extract(payload_json,'$.source.repository')=?",
        parameters=(repository,),
    )
    selected = []
    ids: set[int] = set()
    for row in raw:
        try:
            envelope = parse_coordination_envelope(row["payload_json"])
        except CoordinationError as exc:
            raise SnapshotHold("COORDINATION_TRUTH_MESSAGE_INVALID") from exc
        if envelope.payload_sha256 != row["payload_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_MESSAGE_DIGEST_INVALID")
        source = envelope.payload.get("source")
        if not isinstance(source, dict) or source.get("repository") != repository:
            raise SnapshotHold("COORDINATION_TRUTH_MESSAGE_ATTRIBUTION_INVALID")
        ids.add(int(row["id"]))
        selected.append({name: row[name] for name in SAFE_COLUMNS["coordination_messages"]})
    return _family({
        "coordination_messages": _project_rows(selected, SAFE_COLUMNS["coordination_messages"]),
        "coordination_supervisor_items": _table_rows(connection, "coordination_supervisor_items", repository),
    }), ids


def _readiness_family(connection: sqlite3.Connection, repository: str) -> tuple[dict[str, Any], set[str], set[int]]:
    campaigns = _table_rows(connection, "portfolio_readiness_campaigns", repository)
    campaign_ids = [row["id"] for row in campaigns]
    campaign_by_id = {row["id"]: row for row in campaigns}
    current = _table_rows(connection, "portfolio_readiness_current", repository)
    if campaigns:
        current_issues = {row["issue_number"] for row in current}
        if not {row["issue_number"] for row in campaigns}.issubset(current_issues):
            raise SnapshotHold("COORDINATION_TRUTH_READINESS_CURRENT_REQUIRED")
    children: dict[str, list[dict[str, Any]]] = {}
    for table, key in (
        ("portfolio_readiness_receipts", "campaign_id"),
        ("portfolio_readiness_gates", "campaign_id"),
        ("portfolio_readiness_approval_consumptions", "request_campaign_id"),
        ("portfolio_readiness_resolution_cycles", "parent_campaign_id"),
        ("portfolio_readiness_source_equivalence", "request_campaign_id"),
        ("portfolio_readiness_events", "campaign_id"),
        ("portfolio_readiness_receipt_pickups", "campaign_id"),
        ("portfolio_readiness_resolution_notices", "campaign_id"),
        ("portfolio_readiness_resolution_contexts", "campaign_id"),
        ("portfolio_readiness_resolution_action_starts", "campaign_id"),
        ("portfolio_readiness_revisit_notices", "request_campaign_id"),
        ("portfolio_readiness_revocation_notices", "campaign_id"),
    ):
        where, values = _in_where(key, campaign_ids)
        children[table] = _table_rows(connection, table, repository, where=where, parameters=values)
    requests = _table_rows(connection, "portfolio_readiness_approval_requests", repository)
    children["portfolio_readiness_approval_requests"] = requests
    notice_ids = [
        row["notice_message_id"]
        for row in children["portfolio_readiness_resolution_action_starts"]
    ]
    where, values = _in_where("notice_message_id", notice_ids)
    children["portfolio_readiness_resolution_action_completions"] = _table_rows(
        connection,
        "portfolio_readiness_resolution_action_completions",
        repository,
        where=where,
        parameters=values,
    )
    receipt_ids = {row["id"] for row in children["portfolio_readiness_receipts"]}
    attempt_ids = {str(row["attempt_id"]) for row in current if row["attempt_id"] is not None}
    attempt_ids.update(str(row["attempt_id"]) for row in children["portfolio_readiness_receipts"] if row["attempt_id"] is not None)
    message_ids = {int(row["message_id"]) for row in current if row["message_id"] is not None}
    message_ids.update(int(row["message_id"]) for row in children["portfolio_readiness_receipts"] if row["message_id"] is not None)
    for table in (
        "portfolio_readiness_receipt_pickups",
        "portfolio_readiness_resolution_notices",
        "portfolio_readiness_revisit_notices",
        "portfolio_readiness_revocation_notices",
    ):
        message_ids.update(
            int(row["message_id"])
            for row in children[table]
            if row["message_id"] is not None
        )
    message_ids.update(
        int(row["notice_message_id"])
        for row in children["portfolio_readiness_resolution_contexts"]
    )
    attempt_ids.update(
        str(row["attempt_id"])
        for row in children["portfolio_readiness_receipt_pickups"]
        if row["attempt_id"] is not None
    )
    receipt_campaign = {
        row["id"]: row["campaign_id"]
        for row in children["portfolio_readiness_receipts"]
    }
    if any(
        row["campaign_id"] not in campaign_by_id
        or campaign_by_id[row["campaign_id"]]["issue_number"]
        != row["issue_number"]
        or (
            row["receipt_id"] is not None
            and receipt_campaign.get(row["receipt_id"]) != row["campaign_id"]
        )
        for row in current
    ):
        raise SnapshotHold("COORDINATION_TRUTH_READINESS_CURRENT_INVALID")
    if any(row["receipt_id"] is not None and row["receipt_id"] not in receipt_ids for row in current):
        raise SnapshotHold("COORDINATION_TRUTH_READINESS_RECEIPT_INVALID")
    for table in (
        "portfolio_readiness_approval_requests",
        "portfolio_readiness_resolution_notices",
        "portfolio_readiness_resolution_contexts",
        "portfolio_readiness_resolution_action_starts",
    ):
        if any(
            row["receipt_id"] not in receipt_ids
            or receipt_campaign.get(row["receipt_id"])
            != row.get("campaign_id", row.get("request_campaign_id"))
            for row in children[table]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_READINESS_RELATIONSHIP_INVALID")
    if any(
        row["receipt_id"] is not None
        and receipt_campaign.get(row["receipt_id"]) != row["campaign_id"]
        for row in children["portfolio_readiness_receipt_pickups"]
    ):
        raise SnapshotHold("COORDINATION_TRUTH_READINESS_RELATIONSHIP_INVALID")
    starts = {
        (row["notice_message_id"], row["action_sha256"]): row
        for row in children["portfolio_readiness_resolution_action_starts"]
    }
    if any(
        starts.get((row["notice_message_id"], row["action_sha256"]), {}).get(
            "context_sha256"
        )
        != row["context_sha256"]
        for row in children[
            "portfolio_readiness_resolution_action_completions"
        ]
    ):
        raise SnapshotHold("COORDINATION_TRUTH_READINESS_RELATIONSHIP_INVALID")
    known_endpoints = {
        str(row["endpoint_id"])
        for row in _select(
            connection, "executor_role_endpoint_current", ("endpoint_id",)
        )
    }
    endpoint_rows = [
        *current,
        *children["portfolio_readiness_resolution_notices"],
        *children["portfolio_readiness_revisit_notices"],
        *children["portfolio_readiness_revocation_notices"],
    ]
    if any(
        row.get("endpoint_id", row.get("routed_endpoint_id")) is not None
        and row.get("endpoint_id", row.get("routed_endpoint_id"))
        not in known_endpoints
        for row in endpoint_rows
    ):
        raise SnapshotHold("COORDINATION_TRUTH_READINESS_ENDPOINT_INVALID")
    tables = {
        "portfolio_readiness_campaigns": campaigns,
        "portfolio_readiness_current": current,
        **children,
    }
    return _family(tables), attempt_ids, message_ids


def _attempts_family(
    connection: sqlite3.Connection,
    repository: str,
    readiness_attempts: set[str],
) -> tuple[dict[str, Any], set[int]]:
    attempts = _select(
        connection, "executor_attempts", SAFE_COLUMNS["executor_attempts"],
        where=("repository_scope=? OR lineage_repository=?" +
               (f' OR attempt_id IN ({",".join("?" for _ in readiness_attempts)})' if readiness_attempts else "")),
        parameters=(repository, repository, *sorted(readiness_attempts)),
    )
    attempts = _project_rows(attempts, SAFE_COLUMNS["executor_attempts"])
    attempt_ids = [row["attempt_id"] for row in attempts]
    if not readiness_attempts.issubset(set(attempt_ids)):
        raise SnapshotHold("COORDINATION_TRUTH_READINESS_ATTEMPT_INVALID")
    if any(
        (
            row["repository_scope"] is not None
            and row["repository_scope"] != repository
        )
        or (
            row["lineage_repository"] is not None
            and row["lineage_repository"] != repository
        )
        for row in attempts
    ):
        raise SnapshotHold("COORDINATION_TRUTH_ATTEMPT_ATTRIBUTION_INVALID")
    where, values = _in_where("attempt_id", attempt_ids)
    events = _table_rows(connection, "executor_attempt_events", repository, where=where, parameters=values)
    watches = _table_rows(connection, "coordination_terminal_watches", repository)
    known_attempts = set(attempt_ids)
    if any(row["claim_attempt_id"] is not None and row["claim_attempt_id"] not in known_attempts for row in watches):
        raise SnapshotHold("COORDINATION_TRUTH_WATCH_ATTEMPT_INVALID")
    if any(
        (
            row["admission_message_id"] is None
            or row["admission_payload_sha256"] is None
        )
        for row in watches
    ):
        raise SnapshotHold("COORDINATION_TRUTH_WATCH_ADMISSION_INVALID")
    watch_message_ids = {
        int(row["admission_message_id"])
        for row in watches if row["admission_message_id"] is not None
    }
    wake_rows = _select(connection, "coordination_wakes", SAFE_COLUMNS["coordination_wakes"])
    wakes = _project_rows(
        [row for row in wake_rows if int(row["message_id"]) in watch_message_ids],
        SAFE_COLUMNS["coordination_wakes"],
    )
    watch_payloads = {
        row["admission_message_id"]: row["admission_payload_sha256"]
        for row in watches
    }
    if any(
        row["message_payload_sha256"] != watch_payloads.get(row["message_id"])
        for row in wakes
    ):
        raise SnapshotHold("COORDINATION_TRUTH_WAKE_RELATIONSHIP_INVALID")
    return _family({
        "coordination_terminal_watches": watches,
        "coordination_wakes": wakes,
        "executor_attempt_events": events,
        "executor_attempts": attempts,
    }), watch_message_ids


def _pull_family(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    tables = {
        table: _table_rows(connection, table, repository)
        for table in FAMILY_TABLES["pull_buffer"]
    }
    candidates = {row["id"]: row for row in tables["portfolio_pull_buffer_candidates"]}
    item_rows = {
        (int(row["issue_number"]), int(row["generation"])): row
        for row in _select(
            connection, "coordination_items",
            ("issue_number", "generation", "version", "source_payload_sha256"),
            where="repository=?", parameters=(repository,),
        )
    }
    graph_versions = {
        int(row["version"])
        for row in _select(
            connection, "portfolio_graph_revisions", ("version",),
            where="repository=?", parameters=(repository,),
        )
    }
    policy_versions = {
        int(row["version"])
        for row in _select(
            connection, "coordination_capacity_policies", ("version",),
            where="repository=?", parameters=(repository,),
        )
    }
    campaign_rows = _select(
        connection, "portfolio_readiness_campaigns",
        ("id", "issue_number", "generation"),
        where="repository=?", parameters=(repository,),
    )
    campaigns = {
        int(row["id"]): (int(row["issue_number"]), int(row["generation"]))
        for row in campaign_rows
    }
    receipt_where, receipt_values = _in_where("campaign_id", sorted(campaigns))
    receipts = {
        int(row["id"]): int(row["campaign_id"])
        for row in _select(
            connection, "portfolio_readiness_receipts", ("id", "campaign_id"),
            where=receipt_where, parameters=receipt_values,
        )
    }
    artifacts = {
        (int(row["issue_number"]), int(row["generation"]), str(row["content_sha256"]))
        for row in _select(
            connection, "coordination_artifacts",
            ("issue_number", "generation", "content_sha256"),
            where="repository=?", parameters=(repository,),
        )
    }
    for candidate in candidates.values():
        item = item_rows.get((candidate["issue_number"], candidate["generation"]))
        campaign = (
            None
            if candidate["readiness_campaign_id"] is None
            else campaigns.get(candidate["readiness_campaign_id"])
        )
        if (
            item is None
            or int(item["version"]) != candidate["item_version"]
            or item["source_payload_sha256"] != candidate["source_payload_sha256"]
            or candidate["graph_version"] not in graph_versions
            or candidate["capacity_policy_version"] not in policy_versions
            or (
                candidate["artifact_content_sha256"] is not None
                and (
                    candidate["issue_number"], candidate["generation"],
                    candidate["artifact_content_sha256"],
                ) not in artifacts
            )
            or (
                candidate["readiness_campaign_id"] is not None
                and campaign
                != (candidate["issue_number"], candidate["generation"])
            )
            or (
                candidate["readiness_receipt_id"] is not None
                and receipts.get(candidate["readiness_receipt_id"])
                != candidate["readiness_campaign_id"]
            )
        ):
            raise SnapshotHold("COORDINATION_TRUTH_PULL_CANDIDATE_INVALID")
    if any(
        row["candidate_id"] not in candidates
        or candidates[row["candidate_id"]]["issue_number"] != row["issue_number"]
        for row in tables["portfolio_pull_buffer_current"]
    ):
        raise SnapshotHold("COORDINATION_TRUTH_PULL_CURRENT_INVALID")
    if any(
        row["candidate_id"] not in candidates
        or candidates[row["candidate_id"]]["issue_number"] != row["issue_number"]
        for row in tables["portfolio_pull_buffer_retirements"]
    ):
        raise SnapshotHold("COORDINATION_TRUTH_PULL_RETIREMENT_INVALID")
    if any(
        row["graph_version"] not in graph_versions
        or row["capacity_policy_version"] not in policy_versions
        for row in tables["portfolio_pull_buffer_audits"]
    ):
        raise SnapshotHold("COORDINATION_TRUTH_PULL_AUDIT_INVALID")
    for row in tables["portfolio_ready_finalizations"]:
        prepared = candidates.get(row["prepared_candidate_id"])
        ready = candidates.get(row["ready_candidate_id"])
        if (
            prepared is None
            or ready is None
            or prepared["issue_number"] != row["issue_number"]
            or ready["issue_number"] != row["issue_number"]
            or campaigns.get(row["campaign_id"])
            != (row["issue_number"], row["generation"])
            or receipts.get(row["receipt_id"]) != row["campaign_id"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_READY_FINALIZATION_INVALID")
    return _family(tables)


APPROVAL_PACKET_KEYS = {
    "schema", "decision_key", "repository", "owning_issue",
    "source_snapshot_sha256", "execution_scope_sha256",
    "requester_session_id", "recipient_session_id", "workstream", "boundary",
    "priority", "urgency", "summary", "question", "requested_action",
    "target", "affected_issues", "blocked_mutation", "immediate_beneficiary",
    "evidence", "risk", "drift_guards", "prohibited_side_effects", "options",
    "recommendation", "expires_at",
}


def _strict_json_value(raw: str, error: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise SnapshotHold(error)
            result[key] = value
        return result

    def constant(_value: str) -> Any:
        raise SnapshotHold(error)

    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 262_144:
        raise SnapshotHold(error)
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise SnapshotHold(error) from exc
    if canonical_json(value) != raw:
        raise SnapshotHold(error)
    return value


def _strict_json(raw: str, error: str) -> dict[str, Any]:
    value = _strict_json_value(raw, error)
    if not isinstance(value, dict):
        raise SnapshotHold(error)
    return value


def _approval_semantic(packet: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "schema", "decision_key", "repository", "owning_issue",
        "source_snapshot_sha256", "execution_scope_sha256", "boundary",
        "summary", "question", "requested_action", "target", "affected_issues",
        "blocked_mutation", "immediate_beneficiary", "risk", "drift_guards",
        "prohibited_side_effects", "options", "recommendation", "expires_at",
    ]
    if packet["schema"] == APPROVAL_V2:
        keys.append("evidence")
    return {key: packet[key] for key in keys}


def _approvals_family(
    connection: sqlite3.Connection,
    repository: str,
    outboxes: Mapping[int, Mapping[str, Any]],
) -> tuple[dict[str, Any], set[int]]:
    proposal_raw = _select(
        connection, "approval_proposals",
        (*SAFE_COLUMNS["approval_proposals"], "requester_session_id", "recipient_session_id", "packet_json"),
        where="repository=?", parameters=(repository,),
    )
    proposals = []
    proposal_schemas: dict[str, str] = {}
    for row in proposal_raw:
        packet = _strict_json(row["packet_json"], "COORDINATION_TRUTH_APPROVAL_PACKET_INVALID")
        if set(packet) != APPROVAL_PACKET_KEYS or packet.get("schema") not in {APPROVAL_V1, APPROVAL_V2}:
            raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_PACKET_INVALID")
        expected = digest_json(_approval_semantic(packet))
        if (
            expected != row["proposal_sha256"] or expected != row["semantic_sha256"]
            or packet["repository"] != row["repository"]
            or packet["owning_issue"] != row["owning_issue"]
            or packet["source_snapshot_sha256"] != row["source_snapshot_sha256"]
            or packet["decision_key"] != row["decision_key"]
            or packet["requester_session_id"] != row["requester_session_id"]
            or packet["recipient_session_id"] != row["recipient_session_id"]
            or packet["workstream"] != row["workstream"]
            or packet["boundary"] != row["boundary"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_BINDING_INVALID")
        proposal_schemas[row["proposal_sha256"]] = packet["schema"]
        projected = {name: row[name] for name in SAFE_COLUMNS["approval_proposals"]}
        projected["semantic_contract"] = packet["schema"]
        proposals.append(projected)
    proposals = _project_rows(proposals, (*SAFE_COLUMNS["approval_proposals"], "semantic_contract"))
    proposal_ids = sorted(proposal_schemas)
    where, values = _in_where("proposal_sha256", proposal_ids)
    submission_raw = _select(
        connection, "approval_submissions",
        (*SAFE_COLUMNS["approval_submissions"], "requester_session_id", "recipient_session_id", "packet_json"),
        where=where, parameters=values,
    )
    submissions = []
    for row in submission_raw:
        packet = _strict_json(row["packet_json"], "COORDINATION_TRUTH_APPROVAL_SUBMISSION_INVALID")
        if (
            set(packet) != APPROVAL_PACKET_KEYS
            or digest_json(packet) != row["submission_sha256"]
            or digest_json(_approval_semantic(packet)) != row["proposal_sha256"]
            or packet["schema"] != proposal_schemas.get(row["proposal_sha256"])
            or packet["requester_session_id"] != row["requester_session_id"]
            or packet["recipient_session_id"] != row["recipient_session_id"]
            or packet["workstream"] != row["workstream"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_SUBMISSION_INVALID")
        submissions.append({name: row[name] for name in SAFE_COLUMNS["approval_submissions"]})
    submissions = _project_rows(submissions, SAFE_COLUMNS["approval_submissions"])
    tables: dict[str, list[dict[str, Any]]] = {
        "approval_proposals": proposals,
        "approval_submissions": submissions,
        "approval_current": _table_rows(connection, "approval_current", repository),
        "approval_semantic_contract_current": _project_rows(
            _approval_contract_rows(connection),
            SAFE_COLUMNS["approval_semantic_contract_current"],
        ),
        "approval_review_batches": _table_rows(
            connection, "approval_review_batches", repository
        ),
    }
    for table in (
        "approval_interests", "approval_decisions", "approval_deliveries",
        "approval_effectivity", "approval_revocations",
    ):
        tables[table] = _table_rows(connection, table, repository, where=where, parameters=values)
    tables["approval_proposal_notices"] = _table_rows(
        connection, "approval_proposal_notices", repository,
        where=where, parameters=values,
    )
    tables["approval_delivery_notices"] = _table_rows(
        connection, "approval_delivery_notices", repository,
        where=where, parameters=values,
    )
    event_keys = [f"approval:{proposal}" for proposal in proposal_ids]
    event_where, event_values = _in_where("entity_key", event_keys)
    tables["approval_events"] = _table_rows(
        connection, "approval_events", repository,
        where=event_where, parameters=event_values,
    )
    decision_events = _select(
        connection, "approval_decisions",
        ("user_event_source", "user_event_id"),
        where=where, parameters=values,
    )
    user_events = []
    for event in decision_events:
        rows = _select(
            connection, "approval_user_events",
            SAFE_COLUMNS["approval_user_events"],
            where="user_event_source=? AND user_event_id=?",
            parameters=(event["user_event_source"], event["user_event_id"]),
        )
        if len(rows) != 1:
            raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_DECISION_INVALID")
        user_events.extend(rows)
    tables["approval_user_events"] = _project_rows(
        user_events, SAFE_COLUMNS["approval_user_events"]
    )
    for table in ("approval_decisions", "approval_revocations"):
        for row in tables[table]:
            if row["owner_outbox_id"] is None:
                continue
            outbox = outboxes.get(int(row["owner_outbox_id"]))
            proposal = next(
                (
                    candidate for candidate in proposals
                    if candidate["proposal_sha256"] == row["proposal_sha256"]
                ),
                None,
            )
            if (
                outbox is None or proposal is None
                or outbox["object_kind"] != "issue"
                or int(outbox["object_number"]) != int(proposal["owning_issue"])
            ):
                raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_OUTBOX_INVALID")
    proposal_by_id = {row["proposal_sha256"]: row for row in proposals}
    if any(
        row["proposal_sha256"] not in proposal_by_id
        or proposal_by_id[row["proposal_sha256"]]["repository"]
        != row["repository"]
        or proposal_by_id[row["proposal_sha256"]]["owning_issue"]
        != row["owning_issue"]
        or proposal_by_id[row["proposal_sha256"]]["semantic_contract"]
        != proposal_schemas[row["proposal_sha256"]]
        for row in tables["approval_current"]
    ):
        raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_CURRENT_INVALID")
    current_raw = _select(
        connection, "approval_current",
        ("proposal_sha256", "decision_key"),
        where="repository=?", parameters=(repository,),
    )
    if any(
        proposal_by_id[row["proposal_sha256"]].get("decision_key")
        != row["decision_key"]
        for row in current_raw
    ):
        raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_CURRENT_INVALID")
    contract = tables["approval_semantic_contract_current"]
    if len(contract) != 1:
        raise SnapshotHold("COORDINATION_TRUTH_APPROVAL_CONTRACT_INVALID")
    if contract[0]["schema"] == APPROVAL_V2:
        current_ids = {row["proposal_sha256"] for row in tables["approval_current"]}
        decisions = {row["proposal_sha256"] for row in tables["approval_decisions"]}
        revoked = {row["proposal_sha256"] for row in tables["approval_revocations"]}
        deliveries: dict[str, set[str]] = {}
        for row in tables["approval_deliveries"]:
            deliveries.setdefault(row["proposal_sha256"], set()).add(row["state"])
        authority_ids = {
            proposal
            for proposal in current_ids - revoked
            if (
                proposal not in decisions
                or not deliveries.get(proposal)
                or any(state != "HOLD" for state in deliveries[proposal])
            )
        }
        if any(proposal_schemas.get(proposal) == APPROVAL_V1 for proposal in authority_ids):
            raise SnapshotHold("COORDINATION_TRUTH_LEGACY_V1_AUTHORITY_QUARANTINED")
    message_ids = {
        int(row["message_id"])
        for table in ("approval_proposal_notices", "approval_delivery_notices")
        for row in tables[table]
    }
    return _family(tables), message_ids


def _validated_routing_objects(value: Any) -> list[dict[str, Any]]:
    """Apply a closed consumer-side oracle to producer-validated objects."""

    if type(value) is not list or len(value) > MAX_ROUTING_OBJECTS:
        raise SnapshotHold("COORDINATION_TRUTH_ROUTING_INVALID")
    objects: list[dict[str, Any]] = []
    identities: set[tuple[str, int, str]] = set()
    required = {"object_kind", "object_number", "node_id", "body_sha256"}
    for candidate in value:
        if (
            type(candidate) is not dict
            or set(candidate) != required
            or type(candidate.get("object_kind")) is not str
            or candidate["object_kind"] not in {"issue", "pull_request"}
            or type(candidate.get("object_number")) is not int
            or candidate["object_number"] <= 0
            or type(candidate.get("node_id")) is not str
            or not candidate["node_id"]
            or len(candidate["node_id"]) > 255
            or type(candidate.get("body_sha256")) is not str
            or SHA256.fullmatch(candidate["body_sha256"]) is None
        ):
            raise SnapshotHold("COORDINATION_TRUTH_ROUTING_INVALID")
        identity = (
            candidate["object_kind"],
            candidate["object_number"],
            candidate["node_id"],
        )
        if identity in identities:
            raise SnapshotHold("COORDINATION_TRUTH_ROUTING_INVALID")
        identities.add(identity)
        objects.append(dict(candidate))
    objects.sort(
        key=lambda item: (
            item["object_kind"], item["object_number"], item["node_id"]
        )
    )
    return objects


def _routing_family(
    connection: sqlite3.Connection,
    repository: str,
    outboxes: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    current = _table_rows(connection, "routing_deprecation_current", repository)
    inventory_rows = _select(
        connection, "routing_deprecation_inventories",
        tuple(item["name"] for item in _schema_record(connection, "routing_deprecation_inventories")["columns"]),
        where="repository=?", parameters=(repository,),
    )
    promotions = _table_rows(connection, "routing_deprecation_promotions", repository)
    if inventory_rows and len(current) != 1:
        raise SnapshotHold("COORDINATION_TRUTH_ROUTING_CURRENT_REQUIRED")
    rendered = []
    for inventory in inventory_rows:
        occurrences = _select(
            connection, "routing_deprecation_occurrences",
            tuple(item["name"] for item in _schema_record(connection, "routing_deprecation_occurrences")["columns"]),
            where="inventory_sha256=?", parameters=(inventory["inventory_sha256"],),
        )
        try:
            validated, _ = validate_inventory_record(inventory, occurrences)
        except RoutingInventoryContractError as exc:
            raise SnapshotHold("COORDINATION_TRUTH_ROUTING_INVALID") from exc
        objects = _validated_routing_objects(validated["object_manifest"])
        outbox = outboxes.get(int(inventory["outbox_id"]))
        if (
            outbox is None
            or outbox["object_kind"] != "issue"
            or int(outbox["object_number"]) != 179
            or outbox["state"] != "COMPLETE"
            or outbox["expected_source_sha256"]
            != inventory["issue_179_source_sha256"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_ROUTING_OUTBOX_INVALID")
        safe = {name: inventory[name] for name in SAFE_COLUMNS["routing_deprecation_inventories"]}
        safe["objects"] = objects
        rendered.append(safe)
    rendered.sort(key=canonical_json)
    if current:
        matches = [
            row for row in inventory_rows
            if row["inventory_sha256"] == current[0]["inventory_sha256"]
            and row["generation"] == current[0]["generation"]
        ]
        promoted = [
            row for row in promotions
            if row["inventory_sha256"] == current[0]["inventory_sha256"]
            and row["generation"] == current[0]["generation"]
        ]
        if len(matches) != 1 or len(promoted) != 1:
            raise SnapshotHold("COORDINATION_TRUTH_ROUTING_CURRENT_INVALID")
    return _family({
        "routing_deprecation_current": current,
        "routing_deprecation_inventories": rendered,
        "routing_deprecation_promotions": promotions,
    })


def _require_source_binding(
    connection: sqlite3.Connection,
    *,
    repository: str,
    object_kind: str,
    object_number: int,
    payload_sha256: str,
    current: bool,
) -> None:
    table = "github_current" if current else "github_snapshots"
    row = connection.execute(
        f"SELECT 1 FROM {table} WHERE repository=? AND object_kind=? "
        "AND object_number=? AND payload_sha256=?",
        (repository, object_kind, object_number, payload_sha256),
    ).fetchone()
    if row is None:
        raise SnapshotHold("COORDINATION_TRUTH_SOURCE_RELATIONSHIP_INVALID")


def _outbox_family(
    connection: sqlite3.Connection, repository: str
) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
    columns = (*SAFE_COLUMNS["github_outbox"], "payload_json", "remote_receipt")
    raw = _select(
        connection, "github_outbox", columns,
        where="repository=?", parameters=(repository,),
    )
    rendered: list[dict[str, Any]] = []
    by_id: dict[int, dict[str, Any]] = {}
    for row in raw:
        payload = _strict_json(row["payload_json"], "COORDINATION_TRUTH_OUTBOX_INVALID")
        if digest_json(payload) != row["payload_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_OUTBOX_DIGEST_INVALID")
        terminal_outbox = connection.execute(
            "SELECT 1 FROM coordination_terminal_closeout_packets "
            "WHERE outbox_id=? AND repository=?",
            (row["id"], repository),
        ).fetchone()
        _require_source_binding(
            connection,
            repository=repository,
            object_kind=row["object_kind"],
            object_number=int(row["object_number"]),
            payload_sha256=row["expected_source_sha256"],
            current=(
                row["state"] in {"PREPARED", "INFLIGHT"}
                and terminal_outbox is None
            ),
        )
        safe = {name: row[name] for name in SAFE_COLUMNS["github_outbox"]}
        rendered.append(safe)
        by_id[int(row["id"])] = dict(row)
    return _family({
        "github_outbox": _project_rows(
            rendered, SAFE_COLUMNS["github_outbox"]
        )
    }), by_id


def _hosted_family(
    connection: sqlite3.Connection,
    repository: str,
    outboxes: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    internal = (
        "scope_json", "recipient_session_id", "claimed_by", "remote_receipt",
    )
    raw = _select(
        connection, "hosted_operations",
        (*SAFE_COLUMNS["hosted_operations"], *internal),
        where="repository=?", parameters=(repository,),
    )
    current_sre = connection.execute(
        "SELECT endpoint_id FROM executor_role_endpoint_current WHERE role='sre'"
    ).fetchone()
    current_identities = set()
    if current_sre is not None:
        current_identities.add(str(current_sre[0]))
        current_identities.update(
            str(row["alias"])
            for row in _select(
                connection, "executor_role_endpoint_aliases", ("alias",),
                where="role='sre' AND endpoint_id=?",
                parameters=(current_sre[0],),
            )
        )
    rendered = []
    for row in raw:
        scope = _strict_json(
            row["scope_json"], "COORDINATION_TRUTH_HOSTED_SCOPE_INVALID"
        )
        if digest_json(scope) != row["scope_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_HOSTED_SCOPE_INVALID")
        active = row["state"] in {"WAITING", "PREPARED", "CLAIMED"}
        _require_source_binding(
            connection,
            repository=repository,
            object_kind="issue",
            object_number=int(row["issue_number"]),
            payload_sha256=row["source_payload_sha256"],
            current=active,
        )
        if active and row["recipient_session_id"] not in current_identities:
            raise SnapshotHold("COORDINATION_TRUTH_HOSTED_ENDPOINT_INVALID")
        if row["state"] == "CLAIMED" and row["claimed_by"] not in current_identities:
            raise SnapshotHold("COORDINATION_TRUTH_HOSTED_CLAIM_INVALID")
        receipt_fields = (
            row["receipt_outbox_id"], row["remote_receipt"],
            row["receipt_outcome"], row["receipt_payload_sha256"],
        )
        if row["state"] in {"WAITING", "PREPARED", "CLAIMED"} and any(
            value is not None for value in receipt_fields
        ):
            raise SnapshotHold("COORDINATION_TRUTH_HOSTED_RECEIPT_INVALID")
        if row["state"] == "COMPLETE" and (
            any(value is None for value in receipt_fields)
            or row["receipt_outcome"] != "SUCCESS"
        ):
            raise SnapshotHold("COORDINATION_TRUTH_HOSTED_RECEIPT_INVALID")
        if row["state"] == "HOLD" and any(
            value is not None for value in receipt_fields
        ) and any(value is None for value in receipt_fields):
            raise SnapshotHold("COORDINATION_TRUTH_HOSTED_RECEIPT_INVALID")
        if row["receipt_outbox_id"] is not None:
            outbox = outboxes.get(int(row["receipt_outbox_id"]))
            if (
                outbox is None
                or outbox["object_kind"] != "issue"
                or int(outbox["object_number"]) != int(row["issue_number"])
                or outbox["state"] != "COMPLETE"
                or outbox["remote_receipt"] != row["remote_receipt"]
            ):
                raise SnapshotHold("COORDINATION_TRUTH_HOSTED_RECEIPT_INVALID")
        rendered.append({
            name: row[name] for name in SAFE_COLUMNS["hosted_operations"]
        })
    return _family({
        "hosted_operations": _project_rows(
            rendered, SAFE_COLUMNS["hosted_operations"]
        )
    })


def _delivery_family(
    connection: sqlite3.Connection,
    repository: str,
    *,
    outboxes: Mapping[int, Mapping[str, Any]],
    message_ids: set[int],
) -> dict[str, Any]:
    direct = {
        table: _table_rows(connection, table, repository)
        for table in (
            "coordination_pre_push_gates", "coordination_pre_push_publications",
            "coordination_terminal_closeout_packets", "portfolio_dirty_events",
            "coordination_admission_source_equivalence",
            "coordination_endpoint_rotation_rearms",
        )
    }
    closeout_keys = [row["closeout_key"] for row in direct["coordination_terminal_closeout_packets"]]
    closeout_where, closeout_values = _in_where("closeout_key", closeout_keys)
    direct["coordination_terminal_closeout_commits"] = _table_rows(
        connection, "coordination_terminal_closeout_commits", repository,
        where=closeout_where, parameters=closeout_values,
    )
    outbox_ids = [row["outbox_id"] for row in direct["coordination_terminal_closeout_packets"]]
    outbox_where, outbox_values = _in_where("outbox_id", outbox_ids)
    direct["coordination_terminal_outbox_readbacks"] = _table_rows(
        connection, "coordination_terminal_outbox_readbacks", repository,
        where=outbox_where, parameters=outbox_values,
    )
    direct["coordination_terminal_outbox_publishers"] = _table_rows(
        connection, "coordination_terminal_outbox_publishers", repository,
        where=outbox_where, parameters=outbox_values,
    )
    direct["coordination_terminal_outbox_recovery"] = _table_rows(
        connection, "coordination_terminal_outbox_recovery", repository,
        where=outbox_where, parameters=outbox_values,
    )

    message_payloads = {
        int(row["id"]): str(row["payload_sha256"])
        for row in _select(
            connection, "coordination_messages", ("id", "payload_sha256")
        )
        if int(row["id"]) in message_ids
    }
    watches = {
        str(row["watch_key"]): row
        for row in _select_all(
            connection, "coordination_terminal_watches",
            where="repository=?", parameters=(repository,),
        )
    }
    attempts = {
        str(row["attempt_id"]): row
        for row in _select_all(connection, "executor_attempts")
    }
    endpoints = {
        str(row["endpoint_id"]): str(row["role"])
        for row in _select(
            connection, "executor_role_endpoints", ("endpoint_id", "role")
        )
    }
    items = {
        int(row["issue_number"]): row
        for row in _select_all(
            connection, "coordination_items",
            where="repository=?", parameters=(repository,),
        )
    }
    graphs = {
        int(row["version"]): row
        for row in _select_all(
            connection, "portfolio_graph_revisions",
            where="repository=?", parameters=(repository,),
        )
    }
    nodes = {
        (int(row["graph_version"]), str(row["node_key"])): row
        for row in _select_all(
            connection, "portfolio_graph_nodes",
            where="repository=?", parameters=(repository,),
        )
    }

    gates = {int(row["id"]): row for row in direct["coordination_pre_push_gates"]}
    for gate in gates.values():
        _require_source_binding(
            connection, repository=repository, object_kind="issue",
            object_number=int(gate["issue_number"]),
            payload_sha256=gate["source_payload_sha256"], current=False,
        )
        if message_payloads.get(int(gate["admission_message_id"])) != gate[
            "admission_payload_sha256"
        ]:
            raise SnapshotHold("COORDINATION_TRUTH_PRE_PUSH_MESSAGE_INVALID")
    for publication in direct["coordination_pre_push_publications"]:
        gate = gates.get(int(publication["gate_id"]))
        if (
            gate is None
            or gate["repository"] != repository
            or gate["issue_number"] != publication["issue_number"]
            or gate["generation"] != publication["generation"]
            or gate["source_payload_sha256"] != publication["source_payload_sha256"]
            or gate["lease_manifest_sha256"] != publication["lease_manifest_sha256"]
            or gate["admission_message_id"] != publication["admission_message_id"]
            or gate["head_sha"] != publication["head_sha"]
            or gate["state"] != "PASS"
        ):
            raise SnapshotHold("COORDINATION_TRUTH_PRE_PUSH_PUBLICATION_INVALID")

    packet_extra = (
        "preparer_attempt_id", "preparer_attempt_version",
        "terminal_receipt_json", "cleanup_evidence_json",
    )
    packet_raw = _select(
        connection, "coordination_terminal_closeout_packets",
        (*SAFE_COLUMNS["coordination_terminal_closeout_packets"], *packet_extra),
        where="repository=?", parameters=(repository,),
    )
    packet_by_key = {str(row["closeout_key"]): row for row in packet_raw}
    for packet in packet_raw:
        terminal_receipt = _strict_json(
            packet["terminal_receipt_json"],
            "COORDINATION_TRUTH_TERMINAL_RECEIPT_INVALID",
        )
        cleanup = _strict_json(
            packet["cleanup_evidence_json"],
            "COORDINATION_TRUTH_TERMINAL_CLEANUP_INVALID",
        )
        if (
            digest_json(terminal_receipt) != packet["terminal_receipt_sha256"]
            or digest_json(cleanup) != packet["cleanup_evidence_sha256"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_PACKET_INVALID")
        message_id = int(packet["activation_message_id"])
        watch = watches.get(str(packet["terminal_watch_key"]))
        outbox = outboxes.get(int(packet["outbox_id"]))
        attempt = attempts.get(str(packet["preparer_attempt_id"]))
        graph = graphs.get(int(packet["graph_version"]))
        node = nodes.get((int(packet["graph_version"]), str(packet["graph_node_key"])))
        item = items.get(int(packet["issue_number"]))
        if (
            message_payloads.get(message_id) != packet["activation_payload_sha256"]
            or watch is None
            or int(watch["issue_number"]) != int(packet["issue_number"])
            or int(watch["generation"]) != int(packet["generation"])
            or watch["lease_manifest_sha256"] != packet["lease_manifest_sha256"]
            or int(watch["admission_message_id"]) != message_id
            or watch["admission_payload_sha256"] != packet["activation_payload_sha256"]
            or outbox is None
            or outbox["object_kind"] != "issue"
            or int(outbox["object_number"]) != int(packet["issue_number"])
            or outbox["payload_sha256"] != packet["outbox_payload_sha256"]
            or attempt is None
            or int(attempt["version"]) != int(packet["preparer_attempt_version"])
            or attempt["endpoint_id"] != packet["endpoint_id"]
            or endpoints.get(str(packet["endpoint_id"])) != packet["accountable_role"]
            or attempt["role"] != packet["accountable_role"]
            or attempt["lineage_repository"] != repository
            or int(attempt["lineage_issue_number"] or 0) != int(packet["issue_number"])
            or attempt["lineage_generation"] is None
            or int(attempt["lineage_generation"]) != int(packet["generation"])
            or attempt["lineage_lease_sha256"] != packet["lease_manifest_sha256"]
            or graph is None
            or graph["graph_sha256"] != packet["graph_sha256"]
            or graph["accepted_main_sha"] != packet["graph_main_sha"]
            or node is None
            or int(node["issue_number"]) != int(packet["issue_number"])
            or node["source_payload_sha256"] != packet["source_payload_sha256"]
            or item is None
            or int(item["generation"]) != int(packet["generation"])
            or item["source_payload_sha256"] != packet["source_payload_sha256"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_RELATIONSHIP_INVALID")
        graph_descriptor = {
            "repository": repository,
            "issue_number": int(packet["issue_number"]),
            "graph_version": int(packet["graph_version"]),
            "graph_sha256": packet["graph_sha256"],
            "graph_main_sha": packet["graph_main_sha"],
            "graph_node_key": packet["graph_node_key"],
            "source_payload_sha256": packet["source_payload_sha256"],
        }
        if digest_json(graph_descriptor) != packet["graph_binding_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_GRAPH_INVALID")
        descriptor = {
            "schema": "twinfinity-terminal-closeout-packet/v1",
            "closeout_key": packet["closeout_key"],
            "repository": repository,
            "issue_number": int(packet["issue_number"]),
            "generation": int(packet["generation"]),
            "source_payload_sha256": packet["source_payload_sha256"],
            "lease_manifest_sha256": packet["lease_manifest_sha256"],
            "accountable_role": packet["accountable_role"],
            "endpoint_id": packet["endpoint_id"],
            "preparer_attempt_id": packet["preparer_attempt_id"],
            "preparer_attempt_version": int(packet["preparer_attempt_version"]),
            "terminal_watch_key": packet["terminal_watch_key"],
            "activation_message_id": message_id,
            "activation_payload_sha256": packet["activation_payload_sha256"],
            "expected_item_version": int(packet["expected_item_version"]),
            "publication_pending_item_version": int(packet["publication_pending_item_version"]),
            "terminal_receipt_sha256": packet["terminal_receipt_sha256"],
            "cleanup_evidence_sha256": packet["cleanup_evidence_sha256"],
            "outbox_id": int(packet["outbox_id"]),
            "outbox_payload_sha256": packet["outbox_payload_sha256"],
            **graph_descriptor,
            "graph_binding_sha256": packet["graph_binding_sha256"],
        }
        if digest_json(descriptor) != packet["packet_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_PACKET_INVALID")

    dirty_raw = {
        int(row["id"]): row
        for row in _select_all(
            connection, "portfolio_dirty_events",
            where="repository=?", parameters=(repository,),
        )
    }
    for dirty in dirty_raw.values():
        payload = _strict_json(
            dirty["payload_json"], "COORDINATION_TRUTH_DIRTY_EVENT_INVALID"
        )
        if digest_json(payload) != dirty["event_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_DIRTY_EVENT_INVALID")
        if (dirty["result_json"] is None) != (dirty["result_sha256"] is None):
            raise SnapshotHold("COORDINATION_TRUTH_DIRTY_EVENT_INVALID")
        if dirty["result_json"] is not None and digest_json(
            _strict_json_value(
                dirty["result_json"], "COORDINATION_TRUTH_DIRTY_EVENT_INVALID"
            )
        ) != dirty["result_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_DIRTY_EVENT_INVALID")

    commit_extra = ("live_evidence_json",)
    commit_raw = _select(
        connection, "coordination_terminal_closeout_commits",
        (*SAFE_COLUMNS["coordination_terminal_closeout_commits"], *commit_extra),
        where=closeout_where, parameters=closeout_values,
    )
    for commit in commit_raw:
        packet = packet_by_key.get(str(commit["closeout_key"]))
        attempt = attempts.get(str(commit["finalizer_attempt_id"]))
        dirty = dirty_raw.get(int(commit["dirty_event_id"]))
        if (
            packet is None
            or attempt is None
            or int(attempt["version"]) != int(commit["finalizer_attempt_version"])
            or dirty is None
            or int(dirty["issue_number"]) != int(packet["issue_number"])
            or int(dirty["release_item_version"]) != int(commit["done_item_version"])
            or dirty["release_source_sha256"] != packet["source_payload_sha256"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_COMMIT_INVALID")
        if commit["live_evidence_json"] is not None and digest_json(
            _strict_json(
                commit["live_evidence_json"],
                "COORDINATION_TRUTH_TERMINAL_COMMIT_INVALID",
            )
        ) != commit["live_evidence_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_COMMIT_INVALID")
        descriptor = {
            "schema": "twinfinity-terminal-closeout-commit/v1",
            "closeout_key": commit["closeout_key"],
            "packet_sha256": packet["packet_sha256"],
            "finalizer_attempt_id": commit["finalizer_attempt_id"],
            "finalizer_attempt_version": int(commit["finalizer_attempt_version"]),
            "live_evidence_sha256": commit["live_evidence_sha256"],
            "remote_receipt_sha256": commit["remote_receipt_sha256"],
            "prior_item_version": int(commit["prior_item_version"]),
            "done_item_version": int(commit["done_item_version"]),
            "dirty_event_id": int(commit["dirty_event_id"]),
        }
        if digest_json(descriptor) != commit["commit_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_COMMIT_INVALID")

    for publisher in _select_all(
        connection, "coordination_terminal_outbox_publishers",
        where=outbox_where, parameters=outbox_values,
    ):
        descriptor = {
            "schema": "twinfinity-terminal-outbox-publisher/v1",
            "outbox_id": int(publisher["outbox_id"]),
            "closeout_key": publisher["closeout_key"],
            "publisher_login": publisher["publisher_login"],
        }
        if (
            publisher["closeout_key"] not in packet_by_key
            or digest_json(descriptor) != publisher["binding_sha256"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_PUBLISHER_INVALID")

    for readback in _select_all(
        connection, "coordination_terminal_outbox_readbacks",
        where=outbox_where, parameters=outbox_values,
    ):
        packet = packet_by_key.get(str(readback["closeout_key"]))
        outbox = outboxes.get(int(readback["outbox_id"]))
        if (
            packet is None or outbox is None
            or outbox["remote_receipt"] != readback["remote_receipt"]
            or hashlib.sha256(readback["remote_receipt"].encode("utf-8")).hexdigest()
            != readback["remote_receipt_sha256"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_TERMINAL_READBACK_INVALID")

    equivalence_raw = _select(
        connection, "coordination_admission_source_equivalence",
        (*SAFE_COLUMNS["coordination_admission_source_equivalence"], "receipt_json"),
        where="repository=?", parameters=(repository,),
    )
    for receipt in equivalence_raw:
        watch = watches.get(str(receipt["watch_key"]))
        outbox = outboxes.get(int(receipt["outbox_id"]))
        attempt = attempts.get(str(receipt["claim_attempt_id"]))
        if digest_json(_strict_json(
            receipt["receipt_json"],
            "COORDINATION_TRUTH_SOURCE_EQUIVALENCE_INVALID",
        )) != receipt["receipt_sha256"]:
            raise SnapshotHold("COORDINATION_TRUTH_SOURCE_EQUIVALENCE_INVALID")
        for source_sha256 in (
            receipt["bound_source_sha256"], receipt["current_source_sha256"],
            receipt["stable_source_sha256"],
        ):
            _require_source_binding(
                connection, repository=repository, object_kind="issue",
                object_number=int(receipt["issue_number"]),
                payload_sha256=source_sha256, current=False,
            )
        if (
            int(receipt["message_id"]) not in message_ids
            or watch is None
            or int(watch["issue_number"]) != int(receipt["issue_number"])
            or int(watch["generation"]) != int(receipt["generation"])
            or outbox is None
            or int(outbox["object_number"]) != int(receipt["issue_number"])
            or attempt is None
            or attempt["endpoint_id"] != receipt["endpoint_id"]
            or attempt["lineage_lease_sha256"] != receipt["lease_manifest_sha256"]
        ):
            raise SnapshotHold("COORDINATION_TRUTH_SOURCE_EQUIVALENCE_INVALID")

    change_versions = {
        (str(row["change_id"]), int(row["version"]))
        for row in _select(
            connection, "executor_registry_changes", ("change_id", "version")
        )
    }
    rearm_raw = _select(
        connection, "coordination_endpoint_rotation_rearms",
        (*SAFE_COLUMNS["coordination_endpoint_rotation_rearms"], "receipt_json"),
        where="repository=?", parameters=(repository,),
    )
    for rearm in rearm_raw:
        watch = watches.get(str(rearm["watch_key"]))
        if (
            digest_json(_strict_json(
                rearm["receipt_json"],
                "COORDINATION_TRUTH_ENDPOINT_REARM_INVALID",
            )) != rearm["receipt_sha256"]
            or (str(rearm["change_id"]), int(rearm["change_version"]))
            not in change_versions
            or int(rearm["message_id"]) not in message_ids
            or watch is None
            or int(watch["issue_number"]) != int(rearm["issue_number"])
            or int(watch["generation"]) != int(rearm["generation"])
        ):
            raise SnapshotHold("COORDINATION_TRUTH_ENDPOINT_REARM_INVALID")
    return _family(direct)


def _assemble(connection: sqlite3.Connection, repository: str) -> dict[str, Any]:
    schema = _validate_schema(connection)
    global_current = _global_current(connection)
    outbox, outboxes = _outbox_family(connection, repository)
    readiness, readiness_attempts, readiness_messages = _readiness_family(connection, repository)
    attempts, watch_messages = _attempts_family(connection, repository, readiness_attempts)
    approvals, approval_messages = _approvals_family(
        connection, repository, outboxes
    )
    messages, selected_messages = _messages_family(connection, repository)
    if not readiness_messages.union(watch_messages, approval_messages).issubset(selected_messages):
        raise SnapshotHold("COORDINATION_TRUTH_MESSAGE_RELATIONSHIP_INVALID")
    hosted = _hosted_family(connection, repository, outboxes)
    delivery = _delivery_family(
        connection, repository, outboxes=outboxes,
        message_ids=selected_messages,
    )
    families = {
        "capacity": _capacity_family(connection, repository),
        "sources_graph": _sources_graph_family(connection, repository),
        "items_allocations_leases": _items_family(connection, repository),
        "messages_admissions": messages,
        "attempts_watches": attempts,
        "readiness": readiness,
        "pull_buffer": _pull_family(connection, repository),
        "approvals": approvals,
        "outbox": outbox,
        "hosted_operations": hosted,
        "delivery_control": delivery,
        "routing_truth": _routing_family(connection, repository, outboxes),
    }
    result = {
        "schema": SNAPSHOT_SCHEMA,
        "repository": repository,
        "global_current": global_current,
        "schema_sentinels": schema,
        "families": families,
        "read_effect_budget": {
            "database_opens": 1,
            "read_transactions": 1,
            "rollbacks": 1,
            "sql_writes": 0,
            "filesystem_namespace_writes": 0,
            "rollback_journal_metadata_changes": 0,
            "read_atime_changes_only": True,
            "wal_existing_shm_lock_bytes_and_timestamps_only": True,
        },
    }
    encoded = canonical_json(result).encode("utf-8")
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise SnapshotHold("COORDINATION_TRUTH_RESOURCE_LIMIT")
    result["snapshot_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def _open_file_noatime(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NOATIME"):
        flags |= os.O_NOATIME
    try:
        return os.open(path, flags)
    except PermissionError:
        return os.open(path, flags & ~getattr(os, "O_NOATIME", 0))


def _stable_file_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _read_file_noatime(path: Path, *, limit: int) -> bytes:
    descriptor = _open_file_noatime(path)
    try:
        before = os.fstat(descriptor)
        data = os.read(descriptor, limit)
        after = os.fstat(descriptor)
        final = path.lstat()
        if (
            _stable_file_tuple(before) != _stable_file_tuple(after)
            or _stable_file_tuple(after) != _stable_file_tuple(final)
        ):
            raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_DRIFT")
        return data
    finally:
        os.close(descriptor)


def _file_identity(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_UNSAFE")
    if (
        metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_UNSAFE")
    descriptor = _open_file_noatime(path)
    try:
        before = os.fstat(descriptor)
        if _stable_file_tuple(before) != _stable_file_tuple(metadata):
            raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_DRIFT")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        final = path.lstat()
        if (
            size != after.st_size
            or _stable_file_tuple(before) != _stable_file_tuple(after)
            or _stable_file_tuple(after) != _stable_file_tuple(final)
        ):
            raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_DRIFT")
        return {
            "device": after.st_dev, "inode": after.st_ino,
            "mode": stat.S_IMODE(after.st_mode), "uid": after.st_uid,
            "gid": after.st_gid, "links": after.st_nlink,
            "size": after.st_size, "mtime_ns": after.st_mtime_ns,
            "ctime_ns": after.st_ctime_ns, "atime_ns": after.st_atime_ns,
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def _filesystem_state(database: Path) -> dict[str, Any]:
    parent_chain = []
    for directory in (*reversed(database.parent.parents), database.parent):
        metadata = directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_UNSAFE")
        parent_chain.append({
            "device": metadata.st_dev, "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid,
            "gid": metadata.st_gid, "links": metadata.st_nlink,
        })
    parent_names = sorted(entry.name for entry in os.scandir(database.parent))
    parent = database.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_nlink < 1
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_UNSAFE")
    files = {}
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = Path(str(database) + suffix)
        if path.exists() or path.is_symlink():
            files[suffix or "database"] = _file_identity(path)
    return {
        "parent_chain": parent_chain,
        "parent": {
            "device": parent.st_dev, "inode": parent.st_ino,
            "mode": stat.S_IMODE(parent.st_mode), "uid": parent.st_uid,
            "gid": parent.st_gid, "links": parent.st_nlink,
        },
        "namespace": parent_names,
        "files": files,
    }


def _journal_contract(database: Path, before: dict[str, Any]) -> str:
    header = _read_file_noatime(database, limit=20)
    if len(header) < 20 or header[:16] != b"SQLite format 3\x00":
        raise SnapshotHold("COORDINATION_TRUTH_DATABASE_INVALID")
    wal = header[18:20] == b"\x02\x02"
    names = set(before["files"])
    if wal:
        if not {"database", "-wal", "-shm"}.issubset(names) or "-journal" in names:
            raise SnapshotHold("COORDINATION_TRUTH_WAL_SIDECAR_REQUIRED")
        return "WAL"
    if names != {"database"}:
        raise SnapshotHold("COORDINATION_TRUTH_ROLLBACK_SIDECAR_FORBIDDEN")
    return "ROLLBACK"


def _validate_filesystem_effect(
    before: dict[str, Any], after: dict[str, Any], journal: str
) -> None:
    if (
        before["parent_chain"] != after["parent_chain"]
        or
        before["parent"] != after["parent"]
        or before["namespace"] != after["namespace"]
        or set(before["files"]) != set(after["files"])
    ):
        raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_NAMESPACE_EFFECT")
    for name, left in before["files"].items():
        right = after["files"][name]
        # Python's stdlib SQLite VFS does not expose O_NOATIME for its database
        # descriptors.  Reads may advance atime.  WAL readers may also update
        # lock/read-mark bytes in the pre-existing SHM coordination file; its
        # identity, mode, owner, links, and size remain exact.
        ignored: set[str] = {"atime_ns"}
        if journal == "WAL" and name == "-shm":
            ignored.update({"mtime_ns", "ctime_ns", "sha256"})
        if any(left[key] != right[key] for key in left if key not in ignored):
            raise SnapshotHold("COORDINATION_TRUTH_FILESYSTEM_EFFECT")


def _validate_controlled_writer_effect(
    before: dict[str, Any], after: dict[str, Any]
) -> None:
    """Allow only content/size/time deltas from the synthetic writer hook."""

    if (
        before["parent_chain"] != after["parent_chain"]
        or before["parent"] != after["parent"]
        or before["namespace"] != after["namespace"]
        or set(before["files"]) != set(after["files"])
    ):
        raise SnapshotHold("COORDINATION_TRUTH_WRITER_ATTRIBUTION_INVALID")
    immutable = {"device", "inode", "mode", "uid", "gid", "links"}
    for name, left in before["files"].items():
        right = after["files"][name]
        if any(left[key] != right[key] for key in immutable):
            raise SnapshotHold("COORDINATION_TRUTH_WRITER_ATTRIBUTION_INVALID")


def snapshot_database(
    database: Path,
    repository: str,
    *,
    after_begin: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Return one complete stable snapshot or raise one typed HOLD."""

    if repository not in ALLOWED_REPOSITORIES:
        raise SnapshotHold("COORDINATION_TRUTH_REPOSITORY_INVALID")
    database = Path(database)
    try:
        database = validate_owner_database(database)
        before = _filesystem_state(database)
        journal = _journal_contract(database, before)
    except SnapshotHold:
        raise
    except (OSError, ValueError) as exc:
        raise SnapshotHold("COORDINATION_TRUTH_DATABASE_UNSAFE") from exc
    connection: sqlite3.Connection | None = None
    begun = False
    total_changes = 0
    result: dict[str, Any] | None = None
    failure: BaseException | None = None
    effect_baseline = before
    try:
        connection = open_owner_database_readonly(database)
        total_changes = connection.total_changes
        connection.execute("BEGIN")
        begun = True
        connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        if after_begin is not None:
            after_begin()
            if not connection.in_transaction:
                raise SnapshotHold("COORDINATION_TRUTH_TRANSACTION_LOST")
            effect_baseline = _filesystem_state(database)
            _validate_controlled_writer_effect(before, effect_baseline)
        result = _assemble(connection, repository)
        if not connection.in_transaction:
            raise SnapshotHold("COORDINATION_TRUTH_TRANSACTION_LOST")
        if connection.total_changes != total_changes:
            raise SnapshotHold("COORDINATION_TRUTH_SQL_EFFECT")
    except BaseException as exc:
        failure = exc
    finally:
        if connection is not None:
            try:
                if begun and connection.in_transaction:
                    connection.execute("ROLLBACK")
            except BaseException:
                failure = SnapshotHold("COORDINATION_TRUTH_ROLLBACK_FAILED")
        try:
            if connection is not None:
                connection.close()
        except BaseException:
            failure = SnapshotHold("COORDINATION_TRUTH_CLOSE_FAILED")
        try:
            after = _filesystem_state(database)
            _validate_filesystem_effect(effect_baseline, after, journal)
        except BaseException as exc:
            if isinstance(exc, SnapshotHold):
                failure = exc
            else:
                failure = SnapshotHold("COORDINATION_TRUTH_POST_EFFECT_INVALID")
    if failure is not None:
        if isinstance(failure, SnapshotHold):
            raise failure
        if isinstance(failure, UnsafeSQLitePathError):
            raise SnapshotHold("COORDINATION_TRUTH_DATABASE_UNSAFE") from failure
        if isinstance(failure, sqlite3.Error):
            raise SnapshotHold("COORDINATION_TRUTH_SQLITE_INVALID") from failure
        raise SnapshotHold("COORDINATION_TRUTH_INTERNAL_ERROR") from failure
    if result is None:
        raise SnapshotHold("COORDINATION_TRUTH_INTERNAL_ERROR")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    args = parser.parse_args(argv)
    try:
        result = snapshot_database(args.database, args.repository)
    except SnapshotHold as exc:
        result = {"schema": HOLD_SCHEMA, "state": "HOLD", "error": str(exc)}
        print(canonical_json(result))
        return 1
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
