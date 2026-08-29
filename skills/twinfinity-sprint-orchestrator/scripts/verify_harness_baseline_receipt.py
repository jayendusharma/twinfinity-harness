#!/usr/bin/env python3
"""Verify a harness candidate receipt with immutable accepted-base tooling.

This module is deliberately self contained.  It never imports candidate code,
never executes a candidate validator, and treats the candidate receipt as
untrusted data.  A PASS is source evidence only.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Sequence


REPOSITORY = "jayendusharma/twinfinity-harness"
ORIGIN_URL = "https://github.com/jayendusharma/twinfinity-harness.git"
GIT = "/usr/bin/git"
PYTHON_PROC_SELF_EXE = "/proc/self/exe"
# This is a stable receipt token, not an executable lookup.  The executable
# used for every command is the accepted-base interpreter derived below.
PYTHON_MANIFEST_TOKEN = "/usr/bin/python3"
VERIFIER_PATH = (
    "skills/twinfinity-sprint-orchestrator/scripts/"
    "verify_harness_baseline_receipt.py"
)
SCHEMA_PATH = (
    "skills/twinfinity-sprint-orchestrator/references/"
    "twinfinity-harness-bootstrap-verifier-v1.schema.json"
)
CANDIDATE_RUNNER_PATH = (
    "skills/twinfinity-sprint-orchestrator/scripts/"
    "run_harness_baseline_validations.py"
)
VALIDATOR_PATH = "skills/.system/skill-creator/scripts/quick_validate.py"
REGISTRY_AUDIT_PATH = (
    "skills/twinfinity-sprint-orchestrator/scripts/executor_registry.py"
)
OWNER_SAFE_SQLITE_PATH = (
    "skills/twinfinity-sprint-orchestrator/scripts/owner_safe_sqlite.py"
)
REGISTRY_CONFIG_PATH = (
    "skills/twinfinity-sprint-orchestrator/references/"
    "twinfinity-executor-registry.toml"
)
REGISTRY_PROFILE_ROOT = "skills/twinfinity-sprint-orchestrator/references"
SKILL_ROOTS = (
    "skills/.system/imagegen",
    "skills/.system/openai-docs",
    "skills/.system/plugin-creator",
    "skills/.system/review-agent",
    "skills/.system/skill-creator",
    "skills/.system/skill-installer",
    "skills/twinfinity-development-executor",
    "skills/twinfinity-devops-sre",
    "skills/twinfinity-product-strategist",
    "skills/twinfinity-skill-governor",
    "skills/twinfinity-sprint-orchestrator",
)
SEALED_EXECUTION_SOURCE = "SEALED_ACCEPTED_BASE_MEMFD"
PINNED_PYTHON_EXECUTION_SOURCE = "PINNED_KERNEL_EXECUTABLE_FD"
TOOL_PATHS = (
    ("accepted_base_verifier", VERIFIER_PATH, "ACCEPTED_BASE"),
    ("receipt_schema", SCHEMA_PATH, "ACCEPTED_BASE"),
    ("candidate_runner", CANDIDATE_RUNNER_PATH, "NOT_EXECUTED"),
    ("skill_validator", VALIDATOR_PATH, SEALED_EXECUTION_SOURCE),
    ("executor_registry_audit", REGISTRY_AUDIT_PATH, SEALED_EXECUTION_SOURCE),
    ("executor_registry_dependency", OWNER_SAFE_SQLITE_PATH, SEALED_EXECUTION_SOURCE),
)
OUTPUT_LIMIT = 1_048_576
COMMAND_TIMEOUT = 60
OUTPUT_LIMIT_DECIMAL = str(OUTPUT_LIMIT)
COMMAND_TIMEOUT_DECIMAL = str(COMMAND_TIMEOUT)
ARCHIVE_LIMIT = 64 * 1024 * 1024
EXTRACTED_LIMIT = 128 * 1024 * 1024
ENTRY_LIMIT = 20_000
ANCESTRY_OBJECT_LIMIT = 10_000
ANCESTRY_BYTE_LIMIT = 64 * 1024 * 1024
ANCESTRY_EDGE_LIMIT = 20_000
COMMIT_HEADER_LINE_LIMIT = ANCESTRY_EDGE_LIMIT + 1_024
RECEIPT_DIRECTORY_ENTRY_LIMIT = 20_000
RECEIPT_DIRECTORY_SCAN_SECONDS = 1.0
ANCESTRY_SECONDS_LIMIT = 30.0
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BRANCH = re.compile(r"^change/[0-9]+-[a-z0-9][a-z0-9-]*$")
DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
SIGNED_DECIMAL = re.compile(r"^(?:0|-?[1-9][0-9]*)$")
COUNT_WORDS = {
    1: "ONE",
    2: "TWO",
    3: "THREE",
    4: "FOUR",
    5: "FIVE",
    6: "SIX",
}
EVIDENCE_SCOPE = (
    "SOURCE_ONLY_NOT_INSTALLATION_ACTIVATION_MERGE_RUNTIME_OR_"
    "APPLICATION_DELIVERY"
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SEALED_EXECUTION_SEALS = "SEAL|SHRINK|GROW|WRITE"
REQUIRED_SEALS = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)
DIRECT_ROUTE = "DIRECT_HARNESS_SOURCE"
APPLICATION_ROUTE = "NORMAL_APPLICATION_ADMISSION"
CONSOLIDATED_ISSUE92_PACKET_V5_SHA256 = (
    "b06f770782863af75da9ed2de02919f36d10ac5f8555fdb638b20954b937aacd"
)
ISSUE92_PACKET_CHAIN_V1_V5 = (
    (1, "aa158c73edb0cab885dee1a378599384adeede024de1a8ea0e7e5638b3f76274"),
    (2, "a56f0c20a0153374f5d31aa8b3126cd09cde99d57a6a55571d217d1772e6c377"),
    (3, "557230053492e139f8344b4f02c3caef508b8583a8eadf460b4a04489822acf2"),
    (4, "99584fc26656e51bd5699ccde38c24939ae0214491dba75c80064446960ad0bd"),
    (5, CONSOLIDATED_ISSUE92_PACKET_V5_SHA256),
)
ISSUE92_POST_MERGE_BRANCH = "change/92-baseline-validation-self-coverage"
ISSUE92_POST_MERGE_WORKTREE = (
    "/home/ubuntu/code/twinfinity/twinfinity-harness-issue92"
)
ISSUE92_POST_MERGE_OPAQUE_WORKTREE_ID = "twinfinity-harness-issue92"
ISSUE92_POST_MERGE_PRIOR_RETAINED_HEAD = (
    "b9b56f8f4f1563d12aa88fe0b0ee5665344142a7"
)
ISSUE92_POST_MERGE_PRIOR_RETAINED_TREE = (
    "49c18ed8a982b0b0e8ea524b1bd0fae06a9232b1"
)
ISSUE92_POST_MERGE_PRIOR_RETAINED_PARENT = (
    "46861c76fcb7e4674be65515c376947c2bb99f61"
)
ISSUE92_POST_MERGE_PRIOR_WRITER = "/root/direct_harness_92_security_repair_writer"
ISSUE92_POST_MERGE_ACCOUNTABLE_WRITER = (
    "/root/direct_harness_92_post98_rebase_writer"
)
ISSUE92_POST_MERGE_FIELDS = frozenset(
    {
        "schema",
        "repository",
        "owning_issue",
        "attempt_generation",
        "supersedes_packet_sha256",
        "complete_packet_chain",
        "issue_body_sha256",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "branch",
        "worktree_path",
        "opaque_worktree_id",
        "prior_retained_head",
        "prior_retained_tree",
        "prior_retained_parent",
        "candidate_head",
        "candidate_tree",
        "candidate_parent",
        "prior_writer",
        "prior_writer_terminal_state",
        "accountable_writer",
        "writer_transfer",
        "fresh_planner_disposition_reason",
        "authority",
        "human_path_authority",
        "direct_capacity",
        "repository_fence",
        "mutable_paths",
        "mutable_path_order",
        "mutable_paths_digest_serialization",
        "mutable_paths_sha256",
        "consolidated_required_outcomes",
        "semantic_scope",
        "safety_invariants",
        "non_goals",
        "authorized_stages",
        "stages_requiring_planner_continuation",
        "hard_stops",
        "excluded_effects",
        "repair_budget_for_attempt_generation_4",
        "current_stage",
    }
)
ISSUE92_POST_MERGE_MUTABLE_PATHS = (
    (
        "skills/twinfinity-sprint-orchestrator/references/"
        "twinfinity-harness-baseline-catalog-v1.json",
        "ABSENT",
        "ABSENT",
    ),
    (
        "skills/twinfinity-sprint-orchestrator/scripts/"
        "run_harness_baseline_validations.py",
        "63468ed8cac7aa82e453de3c58267f8db38d8e6147546d16e2a6268bdc6ddbcd",
        "c35222bd1ac55fe6f399f4b18da5129cc353eed0",
    ),
    (
        "skills/twinfinity-sprint-orchestrator/scripts/prepush_control.py",
        "4f47c695ca4bb1d9bc330abba24d0477440181cdd89b081d7fc84fca2687eedd",
        "7e1185b3abe3f5315578c668d600cdd2dcc2a41e",
    ),
    (
        "skills/twinfinity-sprint-orchestrator/tests/"
        "test_run_harness_baseline_validations.py",
        "185f40ea8581a3c53f5be66dec11fac64bf2d5cb4263cd6994054e686d989758",
        "5651242fa8707a4df27354c8208aa9baca353bd3",
    ),
    (
        "skills/twinfinity-sprint-orchestrator/tests/test_prepush_control.py",
        "a1d0c9633cca277bca3b543c51fe1a51ec9e56de219332e87e2975f59c591a30",
        "de6f182aaa212aae99a23672ebef0b2548a343d6",
    ),
    (
        "skills/twinfinity-sprint-orchestrator/README.md",
        "854113b406f052aa4e09e4c0540743281495f6f485a04c3f74711aa2cad67e0c",
        "3647624498a5f318f7b3bd75b76575e1192b88db",
    ),
)
ISSUE92_POST_MERGE_MUTABLE_PATHS_SHA256 = (
    "7e17825f91b6265e0aad1ae7111075162abfb880e7814492d90c6dc852e712d1"
)
ISSUE98_INHERITED_EXCLUDED_EFFECTS = (
    "SQLITE_READ_AS_AUTHORITY_OR_SQLITE_MUTATION",
    "REMOTE_PUSH_OR_PULL_REQUEST",
    "MERGE",
    "INSTALLATION_OR_RUNTIME_ACTIVATION",
    "ENDPOINT_SYSTEMD_TIMER_SERVICE_PROVIDER_HOSTED_PRODUCTION_OR_APPLICATION_OPERATION",
)
ISSUE98_V5_ADDITIONAL_EXCLUDED_EFFECTS = (
    "NO_REMOTE_PUBLICATION_OR_PULL_REQUEST",
    "NO_GITHUB_ISSUE_OR_BODY_MUTATION_BY_THE_WRITER",
    "NO_SQLITE_READINESS_ADMISSION_ALLOCATION_LEASE_MESSAGE_WATCH_APPROVAL_OUTBOX_OR_CLOSEOUT_MUTATION",
    "NO_INSTALLED_SKILL_GOAL_ENDPOINT_PROFILE_SYSTEMD_TIMER_SERVICE_PROVIDER_HOSTED_APPLICATION_OR_PRODUCTION_EFFECT",
    "NO_MUTATION_OF_THE_EXACT_ISSUE_92_CONSUMER_PACKET_OR_RETAINED_WORKTREE",
)
DIRECT_PACKET_BASE_REQUIRED = frozenset(
    {
        "recorded_at",
        "schema",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "issue_observed_at",
        "issue_observed_state",
        "issue_url",
        "trigger",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "starting_main_contract_sha256",
        "branch",
        "worktree_path",
        "opaque_worktree_id",
        "accountable_writer",
        "authority",
        "direct_capacity",
        "repository_fence",
        "dependencies",
        "mutable_paths",
        "mutable_path_order",
        "mutable_paths_sha256",
        "mutable_paths_digest_serialization",
        "collision_fence",
        "semantic_scope",
        "safety_invariants",
        "authorized_stages",
        "stages_requiring_planner_continuation",
        "repair_budget",
        "hard_stops",
        "excluded_effects",
        "bootstrap_validation_contract",
        "current_stage",
    }
)
PROTECTED_PACKET_FIELDS = frozenset(
    {
        "schema",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "issue_observed_at",
        "issue_observed_state",
        "issue_url",
        "trigger",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "starting_main_contract_sha256",
        "branch",
        "worktree_path",
        "opaque_worktree_id",
        "authority",
        "dependencies",
        "mutable_paths",
        "mutable_path_order",
        "mutable_paths_sha256",
        "mutable_paths_digest_serialization",
        "semantic_scope",
        "safety_invariants",
        "excluded_effects",
        "bootstrap_validation_contract",
        "repair_budget",
    }
)
PACKET_RETRY_COMMON_FIELDS = frozenset(
    {
        "attempt_generation",
        "supersedes_packet_sha256",
        "recorded_at",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "starting_main_contract_sha256",
        "branch",
        "worktree_path",
        "opaque_worktree_id",
        "accountable_writer",
        "direct_capacity",
        "repository_fence",
        "mutable_paths_sha256",
        "mutable_path_order",
        "collision_fence",
        "authorized_stages",
        "stages_requiring_planner_continuation",
        "repair_budget",
        "hard_stops",
        "current_stage",
        "writer_transfer",
        "prior_writer",
        "prior_writer_terminal_state",
        "fresh_planner_disposition_reason",
        "repair_starting_head",
        "repair_starting_tree",
    }
)
PACKET_V2_FIELDS = frozenset(
    {
        "accountable_writer",
        "adopted_uncommitted_state",
        "attempt_generation",
        "authorized_stages",
        "branch",
        "collision_fence",
        "current_stage",
        "direct_capacity",
        "fresh_planner_disposition_reason",
        "hard_stops",
        "incorporated_packet",
        "issue_body_sha256",
        "mutable_path_order",
        "mutable_paths_sha256",
        "opaque_worktree_id",
        "owning_issue",
        "prior_writer",
        "prior_writer_terminal_state",
        "recorded_at",
        "repair_budget",
        "repair_starting_head",
        "repair_starting_tree",
        "repository",
        "repository_fence",
        "schema",
        "stages_requiring_planner_continuation",
        "starting_main_contract_sha256",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "supersedes_packet_sha256",
        "worktree_path",
        "writer_transfer",
    }
)
PACKET_V3_FIELDS = frozenset(
    {
        "accountable_writer",
        "adopted_uncommitted_state",
        "attempt_generation",
        "authorized_stages",
        "branch",
        "changed_diagnosis",
        "collision_fence",
        "current_stage",
        "direct_capacity",
        "fresh_planner_disposition_reason",
        "hard_stops",
        "incorporated_packets",
        "incorporation",
        "inherited_validation_evidence",
        "issue_body_sha256",
        "mutable_path_order",
        "mutable_paths_sha256",
        "opaque_worktree_id",
        "owning_issue",
        "prior_writer",
        "prior_writer_terminal_state",
        "recorded_at",
        "repair_budget",
        "repair_starting_head",
        "repair_starting_tree",
        "repository",
        "repository_fence",
        "schema",
        "stages_requiring_planner_continuation",
        "starting_main_contract_sha256",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "supersedes_packet_sha256",
        "worktree_path",
        "writer_transfer",
    }
)
PACKET_V4_FIELDS = frozenset(
    {
        "accountable_writer",
        "adopted_committed_state",
        "attempt_generation",
        "authorized_stages",
        "branch",
        "changed_diagnosis",
        "collision_fence",
        "current_stage",
        "direct_capacity",
        "fresh_planner_disposition_reason",
        "governor_rejection",
        "hard_stops",
        "incorporated_packets",
        "incorporation",
        "issue_body_sha256",
        "issue_updated_at",
        "mutable_path_order",
        "mutable_paths_sha256",
        "opaque_worktree_id",
        "owning_issue",
        "prior_writer",
        "prior_writer_terminal_state",
        "recorded_at",
        "repair_budget",
        "repair_starting_head",
        "repair_starting_parent",
        "repair_starting_tree",
        "repository",
        "repository_fence",
        "schema",
        "stages_requiring_planner_continuation",
        "starting_main_contract_sha256",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "supersedes_packet_sha256",
        "worktree_path",
        "writer_transfer",
    }
)
PACKET_V5_FIELDS = frozenset(
    {
        "accountable_writer",
        "adopted_committed_state",
        "attempt_generation",
        "authorized_stages",
        "branch",
        "changed_evidence",
        "collision_fence",
        "current_consumer_packet",
        "current_stage",
        "direct_capacity",
        "excluded_effects",
        "fresh_planner_disposition_reason",
        "governor_rejection",
        "hard_stops",
        "incorporated_packets",
        "incorporation",
        "issue_body_sha256",
        "issue_updated_at",
        "mutable_path_order",
        "mutable_paths_sha256",
        "opaque_worktree_id",
        "owning_issue",
        "prior_writer",
        "prior_writer_terminal_state",
        "recorded_at",
        "repair_budget",
        "repair_starting_head",
        "repair_starting_parent",
        "repair_starting_tree",
        "repository",
        "repository_fence",
        "schema",
        "stages_requiring_planner_continuation",
        "starting_main_contract_sha256",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "supersedes_packet_sha256",
        "worktree_path",
        "writer_transfer",
    }
)
CONSOLIDATED_PACKET_V5_FIELDS = frozenset(
    {
        "accountable_writer",
        "attempt_generation",
        "authority",
        "authorized_stages",
        "branch",
        "collision_fence",
        "complete_packet_chain",
        "consolidated_required_outcomes",
        "current_stage",
        "dependencies",
        "direct_capacity",
        "excluded_effects",
        "fresh_planner_disposition_reason",
        "hard_stops",
        "human_path_authority",
        "issue_body_sha256",
        "issue_observed_at",
        "issue_observed_state",
        "mutable_path_order",
        "mutable_paths",
        "mutable_paths_digest_serialization",
        "mutable_paths_sha256",
        "non_goals",
        "opaque_worktree_id",
        "owning_issue",
        "prior_rejection",
        "prior_writer",
        "recorded_at",
        "repair_budget_for_attempt_generation_3",
        "repair_starting_head",
        "repair_starting_parent",
        "repair_starting_tree",
        "repository",
        "repository_fence",
        "safety_invariants",
        "schema",
        "semantic_scope",
        "stages_requiring_planner_continuation",
        "starting_main_contract_sha256",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "supersedes_packet_sha256",
        "worktree_path",
        "writer_transfer",
    }
)
CUMULATIVE_PACKET_V2_FIELDS = DIRECT_PACKET_BASE_REQUIRED | PACKET_V2_FIELDS
CUMULATIVE_PACKET_V3_FIELDS = DIRECT_PACKET_BASE_REQUIRED | PACKET_V3_FIELDS
CUMULATIVE_PACKET_V4_FIELDS = DIRECT_PACKET_BASE_REQUIRED | PACKET_V4_FIELDS
CUMULATIVE_PACKET_V5_FIELDS = DIRECT_PACKET_BASE_REQUIRED | PACKET_V5_FIELDS
PACKET_KEY_SETS = {
    1: (DIRECT_PACKET_BASE_REQUIRED,),
    2: (PACKET_V2_FIELDS, CUMULATIVE_PACKET_V2_FIELDS),
    3: (PACKET_V3_FIELDS, CUMULATIVE_PACKET_V3_FIELDS),
    4: (PACKET_V4_FIELDS, CUMULATIVE_PACKET_V4_FIELDS),
    5: (PACKET_V5_FIELDS, CUMULATIVE_PACKET_V5_FIELDS),
}
TRANSITION_VALUE_CONTRACTS = {
    (98, 2): {
        "writer_transfer": (
            "NEW_FRESH_WRITER_INHERITS_THE_SAME_DIRECT_UNIT_BRANCH_WORKTREE_"
            "AND_EXACT_ONE_FILE_UNCOMMITTED_STATE"
        ),
        "prior_writer_terminal_state": (
            "INTERRUPTED_AFTER_SCHEMA_ONLY_NO_TEST_OR_COMMIT"
        ),
        "fresh_planner_disposition_reason": (
            "FIRST_WRITER_INTERRUPTED_AFTER_ONE_VALID_SCHEMA_FILE_AND_BEFORE_"
            "SCRIPT_TEST_COMMIT_OR_VALIDATION_PROGRESS"
        ),
    },
    (98, 3): {
        "writer_transfer": (
            "NEW_FRESH_WRITER_INHERITS_THE_SAME_DIRECT_UNIT_BRANCH_WORKTREE_"
            "AND_EXACT_THREE_FILE_UNCOMMITTED_STATE"
        ),
        "prior_writer_terminal_state": (
            "ACTIONABLE_HOLD_AFTER_ONE_REPAIR_CYCLE_NO_COMMIT_OR_REMOTE_EFFECT"
        ),
        "fresh_planner_disposition_reason": (
            "PACKET_V2_WRITER_EXHAUSTED_ITS_ONE_REPAIR_CYCLE_AND_RETURNED_"
            "ACTIONABLE_HOLD_WITH_THREE_EXACT_CHANGED_DIAGNOSIS_FINDINGS_"
            "BEFORE_COMMIT"
        ),
        "incorporation": (
            "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_EXCEPT_THE_EXPLICIT_WRITER_"
            "TRANSFER_DIAGNOSIS_AND_STAGE_UPDATES_IN_THIS_PACKET"
        ),
    },
    (98, 4): {
        "writer_transfer": (
            "NEW_FRESH_WRITER_INHERITS_THE_SAME_DIRECT_UNIT_BRANCH_WORKTREE_"
            "AND_EXACT_CLEAN_REJECTED_COMMIT_STATE"
        ),
        "prior_writer_terminal_state": (
            "LOCAL_COMMIT_VALIDATED_THEN_FRESH_GOVERNOR_REJECTED_NO_REMOTE_EFFECT"
        ),
        "fresh_planner_disposition_reason": (
            "FRESH_INDEPENDENT_EXACT_HEAD_GOVERNOR_REJECTED_PACKET_V3_HEAD_"
            "WITH_CHANGED_DIAGNOSIS_OUTSIDE_PACKET_V3_HARD_FENCE"
        ),
        "incorporation": (
            "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_EXCEPT_THE_EXPLICIT_GOVERNOR_"
            "REJECTION_WRITER_TRANSFER_CHANGED_DIAGNOSIS_AND_STAGE_UPDATES_IN_"
            "THIS_PACKET"
        ),
    },
    (98, 5): {
        "writer_transfer": (
            "NEW_FRESH_WRITER_INHERITS_THE_SAME_DIRECT_UNIT_BRANCH_WORKTREE_"
            "AND_EXACT_CLEAN_REJECTED_COMMIT_STATE_UNDER_CHANGED_EVIDENCE"
        ),
        "prior_writer_terminal_state": (
            "LOCAL_COMMIT_VALIDATED_THEN_FRESH_GOVERNOR_REJECTED_NO_REMOTE_EFFECT"
        ),
        "fresh_planner_disposition_reason": (
            "FRESH_INDEPENDENT_EXACT_HEAD_GOVERNOR_REJECTED_PACKET_V4_HEAD_FOR_"
            "TWO_REPRODUCIBLE_CURRENT_CONSUMER_AND_PROCESS_IDENTITY_DEFECTS"
        ),
        "incorporation": (
            "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_EXCEPT_THE_EXPLICIT_GOVERNOR_"
            "REJECTION_WRITER_TRANSFER_CHANGED_EVIDENCE_AND_STAGE_UPDATES_IN_"
            "THIS_PACKET"
        ),
    },
    (92, 2): {
        "writer_transfer": "FRESH_WRITER_INHERITS_THE_DIRECT_UNIT",
        "prior_writer_terminal_state": "INTERRUPTED_NO_REMOTE_EFFECT",
        "fresh_planner_disposition_reason": "SAME_SCOPE_RETRY",
    },
    (92, 3): {
        "writer_transfer": "FRESH_WRITER_INHERITS_THE_DIRECT_UNIT",
        "prior_writer_terminal_state": "ACTIONABLE_HOLD_NO_REMOTE_EFFECT",
        "fresh_planner_disposition_reason": "SAME_SCOPE_REPAIR",
        "incorporation": (
            "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_EXCEPT_EXPLICIT_WRITER_AND_"
            "REPAIR_FIELDS"
        ),
    },
    (92, 4): {
        "writer_transfer": "FRESH_WRITER_INHERITS_THE_EXISTING_UNIT",
        "prior_writer_terminal_state": "GOVERNOR_REJECTED_NO_REMOTE_EFFECT",
        "fresh_planner_disposition_reason": "SAME_SCOPE_GOVERNOR_REPAIR",
        "incorporation": (
            "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE_EXCEPT_EXPLICIT_REPAIR_FIELDS"
        ),
    },
}
AUTHORITY_KEY_SETS = (
    frozenset(
        {
            "kind",
            "direct_owner_instructions",
            "sqlite_harness_loop",
            "temporary_six_writer_authority_sha256",
            "standing_routine_delivery_authority_sha256",
        }
    ),
)
CAPACITY_KEY_SETS = (
    frozenset(
        {
            "class",
            "units",
            "temporary_limit",
            "occupancy_after_reservation_including_active_and_retained",
            "occupancy_components",
            "sqlite_allocation_units",
        }
    ),
    frozenset(
        {
            "class",
            "units",
            "temporary_limit",
            "occupancy_including_active_and_retained",
            "sqlite_allocation_units",
            "capacity_effect",
        }
    ),
)
REPOSITORY_FENCE_KEY_SETS = (
    frozenset(
        {
            "observed_at",
            "live_main",
            "open_pull_requests",
            "remote_branches",
            "candidate_remote_branch_present",
            "planned_local_branch_present",
            "planned_worktree_present",
            "local_branch_inventory_sha256",
            "local_worktree_porcelain_sha256",
        }
    ),
    frozenset(
        {
            "observed_at",
            "live_main",
            "open_pull_requests",
            "remote_branches",
            "candidate_remote_branch_present",
            "local_branch_exact",
            "local_worktree_exact",
        }
    ),
    frozenset(
        {
            "observed_at",
            "live_main",
            "live_main_tree",
            "open_pull_requests",
            "remote_branches",
            "candidate_remote_branch_present",
            "local_branch_exact",
            "local_worktree_exact",
        }
    ),
)
COLLISION_KEY_SETS = (
    frozenset(
        {
            "issue_92_state",
            "issue_92_worktree",
            "issue_92_mutable_paths_sha256",
            "issue_93_state",
            "issue_93_mutable_paths_sha256",
            "issue_94_state",
            "issue_94_mutable_paths_sha256",
            "issue_96_state",
            "issue_96_mutable_paths_sha256",
            "issue_98_intersection_with_92",
            "issue_98_intersection_with_93",
            "issue_98_intersection_with_94",
            "issue_98_intersection_with_96",
            "path_collision",
            "branch_collision",
            "worktree_collision",
            "semantic_relation_with_92",
            "historical_and_retired_worktree_mutation",
            "unknown_overlap_action",
        }
    ),
    frozenset(
        {
            "issue_92_state",
            "issue_93_state",
            "issue_94_state",
            "issue_96_state",
            "issue_98_intersection_with_92",
            "issue_98_intersection_with_93",
            "issue_98_intersection_with_94",
            "issue_98_intersection_with_96",
            "path_collision",
            "semantic_scope_unchanged_from_v1",
            "unknown_overlap_action",
        }
    ),
    frozenset(
        {
            "issue_92_state",
            "issue_93_state",
            "issue_94_state",
            "issue_96_state",
            "issue_98_intersection_with_92",
            "issue_98_intersection_with_93",
            "issue_98_intersection_with_94",
            "issue_98_intersection_with_96",
            "path_collision",
            "unknown_overlap_action",
        }
    ),
)
REJECTION_RECEIPT_ACTUAL_FIELDS = frozenset(
    {
        "schema",
        "recorded_at",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "packet_sha256",
        "starting_main_contract_sha256",
        "base_sha",
        "base_tree",
        "head_sha",
        "head_tree",
        "canonical_diff_bytes",
        "canonical_diff_sha256",
        "validation_manifest_bytes",
        "validation_manifest_sha256",
        "validation_manifest_correction_sha256",
        "governor_contract_sha256",
        "evaluation_rubric_sha256",
        "governor_report_sha256",
        "governor_attempt_identity",
        "terminal_verb",
        "findings",
        "independent_focused_validation",
        "publication_authorized",
        "repair_authorized",
        "installation_or_runtime_authorized",
        "planner_next_action",
    }
)
REJECTION_RECEIPT_V2_FIELDS = frozenset(
    {
        "schema",
        "recorded_at",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "packet_sha256",
        "starting_main_contract_sha256",
        "base_ref",
        "base_sha",
        "base_tree",
        "head_ref",
        "head_sha",
        "head_tree",
        "canonical_diff_bytes",
        "canonical_diff_sha256",
        "validation_manifest_bytes",
        "validation_manifest_sha256",
        "governor_contract_sha256",
        "evaluation_rubric_sha256",
        "governor_report_sha256",
        "governor_attempt_identity",
        "terminal_verb",
        "findings",
        "publication_authorized",
        "same_packet_repair_authorized",
        "installation_or_runtime_authorized",
        "planner_next_action",
    }
)
REJECTED_MANIFEST_ACTUAL_FIELDS = frozenset(
    {
        "schema",
        "recorded_at",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "terminal_state",
        "direct_packet",
        "base",
        "head",
        "canonical_diff",
        "changed_paths",
        "validation_tool_provenance",
        "validations",
        "invalidated_invocations",
        "findings_closed",
        "numeric_schema_note",
        "live_precommit_fence",
        "cleanliness",
        "excluded_effects",
    }
)
REJECTED_MANIFEST_V4_FIELDS = frozenset(
    {
        "schema",
        "recorded_at",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "terminal_state",
        "direct_packet",
        "base",
        "head",
        "canonical_diff",
        "changed_paths",
        "validation_tool_provenance",
        "validations",
        "findings_closed",
        "independent_exact_hash_audits",
        "replay_contract",
        "live_precommit_fence",
        "cleanliness",
        "excluded_effects",
    }
)
SEALED_TOOL_LOADER = r"""
import fcntl, hashlib, json, os, sys, types
required = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
            fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
try:
    python = json.loads(sys.argv[1])
    python_fd = int(python["fd"])
    python_size = int(python["size"])
    python_before = os.fstat(python_fd)
    python_proc = os.stat("/proc/self/exe", follow_symlinks=True)
    python_contents = os.pread(python_fd, python_size + 1, 0)
    python_after = os.fstat(python_fd)
    python_before_identity = [
        python_before.st_dev, python_before.st_ino, python_before.st_mode,
        python_before.st_uid, python_before.st_gid, python_before.st_nlink,
        python_before.st_size, python_before.st_mtime_ns, python_before.st_ctime_ns,
    ]
    python_after_identity = [
        python_after.st_dev, python_after.st_ino, python_after.st_mode,
        python_after.st_uid, python_after.st_gid, python_after.st_nlink,
        python_after.st_size, python_after.st_mtime_ns, python_after.st_ctime_ns,
    ]
    if (python_before_identity != python["identity"] or
            python_before_identity != python_after_identity or
            python_before.st_size != python_size or
            python_before.st_dev != python_proc.st_dev or
            python_before.st_ino != python_proc.st_ino or
            len(python_contents) != python_size or
            hashlib.sha256(python_contents).hexdigest() != python["sha256"]):
        raise RuntimeError("python_identity")
    bundle = json.loads(sys.argv[2])
    logical_main = sys.argv[3]
    tool_argv = sys.argv[4:]
    loaded = {}
    for item in bundle:
        fd = int(item["fd"])
        size = int(item["size"])
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required != required:
            raise RuntimeError("seals")
        before = os.fstat(fd)
        contents = os.pread(fd, size + 1, 0)
        after = os.fstat(fd)
        if (len(contents) != size or before.st_dev != after.st_dev or
                before.st_ino != after.st_ino or before.st_size != after.st_size or
                hashlib.sha256(contents).hexdigest() != item["sha256"]):
            raise RuntimeError("identity")
        loaded[item["logical_path"]] = contents
        module_name = item.get("module")
        if module_name:
            module = types.ModuleType(module_name)
            module.__file__ = item["logical_path"]
            module.__package__ = None
            sys.modules[module_name] = module
            exec(compile(contents, item["logical_path"], "exec"), module.__dict__)
        os.close(fd)
    main = loaded[logical_main]
    sys.argv = [logical_main, *tool_argv]
    namespace = {
        "__name__": "__main__",
        "__file__": logical_main,
        "__package__": None,
        "__cached__": None,
    }
    exec(compile(main, logical_main, "exec"), namespace)
except BaseException as exc:
    if isinstance(exc, SystemExit):
        raise
    print("BOOTSTRAP_SEALED_TOOL_ATTESTATION_FAILED", file=sys.stderr)
    raise SystemExit(97)
""".strip()


class VerificationError(RuntimeError):
    """A closed verifier invariant failed."""


def _derive_executing_interpreter_path() -> str:
    """Return the kernel-bound interpreter, rejecting caller substitution."""

    try:
        first_link = os.readlink(PYTHON_PROC_SELF_EXE)
        resolved = Path(PYTHON_PROC_SELF_EXE).resolve(strict=True)
        executable = Path(sys.executable)
        if not executable.is_absolute():
            raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED")
        caller_resolved = executable.resolve(strict=True)
        proc_identity = os.stat(PYTHON_PROC_SELF_EXE, follow_symlinks=True)
        path_identity = os.stat(resolved, follow_symlinks=False)
        second_link = os.readlink(PYTHON_PROC_SELF_EXE)
    except VerificationError:
        raise
    except (OSError, RuntimeError) as exc:
        raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED") from exc
    if (
        not resolved.is_absolute()
        or first_link != second_link
        or caller_resolved != resolved
        or not stat.S_ISREG(path_identity.st_mode)
        or (proc_identity.st_dev, proc_identity.st_ino)
        != (path_identity.st_dev, path_identity.st_ino)
    ):
        raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED")
    return os.fspath(resolved)


def _pread_exact(descriptor: int, size: int, error: str) -> bytes:
    if type(size) is not int or size < 0 or size > 1024 * 1024 * 1024:
        raise VerificationError(error)
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        try:
            chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        except OSError as exc:
            raise VerificationError(error) from exc
        if not chunk:
            raise VerificationError(error)
        chunks.append(chunk)
        offset += len(chunk)
    try:
        trailing = os.pread(descriptor, 1, size)
    except OSError as exc:
        raise VerificationError(error) from exc
    if trailing:
        raise VerificationError(error)
    return b"".join(chunks)


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _bind_executing_interpreter() -> tuple[str, int, dict[str, Any], dict[str, Any]]:
    """Pin the running kernel executable descriptor for every child exec."""

    source_fd: int | None = None
    try:
        source_fd = os.open(
            PYTHON_PROC_SELF_EXE,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        resolved = _derive_executing_interpreter_path()
        source_before = os.fstat(source_fd)
        path_metadata = os.stat(resolved, follow_symlinks=False)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or _stat_identity(source_before) != _stat_identity(path_metadata)
            or source_before.st_uid not in {0, 65534, os.getuid()}
            or source_before.st_size <= 0
            or not source_before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED")
        contents = _pread_exact(
            source_fd,
            source_before.st_size,
            "BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED",
        )
        source_after = os.fstat(source_fd)
        if _stat_identity(source_before) != _stat_identity(source_after):
            raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED")
        digest = hashlib.sha256(contents).hexdigest()
        source_identity = {
            "name": "python",
            "logical_path": resolved,
            "resolved_path": resolved,
            "sha256": digest,
            "size": str(source_before.st_size),
            "device": str(source_before.st_dev),
            "inode": str(source_before.st_ino),
            "mode": str(source_before.st_mode),
            "uid": str(source_before.st_uid),
            "gid": str(source_before.st_gid),
            "link_count": str(source_before.st_nlink),
            "mtime_ns": str(source_before.st_mtime_ns),
            "ctime_ns": str(source_before.st_ctime_ns),
            "execution_source": PINNED_PYTHON_EXECUTION_SOURCE,
            "execution_sha256": digest,
        }
        execution_identity = {
            "fd": source_fd,
            "sha256": digest,
            "size": len(contents),
            "device": source_before.st_dev,
            "inode": source_before.st_ino,
            "identity": _stat_identity(source_before),
            "source": PINNED_PYTHON_EXECUTION_SOURCE,
        }
        result_source = source_fd
        source_fd = None
        return resolved, result_source, source_identity, execution_identity
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_PYTHON_EXEC_FD_UNAVAILABLE") from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)


PYTHON, PYTHON_SOURCE_FD, PYTHON_SOURCE_IDENTITY, PYTHON_EXECUTION = (
    _bind_executing_interpreter()
)
PYTHON_EXECUTABLE = f"/proc/self/fd/{PYTHON_EXECUTION['fd']}"


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _require_exact_keys(value: Any, keys: set[str], error: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise VerificationError(error)
    return value


def _require_sha(value: Any, pattern: re.Pattern[str], error: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise VerificationError(error)
    return value


def _require_decimal(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    error: str,
    signed: bool = False,
) -> int:
    pattern = SIGNED_DECIMAL if signed else DECIMAL
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise VerificationError(error)
    parsed = int(value)
    if not (minimum <= parsed <= maximum):
        raise VerificationError(error)
    if str(parsed) != value:
        raise VerificationError(error)
    return parsed


def _strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], value) for key, value in expected.items()
        )
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            _strict_equal(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.commitGraph",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "fetch.writeCommitGraph",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(
    repository_root: Path,
    arguments: Sequence[str],
    *,
    accepted: tuple[int, ...] = (0,),
    output_limit: int = OUTPUT_LIMIT,
    deadline: float | None = None,
    timeout_error: str = "BOOTSTRAP_GIT_TIMEOUT",
) -> subprocess.CompletedProcess[bytes]:
    _enable_subreaper()
    command = [GIT, "-C", os.fspath(repository_root), *arguments]
    baseline = _baseline_children()
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    known: dict[int, tuple[int, int]] = {}
    root_start_time: int | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    cleanup_verified = False
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
            start_new_session=True,
            close_fds=True,
        )
        root_fields = _proc_stat(process.pid)
        if root_fields is not None:
            root_start_time = root_fields[2]
        elif process.poll() is None:
            raise VerificationError("BOOTSTRAP_PID_IDENTITY_UNAVAILABLE")
        if process.stdout is None or process.stderr is None:
            raise VerificationError("BOOTSTRAP_GIT_PIPE_SETUP_FAILED")
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        command_deadline = time.monotonic() + 30
        if deadline is not None:
            command_deadline = min(command_deadline, deadline)
        failure: str | None = None
        while selector.get_map() or process.poll() is None:
            _remember_processes(process.pid, root_start_time, baseline, known)
            if time.monotonic() >= command_deadline:
                failure = timeout_error
                break
            for key, _ in selector.select(timeout=0.02):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = buffers[key.data]
                limit = output_limit if key.data == "stdout" else OUTPUT_LIMIT
                if len(target) + len(chunk) > limit:
                    failure = "BOOTSTRAP_GIT_OUTPUT_LIMIT"
                    break
                target.extend(chunk)
            if failure is not None or process.poll() is not None:
                break

        cleanup_verified = _cleanup_processes(
            process, baseline, known, root_start_time
        )
        if not cleanup_verified:
            raise VerificationError("BOOTSTRAP_GIT_CLEANUP_FAILED")

        drain_deadline = time.monotonic() + 1.0
        while selector.get_map() and time.monotonic() < drain_deadline:
            for key, _ in selector.select(timeout=0.01):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = buffers[key.data]
                limit = output_limit if key.data == "stdout" else OUTPUT_LIMIT
                if len(target) + len(chunk) > limit:
                    failure = "BOOTSTRAP_GIT_OUTPUT_LIMIT"
                    break
                target.extend(chunk)
            if failure is not None:
                break
        if selector.get_map():
            raise VerificationError("BOOTSTRAP_GIT_CLEANUP_FAILED")
        if failure is not None:
            raise VerificationError(failure)
        return_code = process.returncode
        if return_code not in accepted:
            raise VerificationError("BOOTSTRAP_GIT_COMMAND_FAILED")
        return subprocess.CompletedProcess(
            command,
            return_code,
            bytes(buffers["stdout"]),
            bytes(buffers["stderr"]),
        )
    finally:
        if process is not None and not cleanup_verified:
            try:
                _cleanup_processes(process, baseline, known, root_start_time)
            except Exception:
                _signal_process_group(process, root_start_time, signal.SIGKILL)
                _signal_known(known, signal.SIGKILL)
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    # Popen still owns an unreaped direct child here, so this
                    # handle cannot name a recycled unrelated process.
                    process.kill()
                    process.wait(timeout=1)
        if selector is not None:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except Exception:
                    pass
                key.fileobj.close()
            selector.close()
        _close_known_processes(known)


def _resolve_repository(path: Path) -> Path:
    lexical = Path(os.path.abspath(os.fspath(path)))
    try:
        supplied = path.resolve(strict=True)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_REPOSITORY_MISSING") from exc
    if lexical != supplied or not supplied.is_dir():
        raise VerificationError("BOOTSTRAP_REPOSITORY_INVALID")
    metadata = supplied.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise VerificationError("BOOTSTRAP_REPOSITORY_INVALID")
    top = _git(supplied, ("rev-parse", "--show-toplevel")).stdout
    try:
        derived = Path(top.decode("utf-8").strip()).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as exc:
        raise VerificationError("BOOTSTRAP_REPOSITORY_IDENTITY_INVALID") from exc
    if supplied != derived:
        raise VerificationError("BOOTSTRAP_REPOSITORY_ROOT_SUBSTITUTED")
    origin = _git(supplied, ("remote", "get-url", "origin")).stdout
    try:
        origin_url = origin.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise VerificationError("BOOTSTRAP_REPOSITORY_ORIGIN_INVALID") from exc
    if origin_url != ORIGIN_URL:
        raise VerificationError("BOOTSTRAP_REPOSITORY_ORIGIN_SUBSTITUTED")
    common_raw = _git(supplied, ("rev-parse", "--git-common-dir")).stdout
    try:
        common_path = Path(common_raw.decode("utf-8").strip())
        if not common_path.is_absolute():
            common_path = supplied / common_path
        common = common_path.resolve(strict=True)
    except (UnicodeDecodeError, OSError) as exc:
        raise VerificationError("BOOTSTRAP_GIT_COMMON_DIR_INVALID") from exc
    for relative in ("info/grafts", "shallow", "objects/info/alternates"):
        candidate = common / relative
        if candidate.exists() or candidate.is_symlink():
            raise VerificationError("BOOTSTRAP_GIT_DERIVED_OBJECT_STATE_PRESENT")
    return supplied


def _directory_identity(path: Path, label: str) -> dict[str, int]:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise VerificationError(f"BOOTSTRAP_{label}_IDENTITY_INVALID") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise VerificationError(f"BOOTSTRAP_{label}_IDENTITY_INVALID")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _repository_state_identity(repository_root: Path) -> dict[str, dict[str, int]]:
    result = {"worktree": _directory_identity(repository_root, "WORKTREE")}
    for key, argument in (
        ("git_dir", "--git-dir"),
        ("common_dir", "--git-common-dir"),
    ):
        raw = _git(repository_root, ("rev-parse", argument)).stdout
        try:
            value = Path(raw.decode("utf-8").strip())
            if not value.is_absolute():
                value = repository_root / value
            resolved = value.resolve(strict=True)
        except (UnicodeDecodeError, OSError) as exc:
            raise VerificationError("BOOTSTRAP_GIT_DIRECTORY_INVALID") from exc
        result[key] = _directory_identity(resolved, "GIT_DIRECTORY")
    return result


def _git_object_bytes(
    repository_root: Path,
    object_id: str,
    expected_type: str,
    *,
    maximum: int,
    label: str,
    deadline: float | None = None,
    timeout_error: str = "BOOTSTRAP_GIT_TIMEOUT",
) -> bytes:
    _require_sha(object_id, SHA1, f"BOOTSTRAP_{label}_SHA_INVALID")
    try:
        object_type = _git(
            repository_root,
            ("cat-file", "-t", object_id),
            deadline=deadline,
            timeout_error=timeout_error,
        ).stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise VerificationError(f"BOOTSTRAP_{label}_OBJECT_TYPE_INVALID") from exc
    if object_type != expected_type:
        raise VerificationError(f"BOOTSTRAP_{label}_OBJECT_TYPE_INVALID")
    raw_size = _git(
        repository_root,
        ("cat-file", "-s", object_id),
        deadline=deadline,
        timeout_error=timeout_error,
    ).stdout
    try:
        size = int(raw_size.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise VerificationError(f"BOOTSTRAP_{label}_OBJECT_SIZE_INVALID") from exc
    if size < 0 or size > maximum:
        raise VerificationError(f"BOOTSTRAP_{label}_OBJECT_SIZE_INVALID")
    contents = _git(
        repository_root,
        ("cat-file", object_type, object_id),
        output_limit=size,
        deadline=deadline,
        timeout_error=timeout_error,
    ).stdout
    if len(contents) != size:
        raise VerificationError(f"BOOTSTRAP_{label}_OBJECT_SIZE_DRIFT")
    header = f"{object_type} {size}\0".encode("ascii")
    derived = hashlib.sha1(header + contents, usedforsecurity=False).hexdigest()
    if derived != object_id:
        raise VerificationError(f"BOOTSTRAP_{label}_OBJECT_DIGEST_MISMATCH")
    return contents


def _validate_identity_header(line: bytes, name: bytes, label: str) -> None:
    prefix = name + b" "
    if not line.startswith(prefix) or b"\0" in line:
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
    identity = line[len(prefix) :]
    match = re.fullmatch(
        rb"[^<>\r\n]+ <[^<>\r\n]*> (0|[1-9][0-9]*) ([+-][0-9]{4})",
        identity,
    )
    if match is None:
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
    try:
        timestamp = int(match.group(1))
        zone = match.group(2)
        hours = int(zone[1:3])
        minutes = int(zone[3:5])
    except ValueError as exc:  # pragma: no cover - regex already constrains digits
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID") from exc
    if timestamp > 9_223_372_036_854_775_807 or hours > 23 or minutes > 59:
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")


def _validate_commit_tail(lines: Sequence[bytes], label: str) -> None:
    index = 0
    if index < len(lines) and lines[index].startswith(b"encoding "):
        value = lines[index].removeprefix(b"encoding ")
        if not value or len(value) > 255 or any(byte < 0x21 or byte > 0x7E for byte in value):
            raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
        index += 1
    def consume(field: bytes) -> bool:
        nonlocal index
        if index >= len(lines) or not lines[index].startswith(field + b" "):
            return False
        if not lines[index].removeprefix(field + b" "):
            raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
        index += 1
        while index < len(lines) and lines[index].startswith(b" "):
            if len(lines[index]) > OUTPUT_LIMIT:
                raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
            index += 1
        return True

    while consume(b"mergetag"):
        pass
    consume(b"gpgsig")
    consume(b"gpgsig-sha256")
    if index != len(lines):
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")


def _raw_commit(
    repository_root: Path,
    commit: str,
    label: str,
    *,
    ancestry_budget: dict[str, int | float] | None = None,
) -> tuple[str, tuple[str, ...]]:
    maximum = 16 * 1024 * 1024
    if ancestry_budget is not None:
        if (
            ancestry_budget["objects"] >= ANCESTRY_OBJECT_LIMIT
            or ancestry_budget["bytes"] >= ANCESTRY_BYTE_LIMIT
            or time.monotonic() >= ancestry_budget["deadline"]
        ):
            raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT")
        maximum = min(
            maximum, ANCESTRY_BYTE_LIMIT - int(ancestry_budget["bytes"])
        )
    try:
        contents = _git_object_bytes(
            repository_root,
            commit,
            "commit",
            maximum=maximum,
            label=label,
            deadline=(
                float(ancestry_budget["deadline"])
                if ancestry_budget is not None
                else None
            ),
            timeout_error=(
                "BOOTSTRAP_ANCESTRY_LIMIT"
                if ancestry_budget is not None
                else "BOOTSTRAP_GIT_TIMEOUT"
            ),
        )
    except VerificationError as exc:
        if (
            ancestry_budget is not None
            and str(exc) == f"BOOTSTRAP_{label}_OBJECT_SIZE_INVALID"
        ):
            raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT") from exc
        raise
    if ancestry_budget is not None:
        ancestry_budget["objects"] += 1
        ancestry_budget["bytes"] += len(contents)
        if (
            ancestry_budget["objects"] > ANCESTRY_OBJECT_LIMIT
            or ancestry_budget["bytes"] > ANCESTRY_BYTE_LIMIT
        ):
            raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT")
    raw_header, separator, _ = contents.partition(b"\n\n")
    if not separator or b"\r" in raw_header or b"\0" in raw_header:
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
    if raw_header.count(b"\n") + 1 > COMMIT_HEADER_LINE_LIMIT:
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_HEADER_LIMIT")
    header = raw_header.split(b"\n")
    if not header or not header[0].startswith(b"tree "):
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
    try:
        tree = header[0].removeprefix(b"tree ").decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"BOOTSTRAP_{label}_TREE_INVALID") from exc
    _require_sha(tree, SHA1, f"BOOTSTRAP_{label}_TREE_INVALID")
    parents: list[str] = []
    parent_end = 1
    while parent_end < len(header) and header[parent_end].startswith(b"parent "):
        if len(parents) >= ANCESTRY_EDGE_LIMIT:
            raise VerificationError(
                "BOOTSTRAP_ANCESTRY_LIMIT"
                if ancestry_budget is not None
                else f"BOOTSTRAP_{label}_COMMIT_HEADER_LIMIT"
            )
        line = header[parent_end]
        try:
            parent = line.removeprefix(b"parent ").decode("ascii")
        except UnicodeDecodeError as exc:
            raise VerificationError(f"BOOTSTRAP_{label}_PARENT_INVALID") from exc
        _require_sha(parent, SHA1, f"BOOTSTRAP_{label}_PARENT_INVALID")
        if (
            ancestry_budget is not None
            and int(ancestry_budget["edges"]) + len(parents) + 1
            > ANCESTRY_EDGE_LIMIT
        ):
            raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT")
        parents.append(parent)
        parent_end += 1
    if any(line.startswith(b"parent ") for line in header[parent_end:]):
        raise VerificationError(f"BOOTSTRAP_{label}_PARENT_INVALID")
    if ancestry_budget is not None:
        ancestry_budget["edges"] += len(parents)
    if len(header) < parent_end + 2:
        raise VerificationError(f"BOOTSTRAP_{label}_COMMIT_INVALID")
    _validate_identity_header(header[parent_end], b"author", label)
    _validate_identity_header(header[parent_end + 1], b"committer", label)
    _validate_commit_tail(header[parent_end + 2 :], label)
    return tree, tuple(parents)


def _resolve_commit(repository_root: Path, commit: str, label: str) -> dict[str, str]:
    tree, _ = _raw_commit(repository_root, commit, label)
    return {"commit": commit, "tree": tree}


def _require_proper_ancestry(repository_root: Path, base: str, head: str) -> None:
    if base == head:
        raise VerificationError("BOOTSTRAP_BASE_EQUALS_HEAD")
    pending = [head]
    queued = {head}
    visited: set[str] = set()
    budget: dict[str, int | float] = {
        "objects": 0,
        "bytes": 0,
        "edges": 0,
        "deadline": time.monotonic() + ANCESTRY_SECONDS_LIMIT,
    }
    while pending:
        if time.monotonic() >= budget["deadline"]:
            raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT")
        current = pending.pop()
        queued.discard(current)
        if current == base:
            return
        if current in visited:
            continue
        visited.add(current)
        if len(visited) > ANCESTRY_OBJECT_LIMIT:
            raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT")
        _, parents = _raw_commit(
            repository_root,
            current,
            "ANCESTRY",
            ancestry_budget=budget,
        )
        if time.monotonic() >= budget["deadline"]:
            raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT")
        if base in parents:
            return
        for parent in parents:
            if parent not in visited and parent not in queued:
                pending.append(parent)
                queued.add(parent)
                if len(pending) > ANCESTRY_OBJECT_LIMIT:
                    raise VerificationError("BOOTSTRAP_ANCESTRY_LIMIT")
    raise VerificationError("BOOTSTRAP_BASE_NOT_ANCESTOR")


def _require_frozen_refs(
    repository_root: Path, base: str, head: str, branch: str
) -> dict[str, str]:
    remote_base = _git(
        repository_root,
        ("show-ref", "--verify", "--hash", "refs/remotes/origin/main"),
    ).stdout.decode("ascii").strip()
    branch_ref = f"refs/heads/{branch}"
    symbolic = _git(
        repository_root, ("symbolic-ref", "--quiet", "HEAD")
    ).stdout.decode("utf-8").strip()
    candidate_head = _git(
        repository_root, ("show-ref", "--verify", "--hash", branch_ref)
    ).stdout.decode("ascii").strip()
    candidate_remote_ref = f"refs/remotes/origin/{branch}"
    remote_candidate = _git(
        repository_root,
        ("for-each-ref", "--format=%(refname)", candidate_remote_ref),
    ).stdout.decode("utf-8").splitlines()
    remote_tracking = _git(
        repository_root,
        (
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(symref)",
            "refs/remotes/",
        ),
        output_limit=16 * 1024 * 1024,
    ).stdout
    try:
        remote_tracking.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("BOOTSTRAP_REMOTE_REF_INVENTORY_INVALID") from exc
    if remote_base != base:
        raise VerificationError("BOOTSTRAP_BASE_NOT_ACCEPTED_ORIGIN_MAIN")
    if symbolic != branch_ref:
        raise VerificationError("BOOTSTRAP_HEAD_BRANCH_SUBSTITUTED")
    if candidate_head != head:
        raise VerificationError("BOOTSTRAP_HEAD_NOT_REPOSITORY_HEAD")
    if remote_candidate:
        raise VerificationError("BOOTSTRAP_CANDIDATE_REMOTE_REF_PRESENT")
    return {
        "accepted_main_ref": "refs/remotes/origin/main",
        "accepted_main_sha": remote_base,
        "head_ref": branch_ref,
        "head_sha": candidate_head,
        "symbolic_head": symbolic,
        "candidate_remote_ref": "ABSENT",
        "remote_tracking_refs_sha256": _sha256(remote_tracking),
        "remote_tracking_refs_bytes": str(len(remote_tracking)),
    }


def _blob_identity(repository_root: Path, tree: str, path: str) -> tuple[str, str, bytes]:
    listing = _git(
        repository_root,
        ("ls-tree", "-z", tree, "--", path),
    ).stdout
    entries = [entry for entry in listing.split(b"\0") if entry]
    if len(entries) != 1:
        raise VerificationError("BOOTSTRAP_TOOL_PATH_MISSING")
    try:
        metadata, raw_path = entries[0].split(b"\t", 1)
        mode, object_type, blob = metadata.decode("ascii").split(" ")
        listed_path = raw_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise VerificationError("BOOTSTRAP_TOOL_IDENTITY_INVALID") from exc
    if (
        mode not in {"100644", "100755"}
        or object_type != "blob"
        or listed_path != path
        or SHA1.fullmatch(blob) is None
    ):
        raise VerificationError("BOOTSTRAP_TOOL_IDENTITY_INVALID")
    contents = _git_object_bytes(
        repository_root,
        blob,
        "blob",
        maximum=16 * 1024 * 1024,
        label="TOOL",
    )
    if not contents:
        raise VerificationError("BOOTSTRAP_TOOL_SIZE_INVALID")
    return blob, _sha256(contents), contents


def _require_packet_git_scope(
    repository_root: Path,
    base_tree: str,
    base: str,
    head: str,
    packet: dict[str, Any],
) -> None:
    raw_paths = _git(
        repository_root,
        (
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "--no-renames",
            "-z",
            base,
            head,
        ),
        output_limit=16 * 1024 * 1024,
    ).stdout
    try:
        changed = [
            value.decode("utf-8") for value in raw_paths.split(b"\0") if value
        ]
    except UnicodeDecodeError as exc:
        raise VerificationError("BOOTSTRAP_CHANGED_PATH_INVALID") from exc
    expected_paths = packet["mutable_path_order"]
    if (
        len(changed) != len(expected_paths)
        or len(set(changed)) != len(changed)
        or set(changed) != set(expected_paths)
    ):
        raise VerificationError("BOOTSTRAP_CHANGED_PATH_SET_MISMATCH")
    for item in packet["mutable_paths"]:
        path = item["path"]
        listing = _git(
            repository_root, ("ls-tree", "-z", base_tree, "--", path)
        ).stdout
        if not listing:
            if (
                item["starting_sha256"] != "ABSENT"
                or item["starting_git_blob"] != "ABSENT"
            ):
                raise VerificationError("BOOTSTRAP_MUTABLE_PATH_PREIMAGE_MISMATCH")
            continue
        blob, digest, _ = _blob_identity(repository_root, base_tree, path)
        if (
            item["starting_sha256"] != digest
            or item["starting_git_blob"] != blob
        ):
            raise VerificationError("BOOTSTRAP_MUTABLE_PATH_PREIMAGE_MISMATCH")


def _require_issue92_post_merge_git_bindings(
    repository_root: Path,
    packet: dict[str, Any],
    *,
    head_sha: str,
    head_tree: str,
    head_parents: tuple[str, ...],
    reference_identity: dict[str, str],
) -> None:
    if packet.get("candidate_head") is None:
        return
    error = "BOOTSTRAP_ISSUE92_POST_MERGE_GIT_BINDING_INVALID"
    base_sha = packet["base_sha"]
    base_tree = packet["base_tree"]
    if (
        packet.get("issue_number") != 92
        or head_sha != packet.get("candidate_head")
        or head_tree != packet.get("candidate_tree")
        or head_parents != (base_sha,)
        or packet.get("candidate_parent") != base_sha
    ):
        raise VerificationError(error)
    prior_tree, prior_parents = _raw_commit(
        repository_root,
        packet["prior_retained_head"],
        "PRIOR_RETAINED",
    )
    if (
        prior_tree != packet["prior_retained_tree"]
        or prior_parents != (packet["prior_retained_parent"],)
    ):
        raise VerificationError(error)
    expected_fence = {
        "accepted_main_ref": reference_identity["accepted_main_ref"],
        "accepted_main_sha": reference_identity["accepted_main_sha"],
        "accepted_main_tree": base_tree,
        "head_ref": reference_identity["head_ref"],
        "candidate_head": reference_identity["head_sha"],
        "candidate_tree": head_tree,
        "candidate_parent": base_sha,
        "candidate_remote_ref": reference_identity["candidate_remote_ref"],
    }
    if not _strict_equal(packet.get("repository_fence"), expected_fence):
        raise VerificationError(error)


def _read_regular_with_identity(
    path: Path,
    *,
    maximum: int,
    error: str,
    allowed_uids: set[int] | None = None,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(error) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in (allowed_uids or {os.getuid()})
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or before.st_size > maximum
        ):
            raise VerificationError(error)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(contents) > maximum
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_gid != after.st_gid
            or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or len(contents) != after.st_size
        ):
            raise VerificationError(error)
        return contents, after
    finally:
        os.close(descriptor)


def _read_regular(
    path: Path,
    *,
    maximum: int,
    error: str,
    allowed_uids: set[int] | None = None,
) -> bytes:
    contents, _ = _read_regular_with_identity(
        path,
        maximum=maximum,
        error=error,
        allowed_uids=allowed_uids,
    )
    return contents


def _validate_json_nesting(raw: bytes, error: str, maximum: int = 128) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > maximum:
                raise VerificationError(error)
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                raise VerificationError(error)


def _load_json_object(
    raw: bytes, error: str, *, reject_floats: bool = True
) -> dict[str, Any]:
    _validate_json_nesting(raw, error)

    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate-key")
            result[key] = value
        return result

    def closed_integer(token: str) -> int:
        if len(token.lstrip("-")) > 19:
            raise ValueError("integer-too-long")
        return int(token)

    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
            parse_int=closed_integer,
            parse_float=(
                (lambda token: (_ for _ in ()).throw(ValueError(token)))
                if reject_floats
                else float
            ),
            object_pairs_hook=closed_object,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
        OverflowError,
    ) as exc:
        raise VerificationError(error) from exc
    if type(value) is not dict:
        raise VerificationError(error)
    return value


def _classify_packet_route(packet: Any) -> str:
    if type(packet) is not dict:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCHEMA_INVALID")
    claims_direct = (
        packet.get("schema") == "twinfinity-direct-harness-source-maintenance/v1"
        or packet.get("repository") == REPOSITORY
    )
    if not claims_direct:
        return APPLICATION_ROUTE
    if (
        packet.get("schema") != "twinfinity-direct-harness-source-maintenance/v1"
        or packet.get("repository") != REPOSITORY
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_ROUTE_SUBSTITUTED")
    return DIRECT_ROUTE


def _packet_string_list(packet: dict[str, Any], key: str) -> list[str]:
    value = packet.get(key)
    if (
        type(value) is not list
        or not value
        or any(type(item) is not str or not item or len(item) > 1024 for item in value)
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCHEMA_INVALID")
    return value


def _closed_keys(
    value: Any,
    variants: Sequence[frozenset[str]],
    error: str,
) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) not in variants:
        raise VerificationError(error)
    return value


def _validate_packet_document_shape(
    document: dict[str, Any], generation: int
) -> None:
    error = "BOOTSTRAP_DIRECT_PACKET_SCHEMA_INVALID"
    key_sets = PACKET_KEY_SETS.get(generation)
    if key_sets is None or frozenset(document) not in key_sets:
        raise VerificationError(error)
    if generation == 1 and not DIRECT_PACKET_BASE_REQUIRED.issubset(document):
        raise VerificationError(error)
    if "attempt_generation" in document and (
        type(document["attempt_generation"]) is not int
        or document["attempt_generation"] != generation
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    if generation >= 2:
        transition_contract = TRANSITION_VALUE_CONTRACTS.get(
            (document.get("owning_issue"), generation)
        )
        if transition_contract is None or any(
            document.get(key) != value
            for key, value in transition_contract.items()
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        _require_sha(
            document.get("supersedes_packet_sha256"),
            SHA256,
            "BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID",
        )
        for key in (
            "writer_transfer",
            "prior_writer_terminal_state",
            "fresh_planner_disposition_reason",
        ):
            if key in document and (
                type(document[key]) is not str or not document[key]
            ):
                raise VerificationError(
                    "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
                )
        if "prior_writer" in document and (
            type(document["prior_writer"]) is not str
            or not document["prior_writer"].startswith("/root/")
            or document["prior_writer"] == document.get("accountable_writer")
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        for key in ("repair_starting_head", "repair_starting_tree"):
            if key in document:
                _require_sha(
                    document[key],
                    SHA1,
                    "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
                )
        if generation in {2, 3} and "repair_starting_head" in document and (
            document["repair_starting_head"] != document.get("starting_main_sha")
            or document["repair_starting_tree"]
            != document.get("starting_main_tree")
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        if "incorporation" in document and (
            type(document["incorporation"]) is not str
            or "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE"
            not in document["incorporation"]
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")

    for key in ("recorded_at", "accountable_writer", "current_stage"):
        if key in document and (
            type(document[key]) is not str or not document[key]
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")
    if "accountable_writer" in document and not document[
        "accountable_writer"
    ].startswith("/root/"):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")
    if "repair_budget" in document and (
        type(document["repair_budget"]) is not int
        or document["repair_budget"] != 1
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")

    if "authority" in document:
        authority = _closed_keys(
            document["authority"],
            AUTHORITY_KEY_SETS,
            "BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID",
        )
        instruction_key = (
            "direct_owner_instructions"
            if "direct_owner_instructions" in authority
            else "instructions"
        )
        if (
            authority["kind"]
            not in {
                "DIRECT_OWNER_INSTRUCTION",
                "DIRECT_OWNER_INSTRUCTION_PLUS_PLANNER_OBSERVED_PRODUCT_FLOW_BLOCKER_DISPOSITION",
            }
            or type(authority[instruction_key]) is not list
            or not authority[instruction_key]
            or any(
                type(item) is not str or not item
                for item in authority[instruction_key]
            )
            or (
                "sqlite_harness_loop" in authority
                and authority["sqlite_harness_loop"]
                != "PROHIBITED_FOR_HARNESS_SOURCE_MAINTENANCE"
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID")
        for key in (
            "temporary_six_writer_authority_sha256",
            "standing_routine_delivery_authority_sha256",
        ):
            _require_sha(
                authority[key],
                SHA256,
                "BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID",
            )

    if "direct_capacity" in document:
        capacity = _closed_keys(
            document["direct_capacity"],
            CAPACITY_KEY_SETS,
            "BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID",
        )
        occupancy = [
            capacity[key]
            for key in (
                "occupancy_after_reservation_including_active_and_retained",
                "occupancy_including_active_and_retained",
            )
            if key in capacity
        ]
        if (
            capacity["class"] != "HARNESS_SOURCE_WRITER"
            or type(capacity["units"]) is not int
            or capacity["units"] != 1
            or type(capacity["temporary_limit"]) is not int
            or capacity["temporary_limit"] != 6
            or len(occupancy) != 1
            or type(occupancy[0]) is not int
            or not (1 <= occupancy[0] <= capacity["temporary_limit"])
            or type(capacity["sqlite_allocation_units"]) is not int
            or capacity["sqlite_allocation_units"] != 0
            or (
                "capacity_effect" in capacity
                and (
                    type(capacity["capacity_effect"]) is not str
                    or not capacity["capacity_effect"]
                )
            )
            or (
                "occupancy_components" in capacity
                and (
                    type(capacity["occupancy_components"]) is not list
                    or not capacity["occupancy_components"]
                    or len(set(capacity["occupancy_components"]))
                    != len(capacity["occupancy_components"])
                    or len(capacity["occupancy_components"]) != occupancy[0]
                    or any(
                        type(item) is not str or not item
                        for item in capacity["occupancy_components"]
                    )
                )
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID")

    if "repository_fence" in document:
        fence = _closed_keys(
            document["repository_fence"],
            REPOSITORY_FENCE_KEY_SETS,
            "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID",
        )
        branches = fence["remote_branches"]
        if (
            type(fence["observed_at"]) is not str
            or type(fence["live_main"]) is not str
            or type(fence["open_pull_requests"]) is not int
            or fence["open_pull_requests"] != 0
            or type(branches) is not list
            or branches == []
            or fence["candidate_remote_branch_present"] is not False
        ):
            raise VerificationError(
                "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
            )
        for key in (
            "planned_local_branch_present",
            "planned_worktree_present",
            "local_branch_exact",
            "local_worktree_exact",
        ):
            if key in fence and type(fence[key]) is not bool:
                raise VerificationError(
                    "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
                )
        if (
            "planned_local_branch_present" in fence
            and (
                fence["planned_local_branch_present"] is not False
                or fence["planned_worktree_present"] is not False
            )
        ):
            raise VerificationError(
                "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
            )
        if (
            "local_branch_exact" in fence
            and (
                fence["local_branch_exact"] is not True
                or fence["local_worktree_exact"] is not True
            )
        ):
            raise VerificationError(
                "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
            )
        for key in (
            "local_branch_inventory_sha256",
            "local_worktree_porcelain_sha256",
        ):
            if key in fence:
                _require_sha(
                    fence[key],
                    SHA256,
                    "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID",
                )
        if "live_main_tree" in fence:
            _require_sha(
                fence["live_main_tree"],
                SHA1,
                "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID",
            )
        for branch_entry in branches:
            if type(branch_entry) is str:
                if not branch_entry:
                    raise VerificationError(
                        "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
                    )
            elif type(branch_entry) is dict and set(branch_entry) == {"name", "sha"}:
                if type(branch_entry["name"]) is not str or not branch_entry["name"]:
                    raise VerificationError(
                        "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
                    )
                _require_sha(
                    branch_entry["sha"],
                    SHA1,
                    "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID",
                )
            else:
                raise VerificationError(
                    "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
                )
        expected_branches: list[Any]
        if "planned_local_branch_present" in fence:
            expected_branches = [{"name": "main", "sha": fence["live_main"]}]
        else:
            expected_branches = ["main"]
        if branches != expected_branches:
            raise VerificationError(
                "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
            )

    if "collision_fence" in document:
        collision = document["collision_fence"]
        collision = _closed_keys(
            collision,
            COLLISION_KEY_SETS,
            "BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID",
        )
        if (
            type(collision["path_collision"]) is not bool
            or collision["path_collision"] is not False
            or collision["unknown_overlap_action"] != "HOLD"
            or any(
                type(value) is not list or value != []
                for key, value in collision.items()
                if "intersection" in key
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
        for key in (
            "branch_collision",
            "worktree_collision",
            "semantic_scope_unchanged_from_v1",
        ):
            if key in collision and (
                type(collision[key]) is not bool
                or (
                    key == "semantic_scope_unchanged_from_v1"
                    and collision[key] is not True
                )
                or (
                    key != "semantic_scope_unchanged_from_v1"
                    and collision[key] is not False
                )
            ):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
        if (
            "historical_and_retired_worktree_mutation" in collision
            and collision["historical_and_retired_worktree_mutation"]
            != "PROHIBITED"
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
        for key, value in collision.items():
            if key.endswith("_state") or key.startswith("semantic_relation_with_"):
                if type(value) is not str or not value:
                    raise VerificationError(
                        "BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID"
                    )
            if key.endswith("_mutable_paths_sha256"):
                _require_sha(
                    value,
                    SHA256,
                    "BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID",
                )
        if "issue_92_worktree" in collision and (
            type(collision["issue_92_worktree"]) is not str
            or not Path(collision["issue_92_worktree"]).is_absolute()
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")

    if "bootstrap_validation_contract" in document:
        validation = document["bootstrap_validation_contract"]
        issue = document.get("owning_issue")
        validation_keys = frozenset(
            {
                f"self_verification_for_issue_{issue}",
                f"issue_{issue}_source_acceptance",
            }
        )
        validation = _closed_keys(
            validation,
            (validation_keys, validation_keys | {"future_issue_92_use"}),
            "BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID",
        )
        if (
            validation[f"self_verification_for_issue_{issue}"] != "PROHIBITED"
            or type(validation[f"issue_{issue}_source_acceptance"]) is not list
            or any(
                type(item) is not str or not item
                for item in validation[f"issue_{issue}_source_acceptance"]
            )
            or (
                "future_issue_92_use" in validation
                and validation["future_issue_92_use"]
                != (
                    "ONLY_AFTER_ISSUE_98_MERGES_AND_THE_VERIFIER_BYTES_"
                    "ARE_PART_OF_THE_EXACT_ACCEPTED_BASE"
                )
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")

    if "dependencies" in document:
        dependencies = document["dependencies"]
        dependency_key_sets = (
            frozenset(
                {
                    "issue_91_accepted_head",
                    "issue_91_merge_result_main",
                    "issue_91_source_complete",
                    "issue_91_terminal_receipt_body_sha256",
                    "unmet_dependencies",
                }
            ),
            frozenset(
                {
                    "predecessor_issue",
                    "predecessor_source_complete",
                    "predecessor_accepted_head",
                    "predecessor_merge_result_main",
                    "predecessor_terminal_receipt_body_sha256",
                    "unmet_dependencies",
                }
            ),
        )
        dependencies = _closed_keys(
            dependencies,
            dependency_key_sets,
            "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID",
        )
        if dependencies["unmet_dependencies"] != []:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID")
        for key, value in dependencies.items():
            if key.endswith("_complete") and type(value) is not bool:
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID")
            if key.endswith("_sha"):
                _require_sha(
                    value, SHA1, "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID"
                )
            if key.endswith("_sha256"):
                _require_sha(
                    value, SHA256, "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID"
                )
        if "issue_91_merge_result_main" in dependencies and (
            dependencies.get("issue_91_source_complete") is not True
            or dependencies["issue_91_merge_result_main"]
            != document.get("starting_main_sha")
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID")
        if "predecessor_issue" in dependencies and (
            type(dependencies["predecessor_issue"]) is not int
            or dependencies["predecessor_issue"] <= 0
            or (
                document.get("owning_issue") == 92
                and dependencies["predecessor_issue"] != 98
            )
            or dependencies.get("predecessor_source_complete") is not True
            or dependencies["predecessor_merge_result_main"]
            != document.get("starting_main_sha")
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID")
        if "predecessor_issue" in dependencies:
            for key in (
                "predecessor_accepted_head",
                "predecessor_merge_result_main",
            ):
                _require_sha(
                    dependencies[key],
                    SHA1,
                    "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID",
                )
            _require_sha(
                dependencies["predecessor_terminal_receipt_body_sha256"],
                SHA256,
                "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID",
            )

    if "authorized_stages" in document:
        stages = document["authorized_stages"]
        if (
            type(stages) is not list
            or any(type(item) is not str or not item for item in stages)
            or any(
                token in " ".join(stages)
                for token in (
                    "REMOTE_PUBLICATION",
                    "PULL_REQUEST",
                    "MERGE",
                    "INSTALLATION",
                    "RUNTIME_ACTIVATION",
                    "SQLITE_MUTATION",
                    "SELF_APPROVAL",
                )
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")

    if "trigger" in document:
        trigger = document["trigger"]
        trigger = _closed_keys(
            trigger,
            (
                frozenset(
                    {
                        "kind",
                        "invariant",
                        "measurable_effect",
                        "blocked_consumer_issue",
                        "blocked_consumer_hold_comment_id",
                    }
                ),
            ),
            "BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID",
        )
        if any(
            type(trigger[key]) is not str or not trigger[key]
            for key in ("kind", "invariant", "measurable_effect")
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")
        for key in ("blocked_consumer_issue", "blocked_consumer_hold_comment_id"):
            if key in trigger and (
                type(trigger[key]) is not int or trigger[key] <= 0
            ):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")

    if "adopted_uncommitted_state" in document:
        adopted = document["adopted_uncommitted_state"]
        v2_keys = frozenset(
            {
                "changed_paths",
                "schema_sha256",
                "schema_json_valid",
                "script_path_state",
                "test_path_state",
                "tracked_changes",
                "untracked_authorized_paths",
                "commit_created",
                "validation_run",
            }
        )
        v3_keys = frozenset(
            {
                "status",
                "head",
                "tree",
                "canonical_diff_sha256",
                "canonical_diff_bytes",
                "canonical_diff_algorithm",
                "paths",
                "commit_created",
                "remote_effect",
            }
        )
        adopted = _closed_keys(
            adopted,
            (v2_keys, v3_keys),
            "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
        )
        if frozenset(adopted) == v2_keys:
            if (
                type(adopted["changed_paths"]) is not list
                or adopted["changed_paths"] != document["mutable_path_order"][:1]
                or adopted["schema_json_valid"] is not True
                or adopted["script_path_state"] != "ABSENT"
                or adopted["test_path_state"] != "ABSENT"
                or type(adopted["tracked_changes"]) is not int
                or adopted["tracked_changes"] != 0
                or type(adopted["untracked_authorized_paths"]) is not int
                or adopted["untracked_authorized_paths"] != 1
                or adopted["commit_created"] is not False
                or adopted["validation_run"] is not False
            ):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
            _require_sha(
                adopted["schema_sha256"],
                SHA256,
                "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
            )
        else:
            if (
                adopted["status"]
                != (
                    f"EXACTLY_{COUNT_WORDS.get(len(document['mutable_path_order']), '')}_"
                    "AUTHORIZED_UNTRACKED_PATHS_NO_TRACKED_DIFF"
                )
                or adopted["head"] != document["repair_starting_head"]
                or adopted["tree"] != document["repair_starting_tree"]
                or type(adopted["canonical_diff_bytes"]) is not int
                or adopted["canonical_diff_bytes"] < 0
                or type(adopted["canonical_diff_algorithm"]) is not str
                or not adopted["canonical_diff_algorithm"]
                or type(adopted["paths"]) is not list
                or [
                    item.get("path") if type(item) is dict else None
                    for item in adopted["paths"]
                ]
                != document["mutable_path_order"]
                or adopted["commit_created"] is not False
                or adopted["remote_effect"] is not False
            ):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
            for key in ("head", "tree"):
                _require_sha(
                    adopted[key],
                    SHA1,
                    "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
                )
            _require_sha(
                adopted["canonical_diff_sha256"],
                SHA256,
                "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
            )
            for item in adopted["paths"]:
                if (
                    type(item) is not dict
                    or set(item) != {"path", "sha256", "git_blob", "bytes", "mode"}
                    or type(item["path"]) is not str
                    or not item["path"]
                    or type(item["bytes"]) is not int
                    or item["bytes"] < 0
                    or item["mode"] not in {"0644", "0755"}
                ):
                    raise VerificationError(
                        "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
                    )
                _require_sha(
                    item["sha256"],
                    SHA256,
                    "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
                )
                _require_sha(
                    item["git_blob"],
                    SHA1,
                    "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
                )

    if "inherited_validation_evidence" in document:
        validation = _closed_keys(
            document["inherited_validation_evidence"],
            (
                frozenset(
                    {
                        "focused_adversarial",
                        "raw_fixed_skill_validators",
                        "executor_registry_audit",
                        "full_hermetic",
                        "acceptance_effect",
                    }
                ),
            ),
            "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
        )
        if (
            any(type(value) is not str or not value for value in validation.values())
            or "PRE_CHANGED_DIAGNOSIS" not in validation["focused_adversarial"]
            or "PRE_CHANGED_DIAGNOSIS"
            not in validation["raw_fixed_skill_validators"]
            or "PRE_CHANGED_DIAGNOSIS" not in validation["executor_registry_audit"]
            or not validation["full_hermetic"].startswith("INVALID_GATE_")
            or not validation["acceptance_effect"].startswith(
                "NO_INHERITED_RESULT_AUTHORIZES_FINAL_HEAD_ACCEPTANCE"
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")


def _packet_documents(
    path: Path,
    packet: dict[str, Any],
) -> list[tuple[dict[str, Any], str, str]]:
    raw_descriptors: Any
    if "incorporated_packets" in packet and "incorporated_packet" in packet:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    if "incorporated_packets" in packet:
        raw_descriptors = packet["incorporated_packets"]
    elif "incorporated_packet" in packet:
        raw_descriptors = [packet["incorporated_packet"]]
    else:
        raw_descriptors = []
    if type(raw_descriptors) is not list or len(raw_descriptors) > 16:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    documents: list[tuple[dict[str, Any], str, str]] = []
    seen: set[str] = set()
    for descriptor in raw_descriptors:
        if (
            type(descriptor) is not dict
            or not {"path", "sha256"}.issubset(descriptor)
            or any(
                key not in {"path", "sha256", "incorporation"}
                for key in descriptor
            )
            or (
                "incorporation" in descriptor
                and (
                    type(descriptor["incorporation"]) is not str
                    or not descriptor["incorporation"]
                )
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
        source = descriptor.get("path")
        digest = descriptor.get("sha256")
        if type(source) is not str or not Path(source).is_absolute():
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
        _require_sha(digest, SHA256, "BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
        if digest in seen:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
        seen.add(digest)
        prior_raw = _read_regular(
            Path(source),
            maximum=1024 * 1024,
            error="BOOTSTRAP_DIRECT_PACKET_LINEAGE_UNSAFE",
        )
        if _sha256(prior_raw) != digest:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_DIGEST_MISMATCH")
        prior = _load_json_object(
            prior_raw, "BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID_JSON"
        )
        if _classify_packet_route(prior) != DIRECT_ROUTE:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
        documents.append((prior, digest, source))
    if documents:
        supersedes = packet.get("supersedes_packet_sha256")
        if supersedes != documents[-1][1]:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
        prior_digest: str | None = None
        prior_generation = 0
        cumulative: dict[str, Any] = {}
        for index, (document, digest, _) in enumerate(documents):
            if document.get("repository") != REPOSITORY or document.get(
                "owning_issue"
            ) != packet.get("owning_issue"):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
            declared_prior = document.get("supersedes_packet_sha256")
            generation = document.get("attempt_generation", 1 if index == 0 else None)
            if type(generation) is not int or generation != index + 1:
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
            _validate_packet_document_shape(document, generation)
            if index == 0 and not DIRECT_PACKET_BASE_REQUIRED.issubset(document):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
            if index:
                if document.get("prior_writer") != cumulative.get(
                    "accountable_writer"
                ):
                    raise VerificationError(
                        "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
                    )
                for key in PROTECTED_PACKET_FIELDS.intersection(document):
                    if key not in cumulative or not _strict_equal(
                        document[key], cumulative[key]
                    ):
                        raise VerificationError(
                            "BOOTSTRAP_DIRECT_PACKET_INHERITED_FIELD_SUBSTITUTED"
                        )
                if "direct_capacity" in document:
                    prior_capacity = cumulative.get("direct_capacity")
                    current_capacity = document["direct_capacity"]
                    if (
                        type(prior_capacity) is not dict
                        or type(current_capacity) is not dict
                        or any(
                            not _strict_equal(
                                current_capacity.get(key), prior_capacity.get(key)
                            )
                            for key in (
                                "class",
                                "units",
                                "temporary_limit",
                                "sqlite_allocation_units",
                            )
                        )
                    ):
                        raise VerificationError(
                            "BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID"
                        )
            if index == 0 and (
                declared_prior is not None
                or "incorporated_packet" in document
                or "incorporated_packets" in document
            ):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
            if index and declared_prior != prior_digest:
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
            if index:
                expected_descriptors = [
                    {"path": source, "sha256": prior_sha}
                    for _, prior_sha, source in documents[:index]
                ]
                if index == 1:
                    singular = document.get("incorporated_packet")
                    if (
                        type(singular) is not dict
                        or singular.get("path") != expected_descriptors[0]["path"]
                        or singular.get("sha256") != expected_descriptors[0]["sha256"]
                        or any(key not in {"path", "sha256", "incorporation"} for key in singular)
                        or (
                            "incorporation" in singular
                            and (
                                type(singular["incorporation"]) is not str
                                or not singular["incorporation"]
                            )
                        )
                    ):
                        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
                    if "incorporated_packets" in document:
                        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
                elif (
                    document.get("incorporated_packets") != expected_descriptors
                    or "incorporated_packet" in document
                ):
                    raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
            prior_generation = generation
            prior_digest = digest
            prior_cumulative = dict(cumulative)
            cumulative.update(document)
            _validate_packet_envelope(
                document,
                cumulative,
                prior_cumulative,
                digest,
                [prior_sha for _, prior_sha, _ in documents[:index]],
            )
        current_generation = packet.get("attempt_generation")
        if current_generation != prior_generation + 1:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    elif (
        packet.get("attempt_generation", 1) != 1
        or packet.get("supersedes_packet_sha256") is not None
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    return documents


def _effective_packet(
    path: Path, packet: dict[str, Any]
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    documents = _packet_documents(path, packet)
    inherited: dict[str, Any] = {}
    digests: list[str] = []
    for document, digest, _ in documents:
        inherited.update(document)
        digests.append(digest)
    effective = dict(inherited)
    effective.update(packet)
    if packet.get("attempt_generation") == 5 and "excluded_effects" in packet:
        inherited_excluded = inherited.get("excluded_effects")
        additional_excluded = packet["excluded_effects"]
        if (
            packet.get("owning_issue") != 98
            or inherited_excluded != list(ISSUE98_INHERITED_EXCLUDED_EFFECTS)
            or additional_excluded
            != list(ISSUE98_V5_ADDITIONAL_EXCLUDED_EFFECTS)
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_HARD_STOP_INVALID")
        effective["excluded_effects"] = [
            *inherited_excluded,
            *additional_excluded,
        ]
    return effective, digests, inherited


def _validate_rejection_receipt_shape(receipt: dict[str, Any]) -> None:
    error = "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
    keys = frozenset(receipt)
    if keys not in {REJECTION_RECEIPT_ACTUAL_FIELDS, REJECTION_RECEIPT_V2_FIELDS}:
        raise VerificationError(error)
    if (
        receipt.get("schema")
        != "twinfinity-harness-governor-rejection-receipt/v1"
        or receipt.get("repository") != REPOSITORY
        or type(receipt.get("owning_issue")) is not int
        or receipt["owning_issue"] <= 0
        or receipt.get("terminal_verb") != "REJECT_SOURCE_HEAD"
        or receipt.get("publication_authorized") is not False
        or type(receipt.get("canonical_diff_bytes")) is not int
        or receipt["canonical_diff_bytes"] < 0
        or type(receipt.get("governor_attempt_identity")) is not str
        or not receipt["governor_attempt_identity"]
        or type(receipt.get("findings")) is not list
        or not receipt["findings"]
        or type(receipt.get("recorded_at")) is not str
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            receipt["recorded_at"],
        )
        is None
        or type(receipt.get("validation_manifest_bytes")) is not int
        or receipt["validation_manifest_bytes"] < 0
        or receipt.get("installation_or_runtime_authorized") is not False
        or type(receipt.get("planner_next_action")) is not str
        or not receipt["planner_next_action"]
    ):
        raise VerificationError(error)
    for key in ("base_sha", "base_tree", "head_sha", "head_tree"):
        _require_sha(receipt.get(key), SHA1, error)
    for key in (
        "issue_body_sha256",
        "packet_sha256",
        "canonical_diff_sha256",
        "validation_manifest_sha256",
        "governor_report_sha256",
        "starting_main_contract_sha256",
        "governor_contract_sha256",
        "evaluation_rubric_sha256",
    ):
        _require_sha(receipt.get(key), SHA256, error)
    if keys == REJECTION_RECEIPT_ACTUAL_FIELDS:
        if (
            receipt.get("repair_authorized") is not False
            or receipt.get("installation_or_runtime_authorized") is not False
            or receipt.get("independent_focused_validation")
            != "24_OF_24_PASS_BUT_INSUFFICIENT"
        ):
            raise VerificationError(error)
        _require_sha(
            receipt.get("validation_manifest_correction_sha256"), SHA256, error
        )
        if any(
            type(item) is not dict
            or set(item) != {"code", "severity", "required_change"}
            or type(item["code"]) is not str
            or not item["code"]
            or item["severity"] not in {"CRITICAL", "HIGH", "MEDIUM"}
            or type(item["required_change"]) is not str
            or re.fullmatch(r"[A-Z0-9_]{20,512}", item["required_change"])
            is None
            for item in receipt["findings"]
        ) or (
            receipt["owning_issue"] == 98
            and [item["severity"] for item in receipt["findings"]]
            != [
                "CRITICAL",
                "HIGH",
                "HIGH",
                "HIGH",
                "HIGH",
                "HIGH",
                "HIGH",
                "HIGH",
                "HIGH",
                "HIGH",
                "MEDIUM",
            ]
        ) or (
            receipt["owning_issue"] != 98
            and [item["severity"] for item in receipt["findings"]]
            != ["CRITICAL"]
        ):
            raise VerificationError(error)
    else:
        if (
            receipt.get("same_packet_repair_authorized") is not False
            or receipt.get("base_ref") != "refs/heads/main"
            or receipt.get("head_ref")
            != f"refs/heads/change/{receipt['owning_issue']}-immutable-bootstrap-verifier"
            or any(
                type(item) is not dict
                or set(item) != {"code", "severity", "evidence", "required_change"}
                or type(item.get("code")) is not str
                or not item["code"]
                or item.get("severity") not in {"CRITICAL", "HIGH", "MEDIUM"}
                or type(item.get("required_change")) is not str
                or re.fullmatch(r"[A-Z0-9_]{20,512}", item["required_change"])
                is None
                or type(item.get("evidence")) is not dict
                or not item["evidence"]
                or any(
                    type(key) is not str
                    or not key
                    or type(value) not in {str, int}
                    or value == ""
                    for key, value in item["evidence"].items()
                )
                for item in receipt["findings"]
            )
            or [item["severity"] for item in receipt["findings"]]
            != ["CRITICAL", "CRITICAL"]
        ):
            raise VerificationError(error)


def _validate_v4_manifest_validation_evidence(
    manifest: dict[str, Any],
    *,
    paths: list[dict[str, Any]],
    effective: dict[str, Any],
    base_sha: str,
    base_tree: str,
) -> None:
    error = "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
    worktree = effective["worktree_path"]
    candidate_root = Path(worktree)
    replay = manifest["replay_contract"]
    retained_root = Path(replay["retained_gate_root"])
    accepted_root = retained_root / "accepted-base"
    accepted_validator = accepted_root / VALIDATOR_PATH
    accepted_registry = accepted_root / REGISTRY_AUDIT_PATH
    schema_path = candidate_root / SCHEMA_PATH
    verifier_path = candidate_root / VERIFIER_PATH
    test_path = (
        candidate_root
        / "skills/twinfinity-sprint-orchestrator/tests/"
        "test_verify_harness_baseline_receipt.py"
    )
    runner_path = (
        candidate_root
        / "skills/twinfinity-sprint-orchestrator/scripts/run_hermetic_tests.py"
    )
    reference_root = (
        candidate_root / "skills/twinfinity-sprint-orchestrator/references"
    )
    schema_code = (
        "import json,sys; from jsonschema import Draft202012Validator; "
        'p=sys.argv[1]; document=json.loads(open(p,"rb").read()); '
        "Draft202012Validator.check_schema(document); "
        'print("PASS draft-2020-12 schema")'
    )
    lineage_code = (
        "import importlib.util,pathlib,sys; "
        "module_path=pathlib.Path(sys.argv[1]); "
        'spec=importlib.util.spec_from_file_location("packet_verifier",module_path); '
        "module=importlib.util.module_from_spec(spec); "
        "spec.loader.exec_module(module); "
        "pairs=zip(sys.argv[2::2],sys.argv[3::2],strict=True); "
        'results=[module._load_direct_packet(pathlib.Path(path),digest)["route"] '
        "for path,digest in pairs]; "
        "assert results==[module.DIRECT_ROUTE]*4; "
        'print("PASS actual packet lineage v1-v4")'
    )
    plan_root = Path("/home/ubuntu/code/twinfinity/plans")
    packet_digests = (
        "84d516552f24ad5cc04959a822977a27ab20fd061787365d3268fec10001f5e6",
        "beaa061d96ad3aecef57b7a2282db29fc8e2113f2b638b4e5bc70d860b4163d2",
        "66ec928121cd52bb25284bfe10907ec7455cb029e7e4c3c4b38278b233b2404d",
        "0bec0ad83ede5111054db71edbe94f7366e579f9f3c81eb53f5e679a7fc94b55",
    )
    lineage_argv = [
        PYTHON_MANIFEST_TOKEN,
        "-c",
        lineage_code,
        os.fspath(verifier_path),
    ]
    for generation, digest in enumerate(packet_digests, start=1):
        lineage_argv.extend(
            (
                os.fspath(
                    plan_root
                    / f"harness-98-direct-maintenance-packet-v{generation}.json"
                ),
                digest,
            )
        )
    accepted_validator_path = os.fspath(accepted_validator)
    expected_invocations = [
        [
            PYTHON_MANIFEST_TOKEN,
            accepted_validator_path,
            os.fspath(candidate_root / skill_root),
        ]
        for skill_root in SKILL_ROOTS
    ]
    expected_validations: list[dict[str, Any]] = [
        {
            "argv": [
                PYTHON_MANIFEST_TOKEN,
                "-c",
                schema_code,
                os.fspath(schema_path),
            ],
            "cwd": worktree,
            "environment_overrides": {"PYTHONDONTWRITEBYTECODE": "1"},
            "gate": "draft_2020_12_schema",
            "result": "PASS",
        },
        {
            "argv": [
                PYTHON_MANIFEST_TOKEN,
                "-m",
                "py_compile",
                os.fspath(verifier_path),
                os.fspath(test_path),
            ],
            "cwd": worktree,
            "environment_overrides": {
                "PYTHONPYCACHEPREFIX": os.fspath(retained_root / "pycache")
            },
            "gate": "py_compile",
            "result": "PASS",
        },
        {
            "argv": [
                PYTHON_MANIFEST_TOKEN,
                os.fspath(runner_path),
                "-v",
                "test_verify_harness_baseline_receipt",
            ],
            "cwd": worktree,
            "gate": "focused_adversarial",
            "result": "PASS",
            "tests_failed": 0,
            "tests_passed": 39,
        },
        {
            "argv": [
                PYTHON_MANIFEST_TOKEN,
                "-m",
                "unittest",
                "skills.twinfinity-sprint-orchestrator.tests."
                "test_verify_harness_baseline_receipt.BootstrapVerifierTests."
                "test_real_issue92_remote_tracking_topology_passes_without_local_main",
            ],
            "cwd": worktree,
            "environment_overrides": {
                "PYTHONDONTWRITEBYTECODE": "1",
                "TWINFINITY_HARNESS_REAL_TOPOLOGY_ROOT": (
                    "/home/ubuntu/code/twinfinity/twinfinity-harness-issue92"
                ),
            },
            "gate": "real_issue_92_shared_repository_topology",
            "result": "PASS",
            "tests_failed": 0,
            "tests_passed": 1,
        },
        {
            "argv": lineage_argv,
            "cwd": worktree,
            "environment_overrides": {"PYTHONDONTWRITEBYTECODE": "1"},
            "gate": "actual_packet_v1_through_v4_lineage",
            "result": "PASS",
            "routes": [DIRECT_ROUTE] * 4,
        },
        {
            "cwd": worktree,
            "environment_overrides": {"PYTHONDONTWRITEBYTECODE": "1"},
            "failed": 0,
            "gate": "immutable_current_main_fixed_skill_validators",
            "invocations": expected_invocations,
            "ordered_skill_roots": list(SKILL_ROOTS),
            "passed": len(SKILL_ROOTS),
            "result": "PASS",
        },
        {
            "argv": [
                PYTHON_MANIFEST_TOKEN,
                os.fspath(accepted_registry),
                "--config",
                os.fspath(reference_root / "twinfinity-executor-registry.toml"),
                "--profile-root",
                os.fspath(reference_root),
                "audit-config",
            ],
            "config_sha256": (
                "b8fc76a28fc4938449a970d65819eaadf0134fe642956a956e28eaf0bd5a4e31"
            ),
            "cwd": worktree,
            "endpoints": {
                "development": "role.development.v6",
                "planner": "role.planner.v2",
                "sre": "role.sre.v6",
            },
            "environment_overrides": {"PYTHONDONTWRITEBYTECODE": "1"},
            "gate": "immutable_current_main_executor_registry_audit",
            "result": "PASS",
            "staged_endpoints": [],
        },
        {
            "argv": [
                "/usr/bin/env",
                "-u",
                "TMPDIR",
                "-u",
                "CODEX_HOME",
                "-u",
                "PYTHONPATH",
                PYTHON_MANIFEST_TOKEN,
                os.fspath(runner_path),
            ],
            "cwd": worktree,
            "environment": (
                "runner-created private HOME,CODEX_HOME,TMPDIR and test-root "
                "PYTHONPATH; caller TMPDIR,CODEX_HOME,PYTHONPATH explicitly unset"
            ),
            "gate": "full_hermetic",
            "result": "PASS",
            "tests_failed": 0,
            "tests_passed": 950,
        },
    ]
    validations = manifest.get("validations")
    if type(validations) is not list or len(validations) != len(
        expected_validations
    ):
        raise VerificationError(error)
    for index, (actual, expected) in enumerate(
        zip(validations, expected_validations, strict=True)
    ):
        if type(actual) is not dict:
            raise VerificationError(error)
        normalized = dict(actual)
        if index in {2, 3, 7}:
            elapsed = normalized.pop("elapsed_seconds", None)
            if (
                type(elapsed) not in {int, float}
                or not math.isfinite(elapsed)
                or elapsed < 0
            ):
                raise VerificationError(error)
        if not _strict_equal(normalized, expected):
            raise VerificationError(error)

    source_by_path = {
        item["path"]: item["sha256"]
        for item in paths
        if type(item) is dict
    }
    expected_source_hashes = {
        "schema": source_by_path.get(SCHEMA_PATH),
        "verifier": source_by_path.get(VERIFIER_PATH),
        "tests": source_by_path.get(
            "skills/twinfinity-sprint-orchestrator/tests/"
            "test_verify_harness_baseline_receipt.py"
        ),
    }
    provenance = manifest.get("validation_tool_provenance")
    expected_provenance = {
        "accepted_base_materialization": {
            "commit": base_sha,
            "descendant_directory_mode": "0700",
            "file_count": 226,
            "path": os.fspath(accepted_root),
            "root_mode": "0700",
            "symlink_count": 0,
            "tree": base_tree,
        },
        "final_source_sha256": expected_source_hashes,
        "git": {"logical_path": GIT, "version": "2.43.0"},
        "hermetic_runner_sha256": (
            "edefef06e8c9b06ee4054151fefe10d65f0efc055eda8b72dcce45306e2ea716"
        ),
        "jsonschema_version": "4.10.3",
        "python": {
            "logical_path": PYTHON_MANIFEST_TOKEN,
            "resolved_path": "/usr/bin/python3.12",
            "version": "3.12.3",
        },
        "raw_executor_registry": {
            "git_blob": "fde2137b37af0b46e99270f85acf06f0a3e4a102",
            "sha256": (
                "02b473448b3ce2f13db1b04491f6c6c4cf4ada114e2085b752cfcb91c6f38467"
            ),
        },
        "raw_executor_registry_dependency": {
            "git_blob": "fdf37238d2704178ba2e614bbb5ce4aecc5031c1",
            "sha256": (
                "ac9f14cac7b507444e89a360a637f88ba7ef508a2012c94bfa0ce5be67bbee75"
            ),
        },
        "raw_quick_validator": {
            "git_blob": "877c9b384a56622098a4f863ac9e0a31242a3b2d",
            "sha256": (
                "1fd66498c219616fd9249eacdf16c458412ea9065a9d887fd716aeef03907762"
            ),
        },
    }
    if not _strict_equal(provenance, expected_provenance):
        raise VerificationError(error)

    source_hashes = [item["sha256"] for item in paths]
    expected_audits = [
        {
            "audit": "final_v4_source_audit",
            "crash_recovery_stress": "50_ROUNDS_ZERO_FAILURE_OR_RESIDUE",
            "focused_tests": "39_OF_39_PASS",
            "process_stress": "100_ROUNDS_X_4_WRITERS_ZERO_FAILURE_OR_RESIDUE",
            "publication_same_process_repeats": "5_OF_5_PASS",
            "result": "PASS",
            "source_sha256": source_hashes,
            "thread_stress": "250_ROUNDS_X_4_WRITERS_ZERO_FAILURE_OR_RESIDUE",
        },
        {
            "actual_packet_lineage": "V1_V2_V3_V4_PASS",
            "audit": "final_v4_adversarial_probe",
            "killed_owner_recovery": "PASS_TWO_LINK_TO_ONE_LINK_ZERO_RESIDUE",
            "late_parent_target_and_ref_cas": "6_OF_6_PASS",
            "multiprocess_writes": "4000_OF_4000_PASS_EXACT_NLINK_1_ZERO_RESIDUE",
            "real_issue_92_topology": "1_OF_1_PASS",
            "result": "PASS",
            "source_sha256": source_hashes,
        },
    ]
    if not _strict_equal(
        manifest.get("independent_exact_hash_audits"), expected_audits
    ):
        raise VerificationError(error)
    if manifest.get("findings_closed") != [
        "ACCEPTED_BASE_TOOL_COPY_SAME_UID_SUBSTITUTION",
        "LOCAL_MAIN_REF_TOPOLOGY_FALSE_REQUIREMENT",
        "RAW_COMMIT_COMPLETE_HEADER_GRAMMAR_NOT_CLOSED",
        "SCHEMA_EXACT_NUMERIC_AND_DIGEST_FORMS_NOT_CLOSED",
        "DIRECT_PACKET_VALIDATION_INCOMPLETE",
        "ROOT_INSENSITIVE_TEST_FIXTURES_FALSE_POSITIVE",
        "VALIDATION_MANIFEST_COMMANDS_NOT_LITERAL_REPLAYABLE",
        "PROCESS_GROUP_RECYCLED_PID_RISK",
        "RECEIPT_PARENT_LEXICAL_PATH_NOT_REVALIDATED",
        "FINAL_REPOSITORY_REF_CAS_MISSING",
        "UNBOUNDED_ANCESTRY_AND_ERROR_GRAMMAR_GAPS",
    ]:
        raise VerificationError(error)


def _validate_rejected_manifest_v4_shape(
    manifest: dict[str, Any],
    *,
    issue: int,
    branch: str,
    base_sha: str,
    base_tree: str,
    head_sha: str,
    head_tree: str,
    diff_sha256: str,
    diff_bytes: int,
    prior_packet_sha256: str,
    incorporated_digests: list[str],
    effective: dict[str, Any],
) -> None:
    error = "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
    timestamp = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
    base = manifest.get("base")
    head = manifest.get("head")
    diff = manifest.get("canonical_diff")
    direct = manifest.get("direct_packet")
    paths = manifest.get("changed_paths")
    if (
        manifest.get("schema")
        != "twinfinity-harness-source-validation-manifest/v1"
        or manifest.get("repository") != REPOSITORY
        or manifest.get("owning_issue") != issue
        or manifest.get("issue_body_sha256") != effective["issue_body_sha256"]
        or type(manifest.get("recorded_at")) is not str
        or re.fullmatch(timestamp, manifest["recorded_at"]) is None
        or manifest.get("terminal_state")
        != "LOCAL_COMMIT_VALIDATED_AWAITING_PLANNER_CONTINUATION"
        or base
        != {"ref": "refs/heads/main", "commit": base_sha, "tree": base_tree}
        or type(head) is not dict
        or set(head)
        != {"ref", "commit", "tree", "parents", "commits_from_base", "subject"}
        or head.get("ref") != f"refs/heads/{branch}"
        or head.get("commit") != head_sha
        or head.get("tree") != head_tree
        or head.get("parents") != [base_sha]
        or head.get("commits_from_base") != 1
        or type(head.get("subject")) is not str
        or not head["subject"]
    ):
        raise VerificationError(error)

    expected_diff_argv = [
        GIT,
        "diff",
        "--binary",
        "--no-ext-diff",
        base_sha,
        head_sha,
        "--",
        *effective["mutable_path_order"],
    ]
    if (
        type(diff) is not dict
        or set(diff)
        != {
            "algorithm",
            "argv",
            "bytes",
            "cwd",
            "packet_order_no_index_crosscheck_sha256",
            "sha256",
        }
        or diff.get("algorithm")
        != "SHA256_OF_GIT_DIFF_BINARY_NO_EXT_DIFF_PARENT_HEAD_PACKET_PATH_ORDER"
        or diff.get("argv") != expected_diff_argv
        or diff.get("cwd") != effective["worktree_path"]
        or type(diff.get("bytes")) is not int
        or diff["bytes"] != diff_bytes
        or diff.get("sha256") != diff_sha256
        or diff.get("packet_order_no_index_crosscheck_sha256") != diff_sha256
    ):
        raise VerificationError(error)
    _require_sha(diff.get("sha256"), SHA256, error)

    if (
        type(direct) is not dict
        or set(direct)
        != {
            "attempt_generation",
            "incorporated_packet_sha256",
            "mutable_paths_sha256",
            "schema",
            "sha256",
            "starting_main_contract_sha256",
        }
        or direct.get("attempt_generation") != len(incorporated_digests)
        or direct.get("incorporated_packet_sha256") != incorporated_digests[:-1]
        or direct.get("mutable_paths_sha256") != effective["mutable_paths_sha256"]
        or direct.get("schema")
        != "twinfinity-direct-harness-source-maintenance/v1"
        or direct.get("sha256") != prior_packet_sha256
        or direct.get("starting_main_contract_sha256")
        != effective["starting_main_contract_sha256"]
    ):
        raise VerificationError(error)

    if (
        type(paths) is not list
        or len(paths) != len(effective["mutable_path_order"])
        or [item.get("path") if type(item) is dict else None for item in paths]
        != effective["mutable_path_order"]
    ):
        raise VerificationError(error)
    for item in paths:
        if (
            type(item) is not dict
            or set(item)
            != {
                "path",
                "sha256",
                "git_blob",
                "bytes",
                "lines",
                "git_mode",
                "filesystem_mode",
                "status",
            }
            or type(item.get("bytes")) is not int
            or item["bytes"] < 0
            or type(item.get("lines")) is not int
            or item["lines"] < 0
            or item.get("git_mode") not in {"100644", "100755"}
            or item.get("filesystem_mode") not in {"0644", "0755"}
            or item.get("status") not in {"A", "M"}
        ):
            raise VerificationError(error)
        _require_sha(item.get("sha256"), SHA256, error)
        _require_sha(item.get("git_blob"), SHA1, error)

    cleanliness = manifest.get("cleanliness")
    if (
        type(cleanliness) is not dict
        or set(cleanliness)
        != {
            "diff_check",
            "exact_changed_path_count",
            "generated_worktree_artifacts",
            "ignored_paths",
            "lane_cleanup_performed",
            "owner_local_validation_run_root_retained",
            "tracked_or_untracked_fourth_paths",
            "worktree_status",
        }
        or cleanliness.get("diff_check") != "PASS"
        or cleanliness.get("exact_changed_path_count") != len(paths)
        or cleanliness.get("generated_worktree_artifacts") != 0
        or cleanliness.get("ignored_paths") != 0
        or cleanliness.get("lane_cleanup_performed") is not False
        or cleanliness.get("tracked_or_untracked_fourth_paths") != 0
        or cleanliness.get("worktree_status") != "CLEAN"
        or type(cleanliness.get("owner_local_validation_run_root_retained"))
        is not str
        or not Path(cleanliness["owner_local_validation_run_root_retained"]).is_absolute()
    ):
        raise VerificationError(error)

    capacity = effective["direct_capacity"]
    occupancy = next(
        (
            capacity[key]
            for key in (
                "occupancy_after_reservation_including_active_and_retained",
                "occupancy_including_active_and_retained",
            )
            if key in capacity
        ),
        None,
    )
    fence = manifest.get("live_precommit_fence")
    if (
        type(fence) is not dict
        or set(fence)
        != {
            "candidate_remote_branch_present",
            "collision_drift",
            "direct_capacity_available",
            "direct_capacity_limit",
            "direct_capacity_occupancy",
            "main_commit",
            "main_tree",
            "observed_at",
            "open_pull_requests",
            "remote_branches",
            "sqlite_allocation_units",
            "verdict",
        }
        or fence.get("candidate_remote_branch_present") is not False
        or fence.get("collision_drift") is not False
        or fence.get("direct_capacity_limit") != capacity["temporary_limit"]
        or fence.get("direct_capacity_occupancy") != occupancy
        or fence.get("direct_capacity_available")
        != capacity["temporary_limit"] - occupancy
        or fence.get("main_commit") != base_sha
        or fence.get("main_tree") != base_tree
        or type(fence.get("observed_at")) is not str
        or re.fullmatch(timestamp, fence["observed_at"]) is None
        or fence.get("open_pull_requests") != 0
        or fence.get("remote_branches") != ["main"]
        or fence.get("sqlite_allocation_units") != 0
        or fence.get("verdict") != "PASS"
    ):
        raise VerificationError(error)

    replay = manifest.get("replay_contract")
    if (
        type(replay) is not dict
        or set(replay)
        != {
            "argv_form",
            "path_form",
            "retained_descendant_directory_mode",
            "retained_gate_root",
            "retained_gate_root_mode",
        }
        or replay.get("argv_form")
        != "EVERY_PROGRAM_ARGUMENT_IS_A_LITERAL_JSON_STRING_WITH_NO_PLACEHOLDER_TOKENS"
        or replay.get("path_form")
        != "EVERY_PATH_IS_ABSOLUTE_OR_PACKET_RELATIVE_WITH_AN_EXPLICIT_CWD"
        or replay.get("retained_descendant_directory_mode") != "0700"
        or replay.get("retained_gate_root_mode") != "0700"
        or type(replay.get("retained_gate_root")) is not str
        or not Path(replay["retained_gate_root"]).is_absolute()
    ):
        raise VerificationError(error)

    _validate_v4_manifest_validation_evidence(
        manifest,
        paths=paths,
        effective=effective,
        base_sha=base_sha,
        base_tree=base_tree,
    )

    validations = manifest.get("validations")
    expected_gates = [
        "draft_2020_12_schema",
        "py_compile",
        "focused_adversarial",
        "real_issue_92_shared_repository_topology",
        "actual_packet_v1_through_v4_lineage",
        "immutable_current_main_fixed_skill_validators",
        "immutable_current_main_executor_registry_audit",
        "full_hermetic",
    ]
    if (
        type(validations) is not list
        or [item.get("gate") if type(item) is dict else None for item in validations]
        != expected_gates
        or any(item.get("result") != "PASS" for item in validations)
    ):
        raise VerificationError(error)
    for item in validations:
        argument_vectors = [item["argv"]] if "argv" in item else item.get("invocations")
        if (
            type(item.get("cwd")) is not str
            or not Path(item["cwd"]).is_absolute()
            or type(argument_vectors) is not list
            or not argument_vectors
            or any(
                type(argv) is not list
                or not argv
                or any(
                    type(argument) is not str
                    or not argument
                    or "<" in argument
                    or ">" in argument
                    for argument in argv
                )
                for argv in argument_vectors
            )
        ):
            raise VerificationError(error)

    provenance = manifest.get("validation_tool_provenance")
    if (
        type(provenance) is not dict
        or set(provenance)
        != {
            "accepted_base_materialization",
            "final_source_sha256",
            "git",
            "hermetic_runner_sha256",
            "jsonschema_version",
            "python",
            "raw_executor_registry",
            "raw_executor_registry_dependency",
            "raw_quick_validator",
        }
        or type(provenance.get("final_source_sha256")) is not dict
        or set(provenance["final_source_sha256"].values())
        != {item["sha256"] for item in paths}
    ):
        raise VerificationError(error)
    for value in provenance["final_source_sha256"].values():
        _require_sha(value, SHA256, error)
    for key in (
        "hermetic_runner_sha256",
        "raw_executor_registry",
        "raw_executor_registry_dependency",
        "raw_quick_validator",
    ):
        value = provenance.get(key)
        if key == "hermetic_runner_sha256":
            _require_sha(value, SHA256, error)
        elif type(value) is not dict or set(value) != {"git_blob", "sha256"}:
            raise VerificationError(error)
        else:
            _require_sha(value.get("git_blob"), SHA1, error)
            _require_sha(value.get("sha256"), SHA256, error)

    audits = manifest.get("independent_exact_hash_audits")
    if (
        type(audits) is not list
        or not audits
        or any(
            type(item) is not dict
            or item.get("result") != "PASS"
            or item.get("source_sha256") != [path["sha256"] for path in paths]
            for item in audits
        )
        or manifest.get("findings_closed") is None
        or type(manifest["findings_closed"]) is not list
        or not manifest["findings_closed"]
    ):
        raise VerificationError(error)

    if manifest.get("excluded_effects") != [
        "NO_REMOTE_PUSH",
        "NO_PULL_REQUEST_CREATION_OR_MUTATION",
        "NO_MERGE",
        "NO_GOVERNOR_SELF_APPROVAL",
        "NO_SQLITE_READ_OR_MUTATION_AS_AUTHORITY",
        "NO_SKILL_INSTALLATION_OR_RUNTIME_ACTIVATION",
        "NO_ENDPOINT_PROFILE_SYSTEMD_TIMER_OR_SERVICE_EFFECT",
        "NO_PROVIDER_HOSTED_DEPLOYMENT_TRAFFIC_PRODUCTION_OR_APPLICATION_EFFECT",
        "NO_MUTATION_OF_ISSUES_92_93_94_OR_96",
        "NO_BRANCH_WORKTREE_CAPACITY_OR_TERMINAL_CLEANUP",
    ]:
        raise VerificationError(error)


def _validate_rejected_manifest_shape(
    manifest: dict[str, Any],
    *,
    issue: int,
    branch: str,
    base_sha: str,
    base_tree: str,
    head_sha: str,
    head_tree: str,
    diff_sha256: str,
    diff_bytes: int,
    prior_packet_sha256: str,
    incorporated_digests: list[str],
    effective: dict[str, Any],
) -> None:
    error = "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
    keys = frozenset(manifest)
    if keys == REJECTED_MANIFEST_V4_FIELDS:
        _validate_rejected_manifest_v4_shape(
            manifest,
            issue=issue,
            branch=branch,
            base_sha=base_sha,
            base_tree=base_tree,
            head_sha=head_sha,
            head_tree=head_tree,
            diff_sha256=diff_sha256,
            diff_bytes=diff_bytes,
            prior_packet_sha256=prior_packet_sha256,
            incorporated_digests=incorporated_digests,
            effective=effective,
        )
        return
    if keys != REJECTED_MANIFEST_ACTUAL_FIELDS:
        raise VerificationError(error)
    if (
        manifest.get("repository") != REPOSITORY
        or type(manifest.get("owning_issue")) is not int
        or manifest["owning_issue"] != issue
    ):
        raise VerificationError(error)
    base = manifest.get("base")
    head = manifest.get("head")
    diff = manifest.get("canonical_diff")
    direct_packet = manifest.get("direct_packet")
    paths = manifest.get("changed_paths")
    if (
        type(base) is not dict
        or type(head) is not dict
        or type(diff) is not dict
        or type(direct_packet) is not dict
        or type(paths) is not list
        or len(paths) != len(effective["mutable_path_order"])
    ):
        raise VerificationError(error)
    if keys == REJECTED_MANIFEST_ACTUAL_FIELDS:
        if (
            manifest.get("schema")
            != "twinfinity-harness-source-validation-manifest/v1"
            or type(manifest.get("recorded_at")) is not str
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                manifest["recorded_at"],
            )
            is None
            or manifest.get("issue_body_sha256")
            != effective["issue_body_sha256"]
            or manifest.get("terminal_state")
            != "LOCAL_COMMIT_VALIDATED_AWAITING_PLANNER_CONTINUATION"
            or set(base) != {"ref", "commit", "tree"}
            or base.get("ref") != effective["starting_main_ref"]
            or set(head)
            != {"ref", "commit", "tree", "parents", "commits_from_base", "subject"}
            or head.get("ref") != f"refs/heads/{branch}"
            or head.get("parents") != [base_sha]
            or type(head.get("commits_from_base")) is not int
            or head["commits_from_base"] != 1
            or type(head.get("subject")) is not str
            or not head["subject"]
            or set(diff)
            != {
                "algorithm",
                "bytes",
                "command",
                "packet_order_no_index_crosscheck_sha256",
                "sha256",
            }
            or type(diff.get("algorithm")) is not str
            or diff["algorithm"]
            != "SHA256_OF_GIT_DIFF_BINARY_NO_EXT_DIFF_PARENT_HEAD_PACKET_PATH_ORDER"
            or type(diff.get("command")) is not str
            or diff["command"]
            != (
                f"git diff --binary --no-ext-diff {base_sha} {head_sha} -- "
                "<packet-order-paths>"
            )
            or set(direct_packet)
            != {
                "attempt_generation",
                "incorporated_packet_sha256",
                "mutable_paths_sha256",
                "schema",
                "sha256",
                "starting_main_contract_sha256",
            }
            or type(direct_packet.get("attempt_generation")) is not int
            or direct_packet["attempt_generation"] != 3
            or direct_packet.get("incorporated_packet_sha256")
            != incorporated_digests[:-1]
            or direct_packet.get("mutable_paths_sha256")
            != effective["mutable_paths_sha256"]
            or direct_packet.get("schema")
            != "twinfinity-direct-harness-source-maintenance/v1"
            or direct_packet.get("starting_main_contract_sha256")
            != effective["starting_main_contract_sha256"]
        ):
            raise VerificationError(error)
        _require_sha(
            diff.get("packet_order_no_index_crosscheck_sha256"), SHA256, error
        )
        if diff["packet_order_no_index_crosscheck_sha256"] != diff_sha256:
            raise VerificationError(error)
        cleanliness = manifest.get("cleanliness")
        if (
            type(cleanliness) is not dict
            or set(cleanliness)
            != {
                "diff_check",
                "exact_changed_path_count",
                "generated_worktree_artifacts",
                "ignored_paths",
                "lane_cleanup_performed",
                "owner_local_validation_run_root_retained",
                "tracked_or_untracked_fourth_paths",
                "worktree_status",
            }
            or cleanliness.get("diff_check") != "PASS"
            or type(cleanliness.get("exact_changed_path_count")) is not int
            or cleanliness["exact_changed_path_count"]
            != len(effective["mutable_path_order"])
            or type(cleanliness.get("generated_worktree_artifacts")) is not int
            or cleanliness["generated_worktree_artifacts"] != 0
            or type(cleanliness.get("ignored_paths")) is not int
            or cleanliness["ignored_paths"] != 0
            or cleanliness.get("lane_cleanup_performed") is not False
            or type(cleanliness.get("tracked_or_untracked_fourth_paths")) is not int
            or cleanliness["tracked_or_untracked_fourth_paths"] != 0
            or cleanliness.get("worktree_status") != "CLEAN"
            or type(cleanliness.get("owner_local_validation_run_root_retained"))
            is not str
            or not Path(cleanliness["owner_local_validation_run_root_retained"]).is_absolute()
        ):
            raise VerificationError(error)
        fence = manifest.get("live_precommit_fence")
        effective_occupancy = next(
            (
                effective["direct_capacity"][key]
                for key in (
                    "occupancy_after_reservation_including_active_and_retained",
                    "occupancy_including_active_and_retained",
                )
                if key in effective["direct_capacity"]
            ),
            None,
        )
        if (
            type(fence) is not dict
            or set(fence)
            != {
                "candidate_remote_branch_present",
                "collision_drift",
                "direct_capacity_limit",
                "direct_capacity_occupancy",
                "main_commit",
                "main_tree",
                "observed_at",
                "open_pull_requests",
                "remote_branches",
                "sqlite_allocation_units",
                "verdict",
            }
            or fence.get("candidate_remote_branch_present") is not False
            or fence.get("collision_drift") is not False
            or type(fence.get("direct_capacity_limit")) is not int
            or type(fence.get("direct_capacity_occupancy")) is not int
            or fence.get("main_commit") != base_sha
            or fence.get("main_tree") != base_tree
            or type(fence.get("observed_at")) is not str
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                fence["observed_at"],
            )
            is None
            or type(fence.get("open_pull_requests")) is not int
            or fence["open_pull_requests"] != 0
            or fence.get("remote_branches") != ["main"]
            or type(fence.get("direct_capacity_limit")) is not int
            or fence["direct_capacity_limit"]
            != effective["direct_capacity"]["temporary_limit"]
            or type(fence.get("direct_capacity_occupancy")) is not int
            or fence["direct_capacity_occupancy"] != effective_occupancy
            or type(fence.get("sqlite_allocation_units")) is not int
            or fence["sqlite_allocation_units"] != 0
            or fence.get("verdict") != "PASS"
        ):
            raise VerificationError(error)
        excluded = manifest.get("excluded_effects")
        if excluded != [
            "NO_REMOTE_PUSH",
            "NO_PULL_REQUEST_CREATION_OR_MUTATION",
            "NO_MERGE",
            "NO_GOVERNOR_SELF_APPROVAL",
            "NO_SQLITE_READ_OR_MUTATION_AS_AUTHORITY",
            "NO_SKILL_INSTALLATION_OR_RUNTIME_ACTIVATION",
            "NO_ENDPOINT_PROFILE_SYSTEMD_TIMER_OR_SERVICE_EFFECT",
            "NO_PROVIDER_HOSTED_DEPLOYMENT_TRAFFIC_PRODUCTION_OR_APPLICATION_EFFECT",
            "NO_MUTATION_OF_ISSUES_92_93_94_OR_96",
            "NO_BRANCH_WORKTREE_CAPACITY_OR_TERMINAL_CLEANUP",
        ]:
            raise VerificationError(error)

        if (
            type(manifest.get("numeric_schema_note")) is not str
            or "canonical raw JSON" not in manifest["numeric_schema_note"]
            or manifest.get("findings_closed")
            != [
                "PASS_SCHEMA_NUMERIC_CONST_TYPE_MALLEABILITY",
                "PASS_SCHEMA_TERMINAL_STATE_NOT_CONST_BOUND",
                "RAW_COMMIT_PARENT_BLOCK_GRAMMAR_TOO_PERMISSIVE",
            ]
        ):
            raise VerificationError(error)
        invalidated = manifest.get("invalidated_invocations")
        if (
            type(invalidated) is not list
            or len(invalidated) != 2
            or type(invalidated[0]) is not dict
            or set(invalidated[0]) != {"invocation", "reason", "result"}
            or invalidated[0].get("result") != "INVALID_COMMAND"
            or type(invalidated[1]) is not dict
            or set(invalidated[1])
            != {"invocation", "observed", "reason", "resolution_evidence", "result"}
            or invalidated[1].get("result") != "INVALID_ENVIRONMENT"
            or any(
                type(value) is not str or not value
                for item in invalidated
                for value in item.values()
            )
        ):
            raise VerificationError(error)

        validations = manifest.get("validations")
        expected_validation_shapes = (
            (
                "draft_2020_12_schema",
                {"command", "gate", "result"},
            ),
            ("py_compile", {"command", "gate", "result"}),
            (
                "focused_adversarial",
                {
                    "command",
                    "elapsed_seconds",
                    "gate",
                    "result",
                    "tests_failed",
                    "tests_passed",
                },
            ),
            (
                "immutable_current_main_fixed_skill_validators",
                {
                    "command",
                    "failed",
                    "gate",
                    "ordered_skill_roots",
                    "passed",
                    "result",
                },
            ),
            (
                "immutable_current_main_executor_registry_audit",
                {
                    "command",
                    "config_sha256",
                    "endpoints",
                    "gate",
                    "result",
                },
            ),
            (
                "full_hermetic",
                {
                    "command",
                    "elapsed_seconds",
                    "environment",
                    "gate",
                    "result",
                    "tests_failed",
                    "tests_passed",
                },
            ),
        )
        if type(validations) is not list or len(validations) != len(
            expected_validation_shapes
        ):
            raise VerificationError(error)
        for validation, (gate, expected_keys) in zip(
            validations, expected_validation_shapes, strict=True
        ):
            if (
                type(validation) is not dict
                or set(validation) != expected_keys
                or validation.get("gate") != gate
                or validation.get("result") != "PASS"
                or type(validation.get("command")) is not str
                or not validation["command"]
            ):
                raise VerificationError(error)
            if "elapsed_seconds" in validation and (
                type(validation["elapsed_seconds"]) not in {int, float}
                or not math.isfinite(validation["elapsed_seconds"])
                or validation["elapsed_seconds"] < 0
            ):
                raise VerificationError(error)
        if (
            type(validations[2].get("tests_failed")) is not int
            or validations[2]["tests_failed"] != 0
            or type(validations[2].get("tests_passed")) is not int
            or validations[2]["tests_passed"] != 24
            or type(validations[3].get("failed")) is not int
            or validations[3]["failed"] != 0
            or type(validations[3].get("passed")) is not int
            or validations[3]["passed"] != len(SKILL_ROOTS)
            or validations[3].get("ordered_skill_roots") != list(SKILL_ROOTS)
            or type(validations[5].get("tests_failed")) is not int
            or validations[5]["tests_failed"] != 0
            or type(validations[5].get("tests_passed")) is not int
            or validations[5]["tests_passed"] != 935
        ):
            raise VerificationError(error)
        endpoints = validations[4].get("endpoints")
        if (
            validations[4].get("config_sha256")
            != "b8fc76a28fc4938449a970d65819eaadf0134fe642956a956e28eaf0bd5a4e31"
            or endpoints
            != {
                "development": "role.development.v6",
                "planner": "role.planner.v2",
                "sre": "role.sre.v6",
            }
        ):
            raise VerificationError(error)

        provenance = manifest.get("validation_tool_provenance")
        if (
            type(provenance) is not dict
            or set(provenance)
            != {
                "accepted_base_materialization",
                "git",
                "hermetic_runner_sha256",
                "jsonschema_version",
                "python",
                "raw_executor_registry",
                "raw_quick_validator",
                "requirements_ci_sha256",
            }
        ):
            raise VerificationError(error)
        materialization = provenance["accepted_base_materialization"]
        if (
            type(materialization) is not dict
            or set(materialization)
            != {"commit", "file_count", "symlink_count", "tree"}
            or materialization.get("commit") != base_sha
            or materialization.get("tree") != base_tree
            or type(materialization.get("file_count")) is not int
            or materialization["file_count"] != 226
            or type(materialization.get("symlink_count")) is not int
            or materialization["symlink_count"] != 0
            or provenance.get("git")
            != {"logical_path": GIT, "version": "2.43.0"}
            or provenance.get("python")
            != {
                "logical_path": PYTHON_MANIFEST_TOKEN,
                "resolved_path": "/usr/bin/python3.12",
                "version": "3.12.3",
            }
            or provenance.get("jsonschema_version") != "4.10.3"
            or provenance.get("raw_executor_registry")
            != {
                "git_blob": "fde2137b37af0b46e99270f85acf06f0a3e4a102",
                "sha256": "02b473448b3ce2f13db1b04491f6c6c4cf4ada114e2085b752cfcb91c6f38467",
            }
            or provenance.get("raw_quick_validator")
            != {
                "git_blob": "877c9b384a56622098a4f863ac9e0a31242a3b2d",
                "sha256": "1fd66498c219616fd9249eacdf16c458412ea9065a9d887fd716aeef03907762",
            }
        ):
            raise VerificationError(error)
        _require_sha(provenance.get("hermetic_runner_sha256"), SHA256, error)
        _require_sha(provenance.get("requirements_ci_sha256"), SHA256, error)

    if (
        base.get("commit") != base_sha
        or base.get("tree") != base_tree
        or head.get("commit") != head_sha
        or head.get("tree") != head_tree
        or diff.get("sha256") != diff_sha256
        or type(diff.get("bytes")) is not int
        or diff["bytes"] != diff_bytes
        or direct_packet.get("sha256") != prior_packet_sha256
    ):
        raise VerificationError(error)
    for item, expected_path in zip(
        paths, effective["mutable_path_order"], strict=True
    ):
        expected_keys = {
            "path",
            "sha256",
            "git_blob",
            "bytes",
            "lines",
            "git_mode",
            "filesystem_mode",
            "status",
        }
        if (
            type(item) is not dict
            or set(item) != expected_keys
            or item.get("path") != expected_path
            or type(item.get("bytes")) is not int
            or item["bytes"] < 0
        ):
            raise VerificationError(error)
        _require_sha(item.get("sha256"), SHA256, error)
        _require_sha(item.get("git_blob"), SHA1, error)
        if keys == REJECTED_MANIFEST_ACTUAL_FIELDS and (
            type(item.get("lines")) is not int
            or item["lines"] < 0
            or item.get("git_mode") not in {"100644", "100755"}
            or item.get("filesystem_mode") not in {"0644", "0755"}
            or item.get("status") not in {"A", "M"}
        ):
            raise VerificationError(error)


def _validate_packet_envelope(
    current: dict[str, Any],
    effective: dict[str, Any],
    inherited: dict[str, Any],
    expected_sha256: str,
    incorporated_digests: list[str],
) -> dict[str, Any]:
    required = {
        "recorded_at",
        "schema",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "issue_observed_at",
        "issue_observed_state",
        "issue_url",
        "trigger",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "starting_main_contract_sha256",
        "branch",
        "worktree_path",
        "opaque_worktree_id",
        "accountable_writer",
        "authority",
        "direct_capacity",
        "repository_fence",
        "dependencies",
        "mutable_paths",
        "mutable_path_order",
        "mutable_paths_sha256",
        "mutable_paths_digest_serialization",
        "collision_fence",
        "semantic_scope",
        "safety_invariants",
        "authorized_stages",
        "stages_requiring_planner_continuation",
        "repair_budget",
        "hard_stops",
        "excluded_effects",
        "bootstrap_validation_contract",
        "current_stage",
    }
    if not required.issubset(effective):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCHEMA_INVALID")
    if _classify_packet_route(effective) != DIRECT_ROUTE:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_ROUTE_SUBSTITUTED")
    generation = current.get("attempt_generation", 1)
    if type(generation) is not int or generation < 1:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    protected_fields = {
        "schema",
        "repository",
        "owning_issue",
        "issue_body_sha256",
        "issue_observed_at",
        "issue_observed_state",
        "issue_url",
        "trigger",
        "starting_main_ref",
        "starting_main_sha",
        "starting_main_tree",
        "starting_main_contract_sha256",
        "branch",
        "worktree_path",
        "opaque_worktree_id",
        "authority",
        "dependencies",
        "mutable_paths",
        "mutable_path_order",
        "mutable_paths_sha256",
        "mutable_paths_digest_serialization",
        "semantic_scope",
        "safety_invariants",
        "excluded_effects",
        "bootstrap_validation_contract",
        "repair_budget",
    }
    if generation >= 5:
        protected_fields.remove("excluded_effects")
        inherited_excluded = inherited.get("excluded_effects")
        additional_excluded = current.get("excluded_effects")
        combined_excluded = [
            *ISSUE98_INHERITED_EXCLUDED_EFFECTS,
            *ISSUE98_V5_ADDITIONAL_EXCLUDED_EFFECTS,
        ]
        if (
            effective.get("owning_issue") != 98
            or generation != 5
            or inherited_excluded != list(ISSUE98_INHERITED_EXCLUDED_EFFECTS)
            or additional_excluded
            != list(ISSUE98_V5_ADDITIONAL_EXCLUDED_EFFECTS)
            or effective.get("excluded_effects") != combined_excluded
            or len(set(combined_excluded)) != len(combined_excluded)
            or any(
                not item.startswith("NO_") or "ALLOW" in item
                for item in additional_excluded
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_HARD_STOP_INVALID")
    if inherited:
        if current.get("prior_writer") != inherited.get("accountable_writer"):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        for key in protected_fields.intersection(current):
            if key not in inherited or not _strict_equal(current[key], inherited[key]):
                raise VerificationError(
                    "BOOTSTRAP_DIRECT_PACKET_INHERITED_FIELD_SUBSTITUTED"
                )
        if "direct_capacity" in current:
            prior_capacity = inherited.get("direct_capacity")
            current_capacity = current["direct_capacity"]
            if type(prior_capacity) is not dict or type(current_capacity) is not dict:
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID")
            for key in (
                "class",
                "units",
                "temporary_limit",
                "sqlite_allocation_units",
            ):
                if not _strict_equal(
                    current_capacity.get(key), prior_capacity.get(key)
                ):
                    raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID")
    issue = effective["owning_issue"]
    branch = effective["branch"]
    worktree = effective["worktree_path"]
    opaque = effective["opaque_worktree_id"]
    if (
        type(effective["recorded_at"]) is not str
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", effective["recorded_at"]) is None
        or type(effective["issue_observed_at"]) is not str
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", effective["issue_observed_at"]) is None
        or effective["issue_observed_state"] != "open"
        or effective["issue_url"]
        != f"https://github.com/jayendusharma/twinfinity-harness/issues/{issue}"
        or type(issue) is not int
        or not (1 <= issue <= 2_147_483_647)
        or effective["starting_main_ref"] != "refs/heads/main"
        or type(branch) is not str
        or BRANCH.fullmatch(branch) is None
        or not branch.startswith(f"change/{issue}-")
        or type(worktree) is not str
        or not Path(worktree).is_absolute()
        or type(opaque) is not str
        or opaque != Path(worktree).name
        or not opaque.startswith(f"twinfinity-harness-issue{issue}")
        or type(effective["accountable_writer"]) is not str
        or not effective["accountable_writer"].startswith("/root/")
        or type(effective["current_stage"]) is not str
        or not effective["current_stage"]
        or type(effective["repair_budget"]) is not int
        or effective["repair_budget"] != 1
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")
    trigger = effective["trigger"]
    if (
        type(trigger) is not dict
        or type(trigger.get("kind")) is not str
        or not trigger["kind"]
        or type(trigger.get("invariant")) is not str
        or not trigger["invariant"]
        or not any(
            type(trigger.get(key)) is str and bool(trigger[key])
            for key in ("measurable_effect", "evidence", "reason")
        )
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")
    base_sha = _require_sha(
        effective["starting_main_sha"],
        SHA1,
        "BOOTSTRAP_DIRECT_PACKET_BASE_INVALID",
    )
    base_tree = _require_sha(
        effective["starting_main_tree"],
        SHA1,
        "BOOTSTRAP_DIRECT_PACKET_BASE_INVALID",
    )
    _require_sha(
        effective["starting_main_contract_sha256"],
        SHA256,
        "BOOTSTRAP_DIRECT_PACKET_BASE_INVALID",
    )
    _require_sha(
        effective["issue_body_sha256"],
        SHA256,
        "BOOTSTRAP_DIRECT_PACKET_BODY_INVALID",
    )

    authority = effective["authority"]
    if (
        type(authority) is not dict
        or type(authority.get("kind")) is not str
        or not authority["kind"].startswith("DIRECT_OWNER_INSTRUCTION")
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID")
    instructions = authority.get("direct_owner_instructions", authority.get("instructions"))
    if (
        type(instructions) is not list
        or not instructions
        or any(type(item) is not str or not item for item in instructions)
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID")
    for key in (
        "temporary_six_writer_authority_sha256",
        "standing_routine_delivery_authority_sha256",
    ):
        _require_sha(
            authority.get(key), SHA256, "BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID"
        )

    capacity = effective["direct_capacity"]
    occupancy_keys = (
        "occupancy_including_active_and_retained",
        "occupancy_after_reservation_including_active_and_retained",
        "occupancy_after_launch",
    )
    occupancy_values = [capacity.get(key) for key in occupancy_keys if key in capacity] if type(capacity) is dict else []
    if (
        type(capacity) is not dict
        or capacity.get("class") != "HARNESS_SOURCE_WRITER"
        or type(capacity.get("units")) is not int
        or capacity.get("units") != 1
        or type(capacity.get("temporary_limit")) is not int
        or not (1 <= capacity["temporary_limit"] <= 64)
        or len(occupancy_values) != 1
        or type(occupancy_values[0]) is not int
        or not (1 <= occupancy_values[0] <= capacity["temporary_limit"])
        or type(capacity.get("sqlite_allocation_units")) is not int
        or capacity.get("sqlite_allocation_units") != 0
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID")

    mutable_paths = effective["mutable_paths"]
    mutable_order = effective["mutable_path_order"]
    if (
        type(mutable_paths) is not list
        or not mutable_paths
        or type(mutable_order) is not list
        or [item.get("path") if type(item) is dict else None for item in mutable_paths]
        != mutable_order
        or len(set(mutable_order)) != len(mutable_order)
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")
    for item, relative in zip(mutable_paths, mutable_order, strict=True):
        if (
            type(item) is not dict
            or set(item) != {"path", "starting_sha256", "starting_git_blob"}
            or type(relative) is not str
            or not relative
            or Path(relative).is_absolute()
            or Path(relative).as_posix() != relative
            or any(component in {"", ".", ".."} for component in relative.split("/"))
            or (
                item.get("starting_sha256") != "ABSENT"
                and (
                    type(item.get("starting_sha256")) is not str
                    or SHA256.fullmatch(item["starting_sha256"]) is None
                )
            )
            or (
                item.get("starting_git_blob") != "ABSENT"
                and (
                    type(item.get("starting_git_blob")) is not str
                    or SHA1.fullmatch(item["starting_git_blob"]) is None
                )
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")
    serialized_order = json.dumps(
        mutable_order, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    if _sha256(serialized_order) != effective["mutable_paths_sha256"]:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")
    if (
        effective["mutable_paths_digest_serialization"]
        != "SHA256_OF_UTF8_COMPACT_JSON_MUTABLE_PATH_ORDER_WITH_NO_TRAILING_LF"
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")
    semantic_scope = _packet_string_list(effective, "semantic_scope")
    safety_invariants = _packet_string_list(effective, "safety_invariants")
    authorized = _packet_string_list(effective, "authorized_stages")
    if len(semantic_scope) < 2 or len(safety_invariants) < 3 or len(authorized) < 6:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")
    authorized_text = " ".join(authorized)
    for alternatives in (
        ("PACKET",),
        ("PATH", "EDIT"),
        ("VALIDAT", "TEST"),
        ("HERMETIC",),
        ("COMMIT", "AMEND"),
        ("MANIFEST", "EVIDENCE"),
    ):
        if not any(token in authorized_text for token in alternatives):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")
    validation_contract = effective["bootstrap_validation_contract"]
    acceptance_lists = (
        [value for key, value in validation_contract.items() if key.endswith("_source_acceptance")]
        if type(validation_contract) is dict
        else []
    )
    if (
        type(validation_contract) is not dict
        or len(acceptance_lists) != 1
        or type(acceptance_lists[0]) is not list
        or len(acceptance_lists[0]) < 6
        or any(type(item) is not str or not item for item in acceptance_lists[0])
        or not any(value == "PROHIBITED" for key, value in validation_contract.items() if key.startswith("self_verification_for_issue_"))
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")
    acceptance_text = " ".join(acceptance_lists[0])
    for token in ("CURRENT_MAIN", "ELEVEN_SKILL", "REGISTRY", "FOCUSED", "HERMETIC", "GOVERNOR"):
        if token not in acceptance_text:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")
    continuations = _packet_string_list(
        effective, "stages_requiring_planner_continuation"
    )
    continuation_text = " ".join(continuations)
    if any(
        token not in continuation_text
        for token in ("GOVERNOR", "REMOTE", "PULL_REQUEST", "MERGE", "CLEANUP")
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")

    dependencies = effective["dependencies"]
    if (
        type(dependencies) is not dict
        or dependencies.get("unmet_dependencies") != []
        or len(dependencies) < 2
        or not any(
            key != "unmet_dependencies" and value is True
            for key, value in dependencies.items()
        )
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID")
    for key, value in dependencies.items():
        if key.endswith("sha") or key.endswith("sha256"):
            _require_sha(
                value,
                SHA1 if key.endswith("_sha") else SHA256,
                "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID",
            )
    repository_fence = effective["repository_fence"]
    remote_branches = repository_fence.get("remote_branches") if type(repository_fence) is dict else None
    remote_names = [
        item if type(item) is str else item.get("name") if type(item) is dict else None
        for item in remote_branches or []
    ]
    local_fence_valid = (
        (
            repository_fence.get("planned_local_branch_present") is False
            and repository_fence.get("planned_worktree_present") is False
        )
        or (
            repository_fence.get("local_branch_exact") is True
            and repository_fence.get("local_worktree_exact") is True
        )
        if generation == 1
        else repository_fence.get("local_branch_exact") is True
        and repository_fence.get("local_worktree_exact") is True
    )
    if (
        type(repository_fence) is not dict
        or type(repository_fence.get("observed_at")) is not str
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", repository_fence["observed_at"]) is None
        or repository_fence.get("live_main") != base_sha
        or (
            "live_main_tree" in repository_fence
            and repository_fence.get("live_main_tree") != base_tree
        )
        or (generation >= 4 and repository_fence.get("live_main_tree") != base_tree)
        or type(repository_fence.get("open_pull_requests")) is not int
        or repository_fence.get("open_pull_requests") != 0
        or remote_names != ["main"]
        or any(
            type(item) is dict and item.get("sha") != base_sha
            for item in remote_branches or []
        )
        or repository_fence.get("candidate_remote_branch_present") is not False
        or not local_fence_valid
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID")
    collision = effective["collision_fence"]
    if type(collision) is not dict:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
    intersection_values = [
        value for key, value in collision.items() if "intersection" in key
    ]
    if (
        not intersection_values
        or any(value != [] for value in intersection_values)
        or collision.get("path_collision", collision.get("active_path_collision"))
        is not False
        or collision.get("unknown_overlap_action") != "HOLD"
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")

    hard_stops = _packet_string_list(effective, "hard_stops")
    excluded = _packet_string_list(effective, "excluded_effects")
    if (
        len(hard_stops) < 6
        or len(excluded) < 5
        or any(not item.startswith("ANY_") or "ALLOW" in item for item in hard_stops)
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_HARD_STOP_INVALID")
    stop_text = " ".join((*hard_stops, *excluded))
    for alternatives in (
        ("PATH",),
        ("SQLITE",),
        ("REMOTE", "PUBLICATION"),
        ("INSTALLATION", "RUNTIME"),
        ("APPLICATION",),
        ("SELF_APPROVAL", "SELF_APPROVE", "SELF_REVIEW"),
    ):
        if not any(token in stop_text for token in alternatives):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_HARD_STOP_INVALID")

    transition_digests: dict[str, str] = {}
    generation = current.get("attempt_generation", 1)
    if type(generation) is not int or generation < 1:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    if generation >= 4:
        finding_field = "changed_evidence" if generation >= 5 else "changed_diagnosis"
        retry_required = {
            "attempt_generation",
            "supersedes_packet_sha256",
            "incorporated_packets",
            "incorporation",
            "issue_updated_at",
            "writer_transfer",
            "prior_writer",
            "prior_writer_terminal_state",
            "fresh_planner_disposition_reason",
            "repair_starting_head",
            "repair_starting_tree",
            "repair_starting_parent",
            "governor_rejection",
            "adopted_committed_state",
            finding_field,
        }
        if (
            not retry_required.issubset(current)
            or type(current["issue_updated_at"]) is not str
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                current["issue_updated_at"],
            )
            is None
            or type(current["incorporation"]) is not str
            or "EVERY_PRIOR_FIELD_REMAINS_EFFECTIVE" not in current["incorporation"]
            or type(current["writer_transfer"]) is not str
            or not current["writer_transfer"]
            or type(current["prior_writer"]) is not str
            or not current["prior_writer"].startswith("/root/")
            or current["prior_writer"] == effective["accountable_writer"]
            or type(current["prior_writer_terminal_state"]) is not str
            or not current["prior_writer_terminal_state"]
            or type(current["fresh_planner_disposition_reason"]) is not str
            or not current["fresh_planner_disposition_reason"]
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        for key in (
            "repair_starting_head",
            "repair_starting_tree",
            "repair_starting_parent",
        ):
            _require_sha(
                current[key], SHA1, "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
            )
    rejection = current.get("governor_rejection")
    adopted = current.get("adopted_committed_state")
    diagnoses = current.get(
        "changed_evidence" if generation >= 5 else "changed_diagnosis"
    )
    if rejection is not None or adopted is not None:
        if (
            type(rejection) is not dict
            or type(adopted) is not dict
            or type(diagnoses) is not list
            or not diagnoses
            or set(rejection)
            != {
                "terminal_verb",
                "attempt_identity",
                "report_sha256",
                "receipt_path",
                "receipt_sha256",
                "github_comment_id",
                "github_comment_url",
                "publication_authorized",
            }
            or set(adopted)
            != {
                "status",
                "head",
                "tree",
                "parent",
                "canonical_diff_sha256",
                "canonical_diff_bytes",
                "validation_manifest_path",
                "validation_manifest_sha256",
                "paths",
                "worktree_clean",
                "ignored_paths",
                "remote_effect",
            }
            or any(
                type(item) is not dict
                or set(item)
                != {"code", "required_behavior", "required_regression"}
                or any(type(item[key]) is not str or not item[key] for key in item)
                for item in diagnoses
            )
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        rejection_path = rejection.get("receipt_path")
        rejection_sha = rejection.get("receipt_sha256")
        manifest_path = adopted.get("validation_manifest_path")
        manifest_sha = adopted.get("validation_manifest_sha256")
        for source, digest in (
            (rejection_path, rejection_sha),
            (manifest_path, manifest_sha),
        ):
            if type(source) is not str or not Path(source).is_absolute():
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
            _require_sha(
                digest, SHA256, "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
            )
        _require_sha(
            rejection.get("report_sha256"),
            SHA256,
            "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID",
        )
        rejection_raw = _read_regular(
            Path(rejection_path),
            maximum=1024 * 1024,
            error="BOOTSTRAP_DIRECT_PACKET_TRANSITION_UNSAFE",
        )
        manifest_raw = _read_regular(
            Path(manifest_path),
            maximum=16 * 1024 * 1024,
            error="BOOTSTRAP_DIRECT_PACKET_TRANSITION_UNSAFE",
        )
        if _sha256(rejection_raw) != rejection_sha or _sha256(manifest_raw) != manifest_sha:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_DIGEST_MISMATCH")
        rejection_receipt = _load_json_object(
            rejection_raw,
            "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID_JSON",
            reject_floats=False,
        )
        manifest = _load_json_object(
            manifest_raw,
            "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID_JSON",
            reject_floats=False,
        )
        adopted_head = adopted.get("head")
        adopted_tree = adopted.get("tree")
        adopted_diff = adopted.get("canonical_diff_sha256")
        adopted_diff_bytes = adopted.get("canonical_diff_bytes")
        _require_sha(
            adopted_head, SHA1, "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
        )
        _require_sha(
            adopted_tree, SHA1, "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
        )
        _require_sha(
            adopted_diff, SHA256, "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID"
        )
        if (
            type(adopted_diff_bytes) is not int
            or adopted_diff_bytes < 0
            or type(adopted.get("ignored_paths")) is not int
            or adopted["ignored_paths"] != 0
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        _validate_rejection_receipt_shape(rejection_receipt)
        _validate_rejected_manifest_shape(
            manifest,
            issue=issue,
            branch=branch,
            base_sha=base_sha,
            base_tree=base_tree,
            head_sha=adopted_head,
            head_tree=adopted_tree,
            diff_sha256=adopted_diff,
            diff_bytes=adopted_diff_bytes,
            prior_packet_sha256=current.get("supersedes_packet_sha256"),
            incorporated_digests=incorporated_digests,
            effective=effective,
        )
        receipt_is_full = (
            frozenset(rejection_receipt) == REJECTION_RECEIPT_ACTUAL_FIELDS
        )
        manifest_is_full = (
            frozenset(manifest) == REJECTED_MANIFEST_ACTUAL_FIELDS
        )
        if receipt_is_full != manifest_is_full:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        if (
            rejection_receipt.get("starting_main_contract_sha256")
            != effective["starting_main_contract_sha256"]
            or rejection_receipt.get("validation_manifest_bytes")
            != len(manifest_raw)
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        expected_next_action = (
            "FRESH_CHANGED_DIAGNOSIS_DISPOSITION_AND_PACKET_REQUIRED"
            if receipt_is_full
            else (
                "PUBLISH_THE_EXACT_REJECTION_THEN_FREEZE_ONE_FRESH_CHANGED_"
                "EVIDENCE_PACKET_AND_ASSIGN_ONE_FRESH_BOUNDED_WRITER"
            )
        )
        if rejection_receipt.get("planner_next_action") != expected_next_action:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        if (
            rejection.get("terminal_verb") != "REJECT_SOURCE_HEAD"
            or rejection.get("publication_authorized") is not False
            or type(rejection.get("attempt_identity")) is not str
            or not rejection["attempt_identity"]
            or type(rejection.get("github_comment_id")) is not int
            or rejection["github_comment_id"] <= 0
            or type(rejection.get("github_comment_url")) is not str
            or rejection["github_comment_url"]
            != (
                "https://github.com/jayendusharma/twinfinity-harness/"
                f"issues/{issue}#issuecomment-{rejection['github_comment_id']}"
            )
            or rejection_receipt.get("terminal_verb") != "REJECT_SOURCE_HEAD"
            or rejection_receipt.get("repository") != REPOSITORY
            or rejection_receipt.get("owning_issue") != issue
            or rejection_receipt.get("issue_body_sha256")
            != effective["issue_body_sha256"]
            or rejection_receipt.get("base_sha") != base_sha
            or rejection_receipt.get("base_tree") != base_tree
            or rejection_receipt.get("head_sha") != adopted_head
            or rejection_receipt.get("head_tree") != adopted_tree
            or rejection_receipt.get("canonical_diff_sha256") != adopted_diff
            or rejection_receipt.get("canonical_diff_bytes") != adopted_diff_bytes
            or rejection_receipt.get("validation_manifest_sha256") != manifest_sha
            or rejection_receipt.get("governor_attempt_identity")
            != rejection["attempt_identity"]
            or rejection_receipt.get("governor_report_sha256")
            != rejection["report_sha256"]
            or rejection_receipt.get("packet_sha256")
            != current.get("supersedes_packet_sha256")
            or manifest.get("repository") != REPOSITORY
            or manifest.get("owning_issue") != issue
            or manifest.get("base", {}).get("commit") != base_sha
            or manifest.get("base", {}).get("tree") != base_tree
            or manifest.get("head", {}).get("commit") != adopted_head
            or manifest.get("head", {}).get("tree") != adopted_tree
            or manifest.get("canonical_diff", {}).get("sha256") != adopted_diff
            or manifest.get("canonical_diff", {}).get("bytes") != adopted_diff_bytes
            or manifest.get("direct_packet", {}).get("sha256")
            != current.get("supersedes_packet_sha256")
            or type(manifest.get("canonical_diff", {}).get("bytes")) is not int
            or adopted.get("status")
            != (
                f"CLEAN_EXACT_{COUNT_WORDS.get(len(mutable_order), '')}_PATH_"
                "SINGLE_COMMIT_FROM_STARTING_MAIN"
                + ("_GOVERNOR_REJECTED" if generation >= 5 else "")
            )
            or adopted.get("parent") != base_sha
            or current.get("repair_starting_head") != adopted_head
            or current.get("repair_starting_tree") != adopted_tree
            or current.get("repair_starting_parent") != adopted.get("parent")
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        diagnosis_codes = [
            item.get("code") if type(item) is dict else None for item in diagnoses
        ]
        rejection_codes = [
            item.get("code") if type(item) is dict else None
            for item in rejection_receipt.get("findings", [])
        ]
        expected_rejection_codes = (
            [diagnosis_codes[0], diagnosis_codes[-1]]
            if generation >= 5
            and diagnosis_codes
            == [
                "ACTUAL_92_DIRECT_PACKET_REJECTED",
                "ACTUAL_92_PATH_ORDER_FALSE_REQUIREMENT",
                "RECYCLED_ROOT_PID_DESCENDANT_CAPTURE",
            ]
            else diagnosis_codes
        )
        if (
            expected_rejection_codes != rejection_codes
            or len(set(diagnosis_codes)) != len(diagnosis_codes)
            or any(type(code) is not str or not code for code in diagnosis_codes)
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        adopted_paths = adopted.get("paths")
        manifest_paths = manifest.get("changed_paths")
        if (
            adopted.get("worktree_clean") is not True
            or adopted.get("ignored_paths") != 0
            or adopted.get("remote_effect") is not False
            or type(adopted_paths) is not list
            or type(manifest_paths) is not list
            or [
                item.get("path") if type(item) is dict else None
                for item in adopted_paths
            ]
            != mutable_order
            or [
                item.get("path") if type(item) is dict else None
                for item in manifest_paths
            ]
            != mutable_order
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        for adopted_item, manifest_item in zip(
            adopted_paths, manifest_paths, strict=True
        ):
            adopted_item_keys = {
                "path",
                "sha256",
                "git_blob",
                "bytes",
                "git_mode",
            }
            if generation >= 5:
                adopted_item_keys.add("lines")
            if (
                type(adopted_item) is not dict
                or set(adopted_item) != adopted_item_keys
                or type(manifest_item) is not dict
                or type(adopted_item.get("bytes")) is not int
                or adopted_item["bytes"] < 0
                or type(manifest_item.get("bytes")) is not int
                or type(adopted_item.get("sha256")) is not str
                or SHA256.fullmatch(adopted_item["sha256"]) is None
                or type(adopted_item.get("git_blob")) is not str
                or SHA1.fullmatch(adopted_item["git_blob"]) is None
                or adopted_item.get("git_mode") not in {"100644", "100755"}
                or adopted_item.get("sha256") != manifest_item.get("sha256")
                or adopted_item.get("git_blob") != manifest_item.get("git_blob")
                or adopted_item.get("bytes") != manifest_item.get("bytes")
                or adopted_item.get("git_mode") != manifest_item.get("git_mode")
                or (
                    generation >= 5
                    and (
                        type(adopted_item.get("lines")) is not int
                        or adopted_item["lines"] < 0
                        or adopted_item.get("lines") != manifest_item.get("lines")
                    )
                )
            ):
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
        transition_digests = {
            "governor_rejection_receipt_sha256": rejection_sha,
            "adopted_validation_manifest_sha256": manifest_sha,
        }
    elif diagnoses is not None:
        if (
            type(diagnoses) is not list
            or not diagnoses
            or any(
                type(item) is not dict
                or set(item)
                != {"code", "required_correction", "required_regression"}
                or any(type(item[key]) is not str or not item[key] for key in item)
                for item in diagnoses
            )
            or len({item["code"] for item in diagnoses}) != len(diagnoses)
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")

    consumer = current.get("current_consumer_packet")
    if consumer is not None:
        consumer_keys = {
            "path",
            "sha256",
            "repository",
            "owning_issue",
            "attempt_generation",
            "starting_main_sha",
            "branch",
            "worktree_path",
            "repair_starting_head",
            "mutable_paths_sha256",
            "mutable_path_order",
            "consumer_state",
        }
        if (
            generation < 5
            or type(consumer) is not dict
            or set(consumer) != consumer_keys
            or type(consumer.get("path")) is not str
            or not Path(consumer["path"]).is_absolute()
            or consumer.get("sha256")
            != CONSOLIDATED_ISSUE92_PACKET_V5_SHA256
            or consumer.get("repository") != REPOSITORY
            or consumer.get("owning_issue") != 92
            or consumer.get("attempt_generation") != 3
            or consumer.get("consumer_state")
            != "RETAINED_DIRTY_HOLD_NO_MUTATION_AUTHORIZED"
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CONSUMER_INVALID")
        consumer_raw = _read_regular(
            Path(consumer["path"]),
            maximum=1024 * 1024,
            error="BOOTSTRAP_DIRECT_PACKET_CONSUMER_UNSAFE",
        )
        if _sha256(consumer_raw) != consumer["sha256"]:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CONSUMER_INVALID")
        consumer_document = _load_json_object(
            consumer_raw, "BOOTSTRAP_DIRECT_PACKET_CONSUMER_INVALID"
        )
        consumer_packet = _validate_consolidated_packet_v5(
            consumer_document, consumer["sha256"]
        )
        if (
            consumer.get("starting_main_sha") != consumer_packet["base_sha"]
            or consumer.get("starting_main_sha") != base_sha
            or consumer.get("branch") != consumer_packet["branch"]
            or consumer.get("worktree_path") != consumer_packet["worktree_path"]
            or consumer.get("repair_starting_head")
            != consumer_document.get("repair_starting_head")
            or consumer.get("mutable_paths_sha256")
            != consumer_packet["mutable_paths_sha256"]
            or consumer.get("mutable_path_order")
            != consumer_packet["mutable_path_order"]
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CONSUMER_INVALID")

    return {
        "sha256": expected_sha256,
        "route": DIRECT_ROUTE,
        "repository": REPOSITORY,
        "issue_number": issue,
        "base_sha": base_sha,
        "base_tree": base_tree,
        "branch": branch,
        "worktree_path": worktree,
        "opaque_worktree_id": opaque,
        "accountable_writer": effective["accountable_writer"],
        "issue_body_sha256": effective["issue_body_sha256"],
        "mutable_paths": mutable_paths,
        "mutable_path_order": mutable_order,
        "mutable_paths_sha256": effective["mutable_paths_sha256"],
        "remote_branches": remote_names,
        "incorporated_packet_sha256": incorporated_digests,
        **transition_digests,
    }


def _issue92_post_merge_expected_document(
    packet: dict[str, Any],
) -> dict[str, Any]:
    """Return the one accepted semantic generation-4 issue-92 envelope."""

    mutable_paths = [
        {
            "path": path,
            "starting_sha256": starting_sha256,
            "starting_git_blob": starting_git_blob,
        }
        for path, starting_sha256, starting_git_blob in (
            ISSUE92_POST_MERGE_MUTABLE_PATHS
        )
    ]
    mutable_order = [item[0] for item in ISSUE92_POST_MERGE_MUTABLE_PATHS]
    return {
        "schema": "twinfinity-direct-harness-source-maintenance/v1",
        "repository": REPOSITORY,
        "owning_issue": 92,
        "attempt_generation": 4,
        "supersedes_packet_sha256": CONSOLIDATED_ISSUE92_PACKET_V5_SHA256,
        "complete_packet_chain": [
            {"version": version, "sha256": digest}
            for version, digest in ISSUE92_PACKET_CHAIN_V1_V5
        ],
        "issue_body_sha256": (
            "667e2eb0cc815bcec22fb4ed402108fb240f0065b71df97f08529007adf77635"
        ),
        "starting_main_ref": "refs/remotes/origin/main",
        "starting_main_sha": packet.get("starting_main_sha"),
        "starting_main_tree": packet.get("starting_main_tree"),
        "branch": ISSUE92_POST_MERGE_BRANCH,
        "worktree_path": ISSUE92_POST_MERGE_WORKTREE,
        "opaque_worktree_id": ISSUE92_POST_MERGE_OPAQUE_WORKTREE_ID,
        "prior_retained_head": ISSUE92_POST_MERGE_PRIOR_RETAINED_HEAD,
        "prior_retained_tree": ISSUE92_POST_MERGE_PRIOR_RETAINED_TREE,
        "prior_retained_parent": ISSUE92_POST_MERGE_PRIOR_RETAINED_PARENT,
        "candidate_head": packet.get("candidate_head"),
        "candidate_tree": packet.get("candidate_tree"),
        "candidate_parent": packet.get("candidate_parent"),
        "prior_writer": ISSUE92_POST_MERGE_PRIOR_WRITER,
        "prior_writer_terminal_state": (
            "PACKET_V5_WRITER_TERMINAL_RETAINED_DIRTY_HOLD_NO_REMOTE_EFFECT"
        ),
        "accountable_writer": ISSUE92_POST_MERGE_ACCOUNTABLE_WRITER,
        "writer_transfer": (
            "RESERVED_POST_ISSUE_98_REBASE_WRITER_INHERITS_THE_EXISTING_"
            "ISSUE_92_DIRECT_UNIT_AND_EXACT_RETAINED_HEAD"
        ),
        "fresh_planner_disposition_reason": (
            "ISSUE_98_SOURCE_COMPLETE_ACCEPTED_BASE_NOW_CONTAINS_THE_"
            "IMMUTABLE_VERIFIER_AND_PACKET_V5_IS_STALE"
        ),
        "authority": {
            "kind": (
                "DIRECT_OWNER_INSTRUCTION_PLUS_FRESH_PLANNER_CHANGED_"
                "DIAGNOSIS_DISPOSITION"
            ),
            "direct_owner_instructions": [
                "we don't want to use sqllite based harness flow right now",
                "we are outisde of it",
                "harness issues need to be patched without using harness loop itself",
                "reflect that in the appropriate skills",
            ],
            "temporary_six_writer_authority_sha256": (
                "dc569290e808d6cd025943f30ad36048375e66581405951b975585f9b65cb5e9"
            ),
            "standing_routine_delivery_authority_sha256": (
                "e603cccbf9cc6b882703bf9b278d8d9839942a949fcea3d07caa9cdb85e49bed"
            ),
            "sqlite_harness_loop": (
                "PROHIBITED_FOR_HARNESS_SOURCE_MAINTENANCE"
            ),
        },
        "human_path_authority": {
            "issue_body_binds_exact_six_path_lease": True,
            "issue_body_states_direct_user_authority_effective": True,
            "independent_governor_v2_authority_disposition": "SATISFIED",
            "independent_governor_report_sha256": (
                "11c66f14f41ec5acb5e9af4232612125e09357a8d0ef3faf15379e59bb6993f7"
            ),
            "fourth_path_clause_interpretation": (
                "THE_PREDECLARED_EXACT_SIX_PATH_OWNER_BODY_AND_PACKET_V1_"
                "INSTRUCTIONS_SATISFY_THE_HUMAN_DIRECTION_FOR_THIS_LANE_ONLY"
            ),
            "expansion_boundary": (
                "ANY_SEVENTH_PATH_PATH_SUBSTITUTION_CATALOG_MEMBERSHIP_"
                "CHANGE_OR_SEMANTIC_EXPANSION_IS_HOLD"
            ),
        },
        "direct_capacity": {
            "class": "HARNESS_SOURCE_WRITER",
            "units": 1,
            "temporary_limit": 6,
            "occupancy_including_active_and_retained": 3,
            "capacity_effect": "TRANSFER_EXISTING_ISSUE_92_UNIT_NO_INCREMENT",
            "sqlite_allocation_units": 0,
        },
        "repository_fence": {
            "accepted_main_ref": "refs/remotes/origin/main",
            "accepted_main_sha": packet.get("starting_main_sha"),
            "accepted_main_tree": packet.get("starting_main_tree"),
            "head_ref": f"refs/heads/{ISSUE92_POST_MERGE_BRANCH}",
            "candidate_head": packet.get("candidate_head"),
            "candidate_tree": packet.get("candidate_tree"),
            "candidate_parent": packet.get("candidate_parent"),
            "candidate_remote_ref": "ABSENT",
        },
        "mutable_paths": mutable_paths,
        "mutable_path_order": mutable_order,
        "mutable_paths_digest_serialization": (
            "SHA256_OF_UTF8_COMPACT_JSON_MUTABLE_PATH_ORDER_WITH_NO_TRAILING_LF"
        ),
        "mutable_paths_sha256": ISSUE92_POST_MERGE_MUTABLE_PATHS_SHA256,
        "consolidated_required_outcomes": [
            {
                "id": "GOV92-1-PARTIAL",
                "outcome": (
                    "RECEIPT_RESULT_AND_LEGACY_STDOUT_STDERR_BYTE_COUNTS_MUST_"
                    "BE_EXACT_INTEGERS_WITHIN_ZERO_THROUGH_CATALOG_MAXIMUM_"
                    "OUTPUT_BYTES"
                ),
                "negative_evidence": "DIGEST_REBOUND_OVER_CAP_COUNTS_REJECT",
            },
            {
                "id": "GOV92-2",
                "outcome": (
                    "AN_ENFORCEABLE_DESCENDANT_BOUNDARY_MUST_PROVE_NO_"
                    "VALIDATOR_DESCENDANT_SURVIVES_NORMAL_ZERO_NONZERO_TIMEOUT_"
                    "OUTPUT_LIMIT_OR_SIGNAL_ESCAPE"
                ),
                "negative_evidence": (
                    "SETSID_START_NEW_SESSION_SETPGID_AND_SIGTERM_ESCAPE_"
                    "PROBES_CANNOT_SURVIVE_OR_PASS"
                ),
            },
            {
                "id": "GOV92-3",
                "outcome": (
                    "STAGED_AND_INSTALLED_VALIDATION_MUST_BIND_INDEPENDENTLY_"
                    "VERIFIED_STATE_SPECIFIC_INSTALLER_EVIDENCE_AND_ACTUAL_"
                    "TARGET_IDENTITY"
                ),
                "negative_evidence": (
                    "THE_SAME_ROOT_MANIFEST_ATOM_AND_TOOL_IDENTITIES_CANNOT_"
                    "PASS_UNDER_BOTH_KINDS"
                ),
            },
            {
                "id": "INSTALL-CLOSURE",
                "outcome": (
                    "REQUIRED_INSTALLATION_CLOSURE_MUST_DERIVE_FROM_THE_"
                    "REVIEWED_SOURCE_CATALOG_AND_MANIFEST_NOT_FROM_FILES_"
                    "ALREADY_PRESENT_IN_THE_TARGET"
                ),
                "negative_evidence": (
                    "OMITTING_ANY_REQUIRED_FILE_INCLUDING_COORDINATION_STORE_"
                    "REJECTS_INSTALLED_RUNTIME"
                ),
            },
            {
                "id": "TRUST-ANCHOR",
                "outcome": (
                    "ACCEPTED_BASE_EXECUTION_AND_RECEIPT_VERIFICATION_MUST_"
                    "USE_IMMUTABLE_ACCEPTED_BASE_TOOLING_AND_DERIVED_GIT_"
                    "IDENTITIES_OUTSIDE_CANDIDATE_CONTROL"
                ),
                "negative_evidence": (
                    "A_CANDIDATE_RUNNER_VERIFIER_FORGED_RECEIPT_EQUAL_BASE_"
                    "HEAD_OR_FALSE_TOOL_COMMIT_CANNOT_PASS"
                ),
            },
            {
                "id": "PREPUSH-BUDGET",
                "outcome": (
                    "THE_OUTER_PREPUSH_TIMEOUT_MUST_BE_DERIVED_FROM_OR_NOT_"
                    "LESS_THAN_THE_COMPLETE_VALID_CATALOG_EXECUTION_BUDGET"
                ),
                "negative_evidence": (
                    "A_CONFORMING_MAXIMUM_DURATION_RUN_IS_NOT_FALSELY_"
                    "TERMINATED_BY_A_SHORTER_OUTER_DEFAULT"
                ),
            },
            {
                "id": "EVIDENCE-COMPLETENESS",
                "outcome": (
                    "THE_FINAL_MANIFEST_MUST_RECORD_EXACT_ARGV_FOR_EVERY_GATE_"
                    "AND_IDENTIFY_THE_CONTRACT_MANDATORY_DIRECT_ROUTE_"
                    "APPLICATION_NORMAL_ADMISSION_AND_SUBSTITUTED_PACKET_"
                    "FORWARD_TESTS"
                ),
                "negative_evidence": "NO_PLACEHOLDER_OR_PROSE_ONLY_COMMAND_EVIDENCE",
            },
        ],
        "semantic_scope": [
            "TRUSTED_ACCEPTED_BASE_VALIDATION",
            "EXACT_RECEIPT_SCHEMA_RANGE_AND_IDENTITY_CLOSURE",
            "ENFORCEABLE_VALIDATOR_DESCENDANT_CONTAINMENT",
            "STATE_SPECIFIC_STAGED_AND_INSTALLED_PROVENANCE",
            "SOURCE_DERIVED_COMPLETE_INSTALL_MANIFEST_COVERAGE",
            "PREPUSH_BUDGET_AND_EVIDENCE_COMPLETENESS",
        ],
        "safety_invariants": [
            "CANDIDATE_BYTES_CANNOT_SELF_ATTEST_OR_SELECT_THE_TRUST_ANCHOR",
            "NO_VALIDATOR_DESCENDANT_SURVIVES_ANY_TERMINAL_PATH",
            (
                "STAGED_INSTALLED_SOURCE_AND_ACCEPTED_BASE_IDENTITIES_ARE_"
                "DERIVED_AND_NONINTERCHANGEABLE"
            ),
            "PARTIAL_INSTALLATIONS_CANNOT_PASS",
            (
                "PUBLICATION_CAN_TARGET_ONLY_A_FRESHLY_INDEPENDENTLY_"
                "ACCEPTED_EXACT_HEAD"
            ),
        ],
        "non_goals": [
            "NO_CATALOG_MEMBERSHIP_CHANGE",
            "NO_ROLE_ENDPOINT_PROFILE_CAPACITY_POLICY_OR_SQLITE_CHANGE",
            "NO_INSTALLATION_RUNTIME_SYSTEMD_PROVIDER_HOSTED_OR_APPLICATION_EFFECT",
            "NO_ISSUE_93_ISSUE_94_OR_ISSUE_96_MUTATION",
        ],
        "authorized_stages": [
            (
                "READ_AND_VALIDATE_THIS_EXACT_GENERATION4_SUCCESSOR_AND_THE_"
                "GIT_DERIVED_ACCEPTED_BASE_CANDIDATE_AND_RETAINED_IDENTITIES"
            ),
            "EDIT_ONLY_THE_EXACT_SIX_PATH_LEASE_TO_CLOSE_ALL_CONSOLIDATED_OUTCOMES",
            "AMEND_THE_ONE_BOUNDED_LOCAL_COMMIT_AFTER_THE_EXACT_REBASE",
            "RUN_EXACT_ADVERSARIAL_FOCUSED_FIXED_CATALOG_ROUTING_AND_FULL_HERMETIC_GATES",
            (
                "RETURN_EXACT_CLEAN_HEAD_TREE_PARENT_DIFF_AND_PACKET_BOUND_"
                "VALIDATION_MANIFEST_WITH_EXACT_ARGV"
            ),
        ],
        "stages_requiring_planner_continuation": [
            "FRESH_INDEPENDENT_EXACT_HEAD_GOVERNOR_REVIEW",
            "REMOTE_PUBLICATION",
            "PULL_REQUEST_CREATION_OR_UPDATE",
            "MATCH_HEAD_MERGE",
            "REMOTE_OR_LOCAL_CLEANUP",
            "TERMINAL_PUBLICATION",
        ],
        "hard_stops": [
            "ANY_SEVENTH_PATH_PATH_SUBSTITUTION_OR_CATALOG_MEMBERSHIP_CHANGE",
            (
                "ANY_CHANGED_DIAGNOSIS_SEMANTIC_SCOPE_AUTHORITY_CAPACITY_"
                "DEPENDENCY_OR_COLLISION"
            ),
            (
                "ANY_ISSUE_BODY_ACCEPTED_BASE_BRANCH_WORKTREE_WRITER_OR_PRIOR_"
                "RETAINED_IDENTITY_DRIFT"
            ),
            "ANY_UNRESOLVED_CONSOLIDATED_FINDING_OR_PLACEHOLDER_VALIDATION_EVIDENCE",
            "ANY_MUTATION_OF_HISTORICAL_RETIRED_HELD_OR_RETAINED_WORKTREES",
            "ANY_SQLITE_READ_OR_MUTATION_AS_HARNESS_AUTHORITY",
            "ANY_RAW_FORCE_OR_REMOTE_PUBLICATION",
            "ANY_INSTALLATION_ENDPOINT_SYSTEMD_PROVIDER_HOSTED_APPLICATION_OR_PRODUCTION_EFFECT",
            "ANY_REUSE_OF_A_REJECTED_GOVERNOR_RECEIPT_AS_APPROVAL",
        ],
        "excluded_effects": [
            "SQLITE_READ_AS_AUTHORITY_OR_SQLITE_MUTATION",
            "REMOTE_PUSH_OR_PULL_REQUEST",
            "MERGE",
            "INSTALLATION_OR_RUNTIME_ACTIVATION",
            (
                "ENDPOINT_SYSTEMD_TIMER_SERVICE_PROVIDER_HOSTED_PRODUCTION_"
                "OR_APPLICATION_OPERATION"
            ),
        ],
        "repair_budget_for_attempt_generation_4": 1,
        "current_stage": (
            "FRESH_POST_ISSUE_98_REBASE_WRITER_READY_ON_EXACT_GENERATION4_"
            "SUCCESSOR"
        ),
    }


def _validate_issue92_post_merge_packet(
    packet: dict[str, Any], raw: bytes, expected_sha256: str
) -> dict[str, Any]:
    """Validate the sole semantic post-issue-98 generation-4 carrier."""

    error = "BOOTSTRAP_ISSUE92_POST_MERGE_PACKET_INVALID"
    if frozenset(packet) != ISSUE92_POST_MERGE_FIELDS:
        raise VerificationError(error)
    for key in (
        "starting_main_sha",
        "starting_main_tree",
        "candidate_head",
        "candidate_tree",
        "candidate_parent",
    ):
        _require_sha(packet.get(key), SHA1, error)
    if (
        packet["starting_main_sha"] == ISSUE92_POST_MERGE_PRIOR_RETAINED_PARENT
        or packet["candidate_head"]
        in {
            packet["starting_main_sha"],
            ISSUE92_POST_MERGE_PRIOR_RETAINED_HEAD,
        }
        or packet["candidate_parent"] != packet["starting_main_sha"]
        or not _strict_equal(packet, _issue92_post_merge_expected_document(packet))
        or raw != _canonical_bytes(packet)
    ):
        raise VerificationError(error)
    return {
        "sha256": expected_sha256,
        "route": DIRECT_ROUTE,
        "repository": REPOSITORY,
        "issue_number": 92,
        "base_sha": packet["starting_main_sha"],
        "base_tree": packet["starting_main_tree"],
        "branch": ISSUE92_POST_MERGE_BRANCH,
        "worktree_path": ISSUE92_POST_MERGE_WORKTREE,
        "opaque_worktree_id": ISSUE92_POST_MERGE_OPAQUE_WORKTREE_ID,
        "accountable_writer": ISSUE92_POST_MERGE_ACCOUNTABLE_WRITER,
        "issue_body_sha256": packet["issue_body_sha256"],
        "mutable_paths": packet["mutable_paths"],
        "mutable_path_order": packet["mutable_path_order"],
        "mutable_paths_sha256": packet["mutable_paths_sha256"],
        "remote_branches": ["main"],
        "incorporated_packet_sha256": [
            digest for _, digest in ISSUE92_PACKET_CHAIN_V1_V5
        ],
        "candidate_head": packet["candidate_head"],
        "candidate_tree": packet["candidate_tree"],
        "candidate_parent": packet["candidate_parent"],
        "prior_retained_head": ISSUE92_POST_MERGE_PRIOR_RETAINED_HEAD,
        "prior_retained_tree": ISSUE92_POST_MERGE_PRIOR_RETAINED_TREE,
        "prior_retained_parent": ISSUE92_POST_MERGE_PRIOR_RETAINED_PARENT,
        "repository_fence": packet["repository_fence"],
    }


def _validate_consolidated_packet_v5(
    packet: dict[str, Any], expected_sha256: str
) -> dict[str, Any]:
    """Validate the self-contained direct-maintenance packet used by issue 92."""

    error = "BOOTSTRAP_DIRECT_PACKET_SCHEMA_INVALID"
    if (
        expected_sha256 != CONSOLIDATED_ISSUE92_PACKET_V5_SHA256
        or frozenset(packet) != CONSOLIDATED_PACKET_V5_FIELDS
    ):
        raise VerificationError(error)
    if (
        packet.get("schema")
        != "twinfinity-direct-harness-source-maintenance/v1"
        or packet.get("repository") != REPOSITORY
        or packet.get("owning_issue") != 92
        or packet.get("attempt_generation") != 3
        or packet.get("repair_budget_for_attempt_generation_3") != 1
        or packet.get("issue_observed_state") != "open"
        or packet.get("starting_main_ref") != "refs/heads/main"
    ):
        raise VerificationError(error)
    timestamp = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
    if any(
        type(packet.get(key)) is not str
        or re.fullmatch(timestamp, packet[key]) is None
        for key in ("recorded_at", "issue_observed_at")
    ):
        raise VerificationError(error)

    for key in (
        "starting_main_sha",
        "starting_main_tree",
        "repair_starting_head",
        "repair_starting_tree",
        "repair_starting_parent",
    ):
        _require_sha(packet.get(key), SHA1, error)
    for key in (
        "issue_body_sha256",
        "starting_main_contract_sha256",
        "mutable_paths_sha256",
        "supersedes_packet_sha256",
    ):
        _require_sha(packet.get(key), SHA256, error)
    if packet["repair_starting_parent"] != packet["starting_main_sha"]:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BASE_INVALID")

    issue = packet["owning_issue"]
    branch = packet.get("branch")
    worktree = packet.get("worktree_path")
    opaque = packet.get("opaque_worktree_id")
    if (
        type(branch) is not str
        or BRANCH.fullmatch(branch) is None
        or not branch.startswith(f"change/{issue}-")
        or type(worktree) is not str
        or not Path(worktree).is_absolute()
        or type(opaque) is not str
        or opaque != Path(worktree).name
        or not opaque.startswith(f"twinfinity-harness-issue{issue}")
        or type(packet.get("accountable_writer")) is not str
        or not packet["accountable_writer"].startswith("/root/")
        or type(packet.get("prior_writer")) is not str
        or not packet["prior_writer"].startswith("/root/")
        or packet["prior_writer"] == packet["accountable_writer"]
        or any(
            type(packet.get(key)) is not str or not packet[key]
            for key in (
                "writer_transfer",
                "fresh_planner_disposition_reason",
                "current_stage",
            )
        )
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_BINDING_INVALID")

    chain = packet.get("complete_packet_chain")
    if type(chain) is not list or not chain or len(chain) > 16:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    chain_digests: list[str] = []
    for expected_version, item in enumerate(chain, start=1):
        if (
            type(item) is not dict
            or set(item) != {"version", "sha256"}
            or type(item.get("version")) is not int
            or item["version"] != expected_version
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
        chain_digests.append(
            _require_sha(
                item.get("sha256"),
                SHA256,
                "BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID",
            )
        )
    if (
        len(set(chain_digests)) != len(chain_digests)
        or packet["supersedes_packet_sha256"] != chain_digests[-1]
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")

    authority = _closed_keys(
        packet.get("authority"),
        AUTHORITY_KEY_SETS,
        "BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID",
    )
    instructions = authority.get("direct_owner_instructions")
    if (
        type(authority.get("kind")) is not str
        or not authority["kind"].startswith("DIRECT_OWNER_INSTRUCTION")
        or type(instructions) is not list
        or not instructions
        or any(type(item) is not str or not item for item in instructions)
        or authority.get("sqlite_harness_loop")
        != "PROHIBITED_FOR_HARNESS_SOURCE_MAINTENANCE"
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID")
    for key in (
        "temporary_six_writer_authority_sha256",
        "standing_routine_delivery_authority_sha256",
    ):
        _require_sha(
            authority.get(key), SHA256, "BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID"
        )

    human = packet.get("human_path_authority")
    if (
        type(human) is not dict
        or set(human)
        != {
            "issue_body_binds_exact_six_path_lease",
            "issue_body_states_direct_user_authority_effective",
            "independent_governor_v2_authority_disposition",
            "independent_governor_report_sha256",
            "fourth_path_clause_interpretation",
            "expansion_boundary",
        }
        or human.get("issue_body_binds_exact_six_path_lease") is not True
        or human.get("issue_body_states_direct_user_authority_effective") is not True
        or human.get("independent_governor_v2_authority_disposition")
        != "SATISFIED"
        or any(
            type(human.get(key)) is not str or not human[key]
            for key in ("fourth_path_clause_interpretation", "expansion_boundary")
        )
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID")
    _require_sha(
        human.get("independent_governor_report_sha256"),
        SHA256,
        "BOOTSTRAP_DIRECT_PACKET_AUTHORITY_INVALID",
    )

    capacity = _closed_keys(
        packet.get("direct_capacity"),
        (CAPACITY_KEY_SETS[1],),
        "BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID",
    )
    if (
        capacity.get("class") != "HARNESS_SOURCE_WRITER"
        or type(capacity.get("units")) is not int
        or capacity["units"] != 1
        or type(capacity.get("temporary_limit")) is not int
        or not (1 <= capacity["temporary_limit"] <= 64)
        or type(capacity.get("occupancy_including_active_and_retained")) is not int
        or not (
            1
            <= capacity["occupancy_including_active_and_retained"]
            <= capacity["temporary_limit"]
        )
        or type(capacity.get("capacity_effect")) is not str
        or not capacity["capacity_effect"]
        or capacity.get("sqlite_allocation_units") != 0
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_CAPACITY_INVALID")

    dependencies = packet.get("dependencies")
    if (
        type(dependencies) is not dict
        or set(dependencies)
        != {
            "issue_91_source_complete",
            "issue_91_accepted_head",
            "issue_91_merge_result_main",
            "issue_91_terminal_receipt_body_sha256",
            "unmet_dependencies",
        }
        or dependencies.get("issue_91_source_complete") is not True
        or dependencies.get("unmet_dependencies") != []
        or dependencies.get("issue_91_merge_result_main")
        != packet["starting_main_sha"]
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID")
    for key in ("issue_91_accepted_head", "issue_91_merge_result_main"):
        _require_sha(
            dependencies.get(key), SHA1, "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID"
        )
    _require_sha(
        dependencies.get("issue_91_terminal_receipt_body_sha256"),
        SHA256,
        "BOOTSTRAP_DIRECT_PACKET_DEPENDENCY_INVALID",
    )

    mutable_paths = packet.get("mutable_paths")
    mutable_order = packet.get("mutable_path_order")
    if (
        type(mutable_paths) is not list
        or not mutable_paths
        or type(mutable_order) is not list
        or len(mutable_paths) != len(mutable_order)
        or len(set(mutable_order)) != len(mutable_order)
        or [item.get("path") if type(item) is dict else None for item in mutable_paths]
        != mutable_order
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")
    for item, relative in zip(mutable_paths, mutable_order, strict=True):
        if (
            type(item) is not dict
            or set(item) != {"path", "starting_sha256", "starting_git_blob"}
            or type(relative) is not str
            or not relative
            or Path(relative).is_absolute()
            or Path(relative).as_posix() != relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")
        for key, pattern in (("starting_sha256", SHA256), ("starting_git_blob", SHA1)):
            value = item.get(key)
            if value != "ABSENT":
                _require_sha(value, pattern, "BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")
    serialized_order = json.dumps(
        mutable_order, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    if (
        _sha256(serialized_order) != packet["mutable_paths_sha256"]
        or packet.get("mutable_paths_digest_serialization")
        != "SHA256_OF_UTF8_COMPACT_JSON_MUTABLE_PATH_ORDER_WITH_NO_TRAILING_LF"
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")

    fence = packet.get("repository_fence")
    if (
        type(fence) is not dict
        or set(fence)
        != {
            "observed_at",
            "live_main",
            "open_pull_requests",
            "remote_branches",
            "candidate_remote_branch_present",
            "local_worktree_porcelain_sha256",
            "local_branch_inventory_sha256",
        }
        or type(fence.get("observed_at")) is not str
        or re.fullmatch(timestamp, fence["observed_at"]) is None
        or fence.get("live_main") != packet["starting_main_sha"]
        or fence.get("open_pull_requests") != 0
        or fence.get("remote_branches")
        != [{"name": "main", "sha": packet["starting_main_sha"]}]
        or fence.get("candidate_remote_branch_present") is not False
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID")
    for key in ("local_worktree_porcelain_sha256", "local_branch_inventory_sha256"):
        _require_sha(
            fence.get(key), SHA256, "BOOTSTRAP_DIRECT_PACKET_REPOSITORY_FENCE_INVALID"
        )

    collision = packet.get("collision_fence")
    collision_keys = {
        "observed_at",
        "active_or_retained_direct_lanes",
        "issue_body_named_inactive_lanes",
        "closed_historical_nonretired_worktrees",
        "retired_worktree_prefix",
        "retired_worktree_mutation",
        "branch_collision",
        "worktree_collision",
        "active_path_collision",
        "semantic_relation_with_93",
        "semantic_relation_with_94",
        "semantic_relation_with_96",
        "unknown_overlap_action",
    }
    if (
        type(collision) is not dict
        or set(collision) != collision_keys
        or type(collision.get("observed_at")) is not str
        or re.fullmatch(timestamp, collision["observed_at"]) is None
        or collision.get("branch_collision") is not False
        or collision.get("worktree_collision") is not False
        or collision.get("active_path_collision") is not False
        or collision.get("retired_worktree_mutation") != "PROHIBITED"
        or collision.get("unknown_overlap_action") != "HOLD"
        or any(
            type(collision.get(key)) is not str or not collision[key]
            for key in (
                "retired_worktree_prefix",
                "semantic_relation_with_93",
                "semantic_relation_with_94",
                "semantic_relation_with_96",
            )
        )
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
    lanes = collision.get("active_or_retained_direct_lanes")
    if type(lanes) is not list or not lanes or len({item.get("issue") for item in lanes if type(item) is dict}) != len(lanes):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
    own_lane = False
    for lane in lanes:
        allowed = {"issue", "branch", "worktree", "state"}
        if type(lane) is not dict:
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
        if lane.get("issue") != issue:
            allowed |= {"packet_sha256", "mutable_paths_sha256", "intersection_with_issue_92"}
        if (
            set(lane) != allowed
            or type(lane.get("issue")) is not int
            or type(lane.get("branch")) is not str
            or not lane["branch"].startswith(f"change/{lane['issue']}-")
            or type(lane.get("worktree")) is not str
            or not Path(lane["worktree"]).is_absolute()
            or type(lane.get("state")) is not str
            or not lane["state"]
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
        if lane["issue"] == issue:
            own_lane = lane["branch"] == branch and lane["worktree"] == worktree
        else:
            _require_sha(lane.get("packet_sha256"), SHA256, "BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
            _require_sha(lane.get("mutable_paths_sha256"), SHA256, "BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
            if lane.get("intersection_with_issue_92") != []:
                raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
    inactive = collision.get("issue_body_named_inactive_lanes")
    historical = collision.get("closed_historical_nonretired_worktrees")
    if (
        not own_lane
        or type(inactive) is not dict
        or set(inactive)
        != {"issues", "local_worktree_paths_present", "remote_branches_present", "open_pull_requests_present"}
        or type(inactive.get("issues")) is not list
        or not inactive["issues"]
        or any(type(value) is not int or value <= 0 for value in inactive["issues"])
        or inactive.get("local_worktree_paths_present") is not False
        or inactive.get("remote_branches_present") is not False
        or inactive.get("open_pull_requests_present") is not False
        or type(historical) is not list
        or not historical
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")
    for item in historical:
        if (
            type(item) is not dict
            or not {"issue", "state", "tracked_status", "mutation"}.issubset(item)
            or any(key not in {"issue", "state", "tracked_status", "mutation", "known_path_intersection", "classification"} for key in item)
            or type(item.get("issue")) is not int
            or item.get("mutation") != "PROHIBITED"
            or item.get("tracked_status") != "clean"
            or any(type(item.get(key)) is not str or not item[key] for key in ("state",))
            or ("known_path_intersection" in item and (type(item["known_path_intersection"]) is not list or any(type(path) is not str or not path for path in item["known_path_intersection"])))
        ):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_COLLISION_INVALID")

    prior = packet.get("prior_rejection")
    if (
        type(prior) is not dict
        or set(prior)
        != {"receipt_path", "receipt_sha256", "report_sha256", "terminal_verb", "rejected_head", "rejected_tree", "rejected_diff_sha256"}
        or type(prior.get("receipt_path")) is not str
        or not Path(prior["receipt_path"]).is_absolute()
        or prior.get("terminal_verb") != "REJECT_SOURCE_HEAD"
        or prior.get("rejected_head") != packet["repair_starting_head"]
        or prior.get("rejected_tree") != packet["repair_starting_tree"]
        or prior.get("report_sha256")
        != human["independent_governor_report_sha256"]
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")
    for key, pattern in (
        ("receipt_sha256", SHA256),
        ("report_sha256", SHA256),
        ("rejected_head", SHA1),
        ("rejected_tree", SHA1),
        ("rejected_diff_sha256", SHA256),
    ):
        _require_sha(prior.get(key), pattern, "BOOTSTRAP_DIRECT_PACKET_TRANSITION_INVALID")

    outcomes = packet.get("consolidated_required_outcomes")
    if (
        type(outcomes) is not list
        or not outcomes
        or len({item.get("id") for item in outcomes if type(item) is dict}) != len(outcomes)
        or any(
            type(item) is not dict
            or set(item) != {"id", "outcome", "negative_evidence"}
            or any(type(item.get(key)) is not str or not item[key] for key in item)
            for item in outcomes
        )
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_SCOPE_INVALID")

    semantic = _packet_string_list(packet, "semantic_scope")
    invariants = _packet_string_list(packet, "safety_invariants")
    non_goals = _packet_string_list(packet, "non_goals")
    authorized = _packet_string_list(packet, "authorized_stages")
    continuations = _packet_string_list(packet, "stages_requiring_planner_continuation")
    hard_stops = _packet_string_list(packet, "hard_stops")
    excluded = _packet_string_list(packet, "excluded_effects")
    if (
        len(semantic) < 2
        or len(invariants) < 3
        or len(non_goals) < 3
        or len(authorized) < 5
        or len(continuations) < 5
        or len(hard_stops) < 6
        or len(excluded) < 5
        or any(not item.startswith("ANY_") or "ALLOW" in item for item in hard_stops)
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")
    authorized_text = " ".join(authorized)
    for alternatives in (("PACKET",), ("PATH", "EDIT"), ("VALIDAT", "TEST"), ("HERMETIC",), ("COMMIT", "AMEND"), ("MANIFEST", "EVIDENCE")):
        if not any(token in authorized_text for token in alternatives):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")
    continuation_text = " ".join(continuations)
    if any(token not in continuation_text for token in ("GOVERNOR", "REMOTE", "PULL_REQUEST", "MERGE", "CLEANUP")):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_STAGE_INVALID")
    stop_text = " ".join((*hard_stops, *excluded, *non_goals))
    for alternatives in (("PATH",), ("SQLITE",), ("REMOTE", "PUBLICATION"), ("INSTALLATION", "RUNTIME"), ("APPLICATION",), ("GOVERNOR", "APPROVAL", "REVIEW")):
        if not any(token in stop_text for token in alternatives):
            raise VerificationError("BOOTSTRAP_DIRECT_PACKET_HARD_STOP_INVALID")

    return {
        "sha256": expected_sha256,
        "route": DIRECT_ROUTE,
        "repository": REPOSITORY,
        "issue_number": issue,
        "base_sha": packet["starting_main_sha"],
        "base_tree": packet["starting_main_tree"],
        "branch": branch,
        "worktree_path": worktree,
        "opaque_worktree_id": opaque,
        "accountable_writer": packet["accountable_writer"],
        "issue_body_sha256": packet["issue_body_sha256"],
        "mutable_paths": mutable_paths,
        "mutable_path_order": mutable_order,
        "mutable_paths_sha256": packet["mutable_paths_sha256"],
        "remote_branches": ["main"],
        "incorporated_packet_sha256": chain_digests,
        "prior_rejection_receipt_sha256": prior["receipt_sha256"],
    }


def _load_direct_packet(path: Path, expected_sha256: str) -> dict[str, Any]:
    _require_sha(
        expected_sha256, SHA256, "BOOTSTRAP_EXPECTED_PACKET_DIGEST_INVALID"
    )
    raw = _read_regular(
        path,
        maximum=1024 * 1024,
        error="BOOTSTRAP_DIRECT_PACKET_UNSAFE",
    )
    if _sha256(raw) != expected_sha256:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DIGEST_MISMATCH")
    packet = _load_json_object(raw, "BOOTSTRAP_DIRECT_PACKET_INVALID_JSON")
    if _classify_packet_route(packet) != DIRECT_ROUTE:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_ROUTE_SUBSTITUTED")
    if "complete_packet_chain" in packet:
        if (
            packet.get("owning_issue") == 92
            and packet.get("attempt_generation") == 4
        ):
            return _validate_issue92_post_merge_packet(
                packet, raw, expected_sha256
            )
        return _validate_consolidated_packet_v5(packet, expected_sha256)
    generation = packet.get("attempt_generation", 1)
    if type(generation) is not int:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    if packet.get("owning_issue") == 92 and generation >= 4:
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_LINEAGE_INVALID")
    _validate_packet_document_shape(packet, generation)
    effective, incorporated, inherited = _effective_packet(path, packet)
    return _validate_packet_envelope(
        packet, effective, inherited, expected_sha256, incorporated
    )


def _tool_identities(
    repository_root: Path,
    base_tree: str,
    head_tree: str,
) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    for name, path, execution_source in TOOL_PATHS:
        base_blob, base_digest, base_bytes = _blob_identity(
            repository_root, base_tree, path
        )
        head_blob, head_digest, _ = _blob_identity(repository_root, head_tree, path)
        if name == "accepted_base_verifier":
            running = _read_regular(
                Path(__file__), maximum=16 * 1024 * 1024,
                error="BOOTSTRAP_RUNNING_VERIFIER_UNSAFE",
            )
            if running != base_bytes or _sha256(running) != base_digest:
                raise VerificationError("BOOTSTRAP_RUNNING_VERIFIER_NOT_ACCEPTED_BASE")
        identities.append(
            {
                "name": name,
                "path": path,
                "base_blob": base_blob,
                "base_sha256": base_digest,
                "head_blob": head_blob,
                "head_sha256": head_digest,
                "execution_source": execution_source,
            }
        )
    return identities


def _required_seals() -> int:
    return REQUIRED_SEALS


def _attest_python_execution(
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item = PYTHON_EXECUTION if execution is None else execution
    try:
        descriptor = item["fd"]
        expected_size = item["size"]
        expected_sha256 = item["sha256"]
    except (KeyError, TypeError):
        raise VerificationError(
            "BOOTSTRAP_PYTHON_EXEC_FD_ATTESTATION_FAILED"
        ) from None
    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(expected_size) is not int
        or type(expected_sha256) is not str
    ):
        raise VerificationError("BOOTSTRAP_PYTHON_EXEC_FD_ATTESTATION_FAILED")
    try:
        before = os.fstat(descriptor)
        contents = _pread_exact(
            descriptor,
            expected_size,
            "BOOTSTRAP_PYTHON_EXEC_FD_ATTESTATION_FAILED",
        )
        after = os.fstat(descriptor)
    except OSError as exc:
        raise VerificationError(
            "BOOTSTRAP_PYTHON_EXEC_FD_ATTESTATION_FAILED"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or _stat_identity(before) != _stat_identity(after)
        or before.st_dev != item.get("device")
        or before.st_ino != item.get("inode")
        or _stat_identity(before) != item.get("identity")
        or before.st_size != expected_size
        or _sha256(contents) != expected_sha256
        or item.get("source") != PINNED_PYTHON_EXECUTION_SOURCE
    ):
        raise VerificationError("BOOTSTRAP_PYTHON_EXEC_FD_ATTESTATION_FAILED")
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": expected_size,
        "sha256": expected_sha256,
        "source": PINNED_PYTHON_EXECUTION_SOURCE,
    }


def _attest_sealed_fd(
    descriptor: int,
    *,
    expected_sha256: str,
    expected_size: int,
) -> dict[str, Any]:
    try:
        before = os.fstat(descriptor)
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        contents = os.pread(descriptor, expected_size + 1, 0)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_SEALED_TOOL_ATTESTATION_FAILED") from exc
    if (
        seals & _required_seals() != _required_seals()
        or not stat.S_ISREG(before.st_mode)
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_size != expected_size
        or len(contents) != expected_size
        or _sha256(contents) != expected_sha256
    ):
        raise VerificationError("BOOTSTRAP_SEALED_TOOL_ATTESTATION_FAILED")
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": expected_size,
        "sha256": expected_sha256,
        "seals": SEALED_EXECUTION_SEALS,
    }


def _create_sealed_tool(contents: bytes, expected_sha256: str, name: str) -> int:
    if not hasattr(os, "memfd_create"):
        raise VerificationError("BOOTSTRAP_SEALED_TOOL_UNAVAILABLE")
    flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
    descriptor: int | None = None
    try:
        descriptor = os.memfd_create(name, flags)
        _write_all(descriptor, contents)
        os.fsync(descriptor)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _required_seals())
        _attest_sealed_fd(
            descriptor,
            expected_sha256=expected_sha256,
            expected_size=len(contents),
        )
        result = descriptor
        descriptor = None
        return result
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_SEALED_TOOL_UNAVAILABLE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _seal_accepted_tools(
    repository_root: Path, base_tree: str
) -> dict[str, dict[str, Any]]:
    sealed: dict[str, dict[str, Any]] = {}
    for path in (VALIDATOR_PATH, REGISTRY_AUDIT_PATH, OWNER_SAFE_SQLITE_PATH):
        _, digest, contents = _blob_identity(repository_root, base_tree, path)
        descriptor = _create_sealed_tool(
            contents, digest, f"twinfinity-accepted-{Path(path).name}"
        )
        sealed[path] = {
            "fd": descriptor,
            "logical_path": path,
            "sha256": digest,
            "size": len(contents),
        }
    return sealed


def _close_sealed_tools(sealed: dict[str, dict[str, Any]]) -> None:
    for item in sealed.values():
        descriptor = item.get("fd")
        if type(descriptor) is int:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _sealed_command(
    command: dict[str, Any],
    base_root: Path,
    head_root: Path,
    sealed: dict[str, dict[str, Any]],
) -> tuple[list[str], tuple[int, ...], list[dict[str, Any]]]:
    canonical = command["argv"]
    if (
        type(canonical) is not list
        or len(canonical) < 3
        or canonical[0] != PYTHON_MANIFEST_TOKEN
        or not canonical[1].startswith("ACCEPTED_BASE/")
    ):
        raise VerificationError("BOOTSTRAP_COMMAND_CATALOG_INVALID")
    tool_path = canonical[1].removeprefix("ACCEPTED_BASE/")
    dependencies = (
        [("owner_safe_sqlite", OWNER_SAFE_SQLITE_PATH)]
        if tool_path == REGISTRY_AUDIT_PATH
        else []
    )
    paths = [tool_path, *(path for _, path in dependencies)]
    if any(path not in sealed for path in paths):
        raise VerificationError("BOOTSTRAP_SEALED_TOOL_ATTESTATION_FAILED")
    bundle: list[dict[str, Any]] = []
    pass_fds: list[int] = []
    for path in paths:
        item = sealed[path]
        _attest_sealed_fd(
            item["fd"],
            expected_sha256=item["sha256"],
            expected_size=item["size"],
        )
        entry = dict(item)
        for module, dependency_path in dependencies:
            if dependency_path == path:
                entry["module"] = module
        bundle.append(entry)
        pass_fds.append(item["fd"])
    arguments = _actual_argv(canonical[2:], base_root, head_root)
    bundle_json = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    python_execution = _attest_python_execution()
    python_bundle = json.dumps(
        {
            "fd": PYTHON_EXECUTION["fd"],
            "sha256": python_execution["sha256"],
            "size": python_execution["size"],
            "identity": PYTHON_EXECUTION["identity"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    actual = [
        PYTHON_EXECUTABLE,
        "-B",
        "-I",
        "-c",
        SEALED_TOOL_LOADER,
        python_bundle,
        bundle_json,
        tool_path,
        *arguments,
    ]
    return actual, (PYTHON_EXECUTION["fd"], *pass_fds), bundle


def _external_identity(name: str, logical_path: str) -> dict[str, Any]:
    logical = Path(logical_path)
    if not logical.is_absolute():
        raise VerificationError("BOOTSTRAP_EXTERNAL_TOOL_MISSING")
    try:
        resolved = logical.resolve(strict=True)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_EXTERNAL_TOOL_MISSING") from exc
    contents, identity = _read_regular_with_identity(
        resolved,
        maximum=1024 * 1024 * 1024,
        error="BOOTSTRAP_EXTERNAL_TOOL_UNSAFE",
        # Restricted user namespaces commonly map host root to overflow uid.
        allowed_uids={0, 65534, os.getuid()},
    )
    try:
        final_resolved = logical.resolve(strict=True)
        final_identity = os.stat(final_resolved, follow_symlinks=False)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_EXTERNAL_TOOL_DRIFT") from exc
    if (
        final_resolved != resolved
        or (final_identity.st_dev, final_identity.st_ino)
        != (identity.st_dev, identity.st_ino)
        or final_identity.st_mode != identity.st_mode
        or final_identity.st_uid != identity.st_uid
        or final_identity.st_gid != identity.st_gid
        or final_identity.st_nlink != identity.st_nlink
        or final_identity.st_size != identity.st_size
        or final_identity.st_mtime_ns != identity.st_mtime_ns
        or final_identity.st_ctime_ns != identity.st_ctime_ns
    ):
        raise VerificationError("BOOTSTRAP_EXTERNAL_TOOL_DRIFT")
    return {
        "name": name,
        "logical_path": logical_path,
        "resolved_path": os.fspath(resolved),
        "sha256": _sha256(contents),
        "size": str(len(contents)),
        "device": str(identity.st_dev),
        "inode": str(identity.st_ino),
        "mode": str(identity.st_mode),
        "uid": str(identity.st_uid),
        "gid": str(identity.st_gid),
        "link_count": str(identity.st_nlink),
        "mtime_ns": str(identity.st_mtime_ns),
        "ctime_ns": str(identity.st_ctime_ns),
    }


def _external_tools() -> list[dict[str, Any]]:
    if _derive_executing_interpreter_path() != PYTHON:
        raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED")
    execution = _attest_python_execution()
    try:
        current_path = os.stat(PYTHON, follow_symlinks=False)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED") from exc
    if (
        current_path.st_dev != execution["device"]
        or current_path.st_ino != execution["inode"]
        or current_path.st_size != execution["size"]
    ):
        raise VerificationError("BOOTSTRAP_PYTHON_IDENTITY_SUBSTITUTED")
    return [
        dict(PYTHON_SOURCE_IDENTITY),
        _external_identity("git", GIT),
    ]


def _command_manifest() -> dict[str, Any]:
    commands: list[dict[str, Any]] = []
    for prefix, root in (("base", "BASE"), ("head", "HEAD")):
        for skill_root in SKILL_ROOTS:
            commands.append(
                {
                    "command_id": f"{prefix}:skill:{skill_root}",
                    "root": root,
                    "kind": "SKILL_VALIDATOR",
                    "argv": [
                        PYTHON_MANIFEST_TOKEN,
                        f"ACCEPTED_BASE/{VALIDATOR_PATH}",
                        f"{root}/{skill_root}",
                    ],
                    "timeout_seconds": COMMAND_TIMEOUT_DECIMAL,
                    "output_limit_bytes": OUTPUT_LIMIT_DECIMAL,
                }
            )
        commands.append(
            {
                "command_id": f"{prefix}:executor-registry-audit",
                "root": root,
                "kind": "EXECUTOR_REGISTRY_AUDIT",
                "argv": [
                    PYTHON_MANIFEST_TOKEN,
                    f"ACCEPTED_BASE/{REGISTRY_AUDIT_PATH}",
                    "--config",
                    f"{root}/{REGISTRY_CONFIG_PATH}",
                    "--profile-root",
                    f"{root}/{REGISTRY_PROFILE_ROOT}",
                    "audit-config",
                ],
                "timeout_seconds": COMMAND_TIMEOUT_DECIMAL,
                "output_limit_bytes": OUTPUT_LIMIT_DECIMAL,
            }
        )
    if len(commands) != 24:
        raise VerificationError("BOOTSTRAP_COMMAND_CATALOG_INVALID")
    return {
        "schema": "twinfinity-harness-bootstrap-command-manifest/v1",
        "commands": commands,
    }


def _raw_tree_entries(
    contents: bytes, *, remaining: int = ENTRY_LIMIT
) -> list[tuple[str, str, str]]:
    if type(remaining) is not int or remaining < 0:
        raise VerificationError("BOOTSTRAP_TREE_ENTRY_LIMIT")
    entries: list[tuple[str, str, str]] = []
    offset = 0
    names: set[str] = set()
    while offset < len(contents):
        if len(entries) >= remaining:
            raise VerificationError("BOOTSTRAP_TREE_ENTRY_LIMIT")
        space = contents.find(b" ", offset)
        nul = contents.find(b"\0", space + 1) if space >= 0 else -1
        if space <= offset or nul < 0 or nul + 21 > len(contents):
            raise VerificationError("BOOTSTRAP_TREE_ENTRY_INVALID")
        raw_mode = contents[offset:space]
        raw_name = contents[space + 1 : nul]
        raw_object = contents[nul + 1 : nul + 21]
        offset = nul + 21
        try:
            mode = raw_mode.decode("ascii")
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError("BOOTSTRAP_TREE_ENTRY_INVALID") from exc
        if (
            mode not in {"40000", "100644", "100755"}
            or not name
            or name in {".", ".."}
            or "/" in name
            or name in names
            or len(raw_name) > 255
        ):
            raise VerificationError("BOOTSTRAP_TREE_ENTRY_UNSAFE")
        names.add(name)
        entries.append((mode, name, raw_object.hex()))
    if offset != len(contents):
        raise VerificationError("BOOTSTRAP_TREE_ENTRY_INVALID")
    return entries


def _extract_tree(
    repository_root: Path, tree: str, destination: Path
) -> dict[str, tuple[str, int, int, str]]:
    destination.mkdir(mode=0o700)
    count = 0
    total = 0
    seen: set[str] = set()
    expected: dict[str, tuple[str, int, int, str]] = {}

    def materialize(tree_id: str, components: tuple[str, ...]) -> None:
        nonlocal count, total
        if len(components) > 128:
            raise VerificationError("BOOTSTRAP_TREE_DEPTH_LIMIT")
        raw_tree = _git_object_bytes(
            repository_root,
            tree_id,
            "tree",
            maximum=ARCHIVE_LIMIT,
            label="TREE",
        )
        for mode, name, object_id in _raw_tree_entries(
            raw_tree, remaining=ENTRY_LIMIT - count
        ):
            count += 1
            if count > ENTRY_LIMIT:
                raise VerificationError("BOOTSTRAP_TREE_ENTRY_LIMIT")
            child_components = (*components, name)
            path = "/".join(child_components)
            if path in seen or len(path.encode("utf-8")) > 4096:
                raise VerificationError("BOOTSTRAP_TREE_ENTRY_UNSAFE")
            seen.add(path)
            target = destination.joinpath(*child_components)
            if mode == "40000":
                expected[path] = ("directory", 0o700, 0, EMPTY_SHA256)
                try:
                    target.mkdir(mode=0o700)
                except OSError as exc:
                    raise VerificationError("BOOTSTRAP_TREE_WRITE_FAILED") from exc
                materialize(object_id, child_components)
                continue
            contents = _git_object_bytes(
                repository_root,
                object_id,
                "blob",
                maximum=EXTRACTED_LIMIT,
                label="TREE_BLOB",
            )
            total += len(contents)
            if total > EXTRACTED_LIMIT:
                raise VerificationError("BOOTSTRAP_TREE_CONTENT_LIMIT")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                file_mode = 0o700 if mode == "100755" else 0o600
                descriptor = os.open(
                    target, flags, file_mode
                )
                try:
                    _write_all(descriptor, contents)
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise VerificationError("BOOTSTRAP_TREE_WRITE_FAILED") from exc
            expected[path] = (
                "file",
                file_mode,
                len(contents),
                _sha256(contents),
            )

    materialize(tree, ())
    return expected


IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
INOTIFY_DIRECTORY_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_UNMOUNT
    | IN_Q_OVERFLOW
    | IN_IGNORED
)
INOTIFY_FILE_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_UNMOUNT
    | IN_Q_OVERFLOW
    | IN_IGNORED
)
INOTIFY_EVENT = struct.Struct("iIII")


def _open_directory_descriptor(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT") from exc


def _snapshot_extracted_tree(
    root_descriptor: int,
) -> dict[str, tuple[str, int, int, str]]:
    observed: dict[str, tuple[str, int, int, str]] = {}
    count = 0
    total = 0

    def scan(directory_fd: int, components: tuple[str, ...]) -> None:
        nonlocal count, total
        try:
            iterator = os.scandir(directory_fd)
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT") from exc
        try:
            with iterator:
                entries = iterator
                for entry in entries:
                    name = entry.name
                    if (
                        not name
                        or name in {".", "..", "__pycache__"}
                        or name.endswith((".pyc", ".pyo"))
                        or "/" in name
                    ):
                        raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
                    count += 1
                    if count > ENTRY_LIMIT:
                        raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
                    child_components = (*components, name)
                    relative = "/".join(child_components)
                    try:
                        lexical = os.stat(
                            name, dir_fd=directory_fd, follow_symlinks=False
                        )
                    except OSError as exc:
                        raise VerificationError(
                            "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                        ) from exc
                    if stat.S_ISDIR(lexical.st_mode):
                        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
                            os, "O_NOFOLLOW", 0
                        )
                        child_fd: int | None = None
                        try:
                            child_fd = os.open(name, flags, dir_fd=directory_fd)
                            pinned = os.fstat(child_fd)
                            if (
                                (
                                    pinned.st_dev,
                                    pinned.st_ino,
                                    pinned.st_mode,
                                    pinned.st_uid,
                                )
                                != (
                                    lexical.st_dev,
                                    lexical.st_ino,
                                    lexical.st_mode,
                                    lexical.st_uid,
                                )
                                or pinned.st_uid != os.getuid()
                                or stat.S_IMODE(pinned.st_mode) != 0o700
                            ):
                                raise VerificationError(
                                    "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                                )
                            observed[relative] = (
                                "directory",
                                0o700,
                                0,
                                EMPTY_SHA256,
                            )
                            scan(child_fd, child_components)
                        except VerificationError:
                            raise
                        except OSError as exc:
                            raise VerificationError(
                                "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                            ) from exc
                        finally:
                            if child_fd is not None:
                                os.close(child_fd)
                        continue
                    if not stat.S_ISREG(lexical.st_mode):
                        raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
                    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
                        os, "O_NONBLOCK", 0
                    )
                    file_fd: int | None = None
                    try:
                        file_fd = os.open(name, flags, dir_fd=directory_fd)
                        before = os.fstat(file_fd)
                        if (
                            not stat.S_ISREG(before.st_mode)
                            or before.st_uid != os.getuid()
                            or before.st_nlink != 1
                            or stat.S_IMODE(before.st_mode) not in {0o600, 0o700}
                            or before.st_size > EXTRACTED_LIMIT - total
                        ):
                            raise VerificationError(
                                "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                            )
                        contents = _pread_exact(
                            file_fd,
                            before.st_size,
                            "BOOTSTRAP_VALIDATION_ROOT_DRIFT",
                        )
                        after = os.fstat(file_fd)
                        current = os.stat(
                            name, dir_fd=directory_fd, follow_symlinks=False
                        )
                        if (
                            _stat_identity(before) != _stat_identity(after)
                            or _stat_identity(before) != _stat_identity(current)
                        ):
                            raise VerificationError(
                                "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                            )
                        total += len(contents)
                        observed[relative] = (
                            "file",
                            stat.S_IMODE(before.st_mode),
                            len(contents),
                            _sha256(contents),
                        )
                    except VerificationError:
                        raise
                    except OSError as exc:
                        raise VerificationError(
                            "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                        ) from exc
                    finally:
                        if file_fd is not None:
                            os.close(file_fd)
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT") from exc

    root = os.fstat(root_descriptor)
    if (
        not stat.S_ISDIR(root.st_mode)
        or root.st_uid != os.getuid()
        or stat.S_IMODE(root.st_mode) != 0o700
    ):
        raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
    scan(root_descriptor, ())
    return observed


class _ValidationRootGuard:
    """Reject every persistent or transient mutation of validation inputs."""

    def __init__(
        self,
        private_root: Path,
        roots: Sequence[tuple[Path, dict[str, tuple[str, int, int, str]]]],
    ) -> None:
        self._fd = -1
        self._private_root = private_root
        self._private_fd = -1
        self._private_identity: tuple[int, ...] = ()
        self._roots: list[
            tuple[Path, int, tuple[int, ...], dict[str, tuple[str, int, int, str]]]
        ] = []
        self._arm_limit = sum(len(expected) for _, expected in roots)
        self._armed_entries = 0
        self._arm_deadline = time.monotonic() + 30.0
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        descriptor = init(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if descriptor < 0:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_GUARD_UNAVAILABLE")
        self._fd = descriptor
        add = libc.inotify_add_watch
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int
        self._inotify_add_watch = add
        try:
            self._private_fd = _open_directory_descriptor(private_root)
            self._private_identity = _stat_identity(os.fstat(self._private_fd))
            self._add_watch(self._private_fd, INOTIFY_DIRECTORY_MASK | IN_ONLYDIR)
            for path, expected in roots:
                root_fd = _open_directory_descriptor(path)
                identity = _stat_identity(os.fstat(root_fd))
                self._roots.append((path, root_fd, identity, expected))
                self._arm_tree(root_fd)
            if self._armed_entries != self._arm_limit:
                raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def _add_watch(self, descriptor: int, mask: int) -> None:
        alias = os.fsencode(f"/proc/self/fd/{descriptor}")
        if self._inotify_add_watch(self._fd, alias, mask) < 0:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_GUARD_UNAVAILABLE")

    def _arm_tree(self, directory_fd: int) -> None:
        self._add_watch(directory_fd, INOTIFY_DIRECTORY_MASK | IN_ONLYDIR)
        try:
            iterator = os.scandir(directory_fd)
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT") from exc
        try:
            with iterator:
                for entry in iterator:
                    self._armed_entries += 1
                    if (
                        self._armed_entries > self._arm_limit
                        or time.monotonic() >= self._arm_deadline
                    ):
                        raise VerificationError(
                            "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                        )
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise VerificationError(
                            "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                        ) from exc
                    if stat.S_ISDIR(metadata.st_mode):
                        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
                            os, "O_NOFOLLOW", 0
                        )
                        child_fd = os.open(
                            entry.name, flags, dir_fd=directory_fd
                        )
                        try:
                            self._arm_tree(child_fd)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(metadata.st_mode):
                        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
                            os, "O_NONBLOCK", 0
                        )
                        file_fd = os.open(
                            entry.name, flags, dir_fd=directory_fd
                        )
                        try:
                            self._add_watch(file_fd, INOTIFY_FILE_MASK)
                        finally:
                            os.close(file_fd)
                    else:
                        raise VerificationError(
                            "BOOTSTRAP_VALIDATION_ROOT_DRIFT"
                        )
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT") from exc

    def check_events(self) -> None:
        if self._fd < 0:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_GUARD_UNAVAILABLE")
        while True:
            try:
                payload = os.read(self._fd, 1024 * 1024)
            except BlockingIOError:
                return
            except InterruptedError:
                continue
            except OSError as exc:
                raise VerificationError(
                    "BOOTSTRAP_VALIDATION_ROOT_GUARD_UNAVAILABLE"
                ) from exc
            if not payload:
                raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_GUARD_UNAVAILABLE")
            offset = 0
            while offset < len(payload):
                if len(payload) - offset < INOTIFY_EVENT.size:
                    raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
                _, _, _, name_length = INOTIFY_EVENT.unpack_from(payload, offset)
                offset += INOTIFY_EVENT.size + name_length
                if offset > len(payload):
                    raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")

    def revalidate(self) -> None:
        self.check_events()
        try:
            if _stat_identity(os.fstat(self._private_fd)) != self._private_identity:
                raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
            lexical_private = _open_directory_descriptor(self._private_root)
            try:
                if _stat_identity(os.fstat(lexical_private)) != self._private_identity:
                    raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
            finally:
                os.close(lexical_private)
            for path, root_fd, identity, expected in self._roots:
                if _stat_identity(os.fstat(root_fd)) != identity:
                    raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
                lexical = _open_directory_descriptor(path)
                try:
                    if _stat_identity(os.fstat(lexical)) != identity:
                        raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
                finally:
                    os.close(lexical)
                if _snapshot_extracted_tree(root_fd) != expected:
                    raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT")
        except VerificationError:
            raise
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_VALIDATION_ROOT_DRIFT") from exc
        self.check_events()

    def close(self) -> None:
        roots, self._roots = self._roots, []
        for _, descriptor, _, _ in roots:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if self._private_fd >= 0:
            try:
                os.close(self._private_fd)
            except OSError:
                pass
            self._private_fd = -1
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    def __enter__(self) -> _ValidationRootGuard:
        return self

    def __exit__(self, exc_type: object, *_: object) -> None:
        try:
            if exc_type is None:
                self.revalidate()
        finally:
            self.close()


def _proc_stat(pid: int) -> tuple[int, int, int] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        closing = raw.rfind(")")
        fields = raw[closing + 2 :].split()
        return int(fields[1]), int(fields[2]), int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def _children_map(
    snapshot: dict[int, tuple[int, int]] | None = None,
) -> dict[int, list[int]]:
    result: dict[int, list[int]] = {}
    try:
        entries = os.scandir("/proc")
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_PROC_UNAVAILABLE") from exc
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            stat_fields = _proc_stat(int(entry.name))
            if stat_fields is None:
                continue
            pid = int(entry.name)
            parent, _, start_time = stat_fields
            result.setdefault(parent, []).append(pid)
            if snapshot is not None:
                snapshot[pid] = (parent, start_time)
    return result


def _descendants(root_pid: int, mapping: dict[int, list[int]]) -> set[int]:
    found: set[int] = set()
    pending = [root_pid]
    while pending:
        parent = pending.pop()
        for child in mapping.get(parent, []):
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def _enable_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise VerificationError("BOOTSTRAP_SUBREAPER_UNAVAILABLE")


def _same_process(pid: int, start_time: int) -> bool:
    current = _proc_stat(pid)
    return current is not None and current[2] == start_time


def _capture_pidfd(pid: int, start_time: int) -> int | None:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise VerificationError("BOOTSTRAP_PID_IDENTITY_UNAVAILABLE")
    try:
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return None
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_PID_IDENTITY_UNAVAILABLE") from exc
    current = _proc_stat(pid)
    if current is None or current[2] != start_time:
        os.close(descriptor)
        return None
    return descriptor


def _snapshot_descendant_stable(
    pid: int,
    root_pid: int,
    root_start_time: int,
    snapshot: dict[int, tuple[int, int]],
) -> bool:
    current = pid
    seen: set[int] = set()
    while current != root_pid:
        if current in seen:
            return False
        seen.add(current)
        identity = snapshot.get(current)
        if identity is None:
            return False
        parent = identity[0]
        if parent == root_pid:
            return _same_process(root_pid, root_start_time)
        parent_identity = snapshot.get(parent)
        if parent_identity is None or not _same_process(
            parent, parent_identity[1]
        ):
            return False
        current = parent
    return _same_process(root_pid, root_start_time)


def _remember_processes(
    root_pid: int,
    root_start_time: int | None,
    baseline_children: dict[int, int],
    known: dict[int, tuple[int, int]],
) -> None:
    root_matches_before = (
        root_start_time is not None and _same_process(root_pid, root_start_time)
    )
    snapshot: dict[int, tuple[int, int]] = {}
    mapping = _children_map(snapshot)
    root_matches_after = (
        root_matches_before
        and root_start_time is not None
        and _same_process(root_pid, root_start_time)
    )
    candidates: dict[int, tuple[int, bool]] = {}
    if root_matches_after and root_start_time is not None:
        candidates[root_pid] = (root_start_time, True)
        for descendant in _descendants(root_pid, mapping):
            identity = snapshot.get(descendant)
            if identity is not None:
                candidates[descendant] = (identity[1], True)
    for child in mapping.get(os.getpid(), []):
        identity = snapshot.get(child)
        if identity is not None and baseline_children.get(child) != identity[1]:
            candidates[child] = (identity[1], False)
    for pid, (expected_start_time, root_descendant) in candidates.items():
        if pid == os.getpid():
            continue
        existing = known.get(pid)
        if existing is not None:
            if existing[0] == expected_start_time or _pidfd_alive(existing[1]):
                continue
            try:
                os.close(existing[1])
            except OSError:
                pass
            del known[pid]
        if root_descendant and pid != root_pid and (
            root_start_time is None
            or not _snapshot_descendant_stable(
                pid, root_pid, root_start_time, snapshot
            )
        ):
            continue
        descriptor = _capture_pidfd(pid, expected_start_time)
        if descriptor is not None:
            known[pid] = (expected_start_time, descriptor)


def _signal_known(known: dict[int, tuple[int, int]], signum: int) -> None:
    for _, (_, descriptor) in sorted(known.items(), reverse=True):
        if not _pidfd_alive(descriptor):
            continue
        try:
            signal.pidfd_send_signal(descriptor, signum)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            raise VerificationError("BOOTSTRAP_DESCENDANT_SIGNAL_DENIED") from exc


def _pidfd_alive(descriptor: int) -> bool:
    poller = select.poll()
    try:
        poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
        return not bool(poller.poll(0))
    except OSError:
        return False
    finally:
        try:
            poller.unregister(descriptor)
        except (KeyError, OSError):
            pass


def _close_known_processes(known: dict[int, tuple[int, int]]) -> None:
    for _, descriptor in known.values():
        try:
            os.close(descriptor)
        except OSError:
            pass
    known.clear()


def _baseline_children() -> dict[int, int]:
    baseline: dict[int, int] = {}
    snapshot: dict[int, tuple[int, int]] = {}
    mapping = _children_map(snapshot)
    for pid in mapping.get(os.getpid(), []):
        identity = snapshot.get(pid)
        if identity is not None:
            baseline[pid] = identity[1]
    return baseline


def _signal_process_group(
    process: subprocess.Popen[bytes], root_start_time: int | None, signum: int
) -> None:
    if root_start_time is None or process.returncode is not None:
        return
    fields = _proc_stat(process.pid)
    if (
        fields is None
        or fields[2] != root_start_time
        or fields[1] != process.pid
    ):
        return
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        raise VerificationError("BOOTSTRAP_DESCENDANT_SIGNAL_DENIED") from exc


def _reap_adopted(
    root_pid: int,
    root_start_time: int | None,
    known: dict[int, tuple[int, int]],
) -> None:
    for pid, identity in tuple(known.items()):
        if (pid, identity[0]) == (root_pid, root_start_time):
            continue
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, ProcessLookupError):
            pass


def _cleanup_processes(
    process: subprocess.Popen[bytes],
    baseline_children: dict[int, int],
    known: dict[int, tuple[int, int]],
    root_start_time: int | None,
) -> bool:
    """Terminate, reap, and stably disprove every attributable descendant."""

    root_pid = process.pid

    def live_descendants() -> bool:
        return any(
            (pid, identity[0]) != (root_pid, root_start_time)
            and _pidfd_alive(identity[1])
            for pid, identity in known.items()
        )

    _remember_processes(root_pid, root_start_time, baseline_children, known)
    _signal_process_group(process, root_start_time, signal.SIGTERM)
    _signal_known(known, signal.SIGTERM)
    term_deadline = time.monotonic() + 0.25
    while time.monotonic() < term_deadline:
        process.poll()
        _remember_processes(root_pid, root_start_time, baseline_children, known)
        _signal_process_group(process, root_start_time, signal.SIGTERM)
        _signal_known(known, signal.SIGTERM)
        _reap_adopted(root_pid, root_start_time, known)
        if process.poll() is not None and not live_descendants():
            break
        time.sleep(0.01)

    _remember_processes(root_pid, root_start_time, baseline_children, known)
    _signal_process_group(process, root_start_time, signal.SIGKILL)
    _signal_known(known, signal.SIGKILL)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        return False

    # Reaping the subreaper's root may adopt a descendant that escaped its
    # session immediately before exit.  Require several consecutive empty
    # observations after root reaping, killing and reaping anything that
    # appears between observations.
    stable_empty = 0
    kill_deadline = time.monotonic() + 1.0
    while time.monotonic() < kill_deadline:
        _remember_processes(root_pid, root_start_time, baseline_children, known)
        _signal_known(known, signal.SIGKILL)
        _reap_adopted(root_pid, root_start_time, known)
        _remember_processes(root_pid, root_start_time, baseline_children, known)
        if live_descendants():
            stable_empty = 0
        else:
            stable_empty += 1
            if stable_empty >= 3:
                return True
        time.sleep(0.001)
    return False


def _drain_ready(
    selector: selectors.BaseSelector,
    buffers: dict[str, bytearray],
    limit: int,
) -> bool:
    limited = False
    for key, _ in selector.select(timeout=0.01):
        stream = key.fileobj
        try:
            chunk = os.read(stream.fileno(), 65536)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(stream)
            stream.close()
            continue
        target = buffers[key.data]
        remaining = max(0, limit - len(target))
        target.extend(chunk[:remaining])
        if len(chunk) > remaining:
            limited = True
    if sum(len(value) for value in buffers.values()) > limit:
        limited = True
    return limited


def _run_bounded(
    actual_argv: Sequence[str],
    *,
    canonical_command: dict[str, Any],
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float | None = None,
    output_limit_bytes: int | None = None,
    pass_fds: Sequence[int] = (),
    sealed_bundle: Sequence[dict[str, Any]] = (),
    python_execution: dict[str, Any] | None = None,
    input_guard: Callable[[], None] | None = None,
) -> dict[str, Any]:
    _enable_subreaper()
    timeout_value = (
        float(canonical_command["timeout_seconds"])
        if timeout_seconds is None
        else timeout_seconds
    )
    limit = (
        int(canonical_command["output_limit_bytes"])
        if output_limit_bytes is None
        else output_limit_bytes
    )
    baseline = _baseline_children()
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    known: dict[int, tuple[int, int]] = {}
    root_start_time: int | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    cleanup_verified = False
    try:
        if input_guard is not None:
            input_guard()
        if python_execution is not None:
            python_identity = _attest_python_execution(python_execution)
            python_fd = python_execution["fd"]
            if (
                python_fd not in pass_fds
                or not actual_argv
                or actual_argv[0] != f"/proc/self/fd/{python_fd}"
            ):
                raise VerificationError(
                    "BOOTSTRAP_PYTHON_EXEC_FD_ATTESTATION_FAILED"
                )
        else:
            python_identity = None
        for item in sealed_bundle:
            _attest_sealed_fd(
                item["fd"],
                expected_sha256=item["sha256"],
                expected_size=item["size"],
            )
        process = subprocess.Popen(
            list(actual_argv),
            executable=(
                f"/proc/self/fd/{python_execution['fd']}"
                if python_execution is not None
                else None
            ),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            pass_fds=tuple(pass_fds),
        )
        root_fields = _proc_stat(process.pid)
        if root_fields is not None:
            root_start_time = root_fields[2]
        elif process.poll() is None:
            raise VerificationError("BOOTSTRAP_PID_IDENTITY_UNAVAILABLE")
        if process.stdout is None or process.stderr is None:
            raise VerificationError("BOOTSTRAP_VALIDATOR_PIPE_SETUP_FAILED")
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        started = time.monotonic()
        timed_out = False
        output_limited = False
        while process.poll() is None:
            if input_guard is not None:
                input_guard()
            _remember_processes(process.pid, root_start_time, baseline, known)
            output_limited = (
                _drain_ready(selector, buffers, limit) or output_limited
            )
            if time.monotonic() - started >= timeout_value:
                timed_out = True
            if timed_out or output_limited:
                break
        _remember_processes(process.pid, root_start_time, baseline, known)
        if input_guard is not None:
            input_guard()
        cleanup_verified = _cleanup_processes(
            process, baseline, known, root_start_time
        )
        if input_guard is not None:
            input_guard()
        if python_execution is not None:
            if _attest_python_execution(python_execution) != python_identity:
                raise VerificationError(
                    "BOOTSTRAP_PYTHON_EXEC_FD_ATTESTATION_FAILED"
                )
        for item in sealed_bundle:
            _attest_sealed_fd(
                item["fd"],
                expected_sha256=item["sha256"],
                expected_size=item["size"],
            )
        descendants_detected = any(
            (pid, identity[0]) != (process.pid, root_start_time)
            for pid, identity in known.items()
        )
        drain_deadline = time.monotonic() + 1.0
        while selector.get_map() and time.monotonic() < drain_deadline:
            output_limited = (
                _drain_ready(selector, buffers, limit) or output_limited
            )
        if selector.get_map():
            cleanup_verified = False
        return_code = process.returncode
        if type(return_code) is not int or return_code < -255 or return_code > 255:
            return_code = -255
        observation = dict(canonical_command)
        observation.update(
            {
                "execution_source": (
                    SEALED_EXECUTION_SOURCE if sealed_bundle else "UNSEALED_TEST_ONLY"
                ),
                "execution_seals": (
                    SEALED_EXECUTION_SEALS if sealed_bundle else "NONE"
                ),
                "executed_tool_sha256": (
                    sealed_bundle[0]["sha256"] if sealed_bundle else EMPTY_SHA256
                ),
                "executed_dependency_sha256": (
                    sealed_bundle[1]["sha256"]
                    if len(sealed_bundle) > 1
                    else EMPTY_SHA256
                ),
                "executed_python_source": (
                    python_identity["source"]
                    if python_identity is not None
                    else "UNSEALED_TEST_ONLY"
                ),
                "executed_python_sha256": (
                    python_identity["sha256"]
                    if python_identity is not None
                    else EMPTY_SHA256
                ),
                "exit_code": return_code,
                "timed_out": timed_out,
                "output_limited": output_limited,
                "descendants_detected": descendants_detected,
                "cleanup_verified": cleanup_verified,
                "stdout_bytes": str(len(buffers["stdout"])),
                "stdout_sha256": _sha256(bytes(buffers["stdout"])),
                "stderr_bytes": str(len(buffers["stderr"])),
                "stderr_sha256": _sha256(bytes(buffers["stderr"])),
            }
        )
        observation["exit_code"] = str(return_code)
        return observation
    finally:
        if process is not None and not cleanup_verified:
            try:
                _remember_processes(process.pid, root_start_time, baseline, known)
                _cleanup_processes(process, baseline, known, root_start_time)
            except Exception:
                _signal_process_group(process, root_start_time, signal.SIGKILL)
                _signal_known(known, signal.SIGKILL)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # Popen still owns an unreaped direct child here, so this
                # handle cannot name a recycled unrelated process.
                process.kill()
                process.wait(timeout=1)
        if process is not None and process.poll() is None:
            _signal_process_group(process, root_start_time, signal.SIGKILL)
            _signal_known(known, signal.SIGKILL)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        if selector is not None:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except Exception:
                    pass
                key.fileobj.close()
            selector.close()
        _close_known_processes(known)
        if python_execution is not None:
            _attest_python_execution(python_execution)


def _actual_argv(
    canonical: Sequence[str], base_root: Path, head_root: Path
) -> list[str]:
    resolved: list[str] = []
    for argument in canonical:
        if argument.startswith("ACCEPTED_BASE/"):
            resolved.append(os.fspath(base_root / argument.removeprefix("ACCEPTED_BASE/")))
        elif argument.startswith("BASE/"):
            resolved.append(os.fspath(base_root / argument.removeprefix("BASE/")))
        elif argument.startswith("HEAD/"):
            resolved.append(os.fspath(head_root / argument.removeprefix("HEAD/")))
        else:
            resolved.append(argument)
    return resolved


def _validation_environment(private_root: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(private_root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": os.fspath(private_root),
    }


def _execute_observations(
    repository_root: Path,
    base_tree: str,
    head_tree: str,
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    old_umask = os.umask(0o077)
    sealed: dict[str, dict[str, Any]] = {}
    try:
        sealed = _seal_accepted_tools(repository_root, base_tree)
        with tempfile.TemporaryDirectory(prefix="twinfinity-bootstrap-verifier-") as root:
            private = Path(root)
            private.chmod(0o700)
            scratch_root = private / "scratch"
            scratch_root.mkdir(mode=0o700)
            base_root = private / "base"
            head_root = private / "head"
            base_expected = _extract_tree(repository_root, base_tree, base_root)
            head_expected = _extract_tree(repository_root, head_tree, head_root)
            environment = _validation_environment(scratch_root)
            observations: list[dict[str, Any]] = []
            with _ValidationRootGuard(
                private,
                ((base_root, base_expected), (head_root, head_expected)),
            ) as input_guard:
                for command in manifest["commands"]:
                    input_guard.revalidate()
                    cwd = base_root if command["root"] == "BASE" else head_root
                    actual, pass_fds, bundle = _sealed_command(
                        command, base_root, head_root, sealed
                    )
                    observation = _run_bounded(
                        actual,
                        canonical_command=command,
                        cwd=cwd,
                        environment=environment,
                        pass_fds=pass_fds,
                        sealed_bundle=bundle,
                        python_execution=PYTHON_EXECUTION,
                        input_guard=input_guard.check_events,
                    )
                    input_guard.revalidate()
                    observations.append(observation)
                    if (
                        observation["exit_code"] != "0"
                        or observation["timed_out"]
                        or observation["output_limited"]
                        or not observation["cleanup_verified"]
                    ):
                        raise VerificationError(
                            "BOOTSTRAP_INDEPENDENT_VALIDATION_FAILED"
                        )
                input_guard.revalidate()
                return observations
    finally:
        _close_sealed_tools(sealed)
        os.umask(old_umask)


def _prepare_evidence(
    direct_packet: Path,
    expected_packet_sha256: str,
) -> dict[str, Any]:
    packet = _load_direct_packet(direct_packet, expected_packet_sha256)
    repository = _resolve_repository(Path(packet["worktree_path"]))
    repository_identity = _repository_state_identity(repository)
    branch_ref = f"refs/heads/{packet['branch']}"
    head_sha = _git(
        repository, ("show-ref", "--verify", "--hash", branch_ref)
    ).stdout.decode("ascii").strip()
    _require_sha(head_sha, SHA1, "BOOTSTRAP_HEAD_SHA_INVALID")
    base_sha = packet["base_sha"]
    reference_identity = _require_frozen_refs(
        repository, base_sha, head_sha, packet["branch"]
    )
    base = _resolve_commit(repository, base_sha, "BASE")
    if base["tree"] != packet["base_tree"]:
        raise VerificationError("BOOTSTRAP_BASE_TREE_PACKET_MISMATCH")
    head_tree, head_parents = _raw_commit(repository, head_sha, "HEAD")
    if head_parents != (base_sha,):
        raise VerificationError("BOOTSTRAP_HEAD_PARENT_SET_INVALID")
    head = {"commit": head_sha, "tree": head_tree}
    _require_issue92_post_merge_git_bindings(
        repository,
        packet,
        head_sha=head_sha,
        head_tree=head_tree,
        head_parents=head_parents,
        reference_identity=reference_identity,
    )
    _require_proper_ancestry(repository, base_sha, head_sha)
    _require_packet_git_scope(
        repository,
        base["tree"],
        base_sha,
        head_sha,
        packet,
    )
    tools = _tool_identities(repository, base["tree"], head["tree"])
    external = _external_tools()
    manifest = _command_manifest()
    return {
        "repository_root": repository,
        "repository_identity": repository_identity,
        "reference_identity": reference_identity,
        "packet": packet,
        "base": base,
        "head": head,
        "tool_identities": tools,
        "external_tools": external,
        "command_manifest": manifest,
        "command_manifest_sha256": _sha256(_canonical_bytes(manifest)),
    }


OBSERVATION_KEYS = {
    "command_id", "root", "kind", "argv", "timeout_seconds",
    "output_limit_bytes", "exit_code", "timed_out", "output_limited",
    "descendants_detected", "cleanup_verified", "stdout_bytes",
    "stdout_sha256", "stderr_bytes", "stderr_sha256", "execution_source",
    "execution_seals", "executed_tool_sha256", "executed_dependency_sha256",
    "executed_python_source", "executed_python_sha256",
}
CANDIDATE_KEYS = {
    "schema", "repository", "issue_number", "packet_sha256", "base", "head",
    "tool_identities", "external_tools", "command_manifest",
    "command_manifest_sha256", "observations", "verdict", "evidence_scope",
}


def _validate_observation_shape(value: Any) -> None:
    item = _require_exact_keys(value, OBSERVATION_KEYS, "BOOTSTRAP_CANDIDATE_OBSERVATION_SCHEMA")
    if (
        type(item["command_id"]) is not str
        or type(item["root"]) is not str
        or type(item["kind"]) is not str
        or type(item["argv"]) is not list
        or not (3 <= len(item["argv"]) <= 7)
        or any(type(arg) is not str or not arg or len(arg) > 500 for arg in item["argv"])
        or item["timeout_seconds"] != COMMAND_TIMEOUT_DECIMAL
        or item["output_limit_bytes"] != OUTPUT_LIMIT_DECIMAL
        or item["execution_source"] != SEALED_EXECUTION_SOURCE
        or item["execution_seals"] != SEALED_EXECUTION_SEALS
        or item["executed_python_source"] != PINNED_PYTHON_EXECUTION_SOURCE
        or item["exit_code"] != "0"
        or any(type(item[key]) is not bool for key in (
            "timed_out", "output_limited", "descendants_detected", "cleanup_verified"
        ))
        or item["timed_out"]
        or item["output_limited"]
        or not item["cleanup_verified"]
    ):
        raise VerificationError("BOOTSTRAP_CANDIDATE_OBSERVATION_TYPE")
    _require_decimal(
        item["stdout_bytes"],
        minimum=0,
        maximum=OUTPUT_LIMIT,
        error="BOOTSTRAP_CANDIDATE_OBSERVATION_TYPE",
    )
    _require_decimal(
        item["stderr_bytes"],
        minimum=0,
        maximum=OUTPUT_LIMIT,
        error="BOOTSTRAP_CANDIDATE_OBSERVATION_TYPE",
    )
    _require_sha(item["stdout_sha256"], SHA256, "BOOTSTRAP_CANDIDATE_OBSERVATION_DIGEST")
    _require_sha(item["stderr_sha256"], SHA256, "BOOTSTRAP_CANDIDATE_OBSERVATION_DIGEST")
    _require_sha(
        item["executed_tool_sha256"],
        SHA256,
        "BOOTSTRAP_CANDIDATE_OBSERVATION_DIGEST",
    )
    _require_sha(
        item["executed_dependency_sha256"],
        SHA256,
        "BOOTSTRAP_CANDIDATE_OBSERVATION_DIGEST",
    )
    _require_sha(
        item["executed_python_sha256"],
        SHA256,
        "BOOTSTRAP_CANDIDATE_OBSERVATION_DIGEST",
    )


def _load_candidate(path: Path) -> tuple[dict[str, Any], str]:
    raw = _read_regular(
        path, maximum=16 * 1024 * 1024,
        error="BOOTSTRAP_CANDIDATE_RECEIPT_UNSAFE",
    )
    parsed = _load_json_object(
        raw,
        "BOOTSTRAP_CANDIDATE_RECEIPT_INVALID_JSON",
        reject_floats=False,
    )
    try:
        canonical = _canonical_bytes(parsed)
    except (RecursionError, OverflowError, TypeError, ValueError) as exc:
        raise VerificationError("BOOTSTRAP_CANDIDATE_RECEIPT_INVALID_JSON") from exc
    if canonical != raw:
        raise VerificationError("BOOTSTRAP_CANDIDATE_RECEIPT_NOT_CANONICAL")
    return parsed, _sha256(raw)


def _validate_candidate_static(
    candidate: Any,
    *,
    issue_number: int,
    packet_sha256: str,
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    item = _require_exact_keys(candidate, CANDIDATE_KEYS, "BOOTSTRAP_CANDIDATE_SCHEMA")
    expected = {
        "schema": "twinfinity-harness-baseline-candidate-receipt/v1",
        "repository": REPOSITORY,
        "issue_number": str(issue_number),
        "packet_sha256": packet_sha256,
        "base": evidence["base"],
        "head": evidence["head"],
        "tool_identities": evidence["tool_identities"],
        "external_tools": evidence["external_tools"],
        "command_manifest": evidence["command_manifest"],
        "command_manifest_sha256": evidence["command_manifest_sha256"],
        "verdict": "PASS",
        "evidence_scope": EVIDENCE_SCOPE,
    }
    for key, value in expected.items():
        if not _strict_equal(item.get(key), value):
            raise VerificationError("BOOTSTRAP_CANDIDATE_IDENTITY_OR_MANIFEST_MISMATCH")
    observations = item["observations"]
    if type(observations) is not list or len(observations) != 24:
        raise VerificationError("BOOTSTRAP_CANDIDATE_OBSERVATIONS_INVALID")
    for observation in observations:
        _validate_observation_shape(observation)
    return observations


def _open_output_directory(path: Path) -> tuple[int, str]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    name = absolute.name
    if (
        not name
        or name in {".", ".."}
        or len(name.encode("utf-8")) > 128
    ):
        raise VerificationError("BOOTSTRAP_RECEIPT_PARENT_UNSAFE")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open("/", flags)
        for component in absolute.parent.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_PARENT_UNSAFE")
        result = descriptor
        descriptor = None
        return result, name
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_PARENT_UNSAFE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _revalidate_output_parent(
    path: Path,
    pinned_descriptor: int,
    pinned_identity: os.stat_result,
) -> None:
    reopened: int | None = None
    try:
        reopened, target = _open_output_directory(path)
        current = os.fstat(reopened)
        pinned = os.fstat(pinned_descriptor)
        if (
            target != Path(os.path.abspath(os.fspath(path))).name
            or current.st_dev != pinned_identity.st_dev
            or current.st_ino != pinned_identity.st_ino
            or current.st_uid != pinned_identity.st_uid
            or current.st_mode != pinned_identity.st_mode
            or pinned.st_dev != pinned_identity.st_dev
            or pinned.st_ino != pinned_identity.st_ino
            or pinned.st_uid != pinned_identity.st_uid
            or pinned.st_mode != pinned_identity.st_mode
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_PARENT_UNSAFE")
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_PARENT_UNSAFE") from exc
    finally:
        if reopened is not None:
            os.close(reopened)


def _read_receipt_at(
    directory_fd: int,
    name: str,
    *,
    allowed_links: set[int],
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink not in allowed_links
            or before.st_size > 16 * 1024 * 1024
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        chunks: list[bytes] = []
        remaining = 16 * 1024 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc
        stable = (
            before.st_dev == after.st_dev == entry.st_dev
            and before.st_ino == after.st_ino == entry.st_ino
            and before.st_mode == after.st_mode == entry.st_mode
            and before.st_uid == after.st_uid == entry.st_uid
            and before.st_nlink == after.st_nlink == entry.st_nlink
            and before.st_size == after.st_size == entry.st_size == len(contents)
            and before.st_mtime_ns == after.st_mtime_ns == entry.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns == entry.st_ctime_ns
            and len(contents) <= 16 * 1024 * 1024
        )
        if not stable:
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        return contents, after
    finally:
        os.close(descriptor)


def _matching_crash_temporary(
    directory_fd: int,
    target: str,
    metadata: os.stat_result,
) -> str:
    prefix = f".{target}.tmp."
    matches: list[str] = []
    deadline = time.monotonic() + RECEIPT_DIRECTORY_SCAN_SECONDS
    observed = 0
    try:
        iterator = os.scandir(directory_fd)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc
    try:
        with iterator:
            for entry in iterator:
                observed += 1
                if (
                    observed > RECEIPT_DIRECTORY_ENTRY_LIMIT
                    or time.monotonic() >= deadline
                ):
                    raise VerificationError(
                        "BOOTSTRAP_RECEIPT_DIRECTORY_SCAN_LIMIT"
                    )
                name = entry.name
                if not name.startswith(prefix):
                    continue
                try:
                    item = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise VerificationError(
                        "BOOTSTRAP_RECEIPT_CONFLICT"
                    ) from exc
                if item.st_dev == metadata.st_dev and item.st_ino == metadata.st_ino:
                    matches.append(name)
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc
    if len(matches) != 1:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
    return matches[0]


def _temporary_owner_active(target: str, temporary: str) -> bool:
    prefix = f".{target}.tmp."
    if not temporary.startswith(prefix):
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
    identity = temporary.removeprefix(prefix).split(".")
    if len(identity) != 5 or any(not item.isdigit() for item in identity):
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
    pid, start_time, native_thread, _, _ = map(int, identity)
    if pid <= 0 or start_time <= 0 or native_thread <= 0:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
    if not _same_process(pid, start_time):
        return False
    try:
        os.stat(f"/proc/{pid}/task/{native_thread}")
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc
    return _same_process(pid, start_time)


def _existing_receipt_at(
    directory_fd: int,
    target: str,
    expected: bytes,
) -> bool:
    deadline = time.monotonic() + RECEIPT_DIRECTORY_SCAN_SECONDS
    while True:
        try:
            existing, metadata = _read_receipt_at(
                directory_fd, target, allowed_links={1, 2}
            )
        except FileNotFoundError:
            return False
        except VerificationError:
            try:
                current = os.stat(
                    target, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc
            if (
                stat.S_ISREG(current.st_mode)
                and stat.S_IMODE(current.st_mode) == 0o600
                and current.st_uid == os.getuid()
                and current.st_nlink in {1, 2}
                and time.monotonic() < deadline
            ):
                time.sleep(0.001)
                continue
            raise
        if existing != expected:
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        if metadata.st_nlink == 1:
            return True
        try:
            temporary = _matching_crash_temporary(directory_fd, target, metadata)
        except VerificationError:
            # A concurrent identical writer may have completed the unlink
            # after our stable two-link read.  Accept only the same inode after
            # a fresh exact one-link read; an unexplained hard link still fails.
            try:
                recovered, final = _read_receipt_at(
                    directory_fd, target, allowed_links={1}
                )
            except FileNotFoundError:
                return False
            except VerificationError:
                if time.monotonic() < deadline:
                    time.sleep(0.001)
                    continue
                raise
            if (
                recovered == expected
                and final.st_dev == metadata.st_dev
                and final.st_ino == metadata.st_ino
            ):
                return True
            raise
        if _temporary_owner_active(target, temporary):
            if time.monotonic() >= deadline:
                raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
            time.sleep(0.001)
            continue
        _unlink_owned_temporary(
            directory_fd, temporary, metadata.st_dev, metadata.st_ino
        )
        os.fsync(directory_fd)
        recovered, final = _read_receipt_at(
            directory_fd, target, allowed_links={1}
        )
        if (
            recovered != expected
            or final.st_dev != metadata.st_dev
            or final.st_ino != metadata.st_ino
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        return True


def _unlink_owned_temporary(
    directory_fd: int,
    name: str,
    device: int,
    inode: int,
) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc
    if metadata.st_dev != device or metadata.st_ino != inode:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT") from exc


def _write_all(descriptor: int, contents: bytes) -> None:
    remaining = memoryview(contents)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED")
        remaining = remaining[written:]


def _write_atomic_receipt(
    path: Path,
    contents: bytes,
    *,
    publication_guard: Callable[[], None] | None = None,
) -> None:
    if len(contents) > 16 * 1024 * 1024:
        raise VerificationError("BOOTSTRAP_RECEIPT_TOO_LARGE")
    directory_fd, target = _open_output_directory(path)
    directory_identity = os.fstat(directory_fd)
    temporary: str | None = None
    temporary_identity: tuple[int, int] | None = None
    published = False
    completed = False

    def guard() -> None:
        _revalidate_output_parent(path, directory_fd, directory_identity)
        if publication_guard is not None:
            publication_guard()
        _revalidate_output_parent(path, directory_fd, directory_identity)

    def require_target(
        identity: tuple[int, int] | None = None,
    ) -> tuple[int, int]:
        final_contents, final_metadata = _read_receipt_at(
            directory_fd, target, allowed_links={1}
        )
        observed_identity = (final_metadata.st_dev, final_metadata.st_ino)
        if final_contents != contents or (
            identity is not None and observed_identity != identity
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        return observed_identity

    def require_durable_target(identity: tuple[int, int]) -> None:
        _revalidate_output_parent(path, directory_fd, directory_identity)
        require_target(identity)
        _revalidate_output_parent(path, directory_fd, directory_identity)

    try:
        guard()
        if _existing_receipt_at(directory_fd, target, contents):
            existing_identity = require_target()
            guard()
            require_durable_target(existing_identity)
            completed = True
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        process_identity = _proc_stat(os.getpid())
        if process_identity is None:
            raise VerificationError("BOOTSTRAP_PID_IDENTITY_UNAVAILABLE")
        for attempt in range(16):
            temporary = (
                f".{target}.tmp.{os.getpid()}.{process_identity[2]}."
                f"{threading.get_native_id()}."
                f"{time.monotonic_ns()}.{attempt}"
            )
            try:
                descriptor = os.open(
                    temporary, flags, 0o600, dir_fd=directory_fd
                )
                break
            except FileExistsError:
                continue
        else:
            raise VerificationError("BOOTSTRAP_RECEIPT_TEMPORARY_COLLISION")
        try:
            try:
                metadata = os.fstat(descriptor)
            except OSError as exc:
                try:
                    fallback = os.stat(f"/proc/self/fd/{descriptor}")
                except OSError as fallback_exc:
                    raise VerificationError(
                        "BOOTSTRAP_RECEIPT_WRITE_FAILED"
                    ) from fallback_exc
                temporary_identity = (fallback.st_dev, fallback.st_ino)
                raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED") from exc
            temporary_identity = (metadata.st_dev, metadata.st_ino)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_size != 0
            ):
                raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED")
            _write_all(descriptor, contents)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_size != len(contents)
                or (metadata.st_dev, metadata.st_ino) != temporary_identity
            ):
                raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED")
        except VerificationError:
            raise
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED") from exc
        finally:
            os.close(descriptor)

        guard()
        try:
            os.link(
                temporary,
                target,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if temporary_identity is None:
                raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED")
            _unlink_owned_temporary(
                directory_fd, temporary, *temporary_identity
            )
            temporary = None
            os.fsync(directory_fd)
            if not _existing_receipt_at(directory_fd, target, contents):
                raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
            existing_identity = require_target()
            guard()
            require_durable_target(existing_identity)
            completed = True
            return
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED") from exc

        published = True
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED") from exc
        guard()
        if temporary_identity is None:
            raise VerificationError("BOOTSTRAP_RECEIPT_WRITE_FAILED")
        linked_contents, linked = _read_receipt_at(
            directory_fd, target, allowed_links={2}
        )
        if (
            linked_contents != contents
            or (linked.st_dev, linked.st_ino) != temporary_identity
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        guard()
        guarded_contents, guarded = _read_receipt_at(
            directory_fd, target, allowed_links={1, 2}
        )
        if (
            guarded_contents != contents
            or (guarded.st_dev, guarded.st_ino) != temporary_identity
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        _unlink_owned_temporary(directory_fd, temporary, *temporary_identity)
        temporary = None
        os.fsync(directory_fd)
        final_contents, final = _read_receipt_at(
            directory_fd, target, allowed_links={1}
        )
        if (
            final_contents != contents
            or (final.st_dev, final.st_ino) != temporary_identity
        ):
            raise VerificationError("BOOTSTRAP_RECEIPT_CONFLICT")
        require_durable_target(temporary_identity)
        completed = True
    finally:
        try:
            parent_unsafe = False
            try:
                final_directory = os.fstat(directory_fd)
                parent_unsafe = (
                    final_directory.st_dev != directory_identity.st_dev
                    or final_directory.st_ino != directory_identity.st_ino
                    or final_directory.st_uid != directory_identity.st_uid
                    or final_directory.st_mode != directory_identity.st_mode
                )
            except OSError:
                parent_unsafe = True
            if parent_unsafe:
                completed = False
            cleanup_error: VerificationError | None = None
            if not completed and published and temporary_identity is not None:
                try:
                    _unlink_owned_temporary(
                        directory_fd, target, *temporary_identity
                    )
                    published = False
                except VerificationError as exc:
                    cleanup_error = exc
            if temporary is not None and temporary_identity is None:
                try:
                    metadata = os.stat(
                        temporary, dir_fd=directory_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    temporary = None
                except OSError as exc:
                    cleanup_error = VerificationError(
                        "BOOTSTRAP_RECEIPT_CONFLICT"
                    )
                else:
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or metadata.st_nlink != 1
                    ):
                        cleanup_error = VerificationError(
                            "BOOTSTRAP_RECEIPT_CONFLICT"
                        )
                    else:
                        temporary_identity = (metadata.st_dev, metadata.st_ino)
            if temporary is not None and temporary_identity is not None:
                try:
                    _unlink_owned_temporary(
                        directory_fd, temporary, *temporary_identity
                    )
                    temporary = None
                except VerificationError as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            try:
                os.fsync(directory_fd)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = VerificationError(
                        "BOOTSTRAP_RECEIPT_WRITE_FAILED"
                    )
            if parent_unsafe:
                raise VerificationError("BOOTSTRAP_RECEIPT_PARENT_UNSAFE")
            if cleanup_error is not None:
                raise cleanup_error
        finally:
            os.close(directory_fd)


def _verify_with_context(
    *,
    direct_packet: Path,
    expected_packet_sha256: str,
    candidate_receipt: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    evidence = _prepare_evidence(direct_packet, expected_packet_sha256)
    packet = evidence["packet"]
    issue_number = packet["issue_number"]
    packet_sha256 = packet["sha256"]
    base_sha = evidence["base"]["commit"]
    head_sha = evidence["head"]["commit"]
    candidate, candidate_digest = _load_candidate(candidate_receipt)
    claimed_observations = _validate_candidate_static(
        candidate,
        issue_number=issue_number,
        packet_sha256=packet_sha256,
        evidence=evidence,
    )
    if _external_tools() != evidence["external_tools"]:
        raise VerificationError("BOOTSTRAP_EXTERNAL_TOOL_DRIFT")
    if (
        _repository_state_identity(evidence["repository_root"])
        != evidence["repository_identity"]
    ):
        raise VerificationError("BOOTSTRAP_REPOSITORY_IDENTITY_DRIFT")
    observed = _execute_observations(
        evidence["repository_root"],
        evidence["base"]["tree"],
        evidence["head"]["tree"],
        evidence["command_manifest"],
    )
    if not _strict_equal(
        _load_direct_packet(direct_packet, expected_packet_sha256), packet
    ):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DRIFT")
    if not _strict_equal(
        _require_frozen_refs(
            evidence["repository_root"], base_sha, head_sha, packet["branch"]
        ),
        evidence["reference_identity"],
    ):
        raise VerificationError("BOOTSTRAP_REPOSITORY_REF_DRIFT")
    if (
        _repository_state_identity(evidence["repository_root"])
        != evidence["repository_identity"]
    ):
        raise VerificationError("BOOTSTRAP_REPOSITORY_IDENTITY_DRIFT")
    if _external_tools() != evidence["external_tools"]:
        raise VerificationError("BOOTSTRAP_EXTERNAL_TOOL_DRIFT")
    if (
        _tool_identities(
            evidence["repository_root"],
            evidence["base"]["tree"],
            evidence["head"]["tree"],
        )
        != evidence["tool_identities"]
    ):
        raise VerificationError("BOOTSTRAP_GIT_TOOL_IDENTITY_DRIFT")
    if claimed_observations != observed:
        raise VerificationError("BOOTSTRAP_CANDIDATE_OBSERVATION_MISMATCH")
    result = {
        "schema": "twinfinity-harness-bootstrap-verifier/v1",
        "repository": REPOSITORY,
        "issue_number": str(issue_number),
        "packet_sha256": packet_sha256,
        "base": evidence["base"],
        "head": evidence["head"],
        "candidate_receipt_sha256": candidate_digest,
        "tool_identities": evidence["tool_identities"],
        "external_tools": evidence["external_tools"],
        "command_manifest": evidence["command_manifest"],
        "command_manifest_sha256": evidence["command_manifest_sha256"],
        "observations": observed,
        "verdict": "PASS",
        "evidence_scope": EVIDENCE_SCOPE,
    }
    return result, evidence, packet


def verify(
    *,
    direct_packet: Path,
    expected_packet_sha256: str,
    candidate_receipt: Path,
) -> dict[str, Any]:
    result, _, _ = _verify_with_context(
        direct_packet=direct_packet,
        expected_packet_sha256=expected_packet_sha256,
        candidate_receipt=candidate_receipt,
    )
    return result


def _final_publication_guard(
    *,
    direct_packet: Path,
    expected_packet_sha256: str,
    evidence: dict[str, Any],
    packet: dict[str, Any],
) -> None:
    current_packet = _load_direct_packet(direct_packet, expected_packet_sha256)
    if not _strict_equal(current_packet, packet):
        raise VerificationError("BOOTSTRAP_DIRECT_PACKET_DRIFT")
    repository = _resolve_repository(Path(packet["worktree_path"]))
    if repository != evidence["repository_root"]:
        raise VerificationError("BOOTSTRAP_REPOSITORY_IDENTITY_DRIFT")
    if _repository_state_identity(repository) != evidence["repository_identity"]:
        raise VerificationError("BOOTSTRAP_REPOSITORY_IDENTITY_DRIFT")
    if not _strict_equal(
        _require_frozen_refs(
            repository,
            evidence["base"]["commit"],
            evidence["head"]["commit"],
            packet["branch"],
        ),
        evidence["reference_identity"],
    ):
        raise VerificationError("BOOTSTRAP_REPOSITORY_REF_DRIFT")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direct-packet", type=Path, required=True)
    parser.add_argument("--expected-packet-sha256", required=True)
    parser.add_argument("--candidate-receipt", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    arguments = parser.parse_args(argv)
    try:
        result, evidence, packet = _verify_with_context(
            direct_packet=arguments.direct_packet,
            expected_packet_sha256=arguments.expected_packet_sha256,
            candidate_receipt=arguments.candidate_receipt,
        )
        output = _canonical_bytes(result)
        guard = lambda: _final_publication_guard(
            direct_packet=arguments.direct_packet,
            expected_packet_sha256=arguments.expected_packet_sha256,
            evidence=evidence,
            packet=packet,
        )
        if arguments.receipt is None:
            guard()
            sys.stdout.buffer.write(output)
        else:
            _write_atomic_receipt(
                arguments.receipt,
                output,
                publication_guard=guard,
            )
            sys.stdout.buffer.write(output)
        return 0
    except VerificationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (
        OSError,
        subprocess.SubprocessError,
        RecursionError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        print("BOOTSTRAP_OPERATION_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
