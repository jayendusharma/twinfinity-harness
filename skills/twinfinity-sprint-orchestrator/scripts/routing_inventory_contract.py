"""Pure structural and digest validation for routing inventory generations."""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any, Mapping, Sequence

def digest_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

KIND = "TWINFINITY_ROUTING_DEPRECATION_INVENTORY_V1"
CLASSIFICATIONS = ("EXECUTABLE_ROUTE", "ROUTING_REFERENCE", "HISTORICAL_PROVENANCE", "AMBIGUOUS_REFERENCE")
TAGS = ("ACCEPTANCE", "APPROVAL", "DEPENDENCY", "HOLD", "SCOPE")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RoutingInventoryContractError(ValueError):
    pass


def _integer(value: Any, *, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def validate_inventory_payload(inventory: Mapping[str, Any], occurrences: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    required = {"kind","repository","alias_source_sha256","endpoint_state_sha256","issue_179_source_sha256","object_manifest_sha256","occurrence_manifest_sha256","object_manifest","object_count","issue_count","pull_request_count","occurrence_count","classification_counts","semantic_tag_counts","inventory_sha256"}
    if type(inventory) is not dict or set(inventory) != required or inventory.get("kind") != KIND or type(inventory.get("repository")) is not str or not inventory["repository"] or type(occurrences) is not list:
        raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    for name in ("alias_source_sha256","endpoint_state_sha256","issue_179_source_sha256","object_manifest_sha256","occurrence_manifest_sha256","inventory_sha256"):
        if type(inventory.get(name)) is not str or SHA256.fullmatch(inventory[name]) is None:
            raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    objects = inventory.get("object_manifest")
    if type(objects) is not list:
        raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    for item in objects:
        if (type(item) is not dict or set(item) != {"object_kind","object_number","node_id","body_sha256"}
                or type(item["object_kind"]) is not str or item["object_kind"] not in {"issue","pull_request"} or not _integer(item["object_number"], minimum=1)
                or type(item["node_id"]) is not str or not item["node_id"] or type(item["body_sha256"]) is not str or SHA256.fullmatch(item["body_sha256"]) is None):
            raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    canonical_occurrences: list[dict[str, Any]] = []
    for ordinal, item in enumerate(occurrences):
        semantic_tags = item.get("semantic_tags") if type(item) is dict else None
        tags_valid = (
            type(semantic_tags) is list
            and all(type(tag) is str and tag in TAGS for tag in semantic_tags)
            and len(semantic_tags) == len(set(semantic_tags))
            and semantic_tags == sorted(semantic_tags)
        )
        if (type(item) is not dict or set(item) != {"ordinal","object_kind","object_number","node_id","body_sha256","alias","byte_start","byte_end","line_number","byte_column","classification","semantic_tags"}
                or not _integer(item["ordinal"]) or item["ordinal"] != ordinal
                or type(item["object_kind"]) is not str or item["object_kind"] not in {"issue","pull_request"} or not _integer(item["object_number"], minimum=1)
                or type(item["node_id"]) is not str or not item["node_id"] or type(item["body_sha256"]) is not str or SHA256.fullmatch(item["body_sha256"]) is None
                or type(item["alias"]) is not str or not item["alias"] or not _integer(item["byte_start"])
                or not _integer(item["byte_end"], minimum=1) or item["byte_end"] <= item["byte_start"]
                or not _integer(item["line_number"], minimum=1) or not _integer(item["byte_column"], minimum=1)
                or type(item["classification"]) is not str or item["classification"] not in CLASSIFICATIONS or not tags_valid):
            raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
        canonical_occurrences.append(dict(item))
    counts = (inventory["object_count"],inventory["issue_count"],inventory["pull_request_count"],inventory["occurrence_count"])
    if any(not _integer(value) for value in counts):
        raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    expected_classes = {name: sum(item["classification"] == name for item in canonical_occurrences) for name in CLASSIFICATIONS}
    expected_tags = {name: sum(name in item["semantic_tags"] for item in canonical_occurrences) for name in TAGS}
    for supplied, expected in ((inventory["classification_counts"], expected_classes), (inventory["semantic_tag_counts"], expected_tags)):
        if type(supplied) is not dict or supplied != expected or any(type(value) is not int or value < 0 for value in supplied.values()):
            raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    if (inventory["object_count"] != len(objects) or inventory["issue_count"] != sum(item["object_kind"] == "issue" for item in objects)
            or inventory["pull_request_count"] != sum(item["object_kind"] == "pull_request" for item in objects)
            or inventory["occurrence_count"] != len(canonical_occurrences) or digest_json(objects) != inventory["object_manifest_sha256"]
            or digest_json(canonical_occurrences) != inventory["occurrence_manifest_sha256"]
            or digest_json({key: inventory[key] for key in required - {"inventory_sha256"}}) != inventory["inventory_sha256"]):
        raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    return dict(inventory), canonical_occurrences


def validate_inventory_record(row: Mapping[str, Any], occurrence_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    row = dict(row)
    occurrence_rows = [dict(item) for item in occurrence_rows]
    if row.get("state") != "COMPLETE":
        raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    try:
        objects = json.loads(row["object_manifest_json"])
        classes = json.loads(row["classification_counts_json"])
        tags = json.loads(row["semantic_tag_counts_json"])
        occurrences = [{"ordinal": item["ordinal"], "object_kind": item["object_kind"], "object_number": item["object_number"], "node_id": item["node_id"], "body_sha256": item["body_sha256"], "alias": item["alias"], "byte_start": item["byte_start"], "byte_end": item["byte_end"], "line_number": item["line_number"], "byte_column": item["byte_column"], "classification": item["classification"], "semantic_tags": json.loads(item["semantic_tags_json"])} for item in occurrence_rows]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID") from exc
    inventory = {"kind": row["kind"], "repository": row["repository"], "alias_source_sha256": row["alias_source_sha256"], "endpoint_state_sha256": row["endpoint_state_sha256"], "issue_179_source_sha256": row["issue_179_source_sha256"], "object_manifest_sha256": row["object_manifest_sha256"], "occurrence_manifest_sha256": row["occurrence_manifest_sha256"], "object_manifest": objects, "object_count": row["object_count"], "issue_count": row["issue_count"], "pull_request_count": row["pull_request_count"], "occurrence_count": row["occurrence_count"], "classification_counts": classes, "semantic_tag_counts": tags, "inventory_sha256": row["inventory_sha256"]}
    validated = validate_inventory_payload(inventory, occurrences)
    if type(row.get("created_at")) is not str or any(type(item.get("object_updated_at")) is not str or item["object_updated_at"] != row["created_at"] for item in occurrence_rows):
        raise RoutingInventoryContractError("ROUTING_DEPRECATION_INVENTORY_INVALID")
    return validated
