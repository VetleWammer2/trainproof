"""Hiding dataset commitments and signed dataset statements."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from .canonical import hash_object, read_json, write_json
from .constants import PROTOCOL_VERSION
from .crypto import sign_object, verify_signature
from .merkle import MerkleTree, verify_proof

DATASET_TREE_DOMAIN = "dataset-merkle/v1"


class DatasetError(ValueError):
    """Raised when a dataset commitment or opening is invalid."""


def validate_record(record: Any) -> None:
    if not isinstance(record, dict):
        raise DatasetError("each record must be an object")
    if set(record) != {"id", "x", "y"}:
        raise DatasetError("records must contain exactly id, x, and y")
    if not isinstance(record["id"], str) or not record["id"]:
        raise DatasetError("record id must be a non-empty string")
    if (
        not isinstance(record["x"], list)
        or len(record["x"]) != 2
        or any(
            not isinstance(item, int) or isinstance(item, bool) for item in record["x"]
        )
    ):
        raise DatasetError("x must be a list of two integers")
    if not isinstance(record["y"], int) or isinstance(record["y"], bool):
        raise DatasetError("y must be an integer")


def opening_commitment(opening: dict[str, Any]) -> bytes:
    return hash_object("dataset-record-commitment/v1", opening)


def build_dataset_commitment(
    records: list[dict[str, Any]],
    dataset_id: str,
    custodian_private_key: str | Path,
    additional_roots: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not records:
        raise DatasetError("dataset must not be empty")
    if additional_roots not in (None, {}):
        raise DatasetError("additional dataset roots are not supported by protocol v1")
    seen_ids: set[str] = set()
    openings: list[dict[str, Any]] = []
    leaf_commitments: list[bytes] = []
    for index, record in enumerate(records):
        validate_record(record)
        if record["id"] in seen_ids:
            raise DatasetError(f"duplicate record id: {record['id']}")
        seen_ids.add(record["id"])
        opening = {
            "index": index,
            "record": record,
            "salt": secrets.token_hex(32),
        }
        openings.append(opening)
        leaf_commitments.append(opening_commitment(opening))
    tree = MerkleTree(DATASET_TREE_DOMAIN, leaf_commitments)
    body = {
        "protocol": PROTOCOL_VERSION,
        "dataset_id": dataset_id,
        "record_schema": "integer-linear-regression-2d/v1",
        "record_count": len(records),
        "commitment_scheme": "salted-sha256-canonical-json/v1",
        "merkle_domain": DATASET_TREE_DOMAIN,
        "sha256_root": tree.root.hex(),
        "leaf_commitments": [leaf.hex() for leaf in leaf_commitments],
        "additional_roots": {},
    }
    signed_statement = {
        "body": body,
        "signature": sign_object(custodian_private_key, "dataset-statement/v1", body),
    }
    private_openings = {
        "protocol": PROTOCOL_VERSION,
        "dataset_id": dataset_id,
        "openings": openings,
    }
    return signed_statement, private_openings


def verify_dataset_statement(
    statement: dict[str, Any], custodian_public_key: dict[str, Any]
) -> None:
    if not isinstance(statement, dict) or set(statement) != {"body", "signature"}:
        raise DatasetError("malformed signed dataset statement")
    body = statement["body"]
    if not isinstance(body, dict) or set(body) != {
        "protocol",
        "dataset_id",
        "record_schema",
        "record_count",
        "commitment_scheme",
        "merkle_domain",
        "sha256_root",
        "leaf_commitments",
        "additional_roots",
    }:
        raise DatasetError("dataset statement body has unexpected or missing fields")
    verify_signature(
        custodian_public_key, "dataset-statement/v1", body, statement["signature"]
    )
    if body.get("protocol") != PROTOCOL_VERSION:
        raise DatasetError("unsupported dataset protocol")
    if body.get("commitment_scheme") != "salted-sha256-canonical-json/v1":
        raise DatasetError("unsupported dataset commitment scheme")
    if body.get("merkle_domain") != DATASET_TREE_DOMAIN:
        raise DatasetError("unsupported dataset Merkle domain")
    if body.get("record_schema") != "integer-linear-regression-2d/v1":
        raise DatasetError("unsupported dataset record schema")
    if (
        not isinstance(body.get("dataset_id"), str)
        or not body["dataset_id"]
        or not isinstance(body.get("record_count"), int)
        or isinstance(body["record_count"], bool)
        or body["record_count"] < 1
        or body.get("additional_roots") != {}
    ):
        raise DatasetError(
            "invalid dataset identity/count or unsupported additional roots"
        )
    leaves_raw = body.get("leaf_commitments")
    if not isinstance(leaves_raw, list) or len(leaves_raw) != body.get("record_count"):
        raise DatasetError("dataset leaf count mismatch")
    try:
        leaves = [bytes.fromhex(item) for item in leaves_raw]
    except (TypeError, ValueError) as exc:
        raise DatasetError("invalid dataset leaf commitment") from exc
    if any(
        len(leaf) != 32 or leaf.hex() != raw
        for leaf, raw in zip(leaves, leaves_raw, strict=True)
    ):
        raise DatasetError("dataset leaf commitments must be canonical 32-byte hex")
    tree = MerkleTree(body["merkle_domain"], leaves)
    if tree.root.hex() != body.get("sha256_root"):
        raise DatasetError("dataset Merkle root mismatch")


def verify_dataset_openings(
    statement: dict[str, Any], private_openings: dict[str, Any]
) -> list[dict[str, Any]]:
    body = statement["body"]
    if private_openings.get("dataset_id") != body.get("dataset_id"):
        raise DatasetError("dataset id mismatch")
    openings = private_openings.get("openings")
    if not isinstance(openings, list) or len(openings) != body.get("record_count"):
        raise DatasetError("dataset opening count mismatch")
    leaves: list[bytes] = []
    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for expected_index, opening in enumerate(openings):
        if opening.get("index") != expected_index:
            raise DatasetError("dataset openings are not in canonical order")
        validate_record(opening.get("record"))
        record_id = opening["record"]["id"]
        if record_id in seen_ids:
            raise DatasetError(f"duplicate opened record id: {record_id}")
        seen_ids.add(record_id)
        salt = opening.get("salt")
        if not isinstance(salt, str):
            raise DatasetError("missing record salt")
        try:
            salt_bytes = bytes.fromhex(salt)
        except ValueError as exc:
            raise DatasetError("invalid record salt") from exc
        if len(salt_bytes) != 32:
            raise DatasetError("record salt must be 32 bytes")
        leaves.append(opening_commitment(opening))
        records.append(opening["record"])
    expected_leaves = body["leaf_commitments"]
    if [leaf.hex() for leaf in leaves] != expected_leaves:
        raise DatasetError("one or more dataset openings do not match")
    tree = MerkleTree(body["merkle_domain"], leaves)
    if tree.root.hex() != body["sha256_root"]:
        raise DatasetError("opened dataset root mismatch")
    return records


def dataset_inclusion_proof(statement: dict[str, Any], index: int) -> dict[str, Any]:
    body = statement["body"]
    leaves = [bytes.fromhex(item) for item in body["leaf_commitments"]]
    return MerkleTree(body["merkle_domain"], leaves).proof(index)


def verify_dataset_leaf(
    statement: dict[str, Any], leaf_hex: str, proof: dict[str, Any]
) -> bool:
    try:
        leaf = bytes.fromhex(leaf_hex)
        root = bytes.fromhex(statement["body"]["sha256_root"])
    except (KeyError, TypeError, ValueError):
        return False
    return verify_proof(leaf, proof, root)


def load_records(path: str | Path) -> list[dict[str, Any]]:
    value = read_json(path)
    if not isinstance(value, list):
        raise DatasetError("dataset file must be a JSON list")
    for record in value:
        validate_record(record)
    return value


def save_records(path: str | Path, records: list[dict[str, Any]]) -> None:
    for record in records:
        validate_record(record)
    write_json(path, records)
