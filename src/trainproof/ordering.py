"""Precommitted deterministic sample ordering."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from .canonical import hash_bytes, hash_object
from .constants import PROTOCOL_VERSION
from .crypto import sign_object, verify_signature
from .merkle import MerkleTree, verify_proof

ORDER_TREE_DOMAIN = "sample-order-merkle/v1"


class OrderingError(ValueError):
    """Raised for invalid sample-order commitments."""


def derive_order(record_count: int, seed: bytes) -> list[int]:
    """Derive a permutation by sorting domain-separated SHA-256 scores."""

    if record_count < 1:
        raise OrderingError("record count must be positive")
    if len(seed) != 32:
        raise OrderingError("sampler seed must be 32 bytes")
    scored = []
    for index in range(record_count):
        score = hash_bytes(
            "sample-order-score/v1",
            seed + record_count.to_bytes(8, "big") + index.to_bytes(8, "big"),
        )
        scored.append((score, index))
    return [index for _, index in sorted(scored)]


def ordering_opening_commitment(opening: dict[str, Any]) -> bytes:
    return hash_object("sample-order-opening/v1", opening)


def build_ordering_commitment(
    record_count: int,
    coordinator_private_key: str | Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    seed = secrets.token_bytes(32)
    order = derive_order(record_count, seed)
    openings: list[dict[str, Any]] = []
    leaves: list[bytes] = []
    for position, dataset_index in enumerate(order):
        opening = {
            "position": position,
            "dataset_index": dataset_index,
            "salt": secrets.token_hex(32),
        }
        openings.append(opening)
        leaves.append(ordering_opening_commitment(opening))
    tree = MerkleTree(ORDER_TREE_DOMAIN, leaves)
    body = {
        "protocol": PROTOCOL_VERSION,
        "algorithm": "sha256-sort-permutation/v1",
        "record_count": record_count,
        "seed_commitment": hash_bytes("sampler-seed/v1", seed).hex(),
        "merkle_domain": ORDER_TREE_DOMAIN,
        "root": tree.root.hex(),
        "leaf_commitments": [leaf.hex() for leaf in leaves],
    }
    statement = {
        "body": body,
        "signature": sign_object(
            coordinator_private_key, "sample-order-statement/v1", body
        ),
    }
    private = {
        "protocol": PROTOCOL_VERSION,
        "seed": seed.hex(),
        "openings": openings,
    }
    return statement, private


def verify_ordering_statement(
    statement: dict[str, Any], coordinator_public_key: dict[str, Any]
) -> None:
    if not isinstance(statement, dict) or set(statement) != {"body", "signature"}:
        raise OrderingError("malformed signed ordering statement")
    body = statement.get("body")
    if not isinstance(body, dict) or set(body) != {
        "protocol",
        "algorithm",
        "record_count",
        "seed_commitment",
        "merkle_domain",
        "root",
        "leaf_commitments",
    }:
        raise OrderingError("ordering statement body has unexpected or missing fields")
    verify_signature(
        coordinator_public_key,
        "sample-order-statement/v1",
        body,
        statement.get("signature"),
    )
    if body.get("protocol") != PROTOCOL_VERSION:
        raise OrderingError("unsupported ordering protocol")
    if body.get("algorithm") != "sha256-sort-permutation/v1":
        raise OrderingError("unsupported ordering algorithm")
    if body.get("merkle_domain") != ORDER_TREE_DOMAIN:
        raise OrderingError("unsupported ordering Merkle domain")
    if (
        not isinstance(body.get("record_count"), int)
        or isinstance(body["record_count"], bool)
        or body["record_count"] < 1
    ):
        raise OrderingError("ordering record count must be a positive integer")
    try:
        seed_commitment = bytes.fromhex(body.get("seed_commitment", ""))
    except (TypeError, ValueError) as exc:
        raise OrderingError("invalid ordering seed commitment") from exc
    if len(seed_commitment) != 32 or seed_commitment.hex() != body["seed_commitment"]:
        raise OrderingError("ordering seed commitment must be canonical 32-byte hex")
    leaves_raw = body.get("leaf_commitments")
    if not isinstance(leaves_raw, list) or len(leaves_raw) != body.get("record_count"):
        raise OrderingError("ordering leaf count mismatch")
    try:
        leaves = [bytes.fromhex(item) for item in leaves_raw]
    except (TypeError, ValueError) as exc:
        raise OrderingError("invalid ordering leaf") from exc
    if any(
        len(leaf) != 32 or leaf.hex() != raw
        for leaf, raw in zip(leaves, leaves_raw, strict=True)
    ):
        raise OrderingError("ordering leaves must be canonical 32-byte hex")
    tree = MerkleTree(body["merkle_domain"], leaves)
    if tree.root.hex() != body.get("root"):
        raise OrderingError("ordering root mismatch")


def verify_ordering_openings(
    statement: dict[str, Any], private: dict[str, Any]
) -> list[int]:
    body = statement["body"]
    try:
        seed = bytes.fromhex(private["seed"])
    except (KeyError, TypeError, ValueError) as exc:
        raise OrderingError("invalid private sampler seed") from exc
    if (
        len(seed) != 32
        or hash_bytes("sampler-seed/v1", seed).hex() != body["seed_commitment"]
    ):
        raise OrderingError("sampler seed does not open the commitment")
    expected_order = derive_order(body["record_count"], seed)
    openings = private.get("openings")
    if not isinstance(openings, list) or len(openings) != len(expected_order):
        raise OrderingError("ordering opening count mismatch")
    leaves: list[bytes] = []
    for position, (opening, expected_index) in enumerate(
        zip(openings, expected_order, strict=True)
    ):
        if (
            opening.get("position") != position
            or opening.get("dataset_index") != expected_index
        ):
            raise OrderingError(
                "ordering opening does not match deterministic permutation"
            )
        try:
            salt = bytes.fromhex(opening["salt"])
        except (KeyError, TypeError, ValueError) as exc:
            raise OrderingError("invalid ordering salt") from exc
        if len(salt) != 32:
            raise OrderingError("ordering salt must be 32 bytes")
        leaves.append(ordering_opening_commitment(opening))
    if [leaf.hex() for leaf in leaves] != body["leaf_commitments"]:
        raise OrderingError("ordering openings do not match public leaves")
    if MerkleTree(body["merkle_domain"], leaves).root.hex() != body["root"]:
        raise OrderingError("ordering openings do not match public root")
    return expected_order


def ordering_inclusion_proof(
    statement: dict[str, Any], position: int
) -> dict[str, Any]:
    body = statement["body"]
    leaves = [bytes.fromhex(item) for item in body["leaf_commitments"]]
    return MerkleTree(body["merkle_domain"], leaves).proof(position)


def verify_ordering_leaf(
    statement: dict[str, Any], leaf_hex: str, proof: dict[str, Any]
) -> bool:
    try:
        leaf = bytes.fromhex(leaf_hex)
        root = bytes.fromhex(statement["body"]["root"])
    except (KeyError, TypeError, ValueError):
        return False
    return verify_proof(leaf, proof, root)
