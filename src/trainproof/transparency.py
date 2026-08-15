"""A witnessed append-only Merkle log for public run anchors."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import hash_object
from .constants import PROTOCOL_VERSION, ZERO_HASH
from .crypto import sign_object, verify_signature
from .merkle import MerkleTree, verify_proof

LOG_TREE_DOMAIN = "transparency-log-merkle/v1"


class TransparencyError(ValueError):
    """Raised for malformed or inconsistent transparency logs."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def new_log(log_id: str, operator_key_id: str, witness_key_id: str) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_VERSION,
        "log_id": log_id,
        "operator_key_id": operator_key_id,
        "witness_key_id": witness_key_id,
        "entries": [],
        "signed_heads": [],
    }


def _entry_leaves(log: dict[str, Any]) -> list[bytes]:
    return [hash_object("transparency-entry/v1", entry) for entry in log["entries"]]


def append_entry(
    log: dict[str, Any],
    kind: str,
    subject_digest: str,
    operator_private_key: str | Path,
    witness_private_key: str | Path,
    timestamp: str | None = None,
) -> int:
    index = len(log["entries"])
    previous_entry = (
        hash_object("transparency-entry/v1", log["entries"][-1]).hex()
        if log["entries"]
        else ZERO_HASH
    )
    entry = {
        "index": index,
        "kind": kind,
        "subject_digest": subject_digest,
        "previous_entry": previous_entry,
        "timestamp": timestamp or utc_now(),
    }
    log["entries"].append(entry)
    tree = MerkleTree(LOG_TREE_DOMAIN, _entry_leaves(log))
    previous_head = (
        hash_object("transparency-head/v1", log["signed_heads"][-1]["body"]).hex()
        if log["signed_heads"]
        else ZERO_HASH
    )
    head_body = {
        "log_id": log["log_id"],
        "size": len(log["entries"]),
        "root": tree.root.hex(),
        "previous_head": previous_head,
        "timestamp": entry["timestamp"],
    }
    log["signed_heads"].append(
        {
            "body": head_body,
            "operator_signature": sign_object(
                operator_private_key, "transparency-head/v1", head_body
            ),
            "witness_signature": sign_object(
                witness_private_key, "transparency-head/v1", head_body
            ),
        }
    )
    return index


def inclusion_proof(log: dict[str, Any], index: int) -> dict[str, Any]:
    tree = MerkleTree(LOG_TREE_DOMAIN, _entry_leaves(log))
    return tree.proof(index)


def final_head(log: dict[str, Any]) -> dict[str, Any]:
    if not log["signed_heads"]:
        raise TransparencyError("transparency log is empty")
    return log["signed_heads"][-1]


def verify_log(
    log: dict[str, Any],
    operator_public_key: dict[str, Any],
    witness_public_key: dict[str, Any],
) -> None:
    if not isinstance(log, dict) or set(log) != {
        "protocol",
        "log_id",
        "operator_key_id",
        "witness_key_id",
        "entries",
        "signed_heads",
    }:
        raise TransparencyError("log has unexpected or missing fields")
    if log.get("protocol") != PROTOCOL_VERSION:
        raise TransparencyError("unsupported log protocol")
    if log.get("operator_key_id") != operator_public_key.get("key_id"):
        raise TransparencyError("log operator key id mismatch")
    if log.get("witness_key_id") != witness_public_key.get("key_id"):
        raise TransparencyError("log witness key id mismatch")
    entries = log.get("entries")
    heads = log.get("signed_heads")
    if (
        not isinstance(entries, list)
        or not isinstance(heads, list)
        or len(entries) != len(heads)
    ):
        raise TransparencyError("log must contain one signed head per entry")
    if not entries:
        raise TransparencyError("log is empty")
    previous_entry = ZERO_HASH
    previous_head = ZERO_HASH
    previous_timestamp: datetime | None = None
    leaves: list[bytes] = []
    for index, (entry, signed_head) in enumerate(zip(entries, heads, strict=True)):
        if not isinstance(entry, dict) or set(entry) != {
            "index",
            "kind",
            "subject_digest",
            "previous_entry",
            "timestamp",
        }:
            raise TransparencyError(f"malformed entry at index {index}")
        if not isinstance(signed_head, dict) or set(signed_head) != {
            "body",
            "operator_signature",
            "witness_signature",
        }:
            raise TransparencyError(f"malformed signed head at index {index}")
        timestamp_text = entry.get("timestamp")
        if not isinstance(timestamp_text, str) or not timestamp_text.endswith("Z"):
            raise TransparencyError(f"invalid UTC timestamp at index {index}")
        try:
            timestamp = datetime.fromisoformat(timestamp_text[:-1] + "+00:00")
        except ValueError as exc:
            raise TransparencyError(f"invalid UTC timestamp at index {index}") from exc
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raise TransparencyError(f"timestamps are not monotonic at index {index}")
        subject = entry.get("subject_digest")
        if (
            not isinstance(entry.get("kind"), str)
            or not entry["kind"]
            or not isinstance(subject, str)
            or len(subject) != 64
            or any(character not in "0123456789abcdef" for character in subject)
        ):
            raise TransparencyError(
                f"invalid entry kind or subject digest at index {index}"
            )
        if entry.get("index") != index or entry.get("previous_entry") != previous_entry:
            raise TransparencyError(f"entry chain mismatch at index {index}")
        entry_digest = hash_object("transparency-entry/v1", entry)
        leaves.append(entry_digest)
        head_body = signed_head.get("body")
        tree = MerkleTree(LOG_TREE_DOMAIN, leaves)
        expected = {
            "log_id": log["log_id"],
            "size": index + 1,
            "root": tree.root.hex(),
            "previous_head": previous_head,
            "timestamp": entry.get("timestamp"),
        }
        if head_body != expected:
            raise TransparencyError(f"invalid tree head at size {index + 1}")
        verify_signature(
            operator_public_key,
            "transparency-head/v1",
            head_body,
            signed_head.get("operator_signature"),
        )
        verify_signature(
            witness_public_key,
            "transparency-head/v1",
            head_body,
            signed_head.get("witness_signature"),
        )
        previous_entry = entry_digest.hex()
        previous_head = hash_object("transparency-head/v1", head_body).hex()
        previous_timestamp = timestamp


def verify_inclusion(log: dict[str, Any], index: int, proof: dict[str, Any]) -> bool:
    if index < 0 or index >= len(log.get("entries", [])):
        return False
    leaf = hash_object("transparency-entry/v1", log["entries"][index])
    try:
        root = bytes.fromhex(final_head(log)["body"]["root"])
    except (KeyError, TypeError, ValueError, TransparencyError):
        return False
    return verify_proof(leaf, proof, root)
