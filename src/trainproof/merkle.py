"""Domain-separated binary Merkle trees with explicit leaf counts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .canonical import hash_bytes, hash_object


class MerkleError(ValueError):
    """Raised for invalid tree inputs or inclusion proofs."""


def leaf_hash(domain: str, value: Any) -> bytes:
    return hash_object(f"{domain}/leaf", value)


def _node_hash(domain: str, left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise MerkleError("Merkle nodes must be 32-byte SHA-256 digests")
    return hash_bytes(f"{domain}/node", left + right)


def _root_hash(domain: str, count: int, top: bytes) -> bytes:
    return hash_bytes(f"{domain}/root", count.to_bytes(8, "big") + top)


@dataclass(frozen=True)
class MerkleTree:
    domain: str
    leaves: tuple[bytes, ...]

    def __init__(self, domain: str, leaves: Iterable[bytes]):
        materialized = tuple(leaves)
        if not materialized:
            raise MerkleError("a Merkle tree needs at least one leaf")
        if any(len(leaf) != 32 for leaf in materialized):
            raise MerkleError("every leaf must be a 32-byte digest")
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "leaves", materialized)

    @property
    def count(self) -> int:
        return len(self.leaves)

    def levels(self) -> list[list[bytes]]:
        levels = [list(self.leaves)]
        while len(levels[-1]) > 1:
            current = levels[-1]
            next_level: list[bytes] = []
            for offset in range(0, len(current), 2):
                left = current[offset]
                right = current[offset + 1] if offset + 1 < len(current) else left
                next_level.append(_node_hash(self.domain, left, right))
            levels.append(next_level)
        return levels

    @property
    def root(self) -> bytes:
        top = self.levels()[-1][0]
        return _root_hash(self.domain, self.count, top)

    def proof(self, index: int) -> dict[str, Any]:
        if index < 0 or index >= self.count:
            raise MerkleError("leaf index out of range")
        siblings: list[dict[str, str]] = []
        cursor = index
        for level in self.levels()[:-1]:
            if cursor % 2 == 0:
                sibling_index = cursor + 1 if cursor + 1 < len(level) else cursor
                side = "right"
            else:
                sibling_index = cursor - 1
                side = "left"
            siblings.append({"side": side, "digest": level[sibling_index].hex()})
            cursor //= 2
        return {
            "domain": self.domain,
            "index": index,
            "count": self.count,
            "siblings": siblings,
        }


def verify_proof(leaf: bytes, proof: dict[str, Any], expected_root: bytes) -> bool:
    if not isinstance(proof, dict) or set(proof) != {
        "domain",
        "index",
        "count",
        "siblings",
    }:
        return False
    try:
        domain = proof["domain"]
        index = proof["index"]
        count = proof["count"]
        siblings = proof["siblings"]
    except (KeyError, TypeError):
        return False
    if (
        not isinstance(domain, str)
        or not isinstance(index, int)
        or isinstance(index, bool)
        or not isinstance(count, int)
        or isinstance(count, bool)
    ):
        return False
    if (
        len(leaf) != 32
        or len(expected_root) != 32
        or index < 0
        or index >= count
        or count < 1
    ):
        return False
    expected_depth = 0
    width = count
    while width > 1:
        width = (width + 1) // 2
        expected_depth += 1
    if not isinstance(siblings, list) or len(siblings) != expected_depth:
        return False
    cursor = index
    current = leaf
    for item in siblings:
        if (
            not isinstance(item, dict)
            or set(item) != {"side", "digest"}
            or item.get("side") not in {"left", "right"}
        ):
            return False
        try:
            sibling = bytes.fromhex(item["digest"])
        except (KeyError, TypeError, ValueError):
            return False
        if len(sibling) != 32 or sibling.hex() != item["digest"]:
            return False
        expected_side = "left" if cursor % 2 else "right"
        if item["side"] != expected_side:
            return False
        current = (
            _node_hash(domain, sibling, current)
            if item["side"] == "left"
            else _node_hash(domain, current, sibling)
        )
        cursor //= 2
    return _root_hash(domain, count, current) == expected_root
