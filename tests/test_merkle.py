from __future__ import annotations

from trainproof.canonical import hash_object
from trainproof.merkle import MerkleTree, verify_proof


def test_odd_sized_tree_proofs_and_tamper_detection() -> None:
    leaves = [hash_object("test-leaf/v1", {"i": index}) for index in range(5)]
    tree = MerkleTree("test-tree/v1", leaves)
    for index, leaf in enumerate(leaves):
        proof = tree.proof(index)
        assert verify_proof(leaf, proof, tree.root)
        assert not verify_proof(
            hash_object("test-leaf/v1", {"i": 99}), proof, tree.root
        )


def test_leaf_count_is_bound_into_root() -> None:
    leaf = hash_object("test-leaf/v1", {"i": 0})
    one = MerkleTree("test-tree/v1", [leaf])
    two = MerkleTree("test-tree/v1", [leaf, leaf])
    assert one.root != two.root
