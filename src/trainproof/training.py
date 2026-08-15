"""Deterministic integer training and signed distributed-step records."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from .canonical import hash_object
from .constants import PROTOCOL_VERSION
from .crypto import sign_object
from .dataset import dataset_inclusion_proof
from .merkle import MerkleTree
from .ordering import ordering_inclusion_proof

ASSIGNMENT_TREE_DOMAIN = "worker-assignment-merkle/v1"
RECEIPT_TREE_DOMAIN = "worker-receipt-merkle/v1"


class TrainingError(ValueError):
    """Raised when a deterministic training transition is invalid."""


def model_root(model: dict[str, Any]) -> str:
    return hash_object("model-state/v1", model).hex()


def optimizer_root(optimizer: dict[str, Any]) -> str:
    return hash_object("optimizer-state/v1", optimizer).hex()


def rng_root(rng: dict[str, Any]) -> str:
    return hash_object("rng-state/v1", rng).hex()


def state_roots(
    model: dict[str, Any], optimizer: dict[str, Any], rng: dict[str, Any]
) -> dict[str, str]:
    return {
        "model": model_root(model),
        "optimizer": optimizer_root(optimizer),
        "rng": rng_root(rng),
    }


def compute_worker_update(
    model: dict[str, Any], record: dict[str, Any]
) -> dict[str, Any]:
    weights = model.get("weights")
    bias = model.get("bias")
    if (
        not isinstance(weights, list)
        or len(weights) != 2
        or not all(isinstance(x, int) and not isinstance(x, bool) for x in weights)
    ):
        raise TrainingError("model weights must be two integers")
    if not isinstance(bias, int) or isinstance(bias, bool):
        raise TrainingError("model bias must be an integer")
    x0, x1 = record["x"]
    prediction = weights[0] * x0 + weights[1] * x1 + bias
    residual = record["y"] - prediction
    return {
        "delta_weights": [residual * x0, residual * x1],
        "delta_bias": residual,
        "sample_count": 1,
    }


def aggregate_updates(updates: list[dict[str, Any]]) -> dict[str, Any]:
    if not updates:
        raise TrainingError("cannot aggregate an empty worker set")
    return {
        "delta_weights": [
            sum(update["delta_weights"][0] for update in updates),
            sum(update["delta_weights"][1] for update in updates),
        ],
        "delta_bias": sum(update["delta_bias"] for update in updates),
        "sample_count": sum(update["sample_count"] for update in updates),
    }


def apply_update(model: dict[str, Any], aggregate: dict[str, Any]) -> dict[str, Any]:
    return {
        "weights": [
            model["weights"][0] + aggregate["delta_weights"][0],
            model["weights"][1] + aggregate["delta_weights"][1],
        ],
        "bias": model["bias"] + aggregate["delta_bias"],
    }


def commitment_with_salt(
    domain: str, value: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    opening = {"value": value, "salt": secrets.token_hex(32)}
    return hash_object(domain, opening).hex(), opening


def _signed_record_digest(domain: str, record: dict[str, Any]) -> bytes:
    return hash_object(domain, record)


def build_step(
    *,
    run_id: str,
    step: int,
    previous_step_commitment: str,
    manifest_digest: str,
    dataset_statement: dict[str, Any],
    ordering_statement: dict[str, Any],
    ordering_private: dict[str, Any],
    dataset_openings: dict[str, Any],
    model: dict[str, Any],
    optimizer: dict[str, Any],
    rng: dict[str, Any],
    coordinator_private_key: str | Path,
    worker_private_keys: list[str | Path],
    worker_public_documents: list[dict[str, Any]],
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    worker_count = len(worker_private_keys)
    if worker_count < 1 or worker_count != len(worker_public_documents):
        raise TrainingError("worker key lists are inconsistent")
    record_count = dataset_statement["body"]["record_count"]
    before_roots = state_roots(model, optimizer, rng)
    assignments: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    private_workers: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []

    for rank in range(worker_count):
        order_position = (step * worker_count + rank) % record_count
        order_opening = ordering_private["openings"][order_position]
        dataset_index = order_opening["dataset_index"]
        dataset_opening = dataset_openings["openings"][dataset_index]
        dataset_leaf = dataset_statement["body"]["leaf_commitments"][dataset_index]
        ordering_leaf = ordering_statement["body"]["leaf_commitments"][order_position]
        assignment_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "step": step,
            "rank": rank,
            "worker_key_id": worker_public_documents[rank]["key_id"],
            "previous_step_commitment": previous_step_commitment,
            "manifest_digest": manifest_digest,
            "pre_state": before_roots,
            "order_position": order_position,
            "dataset_leaf_commitment": dataset_leaf,
            "dataset_inclusion_proof": dataset_inclusion_proof(
                dataset_statement, dataset_index
            ),
            "ordering_leaf_commitment": ordering_leaf,
            "ordering_inclusion_proof": ordering_inclusion_proof(
                ordering_statement, order_position
            ),
        }
        assignment = {
            "body": assignment_body,
            "signature": sign_object(
                coordinator_private_key, "worker-assignment/v1", assignment_body
            ),
        }
        assignment_digest = hash_object("worker-assignment-record/v1", assignment).hex()
        update = compute_worker_update(model, dataset_opening["record"])
        update_commitment, update_opening = commitment_with_salt(
            "worker-update-commitment/v1", update
        )
        receipt_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "step": step,
            "rank": rank,
            "worker_key_id": worker_public_documents[rank]["key_id"],
            "assignment_digest": assignment_digest,
            "pre_state": before_roots,
            "update_commitment": update_commitment,
        }
        receipt = {
            "body": receipt_body,
            "signature": sign_object(
                worker_private_keys[rank], "worker-receipt/v1", receipt_body
            ),
        }
        assignments.append(assignment)
        receipts.append(receipt)
        updates.append(update)
        private_workers.append(
            {
                "rank": rank,
                "order_position": order_position,
                "dataset_index": dataset_index,
                "update_opening": update_opening,
            }
        )

    aggregate = aggregate_updates(updates)
    aggregate_commitment, aggregate_opening = commitment_with_salt(
        "aggregate-update-commitment/v1", aggregate
    )
    model_after = apply_update(model, aggregate)
    optimizer_after = {**optimizer, "step": step + 1}
    rng_after = {**rng, "counter": step + 1}
    after_roots = state_roots(model_after, optimizer_after, rng_after)
    assignment_leaves = [
        _signed_record_digest("worker-assignment-record/v1", assignment)
        for assignment in assignments
    ]
    receipt_leaves = [
        _signed_record_digest("worker-receipt-record/v1", receipt)
        for receipt in receipts
    ]
    assignment_root = MerkleTree(ASSIGNMENT_TREE_DOMAIN, assignment_leaves).root.hex()
    receipt_root = MerkleTree(RECEIPT_TREE_DOMAIN, receipt_leaves).root.hex()
    body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "step": step,
        "previous_step_commitment": previous_step_commitment,
        "manifest_digest": manifest_digest,
        "dataset_root": dataset_statement["body"]["sha256_root"],
        "ordering_root": ordering_statement["body"]["root"],
        "pre_state": before_roots,
        "post_state": after_roots,
        "assignments": assignments,
        "assignment_root": assignment_root,
        "worker_receipts": receipts,
        "worker_receipt_root": receipt_root,
        "aggregate_update_commitment": aggregate_commitment,
        "transition_proof": {
            "scheme": "private-deterministic-replay/v1",
            "publicly_verifiable": False,
            "zero_knowledge": False,
        },
    }
    step_commitment = hash_object("training-step/v1", body).hex()
    public_step = {
        "body": body,
        "step_commitment": step_commitment,
        "coordinator_signature": sign_object(
            coordinator_private_key, "training-step/v1", body
        ),
    }
    private_step = {
        "step": step,
        "model_before": model,
        "optimizer_before": optimizer,
        "rng_before": rng,
        "workers": private_workers,
        "aggregate_opening": aggregate_opening,
        "model_after": model_after,
        "optimizer_after": optimizer_after,
        "rng_after": rng_after,
    }
    return public_step, private_step, model_after, optimizer_after, rng_after
