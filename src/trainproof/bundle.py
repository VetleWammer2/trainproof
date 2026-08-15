"""Build a self-contained proof-carrying training-run bundle."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from .artifacts import source_manifest
from .canonical import hash_object, write_json
from .constants import PROTOCOL_VERSION
from .crypto import generate_keypair, sign_object
from .dataset import build_dataset_commitment
from .ordering import build_ordering_commitment
from .training import build_step, state_roots
from .transparency import append_entry, final_head, inclusion_proof, new_log, utc_now
from .trust import policy_document


class BundleError(ValueError):
    """Raised when a run bundle cannot be created safely."""


DEMO_RECORDS = [
    {"id": "sample-0", "x": [1, 0], "y": 2},
    {"id": "sample-1", "x": [0, 1], "y": 3},
    {"id": "sample-2", "x": [1, 1], "y": 5},
    {"id": "sample-3", "x": [2, 1], "y": 7},
    {"id": "sample-4", "x": [1, 2], "y": 8},
    {"id": "sample-5", "x": [2, 2], "y": 10},
]

_ALLOWED_IN_TREE_OUTPUT_ROOTS = {"demo-run", "tampered-run"}


def _key_paths(root: Path, name: str) -> tuple[Path, Path]:
    return (
        root / "private" / "keys" / f"{name}.private.json",
        root / "public" / "keys" / f"{name}.public.json",
    )


def _create_identity(root: Path, name: str, role: str) -> tuple[Path, dict[str, Any]]:
    private_path, public_path = _key_paths(root, name)
    public = generate_keypair(private_path, public_path, role)
    return private_path, public


def build_demo_bundle(
    output: str | Path,
    project_root: str | Path,
    *,
    steps: int = 4,
    workers: int = 2,
) -> dict[str, Any]:
    """Create, train, seal, and return a deterministic integer-training demo."""

    if steps < 1 or steps > 32:
        raise BundleError("steps must be between 1 and 32 for the v1 integer demo")
    if workers < 1 or workers > len(DEMO_RECORDS):
        raise BundleError("workers must be between 1 and the demo dataset size")
    root = Path(output).resolve()
    source_root = Path(project_root).resolve()
    if root.exists():
        raise BundleError(f"refusing to overwrite existing path: {root}")
    try:
        output_relative = root.relative_to(source_root)
    except ValueError:
        output_relative = None
    if output_relative is not None and (
        not output_relative.parts
        or output_relative.parts[0] not in _ALLOWED_IN_TREE_OUTPUT_ROOTS
    ):
        raise BundleError(
            "an output inside the source root must be under the top-level demo-run "
            "or tampered-run directory"
        )
    code = source_manifest(source_root)
    root.mkdir(parents=True)
    (root / "public").mkdir()
    (root / "private").mkdir()
    (root / "artifacts").mkdir()

    custodian_private, custodian_public = _create_identity(
        root, "custodian", "dataset-custodian"
    )
    coordinator_private, coordinator_public = _create_identity(
        root, "coordinator", "training-coordinator"
    )
    operator_private, operator_public = _create_identity(
        root, "log-operator", "transparency-log-operator"
    )
    witness_private, witness_public = _create_identity(
        root, "witness", "independent-log-witness"
    )
    worker_private: list[Path] = []
    worker_public: list[dict[str, Any]] = []
    for rank in range(workers):
        private, public = _create_identity(
            root, f"worker-{rank}", f"training-worker-{rank}"
        )
        worker_private.append(private)
        worker_public.append(public)

    run_id = secrets.token_hex(16)
    dataset_statement, dataset_private = build_dataset_commitment(
        DEMO_RECORDS,
        dataset_id=f"demo-linear-regression/{run_id}",
        custodian_private_key=custodian_private,
    )
    ordering_statement, ordering_private = build_ordering_commitment(
        len(DEMO_RECORDS), coordinator_private
    )
    write_json(root / "public" / "dataset.statement.json", dataset_statement)
    write_json(root / "private" / "dataset.openings.json", dataset_private)
    write_json(root / "public" / "ordering.statement.json", ordering_statement)
    write_json(root / "private" / "ordering.openings.json", ordering_private)

    initial_model = {"weights": [0, 0], "bias": 0}
    initial_optimizer = {"kind": "integer-sgd/v1", "step": 0}
    initial_rng = {
        "kind": "committed-sampler-counter/v1",
        "seed_commitment": ordering_statement["body"]["seed_commitment"],
        "counter": 0,
    }
    hyperparameters = {
        "trainer": "integer-linear-squared-error/v1",
        "numeric_semantics": "unbounded-signed-integer-exact/v1",
        "features": 2,
        "workers": workers,
        "batch_size": workers,
        "steps": steps,
        "learning_rate_numerator": 1,
        "learning_rate_denominator": 1,
        "aggregation": "rank-ordered-sum/v1",
    }
    manifest_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "created_at": utc_now(),
        "dataset_statement_digest": hash_object(
            "dataset-statement-record/v1", dataset_statement
        ).hex(),
        "dataset_root": dataset_statement["body"]["sha256_root"],
        "ordering_statement_digest": hash_object(
            "sample-order-statement-record/v1", ordering_statement
        ).hex(),
        "ordering_root": ordering_statement["body"]["root"],
        "source": code,
        "hyperparameters": hyperparameters,
        "hyperparameters_root": hash_object(
            "hyperparameters/v1", hyperparameters
        ).hex(),
        "initial_state": state_roots(initial_model, initial_optimizer, initial_rng),
        "participants": {
            "dataset_custodian": custodian_public,
            "coordinator": coordinator_public,
            "log_operator": operator_public,
            "log_witness": witness_public,
            "workers": worker_public,
        },
        "assurance_profile": {
            "public": "signed-commitment-transcript/v1",
            "private_audit": "deterministic-full-replay/v1",
            "zero_knowledge": False,
            "execution_correctness_publicly_proven": False,
            "identity_trust": "self-issued-demo-keys/v1",
            "external_time_anchor": False,
        },
    }
    manifest = {
        "body": manifest_body,
        "signature": sign_object(coordinator_private, "run-manifest/v1", manifest_body),
    }
    manifest_digest = hash_object("run-manifest/v1", manifest_body).hex()
    write_json(root / "public" / "manifest.json", manifest)
    genesis_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "manifest_digest": manifest_digest,
        "dataset_statement_digest": manifest_body["dataset_statement_digest"],
        "ordering_statement_digest": manifest_body["ordering_statement_digest"],
        "initial_state": manifest_body["initial_state"],
    }
    genesis = {
        "body": genesis_body,
        "commitment": hash_object("run-genesis/v1", genesis_body).hex(),
        "signature": sign_object(coordinator_private, "run-genesis/v1", genesis_body),
    }
    write_json(root / "public" / "genesis.json", genesis)

    log = new_log(
        f"demo-log/{run_id}",
        operator_public["key_id"],
        witness_public["key_id"],
    )
    append_entry(
        log,
        "dataset-statement",
        manifest_body["dataset_statement_digest"],
        operator_private,
        witness_private,
    )
    append_entry(
        log,
        "ordering-statement",
        manifest_body["ordering_statement_digest"],
        operator_private,
        witness_private,
    )
    append_entry(
        log,
        "run-genesis",
        genesis["commitment"],
        operator_private,
        witness_private,
    )

    model = initial_model
    optimizer = initial_optimizer
    rng = initial_rng
    previous = genesis["commitment"]
    public_steps: list[dict[str, Any]] = []
    private_steps: list[dict[str, Any]] = []
    for step_number in range(steps):
        public_step, private_step, model, optimizer, rng = build_step(
            run_id=run_id,
            step=step_number,
            previous_step_commitment=previous,
            manifest_digest=manifest_digest,
            dataset_statement=dataset_statement,
            ordering_statement=ordering_statement,
            ordering_private=ordering_private,
            dataset_openings=dataset_private,
            model=model,
            optimizer=optimizer,
            rng=rng,
            coordinator_private_key=coordinator_private,
            worker_private_keys=worker_private,
            worker_public_documents=worker_public,
        )
        public_steps.append(public_step)
        private_steps.append(private_step)
        previous = public_step["step_commitment"]
        append_entry(
            log,
            "training-step",
            public_step["step_commitment"],
            operator_private,
            witness_private,
        )
    write_json(root / "public" / "steps.json", public_steps)
    write_json(
        root / "private" / "trace.json",
        {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "initial_model": initial_model,
            "initial_optimizer": initial_optimizer,
            "initial_rng": initial_rng,
            "steps": private_steps,
        },
    )

    checkpoint = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "step_count": steps,
        "final_step_commitment": previous,
        "model": model,
        "optimizer": optimizer,
        "rng": rng,
        "state_roots": state_roots(model, optimizer, rng),
    }
    checkpoint_digest = hash_object("checkpoint/v1", checkpoint).hex()
    write_json(root / "artifacts" / "checkpoint.json", checkpoint)
    checkpoint_anchor = hash_object(
        "checkpoint-anchor/v1",
        {
            "run_id": run_id,
            "final_step_commitment": previous,
            "checkpoint_digest": checkpoint_digest,
        },
    ).hex()
    checkpoint_log_index = append_entry(
        log,
        "checkpoint",
        checkpoint_anchor,
        operator_private,
        witness_private,
    )
    write_json(root / "public" / "transparency.json", log)

    head = final_head(log)
    certificate_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "manifest_digest": manifest_digest,
        "genesis_commitment": genesis["commitment"],
        "step_count": steps,
        "final_step_commitment": previous,
        "checkpoint_digest": checkpoint_digest,
        "checkpoint_state_roots": checkpoint["state_roots"],
        "checkpoint_anchor": checkpoint_anchor,
        "checkpoint_log_index": checkpoint_log_index,
        "transparency_head_digest": hash_object(
            "transparency-head/v1", head["body"]
        ).hex(),
        "transparency_inclusion_proof": inclusion_proof(log, checkpoint_log_index),
        "assurance": manifest_body["assurance_profile"],
    }
    certificate = {
        "body": certificate_body,
        "coordinator_signature": sign_object(
            coordinator_private, "checkpoint-certificate/v1", certificate_body
        ),
        "witness_signature": sign_object(
            witness_private, "checkpoint-certificate/v1", certificate_body
        ),
    }
    write_json(root / "public" / "certificate.json", certificate)
    write_json(
        root / "trust-policy.example.json",
        policy_document(
            {
                "dataset_custodian": custodian_public["key_id"],
                "coordinator": coordinator_public["key_id"],
                "log_operator": operator_public["key_id"],
                "log_witness": witness_public["key_id"],
                "workers": [worker["key_id"] for worker in worker_public],
            },
            {
                "run_id": run_id,
                "dataset_root": manifest_body["dataset_root"],
                "ordering_root": manifest_body["ordering_root"],
                "source_root": code["root"],
                "source_git_commit": code["git"]["commit"],
                "source_git_dirty": code["git"]["dirty"],
                "hyperparameters_root": manifest_body["hyperparameters_root"],
                "genesis_commitment": genesis["commitment"],
                "step_count": steps,
                "final_step_commitment": previous,
                "checkpoint_digest": checkpoint_digest,
            },
        ),
    )
    return {
        "run_dir": str(root),
        "run_id": run_id,
        "checkpoint_digest": checkpoint_digest,
        "final_step_commitment": previous,
        "public_assurance": manifest_body["assurance_profile"]["public"],
    }
