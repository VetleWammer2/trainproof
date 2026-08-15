"""Independent public verification and private deterministic replay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifacts import validate_source_manifest, verify_source_manifest
from .canonical import hash_object, read_json
from .constants import PROTOCOL_VERSION
from .crypto import validate_public_key_document, verify_signature
from .dataset import (
    verify_dataset_leaf,
    verify_dataset_openings,
    verify_dataset_statement,
)
from .merkle import MerkleTree
from .ordering import (
    verify_ordering_leaf,
    verify_ordering_openings,
    verify_ordering_statement,
)
from .training import (
    ASSIGNMENT_TREE_DOMAIN,
    RECEIPT_TREE_DOMAIN,
    aggregate_updates,
    apply_update,
    compute_worker_update,
    state_roots,
)
from .transparency import final_head, verify_inclusion, verify_log
from .trust import verify_trust_policy


class VerificationError(ValueError):
    """Raised when any public or private invariant fails."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _require_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and set(value) == fields,
        f"{label} has unexpected or missing fields",
    )
    return value


def _plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_bundle(root: Path) -> dict[str, Any]:
    return {
        "dataset": read_json(root / "public" / "dataset.statement.json"),
        "ordering": read_json(root / "public" / "ordering.statement.json"),
        "manifest": read_json(root / "public" / "manifest.json"),
        "genesis": read_json(root / "public" / "genesis.json"),
        "steps": read_json(root / "public" / "steps.json"),
        "checkpoint": read_json(root / "artifacts" / "checkpoint.json"),
        "log": read_json(root / "public" / "transparency.json"),
        "certificate": read_json(root / "public" / "certificate.json"),
    }


def _verify_public_layout(root: Path) -> None:
    public = root / "public"
    expected_public = {
        "dataset.statement.json",
        "ordering.statement.json",
        "manifest.json",
        "genesis.json",
        "steps.json",
        "transparency.json",
        "certificate.json",
        "keys",
    }
    actual_public = {path.name for path in public.iterdir()}
    _require(actual_public == expected_public, "public artifact file set mismatch")
    _require(
        all(not path.is_symlink() for path in public.rglob("*")),
        "public artifact bundle must not contain symbolic links",
    )
    artifacts = root / "artifacts"
    _require(
        {path.name for path in artifacts.iterdir()} == {"checkpoint.json"},
        "checkpoint artifact file set mismatch",
    )
    _require(
        not (artifacts / "checkpoint.json").is_symlink(),
        "checkpoint artifact must not be a symbolic link",
    )


def _validated_participants(
    participants: Any,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
]:
    _require(
        isinstance(participants, dict)
        and set(participants)
        == {
            "coordinator",
            "dataset_custodian",
            "log_operator",
            "log_witness",
            "workers",
        },
        "manifest participant set is malformed",
    )
    coordinator = participants["coordinator"]
    custodian = participants["dataset_custodian"]
    operator = participants["log_operator"]
    witness = participants["log_witness"]
    workers = participants["workers"]
    _require(
        isinstance(workers, list) and workers,
        "manifest worker set is empty or malformed",
    )

    role_documents = [
        (coordinator, "training-coordinator"),
        (custodian, "dataset-custodian"),
        (operator, "transparency-log-operator"),
        (witness, "independent-log-witness"),
        *[(worker, f"training-worker-{rank}") for rank, worker in enumerate(workers)],
    ]
    for document, expected_role in role_documents:
        validate_public_key_document(document, expected_role)
    key_ids = [document["key_id"] for document, _ in role_documents]
    _require(
        len(key_ids) == len(set(key_ids)),
        "participant key ids must be distinct across every role and worker rank",
    )
    return coordinator, custodian, operator, witness, workers


def _validated_replay_genesis(
    bundle: dict[str, Any],
    trace: dict[str, Any],
    records: list[dict[str, Any]],
    order: list[int],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    dataset_count = bundle["dataset"]["body"]["record_count"]
    ordering_count = bundle["ordering"]["body"]["record_count"]
    _require(
        len(records) == dataset_count == ordering_count == len(order),
        "opened dataset and ordering counts do not match their statements",
    )
    _require(
        trace.get("protocol") == PROTOCOL_VERSION, "private trace protocol mismatch"
    )
    model = trace["initial_model"]
    optimizer = trace["initial_optimizer"]
    rng = trace["initial_rng"]
    _require(
        optimizer == {"kind": "integer-sgd/v1", "step": 0},
        "private initial optimizer does not match the committed trainer semantics",
    )
    _require(
        rng
        == {
            "kind": "committed-sampler-counter/v1",
            "seed_commitment": bundle["ordering"]["body"]["seed_commitment"],
            "counter": 0,
        },
        "private initial RNG does not bind the committed ordering seed and counter",
    )
    return model, optimizer, rng


def _verify_published_key_documents(
    root: Path,
    coordinator: dict[str, Any],
    custodian: dict[str, Any],
    operator: dict[str, Any],
    witness: dict[str, Any],
    workers: list[dict[str, Any]],
) -> None:
    expected = {
        "coordinator.public.json": coordinator,
        "custodian.public.json": custodian,
        "log-operator.public.json": operator,
        "witness.public.json": witness,
        **{f"worker-{rank}.public.json": worker for rank, worker in enumerate(workers)},
    }
    key_directory = root / "public" / "keys"
    actual_names = {path.name for path in key_directory.iterdir() if path.is_file()}
    _require(
        actual_names == set(expected),
        "published public-key file set does not match the manifest",
    )
    for filename, document in expected.items():
        _require(
            read_json(key_directory / filename) == document,
            f"published public-key document does not match manifest: {filename}",
        )


def _verify_step(
    step_record: dict[str, Any],
    *,
    expected_step: int,
    expected_previous: str,
    expected_pre_state: dict[str, str],
    manifest_digest: str,
    run_id: str,
    dataset: dict[str, Any],
    ordering: dict[str, Any],
    coordinator: dict[str, Any],
    workers: list[dict[str, Any]],
) -> dict[str, str]:
    body = step_record.get("body")
    _require_fields(
        step_record,
        {"body", "step_commitment", "coordinator_signature"},
        f"step {expected_step}",
    )
    body = _require_fields(
        body,
        {
            "protocol",
            "run_id",
            "step",
            "previous_step_commitment",
            "manifest_digest",
            "dataset_root",
            "ordering_root",
            "pre_state",
            "post_state",
            "assignments",
            "assignment_root",
            "worker_receipts",
            "worker_receipt_root",
            "aggregate_update_commitment",
            "transition_proof",
        },
        f"step {expected_step} body",
    )
    _require(
        body.get("protocol") == PROTOCOL_VERSION,
        f"step {expected_step}: protocol mismatch",
    )
    _require(body.get("run_id") == run_id, f"step {expected_step}: run id mismatch")
    _require(
        _plain_int(body.get("step")) and body["step"] == expected_step,
        f"step {expected_step}: number mismatch",
    )
    _require(
        body.get("previous_step_commitment") == expected_previous,
        f"step {expected_step}: chain predecessor mismatch",
    )
    _require(
        body.get("manifest_digest") == manifest_digest,
        f"step {expected_step}: manifest mismatch",
    )
    _require(
        body.get("dataset_root") == dataset["body"]["sha256_root"],
        f"step {expected_step}: dataset root mismatch",
    )
    _require(
        body.get("ordering_root") == ordering["body"]["root"],
        f"step {expected_step}: ordering root mismatch",
    )
    _require(
        body.get("pre_state") == expected_pre_state,
        f"step {expected_step}: pre-state mismatch",
    )
    commitment = hash_object("training-step/v1", body).hex()
    _require(
        step_record.get("step_commitment") == commitment,
        f"step {expected_step}: commitment mismatch",
    )
    verify_signature(
        coordinator,
        "training-step/v1",
        body,
        step_record.get("coordinator_signature"),
    )

    assignments = body.get("assignments")
    receipts = body.get("worker_receipts")
    _require(
        isinstance(assignments, list)
        and isinstance(receipts, list)
        and len(assignments) == len(workers)
        and len(receipts) == len(workers),
        f"step {expected_step}: worker cardinality mismatch",
    )
    assignment_leaves: list[bytes] = []
    receipt_leaves: list[bytes] = []
    for rank, (assignment, receipt, worker) in enumerate(
        zip(assignments, receipts, workers, strict=True)
    ):
        assignment_body = assignment.get("body")
        _require_fields(
            assignment,
            {"body", "signature"},
            f"step {expected_step} assignment {rank}",
        )
        assignment_body = _require_fields(
            assignment_body,
            {
                "protocol",
                "run_id",
                "step",
                "rank",
                "worker_key_id",
                "previous_step_commitment",
                "manifest_digest",
                "pre_state",
                "order_position",
                "dataset_leaf_commitment",
                "dataset_inclusion_proof",
                "ordering_leaf_commitment",
                "ordering_inclusion_proof",
            },
            f"step {expected_step} assignment {rank} body",
        )
        _require(
            assignment_body.get("protocol") == PROTOCOL_VERSION
            and assignment_body.get("run_id") == run_id
            and assignment_body.get("step") == expected_step
            and assignment_body.get("manifest_digest") == manifest_digest,
            f"step {expected_step}: assignment context mismatch",
        )
        _require(
            _plain_int(assignment_body.get("rank")) and assignment_body["rank"] == rank,
            f"step {expected_step}: assignment rank mismatch",
        )
        _require(
            assignment_body.get("worker_key_id") == worker["key_id"],
            f"step {expected_step}: worker key mismatch",
        )
        _require(
            assignment_body.get("pre_state") == expected_pre_state,
            f"step {expected_step}: assignment state mismatch",
        )
        _require(
            assignment_body.get("previous_step_commitment") == expected_previous,
            f"step {expected_step}: assignment chain mismatch",
        )
        expected_order_position = (expected_step * len(workers) + rank) % ordering[
            "body"
        ]["record_count"]
        _require(
            _plain_int(assignment_body.get("order_position"))
            and assignment_body["order_position"] == expected_order_position,
            f"step {expected_step}: assignment violates the public ordering schedule for rank {rank}",
        )
        ordering_proof = assignment_body.get("ordering_inclusion_proof")
        _require(
            isinstance(ordering_proof, dict)
            and ordering_proof.get("index") == expected_order_position,
            f"step {expected_step}: ordering proof position mismatch for rank {rank}",
        )
        verify_signature(
            coordinator,
            "worker-assignment/v1",
            assignment_body,
            assignment.get("signature"),
        )
        _require(
            verify_dataset_leaf(
                dataset,
                assignment_body.get("dataset_leaf_commitment"),
                assignment_body.get("dataset_inclusion_proof"),
            ),
            f"step {expected_step}: dataset inclusion proof failed for rank {rank}",
        )
        _require(
            verify_ordering_leaf(
                ordering,
                assignment_body.get("ordering_leaf_commitment"),
                ordering_proof,
            ),
            f"step {expected_step}: ordering inclusion proof failed for rank {rank}",
        )
        assignment_digest = hash_object("worker-assignment-record/v1", assignment).hex()
        receipt_body = receipt.get("body")
        _require_fields(
            receipt,
            {"body", "signature"},
            f"step {expected_step} receipt {rank}",
        )
        receipt_body = _require_fields(
            receipt_body,
            {
                "protocol",
                "run_id",
                "step",
                "rank",
                "worker_key_id",
                "assignment_digest",
                "pre_state",
                "update_commitment",
            },
            f"step {expected_step} receipt {rank} body",
        )
        _require(
            receipt_body.get("protocol") == PROTOCOL_VERSION
            and receipt_body.get("run_id") == run_id
            and receipt_body.get("step") == expected_step
            and receipt_body.get("worker_key_id") == worker["key_id"],
            f"step {expected_step}: receipt context mismatch",
        )
        _require(
            _plain_int(receipt_body.get("rank")) and receipt_body["rank"] == rank,
            f"step {expected_step}: receipt rank mismatch",
        )
        _require(
            receipt_body.get("assignment_digest") == assignment_digest,
            f"step {expected_step}: receipt assignment mismatch",
        )
        _require(
            receipt_body.get("pre_state") == expected_pre_state,
            f"step {expected_step}: receipt state mismatch",
        )
        verify_signature(
            worker, "worker-receipt/v1", receipt_body, receipt.get("signature")
        )
        assignment_leaves.append(hash_object("worker-assignment-record/v1", assignment))
        receipt_leaves.append(hash_object("worker-receipt-record/v1", receipt))
    _require(
        MerkleTree(ASSIGNMENT_TREE_DOMAIN, assignment_leaves).root.hex()
        == body.get("assignment_root"),
        f"step {expected_step}: assignment root mismatch",
    )
    _require(
        MerkleTree(RECEIPT_TREE_DOMAIN, receipt_leaves).root.hex()
        == body.get("worker_receipt_root"),
        f"step {expected_step}: receipt root mismatch",
    )
    proof = body.get("transition_proof")
    _require(
        proof
        == {
            "scheme": "private-deterministic-replay/v1",
            "publicly_verifiable": False,
            "zero_knowledge": False,
        },
        f"step {expected_step}: unknown transition-proof claim",
    )
    post_state = body.get("post_state")
    _require(
        isinstance(post_state, dict)
        and set(post_state) == {"model", "optimizer", "rng"},
        f"step {expected_step}: malformed post-state",
    )
    return post_state


def verify_bundle(
    run_dir: str | Path,
    source_root: str | Path | None = None,
    trust_policy: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(run_dir).resolve()
    checks: list[str] = []
    try:
        _verify_public_layout(root)
        bundle = _load_bundle(root)
        manifest = bundle["manifest"]
        _require_fields(manifest, {"body", "signature"}, "run manifest")
        manifest_body = _require_fields(
            manifest.get("body"),
            {
                "protocol",
                "run_id",
                "created_at",
                "dataset_statement_digest",
                "dataset_root",
                "ordering_statement_digest",
                "ordering_root",
                "source",
                "hyperparameters",
                "hyperparameters_root",
                "initial_state",
                "participants",
                "assurance_profile",
            },
            "run manifest body",
        )
        _require(
            manifest_body["protocol"] == PROTOCOL_VERSION, "manifest protocol mismatch"
        )
        _require(
            isinstance(manifest_body["run_id"], str)
            and len(manifest_body["run_id"]) == 32
            and all(
                character in "0123456789abcdef" for character in manifest_body["run_id"]
            ),
            "manifest run id must be 16 bytes of lowercase hexadecimal",
        )
        _require(
            _hex_digest(manifest_body["dataset_statement_digest"])
            and _hex_digest(manifest_body["dataset_root"])
            and _hex_digest(manifest_body["ordering_statement_digest"])
            and _hex_digest(manifest_body["ordering_root"]),
            "manifest roots and statement digests must be canonical SHA-256 values",
        )
        initial_state = _require_fields(
            manifest_body["initial_state"],
            {"model", "optimizer", "rng"},
            "manifest initial state",
        )
        _require(
            all(_hex_digest(value) for value in initial_state.values()),
            "manifest initial-state roots must be canonical SHA-256 values",
        )
        coordinator, custodian, operator, witness, workers = _validated_participants(
            manifest_body.get("participants")
        )
        _verify_published_key_documents(
            root,
            coordinator,
            custodian,
            operator,
            witness,
            workers,
        )
        identity_trust = (
            "not externally established; provide a verifier-controlled trust policy"
        )
        verify_signature(
            coordinator, "run-manifest/v1", manifest_body, manifest.get("signature")
        )
        manifest_digest = hash_object("run-manifest/v1", manifest_body).hex()
        run_id = manifest_body["run_id"]
        expected_assurance = {
            "public": "signed-commitment-transcript/v1",
            "private_audit": "deterministic-full-replay/v1",
            "zero_knowledge": False,
            "execution_correctness_publicly_proven": False,
            "identity_trust": "self-issued-demo-keys/v1",
            "external_time_anchor": False,
        }
        _require(
            manifest_body.get("assurance_profile") == expected_assurance,
            "manifest overstates or changes the implemented assurance profile",
        )
        hyperparameters = manifest_body.get("hyperparameters")
        _require_fields(
            hyperparameters,
            {
                "trainer",
                "numeric_semantics",
                "features",
                "workers",
                "batch_size",
                "steps",
                "learning_rate_numerator",
                "learning_rate_denominator",
                "aggregation",
            },
            "manifest hyperparameters",
        )
        _require(
            all(
                _plain_int(hyperparameters[name])
                for name in {
                    "features",
                    "workers",
                    "batch_size",
                    "steps",
                    "learning_rate_numerator",
                    "learning_rate_denominator",
                }
            ),
            "manifest numeric hyperparameters must be integers, not booleans",
        )
        _require(
            manifest_body.get("hyperparameters_root")
            == hash_object("hyperparameters/v1", hyperparameters).hex(),
            "hyperparameter commitment mismatch",
        )
        _require(
            hyperparameters.get("trainer") == "integer-linear-squared-error/v1"
            and hyperparameters.get("numeric_semantics")
            == "unbounded-signed-integer-exact/v1"
            and hyperparameters.get("features") == 2
            and hyperparameters.get("workers") == len(workers)
            and hyperparameters.get("batch_size") == len(workers)
            and hyperparameters.get("learning_rate_numerator") == 1
            and hyperparameters.get("learning_rate_denominator") == 1
            and hyperparameters.get("aggregation") == "rank-ordered-sum/v1",
            "unsupported or inconsistent training specification",
        )
        _require(
            validate_source_manifest(manifest_body.get("source")),
            "source artifact manifest is internally inconsistent",
        )
        checks.append("run manifest signature and distinct role-bound participant keys")

        verify_dataset_statement(bundle["dataset"], custodian)
        dataset_record_digest = hash_object(
            "dataset-statement-record/v1", bundle["dataset"]
        ).hex()
        _require(
            dataset_record_digest == manifest_body["dataset_statement_digest"],
            "dataset statement digest mismatch",
        )
        _require(
            bundle["dataset"]["body"]["sha256_root"] == manifest_body["dataset_root"],
            "manifest dataset root mismatch",
        )
        checks.append("signed hiding dataset commitment")

        verify_ordering_statement(bundle["ordering"], coordinator)
        ordering_record_digest = hash_object(
            "sample-order-statement-record/v1", bundle["ordering"]
        ).hex()
        _require(
            ordering_record_digest == manifest_body["ordering_statement_digest"],
            "ordering statement digest mismatch",
        )
        _require(
            bundle["ordering"]["body"]["root"] == manifest_body["ordering_root"],
            "manifest ordering root mismatch",
        )
        _require(
            bundle["ordering"]["body"]["record_count"]
            == bundle["dataset"]["body"]["record_count"],
            "dataset and ordering cardinalities differ",
        )
        checks.append("signed sample-order commitment")

        genesis = bundle["genesis"]
        _require_fields(genesis, {"body", "commitment", "signature"}, "run genesis")
        genesis_body = genesis.get("body")
        expected_genesis = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "manifest_digest": manifest_digest,
            "dataset_statement_digest": manifest_body["dataset_statement_digest"],
            "ordering_statement_digest": manifest_body["ordering_statement_digest"],
            "initial_state": manifest_body["initial_state"],
        }
        _require(genesis_body == expected_genesis, "genesis body mismatch")
        genesis_commitment = hash_object("run-genesis/v1", genesis_body).hex()
        _require(
            genesis.get("commitment") == genesis_commitment,
            "genesis commitment mismatch",
        )
        verify_signature(
            coordinator, "run-genesis/v1", genesis_body, genesis.get("signature")
        )
        checks.append("signed genesis")

        steps = bundle["steps"]
        _require(isinstance(steps, list) and steps, "training chain is empty")
        _require(
            hyperparameters.get("steps") == len(steps), "manifest step count mismatch"
        )
        previous = genesis_commitment
        state = manifest_body["initial_state"]
        for index, step in enumerate(steps):
            state = _verify_step(
                step,
                expected_step=index,
                expected_previous=previous,
                expected_pre_state=state,
                manifest_digest=manifest_digest,
                run_id=run_id,
                dataset=bundle["dataset"],
                ordering=bundle["ordering"],
                coordinator=coordinator,
                workers=workers,
            )
            previous = step["step_commitment"]
        checks.append(f"{len(steps)} signed chained distributed steps")

        checkpoint = bundle["checkpoint"]
        _require_fields(
            checkpoint,
            {
                "protocol",
                "run_id",
                "step_count",
                "final_step_commitment",
                "model",
                "optimizer",
                "rng",
                "state_roots",
            },
            "checkpoint",
        )
        model = _require_fields(
            checkpoint["model"], {"weights", "bias"}, "checkpoint model"
        )
        _require(
            isinstance(model["weights"], list)
            and len(model["weights"]) == 2
            and all(_plain_int(value) for value in model["weights"])
            and _plain_int(model["bias"]),
            "checkpoint model must contain two integer weights and one integer bias",
        )
        _require(
            checkpoint["optimizer"] == {"kind": "integer-sgd/v1", "step": len(steps)},
            "checkpoint optimizer semantics mismatch",
        )
        _require(
            checkpoint["rng"]
            == {
                "kind": "committed-sampler-counter/v1",
                "seed_commitment": bundle["ordering"]["body"]["seed_commitment"],
                "counter": len(steps),
            },
            "checkpoint RNG semantics mismatch",
        )
        _require(
            _plain_int(checkpoint["step_count"]),
            "checkpoint step count must be an integer",
        )
        _require(
            checkpoint.get("protocol") == PROTOCOL_VERSION,
            "checkpoint protocol mismatch",
        )
        _require(checkpoint.get("run_id") == run_id, "checkpoint run mismatch")
        _require(
            checkpoint.get("step_count") == len(steps), "checkpoint step count mismatch"
        )
        _require(
            checkpoint.get("final_step_commitment") == previous,
            "checkpoint chain head mismatch",
        )
        actual_checkpoint_roots = state_roots(
            checkpoint["model"], checkpoint["optimizer"], checkpoint["rng"]
        )
        _require(
            checkpoint.get("state_roots") == actual_checkpoint_roots == state,
            "checkpoint state root mismatch",
        )
        checkpoint_digest = hash_object("checkpoint/v1", checkpoint).hex()
        checks.append("exact checkpoint binding")

        log = bundle["log"]
        verify_log(log, operator, witness)
        _require(log["log_id"] == f"demo-log/{run_id}", "transparency log id mismatch")
        expected_subjects = [
            ("dataset-statement", manifest_body["dataset_statement_digest"]),
            ("ordering-statement", manifest_body["ordering_statement_digest"]),
            ("run-genesis", genesis_commitment),
            *[("training-step", step["step_commitment"]) for step in steps],
        ]
        checkpoint_anchor = hash_object(
            "checkpoint-anchor/v1",
            {
                "run_id": run_id,
                "final_step_commitment": previous,
                "checkpoint_digest": checkpoint_digest,
            },
        ).hex()
        expected_subjects.append(("checkpoint", checkpoint_anchor))
        actual_subjects = [
            (entry["kind"], entry["subject_digest"]) for entry in log["entries"]
        ]
        _require(
            actual_subjects == expected_subjects, "transparency log subjects mismatch"
        )
        checks.append("witnessed append-only transparency log")

        certificate = bundle["certificate"]
        _require_fields(
            certificate,
            {"body", "coordinator_signature", "witness_signature"},
            "checkpoint certificate",
        )
        certificate_body = certificate.get("body")
        _require(isinstance(certificate_body, dict), "malformed certificate")
        verify_signature(
            coordinator,
            "checkpoint-certificate/v1",
            certificate_body,
            certificate.get("coordinator_signature"),
        )
        verify_signature(
            witness,
            "checkpoint-certificate/v1",
            certificate_body,
            certificate.get("witness_signature"),
        )
        head_digest = hash_object("transparency-head/v1", final_head(log)["body"]).hex()
        expected_certificate_fields = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "manifest_digest": manifest_digest,
            "genesis_commitment": genesis_commitment,
            "step_count": len(steps),
            "final_step_commitment": previous,
            "checkpoint_digest": checkpoint_digest,
            "checkpoint_state_roots": state,
            "checkpoint_anchor": checkpoint_anchor,
            "checkpoint_log_index": len(log["entries"]) - 1,
            "transparency_head_digest": head_digest,
            "transparency_inclusion_proof": certificate_body.get(
                "transparency_inclusion_proof"
            ),
            "assurance": manifest_body["assurance_profile"],
        }
        _require(
            certificate_body == expected_certificate_fields,
            "certificate fields mismatch",
        )
        _require(
            verify_inclusion(
                log,
                certificate_body["checkpoint_log_index"],
                certificate_body["transparency_inclusion_proof"],
            ),
            "checkpoint transparency inclusion proof failed",
        )
        checks.append("coordinator- and witness-signed certificate")

        if trust_policy is not None:
            source = manifest_body["source"]
            verify_trust_policy(
                trust_policy,
                {
                    "dataset_custodian": custodian["key_id"],
                    "coordinator": coordinator["key_id"],
                    "log_operator": operator["key_id"],
                    "log_witness": witness["key_id"],
                    "workers": [worker["key_id"] for worker in workers],
                },
                {
                    "run_id": run_id,
                    "dataset_root": manifest_body["dataset_root"],
                    "ordering_root": manifest_body["ordering_root"],
                    "source_root": source["root"],
                    "source_git_commit": source["git"]["commit"],
                    "source_git_dirty": source["git"]["dirty"],
                    "hyperparameters_root": manifest_body["hyperparameters_root"],
                    "genesis_commitment": genesis_commitment,
                    "step_count": len(steps),
                    "final_step_commitment": previous,
                    "checkpoint_digest": checkpoint_digest,
                },
            )
            identity_trust = "participant keys and expected run claims matched the verifier-supplied trust policy"
            checks.append("verifier-supplied participant and run-claim trust policy")

        if source_root is not None:
            _require(
                verify_source_manifest(source_root, manifest_body["source"]),
                "source tree does not match manifest",
            )
            checks.append("source artifact tree")

        return {
            "valid": True,
            "run_id": run_id,
            "checkpoint_digest": checkpoint_digest,
            "final_step_commitment": previous,
            "checks": checks,
            "assurance": {
                "transcript_integrity": "cryptographically verified",
                "participant_attribution": "signatures verified against self-issued manifest keys",
                "identity_trust": identity_trust,
                "witness_independence": "key separation verified; organizational independence not established",
                "external_timing": "not established by the bundle-local witness or timestamps",
                "training_execution": "not publicly proven; private replay checks satisfiability, while a sound ZK backend can prove its circuit relation",
                "data_privacy": "public bundle contains salted commitments, not records",
            },
        }
    except Exception as exc:
        return {"valid": False, "checks": checks, "errors": [str(exc)]}


def audit_bundle(
    run_dir: str | Path,
    source_root: str | Path | None = None,
    trust_policy: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(run_dir).resolve()
    public_report = verify_bundle(
        root, source_root=source_root, trust_policy=trust_policy
    )
    if not public_report["valid"]:
        return {
            "valid": False,
            "phase": "public-verification",
            "errors": public_report.get("errors", ["public verification failed"]),
        }
    try:
        bundle = _load_bundle(root)
        dataset_private = read_json(root / "private" / "dataset.openings.json")
        ordering_private = read_json(root / "private" / "ordering.openings.json")
        trace = read_json(root / "private" / "trace.json")
        records = verify_dataset_openings(bundle["dataset"], dataset_private)
        order = verify_ordering_openings(bundle["ordering"], ordering_private)
        _require(
            trace.get("run_id") == public_report["run_id"], "private trace run mismatch"
        )
        model, optimizer, rng = _validated_replay_genesis(bundle, trace, records, order)
        manifest_initial = bundle["manifest"]["body"]["initial_state"]
        _require(
            state_roots(model, optimizer, rng) == manifest_initial,
            "private genesis does not open public state",
        )
        public_steps = bundle["steps"]
        private_steps = trace.get("steps")
        _require(
            isinstance(private_steps, list) and len(private_steps) == len(public_steps),
            "private step count mismatch",
        )
        for step_number, (public_step, private_step) in enumerate(
            zip(public_steps, private_steps, strict=True)
        ):
            _require(
                private_step.get("step") == step_number,
                f"audit step {step_number}: number mismatch",
            )
            _require(
                private_step.get("model_before") == model,
                f"audit step {step_number}: model predecessor mismatch",
            )
            _require(
                private_step.get("optimizer_before") == optimizer,
                f"audit step {step_number}: optimizer predecessor mismatch",
            )
            _require(
                private_step.get("rng_before") == rng,
                f"audit step {step_number}: RNG predecessor mismatch",
            )
            worker_traces = private_step.get("workers")
            assignments = public_step["body"]["assignments"]
            receipts = public_step["body"]["worker_receipts"]
            _require(
                len(worker_traces) == len(assignments),
                f"audit step {step_number}: worker count mismatch",
            )
            updates: list[dict[str, Any]] = []
            for rank, (worker_trace, assignment, receipt) in enumerate(
                zip(worker_traces, assignments, receipts, strict=True)
            ):
                expected_position = (step_number * len(assignments) + rank) % len(order)
                expected_index = order[expected_position]
                _require(
                    worker_trace.get("rank") == rank,
                    f"audit step {step_number}: worker rank mismatch",
                )
                _require(
                    worker_trace.get("order_position") == expected_position,
                    f"audit step {step_number}: order position mismatch",
                )
                _require(
                    worker_trace.get("dataset_index") == expected_index,
                    f"audit step {step_number}: dataset index mismatch",
                )
                assignment_body = assignment["body"]
                _require(
                    assignment_body["order_position"] == expected_position,
                    f"audit step {step_number}: public order position mismatch",
                )
                _require(
                    assignment_body["dataset_leaf_commitment"]
                    == bundle["dataset"]["body"]["leaf_commitments"][expected_index],
                    f"audit step {step_number}: public dataset leaf is not scheduled leaf",
                )
                _require(
                    assignment_body["ordering_leaf_commitment"]
                    == bundle["ordering"]["body"]["leaf_commitments"][
                        expected_position
                    ],
                    f"audit step {step_number}: public ordering leaf mismatch",
                )
                expected_update = compute_worker_update(model, records[expected_index])
                opening = worker_trace["update_opening"]
                _require(
                    opening.get("value") == expected_update,
                    f"audit step {step_number}: worker update is incorrect",
                )
                try:
                    update_salt = bytes.fromhex(opening.get("salt", ""))
                except (TypeError, ValueError) as exc:
                    raise VerificationError(
                        f"audit step {step_number}: invalid worker update salt"
                    ) from exc
                _require(
                    len(update_salt) == 32,
                    f"audit step {step_number}: worker update salt is not 32 bytes",
                )
                _require(
                    hash_object("worker-update-commitment/v1", opening).hex()
                    == receipt["body"]["update_commitment"],
                    f"audit step {step_number}: worker update opening mismatch",
                )
                updates.append(expected_update)
            aggregate = aggregate_updates(updates)
            aggregate_opening = private_step["aggregate_opening"]
            _require(
                aggregate_opening.get("value") == aggregate,
                f"audit step {step_number}: aggregate is incorrect",
            )
            try:
                aggregate_salt = bytes.fromhex(aggregate_opening.get("salt", ""))
            except (TypeError, ValueError) as exc:
                raise VerificationError(
                    f"audit step {step_number}: invalid aggregate salt"
                ) from exc
            _require(
                len(aggregate_salt) == 32,
                f"audit step {step_number}: aggregate salt is not 32 bytes",
            )
            _require(
                hash_object("aggregate-update-commitment/v1", aggregate_opening).hex()
                == public_step["body"]["aggregate_update_commitment"],
                f"audit step {step_number}: aggregate opening mismatch",
            )
            model_after = apply_update(model, aggregate)
            optimizer_after = {**optimizer, "step": step_number + 1}
            rng_after = {**rng, "counter": step_number + 1}
            _require(
                private_step.get("model_after") == model_after,
                f"audit step {step_number}: model transition is incorrect",
            )
            _require(
                private_step.get("optimizer_after") == optimizer_after,
                f"audit step {step_number}: optimizer transition is incorrect",
            )
            _require(
                private_step.get("rng_after") == rng_after,
                f"audit step {step_number}: RNG transition is incorrect",
            )
            _require(
                state_roots(model_after, optimizer_after, rng_after)
                == public_step["body"]["post_state"],
                f"audit step {step_number}: state commitment mismatch",
            )
            model, optimizer, rng = model_after, optimizer_after, rng_after
        checkpoint = bundle["checkpoint"]
        _require(
            checkpoint["model"] == model, "audited model does not match checkpoint"
        )
        _require(
            checkpoint["optimizer"] == optimizer,
            "audited optimizer does not match checkpoint",
        )
        _require(checkpoint["rng"] == rng, "audited RNG does not match checkpoint")
        return {
            "valid": True,
            "run_id": public_report["run_id"],
            "steps_replayed": len(public_steps),
            "records_opened": len(records),
            "assurance": {
                "transition_satisfiability": "all committed transitions satisfy the deterministic replay relation",
                "historical_execution": "not established; a valid replay is not evidence that these operations occurred historically",
                "source_binding": (
                    "verified against the caller-supplied source tree"
                    if source_root is not None
                    else "not checked; pass source_root or --source to bind replay to source artifacts"
                ),
                "data_privacy": "not preserved against this auditor; auditor received private openings",
                "public_zero_knowledge": False,
            },
        }
    except Exception as exc:
        return {"valid": False, "phase": "private-replay", "errors": [str(exc)]}
