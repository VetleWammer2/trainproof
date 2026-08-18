"""Seal and independently verify the concrete Circom/PLONK demonstration."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .canonical import hash_bytes, hash_object, read_json, write_json
from .constants import BN254_BASE_FIELD, BN254_PRIME, PROTOCOL_VERSION
from .crypto import generate_keypair, sign_object, verify_signature
from .transparency import (
    append_entry,
    final_head,
    inclusion_proof,
    new_log,
    verify_inclusion,
    verify_log,
)
from .trust import policy_document, verify_trust_policy

PUBLIC_SIGNAL_ORDER = [
    "initialStep",
    "transitionCount",
    "datasetRoot",
    "orderingRoot",
    "codeCommitment",
    "hyperparametersCommitment",
    "initialStateCommitment",
    "finalStateCommitment",
    "initialChain",
    "finalChain",
]

PTAU_FILE = "powersOfTau28_hez_final_16.ptau"
PTAU_BLAKE2B = (
    "6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf4"
    "3eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125"
)
CIRCOM_SHA256 = "e43f132ee6f0aa79b705beceb59c2a7e6a54d7bdeab917ca34e9fc1951d185e1"
ZK_CIRCUIT_SHA256 = "64442e1374f5451dc145247dded0d220559a6f465cbb907c8860a7b6c5f9b3d3"
ZK_R1CS_SHA256 = "a87715bfe95e28562cfe5a08fc9edf1d76ba1f12a7b0a0fcca4b1afa3dc72de1"
ZK_SCHEME = "circom-2.2.3/snarkjs-0.7.6/plonk-bn254/v2"
ZK_N_STEPS = 4
ZK_FEATURE_COUNT = 2
ZK_DATASET_DEPTH = 2
ZK_ORDERING_DEPTH = 4
ZK_RELATION = "bounded-fixed-point-linear-training-chain/n=4/v2"
ZK_ARITHMETIC = (
    "signed 16-bit offset fixed point at scale 256 with floor rescaling and "
    "checked overflow"
)
ZK_FIELD_COMMITMENT_MAPPING = "unsigned-big-endian-sha256-mod-bn254/v1"
ZK_RUN_COMMITMENT_MAPPING = "sha256-utf8-prefix-and-run-id-mod-bn254/v2"
ZK_HYPERPARAMETERS_SPEC = (
    "fixed-point-linear-sgd/scale=256/raw=s16-offset-binary/round=floor/"
    "overflow=reject/features=2/lr-raw=16/n=4/dataset-depth=2/order-depth=4/v2"
)
ZK_FIXED_POINT_SPEC = {
    "scale": 256,
    "fractionalBits": 8,
    "rawRange": {"minimum": -32768, "maximum": 32767},
    "realRange": {"minimumInclusive": "-128", "maximumInclusive": "32767/256"},
    "encoding": "offset-binary-u16: encoded=raw+32768",
    "multiplication": (
        "exact signed raw integer multiplication; two-feature dot product "
        "accumulated before rescaling"
    ),
    "rescaling": "q=floor(n/256), n=256*q+r, 0<=r<256",
    "rounding": "toward-negative-infinity",
    "overflow": (
        "relation-unsatisfied for any fixed-point input, named intermediate, "
        "or state outside signed-16; counter outside unsigned-32"
    ),
    "fieldEmbedding": (
        "encoded values are canonical integers in [0,65535] in BN254; decoded "
        "arithmetic is encoded-32768"
    ),
    "learningRate": {"raw": 16, "exact": "1/16"},
    "referenceImplementation": "src/trainproof/fixed_point.py",
}
ZK_CIRCUIT_PROFILE = {
    "nSteps": ZK_N_STEPS,
    "featureCount": ZK_FEATURE_COUNT,
    "datasetDepth": ZK_DATASET_DEPTH,
    "orderingDepth": ZK_ORDERING_DEPTH,
}
ZK_PRIVATE_WITNESS_SUMMARY = {
    "datasetSize": 4,
    "orderingLength": 16,
    "transitionCount": ZK_N_STEPS,
    "featureCount": ZK_FEATURE_COUNT,
    "revealedTrainingRecords": 0,
}
ZK_CLAIMS = {
    "privateDatasetMembershipForEveryTransition": True,
    "privateOrderingMembershipForEveryTransition": True,
    "consecutiveOrderingPositions": True,
    "initialStateOpening": True,
    "intermediateStateContinuity": True,
    "deterministicFixedPointTransitions": True,
    "finalStateOpening": True,
    "poseidonTransitionChain": True,
    "checkpointOpening": True,
    "unbiasedOrPermutationOrdering": False,
    "historicalExecution": False,
    "pytorchOrIeeeFloatingPoint": False,
}
ZK_ASSURANCE = {
    "zero_knowledge_transitions": ZK_N_STEPS,
    "private_dataset_membership_for_every_transition": True,
    "private_sample_order_membership_for_every_transition": True,
    "consecutive_ordering_positions": True,
    "fixed_point_reference_equivalence": "bounded domain defined by fixedPointSpec",
    "arithmetic": ZK_ARITHMETIC,
    "pytorch_or_ieee_floating_point": False,
    "historical_execution": False,
    "participant_identity": "self-issued demo keys unless verifier pins a trust policy",
    "external_time_anchor": False,
}


class ZkError(ValueError):
    """Raised for invalid or incomplete ZK artifacts."""


def _validate_output_location(root: Path, project_root: Path) -> None:
    """Keep generated private material out of unignored source paths."""

    try:
        relative = root.relative_to(project_root)
    except ValueError:
        return
    if relative != Path("zk") / "demo-run":
        raise ZkError(
            "inside the source repository, ZK output is restricted to the fixed "
            "excluded path zk/demo-run; use a path outside the repository otherwise"
        )


def _raw_file_digest(domain: str, path: Path) -> str:
    return hash_bytes(domain, path.read_bytes()).hex()


def _sha256_field(payload: bytes) -> int:
    return int.from_bytes(hashlib.sha256(payload).digest(), "big") % BN254_PRIME


def _require_exact_keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ZkError(f"{label} has unexpected or missing fields")


def _canonical_field(value: Any, label: str, *, maximum: int = BN254_PRIME) -> int:
    if not isinstance(value, str):
        raise ZkError(f"{label} is not a decimal string")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ZkError(f"{label} is not a decimal field element") from exc
    if str(parsed) != value or not 0 <= parsed < maximum:
        raise ZkError(f"{label} is not a canonical in-range field element")
    return parsed


def _expected_run_commitment(run_id: str) -> int:
    return _sha256_field(
        b"trainproof-zk-run/fixed-point-v2\0" + run_id.encode("ascii")
    )


def _validate_statement(statement: Any) -> dict[str, Any]:
    _require_exact_keys(
        statement,
        {
            "scheme",
            "relation",
            "arithmetic",
            "fieldCommitmentMapping",
            "fixedPointSpec",
            "circuitProfile",
            "hyperparametersSpec",
            "runId",
            "runCommitmentMapping",
            "publicInputs",
            "claims",
            "privateWitnessSummary",
            "circuitSha256",
        },
        "ZK statement",
    )
    if (
        statement["scheme"] != "circom-plonk-bn254/v2"
        or statement["relation"] != ZK_RELATION
        or statement["arithmetic"] != ZK_ARITHMETIC
        or statement["fieldCommitmentMapping"] != ZK_FIELD_COMMITMENT_MAPPING
        or statement["fixedPointSpec"] != ZK_FIXED_POINT_SPEC
        or statement["circuitProfile"] != ZK_CIRCUIT_PROFILE
        or statement["hyperparametersSpec"] != ZK_HYPERPARAMETERS_SPEC
        or statement["runCommitmentMapping"] != ZK_RUN_COMMITMENT_MAPPING
        or statement["privateWitnessSummary"] != ZK_PRIVATE_WITNESS_SUMMARY
        or statement["claims"] != ZK_CLAIMS
        or statement["circuitSha256"] != ZK_CIRCUIT_SHA256
    ):
        raise ZkError("statement claims do not match the audited circuit profile")
    run_id = statement["runId"]
    if (
        not isinstance(run_id, str)
        or len(run_id) != 32
        or any(character not in "0123456789abcdef" for character in run_id)
    ):
        raise ZkError("statement run id must be 16 bytes of lowercase hexadecimal")
    named = statement["publicInputs"]
    _require_exact_keys(named, set(PUBLIC_SIGNAL_ORDER), "statement public inputs")
    for name in PUBLIC_SIGNAL_ORDER:
        _canonical_field(named[name], f"public input {name}")
    initial_step = int(named["initialStep"])
    if int(named["transitionCount"]) != ZK_N_STEPS:
        raise ZkError("public transition count does not match the circuit profile")
    if initial_step < 0 or initial_step + ZK_N_STEPS > 1 << ZK_ORDERING_DEPTH:
        raise ZkError("public step interval is outside the ordering-tree profile")
    if int(named["initialChain"]) != _expected_run_commitment(run_id):
        raise ZkError("Poseidon chain genesis is not bound to the statement run id")
    return statement


def _state_commitment(project_root: Path, opening: Any) -> str:
    _require_exact_keys(opening, {"w", "b", "counter", "salt"}, "checkpoint opening")
    weights = opening["w"]
    if not isinstance(weights, list) or len(weights) != ZK_FEATURE_COUNT:
        raise ZkError("checkpoint w must contain exactly two encoded values")
    for index, value in enumerate(weights):
        _canonical_field(value, f"checkpoint w[{index}]", maximum=1 << 16)
    _canonical_field(opening["b"], "checkpoint b", maximum=1 << 16)
    _canonical_field(opening["counter"], "checkpoint counter", maximum=1 << 32)
    _canonical_field(opening["salt"], "checkpoint salt")
    node = shutil.which("node") or shutil.which("node.exe")
    if node is None:
        raise ZkError("Node.js is required to verify the Poseidon checkpoint opening")
    output = _run_checked(
        [
            node,
            str(project_root / "zk" / "scripts" / "state-commitment.mjs"),
            opening["w"][0],
            opening["w"][1],
            opening["b"],
            opening["counter"],
            opening["salt"],
        ],
        cwd=project_root,
        label="checkpoint Poseidon opening",
    )
    if not output or "\n" in output or "\r" in output:
        raise ZkError("unexpected Poseidon checkpoint helper output")
    _canonical_field(output, "computed checkpoint commitment")
    return output


def _snarkjs(project_root: Path) -> str:
    names = (
        ["snarkjs.cmd", "snarkjs"] if os.name == "nt" else ["snarkjs", "snarkjs.cmd"]
    )
    for name in names:
        candidate = project_root / "node_modules" / ".bin" / name
        if candidate.is_file():
            return str(candidate)
    raise ZkError("the pinned local snarkjs installation is required; run npm install")


def _circom(project_root: Path) -> Path:
    candidate = project_root / "tools" / "circom.exe"
    if not candidate.is_file():
        raise ZkError(
            "the pinned Circom 2.2.3 binary is required; run bootstrap-zk.ps1"
        )
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != CIRCOM_SHA256:
        raise ZkError("Circom executable checksum mismatch")
    return candidate


def _run_checked(
    command: list[str], *, cwd: Path, label: str, timeout: int = 120
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0:
        raise ZkError(f"{label} failed: {output}")
    return output


def _validate_plonk_proof(proof: Any) -> dict[str, Any]:
    point_names = {"A", "B", "C", "Z", "T1", "T2", "T3", "Wxi", "Wxiw"}
    evaluation_names = {"eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw"}
    _require_exact_keys(
        proof,
        point_names | evaluation_names | {"protocol", "curve"},
        "PLONK proof",
    )
    if proof["protocol"] != "plonk" or proof["curve"] != "bn128":
        raise ZkError("PLONK proof protocol or curve mismatch")
    for name in point_names:
        point = proof[name]
        if not isinstance(point, list) or len(point) != 3:
            raise ZkError(f"PLONK proof point {name} must have three coordinates")
        _canonical_field(point[0], f"PLONK proof {name}.x", maximum=BN254_BASE_FIELD)
        _canonical_field(point[1], f"PLONK proof {name}.y", maximum=BN254_BASE_FIELD)
        if point[2] != "1":
            raise ZkError(f"PLONK proof point {name} must use canonical affine form")
    for name in evaluation_names:
        _canonical_field(proof[name], f"PLONK proof {name}")
    return proof


def verify_plonk_files(public_dir: Path, project_root: Path) -> str:
    _validate_plonk_proof(read_json(public_dir / "proof.json"))
    output = _run_checked(
        [
            _snarkjs(project_root),
            "plonk",
            "verify",
            str(public_dir / "verification_key.json"),
            str(public_dir / "public.json"),
            str(public_dir / "proof.json"),
        ],
        cwd=project_root,
        label="PLONK verification",
    )
    if "OK!" not in output:
        raise ZkError(f"PLONK verification failed: {output}")
    return output


def verify_toolchain_linkage(public_dir: Path, project_root: Path) -> dict[str, str]:
    """Rebuild every deterministic link from audited source to bundled VK.

    snarkjs does not expose ``zkey verify`` for PLONK.  Its PLONK setup is
    deterministic for a fixed R1CS and Powers-of-Tau file, so we recreate the
    zkey, export its verification key, and compare that object exactly.
    """

    circuit = public_dir / "train_step.circom"
    r1cs = public_dir / "train_step.r1cs"
    verification_key = public_dir / "verification_key.json"
    for path in [circuit, r1cs, verification_key]:
        if not path.is_file():
            raise ZkError(f"missing public toolchain artifact: {path.name}")
    circuit_bytes = circuit.read_bytes()
    r1cs_bytes = r1cs.read_bytes()
    if hashlib.sha256(circuit_bytes).hexdigest() != ZK_CIRCUIT_SHA256:
        raise ZkError("circuit source is not the pinned audited relation")
    if hashlib.sha256(r1cs_bytes).hexdigest() != ZK_R1CS_SHA256:
        raise ZkError("R1CS is not the pinned audited relation")
    repository_circuit = project_root / "zk" / "circuits" / "train_step.circom"
    if (
        not repository_circuit.is_file()
        or repository_circuit.read_bytes() != circuit_bytes
    ):
        raise ZkError("public circuit differs from the verifier's audited circuit")
    ptau = project_root / "zk" / "build" / PTAU_FILE
    if not ptau.is_file():
        raise ZkError(f"missing trusted setup file: {PTAU_FILE}")
    if hashlib.blake2b(ptau.read_bytes()).hexdigest() != PTAU_BLAKE2B:
        raise ZkError("Powers-of-Tau file does not match the pinned BLAKE2b hash")

    with tempfile.TemporaryDirectory(prefix="trainproof-zk-link-") as temporary:
        temporary_root = Path(temporary)
        _run_checked(
            [
                str(_circom(project_root)),
                str(circuit),
                "--r1cs",
                "--inspect",
                "-l",
                str(project_root / "node_modules"),
                "-o",
                str(temporary_root),
            ],
            cwd=project_root,
            label="deterministic circuit compilation",
        )
        rebuilt_r1cs = temporary_root / "train_step.r1cs"
        if not rebuilt_r1cs.is_file() or rebuilt_r1cs.read_bytes() != r1cs_bytes:
            raise ZkError(
                "published R1CS was not compiled from the pinned circuit source"
            )
        rebuilt_zkey = temporary_root / "train_step.zkey"
        rebuilt_vk = temporary_root / "verification_key.json"
        snarkjs = _snarkjs(project_root)
        _run_checked(
            [snarkjs, "plonk", "setup", str(r1cs), str(ptau), str(rebuilt_zkey)],
            cwd=project_root,
            label="deterministic PLONK setup",
        )
        _run_checked(
            [
                snarkjs,
                "zkey",
                "export",
                "verificationkey",
                str(rebuilt_zkey),
                str(rebuilt_vk),
            ],
            cwd=project_root,
            label="verification-key derivation",
        )
        if read_json(rebuilt_vk) != read_json(verification_key):
            raise ZkError(
                "verification key is not derived from the published R1CS and PoT"
            )
    return {
        "circuit_sha256": ZK_CIRCUIT_SHA256,
        "r1cs_sha256": ZK_R1CS_SHA256,
        "ptau_blake2b": PTAU_BLAKE2B,
        "verification_key_linkage": "rederived",
    }


def _verify_named_public_signals(
    statement: dict[str, Any], public_signals: Any
) -> None:
    if not isinstance(public_signals, list) or len(public_signals) != len(
        PUBLIC_SIGNAL_ORDER
    ):
        raise ZkError("unexpected PLONK public-signal count")
    named = statement.get("publicInputs")
    if not isinstance(named, dict) or set(named) != set(PUBLIC_SIGNAL_ORDER):
        raise ZkError("statement public inputs do not match fixed-point circuit v2")
    for name, actual in zip(PUBLIC_SIGNAL_ORDER, public_signals, strict=True):
        try:
            expected_text = named[name]
            actual_text = actual
            if (
                not isinstance(expected_text, str)
                or not isinstance(actual_text, str)
                or str(int(expected_text)) != expected_text
                or str(int(actual_text)) != actual_text
            ):
                raise ValueError("non-canonical decimal field element")
            expected_field = int(expected_text)
            actual_field = int(actual_text)
        except (TypeError, ValueError) as exc:
            raise ZkError(f"invalid field element for {name}") from exc
        if not 0 <= expected_field < BN254_PRIME or not 0 <= actual_field < BN254_PRIME:
            raise ZkError(f"out-of-range field element for {name}")
        if actual_field != expected_field:
            raise ZkError(f"public signal mismatch for {name}")


def _trusted_setup_claim() -> dict[str, Any]:
    return {
        "file": PTAU_FILE,
        "published_blake2b": PTAU_BLAKE2B,
        "local_file_hash_verified": True,
        "circuit_recompiled_and_r1cs_matched": True,
        "verification_key_rederived_from_r1cs_and_ptau": True,
        "full_contribution_transcript_audited_in_default_bootstrap": False,
    }


def _precommit_digests(
    public_dir: Path,
    statement: dict[str, Any],
    dataset_statement: dict[str, Any],
    ordering_statement: dict[str, Any],
    checkpoint: dict[str, Any],
    verification_key: dict[str, Any],
) -> dict[str, str]:
    return {
        "statement": hash_object("zk-statement/v1", statement).hex(),
        "dataset_statement": hash_object(
            "zk-dataset-statement-record/v1", dataset_statement
        ).hex(),
        "ordering_statement": hash_object(
            "zk-ordering-statement-record/v1", ordering_statement
        ).hex(),
        "checkpoint": hash_object("zk-checkpoint/v1", checkpoint).hex(),
        "verification_key": hash_object(
            "zk-verification-key/v1", verification_key
        ).hex(),
        "circuit_source": _raw_file_digest(
            "zk-circuit-source/v1", public_dir / "train_step.circom"
        ),
        "r1cs": _raw_file_digest("zk-r1cs/v1", public_dir / "train_step.r1cs"),
    }


def precommit_zk_demo(
    output_dir: str | Path, project_root: str | Path
) -> dict[str, Any]:
    """Create a witnessed run genesis before witness/proof generation."""

    root = Path(output_dir).resolve()
    project = Path(project_root).resolve()
    _validate_output_location(root, project)
    public_dir = root / "public"
    private_dir = root / "private"
    build_dir = project / "zk" / "build"
    if (public_dir / "precommit.json").exists() or (
        public_dir / "certificate.json"
    ).exists():
        raise ZkError("ZK run is already precommitted or sealed")
    for path in [
        public_dir / "statement.json",
        private_dir / "checkpoint.opening.json",
        project / "zk" / "circuits" / "train_step.circom",
        build_dir / "train_step.r1cs",
        build_dir / "verification_key.json",
        build_dir / PTAU_FILE,
    ]:
        if not path.is_file():
            raise ZkError(f"missing precommit artifact: {path}")
    statement = _validate_statement(read_json(public_dir / "statement.json"))
    circuit_source = project / "zk" / "circuits" / "train_step.circom"
    if int(statement["publicInputs"]["codeCommitment"]) != _sha256_field(
        circuit_source.read_bytes()
    ):
        raise ZkError("public code commitment does not match the pinned circuit source")
    if int(statement["publicInputs"]["hyperparametersCommitment"]) != _sha256_field(
        ZK_HYPERPARAMETERS_SPEC.encode("utf-8")
    ):
        raise ZkError(
            "public hyperparameter commitment does not match its specification"
        )
    shutil.copy2(circuit_source, public_dir / "train_step.circom")
    shutil.copy2(build_dir / "train_step.r1cs", public_dir / "train_step.r1cs")
    shutil.copy2(
        build_dir / "verification_key.json", public_dir / "verification_key.json"
    )
    verify_toolchain_linkage(public_dir, project)

    run_id = statement["runId"]
    opening = read_json(private_dir / "checkpoint.opening.json")
    computed_state_commitment = _state_commitment(project, opening)
    if computed_state_commitment != statement["publicInputs"]["finalStateCommitment"]:
        raise ZkError(
            "checkpoint opening does not match the proof's final-state commitment"
        )
    initial_step = int(statement["publicInputs"]["initialStep"])
    next_step = initial_step + ZK_N_STEPS
    if int(opening["counter"]) != next_step:
        raise ZkError("checkpoint counter does not equal initialStep + transitionCount")
    checkpoint = {
        "body": {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "format": "fixed-point-linear-state/offset-binary-s16-scale-256/v2",
            "relation": ZK_RELATION,
            "initial_step": initial_step,
            "transition_count": ZK_N_STEPS,
            "next_step": next_step,
            "state": opening,
            "state_commitment": computed_state_commitment,
            "poseidon_domain": 204,
        }
    }
    write_json(public_dir / "checkpoint.json", checkpoint)

    key_dir_private = private_dir / "keys"
    key_dir_public = public_dir / "keys"
    custodian = generate_keypair(
        key_dir_private / "custodian.private.json",
        key_dir_public / "custodian.public.json",
        "zk-dataset-custodian",
    )
    coordinator = generate_keypair(
        key_dir_private / "coordinator.private.json",
        key_dir_public / "coordinator.public.json",
        "zk-proof-coordinator",
    )
    operator = generate_keypair(
        key_dir_private / "log-operator.private.json",
        key_dir_public / "log-operator.public.json",
        "zk-transparency-log-operator",
    )
    witness = generate_keypair(
        key_dir_private / "witness.private.json",
        key_dir_public / "witness.public.json",
        "zk-independent-log-witness",
    )
    custodian_private = key_dir_private / "custodian.private.json"
    coordinator_private = key_dir_private / "coordinator.private.json"
    operator_private = key_dir_private / "log-operator.private.json"
    witness_private = key_dir_private / "witness.private.json"

    dataset_statement_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "dataset_id": f"zk-demo-private-dataset/{run_id}",
        "scheme": "poseidon-salted-fixed-point-records-depth-2/v2",
        "record_schema": "private-offset-binary-s16-vector2-regression-scale-256/v2",
        "record_count": 4,
        "dataset_root": statement["publicInputs"]["datasetRoot"],
        "leaf_domain": 201,
        "node_domain": 202,
        "salt_assurance": "demo-producer-random; randomness is not circuit-constrained",
    }
    dataset_statement = {
        "body": dataset_statement_body,
        "signature": sign_object(
            custodian_private, "zk-dataset-statement/v1", dataset_statement_body
        ),
    }
    ordering_statement_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "scheme": "poseidon-step-index-ordering-depth-4/v2",
        "ordering_length": 16,
        "ordering_root": statement["publicInputs"]["orderingRoot"],
        "leaf_domain": 203,
        "node_domain": 206,
        "ordering_assurance": "membership only; permutation and unbiased sampling are not proven",
        "salt_assurance": "demo-producer-random; randomness is not circuit-constrained",
    }
    ordering_statement = {
        "body": ordering_statement_body,
        "signature": sign_object(
            coordinator_private,
            "zk-ordering-statement/v1",
            ordering_statement_body,
        ),
    }
    write_json(public_dir / "dataset.statement.json", dataset_statement)
    write_json(public_dir / "ordering.statement.json", ordering_statement)
    verification_key = read_json(public_dir / "verification_key.json")
    digests = _precommit_digests(
        public_dir,
        statement,
        dataset_statement,
        ordering_statement,
        checkpoint,
        verification_key,
    )
    participants = {
        "dataset_custodian": custodian,
        "coordinator": coordinator,
        "log_operator": operator,
        "log_witness": witness,
    }
    write_json(
        root / "trust-policy.example.json",
        policy_document(
            {
                "dataset_custodian": custodian["key_id"],
                "coordinator": coordinator["key_id"],
                "log_operator": operator["key_id"],
                "log_witness": witness["key_id"],
            },
            {
                "run_id": run_id,
                "relation": ZK_RELATION,
                "circuit_sha256": statement["circuitSha256"],
                "dataset_root": statement["publicInputs"]["datasetRoot"],
                "ordering_root": statement["publicInputs"]["orderingRoot"],
                "code_commitment": statement["publicInputs"]["codeCommitment"],
                "hyperparameters_spec": statement["hyperparametersSpec"],
                "hyperparameters_commitment": statement["publicInputs"][
                    "hyperparametersCommitment"
                ],
                "initial_step": initial_step,
                "transition_count": ZK_N_STEPS,
                "initial_state_commitment": statement["publicInputs"]["initialStateCommitment"],
                "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
                "poseidon_genesis": statement["publicInputs"]["initialChain"],
                "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
                "checkpoint_digest": digests["checkpoint"],
            },
        ),
    )
    genesis_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "scheme": ZK_SCHEME,
        "relation": ZK_RELATION,
        "participants": participants,
        "identity_assurance": "self-issued demo keys; pin expected key ids out of band",
        "trusted_setup": _trusted_setup_claim(),
        "artifact_digests": {
            "circuit_source": digests["circuit_source"],
            "r1cs": digests["r1cs"],
            "verification_key": digests["verification_key"],
        },
        "precommitted_run_inputs": {
            "statement_digest": digests["statement"],
            "dataset_statement_digest": digests["dataset_statement"],
            "ordering_statement_digest": digests["ordering_statement"],
            "checkpoint_digest": digests["checkpoint"],
            "dataset_root": statement["publicInputs"]["datasetRoot"],
            "ordering_root": statement["publicInputs"]["orderingRoot"],
            "code_commitment": statement["publicInputs"]["codeCommitment"],
            "hyperparameters_commitment": statement["publicInputs"][
                "hyperparametersCommitment"
            ],
            "initial_step": initial_step,
            "transition_count": ZK_N_STEPS,
            "initial_state_commitment": statement["publicInputs"]["initialStateCommitment"],
            "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
            "poseidon_genesis": statement["publicInputs"]["initialChain"],
            "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
        },
    }
    genesis = {
        "body": genesis_body,
        "commitment": hash_object("zk-genesis/v1", genesis_body).hex(),
        "signature": sign_object(coordinator_private, "zk-genesis/v1", genesis_body),
    }
    log = new_log(f"zk-demo-log/{run_id}", operator["key_id"], witness["key_id"])
    append_entry(
        log,
        "zk-dataset-statement",
        digests["dataset_statement"],
        operator_private,
        witness_private,
    )
    append_entry(
        log,
        "zk-ordering-statement",
        digests["ordering_statement"],
        operator_private,
        witness_private,
    )
    append_entry(
        log, "zk-genesis", genesis["commitment"], operator_private, witness_private
    )
    head = final_head(log)
    precommit_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": run_id,
        "phase": "before-witness-and-proof-generation/v1",
        "genesis_commitment": genesis["commitment"],
        "entry_count": 3,
        "transparency_head_digest": hash_object(
            "transparency-head/v1", head["body"]
        ).hex(),
        "external_time_anchor": False,
    }
    precommit = {
        "body": precommit_body,
        "coordinator_signature": sign_object(
            coordinator_private, "zk-run-precommit/v1", precommit_body
        ),
        "witness_signature": sign_object(
            witness_private, "zk-run-precommit/v1", precommit_body
        ),
    }
    write_json(public_dir / "genesis.json", genesis)
    write_json(public_dir / "transparency.json", log)
    write_json(public_dir / "precommit.json", precommit)
    return {
        "precommitted": True,
        "run_id": run_id,
        "genesis_commitment": genesis["commitment"],
        "checkpoint_digest": digests["checkpoint"],
    }


def seal_zk_demo(output_dir: str | Path, project_root: str | Path) -> dict[str, Any]:
    root = Path(output_dir).resolve()
    project = Path(project_root).resolve()
    _validate_output_location(root, project)
    public_dir = root / "public"
    private_dir = root / "private"
    if (public_dir / "certificate.json").exists():
        raise ZkError("ZK demo is already sealed")
    required_public = [
        "statement.json",
        "proof.json",
        "public.json",
        "verification_key.json",
        "train_step.circom",
        "train_step.r1cs",
        "dataset.statement.json",
        "ordering.statement.json",
        "checkpoint.json",
        "genesis.json",
        "precommit.json",
        "transparency.json",
    ]
    for name in required_public:
        if not (public_dir / name).is_file():
            raise ZkError(f"missing precommitted ZK artifact: public/{name}")
    statement = _validate_statement(read_json(public_dir / "statement.json"))
    proof = read_json(public_dir / "proof.json")
    public_signals = read_json(public_dir / "public.json")
    verification_key = read_json(public_dir / "verification_key.json")
    dataset_statement = read_json(public_dir / "dataset.statement.json")
    ordering_statement = read_json(public_dir / "ordering.statement.json")
    checkpoint = read_json(public_dir / "checkpoint.json")
    genesis = read_json(public_dir / "genesis.json")
    precommit = read_json(public_dir / "precommit.json")
    log = read_json(public_dir / "transparency.json")
    participants = genesis["body"]["participants"]
    custodian = participants["dataset_custodian"]
    coordinator = participants["coordinator"]
    operator = participants["log_operator"]
    witness = participants["log_witness"]
    key_ids = [item["key_id"] for item in participants.values()]
    if len(set(key_ids)) != 4:
        raise ZkError("ZK participant roles must use distinct keys")
    expected_roles = {
        "dataset_custodian": "zk-dataset-custodian",
        "coordinator": "zk-proof-coordinator",
        "log_operator": "zk-transparency-log-operator",
        "log_witness": "zk-independent-log-witness",
    }
    if any(
        participants[name].get("role") != role for name, role in expected_roles.items()
    ):
        raise ZkError("ZK participant role mismatch")
    verify_signature(
        coordinator, "zk-genesis/v1", genesis["body"], genesis["signature"]
    )
    genesis_commitment = hash_object("zk-genesis/v1", genesis["body"]).hex()
    if genesis.get("commitment") != genesis_commitment:
        raise ZkError("ZK genesis commitment mismatch")
    verify_signature(
        custodian,
        "zk-dataset-statement/v1",
        dataset_statement["body"],
        dataset_statement["signature"],
    )
    verify_signature(
        coordinator,
        "zk-ordering-statement/v1",
        ordering_statement["body"],
        ordering_statement["signature"],
    )
    verify_log(log, operator, witness)
    if len(log["entries"]) != 3:
        raise ZkError("precommit log must contain exactly three entries before sealing")
    precommit_head = final_head(log)
    expected_precommit_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": statement["runId"],
        "phase": "before-witness-and-proof-generation/v1",
        "genesis_commitment": genesis_commitment,
        "entry_count": 3,
        "transparency_head_digest": hash_object(
            "transparency-head/v1", precommit_head["body"]
        ).hex(),
        "external_time_anchor": False,
    }
    if precommit.get("body") != expected_precommit_body:
        raise ZkError("precommit receipt does not match the pre-proof log head")
    verify_signature(
        coordinator,
        "zk-run-precommit/v1",
        precommit["body"],
        precommit["coordinator_signature"],
    )
    verify_signature(
        witness,
        "zk-run-precommit/v1",
        precommit["body"],
        precommit["witness_signature"],
    )
    checkpoint_body = checkpoint.get("body")
    _require_exact_keys(
        checkpoint_body,
        {
            "protocol",
            "run_id",
            "format",
            "relation",
            "initial_step",
            "transition_count",
            "next_step",
            "state",
            "state_commitment",
            "poseidon_domain",
        },
        "ZK checkpoint body",
    )
    if (
        checkpoint_body["protocol"] != PROTOCOL_VERSION
        or checkpoint_body["run_id"] != statement["runId"]
        or checkpoint_body["format"]
        != "fixed-point-linear-state/offset-binary-s16-scale-256/v2"
        or checkpoint_body["relation"] != ZK_RELATION
        or checkpoint_body["initial_step"]
        != int(statement["publicInputs"]["initialStep"])
        or checkpoint_body["transition_count"] != ZK_N_STEPS
        or checkpoint_body["next_step"]
        != int(statement["publicInputs"]["initialStep"]) + ZK_N_STEPS
        or checkpoint_body["poseidon_domain"] != 204
        or checkpoint_body["state_commitment"]
        != statement["publicInputs"]["finalStateCommitment"]
        or int(checkpoint_body["state"]["counter"])
        != checkpoint_body["next_step"]
        or _state_commitment(project, checkpoint_body["state"])
        != checkpoint_body["state_commitment"]
    ):
        raise ZkError("checkpoint does not open the proof's terminal state")

    _verify_named_public_signals(statement, public_signals)
    verify_toolchain_linkage(public_dir, project)
    verifier_output = verify_plonk_files(public_dir, project)
    precommit_digests = _precommit_digests(
        public_dir,
        statement,
        dataset_statement,
        ordering_statement,
        checkpoint,
        verification_key,
    )
    proof_digests = {
        "proof": hash_object("zk-plonk-proof/v1", proof).hex(),
        "public_signals": hash_object("zk-public-signals/v1", public_signals).hex(),
        "precommit_receipt": hash_object("zk-run-precommit-record/v1", precommit).hex(),
    }
    artifact_digests = {**precommit_digests, **proof_digests}
    expected_log_prefix = [
        ("zk-dataset-statement", precommit_digests["dataset_statement"]),
        ("zk-ordering-statement", precommit_digests["ordering_statement"]),
        ("zk-genesis", genesis_commitment),
    ]
    if [
        (item["kind"], item["subject_digest"]) for item in log["entries"]
    ] != expected_log_prefix:
        raise ZkError("precommit log subjects do not match signed run inputs")
    if genesis["body"].get("trusted_setup") != _trusted_setup_claim():
        raise ZkError("genesis trusted-setup claim mismatch")
    expected_genesis_digests = {
        "circuit_source": precommit_digests["circuit_source"],
        "r1cs": precommit_digests["r1cs"],
        "verification_key": precommit_digests["verification_key"],
    }
    if genesis["body"].get("artifact_digests") != expected_genesis_digests:
        raise ZkError("genesis toolchain digests mismatch")
    expected_inputs = {
        "statement_digest": precommit_digests["statement"],
        "dataset_statement_digest": precommit_digests["dataset_statement"],
        "ordering_statement_digest": precommit_digests["ordering_statement"],
        "checkpoint_digest": precommit_digests["checkpoint"],
        "dataset_root": statement["publicInputs"]["datasetRoot"],
        "ordering_root": statement["publicInputs"]["orderingRoot"],
        "code_commitment": statement["publicInputs"]["codeCommitment"],
        "hyperparameters_commitment": statement["publicInputs"][
            "hyperparametersCommitment"
        ],
        "initial_step": int(statement["publicInputs"]["initialStep"]),
        "transition_count": ZK_N_STEPS,
        "initial_state_commitment": statement["publicInputs"]["initialStateCommitment"],
        "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
        "poseidon_genesis": statement["publicInputs"]["initialChain"],
        "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
    }
    if genesis["body"].get("precommitted_run_inputs") != expected_inputs:
        raise ZkError("genesis does not bind the proof inputs and checkpoint")

    coordinator_private = private_dir / "keys" / "coordinator.private.json"
    operator_private = private_dir / "keys" / "log-operator.private.json"
    witness_private = private_dir / "keys" / "witness.private.json"
    step_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": statement["runId"],
        "scheme": ZK_SCHEME,
        "relation": ZK_RELATION,
        "previous_sha256_commitment": genesis_commitment,
        "poseidon_chain": {
            "initial_step": statement["publicInputs"]["initialStep"],
            "transition_count": statement["publicInputs"]["transitionCount"],
            "initial": statement["publicInputs"]["initialChain"],
            "final": statement["publicInputs"]["finalChain"],
        },
        "artifact_digests": artifact_digests,
        "public_claims": ZK_CLAIMS,
        "verification_at_seal": {
            "plonk": "OK",
            "named_public_signals": "OK",
            "source_r1cs_vk_setup_linkage": "OK",
            "checkpoint_opening": "OK",
        },
    }
    zk_step = {
        "body": step_body,
        "step_commitment": hash_object("zk-training-step/v1", step_body).hex(),
        "signature": sign_object(coordinator_private, "zk-training-step/v1", step_body),
    }
    step_log_index = append_entry(
        log,
        "zk-training-step",
        zk_step["step_commitment"],
        operator_private,
        witness_private,
    )
    checkpoint_anchor = hash_object(
        "zk-checkpoint-anchor/v1",
        {
            "run_id": statement["runId"],
            "final_step_commitment": zk_step["step_commitment"],
            "checkpoint_digest": precommit_digests["checkpoint"],
            "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
        },
    ).hex()
    checkpoint_log_index = append_entry(
        log, "zk-checkpoint", checkpoint_anchor, operator_private, witness_private
    )
    head = final_head(log)
    certificate_body = {
        "protocol": PROTOCOL_VERSION,
        "run_id": statement["runId"],
        "scheme": ZK_SCHEME,
        "genesis_commitment": genesis_commitment,
        "final_step_commitment": zk_step["step_commitment"],
        "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
        "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
        "checkpoint_digest": precommit_digests["checkpoint"],
        "checkpoint_anchor": checkpoint_anchor,
        "transparency_head_digest": hash_object(
            "transparency-head/v1", head["body"]
        ).hex(),
        "step_log_index": step_log_index,
        "step_inclusion_proof": inclusion_proof(log, step_log_index),
        "checkpoint_log_index": checkpoint_log_index,
        "checkpoint_inclusion_proof": inclusion_proof(log, checkpoint_log_index),
        "assurance": ZK_ASSURANCE,
    }
    certificate = {
        "body": certificate_body,
        "coordinator_signature": sign_object(
            coordinator_private, "zk-checkpoint-certificate/v1", certificate_body
        ),
        "witness_signature": sign_object(
            witness_private, "zk-checkpoint-certificate/v1", certificate_body
        ),
    }
    write_json(public_dir / "step.json", zk_step)
    write_json(public_dir / "transparency.json", log)
    write_json(public_dir / "certificate.json", certificate)
    return {
        "sealed": True,
        "directory": str(root),
        "run_id": statement["runId"],
        "step_commitment": zk_step["step_commitment"],
        "checkpoint_digest": precommit_digests["checkpoint"],
        "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
        "plonk_verifier": verifier_output,
    }


def verify_zk_demo(
    output_dir: str | Path,
    project_root: str | Path,
    trust_policy: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(output_dir).resolve()
    project = Path(project_root).resolve()
    public_dir = root / "public"
    checks: list[str] = []
    try:
        expected_public = {
            "statement.json",
            "dataset.statement.json",
            "ordering.statement.json",
            "checkpoint.json",
            "precommit.json",
            "proof.json",
            "public.json",
            "verification_key.json",
            "train_step.circom",
            "train_step.r1cs",
            "genesis.json",
            "step.json",
            "transparency.json",
            "certificate.json",
            "keys",
        }
        if {path.name for path in public_dir.iterdir()} != expected_public:
            raise ZkError("ZK public artifact file set mismatch")
        if any(path.is_symlink() for path in public_dir.rglob("*")):
            raise ZkError("ZK public artifact bundle must not contain symbolic links")
        statement = _validate_statement(read_json(public_dir / "statement.json"))
        dataset_statement = read_json(public_dir / "dataset.statement.json")
        ordering_statement = read_json(public_dir / "ordering.statement.json")
        checkpoint = read_json(public_dir / "checkpoint.json")
        precommit = read_json(public_dir / "precommit.json")
        proof = read_json(public_dir / "proof.json")
        public_signals = read_json(public_dir / "public.json")
        verification_key = read_json(public_dir / "verification_key.json")
        genesis = read_json(public_dir / "genesis.json")
        zk_step = read_json(public_dir / "step.json")
        log = read_json(public_dir / "transparency.json")
        certificate = read_json(public_dir / "certificate.json")
        _require_exact_keys(
            dataset_statement, {"body", "signature"}, "dataset statement"
        )
        _require_exact_keys(
            ordering_statement, {"body", "signature"}, "ordering statement"
        )
        _require_exact_keys(checkpoint, {"body"}, "checkpoint")
        _require_exact_keys(genesis, {"body", "commitment", "signature"}, "ZK genesis")
        _require_exact_keys(
            precommit,
            {"body", "coordinator_signature", "witness_signature"},
            "ZK precommit receipt",
        )
        _require_exact_keys(
            zk_step, {"body", "step_commitment", "signature"}, "ZK step"
        )
        _require_exact_keys(
            certificate,
            {"body", "coordinator_signature", "witness_signature"},
            "ZK certificate",
        )

        participants = genesis["body"]["participants"]
        _require_exact_keys(
            participants,
            {"dataset_custodian", "coordinator", "log_operator", "log_witness"},
            "ZK participant set",
        )
        expected_roles = {
            "dataset_custodian": "zk-dataset-custodian",
            "coordinator": "zk-proof-coordinator",
            "log_operator": "zk-transparency-log-operator",
            "log_witness": "zk-independent-log-witness",
        }
        for name, role in expected_roles.items():
            _require_exact_keys(
                participants[name],
                {"protocol", "scheme", "role", "key_id", "public_key"},
                f"{name} public key",
            )
            if (
                participants[name]["protocol"] != PROTOCOL_VERSION
                or participants[name]["role"] != role
            ):
                raise ZkError(f"{name} key role or protocol mismatch")
        key_ids = [item["key_id"] for item in participants.values()]
        if len(set(key_ids)) != 4:
            raise ZkError("ZK participant roles must use four distinct keys")
        custodian = participants["dataset_custodian"]
        coordinator = participants["coordinator"]
        operator = participants["log_operator"]
        witness = participants["log_witness"]
        expected_key_files = {
            "custodian.public.json": custodian,
            "coordinator.public.json": coordinator,
            "log-operator.public.json": operator,
            "witness.public.json": witness,
        }
        key_dir = public_dir / "keys"
        if {path.name for path in key_dir.iterdir()} != set(expected_key_files):
            raise ZkError("ZK public-key file set mismatch")
        for filename, document in expected_key_files.items():
            if read_json(key_dir / filename) != document:
                raise ZkError(f"published ZK key does not match genesis: {filename}")
        identity_trust = (
            "not externally established; provide a verifier-controlled trust policy"
        )

        run_id = statement["runId"]
        expected_dataset_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "dataset_id": f"zk-demo-private-dataset/{run_id}",
            "scheme": "poseidon-salted-fixed-point-records-depth-2/v2",
            "record_schema": "private-offset-binary-s16-vector2-regression-scale-256/v2",
            "record_count": 4,
            "dataset_root": statement["publicInputs"]["datasetRoot"],
            "leaf_domain": 201,
            "node_domain": 202,
            "salt_assurance": "demo-producer-random; randomness is not circuit-constrained",
        }
        if dataset_statement["body"] != expected_dataset_body:
            raise ZkError("ZK dataset statement mismatch")
        verify_signature(
            custodian,
            "zk-dataset-statement/v1",
            dataset_statement["body"],
            dataset_statement["signature"],
        )
        expected_ordering_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "scheme": "poseidon-step-index-ordering-depth-4/v2",
            "ordering_length": 16,
            "ordering_root": statement["publicInputs"]["orderingRoot"],
            "leaf_domain": 203,
            "node_domain": 206,
            "ordering_assurance": (
                "membership only; permutation and unbiased sampling are not proven"
            ),
            "salt_assurance": "demo-producer-random; randomness is not circuit-constrained",
        }
        if ordering_statement["body"] != expected_ordering_body:
            raise ZkError("ZK ordering statement mismatch")
        verify_signature(
            coordinator,
            "zk-ordering-statement/v1",
            ordering_statement["body"],
            ordering_statement["signature"],
        )
        checks.append("signed run-bound private dataset and ordering roots")

        checkpoint_body = checkpoint["body"]
        _require_exact_keys(
            checkpoint_body,
            {
                "protocol",
                "run_id",
                "format",
                "relation",
                "initial_step",
                "transition_count",
                "next_step",
                "state",
                "state_commitment",
                "poseidon_domain",
            },
            "ZK checkpoint body",
        )
        if (
            checkpoint_body["protocol"] != PROTOCOL_VERSION
            or checkpoint_body["run_id"] != run_id
            or checkpoint_body["format"]
            != "fixed-point-linear-state/offset-binary-s16-scale-256/v2"
            or checkpoint_body["relation"] != ZK_RELATION
            or checkpoint_body["initial_step"]
            != int(statement["publicInputs"]["initialStep"])
            or checkpoint_body["transition_count"] != ZK_N_STEPS
            or checkpoint_body["next_step"]
            != int(statement["publicInputs"]["initialStep"]) + ZK_N_STEPS
            or checkpoint_body["poseidon_domain"] != 204
            or checkpoint_body["state_commitment"]
            != statement["publicInputs"]["finalStateCommitment"]
            or int(checkpoint_body["state"]["counter"])
            != checkpoint_body["next_step"]
            or _state_commitment(project, checkpoint_body["state"])
            != checkpoint_body["state_commitment"]
        ):
            raise ZkError("public checkpoint does not open the proven terminal state")
        checks.append("exact checkpoint-to-final-state opening")

        circuit_bytes = (public_dir / "train_step.circom").read_bytes()
        if int(statement["publicInputs"]["codeCommitment"]) != _sha256_field(
            circuit_bytes
        ):
            raise ZkError("public code commitment does not match pinned circuit source")
        if int(statement["publicInputs"]["hyperparametersCommitment"]) != _sha256_field(
            ZK_HYPERPARAMETERS_SPEC.encode("utf-8")
        ):
            raise ZkError("public hyperparameter commitment mismatch")
        _verify_named_public_signals(statement, public_signals)
        verify_toolchain_linkage(public_dir, project)
        checks.append("pinned source-to-R1CS-to-VK setup linkage")
        verifier_output = verify_plonk_files(public_dir, project)
        checks.append("PLONK proof and canonical public signals")

        precommit_digests = _precommit_digests(
            public_dir,
            statement,
            dataset_statement,
            ordering_statement,
            checkpoint,
            verification_key,
        )
        artifact_digests = {
            **precommit_digests,
            "proof": hash_object("zk-plonk-proof/v1", proof).hex(),
            "public_signals": hash_object("zk-public-signals/v1", public_signals).hex(),
            "precommit_receipt": hash_object(
                "zk-run-precommit-record/v1", precommit
            ).hex(),
        }
        expected_genesis_artifacts = {
            "circuit_source": precommit_digests["circuit_source"],
            "r1cs": precommit_digests["r1cs"],
            "verification_key": precommit_digests["verification_key"],
        }
        expected_inputs = {
            "statement_digest": precommit_digests["statement"],
            "dataset_statement_digest": precommit_digests["dataset_statement"],
            "ordering_statement_digest": precommit_digests["ordering_statement"],
            "checkpoint_digest": precommit_digests["checkpoint"],
            "dataset_root": statement["publicInputs"]["datasetRoot"],
            "ordering_root": statement["publicInputs"]["orderingRoot"],
            "code_commitment": statement["publicInputs"]["codeCommitment"],
            "hyperparameters_commitment": statement["publicInputs"][
                "hyperparametersCommitment"
            ],
            "initial_step": int(statement["publicInputs"]["initialStep"]),
            "transition_count": ZK_N_STEPS,
            "initial_state_commitment": statement["publicInputs"]["initialStateCommitment"],
            "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
            "poseidon_genesis": statement["publicInputs"]["initialChain"],
            "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
        }
        expected_genesis_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "scheme": ZK_SCHEME,
            "relation": ZK_RELATION,
            "participants": participants,
            "identity_assurance": "self-issued demo keys; pin expected key ids out of band",
            "trusted_setup": _trusted_setup_claim(),
            "artifact_digests": expected_genesis_artifacts,
            "precommitted_run_inputs": expected_inputs,
        }
        if genesis["body"] != expected_genesis_body:
            raise ZkError(
                "ZK genesis contains unexpected fields or mismatched commitments"
            )
        genesis_commitment = hash_object("zk-genesis/v1", genesis["body"]).hex()
        if genesis["commitment"] != genesis_commitment:
            raise ZkError("ZK genesis commitment mismatch")
        verify_signature(
            coordinator, "zk-genesis/v1", genesis["body"], genesis["signature"]
        )
        checks.append("signed run genesis with pre-proof input commitments")

        if trust_policy is not None:
            verify_trust_policy(
                trust_policy,
                {
                    "dataset_custodian": custodian["key_id"],
                    "coordinator": coordinator["key_id"],
                    "log_operator": operator["key_id"],
                    "log_witness": witness["key_id"],
                },
                {
                    "run_id": run_id,
                    "relation": ZK_RELATION,
                    "circuit_sha256": statement["circuitSha256"],
                    "dataset_root": statement["publicInputs"]["datasetRoot"],
                    "ordering_root": statement["publicInputs"]["orderingRoot"],
                    "code_commitment": statement["publicInputs"]["codeCommitment"],
                    "hyperparameters_spec": statement["hyperparametersSpec"],
                    "hyperparameters_commitment": statement["publicInputs"][
                        "hyperparametersCommitment"
                    ],
                    "initial_step": int(statement["publicInputs"]["initialStep"]),
                    "transition_count": ZK_N_STEPS,
                    "initial_state_commitment": statement["publicInputs"][
                        "initialStateCommitment"
                    ],
                    "final_state_commitment": statement["publicInputs"][
                        "finalStateCommitment"
                    ],
                    "poseidon_genesis": statement["publicInputs"]["initialChain"],
                    "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
                    "checkpoint_digest": precommit_digests["checkpoint"],
                },
            )
            identity_trust = (
                "participant keys and expected run claims matched the "
                "verifier-supplied trust policy"
            )
            checks.append("verifier-supplied participant and run-claim trust policy")

        verify_log(log, operator, witness)
        if log["log_id"] != f"zk-demo-log/{run_id}":
            raise ZkError("ZK transparency log id does not match the run")
        if len(log["entries"]) != 5 or len(log["signed_heads"]) != 5:
            raise ZkError("sealed ZK transparency log must have five entries and heads")
        precommit_head = log["signed_heads"][2]
        expected_precommit_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "phase": "before-witness-and-proof-generation/v1",
            "genesis_commitment": genesis_commitment,
            "entry_count": 3,
            "transparency_head_digest": hash_object(
                "transparency-head/v1", precommit_head["body"]
            ).hex(),
            "external_time_anchor": False,
        }
        if precommit["body"] != expected_precommit_body:
            raise ZkError("ZK precommit receipt mismatch")
        verify_signature(
            coordinator,
            "zk-run-precommit/v1",
            precommit["body"],
            precommit["coordinator_signature"],
        )
        verify_signature(
            witness,
            "zk-run-precommit/v1",
            precommit["body"],
            precommit["witness_signature"],
        )
        checks.append("witnessed pre-proof log head")

        expected_step_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "scheme": ZK_SCHEME,
            "relation": ZK_RELATION,
            "previous_sha256_commitment": genesis_commitment,
            "poseidon_chain": {
                "initial_step": statement["publicInputs"]["initialStep"],
                "transition_count": statement["publicInputs"]["transitionCount"],
                "initial": statement["publicInputs"]["initialChain"],
                "final": statement["publicInputs"]["finalChain"],
            },
            "artifact_digests": artifact_digests,
            "public_claims": ZK_CLAIMS,
            "verification_at_seal": {
                "plonk": "OK",
                "named_public_signals": "OK",
                "source_r1cs_vk_setup_linkage": "OK",
                "checkpoint_opening": "OK",
            },
        }
        if zk_step["body"] != expected_step_body:
            raise ZkError("ZK step contains unexpected fields or mismatched artifacts")
        step_commitment = hash_object("zk-training-step/v1", expected_step_body).hex()
        if zk_step["step_commitment"] != step_commitment:
            raise ZkError("ZK step commitment mismatch")
        verify_signature(
            coordinator, "zk-training-step/v1", zk_step["body"], zk_step["signature"]
        )
        checkpoint_anchor = hash_object(
            "zk-checkpoint-anchor/v1",
            {
                "run_id": run_id,
                "final_step_commitment": step_commitment,
                "checkpoint_digest": precommit_digests["checkpoint"],
                "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
            },
        ).hex()
        expected_subjects = [
            ("zk-dataset-statement", precommit_digests["dataset_statement"]),
            ("zk-ordering-statement", precommit_digests["ordering_statement"]),
            ("zk-genesis", genesis_commitment),
            ("zk-training-step", step_commitment),
            ("zk-checkpoint", checkpoint_anchor),
        ]
        if [
            (item["kind"], item["subject_digest"]) for item in log["entries"]
        ] != expected_subjects:
            raise ZkError("ZK transparency subjects mismatch")
        checks.append("signed proof envelope and witnessed final log")

        certificate_body = certificate["body"]
        expected_certificate_body = {
            "protocol": PROTOCOL_VERSION,
            "run_id": run_id,
            "scheme": ZK_SCHEME,
            "genesis_commitment": genesis_commitment,
            "final_step_commitment": step_commitment,
            "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
            "final_state_commitment": statement["publicInputs"]["finalStateCommitment"],
            "checkpoint_digest": precommit_digests["checkpoint"],
            "checkpoint_anchor": checkpoint_anchor,
            "transparency_head_digest": hash_object(
                "transparency-head/v1", final_head(log)["body"]
            ).hex(),
            "step_log_index": 3,
            "step_inclusion_proof": certificate_body.get("step_inclusion_proof"),
            "checkpoint_log_index": 4,
            "checkpoint_inclusion_proof": certificate_body.get(
                "checkpoint_inclusion_proof"
            ),
            "assurance": ZK_ASSURANCE,
        }
        if certificate_body != expected_certificate_body:
            raise ZkError(
                "ZK certificate contains unexpected fields or mismatched claims"
            )
        verify_signature(
            coordinator,
            "zk-checkpoint-certificate/v1",
            certificate_body,
            certificate["coordinator_signature"],
        )
        verify_signature(
            witness,
            "zk-checkpoint-certificate/v1",
            certificate_body,
            certificate["witness_signature"],
        )
        if not verify_inclusion(log, 3, certificate_body["step_inclusion_proof"]):
            raise ZkError("step transparency inclusion proof failed")
        if not verify_inclusion(log, 4, certificate_body["checkpoint_inclusion_proof"]):
            raise ZkError("checkpoint transparency inclusion proof failed")
        checks.append("coordinator- and witness-signed exact checkpoint certificate")
        return {
            "valid": True,
            "checks": checks,
            "run_id": run_id,
            "relation": ZK_RELATION,
            "step_commitment": step_commitment,
            "checkpoint_digest": precommit_digests["checkpoint"],
            "poseidon_final_commitment": statement["publicInputs"]["finalChain"],
            "verifier": verifier_output,
            "assurance": certificate_body["assurance"],
            "identity_trust": identity_trust,
            "limitations": [
                "The circuit proves exactly four bounded fixed-point vector "
                "transitions, not PyTorch, IEEE floating point, or historical "
                "execution.",
                "Ordering-tree membership at four consecutive positions is "
                "proven; a permutation, seed derivation, and unbiased sampling "
                "are not.",
                "Keys and the witness are demo-local unless their key ids and "
                "log heads are pinned externally.",
                "The local pre-proof receipt orders the demo workflow but is not "
                "an external timestamp.",
                "The PoT file hash is pinned; use -VerifyTranscript for a full "
                "contribution-by-contribution audit.",
            ],
        }
    except Exception as exc:
        return {"valid": False, "checks": checks, "errors": [str(exc)]}
