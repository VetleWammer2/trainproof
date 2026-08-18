from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from trainproof.canonical import read_json, write_json
from trainproof.zk import (
    ZK_CIRCUIT_SHA256,
    ZkError,
    precommit_zk_demo,
    verify_plonk_files,
    verify_zk_demo,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ZK_DEMO = PROJECT_ROOT / "zk" / "demo-run"
ZK_AVAILABLE = (ZK_DEMO / "public" / "certificate.json").is_file()


def test_checked_out_circuit_bytes_match_pinned_hash() -> None:
    circuit = PROJECT_ROOT / "zk" / "circuits" / "train_step.circom"
    assert hashlib.sha256(circuit.read_bytes()).hexdigest() == ZK_CIRCUIT_SHA256


def _witness_satisfies(input_value: dict, tmp_path: Path, name: str) -> bool:
    input_path = tmp_path / f"{name}.json"
    witness_path = tmp_path / f"{name}.wtns"
    write_json(input_path, input_value)
    snarkjs = PROJECT_ROOT / "node_modules" / ".bin" / "snarkjs.cmd"
    completed = subprocess.run(
        [
            str(snarkjs),
            "wtns",
            "calculate",
            str(PROJECT_ROOT / "zk" / "build" / "train_step_js" / "train_step.wasm"),
            str(input_path),
            str(witness_path),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        return False
    checked = subprocess.run(
        [
            str(snarkjs),
            "wtns",
            "check",
            str(PROJECT_ROOT / "zk" / "build" / "train_step.r1cs"),
            str(witness_path),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return checked.returncode == 0


def test_zk_private_output_is_restricted_inside_source_tree() -> None:
    unsafe = PROJECT_ROOT / "zk" / "unignored-private-run"
    assert not unsafe.exists()
    with pytest.raises(ZkError, match="restricted"):
        precommit_zk_demo(unsafe, PROJECT_ROOT)
    assert not unsafe.exists()


@pytest.mark.skipif(not ZK_AVAILABLE, reason="generated ZK demo is not present")
def test_zk_verifier_needs_only_public_bundle(tmp_path: Path) -> None:
    public_only = tmp_path / "public-only"
    shutil.copytree(ZK_DEMO / "public", public_only / "public")
    report = verify_zk_demo(public_only, PROJECT_ROOT)
    assert report["valid"], report
    assert report["relation"] == "bounded-fixed-point-linear-training-chain/n=4/v2"
    assert report["assurance"]["zero_knowledge_transitions"] == 4
    assert any("PLONK proof" in check for check in report["checks"])


@pytest.mark.skipif(not ZK_AVAILABLE, reason="generated ZK demo is not present")
def test_zk_verifier_binds_checkpoint_and_rejects_extra_claims(tmp_path: Path) -> None:
    public_only = tmp_path / "public-only"
    shutil.copytree(ZK_DEMO / "public", public_only / "public")
    checkpoint_path = public_only / "public" / "checkpoint.json"
    checkpoint = read_json(checkpoint_path)
    checkpoint["body"]["state"]["w"][0] = str(
        int(checkpoint["body"]["state"]["w"][0]) + 1
    )
    write_json(checkpoint_path, checkpoint)
    tampered = verify_zk_demo(public_only, PROJECT_ROOT)
    assert not tampered["valid"]
    assert "checkpoint" in tampered["errors"][0].lower()

    shutil.rmtree(public_only)
    shutil.copytree(ZK_DEMO / "public", public_only / "public")
    certificate_path = public_only / "public" / "certificate.json"
    certificate = read_json(certificate_path)
    certificate["body"]["full_llm_training_proven"] = True
    write_json(certificate_path, certificate)
    overclaim = verify_zk_demo(public_only, PROJECT_ROOT)
    assert not overclaim["valid"]


@pytest.mark.skipif(not ZK_AVAILABLE, reason="generated ZK demo is not present")
def test_zk_verifier_rejects_wrong_trust_policy(tmp_path: Path) -> None:
    policy = read_json(ZK_DEMO / "trust-policy.example.json")
    policy["participants"]["coordinator"] = "00" * 32
    policy_path = tmp_path / "wrong-policy.json"
    write_json(policy_path, policy)
    report = verify_zk_demo(ZK_DEMO, PROJECT_ROOT, trust_policy=policy_path)
    assert not report["valid"]
    assert "trust-policy" in report["errors"][0]

    policy = read_json(ZK_DEMO / "trust-policy.example.json")
    policy["claims"]["final_state_commitment"] = "0"
    policy_path = tmp_path / "wrong-claims-policy.json"
    write_json(policy_path, policy)
    report = verify_zk_demo(ZK_DEMO, PROJECT_ROOT, trust_policy=policy_path)
    assert not report["valid"]
    assert "trust-policy" in report["errors"][0]


@pytest.mark.skipif(not ZK_AVAILABLE, reason="generated ZK demo is not present")
def test_raw_plonk_verifier_rejects_modified_proof(tmp_path: Path) -> None:
    public_dir = tmp_path / "public"
    shutil.copytree(ZK_DEMO / "public", public_dir)
    proof_path = public_dir / "proof.json"
    proof = read_json(proof_path)
    proof["plaintext_records"] = ["secret"]
    write_json(proof_path, proof)
    with pytest.raises(ZkError, match="unexpected or missing fields"):
        verify_plonk_files(public_dir, PROJECT_ROOT)

    proof.pop("plaintext_records")
    proof["A"][0] = str(int(proof["A"][0]) + 1)
    write_json(proof_path, proof)
    with pytest.raises(ZkError, match="PLONK verification failed"):
        verify_plonk_files(public_dir, PROJECT_ROOT)


@pytest.mark.skipif(not ZK_AVAILABLE, reason="generated ZK demo is not present")
def test_public_bundle_verifier_rejects_tampered_proof(tmp_path: Path) -> None:
    public_only = tmp_path / "public-only"
    shutil.copytree(ZK_DEMO / "public", public_only / "public")
    proof_path = public_only / "public" / "proof.json"
    proof = read_json(proof_path)
    proof["A"][0] = str(int(proof["A"][0]) + 1)
    write_json(proof_path, proof)
    report = verify_zk_demo(public_only, PROJECT_ROOT)
    assert not report["valid"]
    assert "PLONK verification failed" in report["errors"][0]


@pytest.mark.skipif(not ZK_AVAILABLE, reason="generated ZK demo is not present")
def test_circuit_rejects_private_sample_tampering(tmp_path: Path) -> None:
    malicious_input = read_json(ZK_DEMO / "private" / "input.json")
    malicious_input["x"][0][0] = str(int(malicious_input["x"][0][0]) + 1)
    assert not _witness_satisfies(malicious_input, tmp_path, "modified-membership")


@pytest.mark.skipif(not ZK_AVAILABLE, reason="generated ZK demo is not present")
@pytest.mark.parametrize(
    "mutation",
    [
        "intermediate-state",
        "reordered",
        "skipped",
        "inserted-count",
        "poseidon-chain",
    ],
)
def test_circuit_rejects_trajectory_tampering(
    tmp_path: Path, mutation: str
) -> None:
    malicious = read_json(ZK_DEMO / "private" / "input.json")
    if mutation == "intermediate-state":
        malicious["stateW"][2][0] = str(int(malicious["stateW"][2][0]) + 1)
    elif mutation == "reordered":
        per_transition = [
            "sampleIndex",
            "x",
            "y",
            "recordSalt",
            "datasetSiblings",
            "datasetPathBits",
            "orderSalt",
            "orderingSiblings",
            "orderingPathBits",
        ]
        for field in per_transition:
            malicious[field][0], malicious[field][1] = (
                malicious[field][1],
                malicious[field][0],
            )
    elif mutation == "skipped":
        per_transition = [
            "sampleIndex",
            "x",
            "y",
            "recordSalt",
            "datasetSiblings",
            "datasetPathBits",
            "orderSalt",
            "orderingSiblings",
            "orderingPathBits",
        ]
        for field in per_transition:
            malicious[field][1] = malicious[field][2]
    elif mutation == "inserted-count":
        malicious["transitionCount"] = "5"
    else:
        malicious["finalChain"] = str(int(malicious["finalChain"]) + 1)
    assert not _witness_satisfies(malicious, tmp_path, mutation)
