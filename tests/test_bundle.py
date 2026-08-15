from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import trainproof.bundle as bundle_module
from trainproof.bundle import build_demo_bundle
from trainproof.canonical import hash_object, read_json, write_json
from trainproof.crypto import public_key_document, sign_object
from trainproof.dataset import DatasetError, verify_dataset_statement
from trainproof.verify import (
    VerificationError,
    _validated_replay_genesis,
    audit_bundle,
    verify_bundle,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _build(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    build_demo_bundle(run, PROJECT_ROOT, steps=3, workers=2)
    return run


def test_end_to_end_public_verify_and_private_audit(tmp_path: Path) -> None:
    run = _build(tmp_path)
    public = verify_bundle(run)
    audit = audit_bundle(run, source_root=PROJECT_ROOT)
    unbound_audit = audit_bundle(run)
    assert public["valid"], public
    assert audit["valid"], audit
    assert unbound_audit["valid"], unbound_audit
    assert audit["steps_replayed"] == 3
    assert "satisfy" in audit["assurance"]["transition_satisfiability"]
    assert "not established" in audit["assurance"]["historical_execution"]
    assert audit["assurance"]["source_binding"].startswith("verified")
    assert unbound_audit["assurance"]["source_binding"].startswith("not checked")


def test_verifier_controlled_trust_policy_pins_keys_and_run_claims(
    tmp_path: Path,
) -> None:
    run = _build(tmp_path)
    policy = run / "trust-policy.example.json"
    trusted = verify_bundle(run, trust_policy=policy)
    assert trusted["valid"], trusted
    assert "matched" in trusted["assurance"]["identity_trust"]

    wrong_policy = read_json(policy)
    wrong_policy["participants"]["coordinator"] = "00" * 32
    wrong_path = tmp_path / "wrong-trust-policy.json"
    write_json(wrong_path, wrong_policy)
    rejected = verify_bundle(run, trust_policy=wrong_path)
    assert not rejected["valid"]
    assert "trust-policy" in rejected["errors"][0]

    wrong_claims = read_json(policy)
    wrong_claims["claims"]["dataset_root"] = "00" * 32
    wrong_claims_path = tmp_path / "wrong-trust-claims.json"
    write_json(wrong_claims_path, wrong_claims)
    rejected_claims = verify_bundle(run, trust_policy=wrong_claims_path)
    assert not rejected_claims["valid"]
    assert "trust-policy" in rejected_claims["errors"][0]


def test_public_verifier_rejects_checkpoint_tampering(tmp_path: Path) -> None:
    run = _build(tmp_path)
    checkpoint_path = run / "artifacts" / "checkpoint.json"
    checkpoint = read_json(checkpoint_path)
    checkpoint["model"]["weights"][0] += 1
    write_json(checkpoint_path, checkpoint)
    report = verify_bundle(run)
    assert not report["valid"]
    assert "checkpoint" in report["errors"][0].lower()


def test_dataset_v1_rejects_additional_payload_roots(tmp_path: Path) -> None:
    run = _build(tmp_path)
    statement = read_json(run / "public" / "dataset.statement.json")
    statement["body"]["additional_roots"] = {"plaintext_records": ["secret"]}
    statement["signature"] = sign_object(
        run / "private" / "keys" / "custodian.private.json",
        "dataset-statement/v1",
        statement["body"],
    )
    custodian = read_json(run / "public" / "keys" / "custodian.public.json")
    with pytest.raises(DatasetError, match="additional roots"):
        verify_dataset_statement(statement, custodian)


def test_public_verifier_rejects_step_tampering(tmp_path: Path) -> None:
    run = _build(tmp_path)
    steps_path = run / "public" / "steps.json"
    steps = read_json(steps_path)
    steps[0]["body"]["aggregate_update_commitment"] = "00" * 32
    write_json(steps_path, steps)
    report = verify_bundle(run)
    assert not report["valid"]
    assert "commitment" in report["errors"][0].lower()


def test_public_verifier_enforces_the_committed_order_schedule(tmp_path: Path) -> None:
    run = _build(tmp_path)
    steps_path = run / "public" / "steps.json"
    steps = read_json(steps_path)
    steps[0]["body"]["assignments"][0]["body"]["order_position"] = 1
    steps[0]["step_commitment"] = hash_object(
        "training-step/v1", steps[0]["body"]
    ).hex()
    steps[0]["coordinator_signature"] = sign_object(
        run / "private" / "keys" / "coordinator.private.json",
        "training-step/v1",
        steps[0]["body"],
    )
    write_json(steps_path, steps)
    report = verify_bundle(run)
    assert not report["valid"]
    assert "ordering schedule" in report["errors"][0]


def test_public_verifier_rejects_unknown_signed_claims(tmp_path: Path) -> None:
    run = _build(tmp_path)
    manifest_path = run / "public" / "manifest.json"
    manifest = read_json(manifest_path)
    manifest["body"]["full_training_proven"] = True
    write_json(manifest_path, manifest)
    report = verify_bundle(run)
    assert not report["valid"]
    assert "unexpected or missing fields" in report["errors"][0]


def test_malformed_top_level_json_returns_invalid_report(tmp_path: Path) -> None:
    run = _build(tmp_path)
    write_json(run / "public" / "manifest.json", [])
    report = verify_bundle(run)
    assert report["valid"] is False
    assert report["errors"]


def test_public_verifier_rejects_published_key_document_tampering(
    tmp_path: Path,
) -> None:
    run = _build(tmp_path)
    key_path = run / "public" / "keys" / "worker-0.public.json"
    document = read_json(key_path)
    document["role"] = "training-worker-99"
    write_json(key_path, document)
    report = verify_bundle(run)
    assert not report["valid"]
    assert "public-key document" in report["errors"][0]


def test_private_audit_rejects_wrong_hidden_record(tmp_path: Path) -> None:
    run = _build(tmp_path)
    openings_path = run / "private" / "dataset.openings.json"
    openings = read_json(openings_path)
    openings["openings"][0]["record"]["y"] += 1
    write_json(openings_path, openings)
    report = audit_bundle(run)
    assert not report["valid"]
    assert report["phase"] == "private-replay"


def test_public_verifier_does_not_read_private_directory(tmp_path: Path) -> None:
    run = _build(tmp_path)
    private = run / "private"
    hidden = tmp_path / "private-hidden"
    private.rename(hidden)
    report = verify_bundle(run)
    assert report["valid"], report


def test_public_verifier_rejects_duplicate_cross_role_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    def generate_same_key(
        private_path: str | Path,
        public_path: str | Path,
        role: str,
    ) -> dict[str, object]:
        public_document = public_key_document(public_bytes, role)
        write_json(
            private_path,
            {
                **public_document,
                "private_key": private_bytes.hex(),
                "warning": "test key",
            },
        )
        write_json(public_path, public_document)
        return public_document

    monkeypatch.setattr(bundle_module, "generate_keypair", generate_same_key)
    run = tmp_path / "duplicate-keys"
    build_demo_bundle(run, PROJECT_ROOT, steps=1, workers=2)
    report = verify_bundle(run)
    assert not report["valid"]
    assert "distinct" in report["errors"][0]


def test_replay_genesis_binds_rng_optimizer_and_counts() -> None:
    seed_commitment = "11" * 32
    bundle = {
        "dataset": {"body": {"record_count": 2}},
        "ordering": {"body": {"record_count": 2, "seed_commitment": seed_commitment}},
    }
    trace = {
        "protocol": "trainproof/v1",
        "initial_model": {"weights": [0, 0], "bias": 0},
        "initial_optimizer": {"kind": "integer-sgd/v1", "step": 0},
        "initial_rng": {
            "kind": "committed-sampler-counter/v1",
            "seed_commitment": seed_commitment,
            "counter": 0,
        },
    }
    records = [{"id": "a"}, {"id": "b"}]
    order = [1, 0]
    _validated_replay_genesis(bundle, trace, records, order)

    wrong_rng = deepcopy(trace)
    wrong_rng["initial_rng"]["seed_commitment"] = "22" * 32
    with pytest.raises(VerificationError, match="RNG"):
        _validated_replay_genesis(bundle, wrong_rng, records, order)

    wrong_optimizer = deepcopy(trace)
    wrong_optimizer["initial_optimizer"]["step"] = 7
    with pytest.raises(VerificationError, match="optimizer"):
        _validated_replay_genesis(bundle, wrong_optimizer, records, order)

    with pytest.raises(VerificationError, match="counts"):
        _validated_replay_genesis(bundle, trace, records[:1], order)


@pytest.mark.parametrize("relative_output", ["runs/run-1", ".git/trainproof-run"])
def test_bundle_rejects_dynamic_output_exclusion_inside_source(
    tmp_path: Path,
    relative_output: str,
) -> None:
    (tmp_path / "source.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level"):
        build_demo_bundle(tmp_path / relative_output, tmp_path, steps=1, workers=1)
