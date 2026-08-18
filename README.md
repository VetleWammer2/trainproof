# Trainproof

Proof-carrying checkpoints for distributed model training. Two assurance modes,
kept separate on purpose:

1. A signed transcript with hiding dataset commitments, worker receipts, a
   per-step hash chain, a witnessed transparency log, canonical-checkpoint
   binding, and deterministic private replay.
2. A Circom/PLONK zero-knowledge demo proving exactly four chained, bounded
   fixed-point linear-SGD transitions: private dataset membership, private
   sample ordering, shared state openings, integer rounding, checked overflow,
   and a Poseidon transition chain.

This repo never calls a hash chain a proof of execution. The public verifier
says which one it is: execution merely committed, privately replayed, or proven
by the ZK circuit.

## Quick start: signed distributed transcript

Python 3.11+. The source root defaults to the current directory; an installed
wheel never guesses a repository from its installation path.

```powershell
python -m pip install -e .
python -m trainproof demo --output demo-run --steps 4 --workers 2
python -m trainproof verify demo-run
python -m trainproof audit demo-run --source .
```

The demo also emits `demo-run/trust-policy.example.json`. It pins participant
key IDs together with the expected run, dataset, ordering, source/Git,
hyperparameter, trajectory-head, and checkpoint claims. Approve it, copy it to a
verifier-controlled location, then pass it:

```powershell
Copy-Item demo-run/trust-policy.example.json C:\verifier-policy\trainproof-demo.json
python -m trainproof verify demo-run --source . --trust-policy C:\verifier-policy\trainproof-demo.json
python -m trainproof audit demo-run --source . --trust-policy C:\verifier-policy\trainproof-demo.json
```

A policy taken straight from an untrusted bundle proves nothing about identity
or intent. Authenticate it out of band.

`verify` reads `public/` and the checkpoint under `artifacts/`, nothing else.
`audit` also reads `private/`: it opens the hidden data and update commitments,
derives the precommitted order, and checks every transition by replay. Adding
`--source` requires the source files and Git metadata to match the fixed-policy
source manifest.

A successful replay proves that the committed transcript is satisfiable under
the reference transition relation. It does not prove those operations ran on
the claimed workers, or at the bundle's timestamps. Inside the source tree,
demo output is restricted to the fixed top-level `demo-run/` or `tampered-run/`
exclusions; bundle-selected source exclusions are rejected.

Bundle layout:

```text
demo-run/
├── trust-policy.example.json
├── public/
│   ├── dataset.statement.json
│   ├── ordering.statement.json
│   ├── manifest.json
│   ├── genesis.json
│   ├── steps.json
│   ├── transparency.json
│   ├── certificate.json
│   └── keys/
├── artifacts/
│   └── checkpoint.json
└── private/
    ├── dataset.openings.json
    ├── ordering.openings.json
    ├── trace.json
    └── keys/
```

The private keys live inside the bundle so the demo reproduces. They are not
production key management and not external identity trust. The verifier
enforces distinct keys and the protocol roles; who controls those keys is a
question for an outside PKI or governance root.

## Quick start: zero-knowledge proof

Windows x64/PowerShell, plus Node.js and npm. Pinned: Circom 2.2.3, `snarkjs`
0.7.6, `circomlib` 2.0.5, PLONK over BN254, and the power-16 iden3/Hermez public
Powers-of-Tau ceremony. Power 16 is required. The four-step circuit expands to
53,313 PLONK constraints, and the former power-14 setup rejects it.

```powershell
./scripts/bootstrap-zk.ps1
./scripts/prove-zk-demo.ps1
python -m trainproof zk-verify zk/demo-run
```

`prove-zk-demo.ps1` first writes a signed, witnessed pre-proof head over the
dataset root, ordering root, run-specific genesis, code/hyperparameters, and
terminal checkpoint. Then it generates the four-transition witness and PLONK
proof, appends the proof step and checkpoint anchor, and runs the independent
public verifier. The pre-proof head gives local workflow order, not external
time.

In-repository ZK output goes to the fixed ignored path `zk/demo-run/`, so
generated inputs and demo signing keys stay out of source manifests. For further
runs, pass an absolute path outside the repository.

The bootstrap checks the Circom SHA-256 and the Powers-of-Tau BLAKE2b against
the hashes published by the upstream projects. Auditing every ceremony
contribution is slow, so it stays opt-in.[^transcript]

```powershell
./scripts/bootstrap-zk.ps1 -VerifyTranscript
```

The ZK verifier never reads `zk/demo-run/private/`. It needs the run's `public/`
directory and a trusted local toolchain root: the pinned Circom binary,
lockfile-installed Node modules, and a Powers-of-Tau file matched to the pinned
upstream BLAKE2b digest. It recompiles the pinned circuit, byte-compares the
R1CS, rederives the PLONK verification key from that R1CS and PoT, verifies the
proof, opens the public checkpoint to `finalStateCommitment`, and checks the
signed SHA-256 envelope, pre-proof head, final log, and certificate.

As with the transcript demo, copy and approve
`zk/demo-run/trust-policy.example.json` yourself before using it. The ZK policy
pins the participant keys, the `N=4` relation/circuit, private roots, initial
and final state commitments, Poseidon chain endpoints, and checkpoint digest:

```powershell
python -m trainproof zk-verify zk/demo-run --toolchain-root . --trust-policy C:\verifier-policy\trainproof-zk.json
```

## Assurance levels

| Mode | Publicly detects tampering | Attributes workers | Verifies transition math | Records required to verify |
|---|---:|---:|---:|---:|
| Signed transcript | Yes | Manifest keys only | No | No |
| Private replay | Yes | Manifest keys only | Satisfiability by replay | Yes; auditor sees openings |
| Included PLONK demo | Yes | N/A, exactly four transitions | Yes, for the exact circuit | No |

“No records required” is a guarantee about verifier input. It is not proof that
a malicious producer declined to encode data in permitted cryptographic values.
The strict schemas reject extra payload fields; confidentiality still assumes an
honest producer and sound randomness generation.

## What the circuit proves

Four consecutive transitions of one two-feature linear-SGD relation. Signed
16-bit raw integers at scale 256, unsigned offset encoding in the field, floor
rescaling with a constrained remainder, overflow rejected.

It does not prove PyTorch, GPU execution, BF16/FP32, historical execution, or
arbitrary model training. It proves membership at four consecutive positions in
the committed ordering tree, not that the tree is a permutation, seed-derived,
or unbiased.

`N=4`, feature count, tree depths, arithmetic, and Poseidon domains are part of
the circuit version. Change one and you need a new R1CS, key, and protocol
profile.

The arithmetic contract is normative in
[docs/FIXED_POINT.md](docs/FIXED_POINT.md). Measured `N=1,2,4` costs and the
case for spending the next milestone on a zkVM parity spike are in
[docs/FEASIBILITY.md](docs/FEASIBILITY.md). Raw trial data is committed under
[`benchmarks/results`](benchmarks/results).

## Tests

```powershell
python -m pytest -q
```

The suite covers canonical encoding, odd-sized Merkle trees, role-bound and
distinct signing keys, fixed source exclusions and Git metadata, chain and
checkpoint tampering, replay-state binding, public-only verification, private
replay, PLONK verification, and rejection of a modified PLONK proof.

The ZK tests need the generated, ignored `zk/demo-run/` fixture and a
bootstrapped toolchain. On a clean clone, run `./scripts/bootstrap-zk.ps1` and
`./scripts/prove-zk-demo.ps1` before `pytest`; otherwise pytest skips them.

Read [the protocol specification](docs/PROTOCOL.md) and
[security boundaries](SECURITY.md) before adapting this code.

## Errata

- v1 proved one unsigned scalar update, and only where `prediction <= y`. Now four signed transitions.
- Power 14 covered v1. The `N=4` relation needs 53,313 PLONK constraints, so power 16.
- `state-commitment.mjs` accepted any field element for w, b and counter. Now range-checked.
- `codeCommitment` hashes raw circuit bytes. Line endings were unpinned until `.gitattributes`.

[^transcript]: The committed benchmark run did not do it either.
