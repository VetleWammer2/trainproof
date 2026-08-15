# Trainproof

Trainproof is a reference implementation of proof-carrying checkpoints for
distributed model training. It has two deliberately separate assurance modes:

1. A practical signed transcript with hiding dataset commitments, worker
   receipts, a per-step hash chain, a witnessed transparency log, exact
   canonical-checkpoint binding, and deterministic private replay.
2. A real Circom/PLONK zero-knowledge demonstration proving one bounded
   training transition, including private dataset membership, private sample
   ordering, state openings, the update equation, and a Poseidon step chain.

The project never labels a hash chain as a proof of execution. The public
verifier says explicitly whether execution was merely committed, privately
replayed, or proven by the included ZK circuit.

## Quick start: signed distributed transcript

Python 3.11+ is required. The source root defaults to the current directory;
an installed wheel never guesses a repository from its installation path.

```powershell
python -m pip install -e .
python -m trainproof demo --output demo-run --steps 4 --workers 2
python -m trainproof verify demo-run
python -m trainproof audit demo-run --source .
```

The demo also emits `demo-run/trust-policy.example.json`. It pins participant
key IDs together with the expected run, dataset, ordering, source/Git,
hyperparameter, trajectory-head, and checkpoint claims. Approve and copy it to
a verifier-controlled location before relying on those claims, then pass it
explicitly:

```powershell
Copy-Item demo-run/trust-policy.example.json C:\verifier-policy\trainproof-demo.json
python -m trainproof verify demo-run --source . --trust-policy C:\verifier-policy\trainproof-demo.json
python -m trainproof audit demo-run --source . --trust-policy C:\verifier-policy\trainproof-demo.json
```

Passing the policy straight from an untrusted bundle proves nothing about
identity or intent; the verifier must authenticate the policy out of band.

`verify` reads only `public/` and the checkpoint under `artifacts/`. `audit`
also reads `private/`, opens the hidden data and update commitments, derives
the precommitted order, and checks every transition by replay. Passing
`--source` additionally requires the source files and Git metadata to match
the fixed-policy source manifest.

A successful replay proves that the committed transcript is satisfiable under
the reference transition relation. It does not prove that those operations
historically ran on the claimed workers or at the bundle's timestamps.
Within the source tree, demo output is restricted to the fixed top-level
`demo-run/` or `tampered-run/` exclusions; arbitrary bundle-selected source
exclusions are rejected.

The generated bundle is organized as follows:

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

The private keys are generated inside the demo bundle for reproducibility and
must not be treated as production key management or external identity trust.
The verifier enforces distinct keys and exact protocol roles, but only an
outside PKI/governance root can establish who controls them.

## Quick start: real zero-knowledge proof

The ZK demo currently targets Windows x64/PowerShell and requires Node.js/npm.
It uses pinned Circom 2.2.3, `snarkjs` 0.7.6, `circomlib` 2.0.5, PLONK over
BN254, and the iden3/Hermez public Powers-of-Tau ceremony.

```powershell
./scripts/bootstrap-zk.ps1
./scripts/prove-zk-demo.ps1
python -m trainproof zk-verify zk/demo-run
```

`prove-zk-demo.ps1` first creates a signed, witnessed pre-proof head for the
dataset root, ordering root, run-specific genesis, code/hyperparameters, and
concrete checkpoint. It then generates the witness and PLONK proof, appends
both the proof step and checkpoint anchor, and runs the independent public
verifier. The pre-proof head establishes local workflow order, not external
time.

To prevent generated inputs and demo signing keys from entering source
manifests, in-repository ZK output is restricted to the fixed ignored path
`zk/demo-run/`. Pass an absolute path outside the repository for additional
runs.

The bootstrap checks the Circom SHA-256 and the Powers-of-Tau BLAKE2b against
the hashes published by the upstream projects. A full contribution-by-
contribution ceremony audit is intentionally opt-in because it is slow:

```powershell
./scripts/bootstrap-zk.ps1 -VerifyTranscript
```

The ZK verifier never reads `zk/demo-run/private/`; it needs only the run's
`public/` directory. It also requires a trusted local toolchain root containing
the pinned Circom binary, lockfile-installed Node modules, and authenticated
Powers-of-Tau file. It recompiles the pinned circuit, byte-compares the R1CS,
rederives the PLONK verification key from that R1CS and PoT, verifies the
proof, opens the exact public checkpoint to `newStateCommitment`, and checks
the signed SHA-256 envelope, pre-proof head, final log, and certificate.

As with the transcript demo, copy and independently approve
`zk/demo-run/trust-policy.example.json` before using it. The ZK policy pins the
participant keys, exact relation/circuit, private roots, state commitments,
Poseidon chain endpoints, and checkpoint digest:

```powershell
python -m trainproof zk-verify zk/demo-run --toolchain-root . --trust-policy C:\verifier-policy\trainproof-zk.json
```

## Assurance levels

| Mode | Publicly detects tampering | Attributes workers | Verifies transition math | Records required to verify |
|---|---:|---:|---:|---:|
| Signed transcript | Yes | Manifest keys only | No | No |
| Private replay | Yes | Manifest keys only | Satisfiability by replay | Yes; auditor sees openings |
| Included PLONK demo | Yes | N/A, single transition | Yes, for the exact circuit | No |

“No records required” is a verifier-input guarantee, not proof that a malicious
producer did not voluntarily encode data in permitted cryptographic values.
The strict schemas reject extra payload fields, while confidentiality still
assumes an honest producer and sound randomness generation.

The included ZK circuit proves one unsigned, range-constrained integer update
over the BN254 field. It does **not** prove PyTorch, GPU execution, BF16/FP32,
or a large neural-network training run. It proves membership in the committed
ordering tree, not that the tree is a permutation, seed-derived, or unbiased.
Extending the circuit or replacing it with a zkVM backend changes the relation
and requires a new protocol version.

## Tests

```powershell
python -m pytest -q
```

The suite covers canonical encoding, odd-sized Merkle trees, role-bound and
distinct signing keys, fixed source exclusions and Git metadata, chain and
checkpoint tampering, replay-state binding, public-only verification,
successful private replay, successful PLONK verification, and rejection of a
modified PLONK proof.

The ZK tests run when the generated, ignored `zk/demo-run/` fixture and
bootstrapped toolchain are present. On a clean clone, run
`./scripts/bootstrap-zk.ps1` and `./scripts/prove-zk-demo.ps1` before `pytest`
to exercise them; otherwise pytest reports them as skipped.

See [the protocol specification](docs/PROTOCOL.md) and
[security boundaries](SECURITY.md) before adapting this code.
