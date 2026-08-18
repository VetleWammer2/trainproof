# Trainproof protocol v1

## Canonical objects

Every signed or hashed protocol object uses the Trainproof canonical JSON
profile:

- UTF-8, NFC-normalized strings
- string dictionary keys only
- lexicographically sorted keys
- no insignificant whitespace
- integers, booleans, null, lists, and dictionaries only
- no floats, NaN, duplicate keys, or raw binary values
- binary values represented as lowercase hexadecimal strings

Domain-separated hashing is:

```text
SHA256(
  "trainproof/v1\0" ||
  uint16_be(len(domain)) || domain ||
  uint64_be(len(payload)) || payload
)
```

## Identity and source commitments

Every Ed25519 public-key document binds the protocol version and one exact
role. Coordinator, custodian, log operator, witness, and worker-rank key IDs
must all be distinct. These checks prevent role confusion; they do not turn
the demo's self-issued keys into externally trusted identities.

A verifier may supply a `pinned-run-and-participant-claims/v2` trust policy.
Its exact coordinator, custodian, log-operator, witness, and worker key IDs
must match, as must the expected run, committed inputs, trajectory endpoint,
and checkpoint. A policy copied from an untrusted bundle is not a trust anchor;
the complete policy must be authenticated independently.

The source manifest uses a versioned, fixed exclusion policy. Paths to omit
cannot be selected by the bundle being verified. When a verifier or auditor is
given a source root, it recomputes and compares the complete file list, root,
and Git tool/worktree/commit/dirty metadata. Without a supplied source root,
only the signed descriptor's internal consistency is checked.

## Dataset commitment

For record `i`, with a fresh 32-byte salt:

```text
leaf_i = H_dataset_record({ index: i, record: record_i, salt: salt_i })
```

The public statement contains every opaque leaf commitment, the leaf count,
schema, and a count-bound binary Merkle root. The statement is signed by the
dataset-custodian key pinned in the run manifest. The salt prevents practical
dictionary tests against low-entropy records. Protocol v1 requires
`additional_roots` to be exactly empty so the statement cannot carry an
untyped payload.

## Ordering commitment

A private 32-byte sampler seed assigns each dataset index a SHA-256 score. The
indices sorted by score form a deterministic permutation. Each
`(position, dataset_index)` pair is independently salted and committed in a
second Merkle tree. The public statement commits to the seed, opaque leaves,
algorithm, count, and root.

The transcript verifier can establish that assignments reference committed
dataset and ordering leaves. The private replay ties those leaves together.
It also requires equal opened dataset/order counts and binds the initial RNG
state to the ordering seed commitment and counter zero. The ZK profile is
different: it proves membership at consecutive public positions and binds a
state counter to those positions, but does not prove seed derivation.

## Distributed training step

Each coordinator-signed assignment binds:

- run, manifest, step, rank, and previous step commitment
- all pre-state roots
- an opaque dataset leaf plus Merkle inclusion proof
- an opaque ordering leaf plus Merkle inclusion proof

The public verifier also requires the ordering proof index and
`order_position` to equal `(step * worker_count + rank) mod record_count`.

Each worker signs a receipt binding the assignment digest, pre-state roots,
and a salted update commitment. The step contains Merkle roots over all signed
assignments and receipts, a salted aggregate-update commitment, post-state
roots, and the preceding step commitment.

```text
C_0 = H_run_genesis(genesis)
C_t = H_training_step(step_body_t containing C_(t-1))
```

The public transition-proof field is fixed to
`private-deterministic-replay/v1` and explicitly sets both
`publicly_verifiable` and `zero_knowledge` to false. A verifier rejects any
attempt to silently upgrade those claims.

Private replay additionally checks the exact initial integer-SGD optimizer
state and every update/state opening. Passing replay establishes existence of
a satisfying committed trajectory under this relation; it is not evidence
that the trajectory historically executed on the signing machines.

## Transparency log and certificate

Dataset, order, genesis, every step, and the checkpoint anchor are appended to
a binary Merkle log. Each prefix has a tree head signed by both the operator
and witness. Heads bind their predecessor, preventing undetectable rewriting
inside one observed view. Production deployments still need external head
publication and monitors to prevent split views. Bundle-local witness keys and
timestamps do not establish external identity or time.

The final certificate binds the manifest, genesis, chain head, exact canonical
checkpoint digest, terminal state roots, signed final log head, and checkpoint
inclusion proof. Coordinator and witness both sign the certificate.

## Concrete ZK relation

The production v2 Circom profile compiles exactly `N = 4`, two features,
dataset depth 2, and ordering depth 4 into its R1CS. It exposes ten public
BN254 field elements:

```text
initialStep
transitionCount       // constrained equal to 4
datasetRoot
orderingRoot
codeCommitment
hyperparametersCommitment
initialStateCommitment
finalStateCommitment
initialChain
finalChain
```

The private witness contains four record and ordering openings, five shared
states and salts, and the quotient/remainder witnesses for every fixed-point
rescale. State `i + 1` is one shared signal array: it is both the output of
transition `i` and the input of transition `i + 1`.

For each slot `i` in `[0, N)`, the circuit sets
`absoluteStep_i = initialStep + i` and enforces:

1. The encoded two-feature sample opens
   `D_i = Poseidon(201, sampleIndex_i, x0_i, x1_i, y_i, recordSalt_i)` at
   exactly `sampleIndex_i` under `datasetRoot`; dataset nodes use domain 202.
2. `O_i = Poseidon(203, absoluteStep_i, sampleIndex_i, orderSalt_i)` opens at
   exactly `absoluteStep_i` under `orderingRoot`; ordering nodes use domain
   206. The four positions are therefore consecutive and cannot be reordered,
   skipped, or inserted within this fixed-size proof.
3. Every sample value, model value, prediction, error, gradient, parameter
   step, and resulting model value obeys the fixed-point contract in
   [FIXED_POINT.md](FIXED_POINT.md). The state counter is unsigned 32-bit and
   equals `initialStep + i`; state `N` has counter `initialStep + N`.
4. Each shared state opens
   `S_i = Poseidon(204, w0Encoded_i, w1Encoded_i, bEncoded_i, counter_i, salt_i)`.
   `S_0` and `S_N` equal the public initial/final commitments.
5. The exact opened transition is absorbed as
   `T_i = Poseidon(205, absoluteStep_i, datasetRoot, orderingRoot,
   codeCommitment, hyperparametersCommitment, D_i, O_i, S_i, S_(i+1))`.
6. The ordered chain advances as `C_(i+1) = Poseidon(207, C_i, T_i)`, with
   public endpoints `C_0 = initialChain` and `C_N = finalChain`.

The host binds `initialChain` to
`SHA256("trainproof-zk-run/fixed-point-v2\0" || ASCII(runId)) mod p`, derives
`codeCommitment` from the exact LF bytes enforced by `.gitattributes`, derives the
hyperparameter commitment from the complete fixed v2 profile string, and
requires every public field element to be a canonical decimal string in
`[0, p)`. It also enforces the exact snarkjs PLONK proof schema and canonical
curve/scalar encodings before invoking the cryptographic verifier.

This ordering relation proves membership at four consecutive positions only.
It does not prove that the 16-leaf ordering tree is a permutation, derived
from a seed or VRF, or unbiased.

Before proof generation, the producer signs dataset and ordering statements,
a run genesis, and the concrete terminal checkpoint opening, then records
their roots in a three-entry witnessed log head. After proof generation, the
proof, public vector, verification key, circuit source, R1CS, precommit
receipt, and checkpoint receive domain-separated SHA-256 digests inside a
coordinator-signed envelope. The verifier recompiles source to R1CS,
byte-compares it, and deterministically rederives the verification key from
the power-16 PoT matched to the pinned upstream digest. It then verifies the proof step and exact
checkpoint anchor. The local pre-proof head gives sequence within the supplied
view; external publication remains required for trusted time and fork
resistance.
