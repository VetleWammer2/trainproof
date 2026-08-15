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
dictionary tests against low-entropy records.

## Ordering commitment

A private 32-byte sampler seed assigns each dataset index a SHA-256 score. The
indices sorted by score form a deterministic permutation. Each
`(position, dataset_index)` pair is independently salted and committed in a
second Merkle tree. The public statement commits to the seed, opaque leaves,
algorithm, count, and root.

The transcript verifier can establish that assignments reference committed
dataset and ordering leaves. The private replay ties those leaves together.
It also requires equal opened dataset/order counts and binds the initial RNG
state to the ordering seed commitment and counter zero. The ZK demo performs
the analogous link inside its circuit.

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

The Circom circuit exposes nine public BN254 field elements:

```text
step
datasetRoot
orderingRoot
codeCommitment
hyperparametersCommitment
oldStateCommitment
newStateCommitment
prevChain
nextChain
```

Its private witness contains one sample, record salt, dataset Merkle path,
sample index, ordering salt/path, old scalar affine-model state, RNG counter,
and old/new state salts.

The circuit enforces:

1. `sampleIndex`, `x`, and `y` open a salted Poseidon leaf under
   `datasetRoot`.
2. `(step, sampleIndex)` opens a salted leaf under `orderingRoot`; path bits
   equal the range-constrained step bits.
3. The private old state opens `oldStateCommitment`.
4. All relevant values obey explicit unsigned bit bounds.
5. `prediction = oldW*x + oldB` and `prediction <= y`.
6. `delta = y - prediction`, `newW = oldW + delta*x`,
   `newB = oldB + delta`, and `newRng = oldRng + 1`.
7. The resulting private state opens `newStateCommitment`.
8. A domain-separated Poseidon transition maps `prevChain` to `nextChain`
   while binding all public roots and commitments.

The host profile additionally binds `prevChain` to a fresh 128-bit `run_id`,
derives `codeCommitment` from the pinned circuit bytes, derives the
hyperparameter commitment from the fixed v1 specification, and requires all
public field elements to be canonical decimal strings in `[0, p)`.

The ordering relation proves only membership of `(step, sampleIndex)` in the
committed tree. It does not prove that this tree is a permutation, that it was
derived from a seed or VRF, or that sampling was unbiased.

Before proof generation, the producer signs dataset and ordering statements,
a run genesis, and a concrete public checkpoint opening, then records their
roots in a three-entry witnessed log head. After proof generation, the proof,
public vector, verification key, circuit source, R1CS, precommit receipt, and
checkpoint each receive a domain-separated SHA-256 digest inside a
coordinator-signed step envelope. The verifier recompiles source to R1CS and
deterministically rederives the verification key from the authenticated PoT.
It then appends and verifies the proof step plus exact checkpoint anchor.
The local pre-proof head gives sequence within the supplied view; external
publication is still required for trusted time and fork resistance.
