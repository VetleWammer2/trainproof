# Security boundaries

This repository is a research/reference implementation, not an audited
cryptographic product.

## What the signed-transcript verifier establishes

- canonical artifacts have not changed after signing
- the dataset and sample-order roots match their published opaque leaves
- coordinator assignments and worker receipts have valid Ed25519 signatures
- participant key documents use the required roles and distinct key IDs
- step, state, and predecessor commitments form one consistent chain
- the canonical checkpoint object opens the terminal committed state
- every supplied transparency prefix and certificate has valid witness
  signatures

It does not publicly establish that worker updates or the aggregate were
computed correctly. The private audit opens the records and establishes that
all committed transitions satisfy the reference replay relation, at the cost
of revealing them to that auditor. Replay does not prove historical execution,
wall-clock timing, or physical worker participation.

The demo keys are self-issued. Distinct role keys prevent accidental role
collapse, but do not establish real-world identity or organizational witness
independence. Likewise, bundle-local signed timestamps are assertions, not an
external time anchor.

All verifier commands accept `--trust-policy`. This matches both participant
key IDs and the exact expected run/input/trajectory/checkpoint claims against a
policy supplied by the verifier, rather than trusting producer-selected values
from the bundle itself. The generated `trust-policy.example.json` is only a
template: authenticate and pin it through an independent channel before use.

Supplying `--source` makes verification compare the complete fixed-policy
source manifest, including Git repository/commit/dirty metadata. Without it,
the verifier checks only the signed source descriptor's internal consistency.

## What the PLONK verifier establishes

Assuming PLONK soundness, Poseidon security, BN254 assumptions, and a sound
Powers-of-Tau setup, it establishes existence of a private witness satisfying
the pinned relation in `zk/circuits/train_step.circom`. The verifier
recompiles that source, byte-compares its R1CS, rederives the verification key
from the R1CS and digest-matched PoT, and binds a concrete checkpoint opening
to the proven terminal state.

For the v2 profile, that witness contains exactly four consecutive
two-feature fixed-point linear-SGD transitions. Every transition proves
private dataset and ordering membership, shares its output state with the next
transition, advances the state counter, and is absorbed into the public
Poseidon chain. Signed raw values, every named intermediate, quotient
remainders, and state outputs obey [the fixed-point contract](docs/FIXED_POINT.md);
overflow rejects rather than wraps. This establishes the declared arithmetic
relation, not that any historical trainer performed it.

It does not establish:

- PyTorch, CUDA, GPU, BF16, FP32, or physical machine execution
- arbitrary neural-network, tensor, activation, optimizer, or reduction semantics
- wall-clock timing or compute expenditure
- dataset ownership, licensing, consent, quality, or absence of poisoning
- that a custodian's real-world identity is legitimate beyond the configured key
- that the initial state has no earlier, uncommitted training history
- that ordering-tree membership implies a permutation, seed derivation, or
  unbiased sampling
- external chronology: the signed pre-proof head is bundle-local unless
  published to an independent monitor
- salt randomness inside the circuit; demo generation uses OS randomness, but
  the circuit does not constrain entropy

The default bootstrap checks the power-16 ceremony file against the BLAKE2b
hash published by iden3/snarkjs. Pass `-VerifyTranscript` to audit every
ceremony contribution locally. The power was increased because the measured
four-step relation is too large for power 14; that does not weaken or remove
the relation's invariants.

The public transcript and ZK verifiers do not require training records. That
is not a proof that a malicious producer preserved confidentiality: a producer
can intentionally encode information in salts, signatures, proof randomness,
or other permitted cryptographic values. Strict schemas reject unknown payload
fields (and transcript v1 requires `additional_roots == {}`), but privacy
remains an honest-producer property in addition to the ZK protocol's witness
hiding.

## Production changes required

- Put signing keys in HSMs or workload-attested key stores; never place them
  beside the bundle.
- Pin identities through an external PKI or governance root.
- Publish signed log heads to independently operated monitors and require
  consistency proofs to prevent split views.
- Replace the demo witness key with an organizationally independent witness.
- Bind source, lockfiles, container image, compiler, kernels, drivers, numeric
  semantics, and reproducible build output.
- Define deterministic distributed reductions and failover/retry behavior.
- Use a proof relation that exactly matches the production trainer, including
  signed/fixed-point or IEEE floating-point behavior.
- Obtain independent reviews of the circuit, host verifier, protocol schemas,
  dependency chain, and trusted setup.

## Dependency note

The Python public-transcript verifier depends only on `cryptography` beyond the
standard library. The optional ZK toolchain pins Circom/snarkjs/circomlib
versions. Treat npm audit findings and all transitive build dependencies as
supply-chain review items before deployment; do not run the ZK build toolchain
inside a privileged production verifier.

The demo's `private/keys/` directory exists only to make the example
self-contained. Private replay needs the openings and trace, not those signing
keys. Never distribute demo key material as an audit package in production.
