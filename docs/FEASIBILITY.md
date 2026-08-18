# Multi-step proving feasibility and backend verdict

## Verdict

**NO-GO for making the next evidence milestone another custom-Circom-only
scale-up.** Keep the four-step circuit as a small, auditable reference, but use
the next milestone for an implementation-parity experiment in a zkVM or other
backend. This is not a recommendation to rewrite Trainproof, abandon custom
circuits, or select a particular replacement.

The four-step proof succeeded. For the fixed v2 profile, however, the complete
relation adds 8,711 R1CS constraints for each added transition at the measured
`N=1,2,4` points. That marginal cost includes membership proofs, Poseidon
hashes, range and rescaling checks, and the two-feature update; it is not the
cost of fixed-point multiplication alone. At `N=4`, the proving key is
194.8 MB, and proof generation on the measured workstation took a median
47.2 seconds with a median 1.38 GB peak primary-process working set. The
relation remains far smaller than a useful neural layer and excludes
activations, tensors, optimizer state, reductions, and floating-point
behavior.

No zkVM was implemented or benchmarked in this milestone. The measurements do
not establish that any zkVM is faster, smaller, safer, or cheaper than the
custom circuit. They support spending the next milestone obtaining comparable
evidence instead of assuming that another custom-only scale-up is the best use
of the milestone.

## Measurements and limitations

Raw per-trial data is in
[`benchmarks/results/windows-i7-8700k-2026-08-18.json`](../benchmarks/results/windows-i7-8700k-2026-08-18.json).
The procedure is implemented by
[`scripts/benchmark-zk.ps1`](../scripts/benchmark-zk.ps1).

The result records base commit `da41c02e9c5c3435edc1d386f8cbfbf32499c8b0`
and `worktreeDirtyDuringMeasurement: true`. It includes circuit and R1CS
hashes, but it does not identify a clean commit containing the exact benchmark
runner, reference implementation, witness generator, and inputs that were
used. The measurements are therefore an evidence-bearing snapshot, not a
fully reconstructible source-tree attestation. A rerun from a clean commit, or
a manifest hashing every relevant source and fixture, is required for exact
reproduction.

Host: Windows 11 Pro, Intel i7-8700K (6 cores/12 threads), 16 GiB RAM; Circom
2.2.3, snarkjs 0.7.6, circomlib 2.0.5, Node 24.18.0, and PLONK/BN254. The
Powers-of-Tau file was `powersOfTau28_hez_final_16.ptau`. The bootstrap checks
the downloaded file against the published BLAKE2b digest; the benchmark runner
itself records the expected digest rather than recomputing it and does not
record whether contribution-by-contribution transcript verification ran.
These results should therefore be described as using a digest-pinned PoT file,
not as evidence of a fresh full transcript audit.

Witness generation, proof generation, and verification are medians of three
fresh CLI processes. “Fresh” does not mean that operating-system caches were
flushed. Compile and PLONK setup were each measured once per profile, so their
times are single observations rather than medians. Input/reference generation
and `snarkjs wtns check` are outside the reported witness timing. Peak memory is
the primary process working set polled every 10 ms; it excludes unrelated host
processes, is not whole-system peak RAM, and may not represent a backend that
uses child processes or a GPU.

| Profile | N | R1CS constraints | Average constraints/transition | PLONK constraints | R1CS bytes | zkey bytes | Witness median | Prove median | Prove peak | Verify median | Proof JSON |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Legacy unsigned scalar v1 | 1 | 8,408 | 8,408.0 | 12,276 | 1,214,440 | 46,039,580 | 0.443 s | 12.672 s | 835 MB | 0.643 s | 2,248 B |
| Fixed-point vector v2 | 1 | 9,765 | 9,765.0 | 14,604 | 1,423,044 | 48,758,796 | 0.426 s | 12.138 s | 836 MB | 0.601 s | 2,249 B |
| Fixed-point vector v2 | 2 | 18,476 | 9,238.0 | 27,507 | 2,688,184 | 97,449,952 | 0.461 s | 26.009 s | 1,190 MB | 0.625 s | 2,249 B |
| Fixed-point vector v2 | 4 | 35,898 | 8,974.5 | 53,313 | 5,218,464 | 194,832,264 | 0.460 s | 47.206 s | 1,384 MB | 0.665 s | 2,248 B |

The single `N=4` setup observation was 12.197 seconds and 1.467 GB peak
primary-process working set. Verification-key JSON stayed about 2 KB, and the
snarkjs proof JSON stayed about 2.25 KB. Those are JSON serialization sizes,
not canonical binary or on-chain encodings. Constant proof-object shape does
not imply constant proving work, key size, or public-input encoding cost.

The three v2 proof-time ranges were 11.658–12.678 seconds at `N=1`,
21.052–30.040 seconds at `N=2`, and 42.119–50.200 seconds at `N=4`. Three
trials support the reported medians but do not characterize tails, thermal
effects, or host-load variance.

The deterministic constraint counts fit these equations at the measured
`N=1,2,4` points:

```text
R1CS constraints  = 1,054 + 8,711 * N
PLONK constraints = 1,701 + 12,903 * N
```

These equations describe this exact two-feature, depth-2/depth-4 profile at
the sampled points. They are not measured predictions for larger `N`, another
feature width, another tree depth, or a neural model. Resource use is not
smooth merely because constraint count is linear: the PLONK counts cross
successive power-of-two ranges while the measured zkey sizes roughly double
from 48,758,796 to 97,449,952 to 194,832,264 bytes. That observation is
consistent with stepwise domain sizing; it is not a fit for unmeasured sizes.

The measured PLONK counts for `N=2` (27,507) and `N=4` (53,313) both exceed
`2^14`. An `N=4` setup attempt with the former power-14 file was also observed
to fail, but that failed invocation and its stderr are not represented in the
machine-readable result, which contains successful profiles only. The
production profile moved to the published power-16 file. Removing membership,
range, or chain constraints to fit a smaller setup would change the proven
relation and is not an acceptable optimization.

## Whole-relation v2 cost versus the old demo

At `N=1`, v2 has 1,357 more R1CS constraints than the preserved v1 R1CS
(+16.1%), 208,604 more R1CS bytes, and a 2,719,216-byte larger zkey. The
preserved baseline is intended to reproduce the v1 relation from `main` and
produced the R1CS hash recorded in the benchmark result. Exact source-tree
reconstruction remains subject to the dirty-snapshot limitation above.

This is not a fixed-point arithmetic microbenchmark. V2 also moves from one
unsigned scalar feature to two signed features, changes record and state
hashes, adds quotient/remainder checks, adds an explicit transition digest and
chain hash, and makes state types closed under iteration. The delta is the
whole-relation difference between v1 and v2. It does not isolate the cost of a
multiply, rescale, signed range check, or second feature. The slightly lower
v2 `N=1` proving median must not be read as fixed point making proving faster.

If a causal arithmetic cost is needed, a future experiment should compile an
explicitly non-production ablation while retaining the full relation as the
security baseline. No ablation may be presented as proving the production
claim.

## Where constraint growth comes from

For `N` transitions, the circuit structurally instantiates:

- `3N` Poseidons for dataset leaves and depth-2 paths;
- `5N` Poseidons for ordering leaves and depth-4 paths;
- `2N` Poseidons for transition digests and chain links; and
- `N+1` Poseidons for shared state commitments.

That is `11N+1` Poseidon instances before arithmetic. Each step also
range-checks three sample values, the rescaled dot, prediction, error, two
gradients, two parameter steps, a bias step, and their canonical remainders.
Every shared state range-checks two weights, a bias, and a 32-bit counter.
State-hash reuse avoids hashing both endpoints independently in every slot,
but membership, transition hashing, and arithmetic remain per-step costs.

This is a structural inventory, not a measured attribution of how many
constraints or seconds each category contributes. Isolating those shares
would require labeled component counts or ablations.

Circom template sizes and array lengths are compile-time parameters. Thus a
different `N`, feature width, or tree depth is a new circuit/R1CS/zkey/verifier
profile, even though PLONK can reuse a universal Powers of Tau. See the
[Circom template documentation](https://github.com/iden3/circom/blob/master/mkdocs/docs/circom-language/templates-and-components.md)
and [snarkjs setup documentation](https://github.com/iden3/snarkjs).

## What the small measured primitive costs

The v2 `N=1` row is a small measured baseline: one two-feature linear
prediction, signed error, two gradients, learning-rate rescaling, two weight
updates, one bias update, dataset/order membership, state commitments, and one
chain link. It costs 9,765 R1CS constraints, a 48.8 MB zkey, and a median
12.1-second proof on this host.

It is not a neural-network training step and is not a formal lower bound for
one. A single activated neuron would require declared activation and
derivative semantics; a layer would require a declared input/output shape,
accumulation schedule, update rule, and state commitment strategy. No such
target was implemented or measured, so the numeric cost of a “minimally
interesting neural training step” remains unknown. No transformer,
convolution, matrix-training, PyTorch, BF16/FP32, or GPU-execution cost is
claimed.

## Custom circuit versus program proving

The custom circuit remains attractive for the parts already native to this
protocol:

- exact compatibility with the existing BN254 circomlib Poseidon dataset,
  ordering, state, and chain commitments;
- small static Merkle paths and a fixed operation graph whose ranges can be
  reviewed directly; and
- the measured approximately 2.25 KB snarkjs proof JSON and approximately
  0.6-second verification on this host.

A zkVM may reduce circuit-authoring friction when the relation changes shape:
variable-length loops, richer optimizer state, control flow, and tensor
layouts can be expressed as program logic, while continuations or recursion
can split long execution traces. Those mechanisms do not remove the work of
proving each operation, guarantee favorable performance, or remove the need
for an explicit protocol bound and version.

A zkVM proves execution of a pinned machine program. It does not establish
that the source is correct, that the compiler preserved the intended
semantics, or that the program is PyTorch, historical GPU execution, BF16,
FP32, or arbitrary model training. Adoption therefore requires a reproducible
source-to-binary build and verifier binding to the exact program image, proof
configuration, backend version, and security parameters.

Exact circomlib-compatible BN254 Poseidon is not listed as a standard
application precompile by the general RISC-V zkVMs reviewed. See the official
[SP1 precompile specification](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompile-specification)
and [RISC Zero precompile list](https://dev.risczero.com/api/zkvm/precompiles).
Implementing the existing hash in guest code may dominate a VM experiment; a
custom accelerator can reduce that cost only by reintroducing custom-chip
implementation and audit work. This must be measured rather than assumed.

## Backend research snapshot

The following primary sources were reviewed on **2026-08-18**. Version labels
identify the documentation snapshot; none of these backends was installed or
benchmarked for this milestone.

- **OpenVM 2.0.x** (the install page exposed CLI 2.0.2 when reviewed) is a
  plausible protocol-compatibility experiment because its
  [algebra extension](https://docs.openvm.dev/book/acceleration-using-extensions/algebra/)
  supports compile-time modular fields and explicitly gives BN254 as an
  example, while
  [continuations](https://docs.openvm.dev/specs/architecture/continuations/)
  address long executions. Modular BN254 arithmetic does not by itself provide
  the exact existing Poseidon implementation. A
  [custom extension](https://docs.openvm.dev/book/advanced-usage/creating-a-new-extension/)
  would restore custom-chip test and audit obligations. The reviewed
  [security model](https://docs.openvm.dev/specs/security/security-model/)
  did not clearly establish the application-witness privacy guarantee needed
  here, so privacy is an adoption blocker pending a written primary-source
  answer. The official
  [installation guidance](https://docs.openvm.dev/book/getting-started/install/)
  targets Ubuntu/macOS and describes GPU requirements, while this benchmark
  record contains no GPU model or VRAM. Hardware compatibility is therefore
  unestablished, and Windows would require a different execution environment.

- **SP1 v6-family documentation** describes a general RISC-V zkVM with
  [recursive aggregation](https://docs.succinct.xyz/docs/sp1/writing-programs/proof-aggregation)
  and multiple [proof types](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types).
  Its [security model](https://docs.succinct.xyz/docs/sp1/security/security-model)
  says individual STARK proofs are not currently zero knowledge, while the
  Groth16 and PLONK wrappers are. A privacy-preserving comparison must include
  a wrapper, not just a core or compressed proof. The wrapper choices also have
  different setup assumptions: the documented Groth16 path uses a
  circuit-specific ceremony, while PLONK relies on a universal ceremony. The
  official [hardware guidance](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements)
  lists at least 16 GB for several local paths and at least 64 GB for PLONK,
  making proof type and hardware part of the experiment. Official
  [installation](https://docs.succinct.xyz/docs/sp1/getting-started/install)
  targets Linux/macOS rather than native Windows. SP1 also warns that cycles
  alone do not account for differing chip/precompile cost; its
  [prover-gas guidance](https://docs.succinct.xyz/docs/sp1/optimizing-programs/prover-gas)
  should be recorded alongside wall time and memory.

- **RISC Zero 3.0.x documentation** provides verifier binding to a guest
  ImageID and public journal through
  [receipts](https://dev.risczero.com/api/zkvm/receipts), with
  [recursion](https://dev.risczero.com/api/recursion) for segmented execution.
  Its [security model](https://dev.risczero.com/api/security-model) explicitly
  says that it targets perfect zero knowledge but does not yet have a
  mathematical argument establishing that property. It also says an
  un-recursed RISC-V proof leaks execution length and that recursion removes
  that leak. These are material privacy caveats, not a generic “zkVM means ZK”
  guarantee. The reviewed
  [installation guidance](https://dev.risczero.com/api/zkvm/install) provides
  first-class binaries for Linux/macOS rather than native Windows. Its
  documented precompiles do not promise compatibility with this protocol's
  BN254 Poseidon.

- **Jolt**, as represented by its official
  [repository](https://github.com/a16z/jolt) on the access date, is an optional
  research control rather than an adoption recommendation because the project
  labels itself alpha and unsuitable for production.

- **zkDL** is evidence that specialized sumcheck/GKR-style systems merit study
  for dense tensor workloads, not a drop-in backend or comparable performance
  result. Its [paper](https://eprint.iacr.org/2023/1174.pdf) evaluates a
  particular 32-bit integer profile with scale `2^16` and reports that overflow
  was not observed experimentally; that is not the same as this protocol's
  circuit-enforced overflow rejection. The authors'
  [implementation repository](https://github.com/jvhs0706/zkdl-train) is
  archived. Its GPU headline numbers must not be transferred to this workload,
  and its results are not evidence of PyTorch, BF16/FP32, or historical GPU
  equivalence.

“Released,” “audited,” or “production” statements made by backend authors are
not substitutes for Trainproof's own parity, privacy, resource, and verifier
tests. No cross-backend performance number from vendor documentation is used
in this verdict.

## Falsifiable gates for the next milestone

Project owners have not yet declared numeric resource budgets or a minimally
interesting model shape. These values must be filled in before executing the
parity experiment; until then, the verdict selects the next experiment, not a
winning backend.

| Decision input | Predeclared value |
|---|---|
| Fixed v2 parity sizes | `N=1,2,4`; attempt `N=8` if it fits the declared resource limits |
| Minimally interesting feature/model shape | **TBD by project owners** |
| Maximum setup/preprocessing wall time | **TBD by project owners** |
| Maximum proof wall time | **TBD by project owners** |
| Maximum peak host RAM / accelerator VRAM | **TBD by project owners** |
| Maximum proving-key, verification-key, and proof sizes | **TBD by project owners** |
| Maximum verification wall time | **TBD by project owners** |
| Minimum accepted soundness/security level | **TBD by project owners** |
| Accepted trusted-setup assumptions | **TBD by project owners** |
| Whether a network prover may see private witness data | **TBD by project owners; default must be no** |
| Maximum audit/rekey/release-engineering effort per shape | **TBD by project owners** |

### Correctness and security gates

Every candidate, including Circom, must:

1. agree bit-for-bit with the fixed-point reference for the declared signed
   domain, operation order, floor quotient/remainder rule, and overflow
   rejection behavior;
2. preserve the same dataset membership, ordering membership, absolute step,
   fixed transition count, initial/final state commitments, and Poseidon chain,
   including rejection of a modified intermediate state, reordered, skipped,
   or inserted steps, and modified sample membership;
3. reject the same boundary and adversarial fixtures and reject tampered public
   proofs or public statements through the public verifier;
4. use an actual zero-knowledge proof mode with documented witness-privacy
   properties—not a mock, development, core-only non-ZK, or silently trusted
   remote-prover mode; and
5. bind verification to exact circuit or program artifacts, backend/proof
   configuration, security parameters, and a reproducible source-to-artifact
   build.

Correctness is established through specification, constraint/program review,
tests, and valid/invalid proofs; it is not a performance measurement.

### Measurement protocol

The parity experiment must:

- pin backend version/commit, compiler and guest toolchain, program ImageID or
  verification key, proof type, recursion/wrapper mode, setup artifact, and
  claimed security level;
- use identical reference states, samples, roots, order openings, salts, and
  public statements at each fixed v2 `N`;
- separate input preparation, compile/setup/preprocessing, witness or guest
  execution, core proving, recursion/wrapping, and verification;
- record wall time, peak primary and whole-process-tree RAM where practical,
  peak VRAM, proof/key/artifact sizes, and backend-specific work units;
- run at least three fresh-process trials, report median and range, and label
  cold-cache and warm-cache measurements separately if both are claimed;
- use comparable hardware and security levels for direct ratios; if a backend
  requires different hardware, WSL/Linux, a GPU, or a network prover, report it
  as a different deployment profile rather than a normalized speedup; and
- never compare Circom constraints, VM cycles, SP1 prover gas, or another
  backend's internal units as if they were interchangeable. End-to-end time,
  peak resources, proof/verification properties, and security assumptions are
  the common comparison axes.

### Continue or kill criteria

Continue custom Circom beyond the reference only if it passes every
correctness/security gate, the predeclared target shape remains within every
filled resource budget, scaling is measured through the target without an
unaccepted domain/setup cliff, and the per-shape circuit audit/key lifecycle
fits the declared engineering budget.

Kill the custom-only direction for that target if it exceeds any predeclared
budget without weakening membership, chaining, range, rounding, or overflow
invariants, or if the required per-shape audit and key-distribution process
exceeds its declared budget. A new `N` or shape is necessarily a new circuit
profile; it is not inherently “unauditable,” but its lifecycle cost must be
counted.

Kill a zkVM candidate if its privacy-capable proof mode is unavailable or
undocumented, if it cannot preserve the exact public statement and private
membership semantics, if exact Poseidon compatibility causes it to exceed a
predeclared budget, if its wrapped/recursive proof exceeds the same
security-normalized budget, or if its program identity and build cannot be
reproducibly bound by the verifier. Poseidon being a large share of cost is not
alone a kill result; exceeding a declared budget is.

Subject to the privacy and hardware preflight above, the next experiment
should implement the exact v2 transition and fixtures in OpenVM plus either
SP1 or RISC Zero. It must preserve fixed-point behavior, dataset/order
membership, absolute positions, transition count, state endpoints, and the
exact Poseidon chain, and it must run the same positive, boundary, reorder,
skip, insertion, membership, chain, overflow, and tampered-proof cases. This
is a bounded parity experiment, not a backend migration and not evidence that
arbitrary neural-network training has been proven.
