# Multi-step proving feasibility and backend verdict

## Verdict

NO-GO for making the next evidence milestone another custom-Circom-only
scale-up. Keep the four-step circuit as a small, auditable reference, and spend
the next milestone on an implementation-parity experiment in a zkVM or another
backend. This is not a recommendation to rewrite Trainproof, abandon custom
circuits, or select a particular replacement.

The four-step proof succeeded. At the measured `N=1,2,4` points the complete v2
relation adds 8,711 R1CS constraints per added transition. That marginal cost
covers membership proofs, Poseidon hashes, range and rescaling checks, and the
two-feature update. It is not the cost of fixed-point multiplication alone. At
`N=4` the proving key is 194.8 MB, and proof generation on the measured
workstation took a median 49.4 seconds with a median 1.37 GB peak
primary-process working set. The relation stays far smaller than a useful neural
layer and excludes activations, tensors, optimizer state, reductions, and
floating-point behavior.

No zkVM was implemented or benchmarked in this milestone. Nothing measured here
says any zkVM is faster, smaller, safer, or cheaper than the custom circuit. The
numbers support spending the next milestone on comparable evidence instead of
assuming another custom-only scale-up is the best use of it.

## Measurements and limitations

Raw per-trial data:
[`benchmarks/results/windows-i7-8700k-2026-08-18.json`](../benchmarks/results/windows-i7-8700k-2026-08-18.json).
Procedure: [`scripts/benchmark-zk.ps1`](../scripts/benchmark-zk.ps1).

The result records base commit `da41c02e9c5c3435edc1d386f8cbfbf32499c8b0`,
measured implementation commit
`210bd4625da0bc7d87d3f857b59e98203e49a01b`, and
`worktreeDirtyDuringMeasurement: false`. It carries SHA-256 hashes for the
benchmark runner, reference, witness generators, circuits, verifier, lockfile,
and compiled R1CS artifacts. The end-to-end verifier sample also pins every
public fixture file, participant keys included.

Host: Windows 11 Pro, Intel i7-8700K (6 cores/12 threads), 16 GiB RAM; Circom
2.2.3, snarkjs 0.7.6, circomlib 2.0.5, Node 24.18.0, PLONK/BN254. The
Powers-of-Tau file was `powersOfTau28_hez_final_16.ptau`. The bootstrap checks
the downloaded file against the published BLAKE2b digest. The benchmark runner
recomputed the actual digest independently, required it to match the pinned
value, and records both. It did not run contribution-by-contribution transcript
verification, which the record states. These results therefore use a
digest-matched PoT file and are not evidence of a fresh full transcript audit.

Witness generation, proof generation, and verification are medians of three
fresh CLI processes. Fresh does not mean operating-system caches were flushed.
Compile and PLONK setup were each measured once per profile, so those times are
single observations rather than medians. Input/reference generation and
`snarkjs wtns check` sit outside the reported witness timing. Peak memory is the
primary-process working set polled every 10 ms: it excludes unrelated host
processes, is not whole-system peak RAM, and may not represent a backend that
uses child processes or a GPU.

| Profile | N | R1CS constraints | Average constraints/transition | PLONK constraints | R1CS bytes | zkey bytes | Witness median | Prove median | Prove peak | Raw PLONK verify median | Proof JSON |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Legacy unsigned scalar v1 | 1 | 8,408 | 8,408.0 | 12,276 | 1,214,440 | 46,039,580 | 0.373 s | 12.125 s | 835 MB | 0.592 s | 2,250 B |
| Fixed-point vector v2 | 1 | 9,765 | 9,765.0 | 14,604 | 1,423,044 | 48,758,796 | 0.451 s | 13.594 s | 837 MB | 0.672 s | 2,250 B |
| Fixed-point vector v2 | 2 | 18,476 | 9,238.0 | 27,507 | 2,688,184 | 97,449,952 | 0.396 s | 24.832 s | 1,201 MB | 0.609 s | 2,249 B |
| Fixed-point vector v2 | 4 | 35,898 | 8,974.5 | 53,313 | 5,218,464 | 194,832,264 | 0.549 s | 49.421 s | 1,370 MB | 0.730 s | 2,251 B |

The single `N=4` setup observation was 13.213 seconds and 1.499 GB peak
primary-process working set. Verification-key JSON stayed about 2 KB and the
snarkjs proof JSON about 2.25 KB. Both are JSON serialization sizes, not
canonical binary or on-chain encodings. A constant proof-object shape does not
imply constant proving work, key size, or public-input encoding cost.

The raw PLONK verification medians above exclude source compilation, setup,
artifact linkage, signed-envelope checks, and checkpoint validation. One
separate end-to-end run of Trainproof's public verifier did all of those in
16.183 seconds. Single observation; its recorded primary Python-process memory
excludes the child compiler and Node setup processes.

Proof-time ranges over the three v2 trials: 12.530-13.868 seconds at `N=1`,
24.525-26.348 seconds at `N=2`, 48.590-53.315 seconds at `N=4`. Three trials
support the reported medians. They do not characterize tails, thermal effects,
or host-load variance.

The deterministic constraint counts fit these equations at the measured
`N=1,2,4` points:

```text
R1CS constraints  = 1,054 + 8,711 * N
PLONK constraints = 1,701 + 12,903 * N
```

They describe this two-feature, depth-2/depth-4 profile at the sampled points.
They are not measured predictions for larger `N`, another feature width, another
tree depth, or a neural model. Resource use is not smooth merely because the
constraint count is linear: the PLONK counts cross successive power-of-two
ranges, while the measured zkey sizes roughly double, 48,758,796 to 97,449,952
to 194,832,264 bytes. Consistent with stepwise domain sizing. Not a fit for
unmeasured sizes.

The measured PLONK counts for `N=2` (27,507) and `N=4` (53,313) both exceed
`2^14`. An `N=4` setup attempt with the former power-14 file was run and failed.
The machine-readable result records its command, `53,313 > 2^14` stderr, exit
code, timing, peak working set, source URL, and actual legacy-file digest. The
production profile moved to the published power-16 file. Removing membership,
range, or chain constraints to fit a smaller setup would change the proven
relation and is not an acceptable optimization.

## Whole-relation v2 cost versus the old demo

At `N=1`, v2 has 1,357 more R1CS constraints than the preserved v1 R1CS
(+16.1%), 208,604 more R1CS bytes, and a 2,719,216-byte larger zkey. The
preserved baseline is meant to reproduce the v1 relation from `main`, and
produced the R1CS hash recorded in the benchmark result.

This is not a fixed-point arithmetic microbenchmark. v2 also moves from one
unsigned scalar feature to two signed features, changes record and state hashes,
adds quotient/remainder checks, adds a transition digest and chain hash, and
makes state types closed under iteration. The delta is the whole-relation
difference between v1 and v2. It does not isolate the cost of a multiply, a
rescale, a signed range check, or a second feature. Do not attribute the `N=1`
proving-time difference to fixed point alone.

Getting a causal arithmetic cost needs a separate experiment: compile a
non-production ablation and keep the full relation as the security baseline. No
ablation may be presented as proving the production claim.

## Where constraint growth comes from

For `N` transitions the circuit instantiates:

| Poseidons | Purpose |
|---|---|
| `3N` | dataset leaves and depth-2 paths |
| `5N` | ordering leaves and depth-4 paths |
| `2N` | transition digests and chain links |
| `N+1` | shared state commitments |

That is `11N+1` Poseidon instances before arithmetic. Each step also
range-checks three sample values, the rescaled dot, prediction, error, two
gradients, two parameter steps, a bias step, and their canonical remainders.
Every shared state range-checks two weights, a bias, and a 32-bit counter.
State-hash reuse avoids hashing both endpoints independently in every slot;
membership, transition hashing, and arithmetic stay per-step costs.

A structural inventory, not a measured attribution of constraints or seconds per
category. Splitting those shares would need labeled component counts or
ablations.

Circom template sizes and array lengths are compile-time parameters. A different
`N`, feature width, or tree depth is therefore a new circuit/R1CS/zkey/verifier
profile, even though PLONK can reuse a universal Powers of Tau. See the
[Circom template documentation](https://github.com/iden3/circom/blob/master/mkdocs/docs/circom-language/templates-and-components.md)
and [snarkjs setup documentation](https://github.com/iden3/snarkjs).

## What the small measured primitive costs

The v2 `N=1` row is a small measured baseline: one two-feature linear
prediction, signed error, two gradients, learning-rate rescaling, two weight
updates, one bias update, dataset/order membership, state commitments, one chain
link. It costs 9,765 R1CS constraints, a 48.8 MB zkey, and a median 13.6-second
proof on this host.

It is not a neural-network training step, and not a formal lower bound for one.
A single activated neuron would require declared activation and derivative
semantics. A layer would require a declared input/output shape, accumulation
schedule, update rule, and state commitment strategy. Neither target was
implemented or measured, so the numeric cost of a "minimally interesting neural
training step" remains unknown. No transformer, convolution, matrix-training,
PyTorch, BF16/FP32, or GPU-execution cost is claimed.

## Custom circuit versus program proving

The custom circuit remains attractive for the parts already native to this
protocol:

- exact compatibility with the existing BN254 circomlib Poseidon dataset,
  ordering, state, and chain commitments;
- small static Merkle paths and a fixed operation graph whose ranges can be
  reviewed directly;
- the measured approximately 2.25 KB snarkjs proof JSON and approximately
  0.7-second raw PLONK verification on this host.

A zkVM may cut circuit-authoring friction when the relation changes shape.
Variable-length loops, richer optimizer state, control flow, and tensor layouts
become program logic; continuations or recursion split long execution traces.
None of that removes the work of proving each operation, guarantees favorable
performance, or removes the need for an explicit protocol bound and version.

A zkVM proves execution of a pinned machine program. It does not establish that
the source is correct, that the compiler preserved the intended semantics, or
that the program is PyTorch, historical GPU execution, BF16, FP32, or arbitrary
model training. Adoption therefore requires a reproducible source-to-binary
build and verifier binding to the exact program image, proof configuration,
backend version, and security parameters.

The general RISC-V zkVMs reviewed do not list exact circomlib-compatible BN254
Poseidon as a standard application precompile. See the official
[SP1 precompile specification](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompile-specification)
and [RISC Zero precompile list](https://dev.risczero.com/api/zkvm/precompiles).
Implementing the existing hash in guest code may dominate a VM experiment. A
custom accelerator can cut that cost only by reintroducing custom-chip
implementation and audit work. Measure it rather than assume it.

## Backend research snapshot

Primary sources reviewed on 2026-08-18. Version labels identify the
documentation snapshot. None of these backends was installed or benchmarked for
this milestone.

- **OpenVM 2.0.x** (the install page exposed CLI 2.0.2 when reviewed) is a
  plausible protocol-compatibility experiment: its
  [algebra extension](https://docs.openvm.dev/book/acceleration-using-extensions/algebra/)
  supports compile-time modular fields and gives BN254 as an example, and
  [continuations](https://docs.openvm.dev/specs/architecture/continuations/)
  address long executions. Modular BN254 arithmetic does not by itself provide
  the exact existing Poseidon implementation. A
  [custom extension](https://docs.openvm.dev/book/advanced-usage/creating-a-new-extension/)
  would restore custom-chip test and audit obligations. The reviewed
  [security model](https://docs.openvm.dev/specs/security/security-model/) did
  not clearly establish the application-witness privacy guarantee needed here,
  so privacy is an adoption blocker pending a written primary-source answer. The
  official [installation guidance](https://docs.openvm.dev/book/getting-started/install/)
  targets Ubuntu/macOS and describes GPU requirements, while this benchmark
  record contains no GPU model or VRAM. Hardware compatibility is unestablished,
  and Windows would need a different execution environment.

- **SP1 v6-family documentation** describes a general RISC-V zkVM with
  [recursive aggregation](https://docs.succinct.xyz/docs/sp1/writing-programs/proof-aggregation)
  and multiple [proof types](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types).
  Its [security model](https://docs.succinct.xyz/docs/sp1/security/security-model)
  says individual STARK proofs are not currently zero knowledge, while the
  Groth16 and PLONK wrappers are. A privacy-preserving comparison must include a
  wrapper, not a core or compressed proof. The wrappers differ in setup
  assumptions: the documented Groth16 path uses a circuit-specific ceremony,
  PLONK relies on a universal one. The official
  [hardware guidance](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements)
  lists at least 16 GB for several local paths and at least 64 GB for PLONK, so
  proof type and hardware are part of the experiment. Official
  [installation](https://docs.succinct.xyz/docs/sp1/getting-started/install)
  targets Linux/macOS rather than native Windows. SP1 also warns that cycles
  alone do not account for differing chip/precompile cost; its
  [prover-gas guidance](https://docs.succinct.xyz/docs/sp1/optimizing-programs/prover-gas)
  should be recorded next to wall time and memory.

- **RISC Zero 3.0.x documentation** binds the verifier to a guest ImageID and
  public journal through [receipts](https://dev.risczero.com/api/zkvm/receipts),
  with [recursion](https://dev.risczero.com/api/recursion) for segmented
  execution. Its [security model](https://dev.risczero.com/api/security-model)
  says it targets perfect zero knowledge but does not yet have a mathematical
  argument establishing that property. It also says an un-recursed RISC-V proof
  leaks execution length, and that recursion removes that leak. Material privacy
  caveats, not a generic "zkVM means ZK" guarantee. The reviewed
  [installation guidance](https://dev.risczero.com/api/zkvm/install) provides
  first-class binaries for Linux/macOS rather than native Windows. Its
  documented precompiles do not promise compatibility with this protocol's BN254
  Poseidon.

- **Jolt**, as represented by its official
  [repository](https://github.com/a16z/jolt) on the access date, is an optional
  research control rather than an adoption recommendation: the project labels
  itself alpha and unsuitable for production.

- **zkDL** is evidence that specialized sumcheck/GKR-style systems merit study
  for dense tensor workloads, not a drop-in backend or a comparable performance
  result. Its [paper](https://eprint.iacr.org/2023/1174.pdf) evaluates a
  particular 32-bit integer profile with scale `2^16` and reports that overflow
  was not observed experimentally, which is not this protocol's
  circuit-enforced overflow rejection. The authors'
  [implementation repository](https://github.com/jvhs0706/zkdl-train) is
  archived. Its GPU headline numbers must not be transferred to this workload,
  and its results are not evidence of PyTorch, BF16/FP32, or historical GPU
  equivalence.

"Released", "audited", or "production" statements from backend authors do not
substitute for Trainproof's own parity, privacy, resource, and verifier tests.
No cross-backend performance number from vendor documentation feeds this
verdict.

## Falsifiable gates for the next milestone

Project owners have not declared numeric resource budgets or a minimally
interesting model shape. These have to be filled in before the parity experiment
runs. Until then the verdict selects the next experiment, not a winning backend.

| Decision input | Predeclared value |
|---|---|
| Fixed v2 parity sizes | `N=1,2,4`; attempt `N=8` if it fits the declared resource limits |
| Minimally interesting feature/model shape | TBD by project owners |
| Maximum setup/preprocessing wall time | TBD by project owners |
| Maximum proof wall time | TBD by project owners |
| Maximum peak host RAM / accelerator VRAM | TBD by project owners |
| Maximum proving-key, verification-key, and proof sizes | TBD by project owners |
| Maximum verification wall time | TBD by project owners |
| Minimum accepted soundness/security level | TBD by project owners |
| Accepted trusted-setup assumptions | TBD by project owners |
| Whether a network prover may see private witness data | TBD by project owners; default must be no |
| Maximum audit/rekey/release-engineering effort per shape | TBD by project owners |

### Correctness and security gates

Every candidate, Circom included, must:

1. agree bit-for-bit with the fixed-point reference for the declared signed
   domain, operation order, floor quotient/remainder rule, and overflow
   rejection behavior;
2. preserve the same dataset membership, ordering membership, absolute step,
   fixed transition count, initial/final state commitments, and Poseidon chain,
   including rejection of a modified intermediate state, reordered, skipped, or
   inserted steps, and modified sample membership;
3. reject the same boundary and adversarial fixtures, and reject tampered public
   proofs or public statements through the public verifier;
4. use an actual zero-knowledge proof mode with documented witness-privacy
   properties, not a mock, development, core-only non-ZK, or silently trusted
   remote-prover mode;
5. bind verification to exact circuit or program artifacts, backend/proof
   configuration, security parameters, and a reproducible source-to-artifact
   build.

Correctness comes from specification, constraint/program review, tests, and
valid/invalid proofs. It is not a performance measurement.

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
- use comparable hardware and security levels for direct ratios; a backend that
  needs different hardware, WSL/Linux, a GPU, or a network prover is a different
  deployment profile, not a normalized speedup;
- never compare Circom constraints, VM cycles, SP1 prover gas, or another
  backend's internal units as if they were interchangeable. End-to-end time,
  peak resources, proof/verification properties, and security assumptions are
  the common comparison axes.

### Continue or kill

Continue custom Circom beyond the reference only if it passes every
correctness/security gate, the predeclared target shape stays inside every
filled resource budget, scaling is measured through the target without an
unaccepted domain/setup cliff, and the per-shape circuit audit/key lifecycle
fits the declared engineering budget.

Kill the custom-only direction for that target if it exceeds any predeclared
budget without weakening membership, chaining, range, rounding, or overflow
invariants, or if the required per-shape audit and key-distribution process
exceeds its declared budget. A new `N` or shape is necessarily a new circuit
profile. That is not inherently unauditable, but its lifecycle cost has to be
counted.

Kill a zkVM candidate if its privacy-capable proof mode is unavailable or
undocumented, if it cannot preserve the exact public statement and private
membership semantics, if exact Poseidon compatibility pushes it past a
predeclared budget, if its wrapped/recursive proof exceeds the same
security-normalized budget, or if its program identity and build cannot be
reproducibly bound by the verifier. Poseidon being a large share of cost is not
a kill result on its own. Exceeding a declared budget is.

Subject to the privacy and hardware preflight above, the next experiment should
implement the exact v2 transition and fixtures in OpenVM plus either SP1 or
RISC Zero. It must preserve fixed-point behavior, dataset/order membership,
absolute positions, transition count, state endpoints, and the exact Poseidon
chain, and it must run the same positive, boundary, reorder, skip, insertion,
membership, chain, overflow, and tampered-proof cases. A bounded parity
experiment. Not a backend migration, and not evidence that arbitrary
neural-network training has been proven.
