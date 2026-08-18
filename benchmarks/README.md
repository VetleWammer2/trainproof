# ZK benchmark data

Run the committed Windows benchmark after bootstrapping the pinned toolchain:

```powershell
./scripts/bootstrap-zk.ps1
./scripts/benchmark-zk.ps1 -Trials 3
```

The runner compiles and proves four profiles independently:

- the exact legacy v1 R1CS relation at `N=1`;
- fixed-point v2 at `N=1`;
- fixed-point v2 at `N=2`; and
- the production fixed-point v2 profile at `N=4`.

Input generation and witness checking are outside the reported witness timing.
Witness/prove/raw-PLONK-verify medians use three fresh processes by default;
compile and setup are single samples. The JSON records every trial, polled
primary-process peak working set, constraints, source and ceremony hashes,
artifact sizes, the power-14 capacity probe, and (when a sealed fixture exists)
one end-to-end public-verifier wall-time sample.

The superseded power-14 capacity probe is optional because the current
bootstrap downloads only power 16. To reproduce that negative check, place
`powersOfTau28_hez_final_14.ptau` from the
[same upstream ceremony store](https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau)
under `zk/build/`; the result records its actual BLAKE2b digest and the exact
snarkjs rejection text.
Generated circuits, witnesses, keys, and proofs remain under the ignored
`zk/benchmark-work/` directory; only machine-readable results are committed.

Timing is host- and load-specific; OS caches are not cleared. Constraint counts
and artifact hashes are deterministic for the pinned sources/toolchain. The
reported proof size is snarkjs JSON serialization, which can vary by a few bytes
because PLONK proofs are randomized; it is not a canonical binary/on-chain size.
