# ZK benchmark data

Bootstrap the pinned toolchain, then run the committed Windows benchmark:

```powershell
./scripts/bootstrap-zk.ps1
./scripts/benchmark-zk.ps1 -Trials 3
```

Four profiles, compiled and proven independently:

| Profile | N |
|---|---:|
| Legacy v1 R1CS relation | 1 |
| Fixed-point v2 | 1 |
| Fixed-point v2 | 2 |
| Fixed-point v2, production | 4 |

Witness, prove and raw-PLONK-verify medians come from three fresh processes by
default. Compile and setup are single samples. Input generation and witness
checking sit outside the reported witness timing. The JSON records every trial,
the polled primary-process peak working set, constraints, source and ceremony
hashes, artifact sizes, the power-14 capacity probe, and one end-to-end
public-verifier wall-time sample when a sealed fixture exists.

The superseded power-14 capacity probe is optional: the current bootstrap
downloads only power 16. To reproduce that negative check, put
`powersOfTau28_hez_final_14.ptau` from the
[same upstream ceremony store](https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau)
under `zk/build/`. The result records its actual BLAKE2b digest and the exact
snarkjs rejection text.

Generated circuits, witnesses, keys and proofs stay under the ignored
`zk/benchmark-work/` directory. Only machine-readable results are committed.

Timing is host- and load-specific, and OS caches are not cleared. Constraint
counts and artifact hashes are deterministic for the pinned sources and
toolchain. Reported proof size is snarkjs JSON serialization, which varies by a
few bytes because PLONK proofs are randomized: 2,246 to 2,256 bytes over the
twelve recorded trials, with the four reported medians at 2,249 to 2,251. It is
not a canonical binary or on-chain size.
