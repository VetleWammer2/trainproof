# Fixed-point arithmetic profile v2

Normative for `bounded-fixed-point-linear-training-chain/n=4/v2`. The relation
is small on purpose. It is not PyTorch, IEEE floating point, BF16/FP32, or
arbitrary matrix training.

## Representation and field embedding

- Scale `S = 256 = 2^8`.
- A value is represented by a raw integer `q` and denotes exactly `q / 256`.
- The allowed raw range is signed 16-bit, `-32768 <= q <= 32767`. The real
  interval is therefore `[-128, 32767/256]`.
- The circuit input is the unique offset-binary encoding `E(q) = q + 32768`, so
  `0 <= E(q) <= 65535`.
- `E(q)` is embedded as the same non-negative integer in BN254. Arithmetic
  decodes it with the field expression `E(q) - 32768`.
- Zero has one encoding, 32768. No negative zero, and no alternate field
  representative is accepted by the host statement or checkpoint schema.

Dataset leaves and state commitments hash encoded values, not a field-modulus
representation of a negative integer, so their byte/JSON meaning is unambiguous
outside Circom.

## Multiplication, accumulation, and rescaling

Raw multiplication is exact integer multiplication. The two-feature dot product
accumulates both products before one rescale:

```text
dotNumerator = oldW[0] * x[0] + oldW[1] * x[1]
dot           = floor(dotNumerator / 256)
prediction    = dot + oldB
error         = prediction - y
```

Every rescale uses Euclidean quotient and remainder:

```text
numerator = 256 * quotient + remainder
0 <= remainder < 256
```

That uniquely defines `quotient = floor(numerator / 256)`. Rounding goes toward
negative infinity, not toward zero and not to nearest. Examples:

| Numerator | Quotient | Remainder |
|---:|---:|---:|
| 257 | 1 | 1 |
| 256 | 1 | 0 |
| 255 | 0 | 255 |
| -1 | -1 | 255 |
| -256 | -1 | 0 |
| -257 | -2 | 255 |

The Circom gadget uses neither BN254 division nor multiplication by `256^-1`.
For encoded quotient `E(q)` it constrains the shifted integer equation

```text
numerator + 2^32 = (E(q) + 2^24 - 2^15) * 256 + remainder.
```

`E(q)` is range-constrained to 16 bits and the remainder to 8 bits. The shift is
a multiple of 256, so the equation has the floor semantics above for positive
and negative numerators alike.

## Training transition

The fixed learning rate is raw integer 16, exactly `1/16`. For feature indices
`j in {0, 1}`:

```text
gradient[j]   = floor(error * x[j] / 256)
weightStep[j] = floor(gradient[j] * 16 / 256)
biasStep      = floor(error * 16 / 256)
newW[j]       = oldW[j] - weightStep[j]
newB          = oldB - biasStep
newCounter    = oldCounter + 1
```

No division is reassociated or fused. The two rescalings in a weight update are
observable semantics and must not be replaced by one division of
`error*x[j]*16`.

## Ranges and overflow

Every sample coordinate and label, weight, bias, rescaled dot product,
prediction, error, gradient, weight step, bias step, and resulting weight or
bias must stay in the signed-16 raw range. Every state counter must be in
`[0, 2^32-1]`. The circuit also requires state counter `i` to equal
`initialStep + i`.

Overflow does not saturate, wrap, reduce modulo BN254, or silently widen. It
makes the relation unsatisfied. The Python reference raises `FixedPointError` at
the same boundary.

Unscaled intermediates have static bounds:

| Intermediate | Bound |
|---|---|
| One signed-16 product | `[-1,073,709,056, 1,073,741,824]` |
| Two-product dot accumulator | `[-2,147,418,112, 2,147,483,648]` |
| `error*x[j]` | within the one-product bound |
| Signed-16 gradient or error times learning-rate raw 16 | absolute value below `2^19` |

Those values and every shifted rescale equation are tiny next to the BN254
scalar-field modulus, so two distinct in-range integer solutions cannot become
equal through field wraparound.

## Reference equality

[`src/trainproof/fixed_point.py`](../src/trainproof/fixed_point.py) is the
reference implementation. Witness generation calls its JSON adapter instead of
reimplementing negative division in JavaScript.

For the declared domain, reference/circuit equality follows from:

1. the one-to-one offset encoding and identical signed-16 range checks;
2. the unique quotient/remainder equation for each rescale;
3. the same explicit operation order and state equations;
4. the static no-field-wrap bounds above.

Tests cover both signs, exact and adjacent rescale boundaries, minimum and
maximum encodings, intermediate/final overflow, counter overflow, and a
four-transition witness checked against the compiled R1CS.
