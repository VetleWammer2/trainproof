from __future__ import annotations

import pytest

from trainproof.fixed_point import (
    COUNTER_MAX,
    RAW_MAX,
    RAW_MIN,
    FixedPointError,
    FixedSample,
    FixedState,
    decode_encoded,
    encode_raw,
    floor_rescale,
    linear_sgd_transition,
    run_training,
    trajectory_witness,
)


@pytest.mark.parametrize(
    ("numerator", "quotient", "remainder"),
    [
        (0, 0, 0),
        (1, 0, 1),
        (255, 0, 255),
        (256, 1, 0),
        (257, 1, 1),
        (-1, -1, 255),
        (-255, -1, 1),
        (-256, -1, 0),
        (-257, -2, 255),
    ],
)
def test_floor_rescaling_boundaries(
    numerator: int, quotient: int, remainder: int
) -> None:
    assert floor_rescale(numerator) == (quotient, remainder)
    assert numerator == quotient * 256 + remainder


def test_offset_encoding_extrema_and_signs() -> None:
    assert encode_raw(RAW_MIN) == 0
    assert encode_raw(-1) == 32767
    assert encode_raw(0) == 32768
    assert encode_raw(1) == 32769
    assert encode_raw(RAW_MAX) == 65535
    for raw in (RAW_MIN, -1, 0, 1, RAW_MAX):
        assert decode_encoded(encode_raw(raw)) == raw

    with pytest.raises(FixedPointError, match="outside"):
        encode_raw(RAW_MIN - 1)
    with pytest.raises(FixedPointError, match="outside"):
        encode_raw(RAW_MAX + 1)
    with pytest.raises(FixedPointError, match=r"\[0, 65535\]"):
        decode_encoded(65536)


def test_positive_and_negative_fixed_point_training_values() -> None:
    initial = FixedState(w=(64, -32), b=16, counter=0)
    samples = [
        FixedSample(x=(256, -128), y=192),
        FixedSample(x=(-192, 64), y=-128),
        FixedSample(x=(128, 384), y=256),
        FixedSample(x=(-256, -256), y=64),
    ]
    states, traces = run_training(initial, samples, initial_step=0)

    assert traces[0].prediction == 96
    assert traces[0].error == -96
    assert traces[0].gradients == (-96, 48)
    assert traces[0].weight_steps == (-6, 3)
    assert traces[0].bias_step == -6
    assert states[1] == FixedState(w=(70, -35), b=22, counter=1)

    # The remaining fixture covers both error signs and non-zero floor remainders.
    assert {trace.error < 0 for trace in traces} == {False, True}
    assert any(trace.dot_remainder for trace in traces)
    assert any(any(trace.weight_step_remainders) for trace in traces)
    assert states[-1] == FixedState(w=(77, -18), b=40, counter=4)

    witness = trajectory_witness(initial, samples, initial_step=0)
    assert witness["stateW"][-1] == [encode_raw(77), encode_raw(-18)]
    assert witness["stateB"][-1] == encode_raw(40)
    assert witness["stateCounter"] == [0, 1, 2, 3, 4]


def test_overflow_and_counter_mismatch_are_rejected() -> None:
    # The dot-product rescale itself exceeds signed-16.
    with pytest.raises(FixedPointError, match="dot product"):
        linear_sgd_transition(
            FixedState(w=(RAW_MAX, RAW_MAX), b=0, counter=0),
            FixedSample(x=(RAW_MAX, RAW_MAX), y=0),
            expected_step=0,
        )

    # A valid intermediate gradient would increase an already maximal weight.
    with pytest.raises(FixedPointError, match=r"new w\[0\]"):
        linear_sgd_transition(
            FixedState(w=(RAW_MAX, 0), b=0, counter=0),
            FixedSample(x=(1, 0), y=RAW_MAX),
            expected_step=0,
        )

    with pytest.raises(FixedPointError, match="increment overflows"):
        linear_sgd_transition(
            FixedState(w=(0, 0), b=0, counter=COUNTER_MAX),
            FixedSample(x=(0, 0), y=0),
            expected_step=COUNTER_MAX,
        )
    with pytest.raises(FixedPointError, match="does not equal step"):
        linear_sgd_transition(
            FixedState(w=(0, 0), b=0, counter=7),
            FixedSample(x=(0, 0), y=0),
            expected_step=0,
        )
