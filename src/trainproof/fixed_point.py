"""Exact integer reference for the bounded fixed-point ZK relation.

This module is intentionally independent of Circom and Poseidon.  It defines
the arithmetic that the circuit must match; witness preparation calls the
small JSON adapter in ``scripts/fixed-point-reference.py`` rather than keeping
a second implementation of signed division in JavaScript.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

SCALE = 256
FRACTIONAL_BITS = 8
RAW_BITS = 16
RAW_MIN = -(1 << (RAW_BITS - 1))
RAW_MAX = (1 << (RAW_BITS - 1)) - 1
ENCODING_BIAS = 1 << (RAW_BITS - 1)
COUNTER_MAX = (1 << 32) - 1
FEATURE_COUNT = 2
LEARNING_RATE_RAW = 16  # 16 / 256 = 1 / 16 exactly.


class FixedPointError(ValueError):
    """Raised when an input or intermediate is outside the v2 domain."""


def _require_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FixedPointError(f"{label} must be an integer")
    return value


def require_raw(value: Any, label: str = "fixed-point value") -> int:
    parsed = _require_int(value, label)
    if not RAW_MIN <= parsed <= RAW_MAX:
        raise FixedPointError(
            f"{label} raw value {parsed} is outside [{RAW_MIN}, {RAW_MAX}]"
        )
    return parsed


def encode_raw(raw: Any) -> int:
    """Encode a signed raw integer as the circuit's unsigned offset value."""

    return require_raw(raw) + ENCODING_BIAS


def decode_encoded(encoded: Any) -> int:
    """Decode the unique unsigned 16-bit offset representation."""

    parsed = _require_int(encoded, "encoded fixed-point value")
    if not 0 <= parsed < 1 << RAW_BITS:
        raise FixedPointError("encoded fixed-point value must be in [0, 65535]")
    return parsed - ENCODING_BIAS


def floor_rescale(numerator: Any, label: str = "rescaled quotient") -> tuple[int, int]:
    """Return ``(floor(numerator / SCALE), non-negative remainder)``.

    Python's ``divmod`` implements the declared negative-infinity rounding and
    yields ``0 <= remainder < SCALE``.  The quotient is itself a persistent
    signed-16 fixed-point raw value; overflow rejects the relation.
    """

    parsed = _require_int(numerator, "rescale numerator")
    quotient, remainder = divmod(parsed, SCALE)
    require_raw(quotient, label)
    if not 0 <= remainder < SCALE:  # Defensive; guaranteed by divmod here.
        raise FixedPointError("rescale remainder is outside the canonical range")
    return quotient, remainder


@dataclass(frozen=True)
class FixedSample:
    x: tuple[int, int]
    y: int

    def __post_init__(self) -> None:
        if not isinstance(self.x, tuple) or len(self.x) != FEATURE_COUNT:
            raise FixedPointError("sample x must contain exactly two raw integers")
        for index, value in enumerate(self.x):
            require_raw(value, f"sample x[{index}]")
        require_raw(self.y, "sample y")


@dataclass(frozen=True)
class FixedState:
    w: tuple[int, int]
    b: int
    counter: int

    def __post_init__(self) -> None:
        if not isinstance(self.w, tuple) or len(self.w) != FEATURE_COUNT:
            raise FixedPointError("state w must contain exactly two raw integers")
        for index, value in enumerate(self.w):
            require_raw(value, f"state w[{index}]")
        require_raw(self.b, "state b")
        counter = _require_int(self.counter, "state counter")
        if not 0 <= counter <= COUNTER_MAX:
            raise FixedPointError("state counter must be in [0, 2^32-1]")


@dataclass(frozen=True)
class TransitionTrace:
    before: FixedState
    sample: FixedSample
    dot_numerator: int
    dot_scaled: int
    dot_remainder: int
    prediction: int
    error: int
    gradients: tuple[int, int]
    gradient_remainders: tuple[int, int]
    weight_steps: tuple[int, int]
    weight_step_remainders: tuple[int, int]
    bias_step: int
    bias_step_remainder: int
    after: FixedState


def linear_sgd_transition(
    state: FixedState,
    sample: FixedSample,
    *,
    expected_step: int | None = None,
) -> TransitionTrace:
    """Apply one exact two-feature fixed-point linear-SGD transition.

    ``prediction = floor((w0*x0 + w1*x1) / SCALE) + b``

    ``error = prediction - y``

    ``gradient[j] = floor(error*x[j] / SCALE)``

    ``weight_step[j] = floor(gradient[j]*LEARNING_RATE_RAW / SCALE)``

    ``bias_step = floor(error*LEARNING_RATE_RAW / SCALE)``

    ``new_w[j] = w[j] - weight_step[j]`` and ``new_b = b - bias_step``.

    The MAC is accumulated exactly before one rescale.  Every named
    fixed-point intermediate is signed-16.  Any overflow raises instead of
    wrapping in either integers or the BN254 field.
    """

    if expected_step is not None:
        expected = _require_int(expected_step, "expected step")
        if state.counter != expected:
            raise FixedPointError(
                f"state counter {state.counter} does not equal step {expected}"
            )
    if state.counter == COUNTER_MAX:
        raise FixedPointError("state counter increment overflows 32 bits")

    dot_numerator = sum(
        state.w[index] * sample.x[index] for index in range(FEATURE_COUNT)
    )
    # Static circuit bound: two signed-16 products have absolute sum <= 2^31.
    if not -(1 << 31) <= dot_numerator <= 1 << 31:
        raise FixedPointError("dot-product numerator exceeded the proven bound")
    dot_scaled, dot_remainder = floor_rescale(dot_numerator, "dot product")
    prediction = require_raw(dot_scaled + state.b, "prediction")
    error = require_raw(prediction - sample.y, "error")

    gradients: list[int] = []
    gradient_remainders: list[int] = []
    weight_steps: list[int] = []
    weight_step_remainders: list[int] = []
    for index in range(FEATURE_COUNT):
        gradient, gradient_remainder = floor_rescale(
            error * sample.x[index], f"gradient[{index}]"
        )
        weight_step, weight_step_remainder = floor_rescale(
            gradient * LEARNING_RATE_RAW, f"weight step[{index}]"
        )
        gradients.append(gradient)
        gradient_remainders.append(gradient_remainder)
        weight_steps.append(weight_step)
        weight_step_remainders.append(weight_step_remainder)

    bias_step, bias_step_remainder = floor_rescale(
        error * LEARNING_RATE_RAW, "bias step"
    )
    new_w = tuple(
        require_raw(state.w[index] - weight_steps[index], f"new w[{index}]")
        for index in range(FEATURE_COUNT)
    )
    new_b = require_raw(state.b - bias_step, "new b")
    after = FixedState(w=new_w, b=new_b, counter=state.counter + 1)
    return TransitionTrace(
        before=state,
        sample=sample,
        dot_numerator=dot_numerator,
        dot_scaled=dot_scaled,
        dot_remainder=dot_remainder,
        prediction=prediction,
        error=error,
        gradients=tuple(gradients),
        gradient_remainders=tuple(gradient_remainders),
        weight_steps=tuple(weight_steps),
        weight_step_remainders=tuple(weight_step_remainders),
        bias_step=bias_step,
        bias_step_remainder=bias_step_remainder,
        after=after,
    )


def run_training(
    initial_state: FixedState,
    samples: Iterable[FixedSample],
    *,
    initial_step: int,
) -> tuple[list[FixedState], list[TransitionTrace]]:
    """Run an exact consecutive trajectory and return all N+1 states."""

    step = _require_int(initial_step, "initial step")
    if initial_state.counter != step:
        raise FixedPointError("initial state counter must equal initial step")
    states = [initial_state]
    traces: list[TransitionTrace] = []
    for offset, sample in enumerate(samples):
        trace = linear_sgd_transition(
            states[-1], sample, expected_step=step + offset
        )
        traces.append(trace)
        states.append(trace.after)
    return states, traces


def trajectory_witness(
    initial_state: FixedState,
    samples: Iterable[FixedSample],
    *,
    initial_step: int,
) -> dict[str, Any]:
    """Return the arithmetic portion of the Circom witness as JSON values."""

    states, traces = run_training(
        initial_state, samples, initial_step=initial_step
    )
    return {
        "stateW": [[encode_raw(value) for value in state.w] for state in states],
        "stateB": [encode_raw(state.b) for state in states],
        "stateCounter": [state.counter for state in states],
        "dotScaled": [encode_raw(trace.dot_scaled) for trace in traces],
        "dotRemainder": [trace.dot_remainder for trace in traces],
        "prediction": [encode_raw(trace.prediction) for trace in traces],
        "error": [encode_raw(trace.error) for trace in traces],
        "gradients": [
            [encode_raw(value) for value in trace.gradients] for trace in traces
        ],
        "gradientRemainders": [
            list(trace.gradient_remainders) for trace in traces
        ],
        "weightSteps": [
            [encode_raw(value) for value in trace.weight_steps] for trace in traces
        ],
        "weightStepRemainders": [
            list(trace.weight_step_remainders) for trace in traces
        ],
        "biasStep": [encode_raw(trace.bias_step) for trace in traces],
        "biasStepRemainder": [trace.bias_step_remainder for trace in traces],
    }
