from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from trainproof.fixed_point import (  # noqa: E402
    FixedSample,
    FixedState,
    trajectory_witness,
)


def main() -> None:
    request = json.load(sys.stdin)
    if not isinstance(request, dict) or set(request) != {
        "initialStep",
        "initialState",
        "samples",
    }:
        raise ValueError("reference request has unexpected or missing fields")
    initial = request["initialState"]
    state = FixedState(
        w=tuple(initial["w"]),
        b=initial["b"],
        counter=initial["counter"],
    )
    samples = [
        FixedSample(x=tuple(item["x"]), y=item["y"])
        for item in request["samples"]
    ]
    json.dump(
        trajectory_witness(state, samples, initial_step=request["initialStep"]),
        sys.stdout,
        separators=(",", ":"),
        sort_keys=True,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
