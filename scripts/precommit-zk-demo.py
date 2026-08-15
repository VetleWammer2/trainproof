from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from trainproof.zk import precommit_zk_demo  # noqa: E402


if len(sys.argv) != 2:
    raise SystemExit("usage: precommit-zk-demo.py OUTPUT_DIRECTORY")

print(
    json.dumps(
        precommit_zk_demo(sys.argv[1], PROJECT_ROOT),
        indent=2,
        sort_keys=True,
    )
)
