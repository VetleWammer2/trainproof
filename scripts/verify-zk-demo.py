from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from trainproof.zk import verify_zk_demo  # noqa: E402


if len(sys.argv) != 2:
    raise SystemExit("usage: verify-zk-demo.py OUTPUT_DIRECTORY")

report = verify_zk_demo(sys.argv[1], PROJECT_ROOT)
print(json.dumps(report, indent=2, sort_keys=True))
if not report.get("valid"):
    raise SystemExit(1)
