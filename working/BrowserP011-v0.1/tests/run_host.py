#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the host checks and retain independent stdout/stderr bytes and exits."""
import hashlib
import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

tests = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--checks", nargs="+", choices=("source", "fixture", "public-metrics"),
                    default=("source", "fixture", "public-metrics"))
arguments = parser.parse_args()
output = tests / "results" / ("HOST_ONLY-" + uuid.uuid4().hex[:12])
output.mkdir(parents=True, exist_ok=False)
rows = []
commands = dict((
    ("source", [sys.executable, str(tests / "verify_source.py")]),
    ("fixture", ["node", "--experimental-vm-modules", str(tests / "fixture.test.mjs")]),
    ("public-metrics", ["node", str(tests / "public_metrics.test.mjs")]),
))
for name in dict.fromkeys(arguments.checks):
    argv = commands[name]
    result = subprocess.run(argv, cwd=tests, capture_output=True, timeout=30)
    (output / (name + ".stdout.raw")).write_bytes(result.stdout)
    (output / (name + ".stderr.raw")).write_bytes(result.stderr)
    rows.append({"check": name, "host_exit": result.returncode})
record = {
    "scope": "HOST_ONLY", "passed": all(row["host_exit"] == 0 for row in rows),
    "qt_compiled": False, "qt_executed": False, "chromium_executed": False,
    "device_executed": False, "capture_method": "subprocess capture_output bytes",
    "checks": rows,
    "sources": [{"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in sorted((tests.parent / "app").glob("*")) if path.is_file()],
}
(output / "host-results.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                                          encoding="utf-8")
print(json.dumps({"scope": "HOST_ONLY", "passed": record["passed"], "result_dir": str(output)},
                 ensure_ascii=False))
sys.exit(0 if record["passed"] else 1)
