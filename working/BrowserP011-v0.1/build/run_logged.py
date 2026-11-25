"""Run one host command with separate raw streams in the explicit E: work root."""
from pathlib import Path
import argparse
import datetime
import json
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--label", required=True)
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
command = args.command[1:] if args.command[:1] == ["--"] else args.command
if not command:
    raise SystemExit("Command required")
out = args.root.resolve() / "logs" / (datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + args.label)
out.mkdir(parents=True, exist_ok=False)
print("LOG_DIR=" + str(out), flush=True)
(out / "command.json").write_text(json.dumps(command, ensure_ascii=False, indent=2), encoding="utf-8")
with (out / "stdout.raw").open("xb") as stdout, (out / "stderr.raw").open("xb") as stderr:
    result = subprocess.run(command, stdout=stdout, stderr=stderr)
(out / "result.json").write_text(json.dumps(dict(host_exit=result.returncode, device_tested=False), indent=2), encoding="utf-8")
print("HOST_EXIT=" + str(result.returncode), flush=True)
if result.returncode:
    print((out / "stderr.raw").read_text(encoding="utf-8", errors="replace")[-5000:])
raise SystemExit(result.returncode)
