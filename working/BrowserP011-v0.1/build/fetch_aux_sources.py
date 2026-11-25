"""Fetch small host/target prerequisite archives with verified TLS."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import urllib.request

root = Path(r"E:\P011-browser-build\downloads")
root.mkdir(parents=True, exist_ok=True)
items = [
    ("wayland-1.20.0.tar.xz", "https://wayland.freedesktop.org/releases/wayland-1.20.0.tar.xz"),
    ("libffi-3.2.1.tar.gz", "https://sourceware.org/pub/libffi/libffi-3.2.1.tar.gz"),
    ("node-v20.19.0-linux-x64.tar.xz", "https://nodejs.org/dist/v20.19.0/node-v20.19.0-linux-x64.tar.xz"),
]
records = []
for name, url in items:
    target = root / name
    if not target.exists():
        with urllib.request.urlopen(url, timeout=180) as source, (root / (name + ".partial")).open("wb") as dest:
            shutil.copyfileobj(source, dest, 1024 * 1024)
        (root / (name + ".partial")).replace(target)
    digest = hashlib.file_digest(target.open("rb"), "sha256").hexdigest()
    if name.startswith("node-"):
        sums = urllib.request.urlopen("https://nodejs.org/dist/v20.19.0/SHASUMS256.txt", timeout=60).read().decode()
        expected = re.search(r"^([0-9a-f]{64})  " + re.escape(name) + r"$", sums, re.M).group(1)
        if expected != digest:
            raise ValueError("Node official SHA-256 differs")
    entry = dict(name=name, url=url, sha256=digest, bytes=target.stat().st_size,
                 integrity="official SHA-256 verified" if name.startswith("node-") else "TLS fetch and observed SHA-256")
    records.append(entry)
    print(json.dumps(entry), flush=True)
(root / "aux-source-lock.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
