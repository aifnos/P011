"""Fetch official fixed Qt 6.8.5 archives into a new, explicit host build root."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import urllib.request

MODULES = ("qtbase", "qtdeclarative", "qtshadertools", "qtwayland", "qtwebchannel", "qtwebengine")
BASE_URL = "https://download.qt.io/archive/qt/6.8/6.8.5/submodules/"


def fetch(module, downloads):
    name = module + "-everywhere-opensource-src-6.8.5.tar.xz"
    url = BASE_URL + name
    expected_text = urllib.request.urlopen(url + ".sha256", timeout=60).read().decode("ascii")
    expected = re.search(r"\b[0-9a-fA-F]{64}\b", expected_text).group(0).lower()
    dest = downloads / name
    if not dest.exists():
        partial = downloads / (name + ".partial")
        # Python's verified TLS transport avoids Windows Schannel's unavailable
        # CRL endpoint failure. Certificate and hostname checks stay enabled.
        with urllib.request.urlopen(url, timeout=180) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, 1024 * 1024)
        actual = hashlib.file_digest(partial.open("rb"), "sha256").hexdigest()
        if actual != expected:
            raise ValueError("Official SHA-256 differs: " + name)
        partial.replace(dest)
    else:
        actual = hashlib.file_digest(dest.open("rb"), "sha256").hexdigest()
        if actual != expected:
            raise ValueError("Existing archive differs: " + name)
    result = dict(module=module, version="6.8.5", official_tag="v6.8.5-lts-lgpl",
                  url=url, sha256=expected, bytes=dest.stat().st_size)
    print(json.dumps(result), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    downloads = args.root.resolve() / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda module: fetch(module, downloads), MODULES))
    (downloads / "qt685-official-source-lock.json").write_text(
        json.dumps(dict(schema=1, device_tested=False, sources=results), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
