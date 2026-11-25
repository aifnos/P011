"""PC-only settings candidate using the existing Qt 5 browser kernel."""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]


def make_candidate(original: bytes):
    specification = importlib.util.spec_from_file_location(
        "p011_settings_fixed_resource", HERE.parent / "build_settings_candidate.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.ENTRY = "file:///mnt/data/p011-browser/settings/legacy/BrowserPage.qml"
    candidate, qml, result = module.build(original)
    result.update(schema="p011.browser.legacy-settings-candidate.v1",
                  kernel="existing vendor Qt 5.10.1 / QtWebEngine 1.4",
                  independent_controller_required=False, startup_files_changed=False)
    return candidate, qml, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=PROJECT / "working/BiliP011-v0.1/formal/out/P011-Bili-Formal-v4-adb-sysv-20261014/Z03.patched")
    parser.add_argument("--out", type=Path, default=HERE / "out")
    args = parser.parse_args()
    if args.input.is_symlink() or not args.input.is_file():
        raise ValueError("Expected the pinned local Bili Z03")
    candidate, qml, result = make_candidate(args.input.read_bytes())
    destination = args.out / ("legacy-settings-" + result["candidate_sha256"][:24])
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "Z03.patched").write_bytes(candidate)
    (destination / "SetMainPage.qml").write_bytes(qml)
    (destination / "candidate.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(destination), **result}, sort_keys=True))


if __name__ == "__main__":
    main()
